//! YMP wire format types: 15-byte header, segment encoding, error enum.
//!
//! ## Wire layout
//! ```text
//! Offset  Size  Field
//! 0       1     type       — 0x10=DATA, 0x11=ACK, 0x12=SYN, 0x13=SYN-ACK
//! 1       8     msg_id     — big-endian u64
//! 9       2     seq        — big-endian u16
//! 11      2     total      — big-endian u16
//! 13      2     payload_len — big-endian u16
//! 15      N     payload    — (empty for SYN/SYN-ACK)
//! ```

use std::fmt;

// ── constants ────────────────────────────────────────────────────────────

/// Total wire header size: type(1) + msg_id(8) + seq(2) + total(2) + payload_len(2).
pub const HEADER_SIZE: usize = 15;

/// Maximum payload per DATA segment (65535 - 15 = 65520).
pub const FRAGMENT_SIZE: usize = 65520;

/// Seconds before retransmitting unacknowledged segments.
pub const RETRY_TIMEOUT_SECS: u64 = 5;

/// Maximum retransmission attempts per segment (12 × 5s = 60s total).
pub const MAX_RETRIES: u32 = 12;

/// Seconds to wait for a SYN-ACK before retrying the SYN.
pub const SYN_TIMEOUT_SECS: u64 = 5;

/// Maximum SYN retransmission attempts.
/// 5 × SYN_TIMEOUT_SECS = 25s budget — a cold multi-hop Yggdrasil path (DHT
/// lookup + reverse-path warmup) frequently needs more than a flat 3 × 5s = 15s.
pub const MAX_SYN_RETRIES: u32 = 5;

/// Hard limit on total reassembled message size (32 MiB).
pub const MAX_MESSAGE_SIZE: usize = 32 * 1024 * 1024;

/// How long to keep an incomplete reassembly buffer before dropping it.
pub const REASSEMBLY_TIMEOUT_SECS: u64 = 600;

// ── packet types ─────────────────────────────────────────────────────────

const PKT_DATA: u8 = 0x10;
const PKT_ACK: u8 = 0x11;
const PKT_SYN: u8 = 0x12;
const PKT_SYN_ACK: u8 = 0x13;

/// Monotonic message identifier.
pub type MessageId = u64;

// ── header ───────────────────────────────────────────────────────────────

/// Decoded YMP segment header.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SegmentHeader {
    pub pkt_type: PktType,
    pub msg_id: MessageId,
    pub seq: u16,
    pub total: u16,
    pub payload_len: u16,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PktType {
    Data,
    Ack,
    /// Connection handshake — forces path discovery before data.
    Syn,
    /// Handshake response — confirms bidirectional reachability.
    SynAck,
}

impl SegmentHeader {
    /// Encode this header into a buffer (must be at least [`HEADER_SIZE`] bytes).
    pub fn encode(&self, out: &mut [u8]) {
        debug_assert!(out.len() >= HEADER_SIZE, "encode buffer too short: {} < {}", out.len(), HEADER_SIZE);
        out[0] = match self.pkt_type {
            PktType::Data => PKT_DATA,
            PktType::Ack => PKT_ACK,
            PktType::Syn => PKT_SYN,
            PktType::SynAck => PKT_SYN_ACK,
        };
        out[1..9].copy_from_slice(&self.msg_id.to_be_bytes());
        out[9..11].copy_from_slice(&self.seq.to_be_bytes());
        out[11..13].copy_from_slice(&self.total.to_be_bytes());
        out[13..15].copy_from_slice(&self.payload_len.to_be_bytes());
    }

    /// Decode a header from a 15-byte slice.
    /// Returns `None` if the slice is too short or the type byte is unknown.
    pub fn decode(buf: &[u8]) -> Option<Self> {
        if buf.len() < HEADER_SIZE {
            return None;
        }
        let pkt_type = match buf[0] {
            PKT_DATA => PktType::Data,
            PKT_ACK => PktType::Ack,
            PKT_SYN => PktType::Syn,
            PKT_SYN_ACK => PktType::SynAck,
            _ => return None,
        };
        let msg_id = u64::from_be_bytes(buf[1..9].try_into().unwrap());
        let seq = u16::from_be_bytes(buf[9..11].try_into().unwrap());
        let total = u16::from_be_bytes(buf[11..13].try_into().unwrap());
        let payload_len = u16::from_be_bytes(buf[13..15].try_into().unwrap());
        Some(Self { pkt_type, msg_id, seq, total, payload_len })
    }

    /// Build a DATA header for one segment of a fragmented message.
    pub fn data(msg_id: MessageId, seq: u16, total: u16, payload_len: u16) -> Self {
        Self { pkt_type: PktType::Data, msg_id, seq, total, payload_len }
    }

    /// Build an ACK header for a received segment.
    pub fn ack(msg_id: MessageId, seq: u16) -> Self {
        Self { pkt_type: PktType::Ack, msg_id, seq, total: 0, payload_len: 0 }
    }

    /// Build a SYN header for connection handshake.
    pub fn syn(msg_id: MessageId) -> Self {
        Self { pkt_type: PktType::Syn, msg_id, seq: 0, total: 0, payload_len: 0 }
    }

    /// Build a SYN-ACK header for handshake response.
    pub fn syn_ack(msg_id: MessageId) -> Self {
        Self { pkt_type: PktType::SynAck, msg_id, seq: 0, total: 0, payload_len: 0 }
    }
}

// ── errors ───────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum YmpError {
    /// All retransmission attempts exhausted.
    MaxRetriesExceeded,
    /// SYN handshake failed — peer not reachable (no up peer / unreachable destination).
    Unreachable,
    /// Message exceeds MAX_MESSAGE_SIZE.
    TooLarge,
    /// Session is closed.
    Closed,
    /// Invalid or corrupt wire data.
    BadPacket,
    /// Reassembly buffer for this msg_id was dropped (timeout).
    ReassemblyDropped,
}

impl fmt::Display for YmpError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MaxRetriesExceeded => write!(f, "max retries exceeded"),
            Self::Unreachable => write!(f, "unreachable: SYN handshake failed"),
            Self::TooLarge => write!(f, "message too large"),
            Self::Closed => write!(f, "session closed"),
            Self::BadPacket => write!(f, "bad packet"),
            Self::ReassemblyDropped => write!(f, "reassembly buffer dropped"),
        }
    }
}

impl std::error::Error for YmpError {}

// ── tests ────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unreachable_display() {
        assert_eq!(
            YmpError::Unreachable.to_string(),
            "unreachable: SYN handshake failed"
        );
    }

    #[test]
    fn header_roundtrip_data() {
        let h = SegmentHeader::data(42, 3, 7, 100);
        let mut buf = [0u8; HEADER_SIZE];
        h.encode(&mut buf);
        let decoded = SegmentHeader::decode(&buf).unwrap();
        assert_eq!(decoded, h);
    }

    #[test]
    fn header_roundtrip_ack() {
        let h = SegmentHeader::ack(12345, 0);
        let mut buf = [0u8; HEADER_SIZE];
        h.encode(&mut buf);
        let decoded = SegmentHeader::decode(&buf).unwrap();
        assert_eq!(decoded, h);
        assert_eq!(decoded.total, 0);
        assert_eq!(decoded.payload_len, 0);
    }

    #[test]
    fn decode_short_buf_returns_none() {
        assert!(SegmentHeader::decode(&[0u8; 10]).is_none());
    }

    #[test]
    fn decode_bad_type_returns_none() {
        let mut buf = [0u8; HEADER_SIZE];
        buf[0] = 0xFF;
        assert!(SegmentHeader::decode(&buf).is_none());
    }

    #[test]
    fn header_roundtrip_syn() {
        let h = SegmentHeader::syn(99);
        let mut buf = [0u8; HEADER_SIZE];
        h.encode(&mut buf);
        assert_eq!(buf[0], 0x12);
        let decoded = SegmentHeader::decode(&buf).unwrap();
        assert_eq!(decoded, h);
        assert_eq!(decoded.total, 0);
        assert_eq!(decoded.payload_len, 0);
    }

    #[test]
    fn header_roundtrip_syn_ack() {
        let h = SegmentHeader::syn_ack(77);
        let mut buf = [0u8; HEADER_SIZE];
        h.encode(&mut buf);
        assert_eq!(buf[0], 0x13);
        let decoded = SegmentHeader::decode(&buf).unwrap();
        assert_eq!(decoded, h);
    }

    #[test]
    fn constants_sanity() {
        // Full segment fits in ironwood's MTU after encrypt overhead
        assert!(HEADER_SIZE + FRAGMENT_SIZE <= 65535);
        // MAX_MESSAGE_SIZE / FRAGMENT_SIZE fits in u16::MAX
        assert!((MAX_MESSAGE_SIZE / FRAGMENT_SIZE) < u16::MAX as usize);
    }
}
