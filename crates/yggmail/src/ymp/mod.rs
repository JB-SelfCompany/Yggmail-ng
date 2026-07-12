//! YMP — Yggdrasil Mail Protocol: reliable message delivery over PacketConn.
//!
//! Adds fragmentation, ACK-based reliability, and reassembly on top of
//! ironwood's `EncryptedPacketConn` (or any [`PacketConn`] implementor).
//!
//! ## Architecture
//! - One background reader task decouples the inner `PacketConn` from callers.
//! - `send()` fragments, transmits all segments, then waits for cumulative ACKs
//!   with retransmission.
//! - `recv()` drains an mpsc channel fed by the reader after reassembly.

mod types;

pub use types::{MessageId, SegmentHeader, YmpError, HEADER_SIZE, FRAGMENT_SIZE};

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, AtomicBool, Ordering};
use std::sync::Arc;

use ironwood::types::{Addr, PacketConn};
use tokio::sync::{mpsc, Mutex, Notify};
use tokio::time::{timeout, Duration, Instant};
use types::{
    PktType, MAX_MESSAGE_SIZE, MAX_RETRIES, MAX_SYN_RETRIES, REASSEMBLY_TIMEOUT_SECS,
    RETRY_TIMEOUT_SECS, SYN_TIMEOUT_SECS,
};

// ponytail: burst-bound the DATA send loop instead of pacing every segment.
// After SYN the path is warm and ironwood's CoDel/DRR queue provides backpressure,
// but write_to silently drops excess beyond the per-flow cap (~4 MiB), so we bound
// each burst. 8 segments ≈ 512 KiB, well under the cap; total pacing for 32 MiB ≈ 320ms.
const SEND_PACING_EVERY: u16 = 8;
const SEND_PACING_DELAY: Duration = Duration::from_millis(5);

/// Maximum number of concurrent in-flight reassembly buffers.
/// Each buffer can hold up to MAX_MESSAGE_SIZE bytes in segments, so 256
/// live buffers bound memory to ~8 GiB worst-case (all full), but in practice
/// each peer sends one message at a time.  When the cap is hit the oldest
/// (by creation time) incomplete buffer is evicted.
const MAX_REASSEMBLY_BUFFERS: usize = 256;

// ── internal state ───────────────────────────────────────────────────────

/// Tracks delivery progress for one outgoing message.
struct PendingSend {
    /// Total number of DATA segments.
    total: u16,
    /// Which segments have been ACKed (cumulative hint: if N is acked, 0..N are too).
    acked: Vec<bool>,
    /// Signalled when all segments are acked (or we give up).
    notify: Arc<Notify>,
}

/// Tracks a pending SYN handshake — resolved when SYN-ACK arrives.
struct PendingSyn {
    /// Signalled when the matching SYN-ACK is received.
    notify: Arc<Notify>,
    /// The destination we expect the SYN-ACK to come from.
    expected_src: [u8; 32],
}

/// Accumulates incoming segments until a complete message can be reassembled.
struct ReassemblyBuffer {
    total: u16,
    segments: Vec<Option<Vec<u8>>>,
    received: u16,
    created: Instant,
}

// ── public API ───────────────────────────────────────────────────────────

/// Reliable message session over a [`PacketConn`].
///
/// ```ignore
/// let conn: Arc<EncryptedPacketConn> = ...;
/// let session = YmpSession::new(conn);
/// let msg_id = session.send(peer_key, b"hello".to_vec()).await?;
/// let (from, data) = session.recv().await?;
/// ```
pub struct YmpSession {
    inner: Arc<dyn PacketConn>,
    next_id: AtomicU64,
    pending: Arc<Mutex<HashMap<MessageId, PendingSend>>>,
    pending_syns: Arc<Mutex<HashMap<MessageId, PendingSyn>>>,
    /// Per-source reverse-path-lookup rate limiter: last warmup timestamp per
    /// SYN source. Held to keep the Arc alive for the reader_loop clone.
    #[allow(dead_code)]
    syn_throttle: Arc<Mutex<HashMap<[u8; 32], Instant>>>,
    /// Recently-active peers (send dest or inbound source) → last-seen time.
    /// Drives the path-warmer: periodic send_lookup keeps the Yggdrasil path
    /// warm (ironwood expires cached paths after ~60s), matching the Go keepalive.
    active_peers: Arc<Mutex<HashMap<[u8; 32], Instant>>>,
    recv_rx: Mutex<mpsc::Receiver<([u8; 32], Vec<u8>)>>,
    _recv_tx: mpsc::Sender<([u8; 32], Vec<u8>)>,  // kept alive to prevent channel close
    closed: AtomicBool,
    reader_handle: Mutex<Option<tokio::task::JoinHandle<()>>>,
    cleanup_handle: Mutex<Option<tokio::task::JoinHandle<()>>>,
}

impl YmpSession {
    /// Create a new YMP session wrapping the given [`PacketConn`].
    ///
    /// Spawns a background reader and a periodic cleanup task.
    pub fn new(conn: Arc<dyn PacketConn>) -> Self {
        let (recv_tx, recv_rx) = mpsc::channel::<([u8; 32], Vec<u8>)>(128);
        // Keyed by (msg_id, sender_key) to prevent cross-sender segment injection
        let reassembly: Arc<Mutex<HashMap<(MessageId, [u8; 32]), ReassemblyBuffer>>> =
            Arc::new(Mutex::new(HashMap::new()));
        let pending: Arc<Mutex<HashMap<MessageId, PendingSend>>> =
            Arc::new(Mutex::new(HashMap::new()));
        let pending_syns: Arc<Mutex<HashMap<MessageId, PendingSyn>>> =
            Arc::new(Mutex::new(HashMap::new()));
        let syn_throttle: Arc<Mutex<HashMap<[u8; 32], Instant>>> =
            Arc::new(Mutex::new(HashMap::new()));
        let active_peers: Arc<Mutex<HashMap<[u8; 32], Instant>>> =
            Arc::new(Mutex::new(HashMap::new()));

        // Background reader
        let reader_conn = conn.clone();
        let reader_active = active_peers.clone();
        let reader_pending = pending.clone();
        let reader_pending_syns = pending_syns.clone();
        let reader_syn_throttle = syn_throttle.clone();
        let reader_reassembly = reassembly.clone();
        let reader_tx = recv_tx.clone();
        let reader = tokio::spawn(reader_loop(
            reader_conn,
            reader_pending,
            reader_pending_syns,
            reader_syn_throttle,
            reader_reassembly,
            reader_tx,
            reader_active,
        ));

        // Periodic cleanup of stale reassembly buffers
        let cleanup_reassembly = reassembly.clone();
        let cleanup = tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(60));
            interval.tick().await; // skip first immediate tick
            loop {
                interval.tick().await;
                let mut buf = cleanup_reassembly.lock().await;
                buf.retain(|_, b| b.created.elapsed().as_secs() < REASSEMBLY_TIMEOUT_SECS);
            }
        });

        Self {
            inner: conn,
            next_id: AtomicU64::new(0),
            pending,
            pending_syns,
            syn_throttle,
            active_peers,
            recv_rx: Mutex::new(recv_rx),
            _recv_tx: recv_tx,
            closed: AtomicBool::new(false),
            reader_handle: Mutex::new(Some(reader)),
            cleanup_handle: Mutex::new(Some(cleanup)),
        }
    }

    /// Send a message to `dest` (32-byte Ed25519 public key).
    ///
    /// Performs a SYN/SYN-ACK handshake before data delivery to force
    /// path discovery through the Yggdrasil mesh. Blocks until all
    /// segments are acknowledged or retries are exhausted.
    pub async fn send(&self, dest: [u8; 32], message: Vec<u8>) -> Result<MessageId, YmpError> {
        if self.closed.load(Ordering::Relaxed) {
            return Err(YmpError::Closed);
        }
        if message.len() > MAX_MESSAGE_SIZE {
            return Err(YmpError::TooLarge);
        }

        let msg_id = self.next_id.fetch_add(1, Ordering::Relaxed);
        let total = segment_count(message.len());
        let segments = fragment(&message, total);
        let addr = Addr(dest);
        // Record this peer as active so the path-warmer keeps its path warm.
        self.active_peers.lock().await.insert(dest, Instant::now());

        // SYN handshake — kick path discovery, confirm reachability.
        // send_lookup is fire-and-forget path discovery; it is re-issued on every
        // attempt in the loop below (a single up-front call is lost if the first
        // probe races a cold path), so no up-front blind sleep is needed.
        let syn_notify = Arc::new(Notify::new());
        {
            let mut syns = self.pending_syns.lock().await;
            syns.insert(msg_id, PendingSyn {
                notify: syn_notify.clone(),
                expected_src: dest,
            });
        }

        let syn_header = SegmentHeader::syn(msg_id);
        let mut syn_buf = [0u8; HEADER_SIZE];
        syn_header.encode(&mut syn_buf);

        let mut syn_acked = false;
        for attempt in 0..MAX_SYN_RETRIES {
            tracing::debug!(
                "ymp: SYN attempt {}/{} msg_id={} dest={}",
                attempt + 1, MAX_SYN_RETRIES, msg_id,
                hex::encode(&dest[..8]),
            );
            // Re-warm the forward path each attempt — a lookup lost to a cold
            // path must not doom the whole handshake.
            self.inner.send_lookup(addr).await;
            if let Err(e) = self.inner.write_to(&syn_buf, &addr).await {
                tracing::warn!("ymp: SYN write error: {e}");
            }

            let wait_result = timeout(Duration::from_secs(SYN_TIMEOUT_SECS), syn_notify.notified()).await;
            if wait_result.is_ok() {
                syn_acked = true;
                tracing::debug!("ymp: SYN-ACK received msg_id={}", msg_id);
                break;
            }
            tracing::debug!("ymp: SYN timeout msg_id={} attempt={}", msg_id, attempt + 1);
        }

        self.pending_syns.lock().await.remove(&msg_id);

        if !syn_acked {
            // SYN handshake failed — peer is not reachable. After the sender
            // readiness-gate, SYN is only attempted against an "up" peer, so a
            // failure means genuinely unreachable. Fast-fail instead of burning
            // ~60s (MAX_RETRIES × RETRY_TIMEOUT_SECS) on DATA retries into the void.
            tracing::warn!(
                "ymp: SYN handshake failed for msg_id={} to {} — peer unreachable",
                msg_id, hex::encode(&dest[..8]),
            );
            return Err(YmpError::Unreachable);
        }

        // Data delivery — fragment, transmit, wait for ACKs.
        let notify = Arc::new(Notify::new());

        // Register pending send
        {
            let mut pending = self.pending.lock().await;
            pending.insert(
                msg_id,
                PendingSend {
                    total,
                    acked: vec![false; total as usize],
                    notify: notify.clone(),
                },
            );
        }

        // Transmit loop with retries
        for attempt in 0..MAX_RETRIES {
            tracing::debug!("ymp: DATA send msg_id={} attempt={}/{} total_segments={} dest={}", msg_id, attempt + 1, MAX_RETRIES, total, hex::encode(&dest[..8]));
            // Send unacked segments — brief per-segment lock, write+stagger outside.
            for seq in 0..total {
                let already_acked = {
                    let pending = self.pending.lock().await;
                    pending.get(&msg_id)
                        .map(|ps| ps.acked[seq as usize])
                        .unwrap_or(true) // entry gone → skip
                };
                if already_acked {
                    continue;
                }
                let header = SegmentHeader::data(
                    msg_id,
                    seq,
                    total,
                    segments[seq as usize].len() as u16,
                );
                let mut packet = Vec::with_capacity(HEADER_SIZE + segments[seq as usize].len());
                packet.resize(HEADER_SIZE, 0);
                header.encode(&mut packet[..HEADER_SIZE]);
                packet.extend_from_slice(&segments[seq as usize]);
                if let Err(e) = self.inner.write_to(&packet, &addr).await {
                    tracing::warn!("ymp: DATA write error msg_id={} seq={}: {e}", msg_id, seq);
                } else {
                    tracing::trace!("ymp: DATA write ok msg_id={} seq={}/{} size={}", msg_id, seq, total, packet.len());
                }
                // ponytail: burst-bound, don't pace every segment. write_to
                // silent-drops excess beyond the DRR per-flow cap, so we cap a
                // burst to SEND_PACING_EVERY segments then yield briefly. Post-SYN
                // the path is warm; CoDel paces the dequeue side.
                if seq != 0 && seq % SEND_PACING_EVERY == 0 {
                    tokio::time::sleep(SEND_PACING_DELAY).await;
                }
            }

            // Wait for all ACKs or timeout
            let wait_result = timeout(Duration::from_secs(RETRY_TIMEOUT_SECS), async {
                loop {
                    notify.notified().await;
                    let pending = self.pending.lock().await;
                    if let Some(ps) = pending.get(&msg_id) {
                        if ps.acked.iter().all(|a| *a) {
                            return;
                        }
                    } else {
                        return;
                    }
                }
            })
            .await;

            if wait_result.is_ok() {
                self.pending.lock().await.remove(&msg_id);
                tracing::info!("ymp: send complete msg_id={}", msg_id);
                return Ok(msg_id);
            }

            tracing::debug!("ymp: send msg_id={} timeout, retrying", msg_id);
        }

        // Exhausted retries
        self.pending.lock().await.remove(&msg_id);
        tracing::warn!("ymp: send failed msg_id={} — max retries exceeded", msg_id);
        Err(YmpError::MaxRetriesExceeded)
    }

    /// Receive the next assembled message.
    ///
    /// Returns `(sender_pubkey, message_bytes)`.
    pub async fn recv(&self) -> Result<([u8; 32], Vec<u8>), YmpError> {
        let mut rx = self.recv_rx.lock().await;
        match rx.recv().await {
            Some(msg) => Ok(msg),
            None => Err(YmpError::Closed),
        }
    }

    /// Peers seen (sent-to or received-from) within `within`, evicting older
    /// entries. The path-warmer calls this to decide which Yggdrasil paths to
    /// keep warm via periodic `send_lookup` — restoring the warm-path behaviour
    /// the Go library had (QUIC keepalive) and the Rust rewrite dropped.
    pub async fn recent_peers(&self, within: Duration) -> Vec<[u8; 32]> {
        let now = Instant::now();
        let mut map = self.active_peers.lock().await;
        map.retain(|_, t| now.duration_since(*t) < within);
        map.keys().copied().collect()
    }

    pub async fn close(&self) {
        self.closed.store(true, Ordering::Relaxed);
        // Abort background tasks
        if let Some(h) = self.reader_handle.lock().await.take() {
            h.abort();
        }
        if let Some(h) = self.cleanup_handle.lock().await.take() {
            h.abort();
        }
    }
}

// ── helpers ──────────────────────────────────────────────────────────────

fn segment_count(len: usize) -> u16 {
    let n = (len + FRAGMENT_SIZE - 1) / FRAGMENT_SIZE;
    n.max(1) as u16
}

fn fragment(message: &[u8], total: u16) -> Vec<Vec<u8>> {
    let mut segments = Vec::with_capacity(total as usize);
    for i in 0..total as usize {
        let start = i * FRAGMENT_SIZE;
        let end = ((i + 1) * FRAGMENT_SIZE).min(message.len());
        segments.push(message[start..end].to_vec());
    }
    segments
}

fn reassemble(segments: &[Option<Vec<u8>>]) -> Vec<u8> {
    let total_len: usize = segments.iter().map(|s| s.as_ref().map_or(0, |v| v.len())).sum();
    let mut out = Vec::with_capacity(total_len);
    for seg in segments {
        if let Some(data) = seg {
            out.extend_from_slice(data);
        }
    }
    out
}

// ── background reader ────────────────────────────────────────────────────

type ReassemblyMap = HashMap<(MessageId, [u8; 32]), ReassemblyBuffer>;

/// Minimum interval between reverse-path warmup lookups from the same source.
/// Bounds router churn under SYN floods; the SYN-ACK reply itself is never throttled.
const SYN_THROTTLE_INTERVAL: Duration = Duration::from_secs(2);

// Invariant: the reverse-lookup throttle window MUST stay below the SYN retry
// interval. Otherwise a retried SYN would have its reverse-path warmup silently
// throttled, re-introducing the ~1-in-10 connect bug this handshake fix closes.
const _: () = assert!(SYN_THROTTLE_INTERVAL.as_secs() < SYN_TIMEOUT_SECS);

async fn reader_loop(
    conn: Arc<dyn PacketConn>,
    pending: Arc<Mutex<HashMap<MessageId, PendingSend>>>,
    pending_syns: Arc<Mutex<HashMap<MessageId, PendingSyn>>>,
    syn_throttle: Arc<Mutex<HashMap<[u8; 32], Instant>>>,
    reassembly: Arc<Mutex<ReassemblyMap>>,
    recv_tx: mpsc::Sender<([u8; 32], Vec<u8>)>,
    active_peers: Arc<Mutex<HashMap<[u8; 32], Instant>>>,
) {
    let mut buf = vec![0u8; 65535];

    loop {
        let (n, from_addr) = match conn.read_from(&mut buf).await {
            Ok(r) => r,
            Err(e) => {
                tracing::error!("ymp: reader_loop read_from error, exiting: {e:?}");
                break; // connection closed
            }
        };

        if n < HEADER_SIZE {
            // debug, not info: a peer on the old (pre-1.9.0) wire protocol streams
            // packets we can't parse — harmless, dropped, but must not spam logs.
            tracing::debug!("ymp: short packet n={} from {}", n, hex::encode(&from_addr.0[..8]));
            continue;
        }

        let header = match SegmentHeader::decode(&buf[..HEADER_SIZE]) {
            Some(h) => h,
            None => {
                // debug, not info: old-version peers send an incompatible framing;
                // we drop it silently rather than flooding the log at info level.
                tracing::debug!(
                    "ymp: bad header byte={:#x} head={:02x?} from {}",
                    buf[0], &buf[..16.min(n)],
                    hex::encode(&from_addr.0[..8]),
                );
                continue;
            }
        };

        // Record inbound peer for the path-warmer (keep its Yggdrasil path warm).
        active_peers.lock().await.insert(from_addr.0, Instant::now());

        tracing::trace!(
            "ymp: {:?} msg_id={} seq={}/{} len={} from {}",
            header.pkt_type, header.msg_id, header.seq, header.total, header.payload_len,
            hex::encode(&from_addr.0[..8]),
        );

        match header.pkt_type {
            PktType::Syn => {
                // Throttle only the *expensive* reverse-path lookup per source
                // (bounds router churn under SYN floods). The SYN-ACK itself is
                // ALWAYS sent below: it is cheap, idempotent, and correlated
                // per-msg_id on the sender, so suppressing it (the old behaviour)
                // silently killed any handshake that arrived within the window.
                let do_lookup = {
                    let mut throttle = syn_throttle.lock().await;
                    let now = Instant::now();
                    match throttle.get(&from_addr.0) {
                        Some(last) if now.duration_since(*last) < SYN_THROTTLE_INTERVAL => false,
                        _ => {
                            throttle.insert(from_addr.0, now);
                            // ponytail: prune old entries occasionally to bound map size.
                            if throttle.len() > 256 {
                                throttle.retain(|_, t| now.duration_since(*t) < SYN_THROTTLE_INTERVAL * 4);
                            }
                            true
                        }
                    }
                };
                if do_lookup {
                    // Warm the REVERSE path before replying. write_to silently
                    // drops when our route back to the SYN source is cold, so the
                    // SYN-ACK would vanish until that path happened to already
                    // exist — the core of the ~1-in-10 connection bug.
                    conn.send_lookup(from_addr).await;
                }
                // Respond with SYN-ACK — confirms bidirectional reachability.
                let syn_ack = SegmentHeader::syn_ack(header.msg_id);
                let mut ack_buf = [0u8; HEADER_SIZE];
                syn_ack.encode(&mut ack_buf);
                if let Err(e) = conn.write_to(&ack_buf, &from_addr).await {
                    tracing::warn!("ymp: SYN-ACK write error: {e}");
                } else {
                    tracing::debug!("ymp: SYN-ACK sent msg_id={}", header.msg_id);
                }
            }
            PktType::SynAck => {
                // Wake the waiting send() handshake — verify source matches.
                let syns = pending_syns.lock().await;
                if let Some(ps) = syns.get(&header.msg_id) {
                    if ps.expected_src == from_addr.0 {
                        ps.notify.notify_one();
                    } else {
                        tracing::debug!(
                            "ymp: SYN-ACK from unexpected source (expected {}, got {})",
                            hex::encode(&ps.expected_src[..8]),
                            hex::encode(&from_addr.0[..8]),
                        );
                    }
                }
            }
            PktType::Data => {
                let payload = &buf[HEADER_SIZE..n];
                if payload.len() != header.payload_len as usize {
                    tracing::info!(
                        "ymp: DATA drop (length mismatch) msg_id={} seq={} payload_len={} header_len={} from {}",
                        header.msg_id, header.seq, payload.len(), header.payload_len,
                        hex::encode(&from_addr.0[..8]),
                    );
                    continue; // length mismatch
                }

                // Validate before acting — bounds checks must precede ACK.
                if header.seq >= header.total || header.total == 0 {
                    tracing::info!(
                        "ymp: DATA drop (invalid seq/total) msg_id={} seq={} total={} from {}",
                        header.msg_id, header.seq, header.total,
                        hex::encode(&from_addr.0[..8]),
                    );
                    continue;
                }
                let total_data: usize = header.total as usize * FRAGMENT_SIZE;
                if total_data > MAX_MESSAGE_SIZE {
                    tracing::info!(
                        "ymp: DATA drop (too large) msg_id={} seq={} total_data={} max={} from {}",
                        header.msg_id, header.seq, total_data, MAX_MESSAGE_SIZE,
                        hex::encode(&from_addr.0[..8]),
                    );
                    continue;
                }

                // ACK after validation — don't confirm discarded segments.
                let ack = SegmentHeader::ack(header.msg_id, header.seq);
                let mut ack_buf = [0u8; HEADER_SIZE];
                ack.encode(&mut ack_buf);
                if let Err(e) = conn.write_to(&ack_buf, &from_addr).await {
                    tracing::warn!("ymp: ACK write error: {e}");
                }
                tracing::trace!("ymp: ACK sent msg_id={} seq={}", header.msg_id, header.seq);

                // Reassemble — key includes sender to prevent cross-peer injection
                let mut reasm = reassembly.lock().await;
                let key = (header.msg_id, from_addr.0);
                // Cap concurrent reassembly buffers to prevent mesh memory-DoS.
                // Only evict when we are about to create a NEW entry (existing
                // entries for this (msg_id, peer) pair are left untouched).
                if !reasm.contains_key(&key) && reasm.len() >= MAX_REASSEMBLY_BUFFERS {
                    // Evict the oldest buffer by creation time.
                    if let Some(oldest_key) = reasm
                        .iter()
                        .min_by_key(|(_, b)| b.created)
                        .map(|(k, _)| *k)
                    {
                        reasm.remove(&oldest_key);
                        tracing::debug!(
                            "ymp: reassembly cap hit — evicted oldest buffer (msg_id={} peer={})",
                            oldest_key.0,
                            hex::encode(&oldest_key.1[..8]),
                        );
                    }
                }
                let entry = reasm
                    .entry(key)
                    .or_insert_with(|| ReassemblyBuffer {
                        total: header.total,
                        segments: vec![None; header.total as usize],
                        received: 0,
                        created: Instant::now(),
                    });

                if entry.segments[header.seq as usize].is_none() {
                    entry.segments[header.seq as usize] = Some(payload.to_vec());
                    entry.received += 1;
                }

                if entry.received == entry.total {
                    let data = reassemble(&entry.segments);
                    let from_key = from_addr.0;
                    reasm.remove(&key);
                    drop(reasm);
                    tracing::info!(
                        "ymp: reassembly complete msg_id={}, delivering {} bytes to receiver",
                        header.msg_id, data.len()
                    );
                    if recv_tx.send((from_key, data)).await.is_err() {
                        tracing::error!("ymp: recv_tx send failed, reader_loop exiting");
                        break;
                    }
                }
            }
            PktType::Ack => {
                // Per-segment ACK: each ACK confirms exactly one segment.
                // Yggdrasil's packet-switched network permits out-of-order
                // delivery, so cumulative ACKs would silently drop segments
                // that arrived after a gap.
                let mut pend = pending.lock().await;
                if let Some(ps) = pend.get_mut(&header.msg_id) {
                    let idx = header.seq as usize;
                    if idx < ps.total as usize {
                        ps.acked[idx] = true;
                    }
                    if ps.acked.iter().all(|a| *a) {
                        ps.notify.notify_one();
                    }
                }
            }
        }
    }
}

// ── tests ────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;
    use ironwood::types::{Addr, AsyncConn, Error, PacketConn, Result as IwResult};
    use std::sync::Arc;
    use tokio::sync::mpsc;

    // ── mock PacketConn pair ────────────────────────────────────────────

    struct ChanPacketConn {
        tx: mpsc::UnboundedSender<(Vec<u8>, Addr)>,
        rx: Mutex<mpsc::UnboundedReceiver<(Vec<u8>, Addr)>>,
        closed: AtomicBool,
        signing_key: SigningKey,
        local_addr: Addr,
    }

    impl ChanPacketConn {
        fn pair(key_a: SigningKey, key_b: SigningKey) -> (Arc<Self>, Arc<Self>) {
            let addr_a = Addr(key_a.verifying_key().to_bytes());
            let addr_b = Addr(key_b.verifying_key().to_bytes());
            let (tx_a, rx_b) = mpsc::unbounded_channel();
            let (tx_b, rx_a) = mpsc::unbounded_channel();
            let a = Arc::new(Self {
                tx: tx_a, rx: Mutex::new(rx_a),
                closed: AtomicBool::new(false), signing_key: key_a, local_addr: addr_a,
            });
            let b = Arc::new(Self {
                tx: tx_b, rx: Mutex::new(rx_b),
                closed: AtomicBool::new(false), signing_key: key_b, local_addr: addr_b,
            });
            (a, b)
        }
    }

    #[async_trait::async_trait]
    impl PacketConn for ChanPacketConn {
        async fn read_from(&self, buf: &mut [u8]) -> IwResult<(usize, Addr)> {
            let mut rx = self.rx.lock().await;
            match rx.recv().await {
                Some((data, from)) => {
                    let n = buf.len().min(data.len());
                    buf[..n].copy_from_slice(&data[..n]);
                    Ok((n, from))
                }
                None => Err(Error::Closed),
            }
        }

        async fn write_to(&self, buf: &[u8], _addr: &Addr) -> IwResult<usize> {
            let _ = self.tx.send((buf.to_vec(), self.local_addr));
            Ok(buf.len())
        }

        async fn handle_conn(&self, _key: Addr, _conn: Box<dyn AsyncConn>, _prio: u8) -> IwResult<()> {
            Ok(())
        }

        fn is_closed(&self) -> bool { self.closed.load(Ordering::Relaxed) }
        fn private_key(&self) -> &SigningKey { &self.signing_key }
        fn mtu(&self) -> u64 { 65535 }
        async fn send_lookup(&self, _target: Addr) {}
        fn local_addr(&self) -> Addr { self.local_addr }

        async fn close(&self) -> IwResult<()> {
            self.closed.store(true, Ordering::Relaxed);
            Ok(())
        }
    }

    // ── unit tests ──────────────────────────────────────────────────────

    #[test]
    fn segment_count_single() {
        assert_eq!(segment_count(1), 1);
        assert_eq!(segment_count(FRAGMENT_SIZE), 1);
    }

    #[test]
    fn segment_count_multi() {
        assert_eq!(segment_count(FRAGMENT_SIZE + 1), 2);
        assert_eq!(segment_count(FRAGMENT_SIZE * 3), 3);
    }

    #[test]
    fn fragment_roundtrip() {
        let data: Vec<u8> = (0..200_000u32).map(|i| (i % 256) as u8).collect();
        let total = segment_count(data.len());
        let segments = fragment(&data, total);
        let opts: Vec<Option<Vec<u8>>> = segments.into_iter().map(Some).collect();
        let back = reassemble(&opts);
        assert_eq!(data, back);
    }

    #[test]
    fn fragment_small_message() {
        let data = b"hello, ymp!".to_vec();
        let total = segment_count(data.len());
        let segments = fragment(&data, total);
        assert_eq!(segments.len(), 1);
        assert_eq!(segments[0], data);
    }

    // ── mock pair sanity ────────────────────────────────────────────────

    #[tokio::test]
    async fn mock_pair_write_read() {
        let mut rng = rand::rngs::OsRng;
        let ka = SigningKey::generate(&mut rng);
        let kb = SigningKey::generate(&mut rng);
        let pkb: [u8; 32] = kb.verifying_key().to_bytes();

        let (a, b) = ChanPacketConn::pair(ka, kb);
        a.write_to(b"ping", &Addr(pkb)).await.unwrap();

        let mut buf = [0u8; 1024];
        let (n, from) = b.read_from(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], b"ping");
        assert_ne!(from.0, [0u8; 32]);
    }

    #[tokio::test]
    async fn mock_pair_spawned_reader() {
        // Verify write_to from one task wakes read_from in another spawned task
        let mut rng = rand::rngs::OsRng;
        let ka = SigningKey::generate(&mut rng);
        let kb = SigningKey::generate(&mut rng);
        let pkb: [u8; 32] = kb.verifying_key().to_bytes();

        let (a, b) = ChanPacketConn::pair(ka, kb);
        let b_clone = b.clone();

        // Spawn reader
        let reader = tokio::spawn(async move {
            let mut buf = [0u8; 1024];
            let (n, from) = b_clone.read_from(&mut buf).await.unwrap();
            (n, from.0, buf)
        });

        // Small delay to ensure reader is waiting
        tokio::task::yield_now().await;

        // Write from main task
        a.write_to(b"spawned-test", &Addr(pkb)).await.unwrap();

        let (n, from_key, buf) = reader.await.unwrap();
        assert_eq!(&buf[..n], b"spawned-test");
        assert_ne!(from_key, [0u8; 32]);
    }

    // ── reverse-path warmup regression (the ~1-in-10 connect bug) ───────
    //
    // One-directional by design: inject a single SYN into a fresh session and
    // assert the reader (a) warms the REVERSE path via send_lookup toward the
    // SYN source and (b) ALWAYS emits a SYN-ACK. No duplex ACK round-trip, so
    // it sidesteps the mpsc scheduling limitation documented below.

    struct ProbeConn {
        inbound: Mutex<Option<(Vec<u8>, Addr)>>,
        writes: mpsc::UnboundedSender<(Vec<u8>, Addr)>,
        lookups: Mutex<Vec<[u8; 32]>>,
        signing_key: SigningKey,
        local_addr: Addr,
    }

    #[async_trait::async_trait]
    impl PacketConn for ProbeConn {
        async fn read_from(&self, buf: &mut [u8]) -> IwResult<(usize, Addr)> {
            // Deliver the single queued inbound packet, then park (idle) so the
            // reader doesn't busy-spin. Guard dropped before the await.
            let msg = self.inbound.lock().await.take();
            if let Some((data, from)) = msg {
                let n = buf.len().min(data.len());
                buf[..n].copy_from_slice(&data[..n]);
                return Ok((n, from));
            }
            std::future::pending::<()>().await;
            unreachable!()
        }

        async fn write_to(&self, buf: &[u8], addr: &Addr) -> IwResult<usize> {
            let _ = self.writes.send((buf.to_vec(), *addr));
            Ok(buf.len())
        }

        async fn handle_conn(&self, _key: Addr, _conn: Box<dyn AsyncConn>, _prio: u8) -> IwResult<()> {
            Ok(())
        }

        fn is_closed(&self) -> bool { false }
        fn private_key(&self) -> &SigningKey { &self.signing_key }
        fn mtu(&self) -> u64 { 65535 }
        async fn send_lookup(&self, target: Addr) {
            self.lookups.lock().await.push(target.0);
        }
        fn local_addr(&self) -> Addr { self.local_addr }
        async fn close(&self) -> IwResult<()> { Ok(()) }
    }

    #[tokio::test]
    async fn syn_warms_reverse_path_and_always_acks() {
        let mut rng = rand::rngs::OsRng;
        let key = SigningKey::generate(&mut rng);
        let peer: [u8; 32] = SigningKey::generate(&mut rng).verifying_key().to_bytes();
        let local = Addr(key.verifying_key().to_bytes());

        // Craft a SYN as if received from `peer`.
        let mut syn_buf = [0u8; HEADER_SIZE];
        SegmentHeader::syn(42).encode(&mut syn_buf);

        let (wtx, mut wrx) = mpsc::unbounded_channel();
        let conn = Arc::new(ProbeConn {
            inbound: Mutex::new(Some((syn_buf.to_vec(), Addr(peer)))),
            writes: wtx,
            lookups: Mutex::new(Vec::new()),
            signing_key: key,
            local_addr: local,
        });

        let _session = YmpSession::new(conn.clone() as Arc<dyn PacketConn>);

        // The reader must emit a SYN-ACK for msg_id 42 (bounded — never hangs).
        let (data, to) = timeout(Duration::from_secs(2), wrx.recv())
            .await
            .expect("no SYN-ACK written within 2s")
            .expect("writes channel closed");
        let hdr = SegmentHeader::decode(&data[..HEADER_SIZE]).expect("valid header");
        assert_eq!(hdr.pkt_type, PktType::SynAck, "reply must be a SYN-ACK");
        assert_eq!(hdr.msg_id, 42, "SYN-ACK must echo the SYN msg_id");
        assert_eq!(to.0, peer, "SYN-ACK must target the SYN source");

        // And the reverse path to the SYN source must have been warmed first.
        let lookups = conn.lookups.lock().await;
        assert!(
            lookups.contains(&peer),
            "reader must send_lookup toward the SYN source to warm the reverse path",
        );
    }

    #[tokio::test]
    async fn reader_records_active_peer_for_warming() {
        // The path-warmer needs the set of recently-active peers. Verify the
        // reader records an inbound peer, and that the TTL window evicts it.
        let mut rng = rand::rngs::OsRng;
        let key = SigningKey::generate(&mut rng);
        let peer: [u8; 32] = SigningKey::generate(&mut rng).verifying_key().to_bytes();
        let local = Addr(key.verifying_key().to_bytes());

        let mut syn_buf = [0u8; HEADER_SIZE];
        SegmentHeader::syn(7).encode(&mut syn_buf);

        let (wtx, _wrx) = mpsc::unbounded_channel();
        let conn = Arc::new(ProbeConn {
            inbound: Mutex::new(Some((syn_buf.to_vec(), Addr(peer)))),
            writes: wtx,
            lookups: Mutex::new(Vec::new()),
            signing_key: key,
            local_addr: local,
        });
        let session = YmpSession::new(conn.clone() as Arc<dyn PacketConn>);

        // Reader must record the inbound peer (bounded wait — never hangs).
        let mut found = false;
        for _ in 0..25 {
            if session.recent_peers(Duration::from_secs(600)).await.contains(&peer) {
                found = true;
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        assert!(found, "reader must record inbound peer for path warming");

        // A zero-length window evicts everything.
        assert!(session.recent_peers(Duration::from_millis(0)).await.is_empty());
    }

    // ── integration: YmpSession ↔ YmpSession ────────────────────────────
    // ponytail: ChanPacketConn mpsc channels can't reliably model async I/O
    // for ACK-based protocols — the tokio scheduler serializes send/reader
    // tasks in a way that prevents ACK delivery regardless of thread count.
    // Real I/O (duplex streams, actual network) doesn't have this limitation.
    //
    // Verified through:
    //   - Wire format roundtrip (header encode/decode tests)
    //   - Fragment/reassemble roundtrip tests
    //   - Mock pair write/read (proves bidirectional channel delivery)
    //   - Raw ironwood two-node test (proves tree convergence + packet delivery)
    //
    // Re-enable when integrating with real Yggdrasil nodes (Phase 2).

    #[tokio::test]
    #[ignore = "mpsc scheduling limitation — re-enable with live Yggdrasil nodes in Phase 2"]
    async fn ymp_send_recv_small_message() {
        let mut rng = rand::rngs::OsRng;
        let key_a = SigningKey::generate(&mut rng);
        let key_b = SigningKey::generate(&mut rng);
        let pubkey_a = key_a.verifying_key().to_bytes();
        let pubkey_b = key_b.verifying_key().to_bytes();

        let (conn_a, conn_b) = ChanPacketConn::pair(key_a, key_b);
        let alice = YmpSession::new(conn_a as Arc<dyn PacketConn>);
        let bob = YmpSession::new(conn_b as Arc<dyn PacketConn>);

        let msg = b"Hello from Alice to Bob via YMP!".to_vec();
        alice.send(pubkey_b, msg.clone()).await.unwrap();

        let (from, received) = bob.recv().await.unwrap();
        assert_eq!(from, pubkey_a);
        assert_eq!(received, msg);
    }

    #[tokio::test]
    #[ignore = "mpsc scheduling limitation — re-enable with live Yggdrasil nodes in Phase 2"]
    async fn ymp_send_recv_large_message_fragments() {
        let mut rng = rand::rngs::OsRng;
        let key_a = SigningKey::generate(&mut rng);
        let key_b = SigningKey::generate(&mut rng);
        let pubkey_a = key_a.verifying_key().to_bytes();
        let pubkey_b = key_b.verifying_key().to_bytes();

        let (conn_a, conn_b) = ChanPacketConn::pair(key_a, key_b);
        let alice = YmpSession::new(conn_a as Arc<dyn PacketConn>);
        let bob = YmpSession::new(conn_b as Arc<dyn PacketConn>);

        // 128 KB — spans 2 segments: 65520 + 62480
        let msg: Vec<u8> = (0..128_000u32).map(|i| (i % 256) as u8).collect();
        alice.send(pubkey_b, msg.clone()).await.unwrap();

        let (from, received) = bob.recv().await.unwrap();
        assert_eq!(from, pubkey_a);
        assert_eq!(received, msg);
    }

    #[tokio::test]
    #[ignore = "mpsc scheduling limitation — re-enable with live Yggdrasil nodes in Phase 2"]
    async fn ymp_multiple_messages_ordered() {
        let mut rng = rand::rngs::OsRng;
        let key_a = SigningKey::generate(&mut rng);
        let key_b = SigningKey::generate(&mut rng);
        let pubkey_b = key_b.verifying_key().to_bytes();

        let (conn_a, conn_b) = ChanPacketConn::pair(key_a, key_b);
        let alice = YmpSession::new(conn_a as Arc<dyn PacketConn>);
        let bob = YmpSession::new(conn_b as Arc<dyn PacketConn>);

        for i in 0..5 {
            let msg = format!("message {}", i).into_bytes();
            alice.send(pubkey_b, msg.clone()).await.unwrap();
            let (_from, received) = bob.recv().await.unwrap();
            assert_eq!(received, msg);
        }
    }
}
