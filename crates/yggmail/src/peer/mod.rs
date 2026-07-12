//! Peer-to-peer mail exchange: outbound sender + inbound receiver.
//! ponytail: tokio::spawn background loops, poll-based (no event-driven complexity).

pub mod sender;
pub mod receiver;
