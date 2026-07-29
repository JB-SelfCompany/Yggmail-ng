# QUIC Mail-Overlay Transport (yggmail-ng ↔ yggmail-go interop) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace yggmail-ng's YMP mail transport with a standard QUIC/SMTP overlay (`quinn` over the Yggdrasil mesh) so Tyr rejoins the wider yggmail-go network (Thunderbird, desktop, non-Tyr nodes), then delete YMP as the single transport.

**Architecture:** A single `quinn::Endpoint` runs over a hand-written `AsyncUdpSocket` adapter that bridges quinn's `SocketAddr` world to Yggdrasil's key-addressed datagram `PacketConn` (`Core::write_to`/`read_from`). TLS is the ed25519-self-signed / accept-all-then-pin scheme already shipped for link-QUIC (`f77cb6c`, `yggdrasil::transport::tls`). Mail rides an emersion-compatible SMTP dialog over one bidirectional QUIC stream, kick-byte prefixed, byte-for-byte matching yggquic. The overlay presents the **same `send()`/`recv()` surface** as `YmpSession`, so `peer/sender.rs`, `peer/receiver.rs`, `main.rs`, and `yggmail-mobile` rewire with near-trivial diffs. Storage (`yggmail.db`, `tyr_chat.db`) and at-rest format are never touched — old DeltaChat + internal-chat history survives the transport swap.

**Tech Stack:** Rust 2024, `quinn 0.11` (`runtime-tokio`, `rustls-ring`), `rustls 0.23` (ring), `rcgen 0.14`, `x509-parser 0.18`, `tokio`, `ed25519-dalek 2`, existing `yggmail` crate (`smtp`, `storage`, `address`), `yggdrasil::transport::tls` (reused verbatim), `ironwood::PacketConn`.

**Precondition:** Phase 0 (identity stability / issue #39) is complete and shipped separately. This plan is Phases 1–3 only. The stable, portable ed25519 identity from Phase 0 is the linchpin: the same key is the mail address, the TLS cert key, and the mesh routing key.

**Invariant (do not violate in any task):** The Phase 1–3 migration is **peer-layer only**. Never recreate, migrate destructively, or change the at-rest format of `yggmail.db` (INBOX/queue) or `tyr_chat.db` (internal chat). The internal chat (`X-Tyr-Chat` over SMTP/IMAP) is transport-agnostic and survives YMP→QUIC as long as mail is delivered.

---

## Orientation: the seam these tasks build on

Read these before starting — every task assumes them:

- **Datagram seam:** `yggdrasil::core::Core::write_to(&self, buf: &[u8], addr: &Addr) -> Result<usize, ironwood::Error>` and `read_from(&self, buf: &mut [u8]) -> Result<(usize, Addr)>`. `ironwood::types::Addr(pub [u8; 32])` is an ed25519 pubkey. `Core::mtu() -> u64`, `Core::public_key() -> &[u8; 32]`.
- **Existing PacketConn adapter:** `crates/yggmail/src/core_conn.rs` — `CoreConn::new(core, signing_key) -> Arc<CoreConn>` implements `ironwood::PacketConn`. **Kept** (still the datagram source for the QUIC adapter). Only `ymp/` is deleted in Phase 3.
- **Reused TLS (verbatim, `yggdrasil::transport::tls`):** `generate_self_signed_cert(&SigningKey) -> Result<TlsCertMaterial, String>`; `TlsCertMaterial::cert_chain() -> Vec<CertificateDer<'static>>`, `::private_key() -> Result<PrivateKeyDer<'static>, String>`; `create_server_config(certs, key) -> Result<Arc<rustls::ServerConfig>, String>` (accept-all client verifier, `alpn_protocols = vec![]`, TLS1.3); `create_client_config(certs, key) -> Result<Arc<rustls::ClientConfig>, String>` (accept-all server verifier, sends client cert); `extract_ed25519_pubkey_from_cert(&[u8]) -> Option<[u8; 32]>`. Reachable from `yggmail` because `yggdrasil::transport` and `transport::tls` are `pub` and NOT feature-gated.
- **Reused mail plumbing:** `crates/yggmail/src/address.rs` — `parse_address(&str) -> Option<[u8;32]>`, `create_address(&[u8;32]) -> String`. `crates/yggmail/src/storage/mod.rs` — `mail_insert_inbox_dedup(&self, from_key: &[u8;32], raw: &[u8]) -> Result<Option<u32>, rusqlite::Error>` (dedup: `Ok(None)` = duplicate).
- **YMP surface being replaced (mirror it):** `YmpSession::send(&self, dest: [u8;32], message: Vec<u8>) -> Result<MessageId, YmpError>` and `recv(&self) -> Result<([u8;32], Vec<u8>), YmpError>`. Callers: `crates/yggmail/src/main.rs:116-128`, `crates/yggmail-mobile/src/lib.rs:175-230`, `crates/yggmail/src/peer/{sender,receiver}.rs`.
- **quinn 0.11 `AsyncUdpSocket` contract (confirmed against docs.rs/quinn/0.11.8):**
  ```rust
  pub trait AsyncUdpSocket: Send + Sync + Debug + 'static {
      fn create_io_poller(self: Arc<Self>) -> Pin<Box<dyn UdpPoller>>;
      fn try_send(&self, transmit: &quinn::udp::Transmit<'_>) -> io::Result<()>;
      fn poll_recv(&self, cx: &mut Context<'_>, bufs: &mut [IoSliceMut<'_>], meta: &mut [quinn::udp::RecvMeta]) -> Poll<io::Result<usize>>;
      fn local_addr(&self) -> io::Result<SocketAddr>;
      // provided: max_transmit_segments/max_receive_segments/may_fragment
  }
  pub trait UdpPoller: Send + Sync + Debug + 'static {
      fn poll_writable(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>>;
  }
  // Endpoint::new_with_abstract_socket(EndpointConfig, Option<ServerConfig>, Arc<dyn AsyncUdpSocket>, Arc<dyn Runtime>) -> io::Result<Endpoint>
  ```

---

## File Structure

**New module:** `crates/yggmail/src/quic/` — the mail overlay. Distinct from `yggdrasil::transport::quic` (that is the *peering* layer, `pub(crate)`, not reused).

| File | Responsibility |
|------|----------------|
| `crates/yggmail/src/quic/mod.rs` | `QuicOverlay` (single endpoint: connect + accept), transport config, `peer_key(&Connection)` pinning helper, module wiring. |
| `crates/yggmail/src/quic/addr_table.rs` | `AddrTable` — bidirectional map between 32-byte keys and synthetic `SocketAddr`s that quinn requires. |
| `crates/yggmail/src/quic/udp_adapter.rs` | `CoreUdpSocket` — `quinn::AsyncUdpSocket` over `Arc<dyn PacketConn>` with async send/recv pumps. |
| `crates/yggmail/src/quic/smtp_overlay.rs` | `overlay_serve_stream` (inbound SMTP dialog → `(from_key, rfc5322)`) + `overlay_send_stream` (outbound dialog), generic over `AsyncRead`/`AsyncWrite`. Kick-byte lives at the QUIC-stream boundary in `transport.rs`. |
| `crates/yggmail/src/quic/transport.rs` | `QuicMailTransport` — the `YmpSession`-shaped facade: `send()`/`recv()`, connection cache, accept loop, kick-byte framing. |

**Modified:**
- `crates/yggmail/Cargo.toml` — add `quinn` dep.
- `crates/yggmail/src/lib.rs` — `pub mod quic;`
- `crates/yggmail/src/peer/sender.rs`, `receiver.rs` — retype `YmpSession` → `QuicMailTransport`.
- `crates/yggmail/src/main.rs`, `crates/yggmail-mobile/src/lib.rs` — construct `QuicMailTransport` instead of `YmpSession`.
- Phase 3: delete `crates/yggmail/src/ymp/`, remove `pub mod ymp` + re-exports from `lib.rs`.

---

# PHASE 1 — QUIC overlay spike (de-risk the transport first)

Goal: one raw QUIC stream new↔old across the mesh. This phase ends with a **hermetic loopback test** (quinn client+server over an in-memory `PacketConn` pair) plus a **manual live-interop checklist** against a real yggmail-go node. No mail yet.

---

### Task 1: Add quinn dependency + module skeleton

**Files:**
- Modify: `crates/yggmail/Cargo.toml`
- Modify: `crates/yggmail/src/lib.rs:1-11`
- Create: `crates/yggmail/src/quic/mod.rs`

- [ ] **Step 1: Add quinn to `crates/yggmail/Cargo.toml`**

In the `[dependencies]` table (after the existing `async-trait = "0.1"` line), add:

```toml
# QUIC mail overlay (quinn over the Yggdrasil mesh, replacing YMP).
# Same versions already resolved in-tree for yggdrasil's link-QUIC feature.
quinn = { version = "0.11", default-features = false, features = ["runtime-tokio", "rustls-ring", "log"] }
```

`rustls`, `rcgen`, and `x509-parser` are transitively available through `yggdrasil` (its `transport::tls` is not feature-gated), so no direct dep is needed for the reused helpers.

- [ ] **Step 2: Declare the module in `crates/yggmail/src/lib.rs`**

Add `pub mod quic;` in alphabetical position:

```rust
pub mod address;
pub mod config;
pub mod core_conn;
pub mod imap;
pub mod peer;
pub mod quic;
pub mod smtp;
pub mod storage;
pub mod ymp;
```

- [ ] **Step 3: Create the module root `crates/yggmail/src/quic/mod.rs`**

```rust
//! Mail overlay transport: emersion-compatible SMTP over a single QUIC stream,
//! carried by `quinn` over the Yggdrasil mesh. Byte-compatible with yggmail-go's
//! yggquic transport, so Tyr interoperates with the wider yggmail network.
//!
//! Replaces the YMP reliability layer (see `crate::ymp`); both sit over the same
//! key-addressed `ironwood::PacketConn` datagram seam.

mod addr_table;
mod smtp_overlay;
mod transport;
mod udp_adapter;

pub use transport::{QuicMailTransport, QuicMailError};
```

- [ ] **Step 4: Verify it compiles (empty submodules will error — expected until Task 2+)**

Run: `cargo build -p yggmail`
Expected: FAIL with `file not found for module addr_table` (and siblings). This confirms the dep resolved and the module is wired; the submodule files come next.

- [ ] **Step 5: Commit**

```bash
git add crates/yggmail/Cargo.toml crates/yggmail/src/lib.rs crates/yggmail/src/quic/mod.rs
git commit -m "feat(quic): add quinn dep and mail-overlay module skeleton"
```

---

### Task 2: `AddrTable` — key ↔ synthetic SocketAddr map

quinn addresses peers by `SocketAddr`; the mesh addresses them by 32-byte key. `AddrTable` hands quinn a stable fake `SocketAddr` per key and translates back on send. This is yggquic's `iwt.Addr`-fake-`SocketAddr` mapping.

**Files:**
- Create: `crates/yggmail/src/quic/addr_table.rs`
- Test: inline `#[cfg(test)]` in the same file.

- [ ] **Step 1: Write the failing test**

Create `crates/yggmail/src/quic/addr_table.rs` with only the test module first:

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn same_key_maps_to_stable_addr_and_back() {
        let t = AddrTable::default();
        let key = [7u8; 32];
        let a1 = t.addr_for_key(key);
        let a2 = t.addr_for_key(key); // idempotent
        assert_eq!(a1, a2, "same key must map to the same SocketAddr");
        assert_eq!(t.key_for_addr(&a1), Some(key), "reverse lookup must round-trip");
    }

    #[test]
    fn distinct_keys_get_distinct_addrs() {
        let t = AddrTable::default();
        let a = t.addr_for_key([1u8; 32]);
        let b = t.addr_for_key([2u8; 32]);
        assert_ne!(a, b, "distinct keys must not collide");
    }

    #[test]
    fn unknown_addr_is_none() {
        let t = AddrTable::default();
        let bogus = "127.0.0.1:9".parse().unwrap();
        assert_eq!(t.key_for_addr(&bogus), None);
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test -p yggmail quic::addr_table -- --nocapture`
Expected: FAIL — `cannot find type AddrTable`.

- [ ] **Step 3: Write the implementation (prepend above the test module)**

```rust
//! Bidirectional map between 32-byte Ed25519 keys and synthetic `SocketAddr`s.
//!
//! quinn works in terms of `SocketAddr`; the Yggdrasil mesh works in terms of
//! keys. We allocate one synthetic ULA (`fd00::/8`) address per key, indexed by
//! an incrementing counter, and keep both directions so `try_send` can recover
//! the real key from quinn's chosen destination.

use std::collections::HashMap;
use std::net::{Ipv6Addr, SocketAddr, SocketAddrV6};
use std::sync::Mutex;

#[derive(Debug, Default)]
pub(crate) struct AddrTable {
    inner: Mutex<Inner>,
}

#[derive(Default)]
struct Inner {
    by_key: HashMap<[u8; 32], SocketAddr>,
    by_addr: HashMap<SocketAddr, [u8; 32]>,
    next: u32,
}

impl AddrTable {
    /// Return the synthetic `SocketAddr` for `key`, allocating on first use.
    pub(crate) fn addr_for_key(&self, key: [u8; 32]) -> SocketAddr {
        let mut g = self.inner.lock().expect("addr table poisoned");
        if let Some(a) = g.by_key.get(&key) {
            return *a;
        }
        let idx = g.next;
        g.next += 1;
        // fd00::<idx> — synthetic; port is a fixed non-zero placeholder.
        let seg = idx.to_be_bytes();
        let ip = Ipv6Addr::new(
            0xfd00, 0, 0, 0, 0, 0,
            u16::from_be_bytes([seg[0], seg[1]]),
            u16::from_be_bytes([seg[2], seg[3]]),
        );
        let addr = SocketAddr::V6(SocketAddrV6::new(ip, 1, 0, 0));
        g.by_key.insert(key, addr);
        g.by_addr.insert(addr, key);
        addr
    }

    /// Reverse lookup: the key a synthetic `SocketAddr` was allocated for.
    pub(crate) fn key_for_addr(&self, addr: &SocketAddr) -> Option<[u8; 32]> {
        self.inner.lock().expect("addr table poisoned").by_addr.get(addr).copied()
    }
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cargo test -p yggmail quic::addr_table`
Expected: PASS (3 tests).

- [ ] **Step 5: Commit**

```bash
git add crates/yggmail/src/quic/addr_table.rs
git commit -m "feat(quic): key<->SocketAddr table for the quinn adapter"
```

---

### Task 3: `CoreUdpSocket` — `AsyncUdpSocket` over `PacketConn`

The one genuinely-new piece. Wraps `Arc<dyn PacketConn>` (so it is testable with an in-memory pair and works over `CoreConn` in prod). Two async pumps decouple quinn's sync `try_send`/`poll_recv` from the async `write_to`/`read_from`.

**Files:**
- Create: `crates/yggmail/src/quic/udp_adapter.rs`
- Test: inline `#[cfg(test)]` (needs a mem `PacketConn` pair — added here as a shared test double).

- [ ] **Step 1: Write the failing test (adapter + shared in-memory PacketConn pair)**

Create `crates/yggmail/src/quic/udp_adapter.rs`:

```rust
#[cfg(test)]
pub(crate) mod testutil {
    //! In-memory `PacketConn` pair for hermetic overlay tests. Unlike YMP's
    //! `ChanPacketConn`, quinn drives its own timers/retransmits over this
    //! lossless duplex, so a real handshake completes without a live mesh.
    use super::*;
    use async_trait::async_trait;
    use ed25519_dalek::SigningKey;
    use ironwood::types::{Addr, AsyncConn, Error, PacketConn, Result as IwResult};
    use std::sync::atomic::{AtomicBool, Ordering};
    use tokio::sync::mpsc;
    use tokio::sync::Mutex as AsyncMutex;

    pub(crate) struct MemPacketConn {
        tx: mpsc::UnboundedSender<(Vec<u8>, Addr)>,
        rx: AsyncMutex<mpsc::UnboundedReceiver<(Vec<u8>, Addr)>>,
        signing_key: SigningKey,
        local: Addr,
        closed: AtomicBool,
    }

    impl MemPacketConn {
        pub(crate) fn pair(a: SigningKey, b: SigningKey) -> (Arc<Self>, Arc<Self>) {
            let (addr_a, addr_b) = (Addr(a.verifying_key().to_bytes()), Addr(b.verifying_key().to_bytes()));
            let (tx_a, rx_b) = mpsc::unbounded_channel();
            let (tx_b, rx_a) = mpsc::unbounded_channel();
            let ca = Arc::new(Self { tx: tx_a, rx: AsyncMutex::new(rx_a), signing_key: a, local: addr_a, closed: AtomicBool::new(false) });
            let cb = Arc::new(Self { tx: tx_b, rx: AsyncMutex::new(rx_b), signing_key: b, local: addr_b, closed: AtomicBool::new(false) });
            (ca, cb)
        }
    }

    #[async_trait]
    impl PacketConn for MemPacketConn {
        async fn read_from(&self, buf: &mut [u8]) -> IwResult<(usize, Addr)> {
            match self.rx.lock().await.recv().await {
                Some((data, from)) => {
                    let n = buf.len().min(data.len());
                    buf[..n].copy_from_slice(&data[..n]);
                    Ok((n, from))
                }
                None => Err(Error::Closed),
            }
        }
        async fn write_to(&self, buf: &[u8], _addr: &Addr) -> IwResult<usize> {
            // Peer learns our identity as the source addr, matching the mesh.
            let _ = self.tx.send((buf.to_vec(), self.local));
            Ok(buf.len())
        }
        async fn handle_conn(&self, _k: Addr, _c: Box<dyn AsyncConn>, _p: u8) -> IwResult<()> { Ok(()) }
        fn is_closed(&self) -> bool { self.closed.load(Ordering::Relaxed) }
        fn private_key(&self) -> &SigningKey { &self.signing_key }
        fn mtu(&self) -> u64 { 65535 }
        async fn send_lookup(&self, _t: Addr) {}
        fn local_addr(&self) -> Addr { self.local }
        async fn close(&self) -> IwResult<()> { self.closed.store(true, Ordering::Relaxed); Ok(()) }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::testutil::MemPacketConn;
    use ed25519_dalek::SigningKey;
    use quinn::AsyncUdpSocket;

    #[tokio::test]
    async fn adapter_reports_local_addr_and_maps_peer() {
        let mut rng = rand::rngs::OsRng;
        let (a, b) = MemPacketConn::pair(SigningKey::generate(&mut rng), SigningKey::generate(&mut rng));
        let b_key = b.local_addr().0;

        let table = Arc::new(AddrTable::default());
        let sock = CoreUdpSocket::new(a as Arc<dyn ironwood::types::PacketConn>, table.clone());

        // local_addr resolves to our own synthetic addr.
        assert!(sock.local_addr().is_ok());
        // A peer key maps to a stable synthetic addr the table can reverse.
        let peer_addr = table.addr_for_key(b_key);
        assert_eq!(table.key_for_addr(&peer_addr), Some(b_key));
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test -p yggmail quic::udp_adapter`
Expected: FAIL — `cannot find type CoreUdpSocket` / unresolved `AddrTable`.

- [ ] **Step 3: Write the implementation (prepend above the test modules)**

```rust
//! `quinn::AsyncUdpSocket` implemented over a key-addressed `PacketConn`.
//!
//! quinn's socket API is synchronous (`try_send`, `poll_recv`) but the mesh's
//! `write_to`/`read_from` are async, so two background pumps bridge them:
//! an outbound pump drains a channel into `write_to`, an inbound pump copies
//! `read_from` datagrams into a channel that `poll_recv` polls.

use std::fmt;
use std::io::{self, IoSliceMut};
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};

use ironwood::types::{Addr, PacketConn};
use quinn::udp::{RecvMeta, Transmit};
use quinn::{AsyncUdpSocket, UdpPoller};
use tokio::sync::mpsc;

use super::addr_table::AddrTable;

pub(crate) struct CoreUdpSocket {
    table: Arc<AddrTable>,
    local: SocketAddr,
    send_tx: mpsc::UnboundedSender<([u8; 32], Vec<u8>)>,
    recv_rx: Mutex<mpsc::UnboundedReceiver<(SocketAddr, Vec<u8>)>>,
}

impl fmt::Debug for CoreUdpSocket {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CoreUdpSocket").field("local", &self.local).finish()
    }
}

impl CoreUdpSocket {
    pub(crate) fn new(conn: Arc<dyn PacketConn>, table: Arc<AddrTable>) -> Arc<Self> {
        let local = table.addr_for_key(conn.local_addr().0);

        let (send_tx, mut send_rx) = mpsc::unbounded_channel::<([u8; 32], Vec<u8>)>();
        let (recv_tx, recv_rx) = mpsc::unbounded_channel::<(SocketAddr, Vec<u8>)>();

        // Outbound pump: async write_to, off quinn's sync try_send path.
        let send_conn = conn.clone();
        tokio::spawn(async move {
            while let Some((key, bytes)) = send_rx.recv().await {
                if let Err(e) = send_conn.write_to(&bytes, &Addr(key)).await {
                    tracing::debug!("quic: udp send error: {e:?}");
                }
            }
        });

        // Inbound pump: read_from → channel, translating source key → fake addr.
        let recv_conn = conn.clone();
        let recv_table = table.clone();
        tokio::spawn(async move {
            let mut buf = vec![0u8; 65535];
            loop {
                match recv_conn.read_from(&mut buf).await {
                    Ok((n, from)) => {
                        let addr = recv_table.addr_for_key(from.0);
                        if recv_tx.send((addr, buf[..n].to_vec())).is_err() {
                            break; // socket dropped
                        }
                    }
                    Err(e) => {
                        tracing::debug!("quic: udp recv pump exiting: {e:?}");
                        break;
                    }
                }
            }
        });

        Arc::new(Self { table, local, send_tx, recv_rx: Mutex::new(recv_rx) })
    }
}

impl AsyncUdpSocket for CoreUdpSocket {
    fn create_io_poller(self: Arc<Self>) -> Pin<Box<dyn UdpPoller>> {
        // The send channel is unbounded, so a send is always accepted; the pump
        // (and ironwood's DRR queue) applies the real backpressure downstream.
        Box::pin(AlwaysWritable)
    }

    fn try_send(&self, transmit: &Transmit<'_>) -> io::Result<()> {
        let key = self
            .table
            .key_for_addr(&transmit.destination)
            .ok_or_else(|| io::Error::new(io::ErrorKind::AddrNotAvailable, "unknown quic destination"))?;
        self.send_tx
            .send((key, transmit.contents.to_vec()))
            .map_err(|_| io::Error::new(io::ErrorKind::BrokenPipe, "udp send pump gone"))
    }

    fn poll_recv(
        &self,
        cx: &mut Context<'_>,
        bufs: &mut [IoSliceMut<'_>],
        meta: &mut [RecvMeta],
    ) -> Poll<io::Result<usize>> {
        // ponytail: one datagram per call — no GSO/GRO batching over the mesh.
        let mut rx = self.recv_rx.lock().expect("recv rx poisoned");
        match rx.poll_recv(cx) {
            Poll::Ready(Some((addr, data))) => {
                let n = data.len().min(bufs[0].len());
                bufs[0][..n].copy_from_slice(&data[..n]);
                meta[0] = RecvMeta { addr, len: n, stride: n, ecn: None, dst_ip: None };
                Poll::Ready(Ok(1))
            }
            Poll::Ready(None) => Poll::Ready(Err(io::Error::new(io::ErrorKind::BrokenPipe, "udp recv pump closed"))),
            Poll::Pending => Poll::Pending,
        }
    }

    fn local_addr(&self) -> io::Result<SocketAddr> {
        Ok(self.local)
    }

    // Fixed 1200-byte datagrams, no fragmentation — matches yggquic's config.
    fn max_transmit_segments(&self) -> usize { 1 }
    fn max_receive_segments(&self) -> usize { 1 }
    fn may_fragment(&self) -> bool { false }
}

#[derive(Debug)]
struct AlwaysWritable;

impl UdpPoller for AlwaysWritable {
    fn poll_writable(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}
```

Also add `use std::sync::Arc;` and `use super::addr_table::AddrTable;` visibility to the test module (already imported via `super::*`).

- [ ] **Step 4: Run test to verify it passes**

Run: `cargo test -p yggmail quic::udp_adapter`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add crates/yggmail/src/quic/udp_adapter.rs
git commit -m "feat(quic): AsyncUdpSocket adapter over the Yggdrasil PacketConn"
```

---

### Task 4: `QuicOverlay` — endpoint, transport config, peer-key pinning; hermetic handshake spike

The Phase-1 payoff: prove `quinn` completes a real handshake over the mesh adapter and both sides can pin the peer's ed25519 key from its cert. Test runs client+server over a `MemPacketConn` pair — no live mesh, runs in CI.

**Files:**
- Modify: `crates/yggmail/src/quic/mod.rs`
- Test: inline `#[cfg(test)]` in `mod.rs`.

- [ ] **Step 1: Write the failing test (append to `crates/yggmail/src/quic/mod.rs`)**

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use crate::quic::udp_adapter::testutil::MemPacketConn;
    use ed25519_dalek::SigningKey;
    use ironwood::types::PacketConn;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    /// The spike: quinn handshake completes over the mesh adapter, a bidi stream
    /// carries bytes both ways, and each side pins the other's ed25519 key.
    #[tokio::test]
    async fn quic_handshake_and_key_pinning_over_mesh() {
        let mut rng = rand::rngs::OsRng;
        let key_a = SigningKey::generate(&mut rng);
        let key_b = SigningKey::generate(&mut rng);
        let pub_a = key_a.verifying_key().to_bytes();
        let pub_b = key_b.verifying_key().to_bytes();

        let (conn_a, conn_b) = MemPacketConn::pair(key_a.clone(), key_b.clone());
        let server = QuicOverlay::new(conn_b as Arc<dyn PacketConn>, &key_b).unwrap();
        let client = QuicOverlay::new(conn_a as Arc<dyn PacketConn>, &key_a).unwrap();

        let (srv_conn, cli_conn) = tokio::join!(
            async {
                let c = server.accept().await.expect("incoming").expect("accepted");
                // Server accepts the client-initiated stream and echoes.
                let (mut send, mut recv) = c.accept_bi().await.unwrap();
                let mut b = [0u8; 5];
                recv.read_exact(&mut b).await.unwrap();
                send.write_all(&b).await.unwrap();
                send.finish().unwrap();
                c
            },
            async {
                let c = client.connect(pub_b).await.expect("connect");
                let (mut send, mut recv) = c.open_bi().await.unwrap();
                send.write_all(b"hello").await.unwrap();
                send.finish().unwrap();
                let mut back = [0u8; 5];
                recv.read_exact(&mut back).await.unwrap();
                assert_eq!(&back, b"hello");
                c
            },
        );

        // Key pinning: server sees the client's key, client sees the server's.
        assert_eq!(peer_key(&srv_conn), Some(pub_a), "server must pin client key");
        assert_eq!(peer_key(&cli_conn), Some(pub_b), "client must pin server key");
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test -p yggmail quic::tests::quic_handshake -- --nocapture`
Expected: FAIL — `QuicOverlay`/`peer_key` not defined.

- [ ] **Step 3: Write the implementation (prepend above the test module in `mod.rs`, below the `pub use`)**

```rust
use std::sync::Arc;
use std::time::Duration;

use ed25519_dalek::SigningKey;
use ironwood::types::PacketConn;
use quinn::crypto::rustls::{QuicClientConfig, QuicServerConfig};
use quinn::{
    ClientConfig, Connection, Endpoint, EndpointConfig, ServerConfig, TokioRuntime, TransportConfig,
};
use rustls::pki_types::CertificateDer;
use yggdrasil::transport::tls;

use addr_table::AddrTable;
use udp_adapter::CoreUdpSocket;

/// One quinn endpoint over the mesh — dials peers AND accepts inbound mail
/// connections through a single `CoreUdpSocket`, mirroring yggquic.
pub(crate) struct QuicOverlay {
    endpoint: Endpoint,
    table: Arc<AddrTable>,
}

/// yggquic-matching QUIC parameters: 30-min idle, fixed 1200-byte packets,
/// no path-MTU discovery. (Peering QUIC uses 60s idle; mail holds longer.)
fn overlay_transport_config() -> Arc<TransportConfig> {
    let mut t = TransportConfig::default();
    t.max_idle_timeout(Some(Duration::from_secs(1800).try_into().expect("valid idle")));
    t.initial_mtu(1200);
    t.min_mtu(1200);
    t.mtu_discovery_config(None);
    Arc::new(t)
}

impl QuicOverlay {
    pub(crate) fn new(conn: Arc<dyn PacketConn>, signing_key: &SigningKey) -> Result<Self, String> {
        let table = Arc::new(AddrTable::default());
        let socket = CoreUdpSocket::new(conn, table.clone());

        // Reuse the shipped ed25519 self-signed / accept-all TLS (f77cb6c).
        let material = tls::generate_self_signed_cert(signing_key)?;
        let server_rustls = tls::create_server_config(material.cert_chain(), material.private_key()?)?;
        let client_rustls = tls::create_client_config(material.cert_chain(), material.private_key()?)?;

        let mut server_config = ServerConfig::with_crypto(Arc::new(
            QuicServerConfig::try_from(server_rustls).map_err(|e| format!("quic server crypto: {e}"))?,
        ));
        server_config.transport_config(overlay_transport_config());

        let mut client_config = ClientConfig::new(Arc::new(
            QuicClientConfig::try_from(client_rustls).map_err(|e| format!("quic client crypto: {e}"))?,
        ));
        client_config.transport_config(overlay_transport_config());

        let mut endpoint = Endpoint::new_with_abstract_socket(
            EndpointConfig::default(),
            Some(server_config),
            socket,
            Arc::new(TokioRuntime),
        )
        .map_err(|e| format!("quic endpoint: {e}"))?;
        endpoint.set_default_client_config(client_config);

        Ok(Self { endpoint, table })
    }

    /// Dial a peer by 32-byte key. ServerName = hex(pubkey), matching yggquic.
    pub(crate) async fn connect(&self, dest: [u8; 32]) -> Result<Connection, String> {
        let addr = self.table.addr_for_key(dest);
        self.endpoint
            .connect(addr, &hex::encode(dest))
            .map_err(|e| format!("quic connect: {e}"))?
            .await
            .map_err(|e| format!("quic handshake: {e}"))
    }

    /// Accept the next inbound connection, or `None` when the endpoint closes.
    pub(crate) async fn accept(&self) -> Option<Result<Connection, String>> {
        let incoming = self.endpoint.accept().await?;
        Some(incoming.await.map_err(|e| format!("quic accept: {e}")))
    }
}

/// Pin the peer's ed25519 key from its TLS cert (accepted at TLS level, verified
/// here). `None` if the peer sent no cert or a non-ed25519 one — reject those.
pub(crate) fn peer_key(conn: &Connection) -> Option<[u8; 32]> {
    let certs = conn.peer_identity()?.downcast::<Vec<CertificateDer<'static>>>().ok()?;
    tls::extract_ed25519_pubkey_from_cert(certs.first()?.as_ref())
}
```

> **NB on client-auth:** `tls::create_server_config` uses the shipped accept-all client verifier with `client_auth_mandatory() == false`. We do not fork it. Instead, the accept loop (Task 8/10) **rejects any connection where `peer_key()` is `None`** — cryptographically we require the client cert anyway to derive the sender key, so app-layer enforcement is equivalent to yggquic's `RequireAnyClientCert` and keeps the reused config untouched. `ponytail: enforce cert presence at the app layer, not by forking the TLS verifier.`

- [ ] **Step 4: Run test to verify it passes**

Run: `cargo test -p yggmail quic::tests::quic_handshake -- --nocapture`
Expected: PASS — handshake completes, `hello` echoes, both keys pinned.

> If this fails on the handshake, STOP and diagnose TLS/transport-config before proceeding (this is the spike gate). Likely culprits: `QuicClientConfig::try_from` requires the rustls config to advertise no ALPN (it does) and TLS1.3; `initial_mtu`/`min_mtu` must both be ≥1200.

- [ ] **Step 5: Commit**

```bash
git add crates/yggmail/src/quic/mod.rs
git commit -m "feat(quic): QuicOverlay endpoint + key pinning; hermetic handshake spike"
```

---

### Task 5: Live-interop verification (manual — real yggmail-go partner)

The hermetic test proves quinn↔quinn over our adapter. This task proves quinn↔quic-go on the wire. **No code**; a checklist to run before Phase 2 is trusted.

**Reference for building a Go partner:** `Librarys/yggmail-old-mobile/` — a standard `yggmail`/`yggmail-old-mobile` binary. Its local `replace => ../yggquic` is broken; remove it and let `go get` pull the pinned `v0.0.0-20260224233053-…` (see spec §Compat).

- [ ] **Step 1:** Build a live yggmail-go node (or run Tyr 1.8.1) and a debug yggmail-ng node, both peered to the same hub (`tcp://bra.zbin.eu:7743`).
- [ ] **Step 2:** Add a temporary `--quic-ping <hex_pubkey>` debug path to `main.rs` that calls `QuicOverlay::connect(dest)` then `open_bi` + writes a kick byte, and assert the handshake completes against the Go node's yggquic listener.
- [ ] **Step 3:** Confirm from logs: TLS handshake succeeds, `peer_key()` equals the Go node's advertised pubkey.
- [ ] **Step 4:** If it fails: capture whether it is (a) no datagrams flowing (adapter/mesh issue — check the pumps and `AddrTable`), or (b) TLS `handshake_failure` (verify empty ALPN + TLS1.3 + accept-all on both sides). Fix before Phase 2.
- [ ] **Step 5:** Remove the temporary `--quic-ping` path.

**Phase 1 exit criteria:** hermetic test green in CI **and** the live handshake observed at least once.

---

# PHASE 2 — Mail new↔old over QUIC (SMTP overlay)

Goal: real mail both directions, Tyr-1.9-interop ↔ Tyr 1.8.1 and ↔ yggmail-go+Thunderbird. The overlay speaks the same kick-byte + emersion-SMTP dialog as yggquic.

---

### Task 6: SMTP overlay dialog (server + client), stream-generic

The peer-to-peer SMTP dialog (distinct from the localhost MUA server in `smtp/mod.rs`). Generic over `AsyncRead`/`AsyncWrite` so it is tested over `tokio::io::duplex` — fully hermetic — and later runs over a QUIC bidi stream. The **server** yields `(from_key, rfc5322_bytes)` to its caller (which does INBOX insert + dedup + IDLE-notify, preserving existing behavior). The **client** sends one mail.

**Files:**
- Create: `crates/yggmail/src/quic/smtp_overlay.rs`
- Test: inline `#[cfg(test)]`.

- [ ] **Step 1: Write the failing test**

Create `crates/yggmail/src/quic/smtp_overlay.rs`:

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::split;

    /// Client dialog → server dialog over an in-memory duplex delivers the mail
    /// body and the crypto-enforced sender key, with no network.
    #[tokio::test]
    async fn overlay_smtp_delivers_body_and_sender_key() {
        let sender_key = [0x11u8; 32];
        let recipient_key = [0x22u8; 32];

        // Two duplexes = one full-duplex link (client_w→server_r, server_w→client_r).
        let (client_side, server_side) = tokio::io::duplex(64 * 1024);
        let (cr, cw) = split(client_side);
        let (sr, sw) = split(server_side);

        let body = "Subject: Hi\r\nFrom: test\r\n\r\nPayload line\r\n";

        let server = tokio::spawn(async move {
            overlay_serve_stream(sr, sw, recipient_key, sender_key).await
        });
        let client = tokio::spawn(async move {
            overlay_send_stream(
                cr,
                cw,
                &crate::address::create_address(&sender_key),
                &[crate::address::create_address(&recipient_key)],
                body.as_bytes(),
            )
            .await
        });

        client.await.unwrap().expect("client dialog ok");
        let (from_key, raw) = server.await.unwrap().expect("server yields one mail");
        assert_eq!(from_key, sender_key, "server pins the crypto sender identity");
        let text = String::from_utf8_lossy(&raw);
        assert!(text.contains("Payload line"), "body delivered: {text}");
    }

    /// A MAIL FROM whose address ≠ the pinned peer key is rejected (yggmail-go
    /// session_remote.go semantics: sender identity is cryptographic).
    #[tokio::test]
    async fn overlay_smtp_rejects_spoofed_sender() {
        let peer_key = [0x11u8; 32];
        let spoofed = [0x99u8; 32];
        let (client_side, server_side) = tokio::io::duplex(64 * 1024);
        let (cr, cw) = tokio::io::split(client_side);
        let (sr, sw) = tokio::io::split(server_side);

        let server = tokio::spawn(async move {
            overlay_serve_stream(sr, sw, [0x22u8; 32], peer_key).await
        });
        let _ = tokio::spawn(async move {
            overlay_send_stream(
                cr, cw,
                &crate::address::create_address(&spoofed), // lies about identity
                &[crate::address::create_address(&[0x22u8; 32])],
                b"Subject: x\r\n\r\nbad\r\n",
            ).await
        });

        let res = server.await.unwrap();
        assert!(res.is_err(), "spoofed sender must be rejected, got {res:?}");
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test -p yggmail quic::smtp_overlay`
Expected: FAIL — `overlay_serve_stream`/`overlay_send_stream` not defined.

- [ ] **Step 3: Write the implementation (prepend above the test module)**

```rust
//! Peer-to-peer SMTP dialog over a single (QUIC) stream. Distinct from the
//! localhost MUA server in `crate::smtp`: here the sender identity is the pinned
//! ed25519 key, and a received mail is handed back to the caller (which inserts
//! it into INBOX with dedup + IDLE-notify).
//!
//! Wire dialog mirrors emersion/go-smtp (yggmail-go): greeting (server first),
//! then MAIL FROM / RCPT TO / DATA / QUIT.

use crate::address::parse_address;
use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncWrite, AsyncWriteExt, BufReader};

/// 33 MiB ceiling on DATA (matches `smtp::MAX_DATA_BYTES`); YMP's 32 MiB cap is gone.
const MAX_DATA_BYTES: usize = 33 * 1024 * 1024;
const MAX_LINE_BYTES: usize = 64 * 1024;

/// Errors surfaced by the overlay SMTP dialog. `ponytail: manual Display, no
/// thiserror (matches the crate's convention).`
#[derive(Debug)]
pub(crate) enum OverlayError {
    Io(std::io::Error),
    Protocol(String),
    SpoofedSender,
}
impl std::fmt::Display for OverlayError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            OverlayError::Io(e) => write!(f, "io: {e}"),
            OverlayError::Protocol(s) => write!(f, "protocol: {s}"),
            OverlayError::SpoofedSender => write!(f, "MAIL FROM does not match peer key"),
        }
    }
}
impl std::error::Error for OverlayError {}
impl From<std::io::Error> for OverlayError {
    fn from(e: std::io::Error) -> Self { OverlayError::Io(e) }
}

/// Serve one inbound peer: run the SMTP dialog, enforce `MAIL FROM == peer_key`,
/// return the assembled RFC 5322 mail. `peer_key` is pinned from the TLS cert.
/// `local_key` is our own address (for the RCPT TO acceptance check).
pub(crate) async fn overlay_serve_stream<R, W>(
    reader: R,
    mut writer: W,
    local_key: [u8; 32],
    peer_key: [u8; 32],
) -> Result<([u8; 32], Vec<u8>), OverlayError>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut reader = BufReader::new(reader);
    let mut line = String::new();

    writer.write_all(b"220 yggmail-ng overlay ready\r\n").await?;
    writer.flush().await?;

    let mut from_ok = false;
    let mut rcpt_ok = false;

    loop {
        line.clear();
        let n = (&mut reader).take(MAX_LINE_BYTES as u64).read_line(&mut line).await?;
        if n == 0 {
            return Err(OverlayError::Protocol("peer closed before DATA".into()));
        }
        let upper = line.trim().to_uppercase();

        if upper.starts_with("HELO") || upper.starts_with("EHLO") {
            writer.write_all(b"250 yggmail-ng\r\n").await?;
        } else if upper.starts_with("MAIL FROM:") {
            let addr = extract_addr(line.trim(), "MAIL FROM:").unwrap_or_default();
            match parse_address(&addr) {
                Some(k) if k == peer_key => { from_ok = true; writer.write_all(b"250 OK\r\n").await?; }
                _ => {
                    writer.write_all(b"550 sender not permitted\r\n").await?;
                    writer.flush().await?;
                    return Err(OverlayError::SpoofedSender);
                }
            }
        } else if upper.starts_with("RCPT TO:") {
            let addr = extract_addr(line.trim(), "RCPT TO:").unwrap_or_default();
            // Accept only mail addressed to us.
            match parse_address(&addr) {
                Some(k) if k == local_key => { rcpt_ok = true; writer.write_all(b"250 OK\r\n").await?; }
                _ => { writer.write_all(b"550 no such user\r\n").await?; }
            }
        } else if upper == "DATA" {
            if !from_ok || !rcpt_ok {
                writer.write_all(b"503 bad sequence\r\n").await?;
                writer.flush().await?;
                return Err(OverlayError::Protocol("DATA before MAIL/RCPT".into()));
            }
            writer.write_all(b"354 go ahead\r\n").await?;
            writer.flush().await?;
            let body = read_data(&mut reader).await?;
            writer.write_all(b"250 OK\r\n").await?;
            writer.flush().await?;
            return Ok((peer_key, body));
        } else if upper == "QUIT" {
            writer.write_all(b"221 bye\r\n").await?;
            writer.flush().await?;
            return Err(OverlayError::Protocol("QUIT before DATA".into()));
        } else {
            writer.write_all(b"250 OK\r\n").await?;
        }
        writer.flush().await?;
    }
}

/// Read a dot-terminated DATA body, un-stuffing leading dots (RFC 5321 §4.5.2).
async fn read_data<R: AsyncRead + Unpin>(reader: &mut BufReader<R>) -> Result<Vec<u8>, OverlayError> {
    let mut out = String::new();
    let mut line = String::new();
    loop {
        line.clear();
        let n = (&mut *reader).take(MAX_LINE_BYTES as u64).read_line(&mut line).await?;
        if n == 0 {
            return Err(OverlayError::Protocol("EOF inside DATA".into()));
        }
        if line == ".\r\n" || line == ".\n" {
            return Ok(out.into_bytes());
        }
        let stripped = if line.starts_with("..") { &line[1..] } else { &line[..] };
        if out.len() + stripped.len() > MAX_DATA_BYTES {
            return Err(OverlayError::Protocol("message too large".into()));
        }
        out.push_str(stripped);
    }
}

/// Send one mail as an SMTP client. Reads greeting/replies, walks the dialog,
/// dot-stuffs the body. Non-2xx at any step is a protocol error.
pub(crate) async fn overlay_send_stream<R, W>(
    reader: R,
    mut writer: W,
    from: &str,
    rcpts: &[String],
    body: &[u8],
) -> Result<(), OverlayError>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut reader = BufReader::new(reader);
    expect_code(&mut reader, b'2').await?; // 220 greeting

    writer.write_all(b"EHLO yggmail\r\n").await?;
    writer.flush().await?;
    expect_code(&mut reader, b'2').await?;

    writer.write_all(format!("MAIL FROM:<{from}>\r\n").as_bytes()).await?;
    writer.flush().await?;
    expect_code(&mut reader, b'2').await?;

    for rcpt in rcpts {
        writer.write_all(format!("RCPT TO:<{rcpt}>\r\n").as_bytes()).await?;
        writer.flush().await?;
        expect_code(&mut reader, b'2').await?;
    }

    writer.write_all(b"DATA\r\n").await?;
    writer.flush().await?;
    expect_code(&mut reader, b'3').await?; // 354

    write_dot_stuffed(&mut writer, body).await?;
    writer.write_all(b".\r\n").await?;
    writer.flush().await?;
    expect_code(&mut reader, b'2').await?; // 250 accepted

    writer.write_all(b"QUIT\r\n").await?;
    writer.flush().await?;
    Ok(())
}

async fn write_dot_stuffed<W: AsyncWrite + Unpin>(w: &mut W, body: &[u8]) -> Result<(), OverlayError> {
    // Stuff a leading '.' at the start of any line to protect the terminator.
    let text = body;
    let mut start = 0;
    for i in 0..text.len() {
        if text[i] == b'\n' {
            let line = &text[start..=i];
            if line.first() == Some(&b'.') {
                w.write_all(b".").await?;
            }
            w.write_all(line).await?;
            start = i + 1;
        }
    }
    if start < text.len() {
        let line = &text[start..];
        if line.first() == Some(&b'.') { w.write_all(b".").await?; }
        w.write_all(line).await?;
        w.write_all(b"\r\n").await?;
    }
    Ok(())
}

/// Read one reply line, assert its first byte (`2`/`3`) is the expected class.
async fn expect_code<R: AsyncRead + Unpin>(reader: &mut BufReader<R>, class: u8) -> Result<(), OverlayError> {
    let mut line = String::new();
    let n = reader.take(MAX_LINE_BYTES as u64).read_line(&mut line).await?;
    if n == 0 {
        return Err(OverlayError::Protocol("peer closed mid-dialog".into()));
    }
    // Skip multi-line replies ("250-...") to the final line ("250 ...").
    while line.as_bytes().get(3) == Some(&b'-') {
        line.clear();
        let n = reader.take(MAX_LINE_BYTES as u64).read_line(&mut line).await?;
        if n == 0 { return Err(OverlayError::Protocol("peer closed mid multiline".into())); }
    }
    match line.as_bytes().first() {
        Some(&c) if c == class => Ok(()),
        _ => Err(OverlayError::Protocol(format!("unexpected reply: {}", line.trim()))),
    }
}

/// `MAIL FROM:<addr>` / `RCPT TO:<addr>` → `addr`. (Mirror of `smtp::extract_addr`.)
fn extract_addr(line: &str, prefix: &str) -> Option<String> {
    let rest = line.get(prefix.len()..)?.trim();
    let addr = rest.strip_prefix('<').and_then(|s| s.strip_suffix('>')).unwrap_or(rest);
    if addr.is_empty() { None } else { Some(addr.to_string()) }
}
```

Add the needed import to the test module: `use tokio::io::split;` (already used). Ensure `AsyncReadExt::take` is in scope via `AsyncBufReadExt`/`AsyncReadExt` (`tokio::io::AsyncReadExt` provides `take`; add `AsyncReadExt` to the `use`).

- [ ] **Step 4: Run test to verify it passes**

Run: `cargo test -p yggmail quic::smtp_overlay`
Expected: PASS (2 tests) — body + sender key delivered; spoofed sender rejected.

- [ ] **Step 5: Commit**

```bash
git add crates/yggmail/src/quic/smtp_overlay.rs
git commit -m "feat(quic): peer SMTP overlay dialog (server+client), sender crypto-enforced"
```

---

### Task 7: `QuicMailTransport` facade (kick-byte, accept loop, connection cache)

The `YmpSession`-shaped API that `sender`/`receiver` consume. `send()` connects (cached), opens a bidi stream, writes the kick byte, runs the client dialog. An accept loop handles inbound connections: consume the kick byte, run the server dialog, push `(from_key, mail)` into the `recv()` channel. Rejects connections with no pinned key.

**Files:**
- Create: `crates/yggmail/src/quic/transport.rs`
- Test: inline `#[cfg(test)]` (loopback over `MemPacketConn`).

- [ ] **Step 1: Write the failing test**

Create `crates/yggmail/src/quic/transport.rs`:

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use crate::quic::udp_adapter::testutil::MemPacketConn;
    use ed25519_dalek::SigningKey;
    use ironwood::types::PacketConn;

    /// End-to-end over the mesh adapter: sender.send() → receiver.recv() carries
    /// the mail body and the sender key. This is the YMP integration test that
    /// was `#[ignore]`d — now hermetic, because quinn drives real I/O.
    #[tokio::test]
    async fn send_then_recv_over_quic_overlay() {
        let mut rng = rand::rngs::OsRng;
        let key_a = SigningKey::generate(&mut rng);
        let key_b = SigningKey::generate(&mut rng);
        let pub_a = key_a.verifying_key().to_bytes();
        let pub_b = key_b.verifying_key().to_bytes();

        let (conn_a, conn_b) = MemPacketConn::pair(key_a.clone(), key_b.clone());
        let alice = QuicMailTransport::new(conn_a as Arc<dyn PacketConn>, &key_a).unwrap();
        let bob = QuicMailTransport::new(conn_b as Arc<dyn PacketConn>, &key_b).unwrap();

        let mail = b"Subject: Meshmail\r\nFrom: a\r\n\r\nHello over QUIC\r\n".to_vec();
        alice.send(pub_b, mail.clone()).await.expect("send ok");

        let (from, got) = tokio::time::timeout(std::time::Duration::from_secs(5), bob.recv())
            .await
            .expect("recv within 5s")
            .expect("recv ok");
        assert_eq!(from, pub_a);
        assert!(String::from_utf8_lossy(&got).contains("Hello over QUIC"));
        let _ = pub_a; // silence if unused in edits
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test -p yggmail quic::transport`
Expected: FAIL — `QuicMailTransport` not defined.

- [ ] **Step 3: Write the implementation (prepend above the test module)**

```rust
//! `QuicMailTransport` — the mail-overlay facade, shaped like `YmpSession`
//! (`send`/`recv`) so the peer loops rewire with a type change. Owns the
//! endpoint, an accept loop feeding `recv()`, and a per-peer connection cache.

use std::collections::HashMap;
use std::sync::Arc;

use ed25519_dalek::SigningKey;
use ironwood::types::PacketConn;
use quinn::Connection;
use tokio::sync::{mpsc, Mutex};

use super::mod_reexports::{peer_key, QuicOverlay};
use super::smtp_overlay::{overlay_send_stream, overlay_serve_stream};

/// Errors from the mail transport. `ponytail: manual Display (crate convention).`
#[derive(Debug)]
pub enum QuicMailError {
    Connect(String),
    Stream(String),
    Dialog(String),
    Closed,
}
impl std::fmt::Display for QuicMailError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            QuicMailError::Connect(s) => write!(f, "connect: {s}"),
            QuicMailError::Stream(s) => write!(f, "stream: {s}"),
            QuicMailError::Dialog(s) => write!(f, "dialog: {s}"),
            QuicMailError::Closed => write!(f, "transport closed"),
        }
    }
}
impl std::error::Error for QuicMailError {}

pub struct QuicMailTransport {
    overlay: Arc<QuicOverlay>,
    local_key: [u8; 32],
    conns: Mutex<HashMap<[u8; 32], Connection>>,
    recv_rx: Mutex<mpsc::Receiver<([u8; 32], Vec<u8>)>>,
}

impl QuicMailTransport {
    pub fn new(conn: Arc<dyn PacketConn>, signing_key: &SigningKey) -> Result<Arc<Self>, String> {
        let local_key = signing_key.verifying_key().to_bytes();
        let overlay = Arc::new(QuicOverlay::new(conn, signing_key)?);
        let (recv_tx, recv_rx) = mpsc::channel::<([u8; 32], Vec<u8>)>(128);

        // Accept loop: one task per inbound connection; each connection may carry
        // many mails (one bidi stream each), matching yggquic's stream-per-mail.
        let accept_overlay = overlay.clone();
        let accept_tx = recv_tx;
        tokio::spawn(async move {
            while let Some(incoming) = accept_overlay.accept().await {
                let connection = match incoming {
                    Ok(c) => c,
                    Err(e) => { tracing::debug!("quic: accept error: {e}"); continue; }
                };
                // Enforce client-cert presence (yggquic RequireAnyClientCert equiv).
                let Some(from_key) = peer_key(&connection) else {
                    tracing::warn!("quic: inbound connection without ed25519 cert — dropping");
                    connection.close(1u32.into(), b"cert required");
                    continue;
                };
                let tx = accept_tx.clone();
                tokio::spawn(async move {
                    loop {
                        let (send, recv) = match connection.accept_bi().await {
                            Ok(s) => s,
                            Err(_) => break, // peer closed the connection
                        };
                        let tx = tx.clone();
                        tokio::spawn(async move {
                            let (mut send, mut recv) = (send, recv);
                            // Consume the kick byte (yggquic kickByteListener).
                            let mut kick = [0u8; 1];
                            use tokio::io::AsyncReadExt;
                            if recv.read_exact(&mut kick).await.is_err() {
                                return;
                            }
                            match overlay_serve_stream(&mut recv, &mut send, local_key, from_key).await {
                                Ok((k, mail)) => { let _ = tx.send((k, mail)).await; }
                                Err(e) => tracing::debug!("quic: overlay serve error: {e}"),
                            }
                        });
                    }
                });
            }
            tracing::info!("quic: accept loop ended (endpoint closed)");
        });

        Ok(Arc::new(Self {
            overlay,
            local_key,
            conns: Mutex::new(HashMap::new()),
            recv_rx: Mutex::new(recv_rx),
        }))
    }

    /// Deliver one mail to `dest`. Mirrors `YmpSession::send`.
    pub async fn send(&self, dest: [u8; 32], mail: Vec<u8>) -> Result<(), QuicMailError> {
        let connection = self.get_or_connect(dest).await?;
        let (mut send, mut recv) = connection
            .open_bi()
            .await
            .map_err(|e| QuicMailError::Stream(e.to_string()))?;
        // Kick byte: server speaks first (SMTP greeting), matching kickByteConn.
        send.write_all(&[0u8]).await.map_err(|e| QuicMailError::Stream(e.to_string()))?;

        let from = crate::address::create_address(&self.local_key);
        let rcpts = [crate::address::create_address(&dest)];
        overlay_send_stream(&mut recv, &mut send, &from, &rcpts, &mail)
            .await
            .map_err(|e| QuicMailError::Dialog(e.to_string()))?;
        Ok(())
    }

    /// Next inbound mail. Mirrors `YmpSession::recv`.
    pub async fn recv(&self) -> Result<([u8; 32], Vec<u8>), QuicMailError> {
        self.recv_rx.lock().await.recv().await.ok_or(QuicMailError::Closed)
    }

    /// Reuse a live connection or dial a new one, dropping dead entries.
    async fn get_or_connect(&self, dest: [u8; 32]) -> Result<Connection, QuicMailError> {
        {
            let cache = self.conns.lock().await;
            if let Some(c) = cache.get(&dest) {
                if c.close_reason().is_none() {
                    return Ok(c.clone());
                }
            }
        }
        let c = self.overlay.connect(dest).await.map_err(QuicMailError::Connect)?;
        self.conns.lock().await.insert(dest, c.clone());
        Ok(c)
    }
}
```

> `use tokio::io::AsyncWriteExt` is needed for `send.write_all`; add it at the top. The `super::mod_reexports` path is a placeholder — expose `QuicOverlay` and `peer_key` to sibling modules by adding `pub(crate) use self::{...}` in `mod.rs` (see Step 4).

- [ ] **Step 4: Expose `QuicOverlay`/`peer_key` to siblings — edit `crates/yggmail/src/quic/mod.rs`**

The `QuicOverlay` struct and `peer_key` fn live in `mod.rs`. Make them `pub(crate)` (already are) and reference them from `transport.rs` as `use super::{QuicOverlay, peer_key};` (delete the `mod_reexports` placeholder — that path does not exist). Fix the `transport.rs` import to:

```rust
use super::{peer_key, QuicOverlay};
use super::smtp_overlay::{overlay_send_stream, overlay_serve_stream};
```

- [ ] **Step 5: Run test to verify it passes**

Run: `cargo test -p yggmail quic::transport -- --nocapture`
Expected: PASS — `send()` delivers to `recv()` over the mesh adapter, sender key = alice.

- [ ] **Step 6: Commit**

```bash
git add crates/yggmail/src/quic/transport.rs crates/yggmail/src/quic/mod.rs
git commit -m "feat(quic): QuicMailTransport facade (kick-byte, accept loop, conn cache)"
```

---

### Task 8: Rewire `peer/sender.rs` from YMP → QUIC

The sender's structure (poll queue → readiness-gate → deliver → de-queue → move to Sent) is transport-agnostic. Only the transport type and the send call change. **Preserve** the delete-first / group-mail ordering (memory: outbox re-send spam bug) and the readiness gate.

**Files:**
- Modify: `crates/yggmail/src/peer/sender.rs`

- [ ] **Step 1: Update the failing build (change imports + signature)**

In `crates/yggmail/src/peer/sender.rs`, replace the YMP import and `spawn`/`process_queue` signatures:

```rust
use crate::quic::QuicMailTransport;
use crate::storage::SqliteStorage;
use std::sync::Arc;
use tokio::time::{Duration, Instant, sleep_until};
use tracing;
use yggdrasil::core::Core;
use yggdrasil::links::PeerEvent;
```

Change `spawn(storage, ymp: Arc<YmpSession>, core, base_interval)` → `spawn(storage, transport: Arc<QuicMailTransport>, core, base_interval)` and thread it through to `process_queue(storage, transport, core)`.

- [ ] **Step 2: Update the send call**

Replace the YMP send/return-handling block (`crates/yggmail/src/peer/sender.rs:107-131`) — keep the delete-first + group-mail-move logic verbatim, change only the call:

```rust
match transport.send(dest_key, mail.mail.clone()).await {
    Ok(()) => {
        // Delete-first (see queue FK note): drop the queue entry while the
        // mail is still in Outbox so it matches (dest, "Outbox", id).
        storage.queue_delete(dest_hex, "Outbox", qm.id)?;
        if storage.queue_count_for_mail("Outbox", qm.id)? == 0 {
            let _ = storage.mail_move("Outbox", "Sent", qm.id);
        }
        tracing::info!("sender: mail #{id} delivered over QUIC, de-queued", id = qm.id);
    }
    Err(e) => {
        tracing::warn!("sender: QUIC send failed for #{id}: {e}", id = qm.id);
        // Will retry on next poll cycle.
    }
}
```

The `wait_for_up_peer` / `has_up_peer` readiness-gate helpers are unchanged.

- [ ] **Step 3: Run the crate build + existing sender tests**

Run: `cargo build -p yggmail` then `cargo test -p yggmail peer::`
Expected: PASS (compiles; sender has no unit tests of its own — the transport test in Task 7 covers delivery).

- [ ] **Step 4: Commit**

```bash
git add crates/yggmail/src/peer/sender.rs
git commit -m "refactor(peer): sender delivers over QuicMailTransport (queue logic unchanged)"
```

---

### Task 9: Rewire `peer/receiver.rs` from YMP → QUIC

The receiver already just drains `recv()` and inserts to INBOX with dedup. Only the type name changes; dedup + logging stay.

**Files:**
- Modify: `crates/yggmail/src/peer/receiver.rs`

- [ ] **Step 1: Swap the transport type**

Replace `use crate::ymp::YmpSession;` with `use crate::quic::QuicMailTransport;` and change `spawn(storage, ymp: Arc<YmpSession>)` → `spawn(storage, transport: Arc<QuicMailTransport>)`, and the loop `ymp.recv()` → `transport.recv()`. The `mail_insert_inbox_dedup` branch (Ok(Some)/Ok(None)/Err) is unchanged.

- [ ] **Step 2: Run build**

Run: `cargo build -p yggmail`
Expected: PASS.

- [ ] **Step 3: Commit**

```bash
git add crates/yggmail/src/peer/receiver.rs
git commit -m "refactor(peer): receiver drains QuicMailTransport (dedup unchanged)"
```

---

### Task 10: Wire the overlay into `main.rs` and `yggmail-mobile`

Both construction sites build `CoreConn` → `YmpSession` → sender/receiver. Swap `YmpSession` for `QuicMailTransport`. **`CoreConn` stays** (it is the `PacketConn` the overlay wraps). The mobile receiver task's IDLE-notify + dedup logic is preserved (it consumes `transport.recv()`).

**Files:**
- Modify: `crates/yggmail/src/main.rs:110-128`
- Modify: `crates/yggmail-mobile/src/lib.rs:175-230`

- [ ] **Step 1: `main.rs` — replace YMP construction**

Replace lines 116-128 (`CoreConn::new` … `YmpSession::new` … sender/receiver spawn) with:

```rust
    let conn = CoreConn::new(core.clone(), signing_key.clone());
    let transport = yggmail::quic::QuicMailTransport::new(
        conn as Arc<dyn ironwood::types::PacketConn>,
        &signing_key,
    )
    .map_err(|e| format!("quic transport init: {e}"))?;

    // ── Peer exchange ─────────────────────────────────────────────────
    let _receiver = peer::receiver::spawn(storage.clone(), transport.clone());
    let _sender = peer::sender::spawn(
        storage.clone(),
        transport.clone(),
        core.clone(),
        tokio::time::Duration::from_secs(30),
    );
```

Update imports at the top of `main.rs`: remove `use yggmail::ymp::YmpSession;` and `use yggmail::core_conn::CoreConn;` stays; add nothing else (`QuicMailTransport` referenced by full path). Note `signing_key` is now cloned before `Core::new` (it already is at line 111 — reuse that clone; keep one owned copy for the transport).

- [ ] **Step 2: `yggmail-mobile/src/lib.rs` — replace YMP construction**

Replace lines 175-178 (`CoreConn::new` … `YmpSession::new`) with:

```rust
            let conn = CoreConn::new(core.clone(), signing_key.clone());
            let transport = yggmail::quic::QuicMailTransport::new(
                conn.clone() as Arc<dyn ironwood::types::PacketConn>,
                &signing_key,
            )
            .map_err(|e| YggmailError::Startup { message: format!("quic init: {e}") })?;
```

(Use the crate's existing error variant; match the surrounding `?`/error style at that call site.) Then rename the `ymp`/`rx_ymp`/`tx_ymp`/`warm_ymp` bindings to `transport` and update:
- receiver task: `rx_ymp.recv()` → `rx_transport.recv()` (the `mail_insert_inbox_dedup` + `imap_notify_tx.send(())` block is unchanged).
- sender spawn (line 230): `yggmail::peer::sender::spawn(tx_storage, tx_transport, core.clone(), Duration::from_secs(30));`.
- Path-warmer (lines 237-253): `recent_peers` was a `YmpSession` method. **Decision:** the path-warmer stays useful, but `QuicMailTransport` doesn't expose `recent_peers`. QUIC's own keep-alive is disabled (idle 30 min, no keep-alive) to match yggquic, so the ironwood path-warmer is still wanted. Add a `recent_peers(&self, within: Duration) -> Vec<[u8;32]>` method to `QuicMailTransport` that returns the keys of currently-cached connections (`self.conns.lock().await.keys().copied().collect()`), and point the warmer at it: `warm_transport.recent_peers(...)`. `ponytail: cached-connection keys are exactly the active correspondents; no separate activity map needed.`
- `NodeState._conn: conn` field stays (keeps `CoreConn` alive); if `NodeState` held an `ymp` field, replace it with `transport`.

- [ ] **Step 3: Add `recent_peers` to `QuicMailTransport` (edit `transport.rs`)**

```rust
    /// Keys of currently-cached (live) peer connections — the active
    /// correspondents whose Yggdrasil path the warmer should keep warm.
    pub async fn recent_peers(&self, _within: std::time::Duration) -> Vec<[u8; 32]> {
        self.conns
            .lock()
            .await
            .iter()
            .filter(|(_, c)| c.close_reason().is_none())
            .map(|(k, _)| *k)
            .collect()
    }
```

- [ ] **Step 4: Build both crates**

Run: `cargo build -p yggmail` and `cargo build -p yggmail-mobile`
Expected: PASS. (If `yggmail-mobile` needs the Android target to build fully, `cargo build -p yggmail-mobile` on host still type-checks the Rust.)

- [ ] **Step 5: Commit**

```bash
git add crates/yggmail/src/main.rs crates/yggmail-mobile/src/lib.rs crates/yggmail/src/quic/transport.rs
git commit -m "feat(quic): wire QuicMailTransport into desktop binary and mobile FFI"
```

---

### Task 11: Phase-2 interop verification (manual)

**No code.** Prove mail flows both directions with real partners. Storage untouched → old chats must still be present.

- [ ] **Step 1:** yggmail-ng debug node ↔ **Tyr 1.8.1** on a shared hub: send a mail each way; confirm receipt in INBOX (IMAP FETCH) on both.
- [ ] **Step 2:** yggmail-ng ↔ **yggmail-go + Thunderbird**: compose in Thunderbird to the yggmail-ng address; confirm arrival. Reply from yggmail-ng; confirm in Thunderbird.
- [ ] **Step 3:** Group send (multiple RCPT / multiple queue rows for one Outbox mail): confirm each recipient gets it and the Outbox→Sent move happens only after the last recipient (regression: outbox re-send spam).
- [ ] **Step 4:** Cross-hub, 3 devices behind different hubs: confirm delivery (regression: ironwood cross-hub ~1/10 routing — the return-path/forward-retry fixes ride under QUIC unchanged).
- [ ] **Step 5:** Restart the yggmail-ng node mid-session: confirm the same `@yggmail` address (Phase 0 identity), and that pre-existing DeltaChat mail + internal `X-Tyr-Chat` history are still readable.

**Phase 2 exit criteria:** all five green. Do NOT start Phase 3 until new↔old is proven.

---

# PHASE 3 — Delete YMP, QUIC is the only transport

Pure QUIC-only cutover, no receive-only window (user decision). Already-deployed 1.9.0-YMP nodes lose *live* delivery until they update; their local history is intact (storage untouched). **Do not ship the deletion until new↔new over QUIC is proven** (Task 13).

---

### Task 12: New↔new QUIC regression (the coverage YMP used to provide)

Before deleting YMP, prove QUIC alone covers everything YMP did between two yggmail-ng nodes.

**Files:**
- Test: extend `crates/yggmail/src/quic/transport.rs` `#[cfg(test)]`.

- [ ] **Step 1: Write failing tests — multi-mail on one connection + dedup + large body**

Append to the `transport.rs` test module:

```rust
    #[tokio::test]
    async fn multiple_mails_one_connection_and_large_body() {
        let mut rng = rand::rngs::OsRng;
        let key_a = SigningKey::generate(&mut rng);
        let key_b = SigningKey::generate(&mut rng);
        let pub_b = key_b.verifying_key().to_bytes();

        let (ca, cb) = MemPacketConn::pair(key_a.clone(), key_b.clone());
        let alice = QuicMailTransport::new(ca as Arc<dyn PacketConn>, &key_a).unwrap();
        let bob = QuicMailTransport::new(cb as Arc<dyn PacketConn>, &key_b).unwrap();

        // Three small mails (connection is cached & reused after the first).
        for i in 0..3 {
            let m = format!("Subject: n{i}\r\n\r\nbody {i}\r\n").into_bytes();
            alice.send(pub_b, m).await.expect("send");
        }
        for _ in 0..3 {
            let (_from, got) = tokio::time::timeout(std::time::Duration::from_secs(5), bob.recv())
                .await.expect("recv").expect("ok");
            assert!(String::from_utf8_lossy(&got).contains("body"));
        }

        // A ~256 KiB body survives QUIC stream flow-control (no YMP 32 MiB cap).
        let big = format!("Subject: big\r\n\r\n{}\r\n", "x".repeat(256 * 1024)).into_bytes();
        alice.send(pub_b, big.clone()).await.expect("send big");
        let (_f, got) = tokio::time::timeout(std::time::Duration::from_secs(10), bob.recv())
            .await.expect("recv big").expect("ok");
        assert!(got.len() > 256 * 1024);
    }
```

- [ ] **Step 2: Run to verify it fails, then passes**

Run: `cargo test -p yggmail quic::transport::tests::multiple_mails -- --nocapture`
Expected: If the accept-loop/connection-cache is correct from Task 7, this may PASS immediately (good — it is a regression guard). If it FAILs on the 2nd mail, the per-connection `accept_bi` loop isn't looping — fix `QuicMailTransport::new`'s inner loop.

- [ ] **Step 3: Commit**

```bash
git add crates/yggmail/src/quic/transport.rs
git commit -m "test(quic): new<->new regression — multi-mail per connection + large body"
```

---

### Task 13: Delete the YMP module

**Files:**
- Delete: `crates/yggmail/src/ymp/mod.rs`, `crates/yggmail/src/ymp/types.rs` (the whole `ymp/` dir)
- Modify: `crates/yggmail/src/lib.rs` (remove `pub mod ymp;` and the `pub use ymp::{...}` re-export)

- [ ] **Step 1: Confirm nothing outside `ymp/` still references it**

Run: `grep -rn "ymp\|YmpSession\|YmpError\|MessageId" crates/ --include=*.rs | grep -v "src/ymp/"`
Expected: no matches (all callers rewired in Phase 2). If any remain, fix them first.

- [ ] **Step 2: Delete the module and its declaration**

```bash
git rm -r crates/yggmail/src/ymp
```

In `crates/yggmail/src/lib.rs`, remove:
```rust
pub mod ymp;
// ...
pub use ymp::{MessageId, YmpError, YmpSession};
```

- [ ] **Step 3: Build + full test suite**

Run: `cargo build -p yggmail && cargo test -p yggmail`
Expected: PASS — YMP gone, overlay tests green, identity tests (Phase 0) green, SMTP/IMAP tests green.

- [ ] **Step 4: Commit**

```bash
git add -A
git commit -m "refactor(transport): remove YMP — QUIC/SMTP overlay is the sole mail transport"
```

---

### Task 14: Docs + full regression sign-off

**Files:**
- Modify: `Librarys/Yggmail-ng/CLAUDE.md`
- Modify: `Librarys/Yggmail-ng/README.md` (if present) and `Android/README`/`Android/CLAUDE.md` transport notes.

- [ ] **Step 1: Update `Librarys/Yggmail-ng/CLAUDE.md`**

- Architecture diagram: `←YMP→` → `←QUIC/SMTP→`.
- Crate/module table: replace the `ymp/` row with `quic/ — QUIC mail overlay (quinn over the mesh, yggquic-compatible)`.
- Design-decisions: remove "YMP over QUIC / Yggdrasil-ng provides only PacketConn" rationale; replace with "QUIC overlay: quinn over a `CoreUdpSocket` AsyncUdpSocket adapter, standard yggquic wire — interoperates with yggmail-go."
- Testing-patterns: delete the `#[ignore]`d YMP-integration note; add the hermetic `MemPacketConn` + quinn loopback pattern.

- [ ] **Step 2: Update Android-side notes** — any doc claiming the transport is a custom YMP now says "standard yggmail QUIC/SMTP transport (interoperable)."

- [ ] **Step 3: Final full regression (manual, all invariants)**

- [ ] new↔new over QUIC: delivery, dedup, IMAP FETCH, cross-hub 3-device (Task 12 covers hermetic; confirm live).
- [ ] new↔old: Tyr 1.8.1 + yggmail-go/Thunderbird both directions (Phase 2).
- [ ] **Old-chat preservation:** after 1.9.0-YMP → migrated upgrade on a device with existing history — same `@yggmail` address, prior DeltaChat mail present, internal `X-Tyr-Chat` conversations continue. Storage/at-rest untouched.
- [ ] Android: rebuild `.so` for all 4 ABI (`./build-android.sh`), device smoke test (onboarding → note address → send/recv to a desktop node → restart → same address + history).

- [ ] **Step 4: Commit**

```bash
git add -A
git commit -m "docs(transport): yggmail-ng runs standard yggmail QUIC/SMTP again"
```

---

## Explicitly NOT doing (YAGNI — from spec)

- Do **not** port yggquic verbatim — only its TLS/ALPN/address scheme, on `quinn`. (Done: reused `transport::tls`.)
- Do **not** enable link-`quic://`/`wss://` peering (available since `f77cb6c`; decision = mail overlay only). Peering stays on `tcp://`/`tls://`.
- Do **not** touch `yggdrasil::transport::tls`/link-QUIC (peering layer, not mail).
- Do **not** keep YMP as fallback; no receive-only-YMP transition (single transport, 1.9.0 casualty accepted).
- Do **not** alter the schema/content of `yggmail.db` or `tyr_chat.db` or the at-rest format.

---

## Self-Review (run against the spec)

**Spec coverage:**
- Фаза 1 (QUIC spike): Tasks 1–5 — adapter (`AsyncUdpSocket` over `CoreConn`, the "писать самим" piece), TLS reuse from `f77cb6c`, empty ALPN, 1200-MTU/30-min config, key pinning, hermetic + live handshake. ✓
- Фаза 2 (mail over QUIC): Tasks 6–11 — kick-byte, overlay SMTP server (From==peer crypto-enforce, INBOX via `mail_insert_inbox_dedup`), overlay SMTP client, `peer/sender`+`receiver` rewire, main.rs + mobile wiring, interop matrix (1.8.1, Thunderbird, group, cross-hub). ✓
- Фаза 3 (delete YMP): Tasks 12–14 — new↔new QUIC regression gate BEFORE deletion, module removal, old-chat-preservation regression, docs. ✓
- Compat table (empty ALPN, InsecureSkipVerify, RequireAnyClientCert-equiv via app-layer cert enforcement, ServerName=hex(pubkey), kick-byte once, 1200/PMTUD-off/30-min idle, `hex@yggmail`): mapped across Tasks 4/6/7. ✓
- Reuse list (identity Phase 0, `transport::tls`, `smtp` parsing, `mail_insert_inbox_dedup`, ironwood routing fixes, `address.rs`): honored. ✓
- Backward-compat invariant (storage/at-rest untouched, chats survive): asserted in Task 11 §5 and Task 14 §3. ✓

**Type consistency:** `QuicMailTransport::{new,send,recv,recent_peers}`, `QuicOverlay::{new,connect,accept}`, `peer_key`, `overlay_serve_stream`/`overlay_send_stream`, `CoreUdpSocket::new`, `AddrTable::{addr_for_key,key_for_addr}` are used identically across all tasks. `send` returns `Result<(), QuicMailError>` (sender matches on `Ok(())`, consistent).

**Placeholder scan:** the `super::mod_reexports` placeholder in Task 7 Step 3 is explicitly corrected in Step 4 to `use super::{peer_key, QuicOverlay};`. No TBD/TODO left.

**Open risk carried into execution:** exact quinn 0.11 minor-API spellings (`SendStream::finish()` signature, `Transmit`/`RecvMeta` field set) are pinned from docs.rs/0.11.8 but the compiler is the final authority — the TDD loop (write test → build → fix) absorbs any minor drift.
