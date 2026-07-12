//! Thin adapter: wraps `Arc<Core>` to implement `ironwood::PacketConn`.
//!
//! Delegates `read_from`/`write_to` to Core's type-byte-dispatching methods
//! (0x01=traffic, 0x02=proto). This lets YmpSession use Core directly while
//! keeping its existing `Arc<dyn PacketConn>` interface.
//!
//! ponytail: Core doesn't expose private_key or is_closed publicly, so those
//! are stubbed. Only read_from/write_to are on YMP's hot path.

use std::sync::Arc;

use ed25519_dalek::SigningKey;
use ironwood::types::{Addr, AsyncConn, Error, PacketConn, Result as IwResult};
use yggdrasil::core::Core;

pub struct CoreConn {
    core: Arc<Core>,
    signing_key: SigningKey,
}

impl CoreConn {
    pub fn new(core: Arc<Core>, signing_key: SigningKey) -> Arc<Self> {
        Arc::new(Self { core, signing_key })
    }
}

#[async_trait::async_trait]
impl PacketConn for CoreConn {
    async fn read_from(&self, buf: &mut [u8]) -> IwResult<(usize, Addr)> {
        self.core.read_from(buf).await
    }

    async fn write_to(&self, buf: &[u8], addr: &Addr) -> IwResult<usize> {
        self.core.write_to(buf, addr).await
    }

    async fn handle_conn(&self, key: Addr, conn: Box<dyn AsyncConn>, prio: u8) -> IwResult<()> {
        self.core.handle_conn(key.0, conn, prio).await
    }

    fn is_closed(&self) -> bool {
        false // ponytail: Core doesn't expose is_closed; not used by YMP
    }

    fn private_key(&self) -> &SigningKey {
        &self.signing_key
    }

    fn mtu(&self) -> u64 {
        self.core.mtu()
    }

    async fn send_lookup(&self, target: Addr) {
        self.core.send_lookup(target).await;
    }

    fn local_addr(&self) -> Addr {
        Addr(*self.core.public_key())
    }

    async fn close(&self) -> IwResult<()> {
        self.core.close().await
    }
}
