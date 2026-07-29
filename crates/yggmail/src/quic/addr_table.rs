//! Двусторонняя карта между 32-байтными ed25519-ключами и синтетическими
//! `SocketAddr`. quinn мыслит `SocketAddr`, mesh — ключами. На каждый ключ
//! выдаётся один синтетический ULA-адрес (`fd00::/8`) по возрастающему счётчику;
//! обратное направление нужно, чтобы `try_send` восстановил настоящий ключ из
//! выбранного quinn назначения. На провод эти адреса не попадают.

use std::collections::HashMap;
use std::net::{Ipv6Addr, SocketAddr, SocketAddrV6};
use std::sync::Mutex;

#[derive(Debug, Default)]
pub(crate) struct AddrTable {
    inner: Mutex<Inner>,
}

#[derive(Debug, Default)]
struct Inner {
    by_key: HashMap<[u8; 32], SocketAddr>,
    by_addr: HashMap<SocketAddr, [u8; 32]>,
    next: u32,
}

impl AddrTable {
    /// Синтетический `SocketAddr` для ключа; выделяется при первом обращении.
    pub(crate) fn addr_for_key(&self, key: [u8; 32]) -> SocketAddr {
        let mut g = self.inner.lock().expect("addr table poisoned");
        if let Some(a) = g.by_key.get(&key) {
            return *a;
        }
        let idx = g.next;
        g.next += 1;
        let seg = idx.to_be_bytes();
        let ip = Ipv6Addr::new(
            0xfd00,
            0,
            0,
            0,
            0,
            0,
            u16::from_be_bytes([seg[0], seg[1]]),
            u16::from_be_bytes([seg[2], seg[3]]),
        );
        // Порт фиксированный ненулевой — quinn требует валидный адрес,
        // но сам порт нигде не используется.
        let addr = SocketAddr::V6(SocketAddrV6::new(ip, 1, 0, 0));
        g.by_key.insert(key, addr);
        g.by_addr.insert(addr, key);
        addr
    }

    /// Обратный поиск: ключ, под который был выдан синтетический адрес.
    pub(crate) fn key_for_addr(&self, addr: &SocketAddr) -> Option<[u8; 32]> {
        self.inner
            .lock()
            .expect("addr table poisoned")
            .by_addr
            .get(addr)
            .copied()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn same_key_maps_to_stable_addr_and_back() {
        let t = AddrTable::default();
        let key = [7u8; 32];
        let a1 = t.addr_for_key(key);
        let a2 = t.addr_for_key(key);
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
