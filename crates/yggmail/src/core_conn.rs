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
use tokio::sync::Mutex as AsyncMutex;
use tokio::sync::mpsc;
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

/// QUIC Fixed Bit (RFC 9000 §17.2/§17.3). Взведён в каждом валидном QUIC-пакете:
/// long header 0xC0–0xFF, short header 0x40–0x7F. Типы YMP (0x10 DATA, 0x11 ACK,
/// 0x12 SYN, 0x13 SYN-ACK) его не имеют, поэтому множества не пересекаются.
const QUIC_FIXED_BIT: u8 = 0x40;

/// Наибольшая датаграмма, которую переносит mesh. Насос читает в буфер этого
/// размера, чтобы ничего не резать на входе.
const PUMP_BUF_BYTES: usize = 65535;

/// Один из двух видов на общий `PacketConn`. Читает только «свои» датаграммы
/// из очереди, которую наполняет насос демукса; запись и всё остальное —
/// напрямую в исходное соединение.
pub struct DemuxedConn {
    inner: Arc<dyn PacketConn>,
    signing_key: SigningKey,
    rx: AsyncMutex<mpsc::UnboundedReceiver<(Vec<u8>, Addr)>>,
}

/// Отдать `read_from` одному владельцу и развести датаграммы на две очереди.
///
/// Возвращает `(ymp_view, quic_view)`. Нужен только на время сосуществования
/// двух транспортов: когда YMP уйдёт, `CoreConn` передаётся в QUIC напрямую,
/// а эта функция удаляется.
///
/// ponytail: очереди неограниченные. Настоящий backpressure даёт DRR-очередь
/// ironwood ниже по стеку, а оба потребителя читают непрерывно.
pub fn demux(
    inner: Arc<dyn PacketConn>,
    signing_key: SigningKey,
) -> (Arc<DemuxedConn>, Arc<DemuxedConn>) {
    let (ymp_tx, ymp_rx) = mpsc::unbounded_channel();
    let (quic_tx, quic_rx) = mpsc::unbounded_channel();

    let pump = inner.clone();
    tokio::spawn(async move {
        let mut buf = vec![0u8; PUMP_BUF_BYTES];
        // Каждый маршрут отслеживается независимо: если один потребитель
        // ушёл, насос не должен глохнуть для второго — иначе выживший вид
        // тихо перестаёт получать входящий трафик, хотя write_to у него
        // продолжает как ни в чём не бывало работать.
        let mut ymp_alive = true;
        let mut quic_alive = true;
        loop {
            if !ymp_alive && !quic_alive {
                break;
            }
            match pump.read_from(&mut buf).await {
                Ok((0, _)) => continue,
                Ok((n, from)) => {
                    if buf[0] & QUIC_FIXED_BIT != 0 {
                        if quic_alive && quic_tx.send((buf[..n].to_vec(), from)).is_err() {
                            tracing::debug!("demux: quic consumer gone");
                            quic_alive = false;
                        }
                    } else if ymp_alive && ymp_tx.send((buf[..n].to_vec(), from)).is_err() {
                        tracing::debug!("demux: ymp consumer gone");
                        ymp_alive = false;
                    }
                }
                Err(e) => {
                    tracing::warn!("demux: read_from exiting: {e:?}");
                    break;
                }
            }
        }
    });

    let ymp_view = Arc::new(DemuxedConn {
        inner: inner.clone(),
        signing_key: signing_key.clone(),
        rx: AsyncMutex::new(ymp_rx),
    });
    let quic_view = Arc::new(DemuxedConn {
        inner,
        signing_key,
        rx: AsyncMutex::new(quic_rx),
    });
    (ymp_view, quic_view)
}

#[async_trait::async_trait]
impl PacketConn for DemuxedConn {
    async fn read_from(&self, buf: &mut [u8]) -> IwResult<(usize, Addr)> {
        let mut rx = self.rx.lock().await;
        loop {
            match rx.recv().await {
                Some((data, from)) => {
                    if data.len() > buf.len() {
                        // Резать нельзя: обрезанный QUIC-пакет молча провалит
                        // расшифровку и выглядит как потеря сети.
                        tracing::warn!(
                            "demux: dropping {}-byte datagram, buffer is {}",
                            data.len(),
                            buf.len()
                        );
                        continue;
                    }
                    buf[..data.len()].copy_from_slice(&data);
                    return Ok((data.len(), from));
                }
                None => return Err(Error::Closed),
            }
        }
    }

    async fn write_to(&self, buf: &[u8], addr: &Addr) -> IwResult<usize> {
        self.inner.write_to(buf, addr).await
    }

    async fn handle_conn(&self, key: Addr, conn: Box<dyn AsyncConn>, prio: u8) -> IwResult<()> {
        self.inner.handle_conn(key, conn, prio).await
    }

    fn is_closed(&self) -> bool {
        self.inner.is_closed()
    }

    fn private_key(&self) -> &SigningKey {
        &self.signing_key
    }

    fn mtu(&self) -> u64 {
        self.inner.mtu()
    }

    async fn send_lookup(&self, target: Addr) {
        self.inner.send_lookup(target).await;
    }

    fn local_addr(&self) -> Addr {
        self.inner.local_addr()
    }

    async fn close(&self) -> IwResult<()> {
        self.inner.close().await
    }
}

#[cfg(test)]
pub(crate) mod testutil {
    //! In-memory `PacketConn`-пара для герметичных тестов транспорта.
    //! В отличие от YMP-шного `ChanPacketConn`, quinn гоняет поверх этого
    //! дуплекса собственные таймеры и ретрансмиты, поэтому настоящий
    //! handshake проходит без живого mesh.
    use super::*;
    use ironwood::types::Error;
    use std::sync::atomic::{AtomicBool, Ordering};
    use tokio::sync::Mutex as AsyncMutex;
    use tokio::sync::mpsc;

    pub(crate) struct MemPacketConn {
        tx: mpsc::UnboundedSender<(Vec<u8>, Addr)>,
        rx: AsyncMutex<mpsc::UnboundedReceiver<(Vec<u8>, Addr)>>,
        signing_key: SigningKey,
        local: Addr,
        closed: AtomicBool,
    }

    impl MemPacketConn {
        pub(crate) fn pair(a: SigningKey, b: SigningKey) -> (Arc<Self>, Arc<Self>) {
            let addr_a = Addr(a.verifying_key().to_bytes());
            let addr_b = Addr(b.verifying_key().to_bytes());
            let (tx_a, rx_b) = mpsc::unbounded_channel();
            let (tx_b, rx_a) = mpsc::unbounded_channel();
            let ca = Arc::new(Self {
                tx: tx_a,
                rx: AsyncMutex::new(rx_a),
                signing_key: a,
                local: addr_a,
                closed: AtomicBool::new(false),
            });
            let cb = Arc::new(Self {
                tx: tx_b,
                rx: AsyncMutex::new(rx_b),
                signing_key: b,
                local: addr_b,
                closed: AtomicBool::new(false),
            });
            (ca, cb)
        }
    }

    #[async_trait::async_trait]
    impl PacketConn for MemPacketConn {
        async fn read_from(&self, buf: &mut [u8]) -> IwResult<(usize, Addr)> {
            match self.rx.lock().await.recv().await {
                Some((data, from)) => {
                    // Тихо режет, в отличие от DemuxedConn::read_from, который
                    // дропает целиком. Это тестовый двойник, и такая простота
                    // не мешает: единственный читатель — насос demux(), а он
                    // всегда читает буфером PUMP_BUF_BYTES (65535), который
                    // больше любой датаграммы mesh. Если PUMP_BUF_BYTES когда-
                    // нибудь уменьшат, это предположение может тихо сломаться.
                    let n = data.len().min(buf.len());
                    buf[..n].copy_from_slice(&data[..n]);
                    Ok((n, from))
                }
                None => Err(Error::Closed),
            }
        }
        async fn write_to(&self, buf: &[u8], _addr: &Addr) -> IwResult<usize> {
            // Пир видит нас как источник — как и в настоящем mesh.
            let _ = self.tx.send((buf.to_vec(), self.local));
            Ok(buf.len())
        }
        async fn handle_conn(&self, _k: Addr, _c: Box<dyn AsyncConn>, _p: u8) -> IwResult<()> {
            Ok(())
        }
        fn is_closed(&self) -> bool {
            self.closed.load(Ordering::Relaxed)
        }
        fn private_key(&self) -> &SigningKey {
            &self.signing_key
        }
        fn mtu(&self) -> u64 {
            65535
        }
        async fn send_lookup(&self, _t: Addr) {}
        fn local_addr(&self) -> Addr {
            self.local
        }
        async fn close(&self) -> IwResult<()> {
            self.closed.store(true, Ordering::Relaxed);
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use testutil::MemPacketConn;

    fn keys() -> (SigningKey, SigningKey) {
        (SigningKey::from_bytes(&[1u8; 32]), SigningKey::from_bytes(&[2u8; 32]))
    }

    /// Пакет с взведённым Fixed Bit уходит в QUIC-ветку, YMP-типы — в YMP-ветку.
    #[tokio::test]
    async fn splits_quic_and_ymp_by_fixed_bit() {
        let (ka, kb) = keys();
        let (a, b) = MemPacketConn::pair(ka.clone(), kb);
        let (ymp_view, quic_view) = demux(a as Arc<dyn PacketConn>, ka);

        // 0xC0 = long header, 0x40 = short header, 0x10 = YMP DATA, 0x11 = YMP ACK.
        for first in [0xC0u8, 0x10, 0x40, 0x11] {
            b.write_to(&[first, 0xAA, 0xBB], &Addr([0u8; 32])).await.unwrap();
        }

        let mut buf = [0u8; 64];
        let (n, _) = quic_view.read_from(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], &[0xC0, 0xAA, 0xBB], "long header must go to QUIC");
        let (n, _) = quic_view.read_from(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], &[0x40, 0xAA, 0xBB], "short header must go to QUIC");

        let (n, _) = ymp_view.read_from(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], &[0x10, 0xAA, 0xBB], "YMP DATA must go to YMP");
        let (n, _) = ymp_view.read_from(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], &[0x11, 0xAA, 0xBB], "YMP ACK must go to YMP");
    }

    /// Оба вида отдают исходный адрес источника без искажений.
    #[tokio::test]
    async fn preserves_source_address() {
        let (ka, kb) = keys();
        let peer = Addr(kb.verifying_key().to_bytes());
        let (a, b) = MemPacketConn::pair(ka.clone(), kb);
        let (_ymp_view, quic_view) = demux(a as Arc<dyn PacketConn>, ka);

        b.write_to(&[0xC0, 0x01], &Addr([0u8; 32])).await.unwrap();

        let mut buf = [0u8; 64];
        let (_n, from) = quic_view.read_from(&mut buf).await.unwrap();
        assert_eq!(from, peer);
    }

    /// Датаграмма больше буфера дропается с предупреждением, а не режется:
    /// обрезанный QUIC-пакет молча провалит расшифровку.
    #[tokio::test]
    async fn oversized_datagram_is_dropped_not_truncated() {
        let (ka, kb) = keys();
        let (a, b) = MemPacketConn::pair(ka.clone(), kb);
        let (_ymp_view, quic_view) = demux(a as Arc<dyn PacketConn>, ka);

        let mut big = vec![0xAAu8; 100];
        big[0] = 0xC0;
        b.write_to(&big, &Addr([0u8; 32])).await.unwrap();
        b.write_to(&[0xC0, 0x77], &Addr([0u8; 32])).await.unwrap();

        // Буфер на 8 байт: большой пакет обязан быть отброшен целиком,
        // а следующий — доставлен нетронутым.
        let mut buf = [0u8; 8];
        let (n, _) = quic_view.read_from(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], &[0xC0, 0x77], "oversized must be dropped, not truncated");
    }

    /// Если один потребитель ушёл, насос обязан продолжать обслуживать
    /// второй маршрут, а не глохнуть целиком (иначе выживший вид тихо
    /// перестаёт получать входящий трафик). Проваливается на старом
    /// поведении «break при первом неудачном send», потому что там весь
    /// насос — и оба tx внутри него — исчезает вместе с первой же ошибкой.
    #[tokio::test]
    async fn surviving_view_keeps_working_after_other_drops() {
        let (ka, kb) = keys();
        let (a, b) = MemPacketConn::pair(ka.clone(), kb);
        let (ymp_view, quic_view) = demux(a as Arc<dyn PacketConn>, ka);

        // Получатель YMP-маршрута уходит первым...
        drop(ymp_view);

        // ...а трафик для мёртвого маршрута отправляется раньше трафика для
        // живого, чтобы насос гарантированно наткнулся на неудачный send()
        // до того, как дойдёт до QUIC-датаграммы — иначе тест прошёл бы
        // и без починки.
        b.write_to(&[0x10, 0x01], &Addr([0u8; 32])).await.unwrap();
        b.write_to(&[0xC0, 0x02], &Addr([0u8; 32])).await.unwrap();

        let mut buf = [0u8; 64];
        let (n, _) = quic_view
            .read_from(&mut buf)
            .await
            .expect("surviving QUIC route must still receive datagrams after YMP view is dropped");
        assert_eq!(&buf[..n], &[0xC0, 0x02]);
    }
}
