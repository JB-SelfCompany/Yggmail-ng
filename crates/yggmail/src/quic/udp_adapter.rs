//! `quinn::AsyncUdpSocket` поверх ключ-адресуемого `PacketConn`.
//!
//! У quinn синхронный сокетный API (`try_send`, `poll_recv`), а у mesh
//! `write_to`/`read_from` асинхронные, поэтому их сводят два фоновых насоса:
//! исходящий сливает канал в `write_to`, входящий копирует датаграммы из
//! `read_from` в канал, который опрашивает `poll_recv`.

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
use crate::core_conn::PUMP_BUF_BYTES;

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

        // Исходящий насос: асинхронный write_to вне синхронного try_send.
        let send_conn = conn.clone();
        tokio::spawn(async move {
            while let Some((key, bytes)) = send_rx.recv().await {
                if let Err(e) = send_conn.write_to(&bytes, &Addr(key)).await {
                    tracing::debug!("quic: udp send error: {e:?}");
                }
            }
        });

        // Входящий насос: read_from → канал, ключ источника → синтетический адрес.
        let recv_conn = conn;
        let recv_table = table.clone();
        tokio::spawn(async move {
            // Тот же буфер, что у насоса демукса, чтобы ни один слой не резал
            // датаграммы: одна константа на двоих.
            let mut buf = vec![0u8; PUMP_BUF_BYTES];
            loop {
                // Симметрично исходящему насосу: без этого select входящий
                // насос замечает уничтоженный сокет только по следующей
                // датаграмме (send в закрытый канал), а пока пир молчит —
                // держит Arc<dyn PacketConn> вечно. На Android сервис
                // многократно останавливается/стартует, так что такие
                // задачи копятся одна за другим.
                tokio::select! {
                    _ = recv_tx.closed() => {
                        tracing::debug!("quic: udp recv pump exiting: socket dropped");
                        break;
                    }
                    r = recv_conn.read_from(&mut buf) => {
                        match r {
                            Ok((n, from)) => {
                                tracing::debug!("quic: datagram from {}", hex::encode(&from.0[..8]));
                                let addr = recv_table.addr_for_key(from.0);
                                if recv_tx.send((addr, buf[..n].to_vec())).is_err() {
                                    break; // сокет уничтожен
                                }
                            }
                            Err(e) => {
                                tracing::debug!("quic: udp recv pump exiting: {e:?}");
                                break;
                            }
                        }
                    }
                }
            }
        });

        Arc::new(Self { table, local, send_tx, recv_rx: Mutex::new(recv_rx) })
    }
}

impl AsyncUdpSocket for CoreUdpSocket {
    fn create_io_poller(self: Arc<Self>) -> Pin<Box<dyn UdpPoller>> {
        // Канал отправки неограниченный, поэтому запись принимается всегда;
        // настоящий backpressure даёт DRR-очередь ironwood ниже по стеку.
        Box::pin(AlwaysWritable)
    }

    fn try_send(&self, transmit: &Transmit<'_>) -> io::Result<()> {
        let key = self.table.key_for_addr(&transmit.destination).ok_or_else(|| {
            io::Error::new(io::ErrorKind::AddrNotAvailable, "unknown quic destination")
        })?;
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
        // ponytail: одна датаграмма за вызов — GSO/GRO поверх mesh не бывает.
        let mut rx = self.recv_rx.lock().expect("recv rx poisoned");
        loop {
            match rx.poll_recv(cx) {
                Poll::Ready(Some((addr, data))) => {
                    if data.len() > bufs[0].len() {
                        // Резать нельзя: обрезанный QUIC-пакет провалит
                        // расшифровку и будет неотличим от потери сети.
                        tracing::warn!(
                            "quic: dropping {}-byte datagram, quinn buffer is {}",
                            data.len(),
                            bufs[0].len()
                        );
                        continue;
                    }
                    let n = data.len();
                    bufs[0][..n].copy_from_slice(&data);
                    meta[0] = RecvMeta { addr, len: n, stride: n, ecn: None, dst_ip: None };
                    return Poll::Ready(Ok(1));
                }
                Poll::Ready(None) => {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::BrokenPipe,
                        "udp recv pump closed",
                    )));
                }
                Poll::Pending => return Poll::Pending,
            }
        }
    }

    fn local_addr(&self) -> io::Result<SocketAddr> {
        Ok(self.local)
    }

    fn max_transmit_segments(&self) -> usize {
        1
    }

    fn max_receive_segments(&self) -> usize {
        1
    }

    fn may_fragment(&self) -> bool {
        false
    }
}

#[derive(Debug)]
struct AlwaysWritable;

impl UdpPoller for AlwaysWritable {
    fn poll_writable(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core_conn::testutil::MemPacketConn;
    use ed25519_dalek::SigningKey;
    use ironwood::types::PacketConn as _;
    use quinn::AsyncUdpSocket as _;

    #[tokio::test]
    async fn reports_local_addr_and_round_trips_peer_key() {
        let ka = SigningKey::from_bytes(&[3u8; 32]);
        let kb = SigningKey::from_bytes(&[4u8; 32]);
        let (a, b) = MemPacketConn::pair(ka, kb);
        let b_key = b.local_addr().0;

        let table = Arc::new(AddrTable::default());
        let sock = CoreUdpSocket::new(a as Arc<dyn PacketConn>, table.clone());

        assert!(sock.local_addr().is_ok(), "adapter must report a local addr");

        let peer_addr = table.addr_for_key(b_key);
        assert_eq!(table.key_for_addr(&peer_addr), Some(b_key));
    }

    /// Датаграмма, отправленная через quinn-овский `try_send`, доезжает до пира
    /// по mesh с правильным ключом назначения.
    #[tokio::test]
    async fn try_send_reaches_the_peer() {
        let ka = SigningKey::from_bytes(&[5u8; 32]);
        let kb = SigningKey::from_bytes(&[6u8; 32]);
        let (a, b) = MemPacketConn::pair(ka, kb);
        let b_key = b.local_addr().0;

        let table = Arc::new(AddrTable::default());
        let sock = CoreUdpSocket::new(a as Arc<dyn PacketConn>, table.clone());
        let dest = table.addr_for_key(b_key);

        sock.try_send(&quinn::udp::Transmit {
            destination: dest,
            ecn: None,
            contents: &[0xC0, 0x42],
            segment_size: None,
            src_ip: None,
        })
        .expect("try_send accepted");

        let mut buf = [0u8; 16];
        let (n, _from) = b.read_from(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], &[0xC0, 0x42]);
    }

    /// Неизвестное назначение — ошибка, а не паника и не тихий дроп.
    #[tokio::test]
    async fn try_send_to_unknown_destination_errors() {
        let ka = SigningKey::from_bytes(&[7u8; 32]);
        let kb = SigningKey::from_bytes(&[8u8; 32]);
        let (a, _b) = MemPacketConn::pair(ka, kb);
        let table = Arc::new(AddrTable::default());
        let sock = CoreUdpSocket::new(a as Arc<dyn PacketConn>, table);

        let res = sock.try_send(&quinn::udp::Transmit {
            destination: "[fd00::dead]:1".parse().unwrap(),
            ecn: None,
            contents: &[0xC0],
            segment_size: None,
            src_ip: None,
        });
        assert!(res.is_err(), "unknown destination must error");
    }

    /// `poll_recv` должен отбрасывать датаграмму, не влезающую в буфер quinn,
    /// а не обрезать её — обрезанный QUIC-пакет провалит расшифровку и будет
    /// неотличим от потери сети. Большая датаграмма уходит первой, чтобы
    /// путь дропа реально сработал прежде, чем придёт валидная.
    #[tokio::test]
    async fn poll_recv_drops_oversized_datagram_but_delivers_the_next() {
        let ka = SigningKey::from_bytes(&[9u8; 32]);
        let kb = SigningKey::from_bytes(&[10u8; 32]);
        let (a, b) = MemPacketConn::pair(ka, kb);

        let table = Arc::new(AddrTable::default());
        let sock = CoreUdpSocket::new(a as Arc<dyn PacketConn>, table);

        let big = vec![0xAAu8; 100];
        b.write_to(&big, &Addr([0u8; 32])).await.unwrap();
        b.write_to(&[0xC0, 0x77], &Addr([0u8; 32])).await.unwrap();

        // quinn выделяет под poll_recv буфер на 8 байт: 100-байтовая
        // датаграмма в него не влезает и обязана быть отброшена целиком.
        let mut recv_buf = [0u8; 8];
        let mut iov = [IoSliceMut::new(&mut recv_buf)];
        let mut meta = [RecvMeta {
            addr: "[::1]:0".parse().unwrap(),
            len: 0,
            stride: 0,
            ecn: None,
            dst_ip: None,
        }];

        let mut task = tokio_test::task::spawn(());
        let mut result = None;
        for _ in 0..200 {
            let poll = task.enter(|cx, _| sock.poll_recv(cx, &mut iov, &mut meta));
            match poll {
                Poll::Ready(r) => {
                    result = Some(r);
                    break;
                }
                Poll::Pending => tokio::time::sleep(std::time::Duration::from_millis(5)).await,
            }
        }

        let n = result
            .expect("poll_recv must eventually become ready")
            .expect("poll_recv must not error");
        assert_eq!(n, 1);
        assert_eq!(
            &recv_buf[..meta[0].len],
            &[0xC0, 0x77],
            "oversized datagram must be dropped, not truncated into the buffer"
        );
    }
}
