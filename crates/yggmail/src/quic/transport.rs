//! Фасад почтового транспорта формы `YmpSession`: `send()` / `recv()`.
//!
//! Один `QuicOverlay` и дозванивается, и принимает. Исходящее письмо едет по
//! свежему bidi-стриму существующего соединения; входящее принимается фоновым
//! циклом и складывается в канал, который опрашивает `recv()`.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use ed25519_dalek::SigningKey;
use ironwood::types::PacketConn;
use quinn::Connection;
use tokio::io::AsyncWriteExt;
use tokio::sync::{Mutex as AsyncMutex, mpsc};

use super::smtp_overlay::{OverlayError, overlay_send_stream, overlay_serve_stream};
use super::{QuicOverlay, peer_key};
use crate::address::create_address;

/// Глубина очереди входящих писем до того, как цикл приёма упрётся в
/// backpressure. ponytail: письма редкие, 64 хватает с запасом.
const RECV_QUEUE_DEPTH: usize = 64;

#[derive(Debug)]
pub enum QuicMailError {
    Transport(String),
    Dialog(String),
    Closed,
}

impl std::fmt::Display for QuicMailError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            QuicMailError::Transport(s) => write!(f, "quic transport: {s}"),
            QuicMailError::Dialog(s) => write!(f, "smtp dialog: {s}"),
            QuicMailError::Closed => write!(f, "transport closed"),
        }
    }
}
impl std::error::Error for QuicMailError {}
impl From<OverlayError> for QuicMailError {
    fn from(e: OverlayError) -> Self {
        QuicMailError::Dialog(e.to_string())
    }
}

pub struct QuicMailTransport {
    overlay: Arc<QuicOverlay>,
    local_key: [u8; 32],
    conns: AsyncMutex<HashMap<[u8; 32], Connection>>,
    active_peers: AsyncMutex<HashMap<[u8; 32], Instant>>,
    recv_rx: AsyncMutex<mpsc::Receiver<([u8; 32], Vec<u8>)>>,
}

impl QuicMailTransport {
    pub fn new(conn: Arc<dyn PacketConn>, signing_key: &SigningKey) -> Result<Arc<Self>, String> {
        let local_key = signing_key.verifying_key().to_bytes();
        let overlay = Arc::new(QuicOverlay::new(conn, signing_key)?);
        let (recv_tx, recv_rx) = mpsc::channel(RECV_QUEUE_DEPTH);

        let me = Arc::new(Self {
            overlay: overlay.clone(),
            local_key,
            conns: AsyncMutex::new(HashMap::new()),
            active_peers: AsyncMutex::new(HashMap::new()),
            recv_rx: AsyncMutex::new(recv_rx),
        });

        // Цикл приёма: соединение → стримы → серверный диалог → канал.
        //
        // Держать здесь сильный Arc<Self> сделало бы транспорт неубиваемым:
        // единственный выход из цикла — overlay.accept(), возвращающий None,
        // а это требует, чтобы Endpoint внутри QuicOverlay уже уронили, что
        // не случится, пока эта задача держит на него сильную ссылку.
        // Вместо AbortHandle/close()-метода цикл слушает тот же сигнал о
        // смерти владельца, что и насос в udp_adapter.rs: closed() на
        // отправителе канала, чей получатель живёт внутри Self. Когда Self
        // роняют, recv_rx роняется вместе с ним, closed() срабатывает — и
        // цикл выходит сам, отпуская overlay.
        let weak_self = Arc::downgrade(&me);
        tokio::spawn(async move {
            loop {
                let incoming = tokio::select! {
                    _ = recv_tx.closed() => {
                        tracing::debug!("quic: accept loop exiting: transport dropped");
                        break;
                    }
                    incoming = overlay.accept() => incoming,
                };
                let Some(incoming) = incoming else {
                    break;
                };
                let connection = match incoming {
                    Ok(c) => c,
                    Err(e) => {
                        tracing::debug!("quic: accept failed: {e}");
                        continue;
                    }
                };
                // Ключ пира обязателен: он и есть аутентификация. Соединение
                // без сертификата (или с не-ed25519) отвергается — это то же
                // требование, что RequireAnyClientCert на Go-стороне.
                let Some(pk) = peer_key(&connection) else {
                    tracing::warn!("quic: rejecting connection without a pinned ed25519 key");
                    connection.close(1u32.into(), b"no peer key");
                    continue;
                };
                // Сертификат ничего не доказывает: verify_tls13_signature в общем
                // верификаторе возвращает assertion(), поэтому пир может заявить
                // чужой ключ, не владея приватным. Публичный ключ = почтовый
                // адрес, то есть общеизвестен. Сверяем с адресом источника
                // датаграмм — его подделать нельзя, он подтверждён шифрованной
                // сессией ironwood. Go делает то же самое (session_remote.go:41-43).
                match overlay.source_key(&connection) {
                    Some(src) if src == pk => {}
                    _ => {
                        tracing::warn!(
                            "quic: rejecting {} — cert key does not match mesh source",
                            hex::encode(&pk[..8])
                        );
                        connection.close(1u32.into(), b"cert key does not match mesh source");
                        continue;
                    }
                }
                tracing::info!("quic: handshake ok peer={}", hex::encode(&pk[..8]));
                let Some(strong_self) = weak_self.upgrade() else {
                    tracing::debug!("quic: accept loop exiting: transport dropped");
                    break;
                };
                strong_self.note_active(pk).await;
                let local_key = strong_self.local_key;
                drop(strong_self);

                let tx = recv_tx.clone();
                tokio::spawn(async move {
                    loop {
                        let (send, recv) = match connection.accept_bi().await {
                            Ok(s) => s,
                            Err(e) => {
                                tracing::debug!(
                                    "quic: peer {} closed: {e}",
                                    hex::encode(&pk[..8])
                                );
                                return;
                            }
                        };
                        let tx = tx.clone();
                        tokio::spawn(async move {
                            match serve_one_stream(recv, send, local_key, pk).await {
                                Ok((from, mail)) => {
                                    if tx.send((from, mail)).await.is_err() {
                                        tracing::debug!("quic: recv queue closed");
                                    }
                                }
                                Err(e) => {
                                    tracing::warn!(
                                        "quic: inbound dialog from {} failed: {e}",
                                        hex::encode(&pk[..8])
                                    );
                                }
                            }
                        });
                    }
                });
            }
            tracing::debug!("quic: accept loop exiting");
        });

        Ok(me)
    }

    /// Отправить одно письмо пиру. Блокируется до подтверждения `250`.
    pub async fn send(&self, dest: [u8; 32], message: Vec<u8>) -> Result<(), QuicMailError> {
        let connection = self.connection_for(dest).await?;

        let (mut send, recv) = match connection.open_bi().await {
            Ok(s) => s,
            Err(e) => {
                // Закэшированное соединение могло протухнуть — выбросить и
                // дать следующей попытке дозвониться заново.
                self.conns.lock().await.remove(&dest);
                return Err(QuicMailError::Transport(format!("open_bi: {e}")));
            }
        };

        // Kick-байт: пир узнаёт о стриме только с первым STREAM-фреймом, без
        // него его accept_bi() не вернётся никогда (`kickbyte_conn.go`).
        send.write_all(&[0u8])
            .await
            .map_err(|e| QuicMailError::Transport(format!("kick byte: {e}")))?;
        send.flush()
            .await
            .map_err(|e| QuicMailError::Transport(format!("kick flush: {e}")))?;
        tracing::info!("quic: stream open, kick sent to {}", hex::encode(&dest[..8]));

        // EHLO должен нести hex нашего ключа: Go-сервер сверяет его с адресом
        // источника датаграмм и иначе отвечает 502 (см. overlay_send_stream).
        let local_hostname = hex::encode(self.local_key);
        let from = create_address(&self.local_key);
        let rcpts = vec![create_address(&dest)];
        overlay_send_stream(recv, send, &local_hostname, &from, &rcpts, &message).await?;

        self.note_active(dest).await;
        Ok(())
    }

    /// Получить следующее входящее письмо: `(ключ отправителя, RFC 5322)`.
    pub async fn recv(&self) -> Result<([u8; 32], Vec<u8>), QuicMailError> {
        self.recv_rx
            .lock()
            .await
            .recv()
            .await
            .ok_or(QuicMailError::Closed)
    }

    /// Пиры, активные за последние `within` — для прогревателя путей.
    pub async fn recent_peers(&self, within: Duration) -> Vec<[u8; 32]> {
        let now = Instant::now();
        self.active_peers
            .lock()
            .await
            .iter()
            .filter(|(_, seen)| now.duration_since(**seen) <= within)
            .map(|(k, _)| *k)
            .collect()
    }

    /// Сколько соединений сейчас в кэше (для тестов).
    ///
    /// `try_lock`, а не `blocking_lock`: последний паникует при вызове изнутри
    /// рантайма tokio, а вызывают его как раз из `#[tokio::test]`.
    pub fn cached_connection_count(&self) -> usize {
        self.conns.try_lock().map(|g| g.len()).unwrap_or(0)
    }

    /// `stable_id()` закэшированного соединения к `dest` (для тестов).
    ///
    /// Количество записей в кэше не отличает переиспользование соединения от
    /// передозвона, перезаписавшего тот же слот — `stable_id()` уникален на
    /// процесс, поэтому равенство двух id доказывает именно переиспользование.
    #[cfg(test)]
    pub(crate) async fn cached_connection_stable_id(&self, dest: [u8; 32]) -> Option<usize> {
        self.conns.lock().await.get(&dest).map(|c| c.stable_id())
    }

    async fn connection_for(&self, dest: [u8; 32]) -> Result<Connection, QuicMailError> {
        {
            let cache = self.conns.lock().await;
            if let Some(c) = cache.get(&dest) {
                if c.close_reason().is_none() {
                    return Ok(c.clone());
                }
            }
        }
        let c = self
            .overlay
            .connect(dest)
            .await
            .map_err(QuicMailError::Transport)?;
        match peer_key(&c) {
            Some(pk) if pk == dest => {
                tracing::info!("quic: handshake ok peer={}", hex::encode(&dest[..8]));
            }
            _ => {
                c.close(1u32.into(), b"peer key mismatch");
                return Err(QuicMailError::Transport(
                    "peer certificate key does not match the dialled address".into(),
                ));
            }
        }
        // Дозвон шёл без лока (иначе дозвоны к разным пирам сериализовались
        // бы друг за другом), так что конкурентный send() к тому же пиру мог
        // успеть вставить своё соединение первым. Двойная проверка перед
        // вставкой не даёт двум живым соединениям на одного пира разойтись:
        // проигравшее закрывается сразу, а не висит до 30-минутного
        // idle-таймаута, будучи уже недостижимым из кэша.
        let mut cache = self.conns.lock().await;
        if let Some(existing) = cache.get(&dest) {
            if existing.close_reason().is_none() {
                c.close(0u32.into(), b"duplicate connection, using cached");
                return Ok(existing.clone());
            }
        }
        cache.insert(dest, c.clone());
        Ok(c)
    }

    async fn note_active(&self, key: [u8; 32]) {
        self.active_peers.lock().await.insert(key, Instant::now());
    }
}

/// Съесть kick-байт и провести серверный диалог на одном стриме.
async fn serve_one_stream(
    mut recv: quinn::RecvStream,
    send: quinn::SendStream,
    local_key: [u8; 32],
    peer: [u8; 32],
) -> Result<([u8; 32], Vec<u8>), QuicMailError> {
    let mut kick = [0u8; 1];
    recv.read_exact(&mut kick)
        .await
        .map_err(|e| QuicMailError::Transport(format!("kick byte: {e}")))?;
    tracing::info!("quic: stream open, kick consumed from {}", hex::encode(&peer[..8]));

    let (from, mail) = overlay_serve_stream(recv, send, local_key, peer).await?;
    tracing::info!("smtp-overlay: DATA {} bytes from {}", mail.len(), hex::encode(&peer[..8]));
    Ok((from, mail))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core_conn::testutil::MemPacketConn;
    use ed25519_dalek::SigningKey;

    /// Сквозной путь поверх mesh-адаптера: `send()` у одного узла даёт `recv()`
    /// у другого с телом письма и ключом отправителя. Это тот самый
    /// интеграционный тест YMP, который стоял под `#[ignore]` — теперь он
    /// герметичен, потому что quinn гоняет настоящий ввод-вывод.
    #[tokio::test]
    async fn send_then_recv_over_quic_overlay() {
        let key_a = SigningKey::from_bytes(&[11u8; 32]);
        let key_b = SigningKey::from_bytes(&[12u8; 32]);
        let pub_a = key_a.verifying_key().to_bytes();
        let pub_b = key_b.verifying_key().to_bytes();

        let (conn_a, conn_b) = MemPacketConn::pair(key_a.clone(), key_b.clone());
        let alice = QuicMailTransport::new(conn_a as Arc<dyn PacketConn>, &key_a).unwrap();
        let bob = QuicMailTransport::new(conn_b as Arc<dyn PacketConn>, &key_b).unwrap();

        let mail = b"Subject: Meshmail\r\nFrom: a\r\n\r\nHello over QUIC\r\n".to_vec();
        alice.send(pub_b, mail.clone()).await.expect("send ok");

        let (from, got) = tokio::time::timeout(std::time::Duration::from_secs(10), bob.recv())
            .await
            .expect("recv did not time out")
            .expect("recv ok");

        assert_eq!(from, pub_a, "receiver must see the sender's key");
        assert!(
            String::from_utf8_lossy(&got).contains("Hello over QUIC"),
            "body delivered"
        );
    }

    /// Второе письмо тому же пиру переиспользует закэшированное соединение.
    #[tokio::test]
    async fn reuses_cached_connection() {
        let key_a = SigningKey::from_bytes(&[13u8; 32]);
        let key_b = SigningKey::from_bytes(&[14u8; 32]);
        let pub_b = key_b.verifying_key().to_bytes();

        let (conn_a, conn_b) = MemPacketConn::pair(key_a.clone(), key_b.clone());
        let alice = QuicMailTransport::new(conn_a as Arc<dyn PacketConn>, &key_a).unwrap();
        let bob = QuicMailTransport::new(conn_b as Arc<dyn PacketConn>, &key_b).unwrap();

        alice.send(pub_b, b"Subject: one\r\n\r\n1\r\n".to_vec()).await.unwrap();
        let _ = tokio::time::timeout(std::time::Duration::from_secs(10), bob.recv()).await.unwrap();
        let first_id = alice
            .cached_connection_stable_id(pub_b)
            .await
            .expect("connection cached after first send");

        alice.send(pub_b, b"Subject: two\r\n\r\n2\r\n".to_vec()).await.unwrap();
        let _ = tokio::time::timeout(std::time::Duration::from_secs(10), bob.recv()).await.unwrap();
        let second_id = alice
            .cached_connection_stable_id(pub_b)
            .await
            .expect("connection cached after second send");

        assert_eq!(alice.cached_connection_count(), 1, "one cached connection per peer");
        assert_eq!(
            first_id, second_id,
            "second send must reuse the cached QUIC connection, not redial"
        );
    }

    /// Недавно активные пиры видны прогревателю путей.
    #[tokio::test]
    async fn tracks_recent_peers() {
        let key_a = SigningKey::from_bytes(&[15u8; 32]);
        let key_b = SigningKey::from_bytes(&[16u8; 32]);
        let pub_b = key_b.verifying_key().to_bytes();

        let (conn_a, conn_b) = MemPacketConn::pair(key_a.clone(), key_b.clone());
        let alice = QuicMailTransport::new(conn_a as Arc<dyn PacketConn>, &key_a).unwrap();
        let bob = QuicMailTransport::new(conn_b as Arc<dyn PacketConn>, &key_b).unwrap();

        alice.send(pub_b, b"Subject: x\r\n\r\nx\r\n".to_vec()).await.unwrap();
        let _ = tokio::time::timeout(std::time::Duration::from_secs(10), bob.recv()).await.unwrap();

        let recent = alice.recent_peers(std::time::Duration::from_secs(60)).await;
        assert!(recent.contains(&pub_b), "peer must be tracked as recently active");
    }

    /// Пир, чей сертификат заявляет чужой ключ, должен быть отвергнут.
    ///
    /// Сертификат ничего не доказывает: общий верификатор возвращает
    /// assertion() вместо проверки CertificateVerify. Единственное надёжное
    /// свидетельство — mesh-адрес источника, аутентифицированный шифрованной
    /// сессией ironwood.
    #[tokio::test]
    async fn rejects_peer_whose_cert_key_is_not_its_mesh_address() {
        let attacker_mesh = SigningKey::from_bytes(&[21u8; 32]);
        let victim = SigningKey::from_bytes(&[22u8; 32]);
        let server_key = SigningKey::from_bytes(&[23u8; 32]);
        let server_pub = server_key.verifying_key().to_bytes();

        let (conn_att, conn_srv) = MemPacketConn::pair(attacker_mesh.clone(), server_key.clone());

        // Датаграммы уйдут с mesh-ключа атакующего, а сертификат заявит жертву.
        let attacker = QuicMailTransport::new(conn_att as Arc<dyn PacketConn>, &victim).unwrap();
        let server = QuicMailTransport::new(conn_srv as Arc<dyn PacketConn>, &server_key).unwrap();

        let _ = attacker
            .send(server_pub, b"Subject: spoof\r\n\r\nnot me\r\n".to_vec())
            .await;

        // Ничего не должно доехать до recv(): соединение обязано быть закрыто
        // до SMTP-диалога.
        let got = tokio::time::timeout(std::time::Duration::from_secs(3), server.recv()).await;
        assert!(
            got.is_err(),
            "spoofed peer must not deliver mail, got {:?}",
            got.map(|r| r.map(|(k, _)| hex::encode(k)))
        );
    }
}
