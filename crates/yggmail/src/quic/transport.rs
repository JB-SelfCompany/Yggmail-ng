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
use tokio::sync::{Mutex as AsyncMutex, mpsc, oneshot};

use super::smtp_overlay::{
    OverlayError, overlay_send_stream, overlay_serve_stream, write_data_reply,
};
use super::{QuicOverlay, peer_key};
use crate::address::create_address;

/// Глубина очереди входящих писем до того, как цикл приёма упрётся в
/// backpressure. ponytail: письма редкие, 64 хватает с запасом.
const RECV_QUEUE_DEPTH: usize = 64;

/// Дозвон до пира ограничен этим временем — совпадает с
/// `HandshakeIdleTimeout: 10s` у Go (`internal/transport/yggdrasil.go:57`).
/// Дольше — пир недоступен, и очередь обязана перейти к следующему адресату,
/// а не ждать 30-минутный `max_idle_timeout` из `overlay_transport_config`.
const DIAL_TIMEOUT: Duration = Duration::from_secs(10);

/// Весь SMTP-диалог по уже открытому соединению: `open_bi` + kick-байт +
/// `overlay_send_stream`. YMP, который заменили, давал попытке 30с; здесь
/// диалог многошаговый (EHLO/MAIL/RCPT/DATA), поэтому бюджет шире. Это
/// накладные расходы протокола, отдельные от переноса тела DATA — само тело
/// добавляет свой бюджет поверх, см. `MIN_THROUGHPUT`.
const DIALOG_TIMEOUT: Duration = Duration::from_secs(120);

/// Таймаут должен ограничивать простой, а не саму работу. `DIALOG_TIMEOUT`
/// один на всех делает `MAX_DATA_BYTES` (33 МиБ, `smtp_overlay.rs`) недостижимым
/// на медленном многошаговом пути: 33 МиБ за 120с — это ~275 КБ/с сквозь mesh,
/// и письмо ниже этой скорости обречено таймаутиться на каждой попытке отправки
/// вечно. Поэтому бюджет диалога растёт с размером письма: `DIALOG_TIMEOUT` —
/// это фиксированные накладные расходы протокола (EHLO/MAIL/RCPT/DATA-заголовок),
/// а `message.len() / MIN_THROUGHPUT` — присланное сверху время на сам перенос
/// тела при худшей допустимой скорости. 32 КиБ/с выбраны так, чтобы 33 МиБ
/// укладывались в ~20 минут — меньше 30-минутного `max_idle_timeout` в
/// `overlay_transport_config`, то есть транспорт не убьёт соединение, которое
/// реально продвигается. Мёртвый пир по-прежнему стоит очереди только
/// `DIAL_TIMEOUT` — этот бюджет расширяет только диалог с уже дозвонившимся,
/// живым, но медленным пиром.
const MIN_THROUGHPUT: u64 = 32 * 1024;

/// Сколько входящий диалог ждёт подтверждения укладки, прежде чем ответить
/// `451`. Работы здесь на один INSERT в локальную SQLite; бюджет с запасом
/// покрывает и заблокированную на секунды базу, и потребителя, который в этот
/// момент дожёвывает предыдущее письмо. Всё, что дольше, означает, что
/// потребитель `recv()` встал или его вовсе нет — тогда честнее сказать пиру
/// `451` и дать ему повторить, чем держать стрим открытым до конца бюджета
/// диалога. Держится ниже `DIALOG_TIMEOUT` (120с) с обеих сторон: пир 1.8
/// должен получить наш ответ раньше, чем сам сдастся по таймауту.
const DURABILITY_TIMEOUT: Duration = Duration::from_secs(30);

/// Подтверждение долговечности: потребитель шлёт `()` после того, как письмо
/// уложено в INBOX (или признано дубликатом — оно durable уже с прошлой
/// доставки). Уронить отправитель, не послав ничего, — это «не уложено», и
/// диалог отвечает пиру `451`.
pub type DurabilityAck = oneshot::Sender<()>;

/// Входящее письмо: ключ отправителя, сырой RFC 5322 и подтверждение укладки.
///
/// Подтверждение — `Option`, потому что YMP его не требует: у того протокола
/// нет квитанции в проводе, подтверждать нечего, и его ветка в `select!`
/// подставляет `None`. Для QUIC он всегда `Some`, и потребитель обязан его
/// отправить, иначе пир получит `451` и доставит письмо ещё раз.
pub type InboundMail = ([u8; 32], Vec<u8>, Option<DurabilityAck>);

/// Эффективный бюджет диалога для письма данного размера: фиксированные
/// накладные расходы плюс время на передачу тела при `MIN_THROUGHPUT`.
/// Сложение насыщающее — не ради переполнения (`MAX_DATA_BYTES` уже держит
/// `message.len()` в разумных пределах), а чтобы не тащить сюда лишнюю
/// проверку ради одной операции.
fn dialog_budget(message_len: usize) -> Duration {
    DIALOG_TIMEOUT.saturating_add(Duration::from_secs(message_len as u64 / MIN_THROUGHPUT))
}

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
    recv_rx: AsyncMutex<mpsc::Receiver<InboundMail>>,
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
                            if let Err(e) = serve_one_stream(recv, send, local_key, pk, tx).await {
                                tracing::warn!(
                                    "quic: inbound dialog from {} failed: {e}",
                                    hex::encode(&pk[..8])
                                );
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
        let budget = dialog_budget(message.len());

        match tokio::time::timeout(budget, self.dialog(&connection, dest, &message)).await {
            Ok(result) => result,
            Err(_) => {
                // Пир мог принять хендшейк и затем замолчать: idle-таймаут
                // соединения — 1800с, и keep-alive не даёт ему сработать, пока
                // транспорт вообще жив. Раз диалог не продвинулся за отведённое
                // время, закрыть соединение и выбросить его из кэша — иначе
                // следующий send() к тому же пиру унаследует тот же труп и
                // снова простоит полный таймаут (`open_bi` на закэшированном
                // соединении к молчащему пиру не вернёт ошибку сам по себе).
                connection.close(0u32.into(), b"dialog timeout");
                self.conns.lock().await.remove(&dest);
                Err(QuicMailError::Transport(format!(
                    "dialog: {}",
                    std::io::Error::from(std::io::ErrorKind::TimedOut)
                )))
            }
        }
    }

    /// Один SMTP-диалог по уже установленному соединению: `open_bi` + kick-
    /// байт + `overlay_send_stream`. Вынесено из `send()`, чтобы весь диалог
    /// целиком помещался под один `tokio::time::timeout`.
    async fn dialog(
        &self,
        connection: &Connection,
        dest: [u8; 32],
        message: &[u8],
    ) -> Result<(), QuicMailError> {
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
        overlay_send_stream(recv, send, &local_hostname, &from, &rcpts, message).await?;

        self.note_active(dest).await;
        Ok(())
    }

    /// Получить следующее входящее письмо: `(ключ отправителя, RFC 5322,
    /// подтверждение укладки)`.
    ///
    /// Пир всё ещё ждёт ответа на DATA. Отправить подтверждение — обязанность
    /// вызывающего, и только после того, как письмо реально уложено: пока
    /// подтверждения нет, пир не получит `250` и не снимет свою копию.
    pub async fn recv(&self) -> Result<InboundMail, QuicMailError> {
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
        let c = match tokio::time::timeout(DIAL_TIMEOUT, self.overlay.connect(dest)).await {
            Ok(Ok(c)) => c,
            Ok(Err(e)) => return Err(QuicMailError::Transport(e)),
            Err(_) => {
                // `connect()` не вставляет ничего в кэш до успеха, так что
                // тут нечего выбрасывать — следующий send() дозвонится заново
                // сам по себе.
                return Err(QuicMailError::Transport(format!(
                    "dial: {}",
                    std::io::Error::from(std::io::ErrorKind::TimedOut)
                )));
            }
        };
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

/// Съесть kick-байт, провести серверный диалог на одном стриме и ответить на
/// DATA только после того, как потребитель подтвердил укладку письма.
///
/// Отдать письмо в канал и дождаться подтверждения — часть диалога, а не то,
/// что делают с его результатом: пир всё это время держит стрим открытым и
/// ждёт ответа. Раньше `250` уходил здесь же, а укладка случалась двумя
/// задачами позже, и на `stop()` очередь на 64 письма роняли вместе с
/// содержимым — пир уже снял свою копию.
async fn serve_one_stream(
    mut recv: quinn::RecvStream,
    mut send: quinn::SendStream,
    local_key: [u8; 32],
    peer: [u8; 32],
    tx: mpsc::Sender<InboundMail>,
) -> Result<(), QuicMailError> {
    let mut kick = [0u8; 1];
    recv.read_exact(&mut kick)
        .await
        .map_err(|e| QuicMailError::Transport(format!("kick byte: {e}")))?;
    tracing::info!("quic: stream open, kick consumed from {}", hex::encode(&peer[..8]));

    let (from, mail) = overlay_serve_stream(recv, &mut send, local_key, peer).await?;
    tracing::info!("smtp-overlay: DATA {} bytes from {}", mail.len(), hex::encode(&peer[..8]));

    // Общий бюджет на «отдать и дождаться»: очередь может быть забита ровно
    // потому, что потребитель встал, — тогда ждать на `send()` так же вредно,
    // как ждать на подтверждении.
    let (ack_tx, ack_rx) = oneshot::channel();
    let durable = tokio::time::timeout(DURABILITY_TIMEOUT, async move {
        tx.send((from, mail, Some(ack_tx))).await.is_ok() && ack_rx.await.is_ok()
    })
    .await
    .unwrap_or(false);

    if !durable {
        tracing::error!(
            "quic: mail from {} not stored, answering 451",
            hex::encode(&peer[..8])
        );
    }
    write_data_reply(&mut send, durable).await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core_conn::testutil::MemPacketConn;
    use ed25519_dalek::SigningKey;
    use std::sync::atomic::{AtomicBool, Ordering};

    /// Фоновый потребитель входящих писем, подтверждающий укладку — та же
    /// роль, что у `peer::receiver`. Без него `send()` не дождётся `250`:
    /// пир держит стрим до подтверждения. Отданные письма складываются в
    /// канал, чтобы тест мог их проверить.
    fn spawn_acking_consumer(
        transport: Arc<QuicMailTransport>,
    ) -> mpsc::UnboundedReceiver<([u8; 32], Vec<u8>)> {
        let (tx, rx) = mpsc::unbounded_channel();
        tokio::spawn(async move {
            while let Ok((from, mail, ack)) = transport.recv().await {
                if let Some(ack) = ack {
                    let _ = ack.send(());
                }
                if tx.send((from, mail)).is_err() {
                    return;
                }
            }
        });
        rx
    }

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

        let mut bob_rx = spawn_acking_consumer(bob);

        let mail = b"Subject: Meshmail\r\nFrom: a\r\n\r\nHello over QUIC\r\n".to_vec();
        alice.send(pub_b, mail.clone()).await.expect("send ok");

        let (from, got) = tokio::time::timeout(std::time::Duration::from_secs(10), bob_rx.recv())
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

        let mut bob_rx = spawn_acking_consumer(bob);

        alice.send(pub_b, b"Subject: one\r\n\r\n1\r\n".to_vec()).await.unwrap();
        let _ = tokio::time::timeout(std::time::Duration::from_secs(10), bob_rx.recv())
            .await
            .unwrap();
        let first_id = alice
            .cached_connection_stable_id(pub_b)
            .await
            .expect("connection cached after first send");

        alice.send(pub_b, b"Subject: two\r\n\r\n2\r\n".to_vec()).await.unwrap();
        let _ = tokio::time::timeout(std::time::Duration::from_secs(10), bob_rx.recv())
            .await
            .unwrap();
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

        let mut bob_rx = spawn_acking_consumer(bob);

        alice.send(pub_b, b"Subject: x\r\n\r\nx\r\n".to_vec()).await.unwrap();
        let _ = tokio::time::timeout(std::time::Duration::from_secs(10), bob_rx.recv())
            .await
            .unwrap();

        let recent = alice.recent_peers(std::time::Duration::from_secs(60)).await;
        assert!(recent.contains(&pub_b), "peer must be tracked as recently active");
    }

    /// Дозвон до пира, который никогда не отвечает ни на один пакет
    /// (недоступный узел), должен провалиться в бюджет `DIAL_TIMEOUT`, а не
    /// висеть до внутреннего handshake-таймаута quinn (завязан на
    /// `max_idle_timeout` = 1800с виртуального времени).
    ///
    /// Внешний `tokio::time::timeout(300s, ...)` — предохранитель теста, а
    /// не часть проверяемого поведения: без него, если бы в коде вовсе не
    /// было таймаута, тест завис бы на реальных 1800с виртуального времени,
    /// которые paused-clock раскрутил бы мгновенно, но сама попытка это
    /// сделать не должна зависеть от того, действительно ли quinn когда-то
    /// сдаётся сам.
    #[tokio::test(start_paused = true)]
    async fn dial_to_unreachable_peer_fails_within_dial_budget() {
        let key_a = SigningKey::from_bytes(&[41u8; 32]);
        let key_b = SigningKey::from_bytes(&[42u8; 32]);
        let pub_b = key_b.verifying_key().to_bytes();

        // conn_b существует, чтобы дозвон был адресован реальному ключу, но
        // никто её не читает — датаграммы от alice копятся непрочитанными.
        // Это и есть «недоступный узел».
        let (conn_a, _conn_b) = MemPacketConn::pair(key_a.clone(), key_b.clone());
        let alice = QuicMailTransport::new(conn_a as Arc<dyn PacketConn>, &key_a).unwrap();

        let start = tokio::time::Instant::now();
        let outcome = tokio::time::timeout(
            Duration::from_secs(300),
            alice.send(pub_b, b"Subject: x\r\n\r\nbody\r\n".to_vec()),
        )
        .await;
        let elapsed = start.elapsed();

        let result = outcome.expect("send must not hang past the 300s test safety bound");
        assert!(result.is_err(), "send to an unreachable peer must fail");
        assert!(
            elapsed < Duration::from_secs(60),
            "dial must fail within its budget, took {elapsed:?}"
        );
    }

    /// Хендшейк проходит (иначе дозвон провалился бы раньше диалога), но
    /// пир дальше молчит — не принимает bi-стрим и не пишет ни байта.
    /// Диалог должен провалиться в бюджет `DIALOG_TIMEOUT`, а не висеть
    /// неограниченно за счёт keep-alive, поддерживающего QUIC-соединение
    /// живым на транспортном уровне.
    #[tokio::test(start_paused = true)]
    async fn dialog_with_silent_peer_fails_within_dialog_budget() {
        let key_a = SigningKey::from_bytes(&[43u8; 32]);
        let key_b = SigningKey::from_bytes(&[44u8; 32]);
        let pub_b = key_b.verifying_key().to_bytes();

        let (conn_a, conn_b) = MemPacketConn::pair(key_a.clone(), key_b.clone());
        let alice = QuicMailTransport::new(conn_a as Arc<dyn PacketConn>, &key_a).unwrap();

        // «Молчаливый сервер»: сырой QuicOverlay (не QuicMailTransport)
        // принимает соединение один раз и дальше не делает ничего — ни
        // accept_bi, ни единого байта в ответ.
        let server = QuicOverlay::new(conn_b as Arc<dyn PacketConn>, &key_b).unwrap();
        tokio::spawn(async move {
            let _incoming = server.accept().await;
            std::future::pending::<()>().await
        });

        let start = tokio::time::Instant::now();
        let outcome = tokio::time::timeout(
            Duration::from_secs(300),
            alice.send(pub_b, b"Subject: x\r\n\r\nbody\r\n".to_vec()),
        )
        .await;
        let elapsed = start.elapsed();

        let result = outcome.expect("send must not hang past the 300s test safety bound");
        assert!(result.is_err(), "send against a silent peer must fail");
        // Нижняя граница обязательна: без неё этот тест ничего не отличает от
        // повторного теста на DIAL_TIMEOUT (10с) — оба удовлетворили бы
        // верхнюю границу в 150с. Раз хендшейк здесь проходит, провал обязан
        // случиться именно на бюджете диалога, а не раньше.
        assert!(
            elapsed >= DIALOG_TIMEOUT,
            "must fail on the dialog budget, not the dial budget, took {elapsed:?}"
        );
        assert!(
            elapsed < Duration::from_secs(150),
            "dialog must fail within its budget, took {elapsed:?}"
        );
    }

    /// Письмо крупнее, чем `DIALOG_TIMEOUT` в одиночку способен перенести при
    /// `MIN_THROUGHPUT`, должно получить пропорционально больший бюджет — иначе
    /// таймаут ограничивал бы саму работу, а не простой, и такое письмо
    /// таймаутилось бы на каждой попытке отправки и никогда бы не доставилось.
    #[tokio::test(start_paused = true)]
    async fn dialog_with_silent_peer_gets_a_larger_budget_for_a_larger_message() {
        let key_a = SigningKey::from_bytes(&[45u8; 32]);
        let key_b = SigningKey::from_bytes(&[46u8; 32]);
        let pub_b = key_b.verifying_key().to_bytes();

        let (conn_a, conn_b) = MemPacketConn::pair(key_a.clone(), key_b.clone());
        let alice = QuicMailTransport::new(conn_a as Arc<dyn PacketConn>, &key_a).unwrap();

        let server = QuicOverlay::new(conn_b as Arc<dyn PacketConn>, &key_b).unwrap();
        tokio::spawn(async move {
            let _incoming = server.accept().await;
            std::future::pending::<()>().await
        });

        let message = vec![0u8; 5 * 1024 * 1024];
        let expected_budget = dialog_budget(message.len());
        assert!(
            expected_budget > DIALOG_TIMEOUT,
            "test message must be large enough to actually stretch the budget"
        );

        let start = tokio::time::Instant::now();
        let outcome = tokio::time::timeout(
            expected_budget + Duration::from_secs(60),
            alice.send(pub_b, message),
        )
        .await;
        let elapsed = start.elapsed();

        let result = outcome.expect("send must not hang past the test safety bound");
        assert!(result.is_err(), "send against a silent peer must fail");
        assert!(
            elapsed >= expected_budget,
            "must not fail before the size-scaled budget, took {elapsed:?}, budget {expected_budget:?}"
        );
        assert!(
            elapsed < expected_budget + Duration::from_secs(30),
            "must fail promptly once the size-scaled budget elapses, took {elapsed:?}"
        );
    }

    /// Бюджет диалога растёт линейно с размером письма при `MIN_THROUGHPUT`,
    /// но остаётся ниже 30-минутного `max_idle_timeout` даже для `MAX_DATA_BYTES`
    /// — иначе транспорт убил бы соединение раньше, чем сработал бы сам бюджет.
    #[test]
    fn dialog_budget_grows_with_message_size_but_stays_under_idle_timeout() {
        assert_eq!(
            dialog_budget(0),
            DIALOG_TIMEOUT,
            "small mail keeps just the base protocol-overhead budget"
        );
        assert_eq!(
            dialog_budget(MIN_THROUGHPUT as usize),
            DIALOG_TIMEOUT + Duration::from_secs(1),
            "one throughput-unit of bytes adds exactly one second"
        );
        let max_size_budget = dialog_budget(33 * 1024 * 1024);
        assert!(
            max_size_budget > DIALOG_TIMEOUT && max_size_budget < Duration::from_secs(1800),
            "max-size mail must get a larger budget, but still under the QUIC idle timeout, got {max_size_budget:?}"
        );
    }

    /// `250` уходит только после подтверждения укладки. Потребитель здесь
    /// подтверждает не мгновенно: если бы диалог отвечал `250` сразу после
    /// DATA, `send()` вернулся бы раньше, чем выставлен флаг — то есть пир
    /// счёл бы доставленным письмо, которого ещё нигде нет.
    #[tokio::test(start_paused = true)]
    async fn data_reply_waits_for_the_durability_ack() {
        let key_a = SigningKey::from_bytes(&[51u8; 32]);
        let key_b = SigningKey::from_bytes(&[52u8; 32]);
        let pub_a = key_a.verifying_key().to_bytes();
        let pub_b = key_b.verifying_key().to_bytes();

        let (conn_a, conn_b) = MemPacketConn::pair(key_a.clone(), key_b.clone());
        let alice = QuicMailTransport::new(conn_a as Arc<dyn PacketConn>, &key_a).unwrap();
        let bob = QuicMailTransport::new(conn_b as Arc<dyn PacketConn>, &key_b).unwrap();

        let stored = Arc::new(AtomicBool::new(false));
        let flag = stored.clone();
        tokio::spawn(async move {
            let (from, mail, ack) = bob.recv().await.expect("recv ok");
            assert_eq!(from, pub_a, "receiver must see the sender's key");
            assert!(!mail.is_empty(), "body delivered");
            // «Укладка»: занимает время, как настоящий INSERT.
            tokio::time::sleep(Duration::from_secs(5)).await;
            flag.store(true, Ordering::SeqCst);
            ack.expect("QUIC mail must carry a durability ack")
                .send(())
                .expect("dialog must still be waiting for the ack");
        });

        alice
            .send(pub_b, b"Subject: x\r\n\r\nbody\r\n".to_vec())
            .await
            .expect("send must succeed once the mail is durable");

        assert!(
            stored.load(Ordering::SeqCst),
            "sender saw 250 before the receiver stored the mail"
        );
    }

    /// Потребитель забрал письмо, но подтверждения не послал — так выглядит
    /// провалившаяся укладка (`Err` из `mail_insert_inbox_dedup`). Пир обязан
    /// получить `451` и повторить, а не `250` на письмо, которого нет.
    #[tokio::test]
    async fn dropped_ack_answers_451_instead_of_250() {
        let key_a = SigningKey::from_bytes(&[53u8; 32]);
        let key_b = SigningKey::from_bytes(&[54u8; 32]);
        let pub_b = key_b.verifying_key().to_bytes();

        let (conn_a, conn_b) = MemPacketConn::pair(key_a.clone(), key_b.clone());
        let alice = QuicMailTransport::new(conn_a as Arc<dyn PacketConn>, &key_a).unwrap();
        let bob = QuicMailTransport::new(conn_b as Arc<dyn PacketConn>, &key_b).unwrap();

        tokio::spawn(async move {
            let (_from, _mail, ack) = bob.recv().await.expect("recv ok");
            drop(ack);
        });

        let err = alice
            .send(pub_b, b"Subject: x\r\n\r\nbody\r\n".to_vec())
            .await
            .expect_err("send must fail when the receiver could not store the mail");
        assert!(
            format!("{err}").contains("451"),
            "peer must be answered 451, never 250, got {err}"
        );
    }

    /// Пир не должен увидеть `250` на DATA, пока письмо не уложено. Здесь
    /// потребитель `recv()` не запущен вовсе — ровно то, что происходит при
    /// `stop()`: письмо остаётся в канале и никогда не доходит до INBOX.
    /// Диалог обязан ответить `451`, чтобы пир повторил доставку, а не
    /// отрапортовать `250` о письме, которое никто не уложил.
    #[tokio::test(start_paused = true)]
    async fn data_without_durability_ack_fails_instead_of_reporting_250() {
        let key_a = SigningKey::from_bytes(&[47u8; 32]);
        let key_b = SigningKey::from_bytes(&[48u8; 32]);
        let pub_b = key_b.verifying_key().to_bytes();

        let (conn_a, conn_b) = MemPacketConn::pair(key_a.clone(), key_b.clone());
        let alice = QuicMailTransport::new(conn_a as Arc<dyn PacketConn>, &key_a).unwrap();
        // Транспорт получателя жив и принимает диалог, но recv() никто не
        // вызывает — подтверждения долговечности не будет.
        let _bob = QuicMailTransport::new(conn_b as Arc<dyn PacketConn>, &key_b).unwrap();

        let outcome = tokio::time::timeout(
            Duration::from_secs(300),
            alice.send(pub_b, b"Subject: x\r\n\r\nbody\r\n".to_vec()),
        )
        .await
        .expect("send must not hang past the 300s test safety bound");

        let err = outcome.expect_err("send must fail when the mail was never stored");
        assert!(
            format!("{err}").contains("451"),
            "peer must be answered 451, never 250, got {err}"
        );
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
            got.map(|r| r.map(|(k, _, _)| hex::encode(k)))
        );
    }
}
