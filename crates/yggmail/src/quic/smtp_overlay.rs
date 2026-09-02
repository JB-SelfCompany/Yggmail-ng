//! SMTP-диалог «пир↔пир» по одному (QUIC-)стриму. Отличается от локального
//! MUA-сервера в `crate::smtp`: здесь личность отправителя — спиненный
//! ed25519-ключ, а принятое письмо отдаётся вызывающему (он кладёт его в INBOX
//! с дедупом и будит IMAP IDLE).
//!
//! Провод повторяет emersion/go-smtp (yggmail-go): greeting (сервер первым),
//! затем MAIL FROM / RCPT TO / DATA / QUIT.

use crate::address::parse_address;
use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, BufReader};

/// Потолок письма — тот же, что у локального SMTP (`smtp/mod.rs:23`).
/// Стриминг и файловое хранилище из продукта убраны, поэтому лимит один.
const MAX_DATA_BYTES: usize = 33 * 1024 * 1024;
const MAX_LINE_BYTES: usize = 64 * 1024;
/// Потолок строк-продолжений `250-...` в ответе. 1.8 никогда не шлёт больше
/// нескольких (SIZE/8BITMIME на EHLO) — 32 с большим запасом отличает
/// реальный многострочный ответ от пира, который крутит цикл вечно.
const MAX_CONTINUATION_LINES: u32 = 32;

/// Ошибки оверлейного диалога.
/// ponytail: ручной Display вместо thiserror — стиль крейта.
#[derive(Debug)]
pub(crate) enum OverlayError {
    Io(std::io::Error),
    Protocol(String),
    SpoofedSender,
    TooLarge,
}

impl std::fmt::Display for OverlayError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            OverlayError::Io(e) => write!(f, "io: {e}"),
            OverlayError::Protocol(s) => write!(f, "protocol: {s}"),
            OverlayError::SpoofedSender => write!(f, "MAIL FROM does not match peer key"),
            OverlayError::TooLarge => write!(f, "message exceeds {MAX_DATA_BYTES} bytes"),
        }
    }
}
impl std::error::Error for OverlayError {}
impl From<std::io::Error> for OverlayError {
    fn from(e: std::io::Error) -> Self {
        OverlayError::Io(e)
    }
}

/// Обслужить одного входящего пира: провести SMTP-диалог, потребовать
/// `MAIL FROM == peer_key`, вернуть собранное RFC 5322 письмо.
///
/// `peer_key` спинен из TLS-сертификата и сверен с адресом источника датаграмм.
/// `local_key` — наш адрес, для проверки `RCPT TO`.
///
/// Письмо возвращается ровно как получено: трассировочные заголовки не
/// добавляются, иначе отпечаток `hash(from_key, raw)` в
/// `mail_insert_inbox_dedup` станет уникальным на каждой повторной доставке.
///
/// Финальный ответ на DATA здесь **не пишется**: письмо на этот момент ещё
/// нигде не лежит. Его пишет вызывающий через `write_data_reply` — уже зная,
/// стало ли письмо durable. Поэтому `writer` берётся по `&mut`: он нужен
/// вызывающему после возврата. Все остальные ответы (greeting, MAIL/RCPT, 354
/// и любые коды ошибок) по-прежнему выдаёт сам диалог.
pub(crate) async fn overlay_serve_stream<R, W>(
    reader: R,
    writer: &mut W,
    local_key: [u8; 32],
    peer_key: [u8; 32],
) -> Result<([u8; 32], Vec<u8>), OverlayError>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut reader = BufReader::new(reader);
    let mut line = Vec::new();

    writer.write_all(b"220 yggmail-ng overlay ready\r\n").await?;
    writer.flush().await?;

    let mut from_ok = false;
    let mut rcpt_ok = false;

    loop {
        let n = read_line(&mut reader, &mut line).await?;
        if n == 0 {
            return Err(OverlayError::Protocol("peer closed before DATA".into()));
        }
        let upper = line.to_ascii_uppercase();

        if upper.starts_with(b"HELO") || upper.starts_with(b"EHLO") {
            // Расширений не анонсируем сознательно: клиент go-smtp добавляет
            // SIZE=/BODY= к MAIL FROM только под анонсированное расширение,
            // так что пустой ответ — самая узкая поверхность.
            writer.write_all(b"250 yggmail-ng\r\n").await?;
        } else if upper.starts_with(b"MAIL FROM:") {
            match extract_path(&line, b"MAIL FROM:").as_deref().and_then(parse_address) {
                Some(k) if k == peer_key => {
                    from_ok = true;
                    writer.write_all(b"250 OK\r\n").await?;
                }
                _ => {
                    writer.write_all(b"550 sender not permitted\r\n").await?;
                    writer.flush().await?;
                    return Err(OverlayError::SpoofedSender);
                }
            }
        } else if upper.starts_with(b"RCPT TO:") {
            match extract_path(&line, b"RCPT TO:").as_deref().and_then(parse_address) {
                Some(k) if k == local_key => {
                    rcpt_ok = true;
                    writer.write_all(b"250 OK\r\n").await?;
                }
                _ => {
                    writer.write_all(b"550 no such user\r\n").await?;
                }
            }
        } else if upper.starts_with(b"DATA") {
            if !from_ok || !rcpt_ok {
                writer.write_all(b"503 bad sequence\r\n").await?;
                writer.flush().await?;
                return Err(OverlayError::Protocol("DATA before MAIL/RCPT".into()));
            }
            writer.write_all(b"354 go ahead\r\n").await?;
            writer.flush().await?;
            match read_data(&mut reader).await {
                // Ответа тут нет намеренно: письмо ещё не уложено. См.
                // `write_data_reply`.
                Ok(body) => return Ok((peer_key, body)),
                Err(OverlayError::TooLarge) => {
                    // 552 — тот же код, которым отвечает Go-сторона.
                    let _ = writer.write_all(b"552 message size limit exceeded\r\n").await;
                    let _ = writer.flush().await;
                    return Err(OverlayError::TooLarge);
                }
                Err(e) => return Err(e),
            }
        } else if upper.starts_with(b"QUIT") {
            writer.write_all(b"221 bye\r\n").await?;
            writer.flush().await?;
            return Err(OverlayError::Protocol("QUIT before DATA".into()));
        } else {
            writer.write_all(b"250 OK\r\n").await?;
        }
        writer.flush().await?;
    }
}

/// Написать финальный ответ на DATA — после того, как судьба письма известна.
///
/// `durable == true` → `250`: письмо в INBOX, пир вправе снять свою копию.
/// `durable == false` → `451`: транзиентный отказ. Именно `451`, а не `250`:
/// 250 о неулаженном письме — это ложь, на которую пир имеет полное право
/// удалить свою копию.
///
/// Насколько `451` спасает письмо — зависит от версии пира, и обещать доставку
/// он не может:
///
/// * **1.9 (мы сами)** — повторит. Клиент разбирает финальный код в
///   `expect_code(.., b'2')`, ошибка поднимается в `peer/sender.rs`, строка
///   очереди остаётся на месте, и следующий опрос отправит письмо снова. При
///   этом повторе сработает дедуп: `hash(from_key, raw)` совпадёт, потому что
///   письмо не перерендеривается между попытками.
/// * **1.8 (Go)** — не повторит и даже не узнает про `451`. В
///   `yggmail-old-mobile/internal/smtpsender/sender.go` терминатор и чтение
///   финального ответа происходят внутри `writer.Close()`, а он там ровно один
///   и стоит как `defer writer.Close() // nolint:errcheck` (`sender.go:495`) —
///   то есть выполняется на выходе из функции, и его ошибка отбрасывается.
///   Снятие с очереди `QueueDeleteDestinationForID` идёт раньше, на
///   `sender.go:539`. Пир 1.8 удаляет письмо из очереди до того, как отправлен
///   терминатор, и наш код ответа он не читает вообще.
///
/// Поэтому для 1.8 `451` — это честная сигнализация, а не гарантия доставки:
/// в этом окне письмо теряется независимо от того, что мы ответим. Так было и
/// до появления этого ответа — здесь не регрессия, а предел. Убрать его можно
/// только со стороны 1.8.
pub(crate) async fn write_data_reply<W>(writer: &mut W, durable: bool) -> Result<(), OverlayError>
where
    W: AsyncWrite + Unpin,
{
    let reply: &[u8] = if durable {
        b"250 OK\r\n"
    } else {
        b"451 4.3.0 mail not stored, try again later\r\n"
    };
    writer.write_all(reply).await?;
    writer.flush().await?;
    Ok(())
}

/// Прочитать одну строку до `\n` включительно, с потолком длины `cap`.
/// Общий примитив для командных строк (SMTP-глаголы) и для строк тела DATA —
/// у них разный подходящий потолок, поэтому cap параметризован.
async fn read_line_capped<R: AsyncRead + Unpin>(
    reader: &mut BufReader<R>,
    out: &mut Vec<u8>,
    cap: usize,
) -> Result<usize, OverlayError> {
    out.clear();
    let n = reader.take(cap as u64).read_until(b'\n', out).await?;
    if out.len() >= cap && !out.ends_with(b"\n") {
        return Err(OverlayError::Protocol("line too long".into()));
    }
    Ok(n)
}

/// Прочитать одну командную строку (HELO/MAIL FROM/RCPT TO/...) с потолком
/// `MAX_LINE_BYTES` — этого достаточно с большим запасом для любой ESMTP-команды.
async fn read_line<R: AsyncRead + Unpin>(
    reader: &mut BufReader<R>,
    out: &mut Vec<u8>,
) -> Result<usize, OverlayError> {
    read_line_capped(reader, out, MAX_LINE_BYTES).await
}

/// Прочитать тело до точки-терминатора, снимая точечное экранирование
/// (RFC 5321 §4.5.2). Работает с байтами: тело DeltaChat не обязано быть UTF-8.
///
/// Строки тела читаются с потолком, привязанным к оставшемуся бюджету
/// `MAX_DATA_BYTES`, а не к фиксированному `MAX_LINE_BYTES` командных строк:
/// реальные почтовые клиенты дробят тело на короткие CRLF-строки, но ничто в
/// протоколе не гарантирует это — пир может прислать одну гигантскую строку
/// без переноса. Динамический потолок гарантирует, что даже такая строка не
/// раздует память сверх `MAX_DATA_BYTES + MAX_LINE_BYTES`, и превышение
/// сообщается как `TooLarge`, а не как непонятный протокольный сбой.
async fn read_data<R: AsyncRead + Unpin>(
    reader: &mut BufReader<R>,
) -> Result<Vec<u8>, OverlayError> {
    let mut out: Vec<u8> = Vec::new();
    let mut line = Vec::new();
    loop {
        let cap = MAX_DATA_BYTES.saturating_sub(out.len()) + MAX_LINE_BYTES;
        let n = match read_line_capped(reader, &mut line, cap).await {
            Ok(n) => n,
            Err(OverlayError::Protocol(_)) => return Err(OverlayError::TooLarge),
            Err(e) => return Err(e),
        };
        if n == 0 {
            return Err(OverlayError::Protocol("EOF inside DATA".into()));
        }
        if line == b".\r\n" || line == b".\n" {
            return Ok(out);
        }
        let stripped: &[u8] = if line.starts_with(b"..") { &line[1..] } else { &line[..] };
        if out.len() + stripped.len() > MAX_DATA_BYTES {
            return Err(OverlayError::TooLarge);
        }
        out.extend_from_slice(stripped);
    }
}

/// Отправить одно письмо как SMTP-клиент: прочитать greeting и ответы, пройти
/// диалог, заэкранировать точки. Любой не-2xx по пути — ошибка протокола.
/// `local_hostname` — hex нашего собственного публичного ключа, и это не
/// косметика. Go-сервер сверяет аргумент EHLO с ключом пира, от которого пришли
/// датаграммы (`internal/smtpserver/backend.go:95-103`): при расхождении диалог
/// отбивается с `502 5.7.0 you are not who you claim to be`. Go-клиент шлёт туда
/// `hex(own pubkey)` (`smtpsender/sender.go`, `client.Hello`), и мы обязаны так же —
/// иначе ни одно письмо на узел 1.8 не пройдёт.
pub(crate) async fn overlay_send_stream<R, W>(
    reader: R,
    mut writer: W,
    local_hostname: &str,
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

    writer
        .write_all(format!("EHLO {local_hostname}\r\n").as_bytes())
        .await?;
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
    expect_code(&mut reader, b'2').await?; // 250 принято

    // Deviation from the brief: QUIT is best-effort. The mail transaction is
    // already durable once 250 for DATA came back — `overlay_serve_stream`
    // returns right after sending it and drops its stream halves, so on an
    // in-memory duplex (and plausibly a QUIC stream under real teardown
    // timing) the peer can already be gone by the time we write QUIT. Failing
    // the whole send over a courtesy goodbye would treat a delivered mail as
    // an error.
    let _ = writer.write_all(b"QUIT\r\n").await;
    let _ = writer.flush().await;
    Ok(())
}

async fn write_dot_stuffed<W: AsyncWrite + Unpin>(
    w: &mut W,
    body: &[u8],
) -> Result<(), OverlayError> {
    let mut start = 0;
    for i in 0..body.len() {
        if body[i] == b'\n' {
            let line = &body[start..=i];
            if line.first() == Some(&b'.') {
                w.write_all(b".").await?;
            }
            w.write_all(line).await?;
            start = i + 1;
        }
    }
    if start < body.len() {
        let line = &body[start..];
        if line.first() == Some(&b'.') {
            w.write_all(b".").await?;
        }
        w.write_all(line).await?;
        w.write_all(b"\r\n").await?;
    }
    Ok(())
}

/// Прочитать ответ и проверить его класс (`2`/`3`), пропуская многострочные
/// продолжения. Сервер 1.8 отвечает на EHLO многострочно (он анонсирует SIZE),
/// поэтому обработка `250-` обязательна.
async fn expect_code<R: AsyncRead + Unpin>(
    reader: &mut BufReader<R>,
    class: u8,
) -> Result<(), OverlayError> {
    let mut line = Vec::new();
    for _ in 0..MAX_CONTINUATION_LINES {
        let n = read_line(reader, &mut line).await?;
        if n == 0 {
            return Err(OverlayError::Protocol("peer closed mid-dialog".into()));
        }
        if line.get(3) == Some(&b'-') {
            continue; // продолжение многострочного ответа
        }
        return match line.first() {
            Some(&c) if c == class => Ok(()),
            _ => Err(OverlayError::Protocol(format!(
                "unexpected reply: {}",
                String::from_utf8_lossy(&line).trim()
            ))),
        };
    }
    Err(OverlayError::Protocol("too many continuation lines".into()))
}

/// Достать обратный/прямой путь из `MAIL FROM:` / `RCPT TO:` по RFC 5321.
///
/// Форма — `<addr>` с опциональными параметрами `key=value` через пробел
/// (`MAIL FROM:<a@yggmail> SIZE=4096 BODY=8BITMIME`). Наивный разбор «всё после
/// двоеточия» ломается ровно на этих параметрах, а клиент go-smtp из 1.8 их
/// подставляет, когда сервер анонсировал соответствующее расширение.
fn extract_path(line: &[u8], prefix: &[u8]) -> Option<String> {
    let rest = line.get(prefix.len()..)?;
    let rest = std::str::from_utf8(rest).ok()?.trim();
    let addr = match rest.strip_prefix('<') {
        Some(after) => after.split('>').next()?,
        // Без угловых скобок берём первое слово — параметры отсекаются.
        None => rest.split_whitespace().next()?,
    };
    let addr = addr.trim();
    if addr.is_empty() { None } else { Some(addr.to_string()) }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncWriteExt, duplex, split};

    fn addr(key: &[u8; 32]) -> String {
        crate::address::create_address(key)
    }

    /// Клиентский диалог → серверный по in-memory дуплексу доставляет тело
    /// письма и крипто-подтверждённый ключ отправителя, без сети.
    #[tokio::test]
    async fn delivers_body_and_sender_key() {
        let sender_key = [0x11u8; 32];
        let recipient_key = [0x22u8; 32];

        let (client_side, server_side) = tokio::io::duplex(64 * 1024);
        let (cr, cw) = split(client_side);
        let (sr, mut sw) = split(server_side);

        let body = "Subject: Hi\r\nFrom: test\r\n\r\nPayload line\r\n";

        // Как в бою: диалог отдаёт письмо, финальный `250` пишет вызывающий —
        // здесь сразу, потому что письму в тесте некуда укладываться.
        let server = tokio::spawn(async move {
            let r = overlay_serve_stream(sr, &mut sw, recipient_key, sender_key).await;
            if r.is_ok() {
                write_data_reply(&mut sw, true).await.unwrap();
            }
            r
        });
        let client = tokio::spawn(async move {
            overlay_send_stream(cr, cw, &hex::encode(sender_key), &addr(&sender_key), &[addr(&recipient_key)], body.as_bytes())
                .await
        });

        client.await.unwrap().expect("client dialog ok");
        let (from_key, raw) = server.await.unwrap().expect("server yields one mail");
        assert_eq!(from_key, sender_key, "server pins the crypto sender identity");
        let text = String::from_utf8_lossy(&raw);
        assert!(text.contains("Payload line"), "body delivered: {text}");
    }

    /// `MAIL FROM` с параметром SIZE (так шлёт клиент go-smtp из 1.8, когда
    /// сервер анонсировал SIZE) разбирается корректно, а не отбивается 550.
    #[tokio::test]
    async fn accepts_mail_from_with_size_parameter() {
        let sender_key = [0x33u8; 32];
        let recipient_key = [0x44u8; 32];

        let (client_side, server_side) = tokio::io::duplex(64 * 1024);
        let (sr, mut sw) = split(server_side);
        let (_cr, mut cw) = split(client_side);

        let server =
            tokio::spawn(
                async move { overlay_serve_stream(sr, &mut sw, recipient_key, sender_key).await },
            );

        cw.write_all(b"EHLO yggmail\r\n").await.unwrap();
        cw.write_all(format!("MAIL FROM:<{}> SIZE=4096\r\n", addr(&sender_key)).as_bytes())
            .await
            .unwrap();
        cw.write_all(format!("RCPT TO:<{}>\r\n", addr(&recipient_key)).as_bytes())
            .await
            .unwrap();
        cw.write_all(b"DATA\r\nSubject: x\r\n\r\nbody\r\n.\r\n").await.unwrap();

        let (from_key, raw) = server.await.unwrap().expect("mail accepted");
        assert_eq!(from_key, sender_key);
        assert!(String::from_utf8_lossy(&raw).contains("body"));
    }

    /// Адрес в домене-алиасе `yggmail.local` принимается: у 1.8 так может быть
    /// настроен почтовый клиент.
    #[tokio::test]
    async fn accepts_local_domain_alias_in_mail_from() {
        let sender_key = [0x55u8; 32];
        let recipient_key = [0x66u8; 32];

        let (client_side, server_side) = tokio::io::duplex(64 * 1024);
        let (sr, mut sw) = split(server_side);
        let (_cr, mut cw) = split(client_side);

        let server =
            tokio::spawn(
                async move { overlay_serve_stream(sr, &mut sw, recipient_key, sender_key).await },
            );

        cw.write_all(b"EHLO yggmail\r\n").await.unwrap();
        cw.write_all(format!("MAIL FROM:<{}@yggmail.local>\r\n", hex::encode(sender_key)).as_bytes())
            .await
            .unwrap();
        cw.write_all(format!("RCPT TO:<{}>\r\n", addr(&recipient_key)).as_bytes())
            .await
            .unwrap();
        cw.write_all(b"DATA\r\nSubject: x\r\n\r\nbody\r\n.\r\n").await.unwrap();

        let (from_key, _raw) = server.await.unwrap().expect("alias accepted");
        assert_eq!(from_key, sender_key);
    }

    /// Тело с 8-битными байтами (вложения DeltaChat) проходит без потерь —
    /// путь обязан быть байтовым, а не UTF-8.
    #[tokio::test]
    async fn carries_eight_bit_body_intact() {
        let sender_key = [0x77u8; 32];
        let recipient_key = [0x88u8; 32];

        let (client_side, server_side) = tokio::io::duplex(64 * 1024);
        let (cr, cw) = split(client_side);
        let (sr, mut sw) = split(server_side);

        let mut body = b"Subject: bin\r\n\r\n".to_vec();
        body.extend_from_slice(&[0xFF, 0xFE, 0x00, 0x80, 0xC3]);
        body.extend_from_slice(b"\r\n");
        let expected = body.clone();

        let server = tokio::spawn(async move {
            let r = overlay_serve_stream(sr, &mut sw, recipient_key, sender_key).await;
            if r.is_ok() {
                write_data_reply(&mut sw, true).await.unwrap();
            }
            r
        });
        let client = tokio::spawn(async move {
            overlay_send_stream(cr, cw, &hex::encode(sender_key), &addr(&sender_key), &[addr(&recipient_key)], &body).await
        });

        client.await.unwrap().expect("client dialog ok");
        let (_from, raw) = server.await.unwrap().expect("server yields one mail");
        assert!(
            raw.windows(5).any(|w| w == [0xFF, 0xFE, 0x00, 0x80, 0xC3]),
            "8-bit bytes must survive the dialog"
        );
        assert_eq!(raw.len(), expected.len(), "body must not be re-encoded");
    }

    /// `MAIL FROM`, чей адрес не равен спиненному ключу пира, отвергается —
    /// семантика `session_remote.go:44`.
    #[tokio::test]
    async fn rejects_spoofed_sender() {
        let peer_key = [0x11u8; 32];
        let spoofed = [0x99u8; 32];

        let (client_side, server_side) = tokio::io::duplex(64 * 1024);
        let (cr, cw) = split(client_side);
        let (sr, mut sw) = split(server_side);

        let server =
            tokio::spawn(
                async move { overlay_serve_stream(sr, &mut sw, [0x22u8; 32], peer_key).await },
            );
        let _client = tokio::spawn(async move {
            overlay_send_stream(
                cr,
                cw,
                &hex::encode(spoofed),
                &addr(&spoofed),
                &[addr(&[0x22u8; 32])],
                b"Subject: x\r\n\r\nbad\r\n",
            )
            .await
        });

        let res = server.await.unwrap();
        assert!(matches!(res, Err(OverlayError::SpoofedSender)), "got {res:?}");
    }

    /// Письмо тяжелее потолка отбивается ошибкой, а не съедает память.
    #[tokio::test]
    async fn rejects_oversized_body() {
        let sender_key = [0xAAu8; 32];
        let recipient_key = [0xBBu8; 32];

        let (client_side, server_side) = tokio::io::duplex(1024 * 1024);
        let (sr, mut sw) = split(server_side);
        let (_cr, mut cw) = split(client_side);

        let server =
            tokio::spawn(
                async move { overlay_serve_stream(sr, &mut sw, recipient_key, sender_key).await },
            );

        cw.write_all(b"EHLO yggmail\r\n").await.unwrap();
        cw.write_all(format!("MAIL FROM:<{}>\r\n", addr(&sender_key)).as_bytes()).await.unwrap();
        cw.write_all(format!("RCPT TO:<{}>\r\n", addr(&recipient_key)).as_bytes()).await.unwrap();
        cw.write_all(b"DATA\r\n").await.unwrap();
        let chunk = vec![b'x'; 64 * 1024];
        for _ in 0..(MAX_DATA_BYTES / chunk.len() + 2) {
            if cw.write_all(&chunk).await.is_err() {
                break;
            }
            if cw.write_all(b"\r\n").await.is_err() {
                break;
            }
        }

        let res = server.await.unwrap();
        assert!(matches!(res, Err(OverlayError::TooLarge)), "got {res:?}");
    }

    /// Клиент обязан представиться в EHLO hex своего публичного ключа.
    ///
    /// Go-сервер сверяет аргумент EHLO с ключом пира, от которого пришли
    /// датаграммы (`internal/smtpserver/backend.go:95-103`), и на расхождении
    /// отвечает `502 5.7.0 you are not who you claim to be`. Наш собственный
    /// сервер аргумент EHLO не проверяет, поэтому диалог «клиент↔наш сервер»
    /// такую регрессию не заметит — она видна только против Go. Этот тест
    /// читает то, что клиент реально пишет в поток.
    #[tokio::test]
    async fn client_announces_its_own_key_in_ehlo() {
        use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader as TokioBufReader};

        let sender_key = [0xC3u8; 32];
        let recipient_key = [0xD4u8; 32];

        let (client_side, server_side) = tokio::io::duplex(64 * 1024);
        let (cr, cw) = split(client_side);
        let (sr, mut sw) = split(server_side);

        tokio::spawn(async move {
            overlay_send_stream(
                cr,
                cw,
                &hex::encode(sender_key),
                &addr(&sender_key),
                &[addr(&recipient_key)],
                b"Subject: x\r\n\r\nbody\r\n",
            )
            .await
        });

        sw.write_all(b"220 ready\r\n").await.unwrap();
        sw.flush().await.unwrap();

        let mut reader = TokioBufReader::new(sr);
        let mut line = String::new();
        reader.read_line(&mut line).await.unwrap();

        assert_eq!(
            line.trim(),
            format!("EHLO {}", hex::encode(sender_key)),
            "EHLO must carry hex(own pubkey); \"EHLO yggmail\" makes a 1.8 node \
             answer 502 and rejects every mail we send it"
        );
    }

    /// Пир, который шлёт бесконечный поток строк-продолжений `250-...`, не
    /// должен раскручивать цикл `expect_code` вечно — потолок числа строк
    /// обязан оборвать его ошибкой вместо того, чтобы дочитать до настоящего
    /// финального ответа.
    #[tokio::test]
    async fn expect_code_bails_out_after_too_many_continuation_lines() {
        let (client_side, mut server_side) = duplex(64 * 1024);
        let (cr, _cw) = split(client_side);

        tokio::spawn(async move {
            for _ in 0..(MAX_CONTINUATION_LINES as usize + 10) {
                if server_side.write_all(b"250-continuing\r\n").await.is_err() {
                    return;
                }
            }
            let _ = server_side.write_all(b"250 done\r\n").await;
            let _ = server_side.flush().await;
        });

        let mut reader = BufReader::new(cr);
        let res = expect_code(&mut reader, b'2').await;
        assert!(
            matches!(res, Err(OverlayError::Protocol(_))),
            "must bail out instead of consuming an unbounded run of continuation lines, got {res:?}"
        );
    }

    #[test]
    fn parses_mail_from_with_and_without_params() {
        assert_eq!(
            extract_path(b"MAIL FROM:<a@yggmail>", b"MAIL FROM:").as_deref(),
            Some("a@yggmail")
        );
        assert_eq!(
            extract_path(b"MAIL FROM:<a@yggmail> SIZE=10 BODY=8BITMIME", b"MAIL FROM:").as_deref(),
            Some("a@yggmail")
        );
        assert_eq!(
            extract_path(b"RCPT TO:  <b@yggmail>", b"RCPT TO:").as_deref(),
            Some("b@yggmail")
        );
        // Без угловых скобок — берём первое слово, параметры отбрасываем.
        assert_eq!(
            extract_path(b"MAIL FROM:a@yggmail SIZE=10", b"MAIL FROM:").as_deref(),
            Some("a@yggmail")
        );
        assert_eq!(extract_path(b"MAIL FROM:<>", b"MAIL FROM:"), None);
    }
}
