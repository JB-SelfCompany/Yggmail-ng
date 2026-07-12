//! Minimal SMTP server — localhost-only, self-written over tokio.
//! Supports the subset of ESMTP that Thunderbird/Outlook need:
//! HELO, EHLO, AUTH LOGIN, MAIL FROM, RCPT TO, DATA, RSET, QUIT, NOOP.
//!
//! ponytail: no external SMTP library (~200 lines vs adding a 10k-line dep).

use crate::address::parse_address;
use crate::storage::SqliteStorage;
use sha2::{Digest, Sha256};
use std::sync::Arc;
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader, BufWriter};
use tokio::net::TcpListener;

/// Maximum bytes accepted for a single SMTP command line (64 KiB).
/// A real SMTP command (EHLO/MAIL FROM/RCPT TO) is never close to this;
/// the limit exists purely to cap memory before `read_line` finishes.
const MAX_LINE_BYTES: usize = 64 * 1024;

/// Maximum accumulated DATA bytes before we abort (33 MiB).
/// Slightly above the 32 MiB YMP transport limit so a max-size legitimate
/// mail still passes the SMTP layer; YMP enforces its own hard cap at send
/// time.
const MAX_DATA_BYTES: usize = 33 * 1024 * 1024;

/// State machine for an SMTP session.
#[derive(Debug, Clone, Copy, PartialEq)]
enum State {
    ExpectHelo,
    ExpectAuth,
    ExpectMail,
    ExpectRcpt,
    ReceivingData,
}

/// An active SMTP session with one MUA client.
struct Session {
    state: State,
    from: Option<String>,
    rcpts: Vec<String>,
    authenticated: bool,
    password_hash: Option<String>, // SHA-256 hex string; None = no auth required
    local_key: [u8; 32],
    storage: Arc<SqliteStorage>,
}

impl Session {
    fn new(storage: Arc<SqliteStorage>, local_key: [u8; 32], password_hash: Option<String>) -> Self {
        Self {
            state: State::ExpectHelo,
            from: None,
            rcpts: Vec::with_capacity(4),
            authenticated: password_hash.is_none(),
            password_hash,
            local_key,
            storage,
        }
    }

    fn reply_code(&mut self, line: &str) -> &'static str {
        match line {
            l if l.starts_with("HELO") || l.starts_with("EHLO") => {
                // ponytail: RFC 5321 §4.1.1.1 — EHLO resets all session state.
                // Allowed at any point (clients re-EHLO after AUTH to get capabilities).
                self.from = None;
                self.rcpts.clear();
                self.state = if self.authenticated { State::ExpectMail } else { State::ExpectAuth };
                if l.starts_with("EHLO") {
                    if self.password_hash.is_some() {
                        "250-yggmail-ng Hello\r\n250 AUTH LOGIN\r\n"
                    } else {
                        "250 yggmail-ng Hello\r\n"
                    }
                } else {
                    "250 yggmail-ng Hello\r\n"
                }
            }
            l if l.starts_with("AUTH LOGIN") => {
                // Handled in handle_conn with proper 2-step SASL LOGIN protocol
                "503 Bad sequence\r\n"
            }
            l if l.starts_with("MAIL FROM:") => {
                if self.state != State::ExpectMail {
                    return "503 Bad sequence\r\n";
                }
                let addr = extract_addr(l, "MAIL FROM:").unwrap_or_default();
                if addr.is_empty() {
                    return "501 Syntax error in MAIL FROM\r\n";
                }
                if let Some(pk) = parse_address(&addr) {
                    if pk != self.local_key {
                        return "550 Not allowed to send as that address\r\n";
                    }
                }
                self.from = Some(addr);
                self.rcpts.clear();
                self.state = State::ExpectRcpt;
                "250 OK\r\n"
            }
            l if l.starts_with("RCPT TO:") => {
                if self.state != State::ExpectRcpt {
                    return "503 Bad sequence\r\n";
                }
                if self.rcpts.len() >= 50 {
                    return "552 Too many recipients\r\n";
                }
                let addr = extract_addr(l, "RCPT TO:").unwrap_or_default();
                if addr.is_empty() {
                    return "501 Syntax error in RCPT TO\r\n";
                }
                self.rcpts.push(addr);
                "250 OK\r\n"
            }
            "DATA" => {
                if self.state != State::ExpectRcpt || self.rcpts.is_empty() {
                    return "503 Bad sequence\r\n";
                }
                self.state = State::ReceivingData;
                "354 Start mail input; end with <CRLF>.<CRLF>\r\n"
            }
            "QUIT" => {
                "221 Bye\r\n"
            }
            "RSET" => {
                self.from = None;
                self.rcpts.clear();
                self.state = State::ExpectMail;
                "250 OK\r\n"
            }
            "NOOP" => "250 OK\r\n",
            _ => "500 Unknown command\r\n",
        }
    }

    /// Process a dot-terminated mail body: store in Outbox + enqueue.
    async fn accept_mail(&mut self, body: &str, writer: &mut BufWriter<tokio::net::tcp::OwnedWriteHalf>) {
        let from = match self.from.as_ref() {
            Some(f) => f.clone(),
            None => {
                let _ = writer.write_all(b"503 No sender\r\n").await;
                return;
            }
        };

        // Add Received header (RFC 2822). Delta Chat provides its own Date header.
        let received = format!(
            "Received: from localhost by Yggmail {}; {}\r\n",
            hex::encode(&self.local_key[..8]),
            chrono_now()
        );
        let full_mail = format!("{}{}", received, body);

        let id = match self.storage.mail_insert("Outbox", full_mail.as_bytes()) {
            Ok(id) => id,
            Err(e) => {
                tracing::error!("SMTP: failed to store mail in Outbox: {e}");
                let _ = writer.write_all(b"451 Storage error\r\n").await;
                return;
            }
        };

        for rcpt in &self.rcpts {
            if let Some(dest_key) = parse_address(rcpt) {
                let dest_hex = hex::encode(dest_key);
                if let Err(e) = self.storage.queue_insert(
                    &dest_hex, "Outbox", id, &from, rcpt,
                ) {
                    tracing::error!("SMTP: failed to enqueue for {}: {}", rcpt, e);
                }
            }
        }

        let _ = writer.write_all(b"250 OK\r\n").await;
        tracing::info!("SMTP: queued mail from {} to {} recipients", from, self.rcpts.len());

        self.from = None;
        self.rcpts.clear();
        self.state = State::ExpectMail;
    }
}

/// Extract the address portion from SMTP command syntax:
/// `MAIL FROM:<addr>` or `RCPT TO:<addr>`.
fn extract_addr(line: &str, prefix: &str) -> Option<String> {
    let rest = line[prefix.len()..].trim();
    // Strip angle brackets if present
    let addr = rest.strip_prefix('<').and_then(|s| s.strip_suffix('>')).unwrap_or(rest);
    if addr.is_empty() { None } else { Some(addr.to_string()) }
}

/// Minimal RFC 2822 timestamp string for Date/Received headers.
/// ponytail: stdlib-only, no chrono crate. Fixed UTC.
fn chrono_now() -> String {
    use std::time::SystemTime;
    let now = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap_or_default();
    let secs = now.as_secs();
    // RFC 2822 §3.3: "Thu, 25 Jun 2026 10:09:51 +0000"
    // ponytail: fixed UTC, no leap seconds, compute calendar manually
    const DAYS_PER_YEAR: u64 = 365;
    const DAYS_PER_4Y: u64 = 365 * 4 + 1;
    const DAYS_PER_100Y: u64 = DAYS_PER_4Y * 25 - 1;
    const DAYS_PER_400Y: u64 = DAYS_PER_100Y * 4 + 1;
    const EPOCH_YEAR: i64 = 1970;
    const SECS_PER_DAY: u64 = 86400;
    const DOW: &[&str] = &["Thu", "Fri", "Sat", "Sun", "Mon", "Tue", "Wed"];
    const MONTHS: &[&str] = &[
        "Jan", "Feb", "Mar", "Apr", "May", "Jun",
        "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
    ];
    // Unix epoch = Thu 1970-01-01 (day 4)
    let days = secs / SECS_PER_DAY;
    let time_secs = secs % SECS_PER_DAY;
    let h = time_secs / 3600;
    let m = (time_secs % 3600) / 60;
    let s = time_secs % 60;
    // Algorithm from Howard Hinnant
    let z = days + 719468;
    let era = z / DAYS_PER_400Y;
    let doe = z - era * DAYS_PER_400Y;
    let yoe = (doe - doe / DAYS_PER_4Y + doe / DAYS_PER_100Y - doe / DAYS_PER_400Y) / DAYS_PER_YEAR;
    let y = (yoe + era * 400) as i64;
    let doy = doe - (DAYS_PER_YEAR * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = if month <= 2 { y + 1 } else { y };
    let dow_idx = ((days + 4) % 7) as usize;
    format!(
        "{}, {:02} {} {} {:02}:{:02}:{:02} +0000",
        DOW[dow_idx], d, MONTHS[month as usize - 1], year, h, m, s
    )
}

/// SHA-256 hex hash of a password (matching the Android-side format).
fn sha2_hex(password: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(password.as_bytes());
    hex::encode(hasher.finalize())
}

/// Base64 decode a SASL response.
fn base64_decode(input: &str) -> Option<String> {
    use base64::Engine as _;
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(input)
        .ok()?;
    String::from_utf8(bytes).ok()
}

/// Constant-time equality for equal-length hex hash strings.
/// Length mismatch returns false immediately (both sides are fixed 64-char
/// SHA-256 hex).  Prevents timing side-channels on the password comparison.
fn ct_eq(a: &str, b: &str) -> bool {
    let (a, b) = (a.as_bytes(), b.as_bytes());
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

/// Start the SMTP server on `127.0.0.1:port`, spawning a task per connection.
pub async fn serve(
    port: u16,
    storage: Arc<SqliteStorage>,
    local_key: [u8; 32],
    password_hash: Option<String>,
) -> Result<(), Box<dyn std::error::Error>> {
    if password_hash.is_none() {
        tracing::warn!(
            "SMTP: starting WITHOUT authentication — any local app on this device can access mail"
        );
    }
    let addr = format!("127.0.0.1:{}", port);
    let listener = TcpListener::bind(&addr).await?;
    tracing::info!("SMTP server listening on {}", addr);

    loop {
        let (stream, peer) = listener.accept().await?;
        if !peer.ip().is_loopback() {
            tracing::warn!("SMTP: rejected non-loopback connection from {}", peer);
            continue;
        }

        let storage = storage.clone();
        let pw = password_hash.clone();
        tokio::spawn(async move {
            if let Err(e) = handle_conn(stream, storage, local_key, pw).await {
                tracing::warn!("SMTP session error: {e}");
            }
        });
    }
}

pub async fn handle_conn(
    stream: tokio::net::TcpStream,
    storage: Arc<SqliteStorage>,
    local_key: [u8; 32],
    password_hash: Option<String>,
) -> Result<(), Box<dyn std::error::Error>> {
    let (reader, writer) = stream.into_split();
    let mut reader = BufReader::new(reader);
    let mut writer = BufWriter::new(writer);
    let mut line = String::new();
    let mut data_buf = String::new();

    let mut session = Session::new(storage, local_key, password_hash);

    writer.write_all(b"220 yggmail-ng ESMTP Ready\r\n").await?;
    writer.flush().await?;

    loop {
        line.clear();
        // Bounded read: tokio's read_line normally buffers the entire line into
        // memory before returning.  `take(MAX_LINE_BYTES as u64)` wraps the
        // reader in an adapter whose Read impl returns EOF after that many bytes,
        // so read_line stops filling `line` beyond the cap.  If the line arrived
        // with no trailing '\n' at exactly the cap length it was truncated — we
        // detect that and close the connection to prevent desync.
        let n = (&mut reader)
            .take(MAX_LINE_BYTES as u64)
            .read_line(&mut line)
            .await?;
        if n == 0 {
            break; // EOF
        }
        // A full cap without a newline means the line was truncated — reject.
        if line.len() >= MAX_LINE_BYTES && !line.ends_with('\n') {
            writer.write_all(b"500 Line too long\r\n").await?;
            writer.flush().await?;
            return Ok(()); // close connection
        }

        let cmd = line.trim().to_uppercase();
        tracing::trace!("SMTP CMD: {}", cmd);

        if session.state == State::ReceivingData {
            // Accumulate DATA content until "\r\n.\r\n"
            if line == ".\r\n" || line == ".\n" {
                // End of DATA — store and enqueue
                session.accept_mail(&data_buf, &mut writer).await;
                data_buf.clear();
                writer.flush().await?;
            } else {
                // Handle dot-stuffing: RFC 5321 §4.5.2 — only strip leading dot if line starts with ".."
                // Single "." followed by CRLF is the DATA terminator (already handled above)
                let stripped = if line.starts_with("..") { &line[1..] } else { &line[..] };
                // Guard against unbounded accumulation before the dot-terminator.
                if data_buf.len() + stripped.len() > MAX_DATA_BYTES {
                    writer.write_all(b"552 Message too large\r\n").await?;
                    writer.flush().await?;
                    data_buf.clear();
                    session.state = State::ExpectMail;
                    session.from = None;
                    session.rcpts.clear();
                    continue;
                }
                data_buf.push_str(stripped);
            }
        } else if session.state == State::ExpectAuth && cmd.starts_with("AUTH LOGIN") {
            // SASL LOGIN 2-step challenge-response (RFC 4954)
            // Step 1: challenge with base64("Username:")
            writer.write_all(b"334 VXNlcm5hbWU6\r\n").await?;
            writer.flush().await?;

            // Step 2: read username (ignored — local key verifies identity, not username)
            line.clear();
            {
                let n = (&mut reader).take(MAX_LINE_BYTES as u64).read_line(&mut line).await?;
                if n == 0 { break; }
                if line.len() >= MAX_LINE_BYTES && !line.ends_with('\n') {
                    writer.write_all(b"500 Line too long\r\n").await?;
                    writer.flush().await?;
                    return Ok(());
                }
            }

            // Step 3: challenge with base64("Password:")
            writer.write_all(b"334 UGFzc3dvcmQ6\r\n").await?;
            writer.flush().await?;

            // Step 4: read base64-encoded password and verify
            line.clear();
            {
                let n = (&mut reader).take(MAX_LINE_BYTES as u64).read_line(&mut line).await?;
                if n == 0 { break; }
                if line.len() >= MAX_LINE_BYTES && !line.ends_with('\n') {
                    writer.write_all(b"500 Line too long\r\n").await?;
                    writer.flush().await?;
                    return Ok(());
                }
            }
            let password = match base64_decode(line.trim()) {
                Some(p) => p,
                None => {
                    writer.write_all(b"535 Authentication failed\r\n").await?;
                    writer.flush().await?;
                    continue;
                }
            };

            let ok = match session.password_hash {
                Some(ref hash) => ct_eq(&sha2_hex(&password), hash),
                None => true,
            };

            if ok {
                session.authenticated = true;
                session.state = State::ExpectMail;
                writer.write_all(b"235 Authentication successful\r\n").await?;
            } else {
                writer.write_all(b"535 Authentication failed\r\n").await?;
            }
            writer.flush().await?;
        } else {
            let reply = session.reply_code(&cmd);
            writer.write_all(reply.as_bytes()).await?;
            writer.flush().await?;

            if cmd == "QUIT" {
                break;
            }
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::SqliteStorage;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    fn temp_db(name: &str) -> SqliteStorage {
        let dir = std::env::temp_dir();
        let path = dir.join(format!("yggmail_smtp_test_{}_{}.db", std::process::id(), name));
        let _ = std::fs::remove_file(&path);
        SqliteStorage::open(&path.to_string_lossy(), None).unwrap()
    }

    /// Smoke test: connect to SMTP, send HELO/MAIL/RCPT/DATA/QUIT, verify mail lands in Outbox.
    #[tokio::test]
    async fn smtp_session_roundtrip() {
        let storage = Arc::new(temp_db("roundtrip"));
        let local_key = [0x42u8; 32];

        // Spawn SMTP server on a random port
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let srv_storage = storage.clone();
        tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let _ = handle_conn(stream, srv_storage, local_key, None).await;
        });

        // Connect as SMTP client
        let mut stream = tokio::net::TcpStream::connect(format!("127.0.0.1:{}", port)).await.unwrap();
        let mut buf = vec![0u8; 1024];

        // Read greeting
        let n = stream.read(&mut buf).await.unwrap();
        assert!(buf[..n].starts_with(b"220 "), "expected 220 greeting");

        // HELO
        stream.write_all(b"HELO test\r\n").await.unwrap();
        let n = stream.read(&mut buf).await.unwrap();
        assert!(buf[..n].starts_with(b"250 "), "expected 250 HELO");

        // MAIL FROM
        let from = crate::address::create_address(&local_key);
        stream.write_all(format!("MAIL FROM:<{}>\r\n", from).as_bytes()).await.unwrap();
        let n = stream.read(&mut buf).await.unwrap();
        assert!(buf[..n].starts_with(b"250 "), "expected 250 MAIL FROM");

        // RCPT TO
        let bob = crate::address::create_address(&[0x99u8; 32]);
        stream.write_all(format!("RCPT TO:<{}>\r\n", bob).as_bytes()).await.unwrap();
        let n = stream.read(&mut buf).await.unwrap();
        assert!(buf[..n].starts_with(b"250 "), "expected 250 RCPT TO");

        // DATA
        stream.write_all(b"DATA\r\n").await.unwrap();
        let n = stream.read(&mut buf).await.unwrap();
        assert!(buf[..n].starts_with(b"354 "), "expected 354 DATA");

        // Send body + dot terminator
        let body = "Subject: Test\r\nFrom: test@yggmail\r\n\r\nHello, SMTP!\r\n.\r\n";
        stream.write_all(body.as_bytes()).await.unwrap();
        let n = stream.read(&mut buf).await.unwrap();
        assert!(buf[..n].starts_with(b"250 "), "expected 250 after DATA");

        // QUIT
        stream.write_all(b"QUIT\r\n").await.unwrap();
        let n = stream.read(&mut buf).await.unwrap();
        assert!(buf[..n].starts_with(b"221 "), "expected 221 QUIT");

        // Verify mail is in Outbox
        let ids = storage.mail_list("Outbox").unwrap();
        assert!(!ids.is_empty(), "mail should be in Outbox");

        // Verify queue entry exists
        let dests = storage.queue_list_destinations().unwrap();
        assert!(!dests.is_empty(), "queue should have a destination");
    }
}
