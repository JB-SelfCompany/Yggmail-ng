//! yggmail-ng — P2P email server over Yggdrasil mesh network.
//!
//! Usage: yggmail [--config <yggdrasil.toml>] [--yggmail-config <yggmail.toml>]
//!                [--genconf] [--help] [--version]

use std::sync::Arc;

use yggdrasil::core::Core;
use yggmail::config::YggmailConfig;
use yggmail::core_conn::CoreConn;
use yggmail::peer;
use yggmail::storage::SqliteStorage;
use yggmail::ymp::YmpSession;

const VERSION: &str = env!("CARGO_PKG_VERSION");

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = std::env::args().collect();

    // ── CLI flags ─────────────────────────────────────────────────────
    let mut yggdrasil_config_path = "yggdrasil.toml".to_string();
    let mut yggmail_config_path = "yggmail.toml".to_string();
    let mut genconf = false;
    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--help" | "-h" => { print_help(); return Ok(()); }
            "--version" | "-V" => { println!("yggmail-ng {}", VERSION); return Ok(()); }
            "--genconf" => { genconf = true; }
            "--config" | "-c" => {
                i += 1;
                if i < args.len() { yggdrasil_config_path = args[i].clone(); }
            }
            "--yggmail-config" => {
                i += 1;
                if i < args.len() { yggmail_config_path = args[i].clone(); }
            }
            _ => {}
        }
        i += 1;
    }

    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "info".into()),
        )
        .init();

    tracing::info!("yggmail-ng v{} starting", VERSION);

    // ── Genconf mode ──────────────────────────────────────────────────
    if genconf {
        let cfg = yggdrasil::config::Config::generate();
        let yggmail_cfg = YggmailConfig::default();
        std::fs::write(&yggdrasil_config_path, toml::to_string_pretty(&cfg)?)?;
        std::fs::write(&yggmail_config_path, toml::to_string_pretty(&yggmail_cfg)?)?;
        tracing::info!("Configs written: {}, {}", yggdrasil_config_path, yggmail_config_path);
        return Ok(());
    }

    // ── Load configs ──────────────────────────────────────────────────
    let yggdrasil_config = load_yggdrasil_config(&yggdrasil_config_path)?;
    let yggmail_config = YggmailConfig::load_or_create(&yggmail_config_path)?;

    let signing_key = yggdrasil_config.signing_key()?;
    let public_key = signing_key.verifying_key().to_bytes();
    let address = yggmail::address::create_address(&public_key);

    tracing::info!("Identity: {}", address);

    // ── Storage + welcome email ───────────────────────────────────────
    // ponytail: desktop binary has no password config yet; plaintext mode.
    let storage = Arc::new(SqliteStorage::open(&yggmail_config.db_path, None)?);

    // Welcome email on first run (if INBOX is empty)
    if storage.mail_count("INBOX").unwrap_or(0) == 0 {
        let welcome = format!(
            "From: Yggmail Team\r\nTo: {}\r\nSubject: Welcome to Yggmail!\r\n\r\n\
             Hey {}!\r\n\r\n\
             Welcome to yggmail-ng — P2P email over the Yggdrasil mesh network.\r\n\
             Your address: {}\r\n\r\n\
             SMTP: 127.0.0.1:{}\r\n\
             IMAP: 127.0.0.1:{}\r\n\r\n\
             Configure your mail client (Thunderbird/Outlook) to use the above\r\n\
             servers with no authentication or encryption.\r\n\r\n\
             — The yggmail-ng team\r\n",
            address, address, address,
            yggmail_config.smtp_port,
            yggmail_config.imap_port,
        );
        storage.mail_insert("INBOX", welcome.as_bytes())?;
        tracing::info!("Welcome email sent to {}", address);
    }

    // ── Core + YMP ────────────────────────────────────────────────────
    let core = Core::new(signing_key.clone(), yggdrasil_config);
    core.init_links().await;
    core.start().await;
    tracing::info!("Core started");

    let conn = CoreConn::new(core.clone(), signing_key);
    let ymp = Arc::new(YmpSession::new(
        conn as Arc<dyn ironwood::types::PacketConn>,
    ));

    // ── Peer exchange ─────────────────────────────────────────────────
    let _receiver = peer::receiver::spawn(storage.clone(), ymp.clone());
    let _sender = peer::sender::spawn(
        storage.clone(), ymp.clone(),
        core.clone(),
        tokio::time::Duration::from_secs(30),
    );

    // ── SMTP ──────────────────────────────────────────────────────────
    let smtp_storage = storage.clone();
    let _smtp = tokio::spawn(async move {
        if let Err(e) = yggmail::smtp::serve(
            yggmail_config.smtp_port, smtp_storage, public_key, None,
        ).await { tracing::error!("SMTP: {e}"); }
    });

    // ── IMAP ──────────────────────────────────────────────────────────
    // ponytail: IDLE notify channel. Binary receiver (peer::receiver::spawn)
    // doesn't send notifications yet — IDLE clients rely on reconnect poll.
    // Channel kept so serve() signature matches the mobile path.
    let (imap_notify_tx, _) = tokio::sync::broadcast::channel::<()>(16);
    let imap_storage = storage.clone();
    let _imap = tokio::spawn(async move {
        if let Err(e) = yggmail::imap::serve(
            yggmail_config.imap_port, imap_storage, public_key, None, imap_notify_tx,
        ).await { tracing::error!("IMAP: {e}"); }
    });

    tracing::info!(
        "SMTP 127.0.0.1:{}  IMAP 127.0.0.1:{}  Ctrl+C to stop",
        yggmail_config.smtp_port, yggmail_config.imap_port
    );

    tokio::signal::ctrl_c().await?;
    tracing::info!("Shutting down");
    core.close().await?;
    Ok(())
}

fn print_help() {
    println!("yggmail-ng {} — P2P email over Yggdrasil mesh", VERSION);
    println!("Usage: yggmail [flags]");
    println!("  --config, -c FILE       Yggdrasil config (default: yggdrasil.toml)");
    println!("  --yggmail-config FILE   Yggmail config (default: yggmail.toml)");
    println!("  --genconf               Generate fresh configs and exit");
    println!("  --help, -h              Show this help");
    println!("  --version, -V           Show version");
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[tokio::test]
    async fn e2e_smtp_imap_roundtrip() {
        let dir = std::env::temp_dir();
        let db_path = dir.join(format!("yggmail_e2e_{}.db", std::process::id()));
        let _ = std::fs::remove_file(&db_path);

        let storage = Arc::new(SqliteStorage::open(&db_path.to_string_lossy(), None).unwrap());
        let local_key = [0x42u8; 32];

        // SMTP server on random port
        let smtp_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let smtp_port = smtp_listener.local_addr().unwrap().port();
        let smtp_storage = storage.clone();
        tokio::spawn(async move {
            let (stream, _) = smtp_listener.accept().await.unwrap();
            let _ = yggmail::smtp::handle_conn(stream, smtp_storage, local_key, None).await;
        });

        // IMAP server on random port
        let imap_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let imap_port = imap_listener.local_addr().unwrap().port();
        let imap_storage = storage.clone();
        tokio::spawn(async move {
            let (stream, _) = imap_listener.accept().await.unwrap();
            let (idle_tx, _) = tokio::sync::broadcast::channel(1);
            let _ = yggmail::imap::handle_conn(stream, imap_storage, local_key, None, idle_tx).await;
        });

        // ── SMTP: send a mail ────────────────────────────────────────
        let mut smtp = tokio::net::TcpStream::connect(format!("127.0.0.1:{}", smtp_port)).await.unwrap();
        let mut buf = vec![0u8; 4096];
        let _ = smtp.read(&mut buf).await.unwrap(); // greeting

        smtp.write_all(b"HELO e2e\r\n").await.unwrap();
        let _ = smtp.read(&mut buf).await.unwrap();

        let from = yggmail::address::create_address(&local_key);
        smtp.write_all(format!("MAIL FROM:<{}>\r\n", from).as_bytes()).await.unwrap();
        let _ = smtp.read(&mut buf).await.unwrap();

        smtp.write_all(b"RCPT TO:<bob@yggmail>\r\n").await.unwrap();
        let _ = smtp.read(&mut buf).await.unwrap();

        smtp.write_all(b"DATA\r\n").await.unwrap();
        let _ = smtp.read(&mut buf).await.unwrap();

        smtp.write_all(b"Subject: E2E Test\r\n\r\nEnd-to-end works!\r\n.\r\n").await.unwrap();
        let _ = smtp.read(&mut buf).await.unwrap();

        smtp.write_all(b"QUIT\r\n").await.unwrap();
        let _ = smtp.read(&mut buf).await.unwrap();

        // ── IMAP: read the mail back ──────────────────────────────────
        let mut imap = tokio::net::TcpStream::connect(format!("127.0.0.1:{}", imap_port)).await.unwrap();
        let _ = imap.read(&mut buf).await.unwrap(); // greeting

        let user = hex::encode(local_key);
        imap.write_all(format!("a001 LOGIN {} x\r\n", user).as_bytes()).await.unwrap();
        let _ = imap.read(&mut buf).await.unwrap();

        imap.write_all(b"a002 SELECT Outbox\r\n").await.unwrap();
        let _ = imap.read(&mut buf).await.unwrap();

        imap.write_all(b"a003 FETCH 1:* (BODY[])\r\n").await.unwrap();
        let n = imap.read(&mut buf).await.unwrap();
        let resp = String::from_utf8_lossy(&buf[..n]);
        assert!(resp.contains("E2E Test"), "E2E: subject not found in IMAP response:\n{}", resp);
        assert!(resp.contains("End-to-end works!"), "E2E: body not found");

        imap.write_all(b"a004 LOGOUT\r\n").await.unwrap();
        let _ = imap.read(&mut buf).await.unwrap();
    }
}

fn load_yggdrasil_config(path: &str) -> Result<yggdrasil::config::Config, Box<dyn std::error::Error>> {
    if std::path::Path::new(path).exists() {
        let text = std::fs::read_to_string(path)?;
        Ok(toml::from_str(&text)?)
    } else {
        tracing::info!("No config at {}, generating…", path);
        let cfg = yggdrasil::config::Config::generate();
        std::fs::write(path, toml::to_string_pretty(&cfg)?)?;
        Ok(cfg)
    }
}
