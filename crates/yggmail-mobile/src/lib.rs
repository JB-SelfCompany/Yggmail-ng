//! yggmail-mobile — UniFFI bindings for Android/iOS.

uniffi::include_scaffolding!("yggmail_mobile");

use std::collections::HashSet;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, Once};
use std::time::Duration;
use tokio::runtime::Runtime;
use tokio::sync::broadcast;

#[cfg(test)]
use rand::rngs::OsRng;
use sha2::{Digest, Sha256};

use yggdrasil::config::Config as YggdrasilConfig;
use yggdrasil::core::Core;
use yggmail::address::create_address;
use yggmail::core_conn::CoreConn;
use yggmail::identity::{load_or_migrate_identity, parse_signing_key};
use yggmail::storage::SqliteStorage;
use yggmail::ymp::YmpSession;

// ── tracing ────────────────────────────────────────────────────────────

fn init_tracing() {
    static INIT: Once = Once::new();
    INIT.call_once(|| {
        use tracing_subscriber::EnvFilter;
        use tracing_subscriber::layer::SubscriberExt;
        use tracing_subscriber::util::SubscriberInitExt;
        let filter = EnvFilter::new("ironwood=info,yggmail=info,info");
        #[cfg(target_os = "android")]
        {
            tracing_subscriber::registry()
                .with(filter)
                .with(tracing_android::layer("Yggmail").unwrap())
                .init();
        }
        #[cfg(not(target_os = "android"))]
        {
            tracing_subscriber::registry()
                .with(filter)
                .with(tracing_subscriber::fmt::layer())
                .init();
        }
    });
}

// ── error ──────────────────────────────────────────────────────────────

#[derive(Debug, thiserror::Error)]
pub enum YggmailError {
    #[error("Config: {0}")]
    Config(String),
    #[error("Runtime: {0}")]
    Runtime(String),
    #[error("Io: {0}")]
    Io(String),
    #[error("Network: {0}")]
    Network(String),
}

impl From<yggmail::identity::IdentityError> for YggmailError {
    fn from(e: yggmail::identity::IdentityError) -> Self {
        match e {
            yggmail::identity::IdentityError::Io(s) => YggmailError::Io(s),
            yggmail::identity::IdentityError::Config(s) => YggmailError::Config(s),
        }
    }
}

// ── config / state types ───────────────────────────────────────────────

pub struct YggmailConfig {
    pub private_key: String,
    pub peers: Vec<String>,
    pub listen: Vec<String>,
    pub group_password: String,
    pub database_path: String,
    pub smtp_port: u16,
    pub imap_port: u16,
    pub password_hash: String,
}

pub struct YggmailState {
    pub address: String,
    pub public_key: String,
    pub inbox_count: u32,
    pub peers_connected: u32,
    pub routing_entries: u32,
}

pub struct MailSummary {
    pub id: u32,
    pub from: String,
    pub subject: String,
    pub date_secs: u64,
    pub seen: bool,
    pub size: u32,
}

// ── internal node state ────────────────────────────────────────────────

struct NodeState {
    core: Arc<Core>,
    _conn: Arc<CoreConn>,
    storage: Arc<SqliteStorage>,
    ymp: Arc<YmpSession>,
    stop_tx: broadcast::Sender<()>,
    active_tx: broadcast::Sender<bool>,
    receiver_handle: Option<tokio::task::JoinHandle<()>>,
    smtp_handle: Option<tokio::task::AbortHandle>,
    imap_handle: Option<tokio::task::AbortHandle>,
    imap_notify_tx: Option<broadcast::Sender<()>>,
    password_hash: Mutex<Option<String>>,
    db_path: String,
}

// ── YggmailMobile ─────────────────────────────────────────────────────

pub struct YggmailMobile {
    state: Mutex<Option<NodeState>>,
    runtime: Runtime,
    active: AtomicBool,
    charging: AtomicBool,
    max_message_size: AtomicU64,
}

impl YggmailMobile {
    pub fn new() -> Result<Self, YggmailError> {
        init_tracing();
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .map_err(|e| YggmailError::Runtime(e.to_string()))?;
        Ok(Self {
            state: Mutex::new(None),
            runtime,
            active: AtomicBool::new(false),
            charging: AtomicBool::new(false),
            max_message_size: AtomicU64::new(0),
        })
    }

    pub fn start(&self, config: YggmailConfig) -> Result<(), YggmailError> {
        self.runtime.block_on(async {
            // Open storage first so the data key (DK) is available for private-key
            // encryption/decryption before we load the identity.
            let pw_hash_opt = if config.password_hash.is_empty() {
                None
            } else {
                Some(config.password_hash.as_str())
            };
            let storage = Arc::new(
                SqliteStorage::open(&config.database_path, pw_hash_opt)
                    .map_err(|e| YggmailError::Runtime(e.to_string()))?
            );

            // Load (or generate) the Ed25519 identity, encrypting/decrypting via DK.
            // ponytail: identity MUST be stable across restarts. Writing mobile_config
            // without reading it back (the old code) rotated the Ed25519 key on every
            // start, so a double-start left the bound IMAP server holding key K1 while
            // the chat client logged in with node #2's address (key K2) → IMAP LOGIN
            // failed, and the user's mail address changed on every app restart.
            let (signing_key, private_key_hex) = if config.private_key.is_empty() {
                load_or_migrate_identity(&config.database_path, storage.at_rest_key.as_ref())?
            } else {
                (parse_signing_key(&config.private_key)?, config.private_key.clone())
            };
            let public_key = signing_key.verifying_key().to_bytes();

            let ygg_config = YggdrasilConfig {
                private_key: private_key_hex,
                peers: config.peers.clone(),
                listen: if config.listen.is_empty() { vec!["tcp://[::]:0".to_string()] }
                         else { config.listen.clone() },
                group_password: config.group_password.clone(),
                ..YggdrasilConfig::default()
            };

            let core = Core::new(signing_key.clone(), ygg_config);
            core.init_links().await;
            core.start().await;

            let conn = CoreConn::new(core.clone(), signing_key);
            let ymp = Arc::new(YmpSession::new(
                conn.clone() as Arc<dyn ironwood::types::PacketConn>,
            ));

            let (stop_tx, _) = broadcast::channel(1);
            let (active_tx, _) = broadcast::channel(1);
            // IMAP notification channel — wakes IDLE clients (Delta Chat)
            // when YMP delivers new mail to INBOX.
            let (imap_notify_tx, _) = broadcast::channel::<()>(16);

            // Spawn receiver (YMP -> INBOX)
            let rx_storage = storage.clone();
            let rx_ymp = ymp.clone();
            let rx_stop = stop_tx.subscribe();
            let rx_imap_notify = imap_notify_tx.clone();
            let receiver_handle = tokio::spawn(async move {
                let mut stop_rx = rx_stop;
                loop {
                    tokio::select! {
                        _ = stop_rx.recv() => break,
                        msg = rx_ymp.recv() => {
                            match msg {
                                Ok((from_key, data)) => {
                                    tracing::info!("mobile: received mail via YMP, {} bytes", data.len());
                                    match rx_storage.mail_insert_inbox_dedup(&from_key, &data) {
                                        Ok(Some(id)) => {
                                            tracing::info!("mobile: stored mail in INBOX, id={}", id);
                                            // Notify IMAP IDLE clients (Delta Chat)
                                            let _ = rx_imap_notify.send(());
                                        }
                                        Ok(None) => {
                                            tracing::debug!(
                                                "mobile: duplicate mail from {} dropped",
                                                hex::encode(from_key)
                                            );
                                            // No IDLE notify — duplicate was not stored
                                        }
                                        Err(e) => {
                                            tracing::error!("mail_insert error: {e}");
                                        }
                                    }
                                }
                                Err(_) => tokio::time::sleep(Duration::from_secs(1)).await,
                            }
                        }
                    }
                }
            });

            // Spawn outbound sender (polls queue -> readiness-gate -> YMP delivery).
            // The sender waits for ≥1 "up" peer before each send (wait_for_up_peer),
            // so send_mail is enqueue-only and never blocks the Android serviceHandler.
            let tx_storage = storage.clone();
            let tx_ymp = ymp.clone();
            yggmail::peer::sender::spawn(tx_storage, tx_ymp, core.clone(), Duration::from_secs(30));

            // Path-warmer: keep the Yggdrasil path to recently-active correspondents
            // warm. ironwood expires a cached path after ~60s (path_timeout); the Go
            // library kept it warm via QUIC keepalive/heartbeat, which the Rust rewrite
            // dropped — the root cause of slow/failed reconnection vs Go. Re-warm every
            // 25s (< 60s) via send_lookup for peers seen in the last 10 minutes.
            let warm_ymp = ymp.clone();
            let warm_core = core.clone();
            let mut warm_stop = stop_tx.subscribe();
            tokio::spawn(async move {
                let mut tick = tokio::time::interval(Duration::from_secs(25));
                tick.tick().await; // skip the immediate first tick
                loop {
                    tokio::select! {
                        _ = warm_stop.recv() => break,
                        _ = tick.tick() => {
                            for peer in warm_ymp.recent_peers(Duration::from_secs(600)).await {
                                warm_core.send_lookup(ironwood::types::Addr(peer)).await;
                            }
                        }
                    }
                }
            });

            let pw = if config.password_hash.is_empty() { None } else { Some(config.password_hash.clone()) };
            let node = NodeState {
                core,
                _conn: conn,
                storage,
                ymp,
                stop_tx,
                active_tx,
                imap_notify_tx: Some(imap_notify_tx),
                receiver_handle: Some(receiver_handle),
                smtp_handle: None,
                imap_handle: None,
                password_hash: Mutex::new(pw),
                db_path: config.database_path,
            };
            *self.state.lock().unwrap() = Some(node);
            Ok(())
        })
    }

    pub fn stop(&self) {
        let mut guard = self.state.lock().unwrap();
        if let Some(ref node) = *guard {
            // Abort all background tasks
            if let Some(h) = node.receiver_handle.as_ref() {
                h.abort();
            }
            if let Some(h) = node.smtp_handle.as_ref() {
                h.abort();
            }
            if let Some(h) = node.imap_handle.as_ref() {
                h.abort();
            }
            let _ = node.stop_tx.send(());
        }
        *guard = None;
    }

    pub fn send_mail(&self, to: String, subject: String, body: String) -> Result<(), YggmailError> {
        // Sanitize to prevent header injection
        let safe_subject = subject.replace('\r', "").replace('\n', " ");
        let safe_body = body.replace('\r', "").replace('\n', " ");

        let state = self.state.lock().unwrap();
        let node = state
            .as_ref()
            .ok_or(YggmailError::Runtime("not started".into()))?;

        let mail = format!(
            "To: {}\r\nSubject: {}\r\n\r\n{}",
            to, safe_subject, safe_body
        );
        let id = node
            .storage
            .mail_insert("Outbox", mail.as_bytes())
            .map_err(|e| YggmailError::Runtime(e.to_string()))?;

        let dest = yggmail::address::parse_address(&to)
            .ok_or_else(|| YggmailError::Config(format!("invalid address: {}", to)))?;

        let from = create_address(node.core.public_key());
        node.storage
            .queue_insert(&hex::encode(dest), "Outbox", id, &from, &to)
            .map_err(|e| YggmailError::Runtime(e.to_string()))?;

        // Enqueue-only: the background sender task handles delivery (with the
        // readiness-gate). send_mail must NOT block_on ymp.send() — on Android
        // this runs on the single-threaded serviceHandler, and a cold-start
        // block_on would freeze the entire YggmailService (~75s stall).
        drop(state);
        Ok(())
    }

    pub fn get_inbox_count(&self) -> u32 {
        self.state
            .lock()
            .unwrap()
            .as_ref()
            .and_then(|n| n.storage.mail_count("INBOX").ok())
            .unwrap_or(0)
    }

    pub fn get_mail_summaries(&self, page: u32, page_size: u32) -> Vec<MailSummary> {
        let state = self.state.lock().unwrap();
        let node = match state.as_ref() {
            Some(n) => n,
            None => return vec![],
        };
        let ids = node.storage.mail_list("INBOX").unwrap_or_default();
        ids.iter()
            .skip((page * page_size) as usize)
            .take(page_size as usize)
            .filter_map(|id| {
                node.storage
                    .mail_get("INBOX", *id)
                    .ok()
                    .flatten()
                    .map(|m| MailSummary {
                        id: m.id,
                        from: extract_header(&m.mail, "From:").unwrap_or_default(),
                        subject: extract_header(&m.mail, "Subject:").unwrap_or_default(),
                        date_secs: m.date as u64,
                        seen: m.seen,
                        size: m.mail.len() as u32,
                    })
            })
            .collect()
    }

    pub fn get_mail_raw(&self, mailbox: String, id: u32) -> Vec<u8> {
        self.state
            .lock()
            .unwrap()
            .as_ref()
            .and_then(|n| n.storage.mail_get(&mailbox, id).ok().flatten())
            .map(|m| m.mail)
            .unwrap_or_default()
    }

    pub fn get_state(&self) -> YggmailState {
        match self.state.lock().unwrap().as_ref() {
            Some(node) => {
                let peers_connected = self.runtime.block_on(async {
                    let peers = node.core.get_peers().await;
                    peers.iter().filter(|p| p.up).count() as u32
                });
                YggmailState {
                    address: create_address(node.core.public_key()),
                    public_key: hex::encode(node.core.public_key()),
                    inbox_count: node.storage.mail_count("INBOX").unwrap_or(0),
                    peers_connected,
                    routing_entries: 0, // Not directly available from Core API
                }
            }
            None => YggmailState {
                address: String::new(),
                public_key: String::new(),
                inbox_count: 0,
                peers_connected: 0,
                routing_entries: 0,
            },
        }
    }

    // ── SMTP/IMAP server control ─────────────────────────────────────────

    pub fn start_smtp(&self, port: u16, password_hash: String) -> Result<(), YggmailError> {
        let mut state = self.state.lock().unwrap();
        let node = state
            .as_mut()
            .ok_or(YggmailError::Runtime("not started".into()))?;
        let storage = node.storage.clone();
        let local_key = *node.core.public_key();
        let pw = if password_hash.is_empty() {
            None
        } else {
            Some(password_hash)
        };

        let handle = self.runtime.handle().spawn(async move {
            if let Err(e) = yggmail::smtp::serve(port, storage, local_key, pw).await {
                tracing::error!("SMTP server error: {e}");
            }
        });
        node.smtp_handle = Some(handle.abort_handle());
        Ok(())
    }

    pub fn start_imap(&self, port: u16, password_hash: String) -> Result<(), YggmailError> {
        let mut state = self.state.lock().unwrap();
        let node = state
            .as_mut()
            .ok_or(YggmailError::Runtime("not started".into()))?;
        let storage = node.storage.clone();
        let local_key = *node.core.public_key();
        let pw = if password_hash.is_empty() {
            None
        } else {
            Some(password_hash)
        };

        let notify_tx = node.imap_notify_tx.clone().unwrap();
        let handle = self.runtime.handle().spawn(async move {
            if let Err(e) = yggmail::imap::serve(port, storage, local_key, pw, notify_tx).await {
                tracing::error!("IMAP server error: {e}");
            }
        });
        node.imap_handle = Some(handle.abort_handle());
        Ok(())
    }

    pub fn stop_smtp(&self) {
        let mut state = self.state.lock().unwrap();
        if let Some(ref mut node) = *state {
            if let Some(h) = node.smtp_handle.take() {
                h.abort();
            }
        }
    }

    pub fn stop_imap(&self) {
        let mut state = self.state.lock().unwrap();
        if let Some(ref mut node) = *state {
            if let Some(h) = node.imap_handle.take() {
                h.abort();
            }
        }
    }

    // ── Battery optimization ─────────────────────────────────────────────

    pub fn set_active(&self, active: bool) {
        self.active.store(active, Ordering::Relaxed);
        let state = self.state.lock().unwrap();
        if let Some(ref node) = *state {
            let _ = node.active_tx.send(active);
        }
    }

    pub fn set_charging(&self, charging: bool) {
        self.charging.store(charging, Ordering::Relaxed);
    }

    // ── Peer management ──────────────────────────────────────────────────

    pub fn update_peers(&self, peers_json: String) {
        let state = self.state.lock().unwrap();
        let node = match state.as_ref() {
            Some(n) => n,
            None => return,
        };

        let desired: Vec<String> = match serde_json::from_str(&peers_json) {
            Ok(v) => v,
            Err(_) => return,
        };

        self.runtime.block_on(async {
            let current = node.core.get_peers().await;
            let current_uris: HashSet<&str> = current.iter().map(|p| p.uri.as_str()).collect();
            let desired_set: HashSet<&str> = desired.iter().map(|s| s.as_str()).collect();

            // Add new peers
            for uri in &desired {
                if !current_uris.contains(uri.as_str()) {
                    let _ = node.core.add_peer(uri).await;
                }
            }

            // Remove peers no longer desired
            for p in &current {
                if !desired_set.contains(p.uri.as_str()) {
                    let _ = node.core.remove_peer(&p.uri).await;
                }
            }
        });
    }

    pub fn get_peer_connections_json(&self) -> String {
        let state = self.state.lock().unwrap();
        let node = match state.as_ref() {
            Some(n) => n,
            None => return "[]".to_string(),
        };

        self.runtime.block_on(async {
            let peers = node.core.get_peers().await;
            let list: Vec<serde_json::Value> = peers
                .iter()
                .map(|p| {
                    serde_json::json!({
                        "uri": p.uri,
                        "up": p.up,
                        "inbound": p.inbound,
                        "key": hex::encode(p.key),
                        "latencyMs": p.latency_ms,
                        "rxBytes": p.rx_bytes,
                        "txBytes": p.tx_bytes,
                        "uptime": p.uptime_secs,
                    })
                })
                .collect();
            serde_json::to_string(&list).unwrap_or_else(|_| "[]".to_string())
        })
    }

    // ── Storage/quota ────────────────────────────────────────────────────

    pub fn set_max_message_size_mb(&self, mb: u64) {
        self.max_message_size.store(mb, Ordering::Relaxed);
    }

    pub fn get_max_message_size_info(&self) -> String {
        let max_mb = self.max_message_size.load(Ordering::Relaxed);
        serde_json::json!({ "maxSizeMB": max_mb }).to_string()
    }

    pub fn get_mail_storage_stats(&self) -> String {
        let state = self.state.lock().unwrap();
        let db_size = match state.as_ref() {
            Some(node) => std::fs::metadata(&node.db_path)
                .map(|m| m.len())
                .unwrap_or(0),
            None => 0,
        };
        let max_mb = self.max_message_size.load(Ordering::Relaxed);
        let db_size_mb = db_size as f64 / (1024.0 * 1024.0);
        serde_json::json!({
            "dbSizeMB": (db_size_mb * 100.0).round() / 100.0,
            "maxSizeMB": max_mb,
        })
        .to_string()
    }

    pub fn get_outbound_queue_count(&self) -> u32 {
        let state = self.state.lock().unwrap();
        let node = match state.as_ref() {
            Some(n) => n,
            None => return 0,
        };
        let dests = node.storage.queue_list_destinations().unwrap_or_default();
        let mut total = 0u32;
        for d in dests {
            if let Ok(items) = node.storage.queue_get_for_destination(&d) {
                total += items.len() as u32;
            }
        }
        total
    }

    pub fn clear_outbound_queue(&self) {
        let state = self.state.lock().unwrap();
        let node = match state.as_ref() {
            Some(n) => n,
            None => return,
        };
        let dests = match node.storage.queue_list_destinations() {
            Ok(d) => d,
            Err(_) => return,
        };
        for d in dests {
            if let Ok(items) = node.storage.queue_get_for_destination(&d) {
                for item in items {
                    let _ = node.storage.queue_delete(&d, "Outbox", item.id);
                }
            }
        }
    }

    pub fn set_password(&self, password: String) {
        let mut hasher = Sha256::new();
        hasher.update(password.as_bytes());
        let hash = hex::encode(hasher.finalize());

        let state = self.state.lock().unwrap();
        if let Some(ref node) = *state {
            // Re-wrap the data key under the new password hash.
            // This is a no-op when at_rest_key is None (plaintext mode).
            if let Err(e) = node.storage.rewrap_data_key(&hash) {
                tracing::error!("set_password: failed to re-wrap data key: {e}");
            }
            *node.password_hash.lock().unwrap() = Some(hash);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use yggmail::storage::SqliteStorage;

    // Открыть storage с паролем и вернуть выведенный data-key (DK).
    // Storage дропается сразу — load_or_migrate_identity откроет свою connection,
    // ровно как в start(): сперва open() минтит/распечатывает DK, затем identity.
    fn dk_for(db: &str, password_hash: &str) -> Option<[u8; 32]> {
        SqliteStorage::open(db, Some(password_hash))
            .expect("storage open")
            .at_rest_key
    }

    const PW_A: &str = "1111111111111111111111111111111111111111111111111111111111111111";
    const PW_B: &str = "2222222222222222222222222222222222222222222222222222222222222222";

    fn temp_db(tag: &str) -> String {
        let p =
            std::env::temp_dir().join(format!("yggmail-mobile-{}-{}.db", std::process::id(), tag));
        let _ = std::fs::remove_file(&p);
        p.to_str().unwrap().to_string()
    }

    #[test]
    fn migrates_legacy_config_key_preserving_address() {
        let p = temp_db("mig");
        // Simulate a 1.8 DB: legacy `config` table holding the identity key.
        let key = ed25519_dalek::SigningKey::generate(&mut OsRng);
        let hex_key = hex::encode(key.to_keypair_bytes());
        {
            let conn = rusqlite::Connection::open(&p).unwrap();
            conn.execute_batch(
                "CREATE TABLE config (key TEXT NOT NULL, value TEXT NOT NULL, PRIMARY KEY(key));",
            )
            .unwrap();
            conn.execute(
                "INSERT INTO config (key, value) VALUES ('private_key', ?1)",
                rusqlite::params![&hex_key],
            )
            .unwrap();
        }

        // 1.9 start must ADOPT the legacy key (same @yggmail address), not generate one.
        let (loaded, loaded_hex) = load_or_migrate_identity(&p, None).unwrap();
        assert_eq!(
            loaded.verifying_key().to_bytes(),
            key.verifying_key().to_bytes(),
            "upgrade 1.8→1.9 must preserve the @yggmail address"
        );
        assert_eq!(loaded_hex, hex_key);

        // Migrated key is persisted to mobile_config for subsequent starts.
        // In plaintext mode (dk=None) the stored value is the hex key verbatim.
        let conn = rusqlite::Connection::open(&p).unwrap();
        let persisted: String = conn
            .query_row(
                "SELECT value FROM mobile_config WHERE key = 'private_key'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(persisted, hex_key);

        // Idempotent: second call returns the same key.
        let (again, _) = load_or_migrate_identity(&p, None).unwrap();
        assert_eq!(
            again.verifying_key().to_bytes(),
            key.verifying_key().to_bytes()
        );

        let _ = std::fs::remove_file(&p);
    }

    #[test]
    fn legacy_config_key_wins_over_poisoned_mobile_config() {
        // Regression: an older/buggy 1.9 build minted a fresh random key into
        // `mobile_config`, shadowing the real 1.8 address. On upgrade the legacy
        // `config` key MUST win and heal the poisoned mobile_config.
        let p = temp_db("poisoned");
        let real = ed25519_dalek::SigningKey::generate(&mut OsRng);
        let real_hex = hex::encode(real.to_keypair_bytes());
        let bogus = ed25519_dalek::SigningKey::generate(&mut OsRng);
        let bogus_hex = hex::encode(bogus.to_keypair_bytes());
        {
            let conn = rusqlite::Connection::open(&p).unwrap();
            conn.execute_batch(
                "CREATE TABLE config (key TEXT NOT NULL, value TEXT NOT NULL, PRIMARY KEY(key));
                 CREATE TABLE mobile_config (key TEXT PRIMARY KEY, value TEXT);",
            )
            .unwrap();
            conn.execute(
                "INSERT INTO config (key, value) VALUES ('private_key', ?1)",
                rusqlite::params![&real_hex],
            )
            .unwrap();
            conn.execute(
                "INSERT INTO mobile_config (key, value) VALUES ('private_key', ?1)",
                rusqlite::params![&bogus_hex],
            )
            .unwrap();
        }

        let (loaded, loaded_hex) = load_or_migrate_identity(&p, None).unwrap();
        assert_eq!(
            loaded.verifying_key().to_bytes(),
            real.verifying_key().to_bytes(),
            "legacy 1.8 `config` key must win over a poisoned mobile_config key"
        );
        assert_eq!(loaded_hex, real_hex);

        // The poisoned mobile_config must be healed to the real key.
        // In plaintext mode (dk=None) the stored value is the hex key verbatim.
        let conn = rusqlite::Connection::open(&p).unwrap();
        let persisted: String = conn
            .query_row(
                "SELECT value FROM mobile_config WHERE key = 'private_key'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(
            persisted, real_hex,
            "poisoned mobile_config must be overwritten with the real key"
        );

        let _ = std::fs::remove_file(&p);
    }

    #[test]
    fn fresh_install_generates_stable_key() {
        let p = temp_db("fresh");
        let (k1, _) = load_or_migrate_identity(&p, None).unwrap();
        let (k2, _) = load_or_migrate_identity(&p, None).unwrap();
        assert_eq!(
            k1.verifying_key().to_bytes(),
            k2.verifying_key().to_bytes(),
            "a generated key must persist and be stable across starts"
        );
        let _ = std::fs::remove_file(&p);
    }

    #[test]
    fn encrypted_identity_roundtrips() {
        let p = temp_db("enc-roundtrip");

        // Первый "старт": open минтит DK, load генерит+шифрует identity в mobile_config.
        let dk = dk_for(&p, PW_A);
        assert!(dk.is_some(), "password → DK must be present");
        let (k1, hex1) = load_or_migrate_identity(&p, dk.as_ref()).unwrap();

        // Хранимое значение — зашифрованный блоб, НЕ 128-hex plaintext keypair.
        let conn = rusqlite::Connection::open(&p).unwrap();
        let stored: String = conn
            .query_row(
                "SELECT value FROM mobile_config WHERE key = 'private_key'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        let raw = hex::decode(&stored).expect("stored value is hex");
        assert_ne!(raw.len(), 64, "encrypted blob must not be a 64-byte keypair");
        assert_eq!(raw.first(), Some(&0x01u8), "encrypted blob starts with VERSION_XCHACHA");
        assert_ne!(stored, hex1, "stored form must be ciphertext, not plaintext hex");

        // Второй load с тем же DK возвращает тот же адрес (расшифровка сработала).
        let (k2, _) = load_or_migrate_identity(&p, dk.as_ref()).unwrap();
        assert_eq!(
            k1.verifying_key().to_bytes(),
            k2.verifying_key().to_bytes(),
            "encrypted identity must round-trip to the same @yggmail address"
        );

        let _ = std::fs::remove_file(&p);
    }

    #[test]
    fn encrypted_identity_stable_across_restarts() {
        let p = temp_db("enc-restarts");

        // Первый старт фиксирует адрес.
        let first = {
            let dk = dk_for(&p, PW_A);
            let (k, _) = load_or_migrate_identity(&p, dk.as_ref()).unwrap();
            k.verifying_key().to_bytes()
        };

        // Ещё 5 "рестартов": каждый заново открывает storage (распечатывает тот же DK
        // из wrapped_dk) и загружает identity. Адрес обязан остаться прежним.
        for i in 0..5 {
            let dk = dk_for(&p, PW_A);
            let (k, _) = load_or_migrate_identity(&p, dk.as_ref()).unwrap();
            assert_eq!(
                k.verifying_key().to_bytes(),
                first,
                "restart #{i} rotated the @yggmail address — issue #39 regression"
            );
        }

        let _ = std::fs::remove_file(&p);
    }

    #[test]
    fn wrong_password_errors_and_never_rotates_identity() {
        let p = temp_db("enc-wrongpw");

        // Установить identity под паролем A.
        let original = {
            let dk = dk_for(&p, PW_A);
            let (k, _) = load_or_migrate_identity(&p, dk.as_ref()).unwrap();
            k.verifying_key().to_bytes()
        };

        // Открытие под НЕВЕРНЫМ паролем B → hard error (DK не распечатывается),
        // wrapped_dk НЕ перезаписывается новым ключом.
        let bad = SqliteStorage::open(&p, Some(PW_B));
        assert!(bad.is_err(), "wrong password must fail open, never mint a new DK");

        // Возврат к верному паролю A → тот же DK, тот же адрес (ничего не потеряно).
        let dk = dk_for(&p, PW_A);
        let (k, _) = load_or_migrate_identity(&p, dk.as_ref()).unwrap();
        assert_eq!(
            k.verifying_key().to_bytes(),
            original,
            "correct password must recover the exact same @yggmail address"
        );

        let _ = std::fs::remove_file(&p);
    }

    #[test]
    fn password_change_preserves_identity_address() {
        let p = temp_db("enc-rewrap");

        // Identity под паролем A.
        let (before, before_hex) = {
            let dk = dk_for(&p, PW_A);
            load_or_migrate_identity(&p, dk.as_ref()).unwrap()
        };

        // Смена пароля A→B: тот же DK перезаворачивается под KEK(B). Identity/mail не трогаются.
        {
            let s = SqliteStorage::open(&p, Some(PW_A)).unwrap();
            s.rewrap_data_key(PW_B).unwrap();
        }

        // Теперь открытие под НОВЫМ паролем B распечатывает тот же DK → тот же адрес.
        let dk_b = dk_for(&p, PW_B);
        let (after, after_hex) = load_or_migrate_identity(&p, dk_b.as_ref()).unwrap();
        assert_eq!(
            after_hex, before_hex,
            "rewrap must preserve the exact keypair hex — same DK, not a re-mint"
        );
        assert_eq!(
            after.verifying_key().to_bytes(),
            before.verifying_key().to_bytes(),
            "password change must preserve the @yggmail address (restore-under-new-password path)"
        );

        // И старый пароль A после rewrap больше не открывает БД (обёртка сменилась).
        assert!(
            SqliteStorage::open(&p, Some(PW_A)).is_err(),
            "old password must stop working after rewrap"
        );

        let _ = std::fs::remove_file(&p);
    }

    #[test]
    fn legacy_migration_under_encryption_heals_and_encrypts() {
        let p = temp_db("enc-legacy");

        // 1.8 DB: легаси `config` держит реальный ключ; сначала создаём его.
        let real = ed25519_dalek::SigningKey::generate(&mut OsRng);
        let real_hex = hex::encode(real.to_keypair_bytes());
        {
            let conn = rusqlite::Connection::open(&p).unwrap();
            conn.execute_batch(
                "CREATE TABLE config (key TEXT NOT NULL, value TEXT NOT NULL, PRIMARY KEY(key));",
            )
            .unwrap();
            conn.execute(
                "INSERT INTO config (key, value) VALUES ('private_key', ?1)",
                rusqlite::params![&real_hex],
            )
            .unwrap();
        }

        // Открытие storage с паролем создаёт at_rest/DK поверх той же БД.
        let dk = dk_for(&p, PW_A);
        let (loaded, loaded_hex) = load_or_migrate_identity(&p, dk.as_ref()).unwrap();

        // Легаси-адрес сохранён.
        assert_eq!(
            loaded.verifying_key().to_bytes(),
            real.verifying_key().to_bytes(),
            "1.8→1.9 migration must keep the @yggmail address under encryption"
        );
        assert_eq!(loaded_hex, real_hex);

        // mobile_config вылечен И зашифрован (не 64-байтный plaintext keypair).
        let conn = rusqlite::Connection::open(&p).unwrap();
        let stored: String = conn
            .query_row(
                "SELECT value FROM mobile_config WHERE key = 'private_key'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        let raw = hex::decode(&stored).expect("mobile_config stored value must be hex-encoded ciphertext");
        assert_eq!(raw.first(), Some(&0x01u8), "healed mobile_config must be encrypted");
        assert_ne!(stored, real_hex, "must not store legacy key in plaintext");

        // Следующий старт под тем же паролем даёт тот же адрес.
        let dk2 = dk_for(&p, PW_A);
        let (again, _) = load_or_migrate_identity(&p, dk2.as_ref()).unwrap();
        assert_eq!(
            again.verifying_key().to_bytes(),
            real.verifying_key().to_bytes(),
            "second load under same password must return the original legacy address"
        );

        let _ = std::fs::remove_file(&p);
    }
}

fn extract_header(raw: &[u8], name: &str) -> Option<String> {
    let text = String::from_utf8_lossy(raw);
    for line in text.lines() {
        if line.is_empty() {
            break;
        }
        if let Some(val) = line.strip_prefix(name) {
            return Some(val.trim().to_string());
        }
    }
    None
}
