//! yggmail-mobile — UniFFI bindings for Android/iOS.

uniffi::include_scaffolding!("yggmail_mobile");

use std::collections::HashSet;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, Once};
use std::time::Duration;
use tokio::runtime::Runtime;
use tokio::sync::broadcast;

use rand::rngs::OsRng;
use sha2::{Digest, Sha256};

use yggdrasil::config::Config as YggdrasilConfig;
use yggdrasil::core::Core;
use yggmail::address::create_address;
use yggmail::core_conn::CoreConn;
use yggmail::storage::SqliteStorage;
use yggmail::ymp::YmpSession;

// ── tracing ────────────────────────────────────────────────────────────

fn init_tracing() {
    static INIT: Once = Once::new();
    INIT.call_once(|| {
        use tracing_subscriber::layer::SubscriberExt;
        use tracing_subscriber::util::SubscriberInitExt;
        use tracing_subscriber::EnvFilter;
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
            if let Some(h) = node.receiver_handle.as_ref() { h.abort(); }
            if let Some(h) = node.smtp_handle.as_ref() { h.abort(); }
            if let Some(h) = node.imap_handle.as_ref() { h.abort(); }
            let _ = node.stop_tx.send(());
        }
        *guard = None;
    }

    pub fn send_mail(&self, to: String, subject: String, body: String) -> Result<(), YggmailError> {
        // Sanitize to prevent header injection
        let safe_subject = subject.replace('\r', "").replace('\n', " ");
        let safe_body = body.replace('\r', "").replace('\n', " ");

        let state = self.state.lock().unwrap();
        let node = state.as_ref().ok_or(YggmailError::Runtime("not started".into()))?;

        let mail = format!("To: {}\r\nSubject: {}\r\n\r\n{}", to, safe_subject, safe_body);
        let id = node.storage.mail_insert("Outbox", mail.as_bytes())
            .map_err(|e| YggmailError::Runtime(e.to_string()))?;

        let dest = yggmail::address::parse_address(&to)
            .ok_or_else(|| YggmailError::Config(format!("invalid address: {}", to)))?;

        let from = create_address(node.core.public_key());
        node.storage.queue_insert(&hex::encode(dest), "Outbox", id, &from, &to)
            .map_err(|e| YggmailError::Runtime(e.to_string()))?;

        // Enqueue-only: the background sender task handles delivery (with the
        // readiness-gate). send_mail must NOT block_on ymp.send() — on Android
        // this runs on the single-threaded serviceHandler, and a cold-start
        // block_on would freeze the entire YggmailService (~75s stall).
        drop(state);
        Ok(())
    }

    pub fn get_inbox_count(&self) -> u32 {
        self.state.lock().unwrap().as_ref()
            .and_then(|n| n.storage.mail_count("INBOX").ok())
            .unwrap_or(0)
    }

    pub fn get_mail_summaries(&self, page: u32, page_size: u32) -> Vec<MailSummary> {
        let state = self.state.lock().unwrap();
        let node = match state.as_ref() { Some(n) => n, None => return vec![] };
        let ids = node.storage.mail_list("INBOX").unwrap_or_default();
        ids.iter().skip((page * page_size) as usize).take(page_size as usize)
            .filter_map(|id| {
                node.storage.mail_get("INBOX", *id).ok().flatten().map(|m| MailSummary {
                    id: m.id,
                    from: extract_header(&m.mail, "From:").unwrap_or_default(),
                    subject: extract_header(&m.mail, "Subject:").unwrap_or_default(),
                    date_secs: m.date as u64,
                    seen: m.seen,
                    size: m.mail.len() as u32,
                })
            }).collect()
    }

    pub fn get_mail_raw(&self, mailbox: String, id: u32) -> Vec<u8> {
        self.state.lock().unwrap().as_ref()
            .and_then(|n| n.storage.mail_get(&mailbox, id).ok().flatten())
            .map(|m| m.mail).unwrap_or_default()
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
                address: String::new(), public_key: String::new(),
                inbox_count: 0, peers_connected: 0, routing_entries: 0,
            },
        }
    }

    // ── SMTP/IMAP server control ─────────────────────────────────────────

    pub fn start_smtp(&self, port: u16, password_hash: String) -> Result<(), YggmailError> {
        let mut state = self.state.lock().unwrap();
        let node = state.as_mut().ok_or(YggmailError::Runtime("not started".into()))?;
        let storage = node.storage.clone();
        let local_key = *node.core.public_key();
        let pw = if password_hash.is_empty() { None } else { Some(password_hash) };

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
        let node = state.as_mut().ok_or(YggmailError::Runtime("not started".into()))?;
        let storage = node.storage.clone();
        let local_key = *node.core.public_key();
        let pw = if password_hash.is_empty() { None } else { Some(password_hash) };

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
        let node = match state.as_ref() { Some(n) => n, None => return };

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
        let node = match state.as_ref() { Some(n) => n, None => return "[]".to_string() };

        self.runtime.block_on(async {
            let peers = node.core.get_peers().await;
            let list: Vec<serde_json::Value> = peers.iter().map(|p| {
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
            }).collect();
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
            Some(node) => std::fs::metadata(&node.db_path).map(|m| m.len()).unwrap_or(0),
            None => 0,
        };
        let max_mb = self.max_message_size.load(Ordering::Relaxed);
        let db_size_mb = db_size as f64 / (1024.0 * 1024.0);
        serde_json::json!({
            "dbSizeMB": (db_size_mb * 100.0).round() / 100.0,
            "maxSizeMB": max_mb,
        }).to_string()
    }

    pub fn get_outbound_queue_count(&self) -> u32 {
        let state = self.state.lock().unwrap();
        let node = match state.as_ref() { Some(n) => n, None => return 0 };
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
        let node = match state.as_ref() { Some(n) => n, None => return };
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

// ── helpers ──────────────────────────────────────────────────────────────

fn parse_signing_key(hex_key: &str) -> Result<ed25519_dalek::SigningKey, YggmailError> {
    let bytes = hex::decode(hex_key).map_err(|e| YggmailError::Config(e.to_string()))?;
    if bytes.len() != 64 {
        return Err(YggmailError::Config(format!("key must be 64 bytes, got {}", bytes.len())));
    }
    let mut arr = [0u8; 64];
    arr.copy_from_slice(&bytes);
    ed25519_dalek::SigningKey::from_keypair_bytes(&arr)
        .map_err(|e| YggmailError::Config(e.to_string()))
}

/// Load the node's Ed25519 identity from the DB, persisting it to `mobile_config`.
///
/// When `dk` (the at-rest data key) is `Some`, the stored value in `mobile_config`
/// is the hex encoding of an XChaCha20-Poly1305 encrypted blob wrapping the
/// plaintext `private_key_hex`.  Reading: hex-decode → if the bytes start with
/// `0x01` → decrypt to recover `private_key_hex`; else treat the raw value as
/// the legacy plaintext hex (never starts with 0x01 because it is 128 lowercase
/// hex chars whose first byte is always a digit or a–f).  Writing: always store
/// the encrypted form when `dk` is `Some`.
///
/// Order (precedence matters — see below):
/// 1. **Migration 1.8→1.9 wins.** If the legacy Go `config.private_key` exists, it IS the
///    user's real identity (yggmail_old stored it as 64-byte-keypair hex, the same layout
///    as `to_keypair_bytes`). It MUST take precedence over `mobile_config`, because an
///    older/buggy 1.9 build could have minted a *fresh random* key into `mobile_config`
///    that would otherwise permanently shadow the real `@yggmail` address. We adopt the
///    legacy key and (re)write it to `mobile_config`, healing any such poisoning.
/// 2. No legacy key (a genuine fresh 1.9 install — `SqliteStorage` never creates `config`):
///    reuse the key already persisted in `mobile_config`.
/// 3. Truly fresh: mint a new key and persist it.
///
/// Only reads `config` — never mutates the legacy table.
fn load_or_migrate_identity(
    db_path: &str,
    dk: Option<&[u8; 32]>,
) -> Result<(ed25519_dalek::SigningKey, String), YggmailError> {
    let conn = rusqlite::Connection::open(db_path).map_err(|e| YggmailError::Io(e.to_string()))?;
    conn.execute_batch("CREATE TABLE IF NOT EXISTS mobile_config (key TEXT PRIMARY KEY, value TEXT);")
        .map_err(|e| YggmailError::Io(e.to_string()))?;

    // (1) Legacy 1.8 key present → it is authoritative. Adopt + heal mobile_config.
    // Legacy `config` always stores plaintext hex — no decryption needed here.
    if let Some((key, hex_key)) = conn
        .query_row("SELECT value FROM config WHERE key = 'private_key'", [], |r| {
            r.get::<_, String>(0)
        })
        .ok()
        .and_then(|h| parse_signing_key(&h).ok().map(|k| (k, h)))
    {
        persist_identity(&conn, &hex_key, dk)?;
        tracing::info!("mobile: adopted legacy (1.8) identity from `config` — @yggmail address preserved");
        return Ok((key, hex_key));
    }

    // (2) No legacy key: reuse the persisted 1.9 identity.
    if let Some(stored_value) = conn
        .query_row("SELECT value FROM mobile_config WHERE key = 'private_key'", [], |r| {
            r.get::<_, String>(0)
        })
        .ok()
    {
        let plaintext_hex = decrypt_stored_key(&stored_value, dk)?;
        if let Some(pair) = parse_signing_key(&plaintext_hex).ok().map(|k| (k, plaintext_hex.clone())) {
            // Re-persist to ensure the stored form matches the current encryption mode
            // (e.g., upgrade from plaintext to encrypted, or key rotation).
            persist_identity(&conn, &plaintext_hex, dk)?;
            return Ok(pair);
        }
    }

    // (3) Truly fresh install: generate and persist.
    let key = ed25519_dalek::SigningKey::generate(&mut OsRng);
    let hex_key = hex::encode(key.to_keypair_bytes());
    persist_identity(&conn, &hex_key, dk)?;
    Ok((key, hex_key))
}

/// Decode a value stored in `mobile_config` for `private_key`.
///
/// Disambiguation rule (discriminate by LENGTH, not just the first byte):
/// a legacy plaintext keypair hex-decodes to exactly 64 bytes, whereas an
/// encrypted blob is `[0x01][nonce24][ct][tag16]` and is never 64 bytes.
/// A legacy keypair's first byte is random, so it is `0x01` for ~1/256 of
/// users — checking the version byte ALONE would misread those as encrypted
/// and brick key loading. So we only treat a value as encrypted when its
/// decoded length is not 64 AND the version byte is set.
/// - hex-decode → if `len != 64` and first byte is `0x01`, decrypt with `dk`
///   (error if `dk` is absent).
/// - Otherwise, the stored string IS the plaintext hex key (legacy unencrypted).
fn decrypt_stored_key(stored_value: &str, dk: Option<&[u8; 32]>) -> Result<String, YggmailError> {
    use yggmail::storage::crypt::{VERSION_XCHACHA, aead_decrypt};
    // Attempt hex-decode; if it fails the value is definitely not an encrypted blob.
    if let Ok(bytes) = hex::decode(stored_value) {
        // 64 bytes = legacy Ed25519 keypair; an encrypted blob is never 64 bytes.
        if bytes.len() != 64 && bytes.first() == Some(&VERSION_XCHACHA) {
            // Encrypted blob.
            let dk = dk.ok_or_else(|| YggmailError::Config(
                "private_key is encrypted but no data key available (wrong password?)".into(),
            ))?;
            let plaintext = aead_decrypt(dk, &bytes).ok_or_else(|| YggmailError::Config(
                "private_key decryption failed — wrong key or corrupted blob".into(),
            ))?;
            return String::from_utf8(plaintext)
                .map_err(|_| YggmailError::Config("decrypted private_key is not valid UTF-8".into()));
        }
    }
    // Legacy plaintext: the stored value IS the hex key directly.
    Ok(stored_value.to_string())
}

/// Persist the identity key to `mobile_config` (idempotent overwrite).
///
/// When `dk` is `Some`, the plaintext `hex_key` is encrypted before storage
/// so the key never appears in plaintext in the DB.
fn persist_identity(
    conn: &rusqlite::Connection,
    hex_key: &str,
    dk: Option<&[u8; 32]>,
) -> Result<(), YggmailError> {
    use yggmail::storage::crypt::aead_encrypt;
    let stored_value: String = if let Some(dk) = dk {
        let encrypted_blob = aead_encrypt(dk, hex_key.as_bytes());
        hex::encode(encrypted_blob)
    } else {
        hex_key.to_string()
    };
    conn.execute(
        "INSERT OR REPLACE INTO mobile_config (key, value) VALUES ('private_key', ?1)",
        rusqlite::params![stored_value],
    )
    .map_err(|e| YggmailError::Io(e.to_string()))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_db(tag: &str) -> String {
        let p = std::env::temp_dir().join(format!("yggmail-mobile-{}-{}.db", std::process::id(), tag));
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
            .query_row("SELECT value FROM mobile_config WHERE key = 'private_key'", [], |r| r.get(0))
            .unwrap();
        assert_eq!(persisted, hex_key);

        // Idempotent: second call returns the same key.
        let (again, _) = load_or_migrate_identity(&p, None).unwrap();
        assert_eq!(again.verifying_key().to_bytes(), key.verifying_key().to_bytes());

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
            .query_row("SELECT value FROM mobile_config WHERE key = 'private_key'", [], |r| r.get(0))
            .unwrap();
        assert_eq!(persisted, real_hex, "poisoned mobile_config must be overwritten with the real key");

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
}

fn extract_header(raw: &[u8], name: &str) -> Option<String> {
    let text = String::from_utf8_lossy(raw);
    for line in text.lines() {
        if line.is_empty() { break; }
        if let Some(val) = line.strip_prefix(name) {
            return Some(val.trim().to_string());
        }
    }
    None
}
