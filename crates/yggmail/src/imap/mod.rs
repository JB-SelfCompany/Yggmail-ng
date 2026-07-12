//! IMAP server — delegates to imap-rs library (RFC 3501 compliant).
//!
//! Replaces the 760-line hand-written server with ~130 lines
//! implementing Backend + UserSession traits on top of SqliteStorage.

use std::sync::Arc;
use tokio::sync::broadcast;

use imap_core::error::ImapError;
use imap_core::fetch::{FetchOptions, SectionSpecifier};
use imap_core::search::SearchCriteria;
use imap_core::select::*;
use imap_core::store::{StoreOp, StoreFlags};
use imap_core::types::{Flag, MailboxAttr, SeqSet};
use imap_server::backend::{Backend, ConnInfo, FetchedMessage, StoredMessage, UserSession};
use imap_server::Server;
use sha2::Digest;

use crate::address::parse_address;
use crate::storage::SqliteStorage;

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

const PROTECTED: &[&str] = &["INBOX", "Outbox", "Sent"];

// ── Backend (session factory) ────────────────────────────────────

pub struct YggmailBackend {
    storage: Arc<SqliteStorage>,
    local_key: [u8; 32],
    password_hash: Option<String>,
    notify_tx: broadcast::Sender<()>,
}

#[async_trait::async_trait]
impl Backend for YggmailBackend {
    async fn login(
        &self, _conn: &ConnInfo, username: &str, password: &str,
    ) -> Result<Box<dyn UserSession>, ImapError> {
        if let Some(ref hash) = self.password_hash {
            let computed = hex::encode(sha2::Sha256::digest(password.as_bytes()));
            if !ct_eq(&computed, hash) {
                return Err(ImapError::no("Login failed"));
            }
        }
        let key_ok = parse_address(username).map(|k| k == self.local_key).unwrap_or(false)
            || hex::decode(username).map(|b| b == self.local_key).unwrap_or(false);
        if !key_ok {
            return Err(ImapError::no("Login failed"));
        }
        Ok(Box::new(YggmailSession {
            storage: self.storage.clone(),
            selected: None,
            notify_rx: self.notify_tx.subscribe(),
        }))
    }
}

// ── UserSession (per-connection state) ───────────────────────────

struct YggmailSession {
    storage: Arc<SqliteStorage>,
    selected: Option<String>,
    notify_rx: broadcast::Receiver<()>,
}

#[async_trait::async_trait]
impl UserSession for YggmailSession {
    async fn list(&mut self, _reference: &str, _pattern: &str) -> Result<Vec<ListData>, ImapError> {
        let mbs = self.storage.mailbox_list()
            .map_err(|e| ImapError::Internal(Box::new(e)))?;
        Ok(mbs.into_iter().map(|name| ListData {
            attrs: vec![MailboxAttr("\\HasNoChildren".into())],
            delimiter: "/".into(),
            name,
            child_info: None,
            old_name: None,
            status: None,
        }).collect())
    }

    async fn subscribe(&mut self, mailbox: &str) -> Result<(), ImapError> {
        self.storage.mailbox_subscribe(mailbox, true).map_err(|e| ImapError::Internal(Box::new(e)))
    }

    async fn unsubscribe(&mut self, mailbox: &str) -> Result<(), ImapError> {
        self.storage.mailbox_subscribe(mailbox, false).map_err(|e| ImapError::Internal(Box::new(e)))
    }

    async fn create(&mut self, mailbox: &str) -> Result<(), ImapError> {
        self.storage.mailbox_create(mailbox).map_err(|e| ImapError::no(e.to_string()))
    }

    async fn delete(&mut self, mailbox: &str) -> Result<(), ImapError> {
        if PROTECTED.contains(&mailbox) {
            return Err(ImapError::no("Cannot delete protected mailbox"));
        }
        self.storage.mailbox_delete(mailbox).map_err(|e| ImapError::no(e.to_string()))
    }

    async fn rename(&mut self, from: &str, to: &str) -> Result<(), ImapError> {
        if PROTECTED.contains(&from) {
            return Err(ImapError::no("Cannot rename protected mailbox"));
        }
        self.storage.mailbox_rename(from, to).map_err(|e| ImapError::no(e.to_string()))
    }

    async fn status(&mut self, mailbox: &str) -> Result<StatusData, ImapError> {
        let count = self.storage.mail_count(mailbox).map_err(|e| ImapError::Internal(Box::new(e)))?;
        Ok(StatusData {
            messages: Some(count),
            recent: Some(0),
            uid_next: None,
            uid_validity: None,
            unseen: None,
            size: None,
            deleted: None,
            highest_mod_seq: None,
        })
    }

    async fn select(&mut self, mailbox: &str, read_only: bool) -> Result<SelectData, ImapError> {
        let count = self.storage.mail_count(mailbox).map_err(|e| ImapError::Internal(Box::new(e)))?;
        let unseen = self.storage.mail_unseen_count(mailbox).map_err(|e| ImapError::Internal(Box::new(e)))?;
        let ids = self.storage.mail_list(mailbox).map_err(|e| ImapError::Internal(Box::new(e)))?;
        let uid_validity = self.storage.mail_uid_validity().unwrap_or(1);
        let uid_next = self.storage.mail_uid_next(mailbox).unwrap_or(1);
        self.selected = Some(mailbox.to_string());
        Ok(SelectData {
            flags: vec![Flag::seen(), Flag::answered(), Flag::flagged(), Flag::deleted()],
            exists: count,
            recent: 0,
            unseen,
            uid_validity,
            uid_next,
            permanent_flags: vec![Flag::seen(), Flag::answered(), Flag::flagged(), Flag::deleted()],
            read_only,
            first_unseen_seq_num: None,
            list: None,
            highest_mod_seq: None,
        })
    }

    async fn close(&mut self) -> Result<(), ImapError> {
        self.selected = None;
        Ok(())
    }

    async fn fetch(
        &mut self, uid: bool, seq_set: &SeqSet, options: &FetchOptions,
    ) -> Result<Vec<FetchedMessage>, ImapError> {
        let mb = self.selected.as_ref()
            .ok_or_else(|| ImapError::bad("No mailbox selected"))?;
        let ids = self.storage.mail_list(mb).map_err(|e| ImapError::Internal(Box::new(e)))?;

        let has_body = !options.body_sections.is_empty();

        let mut result = Vec::new();
        for (i, &id) in ids.iter().enumerate() {
            let seq = (i + 1) as u32;
            let matches = if uid { seq_set.contains(id) } else { seq_set.contains(seq) };
            if !matches { continue; }

            if let Some(mail) = self.storage.mail_get(mb, id)
                .map_err(|e| ImapError::Internal(Box::new(e)))?
            {
                let body = if has_body {
                    // Server writes msg.body as literal for each body section.
                    // Filter based on section specifier.
                    if let Some(bs) = options.body_sections.first() {
                        match &bs.specifier {
                            SectionSpecifier::HeaderFields(fields) =>
                                extract_headers(&mail.mail, fields),
                            SectionSpecifier::Header =>
                                extract_header_end(&mail.mail),
                            SectionSpecifier::None =>
                                mail.mail.clone(),
                            _ => mail.mail.clone(),
                        }
                    } else { mail.mail.clone() }
                } else { Vec::new() };

                result.push(FetchedMessage {
                    seq, uid: mail.id,
                    flags: build_flags(&mail),
                    internal_date: format_date(mail.date),
                    rfc822_size: mail.mail.len() as u32,
                    body,
                });
            }
        }
        Ok(result)
    }

    async fn store(
        &mut self, uid: bool, seq_set: &SeqSet, flags: &StoreFlags,
    ) -> Result<Vec<StoredMessage>, ImapError> {
        let mb = self.selected.as_ref()
            .ok_or_else(|| ImapError::bad("No mailbox selected"))?;
        let ids = self.storage.mail_list(mb).map_err(|e| ImapError::Internal(Box::new(e)))?;
        let req: Vec<Flag> = flags.flags.iter().map(|s| Flag(s.clone())).collect();
        let mut result = Vec::new();

        for (i, &id) in ids.iter().enumerate() {
            let seq = (i + 1) as u32;
            let matches = if uid { seq_set.contains(id) } else { seq_set.contains(seq) };
            if !matches { continue; }

            if let Some(mail) = self.storage.mail_get(mb, id)
                .map_err(|e| ImapError::Internal(Box::new(e)))?
            {
                let mut f = build_flags(&mail);
                match flags.op {
                    StoreOp::Add | StoreOp::AddSilent =>
                        for fl in &req { if !f.iter().any(|x| x.0 == fl.0) { f.push(fl.clone()); } },
                    StoreOp::Remove | StoreOp::RemoveSilent =>
                        f.retain(|fl| !req.iter().any(|r| r.0 == fl.0)),
                    StoreOp::Replace | StoreOp::ReplaceSilent =>
                        f = req.clone(),
                }
                let _ = self.storage.mail_update_flags(mb, id,
                    f.iter().any(|x| x.0 == "\\Seen"),
                    f.iter().any(|x| x.0 == "\\Answered"),
                    f.iter().any(|x| x.0 == "\\Flagged"),
                    f.iter().any(|x| x.0 == "\\Deleted"),
                );
                result.push(StoredMessage { seq, uid: id, flags: f });
            }
        }
        Ok(result)
    }

    async fn search(&mut self, _uid: bool, _criteria: &SearchCriteria) -> Result<Vec<u32>, ImapError> {
        let mb = self.selected.as_ref()
            .ok_or_else(|| ImapError::bad("No mailbox selected"))?;
        let ids = self.storage.mail_list(mb).map_err(|e| ImapError::Internal(Box::new(e)))?;
        Ok(ids)
    }

    async fn copy(
        &mut self, uid: bool, seq_set: &SeqSet, dest: &str,
    ) -> Result<CopyData, ImapError> {
        let mb = self.selected.as_ref()
            .ok_or_else(|| ImapError::bad("No mailbox selected"))?;
        let ids = self.storage.mail_list(mb).map_err(|e| ImapError::Internal(Box::new(e)))?;
        let uid_validity = self.storage.mail_uid_validity().unwrap_or(1);
        let mut source_uids = Vec::new();
        let mut dest_uids = Vec::new();

        for (i, &id) in ids.iter().enumerate() {
            let seq = (i + 1) as u32;
            let matches = if uid { seq_set.contains(id) } else { seq_set.contains(seq) };
            if !matches { continue; }

            if let Some(mail) = self.storage.mail_get(mb, id)
                .map_err(|e| ImapError::Internal(Box::new(e)))?
            {
                match self.storage.mail_insert(dest, &mail.mail) {
                    Ok(new_id) => { source_uids.push(id); dest_uids.push(new_id); }
                    Err(e) => return Err(ImapError::no(e.to_string())),
                }
            }
        }
        Ok(CopyData { uid_validity, source_uids, dest_uids })
    }

    async fn expunge(&mut self, _uid_set: Option<&SeqSet>) -> Result<Vec<u32>, ImapError> {
        let mb = self.selected.as_ref()
            .ok_or_else(|| ImapError::bad("No mailbox selected"))?;
        self.storage.mail_expunge(mb).map_err(|e| ImapError::Internal(Box::new(e)))?;
        Ok(Vec::new())
    }

    async fn append(
        &mut self, mailbox: &str, data: Vec<u8>, flags: Option<Vec<Flag>>, _date: Option<String>,
    ) -> Result<AppendData, ImapError> {
        let uid = self.storage.mail_insert(mailbox, &data)
            .map_err(|e| ImapError::no(e.to_string()))?;

        // Apply flags if provided (e.g. \Seen from draft)
        if let Some(ref fl) = flags {
            let _ = self.storage.mail_update_flags(mailbox, uid,
                fl.iter().any(|f| f.0 == "\\Seen"),
                fl.iter().any(|f| f.0 == "\\Answered"),
                fl.iter().any(|f| f.0 == "\\Flagged"),
                fl.iter().any(|f| f.0 == "\\Deleted"),
            );
        }

        let uid_validity = self.storage.mail_uid_validity().unwrap_or(1);
        Ok(AppendData { uid_validity: Some(uid_validity), uid: Some(uid) })
    }

    async fn poll(&mut self) -> Result<(), ImapError> {
        // Drain all pending YMP notifications (non-blocking).
        // Called every second during IDLE and after each command.
        while self.notify_rx.try_recv().is_ok() {}
        Ok(())
    }

    async fn current_message_count(&mut self) -> Option<u32> {
        // Live count of the SELECTED mailbox — drives IDLE EXISTS push so
        // DeltaChat sees YMP-delivered mail without reconnecting/restarting.
        let mb = self.selected.as_ref()?;
        self.storage.mail_count(mb).ok()
    }
}

// ── Public API (SAME signature as before) ────────────────────────

pub async fn serve(
    port: u16, storage: Arc<SqliteStorage>,
    local_key: [u8; 32], password_hash: Option<String>,
    notify_tx: broadcast::Sender<()>,
) -> Result<(), Box<dyn std::error::Error>> {
    if password_hash.is_none() {
        tracing::warn!(
            "IMAP: starting WITHOUT authentication — any local app on this device can access mail"
        );
    }
    let backend = YggmailBackend { storage, local_key, password_hash, notify_tx };
    let options = imap_server::Options {
        // Safe: IMAP binds 127.0.0.1 only (localhost); no TLS needed on the loopback interface.
        insecure_auth: true,
        ..Default::default()
    };
    Server::new(backend, options)
        .listen(format!("127.0.0.1:{}", port))
        .await
}

/// Handle a single IMAP connection (used by the e2e test; production uses [`serve`]).
///
/// Thin wrapper over `imap_server::Server::serve_conn`, mirroring the SMTP-side
/// `handle_conn` so a test can drive exactly one accepted stream. Pre-existing gap:
/// the IMAP path migrated to `imap_server::Server` (which self-binds in `serve`)
/// but the e2e test still calls `imap::handle_conn` per-connection.
pub async fn handle_conn(
    stream: tokio::net::TcpStream,
    storage: Arc<SqliteStorage>,
    local_key: [u8; 32],
    password_hash: Option<String>,
    notify_tx: broadcast::Sender<()>,
) {
    let peer_addr = stream.peer_addr().map(|a| a.to_string()).unwrap_or_default();
    let backend: Arc<dyn Backend> = Arc::new(YggmailBackend {
        storage, local_key, password_hash, notify_tx,
    });
    let (reader, writer) = stream.into_split();
    Server::serve_conn(backend, reader, writer, peer_addr, true).await;
}

// ── helpers ──────────────────────────────────────────────────────

fn build_flags(mail: &crate::storage::MailEntry) -> Vec<Flag> {
    let mut flags = Vec::new();
    if mail.seen { flags.push(Flag::seen()); }
    if mail.answered { flags.push(Flag::answered()); }
    if mail.flagged { flags.push(Flag::flagged()); }
    if mail.deleted { flags.push(Flag::deleted()); }
    flags
}

fn format_date(epoch_secs: i64) -> String {
    let s = epoch_secs.max(0) as u64;
    let days = s / 86400;
    let sod = s % 86400;
    let (y, m, d) = epoch_days_to_ymd(days);
    let (h, mi, sec) = (sod / 3600, (sod % 3600) / 60, sod % 60);
    let mn = ["Jan","Feb","Mar","Apr","May","Jun","Jul","Aug","Sep","Oct","Nov","Dec"];
    format!("{:02}-{}-{} {:02}:{:02}:{:02} +0000", d, mn[(m-1) as usize], y, h, mi, sec)
}

fn epoch_days_to_ymd(mut days: u64) -> (u64, u64, u64) {
    let mut year = 1970u64;
    loop {
        let diy = if is_leap(year) { 366 } else { 365 };
        if days < diy { break; }
        days -= diy;
        year += 1;
    }
    let dim = [31, if is_leap(year) { 29 } else { 28 }, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];
    let mut month = 1u64;
    for &m in &dim {
        if days < m { break; }
        days -= m;
        month += 1;
    }
    (year, month, days + 1)
}

fn is_leap(y: u64) -> bool { (y % 4 == 0 && y % 100 != 0) || y % 400 == 0 }

/// Extract all headers (up to and including the blank line separator).
fn extract_header_end(raw: &[u8]) -> Vec<u8> {
    for i in 0..raw.len().saturating_sub(3) {
        if raw[i] == b'\r' && raw[i+1] == b'\n' && raw[i+2] == b'\r' && raw[i+3] == b'\n' {
            return raw[..i+4].to_vec();
        }
    }
    raw.to_vec()
}

/// Extract only the requested headers from raw RFC 5322 mail.
/// Handles folded continuation lines (RFC 5322 §2.2.3).
fn extract_headers(raw: &[u8], field_names: &[String]) -> Vec<u8> {
    let text = String::from_utf8_lossy(raw);
    let mut result = Vec::new();
    let mut copying = false;
    for line in text.lines() {
        if line.is_empty() { break; }
        if line.starts_with(' ') || line.starts_with('\t') {
            if copying {
                result.extend_from_slice(line.as_bytes());
                result.extend_from_slice(b"\r\n");
            }
            continue;
        }
        copying = false;
        if let Some(colon) = line.find(':') {
            let name = line[..colon].trim();
            if field_names.iter().any(|f| f.eq_ignore_ascii_case(name)) {
                result.extend_from_slice(line.as_bytes());
                result.extend_from_slice(b"\r\n");
                copying = true;
            }
        }
    }
    if !result.is_empty() {
        result.extend_from_slice(b"\r\n");
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    // Verifies the IDLE EXISTS-push source of truth: current_message_count must
    // reflect the live INBOX count so the imap-rs IDLE loop can emit `* N EXISTS`
    // when YMP delivers mail — the fix for "hangs on Establishing connection
    // until Tyr restart" (DeltaChat never learned of new mail during IDLE).
    #[tokio::test]
    async fn current_message_count_tracks_selected_inbox() {
        let path = std::env::temp_dir()
            .join(format!("yggmail-idle-count-{}.db", std::process::id()));
        let path_str = path.to_str().unwrap();
        let _ = std::fs::remove_file(&path);

        let storage = Arc::new(SqliteStorage::open(path_str, None).unwrap());
        let (_tx, rx) = broadcast::channel::<()>(1);
        let mut session = YggmailSession {
            storage: storage.clone(),
            selected: Some("INBOX".to_string()),
            notify_rx: rx,
        };

        // Empty INBOX → 0.
        assert_eq!(session.current_message_count().await, Some(0));

        // After a delivery the count must grow — this is exactly what the IDLE
        // loop compares against its baseline to push EXISTS to the client.
        storage.mail_insert("INBOX", b"From: a@yggmail\r\n\r\nhi").unwrap();
        assert_eq!(session.current_message_count().await, Some(1));

        // No mailbox selected → None disables IDLE push.
        session.selected = None;
        assert_eq!(session.current_message_count().await, None);

        let _ = std::fs::remove_file(&path);
    }
}
