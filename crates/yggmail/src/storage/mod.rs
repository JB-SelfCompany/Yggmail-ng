//! SQLite storage layer — schema-compatible with yggmail_old.
//!
//! ponytail: writer channel skipped — rusqlite serializes writes internally.
//! Prepared statements cached at startup for all hot paths.

mod mails;
mod queue;
pub mod crypt;

pub use mails::MailEntry;
pub use queue::QueuedMail;

use rand::RngCore;
use rusqlite::Connection;
use std::sync::{Arc, Mutex, MutexGuard};
use tokio::sync::Notify;

/// Lock the shared SQLite connection, recovering from mutex poisoning.
///
/// The whole app shares one `Mutex<Connection>`. With a plain `.lock().unwrap()`
/// a panic in ANY thread while the lock is held poisons the mutex, and every
/// later access panics too — storage stays dead until the process restarts
/// (a strong candidate for the "connection only works after restarting Tyr"
/// symptom). Recovering the guard via `into_inner()` keeps storage alive; the
/// error log ensures the original panic is still surfaced rather than masked.
pub(crate) fn lock_db(db: &Mutex<Connection>) -> MutexGuard<'_, Connection> {
    db.lock().unwrap_or_else(|poisoned| {
        tracing::error!("storage: DB mutex was poisoned by a prior panic; recovering connection");
        poisoned.into_inner()
    })
}

/// SQLite-backed mail storage.
pub struct SqliteStorage {
    db: Arc<Mutex<Connection>>,
    queue_notify: Arc<Notify>,
    /// 32-byte data key used for XChaCha20-Poly1305 encryption of mail bodies.
    /// `None` when no password is set (plaintext / legacy mode).
    /// Exposed `pub` so that `yggmail-mobile` can pass it to identity loading.
    /// MUST NOT be logged or serialised.
    pub at_rest_key: Option<[u8; 32]>,
}

impl SqliteStorage {
    /// Open (or create) the database at `path`, running all schema migrations.
    ///
    /// `password_hash` — the SHA-256 hex of the user's IMAP/SMTP password, or
    /// `None` to operate in plaintext mode (unchanged behaviour for development
    /// and the desktop binary which has no password yet).
    ///
    /// When a password is supplied:
    /// 1. A per-DB random 16-byte `salt` is generated on first open and stored
    ///    plaintext in the `at_rest` table.
    /// 2. `KEK = SHA-256("yggmail-at-rest-v1" || salt || password_hash_hex)`.
    /// 3. On first open, a 32-byte data key (`DK`) is generated and stored as
    ///    `aead_encrypt(KEK, DK)` in `at_rest.wrapped_dk`.
    /// 4. On subsequent opens, `wrapped_dk` is unwrapped with KEK.
    ///    **If unwrapping fails, the call returns `Err`** — the wrong password
    ///    was supplied; a new DK is never generated (that would orphan all data).
    /// 5. Existing plaintext mail rows are migrated to encrypted blobs in one
    ///    idempotent pass (rows whose blob already starts with `0x01` are skipped).
    pub fn open(path: &str, password_hash: Option<&str>) -> Result<Self, rusqlite::Error> {
        let conn = Connection::open(path)?;
        conn.execute_batch("PRAGMA foreign_keys = ON;")?;
        conn.execute_batch(mails::SCHEMA)?;
        conn.execute_batch(queue::SCHEMA)?;
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS mailboxes (
                mailbox    TEXT NOT NULL DEFAULT('INBOX') PRIMARY KEY,
                subscribed BOOLEAN NOT NULL DEFAULT 1,
                uid_next   INTEGER NOT NULL DEFAULT 1
            );",
        )?;
        // Key-material table for at-rest encryption.
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS at_rest (
                k TEXT PRIMARY KEY,
                v BLOB NOT NULL
            );",
        )?;
        // Ensure protected mailboxes exist
        for mb in &["INBOX", "Outbox", "Sent"] {
            conn.execute(
                "INSERT OR IGNORE INTO mailboxes (mailbox) VALUES (?1)",
                [mb],
            )?;
        }
        // Migrate older DBs: add the monotonic UID counter if missing, then lift
        // each mailbox's counter above any id already present so UIDs are never
        // reused (Delta Chat ignores mail whose UID is below its watermark).
        let _ = conn.execute("ALTER TABLE mailboxes ADD COLUMN uid_next INTEGER NOT NULL DEFAULT 1", []);
        conn.execute(
            "UPDATE mailboxes SET uid_next = MAX(
                 uid_next,
                 COALESCE((SELECT MAX(id) + 1 FROM mails WHERE mails.mailbox = mailboxes.mailbox), 1)
             )",
            [],
        )?;
        // Reclaim queue rows leaked by the old move-first path: the queue only
        // ever holds Outbox entries, so anything else is a FK-cascade artifact
        // ("Sent", id) that would otherwise be polled forever.
        conn.execute("DELETE FROM queue WHERE mailbox <> 'Outbox'", [])?;

        // ── At-rest key setup ─────────────────────────────────────────────
        let at_rest_key = match password_hash {
            Some(h) if !h.is_empty() => {
                // (1) Get-or-create the per-DB salt.
                let salt: Vec<u8> = match conn.query_row(
                    "SELECT v FROM at_rest WHERE k = 'salt'",
                    [],
                    |row| row.get::<_, Vec<u8>>(0),
                ) {
                    Ok(existing) => existing,
                    Err(rusqlite::Error::QueryReturnedNoRows) => {
                        let mut s = [0u8; 16];
                        rand::thread_rng().fill_bytes(&mut s);
                        conn.execute(
                            "INSERT INTO at_rest (k, v) VALUES ('salt', ?1)",
                            rusqlite::params![s.as_ref()],
                        )?;
                        s.to_vec()
                    }
                    Err(e) => return Err(e),
                };

                // (2) Derive KEK.
                let kek = crypt::derive_kek(h, &salt);

                // (3) Get or create the wrapped data key.
                let dk: [u8; 32] = match conn.query_row(
                    "SELECT v FROM at_rest WHERE k = 'wrapped_dk'",
                    [],
                    |row| row.get::<_, Vec<u8>>(0),
                ) {
                    Ok(wrapped) => {
                        // Unwrap: wrong password → hard error, never regenerate.
                        let dk_bytes = crypt::aead_decrypt(&kek, &wrapped)
                            .ok_or_else(|| rusqlite::Error::InvalidParameterName(
                                "at-rest: wrong password or corrupted wrapped_dk — cannot decrypt data key".into(),
                            ))?;
                        if dk_bytes.len() != 32 {
                            return Err(rusqlite::Error::InvalidParameterName(
                                "at-rest: wrapped_dk decrypted to wrong length".into(),
                            ));
                        }
                        let mut arr = [0u8; 32];
                        arr.copy_from_slice(&dk_bytes);
                        arr
                    }
                    Err(rusqlite::Error::QueryReturnedNoRows) => {
                        // First encrypted open: mint a fresh data key and wrap it.
                        let mut dk = [0u8; 32];
                        rand::thread_rng().fill_bytes(&mut dk);
                        let wrapped = crypt::aead_encrypt(&kek, &dk);
                        conn.execute(
                            "INSERT INTO at_rest (k, v) VALUES ('wrapped_dk', ?1)",
                            rusqlite::params![wrapped],
                        )?;
                        dk
                    }
                    Err(e) => return Err(e),
                };

                Some(dk)
            }
            _ => None,
        };

        let storage = Self {
            db: Arc::new(Mutex::new(conn)),
            queue_notify: Arc::new(Notify::new()),
            at_rest_key,
        };

        // (5) One-time migration: encrypt any plaintext mail rows.
        if let Some(ref dk) = storage.at_rest_key {
            storage.migrate_plaintext_mails(dk)?;
        }

        Ok(storage)
    }

    /// Re-wrap the data key under a new password without re-encrypting any mail.
    ///
    /// Called from `set_password` after the password hash is updated.  If
    /// `at_rest_key` is `None` (plaintext mode), this is a no-op.
    pub fn rewrap_data_key(&self, new_password_hash: &str) -> Result<(), rusqlite::Error> {
        let dk = match self.at_rest_key {
            Some(ref k) => k,
            None => return Ok(()),
        };
        let conn = lock_db(&self.db);
        let salt: Vec<u8> = conn.query_row(
            "SELECT v FROM at_rest WHERE k = 'salt'",
            [],
            |row| row.get::<_, Vec<u8>>(0),
        )?;
        let new_kek = crypt::derive_kek(new_password_hash, &salt);
        let new_wrapped = crypt::aead_encrypt(&new_kek, dk);
        conn.execute(
            "INSERT OR REPLACE INTO at_rest (k, v) VALUES ('wrapped_dk', ?1)",
            rusqlite::params![new_wrapped],
        )?;
        Ok(())
    }

    /// Idempotent one-time pass: encrypt all plaintext mail rows.
    ///
    /// Rows already starting with `0x01` are skipped (already encrypted).
    /// Kept simple — small mailboxes, runs once at open time.
    fn migrate_plaintext_mails(&self, dk: &[u8; 32]) -> Result<(), rusqlite::Error> {
        // Collect plaintext rows (blob does NOT start with 0x01).
        // We must not hold the lock across the update loop because mails::insert
        // also takes it; instead, collect all work first, then apply.
        let plaintext_rows: Vec<(String, u32, Vec<u8>)> = {
            let conn = lock_db(&self.db);
            let mut stmt = conn.prepare(
                "SELECT mailbox, id, mail FROM mails WHERE SUBSTR(mail, 1, 1) <> X'01'",
            )?;
            let rows: Vec<_> = stmt
                .query_map([], |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, u32>(1)?,
                        row.get::<_, Vec<u8>>(2)?,
                    ))
                })?
                .filter_map(|r| r.ok())
                .collect();
            rows
        };

        for (mailbox, id, raw) in plaintext_rows {
            let encrypted = crypt::aead_encrypt(dk, &raw);
            let conn = lock_db(&self.db);
            conn.execute(
                "UPDATE mails SET mail = ?1 WHERE mailbox = ?2 AND id = ?3",
                rusqlite::params![encrypted, mailbox, id],
            )?;
        }
        Ok(())
    }

    // ── mail operations (delegate to mails module) ──────────────────────

    pub fn mail_insert(&self, mailbox: &str, raw_rfc5322: &[u8]) -> Result<u32, rusqlite::Error> {
        mails::insert(&self.db, mailbox, raw_rfc5322, self.at_rest_key.as_ref())
    }

    /// Insert an inbound mail into INBOX, skipping exact duplicates.
    ///
    /// Returns `Ok(Some(id))` if stored, `Ok(None)` if it was a duplicate.
    ///
    /// Fingerprint = std SipHash of `(from_key ++ raw)`; a re-sent mail has
    /// identical bytes (same Message-ID) so it collides and is dropped.
    /// The `inbox_seen` table is the durable "already stored" marker — it
    /// persists across restarts so a reconnect-triggered re-delivery is also
    /// caught. No new crate dependency: `DefaultHasher` is `std` SipHash.
    pub fn mail_insert_inbox_dedup(
        &self,
        from_key: &[u8; 32],
        raw: &[u8],
    ) -> Result<Option<u32>, rusqlite::Error> {
        use std::hash::{Hash, Hasher};
        let mut h = std::collections::hash_map::DefaultHasher::new();
        from_key.hash(&mut h);
        raw.hash(&mut h);
        let fp = h.finish() as i64;
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as i64;
        {
            let conn = lock_db(&self.db);
            // Only dedup within a short window: rapid network/app re-delivery of the
            // exact same bytes happens within seconds. Pruning older fingerprints
            // bounds the table and guarantees a legit recurring mail is never
            // permanently blocked.
            const DEDUP_WINDOW_SECS: i64 = 600;
            conn.execute(
                "DELETE FROM inbox_seen WHERE datetime < ?1",
                rusqlite::params![now - DEDUP_WINDOW_SECS],
            )?;
            let inserted = conn.execute(
                "INSERT OR IGNORE INTO inbox_seen (fp, datetime) VALUES (?1, ?2)",
                rusqlite::params![fp, now],
            )?;
            if inserted == 0 {
                return Ok(None); // duplicate seen within the window
            }
        } // guard dropped here; std Mutex is not reentrant — mail_insert takes it next
        let id = self.mail_insert("INBOX", raw)?;
        Ok(Some(id))
    }

    pub fn mail_get(&self, mailbox: &str, id: u32) -> Result<Option<MailEntry>, rusqlite::Error> {
        mails::get(&self.db, mailbox, id, self.at_rest_key.as_ref())
    }

    pub fn mail_list(&self, mailbox: &str) -> Result<Vec<u32>, rusqlite::Error> {
        mails::list_ids(&self.db, mailbox)
    }

    pub fn mail_count(&self, mailbox: &str) -> Result<u32, rusqlite::Error> {
        mails::count(&self.db, mailbox)
    }

    pub fn mail_unseen_count(&self, mailbox: &str) -> Result<u32, rusqlite::Error> {
        mails::unseen_count(&self.db, mailbox)
    }

    pub fn mail_uid_validity(&self) -> Result<u32, rusqlite::Error> {
        mails::uid_validity(&self.db)
    }

    /// The next UID that will be assigned in `mailbox` (monotonic, never reused).
    /// IMAP SELECT reports this as UIDNEXT.
    pub fn mail_uid_next(&self, mailbox: &str) -> Result<u32, rusqlite::Error> {
        mails::uid_next(&self.db, mailbox)
    }

    // ── queue operations (delegate to queue module) ─────────────────────

    /// A handle the outbound sender awaits; `queue_insert` fires it so a newly
    /// enqueued mail is sent immediately instead of waiting the poll interval.
    pub fn queue_notify(&self) -> Arc<Notify> {
        self.queue_notify.clone()
    }

    pub fn queue_insert(
        &self, destination: &str, mailbox: &str, id: u32, from: &str, rcpt: &str,
    ) -> Result<(), rusqlite::Error> {
        queue::insert(&self.db, destination, mailbox, id, from, rcpt)?;
        self.queue_notify.notify_one();
        Ok(())
    }

    pub fn queue_list_destinations(&self) -> Result<Vec<String>, rusqlite::Error> {
        queue::list_destinations(&self.db)
    }

    pub fn queue_get_for_destination(&self, dest: &str) -> Result<Vec<QueuedMail>, rusqlite::Error> {
        queue::get_for_destination(&self.db, dest)
    }

    pub fn queue_delete(&self, destination: &str, mailbox: &str, id: u32) -> Result<(), rusqlite::Error> {
        queue::delete(&self.db, destination, mailbox, id)
    }

    /// How many queue rows still reference this mail (one per undelivered
    /// recipient). Used to move a mail to Sent only after the LAST recipient.
    pub fn queue_count_for_mail(&self, mailbox: &str, id: u32) -> Result<u32, rusqlite::Error> {
        queue::count_for_mail(&self.db, mailbox, id)
    }

    // ── mailbox operations ─────────────────────────────────────────────

    pub fn mailbox_list(&self) -> Result<Vec<String>, rusqlite::Error> {
        mails::list_mailboxes(&self.db)
    }

    pub fn mailbox_create(&self, name: &str) -> Result<(), rusqlite::Error> {
        mails::create_mailbox(&self.db, name)
    }

    pub fn mailbox_delete(&self, name: &str) -> Result<(), rusqlite::Error> {
        mails::delete_mailbox(&self.db, name)
    }

    pub fn mailbox_rename(&self, old: &str, new: &str) -> Result<(), rusqlite::Error> {
        mails::rename_mailbox(&self.db, old, new)
    }

    pub fn mailbox_subscribe(&self, name: &str, sub: bool) -> Result<(), rusqlite::Error> {
        mails::subscribe_mailbox(&self.db, name, sub)
    }

    // ── mail flag/move operations ──────────────────────────────────────

    pub fn mail_update_flags(
        &self, mailbox: &str, id: u32,
        seen: bool, answered: bool, flagged: bool, deleted: bool,
    ) -> Result<(), rusqlite::Error> {
        mails::update_flags(&self.db, mailbox, id, seen, answered, flagged, deleted)
    }

    pub fn mail_expunge(&self, mailbox: &str) -> Result<(), rusqlite::Error> {
        mails::expunge(&self.db, mailbox)
    }

    pub fn mail_delete(&self, mailbox: &str, id: u32) -> Result<(), rusqlite::Error> {
        mails::delete_mail(&self.db, mailbox, id)
    }

    pub fn mail_move(&self, from: &str, to: &str, id: u32) -> Result<(), rusqlite::Error> {
        mails::move_mail(&self.db, from, to, id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lock_db_recovers_from_poison() {
        // Reproduce RC2: a panic while the DB lock is held poisons the mutex.
        // A plain `.lock().unwrap()` would then panic forever (storage dead
        // until a process restart); `lock_db` must recover a usable connection.
        let db = Arc::new(Mutex::new(Connection::open_in_memory().unwrap()));
        let db2 = db.clone();
        let _ = std::thread::spawn(move || {
            let _guard = db2.lock().unwrap();
            panic!("poison the DB mutex");
        })
        .join();

        assert!(db.lock().is_err(), "mutex should be poisoned after the panic");

        // Recovery path still yields a working connection.
        let conn = lock_db(&db);
        conn.execute_batch("SELECT 1;").unwrap();
    }

    fn temp_db(name: &str) -> SqliteStorage {
        let dir = std::env::temp_dir();
        let path = dir.join(format!("yggmail_test_{}_{}.db", std::process::id(), name));
        let _ = std::fs::remove_file(&path);
        SqliteStorage::open(&path.to_string_lossy(), None).unwrap()
    }

    #[test]
    fn mail_insert_and_get() {
        let s = temp_db("insert_get");
        let raw = b"From: alice@yggmail\r\nSubject: test\r\n\r\nHello!";
        let id = s.mail_insert("INBOX", raw).unwrap();
        let mail = s.mail_get("INBOX", id).unwrap().unwrap();
        assert_eq!(mail.id, id);
        assert_eq!(mail.mail, raw);
        assert!(!mail.seen);
    }

    #[test]
    fn mail_list_and_count() {
        let s = temp_db("list_count");
        s.mail_insert("INBOX", b"msg1").unwrap();
        s.mail_insert("INBOX", b"msg2").unwrap();
        s.mail_insert("INBOX", b"msg3").unwrap();

        assert_eq!(s.mail_count("INBOX").unwrap(), 3);
        let ids = s.mail_list("INBOX").unwrap();
        assert_eq!(ids.len(), 3);
    }

    #[test]
    fn queue_roundtrip() {
        let s = temp_db("queue");
        s.mail_insert("Outbox", b"test mail").unwrap();

        s.queue_insert("00ff", "Outbox", 1, "alice@yggmail", "bob@yggmail").unwrap();

        let dests = s.queue_list_destinations().unwrap();
        assert_eq!(dests, vec!["00ff"]);

        let qm = s.queue_get_for_destination("00ff").unwrap();
        assert_eq!(qm.len(), 1);
        assert_eq!(qm[0].from, "alice@yggmail");

        s.queue_delete("00ff", "Outbox", 1).unwrap();
        assert!(s.queue_list_destinations().unwrap().is_empty());
    }

    #[test]
    fn encrypted_open_inserts_and_gets() {
        let dir = std::env::temp_dir();
        let path = dir.join(format!("yggmail_test_{}_enc.db", std::process::id()));
        let _ = std::fs::remove_file(&path);
        let hash = "a665a45920422f9d417e4867efdc4fb8a04a1f3fff1fa07e998e86f7f7a27ae3";
        let s = SqliteStorage::open(&path.to_string_lossy(), Some(hash)).unwrap();
        let raw = b"From: alice@yggmail\r\nSubject: encrypted\r\n\r\nSecret!";
        let id = s.mail_insert("INBOX", raw).unwrap();
        let mail = s.mail_get("INBOX", id).unwrap().unwrap();
        assert_eq!(mail.mail, raw, "decrypted mail must match original");
    }

    #[test]
    fn wrong_password_errors_on_second_open() {
        let dir = std::env::temp_dir();
        let path = dir.join(format!("yggmail_test_{}_wrongpw.db", std::process::id()));
        let _ = std::fs::remove_file(&path);
        let good_hash = "a665a45920422f9d417e4867efdc4fb8a04a1f3fff1fa07e998e86f7f7a27ae3";
        let bad_hash = "0000000000000000000000000000000000000000000000000000000000000000";
        // First open: creates salt + DK.
        SqliteStorage::open(&path.to_string_lossy(), Some(good_hash)).unwrap();
        // Second open with wrong password must error, never generate a new DK.
        let result = SqliteStorage::open(&path.to_string_lossy(), Some(bad_hash));
        assert!(result.is_err(), "wrong password must return Err");
    }

    #[test]
    fn rewrap_data_key_allows_reopen_with_new_password() {
        let dir = std::env::temp_dir();
        let path = dir.join(format!("yggmail_test_{}_rewrap.db", std::process::id()));
        let _ = std::fs::remove_file(&path);
        let old_hash = "a665a45920422f9d417e4867efdc4fb8a04a1f3fff1fa07e998e86f7f7a27ae3";
        let new_hash = "b3a8e0e1f9ab1bfe3a36f231f676f78bb28a2d0b39ce07830f28a38f63e29b6b";

        // Open with old password, insert mail.
        let s = SqliteStorage::open(&path.to_string_lossy(), Some(old_hash)).unwrap();
        let raw = b"From: bob@yggmail\r\n\r\nHello!";
        s.mail_insert("INBOX", raw).unwrap();

        // Change password: rewrap DK only.
        s.rewrap_data_key(new_hash).unwrap();

        // Re-open with the new password — DK must unwrap correctly.
        let s2 = SqliteStorage::open(&path.to_string_lossy(), Some(new_hash)).unwrap();
        let ids = s2.mail_list("INBOX").unwrap();
        assert_eq!(ids.len(), 1);
        let mail = s2.mail_get("INBOX", ids[0]).unwrap().unwrap();
        assert_eq!(mail.mail, raw, "mail must decrypt correctly after password change");
    }

    #[test]
    fn plaintext_migration_on_encrypted_open() {
        // Insert plaintext rows via an unencrypted open, then re-open with a password.
        // The migration pass must encrypt them so they can be read back.
        let dir = std::env::temp_dir();
        let path = dir.join(format!("yggmail_test_{}_migration.db", std::process::id()));
        let _ = std::fs::remove_file(&path);

        let raw = b"From: legacy@yggmail\r\n\r\nLegacy plaintext mail";
        {
            let s = SqliteStorage::open(&path.to_string_lossy(), None).unwrap();
            s.mail_insert("INBOX", raw).unwrap();
        }

        // Re-open with a password: migration should encrypt the existing row.
        let hash = "a665a45920422f9d417e4867efdc4fb8a04a1f3fff1fa07e998e86f7f7a27ae3";
        let s = SqliteStorage::open(&path.to_string_lossy(), Some(hash)).unwrap();
        let ids = s.mail_list("INBOX").unwrap();
        assert_eq!(ids.len(), 1);
        let mail = s.mail_get("INBOX", ids[0]).unwrap().unwrap();
        assert_eq!(mail.mail, raw, "migrated plaintext mail must decrypt correctly");
    }
}
