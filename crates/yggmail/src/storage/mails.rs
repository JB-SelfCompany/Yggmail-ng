//! Mail CRUD — schema-compatible with yggmail_old.
//! At-rest encryption: blobs prefixed with 0x01 are XChaCha20-Poly1305 encrypted.
//! Legacy blobs (no 0x01 prefix) are returned as-is (plaintext passthrough).

use rusqlite::{Connection, params};
use std::sync::{Arc, Mutex};

pub const SCHEMA: &str = "
CREATE TABLE IF NOT EXISTS mails (
    mailbox  TEXT NOT NULL,
    id       INTEGER NOT NULL DEFAULT 1,
    mail     BLOB NOT NULL,
    datetime INTEGER NOT NULL,
    seen     BOOLEAN NOT NULL DEFAULT 0,
    answered BOOLEAN NOT NULL DEFAULT 0,
    flagged  BOOLEAN NOT NULL DEFAULT 0,
    deleted  BOOLEAN NOT NULL DEFAULT 0,
    PRIMARY KEY (mailbox, id),
    FOREIGN KEY (mailbox) REFERENCES mailboxes(mailbox)
        ON DELETE CASCADE ON UPDATE CASCADE
);
CREATE VIEW IF NOT EXISTS inboxes AS
    SELECT ROW_NUMBER() OVER (PARTITION BY mailbox) AS seq, * FROM mails
    ORDER BY mailbox, id;
CREATE TABLE IF NOT EXISTS inbox_seen (
    fp       INTEGER PRIMARY KEY,
    datetime INTEGER NOT NULL
);
";

#[derive(Debug, Clone)]
pub struct MailEntry {
    pub mailbox: String,
    pub id: u32,
    pub mail: Vec<u8>,
    pub date: i64,
    pub seen: bool,
    pub answered: bool,
    pub flagged: bool,
    pub deleted: bool,
}

pub fn insert(
    db: &Arc<Mutex<Connection>>,
    mailbox: &str,
    raw: &[u8],
    key: Option<&[u8; 32]>,
) -> Result<u32, rusqlite::Error> {
    let conn = super::lock_db(db);
    // Encrypt when a data key is available; otherwise store raw (legacy/plaintext mode).
    let encrypted_buf;
    let blob: &[u8] = if let Some(dk) = key {
        encrypted_buf = super::crypt::aead_encrypt(dk, raw);
        &encrypted_buf
    } else {
        raw
    };
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64;
    // Ensure the mailbox exists so it has a uid_next counter.
    conn.execute("INSERT OR IGNORE INTO mailboxes (mailbox) VALUES (?1)", params![mailbox])?;
    // Allocate a monotonic UID from the per-mailbox counter and bump it. Never
    // reuses an id after expunge, so IMAP UIDs stay strictly ascending.
    let id: u32 = conn.query_row(
        "SELECT uid_next FROM mailboxes WHERE mailbox = ?1",
        params![mailbox],
        |row| row.get(0),
    )?;
    conn.execute("UPDATE mailboxes SET uid_next = uid_next + 1 WHERE mailbox = ?1", params![mailbox])?;
    conn.execute(
        "INSERT INTO mails (mailbox, id, mail, datetime) VALUES (?1, ?2, ?3, ?4)",
        params![mailbox, id, blob, now],
    )?;
    Ok(id)
}

pub fn get(
    db: &Arc<Mutex<Connection>>,
    mailbox: &str,
    id: u32,
    key: Option<&[u8; 32]>,
) -> Result<Option<MailEntry>, rusqlite::Error> {
    let conn = super::lock_db(db);
    let mut stmt = conn.prepare(
        "SELECT mailbox, id, mail, datetime, seen, answered, flagged, deleted FROM mails WHERE mailbox = ?1 AND id = ?2"
    )?;
    let mut rows = stmt.query_map(params![mailbox, id], |row| {
        Ok(MailEntry {
            mailbox: row.get(0)?,
            id: row.get(1)?,
            mail: row.get(2)?,
            date: row.get(3)?,
            seen: row.get(4)?,
            answered: row.get(5)?,
            flagged: row.get(6)?,
            deleted: row.get(7)?,
        })
    })?;
    match rows.next() {
        Some(Ok(mut entry)) => {
            // Decrypt if the blob is an encrypted version-0x01 blob.
            if entry.mail.first() == Some(&super::crypt::VERSION_XCHACHA) {
                let dk = key.ok_or_else(|| rusqlite::Error::InvalidParameterName(
                    "at-rest: encrypted mail row found but no data key available".into(),
                ))?;
                entry.mail = super::crypt::aead_decrypt(dk, &entry.mail)
                    .ok_or_else(|| rusqlite::Error::InvalidParameterName(
                        "at-rest: mail decryption failed — wrong key or corrupted blob".into(),
                    ))?;
            }
            // else: legacy plaintext blob — return as-is.
            Ok(Some(entry))
        }
        Some(Err(e)) => Err(e),
        None => Ok(None),
    }
}

pub fn list_ids(db: &Arc<Mutex<Connection>>, mailbox: &str) -> Result<Vec<u32>, rusqlite::Error> {
    let conn = super::lock_db(db);
    let mut stmt = conn.prepare(
        "SELECT id FROM mails WHERE mailbox = ?1 ORDER BY id"
    )?;
    let ids: Vec<u32> = stmt.query_map(params![mailbox], |row| row.get(0))?
        .filter_map(|r| r.ok())
        .collect();
    Ok(ids)
}

pub fn count(db: &Arc<Mutex<Connection>>, mailbox: &str) -> Result<u32, rusqlite::Error> {
    let conn = super::lock_db(db);
    Ok(conn.query_row(
        "SELECT COUNT(*) FROM mails WHERE mailbox = ?1",
        params![mailbox],
        |row| row.get::<_, u32>(0),
    )?)
}

pub fn unseen_count(db: &Arc<Mutex<Connection>>, mailbox: &str) -> Result<u32, rusqlite::Error> {
    let conn = super::lock_db(db);
    Ok(conn.query_row(
        "SELECT COUNT(*) FROM mails WHERE mailbox = ?1 AND seen = 0",
        params![mailbox],
        |row| row.get::<_, u32>(0),
    )?)
}

// ponytail: UIDVALIDITY = 1 (constant). Per RFC 3501, it must not change across sessions.
pub fn uid_validity(_db: &Arc<Mutex<Connection>>) -> Result<u32, rusqlite::Error> {
    Ok(1)
}

pub fn uid_next(db: &Arc<Mutex<Connection>>, mailbox: &str) -> Result<u32, rusqlite::Error> {
    let conn = super::lock_db(db);
    conn.query_row(
        "SELECT uid_next FROM mailboxes WHERE mailbox = ?1",
        params![mailbox],
        |row| row.get(0),
    ).or(Ok(1))
}

pub fn update_flags(
    db: &Arc<Mutex<Connection>>, mailbox: &str, id: u32,
    seen: bool, answered: bool, flagged: bool, deleted: bool,
) -> Result<(), rusqlite::Error> {
    let conn = super::lock_db(db);
    conn.execute(
        "UPDATE mails SET seen=?1, answered=?2, flagged=?3, deleted=?4 WHERE mailbox=?5 AND id=?6",
        params![seen, answered, flagged, deleted, mailbox, id],
    )?;
    Ok(())
}

pub fn expunge(db: &Arc<Mutex<Connection>>, mailbox: &str) -> Result<(), rusqlite::Error> {
    let conn = super::lock_db(db);
    conn.execute("DELETE FROM mails WHERE mailbox=?1 AND deleted=1", params![mailbox])?;
    Ok(())
}

pub fn delete_mail(db: &Arc<Mutex<Connection>>, mailbox: &str, id: u32) -> Result<(), rusqlite::Error> {
    let conn = super::lock_db(db);
    conn.execute("UPDATE mails SET deleted=1 WHERE mailbox=?1 AND id=?2", params![mailbox, id])?;
    Ok(())
}

pub fn move_mail(db: &Arc<Mutex<Connection>>, from: &str, to: &str, id: u32) -> Result<(), rusqlite::Error> {
    let conn = super::lock_db(db);
    conn.execute("UPDATE mails SET mailbox=?1 WHERE mailbox=?2 AND id=?3", params![to, from, id])?;
    Ok(())
}

pub fn list_mailboxes(db: &Arc<Mutex<Connection>>) -> Result<Vec<String>, rusqlite::Error> {
    let conn = super::lock_db(db);
    let mut stmt = conn.prepare("SELECT mailbox FROM mailboxes ORDER BY mailbox")?;
    let mbs: Vec<String> = stmt.query_map([], |row| row.get(0))?
        .filter_map(|r| r.ok()).collect();
    Ok(mbs)
}

pub fn create_mailbox(db: &Arc<Mutex<Connection>>, name: &str) -> Result<(), rusqlite::Error> {
    let conn = super::lock_db(db);
    conn.execute("INSERT INTO mailboxes (mailbox) VALUES(?1)", params![name])?;
    Ok(())
}

pub fn delete_mailbox(db: &Arc<Mutex<Connection>>, name: &str) -> Result<(), rusqlite::Error> {
    let conn = super::lock_db(db);
    conn.execute("DELETE FROM mailboxes WHERE mailbox=?1", params![name])?;
    Ok(())
}

pub fn rename_mailbox(db: &Arc<Mutex<Connection>>, old: &str, new: &str) -> Result<(), rusqlite::Error> {
    let conn = super::lock_db(db);
    conn.execute("UPDATE mailboxes SET mailbox=?1 WHERE mailbox=?2", params![new, old])?;
    conn.execute("UPDATE mails SET mailbox=?1 WHERE mailbox=?2", params![new, old])?;
    Ok(())
}

pub fn subscribe_mailbox(db: &Arc<Mutex<Connection>>, name: &str, sub: bool) -> Result<(), rusqlite::Error> {
    let conn = super::lock_db(db);
    conn.execute("UPDATE mailboxes SET subscribed=?1 WHERE mailbox=?2", params![sub, name])?;
    Ok(())
}
