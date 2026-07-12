//! Outbound queue — schema-compatible with yggmail_old.
//! ponytail: direct rusqlite calls, no prepared-statement cache (YAGNI for Phase 2).

use rusqlite::{Connection, params};
use std::sync::{Arc, Mutex};

pub const SCHEMA: &str = "
CREATE TABLE IF NOT EXISTS queue (
    destination TEXT NOT NULL,
    mailbox     TEXT NOT NULL,
    id          INTEGER NOT NULL,
    mail        TEXT NOT NULL,
    rcpt        TEXT NOT NULL,
    PRIMARY KEY (destination, mailbox, id),
    FOREIGN KEY (mailbox, id) REFERENCES mails(mailbox, id)
        ON DELETE CASCADE ON UPDATE CASCADE
);
";

#[derive(Debug, Clone)]
pub struct QueuedMail {
    pub id: u32,
    pub from: String,    // "hex_key@yggmail"
    pub rcpt: String,    // "hex_key@yggmail"
    pub destination: String, // hex pubkey
}

pub fn insert(
    db: &Arc<Mutex<Connection>>,
    destination: &str, mailbox: &str, id: u32,
    from: &str, rcpt: &str,
) -> Result<(), rusqlite::Error> {
    let conn = super::lock_db(db);
    conn.execute(
        "INSERT INTO queue (destination, mailbox, id, mail, rcpt) VALUES(?1, ?2, ?3, ?4, ?5)",
        params![destination, mailbox, id, from, rcpt],
    )?;
    Ok(())
}

pub fn list_destinations(db: &Arc<Mutex<Connection>>) -> Result<Vec<String>, rusqlite::Error> {
    let conn = super::lock_db(db);
    let mut stmt = conn.prepare("SELECT DISTINCT destination FROM queue")?;
    let dests: Vec<String> = stmt.query_map([], |row| row.get(0))?
        .filter_map(|r| r.ok())
        .collect();
    Ok(dests)
}

pub fn get_for_destination(
    db: &Arc<Mutex<Connection>>, dest: &str,
) -> Result<Vec<QueuedMail>, rusqlite::Error> {
    let conn = super::lock_db(db);
    let mut stmt = conn.prepare(
        "SELECT id, mail, rcpt FROM queue WHERE destination = ?1 ORDER BY id DESC"
    )?;
    let mails: Vec<QueuedMail> = stmt.query_map(params![dest], |row| {
        Ok(QueuedMail {
            id: row.get(0)?,
            from: row.get(1)?,
            rcpt: row.get(2)?,
            destination: dest.to_string(),
        })
    })?
    .filter_map(|r| r.ok())
    .collect();
    Ok(mails)
}

pub fn delete(
    db: &Arc<Mutex<Connection>>,
    destination: &str, mailbox: &str, id: u32,
) -> Result<(), rusqlite::Error> {
    let conn = super::lock_db(db);
    conn.execute(
        "DELETE FROM queue WHERE destination = ?1 AND mailbox = ?2 AND id = ?3",
        params![destination, mailbox, id],
    )?;
    Ok(())
}

pub fn count_for_mail(
    db: &Arc<Mutex<Connection>>, mailbox: &str, id: u32,
) -> Result<u32, rusqlite::Error> {
    let conn = super::lock_db(db);
    conn.query_row(
        "SELECT COUNT(*) FROM queue WHERE mailbox = ?1 AND id = ?2",
        params![mailbox, id],
        |row| row.get(0),
    )
}
