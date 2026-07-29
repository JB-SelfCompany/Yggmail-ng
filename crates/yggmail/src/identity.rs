//! Стабильная Ed25519-identity узла: загрузка / миграция / персист в `mobile_config`.
//!
//! Общая логика для Android (`yggmail-mobile`) и Desktop (`Desktop-rs`) — единый
//! `@yggmail`-адрес и миграция legacy 1.8-ключа. НЕ дублировать в вызывающих крейтах:
//! `decrypt_stored_key` содержит тонкое brick-safe различение (по длине, не по
//! version-байту), а `load_or_migrate_identity` — приоритет legacy-ключа над
//! возможным «отравленным» 1.9-`mobile_config`.

use rand::rngs::OsRng;

/// Ошибка загрузки/персиста identity. Без thiserror — стиль yggmail (ручной Display).
#[derive(Debug)]
pub enum IdentityError {
    Io(String),
    Config(String),
}

impl std::fmt::Display for IdentityError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(s) => write!(f, "identity io: {s}"),
            Self::Config(s) => write!(f, "identity config: {s}"),
        }
    }
}
impl std::error::Error for IdentityError {}

/// Разобрать 64-байтный keypair-hex в `SigningKey`.
pub fn parse_signing_key(hex_key: &str) -> Result<ed25519_dalek::SigningKey, IdentityError> {
    let bytes = hex::decode(hex_key).map_err(|e| IdentityError::Config(e.to_string()))?;
    if bytes.len() != 64 {
        return Err(IdentityError::Config(format!(
            "key must be 64 bytes, got {}",
            bytes.len()
        )));
    }
    let mut arr = [0u8; 64];
    arr.copy_from_slice(&bytes);
    ed25519_dalek::SigningKey::from_keypair_bytes(&arr)
        .map_err(|e| IdentityError::Config(e.to_string()))
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
pub fn load_or_migrate_identity(
    db_path: &str,
    dk: Option<&[u8; 32]>,
) -> Result<(ed25519_dalek::SigningKey, String), IdentityError> {
    let conn = rusqlite::Connection::open(db_path).map_err(|e| IdentityError::Io(e.to_string()))?;
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS mobile_config (key TEXT PRIMARY KEY, value TEXT);",
    )
    .map_err(|e| IdentityError::Io(e.to_string()))?;

    // (1) Legacy 1.8 key present → it is authoritative. Adopt + heal mobile_config.
    // Legacy `config` always stores plaintext hex — no decryption needed here.
    if let Some((key, hex_key)) = conn
        .query_row(
            "SELECT value FROM config WHERE key = 'private_key'",
            [],
            |r| r.get::<_, String>(0),
        )
        .ok()
        .and_then(|h| parse_signing_key(&h).ok().map(|k| (k, h)))
    {
        persist_identity(&conn, &hex_key, dk)?;
        tracing::info!(
            "identity: adopted legacy (1.8) identity from `config` — @yggmail address preserved"
        );
        return Ok((key, hex_key));
    }

    // (2) No legacy key: reuse the persisted 1.9 identity.
    if let Some(stored_value) = conn
        .query_row(
            "SELECT value FROM mobile_config WHERE key = 'private_key'",
            [],
            |r| r.get::<_, String>(0),
        )
        .ok()
    {
        let plaintext_hex = decrypt_stored_key(&stored_value, dk)?;
        if let Some(pair) = parse_signing_key(&plaintext_hex)
            .ok()
            .map(|k| (k, plaintext_hex.clone()))
        {
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

/// Mint a brand-new Ed25519 identity, persist it (encrypted under `dk` when
/// `Some`), and return it. **Destructive:** the node's `@yggmail` address changes
/// permanently; peers can no longer reach the old address.
///
/// Also deletes any legacy `config.private_key` row so that a later
/// [`load_or_migrate_identity`] does not re-adopt the old 1.8 identity (its
/// legacy-precedence rule would otherwise shadow the new key). The Rust storage
/// layer never creates the `config` table — only the legacy Go binary does — so
/// the delete is best-effort and a "no such table" error is intentionally ignored.
///
/// The delete and the new-key write run in ONE transaction: a crash between them
/// must not leave the legacy row gone AND the new key unwritten (which would make
/// the next load mint yet another random third key).
///
/// The at-rest data key (`dk`) is NOT changed, so existing encrypted mail stays
/// readable after regeneration.
pub fn regenerate_identity(
    db_path: &str,
    dk: Option<&[u8; 32]>,
) -> Result<(ed25519_dalek::SigningKey, String), IdentityError> {
    let mut conn =
        rusqlite::Connection::open(db_path).map_err(|e| IdentityError::Io(e.to_string()))?;
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS mobile_config (key TEXT PRIMARY KEY, value TEXT);",
    )
    .map_err(|e| IdentityError::Io(e.to_string()))?;
    let key = ed25519_dalek::SigningKey::generate(&mut OsRng);
    let hex_key = hex::encode(key.to_keypair_bytes());
    let tx = conn
        .transaction()
        .map_err(|e| IdentityError::Io(e.to_string()))?;
    // ponytail: legacy `config` table may not exist on desktop — ignore "no such
    // table". A genuine I/O/corruption error instead surfaces through the
    // un-ignored persist_identity write below, so nothing real is masked here.
    let _ = tx.execute("DELETE FROM config WHERE key = 'private_key'", []);
    persist_identity(&tx, &hex_key, dk)?; // &Transaction derefs to &Connection
    tx.commit().map_err(|e| IdentityError::Io(e.to_string()))?;
    tracing::info!("identity: regenerated node key — @yggmail address changed");
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
fn decrypt_stored_key(stored_value: &str, dk: Option<&[u8; 32]>) -> Result<String, IdentityError> {
    use crate::storage::crypt::{VERSION_XCHACHA, aead_decrypt};
    // Attempt hex-decode; if it fails the value is definitely not an encrypted blob.
    if let Ok(bytes) = hex::decode(stored_value) {
        // 64 bytes = legacy Ed25519 keypair; an encrypted blob is never 64 bytes.
        if bytes.len() != 64 && bytes.first() == Some(&VERSION_XCHACHA) {
            // Encrypted blob.
            let dk = dk.ok_or_else(|| {
                IdentityError::Config(
                    "private_key is encrypted but no data key available (wrong password?)".into(),
                )
            })?;
            let plaintext = aead_decrypt(dk, &bytes).ok_or_else(|| {
                IdentityError::Config(
                    "private_key decryption failed — wrong key or corrupted blob".into(),
                )
            })?;
            return String::from_utf8(plaintext).map_err(|_| {
                IdentityError::Config("decrypted private_key is not valid UTF-8".into())
            });
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
) -> Result<(), IdentityError> {
    use crate::storage::crypt::aead_encrypt;
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
    .map_err(|e| IdentityError::Io(e.to_string()))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp(tag: &str) -> String {
        let p = std::env::temp_dir().join(format!("ident-{}-{}.db", std::process::id(), tag));
        let _ = std::fs::remove_file(&p);
        p.to_string_lossy().into_owned()
    }

    #[test]
    fn regenerate_changes_identity_and_persists() {
        let db = tmp("regen");
        // Fresh identity.
        let (k1, _) = load_or_migrate_identity(&db, None).unwrap();
        // Regenerate → different verifying key.
        let (k2, _) = regenerate_identity(&db, None).unwrap();
        assert_ne!(
            k1.verifying_key().to_bytes(),
            k2.verifying_key().to_bytes(),
            "regenerate must mint a different key"
        );
        // Next load returns the regenerated key (persist worked, no legacy re-adopt).
        let (k3, _) = load_or_migrate_identity(&db, None).unwrap();
        assert_eq!(
            k2.verifying_key().to_bytes(),
            k3.verifying_key().to_bytes(),
            "regenerated key must survive reload"
        );
        let _ = std::fs::remove_file(&db);
    }

    #[test]
    fn regenerate_roundtrips_under_encryption() {
        // With a DK, the persisted key is encrypted; reload with the same DK must recover it.
        let db = tmp("regen-enc");
        let dk = [0x24u8; 32];
        let (k2, _) = regenerate_identity(&db, Some(&dk)).unwrap();
        let (k3, _) = load_or_migrate_identity(&db, Some(&dk)).unwrap();
        assert_eq!(k2.verifying_key().to_bytes(), k3.verifying_key().to_bytes());
        let _ = std::fs::remove_file(&db);
    }
}
