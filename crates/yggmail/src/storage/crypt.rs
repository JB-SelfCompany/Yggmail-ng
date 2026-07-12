//! At-rest encryption primitives — XChaCha20-Poly1305 with a wrapped data key.
//!
//! # Design
//! - **KEK** = SHA-256(`"yggmail-at-rest-v1"` || `salt` || `password_hash_hex`)
//!   per-DB random 16-byte salt stored plaintext in `at_rest`.
//! - **DK** (data key) = 32 random bytes, generated once, stored wrapped under KEK.
//! - Mail bodies and the Ed25519 private key are encrypted with DK (not KEK).
//! - Cipher: XChaCha20-Poly1305, 24-byte random nonce per encryption, 16-byte tag.
//! - Blob format: `[0x01][24-byte nonce][ciphertext+tag]`.
//!   Version `0x00` / absent bytes = legacy plaintext (passthrough).

use chacha20poly1305::{
    aead::{Aead, KeyInit},
    XChaCha20Poly1305, XNonce,
};
use rand::RngCore;
use sha2::{Digest, Sha256};

/// Version byte that prefixes every encrypted blob produced by this module.
pub const VERSION_XCHACHA: u8 = 0x01;

const NONCE_LEN: usize = 24;
/// Minimum valid encrypted blob length: version(1) + nonce(24) + tag(16).
const MIN_BLOB_LEN: usize = 1 + NONCE_LEN + 16;

/// Derive a 32-byte Key-Encryption-Key from `password_hash_hex` and `salt`.
///
/// `KEK = SHA-256(b"yggmail-at-rest-v1" || salt || password_hash_hex.as_bytes())`
///
/// The label makes the output domain-separated from any other SHA-256 usage.
/// Strength is bounded by the password: an attacker who has the DB and can
/// brute-force a weak password can recover the KEK and unwrap the DK.
pub fn derive_kek(password_hash_hex: &str, salt: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(b"yggmail-at-rest-v1");
    h.update(salt);
    h.update(password_hash_hex.as_bytes());
    h.finalize().into()
}

/// Encrypt `plaintext` under `key` using XChaCha20-Poly1305.
///
/// A fresh 24-byte nonce is drawn from `rand::thread_rng()` for every call —
/// nonces are NEVER reused.  Returns `[0x01][nonce24][ciphertext+tag]`.
pub fn aead_encrypt(key: &[u8; 32], plaintext: &[u8]) -> Vec<u8> {
    let cipher = XChaCha20Poly1305::new(key.into());
    let mut nonce_bytes = [0u8; NONCE_LEN];
    rand::thread_rng().fill_bytes(&mut nonce_bytes);
    let nonce = XNonce::from(nonce_bytes);
    // XChaCha20-Poly1305::encrypt only fails on RNG issues or internal errors;
    // neither applies here — the key and nonce are always well-formed.
    let ciphertext = cipher
        .encrypt(&nonce, plaintext)
        .expect("XChaCha20-Poly1305 encrypt must not fail with valid key and nonce");
    let mut blob = Vec::with_capacity(1 + NONCE_LEN + ciphertext.len());
    blob.push(VERSION_XCHACHA);
    blob.extend_from_slice(&nonce_bytes);
    blob.extend_from_slice(&ciphertext);
    blob
}

/// Decrypt a blob produced by [`aead_encrypt`].
///
/// Returns `None` on:
/// - Wrong version byte (not `0x01`).
/// - Blob shorter than `1 + 24 + 16` bytes.
/// - AEAD tag verification failure (wrong key or corrupted data).
///
/// Never returns `None` silently when data is structurally valid — a tag
/// failure means wrong key or corruption, and the caller must propagate an
/// error rather than returning ciphertext or an empty buffer.
pub fn aead_decrypt(key: &[u8; 32], blob: &[u8]) -> Option<Vec<u8>> {
    if blob.first() != Some(&VERSION_XCHACHA) {
        return None;
    }
    if blob.len() < MIN_BLOB_LEN {
        return None;
    }
    let nonce = XNonce::from_slice(&blob[1..1 + NONCE_LEN]);
    let ciphertext = &blob[1 + NONCE_LEN..];
    let cipher = XChaCha20Poly1305::new(key.into());
    cipher.decrypt(nonce, ciphertext).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_returns_plaintext() {
        let key = [0x42u8; 32];
        let plaintext = b"Hello, Yggmail at-rest encryption!";
        let blob = aead_encrypt(&key, plaintext);
        let recovered = aead_decrypt(&key, &blob).expect("decryption must succeed");
        assert_eq!(recovered, plaintext);
    }

    #[test]
    fn flipped_byte_in_tag_returns_none() {
        let key = [0x13u8; 32];
        let plaintext = b"sensitive mail body";
        let mut blob = aead_encrypt(&key, plaintext);
        // Flip a byte in the ciphertext+tag region (well past the nonce).
        let last = blob.len() - 1;
        blob[last] ^= 0xff;
        assert!(
            aead_decrypt(&key, &blob).is_none(),
            "corrupted blob must not decrypt"
        );
    }

    #[test]
    fn wrong_key_returns_none() {
        let key_a = [0x01u8; 32];
        let key_b = [0x02u8; 32];
        let blob = aead_encrypt(&key_a, b"secret");
        assert!(aead_decrypt(&key_b, &blob).is_none());
    }

    #[test]
    fn bad_version_byte_returns_none() {
        let key = [0x55u8; 32];
        let mut blob = aead_encrypt(&key, b"data");
        blob[0] = 0x00; // override version byte to legacy/plaintext marker
        assert!(aead_decrypt(&key, &blob).is_none());
    }

    #[test]
    fn too_short_blob_returns_none() {
        let key = [0x77u8; 32];
        // A blob with version byte but only partial nonce — below MIN_BLOB_LEN.
        let short = [VERSION_XCHACHA, 0x00, 0x01];
        assert!(aead_decrypt(&key, &short).is_none());
    }

    #[test]
    fn nonce_is_random_per_call() {
        // Two encryptions of the same plaintext must produce different blobs
        // (i.e., different nonces) — ensures nonces are never reused.
        let key = [0xabu8; 32];
        let plaintext = b"same plaintext";
        let blob1 = aead_encrypt(&key, plaintext);
        let blob2 = aead_encrypt(&key, plaintext);
        // Extract the 24-byte nonces and compare.
        assert_ne!(
            &blob1[1..1 + 24],
            &blob2[1..1 + 24],
            "nonces must differ across encryptions"
        );
    }

    #[test]
    fn derive_kek_is_deterministic() {
        let salt = [0xdeu8; 16];
        let hash = "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890";
        let kek1 = derive_kek(hash, &salt);
        let kek2 = derive_kek(hash, &salt);
        assert_eq!(kek1, kek2);
    }

    #[test]
    fn derive_kek_different_salts_differ() {
        let salt_a = [0x11u8; 16];
        let salt_b = [0x22u8; 16];
        let hash = "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890";
        assert_ne!(derive_kek(hash, &salt_a), derive_kek(hash, &salt_b));
    }
}
