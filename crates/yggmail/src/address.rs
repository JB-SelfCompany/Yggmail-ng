//! Yggmail address parsing: `hex_pubkey@yggmail`.
//! ponytail: port of yggmail_old/internal/utils/address.go.

const DOMAIN: &str = "yggmail";

/// Build a yggmail address from an Ed25519 public key.
pub fn create_address(pubkey: &[u8; 32]) -> String {
    format!("{}@{}", hex::encode(pubkey), DOMAIN)
}

/// Parse a yggmail address, returning the Ed25519 public key bytes.
/// Returns `None` if the address is malformed or has the wrong domain.
pub fn parse_address(email: &str) -> Option<[u8; 32]> {
    let at = email.rfind('@')?;
    if at == 0 {
        return None;
    }
    if !email[at + 1..].eq_ignore_ascii_case(DOMAIN) {
        return None;
    }
    let hex_part = &email[..at];
    let bytes = hex::decode(hex_part).ok()?;
    if bytes.len() != 32 {
        return None;
    }
    let mut key = [0u8; 32];
    key.copy_from_slice(&bytes);
    Some(key)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip() {
        let key = [0x42u8; 32];
        let addr = create_address(&key);
        assert_eq!(parse_address(&addr), Some(key));
    }

    #[test]
    fn bad_domain() {
        assert!(parse_address("abc123@wrongdomain").is_none());
    }

    #[test]
    fn no_at_sign() {
        assert!(parse_address("just-a-string").is_none());
    }

    #[test]
    fn short_hex() {
        assert!(parse_address("deadbeef@yggmail").is_none());
    }
}
