//! Yggmail address parsing: `hex_pubkey@yggmail`.
//! ponytail: port of yggmail_old/internal/utils/address.go.

const DOMAIN: &str = "yggmail";
/// Go-сторона принимает оба домена (`utils/address.go`: `DomainAlias`), алиас
/// добавлен ради почтовых клиентов, которым нужен FQDN. Без него `MAIL FROM`
/// от узла 1.8 с таким адресом отбивается с 550.
const DOMAIN_ALIAS: &str = "yggmail.local";

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
    let domain = email[at + 1..].trim();
    if !domain.eq_ignore_ascii_case(DOMAIN) && !domain.eq_ignore_ascii_case(DOMAIN_ALIAS) {
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

    #[test]
    fn accepts_local_domain_alias() {
        let key = [0x42u8; 32];
        let alias = format!("{}@yggmail.local", hex::encode(key));
        assert_eq!(parse_address(&alias), Some(key));
    }

    #[test]
    fn domain_match_is_case_insensitive() {
        let key = [0x42u8; 32];
        let upper = format!("{}@YGGMAIL.LOCAL", hex::encode(key));
        assert_eq!(parse_address(&upper), Some(key));
    }

    #[test]
    fn create_address_still_emits_canonical_domain() {
        let addr = create_address(&[0x42u8; 32]);
        assert!(addr.ends_with("@yggmail"), "got {addr}");
    }

    #[test]
    fn near_miss_domains_are_rejected() {
        let key = hex::encode([0x42u8; 32]);
        assert!(parse_address(&format!("{key}@yggmail.localhost")).is_none());
        assert!(parse_address(&format!("{key}@local")).is_none());
    }
}
