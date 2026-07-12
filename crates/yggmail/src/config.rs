//! Yggmail-specific configuration (TOML, separate from yggdrasil::Config).
//! ponytail: minimal — only what Phase 2-3 needs.

use serde::{Deserialize, Serialize};

/// Yggmail node configuration.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct YggmailConfig {
    /// Path to the SQLite database file.
    #[serde(default = "default_db_path")]
    pub db_path: String,

    /// SMTP listen port (localhost only).
    #[serde(default = "default_smtp_port")]
    pub smtp_port: u16,

    /// IMAP listen port (localhost only).
    #[serde(default = "default_imap_port")]
    pub imap_port: u16,
}

fn default_db_path() -> String {
    "yggmail.db".to_string()
}

fn default_smtp_port() -> u16 {
    1025
}

fn default_imap_port() -> u16 {
    1143
}

impl Default for YggmailConfig {
    fn default() -> Self {
        Self {
            db_path: default_db_path(),
            smtp_port: default_smtp_port(),
            imap_port: default_imap_port(),
        }
    }
}

impl YggmailConfig {
    /// Load from a TOML file, or generate defaults if the file doesn't exist.
    pub fn load_or_create(path: &str) -> Result<Self, Box<dyn std::error::Error>> {
        if std::path::Path::new(path).exists() {
            let text = std::fs::read_to_string(path)?;
            Ok(toml::from_str(&text)?)
        } else {
            let cfg = Self::default();
            std::fs::write(path, toml::to_string_pretty(&cfg)?)?;
            Ok(cfg)
        }
    }
}
