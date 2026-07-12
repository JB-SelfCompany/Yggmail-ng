//! Inbound mail receiver: YMP → DB (INBOX).
//! ponytail: minimal — no IMAP IDLE notify until Phase 5.

use crate::storage::SqliteStorage;
use crate::ymp::YmpSession;
use std::sync::Arc;
use tracing;

/// Start the inbound receiver background task.
/// Reads assembled messages from YMP and stores them in INBOX.
pub fn spawn(
    storage: Arc<SqliteStorage>,
    ymp: Arc<YmpSession>,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        loop {
            match ymp.recv().await {
                Ok((from_key, data)) => {
                    let from_addr = crate::address::create_address(&from_key);
                    match storage.mail_insert_inbox_dedup(&from_key, &data) {
                        Ok(Some(_id)) => {
                            tracing::info!(
                                "receiver: new mail from {} ({} bytes)",
                                &from_addr[..16],
                                data.len()
                            );
                        }
                        Ok(None) => {
                            tracing::debug!(
                                "receiver: duplicate mail from {} dropped",
                                &from_addr[..16]
                            );
                        }
                        Err(e) => {
                            tracing::error!("receiver: failed to store mail: {e}");
                        }
                    }
                }
                Err(e) => {
                    tracing::error!("receiver: YMP recv error: {e}");
                    // ponytail: exponential backoff in Phase 3+ if needed
                    tokio::time::sleep(std::time::Duration::from_secs(1)).await;
                }
            }
        }
    })
}
