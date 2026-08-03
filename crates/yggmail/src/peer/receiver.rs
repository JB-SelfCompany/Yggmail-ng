//! Приём входящей почты: транспорт → БД (INBOX).
//!
//! На время сосуществования транспортов слушаем оба: QUIC (узлы 1.8 и все
//! обновлённые) и YMP (уже выкаченные 1.9.0, которые умеют только его).
//! Когда YMP уйдёт, параметр `ymp` и вся его ветка удаляются.

use crate::quic::QuicMailTransport;
use crate::storage::SqliteStorage;
use crate::ymp::YmpSession;
use std::sync::Arc;
use tracing;

/// Запустить фоновый приём. `ymp` — `None`, когда YMP уже удалён.
pub fn spawn(
    storage: Arc<SqliteStorage>,
    quic: Arc<QuicMailTransport>,
    ymp: Option<Arc<YmpSession>>,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        loop {
            // Транспорт называем в тексте ошибки: пока их два, по одной строке
            // лога должно быть видно, какой именно отказал.
            let received = match &ymp {
                Some(ymp) => tokio::select! {
                    r = quic.recv() => r.map_err(|e| format!("QUIC: {e}")),
                    r = ymp.recv() => r.map_err(|e| format!("YMP: {e}")),
                },
                None => quic.recv().await.map_err(|e| format!("QUIC: {e}")),
            };

            match received {
                Ok((from_key, data)) => store(&storage, from_key, &data),
                Err(e) => {
                    tracing::error!("receiver: recv error: {e}");
                    tokio::time::sleep(std::time::Duration::from_secs(1)).await;
                }
            }
        }
    })
}

fn store(storage: &SqliteStorage, from_key: [u8; 32], data: &[u8]) {
    let from_addr = crate::address::create_address(&from_key);
    match storage.mail_insert_inbox_dedup(&from_key, data) {
        Ok(Some(id)) => {
            tracing::info!(
                "receiver: stored in INBOX id={id} from {} ({} bytes)",
                &from_addr[..16],
                data.len()
            );
        }
        Ok(None) => {
            tracing::debug!("receiver: duplicate mail from {} dropped", &from_addr[..16]);
        }
        Err(e) => {
            tracing::error!("receiver: failed to store mail: {e}");
        }
    }
}
