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
                    // У YMP нет квитанции в проводе: отправитель уже считает
                    // письмо доставленным, подтверждать некому и нечего.
                    r = ymp.recv() => r.map(|(k, d)| (k, d, None)).map_err(|e| format!("YMP: {e}")),
                },
                None => quic.recv().await.map_err(|e| format!("QUIC: {e}")),
            };

            match received {
                Ok((from_key, data, ack)) => {
                    // Подтверждение — только после укладки: пир держит стрим
                    // открытым и получит `250` ровно от этого `send`.
                    if store(&storage, from_key, &data) {
                        if let Some(ack) = ack {
                            let _ = ack.send(());
                        }
                    }
                }
                Err(e) => {
                    tracing::error!("receiver: recv error: {e}");
                    tokio::time::sleep(std::time::Duration::from_secs(1)).await;
                }
            }
        }
    })
}

/// Уложить письмо. `true` — письмо durable, то есть отправителю можно
/// подтверждать приём. Дубликат тоже durable: он уже лежит в INBOX с прошлой
/// доставки, и заставлять пира слать его снова не за чем.
fn store(storage: &SqliteStorage, from_key: [u8; 32], data: &[u8]) -> bool {
    let from_addr = crate::address::create_address(&from_key);
    match storage.mail_insert_inbox_dedup(&from_key, data) {
        Ok(Some(id)) => {
            tracing::info!(
                "receiver: stored in INBOX id={id} from {} ({} bytes)",
                &from_addr[..16],
                data.len()
            );
            true
        }
        Ok(None) => {
            tracing::debug!("receiver: duplicate mail from {} dropped", &from_addr[..16]);
            true
        }
        Err(e) => {
            tracing::error!("receiver: failed to store mail: {e}");
            false
        }
    }
}
