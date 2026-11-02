//! Приём входящей почты: транспорт → БД (INBOX).
//!
//! На время сосуществования транспортов слушаем оба: QUIC (узлы 1.8 и все
//! обновлённые) и YMP (уже выкаченные 1.9.0, которые умеют только его).
//! Когда YMP уйдёт, параметр `ymp` и вся его ветка удаляются.

use crate::quic::QuicMailTransport;
use crate::storage::SqliteStorage;
use crate::ymp::YmpSession;
use std::sync::Arc;
use tokio::sync::broadcast;
use tracing;

/// Чем кончилась укладка входящего письма.
///
/// Именно три исхода, а не два: дубликат и отказ БД обязаны расходиться.
/// Дубликат уже лежит в INBOX с прошлой доставки — его надо подтвердить, иначе
/// узел 1.8 будет слать одно и то же письмо вечно. Отказ подтверждать нельзя:
/// письмо нигде не сохранено, и повтор — единственный способ его не потерять.
/// Перечисление публичное, потому что `yggmail-mobile` — отдельный крейт со
/// своим циклом приёма, и разбор вариантов там должен быть тем же самым.
#[derive(Debug, PartialEq, Eq)]
pub enum Stored {
    /// Уложено впервые, `id` в INBOX.
    New(u32),
    /// Такое письмо уже есть — повторная укладка пропущена.
    Duplicate,
    /// Уложить не удалось.
    Failed,
}

/// Запустить фоновый приём. `ymp` — `None`, когда YMP уже удалён.
/// `imap_notify` будит IDLE-клиентов, когда в INBOX реально что-то легло.
pub fn spawn(
    storage: Arc<SqliteStorage>,
    quic: Arc<QuicMailTransport>,
    ymp: Option<Arc<YmpSession>>,
    imap_notify: broadcast::Sender<()>,
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
                    let durable = match store(&storage, from_key, &data) {
                        Stored::New(_) => {
                            // В INBOX появилось письмо — будим IDLE. Ошибка
                            // send() тут штатна: подписчиков нет, пока не
                            // подключён почтовый клиент.
                            let _ = imap_notify.send(());
                            true
                        }
                        // Дубликат durable, но будить некого: нового ничего
                        // не появилось.
                        Stored::Duplicate => true,
                        Stored::Failed => false,
                    };
                    if durable {
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

/// Уложить входящее письмо в INBOX.
///
/// Единственная точка, где принимается это решение: мобильный крейт крутит свой
/// цикл приёма, но зовёт эту же функцию и разбирает тот же `Stored` — чтобы две
/// копии логики не разошлись.
pub fn store(storage: &SqliteStorage, from_key: [u8; 32], data: &[u8]) -> Stored {
    let from_addr = crate::address::create_address(&from_key);
    match storage.mail_insert_inbox_dedup(&from_key, data) {
        Ok(Some(id)) => {
            tracing::info!(
                "receiver: stored in {} id={id} from {} ({} bytes)",
                crate::storage::inbound_mailbox(data),
                &from_addr[..16],
                data.len()
            );
            Stored::New(id)
        }
        Ok(None) => {
            tracing::debug!("receiver: duplicate mail from {} dropped", &from_addr[..16]);
            Stored::Duplicate
        }
        Err(e) => {
            tracing::error!("receiver: failed to store mail: {e}");
            Stored::Failed
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_db(name: &str) -> SqliteStorage {
        let path = std::env::temp_dir().join(format!(
            "yggmail_receiver_test_{}_{}.db",
            std::process::id(),
            name
        ));
        let _ = std::fs::remove_file(&path);
        SqliteStorage::open(&path.to_string_lossy(), None).unwrap()
    }

    /// Три исхода укладки должны именно расходиться. Слить дубликат с отказом
    /// в один «неуспех» — значит перестать подтверждать повтор, и узел 1.8
    /// будет слать то же письмо бесконечно.
    #[test]
    fn store_separates_new_from_duplicate() {
        let storage = temp_db("store_outcomes");
        let from = [0x7eu8; 32];
        let raw = b"Subject: hi\r\n\r\nbody\r\n";

        assert!(
            matches!(store(&storage, from, raw), Stored::New(_)),
            "first delivery must report New"
        );
        assert_eq!(
            store(&storage, from, raw),
            Stored::Duplicate,
            "the same bytes again must report Duplicate, not New and not Failed"
        );
    }
}
