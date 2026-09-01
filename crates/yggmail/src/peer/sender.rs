//! Outbound queue sender: polls DB → readiness-gate → QUIC → mark sent.
//! ponytail: simple poll loop, 30s base / 10s fast-retry interval. No backpressure or prioritisation yet.

use crate::quic::QuicMailTransport;
use crate::storage::SqliteStorage;
use std::sync::Arc;
use tokio::sync::broadcast;
use tokio::time::{Duration, Instant, sleep_until};
use tracing;
use yggdrasil::core::Core;
use yggdrasil::links::PeerEvent;

/// How long the readiness-gate waits for ≥1 "up" peer before deferring a send.
/// Tuned below the 30s base poll interval and far below the old ~75s cold-start stall.
const READINESS_WAIT: Duration = Duration::from_secs(20);

/// Start the outbound sender background task.
/// Polls the queue every `interval`, gates on peer readiness, then sends via QUIC.
///
/// `stop` is the shared shutdown signal (same broadcast channel the receiver and
/// path-warmer already subscribe to in the mobile crate). Racing it against
/// `process_queue` too — not just the idle sleep — matters because a single
/// large send can hold `process_queue` for up to ~20 minutes (the readiness-gate
/// wait plus QUIC delivery); a stop branch only on the sleep would leave this
/// task holding the storage/QUIC/Core `Arc`s for that long after `stop()`
/// returns. Cancelling mid-`process_queue` is safe to do: `queue_delete` only
/// runs on the `Ok(())` arm, so a cancelled send leaves the queue row and
/// Outbox mail intact and simply retries on next start. There is a narrow
/// window where a peer accepted the mail but we were cancelled before
/// de-queueing, producing a duplicate on restart; the receiver side already
/// dedups via `mail_insert_inbox_dedup`.
pub fn spawn(
    storage: Arc<SqliteStorage>,
    quic: Arc<QuicMailTransport>,
    core: Arc<Core>,
    base_interval: Duration,
    mut stop: broadcast::Receiver<()>,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let mut interval = base_interval;
        // Skip first tick so storage+quic are fully initialised
        tokio::time::sleep(Duration::from_secs(2)).await;

        let notify = storage.queue_notify();
        loop {
            tokio::select! {
                _ = stop.recv() => break,
                result = process_queue(&storage, &quic, &core) => {
                    match result {
                        Ok(()) => {
                            // ponytail: success → back to base interval
                            interval = Duration::from_secs(30);
                        }
                        Err(_) => {
                            // ponytail: failure or deferred (no up peer) → fast retry (10s)
                            interval = Duration::from_secs(10);
                        }
                    }
                }
            }
            // Wake immediately when new mail is enqueued (queue_insert fires the
            // notify), else fall back to the poll interval. Notify stores a permit
            // if the enqueue happened while we were mid-process, so no wake is lost.
            tokio::select! {
                _ = stop.recv() => break,
                _ = tokio::time::sleep(interval) => {}
                _ = notify.notified() => {}
            }
        }
    })
}

async fn process_queue(
    storage: &SqliteStorage,
    quic: &QuicMailTransport,
    core: &Arc<Core>,
) -> Result<(), Box<dyn std::error::Error>> {
    let destinations = storage.queue_list_destinations()?;
    if destinations.is_empty() {
        return Ok(());
    }

    for dest_hex in &destinations {
        let dest_key: [u8; 32] = match hex::decode(dest_hex) {
            Ok(b) if b.len() == 32 => {
                let mut k = [0u8; 32];
                k.copy_from_slice(&b);
                k
            }
            _ => {
                tracing::warn!("sender: invalid destination hex: {dest_hex}");
                continue;
            }
        };

        // Самому себе — локально, до readiness-gate.
        if dest_key == *core.public_key() {
            deliver_to_self(storage, dest_hex, &dest_key)?;
            continue;
        }

        let pending = storage.queue_get_for_destination(dest_hex)?;
        for qm in &pending {
            // Fetch the mail body from Outbox
            let mail = match storage.mail_get("Outbox", qm.id)? {
                Some(m) => m,
                None => {
                    // Orphaned queue entry — clean up
                    let _ = storage.queue_delete(dest_hex, "Outbox", qm.id);
                    continue;
                }
            };

            tracing::info!(
                "sender: delivering mail #{id} to {dest}",
                id = qm.id,
                dest = &dest_hex[..8]
            );

            // Readiness-gate per send: re-check ≥1 peer up before delivery. On
            // cold start / mesh partition the gate defers (mail stays queued)
            // instead of burning ~60s of SYN/DATA retries into the void.
            // Returning Err selects the 10s fast-retry cadence so delivery
            // resumes promptly once the mesh converges.
            if !wait_for_up_peer(core, Instant::now() + READINESS_WAIT).await {
                tracing::info!(
                    "sender: no up peer for mail #{id} within {secs}s — deferring",
                    id = qm.id,
                    secs = READINESS_WAIT.as_secs()
                );
                return Err("deferred: no up peer".into());
            }

            match quic.send(dest_key, mail.mail.clone()).await {
                Ok(()) => {
                    // Delete-first: drop the queue entry while the mail is still in
                    // Outbox so it matches (dest, "Outbox", id). Delivery is already
                    // confirmed, so de-queuing is the durable "done" marker. Doing
                    // mail_move first instead wedges delivery: the queue FK's
                    // ON UPDATE CASCADE rewrites the row to ("Sent", id), the delete
                    // misses, and a reused Outbox id colliding with an existing Sent
                    // id makes mail_move fail — re-sending every poll (dup spam).
                    storage.queue_delete(dest_hex, "Outbox", qm.id)?;
                    // A group mail is ONE Outbox row with MULTIPLE queue entries
                    // (one per recipient). Move it to Sent only after the LAST
                    // recipient is de-queued — moving it earlier makes
                    // mail_get("Outbox") return None for the remaining recipients,
                    // which drops them as "orphaned". Sent move stays best-effort.
                    if storage.queue_count_for_mail("Outbox", qm.id)? == 0 {
                        let _ = storage.mail_move("Outbox", "Sent", qm.id);
                    }
                    tracing::info!("sender: mail #{id} delivered, de-queued", id = qm.id);
                }
                Err(e) => {
                    tracing::warn!("sender: QUIC send failed for #{id}: {e}", id = qm.id);
                    // Will retry on next poll cycle
                }
            }
        }
    }

    Ok(())
}

/// Wait until at least one peer is "up", or until `deadline` elapses.
///
/// Fast-path: a warm mesh returns immediately (no regression on the working case).
/// Otherwise subscribes to peer events and waits for a `Connected` event, with a
/// re-check after subscribe to close the TOCTOU window (event fired between the
/// initial check and the subscribe). Returns `false` only on deadline.
async fn wait_for_up_peer(core: &Arc<Core>, deadline: Instant) -> bool {
    // Fast-path — warm mesh, ~0 latency.
    if has_up_peer(core).await {
        return true;
    }
    // Event-driven wait — no busy-poll.
    let mut rx = core.subscribe_peer_events();
    // Close the TOCTOU window: a Connected event may have fired between the
    // check above and subscribe(). Re-check, then trust subsequent events.
    if has_up_peer(core).await {
        return true;
    }
    loop {
        tokio::select! {
            ev = rx.recv() => {
                if matches!(ev, Ok(PeerEvent::Connected { .. })) && has_up_peer(core).await {
                    return true;
                }
                // Disconnected / RecvError(Lagged|Closed) → keep waiting until deadline.
            }
            _ = sleep_until(deadline) => return false,
        }
    }
}

/// Whether any currently-known peer link is in the "up" state.
async fn has_up_peer(core: &Core) -> bool {
    core.get_peers().await.iter().any(|p| p.up)
}

/// Доставить письма, адресованные собственному ключу, минуя сеть.
///
/// Повторяет ветку `isSelfSend` из Go (`smtpsender/sender.go:326`). Стоит до
/// readiness-gate: доставка самому себе не зависит от наличия пиров, а попытка
/// дозвониться по QUIC до самого себя — это в лучшем случае бессмысленный
/// круг, в худшем зависание до idle-таймаута.
fn deliver_to_self(
    storage: &SqliteStorage,
    dest_hex: &str,
    local_key: &[u8; 32],
) -> Result<(), Box<dyn std::error::Error>> {
    for qm in &storage.queue_get_for_destination(dest_hex)? {
        let Some(mail) = storage.mail_get("Outbox", qm.id)? else {
            let _ = storage.queue_delete(dest_hex, "Outbox", qm.id);
            continue;
        };
        // Тот же путь, что у приёмника: дедуп защищает от повторной укладки,
        // если снятие с очереди не доехало и опрос вернулся к тому же письму.
        storage.mail_insert_inbox_dedup(local_key, &mail.mail)?;
        storage.queue_delete(dest_hex, "Outbox", qm.id)?;
        if storage.queue_count_for_mail("Outbox", qm.id)? == 0 {
            let _ = storage.mail_move("Outbox", "Sent", qm.id);
        }
        tracing::info!("sender: mail #{id} delivered locally (self-send)", id = qm.id);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core_conn::testutil::MemPacketConn;
    use ed25519_dalek::SigningKey;
    use ironwood::types::PacketConn;

    fn temp_db(name: &str) -> SqliteStorage {
        let path = std::env::temp_dir().join(format!(
            "yggmail_sender_test_{}_{}.db",
            std::process::id(),
            name
        ));
        let _ = std::fs::remove_file(&path);
        SqliteStorage::open(&path.to_string_lossy(), None).unwrap()
    }

    /// Письмо самому себе кладётся в INBOX и снимается с очереди, не касаясь сети.
    #[test]
    fn self_send_lands_in_inbox_and_leaves_the_queue() {
        let storage = temp_db("self_send");
        let me = [0x42u8; 32];
        let me_hex = hex::encode(me);
        let addr = crate::address::create_address(&me);

        let id = storage
            .mail_insert("Outbox", b"Subject: note\r\n\r\nto myself\r\n")
            .unwrap();
        storage
            .queue_insert(&me_hex, "Outbox", id, &addr, &addr)
            .unwrap();

        deliver_to_self(&storage, &me_hex, &me).expect("local delivery ok");

        assert!(
            !storage.mail_list("INBOX").unwrap().is_empty(),
            "self-sent mail must land in INBOX"
        );
        assert!(
            storage.queue_list_destinations().unwrap().is_empty(),
            "queue must be drained"
        );
        assert!(
            !storage.mail_list("Sent").unwrap().is_empty(),
            "the last recipient moves the mail to Sent"
        );
    }

    fn test_core(seed: u8) -> Arc<Core> {
        // Core::new is synchronous and binds no sockets — init_links()/start()
        // are never called, so this is a plain in-memory node for tests.
        let key = SigningKey::from_bytes(&[seed; 32]);
        Core::new(key, yggdrasil::config::Config::default())
    }

    fn test_quic(seed_a: u8, seed_b: u8) -> Arc<QuicMailTransport> {
        let key_a = SigningKey::from_bytes(&[seed_a; 32]);
        let key_b = SigningKey::from_bytes(&[seed_b; 32]);
        let (conn_a, _conn_b) = MemPacketConn::pair(key_a.clone(), key_b);
        QuicMailTransport::new(conn_a as Arc<dyn PacketConn>, &key_a).unwrap()
    }

    /// Task 14: `stop` must terminate the sender while it is idling in the
    /// sleep(interval)/notify select — the branch the brief names directly.
    /// Empty queue → `process_queue` returns immediately, parking the loop in
    /// the second select before the signal is sent.
    #[tokio::test(flavor = "multi_thread")]
    async fn stop_signal_terminates_sender_idling_in_the_sleep() {
        let storage = Arc::new(temp_db("stop_idle"));
        let quic = test_quic(0x51, 0x52);
        let core = test_core(0x53);

        let (stop_tx, stop_rx) = broadcast::channel(1);
        let handle = spawn(storage, quic, core, Duration::from_secs(30), stop_rx);

        // Past the 2s startup delay, with an empty queue process_queue()
        // returns at once, so by now the loop is parked in sleep(30s)/notify.
        tokio::time::sleep(Duration::from_millis(2500)).await;
        stop_tx.send(()).unwrap();

        tokio::time::timeout(Duration::from_secs(5), handle)
            .await
            .expect("sender must exit promptly after stop while idling in sleep()")
            .expect("sender task must not panic");
    }

    /// Task 14, ruling 2: a stop branch on the sleep alone is not enough —
    /// `process_queue` itself can block for up to ~20s in `wait_for_up_peer`
    /// (longer still with Task 13's size-scaled dialog budget once a send is
    /// underway). Queue mail to a destination that never comes "up" so
    /// `process_queue` is genuinely parked inside that wait, then confirm the
    /// signal cuts it short well before the 20s readiness deadline.
    #[tokio::test(flavor = "multi_thread")]
    async fn stop_signal_terminates_sender_blocked_in_process_queue() {
        let storage = Arc::new(temp_db("stop_mid_process"));
        let quic = test_quic(0x61, 0x62);
        let core = test_core(0x63);

        let dest = [0x99u8; 32];
        let dest_hex = hex::encode(dest);
        let from = crate::address::create_address(core.public_key());
        let to = crate::address::create_address(&dest);
        let id = storage
            .mail_insert("Outbox", b"Subject: never delivered\r\n\r\nhi\r\n")
            .unwrap();
        storage
            .queue_insert(&dest_hex, "Outbox", id, &from, &to)
            .unwrap();

        let (stop_tx, stop_rx) = broadcast::channel(1);
        let handle = spawn(storage, quic, core, Duration::from_secs(30), stop_rx);

        // Past the 2s startup delay and into wait_for_up_peer's up-to-20s wait
        // (no peer will ever come up in this test).
        tokio::time::sleep(Duration::from_millis(2500)).await;
        stop_tx.send(()).unwrap();

        // READINESS_WAIT is 20s — a prompt exit here proves cancellation cut
        // process_queue short rather than letting it run to its own timeout.
        tokio::time::timeout(Duration::from_secs(5), handle)
            .await
            .expect("sender must exit promptly even while blocked inside process_queue")
            .expect("sender task must not panic");
    }
}
