//! Outbound queue sender: polls DB → readiness-gate → YMP → mark sent.
//! ponytail: simple poll loop, 30s base / 10s fast-retry interval. No backpressure or prioritisation yet.

use crate::storage::SqliteStorage;
use crate::ymp::YmpSession;
use std::sync::Arc;
use tokio::time::{sleep_until, Duration, Instant};
use tracing;
use yggdrasil::core::Core;
use yggdrasil::links::PeerEvent;

/// How long the readiness-gate waits for ≥1 "up" peer before deferring a send.
/// Tuned below the 30s base poll interval and far below the old ~75s cold-start stall.
const READINESS_WAIT: Duration = Duration::from_secs(20);

/// Start the outbound sender background task.
/// Polls the queue every `interval`, gates on peer readiness, then sends via YMP.
pub fn spawn(
    storage: Arc<SqliteStorage>,
    ymp: Arc<YmpSession>,
    core: Arc<Core>,
    base_interval: Duration,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let mut interval = base_interval;
        // Skip first tick so storage+ymp are fully initialised
        tokio::time::sleep(Duration::from_secs(2)).await;

        let notify = storage.queue_notify();
        loop {
            match process_queue(&storage, &ymp, &core).await {
                Ok(()) => {
                    // ponytail: success → back to base interval
                    interval = Duration::from_secs(30);
                }
                Err(_) => {
                    // ponytail: failure or deferred (no up peer) → fast retry (10s)
                    interval = Duration::from_secs(10);
                }
            }
            // Wake immediately when new mail is enqueued (queue_insert fires the
            // notify), else fall back to the poll interval. Notify stores a permit
            // if the enqueue happened while we were mid-process, so no wake is lost.
            tokio::select! {
                _ = tokio::time::sleep(interval) => {}
                _ = notify.notified() => {}
            }
        }
    })
}

async fn process_queue(
    storage: &SqliteStorage,
    ymp: &YmpSession,
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

            match ymp.send(dest_key, mail.mail.clone()).await {
                Ok(_msg_id) => {
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
                    tracing::warn!("sender: YMP send failed for #{id}: {e}", id = qm.id);
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
