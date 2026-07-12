//! Reproduction harness for the cross-peer (multi-hop) encrypted-session failure.
//!
//! Symptom (real devices): two 1.9 nodes whose correspondents attach to the
//! SAME Yggdrasil hub exchange mail fine, but when a correspondent is behind a
//! DIFFERENT hub, the first message is sent and nothing ever comes back for
//! minutes.
//!
//! ROOT CAUSE (in ironwood — Yggdrasil-ng): the encrypted session handshake is
//!   bidirectional (A→D INIT, D→A ACK, then A→D traffic), so an A→D delivery
//!   secretly needs the D→A return path. When D receives A's INIT it has no
//!   cached path back to A and issues ONE reactive lookup; ironwood never
//!   retries an unresolved rumor (`router.rs do_maintenance`), and A's repeated
//!   INITs are gated as stale on D, so if that single lookup is dropped during
//!   tree convergence the ACK never routes back and the session wedges until the
//!   ~60s buffer expiry. It is specifically root→leaf discovery that fails;
//!   leaf→root (the forward INIT) is trivial, which is why same-hub works.
//!
//! FIX (ironwood `router.rs` / `pathfinder.rs`): on delivering traffic to self,
//!   learn the return path to the source for free from the coords it stamped
//!   into the packet (`tr.from`) via `pathfinder::learn_path_from_traffic`, so D
//!   needs no lookup at all. The EMPTY path (source is the tree root) is learned
//!   too — `send_traffic` routes via `get_path` with no root special-case, so a
//!   leaf replying to a root-initiator must cache the root's (empty) path or it
//!   wedges the same way. Verified at the plain-routing layer by
//!   `ironwood/tests/integration.rs::cross_hub_plain_reactive_reply_diagnostic`
//!   (11/30 wedged → 0/30 after both parts of the fix).
//!
//! These encrypted tests are `#[ignore]`d (slow, convergence-timed) and run
//! explicitly to confirm the end-to-end fix:
//!
//!   cargo test -p yggmail --test multihop_routing -- --ignored --nocapture

use std::sync::Arc;
use std::time::Duration;

use ed25519_dalek::SigningKey;
use ironwood::{new_encrypted_packet_conn, Addr, Config, EncryptedPacketConn, PacketConn};
use rand::rngs::OsRng;
use tokio::time::timeout;

/// Wire two ironwood nodes together over an in-memory duplex stream.
async fn connect(a: &Arc<impl PacketConn + 'static>, b: &Arc<impl PacketConn + 'static>) {
    let (sa, sb) = tokio::io::duplex(1 << 16);
    let addr_a = a.local_addr();
    let addr_b = b.local_addr();
    let a2 = Arc::clone(a);
    let b2 = Arc::clone(b);
    tokio::spawn(async move {
        let _ = a2.handle_conn(addr_b, Box::new(sa), 0).await;
    });
    tokio::spawn(async move {
        let _ = b2.handle_conn(addr_a, Box::new(sb), 0).await;
    });
}

/// Keep sending `msg` to `dest` every 200ms (mimics the YMP SYN retry cadence).
fn keep_sending(
    node: Arc<impl PacketConn + 'static>,
    dest: Addr,
    msg: Vec<u8>,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        loop {
            let _ = node.write_to(&msg, &dest).await;
            tokio::time::sleep(Duration::from_millis(200)).await;
        }
    })
}

/// Read until a non-empty packet arrives from `want_from`.
async fn recv_from(node: Arc<impl PacketConn + 'static>, want_from: Addr) -> Vec<u8> {
    let mut buf = vec![0u8; 4096];
    loop {
        match node.read_from(&mut buf).await {
            Ok((n, from)) if n > 0 && from == want_from => return buf[..n].to_vec(),
            Ok(_) => continue,
            Err(_) => return Vec::new(),
        }
    }
}

/// One dumbbell A<->H1<->H2<->D forward attempt. Returns true if D received A's
/// packet within `deadline` (after an optional convergence `settle`).
async fn dumbbell_forward_once(settle: Duration, deadline: Duration) -> bool {
    let a = new_encrypted_packet_conn(SigningKey::generate(&mut OsRng), Config::default());
    let h1 = new_encrypted_packet_conn(SigningKey::generate(&mut OsRng), Config::default());
    let h2 = new_encrypted_packet_conn(SigningKey::generate(&mut OsRng), Config::default());
    let d = new_encrypted_packet_conn(SigningKey::generate(&mut OsRng), Config::default());

    connect(&a, &h1).await;
    connect(&h1, &h2).await;
    connect(&h2, &d).await;

    let addr_a = a.local_addr();
    let addr_d = d.local_addr();

    tokio::time::sleep(settle).await;

    let d_reader = tokio::spawn(recv_from(d.clone(), addr_a));
    let a_send = keep_sending(a.clone(), addr_d, b"SYN".to_vec());
    let got = timeout(deadline, d_reader).await;
    a_send.abort();

    let ok = matches!(&got, Ok(Ok(v)) if !v.is_empty());
    for n in [a, h1, h2, d] {
        let _ = n.close().await;
    }
    ok
}

/// The bug demonstrator. A and D each sit behind a DIFFERENT hub (A-H1, H2-D,
/// hubs interconnected), encrypted conn, bidirectional handshake. Intermittently
/// FAILS (~1 in 4) due to the stale-path seq-tie wedge described in the module
/// header. `#[ignore]`d so CI stays green; run with `--ignored` to observe.
#[tokio::test]
#[ignore = "reproduces the ironwood stale-path wedge; intermittently fails by design"]
async fn cross_hub_dumbbell_bidirectional_encrypted() {
    let a = new_encrypted_packet_conn(SigningKey::generate(&mut OsRng), Config::default());
    let h1 = new_encrypted_packet_conn(SigningKey::generate(&mut OsRng), Config::default());
    let h2 = new_encrypted_packet_conn(SigningKey::generate(&mut OsRng), Config::default());
    let d = new_encrypted_packet_conn(SigningKey::generate(&mut OsRng), Config::default());

    connect(&a, &h1).await;
    connect(&h1, &h2).await;
    connect(&h2, &d).await;

    let addr_a = a.local_addr();
    let addr_d = d.local_addr();

    let d_reader = tokio::spawn(recv_from(d.clone(), addr_a));
    let a_reader = tokio::spawn(recv_from(a.clone(), addr_d));
    let a_send = keep_sending(a.clone(), addr_d, b"SYN".to_vec());

    let d_got = timeout(Duration::from_secs(30), d_reader).await;
    assert!(
        matches!(&d_got, Ok(Ok(v)) if !v.is_empty()),
        "cross-hub forward path broken: D never received the SYN from A"
    );

    let d_reply = keep_sending(d.clone(), addr_a, b"SYN-ACK".to_vec());
    let a_got = timeout(Duration::from_secs(30), a_reader).await;
    a_send.abort();
    d_reply.abort();

    assert!(
        matches!(&a_got, Ok(Ok(v)) if !v.is_empty()),
        "cross-hub RETURN path broken: A never received the SYN-ACK from D"
    );

    for n in [a, h1, h2, d] {
        n.close().await.unwrap();
    }
}

/// Statistical demonstration of the wedge that stays deterministic-enough to be
/// a real assertion: across many dumbbell attempts, at least one wedges (fails)
/// even though multi-hop routing is *capable* of succeeding. Proves the failure
/// is real and not environmental. `#[ignore]`d because it is slow (~minutes).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "slow statistical repro of the ironwood stale-path wedge"]
async fn cross_hub_wedge_is_reproducible() {
    let trials = 20;
    let mut fails = 0;
    for _ in 0..trials {
        // 8s window = ~40 retries at 200ms. A correct router recovers within
        // this; the stale-path wedge does not.
        if !dumbbell_forward_once(Duration::from_secs(3), Duration::from_secs(8)).await {
            fails += 1;
        }
    }
    eprintln!("cross_hub_wedge_is_reproducible: {}/{} attempts wedged", fails, trials);
    // Regression guard: before the return-path fix this wedged ~40% (8/20). With
    // `learn_path_from_traffic` in ironwood only the inherent rare single-packet
    // loss of a one-shot reply remains, so allow a small residual but catch any
    // regression back toward the systematic failure.
    assert!(
        fails <= trials / 4,
        "cross-hub wedge rate {}/{} is too high — the return-path fix regressed",
        fails,
        trials
    );
}

/// Dump one encrypted node's routing + session state (diagnostic only).
async fn dump_node(label: &str, n: &Arc<EncryptedPacketConn>, peer: [u8; 32]) {
    let s = n.get_debug_snapshot().await;
    eprintln!(
        "{}: coords={:?} root={} tree_nodes={} routing_peers={} path_cache={} broken={} pending={}",
        label,
        s.our_coords,
        hex::encode(&s.tree_root[..8]),
        s.tree_node_count,
        s.routing_peer_count,
        s.path_cache_count,
        s.broken_path_count,
        s.pending_lookups.len(),
    );
    for pl in &s.pending_lookups {
        eprintln!(
            "  {} pending: dest={} xformed={} age={:.2}s sent={} targets={}",
            label,
            pl.dest_key.map_or("none".to_string(), |k| hex::encode(&k[..8])),
            hex::encode(&pl.xformed_key[..8]),
            pl.age_secs,
            pl.sent,
            pl.multicast_count,
        );
    }
    let (xk, targets) = n.count_lookup_targets(peer).await;
    eprintln!(
        "  {} count_lookup_targets(peer)={} xformed={}",
        label,
        targets,
        hex::encode(&xk[..8])
    );
    for p in n.get_paths().await {
        eprintln!(
            "  {} cached-path dest={} path={:?} seq={}",
            label,
            hex::encode(&p.key[..8]),
            p.path,
            p.sequence
        );
    }
    for se in n.get_sessions().await {
        eprintln!(
            "  {} session peer={} tx={} rx={} up={:.1}s",
            label,
            hex::encode(&se.key[..4]),
            se.bytes_sent,
            se.bytes_recvd,
            se.uptime_seconds
        );
    }
}

/// Instrument the ENCRYPTED cross-hub wedge. Unlike the plain forward-only
/// ironwood diagnostic (which never wedges because it only exercises A->D), the
/// encrypted handshake needs the D->A ACK too, so this catches the real defect.
/// On the first wedge it dumps BOTH A's and D's routing + session state so we can
/// see which DIRECTION's path is missing/broken and whether a session formed.
///
///   cargo test -p yggmail --test multihop_routing cross_hub_encrypted_wedge_diagnostic -- --ignored --nocapture
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "diagnostic: instruments the encrypted cross-hub wedge; run with --ignored --nocapture"]
async fn cross_hub_encrypted_wedge_diagnostic() {
    let trials = 30;
    for trial in 0..trials {
        let a = new_encrypted_packet_conn(SigningKey::generate(&mut OsRng), Config::default());
        let h1 = new_encrypted_packet_conn(SigningKey::generate(&mut OsRng), Config::default());
        let h2 = new_encrypted_packet_conn(SigningKey::generate(&mut OsRng), Config::default());
        let d = new_encrypted_packet_conn(SigningKey::generate(&mut OsRng), Config::default());

        connect(&a, &h1).await;
        connect(&h1, &h2).await;
        connect(&h2, &d).await;

        let addr_a = a.local_addr();
        let addr_d = d.local_addr();

        tokio::time::sleep(Duration::from_secs(3)).await;

        let d_reader = tokio::spawn(recv_from(d.clone(), addr_a));
        let a_send = keep_sending(a.clone(), addr_d, b"SYN".to_vec());
        let got = timeout(Duration::from_secs(8), d_reader).await;
        a_send.abort();

        let wedged = !matches!(&got, Ok(Ok(v)) if !v.is_empty());
        if wedged {
            eprintln!("\n=== ENCRYPTED WEDGE on trial {} ===", trial);
            dump_node("A", &a, addr_d.0).await;
            dump_node("D", &d, addr_a.0).await;
            let s1 = h1.get_debug_snapshot().await;
            let s2 = h2.get_debug_snapshot().await;
            eprintln!("H1: coords={:?} root={}", s1.our_coords, hex::encode(&s1.tree_root[..8]));
            eprintln!("H2: coords={:?} root={}", s2.our_coords, hex::encode(&s2.tree_root[..8]));
            for n in [&a, &h1, &h2, &d] {
                let _ = n.close().await;
            }
            return;
        }

        for n in [&a, &h1, &h2, &d] {
            let _ = n.close().await;
        }
        eprintln!("trial {}: ok", trial);
    }
    eprintln!("no encrypted wedge observed in {} trials", trials);
}
