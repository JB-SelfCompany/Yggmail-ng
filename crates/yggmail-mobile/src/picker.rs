//! Public-peer picker, ported from Huginn (`src/picker.rs`, Nov 2026).
//!
//! Two stages, like the core picks a parent:
//! A. time TCP connects to every catalog peer through the ISP, keep the best `A_TOP`;
//! B. link those peers for real, wait for their ancestry in the tree, then rank by
//!    `RTT x (depth + 1)` on the root most links agree on.
//!
//! Differences from Huginn: only `tls`/`tcp` (Tyr builds Yggdrasil-ng without ws/quic links),
//! no ICMP (stage B latency is the core's own RTT), and the catalog JSON comes from the caller.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use serde::Deserialize;
use tokio::net::{TcpStream, lookup_host};
use tokio::sync::Semaphore;
use tokio::task::JoinSet;
use url::{Host, Url};
use yggdrasil::core::Core;
use yggdrasil::links::LinkPeerInfo;

/// A switch needs the best score to beat the current one by more than this.
const HYSTERESIS: f64 = 0.15;
const MIN_UPTIME: f64 = 0.90;
/// The link schemes this build of the core can dial.
const SCHEMES: [&str; 2] = ["tls", "tcp"];

pub const REASON_CURRENT_BEST: &str = "current_best";
pub const REASON_SMALL_GAIN: &str = "small_gain";
pub const REASON_NONE_PASSED: &str = "none_passed";

const A_TOP: usize = 8;
const A_PROBES: usize = 5;
const A_TIMEOUT: Duration = Duration::from_secs(3);
const A_WORKERS: usize = 32;
const MAX_CANDIDATES: usize = 500;
const LINK_UP_TIMEOUT: Duration = Duration::from_secs(20);
const SETTLE: Duration = Duration::from_secs(2);
/// After the links are up, how long to wait for each one's ancestry to reach a root.
const TREE_WAIT: Duration = Duration::from_secs(10);
const MAX_LOSS_A: f64 = 40.0;
/// Link poll period, also how often a waiting step looks at the cancel flag.
const POLL: Duration = Duration::from_millis(500);

pub const STAGE_PROVIDER: &str = "provider";
pub const STAGE_YGGDRASIL: &str = "yggdrasil";

#[derive(Debug, PartialEq)]
pub enum PickError {
    Cancelled,
    Other(String),
}

impl std::fmt::Display for PickError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PickError::Cancelled => f.write_str("cancelled"),
            PickError::Other(text) => f.write_str(text),
        }
    }
}

/// Runs `fut` unless `cancel` is set first; then it is dropped and the result is `Cancelled`.
async fn guard<T>(cancel: &AtomicBool, fut: impl std::future::Future<Output = T>) -> Result<T, PickError> {
    let cancelled = async {
        while !cancel.load(Ordering::Relaxed) {
            tokio::time::sleep(POLL).await;
        }
    };
    tokio::select! {
        v = fut => Ok(v),
        () = cancelled => Err(PickError::Cancelled),
    }
}

/// TCP connect timings in ms, in arrival order; lost probes only count in `sent`.
#[derive(Clone, Debug)]
struct Stats {
    sent: usize,
    rtts: Vec<f64>,
}

/// Linear-interpolated percentile of an ascending slice.
fn pct(sorted: &[f64], q: f64) -> Option<f64> {
    let n = sorted.len();
    if n == 0 {
        return None;
    }
    let k = (n - 1) as f64 * q;
    let f = k.floor() as usize;
    let c = (f + 1).min(n - 1);
    Some(sorted[f] + (sorted[c] - sorted[f]) * (k - f as f64))
}

impl Stats {
    fn recv(&self) -> usize {
        self.rtts.len()
    }

    fn loss_pct(&self) -> f64 {
        if self.sent == 0 {
            return 100.0;
        }
        100.0 * (self.sent - self.recv()) as f64 / self.sent as f64
    }

    /// Milliseconds-ish, lower is better; INFINITY means failed.
    fn score(&self, max_loss: f64) -> f64 {
        let mut s = self.rtts.clone();
        s.sort_by(f64::total_cmp);
        let (Some(p50), Some(p95)) = (pct(&s, 0.5), pct(&s, 0.95)) else { return f64::INFINITY };
        if self.loss_pct() > max_loss {
            return f64::INFINITY;
        }
        let jitter = if self.rtts.len() < 2 {
            0.0
        } else {
            self.rtts.windows(2).map(|w| (w[0] - w[1]).abs()).sum::<f64>() / (self.rtts.len() - 1) as f64
        };
        p50 + 2.0 * jitter + 0.5 * (p95 - p50) + 10.0 * self.loss_pct()
    }
}

async fn tcp_probe(addr: SocketAddr, count: usize, timeout: Duration) -> Stats {
    let mut rtts = Vec::with_capacity(count);
    for i in 0..count {
        let t0 = Instant::now();
        if matches!(tokio::time::timeout(timeout, TcpStream::connect(addr)).await, Ok(Ok(_))) {
            rtts.push(t0.elapsed().as_secs_f64() * 1000.0);
        }
        if i + 1 < count {
            tokio::time::sleep(Duration::from_millis(200)).await;
        }
    }
    Stats { sent: count, rtts }
}

#[derive(Clone, Debug)]
pub struct Candidate {
    pub uri: String,
    pub host: String,
    pub country: String,
    /// Address stage A reached it at; None until probed.
    pub ip: Option<IpAddr>,
}

/// Why a row that came up still cannot be used.
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum RowReason {
    /// Its tree has another root than most links: a split-off part of the network.
    OtherNetwork,
    /// Its ancestry did not reach a root in time.
    NoTree,
}

#[derive(Clone, Debug)]
pub struct Row {
    pub uri: String,
    pub host: String,
    pub country: String,
    /// The core's RTT to it; 0 when the link never came up.
    pub latency_ms: f64,
    pub score: f64,
    /// Hops from this peer to the tree root.
    pub depth: Option<usize>,
    pub reason: Option<RowReason>,
    pub ip: Option<IpAddr>,
}

#[derive(Clone, Debug, PartialEq)]
pub enum Verdict {
    Keep(&'static str),
    /// `gain_pct` is None when the current peer failed the check, so there is nothing to compare with.
    Switch { uri: String, gain_pct: Option<u32> },
}

impl Verdict {
    pub fn switch_uri(&self) -> Option<&str> {
        match self {
            Verdict::Switch { uri, .. } => Some(uri),
            Verdict::Keep(_) => None,
        }
    }
}

#[derive(Clone, Debug)]
pub struct PickReport {
    /// Stage-B candidates, best first.
    pub rows: Vec<Row>,
    pub verdict: Verdict,
    /// Standby peer for the one this pick leaves enabled.
    pub backup: Option<String>,
}

/// What stage B learned about one up link.
#[derive(Clone, Debug)]
struct Probe {
    core_ms: f64,
    tree: Option<([u8; 32], usize)>,
}

#[derive(Deserialize)]
struct Entry {
    #[serde(default)]
    up: bool,
    #[serde(default)]
    key: Option<String>,
    // Option: the list sometimes has `"states": null`, which a plain String rejects.
    #[serde(default)]
    states: Option<String>,
}

/// Lowercased `scheme://host:port`, the identity of a peer regardless of its query.
fn base(u: &Url) -> Option<String> {
    Some(format!("{}://{}:{}", u.scheme(), u.host_str()?, u.port_or_known_default()?).to_lowercase())
}

/// Share of `*` among the last 100 state characters; 0 when there is no history.
fn uptime(states: &str) -> f64 {
    let tail: Vec<char> = states.chars().rev().take(100).collect();
    if tail.is_empty() {
        return 0.0;
    }
    tail.iter().filter(|&&c| c == '*').count() as f64 / tail.len() as f64
}

/// Usable catalog peers, minus `skip` (already configured or disabled), sorted by uri.
pub fn candidates(json: &str, skip: &[String]) -> Result<Vec<Candidate>, String> {
    let files: BTreeMap<String, BTreeMap<String, Entry>> = serde_json::from_str(json).map_err(|e| e.to_string())?;
    let skip: HashSet<String> = skip.iter().filter_map(|s| Url::parse(s.trim()).ok().and_then(|u| base(&u))).collect();
    let mut out: Vec<(String, Candidate)> = Vec::new();
    for (file, peers) in &files {
        let country = file.strip_suffix(".md").unwrap_or(file).replace('-', " ");
        for (uri, e) in peers {
            if !e.up {
                continue;
            }
            let Ok(u) = Url::parse(uri.trim()) else { continue };
            let (Some(b), Some(host)) = (base(&u), u.host_str().filter(|h| !h.is_empty())) else {
                continue;
            };
            let up = uptime(e.states.as_deref().unwrap_or_default());
            if !SCHEMES.contains(&u.scheme()) || up < MIN_UPTIME || skip.contains(&b) {
                continue;
            }
            // Only a well-formed key is pinned: anything else could inject query parameters.
            let key = e.key.as_deref().filter(|k| k.len() == 64 && k.bytes().all(|b| b.is_ascii_hexdigit()));
            let mut full = uri.trim().to_string();
            if let Some(k) = key.filter(|_| !u.query_pairs().any(|(n, _)| n == "key")) {
                // Into the query, before any #fragment.
                let at = full.find('#').unwrap_or(full.len());
                let sep = if u.query().is_some() { '&' } else { '?' };
                full.insert_str(at, &format!("{sep}key={k}"));
            }
            out.push((b, Candidate { uri: full, host: host.to_string(), country: country.clone(), ip: None }));
        }
    }
    out.sort_by(|a, b| a.1.uri.cmp(&b.1.uri));
    let mut seen = HashSet::new();
    Ok(out.into_iter().filter(|(b, _)| seen.insert(b.clone())).map(|(_, c)| c).take(MAX_CANDIDATES).collect())
}

/// A routable internet address. The catalog decides what stage A connects to, so it must not point
/// the probes at this device, the LAN or the mesh itself.
pub fn is_public(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            let [a, b, ..] = v4.octets();
            !(v4.is_loopback() || v4.is_private() || v4.is_link_local() || v4.is_unspecified() || v4.is_broadcast() || v4.is_multicast()
                // 100.64.0.0/10, carrier-grade NAT.
                || (a == 100 && (64..128).contains(&b)))
        }
        IpAddr::V6(v6) => {
            let first = v6.segments()[0];
            !(v6.is_loopback() || v6.is_unspecified() || v6.is_multicast()
                // fc00::/7 unique local, fe80::/10 link-local, 200::/7 Yggdrasil.
                || (first & 0xfe00) == 0xfc00 || (first & 0xffc0) == 0xfe80 || (first & 0xfe00) == 0x0200)
        }
    }
}

pub fn decide(current: f64, rows: &[Row]) -> Verdict {
    let Some(best) = rows.iter().min_by(|a, b| a.score.total_cmp(&b.score)) else {
        return Verdict::Keep(REASON_NONE_PASSED);
    };
    if best.score.is_infinite() {
        Verdict::Keep(REASON_NONE_PASSED)
    } else if current.is_infinite() {
        Verdict::Switch { uri: best.uri.clone(), gain_pct: None }
    } else if best.score >= current {
        Verdict::Keep(REASON_CURRENT_BEST)
    } else if best.score > current * (1.0 - HYSTERESIS) {
        Verdict::Keep(REASON_SMALL_GAIN)
    } else {
        Verdict::Switch { uri: best.uri.clone(), gain_pct: Some(((1.0 - best.score / current) * 100.0).round() as u32) }
    }
}

/// Root and hop count from `key` to it, following `parent` links; None on a loop or a missing ancestor.
fn tree_info(tree: &HashMap<[u8; 32], [u8; 32]>, key: &[u8; 32]) -> Option<([u8; 32], usize)> {
    let mut next = *key;
    // More steps than nodes means a loop.
    for depth in 0..=tree.len() {
        let parent = tree.get(&next)?;
        if *parent == next {
            return Some((next, depth));
        }
        next = *parent;
    }
    None
}

/// The root most links agree on. Not the smallest key: a split-off part elects its own root, which may
/// be smaller. Ties go to the current peer's root, then to the smallest key so the result is stable.
fn network_root(roots: &[[u8; 32]], current: Option<[u8; 32]>) -> Option<[u8; 32]> {
    let mut counts: HashMap<[u8; 32], usize> = HashMap::new();
    for r in roots {
        *counts.entry(*r).or_default() += 1;
    }
    counts
        .into_iter()
        .max_by(|(ra, a), (rb, b)| a.cmp(b).then((Some(*ra) == current).cmp(&(Some(*rb) == current))).then(rb.cmp(ra)))
        .map(|(r, _)| r)
}

fn same_net(a: IpAddr, b: IpAddr) -> bool {
    match (a, b) {
        (IpAddr::V4(a), IpAddr::V4(b)) => a.octets()[..3] == b.octets()[..3],
        (IpAddr::V6(a), IpAddr::V6(b)) => a.segments()[..3] == b.segments()[..3],
        (IpAddr::V4(_), IpAddr::V6(_)) | (IpAddr::V6(_), IpAddr::V4(_)) => false,
    }
}

/// The best usable row other than `main` on another /24 (IPv4) or /48 (IPv6): two peers at one hoster
/// tend to fail together. Rows come best first.
fn pick_backup(rows: &[Row], main: &str, main_ip: Option<IpAddr>) -> Option<String> {
    let main_ip = main_ip?;
    rows.iter()
        .filter(|r| r.uri != main && r.score.is_finite())
        .find(|r| r.ip.is_some_and(|ip| !same_net(ip, main_ip)))
        .map(|r| r.uri.clone())
}

/// Scores every candidate and the configured peers like the core picks a parent: latency x (depth + 1).
fn rank(top: &[(Candidate, f64)], configured: &[String], probes: &HashMap<String, Probe>) -> (Vec<Row>, f64) {
    let roots: Vec<[u8; 32]> = probes.values().filter_map(|p| p.tree.map(|t| t.0)).collect();
    let current_root = configured.iter().find_map(|u| probes.get(u)?.tree.map(|t| t.0));
    let root = network_root(&roots, current_root);
    let judge = |p: &Probe| match p.tree {
        None => (f64::INFINITY, Some(RowReason::NoTree)),
        Some((r, _)) if Some(r) != root => (f64::INFINITY, Some(RowReason::OtherNetwork)),
        Some(_) if p.core_ms <= 0.0 => (f64::INFINITY, None),
        Some((_, depth)) => (p.core_ms * (depth + 1) as f64, None),
    };
    let mut rows: Vec<Row> = top
        .iter()
        .map(|(c, _)| {
            let p = probes.get(&c.uri);
            let (score, reason) = p.map_or((f64::INFINITY, None), judge);
            Row {
                uri: c.uri.clone(),
                host: c.host.clone(),
                country: c.country.clone(),
                latency_ms: p.map_or(0.0, |p| p.core_ms),
                score,
                depth: p.and_then(|p| p.tree.map(|t| t.1)),
                reason,
                ip: c.ip,
            }
        })
        .collect();
    rows.sort_by(|a, b| a.score.total_cmp(&b.score));
    let current = configured.iter().filter_map(|u| probes.get(u)).map(|p| judge(p).0).fold(f64::INFINITY, f64::min);
    (rows, current)
}

/// The host as an address when it is an IP literal. Non-special schemes (tcp, tls) leave an IPv4
/// literal as a domain, hence the parse.
fn literal_ip(u: &Url) -> Option<IpAddr> {
    match u.host()? {
        Host::Ipv4(ip) => Some(IpAddr::V4(ip)),
        Host::Ipv6(ip) => Some(IpAddr::V6(ip)),
        Host::Domain(d) => d.parse().ok(),
    }
}

/// Prefers IPv4.
async fn resolve(u: &Url, port: u16) -> Option<IpAddr> {
    if let Some(ip) = literal_ip(u) {
        return Some(ip);
    }
    let addrs: Vec<SocketAddr> = tokio::time::timeout(A_TIMEOUT, lookup_host((u.host_str()?, port))).await.ok()?.ok()?.collect();
    addrs.iter().find(|a| a.is_ipv4()).or(addrs.first()).map(|a| a.ip())
}

/// Stage-A score of one catalog endpoint through the ISP; None when it does not resolve, resolves to a
/// non-public address, or answers fewer than 3 connects.
async fn probe_isp(u: &Url) -> Option<(f64, IpAddr)> {
    let port = u.port_or_known_default()?;
    let ip = resolve(u, port).await?;
    if !is_public(ip) {
        return None;
    }
    let st = tcp_probe(SocketAddr::new(ip, port), A_PROBES, A_TIMEOUT).await;
    (st.recv() >= 3).then(|| (st.score(MAX_LOSS_A), ip))
}

async fn stage_a(cands: Vec<Candidate>, progress: &impl Fn(&str, usize, usize), cancel: &AtomicBool) -> Result<Vec<(Candidate, f64)>, PickError> {
    let total = cands.len();
    let workers = Arc::new(Semaphore::new(A_WORKERS));
    let mut set: JoinSet<Option<(Candidate, f64)>> = JoinSet::new();
    for mut c in cands {
        let workers = workers.clone();
        set.spawn(async move {
            let _permit = workers.acquire_owned().await.ok()?;
            let (score, ip) = probe_isp(&Url::parse(&c.uri).ok()?).await?;
            c.ip = Some(ip);
            Some((c, score))
        });
    }
    progress(STAGE_PROVIDER, 0, total);
    let mut ok = Vec::new();
    let mut done = 0;
    // Dropping the set on cancel aborts the rest.
    while let Some(r) = guard(cancel, set.join_next()).await? {
        done += 1;
        if let Ok(Some(hit)) = r {
            ok.push(hit);
        }
        progress(STAGE_PROVIDER, done, total);
    }
    ok.sort_by(|a, b| a.1.total_cmp(&b.1));
    ok.truncate(A_TOP);
    Ok(ok)
}

async fn stage_b(core: &Core, configured: &[String], top: &[(Candidate, f64)], progress: &impl Fn(&str, usize, usize), cancel: &AtomicBool) -> Result<PickReport, PickError> {
    progress(STAGE_YGGDRASIL, 0, top.len());
    for (c, _) in top {
        if let Err(e) = guard(cancel, core.add_peer(&c.uri)).await? {
            tracing::debug!("picker: add probe peer {}: {e}", c.uri);
        }
    }
    let is_candidate = |uri: &str| top.iter().any(|(c, _)| c.uri == uri);
    let probed = |l: &LinkPeerInfo| l.up && !l.inbound && (is_candidate(&l.uri) || configured.contains(&l.uri));
    let deadline = Instant::now() + LINK_UP_TIMEOUT;
    loop {
        let links = guard(cancel, core.get_peers()).await?;
        let up = top.iter().filter(|(c, _)| links.iter().any(|l| l.up && l.uri == c.uri)).count();
        progress(STAGE_YGGDRASIL, up, top.len());
        if up == top.len() || Instant::now() >= deadline {
            break;
        }
        guard(cancel, tokio::time::sleep(POLL)).await?;
    }
    guard(cancel, tokio::time::sleep(SETTLE)).await?;

    // Each peer sends us its ancestry when the link comes up; wait until every probed one reaches a root.
    let deadline = Instant::now() + TREE_WAIT;
    let (links, tree) = loop {
        let links = guard(cancel, core.get_peers()).await?;
        let tree: HashMap<[u8; 32], [u8; 32]> = guard(cancel, core.get_tree()).await?.into_iter().map(|e| (e.key, e.parent)).collect();
        let pending = links.iter().any(|l| probed(l) && tree_info(&tree, &l.key).is_none());
        if !pending || Instant::now() >= deadline {
            break (links, tree);
        }
        guard(cancel, tokio::time::sleep(POLL)).await?;
    };
    let probes: HashMap<String, Probe> = links
        .iter()
        .filter(|l| probed(l))
        .map(|l| (l.uri.clone(), Probe { core_ms: l.latency_ms, tree: tree_info(&tree, &l.key) }))
        .collect();

    let (rows, current) = rank(top, configured, &probes);
    let verdict = decide(current, &rows);
    // The backup stands in for whichever peer stays enabled: the winner, or the current one on Keep.
    let main_ip = match verdict.switch_uri() {
        Some(u) => rows.iter().find(|r| r.uri == u).and_then(|r| r.ip),
        None => match configured.first().and_then(|u| Url::parse(u.trim()).ok()) {
            Some(u) => match u.port_or_known_default() {
                Some(port) => resolve(&u, port).await,
                None => None,
            },
            None => None,
        },
    };
    let main = verdict.switch_uri().or(configured.first().map(String::as_str)).unwrap_or_default();
    let backup = pick_backup(&rows, main, main_ip);
    Ok(PickReport { rows, verdict, backup })
}

/// The two-stage search. Probe links are removed on every exit except a `Switch` winner, which stays
/// linked so applying it costs no reconnect.
pub async fn run(
    core: Arc<Core>,
    catalog_json: &str,
    enabled: Vec<String>,
    disabled: Vec<String>,
    progress: impl Fn(&str, usize, usize),
    cancel: &AtomicBool,
) -> Result<PickReport, PickError> {
    let skip: Vec<String> = enabled.iter().chain(&disabled).cloned().collect();
    let top = stage_a(candidates(catalog_json, &skip).map_err(PickError::Other)?, &progress, cancel).await?;
    let result = stage_b(&core, &enabled, &top, &progress, cancel).await;
    let keep = result.as_ref().ok().and_then(|r| r.verdict.switch_uri());
    // Rust has no async Drop: release explicitly, on every exit.
    for (c, _) in top.iter().filter(|(c, _)| Some(c.uri.as_str()) != keep) {
        if let Err(e) = core.remove_peer(&c.uri).await {
            tracing::debug!("picker: remove probe peer {}: {e}", c.uri);
        }
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cand(uri: &str) -> Candidate {
        Candidate { uri: uri.into(), host: uri.into(), country: "x".into(), ip: None }
    }

    fn row(uri: &str, score: f64) -> Row {
        Row { uri: uri.into(), host: uri.into(), country: String::new(), latency_ms: score, score, depth: None, reason: None, ip: None }
    }

    fn k(b: u8) -> [u8; 32] {
        [b; 32]
    }

    fn probe(core_ms: f64, tree: Option<([u8; 32], usize)>) -> Probe {
        Probe { core_ms, tree }
    }

    #[test]
    fn tree_info_walks_to_the_root() {
        // 1 is the root; 3 -> 2 -> 1.
        let tree = HashMap::from([(k(1), k(1)), (k(2), k(1)), (k(3), k(2))]);
        assert_eq!(tree_info(&tree, &k(1)), Some((k(1), 0)));
        assert_eq!(tree_info(&tree, &k(3)), Some((k(1), 2)));
        assert_eq!(tree_info(&tree, &k(9)), None, "unknown key");
        let gap = HashMap::from([(k(3), k(2))]);
        assert_eq!(tree_info(&gap, &k(3)), None, "missing ancestor");
        let lp = HashMap::from([(k(2), k(3)), (k(3), k(2))]);
        assert_eq!(tree_info(&lp, &k(3)), None, "loop");
    }

    #[test]
    fn network_root_is_the_majority() {
        assert_eq!(network_root(&[k(5), k(5), k(1)], None), Some(k(5)), "a smaller key in a minority is a split, not the network");
        assert_eq!(network_root(&[k(5), k(7)], Some(k(7))), Some(k(7)), "tie: the current peer's root");
        assert_eq!(network_root(&[k(7), k(5)], None), Some(k(5)), "tie without current: smallest key");
        assert_eq!(network_root(&[], None), None);
    }

    #[test]
    fn rank_scores_core_latency_times_depth() {
        let top = [(cand("tls://a:1"), 0.0), (cand("tls://b:1"), 0.0), (cand("tls://c:1"), 0.0), (cand("tls://d:1"), 0.0), (cand("tls://e:1"), 0.0)];
        let configured = ["tls://cur:1".to_string()];
        let s = |u: &str| u.to_string();
        let probes = HashMap::from([
            // Fast but deep: 10 ms x (6 + 1) = 70.
            (s("tls://a:1"), probe(10.0, Some((k(1), 6)))),
            // Slower but next to the root: 25 ms x (1 + 1) = 50.
            (s("tls://b:1"), probe(25.0, Some((k(1), 1)))),
            // 30 x (0 + 1) = 30.
            (s("tls://c:1"), probe(30.0, Some((k(1), 0)))),
            // Another tree: a split.
            (s("tls://d:1"), probe(1.0, Some((k(9), 0)))),
            // e never came up: no probe.
            (s("tls://cur:1"), probe(40.0, Some((k(1), 2)))),
        ]);
        let (rows, current) = rank(&top, &configured, &probes);
        let got: Vec<(&str, f64, Option<usize>, Option<RowReason>)> = rows.iter().map(|r| (r.uri.as_str(), r.score, r.depth, r.reason)).collect();
        assert_eq!(got, [
            ("tls://c:1", 30.0, Some(0), None),
            ("tls://b:1", 50.0, Some(1), None),
            ("tls://a:1", 70.0, Some(6), None),
            ("tls://d:1", f64::INFINITY, Some(0), Some(RowReason::OtherNetwork)),
            ("tls://e:1", f64::INFINITY, None, None),
        ]);
        assert_eq!(current, 120.0, "40 ms x (2 + 1)");
    }

    #[test]
    fn rank_without_tree_or_latency_fails_the_row() {
        let top = [(cand("tls://a:1"), 0.0), (cand("tls://b:1"), 0.0)];
        let probes = HashMap::from([
            ("tls://a:1".to_string(), probe(10.0, None)),
            ("tls://b:1".to_string(), probe(0.0, Some((k(1), 0)))),
        ]);
        let (rows, current) = rank(&top, &[], &probes);
        assert_eq!(rows.iter().find(|r| r.uri == "tls://a:1").unwrap().reason, Some(RowReason::NoTree));
        assert!(rows.iter().all(|r| r.score.is_infinite()), "no tree, or no RTT yet, is not a usable link");
        assert!(current.is_infinite(), "no configured peer up");
    }

    #[test]
    fn backup_is_on_another_subnet() {
        let ip = |s: &str| Some(s.parse::<IpAddr>().unwrap());
        let mut rows = vec![row("main", 10.0), row("same24", 20.0), row("other", 30.0), row("dead", f64::INFINITY)];
        rows[0].ip = ip("1.2.3.4");
        rows[1].ip = ip("1.2.3.99");
        rows[2].ip = ip("5.6.7.8");
        rows[3].ip = ip("9.9.9.9");
        assert_eq!(pick_backup(&rows, "main", ip("1.2.3.4")), Some("other".into()), "same /24 and failed rows skipped");
        assert_eq!(pick_backup(&rows, "main", None), None, "diversity cannot be checked without the main's IP");
        let mut v6 = vec![row("v6", 25.0)];
        v6[0].ip = ip("2a01:1:2:ffff::1");
        assert_eq!(pick_backup(&v6, "x", ip("2a01:1:2:1::5")), None, "same /48");
        assert_eq!(pick_backup(&v6, "x", ip("1.2.3.4")), Some("v6".into()), "another family is another network");
    }

    const KEY: &str = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff";

    fn list() -> String {
        r#"{
      "germany.md": {
        "tls://good.example:443": {"up": true, "key": "KEY", "states": "**********"},
        "tls://flaky.example:443": {"up": true, "states": "*.*.*.*.*."},
        "tcp://down.example:1": {"up": false, "states": "**********"},
        "http://bad.example:1": {"up": true, "states": "**********"},
        "quic://q.example:443?key=ff": {"up": true, "key": "KEY", "states": "*********."},
        "wss://w.example:443": {"up": true, "states": "**********"},
        "tls://frag.example:1?a=1#note": {"up": true, "key": "KEY", "states": "**********"},
        "tls://inject.example:1": {"up": true, "key": "ab&x=1", "states": "**********"}
      },
      "france.md": { "tls://mine.example:1": {"up": true, "states": "**********"} }
    }"#
        .replace("KEY", KEY)
    }

    #[test]
    fn only_public_addresses_are_probed() {
        for ip in ["1.1.1.1", "176.114.228.31", "2a01:4f8::1"] {
            assert!(is_public(ip.parse().unwrap()), "{ip}");
        }
        for ip in ["127.0.0.1", "10.1.2.3", "192.168.0.1", "172.16.0.1", "169.254.1.1", "100.64.0.1", "0.0.0.0", "::1", "fe80::1", "fd00::1", "200:1::1", "302:1::1"] {
            assert!(!is_public(ip.parse().unwrap()), "{ip}");
        }
    }

    #[test]
    fn candidates_tolerate_null_and_missing_fields() {
        let list = r#"{"a.md": {"tls://n.example:1": {"up": true, "states": null}, "tls://m.example:1": {"states": "**********"}}}"#;
        assert!(candidates(list, &[]).unwrap().is_empty(), "null states = 0 uptime, missing up = down; neither rejects the list");
    }

    #[test]
    fn candidates_keep_only_dialable_schemes_and_pin_key() {
        let c = candidates(&list(), &["tls://mine.example:1".into()]).unwrap();
        let uris: Vec<&str> = c.iter().map(|c| c.uri.as_str()).collect();
        let good = format!("tls://good.example:443?key={KEY}");
        let frag = format!("tls://frag.example:1?a=1&key={KEY}#note");
        assert_eq!(
            uris,
            [frag.as_str(), good.as_str(), "tls://inject.example:1"],
            "sorted by uri; quic/wss (no such links in this core), flaky, down, bad scheme, configured dropped; key before the fragment; a non-hex key not pinned"
        );
        assert_eq!(c[1].country, "germany");
    }

    #[test]
    fn literal_hosts_need_no_lookup() {
        let ip = |s: &str| literal_ip(&Url::parse(s).unwrap());
        assert_eq!(ip("tls://[2a01::1]:443"), Some("2a01::1".parse().unwrap()));
        assert_eq!(ip("tcp://1.2.3.4:1"), Some("1.2.3.4".parse().unwrap()));
        assert_eq!(ip("tls://h.example:1"), None);
    }

    #[test]
    fn decision_uses_hysteresis() {
        assert_eq!(decide(100.0, &[row("a", 90.0)]), Verdict::Keep(REASON_SMALL_GAIN));
        assert_eq!(decide(100.0, &[row("a", 80.0)]), Verdict::Switch { uri: "a".into(), gain_pct: Some(20) });
        assert_eq!(decide(50.0, &[row("a", 80.0)]), Verdict::Keep(REASON_CURRENT_BEST));
        assert_eq!(decide(f64::INFINITY, &[row("a", 300.0)]), Verdict::Switch { uri: "a".into(), gain_pct: None }, "current failed: no gain to show");
        assert_eq!(decide(f64::INFINITY, &[row("a", f64::INFINITY)]), Verdict::Keep(REASON_NONE_PASSED));
    }

    #[test]
    fn stage_a_score_penalises_loss_and_jitter() {
        let clean = Stats { sent: 5, rtts: vec![20.0; 5] };
        assert_eq!(clean.score(MAX_LOSS_A), 20.0);
        let lossy = Stats { sent: 5, rtts: vec![20.0; 4] };
        assert_eq!(lossy.score(MAX_LOSS_A), 220.0, "20 + 10 x 20% loss");
        assert!(Stats { sent: 5, rtts: vec![20.0; 2] }.score(MAX_LOSS_A).is_infinite(), "60% loss > 40%");
    }
}
