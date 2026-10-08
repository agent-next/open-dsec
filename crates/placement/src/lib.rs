//! Placement engine (P §3.2, §7; V4.1 §5.1.3).
//!
//! Two stages: *filtering* keeps healthy nodes that provide the backend and
//! hardware capabilities the request needs; *ranking* samples a few eligible
//! nodes at random and picks the least loaded — power-of-d-choices (Mitzenmacher
//! 2001, P §7), which avoids the herding a pure least-loaded choice exhibits
//! when every replica acts on the same stale snapshot during a burst.
//!
//! Each instance overlays its own recent placements that the periodic watcher
//! snapshot does not reflect yet (P §7), accounting for in-flight load without
//! cross-instance coordination; V4.1 §5.1.3: replicas deploy independently and
//! "trade strong global consistency for scalability" because edges enforce the
//! final admission. On edge rejection the caller retries on another node
//! (edge retains final admission authority, P §7).
//!
//! Load metric for M1: running sandboxes per node (the watcher's counts).

use std::collections::{BTreeMap, HashSet};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use serde_json::json;
use tokio::sync::RwLock;

use dsec_watcher::Snapshot;

/// Where fleet state comes from: the watcher over RPC in production, a fixed
/// snapshot in tests.
pub trait FleetView: Send + Sync + 'static {
    fn view(&self) -> impl std::future::Future<Output = Snapshot> + Send;
}

impl<T: FleetView> FleetView for std::sync::Arc<T> {
    async fn view(&self) -> Snapshot {
        (**self).view().await
    }
}

pub struct WatcherView {
    pub addr: dsec_rpc::Addr,
}

impl FleetView for WatcherView {
    async fn view(&self) -> Snapshot {
        match dsec_rpc::Client::new(self.addr.clone()).call("snapshot", json!({})).await {
            Ok(v) => serde_json::from_value(v).unwrap_or_default(),
            Err(_) => Snapshot::default(),
        }
    }
}

/// A view pinned to a value tests can swap between rounds.
pub struct PinnedView(pub RwLock<Snapshot>);

impl FleetView for PinnedView {
    async fn view(&self) -> Snapshot {
        self.0.read().await.clone()
    }
}

#[derive(Debug, Clone)]
pub struct PlaceReq {
    /// Backend type ("container") — must appear in the edge's capabilities.
    pub backend: String,
    /// Extra hardware requirements ("gpu", ...) — all must be provided.
    pub requirements: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct Choice {
    pub edge_id: String,
    pub addr: String,
    /// Effective load the decision saw: snapshot count + own in-flight overlay.
    pub load: u64,
}

#[derive(Debug, Clone)]
pub struct Opts {
    /// Power-of-d sample size (P §7). d >= 2; `usize::MAX` degenerates to pure
    /// least-loaded (used only to demonstrate herding in tests).
    pub d: usize,
    /// Refresh the fleet view at most this often; a burst inside one window is
    /// exactly the stale-snapshot scenario power-of-d protects against.
    pub refresh: Duration,
    /// Own placements stay in the overlay until this long after the snapshot
    /// that should already include them (2.5 refreshes by default).
    pub overlay_ttl: Duration,
    /// When false, no in-flight overlay is kept (test oracle: herding).
    pub overlay: bool,
}

impl Default for Opts {
    fn default() -> Self {
        Opts { d: 2, refresh: Duration::from_secs(1), overlay_ttl: Duration::from_millis(2500), overlay: true }
    }
}

/// Tiny xorshift PRNG: sampling does not need crypto strength, and this keeps
/// the dependency set minimal.
struct Rng(u64);

impl Rng {
    fn seeded() -> Rng {
        let mut b = [0u8; 8];
        if std::io::Read::read(&mut std::fs::File::open("/dev/urandom").unwrap(), &mut b).is_ok() {
            return Rng(u64::from_le_bytes(b) | 1);
        }
        Rng(0x9E3779B97F4A7C15)
    }
    fn next(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.0 = x;
        x
    }
    fn below(&mut self, n: usize) -> usize {
        (self.next() % n as u64) as usize
    }
}

struct Overlay {
    stamps: Vec<(Instant, String)>,
}

pub struct Placement<V: FleetView> {
    view: V,
    opts: Opts,
    inner: Mutex<Inner>,
}

struct Inner {
    snap: Snapshot,
    refreshed_at: Option<Instant>,
    rng: Rng,
    overlay: Overlay,
}

impl<V: FleetView> Placement<V> {
    pub fn new(view: V, opts: Opts) -> Placement<V> {
        Placement {
            view,
            opts,
            inner: Mutex::new(Inner {
                snap: Snapshot::default(),
                refreshed_at: None,
                rng: Rng::seeded(),
                overlay: Overlay { stamps: vec![] },
            }),
        }
    }

    /// Pull the fleet view if it is older than the refresh window.
    async fn refresh_if_stale(&self) {
        let stale = {
            let g = self.inner.lock().unwrap();
            g.refreshed_at.is_none_or(|t| t.elapsed() >= self.opts.refresh)
        };
        if !stale {
            return;
        }
        let snap = self.view.view().await;
        let mut g = self.inner.lock().unwrap();
        if g.refreshed_at.is_none_or(|t| t.elapsed() >= self.opts.refresh) {
            g.snap = snap;
            g.refreshed_at = Some(Instant::now());
        }
    }

    fn overlay_load(g: &Inner, ttl: &Duration, edge: &str) -> u64 {
        g.overlay.stamps.iter().filter(|(t, id)| id == edge && t.elapsed() < *ttl).count() as u64
    }

    /// Filter + rank, excluding `excluded` edges (retry-on-reject bookkeeping,
    /// P §7). Records the pick in the in-flight overlay unless disabled.
    pub async fn select_excluding(&self, req: &PlaceReq, excluded: &HashSet<String>) -> anyhow::Result<Choice> {
        self.refresh_if_stale().await;
        let mut g = self.inner.lock().unwrap();
        let mut need: HashSet<String> = req.requirements.clone().into_iter().collect();
        need.insert(req.backend.clone());
        let mut cands: Vec<(String, String, u64)> = g
            .snap
            .edges
            .iter()
            .filter(|(id, v)| {
                !excluded.contains(*id)
                    && v.healthy
                    && v.status.as_ref().is_some_and(|s| need.iter().all(|n| s.capabilities.iter().any(|c| c == n)))
            })
            .map(|(id, v)| {
                let base = v.status.as_ref().map_or(0, |s| s.sbx_used);
                let over = if self.opts.overlay { Self::overlay_load(&g, &self.opts.overlay_ttl, id) } else { 0 };
                (id.clone(), v.addr.clone(), base + over)
            })
            .collect();
        if cands.is_empty() {
            anyhow::bail!("no eligible edge (backend {:?}, excluded {:?})", req.backend, excluded);
        }
        // Power-of-d (P §7): sample d distinct candidates, take the least loaded.
        let d = self.opts.d.min(cands.len());
        let mut sample_idx: Vec<usize> = vec![];
        while sample_idx.len() < d {
            let i = g.rng.below(cands.len());
            if !sample_idx.contains(&i) {
                sample_idx.push(i);
            }
        }
        let best = sample_idx
            .into_iter()
            .min_by_key(|&i| (cands[i].2, cands[i].0.clone()))
            .expect("sample nonempty");
        let (id, addr, load) = cands.swap_remove(best);
        if self.opts.overlay {
            g.overlay.stamps.push((Instant::now(), id.clone()));
        }
        Ok(Choice { edge_id: id, addr, load })
    }

    pub async fn select(&self, req: &PlaceReq) -> anyhow::Result<Choice> {
        self.select_excluding(req, &HashSet::new()).await
    }

    /// Drop overlay stamps that a refreshed snapshot must have absorbed.
    pub fn settle_overlay(&self) {
        self.inner.lock().unwrap().overlay.stamps.retain(|(t, _)| t.elapsed() < self.opts.overlay_ttl);
    }

    /// Effective load as this instance sees it (tests and diagnostics).
    pub async fn effective_loads(&self) -> BTreeMap<String, u64> {
        self.refresh_if_stale().await;
        let g = self.inner.lock().unwrap();
        g.snap
            .edges
            .iter()
            .map(|(id, v)| {
                let base = v.status.as_ref().map_or(0, |s| s.sbx_used);
                let over = Self::overlay_load(&g, &self.opts.overlay_ttl, id);
                (id.clone(), base + over)
            })
            .collect()
    }
}

/// Serves a placement replica to the apiserver over dsec-rpc.
pub struct PlacementService<V: FleetView>(pub std::sync::Arc<Placement<V>>);

impl<V: FleetView> dsec_rpc::Handler for PlacementService<V> {
    async fn handle(&self, req: dsec_rpc::Request, out: dsec_rpc::Responder) {
        match req.method.as_str() {
            "select" => {
                let pr = PlaceReq {
                    backend: req.params["backend"].as_str().unwrap_or("container").to_string(),
                    requirements: req.params["requirements"]
                        .as_array()
                        .map(|a| a.iter().filter_map(|x| x.as_str().map(String::from)).collect())
                        .unwrap_or_default(),
                };
                let excluded: HashSet<String> = req.params["excluded"]
                    .as_array()
                    .map(|a| a.iter().filter_map(|x| x.as_str().map(String::from)).collect())
                    .unwrap_or_default();
                match self.0.select_excluding(&pr, &excluded).await {
                    Ok(c) => out.ok(json!({ "edge_id": c.edge_id, "addr": c.addr, "load": c.load })).await,
                    Err(e) => out.err("no_candidate", e.to_string()).await,
                }
            }
            _ => out.err("not_found", format!("no such method {}", req.method)).await,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use dsec_watcher::EdgeView;
    use std::collections::HashMap;
    use std::sync::Arc;

    fn snap(n_edges: usize, base_load: u64, caps: Vec<String>) -> Snapshot {
        let mut edges = BTreeMap::new();
        for i in 0..n_edges {
            edges.insert(
                format!("e{i}"),
                EdgeView {
                    addr: format!("tcp://10.0.0.{i}:9000"),
                    healthy: true,
                    status: Some(dsec_watcher::EdgeStatus {
                        edge_id: format!("e{i}"),
                        sbx_used: base_load,
                        sbx_total: 100,
                        capabilities: caps.clone(),
                        ..Default::default()
                    }),
                    last_ok_ms: 0,
                },
            );
        }
        Snapshot { edges, taken_ms: 0 }
    }

    fn pinned(s: Snapshot) -> Arc<PinnedView> {
        Arc::new(PinnedView(RwLock::new(s)))
    }

    #[tokio::test]
    async fn filter_keeps_only_healthy_capable_edges() {
        let mut s = snap(3, 0, vec!["container".into()]);
        s.edges.get_mut("e1").unwrap().healthy = false;
        s.edges.get_mut("e2").unwrap().status.as_mut().unwrap().capabilities.push("gpu".into());
        let p = Placement::new(pinned(s), Opts::default());
        // e1 unhealthy, e2 is the only gpu node.
        for _ in 0..20 {
            let c = p.select(&PlaceReq { backend: "container".into(), requirements: vec!["gpu".into()] }).await.unwrap();
            assert_eq!(c.edge_id, "e2");
        }
        let mut seen = HashSet::new();
        for _ in 0..40 {
            let c = p.select(&PlaceReq { backend: "container".into(), requirements: vec![] }).await.unwrap();
            seen.insert(c.edge_id);
        }
        assert!(!seen.contains("e1"), "unhealthy edge must never be picked");
        assert_eq!(seen, HashSet::from(["e0".into(), "e2".into()]));
        // A backend nobody provides yields no candidate.
        assert!(p.select(&PlaceReq { backend: "microvm".into(), requirements: vec![] }).await.is_err());
    }

    #[tokio::test]
    async fn overlay_accounts_for_in_flight_placements() {
        // Frozen snapshot: every edge at load 0 forever (the watcher never
        // catches up). Without the overlay, the sampler would treat the node as
        // empty no matter how many of our own sandboxes are in flight there.
        let p = Placement::new(pinned(snap(4, 0, vec!["container".into()])), Opts::default());
        let mut counts: HashMap<String, u64> = HashMap::new();
        for _ in 0..40 {
            let c = p.select(&PlaceReq { backend: "container".into(), requirements: vec![] }).await.unwrap();
            *counts.entry(c.edge_id).or_insert(0) += 1;
        }
        let max = counts.values().max().unwrap();
        let min = counts.values().min().unwrap();
        assert!(max - min <= 2, "with overlay accounting the burst should stay balanced: {counts:?}");
        let loads = p.effective_loads().await;
        assert_eq!(loads.values().sum::<u64>(), 40, "overlay must account for all 40 in-flight picks");
    }

    #[tokio::test]
    async fn overlay_expires_once_snapshots_absorb_the_load() {
        let view = pinned(snap(2, 0, vec!["container".into()]));
        let p = Placement::new(
            view.clone(),
            Opts { refresh: Duration::from_millis(30), overlay_ttl: Duration::from_millis(60), ..Default::default() },
        );
        for _ in 0..6 {
            p.select(&PlaceReq { backend: "container".into(), requirements: vec![] }).await.unwrap();
        }
        // The watcher "catches up": the pinned snapshot now shows 3/3.
        *view.0.write().await = snap(2, 3, vec!["container".into()]);
        tokio::time::sleep(Duration::from_millis(120)).await;
        let loads = p.effective_loads().await;
        assert_eq!(loads.values().sum::<u64>(), 6, "stale overlay stamps must expire, not double-count");
    }

    #[tokio::test]
    async fn power_of_d_avoids_the_herding_of_pure_least_loaded() {
        // A 200-sandbox burst inside one refresh window (frozen snapshot), one
        // placement replica: measured spread across 10 identical nodes.
        let n = 200usize;
        let mut spread: HashMap<String, u64> = HashMap::new();
        let p = Placement::new(pinned(snap(10, 0, vec!["container".into()])), Opts::default());
        for _ in 0..n {
            let c = p.select(&PlaceReq { backend: "container".into(), requirements: vec![] }).await.unwrap();
            *spread.entry(c.edge_id).or_insert(0) += 1;
        }
        let max = *spread.values().max().unwrap();
        let min = *spread.values().min().unwrap();
        assert_eq!(spread.len(), 10, "every node must receive work");
        assert!(max - min <= 6, "power-of-d spread too skewed: {spread:?}");
        // Counterfactual — the mechanism disabled: pure least-loaded on the
        // stale snapshot (sample everything, no in-flight overlay) herds onto
        // the single apparently-empty node.
        let mut herd: HashMap<String, u64> = HashMap::new();
        let greedy = Placement::new(
            pinned(snap(10, 0, vec!["container".into()])),
            Opts { d: usize::MAX, overlay: false, refresh: Duration::from_secs(3600), ..Default::default() },
        );
        for _ in 0..n {
            let c = greedy.select(&PlaceReq { backend: "container".into(), requirements: vec![] }).await.unwrap();
            *herd.entry(c.edge_id).or_insert(0) += 1;
        }
        assert_eq!(*herd.values().max().unwrap(), n as u64, "pure least-loaded must herd onto one node");
        assert_eq!(herd.len(), 1);
    }

    #[tokio::test]
    async fn independent_replicas_need_no_coordination() {
        // V4.1 §5.1.3: several placement replicas, zero coordination; none may
        // fail or starve the other. Their combined burst still spreads.
        let views: Vec<Arc<PinnedView>> = (0..3).map(|_| pinned(snap(8, 0, vec!["container".into()]))).collect();
        let reps: Vec<Placement<Arc<PinnedView>>> = views.into_iter().map(|v| Placement::new(v, Opts::default())).collect();
        let mut total: HashMap<String, u64> = HashMap::new();
        let mut handles = vec![];
        for r in reps {
            handles.push(tokio::spawn(async move {
                let mut mine = vec![];
                for _ in 0..30 {
                    mine.push(r.select(&PlaceReq { backend: "container".into(), requirements: vec![] }).await.unwrap());
                }
                mine
            }));
        }
        for h in handles {
            for c in h.await.unwrap() {
                *total.entry(c.edge_id).or_insert(0) += 1;
            }
        }
        assert_eq!(total.values().sum::<u64>(), 90);
        let max = *total.values().max().unwrap();
        assert!(max <= 90 / 8 + 6, "uncoordinated replicas still spread roughly evenly: {total:?}");
    }

    #[tokio::test]
    async fn edge_rejection_retries_on_another_node() {
        // P §7: the edge keeps final admission; on rejection the caller
        // re-selects excluding the node that said no.
        let p = Arc::new(Placement::new(pinned(snap(4, 0, vec!["container".into()])), Opts::default()));
        let mut excluded: HashSet<String> = HashSet::new();
        let mut accepted = vec![];
        for _ in 0..4 {
            let c = p.select_excluding(&PlaceReq { backend: "container".into(), requirements: vec![] }, &excluded)
                .await
                .unwrap();
            if accepted.len() < 2 {
                // First two edges reject (full): must land somewhere else.
                accepted.push(c.edge_id.clone());
                excluded.insert(c.edge_id.clone());
            } else {
                accepted.push(c.edge_id.clone());
                break;
            }
        }
        assert_ne!(accepted[2], accepted[0]);
        assert_ne!(accepted[2], accepted[1]);
        // Every node refusing exhausts the candidates.
        let all: HashSet<String> = ["e0", "e1", "e2", "e3"].into_iter().map(String::from).collect();
        assert!(p.select_excluding(&PlaceReq { backend: "container".into(), requirements: vec![] }, &all).await.is_err());
    }

    #[tokio::test]
    async fn serves_select_over_rpc() {
        let l = dsec_rpc::Listener::bind(&"tcp://127.0.0.1:0".parse().unwrap()).await.unwrap();
        let addr = l.local_addr().unwrap();
        let p = Arc::new(Placement::new(pinned(snap(3, 0, vec!["container".into()])), Opts::default()));
        tokio::spawn(l.serve(Arc::new(PlacementService(p))));
        let c = dsec_rpc::Client::new(addr);
        let r = c
            .call(
                "select",
                json!({ "backend": "container", "requirements": [], "excluded": [] }),
            )
            .await
            .unwrap();
        assert!(r["edge_id"].as_str().unwrap().starts_with('e'));
        assert!(r["addr"].as_str().unwrap().starts_with("tcp://"));
    }
}
