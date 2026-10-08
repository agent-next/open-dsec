//! Watcher: probes every edge and maintains the fleet view placement relies on
//! (P §3.2): per-edge health and scheduling-relevant state — the number of
//! running sandboxes broken down per backend type, per edge, per user and per
//! task — plus node capacity.
//!
//! The watcher keeps no durable state: it rebuilds its view after a restart by
//! polling the edges again (P §3.2), which is exercised in the tests.

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use dsec_rpc::{Client, Handler, Request, Responder};
use serde::{Deserialize, Serialize};
use serde_json::json;
use tokio::sync::RwLock;

/// The status every edge serves for the watcher (polled method `status`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct EdgeStatus {
    pub edge_id: String,
    /// Node capacity as the edge sees it (millicores / MiB / sandboxes).
    #[serde(default)]
    pub cpu_total_mc: u64,
    #[serde(default)]
    pub cpu_used_mc: u64,
    #[serde(default)]
    pub mem_total_mb: u64,
    #[serde(default)]
    pub mem_used_mb: u64,
    #[serde(default)]
    pub sbx_total: u64,
    #[serde(default)]
    pub sbx_used: u64,
    /// Running sandboxes by backend type ("container", ...).
    #[serde(default)]
    pub by_backend: BTreeMap<String, u64>,
    /// Running sandboxes by owner principal (P §3.2 "per user").
    #[serde(default)]
    pub by_user: BTreeMap<String, u64>,
    /// Running sandboxes by task label (P §3.2 "per task").
    #[serde(default)]
    pub by_task: BTreeMap<String, u64>,
    /// Backends/hardware this node provides (placement filter stage, P §3.2).
    #[serde(default)]
    pub capabilities: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EdgeView {
    pub addr: String,
    pub healthy: bool,
    pub status: Option<EdgeStatus>,
    #[serde(default)]
    pub last_ok_ms: u64,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Snapshot {
    pub edges: BTreeMap<String, EdgeView>,
    pub taken_ms: u64,
}

struct Inner {
    /// edge_id -> address (the poll set; static config plus registrations).
    edges: BTreeMap<String, String>,
    views: RwLock<Snapshot>,
}

pub struct Watcher {
    inner: Arc<Inner>,
}

impl Watcher {
    /// Start polling `edges` (id -> rpc address) every `interval`. One round
    /// runs immediately so callers get a fresh view without waiting.
    pub fn start(edges: BTreeMap<String, String>, interval: Duration) -> Arc<Watcher> {
        let w = Arc::new(Watcher {
            inner: Arc::new(Inner { edges, views: RwLock::new(Snapshot::default()) }),
        });
        let w2 = w.clone();
        tokio::spawn(async move {
            w2.poll_all().await;
            let mut t = tokio::time::interval(interval);
            t.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            loop {
                t.tick().await;
                w2.poll_all().await;
            }
        });
        w
    }

    /// One poll round: every edge answers `status` or is marked unhealthy.
    async fn poll_all(&self) {
        let mut snap = Snapshot { edges: BTreeMap::new(), taken_ms: now_ms() };
        for (id, addr) in &self.inner.edges {
            let mut v = EdgeView { addr: addr.clone(), healthy: false, status: None, last_ok_ms: 0 };
            if let Ok(r) = Client::new(addr.parse().unwrap()).call("status", json!({})).await {
                if let Ok(st) = serde_json::from_value::<EdgeStatus>(r) {
                    v.healthy = true;
                    v.last_ok_ms = now_ms();
                    v.status = Some(st);
                }
            }
            snap.edges.insert(id.clone(), v);
        }
        *self.inner.views.write().await = snap;
    }

    /// Add an edge to the poll set (picked up on the next round).
    pub async fn register(&self, id: &str, addr: &str) {
        self.inner
            .views
            .write()
            .await
            .edges
            .entry(id.to_string())
            .or_insert(EdgeView { addr: addr.to_string(), healthy: false, status: None, last_ok_ms: 0 });
    }

    pub async fn snapshot(&self) -> Snapshot {
        self.inner.views.read().await.clone()
    }

    /// Where the apiserver sends sandbox requests: id -> address for healthy
    /// edges (the apiserver "periodically refreshes the set of edge nodes from
    /// the watcher", P §3.2).
    pub async fn edge_routes(&self) -> BTreeMap<String, String> {
        self.inner
            .views
            .read()
            .await
            .edges
            .iter()
            .filter(|(_, v)| v.healthy)
            .map(|(k, v)| (k.clone(), v.addr.clone()))
            .collect()
    }

    /// Aggregate running-sandbox counts across healthy edges, per key kind.
    pub async fn count_by(&self, kind: CountKind) -> BTreeMap<String, u64> {
        let snap = self.snapshot().await;
        let mut out = BTreeMap::new();
        for v in snap.edges.values().filter(|v| v.healthy) {
            let Some(st) = &v.status else { continue };
            let m = match kind {
                CountKind::Backend => &st.by_backend,
                CountKind::User => &st.by_user,
                CountKind::Task => &st.by_task,
            };
            for (k, n) in m {
                *out.entry(k.clone()).or_insert(0) += n;
            }
        }
        out
    }
}

#[derive(Debug, Clone, Copy)]
pub enum CountKind {
    Backend,
    User,
    Task,
}

pub fn now_ms() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_millis() as u64).unwrap_or(0)
}

/// Serves the watcher to placement and the apiserver.
pub struct WatcherService(Arc<Watcher>);

impl Handler for WatcherService {
    async fn handle(&self, req: Request, out: Responder) {
        match req.method.as_str() {
            "snapshot" => {
                let s = self.0.snapshot().await;
                out.ok(serde_json::to_value(s).unwrap()).await
            }
            "edges" => {
                let r = self.0.edge_routes().await;
                out.ok(json!({ "edges": r })).await
            }
            "register" => {
                self.0
                    .register(req.params["id"].as_str().unwrap_or_default(), req.params["addr"].as_str().unwrap_or_default())
                    .await;
                out.ok(json!({})).await
            }
            _ => out.err("not_found", format!("no such method {}", req.method)).await,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use dsec_rpc::Listener;
    use serde_json::Value;
    use std::sync::atomic::{AtomicU64, Ordering};

    /// A fake edge whose counters can be bumped between polls.
    struct FakeEdge {
        id: String,
        running: AtomicU64,
        caps: Vec<String>,
        /// 1 = answer status, 0 = pretend unreachable.
        alive: AtomicU64,
    }

    impl Handler for FakeEdge {
        async fn handle(&self, req: Request, out: Responder) {
            match req.method.as_str() {
                "status" if self.alive.load(Ordering::SeqCst) == 1 => {
                    let n = self.running.load(Ordering::SeqCst);
                    out.ok(json!({
                        "edge_id": self.id,
                        "cpu_total_mc": 8000, "cpu_used_mc": n * 100,
                        "mem_total_mb": 8000, "mem_used_mb": n * 100,
                        "sbx_total": 20, "sbx_used": n,
                        "by_backend": { "container": n },
                        "by_user": { "alice": n },
                        "by_task": { "swe-bench": n },
                        "capabilities": self.caps,
                    }))
                    .await
                }
                "status" => out.err("unreachable", "edge down").await,
                _ => out.err("not_found", "no such method").await,
            }
        }
    }

    async fn spawn_edge(id: &str, caps: Vec<String>) -> (String, Arc<FakeEdge>) {
        let e = Arc::new(FakeEdge { id: id.into(), running: AtomicU64::new(2), caps, alive: AtomicU64::new(1) });
        let l = Listener::bind(&"tcp://127.0.0.1:0".parse().unwrap()).await.unwrap();
        let addr = l.local_addr().unwrap().to_string(); // already tcp://host:port
        tokio::spawn(l.serve(e.clone()));
        (addr, e)
    }

    #[tokio::test]
    async fn polls_edges_and_aggregates_counts() {
        let (a1, e1) = spawn_edge("e1", vec!["container".into()]).await;
        let (a2, e2) = spawn_edge("e2", vec!["container".into(), "gpu".into()]).await;
        e2.running.store(5, Ordering::SeqCst);
        let w = Watcher::start(BTreeMap::from([("e1".into(), a1), ("e2".into(), a2)]), Duration::from_secs(1));
        tokio::time::sleep(Duration::from_millis(250)).await;
        let snap = w.snapshot().await;
        assert!(snap.edges["e1"].healthy && snap.edges["e2"].healthy);
        assert_eq!(snap.edges["e2"].status.as_ref().unwrap().by_user["alice"], 5);
        assert_eq!(w.count_by(CountKind::User).await["alice"], 7);
        assert_eq!(w.count_by(CountKind::Backend).await["container"], 7);
        // Counts move when the edge's load moves (next poll round).
        e1.running.store(4, Ordering::SeqCst);
        tokio::time::sleep(Duration::from_millis(1300)).await;
        assert_eq!(w.count_by(CountKind::User).await["alice"], 9);
    }

    #[tokio::test]
    async fn unreachable_edges_are_unhealthy_and_excluded_from_routes() {
        let (a1, e1) = spawn_edge("e1", vec!["container".into()]).await;
        let w = Watcher::start(BTreeMap::from([("e1".into(), a1)]), Duration::from_millis(150));
        tokio::time::sleep(Duration::from_millis(250)).await;
        assert!(w.edge_routes().await.contains_key("e1"));
        e1.alive.store(0, Ordering::SeqCst);
        tokio::time::sleep(Duration::from_millis(500)).await;
        assert!(w.edge_routes().await.is_empty(), "dead edge must drop out of routes");
        assert!(!w.snapshot().await.edges["e1"].healthy);
        assert_eq!(w.count_by(CountKind::User).await.get("alice"), None);
    }

    #[tokio::test]
    async fn rebuilds_its_view_after_restart_by_re_polling() {
        // Stateless oracle (P §3.2): drop the watcher entirely, start a new
        // one over the same edges, and the fleet view comes back by polling.
        let (a1, e1) = spawn_edge("e1", vec!["container".into()]).await;
        let (a2, e2) = spawn_edge("e2", vec!["container".into()]).await;
        e1.running.store(3, Ordering::SeqCst);
        e2.running.store(6, Ordering::SeqCst);
        let edges = BTreeMap::from([("e1".into(), a1), ("e2".into(), a2)]);
        let before = {
            let w = Watcher::start(edges.clone(), Duration::from_secs(60));
            tokio::time::sleep(Duration::from_millis(250)).await;
            w.snapshot().await
        }; // watcher dropped here: "restart"
        let w2 = Watcher::start(edges, Duration::from_secs(60));
        tokio::time::sleep(Duration::from_millis(250)).await;
        let after = w2.snapshot().await;
        let norm = |s: &Snapshot| s
            .edges
            .values()
            .map(|v| (v.addr.clone(), v.status.as_ref().unwrap().sbx_used))
            .collect::<BTreeMap<_, _>>();
        assert_eq!(norm(&before), norm(&after), "view must rebuild identically from re-polling");
        assert_eq!(w2.count_by(CountKind::Task).await["swe-bench"], 9);
    }

    #[tokio::test]
    async fn serves_snapshot_over_rpc_for_placement_and_apiserver() {
        let (a1, _e1) = spawn_edge("e1", vec!["container".into()]).await;
        let w = Watcher::start(BTreeMap::from([("e1".into(), a1)]), Duration::from_secs(1));
        tokio::time::sleep(Duration::from_millis(250)).await;
        let l = Listener::bind(&"tcp://127.0.0.1:0".parse().unwrap()).await.unwrap();
        let addr = l.local_addr().unwrap();
        tokio::spawn(l.serve(Arc::new(WatcherService(w))));
        let c = Client::new(addr);
        let r: Value = c.call("snapshot", json!({})).await.unwrap();
        assert!(r["edges"]["e1"]["healthy"].as_bool().unwrap());
        let r = c.call("edges", json!({})).await.unwrap();
        assert!(r["edges"]["e1"].as_str().unwrap().starts_with("tcp://"));
    }
}
