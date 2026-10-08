//! Edge: the per-node sandbox runtime component (P §3.3).
//!
//! Before accepting a creation request the edge checks node capacity against a
//! configurable warning threshold and rejects the request when it would be
//! exceeded — the node-local admission that backs the placement engine's
//! eventually-consistent decisions (V4.1 §5.1.3). Creation provisions the
//! container backend (Docker Engine API: cpu/memory limits, `network none`
//! unless a policy says otherwise, `open-dsec=1` labels) and a per-sandbox
//! Unix socket that the in-sandbox aether dials; the edge watches that channel
//! and marks the sandbox failed when it closes (P §3.3). If the environment
//! crashed, the status carries a *repercussion* signal for the RL framework
//! (V4.1 §5.1.3). A reaper releases sandboxes whose TTL expired (P §2.3).
//!
//! Every operation and its result is appended to the per-sandbox trajectory
//! log before the reply is sent, and a re-issued completed operation replays
//! from it instead of re-executing (V4 §5.2.5).

pub mod docker;

use std::collections::{BTreeMap, HashMap};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use docker::{CreateSpec, Docker};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use tokio::sync::Mutex;

use dsec_rpc::{Client, Handler, Request, Responder};
use dsec_trajlog::{Entry, TrajLog};

/// Label every sandbox container carries (cleanup/ownership marker).
pub const LABEL: &str = "open-dsec";
/// Per-sandbox label with the sandbox id.
pub const LABEL_SBX: &str = "open-dsec.sandbox";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum SbxStatus {
    Creating,
    /// Container up, aether channel accepted.
    Running,
    /// Environment died unexpectedly (V4.1 §5.1.3: a crashed trajectory).
    Failed { reason: String, exit_code: Option<i64>, repercussion: bool },
    /// Normal end: explicit release or TTL expiry.
    Stopped { reason: String },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Sandbox {
    pub id: String,
    pub edge_id: String,
    pub user: String,
    pub project: String,
    pub task: Option<String>,
    pub image: String,
    pub cpu_mc: u64,
    pub mem_mb: u64,
    pub ttl_ms: Option<u64>,
    /// Stored as given (P §2.1 `network={"pypi": True, ...}`); enforcement is
    /// the eBPF allowlist of M4 — containers stay on `network none` in M1.
    pub network: Value,
    pub status: SbxStatus,
    pub container_id: Option<String>,
    pub created_ms: u64,
}

impl Sandbox {
    pub fn running(&self) -> bool {
        matches!(self.status, SbxStatus::Running)
    }
    pub fn repercussion(&self) -> bool {
        matches!(self.status, SbxStatus::Failed { repercussion: true, .. })
    }
}

#[derive(Debug, Clone)]
pub struct EdgeConfig {
    pub edge_id: String,
    /// Admit while used/total stays below this fraction on every dimension
    /// (V4.1 §5.1.3 "local warning threshold").
    pub warning_threshold: f64,
    pub cpu_total_mc: u64,
    pub mem_total_mb: u64,
    pub sbx_total: u64,
    pub docker_sock: PathBuf,
    /// Where per-sandbox socket dirs and the trajectory log live.
    pub data_dir: PathBuf,
    /// Host path of the aether binary bind-mounted into containers.
    pub aether_bin: PathBuf,
    /// IAM service address (quota release on reaped/failed sandboxes).
    pub iam_addr: String,
    /// Default image if the request names none.
    pub default_image: String,
    pub ttl_sweep: Duration,
    /// Backends/hardware this node offers (placement filter stage).
    pub capabilities: Vec<String>,
}

impl Default for EdgeConfig {
    fn default() -> Self {
        EdgeConfig {
            edge_id: "edge-local".into(),
            warning_threshold: 0.9,
            cpu_total_mc: 8_000,
            mem_total_mb: 16_384,
            sbx_total: 64,
            docker_sock: "/var/run/docker.sock".into(),
            data_dir: std::env::temp_dir().join("dsec-edge"),
            aether_bin: "dsec-aether".into(),
            iam_addr: String::new(),
            default_image: "debian:12-slim".into(),
            ttl_sweep: Duration::from_secs(2),
            capabilities: vec!["container".into()],
        }
    }
}

struct SbxEntry {
    meta: Sandbox,
    /// Edge -> aether channel (P §3.3). Present while aether is connected.
    aether: Option<Client>,
    /// Directory bind-mounted into the container; holds aether.sock.
    dir: PathBuf,
}

pub struct Edge {
    cfg: EdgeConfig,
    docker: Docker,
    traj: TrajLog,
    sbx: Mutex<HashMap<String, SbxEntry>>,
    iam: Option<Client>,
}

impl Edge {
    pub fn new(cfg: EdgeConfig) -> anyhow::Result<Arc<Edge>> {
        let traj = TrajLog::open(cfg.data_dir.join("traj"))?;
        Ok(Arc::new(Edge {
            docker: Docker::new(cfg.docker_sock.clone()),
            traj,
            sbx: Mutex::new(HashMap::new()),
            iam: if cfg.iam_addr.is_empty() { None } else { Some(Client::new(cfg.iam_addr.parse()?)) },
            cfg,
        }))
    }

    fn sbx_id(&self) -> String {
        let mut b = [0u8; 6];
        let _ = std::io::Read::read(&mut std::fs::File::open("/dev/urandom").unwrap(), &mut b);
        // P §3.2: the sandbox id encodes its owning edge so any apiserver
        // instance can route without shared state.
        format!("sbx-{}-{}", self.cfg.edge_id, b.iter().map(|x| format!("{x:02x}")).collect::<String>())
    }

    fn used(sbx: &HashMap<String, SbxEntry>) -> (u64, u64, u64) {
        sbx.values().filter(|e| e.meta.running()).fold((0, 0, 0), |(c, m, n), e| (c + e.meta.cpu_mc, m + e.meta.mem_mb, n + 1))
    }

    /// Node-local admission (P §3.3, V4.1 §5.1.3): reject when the request
    /// would push any dimension past the warning threshold.
    async fn admit(&self, cpu_mc: u64, mem_mb: u64) -> Result<(), String> {
        let g = self.sbx.lock().await;
        let (uc, um, un) = Self::used(&g);
        let t = self.cfg.warning_threshold;
        let over = |used: u64, req: u64, total: u64| total == 0 || (used + req) as f64 > total as f64 * t;
        if over(uc, cpu_mc, self.cfg.cpu_total_mc) {
            return Err(format!(
                "edge {}: cpu would be {}/{} mc > {:.0}% threshold",
                self.cfg.edge_id,
                uc + cpu_mc,
                self.cfg.cpu_total_mc,
                t * 100.0
            ));
        }
        if over(um, mem_mb, self.cfg.mem_total_mb) {
            return Err(format!(
                "edge {}: mem would be {}/{} mb > {:.0}% threshold",
                self.cfg.edge_id,
                um + mem_mb,
                self.cfg.mem_total_mb,
                t * 100.0
            ));
        }
        if over(un, 1, self.cfg.sbx_total) {
            return Err(format!("edge {}: sandbox count would exceed {}", self.cfg.edge_id, self.cfg.sbx_total));
        }
        Ok(())
    }

    /// Create a sandbox (P §3.3): provision, start, adopt the aether channel.
    pub async fn create(self: &Arc<Self>, req: Value) -> Result<Sandbox, (String, String)> {
        let image = req["image"].as_str().unwrap_or(&self.cfg.default_image).to_string();
        let cpu_mc = req["cpu_mc"].as_u64().unwrap_or(500).max(50);
        let mem_mb = req["mem_mb"].as_u64().unwrap_or(512).max(32);
        if let Err(e) = self.admit(cpu_mc, mem_mb).await {
            return Err(("edge_overloaded".into(), e));
        }
        let id = self.sbx_id();
        let dir = self.cfg.data_dir.join("active").join(&id);
        std::fs::create_dir_all(&dir).map_err(|e| ("internal".into(), e.to_string()))?;
        let name = format!("dsec-{}", id.replace('/', "-"));
        let sock_in_container = "/run/dsec/aether.sock";
        let spec = CreateSpec {
            image: image.clone(),
            cmd: vec![
                self.cfg.aether_bin.file_name().unwrap().to_string_lossy().into_owned(),
                format!("unix://{sock_in_container}"),
            ],
            cpu_mc,
            mem_mb,
            network_mode: "none".into(),
            binds: vec![
                format!("{}:/run/dsec", dir.display()),
                format!("{}:{}:ro", self.cfg.aether_bin.display(), self.cfg.aether_bin.display()),
            ],
            labels: vec![(LABEL.into(), "1".into()), (LABEL_SBX.into(), id.clone())],
            name,
        };
        let cid = self.docker.create(&spec).await.map_err(|e| ("create_failed".into(), e.to_string()))?;
        if let Err(e) = self.docker.start(&cid).await {
            let _ = self.docker.remove(&cid, true).await;
            return Err(("start_failed".into(), e.to_string()));
        }
        let meta = Sandbox {
            id: id.clone(),
            edge_id: self.cfg.edge_id.clone(),
            user: req["user"].as_str().unwrap_or("anon").into(),
            project: req["project"].as_str().unwrap_or("root").into(),
            task: req["task"].as_str().map(String::from),
            image,
            cpu_mc,
            mem_mb,
            ttl_ms: req["ttl_ms"].as_u64(),
            network: req["network"].clone(),
            status: SbxStatus::Running,
            container_id: Some(cid.clone()),
            created_ms: dsec_watcher::now_ms(),
        };
        self.sbx.lock().await.insert(id.clone(), SbxEntry { meta: meta.clone(), aether: None, dir: dir.clone() });
        // Adopt the aether channel when it dials in, and watch for it closing.
        self.spawn_channel_adopt(id);
        Ok(meta)
    }

    /// Bind the sandbox socket and take the first aether that connects; when
    /// the channel closes, the sandbox is marked failed (P §3.3) with a
    /// repercussion signal if the container crashed (V4.1 §5.1.3).
    fn spawn_channel_adopt(self: &Arc<Self>, id: String) {
        let edge = self.clone();
        tokio::spawn(async move {
            let (dir, cid) = {
                let m = edge.sbx.lock().await;
                let Some(e) = m.get(&id) else { return };
                (e.dir.clone(), e.meta.container_id.clone())
            };
            let sock = dir.join("aether.sock");
            let _ = std::fs::remove_file(&sock);
            let listener = match tokio::net::UnixListener::bind(&sock) {
                Ok(l) => l,
                Err(_) => return,
            };
            // aether retries every 250ms; the first dial is the channel.
            let (stream, _) = match listener.accept().await {
                Ok(x) => x,
                Err(_) => return,
            };
            let client = Client::from_stream(stream);
            {
                let mut m = edge.sbx.lock().await;
                match m.get_mut(&id) {
                    Some(e) => e.aether = Some(client.clone()),
                    None => return,
                }
            }
            client.closed().await;
            // Channel closed. If the sandbox should still be running this is a
            // failure (P §3.3); whether the container crashed decides the
            // repercussion signal (V4.1 §5.1.3).
            let (running, exit_code) = match &cid {
                Some(c) => edge.docker.inspect(c).await.map(|(r, e, _)| (r, e)).unwrap_or((false, None)),
                None => (false, None),
            };
            let mut m = edge.sbx.lock().await;
            let Some(e) = m.get_mut(&id) else { return };
            if e.meta.running() {
                if running {
                    e.meta.status = SbxStatus::Failed {
                        reason: "aether channel closed".into(),
                        exit_code: None,
                        repercussion: false,
                    };
                } else {
                    e.meta.status = SbxStatus::Failed {
                        reason: "environment crashed".into(),
                        exit_code,
                        repercussion: true,
                    };
                    edge.release_quota(&e.meta).await;
                }
                e.aether = None;
            }
        });
    }

    async fn release_quota(&self, meta: &Sandbox) {
        if let Some(iam) = &self.iam {
            let _ = iam
                .call("release", json!({ "project": meta.project, "cpu_mc": meta.cpu_mc, "mem_mb": meta.mem_mb }))
                .await;
        }
    }

    pub async fn get(&self, id: &str) -> Option<Sandbox> {
        self.sbx.lock().await.get(id).map(|e| e.meta.clone())
    }

    /// Directory holding the sandbox's aether socket (bind-mounted into the
    /// container); tests use it to run a stand-in aether.
    pub async fn socket_dir(&self, id: &str) -> Option<PathBuf> {
        self.sbx.lock().await.get(id).map(|e| e.dir.clone())
    }

    pub async fn list(&self) -> Vec<Sandbox> {
        self.sbx.lock().await.values().map(|e| e.meta.clone()).collect()
    }

    /// Stop and remove the container and release quota. Idempotent.
    pub async fn delete(&self, id: &str) -> Result<Sandbox, String> {
        let meta = {
            let mut m = self.sbx.lock().await;
            let Some(e) = m.get_mut(id) else { return Err(format!("unknown sandbox {id}")) };
            if e.meta.running() {
                e.meta.status = SbxStatus::Stopped { reason: "released".into() };
            }
            e.aether = None; // channel monitor sees non-running: no failure mark
            e.meta.clone()
        };
        if let Some(cid) = &meta.container_id {
            let _ = self.docker.stop(cid, 3).await;
            let _ = self.docker.remove(cid, true).await;
        }
        // Quota release for an explicit delete is the apiserver's job (it
        // charged); the edge releases only on paths it owns (TTL reap, crash).
        let _ = std::fs::remove_dir_all(self.cfg.data_dir.join("active").join(id));
        self.sbx.lock().await.remove(id);
        Ok(meta)
    }

    /// TTL reaper (P §2.3: sandboxes are reclaimed once their TTL elapses so
    /// idle sessions do not hold resources indefinitely).
    pub async fn reap_expired(&self) -> Vec<Sandbox> {
        let now = dsec_watcher::now_ms();
        let due: Vec<String> = {
            let m = self.sbx.lock().await;
            m.iter()
                .filter(|(_, e)| e.meta.running() && e.meta.ttl_ms.is_some_and(|t| e.meta.created_ms + t <= now))
                .map(|(k, _)| k.clone())
                .collect()
        };
        let mut out = vec![];
        for id in due {
            let meta = {
                let mut m = self.sbx.lock().await;
                match m.get_mut(&id) {
                    Some(e) => {
                        e.meta.status = SbxStatus::Stopped { reason: "ttl".into() };
                        e.meta.clone()
                    }
                    None => continue,
                }
            };
            self.release_quota(&meta).await;
            if let Ok(m) = self.delete(&id).await {
                out.push(m);
            }
        }
        out
    }

    pub fn start_background(self: &Arc<Self>) {
        let edge = self.clone();
        tokio::spawn(async move {
            let mut t = tokio::time::interval(edge.cfg.ttl_sweep);
            loop {
                t.tick().await;
                edge.reap_expired().await;
            }
        });
    }

    /// The watcher's `status` (P §3.2): per-edge health + running counts.
    pub async fn status(&self) -> Value {
        let m = self.sbx.lock().await;
        let (cpu_used, mem_used, n) = Self::used(&m);
        let mut by_backend = BTreeMap::new();
        let mut by_user = BTreeMap::new();
        let mut by_task = BTreeMap::new();
        for e in m.values().filter(|e| e.meta.running()) {
            *by_backend.entry("container".to_string()).or_insert(0) += 1;
            *by_user.entry(e.meta.user.clone()).or_insert(0) += 1;
            let task = e.meta.task.clone().unwrap_or_else(|| "-".into());
            *by_task.entry(task).or_insert(0) += 1;
        }
        json!({
            "edge_id": self.cfg.edge_id,
            "cpu_total_mc": self.cfg.cpu_total_mc, "cpu_used_mc": cpu_used,
            "mem_total_mb": self.cfg.mem_total_mb, "mem_used_mb": mem_used,
            "sbx_total": self.cfg.sbx_total, "sbx_used": n,
            "by_backend": by_backend, "by_user": by_user, "by_task": by_task,
            "capabilities": self.cfg.capabilities,
        })
    }

    /// Fast-forward decision for one operation (V4 §5.2.5).
    fn traj_replay(&self, sbx: &str, session: &str, idx: u64, op: &str, params: &Value) -> dsec_trajlog::Replay {
        self.traj.replay(sbx, session, idx, op, params)
    }

    fn traj_record(&self, sbx: &str, ctx: &OpCtx, result: Value) {
        let e = Entry {
            seq: 0,
            ts_ms: dsec_watcher::now_ms(),
            user: ctx.user.clone(),
            session: ctx.session.clone(),
            idx: ctx.idx,
            op: ctx.op.clone(),
            params: ctx.params.clone(),
            result,
        };
        let _ = self.traj.record(sbx, e);
    }

    pub fn traj_log(&self) -> &TrajLog {
        &self.traj
    }
}

/// Everything the trajectory log needs about one operation (V4 §5.2.5).
struct OpCtx {
    user: String,
    session: String,
    idx: u64,
    op: String,
    params: Value,
}

// ------------------------------------------------------------------ service

impl Edge {
    /// The aether channel of a running sandbox, or a precise error carrying
    /// the repercussion state (V4.1 §5.1.3) for failed environments.
    async fn aether_of(&self, id: &str) -> Result<Client, (String, String)> {
        let (status, client) = {
            let m = self.sbx.lock().await;
            let Some(e) = m.get(id) else { return Err(("not_found".into(), format!("unknown sandbox {id}"))) };
            (e.meta.status.clone(), e.aether.clone())
        };
        match (status, client) {
            (SbxStatus::Running, Some(c)) => Ok(c),
            (SbxStatus::Failed { reason, exit_code, repercussion }, _) => Err((
                "sandbox_failed".into(),
                format!("sandbox {id} failed: {reason} (exit={exit_code:?}, repercussion={repercussion})"),
            )),
            (s, _) => Err(("not_ready".into(), format!("sandbox {id} is in state {s:?}"))),
        }
    }

    /// One operation's journey: trajlog replay check, aether forward, record.
    async fn op_call(&self, req: &Request, method_on_aether: &str, op: &str) -> Result<Value, (String, String)> {
        let sbx = req.params["sandbox_id"].as_str().unwrap_or_default().to_string();
        // Replay key: the op's own params, without sandbox id / idx / token.
        let mut op_params = req.params.clone();
        op_params["sandbox_id"].take();
        op_params["idx"].take();
        let ctx = OpCtx {
            user: req.params["user"].as_str().unwrap_or("anon").to_string(),
            session: req.params["session"].as_str().unwrap_or("default").to_string(),
            idx: req.params["idx"].as_u64().unwrap_or(0),
            op: op.to_string(),
            params: op_params.clone(),
        };
        let c = self.aether_of(&sbx).await?;
        match self.traj_replay(&sbx, &ctx.session, ctx.idx, op, &ctx.params) {
            dsec_trajlog::Replay::Hit(e) => {
                let mut v = e.result;
                v["replayed"] = json!(true);
                Ok(v)
            }
            dsec_trajlog::Replay::Diverged(e) => Err((
                "traj_diverged".into(),
                format!(
                    "session {} idx {} already ran with different arguments ({} {}); refusing to re-execute",
                    ctx.session, ctx.idx, e.op, e.params
                ),
            )),
            dsec_trajlog::Replay::Miss => {
                let v = c.call(method_on_aether, ctx.params.clone()).await.map_err(|e| (e.code, e.message))?;
                self.traj_record(&sbx, &ctx, v.clone());
                Ok(v)
            }
        }
    }
}

pub struct EdgeService(pub Arc<Edge>);

impl Handler for EdgeService {
    async fn handle(&self, req: Request, out: Responder) {
        match req.method.as_str() {
            "status" => out.ok(self.0.status().await).await,
            "sandbox.create" => match self.0.create(req.params).await {
                Ok(m) => out.ok(serde_json::to_value(&m).unwrap()).await,
                Err((code, msg)) => out.err(&code, msg).await,
            },
            "sandbox.delete" => match self.0.delete(req.params["sandbox_id"].as_str().unwrap_or_default()).await {
                Ok(m) => out.ok(serde_json::to_value(&m).unwrap()).await,
                Err(e) => out.err("delete_failed", e).await,
            },
            "sandbox.get" => match self.0.get(req.params["sandbox_id"].as_str().unwrap_or_default()).await {
                Some(m) => out.ok(serde_json::to_value(&m).unwrap()).await,
                None => out.err("not_found", "no such sandbox").await,
            },
            "sandbox.list" => {
                let l = self.0.list().await;
                out.ok(json!({ "sandboxes": l })).await
            }
            "sandbox.exec" => match self.0.op_call(&req, "exec_collect", "exec").await {
                Ok(v) => out.ok(v).await,
                Err((code, msg)) => out.err(&code, msg).await,
            },
            "sandbox.read_file" => match self.0.op_call(&req, "read_file", "read_file").await {
                Ok(v) => out.ok(v).await,
                Err((code, msg)) => out.err(&code, msg).await,
            },
            "sandbox.write_file" => match self.0.op_call(&req, "write_file", "write_file").await {
                Ok(v) => out.ok(v).await,
                Err((code, msg)) => out.err(&code, msg).await,
            },
            "sandbox.list_dir" => match self.0.op_call(&req, "list_dir", "list_dir").await {
                Ok(v) => out.ok(v).await,
                Err((code, msg)) => out.err(&code, msg).await,
            },
            "sandbox.http" => match self.0.op_call(&req, "http", "http").await {
                Ok(v) => out.ok(v).await,
                Err((code, msg)) => out.err(&code, msg).await,
            },
            // Streaming exec (P §3.3): stdout/stderr chunks then exit info.
            // Streams are interaction, not replayable results: no trajlog.
            "sandbox.stream" => {
                let sbx = req.params["sandbox_id"].as_str().unwrap_or_default();
                let c = match self.0.aether_of(sbx).await {
                    Ok(c) => c,
                    Err((code, msg)) => return out.err(&code, msg).await,
                };
                let mut params = req.params.clone();
                params["sandbox_id"].take();
                match c.stream("exec", params).await {
                    Ok(mut rx) => {
                        while let Some(item) = rx.recv().await {
                            match item {
                                Ok(v) => {
                                    if !out.chunk(v).await {
                                        break;
                                    }
                                }
                                Err(e) => return out.err(&e.code, e.message).await,
                            }
                        }
                        out.end().await
                    }
                    Err(e) => out.err(&e.code, e.message).await,
                }
            }
            "sandbox.session_end" => {
                let sbx = req.params["sandbox_id"].as_str().unwrap_or_default();
                let session = req.params["session"].as_str().unwrap_or_default();
                match self.0.aether_of(sbx).await {
                    Ok(c) => match c.call("session_end", json!({ "session": session })).await {
                        Ok(_) => out.ok(json!({})).await,
                        Err(e) => out.err(&e.code, e.message).await,
                    },
                    Err((code, msg)) => out.err(&code, msg).await,
                }
            }
            "sandbox.traj" => {
                let sbx = req.params["sandbox_id"].as_str().unwrap_or_default();
                let entries = self.0.traj_log().query(sbx, req.params["session"].as_str(), req.params["op"].as_str());
                out.ok(json!({ "entries": entries })).await
            }
            _ => out.err("not_found", format!("no such method {}", req.method)).await,
        }
    }
}

#[cfg(test)]
mod tests;
