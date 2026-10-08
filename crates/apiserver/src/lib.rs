//! Apiserver: the stateless ingress of the sandbox cluster (P §3.2).
//!
//! All sandbox requests — creation, command execution, streaming I/O — enter
//! here. The apiserver keeps **no per-sandbox state**: it refreshes the edge
//! set from the watcher, and each sandbox id encodes its owning edge, so any
//! instance resolves and forwards directly to the target edge and the tier
//! scales horizontally.
//!
//! Management requests pass IAM first (authenticate the bearer token,
//! authorize the operation, charge quota on create / release on delete,
//! P §3.2). Creation asks the placement engine for a node and retries on
//! another node when the edge rejects for local capacity (P §7: the edge
//! keeps final admission authority).

use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::Duration;

use dsec_iam::Op;
use dsec_rpc::{Client, Handler, Request, Responder};
use serde_json::{json, Value};
use tokio::sync::RwLock;

/// Methods forwarded straight to the owning edge (authn still applies).
const FORWARDED: &[&str] = &[
    "sandbox.exec",
    "sandbox.read_file",
    "sandbox.write_file",
    "sandbox.list_dir",
    "sandbox.http",
    "sandbox.get",
    "sandbox.traj",
    "sandbox.session_end",
];

pub struct Apiserver {
    iam: Client,
    placement: Client,
    watcher: Client,
    /// edge_id -> rpc addr, refreshed from the watcher (P §3.2).
    routes: RwLock<HashMap<String, String>>,
    max_place_attempts: usize,
}

impl Apiserver {
    pub fn new(iam_addr: &str, placement_addr: &str, watcher_addr: &str) -> anyhow::Result<Arc<Apiserver>> {
        let a = Arc::new(Apiserver {
            iam: Client::new(iam_addr.parse()?),
            placement: Client::new(placement_addr.parse()?),
            watcher: Client::new(watcher_addr.parse()?),
            routes: RwLock::new(HashMap::new()),
            max_place_attempts: 4,
        });
        let a2 = a.clone();
        tokio::spawn(async move {
            a2.refresh_routes().await;
            loop {
                tokio::time::sleep(Duration::from_secs(2)).await;
                a2.refresh_routes().await;
            }
        });
        Ok(a)
    }

    async fn refresh_routes(&self) {
        if let Ok(v) = self.watcher.call("edges", json!({})).await {
            if let Some(m) = v["edges"].as_object() {
                if !m.is_empty() {
                    *self.routes.write().await =
                        m.iter().map(|(k, v)| (k.clone(), v.as_str().unwrap_or_default().to_string())).collect();
                }
            }
        }
    }

    /// The owning edge of a sandbox id: "sbx-<edge_id>-<hex>" (P §3.2).
    fn edge_of(id: &str) -> Option<&str> {
        let rest = id.strip_prefix("sbx-")?;
        let (edge, hex) = rest.rsplit_once('-')?;
        if edge.is_empty() || hex.is_empty() || hex.bytes().all(|b| b.is_ascii_hexdigit()) {
            Some(edge)
        } else {
            None
        }
    }

    async fn edge_client(&self, id: &str) -> Result<Client, dsec_rpc::RpcError> {
        let edge_id = Self::edge_of(id).ok_or_else(|| dsec_rpc::RpcError::new("bad_sandbox_id", format!("{id}: id does not encode an edge")))?;
        let addr = {
            let r = self.routes.read().await;
            r.get(edge_id).cloned()
        };
        let addr = match addr {
            Some(a) => Some(a),
            None => {
                self.refresh_routes().await;
                self.routes.read().await.get(edge_id).cloned()
            }
        };
        let addr = addr.ok_or_else(|| {
            dsec_rpc::RpcError::new("unknown_edge", format!("sandbox {id} names edge {edge_id}, which the watcher does not report"))
        })?;
        Ok(Client::new(addr.parse().unwrap()))
    }

    async fn authenticate(&self, token: &str) -> Result<String, dsec_rpc::RpcError> {
        match self.iam.call("authenticate", json!({ "token": token })).await {
            Ok(v) => Ok(v["principal"].as_str().unwrap_or_default().to_string()),
            Err(e) => Err(dsec_rpc::RpcError::new("denied", format!("authentication failed: {}", e.message))),
        }
    }

    async fn authorize(&self, principal: &str, project: &str, op: Op) -> Result<(), dsec_rpc::RpcError> {
        let r = self
            .iam
            .call("authorize", json!({ "principal": principal, "project": project, "op": op.as_str() }))
            .await
            .map_err(|e| dsec_rpc::RpcError::new("denied", e.message))?;
        let _ = r;
        Ok(())
    }

    /// Create with placement + edge-rejection retry (P §3.2, §7).
    async fn create(&self, principal: &str, params: Value) -> Result<Value, dsec_rpc::RpcError> {
        let project = params["project"].as_str().unwrap_or("root").to_string();
        let cpu_mc = params["cpu_mc"].as_u64().unwrap_or(500);
        let mem_mb = params["mem_mb"].as_u64().unwrap_or(512);
        self.authorize(principal, &project, Op::SandboxCreate).await?;
        self.iam
            .call("charge", json!({ "project": project, "cpu_mc": cpu_mc, "mem_mb": mem_mb }))
            .await
            .map_err(|e| dsec_rpc::RpcError::new(&e.code, e.message))?;
        let backend = params["backend"].as_str().unwrap_or("container").to_string();
        let mut excluded: HashSet<String> = HashSet::new();
        let mut last: Option<dsec_rpc::RpcError> = None;
        for _ in 0..self.max_place_attempts {
            let choice = match self
                .placement
                .call("select", json!({ "backend": backend, "requirements": [], "excluded": excluded.iter().collect::<Vec<_>>() }))
                .await
            {
                Ok(v) => v,
                Err(e) => {
                    last = Some(dsec_rpc::RpcError::new(&e.code, e.message));
                    break;
                }
            };
            let edge_id = choice["edge_id"].as_str().unwrap_or_default().to_string();
            let addr = choice["addr"].as_str().unwrap_or_default().to_string();
            let mut p = params.clone();
            p["user"] = json!(principal);
            let edge = Client::new(addr.parse().unwrap());
            match edge.call("sandbox.create", p).await {
                Ok(m) => return Ok(m),
                Err(e) if e.code == "edge_overloaded" || e.code == "unreachable" => {
                    // The edge refused for local capacity (P §7): try another
                    // node; the charge stays until a create succeeds or the
                    // attempts run out.
                    excluded.insert(edge_id);
                    last = Some(e);
                }
                Err(e) => {
                    self.iam.call("release", json!({ "project": project, "cpu_mc": cpu_mc, "mem_mb": mem_mb })).await.ok();
                    return Err(e);
                }
            }
        }
        self.iam.call("release", json!({ "project": project, "cpu_mc": cpu_mc, "mem_mb": mem_mb })).await.ok();
        Err(last.unwrap_or_else(|| dsec_rpc::RpcError::new("no_candidate", "no edge accepted the creation")))
    }

    async fn delete(&self, principal: &str, params: Value) -> Result<Value, dsec_rpc::RpcError> {
        let id = params["sandbox_id"].as_str().unwrap_or_default().to_string();
        let edge = self.edge_client(&id).await?;
        // Release needs the sandbox's own charge: fetch meta first.
        let meta = edge.call("sandbox.get", json!({ "sandbox_id": id })).await.map_err(|e| dsec_rpc::RpcError::new(&e.code, e.message))?;
        let project = meta["project"].as_str().unwrap_or("root").to_string();
        self.authorize(principal, &project, Op::SandboxDelete).await?;
        let out = edge.call("sandbox.delete", json!({ "sandbox_id": id })).await.map_err(|e| dsec_rpc::RpcError::new(&e.code, e.message))?;
        self.iam
            .call(
                "release",
                json!({ "project": project, "cpu_mc": meta["cpu_mc"], "mem_mb": meta["mem_mb"] }),
            )
            .await
            .ok();
        Ok(out)
    }
}

pub struct ApiserverService(pub Arc<Apiserver>);

impl Handler for ApiserverService {
    async fn handle(&self, req: Request, out: Responder) {
        let Some(token) = req.token.clone() else {
            return out.err("denied", "missing bearer token").await;
        };
        let principal = match self.0.authenticate(&token).await {
            Ok(p) => p,
            Err(e) => return out.err(&e.code, e.message).await,
        };
        let mut params = req.params.clone();
        params["user"] = json!(principal);
        match req.method.as_str() {
            "sandbox.create" => match self.0.create(&principal, params).await {
                Ok(v) => out.ok(v).await,
                Err(e) => out.err(&e.code, e.message).await,
            },
            "sandbox.delete" => match self.0.delete(&principal, params).await {
                Ok(v) => out.ok(v).await,
                Err(e) => out.err(&e.code, e.message).await,
            },
            "sandbox.stream" => {
                let id = params["sandbox_id"].as_str().unwrap_or_default().to_string();
                let edge = match self.0.edge_client(&id).await {
                    Ok(e) => e,
                    Err(e) => return out.err(&e.code, e.message).await,
                };
                match edge.stream("sandbox.stream", params).await {
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
            m if FORWARDED.contains(&m) => {
                let id = params["sandbox_id"].as_str().unwrap_or_default().to_string();
                match self.0.edge_client(&id).await {
                    Ok(edge) => match edge.call(m, params).await {
                        Ok(v) => out.ok(v).await,
                        Err(e) => out.err(&e.code, e.message).await,
                    },
                    Err(e) => out.err(&e.code, e.message).await,
                }
            }
            _ => out.err("not_found", format!("no such method {}", req.method)).await,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use dsec_aether::{Aether, SessionOpts, UnixTransport};
    use dsec_rpc::Listener;
    use dsec_edge::{Edge, EdgeConfig, EdgeService};
    use dsec_iam::{Iam, PrincipalKind, Quota};
    use dsec_placement::{Opts, Placement, PlacementService};
    use dsec_watcher::{Watcher, WatcherService};
    use std::collections::BTreeMap;

    /// Full unprivileged stack: iam + watcher + placement + edge (fake docker,
    /// real in-process aether) + N apiserver instances that share nothing but
    /// service addresses.
    struct Lab {
        api_addr: Vec<dsec_rpc::Addr>,
        iam: Arc<Iam>,
        edge: Arc<Edge>,
        alice_token: String,
        _dirs: Vec<tempfile::TempDir>,
    }

    impl Lab {
        fn alice(&self, i: usize) -> Client {
            Client::new(self.api_addr[i].clone()).with_token(&self.alice_token)
        }
        fn mallory(&self, i: usize) -> Client {
            let t = self.iam.principal("mallory").unwrap().token;
            Client::new(self.api_addr[i].clone()).with_token(&t)
        }
    }

    async fn fake_docker() -> (String, tempfile::TempDir) {
        let dir = tempfile::tempdir().unwrap();
        let sock = dir.path().join("docker.sock");
        let s = sock.clone();
        tokio::spawn(async move {
            use tokio::io::{AsyncReadExt, AsyncWriteExt};
            let l = tokio::net::UnixListener::bind(&s).unwrap();
            while let Ok((mut c, _)) = l.accept().await {
                tokio::spawn(async move {
                    let mut buf = vec![0u8; 65536];
                    let n = c.read(&mut buf).await.unwrap_or(0);
                    let text = String::from_utf8_lossy(&buf[..n]).into_owned();
                    let head = text.split("\r\n\r\n").next().unwrap_or("");
                    let path = head.lines().next().unwrap_or("").split_whitespace().nth(1).unwrap_or("");
                    let (code, body) = if path.contains("/containers/create") {
                        ("201 Created", r#"{"Id":"cid1"}"#)
                    } else if path.contains("/json") {
                        ("200 OK", r#"{"State":{"Running":true,"ExitCode":0,"StartedAt":"2026-10-07T00:00:00Z"}}"#)
                    } else {
                        ("204 No Content", "")
                    };
                    let resp = format!("HTTP/1.1 {code} x\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len());
                    c.write_all(resp.as_bytes()).await.unwrap_or(());
                });
            }
        });
        (format!("unix://{}", sock.display()), dir)
    }

    async fn lab(n_apis: usize) -> Lab {
        let iam = Arc::new(Iam::in_memory());
        for p in ["alice", "admin", "mallory"] {
            iam.add_principal(p, PrincipalKind::Human);
        }
        let alice_token = iam.principal("alice").unwrap().token;
        iam.create_root_project("root", Quota { cpu_mc: 100_000, mem_mb: 100_000, sandboxes: 100 }, "admin").unwrap();
        iam.set_policy("admin", "root", "alice", [Op::SandboxCreate, Op::SandboxDelete, Op::SandboxExec].into()).unwrap();

        let iam_l = Listener::bind(&"tcp://127.0.0.1:0".parse().unwrap()).await.unwrap();
        let iam_addr = iam_l.local_addr().unwrap();
        tokio::spawn(iam_l.serve(Arc::new(dsec_iam::rpc::IamService(iam.clone()))));

        let (docker_addr, d1) = fake_docker().await;
        let dir = tempfile::tempdir().unwrap();
        let cfg = EdgeConfig {
            edge_id: "e-lab".into(),
            data_dir: dir.path().join("edge"),
            docker_sock: docker_addr.strip_prefix("unix://").unwrap().into(),
            ttl_sweep: Duration::from_secs(3600),
            ..Default::default()
        };
        let edge = Edge::new(cfg).unwrap();
        edge.start_background();
        let edge_l = Listener::bind(&"tcp://127.0.0.1:0".parse().unwrap()).await.unwrap();
        let edge_addr = edge_l.local_addr().unwrap();
        tokio::spawn(edge_l.serve(Arc::new(EdgeService(edge.clone()))));

        let w = Watcher::start(BTreeMap::from([("e-lab".into(), edge_addr.to_string())]), Duration::from_millis(150));
        let w_l = Listener::bind(&"tcp://127.0.0.1:0".parse().unwrap()).await.unwrap();
        let w_addr = w_l.local_addr().unwrap();
        tokio::spawn(w_l.serve(Arc::new(WatcherService(w))));

        let pl = Arc::new(Placement::new(
            Arc::new(dsec_placement::WatcherView { addr: w_addr.clone() }),
            Opts { refresh: Duration::from_millis(100), ..Default::default() },
        ));
        let pl_l = Listener::bind(&"tcp://127.0.0.1:0".parse().unwrap()).await.unwrap();
        let pl_addr = pl_l.local_addr().unwrap();
        tokio::spawn(pl_l.serve(Arc::new(PlacementService(pl))));

        let mut api_addr = vec![];
        for _ in 0..n_apis {
            let a = Apiserver::new(&iam_addr.to_string(), &pl_addr.to_string(), &w_addr.to_string()).unwrap();
            let l = Listener::bind(&"tcp://127.0.0.1:0".parse().unwrap()).await.unwrap();
            api_addr.push(l.local_addr().unwrap());
            tokio::spawn(l.serve(Arc::new(ApiserverService(a))));
        }
        tokio::time::sleep(Duration::from_millis(300)).await;
        Lab { api_addr, iam, edge, alice_token, _dirs: vec![d1, dir] }
    }

    async fn attach_aether(l: &Lab, id: &str) -> tokio::task::JoinHandle<()> {
        let dir = l.edge.socket_dir(id).await.expect("sandbox exists");
        for _ in 0..100 {
            if dir.join("aether.sock").exists() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        let sock = dir.join("aether.sock");
        let addr = format!("unix://{}", sock.display());
        let a = Aether::new(Box::new(UnixTransport), SessionOpts::default());
        tokio::spawn(async move { a.run(&addr).await })
    }

    #[tokio::test]
    async fn management_ops_are_iam_gated_and_quota_charged() {
        let l = lab(1).await;
        let c = l.alice(0);
        // No token at all.
        let bare = Client::new(l.api_addr[0].clone());
        let e = bare.call("sandbox.create", json!({ "project": "root" })).await.unwrap_err();
        assert_eq!(e.code, "denied");
        // Forged token.
        let forged = Client::new(l.api_addr[0].clone()).with_token("dsec-forged");
        let e = forged.call("sandbox.create", json!({ "project": "root" })).await.unwrap_err();
        assert_eq!(e.code, "denied");
        // Principal with no policy on root (mallory) is denied create.
        let e = l.mallory(0).call("sandbox.create", json!({ "project": "root" })).await.unwrap_err();
        assert_eq!(e.code, "denied", "{}", e.message);
        // alice: create charges quota.
        let m = c
            .call("sandbox.create", json!({ "project": "root", "cpu_mc": 1000, "mem_mb": 100 }))
            .await
            .unwrap();
        let id = m["id"].as_str().unwrap().to_string();
        assert_eq!(l.iam.usage("root").unwrap().sandboxes, 1);
        let h = attach_aether(&l, &id).await;
        let r = c.call("sandbox.exec", json!({ "sandbox_id": id, "session": "s", "idx": 0, "cmd": "echo hi" })).await.unwrap();
        assert_eq!(r["stdout"].as_str().unwrap(), "hi\n");
        // mallory cannot delete alice's sandbox either.
        let e = l.mallory(0).call("sandbox.delete", json!({ "sandbox_id": id })).await.unwrap_err();
        assert_eq!(e.code, "denied");
        // alice's delete releases the charge.
        c.call("sandbox.delete", json!({ "sandbox_id": id })).await.unwrap();
        assert_eq!(l.iam.usage("root").unwrap().sandboxes, 0);
        h.abort();
    }

    #[tokio::test]
    async fn two_instances_route_the_same_sandbox_identically() {
        let l = lab(2).await;
        let m = l.alice(0)
            .call("sandbox.create", json!({ "project": "root", "cpu_mc": 500, "mem_mb": 100 }))
            .await
            .unwrap();
        let id = m["id"].as_str().unwrap().to_string();
        let h = attach_aether(&l, &id).await;
        // Created through instance 0; instance 1 shares no state yet must
        // resolve the same owning edge purely from the id + watcher view.
        for (i, c) in l.api_addr.iter().enumerate() {
            let cl = Client::new(c.clone()).with_token(&l.alice_token);
            let r = cl
                .call("sandbox.exec", json!({ "sandbox_id": id, "session": "s", "idx": 0, "cmd": "echo routed" }))
                .await
                .unwrap();
            assert_eq!(r["stdout"].as_str().unwrap(), "routed\n");
            if i == 0 {
                assert!(r.get("replayed").is_none(), "first run executes");
            } else {
                assert_eq!(r["replayed"].as_bool(), Some(true), "same op via the other instance replays");
            }
        }
        let e = l.alice(1).call("sandbox.get", json!({ "sandbox_id": "sbx-elsewhere-0123456789ab" })).await.unwrap_err();
        assert_eq!(e.code, "unknown_edge", "{}", e.message);
        let e = l.alice(1).call("sandbox.get", json!({ "sandbox_id": "garbage" })).await.unwrap_err();
        assert_eq!(e.code, "bad_sandbox_id");
        h.abort();
        l.alice(0).call("sandbox.delete", json!({ "sandbox_id": id })).await.unwrap();
    }
}
