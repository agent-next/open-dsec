use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use serde_json::{json, Value};

use dsec_aether::{Aether, SessionOpts, UnixTransport};
use dsec_rpc::{Client, Listener};

use super::*;

// ------------------------------------------------- fake Docker Engine API

/// Serves enough of the Docker API over a Unix socket for the edge, recording
/// every request. Inspect results are settable so tests can crash containers.
struct FakeDocker {
    #[allow(dead_code)]
    sock: PathBuf,
    running: std::sync::Arc<std::sync::atomic::AtomicBool>,
    exit_code: std::sync::Arc<std::sync::Mutex<Option<i64>>>,
    requests: std::sync::Arc<tokio::sync::Mutex<Vec<(String, String, Value)>>>,
}

impl FakeDocker {
    async fn start() -> (Arc<FakeDocker>, String) {
        let dir = tempfile::tempdir().unwrap();
        let sock = dir.keep().join("docker.sock");
        let f = Arc::new(FakeDocker {
            sock: sock.clone(),
            running: Arc::new(std::sync::atomic::AtomicBool::new(true)),
            exit_code: Arc::new(std::sync::Mutex::new(None)),
            requests: Arc::new(tokio::sync::Mutex::new(vec![])),
        });
        let l = tokio::net::UnixListener::bind(&sock).unwrap();
        let f2 = f.clone();
        tokio::spawn(async move {
            while let Ok((mut s, _)) = l.accept().await {
                let f3 = f2.clone();
                tokio::spawn(async move {
                    use tokio::io::{AsyncReadExt, AsyncWriteExt};
                    let mut buf = vec![0u8; 64 * 1024];
                    let n = s.read(&mut buf).await.unwrap();
                    let text = String::from_utf8_lossy(&buf[..n]).into_owned();
                    let (head, body) = text.split_once("\r\n\r\n").unwrap_or((&text, ""));
                    let mut lines = head.split("\r\n");
                    let reqline = lines.next().unwrap_or("");
                    let mut parts = reqline.split_whitespace();
                    let method = parts.next().unwrap_or("").to_string();
                    let path = parts.next().unwrap_or("").to_string();
                    let mut len = 0usize;
                    for l in lines {
                        if let Some((k, v)) = l.split_once(':') {
                            if k.trim().eq_ignore_ascii_case("content-length") {
                                len = v.trim().parse().unwrap_or(0);
                            }
                        }
                    }
                    let mut body = body.as_bytes().to_vec();
                    while body.len() < len {
                        let m = s.read(&mut buf).await.unwrap();
                        if m == 0 {
                            break;
                        }
                        body.extend_from_slice(&buf[..m]);
                    }
                    let v: Value = if body.is_empty() {
                        Value::Null
                    } else {
                        serde_json::from_slice(&body).unwrap_or(Value::Null)
                    };
                    f3.requests
                        .lock()
                        .await
                        .push((method.clone(), path.clone(), v.clone()));
                    let (code, resp) = f3.route(&method, &path, &v).await;
                    let body = serde_json::to_string(&resp).unwrap_or_default();
                    let out = format!(
                        "HTTP/1.1 {code} x\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                        body.len()
                    );
                    s.write_all(out.as_bytes()).await.unwrap();
                });
            }
        });
        (f, format!("unix://{}", sock.display()))
    }

    async fn route(&self, method: &str, path: &str, _body: &Value) -> (&'static str, Value) {
        let create = path.starts_with("/v1.43/containers/create");
        let start = method == "POST" && path.ends_with("/start");
        let stop = method == "POST" && path.contains("/stop");
        let rm = method == "DELETE" && path.starts_with("/v1.43/containers/");
        let inspect = method == "GET" && path.ends_with("/json");
        if create {
            static N: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
            let id = format!("cid{}", N.fetch_add(1, std::sync::atomic::Ordering::SeqCst));
            return ("201 Created", json!({ "Id": id }));
        }
        if start || stop || rm {
            return ("204 No Content", json!({}));
        }
        if inspect {
            let running = self.running.load(std::sync::atomic::Ordering::SeqCst);
            let exit = *self.exit_code.lock().unwrap();
            return (
                "200 OK",
                json!({ "State": { "Running": running, "ExitCode": exit.unwrap_or(0), "StartedAt": "2026-10-07T00:00:00Z" } }),
            );
        }
        ("404 Not Found", json!({ "message": "no such route" }))
    }

    async fn requests(&self) -> Vec<(String, String, Value)> {
        self.requests.lock().await.clone()
    }
}

// ---------------------------------------------------------------- helpers

fn cfg(dir: &std::path::Path, docker_addr: &str) -> EdgeConfig {
    EdgeConfig {
        edge_id: "e-test".into(),
        docker_sock: docker_addr.strip_prefix("unix://").unwrap().into(),
        data_dir: dir.join("edge"),
        aether_bin: "/usr/local/bin/dsec-aether".into(),
        iam_addr: String::new(),
        ttl_sweep: Duration::from_millis(100),
        sbx_total: 64,
        cpu_total_mc: 8_000,
        mem_total_mb: 16_384,
        ..Default::default()
    }
}

struct Stack {
    edge: Arc<Edge>,
    client: Client,
    docker: Option<Arc<FakeDocker>>,
    _dir: tempfile::TempDir,
}

async fn stack(tweak: impl FnOnce(&mut EdgeConfig)) -> Stack {
    let (docker, daddr) = FakeDocker::start().await;
    let dir = tempfile::tempdir().unwrap();
    let mut c = cfg(dir.path(), &daddr);
    tweak(&mut c);
    let edge = Edge::new(c).unwrap();
    edge.start_background();
    let l = Listener::bind(&"tcp://127.0.0.1:0".parse().unwrap())
        .await
        .unwrap();
    let addr = l.local_addr().unwrap();
    tokio::spawn(l.serve(Arc::new(EdgeService(edge.clone()))));
    Stack {
        edge,
        client: Client::new(addr),
        docker: Some(docker),
        _dir: dir,
    }
}

async fn create(s: &Stack, extra: Value) -> Sandbox {
    let v = s
        .client
        .call(
            "sandbox.create",
            json!({ "user": "alice", "project": "root", "image": "ubuntu:24.04", "cpu_mc": 500, "mem_mb": 256, "network": {"pypi": true, "npm": false} }),
        )
        .await;
    if let Err(e) = &v {
        panic!("create failed: {e:?}");
    }
    let mut m: Sandbox = serde_json::from_value(v.unwrap()).unwrap();
    for (k, val) in extra.as_object().into_iter().flatten() {
        m.network[k.clone()] = val.clone();
    }
    m
}

/// Spawn a real aether dialing the sandbox's socket (in production aether runs
/// inside the container; the harness here runs it on the host process).
async fn attach_aether(s: &Stack, id: &str) -> tokio::task::JoinHandle<()> {
    let dir = {
        let m = s.edge.sbx.lock().await;
        m.get(id).unwrap().dir.clone()
    };
    // Wait for the edge to bind the socket.
    for _ in 0..100 {
        if dir.join("aether.sock").exists() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    let addr = format!("unix://{}", dir.join("aether.sock").display());
    let a = Aether::new(Box::new(UnixTransport), SessionOpts::default());
    tokio::spawn(async move { a.run(&addr).await })
}

async fn exec(s: &Stack, id: &str, session: &str, idx: u64, cmd: &str) -> Value {
    s.client
        .call(
            "sandbox.exec",
            json!({ "sandbox_id": id, "session": session, "idx": idx, "cmd": cmd, "user": "alice" }),
        )
        .await
        .expect("exec")
}

// ----------------------------------------------------------------- tests

#[tokio::test]
async fn create_uses_cpu_mem_limits_none_network_and_labels() {
    let s = stack(|_| {}).await;
    let m = create(&s, json!({})).await;
    assert!(
        m.id.starts_with("sbx-e-test-"),
        "id must encode the edge: {}",
        m.id
    );
    assert_eq!(m.edge_id, "e-test");
    assert_eq!(m.status, SbxStatus::Running);
    let reqs = s.docker.as_ref().unwrap().requests().await;
    let (method, path, body) = reqs
        .iter()
        .find(|(m, p, _)| m == "POST" && p.starts_with("/v1.43/containers/create"))
        .unwrap();
    assert!(path.contains("name=dsec-sbx-e-test-"), "{path}");
    assert_eq!(body["HostConfig"]["NanoCpus"], json!(500 * 1_000_000));
    assert_eq!(body["HostConfig"]["Memory"], json!(256 * 1024 * 1024));
    assert_eq!(body["HostConfig"]["NetworkMode"], "none");
    assert_eq!(body["Labels"]["open-dsec"], "1");
    assert_eq!(body["Labels"]["open-dsec.sandbox"], m.id);
    let binds = body["HostConfig"]["Binds"].as_array().unwrap();
    assert!(
        binds
            .iter()
            .any(|b| b.as_str().unwrap().ends_with(":/run/dsec")),
        "{binds:?}"
    );
    assert!(
        binds
            .iter()
            .any(|b| b.as_str().unwrap().contains("dsec-aether")),
        "{binds:?}"
    );
    assert!(
        body["Cmd"][0].as_str().unwrap().ends_with("/dsec-aether"),
        "{:?}",
        body["Cmd"]
    );
    assert_eq!(body["Cmd"][1], "unix:///run/dsec/aether.sock");
    let _ = method;
    s.client
        .call("sandbox.delete", json!({ "sandbox_id": m.id }))
        .await
        .unwrap();
}

#[tokio::test]
async fn admission_rejects_when_over_the_warning_threshold() {
    let s = stack(|c| {
        c.sbx_total = 2;
        c.cpu_total_mc = 1_000;
    })
    .await;
    let a = create(&s, json!({})).await; // 500mc of 1000: 50%
    let e = s
        .client
        .call(
            "sandbox.create",
            json!({ "user": "alice", "project": "root", "cpu_mc": 500, "mem_mb": 256 }),
        )
        .await
        .unwrap_err();
    // (used+req)=1000 > 900 threshold -> overloaded. And a 2nd sandbox alone
    // would also trip the count threshold (2 > 0.9*2).
    assert_eq!(e.code, "edge_overloaded", "{}", e.message);
    s.client
        .call("sandbox.delete", json!({ "sandbox_id": a.id }))
        .await
        .unwrap();
    // After release, room again.
    let b = s
        .client
        .call(
            "sandbox.create",
            json!({ "user": "alice", "project": "root", "cpu_mc": 500, "mem_mb": 256 }),
        )
        .await
        .unwrap();
    s.client
        .call(
            "sandbox.delete",
            json!({ "sandbox_id": b["id"].as_str().unwrap() }),
        )
        .await
        .unwrap();
}

#[tokio::test]
async fn crashed_environment_marks_failed_with_repercussion() {
    let s = stack(|_| {}).await;
    let m = create(&s, json!({})).await;
    let h = attach_aether(&s, &m.id).await;
    // Channel up: exec must work (aether adopted).
    let r = exec(&s, &m.id, "t", 0, "echo alive").await;
    assert_eq!(r["stdout"].as_str().unwrap(), "alive\n");
    // The container dies (docker says not running, exit 137), then aether's
    // channel closes: failed trajectory + repercussion (V4.1 §5.1.3).
    s.docker
        .as_ref()
        .unwrap()
        .running
        .store(false, std::sync::atomic::Ordering::SeqCst);
    *s.docker.as_ref().unwrap().exit_code.lock().unwrap() = Some(137);
    h.abort();
    let mut meta = None;
    for _ in 0..100 {
        if let Some(g) = s.edge.get(&m.id).await {
            if !g.running() {
                meta = Some(g);
                break;
            }
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    let g = meta.expect("sandbox must be marked failed after channel close");
    match g.status {
        SbxStatus::Failed {
            reason,
            exit_code,
            repercussion,
        } => {
            assert!(reason.contains("crash"), "{reason}");
            assert_eq!(exit_code, Some(137));
            assert!(
                repercussion,
                "crashed environment must raise the repercussion signal"
            );
        }
        other => panic!("{other:?}"),
    }
    // Further operations are refused with the repercussion in the message.
    let e = s
        .client
        .call(
            "sandbox.exec",
            json!({ "sandbox_id": m.id, "session": "t", "idx": 1, "cmd": "echo no" }),
        )
        .await
        .unwrap_err();
    assert_eq!(e.code, "sandbox_failed");
    assert!(e.message.contains("repercussion=true"), "{}", e.message);
    s.client
        .call("sandbox.delete", json!({ "sandbox_id": m.id }))
        .await
        .unwrap();
}

#[tokio::test]
async fn channel_close_with_live_container_fails_without_repercussion() {
    let s = stack(|_| {}).await;
    let m = create(&s, json!({})).await;
    let h = attach_aether(&s, &m.id).await;
    let r = exec(&s, &m.id, "t", 0, "echo ok").await;
    assert_eq!(r["stdout"].as_str().unwrap(), "ok\n");
    h.abort(); // aether dies, container still "running" per docker
    let mut meta = None;
    for _ in 0..100 {
        if let Some(g) = s.edge.get(&m.id).await {
            if !g.running() {
                meta = Some(g);
                break;
            }
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    match meta.expect("failed").status {
        SbxStatus::Failed { repercussion, .. } => assert!(!repercussion),
        other => panic!("{other:?}"),
    }
    s.client
        .call("sandbox.delete", json!({ "sandbox_id": m.id }))
        .await
        .unwrap();
}

#[tokio::test]
async fn ttl_reaper_releases_idle_sandboxes() {
    let s = stack(|_| {}).await;
    let m = s
        .client
        .call(
            "sandbox.create",
            json!({ "user": "alice", "project": "root", "cpu_mc": 100, "mem_mb": 64, "ttl_ms": 200 }),
        )
        .await
        .unwrap();
    let id = m["id"].as_str().unwrap().to_string();
    tokio::time::sleep(Duration::from_millis(600)).await;
    assert!(
        s.edge.get(&id).await.is_none(),
        "TTL sandbox must be reaped and removed"
    );
    let reqs = s.docker.as_ref().unwrap().requests().await;
    assert!(
        reqs.iter()
            .any(|(m, p, _)| m == "POST" && p.contains("/stop")),
        "stop called"
    );
    assert!(
        reqs.iter()
            .any(|(m, p, _)| m == "DELETE" && p.starts_with("/v1.43/containers/")),
        "remove called"
    );
}

#[tokio::test]
async fn exec_state_persists_and_trajlog_replay_never_reexecutes() {
    let s = stack(|_| {}).await;
    let m = create(&s, json!({})).await;
    let h = attach_aether(&s, &m.id).await;
    let f = std::env::temp_dir().join(format!("dsec-traj-test-{}", std::process::id()));
    let _ = std::fs::remove_file(&f);
    let cmd = format!("echo x >> {p}; wc -l < {p}", p = f.display());
    // Same session: cwd/env persist across idx 0 and 1.
    let r = exec(
        &s,
        &m.id,
        "sess",
        0,
        &format!("cd /tmp && export DSEC_T=1 && {cmd}"),
    )
    .await;
    assert_eq!(r["stdout"].as_str().unwrap(), "1\n");
    let r = exec(&s, &m.id, "sess", 1, "echo $DSEC_T").await;
    assert_eq!(r["stdout"].as_str().unwrap(), "1\n");
    // Re-issue idx 0 verbatim (as a preempted client resuming): cached result,
    // never re-executed — the file would have two lines if it re-ran.
    let r = exec(
        &s,
        &m.id,
        "sess",
        0,
        &format!("cd /tmp && export DSEC_T=1 && {cmd}"),
    )
    .await;
    assert_eq!(
        r["replayed"].as_bool(),
        Some(true),
        "must come from the trajectory log"
    );
    assert_eq!(
        r["stdout"].as_str().unwrap(),
        "1\n",
        "cached stdout, not a re-run"
    );
    // Divergence: same identity, different command -> surfaced, not replayed.
    let e = s
        .client
        .call("sandbox.exec", json!({ "sandbox_id": m.id, "session": "sess", "idx": 0, "cmd": "echo other", "user": "alice" }))
        .await
        .unwrap_err();
    assert_eq!(e.code, "traj_diverged");
    // Provenance query (V4 §5.2.5): ordered entries with user attribution.
    let traj = s
        .client
        .call("sandbox.traj", json!({ "sandbox_id": m.id }))
        .await
        .unwrap();
    let entries = traj["entries"].as_array().unwrap();
    assert_eq!(entries.len(), 2);
    assert_eq!(entries[0]["seq"], 1);
    assert_eq!(entries[0]["user"], "alice");
    assert_eq!(entries[0]["op"], "exec");
    h.abort();
    let _ = std::fs::remove_file(&f);
    s.client
        .call("sandbox.delete", json!({ "sandbox_id": m.id }))
        .await
        .unwrap();
}

#[tokio::test]
async fn status_reports_counts_for_the_watcher() {
    let s = stack(|_| {}).await;
    let a = s
        .client
        .call("sandbox.create", json!({ "user": "alice", "project": "root", "cpu_mc": 500, "mem_mb": 256, "task": "swe" }))
        .await
        .unwrap();
    let _b = s
        .client
        .call(
            "sandbox.create",
            json!({ "user": "bob", "project": "root", "cpu_mc": 500, "mem_mb": 256 }),
        )
        .await
        .unwrap();
    let st = s.edge.status().await;
    assert_eq!(st["sbx_used"], 2);
    assert_eq!(st["by_user"]["alice"], 1);
    assert_eq!(st["by_user"]["bob"], 1);
    assert_eq!(st["by_backend"]["container"], 2);
    assert_eq!(st["by_task"]["swe"], 1);
    assert_eq!(st["capabilities"][0], "container");
    let parsed: dsec_watcher::EdgeStatus = serde_json::from_value(st).unwrap();
    assert_eq!(parsed.cpu_used_mc, 1000);
    s.client
        .call("sandbox.delete", json!({ "sandbox_id": a["id"] }))
        .await
        .unwrap();
}

#[tokio::test]
async fn streaming_exec_chunks_flow_through_the_edge() {
    let s = stack(|_| {}).await;
    let m = create(&s, json!({})).await;
    let h = attach_aether(&s, &m.id).await;
    let mut rx = s
        .client
        .stream(
            "sandbox.stream",
            json!({ "sandbox_id": m.id, "session": "t", "cmd": "echo one; sleep 1; echo two" }),
        )
        .await
        .unwrap();
    let t0 = std::time::Instant::now();
    let first = rx.recv().await.unwrap().unwrap();
    assert_eq!(first["data"].as_str().unwrap(), "one\n");
    assert!(t0.elapsed() < Duration::from_millis(800));
    let mut exit = false;
    while let Some(v) = rx.recv().await {
        if v.unwrap().get("code").is_some() {
            exit = true;
        }
    }
    assert!(exit);
    h.abort();
    s.client
        .call("sandbox.delete", json!({ "sandbox_id": m.id }))
        .await
        .unwrap();
}

#[tokio::test]
async fn delete_stops_removes_and_cleans_state() {
    let s = stack(|_| {}).await;
    let m = create(&s, json!({})).await;
    let dir = s.cfg_active_dir(&m.id).await;
    s.client
        .call("sandbox.delete", json!({ "sandbox_id": m.id }))
        .await
        .unwrap();
    assert!(s.edge.get(&m.id).await.is_none());
    assert!(!dir.exists(), "sandbox dir must be removed");
    let reqs = s.docker.as_ref().unwrap().requests().await;
    assert!(reqs
        .iter()
        .any(|(m, p, _)| m == "POST" && p.contains("/stop")));
    assert!(reqs.iter().any(|(m, _, _)| m == "DELETE"));
}

impl Stack {
    async fn cfg_active_dir(&self, id: &str) -> PathBuf {
        self.edge.cfg.data_dir.join("active").join(id)
    }
}

// Real-docker tests: `cargo test -p dsec-edge -- --ignored` / make host-check.
mod host {
    use super::*;

    fn aether_bin() -> String {
        std::env::var("DSEC_AETHER_BIN").unwrap_or_else(|_| {
            let p =
                PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../target/debug/dsec-aether");
            p.to_string_lossy().into_owned()
        })
    }

    fn host_cfg() -> EdgeConfig {
        EdgeConfig {
            edge_id: "e-docker".into(),
            data_dir: std::env::temp_dir().join(format!("dsec-edge-host-{}", std::process::id())),
            aether_bin: aether_bin().into(),
            sbx_total: 8,
            ..Default::default()
        }
    }

    async fn host_stack() -> Stack {
        let dir = tempfile::tempdir().unwrap();
        let c = EdgeConfig {
            data_dir: host_cfg().data_dir,
            ..host_cfg()
        };
        let edge = Edge::new(c).unwrap();
        edge.start_background();
        let l = Listener::bind(&"tcp://127.0.0.1:0".parse().unwrap())
            .await
            .unwrap();
        let addr = l.local_addr().unwrap();
        tokio::spawn(l.serve(Arc::new(EdgeService(edge.clone()))));
        Stack {
            edge,
            client: Client::new(addr),
            docker: None,
            _dir: dir,
        }
    }

    /// Real container: network none, cpu/mem limits, aether + chronus work,
    /// release leaves no container behind.
    #[tokio::test]
    #[ignore]
    async fn real_docker_container_end_to_end() {
        let s = host_stack().await;
        let m: Sandbox = serde_json::from_value(
            s.client
                .call(
                    "sandbox.create",
                    json!({ "user": "alice", "project": "root", "image": "ubuntu:24.04", "cpu_mc": 500, "mem_mb": 256, "ttl_ms": 600_000 }),
                )
                .await
                .unwrap(),
        )
        .unwrap();
        // Wait for in-container aether to dial in.
        let mut ok = false;
        for _ in 0..300 {
            if let Ok(r) = s
                .client
                .call("sandbox.exec", json!({ "sandbox_id": m.id, "session": "t", "idx": 0, "cmd": "echo in-container", "user": "alice" }))
                .await
            {
                assert_eq!(r["stdout"].as_str().unwrap(), "in-container\n");
                ok = true;
                break;
            }
            tokio::time::sleep(Duration::from_millis(200)).await;
        }
        assert!(ok, "aether never connected");
        // Network none: only the loopback interface exists.
        let r = s
            .client
            .call("sandbox.exec", json!({ "sandbox_id": m.id, "session": "t", "idx": 1, "cmd": "ls /sys/class/net | tr '\\n' ' '", "user": "alice" }))
            .await
            .unwrap();
        assert_eq!(r["stdout"].as_str().unwrap(), "lo ");
        // CPU limit: 0.5 cpu -> cpu.max "50000 100000".
        let r = s
            .client
            .call("sandbox.exec", json!({ "sandbox_id": m.id, "session": "t", "idx": 2, "cmd": "cat /sys/fs/cgroup/cpu.max", "user": "alice" }))
            .await
            .unwrap();
        assert_eq!(r["stdout"].as_str().unwrap(), "50000 100000\n");
        s.client
            .call("sandbox.delete", json!({ "sandbox_id": m.id }))
            .await
            .unwrap();
        assert!(s.edge.get(&m.id).await.is_none());
    }
}
