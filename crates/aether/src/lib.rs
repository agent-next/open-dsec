//! aether: the per-sandbox proxy (P §3.1, §3.3).
//!
//! One aether runs inside each container/VM sandbox. It dials the edge over a
//! platform-specific transport — a Unix domain socket for Linux containers;
//! vsock for VM backends plugs into the same trait later — and serves the
//! sandbox's operations on that single channel. The edge watches the channel:
//! if it closes, the sandbox is marked failed (P §3.3).
//!
//! Each operation names a terminal-session id (P §3.1); aether keeps one
//! chronus shell session per id — so cwd/env persist across calls within a
//! session — and terminates the chronus process tree when the session ends.

use std::collections::HashMap;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use dsec_chronus::{self as chronus, Session};

pub use dsec_chronus::SessionOpts;
use dsec_rpc::b64;
use dsec_rpc::{Duplex, Handler, Request, Responder};
use serde_json::json;
use tokio::sync::Mutex;

/// Transport aether uses to reach the edge. UDS in M1 (P §3.3 "Unix domain
/// socket for Linux containers"); vsock for VM backends arrives with M3.
/// Future returned by [`Transport::dial`].
pub type DialFut<'a> = Pin<Box<dyn Future<Output = std::io::Result<Box<dyn Duplex>>> + Send + 'a>>;

pub trait Transport: Send + Sync + 'static {
    fn dial<'a>(&'a self, addr: &'a str) -> DialFut<'a>;
}

pub struct UnixTransport;

impl Transport for UnixTransport {
    fn dial<'a>(&'a self, addr: &'a str) -> DialFut<'a> {
        Box::pin(async move {
            let p = addr.strip_prefix("unix://").unwrap_or(addr);
            Ok(Box::new(tokio::net::UnixStream::connect(p).await?) as Box<dyn Duplex>)
        })
    }
}

pub struct Aether {
    transport: Box<dyn Transport>,
    /// terminal-session id -> shell session (P §3.1).
    sessions: Mutex<HashMap<String, Arc<Session>>>,
    opts: SessionOpts,
}

impl Aether {
    pub fn new(transport: Box<dyn Transport>, opts: SessionOpts) -> Arc<Aether> {
        Arc::new(Aether { transport, sessions: Mutex::new(HashMap::new()), opts })
    }

    async fn session(&self, id: &str) -> Result<Arc<Session>, String> {
        let mut m = self.sessions.lock().await;
        if let Some(s) = m.get(id) {
            return Ok(s.clone());
        }
        let s = Arc::new(Session::spawn(self.opts.clone()).await.map_err(|e| e.to_string())?);
        m.insert(id.to_string(), s.clone());
        Ok(s)
    }

    /// End a session: kill its chronus process tree (P §3.1).
    pub async fn end_session(&self, id: &str) {
        if let Some(s) = self.sessions.lock().await.remove(id) {
            s.close().await;
        }
    }

    /// Kill every session (channel closed or aether shutting down).
    pub async fn end_all(&self) {
        let all: Vec<Arc<Session>> = self.sessions.lock().await.drain().map(|(_, v)| v).collect();
        for s in all {
            s.close().await;
        }
    }

    pub async fn session_count(&self) -> usize {
        self.sessions.lock().await.len()
    }

    /// Serve one edge connection until it closes, then kill every session:
    /// the edge reads "channel closed" as "sandbox failed" (P §3.3), so no
    /// runtime state may outlive the channel.
    pub async fn serve_connection(self: Arc<Self>, stream: Box<dyn Duplex>) {
        dsec_rpc::serve_stream(stream, Arc::new(AetherHandler(self.clone()))).await;
        self.end_all().await;
    }

    /// Dial the edge and serve requests until the channel closes, then
    /// reconnect and repeat for the lifetime of the sandbox.
    pub async fn run(self: Arc<Self>, addr: &str) -> ! {
        loop {
            if let Ok(stream) = self.transport.dial(addr).await {
                self.clone().serve_connection(stream).await;
            }
            tokio::time::sleep(std::time::Duration::from_millis(250)).await;
        }
    }
}

pub struct AetherHandler(pub Arc<Aether>);

impl Handler for AetherHandler {
    async fn handle(&self, req: Request, out: Responder) {
        let session_id = req.params["session"].as_str().unwrap_or("default").to_string();
        match req.method.as_str() {
            // Streaming exec (P §3.3 "streaming I/O"): stdout/stderr chunks
            // then a final exit chunk.
            "exec" => {
                let s = match self.0.session(&session_id).await {
                    Ok(s) => s,
                    Err(e) => return out.err("spawn_failed", e).await,
                };
                let cmd = req.params["cmd"].as_str().unwrap_or_default().to_string();
                let timeout = req.params["timeout_ms"].as_u64().map(std::time::Duration::from_millis);
                let (tx, mut rx) = tokio::sync::mpsc::channel::<chronus::Event>(64);
                let run = tokio::spawn(async move { s.exec(&cmd, timeout, tx).await });
                while let Some(ev) = rx.recv().await {
                    let v = match ev {
                        chronus::Event::Stdout { data } => json!({ "stream": "stdout", "data": data }),
                        chronus::Event::Stderr { data } => json!({ "stream": "stderr", "data": data }),
                        chronus::Event::Exit(e) => serde_json::to_value(e).unwrap(),
                    };
                    if !out.chunk(v).await {
                        // Consumer gone: stop pumping; exec stops the command
                        // when its sender is dropped.
                        break;
                    }
                }
                rx.close();
                let _ = run.await;
                out.end().await
            }
            "exec_collect" => {
                let s = match self.0.session(&session_id).await {
                    Ok(s) => s,
                    Err(e) => return out.err("spawn_failed", e).await,
                };
                let cmd = req.params["cmd"].as_str().unwrap_or_default().to_string();
                let timeout = req.params["timeout_ms"].as_u64().map(std::time::Duration::from_millis);
                match s.exec_collect(&cmd, timeout).await {
                    Ok(r) => out.ok(serde_json::to_value(&r).unwrap()).await,
                    Err(e) => out.err("exec_failed", e.to_string()).await,
                }
            }
            "read_file" => {
                let p = req.params["path"].as_str().unwrap_or_default();
                match chronus::fs::read_file(p).await {
                    Ok(data) => out.ok(json!({ "data": b64::encode(&data) })).await,
                    Err(e) => out.err("io_error", e.to_string()).await,
                }
            }
            "write_file" => {
                let p = req.params["path"].as_str().unwrap_or_default();
                let data = req.params["data"].as_str().and_then(b64::decode).unwrap_or_default();
                let mode = req.params["mode"].as_u64().map(|m| m as u32);
                match chronus::fs::write_file(p, &data, mode).await {
                    Ok(()) => out.ok(json!({})).await,
                    Err(e) => out.err("io_error", e.to_string()).await,
                }
            }
            "list_dir" => {
                let p = req.params["path"].as_str().unwrap_or_default();
                match chronus::fs::list_dir(p).await {
                    Ok(ls) => out.ok(json!({ "entries": ls })).await,
                    Err(e) => out.err("io_error", e.to_string()).await,
                }
            }
            "http" => {
                let r: chronus::http::HttpRequest = match serde_json::from_value(req.params["request"].clone()) {
                    Ok(r) => r,
                    Err(e) => return out.err("bad_request", e.to_string()).await,
                };
                match chronus::http::request(&r).await {
                    Ok(resp) => {
                        let v = json!({
                            "status": resp.status,
                            "headers": resp.headers,
                            "body": b64::encode(&resp.body),
                        });
                        out.ok(v).await
                    }
                    Err(e) => out.err("http_failed", e.to_string()).await,
                }
            }
            "session_end" => {
                self.0.end_session(&session_id).await;
                out.ok(json!({})).await
            }
            _ => out.err("not_found", format!("no such method {}", req.method)).await,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use dsec_rpc::Client;
    use std::time::Duration;

    /// Serve an aether over a real Unix socket; the returned client speaks
    /// edge-side of the channel (aether dials the edge in production, the
    /// edge serves — for the unit test we accept one stream and drive it).
    async fn aether_pair(opts: SessionOpts) -> (Client, Arc<Aether>) {
        let a = Aether::new(Box::new(UnixTransport), opts);
        let dir = tempfile::tempdir().unwrap();
        let sock = dir.path().join("aether.sock");
        let l = tokio::net::UnixListener::bind(&sock).unwrap();
        let a2 = a.clone();
        tokio::spawn(async move {
            let (stream, _) = l.accept().await.unwrap();
            a2.serve_connection(Box::new(stream)).await;
        });
        (Client::from_stream(tokio::net::UnixStream::connect(&sock).await.unwrap()), a)
    }

    #[tokio::test]
    async fn sessions_map_ids_to_independent_stateful_chronus_instances() {
        let (c, a) = aether_pair(SessionOpts::default()).await;
        // Session A persists state across calls...
        c.call("exec_collect", json!({ "session": "A", "cmd": "cd /tmp && export K=v1" })).await.unwrap();
        let r = c.call("exec_collect", json!({ "session": "A", "cmd": "echo $K" })).await.unwrap();
        assert_eq!(r["stdout"].as_str().unwrap(), "v1\n");
        // ...session B is a different chronus instance with its own state.
        let r = c.call("exec_collect", json!({ "session": "B", "cmd": "echo -n $K" })).await.unwrap();
        assert_eq!(r["stdout"].as_str().unwrap(), "");
        assert_eq!(a.session_count().await, 2);
        c.call("session_end", json!({ "session": "A" })).await.unwrap();
        assert_eq!(a.session_count().await, 1);
    }

    #[tokio::test]
    async fn session_end_kills_the_chronus_process_tree() {
        let (c, a) = aether_pair(SessionOpts::default()).await;
        // Start a long-running child under the session's shell.
        let d = tempfile::tempdir().unwrap();
        let pidfile = d.path().join("pid");
        c.call(
            "exec_collect",
            json!({ "session": "s", "cmd": format!("sleep 300 & echo $! > {}", pidfile.display()), "timeout_ms": 5000 }),
        )
        .await
        .unwrap();
        let pid: i32 = std::fs::read_to_string(&pidfile).unwrap().trim().parse().unwrap();
        assert!(chronus::pid_alive(pid));
        c.call("session_end", json!({ "session": "s" })).await.unwrap();
        tokio::time::sleep(Duration::from_millis(200)).await;
        assert!(!chronus::pid_alive(pid), "session end must kill the chronus tree");
        assert_eq!(a.session_count().await, 0);
    }

    #[tokio::test]
    async fn channel_close_ends_every_session() {
        // P §3.3: the channel closing invalidates the sandbox runtime state.
        let (c, a) = aether_pair(SessionOpts::default()).await;
        c.call("exec_collect", json!({ "session": "x", "cmd": "echo hi" })).await.unwrap();
        c.call("exec_collect", json!({ "session": "y", "cmd": "echo hi" })).await.unwrap();
        assert_eq!(a.session_count().await, 2);
        drop(c); // closes the UDS stream
        tokio::time::sleep(Duration::from_millis(200)).await;
        assert_eq!(a.session_count().await, 0, "all sessions die with the channel");
    }

    #[tokio::test]
    async fn streaming_exec_chunks_arrive_before_completion() {
        let (c, _a) = aether_pair(SessionOpts::default()).await;
        let mut rx = c.stream("exec", json!({ "session": "s", "cmd": "echo one; sleep 1; echo two" })).await.unwrap();
        let t0 = std::time::Instant::now();
        let first = rx.recv().await.unwrap().unwrap();
        assert_eq!(first["data"].as_str().unwrap(), "one\n");
        assert!(t0.elapsed() < Duration::from_millis(800), "{:?}", t0.elapsed());
        let mut got_exit = false;
        while let Some(v) = rx.recv().await {
            if v.unwrap().get("code").is_some() {
                got_exit = true;
            }
        }
        assert!(got_exit, "stream must end with the exit info");
    }

    #[tokio::test]
    async fn fs_ops_roundtrip_through_the_channel() {
        let (c, _a) = aether_pair(SessionOpts::default()).await;
        let d = tempfile::tempdir().unwrap();
        let f = d.path().join("f.bin");
        let data: Vec<u8> = (0..=255).collect();
        c.call(
            "write_file",
            json!({ "session": "s", "path": f.to_str().unwrap(), "data": b64::encode(&data), "mode": 0o600 }),
        )
        .await
        .unwrap();
        let r = c.call("read_file", json!({ "session": "s", "path": f.to_str().unwrap() })).await.unwrap();
        assert_eq!(b64::decode(r["data"].as_str().unwrap()).unwrap(), data);
        let r = c.call("list_dir", json!({ "session": "s", "path": d.path().to_str().unwrap() })).await.unwrap();
        assert_eq!(r["entries"][0]["name"].as_str().unwrap(), "f.bin");
        assert_eq!(r["entries"][0]["size"].as_u64().unwrap(), 256);
    }
}
