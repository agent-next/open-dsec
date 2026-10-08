//! Framed RPC shared by DSec components.
//!
//! Substitute (SPEC): DSec's custom RPC (V4 §5.2.5) is unpublished. Frames are a
//! 4-byte big-endian length followed by a JSON body, so any language (the Python
//! SDK included) can speak it with a socket and `struct`. Calls are multiplexed on
//! one connection by request id; a call is either request/response or
//! server-streaming (`Chunk`* then `End`). Works over any `AsyncRead + AsyncWrite`
//! (TCP, Unix socket; vsock plugs in the same way, P §3.1).

use std::collections::HashMap;
use std::future::Future;
use std::io;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use serde::{Deserialize, Serialize};
use serde_json::Value;
use tokio::io::{
    split, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, BufReader, BufWriter, ReadHalf,
    WriteHalf,
};
use tokio::net::{TcpListener, TcpStream, UnixListener, UnixStream};
use tokio::sync::{mpsc, oneshot};

pub mod b64;

/// Largest accepted frame body (guards against a bogus length prefix).
pub const MAX_FRAME: usize = 64 * 1024 * 1024;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Request {
    pub id: u64,
    pub method: String,
    #[serde(default)]
    pub params: Value,
    /// Bearer token (IAM principal) on client-facing calls.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub token: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Reply {
    Ok {
        id: u64,
        result: Value,
    },
    Err {
        id: u64,
        code: String,
        message: String,
    },
    Chunk {
        id: u64,
        item: Value,
    },
    End {
        id: u64,
    },
}

impl Reply {
    fn id(&self) -> u64 {
        match self {
            Reply::Ok { id, .. }
            | Reply::Err { id, .. }
            | Reply::Chunk { id, .. }
            | Reply::End { id } => *id,
        }
    }
}

#[derive(Debug, Clone)]
pub struct RpcError {
    pub code: String,
    pub message: String,
}

impl std::error::Error for RpcError {}

impl std::fmt::Display for RpcError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {}", self.code, self.message)
    }
}

impl RpcError {
    pub fn new(code: &str, message: impl Into<String>) -> Self {
        RpcError {
            code: code.into(),
            message: message.into(),
        }
    }
}

pub async fn write_frame<W: AsyncWrite + Unpin>(w: &mut W, body: &[u8]) -> io::Result<()> {
    w.write_all(&(body.len() as u32).to_be_bytes()).await?;
    w.write_all(body).await
}

/// Read one frame; `Ok(None)` on clean EOF at a frame boundary.
pub async fn read_frame<R: AsyncRead + Unpin>(r: &mut R) -> io::Result<Option<Vec<u8>>> {
    let mut len = [0u8; 4];
    match r.read_exact(&mut len).await {
        Ok(_) => {}
        Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(e) => return Err(e),
    }
    let n = u32::from_be_bytes(len) as usize;
    if n > MAX_FRAME {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("frame too large: {n}"),
        ));
    }
    let mut buf = vec![0u8; n];
    r.read_exact(&mut buf).await?;
    Ok(Some(buf))
}

/// Where a service listens / a client connects.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Addr {
    Tcp(String),
    Unix(PathBuf),
}

impl std::str::FromStr for Addr {
    type Err = anyhow::Error;
    fn from_str(s: &str) -> anyhow::Result<Self> {
        if let Some(p) = s.strip_prefix("unix://") {
            Ok(Addr::Unix(p.into()))
        } else if let Some(h) = s.strip_prefix("tcp://") {
            Ok(Addr::Tcp(h.into()))
        } else {
            anyhow::bail!("address must start with tcp:// or unix://: {s}")
        }
    }
}

impl std::fmt::Display for Addr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Addr::Tcp(h) => write!(f, "tcp://{h}"),
            Addr::Unix(p) => write!(f, "unix://{}", p.display()),
        }
    }
}

// ---------------------------------------------------------------- server

/// Handles one request. Every request must end by calling `ok`, `err` or (after
/// any `chunk`s) `end` on the responder; dropping it without replying yields an
/// `internal` error to the caller.
pub trait Handler: Send + Sync + 'static {
    fn handle(&self, req: Request, out: Responder) -> impl Future<Output = ()> + Send;
}

pub struct Responder {
    id: u64,
    tx: mpsc::Sender<Reply>,
    done: bool,
}

impl Responder {
    pub async fn ok(mut self, result: Value) {
        self.done = true;
        let _ = self
            .tx
            .send(Reply::Ok {
                id: self.id,
                result,
            })
            .await;
    }
    pub async fn err(mut self, code: &str, message: impl Into<String>) {
        self.done = true;
        let _ = self
            .tx
            .send(Reply::Err {
                id: self.id,
                code: code.into(),
                message: message.into(),
            })
            .await;
    }
    /// Send one streamed item; returns false if the peer is gone.
    pub async fn chunk(&self, item: Value) -> bool {
        self.tx
            .send(Reply::Chunk { id: self.id, item })
            .await
            .is_ok()
    }
    pub async fn end(mut self) {
        self.done = true;
        let _ = self.tx.send(Reply::End { id: self.id }).await;
    }
}

impl Drop for Responder {
    fn drop(&mut self) {
        if !self.done {
            let _ = self.tx.try_send(Reply::Err {
                id: self.id,
                code: "internal".into(),
                message: "handler dropped the request without replying".into(),
            });
        }
    }
}

/// Serve requests on one established stream until it closes.
pub async fn serve_stream<S, H>(stream: S, handler: Arc<H>)
where
    S: AsyncRead + AsyncWrite + Send + 'static,
    H: Handler,
{
    let (rd, wr) = split(stream);
    let (tx, mut rx) = mpsc::channel::<Reply>(256);
    let writer = tokio::spawn(async move {
        let mut w = BufWriter::new(wr);
        while let Some(rep) = rx.recv().await {
            let body = serde_json::to_vec(&rep).expect("reply serializes");
            if write_frame(&mut w, &body).await.is_err() {
                break;
            }
            // Flush when nothing else is queued so replies are not delayed.
            if rx.is_empty() && w.flush().await.is_err() {
                break;
            }
        }
    });
    let mut rd = BufReader::new(rd);
    while let Ok(Some(buf)) = read_frame(&mut rd).await {
        let Ok(req) = serde_json::from_slice::<Request>(&buf) else {
            break;
        };
        let out = Responder {
            id: req.id,
            tx: tx.clone(),
            done: false,
        };
        let h = handler.clone();
        tokio::spawn(async move { h.handle(req, out).await });
    }
    drop(tx);
    let _ = writer.await;
}

pub enum Listener {
    Tcp(TcpListener),
    Unix(UnixListener),
}

impl Listener {
    pub async fn bind(addr: &Addr) -> io::Result<Listener> {
        match addr {
            Addr::Tcp(h) => Ok(Listener::Tcp(TcpListener::bind(h).await?)),
            Addr::Unix(p) => {
                let _ = std::fs::remove_file(p);
                Ok(Listener::Unix(UnixListener::bind(p)?))
            }
        }
    }
    pub fn local_addr(&self) -> io::Result<Addr> {
        match self {
            Listener::Tcp(l) => Ok(Addr::Tcp(l.local_addr()?.to_string())),
            Listener::Unix(l) => {
                let a = l.local_addr()?;
                Ok(Addr::Unix(
                    a.as_pathname().map(|p| p.to_path_buf()).unwrap_or_default(),
                ))
            }
        }
    }
    /// Accept loop; runs until the task is aborted.
    pub async fn serve<H: Handler>(self, handler: Arc<H>) {
        loop {
            match self {
                Listener::Tcp(ref l) => match l.accept().await {
                    Ok((s, _)) => {
                        let _ = s.set_nodelay(true);
                        tokio::spawn(serve_stream(s, handler.clone()));
                    }
                    Err(_) => tokio::time::sleep(std::time::Duration::from_millis(50)).await,
                },
                Listener::Unix(ref l) => match l.accept().await {
                    Ok((s, _)) => {
                        tokio::spawn(serve_stream(s, handler.clone()));
                    }
                    Err(_) => tokio::time::sleep(std::time::Duration::from_millis(50)).await,
                },
            }
        }
    }
}

// ---------------------------------------------------------------- client

enum Pending {
    Call(oneshot::Sender<Result<Value, RpcError>>),
    Stream(mpsc::Sender<Result<Value, RpcError>>),
}

type PendingMap = Arc<Mutex<HashMap<u64, Pending>>>;

struct Conn {
    wr: tokio::sync::Mutex<BufWriter<WriteHalf<Box<dyn Duplex>>>>,
    pending: PendingMap,
    alive: Arc<std::sync::atomic::AtomicBool>,
    /// Fired when the last external `Arc<Conn>` is dropped, so the reader
    /// task releases its half of the stream and the peer sees EOF.
    gone: Arc<tokio::sync::Notify>,
}

pub trait Duplex: AsyncRead + AsyncWrite + Send + Unpin {}
impl<T: AsyncRead + AsyncWrite + Send + Unpin> Duplex for T {}

impl Drop for Conn {
    fn drop(&mut self) {
        self.gone.notify_one();
    }
}

impl Conn {
    fn new(stream: Box<dyn Duplex>) -> Arc<Conn> {
        let (rd, wr): (ReadHalf<Box<dyn Duplex>>, _) = split(stream);
        let pending: PendingMap = Arc::default();
        let alive = Arc::new(std::sync::atomic::AtomicBool::new(true));
        let gone = Arc::new(tokio::sync::Notify::new());
        let conn = Arc::new(Conn {
            wr: tokio::sync::Mutex::new(BufWriter::new(wr)),
            pending: pending.clone(),
            alive: alive.clone(),
            gone: gone.clone(),
        });
        tokio::spawn(async move {
            let mut rd = BufReader::new(rd);
            loop {
                let frame = tokio::select! {
                    _ = gone.notified() => break,
                    f = read_frame(&mut rd) => match f {
                        Ok(Some(buf)) => buf,
                        Ok(None) | Err(_) => break,
                    },
                };
                let Ok(rep) = serde_json::from_slice::<Reply>(&frame) else {
                    break;
                };
                let id = rep.id();
                // Each arm locks, finishes with the guard, then awaits if it
                // must: a MutexGuard held across an await is not Send.
                match rep {
                    Reply::Ok { result, .. } => {
                        if let Some(Pending::Call(tx)) = pending.lock().unwrap().remove(&id) {
                            let _ = tx.send(Ok(result));
                        }
                    }
                    Reply::Err { code, message, .. } => match pending.lock().unwrap().remove(&id) {
                        Some(Pending::Call(tx)) => {
                            let _ = tx.send(Err(RpcError { code, message }));
                        }
                        Some(Pending::Stream(tx)) => {
                            let _ = tx.try_send(Err(RpcError { code, message }));
                        }
                        None => {}
                    },
                    Reply::Chunk { item, .. } => {
                        let tx = {
                            let map = pending.lock().unwrap();
                            match map.get(&id) {
                                Some(Pending::Stream(tx)) => Some(tx.clone()),
                                _ => None,
                            }
                        };
                        // Backpressure: wait for the consumer; drop the call if it left.
                        if let Some(tx) = tx {
                            if tx.send(Ok(item)).await.is_err() {
                                pending.lock().unwrap().remove(&id);
                            }
                        }
                    }
                    Reply::End { .. } => {
                        pending.lock().unwrap().remove(&id);
                    }
                }
            }
            alive.store(false, Ordering::SeqCst);
            // Connection closed: fail everything still waiting.
            let mut map = pending.lock().unwrap();
            for (_, p) in map.drain() {
                let e = RpcError::new("disconnected", "connection closed");
                match p {
                    Pending::Call(tx) => {
                        let _ = tx.send(Err(e));
                    }
                    Pending::Stream(tx) => {
                        let _ = tx.try_send(Err(e));
                    }
                }
            }
        });
        conn
    }

    async fn send(&self, req: &Request) -> io::Result<()> {
        let body = serde_json::to_vec(req).expect("request serializes");
        let mut w = self.wr.lock().await;
        write_frame(&mut *w, &body).await?;
        w.flush().await
    }
}

/// Multiplexing RPC client. Reconnects lazily when constructed from an
/// address. Clones share one connection and request-id space.
#[derive(Clone)]
pub struct Client {
    inner: Arc<ClientInner>,
}

struct ClientInner {
    addr: Option<Addr>,
    conn: tokio::sync::Mutex<Option<Arc<Conn>>>,
    next_id: AtomicU64,
    token: Mutex<Option<String>>,
}

impl Client {
    pub fn new(addr: Addr) -> Client {
        Client {
            inner: Arc::new(ClientInner {
                addr: Some(addr),
                conn: Default::default(),
                next_id: AtomicU64::new(1),
                token: Mutex::new(None),
            }),
        }
    }

    /// Client over an already-established stream (no reconnect): used for the
    /// edge -> aether channel, where aether dials in (P §3.1).
    pub fn from_stream<S: Duplex + 'static>(stream: S) -> Client {
        Client {
            inner: Arc::new(ClientInner {
                addr: None,
                conn: tokio::sync::Mutex::new(Some(Conn::new(Box::new(stream)))),
                next_id: AtomicU64::new(1),
                token: Mutex::new(None),
            }),
        }
    }

    pub fn with_token(self, token: &str) -> Client {
        *self.inner.token.lock().unwrap() = Some(token.to_string());
        self
    }

    /// True while the underlying connection is up (the "channel" of P §3.3 health monitoring).
    pub async fn is_alive(&self) -> bool {
        match &*self.inner.conn.lock().await {
            Some(c) => c.alive.load(Ordering::SeqCst),
            None => false,
        }
    }

    /// Resolves when the connection closes.
    pub async fn closed(&self) {
        loop {
            if !self.is_alive().await {
                return;
            }
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
    }

    async fn conn(&self) -> Result<Arc<Conn>, RpcError> {
        let mut g = self.inner.conn.lock().await;
        if let Some(c) = &*g {
            if c.alive.load(Ordering::SeqCst) {
                return Ok(c.clone());
            }
        }
        let Some(addr) = &self.inner.addr else {
            return Err(RpcError::new("disconnected", "connection closed"));
        };
        let stream: Box<dyn Duplex> = match addr {
            Addr::Tcp(h) => {
                let s = TcpStream::connect(h)
                    .await
                    .map_err(|e| RpcError::new("unreachable", format!("{addr}: {e}")))?;
                let _ = s.set_nodelay(true);
                Box::new(s)
            }
            Addr::Unix(p) => Box::new(
                UnixStream::connect(p)
                    .await
                    .map_err(|e| RpcError::new("unreachable", format!("{addr}: {e}")))?,
            ),
        };
        let c = Conn::new(stream);
        *g = Some(c.clone());
        Ok(c)
    }

    fn request(&self, method: &str, params: Value) -> Request {
        Request {
            id: self.inner.next_id.fetch_add(1, Ordering::SeqCst),
            method: method.into(),
            params,
            token: self.inner.token.lock().unwrap().clone(),
        }
    }

    pub async fn call(&self, method: &str, params: Value) -> Result<Value, RpcError> {
        let conn = self.conn().await?;
        let req = self.request(method, params);
        let (tx, rx) = oneshot::channel();
        conn.pending
            .lock()
            .unwrap()
            .insert(req.id, Pending::Call(tx));
        if let Err(e) = conn.send(&req).await {
            conn.pending.lock().unwrap().remove(&req.id);
            return Err(RpcError::new("disconnected", e.to_string()));
        }
        rx.await
            .unwrap_or_else(|_| Err(RpcError::new("disconnected", "connection closed")))
    }

    /// Server-streaming call: items arrive on the receiver; it ends when the
    /// server sends `End` (channel closes) or yields an `Err` item on failure.
    pub async fn stream(
        &self,
        method: &str,
        params: Value,
    ) -> Result<mpsc::Receiver<Result<Value, RpcError>>, RpcError> {
        let conn = self.conn().await?;
        let req = self.request(method, params);
        let (tx, rx) = mpsc::channel(256);
        conn.pending
            .lock()
            .unwrap()
            .insert(req.id, Pending::Stream(tx));
        if let Err(e) = conn.send(&req).await {
            conn.pending.lock().unwrap().remove(&req.id);
            return Err(RpcError::new("disconnected", e.to_string()));
        }
        Ok(rx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    struct Echo;
    impl Handler for Echo {
        async fn handle(&self, req: Request, out: Responder) {
            match req.method.as_str() {
                "echo" => out.ok(req.params).await,
                "count" => {
                    let n = req.params["n"].as_u64().unwrap();
                    for i in 0..n {
                        if !out.chunk(json!(i)).await {
                            return;
                        }
                    }
                    out.end().await
                }
                "slow" => {
                    tokio::time::sleep(std::time::Duration::from_millis(200)).await;
                    out.ok(json!("slow")).await
                }
                "drop" => {}
                "token" => out.ok(json!(req.token)).await,
                _ => out.err("not_found", "no such method").await,
            }
        }
    }

    async fn tcp_pair() -> Client {
        let l = Listener::bind(&"tcp://127.0.0.1:0".parse().unwrap())
            .await
            .unwrap();
        let addr = l.local_addr().unwrap();
        tokio::spawn(l.serve(Arc::new(Echo)));
        Client::new(addr)
    }

    #[tokio::test]
    async fn request_response_over_tcp_and_unix() {
        let c = tcp_pair().await;
        assert_eq!(
            c.call("echo", json!({"a": 1})).await.unwrap(),
            json!({"a": 1})
        );
        let e = c.call("nope", json!(null)).await.unwrap_err();
        assert_eq!(e.code, "not_found");

        let dir = std::env::temp_dir().join(format!("dsec-rpc-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let addr = Addr::Unix(dir.join("s.sock"));
        let l = Listener::bind(&addr).await.unwrap();
        tokio::spawn(l.serve(Arc::new(Echo)));
        let c = Client::new(addr);
        assert_eq!(c.call("echo", json!("hi")).await.unwrap(), json!("hi"));
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[tokio::test]
    async fn server_streaming_delivers_items_in_order_then_ends() {
        let c = tcp_pair().await;
        let mut rx = c.stream("count", json!({"n": 1000})).await.unwrap();
        let mut got = vec![];
        while let Some(item) = rx.recv().await {
            got.push(item.unwrap().as_u64().unwrap());
        }
        assert_eq!(got, (0..1000).collect::<Vec<_>>());
    }

    #[tokio::test]
    async fn calls_are_multiplexed_on_one_connection() {
        let c = Arc::new(tcp_pair().await);
        let t0 = std::time::Instant::now();
        let hs: Vec<_> = (0..20)
            .map(|_| {
                let c = c.clone();
                tokio::spawn(async move { c.call("slow", json!(null)).await.unwrap() })
            })
            .collect();
        for h in hs {
            h.await.unwrap();
        }
        // 20 x 200ms serialized would be 4s; multiplexed is ~200ms.
        assert!(
            t0.elapsed() < std::time::Duration::from_millis(1500),
            "{:?}",
            t0.elapsed()
        );
    }

    #[tokio::test]
    async fn dropped_handler_reports_internal_error_and_token_is_carried() {
        let c = tcp_pair().await;
        assert_eq!(
            c.call("drop", json!(null)).await.unwrap_err().code,
            "internal"
        );
        let c = tcp_pair().await.with_token("t1");
        assert_eq!(c.call("token", json!(null)).await.unwrap(), json!("t1"));
    }

    #[tokio::test]
    async fn oversized_frame_is_rejected() {
        let (mut a, mut b) = tokio::io::duplex(64);
        a.write_all(&u32::MAX.to_be_bytes()).await.unwrap();
        let e = read_frame(&mut b).await.unwrap_err();
        assert_eq!(e.kind(), io::ErrorKind::InvalidData);
    }

    #[tokio::test]
    async fn pending_calls_fail_when_peer_disconnects() {
        let (a, b) = tokio::io::duplex(4096);
        let c = Client::from_stream(a);
        let call = tokio::spawn(async move { c.call("x", json!(null)).await });
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        drop(b);
        assert_eq!(call.await.unwrap().unwrap_err().code, "disconnected");
    }

    #[tokio::test]
    async fn dropping_the_client_closes_its_side_of_the_stream() {
        // The reader task must not pin the connection open after the client is
        // dropped: the peer relies on EOF (e.g. edge detecting a dead aether).
        struct Nop;
        impl Handler for Nop {
            async fn handle(&self, _req: Request, out: Responder) {
                out.ok(json!(null)).await
            }
        }
        let (a, b) = tokio::io::duplex(4096);
        let c = Client::from_stream(a);
        let (done, done_rx) = oneshot::channel();
        tokio::spawn(async move {
            serve_stream(b, Arc::new(Nop)).await;
            let _ = done.send(());
        });
        c.call("x", json!(null)).await.unwrap();
        drop(c);
        tokio::time::timeout(std::time::Duration::from_secs(2), done_rx)
            .await
            .expect("server must see EOF after client drop")
            .unwrap();
    }
}
