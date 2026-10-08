//! HTTP request from inside the sandbox (P §3.3). Plain `http://` only in M1;
//! TLS is out of scope until the network allowlist work (M4).

use std::collections::BTreeMap;

use anyhow::{anyhow, bail, Result};
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HttpRequest {
    #[serde(default = "get")]
    pub method: String,
    pub url: String,
    #[serde(default)]
    pub headers: BTreeMap<String, String>,
    #[serde(default)]
    pub body: Vec<u8>,
}

fn get() -> String {
    "GET".into()
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HttpResponse {
    pub status: u16,
    pub headers: BTreeMap<String, String>,
    pub body: Vec<u8>,
}

/// Cap on a response body.
pub const MAX_BODY: usize = 8 * 1024 * 1024;

pub async fn request(req: &HttpRequest) -> Result<HttpResponse> {
    let rest = req
        .url
        .strip_prefix("http://")
        .ok_or_else(|| anyhow!("only http:// URLs are supported"))?;
    let (hostport, path) = match rest.find('/') {
        Some(i) => (&rest[..i], &rest[i..]),
        None => (rest, "/"),
    };
    let target = if hostport.contains(':') {
        hostport.to_string()
    } else {
        format!("{hostport}:80")
    };
    let mut s = TcpStream::connect(&target).await?;
    let mut head = format!(
        "{} {} HTTP/1.1\r\nHost: {}\r\nConnection: close\r\n",
        req.method, path, hostport
    );
    for (k, v) in &req.headers {
        head.push_str(&format!("{k}: {v}\r\n"));
    }
    if !req.body.is_empty() {
        head.push_str(&format!("Content-Length: {}\r\n", req.body.len()));
    }
    head.push_str("\r\n");
    s.write_all(head.as_bytes()).await?;
    s.write_all(&req.body).await?;
    let mut raw = vec![];
    let mut chunk = [0u8; 8192];
    loop {
        let n = s.read(&mut chunk).await?;
        if n == 0 {
            break;
        }
        raw.extend_from_slice(&chunk[..n]);
        if raw.len() > MAX_BODY + 65536 {
            bail!("response exceeds {MAX_BODY} bytes");
        }
    }
    parse_response(&raw)
}

fn parse_response(raw: &[u8]) -> Result<HttpResponse> {
    let split = raw
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .ok_or_else(|| anyhow!("malformed response"))?;
    let head = std::str::from_utf8(&raw[..split])?;
    let mut lines = head.split("\r\n");
    let status: u16 = lines
        .next()
        .and_then(|l| l.split_whitespace().nth(1))
        .and_then(|s| s.parse().ok())
        .ok_or_else(|| anyhow!("bad status line"))?;
    let headers: BTreeMap<String, String> = lines
        .filter_map(|l| l.split_once(':'))
        .map(|(k, v)| (k.trim().to_ascii_lowercase(), v.trim().to_string()))
        .collect();
    let mut body = raw[split + 4..].to_vec();
    if headers
        .get("transfer-encoding")
        .is_some_and(|v| v.contains("chunked"))
    {
        body = dechunk(&body)?;
    }
    Ok(HttpResponse {
        status,
        headers,
        body,
    })
}

fn dechunk(mut b: &[u8]) -> Result<Vec<u8>> {
    let mut out = vec![];
    loop {
        let nl = b
            .windows(2)
            .position(|w| w == b"\r\n")
            .ok_or_else(|| anyhow!("bad chunk"))?;
        let n = usize::from_str_radix(
            std::str::from_utf8(&b[..nl])?
                .split(';')
                .next()
                .unwrap()
                .trim(),
            16,
        )?;
        b = &b[nl + 2..];
        if n == 0 {
            return Ok(out);
        }
        if b.len() < n + 2 {
            bail!("truncated chunk");
        }
        out.extend_from_slice(&b[..n]);
        b = &b[n + 2..];
    }
}
