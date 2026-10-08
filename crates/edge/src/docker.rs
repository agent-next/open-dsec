//! Minimal Docker Engine API client over the daemon's Unix socket (P §3.3
//! container backend). Only the endpoints the edge needs: create, start, stop,
//! remove, inspect. HTTP/1.1 with `Connection: close` framing so no response
//! is ever ambiguous; bodies are JSON.

use std::path::{Path, PathBuf};

use anyhow::{anyhow, Context, Result};
use serde_json::{json, Value};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixStream;

const API: &str = "/v1.43";

pub struct Docker {
    sock: PathBuf,
}

#[derive(Debug, Clone)]
pub struct CreateSpec {
    pub image: String,
    /// argv of the container, e.g. the aether binary + its address.
    pub cmd: Vec<String>,
    pub cpu_mc: u64,
    pub mem_mb: u64,
    /// "none" unless a later milestone's network policy says otherwise
    /// (enforcement of the per-domain allowlist is M4).
    pub network_mode: String,
    /// host_path:container_path[:ro] bind mounts.
    pub binds: Vec<String>,
    pub labels: Vec<(String, String)>,
    pub name: String,
}

impl Docker {
    pub fn new(sock: impl AsRef<Path>) -> Docker {
        Docker {
            sock: sock.as_ref().to_path_buf(),
        }
    }

    async fn roundtrip(
        &self,
        method: &str,
        path: &str,
        body: Option<&Value>,
    ) -> Result<(u16, Value)> {
        let mut s = UnixStream::connect(&self.sock)
            .await
            .with_context(|| self.sock.display().to_string())?;
        let body = body.map(|v| v.to_string()).unwrap_or_default();
        let req = format!(
            "{method} {API}{path} HTTP/1.1\r\nHost: docker\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        );
        s.write_all(req.as_bytes()).await?;
        let mut raw = vec![];
        s.read_to_end(&mut raw).await?;
        let (status, headers, rest) = parse_head(&raw)?;
        let body_bytes = if headers
            .iter()
            .any(|(k, _)| k.eq_ignore_ascii_case("transfer-encoding"))
        {
            dechunk(&rest)?
        } else {
            rest
        };
        let v = if body_bytes.is_empty() {
            Value::Null
        } else {
            serde_json::from_slice(&body_bytes).context("docker body")?
        };
        Ok((status, v))
    }

    pub async fn create(&self, spec: &CreateSpec) -> Result<String> {
        let mut labels = json!({});
        for (k, v) in &spec.labels {
            labels[k] = json!(v);
        }
        let body = json!({
            "Image": spec.image,
            "Cmd": spec.cmd,
            "Labels": labels,
            "HostConfig": {
                "NanoCpus": spec.cpu_mc * 1_000_000,
                "Memory": spec.mem_mb * 1024 * 1024,
                "NetworkMode": spec.network_mode,
                "Binds": spec.binds,
                "AutoRemove": false,
            },
        });
        let (code, v) = self
            .roundtrip(
                "POST",
                &format!("/containers/create?name={}", spec.name),
                Some(&body),
            )
            .await?;
        if code >= 400 {
            return Err(anyhow!(
                "docker create {} ({}): {}",
                code,
                spec.image,
                v["message"].as_str().unwrap_or("?")
            ));
        }
        Ok(v["Id"]
            .as_str()
            .ok_or_else(|| anyhow!("docker create returned no Id"))?
            .to_string())
    }

    pub async fn start(&self, id: &str) -> Result<()> {
        let (code, v) = self
            .roundtrip("POST", &format!("/containers/{id}/start"), None)
            .await?;
        if code >= 400 {
            return Err(anyhow!(
                "docker start {id} ({code}): {}",
                v["message"].as_str().unwrap_or("?")
            ));
        }
        Ok(())
    }

    pub async fn stop(&self, id: &str, timeout_s: u64) -> Result<()> {
        let (code, v) = self
            .roundtrip(
                "POST",
                &format!("/containers/{id}/stop?t={timeout_s}"),
                None,
            )
            .await?;
        if code >= 400 {
            return Err(anyhow!(
                "docker stop {id} ({code}): {}",
                v["message"].as_str().unwrap_or("?")
            ));
        }
        Ok(())
    }

    pub async fn remove(&self, id: &str, force: bool) -> Result<()> {
        let (code, v) = self
            .roundtrip(
                "DELETE",
                &format!("/containers/{id}?v=1&force={force}"),
                None,
            )
            .await?;
        if code >= 400 {
            return Err(anyhow!(
                "docker rm {id} ({code}): {}",
                v["message"].as_str().unwrap_or("?")
            ));
        }
        Ok(())
    }

    /// Inspect: (running, exit_code, started_ms).
    pub async fn inspect(&self, id: &str) -> Result<(bool, Option<i64>, Option<u64>)> {
        let (code, v) = self
            .roundtrip("GET", &format!("/containers/{id}/json"), None)
            .await?;
        if code >= 400 {
            return Err(anyhow!("docker inspect {id} ({code})"));
        }
        let running = v["State"]["Running"].as_bool().unwrap_or(false);
        let exit = v["State"]["ExitCode"]
            .as_i64()
            .filter(|c| *c != 0 || !running);
        let started = v["State"]["StartedAt"].as_str().and_then(parse_docker_ts);
        Ok((running, exit, started))
    }

    pub async fn ping(&self) -> bool {
        self.roundtrip("GET", "/_ping", None).await.is_ok()
    }
}

type Head = (u16, Vec<(String, String)>, Vec<u8>);

fn parse_head(raw: &[u8]) -> Result<Head> {
    let split = raw
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .ok_or_else(|| anyhow!("malformed docker response"))?;
    let head = std::str::from_utf8(&raw[..split])?;
    let mut lines = head.split("\r\n");
    let status: u16 = lines
        .next()
        .and_then(|l| l.split_whitespace().nth(1))
        .and_then(|s| s.parse().ok())
        .ok_or_else(|| anyhow!("bad docker status line"))?;
    let headers = lines
        .filter_map(|l| l.split_once(':'))
        .map(|(k, v)| (k.trim().to_string(), v.trim().to_string()))
        .collect();
    Ok((status, headers, raw[split + 4..].to_vec()))
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
        if b.len() < n {
            anyhow::bail!("truncated chunk");
        }
        out.extend_from_slice(&b[..n]);
        b = &b[n + 2..];
    }
}

/// Docker timestamps: RFC3339 with nanoseconds, UTC.
fn parse_docker_ts(s: &str) -> Option<u64> {
    let s = s.trim_end_matches('Z');
    let (date, time) = s.split_once('T')?;
    let (y, mo, d) = date.split('-').next().map(|_| {
        let mut it = date.split('-');
        let y: i64 = it.next()?.parse().ok()?;
        let mo: i64 = it.next()?.parse().ok()?;
        let d: i64 = it.next()?.parse().ok()?;
        Some((y, mo, d))
    })??;
    let (h, mi, sec) = {
        let mut it = time.split(':');
        let h: i64 = it.next()?.parse().ok()?;
        let mi: i64 = it.next()?.parse().ok()?;
        let sec: f64 = it.next()?.parse().ok()?;
        (h, mi, sec)
    };
    // days from civil epoch (Howard Hinnant's algorithm)
    let yy = if mo <= 2 { y - 1 } else { y };
    let era = (if yy >= 0 { yy } else { yy - 399 }) / 400;
    let yoe = yy - era * 400;
    let mp = (mo + 9) % 12;
    let doy = (153 * mp + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let days = era * 146097 + doe - 719468;
    let whole_s = (days * 86400 + h * 3600 + mi * 60) as f64;
    Some(((whole_s + sec) * 1000.0).round() as u64)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_docker_timestamps() {
        assert_eq!(
            parse_docker_ts("2026-10-07T12:00:00.123456789Z"),
            Some(1791374400123)
        );
        assert_eq!(parse_docker_ts("bogus"), None);
    }
}
