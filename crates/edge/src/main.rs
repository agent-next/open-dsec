//! Edge binary: node-local sandbox runtime (P §3.3).
//! Args: --listen ADDR --id ID [--docker-sock PATH] [--data-dir DIR]
//!       [--aether-bin PATH] [--iam ADDR] [--threshold FRACTION]
//!       [--cpu-mc N] [--mem-mb N] [--sandboxes N].

use std::sync::Arc;

use dsec_edge::{Edge, EdgeConfig, EdgeService};
use dsec_rpc::Listener;

fn arg(name: &str) -> Option<String> {
    let args: Vec<String> = std::env::args().collect();
    args.iter()
        .position(|a| a == name)
        .and_then(|i| args.get(i + 1))
        .cloned()
}

fn env_or(name: &str, default: &str) -> String {
    std::env::var(name).unwrap_or_else(|_| default.into())
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let listen =
        arg("--listen").unwrap_or_else(|| env_or("DSEC_EDGE_LISTEN", "tcp://127.0.0.1:9104"));
    let mut cfg = EdgeConfig {
        edge_id: arg("--id").unwrap_or_else(|| env_or("DSEC_EDGE_ID", "edge-1")),
        docker_sock: arg("--docker-sock")
            .unwrap_or_else(|| env_or("DSEC_DOCKER_SOCK", "/var/run/docker.sock"))
            .into(),
        data_dir: arg("--data-dir")
            .unwrap_or_else(|| env_or("DSEC_EDGE_DATA", "/tmp/dsec-edge"))
            .into(),
        aether_bin: arg("--aether-bin")
            .unwrap_or_else(|| env_or("DSEC_AETHER_BIN", "/usr/local/bin/dsec-aether"))
            .into(),
        iam_addr: arg("--iam").unwrap_or_default(),
        ..Default::default()
    };
    if let Some(t) = arg("--threshold").and_then(|v| v.parse().ok()) {
        cfg.warning_threshold = t;
    }
    if let Some(n) = arg("--cpu-mc").and_then(|v| v.parse().ok()) {
        cfg.cpu_total_mc = n;
    }
    if let Some(n) = arg("--mem-mb").and_then(|v| v.parse().ok()) {
        cfg.mem_total_mb = n;
    }
    if let Some(n) = arg("--sandboxes").and_then(|v| v.parse().ok()) {
        cfg.sbx_total = n;
    }
    let edge = Edge::new(cfg.clone())?;
    edge.start_background();
    let l = Listener::bind(&listen.parse()?).await?;
    eprintln!(
        "edge {} listening on {listen} (docker {}, threshold {:.0}%, aether {})",
        cfg.edge_id,
        cfg.docker_sock.display(),
        cfg.warning_threshold * 100.0,
        cfg.aether_bin.display()
    );
    l.serve(Arc::new(EdgeService(edge))).await;
    Ok(())
}
