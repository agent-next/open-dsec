//! Watcher service binary. Args: --listen ADDR --edge id=addr [--edge ...]
//! [--interval-ms N]. Polls each edge's `status` and serves the fleet view.

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Duration;

use dsec_rpc::Listener;
use dsec_watcher::{Watcher, WatcherService};

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
        arg("--listen").unwrap_or_else(|| env_or("DSEC_WATCHER_LISTEN", "tcp://127.0.0.1:9102"));
    let mut edges = BTreeMap::new();
    let args: Vec<String> = std::env::args().collect();
    for (i, a) in args.iter().enumerate() {
        if a == "--edge" {
            if let Some(v) = args.get(i + 1) {
                let (id, addr) = v
                    .split_once('=')
                    .ok_or_else(|| anyhow::anyhow!("--edge expects id=tcp://addr"))?;
                edges.insert(id.to_string(), addr.to_string());
            }
        }
    }
    let interval = arg("--interval-ms").map_or(1000, |v| v.parse().unwrap_or(1000));
    let w = Watcher::start(edges, Duration::from_millis(interval));
    let l = Listener::bind(&listen.parse()?).await?;
    eprintln!("watcher listening on {listen}");
    l.serve(Arc::new(WatcherService(w))).await;
    Ok(())
}
