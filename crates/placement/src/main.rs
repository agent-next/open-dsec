//! Placement replica binary. Args: --listen ADDR --watcher ADDR [--d N].
//! One replica per apiserver deployment point; replicas share nothing (P §7).

use std::sync::Arc;

use dsec_placement::{Opts, Placement, PlacementService, WatcherView};
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
        arg("--listen").unwrap_or_else(|| env_or("DSEC_PLACEMENT_LISTEN", "tcp://127.0.0.1:9103"));
    let watcher =
        arg("--watcher").unwrap_or_else(|| env_or("DSEC_WATCHER_LISTEN", "tcp://127.0.0.1:9102"));
    let d = arg("--d").and_then(|v| v.parse().ok()).unwrap_or(2);
    let p = Arc::new(Placement::new(
        Arc::new(WatcherView {
            addr: watcher.parse()?,
        }),
        Opts {
            d,
            ..Default::default()
        },
    ));
    let l = Listener::bind(&listen.parse()?).await?;
    eprintln!("placement listening on {listen} (watcher {watcher}, d={d})");
    l.serve(Arc::new(PlacementService(p))).await;
    Ok(())
}
