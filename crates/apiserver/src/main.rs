//! Apiserver binary: the stateless ingress (P §3.2).
//! Args: --listen ADDR --iam ADDR --placement ADDR --watcher ADDR.

use std::sync::Arc;

use dsec_apiserver::{Apiserver, ApiserverService};
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
        arg("--listen").unwrap_or_else(|| env_or("DSEC_API_LISTEN", "tcp://127.0.0.1:9100"));
    let iam = arg("--iam").unwrap_or_else(|| env_or("DSEC_IAM_LISTEN", "tcp://127.0.0.1:9101"));
    let placement = arg("--placement")
        .unwrap_or_else(|| env_or("DSEC_PLACEMENT_LISTEN", "tcp://127.0.0.1:9103"));
    let watcher =
        arg("--watcher").unwrap_or_else(|| env_or("DSEC_WATCHER_LISTEN", "tcp://127.0.0.1:9102"));
    let a = Apiserver::new(&iam, &placement, &watcher)?;
    let l = Listener::bind(&listen.parse()?).await?;
    eprintln!(
        "apiserver listening on {listen} (iam {iam}, placement {placement}, watcher {watcher})"
    );
    l.serve(Arc::new(ApiserverService(a))).await;
    Ok(())
}
