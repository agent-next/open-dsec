//! Aether binary: runs INSIDE the sandbox (P §3.1/§3.3).
//! Usage: dsec-aether unix:///run/dsec/aether.sock
//! The transport is selected by scheme (unix now; vsock for VMs later).

use dsec_aether::{Aether, SessionOpts, UnixTransport};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let addr = std::env::args()
        .nth(1)
        .expect("usage: dsec-aether unix:///path/to/edge.sock");
    if !addr.starts_with("unix://") {
        anyhow::bail!("M1 supports unix:// only (vsock arrives with the VM backends)");
    }
    let aether = Aether::new(Box::new(UnixTransport), SessionOpts::default());
    aether.run(&addr).await
}
