//! IAM service binary. Args: --listen tcp://127.0.0.1:9101 [--state FILE].
//! On empty state, bootstraps the root project and an admin principal with a
//! token printed once to stderr (dev convenience; production provisioning is
//! out of scope for M1).

use std::collections::BTreeSet;
use std::sync::Arc;

use dsec_iam::{rpc::IamService, Iam, Op, PrincipalKind, Quota};

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
        arg("--listen").unwrap_or_else(|| env_or("DSEC_IAM_LISTEN", "tcp://127.0.0.1:9101"));
    let iam = match arg("--state") {
        Some(p) => Arc::new(Iam::persisted(p)?),
        None => Arc::new(Iam::in_memory()),
    };
    if iam.project("root").is_none() {
        let admin_token = iam.add_principal("admin", PrincipalKind::Human);
        iam.create_root_project(
            "root",
            Quota {
                cpu_mc: 1_000_000,
                mem_mb: 1_000_000,
                sandboxes: 10_000,
            },
            "admin",
        )
        .map_err(|e| anyhow::anyhow!("{e}"))?;
        // Default working project for the quickstart, admin-delegated.
        iam.add_principal("dev", PrincipalKind::Human);
        let pol: std::collections::BTreeMap<String, BTreeSet<Op>> = [(
            "dev".to_string(),
            BTreeSet::from([Op::SandboxCreate, Op::SandboxDelete, Op::SandboxExec]),
        )]
        .into_iter()
        .collect();
        iam.create_subproject(
            "admin",
            "root",
            "dev",
            Quota {
                cpu_mc: 500_000,
                mem_mb: 500_000,
                sandboxes: 500,
            },
            &pol,
        )
        .map_err(|e| anyhow::anyhow!("{e}"))?;
        eprintln!("bootstrapped: admin token {admin_token}");
        let dev = iam.principal("dev").unwrap().token;
        eprintln!("dev token {dev}");
    }
    let l = Listener::bind(&listen.parse()?).await?;
    eprintln!("iam listening on {listen}");
    l.serve(Arc::new(IamService(iam))).await;
    Ok(())
}
