use super::*;

fn q(cpu: u64, mem: u64, sb: u64) -> Quota {
    Quota { cpu_mc: cpu, mem_mb: mem, sandboxes: sb }
}

/// root(admin) with quota 16c/32g/10; child for alice; grandchild for the agent.
fn tree() -> Iam {
    let iam = Iam::in_memory();
    iam.add_principal("admin", PrincipalKind::Human);
    iam.add_principal("alice", PrincipalKind::Human);
    iam.add_principal("agent-7", PrincipalKind::Agent);
    iam.add_principal("mallory", PrincipalKind::Human);
    iam.create_root_project("root", q(16_000, 32_768, 10), "admin").unwrap();
    // admin delegates to alice: create/delete/exec sandboxes and the right to
    // make her own subprojects, within 8c/16g/6.
    iam.create_subproject(
        "admin",
        "root",
        "eng",
        q(8_000, 16_384, 6),
        &BTreeMap::from([("alice".into(), BTreeSet::from([Op::SandboxCreate, Op::SandboxDelete, Op::SandboxExec, Op::ProjectCreateChild]))]),
    )
    .unwrap();
    iam
}

#[test]
fn authenticate_returns_principal_for_valid_token_only() {
    let iam = tree();
    let tok = iam.principal("alice").unwrap().token;
    assert_eq!(iam.authenticate(&tok).unwrap(), "alice");
    assert!(iam.authenticate("dsec-forged").is_err());
}

#[test]
fn authorize_honors_policies_and_denies_without_one() {
    let iam = tree();
    assert!(iam.authorize("alice", "eng", Op::SandboxCreate).is_ok());
    assert!(iam.authorize("alice", "eng", Op::QuotaSet).is_err(), "never granted");
    assert!(iam.authorize("mallory", "eng", Op::SandboxCreate).is_err(), "no policy at all");
    assert!(iam.authorize("alice", "nope", Op::SandboxCreate).is_err(), "unknown project");
}

#[test]
fn ancestor_policy_covers_subproject_resources() {
    let iam = tree();
    // admin holds ops only at root; they must apply to the subproject's
    // resources (P §3.2 scoping).
    iam.create_subproject("admin", "eng", "team", q(2_000, 4_096, 2), &BTreeMap::new()).unwrap();
    let d = iam.authorize("admin", "team", Op::PolicyGrant).unwrap();
    assert_eq!(d.via, "root", "matched at the root scope");
    // alice has no policy on `team` itself; her `eng` grant does not cover
    // nothing she was not granted, but what she WAS granted covers the child:
    assert!(iam.authorize("alice", "team", Op::SandboxCreate).is_ok());
}

#[test]
fn delegation_cannot_grant_ops_the_delegator_lacks() {
    let iam = tree();
    // alice holds sandbox ops + create_child, but NOT policy_grant/quota_set.
    let e = iam
        .create_subproject(
            "alice",
            "eng",
            "team",
            q(2_000, 4_096, 2),
            &BTreeMap::from([("mallory".into(), BTreeSet::from([Op::QuotaSet]))]),
        )
        .unwrap_err();
    assert!(e.contains("delegation bound"), "{e}");
    // Granting something she does hold succeeds.
    iam.create_subproject(
        "alice",
        "eng",
        "team",
        q(2_000, 4_096, 2),
        &BTreeMap::from([("mallory".into(), BTreeSet::from([Op::SandboxExec]))]),
    )
    .unwrap();
    assert!(iam.authorize("mallory", "team", Op::SandboxExec).is_ok());
    // Same bound on later policy edits.
    assert!(iam.set_policy("alice", "team", "mallory", BTreeSet::from([Op::QuotaSet])).is_err());
}

#[test]
fn subproject_quota_sum_cannot_exceed_parent() {
    let iam = tree();
    // eng has 8c; delegating 6c then 3c must fail on the second.
    iam.create_subproject("admin", "eng", "a", q(6_000, 0, 0), &BTreeMap::new()).unwrap();
    let e = iam.create_subproject("admin", "eng", "b", q(3_000, 0, 0), &BTreeMap::new()).unwrap_err();
    assert!(e.contains("delegation bound"), "{e}");
    // Growing a child past the envelope via set_quota is blocked the same way.
    let e = iam.set_quota("admin", "a", q(9_000, 0, 0)).unwrap_err();
    assert!(e.contains("delegation bound"), "{e}");
    // Shrinking `a` to 5c leaves room: 5 + 3 = 8 fits.
    iam.set_quota("admin", "a", q(5_000, 0, 0)).unwrap();
    iam.create_subproject("admin", "eng", "b", q(3_000, 0, 0), &BTreeMap::new()).unwrap();
    // Cannot shrink below what the project already delegated onward.
    iam.create_subproject("admin", "a", "deep", q(4_500, 0, 0), &BTreeMap::new()).unwrap();
    assert!(iam.set_quota("admin", "a", q(4_000, 0, 0)).is_err(), "below delegated 4.5c");
}

#[test]
fn charge_respects_quota_at_every_level_of_the_chain() {
    let iam = tree();
    // eng: 6 sandboxes max. Six fit, the seventh is rejected at `eng`.
    for i in 0..6 {
        iam.charge("eng", 1, 1).unwrap_or_else(|e| panic!("charge {i}: {e}"));
    }
    let e = iam.charge("eng", 1, 1).unwrap_err();
    assert!(e.contains("quota exceeded at eng"), "{e}");
    // Root-level bound: root allows 10, eng holds 6; delegate 4 to `other`.
    iam.create_subproject("admin", "root", "other", q(8_000, 16_384, 4), &BTreeMap::new()).unwrap();
    for _ in 0..4 {
        iam.charge("other", 0, 0).unwrap();
    }
    assert_eq!(iam.usage("root").unwrap().sandboxes, 10);
    // Full at both levels: reported at the child first.
    let e = iam.charge("other", 0, 0).unwrap_err();
    assert!(e.contains("quota exceeded at other"), "{e}");
    // Freeing a slot at eng makes root room, but `other` stays full: the
    // child's own bound still rejects.
    iam.release("eng", 1, 1);
    assert_eq!(iam.usage("root").unwrap().sandboxes, 9);
    let e = iam.charge("other", 0, 0).unwrap_err();
    assert!(e.contains("quota exceeded at other"), "{e}");
    iam.release("other", 0, 0);
    iam.charge("other", 0, 0).unwrap();
    // 5 in eng (one was released) + 4 in other.
    assert_eq!(iam.usage("root").unwrap().sandboxes, 9);
}

#[test]
fn humans_and_agents_use_the_same_api() {
    let iam = tree();
    // The agent gets exactly what a human would via the same calls, and every
    // decision path ignores `kind`.
    iam.set_policy(
        "admin",
        "root",
        "agent-7",
        BTreeSet::from([Op::SandboxCreate, Op::SandboxExec, Op::ProjectCreateChild, Op::PolicyGrant]),
    )
    .unwrap();
    iam.create_subproject(
        "agent-7",
        "root",
        "agent-env",
        q(1_000, 2_048, 2),
        &BTreeMap::from([("agent-7".into(), BTreeSet::from([Op::SandboxCreate, Op::SandboxExec]))]),
    )
    .unwrap();
    assert!(iam.authorize("agent-7", "agent-env", Op::SandboxCreate).is_ok());
    assert!(iam.charge("agent-env", 500, 512).is_ok());
    let a = iam.principal("agent-7").unwrap();
    assert_eq!(a.kind, PrincipalKind::Agent);
}

#[test]
fn state_persists_across_restart() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("iam.json");
    let tok;
    {
        let iam = Iam::persisted(&path).unwrap();
        iam.add_principal("admin", PrincipalKind::Human);
        iam.create_root_project("root", q(100, 100, 1), "admin").unwrap();
        tok = iam.principal("admin").unwrap().token;
    }
    let iam = Iam::persisted(&path).unwrap();
    assert_eq!(iam.authenticate(&tok).unwrap(), "admin");
    assert!(iam.authorize("admin", "root", Op::PolicyGrant).is_ok());
}

#[tokio::test]
async fn iam_service_serves_authorize_and_charge_over_rpc() {
    use dsec_rpc::{Client, Listener};
    use std::sync::Arc;

    let iam = Arc::new(tree());
    let l = Listener::bind(&"tcp://127.0.0.1:0".parse().unwrap()).await.unwrap();
    let addr = l.local_addr().unwrap();
    tokio::spawn(l.serve(Arc::new(crate::rpc::IamService(iam.clone()))));
    let c = Client::new(addr);
    let tok = serde_json::json!(iam.principal("alice").unwrap().token);
    let r = c.call("authenticate", serde_json::json!({ "token": tok })).await.unwrap();
    assert_eq!(r["principal"], "alice");
    let r = c
        .call(
            "authorize",
            serde_json::json!({ "principal": "alice", "project": "eng", "op": "sandbox_create" }),
        )
        .await
        .unwrap();
    assert_eq!(r["via"], "eng");
    let e = c
        .call(
            "authorize",
            serde_json::json!({ "principal": "mallory", "project": "eng", "op": "sandbox_create" }),
        )
        .await
        .unwrap_err();
    assert_eq!(e.code, "denied");
    c.call("charge", serde_json::json!({ "project": "eng", "cpu_mc": 1, "mem_mb": 1 })).await.unwrap();
    assert_eq!(iam.usage("eng").unwrap().sandboxes, 1);
}
