//! IAM: identity and access management for DSec management requests (P §3.2).
//!
//! A *principal* is the user or service identity behind a management request;
//! humans and agents use the same API and the same authorization model (the
//! `kind` field is bookkeeping only — nothing in the decision path reads it).
//! *Projects* scope resource management and access control, and nest to
//! arbitrary depth. Within a project, policies say which principals may perform
//! which management operations on its resources (a policy on an ancestor covers
//! its subprojects), and quotas cap cpu/memory/concurrency consumption.
//!
//! Delegation is bounded by the parent (P §3.2): a principal cannot grant
//! permissions it does not hold, and the sum of subproject quotas cannot exceed
//! the parent's quota. Usage charged against a subproject also consumes the
//! quota of every ancestor, so a parent cannot be overflowed through children.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::RwLock;

use serde::{Deserialize, Serialize};

/// Management operations gated by IAM (P §3.2: "requests to create or delete
/// sandboxes or change a user's resource or concurrency limits must pass IAM
/// checks before execution").
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Op {
    SandboxCreate,
    SandboxDelete,
    /// exec / stream / file operations on an existing sandbox.
    SandboxExec,
    ProjectCreateChild,
    PolicyGrant,
    QuotaSet,
}

impl Op {
    pub fn as_str(self) -> &'static str {
        match self {
            Op::SandboxCreate => "sandbox_create",
            Op::SandboxDelete => "sandbox_delete",
            Op::SandboxExec => "sandbox_exec",
            Op::ProjectCreateChild => "project_create_child",
            Op::PolicyGrant => "policy_grant",
            Op::QuotaSet => "quota_set",
        }
    }
}

/// CPU in millicores, memory in MiB, plus a concurrent-sandbox count
/// (P §3.2: "resource quotas limit resource consumption").
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct Quota {
    #[serde(default)]
    pub cpu_mc: u64,
    #[serde(default)]
    pub mem_mb: u64,
    #[serde(default)]
    pub sandboxes: u64,
}

impl Quota {
    fn fits(&self, used: &Quota) -> bool {
        used.cpu_mc <= self.cpu_mc && used.mem_mb <= self.mem_mb && used.sandboxes <= self.sandboxes
    }
    fn plus(&self, o: &Quota) -> Quota {
        Quota {
            cpu_mc: self.cpu_mc + o.cpu_mc,
            mem_mb: self.mem_mb + o.mem_mb,
            sandboxes: self.sandboxes + o.sandboxes,
        }
    }
    pub fn sub_len(&self) -> String {
        format!("cpu_mc={}, mem_mb={}, sandboxes={}", self.cpu_mc, self.mem_mb, self.sandboxes)
    }
}

/// Humans and agents share one API (P §3.2); `kind` is metadata only.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PrincipalKind {
    Human,
    Agent,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Principal {
    pub id: String,
    pub kind: PrincipalKind,
    /// Opaque bearer token presented on each management call.
    pub token: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Project {
    pub id: String,
    pub parent: Option<String>,
    pub quota: Quota,
    /// Sum of direct children quotas (enforced <= quota).
    pub allocated: Quota,
    pub usage: Quota,
    /// principal -> operations allowed on this project's resources.
    pub policies: BTreeMap<String, BTreeSet<Op>>,
    pub children: BTreeSet<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct State {
    pub principals: BTreeMap<String, Principal>,
    /// token -> principal id.
    pub tokens: BTreeMap<String, String>,
    pub projects: BTreeMap<String, Project>,
}

#[derive(Debug)]
pub struct Decision {
    /// Project whose policy matched (authorization succeeded via this scope).
    pub via: String,
}

pub struct Iam {
    state: RwLock<State>,
    path: Option<std::path::PathBuf>,
}

impl Iam {
    pub fn in_memory() -> Iam {
        Iam { state: RwLock::new(State::default()), path: None }
    }

    /// State persisted to `path` (atomic rewrite on every mutation). M1
    /// stand-in for a real database; DSec's IAM backing store is unpublished.
    pub fn persisted(path: impl Into<std::path::PathBuf>) -> std::io::Result<Iam> {
        let path = path.into();
        let state = match std::fs::read(&path) {
            Ok(b) if !b.is_empty() => serde_json::from_slice(&b).map_err(|e| {
                std::io::Error::new(std::io::ErrorKind::InvalidData, format!("{}: {e}", path.display()))
            })?,
            _ => State::default(),
        };
        Ok(Iam { state: RwLock::new(state), path: Some(path) })
    }

    fn save(&self, s: &State) {
        if let Some(p) = &self.path {
            if let Ok(b) = serde_json::to_vec_pretty(s) {
                let tmp = p.with_extension("tmp");
                if std::fs::write(&tmp, &b).is_ok() {
                    let _ = std::fs::rename(&tmp, p);
                }
            }
        }
    }

    // ------------------------------------------------------------- identity

    pub fn add_principal(&self, id: &str, kind: PrincipalKind) -> String {
        let mut s = self.state.write().unwrap();
        let mut b = [0u8; 24];
        getrandom(&mut b);
        let token = format!("dsec-{}", b.iter().map(|x| format!("{x:02x}")).collect::<String>());
        s.principals.insert(id.into(), Principal { id: id.into(), kind, token: token.clone() });
        s.tokens.insert(token.clone(), id.into());
        self.save(&s);
        token
    }

    /// P §3.2: IAM "authenticates callers". Returns the principal id for a
    /// bearer token.
    pub fn authenticate(&self, token: &str) -> Result<String, String> {
        self.state
            .read()
            .unwrap()
            .tokens
            .get(token)
            .cloned()
            .ok_or_else(|| "invalid token".to_string())
    }

    pub fn principal(&self, id: &str) -> Option<Principal> {
        self.state.read().unwrap().principals.get(id).cloned()
    }

    // ------------------------------------------------------------- projects

    pub fn create_root_project(&self, id: &str, quota: Quota, admin: &str) -> Result<(), String> {
        let mut s = self.state.write().unwrap();
        if s.projects.contains_key(id) {
            return Err(format!("project {id} already exists"));
        }
        if !s.principals.contains_key(admin) {
            return Err(format!("principal {admin} does not exist"));
        }
        let mut policies = BTreeMap::new();
        policies.insert(admin.to_string(), BTreeSet::from([Op::ProjectCreateChild, Op::PolicyGrant, Op::QuotaSet]));
        s.projects.insert(
            id.into(),
            Project {
                id: id.into(),
                parent: None,
                quota,
                allocated: Quota::default(),
                usage: Quota::default(),
                policies,
                children: BTreeSet::new(),
            },
        );
        self.save(&s);
        Ok(())
    }

    fn chain(&self, s: &State, project: &str) -> Result<Vec<String>, String> {
        let mut chain = vec![project.to_string()];
        let mut cur = project.to_string();
        let mut depth = 0;
        loop {
            depth += 1;
            if depth > 64 {
                return Err("project nesting too deep".into());
            }
            let parent = s
                .projects
                .get(&cur)
                .ok_or_else(|| format!("project {cur} does not exist"))?
                .parent
                .clone();
            let Some(p) = parent else { break };
            if !s.projects.contains_key(&p) {
                return Err(format!("project {p} does not exist"));
            }
            chain.push(p.clone());
            cur = p;
        }
        Ok(chain)
    }

    /// Authorized iff some project on the chain from `project` to the root has
    /// a policy granting `principal` the op (policies scope over subprojects).
    pub fn authorize(&self, principal: &str, project: &str, op: Op) -> Result<Decision, String> {
        let s = self.state.read().unwrap();
        if !s.principals.contains_key(principal) {
            return Err(format!("unknown principal {principal}"));
        }
        let chain = self.chain(&s, project)?;
        for pid in &chain {
            if s.projects[pid].policies.get(principal).is_some_and(|ops| ops.contains(&op)) {
                return Ok(Decision { via: pid.clone() });
            }
        }
        Err(format!(
            "principal {principal} may not {} on project {project} (checked {})",
            op.as_str(),
            chain.join(" -> ")
        ))
    }

    /// Create a subproject under `parent`, delegating quota and permissions
    /// (P §3.2). Both delegation bounds are enforced: `by` must hold every
    /// granted op on the parent chain, and the parent's children quota sum
    /// stays within the parent's own quota.
    pub fn create_subproject(
        &self,
        by: &str,
        parent: &str,
        id: &str,
        quota: Quota,
        policies: &BTreeMap<String, BTreeSet<Op>>,
    ) -> Result<(), String> {
        if self.state.read().unwrap().projects.contains_key(id) {
            return Err(format!("project {id} already exists"));
        }
        self.authorize(by, parent, Op::ProjectCreateChild)?;
        // Delegation bound 1: cannot grant permissions the delegator lacks.
        for (grantee, ops) in policies {
            if !self.state.read().unwrap().principals.contains_key(grantee) {
                return Err(format!("unknown grantee {grantee}"));
            }
            for &op in ops {
                self.authorize(by, parent, op).map_err(|e| {
                    format!("delegation bound: cannot grant {} to {grantee}: {e}", op.as_str())
                })?;
            }
        }
        let mut s = self.state.write().unwrap();
        let new_alloc = {
            let p = s.projects.get(parent).ok_or_else(|| format!("project {parent} does not exist"))?;
            p.allocated.plus(&quota)
        };
        // Delegation bound 2: subproject quota sum <= parent quota.
        if !s.projects[parent].quota.fits(&new_alloc) {
            return Err(format!(
                "delegation bound: children of {parent} would sum to {} exceeding {}",
                new_alloc.sub_len(),
                s.projects[parent].quota.sub_len()
            ));
        }
        let p = s.projects.get_mut(parent).unwrap();
        p.allocated = new_alloc;
        p.children.insert(id.into());
        s.projects.insert(
            id.into(),
            Project {
                id: id.into(),
                parent: Some(parent.into()),
                quota,
                allocated: Quota::default(),
                usage: Quota::default(),
                policies: policies.clone(),
                children: BTreeSet::new(),
            },
        );
        self.save(&s);
        Ok(())
    }

    /// Grow/shrink a project's quota (the parent re-delegates part of its
    /// envelope). The children sum bound and current usage both still hold.
    pub fn set_quota(&self, by: &str, project: &str, quota: Quota) -> Result<(), String> {
        self.authorize(by, project, Op::QuotaSet)?;
        let mut s = self.state.write().unwrap();
        let (parent, old_quota, usage, allocated) = {
            let p = s.projects.get(project).ok_or_else(|| format!("project {project} does not exist"))?;
            (p.parent.clone(), p.quota, p.usage, p.allocated)
        };
        if !quota.fits(&usage) {
            return Err(format!("quota {} is below current usage {}", quota.sub_len(), usage.sub_len()));
        }
        if !quota.fits(&allocated) {
            return Err(format!(
                "quota {} is below the {} already delegated to subprojects",
                quota.sub_len(),
                allocated.sub_len()
            ));
        }
        if let Some(parent) = parent {
            let siblings: Quota = s.projects[&parent]
                .children
                .iter()
                .filter(|c| c.as_str() != project)
                .fold(Quota::default(), |acc, c| acc.plus(&s.projects[c.as_str()].quota));
            let sum = siblings.plus(&quota);
            if !s.projects[&parent].quota.fits(&sum) {
                return Err(format!(
                    "delegation bound: children of {parent} would sum to {} exceeding {}",
                    sum.sub_len(),
                    s.projects[&parent].quota.sub_len()
                ));
            }
            s.projects.get_mut(&parent).unwrap().allocated = sum;
        }
        let _ = old_quota;
        s.projects.get_mut(project).unwrap().quota = quota;
        self.save(&s);
        Ok(())
    }

    /// Grant/revoke policy entries. Same delegation bound as subproject
    /// creation: `by` must hold every granted op on the chain.
    pub fn set_policy(&self, by: &str, project: &str, principal: &str, ops: BTreeSet<Op>) -> Result<(), String> {
        self.authorize(by, project, Op::PolicyGrant)?;
        if !self.state.read().unwrap().principals.contains_key(principal) {
            return Err(format!("unknown principal {principal}"));
        }
        for &op in &ops {
            self.authorize(by, project, op)
                .map_err(|e| format!("delegation bound: cannot grant {}: {e}", op.as_str()))?;
        }
        let mut s = self.state.write().unwrap();
        if ops.is_empty() {
            s.projects.get_mut(project).unwrap().policies.remove(principal);
        } else {
            s.projects.get_mut(project).unwrap().policies.insert(principal.into(), ops);
        }
        self.save(&s);
        Ok(())
    }

    // --------------------------------------------------------------- quota

    /// Reserve resources for a new sandbox in `project`, consuming quota at
    /// every level of the chain (so children cannot overflow their ancestors).
    /// Caller must already hold `sandbox_create` on the project.
    pub fn charge(&self, project: &str, cpu_mc: u64, mem_mb: u64) -> Result<(), String> {
        let mut s = self.state.write().unwrap();
        let chain = self.chain(&s, project)?;
        // Check every level first, then apply.
        for pid in &chain {
            let p = &s.projects[pid];
            let after = Quota {
                cpu_mc: p.usage.cpu_mc + cpu_mc,
                mem_mb: p.usage.mem_mb + mem_mb,
                sandboxes: p.usage.sandboxes + 1,
            };
            if !p.quota.fits(&after) {
                return Err(format!("quota exceeded at {pid}: would be {}, limit {}", after.sub_len(), p.quota.sub_len()));
            }
        }
        for pid in &chain {
            let p = s.projects.get_mut(pid).unwrap();
            p.usage.cpu_mc += cpu_mc;
            p.usage.mem_mb += mem_mb;
            p.usage.sandboxes += 1;
        }
        self.save(&s);
        Ok(())
    }

    pub fn release(&self, project: &str, cpu_mc: u64, mem_mb: u64) {
        let mut s = self.state.write().unwrap();
        if let Ok(chain) = self.chain(&s, project) {
            for pid in &chain {
                if let Some(p) = s.projects.get_mut(pid) {
                    p.usage.cpu_mc = p.usage.cpu_mc.saturating_sub(cpu_mc);
                    p.usage.mem_mb = p.usage.mem_mb.saturating_sub(mem_mb);
                    p.usage.sandboxes = p.usage.sandboxes.saturating_sub(1);
                }
            }
            self.save(&s);
        }
    }

    pub fn project(&self, id: &str) -> Option<Project> {
        self.state.read().unwrap().projects.get(id).cloned()
    }

    pub fn usage(&self, id: &str) -> Option<Quota> {
        self.state.read().unwrap().projects.get(id).map(|p| p.usage)
    }
}

fn getrandom(buf: &mut [u8]) {
    use std::io::Read;
    std::fs::File::open("/dev/urandom")
        .and_then(|mut f| f.read_exact(buf))
        .expect("/dev/urandom");
}

/// Maps an apiserver method to the IAM operation it constitutes (P §3.2).
pub fn op_for_method(method: &str) -> Option<Op> {
    match method {
        "sandbox.create" | "quota.charge" => Some(Op::SandboxCreate),
        "sandbox.delete" => Some(Op::SandboxDelete),
        "sandbox.exec" | "sandbox.stream" | "sandbox.read_file" | "sandbox.write_file" | "sandbox.list_dir"
        | "sandbox.http" => Some(Op::SandboxExec),
        _ => None,
    }
}

// ------------------------------------------------------------ rpc service

pub mod rpc {
    use super::*;
    use dsec_rpc::{Handler, Request, Responder};
    use serde_json::{json, Value};
    use std::sync::Arc;

    fn q(v: &Value) -> Quota {
        Quota {
            cpu_mc: v["cpu_mc"].as_u64().unwrap_or(0),
            mem_mb: v["mem_mb"].as_u64().unwrap_or(0),
            sandboxes: v["sandboxes"].as_u64().unwrap_or(0),
        }
    }

    fn ops(v: &Value) -> BTreeSet<Op> {
        v.as_array()
            .map(|a| a.iter().filter_map(|x| serde_json::from_value(x.clone()).ok()).collect())
            .unwrap_or_default()
    }

    /// Serves IAM over the shared RPC layer. The apiserver calls
    /// `authenticate` + `authorize`/`charge` on every management request.
    pub struct IamService(pub Arc<Iam>);

    impl Handler for IamService {
        async fn handle(&self, req: Request, out: Responder) {
            match req.method.as_str() {
                "authenticate" => match self.0.authenticate(req.params["token"].as_str().unwrap_or_default()) {
                    Ok(p) => out.ok(json!({ "principal": p })).await,
                    Err(e) => out.err("denied", e).await,
                },
                "authorize" => {
                    let op: Op = match serde_json::from_value(req.params["op"].clone()) {
                        Ok(o) => o,
                        Err(e) => return out.err("bad_request", e.to_string()).await,
                    };
                    match self.0.authorize(
                        req.params["principal"].as_str().unwrap_or_default(),
                        req.params["project"].as_str().unwrap_or_default(),
                        op,
                    ) {
                        Ok(d) => out.ok(json!({ "via": d.via })).await,
                        Err(e) => out.err("denied", e).await,
                    }
                }
                "charge" => match self.0.charge(
                    req.params["project"].as_str().unwrap_or_default(),
                    req.params["cpu_mc"].as_u64().unwrap_or(0),
                    req.params["mem_mb"].as_u64().unwrap_or(0),
                ) {
                    Ok(()) => out.ok(json!({})).await,
                    Err(e) => out.err("quota_exceeded", e).await,
                },
                "release" => {
                    self.0.release(
                        req.params["project"].as_str().unwrap_or_default(),
                        req.params["cpu_mc"].as_u64().unwrap_or(0),
                        req.params["mem_mb"].as_u64().unwrap_or(0),
                    );
                    out.ok(json!({})).await
                }
                "principal" => match self.0.principal(req.params["id"].as_str().unwrap_or_default()) {
                    Some(p) => out.ok(serde_json::to_value(p).unwrap()).await,
                    None => out.err("not_found", "no such principal").await,
                },
                "project" => match self.0.project(req.params["id"].as_str().unwrap_or_default()) {
                    Some(p) => out.ok(serde_json::to_value(p).unwrap()).await,
                    None => out.err("not_found", "no such project").await,
                },
                "add_principal" => {
                    let id = req.params["id"].as_str().unwrap_or_default().to_string();
                    let kind = if req.params["kind"].as_str() == Some("agent") { PrincipalKind::Agent } else { PrincipalKind::Human };
                    let token = self.0.add_principal(&id, kind);
                    out.ok(json!({ "token": token })).await
                }
                "create_root_project" => {
                    let admin = req.params["admin"].as_str().unwrap_or_default().to_string();
                    let id = req.params["id"].as_str().unwrap_or_default().to_string();
                    match self.0.create_root_project(&id, q(&req.params["quota"]), &admin) {
                        Ok(()) => out.ok(json!({})).await,
                        Err(e) => out.err("conflict", e).await,
                    }
                }
                "create_subproject" => {
                    let policies: BTreeMap<String, BTreeSet<Op>> = req.params["policies"]
                        .as_object()
                        .map(|m| m.iter().map(|(k, v)| (k.clone(), ops(v))).collect())
                        .unwrap_or_default();
                    match self.0.create_subproject(
                        req.params["by"].as_str().unwrap_or_default(),
                        req.params["parent"].as_str().unwrap_or_default(),
                        req.params["id"].as_str().unwrap_or_default(),
                        q(&req.params["quota"]),
                        &policies,
                    ) {
                        Ok(()) => out.ok(json!({})).await,
                        Err(e) => out.err("denied", e).await,
                    }
                }
                "set_quota" => match self.0.set_quota(
                    req.params["by"].as_str().unwrap_or_default(),
                    req.params["project"].as_str().unwrap_or_default(),
                    q(&req.params["quota"]),
                ) {
                    Ok(()) => out.ok(json!({})).await,
                    Err(e) => out.err("denied", e).await,
                },
                "set_policy" => {
                    let set = ops(&req.params["ops"]);
                    match self.0.set_policy(
                        req.params["by"].as_str().unwrap_or_default(),
                        req.params["project"].as_str().unwrap_or_default(),
                        req.params["principal"].as_str().unwrap_or_default(),
                        set,
                    ) {
                        Ok(()) => out.ok(json!({})).await,
                        Err(e) => out.err("denied", e).await,
                    }
                }
                _ => out.err("not_found", format!("no such method {}", req.method)).await,
            }
        }
    }
}

#[cfg(test)]
mod tests;
