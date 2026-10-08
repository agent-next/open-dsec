# Changelog

## 0.0.1 (2026-10-08)

First tagged release — Milestone 1 of SPEC.md: single-host DSec control plane with the container
sandbox backend, end to end through the Python SDK.

Sources reproduced: arXiv:2609.22978 (DSec report); DeepSeek-V4 tech report §5.2.5;
DeepSeek-V4.1-Flash tech report §5.1.3.

### Control plane
- `rpc`: framed RPC (length-prefixed serde, TCP + Unix sockets, server-streaming).
- `iam`: principals, multi-level nested projects, bounded delegation (child cannot exceed parent
  quota or grant operations the parent lacks), resource quotas (P §3.2).
- `watcher`: edge health polling, running counts per backend/user/task, stateless rebuild (P §3.2).
- `placement`: capability filter + power-of-d least-loaded sampling, in-flight placement overlay,
  retry-on-edge-rejection (P §3.2, §7; V4.1).
- `apiserver`: stateless ingress; sandbox ID encodes its owning edge; horizontal instances with no
  shared state (P §3.2).

### Sandbox runtime
- `edge`: node-local admission threshold, Docker container backend (label `open-dsec=1`,
  network none by default, cpu/mem limits), TTL reaper, health via aether channel, repercussion
  status on environment crash (P §3.3; V4.1).
- `aether`: per-sandbox proxy over a Unix-socket channel (vsock transport trait reserved for M3),
  terminal-session → chronus mapping, process-tree teardown on session end (P §3.1, §3.3).
- `chronus`: shell-session runtime — stateful exec (cwd/env persist across calls), filesystem ops,
  streaming stdout/stderr, hard per-command captured-output cap (P §6.4 unbounded-output incident).
- `trajlog`: per-sandbox globally ordered durable log; fast-forward replay returns cached results
  so non-idempotent commands never re-execute (V4 §5.2.5).

### SDK and tooling
- `sdk/python/libdsec`: create/exec/fs ops/release; per-sandbox network policy dict plumbed to edge
  (enforcement lands with M4 eBPF).
- `scripts/dev-up.sh` / `dev-down.sh`: one-host stack; `make check` (unprivileged) and
  `make host-check` (real Docker); `scripts/e2e_m1.py` concurrent lifecycle e2e.

### Verification (receipt: workspace task-runs/20261007-open-dsec/w1/VERIFY.md)
- `make check`: 62 Rust tests + SDK pytest, fmt/clippy clean.
- `make host-check`: real-container edge test, host SDK e2e, zero leftover containers enforced.
- e2e: 50 concurrent sandboxes created/used/released at 12.8/s, trajectory replay 50/50 cached.
- CI green on main.

### Known limitations
- Single host; multi-node placement runs but is exercised on one edge (M8).
- Network policy dict is stored and forwarded, not yet enforced (M4).
- Aether binary is glibc-linked; default image `ubuntu:24.04` (musl static build pending network).
- Trajectory replay key scheme synthesized (paper does not publish the exact scheme).
- No cross-family independent review of this diff yet (reviewer lanes unavailable at merge time;
  follow-up review owed on the same SHAs).
