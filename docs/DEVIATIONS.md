# Deviations log (M1)

What we built differently from the paper/spec text and why. Fidelity-column
updates for these live in `SPEC.md`.

| # | What | Why | Source |
| - | ---- | ---- | ------ |
| 1 | Containers run under plain host Docker, not "Docker inside QEMU/libvirt worker VMs" | M1 scope (single host, no worker-VM layer); the worker-VM/sub-NUMA hardening is later work | P §3.3 |
| 2 | `dsec-aether` is a dynamically linked glibc binary; default sandbox image is `ubuntu:24.04` | The host toolchain links against glibc ≥ 2.39 (bookworm ships 2.36), and the static-musl Rust target could not be downloaded in the build environment at the time. A musl-static aether (any-image compatible) replaces this when `rustup target add x86_64-unknown-linux-musl` succeeds | — |
| 3 | Trajectory replay keyed by (sandbox, terminal session, client-side op index, op, params) | V4 §5.2.5 does not publish the exact identity of "previously completed commands"; positional identity is the minimal scheme that never re-runs non-idempotent ops and surfaces divergence as an error instead | V4 §5.2.5 |
| 4 | IAM state persists to a JSON file (atomic rewrite) | DSec's IAM backing store is unpublished; M1 needs durability across dev-up restarts only | P §3.2 |
| 5 | Placement load metric = running sandboxes per node | The paper says "least loaded" without publishing the metric; watcher's counts are the M1 signal | P §3.2, §7 |
| 6 | Admission threshold default 0.9 of node capacity on cpu/mem/count, configured in seconds-level TTL sweeps | V4.1 §5.1.3 names a "local warning threshold" without numbers; defaults chosen for a dev host | V4.1 §5.1.3 |
| 7 | Sandbox streams are not journaled for replay (only request/response ops are) | A stream is interaction, not a re-executable result; the exec_collect path is journaled | V4 §5.2.5 |
| 8 | exec-family calls authenticate the bearer token but only create/delete are project-authorized | P §3.2 names create/delete/quota changes as the IAM-gated management ops | P §3.2 |
