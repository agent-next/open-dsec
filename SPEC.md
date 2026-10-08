# open-dsec — spec v0 (2026-10-07)

## Goal

Reproduce DeepSeek Elastic Compute (DSec) as faithfully as public information
allows: same component split, same mechanisms, same experiments. Where
something can't be copied exactly, use the closest open substitute and label it.

Primary sources (the only authority; every design claim in this repo cites one):

- [P] Huang et al., "DeepSeek Elastic Compute (DSec): A Sandbox Infrastructure for
  Effective Agentic Training at Scale", arXiv:2609.22978v1 (2026-09-19).
- [V4] DeepSeek-V4 tech report, arXiv:2606.19348v1, §5.2.5.
- [V4.1] DeepSeek-V4.1-Flash tech report, arXiv:2609.19969v1, §5.1.3.
- [AENV] DeepSeek's released storage code: kvcache-ai/AgentENV `storage/overlaybd`
  (Rust overlaybd + ublk; cited in [P] §7).

## Non-goals

- Production scale (160 nodes / 380K concurrent / 5K creates/s). We reproduce the
  mechanisms and run the experiments at small scale; scaling numbers are measured, not claimed.
- DeepSeek-internal pieces nobody outside can access: DeepSeek Harness (DSH), the
  internal env QC platform, the RL framework itself. Stand-ins are labeled.
- BGP/ECMP VIP load balancing on physical switches ([P] §7) — documented, not built.

## Architecture (1:1 component map)

| DSec component | Source | open-dsec | Fidelity |
| --- | --- | --- | --- |
| libdsec (Python SDK) | P §2.1, V4 | `sdk/python/libdsec` | 1:1 surface (create/exec/fs/tty/pause/resume/pack_diff/release; `network={pypi:True,npm:False}`) |
| Apiserver (Rust, stateless ingress; sandbox ID encodes edge) | P §3.2, V4 | `crates/apiserver` | 1:1 |
| IAM (multi-level nested projects, delegated bounded quota) | P §3.2 | `crates/iam` | 1:1 |
| Placement engine (filter → power-of-d sampling, least loaded; in-flight overlay; no durable state) | P §3.2, §7, V4.1 | `crates/placement` | 1:1 |
| Watcher (edge probes; counts per backend/edge/user/task; rebuild by re-polling) | P §3.2, V4 | `crates/watcher` | 1:1 |
| Custom RPC between components | V4 | `crates/rpc` | SUBSTITUTE: protocol unpublished; length-prefixed frames over TCP/UDS/vsock |
| Edge (per-node admission, backends, storage, eBPF, snapshots, TTL) | P §3.3 | `crates/edge` | 1:1 |
| aether (per-sandbox proxy, UDS for containers / vsock for VMs, session → chronus) | P §3.1, §3.3 | `crates/aether` | 1:1 |
| chronus (shell session: exec, fs ops, HTTP, streaming I/O) | P §3.3 | `crates/chronus` | 1:1 + output cap (P §6.4 `yes` incident) |
| Trajectory log (globally ordered per sandbox; fast-forward replay; provenance; deterministic replay) | V4 | `crates/trajlog` | 1:1 |
| Backends: FnCall (pre-warmed pool, CPU+GPU shared/exclusive, warm Python pool) | P §2.2, §7 | `crates/edge/src/backend/fncall` | GPU: MIG unavailable on RTX 5090 → exclusive = whole GPU, shared = MPS (SUBSTITUTE) |
| Backends: Container (Docker inside QEMU/libvirt worker VMs, sub-NUMA-bound) | P §3.3, V4.1 | `.../container` | M1: plain Docker on the host — no worker-VM nesting/sub-NUMA (docs/DEVIATIONS.md #1); paper-faithful from M4 hardening on |
| Backends: MicroVM (Firecracker; EROFS ro block devs; overlayfs root in guest; OverlayBD via ublk; Docker-in-microVM disk) | P §5.1, §5.3 | `.../microvm` | 1:1 (reuse [AENV] overlaybd-rs/ublk) |
| Backends: Full VM (QEMU; Android; virtio-gpu; DXVK) | P §2.2, §3.3 | `.../fullvm` | 1:1 for Linux GUI + Android x86 image; DXVK path best-effort |
| Composable layers (base/workspace/toolkit as EROFS lowerdirs) + dockerd patch (~30 lines Go) | P §5.1, §7 | `images/`, `patches/moby/` | 1:1 |
| EROFS meta/data split, meta local, data on shared FS; ≤3 GB layer collapsing w/ whiteouts; file-backed mount | P §5.3 | `images/erofs-convert` | 1:1 |
| 3FS shared image store (FUSE client) | P §2.4, §7 | `deploy/3fs` | 1:1 software; RDMA → SoftRoCE/rxe or whatever NIC we have (SUBSTITUTE for hardware) |
| Memory: virtio-pmem+DAX for ro layers; DAMON + balloon free-page reporting for writable | P §5.2, §7 | `crates/edge` + `guest/` | 1:1 |
| CPU QoS: LS/BE classes; BE=SCHED_IDLE; LS=core scheduling (PR_SCHED_CORE) | P §5.2, §7, V4.1 | `crates/edge/src/qos` | 1:1 |
| Pause/resume: container = docker pause + memory.swap.max + memory.reclaim; resume = MADV_WILLNEED then unpause; microVM = FC snapshot + kill, restore on next request | P §6.3 | `crates/edge` | 1:1 |
| pack_diff (incremental disk snapshot → restorable env; scrub build residue; separate builder/runtime accounts) | P §6.1 | `crates/edge` + SDK | 1:1 |
| Worker container + agent sandbox (rollout decoupled from preemptible trainer) | P §6.2 | `rl/worker` | 1:1 shape; scaffold = open harness (opencode / mini-swe-agent) instead of DSH |
| AppArmor per-sandbox profiles (chronus logs/sockets, /bin/bash) | P §6.5, V4.1 | `security/apparmor` | 1:1 |
| eBPF per-sandbox network allowlist (IP/port/proto; domain/mirror groups; live update) | P §6.5 | `security/ebpf` | 1:1 |
| Repercussion signal on env crash | V4.1 | `crates/edge` + SDK | 1:1 |
| Cloud bursting (>80% util → cloud VMs; cloud-eligible = image set covered) | P §3.4 | `crates/placement` | 1:1 logic; cloud = DigitalOcean / Lambda VMs |
| Scale units (shards) | V4.1 | config | 1:1 logic |

## Experiments to reproduce ([P] §8), scaled to our hardware

| # | Paper result | Our oracle |
| --- | --- | --- |
| E1 | On-demand EROFS vs eager pull: 1.71× faster; −57% disk writes (8,192 containers / 10 nodes) | same 3 configs (cold pull / cached / on-demand), N scaled to hardware; report ratio + bytes written |
| E2 | EROFS layers vs tar.gz: 1.76× faster; 5.5× write traffic | same, scripted deterministic tool-call replay |
| E3 | Memory: pmem+DAX −40.2% peak; DAMON+FPR −21.2% time-integrated; both best | same 4 Firecracker configs |
| E4 | CPU QoS: chess LS latency +45.2% → +17.3% at 50% BE | same 3 configs × BE 10–50% |
| E5 | Access-control red-team (P §6.4 attacks: chronus socket forging, log reading, /bin/bash overwrite, port scan, proxy exfil, `yes` flood) | each attack must fail, with a test |

Hardware (honest): dev host i9-14900K (hybrid P/E, SMT, 62 GB, RTX 5090, kernel 6.14),
DigitalOcean droplets (nested KVM), on-demand Lambda. Paper used 10× EPYC 9655 nodes. Absolute numbers will differ; we compare ratios.

## Milestones

- M0 spec + skeleton (this PR).
- M1 control plane end-to-end on one host: apiserver + iam + placement + watcher + edge + container backend (plain Docker) + aether + chronus + trajlog + libdsec.
- M2 image path: EROFS converter, layer composition, dockerd patch, shared-FS on-demand (3FS).
- M3 microVM backend: Firecracker + EROFS ro devices + overlaybd/ublk + pmem/DAX + DAMON/FPR + snapshot pause/resume.
- M4 QoS + security: SCHED_IDLE/core-sched, AppArmor, eBPF allowlist, output cap, repercussion.
- M5 RL co-design: pause/resume API, pack_diff, worker container, trajectory replay demo.
- M6 FnCall (CPU + GPU) and full VM (QEMU Linux GUI + Android).
- M7 experiments E1–E5 with receipts.
- M8 multi-node: scale unit across ≥3 hosts + cloud burst.

## Acceptance (applies to every milestone)

Real oracles only: each mechanism has a test that fails with the mechanism
disabled and passes with it enabled. Numbers come from runs, never from the paper.
Every PR updates the fidelity column above if reality differs.
