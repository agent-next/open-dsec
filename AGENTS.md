# open-dsec — agent entrypoint

Open reproduction of DeepSeek Elastic Compute (DSec), the sandbox platform
DeepSeek uses for agentic RL training and evaluation (arXiv:2609.22978).
This repo follows the [agent-next agent
standard](https://github.com/agent-next/.github/blob/main/AGENT-STANDARD.md).

## Purpose

Reproduce DSec from the public reports only: same component split, same
mechanisms, experiments at small scale with measured numbers. Independent
community work — not affiliated with or endorsed by DeepSeek, no
DeepSeek-internal code. `SPEC.md` is binding: component map, fidelity
targets, milestones, acceptance.

## Orient

- `SPEC.md` — binding spec and milestone plan; primary sources listed there.
- `crates/` — Rust workspace: rpc, apiserver, iam, placement, watcher, edge
  (Docker container backend), aether, chronus, trajlog, vmm. `dsec-vmm` is
  M3 work in progress and excluded from `make check`.
- `sdk/python/` — `libdsec` SDK and its pytest suite (uv; dev deps in the
  `dev` dependency group).
- `scripts/` — `dev-up.sh`/`dev-down.sh` local stack, `e2e_m1.py`.
- `docs/DEVIATIONS.md` — where the build differs from the paper, and why.
- `CHANGELOG.md`, `README.md` (quickstart, contributing pointers).

## Setup

Prerequisites (README): Rust stable with `rustfmt` and `clippy`, `uv`,
Python >= 3.10. Docker is needed only for `make host-check` and the
quickstart — not for `make check`.

    make setup

installs the `rustfmt`/`clippy` components, fetches the workspace lockfile,
and syncs the SDK dev dependencies (pytest) with uv.

## Check

    make check        # unprivileged: fmt, clippy, cargo test, SDK pytest
    make host-check   # needs docker: edge --ignored tests + SDK e2e vs dev-up

CI runs `make check` on every PR and push to `main`.

## Boundaries

- Every mechanism cites its source section (`P §x`, `V4`, `V4.1`) in a doc
  comment or doc. If you deviate from the paper, update the Fidelity column
  in `SPEC.md` in the same PR and log it in `docs/DEVIATIONS.md`.
- No invented numbers. Performance claims need a recorded run (command,
  config, raw output) — never the paper's numbers.
- Tests use real oracles: each mechanism has a test that fails with it
  disabled.
- Tests needing root/KVM/ublk/3FS/docker are marked `#[ignore]` (Rust) or
  `@pytest.mark.host` (Python) and run by `make host-check`; `make check`
  stays runnable without privileges.
- Branches + PRs only; never commit to `main`. Conventional Commits.
  Versions 0.0.x.
- Public repo: no internal plans, people names, data paths, hostnames, or
  timelines; no secrets. Primary sources are the arXiv reports in `SPEC.md`.
- Don't rewrite working CI or delete existing workflows.

## Done

- `make check` passes locally and in CI. Pre-existing failures are listed in
  the PR body — never hidden (no skip/xfail/`|| true`).
- New mechanisms: cite their source, ship a real-oracle test, log any
  deviation. Performance claims carry a receipt.
- CHANGELOG.md updated for user-visible changes; Conventional Commit on a
  PR branch against `main`.
