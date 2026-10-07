# open-dsec — agent entrypoint

Open reproduction of DeepSeek Elastic Compute (DSec), arXiv:2609.22978.
`SPEC.md` is binding: component map, fidelity labels, milestones, acceptance.

## Rules

- Every mechanism cites its source section (`P §x`, `V4`, `V4.1`) in a doc comment or
  doc. If you deviate from the paper, update the Fidelity column in `SPEC.md` in the same PR.
- No invented numbers. Performance claims come from runs in `bench/` with a receipt
  under `task-runs/` (workspace level) — never from the paper.
- Tests use real oracles: each mechanism has a test that fails with it disabled.
- Tests needing root/KVM/ublk/3FS are marked `#[ignore]` (Rust) or `@pytest.mark.host` (Python)
  and run by `make host-check`; `make check` stays runnable without privileges.
- Branches + PRs only; never commit to `main`. Conventional Commits. Versions 0.0.x.
- Primary source texts: `../task-runs/20261007-open-dsec/sources/`.

## Check

`make check` (cargo fmt/clippy/test + SDK pytest).
