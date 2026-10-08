# open-dsec

Open reproduction of **DeepSeek Elastic Compute (DSec)**: the sandbox platform
DeepSeek uses for agentic RL training and evaluation (arXiv:2609.22978).

DSec offers four sandbox backends behind one SDK (FnCall, container,
Firecracker microVM, QEMU full VM). It composes environments from EROFS layers
loaded on demand from a shared filesystem, and runs sandboxes at high density
with memory sharing, memory reclamation and CPU QoS. It also works with the RL
trainer to pause and resume sandboxes when GPU jobs are preempted, and to
contain reward hacking.

open-dsec is an independent, community reproduction built only from the
public reports cited in `SPEC.md`. It is not affiliated with or endorsed by
DeepSeek, and contains no DeepSeek code beyond what they released under open
licenses.

Status: v0.0.1, milestone M1 — single-host control plane + container sandbox
end to end (apiserver, IAM, placement, watcher, edge, Docker container backend,
aether, chronus, trajectory log, libdsec). Everything else in `SPEC.md`
(microVM, full VM, FnCall, EROFS image path, QoS, eBPF, RL co-design,
experiments) is planned, not built. `SPEC.md` has the component map, fidelity
labels (targets) and the milestone plan; `docs/DEVIATIONS.md` lists where M1
differs from the paper.

Prerequisites: Rust (stable, with clippy and rustfmt), [uv](https://docs.astral.sh/uv/),
Python >= 3.10; `make host-check` and the quickstart also need a running Docker
daemon (the dev stack pulls `ubuntu:24.04`).

```
make check        # unprivileged: fmt, clippy, cargo tests, SDK pytest
make host-check   # real-docker edge tests + SDK e2e against dev-up
```

## Quickstart (M1)

```sh
cargo build                       # debug binaries incl. dsec-aether
scripts/dev-up.sh                 # iam + watcher + placement + apiserver + edge
```

`dev-up.sh` prints a snippet with a fresh `dev` token (also in
`/tmp/dsec-dev/iam.json`; set `DSEC_HOME` to move that directory). Then, from
`sdk/python` (or after `pip install ./sdk/python`):

```python
from libdsec import Client

c = Client("127.0.0.1:9100", token="<dev token>")
sb = c.create(image="ubuntu:24.04", cpu=0.5, memory=256, ttl=600,
              network={"pypi": True, "npm": False})
r = sb.exec("cd /tmp && export T=1 && echo hi")   # r.stdout == "hi\n"
r = sb.exec("pwd; echo $T")                       # state persists: r.stdout == "/tmp\n1\n"

sb.write_file("/tmp/d/blob", bytes(range(256)))
sb.read_file("/tmp/d/blob")
list(sb.stream("echo streaming"))                 # chunks + exit info
sb.release()                                      # container removed
```

Requests travel the paper's path (arXiv:2609.22978 §3.1; `SPEC.md` lists the sources): libdsec -> apiserver (IAM
check, placement, edge-id routing) -> edge (admission, Docker
Engine API) -> in-sandbox aether -> per-session chronus shell. Every
operation is journaled per sandbox; re-issuing a completed command
returns the cached result instead of re-executing (DeepSeek-V4 report §5.2.5). The
`network` allowlist is stored and forwarded; its eBPF enforcement
lands in M4 — M1 containers run with `network none`.

Stop the stack with `scripts/dev-down.sh` (also removes containers
labeled `open-dsec`).

## Contributing and security

Contribution guidelines and the security-reporting policy are the
organization-wide ones:
[CONTRIBUTING](https://github.com/agent-next/.github/blob/main/CONTRIBUTING.md),
[SECURITY](https://github.com/agent-next/.github/blob/main/SECURITY.md).
Report vulnerabilities privately, not in public issues. `AGENTS.md` has the
repo conventions (cited sources, real-oracle tests, `make check` must pass).

## License

MIT — see `LICENSE`.
