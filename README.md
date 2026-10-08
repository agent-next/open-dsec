# open-dsec

Open reproduction of **DeepSeek Elastic Compute (DSec)**: the sandbox platform
DeepSeek uses for agentic RL training and evaluation (arXiv:2609.22978).

DSec offers four sandbox backends behind one SDK (FnCall, container,
Firecracker microVM, QEMU full VM). It composes environments from EROFS layers
loaded on demand from a shared filesystem, and runs sandboxes at high density
with memory sharing, memory reclamation and CPU QoS. It also works with the RL
trainer to pause and resume sandboxes when GPU jobs are preempted, and to
contain reward hacking.

Status: M1 — single-host control plane + container sandbox end to end
(apiserver, IAM, placement, watcher, edge, Docker container backend,
aether, chronus, trajectory log, libdsec). See `SPEC.md` for the
component map, fidelity labels and the milestone plan.

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
`/tmp/dsec-dev/iam.json`). Then, from `sdk/python`:

```python
from libdsec import Client

c = Client("127.0.0.1:9100", token="<dev token>")
sb = c.create(image="ubuntu:24.04", cpu=0.5, memory=256, ttl=600,
              network={"pypi": True, "npm": False})
r = sb.exec("cd /tmp && export T=1 && echo hi")   # state persists across execs
r = sb.exec("pwd; echo $T")                       # -> /tmp
1

sb.write_file("/tmp/d/blob", bytes(range(256)))
sb.read_file("/tmp/d/blob")
list(sb.stream("echo streaming"))                 # chunks + exit info
sb.release()                                      # container removed
```

Requests travel the paper's path (P §3.1): libdsec -> apiserver (IAM
check, placement, edge-id routing) -> edge (admission, Docker
Engine API) -> in-sandbox aether -> per-session chronus shell. Every
operation is journaled per sandbox; re-issuing a completed command
returns the cached result instead of re-executing (V4 §5.2.5). The
`network` allowlist is stored and forwarded; its eBPF enforcement
lands in M4 — M1 containers run with `network none`.

Stop the stack with `scripts/dev-down.sh` (also removes containers
labeled `open-dsec`).
