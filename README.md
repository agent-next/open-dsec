# open-dsec

Open reproduction of **DeepSeek Elastic Compute (DSec)**: the sandbox platform
DeepSeek uses for agentic RL training and evaluation (arXiv:2609.22978).

DSec offers four sandbox backends behind one SDK (FnCall, container,
Firecracker microVM, QEMU full VM). It composes environments from EROFS layers
loaded on demand from a shared filesystem, and runs sandboxes at high density
with memory sharing, memory reclamation and CPU QoS. It also works with the RL
trainer to pause and resume sandboxes when GPU jobs are preempted, and to
contain reward hacking.

Status: M0 (spec + skeleton). See `SPEC.md` for the component map, what is
reproduced 1:1 and what is substituted, and the milestone plan.

```
make check
```
