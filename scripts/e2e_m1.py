"""M1 verification: 50 concurrent container sandboxes through libdsec.

Stateful commands (cd + export persist across execs), trajectory replay
returns the cached result for a re-issued position, everything released,
zero containers left behind.
"""

import concurrent.futures as cf
import json
import socket
import subprocess
import sys
import time
import uuid

sys.path.insert(0, "sdk/python")
from libdsec import Client, RpcError  # noqa: E402

ENDPOINT = "127.0.0.1:9100"
N = int(sys.argv[1]) if len(sys.argv) > 1 else 50

with open("/tmp/dsec-dev/iam.json") as f:
    token = next(p["token"] for p in json.load(f)["principals"].values() if p["id"] == "dev")

c = Client(ENDPOINT, token=token, project="dev")


def one(i: int) -> dict:
    sb = c.create(image="ubuntu:24.04", cpu=0.25, memory=128, ttl=1800,
                  network={"pypi": True, "npm": False})
    assert sb.id.startswith("sbx-edge-1-"), sb.id  # id encodes the owning edge
    # Stateful: cwd + env persist across exec calls.
    sb.exec(f"cd /tmp && export E2E={i}")
    r = sb.exec("pwd; echo $E2E")
    assert r.stdout == f"/tmp\n{i}\n", (i, r)
    # Trajectory replay (V4 §5.2.5): same position + same text re-issued
    # returns the cached result — the file must not gain a second line.
    marker = f"/tmp/e2e-{uuid.uuid4().hex[:8]}"
    cmd = f"echo x >> {marker}; wc -l < {marker}"
    r1 = sb.exec(cmd, idx=1000 + i)
    assert r1.stdout == "1\n" and not r1.replayed, (i, r1)
    r2 = sb.exec(cmd, idx=1000 + i)
    assert r2.replayed and r2.stdout == "1\n", (i, r2)
    sb.release()
    return {"i": i, "id": sb.id, "replayed": r2.replayed}


# Wait for the stack (dev-up gates on the watcher, but be safe).
for _ in range(50):
    try:
        with socket.create_connection(("127.0.0.1", 9100), timeout=2):
            break
    except OSError:
        time.sleep(0.2)

t0 = time.monotonic()
with cf.ThreadPoolExecutor(max_workers=N) as ex:
    results = list(ex.map(one, range(N)))
wall = time.monotonic() - t0

replayed = sum(r["replayed"] for r in results)
print(f"created+used+released {len(results)} sandboxes concurrently in {wall:.1f}s "
      f"({len(results)/wall:.1f}/s), replayed-from-log: {replayed}/{len(results)}")

# Every sandbox gone from the platform AND from docker.
leftover = subprocess.run(
    ["docker", "ps", "-a", "--filter", "label=open-dsec", "--format", "{{.Names}}"],
    capture_output=True, text=True).stdout.split()
print("docker leftover containers:", leftover if leftover else "NONE")
assert len(results) == N and replayed == N and not leftover
print("E2E OK")
