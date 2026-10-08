"""End-to-end against a real local stack (docker backend).

Requires: scripts/dev-up.sh running, docker reachable, a dev token in
DSEC_TOKEN (dev-up prints one; $DSEC_HOME/iam.json holds it). Selected
with `pytest -m host` (make host-check).
"""

import json
import os
import socket
import uuid

import pytest

pytestmark = pytest.mark.host

ENDPOINT = os.environ.get("DSEC_ENDPOINT", "127.0.0.1:9100")


def _token():
    tok = os.environ.get("DSEC_TOKEN")
    if tok:
        return tok
    state = os.environ.get("DSEC_STATE", "/tmp/dsec-dev/iam.json")
    with open(state) as f:
        for p in json.load(f)["principals"].values():
            if p["id"] == "dev":
                return p["token"]
    raise AssertionError("no dev token: set DSEC_TOKEN or run scripts/dev-up.sh")


@pytest.fixture(scope="module")
def client():
    host, port = ENDPOINT.split(":")
    try:
        with socket.create_connection((host, int(port)), timeout=5):
            pass
    except OSError:
        pytest.skip("no local stack (run scripts/dev-up.sh)")
    from libdsec import Client

    return Client(ENDPOINT, token=_token(), project="dev")


@pytest.fixture()
def sb(client):
    box = client.create(image="ubuntu:24.04", cpu=0.5, memory=256, ttl=600, network={"pypi": True, "npm": False})
    yield box
    try:
        box.release()
    except Exception:
        pass


def test_stateful_exec_cwd_and_env_persist(sb):
    r = sb.exec("cd /tmp && export M1=works && pwd")
    assert r.exit_code == 0
    r = sb.exec("pwd; echo $M1")
    assert r.stdout == "/tmp\nworks\n"


def test_files_roundtrip(sb):
    data = bytes(range(256))
    sb.write_file("/tmp/m1/bin", data, mode=0o600)
    assert sb.read_file("/tmp/m1/bin") == data
    assert [e["name"] for e in sb.list_dir("/tmp/m1")] == ["bin"]


def test_trajlog_replay_returns_cached_result(sb):
    marker = f"/tmp/m1-replay-{uuid.uuid4().hex[:8]}"
    cmd = f"echo x >> {marker}; wc -l < {marker}"
    r1 = sb.exec(cmd, idx=0)
    assert r1.stdout == "1\n"
    assert not r1.replayed
    r2 = sb.exec(cmd, idx=0)
    assert r2.replayed, "identical re-issue must come from the trajectory log"
    assert r2.stdout == "1\n", "a re-execution would have appended a second line"


def test_streaming_and_release(sb):
    chunks = list(sb.stream("echo hello; echo world"))
    out = "".join(c.get("data", "") for c in chunks if c.get("stream") == "stdout")
    assert out == "hello\nworld\n"
    assert chunks[-1]["code"] == 0
