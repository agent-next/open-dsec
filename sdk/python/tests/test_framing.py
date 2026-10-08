"""SDK wire-protocol tests against a small in-process server: the Python
client speaks the same framed RPC the Rust components serve."""

import json
import struct
import threading
import socket

import pytest

from libdsec import Client, RpcError


def _frame(rep):
    body = json.dumps(rep).encode()
    return struct.pack(">I", len(body)) + body


def _serve_conn(conn, handlers):
    buf = b""
    try:
        while True:
            while len(buf) < 4:
                d = conn.recv(65536)
                if not d:
                    return
                buf += d
            (n,) = struct.unpack(">I", buf[:4])
            buf = buf[4:]
            while len(buf) < n:
                d = conn.recv(65536)
                if not d:
                    return
                buf += d
            body, buf = buf[:n], buf[n:]
            req = json.loads(body)
            h = handlers.get(req["method"])
            if h is None:
                conn.sendall(_frame({"kind": "err", "id": req["id"], "code": "not_found", "message": "no such method"}))
                continue
            for out in h(req):
                kind, item = out
                conn.sendall(_frame({"kind": kind, "id": req["id"], **item}))
    except OSError:
        pass


def _serve(server_sock, handlers):
    server_sock.listen(8)
    while True:
        try:
            conn, _ = server_sock.accept()
        except OSError:
            return
        threading.Thread(target=_serve_conn, args=(conn, handlers), daemon=True).start()


@pytest.fixture()
def fake_api():
    calls = []

    def create(req):
        calls.append(req)
        return [
            (
                "ok",
                {
                    "result": {
                        "id": "sbx-e1-abcdef012345",
                        "edge_id": "e1",
                        "image": "debian:12-slim",
                        "cpu_mc": 500,
                        "mem_mb": 256,
                        "network": req["params"]["network"],
                    }
                },
            )
        ]

    def exec_(req):
        calls.append(req)
        if req["params"]["cmd"] == "boom":
            return [("err", {"code": "sandbox_failed", "message": "environment crashed (repercussion=true)"})]
        # Plain exec: one ok reply carrying the collected result (like the
        # real apiserver); sandbox.stream below is the streaming variant.
        return [
            (
                "ok",
                {
                    "result": {
                        "stdout": "partial\n",
                        "stderr": "",
                        "code": 0,
                        "truncated": False,
                        "timed_out": False,
                        "session_reset": False,
                    }
                },
            )
        ]

    def stream_(req):
        return [
            ("chunk", {"item": {"stream": "stdout", "data": "par"}}),
            ("chunk", {"item": {"stream": "stdout", "data": "tial\n"}}),
            ("chunk", {"item": {"code": 0, "truncated": False, "timed_out": False, "session_reset": False}}),
            ("end", {}),
        ]

    handlers = {
        "sandbox.create": create,
        "sandbox.exec": exec_,
        "sandbox.stream": stream_,
        "sandbox.delete": lambda req: [("ok", {"result": {}})],
        "sandbox.get": lambda req: [
            (
                "ok",
                {
                    "result": {
                        "id": "sbx-e1-abcdef012345",
                        "edge_id": "e1",
                        "image": "debian:12-slim",
                        "cpu_mc": 500,
                        "mem_mb": 256,
                        "network": {},
                        "status": {"state": "running"},
                    }
                },
            )
        ],
    }
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    threading.Thread(target=_serve, args=(s, handlers), daemon=True).start()
    yield f"127.0.0.1:{s.getsockname()[1]}", calls
    s.close()


def test_create_exec_release_roundtrip(fake_api):
    endpoint, calls = fake_api
    c = Client(endpoint, token="dsec-t", project="dev")
    sb = c.create(image="debian:12-slim", cpu=0.5, memory=256, network={"pypi": True, "npm": False})
    assert sb.id == "sbx-e1-abcdef012345"
    # network dict is carried through untouched (enforcement is M4)
    assert calls[0]["params"]["network"] == {"pypi": True, "npm": False}
    assert calls[0]["params"]["cpu_mc"] == 500
    assert calls[0]["token"] == "dsec-t"
    # exec journals with session+idx for trajlog replay
    r = sb.exec("echo partial")
    assert (r.exit_code, r.stdout) == (0, "partial\n")
    assert calls[-1]["params"]["session"] == sb._session
    assert calls[-1]["params"]["idx"] == 0
    sb.exec("echo again")
    assert calls[-1]["params"]["idx"] == 1
    sb.release()


def test_error_replies_raise(fake_api):
    endpoint, _ = fake_api
    c = Client(endpoint, token="dsec-t")
    sb = c.sandbox("sbx-e1-abcdef012345")
    with pytest.raises(RpcError) as ei:
        sb.exec("boom")
    assert ei.value.code == "sandbox_failed"
    assert "repercussion" in ei.value.message


def test_streaming_yields_chunks_then_exit(fake_api):
    endpoint, _ = fake_api
    c = Client(endpoint, token="dsec-t")
    sb = c.sandbox("sbx-e1-abcdef012345")
    items = list(sb.stream("echo partial"))
    out = "".join(i.get("data", "") for i in items if i.get("stream") == "stdout")
    assert out == "partial\n"
    assert items[0] == {"stream": "stdout", "data": "par"}
    assert items[-1]["code"] == 0
