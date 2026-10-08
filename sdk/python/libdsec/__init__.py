"""libdsec: Python client SDK for open-dsec sandboxes (P §2.1,
arXiv:2609.22978).

Mirrors DSec's libdsec: one entry point that creates and operates sandboxes
across backends with a unified operational model — create, exec, file
access, streaming I/O, release. The caller picks the backend; `network` is
a per-domain allowlist ({"pypi": True, "npm": False}); open-dsec stores and
passes it through to the edge, and enforces it via eBPF from M4.

Wire protocol: the same framed RPC the Rust components speak — 4-byte
big-endian length + JSON body, multiplexed by request id, so the SDK needs
nothing beyond the standard library.
"""

from __future__ import annotations

import json
import secrets
import socket
import struct
import threading
import time
from typing import Iterator, Optional

__all__ = ["Client", "Sandbox", "RpcError", "ExecResult"]


class RpcError(Exception):
    """Error reply from the platform (`code`, `message`)."""

    def __init__(self, code: str, message: str):
        super().__init__(f"{code}: {message}")
        self.code = code
        self.message = message


class ExecResult:
    def __init__(self, payload: dict):
        self.exit_code: int = payload.get("code", -1)
        self.stdout: str = payload.get("stdout", "")
        self.stderr: str = payload.get("stderr", "")
        self.truncated: bool = payload.get("truncated", False)
        self.timed_out: bool = payload.get("timed_out", False)
        self.replayed: bool = payload.get("replayed", False)

    def __repr__(self) -> str:
        return f"ExecResult(code={self.exit_code!r}, stdout={self.stdout!r}, stderr={self.stderr!r}, replayed={self.replayed!r})"


class _Conn:
    """One TCP connection; concurrent calls multiplex by request id."""

    def __init__(self, endpoint: str):
        host, _, port = endpoint.partition(":")
        self.sock = socket.create_connection((host, int(port or 9100)))
        self.sock.settimeout(None)
        self._next_id = 1
        self._lock = threading.Lock()
        self._pending: dict[int, list] = {}  # id -> queue of replies
        self._cv = threading.Condition()
        self._reader = threading.Thread(target=self._read_loop, daemon=True)
        self._reader.start()

    def _read_loop(self) -> None:
        try:
            buf = b""
            while True:
                while len(buf) < 4:
                    d = self.sock.recv(65536)
                    if not d:
                        raise ConnectionError("closed")
                    buf += d
                (n,) = struct.unpack(">I", buf[:4])
                buf = buf[4:]
                while len(buf) < n:
                    d = self.sock.recv(65536)
                    if not d:
                        raise ConnectionError("closed")
                    buf += d
                body, buf = buf[:n], buf[n:]
                rep = json.loads(body)
                kind = rep.get("kind")
                rid = rep.get("id")
                with self._cv:
                    q = self._pending.setdefault(rid, [])
                    if kind == "ok":
                        q.append(("ok", rep["result"]))
                        self._cv.notify_all()
                    elif kind == "err":
                        q.append(("err", rep))
                        self._cv.notify_all()
                    elif kind == "chunk":
                        q.append(("chunk", rep["item"]))
                        self._cv.notify_all()
                    elif kind == "end":
                        q.append(("end", None))
                        self._cv.notify_all()
        except OSError:
            with self._cv:
                for rid in list(self._pending):
                    self._pending[rid].append(("err", {"code": "disconnected", "message": "connection closed"}))
                    self._cv.notify_all()

    def call(self, method: str, params: dict, token: str) -> dict:
        rid = self._send(method, params, token)
        while True:
            item = self._wait(rid)
            kind, val = item[0], item[1]
            if kind == "ok":
                return val
            if kind == "err":
                raise RpcError(val["code"], val["message"])
            # stray chunk/end on a plain call: keep waiting

    def stream(self, method: str, params: dict, token: str) -> Iterator[dict]:
        rid = self._send(method, params, token)
        done = False
        while not done:
            kind, val = self._wait(rid)
            if kind == "chunk":
                yield val
            elif kind == "err":
                raise RpcError(val["code"], val["message"])
            elif kind in ("ok", "end"):
                done = True

    def _send(self, method: str, params: dict, token: str) -> int:
        with self._lock:
            rid = self._next_id
            self._next_id += 1
        req = {"id": rid, "method": method, "params": params, "token": token}
        body = json.dumps(req).encode()
        with self._cv:
            self._pending[rid] = []
        with self._lock:
            self.sock.sendall(struct.pack(">I", len(body)) + body)
        return rid

    def _wait(self, rid: int, timeout: float = 3600.0):
        with self._cv:
            while not self._pending.get(rid):
                self._cv.wait(timeout)
            q = self._pending[rid]
            return q.pop(0)


class Sandbox:
    """One sandbox handle (P §2.3): stateful across calls until released."""

    def __init__(self, client: "Client", meta: dict):
        self._c = client
        self.id: str = meta["id"]
        self.edge_id: str = meta.get("edge_id", "")
        self.image: str = meta.get("image", "")
        self.cpu_mc: int = meta.get("cpu_mc", 0)
        self.mem_mb: int = meta.get("mem_mb", 0)
        self.network: dict = meta.get("network") or {}
        self.status: dict | None = meta.get("status")
        # Terminal-session id for this handle (P §3.1): one chronus session,
        # so cwd/env persist across exec calls.
        self._session = secrets.token_hex(8)
        self._idx = 0

    def exec(self, cmd: str, timeout_ms: Optional[int] = None, idx: Optional[int] = None) -> ExecResult:
        """Run a shell command; state (cwd, env, files) persists across calls.

        Every call is journaled in the sandbox's trajectory log under its
        position `idx` (auto-incremented when not given). A preempted client
        resuming its command stream re-issues the same idx with the same
        text and gets the cached result instead of a re-execution — the
        fast-forward of V4 §5.2.5 (never re-runs non-idempotent commands)."""
        params: dict = {"sandbox_id": self.id, "session": self._session, "cmd": cmd, "idx": self._bump() if idx is None else idx}
        if timeout_ms is not None:
            params["timeout_ms"] = timeout_ms
        r = self._call_ready("sandbox.exec", params)
        return ExecResult(r)

    def stream(self, cmd: str, timeout_ms: Optional[int] = None) -> Iterator[dict]:
        """Server-streaming exec: yields {"stream": "stdout"|"stderr",
        "data": str} chunks then one exit-info dict (P §3.3)."""
        params: dict = {"sandbox_id": self.id, "session": self._session, "cmd": cmd}
        if timeout_ms is not None:
            params["timeout_ms"] = timeout_ms
        deadline = time.monotonic() + 30.0
        while True:
            try:
                rx = self._c._stream("sandbox.stream", params)
                first = next(rx)
                break
            except RpcError as e:
                if e.code != "not_ready" or time.monotonic() >= deadline:
                    raise
                time.sleep(0.15)
        yield first
        yield from rx

    def read_file(self, path: str) -> bytes:
        import base64

        r = self._call_ready("sandbox.read_file", {"sandbox_id": self.id, "session": self._session, "path": path, "idx": self._bump()})
        return base64.b64decode(r["data"])

    def write_file(self, path: str, data: bytes, mode: Optional[int] = None) -> None:
        import base64

        params = {
            "sandbox_id": self.id,
            "session": self._session,
            "path": path,
            "data": base64.b64encode(data).decode(),
            "idx": self._bump(),
        }
        if mode is not None:
            params["mode"] = mode
        self._call_ready("sandbox.write_file", params)

    def list_dir(self, path: str) -> list[dict]:
        r = self._call_ready("sandbox.list_dir", {"sandbox_id": self.id, "session": self._session, "path": path, "idx": self._bump()})
        return r["entries"]

    def http_request(self, method: str = "GET", url: str = "", headers: Optional[dict] = None, body: bytes = b""):
        import base64

        r = self._call_ready(
            "sandbox.http",
            {
                "sandbox_id": self.id,
                "session": self._session,
                "idx": self._bump(),
                "request": {"method": method, "url": url, "headers": headers or {}, "body": base64.b64encode(body).decode()},
            },
        )
        return {"status": r["status"], "headers": r["headers"], "body": base64.b64decode(r["body"])}

    def trajectory(self) -> list[dict]:
        """Provenance: the sandbox's globally ordered operation log."""
        r = self._c._call("sandbox.traj", {"sandbox_id": self.id})
        return r["entries"]

    def _call_ready(self, method: str, params: dict, wait_s: float = 30.0) -> dict:
        """Call, tolerating the aether channel still coming up after create
        (the in-sandbox proxy needs a moment to dial the edge, P §3.3)."""
        deadline = time.monotonic() + wait_s
        while True:
            try:
                return self._c._call(method, params)
            except RpcError as e:
                if e.code != "not_ready" or time.monotonic() >= deadline:
                    raise
                time.sleep(0.15)

    def refresh(self) -> dict:
        self.status = self._c._call("sandbox.get", {"sandbox_id": self.id})["status"]
        return self.status

    @property
    def repercussion(self) -> bool:
        """True when the environment crashed (V4.1 §5.1.3 repercussion)."""
        st = self.refresh()
        return bool(st.get("repercussion")) if isinstance(st, dict) else False

    def release(self) -> None:
        self._c._call("sandbox.delete", {"sandbox_id": self.id})

    def _bump(self) -> int:
        i = self._idx
        self._idx += 1
        return i

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.release()
        return False


class Client:
    """`Client(endpoint, token)` — the libdsec entry point (P §2.1).

    endpoint is host:port of an apiserver.
    """

    def __init__(self, endpoint: str, token: str, project: str = "dev"):
        self.endpoint = endpoint
        self.token = token
        self.project = project
        self._conn = _Conn(endpoint)

    def create(
        self,
        *,
        type: str = "container",
        image: str = "ubuntu:24.04",
        cpu: float = 1.0,
        memory: int = 512,
        ttl: Optional[int] = None,
        network: Optional[dict] = None,
        task: Optional[str] = None,
    ) -> Sandbox:
        """Create a sandbox (P §2.1/§2.3). cpu in cores, memory in MiB,
        ttl in seconds, network a per-domain allowlist like
        {"pypi": True, "npm": False}. Only type="container" exists in M1;
        the network allowlist is stored and forwarded to the edge —
        enforcement ships with the eBPF work in M4."""
        if type != "container":
            raise RpcError("unsupported", f"backend {type!r} arrives in a later milestone (M1: container)")
        params = {
            "backend": "container",
            "project": self.project,
            "image": image,
            "cpu_mc": int(cpu * 1000),
            "mem_mb": int(memory),
            "network": network or {},
        }
        if ttl is not None:
            params["ttl_ms"] = int(ttl * 1000)
        if task is not None:
            params["task"] = task
        return Sandbox(self, self._call("sandbox.create", params))

    def sandbox(self, sandbox_id: str) -> Sandbox:
        """Adopt an existing sandbox by id."""
        meta = self._call("sandbox.get", {"sandbox_id": sandbox_id})
        return Sandbox(self, meta)

    def _call(self, method: str, params: dict) -> dict:
        return self._conn.call(method, params, self.token)

    def _stream(self, method: str, params: dict) -> Iterator[dict]:
        yield from self._conn.stream(method, params, self.token)
