"""Helpers for service tests: real sender/receiver subprocesses on loopback and a mock sink."""
from __future__ import annotations

import hashlib
import http.client
import json
import os
import signal
import socket
import subprocess
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
TOKEN = "api-token-for-tests-0123456789"


def free_port(kind: int = socket.SOCK_STREAM) -> int:
    with socket.socket(socket.AF_INET, kind) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


class Sink:
    """Mock high-side HTTP endpoint. ``script`` is a list of statuses consumed one per request."""

    def __init__(self) -> None:
        self.received: list[dict] = []
        self.script: list[int] = []
        self.lock = threading.Lock()
        sink = self

        class H(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def do_POST(self) -> None:
                n = int(self.headers.get("Content-Length", "0"))
                h = hashlib.sha256()
                got = 0
                while got < n:
                    block = self.rfile.read(min(65536, n - got))
                    if not block:
                        break
                    h.update(block)
                    got += len(block)
                with sink.lock:
                    status = sink.script.pop(0) if sink.script else 200
                    sink.received.append(
                        {
                            "status": status,
                            "sha256": h.hexdigest(),
                            "size": got,
                            "key": self.headers.get("Idempotency-Key"),
                            "tid": self.headers.get("X-Diode-Transfer-Id"),
                            "hdr_sha": self.headers.get("X-Diode-Sha256"),
                            "ctype": self.headers.get("Content-Type"),
                            "path": self.path,
                        }
                    )
                self.send_response(status)
                self.send_header("Content-Length", "0")
                self.send_header("Connection", "close")
                self.end_headers()

            def log_message(self, *a: object) -> None:
                pass

        self.port = free_port()
        self.server = ThreadingHTTPServer(("127.0.0.1", self.port), H)
        self.server.daemon_threads = True
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    @property
    def url(self) -> str:
        return f"http://127.0.0.1:{self.port}/ingest"

    def stop(self) -> None:
        self.server.shutdown()
        self.server.server_close()

    def accepted(self) -> list[dict]:
        with self.lock:
            return [r for r in self.received if 200 <= r["status"] < 300]

    def wait_accepted(self, n: int, timeout: float = 60.0) -> list[dict]:
        end = time.time() + timeout
        while time.time() < end:
            got = self.accepted()
            if len(got) >= n:
                return got
            time.sleep(0.05)
        raise AssertionError(f"sink got {len(self.accepted())} of {n} bodies in {timeout}s")


class Proc:
    def __init__(self, role: str, env: dict[str, str], log: Path) -> None:
        self.role = role
        self.log = log
        self.env = env
        self.fh = log.open("ab")
        self.p = subprocess.Popen(
            [sys.executable, str(ROOT / "diode.py")],
            env={**os.environ, **env, "DIODE_MODE": role, "PYTHONUNBUFFERED": "1"},
            cwd=ROOT,
            stdout=self.fh,
            stderr=subprocess.STDOUT,
        )
        self.http_port = int(env["DIODE_HTTP_PORT"])

    def wait_ready(self, timeout: float = 20.0, path: str = "/readyz") -> None:
        end = time.time() + timeout
        while time.time() < end:
            if self.p.poll() is not None:
                raise AssertionError(f"{self.role} exited {self.p.returncode}:\n{self.log.read_text()[-2000:]}")
            try:
                c = http.client.HTTPConnection("127.0.0.1", self.http_port, timeout=2)
                c.request("GET", path)
                r = c.getresponse()
                r.read()
                if r.status == 200:
                    return
            except OSError:
                pass
            time.sleep(0.1)
        raise AssertionError(f"{self.role} not ready:\n{self.log.read_text()[-2000:]}")

    def term(self, timeout: float = 20.0) -> int:
        if self.p.poll() is None:
            self.p.send_signal(signal.SIGTERM)
            try:
                self.p.wait(timeout)
            except subprocess.TimeoutExpired:
                self.p.kill()
                self.p.wait()
        self.fh.close()
        return self.p.returncode

    def kill(self) -> None:
        if self.p.poll() is None:
            self.p.send_signal(signal.SIGKILL)
            self.p.wait()
        self.fh.close()


class Pair:
    def __init__(self, tmp: Path, feedback: str = "off", sender_extra: dict | None = None,
                 receiver_extra: dict | None = None, sink: Sink | None = None) -> None:
        self.tmp = tmp
        self.sink = sink or Sink()
        self.feedback = feedback
        (tmp / "secrets").mkdir(exist_ok=True)
        for name, value in (("token", TOKEN), ("data.key", "d" * 32), ("receipt.key", "r" * 32)):
            (tmp / "secrets" / name).write_text(value + "\n")
        self.data_port = free_port(socket.SOCK_DGRAM)
        self.receipt_port = free_port(socket.SOCK_DGRAM)
        self.s_http = free_port()
        self.r_http = free_port()
        self.s_state = tmp / "s_state"
        self.r_state = tmp / "r_state"
        common = {
            "DIODE_FEEDBACK": feedback,
            "DIODE_API_TOKEN_FILE": str(tmp / "secrets" / "token"),
            "DIODE_DATA_KEY_FILE": str(tmp / "secrets" / "data.key"),
            "DIODE_HTTP_BIND": "127.0.0.1",
        }
        if feedback == "receipts":
            common["DIODE_RECEIPT_KEY_FILE"] = str(tmp / "secrets" / "receipt.key")
        self.sender_env = {
            **common,
            "DIODE_STATE_DIR": str(self.s_state),
            "DIODE_HTTP_PORT": str(self.s_http),
            "DIODE_DATA_PEER": f"127.0.0.1:{self.data_port}",
            "DIODE_MAX_BITRATE_MBPS": "400",
            "DIODE_DISK_RESERVE_BYTES": "1048576",
            "DIODE_HTTP_IO_TIMEOUT_S": "3",
            **({"DIODE_RECEIPT_BIND": f"127.0.0.1:{self.receipt_port}"} if feedback == "receipts" else {}),
            **(sender_extra or {}),
        }
        self.receiver_env = {
            **common,
            "DIODE_STATE_DIR": str(self.r_state),
            "DIODE_HTTP_PORT": str(self.r_http),
            "DIODE_DATA_BIND": f"127.0.0.1:{self.data_port}",
            "DIODE_DELIVERY_URL": self.sink.url,
            "DIODE_MIN_FREE_BYTES": "1048576",
            "DIODE_DELIVERY_BACKOFF_MIN_S": "0.2",
            "DIODE_DELIVERY_BACKOFF_MAX_S": "1",
            **({"DIODE_RECEIPT_PEER": f"127.0.0.1:{self.receipt_port}"} if feedback == "receipts" else {}),
            **(receiver_extra or {}),
        }
        self.sender: Proc | None = None
        self.receiver: Proc | None = None

    def start_receiver(self) -> Proc:
        self.receiver = Proc("receiver", self.receiver_env, self.tmp / "receiver.log")
        self.receiver.wait_ready()
        return self.receiver

    def start_sender(self, extra: dict | None = None, ready: bool = True) -> Proc:
        env = {**self.sender_env, **(extra or {})}
        self.sender = Proc("sender", env, self.tmp / "sender.log")
        self.sender.wait_ready(path="/readyz" if ready else "/healthz")
        return self.sender

    def start(self, sender_ready: bool = True) -> "Pair":
        self.start_receiver()
        self.start_sender(ready=sender_ready)
        return self

    def stop(self) -> None:
        for p in (self.sender, self.receiver):
            if p is not None:
                p.term()
        self.sink.stop()

    def __enter__(self) -> "Pair":
        return self.start()

    def __exit__(self, *a: object) -> None:
        self.stop()

    # ---- client helpers ------------------------------------------------

    def post(self, body: bytes, key: str, headers: dict | None = None, port: int | None = None,
             token: str | None = TOKEN) -> tuple[int, dict, dict]:
        c = http.client.HTTPConnection("127.0.0.1", port or self.s_http, timeout=60)
        h = {"Idempotency-Key": key, "Content-Type": "application/octet-stream"}
        if token is not None:
            h["Authorization"] = f"Bearer {token}"
        h.update(headers or {})
        c.request("POST", "/v1/transfers", body=body, headers=h)
        r = c.getresponse()
        data = r.read()
        out = json.loads(data) if data else {}
        hdrs = {k.lower(): v for k, v in r.getheaders()}
        c.close()
        return r.status, out, hdrs

    def get(self, path: str, port: int | None = None, token: str | None = TOKEN) -> tuple[int, dict]:
        c = http.client.HTTPConnection("127.0.0.1", port or self.s_http, timeout=10)
        h = {"Authorization": f"Bearer {token}"} if token is not None else {}
        c.request("GET", path, headers=h)
        r = c.getresponse()
        data = r.read()
        c.close()
        return r.status, (json.loads(data) if data else {})

    def wait_state(self, tid: str, states: tuple[str, ...], timeout: float = 60.0) -> dict:
        end = time.time() + timeout
        last: dict = {}
        while time.time() < end:
            code, last = self.get(f"/v1/transfers/{tid}")
            if code == 200 and last.get("state") in states:
                return last
            time.sleep(0.1)
        raise AssertionError(f"transfer {tid} never reached {states}: {last}")


def sha(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()
