#!/usr/bin/env python3
"""Mock high-side destination for the demo: records what it is sent, nothing else.

POST /ingest        hash the body, remember (Idempotency-Key, size, sha256), answer 200
GET  /received      JSON list of what arrived
GET  /healthz       200
"""
import hashlib
import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

received: list[dict] = []
lock = threading.Lock()


class H(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def reply(self, code: int, body: bytes = b"", ctype: str = "application/json") -> None:
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:
        if self.path == "/healthz":
            return self.reply(200, b"ok\n", "text/plain")
        if self.path == "/received":
            with lock:
                return self.reply(200, json.dumps(received).encode())
        self.reply(404)

    def do_POST(self) -> None:
        if self.path != "/ingest":
            return self.reply(404)
        n = int(self.headers.get("Content-Length", "0"))
        h, got = hashlib.sha256(), 0
        while got < n:
            block = self.rfile.read(min(65536, n - got))
            if not block:
                break
            h.update(block)
            got += len(block)
        with lock:
            received.append(
                {
                    "key": self.headers.get("Idempotency-Key"),
                    "size": got,
                    "sha256": h.hexdigest(),
                    "sha256_header": self.headers.get("X-Diode-Sha256"),
                }
            )
        self.reply(200, b"{}")

    def log_message(self, *a: object) -> None:
        pass


ThreadingHTTPServer(("0.0.0.0", 8081), H).serve_forever()
