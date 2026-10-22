"""Small HTTP plumbing shared by the sender and receiver services.

Standard library only. ``http.server`` is not a hardened server, so this module
adds what a network-facing service needs from it: a connection cap that answers
503, a short deadline for request headers and a longer one for the body (both
enforced by closing the socket, so a drip-feed client cannot hold a thread),
per-recv socket timeouts, one request per connection, a bounded chunked-body
decoder, bearer-token auth with a constant-time compare, and optional TLS with
the handshake done in the handler thread. It is meant for a few trusted
clients (NiFi, a sidecar) on a controlled network, not the open internet.
"""
from __future__ import annotations

import hmac
import json
import socket
import ssl
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Callable

READ_BLOCK = 256 * 1024
MAX_LINE = 4096
MAX_HEADER_BYTES = 16 * 1024


class HttpError(Exception):
    def __init__(self, status: int, message: str, headers: dict[str, str] | None = None) -> None:
        super().__init__(message)
        self.status = status
        self.message = message
        self.headers = headers or {}


class BoundedServer(ThreadingHTTPServer):
    daemon_threads = True
    request_queue_size = 128
    allow_reuse_address = True

    def __init__(
        self,
        addr: tuple[str, int],
        handler: type[BaseHTTPRequestHandler],
        *,
        max_connections: int,
        header_deadline_s: float,
        body_deadline_s: float,
        ssl_context: ssl.SSLContext | None = None,
    ) -> None:
        self._slots = threading.BoundedSemaphore(max_connections)
        self.header_deadline_s = header_deadline_s
        self.body_deadline_s = body_deadline_s
        self._timers: dict[int, threading.Timer] = {}
        self._timer_lock = threading.Lock()
        self.ctx: Any = None  # service object the handler reaches through self.server.ctx
        super().__init__(addr, handler)
        if ssl_context is not None:
            self.socket = ssl_context.wrap_socket(
                self.socket, server_side=True, do_handshake_on_connect=False
            )

    def arm(self, request: socket.socket, seconds: float) -> None:
        """(Re)start this connection's kill timer."""
        timer = threading.Timer(seconds, self._kill, args=(request,))
        timer.daemon = True
        with self._timer_lock:
            old = self._timers.get(id(request))
            self._timers[id(request)] = timer
        if old is not None:
            old.cancel()
        timer.start()

    def disarm(self, request: socket.socket) -> None:
        with self._timer_lock:
            timer = self._timers.pop(id(request), None)
        if timer is not None:
            timer.cancel()

    @staticmethod
    def _kill(request: socket.socket) -> None:
        try:
            request.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass

    def process_request(self, request: socket.socket, client_address: Any) -> None:
        if not self._slots.acquire(blocking=False):
            try:
                request.settimeout(1.0)
                request.sendall(
                    b"HTTP/1.1 503 Service Unavailable\r\nRetry-After: 1\r\n"
                    b"Content-Length: 0\r\nConnection: close\r\n\r\n"
                )
            except OSError:
                pass
            finally:
                self.shutdown_request(request)
            return
        self.arm(request, self.header_deadline_s)
        super().process_request(request, client_address)

    def process_request_thread(self, request: socket.socket, client_address: Any) -> None:
        try:
            super().process_request_thread(request, client_address)
        finally:
            self.disarm(request)
            self._slots.release()


class Handler(BaseHTTPRequestHandler):
    """Base handler. Subclasses set ``routes`` and implement ``route``."""

    protocol_version = "HTTP/1.1"
    server_version = "diode"
    sys_version = ""
    timeout = 30.0  # per-recv; set by make_handler

    def setup(self) -> None:
        super().setup()
        if isinstance(self.request, ssl.SSLSocket):
            self.request.do_handshake()

    def log_message(self, fmt: str, *args: Any) -> None:  # one line per request on stderr
        import sys

        print(f"http {self.address_string()} {fmt % args}", file=sys.stderr)

    def parse_request(self) -> bool:
        ok = super().parse_request()
        self.close_connection = True  # one request per connection
        if ok:
            self.server.arm(self.request, self.server.body_deadline_s)  # type: ignore[attr-defined]
        return ok

    # ---- plumbing -------------------------------------------------------

    @property
    def ctx(self) -> Any:
        return self.server.ctx  # type: ignore[attr-defined]

    def send_json(self, status: int, obj: Any, headers: dict[str, str] | None = None) -> None:
        body = (json.dumps(obj, separators=(",", ":")) + "\n").encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Connection", "close")
        for k, v in (headers or {}).items():
            self.send_header(k, v)
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def authorized(self) -> bool:
        presented = self.headers.get("Authorization", "")
        scheme, _, token = presented.partition(" ")
        if scheme.lower() != "bearer":
            return False
        return hmac.compare_digest(token.strip().encode(), self.ctx.cfg.api_token)

    def require_auth(self) -> None:
        if not self.authorized():
            raise HttpError(401, "missing or invalid bearer token", {"WWW-Authenticate": "Bearer"})

    def dispatch(self) -> None:
        try:
            if len(self.requestline) > MAX_LINE:
                raise HttpError(414, "request line too long")
            self.route()
        except HttpError as err:
            self.close_connection = True
            self.send_json(err.status, {"error": err.message}, err.headers)
        except (TimeoutError, socket.timeout):
            self.close_connection = True
            try:
                self.send_json(408, {"error": "read timed out"})
            except OSError:
                pass
        except (ConnectionError, OSError):
            self.close_connection = True  # peer went away or the kill timer fired
        except Exception as exc:  # noqa: BLE001 - never leak internals to the client
            self.close_connection = True
            import sys

            print(f"http handler error: {type(exc).__name__}: {exc}", file=sys.stderr)
            try:
                self.send_json(500, {"error": "internal error"})
            except OSError:
                pass

    def route(self) -> None:  # pragma: no cover - overridden
        raise HttpError(404, "not found")

    do_GET = do_POST = do_PUT = do_DELETE = do_PATCH = do_HEAD = dispatch

    # ---- request body ---------------------------------------------------

    def body_framing(self, max_bytes: int) -> tuple[int | None, bool]:
        """(content_length, chunked). Rejects ambiguous or oversized framing before any body byte is read."""
        te = self.headers.get("Transfer-Encoding")
        cl = self.headers.get("Content-Length")
        if te is not None:
            if cl is not None:
                raise HttpError(400, "both Content-Length and Transfer-Encoding")
            if te.strip().lower() != "chunked":
                raise HttpError(501, "only chunked transfer encoding is supported")
            return None, True
        if cl is None:
            raise HttpError(411, "Content-Length or chunked encoding required")
        if not cl.isascii() or not cl.isdigit() or len(cl) > 18:
            raise HttpError(400, "bad Content-Length")
        length = int(cl)
        if max_bytes and length > max_bytes:
            raise HttpError(413, f"body exceeds {max_bytes} bytes")
        return length, False

    def iter_body(self, length: int | None, chunked: bool, max_bytes: int) -> Any:
        """Yield body blocks. Raises HttpError on a short, oversized or malformed body."""
        total = 0
        if not chunked:
            remaining = length or 0
            while remaining:
                block = self.rfile.read(min(READ_BLOCK, remaining))
                if not block:
                    raise HttpError(400, "body ended before Content-Length")
                remaining -= len(block)
                yield block
            return
        while True:
            line = self.rfile.readline(MAX_LINE + 1)
            if not line.endswith(b"\n") or len(line) > MAX_LINE:
                raise HttpError(400, "bad chunk header")
            size_text = line.split(b";", 1)[0].strip()
            try:
                size = int(size_text, 16)
            except ValueError:
                raise HttpError(400, "bad chunk size") from None
            if size < 0 or not size_text:
                raise HttpError(400, "bad chunk size")
            if size == 0:
                trailer = 0
                while True:  # trailers are read and ignored, bounded
                    t = self.rfile.readline(MAX_LINE + 1)
                    trailer += len(t)
                    if t in (b"\r\n", b"\n") or not t:
                        break
                    if trailer > MAX_HEADER_BYTES:
                        raise HttpError(400, "trailers too large")
                return
            total += size
            if max_bytes and total > max_bytes:
                raise HttpError(413, f"body exceeds {max_bytes} bytes")
            remaining = size
            while remaining:
                block = self.rfile.read(min(READ_BLOCK, remaining))
                if not block:
                    raise HttpError(400, "chunk ended early")
                remaining -= len(block)
                yield block
            if self.rfile.read(2) != b"\r\n":
                raise HttpError(400, "missing chunk terminator")


def make_handler(base: type[Handler], io_timeout_s: float) -> type[Handler]:
    return type(base.__name__, (base,), {"timeout": io_timeout_s})


def make_ssl_context(cert: str, key: str) -> ssl.SSLContext:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.load_cert_chain(cert, key)
    return ctx


def serve_in_thread(server: BoundedServer, name: str) -> threading.Thread:
    t = threading.Thread(target=server.serve_forever, kwargs={"poll_interval": 0.2}, name=name, daemon=True)
    t.start()
    return t


Check = Callable[[], tuple[bool, str]]
