"""Low-side service: HTTP ingress, durable spool and ledger, DIO2 UDP sender.

Custody rules
  * 202 is returned only after the payload file and the ledger row are durable
    (file fsync, rename, directory fsync, then a synchronous SQLite commit).
  * A transfer leaves the spool only on receiver-verified, or after a retention
    window for sent-unconfirmed / failed objects. "Send returned" is not a reason.
  * A restart puts in-flight jobs back in the queue; the receiver deduplicates
    by transfer id, so resending is safe.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import secrets
import shutil
import socket
import sqlite3
import sys
import threading
import time
import uuid
from pathlib import Path
from typing import Any

import pitcher
from catcher import Catcher, fsync_dir
from diode_config import Config
from diode_http import (
    BoundedServer,
    Handler,
    HttpError,
    make_handler,
    make_ssl_context,
    serve_in_thread,
)
from protocol import MAX_CONTENT_TYPE_LEN
from receipts import ReceiptStore

IDEM_RE = re.compile(r"[A-Za-z0-9._:-]{1,128}")
TID_RE = re.compile(r"[0-9a-f]{32}")
STATES = ("queued", "sending", "sent-unconfirmed", "receiver-verified", "failed", "expired")
TERMINAL = ("sent-unconfirmed", "receiver-verified", "failed", "expired")


class Conflict(Exception):
    pass


class Ledger:
    """SQLite (WAL, synchronous=FULL) transfer ledger. One lock; short transactions."""

    def __init__(self, path: Path) -> None:
        self.lock = threading.RLock()
        self.db = sqlite3.connect(path, check_same_thread=False, isolation_level=None)
        self.db.row_factory = sqlite3.Row
        with self.lock:
            self.db.execute("PRAGMA journal_mode=WAL")
            self.db.execute("PRAGMA synchronous=FULL")
            self.db.execute(
                """CREATE TABLE IF NOT EXISTS transfers(
                  id TEXT PRIMARY KEY,
                  idem_key TEXT NOT NULL UNIQUE,
                  sha256 TEXT NOT NULL,
                  size INTEGER NOT NULL,
                  content_type TEXT NOT NULL,
                  state TEXT NOT NULL,
                  reason TEXT,
                  created REAL NOT NULL,
                  updated REAL NOT NULL,
                  attempts INTEGER NOT NULL DEFAULT 0,
                  purged INTEGER NOT NULL DEFAULT 0)"""
            )
            self.db.execute("CREATE INDEX IF NOT EXISTS transfers_state ON transfers(state, created)")

    def close(self) -> None:
        with self.lock:
            self.db.close()

    def get(self, tid: str) -> dict | None:
        with self.lock:
            row = self.db.execute("SELECT * FROM transfers WHERE id=?", (tid,)).fetchone()
        return dict(row) if row else None

    def admit(
        self, key: str, sha: str, size: int, ctype: str, staged: Path, spool: Path
    ) -> tuple[dict, bool]:
        """Return (row, created). Raises Conflict when the key was used for other bytes."""
        with self.lock:
            self.db.execute("BEGIN IMMEDIATE")
            final: Path | None = None
            try:
                row = self.db.execute("SELECT * FROM transfers WHERE idem_key=?", (key,)).fetchone()
                if row is not None:
                    self.db.execute("COMMIT")
                    if row["sha256"] != sha or row["size"] != size:
                        raise Conflict(key)
                    return dict(row), False
                tid = uuid.uuid4().hex
                final = spool / f"{tid}.bin"
                os.replace(staged, final)
                fsync_dir(spool)
                now = time.time()
                self.db.execute(
                    "INSERT INTO transfers(id,idem_key,sha256,size,content_type,state,created,updated)"
                    " VALUES(?,?,?,?,?,?,?,?)",
                    (tid, key, sha, size, ctype, "queued", now, now),
                )
                self.db.execute("COMMIT")
                return self.get(tid) or {}, True
            except Conflict:
                raise
            except BaseException:
                try:
                    self.db.execute("ROLLBACK")
                except sqlite3.Error:
                    pass
                if final is not None:
                    final.unlink(missing_ok=True)
                raise

    def claim_next(self) -> dict | None:
        with self.lock:
            self.db.execute("BEGIN IMMEDIATE")
            try:
                row = self.db.execute(
                    "SELECT * FROM transfers WHERE state='queued' ORDER BY created LIMIT 1"
                ).fetchone()
                if row is None:
                    self.db.execute("COMMIT")
                    return None
                self.db.execute(
                    "UPDATE transfers SET state='sending', attempts=attempts+1, updated=? WHERE id=?",
                    (time.time(), row["id"]),
                )
                self.db.execute("COMMIT")
            except BaseException:
                self.db.execute("ROLLBACK")
                raise
        return self.get(row["id"])

    def set_state(self, tid: str, state: str, reason: str | None = None) -> None:
        assert state in STATES
        with self.lock:
            self.db.execute(
                "UPDATE transfers SET state=?, reason=?, updated=? WHERE id=?",
                (state, reason, time.time(), tid),
            )

    def recover(self) -> int:
        """Jobs that were mid-send when the process died go back to the queue."""
        with self.lock:
            cur = self.db.execute(
                "UPDATE transfers SET state='queued', updated=? WHERE state='sending'", (time.time(),)
            )
            return cur.rowcount

    def known_ids(self) -> set[str]:
        with self.lock:
            return {r[0] for r in self.db.execute("SELECT id FROM transfers WHERE purged=0")}

    def unpurged_bytes(self) -> int:
        with self.lock:
            return int(self.db.execute("SELECT COALESCE(SUM(size),0) FROM transfers WHERE purged=0").fetchone()[0])

    def mark_purged(self, tid: str) -> None:
        with self.lock:
            self.db.execute("UPDATE transfers SET purged=1, updated=? WHERE id=?", (time.time(), tid))

    def purgeable(self, now: float, spool_retention: float, failed_retention: float) -> list[str]:
        with self.lock:
            rows = self.db.execute(
                "SELECT id FROM transfers WHERE purged=0 AND ("
                " state='receiver-verified'"
                " OR (state='sent-unconfirmed' AND updated < ?)"
                " OR (state IN ('failed','expired') AND updated < ?))",
                (now - spool_retention, now - failed_retention),
            ).fetchall()
        return [r[0] for r in rows]

    def forget_old(self, now: float, retention: float) -> int:
        with self.lock:
            cur = self.db.execute(
                "DELETE FROM transfers WHERE purged=1 AND updated < ?", (now - retention,)
            )
            return cur.rowcount

    def summary(self) -> dict:
        with self.lock:
            by_state = {
                r[0]: {"count": r[1], "bytes": r[2]}
                for r in self.db.execute("SELECT state, COUNT(*), COALESCE(SUM(size),0) FROM transfers GROUP BY state")
            }
            oldest = self.db.execute(
                "SELECT MIN(created) FROM transfers WHERE state IN ('queued','sending')"
            ).fetchone()[0]
        return {"by_state": by_state, "oldest_queued_created": oldest}


class Counters:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self.values: dict[str, int] = {}

    def add(self, name: str, n: int = 1) -> None:
        with self._lock:
            self.values[name] = self.values.get(name, 0) + n

    def snapshot(self) -> dict[str, int]:
        with self._lock:
            return dict(self.values)


class CountingSock:
    """Counts bytes a phase puts on the wire (first pass vs ARQ retry)."""

    def __init__(self, sock: socket.socket, counters: Counters, key: str) -> None:
        self.sock, self.counters, self.key = sock, counters, key

    def sendto(self, data: bytes, dest: tuple[str, int]) -> int:
        n = self.sock.sendto(data, dest)
        self.counters.add(self.key, n)
        return n


class SenderService:
    def __init__(self, cfg: Config) -> None:
        self.cfg = cfg
        self.state = cfg.state_dir
        self.spool = self.state / "spool"
        self.staging = self.state / "staging"
        for d in (self.spool, self.staging):
            d.mkdir(parents=True, exist_ok=True)
        self.ledger = Ledger(self.state / "ledger.db")
        self.counters = Counters()
        self.stop_event = threading.Event()
        self.wake = threading.Event()
        self.uploads = threading.BoundedSemaphore(cfg.max_uploads)
        self.active: set[str] = set()
        self.active_lock = threading.Lock()
        self.threads: list[threading.Thread] = []
        self.pacer = pitcher.Pacer(cfg.max_bitrate_mbps * 1_000_000 / 8.0, cfg.gap_ms / 1000.0)
        self.started = time.time()
        self.server: BoundedServer | None = None
        assert cfg.data_peer is not None
        self.dest = socket.getaddrinfo(cfg.data_peer[0], cfg.data_peer[1], socket.AF_INET, socket.SOCK_DGRAM)[0][4]
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        if cfg.sndbuf:
            self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, cfg.sndbuf)
        else:
            pitcher._configure_send_buf(self.sock, cfg.chunk_size + 256)
        self.rx_store: ReceiptStore | None = None
        self.rx_catcher: Catcher | None = None
        self.rx_sock: socket.socket | None = None
        if cfg.feedback == "receipts":
            self.rx_store = ReceiptStore(self.state / "receipts_in")
            rx_root = self.state / "_rx"
            self.rx_catcher = Catcher(
                rx_root / "out", rx_root / "q", 60.0, None, hmac_secret=cfg.receipt_key,
                work_dir=rx_root / "work",
            )
            self.rx_catcher.receipts = self.rx_store
            self.rx_catcher.status_only = True
            self.rx_catcher.active_ids = self.is_active
            self.rx_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self.rx_sock.bind(cfg.receipt_bind)
            self.rx_sock.settimeout(0.5)
        self._recover()

    # ------------------------------------------------------------ startup

    def _recover(self) -> None:
        for leftover in self.staging.iterdir():
            leftover.unlink(missing_ok=True)  # an upload that never got its 202
        known = self.ledger.known_ids()
        for f in self.spool.iterdir():
            if f.suffix == ".bin" and f.stem not in known:
                f.unlink(missing_ok=True)  # renamed into the spool, never committed: client retries
        resumed = self.ledger.recover()
        for tid in known:
            row = self.ledger.get(tid)
            if row and row["state"] == "queued" and not (self.spool / f"{tid}.bin").is_file():
                self.ledger.set_state(tid, "failed", "source-missing")
        if resumed:
            print(f"recovered {resumed} in-flight transfer(s) to the queue", file=sys.stderr)

    # -------------------------------------------------------------- state

    def is_active(self, tid: str) -> bool:
        with self.active_lock:
            return tid in self.active

    def spool_path(self, tid: str) -> Path:
        return self.spool / f"{tid}.bin"

    def disk_free(self) -> int:
        return shutil.disk_usage(self.spool).free

    def ready(self) -> tuple[bool, list[str]]:
        problems: list[str] = []
        if not os.access(self.spool, os.W_OK):
            problems.append("spool not writable")
        elif self.disk_free() < self.cfg.disk_reserve_bytes:
            problems.append("disk below reserve")
        try:
            self.ledger.summary()
        except sqlite3.Error:
            problems.append("ledger unavailable")
        workers = [t for t in self.threads if t.name.startswith("send-")]
        if len(workers) < self.cfg.send_concurrency or not all(t.is_alive() for t in workers):
            problems.append("sender worker not running")
        if self.cfg.feedback == "receipts":
            rx = [t for t in self.threads if t.name == "receipts"]
            if not rx or not rx[0].is_alive():
                problems.append("receipt listener not running")
        if self.server is None:
            problems.append("http not serving")
        return (not problems, problems)

    def stats(self) -> dict:
        summ = self.ledger.summary()
        by = summ["by_state"]
        oldest = summ["oldest_queued_created"]
        c = self.counters.snapshot()
        out: dict[str, Any] = {
            "mode": "sender",
            "feedback": self.cfg.feedback,
            "uptime_s": round(time.time() - self.started, 1),
            "queue_bytes": by.get("queued", {}).get("bytes", 0) + by.get("sending", {}).get("bytes", 0),
            "queued": by.get("queued", {}).get("count", 0),
            "sending": by.get("sending", {}).get("count", 0),
            "oldest_queued_age_s": None if oldest is None else round(time.time() - oldest, 1),
            "accepted": c.get("accepted", 0),
            "replayed": c.get("replayed", 0),
            "conflicts": c.get("conflicts", 0),
            "rejected": c.get("rejected", 0),
            "verified": by.get("receiver-verified", {}).get("count", 0),
            "sent_unconfirmed": by.get("sent-unconfirmed", {}).get("count", 0),
            "failed": by.get("failed", {}).get("count", 0),
            "expired": by.get("expired", {}).get("count", 0),
            "wire_bytes_first": c.get("wire_bytes_first", 0),
            "retry_bytes": c.get("wire_bytes_retry", 0),
            "spool_unpurged_bytes": self.ledger.unpurged_bytes(),
            "disk_free_bytes": self.disk_free(),
        }
        if self.cfg.feedback == "receipts" and self.rx_catcher is not None:
            out["receipt_frames"] = self.rx_catcher.stats["status_frames"]
            out["receipts_rejected"] = self.rx_catcher.stats["hmac_fail"]
            # repeats of a terminal receipt that arrive after the job finished
            out["receipts_late"] = self.rx_catcher.stats["status_unbound"]
        # Strict mode never learns whether the far side is reachable, so it reports nothing about it.
        return out

    # ------------------------------------------------------------- upload

    def upload(self, h: "SenderHandler") -> tuple[dict, bool]:
        """Stream the request body to staging, then admit it. Returns (row, created)."""
        cfg = self.cfg
        key = h.headers.get("Idempotency-Key", "")
        if not IDEM_RE.fullmatch(key):
            raise HttpError(400, "Idempotency-Key header required (1-128 of A-Za-z0-9._:-)")
        ctype = h.headers.get("Content-Type", "application/octet-stream")
        if len(ctype) > MAX_CONTENT_TYPE_LEN or not ctype.isascii() or not ctype.isprintable():
            ctype = "application/octet-stream"
        length, chunked = h.body_framing(cfg.max_body_bytes)
        self._precheck_space(length)
        if not self.uploads.acquire(blocking=False):
            raise HttpError(503, "too many uploads in progress", {"Retry-After": "1"})
        staged = self.staging / f"{secrets.token_hex(12)}.part"
        try:
            sha = hashlib.sha256()
            size = 0
            next_space_check = 64 * 1024 * 1024
            with staged.open("wb") as out:
                for block in h.iter_body(length, chunked, cfg.max_body_bytes):
                    out.write(block)
                    sha.update(block)
                    size += len(block)
                    if size >= next_space_check:
                        next_space_check += 64 * 1024 * 1024
                        self._precheck_space(None)
                out.flush()
                os.fsync(out.fileno())
            try:
                return self.ledger.admit(key, sha.hexdigest(), size, ctype, staged, self.spool)
            except Conflict:
                self.counters.add("conflicts")
                raise HttpError(409, "Idempotency-Key was already used for different content") from None
        except HttpError:
            self.counters.add("rejected")
            raise
        except (TimeoutError, socket.timeout):
            self.counters.add("rejected")
            raise
        finally:
            staged.unlink(missing_ok=True)  # no-op after a successful rename
            self.uploads.release()

    def _precheck_space(self, incoming: int | None) -> None:
        cfg = self.cfg
        free = self.disk_free()
        if free - (incoming or 0) < cfg.disk_reserve_bytes:
            raise HttpError(507, "insufficient storage (disk reserve)")
        if incoming is not None and self.ledger.unpurged_bytes() + incoming > cfg.spool_quota_bytes:
            raise HttpError(507, "insufficient storage (spool quota)")

    # ------------------------------------------------------------ workers

    def _worker(self) -> None:
        while not self.stop_event.is_set():
            row = self.ledger.claim_next()
            if row is None:
                self.wake.wait(1.0)
                self.wake.clear()
                continue
            try:
                self._run_job(row)
            except Exception as exc:  # noqa: BLE001 - one bad job must not kill the worker
                print(f"job {row['id']} error: {type(exc).__name__}: {exc}", file=sys.stderr)
                self.ledger.set_state(row["id"], "failed", "internal-error")

    def _run_job(self, row: dict) -> None:
        cfg = self.cfg
        tid = row["id"]
        path = self.spool_path(tid)
        try:
            if path.stat().st_size != row["size"]:
                raise OSError("size changed")
            prepared = pitcher.prepare_transfer(
                path, tid, cfg.chunk_size, cfg.parity_group, cfg.data_key, row["content_type"]
            )
        except OSError:
            self.ledger.set_state(tid, "failed", "source-missing")
            return
        if prepared.digest != row["sha256"]:
            self.ledger.set_state(tid, "failed", "source-corrupt")
            return

        first = CountingSock(self.sock, self.counters, "wire_bytes_first")
        retry = CountingSock(self.sock, self.counters, "wire_bytes_retry")

        def do_pass(sock: Any) -> None:
            pitcher.send_pass(
                sock, self.dest, path, prepared,
                chunk_size=cfg.chunk_size, parity_group=cfg.parity_group,
                meta_copies=cfg.meta_copies, eof_copies=cfg.eof_copies,
                pacer=self.pacer, stop=self.stop_event,
            )

        if self.rx_store is not None:
            self.rx_store.delete(tid)  # a receipt from an earlier attempt says nothing about this one
        with self.active_lock:
            self.active.add(tid)
        try:
            for _ in range(cfg.passes):
                do_pass(first)
                if self.stop_event.is_set():
                    break
            if self.stop_event.is_set():
                self.ledger.set_state(tid, "queued")
                return
            if cfg.feedback == "off":
                self.ledger.set_state(tid, "sent-unconfirmed")
                self.counters.add("sent")
                return
            assert self.rx_store is not None
            job = pitcher.ArqJob(
                transfer_id=tid, source=path, chunk_size=cfg.chunk_size,
                meta=prepared.meta, eof=prepared.eof, receipts=self.rx_store,
                timeout_s=cfg.ack_timeout_s, rounds=10**9, backoff=cfg.ack_backoff,
                max_timeout_s=cfg.ack_timeout_cap_s, meta_copies=cfg.meta_copies,
                eof_copies=cfg.eof_copies, pacer=self.pacer, budget_s=cfg.retry_budget_s,
                stop=self.stop_event, repass=lambda: do_pass(retry),
            )
            rc = pitcher.watch_receipts_and_resend(retry, self.dest, job)
            if rc == 0:
                self.ledger.set_state(tid, "receiver-verified")
            elif rc == 2:
                report = self.rx_store.read(tid)
                self.ledger.set_state(tid, "failed", f"receiver-fail:{report.reason if report else 'unknown'}")
            elif rc == 3:
                self.ledger.set_state(tid, "queued")
            else:
                self.ledger.set_state(tid, "expired", "retry-budget")
        finally:
            with self.active_lock:
                self.active.discard(tid)
            if self.rx_store is not None:
                self.rx_store.delete(tid)

    def _receipt_loop(self) -> None:
        assert self.rx_sock is not None and self.rx_catcher is not None
        while not self.stop_event.is_set():
            try:
                data, _ = self.rx_sock.recvfrom(65535)
            except socket.timeout:
                continue
            except OSError:
                return
            self.rx_catcher.handle(data)

    def _housekeeping(self) -> None:
        while not self.stop_event.wait(30.0):
            self.housekeep()

    def housekeep(self) -> None:
        cfg = self.cfg
        now = time.time()
        for tid in self.ledger.purgeable(now, cfg.spool_retention_s, cfg.failed_retention_s):
            self.spool_path(tid).unlink(missing_ok=True)
            self.ledger.mark_purged(tid)
        self.ledger.forget_old(now, cfg.ledger_retention_s)

    # ----------------------------------------------------------- lifecycle

    def start(self) -> None:
        cfg = self.cfg
        for n in range(cfg.send_concurrency):
            t = threading.Thread(target=self._worker, name=f"send-{n}", daemon=True)
            t.start()
            self.threads.append(t)
        if self.rx_sock is not None:
            t = threading.Thread(target=self._receipt_loop, name="receipts", daemon=True)
            t.start()
            self.threads.append(t)
        t = threading.Thread(target=self._housekeeping, name="housekeeping", daemon=True)
        t.start()
        self.threads.append(t)
        ssl_ctx = None
        if cfg.tls_cert_file and cfg.tls_key_file:
            ssl_ctx = make_ssl_context(str(cfg.tls_cert_file), str(cfg.tls_key_file))
        self.server = BoundedServer(
            (cfg.http_bind, cfg.http_port),
            make_handler(SenderHandler, cfg.http_io_timeout_s),
            max_connections=cfg.max_connections,
            header_deadline_s=cfg.header_deadline_s,
            body_deadline_s=cfg.upload_deadline_s,
            ssl_context=ssl_ctx,
        )
        self.server.ctx = self
        self.threads.append(serve_in_thread(self.server, "http"))
        print(
            f"sender up http={cfg.http_bind}:{self.server.server_address[1]} "
            f"peer={cfg.data_peer[0]}:{cfg.data_peer[1]} feedback={cfg.feedback}",  # type: ignore[index]
            file=sys.stderr,
        )

    def stop(self) -> None:
        self.stop_event.set()
        self.wake.set()
        if self.server is not None:
            self.server.shutdown()
            self.server.server_close()
        for t in self.threads:
            t.join(10.0)
        self.sock.close()
        if self.rx_sock is not None:
            self.rx_sock.close()
        self.ledger.close()


class SenderHandler(Handler):
    ctx: SenderService  # type: ignore[assignment]

    def handle_expect_100(self) -> bool:
        # Refuse before the client sends the body.
        try:
            self.require_auth()
            if self.command == "POST" and self.path.rstrip("/") == "/v1/transfers":
                if not IDEM_RE.fullmatch(self.headers.get("Idempotency-Key", "")):
                    raise HttpError(400, "Idempotency-Key header required")
                length, _ = self.body_framing(self.ctx.cfg.max_body_bytes)
                self.ctx._precheck_space(length)
        except HttpError as err:
            self.close_connection = True
            self.send_json(err.status, {"error": err.message}, err.headers)
            return False
        return super().handle_expect_100()

    def route(self) -> None:
        path = self.path.split("?", 1)[0].rstrip("/") or "/"
        if self.command in ("GET", "HEAD"):
            if path == "/healthz":
                return self.send_json(200, {"status": "ok"})
            if path == "/readyz":
                ok, problems = self.ctx.ready()
                return self.send_json(200 if ok else 503, {"ready": ok, "problems": problems})
            self.require_auth()
            if path == "/v1/stats":
                return self.send_json(200, self.ctx.stats())
            m = re.fullmatch(r"/v1/transfers/([0-9a-f]{32})", path)
            if m:
                row = self.ctx.ledger.get(m.group(1))
                if row is None:
                    raise HttpError(404, "unknown transfer")
                return self.send_json(200, self.describe(row))
            raise HttpError(404, "not found")
        if self.command == "POST" and path == "/v1/transfers":
            self.require_auth()
            row, created = self.ctx.upload(self)
            if created:
                self.ctx.counters.add("accepted")
                self.ctx.wake.set()
            else:
                self.ctx.counters.add("replayed")
            body = self.describe(row)
            body["idempotent_replay"] = not created
            return self.send_json(
                202, body,
                {"Location": f"/v1/transfers/{row['id']}", "Idempotent-Replay": str(not created).lower()},
            )
        raise HttpError(405 if path in ("/v1/transfers", "/v1/stats") else 404, "not found")

    def describe(self, row: dict) -> dict:
        state = row["state"]
        return {
            "id": row["id"],
            "state": state,
            "reason": row["reason"],
            "size": row["size"],
            "sha256": row["sha256"],
            "created": row["created"],
            "updated": row["updated"],
            "attempts": row["attempts"],
            # Only a receiver-verified object is known to be in far-side custody.
            "receiver_confirmed": state == "receiver-verified",
            "feedback": self.ctx.cfg.feedback,
        }
