"""High-side service: DIO2 UDP receiver, durable output, HTTP delivery worker.

Custody rules
  * "Verified" means the object is on this side's disk, fsynced, with a commit
    marker. The OK receipt (when feedback is on) is sent only after that.
  * Delivery to the destination is a separate, retried step with a stable
    Idempotency-Key (the transfer id). It can duplicate if a timeout hides an
    accepted request, so the destination should deduplicate on that key.
  * Permanent refusals (4xx other than 408/425/429) are parked, with the payload
    kept, for an operator to retry or remove.
  * Incomplete assemblies live in RAM or scratch space and are dropped on
    restart; the sender resends them from its retained spool.
"""
from __future__ import annotations

import http.client
import json
import random
import re
import shutil
import socket
import sqlite3
import ssl
import sys
import threading
import time
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

import pitcher
from catcher import Catcher, _configure_recv_buf
from diode_config import Config
from diode_http import (
    BoundedServer,
    Handler,
    HttpError,
    make_handler,
    make_ssl_context,
    serve_in_thread,
)
from protocol import valid_transfer_id
from receipts import ReceiptStore

RETRYABLE = {408, 425, 429}


class DeliveryLedger:
    def __init__(self, path: Path) -> None:
        self.lock = threading.RLock()
        self.db = sqlite3.connect(path, check_same_thread=False, isolation_level=None)
        self.db.row_factory = sqlite3.Row
        self.inflight: set[str] = set()
        with self.lock:
            self.db.execute("PRAGMA journal_mode=WAL")
            self.db.execute("PRAGMA synchronous=FULL")
            self.db.execute(
                """CREATE TABLE IF NOT EXISTS deliveries(
                  id TEXT PRIMARY KEY,
                  size INTEGER NOT NULL,
                  sha256 TEXT NOT NULL,
                  state TEXT NOT NULL,
                  attempts INTEGER NOT NULL DEFAULT 0,
                  next_attempt REAL NOT NULL,
                  last_status INTEGER,
                  last_error TEXT,
                  created REAL NOT NULL,
                  updated REAL NOT NULL)"""
            )
            self.db.execute("CREATE INDEX IF NOT EXISTS deliveries_state ON deliveries(state, next_attempt)")

    def close(self) -> None:
        with self.lock:
            self.db.close()

    def get(self, tid: str) -> dict | None:
        with self.lock:
            row = self.db.execute("SELECT * FROM deliveries WHERE id=?", (tid,)).fetchone()
        return dict(row) if row else None

    def insert_pending(self, tid: str, size: int, sha: str) -> None:
        now = time.time()
        with self.lock:
            self.db.execute(
                "INSERT OR IGNORE INTO deliveries(id,size,sha256,state,next_attempt,created,updated)"
                " VALUES(?,?,?,'pending',?,?,?)",
                (tid, size, sha, now, now, now),
            )

    def claim_due(self, now: float) -> dict | None:
        with self.lock:
            rows = self.db.execute(
                "SELECT * FROM deliveries WHERE state='pending' AND next_attempt<=? ORDER BY created LIMIT 16",
                (now,),
            ).fetchall()
            for row in rows:
                if row["id"] not in self.inflight:
                    self.inflight.add(row["id"])
                    return dict(row)
        return None

    def release(self, tid: str) -> None:
        with self.lock:
            self.inflight.discard(tid)

    def finish(self, tid: str, state: str, status: int | None, error: str | None, next_attempt: float | None = None) -> None:
        with self.lock:
            self.db.execute(
                "UPDATE deliveries SET state=?, attempts=attempts+1, last_status=?, last_error=?,"
                " next_attempt=COALESCE(?, next_attempt), updated=? WHERE id=?",
                (state, status, error, next_attempt, time.time(), tid),
            )
            self.inflight.discard(tid)

    def requeue(self, tid: str) -> bool:
        with self.lock:
            cur = self.db.execute(
                "UPDATE deliveries SET state='pending', next_attempt=?, updated=? WHERE id=? AND state='parked'",
                (time.time(), time.time(), tid),
            )
            return cur.rowcount == 1

    def park(self, tid: str, error: str) -> None:
        self.finish(tid, "parked", None, error)

    def all_ids(self) -> set[str]:
        with self.lock:
            return {r[0] for r in self.db.execute("SELECT id FROM deliveries")}

    def delivered_before(self, cutoff: float) -> list[str]:
        with self.lock:
            return [r[0] for r in self.db.execute(
                "SELECT id FROM deliveries WHERE state='delivered' AND updated < ?", (cutoff,))]

    def delete(self, tid: str) -> None:
        with self.lock:
            self.db.execute("DELETE FROM deliveries WHERE id=?", (tid,))

    def summary(self) -> dict:
        with self.lock:
            by = {
                r[0]: {"count": r[1], "bytes": r[2], "attempts": r[3]}
                for r in self.db.execute(
                    "SELECT state, COUNT(*), COALESCE(SUM(size),0), COALESCE(SUM(attempts),0)"
                    " FROM deliveries GROUP BY state"
                )
            }
            oldest = self.db.execute("SELECT MIN(created) FROM deliveries WHERE state='pending'").fetchone()[0]
        return {"by_state": by, "oldest_pending_created": oldest}


class ReceiverService:
    def __init__(self, cfg: Config) -> None:
        self.cfg = cfg
        s = cfg.state_dir
        self.out = s / "out"
        self.stop_event = threading.Event()
        self.wake = threading.Event()
        self.threads: list[threading.Thread] = []
        self.started = time.time()
        self.loop_tick = time.monotonic()
        self.server: BoundedServer | None = None
        self.counters = {"delivered": 0, "delivery_retries": 0, "delivery_parked": 0, "delivery_errors": 0}
        self.counter_lock = threading.Lock()

        self.catcher = Catcher(
            self.out,
            s / "quarantine",
            cfg.ttl_s,
            None,
            hmac_secret=cfg.data_key,
            work_dir=s / "work",
            disk_threshold_bytes=cfg.ram_max_bytes,
            max_transfer_bytes=cfg.max_transfer_bytes,
            max_active=cfg.max_active,
            min_free_bytes=cfg.min_free_bytes,
            holes_window=cfg.holes_window,
            ram_budget_bytes=cfg.ram_budget_bytes,
        )
        self.rcpt_store: ReceiptStore | None = None
        self.rcpt_sock: socket.socket | None = None
        self.emitter: pitcher.ReceiptEmitter | None = None
        if cfg.feedback == "receipts":
            assert cfg.receipt_peer is not None
            self.rcpt_store = ReceiptStore(s / "receipts_out")
            self.catcher.receipts = self.rcpt_store
            self.catcher.receipt_every = cfg.receipt_every
            dest = socket.getaddrinfo(cfg.receipt_peer[0], cfg.receipt_peer[1], socket.AF_INET, socket.SOCK_DGRAM)[0][4]
            # Send-only socket, and only in receipts mode. Feedback off opens none.
            self.rcpt_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self.emitter = pitcher.ReceiptEmitter(
                self.rcpt_store, self.rcpt_sock, dest, hmac_secret=cfg.receipt_key,
                copies=cfg.receipt_copies, repeat_s=cfg.receipt_interval_s,
                retention_s=cfg.receipt_retention_s, prune=True,
            )
        self.ledger = DeliveryLedger(s / "deliveries.db")
        self.catcher.on_published = self._on_published
        self._reconcile()

        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        _configure_recv_buf(self.sock, cfg.chunk_size + 256, want=cfg.rcvbuf)
        self.sock.bind(cfg.data_bind)
        self.sock.settimeout(0.2)

    # ------------------------------------------------------------ recovery

    def _reconcile(self) -> None:
        """Make the delivery ledger agree with what is durably on disk."""
        known = self.ledger.all_ids()
        for marker in self.out.glob("*.meta.json"):
            tid = marker.name[: -len(".meta.json")]
            payload = self.out / f"{tid}.bin"
            row = self.ledger.get(tid) if tid in known else None
            if row is not None and row["state"] == "delivered":
                payload.unlink(missing_ok=True)  # crash between delivery and cleanup
                continue
            if row is None and payload.is_file():
                try:
                    meta = json.loads(marker.read_text())
                    self.ledger.insert_pending(tid, int(meta["total_len"]), str(meta["sha256_actual"]))
                except (OSError, ValueError, KeyError, TypeError):
                    print(f"cannot read marker for {tid}", file=sys.stderr)
        for tid in known:
            row = self.ledger.get(tid)
            if row and row["state"] == "pending" and not (self.out / f"{tid}.bin").is_file():
                self.ledger.park(tid, "payload-missing")

    def _on_published(self, meta: dict) -> None:
        self.ledger.insert_pending(meta["transfer_id"], int(meta["total_len"]), meta["sha256_actual"])
        self.wake.set()

    # ------------------------------------------------------------ delivery

    def _bump(self, name: str) -> None:
        with self.counter_lock:
            self.counters[name] += 1

    def _connection(self) -> tuple[http.client.HTTPConnection, str]:
        cfg = self.cfg
        u = urlsplit(cfg.delivery_url)
        target = (u.path or "/") + (f"?{u.query}" if u.query else "")
        if u.scheme == "https":
            ctx = ssl.create_default_context(cafile=str(cfg.delivery_ca_file) if cfg.delivery_ca_file else None)
            conn: http.client.HTTPConnection = http.client.HTTPSConnection(
                u.hostname, u.port or 443, timeout=cfg.delivery_timeout_s, context=ctx, blocksize=65536
            )
        else:
            conn = http.client.HTTPConnection(
                u.hostname, u.port or 80, timeout=cfg.delivery_timeout_s, blocksize=65536
            )
        return conn, target

    def deliver(self, row: dict) -> None:
        cfg = self.cfg
        tid = row["id"]
        path = self.out / f"{tid}.bin"
        try:
            size = path.stat().st_size
        except OSError:
            self.ledger.park(tid, "payload-missing")
            self._bump("delivery_parked")
            return
        if size != row["size"]:
            self.ledger.park(tid, "payload-size-changed")
            self._bump("delivery_parked")
            return
        headers = {
            "Content-Type": "application/octet-stream",
            "Content-Length": str(size),
            "Idempotency-Key": tid,
            "X-Diode-Transfer-Id": tid,
            "X-Diode-Sha256": row["sha256"],
            "Connection": "close",
        }
        if cfg.delivery_token:
            headers["Authorization"] = "Bearer " + cfg.delivery_token.decode("utf-8", "replace")
        status: int | None = None
        error: str | None = None
        conn, target = self._connection()
        try:
            with path.open("rb") as fh:
                conn.request("POST", target, body=fh, headers=headers)
                resp = conn.getresponse()
                status = resp.status
                resp.read(65536)
        except (OSError, http.client.HTTPException) as exc:
            error = type(exc).__name__
        finally:
            conn.close()
        if status is not None and 200 <= status < 300:
            path.unlink(missing_ok=True)  # the marker stays as the duplicate-suppression tombstone
            self.ledger.finish(tid, "delivered", status, None)
            self._bump("delivered")
            return
        if status is None or status in RETRYABLE or status >= 500:
            attempts = row["attempts"] + 1
            delay = min(cfg.delivery_backoff_max_s, cfg.delivery_backoff_min_s * (2 ** min(attempts - 1, 20)))
            delay *= random.uniform(0.8, 1.2)
            self.ledger.finish(tid, "pending", status, error or f"http-{status}", time.time() + delay)
            self._bump("delivery_retries")
            if status is None:
                self._bump("delivery_errors")
            return
        self.ledger.finish(tid, "parked", status, f"http-{status}")
        self._bump("delivery_parked")
        print(f"delivery parked transfer_id={tid} status={status}", file=sys.stderr)

    def _delivery_loop(self) -> None:
        while not self.stop_event.is_set():
            row = self.ledger.claim_due(time.time())
            if row is None:
                self.wake.wait(0.5)
                self.wake.clear()
                continue
            try:
                self.deliver(row)
            except Exception as exc:  # noqa: BLE001 - one object must not stop delivery
                print(f"delivery error {row['id']}: {type(exc).__name__}: {exc}", file=sys.stderr)
                self.ledger.finish(row["id"], "pending", None, "internal-error", time.time() + 30)
            finally:
                self.ledger.release(row["id"])

    def _emit_loop(self) -> None:
        assert self.emitter is not None
        while not self.stop_event.wait(min(0.1, self.cfg.receipt_interval_s / 2)):
            try:
                self.emitter.poll()
            except OSError as exc:
                print(f"receipt send failed: {exc}", file=sys.stderr)

    def _housekeeping(self) -> None:
        while not self.stop_event.wait(60.0):
            cutoff = time.time() - self.cfg.dedupe_retention_s
            for tid in self.ledger.delivered_before(cutoff):
                (self.out / f"{tid}.meta.json").unlink(missing_ok=True)
                self.catcher.forget_done(tid)
                self.ledger.delete(tid)

    # ----------------------------------------------------------- inspection

    def disk_free(self) -> int:
        return shutil.disk_usage(self.out).free

    def ready(self) -> tuple[bool, list[str]]:
        problems = []
        if time.monotonic() - self.loop_tick > 5.0:
            problems.append("udp receive loop stalled")
        if self.disk_free() < self.cfg.min_free_bytes:
            problems.append("disk below reserve")
        workers = [t for t in self.threads if t.name.startswith("deliver-")]
        if len(workers) < self.cfg.delivery_concurrency or not all(t.is_alive() for t in workers):
            problems.append("delivery worker not running")
        pub = self.catcher._publisher
        if pub is None or not pub.is_alive():
            problems.append("publish worker not running")
        try:
            self.ledger.summary()
        except sqlite3.Error:
            problems.append("ledger unavailable")
        if self.server is None:
            problems.append("http not serving")
        return (not problems, problems)

    def stats(self) -> dict:
        c = self.catcher.stats
        summ = self.ledger.summary()
        by = summ["by_state"]
        oldest = summ["oldest_pending_created"]
        with self.counter_lock:
            counters = dict(self.counters)
        return {
            "mode": "receiver",
            "feedback": self.cfg.feedback,
            "uptime_s": round(time.time() - self.started, 1),
            "datagrams": c["datagrams"],
            "verified": c["published"],
            "bytes_verified": c["bytes_published"],
            "failed": c["quarantined"],
            "fec_recovered": c["fec_recovered"],
            "rejected_frames": c["crc_fail"],
            "meta_rejected": c["meta_rejected"],
            "active_assemblies": len(self.catcher.assemblies),
            "publish_backlog": self.catcher.publish_backlog(),
            "delivery_pending": by.get("pending", {}).get("count", 0),
            "delivery_pending_bytes": by.get("pending", {}).get("bytes", 0),
            "oldest_pending_age_s": None if oldest is None else round(time.time() - oldest, 1),
            "delivery_parked": by.get("parked", {}).get("count", 0),
            "delivered": by.get("delivered", {}).get("count", 0),
            "downstream_failures": counters["delivery_retries"] + counters["delivery_parked"],
            "downstream_retries": counters["delivery_retries"],
            "retry_bytes": None,
            "receipts_written": c["receipts_written"],
            "disk_free_bytes": self.disk_free(),
        }

    # ------------------------------------------------------------ lifecycle

    def start(self) -> None:
        cfg = self.cfg
        self.catcher.start_publisher()
        for n in range(cfg.delivery_concurrency):
            t = threading.Thread(target=self._delivery_loop, name=f"deliver-{n}", daemon=True)
            t.start()
            self.threads.append(t)
        if self.emitter is not None:
            t = threading.Thread(target=self._emit_loop, name="emit", daemon=True)
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
            make_handler(ReceiverHandler, cfg.http_io_timeout_s),
            max_connections=cfg.max_connections,
            header_deadline_s=cfg.header_deadline_s,
            body_deadline_s=cfg.header_deadline_s * 3,
            ssl_context=ssl_ctx,
        )
        self.server.ctx = self
        self.threads.append(serve_in_thread(self.server, "http"))
        print(
            f"receiver up udp={cfg.data_bind[0]}:{cfg.data_bind[1]} http={cfg.http_bind}:{cfg.http_port} "
            f"feedback={cfg.feedback} delivery={cfg.delivery_url}",
            file=sys.stderr,
        )

    def run(self) -> None:
        """The UDP receive loop. Blocks until stop(); nothing here waits on disk or HTTP beyond handle()."""
        sock, catcher = self.sock, self.catcher
        while not self.stop_event.is_set():
            self.loop_tick = time.monotonic()
            catcher.expire()
            try:
                data, _ = sock.recvfrom(65535)
            except socket.timeout:
                continue
            catcher.handle(data)
            sock.settimeout(0.0)  # drain what queued while handling, without waiting
            try:
                while True:
                    try:
                        data, _ = sock.recvfrom(65535)
                    except (BlockingIOError, InterruptedError):
                        break
                    catcher.handle(data)
            finally:
                sock.settimeout(0.2)

    def stop(self) -> None:
        self.stop_event.set()
        self.wake.set()
        if self.server is not None:
            self.server.shutdown()
            self.server.server_close()
        self.catcher.stop_publisher(30.0)
        for t in self.threads:
            t.join(10.0)
        self.sock.close()
        if self.rcpt_sock is not None:
            self.rcpt_sock.close()
        self.ledger.close()


class ReceiverHandler(Handler):
    def route(self) -> None:
        path = self.path.split("?", 1)[0].rstrip("/") or "/"
        svc: ReceiverService = self.ctx
        if self.command in ("GET", "HEAD"):
            if path == "/healthz":
                return self.send_json(200, {"status": "ok"})
            if path == "/readyz":
                ok, problems = svc.ready()
                return self.send_json(200 if ok else 503, {"ready": ok, "problems": problems})
            self.require_auth()
            if path == "/v1/stats":
                return self.send_json(200, svc.stats())
            m = re.fullmatch(r"/v1/deliveries/([A-Za-z0-9_-]{1,64})", path)
            if m:
                row = svc.ledger.get(m.group(1))
                if row is None:
                    raise HttpError(404, "unknown transfer")
                return self.send_json(200, self.describe(row))
            raise HttpError(404, "not found")
        if self.command == "POST":
            self.require_auth()
            m = re.fullmatch(r"/v1/deliveries/([A-Za-z0-9_-]{1,64})/retry", path)
            if m and valid_transfer_id(m.group(1)):
                if not svc.ledger.requeue(m.group(1)):
                    raise HttpError(409, "only a parked delivery can be retried")
                svc.wake.set()
                return self.send_json(202, {"id": m.group(1), "state": "pending"})
        raise HttpError(404, "not found")

    @staticmethod
    def describe(row: dict) -> dict:
        return {
            "id": row["id"],
            "state": row["state"],
            "size": row["size"],
            "sha256": row["sha256"],
            "attempts": row["attempts"],
            "last_status": row["last_status"],
            "last_error": row["last_error"],
            "next_attempt": row["next_attempt"],
            "updated": row["updated"],
        }
