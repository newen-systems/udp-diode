#!/usr/bin/env python3
"""High-side catcher: UDP frames → reassemble → output or quarantine.

Absorbs industry practice (godiode / svenseeberg / UDPcast):
  - single-file seek assembly (multi‑GB without 2× RAM or per-chunk inodes)
  - compact META (chunk_size + last_chunk_len)
  - large SO_RCVBUF
  - stream hash + fsynced atomic .part→final publish
  - fail closed: incomplete/TTL/integrity → quarantine
  - optional META HMAC over every field that shapes reconstruction

Trust model: decode_frame validates every field, so handlers see typed,
bounded values. Nothing publishes without an accepted META, which is
immutable once accepted. EOF only signals "sender finished"; it can never
supply or change length, chunk count or digest.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import mmap
import os
import queue
import shutil
import socket
import sys
import threading
import time
from array import array
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable

from protocol import (
    DEFAULT_CHUNK_SIZE,
    FAIL_REASONS,
    STATUS_FAIL,
    STATUS_HOLES,
    STATUS_OK,
    STATUS_MISSING_CAP,
    FrameType,
    ProtocolError,
    StatusReport,
    decode_frame,
    drop_reason,
    expected_chunk_len,
    frame_key,
    meta_families,
    recover_missing_chunk,
    status_report_from_frame,
    valid_transfer_id,
    verify_meta_hmac,
    verify_status_hmac,
)
from receipts import ReceiptStore

QUARANTINE_PAYLOAD_MAX = 64 * 1024 * 1024
# Prefer pure-RAM assembly below this size. Lab catchers have multi-GB free;
# staying off mmap/disk for ≤512 MiB avoids page-fault writeback that starves
# the UDP receive path (~20% loss observed at 128 MiB with seek/mmap spill).
RAM_MAX_BYTES = 640 * 1024 * 1024
DEFAULT_MAX_TRANSFER_BYTES = 64 * 1024**3
DEFAULT_MAX_ACTIVE = 64
# DATA/PARITY frames buffered for a transfer whose META has not arrived yet.
PREMETA_MAX_FRAMES = 1024
PREMETA_MAX_PARITIES = 64
REJECTED_RECORD_CAP = 1000
_META_KEYS = (
    "transfer_id",
    "total_len",
    "total_chunks",
    "sha256",
    "content_type",
    "chunk_size",
    "last_chunk_len",
    "parity_group",
)


def fsync_dir(path: Path) -> None:
    """Make a rename or create inside ``path`` durable."""
    fd = os.open(path, os.O_RDONLY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def write_json_durable(path: Path, obj: dict) -> None:
    """Atomic, fsynced JSON write: tmp file, fsync, rename, fsync directory."""
    tmp = path.with_name(path.name + ".tmp")
    with tmp.open("w") as fh:
        fh.write(json.dumps(obj, indent=2) + "\n")
        fh.flush()
        os.fsync(fh.fileno())
    os.replace(tmp, path)
    fsync_dir(path.parent)


@dataclass
class Assembly:
    transfer_id: str
    meta: dict | None = None  # accepted META fields (no hmac); immutable once set
    total_len: int | None = None
    total_chunks: int | None = None
    sha256: str | None = None
    chunk_size: int = DEFAULT_CHUNK_SIZE
    last_chunk_len: int = 0
    # (group, stride) per parity family; see protocol.meta_families
    families: list[tuple[int, int]] = field(default_factory=list)
    # RAM path
    chunks: dict[int, bytes] | None = field(default_factory=dict)
    # Disk path: one mmap'd file + presence bitmap (avoids seek-per-packet)
    work_dir: Path | None = None
    data_path: Path | None = None
    present: array | None = None  # 'B' 0/1 per seq
    have: int = 0
    # keyed by (seq_start, seq_end, stride)
    parities: dict[tuple[int, int], dict] = field(default_factory=dict)
    first_seen: float = field(default_factory=time.time)
    last_seen: float = field(default_factory=time.time)
    complete: bool = False
    failed: bool = False
    disk: bool = False
    data_fh: object | None = None
    mm: mmap.mmap | None = None
    first_hole: int = 0  # holes only fill, so the scan cursor never moves back

    def has_seq(self, seq: int) -> bool:
        if self.disk and self.present is not None:
            return bool(self.present[seq])
        assert self.chunks is not None
        return seq in self.chunks

    def get_seq(self, seq: int) -> bytes | None:
        if self.disk:
            if self.present is None or not self.present[seq]:
                return None
            assert self.mm is not None and self.total_chunks is not None
            ln = expected_chunk_len(
                self.chunk_size, self.last_chunk_len, int(self.total_chunks), seq
            )
            off = seq * self.chunk_size
            return bytes(self.mm[off : off + ln])
        assert self.chunks is not None
        return self.chunks.get(seq)

    def put_seq(self, seq: int, body: bytes) -> None:
        if self.disk:
            assert self.mm is not None and self.present is not None
            if self.present[seq]:
                return
            off = seq * self.chunk_size
            end = off + len(body)
            self.mm[off:end] = body
            # pad remainder of fixed slot so stream-hash reads are length-correct
            if len(body) < self.chunk_size:
                pad = self.chunk_size - len(body)
                self.mm[end : end + pad] = b"\x00" * pad
            self.present[seq] = 1
            self.have += 1
            return
        assert self.chunks is not None
        if seq not in self.chunks:
            self.have += 1
        self.chunks[seq] = body

    def seq_count(self) -> int:
        return self.have

    def missing_prefix(self, cap: int = STATUS_MISSING_CAP) -> list[int]:
        if self.total_chunks is None:
            return []
        total = int(self.total_chunks)
        while self.first_hole < total and self.has_seq(self.first_hole):
            self.first_hole += 1
        out: list[int] = []
        for i in range(self.first_hole, total):
            if not self.has_seq(i):
                out.append(i)
                if len(out) >= cap:
                    break
        return out

    def enable_disk(self, base: Path) -> None:
        if self.disk:
            return
        if self.total_chunks is None or self.total_chunks <= 0:
            return
        self.work_dir = base / self.transfer_id
        self.work_dir.mkdir(parents=True, exist_ok=True)
        self.data_path = self.work_dir / "slots.bin"
        n = int(self.total_chunks)
        slot_bytes = n * self.chunk_size
        # Pre-size + mmap: random put/get without per-packet lseek syscalls.
        self.data_fh = open(self.data_path, "w+b")  # noqa: SIM115
        self.data_fh.truncate(slot_bytes)
        self.data_fh.flush()
        self.mm = mmap.mmap(self.data_fh.fileno(), slot_bytes)
        self.present = array("B", [0]) * n
        # migrate RAM chunks
        if self.chunks:
            for seq, body in self.chunks.items():
                off = seq * self.chunk_size
                self.mm[off : off + len(body)] = body
                if len(body) < self.chunk_size:
                    pad = self.chunk_size - len(body)
                    self.mm[off + len(body) : off + len(body) + pad] = b"\x00" * pad
                self.present[seq] = 1
            self.have = sum(self.present)
        self.chunks = None
        self.disk = True

    def close(self) -> None:
        if self.mm is not None:
            try:
                self.mm.flush()
                self.mm.close()
            except (OSError, BufferError, ValueError):
                pass
            self.mm = None
        if self.data_fh is not None:
            try:
                self.data_fh.close()
            except OSError:
                pass
            self.data_fh = None


class Catcher:
    def __init__(
        self,
        out_dir: Path,
        quarantine_dir: Path,
        ttl_s: float,
        idle_exit_s: float | None,
        hmac_secret: bytes | None = None,
        work_dir: Path | None = None,
        disk_threshold_bytes: int = RAM_MAX_BYTES,
        max_transfer_bytes: int = DEFAULT_MAX_TRANSFER_BYTES,
        max_active: int = DEFAULT_MAX_ACTIVE,
        min_free_bytes: int = 0,
        holes_window: int = STATUS_MISSING_CAP,
        ram_budget_bytes: int | None = None,
        frame_key: bytes | None = None,
        require_frame_auth: bool = False,
    ) -> None:
        self.out_dir = out_dir
        # Per-frame auth (protocol.frame_key). Required: untagged frames are dropped too.
        self.frame_key = frame_key
        self.require_frame_auth = require_frame_auth
        self.quarantine_dir = quarantine_dir
        self.ttl_s = ttl_s
        self.idle_exit_s = idle_exit_s
        self.hmac_secret = hmac_secret
        self.work_dir = work_dir or (out_dir.parent / "diode_work")
        self.disk_threshold_bytes = disk_threshold_bytes
        self.max_transfer_bytes = max_transfer_bytes
        self.max_active = max_active
        self.min_free_bytes = min_free_bytes
        self.holes_window = holes_window
        # Total bytes all in-RAM assemblies may claim; past it a new one goes to disk.
        self.ram_budget_bytes = ram_budget_bytes
        self.assemblies: dict[str, Assembly] = {}
        self.done_ids: set[str] = set()
        self.stats = {
            "datagrams": 0,
            "data_frames": 0,
            "parity_frames": 0,
            "meta_frames": 0,
            "eof_frames": 0,
            "crc_fail": 0,
            "legacy_peer": 0,
            "hmac_fail": 0,
            "meta_rejected": 0,
            "meta_conflict": 0,
            "eof_conflict": 0,
            "data_rejected": 0,
            "parity_rejected": 0,
            "premeta_dropped": 0,
            "dropped_capacity": 0,
            "published": 0,
            "quarantined": 0,
            "duplicates": 0,
            "fec_recovered": 0,
            "bytes_published": 0,
            "last_transfer_id": "",
            "last_duration_s": 0.0,
            "receipts_written": 0,
            "receipts_refreshed": 0,
            "status_frames": 0,
            "status_ignored": 0,
            "status_unbound": 0,
            "status_stale": 0,
            "status_dup": 0,
            "heartbeats": 0,
            "heartbeats_missed": 0,
            "heartbeat_replays": 0,
        }
        # Every datagram refused at decode, by reason (crc, auth, length, schema, ...).
        self.drops: dict[str, int] = {}
        self.heartbeat_sender = ""
        self.heartbeat_seq = -1
        self.heartbeat_at: float | None = None  # time.monotonic() of the last good heartbeat
        self.out_dir.mkdir(parents=True, exist_ok=True)
        self.quarantine_dir.mkdir(parents=True, exist_ok=True)
        self.work_dir.mkdir(parents=True, exist_ok=True)
        # Recv-only: receipts are local files. Never send UDP from this process.
        self.receipts: ReceiptStore | None = None
        self.status_only = False
        self.receipt_every = 50
        self._data_since_receipt = 0
        # status_only: accept receipts only for transfers this predicate knows.
        self.active_ids: Callable[[str], bool] | None = None
        # Called with the committed meta dict after a transfer is durable, before the OK receipt.
        self.on_published: Callable[[dict], None] | None = None
        self._nudge_at: dict[str, float] = {}
        # Optional: hash/fsync/publish on a worker thread so a large object does
        # not stall the UDP receive loop (see start_publisher).
        self._publish_q: queue.Queue | None = None
        self._publisher: threading.Thread | None = None
        self._recover()

    # ------------------------------------------------------------ recovery

    def _recover(self) -> None:
        """Rebuild completion state from disk and drop half-finished artefacts."""
        for part in self.out_dir.glob("*.bin.part"):
            part.unlink(missing_ok=True)
        for tmp in self.out_dir.glob("*.meta.json.tmp"):
            stem = tmp.name[: -len(".meta.json.tmp")]
            if valid_transfer_id(stem) and (self.out_dir / f"{stem}.bin").is_file():
                # Crash between the payload rename and the marker rename: the
                # payload was verified before it was renamed, so commit the marker.
                os.replace(tmp, self.out_dir / f"{stem}.meta.json")
                fsync_dir(self.out_dir)
            else:
                tmp.unlink(missing_ok=True)
        for marker in self.out_dir.glob("*.meta.json"):
            stem = marker.name[: -len(".meta.json")]
            if valid_transfer_id(stem):
                self.done_ids.add(stem)
        for qdir in self.quarantine_dir.iterdir():
            if qdir.is_dir() and valid_transfer_id(qdir.name) and (qdir / "meta.json").is_file():
                self.done_ids.add(qdir.name)
        # Partial assemblies lived in RAM or this scratch space; the sender
        # (or an operator) resends them from retained low-side source.
        for child in self.work_dir.iterdir():
            if child.is_dir():
                shutil.rmtree(child, ignore_errors=True)

    def forget_done(self, transfer_id: str) -> None:
        """Drop one completion marker after its retention window has passed."""
        self.done_ids.discard(transfer_id)

    # ------------------------------------------------------------- helpers

    def _asm(self, tid: str) -> Assembly | None:
        asm = self.assemblies.get(tid)
        if asm is None:
            if len(self.assemblies) >= self.max_active:
                self.stats["dropped_capacity"] += 1
                return None
            asm = Assembly(transfer_id=tid)
            self.assemblies[tid] = asm
        return asm

    def _maybe_spill(self, asm: Assembly) -> None:
        if asm.disk or asm.total_len is None or asm.total_chunks is None:
            return
        if asm.total_len >= self.disk_threshold_bytes or (
            self.ram_budget_bytes is not None
            and self._ram_resident(asm) + asm.total_len > self.ram_budget_bytes
        ):
            asm.enable_disk(self.work_dir)

    def _ram_resident(self, skip: Assembly) -> int:
        return sum(
            a.total_len or 0 for a in self.assemblies.values() if a is not skip and not a.disk
        )

    def _finish(self, asm: Assembly) -> None:
        self.assemblies.pop(asm.transfer_id, None)

    # --------------------------------------------------------------- input

    def handle(self, data: bytes) -> None:
        """Process one datagram. A bug or I/O error costs that datagram, never the daemon."""
        try:
            self._handle(data)
        except Exception as exc:  # noqa: BLE001 - keep serving valid transfers
            self.stats["handler_errors"] = self.stats.get("handler_errors", 0) + 1
            if self.stats["handler_errors"] <= 5:
                print(f"handler error: {type(exc).__name__}: {exc}", file=sys.stderr)

    def _handle(self, data: bytes) -> None:
        self.stats["datagrams"] += 1
        try:
            frame = decode_frame(data, self.frame_key, self.require_frame_auth)
        except ProtocolError as exc:
            self.stats["crc_fail"] += 1  # every decode refusal; ``drops`` has the breakdown
            reason = drop_reason(exc)
            self.drops[reason] = self.drops.get(reason, 0) + 1
            if reason == "legacy":
                self.stats["legacy_peer"] += 1
            if self.stats["crc_fail"] <= 5 or self.stats["crc_fail"] % 500 == 0:
                print(f"drop: {exc}", file=sys.stderr)
            return

        if frame.type is FrameType.HEARTBEAT:
            if not self.status_only:
                self._on_heartbeat(frame.header)
            return
        if self.status_only:
            if frame.type is not FrameType.STATUS:
                self.stats["status_ignored"] += 1
                return
            self._handle_status_frame(frame)
            return
        if frame.type is FrameType.STATUS:
            self.stats["status_ignored"] += 1
            return
        tid = frame.header["transfer_id"]
        if tid in self.done_ids:
            self.stats["duplicates"] += 1
            if frame.type in (FrameType.META, FrameType.EOF):
                self._answer_nudge(tid)
            return

        if frame.type is FrameType.META:
            self._on_meta(tid, frame)
            return
        asm = self._asm(tid)
        if asm is None or asm.failed:
            return
        asm.last_seen = time.time()

        if frame.type is FrameType.EOF:
            self.stats["eof_frames"] += 1
            h = frame.header
            if asm.meta is not None and (
                h["total_chunks"] != asm.total_chunks
                or h["sha256"] != asm.sha256
                or h["total_len"] != asm.total_len
            ):
                self.stats["eof_conflict"] += 1
                return
        elif frame.type is FrameType.DATA:
            self.stats["data_frames"] += 1
            seq = frame.header["seq"]
            if asm.meta is None:
                if len(asm.chunks or ()) >= PREMETA_MAX_FRAMES:
                    self.stats["premeta_dropped"] += 1
                    return
            elif seq >= asm.total_chunks or len(frame.body) != expected_chunk_len(
                asm.chunk_size, asm.last_chunk_len, asm.total_chunks, seq
            ):
                self.stats["data_rejected"] += 1
                return
            if not asm.has_seq(seq):
                asm.put_seq(seq, frame.body)
                self._note_data_receipt(asm)
            else:
                self.stats["duplicates"] += 1
        elif frame.type is FrameType.PARITY:
            self.stats["parity_frames"] += 1
            start, end = frame.header["seq_start"], frame.header["seq_end"]
            if asm.meta is None:
                if len(asm.parities) >= PREMETA_MAX_PARITIES:
                    self.stats["premeta_dropped"] += 1
                    return
            elif not self._parity_ok(asm, start, end, len(frame.body), frame.header.get("stride", 1)):
                self.stats["parity_rejected"] += 1
                return
            stride = frame.header.get("stride", 1)
            key = (start, end, stride)
            asm.parities[key] = {
                "group_seqs": list(range(start, end + 1, stride)),
                "body": frame.body,
            }
            if asm.meta is not None:
                self._try_fec_group(asm, key)

        # FEC is intentional off the DATA hot path: every DATA used to scan
        # parity keys and often re-read group members — that starved recv and
        # caused multi‑% kernel drops on ≥128 MiB dual-pass transfers.
        # PARITY frames still try recovery; EOF / expire do a full sweep.
        if frame.type == FrameType.EOF and asm.parities and asm.meta is not None:
            for key in list(asm.parities.keys()):
                self._try_fec_group(asm, key)

        self._try_complete(asm)
        if (
            frame.type == FrameType.EOF
            and not asm.complete
            and not asm.failed
        ):
            self._write_receipt(asm, STATUS_HOLES)

    # ---------------------------------------------------------------- META

    @staticmethod
    def _group_key(asm: Assembly, group: int, stride: int, seq: int) -> tuple[int, int, int]:
        """Key of the one group in family (group, stride) that holds ``seq``."""
        total = asm.total_chunks or 0
        block = group * stride
        base = seq - seq % block
        start = base + (seq - base) % stride
        last = start + (group - 1) * stride
        while last >= min(base + block, total):
            last -= stride
        return (start, last, stride)

    @classmethod
    def _parity_ok(cls, asm: Assembly, start: int, end: int, body_len: int, stride: int = 1) -> bool:
        """The group must be exactly one that META's geometry defines (see protocol.parity_groups)."""
        group = {st: g for g, st in asm.families}.get(stride)
        total = asm.total_chunks or 0
        if group is None or end >= total or body_len > asm.chunk_size:
            return False
        return cls._group_key(asm, group, stride, start) == (start, end, stride)

    def _on_meta(self, tid: str, frame) -> None:
        self.stats["meta_frames"] += 1
        h = frame.header
        if self.hmac_secret is not None and not verify_meta_hmac(self.hmac_secret, h):
            # Dropped, not terminal: an attacker who can see the transfer id
            # must not be able to burn it with a forged META.
            self.stats["hmac_fail"] += 1
            self.stats["meta_rejected"] += 1
            self.stats["quarantined"] += 1
            print(f"drop: meta hmac fail transfer_id={tid}", file=sys.stderr)
            self._record_rejected(tid, h, "hmac")
            return
        fields = {k: h[k] for k in _META_KEYS}
        fields["parity_families"] = h.get("parity_families")
        asm = self._asm(tid)
        if asm is None or asm.failed:
            return
        asm.last_seen = time.time()
        if asm.meta is not None:
            if asm.meta != fields:
                self.stats["meta_conflict"] += 1
            return  # identical repeat or conflicting repeat: the first META stands
        asm.meta = fields
        asm.total_len = fields["total_len"]
        asm.total_chunks = fields["total_chunks"]
        asm.sha256 = fields["sha256"]
        asm.chunk_size = fields["chunk_size"]
        asm.last_chunk_len = fields["last_chunk_len"]
        asm.families = meta_families(h)
        if not self._admit(asm):
            return
        self._adopt_premeta(asm)
        self._maybe_spill(asm)
        for key in list(asm.parities):
            self._try_fec_group(asm, key)
        self._try_complete(asm)

    def _admit(self, asm: Assembly) -> bool:
        """Policy limits. A refusal is a FAIL receipt, not a terminal state, so a retry can succeed."""
        assert asm.total_len is not None
        reason = None
        if asm.total_len > self.max_transfer_bytes:
            reason = "limit"
        elif self.min_free_bytes:
            free = shutil.disk_usage(self.out_dir).free
            if free - asm.total_len < self.min_free_bytes:
                reason = "limit"
        if reason is None:
            return True
        asm.failed = True
        print(f"refuse: transfer_id={asm.transfer_id} reason={reason}", file=sys.stderr)
        self._write_receipt(asm, STATUS_FAIL, reason)
        return False

    def _adopt_premeta(self, asm: Assembly) -> None:
        """Keep only pre-META frames that fit the geometry META just declared."""
        assert asm.total_chunks is not None
        if asm.chunks:
            for seq, body in list(asm.chunks.items()):
                if seq >= asm.total_chunks or len(body) != expected_chunk_len(
                    asm.chunk_size, asm.last_chunk_len, asm.total_chunks, seq
                ):
                    del asm.chunks[seq]
                    self.stats["data_rejected"] += 1
            asm.have = len(asm.chunks)
        for key, entry in list(asm.parities.items()):
            if not self._parity_ok(asm, key[0], key[1], len(entry["body"]), key[2]):
                del asm.parities[key]
                self.stats["parity_rejected"] += 1

    def _on_heartbeat(self, h: dict) -> None:
        """Link liveness. Counts gaps in the sender's sequence as missed heartbeats.

        A new sender id (sender restart) resets the sequence. With frame auth
        required, a replayed or old heartbeat is counted and ignored.
        """
        sender, seq = h["sender"], h["seq"]
        if sender == self.heartbeat_sender:
            if seq <= self.heartbeat_seq:
                self.stats["heartbeat_replays"] += 1
                return
            self.stats["heartbeats_missed"] += seq - self.heartbeat_seq - 1
        self.heartbeat_sender = sender
        self.heartbeat_seq = seq
        self.heartbeat_at = time.monotonic()
        self.stats["heartbeats"] += 1

    def _record_rejected(self, tid: str, header: dict, reason: str) -> None:
        rdir = self.quarantine_dir / "_rejected"
        try:
            rdir.mkdir(exist_ok=True)
            if sum(1 for _ in rdir.iterdir()) >= REJECTED_RECORD_CAP:
                return
            rec = {"transfer_id": tid, "reason": reason, "sha256_claimed": header.get("sha256")}
            (rdir / f"{time.time_ns()}-{tid}.json").write_text(json.dumps(rec) + "\n")
        except OSError:
            pass

    # ------------------------------------------------------------- receipts

    def _answer_nudge(self, tid: str) -> None:
        """A sender is still talking about a finished transfer: its receipt was lost."""
        if self.receipts is None:
            return
        now = time.monotonic()
        if now - self._nudge_at.get(tid, 0.0) < 0.5:
            return
        if len(self._nudge_at) > 10_000:
            self._nudge_at.clear()
        self._nudge_at[tid] = now
        if self.receipts.touch(tid):
            self.stats["receipts_refreshed"] += 1
            return
        # The receipt aged out; rebuild it from the durable terminal marker.
        try:
            marker = json.loads((self.out_dir / f"{tid}.meta.json").read_text())
            report = StatusReport(tid, STATUS_OK, have=marker["chunks"], total_chunks=marker["chunks"])
        except (OSError, ValueError, KeyError, TypeError):
            try:
                q = json.loads((self.quarantine_dir / tid / "meta.json").read_text())
                reason = q.get("reason")
                report = StatusReport(
                    tid, STATUS_FAIL, have=0,
                    reason=reason if reason in FAIL_REASONS else "io",
                )
            except (OSError, ValueError, TypeError):
                return
        try:
            self.receipts.write(report)
        except ValueError:
            return
        self.stats["receipts_written"] += 1

    def _handle_status_frame(self, frame) -> None:
        """Validate-track catcher: STATUS frames become local receipts only."""
        try:
            report = status_report_from_frame(frame)
        except ProtocolError as exc:
            self.stats["crc_fail"] += 1
            print(f"drop status: {exc}", file=sys.stderr)
            return
        self.stats["status_frames"] += 1
        if self.hmac_secret is not None:
            provided = str(frame.header.get("hmac", ""))
            if not verify_status_hmac(self.hmac_secret, report, provided):
                self.stats["hmac_fail"] += 1
                print(
                    f"drop: status hmac fail transfer_id={report.transfer_id}",
                    file=sys.stderr,
                )
                return
        if self.active_ids is not None and not self.active_ids(report.transfer_id):
            self.stats["status_unbound"] += 1
            return
        if self.receipts is None:
            return
        current = self.receipts.read(report.transfer_id)
        if current is not None:
            if current == report:
                self.stats["status_dup"] += 1
                return
            if current.kind != STATUS_HOLES:
                # Terminal receipts are sticky: replays and late HOLES change nothing.
                self.stats["status_stale"] += 1
                return
        self.receipts.write(report)
        self.stats["receipts_written"] += 1

    def _note_data_receipt(self, asm: Assembly) -> None:
        if self.receipts is None or asm.total_chunks is None:
            return
        self._data_since_receipt += 1
        if self.receipt_every <= 0 or self._data_since_receipt < self.receipt_every:
            return
        self._data_since_receipt = 0
        self._write_receipt(asm, STATUS_HOLES)

    def _write_receipt(self, asm: Assembly, kind: str, reason: str | None = None) -> None:
        if self.receipts is None:
            return
        missing = (
            tuple(asm.missing_prefix(self.holes_window)) if kind == STATUS_HOLES else ()
        )
        if kind == STATUS_HOLES and asm.total_chunks is not None and not missing:
            return
        report = StatusReport(
            transfer_id=asm.transfer_id,
            kind=kind,
            # work state is released before the OK receipt, so OK states the count outright
            have=asm.total_chunks if kind == STATUS_OK else asm.seq_count(),
            total_chunks=asm.total_chunks,
            missing=missing,
            reason=reason if kind == STATUS_FAIL else None,
        )
        self.receipts.write(report)
        self.stats["receipts_written"] += 1

    # ----------------------------------------------------------------- FEC

    def _lens_map(self, asm: Assembly, group: list[int]) -> dict[int, int]:
        out: dict[int, int] = {}
        if asm.total_chunks is None:
            return out
        for s in group:
            out[s] = expected_chunk_len(
                asm.chunk_size, asm.last_chunk_len, int(asm.total_chunks), s
            )
        return out

    def _try_fec_group(self, asm: Assembly, key: tuple[int, int, int]) -> None:
        """XOR-recover the one missing member of a group, then follow the repair.

        A recovered chunk can leave a group of another family with one missing
        member, so those groups are tried next (peeling decoder). Each step
        repairs a chunk, so the work is bounded by the number of holes.
        """
        work = [key]
        while work:
            miss = self._repair_one(asm, work.pop())
            if miss is not None:
                for g, st in asm.families:
                    nxt = self._group_key(asm, g, st, miss)
                    if nxt in asm.parities:
                        work.append(nxt)

    def _repair_one(self, asm: Assembly, key: tuple[int, int, int]) -> int | None:
        if asm.total_chunks is None or key not in asm.parities:
            return None
        entry = asm.parities[key]
        group = entry["group_seqs"]
        missing = [s for s in group if not asm.has_seq(s)]
        if len(missing) != 1:
            return None
        miss = missing[0]
        mem: dict[int, bytes] = {}
        for s in group:
            if s == miss:
                continue
            body = asm.get_seq(s)
            if body is None:
                return None
            mem[s] = body
        lens = self._lens_map(asm, group)
        if miss not in lens:
            return None
        try:
            body = recover_missing_chunk(mem, miss, entry["body"], group, lens)
        except ValueError:
            return None
        asm.put_seq(miss, body)
        self.stats["fec_recovered"] += 1
        if self.stats["fec_recovered"] <= 3 or self.stats["fec_recovered"] % 500 == 0:
            print(
                f"FEC recovered seq={miss} total_fec={self.stats['fec_recovered']}",
                file=sys.stderr,
            )
        return miss

    # ------------------------------------------------------------- publish

    def _stream_hash_and_publish(self, asm: Assembly) -> None:
        """Verify, then make the object durable before anything is acknowledged.

        Order: write + fsync .part, write + fsync marker tmp, rename .part to
        final, fsync directory, rename marker into place, fsync directory. The
        marker rename is the commit point; a crash before it leaves only
        artefacts that _recover() removes or completes.
        """
        assert asm.total_chunks is not None
        assert asm.total_len is not None
        assert asm.sha256 is not None
        tid = asm.transfer_id
        h = hashlib.sha256()
        total = 0
        final = self.out_dir / f"{tid}.bin"
        part = self.out_dir / f"{tid}.bin.part"
        marker = self.out_dir / f"{tid}.meta.json"
        with part.open("wb") as out:
            for i in range(asm.total_chunks):
                body = asm.get_seq(i)
                if body is None:
                    raise RuntimeError(f"missing seq {i}")
                out.write(body)
                h.update(body)
                total += len(body)
            out.flush()
            os.fsync(out.fileno())
        digest = h.hexdigest()
        meta = {
            "transfer_id": tid,
            "total_len": asm.total_len,
            "sha256_expected": asm.sha256,
            "sha256_actual": digest,
            "chunks": asm.total_chunks,
            "fec_recovered": self.stats["fec_recovered"],
            "disk": asm.disk,
        }
        if total != asm.total_len or digest != asm.sha256:
            part.unlink(missing_ok=True)
            self._quarantine(asm, meta, reason="integrity", payload=b"")
            asm.failed = True
            self.done_ids.add(tid)
            self._finish(asm)
            return
        marker_tmp = marker.with_name(marker.name + ".tmp")
        with marker_tmp.open("w") as fh:
            fh.write(json.dumps(meta, indent=2) + "\n")
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(part, final)
        fsync_dir(self.out_dir)
        os.replace(marker_tmp, marker)
        fsync_dir(self.out_dir)
        self._cleanup_work(asm)
        asm.complete = True
        self.done_ids.add(tid)
        self._finish(asm)
        self.stats["published"] += 1
        self.stats["bytes_published"] += int(total)
        self.stats["last_transfer_id"] = tid
        self.stats["last_duration_s"] = round(time.time() - asm.first_seen, 3)
        if self.on_published is not None:
            try:
                self.on_published(meta)
            except Exception as exc:  # noqa: BLE001 - custody hook must not kill the receive loop
                print(f"on_published failed for {tid}: {exc}", file=sys.stderr)
        self._write_receipt(asm, STATUS_OK)
        print(f"PUBLISHED {tid} bytes={total} sha256={digest}")
        try:
            (self.out_dir / f"{tid}.stats.json").write_text(
                json.dumps(self.stats, indent=2) + "\n"
            )
        except OSError:
            pass

    def start_publisher(self) -> None:
        """Run verify + publish on a worker thread; the receive loop only hands off."""
        if self._publisher is not None:
            return
        self._publish_q = queue.Queue()
        self._publisher = threading.Thread(target=self._publish_loop, name="publisher", daemon=True)
        self._publisher.start()

    def stop_publisher(self, timeout: float = 30.0) -> None:
        if self._publisher is None or self._publish_q is None:
            return
        self._publish_q.put(None)
        self._publisher.join(timeout)
        self._publisher = None

    def publish_backlog(self) -> int:
        return self._publish_q.qsize() if self._publish_q is not None else 0

    def _publish_loop(self) -> None:
        assert self._publish_q is not None
        while True:
            asm = self._publish_q.get()
            if asm is None:
                return
            try:
                self._publish(asm)
            except Exception as exc:  # noqa: BLE001 - the worker must survive one bad object
                print(f"publish worker error for {asm.transfer_id}: {exc}", file=sys.stderr)

    def _try_complete(self, asm: Assembly) -> None:
        if asm.complete or asm.failed:
            return
        if asm.meta is None or asm.total_chunks is None or asm.sha256 is None:
            return
        if asm.seq_count() < asm.total_chunks:
            return
        if self._publish_q is None:
            self._publish(asm)
            return
        # Claim the id so repeats are duplicates while the worker finishes it.
        self.done_ids.add(asm.transfer_id)
        self._finish(asm)
        asm.complete = False
        self._publish_q.put(asm)

    def _publish(self, asm: Assembly) -> None:
        try:
            self._stream_hash_and_publish(asm)
        except OSError as exc:
            print(f"publish error: {exc}", file=sys.stderr)
            for leftover in (
                self.out_dir / f"{asm.transfer_id}.bin.part",
                self.out_dir / f"{asm.transfer_id}.meta.json.tmp",
            ):
                leftover.unlink(missing_ok=True)
            if not (self.out_dir / f"{asm.transfer_id}.meta.json").exists():
                # Payload renamed but never committed: do not leave an unowned object.
                (self.out_dir / f"{asm.transfer_id}.bin").unlink(missing_ok=True)
            self._quarantine(
                asm,
                {"transfer_id": asm.transfer_id, "error": str(exc)},
                reason="io",
                payload=b"",
            )
            asm.failed = True
            self.done_ids.add(asm.transfer_id)
            self._finish(asm)

    def _cleanup_work(self, asm: Assembly) -> None:
        asm.close()
        if asm.work_dir and asm.work_dir.is_dir():
            shutil.rmtree(asm.work_dir, ignore_errors=True)
        asm.chunks = {}
        asm.parities.clear()
        asm.present = None
        asm.have = 0

    def _quarantine(
        self,
        asm: Assembly,
        meta: dict,
        reason: str,
        payload: bytes | None = None,
    ) -> None:
        meta = {**meta, "reason": reason, "chunks_have": asm.seq_count()}
        qdir = self.quarantine_dir / asm.transfer_id
        try:
            qdir.mkdir(parents=True, exist_ok=True)
            if payload is not None and len(payload) <= QUARANTINE_PAYLOAD_MAX:
                (qdir / "payload.bin").write_bytes(payload)
            write_json_durable(qdir / "meta.json", meta)
        except OSError as exc:
            # The in-memory terminal state still holds; only restart dedupe is weaker.
            print(f"quarantine record failed for {asm.transfer_id}: {exc}", file=sys.stderr)
        fail_reason = reason if reason in FAIL_REASONS else "io"
        self._write_receipt(asm, STATUS_FAIL, fail_reason)
        self._cleanup_work(asm)
        self.stats["quarantined"] += 1
        print(f"QUARANTINE {asm.transfer_id} reason={reason}", file=sys.stderr)

    def expire(self, force: bool = False) -> None:
        now = time.time()
        for tid, asm in list(self.assemblies.items()):
            if asm.complete or tid in self.done_ids:
                self.assemblies.pop(tid, None)
                continue
            if not force and now - asm.last_seen < self.ttl_s:
                continue
            if asm.failed or asm.meta is None:
                # Refused by policy, or never authenticated by a META: nothing
                # worth a quarantine record. Free the slot.
                asm.close()
                self.assemblies.pop(tid, None)
                continue
            # Last-chance FEC before fail (covers idle-timeout / graceful shutdown)
            if asm.parities and asm.total_chunks is not None:
                for key in list(asm.parities.keys()):
                    self._try_fec_group(asm, key)
                self._try_complete(asm)
                if asm.complete or asm.failed:
                    continue
            reason = "shutdown_incomplete" if force else "ttl"
            meta = {
                "transfer_id": tid,
                "total_len": asm.total_len,
                "total_chunks": asm.total_chunks,
                "sha256_expected": asm.sha256,
                "chunks_have_count": asm.seq_count(),
                "reason": reason,
            }
            self._quarantine(asm, meta, reason=reason, payload=b"")
            asm.failed = True
            self.done_ids.add(tid)
            self._finish(asm)


def _configure_recv_buf(sock: socket.socket, packet_size: int, want: int = 0) -> int:
    """Ask for a large receive buffer and say so loudly when the kernel grants less.

    Returns the size the kernel reports. Linux reports double what it granted
    and caps the request at net.core.rmem_max, so a reported value below the
    request means the cap won: raise rmem_max to at least the requested size.
    Sizing: the buffer must absorb the longest receiver stall at line rate,
    e.g. 100 Mbit/s x 250 ms = 3.1 MB; 32 MiB covers about 2.7 s at 100 Mbit/s.
    """
    if want <= 0:
        want = max(32 * 1024 * 1024, 2000 * packet_size)
    try:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, want)
    except OSError as exc:
        print(f"warn: SO_RCVBUF={want} failed: {exc}", file=sys.stderr)
    actual = sock.getsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF)
    print(f"SO_RCVBUF want={want} actual={actual}", file=sys.stderr)
    if actual < want:
        print(
            f"warn: kernel capped SO_RCVBUF at {actual} (< {want}); bursts will overflow it. "
            f"Raise it: sysctl -w net.core.rmem_max={want}",
            file=sys.stderr,
        )
    return actual


def kernel_udp_counters() -> dict | None:
    """Kernel-side UDP drop counters for this network namespace (Linux), None elsewhere.

    rcvbuf_errors: datagrams dropped because a socket receive buffer was full.
    softnet_dropped: packets dropped before any socket (netdev backlog full).
    """
    try:
        lines = Path("/proc/net/snmp").read_text().splitlines()
        udp = [ln.split() for ln in lines if ln.startswith("Udp:")]
        out = {
            "rcvbuf_errors": int(udp[1][udp[0].index("RcvbufErrors")]),
            "in_errors": int(udp[1][udp[0].index("InErrors")]),
        }
    except (OSError, IndexError, ValueError):
        return None
    try:
        out["softnet_dropped"] = sum(
            int(ln.split()[1], 16) for ln in Path("/proc/net/softnet_stat").read_text().splitlines()
        )
    except (OSError, IndexError, ValueError):
        pass
    return out



def main() -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--bind", default="127.0.0.1")
    p.add_argument("--port", type=int, default=9400)
    p.add_argument("--out", type=Path, default=Path("/tmp/diode_out"))
    p.add_argument("--quarantine", type=Path, default=Path("/tmp/diode_quarantine"))
    p.add_argument("--work", type=Path, default=None)
    p.add_argument("--ttl", type=float, default=300.0)
    p.add_argument("--idle-exit", type=float, default=None)
    p.add_argument("--max-seconds", type=float, default=None)
    p.add_argument("--hmac-secret", default="")
    p.add_argument("--rcvbuf", type=int, default=0)
    p.add_argument(
        "--max-transfer-bytes",
        type=int,
        default=DEFAULT_MAX_TRANSFER_BYTES,
        help="Refuse a META larger than this (FAIL receipt reason 'limit')",
    )
    p.add_argument("--max-active", type=int, default=DEFAULT_MAX_ACTIVE)
    p.add_argument(
        "--ram-max-bytes",
        type=int,
        default=RAM_MAX_BYTES,
        help="Transfers at or above this size assemble in an mmap'd work file, not RAM",
    )
    p.add_argument(
        "--min-free-bytes",
        type=int,
        default=0,
        help="Refuse a transfer that would leave less than this free on the output volume",
    )
    p.add_argument(
        "--holes-window",
        type=int,
        default=STATUS_MISSING_CAP,
        help="Missing sequence numbers listed per holes receipt",
    )
    p.add_argument(
        "--receipts",
        type=Path,
        default=None,
        help="Local receipt drop-dir (recv-only). Coordinator copies this to the validate pitcher.",
    )
    p.add_argument(
        "--status-only",
        action="store_true",
        help="Validate-track catcher: accept STATUS frames only, write receipts, never assemble files.",
    )
    p.add_argument(
        "--require-source-map",
        type=Path,
        default=None,
        help="With --status-only: store a receipt only if DIR holds a source map for its transfer id",
    )
    p.add_argument(
        "--receipt-every",
        type=int,
        default=50,
        help="Write a holes receipt every N new DATA frames (0=EOF/terminal only)",
    )
    p.add_argument(
        "--require-frame-auth",
        action="store_true",
        help="Drop any data-track frame without a valid MAC from --hmac-secret",
    )
    p.add_argument(
        "--insecure",
        action="store_true",
        help="Allow a non-loopback --bind without --hmac-secret (anyone who reaches the port can publish)",
    )
    args = p.parse_args()

    secret = args.hmac_secret.encode("utf-8") if args.hmac_secret else None
    if secret is None and args.bind not in ("127.0.0.1", "::1", "localhost") and not args.insecure:
        p.error("--hmac-secret is required for a non-loopback --bind (or pass --insecure for a lab)")
    idle_exit = args.idle_exit if args.idle_exit is not None and args.idle_exit > 0 else None
    catcher = Catcher(
        args.out,
        args.quarantine,
        args.ttl,
        idle_exit,
        secret,
        work_dir=args.work,
        disk_threshold_bytes=args.ram_max_bytes,
        max_transfer_bytes=args.max_transfer_bytes,
        max_active=args.max_active,
        min_free_bytes=args.min_free_bytes,
        holes_window=max(1, min(args.holes_window, 128)),
        frame_key=frame_key(secret) if secret else None,
        require_frame_auth=bool(args.require_frame_auth and secret),
    )
    if args.require_frame_auth and not secret:
        print("--require-frame-auth needs --hmac-secret", file=sys.stderr)
        return 2
    if args.receipts is not None:
        catcher.receipts = ReceiptStore(args.receipts)
    catcher.status_only = bool(args.status_only)
    if args.require_source_map is not None:
        sm_dir = args.require_source_map
        catcher.active_ids = lambda tid: (sm_dir / f"{tid}.json").is_file()
    catcher.receipt_every = max(0, int(args.receipt_every))
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    _configure_recv_buf(sock, DEFAULT_CHUNK_SIZE + 256, want=args.rcvbuf)
    sock.bind((args.bind, args.port))
    sock.settimeout(0.2)
    print(f"catcher listening on {args.bind}:{args.port}", file=sys.stderr)

    start = time.time()
    last_pkt = start
    try:
        while True:
            now = time.time()
            if args.max_seconds is not None and now - start >= args.max_seconds:
                break
            if (
                idle_exit is not None
                and now - last_pkt >= idle_exit
                and catcher.stats["datagrams"]
            ):
                break
            catcher.expire()
            try:
                data, _addr = sock.recvfrom(65535)
            except socket.timeout:
                continue
            last_pkt = time.time()
            catcher.handle(data)
            # Drain kernel queue before next timeout: under dual-pass bursts the
            # socket fills faster than one-packet-per-loop handling.
            sock.setblocking(False)
            try:
                while True:
                    try:
                        data, _addr = sock.recvfrom(65535)
                    except BlockingIOError:
                        break
                    last_pkt = time.time()
                    catcher.handle(data)
            finally:
                sock.setblocking(True)
                sock.settimeout(0.2)
    except KeyboardInterrupt:
        pass
    finally:
        sock.close()
        catcher.expire(force=True)
        print(json.dumps(catcher.stats, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
