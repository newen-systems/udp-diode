#!/usr/bin/env python3
"""Send-only UDP pitcher: file → sequenced frames, or receipts → STATUS.

Never binds a receive socket. Retransmit is driven by local receipt files
that a same-side coordinator copied from the validate-track catcher.

Absorbs industry practice (godiode / UDPcast / svenseeberg):
  - stream large files (no full-file RAM)
  - compact META (chunk_size + last_chunk_len)
  - META/EOF redundancy (default ×3)
  - XOR FEC groups
  - send-side bitrate throttle + SO_SNDBUF
  - optional HMAC on META / STATUS
"""
from __future__ import annotations

import argparse
import random
import socket
import sys
import threading
import time
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Callable

from protocol import (  # noqa: I001
    DEFAULT_CHUNK_SIZE,
    IN_MEMORY_MAX_BYTES,
    STATUS_FAIL,
    STATUS_HOLES,
    STATUS_OK,
    Frame,
    FrameType,
    build_meta_header,
    build_status_frame,
    build_transfer_frames,
    file_transfer_stats,
    iter_data_and_parity_from_file,
    iter_data_seqs_from_file,
)
from receipts import ReceiptStore, read_source_map, write_source_map


class Pacer:
    """Thread-safe send-rate limiter shared by every sender in a process.

    Keeps a virtual clock advanced by wire_len / rate per frame. It only sleeps
    once the clock is more than a millisecond ahead, so coarse OS sleeps do not
    cap the rate below the target, and an idle gap grants at most a few ms of burst.
    """

    def __init__(self, max_bps: float = 0.0, gap_s: float = 0.0) -> None:
        self.max_bps = max_bps
        self.gap_s = gap_s
        self._next = 0.0
        self._lock = threading.Lock()

    def wait(self, nbytes: int) -> None:
        cost = self.gap_s
        if self.max_bps > 0:
            cost = max(cost, nbytes / self.max_bps)
        if cost <= 0:
            return
        with self._lock:
            now = time.monotonic()
            start = max(now - 0.005, self._next)
            self._next = start + cost
            delay = start - now
        if delay > 0.001:
            time.sleep(delay)


def _configure_send_buf(sock: socket.socket, packet_size: int) -> None:
    """godiode lesson: enlarge send buffer for burst pacing."""
    want = max(256 * 1024, 64 * packet_size)
    try:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, want)
    except OSError as exc:
        print(f"warn: SO_SNDBUF={want} failed: {exc}", file=sys.stderr)


def _send_frame(
    sock: socket.socket,
    dest: tuple[str, int],
    fr: Frame,
    gap_s: float,
    max_bps: float,
    pacer: Pacer | None = None,
) -> int:
    wire = fr.encode()
    sock.sendto(wire, dest)
    if pacer is not None:
        pacer.wait(len(wire))
        return len(wire)
    sleep_s = gap_s
    if max_bps > 0:
        sleep_s = max(sleep_s, len(wire) / max_bps)
    if sleep_s > 0:
        time.sleep(sleep_s)
    return len(wire)


class ReceiptEmitter:
    """Send the current receipt for each transfer, and repeat it on a timer.

    A receipt is a state, not an event: losing every copy of it must not stall
    the sender. New or changed receipts go out ``copies`` times; an unchanged one
    is repeated once per ``repeat_s`` until it is ``retention_s`` old (age is the
    file mtime, so a nudge that touches the file extends the window). With
    ``prune`` the expired file is deleted so the directory scan stays small.
    """

    def __init__(
        self,
        store: ReceiptStore,
        sock: socket.socket,
        dest: tuple[str, int],
        hmac_secret: bytes | None = None,
        copies: int = 3,
        gap_s: float = 0.0,
        repeat_s: float = 1.0,
        retention_s: float = 300.0,
        prune: bool = False,
    ) -> None:
        self.store = store
        self.sock = sock
        self.dest = dest
        self.secret = hmac_secret
        self.copies = max(1, copies)
        self.gap_s = gap_s
        self.repeat_s = repeat_s
        self.retention_s = retention_s
        self.prune = prune
        self._last: dict[str, tuple[str, float]] = {}
        self.sent = 0
        self.new_receipts = 0

    def poll(self, now: float | None = None) -> int:
        """One pass over the store. Returns the number of frames sent."""
        now = time.time() if now is None else now
        frames = 0
        for path, report in self.store.list_reports():
            tid = report.transfer_id
            try:
                age = now - path.stat().st_mtime
            except OSError:
                continue
            if age > self.retention_s:
                self._last.pop(tid, None)
                if self.prune:
                    path.unlink(missing_ok=True)
                continue
            token = _token(report)
            prev = self._last.get(tid)
            changed = prev is None or prev[0] != token
            if not changed and now - prev[1] < self.repeat_s:
                continue
            frame = build_status_frame(report, hmac_secret=self.secret)
            for _ in range(self.copies if changed else 1):
                _send_frame(self.sock, self.dest, frame, self.gap_s, 0.0)
                frames += 1
            self._last[tid] = (token, now)
            if changed:
                self.new_receipts += 1
                print(
                    f"status sent transfer_id={tid} kind={report.kind} "
                    f"have={report.have} missing={list(report.missing)}",
                    file=sys.stderr,
                )
        self.sent += frames
        return frames


def run_validate_pitcher(args: argparse.Namespace) -> int:
    """Send-only: STATUS frames from a local receipt inbox (validate track)."""
    store = ReceiptStore(args.send_receipts)
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    _configure_send_buf(sock, 512)
    dest = (args.host, args.port)
    secret = args.hmac_secret.encode("utf-8") if args.hmac_secret else None
    emitter = ReceiptEmitter(
        store,
        sock,
        dest,
        hmac_secret=secret,
        copies=args.receipt_copies,
        gap_s=args.gap_ms / 1000.0,
        repeat_s=getattr(args, "receipt_repeat_s", 1.0),
        retention_s=getattr(args, "receipt_retention_s", 300.0),
    )
    start = time.time()
    last_activity = start
    print(
        f"validate pitcher receipts={args.send_receipts} dest={dest[0]}:{dest[1]}",
        file=sys.stderr,
    )
    try:
        while True:
            now = time.time()
            if args.max_seconds is not None and now - start >= args.max_seconds:
                break
            if (
                args.idle_exit is not None
                and emitter.sent
                and now - last_activity >= args.idle_exit
            ):
                break
            seen = emitter.new_receipts
            emitter.poll(now)
            if emitter.new_receipts != seen:
                last_activity = time.time()  # repeats are not activity: idle-exit still fires
            time.sleep(max(0.05, args.receipt_poll))
    except KeyboardInterrupt:
        pass
    finally:
        sock.close()
    print(f"status_frames_sent={emitter.sent}", file=sys.stderr)
    return 0


@dataclass
class ArqJob:
    transfer_id: str
    source: Path
    chunk_size: int
    meta: Frame
    eof: Frame
    receipts: ReceiptStore
    timeout_s: float = 2.0
    rounds: int = 8
    backoff: float = 2.0
    max_timeout_s: float = 30.0
    gap_s: float = 0.0
    max_bps: float = 0.0
    meta_copies: int = 3
    eof_copies: int = 3
    pacer: Pacer | None = None
    # Give up after this long (None: only ``rounds`` bounds the wait).
    budget_s: float | None = None
    stop: threading.Event | None = None
    # Re-send the whole object when the receiver clearly lost its state (its
    # ``have`` count fell, or most of the object never arrived). Bounded.
    repass: "Callable[[], None] | None" = None
    max_repasses: int = 3


def _read_valid_receipt(job: ArqJob):
    """Latest receipt, only if it is a plausible statement about THIS job's object."""
    report = job.receipts.read(job.transfer_id)
    if report is None:
        return None
    total = int(job.meta.header["total_chunks"])
    if report.transfer_id != job.transfer_id:
        return None
    if report.total_chunks is not None and report.total_chunks != total:
        return None
    if report.kind == STATUS_OK and report.have != total:
        return None
    if any(not 0 <= s < total for s in report.missing):
        return None
    return report


def _token(report) -> str:
    return f"{report.kind}:{report.have}:{report.missing}"


def _pause(job: ArqJob, seconds: float) -> bool:
    """Sleep; True when the job was asked to stop."""
    if job.stop is not None:
        return job.stop.wait(seconds)
    time.sleep(seconds)
    return False


def watch_receipts_and_resend(
    sock: socket.socket, dest: tuple[str, int], job: ArqJob
) -> int:
    """Poll local receipts (validate catcher → coordinator). Send-only.

    Returns 0 on receiver OK, 2 on receiver FAIL, 1 when rounds or budget run
    out, 3 when asked to stop. An unchanged HOLES receipt is not "no news":
    it means the last refill (or the receipt that would report it) was lost,
    so the same window is sent again, with backoff.
    """

    def send(fr: Frame) -> None:
        _send_frame(sock, dest, fr, job.gap_s, job.max_bps, job.pacer)

    wait = job.timeout_s
    last_token = ""
    last_have = -1
    repasses = 0
    started = time.time()
    for round_i in range(max(1, job.rounds)):
        if job.stop is not None and job.stop.is_set():
            return 3
        if job.budget_s is not None and time.time() - started > job.budget_s:
            break
        # Wait for news: a receipt that differs from the one last acted on. The same receipt
        # again at the deadline means the refill (or its receipt) was lost, so it is resent.
        deadline = time.time() + wait
        report = None
        while time.time() < deadline:
            current = _read_valid_receipt(job)
            if current is not None:
                report = current
                if report.kind != STATUS_HOLES or _token(report) != last_token:
                    break
            if _pause(job, 0.01):
                return 3
        if report is None:
            print(
                f"arq round={round_i + 1}/{job.rounds} no receipt; "
                f"nudge meta/eof wait={wait:.1f}s",
                file=sys.stderr,
            )
            for _ in range(job.meta_copies):
                send(job.meta)
            for _ in range(job.eof_copies):
                send(job.eof)
            wait = min(wait * job.backoff, job.max_timeout_s)
            continue
        if report.kind == STATUS_OK:
            print(f"arq ok transfer_id={job.transfer_id}", file=sys.stderr)
            return 0
        if report.kind == STATUS_FAIL:
            print(
                f"arq fail transfer_id={job.transfer_id} reason={report.reason}",
                file=sys.stderr,
            )
            return 2
        total = int(job.meta.header["total_chunks"])
        lost_state = report.have < last_have or (last_have < 0 and report.have * 2 < total)
        last_have = report.have
        if lost_state and job.repass is not None and repasses < job.max_repasses:
            repasses += 1
            print(
                f"arq round={round_i + 1}/{job.rounds} receiver has {report.have}/{total}: "
                f"full re-send {repasses}/{job.max_repasses}",
                file=sys.stderr,
            )
            job.repass()
            last_token = ""
            wait = job.timeout_s
            if _pause(job, wait):
                return 3
            continue
        token = _token(report)
        stalled = token == last_token
        last_token = token
        missing = list(report.missing)
        print(
            f"arq round={round_i + 1}/{job.rounds} holes={missing} have={report.have}"
            + (" (unchanged, resending)" if stalled else ""),
            file=sys.stderr,
        )
        for _ in range(job.meta_copies):
            send(job.meta)
        for fr in iter_data_seqs_from_file(
            job.source, job.transfer_id, missing, job.chunk_size
        ):
            send(fr)
        for _ in range(job.eof_copies):
            send(job.eof)
        wait = min(wait * job.backoff, job.max_timeout_s) if stalled else job.timeout_s
    print(f"arq exhausted transfer_id={job.transfer_id}", file=sys.stderr)
    return 1


@dataclass
class Prepared:
    """What a sender needs to (re)send one stored object."""

    meta: Frame
    eof: Frame
    digest: str
    total_len: int
    total_chunks: int


def prepare_transfer(
    path: Path,
    transfer_id: str,
    chunk_size: int,
    parity_group: int = 0,
    hmac_secret: bytes | None = None,
    content_type: str = "application/octet-stream",
) -> Prepared:
    """Hash the file once and build its META and EOF frames."""
    digest, total_len, total_chunks, last_len = file_transfer_stats(path, chunk_size)
    meta = Frame(
        type=FrameType.META,
        header=build_meta_header(
            transfer_id,
            total_len,
            total_chunks,
            digest,
            chunk_size,
            last_len,
            content_type=content_type,
            parity_group=parity_group,
            hmac_secret=hmac_secret,
        ),
    )
    eof = Frame(
        type=FrameType.EOF,
        header={
            "transfer_id": transfer_id,
            "total_chunks": total_chunks,
            "sha256": digest,
            "total_len": total_len,
        },
    )
    return Prepared(meta, eof, digest, total_len, total_chunks)


def send_pass(
    sock: socket.socket,
    dest: tuple[str, int],
    path: Path,
    prepared: Prepared,
    *,
    chunk_size: int,
    parity_group: int = 0,
    meta_copies: int = 3,
    eof_copies: int = 3,
    pacer: Pacer | None = None,
    stop: threading.Event | None = None,
) -> bool:
    """One full pass: META xN, DATA (+PARITY) streamed from the file, EOF xN. False if stopped."""
    tid = prepared.meta.header["transfer_id"]
    for _ in range(meta_copies):
        _send_frame(sock, dest, prepared.meta, 0.0, 0.0, pacer)
    for n, fr in enumerate(iter_data_and_parity_from_file(path, tid, chunk_size, parity_group)):
        if stop is not None and n % 256 == 0 and stop.is_set():
            return False
        _send_frame(sock, dest, fr, 0.0, 0.0, pacer)
    for _ in range(eof_copies):
        _send_frame(sock, dest, prepared.eof, 0.0, 0.0, pacer)
    return True


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument(
        "path",
        type=Path,
        nargs="?",
        default=None,
        help="File to send (data track). Omit with --send-receipts.",
    )
    p.add_argument("--host", default="127.0.0.1")
    p.add_argument("--port", type=int, default=9400)
    p.add_argument("--chunk-size", type=int, default=DEFAULT_CHUNK_SIZE)
    p.add_argument("--meta-copies", type=int, default=3)
    p.add_argument("--eof-copies", type=int, default=3)
    p.add_argument(
        "--passes",
        type=int,
        default=1,
        help="Full retransmit passes (data track redundancy; validate-track ARQ is --watch-receipts)",
    )
    p.add_argument("--loss", type=float, default=0.0, help="Probability of dropping a DATA frame")
    p.add_argument(
        "--reorder",
        action="store_true",
        help="Shuffle DATA before send (in-memory path only; small files)",
    )
    p.add_argument(
        "--corrupt",
        action="store_true",
        help="Flip a byte in one DATA body (wire CRC still valid; whole-payload sha256 fails)",
    )
    p.add_argument(
        "--wire-corrupt",
        action="store_true",
        help="Corrupt one encoded datagram so catcher CRC rejects it",
    )
    p.add_argument(
        "--parity-group",
        type=int,
        default=0,
        help="XOR FEC group size (>1 enables PARITY frames; recover 1 loss per group)",
    )
    p.add_argument(
        "--drop-seq",
        type=int,
        default=-1,
        help="Deterministically drop DATA with this seq (for FEC demos)",
    )
    p.add_argument("--gap-ms", type=float, default=0.0, help="Minimum inter-datagram sleep (ms)")
    p.add_argument(
        "--max-bitrate",
        type=float,
        default=0.0,
        help=(
            "Throttle send rate to X Mbit/s (wire size). "
            "godiode/UDPcast: unthrottled blasts self-inflict loss on WAN. 0 = gap only."
        ),
    )
    p.add_argument(
        "--progress-every-mb",
        type=float,
        default=32.0,
        help="Log progress every N MiB of DATA body (0=off)",
    )
    p.add_argument("--transfer-id", default="")
    p.add_argument(
        "--hmac-secret",
        default="",
        help="If set, sign META/STATUS with HMAC-SHA256 (must match the catcher on this track)",
    )
    p.add_argument(
        "--force-memory",
        action="store_true",
        help="Force in-memory frame build (tests/reorder/corrupt only)",
    )
    p.add_argument(
        "--send-receipts",
        type=Path,
        default=None,
        help="Validate track: send STATUS from this inbox. Send-only; no file path.",
    )
    p.add_argument("--receipt-copies", type=int, default=3)
    p.add_argument("--receipt-poll", type=float, default=0.2)
    p.add_argument(
        "--receipt-repeat-s",
        type=float,
        default=1.0,
        help="Validate track: repeat an unchanged receipt this often, so lost copies cannot stall the sender",
    )
    p.add_argument(
        "--receipt-retention-s",
        type=float,
        default=300.0,
        help="Validate track: stop repeating a receipt once its file is this old",
    )
    p.add_argument("--idle-exit", type=float, default=None)
    p.add_argument("--max-seconds", type=float, default=None)
    p.add_argument(
        "--watch-receipts",
        type=Path,
        default=None,
        help="Data track: after send, poll this inbox for holes/ok/fail and resend. Send-only.",
    )
    p.add_argument(
        "--source-map",
        type=Path,
        default=None,
        help="Directory for {transfer_id}.json mapping to the source file (data track).",
    )
    p.add_argument("--ack-timeout-s", type=float, default=2.0)
    p.add_argument("--ack-rounds", type=int, default=8)
    p.add_argument("--ack-backoff", type=float, default=2.0)
    p.add_argument("--ack-timeout-cap-s", type=float, default=30.0)
    args = p.parse_args()

    if args.send_receipts is not None:
        return run_validate_pitcher(args)

    path = args.path
    if path is None or not path.is_file():
        print("data track requires a file path", file=sys.stderr)
        return 2

    size = path.stat().st_size
    use_memory = args.force_memory or args.reorder or args.corrupt or size <= IN_MEMORY_MAX_BYTES
    if args.reorder and size > IN_MEMORY_MAX_BYTES and not args.force_memory:
        print(
            "error: --reorder requires in-memory path; use smaller file or --force-memory",
            file=sys.stderr,
        )
        return 2

    transfer_id = args.transfer_id or str(uuid.uuid4())
    secret = args.hmac_secret.encode("utf-8") if args.hmac_secret else None
    if args.source_map is not None:
        write_source_map(
            args.source_map,
            transfer_id,
            path,
            args.chunk_size,
            args.parity_group,
        )
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    _configure_send_buf(sock, args.chunk_size + 256)
    dest = (args.host, args.port)
    sent = dropped = 0
    wire_corrupt_done = False
    max_bps = (args.max_bitrate * 1_000_000 / 8.0) if args.max_bitrate > 0 else 0.0
    progress_every = int(args.progress_every_mb * 1024 * 1024) if args.progress_every_mb > 0 else 0
    data_bytes_sent = 0
    next_progress = progress_every

    def _send(fr: Frame) -> None:
        nonlocal sent, wire_corrupt_done, data_bytes_sent, next_progress
        wire = fr.encode()
        if args.wire_corrupt and not wire_corrupt_done and fr.type == FrameType.DATA:
            wire = bytearray(wire)
            wire[-5] ^= 0xFF
            wire = bytes(wire)
            wire_corrupt_done = True
        sock.sendto(wire, dest)
        sent += 1
        if fr.type == FrameType.DATA:
            data_bytes_sent += len(fr.body)
            if progress_every and data_bytes_sent >= next_progress:
                print(
                    f"progress data_bytes={data_bytes_sent} sent_frames={sent}",
                    file=sys.stderr,
                )
                next_progress += progress_every
        sleep_s = args.gap_ms / 1000.0
        if max_bps > 0:
            sleep_s = max(sleep_s, len(wire) / max_bps)
        if sleep_s > 0:
            time.sleep(sleep_s)

    if use_memory:
        payload = path.read_bytes()
        frames = build_transfer_frames(
            transfer_id,
            payload,
            chunk_size=args.chunk_size,
            parity_group=args.parity_group,
            hmac_secret=secret,
        )
        meta = next(f for f in frames if f.type is FrameType.META)
        data = [f for f in frames if f.type is FrameType.DATA]
        parity = [f for f in frames if f.type is FrameType.PARITY]
        eof = next(f for f in frames if f.type is FrameType.EOF)

        if args.reorder:
            random.shuffle(data)
        if args.corrupt and data:
            victim = random.randrange(len(data))
            body = bytearray(data[victim].body)
            if body:
                body[0] ^= 0xFF
            data[victim] = Frame(
                type=FrameType.DATA, header=data[victim].header, body=bytes(body)
            )

        total_len = len(payload)
        total_chunks = len(data)
        for pass_i in range(args.passes):
            for _ in range(args.meta_copies):
                _send(meta)
            for fr in data:
                seq = int(fr.header["seq"])
                if args.drop_seq >= 0 and seq == args.drop_seq:
                    dropped += 1
                    continue
                if args.loss > 0 and random.random() < args.loss:
                    dropped += 1
                    continue
                _send(fr)
            for fr in parity:
                _send(fr)
            for _ in range(args.eof_copies):
                _send(eof)
            print(
                f"pass={pass_i + 1}/{args.passes} transfer_id={transfer_id} "
                f"bytes={total_len} chunks={total_chunks} parity={len(parity)} "
                f"sent={sent} dropped_data={dropped} mode=memory",
                file=sys.stderr,
            )
    else:
        # Streaming path (multi‑GB safe): hash pass, then send passes re-read file.
        digest, total_len, total_chunks, last_len = file_transfer_stats(
            path, args.chunk_size
        )
        meta = Frame(
            type=FrameType.META,
            header=build_meta_header(
                transfer_id,
                total_len,
                total_chunks,
                digest,
                args.chunk_size,
                last_len,
                parity_group=args.parity_group,
                hmac_secret=secret,
            ),
        )
        eof = Frame(
            type=FrameType.EOF,
            header={
                "transfer_id": transfer_id,
                "total_chunks": total_chunks,
                "sha256": digest,
                "total_len": total_len,
            },
        )
        print(
            f"stream prep transfer_id={transfer_id} bytes={total_len} "
            f"chunks={total_chunks} sha256={digest}",
            file=sys.stderr,
        )
        for pass_i in range(args.passes):
            data_bytes_sent = 0
            next_progress = progress_every
            for _ in range(args.meta_copies):
                _send(meta)
            parity_count = 0
            for fr in iter_data_and_parity_from_file(
                path, transfer_id, args.chunk_size, args.parity_group
            ):
                if fr.type is FrameType.DATA:
                    seq = int(fr.header["seq"])
                    if args.drop_seq >= 0 and seq == args.drop_seq:
                        dropped += 1
                        continue
                    if args.loss > 0 and random.random() < args.loss:
                        dropped += 1
                        continue
                    if args.wire_corrupt and not wire_corrupt_done:
                        # handled inside _send once
                        pass
                    _send(fr)
                else:
                    parity_count += 1
                    _send(fr)
            for _ in range(args.eof_copies):
                _send(eof)
            print(
                f"pass={pass_i + 1}/{args.passes} transfer_id={transfer_id} "
                f"bytes={total_len} chunks={total_chunks} parity≈{parity_count} "
                f"sent={sent} dropped_data={dropped} mode=stream",
                file=sys.stderr,
            )

    if args.watch_receipts is not None:
        src = path
        chunk_size = args.chunk_size
        mapped = None
        if args.source_map is not None:
            mapped = read_source_map(args.source_map, transfer_id)
        if mapped is not None:
            src = mapped["path"]
            chunk_size = int(mapped["chunk_size"])
        rc = watch_receipts_and_resend(
            sock,
            dest,
            ArqJob(
                transfer_id=transfer_id,
                source=src,
                chunk_size=chunk_size,
                meta=meta,
                eof=eof,
                receipts=ReceiptStore(args.watch_receipts),
                timeout_s=args.ack_timeout_s,
                rounds=args.ack_rounds,
                backoff=args.ack_backoff,
                max_timeout_s=args.ack_timeout_cap_s,
                gap_s=args.gap_ms / 1000.0,
                max_bps=max_bps,
                meta_copies=args.meta_copies,
                eof_copies=args.eof_copies,
            ),
        )
        sock.close()
        print(transfer_id)
        return rc

    sock.close()
    print(transfer_id)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
