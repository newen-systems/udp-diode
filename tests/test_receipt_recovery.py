"""Receipt repetition, wire version, resource caps and crash recovery."""
from __future__ import annotations

import os
import random
import sys
import threading
import time
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import pitcher  # noqa: E402
from catcher import PREMETA_MAX_FRAMES, Catcher  # noqa: E402
from protocol import (  # noqa: E402
    STATUS_FAIL,
    STATUS_HOLES,
    STATUS_OK,
    Frame,
    FrameType,
    ProtocolError,
    StatusReport,
    build_meta_header,
    build_status_frame,
    build_transfer_frames,
    decode_frame,
    max_datagram_len,
)
from receipts import ReceiptStore  # noqa: E402

FWD = b"forward-key"
REV = b"reverse-key"
PAYLOAD = bytes(random.Random(5).getrandbits(8) for _ in range(9000))


class Link:
    """Both directions in one process. Drops are decided per frame kind."""

    def __init__(self, tmp: Path, drop_ok: int = 0, drop_holes: int = 0, drop_data: dict | None = None):
        self.high = Catcher(tmp / "out", tmp / "q", 60, None, hmac_secret=FWD)
        self.high_store = ReceiptStore(tmp / "high_rcpt")
        self.high.receipts = self.high_store
        self.high.receipt_every = 0
        self.low_store = ReceiptStore(tmp / "low_inbox")
        self.low = Catcher(tmp / "lout", tmp / "lq", 60, None, hmac_secret=REV)
        self.low.receipts = self.low_store
        self.low.status_only = True
        self.low.active_ids = lambda tid: tid == "arq-2"
        self.drop_ok = drop_ok
        self.drop_holes = drop_holes
        self.drop_data = dict(drop_data or {})
        self.lock = threading.Lock()
        self.dropped_status = 0

        outer = self

        class Fwd:
            def sendto(self, data: bytes, dest: object) -> int:
                f = decode_frame(data)
                with outer.lock:
                    if f.type is FrameType.DATA and outer.drop_data.get(f.header["seq"], 0) > 0:
                        outer.drop_data[f.header["seq"]] -= 1
                        return len(data)
                outer.high.handle(data)
                return len(data)

            def setsockopt(self, *a: object) -> None:
                pass

            def close(self) -> None:
                pass

        class Rev:
            def sendto(self, data: bytes, dest: object) -> int:
                f = decode_frame(data)
                with outer.lock:
                    if f.header["kind"] == STATUS_OK and outer.drop_ok > 0:
                        outer.drop_ok -= 1
                        outer.dropped_status += 1
                        return len(data)
                    if f.header["kind"] == STATUS_HOLES and outer.drop_holes > 0:
                        outer.drop_holes -= 1
                        outer.dropped_status += 1
                        return len(data)
                outer.low.handle(data)
                return len(data)

            def setsockopt(self, *a: object) -> None:
                pass

            def close(self) -> None:
                pass

        self.fwd = Fwd()
        self.emitter = pitcher.ReceiptEmitter(
            self.high_store, Rev(), ("127.0.0.1", 9), hmac_secret=REV,
            copies=3, repeat_s=0.1, retention_s=30,
        )
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._pump, daemon=True)

    def _pump(self) -> None:
        while not self._stop.is_set():
            self.emitter.poll()
            self._stop.wait(0.02)

    def __enter__(self) -> "Link":
        self._thread.start()
        return self

    def __exit__(self, *a: object) -> None:
        self._stop.set()
        self._thread.join(2)


def run_transfer(tmp: Path, link: Link, rounds: int = 40) -> int:
    src = tmp / "src.bin"
    src.write_bytes(PAYLOAD)
    frames = build_transfer_frames("arq-2", PAYLOAD, chunk_size=500, hmac_secret=FWD)
    job = pitcher.ArqJob(
        transfer_id="arq-2", source=src, chunk_size=500, meta=frames[0], eof=frames[-1],
        receipts=link.low_store, timeout_s=0.1, rounds=rounds, backoff=1.0, max_timeout_s=0.1,
    )
    for f in frames:
        link.fwd.sendto(f.encode(), None)
    return pitcher.watch_receipts_and_resend(link.fwd, ("127.0.0.1", 9), job)


def test_baseline_link_completes(tmp_path: Path) -> None:
    with Link(tmp_path, drop_data={2: 1}) as link:
        assert run_transfer(tmp_path, link) == 0
    assert link.high.stats["published"] == 1


def test_all_initial_ok_copies_lost_still_confirms(tmp_path: Path) -> None:
    with Link(tmp_path, drop_ok=3) as link:
        assert run_transfer(tmp_path, link) == 0
        assert link.dropped_status == 3


def test_all_initial_holes_copies_lost_still_recovers(tmp_path: Path) -> None:
    with Link(tmp_path, drop_holes=3, drop_data={2: 1}) as link:
        assert run_transfer(tmp_path, link) == 0
        assert link.dropped_status == 3
    assert link.high.stats["published"] == 1


def test_first_refill_lost_and_first_holes_lost(tmp_path: Path) -> None:
    with Link(tmp_path, drop_holes=3, drop_data={2: 2, 5: 1}) as link:
        assert run_transfer(tmp_path, link) == 0


def test_refill_rounds_follow_fresh_receipts_not_the_ack_timeout(tmp_path: Path) -> None:
    # Lost chunks are refilled with a 5 s ACK timeout. The refill is answered by a new receipt,
    # so the transfer must finish long before even one timeout has passed.
    with Link(tmp_path, drop_data={2: 1, 7: 1, 12: 1}) as link:
        src = tmp_path / "src.bin"
        src.write_bytes(PAYLOAD)
        frames = build_transfer_frames("arq-2", PAYLOAD, chunk_size=500, hmac_secret=FWD)
        job = pitcher.ArqJob(
            transfer_id="arq-2", source=src, chunk_size=500, meta=frames[0], eof=frames[-1],
            receipts=link.low_store, timeout_s=5.0, rounds=40, backoff=1.0, max_timeout_s=5.0,
        )
        for f in frames:
            link.fwd.sendto(f.encode(), None)
        started = time.time()
        assert pitcher.watch_receipts_and_resend(link.fwd, ("127.0.0.1", 9), job) == 0
        assert time.time() - started < 2.5
    assert link.high.stats["published"] == 1


def test_stale_receipt_for_an_unrelated_transfer_is_not_accepted_by_sender(tmp_path: Path) -> None:
    with Link(tmp_path) as link:
        bogus = build_status_frame(StatusReport("other-9", STATUS_OK, have=3, total_chunks=3), REV)
        link.low.handle(bogus.encode())
        assert link.low_store.read("other-9") is None
        assert link.low.stats["status_unbound"] == 1


def test_identical_replayed_receipt_changes_nothing(tmp_path: Path) -> None:
    with Link(tmp_path) as link:
        fr = build_status_frame(
            StatusReport("arq-2", STATUS_HOLES, have=1, total_chunks=18, missing=(3,)), REV
        )
        link.low.handle(fr.encode())
        link.low.handle(fr.encode())
        assert link.low.stats["status_dup"] == 1
        assert link.low.stats["receipts_written"] == 1


def test_emitter_prunes_expired_receipts_and_stops_repeating(tmp_path: Path) -> None:
    store = ReceiptStore(tmp_path / "r")
    path = store.write(StatusReport("old-1", STATUS_OK, have=2, total_chunks=2))
    sent: list[bytes] = []

    class S:
        def sendto(self, data: bytes, dest: object) -> int:
            sent.append(data)
            return len(data)

    em = pitcher.ReceiptEmitter(store, S(), ("h", 1), copies=1, repeat_s=1.0, retention_s=60, prune=True)
    t0 = path.stat().st_mtime
    assert em.poll(t0 + 1) == 1
    assert em.poll(t0 + 1.5) == 0  # inside the repeat interval
    assert em.poll(t0 + 2.5) == 1  # repeated on the timer
    assert em.poll(t0 + 120) == 0  # past retention: silent
    assert not path.exists()  # and pruned


# ----------------------------------------------------------- wire version


def test_legacy_dio1_peer_fails_clearly(tmp_path: Path) -> None:
    wire = bytearray(build_transfer_frames("old-1", PAYLOAD, chunk_size=500)[0].encode())
    wire[:4] = b"DIO1"
    with pytest.raises(ProtocolError, match="legacy DIO1"):
        decode_frame(bytes(wire))
    c = Catcher(tmp_path / "o", tmp_path / "q", 60, None)
    c.handle(bytes(wire))
    assert c.stats["legacy_peer"] == 1 and c.stats["published"] == 0


# --------------------------------------------------------- datagram budget


def test_default_frames_fit_a_1500_byte_mtu() -> None:
    assert max_datagram_len(1200) <= 1500 - 28
    missing = tuple(range(90_000_000 // 2, 90_000_000 // 2 + 128))
    status = build_status_frame(
        StatusReport("x" * 64, STATUS_HOLES, have=0, total_chunks=1 << 26, missing=missing), REV
    )
    assert len(status.encode()) <= 1500 - 28


# ---------------------------------------------------------- resource caps


def test_premeta_buffering_is_bounded(tmp_path: Path) -> None:
    frames = build_transfer_frames("pm-1", b"z" * 5000, chunk_size=1)
    c = Catcher(tmp_path / "o", tmp_path / "q", 60, None)
    for f in frames:
        if f.type is FrameType.DATA:
            c.handle(f.encode())
    asm = c.assemblies["pm-1"]
    assert len(asm.chunks) == PREMETA_MAX_FRAMES
    assert c.stats["premeta_dropped"] == 5000 - PREMETA_MAX_FRAMES


def test_ram_budget_sends_later_assemblies_to_disk(tmp_path: Path) -> None:
    # Each 9000-byte transfer fits the per-transfer RAM threshold, but only one fits the budget.
    c = Catcher(tmp_path / "out", tmp_path / "q", 60, None, hmac_secret=FWD, ram_budget_bytes=12000)
    for tid in ("ram-a", "ram-b"):
        meta = build_transfer_frames(tid, PAYLOAD, chunk_size=500, hmac_secret=FWD)[0]
        c.handle(meta.encode())
    assert [c.assemblies[t].disk for t in ("ram-a", "ram-b")] == [False, True]


def test_active_transfer_table_is_bounded(tmp_path: Path) -> None:
    c = Catcher(tmp_path / "o", tmp_path / "q", 60, None, max_active=2)
    for n in range(5):
        f = build_transfer_frames(f"cap-{n}", b"abc", chunk_size=2)[1]
        c.handle(f.encode())
    assert len(c.assemblies) == 2 and c.stats["dropped_capacity"] == 3


def test_oversize_transfer_is_refused_with_fail_limit_but_not_burned(tmp_path: Path) -> None:
    c = Catcher(tmp_path / "o", tmp_path / "q", 60, None, max_transfer_bytes=1000)
    c.receipts = ReceiptStore(tmp_path / "r")
    for f in build_transfer_frames("big-1", PAYLOAD, chunk_size=500):
        c.handle(f.encode())
    got = c.receipts.read("big-1")
    assert got is not None and got.kind == STATUS_FAIL and got.reason == "limit"
    assert c.stats["published"] == 0 and "big-1" not in c.done_ids


def test_forged_meta_cannot_burn_a_transfer_id(tmp_path: Path) -> None:
    good = build_transfer_frames("burn-1", PAYLOAD, chunk_size=500, hmac_secret=FWD)
    forged = dict(good[0].header)
    forged["hmac"] = "0" * 64
    c = Catcher(tmp_path / "o", tmp_path / "q", 60, None, hmac_secret=FWD)
    c.handle(Frame(FrameType.META, forged).encode())
    for f in good:
        c.handle(f.encode())
    assert c.stats["hmac_fail"] == 1 and c.stats["published"] == 1


def test_conflicting_meta_is_counted_and_ignored(tmp_path: Path) -> None:
    good = build_transfer_frames("cm-1", PAYLOAD, chunk_size=500)
    other = build_transfer_frames("cm-1", b"y" * len(PAYLOAD), chunk_size=500)[0]
    c = Catcher(tmp_path / "o", tmp_path / "q", 60, None)
    c.handle(good[0].encode())
    c.handle(other.encode())
    for f in good[1:]:
        c.handle(f.encode())
    assert c.stats["meta_conflict"] == 1 and c.stats["published"] == 1


# --------------------------------------------------------- crash recovery


class PowerCut(BaseException):
    """Stands in for a kill: not an Exception, so no handler can clean up after it."""


def test_recovery_commits_marker_when_crash_followed_payload_rename(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    real = os.replace
    calls = {"n": 0}

    def crash_on_marker(src, dst, *a, **k):  # type: ignore[no-untyped-def]
        if str(dst).endswith(".meta.json") and "crash-1" in str(dst):
            raise PowerCut()
        calls["n"] += 1
        return real(src, dst, *a, **k)

    monkeypatch.setattr(os, "replace", crash_on_marker)
    c1 = Catcher(tmp_path / "out", tmp_path / "q", 60, None)
    with pytest.raises(PowerCut):
        for f in build_transfer_frames("crash-1", PAYLOAD, chunk_size=500):
            c1.handle(f.encode())
    monkeypatch.setattr(os, "replace", real)
    out = tmp_path / "out"
    assert (out / "crash-1.bin").exists() and (out / "crash-1.meta.json.tmp").exists()
    c2 = Catcher(tmp_path / "out", tmp_path / "q", 60, None)
    assert "crash-1" in c2.done_ids
    assert (out / "crash-1.meta.json").exists() and not (out / "crash-1.meta.json.tmp").exists()
    assert (out / "crash-1.bin").read_bytes() == PAYLOAD


def test_recovery_discards_marker_tmp_without_payload(tmp_path: Path) -> None:
    out = tmp_path / "out"
    out.mkdir()
    (out / "ghost-1.meta.json.tmp").write_text("{}")
    (out / "ghost-1.bin.part").write_bytes(b"partial")
    c = Catcher(out, tmp_path / "q", 60, None)
    assert "ghost-1" not in c.done_ids
    assert not list(out.iterdir())


def test_quarantined_transfer_stays_terminal_after_restart(tmp_path: Path) -> None:
    frames = build_transfer_frames("qt-1", PAYLOAD, chunk_size=500)
    c1 = Catcher(tmp_path / "o", tmp_path / "q", 0.0, None)
    c1.handle(frames[0].encode())
    c1.expire(force=True)
    assert c1.stats["quarantined"] == 1
    c2 = Catcher(tmp_path / "o", tmp_path / "q", 60, None)
    for f in frames:
        c2.handle(f.encode())
    assert c2.stats["published"] == 0 and c2.stats["duplicates"] >= 1


def test_meta_header_is_built_with_every_field_in_the_mac() -> None:
    a = build_meta_header("m-1", 1000, 2, "a" * 64, 500, 500, hmac_secret=FWD)
    b = build_meta_header("m-1", 1000, 2, "a" * 64, 500, 500, content_type="x/y", hmac_secret=FWD)
    c = build_meta_header("m-1", 1000, 2, "a" * 64, 500, 500, parity_group=4, hmac_secret=FWD)
    assert len({a["hmac"], b["hmac"], c["hmac"]}) == 3
