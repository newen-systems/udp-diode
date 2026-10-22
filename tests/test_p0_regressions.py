"""P0 regression matrix: protocol trust boundary, receipts, ARQ stalls, publish custody.

Each test pins one finding from the review of b779f3f. Frames that the
sender would never build are crafted at byte level so the checks exercise the
decoder and the catcher, not the encoder.
"""
from __future__ import annotations

import json
import os
import random
import stat
import sys
import time
import zlib
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import pitcher  # noqa: E402
from catcher import Catcher  # noqa: E402
from protocol import (  # noqa: E402
    CRC_STRUCT,
    HEADER_STRUCT,
    MAGIC,
    STATUS_HOLES,
    STATUS_OK,
    FrameType,
    ProtocolError,
    StatusReport,
    build_meta_header,
    build_status_frame,
    build_transfer_frames,
    decode_frame,
    sha256_hex,
)
from receipts import ReceiptStore, report_from_dict  # noqa: E402

SECRET = b"forward-key"


# ---------------------------------------------------------------- helpers


def raw_frame(ftype: int, header: bytes, body: bytes = b"") -> bytes:
    prefix = HEADER_STRUCT.pack(MAGIC, ftype, 0, len(header), len(body))
    payload = prefix + header + body
    return payload + CRC_STRUCT.pack(zlib.crc32(payload) & 0xFFFFFFFF)


def wire(ftype: FrameType, header: object, body: bytes = b"") -> bytes:
    return raw_frame(int(ftype), json.dumps(header).encode(), body)


def retag(frame, tid: str) -> bytes:
    """Re-encode a built frame under an arbitrary transfer id (bypasses any encode check)."""
    header = dict(frame.header)
    header["transfer_id"] = tid
    return wire(frame.type, header, frame.body)


@pytest.fixture
def payload() -> bytes:
    rng = random.Random(42)
    return bytes(rng.getrandbits(8) for _ in range(3500))


def new_catcher(tmp_path: Path, **kw) -> Catcher:
    return Catcher(
        tmp_path / "out", tmp_path / "q", ttl_s=60, idle_exit_s=None, **kw
    )


def published(tmp_path: Path) -> list[Path]:
    return sorted((tmp_path / "out").glob("*.bin"))


class FakeSock:
    def __init__(self) -> None:
        self.sent: list[bytes] = []

    def sendto(self, data: bytes, dest: object) -> int:
        self.sent.append(data)
        return len(data)

    def setsockopt(self, *a: object) -> None:
        pass

    def close(self) -> None:
        pass


def data_seqs(sock: FakeSock) -> list[int]:
    out = []
    for w in sock.sent:
        f = decode_frame(w)
        if f.type is FrameType.DATA:
            out.append(int(f.header["seq"]))
    return out


def valid_headers(tid: str = "t1") -> dict[str, dict]:
    """One valid header per frame type, used as a mutation base."""
    meta = build_meta_header(tid, 2400, 2, "a" * 64, 1200, 1200)
    return {
        "meta": meta,
        "data": {"transfer_id": tid, "seq": 0, "chunk_len": 3},
        "eof": {"transfer_id": tid, "total_chunks": 2, "sha256": "a" * 64, "total_len": 2400},
        "parity": {
            "transfer_id": tid,
            "seq_start": 0,
            "seq_end": 1,
        },
        "status": {
            "transfer_id": tid,
            "kind": "holes",
            "have": 1,
            "total_chunks": 2,
            "missing": [1],
        },
    }


def mutated(kind: str, /, **changes: object) -> dict:
    h = valid_headers()[kind]
    for k, v in changes.items():
        if v is _DEL:
            h.pop(k, None)
        else:
            h[k] = v
    return h


_DEL = object()
_T = {
    "meta": FrameType.META,
    "data": FrameType.DATA,
    "eof": FrameType.EOF,
    "parity": FrameType.PARITY,
    "status": FrameType.STATUS,
}


def case(kind: str, body: bytes = b"", /, **changes: object):
    return (_T[kind], mutated(kind, **changes), body)


BAD_TIDS = [
    "../x",
    "/abs/path",
    "a/b",
    "a\\b",
    "",
    ".",
    "..",
    "x" * 200,
    "a b",
    "café",
    "a\x00b",
    5,
    None,
]

# (id, frame type, header object, body) for headers that must be protocol errors.
BAD_FRAMES: list[tuple[str, FrameType, object, bytes]] = []
for _kind in ("meta", "data", "eof", "parity", "status"):
    for _tid in BAD_TIDS:
        BAD_FRAMES.append(
            (f"{_kind}-tid-{_tid!r}", *case(_kind, transfer_id=_tid)),
        )
_extra = [
    ("data-seq-negative", *case("data", seq=-1)),
    ("data-seq-huge", *case("data", seq=2**40)),
    ("data-seq-string", *case("data", seq="3")),
    ("data-seq-float", *case("data", seq=1.5)),
    ("data-seq-bool", *case("data", seq=True)),
    ("data-seq-null", *case("data", seq=None)),
    ("data-seq-missing", *case("data", seq=_DEL)),
    ("data-chunk_len-mismatch", *case("data", chunk_len=5)),
    ("data-chunk_len-negative", *case("data", chunk_len=-3)),
    ("data-extra-key", *case("data", note="x")),
    ("meta-total_len-negative", *case("meta", total_len=-1)),
    ("meta-total_chunks-zero", *case("meta", total_chunks=0)),
    ("meta-total_chunks-huge", *case("meta", total_chunks=2**40)),
    ("meta-chunk_size-zero", *case("meta", chunk_size=0)),
    ("meta-chunk_size-huge", *case("meta", chunk_size=10**9)),
    ("meta-last_chunk_len-over", *case("meta", last_chunk_len=99999)),
    ("meta-geometry-inconsistent", *case("meta", total_chunks=7)),
    ("meta-sha256-short", *case("meta", sha256="abc")),
    ("meta-sha256-nonhex", *case("meta", sha256="z" * 64)),
    ("meta-parity_group-huge", *case("meta", parity_group=10**6)),
    ("meta-hmac-not-string", *case("meta", hmac=5)),
    ("meta-extra-key", *case("meta", chunk_lens=[1200, 1200])),
    ("meta-total_len-string", *case("meta", total_len="2400")),
    ("eof-sha256-missing", *case("eof", sha256=_DEL)),
    ("eof-total_chunks-string", *case("eof", total_chunks="2")),
    ("parity-range-huge", *case("parity", seq_end=10**9)),
    ("parity-group-too-large", *case("parity", seq_end=10_000)),
    ("parity-negative-start", *case("parity", seq_start=-1, seq_end=1)),
    ("parity-start-after-end", *case("parity", seq_start=3, seq_end=1)),
    ("parity-extra-group_seqs", *case("parity", group_seqs=[0, 1])),
    ("parity-seq-string", *case("parity", seq_end="1")),
    ("status-extra-key", *case("status", hostname="high-side")),
    ("status-kind-unknown", *case("status", kind="resend-all")),
    ("status-kind-missing", *case("status", kind=_DEL)),
    ("status-have-negative", *case("status", have=-1)),
    ("status-have-string", *case("status", have="1")),
    ("status-have-over-total", *case("status", have=9)),
    ("status-total-negative", *case("status", total_chunks=-4)),
    ("status-missing-negative", *case("status", missing=[-1])),
    ("status-missing-unsorted", *case("status", missing=[1, 0])),
    ("status-missing-duplicate", *case("status", missing=[1, 1])),
    ("status-missing-string-items", *case("status", missing=["1"])),
    ("status-missing-not-list", *case("status", missing="1")),
    ("status-missing-too-many", *case("status", missing=list(range(5000)), total_chunks=6000, have=0)),
    ("status-reason-unknown", *case("status", kind="fail", reason="some traceback text")),
    ("status-reason-on-ok", *case("status", kind="ok", reason="io", missing=[])),
    ("status-ok-with-missing", *case("status", kind="ok", missing=[1])),
]
for _id, _t, _h, _b in _extra:
    BAD_FRAMES.append((_id, _t, _h, _b))
# status-body case above used a header key by mistake; real body case:
BAD_FRAMES = [x for x in BAD_FRAMES if x[0] != "status-body-nonempty"]
BAD_FRAMES.append(
    ("status-body-nonempty", FrameType.STATUS, valid_headers()["status"], b"leak")
)

# Raw header byte strings (JSON shape / encoding attacks).
RAW_BAD_HEADERS: list[tuple[str, bytes]] = [
    ("hdr-list", b"[]"),
    ("hdr-string", b'"x"'),
    ("hdr-int", b"5"),
    ("hdr-null", b"null"),
    ("hdr-true", b"true"),
    ("hdr-bad-utf8", b'\xff\xfe{"transfer_id":"a"}'),
    ("hdr-deep-nesting", b"[" * 30000 + b"]" * 30000),
    ("hdr-nan", b'{"transfer_id":"a","seq":NaN,"chunk_len":0}'),
    ("hdr-infinity", b'{"transfer_id":"a","seq":Infinity,"chunk_len":0}'),
    ("hdr-empty", b""),
]

# Cases whose decode currently succeeds with values a catcher would allocate
# against; they are checked at decode level only.
DANGEROUS_FOR_HANDLE = {
    "meta-total_chunks-huge",
    "meta-chunk_size-huge",
    "parity-range-huge",
    "meta-total_len-negative",
}


# ------------------------------------------------- P0 frame schema (decode)


@pytest.mark.parametrize(
    "ftype,header,body", [pytest.param(t, h, b, id=i) for i, t, h, b in BAD_FRAMES]
)
def test_decode_rejects_invalid_frame(ftype: FrameType, header: object, body: bytes) -> None:
    with pytest.raises(ProtocolError):
        decode_frame(wire(ftype, header, body))


@pytest.mark.parametrize("hdr", [pytest.param(b, id=i) for i, b in RAW_BAD_HEADERS])
@pytest.mark.parametrize("ftype", [FrameType.META, FrameType.DATA, FrameType.STATUS])
def test_decode_rejects_bad_header_encoding_and_shape(ftype: FrameType, hdr: bytes) -> None:
    with pytest.raises(ProtocolError):
        decode_frame(raw_frame(int(ftype), hdr))


def test_decode_accepts_every_valid_built_frame(payload: bytes) -> None:
    frames = build_transfer_frames("ok-1", payload, chunk_size=500, parity_group=3)
    for f in frames:
        assert decode_frame(f.encode()).type is f.type
    status = build_status_frame(
        StatusReport("ok-1", STATUS_HOLES, have=2, total_chunks=7, missing=(3, 5))
    )
    assert decode_frame(status.encode()).type is FrameType.STATUS


# --------------------------------------- P0 catcher survives hostile input


@pytest.mark.parametrize(
    "ftype,header,body",
    [
        pytest.param(t, h, b, id=i)
        for i, t, h, b in BAD_FRAMES
        if i not in DANGEROUS_FOR_HANDLE
    ],
)
def test_catcher_survives_hostile_frames_and_keeps_serving(
    tmp_path: Path, payload: bytes, ftype: FrameType, header: object, body: bytes
) -> None:
    c = new_catcher(tmp_path, disk_threshold_bytes=1000)
    c.handle(wire(ftype, header, body))
    for f in build_transfer_frames("good-1", payload, chunk_size=400):
        c.handle(f.encode())
    assert c.stats["published"] == 1
    assert (tmp_path / "out" / "good-1.bin").read_bytes() == payload


@pytest.mark.parametrize("tid", ["../pwned", "..", "ABS", "a/../../pwned"])
def test_transfer_id_cannot_escape_out_or_work_dir(
    tmp_path: Path, payload: bytes, tid: str
) -> None:
    if tid == "ABS":
        tid = str(tmp_path / "abs-pwned")
    out = tmp_path / "base" / "out"
    c = Catcher(
        out,
        tmp_path / "base" / "q",
        ttl_s=60,
        idle_exit_s=None,
        work_dir=tmp_path / "base" / "work",
        disk_threshold_bytes=1000,
    )
    for f in build_transfer_frames("placeholder", payload, chunk_size=400):
        c.handle(retag(f, tid))
    c.expire(force=True)
    assert c.stats["published"] == 0
    assert not (tmp_path / "base" / "pwned.bin").exists()
    assert not (tmp_path / "pwned.bin").exists()
    assert not (tmp_path / "base" / "pwned").exists()
    assert [p for p in tmp_path.rglob("*") if "pwned" in p.name] == []


def test_negative_seq_cannot_stand_in_for_a_missing_chunk(
    tmp_path: Path, payload: bytes
) -> None:
    frames = build_transfer_frames("neg-1", payload, chunk_size=800)
    c = new_catcher(tmp_path)
    data = [f for f in frames if f.type is FrameType.DATA]
    last = data[-1]
    for f in frames:
        if f is last:
            continue
        c.handle(f.encode())
    h = dict(last.header)
    h["seq"] = -1
    c.handle(wire(FrameType.DATA, h, last.body))
    assert c.stats["published"] == 0
    assert not published(tmp_path)


def test_out_of_range_seq_does_not_crash_disk_assembly(
    tmp_path: Path, payload: bytes
) -> None:
    frames = build_transfer_frames("oob-1", payload, chunk_size=800)
    c = new_catcher(tmp_path, disk_threshold_bytes=1, work_dir=tmp_path / "work")
    c.handle(frames[0].encode())
    c.handle(wire(FrameType.DATA, {"transfer_id": "oob-1", "seq": 50, "chunk_len": 3}, b"abc"))
    for f in frames[1:]:
        c.handle(f.encode())
    assert c.stats["published"] == 1


def test_data_body_must_match_meta_geometry(tmp_path: Path, payload: bytes) -> None:
    frames = build_transfer_frames("geo-1", payload, chunk_size=800)
    c = new_catcher(tmp_path)
    c.handle(frames[0].encode())
    # oversize body for seq 0 (declared chunk_size 800)
    c.handle(
        wire(
            FrameType.DATA,
            {"transfer_id": "geo-1", "seq": 0, "chunk_len": 900},
            b"\x00" * 900,
        )
    )
    for f in frames[1:]:
        c.handle(f.encode())
    assert c.stats["published"] == 1
    assert (tmp_path / "out" / "geo-1.bin").read_bytes() == payload


# ----------------------------------------------- P0 META / EOF authority


def keyed_catcher(tmp_path: Path) -> Catcher:
    return new_catcher(tmp_path, hmac_secret=SECRET)


def test_keyed_catcher_never_publishes_data_and_eof_without_meta(
    tmp_path: Path, payload: bytes
) -> None:
    frames = build_transfer_frames("nometa-1", payload, chunk_size=400, hmac_secret=SECRET)
    c = keyed_catcher(tmp_path)
    for f in frames:
        if f.type is not FrameType.META:
            c.handle(f.encode())
    assert c.stats["published"] == 0
    assert not published(tmp_path)


def test_unkeyed_catcher_also_requires_meta(tmp_path: Path, payload: bytes) -> None:
    frames = build_transfer_frames("nometa-2", payload, chunk_size=400)
    c = new_catcher(tmp_path)
    for f in frames:
        if f.type is not FrameType.META:
            c.handle(f.encode())
    assert c.stats["published"] == 0
    assert not published(tmp_path)


def test_attacker_eof_without_signed_meta_cannot_publish_attacker_object(
    tmp_path: Path,
) -> None:
    evil = b"attacker chosen bytes" * 20
    frames = build_transfer_frames("evil-1", evil, chunk_size=100)  # unsigned
    c = keyed_catcher(tmp_path)
    for f in frames:
        if f.type is not FrameType.META:
            c.handle(f.encode())
    assert not published(tmp_path)
    assert c.stats["published"] == 0


def test_conflicting_eof_cannot_override_signed_meta(
    tmp_path: Path, payload: bytes
) -> None:
    frames = build_transfer_frames("eofx-1", payload, chunk_size=800, hmac_secret=SECRET)
    meta = frames[0]
    data = [f for f in frames if f.type is FrameType.DATA]
    c = keyed_catcher(tmp_path)
    c.handle(meta.encode())
    for f in data[:-1]:
        c.handle(f.encode())
    forged_eof = wire(
        FrameType.EOF,
        {
            "transfer_id": "eofx-1",
            "total_chunks": len(data),
            "sha256": sha256_hex(b"something else"),
            "total_len": len(payload),
        },
    )
    c.handle(forged_eof)
    c.handle(data[-1].encode())
    assert c.stats["published"] == 1
    assert (tmp_path / "out" / "eofx-1.bin").read_bytes() == payload


def test_eof_total_len_and_chunks_cannot_change_geometry(
    tmp_path: Path, payload: bytes
) -> None:
    frames = build_transfer_frames("eofx-2", payload, chunk_size=800, hmac_secret=SECRET)
    data = [f for f in frames if f.type is FrameType.DATA]
    c = keyed_catcher(tmp_path)
    c.handle(frames[0].encode())
    c.handle(
        wire(
            FrameType.EOF,
            {
                "transfer_id": "eofx-2",
                "total_chunks": 2,
                "sha256": frames[0].header["sha256"],
                "total_len": 1000,
            },
        )
    )
    for f in data:
        c.handle(f.encode())
    assert c.stats["published"] == 1
    assert (tmp_path / "out" / "eofx-2.bin").read_bytes() == payload


@pytest.mark.parametrize(
    "variant",
    [
        {"chunk_size": 400},  # geometry recomputed to stay self-consistent
        {"parity_group": 4},
        {"content_type": "x/y"},
    ],
    ids=["chunk_size", "parity_group", "content_type"],
)
def test_unauthenticated_meta_fields_are_rejected(
    tmp_path: Path, payload: bytes, variant: dict
) -> None:
    frames = build_transfer_frames("tamper-1", payload, chunk_size=800, hmac_secret=SECRET)
    signed = frames[0].header
    chunk = variant.get("chunk_size", 800)
    n = -(-len(payload) // chunk)
    header = build_meta_header(
        "tamper-1",
        len(payload),
        n,
        signed["sha256"],
        chunk,
        len(payload) - (n - 1) * chunk,
        content_type=variant.get("content_type", signed["content_type"]),
        parity_group=variant.get("parity_group", 0),
    )
    header["hmac"] = signed["hmac"]  # signature of the original, valid-looking geometry
    c = keyed_catcher(tmp_path)
    c.handle(wire(FrameType.META, header))
    for f in frames[1:]:
        c.handle(f.encode())
    assert c.stats["hmac_fail"] >= 1
    assert c.stats["published"] == 0


def test_wrong_key_meta_is_rejected_and_right_key_still_works(
    tmp_path: Path, payload: bytes
) -> None:
    bad = build_transfer_frames("key-1", payload, chunk_size=500, hmac_secret=b"other")
    c = keyed_catcher(tmp_path)
    for f in bad:
        c.handle(f.encode())
    assert c.stats["published"] == 0
    good = build_transfer_frames("key-2", payload, chunk_size=500, hmac_secret=SECRET)
    for f in good:
        c.handle(f.encode())
    assert c.stats["published"] == 1


def test_second_conflicting_meta_does_not_replace_the_first(
    tmp_path: Path, payload: bytes
) -> None:
    frames = build_transfer_frames("imm-1", payload, chunk_size=800)
    forged = dict(frames[0].header)
    forged["sha256"] = sha256_hex(b"forged")
    c = new_catcher(tmp_path)
    c.handle(frames[0].encode())
    c.handle(wire(FrameType.META, forged))
    for f in frames[1:]:
        c.handle(f.encode())
    assert c.stats["published"] == 1


# ------------------------------------------------ P0 strict receipt schema


@pytest.mark.parametrize(
    "data",
    [
        {"transfer_id": "../x", "kind": "ok", "have": 1, "total_chunks": 1, "missing": []},
        {"transfer_id": "t", "kind": "ok", "have": "1", "total_chunks": 1, "missing": []},
        {"transfer_id": "t", "kind": "holes", "have": 0, "total_chunks": 9, "missing": ["1"]},
        {"transfer_id": "t", "kind": "holes", "have": 0, "total_chunks": 9, "missing": [-1]},
        {"transfer_id": "t", "kind": "holes", "have": 0, "total_chunks": 9, "missing": [1.5]},
        {"transfer_id": "t", "kind": "holes", "have": 0, "total_chunks": 9, "missing": [True]},
        {"transfer_id": "t", "kind": "holes", "have": 0, "total_chunks": 9, "missing": [2, 1]},
        {"transfer_id": "t", "kind": "holes", "have": 0, "total_chunks": 9, "missing": 3},
        {"transfer_id": "t", "kind": "holes", "have": 0, "total_chunks": 20000, "missing": list(range(10000))},
        {"transfer_id": "t", "kind": "holes", "have": 0, "total_chunks": 3, "missing": [7]},
        {"transfer_id": "t", "kind": "holes", "have": 9, "total_chunks": 3, "missing": [1]},
        {"transfer_id": "t", "kind": "fail", "have": 0, "total_chunks": 3, "missing": [], "reason": "free text"},
        {"transfer_id": "t", "kind": "ok", "have": 3, "total_chunks": 3, "missing": [1]},
        {"transfer_id": "t", "kind": "ok", "have": 3, "total_chunks": -3, "missing": []},
        {"transfer_id": 5, "kind": "ok", "have": 3, "total_chunks": 3, "missing": []},
    ],
    ids=lambda d: "-".join(str(v) for v in list(d.values())[:4])[:40],
)
def test_report_from_dict_rejects_instead_of_coercing(data: dict) -> None:
    with pytest.raises((ValueError, TypeError)):
        report_from_dict(data)


def test_receipt_store_rejects_traversal_ids(tmp_path: Path) -> None:
    store = ReceiptStore(tmp_path / "r")
    (tmp_path / "secret.json").write_text(
        json.dumps(
            {"transfer_id": "secret", "kind": "ok", "have": 1, "total_chunks": 1, "missing": []}
        )
    )
    with pytest.raises(ValueError):
        store.read("../secret")
    with pytest.raises(ValueError):
        store.write(StatusReport("../escape", STATUS_OK, have=1, total_chunks=1))
    assert not (tmp_path / "escape.json").exists()


def status_only(tmp_path: Path, secret: bytes | None = None) -> tuple[Catcher, ReceiptStore]:
    store = ReceiptStore(tmp_path / "rcpt")
    c = new_catcher(tmp_path, hmac_secret=secret)
    c.receipts = store
    c.status_only = True
    return c, store


def test_status_with_body_or_extra_fields_is_not_stored(tmp_path: Path) -> None:
    c, store = status_only(tmp_path)
    h = valid_headers("rcv-1")["status"]
    c.handle(wire(FrameType.STATUS, h, b"stolen secret"))
    c.handle(wire(FrameType.STATUS, {**h, "hostname": "high"}))
    assert store.list_reports() == []
    assert c.stats["receipts_written"] == 0


def test_status_for_unknown_transfer_is_not_stored(tmp_path: Path) -> None:
    c, store = status_only(tmp_path)
    c.active_ids = lambda tid: tid == "known-1"
    ok = StatusReport("other-1", STATUS_OK, have=3, total_chunks=3)
    c.handle(build_status_frame(ok).encode())
    assert store.read("other-1") is None
    ok2 = StatusReport("known-1", STATUS_OK, have=3, total_chunks=3)
    c.handle(build_status_frame(ok2).encode())
    assert store.read("known-1") is not None


def test_stale_holes_cannot_replace_a_terminal_ok(tmp_path: Path) -> None:
    c, store = status_only(tmp_path, secret=SECRET)
    holes = build_status_frame(
        StatusReport("rep-1", STATUS_HOLES, have=1, total_chunks=3, missing=(1, 2)),
        hmac_secret=SECRET,
    )
    ok = build_status_frame(
        StatusReport("rep-1", STATUS_OK, have=3, total_chunks=3), hmac_secret=SECRET
    )
    c.handle(holes.encode())
    c.handle(ok.encode())
    c.handle(holes.encode())  # replayed old receipt
    got = store.read("rep-1")
    assert got is not None and got.kind == STATUS_OK


def test_unsigned_status_rejected_when_keyed(tmp_path: Path) -> None:
    c, store = status_only(tmp_path, secret=SECRET)
    c.handle(build_status_frame(StatusReport("u-1", STATUS_OK, have=1, total_chunks=1)).encode())
    assert store.read("u-1") is None
    assert c.stats["hmac_fail"] >= 1


# ----------------------------------- P0 pitcher consumes receipts safely


def make_job(tmp_path: Path, payload: bytes, **kw) -> tuple[pitcher.ArqJob, Path]:
    src = tmp_path / "src.bin"
    src.write_bytes(payload)
    frames = build_transfer_frames("arq-1", payload, chunk_size=500)
    meta = frames[0]
    eof = frames[-1]
    store = ReceiptStore(tmp_path / "inbox")
    params = dict(
        transfer_id="arq-1",
        source=src,
        chunk_size=500,
        meta=meta,
        eof=eof,
        receipts=store,
        timeout_s=0.05,
        rounds=4,
        backoff=1.0,
        max_timeout_s=0.05,
    )
    params.update(kw)
    return pitcher.ArqJob(**params), tmp_path / "inbox"


def test_out_of_range_holes_are_never_read_or_sent(tmp_path: Path, payload: bytes) -> None:
    job, inbox = make_job(tmp_path, payload)  # 7 chunks of 500
    inbox.mkdir(exist_ok=True)
    (inbox / "arq-1.json").write_text(
        json.dumps(
            {
                "transfer_id": "arq-1",
                "kind": "holes",
                "have": 1,
                "total_chunks": 7,
                "missing": [-1, 2, 99999],
                "reason": None,
            }
        )
    )
    sock = FakeSock()
    rc = pitcher.watch_receipts_and_resend(sock, ("127.0.0.1", 9), job)
    assert rc in (0, 1, 2)
    assert set(data_seqs(sock)) <= {2}


def test_malformed_local_receipt_does_not_crash_pitcher(tmp_path: Path, payload: bytes) -> None:
    job, inbox = make_job(tmp_path, payload)
    inbox.mkdir(exist_ok=True)
    (inbox / "arq-1.json").write_text("{not json")
    rc = pitcher.watch_receipts_and_resend(FakeSock(), ("127.0.0.1", 9), job)
    assert rc in (0, 1, 2)


def test_receipt_for_other_geometry_is_not_acted_on(tmp_path: Path, payload: bytes) -> None:
    job, inbox = make_job(tmp_path, payload)
    inbox.mkdir(exist_ok=True)
    (inbox / "arq-1.json").write_text(
        json.dumps(
            {
                "transfer_id": "arq-1",
                "kind": "ok",
                "have": 3,
                "total_chunks": 3,  # job has 7 chunks: receipt is not about this object
                "missing": [],
                "reason": None,
            }
        )
    )
    rc = pitcher.watch_receipts_and_resend(FakeSock(), ("127.0.0.1", 9), job)
    assert rc != 0


# -------------------------------------------------------- P0 ARQ stalls


def test_unchanged_holes_receipt_is_resent_after_timeout(tmp_path: Path, payload: bytes) -> None:
    job, inbox = make_job(tmp_path, payload, rounds=5)
    inbox.mkdir(exist_ok=True)
    (inbox / "arq-1.json").write_text(
        json.dumps(
            {
                "transfer_id": "arq-1",
                "kind": "holes",
                "have": 6,
                "total_chunks": 7,
                "missing": [1],
                "reason": None,
            }
        )
    )
    sock = FakeSock()
    pitcher.watch_receipts_and_resend(sock, ("127.0.0.1", 9), job)
    assert data_seqs(sock).count(1) >= 2


class LinkSock:
    """Pitcher socket wired straight into a catcher; drops chosen DATA seqs."""

    def __init__(self, catcher: Catcher, drop_seq: int, drop_times: int) -> None:
        self.catcher = catcher
        self.drop_seq = drop_seq
        self.drop_times = drop_times
        self.dropped = 0

    def sendto(self, data: bytes, dest: object) -> int:
        f = decode_frame(data)
        if (
            f.type is FrameType.DATA
            and f.header["seq"] == self.drop_seq
            and self.dropped < self.drop_times
        ):
            self.dropped += 1
            return len(data)
        self.catcher.handle(data)
        return len(data)

    def setsockopt(self, *a: object) -> None:
        pass

    def close(self) -> None:
        pass


@pytest.mark.parametrize("drop_times", [1, 2, 3])
def test_lost_first_refill_still_recovers(tmp_path: Path, payload: bytes, drop_times: int) -> None:
    job, inbox = make_job(tmp_path, payload, rounds=10)
    c = new_catcher(tmp_path)
    c.receipts = ReceiptStore(inbox)
    c.receipt_every = 0
    link = LinkSock(c, drop_seq=1, drop_times=drop_times)
    frames = build_transfer_frames("arq-1", payload, chunk_size=500)
    for f in frames:
        link.sendto(f.encode(), None)
    rc = pitcher.watch_receipts_and_resend(link, ("127.0.0.1", 9), job)
    assert link.dropped == drop_times
    assert rc == 0
    assert c.stats["published"] == 1


@pytest.mark.parametrize("kind", [STATUS_OK, STATUS_HOLES])
def test_validate_pitcher_repeats_current_receipt_on_a_timer(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, kind: str
) -> None:
    inbox = tmp_path / "inbox"
    store = ReceiptStore(inbox)
    if kind == STATUS_OK:
        store.write(StatusReport("rep-9", STATUS_OK, have=3, total_chunks=3))
    else:
        store.write(StatusReport("rep-9", STATUS_HOLES, have=1, total_chunks=3, missing=(1, 2)))
    fake = FakeSock()
    monkeypatch.setattr(pitcher.socket, "socket", lambda *a, **k: fake)
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "pitcher.py",
            "--send-receipts",
            str(inbox),
            "--port",
            "9",
            "--receipt-copies",
            "1",
            "--receipt-poll",
            "0.05",
            "--max-seconds",
            "3.0",
        ],
    )
    assert pitcher.main() == 0
    kinds = [decode_frame(w).header["kind"] for w in fake.sent]
    assert kinds.count(kind) >= 2, f"receipt sent {kinds.count(kind)} time(s), never repeated"


def test_completed_transfer_answers_a_nudge_with_its_terminal_receipt(
    tmp_path: Path, payload: bytes
) -> None:
    frames = build_transfer_frames("done-1", payload, chunk_size=500)
    store = ReceiptStore(tmp_path / "rcpt")
    c = new_catcher(tmp_path)
    c.receipts = store
    c.receipt_every = 0
    for f in frames:
        c.handle(f.encode())
    assert store.read("done-1").kind == STATUS_OK
    (tmp_path / "rcpt" / "done-1.json").unlink()  # receipt lost / pruned
    time.sleep(0.6)  # nudges inside one burst are answered once
    c.handle(frames[-1].encode())  # sender nudge: EOF again
    got = store.read("done-1")
    assert got is not None and got.kind == STATUS_OK


# --------------------------------------------- P0 publish custody / fsync


def test_publish_orders_fsync_rename_dirsync_before_ok_receipt(
    tmp_path: Path, payload: bytes, monkeypatch: pytest.MonkeyPatch
) -> None:
    events: list[tuple] = []
    real_fsync, real_replace = os.fsync, os.replace

    def fsync(fd: int) -> None:
        st = os.fstat(fd)
        kind = "dir" if stat.S_ISDIR(st.st_mode) else "file"
        events.append(("fsync", kind, st.st_ino))
        real_fsync(fd)

    def replace(src, dst, *a, **k):  # type: ignore[no-untyped-def]
        events.append(("replace", str(src), str(dst)))
        return real_replace(src, dst, *a, **k)

    monkeypatch.setattr(os, "fsync", fsync)
    monkeypatch.setattr(os, "replace", replace)
    real_write = ReceiptStore.write

    def write(self, report):  # type: ignore[no-untyped-def]
        events.append(("receipt", report.kind))
        return real_write(self, report)

    monkeypatch.setattr(ReceiptStore, "write", write)

    c = new_catcher(tmp_path)
    c.receipts = ReceiptStore(tmp_path / "rcpt")
    c.receipt_every = 0
    for f in build_transfer_frames("fs-1", payload, chunk_size=500):
        c.handle(f.encode())
    final = tmp_path / "out" / "fs-1.bin"
    assert final.read_bytes() == payload
    out_ino = (tmp_path / "out").stat().st_ino
    final_ino = final.stat().st_ino

    rename_i = next(
        i
        for i, e in enumerate(events)
        if e[0] == "replace" and e[2].endswith("fs-1.bin") and e[1].endswith(".part")
    )
    assert any(
        e[0] == "fsync" and e[1] == "file" and e[2] == final_ino for e in events[:rename_i]
    ), "payload file was not fsynced before the rename"
    dir_after = [
        i
        for i, e in enumerate(events)
        if i > rename_i and e[0] == "fsync" and e[1] == "dir" and e[2] == out_ino
    ]
    assert dir_after, "output directory was not fsynced after the rename"
    ok_i = next(i for i, e in enumerate(events) if e == ("receipt", STATUS_OK))
    assert dir_after[0] < ok_i, "OK receipt written before the publish was durable"


def test_completion_survives_catcher_restart(tmp_path: Path, payload: bytes) -> None:
    frames = build_transfer_frames("rst-1", payload, chunk_size=500)
    c1 = new_catcher(tmp_path)
    for f in frames:
        c1.handle(f.encode())
    assert c1.stats["published"] == 1
    c2 = new_catcher(tmp_path)  # same directories, fresh process
    for f in frames:
        c2.handle(f.encode())
    assert c2.stats["published"] == 0
    assert c2.stats["duplicates"] >= 1
    assert (tmp_path / "out" / "rst-1.bin").read_bytes() == payload


def test_failure_is_not_left_at_final_path_when_rename_fails(
    tmp_path: Path, payload: bytes, monkeypatch: pytest.MonkeyPatch
) -> None:
    def boom(*a: object, **k: object) -> None:
        raise OSError("disk went away")

    monkeypatch.setattr(os, "replace", boom)
    c = new_catcher(tmp_path)
    for f in build_transfer_frames("part-1", payload, chunk_size=500):
        c.handle(f.encode())
    assert not (tmp_path / "out" / "part-1.bin").exists()
    assert c.stats["published"] == 0


def test_catcher_start_removes_stale_part_files(tmp_path: Path) -> None:
    out = tmp_path / "out"
    out.mkdir()
    (out / "old-1.bin.part").write_bytes(b"half written")
    new_catcher(tmp_path)
    assert not list(out.glob("*.part"))
