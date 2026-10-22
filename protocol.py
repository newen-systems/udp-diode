"""UDP diode frame protocol — lab simulation only.

Wire format (big-endian):
  magic(4)=DIO2 | type(1) | flags(1) | header_len(2) | body_len(4) | header_json | body | crc32(4)

The magic is the wire version. DIO1 peers (unauthenticated chunk geometry,
EOF-supplied metadata) are rejected with a clear error instead of being
silently downgraded to.

Types: META=1, DATA=2, EOF=3, PARITY=4, STATUS=5
CRC covers everything before the CRC field.

STATUS is the payload of the **validate track** (a second one-way stream,
high→low). The data track never sends or receives STATUS. Coordinators on
each side join the two tracks via local drop directories; a host that both
sends and receives is the exfil anti-pattern.

META is intentionally compact for multi‑GB transfers: fixed ``chunk_size`` +
``last_chunk_len`` (not a full ``chunk_lens[]`` array — that blows the 16-bit
header length limit around ~tens of MB payloads).

High-assurance properties this encodes:
  - integrity: per-datagram CRC32 + whole-payload sha256
  - completeness: total_chunks + seq set
  - optional FEC: XOR parity over groups of DATA chunks (recover 1 loss/group)
"""
from __future__ import annotations

import hashlib
import hmac as _hmac
import json
import re
import struct
import zlib
from dataclasses import dataclass
from enum import IntEnum
from pathlib import Path
from typing import Any, Iterator, Mapping

MAGIC = b"DIO2"
LEGACY_MAGIC = b"DIO1"
HEADER_STRUCT = struct.Struct("!4sBBHI")  # magic, type, flags, header_len, body_len
CRC_STRUCT = struct.Struct("!I")
# UDP practical body; leave room for IP/UDP + JSON DATA header under ~1500 MTU / WG.
DEFAULT_CHUNK_SIZE = 1200
# Soft limit for in-memory build_transfer_frames (tests / small lab only).
IN_MEMORY_MAX_BYTES = 32 * 1024 * 1024

# Hard bounds enforced by decode_frame, the one trust boundary. Operators set
# tighter policy limits on the catcher; these only cap what any input can ask for.
MAX_CHUNK_SIZE = 8192
MAX_CHUNKS = 1 << 26
MAX_TOTAL_LEN = MAX_CHUNKS * MAX_CHUNK_SIZE
MAX_PARITY_GROUP = 256
MAX_CONTENT_TYPE_LEN = 128
# Default IP MTU budget. Datagram = MTU - 20 (IPv4) - 8 (UDP).
DEFAULT_MTU = 1500
_TID_RE = re.compile(r"[A-Za-z0-9_-]{1,64}")
_HEX64_RE = re.compile(r"[0-9a-f]{64}")


class FrameType(IntEnum):
    META = 1
    DATA = 2
    EOF = 3
    PARITY = 4
    STATUS = 5


# Reverse-channel STATUS kinds. Keep this set closed: the pitcher treats
# unknown kinds as noise, not as a cue to resend the whole envelope.
STATUS_HOLES = "holes"
STATUS_OK = "ok"
STATUS_FAIL = "fail"
STATUS_KINDS = frozenset({STATUS_HOLES, STATUS_OK, STATUS_FAIL})
# Default hole window per STATUS datagram, and the hard maximum any receipt may carry.
STATUS_MISSING_CAP = 64
STATUS_MISSING_MAX = 128
# Closed set of failure reasons a receipt may carry. No free text crosses.
FAIL_REASONS = frozenset(
    {"integrity", "ttl", "hmac", "io", "shutdown_incomplete", "limit"}
)


class ProtocolError(ValueError):
    pass


@dataclass(frozen=True)
class Frame:
    type: FrameType
    header: dict[str, Any]
    body: bytes = b""

    def encode(self) -> bytes:
        # Validate on the way out too: a sender must not emit a frame that no
        # conforming receiver would accept.
        _check_header(self.type, self.header, self.body)
        header_bytes = json.dumps(self.header, separators=(",", ":"), sort_keys=True).encode(
            "utf-8"
        )
        if len(header_bytes) > 0xFFFF:
            raise ProtocolError(
                f"header too large for wire ({len(header_bytes)} > 65535); "
                "META must stay compact (no full chunk_lens for large files)"
            )
        prefix = HEADER_STRUCT.pack(
            MAGIC, int(self.type), 0, len(header_bytes), len(self.body)
        )
        payload = prefix + header_bytes + self.body
        return payload + CRC_STRUCT.pack(zlib.crc32(payload) & 0xFFFFFFFF)


def valid_transfer_id(value: object) -> bool:
    """Transfer ids become file names: ASCII letters, digits, '_' and '-', 1 to 64."""
    return type(value) is str and _TID_RE.fullmatch(value) is not None


def _int(h: Mapping[str, Any], key: str, lo: int, hi: int) -> int:
    value = h.get(key)
    if type(value) is not int or value < lo or value > hi:
        raise ProtocolError(f"bad {key}")
    return value


def _keys(h: Mapping[str, Any], required: frozenset, optional: frozenset = frozenset()) -> None:
    keys = h.keys()
    if not required <= keys:
        raise ProtocolError(f"missing header field {sorted(required - keys)[0]}")
    extra = keys - required - optional
    if extra:
        raise ProtocolError(f"unexpected header field {sorted(extra)[0]}")


def _hex64(value: object, name: str) -> str:
    if type(value) is not str or _HEX64_RE.fullmatch(value) is None:
        raise ProtocolError(f"bad {name}")
    return value


_META_REQ = frozenset(
    {
        "transfer_id",
        "total_len",
        "total_chunks",
        "sha256",
        "content_type",
        "chunk_size",
        "last_chunk_len",
        "parity_group",
    }
)
_DATA_REQ = frozenset({"transfer_id", "seq", "chunk_len"})
_EOF_REQ = frozenset({"transfer_id", "total_chunks", "sha256", "total_len"})
_PARITY_REQ = frozenset({"transfer_id", "seq_start", "seq_end"})
_STATUS_REQ = frozenset({"transfer_id", "kind", "have", "total_chunks", "missing"})
_STATUS_OPT = frozenset({"reason", "hmac"})
_HMAC_OPT = frozenset({"hmac"})


def check_meta_fields(h: Mapping[str, Any]) -> None:
    """Geometry must be self-consistent: chunk count and last chunk follow from total_len."""
    chunk = _int(h, "chunk_size", 1, MAX_CHUNK_SIZE)
    total_len = _int(h, "total_len", 0, MAX_TOTAL_LEN)
    n = _int(h, "total_chunks", 1, MAX_CHUNKS)
    last = _int(h, "last_chunk_len", 0, chunk)
    if n != max(1, -(-total_len // chunk)) or last != total_len - (n - 1) * chunk:
        raise ProtocolError("inconsistent META geometry")
    group = _int(h, "parity_group", 0, MAX_PARITY_GROUP)
    if group == 1:
        raise ProtocolError("bad parity_group")
    _hex64(h.get("sha256"), "sha256")
    ctype = h.get("content_type")
    if (
        type(ctype) is not str
        or len(ctype) > MAX_CONTENT_TYPE_LEN
        or not ctype.isascii()
        or not ctype.isprintable()
    ):
        raise ProtocolError("bad content_type")
    if "hmac" in h:
        _hex64(h["hmac"], "hmac")


def check_report_fields(
    transfer_id: object,
    kind: object,
    have: object,
    total_chunks: object,
    missing: object,
    reason: object,
) -> None:
    """Strict receipt schema shared by the wire decoder and the local drop-dir."""
    if not valid_transfer_id(transfer_id):
        raise ProtocolError("bad transfer_id")
    if type(kind) is not str or kind not in STATUS_KINDS:
        raise ProtocolError("bad status kind")
    if type(have) is not int or not 0 <= have <= MAX_CHUNKS:
        raise ProtocolError("bad have")
    if total_chunks is not None and (
        type(total_chunks) is not int or not 1 <= total_chunks <= MAX_CHUNKS
    ):
        raise ProtocolError("bad total_chunks")
    if total_chunks is not None and have > total_chunks:
        raise ProtocolError("have exceeds total_chunks")
    if type(missing) is not list or len(missing) > STATUS_MISSING_MAX:
        raise ProtocolError("bad missing list")
    prev = -1
    for item in missing:
        if type(item) is not int or item <= prev or item >= MAX_CHUNKS:
            raise ProtocolError("bad missing entry")
        if total_chunks is not None and item >= total_chunks:
            raise ProtocolError("missing entry beyond total_chunks")
        prev = item
    if kind != STATUS_HOLES and missing:
        raise ProtocolError("only holes carries a missing list")
    if kind == STATUS_OK and (total_chunks is None or have != total_chunks):
        raise ProtocolError("ok receipt must cover every chunk")
    if kind == STATUS_FAIL:
        if reason is not None and (type(reason) is not str or reason not in FAIL_REASONS):
            raise ProtocolError("bad fail reason")
    elif reason is not None:
        raise ProtocolError("reason only allowed on fail")


def _check_header(ftype: FrameType, h: Mapping[str, Any], body: bytes) -> None:
    tid = h.get("transfer_id")
    if not valid_transfer_id(tid):
        raise ProtocolError("bad transfer_id")
    if ftype is FrameType.DATA:
        _keys(h, _DATA_REQ)
        _int(h, "seq", 0, MAX_CHUNKS - 1)
        if _int(h, "chunk_len", 0, MAX_CHUNK_SIZE) != len(body):
            raise ProtocolError("chunk_len does not match body")
        return
    if ftype is FrameType.PARITY:
        _keys(h, _PARITY_REQ)
        start = _int(h, "seq_start", 0, MAX_CHUNKS - 1)
        _int(h, "seq_end", start, min(start + MAX_PARITY_GROUP - 1, MAX_CHUNKS - 1))
        if len(body) > MAX_CHUNK_SIZE:
            raise ProtocolError("parity body too large")
        return
    if body:
        raise ProtocolError(f"{ftype.name} frame must have an empty body")
    if ftype is FrameType.META:
        _keys(h, _META_REQ, _HMAC_OPT)
        check_meta_fields(h)
    elif ftype is FrameType.EOF:
        _keys(h, _EOF_REQ)
        _int(h, "total_chunks", 1, MAX_CHUNKS)
        _int(h, "total_len", 0, MAX_TOTAL_LEN)
        _hex64(h.get("sha256"), "sha256")
    else:
        _keys(h, _STATUS_REQ, _STATUS_OPT)
        check_report_fields(
            tid, h.get("kind"), h.get("have"), h.get("total_chunks"), h.get("missing"), h.get("reason")
        )
        if "hmac" in h:
            _hex64(h["hmac"], "hmac")


def _no_constant(name: str) -> None:
    raise ValueError(f"non-finite JSON constant {name}")


def decode_frame(datagram: bytes) -> Frame:
    """Parse and fully validate one datagram. Every later stage may trust the result."""
    if len(datagram) < HEADER_STRUCT.size + CRC_STRUCT.size:
        raise ProtocolError("datagram too short")
    magic, ftype, _flags, hlen, blen = HEADER_STRUCT.unpack_from(datagram, 0)
    if magic != MAGIC:
        if magic == LEGACY_MAGIC:
            raise ProtocolError("legacy DIO1 peer: wire version DIO2 is required")
        raise ProtocolError(f"bad magic {magic!r}")
    total = HEADER_STRUCT.size + hlen + blen + CRC_STRUCT.size
    if len(datagram) != total:
        raise ProtocolError(f"length mismatch got={len(datagram)} want={total}")
    crc_off = HEADER_STRUCT.size + hlen + blen
    (want_crc,) = CRC_STRUCT.unpack_from(datagram, crc_off)
    got_crc = zlib.crc32(datagram[:crc_off]) & 0xFFFFFFFF
    if want_crc != got_crc:
        raise ProtocolError("crc mismatch")
    try:
        t = FrameType(ftype)
    except ValueError as exc:
        raise ProtocolError(f"unknown type {ftype}") from exc
    try:
        header = json.loads(
            datagram[HEADER_STRUCT.size : HEADER_STRUCT.size + hlen].decode("utf-8"),
            parse_constant=_no_constant,
        )
    except (ValueError, RecursionError) as exc:
        raise ProtocolError("bad header json") from exc
    if type(header) is not dict:
        raise ProtocolError("header is not a JSON object")
    body = datagram[HEADER_STRUCT.size + hlen : crc_off]
    _check_header(t, header, body)
    return Frame(type=t, header=header, body=body)


def max_datagram_len(chunk_size: int) -> int:
    """Largest encoded DATA or PARITY datagram for this chunk size (worst-case header)."""
    tid = "x" * 64
    data = Frame(
        FrameType.DATA,
        {"transfer_id": tid, "seq": MAX_CHUNKS - 1, "chunk_len": chunk_size},
        b"\x00" * chunk_size,
    )
    parity = Frame(
        FrameType.PARITY,
        {"transfer_id": tid, "seq_start": MAX_CHUNKS - MAX_PARITY_GROUP, "seq_end": MAX_CHUNKS - 1},
        b"\x00" * chunk_size,
    )
    return max(len(data.encode()), len(parity.encode()))


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_file(path: Path, chunk_size: int = 1024 * 1024) -> tuple[str, int]:
    """Stream-hash a file; returns (hex_digest, size_bytes)."""
    h = hashlib.sha256()
    total = 0
    with path.open("rb") as fh:
        while True:
            block = fh.read(chunk_size)
            if not block:
                break
            h.update(block)
            total += len(block)
    return h.hexdigest(), total


_META_MAC_FIELDS = (
    "transfer_id",
    "total_len",
    "total_chunks",
    "sha256",
    "chunk_size",
    "last_chunk_len",
    "parity_group",
    "content_type",
)


def meta_hmac(secret: bytes, header: Mapping[str, Any]) -> str:
    """HMAC-SHA256 over every META field that shapes reconstruction (not just the digest)."""
    msg = "DIO2-META|" + "|".join(str(header[k]) for k in _META_MAC_FIELDS)
    return _hmac.new(secret, msg.encode("utf-8"), hashlib.sha256).hexdigest()


def verify_meta_hmac(secret: bytes, header: Mapping[str, Any]) -> bool:
    provided = header.get("hmac")
    if type(provided) is not str:
        return False
    return _hmac.compare_digest(meta_hmac(secret, header), provided)


@dataclass(frozen=True)
class StatusReport:
    """High→low receipt. ``missing`` is the next hole window, not the full gap set."""

    transfer_id: str
    kind: str
    have: int
    total_chunks: int | None = None
    missing: tuple[int, ...] = ()
    reason: str | None = None


def status_hmac(secret: bytes, report: StatusReport) -> str:
    """HMAC-SHA256 over stable STATUS fields (authenticity of the reverse channel)."""
    missing = ",".join(str(s) for s in report.missing)
    total = "" if report.total_chunks is None else str(report.total_chunks)
    reason = report.reason or ""
    msg = (
        f"DIO2-STATUS|{report.transfer_id}|{report.kind}|{report.have}|{total}|{missing}|{reason}"
    ).encode("utf-8")
    return _hmac.new(secret, msg, hashlib.sha256).hexdigest()


def verify_status_hmac(secret: bytes, report: StatusReport, provided: str) -> bool:
    return _hmac.compare_digest(status_hmac(secret, report), provided or "")


def build_status_frame(
    report: StatusReport, hmac_secret: bytes | None = None
) -> Frame:
    """Build a STATUS frame. Unknown kinds are rejected at build time."""
    if report.kind not in STATUS_KINDS:
        raise ProtocolError(f"unknown status kind {report.kind!r}")
    missing = tuple(sorted(report.missing)[:STATUS_MISSING_MAX])
    trimmed = StatusReport(
        transfer_id=report.transfer_id,
        kind=report.kind,
        have=report.have,
        total_chunks=report.total_chunks,
        missing=missing,
        reason=report.reason if report.kind == STATUS_FAIL else None,
    )
    header: dict[str, Any] = {
        "transfer_id": trimmed.transfer_id,
        "kind": trimmed.kind,
        "have": trimmed.have,
        "total_chunks": trimmed.total_chunks,
        "missing": list(trimmed.missing),
    }
    if trimmed.reason:
        header["reason"] = trimmed.reason
    if hmac_secret is not None:
        header["hmac"] = status_hmac(hmac_secret, trimmed)
    return Frame(type=FrameType.STATUS, header=header)


def status_report_from_frame(frame: Frame) -> StatusReport:
    """Frames from decode_frame are already validated; this is a typed projection."""
    if frame.type is not FrameType.STATUS:
        raise ProtocolError(f"not a STATUS frame: {frame.type}")
    h = frame.header
    check_report_fields(
        h.get("transfer_id"), h.get("kind"), h.get("have"),
        h.get("total_chunks"), h.get("missing"), h.get("reason"),
    )
    return StatusReport(
        transfer_id=h["transfer_id"],
        kind=h["kind"],
        have=h["have"],
        total_chunks=h["total_chunks"],
        missing=tuple(h["missing"]),
        reason=h.get("reason"),
    )


def iter_data_seqs_from_file(
    path: Path,
    transfer_id: str,
    seqs: list[int],
    chunk_size: int = DEFAULT_CHUNK_SIZE,
) -> Iterator[Frame]:
    """Seek-read selected DATA seqs from a file (ARQ fill; no full RAM)."""
    if chunk_size < 1:
        raise ValueError("chunk_size must be >= 1")
    with path.open("rb") as fh:
        for seq in seqs:
            if seq < 0:
                continue
            fh.seek(seq * chunk_size)
            body = fh.read(chunk_size)
            if not body and seq != 0:
                continue
            yield Frame(
                type=FrameType.DATA,
                header={
                    "transfer_id": transfer_id,
                    "seq": seq,
                    "chunk_len": len(body),
                },
                body=body,
            )


def chunk_payload(data: bytes, chunk_size: int) -> list[bytes]:
    if chunk_size < 1:
        raise ValueError("chunk_size must be >= 1")
    return [data[i : i + chunk_size] for i in range(0, len(data), chunk_size)] or [b""]


def expected_chunk_len(chunk_size: int, last_chunk_len: int, total_chunks: int, seq: int) -> int:
    """Authoritative body length for DATA seq (compact META model)."""
    if total_chunks <= 0:
        return 0
    if seq == total_chunks - 1:
        return last_chunk_len
    return chunk_size


def xor_bytes(parts: list[bytes]) -> bytes:
    """XOR equal-width byte strings (pad shorter with zeros to max length)."""
    if not parts:
        return b""
    width = max(len(p) for p in parts)
    acc = bytearray(width)
    for part in parts:
        for i, b in enumerate(part):
            acc[i] ^= b
    return bytes(acc)


def recover_missing_chunk(
    chunks: dict[int, bytes],
    missing_seq: int,
    parity_body: bytes,
    group_seqs: list[int],
    original_lens: dict[int, int],
) -> bytes:
    """Recover one missing DATA body from XOR parity of its group."""
    others = []
    for seq in group_seqs:
        if seq == missing_seq:
            continue
        if seq not in chunks:
            raise ValueError("cannot recover: more than one missing in group")
        others.append(chunks[seq])
    others.append(parity_body)
    recovered = xor_bytes(others)
    want = original_lens.get(missing_seq)
    if want is None:
        return recovered.rstrip(b"\x00")  # weak fallback
    return recovered[:want]


def build_meta_header(
    transfer_id: str,
    total_len: int,
    total_chunks: int,
    digest: str,
    chunk_size: int,
    last_chunk_len: int,
    content_type: str = "application/octet-stream",
    parity_group: int = 0,
    hmac_secret: bytes | None = None,
) -> dict[str, Any]:
    header: dict[str, Any] = {
        "transfer_id": transfer_id,
        "total_len": total_len,
        "total_chunks": total_chunks,
        "sha256": digest,
        "content_type": content_type,
        "chunk_size": chunk_size,
        "last_chunk_len": last_chunk_len,
        "parity_group": parity_group if parity_group > 1 else 0,
    }
    if hmac_secret is not None:
        header["hmac"] = meta_hmac(hmac_secret, header)
    return header


def build_transfer_frames(
    transfer_id: str,
    payload: bytes,
    chunk_size: int = DEFAULT_CHUNK_SIZE,
    content_type: str = "application/octet-stream",
    parity_group: int = 0,
    hmac_secret: bytes | None = None,
) -> list[Frame]:
    """Build META + DATA [+ PARITY] + EOF in memory (tests / small payloads).

    For large files use :func:`iter_transfer_frames_from_path` / pitcher streaming.
    """
    if len(payload) > IN_MEMORY_MAX_BYTES:
        raise ValueError(
            f"payload {len(payload)} exceeds in-memory limit {IN_MEMORY_MAX_BYTES}; "
            "use streaming pitcher for large files"
        )
    chunks = chunk_payload(payload, chunk_size)
    digest = sha256_hex(payload)
    last_len = len(chunks[-1]) if chunks else 0
    header = build_meta_header(
        transfer_id,
        len(payload),
        len(chunks),
        digest,
        chunk_size,
        last_len,
        content_type=content_type,
        parity_group=parity_group,
        hmac_secret=hmac_secret,
    )
    meta = Frame(type=FrameType.META, header=header)
    data_frames = [
        Frame(
            type=FrameType.DATA,
            header={
                "transfer_id": transfer_id,
                "seq": seq,
                "chunk_len": len(chunk),
            },
            body=chunk,
        )
        for seq, chunk in enumerate(chunks)
    ]
    out: list[Frame] = [meta, *data_frames]

    if parity_group > 1:
        for start in range(0, len(chunks), parity_group):
            group = list(range(start, min(start + parity_group, len(chunks))))
            bodies = [chunks[i] for i in group]
            out.append(
                Frame(
                    type=FrameType.PARITY,
                    header={
                        "transfer_id": transfer_id,
                        "seq_start": group[0],
                        "seq_end": group[-1],
                    },
                    body=xor_bytes(bodies),
                )
            )

    eof = Frame(
        type=FrameType.EOF,
        header={
            "transfer_id": transfer_id,
            "total_chunks": len(chunks),
            "sha256": digest,
            "total_len": len(payload),
        },
    )
    out.append(eof)
    return out


def file_transfer_stats(
    path: Path, chunk_size: int = DEFAULT_CHUNK_SIZE
) -> tuple[str, int, int, int]:
    """Return (sha256_hex, total_len, total_chunks, last_chunk_len) without full load."""
    if chunk_size < 1:
        raise ValueError("chunk_size must be >= 1")
    h = hashlib.sha256()
    total = 0
    chunks = 0
    last_len = 0
    with path.open("rb") as fh:
        while True:
            block = fh.read(chunk_size)
            if not block:
                break
            h.update(block)
            total += len(block)
            last_len = len(block)
            chunks += 1
    if chunks == 0:
        # empty file: one empty chunk
        chunks = 1
        last_len = 0
        h.update(b"")
    return h.hexdigest(), total, chunks, last_len


def iter_data_and_parity_from_file(
    path: Path,
    transfer_id: str,
    chunk_size: int = DEFAULT_CHUNK_SIZE,
    parity_group: int = 0,
) -> Iterator[Frame]:
    """Yield DATA and optional PARITY frames by streaming the file (no full RAM)."""
    group_seqs: list[int] = []
    group_bodies: list[bytes] = []
    seq = 0
    with path.open("rb") as fh:
        empty = True
        while True:
            body = fh.read(chunk_size)
            if not body:
                break
            empty = False
            yield Frame(
                type=FrameType.DATA,
                header={
                    "transfer_id": transfer_id,
                    "seq": seq,
                    "chunk_len": len(body),
                },
                body=body,
            )
            if parity_group > 1:
                group_seqs.append(seq)
                group_bodies.append(body)
                if len(group_bodies) >= parity_group:
                    yield Frame(
                        type=FrameType.PARITY,
                        header={
                            "transfer_id": transfer_id,
                            "seq_start": group_seqs[0],
                            "seq_end": group_seqs[-1],
                        },
                        body=xor_bytes(group_bodies),
                    )
                    group_seqs.clear()
                    group_bodies.clear()
            seq += 1
        if empty:
            yield Frame(
                type=FrameType.DATA,
                header={"transfer_id": transfer_id, "seq": 0, "chunk_len": 0},
                body=b"",
            )
            seq = 1
        if parity_group > 1 and group_bodies:
            yield Frame(
                type=FrameType.PARITY,
                header={
                    "transfer_id": transfer_id,
                    "seq_start": group_seqs[0],
                    "seq_end": group_seqs[-1],
                },
                body=xor_bytes(group_bodies),
            )
