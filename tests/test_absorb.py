"""Ideas absorbed from lidi and datadiodefileproxy: interleaved FEC, per-frame auth,
drop reasons, heartbeat, MTU-derived chunk size, and the impairment relay.
"""
from __future__ import annotations

import os
import random
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import diode_config  # noqa: E402
from catcher import Catcher, kernel_udp_counters  # noqa: E402
from protocol import (  # noqa: E402
    MAX_CHUNK_SIZE,
    Frame,
    FrameAuthError,
    FrameType,
    ProtocolError,
    build_transfer_frames,
    chunk_for_mtu,
    decode_frame,
    drop_reason,
    frame_key,
    iter_data_and_parity_from_file,
    max_datagram_len,
    parity_groups,
    xor_bytes,
)
from soft_diode_relay import Impairment  # noqa: E402

SECRET = b"forward-key-0123456789"
KEY = frame_key(SECRET)


def catcher(tmp: Path, **kw) -> Catcher:
    return Catcher(tmp / "out", tmp / "q", 60.0, None, hmac_secret=SECRET, work_dir=tmp / "w", **kw)


def published(c: Catcher) -> list[Path]:
    return sorted(c.out_dir.glob("*.bin"))


# ------------------------------------------------------------------- XOR


def test_xor_matches_bytewise_reference():
    def slow(parts):
        acc = bytearray(max(len(p) for p in parts))
        for p in parts:
            for i, b in enumerate(p):
                acc[i] ^= b
        return bytes(acc)

    rng = random.Random(1)
    for _ in range(300):
        parts = [rng.randbytes(rng.randint(0, 64)) for _ in range(rng.randint(1, 6))]
        assert xor_bytes(parts) == slow(parts)
    assert xor_bytes([b"\x00\x00", b""]) == b"\x00\x00"  # width kept even when the XOR is zero


# --------------------------------------------------------- interleaved FEC


@pytest.mark.parametrize("n,k,d", [(1, 4, 8), (10, 4, 1), (100, 4, 8), (33, 3, 5), (64, 4, 16), (65, 4, 16)])
def test_parity_groups_cover_every_chunk_once(n, k, d):
    groups = list(parity_groups(n, k, d))
    assert sorted(s for g in groups for s in g) == list(range(n))
    assert all(len(g) <= k for g in groups)


def test_streamed_interleaved_parity_matches_in_memory(tmp_path):
    data = os.urandom(1200 * 77 + 5)
    src = tmp_path / "src.bin"
    src.write_bytes(data)
    fams = [(4, 8), (3, 9), (5, 1)]
    mem = {f.encode() for f in build_transfer_frames("t", data, 1200, parity_families=fams)
           if f.type is FrameType.PARITY}
    streamed = [f.encode() for f in iter_data_and_parity_from_file(src, "t", 1200, parity_families=fams)
                if f.type is FrameType.PARITY]
    assert mem == set(streamed) and len(streamed) == len(mem)
    legacy = [f.encode() for f in iter_data_and_parity_from_file(src, "t", 1200, 4)]
    assert legacy == [f.encode() for f in iter_data_and_parity_from_file(src, "t", 1200, parity_families=[(4, 1)])]


def _send_with_loss(c: Catcher, fams, lost) -> None:
    data = random.Random(7).randbytes(1200 * 200)
    for f in build_transfer_frames("burst", data, 1200, hmac_secret=SECRET, parity_families=fams):
        if f.type is FrameType.DATA and f.header["seq"] in lost:
            continue
        c.handle(f.encode())


def test_interleave_recovers_a_burst_plain_fec_cannot(tmp_path):
    burst = range(70, 86)  # 16 consecutive DATA frames
    plain = catcher(tmp_path / "plain")
    _send_with_loss(plain, [(4, 1)], burst)
    assert published(plain) == []
    inter = catcher(tmp_path / "inter")
    _send_with_loss(inter, [(4, 16)], burst)
    assert len(published(inter)) == 1
    assert inter.stats["fec_recovered"] == 16


def test_second_family_peels_what_one_family_cannot(tmp_path):
    lost = {3, 19}  # same (4, 16) group: one family alone is stuck
    one = catcher(tmp_path / "one")
    _send_with_loss(one, [(4, 16)], lost)
    assert published(one) == []
    two = catcher(tmp_path / "two")
    _send_with_loss(two, [(4, 16), (4, 17)], lost)
    assert len(published(two)) == 1
    # stride 17 puts 3 and 19 in different groups, each missing one member
    assert two.stats["fec_recovered"] == 2


def test_parity_must_match_declared_stride(tmp_path):
    c = catcher(tmp_path)
    data = os.urandom(1200 * 64)
    frames = build_transfer_frames("s", data, 1200, hmac_secret=SECRET, parity_families=[(4, 16)])
    c.handle(frames[0].encode())  # META declares stride 16
    plain = build_transfer_frames("s", data, 1200, parity_group=4, hmac_secret=SECRET)
    for f in plain:
        if f.type is FrameType.PARITY:
            c.handle(f.encode())
    assert c.stats["parity_rejected"] == 16
    bad = Frame(FrameType.PARITY, {"transfer_id": "s", "seq_start": 1, "seq_end": 33, "stride": 16},
                bytes(1200))  # group of 3, but the block holds 4
    c.handle(bad.encode())
    assert c.stats["parity_rejected"] == 17


def test_meta_families_are_signed_and_checked(tmp_path):
    c = catcher(tmp_path)
    frames = build_transfer_frames("m", os.urandom(5000), 1200, hmac_secret=SECRET, parity_families=[(4, 8), (4, 9)])
    meta = frames[0].header
    c.handle(Frame(FrameType.META, {**meta, "parity_families": [[4, 8]]}).encode())
    assert c.stats["hmac_fail"] == 1
    for bad in ([[4, 8], [5, 8]], [[1, 8]], [[4, 0]], [[4, 8]] * 5, [[4, 8, 1]], [["4", 8]], []):
        with pytest.raises(ProtocolError):
            Frame(FrameType.META, {**meta, "parity_families": bad}).encode()
    with pytest.raises(ProtocolError):
        Frame(FrameType.META, {**meta, "parity_group": 4}).encode()  # one source of truth


# ------------------------------------------------------------ frame auth


def _data(seq: int = 0) -> Frame:
    return Frame(FrameType.DATA, {"transfer_id": "a", "seq": seq, "chunk_len": 3}, b"abc")


def test_frame_auth_roundtrip_and_tamper():
    wire = _data().encode(KEY)
    assert decode_frame(wire, KEY, True).body == b"abc"
    assert decode_frame(wire).body == b"abc"  # a tag is skippable when nobody checks it
    with pytest.raises(FrameAuthError):
        decode_frame(wire, frame_key(b"some-other-key-000000"), True)
    with pytest.raises(FrameAuthError):
        decode_frame(_data().encode(), KEY, True)  # untagged, but auth required
    assert decode_frame(_data().encode(), KEY, False).body == b"abc"


def test_frame_auth_catches_body_swap_that_crc_allows():
    """The attack the tag exists for: rewrite a DATA body and fix up the CRC."""
    import zlib

    from protocol import AUTH_TAG_LEN, CRC_STRUCT

    wire = bytearray(_data().encode(KEY))
    body_at = wire.index(b"abc")
    wire[body_at : body_at + 3] = b"xyz"
    end = len(wire) - CRC_STRUCT.size
    wire[end:] = CRC_STRUCT.pack(zlib.crc32(bytes(wire[:end])) & 0xFFFFFFFF)
    assert AUTH_TAG_LEN == 16
    with pytest.raises(FrameAuthError):
        decode_frame(bytes(wire), KEY, True)


def test_unknown_flags_rejected():
    wire = bytearray(_data().encode())
    wire[5] = 0x02
    with pytest.raises(ProtocolError, match="unknown flags"):
        decode_frame(bytes(wire))


def test_catcher_counts_drops_by_reason(tmp_path):
    c = catcher(tmp_path, frame_key=KEY, require_frame_auth=True)
    c.handle(_data().encode())  # untagged
    c.handle(b"DIO1" + bytes(20))
    c.handle(b"short")
    good = bytearray(_data().encode(KEY))
    good[-1] ^= 1
    c.handle(bytes(good))
    assert c.drops == {"auth": 1, "legacy": 1, "length": 1, "crc": 1}
    assert c.stats["crc_fail"] == 4


def test_signed_transfer_with_frame_auth_publishes(tmp_path):
    c = catcher(tmp_path, frame_key=KEY, require_frame_auth=True)
    data = os.urandom(10_000)
    for f in build_transfer_frames("ok", data, 1200, hmac_secret=SECRET, parity_families=[(4, 2), (3, 5)]):
        c.handle(f.encode(KEY))
    assert [p.read_bytes() for p in published(c)] == [data]


def test_drop_reason_labels():
    assert drop_reason(FrameAuthError("x")) == "auth"
    assert drop_reason(ProtocolError("crc mismatch")) == "crc"
    assert drop_reason(ProtocolError("bad seq")) == "schema"


# -------------------------------------------------------------- heartbeat


def _hb(sender: str, seq: int) -> bytes:
    return Frame(FrameType.HEARTBEAT, {"sender": sender, "seq": seq}).encode(KEY)


def test_heartbeat_counts_gaps_replays_and_restarts(tmp_path):
    c = catcher(tmp_path, frame_key=KEY, require_frame_auth=True)
    a, b = "0" * 16, "f" * 16
    for seq in (0, 1, 4):
        c.handle(_hb(a, seq))
    c.handle(_hb(a, 4))  # replay
    c.handle(_hb(b, 0))  # sender restarted with a new id
    assert c.stats["heartbeats"] == 4
    assert c.stats["heartbeats_missed"] == 2
    assert c.stats["heartbeat_replays"] == 1
    assert c.heartbeat_at is not None
    with pytest.raises(ProtocolError):
        Frame(FrameType.HEARTBEAT, {"sender": "nothex", "seq": 0}).encode()


# ------------------------------------------------------------ MTU / config


@pytest.mark.parametrize("mtu", [576, 1280, 1420, 1500, 9000])
@pytest.mark.parametrize("auth", [False, True])
def test_chunk_for_mtu_is_the_largest_that_fits(mtu, auth):
    chunk = chunk_for_mtu(mtu, auth)
    assert max_datagram_len(chunk, auth) <= mtu - 28
    if chunk < MAX_CHUNK_SIZE:
        assert max_datagram_len(chunk + 1, auth) > mtu - 28


def _env(tmp: Path, **extra: str) -> dict:
    for name in ("token", "data"):
        (tmp / name).write_text(name * 16)
    return {
        "DIODE_MODE": "sender", "DIODE_STATE_DIR": str(tmp / "s"), "DIODE_DATA_PEER": "127.0.0.1:9400",
        "DIODE_API_TOKEN_FILE": str(tmp / "token"), "DIODE_DATA_KEY_FILE": str(tmp / "data"), **extra,
    }


def test_config_toggles(tmp_path):
    cfg = diode_config.load(_env(tmp_path))
    assert (cfg.frame_auth, cfg.parity_families, cfg.heartbeat_s, cfg.chunk_size) == (True, (), 5.0, 1200)
    cfg = diode_config.load(_env(tmp_path, DIODE_FEC_FAMILIES="12x64,12x72,12x80"))
    assert cfg.parity_families == ((12, 64), (12, 72), (12, 80))
    cfg = diode_config.load(_env(tmp_path, DIODE_CHUNK_SIZE="auto", DIODE_MTU="1420"))
    assert cfg.chunk_size == chunk_for_mtu(1420, True)
    cfg = diode_config.load(_env(tmp_path, DIODE_FRAME_AUTH="off", DIODE_HEARTBEAT_S="0"))
    assert (cfg.frame_auth, cfg.heartbeat_s) == (False, 0)
    with pytest.raises(diode_config.ConfigError, match="not both"):
        diode_config.load(_env(tmp_path, DIODE_FEC_FAMILIES="4x16", DIODE_PARITY_GROUP="4"))
    for bad in ("4x16,4x16", "1x16", "4x0", "4", "axb", "4x16,4x17,4x18,4x19,4x20"):
        with pytest.raises(diode_config.ConfigError, match="DIODE_FEC_FAMILIES"):
            diode_config.load(_env(tmp_path, DIODE_FEC_FAMILIES=bad))
    with pytest.raises(diode_config.ConfigError, match="DIODE_FRAME_AUTH"):
        diode_config.load(_env(tmp_path, DIODE_FRAME_AUTH="maybe"))


def test_secret_with_control_characters_is_refused(tmp_path):
    env = _env(tmp_path)
    (tmp_path / "token").write_text("a" * 16 + "\r\n" + "b" * 16 + "\n")  # trailing newline alone is fine
    with pytest.raises(diode_config.ConfigError, match="control characters"):
        diode_config.load(env)


def test_kernel_counters_shape():
    k = kernel_udp_counters()
    assert k is None or {"rcvbuf_errors", "in_errors"} <= k.keys()


# ------------------------------------------------------------ impairment


def test_impairment_loss_rate_and_burst_length():
    imp = Impairment(loss=0.05, burst=6, seed=3)
    fates = [bool(imp.process(b"x", 0.0)) for _ in range(200_000)]
    rate = fates.count(False) / len(fates)
    runs, run = [], 0
    for ok in fates:
        if not ok:
            run += 1
        elif run:
            runs.append(run)
            run = 0
    assert 0.04 < rate < 0.06
    assert 5 < sum(runs) / len(runs) < 7


def test_impairment_blackout_dup_reorder():
    imp = Impairment(blackout=(1.0, 2.0), seed=1)
    assert imp.process(b"a", 0.5) == [b"a"]
    assert imp.process(b"b", 1.5) == []
    assert imp.process(b"c", 3.0) == [b"c"]
    imp = Impairment(reorder=1.0, seed=1)
    assert imp.process(b"1", 0) == []
    assert imp.process(b"2", 0) == [b"2", b"1"]
    imp = Impairment(dup=1.0, seed=1)
    assert imp.process(b"d", 0) == [b"d", b"d"]
    with pytest.raises(ValueError):
        Impairment(loss=1.0)
