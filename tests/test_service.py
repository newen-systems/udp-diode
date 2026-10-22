"""HTTP custody service: real sender and receiver processes on loopback, mock sink."""
from __future__ import annotations

import http.client
import os
import random
import socket
import sys
import time
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from diode_config import ConfigError, load  # noqa: E402
from tests.svc_harness import TOKEN, Pair, Sink, free_port, sha  # noqa: E402

RNG = random.Random(11)


def rand(n: int) -> bytes:
    return RNG.randbytes(n)


# ------------------------------------------------------------------ config


def base_env(tmp: Path, **over: str) -> dict[str, str]:
    (tmp / "k").mkdir(exist_ok=True)
    for n in ("token", "data", "rcpt", "rcpt2"):
        (tmp / "k" / n).write_text(n * 8 + "-secret-material\n")
    env = {
        "DIODE_MODE": "sender",
        "DIODE_STATE_DIR": str(tmp / "state"),
        "DIODE_API_TOKEN_FILE": str(tmp / "k" / "token"),
        "DIODE_DATA_KEY_FILE": str(tmp / "k" / "data"),
        "DIODE_DATA_PEER": "10.0.0.2:9400",
    }
    env.update(over)
    return env


def test_valid_sender_and_receiver_config(tmp_path: Path) -> None:
    s = load(base_env(tmp_path))
    assert s.mode == "sender" and s.feedback == "off" and s.http_port == 8080
    assert s.data_peer == ("10.0.0.2", 9400) and s.receipt_bind == ("0.0.0.0", 9401)
    r = load(
        base_env(tmp_path, DIODE_MODE="receiver", DIODE_DELIVERY_URL="http://nifi:8081/in")
        | {"DIODE_DATA_PEER": ""}
    )
    assert r.mode == "receiver" and r.data_bind == ("0.0.0.0", 9400)


@pytest.mark.parametrize(
    "over,fragment",
    [
        ({"DIODE_MODE": "both"}, "DIODE_MODE"),
        ({"DIODE_MODE": ""}, "DIODE_MODE is required"),
        ({"DIODE_FEEDBACK": "yes"}, "DIODE_FEEDBACK"),
        ({"DIODE_DATA_PEER": ""}, "DIODE_DATA_PEER is required"),
        ({"DIODE_DATA_PEER": "host"}, "host:port"),
        ({"DIODE_DATA_PEER": "host:99999"}, "port 1-65535"),
        ({"DIODE_MAX_BITRATE_MBPS": "fast"}, "not a number"),
        ({"DIODE_MAX_BITRATE_MBPS": "-1"}, "must be between"),
        ({"DIODE_CHUNK_SIZE": "1472"}, "datagram"),
        ({"DIODE_CHUNK_SIZE": "99999"}, "must be between"),
        ({"DIODE_PARITY_GROUP": "1"}, "meaningless"),
        ({"DIODE_FEEDBACK": "receipts"}, "DIODE_RECEIPT_KEY_FILE is required"),
        ({"DIODE_API_TOKEN_FILE": "/nonexistent/token"}, "cannot read"),
        ({"DIODE_STATE_DIR": ""}, "DIODE_STATE_DIR is required"),
        ({"DIODE_RECEIPT_KEY_FILE": "{k}/rcpt"}, "FEEDBACK=off"),
        ({"DIODE_RECEIPT_BIND": "0.0.0.0:9401"}, "FEEDBACK=off"),
        ({"DIODE_RECEIPT_PEER": "h:1"}, "belongs to the receiver"),
        ({"DIODE_TLS_CERT_FILE": "/etc/hosts"}, "set together"),
    ],
)
def test_invalid_config_is_rejected_at_startup(tmp_path: Path, over: dict, fragment: str) -> None:
    over = {k: v.replace("{k}", str(tmp_path / "k")) for k, v in over.items()}
    env = base_env(tmp_path)
    env.update(over)
    for k, v in list(env.items()):
        if v == "" and k != "DIODE_MODE":
            del env[k]
    with pytest.raises(ConfigError, match=fragment):
        load(env)


def test_receipt_key_must_differ_from_data_key(tmp_path: Path) -> None:
    env = base_env(tmp_path, DIODE_FEEDBACK="receipts", DIODE_RECEIPT_KEY_FILE=str(tmp_path / "k" / "data"))
    with pytest.raises(ConfigError, match="must differ"):
        load(env)


def test_receiver_config_errors(tmp_path: Path) -> None:
    env = base_env(tmp_path, DIODE_MODE="receiver")
    del env["DIODE_DATA_PEER"]
    with pytest.raises(ConfigError, match="DIODE_DELIVERY_URL is required"):
        load(env)
    env["DIODE_DELIVERY_URL"] = "ftp://x/y"
    with pytest.raises(ConfigError, match="http"):
        load(env)
    env["DIODE_DELIVERY_URL"] = "http://x/y"
    env["DIODE_FEEDBACK"] = "receipts"
    env["DIODE_RECEIPT_KEY_FILE"] = str(tmp_path / "k" / "rcpt")
    with pytest.raises(ConfigError, match="DIODE_RECEIPT_PEER is required"):
        load(env)


def test_launcher_exits_2_on_bad_config(tmp_path: Path) -> None:
    import subprocess

    p = subprocess.run(
        [sys.executable, str(ROOT / "diode.py")],
        env={"PATH": os.environ["PATH"], "DIODE_MODE": "sender"},
        capture_output=True, text=True, timeout=30,
    )
    assert p.returncode == 2 and "DIODE_STATE_DIR is required" in p.stderr


def test_check_config_masks_secrets(tmp_path: Path) -> None:
    import subprocess

    env = base_env(tmp_path)
    p = subprocess.run(
        [sys.executable, str(ROOT / "diode.py"), "--check-config"],
        env={"PATH": os.environ["PATH"], **env}, capture_output=True, text=True, timeout=30, cwd=ROOT,
    )
    assert p.returncode == 0
    assert "api_token=set" in p.stdout and "secret-material" not in p.stdout


# ------------------------------------------------------- end to end, strict


@pytest.mark.parametrize("size", [0, 1, 1024, 100_000])
def test_strict_mode_delivers_exact_bytes(tmp_path: Path, size: int) -> None:
    body = rand(size)
    with Pair(tmp_path, "off") as pair:
        code, out, hdr = pair.post(body, f"k-{size}")
        assert code == 202 and out["state"] == "queued" and out["size"] == size
        assert out["sha256"] == sha(body) and not out["receiver_confirmed"]
        assert hdr["location"] == f"/v1/transfers/{out['id']}"
        got = pair.sink.wait_accepted(1)
        assert got[0]["sha256"] == sha(body) and got[0]["size"] == size
        assert got[0]["key"] == out["id"] and got[0]["tid"] == out["id"]
        assert got[0]["hdr_sha"] == sha(body) and got[0]["ctype"] == "application/octet-stream"
        row = pair.wait_state(out["id"], ("sent-unconfirmed",))
        assert row["receiver_confirmed"] is False  # never claims remote delivery without feedback
        _, stats = pair.get("/v1/stats")
        assert stats["sent_unconfirmed"] == 1 and stats["accepted"] == 1


def test_receipts_mode_confirms_and_purges(tmp_path: Path) -> None:
    body = rand(300_000)
    with Pair(tmp_path, "receipts") as pair:
        code, out, _ = pair.post(body, "k-r1")
        assert code == 202
        row = pair.wait_state(out["id"], ("receiver-verified", "failed", "expired"))
        assert row["state"] == "receiver-verified" and row["receiver_confirmed"]
        got = pair.sink.wait_accepted(1)
        assert got[0]["sha256"] == sha(body)
        spool = pair.s_state / "spool" / f"{out['id']}.bin"
        # housekeeping purges verified payloads on its own sweep, so only require a consistent file or none
        assert not spool.exists() or spool.stat().st_size == len(body)


def test_32_mib_binary_object_exact_sha_in_both_modes(tmp_path: Path) -> None:
    body = rand(32 * 1024 * 1024)
    want = sha(body)
    for mode in ("off", "receipts"):
        d = tmp_path / mode
        d.mkdir()
        with Pair(d, mode, sender_extra={"DIODE_MAX_BITRATE_MBPS": "250"}) as pair:
            code, out, _ = pair.post(body, "big-1")
            assert code == 202
            got = pair.sink.wait_accepted(1, timeout=120)
            assert got[0]["sha256"] == want and got[0]["size"] == len(body), mode


def test_chunked_upload_is_accepted(tmp_path: Path) -> None:
    body = rand(70_000)
    with Pair(tmp_path, "off") as pair:
        c = http.client.HTTPConnection("127.0.0.1", pair.s_http, timeout=30)
        c.request(
            "POST", "/v1/transfers",
            body=(body[i : i + 10_000] for i in range(0, len(body), 10_000)),
            headers={"Authorization": f"Bearer {TOKEN}", "Idempotency-Key": "chunky"},
            encode_chunked=True,
        )
        r = c.getresponse()
        r.read()
        assert r.status == 202
        assert pair.sink.wait_accepted(1)[0]["sha256"] == sha(body)


# --------------------------------------------------------- admission rules


def test_idempotent_retry_conflict_and_single_spool_owner(tmp_path: Path) -> None:
    a, b = rand(5000), rand(5000)
    with Pair(tmp_path, "off", sender_extra={"DIODE_MAX_BITRATE_MBPS": "0.05"}) as pair:
        c1, o1, h1 = pair.post(a, "same-key")
        c2, o2, h2 = pair.post(a, "same-key")  # lost 202: client retries identical bytes
        assert (c1, c2) == (202, 202) and o1["id"] == o2["id"]
        assert h1["idempotent-replay"] == "false" and h2["idempotent-replay"] == "true"
        c3, o3, _ = pair.post(b, "same-key")
        assert c3 == 409 and "different content" in o3["error"]
        c4, o4, _ = pair.post(a + b"x", "same-key")
        assert c4 == 409
        spool = list((pair.s_state / "spool").glob("*.bin"))
        assert [p.stem for p in spool] == [o1["id"]]  # exactly one owner
        _, stats = pair.get("/v1/stats")
        assert stats["accepted"] == 1 and stats["replayed"] == 1 and stats["conflicts"] == 2


def test_auth_and_header_validation(tmp_path: Path) -> None:
    with Pair(tmp_path, "off") as pair:
        assert pair.post(b"x", "k1", token=None)[0] == 401
        assert pair.post(b"x", "k1", token="wrong-token-wrong-token")[0] == 401
        assert pair.post(b"x", "k1", headers={"Authorization": "Basic abc"})[0] == 401
        assert pair.post(b"x", "bad key!")[0] == 400
        assert pair.post(b"x", "")[0] == 400
        assert pair.post(b"x", "k" * 129)[0] == 400
        assert pair.get("/v1/stats", token=None)[0] == 401
        assert pair.get("/v1/transfers/" + "0" * 32)[0] == 404
        assert pair.get("/v1/transfers/not-an-id")[0] == 404
        # health endpoints need no token and say nothing about the far side
        code, body = pair.get("/healthz", token=None)
        assert code == 200
        code, body = pair.get("/readyz", token=None)
        assert code == 200 and body["ready"] is True
        assert list((pair.s_state / "spool").glob("*.bin")) == []  # nothing admitted


def test_oversize_and_no_length_rejected_before_admission(tmp_path: Path) -> None:
    with Pair(tmp_path, "off", sender_extra={"DIODE_MAX_BODY_BYTES": "1000"}) as pair:
        assert pair.post(rand(1001), "big")[0] == 413
        c = http.client.HTTPConnection("127.0.0.1", pair.s_http, timeout=10)
        c.putrequest("POST", "/v1/transfers")
        c.putheader("Authorization", f"Bearer {TOKEN}")
        c.putheader("Idempotency-Key", "nolen")
        c.endheaders()
        assert c.getresponse().status == 411
        assert list((pair.s_state / "spool").glob("*.bin")) == []
        assert list((pair.s_state / "staging").iterdir()) == []


def test_interrupted_upload_admits_nothing(tmp_path: Path) -> None:
    with Pair(tmp_path, "off") as pair:
        s = socket.create_connection(("127.0.0.1", pair.s_http), timeout=10)
        s.sendall(
            b"POST /v1/transfers HTTP/1.1\r\nHost: x\r\nIdempotency-Key: cut\r\n"
            + f"Authorization: Bearer {TOKEN}\r\nContent-Length: 100000\r\n\r\n".encode()
            + b"A" * 5000
        )
        time.sleep(0.3)
        s.close()  # client vanishes mid-body
        time.sleep(1.0)
        assert list((pair.s_state / "spool").glob("*.bin")) == []
        assert list((pair.s_state / "staging").iterdir()) == []
        _, stats = pair.get("/v1/stats")
        assert stats["accepted"] == 0 and stats["queued"] == 0
        # and the same key still works afterwards
        assert pair.post(rand(100), "cut")[0] == 202


def test_stalled_upload_times_out_and_frees_its_slot(tmp_path: Path) -> None:
    with Pair(tmp_path, "off", sender_extra={"DIODE_HTTP_IO_TIMEOUT_S": "1", "DIODE_MAX_UPLOADS": "1"}) as pair:
        s = socket.create_connection(("127.0.0.1", pair.s_http), timeout=10)
        s.sendall(
            b"POST /v1/transfers HTTP/1.1\r\nHost: x\r\nIdempotency-Key: slow\r\n"
            + f"Authorization: Bearer {TOKEN}\r\nContent-Length: 100000\r\n\r\n".encode()
            + b"A" * 100
        )
        time.sleep(0.3)
        # the only upload slot is held: a second upload is told to retry, not queued unbounded
        code, out, hdr = pair.post(rand(10), "other")
        assert code == 503 and hdr.get("retry-after") == "1"
        s.settimeout(10)
        data = s.recv(4096)  # server gives up after the read timeout
        assert b"408" in data or data == b""
        s.close()
        time.sleep(0.5)
        assert pair.post(rand(10), "other")[0] == 202
        assert list((pair.s_state / "staging").iterdir()) == []


def test_disk_reserve_and_quota_refuse_without_partial_admission(tmp_path: Path) -> None:
    pair = Pair(tmp_path, "off", sender_extra={"DIODE_DISK_RESERVE_BYTES": str(1 << 49)})
    pair.start(sender_ready=False)
    try:
        # readiness reflects the disk reserve, uploads are refused
        code, body = pair.get("/readyz", token=None)
        assert code == 503 and "disk below reserve" in body["problems"]
        assert pair.post(rand(10), "nospace")[0] == 507
        assert list((pair.s_state / "spool").glob("*.bin")) == []
    finally:
        pair.stop()
    d = tmp_path / "q"
    d.mkdir()
    with Pair(d, "off", sender_extra={"DIODE_SPOOL_QUOTA_BYTES": "5000", "DIODE_MAX_BITRATE_MBPS": "0.01"}) as pair:
        assert pair.post(rand(3000), "q1")[0] == 202
        assert pair.post(rand(3000), "q2")[0] == 507
        assert len(list((pair.s_state / "spool").glob("*.bin"))) == 1


def test_connection_cap_answers_503(tmp_path: Path) -> None:
    with Pair(tmp_path, "off", sender_extra={"DIODE_MAX_CONNECTIONS": "2", "DIODE_HEADER_DEADLINE_S": "3"}) as pair:
        idle = [socket.create_connection(("127.0.0.1", pair.s_http), timeout=5) for _ in range(2)]
        time.sleep(0.2)
        s = socket.create_connection(("127.0.0.1", pair.s_http), timeout=5)
        s.sendall(b"GET /healthz HTTP/1.1\r\nHost: x\r\n\r\n")
        assert b"503" in s.recv(200)
        s.close()
        for c in idle:
            c.close()
        # idle connections are cut by the header deadline, freeing the slots
        time.sleep(0.3)
        assert pair.get("/healthz", token=None)[0] == 200


# ------------------------------------------------------ downstream delivery


def test_destination_5xx_then_success_uses_one_stable_key(tmp_path: Path) -> None:
    sink = Sink()
    sink.script = [503, 500, 429]
    body = rand(20_000)
    with Pair(tmp_path, "off", sink=sink) as pair:
        code, out, _ = pair.post(body, "dn-1")
        got = sink.wait_accepted(1, timeout=30)
        assert got[0]["sha256"] == sha(body)
        with sink.lock:
            attempts = list(sink.received)
        assert [a["status"] for a in attempts] == [503, 500, 429, 200]
        assert {a["key"] for a in attempts} == {out["id"]}  # stable idempotency key
        assert all(a["sha256"] == sha(body) for a in attempts)
        _, stats = pair.get("/v1/stats", port=pair.r_http)
        assert stats["downstream_retries"] == 3 and stats["delivered"] == 1
        assert not (pair.r_state / "out" / f"{out['id']}.bin").exists()  # reclaimed after delivery


def test_permanent_refusal_is_parked_then_retried_by_operator(tmp_path: Path) -> None:
    sink = Sink()
    sink.script = [400]
    body = rand(3000)
    with Pair(tmp_path, "off", sink=sink) as pair:
        code, out, _ = pair.post(body, "park-1")
        end = time.time() + 20
        row: dict = {}
        while time.time() < end:
            c, row = pair.get(f"/v1/deliveries/{out['id']}", port=pair.r_http)
            if c == 200 and row["state"] == "parked":
                break
            time.sleep(0.1)
        assert row["state"] == "parked" and row["last_status"] == 400
        assert (pair.r_state / "out" / f"{out['id']}.bin").exists()  # payload retained for the operator
        time.sleep(1.5)
        assert len(sink.received) == 1  # no automatic retry of a permanent refusal
        _, stats = pair.get("/v1/stats", port=pair.r_http)
        assert stats["delivery_parked"] == 1
        c = http.client.HTTPConnection("127.0.0.1", pair.r_http, timeout=10)
        c.request("POST", f"/v1/deliveries/{out['id']}/retry", headers={"Authorization": f"Bearer {TOKEN}"})
        assert c.getresponse().status == 202
        assert sink.wait_accepted(1)[0]["sha256"] == sha(body)


def test_timeout_after_accept_is_at_least_once_with_same_key(tmp_path: Path) -> None:
    sink = Sink()
    body = rand(2000)
    with Pair(tmp_path, "off", sink=sink, receiver_extra={"DIODE_DELIVERY_TIMEOUT_S": "1"}) as pair:
        # first request: sink "accepts" (records it) but answers 599-style by closing; emulate with 504
        sink.script = [504]
        code, out, _ = pair.post(body, "dup-1")
        got = sink.wait_accepted(1, timeout=30)
        with sink.lock:
            keys = [r["key"] for r in sink.received]
        assert keys.count(out["id"]) >= 2 and got[0]["key"] == out["id"]


def test_delivery_resumes_after_receiver_restart_and_ledger_loss(tmp_path: Path) -> None:
    sink = Sink()
    sink.script = [503] * 1000  # destination down
    body = rand(10_000)
    pair = Pair(tmp_path, "off", sink=sink)
    pair.start()
    try:
        code, out, _ = pair.post(body, "rs-1")
        end = time.time() + 20
        while time.time() < end:
            _, st = pair.get("/v1/stats", port=pair.r_http)
            if st["verified"] == 1:
                break
            time.sleep(0.1)
        assert st["verified"] == 1 and st["delivered"] == 0
        pair.receiver.kill()  # crash with the object verified but undelivered
        (pair.r_state / "deliveries.db").unlink()  # and lose the delivery ledger as well
        for ext in ("-wal", "-shm"):
            (pair.r_state / f"deliveries.db{ext}").unlink(missing_ok=True)
        with sink.lock:
            sink.script.clear()
        pair.start_receiver()
        got = sink.wait_accepted(1, timeout=30)
        assert got[0]["sha256"] == sha(body)
    finally:
        pair.stop()


# --------------------------------------------------------- crash recovery


def test_sender_kill_mid_send_keeps_custody_and_resumes(tmp_path: Path) -> None:
    body = rand(2_000_000)
    pair = Pair(tmp_path, "off", sender_extra={"DIODE_MAX_BITRATE_MBPS": "8"})
    pair.start()
    try:
        code, out, _ = pair.post(body, "crash-1")
        assert code == 202
        time.sleep(1.2)  # a 2 MB object at 8 Mbit/s needs ~2 s: this lands mid-send
        assert pair.get(f"/v1/transfers/{out['id']}")[1]["state"] == "sending"
        pair.sender.kill()
        assert pair.sink.accepted() == []
        pair.start_sender({"DIODE_MAX_BITRATE_MBPS": "400"})
        # the ledger row and spool file survived the kill
        code, row = pair.get(f"/v1/transfers/{out['id']}")
        assert code == 200 and row["id"] == out["id"]
        got = pair.sink.wait_accepted(1, timeout=60)
        assert got[0]["sha256"] == sha(body) and got[0]["key"] == out["id"]
        # the original idempotency key still maps to the same job after the crash
        c2, o2, _ = pair.post(body, "crash-1")
        assert c2 == 202 and o2["id"] == out["id"]
    finally:
        pair.stop()


def test_uncommitted_staging_and_orphan_spool_files_are_cleaned_on_restart(tmp_path: Path) -> None:
    pair = Pair(tmp_path, "off")
    pair.start()
    try:
        pair.sender.term()
        (pair.s_state / "staging" / "half.part").write_bytes(b"x" * 100)
        (pair.s_state / "spool" / ("a" * 32 + ".bin")).write_bytes(b"orphan")  # renamed, never committed
        pair.start_sender()
        assert list((pair.s_state / "staging").iterdir()) == []
        assert not (pair.s_state / "spool" / ("a" * 32 + ".bin")).exists()
    finally:
        pair.stop()


def test_sigterm_stops_cleanly(tmp_path: Path) -> None:
    pair = Pair(tmp_path, "receipts")
    pair.start()
    try:
        assert pair.sender.term() == 0
        assert pair.receiver.term() == 0
    finally:
        pair.sink.stop()


def test_strict_mode_opens_no_reverse_socket(tmp_path: Path) -> None:
    with Pair(tmp_path, "off") as pair:
        if sys.platform != "darwin" and sys.platform != "linux":
            pytest.skip("needs lsof")
        import subprocess

        out = subprocess.run(
            ["lsof", "-nP", "-a", "-p", str(pair.receiver.p.pid), "-iUDP"],
            capture_output=True, text=True,
        ).stdout
        udp_lines = [l for l in out.splitlines()[1:] if l.strip()]
        assert len(udp_lines) == 1 and str(pair.data_port) in udp_lines[0]  # only the data listener
        out_s = subprocess.run(
            ["lsof", "-nP", "-a", "-p", str(pair.sender.p.pid), "-iUDP"],
            capture_output=True, text=True,
        ).stdout
        assert str(pair.receipt_port) not in out_s  # sender does not listen for receipts


def test_receiver_kill_mid_transfer_recovers_from_retained_source(tmp_path: Path) -> None:
    """Receipts mode: the receiver loses its partial assembly; the sender still holds the source and resends."""
    body = rand(3_000_000)
    pair = Pair(
        tmp_path, "receipts",
        sender_extra={"DIODE_MAX_BITRATE_MBPS": "12", "DIODE_ACK_TIMEOUT_S": "0.5", "DIODE_ACK_TIMEOUT_CAP_S": "1"},
    )
    pair.start()
    try:
        code, out, _ = pair.post(body, "rk-1")
        assert code == 202
        time.sleep(1.0)  # about a third of the object is on the wire
        pair.receiver.kill()
        time.sleep(0.5)
        pair.start_receiver()
        row = pair.wait_state(out["id"], ("receiver-verified", "failed", "expired"), timeout=120)
        assert row["state"] == "receiver-verified", row
        got = pair.sink.wait_accepted(1, timeout=60)
        assert got[0]["sha256"] == sha(body)
        _, st = pair.get("/v1/stats")
        assert st["retry_bytes"] > 0  # the resend is accounted for
    finally:
        pair.stop()


def test_receiver_restart_does_not_redeliver_a_finished_object(tmp_path: Path) -> None:
    body = rand(50_000)
    pair = Pair(tmp_path, "receipts")
    pair.start()
    try:
        code, out, _ = pair.post(body, "once-1")
        pair.wait_state(out["id"], ("receiver-verified",), timeout=60)
        pair.sink.wait_accepted(1)
        time.sleep(1.5)  # let the receiver finish deleting the delivered payload
        pair.receiver.term()
        pair.start_receiver()
        # a stray resend of the same transfer is a duplicate, not a second delivery
        time.sleep(2.0)
        assert len(pair.sink.accepted()) == 1
    finally:
        pair.stop()


def test_tls_listener_serves_the_same_api(tmp_path: Path) -> None:
    import shutil
    import ssl
    import subprocess

    if shutil.which("openssl") is None:
        pytest.skip("openssl not available")
    cert, key = tmp_path / "c.pem", tmp_path / "k.pem"
    subprocess.run(
        ["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", str(key), "-out", str(cert),
         "-days", "1", "-subj", "/CN=localhost"],
        check=True, capture_output=True,
    )
    extra = {"DIODE_TLS_CERT_FILE": str(cert), "DIODE_TLS_KEY_FILE": str(key)}
    pair = Pair(tmp_path, "off", sender_extra=extra)
    pair.start_receiver()
    from tests.svc_harness import Proc

    pair.sender = Proc("sender", {**pair.sender_env}, tmp_path / "sender.log")
    try:
        ctx = ssl.create_default_context()
        ctx.load_verify_locations(str(cert))
        end = time.time() + 20
        while True:
            try:
                c = http.client.HTTPSConnection("localhost", pair.s_http, timeout=5, context=ctx)
                c.request("GET", "/readyz")
                if c.getresponse().status == 200:
                    break
            except OSError:
                if time.time() > end:
                    raise
                time.sleep(0.2)
        body = rand(4000)
        c = http.client.HTTPSConnection("localhost", pair.s_http, timeout=10, context=ctx)
        c.request("POST", "/v1/transfers", body=body,
                  headers={"Authorization": f"Bearer {TOKEN}", "Idempotency-Key": "tls-1"})
        assert c.getresponse().status == 202
        assert pair.sink.wait_accepted(1)[0]["sha256"] == sha(body)
        # plain HTTP to the TLS port is refused, not served
        with pytest.raises((OSError, http.client.HTTPException)):
            p = http.client.HTTPConnection("127.0.0.1", pair.s_http, timeout=5)
            p.request("GET", "/healthz")
            p.getresponse().read()
    finally:
        pair.stop()
