#!/usr/bin/env python3
"""Compare service builds and toggles end to end: HTTP POST on low, verified body at the HTTP sink on high.

Runs real sender and receiver processes (diode.py) from --root, with
soft_diode_relay.py (from this checkout) impairing the data path and, in
receipts mode, the receipt path. Each scenario runs --reps times with fixed
seeds; every rep is reported, failures included.

  python3 scripts/bench_toggles.py --root ../base --label baseline --out results/bench/baseline.json
  python3 scripts/bench_toggles.py --root . --label rx-thread --env DIODE_RX_THREAD=on --out ...

Goodput is payload bits / wall seconds / 1e6 (true Mbit/s), wall time from
the 202 to the sink holding a body with the right sha256.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import random
import re
import signal
import socket
import statistics
import subprocess
import sys
import tempfile
import time
from pathlib import Path

HERE = Path(__file__).resolve().parents[1]

# name: (size MiB, feedback, parity, bitrate Mbit/s, relay args each way or None, expect delivery)
SCENARIOS: dict[str, dict] = {
    "clean-nofec": dict(mib=64, feedback="off", parity=0, mbps=1000, relay=None, expect=True),
    "clean-fec4": dict(mib=64, feedback="off", parity=4, mbps=1000, relay=None, expect=True),
    "loss5-receipts": dict(mib=16, feedback="receipts", parity=4, mbps=200, relay=["--loss", "0.05"], expect=True),
    "burst15-receipts": dict(
        mib=16, feedback="receipts", parity=4, mbps=200, relay=["--loss", "0.15", "--burst", "3"], expect=True
    ),
    "blackout-receipts": dict(
        mib=16, feedback="receipts", parity=4, mbps=100, relay=["--blackout", "0.3:2"], expect=True
    ),
    # lidi's negative case: loss beyond what FEC repairs, and no feedback. Must not deliver anything wrong.
    "loss15-off": dict(mib=8, feedback="off", parity=4, mbps=200, relay=["--loss", "0.15"], expect=False),
}
# No-helper WAN emulation: results/WAN-BALANCE.md settings (feedback off, 18 Mbit/s, gap 0.5 ms) with
# bursty loss from the relay. The real VPN loss pattern is not reproduced; RTT does not matter without feedback.
_WAN = dict(mib=16, feedback="off", parity=4, mbps=18, expect=True)
_FAM = {"DIODE_PASSES": "1", "DIODE_GAP_MS": "0.5", "DIODE_FEC_FAMILIES": "12x64,12x72,12x80"}
for _name, _relay in (
    ("wan1", ["--loss", "0.01", "--burst", "6"]),
    ("wan3", ["--loss", "0.03", "--burst", "6"]),
    ("wan5", ["--loss", "0.05", "--burst", "6"]),
):
    SCENARIOS[f"{_name}-dualpass"] = dict(_WAN, relay=_relay, env={"DIODE_PASSES": "2", "DIODE_GAP_MS": "0.5"})
    # Three interleaved XOR families (scripts/fec_sim.py pick): same 1.26x overhead as FEC4, one pass.
    SCENARIOS[f"{_name}-families"] = dict(_WAN, relay=_relay, parity=0, env=_FAM)
for _mib in (64, 128):
    _relay = ["--loss", "0.01", "--burst", "6"]
    SCENARIOS[f"wan1-dualpass-{_mib}m"] = dict(
        _WAN, mib=_mib, relay=_relay, env={"DIODE_PASSES": "2", "DIODE_GAP_MS": "0.5"}
    )
    SCENARIOS[f"wan1-families-{_mib}m"] = dict(_WAN, mib=_mib, relay=_relay, parity=0, env=_FAM)
DEFAULT_SCENARIOS = "clean-nofec,clean-fec4,loss5-receipts,burst15-receipts,blackout-receipts,loss15-off"


def free_udp() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def cpu_seconds(pid: int) -> float | None:
    try:
        fields = Path(f"/proc/{pid}/stat").read_text().rsplit(")", 1)[1].split()
        return (int(fields[11]) + int(fields[12])) / os.sysconf("SC_CLK_TCK")
    except OSError:
        pass
    try:
        out = subprocess.run(["ps", "-o", "cputime=", "-p", str(pid)], capture_output=True, text=True).stdout.strip()
        parts = [float(x) for x in re.split("[:]", out.replace("-", ":"))]
        secs = 0.0
        for x in parts:
            secs = secs * 60 + x
        return secs
    except (OSError, ValueError):
        return None


def kernel_udp_drops() -> int | None:
    """Datagrams the kernel dropped for a full receive buffer, host-wide."""
    try:
        lines = Path("/proc/net/snmp").read_text().splitlines()
        udp = [ln.split() for ln in lines if ln.startswith("Udp:")]
        return int(udp[1][udp[0].index("RcvbufErrors")])
    except (OSError, IndexError, ValueError):
        pass
    try:
        out = subprocess.run(["netstat", "-s", "-p", "udp"], capture_output=True, text=True).stdout
        m = re.search(r"(\d+) dropped due to full socket buffers", out)
        return int(m.group(1)) if m else None
    except OSError:
        return None


class Relay:
    def __init__(self, listen: int, forward: int, args: list[str], seed: int, stats: Path) -> None:
        self.stats = stats
        self.p = subprocess.Popen(
            [sys.executable, str(HERE / "soft_diode_relay.py"), "--listen-port", str(listen),
             "--forward-port", str(forward), "--seed", str(seed), "--stats-file", str(stats), *args],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )

    def stop(self) -> dict:
        self.p.send_signal(signal.SIGINT)
        try:
            self.p.wait(10)
        except subprocess.TimeoutExpired:
            self.p.kill()
        try:
            return json.loads(self.stats.read_text())
        except (OSError, ValueError):
            return {}


def run_rep(root: Path, name: str, sc: dict, rep: int, env_extra: dict[str, str], tmp: Path) -> dict:
    sys.path.insert(0, str(root))
    from tests.svc_harness import Pair  # noqa: E402 - imported from the build under test

    seed = 1000 * rep + sum(map(ord, name))
    rng = random.Random(seed)
    body = rng.randbytes(sc["mib"] * 1024 * 1024)
    digest = hashlib.sha256(body).hexdigest()
    relays: list[Relay] = []
    common = {**sc.get("env", {}), **env_extra}
    sender_extra = {**common, "DIODE_MAX_BITRATE_MBPS": str(sc["mbps"]), "DIODE_PARITY_GROUP": str(sc["parity"]),
                    "DIODE_ACK_TIMEOUT_S": "0.5", "DIODE_ACK_TIMEOUT_CAP_S": "2"}
    receiver_extra = {**common, "DIODE_TTL_S": "60"}
    pair = Pair(tmp, feedback=sc["feedback"], sender_extra=sender_extra, receiver_extra=receiver_extra)
    if sc["relay"] is not None:
        r_in = free_udp()
        relays.append(Relay(r_in, pair.data_port, sc["relay"], seed, tmp / "relay-data.json"))
        pair.sender_env["DIODE_DATA_PEER"] = f"127.0.0.1:{r_in}"
        if sc["feedback"] == "receipts":
            back_in = free_udp()
            relays.append(Relay(back_in, pair.receipt_port, sc["relay"], seed + 1, tmp / "relay-receipts.json"))
            pair.receiver_env["DIODE_RECEIPT_PEER"] = f"127.0.0.1:{back_in}"
    drops0 = kernel_udp_drops()
    out: dict = {"scenario": name, "rep": rep, "seed": seed, "bytes": len(body)}
    try:
        pair.start()
        code, resp, _ = pair.post(body, key=f"bench-{rep}")
        assert code == 202, (code, resp)
        tid = resp["id"]
        t0 = time.time()
        line_s = len(body) * 8 / (sc["mbps"] * 1e6)
        timeout = max(20.0, line_s * 6 + 10) if sc["expect"] else max(10.0, line_s * 3 + 5)
        ok = False
        while time.time() - t0 < timeout:
            got = [r for r in pair.sink.accepted() if r["tid"] == tid]
            if got:
                ok = got[0]["sha256"] == digest
                out["wrong_body"] = not ok
                break
            time.sleep(0.02)
        wall = time.time() - t0
        out.update(delivered=ok, wall_s=round(wall, 3))
        if ok:
            out["goodput_mbps"] = round(len(body) * 8 / wall / 1e6, 2)
        _, s_stats = pair.get("/v1/stats")
        _, r_stats = pair.get("/v1/stats", port=pair.r_http)
        out["sender"] = s_stats
        out["receiver"] = r_stats
        out["cpu_sender_s"] = cpu_seconds(pair.sender.p.pid)
        out["cpu_receiver_s"] = cpu_seconds(pair.receiver.p.pid)
        wire = (s_stats.get("wire_bytes_first") or 0) + (s_stats.get("retry_bytes") or 0)
        out["wire_overhead"] = round(wire / len(body), 3) if wire else None
        out["wrong_bodies_at_sink"] = sum(1 for r in pair.sink.received if r["sha256"] != digest)
    except Exception as exc:  # noqa: BLE001 - a broken rep is a result, not a crash
        out.update(delivered=False, error=f"{type(exc).__name__}: {exc}")
    finally:
        pair.stop()
        out["relay"] = [r.stop() for r in relays]
        drops1 = kernel_udp_drops()
        out["kernel_rcvbuf_drops"] = None if drops0 is None or drops1 is None else drops1 - drops0
        sys.path.remove(str(root))
        for mod in [m for m in sys.modules if m == "tests" or m.startswith("tests.")]:
            del sys.modules[mod]
    return out


def summarise(reps: list[dict], expect: bool) -> dict:
    good = [r for r in reps if r.get("delivered")]
    def med(key: str, rows: list[dict]) -> float | None:
        vals = [r[key] for r in rows if r.get(key) is not None]
        return round(statistics.median(vals), 3) if vals else None
    def p95(key: str, rows: list[dict]) -> float | None:
        vals = sorted(r[key] for r in rows if r.get(key) is not None)
        return round(vals[min(len(vals) - 1, int(0.95 * len(vals)))], 3) if vals else None
    return {
        "expect_delivery": expect,
        "delivered": f"{len(good)}/{len(reps)}",
        "wrong_bodies": sum(r.get("wrong_bodies_at_sink", 0) or 0 for r in reps),
        "goodput_mbps_median": med("goodput_mbps", good),
        "wall_s_median": med("wall_s", good),
        "wall_s_p95": p95("wall_s", good),
        "cpu_sender_s_median": med("cpu_sender_s", reps),
        "cpu_receiver_s_median": med("cpu_receiver_s", reps),
        "wire_overhead_median": med("wire_overhead", reps),
        "kernel_rcvbuf_drops_median": med("kernel_rcvbuf_drops", reps),
    }


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--root", type=Path, default=HERE, help="Checkout whose diode.py is measured")
    ap.add_argument("--label", required=True)
    ap.add_argument("--reps", type=int, default=5)
    ap.add_argument("--scenarios", default=DEFAULT_SCENARIOS, help=f"Any of: {', '.join(SCENARIOS)}")
    ap.add_argument("--env", action="append", default=[], help="KEY=VALUE for both services (a toggle)")
    ap.add_argument("--out", type=Path, required=True)
    args = ap.parse_args()
    env = dict(e.split("=", 1) for e in args.env)
    root = args.root.resolve()
    try:
        commit = subprocess.run(["git", "-C", str(root), "rev-parse", "--short", "HEAD"],
                                capture_output=True, text=True).stdout.strip()
    except OSError:
        commit = os.environ.get("BENCH_COMMIT", "")  # no git in the container
    result = {
        "label": args.label, "root_commit": commit, "env": env, "reps": args.reps,
        "python": platform.python_version(), "platform": platform.platform(),
        "cpus": os.cpu_count(), "scenarios": {},
    }
    for name in args.scenarios.split(","):
        sc = SCENARIOS[name]
        reps = []
        for rep in range(args.reps):
            with tempfile.TemporaryDirectory(prefix=f"bench-{name}-") as tmp:
                r = run_rep(root, name, sc, rep, env, Path(tmp))
            reps.append(r)
            print(f"{args.label} {name} rep={rep} delivered={r.get('delivered')} wall={r.get('wall_s')} "
                  f"mbps={r.get('goodput_mbps')} cpu_r={r.get('cpu_receiver_s')} "
                  f"drops={r.get('kernel_rcvbuf_drops')} {r.get('error', '')}", file=sys.stderr, flush=True)
        result["scenarios"][name] = {"summary": summarise(reps, sc["expect"]), "reps": reps}
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(result, indent=1) + "\n")
    print(json.dumps({k: v["summary"] for k, v in result["scenarios"].items()}, indent=1))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
