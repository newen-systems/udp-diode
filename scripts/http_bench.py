#!/usr/bin/env python3
"""Benchmark a running sender over its HTTP API, one transfer at a time.

Runs next to the sender (e.g. `kubectl exec ... -- python - < scripts/http_bench.py`) so the
upload to the sender never limits the result. For each run: POST a random object, poll until
the sender reports receiver-verified (or failed/expired, or the deadline passes), and record
the time from admission to verification plus the wire bytes the sender counted for it.

Prints one JSON object per run, then a summary line. Configuration through env:
  BENCH_URL (http://127.0.0.1:8080)  BENCH_TOKEN_FILE (/run/secrets/diode/api_token)
  BENCH_SIZE_MIB (32)  BENCH_RUNS (10)  BENCH_TIMEOUT_S (300)  BENCH_LABEL ("")
  BENCH_STRICT (unset): feedback-off sender. A run ends at sent-unconfirmed, "ok" only means
  the sender finished, and delivery must be checked at the far side by sha256.
"""
import hashlib
import json
import os
import statistics
import time
import urllib.request
import uuid
from datetime import datetime

URL = os.environ.get("BENCH_URL", "http://127.0.0.1:8080")
TOKEN = open(os.environ.get("BENCH_TOKEN_FILE", "/run/secrets/diode/api_token")).read().strip()
SIZE = int(float(os.environ.get("BENCH_SIZE_MIB", "32")) * 1024 * 1024)
RUNS = int(os.environ.get("BENCH_RUNS", "10"))
TIMEOUT = float(os.environ.get("BENCH_TIMEOUT_S", "300"))
LABEL = os.environ.get("BENCH_LABEL", "")
STRICT = bool(os.environ.get("BENCH_STRICT"))
DONE = ("sent-unconfirmed", "failed", "expired") if STRICT else ("receiver-verified", "failed", "expired")


def call(method: str, path: str, body: bytes | None = None, headers: dict | None = None) -> dict:
    h = {"Authorization": f"Bearer {TOKEN}", **(headers or {})}
    req = urllib.request.Request(URL + path, data=body, method=method, headers=h)
    with urllib.request.urlopen(req, timeout=120) as r:
        return json.load(r)


def ts(value: str | float) -> float:
    return value if isinstance(value, (int, float)) else datetime.fromisoformat(value).timestamp()


def run_once(i: int) -> dict:
    payload = os.urandom(SIZE)
    digest = hashlib.sha256(payload).hexdigest()
    before = call("GET", "/v1/stats")
    row = call("POST", "/v1/transfers", payload, {
        "Idempotency-Key": f"bench-{uuid.uuid4().hex}",
        "Content-Type": "application/octet-stream",
    })
    t_admit = time.time()
    while True:
        row = call("GET", f"/v1/transfers/{row['id']}")
        if row["state"] in DONE:
            break
        if time.time() - t_admit > TIMEOUT:
            break
        time.sleep(0.05)
    t_end = time.time()
    after = call("GET", "/v1/stats")
    ok = row["state"] == DONE[0] and row["sha256"] == digest
    secs = (ts(row["updated"]) - ts(row["created"])) if ok else t_end - t_admit
    first = after["wire_bytes_first"] - before["wire_bytes_first"]
    retry = after["retry_bytes"] - before["retry_bytes"]
    return {
        "label": LABEL, "run": i, "ok": ok, "state": row["state"], "reason": row.get("reason"),
        "id": row["id"], "sha256": digest, "bytes": SIZE, "secs": round(secs, 3),
        "goodput_mbps": round(SIZE * 8 / secs / 1e6, 2) if ok and secs > 0 else 0.0,
        "wire_first": first, "wire_retry": retry,
        "overhead": round((first + retry) / SIZE, 4),
    }


def main() -> None:
    results = []
    for i in range(RUNS):
        r = run_once(i)
        results.append(r)
        print(json.dumps(r), flush=True)
    good = [r["goodput_mbps"] for r in results if r["ok"]]
    q = sorted(good)
    print(json.dumps({
        "summary": LABEL, "runs": RUNS, "ok": len(good),
        "median_mbps": round(statistics.median(good), 2) if good else 0.0,
        "p05_mbps": round(q[max(0, int(len(q) * 0.05) - 1)], 2) if q else 0.0,
        "min_mbps": round(min(good), 2) if good else 0.0,
        "median_overhead": round(statistics.median(r["overhead"] for r in results), 4),
        "retry_bytes_total": sum(r["wire_retry"] for r in results),
    }), flush=True)


if __name__ == "__main__":
    main()
