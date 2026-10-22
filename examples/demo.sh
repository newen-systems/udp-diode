#!/usr/bin/env bash
# Compose loopback demo: POST a 50 MiB random object and a 1 KiB object to the sender and
# check the sink received byte-identical bodies.
#   examples/demo.sh            feedback off (strict one-way)
#   examples/demo.sh receipts   restricted receipts on
# Uses DOCKER_CONTEXT (default: colima). Brings the stack up and tears it down, volumes included.
set -euo pipefail
cd "$(dirname "$0")"
MODE="${1:-off}"
export DOCKER_CONTEXT="${DOCKER_CONTEXT:-colima}"
export SENDER_HTTP_PORT="${SENDER_HTTP_PORT:-38080}" SINK_PORT="${SINK_PORT:-38081}"
FILES=(-f compose.yml)
if [[ "$MODE" == receipts ]]; then FILES+=(-f compose.receipts.yml); fi
DC=(docker compose "${FILES[@]}")
sha() { shasum -a 256 "$1" | cut -d' ' -f1; }

./make-secrets.sh
WORK="$(mktemp -d)"
cleanup() {
  "${DC[@]}" down -v --remove-orphans >/dev/null 2>&1 || true
  rm -f "$WORK/big.bin" "$WORK/small.bin"
  rmdir "$WORK" 2>/dev/null || true
}
trap cleanup EXIT

"${DC[@]}" up -d --build --wait
TOKEN="$(cat secrets/api_token)"
head -c $((50 * 1024 * 1024)) /dev/urandom >"$WORK/big.bin"
head -c 1024 /dev/urandom >"$WORK/small.bin"
BIG_SHA="$(sha "$WORK/big.bin")"
SMALL_SHA="$(sha "$WORK/small.bin")"

post() { # file key
  curl -sS --fail-with-body -X POST "http://127.0.0.1:${SENDER_HTTP_PORT}/v1/transfers" \
    -H "Authorization: Bearer ${TOKEN}" -H "Idempotency-Key: $2" \
    -H "Content-Type: application/octet-stream" --data-binary "@$1"
}
jid() { python3 -c 'import json,sys; print(json.load(sys.stdin)["id"])'; }

t0=$(date +%s)
BIG_ID="$(post "$WORK/big.bin" "demo-big-$$" | jid)"
SMALL_ID="$(post "$WORK/small.bin" "demo-small-$$" | jid)"
echo "mode=$MODE accepted big=$BIG_ID small=$SMALL_ID (202 returned after durable spool)"

n=0
got="[]"
for _ in $(seq 1 300); do
  got="$(curl -sS "http://127.0.0.1:${SINK_PORT}/received")"
  n="$(python3 -c 'import json,sys; print(len(json.loads(sys.argv[1])))' "$got")"
  if [[ "$n" -ge 2 ]]; then break; fi
  sleep 1
done
echo "elapsed=$(($(date +%s) - t0))s sink received=$n"
python3 - "$got" "$BIG_ID" "$BIG_SHA" "$SMALL_ID" "$SMALL_SHA" <<'PY'
import json, sys
got = {r["key"]: r for r in json.loads(sys.argv[1])}
ok = True
for tid, want in ((sys.argv[2], sys.argv[3]), (sys.argv[4], sys.argv[5])):
    r = got.get(tid)
    good = bool(r) and r["sha256"] == want
    ok &= good
    print("OK  " if good else "FAIL", tid, "size=%s" % (r or {}).get("size"), "sha256=%s" % (r or {}).get("sha256"))
    print("    expected sha256=%s" % want)
sys.exit(0 if ok else 1)
PY
sleep 3
for id in "$BIG_ID" "$SMALL_ID"; do
  curl -sS -H "Authorization: Bearer ${TOKEN}" "http://127.0.0.1:${SENDER_HTTP_PORT}/v1/transfers/$id" |
    python3 -c 'import json,sys; d=json.load(sys.stdin); print("sender state:", d["state"], "receiver_confirmed:", d["receiver_confirmed"])'
done
echo "--- image"
docker image ls udp-diode:dev --format 'size={{.Size}} id={{.ID}}'
echo "--- containers (docker stats MemUsage is cgroup memory, RSS plus page cache)"
docker stats --no-stream --format '{{.Name}} mem={{.MemUsage}} cpu={{.CPUPerc}}' $("${DC[@]}" ps -q sender receiver relay-fwd)
for svc in sender receiver; do
  echo "--- $svc RSS (VmRSS/VmHWM of the python process)"
  "${DC[@]}" exec -T "$svc" sh -c 'for p in /proc/[0-9]*; do if grep -q diode.py $p/cmdline 2>/dev/null; then grep -E "VmRSS|VmHWM" $p/status; fi; done' || true
done
