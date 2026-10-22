#!/usr/bin/env bash
# End-to-end smoke test of a built image: sender -> UDP -> receiver -> sink, strict one-way.
#   tests/smoke.sh IMAGE            ENGINE=podman (default) or ENGINE=docker
# Checks the sink got byte-identical content and that every container runs as uid 10001.
set -euo pipefail
cd "$(dirname "$0")/.."
IMAGE=${1:?image}
ENGINE=${ENGINE:-podman}
N=udp-diode-smoke
WORK=$(mktemp -d "${TMPDIR:-/tmp}/udp-diode-smoke.XXXXXX")
cleanup() {
  "$ENGINE" rm -f "$N-sender" "$N-receiver" "$N-sink" >/dev/null 2>&1 || true
  "$ENGINE" network rm "$N" >/dev/null 2>&1 || true
  "$ENGINE" volume rm "$N-rx" "$N-tx" >/dev/null 2>&1 || true
  rm -rf "$WORK"
}
[ -n "${KEEP:-}" ] || trap cleanup EXIT

for k in api_token data_key; do openssl rand -hex 32 >"$WORK/$k"; done
chmod 0755 "$WORK" && chmod 0644 "$WORK"/*   # readable by uid 10001 inside the containers
"$ENGINE" network create "$N" >/dev/null
hardened=(--read-only --cap-drop ALL --security-opt no-new-privileges --tmpfs /tmp:size=16m --network "$N")
keys=(-v "$WORK:/run/secrets/diode:ro" -e DIODE_API_TOKEN_FILE=/run/secrets/diode/api_token
      -e DIODE_DATA_KEY_FILE=/run/secrets/diode/data_key -e DIODE_STATE_DIR=/var/lib/diode)

"$ENGINE" run -d --name "$N-sink" "${hardened[@]}" -v "$PWD/examples/k8s/sink.py:/sink.py:ro" \
  --entrypoint python "$IMAGE" /sink.py >/dev/null
"$ENGINE" run -d --name "$N-receiver" "${hardened[@]}" "${keys[@]}" -v "$N-rx:/var/lib/diode" \
  -e DIODE_MODE=receiver -e DIODE_DELIVERY_URL="http://$N-sink:8081/ingest" "$IMAGE" >/dev/null
"$ENGINE" run -d --name "$N-sender" "${hardened[@]}" "${keys[@]}" -v "$N-tx:/var/lib/diode" -p 127.0.0.1:38080:8080 \
  -e DIODE_MODE=sender -e DIODE_DATA_PEER="$N-receiver:9400" -e DIODE_MAX_BITRATE_MBPS=200 \
  -e DIODE_FEC_FAMILIES=12x240,12x248,12x256 "$IMAGE" >/dev/null

for _ in $(seq 60); do curl -fs 127.0.0.1:38080/readyz >/dev/null && break; sleep 1; done
for c in sender receiver sink; do
  uid=$("$ENGINE" exec "$N-$c" id -u)
  [ "$uid" = 10001 ] || { echo "FAIL $c runs as uid $uid"; exit 1; }
done

head -c $((4 * 1024 * 1024)) /dev/urandom >"$WORK/obj"
want=$(sha256sum "$WORK/obj" | cut -d' ' -f1)
printf 'Authorization: Bearer %s\n' "$(cat "$WORK/api_token")" >"$WORK/auth"
curl -fsS -X POST 127.0.0.1:38080/v1/transfers -H @"$WORK/auth" \
  -H "Idempotency-Key: smoke-$$" -H "Content-Type: application/octet-stream" --data-binary "@$WORK/obj" >/dev/null
for _ in $(seq 60); do
  got=$("$ENGINE" exec "$N-sink" python -c \
    "import json,urllib.request as u; print(' '.join(r['sha256'] for r in json.load(u.urlopen('http://127.0.0.1:8081/received'))))")
  case " $got " in *" $want "*) echo "PASS delivered $want, all containers uid 10001"; exit 0 ;; esac
  sleep 1
done
"$ENGINE" logs "$N-sender" | tail -20
"$ENGINE" logs "$N-receiver" | tail -20
echo "FAIL sink never received $want"
exit 1
