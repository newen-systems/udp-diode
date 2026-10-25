# udp-diode

**DIO1** (wire magic `DIO2`): a lab-grade one-way UDP file transfer protocol (pitcher → catcher).

> **Not a security boundary.** This models sequenced UDP + checksums so you can reason about reorder, loss, FEC, quarantine, and multi‑GB transfers. A true data diode is a *physics* one-way link; applications still own integrity (at-least-once assembly). A second, independent one-way stream may carry receipts. A host that both sends and receives is the exfil anti-pattern.

## Run it

The service is one image with two roles (`DIODE_MODE=sender|receiver`), standard-library
Python only, running as uid 10001 with a read-only root filesystem.

```bash
# pull a release (linux/amd64 and linux/arm64)
podman pull ghcr.io/newen-systems/udp-diode:0.3.0     # or docker pull

# or build it yourself
podman build -t udp-diode .                           # or docker build -t udp-diode .

# end-to-end check of a built image: sender -> UDP -> receiver -> sink, all uid 10001
ENGINE=podman tests/smoke.sh udp-diode                # ENGINE=docker for Docker

# two-network Compose demo through a one-way relay (COMPOSE picks the engine)
COMPOSE="podman compose" examples/demo.sh             # default: docker compose
COMPOSE="podman compose" examples/demo.sh receipts

# Kubernetes (Helm): sender, receiver and demo sink, restricted Pod Security, default-deny NetworkPolicy
kubectl create namespace udp-diode
kubectl label namespace udp-diode pod-security.kubernetes.io/enforce=restricted
helm install udp-diode oci://ghcr.io/newen-systems/charts/udp-diode -n udp-diode --wait
helm test udp-diode -n udp-diode --logs              # POSTs 4 MiB, checks the SHA-256 at the sink
```

The chart, a sender-only and receiver-only install for two clusters, and every value
are in [charts/udp-diode](charts/udp-diode/README.md).

Releases: push a tag `vX.Y.Z` that matches `VERSION`. The `build` workflow builds
amd64 and arm64 with buildah, smoke-tests with podman, pushes
`ghcr.io/newen-systems/udp-diode:X.Y.Z` (plus `X.Y`, `X`, `latest`; `main` pushes
`edge`) and creates the GitHub Release. Pin a digest in production.

## What you get

| Piece | Role |
|---|---|
| `pitcher.py` | Low-side sender (stream multi‑GB, throttle, multi-pass, XOR FEC) |
| `catcher.py` | High-side reassembler (RAM/mmap, HMAC META, atomic publish / quarantine) |
| `protocol.py` | Wire format (magic `DIO2`): META / DATA / PARITY / EOF / STATUS, strict per-field validation |
| `receipts.py` | Local receipt JSON (holes / ok / fail). Coordinator language. |
| `coordinator.py` | Same-side copy of allowlisted receipts. No sockets. |
| `soft_diode_relay.py` | Software one-way hop; optional seeded loss, bursts, blackout, dup, reorder for tests |
| `run_demo.sh` | Loopback scenario matrix (publish / quarantine / dual-track ARQ) |

### Research absorbed

| Practice | In this tool |
|---|---|
| Compact META (no full lens array) | `chunk_size` + `last_chunk_len` |
| Stream large files | Pitcher stream path (>32 MiB) |
| Disk-backed reassembly | Catcher mmap spill above 640 MiB (RAM first) |
| META/EOF ×N redundancy | `--meta-copies` / `--eof-copies` (default 3) |
| XOR FEC (1 loss / group) | `--parity-group N` (PARITY + EOF path) |
| Interleaved multi-family XOR FEC (peeling decoder) | `--parity-families 12x240,12x248,12x256` / `DIODE_FEC_FAMILIES` |
| Per-frame MAC on every data-track frame | `--frame-auth` / `DIODE_FRAME_AUTH=on` (default) |
| Signed heartbeat, drop counters by reason, kernel UDP counters | `DIODE_HEARTBEAT_S`, `/v1/stats` |
| Send bitrate throttle | `--max-bitrate` Mbit/s |
| Large SO_RCVBUF + drain | Default ~32 MiB + non-blocking queue drain |
| META HMAC | `--hmac-secret` |
| Atomic publish + hash gate | `.part` → final + SHA-256 |

**Not included (candidates):** Reed-Solomon or RaptorQ, jumbo frames E2E, product integrations, a binary frame header (JSON headers cost about 7 %), holes as ranges in receipts (repair is limited to 128 holes per receipt), loss-driven rate back-off in receipt mode, and reading the body before a `507` so clients get the status instead of a broken pipe.
What was tried, measured and rejected (and why) is in [`results/ABSORB-RESEARCH.md`](results/ABSORB-RESEARCH.md).

## Quick start

```bash
# demo matrix (loopback)
./run_demo.sh

# unit tests
python3 -m pytest -q

# manual
python3 catcher.py --bind 127.0.0.1 --port 9400 \
  --out /tmp/diode_out --quarantine /tmp/diode_q --ttl 600

dd if=/dev/urandom of=/tmp/blob bs=1m count=64
python3 pitcher.py /tmp/blob --host 127.0.0.1 --port 9400 \
  --parity-group 4 --max-bitrate 80 --passes 2
```

## Multi‑GB

- Pitcher **streams** (hash pass, then send) — does not load the whole file into RAM.
- Catcher keeps assemblies in RAM up to 640 MiB, then mmap-backed slots.
- Prefer `--max-bitrate` on WAN; raise catcher `--ttl` for long transfers.

```bash
# high side
sudo sysctl -w net.core.rmem_max=67108864 net.core.rmem_default=16777216
python3 catcher.py --bind 0.0.0.0 --port 9400 \
  --out /tmp/diode_out --quarantine /tmp/diode_q --work /tmp/diode_work \
  --ttl 7200 --rcvbuf 33554432 --hmac-secret "$SECRET"

# low side (WAN-balanced example ≤128 MiB)
python3 pitcher.py /path/to/file.bin --host HIGH_IP --port 9400 \
  --hmac-secret "$SECRET" --parity-group 4 \
  --max-bitrate 18 --passes 2 --gap-ms 0.5
```

## Soft diode (local one-way hop)

```bash
python3 catcher.py --bind 127.0.0.1 --port 9400 --out /tmp/out --quarantine /tmp/q
python3 soft_diode_relay.py --listen-port 9401 --forward-port 9400
python3 pitcher.py /tmp/blob --host 127.0.0.1 --port 9401
```

Impair the hop for tests that cannot use `tc netem` (macOS, CI without root).
Loss is a two-state burst model: `--loss` is the long-run rate, `--burst` the
mean run of drops. Seed it for repeatable runs; run a second relay to impair
the receipt direction too.

```bash
python3 soft_diode_relay.py --listen-port 9401 --forward-port 9400 \
  --loss 0.03 --burst 6 --blackout 2:1.5 --dup 0.01 --reorder 0.01 --seed 7 --stats-file /tmp/relay.json
```

## WAN recommended profile (speed vs assurance)

Measured on a ~10 ms RTT bidirectional site VPN (not optical diode). Full table: [`results/WAN-BALANCE.md`](results/WAN-BALANCE.md).

| Goal | Pitcher flags | Observed goodput |
|---|---|---|
| **Balanced ≤128 MiB** | `--max-bitrate 18 --passes 2 --parity-group 4 --gap-ms 0.5` | **~4.6–5.1 Mbit/s** |
| **256 MiB** | `--max-bitrate 15 --passes 2 …` | **~4.1 Mbit/s** |
| **512 MiB** | `--max-bitrate 12 --passes 2 …` | **~3.4 Mbit/s** |
| Speed best-effort | `--max-bitrate 18 --passes 1 …` | ~9.4 when lucky — **flaky integrity** |
| **Families, one pass (container, VPN, 2026-10-23)** | `DIODE_PASSES=1 DIODE_FEC_FAMILIES=12x240,12x248,12x256 DIODE_PARITY_GROUP=0 DIODE_MAX_BITRATE_MBPS=95` | **~68.8 Mbit/s**, 14/14 at the sink, 64-512 MiB |

Families row: feedback off, 1250-byte chunks with frame auth at MTU 1432. Two passes with no parity on the same path and day gave 43.9 Mbit/s. Strides of 64 to 80 failed 2 of 7 at 256 MiB: one VPN loss burst was longer than the stride. See [`results/ABSORB-RESEARCH.md`](results/ABSORB-RESEARCH.md).

**Takeaway:** dual-pass is the knee. Single-pass is faster but not for custody. Third pass is usually diminishing returns once dual-pass + FEC + catcher buffering hold. Unthrottled blasts self-inflict severe loss.

## Pitcher flags

| Flag | Effect |
|---|---|
| `--loss 0.1` | Drop 10% of DATA frames (lab) |
| `--reorder` | Shuffle DATA (memory path / small files) |
| `--corrupt` / `--wire-corrupt` | Integrity / CRC demos |
| `--parity-group N` | XOR FEC every N DATA chunks |
| `--parity-families GxS,...` | Interleaved XOR families instead of `--parity-group` (catcher reads them from META) |
| `--frame-auth` | MAC every frame with a key derived from `--hmac-secret` |
| `--passes N` | Full envelope retransmit N times (data-track redundancy) |
| `--send-receipts DIR` | Validate track: send STATUS from a receipt inbox (send-only) |
| `--watch-receipts DIR` | Data track: poll local inbox for holes/ok/fail and resend |
| `--meta-copies` / `--eof-copies` | Control-plane redundancy |
| `--hmac-secret S` | Sign META HMAC-SHA256 over every META field |
| `--receipt-repeat-s N` | With `--send-receipts`: repeat an unchanged receipt every N seconds (default 1) |
| `--receipt-retention-s N` | With `--send-receipts`: stop repeating a receipt once its file is N seconds old (default 300) |
| `--max-bitrate X` | Throttle to X Mbit/s |
| `--gap-ms N` | Minimum inter-datagram sleep |
| `--progress-every-mb N` | Progress logs while streaming |

## Catcher flags

| Flag | Effect |
|---|---|
| `--ttl` | Incomplete assembly TTL (default 300s) |
| `--work DIR` | Spill root for large assemblies |
| `--rcvbuf N` | Explicit SO_RCVBUF (0 = auto ~32 MiB) |
| `--hmac-secret S` | Require META HMAC |
| `--idle-exit N` | Exit after idle (**positive only**; ≤0 disables) |
| `--max-seconds N` | Hard run limit |
| `--receipts DIR` | Local receipt drop-dir (recv-only; coordinator copies this) |
| `--status-only` | Validate-track catcher: STATUS frames only |
| `--require-source-map DIR` | With `--status-only`: keep a receipt only if DIR has a source map for its transfer id |
| `--max-transfer-bytes N` | Refuse a larger META (FAIL receipt reason `limit`) |
| `--max-active N` | Concurrent assemblies (default 64) |
| `--ram-max-bytes N` | Assemble at or above this size in an mmap work file |
| `--min-free-bytes N` | Refuse a transfer that would leave less free on the output volume |
| `--holes-window N` | Missing sequence numbers per holes receipt (default 64, max 128) |
| `--require-frame-auth` | Drop any data-track frame without a valid MAC from `--hmac-secret` |

## Dual track (data ↑, validate ↓)

Two one-way streams that never share a socket, a directory, or a host role.
A process is send-only **or** receive-only. Production is four hosts
(`low-tx`, `high-rx`, `high-tx`, `low-rx`). Lab loopback uses four processes
plus two coordinators.

```text
LOW                              HIGH
data-pitcher ──data UDP──► data-catcher      recv-only, writes receipts/
     send-only                      │ coordinator (files only)
                                    ▼
validate-catcher ◄──STATUS── validate-pitcher  send-only
     recv-only, receipts/          reads inbox/
          │ coordinator
          ▼
data-pitcher watches inbox/ and resends missing DATA only
```

```bash
# high-rx
python3 catcher.py --bind 0.0.0.0 --port 9400 --out /tmp/out \
  --quarantine /tmp/q --receipts /high/data/out --receipt-every 0

python3 coordinator.py --from-dir /high/data/out --to-dir /high/validate/in

# high-tx
python3 pitcher.py --send-receipts /high/validate/in \
  --host LOW_RX_IP --port 9401 --receipt-copies 3

# low-rx
python3 catcher.py --bind 0.0.0.0 --port 9401 --status-only \
  --receipts /low/validate/out --out /tmp/val-out --quarantine /tmp/val-q

python3 coordinator.py --from-dir /low/validate/out --to-dir /low/data/in

# low-tx
python3 pitcher.py /path/to/file.bin --host HIGH_RX_IP --port 9400 \
  --watch-receipts /low/data/in --source-map /low/data/sources
```

Packet retry lives in the send-only data pitcher (`--watch-receipts`,
`--ack-timeout-s`, `--ack-rounds`, `--ack-backoff`). It never binds a
receive socket. An orchestrator is optional and only drops files next to
that pitcher.

### Loopback bench (8 MiB, induced DATA loss, n=3)

Not a WAN figure. No bitrate cap. Full table:
[`results/DUAL-VS-SINGLE.md`](results/DUAL-VS-SINGLE.md).

| Loss | single p=1 | single p=2+FEC | dual p=1 | dual p=1+FEC |
|---:|---|---|---|---|
| 0% | 3/3, **430 Mbit/s** | 3/3, 116 Mbit/s | 3/3, 205 Mbit/s | 3/3, 118 Mbit/s |
| 8% | 0/3 | 3/3, **119 Mbit/s** | 3/3, 25 Mbit/s | 3/3, 46 Mbit/s |
| 15% | 0/3 | 0/3 | 0/3 | 3/3, **26 Mbit/s** |

Dual-track is **not** a line-rate boost. On a clean path, single-pass is
fastest; dual-track adds receipt lag. At 8% loss it recovers where
single-pass cannot, but dual-pass+FEC is still faster on loopback
(second copy is cheaper than many 64-seq hole rounds). At 15%
independent loss, dual-pass+FEC failed and dual-track+FEC was the only
mode that published. Re-run: `python3 scripts/bench_dual_vs_single.py`.

## Guarantee modelled

At-least-once assembly with atomic publish and quarantine on integrity/TTL
failure. Without the validate track, retransmit is time/redundancy based only.
With it, the low-side coordinator resends only the missing seqs.

## Cross-site helpers

```bash
# deploy tools to two SSH hosts (you supply hosts — no estate defaults)
export PITCHER_HOST=low.example.net CATCHER_HOST=high.example.net
export SSH_USER=ops SSH_KEY=~/.ssh/id_ed25519
./scripts/bench_cross_site.sh

# local size ladder (both ends on this machine or tunnel)
python3 scripts/bench_size_ladder.py --help
```

## License

MIT — see [LICENSE](LICENSE).

## Wire version and trust rules

The frame magic is `DIO2`. A `DIO1` peer is rejected with a `legacy DIO1`
error (counted as `legacy_peer`); there is no silent downgrade. Changes from
`DIO1`: the META HMAC covers `chunk_size`, `last_chunk_len`, `parity_group` and
`content_type` as well as id, length, chunk count and digest; PARITY headers no
longer carry `group_seqs` (the group is `seq_start..seq_end`); transfer ids are
`[A-Za-z0-9_-]{1,64}`.

- `decode_frame` is the single validation point. It rejects non-object or
  non-UTF-8 headers, unknown or missing fields, wrong types, out-of-range
  numbers, inconsistent geometry and STATUS frames with a body.
- A transfer publishes only after an accepted META. The first valid META is
  immutable; EOF only signals "sender finished" and must agree with it.
- A forged META with a bad HMAC is dropped and recorded under
  `quarantine/_rejected/`; it does not consume the transfer id.
- Publish order: fsync `.part`, fsync marker, rename payload, fsync directory,
  rename marker (`<id>.meta.json`, the commit point), fsync directory. The OK
  receipt is written after that. Startup removes half-written artefacts and
  rebuilds the duplicate table from the markers.
- Receipts are states, not events: an unchanged receipt is repeated on a timer
  for a bounded window, and the sender re-sends an unchanged HOLES window with
  backoff, so losing every copy of one receipt cannot stall a transfer.

## HTTP service (sender / receiver roles)

`diode.py` runs one role from environment variables (`DIODE_MODE=sender|receiver`).
`python diode.py --check-config` validates the environment and prints the
effective values with secrets masked. Invalid configuration exits 2 at startup.

```text
low:   client --POST--> sender (HTTP, spool+ledger) --DIO2 UDP--> receiver (verify, fsync) --POST--> destination
                                 ^                                   |
                                 +--- optional authenticated STATUS (DIODE_FEEDBACK=receipts) ---+
```

HTTP API (bearer token from `DIODE_API_TOKEN_FILE`, except `/healthz` and `/readyz`):

| Request | Result |
|---|---|
| `POST /v1/transfers` on the sender, header `Idempotency-Key` (1-128 of `A-Za-z0-9._:-`), body streamed (Content-Length or chunked) | `202` `{id,state,size,sha256,...}` after the payload and ledger row are durable. Same key and bytes: `202` again with `Idempotent-Replay: true`. Same key, other bytes: `409`. `400` bad key/framing, `401`, `411`, `413`, `408` read timeout, `503` too many uploads (`Retry-After`), `507` disk reserve or spool quota. |
| `GET /v1/transfers/{id}` on the sender | Local state only: `queued`, `sending`, `sent-unconfirmed` (feedback off), `receiver-verified` (feedback on), `failed`, `expired`. `receiver_confirmed` is true only for `receiver-verified`. |
| `GET /v1/stats` | Queue bytes, oldest age, accepted/verified/failed, retry bytes, downstream failures, disk free. Receiver also: `drops` by reason (`crc`, `auth`, `length`, `schema`, ...), `kernel_udp` (`rcvbuf_errors`, `softnet_dropped`, Linux only), granted `rcvbuf_bytes`, heartbeat age and gaps. Feedback off reports nothing about the far side. |
| `GET /healthz`, `GET /readyz` | Liveness; readiness (spool writable and above reserve, ledger open, workers running). |
| `GET /v1/deliveries/{id}`, `POST /v1/deliveries/{id}/retry` on the receiver | Delivery state; requeue a parked delivery. |

The receiver POSTs each verified object to `DIODE_DELIVERY_URL` with
`Idempotency-Key` and `X-Diode-Transfer-Id` (the transfer id), `X-Diode-Sha256`,
`Content-Type: application/octet-stream`. 2xx completes it; 408/425/429/5xx and
network errors back off and retry; other 4xx are parked with the payload kept.
A timeout after the destination accepted the object causes a duplicate, so the
destination should deduplicate on `Idempotency-Key`. The receiver's transport OK
means durable verified custody on the high side, not downstream success.

Restart policy: sender jobs in flight return to the queue and are resent from
the retained spool (the receiver deduplicates by transfer id); a receiver drops
partial assemblies on restart and relies on that resend. In feedback mode the
sender notices the lost state and re-sends the whole object (bounded), otherwise
it fills holes 64 at a time.

| Variable | Role | Default | Meaning |
|---|---|---|---|
| `DIODE_MODE` | both | required | `sender` or `receiver` |
| `DIODE_FEEDBACK` | both | `off` | `off`: no reverse socket opened. `receipts`: authenticated STATUS receipts |
| `DIODE_STATE_DIR` | both | required | Persistent volume: ledger, spool, output |
| `DIODE_API_TOKEN_FILE` | both | required | Bearer token file |
| `DIODE_DATA_KEY_FILE` | both | required | Forward (META) HMAC key file |
| `DIODE_RECEIPT_KEY_FILE` | both | required if `receipts` | Reverse HMAC key file, must differ from the data key |
| `DIODE_HTTP_BIND`, `DIODE_HTTP_PORT` | both | `0.0.0.0`, `8080` | HTTP listener |
| `DIODE_TLS_CERT_FILE`, `DIODE_TLS_KEY_FILE` | both | unset | Serve HTTPS |
| `DIODE_DATA_PEER` | sender | required | `host:port` of the receiver (UDP 9400) |
| `DIODE_RECEIPT_BIND` | sender | `0.0.0.0:9401` | Receipt listener, only opened with `receipts` |
| `DIODE_DATA_BIND` | receiver | `0.0.0.0:9400` | UDP listener |
| `DIODE_RECEIPT_PEER` | receiver | required if `receipts` | `host:port` the receipts are sent to (UDP 9401) |
| `DIODE_DELIVERY_URL` | receiver | required | Destination for verified objects |
| `DIODE_DELIVERY_TOKEN_FILE`, `DIODE_DELIVERY_CA_FILE` | receiver | unset | Bearer token to the destination, CA bundle for https |

Transport tuning (all validated; defaults in brackets):

| Variable | Default | Effect |
|---|---|---|
| `DIODE_MAX_BITRATE_MBPS` | 100 | Sender pacing, Mbit/s of wire bytes, shared by all jobs and resends |
| `DIODE_CHUNK_SIZE` | 1200 | DATA body bytes; rejected if the worst-case datagram exceeds `DIODE_MTU - 28`. `auto`: the largest that fits `DIODE_MTU` |
| `DIODE_MTU` | 1500 | Path MTU the frame budget is checked against |
| `DIODE_PARITY_GROUP` | 0 | XOR FEC group size (0 off, 2 and up) |
| `DIODE_FEC_FAMILIES` | `12x240,12x248,12x256` with `DIODE_FEEDBACK=off` and no `DIODE_PARITY_GROUP`, else unset | Interleaved XOR families `GxS,...` instead of `DIODE_PARITY_GROUP` (about 1.37x wire with headers). `off` disables. See `results/ABSORB-RESEARCH.md` |
| `DIODE_FRAME_AUTH` | on | Both roles. `on`: every data-track frame carries a 16-byte MAC and the receiver drops untagged or forged frames. Must match on both sides |
| `DIODE_HEARTBEAT_S` | 5 | Sender sends a sequenced HEARTBEAT this often (0 off). Receiver `/v1/stats` shows `last_heartbeat_age_s` and `heartbeats_missed` |
| `DIODE_META_COPIES`, `DIODE_EOF_COPIES` | 3, 3 | Control-frame redundancy |
| `DIODE_PASSES` | 1 | Full passes before waiting for receipts / marking sent-unconfirmed |
| `DIODE_GAP_MS` | 0 | Minimum inter-datagram gap |
| `DIODE_SNDBUF`, `DIODE_RCVBUF` | auto | Socket buffers (receiver auto = 32 MiB request, capped by the kernel) |
| `DIODE_HOLES_WINDOW` | 64 | Missing sequence numbers per holes receipt (max 128) |
| `DIODE_RECEIPT_INTERVAL_S` | 1.0 | Receiver repeats the current receipt this often |
| `DIODE_RECEIPT_RETENTION_S` | 300 | Receipt repeat window |
| `DIODE_RECEIPT_COPIES` | 3 | Copies of a new or changed receipt |
| `DIODE_RECEIPT_EVERY` | 0 | Also write holes receipts every N DATA frames (0 = at EOF only) |
| `DIODE_ACK_TIMEOUT_S`, `DIODE_ACK_BACKOFF`, `DIODE_ACK_TIMEOUT_CAP_S` | 2, 1.5, 10 | Sender wait for receipts and backoff when nothing changes |
| `DIODE_RETRY_BUDGET_S` | 3600 | Sender gives up (`expired`) after this long without a receiver OK |
| `DIODE_TTL_S` | 3600 | Receiver idle time before an incomplete assembly fails |
| `DIODE_RAM_MAX_BYTES` | 64 MiB | Assemble in RAM below this size, in a work file above |
| `DIODE_RAM_BUDGET_BYTES` | 256 MiB | Total RAM all in-memory assemblies may claim; a transfer that would exceed it goes to a work file. Size the container memory limit above this |
| `DIODE_SEND_CONCURRENCY` | 2 | Sender jobs in parallel |
| `DIODE_DELIVERY_CONCURRENCY`, `DIODE_DELIVERY_TIMEOUT_S` | 2, 60 | Delivery workers, request timeout |
| `DIODE_DELIVERY_BACKOFF_MIN_S`, `DIODE_DELIVERY_BACKOFF_MAX_S` | 1, 300 | Retry backoff |

Limits: `DIODE_MAX_BODY_BYTES` (16 GiB), `DIODE_DISK_RESERVE_BYTES` (256 MiB),
`DIODE_SPOOL_QUOTA_BYTES` (64 GiB), `DIODE_MAX_UPLOADS` (4), `DIODE_MAX_CONNECTIONS`
(32), `DIODE_HTTP_IO_TIMEOUT_S` (30), `DIODE_HEADER_DEADLINE_S` (10),
`DIODE_UPLOAD_DEADLINE_S` (3600), `DIODE_MAX_TRANSFER_BYTES` (16 GiB),
`DIODE_MAX_ACTIVE` (16), `DIODE_MIN_FREE_BYTES` (256 MiB), retention:
`DIODE_SPOOL_RETENTION_S` (1 day, sent-unconfirmed payloads),
`DIODE_FAILED_RETENTION_S` (7 days), `DIODE_LEDGER_RETENTION_S` (30 days),
`DIODE_DEDUPE_RETENTION_S` (7 days).

The HTTP server is the standard library's threading server with explicit
limits (connection cap, per-recv timeout, header and body deadlines enforced by
closing the socket, bounded chunked decoding, one request per connection). It
is meant for a few trusted clients on a controlled network; terminate TLS in
front of it or set the TLS variables.

## Container image and Compose demo

```bash
podman build -t udp-diode:dev .                                        # or docker build; the host's arch
podman build --platform linux/amd64 -t udp-diode:dev-amd64 .           # cross-build, needs qemu-user-static
examples/demo.sh             # strict one-way: 50 MiB and 1 KiB through sender -> relay -> receiver -> sink
examples/demo.sh receipts    # the same with restricted receipts
```

The image is `python:3.12-slim` pinned by digest, runs as uid 10001, has no pip
and no dev dependencies, and the state directory is the only writable path
(`/var/lib/diode`). `examples/compose.yml` runs it read-only with all
capabilities dropped, `no-new-privileges`, an init process, memory/CPU/pid
limits and named volumes. The receiver and sink sit on an `internal: true`
network and reach the low network only through `soft_diode_relay.py`, which
forwards one way. Without `compose.receipts.yml` there is no relay in the other
direction and the receiver process opens no socket that could use one.
`examples/make-secrets.sh` creates the token and distinct forward and reverse
keys under `examples/secrets/` (ignored by git). On a single Docker host this
shows function, not isolation; use separate hosts or networks with firewall
policy for a real boundary. The receiver asks for a 32 MiB receive buffer and
the kernel caps it (`net.core.rmem_max`); raise it on the host for fast links.

## Security

Reviewed for the 0.1.0 release (code, image, Compose and Kubernetes examples). No
critical or high finding in the service's default configuration: frame auth is on, the
data key is required, every frame tag is checked before parsing, and the META HMAC and
whole-object SHA-256 are checked before anything is published. Paths are built only
from validated ids, and secrets and tokens are compared in constant time.

Fixed for 0.1.0:
- The standalone `catcher.py` binds `127.0.0.1` by default and refuses a non-loopback
  bind without `--hmac-secret` unless `--insecure` is passed.
- Secret files with control characters are refused at startup, and the receiver logs
  only the delivery host, never URL credentials.
- `DIODE_FRAME_AUTH=off` logs a warning at startup.
- The demo and smoke scripts pass the bearer token in a header file, not on the command line.

Known limits (by design or open):
- With `DIODE_FRAME_AUTH=off`, one forged datagram can block a transfer, and forged
  DATA for random ids can fill the active-assembly slots. Content is still never
  published unless it verifies. Keep frame auth on unless the path is trusted.
- A captured transfer replayed after `DIODE_DEDUPE_RETENTION_S` (7 days) is delivered
  again under the same `Idempotency-Key`. Destinations should deduplicate on it.
- The HTTP API is plaintext unless `DIODE_TLS_CERT_FILE`/`DIODE_TLS_KEY_FILE` are set.
  Terminate TLS in front of it or set them.
- The spool quota is checked against Content-Length. A chunked upload is bounded only by
  the disk reserve. Only authenticated clients can upload.
- Receipts carry no nonce: an old receipt replayed on the high-to-low path is bounded by
  the receipt retention window and the active-job binding.
- The image is not signed. Pin by digest.
- `net.core.rmem_max` is a host setting. Kubernetes cannot raise it per pod, so size it on
  the receiver's nodes for fast links.
