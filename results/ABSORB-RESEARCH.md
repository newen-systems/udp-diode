# Research absorbed from other diodes (2026-10)

This file records what we looked at, what we built, what we measured, and what
we rejected and why. The aim is that nobody redoes this work when the code is
revisited. Raw numbers are in `results/bench/*.json`.

## Summary

- No other open project takes objects over HTTP, holds them on disk until
  delivery, and refills holes from receipts. We absorbed eight small ideas, not
  a design.
- The big result is **multi-family XOR parity** (`DIODE_FEC_FAMILIES`). With
  feedback off, in the burst-loss emulation, it delivered 16 to 128 MiB 5/5 at
  1%, 3% and 5% loss, at about 13.1 Mbit/s goodput under an 18 Mbit/s cap. The
  WAN-BALANCE dual-pass profile delivered 3/5 at 1% and 0/5 at 3% in the same
  emulation, at about 6.7 Mbit/s.
- **Confirmed on the real site VPN** (2026-10-23, section 5.4) with longer
  strides, `12x240,12x248,12x256`. With feedback off it delivered 14/14 at the
  sink at 64, 256 and 512 MiB, at 68.8 Mbit/s. Two passes with no parity, the
  best strict profile from the container runs, gave 43.9 Mbit/s on the same
  path and day. The short strides from the model (`12x64,...`) failed 2 of 7 at
  256 MiB, because one real loss burst was longer than the stride.
- Rust: not now (R1). Revisit only on the R2 trigger.

## 1. Survey of other containerised diodes

Cloned and read, not built or run.

| Code | Project | What it is | Verdict |
|---|---|---|---|
| F1 | [ANSSI lidi](https://github.com/ANSSI-FR/lidi) | Rust, RaptorQ FEC, distroless image. Most mature. | Source of A1, A2, A4, A5, A6, A7. Packets carry only a logged hash, no authentication. No retransmission: one lost block aborts every active transfer. Compose file has no hardening. |
| F2 | [Datadiodefileproxy](https://gitlab.com/ViktorToreRudolf/services/datadiodefileproxy) | Rust, RaptorQ, REST API, web UI, ClamAV. Closest in shape to ours. | Source of A3, A8. State is memory only (restart resends the outbox). CRC check off by default. Receiver runs as root and applies mode and owner taken from the wire. "2.7 Gbit/s clean" is one hardware pair with 3491 NIC drops absorbed by FEC. |
| F3 | [godiode](https://github.com/klockcykel/godiode) | Go. Container is `go run` with host networking. | Nothing to take except jumbo-frame guidance. |
| F4 | [svenseeberg/data-diode](https://github.com/svenseeberg/data-diode) | Rust, Reed-Solomon, not containerised. | Good list of receiver defences. We already have most of it. |
| F5 | [OSDD](https://github.com/CyberInnovationHub-NLD/OpenSourceDataDiode) | Last updated 2022. | Skipped. |
| F9 | [Data Diode Connector (DDC)](https://github.com/ffutop/DataDiodeConnector) | Apache-2.0 fork of OSDD, shipped as Docker images. | Nothing to absorb. See below. |

Do not copy from them: F2's root receiver or mode/chown from the wire, or
lidi's removal of the internal rate limit in favour of `tc` (needs NET_ADMIN).
Our container hardening is already stronger than both.

### DDC binary inspection

- Source is public. 93 of 123 commits are OSDD authors. The fork's own commits
  change 2 lines of Rust and add Docker, Helm and docs.
- Method: pulled the amd64 0.4.0 `ddc-transport-udp-send` and `-receive`
  images, extracted the (unstripped) binaries, and compared compiled source
  paths and crates against the public repo and lockfile.
- Every compiled DDC source file exists in the public repo except
  `framework/transport_udp/src/license.rs` (`verify_license`,
  `get_system_fingerprint`, `get_k8s_cluster_uid`). It is an ed25519 licence
  bound to `/etc/machine-id` or the kube-system namespace UID. The 23 extra
  crates are all that licence stack.
- We did not decompile the licence check. It teaches nothing about diodes, and
  studying a way past a vendor licence gate is out of scope.
- Open transport (from its protocol doc and sender): 9-byte header, about 64 KB
  datagrams that rely on IP fragmentation, no FEC, no checksum, no
  authentication, one sequence gap discards the message, an unauthenticated
  `Shutdown` packet stops the receiver, millisecond sleeps for pacing, root
  containers.
- Lessons are negative: do not rely on IP fragmentation (supports A7), and
  authenticate control frames (supports H1 and A6).

## 2. Non-TCP/UDP feedback research

An external research pass looked at feedback channels other than a UDP return
path.

| Code | Idea | Verdict |
|---|---|---|
| F6 | Layer 2 tricks for feedback: Ethernet PAUSE, LLDP, link state | Reject. Any reverse bit is feedback across the boundary, just unassessed. If feedback is allowed, `DIODE_FEEDBACK=receipts` is already the defined, HMAC'd, rate-capped status channel. |
| F7 | NORM (RFC 5740) | Prior art for our receipts path (selective NACK over a narrow return path). Nothing to absorb, it still needs the reverse path. |
| F8 | FLUTE (RFC 6726), FEC building blocks (RFC 6363), RaptorQ, carousels | Matches the no-helper direction. RaptorQ is not available in stdlib Python (R1). Multi-family XOR is our stdlib step in this direction. |
| E1 | Carousel repair pass: pass 2 sends a fresh parity set instead of a full resend | Superseded. Multi-family parity in one pass already reaches the target. Families plus `DIODE_PASSES=2` is still available. |

Content addressing ("ignore already-verified objects") is already covered by
the transfer id plus SHA-256 dedupe.

## 3. Rust

- **R1 (not now).** On the real path speed is limited by loss, not CPU. The
  WAN runs top out at 5 to 18 Mbit/s and Python does several hundred Mbit/s on
  loopback. A rewrite would discard the tests and P0 hardening. What Rust buys
  is `recvmmsg`/`sendmmsg` and RaptorQ, which matter only at gigabit rates on a
  real optical diode.
- **R2 (trigger).** Reconsider when Stage 5 shows Python CPU limiting
  throughput at line rate. Then wrap lidi (keep the Python HTTP layer and
  ledger, send each object through lidi) rather than write our own Rust.

## 4. Ideas, status and toggles

| Code | Idea | Status | Toggle | Evidence |
|---|---|---|---|---|
| X1 | Fast XOR with `int.from_bytes` | Adopted | none | clean-fec4 170 to 555 Mbit/s, sender CPU 3.04 to 0.65 s |
| H1 | Per-frame HMAC tag (`FLAG_AUTH`, 16-byte truncated HMAC-SHA256, key derived from the shared secret) | Adopted, default on | `DIODE_FRAME_AUTH=on\|off`, `--frame-auth`, `--require-frame-auth` | No measurable goodput cost (table 5.1) |
| A1 | Receive thread draining the socket into a queue | **Rejected** | removed | GIL convoy, see below |
| A2 | Read SO_RCVBUF back, warn with sysctl hint | Adopted | none | warning in logs |
| A3 | Drop counters by reason, kernel UDP counters | Adopted | none | `/v1/stats` `drops`, `kernel_udp` |
| A4 | Relay impairment: Gilbert burst loss, dup, reorder, blackout, seed | Adopted | relay flags | all bench scenarios |
| A5 | Random session id in the HMAC | Skipped | | Per-transfer-id state already exists. A session reset would throw away resumable partials. |
| A6 | Signed heartbeat | Adopted, default 5 s | `DIODE_HEARTBEAT_S` (0 = off) | `/v1/stats` heartbeats, missed, last age |
| A7 | Chunk size from MTU | Opt-in | `DIODE_CHUNK_SIZE=auto` | Not default: 1500 MTU fragments on a VPN, the fixed 1200 fits. |
| A8 | Burst pacing, at most 64 frames | Skipped | | The pacer already caps idle credit at 5 ms. |
| I1 | Single-family interleaved parity (stride) | Superseded by families | | 0 to 1/5 at 1% burst 6 |
| I2 | Multi-family interleaved XOR parity, peeling decoder | **Adopted, opt-in** | `DIODE_FEC_FAMILIES=GxS,...`, `--parity-families` | Section 5.2, 5.3 |

Other toggles that already existed: `DIODE_FEEDBACK=off|receipts` (the resend
helper), `DIODE_PARITY_GROUP`, `DIODE_PASSES`.

### A1 rejection

A receive thread feeding `queue.Queue` made kernel drops far worse in CPython.
The receive thread and the processing thread contend for the GIL, and the
thread that drains the socket waits behind the other one (a convoy).

| Variant (clean-nofec, 5 reps) | Delivered | Kernel rcvbuf drops (median) |
|---|---|---|
| No receive thread | 2/5 | 24 |
| Receive thread | 0/5 | 14181 |
| Receive thread, `sys.setswitchinterval(0.00005)` | 0/5 | 13456 |

Do not retry this in CPython. A free-threaded build or a native receiver
(R2) is the only way this idea helps.

### Why families (I2) and how they work

- Single-parity XOR repairs one loss per group. Bursty loss puts several
  losses in a group, so a single family (even interleaved) cannot carry 16 MiB
  without feedback (section 5.3).
- A family `GxS` puts every S-th chunk into a group of G, over a block of G*S
  chunks. A burst shorter than S hits each group at most once.
- Several families with different strides form a small product code. The
  receiver peels: any group missing one chunk repairs it, which may complete a
  group in another family. This repairs patterns no single family can.
- Parities for a block are sent together after the block. Sending each parity
  right after its last member is worse: one burst takes both the chunk and the
  parity that covers it (section 5.3, "spread").
- The META carries `parity_families` and is covered by the transfer HMAC, so
  the layout cannot be changed in flight.
- Chosen layout: `12x240,12x248,12x256` (about 25% parity). Short strides
  (`12x64,12x72,12x80`) passed the model but failed 2 of 7 at 256 MiB on the
  VPN (section 5.4). A burst hits each group at most once only while it is
  shorter than the stride. Strides of about 240 tolerate about 300 KB (25 ms at
  95 Mbit/s) of continuous loss. Overhead is the same, and the bodies held for
  encoding grow to G*S chunks per family (about 4 MB).

## 5. Measurements

### Method and limits

- `scripts/bench_toggles.py` runs the real `diode.py` sender and receiver
  services, plus `soft_diode_relay.py` for impairment, on loopback inside a
  `python:3.12-slim` container (4 CPU aarch64). 5 reps per scenario.
- Baseline is the P0 branch tip. Each variant adds one change on top of the
  previous one.
- Limits:
  - Loopback in a container, not a real link. The relay is a loss model, not
    the VPN. The model is harsher than the real VPN for dual pass: the real
    VPN delivered 16 to 128 MiB with dual pass, the model delivered 3/5 at 16
    MiB.
  - The container caps `net.core.rmem_max`, so clean unthrottled runs drop in
    the kernel and are flaky in every variant (3/5 to 4/5 for clean-nofec).
    This is a test-host limit, not a code difference.
  - One "Address already in use" failure (02, loss5-receipts) is a free-port
    race in the test harness, not a diode failure.
  - Goodput is file bytes over wall time from first send to publish.

### 5.1 Baseline vs each change (delivered, goodput Mbit/s)

| Scenario | 00 baseline | 01 xor | 02 frame auth | 03 + heartbeat | 04 chunk auto |
|---|---|---|---|---|---|
| clean-nofec | 3/5, 634 | 4/5, 657 | 3/5, 627 | 4/5, 650 | 3/5, 655 |
| clean-fec4 | 5/5, 170 | 5/5, 555 | 2/5, 537 | 5/5, 556 | 5/5, 560 |
| loss5-receipts | 5/5, 121 | 5/5, 124 | 4/5 (port race), 117 | 5/5, 112 | 5/5, 123 |
| burst15-receipts | 5/5, 19.5 | 5/5, 19.5 | 5/5, 19.4 | 5/5, 21.4 | 5/5, 21.7 |
| blackout-receipts | 5/5, 31.8 | 5/5, 31.9 | 5/5, 31.1 | 5/5, 31.1 | 5/5, 31.9 |
| loss15-off (must fail) | 0/5 | 0/5 | 0/5 | 0/5 | 0/5 |

- loss15-off is the negative test: FEC cannot repair 15% loss without
  feedback. Every variant failed closed with 0 wrong bodies at the sink.
- The 02 clean-fec4 2/5 is the rcvbuf limit above (03 with the same auth code
  is 5/5).

### 5.2 No-helper WAN comparison (feedback off, 18 Mbit/s cap, 16 MiB unless noted)

Relay: Gilbert loss with mean burst 6.

| Scenario | Base dual pass (fec4, passes 2) | New dual pass | Families 12x64,12x72,12x80, passes 1 |
|---|---|---|---|
| 1% loss | 3/5, 6.71 | 3/5, 6.64 | **5/5, 13.12** |
| 3% loss | 0/5 | 0/5 | **5/5, 13.12** |
| 5% loss | 0/5 | 0/5 | **5/5, 13.08** |
| 1%, 64 MiB | 0/5 | | **5/5, 13.09** |
| 1%, 128 MiB | 0/5 | | **5/5, 13.07** |
| Wire overhead | 2.70 | 2.73 | 1.37 |
| Sender CPU s (16 MiB) | 2.59 | 1.25 | 0.74 |

Against [WAN-BALANCE](WAN-BALANCE.md) (real VPN, dual pass): 4.6 to 5.1
Mbit/s for 16 to 128 MiB. Families in the model reach 13.1 Mbit/s. Files:
`20-wan-baseline-dualpass.json`, `21-wan-families.json`,
`22-wan-new-dualpass.json`.

Earlier run with single-family interleave (`10-wan-baseline.json`,
`11-wan-new.json`): fec4 stride 16 delivered 1/5 at 1% and 0/5 at 3%. This is
why I1 was dropped.

### 5.3 FEC simulation (16 MiB = 13981 chunks, 100 runs, ok/100)

`scripts/fec_sim.py` models frame order, the same Gilbert loss, and the
peeling decoder. It ignores frame headers, so its overhead is lower than the
measured wire overhead.

| Layout | Overhead | 1% b6 | 3% b6 | 5% b6 | 1% indep | 3% indep |
|---|---|---|---|---|---|---|
| fec4, 2 passes (WAN-BALANCE) | 2.5 | 70 | 8 | | 100 | |
| fec4 stride 16 | 1.25 | 15 | 0 | | 5 | |
| 2 families g8 s64+s72 | 1.257 | 99 | 71 | 18 | 96 | 60 |
| 2 families g8 s128+s136 | 1.255 | 100 | 85 | 28 | 98 | 57 |
| 3 families g8 s64+s72+s80 | 1.383 | 100 | 99 | 98 | 100 | 100 |
| **3 families g12 s64+s72+s80 (chosen)** | 1.26 | 100 | 99 | 92 | 100 | 98 |
| 2 families g8, 2 passes | 2.514 | 100 | 100 | 100 | 100 | 100 |

Spread parity order scored far lower than batched order for every layout.
Keep batched.

### 5.4 Real site VPN, container to container (2026-10-23)

Same rig as `CONTAINER-WAN.md`. The sender runs in a Kubernetes pod at site A,
the receiver and a hashing sink run on a Docker host at site B, over a
WireGuard VPN (about 9 ms RTT, tunnel MTU 1432, about 100 Mbit/s shared
uplink). Both "theirs" (the P0 image) and "mine" (this branch's code mounted
on the same image) ran on both ends. Configs alternated in rounds, so uplink
noise hits all of them alike. Delivery means the sink received the right
SHA-256. Raw rows: `absorb-vpn-2026-10-23/runs.jsonl`.

Send rate is object bits over the sender's admission to end of the last pass.
This is the rate a queue of objects sustains. End-to-end is admission to sink
delivery (clocks NTP-synced). With two passes it is often higher than the send
rate, because a clean first pass completes the object early, but the link is
still busy with pass 2.

| Config (95 Mbit/s cap unless noted) | Size | At sink | Send Mbit/s median | Wire overhead |
|---|---|---|---:|---:|
| Theirs, 2 passes, no parity | 64 MiB | 9/9 | 43.88 | 2.15 |
| Mine, 2 passes, no parity | 64 MiB | 9/9 | 43.34 | 2.18 |
| Theirs, 1 pass, no parity | 64 MiB | **0/6** | (87.1) | 1.08 |
| Mine, families 12x64,12x72,12x80 | 64 MiB | 9/9 | 68.81 | 1.37 |
| Theirs, 2 passes, 90 Mbit/s cap | 256 MiB | 2/2 | 41.58 | 2.15 |
| Mine, families 12x64,12x72,12x80 | 256 MiB | **5/7** | 68.89 | 1.37 |
| **Mine, families 12x240,12x248,12x256** | 64 MiB | **6/6** | **68.53** | 1.37 |
| **Mine, families 12x240,12x248,12x256** | 256 MiB | **6/6** | **68.80** | 1.37 |
| **Mine, families 12x240,12x248,12x256** | 512 MiB | **2/2** | **68.62** | 1.37 |
| Theirs, receipts, 1 pass | 32 MiB | 10/10 | 83.69 | 1.08 |
| Mine, receipts, 1 pass | 32 MiB | 10/10 | 82.59 | 1.09 |

Findings:

- **V1 (their claims).** Reproduced: 43.9 Mbit/s strict at 64 MiB, 41.6 at
  256 MiB, 83.7 with receipts, and single pass without parity fails (0/6 here).
  The "9 to 10 times the old result" ratio compares a 95 Mbit/s cap with the old
  18 Mbit/s cap and a different harness. It is a better configuration on the
  same path, not a code speed-up of that size.
- **V2 (cost of this branch).** About 1.2% slower than theirs in the same mode
  (43.34 against 43.88, 82.6 against 83.7). The 16-byte frame tag forces
  1250-byte chunks instead of 1260 at MTU 1432. Set `DIODE_FRAME_AUTH=off` to
  get the 1% back where the path is trusted.
- **V3 (families).** Strict single pass with long-stride families: 68.8 Mbit/s,
  14/14 delivered. That is 1.57 times the best strict profile, on the same
  path and day.
- **V4 (failure mode).** The two short-stride failures had no kernel buffer
  drops. Loss came from the path: one burst longer than the 64-chunk stride
  hit the same group twice in every family. In strict mode a failed transfer
  is lost without a signal to the sender, so the out-of-band ledger (sent list
  against received list) still matters with families.
- The receiver host caps `SO_RCVBUF` at 416 KiB (`rmem_max`). The new
  read-back warning fired. A 512 MiB run took 188 kernel drops, which families
  repaired. Raising `net.core.rmem_max` on that host was left to its owner.
- Sample sizes are small (2 to 10 per config). 14/14 for long strides shows
  the failure rate is low, not that it is zero.

## 6. How to rerun

```bash
# unit tests
python3 -m pytest -q

# FEC layout simulation
python3 scripts/fec_sim.py --chunks 13981 --loss 0.03 --burst 6 --runs 100

# end-to-end bench (Linux, for /proc CPU and kernel counters)
docker run --rm -e BENCH_COMMIT=label -v "$PWD":/new -w /new python:3.12-slim \
  python3 scripts/bench_toggles.py --root /new --label label --reps 5 \
  --scenarios wan3-dualpass,wan3-families --out results/bench/xx.json
```

To compare against an older commit, mount a second worktree read-only and pass
it as `--root`. The bench script itself always runs from the new tree.

## 7. Open follow-ups

1. Run long-stride families for longer (tens of transfers, multi-GB, a busy
   uplink period) before making them the strict-mode default.
2. Strides above 256 need `MAX_PARITY_STRIDE` raised. Only worth it if real
   bursts longer than about 25 ms show up.
3. Stage 5 items and the R2 Rust trigger stand as before.
