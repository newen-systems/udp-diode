# Container transport over a site VPN (2026-10-22)

Sender: the container in a Kubernetes pod at site A. Receiver and a mock HTTP sink: the
container on a Docker host at site B. Path: a WireGuard site-to-site VPN, about 9 ms RTT,
tunnel MTU 1432, limited by site A's shared uplink of about 100 Mbit/s. This is a bidirectional
VPN, not a physical diode, and the uplink carried other traffic during the runs.

Each run POSTs a random object to the sender's HTTP API from inside the sender pod (so the
upload never limits the result). Throughput is object bits over the sender's admission to
completion time: receiver-verified with receipts, or the end of the last pass in strict mode.
Strict-mode delivery was checked at the sink by SHA-256, not taken from the sender. Raw runs
are in `container-wan-2026-10-22/` (`ok` in strict-mode files means the sender finished; see
the tables below for what the sink received). Driver: `scripts/http_bench.py`.

## NiFi end to end (same cluster)

NiFi 2.12 with sender and receiver pods in its namespace (`examples/k8s/diode.yaml`,
NetworkPolicy keeping UDP one-way): GenerateFlowFile (4 MB random, attribute `test.origin`),
CryptographicHashContent, PackageFlowFile (FlowFile v3), InvokeHTTP POST to the sender with
`Idempotency-Key: ${uuid}`; the receiver delivered to ListenHTTP, then UnpackContent,
CryptographicHashContent and RouteOnAttribute comparing hash and attribute. 6 of 6 FlowFiles
arrived with the original content hash and attributes; the container never parsed the
FlowFile v3 envelope.

## Numbers to beat (strict one-way, no helper)

`WAN-BALANCE.md`, same path: 4.74 Mbit/s for 64 MiB and 4.08 Mbit/s for 256 MiB, two passes at
an 18 Mbit/s cap. A single pass failed integrity.

## Strict one-way (DIODE_FEEDBACK=off), 1260-byte chunks

| Config | Size | Delivered at sink | Median Mbit/s | Min |
|---|---|---|---:|---:|
| 95 Mbit/s cap, 2 passes | 64 MiB | 10/10 | **43.86** | 43.79 |
| 90 Mbit/s cap, 2 passes | 64 MiB | 10/10 | 41.55 | 41.45 |
| 90 Mbit/s cap, 2 passes | 256 MiB | 3/3 | **41.54** | 41.46 |
| 80 Mbit/s, 2 passes, no FEC | 64 MiB | 5/5 | 36.97 | 36.94 |
| 80 Mbit/s, 2 passes, parity 8 | 64 MiB | 5/5 | 29.13 | 28.66 |
| 90 Mbit/s, 2 passes, parity 16 | 64 MiB | 5/5 | 37.14 | 35.21 |
| 80 Mbit/s, 1 pass, no FEC | 64 MiB | 0/5 | | |
| 80 Mbit/s, 1 pass, parity 8 | 64 MiB | 2/5 | 64.98 | |
| 60 Mbit/s, 1 pass, parity 4 | 64 MiB | 1/5 | 44.28 | |

About 9 to 10 times the earlier result. Two passes is still the assurance knee: the residual
loss on this path is clustered, so XOR parity (one loss per group) does not rescue a single
pass, and adds nothing on top of two passes. A stronger code (Reed-Solomon, interleaved) is the
route to single-pass strict transfers; it was not tested here.

## With receipts (DIODE_FEEDBACK=receipts)

After commit 2c8c935 (refill rounds wait for a fresh receipt instead of sleeping out the ACK
timeout). Receiver: receipt interval 0.05 s, holes window 128. Sender: ACK timeout 0.5 s.
Interleaved blocks of 2 runs per config, 10 runs each, 32 MiB:

| Cap Mbit/s | OK | Median | Min | Max |
|---:|---:|---:|---:|---:|
| 70 | 10/10 | 62.4 | 62.0 | 63.0 |
| 80 | 10/10 | 70.7 | 67.8 | 71.7 |
| 90 | 10/10 | 79.1 | 78.3 | 79.6 |
| **95** | 10/10 | **83.1** | 81.9 | 83.5 |

Before that fix, at the same caps (1200-byte chunks, 5 runs): 80 Mbit/s gave a 47 Mbit/s median
with runs at 7.5, and 120 Mbit/s collapsed to 2.3 Mbit/s (each refill of at most 64 chunks
waited 2 s, so repair ran at about 0.3 Mbit/s). After it, 120 Mbit/s (12 percent loss from
overrunning the uplink) still delivered 53.8 Mbit/s.

Added random loss in both directions (data and receipts), 90 Mbit/s cap, 32 MiB, 5 runs each,
all receiver-verified:

| Loss | No FEC median / min | Parity 8 median / min |
|---:|---:|---:|
| 0 | 78.7 / 77.7 | |
| 1 % | 73.4 / 71.4 | 66.8 / 65.9 |
| 5 % | 56.7 / 45.4 | 58.7 / 54.5 |
| 15 % | 33.1 / 29.0 | 32.4 / 27.7 |

With receipts, FEC only pays below the line at about 5 percent loss, where it narrows the
tail; at 1 percent its 12.5 percent overhead costs more than it saves.

Outage: a 10 s blackout of both directions starting 1.5 s into a 64 MiB transfer, 3 runs: all
receiver-verified in 19.6 s (the sender saw the receiver had lost the object and re-sent it
at line rate once the path returned).

## Sweet spot on this path

- Rate cap just under the bottleneck: 95 Mbit/s on a 100 Mbit/s uplink. Above it the sender
  makes its own loss. Below it throughput falls in proportion.
- Largest chunk the path MTU allows without fragmentation: `DIODE_MTU=1432`,
  `DIODE_CHUNK_SIZE=1260` (about 5 percent more payload per datagram than 1200).
- Strict mode: 2 passes, no parity. With receipts: 1 pass, no parity (parity 8 only when loss
  is above about 5 percent), receipt interval 0.05 s, holes window 128, ACK timeout 0.5 s.
- The uplink is shared. During a busy period three 90 Mbit/s runs fell to 3 to 9 Mbit/s with
  14 to 18 percent loss that hit retransmissions too. A fixed cap cannot react to that; with
  receipts on, a rate that backs off on measured loss would.

## Defects found and fixed during these runs

- Refill rounds slept the full ACK timeout (2c8c935).
- Published-bytes counter overwrote instead of adding; late terminal receipts were counted as
  rejected (2bf9d15).
- `DIODE_RAM_MAX_BYTES` bounded each transfer but not the total, so abandoned assemblies OOM
  killed a 1 GiB receiver. `DIODE_RAM_BUDGET_BYTES` (abfdcc1). Every strict-mode transfer sent
  while it was down was lost without any signal to the sender, which is the case an
  out-of-band ledger (sent list against received list) exists to catch.

## Known gaps

- A sender that answers 507 (spool full) before reading the body leaves the client with a
  broken pipe rather than the 507.
- Strict mode keeps every sent object for `DIODE_SPOOL_RETENTION_S` (24 h default); size the
  spool for a day of traffic or shorten it.
- The JSON frame header costs about 7 percent; a binary header would recover most of it.
