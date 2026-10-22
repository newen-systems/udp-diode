udp-diode moves files one way over UDP between two HTTP custody services. A client POSTs an object to the sender, which spools it and sends it as authenticated, FEC-protected frames. The receiver verifies it and delivers it over HTTP. It works with no return path, or with optional authenticated receipts that drive repair.

## Run it

`podman pull ghcr.io/newen-systems/udp-diode:0.1.0` (or docker), then see the README "Run it" section for Compose, the end-to-end smoke test and the Kubernetes (Kustomize) example. `podman build .` or `docker build .` builds it from source.

## In 0.1.0

- One image, two roles (`DIODE_MODE=sender|receiver`): standard-library Python, uid 10001, read-only root filesystem, no package manager tooling.
- Strict one-way mode (`DIODE_FEEDBACK=off`) and receipt mode (`receipts`).
- Per-frame HMAC on every data-track frame (`DIODE_FRAME_AUTH`, on by default), META HMAC and whole-object SHA-256 before publish.
- Interleaved multi-family XOR parity (`DIODE_FEC_FAMILIES`) for single-pass strict transfers. Measured over a site VPN at 68.8 Mbit/s with 14 of 14 delivered (64 to 512 MiB), against 43.9 Mbit/s for two passes on the same path.
- Signed heartbeat, drop counters by reason, kernel UDP counters and a receive-buffer warning in `/v1/stats`.
- Kubernetes example with restricted Pod Security, a ServiceAccount per role with no token, and default-deny NetworkPolicy.

## Security

See the README "Security" section for the review result, what was fixed and the known limits.
