udp-diode moves files one way over UDP between two HTTP custody services. A client POSTs an object to the sender, which spools it and sends it as authenticated, FEC-protected frames. The receiver verifies it and delivers it over HTTP. It works with no return path, or with optional authenticated receipts that drive repair.

## Run it

- Container: `podman pull ghcr.io/newen-systems/udp-diode:0.3.1` (or docker). `podman build .` or `docker build .` builds it from source.
- Kubernetes: `helm install udp-diode oci://ghcr.io/newen-systems/charts/udp-diode -n udp-diode`, then `helm test udp-diode -n udp-diode --logs`. See `charts/udp-diode/README.md`.

## In 0.3.1

### Bug Fixes

- Build tags no longer read as versions: platform images are pushed by digest with no tag and each build is tagged `sha-<first 7 hex>`, so Renovate with `loose` versioning stops offering a tag such as `<sha>-arm64` as a major version. Older build tags stay because earlier releases use them ([#3](https://github.com/newen-systems/udp-diode/pull/3))

### Chores

- Each GitHub release shows only its own section of these notes, grouped by type, with a link to the full history, and a build fails when `VERSION` has no section here ([#3](https://github.com/newen-systems/udp-diode/pull/3))

## In 0.3.0

### New Features

- Strict one-way mode sends interleaved parity families `12x240,12x248,12x256` by default. Set `DIODE_FEC_FAMILIES=off` for none, or set `DIODE_PARITY_GROUP` instead. Receipt mode is unchanged ([29480f6](https://github.com/newen-systems/udp-diode/commit/29480f6))

### Chores

- The chart no longer sets the families itself ([29480f6](https://github.com/newen-systems/udp-diode/commit/29480f6))

## In 0.2.0

- Helm chart, published to `oci://ghcr.io/newen-systems/charts/udp-diode` with each release. It replaces the Kustomize example.
  - Sender, receiver and demo sink in one namespace by default, or each side alone for two clusters.
  - Keys are generated and kept, or taken from an existing Secret.
  - Restricted Pod Security, a ServiceAccount per role with no token, default-deny NetworkPolicy.
  - `helm test` checks an end-to-end transfer.
- No change to the protocol or the image.

## In 0.1.0

- One image, two roles (`DIODE_MODE=sender|receiver`): standard-library Python, uid 10001, read-only root filesystem.
- Strict one-way mode (`DIODE_FEEDBACK=off`) and receipt mode (`receipts`).
- Per-frame HMAC on every data-track frame (`DIODE_FRAME_AUTH`, on by default), META HMAC and whole-object SHA-256 before publish.
- Interleaved multi-family XOR parity (`DIODE_FEC_FAMILIES`) for single-pass strict transfers. Measured over a site VPN at 68.8 Mbit/s with 14 of 14 delivered (64 to 512 MiB), against 43.9 Mbit/s for two passes on the same path.

## Security

See the README "Security" section for the review result, what was fixed and the known limits.
