# udp-diode Helm chart

Deploys the udp-diode sender, receiver and an optional demo sink. Defaults give a
working one-way transfer in one namespace: strict mode (no feedback), parity
families, restricted Pod Security, default-deny NetworkPolicy.

## Install

```bash
kubectl create namespace udp-diode
kubectl label namespace udp-diode pod-security.kubernetes.io/enforce=restricted
helm install udp-diode oci://ghcr.io/newen-systems/charts/udp-diode -n udp-diode --wait
helm test udp-diode -n udp-diode --logs
```

`helm test` POSTs 4 MiB of random bytes to the sender and waits for the sink to
report the same SHA-256. From a clone, use `./charts/udp-diode` in place of the
OCI reference.

## Cluster prerequisites

Nothing in the chart checks these.

- A default StorageClass, or `sender.persistence.storageClass` and
  `receiver.persistence.storageClass` (one RWO volume per role for spool and ledger).
- A CNI that enforces NetworkPolicy (Canal on RKE2, Calico, Cilium). Without one
  the policies are accepted and do nothing.
- DNS pods labelled `k8s-app: kube-dns` (true for RKE2, kubeadm, kind, EKS, GKE).
  Otherwise set `networkPolicy.dns`.
- For a sender in another cluster: a LoadBalancer or NodePort that passes UDP.

## Two clusters

One namespace keeps the path one-way by NetworkPolicy only. For a real boundary
put the sender and the receiver in different clusters, or behind a hardware diode.

1. Make one `api_token` and one `data_key` (each 16 or more printable bytes) and
   create the same Secret on both sides:
   `kubectl -n udp-diode create secret generic udp-diode-keys --from-file=api_token --from-file=data_key`
2. Receiver side: copy [examples/values-receiver.yaml](examples/values-receiver.yaml),
   set `receiver.deliveryUrl` and the address ranges, install with `-f`.
3. Sender side: copy [examples/values-sender.yaml](examples/values-sender.yaml),
   set `sender.peer` to the receiver's UDP address, install with `-f`.

## Values

[values.yaml](values.yaml) documents every value. The ones you are most likely to set:

| Value | Default | Meaning |
|---|---|---|
| `keys.existingSecret` | `""` | Secret with `api_token` and `data_key`. Empty: generated on first install and kept on upgrade and uninstall |
| `sender.peer` | this release's receiver | Receiver UDP `host:port` |
| `sender.env` | strict, families, 200 Mbit/s | Any `DIODE_*` setting (main README, "HTTP service") |
| `receiver.deliveryUrl` | demo sink | Where verified objects are POSTed |
| `receiver.service.type` | `ClusterIP` | `LoadBalancer` for a sender outside the cluster |
| `sink.enabled` | `true` | Demo destination. Turn off in production |
| `networkPolicy.*` | on | Extra peers for senders, clients and destinations outside the release |
| `image.tag` | chart `appVersion` | Pin a digest in production: `0.2.0@sha256:...` |

## Not automated

- Generated keys use Helm `lookup`, which returns nothing under `helm template`.
  Argo CD and Flux renders therefore make new keys on every sync. Set
  `keys.existingSecret` from your secret store (External Secrets, Sealed Secrets, SOPS) there.
- Receipt mode (`DIODE_FEEDBACK=receipts`) needs a receipt key and a return path.
  The chart deploys strict one-way only.
- The chart does not create the namespace, so that it can carry the Pod Security labels.
