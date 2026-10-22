#!/usr/bin/env bash
# Create demo secrets (random, never committed). Distinct forward and reverse keys.
set -euo pipefail
cd "$(dirname "$0")"
umask 077
mkdir -p secrets
for n in api_token data_key receipt_key; do
  [[ -s secrets/$n ]] || openssl rand -hex 32 >secrets/$n
  chmod 0644 secrets/$n   # the container user (uid 10001) must read the bind-mounted file
done
chmod 0755 secrets
