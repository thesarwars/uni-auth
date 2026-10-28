#!/usr/bin/env bash
# Writes .env with random local secrets. Refuses to overwrite one that exists: losing
# HYDRA_SECRETS_SYSTEM makes the stored signing keys unreadable.
set -euo pipefail
cd "$(dirname "$0")/.."
if [[ -f .env ]]; then
  echo ".env exists; leaving it alone." >&2
  exit 0
fi
rand() { openssl rand -hex 32; }
umask 077
cat > .env <<ENV
HYDRA_DB_PASSWORD=$(rand)
HYDRA_SECRETS_SYSTEM=$(rand)
HYDRA_SECRETS_COOKIE=$(rand)
UNI_AUTH_SERVICE_SECRET=$(rand)
ENV
echo "wrote .env"
