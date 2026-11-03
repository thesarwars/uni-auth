#!/usr/bin/env bash
# Fills every empty secret in a deployment's .env with a random value, once. Never replaces a
# value already set: HYDRA_SECRETS_SYSTEM encrypts the signing keys, and a changed database
# password no longer matches the volume it created.
#
# usage: cp .env.prod.example .env && scripts/prod-secrets.sh
set -euo pipefail
cd "$(dirname "$0")/.."
[[ -f .env ]] || { echo "no .env: cp .env.prod.example .env first" >&2; exit 1; }

rand() { openssl rand -hex "$1"; }
for name in HYDRA_DB_PASSWORD IDENTITY_DB_PASSWORD UNI_AUTH_DB_PASSWORD HYDRA_SECRETS_SYSTEM \
  HYDRA_SECRETS_COOKIE HYDRA_HOOK_SECRET COOKIE_SECRET UNI_AUTH_SERVICE_SECRET; do
  if grep -qE "^$name=.+" .env; then
    echo "$name: kept"
  elif grep -qE "^$name=$" .env; then
    value=$(rand 32)
    # | is not in a hex string, so it is a safe sed delimiter.
    sed -i.tmp "s|^$name=$|$name=$value|" .env && rm -f .env.tmp
    echo "$name: generated"
  else
    echo "$name=$(rand 32)" >>.env
    echo "$name: generated"
  fi
done
chmod 600 .env
