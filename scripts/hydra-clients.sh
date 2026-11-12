#!/usr/bin/env bash
# Registers every client in deploy/hydra/clients/ - the only way a client comes to exist:
# dynamic registration is off (hydra.yml). Idempotent: an existing client is replaced with
# the file's definition, so the files are the registry of record.
#
# CLIENTS_DIR picks another set: a deployment's are deploy/hydra/clients.prod/, whose
# ${GSN_WEB_ORIGIN}, ${GSN_API_URL} and ${UNI_AUTH_HOST} are filled in from the environment
# (envsubst).
set -euo pipefail
cd "$(dirname "$0")/.."
ADMIN="${HYDRA_ADMIN_URL:-http://127.0.0.1:4445}"
set -a; [[ -f .env ]] && source .env; set +a

DIR="${CLIENTS_DIR:-deploy/hydra/clients}"

for file in "$DIR"/*.json; do
  # Only the named variables: a stray $ in a definition stays as written.
  body=$(envsubst '${GSN_WEB_ORIGIN} ${GSN_API_URL} ${UNI_AUTH_HOST}' <"$file")
  if grep -q '\${' <<<"$body"; then
    echo "$file: unfilled placeholder (set GSN_WEB_ORIGIN, GSN_API_URL and UNI_AUTH_HOST)" >&2
    exit 1
  fi
  id=$(jq -r .client_id <<<"$body")
  method=$(jq -r .token_endpoint_auth_method <<<"$body")
  if [[ "$method" != "none" ]]; then
    # A confidential client's secret never lives in the repository.
    var="$(tr 'a-z-' 'A-Z_' <<<"$id")_SECRET"
    secret="${!var:?$var is not set (scripts/dev-secrets.sh)}"
    body=$(jq --arg s "$secret" '. + {client_secret: $s}' <<<"$body")
  fi
  if curl -fsS -o /dev/null "$ADMIN/admin/clients/$id" 2>/dev/null; then
    curl -fsS -X PUT "$ADMIN/admin/clients/$id" -H 'Content-Type: application/json' -d "$body" >/dev/null
    echo "$id: updated"
  else
    curl -fsS -X POST "$ADMIN/admin/clients" -H 'Content-Type: application/json' -d "$body" >/dev/null
    echo "$id: created"
  fi
done
