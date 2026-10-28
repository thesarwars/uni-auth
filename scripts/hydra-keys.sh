#!/usr/bin/env bash
# Ensures both of Hydra's signing key sets sign with ES256 (auth-plan.md section 9).
#
# Hydra creates RS256 sets on first start. A key added to a set becomes the signing key and
# the older keys stay published in the JWKS, which is the rotation model too: run with
# --rotate to add a fresh ES256 key; retire the old one only after the last token it signed
# has expired (AU-5).
set -euo pipefail
ADMIN="${HYDRA_ADMIN_URL:-http://127.0.0.1:4445}"
ROTATE="${1:-}"

for set in hydra.jwt.access-token hydra.openid.id-token; do
  first_alg=$(curl -fsS "$ADMIN/admin/keys/$set" 2>/dev/null | jq -r '.keys[0].alg // empty' || true)
  if [[ "$first_alg" == "ES256" && "$ROTATE" != "--rotate" ]]; then
    echo "$set: signing with ES256 already"
    continue
  fi
  curl -fsS -X POST "$ADMIN/admin/keys/$set" \
    -H 'Content-Type: application/json' \
    -d "{\"alg\":\"ES256\",\"use\":\"sig\",\"kid\":\"$set-$(date -u +%Y%m%dT%H%M%SZ)\"}" >/dev/null
  echo "$set: new ES256 signing key added (was: ${first_alg:-none})"
done
