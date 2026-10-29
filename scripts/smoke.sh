#!/usr/bin/env bash
# The part 2 checks (auth-plan.md section 12.2): the provider answers, signs with ES256, holds
# the registered clients to their registrations, and keeps its admin API off the network.
set -uo pipefail
cd "$(dirname "$0")/.."
set -a; source .env; set +a
PUB=http://127.0.0.1:4444
ADMIN=http://127.0.0.1:4445
pass=0; fail=0
check() { if [[ "$2" == "0" ]]; then echo "PASS  $1"; pass=$((pass+1)); else echo "FAIL  $1${3:+ — $3}"; fail=$((fail+1)); fi; }

# 1. Discovery
disc=$(curl -fsS "$PUB/.well-known/openid-configuration")
[[ $(jq -r .issuer <<<"$disc") == "http://localhost:4444" ]]; check "discovery names the issuer" $?
jq -e '.code_challenge_methods_supported | index("S256")' <<<"$disc" >/dev/null; check "discovery offers PKCE S256" $?
[[ $(jq -r '.registration_endpoint // empty' <<<"$disc") == "" ]] || ! curl -fsS -o /dev/null -X POST "$PUB/oauth2/register" -H 'Content-Type: application/json' -d '{}' 2>/dev/null
check "dynamic client registration is off" $?

# 2. Keys
jwks=$(curl -fsS "$PUB/.well-known/jwks.json")
[[ $(jq '[.keys[] | select(.alg != "ES256")] | length' <<<"$jwks") == 0 && $(jq '.keys | length' <<<"$jwks") -ge 2 ]]
check "JWKS publishes ES256 keys only" $?
jq -e '[.keys[] | select(has("d"))] | length == 0' <<<"$jwks" >/dev/null; check "JWKS carries no private key material" $?

# 3. A client-credentials token: signed ES256 by a published key, addressed to its audience
tok=$(curl -fsS -u "uni-auth-service:$UNI_AUTH_SERVICE_SECRET" -d grant_type=client_credentials \
      -d scope=identity:lifecycle -d audience=gsn-api-internal "$PUB/oauth2/token" | jq -r .access_token)
out=$(node scripts/verify-jwt.mjs "$tok" "$PUB/.well-known/jwks.json" 2>&1); check "access token verifies against the JWKS (ES256)" $? "$out"
[[ $(jq -r '.claims.aud | index("gsn-api-internal") != null' <<<"$out" 2>/dev/null) == true ]]; check "aud is the requested API" $?
[[ $(jq -r '.claims.client_id' <<<"$out" 2>/dev/null) == "uni-auth-service" ]]; check "client_id names the caller" $?
[[ $(jq -r '.claims.exp - .claims.iat' <<<"$out" 2>/dev/null) == 900 ]]; check "access token lives 900 s" $?
code=$(curl -sS -o /dev/null -w '%{http_code}' -u "uni-auth-service:$UNI_AUTH_SERVICE_SECRET" \
       -d grant_type=client_credentials -d audience=gsn-api "$PUB/oauth2/token")
[[ "$code" == 400 ]]; check "an audience the client is not registered for is refused" $? "HTTP $code"
code=$(curl -sS -o /dev/null -w '%{http_code}' -u "uni-auth-service:wrong" -d grant_type=client_credentials "$PUB/oauth2/token")
[[ "$code" == 401 ]]; check "a wrong client secret is refused" $? "HTTP $code"

# 4. The authorization endpoint: PKCE enforced, redirect URIs exact, login handed to uni-auth
auth="$PUB/oauth2/auth?client_id=gsn-web&response_type=code&scope=openid&state=abcdefgh12345678"
redir=http%3A%2F%2Flocalhost%3A5173%2Fcallback
# PKCE is enforced when Hydra builds the response, after login and consent, so a missing
# challenge cannot be seen on this first hop; scripts/round-trip.mjs proves it end to end.
verifier=$(openssl rand -hex 32)
challenge=$(printf %s "$verifier" | openssl dgst -sha256 -binary | openssl base64 -A | tr '+/' '-_' | tr -d '=')
loc=$(curl -sS -o /dev/null -w '%{redirect_url}' "$auth&redirect_uri=$redir&code_challenge=$challenge&code_challenge_method=S256")
[[ "$loc" == http://localhost:3100/login\?login_challenge=* ]]; check "a valid request is handed to the uni-auth login screen" $? "$loc"
loc=$(curl -sS -o /dev/null -w '%{redirect_url}' "$auth&redirect_uri=https%3A%2F%2Fevil.example%2Fcb&code_challenge=$challenge&code_challenge_method=S256")
[[ "$loc" != https://evil.example* ]]; check "an unregistered redirect URI is never redirected to" $? "$loc"
loc=$(curl -sS -o /dev/null -w '%{redirect_url}' "${auth/gsn-web/nobody}&redirect_uri=$redir&code_challenge=$challenge&code_challenge_method=S256")
[[ "$loc" != http://localhost:5173* ]]; check "an unknown client is never redirected back" $? "$loc"

# 5. The admin API stays off the network
ports=$(docker compose port hydra 4445 2>/dev/null)
[[ "$ports" == 127.0.0.1:* ]]; check "admin is published on loopback only" $? "$ports"
lan=$(ipconfig getifaddr en0 2>/dev/null || hostname -I 2>/dev/null | awk '{print $1}')
if [[ -n "$lan" ]]; then
  ! curl -fsS -m 3 -o /dev/null "http://$lan:4445/admin/clients" 2>/dev/null; check "admin is unreachable on the LAN address ($lan)" $?
fi
[[ $(docker compose ps hydra-db --format json | jq '[.Publishers[]? | select(.PublishedPort != 0)] | length') == 0 ]]; check "Hydra's database publishes no port" $?

echo "$pass passed, $fail failed"
echo
node scripts/round-trip.mjs || fail=$((fail+1))
[[ $fail == 0 ]]
