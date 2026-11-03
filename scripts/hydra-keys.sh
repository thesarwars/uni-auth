#!/usr/bin/env bash
# Hydra's signing keys (auth-plan.md section 9; the runbook is docs/key-rotation.md).
#
#   scripts/hydra-keys.sh                 both key sets sign with ES256 (first run: Hydra makes RS256)
#   scripts/hydra-keys.sh --list          each set's keys, newest - the signing key - first
#   scripts/hydra-keys.sh --rotate        a fresh ES256 key in each set; it signs from now on, and
#                                         the older keys stay published so their tokens still verify
#   scripts/hydra-keys.sh --retire <kid>  removes a key that no longer signs, once the key that
#                                         replaced it has signed for OVERLAP_SECONDS (default 1800,
#                                         two access-token lifetimes), so no live token needs it (AU-5)
#   scripts/hydra-keys.sh --retire <kid> --now
#                                         the same without waiting: a compromised key. Every token it
#                                         signed stops verifying at once; members sign in again.
set -euo pipefail
ADMIN="${HYDRA_ADMIN_URL:-http://127.0.0.1:4445}"
SETS=(hydra.jwt.access-token hydra.openid.id-token)
OVERLAP_SECONDS="${OVERLAP_SECONDS:-1800}"
cmd="${1:-}"

keys() { curl -fsS "$ADMIN/admin/keys/$1" | jq -r '.keys[].kid'; }

# The time a key was added, from its kid (<set>-YYYYMMDDTHHMMSSZ), in epoch seconds; empty if
# the kid carries none (a key Hydra made itself).
added_at() {
  local stamp="${1##*-}"
  [[ "$stamp" =~ ^[0-9]{8}T[0-9]{6}Z$ ]] || return 0
  date -u -j -f '%Y%m%dT%H%M%SZ' "$stamp" +%s 2>/dev/null ||
    date -u -d "${stamp:0:4}-${stamp:4:2}-${stamp:6:2} ${stamp:9:2}:${stamp:11:2}:${stamp:13:2}" +%s
}

case "$cmd" in
  --list)
    for set in "${SETS[@]}"; do
      echo "$set"
      keys "$set" | awk 'NR == 1 { print "  " $0 "  (signing)"; next } { print "  " $0 }'
    done
    ;;

  --retire)
    kid="${2:?usage: scripts/hydra-keys.sh --retire <kid> [--now]}"
    now_flag="${3:-}"
    set_of=""
    for set in "${SETS[@]}"; do
      if keys "$set" | grep -qxF "$kid"; then set_of="$set"; fi
    done
    [[ -n "$set_of" ]] || { echo "no key $kid in ${SETS[*]}" >&2; exit 1; }
    signing=$(keys "$set_of" | head -1)
    if [[ "$kid" == "$signing" ]]; then
      echo "$kid is $set_of's signing key: rotate first (--rotate), then retire it" >&2
      exit 1
    fi
    if [[ "$now_flag" != "--now" ]]; then
      since=$(added_at "$signing")
      if [[ -z "$since" ]]; then
        echo "cannot tell when $signing began signing; retire with --now only if you mean it" >&2
        exit 1
      fi
      age=$(($(date -u +%s) - since))
      if ((age < OVERLAP_SECONDS)); then
        echo "$signing has signed for ${age}s; $kid may still verify live tokens until it has" \
          "signed for ${OVERLAP_SECONDS}s (again in $((OVERLAP_SECONDS - age))s, or --now for a" \
          "compromised key)" >&2
        exit 1
      fi
    fi
    curl -fsS -X DELETE "$ADMIN/admin/keys/$set_of/$(jq -rn --arg k "$kid" '$k|@uri')" >/dev/null
    echo "$set_of: $kid retired; it is no longer published"
    ;;

  "" | --rotate)
    for set in "${SETS[@]}"; do
      first_alg=$(curl -fsS "$ADMIN/admin/keys/$set" 2>/dev/null | jq -r '.keys[0].alg // empty' || true)
      if [[ "$first_alg" == "ES256" && "$cmd" != "--rotate" ]]; then
        echo "$set: signing with ES256 already"
        continue
      fi
      curl -fsS -X POST "$ADMIN/admin/keys/$set" \
        -H 'Content-Type: application/json' \
        -d "{\"alg\":\"ES256\",\"use\":\"sig\",\"kid\":\"$set-$(date -u +%Y%m%dT%H%M%SZ)\"}" >/dev/null
      echo "$set: new ES256 signing key added (was: ${first_alg:-none})"
    done
    ;;

  *)
    sed -n '2,16p' "$0" | sed 's/^# \{0,1\}//'
    exit 1
    ;;
esac
