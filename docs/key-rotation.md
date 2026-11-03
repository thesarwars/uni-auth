# Signing-key rotation

uni-auth signs every access token and ID token with an ES256 key held by Hydra, and publishes
the public halves at `/.well-known/jwks.json`. Every API that trusts uni-auth verifies tokens
locally against that JWKS. This runbook changes the signing key without signing anyone out
(auth-plan.md `AU-5`), or, for a compromised key, at once.

There are two key sets, rotated together: `hydra.jwt.access-token` (access tokens and
back-channel logout tokens) and `hydra.openid.id-token` (ID tokens). Refresh tokens are opaque
and are not signed with these keys, so rotation never touches them.

## What the APIs do

GSN's Auth service (`apps/auth-service/src/modules/auth/uni-auth-token.ts`) keeps the JWKS for
an hour. A token whose `kid` it has not seen makes it fetch the JWKS again, rate-limited, so a
new key is picked up on its first token and a retired one is forgotten within the hour. No API
needs a deploy or a restart to follow a rotation.

## Scheduled rotation

Every 90 days, or when an operator who could read `HYDRA_SECRETS_SYSTEM` leaves.

1. **Add the new key.** From a host that reaches Hydra's admin API (never public, `AU-2`):

   ```sh
   scripts/hydra-keys.sh --rotate
   scripts/hydra-keys.sh --list      # the new key is first, marked (signing)
   ```

   Hydra signs with the new key from this moment. The old key stays published, so every
   token it signed still verifies.

2. **Check the new key reaches the APIs.** Sign in to GSN web; the API accepts the new token.
   `scripts/smoke.sh` checks that the JWKS still publishes ES256 keys only, with no private
   material.

3. **Wait.** At least 30 minutes, two access-token lifetimes (900 s each). After that no live
   token was signed by the old key.

4. **Retire the old key.**

   ```sh
   scripts/hydra-keys.sh --retire <old access-token kid>
   scripts/hydra-keys.sh --retire <old id-token kid>
   ```

   The script refuses to retire the signing key, and refuses an old key until its replacement
   has signed for `OVERLAP_SECONDS` (1800). Keep at most the signing key and the one before it.

## A compromised key

When a private key may have been read (a leaked database dump together with
`HYDRA_SECRETS_SYSTEM`, a compromised Hydra host):

1. `scripts/hydra-keys.sh --rotate`
2. `scripts/hydra-keys.sh --retire <compromised kid> --now`, for each set.

Every token the old key signed stops verifying at once, including any an attacker made with
it, and each API refuses them as soon as it has fetched the JWKS again: at once for a `kid` it
does not know, and within an hour for one it had cached. To close that hour, restart the APIs.
Members' apps refresh, which issues tokens under the new key; nobody has to sign in again
unless their refresh token is also suspect, in which case revoke the sessions too.

If `HYDRA_SECRETS_SYSTEM` itself leaked, every stored key is readable: rotate it in Hydra's
configuration first (Hydra decrypts with every listed secret and encrypts with the first),
then rotate the keys as above.

## Rehearsed

2026-11-03, against the local stack: a token signed by the old key and one signed by the new
key both verified after `--rotate`; `--retire` refused the signing key and refused the old key
inside the overlap; `--retire --now` removed the old key, after which its token failed and the
new one still verified.
