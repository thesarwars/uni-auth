# uni-auth

One identity provider for every product: the member signs in at one place, each application
is a registered OAuth client, and no application handles a password. The design, and the
reasons behind it, are in the GSN docs: `docs/dev-plan/auth-plan.md`.

uni-auth is two halves:

| Half | What it is | State |
|---|---|---|
| **Hydra** (Ory, v25.4.0) | The protocol: `/oauth2/auth`, `/oauth2/token`, discovery, JWKS, revocation, the client registry and the consent store. Stores no users and no credentials | Part 2 — here |
| **The login application** | The screens and the credentials: Hydra hands it every sign-in, sign-up and sign-out, and it answers through Hydra's admin API | Part 3 — next |

The name is product-neutral on purpose. Products, brands and redirect URIs are client
registrations; nothing in the code names a product.

## Run it locally

Requires Docker, Node 22, `jq` and `openssl`.

```bash
scripts/dev-secrets.sh        # once: writes .env with random local secrets (never overwrites)
docker compose up -d --wait   # Hydra public on :4444, admin on 127.0.0.1:4445
scripts/hydra-keys.sh         # ES256 signing keys
scripts/hydra-clients.sh      # registers deploy/hydra/clients/*.json
scripts/smoke.sh              # the part 2 checks, then the full round trip
```

`scripts/round-trip.mjs` signs in end to end with no login application: it plays the browser
and accepts login and consent through the admin API, exactly where part 3's screens will sit.

## Layout

```
deploy/hydra/hydra.yml        Hydra's configuration; no secrets
deploy/hydra/clients/*.json   the client registry of record
scripts/                      secrets, keys, client registration, checks
docker-compose.yml            Hydra and its own PostgreSQL
```

## Rules that hold everywhere

- **The admin API never faces a network.** Locally it is published on loopback only; a
  deployment publishes it on no interface. It can register clients and accept any sign-in.
- **Clients come only from `deploy/hydra/clients/`.** Dynamic registration is off. A
  confidential client's secret comes from the environment, never the file.
- **Access tokens are ES256 JWTs**, verified by each API against the JWKS. `aud` is the API the
  token is for (`gsn-api`), `client_id` is the application that asked, and `sid` is the provider
  session the API's denylist checks.
- **PKCE is required for public clients.** Hydra enforces it when it builds the response, after
  login and consent, so a missing challenge is refused at the callback, not on the first hop.
- **Key rotation is additive.** `scripts/hydra-keys.sh --rotate` adds a signing key; the old one
  stays in the JWKS until every token it signed has expired (AU-5).
- **Secrets come from the secret store outside local work.** `HYDRA_SECRETS_SYSTEM` encrypts
  the signing keys at rest: lose it and the keys are unreadable.

## Local client registrations

| Client | Kind | Redirect | Audience |
|---|---|---|---|
| `gsn-web` | public, PKCE | `http://localhost:5173/callback` (Vite's default port; the web app is not scaffolded yet) | `gsn-api` |
| `gsn-mobile` | public, PKCE | `gostyles://auth/callback` (the scheme in the Expo app's `app.json`) | `gsn-api` |
| `uni-auth-service` | confidential, client credentials | — | `gsn-api-internal`, scope `accounts:mint` |

Back-channel logout URIs are added in part 7.
