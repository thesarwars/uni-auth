# uni-auth

One identity provider for every product: the member signs in at one place, each application
is a registered OAuth client, and no application handles a password. The design, and the
reasons behind it, are in the GSN docs: `docs/dev-plan/auth-plan.md`.

uni-auth is two halves:

| Half                      | What it is                                                                                                                                                | State                                                                             |
| ------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------- |
| **Hydra** (Ory, v25.4.0)  | The protocol: `/oauth2/auth`, `/oauth2/token`, discovery, JWKS, revocation, the client registry and the consent store. Stores no users and no credentials | Part 2 — done                                                                     |
| **The login application** | The screens and the credentials: Hydra hands it every sign-in, sign-up and sign-out, and it answers through Hydra's admin API                             | Part 3 skeleton — signs in a fixed test member; real credentials arrive in part 4 |

The name is product-neutral on purpose. Products, brands and redirect URIs are client
registrations; nothing in the code names a product.

## Run it locally

Requires Docker, Node 22, `jq` and `openssl`. Install with npm 11.6 or newer: npm 11.3 crashes
resolving the test runner's dependencies.

```bash
scripts/dev-secrets.sh                # writes .env: random secrets and local settings (never overwrites a key)
docker compose up -d --wait           # Hydra public on :4444, admin on 127.0.0.1:4445
scripts/hydra-keys.sh                 # ES256 signing keys
scripts/hydra-clients.sh              # registers deploy/hydra/clients/*.json
npx npm@11.6.2 install
npm run dev                           # the login application on :3100
```

Then sign in as a client would - open this in a browser and press **Continue as dev-member**;
it ends on `localhost:5173/callback?code=...` (nothing listens there yet, which is fine). The
challenge is RFC 7636's example, so the code exchanges with the verifier
`dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk`:

```
http://localhost:4444/oauth2/auth?client_id=gsn-web&response_type=code&redirect_uri=http://localhost:5173/callback&scope=openid%20offline_access&audience=gsn-api&state=0123456789abcdef&code_challenge=E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM&code_challenge_method=S256
```

Checks:

```bash
npm run verify                        # typecheck, lint, and the e2e suite against the real Hydra
scripts/smoke.sh                      # Hydra on its own: keys, audiences, admin boundary, round trip
```

The e2e suite listens on :3100 itself, so stop `npm run dev` first.

## Layout

```
src/flows/                    login, consent, logout - Hydra's challenges, answered
src/hydra/                    the admin API client
src/common/                   pages, the CSRF guard, the error filter
views/                        server-rendered templates (Eta), one per screen
tests/e2e/                    the sign-in, sign-out and refusal flows against the real Hydra
deploy/hydra/hydra.yml        Hydra's configuration; no secrets
deploy/hydra/clients/*.json   the client registry of record
scripts/                      secrets, keys, client registration, Hydra checks
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
- **Every screen is server-rendered and works without JavaScript.** Accepting a sign-in calls
  the admin API, which only this server may reach.
- **Every form carries a CSRF token** checked against a signed cookie, and every page is
  `no-store`, `frame-ancestors 'none'`, `X-Frame-Options: DENY` and `no-referrer`. There is no
  CSP `form-action`: a sign-in form's redirect chain ends at whichever client asked, and browsers
  apply `form-action` to the whole chain.
- **Refusals are pages, never redirects.** An unknown challenge, a bad token or an error from
  Hydra renders the error screen; only Hydra's own `redirect_to` is ever followed.
- **A login challenge is bound to the browser that started it.** Hydra v25 challenges are
  stateless, so one read back after use still renders; Hydra's CSRF cookie is what refuses it in
  any other browser.
- **`DEV_TEST_SUBJECT` is the only credential until part 4**, and the process refuses to start
  with it in production.
- **Secrets come from the secret store outside local work.** `HYDRA_SECRETS_SYSTEM` encrypts
  the signing keys at rest: lose it and the keys are unreadable.

## Local client registrations

| Client             | Kind                             | Redirect                                                                                  | Audience                                  |
| ------------------ | -------------------------------- | ----------------------------------------------------------------------------------------- | ----------------------------------------- |
| `gsn-web`          | public, PKCE                     | `http://localhost:5173/callback` (Vite's default port; the web app is not scaffolded yet) | `gsn-api`                                 |
| `gsn-mobile`       | public, PKCE                     | `gostyles://auth/callback` (the scheme in the Expo app's `app.json`)                      | `gsn-api`                                 |
| `uni-auth-service` | confidential, client credentials | —                                                                                         | `gsn-api-internal`, scope `accounts:mint` |

Back-channel logout URIs are added in part 7.
