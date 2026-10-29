# uni-auth

One identity provider for every product: the member signs in at one place, each application
is a registered OAuth client, and no application handles a password. The design, and the
reasons behind it, are in the GSN docs: `docs/dev-plan/auth-plan.md`.

uni-auth is two halves:

| Half                      | What it is                                                                                                                                                | State                                                                              |
| ------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------- |
| **Hydra** (Ory, v25.4.0)  | The protocol: `/oauth2/auth`, `/oauth2/token`, discovery, JWKS, revocation, the client registry and the consent store. Stores no users and no credentials | Part 2 — done                                                                      |
| **The login application** | The screens and the credentials: Hydra hands it every sign-in, sign-up and sign-out, and it answers through Hydra's admin API                             | Part 4 — password sign-in with its throttle; codes, recovery and Google/Apple next |
| **The identity database** | uni-auth's own PostgreSQL: identities, identifiers, credentials, sessions and the auth journal. A product stores only the `sub`                           | Part 1 — schema done (`db/migrations/0001_identity.sql`)                           |

The name is product-neutral on purpose. Products, brands and redirect URIs are client
registrations; nothing in the code names a product.

## Run it locally

Requires Docker, Node 22, `jq` and `openssl`. Install with npm 11.6 or newer: npm 11.3 crashes
resolving the test runner's dependencies.

```bash
scripts/dev-secrets.sh                # writes .env: random secrets and local settings (never overwrites a key)
docker compose up -d --wait           # Hydra public on :4444, admin on 127.0.0.1:4445; identity DB on 127.0.0.1:5434; Redis on 127.0.0.1:6380
scripts/hydra-keys.sh                 # ES256 signing keys
scripts/hydra-clients.sh              # registers deploy/hydra/clients/*.json
npx npm@11.6.2 install
npm run db:migrate                    # applies db/migrations/*.sql as the owner role
npm run db:dev-roles                  # local login role uni_auth_api (refused in production)
npm run dev:member -- dev@example.com 'Dev-Password-1'   # someone to sign in as, until sign-up (part 5)
npm run dev                           # the login application on :3100
```

Then sign in as a client would - open this in a browser and sign in as that member; it ends on `localhost:5173/callback?code=...` (nothing listens there yet, which is fine). The
challenge is RFC 7636's example, so the code exchanges with the verifier
`dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk`:

```
http://localhost:4444/oauth2/auth?client_id=gsn-web&response_type=code&redirect_uri=http://localhost:5173/callback&scope=openid%20offline_access&audience=gsn-api&state=0123456789abcdef&code_challenge=E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM&code_challenge_method=S256
```

Checks:

```bash
npm run verify                        # typecheck, lint, the schema suite and the e2e suite against the real Hydra
scripts/smoke.sh                      # Hydra on its own: keys, audiences, admin boundary, round trip
```

The e2e suite listens on :3100 itself, so stop `npm run dev` first.

## Layout

```
src/flows/                    login, consent, logout - Hydra's challenges, answered
src/hydra/                    the admin API client
src/common/                   pages, the CSRF guard, the error filter
src/identity/                 identifier parsing and the identity tables' statements
src/credentials/              password hashing and the policy checklist
src/throttle/                 the per-identifier and per-address password throttle (Redis)
src/db/                       the pool and transactions
views/                        server-rendered templates (Eta), one per screen
tests/e2e/                    the sign-in, sign-out and refusal flows against the real Hydra
tests/db/                     the identity schema's rules, run as the application role
db/migrations/                the identity database, hand-written SQL, applied in order
deploy/hydra/hydra.yml        Hydra's configuration; no secrets
deploy/hydra/clients/*.json   the client registry of record
scripts/                      secrets, keys, client registration, Hydra checks
docker-compose.yml            Hydra, its PostgreSQL, and the identity PostgreSQL
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
- **The identity database is uni-auth's alone.** No product reads it; a product learns who
  signed in from the token's `sub` and keeps its own account keyed by it. The application
  connects as a login role in `uni_auth_app`, which cannot delete identities, edit the journal,
  change the password policy or create objects; migrations run as the owner.
- **Credentials are never edited.** A new password is a new row and the old one is revoked;
  revoking a credential, suspending or closing an identity revokes its sessions in the same
  transaction. Erasure needs a closed identity and scrubs identifiers, secrets and journal
  detail, keeping the rows' shape.
- **A sign-in is recorded before a client hears of it.** The `auth_session` row, named by Hydra's
  login session id - the token's `sid` - is written before Hydra is told who signed in. Single
  sign-on asks the identity database too: a revoked session or a suspended identity ends
  Hydra's session and starts the flow again, with a screen.
- **The password throttle fails closed.** Five wrong passwords for one identifier pause it for
  fifteen minutes, and an address is refused after 100 failures in that window; both counted in
  Redis under hashed keys. If Redis is unreachable no password is checked, and `/ready` says so.
  `X-Forwarded-For` is believed only through `TRUST_PROXY_HOPS` proxies, so the address cannot
  be forged by the client.
- **Secrets come from the secret store outside local work.** `HYDRA_SECRETS_SYSTEM` encrypts
  the signing keys at rest: lose it and the keys are unreadable.

## Local client registrations

| Client             | Kind                             | Redirect                                                                                  | Audience                                       |
| ------------------ | -------------------------------- | ----------------------------------------------------------------------------------------- | ---------------------------------------------- |
| `gsn-web`          | public, PKCE                     | `http://localhost:5173/callback` (Vite's default port; the web app is not scaffolded yet) | `gsn-api`                                      |
| `gsn-mobile`       | public, PKCE                     | `gostyles://auth/callback` (the scheme in the Expo app's `app.json`)                      | `gsn-api`                                      |
| `uni-auth-service` | confidential, client credentials | —                                                                                         | `gsn-api-internal`, scope `identity:lifecycle` |

Back-channel logout URIs are added in part 7.
