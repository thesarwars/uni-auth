// The full authorization-code round trip against the local Hydra, with this script playing
// both the browser and the login application (part 3 will be the real one). It proves the
// provider end to end: PKCE, single sign-on, the claims the API guard reads, code replay and
// refresh-token reuse detection.
//
// usage: node scripts/round-trip.mjs      (Hydra up, keys and clients registered)
import { createHash, randomBytes } from 'node:crypto';
import { execFileSync } from 'node:child_process';

const PUB = 'http://localhost:4444';
const ADMIN = 'http://127.0.0.1:4445';
const CLIENT = 'gsn-web';
const REDIRECT = 'http://localhost:5173/callback';
const LOGIN_UI = 'http://localhost:3100/login';
const CONSENT_UI = 'http://localhost:3100/consent';
const SUBJECT = 'smoke-subject';

let pass = 0;
let fail = 0;
const check = (name, ok, note = '') => {
  console.log(`${ok ? 'PASS' : 'FAIL'}  ${name}${!ok && note ? ` — ${note}` : ''}`);
  ok ? pass++ : fail++;
};

const b64url = (buf) => Buffer.from(buf).toString('base64url');
const claimsOf = (jwt) => JSON.parse(Buffer.from(jwt.split('.')[1], 'base64url'));

/** A browser: a cookie jar and redirects followed by hand, so each hop can be inspected. */
function browser() {
  const jar = new Map();
  return async function get(url) {
    const res = await fetch(url, {
      redirect: 'manual',
      headers: { cookie: [...jar].map(([k, v]) => `${k}=${v}`).join('; ') },
    });
    for (const c of res.headers.getSetCookie()) {
      const [pair] = c.split(';');
      const i = pair.indexOf('=');
      jar.set(pair.slice(0, i), pair.slice(i + 1));
    }
    return res.headers.get('location');
  };
}

async function admin(method, path, body) {
  const res = await fetch(`${ADMIN}${path}`, {
    method,
    headers: { 'content-type': 'application/json' },
    body: body && JSON.stringify(body),
  });
  if (!res.ok) throw new Error(`${method} ${path}: ${res.status} ${await res.text()}`);
  return res.json();
}

/**
 * Starts at the client's authorize URL and follows redirects, accepting login and consent
 * through the admin API whenever Hydra hands over, until it lands back on the client.
 * Returns the final callback URL and what the login request said.
 */
async function signIn(get, { pkce, audience = 'gsn-api' }) {
  const params = new URLSearchParams({
    client_id: CLIENT,
    response_type: 'code',
    redirect_uri: REDIRECT,
    scope: 'openid offline_access',
    state: b64url(randomBytes(16)),
    audience,
  });
  if (pkce) {
    params.set('code_challenge', b64url(createHash('sha256').update(pkce).digest()));
    params.set('code_challenge_method', 'S256');
  }
  let url = `${PUB}/oauth2/auth?${params}`;
  let login = null;
  let loginSessionId = null;
  for (let hop = 0; hop < 10; hop++) {
    const next = await get(url);
    if (!next) throw new Error(`no redirect from ${url}`);
    if (next.startsWith(REDIRECT)) return { callback: new URL(next), login, loginSessionId };
    if (next.startsWith(LOGIN_UI)) {
      const challenge = new URL(next).searchParams.get('login_challenge');
      login = await admin('GET', `/admin/oauth2/auth/requests/login?login_challenge=${challenge}`);
      const accepted = await admin(
        'PUT',
        `/admin/oauth2/auth/requests/login/accept?login_challenge=${challenge}`,
        login.skip
          ? { subject: login.subject }
          : { subject: SUBJECT, remember: true, remember_for: 0, acr: 'pwd', amr: ['pwd'] },
      );
      url = accepted.redirect_to;
      continue;
    }
    if (next.startsWith(CONSENT_UI)) {
      const challenge = new URL(next).searchParams.get('consent_challenge');
      const consent = await admin('GET', `/admin/oauth2/auth/requests/consent?consent_challenge=${challenge}`);
      loginSessionId = consent.login_session_id;
      const accepted = await admin(
        'PUT',
        `/admin/oauth2/auth/requests/consent/accept?consent_challenge=${challenge}`,
        {
          grant_scope: consent.requested_scope,
          grant_access_token_audience: consent.requested_access_token_audience,
          session: {
            access_token: { sid: consent.login_session_id, amr: consent.amr ?? ['pwd'] },
            id_token: {},
          },
        },
      );
      url = accepted.redirect_to;
      continue;
    }
    url = new URL(next, url).toString();
  }
  throw new Error('too many redirects');
}

async function token(form) {
  const res = await fetch(`${PUB}/oauth2/token`, {
    method: 'POST',
    headers: { 'content-type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({ client_id: CLIENT, ...form }),
  });
  return { status: res.status, body: await res.json() };
}

const verifyJwt = (jwt) =>
  JSON.parse(
    execFileSync('node', [new URL('./verify-jwt.mjs', import.meta.url).pathname, jwt, `${PUB}/.well-known/jwks.json`], {
      encoding: 'utf8',
    }),
  );

// --- A public client without PKCE is refused when the response is built ---------------------
{
  const get = browser();
  const { callback } = await signIn(get, { pkce: null });
  check(
    'a public client without PKCE gets no code',
    callback.searchParams.get('error') === 'invalid_request' && !callback.searchParams.has('code'),
    callback.toString(),
  );
}

// --- The full round trip ---------------------------------------------------------------------
const get = browser();
const verifier = b64url(randomBytes(32));
const first = await signIn(get, { pkce: verifier });
const code = first.callback.searchParams.get('code');
check('first sign-in shows the login screen (no provider session yet)', first.login && !first.login.skip);
check('the login screen is told which client is asking', first.login?.client?.client_id === CLIENT);
check('a PKCE sign-in returns a code to the registered callback', Boolean(code), first.callback.toString());

const wrong = await token({ grant_type: 'authorization_code', code, redirect_uri: REDIRECT, code_verifier: b64url(randomBytes(32)) });
check('a wrong PKCE verifier is refused', wrong.status === 400, JSON.stringify(wrong.body));

// The failed exchange above invalidates the code in fosite, so sign in again for a clean one.
const second = await signIn(get, { pkce: verifier });
check('second sign-in skips the login screen (single sign-on)', second.login?.skip === true && second.login?.subject === SUBJECT);
const code2 = second.callback.searchParams.get('code');
const t = await token({ grant_type: 'authorization_code', code: code2, redirect_uri: REDIRECT, code_verifier: verifier });
check('the code exchanges for access, ID and refresh tokens', t.status === 200 && t.body.access_token && t.body.id_token && t.body.refresh_token, JSON.stringify(t.body));

if (t.status === 200) {
  const at = verifyJwt(t.body.access_token);
  const c = at.claims;
  check('access token verifies against the JWKS (ES256)', at.header.alg === 'ES256');
  check('access token aud is the API, not the client', Array.isArray(c.aud) && c.aud.includes('gsn-api') && !c.aud.includes(CLIENT), JSON.stringify(c.aud));
  check('access token client_id names the client', c.client_id === CLIENT);
  check('access token sub is the subject the login app accepted', c.sub === SUBJECT);
  check('sid is a top-level claim and equals the provider session', c.sid && c.sid === second.loginSessionId, JSON.stringify(c));
  // 900 s, give or take: Hydra counts expiry from when the sign-in request started, and the
  // whole-second rounding of exp and iat can add one.
  check('access token lives 900 s', Math.abs(c.exp - c.iat - 900) <= 10 && c.exp - c.iat <= 901, `exp-iat=${c.exp - c.iat}`);
  const id = verifyJwt(t.body.id_token).claims;
  check('ID token is addressed to the client and names the session', id.aud.includes(CLIENT) && id.sid === c.sid);

  const r1 = await token({ grant_type: 'refresh_token', refresh_token: t.body.refresh_token });
  check('a refresh token rotates', r1.status === 200 && r1.body.refresh_token && r1.body.refresh_token !== t.body.refresh_token, `${r1.status} ${JSON.stringify(r1.body)}`);
  const reuse = await token({ grant_type: 'refresh_token', refresh_token: t.body.refresh_token });
  check('replaying the rotated refresh token is refused', r1.status === 200 && reuse.status >= 400);
  const after = await token({ grant_type: 'refresh_token', refresh_token: r1.body.refresh_token });
  check('reuse revokes the whole chain: the newest refresh token dies too', r1.status === 200 && after.status >= 400, JSON.stringify(after.body));
}

// --- Replaying a code refuses it and revokes what it already issued (RFC 6749 4.1.2) -------
{
  const v = b64url(randomBytes(32));
  const { callback } = await signIn(get, { pkce: v });
  const c = callback.searchParams.get('code');
  const issued = await token({ grant_type: 'authorization_code', code: c, redirect_uri: REDIRECT, code_verifier: v });
  const replay = await token({ grant_type: 'authorization_code', code: c, redirect_uri: REDIRECT, code_verifier: v });
  check('a replayed authorization code is refused', issued.status === 200 && replay.status === 400, JSON.stringify(replay.body));
  const refresh = await token({ grant_type: 'refresh_token', refresh_token: issued.body.refresh_token });
  check('the replay revokes the tokens the code already issued', refresh.status >= 400, JSON.stringify(refresh.body));
}

console.log(`${pass} passed, ${fail} failed`);
process.exit(fail ? 1 : 0);
