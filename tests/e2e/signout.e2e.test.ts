import type { NestFastifyApplication } from '@nestjs/platform-fastify';
import { createServer, type Server } from 'node:http';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { Outbox } from '../../src/delivery/outbox';
import { startApp } from '../support/app';
import {
  APP,
  HYDRA,
  HYDRA_ADMIN,
  authorizeUrl,
  browser,
  claims,
  exchange,
  formFields,
  pkce,
  type Browser,
  type Hop,
} from '../support/browser';
import { closeMembers, createMember, sql } from '../support/members';

/**
 * Sign-out and revocation, uni-auth's half (auth-plan.md section 12.2, part 7): a session that
 * ends - signed out, or revoked by a password reset - ends at Hydra too, every client hears of it
 * by back-channel logout, and its refresh tokens are refused by the refresh hook.
 *
 * A client registered for this suite sends its back-channel logout here, to a listener Hydra
 * reaches from its container as host.docker.internal.
 */

const CLIENT = 'test-signout';
const LISTENER_PORT = 4779;
const POST_LOGOUT = 'http://localhost:5173/';

let app: NestFastifyApplication;
let outbox: Outbox;
let listener: Server;
const logoutTokens: Record<string, any>[] = [];

beforeAll(async () => {
  listener = createServer((req, res) => {
    let body = '';
    req.on('data', (c) => (body += c));
    req.on('end', () => {
      const token = new URLSearchParams(body).get('logout_token');
      if (token) logoutTokens.push(claims(token));
      res.end();
    });
  });
  await new Promise<void>((r) => listener.listen(LISTENER_PORT, '0.0.0.0', r));
  await fetch(`${HYDRA_ADMIN}/admin/clients/${CLIENT}`, { method: 'DELETE' });
  const reg = await fetch(`${HYDRA_ADMIN}/admin/clients`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({
      client_id: CLIENT,
      token_endpoint_auth_method: 'none',
      grant_types: ['authorization_code', 'refresh_token'],
      response_types: ['code'],
      scope: 'openid offline_access',
      audience: ['gsn-api'],
      redirect_uris: ['http://localhost:5173/callback'],
      post_logout_redirect_uris: [POST_LOGOUT],
      skip_consent: true,
      metadata: { first_party: true, product: 'test' },
      backchannel_logout_uri: `http://host.docker.internal:${LISTENER_PORT}/backchannel`,
      backchannel_logout_session_required: true,
    }),
  });
  expect(reg.status).toBe(201);
  app = await startApp();
  outbox = app.get(Outbox);
});

afterAll(async () => {
  await app?.close();
  await fetch(`${HYDRA_ADMIN}/admin/clients/${CLIENT}`, { method: 'DELETE' });
  await new Promise<void>((r) => listener.close(() => r()));
  await closeMembers();
});

interface Session {
  b: Browser;
  sid: string;
  idToken: string;
  refreshToken: string;
}

async function post(b: Browser, page: Hop, fields: Record<string, string>): Promise<Hop> {
  return b.post(`${APP}/login`, { ...formFields(page.html), ...fields });
}

/** Signs a member in by password to `client`, in `b`, and returns the tokens. */
async function signIn(
  email: string,
  password: string,
  b: Browser = browser(),
  client = CLIENT,
): Promise<Session> {
  const { verifier, challenge } = pkce();
  let page = (await b.follow(authorizeUrl(challenge, { client_id: client }))).hop;
  page = await post(b, page, { action: 'identify', identifier: email });
  page = await post(b, page, { action: 'password', password });
  expect(page.status).toBe(303);
  const { url } = await b.follow(page.location!);
  const t = await exchange(new URL(url).searchParams.get('code')!, verifier, client);
  expect(t.status).toBe(200);
  return {
    b,
    sid: claims(t.body.access_token).sid as string,
    idToken: t.body.id_token,
    refreshToken: t.body.refresh_token,
  };
}

async function refresh(s: Session, client = CLIENT) {
  const r = await fetch(`${HYDRA}/oauth2/token`, {
    method: 'POST',
    headers: { 'content-type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({
      grant_type: 'refresh_token',
      client_id: client,
      refresh_token: s.refreshToken,
    }).toString(),
  });
  const body = (await r.json()) as Record<string, any>;
  if (r.ok) s.refreshToken = body.refresh_token;
  return { status: r.status, error: body.error as string | undefined };
}

/** The client's sign-out: RP-initiated logout, then the confirmation screen's answer. */
async function signOut(s: Session, action: 'sign_out' | 'cancel'): Promise<Hop> {
  const q = new URLSearchParams({
    id_token_hint: s.idToken,
    post_logout_redirect_uri: POST_LOGOUT,
  });
  const { hop } = await s.b.follow(`${HYDRA}/oauth2/sessions/logout?${q.toString()}`);
  expect(hop.html).toContain('Sign out');
  const answered = await s.b.post(`${APP}/logout`, { ...formFields(hop.html), action });
  if (answered.status === 303) await s.b.follow(answered.location!);
  return answered;
}

/** Waits for Hydra's back-channel logout naming `sid`. */
async function logoutTokenFor(sid: string): Promise<Record<string, any> | undefined> {
  for (let i = 0; i < 30; i += 1) {
    const found = logoutTokens.find((t) => t.sid === sid);
    if (found) return found;
    await new Promise((r) => setTimeout(r, 100));
  }
  return undefined;
}

describe('signing out', () => {
  it('ends the session in uni-auth, at Hydra and in every client, and its refresh tokens die', async () => {
    const m = await createMember();
    const s = await signIn(m.email, m.password);
    expect((await refresh(s)).status).toBe(200);

    await signOut(s, 'sign_out');

    const [row] = await sql<{ id: string; revoke_reason: string }>(
      'SELECT id, revoke_reason FROM auth_session WHERE sid = $1',
      [s.sid],
    );
    expect(row!.revoke_reason).toBe('sign_out');
    const [event] = await sql(
      "SELECT outcome, client_id, auth_session_id FROM auth_event WHERE identity_id = $1 AND kind = 'sign_out'",
      [m.identityId],
    );
    expect(event).toEqual({ outcome: 'success', client_id: CLIENT, auth_session_id: row!.id });

    const token = await logoutTokenFor(s.sid);
    expect(token).toMatchObject({
      iss: HYDRA,
      aud: [CLIENT],
      sid: s.sid,
      events: { 'http://schemas.openid.net/event/backchannel-logout': {} },
    });

    expect(await refresh(s)).toEqual({ status: 403, error: 'access_denied' });

    // Single sign-on is over in this browser: the sign-in screen again.
    const { url } = await s.b.follow(authorizeUrl(pkce().challenge, { client_id: CLIENT }));
    expect(url.startsWith(`${APP}/login?`)).toBe(true);
  });

  it('changes nothing when the member stays signed in', async () => {
    const m = await createMember();
    const s = await signIn(m.email, m.password);
    const stayed = await signOut(s, 'cancel');
    expect(stayed.html).toContain('still signed in');
    const [row] = await sql('SELECT revoked_at FROM auth_session WHERE sid = $1', [s.sid]);
    expect(row!.revoked_at).toBeNull();
    expect((await refresh(s)).status).toBe(200);
  });
});

describe('a password reset', () => {
  it('ends every other session at Hydra and in every client', async () => {
    const m = await createMember();
    const elsewhere = await signIn(m.email, m.password);

    // The reset, in another browser, through the default client.
    const b = browser();
    const { verifier, challenge } = pkce();
    let page = (await b.follow(authorizeUrl(challenge))).hop;
    page = await post(b, page, { action: 'identify', identifier: m.email });
    page = await post(b, page, { action: 'send_code', purpose: 'recovery' });
    const otpId = /name="otp_id" value="([^"]+)"/.exec(page.html)![1]!;
    page = await post(b, page, {
      action: 'verify_code',
      otp_id: otpId,
      code: outbox.last(m.email)!.code,
    });
    page = await post(b, page, {
      action: 'new_password',
      password: 'New-Password-1',
      confirm: 'New-Password-1',
    });
    const { url } = await b.follow(page.location!);
    const t = await exchange(new URL(url).searchParams.get('code')!, verifier);
    expect(t.status).toBe(200);

    expect(await logoutTokenFor(elsewhere.sid)).toMatchObject({ sid: elsewhere.sid });
    expect(await refresh(elsewhere)).toEqual({ status: 403, error: 'access_denied' });
    const fresh: Session = { b, sid: '', idToken: '', refreshToken: t.body.refresh_token };
    expect((await refresh(fresh, 'gsn-web')).status).toBe(200);
  });
});

describe('the refresh hook', () => {
  it('refuses a session whose identity is suspended', async () => {
    const m = await createMember();
    const s = await signIn(m.email, m.password);
    await sql("UPDATE identity SET status = 'suspended' WHERE id = $1", [m.identityId]);
    expect(await refresh(s)).toEqual({ status: 403, error: 'access_denied' });
  });

  const hook = (auth: string | null, body: unknown) =>
    fetch(`${APP}/hooks/refresh`, {
      method: 'POST',
      headers: { 'content-type': 'application/json', ...(auth ? { authorization: auth } : {}) },
      body: JSON.stringify(body),
    });
  const asHydra = `Bearer ${process.env.HYDRA_HOOK_SECRET}`;

  it('answers only Hydra', async () => {
    const body = { session: { extra: { sid: 'anything' } } };
    expect((await hook(null, body)).status).toBe(401);
    expect((await hook('Bearer not-the-secret', body)).status).toBe(401);
  });

  it('lets through a session uni-auth did not open, and refuses one with no sid', async () => {
    expect((await hook(asHydra, { session: { extra: { sid: 'admin-accepted' } } })).status).toBe(
      204,
    );
    expect((await hook(asHydra, { session: { extra: {} } })).status).toBe(403);
  });
});
