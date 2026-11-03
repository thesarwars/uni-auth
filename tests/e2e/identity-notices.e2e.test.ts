import type { NestFastifyApplication } from '@nestjs/platform-fastify';
import { createServer, type Server } from 'node:http';
import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import { IdentityNotices } from '../../src/lifecycle/identity-notices';
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
} from '../support/browser';
import { closeMembers, createMember, sql } from '../support/members';

/**
 * Identity notices (auth-plan.md section 12.2, part 7): when an identity closes or is erased,
 * its sessions end at Hydra and the product that trusts uni-auth is told, until it says it
 * has acted (AU-8).
 *
 * One listener plays both the product (IDENTITY_NOTICE_URL) and the back-channel logout URI of
 * a client registered for this suite.
 */

const CLIENT = 'test-notices';
const PORT = 4780;

let app: NestFastifyApplication;
let notices: IdentityNotices;
let listener: Server;
let productAnswers = 204;
const received: { auth: string; body: Record<string, any> }[] = [];
const logoutTokens: Record<string, any>[] = [];

beforeAll(async () => {
  listener = createServer((req, res) => {
    let body = '';
    req.on('data', (c) => (body += c));
    req.on('end', () => {
      if (req.url === '/backchannel') {
        const token = new URLSearchParams(body).get('logout_token');
        if (token) logoutTokens.push(claims(token));
        res.end();
        return;
      }
      received.push({ auth: req.headers.authorization ?? '', body: JSON.parse(body) });
      res.statusCode = productAnswers;
      res.end();
    });
  });
  await new Promise<void>((r) => listener.listen(PORT, '0.0.0.0', r));
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
      skip_consent: true,
      metadata: { first_party: true, product: 'test' },
      backchannel_logout_uri: `http://host.docker.internal:${PORT}/backchannel`,
      backchannel_logout_session_required: true,
    }),
  });
  expect(reg.status).toBe(201);
  app = await startApp();
  notices = app.get(IdentityNotices);
  // Notices other suites left behind are not this suite's business.
  await notices.drain();
});

afterAll(async () => {
  await app?.close();
  await fetch(`${HYDRA_ADMIN}/admin/clients/${CLIENT}`, { method: 'DELETE' });
  await new Promise<void>((r) => listener.close(() => r()));
  await closeMembers();
});

beforeEach(() => {
  productAnswers = 204;
  received.length = 0;
});

/** A member signed in to the suite's client: the session id and a refresh token. */
async function signedIn() {
  const m = await createMember();
  const b = browser();
  const { verifier, challenge } = pkce();
  let page = (await b.follow(authorizeUrl(challenge, { client_id: CLIENT }))).hop;
  page = await b.post(`${APP}/login`, {
    ...formFields(page.html),
    action: 'identify',
    identifier: m.email,
  });
  page = await b.post(`${APP}/login`, {
    ...formFields(page.html),
    action: 'password',
    password: m.password,
  });
  const { url } = await b.follow(page.location!);
  const t = await exchange(new URL(url).searchParams.get('code')!, verifier, CLIENT);
  expect(t.status).toBe(200);
  return { ...m, sid: claims(t.body.access_token).sid as string, refresh: t.body.refresh_token };
}

async function refresh(token: string): Promise<number> {
  const r = await fetch(`${HYDRA}/oauth2/token`, {
    method: 'POST',
    headers: { 'content-type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({
      grant_type: 'refresh_token',
      client_id: CLIENT,
      refresh_token: token,
    }).toString(),
  });
  return r.status;
}

const noticesOf = (identityId: string) =>
  sql(
    `SELECT event, attempts, last_error, sessions_ended_at, delivered_at, next_attempt_at
       FROM identity_notice WHERE identity_id = $1 ORDER BY occurred_at, event`,
    [identityId],
  );

async function logoutTokenFor(sid: string) {
  for (let i = 0; i < 30; i += 1) {
    const found = logoutTokens.find((t) => t.sid === sid);
    if (found) return found;
    await new Promise((r) => setTimeout(r, 100));
  }
  return undefined;
}

describe('an identity that closes', () => {
  it('ends its sessions in every client and tells the product, as uni-auth-service', async () => {
    const m = await signedIn();
    await sql("UPDATE identity SET status = 'closed' WHERE id = $1", [m.identityId]);

    expect(await notices.drain()).toBe(1);

    expect(await logoutTokenFor(m.sid)).toMatchObject({ sid: m.sid, aud: [CLIENT] });
    expect(await refresh(m.refresh)).not.toBe(200);

    expect(received).toHaveLength(1);
    const [{ auth, body }] = received as [(typeof received)[0]];
    expect(body).toEqual({ sub: m.identityId, event: 'closed', occurred_at: expect.any(String) });
    expect(auth.startsWith('Bearer ')).toBe(true);
    expect(claims(auth.slice(7))).toMatchObject({
      iss: HYDRA,
      aud: ['gsn-api-internal'],
      client_id: 'uni-auth-service',
      sub: 'uni-auth-service',
      scp: ['identity:lifecycle'],
    });

    const [row] = await noticesOf(m.identityId);
    expect(row).toMatchObject({ event: 'closed', attempts: 1, last_error: null });
    expect(row!.sessions_ended_at).not.toBeNull();
    expect(row!.delivered_at).not.toBeNull();
  });

  it('keeps trying while the product cannot take it, ending the sessions only once', async () => {
    const m = await signedIn();
    await sql("UPDATE identity SET status = 'closed' WHERE id = $1", [m.identityId]);

    productAnswers = 503;
    expect(await notices.drain()).toBe(0);
    const [failed] = await noticesOf(m.identityId);
    expect(failed).toMatchObject({ attempts: 1, last_error: 'the product answered 503' });
    expect(failed!.delivered_at).toBeNull();
    expect(failed!.sessions_ended_at).not.toBeNull();
    expect(failed!.next_attempt_at.getTime()).toBeGreaterThan(Date.now() + 20_000);
    // Not due yet: nothing is sent.
    expect(await notices.drain()).toBe(0);
    expect(received).toHaveLength(1);

    productAnswers = 204;
    await sql('UPDATE identity_notice SET next_attempt_at = now() WHERE identity_id = $1', [
      m.identityId,
    ]);
    expect(await notices.drain()).toBe(1);
    const [done] = await noticesOf(m.identityId);
    expect(done).toMatchObject({ attempts: 2, last_error: null });
    expect(done!.sessions_ended_at).toEqual(failed!.sessions_ended_at);
  });
});

describe('an identity that is erased', () => {
  it('tells the product it closed and then that it was erased, and no refresh token survives', async () => {
    const m = await signedIn();
    await sql("UPDATE identity SET status = 'closed' WHERE id = $1", [m.identityId]);
    await sql('UPDATE identity SET display_name = NULL, erased_at = now() WHERE id = $1', [
      m.identityId,
    ]);
    // Erasure deleted the session row, so the refresh hook no longer knows the sid: Hydra
    // itself must have forgotten the token.
    expect(await sql('SELECT 1 FROM auth_session WHERE identity_id = $1', [m.identityId])).toEqual(
      [],
    );

    expect(await notices.drain()).toBe(2);
    expect(received.map((r) => r.body.event)).toEqual(['closed', 'erased']);
    expect(await refresh(m.refresh)).not.toBe(200);
  });
});

describe('the notice journal', () => {
  it('is written once per event, and a delivered notice is final and never deleted', async () => {
    const m = await createMember();
    await sql("UPDATE identity SET status = 'closed' WHERE id = $1", [m.identityId]);
    await notices.drain();
    const fail = (q: Promise<unknown>) =>
      q.then(
        () => '',
        (e: { message: string }) => e.message,
      );
    expect(
      await fail(
        sql('UPDATE identity_notice SET attempts = 9 WHERE identity_id = $1', [m.identityId]),
      ),
    ).toContain('a delivered notice is final');
    expect(
      await fail(sql('DELETE FROM identity_notice WHERE identity_id = $1', [m.identityId])),
    ).toContain('permission denied');
    expect(await noticesOf(m.identityId)).toHaveLength(1);
  });
});
