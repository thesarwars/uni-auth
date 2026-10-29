import type { NestFastifyApplication } from '@nestjs/platform-fastify';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import {
  APP,
  HYDRA,
  HYDRA_ADMIN,
  REDIRECT,
  authorizeUrl,
  browser,
  claims,
  exchange,
  formFields,
  pkce,
  type Browser,
} from '../support/browser';
import { startApp } from '../support/app';
import { closeMembers, createMember, type Member } from '../support/members';

/**
 * Part 3's go/no-go (auth-plan.md section 12.2): a client completes redirect -> code -> token
 * against the real Hydra, with this application answering the login, consent and logout
 * challenges.
 */

let app: NestFastifyApplication;
let member: Member;
const THIRD_PARTY = 'test-third-party';

beforeAll(async () => {
  app = await startApp();
  member = await createMember();

  await fetch(`${HYDRA_ADMIN}/admin/clients/${THIRD_PARTY}`, { method: 'DELETE' });
  const created = await fetch(`${HYDRA_ADMIN}/admin/clients`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({
      client_id: THIRD_PARTY,
      client_name: 'Someone Else',
      token_endpoint_auth_method: 'none',
      grant_types: ['authorization_code'],
      response_types: ['code'],
      scope: 'openid',
      audience: ['gsn-api'],
      redirect_uris: [REDIRECT],
      metadata: { first_party: false },
    }),
  });
  expect(created.status).toBe(201);
});

afterAll(async () => {
  await fetch(`${HYDRA_ADMIN}/admin/clients/${THIRD_PARTY}`, { method: 'DELETE' });
  await app?.close();
  await closeMembers();
});

/** From a client's authorize URL to the login page this application renders. */
async function toLoginPage(b: Browser, url: string) {
  const { url: at, hop } = await b.follow(url);
  return { at, hop };
}

/** Identifier, then password, on a login page already open; returns where the client lands. */
async function complete(b: Browser, html: string, who: Member = member): Promise<URL> {
  const identified = await b.post(`${APP}/login`, {
    ...formFields(html),
    action: 'identify',
    identifier: who.email,
  });
  expect(identified.status).toBe(200);
  expect(identified.html).toContain('Enter your password');
  const posted = await b.post(`${APP}/login`, {
    ...formFields(identified.html),
    action: 'password',
    password: who.password,
  });
  expect(posted.status).toBe(303);
  const { url } = await b.follow(posted.location!);
  return new URL(url);
}

/** Signs in through the login page and returns the URL the client gets back. */
async function signIn(b: Browser, challenge: string): Promise<URL> {
  const { at, hop } = await toLoginPage(b, authorizeUrl(challenge));
  expect(at.startsWith(`${APP}/login?`)).toBe(true);
  return complete(b, hop.html);
}

describe('sign-in round trip', () => {
  it('renders the login page for the client that asked, with no cache and no framing', async () => {
    const b = browser();
    const { at, hop } = await toLoginPage(b, authorizeUrl(pkce().challenge));
    expect(at).toMatch(/^http:\/\/localhost:3100\/login\?login_challenge=/);
    expect(hop.status).toBe(200);
    expect(hop.html).toContain('Sign in to continue to Go Style Network');
    expect(hop.html).toContain('autocomplete="username"');
    expect(formFields(hop.html)._csrf).toBeTruthy();
    expect(hop.headers.get('cache-control')).toBe('no-store');
    expect(hop.headers.get('content-security-policy')).toContain("frame-ancestors 'none'");
    expect(hop.headers.get('x-frame-options')).toBe('DENY');
    expect(hop.headers.get('referrer-policy')).toBe('no-referrer');
  });

  it('completes redirect -> code -> token, with the claims the API guard reads', async () => {
    const b = browser();
    const { verifier, challenge } = pkce();
    const back = await signIn(b, challenge);
    expect(back.origin + back.pathname).toBe(REDIRECT);
    const code = back.searchParams.get('code');
    expect(code).toBeTruthy();

    const t = await exchange(code!, verifier);
    expect(t.status).toBe(200);
    const at = claims(t.body.access_token);
    const id = claims(t.body.id_token);
    expect(at.sub).toBe(member.identityId);
    expect(at.aud).toContain('gsn-api');
    expect(at.client_id).toBe('gsn-web');
    expect(at.sid).toBeTruthy();
    expect(id.sid).toBe(at.sid);
    expect(at.amr).toEqual(['pwd']);
    expect(at.acr).toBe('aal1');
    expect(typeof at.auth_time).toBe('number');
    expect(t.body.refresh_token).toBeTruthy();
  });

  it('signs in to a second client with no screen once the provider session exists', async () => {
    const b = browser();
    await signIn(b, pkce().challenge);

    const { verifier, challenge } = pkce();
    const { url, hop } = await b.follow(
      authorizeUrl(challenge, {
        client_id: 'gsn-mobile',
        redirect_uri: 'gostyles://auth/callback',
      }),
    );
    expect(hop.html).not.toContain('Sign in to continue');
    const back = new URL(url);
    expect(back.protocol).toBe('gostyles:');
    const code = back.searchParams.get('code')!;
    expect(code).toBeTruthy();

    const res = await fetch(`${HYDRA}/oauth2/token`, {
      method: 'POST',
      headers: { 'content-type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        grant_type: 'authorization_code',
        client_id: 'gsn-mobile',
        code,
        redirect_uri: 'gostyles://auth/callback',
        code_verifier: verifier,
      }).toString(),
    });
    const body = (await res.json()) as Record<string, string>;
    expect(claims(body.access_token!).client_id).toBe('gsn-mobile');
  });

  it('returns access_denied to the client when the member cancels', async () => {
    const b = browser();
    const { hop } = await toLoginPage(b, authorizeUrl(pkce().challenge));
    const posted = await b.post(`${APP}/login`, { ...formFields(hop.html), action: 'cancel' });
    const { url } = await b.follow(posted.location!);
    const back = new URL(url);
    expect(back.origin + back.pathname).toBe(REDIRECT);
    expect(back.searchParams.get('error')).toBe('access_denied');
    expect(back.searchParams.has('code')).toBe(false);
  });

  it('declines a third-party client until consent is a real screen', async () => {
    const b = browser();
    const { hop } = await toLoginPage(
      b,
      authorizeUrl(pkce().challenge, { client_id: THIRD_PARTY, scope: 'openid' }),
    );
    expect(hop.html).toContain('Sign in to continue to Someone Else');
    const back = await complete(b, hop.html);
    expect(back.searchParams.get('error')).toBe('access_denied');
    expect(back.searchParams.has('code')).toBe(false);
  });
});

describe('refusals become pages, never redirects', () => {
  it('refuses a POST without the CSRF token', async () => {
    const b = browser();
    const { hop } = await toLoginPage(b, authorizeUrl(pkce().challenge));
    const fields = formFields(hop.html);
    delete fields._csrf;
    const posted = await b.post(`${APP}/login`, {
      ...fields,
      action: 'identify',
      identifier: member.email,
    });
    expect(posted.status).toBe(403);
    expect(posted.location).toBeNull();
    expect(posted.html).toContain('This page has expired');
  });

  it('refuses a token from another browser', async () => {
    const attacker = browser();
    const { hop: theirs } = await toLoginPage(attacker, authorizeUrl(pkce().challenge));
    const victim = browser();
    const { hop } = await toLoginPage(victim, authorizeUrl(pkce().challenge));
    const posted = await victim.post(`${APP}/login`, {
      ...formFields(hop.html),
      _csrf: formFields(theirs.html)._csrf!,
      action: 'identify',
      identifier: member.email,
    });
    expect(posted.status).toBe(403);
  });

  it('shows the expired page for an unknown challenge', async () => {
    const hop = await browser().get(`${APP}/login?login_challenge=not-a-challenge`);
    expect(hop.status).toBe(400);
    expect(hop.location).toBeNull();
    expect(hop.html).toContain('This sign-in link has expired');
  });

  it('a login challenge carried into another browser cannot complete a sign-in', async () => {
    // Hydra v25 challenges are stateless: one read back after use is still "valid", and our
    // page renders again. What stops a replay is Hydra's CSRF cookie, bound to the browser
    // that started the flow.
    const victim = browser();
    const { at } = await toLoginPage(victim, authorizeUrl(pkce().challenge));
    const attacker = browser();
    const page = await attacker.get(at);
    expect(page.status).toBe(200);
    const back = await complete(attacker, page.html);
    expect(back.searchParams.get('error')).toBe('request_forbidden');
    expect(back.searchParams.has('code')).toBe(false);
  });

  it("escapes Hydra's error text on the error page", async () => {
    const hop = await browser().get(
      `${APP}/error?error=invalid_request&error_description=${encodeURIComponent('<script>alert(1)</script>')}`,
    );
    expect(hop.status).toBe(400);
    expect(hop.html).not.toContain('<script>alert(1)</script>');
    expect(hop.html).toContain('&lt;script&gt;');
  });
});

describe('sign-out', () => {
  it('confirms, ends the provider session, and returns to the client', async () => {
    const b = browser();
    const { verifier, challenge } = pkce();
    const back = await signIn(b, challenge);
    const t = await exchange(back.searchParams.get('code')!, verifier);

    const start = `${HYDRA}/oauth2/sessions/logout?${new URLSearchParams({
      id_token_hint: t.body.id_token,
      post_logout_redirect_uri: 'http://localhost:5173/',
      state: 'bye-state-1234',
    }).toString()}`;
    const { url, hop } = await b.follow(start);
    expect(url).toMatch(/^http:\/\/localhost:3100\/logout\?logout_challenge=/);
    expect(hop.html).toContain('Sign out of uni-auth?');
    expect(hop.html).toContain('will be signed out too');

    const posted = await b.post(`${APP}/logout`, { ...formFields(hop.html), action: 'sign_out' });
    const { url: landed } = await b.follow(posted.location!);
    expect(landed).toBe('http://localhost:5173/?state=bye-state-1234');

    // The provider session is gone: the next sign-in shows the login page again.
    const { at } = await toLoginPage(b, authorizeUrl(pkce().challenge));
    expect(at.startsWith(`${APP}/login?`)).toBe(true);
  });

  it('keeps the member signed in when they choose to stay', async () => {
    const b = browser();
    const { verifier, challenge } = pkce();
    const back = await signIn(b, challenge);
    const t = await exchange(back.searchParams.get('code')!, verifier);
    const { hop } = await b.follow(
      `${HYDRA}/oauth2/sessions/logout?id_token_hint=${encodeURIComponent(t.body.id_token)}`,
    );
    const stay = await b.post(`${APP}/logout`, { ...formFields(hop.html), action: 'cancel' });
    expect(stay.status).toBe(200);
    expect(stay.html).toContain('You are still signed in');

    // Single sign-on still works: no login page.
    const { url } = await b.follow(authorizeUrl(pkce().challenge));
    expect(url.startsWith(REDIRECT)).toBe(true);
  });
});

describe('probes', () => {
  it('reports ready while Hydra, the database and Redis are', async () => {
    const res = await fetch(`${APP}/ready`);
    expect(res.status).toBe(200);
  });
});
