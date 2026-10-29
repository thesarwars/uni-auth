import type { NestFastifyApplication } from '@nestjs/platform-fastify';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { startApp } from '../support/app';
import {
  APP,
  REDIRECT,
  authorizeUrl,
  browser,
  claims,
  exchange,
  formFields,
  pkce,
  type Browser,
} from '../support/browser';
import { closeMembers, createMember, sql, type Member } from '../support/members';

/**
 * Part 4's password sign-in (auth-plan.md sections 7.2 and 7.3): the identifier screen, the
 * password screen and every state they must handle, the throttle, and the session the identity
 * database records for each sign-in.
 */

let app: NestFastifyApplication;

beforeAll(async () => {
  app = await startApp();
});
afterAll(async () => {
  await app?.close();
  await closeMembers();
});

async function loginPage(b: Browser, challenge = pkce().challenge): Promise<string> {
  const { url, hop } = await b.follow(authorizeUrl(challenge));
  expect(url.startsWith(`${APP}/login?`)).toBe(true);
  return hop.html;
}

const identify = (b: Browser, html: string, identifier: string) =>
  b.post(`${APP}/login`, { ...formFields(html), action: 'identify', identifier });

const enterPassword = (b: Browser, html: string, password: string) =>
  b.post(`${APP}/login`, { ...formFields(html), action: 'password', password });

async function signedIn(b: Browser, m: Member) {
  const { verifier, challenge } = pkce();
  const pw = await identify(b, await loginPage(b, challenge), m.email);
  const posted = await enterPassword(b, pw.html, m.password);
  expect(posted.status).toBe(303);
  const { url } = await b.follow(posted.location!);
  const t = await exchange(new URL(url).searchParams.get('code')!, verifier);
  expect(t.status).toBe(200);
  return claims(t.body.access_token);
}

describe('the identifier screen', () => {
  it('refuses what is neither an email nor an international phone number', async () => {
    const b = browser();
    const res = await identify(b, await loginPage(b), '07700 900123');
    expect(res.status).toBe(422);
    expect(res.html).toContain('with its country code');
    expect(res.html).toContain('value="07700 900123"');
  });

  it('offers to create an account when no account has the address', async () => {
    const b = browser();
    const res = await identify(b, await loginPage(b), 'nobody-here@example.com');
    expect(res.status).toBe(200);
    expect(res.html).toContain('Create your account');
    expect(res.html).toContain('No account uses <strong>nobody-here@example.com</strong> yet.');
  });

  it('matches an address however it was typed', async () => {
    const m = await createMember();
    const b = browser();
    const res = await identify(b, await loginPage(b), `  ${m.email.toUpperCase()} `);
    expect(res.status).toBe(200);
    expect(res.html).toContain('Enter your password');
    expect(res.html).toContain(`value="${m.email}" readonly`);
  });

  it('turns a suspended account away before any password is asked for', async () => {
    const m = await createMember();
    await sql("UPDATE identity SET status = 'suspended' WHERE id = $1", [m.identityId]);
    const b = browser();
    const res = await identify(b, await loginPage(b), m.email);
    expect(res.html).toContain('This account is suspended');
    expect(res.html).not.toContain('Enter your password');
  });

  it('points an account with no password at the way it signs in', async () => {
    const m = await createMember({ password: null });
    await sql(
      "INSERT INTO credential (identity_id, kind, provider_subject) VALUES ($1, 'oauth_google', $2)",
      [m.identityId, `g-${m.identityId}`],
    );
    const b = browser();
    const res = await identify(b, await loginPage(b), m.email);
    expect(res.html).toContain('This account signs in with Google.');
  });
});

describe('the password screen', () => {
  it('signs in, records the session under the token sid, and journals it', async () => {
    const m = await createMember();
    const at = await signedIn(browser(), m);
    expect(at.sub).toBe(m.identityId);
    expect(at.amr).toEqual(['pwd']);

    const [s] = await sql(
      'SELECT id, client_id, credential_id, revoked_at, expires_at FROM auth_session WHERE sid = $1',
      [at.sid],
    );
    expect(s).toBeDefined();
    expect(s!.client_id).toBe('gsn-web');
    expect(s!.revoked_at).toBeNull();
    const days = (s!.expires_at.getTime() - Date.now()) / 86_400_000;
    expect(days).toBeGreaterThan(89);

    const events = await sql(
      "SELECT kind, outcome, credential_kind, auth_session_id FROM auth_event WHERE identity_id = $1 AND kind = 'sign_in'",
      [m.identityId],
    );
    expect(events).toEqual([
      { kind: 'sign_in', outcome: 'success', credential_kind: 'password', auth_session_id: s!.id },
    ]);
    const [cred] = await sql('SELECT last_used_at FROM credential WHERE id = $1', [
      s!.credential_id,
    ]);
    expect(cred!.last_used_at).toBeInstanceOf(Date);
  });

  it('counts wrong passwords, warns at two left, and pauses sign-in at five', async () => {
    const m = await createMember();
    const b = browser();
    const pw = await identify(b, await loginPage(b), m.email);

    const seen: string[] = [];
    let last = pw;
    for (let i = 0; i < 4; i++) {
      last = await enterPassword(b, pw.html, 'wrong-password');
      expect(last.status).toBe(422);
      seen.push(last.html);
    }
    expect(seen[0]).toContain('That password is not right.');
    expect(seen[0]).not.toContain('left before');
    expect(seen[2]).toContain('2 attempts left before sign-in is paused.');
    expect(seen[3]).toContain('1 attempt left before sign-in is paused.');

    const fifth = await enterPassword(b, pw.html, 'wrong-password');
    expect(fifth.status).toBe(429);
    expect(fifth.html).toContain('Too many attempts');
    expect(fifth.html).toMatch(/try again in 1[45] minutes/);

    // The right password is not even checked while the lockout holds.
    const right = await enterPassword(b, pw.html, m.password);
    expect(right.status).toBe(429);

    const journal = await sql(
      'SELECT kind, outcome FROM auth_event WHERE identity_id = $1 ORDER BY occurred_at, id',
      [m.identityId],
    );
    expect(journal.filter((e) => e.kind === 'sign_in' && e.outcome === 'failure')).toHaveLength(5);
    expect(journal.filter((e) => e.kind === 'lockout')).toHaveLength(1);
    expect(journal.some((e) => e.outcome === 'success')).toBe(false);
  });

  it('journals an attempt at an address nobody owns by its hash alone', async () => {
    const b = browser();
    const html = await loginPage(b);
    const ghost = `ghost-${Date.now()}@example.com`;
    const res = await b.post(`${APP}/login`, {
      ...formFields(html),
      action: 'password',
      identifier: ghost,
      password: 'anything-at-all',
    });
    expect(res.status).toBe(422);
    const rows = await sql(
      "SELECT identity_id FROM auth_event WHERE identifier_hash = sha256(convert_to($1, 'UTF8'))",
      [ghost],
    );
    expect(rows).toEqual([{ identity_id: null }]);
  });

  it('starts again when the member says it is not them', async () => {
    const m = await createMember();
    const b = browser();
    const pw = await identify(b, await loginPage(b), m.email);
    const href = /href="(\/login\?login_challenge=[^"]+)"/.exec(pw.html)![1]!;
    const back = await b.get(`${APP}${href.replace(/&amp;/g, '&')}`);
    expect(back.status).toBe(200);
    expect(back.html).toContain('Sign in to continue to');
    expect(back.html).toContain('value=""');
  });
});

describe('single sign-on answers to the identity database', () => {
  async function ssoLands(b: Browser): Promise<string> {
    const { url } = await b.follow(authorizeUrl(pkce().challenge));
    return url;
  }

  it('skips the screen while the session stands', async () => {
    const m = await createMember();
    const b = browser();
    await signedIn(b, m);
    expect((await ssoLands(b)).startsWith(REDIRECT)).toBe(true);
  });

  it('shows the sign-in screen again once the session is revoked', async () => {
    const m = await createMember();
    const b = browser();
    const at = await signedIn(b, m);
    await sql(
      "UPDATE auth_session SET revoked_at = now(), revoke_reason = 'operator' WHERE sid = $1",
      [at.sid],
    );
    expect((await ssoLands(b)).startsWith(`${APP}/login?`)).toBe(true);
  });

  it('shows the sign-in screen again once the identity is suspended', async () => {
    const m = await createMember();
    const b = browser();
    await signedIn(b, m);
    await sql("UPDATE identity SET status = 'suspended' WHERE id = $1", [m.identityId]);
    expect((await ssoLands(b)).startsWith(`${APP}/login?`)).toBe(true);
  });
});
