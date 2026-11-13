import type { NestFastifyApplication } from '@nestjs/platform-fastify';
import { afterAll, beforeAll, describe, expect, it, vi } from 'vitest';
import { FRESH_SECONDS } from '../../src/account/account.controller';
import { Outbox } from '../../src/delivery/outbox';
import { startApp } from '../support/app';
import {
  APP,
  HYDRA,
  authorizeUrl,
  browser,
  exchange,
  formFields,
  pkce,
  type Browser,
  type Hop,
} from '../support/browser';
import { closeMembers, createMember, sql, type Member } from '../support/members';

/**
 * The account centre (account-plan.md parts 1-3): signing in to it through Hydra like any
 * client, personal info, email and phone, password, and "Confirm it's you" before a change.
 */

let app: NestFastifyApplication;
let outbox: Outbox;

beforeAll(async () => {
  app = await startApp();
  outbox = app.get(Outbox);
});

afterAll(async () => {
  vi.useRealTimers();
  await app?.close();
  await closeMembers();
});

const csrf = (page: Hop): string => /name="_csrf" value="([^"]+)"/.exec(page.html)![1]!;

/** Opens an account page, signing in through the real login screens when asked to. */
async function signIn(m: Member, path = '/account'): Promise<{ b: Browser; page: Hop }> {
  const b = browser();
  let { hop: page } = await b.follow(`${APP}${path}`);
  expect(page.html).toContain('id="identifier"');
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
  expect(page.status).toBe(303);
  ({ hop: page } = await b.follow(page.location!));
  expect(page.status).toBe(200);
  return { b, page };
}

async function open(b: Browser, path: string): Promise<Hop> {
  return (await b.follow(`${APP}${path}`)).hop;
}

async function postTo(
  b: Browser,
  path: string,
  page: Hop,
  fields: Record<string, string>,
): Promise<Hop> {
  const res = await b.post(`${APP}${path}`, { _csrf: csrf(page), ...fields });
  return res.location?.startsWith(APP) && res.status === 303
    ? (await b.follow(res.location)).hop
    : res;
}

const events = (identityId: string, kind: string) =>
  sql('SELECT detail FROM auth_event WHERE identity_id = $1 AND kind = $2', [identityId, kind]);

describe('signing in to the account centre', () => {
  it('signs in through the login screens and shows the account', async () => {
    const m = await createMember();
    const { page } = await signIn(m);
    expect(page.html).toContain('<h1 id="title">Your account</h1>');
    expect(page.html).toContain(m.email);
    expect(page.html).toContain('aria-current="page"');
  });

  it('starts at the bare domain, and at /login with no sign-in in progress', async () => {
    for (const path of ['/', '/login']) {
      const m = await createMember();
      const { page } = await signIn(m, path);
      expect(page.html).toContain('<h1 id="title">Your account</h1>');
      expect(page.html).toContain(m.email);
    }
  });

  it('ends when the provider session is revoked elsewhere', async () => {
    const m = await createMember();
    const { b } = await signIn(m);
    await sql(
      "UPDATE auth_session SET revoked_at = now(), revoke_reason = 'operator' WHERE identity_id = $1",
      [m.identityId],
    );
    const res = await b.get(`${APP}/account`);
    expect(res.status).toBe(303);
    expect(res.location).toMatch(new RegExp(`^${HYDRA}/oauth2/auth\\?`));
  });

  it('signs out through Hydra, and the account needs a sign-in again', async () => {
    const m = await createMember();
    const { b, page } = await signIn(m);
    const out = await b.post(`${APP}/account/sign-out`, { _csrf: csrf(page) });
    expect(out.location).toMatch(new RegExp(`^${HYDRA}/oauth2/sessions/logout\\?`));
    const confirm = (await b.follow(out.location!)).hop;
    expect(confirm.html).toContain('Sign out of entity-auth?');
    const done = await b.post(`${APP}/logout`, { ...formFields(confirm.html), action: 'sign_out' });
    const landed = (await b.follow(done.location!)).hop;
    expect(landed.html).toContain('You have signed out');
    expect((await b.get(`${APP}/account`)).location).toMatch(new RegExp(`^${HYDRA}/`));
  });

  it('refuses a callback whose state this browser did not start', async () => {
    const res = await browser().get(`${APP}/account/callback?code=x&state=forged`);
    expect(res.status).toBe(200);
    expect(res.html).toContain('You are not signed in');
  });
});

describe('personal info', () => {
  it('saves the name and language, and journals it', async () => {
    const m = await createMember();
    const { b } = await signIn(m);
    let page = await open(b, '/account/personal/edit');
    page = await postTo(b, '/account/personal', page, {
      display_name: '  Amelia   Hart ',
      locale: 'fr-FR',
    });
    expect(page.html).toContain('Your details are saved.');
    expect(page.html).toContain('<span class="val">Amelia Hart</span>');
    expect(page.html).toContain('<span class="val">Français</span>');
    const [row] = await sql('SELECT display_name, locale FROM identity WHERE id = $1', [
      m.identityId,
    ]);
    expect(row).toEqual({ display_name: 'Amelia Hart', locale: 'fr-FR' });
    expect(await events(m.identityId, 'profile_updated')).toHaveLength(1);
  });

  it('refuses a language that is not offered', async () => {
    const m = await createMember();
    const { b } = await signIn(m);
    const page = await open(b, '/account/personal');
    const res = await b.post(`${APP}/account/personal`, {
      _csrf: csrf(page),
      display_name: 'A',
      locale: 'xx',
    });
    expect(res.status).toBe(422);
  });

  it('refuses a post without the form token', async () => {
    const m = await createMember();
    const { b } = await signIn(m);
    const res = await b.post(`${APP}/account/personal`, { display_name: 'A', locale: 'en-GB' });
    expect(res.status).toBe(403);
  });
});

describe('email and phone', () => {
  it('adds an email by code, makes it primary, and removes the old one', async () => {
    const m = await createMember();
    const extra = `extra-${Date.now()}@example.com`;
    const { b } = await signIn(m, '/account/contact');
    let page = await open(b, '/account/contact');
    expect(page.html).toContain('Email addresses');

    page = await postTo(b, '/account/contact/add', page, { kind: 'email', value: extra });
    expect(page.html).toContain('Check your email');
    const otpId = /name="otp_id" value="([^"]+)"/.exec(page.html)![1]!;

    const wrong = await b.post(`${APP}/account/contact/verify`, {
      _csrf: csrf(page),
      otp_id: otpId,
      code: '000000',
      destination: extra,
      kind: 'email',
    });
    expect(wrong.status).toBe(422);
    expect(wrong.html).toContain('isn&#39;t right');

    page = await postTo(b, '/account/contact/verify', wrong, {
      otp_id: otpId,
      code: outbox.last(extra)!.code,
      destination: extra,
      kind: 'email',
    });
    expect(page.html).toContain('Email address added.');
    expect(outbox.noticesTo(m.email).map((n) => n.subject)).toContain(
      'An address was added to your account',
    );

    const ids = await sql<{ id: string; value: string; is_primary: boolean }>(
      'SELECT id, value, is_primary FROM identity_identifier WHERE identity_id = $1 AND revoked_at IS NULL ORDER BY created_at',
      [m.identityId],
    );
    expect(ids.map((r) => [r.value, r.is_primary])).toEqual([
      [m.email, true],
      [extra, false],
    ]);

    page = await postTo(b, '/account/contact/primary', page, { id: ids[1]!.id });
    expect(page.html).toContain('Primary address changed.');
    expect(outbox.noticesTo(m.email).map((n) => n.subject)).toContain(
      'Your primary email address changed',
    );

    page = await postTo(b, '/account/contact/remove', page, { id: ids[0]!.id });
    expect(page.html).toContain('Removed.');
    const live = await sql(
      'SELECT value, is_primary FROM identity_identifier WHERE identity_id = $1 AND revoked_at IS NULL',
      [m.identityId],
    );
    expect(live).toEqual([{ value: extra, is_primary: true }]);
    expect(await events(m.identityId, 'identifier_added')).toHaveLength(1);
    expect(await events(m.identityId, 'identifier_removed')).toHaveLength(1);
  });

  it('never removes the last verified address, and the schema agrees', async () => {
    const m = await createMember();
    const { b } = await signIn(m, '/account/contact');
    const page = await open(b, '/account/contact');
    expect(page.html).not.toContain('Remove<span class="sr">');
    const [only] = await sql<{ id: string }>(
      'SELECT id FROM identity_identifier WHERE identity_id = $1',
      [m.identityId],
    );
    const res = await b.post(`${APP}/account/contact/remove`, { _csrf: csrf(page), id: only!.id });
    expect(res.status).toBe(422);
    expect(res.html).toContain('Add another email address or phone number');
    await expect(
      sql('UPDATE identity_identifier SET revoked_at = now(), is_primary = false WHERE id = $1', [
        only!.id,
      ]),
    ).rejects.toThrow(/keeps at least one verified identifier/);
  });

  it('sends no code to an address another account holds', async () => {
    const m = await createMember();
    const other = await createMember();
    const { b } = await signIn(m, '/account/contact');
    const page = await open(b, '/account/contact');
    const res = await b.post(`${APP}/account/contact/add`, {
      _csrf: csrf(page),
      kind: 'email',
      value: other.email,
    });
    expect(res.status).toBe(409);
    expect(res.html).toContain('Another account already uses that address.');
    expect(outbox.last(other.email)).toBeUndefined();
  });

  it("asks to confirm it's you once the sign-in is more than ten minutes old", async () => {
    const m = await createMember();
    const { b } = await signIn(m);
    vi.useFakeTimers({ toFake: ['Date'], now: Date.now() + (FRESH_SECONDS + 60) * 1000 });
    const res = await b.get(`${APP}/account/contact`);
    vi.useRealTimers();
    expect(res.status).toBe(303);
    const to = new URL(res.location!);
    expect(to.searchParams.get('prompt')).toBe('login');
    expect(to.searchParams.get('id_token_hint')).toBeTruthy();

    // No identifier screen: straight to the password, for the same member.
    let page = (await b.follow(res.location!)).hop;
    expect(page.html).toContain('Confirm it&#39;s you');
    expect(page.html).toContain(`<span class="who">${m.email}</span>`);
    page = await b.post(`${APP}/login`, {
      ...formFields(page.html),
      action: 'password',
      password: m.password,
    });
    page = (await b.follow(page.location!)).hop;
    expect(page.html).toContain('<h1 id="title">Email and phone</h1>');
  });
});

describe('password', () => {
  it('changes it, keeps this device signed in, and signs every other one out', async () => {
    const m = await createMember();
    // Signed in to GSN on another device.
    const elsewhere = browser();
    const { verifier, challenge } = pkce();
    let other = (await elsewhere.follow(authorizeUrl(challenge))).hop;
    other = await elsewhere.post(`${APP}/login`, {
      ...formFields(other.html),
      action: 'identify',
      identifier: m.email,
    });
    other = await elsewhere.post(`${APP}/login`, {
      ...formFields(other.html),
      action: 'password',
      password: m.password,
    });
    const { url } = await elsewhere.follow(other.location!);
    const t = await exchange(new URL(url).searchParams.get('code')!, verifier);
    const otherSid = JSON.parse(
      Buffer.from(t.body.access_token.split('.')[1], 'base64url').toString(),
    ).sid;

    const { b } = await signIn(m, '/account/password');
    let page = await open(b, '/account/password');
    expect(page.html).toContain('Change password');

    const weak = await b.post(`${APP}/account/password`, {
      _csrf: csrf(page),
      password: 'short',
      confirm: 'short',
    });
    expect(weak.status).toBe(422);
    expect(weak.html).toContain('does not meet every rule');

    page = await postTo(b, '/account/password', page, {
      password: 'Brand-New-Pass-4',
      confirm: 'Brand-New-Pass-4',
    });
    expect(page.html).toContain('Password changed.');

    const [gone] = await sql('SELECT revoke_reason FROM auth_session WHERE sid = $1', [otherSid]);
    expect(gone!.revoke_reason).toBe('password_changed');
    expect((await b.get(`${APP}/account`)).status).toBe(200); // this device is still signed in
    expect(outbox.noticesTo(m.email).map((n) => n.subject)).toContain('Your password was changed');
    expect(await events(m.identityId, 'password_changed')).toHaveLength(1);

    // The old password no longer signs in; the new one does.
    const g = browser();
    let p = (await g.follow(authorizeUrl(pkce().challenge))).hop;
    p = await g.post(`${APP}/login`, {
      ...formFields(p.html),
      action: 'identify',
      identifier: m.email,
    });
    expect(
      (
        await g.post(`${APP}/login`, {
          ...formFields(p.html),
          action: 'password',
          password: m.password,
        })
      ).status,
    ).toBe(422);
    expect(
      (
        await g.post(`${APP}/login`, {
          ...formFields(p.html),
          action: 'password',
          password: 'Brand-New-Pass-4',
        })
      ).status,
    ).toBe(303);
  });

  it('sets a first password on an account that has none', async () => {
    const m = await createMember({ password: null });
    // A code-only member signs in by code.
    const b = browser();
    let page = (await b.follow(`${APP}/account/password`)).hop;
    page = await b.post(`${APP}/login`, {
      ...formFields(page.html),
      action: 'identify',
      identifier: m.email,
    });
    const otpId = /name="otp_id" value="([^"]+)"/.exec(page.html)![1]!;
    page = await b.post(`${APP}/login`, {
      ...formFields(page.html),
      action: 'verify_code',
      otp_id: otpId,
      code: outbox.last(m.email)!.code,
    });
    page = (await b.follow(page.location!)).hop;
    expect(page.html).toContain('Set a password');
    page = await postTo(b, '/account/password', page, {
      password: 'First-Pass-word-1',
      confirm: 'First-Pass-word-1',
    });
    expect(page.html).toContain('Password set.');
    const live = await sql(
      "SELECT 1 FROM credential WHERE identity_id = $1 AND kind = 'password' AND revoked_at IS NULL",
      [m.identityId],
    );
    expect(live).toHaveLength(1);
  });
});
