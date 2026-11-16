import type { NestFastifyApplication } from '@nestjs/platform-fastify';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { Outbox } from '../../src/delivery/outbox';
import { IdentityRepository } from '../../src/identity/identity.repository';
import { startApp } from '../support/app';
import { APP, HYDRA, browser, formFields, type Browser, type Hop } from '../support/browser';
import { closeMembers, createMember, sql, type Member } from '../support/members';

/**
 * Devices and Security activity (account-plan.md part 1): the member's live sessions, signing
 * one or all others out, and the journal in plain words.
 */

let app: NestFastifyApplication;

beforeAll(async () => {
  app = await startApp();
});

afterAll(async () => {
  await app?.close();
  await closeMembers();
});

const csrf = (page: Hop): string => /name="_csrf" value="([^"]+)"/.exec(page.html)![1]!;

async function signIn(
  m: Member,
  path = '/account',
  userAgent?: string,
): Promise<{ b: Browser; page: Hop }> {
  const b = browser(userAgent);
  let { hop: page } = await b.follow(`${APP}${path}`);
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

const open = async (b: Browser, path: string): Promise<Hop> =>
  (await b.follow(`${APP}${path}`)).hop;

const sessionIds = (page: Hop): string[] =>
  [...page.html.matchAll(/name="id" value="([0-9a-f-]{36})"/g)].map((m) => m[1]!);

const live = (identityId: string) =>
  sql<{ id: string; sid: string }>(
    'SELECT id, sid FROM auth_session WHERE identity_id = $1 AND revoked_at IS NULL',
    [identityId],
  );

/** Signed out: the account centre sends the browser to sign in again. */
async function signedOut(b: Browser): Promise<boolean> {
  const res = await b.get(`${APP}/account`);
  return res.status === 303 && new RegExp(`^${HYDRA}/`).test(res.location ?? '');
}

describe('your devices', () => {
  it('lists every signed-in device, marking this one, with no sign-out for it', async () => {
    const m = await createMember();
    await signIn(m);
    const { b } = await signIn(m);
    const page = await open(b, '/account/devices');
    expect(page.html).toContain('<h1 id="title">Your devices</h1>');
    // No subtitle; and no GeoIP database in the tests, so no MaxMind small print either.
    expect(page.html).not.toContain('Signing out a device signs it out');
    expect(page.html).not.toContain('GeoLite2');
    expect(page.html.match(/class="tag inverse">This device</g)).toHaveLength(1);
    // Two devices, one button: the other one.
    expect(sessionIds(page)).toHaveLength(1);
    expect(page.html).toContain('Sign out of all other devices');
  });

  it('signs one device out, everywhere, and journals it', async () => {
    const m = await createMember();
    const other = await signIn(m);
    const { b } = await signIn(m);
    let page = await open(b, '/account/devices');
    const [id] = sessionIds(page);
    const res = await b.post(`${APP}/account/devices/sign-out`, { _csrf: csrf(page), id: id! });
    expect(res.location).toBe(`${APP}/account/devices?done=device_signed_out`);
    page = (await b.follow(res.location!)).hop;
    expect(page.html).toContain('That device has been signed out.');
    expect(sessionIds(page)).toHaveLength(0);

    expect(await signedOut(other.b)).toBe(true);
    expect(await signedOut(b)).toBe(false);
    const [row] = await sql<{ revoke_reason: string }>(
      'SELECT revoke_reason FROM auth_session WHERE id = $1',
      [id],
    );
    expect(row!.revoke_reason).toBe('sign_out');
    const journal = await sql(
      "SELECT auth_session_id FROM auth_event WHERE identity_id = $1 AND kind = 'session_revoked'",
      [m.identityId],
    );
    expect(journal).toEqual([{ auth_session_id: id }]);
  });

  it("cannot sign out another member's device, or its own", async () => {
    const victim = await createMember();
    await signIn(victim);
    const [theirs] = await live(victim.identityId);

    const m = await createMember();
    const { b } = await signIn(m);
    const page = await open(b, '/account/devices');
    const [mine] = await live(m.identityId);
    for (const id of [theirs!.id, mine!.id]) {
      const res = await b.post(`${APP}/account/devices/sign-out`, { _csrf: csrf(page), id });
      expect(res.location).toBe(`${APP}/account/devices`);
    }
    expect(await live(victim.identityId)).toHaveLength(1);
    expect(await signedOut(b)).toBe(false);
  });

  it('signs out every other device and keeps this one', async () => {
    const m = await createMember();
    const one = await signIn(m);
    const two = await signIn(m);
    const { b } = await signIn(m);
    const page = await open(b, '/account/devices');
    const res = await b.post(`${APP}/account/devices/sign-out-others`, { _csrf: csrf(page) });
    expect(res.location).toBe(`${APP}/account/devices?done=others_signed_out`);

    expect(await signedOut(one.b)).toBe(true);
    expect(await signedOut(two.b)).toBe(true);
    expect(await signedOut(b)).toBe(false);
    expect(await live(m.identityId)).toHaveLength(1);
    const [e] = await sql<{ detail: { others: number } }>(
      "SELECT detail FROM auth_event WHERE identity_id = $1 AND kind = 'session_revoked'",
      [m.identityId],
    );
    expect(e!.detail).toEqual({ others: 2 });
  });

  it('needs the form token', async () => {
    const m = await createMember();
    await signIn(m);
    const { b } = await signIn(m);
    const res = await b.post(`${APP}/account/devices/sign-out-others`, {});
    expect(res.status).toBe(403);
    expect(await live(m.identityId)).toHaveLength(2);
  });
});

describe('security activity', () => {
  it('shows sign-ins, failed attempts and changes, in plain words', async () => {
    const m = await createMember();
    // A wrong password first: a failed attempt on this account.
    const w = browser();
    let { hop } = await w.follow(`${APP}/account`);
    hop = await w.post(`${APP}/login`, {
      ...formFields(hop.html),
      action: 'identify',
      identifier: m.email,
    });
    await w.post(`${APP}/login`, {
      ...formFields(hop.html),
      action: 'password',
      password: 'Not-The-Password-1',
    });

    await signIn(m);
    const { b } = await signIn(m);
    const devices = await open(b, '/account/devices');
    await b.post(`${APP}/account/devices/sign-out-others`, { _csrf: csrf(devices) });

    const page = await open(b, '/account/activity');
    expect(page.html).toContain('<h1 id="title">Security activity</h1>');
    expect(page.html).toContain('Last 90 days');
    expect(page.html).toContain('Failed sign-in attempt');
    expect(page.html).toContain('Signed out of 1 other device');
    expect(page.html.match(/>Signed in(?: on [^<]+)?</g)!.length).toBeGreaterThanOrEqual(2);
    expect(page.html).toContain('href="/account/password">Wasn’t me</a>');
  });

  it('shows the latest on Security & sign-in, with links to both pages', async () => {
    const m = await createMember();
    const { b } = await signIn(m);
    const page = await open(b, '/account/security');
    expect(page.html).toContain('Your devices');
    expect(page.html).toContain('class="tag inverse">This device<');
    expect(page.html).toContain('href="/account/devices"');
    expect(page.html).toContain('Recent security activity');
    expect(page.html).toContain('href="/account/activity"');
  });
});

describe('device and place at sign-in', () => {
  it('records nothing it cannot tell: no device in the user agent, no GeoIP database', async () => {
    const m = await createMember();
    await signIn(m);
    const rows = await sql(
      'SELECT device_label, geo_city, geo_country FROM auth_session WHERE identity_id = $1',
      [m.identityId],
    );
    expect(rows).toEqual([{ device_label: null, geo_city: null, geo_country: null }]);
  });
});

describe('new-device email', () => {
  const MAC =
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36';
  const IPHONE =
    'Mozilla/5.0 (iPhone; CPU iPhone OS 18_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.1 Mobile/15E148 Safari/604.1';
  const alerts = (m: Member) =>
    app
      .get(Outbox)
      .noticesTo(m.email)
      .filter((n) => n.subject === 'New sign-in to your account');

  it('is sent for a device not seen lately, and not for the first or a familiar one', async () => {
    const m = await createMember();
    await signIn(m, '/account', MAC);
    expect(alerts(m)).toHaveLength(0);
    await signIn(m, '/account', MAC);
    expect(alerts(m)).toHaveLength(0);

    await signIn(m, '/account', IPHONE);
    const [n, ...more] = alerts(m);
    expect(more).toHaveLength(0);
    expect(n!.text).toContain('Device: Safari on iPhone');
    expect(n!.text).toMatch(/When: \d{1,2} \w+ \d{4} at \d{2}:\d{2} UK time/);
    // No GeoIP database in the tests: no location line rather than a blank one.
    expect(n!.text).not.toContain('Location:');

    await signIn(m, '/account', IPHONE);
    expect(alerts(m)).toHaveLength(1);
  });
});

describe('last seen', () => {
  it('moves forward when a refresh is let through', async () => {
    const m = await createMember();
    await signIn(m);
    const [s] = await live(m.identityId);
    const [before] = await sql<{ last_seen_at: Date }>(
      'SELECT last_seen_at FROM auth_session WHERE id = $1',
      [s!.id],
    );
    await new Promise((r) => setTimeout(r, 20));
    await app.get(IdentityRepository).touchSession(s!.sid);
    const [after] = await sql<{ last_seen_at: Date }>(
      'SELECT last_seen_at FROM auth_session WHERE id = $1',
      [s!.id],
    );
    expect(after!.last_seen_at.getTime()).toBeGreaterThan(before!.last_seen_at.getTime());
  });
});
