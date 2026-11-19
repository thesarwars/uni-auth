import type { NestFastifyApplication } from '@nestjs/platform-fastify';
import { afterAll, afterEach, beforeAll, describe, expect, it } from 'vitest';
import { BUDGETS, Limits, tryAgainIn, type BudgetName } from '../../src/limits/limits';
import { RedisService } from '../../src/redis/redis.service';
import { startApp } from '../support/app';
import {
  APP,
  authorizeUrl,
  browser,
  formFields,
  pkce,
  type Browser,
  type Hop,
} from '../support/browser';
import { closeMembers, createMember, sql, type Member } from '../support/members';

/**
 * Part 8's limits (src/limits/limits.ts): every account-centre change has a budget per member,
 * and codes and passkey sign-ins have one per address. Each test fills a budget in Redis and
 * checks the next request is refused, says why, and changes nothing.
 */

let app: NestFastifyApplication;
let limits: Limits;
let redis: RedisService['client'];

beforeAll(async () => {
  app = await startApp();
  limits = app.get(Limits);
  redis = app.get(RedisService).client;
  // The first tests talk to Redis straight away: wait for the connection, not the first request.
  while (redis.status !== 'ready') await new Promise((r) => setTimeout(r, 20));
});
afterAll(async () => {
  await app?.close();
  await closeMembers();
});

/** The server sees the suite as one of these, depending on how localhost resolves. */
const LOOPBACK = ['127.0.0.1', '::1', '::ffff:127.0.0.1'];
afterEach(async () => {
  for (const name of ['codes', 'passkey_sign_in'] as const) {
    await redis.del(...LOOPBACK.map((ip) => limits.key(name, ip)));
  }
});

const fill = async (name: BudgetName, subjects: string[]) => {
  for (const s of subjects) {
    await redis.set(limits.key(name, s), String(limits.limit(name)), 'EX', 3600);
  }
};

const csrf = (page: Hop): string => /name="_csrf" value="([^"]+)"/.exec(page.html)![1]!;
const open = async (b: Browser, path: string): Promise<Hop> =>
  (await b.follow(`${APP}${path}`)).hop;

async function accountSignIn(m: Member): Promise<Browser> {
  const b = browser();
  let { hop: page } = await b.follow(`${APP}/account`);
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
  await b.follow(page.location!);
  return b;
}

describe('Limits', () => {
  it('counts in a window, and says when there is room again', async () => {
    const who = `test-${Date.now()}`;
    for (let i = 0; i < BUDGETS.password.limit; i++) {
      expect((await limits.take('password', who)).ok).toBe(true);
    }
    const refused = await limits.take('password', who);
    expect(refused.ok).toBe(false);
    if (!refused.ok) expect(tryAgainIn(refused.retryAt)).toBe('in an hour');
    expect(await redis.ttl(limits.key('password', who))).toBeGreaterThan(3500);
    expect(tryAgainIn(new Date(Date.now() + 12 * 60_000 - 500))).toBe('in 12 minutes');
    expect(tryAgainIn(new Date(Date.now() + 10_000))).toBe('in a minute');
  });

  it('keeps no address in Redis', () => {
    expect(limits.key('codes', '203.0.113.9')).not.toContain('203.0.113.9');
    expect(limits.key('password', 'abc')).toMatch(/:abc$/);
  });
});

describe('Account centre', () => {
  it('refuses a password change once the hour’s are used, and changes nothing', async () => {
    const m = await createMember();
    const b = await accountSignIn(m);
    const page = await open(b, '/account/password');
    await fill('password', [m.identityId]);
    const res = await b.post(`${APP}/account/password`, {
      _csrf: csrf(page),
      password: 'An0ther-long-passphrase!',
      confirm: 'An0ther-long-passphrase!',
    });
    expect(res.status).toBe(429);
    expect(Number(res.headers.get('retry-after'))).toBeGreaterThan(0);
    expect(res.html).toContain('<h1 id="title">Try again later</h1>');
    expect(res.html).toContain('You’ve changed your password a lot in the last hour.');
    expect(res.html).toContain('href="/account/security"');
    const events = await sql(
      `SELECT 1 FROM auth_event WHERE identity_id = $1 AND kind = 'password_changed'`,
      [m.identityId],
    );
    expect(events).toHaveLength(0);
  });

  it('caps codes to new addresses, whichever addresses they are', async () => {
    const m = await createMember();
    const b = await accountSignIn(m);
    const page = await open(b, '/account/contact');
    await fill('contact_add', [m.identityId]);
    const res = await b.post(`${APP}/account/contact/add`, {
      _csrf: csrf(page),
      kind: 'email',
      value: `new-${Date.now()}@example.com`,
    });
    expect(res.status).toBe(429);
    expect(res.html).toContain('You’ve asked for a lot of codes to new addresses');
    const sent = await sql(`SELECT 1 FROM otp_challenge WHERE identity_id = $1`, [m.identityId]);
    expect(sent).toHaveLength(0);
  });

  it('caps signing out devices and apps', async () => {
    const m = await createMember();
    const b = await accountSignIn(m);
    const page = await open(b, '/account/devices');
    await fill('sign_out', [m.identityId]);
    const res = await b.post(`${APP}/account/devices/sign-out-others`, { _csrf: csrf(page) });
    expect(res.status).toBe(429);
    expect(res.html).toContain('You’ve signed out devices and apps a lot in the last hour.');
  });

  it('counts each member on their own', async () => {
    const [one, two] = [await createMember(), await createMember()];
    await fill('personal', [one.identityId]);
    const b = await accountSignIn(two);
    const page = await open(b, '/account/personal/edit');
    const res = await b.post(`${APP}/account/personal`, {
      _csrf: csrf(page),
      display_name: 'Two',
      locale: 'en-GB',
    });
    expect(res.status).toBe(303);
  });
});

describe('Before sign-in, per address', () => {
  it('stops sending codes from a network that has sent its hour’s', async () => {
    const m = await createMember({ password: null });
    const b = browser();
    const { challenge } = pkce();
    let { hop: page } = await b.follow(authorizeUrl(challenge));
    await fill('codes', LOOPBACK);
    page = await b.post(`${APP}/login`, {
      ...formFields(page.html),
      action: 'identify',
      identifier: m.email,
    });
    expect(page.status).toBe(429);
    expect(page.html).toContain("We've sent as many codes from your network as we can for now.");
    const sent = await sql(`SELECT 1 FROM otp_challenge WHERE identity_id = $1`, [m.identityId]);
    expect(sent).toHaveLength(0);
  });

  it('stops passkey sign-ins from a network that has tried too many', async () => {
    const b = browser();
    const { challenge } = pkce();
    const { hop: page } = await b.follow(authorizeUrl(challenge));
    const loginChallenge = /name="login_challenge" value="([^"]+)"/.exec(page.html)![1]!;
    await fill('passkey_sign_in', LOOPBACK);
    const options = await fetch(
      `${APP}/login/passkey/options?login_challenge=${encodeURIComponent(loginChallenge)}`,
    );
    expect(options.status).toBe(429);
    const res = await b.post(`${APP}/login/passkey`, {
      _csrf: csrf(page),
      login_challenge: loginChallenge,
      credential: '{}',
    });
    expect(res.status).toBe(303);
    expect(res.location).toContain('passkey=busy');
    const back = await b.follow(res.location!);
    expect(back.hop.html).toContain('Too many passkey sign-ins came from your network.');
  });
});
