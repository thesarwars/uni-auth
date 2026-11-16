import type { NestFastifyApplication } from '@nestjs/platform-fastify';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { Outbox } from '../../src/delivery/outbox';
import { codeAt, fromBase32, stepAt } from '../../src/two-step/totp';
import { startApp } from '../support/app';
import {
  APP,
  authorizeUrl,
  browser,
  claims,
  exchange,
  formFields,
  pkce,
  type Browser,
  type Hop,
} from '../support/browser';
import { closeMembers, createMember, sql, type Member } from '../support/members';

/**
 * 2-step verification (account-plan.md part 4): turning it on in the account centre, and the
 * second step every way in must then pass - with a code from the app, once, or a recovery
 * code, once.
 */

let app: NestFastifyApplication;
let outbox: Outbox;

beforeAll(async () => {
  app = await startApp();
  outbox = app.get(Outbox);
});
afterAll(async () => {
  await app?.close();
  await closeMembers();
});

const csrf = (page: Hop): string => /name="_csrf" value="([^"]+)"/.exec(page.html)![1]!;
const open = async (b: Browser, path: string): Promise<Hop> =>
  (await b.follow(`${APP}${path}`)).hop;

/** Signs in to the account centre with the password, with no second step (2FA still off). */
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

/** Turns 2-step verification on; returns the seed and the recovery codes shown. */
async function turnOn(m: Member): Promise<{ b: Browser; seed: Buffer; codes: string[] }> {
  const b = await accountSignIn(m);
  const setup = await open(b, '/account/two-step/setup');
  expect(setup.status).toBe(200);
  expect(setup.html).toContain('<svg');
  const key = /aria-label="Setup key">([A-Z2-7 ]+)</.exec(setup.html)![1]!;
  const seed = fromBase32(key);
  const res = await b.post(`${APP}/account/two-step/setup`, {
    _csrf: csrf(setup),
    code: codeAt(seed, stepAt(Date.now())),
  });
  expect(res.status).toBe(200);
  expect(res.html).toContain('Save your recovery codes');
  const codes = [...res.html.matchAll(/<li>([0-9A-Z]{5}-[0-9A-Z]{5})<\/li>/g)].map((x) => x[1]!);
  expect(codes).toHaveLength(10);
  return { b, seed, codes };
}

interface Flow {
  b: Browser;
  verifier: string;
  page: Hop;
}

/** A sign-in to GSN web with the password: where it lands after the first step. */
async function passwordFirst(m: Member, b: Browser = browser()): Promise<Flow> {
  const { verifier, challenge } = pkce();
  let page = (await b.follow(authorizeUrl(challenge))).hop;
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
  return { b, verifier, page };
}

/** On the second-step screen: the first step's redirect, followed. */
async function atSecondStep(f: Flow): Promise<Hop> {
  expect(f.page.status).toBe(303);
  expect(f.page.location).toMatch(new RegExp(`^${APP}/login/two-step\\?login_challenge=`));
  f.page = (await f.b.follow(f.page.location!)).hop;
  expect(f.page.status).toBe(200);
  expect(f.page.html).toContain('<h1 id="title">2-step verification</h1>');
  return f.page;
}

async function second(f: Flow, mode: 'app' | 'recovery', code: string): Promise<Hop> {
  const challenge = /name="login_challenge" value="([^"]+)"/.exec(f.page.html)![1]!;
  f.page = await f.b.post(`${APP}/login/two-step`, {
    _csrf: csrf(f.page),
    login_challenge: challenge,
    mode,
    code,
  });
  return f.page;
}

/** Back at the client with a code; the access token's claims. */
async function landed(f: Flow): Promise<Record<string, any>> {
  expect(f.page.status).toBe(303);
  const { url } = await f.b.follow(f.page.location!);
  const t = await exchange(new URL(url).searchParams.get('code')!, f.verifier);
  expect(t.status).toBe(200);
  return claims(t.body.access_token);
}

const nextCode = (seed: Buffer) => codeAt(seed, stepAt(Date.now()) + 1);

describe('turning it on', () => {
  it('shows on Security & sign-in, and needs a code from the app to turn on', async () => {
    const m = await createMember();
    const b = await accountSignIn(m);
    let page = await open(b, '/account/security');
    expect(page.html).toMatch(/2-step verification<span class="tag">Off</);

    page = await open(b, '/account/two-step/setup');
    const res = await b.post(`${APP}/account/two-step/setup`, {
      _csrf: csrf(page),
      code: '000000',
    });
    expect(res.status).toBe(422);
    expect(res.html).toMatch(/That code isn(&#39;|')t right\./);
    expect(
      await sql("SELECT 1 FROM credential WHERE identity_id = $1 AND kind = 'totp'", [
        m.identityId,
      ]),
    ).toEqual([]);
  });

  it('turns on with a code, shows ten recovery codes once, and emails the member', async () => {
    const m = await createMember();
    const { b } = await turnOn(m);
    const rows = await sql<{ kind: string; n: number }>(
      `SELECT c.kind::text AS kind, (SELECT count(*)::int FROM recovery_code r WHERE r.credential_id = c.id) AS n
         FROM credential c WHERE c.identity_id = $1 AND c.kind IN ('totp', 'recovery_codes') AND c.revoked_at IS NULL
        ORDER BY c.kind`,
      [m.identityId],
    );
    expect(rows).toEqual([
      { kind: 'totp', n: 0 },
      { kind: 'recovery_codes', n: 10 },
    ]);
    expect(outbox.noticesTo(m.email).map((n) => n.subject)).toContain(
      '2-step verification was turned on',
    );
    const page = await open(b, '/account/two-step');
    expect(page.html).toContain('10 of 10 left');
    const security = await open(b, '/account/security');
    expect(security.html).toMatch(/2-step verification<span class="tag inverse">On</);
  });
});

describe('signing in with it on', () => {
  it('asks for the code after the password, and the code makes it aal2', async () => {
    const m = await createMember();
    const { seed } = await turnOn(m);
    const f = await passwordFirst(m);
    await atSecondStep(f);
    const bad = await second(f, 'app', '000000');
    expect(bad.status).toBe(422);
    expect(bad.html).toMatch(/That code isn(&#39;|')t right\./);

    await second(f, 'app', nextCode(seed));
    const at = await landed(f);
    expect(at.sub).toBe(m.identityId);
    expect(at.amr).toEqual(expect.arrayContaining(['pwd', 'otp', 'mfa']));
    const [s] = await sql<{ aal: number }>('SELECT aal FROM auth_session WHERE sid = $1', [at.sid]);
    expect(s!.aal).toBe(2);
  });

  it('takes each code once', async () => {
    const m = await createMember();
    const { seed } = await turnOn(m);
    const code = nextCode(seed);
    const one = await passwordFirst(m);
    await atSecondStep(one);
    await second(one, 'app', code);
    await landed(one);

    const two = await passwordFirst(m);
    await atSecondStep(two);
    const again = await second(two, 'app', code);
    expect(again.status).toBe(422);
  });

  it('asks after a code to the email too, and after a password reset', async () => {
    const m = await createMember();
    await turnOn(m);

    const b = browser();
    const { challenge } = pkce();
    let page = (await b.follow(authorizeUrl(challenge))).hop;
    page = await b.post(`${APP}/login`, {
      ...formFields(page.html),
      action: 'identify',
      identifier: m.email,
    });
    page = await b.post(`${APP}/login`, {
      ...formFields(page.html),
      action: 'send_code',
      purpose: 'sign_in',
    });
    const otpId = /name="otp_id" value="([^"]+)"/.exec(page.html)![1]!;
    page = await b.post(`${APP}/login`, {
      ...formFields(page.html),
      action: 'verify_code',
      otp_id: otpId,
      code: outbox.last(m.email)!.code,
    });
    expect(page.status).toBe(303);
    expect(page.location).toContain('/login/two-step?');

    // A reset: the new password is set, and the next stop is still the second step.
    const r = browser();
    let p = (await r.follow(authorizeUrl(pkce().challenge))).hop;
    p = await r.post(`${APP}/login`, {
      ...formFields(p.html),
      action: 'identify',
      identifier: m.email,
    });
    p = await r.post(`${APP}/login`, {
      ...formFields(p.html),
      action: 'send_code',
      purpose: 'recovery',
    });
    const resetId = /name="otp_id" value="([^"]+)"/.exec(p.html)![1]!;
    p = await r.post(`${APP}/login`, {
      ...formFields(p.html),
      action: 'verify_code',
      otp_id: resetId,
      code: outbox.last(m.email)!.code,
    });
    p = await r.post(`${APP}/login`, {
      ...formFields(p.html),
      action: 'new_password',
      password: 'Brand-New-Pass-7',
      confirm: 'Brand-New-Pass-7',
    });
    expect(p.status).toBe(200);
    expect(p.html).toContain('Password updated');
    expect(p.html).toMatch(/href="\/login\/two-step\?login_challenge=/);
  });

  it('signs in with a recovery code, once, and says so by email', async () => {
    const m = await createMember();
    const { codes } = await turnOn(m);
    const f = await passwordFirst(m);
    await atSecondStep(f);
    f.page = (
      await f.b.follow(
        `${APP}/login/two-step?login_challenge=${encodeURIComponent(/name="login_challenge" value="([^"]+)"/.exec(f.page.html)![1]!)}&mode=recovery`,
      )
    ).hop;
    expect(f.page.html).toContain('Enter one of the recovery codes');
    await second(f, 'recovery', codes[0]!.toLowerCase());
    const at = await landed(f);
    expect(at.amr).toEqual(expect.arrayContaining(['mfa']));
    expect(outbox.noticesTo(m.email).map((n) => n.subject)).toContain(
      'A recovery code was used to sign in',
    );
    const [e] = await sql<{ detail: { left: number } }>(
      "SELECT detail FROM auth_event WHERE identity_id = $1 AND kind = 'recovery_code_used'",
      [m.identityId],
    );
    expect(e!.detail.left).toBe(9);

    const g = await passwordFirst(m);
    await atSecondStep(g);
    const again = await second(g, 'recovery', codes[0]!);
    expect(again.status).toBe(422);
    expect(again.html).toContain('used already');
  });

  it('pauses after five wrong codes', async () => {
    const m = await createMember();
    const { seed } = await turnOn(m);
    const f = await passwordFirst(m);
    await atSecondStep(f);
    let last: Hop | null = null;
    for (let i = 0; i < 5; i++) last = await second(f, 'app', '000000');
    expect(last!.status).toBe(429);
    expect(last!.html).toContain('Too many wrong codes');
    // The right code doesn't get through while paused.
    const still = await second(f, 'app', nextCode(seed));
    expect(still.status).toBe(429);
  });

  it('belongs to the browser that passed the first step', async () => {
    const m = await createMember();
    await turnOn(m);
    const f = await passwordFirst(m);
    const to = f.page.location!;
    const other = browser();
    const res = await other.get(to);
    expect(res.status).toBe(303);
    expect(res.location).toMatch(new RegExp(`^${APP}/login\\?login_challenge=`));
  });
});

describe('managing it', () => {
  it('makes new recovery codes, and the old ones stop working', async () => {
    const m = await createMember();
    const { b, codes } = await turnOn(m);
    const page = await open(b, '/account/two-step');
    const res = await b.post(`${APP}/account/two-step/codes`, { _csrf: csrf(page) });
    expect(res.status).toBe(200);
    const fresh = [...res.html.matchAll(/<li>([0-9A-Z]{5}-[0-9A-Z]{5})<\/li>/g)].map((x) => x[1]!);
    expect(fresh).toHaveLength(10);
    expect(fresh).not.toContain(codes[0]);

    const f = await passwordFirst(m);
    await atSecondStep(f);
    expect((await second(f, 'recovery', codes[0]!)).status).toBe(422);
    await second(f, 'recovery', fresh[0]!);
    await landed(f);
  });

  it('turns off, and sign-in goes back to one step', async () => {
    const m = await createMember();
    const { b } = await turnOn(m);
    const page = await open(b, '/account/two-step');
    const res = await b.post(`${APP}/account/two-step/off`, { _csrf: csrf(page) });
    expect(res.location).toBe(`${APP}/account/two-step?done=two_step_off`);
    expect(outbox.noticesTo(m.email).map((n) => n.subject)).toContain(
      '2-step verification was turned off',
    );
    const live = await sql(
      "SELECT kind FROM credential WHERE identity_id = $1 AND kind IN ('totp', 'recovery_codes') AND revoked_at IS NULL",
      [m.identityId],
    );
    expect(live).toEqual([]);

    const f = await passwordFirst(m);
    const at = await landed(f);
    expect(at.amr).toEqual(['pwd']);
  });

  it('needs the form token', async () => {
    const m = await createMember();
    const { b } = await turnOn(m);
    const res = await b.post(`${APP}/account/two-step/off`, {});
    expect(res.status).toBe(403);
  });
});
