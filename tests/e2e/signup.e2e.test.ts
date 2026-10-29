import type { NestFastifyApplication } from '@nestjs/platform-fastify';
import { createHash, randomBytes } from 'node:crypto';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { Outbox } from '../../src/delivery/outbox';
import { RedisService } from '../../src/redis/redis.service';
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
import { FakeOidc } from '../support/fake-oidc';
import { closeMembers, createMember, sql } from '../support/members';

/**
 * Part 5's sign-up, uni-auth's half (auth-plan.md section 12.1, AU-D3): uni-auth creates the
 * identity and its credential, and nothing else - a product creates its own account the first
 * time it sees the `sub`. Nothing is written until the address is proved.
 */

let app: NestFastifyApplication;
let outbox: Outbox;
const fake = new FakeOidc();

beforeAll(async () => {
  await fake.start();
  app = await startApp();
  outbox = app.get(Outbox);
});
afterAll(async () => {
  await app?.close();
  await fake.stop();
  await closeMembers();
});

interface Flow {
  b: Browser;
  verifier: string;
  page: Hop;
}

async function start(b: Browser = browser()): Promise<Flow> {
  const { verifier, challenge } = pkce();
  const { hop } = await b.follow(authorizeUrl(challenge));
  return { b, verifier, page: hop };
}

async function post(f: Flow, fields: Record<string, string>): Promise<Hop> {
  f.page = await f.b.post(`${APP}/login`, { ...formFields(f.page.html), ...fields });
  return f.page;
}

const otpId = (page: Hop) => /name="otp_id" value="([^"]+)"/.exec(page.html)![1]!;
const enter = (f: Flow, code: string) =>
  post(f, { action: 'verify_code', otp_id: otpId(f.page), code });

async function landed(f: Flow): Promise<Record<string, any>> {
  expect(f.page.status).toBe(303);
  const { url } = await f.b.follow(f.page.location!);
  const t = await exchange(new URL(url).searchParams.get('code')!, f.verifier);
  expect(t.status).toBe(200);
  return claims(t.body.access_token);
}

const fresh = () => `new-${randomBytes(6).toString('hex')}@example.com`;
const PASSWORD = 'Brand-New-Pass-1';

async function toSignup(email: string): Promise<Flow> {
  const f = await start();
  const page = await post(f, { action: 'identify', identifier: email });
  expect(page.html).toContain('Create your account');
  return f;
}

const identities = (email: string) =>
  sql<{ identity_id: string }>(
    "SELECT identity_id FROM identity_identifier WHERE kind = 'email' AND value = $1",
    [email],
  );

describe('create an account with an email or phone', () => {
  it('checks the password before anything is sent', async () => {
    const email = fresh();
    const f = await toSignup(email);
    expect(f.page.html).toContain('autocomplete="new-password"');

    const weak = await post(f, { action: 'signup', password: 'weak', confirm: 'weak' });
    expect(weak.status).toBe(422);
    expect(weak.html).toMatch(/class="unmet">At least 8 characters/);
    const mismatch = await post(f, {
      action: 'signup',
      password: PASSWORD,
      confirm: 'Other-Pass-1',
    });
    expect(mismatch.html).toContain('do not match');
    expect(outbox.count(email)).toBe(0);
  });

  it('proves the address by code, then creates the identity and signs it in', async () => {
    const email = fresh();
    const f = await toSignup(email);
    const code = await post(f, { action: 'signup', password: PASSWORD, confirm: PASSWORD });
    expect(code.html).toContain('Confirm your email address');
    // Nothing is written before the code.
    expect(await identities(email)).toHaveLength(0);

    await enter(f, outbox.last(email)!.code);
    const at = await landed(f);
    expect(at.amr).toEqual(['otp']);

    const [row] = await identities(email);
    expect(at.sub).toBe(row!.identity_id);
    const [id] = await sql(
      'SELECT verified_at, is_primary FROM identity_identifier WHERE identity_id = $1',
      [at.sub],
    );
    expect(id!.verified_at).toBeInstanceOf(Date);
    expect(id!.is_primary).toBe(true);
    const journal = await sql(
      "SELECT kind FROM auth_event WHERE identity_id = $1 AND outcome = 'success'",
      [at.sub],
    );
    // One transaction writes the first three, so they share a timestamp: compare as a set.
    expect(journal.map((e) => e.kind).sort()).toEqual([
      'credential_added',
      'identifier_verified',
      'identity_created',
      'sign_in',
    ]);

    // The password it chose signs it in from now on.
    const g = await start();
    await post(g, { action: 'identify', identifier: email });
    await post(g, { action: 'password', password: PASSWORD });
    expect((await landed(g)).sub).toBe(at.sub);
  });

  it('creates an account on a phone number, proved over WhatsApp', async () => {
    const phone = `+4477008${String(Date.now()).slice(-5)}`;
    const f = await start();
    await post(f, { action: 'identify', identifier: phone });
    const code = await post(f, { action: 'signup', password: PASSWORD, confirm: PASSWORD });
    expect(code.html).toContain('Confirm your phone number');
    expect(outbox.last(phone)!.channel).toBe('whatsapp');
    await enter(f, outbox.last(phone)!.code);
    const at = await landed(f);
    const [row] = await sql(
      "SELECT identity_id FROM identity_identifier WHERE kind = 'phone' AND value = $1",
      [phone],
    );
    expect(row!.identity_id).toBe(at.sub);
  });

  it('writes nothing for a wrong code', async () => {
    const email = fresh();
    const f = await toSignup(email);
    await post(f, { action: 'signup', password: PASSWORD, confirm: PASSWORD });
    const right = outbox.last(email)!.code;
    const res = await enter(f, right === '000000' ? '111111' : '000000');
    expect(res.status).toBe(422);
    expect(await identities(email)).toHaveLength(0);
  });

  it('is not blocked by someone who only typed the address', async () => {
    const email = fresh();
    const squatter = await createMember();
    await sql(
      "INSERT INTO identity_identifier (identity_id, kind, value) VALUES ($1, 'email', $2)",
      [squatter.identityId, email],
    );
    const f = await toSignup(email);
    await post(f, { action: 'signup', password: PASSWORD, confirm: PASSWORD });
    await enter(f, outbox.last(email)!.code);
    const at = await landed(f);
    expect(at.sub).not.toBe(squatter.identityId);
  });

  it('signs in instead when the address was proved by someone else meanwhile', async () => {
    const email = fresh();
    const f = await toSignup(email);
    await post(f, { action: 'signup', password: PASSWORD, confirm: PASSWORD });
    const code = outbox.last(email)!.code;
    const owner = await createMember();
    await sql(
      "INSERT INTO identity_identifier (identity_id, kind, value, verified_at) VALUES ($1, 'email', $2, now())",
      [owner.identityId, email],
    );
    const res = await enter(f, code);
    expect(res.status).toBe(422);
    expect(res.html).toContain('An account already uses that email address. Sign in instead.');
    expect((await identities(email)).map((r) => r.identity_id)).toEqual([owner.identityId]);
  });

  it('starts again when the sign-up outlives what it holds', async () => {
    const email = fresh();
    const f = await toSignup(email);
    await post(f, { action: 'signup', password: PASSWORD, confirm: PASSWORD });
    const flow = formFields(f.page.html).login_challenge!;
    const key = `uni-auth:signup:${createHash('sha256').update(flow).digest('base64url')}`;
    expect(await app.get(RedisService).client.del(key)).toBe(1);

    const res = await enter(f, outbox.last(email)!.code);
    expect(res.status).toBe(422);
    expect(res.html).toContain('Your sign-up took too long');
    expect(res.html).toContain('Start again');
    expect(await identities(email)).toHaveLength(0);
  });

  it('cannot be completed from another sign-in', async () => {
    const email = fresh();
    const f = await toSignup(email);
    await post(f, { action: 'signup', password: PASSWORD, confirm: PASSWORD });
    const code = outbox.last(email)!.code;
    const id = otpId(f.page);

    const other = await toSignup(email);
    const res = await post(other, { action: 'verify_code', otp_id: id, code });
    expect(res.status).toBe(422);
    expect(await identities(email)).toHaveLength(0);
  });
});

describe('create an account with Google or Apple', () => {
  async function viaGoogle(user: { sub: string; email: string; email_verified: boolean }) {
    const f = await start();
    const left = await f.b.post(`${APP}/login`, {
      ...formFields(f.page.html),
      action: 'upstream',
      provider: 'google',
    });
    const { redirectUri, code, state } = fake.approve('google', left.location!, user);
    const back = await f.b.get(`${redirectUri}?${new URLSearchParams({ code, state }).toString()}`);
    expect(back.status).toBe(303);
    f.page = await f.b.get(back.location!);
    return f;
  }

  it('offers an account for a verified email no one uses, and creates it on confirmation', async () => {
    const email = fresh();
    const sub = `g-${randomBytes(6).toString('hex')}`;
    const f = await viaGoogle({ sub, email, email_verified: true });
    expect(f.page.html).toContain('Create one that signs in with Google?');
    expect(f.page.html).toContain(email);
    expect(await identities(email)).toHaveLength(0);

    await post(f, { action: 'upstream_signup' });
    const at = await landed(f);
    expect(at.amr).toEqual(['fed']);
    const creds = await sql(
      'SELECT kind, provider_subject, provider_email FROM credential WHERE identity_id = $1',
      [at.sub],
    );
    expect(creds).toEqual([{ kind: 'oauth_google', provider_subject: sub, provider_email: email }]);
    expect((await identities(email)).map((r) => r.identity_id)).toEqual([at.sub]);
  });

  it('spends the offer once, and only in the sign-in it was made in', async () => {
    const email = fresh();
    const f = await viaGoogle({
      sub: `g-${randomBytes(6).toString('hex')}`,
      email,
      email_verified: true,
    });
    const token = formFields(f.page.html).token!;

    const other = await start();
    const stolen = await post(other, { action: 'upstream_signup', token });
    expect(stolen.html).toContain('That took too long');
    expect(await identities(email)).toHaveLength(0);

    const confirm = f.page.html;
    await post(f, { action: 'upstream_signup' });
    expect(f.page.status).toBe(303);
    const again = await f.b.post(`${APP}/login`, {
      ...formFields(confirm),
      action: 'upstream_signup',
    });
    expect(again.html).toContain('That took too long');
  });

  it('offers nothing for an email Google has not verified', async () => {
    const f = await viaGoogle({
      sub: `g-${randomBytes(6).toString('hex')}`,
      email: fresh(),
      email_verified: false,
    });
    expect(f.page.html).toContain('No account here uses that Google account yet.');
  });
});
