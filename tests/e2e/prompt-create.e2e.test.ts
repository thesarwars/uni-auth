import type { NestFastifyApplication } from '@nestjs/platform-fastify';
import { randomBytes } from 'node:crypto';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { Outbox } from '../../src/delivery/outbox';
import { wantsCreate } from '../../src/flows/login.controller';
import type { LoginRequest } from '../../src/hydra/hydra-admin.service';
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
import { closeMembers, createMember, type Member } from '../support/members';

/**
 * `prompt=create` (OpenID Connect "Initiating User Registration via OpenID Connect 1.0"): a
 * client's "Create account" button opens uni-auth on the create-account wording. It changes
 * what the screens say, never what they allow.
 */

let app: NestFastifyApplication;
let outbox: Outbox;
let member: Member;

beforeAll(async () => {
  app = await startApp();
  outbox = app.get(Outbox);
  member = await createMember();
});
afterAll(async () => {
  await app?.close();
  await closeMembers();
});

interface Flow {
  b: Browser;
  verifier: string;
  page: Hop;
}

async function start(prompt?: string): Promise<Flow> {
  const b = browser();
  const { verifier, challenge } = pkce();
  const { hop } = await b.follow(authorizeUrl(challenge, prompt ? { prompt } : {}));
  return { b, verifier, page: hop };
}

async function post(f: Flow, fields: Record<string, string>): Promise<Hop> {
  f.page = await f.b.post(`${APP}/login`, { ...formFields(f.page.html), ...fields });
  return f.page;
}

const h1 = (page: Hop) => /<h1>([^<]*)<\/h1>/.exec(page.html)?.[1];

describe('prompt=create', () => {
  it('opens on the create-account wording', async () => {
    const f = await start('create');
    expect(f.page.status).toBe(200);
    expect(h1(f.page)).toBe('Create your account');
    expect(f.page.html).toContain("send it a code to confirm it's yours");
    expect(f.page.html).toContain('<title>Create your account');
  });

  it('leaves an ordinary sign-in as it was', async () => {
    const f = await start();
    expect(h1(f.page)).toBe('Sign in to continue to Go Style Network');
  });

  it('is found among several prompt values', async () => {
    expect(h1((await start('login create')).page)).toBe('Create your account');
  });

  it('creates the account for a new address, with its code, and signs in', async () => {
    const f = await start('create');
    const email = `new-${randomBytes(6).toString('hex')}@example.com`;
    await post(f, { action: 'identify', identifier: email });
    expect(h1(f.page)).toBe('Create your account');
    await post(f, { action: 'signup', password: 'Brand-New-Pass-1', confirm: 'Brand-New-Pass-1' });
    const otpId = /name="otp_id" value="([^"]+)"/.exec(f.page.html)![1]!;
    await post(f, { action: 'verify_code', otp_id: otpId, code: outbox.last(email)!.code });
    expect(f.page.status).toBe(303);
    const { url } = await f.b.follow(f.page.location!);
    const t = await exchange(new URL(url).searchParams.get('code')!, f.verifier);
    expect(t.status).toBe(200);
    expect(claims(t.body.access_token).sub).toMatch(/^[0-9a-f-]{36}$/);
  });

  it('signs an address that already has an account in to it, and says so', async () => {
    const f = await start('create');
    await post(f, { action: 'identify', identifier: member.email });
    expect(h1(f.page)).toBe('Enter your password');
    expect(f.page.html).toContain(`There&#39;s already an account for ${member.email}`);
    await post(f, { action: 'password', password: member.password });
    expect(f.page.status).toBe(303);
  });

  it('says nothing of the kind on an ordinary sign-in', async () => {
    const f = await start();
    await post(f, { action: 'identify', identifier: member.email });
    expect(f.page.html).not.toContain('already an account');
  });

  it('cannot be switched on by the browser', async () => {
    const f = await start();
    await post(f, { action: 'identify', identifier: 'x', prompt: 'create', create: 'true' });
    expect(h1(f.page)).toBe('Sign in to continue to Go Style Network');
  });
});

describe('wantsCreate', () => {
  const req = (request_url: string | null) => ({ request_url }) as unknown as LoginRequest;
  it.each([
    ['https://a/oauth2/auth?prompt=create', true],
    ['https://a/oauth2/auth?prompt=login%20create', true],
    ['https://a/oauth2/auth?prompt=created', false],
    ['https://a/oauth2/auth?prompt=login', false],
    ['https://a/oauth2/auth', false],
    ['not a url', false],
    [null, false],
  ])('%s -> %s', (url, expected) => {
    expect(wantsCreate(req(url))).toBe(expected);
  });
});
