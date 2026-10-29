import type { NestFastifyApplication } from '@nestjs/platform-fastify';
import { randomBytes } from 'node:crypto';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
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
import { FakeOidc, type FakeProvider, type FakeUser } from '../support/fake-oidc';
import { closeMembers, createMember, sql } from '../support/members';

/**
 * Sign in with Google and with Apple (auth-plan.md section 12.2, part 4): redirect flows the
 * login application runs itself, against a stand-in for each provider.
 */

let app: NestFastifyApplication;
const fake = new FakeOidc();

beforeAll(async () => {
  await fake.start();
  app = await startApp();
});
afterAll(async () => {
  await app?.close();
  await fake.stop();
  await closeMembers();
});

const subject = () => `up-${randomBytes(6).toString('hex')}`;

interface Trip {
  b: Browser;
  verifier: string;
  /** The callback the provider would send the browser to. */
  callback: () => Promise<Hop>;
  authorizeUrl: string;
}

/** From the identifier screen to the provider, approved there as `user`. */
async function leave(
  provider: FakeProvider,
  user: FakeUser,
  b: Browser = browser(),
): Promise<Trip> {
  const { verifier, challenge } = pkce();
  const { hop } = await b.follow(authorizeUrl(challenge));
  expect(hop.html).toContain(`Continue with ${provider === 'google' ? 'Google' : 'Apple'}`);
  const left = await b.post(`${APP}/login`, {
    ...formFields(hop.html),
    action: 'upstream',
    provider,
  });
  expect(left.status).toBe(303);
  const at = left.location!;
  expect(at.startsWith(`http://localhost:4999/${provider}/authorize?`)).toBe(true);

  const { redirectUri, code, state } = fake.approve(provider, at, user);
  const callback = () =>
    provider === 'google'
      ? b.get(`${redirectUri}?${new URLSearchParams({ code, state }).toString()}`)
      : b.post(redirectUri, { code, state }); // Apple's form_post: no token of ours
  return { b, verifier, callback, authorizeUrl: at };
}

async function signedIn(t: Trip, hop: Hop): Promise<Record<string, any>> {
  expect(hop.status).toBe(303);
  const { url } = await t.b.follow(hop.location!);
  const tokens = await exchange(new URL(url).searchParams.get('code')!, t.verifier);
  expect(tokens.status).toBe(200);
  return claims(tokens.body.access_token);
}

/** Where a refused callback lands: the identifier screen of the same sign-in, with its reason. */
async function backOnIdentifier(t: Trip, hop: Hop): Promise<string> {
  expect(hop.status).toBe(303);
  expect(hop.location!.startsWith(`${APP}/login?`)).toBe(true);
  const page = await t.b.get(hop.location!);
  expect(page.html).toContain('Sign in to continue to');
  return page.html;
}

describe('Sign in with Google', () => {
  it('asks Google for a code with state, nonce and PKCE, and nothing else of the member', async () => {
    const t = await leave('google', { sub: subject() });
    const q = new URL(t.authorizeUrl).searchParams;
    expect(q.get('client_id')).toBe('test-google-client');
    expect(q.get('redirect_uri')).toBe(`${APP}/upstream/google/callback`);
    expect(q.get('scope')).toBe('openid email');
    expect(q.get('response_type')).toBe('code');
    expect(q.get('code_challenge_method')).toBe('S256');
    expect(q.get('state')!.length).toBeGreaterThanOrEqual(40);
    expect(q.get('nonce')!.length).toBeGreaterThanOrEqual(40);
  });

  it('signs in the identity a Google account belongs to', async () => {
    const m = await createMember();
    const sub = subject();
    const [cred] = await sql<{ id: string }>(
      "INSERT INTO credential (identity_id, kind, provider_subject) VALUES ($1, 'oauth_google', $2) RETURNING id",
      [m.identityId, sub],
    );
    const t = await leave('google', { sub, email: 'whatever@gmail.example', email_verified: true });
    const at = await signedIn(t, await t.callback());
    expect(at.sub).toBe(m.identityId);
    expect(at.amr).toEqual(['fed']);
    const [s] = await sql('SELECT credential_id FROM auth_session WHERE sid = $1', [at.sid]);
    expect(s!.credential_id).toBe(cred!.id);
  });

  it('links a first-time Google account to the identity that holds the same verified email', async () => {
    const m = await createMember();
    const sub = subject();
    const t = await leave('google', { sub, email: m.email.toUpperCase(), email_verified: true });
    const at = await signedIn(t, await t.callback());
    expect(at.sub).toBe(m.identityId);

    const creds = await sql(
      "SELECT provider_subject, provider_email, provider_email_verified FROM credential WHERE identity_id = $1 AND kind = 'oauth_google'",
      [m.identityId],
    );
    expect(creds).toEqual([
      { provider_subject: sub, provider_email: m.email, provider_email_verified: true },
    ]);
    const added = await sql(
      "SELECT detail FROM auth_event WHERE identity_id = $1 AND kind = 'credential_added'",
      [m.identityId],
    );
    expect(added).toEqual([{ detail: { linked_by: 'verified_email' } }]);

    // The next time, the link is used directly.
    const again = await leave('google', { sub, email: m.email, email_verified: true });
    expect((await signedIn(again, await again.callback())).sub).toBe(m.identityId);
  });

  it('does not link on an email Google has not verified', async () => {
    const m = await createMember();
    const t = await leave('google', { sub: subject(), email: m.email, email_verified: false });
    const html = await backOnIdentifier(t, await t.callback());
    expect(html).toContain('No account here uses that Google account yet.');
    const creds = await sql(
      "SELECT 1 FROM credential WHERE identity_id = $1 AND kind = 'oauth_google'",
      [m.identityId],
    );
    expect(creds).toHaveLength(0);
  });

  it('returns to the identifier screen when the member cancels at Google', async () => {
    const b = browser();
    const t = await leave('google', { sub: subject() }, b);
    const state = new URL(t.authorizeUrl).searchParams.get('state')!;
    const hop = await b.get(
      `${APP}/upstream/google/callback?${new URLSearchParams({ state, error: 'access_denied' }).toString()}`,
    );
    expect(await backOnIdentifier(t, hop)).toContain('Signing in with Google was cancelled.');
  });

  it('spends the state once: a replayed callback is refused', async () => {
    const m = await createMember();
    const sub = subject();
    await sql(
      "INSERT INTO credential (identity_id, kind, provider_subject) VALUES ($1, 'oauth_google', $2)",
      [m.identityId, sub],
    );
    const t = await leave('google', { sub });
    await signedIn(t, await t.callback());
    const replay = await t.callback();
    expect(replay.status).toBe(400);
    expect(replay.html).toContain('This sign-in has expired');
  });

  it('refuses a callback in a browser that did not leave for Google, and burns the state', async () => {
    const t = await leave('google', { sub: subject() });
    const q = new URL(t.authorizeUrl).searchParams;
    const { code, state } = fake.approve('google', t.authorizeUrl, { sub: subject() });
    const stranger = await browser().get(
      `${APP}/upstream/google/callback?${new URLSearchParams({ code, state }).toString()}`,
    );
    expect(stranger.status).toBe(400);
    expect(stranger.html).toContain('This sign-in has expired');
    expect(q.get('state')).toBe(state);
    // The rightful browser cannot use it afterwards either.
    const late = await t.callback();
    expect(late.status).toBe(400);
  });

  it('refuses an ID token for another sign-in (nonce) or another client (audience)', async () => {
    const m = await createMember();
    for (const bad of [{ nonce: 'someone-elses' }, { aud: 'another-client' }]) {
      const t = await leave('google', {
        sub: subject(),
        email: m.email,
        email_verified: true,
        ...bad,
      });
      expect(await backOnIdentifier(t, await t.callback())).toContain(
        'sign you in. Try again, or use another way.',
      );
    }
    const creds = await sql(
      "SELECT 1 FROM credential WHERE identity_id = $1 AND kind = 'oauth_google'",
      [m.identityId],
    );
    expect(creds).toHaveLength(0);
  });

  it('turns a suspended identity away', async () => {
    const m = await createMember();
    const sub = subject();
    await sql(
      "INSERT INTO credential (identity_id, kind, provider_subject) VALUES ($1, 'oauth_google', $2)",
      [m.identityId, sub],
    );
    await sql("UPDATE identity SET status = 'suspended' WHERE id = $1", [m.identityId]);
    const t = await leave('google', { sub });
    expect(await backOnIdentifier(t, await t.callback())).toContain('This account is suspended');
  });
});

describe('Sign in with Apple', () => {
  it('comes back by form_post, pays with a signed client secret, and links a verified email', async () => {
    const m = await createMember();
    const sub = `${subject()}.apple`;
    // Apple sends email_verified as the string "true".
    const t = await leave('apple', { sub, email: m.email, email_verified: 'true' });
    const q = new URL(t.authorizeUrl).searchParams;
    expect(q.get('response_mode')).toBe('form_post');
    expect(q.has('code_challenge')).toBe(false);

    const refusalsBefore = fake.refusals.length;
    const at = await signedIn(t, await t.callback());
    expect(fake.refusals.length).toBe(refusalsBefore);
    expect(at.sub).toBe(m.identityId);
    const creds = await sql(
      "SELECT provider_subject FROM credential WHERE identity_id = $1 AND kind = 'oauth_apple'",
      [m.identityId],
    );
    expect(creds).toEqual([{ provider_subject: sub }]);
  });
});
