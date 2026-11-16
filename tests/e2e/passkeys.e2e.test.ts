import type { NestFastifyApplication } from '@nestjs/platform-fastify';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { Outbox } from '../../src/delivery/outbox';
import { codeAt, fromBase32, stepAt } from '../../src/two-step/totp';
import { startApp } from '../support/app';
import { Authenticator } from '../support/authenticator';
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
 * Passkeys (account-plan.md part 5): adding one in the account centre, signing in with it and
 * no password (AC-D5), using it as the second step, and the refusals - a replayed answer, a
 * wrong site, no user verification, a cloned key, someone else's passkey.
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

const ICLOUD = 'fbfc3007-154e-4ecc-8c0b-6e020557d7bd';
const csrf = (page: Hop): string => /name="_csrf" value="([^"]+)"/.exec(page.html)![1]!;
const challengeOf = (page: Hop): string =>
  /name="login_challenge" value="([^"]+)"/.exec(page.html)![1]!;
const open = async (b: Browser, path: string): Promise<Hop> =>
  (await b.follow(`${APP}${path}`)).hop;
const json = async (b: Browser, url: string): Promise<{ status: number; body: any }> => {
  const hop = await b.get(url);
  return { status: hop.status, body: hop.status === 200 ? JSON.parse(hop.html) : null };
};

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

/** Adds a passkey from the account centre; the account browser is handed back. */
async function addPasskey(m: Member, key: Authenticator, b?: Browser): Promise<Browser> {
  b ??= await accountSignIn(m);
  const page = await open(b, '/account/passkeys/add');
  expect(page.status).toBe(200);
  const { status, body } = await json(b, `${APP}/account/passkeys/options`);
  expect(status).toBe(200);
  const res = await b.post(`${APP}/account/passkeys/add`, {
    _csrf: csrf(page),
    credential: key.create(body),
  });
  expect(res.status).toBe(303);
  expect(res.location).toBe(`${APP}/account/passkeys?done=passkey_added`);
  return b;
}

interface Flow {
  b: Browser;
  verifier: string;
  page: Hop;
}

/** GSN web's sign-in, at the identifier screen. */
async function startSignIn(b: Browser = browser()): Promise<Flow> {
  const { verifier, challenge } = pkce();
  const page = (await b.follow(authorizeUrl(challenge))).hop;
  expect(page.status).toBe(200);
  return { b, verifier, page };
}

/** Signs in on the screen `f` is at with `key`, answering options from `optionsUrl`. */
async function withPasskey(
  f: Flow,
  key: Authenticator,
  o: { uv?: boolean; origin?: string } = {},
): Promise<Hop> {
  const challenge = challengeOf(f.page);
  const { body } = await json(
    f.b,
    `${APP}/login/passkey/options?login_challenge=${encodeURIComponent(challenge)}`,
  );
  f.page = await f.b.post(`${APP}/login/passkey`, {
    _csrf: csrf(f.page),
    login_challenge: challenge,
    credential: key.get(body, o),
  });
  return f.page;
}

async function landed(f: Flow): Promise<Record<string, any>> {
  expect(f.page.status).toBe(303);
  const { url } = await f.b.follow(f.page.location!);
  const code = new URL(url).searchParams.get('code');
  expect(code, `landed at ${url}`).toBeTruthy();
  const t = await exchange(code!, f.verifier);
  expect(t.status).toBe(200);
  return { ...claims(t.body.access_token), id_token: t.body.id_token };
}

/** Where a refused passkey sends the browser: the identifier screen, saying so. */
async function refused(f: Flow): Promise<void> {
  expect(f.page.status).toBe(303);
  expect(f.page.location).toMatch(/[?&]passkey=failed$/);
  const back = (await f.b.follow(f.page.location!)).hop;
  expect(back.html).toMatch(/That passkey couldn(&#39;|')t be used/);
}

describe('adding a passkey', () => {
  it('shows on Security & sign-in, needs the member to verify, and emails them', async () => {
    const m = await createMember();
    const b = await accountSignIn(m);
    let page = await open(b, '/account/security');
    expect(page.html).toContain('>Passkeys<');
    expect(page.html).toContain('Sign in without a password');

    page = await open(b, '/account/passkeys/add');
    expect(page.html).toContain('data-passkey="create"');
    const { body } = await json(b, `${APP}/account/passkeys/options`);
    expect(body.rp).toEqual({ name: expect.any(String), id: 'localhost' });
    expect(body.authenticatorSelection).toMatchObject({
      residentKey: 'required',
      userVerification: 'required',
    });
    expect(body.attestation).toBe('none');
    expect(body.user.name).toBe(m.email);

    const key = new Authenticator({ aaguid: ICLOUD });
    const res = await b.post(`${APP}/account/passkeys/add`, {
      _csrf: csrf(page),
      credential: key.create(body),
    });
    expect(res.location).toBe(`${APP}/account/passkeys?done=passkey_added`);
    const [row] = await sql(
      `SELECT nickname, backup_eligible, backup_state, sign_count::int AS sign_count, transports
         FROM credential WHERE identity_id = $1 AND kind = 'passkey'`,
      [m.identityId],
    );
    expect(row).toEqual({
      nickname: 'iCloud Keychain',
      backup_eligible: true,
      backup_state: true,
      sign_count: 0,
      transports: ['internal', 'hybrid'],
    });
    expect(outbox.noticesTo(m.email).map((n) => n.subject)).toContain(
      'A passkey was added to your account',
    );
    page = await open(b, '/account/passkeys?done=passkey_added');
    expect(page.html).toContain('iCloud Keychain<span class="tag">Synced</span>');
    page = await open(b, '/account/security');
    expect(page.html).toMatch(/Passkeys<span class="tag inverse">1</);
  });

  it('refuses an answer to a challenge it did not give, or the same answer twice', async () => {
    const m = await createMember();
    const b = await accountSignIn(m);
    const page = await open(b, '/account/passkeys/add');
    const key = new Authenticator();
    const made = key.create({
      challenge: 'bm90LWdpdmVu',
      rp: { id: 'localhost' },
      user: { id: 'AAAA' },
    });
    const res = await b.post(`${APP}/account/passkeys/add`, {
      _csrf: csrf(page),
      credential: made,
    });
    expect(res.status).toBe(422);
    expect(res.html).toMatch(/That passkey couldn(&#39;|')t be saved/);

    const { body } = await json(b, `${APP}/account/passkeys/options`);
    const answer = key.create(body);
    await b.post(`${APP}/account/passkeys/add`, { _csrf: csrf(page), credential: answer });
    const again = await b.post(`${APP}/account/passkeys/add`, {
      _csrf: csrf(page),
      credential: answer,
    });
    expect(again.status).toBe(422);
    const rows = await sql("SELECT 1 FROM credential WHERE identity_id = $1 AND kind = 'passkey'", [
      m.identityId,
    ]);
    expect(rows).toHaveLength(1);
  });

  it('leaves out the passkeys the member already has', async () => {
    const m = await createMember();
    const key = new Authenticator();
    const b = await addPasskey(m, key);
    await open(b, '/account/passkeys/add');
    const { body } = await json(b, `${APP}/account/passkeys/options`);
    expect(body.excludeCredentials.map((c: { id: string }) => c.id)).toEqual([
      key.credentialId.toString('base64url'),
    ]);
  });

  it('needs the form token', async () => {
    const m = await createMember();
    const b = await accountSignIn(m);
    const res = await b.post(`${APP}/account/passkeys/add`, { credential: '{}' });
    expect(res.status).toBe(403);
  });
});

describe('signing in with a passkey', () => {
  it('needs no password, and is aal2 on its own', async () => {
    const m = await createMember();
    const key = new Authenticator();
    await addPasskey(m, key);

    const f = await startSignIn();
    expect(f.page.html).toContain('autocomplete="username webauthn"');
    expect(f.page.html).toContain('Sign in with a passkey');
    const { body } = await json(
      f.b,
      `${APP}/login/passkey/options?login_challenge=${encodeURIComponent(challengeOf(f.page))}`,
    );
    expect(body.allowCredentials).toEqual([]);
    expect(body.userVerification).toBe('required');
    expect(body.rpId).toBe('localhost');

    await withPasskey(f, key);
    const at = await landed(f);
    expect(at.sub).toBe(m.identityId);
    expect(at.amr).toEqual(['swk', 'mfa']);
    const [s] = await sql<{ aal: number; credential_kind: string }>(
      `SELECT s.aal, c.kind::text AS credential_kind
         FROM auth_session s JOIN credential c ON c.id = s.credential_id WHERE s.sid = $1`,
      [at.sid],
    );
    expect(s).toEqual({ aal: 2, credential_kind: 'passkey' });
    const [used] = await sql<{ last_used_at: Date | null }>(
      "SELECT last_used_at FROM credential WHERE identity_id = $1 AND kind = 'passkey'",
      [m.identityId],
    );
    expect(used!.last_used_at).not.toBeNull();
  });

  it('skips the second step of a 2-step account', async () => {
    const m = await createMember();
    const key = new Authenticator();
    const b = await addPasskey(m, key);
    const setup = await open(b, '/account/two-step/setup');
    const seed = fromBase32(/aria-label="Setup key">([A-Z2-7 ]+)</.exec(setup.html)![1]!);
    await b.post(`${APP}/account/two-step/setup`, {
      _csrf: csrf(setup),
      code: codeAt(seed, stepAt(Date.now())),
    });

    const f = await startSignIn();
    await withPasskey(f, key);
    expect(f.page.location).not.toContain('/login/two-step');
    expect((await landed(f)).amr).toEqual(['swk', 'mfa']);
  });

  it('refuses a replayed answer, another site, and a tap with no verification', async () => {
    const m = await createMember();
    const key = new Authenticator();
    await addPasskey(m, key);

    // Replayed: an answer to one sign-in's challenge, posted to another.
    const one = await startSignIn();
    const { body } = await json(
      one.b,
      `${APP}/login/passkey/options?login_challenge=${encodeURIComponent(challengeOf(one.page))}`,
    );
    const answer = key.get(body);
    const two = await startSignIn();
    two.page = await two.b.post(`${APP}/login/passkey`, {
      _csrf: csrf(two.page),
      login_challenge: challengeOf(two.page),
      credential: answer,
    });
    await refused(two);

    // A look-alike site relaying our challenge: the browser names its own origin.
    const phished = await startSignIn();
    await withPasskey(phished, key, { origin: 'https://uni-auth.gostyle.uk.evil.example' });
    await refused(phished);

    // Presence only, with no fingerprint, face or PIN: not enough to sign in alone.
    const tapped = await startSignIn();
    await withPasskey(tapped, key, { uv: false });
    await refused(tapped);

    const failures = await sql<{ why: string }>(
      `SELECT detail->>'why' AS why FROM auth_event
        WHERE identity_id = $1 AND kind = 'sign_in' AND outcome = 'failure'
          AND credential_kind = 'passkey' ORDER BY occurred_at`,
      [m.identityId],
    );
    expect(failures.map((r) => r.why)).toEqual(['signature', 'signature']);
  });

  it('refuses a hardware key whose counter went back: a copy of the key', async () => {
    const m = await createMember();
    const key = new Authenticator({ synced: false, counter: 0 });
    await addPasskey(m, key);

    const f = await startSignIn();
    await withPasskey(f, key);
    expect((await landed(f)).amr).toEqual(['hwk', 'mfa']);

    key.counter = 0; // the clone starts where the original did
    const g = await startSignIn();
    await withPasskey(g, key);
    await refused(g);
    const [e] = await sql<{ why: string }>(
      `SELECT detail->>'why' AS why FROM auth_event
        WHERE identity_id = $1 AND kind = 'sign_in' AND outcome = 'failure'`,
      [m.identityId],
    );
    expect(e!.why).toBe('sign_count');
  });

  it('turns a suspended account away', async () => {
    const m = await createMember();
    const key = new Authenticator();
    await addPasskey(m, key);
    await sql("UPDATE identity SET status = 'suspended' WHERE id = $1", [m.identityId]);
    const f = await startSignIn();
    await withPasskey(f, key);
    expect(f.page.location).toMatch(/passkey=suspended$/);
    const back = (await f.b.follow(f.page.location!)).hop;
    expect(back.html).toContain('This account is suspended');
  });

  it('confirms it’s you for step-up, with that member’s passkey only', async () => {
    const m = await createMember();
    const key = new Authenticator();
    await addPasskey(m, key);
    const other = await createMember();
    const theirs = new Authenticator();
    await addPasskey(other, theirs);

    const first = await startSignIn();
    await withPasskey(first, key);
    const { id_token } = await landed(first);

    // GSN asks again before a money action: prompt=login with the member named.
    const stepUp = async (): Promise<Flow> => {
      const { verifier, challenge } = pkce();
      const page = (
        await first.b.follow(authorizeUrl(challenge, { prompt: 'login', id_token_hint: id_token }))
      ).hop;
      expect(page.html).toContain('Confirm it');
      expect(page.html).toContain('Use a passkey instead');
      return { b: first.b, verifier, page };
    };
    const wrong = await stepUp();
    await withPasskey(wrong, theirs);
    expect(wrong.page.location).toMatch(/passkey=failed$/);

    const right = await stepUp();
    await withPasskey(right, key);
    const at = await landed(right);
    expect(at.sub).toBe(m.identityId);
    expect(at.amr).toEqual(['swk', 'mfa']);
  });
});

describe('a passkey as the second step', () => {
  it('passes 2-step verification after a password, and only with the member’s own', async () => {
    const m = await createMember();
    const key = new Authenticator();
    const b = await addPasskey(m, key);
    const setup = await open(b, '/account/two-step/setup');
    const seed = fromBase32(/aria-label="Setup key">([A-Z2-7 ]+)</.exec(setup.html)![1]!);
    await b.post(`${APP}/account/two-step/setup`, {
      _csrf: csrf(setup),
      code: codeAt(seed, stepAt(Date.now())),
    });
    const stranger = new Authenticator();
    await addPasskey(await createMember(), stranger);

    const second = async (k: Authenticator): Promise<Flow> => {
      const f = await startSignIn();
      f.page = await f.b.post(`${APP}/login`, {
        ...formFields(f.page.html),
        action: 'identify',
        identifier: m.email,
      });
      f.page = await f.b.post(`${APP}/login`, {
        ...formFields(f.page.html),
        action: 'password',
        password: m.password,
      });
      expect(f.page.location).toContain('/login/two-step?');
      f.page = (await f.b.follow(f.page.location!)).hop;
      expect(f.page.html).toContain('Use a passkey instead');
      const challenge = challengeOf(f.page);
      const { body } = await json(
        f.b,
        `${APP}/login/two-step/passkey?login_challenge=${encodeURIComponent(challenge)}`,
      );
      expect(body.allowCredentials.map((c: { id: string }) => c.id)).toEqual([
        key.credentialId.toString('base64url'),
      ]);
      f.page = await f.b.post(`${APP}/login/two-step`, {
        _csrf: csrf(f.page),
        login_challenge: challenge,
        mode: 'passkey',
        credential: k.get(body, { uv: false }),
      });
      return f;
    };

    const bad = await second(stranger);
    expect(bad.page.status).toBe(422);
    expect(bad.page.html).toMatch(/That passkey couldn(&#39;|')t be used/);

    const good = await second(key);
    const at = await landed(good);
    expect(at.amr).toEqual(expect.arrayContaining(['pwd', 'swk', 'mfa']));
  });

  it('is not offered without the cookie of the browser that passed the first step', async () => {
    const res = await browser().get(`${APP}/login/two-step/passkey?login_challenge=nope`);
    expect(res.status).toBe(401);
  });
});

describe('managing passkeys', () => {
  it('renames one, refusing an empty name', async () => {
    const m = await createMember();
    const b = await addPasskey(m, new Authenticator());
    const [{ id }] = (await sql(
      "SELECT id FROM credential WHERE identity_id = $1 AND kind = 'passkey'",
      [m.identityId],
    )) as [{ id: string }];
    const page = await open(b, `/account/passkeys/rename?id=${id}`);
    expect(page.status).toBe(200);
    const empty = await b.post(`${APP}/account/passkeys/rename`, {
      _csrf: csrf(page),
      id,
      name: '   ',
    });
    expect(empty.status).toBe(422);
    const res = await b.post(`${APP}/account/passkeys/rename`, {
      _csrf: csrf(page),
      id,
      name: '  Work   laptop ',
    });
    expect(res.location).toBe(`${APP}/account/passkeys?done=passkey_renamed`);
    const list = await open(b, '/account/passkeys');
    expect(list.html).toContain('Work laptop');
  });

  it('removes one: it signs nobody in after, and the member is told', async () => {
    const m = await createMember();
    const key = new Authenticator();
    const b = await addPasskey(m, key);
    const [{ id }] = (await sql(
      "SELECT id FROM credential WHERE identity_id = $1 AND kind = 'passkey'",
      [m.identityId],
    )) as [{ id: string }];
    const page = await open(b, '/account/passkeys');
    const res = await b.post(`${APP}/account/passkeys/remove`, { _csrf: csrf(page), id });
    expect(res.location).toBe(`${APP}/account/passkeys?done=passkey_removed`);
    expect(outbox.noticesTo(m.email).map((n) => n.subject)).toContain(
      'A passkey was removed from your account',
    );
    const activity = await open(b, '/account/activity');
    expect(activity.html).toContain('Passkey removed');

    const f = await startSignIn();
    await withPasskey(f, key);
    await refused(f);
  });

  it('can’t touch another member’s passkey', async () => {
    const owner = await createMember();
    await addPasskey(owner, new Authenticator());
    const [{ id }] = (await sql(
      "SELECT id FROM credential WHERE identity_id = $1 AND kind = 'passkey'",
      [owner.identityId],
    )) as [{ id: string }];
    const b = await accountSignIn(await createMember());
    const page = await open(b, '/account/passkeys');
    await b.post(`${APP}/account/passkeys/remove`, { _csrf: csrf(page), id });
    await b.post(`${APP}/account/passkeys/rename`, { _csrf: csrf(page), id, name: 'Mine now' });
    const [row] = await sql('SELECT revoked_at, nickname FROM credential WHERE id = $1', [id]);
    expect(row!.revoked_at).toBeNull();
    expect(row!.nickname).not.toBe('Mine now');
  });
});
