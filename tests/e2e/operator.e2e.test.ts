import type { NestFastifyApplication } from '@nestjs/platform-fastify';
import { execFileSync } from 'node:child_process';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { Outbox } from '../../src/delivery/outbox';
import { startApp } from '../support/app';
import { Authenticator } from '../support/authenticator';
import { AccountSessions } from '../../src/account/account-sessions';
import { APP, browser, formFields, type Browser, type Hop } from '../support/browser';
import { closeMembers, createMember, sql, type Member } from '../support/members';

/**
 * The operator console (account-plan.md part 8): only for an operator signed in with a passkey,
 * invisible to everyone else; finds an account, shows it, suspends, reinstates and signs it out
 * everywhere, and logs all of it with the operator's name and reason.
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
const json = async (b: Browser, url: string) => JSON.parse((await b.get(url)).html);

/** scripts/operator.mjs, as an administrator runs it on the server. */
const operatorScript = (...args: string[]): string =>
  execFileSync('node', ['scripts/operator.mjs', ...args], { encoding: 'utf8' });

async function passwordSignIn(m: Member): Promise<Browser> {
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

async function addPasskey(b: Browser, key: Authenticator): Promise<void> {
  const page = await open(b, '/account/passkeys/add');
  const options = await json(b, `${APP}/account/passkeys/options`);
  const res = await b.post(`${APP}/account/passkeys/add`, {
    _csrf: csrf(page),
    credential: key.create(options),
  });
  expect(res.status).toBe(303);
}

/** From the console's "Confirm with a passkey" page, through sign-in with `key`, and back. */
async function confirmWithPasskey(b: Browser, page: Hop, key: Authenticator): Promise<Hop> {
  const href = /href="(\/account\/operator\/confirm\?[^"]+)"/.exec(page.html)![1]!;
  const login = (await b.follow(`${APP}${href.replace(/&amp;/g, '&')}`)).hop;
  const challenge = /name="login_challenge" value="([^"]+)"/.exec(login.html)![1]!;
  const options = await json(
    b,
    `${APP}/login/passkey/options?login_challenge=${encodeURIComponent(challenge)}`,
  );
  const res = await b.post(`${APP}/login/passkey`, {
    _csrf: csrf(login),
    login_challenge: challenge,
    credential: key.get(options),
  });
  expect(res.status).toBe(303);
  return (await b.follow(res.location!)).hop;
}

/** An operator with a passkey, signed in to the console with it. */
async function operator(): Promise<{ m: Member; b: Browser; key: Authenticator }> {
  const m = await createMember();
  const key = new Authenticator();
  const b = await passwordSignIn(m);
  await addPasskey(b, key);
  expect(operatorScript('grant', m.email, 'test support team')).toContain('is now an operator');
  const gate = await open(b, '/account/operator');
  expect(gate.status).toBe(401);
  expect(gate.html).toContain('Confirm with a passkey');
  const console_ = await confirmWithPasskey(b, gate, key);
  expect(console_.status).toBe(200);
  expect(console_.html).toContain('<h1 id="title">Operator console</h1>');
  return { m, b, key };
}

async function find(b: Browser, q: string): Promise<Hop> {
  const page = await open(b, '/account/operator');
  return b.post(`${APP}/account/operator`, { _csrf: csrf(page), q });
}

describe('Who can use it', () => {
  it('is a page that doesn’t exist for a member who isn’t an operator', async () => {
    const b = await passwordSignIn(await createMember());
    const page = await open(b, '/account/operator');
    expect(page.status).toBe(404);
    expect(page.html).not.toContain('Operator console');
    expect((await open(b, '/account')).html).not.toContain('/account/operator');
  });

  it('asks an operator without a passkey to add one first', async () => {
    const m = await createMember();
    operatorScript('grant', m.email, 'test');
    const b = await passwordSignIn(m);
    const page = await open(b, '/account/operator');
    expect(page.status).toBe(401);
    expect(page.html).toContain('href="/account/passkeys/add"');
    // The menu shows it to an operator, though.
    expect((await open(b, '/account')).html).toContain('href="/account/operator"');
  });

  it('lets an operator in with a passkey, not a password', async () => {
    const { b } = await operator();
    const page = await open(b, '/account/operator');
    expect(page.status).toBe(200);
    expect(page.html).toContain(
      'aria-current="page"><span class="tile"><img class="off" src="/assets/icons/search.svg',
    );
  });

  it('shuts the door at once when the grant is revoked', async () => {
    const { m, b } = await operator();
    expect(operatorScript('revoke', m.email, 'left the team')).toContain('no longer an operator');
    expect((await open(b, '/account/operator')).status).toBe(404);
    expect(operatorScript('list')).not.toContain(m.email);
  });
});

describe('Finding and seeing an account', () => {
  it('finds by email, phone or ID, and logs every search and view', async () => {
    const { m: op, b } = await operator();
    const member = await createMember();
    await passwordSignIn(member);
    const byEmail = await find(b, member.email.toUpperCase());
    expect(byEmail.status).toBe(303);
    expect(byEmail.location).toBe(`${APP}/account/operator/identity?id=${member.identityId}`);
    expect((await find(b, member.identityId)).location).toBe(byEmail.location);

    const page = await open(b, `/account/operator/identity?id=${member.identityId}`);
    expect(page.status).toBe(200);
    expect(page.html).toContain(member.email);
    expect(page.html).toContain(member.identityId);
    expect(page.html).toContain('Active');
    expect(page.html).toContain('Suspend account');
    expect(page.html).toContain('Signed in'); // its activity
    expect(page.html).toContain('Signed in now');

    const missing = await find(b, 'no-one-here@example.com');
    expect(missing.status).toBe(404);
    expect(missing.html).toContain('No account has that email address, phone number or ID.');

    const log = await sql(
      `SELECT a.action, a.identity_id FROM operator_action a JOIN operator o ON o.id = a.operator_id
        WHERE o.identity_id = $1 ORDER BY a.occurred_at, a.id`,
      [op.identityId],
    );
    expect(log.map((r) => r.action)).toEqual(['searched', 'searched', 'viewed', 'searched']);
    expect(log[3]!.identity_id).toBeNull();
  });
});

describe('Changing an account', () => {
  it('suspends: signed out everywhere, can’t sign in, told by email; then reinstates', async () => {
    const { b } = await operator();
    const member = await createMember();
    const theirs = await passwordSignIn(member);
    let page = await open(b, `/account/operator/identity?id=${member.identityId}`);

    const noReason = await b.post(`${APP}/account/operator/suspend`, {
      _csrf: csrf(page),
      id: member.identityId,
      reason: '  ',
    });
    expect(noReason.status).toBe(422);
    expect(noReason.html).toContain('Say why, in a few words.');

    const res = await b.post(`${APP}/account/operator/suspend`, {
      _csrf: csrf(page),
      id: member.identityId,
      reason: 'Reported takeover, ticket 42',
    });
    expect(res.status).toBe(303);
    page = await open(b, new URL(res.location!).pathname + new URL(res.location!).search);
    expect(page.html).toContain('Account suspended.');
    expect(page.html).toContain('Reinstate account');
    expect(page.html).toContain('Reported takeover, ticket 42');

    // Their account centre session is over, and they can't sign in again.
    const after = await theirs.get(`${APP}/account`);
    expect(after.status).toBe(303);
    const [s] = await sql(
      `SELECT count(*)::int AS live FROM auth_session WHERE identity_id = $1 AND revoked_at IS NULL`,
      [member.identityId],
    );
    expect(s!.live).toBe(0);
    expect(outbox.noticesTo(member.email).map((n) => n.subject)).toContain(
      'Your account has been suspended',
    );

    const back = await b.post(`${APP}/account/operator/reinstate`, {
      _csrf: csrf(page),
      id: member.identityId,
      reason: 'Owner confirmed by phone',
    });
    expect(back.status).toBe(303);
    const [i] = await sql(`SELECT status FROM identity WHERE id = $1`, [member.identityId]);
    expect(i!.status).toBe('active');
    await passwordSignIn(member); // signs in again

    const events = await sql(
      `SELECT kind, detail FROM auth_event WHERE identity_id = $1
          AND kind IN ('identity_suspended', 'identity_reinstated') ORDER BY occurred_at`,
      [member.identityId],
    );
    expect(events.map((e) => e.kind)).toEqual(['identity_suspended', 'identity_reinstated']);
    // The member sees it, without the operator's reason.
    const activity = await open(await passwordSignIn(member), '/account/activity');
    expect(activity.html).toContain('Account suspended by support');
    expect(activity.html).not.toContain('ticket 42');
  });

  it('signs an account out everywhere, and it can sign in again', async () => {
    const { b } = await operator();
    const member = await createMember();
    await passwordSignIn(member);
    await passwordSignIn(member);
    const page = await open(b, `/account/operator/identity?id=${member.identityId}`);
    const res = await b.post(`${APP}/account/operator/sign-out`, {
      _csrf: csrf(page),
      id: member.identityId,
      reason: 'Lost phone',
    });
    expect(res.status).toBe(303);
    const sessions = await sql(`SELECT revoke_reason FROM auth_session WHERE identity_id = $1`, [
      member.identityId,
    ]);
    expect(sessions.length).toBeGreaterThanOrEqual(2);
    expect(sessions.every((r) => r.revoke_reason === 'operator')).toBe(true);
    await passwordSignIn(member);
  });

  it('won’t change the operator’s own account', async () => {
    const { m, b } = await operator();
    const page = await open(b, `/account/operator/identity?id=${m.identityId}`);
    expect(page.html).not.toContain('Suspend account');
    const res = await b.post(`${APP}/account/operator/suspend`, {
      _csrf: csrf(page),
      id: m.identityId,
      reason: 'testing',
    });
    expect(res.status).toBe(422);
    const [i] = await sql(`SELECT status FROM identity WHERE id = $1`, [m.identityId]);
    expect(i!.status).toBe('active');
  });

  it('asks for the passkey again when the sign-in is over 10 minutes old', async () => {
    const { b, key } = await operator();
    const member = await createMember();
    const page = await open(b, `/account/operator/identity?id=${member.identityId}`);
    // Make the account session's sign-in 11 minutes old.
    const sessions = app.get(AccountSessions);
    const cookie = b.cookie('ea_account')!;
    const id = decodeURIComponent(cookie).split('.')[0]!;
    const s = (await sessions.get(id))!;
    await sessions.refresh(s, { ...s, authTime: s.authTime - 11 * 60 });

    const res = await b.post(`${APP}/account/operator/sign-out`, {
      _csrf: csrf(page),
      id: member.identityId,
      reason: 'Lost phone',
    });
    expect(res.status).toBe(401);
    expect(res.html).toContain('in the last 10 minutes');
    const again = await confirmWithPasskey(b, res, key);
    expect(again.status).toBe(200);
    expect(again.html).toContain(member.email);
  });
});

describe('The operator script', () => {
  it('refuses an address no active account has, and lists who is an operator', async () => {
    expect(() => operatorScript('grant', 'nobody-at-all@example.com', 'x')).toThrow();
    const m = await createMember();
    operatorScript('grant', m.email, 'support');
    expect(operatorScript('grant', m.email, 'support')).toContain('already an operator');
    expect(operatorScript('list')).toContain(m.identityId);
  });

  it('ends with the account: closing it revokes the grant', async () => {
    const m = await createMember();
    operatorScript('grant', m.email, 'support');
    await sql(`UPDATE identity SET status = 'closed' WHERE id = $1`, [m.identityId]);
    const [g] = await sql(`SELECT revoke_note FROM operator WHERE identity_id = $1`, [
      m.identityId,
    ]);
    expect(g!.revoke_note).toBe('identity closed');
  });

  it('can’t be done by the application’s own database role', async () => {
    const m = await createMember();
    await expect(
      sql(`INSERT INTO operator (identity_id, grant_note) VALUES ($1, 'x')`, [m.identityId]),
    ).rejects.toThrow(/permission denied/);
    await expect(sql(`UPDATE operator_action SET reason = 'x'`)).rejects.toThrow(
      /permission denied/,
    );
    await expect(sql(`DELETE FROM operator_action`)).rejects.toThrow(/permission denied/);
  });
});
