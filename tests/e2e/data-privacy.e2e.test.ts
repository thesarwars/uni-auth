import type { NestFastifyApplication } from '@nestjs/platform-fastify';
import { afterAll, beforeAll, describe, expect, it, vi } from 'vitest';
import { FRESH_SECONDS } from '../../src/account/account.controller';
import { Outbox } from '../../src/delivery/outbox';
import { AccountDeletions } from '../../src/lifecycle/account-deletions';
import { startApp } from '../support/app';
import {
  APP,
  HYDRA,
  HYDRA_ADMIN,
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
 * Data and privacy (account-plan.md part 6): downloading a copy of one's data, deleting the
 * account with a 14-day grace period that signing in cancels, and Linked apps - Google and Apple,
 * and the apps using Entity, each of whose access can be removed.
 */

let app: NestFastifyApplication;
let outbox: Outbox;
let deletions: AccountDeletions;

beforeAll(async () => {
  app = await startApp();
  outbox = app.get(Outbox);
  deletions = app.get(AccountDeletions);
});
afterAll(async () => {
  await app?.close();
  await closeMembers();
});

const DAY = 24 * 60 * 60 * 1000;
const csrf = (page: Hop): string => /name="_csrf" value="([^"]+)"/.exec(page.html)![1]!;
const open = async (b: Browser, path: string): Promise<Hop> =>
  (await b.follow(`${APP}${path}`)).hop;

/** Signs in to the account centre with the password, in `b` (a fresh browser by default). */
async function accountSignIn(m: Member, b: Browser = browser()): Promise<Browser> {
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

/** Signs in to GSN web; returns the browser and GSN's tokens. */
async function gsnSignIn(m: Member, b: Browser = browser()) {
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
  const { url } = await b.follow(page.location!);
  const code = new URL(url).searchParams.get('code')!;
  const tokens = await exchange(code, verifier);
  expect(tokens.status).toBe(200);
  return { b, tokens: tokens.body };
}

const refresh = (token: string) =>
  fetch(`${HYDRA}/oauth2/token`, {
    method: 'POST',
    headers: { 'content-type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({
      grant_type: 'refresh_token',
      client_id: 'gsn-web',
      refresh_token: token,
    }).toString(),
  });

const events = (identityId: string, kind: string) =>
  sql('SELECT * FROM auth_event WHERE identity_id = $1 AND kind = $2', [identityId, kind]);

/** A stale sign-in: more than ten minutes old. */
async function stale<T>(work: () => Promise<T>): Promise<T> {
  vi.useFakeTimers({ toFake: ['Date'], now: Date.now() + (FRESH_SECONDS + 60) * 1000 });
  try {
    return await work();
  } finally {
    vi.useRealTimers();
  }
}

describe('Data & privacy', () => {
  it('is in the menu, with the download, the other apps, and deleting the account', async () => {
    const b = await accountSignIn(await createMember());
    const page = await open(b, '/account/privacy');
    expect(page.status).toBe(200);
    expect(page.html).toContain('<h1 id="title">Data &amp; privacy</h1>');
    expect(page.html).toContain('href="/account/apps"');
    expect(page.html).toContain('href="/account/privacy" aria-current="page"');
    expect(page.html).toContain('Download your data');
    // GSN keeps its own data; the row says what, and goes to the app.
    expect(page.html).toContain('Go Style Network');
    expect(page.html).toContain('Profile, orders, bookings and posts');
    expect(page.html).toContain('You can cancel within 14 days by signing in.');
    expect(page.html).toContain('<dialog id="delete-dialog"');
  });

  it('downloads everything held about the member, and nothing secret', async () => {
    const m = await createMember();
    const b = await accountSignIn(m);
    const page = await open(b, '/account/privacy');
    const res = await b.post(`${APP}/account/privacy/download`, { _csrf: csrf(page) });
    expect(res.status).toBe(200);
    expect(res.headers.get('content-type')).toMatch(/^application\/json/);
    expect(res.headers.get('content-disposition')).toMatch(
      /^attachment; filename="entity-auth-account-data-\d{4}-\d{2}-\d{2}\.json"$/,
    );
    expect(res.headers.get('cache-control')).toBe('no-store');

    const data = JSON.parse(res.html);
    expect(data.format).toBe(1);
    expect(data.account.id).toBe(m.identityId);
    expect(data.email_addresses_and_phone_numbers).toEqual([
      expect.objectContaining({ kind: 'email', value: m.email, primary: true }),
    ]);
    expect(data.sign_in_methods).toEqual([expect.objectContaining({ method: 'password' })]);
    expect(data.sessions.length).toBeGreaterThan(0);
    expect(data.security_activity).toContainEqual(
      expect.objectContaining({ event: 'sign_in', outcome: 'success' }),
    );
    expect(data.apps).toContainEqual(expect.objectContaining({ app: 'entity-auth-account' }));
    // No password hash, in any field.
    expect(res.html).not.toMatch(/scrypt\$|secret|ciphertext|public_key/);

    expect(await events(m.identityId, 'export_downloaded')).toHaveLength(1);
    expect(outbox.noticesTo(m.email).map((n) => n.subject)).toContain(
      'A copy of your account data was downloaded',
    );
  });

  it("asks to confirm it's you first, then returns to the download", async () => {
    const m = await createMember();
    const b = await accountSignIn(m);
    const page = await open(b, '/account/privacy');
    const res = await stale(() => b.post(`${APP}/account/privacy/download`, { _csrf: csrf(page) }));
    expect(res.status).toBe(303);
    expect(new URL(res.location!).searchParams.get('prompt')).toBe('login');
    let confirm = (await b.follow(res.location!)).hop;
    expect(confirm.html).toContain('Confirm it&#39;s you');
    confirm = await b.post(`${APP}/login`, {
      ...formFields(confirm.html),
      action: 'password',
      password: m.password,
    });
    const back = (await b.follow(confirm.location!)).hop;
    expect(back.html).toContain('<h1 id="title">Download your data</h1>');
    const file = await b.post(`${APP}/account/privacy/download`, { _csrf: csrf(back) });
    expect(JSON.parse(file.html).account.id).toBe(m.identityId);
  });

  it('allows five downloads an hour', async () => {
    const m = await createMember();
    const b = await accountSignIn(m);
    const page = await open(b, '/account/privacy');
    for (let i = 0; i < 5; i += 1) {
      expect((await b.post(`${APP}/account/privacy/download`, { _csrf: csrf(page) })).status).toBe(
        200,
      );
    }
    const sixth = await b.post(`${APP}/account/privacy/download`, { _csrf: csrf(page) });
    expect(sixth.status).toBe(429);
    expect(sixth.html).toContain('You can download your data 5 times an hour.');
  });
});

describe('deleting the account', () => {
  it('signs the member out everywhere, then erases the identity 14 days later', async () => {
    const m = await createMember();
    const gsn = await gsnSignIn(m);
    const b = await accountSignIn(m);
    const page = await open(b, '/account/privacy/delete');
    expect(page.html).toContain('Delete your entity-auth account?');

    const res = await b.post(`${APP}/account/privacy/delete`, { _csrf: csrf(page) });
    expect(res.status).toBe(200);
    expect(res.html).toContain('Your account will be deleted');

    const [d] = await sql(
      `SELECT requested_at, scheduled_for, cancelled_at, completed_at FROM account_deletion
        WHERE identity_id = $1`,
      [m.identityId],
    );
    expect(d!.scheduled_for.getTime() - d!.requested_at.getTime()).toBe(14 * DAY);
    expect(
      await sql(`SELECT 1 FROM auth_session WHERE identity_id = $1 AND revoked_at IS NULL`, [
        m.identityId,
      ]),
    ).toHaveLength(0);
    expect(
      await sql(
        `SELECT 1 FROM auth_session WHERE identity_id = $1 AND revoke_reason = 'deletion_requested'`,
        [m.identityId],
      ),
    ).toHaveLength(2);
    expect(await events(m.identityId, 'deletion_requested')).toHaveLength(1);
    expect(outbox.noticesTo(m.email).map((n) => n.subject)).toContain(
      'Your account will be deleted',
    );
    // Signed out of the account centre, and GSN's refresh token no longer works.
    expect((await b.get(`${APP}/account`)).status).toBe(303);
    expect((await refresh(gsn.tokens.refresh_token)).ok).toBe(false);

    // Not yet: nothing happens before the 14 days are up.
    await deletions.run(new Date(Date.now() + 13 * DAY));
    expect(
      (await sql('SELECT status FROM identity WHERE id = $1', [m.identityId]))[0]!.status,
    ).toBe('active');

    await deletions.run(new Date(Date.now() + 15 * DAY));
    const [i] = await sql('SELECT status, erased_at FROM identity WHERE id = $1', [m.identityId]);
    expect(i!.status).toBe('closed');
    expect(i!.erased_at).not.toBeNull();
    expect(
      (
        await sql('SELECT completed_at FROM account_deletion WHERE identity_id = $1', [
          m.identityId,
        ])
      )[0]!.completed_at,
    ).not.toBeNull();
    // GSN is told, as for any erasure.
    const told = await sql('SELECT event FROM identity_notice WHERE identity_id = $1', [
      m.identityId,
    ]);
    expect(told.map((n) => n.event).sort()).toEqual(['closed', 'erased']);
    // The address is gone.
    expect(
      await sql('SELECT 1 FROM identity_identifier WHERE identity_id = $1 AND value IS NOT NULL', [
        m.identityId,
      ]),
    ).toHaveLength(0);
  });

  it('is cancelled by signing in again within the 14 days', async () => {
    const m = await createMember();
    const b = await accountSignIn(m);
    const page = await open(b, '/account/privacy');
    await b.post(`${APP}/account/privacy/delete`, { _csrf: csrf(page) });

    const again = await accountSignIn(m);
    expect((await open(again, '/account')).status).toBe(200);
    const [d] = await sql('SELECT cancelled_at FROM account_deletion WHERE identity_id = $1', [
      m.identityId,
    ]);
    expect(d!.cancelled_at).not.toBeNull();
    expect(await events(m.identityId, 'deletion_cancelled')).toHaveLength(1);
    expect(outbox.noticesTo(m.email).map((n) => n.subject)).toContain(
      'Your account is no longer being deleted',
    );
    const activity = await open(again, '/account/activity');
    expect(activity.html).toContain('Account deletion cancelled by signing in');

    await deletions.run(new Date(Date.now() + 15 * DAY));
    expect(
      (await sql('SELECT status FROM identity WHERE id = $1', [m.identityId]))[0]!.status,
    ).toBe('active');
  });

  it("asks to confirm it's you before deleting", async () => {
    const m = await createMember();
    const b = await accountSignIn(m);
    const page = await open(b, '/account/privacy');
    const res = await stale(() => b.post(`${APP}/account/privacy/delete`, { _csrf: csrf(page) }));
    expect(res.status).toBe(303);
    expect(new URL(res.location!).searchParams.get('prompt')).toBe('login');
    expect(
      await sql('SELECT 1 FROM account_deletion WHERE identity_id = $1', [m.identityId]),
    ).toHaveLength(0);
  });
});

describe('Linked apps', () => {
  it("lists the apps the member uses, and removes one's access", async () => {
    const m = await createMember();
    const { b, tokens } = await gsnSignIn(m);
    // The account centre, by single sign-on in the same browser.
    expect((await open(b, '/account')).status).toBe(200);

    const list = await open(b, '/account/apps');
    expect(list.html).toContain('<h1 id="title">Linked apps</h1>');
    expect(list.html).toContain('Go Style Network');
    expect(list.html).toContain('Signed in since');
    // Entity's own account centre is not an app to remove.
    expect(list.html).not.toContain('entity-auth account');

    const detail = await open(b, '/account/apps/app?id=gsn');
    expect(detail.html).toContain('Keep you signed in');
    const res = await b.post(`${APP}/account/apps/remove`, { _csrf: csrf(detail), id: 'gsn' });
    expect(res.status).toBe(303);
    expect(new URL(res.location!, APP).pathname + new URL(res.location!, APP).search).toBe(
      '/account/apps?done=access_removed',
    );

    // GSN's tokens are revoked; the account centre is still signed in.
    expect((await refresh(tokens.refresh_token)).ok).toBe(false);
    const consents = (await (
      await fetch(`${HYDRA_ADMIN}/admin/oauth2/auth/sessions/consent?subject=${m.identityId}`)
    ).json()) as { consent_request: { client: { client_id: string } } }[];
    expect(consents.map((c) => c.consent_request.client.client_id)).not.toContain('gsn-web');
    expect(await events(m.identityId, 'consent_revoked')).toHaveLength(1);
    const after = await open(b, '/account/apps');
    expect(after.status).toBe(200);
    expect(after.html).not.toContain('Signed in since');
  });

  it('unlinks Google, keeping this device signed in', async () => {
    const m = await createMember();
    await sql(
      `INSERT INTO credential (identity_id, kind, provider_subject, provider_email, provider_email_verified)
       VALUES ($1, 'oauth_google', $2, $3, true)`,
      [m.identityId, `google-${m.identityId}`, m.email],
    );
    const b = await accountSignIn(m);
    const list = await open(b, '/account/apps');
    expect(list.html).toContain('Google');
    expect(list.html).toContain('name="provider" value="google"');

    const res = await b.post(`${APP}/account/apps/unlink`, {
      _csrf: csrf(list),
      provider: 'google',
    });
    expect(res.status).toBe(303);
    expect(new URL(res.location!, APP).pathname + new URL(res.location!, APP).search).toBe(
      '/account/apps?done=unlinked',
    );
    expect(
      await sql(
        `SELECT 1 FROM credential WHERE identity_id = $1 AND kind = 'oauth_google' AND revoked_at IS NULL`,
        [m.identityId],
      ),
    ).toHaveLength(0);
    const after = await open(b, '/account/apps');
    expect(after.status).toBe(200);
    expect(after.html).toContain('Not linked. Sign in with Google to link it.');
    expect(outbox.noticesTo(m.email).map((n) => n.subject)).toContain(
      'Google was unlinked from your account',
    );
  });
});
