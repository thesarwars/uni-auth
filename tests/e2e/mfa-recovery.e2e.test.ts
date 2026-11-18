import type { NestFastifyApplication } from '@nestjs/platform-fastify';
import { createServer, type Server } from 'node:http';
import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import { Outbox } from '../../src/delivery/outbox';
import { MfaRecoveries } from '../../src/recovery/mfa-recoveries';
import { codeAt, fromBase32, stepAt } from '../../src/two-step/totp';
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
 * Account recovery without a second factor (account-plan.md part 7): a member who can't use any
 * 2-step method asks, after their password, for 2-step verification to be removed. Every address
 * hears at once, with a cancel link; after 7 days it goes ahead - straight away for ordinary
 * accounts, only once GSN's administrator approves for accounts that handle money.
 *
 * GSN is played by a listener here: it answers each request with `review`, and each decision
 * with whatever `decisions` holds.
 */

const PORT = 4781;
const DAY = 24 * 60 * 60 * 1000;

let app: NestFastifyApplication;
let outbox: Outbox;
let jobs: MfaRecoveries;
let listener: Server;

/** What the fake GSN answers and remembers. */
const gsn = {
  review: 'not_required' as 'required' | 'not_required',
  up: true,
  registered: new Map<string, { sub: string; scopes: string[] }>(),
  decisions: new Map<string, 'pending' | 'approved' | 'rejected'>(),
  withdrawn: new Set<string>(),
};

const scopesOf = (auth: string | undefined): string[] => {
  const payload = (auth ?? '').replace(/^Bearer /, '').split('.')[1] ?? '';
  try {
    const c = JSON.parse(Buffer.from(payload, 'base64url').toString()) as { scp?: string[] };
    return c.scp ?? [];
  } catch {
    return [];
  }
};

beforeAll(async () => {
  listener = createServer((req, res) => {
    let body = '';
    req.on('data', (c: Buffer) => (body += c.toString()));
    req.on('end', () => {
      if (!gsn.up) {
        res.writeHead(503).end();
        return;
      }
      const url = new URL(req.url!, `http://127.0.0.1:${PORT}`);
      const parts = url.pathname.split('/').filter(Boolean); // recovery-requests, id, withdraw
      if (req.method === 'POST' && parts.length === 1) {
        const r = JSON.parse(body) as { id: string; sub: string };
        gsn.registered.set(r.id, { sub: r.sub, scopes: scopesOf(req.headers.authorization) });
        if (gsn.review === 'required') gsn.decisions.set(r.id, 'pending');
        res.writeHead(200, { 'content-type': 'application/json' });
        res.end(JSON.stringify({ review: gsn.review }));
        return;
      }
      if (req.method === 'GET' && parts.length === 2) {
        res.writeHead(200, { 'content-type': 'application/json' });
        res.end(JSON.stringify({ decision: gsn.decisions.get(parts[1]!) ?? 'pending' }));
        return;
      }
      if (req.method === 'POST' && parts[2] === 'withdraw') {
        gsn.withdrawn.add(parts[1]!);
        res.writeHead(204).end();
        return;
      }
      res.writeHead(404).end();
    });
  });
  await new Promise<void>((r) => listener.listen(PORT, '127.0.0.1', r));
  app = await startApp();
  outbox = app.get(Outbox);
  jobs = app.get(MfaRecoveries);
});
afterAll(async () => {
  await app?.close();
  await new Promise((r) => listener?.close(r));
  await closeMembers();
});
beforeEach(() => {
  gsn.review = 'not_required';
  gsn.up = true;
});

const csrf = (page: Hop): string => /name="_csrf" value="([^"]+)"/.exec(page.html)![1]!;
const challengeOf = (page: Hop): string =>
  decodeURIComponent(/login_challenge=([^"&]+)/.exec(page.html)![1]!);

/** A member with 2-step verification on (the authenticator app); returns its seed. */
async function withTwoStep(m: Member): Promise<Buffer> {
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
  await b.follow(page.location!);
  const setup = (await b.follow(`${APP}/account/two-step/setup`)).hop;
  const seed = fromBase32(/aria-label="Setup key">([A-Z2-7 ]+)</.exec(setup.html)![1]!);
  const res = await b.post(`${APP}/account/two-step/setup`, {
    _csrf: csrf(setup),
    code: codeAt(seed, stepAt(Date.now())),
  });
  expect(res.html).toContain('Save your recovery codes');
  return seed;
}

/** Signs in to GSN with the password, up to the second step's screen. */
async function atSecondStep(m: Member, b: Browser = browser()): Promise<{ b: Browser; page: Hop }> {
  let page = (await b.follow(authorizeUrl(pkce().challenge))).hop;
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
  page = (await b.follow(page.location!)).hop;
  expect(page.html).toContain('<h1 id="title">2-step verification</h1>');
  return { b, page };
}

/** From the second step: "Can't use any of these?", then "Ask to remove it". */
async function ask(m: Member): Promise<{ b: Browser; page: Hop; request: string }> {
  const { b, page: step } = await atSecondStep(m);
  expect(step.html).toContain('Can’t use any of these?');
  const help = (
    await b.follow(
      `${APP}/login/two-step/help?login_challenge=${encodeURIComponent(challengeOf(step))}`,
    )
  ).hop;
  expect(help.status).toBe(200);
  expect(help.html).toContain('Can’t use 2-step verification?');
  const page = await b.post(`${APP}/login/two-step/help`, {
    _csrf: csrf(help),
    login_challenge: challengeOf(help),
  });
  expect(page.status).toBe(200);
  expect(page.html).toContain('<h1 id="title">Request sent</h1>');
  const [r] = await sql(
    `SELECT id FROM mfa_recovery WHERE identity_id = $1 ORDER BY requested_at DESC LIMIT 1`,
    [m.identityId],
  );
  return { b, page, request: r!.id };
}

const twoStepOn = async (m: Member) =>
  (
    await sql(
      `SELECT 1 FROM credential WHERE identity_id = $1 AND kind = 'totp' AND revoked_at IS NULL`,
      [m.identityId],
    )
  ).length === 1;

const events = async (m: Member, kind: string) =>
  sql('SELECT detail FROM auth_event WHERE identity_id = $1 AND kind = $2', [m.identityId, kind]);

const subjects = (m: Member) => outbox.noticesTo(m.email).map((n) => n.subject);

const cancelLink = (m: Member): string => {
  const n = outbox
    .noticesTo(m.email)
    .reverse()
    .find((x) => x.subject === 'Someone asked to remove 2-step verification')!;
  return /Cancel this request: (\S+)/.exec(n.text)![1]!;
};

describe('asking', () => {
  it('needs the password first, then tells every address, with a link to cancel', async () => {
    const m = await createMember();
    await withTwoStep(m);
    // A second verified address, which hears too.
    const other = `second-${m.identityId}@example.com`;
    await sql(
      `INSERT INTO identity_identifier (identity_id, kind, value, verified_at, is_primary)
       VALUES ($1, 'email', $2, now(), false)`,
      [m.identityId, other],
    );

    const { page, request } = await ask(m);
    expect(page.html).toContain('If nobody cancels it, 2-step verification is removed on');
    expect(subjects(m)).toContain('Someone asked to remove 2-step verification');
    expect(outbox.noticesTo(other).map((n) => n.subject)).toContain(
      'Someone asked to remove 2-step verification',
    );
    expect(cancelLink(m)).toMatch(/\/recovery\/cancel\?token=[A-Za-z0-9_-]{43}$/);
    expect(await events(m, 'mfa_recovery_requested')).toEqual([{ detail: { request } }]);

    // Registered with GSN at once, with a token for identity:recovery only.
    expect(gsn.registered.get(request)).toEqual({
      sub: m.identityId,
      scopes: ['identity:recovery'],
    });
    const [r] = await sql(
      'SELECT review, eligible_at - requested_at AS wait FROM mfa_recovery WHERE id = $1',
      [request],
    );
    expect(r!.review).toBe('not_required');
    expect(r!.wait).toEqual({ days: 7 });
  });

  it('asking again shows the request already waiting', async () => {
    const m = await createMember();
    await withTwoStep(m);
    await ask(m);
    const { b, page: step } = await atSecondStep(m);
    const again = (
      await b.follow(
        `${APP}/login/two-step/help?login_challenge=${encodeURIComponent(challengeOf(step))}`,
      )
    ).hop;
    expect(again.html).toContain('You’ve already asked');
    expect(
      await sql('SELECT 1 FROM mfa_recovery WHERE identity_id = $1', [m.identityId]),
    ).toHaveLength(1);
  });
});

describe('an ordinary account', () => {
  it('loses 2-step verification after 7 days, and the password alone signs in', async () => {
    const m = await createMember();
    await withTwoStep(m);
    const { request } = await ask(m);

    await jobs.run(new Date(Date.now() + 6 * DAY));
    expect(await twoStepOn(m)).toBe(true);

    await jobs.run(new Date(Date.now() + 7 * DAY + 60_000));
    expect(await twoStepOn(m)).toBe(false);
    const [r] = await sql('SELECT completed_at FROM mfa_recovery WHERE id = $1', [request]);
    expect(r!.completed_at).not.toBeNull();
    expect(
      await sql(
        `SELECT revoke_reason FROM credential WHERE identity_id = $1 AND kind IN ('totp', 'recovery_codes')`,
        [m.identityId],
      ),
    ).toEqual([{ revoke_reason: 'account_recovery' }, { revoke_reason: 'account_recovery' }]);
    expect(await events(m, 'mfa_recovery_completed')).toHaveLength(1);
    expect(subjects(m)).toContain('2-step verification was removed');

    // The password alone now reaches the app.
    const b = browser();
    let page = (await b.follow(authorizeUrl(pkce().challenge))).hop;
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
    expect(page.location).not.toMatch(/two-step/);
  });

  it('never goes ahead while GSN has not answered', async () => {
    const m = await createMember();
    await withTwoStep(m);
    gsn.up = false;
    const { page, request } = await ask(m);
    // Not knowing, the page promises no less than may happen.
    expect(page.html).toContain('Our team will check the request.');
    await jobs.run(new Date(Date.now() + 8 * DAY));
    expect(await twoStepOn(m)).toBe(true);
    // GSN answers at the next run; then the wait is what counts.
    gsn.up = true;
    await jobs.run(new Date(Date.now() + 8 * DAY));
    expect(gsn.registered.has(request)).toBe(true);
    expect(await twoStepOn(m)).toBe(false);
  });
});

describe('an account that handles money', () => {
  it('waits for the administrator, then goes ahead once approved', async () => {
    const m = await createMember();
    await withTwoStep(m);
    gsn.review = 'required';
    const { page, request } = await ask(m);
    expect(page.html).toContain('Our team will check the request.');

    await jobs.run(new Date(Date.now() + 8 * DAY));
    expect(await twoStepOn(m)).toBe(true);

    gsn.decisions.set(request, 'approved');
    await jobs.run(new Date(Date.now() + 6 * DAY));
    // Approved, but the 7 days still apply.
    expect(await twoStepOn(m)).toBe(true);
    await jobs.run(new Date(Date.now() + 8 * DAY));
    expect(await twoStepOn(m)).toBe(false);
  });

  it('stays on when the administrator refuses, and the member hears', async () => {
    const m = await createMember();
    await withTwoStep(m);
    gsn.review = 'required';
    const { request } = await ask(m);
    gsn.decisions.set(request, 'rejected');
    await jobs.run(new Date(Date.now() + 8 * DAY));
    expect(await twoStepOn(m)).toBe(true);
    const [r] = await sql('SELECT decision FROM mfa_recovery WHERE id = $1', [request]);
    expect(r!.decision).toBe('rejected');
    expect(await events(m, 'mfa_recovery_rejected')).toHaveLength(1);
    expect(subjects(m)).toContain("The request to remove 2-step verification wasn't approved");
  });
});

describe('cancelling', () => {
  it('by the link: opening it changes nothing, confirming cancels, and GSN is told', async () => {
    const m = await createMember();
    await withTwoStep(m);
    gsn.review = 'required';
    const { request } = await ask(m);

    const b = browser();
    const confirm = (await b.follow(cancelLink(m))).hop;
    expect(confirm.status).toBe(200);
    expect(confirm.html).toContain('Cancel the request?');
    const [still] = await sql('SELECT cancelled_at FROM mfa_recovery WHERE id = $1', [request]);
    expect(still!.cancelled_at).toBeNull();

    const token = /name="token" value="([^"]+)"/.exec(confirm.html)![1]!;
    const done = await b.post(`${APP}/recovery/cancel`, { _csrf: csrf(confirm), token });
    expect(done.html).toContain('Request cancelled');
    expect(await events(m, 'mfa_recovery_cancelled')).toEqual([
      { detail: { request, by: 'link' } },
    ]);
    expect(subjects(m)).toContain('The request to remove 2-step verification was cancelled');

    gsn.decisions.set(request, 'approved');
    await jobs.run(new Date(Date.now() + 8 * DAY));
    expect(await twoStepOn(m)).toBe(true);
    expect(gsn.withdrawn.has(request)).toBe(true);

    // The link again: nothing left to cancel.
    expect((await browser().follow(cancelLink(m))).hop.html).toContain(
      'This request was already cancelled.',
    );
  });

  it('by signing in with the authenticator app', async () => {
    const m = await createMember();
    const seed = await withTwoStep(m);
    const { request } = await ask(m);

    const { b, page } = await atSecondStep(m);
    const res = await b.post(`${APP}/login/two-step`, {
      _csrf: csrf(page),
      login_challenge: challengeOf(page),
      mode: 'app',
      code: codeAt(seed, stepAt(Date.now()) + 1),
    });
    expect(res.status).toBe(303);
    const [r] = await sql('SELECT cancelled_by FROM mfa_recovery WHERE id = $1', [request]);
    expect(r!.cancelled_by).toBe('sign_in');
    await jobs.run(new Date(Date.now() + 8 * DAY));
    expect(await twoStepOn(m)).toBe(true);
  });

  it('an unknown link says so', async () => {
    const page = (await browser().follow(`${APP}/recovery/cancel?token=${'A'.repeat(43)}`)).hop;
    expect(page.status).toBe(404);
    expect(page.html).toContain('This link isn’t valid.');
  });
});
