import type { NestFastifyApplication } from '@nestjs/platform-fastify';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { Outbox } from '../../src/delivery/outbox';
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
 * Part 4's codes (auth-plan.md sections 7.2 and 7.3): sign-in by a code to the identifier, and
 * recovery by code to a new password - every state the screens must handle, with the caps
 * enforced by the database.
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

interface Flow {
  b: Browser;
  verifier: string;
  page: Hop;
}

async function start(b: Browser = browser()): Promise<Flow> {
  const { verifier, challenge } = pkce();
  const { url, hop } = await b.follow(authorizeUrl(challenge));
  expect(url.startsWith(`${APP}/login?`)).toBe(true);
  return { b, verifier, page: hop };
}

async function post(f: Flow, fields: Record<string, string>): Promise<Hop> {
  f.page = await f.b.post(`${APP}/login`, { ...formFields(f.page.html), ...fields });
  return f.page;
}

const identify = (f: Flow, identifier: string) => post(f, { action: 'identify', identifier });
const sendCode = (f: Flow, purpose: 'sign_in' | 'recovery') =>
  post(f, { action: 'send_code', purpose });

function otpId(page: Hop): string {
  return /name="otp_id" value="([^"]+)"/.exec(page.html)![1]!;
}

/** Enters a code on the code screen, keeping the screen's own otp_id. */
async function enter(f: Flow, code: string): Promise<Hop> {
  return post(f, { action: 'verify_code', otp_id: otpId(f.page), code });
}

/** Follows a successful sign-in back to the client and exchanges the code for tokens. */
async function landed(f: Flow): Promise<Record<string, any>> {
  expect(f.page.status).toBe(303);
  const { url } = await f.b.follow(f.page.location!);
  const t = await exchange(new URL(url).searchParams.get('code')!, f.verifier);
  expect(t.status).toBe(200);
  return claims(t.body.access_token);
}

const codeFor = (to: string): string => outbox.last(to)!.code;

async function codeOnly(): Promise<Member> {
  return createMember({ password: null });
}

describe('sign-in by code', () => {
  it('sends a code to an account with no password, and the code signs in', async () => {
    const m = await codeOnly();
    const f = await start();
    const page = await identify(f, m.email);
    expect(page.status).toBe(200);
    expect(page.html).toContain('Enter your code');
    expect(page.html).toMatch(
      /We sent a 6-digit code to <strong>m•••@example\.com<\/strong> by email/,
    );
    expect(page.html).toContain('autocomplete="one-time-code"');

    await enter(f, codeFor(m.email));
    const at = await landed(f);
    expect(at.sub).toBe(m.identityId);
    expect(at.amr).toEqual(['otp']);

    const [s] = await sql('SELECT credential_id FROM auth_session WHERE sid = $1', [at.sid]);
    expect(s!.credential_id).toBeNull();
    const [e] = await sql(
      "SELECT detail FROM auth_event WHERE identity_id = $1 AND kind = 'sign_in' AND outcome = 'success'",
      [m.identityId],
    );
    expect(e!.detail).toEqual({ method: 'code', channel: 'email' });
  });

  it('offers a code instead of the password', async () => {
    const m = await createMember();
    const f = await start();
    const pw = await identify(f, m.email);
    expect(pw.html).toContain('Get a code by email instead');
    await sendCode(f, 'sign_in');
    await enter(f, codeFor(m.email));
    expect((await landed(f)).amr).toEqual(['otp']);
  });

  it('reaches a phone number over WhatsApp', async () => {
    const m = await codeOnly();
    const phone = `+4477009${String(Date.now()).slice(-5)}`;
    await sql(
      "INSERT INTO identity_identifier (identity_id, kind, value, verified_at) VALUES ($1, 'phone', $2, now())",
      [m.identityId, phone],
    );
    const f = await start();
    const page = await identify(
      f,
      phone.replace(/^\+44/, '+44 ').replace(/(\d{4})(\d+)$/, '$1 $2'),
    );
    expect(page.html).toContain(`•••• ${phone.slice(-4)}`);
    expect(page.html).toContain('by WhatsApp');
    expect(outbox.last(phone)!.channel).toBe('whatsapp');
    await enter(f, codeFor(phone));
    expect((await landed(f)).sub).toBe(m.identityId);
  });

  it('counts wrong codes, warns at two left, and still takes the right one inside the cap', async () => {
    const m = await codeOnly();
    const f = await start();
    await identify(f, m.email);
    const right = codeFor(m.email);
    const wrong = right === '000000' ? '111111' : '000000';

    const pages: string[] = [];
    for (let i = 0; i < 4; i++) {
      const p = await enter(f, wrong);
      expect(p.status).toBe(422);
      pages.push(p.html);
    }
    expect(pages[0]).toContain('That code is not right.');
    expect(pages[0]).not.toContain('left.');
    expect(pages[2]).toContain('2 attempts left.');
    expect(pages[3]).toContain('1 attempt left.');

    await enter(f, right);
    expect((await landed(f)).sub).toBe(m.identityId);
  });

  it('locks the address after five wrong codes, and no new code goes until it lifts', async () => {
    const m = await codeOnly();
    const f = await start();
    await identify(f, m.email);
    const wrong = codeFor(m.email) === '000000' ? '111111' : '000000';
    for (let i = 0; i < 4; i++) await enter(f, wrong);
    const fifth = await enter(f, wrong);
    expect(fifth.status).toBe(429);
    expect(fifth.html).toContain('Too many wrong codes');
    expect(fifth.html).toMatch(/for (29|30) minutes/);
    expect(fifth.html).not.toContain('Send the code again');

    // A new sign-in cannot get a fresh code to the same address either.
    const g = await start();
    const again = await identify(g, m.email);
    expect(again.status).toBe(429);
    expect(again.html).toContain('Too many wrong codes');

    const journal = await sql(
      "SELECT kind FROM auth_event WHERE identity_id = $1 AND outcome = 'failure' ORDER BY occurred_at, id",
      [m.identityId],
    );
    expect(journal.map((e) => e.kind)).toEqual([
      'sign_in',
      'sign_in',
      'sign_in',
      'sign_in',
      'lockout',
    ]);
  });

  it('resends a fresh code, and the old one stops working', async () => {
    const m = await codeOnly();
    const f = await start();
    await identify(f, m.email);
    const first = codeFor(m.email);
    await sendCode(f, 'sign_in');
    const second = codeFor(m.email);
    expect(outbox.count(m.email)).toBe(2);

    if (first !== second) {
      const stale = await enter(f, first);
      expect(stale.status).toBe(422);
    }
    await enter(f, second);
    expect((await landed(f)).sub).toBe(m.identityId);
  });

  it('stops at five codes to one address in an hour', async () => {
    const m = await codeOnly();
    const f = await start();
    await identify(f, m.email);
    for (let i = 0; i < 3; i++) await sendCode(f, 'sign_in');
    const g = await start();
    await identify(g, m.email);
    expect(outbox.count(m.email)).toBe(5);

    const sixth = await sendCode(g, 'sign_in');
    expect(sixth.status).toBe(429);
    expect(sixth.html).toContain("We've sent as many codes");
    expect(sixth.html).toMatch(/another in (59|60) minutes/);
    expect(outbox.count(m.email)).toBe(5);
  });

  it('refuses a code in any sign-in but the one that asked for it', async () => {
    const m = await codeOnly();
    const mine = await start();
    await identify(mine, m.email);
    const code = codeFor(m.email);
    const id = otpId(mine.page);

    const other = await start();
    await identify(other, m.email); // a second sign-in, its own code
    const res = await post(other, { action: 'verify_code', otp_id: id, code });
    expect(res.status).toBe(422);
    expect(res.html).toContain('That code has expired');

    // The code still works where it was sent.
    await enter(mine, code);
    expect(mine.page.status).toBe(303);
  });
});

describe('recovery', () => {
  it('resets the password by code, signs in, and ends every other session', async () => {
    const m = await createMember();
    // An existing session somewhere else.
    const elsewhere = await start();
    await identify(elsewhere, m.email);
    await post(elsewhere, { action: 'password', password: m.password });
    const old = await landed(elsewhere);

    const f = await start();
    await identify(f, m.email);
    const code = await sendCode(f, 'recovery');
    expect(code.html).toContain('Reset your password');
    const choose = await enter(f, codeFor(m.email));
    expect(choose.html).toContain('Choose a new password');
    expect(choose.html).toContain('At least 8 characters');
    expect(choose.html).toContain('autocomplete="new-password"');

    // Every rule that fails is named, on the same screen.
    const weak = await post(f, { action: 'new_password', password: 'short', confirm: 'short' });
    expect(weak.status).toBe(422);
    expect(weak.html).toContain('does not meet every rule');
    expect(weak.html).toMatch(/class="unmet">At least 8 characters/);
    expect(weak.html).toMatch(/class="unmet">One uppercase letter/);

    const mismatch = await post(f, {
      action: 'new_password',
      password: 'New-Password-1',
      confirm: 'New-Password-2',
    });
    expect(mismatch.html).toContain('do not match');

    await post(f, {
      action: 'new_password',
      password: 'New-Password-1',
      confirm: 'New-Password-1',
    });
    const at = await landed(f);
    expect(at.sub).toBe(m.identityId);

    const [was] = await sql('SELECT revoke_reason FROM auth_session WHERE sid = $1', [old.sid]);
    expect(was!.revoke_reason).toBe('password_reset');
    const [now] = await sql('SELECT revoked_at FROM auth_session WHERE sid = $1', [at.sid]);
    expect(now!.revoked_at).toBeNull();
    const creds = await sql(
      "SELECT revoke_reason FROM credential WHERE identity_id = $1 AND kind = 'password' ORDER BY created_at",
      [m.identityId],
    );
    expect(creds.map((c) => c.revoke_reason)).toEqual(['password_reset', null]);
    const events = await sql(
      "SELECT 1 FROM auth_event WHERE identity_id = $1 AND kind = 'password_reset' AND outcome = 'success'",
      [m.identityId],
    );
    expect(events).toHaveLength(1);

    // The old password no longer signs in; the new one does.
    const g = await start();
    await identify(g, m.email);
    expect((await post(g, { action: 'password', password: m.password })).status).toBe(422);
    await post(g, { action: 'password', password: 'New-Password-1' });
    expect((await landed(g)).sub).toBe(m.identityId);
  });

  it('is the way out of a password lockout, and lifts it', async () => {
    const m = await createMember();
    const f = await start();
    await identify(f, m.email);
    let page = f.page;
    for (let i = 0; i < 5; i++) page = await post(f, { action: 'password', password: 'wrong-one' });
    expect(page.status).toBe(429);
    expect(page.html).toContain('Reset password');

    await sendCode(f, 'recovery');
    await enter(f, codeFor(m.email));
    await post(f, {
      action: 'new_password',
      password: 'Fresh-Password-7',
      confirm: 'Fresh-Password-7',
    });
    expect((await landed(f)).sub).toBe(m.identityId);

    const g = await start();
    await identify(g, m.email);
    await post(g, { action: 'password', password: 'Fresh-Password-7' });
    expect(g.page.status).toBe(303);
  });

  it('refuses a reset ticket outside the sign-in that opened it', async () => {
    const m = await createMember();
    const f = await start();
    await identify(f, m.email);
    await sendCode(f, 'recovery');
    const choose = await enter(f, codeFor(m.email));
    const ticket = /name="ticket" value="([^"]+)"/.exec(choose.html)![1]!;

    const other = await start();
    await identify(other, m.email);
    const res = await post(other, {
      action: 'new_password',
      ticket,
      password: 'Stolen-Password-1',
      confirm: 'Stolen-Password-1',
    });
    expect(res.status).toBe(422);
    expect(res.html).toContain('Your reset took too long');
    const live = await sql(
      "SELECT 1 FROM credential WHERE identity_id = $1 AND kind = 'password' AND revoked_at IS NULL",
      [m.identityId],
    );
    expect(live).toHaveLength(1);
  });
});
