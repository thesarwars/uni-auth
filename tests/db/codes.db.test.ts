import { randomBytes } from 'node:crypto';
import { describe, expect, it } from 'vitest';
import {
  newIdentity,
  one,
  password,
  q,
  refused,
  rolledBack,
  session,
  sessionState,
} from '../support/db';

/**
 * One-time codes and password recovery (db/migrations/0002_one_time_codes.sql): the caps the
 * screens render, enforced where no caller can skip them.
 */

rolledBack();

const sha = () => randomBytes(32);

async function verifiedEmail(identityId: string, email: string): Promise<void> {
  await q(
    "INSERT INTO identity_identifier (identity_id, kind, value, verified_at) VALUES ($1, 'email', $2, now())",
    [identityId, email],
  );
}

async function issue(
  identityId: string | null,
  destination: string,
  purpose = 'sign_in',
  flow: Buffer = sha(),
): Promise<string> {
  return (
    await one<{ id: string }>(
      `INSERT INTO otp_challenge (identity_id, purpose, channel, destination, flow_hash, code_hash, code_salt, expires_at)
       VALUES ($1, $2, 'email', $3, $4, $5, $6, now() + interval '15 minutes') RETURNING id`,
      [identityId, purpose, destination, flow, sha(), randomBytes(16)],
    )
  ).id;
}

const issueSql = `INSERT INTO otp_challenge (identity_id, purpose, channel, destination, flow_hash, code_hash, code_salt, expires_at)
  VALUES ($1, 'sign_in', 'email', $2, $3, $4, $5, now() + interval '15 minutes')`;

const wrong = (id: string) =>
  one<{ status: string; locked_until: Date | null }>(
    'UPDATE otp_challenge SET attempt_count = attempt_count + 1 WHERE id = $1 RETURNING status, locked_until',
    [id],
  );

const resend = (id: string) =>
  q(
    'UPDATE otp_challenge SET code_hash = $2, code_salt = $3, resend_count = resend_count + 1 WHERE id = $1',
    [id, sha(), randomBytes(16)],
  );

describe('otp_challenge', () => {
  it('sends a sign-in code only to a verified identifier of an active identity', async () => {
    const a = await newIdentity();
    await q(
      "INSERT INTO identity_identifier (identity_id, kind, value) VALUES ($1, 'email', 'typed@example.com')",
      [a],
    );
    expect(
      await refused(issueSql, [a, 'typed@example.com', sha(), sha(), randomBytes(16)]),
    ).toMatch(/verified identifier of an active identity/);

    await verifiedEmail(a, 'ada@example.com');
    const b = await newIdentity();
    expect(await refused(issueSql, [b, 'ada@example.com', sha(), sha(), randomBytes(16)])).toMatch(
      /verified identifier of an active identity/,
    );
    expect(await refused(issueSql, [a, 'ADA@example.com', sha(), sha(), randomBytes(16)])).toMatch(
      /destination_shape/,
    );
    await issue(a, 'ada@example.com');

    await q("UPDATE identity SET status = 'suspended' WHERE id = $1", [a]);
    expect(await refused(issueSql, [a, 'ada@example.com', sha(), sha(), randomBytes(16)])).toMatch(
      /verified identifier of an active identity/,
    );
  });

  it('is born issued, lives at most fifteen minutes, and one is live per sign-in', async () => {
    const a = await newIdentity();
    await verifiedEmail(a, 'b@example.com');
    expect(
      await refused(
        `INSERT INTO otp_challenge (identity_id, purpose, channel, destination, flow_hash, code_hash, code_salt, expires_at, attempt_count)
         VALUES ($1, 'sign_in', 'email', 'b@example.com', $2, $3, $4, now() + interval '5 minutes', 1)`,
        [a, sha(), sha(), randomBytes(16)],
      ),
    ).toMatch(/born issued/);
    expect(
      await refused(
        `INSERT INTO otp_challenge (identity_id, purpose, channel, destination, flow_hash, code_hash, code_salt, expires_at)
         VALUES ($1, 'sign_in', 'email', 'b@example.com', $2, $3, $4, now() + interval '16 minutes')`,
        [a, sha(), sha(), randomBytes(16)],
      ),
    ).toMatch(/short_lived/);

    const flow = sha();
    await issue(a, 'b@example.com', 'sign_in', flow);
    expect(await refused(issueSql, [a, 'b@example.com', flow, sha(), randomBytes(16)])).toMatch(
      /one_live_key/,
    );
  });

  it('locks the challenge and the address on the fifth wrong attempt, for thirty minutes', async () => {
    const a = await newIdentity();
    await verifiedEmail(a, 'c@example.com');
    const id = await issue(a, 'c@example.com');
    for (let i = 0; i < 4; i++) expect((await wrong(id)).status).toBe('issued');
    const locked = await wrong(id);
    expect(locked.status).toBe('locked');
    const minutes = (locked.locked_until!.getTime() - Date.now()) / 60_000;
    expect(minutes).toBeGreaterThan(29);
    expect(minutes).toBeLessThanOrEqual(30.1);

    expect(await refused(issueSql, [a, 'c@example.com', sha(), sha(), randomBytes(16)])).toMatch(
      /locked out/,
    );
    expect(
      await refused('UPDATE otp_challenge SET locked_until = now() WHERE id = $1', [id]),
    ).toMatch(/set only by the attempt that trips it/);
    expect(
      await refused("UPDATE otp_challenge SET status = 'verified' WHERE id = $1", [id]),
    ).toMatch(/not a legal transition/);
  });

  it('verifies once, on one counted attempt, and is final after', async () => {
    const a = await newIdentity();
    await verifiedEmail(a, 'd@example.com');
    const id = await issue(a, 'd@example.com');
    expect(
      await refused("UPDATE otp_challenge SET status = 'verified' WHERE id = $1", [id]),
    ).toMatch(/one counted attempt/);
    const done = await one(
      "UPDATE otp_challenge SET status = 'verified', attempt_count = attempt_count + 1 WHERE id = $1 RETURNING consumed_at",
      [id],
    );
    expect(done.consumed_at).toBeInstanceOf(Date);
    expect(
      await refused('UPDATE otp_challenge SET attempt_count = attempt_count + 1 WHERE id = $1', [
        id,
      ]),
    ).toMatch(/final/);
  });

  it('issues a new code only by a counted resend, one at a time, three at most', async () => {
    const a = await newIdentity();
    await verifiedEmail(a, 'e@example.com');
    const id = await issue(a, 'e@example.com');
    expect(
      await refused('UPDATE otp_challenge SET code_hash = $2 WHERE id = $1', [id, sha()]),
    ).toMatch(/only by a counted resend/);
    expect(
      await refused('UPDATE otp_challenge SET code_hash = $2, resend_count = 2 WHERE id = $1', [
        id,
        sha(),
      ]),
    ).toMatch(/one resend at a time/);
    expect(await refused('UPDATE otp_challenge SET resend_count = 1 WHERE id = $1', [id])).toMatch(
      /issues a new code/,
    );
    for (let i = 0; i < 3; i++) await resend(id);
    const row = await one('SELECT last_resent_at FROM otp_challenge WHERE id = $1', [id]);
    expect(row.last_resent_at).toBeInstanceOf(Date);
    expect(
      await refused(
        'UPDATE otp_challenge SET code_hash = $2, code_salt = $3, resend_count = 4 WHERE id = $1',
        [id, sha(), randomBytes(16)],
      ),
    ).toMatch(/resends_bounded/);
    await wrong(id);
    expect(await refused('UPDATE otp_challenge SET attempt_count = 0 WHERE id = $1', [id])).toMatch(
      /only grow/,
    );
  });

  it('sends one address at most five codes in an hour, resends included', async () => {
    const a = await newIdentity();
    await verifiedEmail(a, 'f@example.com');
    const id = await issue(a, 'f@example.com', 'sign_in');
    await resend(id);
    await resend(id);
    await issue(a, 'f@example.com', 'recovery');
    await issue(a, 'f@example.com', 'sign_in');
    expect((await one("SELECT otp_sends_last_hour('F@example.com') AS n")).n).toBe('5');
    expect(await refused(issueSql, [a, 'f@example.com', sha(), sha(), randomBytes(16)])).toMatch(
      /five codes in the last hour/,
    );
    expect(
      await refused(
        'UPDATE otp_challenge SET code_hash = $2, code_salt = $3, resend_count = 3 WHERE id = $1',
        [id, sha(), randomBytes(16)],
      ),
    ).toMatch(/five codes in the last hour/);
  });

  it('keeps the send ledger append-only while its hour counts', async () => {
    const a = await newIdentity();
    await verifiedEmail(a, 'g@example.com');
    await issue(a, 'g@example.com');
    expect(await refused('UPDATE otp_send SET sent_at = now()')).toMatch(/permission denied/);
    expect(await refused('DELETE FROM otp_send')).toMatch(/long past or erased/);
    expect(await refused('DELETE FROM otp_challenge')).toMatch(/permission denied/);
  });
});

describe('signup codes', () => {
  it('go only to an address no identity holds verified, however it was typed', async () => {
    const a = await newIdentity();
    await verifiedEmail(a, 'taken@example.com');
    expect(
      await refused(
        `INSERT INTO otp_challenge (identity_id, purpose, channel, destination, flow_hash, code_hash, code_salt, expires_at)
         VALUES (NULL, 'signup', 'email', 'taken@example.com', $1, $2, $3, now() + interval '10 minutes')`,
        [sha(), sha(), randomBytes(16)],
      ),
    ).toMatch(/no identity holds verified/);

    // An address someone only typed does not block its owner from signing up.
    const b = await newIdentity();
    await q(
      "INSERT INTO identity_identifier (identity_id, kind, value) VALUES ($1, 'email', 'typed@example.com')",
      [b],
    );
    await issue(null, 'typed@example.com', 'signup');
  });

  it('are the only codes with no owner', async () => {
    expect(
      await refused(
        `INSERT INTO otp_challenge (identity_id, purpose, channel, destination, flow_hash, code_hash, code_salt, expires_at)
         VALUES (NULL, 'sign_in', 'email', 'nobody@example.com', $1, $2, $3, now() + interval '10 minutes')`,
        [sha(), sha(), randomBytes(16)],
      ),
    ).toMatch(/verified identifier of an active identity/);
  });
});

describe('password_reset', () => {
  async function verifiedRecovery(identityId: string, email: string): Promise<string> {
    const id = await issue(identityId, email, 'recovery');
    await q("UPDATE otp_challenge SET status = 'verified', attempt_count = 1 WHERE id = $1", [id]);
    return id;
  }

  const open = (identityId: string, challengeId: string) =>
    one<{ id: string }>(
      "INSERT INTO password_reset (identity_id, otp_challenge_id, expires_at) VALUES ($1, $2, now() + interval '15 minutes') RETURNING id",
      [identityId, challengeId],
    );

  it('opens only from a verified recovery code of its own identity', async () => {
    const a = await newIdentity();
    await verifiedEmail(a, 'h@example.com');
    const signIn = await issue(a, 'h@example.com', 'sign_in');
    await q("UPDATE otp_challenge SET status = 'verified', attempt_count = 1 WHERE id = $1", [
      signIn,
    ]);
    const sql =
      "INSERT INTO password_reset (identity_id, otp_challenge_id, expires_at) VALUES ($1, $2, now() + interval '15 minutes')";
    expect(await refused(sql, [a, signIn])).toMatch(/recovery code of its own active identity/);

    const unverified = await issue(a, 'h@example.com', 'recovery');
    expect(await refused(sql, [a, unverified])).toMatch(/recovery code of its own active identity/);

    const b = await newIdentity();
    await verifiedEmail(b, 'i@example.com');
    const theirs = await verifiedRecovery(b, 'i@example.com');
    expect(await refused(sql, [a, theirs])).toMatch(/recovery code of its own active identity/);
  });

  it('sets a new password, revokes the old one and every session, once', async () => {
    const a = await newIdentity();
    await verifiedEmail(a, 'j@example.com');
    const old = await password(a);
    const byPassword = await session(a, old, 'sid-pw');
    const byCode = await session(a, null, 'sid-code');
    const ticket = await open(a, await verifiedRecovery(a, 'j@example.com'));

    const hash = Buffer.from('scrypt$16384$8$1$bmV3c2FsdA==$bmV3aGFzaA==');
    const { id: fresh } = await one<{ id: string }>(
      'SELECT password_reset_complete($1, $2) AS id',
      [ticket.id, hash],
    );

    expect((await sessionState(byPassword)).revoke_reason).toBe('password_reset');
    expect((await sessionState(byCode)).revoke_reason).toBe('password_reset');
    const creds = await q<{ id: string; revoke_reason: string | null }>(
      'SELECT id, revoke_reason FROM credential WHERE identity_id = $1 ORDER BY created_at, id',
      [a],
    );
    expect(creds.find((c) => c.id === old)!.revoke_reason).toBe('password_reset');
    expect(creds.find((c) => c.id === fresh)!.revoke_reason).toBeNull();

    expect(await refused('SELECT password_reset_complete($1, $2)', [ticket.id, hash])).toMatch(
      /no usable ticket/,
    );
    expect(
      await refused('UPDATE password_reset SET consumed_at = now() WHERE id = $1', [ticket.id]),
    ).toMatch(/used once/);
  });

  it('is used only by setting a live password of its own identity', async () => {
    const a = await newIdentity();
    await verifiedEmail(a, 'k@example.com');
    const ticket = await open(a, await verifiedRecovery(a, 'k@example.com'));
    const b = await newIdentity();
    const theirs = await password(b);
    expect(
      await refused(
        'UPDATE password_reset SET consumed_at = now(), credential_id = $2 WHERE id = $1',
        [ticket.id, theirs],
      ),
    ).toMatch(/live password of its own identity/);
  });
});

describe('erasure', () => {
  it('ends live codes, scrubs every destination and lets the ledger forget them', async () => {
    const a = await newIdentity();
    await verifiedEmail(a, 'erase@example.com');
    const live = await issue(a, 'erase@example.com', 'sign_in');
    const locked = await issue(a, 'erase@example.com', 'recovery');
    for (let i = 0; i < 5; i++) await wrong(locked);

    await q("UPDATE identity SET status = 'closed' WHERE id = $1", [a]);
    await q('UPDATE identity SET erased_at = now() WHERE id = $1', [a]);

    const rows = await q(
      'SELECT id, status, destination, pii_scrubbed_at, locked_until FROM otp_challenge WHERE identity_id = $1',
      [a],
    );
    expect(rows).toHaveLength(2);
    expect(
      rows.every((r) => r.status === 'expired' && r.destination === null && r.pii_scrubbed_at),
    ).toBe(true);
    expect(rows.find((r) => r.id === locked)!.locked_until).toBeInstanceOf(Date);
    expect(
      await q('SELECT 1 FROM otp_send WHERE otp_challenge_id = ANY($1)', [[live, locked]]),
    ).toHaveLength(0);
  });
});
