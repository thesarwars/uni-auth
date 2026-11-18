import { randomBytes } from 'node:crypto';
import { describe, expect, it } from 'vitest';
import { newIdentity, one, q, refused, rolledBack } from '../support/db';

/**
 * Account recovery's rules (db/migrations/0014_mfa_recovery.sql), as the application's own role.
 * Every test runs in a transaction that is rolled back.
 */

rolledBack();

/** An identity with 2-step verification on: a live authenticator credential. */
async function withTotp(): Promise<string> {
  const id = await newIdentity();
  await q(`INSERT INTO credential (identity_id, kind, secret_ciphertext) VALUES ($1, 'totp', $2)`, [
    id,
    Buffer.concat([Buffer.from([1]), randomBytes(48)]),
  ]);
  return id;
}

const request = (identityId: string) =>
  one<{ id: string; requested_at: Date; eligible_at: Date; review: string }>(
    `INSERT INTO mfa_recovery (identity_id, requested_at, eligible_at, cancel_token_hash, review)
     VALUES ($1, '2000-01-01', '2000-01-02', $2, 'not_required')
     RETURNING id, requested_at, eligible_at, review`,
    [identityId, randomBytes(32)],
  );

describe('mfa_recovery', () => {
  it('is stamped by the server: asked now, eligible 7 days on, not yet answered', async () => {
    const r = await request(await withTotp());
    const { now } = await one<{ now: Date }>('SELECT now() AS now');
    expect(r.requested_at).toEqual(now);
    expect(r.eligible_at.getTime() - now.getTime()).toBe(7 * 24 * 60 * 60 * 1000);
    expect(r.review).toBe('unknown');
  });

  it('is asked for only with 2-step verification on, and once at a time', async () => {
    expect(
      await refused(
        `INSERT INTO mfa_recovery (identity_id, eligible_at, cancel_token_hash) VALUES ($1, now(), $2)`,
        [await newIdentity(), randomBytes(32)],
      ),
    ).toMatch(/2-step verification is not on/);
    const id = await withTotp();
    await request(id);
    expect(
      await refused(
        `INSERT INTO mfa_recovery (identity_id, eligible_at, cancel_token_hash) VALUES ($1, now(), $2)`,
        [id, randomBytes(32)],
      ),
    ).toMatch(/mfa_recovery_pending_once/);
  });

  it('completes only when no person had to check it, or one approved', async () => {
    const r = await request(await withTotp());
    await q(`UPDATE mfa_recovery SET review = 'required' WHERE id = $1`, [r.id]);
    expect(
      await refused('UPDATE mfa_recovery SET completed_at = now() WHERE id = $1', [r.id]),
    ).toMatch(/mfa_recovery_completes_when_allowed/);
    await q(`UPDATE mfa_recovery SET decision = 'approved' WHERE id = $1`, [r.id]);
    await q('UPDATE mfa_recovery SET completed_at = now() WHERE id = $1', [r.id]);
  });

  it('takes the product answer and the decision once, and an ended request is final', async () => {
    const r = await request(await withTotp());
    await q(`UPDATE mfa_recovery SET review = 'required' WHERE id = $1`, [r.id]);
    expect(
      await refused(`UPDATE mfa_recovery SET review = 'not_required' WHERE id = $1`, [r.id]),
    ).toMatch(/already answered/);
    await q(`UPDATE mfa_recovery SET decision = 'rejected' WHERE id = $1`, [r.id]);
    expect(
      await refused(`UPDATE mfa_recovery SET decision = 'approved' WHERE id = $1`, [r.id]),
    ).toMatch(/decision is final/);
    expect(
      await refused(
        `UPDATE mfa_recovery SET cancelled_at = now(), cancelled_by = 'link' WHERE id = $1`,
        [r.id],
      ),
    ).toMatch(/final/);
  });

  it('keeps who, when and the token', async () => {
    const r = await request(await withTotp());
    expect(
      await refused('UPDATE mfa_recovery SET eligible_at = now() WHERE id = $1', [r.id]),
    ).toMatch(/fixed/);
    expect(
      await refused('UPDATE mfa_recovery SET cancel_token_hash = $2 WHERE id = $1', [
        r.id,
        randomBytes(32),
      ]),
    ).toMatch(/fixed/);
  });

  it('is withdrawn at the product only once cancelled, and never deleted', async () => {
    const r = await request(await withTotp());
    expect(
      await refused('UPDATE mfa_recovery SET withdrawn_at = now() WHERE id = $1', [r.id]),
    ).toMatch(/mfa_recovery_withdrawn_after_cancel/);
    await q(`UPDATE mfa_recovery SET cancelled_at = now(), cancelled_by = 'link' WHERE id = $1`, [
      r.id,
    ]);
    await q('UPDATE mfa_recovery SET withdrawn_at = now() WHERE id = $1', [r.id]);
    expect(await refused('DELETE FROM mfa_recovery WHERE id = $1', [r.id])).toMatch(
      /permission denied/,
    );
  });

  it('names account_recovery on the credentials it revokes', async () => {
    const id = await withTotp();
    await q(
      `UPDATE credential SET revoked_at = now(), revoke_reason = 'account_recovery'
        WHERE identity_id = $1 AND kind = 'totp'`,
      [id],
    );
  });
});
