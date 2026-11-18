import { describe, expect, it } from 'vitest';
import { newIdentity, one, q, refused, rolledBack } from '../support/db';

/**
 * Account deletion's rules (db/migrations/0012_data_privacy.sql), as the application's own role.
 * Every test runs in a transaction that is rolled back.
 */

rolledBack();

const request = async (identityId: string) =>
  one<{ id: string; requested_at: Date; scheduled_for: Date }>(
    `INSERT INTO account_deletion (identity_id, requested_at, scheduled_for)
     VALUES ($1, '2000-01-01', '2000-01-02') RETURNING id, requested_at, scheduled_for`,
    [identityId],
  );

describe('account_deletion', () => {
  it('is stamped by the server: asked now, due 14 days on, whatever the caller says', async () => {
    const d = await request(await newIdentity());
    const { now } = await one<{ now: Date }>('SELECT now() AS now');
    expect(d.requested_at).toEqual(now);
    expect(d.scheduled_for.getTime() - now.getTime()).toBe(14 * 24 * 60 * 60 * 1000);
  });

  it('is asked for only by an active identity, and only once at a time', async () => {
    const closed = await newIdentity();
    await q("UPDATE identity SET status = 'closed' WHERE id = $1", [closed]);
    expect(
      await refused(
        'INSERT INTO account_deletion (identity_id, scheduled_for) VALUES ($1, now())',
        [closed],
      ),
    ).toMatch(/only an active identity/);

    const a = await newIdentity();
    await request(a);
    expect(
      await refused(
        'INSERT INTO account_deletion (identity_id, scheduled_for) VALUES ($1, now())',
        [a],
      ),
    ).toMatch(/account_deletion_pending_once/);
  });

  it('keeps who and when, ends once, and a cancelled one can be asked for again', async () => {
    const a = await newIdentity();
    const d = await request(a);
    expect(
      await refused('UPDATE account_deletion SET scheduled_for = now() WHERE id = $1', [d.id]),
    ).toMatch(/who and when are fixed/);
    await q('UPDATE account_deletion SET cancelled_at = now() WHERE id = $1', [d.id]);
    expect(
      await refused('UPDATE account_deletion SET completed_at = now() WHERE id = $1', [d.id]),
    ).toMatch(/final/);
    await request(a);
  });

  it('is never deleted', async () => {
    const d = await request(await newIdentity());
    expect(await refused('DELETE FROM account_deletion WHERE id = $1', [d.id])).toMatch(
      /permission denied/,
    );
  });

  it('signs the identity out with its own reason', async () => {
    const a = await newIdentity();
    await q(
      `INSERT INTO auth_session (identity_id, sid, expires_at) VALUES ($1, 'sid-del', now() + interval '1 day')`,
      [a],
    );
    await q(
      `UPDATE auth_session SET revoked_at = now(), revoke_reason = 'deletion_requested' WHERE sid = 'sid-del'`,
    );
    expect(
      await refused(
        `INSERT INTO auth_session (identity_id, sid, expires_at, revoked_at, revoke_reason)
         VALUES ($1, 'sid-x', now() + interval '1 day', now(), 'made_up')`,
        [a],
      ),
    ).toBeTruthy();
  });
});
