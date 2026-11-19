import { randomBytes } from 'node:crypto';
import { describe, expect, it } from 'vitest';
import { newIdentity, one, q, refused, rolledBack } from '../support/db';

/**
 * Profile photos' rules (db/migrations/0015_identity_photo.sql), as the application's own role.
 * Every test runs in a transaction that is rolled back.
 */

rolledBack();

const key = () => `photos/${randomBytes(16).toString('base64url')}.webp`;

const add = (identityId: string, k = key()) =>
  one<{ id: string; created_at: Date; replaced_at: Date | null }>(
    `INSERT INTO identity_photo (identity_id, object_key, bytes, created_at, replaced_at)
     VALUES ($1, $2, 1000, '2000-01-01', '2000-01-02') RETURNING id, created_at, replaced_at`,
    [identityId, k],
  );

describe('identity_photo', () => {
  it('is stamped by the server, and current when added', async () => {
    const p = await add(await newIdentity());
    const { now } = await one<{ now: Date }>('SELECT now() AS now');
    expect(p.created_at).toEqual(now);
    expect(p.replaced_at).toBeNull();
  });

  it('is current once at a time per identity', async () => {
    const id = await newIdentity();
    await add(id);
    expect(
      await refused(
        `INSERT INTO identity_photo (identity_id, object_key, bytes) VALUES ($1, $2, 1)`,
        [id, key()],
      ),
    ).toMatch(/identity_photo_current_once/);
  });

  it('takes only a key of the server’s own shape', async () => {
    const id = await newIdentity();
    for (const bad of ['photos/../x.webp', 'photos/short.webp', `other/${key().slice(7)}`]) {
      expect(
        await refused(
          `INSERT INTO identity_photo (identity_id, object_key, bytes) VALUES ($1, $2, 1)`,
          [id, bad],
        ),
      ).toMatch(/identity_photo_key_shape/);
    }
  });

  it('stays replaced once replaced, and its object is deleted only after', async () => {
    const p = await add(await newIdentity());
    expect(
      await refused('UPDATE identity_photo SET object_deleted_at = now() WHERE id = $1', [p.id]),
    ).toMatch(/identity_photo_deleted_after_replaced/);
    await q('UPDATE identity_photo SET replaced_at = now() WHERE id = $1', [p.id]);
    expect(
      await refused('UPDATE identity_photo SET replaced_at = NULL WHERE id = $1', [p.id]),
    ).toMatch(/stays replaced/);
    expect(
      await refused(`UPDATE identity_photo SET object_key = $2 WHERE id = $1`, [p.id, key()]),
    ).toMatch(/only replaced_at and object_deleted_at change/);
  });

  it('is never deleted by the application', async () => {
    const p = await add(await newIdentity());
    expect(await refused('DELETE FROM identity_photo WHERE id = $1', [p.id])).toMatch(
      /permission denied/,
    );
  });

  it('is taken down when the identity closes, and none is added after', async () => {
    const id = await newIdentity();
    const p = await add(id);
    await q(`UPDATE identity SET status = 'closed' WHERE id = $1`, [id]);
    const after = await one<{ replaced_at: Date | null }>(
      'SELECT replaced_at FROM identity_photo WHERE id = $1',
      [p.id],
    );
    expect(after.replaced_at).not.toBeNull();
    expect(
      await refused(
        `INSERT INTO identity_photo (identity_id, object_key, bytes) VALUES ($1, $2, 1)`,
        [id, key()],
      ),
    ).toMatch(/only an active identity takes a photo/);
  });
});
