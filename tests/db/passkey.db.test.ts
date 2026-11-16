import { randomBytes } from 'node:crypto';
import { describe, expect, it } from 'vitest';
import { newIdentity, one, q, refused, rolledBack } from '../support/db';

/**
 * Passkeys' rules (db/migrations/0010_passkey.sql), as the application's own role. Every test
 * runs in a transaction that is rolled back.
 */

rolledBack();

const INSERT = `INSERT INTO credential
  (identity_id, kind, webauthn_credential_id, public_key, sign_count, transports, aaguid,
   backup_eligible, backup_state, nickname)
  VALUES ($1, 'passkey', $2, $3, $4, $5, $6, $7, $8, $9) RETURNING id`;

const passkey = async (
  identityId: string,
  o: { id?: Buffer; count?: number; synced?: boolean; name?: string } = {},
) =>
  (
    await one<{ id: string }>(INSERT, [
      identityId,
      o.id ?? randomBytes(32),
      randomBytes(77),
      o.count ?? 0,
      ['internal'],
      '00000000-0000-0000-0000-000000000000',
      o.synced ?? true,
      o.synced ?? true,
      o.name ?? 'Mac',
    ])
  ).id;

describe('a passkey', () => {
  it('has its id, key and name, and nothing of the other kinds', async () => {
    const a = await newIdentity();
    expect(
      await refused(
        "INSERT INTO credential (identity_id, kind, sign_count, transports, backup_eligible, backup_state) VALUES ($1, 'passkey', 0, '{}', false, false)",
        [a],
      ),
    ).toMatch(/credential_passkey_shape/);
    expect(
      await refused(
        "INSERT INTO credential (identity_id, kind, secret_hash, password_policy_id) VALUES ($1, 'password', 'x', password_policy_in_effect()) ",
        [a],
      ),
    ).toMatch(/credential_secret_is_a_hash/);
    expect(
      await refused(
        "INSERT INTO credential (identity_id, kind, provider_subject, nickname) VALUES ($1, 'oauth_google', 'g-1', 'Mac')",
        [a],
      ),
    ).toMatch(/credential_passkey_columns/);
    expect(
      await refused(INSERT, [
        a,
        randomBytes(8),
        randomBytes(77),
        0,
        ['internal'],
        null,
        true,
        true,
        'Mac',
      ]),
    ).toMatch(/credential_webauthn_id_bounded/);
    expect(
      await refused(INSERT, [
        a,
        randomBytes(32),
        randomBytes(77),
        0,
        ['carrier-pigeon'],
        null,
        true,
        true,
        'Mac',
      ]),
    ).toMatch(/credential_transports_known/);
    expect(
      await refused(INSERT, [
        a,
        randomBytes(32),
        randomBytes(77),
        0,
        ['usb'],
        null,
        false,
        true,
        'Key',
      ]),
    ).toMatch(/credential_backup_needs_eligible/);
  });

  it('names one live passkey by its credential id, whoever holds it', async () => {
    const id = randomBytes(32);
    await passkey(await newIdentity(), { id });
    expect(
      await refused(INSERT, [
        await newIdentity(),
        id,
        randomBytes(77),
        0,
        ['internal'],
        null,
        true,
        true,
        'Mac',
      ]),
    ).toMatch(/credential_webauthn_id_key/);
  });

  it('keeps its id and key for life, and a name', async () => {
    const p = await passkey(await newIdentity());
    expect(
      await refused('UPDATE credential SET public_key = $2 WHERE id = $1', [p, randomBytes(77)]),
    ).toMatch(/never edited/);
    expect(
      await refused('UPDATE credential SET webauthn_credential_id = $2 WHERE id = $1', [
        p,
        randomBytes(32),
      ]),
    ).toMatch(/never edited/);
    expect(await refused('UPDATE credential SET nickname = NULL WHERE id = $1', [p])).toMatch(
      /keeps a name/,
    );
    expect(await refused("UPDATE credential SET nickname = ' Mac' WHERE id = $1", [p])).toMatch(
      /credential_nickname_bounded/,
    );
    await q("UPDATE credential SET nickname = 'Work laptop' WHERE id = $1", [p]);
  });

  it('counts only forward, unless it keeps no count', async () => {
    const a = await newIdentity();
    const synced = await passkey(a);
    await q('UPDATE credential SET sign_count = 0 WHERE id = $1', [synced]);
    const key = await passkey(a, { count: 5, synced: false });
    expect(await refused('UPDATE credential SET sign_count = 4 WHERE id = $1', [key])).toMatch(
      /only moves forward/,
    );
    await q('UPDATE credential SET sign_count = 6 WHERE id = $1', [key]);
  });

  it('once removed, signs nothing in and is not renamed', async () => {
    const p = await passkey(await newIdentity());
    await q(
      "UPDATE credential SET revoked_at = now(), revoke_reason = 'removed_by_member' WHERE id = $1",
      [p],
    );
    expect(await refused('UPDATE credential SET sign_count = 1 WHERE id = $1', [p])).toMatch(
      /signs nothing in/,
    );
    expect(await refused("UPDATE credential SET nickname = 'Back' WHERE id = $1", [p])).toMatch(
      /not renamed/,
    );
  });

  it('is one of at most twenty per identity', async () => {
    const a = await newIdentity();
    for (let i = 0; i < 20; i++) await passkey(a);
    expect(
      await refused(INSERT, [
        a,
        randomBytes(32),
        randomBytes(77),
        0,
        ['internal'],
        null,
        true,
        true,
        'One more',
      ]),
    ).toMatch(/at most twenty passkeys/);
  });

  it('is scrubbed on erasure', async () => {
    const a = await newIdentity();
    await passkey(a);
    await q("UPDATE identity SET status = 'closed' WHERE id = $1", [a]);
    await q('UPDATE identity SET erased_at = now() WHERE id = $1', [a]);
    const left = await one<{ n: number }>(
      `SELECT count(*)::int AS n FROM credential
        WHERE identity_id = $1 AND (webauthn_credential_id IS NOT NULL OR public_key IS NOT NULL
                                    OR nickname IS NOT NULL)`,
      [a],
    );
    expect(left.n).toBe(0);
  });
});
