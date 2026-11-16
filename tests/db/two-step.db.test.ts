import { randomBytes } from 'node:crypto';
import { describe, expect, it } from 'vitest';
import { newIdentity, one, q, refused, rolledBack, session } from '../support/db';

/**
 * 2-step verification's rules (db/migrations/0008_mfa.sql), as the application's own role.
 * Every test runs in a transaction that is rolled back.
 */

rolledBack();

/** A well-formed sealed seed: version 1, IV, tag, 20 bytes. Never opened here. */
const sealed = () => Buffer.concat([Buffer.from([1]), randomBytes(48)]);
const hash = () => randomBytes(32);

const totp = async (identityId: string, step: number | null = null) =>
  (
    await one<{ id: string }>(
      `INSERT INTO credential (identity_id, kind, secret_ciphertext, totp_last_step)
       VALUES ($1, 'totp', $2, $3) RETURNING id`,
      [identityId, sealed(), step],
    )
  ).id;

const codeSet = async (identityId: string, n = 10) => {
  const set = (
    await one<{ id: string }>(
      `INSERT INTO credential (identity_id, kind) VALUES ($1, 'recovery_codes') RETURNING id`,
      [identityId],
    )
  ).id;
  const codes: string[] = [];
  for (let i = 0; i < n; i++) {
    codes.push(
      (
        await one<{ id: string }>(
          'INSERT INTO recovery_code (credential_id, code_hash) VALUES ($1, $2) RETURNING id',
          [set, hash()],
        )
      ).id,
    );
  }
  return { set, codes };
};

describe('the authenticator', () => {
  it('is one per identity, and holds a sealed seed, never a plain one', async () => {
    const a = await newIdentity();
    await totp(a);
    expect(
      await refused(
        'INSERT INTO credential (identity_id, kind, secret_ciphertext) VALUES ($1, $2, $3)',
        [a, 'totp', sealed()],
      ),
    ).toMatch(/credential_one_live_totp_key/);
    const b = await newIdentity();
    expect(
      await refused("INSERT INTO credential (identity_id, kind) VALUES ($1, 'totp')", [b]),
    ).toMatch(/credential_totp_shape/);
    expect(
      await refused(
        "INSERT INTO credential (identity_id, kind, secret_ciphertext) VALUES ($1, 'totp', $2)",
        [b, Buffer.from('JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP')],
      ),
    ).toMatch(/credential_secret_ciphertext_shape/);
  });

  it('keeps its seed for life, and its last step only moves forward', async () => {
    const a = await newIdentity();
    const t = await totp(a, 100);
    expect(
      await refused('UPDATE credential SET secret_ciphertext = $2 WHERE id = $1', [t, sealed()]),
    ).toMatch(/never edited/);
    expect(await refused('UPDATE credential SET totp_last_step = 99 WHERE id = $1', [t])).toMatch(
      /only moves forward/,
    );
    await q('UPDATE credential SET totp_last_step = 101 WHERE id = $1', [t]);
    await q(
      "UPDATE credential SET revoked_at = now(), revoke_reason = 'removed_by_member' WHERE id = $1",
      [t],
    );
    expect(await refused('UPDATE credential SET totp_last_step = 102 WHERE id = $1', [t])).toMatch(
      /accepts no code/,
    );
  });

  it('does not count as a way to sign in, or as a linked account', async () => {
    const a = await newIdentity();
    await totp(a);
    const kinds = await q(
      "SELECT kind FROM credential WHERE identity_id = $1 AND kind IN ('password', 'oauth_google', 'oauth_apple')",
      [a],
    );
    expect(kinds).toEqual([]);
  });
});

describe('recovery codes', () => {
  it('are made only beside a live authenticator, ten to a set', async () => {
    const a = await newIdentity();
    expect(
      await refused("INSERT INTO credential (identity_id, kind) VALUES ($1, 'recovery_codes')", [
        a,
      ]),
    ).toMatch(/only beside a live authenticator/);
    await totp(a);
    const { set } = await codeSet(a);
    expect(
      await refused('INSERT INTO recovery_code (credential_id, code_hash) VALUES ($1, $2)', [
        set,
        hash(),
      ]),
    ).toMatch(/a set holds ten codes/);
  });

  it('work once, are never deleted, and stop with their set', async () => {
    const a = await newIdentity();
    await totp(a);
    const { set, codes } = await codeSet(a, 2);
    await q('UPDATE recovery_code SET used_at = now() WHERE id = $1', [codes[0]]);
    expect(
      await refused('UPDATE recovery_code SET used_at = NULL WHERE id = $1', [codes[0]]),
    ).toMatch(/works once/);
    expect(await refused('DELETE FROM recovery_code WHERE id = $1', [codes[1]])).toMatch(
      /permission denied/,
    );
    expect(
      await refused('UPDATE recovery_code SET code_hash = $2 WHERE id = $1', [codes[1], hash()]),
    ).toMatch(/nulled only by the erasure scrub/);
    await q("UPDATE credential SET revoked_at = now(), revoke_reason = 'replaced' WHERE id = $1", [
      set,
    ]);
    expect(
      await refused('UPDATE recovery_code SET used_at = now() WHERE id = $1', [codes[1]]),
    ).toMatch(/replaced or turned off/);
  });

  it('go when the authenticator is turned off', async () => {
    const a = await newIdentity();
    const t = await totp(a);
    const { set } = await codeSet(a, 1);
    await q(
      "UPDATE credential SET revoked_at = now(), revoke_reason = 'removed_by_member' WHERE id = $1",
      [t],
    );
    const row = await one<{ revoke_reason: string | null }>(
      'SELECT revoke_reason FROM credential WHERE id = $1',
      [set],
    );
    expect(row.revoke_reason).toBe('removed_by_member');
  });
});

describe('erasure', () => {
  it('scrubs the sealed seed and every recovery code hash', async () => {
    const a = await newIdentity();
    await q(
      "INSERT INTO identity_identifier (identity_id, kind, value, verified_at) VALUES ($1, 'email', 'gone@example.com', now())",
      [a],
    );
    await totp(a);
    await codeSet(a, 3);
    await q("UPDATE identity SET status = 'closed' WHERE id = $1", [a]);
    await q('UPDATE identity SET erased_at = now() WHERE id = $1', [a]);
    const left = await one<{ seeds: number; hashes: number }>(
      `SELECT (SELECT count(*)::int FROM credential WHERE identity_id = $1 AND secret_ciphertext IS NOT NULL) AS seeds,
              (SELECT count(*)::int FROM recovery_code r JOIN credential c ON c.id = r.credential_id
                WHERE c.identity_id = $1 AND r.code_hash IS NOT NULL) AS hashes`,
      [a],
    );
    expect(left).toEqual({ seeds: 0, hashes: 0 });
  });
});

describe('a session’s assurance level', () => {
  it('starts at 1 and only rises', async () => {
    const a = await newIdentity();
    const s = await session(a, null, `aal-${randomBytes(4).toString('hex')}`);
    expect((await one('SELECT aal FROM auth_session WHERE id = $1', [s])).aal).toBe(1);
    await q('UPDATE auth_session SET aal = 2 WHERE id = $1', [s]);
    expect(await refused('UPDATE auth_session SET aal = 1 WHERE id = $1', [s])).toMatch(
      /only rises/,
    );
    expect(await refused('UPDATE auth_session SET aal = 3 WHERE id = $1', [s])).toMatch(
      /auth_session_aal_known/,
    );
  });
});
