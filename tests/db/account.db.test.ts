import { describe, expect, it } from 'vitest';
import { HASH, newIdentity, one, password, q, refused, rolledBack, session } from '../support/db';

/**
 * The account centre's rules (db/migrations/0005_account.sql), as the application's own role.
 * Every test runs in a transaction that is rolled back.
 */

rolledBack();

const verified = (identityId: string, value: string) =>
  one<{ id: string }>(
    "INSERT INTO identity_identifier (identity_id, kind, value, verified_at) VALUES ($1, 'email', $2, now()) RETURNING id",
    [identityId, value],
  );

describe('an identity keeps a way to be reached', () => {
  it('refuses to remove the last verified identifier of a live identity', async () => {
    const a = await newIdentity();
    const first = await verified(a, 'first@example.com');
    expect(
      await refused('UPDATE identity_identifier SET revoked_at = now() WHERE id = $1', [first.id]),
    ).toMatch(/keeps at least one verified identifier/);

    const second = await verified(a, 'second@example.com');
    await q('UPDATE identity_identifier SET revoked_at = now() WHERE id = $1', [first.id]);
    expect(
      await refused('UPDATE identity_identifier SET revoked_at = now() WHERE id = $1', [second.id]),
    ).toMatch(/keeps at least one verified identifier/);
  });

  it('lets an unverified one go, and lets erasure remove them all', async () => {
    const a = await newIdentity();
    await verified(a, 'kept@example.com');
    const typed = await one<{ id: string }>(
      "INSERT INTO identity_identifier (identity_id, kind, value) VALUES ($1, 'email', 'typed@example.com') RETURNING id",
      [a],
    );
    await q('UPDATE identity_identifier SET revoked_at = now() WHERE id = $1', [typed.id]);

    await q("UPDATE identity SET status = 'closed' WHERE id = $1", [a]);
    await q('UPDATE identity SET erased_at = now() WHERE id = $1', [a]);
    const left = await one<{ n: number }>(
      'SELECT count(*)::int AS n FROM identity_identifier WHERE identity_id = $1 AND revoked_at IS NULL',
      [a],
    );
    expect(left.n).toBe(0);
  });
});

describe('a code for an address being added', () => {
  const add = (identityId: string, destination: string) =>
    `INSERT INTO otp_challenge (identity_id, purpose, channel, destination, flow_hash, code_hash, code_salt, code_length, expires_at)
     VALUES ('${identityId}', 'add_identifier', 'email', '${destination}',
             sha256('flow'), sha256('code'), sha256('salt'), 6, now() + interval '10 minutes')`;

  it('goes to a free address, for an active identity', async () => {
    const a = await newIdentity();
    await q(add(a, 'free@example.com'));
  });

  it('never goes to an address another identity holds verified', async () => {
    const a = await newIdentity();
    const b = await newIdentity();
    await verified(b, 'taken@example.com');
    expect(await refused(add(a, 'taken@example.com'))).toMatch(/no identity holds verified/);
  });

  it('is not sent for a suspended identity', async () => {
    const a = await newIdentity();
    await q("UPDATE identity SET status = 'suspended' WHERE id = $1", [a]);
    expect(await refused(add(a, 'free2@example.com'))).toMatch(/only to an active identity/);
  });
});

describe('password_change', () => {
  it('replaces the password and signs out every session but the one named', async () => {
    const a = await newIdentity();
    const old = await password(a);
    const here = await session(a, old, 'here');
    const there = await session(a, old, 'there');
    const coded = await session(a, null, 'by-code');

    const { id } = await one<{ id: string }>('SELECT password_change($1, $2, $3) AS id', [
      a,
      HASH,
      'here',
    ]);
    const state = async (sid: string) =>
      (
        await one<{ revoke_reason: string | null }>(
          'SELECT revoke_reason FROM auth_session WHERE sid = $1',
          [sid],
        )
      ).revoke_reason;
    expect(await state('here')).toBeNull();
    expect(await state('there')).toBe('password_changed');
    expect(await state('by-code')).toBe('password_changed');
    const creds = await q<{ id: string; revoke_reason: string | null }>(
      "SELECT id, revoke_reason FROM credential WHERE identity_id = $1 AND kind = 'password' ORDER BY created_at",
      [a],
    );
    expect(creds.map((c) => c.revoke_reason)).toEqual(['replaced', null]);
    expect(creds[1]!.id).toBe(id);
    void [here, there, coded];
  });

  it('refuses a session that is not a live one of the identity', async () => {
    const a = await newIdentity();
    const b = await newIdentity();
    await session(b, null, 'theirs');
    expect(await refused('SELECT password_change($1, $2, $3)', [a, HASH, 'theirs'])).toMatch(
      /not a live session/,
    );
  });

  it('gives a password to an identity that had none', async () => {
    const a = await newIdentity();
    await session(a, null, 'only');
    await q('SELECT password_change($1, $2, $3)', [a, HASH, 'only']);
    const live = await one<{ n: number }>(
      "SELECT count(*)::int AS n FROM credential WHERE identity_id = $1 AND kind = 'password' AND revoked_at IS NULL",
      [a],
    );
    expect(live.n).toBe(1);
  });
});
