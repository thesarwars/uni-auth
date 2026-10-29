import pg from 'pg';
import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it } from 'vitest';

/**
 * The identity database's rules (db/migrations/0001_identity.sql), exercised as the
 * application's own role. Every test runs in a transaction that is rolled back.
 */

const HASH = Buffer.from('scrypt$16384$8$1$c2FsdHNhbHQ=$aGFzaGhhc2hoYXNo');
let pool: pg.Pool;
let db: pg.PoolClient;

beforeAll(() => {
  pool = new pg.Pool({ connectionString: process.env.DATABASE_URL, max: 2 });
});
afterAll(async () => {
  await pool.end();
});
beforeEach(async () => {
  db = await pool.connect();
  await db.query('BEGIN');
});
afterEach(async () => {
  await db.query('ROLLBACK');
  db.release();
});

const q = async <T extends pg.QueryResultRow = Record<string, any>>(
  sql: string,
  params: unknown[] = [],
): Promise<T[]> => (await db.query<T>(sql, params)).rows;
const one = async <T extends pg.QueryResultRow = Record<string, any>>(
  sql: string,
  params: unknown[] = [],
): Promise<T> => (await q<T>(sql, params))[0]!;

/** Runs a statement that must fail, inside a savepoint so the test can carry on. */
async function refused(sql: string, params: unknown[] = []): Promise<string> {
  await db.query('SAVEPOINT s');
  try {
    await db.query(sql, params);
  } catch (err) {
    await db.query('ROLLBACK TO SAVEPOINT s');
    return (err as Error).message;
  }
  await db.query('RELEASE SAVEPOINT s');
  throw new Error(`expected refusal, but it succeeded: ${sql}`);
}

const newIdentity = async (): Promise<string> =>
  (await one<{ id: string }>('INSERT INTO identity DEFAULT VALUES RETURNING id')).id;

const policy = async (): Promise<string> =>
  (await one<{ id: string }>('SELECT password_policy_in_effect() AS id')).id;

async function password(identityId: string): Promise<string> {
  return (
    await one<{ id: string }>(
      `INSERT INTO credential (identity_id, kind, secret_hash, password_policy_id)
       VALUES ($1, 'password', $2, $3) RETURNING id`,
      [identityId, HASH, await policy()],
    )
  ).id;
}

async function session(identityId: string, credentialId: string | null, sid: string) {
  return (
    await one<{ id: string }>(
      `INSERT INTO auth_session (identity_id, credential_id, sid, client_id, expires_at)
       VALUES ($1, $2, $3, 'gsn-web', now() + interval '1 day') RETURNING id`,
      [identityId, credentialId, sid],
    )
  ).id;
}

const sessionState = (id: string) =>
  one<{ revoked_at: Date | null; revoke_reason: string | null }>(
    'SELECT revoked_at, revoke_reason FROM auth_session WHERE id = $1',
    [id],
  );

describe('identity', () => {
  it('is born active, and the server stamps every lifecycle moment', async () => {
    const id = await newIdentity();
    expect(await refused("INSERT INTO identity (status) VALUES ('suspended')")).toMatch(
      /born active/,
    );

    await q("UPDATE identity SET status = 'suspended', suspended_at = '2000-01-01' WHERE id = $1", [
      id,
    ]);
    const s = await one('SELECT suspended_at FROM identity WHERE id = $1', [id]);
    expect((s.suspended_at as Date).getFullYear()).toBeGreaterThan(2000);

    await q("UPDATE identity SET status = 'active' WHERE id = $1", [id]);
    expect(
      (await one('SELECT suspended_at FROM identity WHERE id = $1', [id])).suspended_at,
    ).toBeNull();
  });

  it('stays closed once closed, and erasure needs a closed identity', async () => {
    const id = await newIdentity();
    expect(await refused('UPDATE identity SET erased_at = now() WHERE id = $1', [id])).toMatch(
      /identity_erasure_is_a_scrub/,
    );
    await q("UPDATE identity SET status = 'closed' WHERE id = $1", [id]);
    expect(await refused("UPDATE identity SET status = 'active' WHERE id = $1", [id])).toMatch(
      /stays closed/,
    );
  });

  it('cannot be deleted by the application', async () => {
    const id = await newIdentity();
    expect(await refused('DELETE FROM identity WHERE id = $1', [id])).toMatch(/permission denied/);
  });
});

describe('identity_identifier', () => {
  it('lets only one identity hold a verified address, but never blocks on an unproved one', async () => {
    const a = await newIdentity();
    const b = await newIdentity();
    // b typed a's address and never proved it: that must not stop a.
    await q(
      "INSERT INTO identity_identifier (identity_id, kind, value) VALUES ($1, 'email', 'Ada@Example.com')",
      [b],
    );
    await q(
      "INSERT INTO identity_identifier (identity_id, kind, value, verified_at) VALUES ($1, 'email', 'ada@example.com', now())",
      [a],
    );
    // Case-insensitive: a second verified holder of the same address is refused.
    expect(
      await refused(
        "INSERT INTO identity_identifier (identity_id, kind, value, verified_at) VALUES ($1, 'email', 'ADA@example.COM', now())",
        [b],
      ),
    ).toMatch(/identity_identifier_verified_owner_key/);
  });

  it('checks the format, and keeps owner, kind and value fixed', async () => {
    const a = await newIdentity();
    expect(
      await refused(
        "INSERT INTO identity_identifier (identity_id, kind, value) VALUES ($1, 'phone', '07700900123')",
        [a],
      ),
    ).toMatch(/phone_e164/);
    const row = await one(
      "INSERT INTO identity_identifier (identity_id, kind, value) VALUES ($1, 'phone', '+447700900123') RETURNING id",
      [a],
    );
    expect(
      await refused("UPDATE identity_identifier SET value = '+447700900999' WHERE id = $1", [
        row.id,
      ]),
    ).toMatch(/fixed/);
  });

  it('makes only a verified, live identifier primary, and a removed one stays removed', async () => {
    const a = await newIdentity();
    const row = await one(
      "INSERT INTO identity_identifier (identity_id, kind, value) VALUES ($1, 'email', 'p@example.com') RETURNING id",
      [a],
    );
    expect(
      await refused('UPDATE identity_identifier SET is_primary = true WHERE id = $1', [row.id]),
    ).toMatch(/primary_is_live/);
    await q('UPDATE identity_identifier SET verified_at = now(), is_primary = true WHERE id = $1', [
      row.id,
    ]);
    await q('UPDATE identity_identifier SET is_primary = false, revoked_at = now() WHERE id = $1', [
      row.id,
    ]);
    expect(
      await refused('UPDATE identity_identifier SET revoked_at = NULL WHERE id = $1', [row.id]),
    ).toMatch(/stays removed/);
  });

  it('cannot be added to a closed identity', async () => {
    const a = await newIdentity();
    await q("UPDATE identity SET status = 'closed' WHERE id = $1", [a]);
    expect(
      await refused(
        "INSERT INTO identity_identifier (identity_id, kind, value) VALUES ($1, 'email', 'x@example.com')",
        [a],
      ),
    ).toMatch(/closed/);
  });
});

describe('credential', () => {
  it('stores only a hash, stamped with the policy in force', async () => {
    const a = await newIdentity();
    expect(
      await refused(
        `INSERT INTO credential (identity_id, kind, secret_hash, password_policy_id)
         VALUES ($1, 'password', convert_to('hunter2', 'UTF8'), password_policy_in_effect())`,
        [a],
      ),
    ).toMatch(/credential_secret_is_a_hash/);
    expect(
      await refused(
        "INSERT INTO credential (identity_id, kind, secret_hash, password_policy_id) VALUES ($1, 'password', $2, NULL)",
        [a, HASH],
      ),
    ).toMatch(/stamped with the policy/);
    await password(a);
  });

  it('allows one live password, and a new password is a new row', async () => {
    const a = await newIdentity();
    const first = await password(a);
    expect(
      await refused('UPDATE credential SET secret_hash = $2 WHERE id = $1', [
        first,
        Buffer.from('scrypt$1$1$1$YQ==$Yg=='),
      ]),
    ).toMatch(/never edited/);
    expect(
      await refused(
        "INSERT INTO credential (identity_id, kind, secret_hash, password_policy_id) VALUES ($1, 'password', $2, password_policy_in_effect())",
        [a, HASH],
      ),
    ).toMatch(/one_live_password/);
    await q("UPDATE credential SET revoked_at = now(), revoke_reason = 'replaced' WHERE id = $1", [
      first,
    ]);
    await password(a);
  });

  it('lets one live identity own an upstream subject', async () => {
    const a = await newIdentity();
    const b = await newIdentity();
    await q(
      "INSERT INTO credential (identity_id, kind, provider_subject) VALUES ($1, 'oauth_google', 'g-123')",
      [a],
    );
    expect(
      await refused(
        "INSERT INTO credential (identity_id, kind, provider_subject) VALUES ($1, 'oauth_google', 'g-123')",
        [b],
      ),
    ).toMatch(/provider_subject_key/);
    expect(
      await refused(
        "INSERT INTO credential (identity_id, kind, provider_subject, secret_hash) VALUES ($1, 'oauth_apple', 'a-1', $2)",
        [b, HASH],
      ),
    ).toMatch(/oauth_shape/);
  });

  it('nulls a secret only through the erasure scrub', async () => {
    const a = await newIdentity();
    const c = await password(a);
    expect(await refused('UPDATE credential SET secret_hash = NULL WHERE id = $1', [c])).toMatch(
      /erasure scrub/,
    );
  });

  it('revoking it revokes the sessions it opened', async () => {
    const a = await newIdentity();
    const c = await password(a);
    const s = await session(a, c, 'sid-credential');
    await q(
      "UPDATE credential SET revoked_at = now(), revoke_reason = 'compromised' WHERE id = $1",
      [c],
    );
    expect((await sessionState(s)).revoke_reason).toBe('credential_revoked');
  });
});

describe('auth_session', () => {
  it('opens only on an active identity and a live credential of its own', async () => {
    const a = await newIdentity();
    const b = await newIdentity();
    const cb = await password(b);
    expect(
      await refused(
        "INSERT INTO auth_session (identity_id, credential_id, sid, expires_at) VALUES ($1, $2, 'x', now() + interval '1 day')",
        [a, cb],
      ),
    ).toMatch(/live credential of its own identity/);
    await q("UPDATE identity SET status = 'suspended' WHERE id = $1", [a]);
    expect(
      await refused(
        "INSERT INTO auth_session (identity_id, sid, expires_at) VALUES ($1, 'y', now() + interval '1 day')",
        [a],
      ),
    ).toMatch(/suspended or closed/);
  });

  it('lives at most 90 days, holds a unique sid, and is final once revoked', async () => {
    const a = await newIdentity();
    expect(
      await refused(
        "INSERT INTO auth_session (identity_id, sid, expires_at) VALUES ($1, 'long', now() + interval '91 days')",
        [a],
      ),
    ).toMatch(/auth_session_lifetime/);
    const s = await session(a, null, 'sid-unique');
    expect(
      await refused(
        "INSERT INTO auth_session (identity_id, sid, expires_at) VALUES ($1, 'sid-unique', now() + interval '1 day')",
        [a],
      ),
    ).toMatch(/auth_session_sid_key/);
    expect(await refused("UPDATE auth_session SET sid = 'other' WHERE id = $1", [s])).toMatch(
      /fixed/,
    );
    expect(
      await refused(
        "UPDATE auth_session SET expires_at = expires_at + interval '1 hour' WHERE id = $1",
        [s],
      ),
    ).toMatch(/expiry only shortens/);
    await q(
      "UPDATE auth_session SET revoked_at = now(), revoke_reason = 'sign_out' WHERE id = $1",
      [s],
    );
    expect(
      await refused('UPDATE auth_session SET last_seen_at = now() WHERE id = $1', [s]),
    ).toMatch(/final/);
  });

  it('is revoked when its identity is suspended or closed', async () => {
    const a = await newIdentity();
    const s1 = await session(a, null, 'sid-s1');
    await q("UPDATE identity SET status = 'suspended' WHERE id = $1", [a]);
    expect((await sessionState(s1)).revoke_reason).toBe('identity_suspended');
    const b = await newIdentity();
    const s2 = await session(b, null, 'sid-s2');
    await q("UPDATE identity SET status = 'closed' WHERE id = $1", [b]);
    expect((await sessionState(s2)).revoke_reason).toBe('identity_closed');
  });
});

describe('auth_event', () => {
  it('is stamped by the server and must name someone', async () => {
    const a = await newIdentity();
    const e = await one(
      "INSERT INTO auth_event (identity_id, kind, outcome, occurred_at) VALUES ($1, 'sign_in', 'success', '2000-01-01') RETURNING occurred_at",
      [a],
    );
    expect((e.occurred_at as Date).getFullYear()).toBeGreaterThan(2000);
    await q(
      "INSERT INTO auth_event (identifier_hash, kind, outcome) VALUES (sha256('a@b.c'), 'sign_in', 'failure')",
    );
    expect(
      await refused("INSERT INTO auth_event (kind, outcome) VALUES ('lockout', 'failure')"),
    ).toMatch(/names_someone/);
  });

  it('is append-only', async () => {
    const a = await newIdentity();
    await q(
      "INSERT INTO auth_event (identity_id, kind, outcome) VALUES ($1, 'sign_in', 'success')",
      [a],
    );
    expect(await refused("UPDATE auth_event SET outcome = 'failure'")).toMatch(/append-only/);
    expect(await refused('DELETE FROM auth_event')).toMatch(/permission denied/);
    expect(await refused('TRUNCATE auth_event')).toMatch(/permission denied/);
  });
});

describe('erasure', () => {
  it('scrubs everything personal beneath the identity and deletes its sessions, once', async () => {
    const a = await newIdentity();
    await q("UPDATE identity SET display_name = 'Ada' WHERE id = $1", [a]);
    await q(
      "INSERT INTO identity_identifier (identity_id, kind, value, verified_at, is_primary) VALUES ($1, 'email', 'erase@example.com', now(), true)",
      [a],
    );
    const c = await password(a);
    await q(
      "INSERT INTO credential (identity_id, kind, provider_subject, provider_email, provider_email_verified) VALUES ($1, 'oauth_apple', 'apple-9', 'r@privaterelay.example', true)",
      [a],
    );
    await session(a, c, 'sid-erase');
    await q(
      `INSERT INTO auth_event (identity_id, identifier_hash, kind, outcome, ip_address, user_agent, detail)
       VALUES ($1, sha256('erase@example.com'), 'sign_in', 'failure', '198.51.100.7', 'ua', '{"why":"bad password"}')`,
      [a],
    );

    await q("UPDATE identity SET status = 'closed' WHERE id = $1", [a]);
    await q('UPDATE identity SET erased_at = now() WHERE id = $1', [a]);

    expect(
      (await one('SELECT display_name FROM identity WHERE id = $1', [a])).display_name,
    ).toBeNull();
    const ids = await q(
      'SELECT value, revoked_at, pii_scrubbed_at FROM identity_identifier WHERE identity_id = $1',
      [a],
    );
    expect(ids.every((r) => r.value === null && r.revoked_at && r.pii_scrubbed_at)).toBe(true);
    const creds = await q(
      'SELECT secret_hash, provider_subject, provider_email, revoked_at FROM credential WHERE identity_id = $1',
      [a],
    );
    expect(creds).toHaveLength(2);
    expect(
      creds.every(
        (r) => !r.secret_hash && !r.provider_subject && !r.provider_email && r.revoked_at,
      ),
    ).toBe(true);
    expect(await q('SELECT 1 FROM auth_session WHERE identity_id = $1', [a])).toHaveLength(0);
    const ev = await q(
      'SELECT identifier_hash, ip_address, detail, pii_scrubbed_at FROM auth_event WHERE identity_id = $1',
      [a],
    );
    expect(
      ev.every(
        (r) =>
          !r.identifier_hash &&
          !r.ip_address &&
          r.pii_scrubbed_at &&
          Object.keys(r.detail).length === 0,
      ),
    ).toBe(true);

    expect(
      await refused('UPDATE identity SET erased_at = clock_timestamp() WHERE id = $1', [a]),
    ).toMatch(/erasure is final/);
    expect(
      await refused('UPDATE auth_event SET pii_scrubbed_at = now() WHERE identity_id = $1', [a]),
    ).toMatch(/append-only/);
  });
});

describe('privileges', () => {
  it('keep the policy and the schema out of the application role', async () => {
    expect(await refused('UPDATE password_policy SET min_length = 4')).toMatch(/permission denied/);
    expect(await refused('CREATE TEMP TABLE shadow (id int)')).toMatch(/permission denied/);
    expect(await refused('CREATE TABLE intruder (id int)')).toMatch(/permission denied/);
  });
});
