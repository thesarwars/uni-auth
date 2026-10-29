import pg from 'pg';
import { afterAll, afterEach, beforeAll, beforeEach } from 'vitest';

/**
 * The identity database as the application's own role, for tests of the schema's rules. Call
 * rolledBack() once per file: every test then runs in a transaction that is rolled back.
 */

/** A well-formed scrypt hash; the schema checks the format, never the secret. */
export const HASH = Buffer.from('scrypt$16384$8$1$c2FsdHNhbHQ=$aGFzaGhhc2hoYXNo');

let pool: pg.Pool;
let db: pg.PoolClient;

export function rolledBack(): void {
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
}

export const q = async <T extends pg.QueryResultRow = Record<string, any>>(
  sql: string,
  params: unknown[] = [],
): Promise<T[]> => (await db.query<T>(sql, params)).rows;

export const one = async <T extends pg.QueryResultRow = Record<string, any>>(
  sql: string,
  params: unknown[] = [],
): Promise<T> => (await q<T>(sql, params))[0]!;

/** Runs a statement that must fail, inside a savepoint so the test can carry on. */
export async function refused(sql: string, params: unknown[] = []): Promise<string> {
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

export const newIdentity = async (): Promise<string> =>
  (await one<{ id: string }>('INSERT INTO identity DEFAULT VALUES RETURNING id')).id;

export const policy = async (): Promise<string> =>
  (await one<{ id: string }>('SELECT password_policy_in_effect() AS id')).id;

export async function password(identityId: string): Promise<string> {
  return (
    await one<{ id: string }>(
      `INSERT INTO credential (identity_id, kind, secret_hash, password_policy_id)
       VALUES ($1, 'password', $2, $3) RETURNING id`,
      [identityId, HASH, await policy()],
    )
  ).id;
}

export async function session(identityId: string, credentialId: string | null, sid: string) {
  return (
    await one<{ id: string }>(
      `INSERT INTO auth_session (identity_id, credential_id, sid, client_id, expires_at)
       VALUES ($1, $2, $3, 'gsn-web', now() + interval '1 day') RETURNING id`,
      [identityId, credentialId, sid],
    )
  ).id;
}

export const sessionState = (id: string) =>
  one<{ revoked_at: Date | null; revoke_reason: string | null }>(
    'SELECT revoked_at, revoke_reason FROM auth_session WHERE id = $1',
    [id],
  );
