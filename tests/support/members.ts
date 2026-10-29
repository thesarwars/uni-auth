import pg from 'pg';
import { randomBytes } from 'node:crypto';
import { PasswordService } from '../../src/credentials/password.service';

/**
 * Members for the e2e suite, written straight into the identity database as the application's
 * role - sign-up arrives in part 5. Each has a fresh address, so tests never share a throttle
 * counter or a lockout. Identities are never deleted (the schema forbids it), so a local
 * database keeps them; they are inert.
 */

export interface Member {
  identityId: string;
  email: string;
  password: string;
}

let pool: pg.Pool | null = null;
const db = () => (pool ??= new pg.Pool({ connectionString: process.env.DATABASE_URL, max: 2 }));

export async function closeMembers(): Promise<void> {
  await pool?.end();
  pool = null;
}

export async function createMember(opts: { password?: string | null } = {}): Promise<Member> {
  const email = `member-${randomBytes(6).toString('hex')}@example.com`;
  const password = opts.password === undefined ? 'Correct-Horse-9' : opts.password;
  const client = await db().connect();
  try {
    await client.query('BEGIN');
    const {
      rows: [identity],
    } = await client.query<{ id: string }>('INSERT INTO identity DEFAULT VALUES RETURNING id');
    await client.query(
      `INSERT INTO identity_identifier (identity_id, kind, value, verified_at, is_primary)
       VALUES ($1, 'email', $2, now(), true)`,
      [identity!.id, email],
    );
    if (password !== null) {
      await client.query(
        `INSERT INTO credential (identity_id, kind, secret_hash, password_policy_id)
         VALUES ($1, 'password', $2, password_policy_in_effect())`,
        [identity!.id, await new PasswordService().hash(password)],
      );
    }
    await client.query('COMMIT');
    return { identityId: identity!.id, email, password: password ?? '' };
  } catch (err) {
    await client.query('ROLLBACK');
    throw err;
  } finally {
    client.release();
  }
}

export async function sql<T extends pg.QueryResultRow = Record<string, any>>(
  text: string,
  params: unknown[] = [],
): Promise<T[]> {
  return (await db().query<T>(text, params)).rows;
}
