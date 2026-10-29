// Creates a member to sign in as on a laptop, until sign-up arrives in part 5. Local only.
//
// The identity gets one verified email and a password, written as the application's role so
// every rule in the schema applies. The hash is the same "scrypt$N$r$p$salt$hash" the login
// application writes (src/credentials/password.service.ts).
//
// usage: npm run dev:member -- <email> <password>
import { randomBytes, scryptSync } from 'node:crypto';
import { resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import pg from 'pg';
import { loadEnv } from './env.mjs';

loadEnv(resolve(fileURLToPath(import.meta.url), '..', '..'));

if (process.env.NODE_ENV === 'production') {
  process.stderr.write('Refusing to run: NODE_ENV=production.\n');
  process.exit(1);
}
const [email, password] = process.argv.slice(2);
if (!email || !password) {
  process.stderr.write('usage: npm run dev:member -- <email> <password>\n');
  process.exit(1);
}

const salt = randomBytes(16);
const key = scryptSync(password, salt, 64, { N: 16384, r: 8, p: 1 });
const hash = Buffer.from(`scrypt$16384$8$1$${salt.toString('base64')}$${key.toString('base64')}`);

const client = new pg.Client({ connectionString: process.env.DATABASE_URL });
await client.connect();
try {
  await client.query('BEGIN');
  const {
    rows: [identity],
  } = await client.query('INSERT INTO identity DEFAULT VALUES RETURNING id');
  await client.query(
    `INSERT INTO identity_identifier (identity_id, kind, value, verified_at, is_primary)
     VALUES ($1, 'email', $2, now(), true)`,
    [identity.id, email.trim().toLowerCase()],
  );
  await client.query(
    `INSERT INTO credential (identity_id, kind, secret_hash, password_policy_id)
     VALUES ($1, 'password', $2, password_policy_in_effect())`,
    [identity.id, hash],
  );
  await client.query('COMMIT');
  process.stdout.write(`${email} -> identity ${identity.id}\n`);
} catch (err) {
  await client.query('ROLLBACK');
  process.stderr.write(`${err.message}\n`);
  process.exitCode = 1;
} finally {
  await client.end();
}
