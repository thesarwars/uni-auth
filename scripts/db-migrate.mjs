// Applies db/migrations/*.sql in order, as the OWNER role, each in its own transaction.
//
// The owner, not the application's role: migrations create roles and revoke TEMPORARY, and the
// running application never holds these credentials.
//
// usage: node scripts/db-migrate.mjs      (reads DATABASE_OWNER_URL from the environment or .env)
import { readdir, readFile } from 'node:fs/promises';
import { join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import pg from 'pg';
import { loadEnv } from './env.mjs';

const ROOT = resolve(fileURLToPath(import.meta.url), '..', '..');
const DIR = join(ROOT, 'db', 'migrations');
loadEnv(ROOT);

const url = process.env.DATABASE_OWNER_URL;
if (!url) {
  process.stderr.write('DATABASE_OWNER_URL must be set (scripts/dev-secrets.sh).\n');
  process.exit(1);
}

const client = new pg.Client({ connectionString: url, application_name: 'uni-auth-migrate' });
await client.connect();
await client.query(`
  CREATE TABLE IF NOT EXISTS schema_migration (
    filename    text PRIMARY KEY,
    applied_at  timestamptz NOT NULL DEFAULT now()
  )`);

const applied = new Set(
  (await client.query('SELECT filename FROM schema_migration')).rows.map((r) => r.filename),
);
const files = (await readdir(DIR)).filter((f) => f.endsWith('.sql')).sort();

let count = 0;
for (const file of files) {
  if (applied.has(file)) continue;
  process.stdout.write(`applying ${file} ... `);
  try {
    await client.query('BEGIN');
    await client.query(await readFile(join(DIR, file), 'utf8'));
    await client.query('INSERT INTO schema_migration (filename) VALUES ($1)', [file]);
    await client.query('COMMIT');
    process.stdout.write('ok\n');
    count += 1;
  } catch (err) {
    await client.query('ROLLBACK');
    process.stderr.write(`FAILED\n${String(err)}\n`);
    await client.end();
    process.exit(1);
  }
}
const { rows } = await client.query(
  "SELECT count(*)::int AS n FROM pg_tables WHERE schemaname = 'public'",
);
process.stdout.write(`${count} migration(s) applied. ${rows[0].n} tables present.\n`);
await client.end();
