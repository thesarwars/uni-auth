// Creates the login role the application connects as. Local and CI only.
//
// The migration creates uni_auth_app as a NOLOGIN privilege role: it carries the privileges and
// nobody connects as it. A deployment creates one login role per deploy unit and grants it
// membership, so credentials rotate without touching the privilege model. This script does that
// with a well-known password so a laptop works, and refuses to run when NODE_ENV says production.
//
// usage: node scripts/db-dev-roles.mjs
import { resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import pg from 'pg';
import { loadEnv } from './env.mjs';

loadEnv(resolve(fileURLToPath(import.meta.url), '..', '..'));

if (process.env.NODE_ENV === 'production') {
  process.stderr.write('Refusing to run: NODE_ENV=production. Provision login roles properly.\n');
  process.exit(1);
}
const url = process.env.DATABASE_OWNER_URL;
if (!url) {
  process.stderr.write('DATABASE_OWNER_URL must be set (scripts/dev-secrets.sh).\n');
  process.exit(1);
}

/** login role -> the privilege role it is granted. */
const LOGIN_ROLES = [['uni_auth_api', 'uni_auth_app']];

const client = new pg.Client({ connectionString: url });
await client.connect();
try {
  for (const [login, memberOf] of LOGIN_ROLES) {
    await client.query(`DO $$
      BEGIN
        IF EXISTS (SELECT 1 FROM pg_catalog.pg_roles WHERE rolname = '${login}') THEN
          ALTER ROLE ${login} LOGIN PASSWORD '${login}';
        ELSE
          CREATE ROLE ${login} LOGIN PASSWORD '${login}';
        END IF;
      END $$;`);
    await client.query(`GRANT ${memberOf} TO ${login}`);
    process.stdout.write(`${login} -> member of ${memberOf}\n`);
  }
} finally {
  await client.end();
}
