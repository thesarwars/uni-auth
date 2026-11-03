// Creates or updates the login role a deployment's application connects as (uni_auth_api,
// a member of the NOLOGIN privilege role uni_auth_app), with the password in
// UNI_AUTH_DB_PASSWORD. The deployed counterpart of db-dev-roles.mjs; run by deploy-setup.sh.
// Setting the password again on every run is how it rotates: change the value, restart.
//
// usage: DATABASE_OWNER_URL=... UNI_AUTH_DB_PASSWORD=... node scripts/db-login-role.mjs
import { resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import pg from 'pg';
import { loadEnv } from './env.mjs';

loadEnv(resolve(fileURLToPath(import.meta.url), '..', '..'));

const url = process.env.DATABASE_OWNER_URL;
const password = process.env.UNI_AUTH_DB_PASSWORD;
if (!url || !password || password.length < 24) {
  process.stderr.write(
    'DATABASE_OWNER_URL and UNI_AUTH_DB_PASSWORD (24+ characters) must be set.\n',
  );
  process.exit(1);
}

const client = new pg.Client({ connectionString: url, application_name: 'uni-auth-setup' });
await client.connect();
try {
  // CREATE/ALTER ROLE take no bind parameters; the password goes in as an escaped literal.
  const literal = client.escapeLiteral(password);
  const { rowCount } = await client.query("SELECT 1 FROM pg_roles WHERE rolname = 'uni_auth_api'");
  await client.query(
    `${rowCount ? 'ALTER' : 'CREATE'} ROLE uni_auth_api LOGIN PASSWORD ${literal}`,
  );
  await client.query('GRANT uni_auth_app TO uni_auth_api');
  process.stdout.write(
    `uni_auth_api ${rowCount ? 'updated' : 'created'} -> member of uni_auth_app\n`,
  );
} finally {
  await client.end();
}
