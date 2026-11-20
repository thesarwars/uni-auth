// Grants, revokes and lists operators: who may use the operator console (/account/operator).
//
// Runs as the OWNER role: the application can only read the list (db/migrations/0017), so a flaw
// in the running server can't make anyone an operator. On the server:
//
//   docker compose -f docker-compose.prod.yml run --rm setup \
//     node scripts/operator.mjs grant someone@example.com "support team"
//
// usage: node scripts/operator.mjs grant  <email | phone | identity id> "<why>"
//        node scripts/operator.mjs revoke <email | phone | identity id> "<why>"
//        node scripts/operator.mjs list
//
// An operator signs in to the console with a passkey, so they need one on their account first.
import { resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import pg from 'pg';
import { loadEnv } from './env.mjs';

loadEnv(resolve(fileURLToPath(import.meta.url), '..', '..'));

const USAGE = `usage: node scripts/operator.mjs grant  <email | phone | identity id> "<why>"
       node scripts/operator.mjs revoke <email | phone | identity id> "<why>"
       node scripts/operator.mjs list
`;
const [command, who, note] = process.argv.slice(2);
if (
  !['grant', 'revoke', 'list'].includes(command) ||
  (command !== 'list' && (!who || !note?.trim()))
) {
  process.stderr.write(USAGE);
  process.exit(1);
}
const url = process.env.DATABASE_OWNER_URL;
if (!url) {
  process.stderr.write('DATABASE_OWNER_URL must be set.\n');
  process.exit(1);
}

const client = new pg.Client({ connectionString: url, application_name: 'uni-auth-operator' });
await client.connect();
try {
  if (command === 'list') {
    const { rows } = await client.query(
      `SELECT o.identity_id, o.granted_at, o.grant_note,
              (SELECT value FROM identity_identifier ii
                WHERE ii.identity_id = o.identity_id AND ii.is_primary AND ii.revoked_at IS NULL
                ORDER BY ii.kind LIMIT 1) AS primary_identifier
         FROM operator o WHERE o.revoked_at IS NULL ORDER BY o.granted_at`,
    );
    if (rows.length === 0) process.stdout.write('No operators.\n');
    for (const r of rows) {
      process.stdout.write(
        `${r.primary_identifier ?? '(no address)'}  ${r.identity_id}  since ${r.granted_at.toISOString().slice(0, 10)}  ${r.grant_note}\n`,
      );
    }
  } else {
    const identityId = await find(who.trim());
    if (!identityId) {
      process.stderr.write(`No active account found for ${who}.\n`);
      process.exitCode = 1;
    } else if (command === 'grant') {
      const { rowCount } = await client.query(
        `INSERT INTO operator (identity_id, grant_note) VALUES ($1, $2)
         ON CONFLICT (identity_id) WHERE revoked_at IS NULL DO NOTHING`,
        [identityId, note.trim()],
      );
      process.stdout.write(
        rowCount ? `${who} is now an operator.\n` : `${who} is already an operator.\n`,
      );
    } else {
      const { rowCount } = await client.query(
        `UPDATE operator SET revoked_at = now(), revoke_note = $2
          WHERE identity_id = $1 AND revoked_at IS NULL`,
        [identityId, note.trim()],
      );
      process.stdout.write(
        rowCount ? `${who} is no longer an operator.\n` : `${who} wasn't an operator.\n`,
      );
    }
  }
} finally {
  await client.end();
}

/** The active identity an email address, phone number or identity id names. */
async function find(value) {
  const uuid = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
  const { rows } = uuid.test(value)
    ? await client.query(`SELECT id FROM identity WHERE id = $1 AND status = 'active'`, [value])
    : await client.query(
        `SELECT i.id FROM identity_identifier ii JOIN identity i ON i.id = ii.identity_id
          WHERE ii.kind = $1 AND ii.value = $2 AND ii.verified_at IS NOT NULL
            AND ii.revoked_at IS NULL AND i.status = 'active'`,
        value.includes('@')
          ? ['email', value.toLowerCase()]
          : ['phone', value.replace(/[\s()-]/g, '')],
      );
  return rows[0]?.id ?? null;
}
