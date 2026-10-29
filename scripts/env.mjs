// Loads .env into process.env for the plain scripts, without overwriting what is already set:
// in CI and deployments the platform supplies the environment and there is no file.
import { readFileSync } from 'node:fs';
import { join } from 'node:path';

export function loadEnv(root) {
  let text;
  try {
    text = readFileSync(join(root, '.env'), 'utf8');
  } catch {
    return;
  }
  for (const line of text.split('\n')) {
    const m = /^([A-Z0-9_]+)=(.*)$/.exec(line.trim());
    if (m && process.env[m[1]] === undefined) process.env[m[1]] = m[2].replace(/\s+#.*$/, '');
  }
}
