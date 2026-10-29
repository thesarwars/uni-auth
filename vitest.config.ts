import { generateKeyPairSync } from 'node:crypto';
import swc from 'unplugin-swc';
import { defineConfig } from 'vitest/config';

/**
 * The e2e suite drives the real local Hydra (docker compose up -d --wait, then
 * scripts/hydra-keys.sh and scripts/hydra-clients.sh) and listens on :3100, where Hydra's
 * urls.login, consent and logout point - so a running `npm run dev` must be stopped first.
 */
// Google and Apple are stood in for by tests/support/fake-oidc.ts; Apple's key is made per run.
const appleKey = generateKeyPairSync('ec', { namedCurve: 'P-256' })
  .privateKey.export({ format: 'pem', type: 'pkcs8' })
  .toString();

const defaults: Record<string, string> = {
  NODE_ENV: 'test',
  LOG_LEVEL: 'error',
  HYDRA_ADMIN_URL: 'http://127.0.0.1:4445',
  COOKIE_SECRET: 'test-only-cookie-secret-0000000000000000',
  PROVIDER_NAME: 'uni-auth',
  HYDRA_PUBLIC_URL: 'http://localhost:4444',
  REDIS_URL: 'redis://127.0.0.1:6380',
  // A fresh namespace per run, so one run's failed attempts never lock out the next.
  THROTTLE_KEY_PREFIX: `uni-auth-test:${Date.now()}:`,
  GOOGLE_CLIENT_ID: 'test-google-client',
  GOOGLE_CLIENT_SECRET: 'test-google-secret',
  GOOGLE_ISSUER: 'http://localhost:4999/google',
  APPLE_CLIENT_ID: 'test.apple.services',
  APPLE_TEAM_ID: 'TESTTEAM01',
  APPLE_KEY_ID: 'TESTKEY001',
  APPLE_PRIVATE_KEY: appleKey,
  APPLE_ISSUER: 'http://localhost:4999/apple',
  // The identity database as the application's own role (scripts/db-dev-roles.mjs).
  DATABASE_URL: 'postgres://uni_auth_api:uni_auth_api@127.0.0.1:5434/identity',
};

export default defineConfig({
  plugins: [swc.vite({ module: { type: 'es6' } })],
  test: {
    include: ['tests/**/*.test.ts'],
    env: Object.fromEntries(Object.entries(defaults).map(([k, v]) => [k, process.env[k] ?? v])),
    fileParallelism: false,
    testTimeout: 30_000,
    hookTimeout: 60_000,
  },
});
