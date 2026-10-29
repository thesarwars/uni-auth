import swc from 'unplugin-swc';
import { defineConfig } from 'vitest/config';

/**
 * The e2e suite drives the real local Hydra (docker compose up -d --wait, then
 * scripts/hydra-keys.sh and scripts/hydra-clients.sh) and listens on :3100, where Hydra's
 * urls.login, consent and logout point - so a running `npm run dev` must be stopped first.
 */
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
