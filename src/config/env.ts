import './dotenv';

import { z } from 'zod';

/**
 * Environment is parsed once, at boot. A bad value exits the process rather than
 * surfacing as an undefined three layers down.
 *
 * .env is shared with docker-compose.yml, which reads the Hydra variables from it; the ones
 * below are the login application's.
 */
const Env = z.object({
  NODE_ENV: z.enum(['development', 'test', 'production']).default('development'),
  LOG_LEVEL: z.enum(['fatal', 'error', 'warn', 'info', 'debug', 'trace']).default('info'),
  /** Hydra's urls.login, urls.consent and urls.logout point here (deploy/hydra/hydra.yml). */
  PORT: z.coerce.number().int().positive().default(3100),
  HOST: z.string().default('0.0.0.0'),

  /**
   * Hydra's admin API. It accepts any login it is asked to, so it is reachable from this
   * server and nowhere else (AU-2); no browser ever sees this URL.
   */
  HYDRA_ADMIN_URL: z.string().url(),

  /**
   * Hydra's public origin, the issuer. A login request's request_url - the authorize URL that
   * started it - is followed only when it is on this origin.
   */
  HYDRA_PUBLIC_URL: z.string().url(),

  /** The identity database, as a login role in uni_auth_app (never the owner). */
  DATABASE_URL: z.string().url(),

  /** The sign-in throttle's counters (auth-plan.md section 9). */
  REDIS_URL: z.string().url(),
  /** Namespaces the throttle's keys, so a test run starts from zero. */
  THROTTLE_KEY_PREFIX: z.string().default('uni-auth:throttle:'),

  /**
   * How many proxies in front of this server to trust for the client address. 0 trusts none:
   * X-Forwarded-For is then ignored, so nobody can dodge the per-address throttle by sending one.
   */
  TRUST_PROXY_HOPS: z.coerce.number().int().min(0).max(5).default(0),

  /** Signs the CSRF cookie. 32+ characters. */
  COOKIE_SECRET: z.string().min(32),

  /**
   * The provider's name on the screens that are about the provider rather than a client:
   * "Sign out of <name>?" (auth-plan.md section 7.2). The brand is OQ-ONB-10's answer.
   */
  PROVIDER_NAME: z.string().min(1).default('uni-auth'),

  /** How long the provider remembers a sign-in: the 90-day ceiling auth_session enforces. */
  REMEMBER_SECONDS: z.coerce
    .number()
    .int()
    .positive()
    .max(90 * 24 * 3600)
    .default(90 * 24 * 3600),
});

const parsed = Env.safeParse(process.env);

if (!parsed.success) {
  const issues = parsed.error.issues.map((i) => `  ${i.path.join('.')}: ${i.message}`).join('\n');
  process.stderr.write(
    `Invalid environment:\n${issues}\n\nLocally the values come from .env: scripts/dev-secrets.sh\n`,
  );
  process.exit(1);
}

export const env = parsed.data;
export type Env = typeof env;
