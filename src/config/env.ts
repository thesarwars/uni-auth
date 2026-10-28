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

  /**
   * TEMPORARY, until part 4 brings real credentials: the login screen offers "Continue as"
   * this subject, and anyone who reaches it signs in as them. Refused in production.
   */
  DEV_TEST_SUBJECT: z.preprocess((v) => (v === '' ? undefined : v), z.string().min(1).optional()),
});

const parsed = Env.safeParse(process.env);

if (!parsed.success) {
  const issues = parsed.error.issues.map((i) => `  ${i.path.join('.')}: ${i.message}`).join('\n');
  process.stderr.write(
    `Invalid environment:\n${issues}\n\nLocally the values come from .env: scripts/dev-secrets.sh\n`,
  );
  process.exit(1);
}

if (parsed.data.DEV_TEST_SUBJECT && parsed.data.NODE_ENV === 'production') {
  process.stderr.write('DEV_TEST_SUBJECT is set. It signs anyone in; never in production.\n');
  process.exit(1);
}

export const env = parsed.data;
export type Env = typeof env;
