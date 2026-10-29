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
   * The proxies in front of this server whose X-Forwarded-For is believed, as comma-separated
   * IPs or CIDRs (the load balancer's subnet). Empty believes none, so a client cannot dodge the
   * per-address throttle by sending the header. Never a hop count: that trusts the header from a
   * client that reaches the server directly.
   */
  TRUSTED_PROXIES: z
    .string()
    .default('')
    .transform((v) =>
      v
        .split(',')
        .map((s) => s.trim())
        .filter(Boolean),
    ),

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

  /** How long a one-time code lives. The schema's ceiling is fifteen minutes. */
  OTP_TTL_SECONDS: z.coerce
    .number()
    .int()
    .min(60)
    .max(15 * 60)
    .default(10 * 60),

  /**
   * Email delivery. `smtp` sends through any provider's SMTP relay; `log` writes the message to
   * the log instead, for a laptop and the tests, and is refused in production - a logged code
   * is a credential in a log file.
   */
  EMAIL_DELIVERY: z.enum(['smtp', 'log']).default('log'),
  SMTP_HOST: z.string().optional(),
  SMTP_PORT: z.coerce.number().int().positive().default(587),
  SMTP_SECURE: z
    .enum(['true', 'false'])
    .default('false')
    .transform((v) => v === 'true'),
  SMTP_USER: z.string().optional(),
  SMTP_PASS: z.string().optional(),
  SMTP_FROM: z.string().default('uni-auth <no-reply@localhost>'),

  /** WhatsApp delivery through Meta's Cloud API, as an approved AUTHENTICATION template. */
  WHATSAPP_DELIVERY: z.enum(['meta', 'log']).default('log'),
  WHATSAPP_PHONE_NUMBER_ID: z.string().optional(),
  WHATSAPP_ACCESS_TOKEN: z.string().optional(),
  WHATSAPP_TEMPLATE_NAME: z.string().default('sign_in_code'),
  WHATSAPP_TEMPLATE_LANGUAGE: z.string().default('en'),
  WHATSAPP_API_VERSION: z.string().default('v21.0'),
});

const parsed = Env.safeParse(process.env);

if (!parsed.success) {
  const issues = parsed.error.issues.map((i) => `  ${i.path.join('.')}: ${i.message}`).join('\n');
  process.stderr.write(
    `Invalid environment:\n${issues}\n\nLocally the values come from .env: scripts/dev-secrets.sh\n`,
  );
  process.exit(1);
}

const deliveryProblems = [
  parsed.data.NODE_ENV === 'production' &&
    parsed.data.EMAIL_DELIVERY === 'log' &&
    'EMAIL_DELIVERY=log in production: codes would be written to the log',
  parsed.data.NODE_ENV === 'production' &&
    parsed.data.WHATSAPP_DELIVERY === 'log' &&
    'WHATSAPP_DELIVERY=log in production: codes would be written to the log',
  parsed.data.EMAIL_DELIVERY === 'smtp' &&
    !parsed.data.SMTP_HOST &&
    'EMAIL_DELIVERY=smtp needs SMTP_HOST',
  parsed.data.WHATSAPP_DELIVERY === 'meta' &&
    !(parsed.data.WHATSAPP_PHONE_NUMBER_ID && parsed.data.WHATSAPP_ACCESS_TOKEN) &&
    'WHATSAPP_DELIVERY=meta needs WHATSAPP_PHONE_NUMBER_ID and WHATSAPP_ACCESS_TOKEN',
].filter(Boolean);
if (deliveryProblems.length) {
  process.stderr.write(`Invalid environment:\n  ${deliveryProblems.join('\n  ')}\n`);
  process.exit(1);
}

export const env = parsed.data;
export type Env = typeof env;
