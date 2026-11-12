import './dotenv';

import { z } from 'zod';

/**
 * Environment is parsed once, at boot. A bad value exits the process rather than
 * surfacing as an undefined three layers down.
 *
 * .env is shared with docker-compose.yml, which reads the Hydra variables from it; the ones
 * below are the login application's.
 */
/** A URL, or unset: compose passes an unset one as an empty string. */
const optionalUrl = z.preprocess((v) => (v === '' ? undefined : v), z.string().url().optional());

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
   * What Hydra sends as `Authorization: Bearer <secret>` when it calls the refresh hook
   * (hydra.yml oauth2.refresh_token_hook). The same value is given to Hydra.
   */
  HYDRA_HOOK_SECRET: z.string().min(32),

  /**
   * The uni-auth-service client's secret (deploy/hydra/clients/uni-auth-service.json): the
   * client-credentials grant this application uses to call a product's internal API.
   */
  UNI_AUTH_SERVICE_SECRET: z.string().min(32),

  /**
   * The account centre's client secret (deploy/hydra/clients/entity-auth-account.json): the
   * account pages sign the member in through Hydra like any client (account-plan.md AC-D1).
   */
  ENTITY_AUTH_ACCOUNT_SECRET: z.string().min(32),

  /**
   * Where an identity notice is delivered - "this identity closed", "this identity was erased" -
   * with a uni-auth-service token for IDENTITY_NOTICE_AUDIENCE (auth-plan.md section 12.2, part
   * 7). One product for now: GSN's Auth service.
   */
  IDENTITY_NOTICE_URL: z.string().url(),
  IDENTITY_NOTICE_AUDIENCE: z.string().min(1).default('gsn-api-internal'),
  /** How often undelivered notices are looked for. */
  IDENTITY_NOTICE_POLL_MS: z.coerce.number().int().min(100).default(5000),

  /**
   * The provider's name on the screens that are about the provider rather than a client:
   * "Sign out of <name>?" (auth-plan.md section 7.2). The brand is OQ-ONB-10's answer.
   */
  PROVIDER_NAME: z.string().min(1).default('entity-auth'),

  /** The footer links on every screen: help, privacy notice and terms. Each is left out unset. */
  HELP_URL: optionalUrl,
  PRIVACY_URL: optionalUrl,
  TERMS_URL: optionalUrl,

  /** How long the provider remembers a sign-in: the 90-day ceiling auth_session enforces. */
  REMEMBER_SECONDS: z.coerce
    .number()
    .int()
    .positive()
    .max(90 * 24 * 3600)
    .default(90 * 24 * 3600),

  /**
   * This application's own public origin. Google and Apple send the member back to
   * <origin>/upstream/<provider>/callback, which must be registered with them exactly.
   */
  LOGIN_PUBLIC_URL: z.string().url().default('http://localhost:3100'),

  /**
   * Sign in with Google: an OAuth client of type "Web application" in Google Cloud. Unset, the
   * button is not shown. The issuer is overridable only so the tests can stand in for Google.
   */
  GOOGLE_CLIENT_ID: z.string().optional(),
  GOOGLE_CLIENT_SECRET: z.string().optional(),
  GOOGLE_ISSUER: z.string().url().default('https://accounts.google.com'),

  /**
   * Sign in with Apple: a Services ID (the client id), the team, and a Sign in with Apple key
   * (.p8, PEM; literal \n allowed). Apple takes no static secret: each token request is
   * authenticated by a short JWT signed with that key.
   */
  APPLE_CLIENT_ID: z.string().optional(),
  APPLE_TEAM_ID: z.string().optional(),
  APPLE_KEY_ID: z.string().optional(),
  APPLE_PRIVATE_KEY: z
    .string()
    .optional()
    .transform((v) => v?.replace(/\\n/g, '\n')),
  APPLE_ISSUER: z.string().url().default('https://appleid.apple.com'),

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

  /**
   * WhatsApp delivery. meta sends codes through Meta's Cloud API, as an approved AUTHENTICATION
   * template; log writes them to the log (never in
   * production); off accepts no phone number at all, for a deployment without WhatsApp.
   */
  WHATSAPP_DELIVERY: z.enum(['meta', 'log', 'off']).default('log'),
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
  !!parsed.data.GOOGLE_CLIENT_ID !== !!parsed.data.GOOGLE_CLIENT_SECRET &&
    'GOOGLE_CLIENT_ID and GOOGLE_CLIENT_SECRET go together',
  [
    parsed.data.APPLE_CLIENT_ID,
    parsed.data.APPLE_TEAM_ID,
    parsed.data.APPLE_KEY_ID,
    parsed.data.APPLE_PRIVATE_KEY,
  ].filter(Boolean).length %
    4 !==
    0 && 'APPLE_CLIENT_ID, APPLE_TEAM_ID, APPLE_KEY_ID and APPLE_PRIVATE_KEY go together',
].filter(Boolean);
if (deliveryProblems.length) {
  process.stderr.write(`Invalid environment:\n  ${deliveryProblems.join('\n  ')}\n`);
  process.exit(1);
}

export const env = parsed.data;
export type Env = typeof env;
