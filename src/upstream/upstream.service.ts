import { Injectable } from '@nestjs/common';
import {
  createHash,
  createPrivateKey,
  createPublicKey,
  randomBytes,
  sign,
  verify,
  type JsonWebKey,
} from 'node:crypto';
import { z } from 'zod';
import { env } from '../config/env';
import { RedisService } from '../redis/redis.service';

export type Provider = 'google' | 'apple';
export const PROVIDERS: readonly Provider[] = ['google', 'apple'];

/** What a verified ID token says. `subject` is the provider's stable, opaque user id. */
export interface UpstreamIdentity {
  provider: Provider;
  subject: string;
  email: string | null;
  emailVerified: boolean;
}

/** The sign-in an upstream round trip belongs to, kept server-side for its ten minutes. */
interface Pending {
  provider: Provider;
  loginChallenge: string;
  nonce: string;
  verifier: string | null;
}

export class UpstreamRefused extends Error {}

interface Spec {
  issuer: () => string;
  clientId: () => string | undefined;
  clientSecret: () => string;
  /** Apple returns the code as a cross-site POST, because it may also send the member's name. */
  responseMode: 'query' | 'form_post';
  scope: string;
  /** Google supports PKCE; Apple does not document it, and its client secret binds the client. */
  pkce: boolean;
}

const SPECS: Record<Provider, Spec> = {
  google: {
    issuer: () => env.GOOGLE_ISSUER,
    clientId: () => env.GOOGLE_CLIENT_ID,
    clientSecret: () => env.GOOGLE_CLIENT_SECRET!,
    responseMode: 'query',
    scope: 'openid email',
    pkce: true,
  },
  apple: {
    issuer: () => env.APPLE_ISSUER,
    clientId: () => env.APPLE_CLIENT_ID,
    clientSecret: appleClientSecret,
    responseMode: 'form_post',
    scope: 'openid email',
    pkce: false,
  },
};

const Discovery = z.object({
  issuer: z.string(),
  authorization_endpoint: z.string().url(),
  token_endpoint: z.string().url(),
  jwks_uri: z.string().url(),
});
type Discovery = z.infer<typeof Discovery>;

type Jwk = JsonWebKey & { kid?: string };

const STATE_TTL_SECONDS = 600;
const CACHE_MS = 60 * 60 * 1000;
const CLOCK_SKEW_SECONDS = 60;

/**
 * Sign in with Google and with Apple, as OpenID Connect authorization-code flows this
 * application runs itself (auth-plan.md section 12.2, part 4). No client posts an ID token any
 * more: the member leaves for the provider from here and comes back here.
 *
 * The round trip is bound three ways. `state` names the pending sign-in in Redis, once, and a
 * signed cookie ties it to the browser that left; `nonce` ties the ID token to that same round
 * trip; and PKCE, where the provider supports it, ties the code to it. The ID token is checked
 * against the provider's published keys, issuer, audience, expiry and nonce. Nothing in it but
 * `sub`, `email` and `email_verified` is used.
 */
@Injectable()
export class Upstream {
  private readonly discovery = new Map<Provider, { at: number; doc: Discovery }>();
  private readonly jwks = new Map<string, { at: number; keys: Jwk[] }>();

  constructor(private readonly redis: RedisService) {}

  configured(provider: Provider): boolean {
    return !!SPECS[provider].clientId();
  }

  /** Whose names the identifier screen shows a button for. */
  enabled(): Provider[] {
    return PROVIDERS.filter((p) => this.configured(p));
  }

  callbackUrl(provider: Provider): string {
    return `${env.LOGIN_PUBLIC_URL}/upstream/${provider}/callback`;
  }

  /** Where to send the member, and the state their browser must come back with. */
  async start(provider: Provider, loginChallenge: string): Promise<{ url: string; state: string }> {
    const spec = SPECS[provider];
    const doc = await this.discover(provider);
    const state = token();
    const nonce = token();
    const verifier = spec.pkce ? token() : null;
    const pending: Pending = { provider, loginChallenge, nonce, verifier };
    await this.redis.client.set(
      this.stateKey(state),
      JSON.stringify(pending),
      'EX',
      STATE_TTL_SECONDS,
    );

    const url = new URL(doc.authorization_endpoint);
    url.search = new URLSearchParams({
      client_id: spec.clientId()!,
      redirect_uri: this.callbackUrl(provider),
      response_type: 'code',
      response_mode: spec.responseMode,
      scope: spec.scope,
      state,
      nonce,
      ...(verifier
        ? {
            code_challenge: createHash('sha256').update(verifier).digest('base64url'),
            code_challenge_method: 'S256',
          }
        : {}),
    }).toString();
    return { url: url.toString(), state };
  }

  /**
   * The pending sign-in a callback names - once: a state is spent by the first callback that
   * presents it, matching cookie or not. null when it is unknown, spent, expired, for another
   * provider, or not this browser's.
   */
  async claim(
    provider: Provider,
    state: string,
    cookieState: string | null,
  ): Promise<Pending | null> {
    const raw = await this.redis.client.getdel(this.stateKey(state));
    if (!raw) return null;
    const pending = JSON.parse(raw) as Pending;
    if (pending.provider !== provider || cookieState !== state) return null;
    return pending;
  }

  /** Exchanges the code and verifies the ID token it returns. Throws UpstreamRefused. */
  async finish(pending: Pending, code: string): Promise<UpstreamIdentity> {
    const spec = SPECS[pending.provider];
    const doc = await this.discover(pending.provider);
    const res = await fetch(doc.token_endpoint, {
      method: 'POST',
      headers: { 'content-type': 'application/x-www-form-urlencoded', accept: 'application/json' },
      body: new URLSearchParams({
        grant_type: 'authorization_code',
        code,
        redirect_uri: this.callbackUrl(pending.provider),
        client_id: spec.clientId()!,
        client_secret: spec.clientSecret(),
        ...(pending.verifier ? { code_verifier: pending.verifier } : {}),
      }).toString(),
      signal: AbortSignal.timeout(10_000),
    });
    if (!res.ok) throw new UpstreamRefused(`token endpoint answered ${res.status}`);
    const body = (await res.json()) as { id_token?: unknown };
    if (typeof body.id_token !== 'string') throw new UpstreamRefused('no id_token');
    return this.verifyIdToken(pending, doc, body.id_token);
  }

  private async verifyIdToken(
    pending: Pending,
    doc: Discovery,
    idToken: string,
  ): Promise<UpstreamIdentity> {
    const parts = idToken.split('.');
    if (parts.length !== 3) throw new UpstreamRefused('malformed id_token');
    const [h, p, s] = parts as [string, string, string];
    const header = decodeJson(h);
    if (header.alg !== 'RS256' || typeof header.kid !== 'string') {
      throw new UpstreamRefused('unsupported id_token header');
    }
    const jwk = await this.signingKey(doc.jwks_uri, header.kid);
    const signed = verify(
      'RSA-SHA256',
      Buffer.from(`${h}.${p}`),
      createPublicKey({ key: jwk, format: 'jwk' }),
      Buffer.from(s, 'base64url'),
    );
    if (!signed) throw new UpstreamRefused('bad signature');

    const c = decodeJson(p);
    const now = Math.floor(Date.now() / 1000);
    // Google has issued tokens under both spellings of its issuer.
    const issuers = [doc.issuer, doc.issuer.replace(/^https:\/\//, '')];
    if (typeof c.iss !== 'string' || !issuers.includes(c.iss)) throw new UpstreamRefused('issuer');
    const aud = Array.isArray(c.aud) ? c.aud : [c.aud];
    if (!aud.includes(SPECS[pending.provider].clientId())) throw new UpstreamRefused('audience');
    if (typeof c.exp !== 'number' || c.exp + CLOCK_SKEW_SECONDS < now) {
      throw new UpstreamRefused('expired');
    }
    if (typeof c.iat === 'number' && c.iat - CLOCK_SKEW_SECONDS > now) {
      throw new UpstreamRefused('issued in the future');
    }
    if (c.nonce !== pending.nonce) throw new UpstreamRefused('nonce');
    if (typeof c.sub !== 'string' || c.sub.length === 0 || c.sub.length > 255) {
      throw new UpstreamRefused('subject');
    }

    const email = typeof c.email === 'string' ? c.email.trim().toLowerCase() : null;
    return {
      provider: pending.provider,
      subject: c.sub,
      email,
      // Apple sends the flag as the string "true".
      emailVerified: email !== null && (c.email_verified === true || c.email_verified === 'true'),
    };
  }

  private async discover(provider: Provider): Promise<Discovery> {
    const cached = this.discovery.get(provider);
    if (cached && Date.now() - cached.at < CACHE_MS) return cached.doc;
    const issuer = SPECS[provider].issuer();
    const res = await fetch(`${issuer}/.well-known/openid-configuration`, {
      signal: AbortSignal.timeout(10_000),
    });
    if (!res.ok) throw new Error(`${provider} discovery failed: ${res.status}`);
    const doc = Discovery.parse(await res.json());
    if (doc.issuer !== issuer) throw new Error(`${provider} discovery names issuer ${doc.issuer}`);
    this.discovery.set(provider, { at: Date.now(), doc });
    return doc;
  }

  private async signingKey(uri: string, kid: string): Promise<Jwk> {
    const cached = this.jwks.get(uri);
    let keys = cached && Date.now() - cached.at < CACHE_MS ? cached.keys : null;
    let found = keys?.find((k) => k.kid === kid);
    if (!found) {
      // An unknown kid usually means the provider rotated its keys: refetch once.
      const res = await fetch(uri, { signal: AbortSignal.timeout(10_000) });
      if (!res.ok) throw new Error(`JWKS fetch failed: ${res.status}`);
      keys = ((await res.json()) as { keys: Jwk[] }).keys;
      this.jwks.set(uri, { at: Date.now(), keys });
      found = keys.find((k) => k.kid === kid);
    }
    if (!found) throw new UpstreamRefused('unknown signing key');
    return found;
  }

  private stateKey(state: string): string {
    return `uni-auth:upstream:${state}`;
  }
}

/**
 * Apple's client secret: a JWT signed with the team's Sign in with Apple key, naming the team as
 * issuer and the Services ID as subject. Short-lived, made per request.
 */
function appleClientSecret(): string {
  const now = Math.floor(Date.now() / 1000);
  const header = b64json({ alg: 'ES256', kid: env.APPLE_KEY_ID });
  const claims = b64json({
    iss: env.APPLE_TEAM_ID,
    iat: now,
    exp: now + 300,
    aud: env.APPLE_ISSUER,
    sub: env.APPLE_CLIENT_ID,
  });
  const signature = sign('sha256', Buffer.from(`${header}.${claims}`), {
    key: createPrivateKey(env.APPLE_PRIVATE_KEY!),
    dsaEncoding: 'ieee-p1363',
  });
  return `${header}.${claims}.${signature.toString('base64url')}`;
}

const token = (): string => randomBytes(32).toString('base64url');
const b64json = (v: unknown): string => Buffer.from(JSON.stringify(v)).toString('base64url');

function decodeJson(segment: string): Record<string, unknown> {
  try {
    return JSON.parse(Buffer.from(segment, 'base64url').toString('utf8')) as Record<
      string,
      unknown
    >;
  } catch {
    throw new UpstreamRefused('malformed id_token');
  }
}
