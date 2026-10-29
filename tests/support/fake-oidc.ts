import {
  createHash,
  createPrivateKey,
  createPublicKey,
  generateKeyPairSync,
  randomBytes,
  sign,
  verify,
} from 'node:crypto';
import { createServer, type Server } from 'node:http';

/**
 * Google and Apple, as far as the login application can tell: discovery, an authorize endpoint
 * that a test approves by hand, a token endpoint, and a JWKS. The token endpoint checks what the
 * real ones check - the code once, the redirect URI, Google's PKCE verifier, Apple's ES256 client
 * secret - so those halves of the flow are exercised, not assumed.
 */

export type FakeProvider = 'google' | 'apple';
export const FAKE_OIDC_PORT = 4999;
const BASE = `http://localhost:${FAKE_OIDC_PORT}`;
export const issuer = (p: FakeProvider) => `${BASE}/${p}`;

export interface FakeUser {
  sub: string;
  email?: string;
  email_verified?: boolean | string;
  /** Overrides, to test that the login application refuses them. */
  aud?: string;
  nonce?: string;
}

interface Grant {
  provider: FakeProvider;
  params: URLSearchParams;
  user: FakeUser;
}

export class FakeOidc {
  private server: Server | null = null;
  private readonly keys = generateKeyPairSync('rsa', { modulusLength: 2048 });
  private readonly grants = new Map<string, Grant>();
  /** Every token request refused, and why: a test can assert the reason. */
  readonly refusals: string[] = [];

  async start(): Promise<void> {
    this.server = createServer((req, res) => {
      let body = '';
      req.on('data', (c) => (body += c));
      req.on('end', () => {
        const url = new URL(req.url ?? '/', BASE);
        const [, provider, ...rest] = url.pathname.split('/') as [
          string,
          FakeProvider,
          ...string[],
        ];
        const route = rest.join('/');
        const json = (status: number, v: unknown) => {
          res.writeHead(status, { 'content-type': 'application/json' });
          res.end(JSON.stringify(v));
        };
        if (route === '.well-known/openid-configuration') {
          return json(200, {
            issuer: issuer(provider),
            authorization_endpoint: `${issuer(provider)}/authorize`,
            token_endpoint: `${issuer(provider)}/token`,
            jwks_uri: `${issuer(provider)}/jwks`,
          });
        }
        if (route === 'jwks') {
          return json(200, {
            keys: [
              {
                ...this.keys.publicKey.export({ format: 'jwk' }),
                kid: 'fake-1',
                alg: 'RS256',
                use: 'sig',
              },
            ],
          });
        }
        if (route === 'token' && req.method === 'POST') {
          const form = new URLSearchParams(body);
          const why = this.refuse(provider, form);
          if (why) {
            this.refusals.push(why);
            return json(400, { error: 'invalid_grant', error_description: why });
          }
          const grant = this.grants.get(form.get('code')!)!;
          this.grants.delete(form.get('code')!);
          return json(200, {
            access_token: 'upstream-at',
            token_type: 'Bearer',
            id_token: this.idToken(grant),
          });
        }
        json(404, { error: 'not_found' });
      });
    });
    await new Promise<void>((resolve) => this.server!.listen(FAKE_OIDC_PORT, 'localhost', resolve));
  }

  async stop(): Promise<void> {
    await new Promise<void>((resolve) =>
      this.server ? this.server.close(() => resolve()) : resolve(),
    );
  }

  /** The member approves at the provider: a code for the authorize request the app made. */
  approve(
    provider: FakeProvider,
    authorizeUrl: string,
    user: FakeUser,
  ): { redirectUri: string; code: string; state: string } {
    const params = new URL(authorizeUrl).searchParams;
    const code = randomBytes(16).toString('hex');
    this.grants.set(code, { provider, params, user });
    return { redirectUri: params.get('redirect_uri')!, code, state: params.get('state')! };
  }

  private refuse(provider: FakeProvider, form: URLSearchParams): string | null {
    const grant = this.grants.get(form.get('code') ?? '');
    if (!grant || grant.provider !== provider) return 'unknown or spent code';
    if (form.get('redirect_uri') !== grant.params.get('redirect_uri'))
      return 'redirect_uri mismatch';
    if (form.get('client_id') !== grant.params.get('client_id')) return 'client_id mismatch';
    if (provider === 'google') {
      if (form.get('client_secret') !== process.env.GOOGLE_CLIENT_SECRET)
        return 'bad client_secret';
      const challenge = createHash('sha256')
        .update(form.get('code_verifier') ?? '')
        .digest('base64url');
      if (challenge !== grant.params.get('code_challenge')) return 'PKCE verifier mismatch';
    } else {
      const why = appleSecretProblem(form.get('client_secret') ?? '');
      if (why) return why;
    }
    return null;
  }

  private idToken(g: Grant): string {
    const now = Math.floor(Date.now() / 1000);
    const claims: Record<string, unknown> = {
      iss: issuer(g.provider),
      aud: g.user.aud ?? g.params.get('client_id'),
      sub: g.user.sub,
      iat: now,
      exp: now + 600,
      nonce: g.user.nonce ?? g.params.get('nonce'),
      ...(g.user.email !== undefined ? { email: g.user.email } : {}),
      ...(g.user.email_verified !== undefined ? { email_verified: g.user.email_verified } : {}),
    };
    const h = b64({ alg: 'RS256', kid: 'fake-1', typ: 'JWT' });
    const p = b64(claims);
    const s = sign('RSA-SHA256', Buffer.from(`${h}.${p}`), this.keys.privateKey).toString(
      'base64url',
    );
    return `${h}.${p}.${s}`;
  }
}

/** Apple's client secret, checked the way Apple does: ES256 by the team's key, naming the client. */
function appleSecretProblem(jwt: string): string | null {
  const [h, p, s] = jwt.split('.');
  if (!h || !p || !s) return 'client_secret is not a JWT';
  const header = JSON.parse(Buffer.from(h, 'base64url').toString()) as Record<string, unknown>;
  const claims = JSON.parse(Buffer.from(p, 'base64url').toString()) as Record<string, unknown>;
  const publicKey = createPublicKey(createPrivateKey(process.env.APPLE_PRIVATE_KEY!));
  const ok = verify(
    'sha256',
    Buffer.from(`${h}.${p}`),
    { key: publicKey, dsaEncoding: 'ieee-p1363' },
    Buffer.from(s, 'base64url'),
  );
  if (!ok || header.alg !== 'ES256' || header.kid !== process.env.APPLE_KEY_ID)
    return 'client_secret signature';
  if (claims.iss !== process.env.APPLE_TEAM_ID || claims.sub !== process.env.APPLE_CLIENT_ID)
    return 'client_secret claims';
  if (claims.aud !== process.env.APPLE_ISSUER) return 'client_secret audience';
  if (typeof claims.exp !== 'number' || claims.exp < Date.now() / 1000)
    return 'client_secret expired';
  return null;
}

const b64 = (v: unknown) => Buffer.from(JSON.stringify(v)).toString('base64url');
