import { Injectable } from '@nestjs/common';
import { createHash, randomBytes, timingSafeEqual } from 'node:crypto';
import { z } from 'zod';
import { env } from '../config/env';

export const ACCOUNT_CLIENT_ID = 'entity-auth-account';

export const accountRedirectUri = (): string => `${env.LOGIN_PUBLIC_URL}/account/callback`;
export const accountSignedOutUri = (): string => `${env.LOGIN_PUBLIC_URL}/account/signed-out`;

const TokenResponse = z.object({ id_token: z.string() });

const IdTokenClaims = z.object({
  iss: z.string(),
  sub: z.string().min(1),
  aud: z.union([z.string(), z.array(z.string())]),
  exp: z.number(),
  nonce: z.string(),
  sid: z.string().min(1),
  auth_time: z.number(),
});
export type IdTokenClaims = z.infer<typeof IdTokenClaims>;

/** The callback's code did not come back as a usable sign-in. */
export class AccountSignInFailed extends Error {}

/**
 * The account centre as an OpenID Connect client of entity-auth's own Hydra (account-plan.md
 * AC-D1): authorization code with PKCE, and a client secret, as a confidential client.
 *
 * The ID token arrives straight from Hydra's token endpoint, over the connection this client
 * authenticated, so OpenID Connect Core 3.1.3.7 lets the issuer's TLS stand in for checking its
 * signature. The claims are still checked: issuer, audience, expiry, and the nonce this sign-in
 * sent.
 */
@Injectable()
export class AccountOidc {
  /**
   * Where to send the browser to sign in. `confirm` makes it a re-authentication of the member
   * that ID token names: prompt=login and max_age=0, so Hydra asks again whatever the session.
   */
  start(confirm?: { idToken: string }): {
    url: string;
    state: string;
    verifier: string;
    nonce: string;
  } {
    const state = token();
    const nonce = token();
    const verifier = token();
    const params = new URLSearchParams({
      client_id: ACCOUNT_CLIENT_ID,
      response_type: 'code',
      scope: 'openid',
      redirect_uri: accountRedirectUri(),
      state,
      nonce,
      code_challenge: createHash('sha256').update(verifier).digest('base64url'),
      code_challenge_method: 'S256',
    });
    if (confirm) {
      params.set('prompt', 'login');
      params.set('max_age', '0');
      params.set('id_token_hint', confirm.idToken);
    }
    return { url: `${env.HYDRA_PUBLIC_URL}/oauth2/auth?${params}`, state, verifier, nonce };
  }

  async finish(
    code: string,
    verifier: string,
    nonce: string,
  ): Promise<{ idToken: string; claims: IdTokenClaims }> {
    const res = await fetch(`${env.HYDRA_PUBLIC_URL}/oauth2/token`, {
      method: 'POST',
      headers: {
        authorization: `Basic ${Buffer.from(
          `${encodeURIComponent(ACCOUNT_CLIENT_ID)}:${encodeURIComponent(env.ENTITY_AUTH_ACCOUNT_SECRET)}`,
        ).toString('base64')}`,
        'content-type': 'application/x-www-form-urlencoded',
      },
      body: new URLSearchParams({
        grant_type: 'authorization_code',
        code,
        redirect_uri: accountRedirectUri(),
        code_verifier: verifier,
      }).toString(),
      signal: AbortSignal.timeout(5000),
    });
    if (!res.ok) throw new AccountSignInFailed(`token endpoint answered ${res.status}`);
    const { id_token: idToken } = TokenResponse.parse(await res.json());

    const parsed = IdTokenClaims.safeParse(payload(idToken));
    if (!parsed.success) throw new AccountSignInFailed('ID token is missing claims');
    const c = parsed.data;
    const aud = Array.isArray(c.aud) ? c.aud : [c.aud];
    if (trimSlash(c.iss) !== trimSlash(env.HYDRA_PUBLIC_URL))
      throw new AccountSignInFailed('issuer');
    if (!aud.includes(ACCOUNT_CLIENT_ID)) throw new AccountSignInFailed('audience');
    if (c.exp * 1000 <= Date.now()) throw new AccountSignInFailed('expired');
    if (!same(c.nonce, nonce)) throw new AccountSignInFailed('nonce');
    return { idToken, claims: c };
  }

  /** Hydra's RP-initiated sign-out, back to the account centre's signed-out page. */
  signOutUrl(idToken: string): string {
    return `${env.HYDRA_PUBLIC_URL}/oauth2/sessions/logout?${new URLSearchParams({
      id_token_hint: idToken,
      post_logout_redirect_uri: accountSignedOutUri(),
    })}`;
  }
}

const token = () => randomBytes(32).toString('base64url');
const trimSlash = (s: string) => s.replace(/\/+$/, '');

function payload(jwt: string): unknown {
  try {
    return JSON.parse(Buffer.from(jwt.split('.')[1] ?? '', 'base64url').toString('utf8'));
  } catch {
    return null;
  }
}

function same(a: string, b: string): boolean {
  const x = Buffer.from(a);
  const y = Buffer.from(b);
  return x.length === y.length && timingSafeEqual(x, y);
}
