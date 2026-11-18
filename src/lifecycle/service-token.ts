import { Injectable } from '@nestjs/common';
import { z } from 'zod';
import { env } from '../config/env';

const TokenResponse = z.object({ access_token: z.string(), expires_in: z.number() });

/** The scopes the uni-auth-service client holds (deploy/hydra/clients/uni-auth-service.json). */
export type ServiceScope = 'identity:lifecycle' | 'identity:recovery';

/**
 * A uni-auth-service access token (client credentials), for calling a product's internal API:
 * one per scope, so each call carries only what it needs. Kept until a minute before it expires.
 */
@Injectable()
export class ServiceToken {
  private readonly cached = new Map<string, { token: string; until: number }>();

  async get(audience: string, scope: ServiceScope = 'identity:lifecycle'): Promise<string> {
    const key = `${audience} ${scope}`;
    const hit = this.cached.get(key);
    if (hit && hit.until > Date.now()) return hit.token;
    const res = await fetch(`${env.HYDRA_PUBLIC_URL}/oauth2/token`, {
      method: 'POST',
      headers: {
        authorization: `Basic ${Buffer.from(`uni-auth-service:${env.UNI_AUTH_SERVICE_SECRET}`).toString('base64')}`,
        'content-type': 'application/x-www-form-urlencoded',
      },
      body: new URLSearchParams({
        grant_type: 'client_credentials',
        scope,
        audience,
      }).toString(),
      signal: AbortSignal.timeout(5000),
    });
    if (!res.ok) throw new Error(`service token: Hydra answered ${res.status}`);
    const t = TokenResponse.parse(await res.json());
    this.cached.set(key, { token: t.access_token, until: Date.now() + (t.expires_in - 60) * 1000 });
    return t.access_token;
  }

  /** Forgets the tokens, after a product refused one. */
  drop(): void {
    this.cached.clear();
  }
}
