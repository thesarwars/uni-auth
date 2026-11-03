import { Injectable } from '@nestjs/common';
import { z } from 'zod';
import { env } from '../config/env';

const TokenResponse = z.object({ access_token: z.string(), expires_in: z.number() });

/**
 * A uni-auth-service access token (client credentials, scope identity:lifecycle), for calling a
 * product's internal API. Kept until a minute before it expires.
 */
@Injectable()
export class ServiceToken {
  private cached: { token: string; until: number } | null = null;

  async get(audience: string): Promise<string> {
    if (this.cached && this.cached.until > Date.now()) return this.cached.token;
    const res = await fetch(`${env.HYDRA_PUBLIC_URL}/oauth2/token`, {
      method: 'POST',
      headers: {
        authorization: `Basic ${Buffer.from(`uni-auth-service:${env.UNI_AUTH_SERVICE_SECRET}`).toString('base64')}`,
        'content-type': 'application/x-www-form-urlencoded',
      },
      body: new URLSearchParams({
        grant_type: 'client_credentials',
        scope: 'identity:lifecycle',
        audience,
      }).toString(),
      signal: AbortSignal.timeout(5000),
    });
    if (!res.ok) throw new Error(`service token: Hydra answered ${res.status}`);
    const t = TokenResponse.parse(await res.json());
    this.cached = { token: t.access_token, until: Date.now() + (t.expires_in - 60) * 1000 };
    return t.access_token;
  }

  /** Forgets the token, after a product refused it. */
  drop(): void {
    this.cached = null;
  }
}
