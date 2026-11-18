import { Injectable } from '@nestjs/common';
import { z } from 'zod';
import { env } from '../config/env';
import { ServiceToken } from '../lifecycle/service-token';
import type { Decision, Recovery } from './recovery.repository';

const Registered = z.object({ review: z.enum(['required', 'not_required']) });
const Decided = z.object({ decision: z.enum(['pending', 'approved', 'rejected']) });

/** Short: the member is waiting on the screen; the job tries again if this runs out. */
const TIMEOUT_MS = 4000;

/**
 * The product's side of account recovery (account-plan.md part 7): GSN decides whether a request
 * needs an administrator (the account handles money there), and that administrator's decision.
 * Every call carries a uni-auth-service token with scope identity:recovery; GSN calls nothing
 * back, so the login application keeps no inbound service API.
 *
 *   POST {url}                 { id, sub, requested_at, eligible_at } -> { review }
 *   GET  {url}/{id}                                                   -> { decision }
 *   POST {url}/{id}/withdraw   the member cancelled it                -> 2xx
 *
 * Each is idempotent at GSN, keyed by the request's id.
 */
@Injectable()
export class RecoveryReview {
  private readonly url =
    env.RECOVERY_REVIEW_URL ?? new URL('recovery-requests', env.IDENTITY_NOTICE_URL).toString();

  constructor(private readonly tokens: ServiceToken) {}

  async register(r: Recovery): Promise<'required' | 'not_required'> {
    const res = await this.call('POST', this.url, {
      id: r.id,
      sub: r.identityId,
      requested_at: r.requestedAt.toISOString(),
      eligible_at: r.eligibleAt.toISOString(),
    });
    return Registered.parse(await res.json()).review;
  }

  async decision(id: string): Promise<Decision | null> {
    const res = await this.call('GET', `${this.url}/${encodeURIComponent(id)}`);
    const d = Decided.parse(await res.json()).decision;
    return d === 'pending' ? null : d;
  }

  async withdraw(id: string): Promise<void> {
    await this.call('POST', `${this.url}/${encodeURIComponent(id)}/withdraw`, {});
  }

  private async call(method: 'GET' | 'POST', url: string, body?: unknown): Promise<Response> {
    const token = await this.tokens.get(env.IDENTITY_NOTICE_AUDIENCE, 'identity:recovery');
    const res = await fetch(url, {
      method,
      headers: {
        authorization: `Bearer ${token}`,
        ...(body === undefined ? {} : { 'content-type': 'application/json' }),
      },
      body: body === undefined ? undefined : JSON.stringify(body),
      signal: AbortSignal.timeout(TIMEOUT_MS),
    });
    if (res.status === 401) this.tokens.drop();
    if (!res.ok) throw new Error(`recovery review: ${method} answered ${res.status}`);
    return res;
  }
}
