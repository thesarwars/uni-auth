import { Injectable } from '@nestjs/common';
import { createHash, randomBytes } from 'node:crypto';
import { RedisService } from '../redis/redis.service';
import type { Identifier } from './identifier';
import type { Provider } from '../upstream/upstream.service';

/** A sign-up by email or phone, waiting for the code that proves the address. */
export interface PendingSignup {
  identifier: Identifier;
  /** The scrypt hash of the chosen password; the password itself is never kept. */
  secretHash: string;
}

/** A sign-up by Google or Apple, waiting for the member to confirm it. */
export interface PendingUpstreamSignup {
  provider: Provider;
  subject: string;
  email: string;
  loginChallenge: string;
}

const TTL_SECONDS = 15 * 60;

/**
 * What a sign-up holds between screens, in Redis and nowhere durable: nothing is written to the
 * identity database until the member has proved the address (a code) or the provider has (a
 * verified email) and confirmed. An abandoned sign-up leaves no identity behind.
 */
@Injectable()
export class SignupStore {
  constructor(private readonly redis: RedisService) {}

  /** Keyed by the sign-in it belongs to: one pending sign-up per login challenge. */
  async hold(flow: string, p: PendingSignup): Promise<void> {
    await this.redis.client.set(this.flowKey(flow), JSON.stringify(p), 'EX', TTL_SECONDS);
  }

  /** Spends it: a second verified code in the same sign-in finds nothing. */
  async take(flow: string): Promise<PendingSignup | null> {
    const raw = await this.redis.client.getdel(this.flowKey(flow));
    return raw ? (JSON.parse(raw) as PendingSignup) : null;
  }

  async holdUpstream(p: PendingUpstreamSignup): Promise<string> {
    const token = randomBytes(24).toString('base64url');
    await this.redis.client.set(this.upstreamKey(token), JSON.stringify(p), 'EX', 10 * 60);
    return token;
  }

  async peekUpstream(token: string, loginChallenge: string): Promise<PendingUpstreamSignup | null> {
    const raw = await this.redis.client.get(this.upstreamKey(token));
    const p = raw ? (JSON.parse(raw) as PendingUpstreamSignup) : null;
    return p && p.loginChallenge === loginChallenge ? p : null;
  }

  /** Spends it, and only for the sign-in it was made in. */
  async takeUpstream(token: string, loginChallenge: string): Promise<PendingUpstreamSignup | null> {
    const p = await this.peekUpstream(token, loginChallenge);
    if (!p) return null;
    return (await this.redis.client.del(this.upstreamKey(token))) === 1 ? p : null;
  }

  private flowKey(flow: string): string {
    return `uni-auth:signup:${createHash('sha256').update(flow).digest('base64url')}`;
  }

  private upstreamKey(token: string): string {
    return `uni-auth:upstream-signup:${token}`;
  }
}
