import { Injectable } from '@nestjs/common';
import { createHash, randomBytes, timingSafeEqual } from 'node:crypto';
import type { Authenticated, Seen } from '../flows/sign-in.service';
import { RedisService } from '../redis/redis.service';

/** A sign-in whose first step succeeded, waiting for the second. */
export interface PendingTwoStep {
  /** Binds it to the browser that passed the first step (a signed cookie holds it too). */
  token: string;
  a: Authenticated;
  seen: Seen;
}

const SIGN_IN_TTL = 10 * 60;
const SETUP_TTL = 15 * 60;

/**
 * What 2-step verification holds between screens, in Redis only: a sign-in between its first
 * and second step, and an authenticator seed between being shown and being confirmed (sealed,
 * as it will be stored). Nothing reaches the identity database until the second step passes or
 * the member confirms a code from the new authenticator.
 */
@Injectable()
export class TwoStepStore {
  constructor(private readonly redis: RedisService) {}

  async holdSignIn(challenge: string, p: Omit<PendingTwoStep, 'token'>): Promise<string> {
    const token = randomBytes(24).toString('base64url');
    await this.redis.client.set(
      this.signInKey(challenge),
      JSON.stringify({ ...p, token }),
      'EX',
      SIGN_IN_TTL,
    );
    return token;
  }

  /** The pending sign-in, only for the browser holding its token. */
  async signIn(challenge: string, token: string | null): Promise<PendingTwoStep | null> {
    if (!token) return null;
    const raw = await this.redis.client.get(this.signInKey(challenge));
    if (!raw) return null;
    const p = JSON.parse(raw) as PendingTwoStep;
    const a = Buffer.from(p.token);
    const b = Buffer.from(token);
    return a.length === b.length && timingSafeEqual(a, b) ? p : null;
  }

  async dropSignIn(challenge: string): Promise<void> {
    await this.redis.client.del(this.signInKey(challenge));
  }

  /** A sealed seed being set up, per account-centre session: a reload shows the same one. */
  async holdSetup(accountSession: string, sealed: Buffer): Promise<void> {
    await this.redis.client.set(
      this.setupKey(accountSession),
      sealed.toString('base64'),
      'EX',
      SETUP_TTL,
    );
  }

  async setup(accountSession: string): Promise<Buffer | null> {
    const raw = await this.redis.client.get(this.setupKey(accountSession));
    return raw ? Buffer.from(raw, 'base64') : null;
  }

  async dropSetup(accountSession: string): Promise<void> {
    await this.redis.client.del(this.setupKey(accountSession));
  }

  private signInKey(challenge: string): string {
    return `uni-auth:two-step:${createHash('sha256').update(challenge).digest('base64url')}`;
  }

  private setupKey(accountSession: string): string {
    return `uni-auth:two-step-setup:${createHash('sha256').update(accountSession).digest('base64url')}`;
  }
}
