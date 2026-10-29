import { Injectable } from '@nestjs/common';
import { createHash } from 'node:crypto';
import { env } from '../config/env';
import { RedisService } from '../redis/redis.service';

/** Failed password attempts per identifier before a lockout, and how long one lasts. */
export const IDENTIFIER_LIMIT = 5;
/** Failed attempts from one address, across every identifier, before it is refused. */
export const ADDRESS_LIMIT = 100;
export const WINDOW_SECONDS = 15 * 60;

export type ThrottleState = { kind: 'open'; remaining: number } | { kind: 'locked'; until: Date };

/**
 * The password throttle (auth-plan.md section 9, AU-G6). One shared sign-in endpoint for every
 * product is a larger credential-stuffing target than one product's, so failures are counted
 * per identifier and per client address in Redis, in fixed windows.
 *
 * OTP has its own caps in the database; the two mechanisms are independent. When Redis is
 * unreachable the throttle fails closed - a password is never checked unthrottled.
 */
@Injectable()
export class Throttle {
  private readonly redis;

  constructor(redis: RedisService) {
    this.redis = redis.client;
  }

  /** Whether a password may be checked now for this identifier from this address. */
  async check(identifier: string, address: string): Promise<ThrottleState> {
    const [lockTtl, failures, fromAddress] = await Promise.all([
      this.redis.pttl(this.key('lock', identifier)),
      this.redis.get(this.key('fail', identifier)),
      this.redis.get(this.key('addr', address)),
    ]);
    if (lockTtl > 0) return { kind: 'locked', until: new Date(Date.now() + lockTtl) };
    if (Number(fromAddress ?? 0) >= ADDRESS_LIMIT) {
      const ttl = await this.redis.pttl(this.key('addr', address));
      return { kind: 'locked', until: new Date(Date.now() + Math.max(ttl, 0)) };
    }
    return { kind: 'open', remaining: IDENTIFIER_LIMIT - Number(failures ?? 0) };
  }

  /**
   * Counts a failure. Returns the state after it: the failure that reaches the limit starts a
   * lockout, and `tripped` says it was this one, so the caller journals it once.
   */
  async fail(identifier: string, address: string): Promise<ThrottleState & { tripped: boolean }> {
    const fail = this.key('fail', identifier);
    const addr = this.key('addr', address);
    const results = await this.redis
      .multi()
      .incr(fail)
      .expire(fail, WINDOW_SECONDS, 'NX')
      .incr(addr)
      .expire(addr, WINDOW_SECONDS, 'NX')
      .exec();
    const count = Number(results?.[0]?.[1] ?? IDENTIFIER_LIMIT);
    if (count >= IDENTIFIER_LIMIT) {
      const set = await this.redis.set(
        this.key('lock', identifier),
        '1',
        'EX',
        WINDOW_SECONDS,
        'NX',
      );
      await this.redis.del(fail);
      const ttl = await this.redis.pttl(this.key('lock', identifier));
      return {
        kind: 'locked',
        until: new Date(Date.now() + Math.max(ttl, 0)),
        tripped: set === 'OK',
      };
    }
    return { kind: 'open', remaining: IDENTIFIER_LIMIT - count, tripped: false };
  }

  /** A correct password clears the identifier's failures; the address keeps its count. */
  async succeed(identifier: string): Promise<void> {
    await this.redis.del(this.key('fail', identifier));
  }

  /** A completed password reset lifts the lockout: the reset was the way out it offered. */
  async lift(identifier: string): Promise<void> {
    await this.redis.del(this.key('fail', identifier), this.key('lock', identifier));
  }

  /** Keys carry a hash, so Redis never holds an email address or a phone number. */
  private key(kind: 'fail' | 'lock' | 'addr', value: string): string {
    return `${env.THROTTLE_KEY_PREFIX}${kind}:${createHash('sha256').update(value).digest('base64url')}`;
  }
}
