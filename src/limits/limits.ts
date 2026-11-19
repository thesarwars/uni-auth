import { Injectable } from '@nestjs/common';
import { createHash } from 'node:crypto';
import { env } from '../config/env';
import { RedisService } from '../redis/redis.service';

interface Budget {
  /** How many in the window. */
  limit: number;
  windowSeconds: number;
  /** Counted per member (their identity id) or per client address. */
  per: 'member' | 'address';
}

const HOUR = 3600;

/**
 * How often each action may be done (account-plan.md part 8). Per member: generous for a person,
 * tight enough that a stolen session can't turn the account centre into a mailer, a hashing
 * service or a store. Per address: what one network can do before anyone is signed in.
 *
 * The password throttle (throttle.service.ts) and OTP's own caps in the database are separate
 * and stay as they are; these sit in front of what they don't cover.
 */
export const BUDGETS = {
  /** Name and language. */
  personal: { limit: 30, windowSeconds: HOUR, per: 'member' },
  photo: { limit: 20, windowSeconds: HOUR, per: 'member' },
  /** A code to a new address: OTP caps each address, this caps how many addresses. */
  contact_add: { limit: 10, windowSeconds: HOUR, per: 'member' },
  /** Primary and remove: each emails an address. */
  contact_change: { limit: 20, windowSeconds: HOUR, per: 'member' },
  /** A hash, every other device signed out, and an email. */
  password: { limit: 5, windowSeconds: HOUR, per: 'member' },
  /** Codes tried while turning 2-step on. */
  two_step_setup: { limit: 10, windowSeconds: 15 * 60, per: 'member' },
  /** New recovery codes, and turning it off: each emails the member. */
  two_step_change: { limit: 10, windowSeconds: HOUR, per: 'member' },
  passkey_options: { limit: 30, windowSeconds: HOUR, per: 'member' },
  /** Add, rename, remove. */
  passkey_change: { limit: 20, windowSeconds: HOUR, per: 'member' },
  /** Devices signed out, apps' access removed, Google or Apple unlinked: each calls Hydra. */
  sign_out: { limit: 30, windowSeconds: HOUR, per: 'member' },
  export: { limit: 5, windowSeconds: HOUR, per: 'member' },
  /** Sign-in, sign-up and reset codes sent from one address, to any addresses. */
  codes: { limit: 30, windowSeconds: HOUR, per: 'address' },
  /** Passkey sign-in challenges and attempts from one address. */
  passkey_sign_in: { limit: 60, windowSeconds: 15 * 60, per: 'address' },
} satisfies Record<string, Budget>;

export type BudgetName = keyof typeof BUDGETS;

export type Taken = { ok: true } | { ok: false; retryAt: Date };

/**
 * Fixed-window counters in Redis, one per action and member or address. Like the throttle, it
 * fails closed: when Redis is unreachable `take` throws and the action isn't done.
 */
@Injectable()
export class Limits {
  constructor(private readonly redis: RedisService) {}

  /** The most this action may be done in its window. Per-address ones scale (tests raise it). */
  limit(name: BudgetName): number {
    const b: Budget = BUDGETS[name];
    return b.per === 'address' ? b.limit * env.ADDRESS_LIMIT_SCALE : b.limit;
  }

  /** Counts one; refused once the window's budget is spent, with when it next has room. */
  async take(name: BudgetName, subject: string): Promise<Taken> {
    const key = this.key(name, subject);
    const results = await this.redis.client
      .multi()
      .incr(key)
      .expire(key, BUDGETS[name].windowSeconds, 'NX')
      .pttl(key)
      .exec();
    if (!results || results.some(([err]) => err)) throw new Error('Limits: Redis refused');
    const count = Number(results[0]![1]);
    if (count <= this.limit(name)) return { ok: true };
    const ttl = Math.max(Number(results[2]![1]), 1000);
    return { ok: false, retryAt: new Date(Date.now() + ttl) };
  }

  /** Addresses are hashed, so Redis never holds one; ids are kept as they are. */
  key(name: BudgetName, subject: string): string {
    const who =
      BUDGETS[name].per === 'address'
        ? createHash('sha256').update(subject).digest('base64url')
        : subject;
    return `${env.THROTTLE_KEY_PREFIX}limit:${name}:${who}`;
  }
}

/** "in 12 minutes", "in an hour": when a refused action can be tried again. */
export const tryAgainIn = (at: Date): string => {
  const minutes = Math.max(1, Math.ceil((at.getTime() - Date.now()) / 60_000));
  if (minutes >= 55) return 'in an hour';
  return minutes === 1 ? 'in a minute' : `in ${minutes} minutes`;
};
