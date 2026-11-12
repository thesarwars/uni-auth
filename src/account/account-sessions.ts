import { Injectable } from '@nestjs/common';
import { createHash, randomBytes } from 'node:crypto';
import { RedisService } from '../redis/redis.service';

/** A member signed in to the account centre. */
export interface AccountSession {
  /** This session's own id: the cookie's value, and the flow every code it asks for is bound to. */
  id: string;
  sub: string;
  /** The provider session it was signed in through; when that ends, so does this. */
  sid: string;
  /** For RP-initiated sign-out and re-authentication (id_token_hint). */
  idToken: string;
  /** When the member last proved who they are, in seconds: what AC-D2 measures. */
  authTime: number;
  createdAt: number;
}

/** A sign-in to the account centre in progress: what the callback checks and where it returns. */
export interface PendingSignIn {
  verifier: string;
  nonce: string;
  returnTo: string;
}

/** Idle out after half an hour; never live longer than twelve hours. */
const IDLE_SECONDS = 30 * 60;
const ABSOLUTE_SECONDS = 12 * 60 * 60;
const PENDING_SECONDS = 10 * 60;

/**
 * The account centre's sessions, in Redis (account-plan.md AC-D1). Nothing durable: the
 * provider session in the identity database is the truth, and the controller checks it on
 * every request, so a sign-out anywhere ends this too.
 */
@Injectable()
export class AccountSessions {
  constructor(private readonly redis: RedisService) {}

  async open(s: Omit<AccountSession, 'id' | 'createdAt'>): Promise<AccountSession> {
    const session: AccountSession = {
      ...s,
      id: randomBytes(24).toString('base64url'),
      createdAt: Math.floor(Date.now() / 1000),
    };
    await this.save(session);
    return session;
  }

  /** The session, its idle clock restarted; null once it has idled out or grown too old. */
  async get(id: string): Promise<AccountSession | null> {
    const raw = await this.redis.client.get(key(id));
    if (!raw) return null;
    const s = JSON.parse(raw) as AccountSession;
    if (Math.floor(Date.now() / 1000) - s.createdAt > ABSOLUTE_SECONDS) {
      await this.end(id);
      return null;
    }
    await this.redis.client.expire(key(id), IDLE_SECONDS);
    return s;
  }

  /** A fresh sign-in on the same session: who and when, after "Confirm it's you". */
  async refresh(
    s: AccountSession,
    with_: Pick<AccountSession, 'sid' | 'idToken' | 'authTime'>,
  ): Promise<AccountSession> {
    const next = { ...s, ...with_ };
    await this.save(next);
    return next;
  }

  async end(id: string): Promise<void> {
    await this.redis.client.del(key(id));
  }

  async hold(state: string, p: PendingSignIn): Promise<void> {
    await this.redis.client.set(pendingKey(state), JSON.stringify(p), 'EX', PENDING_SECONDS);
  }

  /** Spends it: a callback replayed with the same state finds nothing. */
  async take(state: string): Promise<PendingSignIn | null> {
    const raw = await this.redis.client.getdel(pendingKey(state));
    return raw ? (JSON.parse(raw) as PendingSignIn) : null;
  }

  private async save(s: AccountSession): Promise<void> {
    await this.redis.client.set(key(s.id), JSON.stringify(s), 'EX', IDLE_SECONDS);
  }
}

// The cookie holds the id; Redis keys on its hash, so a key list never shows a usable id.
const hash = (id: string) => createHash('sha256').update(id).digest('base64url');
const key = (id: string) => `uni-auth:account:${hash(id)}`;
const pendingKey = (state: string) => `uni-auth:account-signin:${hash(state)}`;
