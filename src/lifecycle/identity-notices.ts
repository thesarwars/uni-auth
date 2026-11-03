import {
  Injectable,
  Logger,
  type OnApplicationBootstrap,
  type OnModuleDestroy,
} from '@nestjs/common';
import { env } from '../config/env';
import { Database, type Db } from '../db/database.service';
import { HydraAdmin, UnknownChallenge } from '../hydra/hydra-admin.service';
import { ServiceToken } from './service-token';

interface Notice {
  id: string;
  identity_id: string;
  event: 'closed' | 'erased';
  occurred_at: Date;
  sessions_ended_at: Date | null;
  attempts: number;
}

/** The longest wait between two attempts at one notice. */
const MAX_BACKOFF_SECONDS = 3600;

/**
 * Delivers identity notices (db/migrations/0004_identity_notices.sql; auth-plan.md section
 * 12.2, part 7). For each notice due:
 *
 *   1. A closed identity's sessions are ended at Hydra: each sid the closure revoked, so every
 *      client hears of it by back-channel logout, then everything Hydra holds for the subject,
 *      so no refresh token outlives the identity - not even one whose session row erasure has
 *      deleted, which the refresh hook could no longer recognise.
 *   2. The product is told: POST IDENTITY_NOTICE_URL { sub, event, occurred_at }, with a
 *      uni-auth-service token. Anything but a 2xx is tried again later, backing off.
 *
 * Each notice is claimed with SKIP LOCKED, so several instances never deliver one twice at once.
 */
@Injectable()
export class IdentityNotices implements OnApplicationBootstrap, OnModuleDestroy {
  private readonly logger = new Logger(IdentityNotices.name);
  private timer: NodeJS.Timeout | null = null;
  private draining: Promise<number> | null = null;

  constructor(
    private readonly db: Database,
    private readonly hydra: HydraAdmin,
    private readonly tokens: ServiceToken,
  ) {}

  onApplicationBootstrap(): void {
    this.timer = setInterval(() => void this.drain(), env.IDENTITY_NOTICE_POLL_MS);
    this.timer.unref();
  }

  async onModuleDestroy(): Promise<void> {
    if (this.timer) clearInterval(this.timer);
    await this.draining;
  }

  /** Works through every notice now due; returns how many were delivered. One drain at a time. */
  drain(): Promise<number> {
    this.draining ??= this.drainAll().finally(() => (this.draining = null));
    return this.draining;
  }

  private async drainAll(): Promise<number> {
    let delivered = 0;
    try {
      for (;;) {
        const outcome = await this.db.tx((db) => this.next(db));
        if (outcome === 'none') return delivered;
        if (outcome === 'delivered') delivered += 1;
      }
    } catch (err) {
      this.logger.warn(`identity notices: ${(err as Error).message}`);
      return delivered;
    }
  }

  private async next(db: Db): Promise<'none' | 'delivered' | 'failed'> {
    const {
      rows: [n],
    } = await db.query<Notice>(
      `SELECT id, identity_id, event, occurred_at, sessions_ended_at, attempts
         FROM identity_notice
        WHERE delivered_at IS NULL AND next_attempt_at <= now()
        ORDER BY next_attempt_at
        LIMIT 1
        FOR UPDATE SKIP LOCKED`,
    );
    if (!n) return 'none';
    try {
      if (n.event === 'closed' && !n.sessions_ended_at) {
        await this.endSessions(db, n.identity_id);
        await db.query('UPDATE identity_notice SET sessions_ended_at = now() WHERE id = $1', [
          n.id,
        ]);
      }
      await this.deliver(n);
      await db.query(
        'UPDATE identity_notice SET delivered_at = now(), attempts = attempts + 1, last_error = NULL WHERE id = $1',
        [n.id],
      );
      return 'delivered';
    } catch (err) {
      const wait = Math.min(30 * 2 ** n.attempts, MAX_BACKOFF_SECONDS);
      await db.query(
        `UPDATE identity_notice
            SET attempts = attempts + 1, last_error = $2,
                next_attempt_at = now() + make_interval(secs => $3)
          WHERE id = $1`,
        [n.id, (err as Error).message.slice(0, 500), wait],
      );
      this.logger.warn(
        `identity notice ${n.id} (${n.event}) not delivered, again in ${wait}s: ${(err as Error).message}`,
      );
      return 'failed';
    }
  }

  private async endSessions(db: Db, identityId: string): Promise<void> {
    const { rows } = await db.query<{ sid: string }>(
      `SELECT sid FROM auth_session WHERE identity_id = $1 AND revoke_reason = 'identity_closed'`,
      [identityId],
    );
    for (const { sid } of rows) {
      await this.hydra.revokeLoginSession(sid).catch((err) => {
        if (!(err instanceof UnknownChallenge)) throw err; // Hydra had already let it go
      });
    }
    await this.hydra.revokeSubject(identityId);
  }

  private async deliver(n: Notice): Promise<void> {
    const res = await fetch(env.IDENTITY_NOTICE_URL, {
      method: 'POST',
      headers: {
        authorization: `Bearer ${await this.tokens.get(env.IDENTITY_NOTICE_AUDIENCE)}`,
        'content-type': 'application/json',
      },
      body: JSON.stringify({
        sub: n.identity_id,
        event: n.event,
        occurred_at: n.occurred_at.toISOString(),
      }),
      signal: AbortSignal.timeout(10_000),
    });
    if (res.status === 401) this.tokens.drop();
    if (!res.ok) throw new Error(`the product answered ${res.status}`);
  }
}
