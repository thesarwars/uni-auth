import {
  Injectable,
  Logger,
  type OnApplicationBootstrap,
  type OnModuleDestroy,
} from '@nestjs/common';
import { env } from '../config/env';
import { Database, type Db } from '../db/database.service';
import { IdentityRepository } from '../identity/identity.repository';
import { RecoveryMail } from './recovery-mail';
import { RecoveryReview } from './recovery-review';
import { RecoveryRepository, type Recovery } from './recovery.repository';

/**
 * Moves account recovery requests along (db/migrations/0014_mfa_recovery.sql; account-plan.md
 * part 7). Each run:
 *
 *   1. registers requests the product hasn't answered yet: does an administrator approve this?
 *   2. fetches the decisions it is waiting for; a refusal ends the request, and the member hears;
 *   3. completes requests whose seven days are over, that needed no person or were approved:
 *      2-step verification is removed, and every address is told;
 *   4. withdraws cancelled requests at the product, so its queue doesn't keep them.
 *
 * A request the product never answers never completes: unknown is never read as "no review".
 * Completion claims each row with SKIP LOCKED, so several instances never complete one twice.
 */
@Injectable()
export class MfaRecoveries implements OnApplicationBootstrap, OnModuleDestroy {
  private readonly logger = new Logger(MfaRecoveries.name);
  private timer: NodeJS.Timeout | null = null;
  private running: Promise<void> | null = null;

  constructor(
    private readonly db: Database,
    private readonly recoveries: RecoveryRepository,
    private readonly identities: IdentityRepository,
    private readonly review: RecoveryReview,
    private readonly mail: RecoveryMail,
  ) {}

  onApplicationBootstrap(): void {
    this.timer = setInterval(() => void this.run(), env.MFA_RECOVERY_POLL_MS);
    this.timer.unref();
  }

  async onModuleDestroy(): Promise<void> {
    if (this.timer) clearInterval(this.timer);
    await this.running;
  }

  /** One pass, as of `asOf` (now, but for tests). One run at a time. */
  run(asOf: Date = new Date()): Promise<void> {
    this.running ??= this.runAll(asOf).finally(() => (this.running = null));
    return this.running;
  }

  /**
   * Asks the product about one request; its answer, or null when it couldn't be asked (the next
   * run tries again). Used at request time too.
   */
  async register(r: Recovery): Promise<'required' | 'not_required' | null> {
    try {
      const review = await this.review.register(r);
      await this.recoveries.setReview(r.id, review);
      return review;
    } catch (err) {
      this.logger.warn(`recovery ${r.id}: not registered yet: ${(err as Error).message}`);
      return null;
    }
  }

  private async runAll(asOf: Date): Promise<void> {
    for (const r of await this.recoveries.unregistered()) await this.register(r);

    for (const r of await this.recoveries.undecided()) {
      try {
        const decision = await this.review.decision(r.id);
        if (decision) await this.decide(r, decision);
      } catch (err) {
        this.logger.warn(`recovery ${r.id}: no decision read: ${(err as Error).message}`);
      }
    }

    try {
      for (;;) {
        const done = await this.db.tx((db) => this.completeNext(db, asOf));
        if (!done) break;
        if (done.completed) await this.mail.completed(done.r);
      }
    } catch (err) {
      this.logger.warn(`recoveries: ${(err as Error).message}`);
    }

    for (const r of await this.recoveries.toWithdraw()) {
      try {
        await this.review.withdraw(r.id);
        await this.recoveries.markWithdrawn(r.id);
      } catch (err) {
        this.logger.warn(`recovery ${r.id}: not withdrawn yet: ${(err as Error).message}`);
      }
    }
  }

  private async decide(r: Recovery, decision: 'approved' | 'rejected'): Promise<void> {
    const decided = await this.db.tx(async (db) => {
      const d = await this.recoveries.decide(db, r.id, decision);
      if (d && decision === 'rejected') {
        await this.identities.event(
          {
            kind: 'mfa_recovery_rejected',
            outcome: 'failure',
            identityId: r.identityId,
            detail: { request: r.id },
          },
          db,
        );
      }
      return d;
    });
    if (decided && decision === 'rejected') await this.mail.rejected(decided);
  }

  private async completeNext(
    db: Db,
    asOf: Date,
  ): Promise<{ r: Recovery; completed: boolean } | null> {
    const due = await this.recoveries.claimDue(db, asOf);
    if (!due) return null;
    // Closed or suspended since it asked: nothing to remove for an account that can't sign in.
    if (!due.identityActive) {
      await this.recoveries.cancel(db, due.id, 'identity_closed');
      return { r: due, completed: false };
    }
    await this.recoveries.complete(db, due);
    await this.identities.event(
      {
        kind: 'mfa_recovery_completed',
        outcome: 'success',
        identityId: due.identityId,
        credentialKind: 'totp',
        detail: { request: due.id, reviewed: due.review === 'required' },
      },
      db,
    );
    this.logger.log(`2-step verification removed from ${due.identityId} by recovery ${due.id}`);
    return { r: due, completed: true };
  }
}
