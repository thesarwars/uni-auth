import {
  Injectable,
  Logger,
  type OnApplicationBootstrap,
  type OnModuleDestroy,
} from '@nestjs/common';
import { env } from '../config/env';
import { Database, type Db } from '../db/database.service';
import { IdentityNotices } from './identity-notices';

/**
 * Carries out account deletions that have fallen due (db/migrations/0012_data_privacy.sql;
 * account-plan.md part 6). A member who asked to delete their account and has not signed in
 * since is closed and erased, through the same path as any erasure: the schema scrubs the
 * identity (0001: identity_effects) and queues the notices that end its sessions at Hydra and
 * tell GSN (0004), which IdentityNotices then delivers.
 *
 * Each due row is claimed with SKIP LOCKED, so several instances never erase one twice at once.
 */
@Injectable()
export class AccountDeletions implements OnApplicationBootstrap, OnModuleDestroy {
  private readonly logger = new Logger(AccountDeletions.name);
  private timer: NodeJS.Timeout | null = null;
  private running: Promise<number> | null = null;

  constructor(
    private readonly db: Database,
    private readonly notices: IdentityNotices,
  ) {}

  onApplicationBootstrap(): void {
    this.timer = setInterval(() => void this.run(), env.ACCOUNT_DELETION_POLL_MS);
    this.timer.unref();
  }

  async onModuleDestroy(): Promise<void> {
    if (this.timer) clearInterval(this.timer);
    await this.running;
  }

  /**
   * Erases every identity whose deletion was due by `asOf` (now, but for tests); returns how
   * many. One run at a time.
   */
  run(asOf: Date = new Date()): Promise<number> {
    this.running ??= this.runAll(asOf).finally(() => (this.running = null));
    return this.running;
  }

  private async runAll(asOf: Date): Promise<number> {
    let erased = 0;
    try {
      while (await this.db.tx((db) => this.next(db, asOf))) erased += 1;
    } catch (err) {
      this.logger.warn(`account deletions: ${(err as Error).message}`);
    }
    // The product hears now, not at the next poll.
    if (erased > 0) void this.notices.drain();
    return erased;
  }

  private async next(db: Db, asOf: Date): Promise<boolean> {
    const {
      rows: [due],
    } = await db.query<{ id: string; identity_id: string }>(
      `SELECT id, identity_id FROM account_deletion
        WHERE cancelled_at IS NULL AND completed_at IS NULL AND scheduled_for <= $1
        ORDER BY scheduled_for
        LIMIT 1
        FOR UPDATE SKIP LOCKED`,
      [asOf],
    );
    if (!due) return false;
    // Closed first (its sessions end, GSN is told it closed), then erased (scrubbed, GSN told).
    await db.query(`UPDATE identity SET status = 'closed' WHERE id = $1 AND status <> 'closed'`, [
      due.identity_id,
    ]);
    await db.query(`UPDATE identity SET erased_at = now() WHERE id = $1 AND erased_at IS NULL`, [
      due.identity_id,
    ]);
    await db.query(`UPDATE account_deletion SET completed_at = now() WHERE id = $1`, [due.id]);
    this.logger.log(`account ${due.identity_id} erased, as its member asked`);
    return true;
  }
}
