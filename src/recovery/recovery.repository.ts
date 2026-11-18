import { Injectable } from '@nestjs/common';
import { Database, type Db } from '../db/database.service';

export type Review = 'unknown' | 'required' | 'not_required';
export type Decision = 'approved' | 'rejected';
export type CancelledBy = 'link' | 'sign_in' | 'identity_closed';

/** Where a request stands, as a member reads it. */
export type RecoveryState = 'pending' | 'cancelled' | 'rejected' | 'completed';

export interface Recovery {
  id: string;
  identityId: string;
  requestedAt: Date;
  eligibleAt: Date;
  review: Review;
  decision: Decision | null;
  state: RecoveryState;
}

interface Row {
  id: string;
  identity_id: string;
  requested_at: Date;
  eligible_at: Date;
  review: Review;
  decision: Decision | null;
  cancelled_at: Date | null;
  completed_at: Date | null;
}

const COLUMNS = `id, identity_id, requested_at, eligible_at, review, decision, cancelled_at,
                 completed_at`;

/** Still waiting: not cancelled, not refused, not completed (0014's mfa_recovery_pending_once). */
const PENDING = `cancelled_at IS NULL AND completed_at IS NULL
                 AND decision IS DISTINCT FROM 'rejected'`;

const toRecovery = (r: Row): Recovery => ({
  id: r.id,
  identityId: r.identity_id,
  requestedAt: r.requested_at,
  eligibleAt: r.eligible_at,
  review: r.review,
  decision: r.decision,
  state: r.completed_at
    ? 'completed'
    : r.cancelled_at
      ? 'cancelled'
      : r.decision === 'rejected'
        ? 'rejected'
        : 'pending',
});

/**
 * Account recovery requests (db/migrations/0014_mfa_recovery.sql). The rules - one waiting per
 * identity, the server's timestamps, final once ended - are the table's; this names the
 * statements.
 */
@Injectable()
export class RecoveryRepository {
  constructor(private readonly db: Database) {}

  /** A new request, or null when one is already waiting for this identity. */
  async create(db: Db, identityId: string, tokenHash: Buffer): Promise<Recovery | null> {
    const res = await db.query<Row>(
      `INSERT INTO mfa_recovery (identity_id, eligible_at, cancel_token_hash)
       VALUES ($1, now(), $2)
       ON CONFLICT (identity_id) WHERE ${PENDING} DO NOTHING
       RETURNING ${COLUMNS}`,
      [identityId, tokenHash],
    );
    return res.rows[0] ? toRecovery(res.rows[0]) : null;
  }

  async pendingFor(identityId: string): Promise<Recovery | null> {
    const [r] = await this.db.rows<Row>(
      `SELECT ${COLUMNS} FROM mfa_recovery WHERE identity_id = $1 AND ${PENDING}`,
      [identityId],
    );
    return r ? toRecovery(r) : null;
  }

  async byToken(tokenHash: Buffer): Promise<Recovery | null> {
    const [r] = await this.db.rows<Row>(
      `SELECT ${COLUMNS} FROM mfa_recovery WHERE cancel_token_hash = $1`,
      [tokenHash],
    );
    return r ? toRecovery(r) : null;
  }

  /** Cancels a waiting request; returns it, or null when it had already ended. */
  async cancel(db: Db, id: string, by: CancelledBy): Promise<Recovery | null> {
    const res = await db.query<Row>(
      `UPDATE mfa_recovery SET cancelled_at = now(), cancelled_by = $2
        WHERE id = $1 AND ${PENDING} RETURNING ${COLUMNS}`,
      [id, by],
    );
    return res.rows[0] ? toRecovery(res.rows[0]) : null;
  }

  /** Cancels whatever request is waiting for the identity; returns it, or null. */
  async cancelFor(db: Db, identityId: string, by: CancelledBy): Promise<Recovery | null> {
    const res = await db.query<Row>(
      `UPDATE mfa_recovery SET cancelled_at = now(), cancelled_by = $2
        WHERE identity_id = $1 AND ${PENDING} RETURNING ${COLUMNS}`,
      [identityId, by],
    );
    return res.rows[0] ? toRecovery(res.rows[0]) : null;
  }

  /** The product's answer: whether a person must approve. Once only; later answers are ignored. */
  async setReview(id: string, review: Exclude<Review, 'unknown'>): Promise<void> {
    await this.db.rows(
      `UPDATE mfa_recovery SET review = $2 WHERE id = $1 AND review = 'unknown' AND ${PENDING}`,
      [id, review],
    );
  }

  /** The administrator's decision; returns the request when this call recorded it. */
  async decide(db: Db, id: string, decision: Decision): Promise<Recovery | null> {
    const res = await db.query<Row>(
      `UPDATE mfa_recovery SET decision = $2
        WHERE id = $1 AND review = 'required' AND decision IS NULL AND ${PENDING}
        RETURNING ${COLUMNS}`,
      [id, decision],
    );
    return res.rows[0] ? toRecovery(res.rows[0]) : null;
  }

  async markWithdrawn(id: string): Promise<void> {
    await this.db.rows(
      `UPDATE mfa_recovery SET withdrawn_at = now() WHERE id = $1 AND withdrawn_at IS NULL`,
      [id],
    );
  }

  /** Waiting for the product to say whether a person must approve. */
  async unregistered(): Promise<Recovery[]> {
    return (
      await this.db.rows<Row>(
        `SELECT ${COLUMNS} FROM mfa_recovery WHERE review = 'unknown' AND ${PENDING}
          ORDER BY requested_at LIMIT 100`,
      )
    ).map(toRecovery);
  }

  /** Waiting for an administrator's decision. */
  async undecided(): Promise<Recovery[]> {
    return (
      await this.db.rows<Row>(
        `SELECT ${COLUMNS} FROM mfa_recovery
          WHERE review = 'required' AND decision IS NULL AND ${PENDING}
          ORDER BY requested_at LIMIT 100`,
      )
    ).map(toRecovery);
  }

  /** Cancelled, and the product not yet told (unless it said no person was checking). */
  async toWithdraw(): Promise<Recovery[]> {
    return (
      await this.db.rows<Row>(
        `SELECT ${COLUMNS} FROM mfa_recovery
          WHERE cancelled_at IS NOT NULL AND review <> 'not_required' AND withdrawn_at IS NULL
          ORDER BY cancelled_at LIMIT 100`,
      )
    ).map(toRecovery);
  }

  /**
   * Claims one request that may complete as of `asOf`: waited out, and either needing no person
   * or approved by one. Locked for the claiming transaction; others skip it.
   */
  async claimDue(db: Db, asOf: Date): Promise<(Recovery & { identityActive: boolean }) | null> {
    const res = await db.query<Row & { identity_active: boolean }>(
      `SELECT r.id, r.identity_id, r.requested_at, r.eligible_at, r.review, r.decision,
              r.cancelled_at, r.completed_at, i.status = 'active' AS identity_active
         FROM mfa_recovery r JOIN identity i ON i.id = r.identity_id
        WHERE r.cancelled_at IS NULL AND r.completed_at IS NULL
          AND r.decision IS DISTINCT FROM 'rejected'
          AND r.eligible_at <= $1
          AND (r.review = 'not_required' OR r.decision = 'approved')
        ORDER BY r.eligible_at
        LIMIT 1
          FOR UPDATE OF r SKIP LOCKED`,
      [asOf],
    );
    const r = res.rows[0];
    return r ? { ...toRecovery(r), identityActive: r.identity_active } : null;
  }

  /**
   * Removes 2-step verification: the authenticator (its recovery codes follow, 0008), and marks
   * the request completed. Passkeys stay: they are a way to sign in, not the second step.
   */
  async complete(db: Db, r: Recovery): Promise<void> {
    await db.query(
      `UPDATE credential SET revoked_at = now(), revoke_reason = 'account_recovery'
        WHERE identity_id = $1 AND kind = 'totp' AND revoked_at IS NULL`,
      [r.identityId],
    );
    await db.query(`UPDATE mfa_recovery SET completed_at = now() WHERE id = $1`, [r.id]);
  }

  /** Every verified email address on the identity: each is told about a request. */
  async emails(identityId: string): Promise<string[]> {
    return (
      await this.db.rows<{ value: string }>(
        `SELECT value FROM identity_identifier
          WHERE identity_id = $1 AND kind = 'email' AND verified_at IS NOT NULL
            AND revoked_at IS NULL AND value IS NOT NULL
          ORDER BY is_primary DESC, created_at`,
        [identityId],
      )
    ).map((r) => r.value);
  }
}
