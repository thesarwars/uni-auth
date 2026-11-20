import { Injectable } from '@nestjs/common';
import { Database, type Db } from '../db/database.service';
import type { IdentityStatus } from '../identity/identity.repository';

export type OperatorActionKind = 'searched' | 'viewed' | 'suspended' | 'reinstated' | 'signed_out';

export interface OperatorAction {
  operatorId: string;
  identityId: string | null;
  action: OperatorActionKind;
  reason?: string | null;
  ip: string | null;
  userAgent: string | null;
}

/** An account as the console shows it. */
export interface Subject {
  id: string;
  status: IdentityStatus;
  displayName: string | null;
  createdAt: Date;
  suspendedAt: Date | null;
  closedAt: Date | null;
  erasedAt: Date | null;
  deletionScheduledFor: Date | null;
  hasPassword: boolean;
  providers: string[];
}

export interface SubjectIdentifier {
  kind: 'email' | 'phone';
  value: string;
  primary: boolean;
  verified: boolean;
}

export interface PastAction {
  action: OperatorActionKind;
  reason: string | null;
  occurredAt: Date;
  /** The operator's primary address, as the log names them. */
  by: string | null;
}

export interface RecoveryRow {
  requestedAt: Date;
  eligibleAt: Date;
  review: string;
  decision: string | null;
  cancelledAt: Date | null;
  cancelledBy: string | null;
  completedAt: Date | null;
}

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

/**
 * The operator console's records (db/migrations/0017_operator.sql): who is an operator, which
 * the application only reads, and the log of what they did, which it only appends to.
 */
@Injectable()
export class OperatorRepository {
  constructor(private readonly db: Database) {}

  /** The identity's live operator grant's id, or null: not an operator. */
  async live(identityId: string): Promise<string | null> {
    const [row] = await this.db.rows<{ id: string }>(
      `SELECT id FROM operator WHERE identity_id = $1 AND revoked_at IS NULL`,
      [identityId],
    );
    return row?.id ?? null;
  }

  async log(a: OperatorAction, db: Db = this.db.asDb()): Promise<void> {
    await db.query(
      `INSERT INTO operator_action (operator_id, identity_id, action, reason, ip_address, user_agent)
       VALUES ($1, $2, $3, $4, $5, $6)`,
      [a.operatorId, a.identityId, a.action, a.reason ?? null, a.ip, a.userAgent],
    );
  }

  /**
   * The identity an email address, phone number or identity id names: any status, closed
   * included, and by an address it once had too, since a member asking for help may give an old
   * one. Lowercased like sign-in; a phone number's spaces and dashes are ignored.
   */
  async find(typed: string): Promise<string | null> {
    const q = typed.trim();
    if (!q) return null;
    if (UUID.test(q)) {
      const [row] = await this.db.rows<{ id: string }>(`SELECT id FROM identity WHERE id = $1`, [
        q.toLowerCase(),
      ]);
      return row?.id ?? null;
    }
    const [kind, value] = q.includes('@')
      ? ['email', q.toLowerCase()]
      : ['phone', q.replace(/[\s().-]/g, '')];
    const [row] = await this.db.rows<{ identity_id: string }>(
      `SELECT identity_id FROM identity_identifier
        WHERE kind = $1 AND value = $2
        ORDER BY revoked_at IS NULL DESC, verified_at IS NOT NULL DESC, created_at DESC
        LIMIT 1`,
      [kind, value],
    );
    return row?.identity_id ?? null;
  }

  async subject(identityId: string): Promise<Subject | null> {
    const [r] = await this.db.rows<{
      id: string;
      status: IdentityStatus;
      display_name: string | null;
      created_at: Date;
      suspended_at: Date | null;
      closed_at: Date | null;
      erased_at: Date | null;
      deletion_scheduled_for: Date | null;
      has_password: boolean;
      providers: string[] | null;
    }>(
      `SELECT i.id, i.status, i.display_name, i.created_at, i.suspended_at, i.closed_at, i.erased_at,
              (SELECT d.scheduled_for FROM account_deletion d
                WHERE d.identity_id = i.id AND d.cancelled_at IS NULL AND d.completed_at IS NULL
                LIMIT 1) AS deletion_scheduled_for,
              EXISTS (SELECT 1 FROM credential c WHERE c.identity_id = i.id
                       AND c.kind = 'password' AND c.revoked_at IS NULL) AS has_password,
              (SELECT array_agg(DISTINCT c.kind::text ORDER BY c.kind::text) FROM credential c
                WHERE c.identity_id = i.id AND c.revoked_at IS NULL
                  AND c.kind IN ('oauth_google', 'oauth_apple')) AS providers
         FROM identity i WHERE i.id = $1`,
      [identityId],
    );
    if (!r) return null;
    return {
      id: r.id,
      status: r.status,
      displayName: r.display_name,
      createdAt: r.created_at,
      suspendedAt: r.suspended_at,
      closedAt: r.closed_at,
      erasedAt: r.erased_at,
      deletionScheduledFor: r.deletion_scheduled_for,
      hasPassword: r.has_password,
      providers: (r.providers ?? []).map((p) => (p === 'oauth_google' ? 'Google' : 'Apple')),
    };
  }

  /** Every address on the account now, primary first. */
  async identifiers(identityId: string): Promise<SubjectIdentifier[]> {
    const rows = await this.db.rows<{
      kind: 'email' | 'phone';
      value: string;
      is_primary: boolean;
      verified: boolean;
    }>(
      `SELECT kind, value, is_primary, verified_at IS NOT NULL AS verified
         FROM identity_identifier
        WHERE identity_id = $1 AND revoked_at IS NULL AND value IS NOT NULL
        ORDER BY is_primary DESC, kind, created_at`,
      [identityId],
    );
    return rows.map((r) => ({
      kind: r.kind,
      value: r.value,
      primary: r.is_primary,
      verified: r.verified,
    }));
  }

  async recoveries(identityId: string): Promise<RecoveryRow[]> {
    const rows = await this.db.rows<{
      requested_at: Date;
      eligible_at: Date;
      review: string;
      decision: string | null;
      cancelled_at: Date | null;
      cancelled_by: string | null;
      completed_at: Date | null;
    }>(
      `SELECT requested_at, eligible_at, review, decision, cancelled_at, cancelled_by, completed_at
         FROM mfa_recovery WHERE identity_id = $1 ORDER BY requested_at DESC LIMIT 20`,
      [identityId],
    );
    return rows.map((r) => ({
      requestedAt: r.requested_at,
      eligibleAt: r.eligible_at,
      review: r.review,
      decision: r.decision,
      cancelledAt: r.cancelled_at,
      cancelledBy: r.cancelled_by,
      completedAt: r.completed_at,
    }));
  }

  /** What operators changed on this account, newest first. Looking isn't listed here. */
  async history(identityId: string, limit = 20): Promise<PastAction[]> {
    const rows = await this.db.rows<{
      action: OperatorActionKind;
      reason: string | null;
      occurred_at: Date;
      by: string | null;
    }>(
      `SELECT a.action, a.reason, a.occurred_at,
              (SELECT ii.value FROM identity_identifier ii
                WHERE ii.identity_id = o.identity_id AND ii.is_primary AND ii.revoked_at IS NULL
                ORDER BY ii.kind LIMIT 1) AS by
         FROM operator_action a JOIN operator o ON o.id = a.operator_id
        WHERE a.identity_id = $1 AND a.action NOT IN ('searched', 'viewed')
        ORDER BY a.occurred_at DESC, a.id DESC LIMIT $2`,
      [identityId, limit],
    );
    return rows.map((r) => ({
      action: r.action,
      reason: r.reason,
      occurredAt: r.occurred_at,
      by: r.by,
    }));
  }

  /** Suspends an active identity; its sessions end in the same statement (0008's effects). */
  async suspend(db: Db, identityId: string): Promise<boolean> {
    const res = await db.query(
      `UPDATE identity SET status = 'suspended' WHERE id = $1 AND status = 'active'`,
      [identityId],
    );
    return (res.rowCount ?? 0) > 0;
  }

  async reinstate(db: Db, identityId: string): Promise<boolean> {
    const res = await db.query(
      `UPDATE identity SET status = 'active' WHERE id = $1 AND status = 'suspended'`,
      [identityId],
    );
    return (res.rowCount ?? 0) > 0;
  }

  /** Ends every live session of the identity. Returns the sids, for Hydra. */
  async endAllSessions(db: Db, identityId: string): Promise<string[]> {
    const res = await db.query<{ sid: string }>(
      `UPDATE auth_session SET revoked_at = now(), revoke_reason = 'operator'
        WHERE identity_id = $1 AND revoked_at IS NULL
        RETURNING sid`,
      [identityId],
    );
    return res.rows.map((r) => r.sid);
  }
}
