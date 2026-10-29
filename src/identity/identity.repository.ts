import { Injectable } from '@nestjs/common';
import { Database, one, type Db } from '../db/database.service';
import { identifierHash, type Identifier } from './identifier';

export type IdentityStatus = 'active' | 'suspended' | 'closed';
export type CredentialKind = 'password' | 'oauth_google' | 'oauth_apple';

/** An identifier that signs someone in, and what that identity can sign in with. */
export interface Resolved {
  identityId: string;
  status: Exclude<IdentityStatus, 'closed'>;
  credentials: CredentialKind[];
}

export interface SessionState {
  identityId: string;
  identityStatus: IdentityStatus;
  revoked: boolean;
}

export interface AuthEvent {
  kind:
    | 'sign_in'
    | 'lockout'
    | 'password_reset'
    | 'credential_added'
    | 'identifier_verified'
    | 'identity_created';
  outcome: 'success' | 'failure';
  identityId?: string | null;
  identifier?: Identifier | null;
  clientId?: string | null;
  credentialKind?: CredentialKind | null;
  authSessionId?: string | null;
  ip?: string | null;
  userAgent?: string | null;
  detail?: Record<string, unknown>;
}

/**
 * Reads and writes on the identity tables. Every rule - who may hold an address, when a session
 * may open, what the journal accepts - is the schema's; this only names the statements.
 */
@Injectable()
export class IdentityRepository {
  constructor(private readonly db: Database) {}

  /**
   * Who a verified, live identifier belongs to. A closed identity signs nobody in and is not
   * reported: to the member it is the same as no account.
   */
  async resolve(id: Identifier): Promise<Resolved | null> {
    const [row] = await this.db.rows<{
      identity_id: string;
      status: Exclude<IdentityStatus, 'closed'>;
      credentials: CredentialKind[] | null;
    }>(
      `SELECT i.id AS identity_id, i.status,
              array_agg(DISTINCT c.kind::text) FILTER (WHERE c.id IS NOT NULL) AS credentials
         FROM identity_identifier ii
         JOIN identity i ON i.id = ii.identity_id
         LEFT JOIN credential c ON c.identity_id = i.id AND c.revoked_at IS NULL
        WHERE ii.kind = $1 AND ii.value = $2
          AND ii.verified_at IS NOT NULL AND ii.revoked_at IS NULL AND i.status <> 'closed'
        GROUP BY i.id, i.status`,
      [id.kind, id.value],
    );
    if (!row) return null;
    return { identityId: row.identity_id, status: row.status, credentials: row.credentials ?? [] };
  }

  async livePassword(identityId: string): Promise<{ id: string; secret_hash: Buffer } | null> {
    const [row] = await this.db.rows<{ id: string; secret_hash: Buffer }>(
      `SELECT id, secret_hash FROM credential
        WHERE identity_id = $1 AND kind = 'password' AND revoked_at IS NULL`,
      [identityId],
    );
    return row ?? null;
  }

  /**
   * Opens the provider session Hydra is about to remember, named by its login session id: the
   * `sid` every token from it carries. Signing in again on the same browser (prompt=login, or
   * after a lapse) finds the same sid; that is the same session, seen again - unless it now
   * names someone else or was revoked, which the caller must not accept.
   */
  async openSession(
    db: Db,
    s: {
      identityId: string;
      credentialId: string | null;
      sid: string;
      clientId: string;
      ip: string | null;
      userAgent: string | null;
      lifetimeSeconds: number;
    },
  ): Promise<string | null> {
    const row = await one<{ id: string }>(
      db,
      `INSERT INTO auth_session (identity_id, credential_id, sid, client_id, ip_address, user_agent, expires_at)
       VALUES ($1, $2, $3, $4, $5, $6, now() + make_interval(secs => $7))
       ON CONFLICT (sid) DO UPDATE SET last_seen_at = now()
         WHERE auth_session.identity_id = EXCLUDED.identity_id
           AND auth_session.revoked_at IS NULL AND auth_session.expires_at > now()
       RETURNING id`,
      [
        s.identityId,
        s.credentialId,
        s.sid,
        s.clientId,
        s.ip,
        truncate(s.userAgent),
        s.lifetimeSeconds,
      ],
    );
    return row?.id ?? null;
  }

  /** The session behind a single sign-on, marked as seen if it is still good. */
  async seeSession(sid: string): Promise<SessionState | null> {
    return this.db.tx(async (db) => {
      const row = await one<{
        id: string;
        identity_id: string;
        status: IdentityStatus;
        revoked: boolean;
      }>(
        db,
        `SELECT s.id, s.identity_id, i.status,
                (s.revoked_at IS NOT NULL OR s.expires_at <= now()) AS revoked
           FROM auth_session s JOIN identity i ON i.id = s.identity_id
          WHERE s.sid = $1 FOR UPDATE OF s`,
        [sid],
      );
      if (!row) return null;
      if (!row.revoked && row.status === 'active') {
        await db.query('UPDATE auth_session SET last_seen_at = now() WHERE id = $1', [row.id]);
      }
      return { identityId: row.identity_id, identityStatus: row.status, revoked: row.revoked };
    });
  }

  async markUsed(db: Db, credentialId: string): Promise<void> {
    await db.query('UPDATE credential SET last_used_at = now() WHERE id = $1', [credentialId]);
  }

  /**
   * Opens a password-reset ticket from a recovery code just verified. The schema checks it was
   * a recovery code of this identity, verified in the last fifteen minutes.
   */
  async openReset(db: Db, identityId: string, otpId: string): Promise<string> {
    const row = await one<{ id: string }>(
      db,
      `INSERT INTO password_reset (identity_id, otp_challenge_id, expires_at)
       VALUES ($1, $2, now() + interval '15 minutes') RETURNING id`,
      [identityId, otpId],
    );
    return row!.id;
  }

  /**
   * Sets the new password through a ticket opened in this same sign-in (its code's flow), and
   * with it revokes the old password and every session. null: no such usable ticket here.
   */
  async completeReset(
    db: Db,
    a: { ticketId: string; flowHash: Buffer; secretHash: Buffer },
  ): Promise<{ identityId: string; credentialId: string } | null> {
    const ticket = await one<{ identity_id: string }>(
      db,
      `SELECT pr.identity_id FROM password_reset pr
         JOIN otp_challenge o ON o.id = pr.otp_challenge_id
        WHERE pr.id = $1 AND o.flow_hash = $2 AND pr.consumed_at IS NULL AND pr.expires_at > now()
        FOR UPDATE OF pr`,
      [a.ticketId, a.flowHash],
    );
    if (!ticket) return null;
    const done = await one<{ id: string }>(db, 'SELECT password_reset_complete($1, $2) AS id', [
      a.ticketId,
      a.secretHash,
    ]);
    return { identityId: ticket.identity_id, credentialId: done!.id };
  }

  /** Appends to auth_event, in the caller's transaction or on its own. */
  async event(e: AuthEvent, db: Db = this.db.asDb()): Promise<void> {
    await db.query(
      `INSERT INTO auth_event
         (identity_id, identifier_hash, kind, outcome, client_id, credential_kind, auth_session_id,
          ip_address, user_agent, detail)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)`,
      [
        e.identityId ?? null,
        e.identifier ? identifierHash(e.identifier) : null,
        e.kind,
        e.outcome,
        e.clientId ?? null,
        e.credentialKind ?? null,
        e.authSessionId ?? null,
        e.ip ?? null,
        truncate(e.userAgent ?? null),
        e.detail ?? {},
      ],
    );
  }
}

const truncate = (ua: string | null): string | null => (ua ? ua.slice(0, 512) : null);
