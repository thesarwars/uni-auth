import { Injectable } from '@nestjs/common';
import type { EventRow, SessionRow } from '../account/device';
import { Database, one, type Db } from '../db/database.service';
import { identifierHash, type Identifier } from './identifier';

export type IdentityStatus = 'active' | 'suspended' | 'closed';
export type CredentialKind =
  'password' | 'oauth_google' | 'oauth_apple' | 'totp' | 'recovery_codes' | 'passkey';
/**
 * The credentials the identifier screen offers once it knows who is signing in; totp and
 * recovery codes are second steps, and a passkey says who it is by itself.
 */
export type FirstFactor = 'password' | 'oauth_google' | 'oauth_apple';

/** An identifier that signs someone in, and what that identity can sign in with. */
export interface Resolved {
  identityId: string;
  status: Exclude<IdentityStatus, 'closed'>;
  credentials: FirstFactor[];
}

export interface SessionState {
  identityId: string;
  identityStatus: IdentityStatus;
  revoked: boolean;
  /** The assurance level the session was opened at: 2 after a second factor. */
  aal: 1 | 2;
}

/** The member's 2-step verification, for the account centre. */
export interface TwoStep {
  totp: { addedAt: Date; lastUsedAt: Date | null } | null;
  /** Unused recovery codes left, and when the set was made; null with no set. */
  codes: { left: number; madeAt: Date } | null;
}

/** One of an identity's live passkeys. */
export interface LivePasskey {
  id: string;
  webauthnId: Buffer;
  transports: string[];
  nickname: string;
  /** It syncs between the member's devices (a password manager), rather than one key. */
  synced: boolean;
  createdAt: Date;
  lastUsedAt: Date | null;
}

/** A passkey a sign-in names, with what checking it needs. */
export interface StoredPasskey {
  id: string;
  identityId: string;
  status: Exclude<IdentityStatus, 'closed'>;
  publicKey: Buffer;
  signCount: number;
  transports: string[];
  backupEligible: boolean;
}

export interface AuthEvent {
  kind:
    | 'sign_in'
    | 'sign_out'
    | 'session_revoked'
    | 'lockout'
    | 'password_reset'
    | 'credential_added'
    | 'identifier_verified'
    | 'identifier_added'
    | 'identifier_removed'
    | 'password_changed'
    | 'profile_updated'
    | 'identity_created'
    | 'credential_revoked'
    | 'mfa_enabled'
    | 'mfa_disabled'
    | 'recovery_code_used'
    | 'export_downloaded'
    | 'deletion_requested'
    | 'deletion_cancelled'
    | 'consent_revoked'
    | 'mfa_recovery_requested'
    | 'mfa_recovery_cancelled'
    | 'mfa_recovery_rejected'
    | 'mfa_recovery_completed';
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
      credentials: FirstFactor[] | null;
    }>(
      `SELECT i.id AS identity_id, i.status,
              array_agg(DISTINCT c.kind::text) FILTER (WHERE c.id IS NOT NULL) AS credentials
         FROM identity_identifier ii
         JOIN identity i ON i.id = ii.identity_id
         LEFT JOIN credential c ON c.identity_id = i.id AND c.revoked_at IS NULL
                                AND c.kind IN ('password', 'oauth_google', 'oauth_apple')
        WHERE ii.kind = $1 AND ii.value = $2
          AND ii.verified_at IS NOT NULL AND ii.revoked_at IS NULL AND i.status <> 'closed'
        GROUP BY i.id, i.status`,
      [id.kind, id.value],
    );
    if (!row) return null;
    return { identityId: row.identity_id, status: row.status, credentials: row.credentials ?? [] };
  }

  /** The identity a live Google or Apple credential belongs to, by the provider's `sub`. */
  async byProvider(
    kind: 'oauth_google' | 'oauth_apple',
    subject: string,
  ): Promise<{ identityId: string; status: IdentityStatus; credentialId: string } | null> {
    const [row] = await this.db.rows<{ identity_id: string; status: IdentityStatus; id: string }>(
      `SELECT c.id, c.identity_id, i.status FROM credential c JOIN identity i ON i.id = c.identity_id
        WHERE c.kind = $1 AND c.provider_subject = $2 AND c.revoked_at IS NULL`,
      [kind, subject],
    );
    return row ? { identityId: row.identity_id, status: row.status, credentialId: row.id } : null;
  }

  /** Adds a Google or Apple credential to an identity, and journals it. */
  async linkProvider(
    db: Db,
    a: {
      identityId: string;
      kind: 'oauth_google' | 'oauth_apple';
      subject: string;
      email: string | null;
      emailVerified: boolean;
      clientId: string;
      ip: string | null;
      userAgent: string | null;
    },
  ): Promise<string> {
    const row = await one<{ id: string }>(
      db,
      `INSERT INTO credential (identity_id, kind, provider_subject, provider_email, provider_email_verified)
       VALUES ($1, $2, $3, $4, $5) RETURNING id`,
      [a.identityId, a.kind, a.subject, a.email, a.email === null ? null : a.emailVerified],
    );
    await this.event(
      {
        kind: 'credential_added',
        outcome: 'success',
        identityId: a.identityId,
        clientId: a.clientId,
        credentialKind: a.kind,
        detail: { linked_by: 'verified_email' },
        ip: a.ip,
        userAgent: a.userAgent,
      },
      db,
    );
    return row!.id;
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
      deviceLabel?: string | null;
      geoCity?: string | null;
      geoCountry?: string | null;
      aal?: 1 | 2;
    },
  ): Promise<string | null> {
    const row = await one<{ id: string }>(
      db,
      `INSERT INTO auth_session (identity_id, credential_id, sid, client_id, ip_address, user_agent, expires_at,
                                 device_label, geo_city, geo_country, aal)
       VALUES ($1, $2, $3, $4, $5, $6, now() + make_interval(secs => $7), $8, $9, $10, $11)
       ON CONFLICT (sid) DO UPDATE SET last_seen_at = now(),
                                       aal = GREATEST(auth_session.aal, EXCLUDED.aal)
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
        s.deviceLabel ?? null,
        s.geoCity ?? null,
        s.geoCountry ?? null,
        s.aal ?? 1,
      ],
    );
    return row?.id ?? null;
  }

  /**
   * Whether a sign-in about to open session `sid` comes from a device the member has not used
   * lately (account-plan.md section 4, new-device alert): they have signed in before, but no
   * session in the last 90 days had this device and country. A first sign-in (sign-up) and the
   * same sid seen again are not new.
   */
  async isNewDevice(
    db: Db,
    identityId: string,
    sid: string,
    deviceLabel: string | null,
    geoCountry: string | null,
  ): Promise<boolean> {
    const row = await one<{ fresh: boolean }>(
      db,
      `SELECT EXISTS (SELECT 1 FROM auth_session WHERE identity_id = $1 AND sid <> $2)
          AND NOT EXISTS (SELECT 1 FROM auth_session WHERE sid = $2)
          AND NOT EXISTS (
                SELECT 1 FROM auth_session
                 WHERE identity_id = $1 AND sid <> $2
                   AND created_at > now() - interval '90 days'
                   AND device_label IS NOT DISTINCT FROM $3
                   AND geo_country IS NOT DISTINCT FROM $4) AS fresh`,
      [identityId, sid, deviceLabel, geoCountry],
    );
    return row?.fresh ?? false;
  }

  /** The session behind a single sign-on, marked as seen if it is still good. */
  async seeSession(sid: string): Promise<SessionState | null> {
    return this.db.tx(async (db) => {
      const row = await one<{
        id: string;
        identity_id: string;
        status: IdentityStatus;
        revoked: boolean;
        aal: 1 | 2;
      }>(
        db,
        `SELECT s.id, s.identity_id, i.status, s.aal,
                (s.revoked_at IS NOT NULL OR s.expires_at <= now()) AS revoked
           FROM auth_session s JOIN identity i ON i.id = s.identity_id
          WHERE s.sid = $1 FOR UPDATE OF s`,
        [sid],
      );
      if (!row) return null;
      if (!row.revoked && row.status === 'active') {
        await db.query('UPDATE auth_session SET last_seen_at = now() WHERE id = $1', [row.id]);
      }
      return {
        identityId: row.identity_id,
        identityStatus: row.status,
        revoked: row.revoked,
        aal: row.aal,
      };
    });
  }

  /**
   * Ends one session, as the member signing out does. Returns the identity it belonged to, or
   * null when there was no live session by that sid.
   */
  async endSession(
    db: Db,
    sid: string,
    reason: 'sign_out',
  ): Promise<{ id: string; identityId: string } | null> {
    const row = await one<{ id: string; identity_id: string }>(
      db,
      `UPDATE auth_session SET revoked_at = now(), revoke_reason = $2
        WHERE sid = $1 AND revoked_at IS NULL
        RETURNING id, identity_id`,
      [sid, reason],
    );
    return row ? { id: row.id, identityId: row.identity_id } : null;
  }

  /**
   * The sids of an identity's sessions this transaction ended for `reason` - the ones a
   * database function (password_reset_complete, say) revoked, to be ended at Hydra too.
   */
  async sessionsEndedNow(db: Db, identityId: string, reason: string): Promise<string[]> {
    const res = await db.query<{ sid: string }>(
      `SELECT sid FROM auth_session
        WHERE identity_id = $1 AND revoke_reason = $2 AND revoked_at = now()`,
      [identityId, reason],
    );
    return res.rows.map((r) => r.sid);
  }

  /**
   * Whether a session may still be refreshed: live, and its identity active. null when uni-auth
   * has no such session - one accepted through Hydra's admin API, not by this application.
   */
  async mayRefresh(sid: string): Promise<boolean | null> {
    const row = await one<{ ok: boolean }>(
      this.db.asDb(),
      `SELECT (s.revoked_at IS NULL AND s.expires_at > now() AND i.status = 'active') AS ok
         FROM auth_session s JOIN identity i ON i.id = s.identity_id
        WHERE s.sid = $1`,
      [sid],
    );
    return row ? row.ok : null;
  }

  /**
   * Marks a session seen as its tokens are refreshed: what "last active" on the Devices page
   * reads. Only a live session moves; the refresh hook has already decided whether it may.
   */
  async touchSession(sid: string): Promise<void> {
    await this.db.asDb().query(
      `UPDATE auth_session SET last_seen_at = now()
        WHERE sid = $1 AND revoked_at IS NULL AND expires_at > now() AND last_seen_at < now()`,
      [sid],
    );
  }

  /** An identity's live sessions - one per device it is signed in on - for the Devices page. */
  async liveSessions(identityId: string): Promise<SessionRow[]> {
    const res = await this.db.asDb().query<{
      id: string;
      sid: string;
      user_agent: string | null;
      ip: string | null;
      device_label: string | null;
      geo_city: string | null;
      geo_country: string | null;
      created_at: Date;
      last_seen_at: Date;
    }>(
      `SELECT id, sid, user_agent, host(ip_address) AS ip, device_label, geo_city, geo_country,
              created_at, last_seen_at FROM auth_session
        WHERE identity_id = $1 AND revoked_at IS NULL AND expires_at > now()
        ORDER BY last_seen_at DESC, id DESC
        LIMIT 100`,
      [identityId],
    );
    return res.rows.map((r) => ({
      id: r.id,
      sid: r.sid,
      userAgent: r.user_agent,
      ip: r.ip,
      deviceLabel: r.device_label,
      geoCity: r.geo_city,
      geoCountry: r.geo_country,
      createdAt: r.created_at,
      lastSeenAt: r.last_seen_at,
    }));
  }

  /**
   * Signs one of the identity's own devices out, never `keepSid` (the device asking). The
   * identity is part of the match: an id from another member's list ends nothing.
   */
  async endDevice(
    db: Db,
    identityId: string,
    sessionId: string,
    keepSid: string,
  ): Promise<{ id: string; sid: string; userAgent: string | null } | null> {
    const row = await one<{ id: string; sid: string; user_agent: string | null }>(
      db,
      `UPDATE auth_session SET revoked_at = now(), revoke_reason = 'sign_out'
        WHERE id = $1 AND identity_id = $2 AND sid <> $3 AND revoked_at IS NULL
        RETURNING id, sid, user_agent`,
      [sessionId, identityId, keepSid],
    );
    return row ? { id: row.id, sid: row.sid, userAgent: row.user_agent } : null;
  }

  /** Signs out every device of the identity but `keepSid`. Returns the sids, for Hydra. */
  async endOtherDevices(db: Db, identityId: string, keepSid: string): Promise<string[]> {
    const res = await db.query<{ sid: string }>(
      `UPDATE auth_session SET revoked_at = now(), revoke_reason = 'sign_out'
        WHERE identity_id = $1 AND sid <> $2 AND revoked_at IS NULL
        RETURNING sid`,
      [identityId, keepSid],
    );
    return res.rows.map((r) => r.sid);
  }

  /** The identity's journal of the last `days` days, newest first, for Security activity. */
  async activity(identityId: string, days = 90, limit = 100): Promise<EventRow[]> {
    const res = await this.db.asDb().query<{
      kind: string;
      outcome: 'success' | 'failure';
      credential_kind: string | null;
      user_agent: string | null;
      ip: string | null;
      detail: Record<string, unknown> | null;
      occurred_at: Date;
    }>(
      `SELECT kind, outcome, credential_kind, user_agent, host(ip_address) AS ip, detail, occurred_at
         FROM auth_event
        WHERE identity_id = $1 AND occurred_at > now() - make_interval(days => $2)
        ORDER BY occurred_at DESC, id DESC
        LIMIT $3`,
      [identityId, days, limit],
    );
    return res.rows.map((r) => ({
      kind: r.kind,
      outcome: r.outcome,
      credentialKind: r.credential_kind,
      userAgent: r.user_agent,
      ip: r.ip,
      detail: r.detail ?? {},
      occurredAt: r.occurred_at,
    }));
  }

  // ---------------------------------------------------------------------------------------
  // 2-step verification (account-plan.md part 4)
  // ---------------------------------------------------------------------------------------

  /** Whether sign-in asks this identity for a second step. */
  async hasTotp(identityId: string): Promise<boolean> {
    const [row] = await this.db.rows<{ on: boolean }>(
      `SELECT EXISTS (SELECT 1 FROM credential
                       WHERE identity_id = $1 AND kind = 'totp' AND revoked_at IS NULL) AS on`,
      [identityId],
    );
    return row?.on ?? false;
  }

  async twoStep(identityId: string): Promise<TwoStep> {
    const rows = await this.db.rows<{
      kind: 'totp' | 'recovery_codes';
      created_at: Date;
      last_used_at: Date | null;
      left: number;
    }>(
      `SELECT c.kind, c.created_at, c.last_used_at,
              (SELECT count(*)::int FROM recovery_code r
                WHERE r.credential_id = c.id AND r.used_at IS NULL) AS left
         FROM credential c
        WHERE c.identity_id = $1 AND c.kind IN ('totp', 'recovery_codes') AND c.revoked_at IS NULL`,
      [identityId],
    );
    const totp = rows.find((r) => r.kind === 'totp');
    const codes = rows.find((r) => r.kind === 'recovery_codes');
    return {
      totp: totp ? { addedAt: totp.created_at, lastUsedAt: totp.last_used_at } : null,
      codes: codes ? { left: codes.left, madeAt: codes.created_at } : null,
    };
  }

  /** The live authenticator's sealed seed and the last time step it accepted. */
  async liveTotp(
    identityId: string,
  ): Promise<{ id: string; sealed: Buffer; lastStep: number | null } | null> {
    const [row] = await this.db.rows<{
      id: string;
      secret_ciphertext: Buffer;
      totp_last_step: string | null;
    }>(
      `SELECT id, secret_ciphertext, totp_last_step FROM credential
        WHERE identity_id = $1 AND kind = 'totp' AND revoked_at IS NULL`,
      [identityId],
    );
    if (!row) return null;
    return {
      id: row.id,
      sealed: row.secret_ciphertext,
      lastStep: row.totp_last_step === null ? null : Number(row.totp_last_step),
    };
  }

  /**
   * Spends an authenticator code's time step. False when that step or a later one was spent
   * already - the same code, replayed - or the authenticator has been turned off meanwhile.
   */
  async spendTotpStep(credentialId: string, step: number): Promise<boolean> {
    const res = await this.db.asDb().query(
      `UPDATE credential SET totp_last_step = $2, last_used_at = now()
          WHERE id = $1 AND kind = 'totp' AND revoked_at IS NULL
            AND (totp_last_step IS NULL OR totp_last_step < $2)`,
      [credentialId, step],
    );
    return (res.rowCount ?? 0) === 1;
  }

  /** Spends one recovery code. Null when no unused code of the live set has this hash. */
  async spendRecoveryCode(identityId: string, hash: Buffer): Promise<{ left: number } | null> {
    return this.db.tx(async (db) => {
      const spent = await one<{ credential_id: string }>(
        db,
        `UPDATE recovery_code r SET used_at = now()
           FROM credential c
          WHERE c.id = r.credential_id AND c.identity_id = $1 AND c.kind = 'recovery_codes'
            AND c.revoked_at IS NULL AND r.code_hash = $2 AND r.used_at IS NULL
          RETURNING r.credential_id`,
        [identityId, hash],
      );
      if (!spent) return null;
      await db.query('UPDATE credential SET last_used_at = now() WHERE id = $1', [
        spent.credential_id,
      ]);
      const left = await one<{ n: number }>(
        db,
        'SELECT count(*)::int AS n FROM recovery_code WHERE credential_id = $1 AND used_at IS NULL',
        [spent.credential_id],
      );
      return { left: left!.n };
    });
  }

  /**
   * Turns 2-step verification on: the authenticator, with the step its confirming code was
   * spent at, and a first set of recovery codes. Fails on the schema's one-live-totp rule when
   * it is on already.
   */
  async enableTotp(
    db: Db,
    a: { identityId: string; sealed: Buffer; step: number; codeHashes: Buffer[] },
  ): Promise<void> {
    await db.query(
      `INSERT INTO credential (identity_id, kind, secret_ciphertext, totp_last_step, last_used_at)
       VALUES ($1, 'totp', $2, $3, now())`,
      [a.identityId, a.sealed, a.step],
    );
    await this.insertRecoveryCodes(db, a.identityId, a.codeHashes);
  }

  /** A new set of recovery codes; the old set stops working. */
  async replaceRecoveryCodes(db: Db, identityId: string, codeHashes: Buffer[]): Promise<void> {
    await db.query(
      `UPDATE credential SET revoked_at = now(), revoke_reason = 'replaced'
        WHERE identity_id = $1 AND kind = 'recovery_codes' AND revoked_at IS NULL`,
      [identityId],
    );
    await this.insertRecoveryCodes(db, identityId, codeHashes);
  }

  private async insertRecoveryCodes(db: Db, identityId: string, codeHashes: Buffer[]) {
    const set = await one<{ id: string }>(
      db,
      `INSERT INTO credential (identity_id, kind) VALUES ($1, 'recovery_codes') RETURNING id`,
      [identityId],
    );
    await db.query(
      `INSERT INTO recovery_code (credential_id, code_hash) SELECT $1, unnest($2::bytea[])`,
      [set!.id, codeHashes],
    );
  }

  /** Turns 2-step verification off; the schema takes the recovery codes with it. */
  async disableTotp(db: Db, identityId: string): Promise<boolean> {
    const res = await db.query(
      `UPDATE credential SET revoked_at = now(), revoke_reason = 'removed_by_member'
        WHERE identity_id = $1 AND kind = 'totp' AND revoked_at IS NULL`,
      [identityId],
    );
    return (res.rowCount ?? 0) === 1;
  }

  // ---------------------------------------------------------------------------------------
  // Passkeys (account-plan.md part 5)
  // ---------------------------------------------------------------------------------------

  async passkeys(identityId: string): Promise<LivePasskey[]> {
    const rows = await this.db.rows<{
      id: string;
      webauthn_credential_id: Buffer;
      transports: string[];
      nickname: string;
      backup_eligible: boolean;
      created_at: Date;
      last_used_at: Date | null;
    }>(
      `SELECT id, webauthn_credential_id, transports, nickname, backup_eligible, created_at,
              last_used_at
         FROM credential
        WHERE identity_id = $1 AND kind = 'passkey' AND revoked_at IS NULL
        ORDER BY created_at`,
      [identityId],
    );
    return rows.map((r) => ({
      id: r.id,
      webauthnId: r.webauthn_credential_id,
      transports: r.transports,
      nickname: r.nickname,
      synced: r.backup_eligible,
      createdAt: r.created_at,
      lastUsedAt: r.last_used_at,
    }));
  }

  /** The live passkey with this WebAuthn credential id, of an identity that isn't closed. */
  async passkeyByWebauthnId(webauthnId: Buffer): Promise<StoredPasskey | null> {
    const [row] = await this.db.rows<{
      id: string;
      identity_id: string;
      status: Exclude<IdentityStatus, 'closed'>;
      public_key: Buffer;
      sign_count: string;
      transports: string[];
      backup_eligible: boolean;
    }>(
      `SELECT c.id, c.identity_id, i.status, c.public_key, c.sign_count, c.transports,
              c.backup_eligible
         FROM credential c JOIN identity i ON i.id = c.identity_id
        WHERE c.webauthn_credential_id = $1 AND c.kind = 'passkey' AND c.revoked_at IS NULL
          AND i.status <> 'closed'`,
      [webauthnId],
    );
    if (!row) return null;
    return {
      id: row.id,
      identityId: row.identity_id,
      status: row.status,
      publicKey: row.public_key,
      signCount: Number(row.sign_count),
      transports: row.transports,
      backupEligible: row.backup_eligible,
    };
  }

  /**
   * Records a passkey's use: its new signature counter and backup state. False when the
   * passkey was removed meanwhile, or the counter didn't move forward (a copy of the key; the
   * schema refuses it too).
   */
  async usePasskey(id: string, signCount: number, backedUp: boolean): Promise<boolean> {
    try {
      const res = await this.db.asDb().query(
        `UPDATE credential
            SET sign_count = $2, backup_state = (backup_eligible AND $3), last_used_at = now()
          WHERE id = $1 AND kind = 'passkey' AND revoked_at IS NULL
            AND (sign_count < $2 OR (sign_count = 0 AND $2 = 0))`,
        [id, signCount, backedUp],
      );
      return (res.rowCount ?? 0) === 1;
    } catch (err) {
      if ((err as { code?: string }).code === '23001') return false; // restrict_violation
      throw err;
    }
  }

  async addPasskey(
    db: Db,
    identityId: string,
    p: {
      webauthnId: Buffer;
      publicKey: Buffer;
      signCount: number;
      transports: string[];
      aaguid: string;
      backupEligible: boolean;
      backupState: boolean;
      nickname: string;
    },
  ): Promise<string> {
    const row = await one<{ id: string }>(
      db,
      `INSERT INTO credential
         (identity_id, kind, webauthn_credential_id, public_key, sign_count, transports, aaguid,
          backup_eligible, backup_state, nickname)
       VALUES ($1, 'passkey', $2, $3, $4, $5, $6, $7, $8, $9) RETURNING id`,
      [
        identityId,
        p.webauthnId,
        p.publicKey,
        p.signCount,
        p.transports,
        p.aaguid,
        p.backupEligible,
        p.backupState,
        p.nickname,
      ],
    );
    return row!.id;
  }

  async renamePasskey(identityId: string, id: string, nickname: string): Promise<boolean> {
    const res = await this.db.asDb().query(
      `UPDATE credential SET nickname = $3
        WHERE id = $2 AND identity_id = $1 AND kind = 'passkey' AND revoked_at IS NULL`,
      [identityId, id, nickname],
    );
    return (res.rowCount ?? 0) === 1;
  }

  /** Removes one of the identity's passkeys; its name, or null when there was no such passkey. */
  async removePasskey(db: Db, identityId: string, id: string): Promise<string | null> {
    const row = await one<{ nickname: string }>(
      db,
      `UPDATE credential SET revoked_at = now(), revoke_reason = 'removed_by_member'
        WHERE id = $2 AND identity_id = $1 AND kind = 'passkey' AND revoked_at IS NULL
        RETURNING nickname`,
      [identityId, id],
    );
    return row?.nickname ?? null;
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
   * with it revokes the old password and every session. `ended` names those sessions, to be
   * ended at Hydra once this commits. null: no such usable ticket here.
   */
  async completeReset(
    db: Db,
    a: { ticketId: string; flowHash: Buffer; secretHash: Buffer },
  ): Promise<{ identityId: string; credentialId: string; ended: string[] } | null> {
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
    const ended = await this.sessionsEndedNow(db, ticket.identity_id, 'password_reset');
    return { identityId: ticket.identity_id, credentialId: done!.id, ended };
  }

  /**
   * Creates an identity from a proved address: the identifier verified and primary, and the one
   * credential it signs in with - a password, or a Google or Apple account. Journals each step.
   * Throws AddressTaken when another identity verified the same address first.
   */
  async createIdentity(
    db: Db,
    a: {
      identifier: Identifier;
      credential:
        | { kind: 'password'; secretHash: Buffer }
        | { kind: 'oauth_google' | 'oauth_apple'; subject: string; email: string };
      clientId: string;
      ip: string | null;
      userAgent: string | null;
    },
  ): Promise<{ identityId: string; credentialId: string }> {
    await db.query('SAVEPOINT create_identity');
    try {
      const identity = await one<{ id: string }>(
        db,
        'INSERT INTO identity DEFAULT VALUES RETURNING id',
      );
      const identityId = identity!.id;
      await db.query(
        `INSERT INTO identity_identifier (identity_id, kind, value, verified_at, is_primary)
         VALUES ($1, $2, $3, now(), true)`,
        [identityId, a.identifier.kind, a.identifier.value],
      );
      const c = a.credential;
      const credential =
        c.kind === 'password'
          ? await one<{ id: string }>(
              db,
              `INSERT INTO credential (identity_id, kind, secret_hash, password_policy_id)
               VALUES ($1, 'password', $2, password_policy_in_effect()) RETURNING id`,
              [identityId, c.secretHash],
            )
          : await one<{ id: string }>(
              db,
              `INSERT INTO credential (identity_id, kind, provider_subject, provider_email, provider_email_verified)
               VALUES ($1, $2, $3, $4, true) RETURNING id`,
              [identityId, c.kind, c.subject, c.email],
            );
      await db.query('RELEASE SAVEPOINT create_identity');

      const base = { identityId, clientId: a.clientId, ip: a.ip, userAgent: a.userAgent };
      await this.event({ ...base, kind: 'identity_created', outcome: 'success' }, db);
      await this.event(
        {
          ...base,
          kind: 'identifier_verified',
          outcome: 'success',
          detail: { kind: a.identifier.kind },
        },
        db,
      );
      await this.event(
        { ...base, kind: 'credential_added', outcome: 'success', credentialKind: c.kind },
        db,
      );
      return { identityId, credentialId: credential!.id };
    } catch (err) {
      await db.query('ROLLBACK TO SAVEPOINT create_identity');
      if ((err as { code?: string }).code === '23505') throw new AddressTaken();
      throw err;
    }
  }

  // ---------------------------------------------------------------------------------------
  // The account centre (account-plan.md parts 1-3)
  // ---------------------------------------------------------------------------------------

  async profile(identityId: string): Promise<Profile | null> {
    const [row] = await this.db.rows<{
      id: string;
      status: IdentityStatus;
      display_name: string | null;
      locale: string;
      created_at: Date;
      password_set_at: Date | null;
      upstreams: ('oauth_google' | 'oauth_apple')[] | null;
    }>(
      `SELECT i.id, i.status, i.display_name, i.locale, i.created_at,
              (SELECT c.created_at FROM credential c
                WHERE c.identity_id = i.id AND c.kind = 'password' AND c.revoked_at IS NULL) AS password_set_at,
              (SELECT array_agg(DISTINCT c.kind::text) FROM credential c
                WHERE c.identity_id = i.id AND c.kind IN ('oauth_google', 'oauth_apple')
                  AND c.revoked_at IS NULL) AS upstreams
         FROM identity i WHERE i.id = $1`,
      [identityId],
    );
    if (!row) return null;
    return {
      identityId: row.id,
      status: row.status,
      displayName: row.display_name,
      locale: row.locale,
      createdAt: row.created_at,
      passwordSetAt: row.password_set_at,
      upstreams: row.upstreams ?? [],
    };
  }

  async updateProfile(
    db: Db,
    identityId: string,
    p: { displayName: string | null; locale: string },
  ): Promise<void> {
    await db.query(
      `UPDATE identity SET display_name = $2, locale = $3 WHERE id = $1 AND status = 'active'`,
      [identityId, p.displayName, p.locale],
    );
  }

  /** The live identifiers, primary first, then emails before phones, oldest first. */
  async identifiers(identityId: string, db: Db = this.db.asDb()): Promise<IdentifierRow[]> {
    const res = await db.query<{
      id: string;
      kind: 'email' | 'phone';
      value: string;
      verified_at: Date | null;
      is_primary: boolean;
      created_at: Date;
    }>(
      `SELECT id, kind, value, verified_at, is_primary, created_at FROM identity_identifier
        WHERE identity_id = $1 AND revoked_at IS NULL
        ORDER BY kind, is_primary DESC, created_at`,
      [identityId],
    );
    return res.rows.map((r) => ({
      id: r.id,
      kind: r.kind,
      value: r.value,
      verified: r.verified_at !== null,
      primary: r.is_primary,
      addedAt: r.created_at,
    }));
  }

  /** The identifier a "Confirm it's you" sign-in starts from: the primary email, else phone. */
  async primaryIdentifier(identityId: string): Promise<Identifier | null> {
    const rows = await this.identifiers(identityId);
    const pick =
      rows.find((r) => r.primary && r.verified && r.kind === 'email') ??
      rows.find((r) => r.primary && r.verified) ??
      rows.find((r) => r.verified);
    return pick ? { kind: pick.kind, value: pick.value } : null;
  }

  /**
   * Adds an address the member has just proved, verified. It becomes the primary of its kind
   * when the identity has none. Throws AddressTaken when another identity verified it first.
   */
  async addIdentifier(db: Db, identityId: string, id: Identifier): Promise<string> {
    await db.query('SAVEPOINT add_identifier');
    try {
      const row = await one<{ id: string }>(
        db,
        `INSERT INTO identity_identifier (identity_id, kind, value, verified_at, is_primary)
         VALUES ($1, $2, $3, now(),
                 NOT EXISTS (SELECT 1 FROM identity_identifier
                              WHERE identity_id = $1 AND kind = $2 AND is_primary))
         RETURNING id`,
        [identityId, id.kind, id.value],
      );
      await db.query('RELEASE SAVEPOINT add_identifier');
      return row!.id;
    } catch (err) {
      await db.query('ROLLBACK TO SAVEPOINT add_identifier');
      if ((err as { code?: string }).code === '23505') throw new AddressTaken();
      throw err;
    }
  }

  /**
   * Makes a verified identifier the primary of its kind. Returns the identifier it replaced, or
   * null when there was none, or nothing changed (not the member's, or not verified).
   */
  async makePrimary(
    db: Db,
    identityId: string,
    identifierId: string,
  ): Promise<{ made: IdentifierRow; was: IdentifierRow | null } | null> {
    const rows = await this.identifiers(identityId, db);
    const made = rows.find((r) => r.id === identifierId);
    if (!made || !made.verified || made.primary) return null;
    const was = rows.find((r) => r.kind === made.kind && r.primary) ?? null;
    if (was) {
      await db.query('UPDATE identity_identifier SET is_primary = false WHERE id = $1', [was.id]);
    }
    await db.query('UPDATE identity_identifier SET is_primary = true WHERE id = $1', [made.id]);
    return { made, was };
  }

  /**
   * Removes an identifier. A primary hands its place to the oldest other verified identifier of
   * its kind, if there is one. Throws LastIdentifier rather than leave none verified (the
   * schema refuses it too: 0005 identity_identifier_keep_one).
   */
  async removeIdentifier(
    db: Db,
    identityId: string,
    identifierId: string,
  ): Promise<IdentifierRow | null> {
    const rows = await this.identifiers(identityId, db);
    const gone = rows.find((r) => r.id === identifierId);
    if (!gone) return null;
    if (gone.verified && !rows.some((r) => r.id !== gone.id && r.verified)) {
      throw new LastIdentifier();
    }
    await db.query(
      'UPDATE identity_identifier SET revoked_at = now(), is_primary = false WHERE id = $1',
      [gone.id],
    );
    if (gone.primary) {
      const heir = rows.find((r) => r.id !== gone.id && r.kind === gone.kind && r.verified);
      if (heir) {
        await db.query('UPDATE identity_identifier SET is_primary = true WHERE id = $1', [heir.id]);
      }
    }
    return gone;
  }

  /**
   * Sets a new password from the account centre (0005 password_change): every other session is
   * revoked, `keepSid` stays signed in. `ended` names the sessions to end at Hydra after commit.
   */
  async changePassword(
    db: Db,
    a: { identityId: string; secretHash: Buffer; keepSid: string },
  ): Promise<{ credentialId: string; ended: string[] }> {
    const done = await one<{ id: string }>(db, 'SELECT password_change($1, $2, $3) AS id', [
      a.identityId,
      a.secretHash,
      a.keepSid,
    ]);
    const res = await db.query<{ sid: string }>(
      `SELECT sid FROM auth_session
        WHERE identity_id = $1 AND revoked_at = now()
          AND revoke_reason IN ('password_changed', 'credential_revoked')`,
      [a.identityId],
    );
    return { credentialId: done!.id, ended: res.rows.map((r) => r.sid) };
  }

  // ---------------------------------------------------------------------------------------
  // Data and privacy (account-plan.md part 6)
  // ---------------------------------------------------------------------------------------

  /** The Google and Apple accounts linked to the identity, with the address each one gave. */
  async linkedProviders(
    identityId: string,
  ): Promise<
    { id: string; kind: 'oauth_google' | 'oauth_apple'; email: string | null; linkedAt: Date }[]
  > {
    const rows = await this.db.rows<{
      id: string;
      kind: 'oauth_google' | 'oauth_apple';
      provider_email: string | null;
      created_at: Date;
    }>(
      `SELECT id, kind, provider_email, created_at FROM credential
        WHERE identity_id = $1 AND kind IN ('oauth_google', 'oauth_apple') AND revoked_at IS NULL
        ORDER BY kind, created_at`,
      [identityId],
    );
    return rows.map((r) => ({
      id: r.id,
      kind: r.kind,
      email: r.provider_email,
      linkedAt: r.created_at,
    }));
  }

  /**
   * Unlinks a Google or Apple account. The sessions it opened end with it (0001:
   * credential_revoke_sessions), except `keepSid`, the session asking. Returns the sids ended,
   * for Hydra, or null when there was no such link. The identity can still sign in: it always
   * keeps a verified address to send a code to (0005).
   */
  async unlinkProvider(
    db: Db,
    identityId: string,
    kind: 'oauth_google' | 'oauth_apple',
    keepSid: string,
  ): Promise<string[] | null> {
    await db.query(`SELECT set_config('uni_auth.keep_sid', $1, true)`, [keepSid]);
    const res = await db.query(
      `UPDATE credential SET revoked_at = now(), revoke_reason = 'removed_by_member'
        WHERE identity_id = $1 AND kind = $2 AND revoked_at IS NULL`,
      [identityId, kind],
    );
    await db.query(`SELECT set_config('uni_auth.keep_sid', '', true)`);
    if (!res.rowCount) return null;
    return this.sessionsEndedNow(db, identityId, 'credential_revoked');
  }

  /**
   * Schedules the identity's deletion (0012: 14 days on) and signs it out of every device.
   * Returns when it falls due and the sids ended, for Hydra. Asked twice, the first request
   * stands.
   */
  async requestDeletion(
    db: Db,
    identityId: string,
  ): Promise<{ scheduledFor: Date; ended: string[] }> {
    await db.query(
      `INSERT INTO account_deletion (identity_id, scheduled_for) VALUES ($1, now())
       ON CONFLICT (identity_id) WHERE cancelled_at IS NULL AND completed_at IS NULL DO NOTHING`,
      [identityId],
    );
    const pending = await one<{ scheduled_for: Date }>(
      db,
      `SELECT scheduled_for FROM account_deletion
        WHERE identity_id = $1 AND cancelled_at IS NULL AND completed_at IS NULL`,
      [identityId],
    );
    const ended = await db.query<{ sid: string }>(
      `UPDATE auth_session SET revoked_at = now(), revoke_reason = 'deletion_requested'
        WHERE identity_id = $1 AND revoked_at IS NULL
        RETURNING sid`,
      [identityId],
    );
    return { scheduledFor: pending!.scheduled_for, ended: ended.rows.map((r) => r.sid) };
  }

  /** Cancels the identity's pending deletion; the date it was due, or null if none waited. */
  async cancelDeletion(db: Db, identityId: string): Promise<Date | null> {
    const row = await one<{ scheduled_for: Date }>(
      db,
      `UPDATE account_deletion SET cancelled_at = now()
        WHERE identity_id = $1 AND cancelled_at IS NULL AND completed_at IS NULL
        RETURNING scheduled_for`,
      [identityId],
    );
    return row?.scheduled_for ?? null;
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

/** One of an identity's live identifiers, as the account centre lists it. */
export interface IdentifierRow {
  id: string;
  kind: 'email' | 'phone';
  value: string;
  verified: boolean;
  primary: boolean;
  addedAt: Date;
}

/** What the account centre shows about an identity. */
export interface Profile {
  identityId: string;
  status: IdentityStatus;
  displayName: string | null;
  locale: string;
  createdAt: Date;
  /** When the live password was set; null when there is none (Google or Apple only). */
  passwordSetAt: Date | null;
  upstreams: ('oauth_google' | 'oauth_apple')[];
}

/** Removing it would leave the identity with no verified identifier. */
export class LastIdentifier extends Error {
  constructor() {
    super('an identity keeps at least one verified identifier');
  }
}

/** Another identity verified the address, or claimed the provider account, first. */
export class AddressTaken extends Error {
  constructor() {
    super('address already belongs to an identity');
  }
}

const truncate = (ua: string | null): string | null => (ua ? ua.slice(0, 512) : null);
