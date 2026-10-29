import { Injectable } from '@nestjs/common';
import { createHash, randomBytes, randomInt, timingSafeEqual } from 'node:crypto';
import { env } from '../config/env';
import { one, type Db } from '../db/database.service';
import type { Identifier } from '../identity/identifier';

export type OtpPurpose = 'sign_in' | 'recovery';
export type OtpChannel = 'email' | 'whatsapp';

const CODE_LENGTH = 6;

interface ChallengeRow {
  id: string;
  identity_id: string;
  purpose: OtpPurpose;
  channel: OtpChannel;
  destination: string;
  code_hash: Buffer;
  code_salt: Buffer;
  code_length: number;
  status: 'issued' | 'verified' | 'expired' | 'locked';
  expires_at: Date;
  attempt_count: number;
  max_attempts: number;
  resend_count: number;
  max_resends: number;
  locked_until: Date | null;
  live: boolean;
}

/** What the code screen shows about the code it is waiting for. */
export interface CodeView {
  otpId: string;
  purpose: OtpPurpose;
  channel: OtpChannel;
  codeLength: number;
  expiresAt: Date;
}

export type SendOutcome =
  | { kind: 'sent'; view: CodeView; code: string; destination: string }
  | { kind: 'locked'; until: Date }
  | { kind: 'rate_limited'; availableAt: Date };

export type VerifyOutcome =
  | { kind: 'verified'; otpId: string; identityId: string }
  | { kind: 'invalid'; remaining: number; view: CodeView }
  | { kind: 'locked'; until: Date }
  | { kind: 'expired' }
  | { kind: 'not_found' };

/**
 * One-time codes over otp_challenge (db/migrations/0002_one_time_codes.sql). The table's triggers
 * own the rules; this service reads the same conditions first, so the member sees "locked until"
 * or "try again at" rather than a refusal, and the triggers stay the backstop.
 *
 * Nothing here throws on a wrong code. verify() counts the attempt and returns an outcome, and
 * the caller must let the transaction commit - otherwise the attempt is rolled back and the cap
 * never bites. Codes are delivered by the caller after commit: a rolled-back challenge must not
 * have put a code in anyone's inbox.
 */
@Injectable()
export class OtpService {
  /**
   * A code for this sign-in. The live one is resent while it has resends left; otherwise it is
   * retired and a new one issued. Both count towards the address's five an hour.
   */
  async send(
    db: Db,
    a: { identityId: string; purpose: OtpPurpose; to: Identifier; flow: string },
  ): Promise<SendOutcome> {
    const destination = a.to.value;
    const channel: OtpChannel = a.to.kind === 'email' ? 'email' : 'whatsapp';

    const lock = await one<{ until: Date | null }>(db, 'SELECT otp_locked_until($1) AS until', [
      destination,
    ]);
    if (lock?.until) return { kind: 'locked', until: lock.until };

    const rate = await one<{ n: string; oldest: Date | null }>(
      db,
      `SELECT count(*) AS n, min(sent_at) AS oldest FROM otp_send
        WHERE destination_hash = otp_destination_hash($1) AND sent_at > now() - interval '1 hour'`,
      [destination],
    );
    if (Number(rate?.n ?? 0) >= 5) {
      return {
        kind: 'rate_limited',
        availableAt: new Date(rate!.oldest!.getTime() + 60 * 60 * 1000),
      };
    }

    const code = newCode();
    const salt = randomBytes(16);
    const flowHash = sha256(a.flow);
    const live = await one<ChallengeRow>(
      db,
      `SELECT * FROM otp_challenge WHERE flow_hash = $1 AND purpose = $2 AND status = 'issued' FOR UPDATE`,
      [flowHash, a.purpose],
    );

    let row: ChallengeRow | null;
    if (live && live.destination === destination && live.resend_count < live.max_resends) {
      row = await one<ChallengeRow>(
        db,
        `UPDATE otp_challenge
            SET code_hash = $2, code_salt = $3, resend_count = resend_count + 1,
                expires_at = now() + make_interval(secs => $4)
          WHERE id = $1 RETURNING *`,
        [live.id, hashCode(code, salt), salt, env.OTP_TTL_SECONDS],
      );
    } else {
      if (live) {
        await db.query("UPDATE otp_challenge SET status = 'expired' WHERE id = $1", [live.id]);
      }
      row = await one<ChallengeRow>(
        db,
        `INSERT INTO otp_challenge
           (identity_id, purpose, channel, destination, flow_hash, code_hash, code_salt, code_length, expires_at)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, now() + make_interval(secs => $9))
         RETURNING *`,
        [
          a.identityId,
          a.purpose,
          channel,
          destination,
          flowHash,
          hashCode(code, salt),
          salt,
          CODE_LENGTH,
          env.OTP_TTL_SECONDS,
        ],
      );
    }
    return { kind: 'sent', view: view(row!), code, destination };
  }

  /** Counts one attempt at the code, whatever the result. */
  async verify(db: Db, a: { otpId: string; flow: string; code: string }): Promise<VerifyOutcome> {
    const row = await one<ChallengeRow>(
      db,
      `SELECT *, expires_at > now() AS live FROM otp_challenge
        WHERE id = $1 AND flow_hash = $2 FOR UPDATE`,
      [a.otpId, sha256(a.flow)],
    );
    if (!row) return { kind: 'not_found' };
    if (row.status === 'locked') return { kind: 'locked', until: row.locked_until! };
    if (row.status !== 'issued') return { kind: 'expired' };
    if (!row.live) {
      await db.query("UPDATE otp_challenge SET status = 'expired' WHERE id = $1", [row.id]);
      return { kind: 'expired' };
    }

    const typed = a.code.replace(/\s/g, '');
    if (
      typed.length === row.code_length &&
      safeEqual(hashCode(typed, row.code_salt), row.code_hash)
    ) {
      await db.query(
        "UPDATE otp_challenge SET status = 'verified', attempt_count = attempt_count + 1 WHERE id = $1",
        [row.id],
      );
      return { kind: 'verified', otpId: row.id, identityId: row.identity_id };
    }

    // The trigger turns the attempt that reaches the cap into a thirty-minute lock.
    const after = await one<ChallengeRow>(
      db,
      'UPDATE otp_challenge SET attempt_count = attempt_count + 1 WHERE id = $1 RETURNING *',
      [row.id],
    );
    if (after!.status === 'locked') return { kind: 'locked', until: after!.locked_until! };
    return {
      kind: 'invalid',
      remaining: after!.max_attempts - after!.attempt_count,
      view: view(after!),
    };
  }
}

function view(row: ChallengeRow): CodeView {
  return {
    otpId: row.id,
    purpose: row.purpose,
    channel: row.channel,
    codeLength: row.code_length,
    expiresAt: row.expires_at,
  };
}

const newCode = (): string => String(randomInt(0, 10 ** CODE_LENGTH)).padStart(CODE_LENGTH, '0');

const sha256 = (s: string): Buffer => createHash('sha256').update(s).digest();

function hashCode(code: string, salt: Buffer): Buffer {
  return createHash('sha256').update(salt).update(code).digest();
}

function safeEqual(a: Buffer, b: Buffer): boolean {
  return a.length === b.length && timingSafeEqual(a, b);
}
