import { Injectable } from '@nestjs/common';
import { createHash } from 'node:crypto';
import type { FastifyReply } from 'fastify';
import { redirect, renderError } from '../common/pages';
import { env } from '../config/env';
import { Database } from '../db/database.service';
import { HydraAdmin, type LoginRequest } from '../hydra/hydra-admin.service';
import { IdentityRepository, type CredentialKind } from '../identity/identity.repository';
import { RedisService } from '../redis/redis.service';

export interface Seen {
  ip: string;
  userAgent: string | null;
}

export interface Authenticated {
  identityId: string;
  credentialId: string | null;
  credentialKind: CredentialKind | null;
  /** RFC 8176 method names, plus `fed` for an upstream provider. */
  amr: string[];
  detail?: Record<string, unknown>;
}

/**
 * The last step of every way in - password, code, recovery, Google, Apple: open the session in
 * the identity database and tell Hydra who signed in. The session row is written first: a
 * sign-in uni-auth has no record of must never reach a client.
 */
@Injectable()
export class SignIn {
  constructor(
    private readonly hydra: HydraAdmin,
    private readonly db: Database,
    private readonly identities: IdentityRepository,
    private readonly redis: RedisService,
  ) {}

  /**
   * Where a sign-in that already finished sent the browser, for a form sent twice (a double
   * click, Enter and a click, Back and resubmit). Hydra's login challenges are stateless, so the
   * second copy would otherwise run again: a code already spent reads as expired, and the member
   * is told their sign-up failed when it worked. The answer is Hydra's own URL, which only the
   * browser that started the flow can use (its CSRF cookie).
   */
  async finished(challenge: string): Promise<string | null> {
    return this.redis.client.get(doneKey(challenge));
  }

  async accept(
    reply: FastifyReply,
    challenge: string,
    request: LoginRequest,
    seen: Seen,
    a: Authenticated,
  ): Promise<void> {
    const to = await this.acceptTo(reply, challenge, request, seen, a);
    if (to) await redirect(reply, to);
  }

  /**
   * As accept, but hands back where the browser goes next instead of sending it there, for a
   * screen that says what happened first. Null when a screen has already been shown instead.
   */
  async acceptTo(
    reply: FastifyReply,
    challenge: string,
    request: LoginRequest,
    seen: Seen,
    a: Authenticated,
  ): Promise<string | null> {
    const sid = request.session_id;
    if (!sid) throw new Error('Hydra sent a login request with no session id');

    const opened = await this.db.tx(async (db) => {
      const sessionId = await this.identities.openSession(db, {
        identityId: a.identityId,
        credentialId: a.credentialId,
        sid,
        clientId: request.client.client_id,
        ip: seen.ip,
        userAgent: seen.userAgent,
        lifetimeSeconds: env.REMEMBER_SECONDS,
      });
      if (!sessionId) return null;
      if (a.credentialId) await this.identities.markUsed(db, a.credentialId);
      await this.identities.event(
        {
          kind: 'sign_in',
          outcome: 'success',
          identityId: a.identityId,
          clientId: request.client.client_id,
          credentialKind: a.credentialKind,
          authSessionId: sessionId,
          detail: a.detail,
          ...seen,
        },
        db,
      );
      return sessionId;
    });

    // The browser's provider session belongs to someone else, or was revoked: end it at Hydra,
    // and send the member round again on a clean one.
    if (!opened) {
      await this.hydra.revokeLoginSession(sid);
      await renderError(
        reply,
        409,
        'Please sign in again',
        'This browser was signed in as someone else. Go back to the app and sign in again.',
      );
      return null;
    }

    const to = await this.hydra.acceptLogin(challenge, {
      subject: a.identityId,
      remember: true,
      remember_for: env.REMEMBER_SECONDS,
      // How the member authenticated. The API reads these for step-up (section 9); one factor
      // is assurance level 1.
      acr: 'aal1',
      amr: a.amr,
      context: { auth_time: Math.floor(Date.now() / 1000) },
    });
    await this.redis.client.set(doneKey(challenge), to, 'EX', DONE_SECONDS);
    return to;
  }
}

/** Long enough for any repeat of the same form; the challenge itself is gone well before. */
const DONE_SECONDS = 5 * 60;

const doneKey = (challenge: string): string =>
  `uni-auth:login-done:${createHash('sha256').update(challenge).digest('base64url')}`;
