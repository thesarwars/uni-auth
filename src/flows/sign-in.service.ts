import { Injectable } from '@nestjs/common';
import { createHash } from 'node:crypto';
import type { FastifyReply } from 'fastify';
import { redirect, renderError } from '../common/pages';
import { env } from '../config/env';
import { describeDevice } from '../account/device';
import { Database } from '../db/database.service';
import { EmailSender } from '../delivery/email.sender';
import { countryName, GeoIp } from '../geo/geoip.service';
import { HydraAdmin, type LoginRequest } from '../hydra/hydra-admin.service';
import { IdentityRepository, type CredentialKind } from '../identity/identity.repository';
import { RedisService } from '../redis/redis.service';
import { TwoStepStore } from '../two-step/two-step.store';

/** Binds a sign-in waiting for its second step to the browser that passed the first. */
export const TWO_STEP_COOKIE = 'ea_two_step';

export interface Seen {
  ip: string;
  userAgent: string | null;
}

export interface Authenticated {
  identityId: string;
  credentialId: string | null;
  credentialKind: CredentialKind | null;
  /**
   * RFC 8176 method names, plus `fed` for an upstream provider. `mfa` among them means the
   * second step has been passed (TwoStepController); without it, an identity with 2-step
   * verification is sent to that step first.
   */
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
    private readonly geo: GeoIp,
    private readonly email: EmailSender,
    private readonly twoStep: TwoStepStore,
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

    // 2-step verification (account-plan.md section 4): every way in - password, code, reset,
    // Google, Apple - passes here, so none of them alone signs a 2-step account in.
    const twoStepDone = a.amr.includes('mfa');
    if (!twoStepDone && (await this.identities.hasTotp(a.identityId))) {
      const token = await this.twoStep.holdSignIn(challenge, { a, seen });
      reply.setCookie(TWO_STEP_COOKIE, token, {
        signed: true,
        httpOnly: true,
        path: '/login',
        maxAge: 600,
        sameSite: 'lax',
        secure: env.NODE_ENV === 'production',
      });
      return `/login/two-step?login_challenge=${encodeURIComponent(challenge)}`;
    }

    // The device and place, recorded with the session (account-plan.md section 5).
    const device = describeDevice(seen.userAgent);
    const label = device.name === 'Unknown device' ? null : device.name;
    const at = this.geo.locate(seen.ip);
    let newDevice = false;
    let undeleted: Date | null = null;
    const opened = await this.db.tx(async (db) => {
      newDevice = await this.identities.isNewDevice(db, a.identityId, sid, label, at.country);
      const sessionId = await this.identities.openSession(db, {
        identityId: a.identityId,
        credentialId: a.credentialId,
        sid,
        clientId: request.client.client_id,
        ip: seen.ip,
        userAgent: seen.userAgent,
        lifetimeSeconds: env.REMEMBER_SECONDS,
        deviceLabel: label,
        geoCity: at.city,
        geoCountry: at.country,
        aal: twoStepDone ? 2 : 1,
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
      // Signing in while a deletion waits cancels it (account-plan.md part 6): the member
      // changed their mind, or someone else asked - either way, the account stays.
      undeleted = await this.identities.cancelDeletion(db, a.identityId);
      if (undeleted) {
        await this.identities.event(
          {
            kind: 'deletion_cancelled',
            outcome: 'success',
            identityId: a.identityId,
            clientId: request.client.client_id,
            authSessionId: sessionId,
            ...seen,
          },
          db,
        );
      }
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
      // How the member authenticated. The API reads these for step-up (section 9): one factor
      // is assurance level 1, a second step makes it 2.
      acr: twoStepDone ? 'aal2' : 'aal1',
      amr: a.amr,
      context: { auth_time: Math.floor(Date.now() / 1000) },
    });
    await this.redis.client.set(doneKey(challenge), to, 'EX', DONE_SECONDS);
    if (newDevice) await this.alertNewDevice(a.identityId, device, at);
    if (undeleted) await this.tellUndeleted(a.identityId);
    return to;
  }

  /** The member signed in during the grace period, so their account is no longer being deleted. */
  private async tellUndeleted(identityId: string): Promise<void> {
    try {
      const to = await this.identities.primaryIdentifier(identityId);
      if (to?.kind !== 'email') return;
      void this.email.sendNotice(to.value, 'Your account is no longer being deleted', [
        `You signed in to your ${env.PROVIDER_NAME} account, so we've cancelled its deletion. Your account and everything in it stays as it was.`,
        `If you still want to delete it, go to Data & privacy in your account and choose Delete account again.`,
        "If you didn't sign in, change your password and check your devices in your account now.",
      ]);
    } catch {
      // A missed email must not turn a good sign-in into an error page.
    }
  }

  /**
   * The new-device security email (account-plan.md section 3), to the primary email. It never
   * holds up the sign-in: the address is looked up, the send itself is not waited for, and
   * sendNotice never throws.
   */
  private async alertNewDevice(
    identityId: string,
    device: { name: string; browser: string | null },
    at: { city: string | null; country: string | null },
  ): Promise<void> {
    try {
      const to = await this.identities.primaryIdentifier(identityId);
      if (to?.kind !== 'email') return;
      const what = device.browser ? `${device.browser} on ${device.name}` : device.name;
      const where = [at.city, countryName(at.country)].filter(Boolean).join(', ');
      const when = new Date().toLocaleString('en-GB', {
        timeZone: 'Europe/London',
        day: 'numeric',
        month: 'long',
        year: 'numeric',
        hour: '2-digit',
        minute: '2-digit',
      });
      void this.email.sendNotice(to.value, 'New sign-in to your account', [
        `Your ${env.PROVIDER_NAME} account was just signed in to from a device we haven't seen lately.`,
        `Device: ${what}`,
        ...(where ? [`Location: ${where} (approximate)`] : []),
        `When: ${when} UK time`,
        "If this was you, there's nothing to do.",
      ]);
    } catch {
      // A missed alert must not turn a good sign-in into an error page.
    }
  }
}

/** Long enough for any repeat of the same form; the challenge itself is gone well before. */
const DONE_SECONDS = 5 * 60;

const doneKey = (challenge: string): string =>
  `uni-auth:login-done:${createHash('sha256').update(challenge).digest('base64url')}`;
