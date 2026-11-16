import { Body, Controller, Get, Post, Query, Req, Res } from '@nestjs/common';
import type { FastifyReply, FastifyRequest } from 'fastify';
import { z } from 'zod';
import { redirect, render } from '../common/pages';
import { EmailSender } from '../delivery/email.sender';
import { Challenge, minutesUntil, page, parse } from '../flows/login.controller';
import { SignIn, TWO_STEP_COOKIE, type Seen } from '../flows/sign-in.service';
import { HydraAdmin, type LoginRequest } from '../hydra/hydra-admin.service';
import { IdentityRepository } from '../identity/identity.repository';
import { Throttle } from '../throttle/throttle.service';
import { MfaKeys } from './mfa-keys';
import { normalise } from './recovery-codes';
import { matchStep } from './totp';
import { TwoStepStore, type PendingTwoStep } from './two-step.store';

const Mode = z.enum(['app', 'recovery']);
type Mode = z.infer<typeof Mode>;
const Form = z.object({
  login_challenge: Challenge,
  mode: Mode,
  code: z.string().max(40),
});

/** The remaining-attempts count is shown only once it is this low, as on the other screens. */
const WARN_AT = 2;

/**
 * The second step of a sign-in (account-plan.md section 4): a code from the authenticator app,
 * or one of the recovery codes. SignIn sends an identity with 2-step verification here after
 * any first step; this finishes the sign-in with `mfa` in its methods and acr aal2.
 *
 * Wrong codes are throttled like passwords - five, then a pause - counted per identity, so the
 * first step can't be repeated to get more guesses.
 */
@Controller('login/two-step')
export class TwoStepController {
  constructor(
    private readonly hydra: HydraAdmin,
    private readonly identities: IdentityRepository,
    private readonly keys: MfaKeys,
    private readonly store: TwoStepStore,
    private readonly throttle: Throttle,
    private readonly signIn: SignIn,
    private readonly email: EmailSender,
  ) {}

  @Get()
  async show(
    @Query('login_challenge') raw: unknown,
    @Query('mode') rawMode: unknown,
    @Req() req: FastifyRequest,
    @Res() reply: FastifyReply,
  ): Promise<void> {
    const challenge = parse(Challenge, raw);
    const pending = await this.pending(req, challenge);
    if (!pending) {
      await this.restart(reply, challenge);
      return;
    }
    const mode = Mode.catch('app').parse(rawMode);
    const request = await this.hydra.getLogin(challenge);
    const locked = await this.throttle.check(throttleKey(pending), req.ip);
    await this.screen(reply, challenge, request, pending, mode, {
      locked: locked.kind === 'locked' ? locked.until : undefined,
    });
  }

  @Post()
  async submit(
    @Body() body: unknown,
    @Req() req: FastifyRequest,
    @Res() reply: FastifyReply,
  ): Promise<void> {
    const form = parse(Form, body);
    const challenge = form.login_challenge;

    // Sent twice: go where the first copy went.
    const done = await this.signIn.finished(challenge);
    if (done) {
      await redirect(reply, done);
      return;
    }
    const pending = await this.pending(req, challenge);
    if (!pending) {
      await this.restart(reply, challenge);
      return;
    }
    const request = await this.hydra.getLogin(challenge);
    const seen: Seen = { ip: req.ip, userAgent: req.headers['user-agent'] ?? null };
    const key = throttleKey(pending);
    const identityId = pending.a.identityId;

    const before = await this.throttle.check(key, seen.ip);
    if (before.kind === 'locked') {
      await this.screen(reply, challenge, request, pending, form.mode, { locked: before.until });
      return;
    }

    // Turned off since the first step (from another device): nothing left to ask.
    const totp = await this.identities.liveTotp(identityId);
    if (!totp) {
      await this.finish(reply, challenge, request, seen, pending, null);
      return;
    }

    let left: number | null = null;
    let ok = false;
    if (form.mode === 'app') {
      const seed = this.keys.open(totp.sealed, identityId);
      const step = matchStep(seed, form.code, Date.now(), totp.lastStep);
      ok = step !== null && (await this.identities.spendTotpStep(totp.id, step));
    } else {
      const code = normalise(form.code);
      const spent = code
        ? await this.identities.spendRecoveryCode(identityId, this.keys.hashCode(code))
        : null;
      ok = spent !== null;
      left = spent?.left ?? null;
    }

    if (!ok) {
      const after = await this.throttle.fail(key, seen.ip);
      const credentialKind = form.mode === 'app' ? 'totp' : 'recovery_codes';
      await this.identities.event({
        kind: 'sign_in',
        outcome: 'failure',
        identityId,
        clientId: request.client.client_id,
        credentialKind,
        detail: { reason: 'wrong_code', step: 'two_step' },
        ...seen,
      });
      if (after.kind === 'locked') {
        if (after.tripped) {
          await this.identities.event({
            kind: 'lockout',
            outcome: 'failure',
            identityId,
            clientId: request.client.client_id,
            credentialKind,
            detail: { until: after.until.toISOString(), method: 'two_step' },
            ...seen,
          });
        }
        await this.screen(reply, challenge, request, pending, form.mode, { locked: after.until });
        return;
      }
      await this.screen(reply, challenge, request, pending, form.mode, {
        error:
          form.mode === 'app'
            ? "That code isn't right. Enter the code your app shows now."
            : "That recovery code isn't right, or it was used already.",
        remaining: after.remaining <= WARN_AT ? after.remaining : null,
      });
      return;
    }

    await this.throttle.succeed(key);
    await this.finish(reply, challenge, request, seen, pending, form.mode, left);
  }

  /** The sign-in, finished at last: through SignIn, now with the second step in its methods. */
  private async finish(
    reply: FastifyReply,
    challenge: string,
    request: LoginRequest,
    seen: Seen,
    pending: PendingTwoStep,
    mode: Mode | null,
    left: number | null = null,
  ): Promise<void> {
    await this.store.dropSignIn(challenge);
    reply.clearCookie(TWO_STEP_COOKIE, { path: '/login' });
    const a = pending.a;
    if (mode === 'recovery') {
      await this.identities.event({
        kind: 'recovery_code_used',
        outcome: 'success',
        identityId: a.identityId,
        clientId: request.client.client_id,
        credentialKind: 'recovery_codes',
        detail: { left },
        ...seen,
      });
      await this.notifyRecoveryCodeUsed(a.identityId, left ?? 0);
    }
    await this.signIn.accept(
      reply,
      challenge,
      request,
      seen,
      mode === null
        ? a
        : {
            ...a,
            // RFC 8176: a one-time code, and more than one factor.
            amr: [...new Set([...a.amr, 'otp', 'mfa'])],
            detail: {
              ...a.detail,
              second_step: mode === 'app' ? 'authenticator' : 'recovery_code',
            },
          },
    );
  }

  private async notifyRecoveryCodeUsed(identityId: string, left: number): Promise<void> {
    const to = await this.identities.primaryIdentifier(identityId);
    if (to?.kind !== 'email') return;
    await this.email.sendNotice(to.value, 'A recovery code was used to sign in', [
      'One of your recovery codes was just used to sign in to your account. It won’t work again.',
      left === 0
        ? 'You have no recovery codes left. Make a new set in your account, under Security & sign-in.'
        : `You have ${left === 1 ? '1 recovery code' : `${left} recovery codes`} left.`,
    ]);
  }

  private async pending(req: FastifyRequest, challenge: string): Promise<PendingTwoStep | null> {
    const raw = req.cookies[TWO_STEP_COOKIE];
    const unsigned = raw ? req.unsignCookie(raw) : null;
    return this.store.signIn(challenge, unsigned?.valid ? unsigned.value : null);
  }

  /** Nothing waiting for this browser (expired, or never started here): sign in from the top. */
  private async restart(reply: FastifyReply, challenge: string): Promise<void> {
    await redirect(reply, `/login?login_challenge=${encodeURIComponent(challenge)}`);
  }

  private async screen(
    reply: FastifyReply,
    challenge: string,
    request: LoginRequest,
    pending: PendingTwoStep,
    mode: Mode,
    state: { error?: string; remaining?: number | null; locked?: Date } = {},
  ): Promise<void> {
    const who = await this.identities.primaryIdentifier(pending.a.identityId);
    await render(
      reply,
      'two-step',
      '2-step verification',
      {
        ...page(reply, challenge, request),
        identifier: who?.value ?? '',
        phone: who?.kind === 'phone',
        mode,
        error: state.error ?? null,
        remaining: state.remaining ?? null,
        locked: !!state.locked,
        minutes: state.locked ? minutesUntil(state.locked) : null,
      },
      state.locked ? 429 : state.error ? 422 : 200,
    );
  }
}

/** Counted per identity, whichever address or first step the attempts come through. */
const throttleKey = (p: PendingTwoStep): string => `two-step:${p.a.identityId}`;
