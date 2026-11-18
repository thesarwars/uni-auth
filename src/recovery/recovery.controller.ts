import { Body, Controller, Get, Post, Query, Req, Res } from '@nestjs/common';
import type { FastifyReply, FastifyRequest } from 'fastify';
import { createHash, randomBytes } from 'node:crypto';
import { z } from 'zod';
import { redirect, render } from '../common/pages';
import { Database } from '../db/database.service';
import { Challenge, page, parse } from '../flows/login.controller';
import { TWO_STEP_COOKIE, type Seen } from '../flows/sign-in.service';
import { HydraAdmin } from '../hydra/hydra-admin.service';
import { IdentityRepository } from '../identity/identity.repository';
import { RedisService } from '../redis/redis.service';
import { TwoStepStore, type PendingTwoStep } from '../two-step/two-step.store';
import { MfaRecoveries } from './mfa-recoveries';
import { longDate, RecoveryMail } from './recovery-mail';
import { RecoveryRepository, type Recovery } from './recovery.repository';

const HelpForm = z.object({ login_challenge: Challenge });
const Token = z.string().regex(/^[A-Za-z0-9_-]{43}$/);
const CancelForm = z.object({ token: Token });

/** Requests one identity may make in a day: each emails every address on the account. */
const ASKS_PER_DAY = 3;

const hashToken = (token: string): Buffer => createHash('sha256').update(token).digest();

/**
 * Account recovery without a second factor (account-plan.md part 7), the member's side.
 *
 * "Can't use any of these?" on the 2-step screen leads here. Only a sign-in whose first step was
 * the password may ask: a code sent to an address proves the address, and the address is where
 * the warning goes, so it can't also be what asks. The request waits seven days, and every
 * verified email address gets a link that cancels it (GET shows the question, POST cancels, so
 * a mail scanner opening the link changes nothing). MfaRecoveries carries it out.
 */
@Controller()
export class RecoveryController {
  constructor(
    private readonly db: Database,
    private readonly hydra: HydraAdmin,
    private readonly identities: IdentityRepository,
    private readonly recoveries: RecoveryRepository,
    private readonly store: TwoStepStore,
    private readonly jobs: MfaRecoveries,
    private readonly mail: RecoveryMail,
    private readonly redis: RedisService,
  ) {}

  @Get('login/two-step/help')
  async help(
    @Query('login_challenge') raw: unknown,
    @Req() req: FastifyRequest,
    @Res() reply: FastifyReply,
  ): Promise<void> {
    const challenge = parse(Challenge, raw);
    const pending = await this.pending(req, challenge);
    if (!pending) return this.restart(reply, challenge);
    const existing = await this.recoveries.pendingFor(pending.a.identityId);
    if (existing) return this.requested(reply, existing, false);
    await this.helpPage(reply, challenge, pending);
  }

  @Post('login/two-step/help')
  async ask(
    @Body() body: unknown,
    @Req() req: FastifyRequest,
    @Res() reply: FastifyReply,
  ): Promise<void> {
    const { login_challenge: challenge } = parse(HelpForm, body);
    const pending = await this.pending(req, challenge);
    if (!pending) return this.restart(reply, challenge);
    const identityId = pending.a.identityId;
    if (!pending.a.amr.includes('pwd')) {
      await this.helpPage(reply, challenge, pending);
      return;
    }
    const existing = await this.recoveries.pendingFor(identityId);
    if (existing) return this.requested(reply, existing, false);

    const key = `uni-auth:recovery-asks:${identityId}`;
    const asks = await this.redis.client.incr(key);
    if (asks === 1) await this.redis.client.expire(key, 24 * 3600);
    if (asks > ASKS_PER_DAY) {
      await this.helpPage(reply, challenge, pending, {
        error: "You've asked too many times today. Try again tomorrow.",
        status: 429,
      });
      return;
    }

    const request = await this.hydra.getLogin(challenge);
    const seen: Seen = { ip: req.ip, userAgent: req.headers['user-agent'] ?? null };
    const token = randomBytes(32).toString('base64url');
    const made = await this.db.tx(async (db) => {
      const r = await this.recoveries.create(db, identityId, hashToken(token));
      if (r) {
        await this.identities.event(
          {
            kind: 'mfa_recovery_requested',
            outcome: 'success',
            identityId,
            clientId: request.client.client_id,
            credentialKind: 'totp',
            detail: { request: r.id },
            ...seen,
          },
          db,
        );
      }
      return r;
    });
    if (!made) {
      const now = await this.recoveries.pendingFor(identityId);
      if (now) return this.requested(reply, now, false);
      await this.helpPage(reply, challenge, pending);
      return;
    }

    // The product is asked now, so the page can say whether a person checks it; if it can't be
    // reached, the job asks again, and the request waits for its answer whatever happens.
    const review = await this.jobs.register(made);
    await this.mail.requested(made, token, review !== 'not_required');
    // This sign-in ends here: the member signs in again once 2-step verification is removed.
    await this.store.dropSignIn(challenge);
    reply.clearCookie(TWO_STEP_COOKIE, { path: '/login' });
    await this.requested(reply, { ...made, review: review ?? 'unknown' }, true);
  }

  @Get('recovery/cancel')
  async cancelPage(@Query('token') raw: unknown, @Res() reply: FastifyReply): Promise<void> {
    const parsed = Token.safeParse(raw);
    const r = parsed.success ? await this.recoveries.byToken(hashToken(parsed.data)) : null;
    await render(
      reply,
      'recovery-cancel',
      'Cancel the request',
      {
        plain: true,
        state: r?.state ?? 'unknown',
        token: parsed.success ? parsed.data : '',
        eligibleOn: r ? longDate(r.eligibleAt) : null,
        requestedOn: r ? longDate(r.requestedAt) : null,
        csrfToken: reply.generateCsrf(),
      },
      r ? 200 : 404,
    );
  }

  @Post('recovery/cancel')
  async cancel(
    @Body() body: unknown,
    @Req() req: FastifyRequest,
    @Res() reply: FastifyReply,
  ): Promise<void> {
    const { token } = parse(CancelForm, body);
    const r = await this.recoveries.byToken(hashToken(token));
    if (!r) {
      await redirect(reply, `/recovery/cancel?token=${encodeURIComponent(token)}`);
      return;
    }
    const cancelled = await this.db.tx(async (db) => {
      const c = await this.recoveries.cancel(db, r.id, 'link');
      if (c) {
        await this.identities.event(
          {
            kind: 'mfa_recovery_cancelled',
            outcome: 'success',
            identityId: r.identityId,
            detail: { request: r.id, by: 'link' },
            ip: req.ip,
            userAgent: req.headers['user-agent'] ?? null,
          },
          db,
        );
      }
      return c;
    });
    if (!cancelled) {
      await redirect(reply, `/recovery/cancel?token=${encodeURIComponent(token)}`);
      return;
    }
    await this.mail.cancelled(cancelled, 'link');
    await render(reply, 'recovery-cancelled', 'Request cancelled', { plain: true });
  }

  private async helpPage(
    reply: FastifyReply,
    challenge: string,
    pending: PendingTwoStep,
    state: { error?: string; status?: number } = {},
  ): Promise<void> {
    const request = await this.hydra.getLogin(challenge);
    const who = await this.identities.primaryIdentifier(pending.a.identityId);
    await render(
      reply,
      'recovery-help',
      "Can't use 2-step verification?",
      {
        ...page(reply, challenge, request),
        identifier: who?.value ?? '',
        phone: who?.kind === 'phone',
        password: pending.a.amr.includes('pwd'),
        error: state.error ?? null,
      },
      state.status ?? 200,
    );
  }

  private async requested(reply: FastifyReply, r: Recovery, fresh: boolean): Promise<void> {
    await render(reply, 'recovery-requested', fresh ? 'Request sent' : 'Request waiting', {
      plain: true,
      fresh,
      // Unknown is read as "a person may check": the page must never promise less than happens.
      review: r.review !== 'not_required',
      requestedOn: longDate(r.requestedAt),
      eligibleOn: longDate(r.eligibleAt),
    });
  }

  private async pending(req: FastifyRequest, challenge: string): Promise<PendingTwoStep | null> {
    const raw = req.cookies[TWO_STEP_COOKIE];
    const unsigned = raw ? req.unsignCookie(raw) : null;
    return this.store.signIn(challenge, unsigned?.valid ? unsigned.value : null);
  }

  private async restart(reply: FastifyReply, challenge: string): Promise<void> {
    await redirect(reply, `/login?login_challenge=${encodeURIComponent(challenge)}`);
  }
}
