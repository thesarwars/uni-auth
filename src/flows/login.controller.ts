import { BadRequestException, Body, Controller, Get, Post, Query, Req, Res } from '@nestjs/common';
import type { FastifyReply, FastifyRequest } from 'fastify';
import { createHash } from 'node:crypto';
import { z } from 'zod';
import { redirect, render, renderError } from '../common/pages';
import { env } from '../config/env';
import { OtpService, type CodeView, type OtpPurpose } from '../credentials/otp.service';
import { checkPassword, PasswordService } from '../credentials/password.service';
import { Database } from '../db/database.service';
import { EmailSender } from '../delivery/email.sender';
import { WhatsAppSender } from '../delivery/whatsapp.sender';
import { HydraAdmin, type LoginRequest } from '../hydra/hydra-admin.service';
import { masked, parseIdentifier, type Identifier } from '../identity/identifier';
import {
  IdentityRepository,
  type CredentialKind,
  type Resolved,
} from '../identity/identity.repository';
import { Throttle } from '../throttle/throttle.service';

const Challenge = z.string().min(1).max(4096);
const Typed = z.string().max(400);
const Purpose = z.enum(['sign_in', 'recovery']);
const LoginForm = z.discriminatedUnion('action', [
  z.object({ action: z.literal('cancel'), login_challenge: Challenge }),
  z.object({ action: z.literal('identify'), login_challenge: Challenge, identifier: Typed }),
  z.object({
    action: z.literal('password'),
    login_challenge: Challenge,
    identifier: Typed,
    password: z.string().max(1024),
  }),
  z.object({
    action: z.literal('send_code'),
    login_challenge: Challenge,
    identifier: Typed,
    purpose: Purpose,
  }),
  z.object({
    action: z.literal('verify_code'),
    login_challenge: Challenge,
    identifier: Typed,
    otp_id: z.string().uuid(),
    code: z.string().max(20),
  }),
  z.object({
    action: z.literal('new_password'),
    login_challenge: Challenge,
    identifier: Typed,
    ticket: z.string().uuid(),
    password: z.string().max(1024),
    confirm: z.string().max(1024),
  }),
]);
type Form = z.infer<typeof LoginForm>;

/** The remaining-attempts count is shown only once it is this low (auth-plan.md section 7.3). */
const WARN_AT = 2;

interface Seen {
  ip: string;
  userAgent: string | null;
}

/**
 * Hydra's login challenge (auth-plan.md section 7.1). Hydra sends the browser here whenever a
 * client asks for a sign-in; this controller decides who the member is and tells Hydra.
 *
 * Identifier first (AU-D2): the member says who they are, then sees only the ways that identity
 * can sign in - a password, a code to the identifier itself, or recovery by code. Every screen
 * posts back here with an `action`; each carries the login challenge, the identifier and a CSRF
 * token, and nothing a screen carries is trusted beyond what the database confirms again.
 */
@Controller('login')
export class LoginController {
  constructor(
    private readonly hydra: HydraAdmin,
    private readonly db: Database,
    private readonly identities: IdentityRepository,
    private readonly passwords: PasswordService,
    private readonly otp: OtpService,
    private readonly email: EmailSender,
    private readonly whatsapp: WhatsAppSender,
    private readonly throttle: Throttle,
  ) {}

  @Get()
  async show(@Query('login_challenge') raw: unknown, @Res() reply: FastifyReply): Promise<void> {
    const challenge = parse(Challenge, raw);
    const request = await this.hydra.getLogin(challenge);

    if (request.skip) {
      await this.singleSignOn(reply, challenge, request);
      return;
    }
    await this.identifierScreen(reply, challenge, request);
  }

  @Post()
  async submit(
    @Body() body: unknown,
    @Req() req: FastifyRequest,
    @Res() reply: FastifyReply,
  ): Promise<void> {
    const form = parse(LoginForm, body);
    const challenge = form.login_challenge;

    if (form.action === 'cancel') {
      const to = await this.hydra.rejectLogin(
        challenge,
        'access_denied',
        'The member cancelled the sign-in.',
      );
      await redirect(reply, to);
      return;
    }

    const request = await this.hydra.getLogin(challenge);
    const id = parseIdentifier(form.identifier);
    if (!id) {
      await this.identifierScreen(reply, challenge, request, {
        typed: form.identifier,
        error: 'Enter an email address, or a phone number with its country code, like +44.',
      });
      return;
    }
    const ctx: Ctx = {
      reply,
      challenge,
      request,
      id,
      seen: { ip: req.ip, userAgent: req.headers['user-agent'] ?? null },
    };

    switch (form.action) {
      case 'identify':
        return this.identify(ctx, form.identifier);
      case 'password':
        return this.password(ctx, form.password);
      case 'send_code':
        return this.sendCode(ctx, form.purpose);
      case 'verify_code':
        return this.verifyCode(ctx, form);
      case 'new_password':
        return this.newPassword(ctx, form);
    }
  }

  /**
   * The provider session is still valid: single sign-on, no screen (section 7.1, step 2) -
   * provided uni-auth agrees. Hydra remembers the session in a cookie; the identity database
   * decides whether it still stands. A revoked session or a suspended identity ends Hydra's
   * session too, and the flow starts again from the client's own request, now with a screen.
   */
  private async singleSignOn(
    reply: FastifyReply,
    challenge: string,
    request: LoginRequest,
  ): Promise<void> {
    const sid = request.session_id;
    const state = sid ? await this.identities.seeSession(sid) : null;
    if (
      state &&
      !state.revoked &&
      state.identityStatus === 'active' &&
      state.identityId === request.subject
    ) {
      await redirect(reply, await this.hydra.acceptLogin(challenge, { subject: request.subject }));
      return;
    }

    if (sid) await this.hydra.revokeLoginSession(sid);
    const restart = request.request_url;
    if (restart && new URL(restart).origin === new URL(env.HYDRA_PUBLIC_URL).origin) {
      await redirect(reply, restart);
      return;
    }
    await this.hydra.rejectLogin(challenge, 'login_required', 'The provider session has ended.');
    await renderError(
      reply,
      400,
      'Please sign in again',
      'Your sign-in has ended. Go back to the app you were using and sign in again.',
    );
  }

  /** Who the identifier belongs to, and so which screen comes next. */
  private async identify(ctx: Ctx, typed: string): Promise<void> {
    const found = await this.identities.resolve(ctx.id);
    if (!found) {
      await this.identifierScreen(ctx.reply, ctx.challenge, ctx.request, {
        typed,
        error: `We couldn't find an account with that ${noun(ctx.id)}.`,
      });
      return;
    }
    if (found.status === 'suspended') {
      await this.suspended(ctx, typed);
      return;
    }
    if (found.credentials.includes('password')) {
      await this.passwordScreen(ctx);
      return;
    }
    if (found.credentials.length > 0) {
      await this.identifierScreen(ctx.reply, ctx.challenge, ctx.request, {
        typed,
        error: `This account signs in with ${upstreamNames(found.credentials)}.`,
      });
      return;
    }
    // No password and no upstream account: the verified identifier itself is the way in.
    await this.sendCode(ctx, 'sign_in', found);
  }

  private async password(ctx: Ctx, password: string): Promise<void> {
    const { id, seen } = ctx;
    const before = await this.throttle.check(id.value, seen.ip);
    if (before.kind === 'locked') {
      await this.lockoutScreen(ctx, before.until);
      return;
    }

    const found = await this.identities.resolve(id);
    const stored = found ? await this.identities.livePassword(found.identityId) : null;
    const ok = await this.passwords.verify(password, stored?.secret_hash ?? null);

    if (!ok || !found || !stored) {
      const after = await this.throttle.fail(id.value, seen.ip);
      await this.journalFailure(ctx, found, 'password', { reason: 'wrong_password' });
      if (after.kind === 'locked') {
        if (after.tripped) {
          await this.journalLockout(ctx, found, 'password', after.until);
        }
        await this.lockoutScreen(ctx, after.until);
        return;
      }
      await this.passwordScreen(ctx, {
        error: 'That password is not right.',
        remaining: after.remaining <= WARN_AT ? after.remaining : null,
      });
      return;
    }

    if (found.status !== 'active') {
      await this.suspended(ctx, id.value);
      return;
    }

    await this.throttle.succeed(id.value);
    await this.accept(ctx, {
      identityId: found.identityId,
      credentialId: stored.id,
      credentialKind: 'password',
      amr: ['pwd'],
    });
  }

  /**
   * Sends a code to the identifier: to sign in with, or to start recovery. A second send in the
   * same sign-in is a resend of the live code while it has resends left.
   */
  private async sendCode(ctx: Ctx, purpose: OtpPurpose, known?: Resolved): Promise<void> {
    const found = known ?? (await this.identities.resolve(ctx.id));
    if (!found) {
      await this.identifierScreen(ctx.reply, ctx.challenge, ctx.request, {
        typed: ctx.id.value,
        error: `We couldn't find an account with that ${noun(ctx.id)}.`,
      });
      return;
    }
    if (found.status !== 'active') {
      await this.suspended(ctx, ctx.id.value);
      return;
    }

    const sent = await this.db.tx((db) =>
      this.otp.send(db, {
        identityId: found.identityId,
        purpose,
        to: ctx.id,
        flow: ctx.challenge,
      }),
    );
    if (sent.kind === 'locked') {
      await this.codeScreen(ctx, purpose, null, { locked: sent.until });
      return;
    }
    if (sent.kind === 'rate_limited') {
      await this.codeScreen(ctx, purpose, null, { rateLimited: sent.availableAt });
      return;
    }

    // After commit: a rolled-back challenge must not have put a code in anyone's inbox.
    try {
      if (sent.view.channel === 'email') {
        await this.email.sendCode(sent.destination, sent.code, purpose);
      } else {
        await this.whatsapp.sendCode(sent.destination, sent.code);
      }
    } catch {
      await renderError(
        ctx.reply,
        502,
        "We couldn't send your code",
        'Nothing has changed on your account. Please go back and try again in a moment.',
      );
      return;
    }
    await this.codeScreen(ctx, purpose, sent.view);
  }

  private async verifyCode(
    ctx: Ctx,
    form: Extract<Form, { action: 'verify_code' }>,
  ): Promise<void> {
    // The attempt is committed whatever the outcome, so the cap holds.
    const outcome = await this.db.tx((db) =>
      this.otp.verify(db, { otpId: form.otp_id, flow: ctx.challenge, code: form.code }),
    );

    switch (outcome.kind) {
      case 'not_found':
      case 'expired':
        await this.codeScreen(ctx, null, null, { expired: true });
        return;
      case 'locked': {
        const found = await this.identities.resolve(ctx.id);
        await this.journalLockout(ctx, found, null, outcome.until);
        await this.codeScreen(ctx, null, null, { locked: outcome.until });
        return;
      }
      case 'invalid': {
        const found = await this.identities.resolve(ctx.id);
        await this.journalFailure(ctx, found, null, { reason: 'wrong_code' });
        await this.codeScreen(ctx, outcome.view.purpose, outcome.view, {
          error: 'That code is not right.',
          remaining: outcome.remaining <= WARN_AT ? outcome.remaining : null,
        });
        return;
      }
      case 'verified':
        break;
    }

    const found = await this.identities.resolve(ctx.id);
    if (!found || found.identityId !== outcome.identityId || found.status !== 'active') {
      await this.suspended(ctx, ctx.id.value);
      return;
    }

    const purpose = await this.purposeOf(outcome.otpId);
    if (purpose === 'recovery') {
      const ticket = await this.db.tx((db) =>
        this.identities.openReset(db, found.identityId, outcome.otpId),
      );
      await this.newPasswordScreen(ctx, ticket);
      return;
    }
    await this.accept(ctx, {
      identityId: found.identityId,
      credentialId: null,
      credentialKind: null,
      amr: ['otp'],
      detail: { method: 'code', channel: ctx.id.kind === 'email' ? 'email' : 'whatsapp' },
    });
  }

  /** The last step of recovery: a new password against the policy in force, then signed in. */
  private async newPassword(
    ctx: Ctx,
    form: Extract<Form, { action: 'new_password' }>,
  ): Promise<void> {
    const policy = await this.passwords.policyInEffect(this.db.asDb());
    const failed = checkPassword(policy, form.password).filter((r) => !r.met);
    if (failed.length > 0 || form.password !== form.confirm) {
      await this.newPasswordScreen(ctx, form.ticket, {
        error:
          failed.length > 0
            ? 'Your new password does not meet every rule yet.'
            : 'The two passwords do not match.',
        typed: form.password,
      });
      return;
    }

    const secretHash = await this.passwords.hash(form.password);
    const done = await this.db.tx(async (db) => {
      const result = await this.identities.completeReset(db, {
        ticketId: form.ticket,
        flowHash: createHash('sha256').update(ctx.challenge).digest(),
        secretHash,
      });
      if (result) {
        await this.identities.event(
          {
            kind: 'password_reset',
            outcome: 'success',
            identityId: result.identityId,
            clientId: ctx.request.client.client_id,
            credentialKind: 'password',
            ...ctx.seen,
          },
          db,
        );
      }
      return result;
    });
    if (!done) {
      await this.codeScreen(ctx, null, null, { expired: true, ticketExpired: true });
      return;
    }

    // The reset was the way out the lockout screen offered; it lifts the lockout.
    await this.throttle.lift(ctx.id.value);
    await this.accept(ctx, {
      identityId: done.identityId,
      credentialId: done.credentialId,
      credentialKind: 'password',
      amr: ['otp'],
      detail: { method: 'recovery' },
    });
  }

  /**
   * Opens the session in the identity database and tells Hydra who signed in. The session row
   * is written first: a sign-in uni-auth has no record of must never reach a client.
   */
  private async accept(
    ctx: Ctx,
    a: {
      identityId: string;
      credentialId: string | null;
      credentialKind: CredentialKind | null;
      amr: string[];
      detail?: Record<string, unknown>;
    },
  ): Promise<void> {
    const { reply, challenge, request, seen } = ctx;
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
      return;
    }

    const to = await this.hydra.acceptLogin(challenge, {
      subject: a.identityId,
      remember: true,
      remember_for: env.REMEMBER_SECONDS,
      // How the member authenticated (RFC 8176 method names). The API reads these for step-up
      // (section 9); one factor is assurance level 1.
      acr: 'aal1',
      amr: a.amr,
      context: { auth_time: Math.floor(Date.now() / 1000) },
    });
    await redirect(reply, to);
  }

  private async purposeOf(otpId: string): Promise<OtpPurpose | null> {
    const [row] = await this.db.rows<{ purpose: OtpPurpose }>(
      'SELECT purpose FROM otp_challenge WHERE id = $1',
      [otpId],
    );
    return row?.purpose ?? null;
  }

  private journalFailure(
    ctx: Ctx,
    found: Resolved | null,
    credentialKind: CredentialKind | null,
    detail: Record<string, unknown>,
  ): Promise<void> {
    return this.identities.event({
      kind: 'sign_in',
      outcome: 'failure',
      identityId: found?.identityId,
      identifier: ctx.id,
      clientId: ctx.request.client.client_id,
      credentialKind,
      detail,
      ...ctx.seen,
    });
  }

  private journalLockout(
    ctx: Ctx,
    found: Resolved | null,
    credentialKind: CredentialKind | null,
    until: Date,
  ): Promise<void> {
    return this.identities.event({
      kind: 'lockout',
      outcome: 'failure',
      identityId: found?.identityId,
      identifier: ctx.id,
      clientId: ctx.request.client.client_id,
      credentialKind,
      detail: { until: until.toISOString(), method: credentialKind ?? 'code' },
      ...ctx.seen,
    });
  }

  private suspended(ctx: Ctx, typed: string): FastifyReply {
    return this.identifierScreen(ctx.reply, ctx.challenge, ctx.request, {
      typed,
      error: 'This account is suspended, so it cannot sign in.',
    });
  }

  private identifierScreen(
    reply: FastifyReply,
    challenge: string,
    request: LoginRequest,
    state: { typed?: string; error?: string } = {},
  ): FastifyReply {
    return render(
      reply,
      'identifier',
      `Sign in to continue to ${clientName(request.client)}`,
      {
        ...page(reply, challenge, request),
        typed: state.typed ?? '',
        error: state.error ?? null,
      },
      state.error ? 422 : 200,
    );
  }

  private passwordScreen(
    ctx: Ctx,
    state: { error?: string; remaining?: number | null } = {},
  ): FastifyReply {
    return render(
      ctx.reply,
      'password',
      'Enter your password',
      {
        ...page(ctx.reply, ctx.challenge, ctx.request),
        identifier: ctx.id.value,
        codeChannel: ctx.id.kind === 'email' ? 'email' : 'WhatsApp',
        error: state.error ?? null,
        remaining: state.remaining ?? null,
      },
      state.error ? 422 : 200,
    );
  }

  /**
   * The code screen in every state section 7.3 lists. `code` is the code it is waiting for;
   * null when there is none to enter - locked, rate-limited or expired.
   */
  private codeScreen(
    ctx: Ctx,
    purpose: OtpPurpose | null,
    code: CodeView | null,
    state: {
      error?: string;
      remaining?: number | null;
      locked?: Date;
      rateLimited?: Date;
      expired?: boolean;
      ticketExpired?: boolean;
    } = {},
  ): FastifyReply {
    const blocked = state.locked ?? state.rateLimited;
    const status =
      state.locked || state.rateLimited ? 429 : state.error || state.expired ? 422 : 200;
    return render(
      ctx.reply,
      'code',
      purpose === 'recovery' ? 'Reset your password' : 'Enter your code',
      {
        ...page(ctx.reply, ctx.challenge, ctx.request),
        identifier: ctx.id.value,
        destination: masked(ctx.id),
        channel: ctx.id.kind === 'email' ? 'email' : 'WhatsApp',
        purpose: purpose ?? 'sign_in',
        recovery: purpose === 'recovery',
        code,
        error: state.error ?? null,
        remaining: state.remaining ?? null,
        locked: !!state.locked,
        rateLimited: !!state.rateLimited,
        minutes: blocked ? minutesUntil(blocked) : null,
        expired: !!state.expired,
        ticketExpired: !!state.ticketExpired,
      },
      status,
    );
  }

  private async newPasswordScreen(
    ctx: Ctx,
    ticket: string,
    state: { error?: string; typed?: string } = {},
  ): Promise<void> {
    const policy = await this.passwords.policyInEffect(this.db.asDb());
    await render(
      ctx.reply,
      'new-password',
      'Choose a new password',
      {
        ...page(ctx.reply, ctx.challenge, ctx.request),
        identifier: ctx.id.value,
        ticket,
        rules: checkPassword(policy, state.typed ?? ''),
        checked: state.typed !== undefined,
        error: state.error ?? null,
      },
      state.error ? 422 : 200,
    );
  }

  private lockoutScreen(ctx: Ctx, until: Date): FastifyReply {
    return render(
      ctx.reply,
      'lockout',
      'Too many attempts',
      {
        ...page(ctx.reply, ctx.challenge, ctx.request),
        identifier: ctx.id.value,
        minutes: minutesUntil(until),
      },
      429,
    );
  }
}

interface Ctx {
  reply: FastifyReply;
  challenge: string;
  request: LoginRequest;
  id: Identifier;
  seen: Seen;
}

/** What every sign-in screen carries: the challenge, a CSRF token, and who is asking. */
function page(reply: FastifyReply, challenge: string, request: LoginRequest) {
  return {
    challenge,
    clientName: clientName(request.client),
    logoUri: request.client.logo_uri,
    csrfToken: reply.generateCsrf(),
  };
}

const minutesUntil = (t: Date): number =>
  Math.max(1, Math.round((t.getTime() - Date.now()) / 60_000));

const noun = (id: Identifier) => (id.kind === 'email' ? 'email address' : 'phone number');

function upstreamNames(kinds: CredentialKind[]): string {
  const names = kinds.flatMap((k) =>
    k === 'oauth_google' ? ['Google'] : k === 'oauth_apple' ? ['Apple'] : [],
  );
  return names.join(' or ');
}

export function clientName(client: { client_name: string; client_id: string }): string {
  return client.client_name || client.client_id;
}

export function parse<T>(schema: z.ZodType<T>, value: unknown): T {
  const result = schema.safeParse(value);
  if (!result.success) throw new BadRequestException('malformed request');
  return result.data;
}
