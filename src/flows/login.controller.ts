import { BadRequestException, Body, Controller, Get, Post, Query, Req, Res } from '@nestjs/common';
import type { FastifyReply, FastifyRequest } from 'fastify';
import { z } from 'zod';
import { redirect, render, renderError } from '../common/pages';
import { env } from '../config/env';
import { PasswordService } from '../credentials/password.service';
import { Database } from '../db/database.service';
import { HydraAdmin, type LoginRequest } from '../hydra/hydra-admin.service';
import { parseIdentifier, type Identifier } from '../identity/identifier';
import { IdentityRepository, type CredentialKind } from '../identity/identity.repository';
import { Throttle } from '../throttle/throttle.service';

const Challenge = z.string().min(1).max(4096);
const LoginForm = z.discriminatedUnion('action', [
  z.object({ action: z.literal('cancel'), login_challenge: Challenge }),
  z.object({
    action: z.literal('identify'),
    login_challenge: Challenge,
    identifier: z.string().max(400),
  }),
  z.object({
    action: z.literal('password'),
    login_challenge: Challenge,
    identifier: z.string().max(400),
    password: z.string().max(1024),
  }),
]);

/** The remaining-attempts count is shown only once it is this low (auth-plan.md section 7.3). */
const WARN_AT = 2;

/**
 * Hydra's login challenge (auth-plan.md section 7.1). Hydra sends the browser here whenever a
 * client asks for a sign-in; this controller decides who the member is and tells Hydra.
 *
 * Identifier first (AU-D2): the member says who they are, then sees only the ways that
 * identity can sign in.
 */
@Controller('login')
export class LoginController {
  constructor(
    private readonly hydra: HydraAdmin,
    private readonly db: Database,
    private readonly identities: IdentityRepository,
    private readonly passwords: PasswordService,
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

    if (form.action === 'identify') {
      await this.identify(reply, challenge, request, id, form.identifier);
      return;
    }
    await this.password(reply, req, challenge, request, id, form.password);
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

  private async identify(
    reply: FastifyReply,
    challenge: string,
    request: LoginRequest,
    id: Identifier,
    typed: string,
  ): Promise<void> {
    const found = await this.identities.resolve(id);
    if (!found) {
      await this.identifierScreen(reply, challenge, request, {
        typed,
        error: `We couldn't find an account with that ${noun(id)}.`,
      });
      return;
    }
    if (found.status === 'suspended') {
      await this.identifierScreen(reply, challenge, request, {
        typed,
        error: 'This account is suspended, so it cannot sign in.',
      });
      return;
    }
    if (found.credentials.includes('password')) {
      await this.passwordScreen(reply, challenge, request, id);
      return;
    }
    await this.identifierScreen(reply, challenge, request, {
      typed,
      error: `This account signs in with ${upstreamNames(found.credentials)}.`,
    });
  }

  private async password(
    reply: FastifyReply,
    req: FastifyRequest,
    challenge: string,
    request: LoginRequest,
    id: Identifier,
    password: string,
  ): Promise<void> {
    const address = req.ip;
    const before = await this.throttle.check(id.value, address);
    if (before.kind === 'locked') {
      await this.lockoutScreen(reply, challenge, request, id, before.until);
      return;
    }

    const found = await this.identities.resolve(id);
    const stored = found ? await this.identities.livePassword(found.identityId) : null;
    const ok = await this.passwords.verify(password, stored?.secret_hash ?? null);
    const seen = { ip: address, userAgent: req.headers['user-agent'] ?? null };

    if (!ok || !found || !stored) {
      const after = await this.throttle.fail(id.value, address);
      await this.identities.event({
        kind: 'sign_in',
        outcome: 'failure',
        identityId: found?.identityId,
        identifier: id,
        clientId: request.client.client_id,
        credentialKind: 'password',
        detail: { reason: 'wrong_password' },
        ...seen,
      });
      if (after.kind === 'locked') {
        if (after.tripped) {
          await this.identities.event({
            kind: 'lockout',
            outcome: 'failure',
            identityId: found?.identityId,
            identifier: id,
            clientId: request.client.client_id,
            credentialKind: 'password',
            detail: { until: after.until.toISOString() },
            ...seen,
          });
        }
        await this.lockoutScreen(reply, challenge, request, id, after.until);
        return;
      }
      await this.passwordScreen(reply, challenge, request, id, {
        error: 'That password is not right.',
        remaining: after.remaining <= WARN_AT ? after.remaining : null,
      });
      return;
    }

    if (found.status !== 'active') {
      await this.identifierScreen(reply, challenge, request, {
        typed: id.value,
        error: 'This account is suspended, so it cannot sign in.',
      });
      return;
    }

    await this.throttle.succeed(id.value);
    await this.accept(reply, challenge, request, {
      identityId: found.identityId,
      credentialId: stored.id,
      credentialKind: 'password',
      amr: ['pwd'],
      ...seen,
    });
  }

  /**
   * Opens the session in the identity database and tells Hydra who signed in. The session row
   * is written first: a sign-in uni-auth has no record of must never reach a client.
   */
  private async accept(
    reply: FastifyReply,
    challenge: string,
    request: LoginRequest,
    a: {
      identityId: string;
      credentialId: string;
      credentialKind: CredentialKind;
      amr: string[];
      ip: string | null;
      userAgent: string | null;
    },
  ): Promise<void> {
    const sid = request.session_id;
    if (!sid) throw new Error('Hydra sent a login request with no session id');

    const opened = await this.db.tx(async (db) => {
      const sessionId = await this.identities.openSession(db, {
        identityId: a.identityId,
        credentialId: a.credentialId,
        sid,
        clientId: request.client.client_id,
        ip: a.ip,
        userAgent: a.userAgent,
        lifetimeSeconds: env.REMEMBER_SECONDS,
      });
      if (!sessionId) return null;
      await this.identities.markUsed(db, a.credentialId);
      await this.identities.event(
        {
          kind: 'sign_in',
          outcome: 'success',
          identityId: a.identityId,
          clientId: request.client.client_id,
          credentialKind: a.credentialKind,
          authSessionId: sessionId,
          ip: a.ip,
          userAgent: a.userAgent,
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
    reply: FastifyReply,
    challenge: string,
    request: LoginRequest,
    id: Identifier,
    state: { error?: string; remaining?: number | null } = {},
  ): FastifyReply {
    return render(
      reply,
      'password',
      'Enter your password',
      {
        ...page(reply, challenge, request),
        identifier: id.value,
        error: state.error ?? null,
        remaining: state.remaining ?? null,
      },
      state.error ? 422 : 200,
    );
  }

  private lockoutScreen(
    reply: FastifyReply,
    challenge: string,
    request: LoginRequest,
    id: Identifier,
    until: Date,
  ): FastifyReply {
    return render(
      reply,
      'lockout',
      'Too many attempts',
      {
        ...page(reply, challenge, request),
        identifier: id.value,
        minutes: Math.max(1, Math.ceil((until.getTime() - Date.now()) / 60_000)),
      },
      429,
    );
  }
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

const noun = (id: Identifier) => (id.kind === 'email' ? 'email address' : 'phone number');

function upstreamNames(kinds: CredentialKind[]): string {
  const names = kinds.flatMap((k) =>
    k === 'oauth_google' ? ['Google'] : k === 'oauth_apple' ? ['Apple'] : [],
  );
  return names.length ? names.join(' or ') : 'a code';
}

export function clientName(client: { client_name: string; client_id: string }): string {
  return client.client_name || client.client_id;
}

export function parse<T>(schema: z.ZodType<T>, value: unknown): T {
  const result = schema.safeParse(value);
  if (!result.success) throw new BadRequestException('malformed request');
  return result.data;
}
