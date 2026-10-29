import { Body, Controller, Get, Logger, Post, Query, Req, Res } from '@nestjs/common';
import type { FastifyReply, FastifyRequest } from 'fastify';
import { z } from 'zod';
import { CrossSite } from '../common/csrf.guard';
import { redirect, renderError } from '../common/pages';
import { Database } from '../db/database.service';
import { HydraAdmin } from '../hydra/hydra-admin.service';
import { IdentityRepository } from '../identity/identity.repository';
import { Upstream, type Provider } from '../upstream/upstream.service';
import { SignIn } from './sign-in.service';

export const UPSTREAM_COOKIE = 'uni_up';

const Callback = z.object({
  state: z.string().min(1).max(200),
  code: z.string().min(1).max(4096).optional(),
  error: z.string().max(200).optional(),
});

/** Why the member is back on the identifier screen: the one-line reason section 7.3 asks for. */
export type UpstreamError = 'cancelled' | 'failed' | 'no_account' | 'suspended';

/**
 * Where Google and Apple send the member back (Upstream). Every outcome but success returns to
 * the identifier screen of the same sign-in with a reason; a callback that names no pending
 * sign-in of this browser is the error page, because there is no sign-in to return to.
 */
@Controller('upstream')
export class UpstreamController {
  private readonly log = new Logger(UpstreamController.name);

  constructor(
    private readonly upstream: Upstream,
    private readonly hydra: HydraAdmin,
    private readonly db: Database,
    private readonly identities: IdentityRepository,
    private readonly signIn: SignIn,
  ) {}

  @Get('google/callback')
  google(@Query() query: unknown, @Req() req: FastifyRequest, @Res() reply: FastifyReply) {
    return this.complete('google', query, req, reply);
  }

  /** Apple answers with response_mode=form_post: a POST from appleid.apple.com, no token of ours. */
  @Post('apple/callback')
  @CrossSite()
  apple(@Body() body: unknown, @Req() req: FastifyRequest, @Res() reply: FastifyReply) {
    return this.complete('apple', body, req, reply);
  }

  private async complete(
    provider: Provider,
    raw: unknown,
    req: FastifyRequest,
    reply: FastifyReply,
  ): Promise<void> {
    const params = Callback.safeParse(raw);
    const cookie = req.cookies[UPSTREAM_COOKIE];
    const unsigned = cookie ? req.unsignCookie(cookie) : null;
    const pending = params.success
      ? await this.upstream.claim(
          provider,
          params.data.state,
          unsigned?.valid ? unsigned.value : null,
        )
      : null;
    reply.clearCookie(UPSTREAM_COOKIE, { path: '/upstream' });
    if (!params.success || !pending) {
      await renderError(
        reply,
        400,
        'This sign-in has expired',
        'Go back to the app you were using and start signing in again.',
      );
      return;
    }

    const back = (why: UpstreamError) =>
      redirect(
        reply,
        `/login?${new URLSearchParams({
          login_challenge: pending.loginChallenge,
          upstream: provider,
          upstream_error: why,
        }).toString()}`,
      );

    const { code, error } = params.data;
    if (error || !code) {
      await back(
        error === 'access_denied' || error === 'user_cancelled_authorize' ? 'cancelled' : 'failed',
      );
      return;
    }

    let who;
    try {
      who = await this.upstream.finish(pending, code);
    } catch (err) {
      this.log.warn(
        `${provider} sign-in refused: ${err instanceof Error ? err.message : String(err)}`,
      );
      await back('failed');
      return;
    }

    const request = await this.hydra.getLogin(pending.loginChallenge);
    const seen = { ip: req.ip, userAgent: req.headers['user-agent'] ?? null };
    const kind = provider === 'google' ? 'oauth_google' : 'oauth_apple';
    const accept = (identityId: string, credentialId: string) =>
      this.signIn.accept(reply, pending.loginChallenge, request, seen, {
        identityId,
        credentialId,
        credentialKind: kind,
        amr: ['fed'],
        detail: { provider },
      });

    const known = await this.identities.byProvider(kind, who.subject);
    if (known) {
      if (known.status !== 'active') return void (await back('suspended'));
      await accept(known.identityId, known.credentialId);
      return;
    }

    // First time with this provider. It joins an existing identity only when the provider says
    // it verified the email and uni-auth holds that same address verified: both have proved it.
    if (who.email && who.emailVerified) {
      const found = await this.identities.resolve({ kind: 'email', value: who.email });
      if (found?.status === 'suspended') return void (await back('suspended'));
      if (found) {
        const credentialId = await this.db.tx((db) =>
          this.identities.linkProvider(db, {
            identityId: found.identityId,
            kind,
            subject: who.subject,
            email: who.email,
            emailVerified: who.emailVerified,
            clientId: request.client.client_id,
            ...seen,
          }),
        );
        await accept(found.identityId, credentialId);
        return;
      }
    }
    await back('no_account');
  }
}
