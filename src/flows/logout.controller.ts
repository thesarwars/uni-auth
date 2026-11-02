import { Body, Controller, Get, Post, Query, Req, Res } from '@nestjs/common';
import type { FastifyReply, FastifyRequest } from 'fastify';
import { z } from 'zod';
import { redirect, render } from '../common/pages';
import { Database } from '../db/database.service';
import { HydraAdmin } from '../hydra/hydra-admin.service';
import { IdentityRepository } from '../identity/identity.repository';
import { parse } from './login.controller';

const Challenge = z.string().min(1).max(4096);
const LogoutForm = z.object({
  logout_challenge: Challenge,
  action: z.enum(['sign_out', 'cancel']),
});

/**
 * Hydra's logout challenge: the sign-out confirmation (auth-plan.md section 7.2). Signing out
 * ends the provider session, so every application signed in through it on this device signs
 * out - the page says so before the member agrees.
 *
 * Signing out revokes the auth_session row and journals it before Hydra is told, so the refresh
 * hook refuses the session's refresh tokens from that moment. Hydra then ends its own session
 * and sends each client's back-channel logout, which tells an API to refuse the session's
 * access tokens (auth-plan.md section 12.2, part 7).
 */
@Controller()
export class LogoutController {
  constructor(
    private readonly hydra: HydraAdmin,
    private readonly db: Database,
    private readonly identities: IdentityRepository,
  ) {}

  @Get('logout')
  async show(@Query('logout_challenge') raw: unknown, @Res() reply: FastifyReply): Promise<void> {
    const challenge = parse(Challenge, raw);
    await this.hydra.getLogout(challenge);
    await render(reply, 'logout', 'Sign out', {
      challenge,
      csrfToken: reply.generateCsrf(),
    });
  }

  @Post('logout')
  async submit(
    @Body() body: unknown,
    @Req() req: FastifyRequest,
    @Res() reply: FastifyReply,
  ): Promise<void> {
    const form = parse(LogoutForm, body);
    if (form.action === 'cancel') {
      await this.hydra.rejectLogout(form.logout_challenge);
      await render(reply, 'still-signed-in', 'You are still signed in');
      return;
    }
    const request = await this.hydra.getLogout(form.logout_challenge);
    if (request.sid) {
      const sid = request.sid;
      await this.db.tx(async (db) => {
        const ended = await this.identities.endSession(db, sid, 'sign_out');
        if (!ended) return;
        await this.identities.event(
          {
            kind: 'sign_out',
            outcome: 'success',
            identityId: ended.identityId,
            clientId: request.client?.client_id ?? null,
            authSessionId: ended.id,
            ip: req.ip,
            userAgent: req.headers['user-agent'] ?? null,
          },
          db,
        );
      });
    }
    await redirect(reply, await this.hydra.acceptLogout(form.logout_challenge));
  }

  /** Hydra's urls.post_logout_redirect: where a sign-out lands when the client named nowhere. */
  @Get('signed-out')
  async signedOut(@Res() reply: FastifyReply): Promise<void> {
    await render(reply, 'signed-out', 'You have signed out');
  }
}
