import { Body, Controller, Get, Post, Query, Res } from '@nestjs/common';
import type { FastifyReply } from 'fastify';
import { z } from 'zod';
import { redirect, render } from '../common/pages';
import { HydraAdmin } from '../hydra/hydra-admin.service';
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
 * Part 7 adds revoking the auth_session row and publishing the sid to the API's denylist.
 */
@Controller()
export class LogoutController {
  constructor(private readonly hydra: HydraAdmin) {}

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
  async submit(@Body() body: unknown, @Res() reply: FastifyReply): Promise<void> {
    const form = parse(LogoutForm, body);
    if (form.action === 'cancel') {
      await this.hydra.rejectLogout(form.logout_challenge);
      await render(reply, 'still-signed-in', 'You are still signed in');
      return;
    }
    await redirect(reply, await this.hydra.acceptLogout(form.logout_challenge));
  }

  /** Hydra's urls.post_logout_redirect: where a sign-out lands when the client named nowhere. */
  @Get('signed-out')
  async signedOut(@Res() reply: FastifyReply): Promise<void> {
    await render(reply, 'signed-out', 'You have signed out');
  }
}
