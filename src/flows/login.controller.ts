import { BadRequestException, Body, Controller, Get, Post, Query, Res } from '@nestjs/common';
import type { FastifyReply } from 'fastify';
import { z } from 'zod';
import { redirect, render } from '../common/pages';
import { env } from '../config/env';
import { HydraAdmin } from '../hydra/hydra-admin.service';

const Challenge = z.string().min(1).max(4096);
const LoginForm = z.object({
  login_challenge: Challenge,
  action: z.enum(['continue', 'cancel']),
});

/**
 * Hydra's login challenge (auth-plan.md section 7.1). Hydra sends the browser here whenever a
 * client asks for a sign-in; this controller decides who the member is and tells Hydra.
 *
 * Part 3 skeleton: the only credential is DEV_TEST_SUBJECT. Part 4 replaces it with the
 * identifier, password and code screens.
 */
@Controller('login')
export class LoginController {
  constructor(private readonly hydra: HydraAdmin) {}

  @Get()
  async show(@Query('login_challenge') raw: unknown, @Res() reply: FastifyReply): Promise<void> {
    const challenge = parse(Challenge, raw);
    const request = await this.hydra.getLogin(challenge);

    // The provider session is still valid: single sign-on, no screen (section 7.1, step 2).
    if (request.skip) {
      await redirect(reply, await this.hydra.acceptLogin(challenge, { subject: request.subject }));
      return;
    }

    await render(reply, 'login', `Sign in to continue to ${clientName(request.client)}`, {
      challenge,
      clientName: clientName(request.client),
      logoUri: request.client.logo_uri,
      testSubject: env.DEV_TEST_SUBJECT ?? null,
      csrfToken: reply.generateCsrf(),
    });
  }

  @Post()
  async submit(@Body() body: unknown, @Res() reply: FastifyReply): Promise<void> {
    const form = parse(LoginForm, body);

    if (form.action === 'cancel') {
      const to = await this.hydra.rejectLogin(
        form.login_challenge,
        'access_denied',
        'The member cancelled the sign-in.',
      );
      await redirect(reply, to);
      return;
    }

    if (!env.DEV_TEST_SUBJECT) throw new BadRequestException('no credential is available yet');
    const to = await this.hydra.acceptLogin(form.login_challenge, {
      subject: env.DEV_TEST_SUBJECT,
      remember: true,
      remember_for: env.REMEMBER_SECONDS,
      // How the member authenticated. The API reads these for step-up (section 9); a test
      // subject says so, so nothing can mistake it for a real factor.
      acr: 'test',
      amr: ['test'],
      context: { auth_time: Math.floor(Date.now() / 1000) },
    });
    await redirect(reply, to);
  }
}

export function clientName(client: { client_name: string; client_id: string }): string {
  return client.client_name || client.client_id;
}

export function parse<T>(schema: z.ZodType<T>, value: unknown): T {
  const result = schema.safeParse(value);
  if (!result.success) throw new BadRequestException('malformed request');
  return result.data;
}
