import { Controller, Get, Query, Res } from '@nestjs/common';
import type { FastifyReply } from 'fastify';
import { z } from 'zod';
import { redirect } from '../common/pages';
import { HydraAdmin, type ConsentRequest } from '../hydra/hydra-admin.service';
import { parse } from './login.controller';

const Challenge = z.string().min(1).max(4096);

/**
 * Hydra's consent challenge. A first-party client - one whose registration says so in
 * deploy/hydra/clients/ - is granted what it asked for without a screen (auth-plan.md section
 * 7.2). A third-party client is declined until OQ-ONB-11 makes consent a real screen.
 */
@Controller('consent')
export class ConsentController {
  constructor(private readonly hydra: HydraAdmin) {}

  @Get()
  async handle(
    @Query('consent_challenge') raw: unknown,
    @Res() reply: FastifyReply,
  ): Promise<void> {
    const challenge = parse(Challenge, raw);
    const request = await this.hydra.getConsent(challenge);

    if (request.client.metadata?.first_party !== true && !request.skip) {
      const to = await this.hydra.rejectConsent(
        challenge,
        'access_denied',
        'Third-party applications cannot be authorised yet.',
      );
      await redirect(reply, to);
      return;
    }

    const to = await this.hydra.acceptConsent(challenge, {
      grant_scope: request.requested_scope ?? [],
      grant_access_token_audience: request.requested_access_token_audience ?? [],
      session: sessionClaims(request),
    });
    await redirect(reply, to);
  }
}

/**
 * The claims the API guard reads (section 9), placed at the top level of the access token by
 * hydra.yml's allowed_top_level_claims: sid for revocation, acr/amr/auth_time for step-up.
 */
export function sessionClaims(request: ConsentRequest): {
  access_token: Record<string, unknown>;
  id_token: Record<string, unknown>;
} {
  const claims: Record<string, unknown> = {};
  if (request.login_session_id) claims.sid = request.login_session_id;
  if (request.acr) claims.acr = request.acr;
  if (request.amr?.length) claims.amr = request.amr;
  const authTime = request.context?.auth_time;
  if (typeof authTime === 'number') claims.auth_time = authTime;
  return { access_token: claims, id_token: {} };
}
