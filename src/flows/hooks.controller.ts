import { Body, Controller, HttpCode, Logger, Post, Req, Res } from '@nestjs/common';
import type { FastifyReply, FastifyRequest } from 'fastify';
import { timingSafeEqual } from 'node:crypto';
import { env } from '../config/env';
import { CrossSite } from '../common/csrf.guard';
import { IdentityRepository } from '../identity/identity.repository';

/**
 * Hydra's refresh hook (hydra.yml oauth2.refresh_token_hook): asked before every refresh,
 * answers 204 to let it through and 403 to refuse it. A refresh token so dies with its session -
 * signed out, revoked by a password reset, or its identity suspended or closed - instead of
 * living out its ninety days.
 *
 * Only Hydra calls it, proving itself with HYDRA_HOOK_SECRET; it is not a page and carries no
 * form token. A session uni-auth does not know - one accepted through Hydra's admin API, which
 * only an operator can reach - is let through and logged.
 */
@Controller('hooks')
export class HooksController {
  private readonly logger = new Logger(HooksController.name);
  private readonly expected = Buffer.from(`Bearer ${env.HYDRA_HOOK_SECRET}`);

  constructor(private readonly identities: IdentityRepository) {}

  @Post('refresh')
  @CrossSite()
  @HttpCode(204)
  async refresh(
    @Req() req: FastifyRequest,
    @Body() body: unknown,
    @Res({ passthrough: true }) reply: FastifyReply,
  ): Promise<void> {
    const presented = Buffer.from(req.headers.authorization ?? '');
    if (presented.length !== this.expected.length || !timingSafeEqual(presented, this.expected)) {
      reply.status(401);
      return;
    }
    const sid = sidOf(body);
    if (!sid) {
      // Every member's token carries one (consent.controller.ts); without it, nothing to vouch for.
      reply.status(403);
      return;
    }
    const ok = await this.identities.mayRefresh(sid);
    if (ok === null) {
      this.logger.warn(`refresh for session ${sid}, which uni-auth did not open; allowed`);
      return;
    }
    if (!ok) reply.status(403);
  }
}

/** The sid the consent handler put among the access token's claims (session.extra). */
function sidOf(body: unknown): string | null {
  const extra = (body as { session?: { extra?: { sid?: unknown } } } | null)?.session?.extra;
  return typeof extra?.sid === 'string' && extra.sid.length > 0 && extra.sid.length <= 128
    ? extra.sid
    : null;
}
