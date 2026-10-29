import { Controller, Get, Query, Res, ServiceUnavailableException } from '@nestjs/common';
import type { FastifyReply } from 'fastify';
import { renderError } from '../common/pages';
import { Database } from '../db/database.service';
import { HydraAdmin } from '../hydra/hydra-admin.service';
import { Throttle } from '../throttle/throttle.service';

/** Hydra's urls.error, and the probes. */
@Controller()
export class SystemController {
  constructor(
    private readonly hydra: HydraAdmin,
    private readonly db: Database,
    private readonly throttle: Throttle,
  ) {}

  /**
   * Hydra sends the browser here when it refuses a request outright - an unknown client, an
   * unregistered redirect URI - which is exactly when it must not send it back to the client.
   * Hydra's own wording is shown as detail, escaped by the template.
   */
  @Get('error')
  async error(
    @Query('error') error: unknown,
    @Query('error_description') description: unknown,
    @Res() reply: FastifyReply,
  ): Promise<void> {
    const detail = [error, description].filter((v) => typeof v === 'string' && v).join(': ');
    await renderError(
      reply,
      400,
      "We couldn't sign you in",
      detail || 'The app that sent you here made a request we could not accept.',
    );
  }

  @Get('health')
  health(): { status: string } {
    return { status: 'ok' };
  }

  /**
   * Readiness touches everything a sign-in needs: Hydra, the identity database, and Redis - the
   * throttle fails closed, so without it no password can be checked.
   */
  @Get('ready')
  async ready(): Promise<{ status: string }> {
    const [hydra, db, throttle] = await Promise.all([
      this.hydra.ready(),
      this.db.ready(),
      this.throttle.ready(),
    ]);
    if (!hydra || !db || !throttle) {
      throw new ServiceUnavailableException(
        `not ready: ${[!hydra && 'hydra', !db && 'database', !throttle && 'redis'].filter(Boolean).join(', ')}`,
      );
    }
    return { status: 'ready' };
  }
}
