import { Controller, Get, Res } from '@nestjs/common';
import type { FastifyReply } from 'fastify';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';

const PUBLIC = join(__dirname, '..', '..', 'public');

/**
 * The one script the screens load (public/password.js), from this origin, which is all the
 * Content-Security-Policy allows (script-src 'self'). Read once at start, so a request never
 * names a path on disk.
 */
@Controller('assets')
export class AssetsController {
  private readonly passwordJs = readFileSync(join(PUBLIC, 'password.js'), 'utf8');

  @Get('password.js')
  password(@Res() reply: FastifyReply): FastifyReply {
    return reply
      .header('content-type', 'text/javascript; charset=utf-8')
      .header('cache-control', 'public, max-age=300')
      .send(this.passwordJs);
  }
}
