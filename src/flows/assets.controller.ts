import { Controller, Get, Req, Res } from '@nestjs/common';
import type { FastifyReply, FastifyRequest } from 'fastify';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';

const PUBLIC = join(__dirname, '..', '..', 'public');

/**
 * The screens' stylesheet, the provider's mark (the SVG on every screen and as the favicon; PNGs for older browsers and
 * iOS) and the Inter face the screens are set in. Each with the type it is served as.
 */
const FILES: Record<string, string> = {
  'entity-auth.svg': 'image/svg+xml',
  'entity-auth.css': 'text/css; charset=utf-8',
  'entity-auth-32.png': 'image/png',
  'entity-auth-120.png': 'image/png',
  'entity-auth-180.png': 'image/png',
  'inter-latin.woff2': 'font/woff2',
};

/**
 * The one script the screens load (public/password.js), the provider's logo and the font, from this
 * origin, which is all the Content-Security-Policy allows (script-src 'self'). Read once at
 * start, so a request never names a path on disk.
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

  private readonly files = new Map<string, Buffer>(
    Object.keys(FILES).map((name) => [name, readFileSync(join(PUBLIC, name))]),
  );

  @Get(Object.keys(FILES))
  file(@Req() request: FastifyRequest, @Res() reply: FastifyReply): FastifyReply {
    const name = request.url.split('?')[0]!.split('/').pop()!;
    return reply
      .header('content-type', FILES[name]!)
      .header('cache-control', 'public, max-age=86400')
      .send(this.files.get(name));
  }
}
