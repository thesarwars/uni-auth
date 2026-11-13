import { Controller, Get, NotFoundException, Param, Res } from '@nestjs/common';
import type { FastifyReply } from 'fastify';
import { existsSync, readdirSync, readFileSync } from 'node:fs';
import { join } from 'node:path';

const PUBLIC = join(__dirname, '..', '..', 'public');

/** What each kind of file is served as. A file of any other kind in public/ is never served. */
const TYPES: Record<string, string> = {
  svg: 'image/svg+xml',
  png: 'image/png',
  css: 'text/css; charset=utf-8',
  woff2: 'font/woff2',
};

/**
 * The files the screens use, read once at start: the stylesheet, the Entity mark (also the
 * favicon, with PNGs for older browsers and iOS), the Geist faces, the design's icons
 * (public/icons/) and the apps' logos (public/clients/, see clientLogo). The source images that
 * only make these (public/icon_blackbg.png) are left out by name.
 */
const SKIP = new Set(['icon_blackbg.png']);

function load(): Map<string, { type: string; body: Buffer }> {
  const files = new Map<string, { type: string; body: Buffer }>();
  for (const dir of ['', 'icons', 'clients']) {
    const at = join(PUBLIC, dir);
    if (!existsSync(at)) continue;
    for (const name of readdirSync(at)) {
      const type = TYPES[name.split('.').pop() ?? ''];
      if (!type || SKIP.has(name)) continue;
      files.set(dir ? `${dir}/${name}` : name, { type, body: readFileSync(join(at, name)) });
    }
  }
  return files;
}

const FILES = load();

/**
 * The apps a sign-in screen can show the logo of: the Hydra client's metadata.product names it,
 * and public/clients/<product>.png must exist. The CSP allows images from this origin only, so a
 * client's own logo_uri is never used.
 */
export function clientLogo(product: unknown): string | null {
  return typeof product === 'string' && FILES.has(`clients/${product}.png`)
    ? `/assets/clients/${product}.png`
    : null;
}

/**
 * The one script the screens load (public/password.js) and the files above, from this origin,
 * which is all the Content-Security-Policy allows (script-src 'self'). A request names a key in
 * the map, never a path on disk.
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

  @Get(':name')
  top(@Param('name') name: string, @Res() reply: FastifyReply): FastifyReply {
    return this.send(name, reply);
  }

  @Get(':dir/:name')
  nested(
    @Param('dir') dir: string,
    @Param('name') name: string,
    @Res() reply: FastifyReply,
  ): FastifyReply {
    return this.send(`${dir}/${name}`, reply);
  }

  private send(key: string, reply: FastifyReply): FastifyReply {
    const file = FILES.get(key);
    if (!file) throw new NotFoundException();
    return reply
      .header('content-type', file.type)
      .header('cache-control', 'public, max-age=86400')
      .send(file.body);
  }
}
