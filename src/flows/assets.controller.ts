import { Controller, Get, NotFoundException, Param, Query, Res } from '@nestjs/common';
import type { FastifyReply } from 'fastify';
import { createHash } from 'node:crypto';
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

type Asset = { type: string; body: Buffer; version: string };

const versionOf = (body: Buffer | string): string =>
  createHash('sha256').update(body).digest('hex').slice(0, 12);

function load(): Map<string, Asset> {
  const files = new Map<string, Asset>();
  for (const dir of ['', 'icons', 'clients']) {
    const at = join(PUBLIC, dir);
    if (!existsSync(at)) continue;
    for (const name of readdirSync(at)) {
      const type = TYPES[name.split('.').pop() ?? ''];
      if (!type || SKIP.has(name)) continue;
      const body = readFileSync(join(at, name));
      files.set(dir ? `${dir}/${name}` : name, { type, body, version: versionOf(body) });
    }
  }
  // The stylesheet names icons and fonts itself: those links carry versions too, and its own
  // version is taken after, so a changed icon also changes the stylesheet's URL.
  for (const [key, file] of files) {
    if (!key.endsWith('.css')) continue;
    const css = file.body
      .toString('utf8')
      .replace(
        /url\(\/assets\/([^)'"?]+)\)/g,
        (_, name: string) => `url(${versioned(files, name)})`,
      );
    files.set(key, { ...file, body: Buffer.from(css), version: versionOf(css) });
  }
  return files;
}

function versioned(files: Map<string, Asset>, name: string): string {
  const file = files.get(name);
  return file ? `/assets/${name}?v=${file.version}` : `/assets/${name}`;
}

const FILES = load();
const PASSWORD_JS = readFileSync(join(PUBLIC, 'password.js'), 'utf8');
const PASSWORD_JS_VERSION = versionOf(PASSWORD_JS);

/**
 * The URL a page links an asset by: /assets/<name>?v=<hash of its contents>. A deploy that
 * changes a file changes its URL, so browsers fetch it at once instead of using a cached copy
 * of the old one - which, beside a new password.js, made screens look half updated. Templates
 * call it as asset('...') (src/common/eta.ts).
 */
export function assetUrl(name: string): string {
  if (name === 'password.js') return `/assets/password.js?v=${PASSWORD_JS_VERSION}`;
  return versioned(FILES, name);
}

/** Every asset's URL, for the templates' asset() (built once: the files never change at run time). */
export function assetUrls(): Record<string, string> {
  const urls: Record<string, string> = { 'password.js': assetUrl('password.js') };
  for (const name of FILES.keys()) urls[name] = assetUrl(name);
  return urls;
}

/** A versioned URL that names the current file can be cached for good; anything else briefly. */
const cacheFor = (asked: unknown, current: string): string =>
  asked === current ? 'public, max-age=31536000, immutable' : 'public, max-age=300';

/**
 * The apps a sign-in screen can show the logo of: the Hydra client's metadata.product names it,
 * and public/clients/<product>.png must exist. The CSP allows images from this origin only, so a
 * client's own logo_uri is never used.
 */
export function clientLogo(product: unknown): string | null {
  return typeof product === 'string' && FILES.has(`clients/${product}.png`)
    ? assetUrl(`clients/${product}.png`)
    : null;
}

/**
 * The one script the screens load (public/password.js) and the files above, from this origin,
 * which is all the Content-Security-Policy allows (script-src 'self'). A request names a key in
 * the map, never a path on disk.
 */
@Controller('assets')
export class AssetsController {
  @Get('password.js')
  password(@Query('v') v: unknown, @Res() reply: FastifyReply): FastifyReply {
    return reply
      .header('content-type', 'text/javascript; charset=utf-8')
      .header('cache-control', cacheFor(v, PASSWORD_JS_VERSION))
      .send(PASSWORD_JS);
  }

  @Get(':name')
  top(
    @Param('name') name: string,
    @Query('v') v: unknown,
    @Res() reply: FastifyReply,
  ): FastifyReply {
    return this.send(name, v, reply);
  }

  @Get(':dir/:name')
  nested(
    @Param('dir') dir: string,
    @Param('name') name: string,
    @Query('v') v: unknown,
    @Res() reply: FastifyReply,
  ): FastifyReply {
    return this.send(`${dir}/${name}`, v, reply);
  }

  private send(key: string, v: unknown, reply: FastifyReply): FastifyReply {
    const file = FILES.get(key);
    if (!file) throw new NotFoundException();
    return reply
      .header('content-type', file.type)
      .header('cache-control', cacheFor(v, file.version))
      .send(file.body);
  }
}
