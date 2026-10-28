import { Injectable, type CanActivate, type ExecutionContext } from '@nestjs/common';
import Tokens from '@fastify/csrf';
import type { FastifyRequest } from 'fastify';

// The plugin is registered without csrfOpts, so its tokens are the defaults: no userInfo.
const tokens = new Tokens({ userInfo: false });

/** A form posted without a token matching its cookie: stale, replayed or forged. */
export class CsrfRejected extends Error {
  constructor() {
    super('csrf token missing or invalid');
  }
}

/**
 * Every form is CSRF-protected (auth-plan.md section 7.4). @fastify/csrf-protection issues the
 * token (reply.generateCsrf() on the GET) and keeps its secret in the signed `_csrf` cookie;
 * this guard checks a POST against it. It is a guard rather than the plugin's own hook so a
 * refusal reaches PageErrorFilter and becomes a page, through Nest, instead of replacing
 * Fastify's error handler.
 */
@Injectable()
export class CsrfGuard implements CanActivate {
  canActivate(ctx: ExecutionContext): boolean {
    const req = ctx.switchToHttp().getRequest<FastifyRequest>();
    if (req.method !== 'POST') return true;

    const cookie = req.cookies._csrf;
    const unsigned = cookie ? req.unsignCookie(cookie) : null;
    const secret = unsigned?.valid ? unsigned.value : null;
    const token = (req.body as { _csrf?: unknown } | undefined)?._csrf;
    if (!secret || typeof token !== 'string' || !tokens.verify(secret, token)) {
      throw new CsrfRejected();
    }
    return true;
  }
}
