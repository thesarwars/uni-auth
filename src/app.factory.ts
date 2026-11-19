import 'reflect-metadata';
import { NestFactory } from '@nestjs/core';
import { FastifyAdapter, type NestFastifyApplication } from '@nestjs/platform-fastify';
import cookie from '@fastify/cookie';
import csrf from '@fastify/csrf-protection';
import helmet from '@fastify/helmet';
import multipart from '@fastify/multipart';
import { PHOTO_MAX_BYTES } from './photos/photos';
import type { Upload } from './photos/upload';
import { createEta } from './common/eta';
import { join } from 'node:path';
import { AppModule } from './app.module';
import { env } from './config/env';

const VIEWS = join(__dirname, '..', 'views');

/** The application as it runs; main.ts listens on it, the tests drive it. */
export async function createApp(
  logger: ('error' | 'warn' | 'log' | 'debug' | 'verbose')[] = ['error', 'warn', 'log'],
): Promise<NestFastifyApplication> {
  const app = await NestFactory.create<NestFastifyApplication>(
    AppModule,
    new FastifyAdapter({
      trustProxy: env.TRUSTED_PROXIES.length ? env.TRUSTED_PROXIES : false,
      genReqId: () => crypto.randomUUID(),
    }),
    { logger },
  );

  await app.register(helmet, {
    contentSecurityPolicy: {
      useDefaults: false,
      directives: {
        'default-src': ["'self'"],
        'img-src': ["'self'", 'https:', 'data:'],
        'style-src': ["'self'", "'unsafe-inline'"],
        // Only this origin's own files: public/password.js, served by AssetsController. No
        // inline script and no other origin, so an injected <script> still never runs.
        'script-src': ["'self'"],
        'base-uri': ["'none'"],
        'object-src': ["'none'"],
        // The login page may not be framed by any site, ours included: a member must see the
        // address they type a password into (auth-plan.md section 7.4, AU-11).
        'frame-ancestors': ["'none'"],
        // No form-action: a sign-in form posts here, and the redirect chain that follows ends at
        // whichever client asked - every registered redirect URI. Browsers apply form-action to
        // that whole chain, so 'self' would break every sign-in.
      },
    },
    frameguard: { action: 'deny' },
    referrerPolicy: { policy: 'no-referrer' }, // a challenge in the URL never leaves in a Referer
  });

  await app.register(cookie, { secret: env.COOKIE_SECRET });
  await app.register(csrf, {
    sessionPlugin: '@fastify/cookie',
    cookieOpts: {
      signed: true,
      httpOnly: true,
      sameSite: 'strict',
      path: '/',
      secure: env.NODE_ENV === 'production',
    },
  });

  // Uploads (the profile photo): parsed into the body like any form, so CsrfGuard reads _csrf
  // the same way. One file, read into memory up to one byte past the limit; a larger one arrives
  // marked too large rather than failing the request, so the member gets a page that says so.
  await app.register(multipart, {
    attachFieldsToBody: 'keyValues',
    limits: { files: 1, fields: 4, fieldSize: 1024, fileSize: PHOTO_MAX_BYTES + 1, parts: 5 },
    throwFileSizeLimit: false,
    onFile: async (part) => {
      const chunks: Buffer[] = [];
      for await (const chunk of part.file) chunks.push(chunk as Buffer);
      const upload: Upload = {
        data: Buffer.concat(chunks),
        tooLarge: part.file.truncated,
      };
      (part as unknown as { value: Upload }).value = upload;
    },
  });

  app.setViewEngine({
    engine: { eta: createEta(VIEWS, env.NODE_ENV === 'production') },
    templates: VIEWS,
    viewExt: 'eta',
  });

  app.enableShutdownHooks();
  await app.init();
  return app;
}
