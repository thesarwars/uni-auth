import 'reflect-metadata';
import { NestFactory } from '@nestjs/core';
import { FastifyAdapter, type NestFastifyApplication } from '@nestjs/platform-fastify';
import cookie from '@fastify/cookie';
import csrf from '@fastify/csrf-protection';
import helmet from '@fastify/helmet';
import { Eta } from 'eta';
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
        'script-src': ["'none'"],
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

  app.setViewEngine({
    engine: { eta: new Eta({ views: VIEWS, cache: env.NODE_ENV === 'production' }) },
    templates: VIEWS,
    viewExt: 'eta',
  });

  app.enableShutdownHooks();
  await app.init();
  return app;
}
