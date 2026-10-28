import { Logger } from '@nestjs/common';
import { createApp } from './app.factory';
import { env } from './config/env';

async function bootstrap(): Promise<void> {
  const app = await createApp(logLevels());
  await app.listen({ port: env.PORT, host: env.HOST });
  new Logger('bootstrap').log(`listening on ${env.HOST}:${env.PORT}`);
}

function logLevels(): ('error' | 'warn' | 'log' | 'debug' | 'verbose')[] {
  switch (env.LOG_LEVEL) {
    case 'fatal':
    case 'error':
      return ['error'];
    case 'warn':
      return ['error', 'warn'];
    case 'debug':
    case 'trace':
      return ['error', 'warn', 'log', 'debug', 'verbose'];
    default:
      return ['error', 'warn', 'log'];
  }
}

void bootstrap();
