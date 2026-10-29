import type { NestFastifyApplication } from '@nestjs/platform-fastify';
import { createApp } from '../../src/app.factory';
import { HYDRA_ADMIN } from './browser';

/**
 * The application on :3100, where Hydra's urls.login, consent and logout point
 * (deploy/hydra/hydra.yml), against the real Hydra.
 */
export async function startApp(): Promise<NestFastifyApplication> {
  const ready = await fetch(`${HYDRA_ADMIN}/health/ready`).catch(() => null);
  if (!ready?.ok) {
    throw new Error(
      'Hydra is not running. docker compose up -d --wait && scripts/hydra-keys.sh && scripts/hydra-clients.sh',
    );
  }
  const app = await createApp(['error']);
  await app.listen({ port: 3100, host: 'localhost' });
  return app;
}
