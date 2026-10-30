import { Injectable, Logger, type OnModuleDestroy } from '@nestjs/common';
import { Redis } from 'ioredis';
import { env } from '../config/env';

/**
 * The one Redis connection: the password throttle's counters and the short-lived state of an
 * upstream sign-in. Nothing durable lives here.
 */
@Injectable()
export class RedisService implements OnModuleDestroy {
  private readonly logger = new Logger(RedisService.name);
  private down = false;

  readonly client = new Redis(env.REDIS_URL, {
    maxRetriesPerRequest: 1,
    enableOfflineQueue: false,
  });

  constructor() {
    // ioredis retries on its own and emits an error on every attempt; without a listener each
    // one is an "Unhandled error event". Say once that Redis is gone - the throttle then fails
    // closed and /ready says so - and once that it is back.
    this.client.on('error', (err: Error) => {
      if (this.down) return;
      this.down = true;
      this.logger.warn(
        `Redis unreachable (${err.message}); retrying. Passwords are not checked meanwhile.`,
      );
    });
    this.client.on('ready', () => {
      if (!this.down) return;
      this.down = false;
      this.logger.log('Redis reachable again');
    });
  }

  async ready(): Promise<boolean> {
    try {
      return (await this.client.ping()) === 'PONG';
    } catch {
      return false;
    }
  }

  onModuleDestroy(): void {
    this.client.disconnect();
  }
}
