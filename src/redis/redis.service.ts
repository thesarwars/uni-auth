import { Injectable, type OnModuleDestroy } from '@nestjs/common';
import { Redis } from 'ioredis';
import { env } from '../config/env';

/**
 * The one Redis connection: the password throttle's counters and the short-lived state of an
 * upstream sign-in. Nothing durable lives here.
 */
@Injectable()
export class RedisService implements OnModuleDestroy {
  readonly client = new Redis(env.REDIS_URL, {
    maxRetriesPerRequest: 1,
    enableOfflineQueue: false,
  });

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
