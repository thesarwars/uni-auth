import {
  Injectable,
  Logger,
  type OnApplicationBootstrap,
  type OnModuleDestroy,
} from '@nestjs/common';
import { env } from '../config/env';
import { PhotoRepository } from './photo.repository';
import { PhotoStore } from './photo-store';

/**
 * Deletes replaced and removed photos from the bucket: a changed photo, a removed one, and the
 * photo of an identity that closed or was erased (0015). A failed delete is tried again next run;
 * the record says which objects are still there.
 */
@Injectable()
export class PhotoCleanup implements OnApplicationBootstrap, OnModuleDestroy {
  private readonly logger = new Logger(PhotoCleanup.name);
  private timer: NodeJS.Timeout | null = null;
  private running: Promise<number> | null = null;

  constructor(
    private readonly photos: PhotoRepository,
    private readonly store: PhotoStore,
  ) {}

  onApplicationBootstrap(): void {
    if (!this.store.enabled) return;
    this.timer = setInterval(() => void this.run(), env.PHOTO_CLEANUP_MS);
    this.timer.unref();
  }

  async onModuleDestroy(): Promise<void> {
    if (this.timer) clearInterval(this.timer);
    await this.running;
    this.store.destroy();
  }

  /** One pass; returns how many objects were deleted. */
  run(): Promise<number> {
    this.running ??= this.pass().finally(() => (this.running = null));
    return this.running;
  }

  private async pass(): Promise<number> {
    if (!this.store.enabled) return 0;
    let deleted = 0;
    try {
      for (const p of await this.photos.toDelete()) {
        await this.store.delete(p.key);
        await this.photos.markDeleted(p.id);
        deleted += 1;
      }
    } catch (e) {
      this.logger.warn(`photo cleanup stopped: ${(e as Error).message}`);
    }
    return deleted;
  }
}
