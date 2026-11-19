import { Controller, Get, NotFoundException, Param, Res } from '@nestjs/common';
import type { FastifyReply } from 'fastify';
import { PhotoRepository } from './photo.repository';
import { PhotoStore } from './photo-store';

const NAME = /^[A-Za-z0-9_-]{22}\.webp$/;

/**
 * A member's current profile photo, by its unguessable name: the account centre shows it, and
 * apps given the profile scope receive its URL as the picture claim. A photo never changes under
 * its name (a new one gets a new name), so it is cached for a day - no longer, so a removed photo
 * soon leaves every cache too. Once replaced or removed it is no longer served here, whether or
 * not the cleanup has deleted it yet. Apps on other sites may show it (Cross-Origin-Resource-Policy).
 */
@Controller('photos')
export class PhotosController {
  constructor(
    private readonly photos: PhotoRepository,
    private readonly store: PhotoStore,
  ) {}

  @Get(':name')
  async photo(@Param('name') name: string, @Res() reply: FastifyReply): Promise<void> {
    if (!this.store.enabled || !NAME.test(name)) throw new NotFoundException();
    const key = `photos/${name}`;
    if (!(await this.photos.isCurrent(key))) throw new NotFoundException();
    const body = await this.store.get(key);
    if (!body) throw new NotFoundException();
    await reply
      .header('content-type', 'image/webp')
      .header('cache-control', 'public, max-age=86400')
      .header('x-content-type-options', 'nosniff')
      .header('cross-origin-resource-policy', 'cross-origin')
      .send(body);
  }
}
