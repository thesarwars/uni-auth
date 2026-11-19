import { Injectable } from '@nestjs/common';
import { randomBytes } from 'node:crypto';
import sharp, { type Metadata } from 'sharp';
import { env } from '../config/env';
import { PhotoRepository } from './photo.repository';
import { PhotoStore } from './photo-store';

/** The largest upload taken: a phone's photo, not a camera's RAW. */
export const PHOTO_MAX_BYTES = 5 * 1024 * 1024;
/** The stored photo is this square, in px: twice the largest avatar on any screen, and more. */
const SIZE = 256;
/** A decoded image this large is refused before it is processed (a "decompression bomb"). */
const MAX_PIXELS = 40_000_000;
const FORMATS = new Set(['jpeg', 'png', 'webp']);

/** Why an upload was refused, as the member reads it. */
export class PhotoRefused extends Error {}

/**
 * Profile photos. An upload is decoded, turned upright, cropped square from its centre and
 * re-encoded as a small WebP; nothing of the original is kept - not its size, its format or its
 * metadata (camera, place, time). The object goes to the bucket first, then the record: a failed
 * record leaves an object no one serves, never a record without its object.
 */
@Injectable()
export class Photos {
  constructor(
    private readonly store: PhotoStore,
    private readonly photos: PhotoRepository,
  ) {}

  get enabled(): boolean {
    return this.store.enabled;
  }

  /** The member's photo as the account centre links it, or null. */
  async path(identityId: string): Promise<string | null> {
    if (!this.enabled) return null;
    const key = await this.photos.currentKey(identityId);
    return key ? `/${key}` : null;
  }

  /** The same, absolute: for apps (the OIDC picture claim). */
  async url(identityId: string): Promise<string | null> {
    const path = await this.path(identityId);
    return path ? `${env.LOGIN_PUBLIC_URL}${path}` : null;
  }

  /** Turns an upload into the stored photo and puts it in the bucket; returns its key. */
  async upload(input: Buffer): Promise<{ key: string; bytes: number }> {
    const webp = await toPhoto(input);
    const key = `photos/${randomBytes(16).toString('base64url')}.webp`;
    await this.store.put(key, webp);
    return { key, bytes: webp.length };
  }
}

/** The stored form of an upload, or PhotoRefused. */
export async function toPhoto(input: Buffer): Promise<Buffer> {
  if (input.length === 0) throw new PhotoRefused('Choose a photo to upload.');
  if (input.length > PHOTO_MAX_BYTES) throw new PhotoRefused('Choose a photo under 5 MB.');
  let meta: Metadata;
  try {
    meta = await sharp(input, { limitInputPixels: MAX_PIXELS }).metadata();
  } catch {
    throw new PhotoRefused('That file isn’t a photo we can use. Choose a JPEG, PNG or WebP.');
  }
  if (!meta.format || !FORMATS.has(meta.format)) {
    throw new PhotoRefused('That file isn’t a photo we can use. Choose a JPEG, PNG or WebP.');
  }
  if ((meta.width ?? 0) * (meta.height ?? 0) > MAX_PIXELS) {
    throw new PhotoRefused('That photo is too large. Choose one under 40 megapixels.');
  }
  try {
    return await sharp(input, { limitInputPixels: MAX_PIXELS, failOn: 'error' })
      .rotate()
      .resize(SIZE, SIZE, { fit: 'cover', position: 'centre' })
      .flatten({ background: '#ffffff' })
      .webp({ quality: 82 })
      .toBuffer();
  } catch {
    throw new PhotoRefused('That photo couldn’t be read. Try another one.');
  }
}
