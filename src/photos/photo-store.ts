import { Injectable } from '@nestjs/common';
import {
  DeleteObjectCommand,
  GetObjectCommand,
  NoSuchKey,
  PutObjectCommand,
  S3Client,
} from '@aws-sdk/client-s3';
import { env } from '../config/env';

/**
 * The bucket profile photos are kept in (S3_PHOTO_BUCKET). Plain S3 calls, so s3mock now and AWS
 * S3 later differ only in .env. Disabled when no bucket is set.
 */
@Injectable()
export class PhotoStore {
  readonly enabled = Boolean(env.S3_PHOTO_BUCKET);
  private readonly bucket = env.S3_PHOTO_BUCKET ?? '';
  private readonly s3 = new S3Client({
    region: env.S3_REGION,
    ...(env.S3_ENDPOINT ? { endpoint: env.S3_ENDPOINT, forcePathStyle: true } : {}),
    ...(env.S3_ACCESS_KEY_ID && env.S3_SECRET_ACCESS_KEY
      ? {
          credentials: {
            accessKeyId: env.S3_ACCESS_KEY_ID,
            secretAccessKey: env.S3_SECRET_ACCESS_KEY,
          },
        }
      : {}),
  });

  async put(key: string, body: Buffer): Promise<void> {
    await this.s3.send(
      new PutObjectCommand({
        Bucket: this.bucket,
        Key: key,
        Body: body,
        ContentType: 'image/webp',
      }),
    );
  }

  /** The object's bytes, or null when it isn't there. */
  async get(key: string): Promise<Buffer | null> {
    try {
      const res = await this.s3.send(new GetObjectCommand({ Bucket: this.bucket, Key: key }));
      return res.Body ? Buffer.from(await res.Body.transformToByteArray()) : null;
    } catch (e) {
      if (e instanceof NoSuchKey) return null;
      throw e;
    }
  }

  /** Deleting a missing object succeeds, as S3 does. */
  async delete(key: string): Promise<void> {
    await this.s3.send(new DeleteObjectCommand({ Bucket: this.bucket, Key: key }));
  }

  destroy(): void {
    this.s3.destroy();
  }
}
