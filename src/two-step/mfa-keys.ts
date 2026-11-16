import { Injectable } from '@nestjs/common';
import { createCipheriv, createDecipheriv, createHmac, hkdfSync, randomBytes } from 'node:crypto';
import { env } from '../config/env';

const VERSION = 1;
const IV_BYTES = 12;
const TAG_BYTES = 16;

/**
 * The keys behind 2-step verification, both derived from MFA_ENCRYPTION_KEY (HKDF-SHA256):
 * one seals authenticator seeds (AES-256-GCM, bound to their identity), the other keyed-hashes
 * recovery codes. The database holds only what these produce.
 */
@Injectable()
export class MfaKeys {
  private readonly seal_: Buffer | null;
  private readonly mac: Buffer | null;

  constructor() {
    const root = env.MFA_ENCRYPTION_KEY ? Buffer.from(env.MFA_ENCRYPTION_KEY, 'hex') : null;
    this.seal_ = root ? derive(root, 'entity-auth totp seed v1') : null;
    this.mac = root ? derive(root, 'entity-auth recovery code v1') : null;
  }

  /** Whether 2-step verification can be offered at all. */
  get enabled(): boolean {
    return this.seal_ !== null;
  }

  /** version | IV | tag | ciphertext. The identity is the additional data: a seed copied to
   * another identity's row doesn't open. */
  seal(seed: Buffer, identityId: string): Buffer {
    const key = this.need(this.seal_);
    const iv = randomBytes(IV_BYTES);
    const cipher = createCipheriv('aes-256-gcm', key, iv);
    cipher.setAAD(Buffer.from(identityId));
    const ct = Buffer.concat([cipher.update(seed), cipher.final()]);
    return Buffer.concat([Buffer.from([VERSION]), iv, cipher.getAuthTag(), ct]);
  }

  open(sealed: Buffer, identityId: string): Buffer {
    const key = this.need(this.seal_);
    if (sealed[0] !== VERSION) throw new Error('unknown seed version');
    const iv = sealed.subarray(1, 1 + IV_BYTES);
    const tag = sealed.subarray(1 + IV_BYTES, 1 + IV_BYTES + TAG_BYTES);
    const decipher = createDecipheriv('aes-256-gcm', key, iv);
    decipher.setAAD(Buffer.from(identityId));
    decipher.setAuthTag(tag);
    return Buffer.concat([
      decipher.update(sealed.subarray(1 + IV_BYTES + TAG_BYTES)),
      decipher.final(),
    ]);
  }

  /** A recovery code's stored form; the code is normalised first (recovery-codes.ts). */
  hashCode(normalised: string): Buffer {
    return createHmac('sha256', this.need(this.mac)).update(normalised).digest();
  }

  private need(key: Buffer | null): Buffer {
    if (!key) throw new Error('MFA_ENCRYPTION_KEY is not set');
    return key;
  }
}

const derive = (root: Buffer, info: string): Buffer =>
  Buffer.from(hkdfSync('sha256', root, Buffer.alloc(0), info, 32));
