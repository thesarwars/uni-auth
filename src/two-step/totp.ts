import { createHmac, randomBytes, timingSafeEqual } from 'node:crypto';

/**
 * Time-based one-time passwords (RFC 6238), as every authenticator app makes them: HMAC-SHA1,
 * 30-second steps, 6 digits. Small enough to write here rather than take a dependency for.
 */

export const DIGITS = 6;
export const PERIOD_SECONDS = 30;
/** Steps either side of now that are still accepted: a phone clock a little off still works. */
const DRIFT = 1;

/** A new seed: 20 random bytes, the size RFC 4226 recommends for HMAC-SHA1. */
export const newSeed = (): Buffer => randomBytes(20);

export const stepAt = (ms: number): number => Math.floor(ms / 1000 / PERIOD_SECONDS);

/** The code for one time step (RFC 4226 section 5.3, dynamic truncation). */
export function codeAt(seed: Buffer, step: number): string {
  const counter = Buffer.alloc(8);
  counter.writeBigUInt64BE(BigInt(step));
  const mac = createHmac('sha1', seed).update(counter).digest();
  const offset = mac[mac.length - 1]! & 0x0f;
  const bin = (mac.readUInt32BE(offset) & 0x7fffffff) % 10 ** DIGITS;
  return bin.toString().padStart(DIGITS, '0');
}

/**
 * The time step a typed code belongs to, within the drift allowed, or null. A step at or before
 * `after` is refused: a code works once, even inside its own 30 seconds.
 */
export function matchStep(
  seed: Buffer,
  typed: string,
  now = Date.now(),
  after: number | null = null,
): number | null {
  const code = typed.replace(/\s/g, '');
  if (!/^\d{6}$/.test(code)) return null;
  const at = stepAt(now);
  let found: number | null = null;
  // Every candidate is compared, so the time taken doesn't say which one matched.
  for (let step = at - DRIFT; step <= at + DRIFT; step++) {
    const same = timingSafeEqual(Buffer.from(codeAt(seed, step)), Buffer.from(code));
    if (same && found === null && (after === null || step > after)) found = step;
  }
  return found;
}

const ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

/** RFC 4648 base32, no padding: how authenticator apps take a seed. */
export function base32(bytes: Buffer): string {
  let bits = 0;
  let value = 0;
  let out = '';
  for (const byte of bytes) {
    value = (value << 8) | byte;
    bits += 8;
    while (bits >= 5) {
      out += ALPHABET[(value >>> (bits - 5)) & 31];
      bits -= 5;
    }
  }
  if (bits > 0) out += ALPHABET[(value << (5 - bits)) & 31];
  return out;
}

export function fromBase32(text: string): Buffer {
  const clean = text.toUpperCase().replace(/[\s=]/g, '');
  let bits = 0;
  let value = 0;
  const out: number[] = [];
  for (const ch of clean) {
    const i = ALPHABET.indexOf(ch);
    if (i < 0) throw new Error('not base32');
    value = (value << 5) | i;
    bits += 5;
    if (bits >= 8) {
      out.push((value >>> (bits - 8)) & 255);
      bits -= 8;
    }
  }
  return Buffer.from(out);
}

/** The seed in groups of four, for typing in by hand. */
export const grouped = (key: string): string => key.match(/.{1,4}/g)!.join(' ');

/** What the QR code holds (Key Uri Format): the app shows "<issuer> (<account>)". */
export function otpauthUri(seed: Buffer, issuer: string, account: string): string {
  const label = `${encodeURIComponent(issuer)}:${encodeURIComponent(account)}`;
  const q = new URLSearchParams({
    secret: base32(seed),
    issuer,
    algorithm: 'SHA1',
    digits: String(DIGITS),
    period: String(PERIOD_SECONDS),
  });
  return `otpauth://totp/${label}?${q.toString()}`;
}
