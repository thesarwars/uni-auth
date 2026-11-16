import { describe, expect, it } from 'vitest';
import { MfaKeys } from '../../src/two-step/mfa-keys';
import { newCodes, normalise, shown } from '../../src/two-step/recovery-codes';
import {
  base32,
  codeAt,
  fromBase32,
  grouped,
  matchStep,
  otpauthUri,
  stepAt,
} from '../../src/two-step/totp';

// RFC 6238 appendix B: the SHA-1 seed, and the last six digits of its eight-digit codes.
const RFC_SEED = Buffer.from('12345678901234567890');

describe('totp', () => {
  it('makes the RFC 6238 reference codes', () => {
    expect(codeAt(RFC_SEED, stepAt(59_000))).toBe('287082');
    expect(codeAt(RFC_SEED, stepAt(1_111_111_109_000))).toBe('081804');
    expect(codeAt(RFC_SEED, stepAt(1_234_567_890_000))).toBe('005924');
    expect(codeAt(RFC_SEED, stepAt(2_000_000_000_000))).toBe('279037');
  });

  it('accepts a step either side of now, and no further', () => {
    const now = 1_234_567_890_000;
    const at = stepAt(now);
    expect(matchStep(RFC_SEED, codeAt(RFC_SEED, at), now)).toBe(at);
    expect(matchStep(RFC_SEED, codeAt(RFC_SEED, at - 1), now)).toBe(at - 1);
    expect(matchStep(RFC_SEED, codeAt(RFC_SEED, at + 1), now)).toBe(at + 1);
    expect(matchStep(RFC_SEED, codeAt(RFC_SEED, at - 2), now)).toBeNull();
    expect(matchStep(RFC_SEED, codeAt(RFC_SEED, at + 2), now)).toBeNull();
  });

  it('refuses a step already spent, so a code works once', () => {
    const now = 1_234_567_890_000;
    const at = stepAt(now);
    expect(matchStep(RFC_SEED, codeAt(RFC_SEED, at), now, at)).toBeNull();
    expect(matchStep(RFC_SEED, codeAt(RFC_SEED, at), now, at - 1)).toBe(at);
  });

  it('takes spaces, and nothing that is not six digits', () => {
    const now = 59_000;
    expect(matchStep(RFC_SEED, '287 082', now)).toBe(stepAt(now));
    expect(matchStep(RFC_SEED, '28708', now)).toBeNull();
    expect(matchStep(RFC_SEED, 'abcdef', now)).toBeNull();
  });

  it('speaks base32 as RFC 4648 does, and builds the otpauth URI', () => {
    expect(base32(Buffer.from('foobar'))).toBe('MZXW6YTBOI');
    expect(fromBase32('mzxw 6ytb oi').toString()).toBe('foobar');
    expect(fromBase32(base32(RFC_SEED))).toEqual(RFC_SEED);
    expect(grouped('ABCDEFGHIJ')).toBe('ABCD EFGH IJ');
    const uri = new URL(otpauthUri(RFC_SEED, 'Entity', 'a@example.com'));
    expect(uri.protocol).toBe('otpauth:');
    expect(uri.host).toBe('totp');
    expect(decodeURIComponent(uri.pathname)).toBe('/Entity:a@example.com');
    expect(uri.searchParams.get('secret')).toBe(base32(RFC_SEED));
    expect(uri.searchParams.get('issuer')).toBe('Entity');
  });
});

describe('MfaKeys', () => {
  const keys = new MfaKeys();

  it('is on in the tests (vitest.config.ts sets MFA_ENCRYPTION_KEY)', () => {
    expect(keys.enabled).toBe(true);
  });

  it('seals a seed for one identity only', () => {
    const sealed = keys.seal(RFC_SEED, 'identity-a');
    expect(sealed[0]).toBe(1);
    expect(sealed.length).toBe(1 + 12 + 16 + 20);
    expect(sealed.includes(RFC_SEED)).toBe(false);
    expect(keys.open(sealed, 'identity-a')).toEqual(RFC_SEED);
    expect(() => keys.open(sealed, 'identity-b')).toThrow();
    // Every seal is fresh.
    expect(keys.seal(RFC_SEED, 'identity-a').equals(sealed)).toBe(false);
  });

  it('hashes a recovery code the same way every time, with a key', () => {
    const h = keys.hashCode('ABCDE12345');
    expect(h.length).toBe(32);
    expect(keys.hashCode('ABCDE12345').equals(h)).toBe(true);
    expect(keys.hashCode('ABCDE12346').equals(h)).toBe(false);
  });
});

describe('recovery codes', () => {
  it('makes ten different codes, shown as XXXXX-XXXXX', () => {
    const codes = newCodes();
    expect(new Set(codes).size).toBe(10);
    for (const c of codes) {
      expect(c).toMatch(/^[0-9A-HJKMNP-TV-Z]{10}$/);
      expect(shown(c)).toMatch(/^[0-9A-Z]{5}-[0-9A-Z]{5}$/);
      expect(normalise(shown(c))).toBe(c);
    }
  });

  it('forgives case, spaces, dashes and look-alike letters', () => {
    expect(normalise(' abcde-12345 ')).toBe('ABCDE12345');
    expect(normalise('ABCDE O1IL5')).toBe('ABCDE01115');
    expect(normalise('ABCDE-1234')).toBeNull();
    expect(normalise('ABCDE-1234U')).toBeNull();
  });
});
