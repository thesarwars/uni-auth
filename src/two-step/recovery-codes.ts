import { randomInt } from 'node:crypto';

/**
 * Recovery codes: ten per set, each ten characters from Crockford's base32 (no I, L, O or U),
 * about 50 bits each, shown as XXXXX-XXXXX. Typing is forgiving: case, spaces and dashes don't
 * matter, and O, I and L read as 0, 1 and 1.
 */

export const CODES_PER_SET = 10;
const ALPHABET = '0123456789ABCDEFGHJKMNPQRSTVWXYZ';
const LENGTH = 10;

export function newCodes(): string[] {
  const codes = new Set<string>();
  while (codes.size < CODES_PER_SET) {
    let c = '';
    for (let i = 0; i < LENGTH; i++) c += ALPHABET[randomInt(ALPHABET.length)];
    codes.add(c);
  }
  return [...codes];
}

/** XXXXX-XXXXX, as shown and saved. */
export const shown = (code: string): string => `${code.slice(0, 5)}-${code.slice(5)}`;

/** What a typed code is compared as; null when it can't be a recovery code at all. */
export function normalise(typed: string): string | null {
  const c = typed.toUpperCase().replace(/[\s-]/g, '').replace(/O/g, '0').replace(/[IL]/g, '1');
  if (c.length !== LENGTH) return null;
  for (const ch of c) if (!ALPHABET.includes(ch)) return null;
  return c;
}
