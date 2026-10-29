import { createHash } from 'node:crypto';

export type Identifier = { kind: 'email'; value: string } | { kind: 'phone'; value: string };

const EMAIL = /^[^@\s]+@[^@\s]+\.[^@\s]+$/;
const E164 = /^\+[1-9][0-9]{6,14}$/;

/**
 * What the member typed on the identifier screen, as the schema stores it: an email in lower
 * case, or a phone number in E.164. Spaces, dashes, dots and brackets are dropped from a phone
 * number; it must carry its country code, because there is no country to assume.
 */
export function parseIdentifier(raw: string): Identifier | null {
  const typed = raw.trim();
  if (typed.includes('@')) {
    const value = typed.toLowerCase();
    return EMAIL.test(value) && value.length <= 320 ? { kind: 'email', value } : null;
  }
  const value = typed.replace(/[\s\-.()]/g, '').replace(/^00/, '+');
  return E164.test(value) ? { kind: 'phone', value } : null;
}

/** The journal's identifier_hash: ties attempts at one address together without storing it. */
export function identifierHash(id: Identifier): Buffer {
  return createHash('sha256').update(id.value).digest();
}

/** "•••• 4821" for a phone, "a•••@example.com" for an email: enough to recognise, no more. */
export function masked(id: Identifier): string {
  if (id.kind === 'phone') return `•••• ${id.value.slice(-4)}`;
  const [local = '', domain = ''] = id.value.split('@');
  return `${local.slice(0, 1)}•••@${domain}`;
}
