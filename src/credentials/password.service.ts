import { Injectable } from '@nestjs/common';
import { randomBytes, scrypt as scryptCb, timingSafeEqual, type ScryptOptions } from 'node:crypto';
import { one, type Db } from '../db/database.service';

const scrypt = (pw: string, salt: Buffer, len: number, opts: ScryptOptions): Promise<Buffer> =>
  new Promise((resolve, reject) =>
    scryptCb(pw, salt, len, opts, (err, key) => (err ? reject(err) : resolve(key))),
  );

const N = 16384;
const R = 8;
const P = 1;
const KEY_LEN = 64;

export interface PasswordPolicy {
  id: string;
  min_length: number;
  require_uppercase: boolean;
  require_digit_or_symbol: boolean;
}

export interface PolicyRule {
  rule: 'min_length' | 'uppercase' | 'digit_or_symbol';
  label: string;
  met: boolean;
}

/**
 * Passwords are hashed here; the database never sees a plaintext, and its CHECK refuses
 * anything that is not this format. The stored secret is self-describing -
 * "scrypt$N$r$p$salt$hash" - so the parameters can be raised without invalidating the hashes
 * already written. Carried over from the GSN API unchanged in behaviour.
 */
@Injectable()
export class PasswordService {
  async hash(password: string): Promise<Buffer> {
    const salt = randomBytes(16);
    const key = await scrypt(password, salt, KEY_LEN, { N, r: R, p: P });
    return Buffer.from(
      `scrypt$${N}$${R}$${P}$${salt.toString('base64')}$${key.toString('base64')}`,
      'utf8',
    );
  }

  async verify(password: string, stored: Buffer | null): Promise<boolean> {
    if (!stored) {
      // Same work as a real check, so an identifier with no password does not answer faster.
      await this.hash(password);
      return false;
    }
    const [scheme, n, r, p, salt, key] = stored.toString('utf8').split('$');
    if (scheme !== 'scrypt' || !salt || !key) return false;
    const expected = Buffer.from(key, 'base64');
    const actual = await scrypt(password, Buffer.from(salt, 'base64'), expected.length, {
      N: Number(n),
      r: Number(r),
      p: Number(p),
      maxmem: 256 * Number(n) * Number(r),
    });
    return timingSafeEqual(actual, expected);
  }

  async policyInEffect(db: Db): Promise<PasswordPolicy> {
    const policy = await one<PasswordPolicy>(
      db,
      `SELECT id, min_length, require_uppercase, require_digit_or_symbol
         FROM password_policy WHERE id = password_policy_in_effect()`,
    );
    if (!policy) throw new Error('No password_policy is in effect');
    return policy;
  }
}

/** The checklist the screens render, evaluated against one password. */
export function checkPassword(policy: PasswordPolicy, password: string): PolicyRule[] {
  const rules: PolicyRule[] = [
    {
      rule: 'min_length',
      label: `At least ${policy.min_length} characters`,
      met: [...password].length >= policy.min_length,
    },
  ];
  if (policy.require_uppercase) {
    rules.push({ rule: 'uppercase', label: 'One uppercase letter', met: /\p{Lu}/u.test(password) });
  }
  if (policy.require_digit_or_symbol) {
    rules.push({
      rule: 'digit_or_symbol',
      label: 'One number or symbol',
      met: /[^\p{L}\s]/u.test(password),
    });
  }
  return rules;
}
