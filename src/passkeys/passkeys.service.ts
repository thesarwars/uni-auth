import { Injectable } from '@nestjs/common';
import {
  generateAuthenticationOptions,
  generateRegistrationOptions,
  verifyAuthenticationResponse,
  verifyRegistrationResponse,
} from '@simplewebauthn/server';
import { createHash } from 'node:crypto';
import { z } from 'zod';
import { describeDevice } from '../account/device';
import { env } from '../config/env';
import { IdentityRepository } from '../identity/identity.repository';
import { RedisService } from '../redis/redis.service';

/**
 * Passkeys (account-plan.md part 5; AC-D5): WebAuthn registration and sign-in, through
 * @simplewebauthn/server. The relying party is this application's own origin
 * (LOGIN_PUBLIC_URL): a passkey made here works on this host and nowhere else.
 *
 * Each ceremony's challenge is held in Redis under the flow it belongs to - a login challenge,
 * or an account session - and spent on first use, so a response can't be replayed.
 */

/** How long a page may wait for the member to use their passkey. */
const CHALLENGE_TTL = 10 * 60;
const TIMEOUT_MS = 5 * 60 * 1000;

const TRANSPORTS = new Set(['usb', 'nfc', 'ble', 'internal', 'hybrid', 'smart-card', 'cable']);

/**
 * What the browser posts back (webauthn.js): PublicKeyCredential, as JSON. Bounded here; the
 * library checks every field's meaning.
 */
const b64 = z
  .string()
  .regex(/^[A-Za-z0-9_-]*$/)
  .max(16_000);
const Assertion = z.object({
  id: b64,
  rawId: b64,
  type: z.literal('public-key'),
  response: z.object({
    clientDataJSON: b64,
    authenticatorData: b64,
    signature: b64,
    userHandle: b64.optional(),
  }),
  clientExtensionResults: z.record(z.string(), z.unknown()).default({}),
  authenticatorAttachment: z.enum(['platform', 'cross-platform']).optional(),
});
const Attestation = z.object({
  id: b64,
  rawId: b64,
  type: z.literal('public-key'),
  response: z.object({
    clientDataJSON: b64,
    attestationObject: b64,
    transports: z.array(z.string().max(20)).max(8).optional(),
  }),
  clientExtensionResults: z.record(z.string(), z.unknown()).default({}),
  authenticatorAttachment: z.enum(['platform', 'cross-platform']).optional(),
});

/** A passkey that signed someone in. */
export interface PasskeyUsed {
  credentialId: string;
  identityId: string;
  /** RFC 8176: `swk` for a passkey that syncs between devices, `hwk` for one bound to hardware. */
  method: 'swk' | 'hwk';
  userVerified: boolean;
}

export type PasskeyRefusal =
  /** Malformed, unknown, expired or not this flow's: nothing to blame on the member. */
  | { reason: 'invalid' }
  /** A real passkey, refused: wrong account, no user verification, or a cloned key. */
  | { reason: 'refused'; identityId: string; credentialId: string; why: string }
  | { reason: 'suspended'; identityId: string };

/** A passkey just made, ready to store. */
export interface NewPasskey {
  webauthnId: Buffer;
  publicKey: Buffer;
  signCount: number;
  transports: string[];
  aaguid: string;
  backupEligible: boolean;
  backupState: boolean;
  nickname: string;
}

@Injectable()
export class Passkeys {
  constructor(
    private readonly identities: IdentityRepository,
    private readonly redis: RedisService,
  ) {}

  /**
   * Options for navigator.credentials.get. With no `identityId`, any passkey for this site
   * (the identifier screen, and the browser's autofill); with one, only that identity's (the
   * second step).
   */
  async signInOptions(flow: string, identityId?: string): Promise<unknown> {
    const allow = identityId ? await this.identities.passkeys(identityId) : [];
    const options = await generateAuthenticationOptions({
      rpID: rpId(),
      userVerification: identityId ? 'preferred' : 'required',
      timeout: TIMEOUT_MS,
      allowCredentials: allow.map((p) => ({
        id: p.webauthnId.toString('base64url'),
        transports: p.transports,
      })),
    });
    await this.hold(flow, options.challenge);
    return options;
  }

  /**
   * Checks a passkey sign-in. `identityId`, when given, is who it must belong to. A first
   * factor needs user verification (a fingerprint, face or PIN): that is what makes it two
   * factors on its own (AC-D5).
   */
  async verifySignIn(
    flow: string,
    raw: string,
    expect: { identityId?: string; requireUserVerification: boolean },
  ): Promise<PasskeyUsed | PasskeyRefusal> {
    const response = parseJson(Assertion, raw);
    if (!response) return { reason: 'invalid' };
    const challenge = challengeOf(response.response.clientDataJSON);
    if (!challenge || !(await this.spend(flow, challenge))) return { reason: 'invalid' };

    const stored = await this.identities.passkeyByWebauthnId(
      Buffer.from(response.rawId, 'base64url'),
    );
    if (!stored) return { reason: 'invalid' };
    const refuse = (why: string): PasskeyRefusal => ({
      reason: 'refused',
      identityId: stored.identityId,
      credentialId: stored.id,
      why,
    });
    if (expect.identityId && stored.identityId !== expect.identityId)
      return refuse('wrong_account');
    if (
      response.response.userHandle &&
      response.response.userHandle !== userHandle(stored.identityId).toString('base64url')
    ) {
      return refuse('user_handle');
    }
    if (stored.status === 'suspended')
      return { reason: 'suspended', identityId: stored.identityId };

    let result;
    try {
      result = await verifyAuthenticationResponse({
        response: response,
        expectedChallenge: challenge,
        expectedOrigin: origin(),
        expectedRPID: rpId(),
        requireUserVerification: expect.requireUserVerification,
        credential: {
          id: response.rawId,
          publicKey: new Uint8Array(stored.publicKey),
          counter: stored.signCount,
          transports: stored.transports,
        },
      });
    } catch (err) {
      // A counter that went back is a copy of the key (AC-4): journalled as such.
      return refuse(/counter/i.test((err as Error).message) ? 'sign_count' : 'signature');
    }
    if (!result.verified) return refuse('signature');
    const info = result.authenticationInfo;
    const spent = await this.identities.usePasskey(
      stored.id,
      info.newCounter,
      info.credentialBackedUp,
    );
    if (!spent) return refuse('sign_count');
    return {
      credentialId: stored.id,
      identityId: stored.identityId,
      method: stored.backupEligible ? 'swk' : 'hwk',
      userVerified: info.userVerified,
    };
  }

  /** Options for navigator.credentials.create: a discoverable passkey, verified by the member. */
  async addOptions(flow: string, identityId: string): Promise<unknown> {
    const [existing, who, profile] = await Promise.all([
      this.identities.passkeys(identityId),
      this.identities.primaryIdentifier(identityId),
      this.identities.profile(identityId),
    ]);
    const name = who?.value ?? identityId;
    const options = await generateRegistrationOptions({
      rpName: env.PROVIDER_NAME,
      rpID: rpId(),
      userID: new Uint8Array(userHandle(identityId)),
      userName: name,
      userDisplayName: profile?.displayName || name,
      timeout: TIMEOUT_MS,
      attestationType: 'none',
      excludeCredentials: existing.map((p) => ({
        id: p.webauthnId.toString('base64url'),
        transports: p.transports,
      })),
      authenticatorSelection: { residentKey: 'required', userVerification: 'required' },
    });
    await this.hold(flow, options.challenge);
    return options;
  }

  /** Checks a new passkey; null when it isn't one this flow asked for. */
  async verifyAdd(flow: string, raw: string, userAgent: string | null): Promise<NewPasskey | null> {
    const response = parseJson(Attestation, raw);
    if (!response) return null;
    const challenge = challengeOf(response.response.clientDataJSON);
    if (!challenge || !(await this.spend(flow, challenge))) return null;
    let result;
    try {
      result = await verifyRegistrationResponse({
        response: response,
        expectedChallenge: challenge,
        expectedOrigin: origin(),
        expectedRPID: rpId(),
        requireUserVerification: true,
      });
    } catch {
      return null;
    }
    if (!result.verified) return null;
    const info = result.registrationInfo;
    const transports = (info.credential.transports ?? []).filter((t) => TRANSPORTS.has(t));
    return {
      webauthnId: Buffer.from(info.credential.id, 'base64url'),
      publicKey: Buffer.from(info.credential.publicKey),
      signCount: info.credential.counter,
      transports,
      aaguid: info.aaguid,
      backupEligible: info.credentialDeviceType === 'multiDevice',
      backupState: info.credentialBackedUp,
      nickname: nicknameFor(info.aaguid, transports, userAgent),
    };
  }

  private async hold(flow: string, challenge: string): Promise<void> {
    await this.redis.client.set(key(flow, challenge), '1', 'EX', CHALLENGE_TTL);
  }

  private async spend(flow: string, challenge: string): Promise<boolean> {
    return (await this.redis.client.getdel(key(flow, challenge))) === '1';
  }
}

export const rpId = (): string => new URL(env.LOGIN_PUBLIC_URL).hostname;
const origin = (): string => new URL(env.LOGIN_PUBLIC_URL).origin;

/** The WebAuthn user handle: the identity's id, as its 16 bytes. Opaque, and never an address. */
export const userHandle = (identityId: string): Buffer =>
  Buffer.from(identityId.replace(/-/g, ''), 'hex');

const key = (flow: string, challenge: string): string =>
  `uni-auth:passkey:${createHash('sha256').update(`${flow}\n${challenge}`).digest('hex')}`;

function parseJson<T>(schema: z.ZodType<T>, raw: string): T | null {
  try {
    const r = schema.safeParse(JSON.parse(raw));
    return r.success ? r.data : null;
  } catch {
    return null;
  }
}

function challengeOf(clientDataJSON: string): string | null {
  try {
    const c = JSON.parse(Buffer.from(clientDataJSON, 'base64url').toString('utf8')) as {
      challenge?: unknown;
    };
    return typeof c.challenge === 'string' && c.challenge.length <= 200 ? c.challenge : null;
  } catch {
    return null;
  }
}

/**
 * The password managers that say who they are (their AAGUID), by the name a member knows. Any
 * other passkey is named after the device it was made on; the member can rename it.
 */
const PROVIDERS: Record<string, string> = {
  'fbfc3007-154e-4ecc-8c0b-6e020557d7bd': 'iCloud Keychain',
  'ea9b8d66-4d01-1d21-3ce4-b6b48cb575d4': 'Google Password Manager',
  'bada5566-a7aa-401f-bd96-45619a55120d': '1Password',
  'd548826e-79b4-db40-a3d8-11116f7e8349': 'Bitwarden',
  '08987058-cadc-4b81-b6e1-30de50dcbe96': 'Windows Hello',
  '9ddd1817-af5a-4672-a2b9-3e3dd95000a9': 'Windows Hello',
  '6028b017-b1d4-4c02-b4b3-afcdafc96bb2': 'Windows Hello',
};

export function nicknameFor(
  aaguid: string,
  transports: string[],
  userAgent: string | null,
): string {
  const known = PROVIDERS[aaguid];
  if (known) return known;
  if (transports.length && transports.every((t) => t === 'usb' || t === 'nfc' || t === 'ble')) {
    return 'Security key';
  }
  const device = describeDevice(userAgent).name;
  return device === 'Unknown device' ? 'Passkey' : device;
}
