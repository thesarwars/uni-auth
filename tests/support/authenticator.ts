import { isoCBOR } from '@simplewebauthn/server/helpers';
import { createHash, generateKeyPairSync, randomBytes, sign, type KeyObject } from 'node:crypto';
import { APP } from './browser';

/**
 * A passkey authenticator in software, for the tests: an ES256 key pair, answering the options
 * the server sends with what a browser would post back (public/webauthn.js), signed for real.
 * `synced` makes it a passkey that syncs (backup eligible and backed up), as a password manager
 * would; `counter` starts it counting, as a hardware key does (synced passkeys report 0).
 */
export class Authenticator {
  readonly credentialId = randomBytes(32);
  private readonly key: KeyObject;
  private readonly cose: Buffer;
  private userHandle: string | null = null;
  counter: number;

  constructor(private readonly opts: { synced?: boolean; counter?: number; aaguid?: string } = {}) {
    const { privateKey, publicKey } = generateKeyPairSync('ec', { namedCurve: 'P-256' });
    this.key = privateKey;
    const jwk = publicKey.export({ format: 'jwk' });
    this.cose = Buffer.from(
      isoCBOR.encode(
        new Map<number, number | Uint8Array>([
          [1, 2], // kty: EC2
          [3, -7], // alg: ES256
          [-1, 1], // crv: P-256
          [-2, Buffer.from(jwk.x!, 'base64url')],
          [-3, Buffer.from(jwk.y!, 'base64url')],
        ]),
      ),
    );
    this.counter = opts.counter ?? 0;
  }

  /** The answer to navigator.credentials.create, as webauthn.js posts it. */
  create(options: any, origin = APP): string {
    this.userHandle = options.user.id;
    const clientData = this.clientData('webauthn.create', options.challenge, origin);
    const aaguid = Buffer.from(
      (this.opts.aaguid ?? '00000000-0000-0000-0000-000000000000').replace(/-/g, ''),
      'hex',
    );
    const length = Buffer.alloc(2);
    length.writeUInt16BE(this.credentialId.length);
    const authData = Buffer.concat([
      this.header(options.rp.id, 0x40),
      aaguid,
      length,
      this.credentialId,
      this.cose,
    ]);
    const attestationObject = Buffer.from(
      isoCBOR.encode(
        new Map<string, unknown>([
          ['fmt', 'none'],
          ['attStmt', new Map()],
          ['authData', authData],
        ]) as never,
      ),
    );
    return JSON.stringify({
      id: this.credentialId.toString('base64url'),
      rawId: this.credentialId.toString('base64url'),
      type: 'public-key',
      clientExtensionResults: {},
      authenticatorAttachment: 'platform',
      response: {
        clientDataJSON: clientData.toString('base64url'),
        attestationObject: attestationObject.toString('base64url'),
        transports: ['internal', 'hybrid'],
      },
    });
  }

  /** The answer to navigator.credentials.get. `uv: false` is a tap with no fingerprint or PIN. */
  get(
    options: any,
    o: { origin?: string; uv?: boolean; rpId?: string; withHandle?: boolean } = {},
  ): string {
    const clientData = this.clientData('webauthn.get', options.challenge, o.origin ?? APP);
    if (this.opts.counter !== undefined) this.counter += 1;
    const authData = this.header(o.rpId ?? options.rpId, 0, o.uv ?? true);
    const signature = sign(
      'sha256',
      Buffer.concat([authData, createHash('sha256').update(clientData).digest()]),
      this.key,
    );
    return JSON.stringify({
      id: this.credentialId.toString('base64url'),
      rawId: this.credentialId.toString('base64url'),
      type: 'public-key',
      clientExtensionResults: {},
      authenticatorAttachment: 'platform',
      response: {
        clientDataJSON: clientData.toString('base64url'),
        authenticatorData: authData.toString('base64url'),
        signature: signature.toString('base64url'),
        ...(o.withHandle !== false && this.userHandle ? { userHandle: this.userHandle } : {}),
      },
    });
  }

  private clientData(type: string, challenge: string, origin: string): Buffer {
    return Buffer.from(JSON.stringify({ type, challenge, origin, crossOrigin: false }));
  }

  /** rpIdHash, flags (UP, UV, BE, BS plus `extra`), and the signature counter. */
  private header(rpId: string, extra: number, uv = true): Buffer {
    const synced = this.opts.synced ?? true;
    const flags = 0x01 | (uv ? 0x04 : 0) | (synced ? 0x08 | 0x10 : 0) | extra;
    const count = Buffer.alloc(4);
    count.writeUInt32BE(this.counter);
    return Buffer.concat([createHash('sha256').update(rpId).digest(), Buffer.from([flags]), count]);
  }
}
