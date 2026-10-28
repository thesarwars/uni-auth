// Verifies a JWT against a JWKS using only node:crypto. Prints the header and claims as JSON.
// usage: node verify-jwt.mjs <jwt> <jwks-url>
import { createPublicKey, verify } from 'node:crypto';

const [token, jwksUrl] = process.argv.slice(2);
const [h, p, s] = token.split('.');
const header = JSON.parse(Buffer.from(h, 'base64url'));
const claims = JSON.parse(Buffer.from(p, 'base64url'));
const { keys } = await (await fetch(jwksUrl)).json();
const jwk = keys.find((k) => k.kid === header.kid);
if (!jwk) throw new Error(`kid ${header.kid} is not in the JWKS`);
if (header.alg !== 'ES256' || jwk.alg !== 'ES256') throw new Error(`alg ${header.alg}, expected ES256`);
const ok = verify('sha256', Buffer.from(`${h}.${p}`), { key: createPublicKey({ key: jwk, format: 'jwk' }), dsaEncoding: 'ieee-p1363' }, Buffer.from(s, 'base64url'));
if (!ok) throw new Error('signature does not verify');
console.log(JSON.stringify({ header, claims }));
