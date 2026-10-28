import { createHash, randomBytes } from 'node:crypto';

/**
 * A browser for the e2e suite: a cookie jar, redirects followed one hop at a time, and HTML
 * forms read back out of the page - so a test can watch every step a member's browser takes.
 */

export const HYDRA = 'http://localhost:4444';
export const HYDRA_ADMIN = 'http://127.0.0.1:4445';
export const APP = 'http://localhost:3100';
export const REDIRECT = 'http://localhost:5173/callback';

export interface Hop {
  status: number;
  location: string | null;
  html: string;
  headers: Headers;
}

export function browser() {
  const jar = new Map<string, string>();

  async function request(url: string, init: RequestInit = {}): Promise<Hop> {
    const res = await fetch(url, {
      ...init,
      redirect: 'manual',
      headers: {
        ...(init.headers ?? {}),
        cookie: [...jar].map(([k, v]) => `${k}=${v}`).join('; '),
      },
    });
    for (const c of res.headers.getSetCookie()) {
      const [pair = ''] = c.split(';');
      const i = pair.indexOf('=');
      jar.set(pair.slice(0, i), pair.slice(i + 1));
    }
    const location = res.headers.get('location');
    return {
      status: res.status,
      location: location ? new URL(location, url).toString() : null,
      html: await res.text(),
      headers: res.headers,
    };
  }

  return {
    get: (url: string) => request(url),
    post: (url: string, form: Record<string, string>) =>
      request(url, {
        method: 'POST',
        headers: { 'content-type': 'application/x-www-form-urlencoded' },
        body: new URLSearchParams(form).toString(),
      }),
    /** Follows redirects from `url` until one lands outside Hydra and this app, or on a page. */
    async follow(url: string): Promise<{ url: string; hop: Hop }> {
      let current = url;
      for (let i = 0; i < 12; i++) {
        const hop = await request(current);
        if (!hop.location) return { url: current, hop };
        const next = hop.location;
        if (!next.startsWith(HYDRA) && !next.startsWith(APP)) return { url: next, hop };
        current = next;
      }
      throw new Error('too many redirects');
    },
  };
}

export type Browser = ReturnType<typeof browser>;

/** The hidden inputs of the page's form, as a POST body. */
export function formFields(html: string): Record<string, string> {
  const fields: Record<string, string> = {};
  for (const m of html.matchAll(/<input type="hidden" name="([^"]+)" value="([^"]*)">/g)) {
    fields[m[1]!] = decode(m[2]!);
  }
  return fields;
}

const decode = (s: string) =>
  s
    .replace(/&quot;/g, '"')
    .replace(/&#39;/g, "'")
    .replace(/&lt;/g, '<')
    .replace(/&gt;/g, '>')
    .replace(/&amp;/g, '&');

export const b64url = (buf: Buffer) => buf.toString('base64url');

export function pkce(): { verifier: string; challenge: string } {
  const verifier = b64url(randomBytes(32));
  return { verifier, challenge: b64url(createHash('sha256').update(verifier).digest()) };
}

export function authorizeUrl(challenge: string, overrides: Record<string, string> = {}): string {
  return `${HYDRA}/oauth2/auth?${new URLSearchParams({
    client_id: 'gsn-web',
    response_type: 'code',
    redirect_uri: REDIRECT,
    scope: 'openid offline_access',
    audience: 'gsn-api',
    state: b64url(randomBytes(16)),
    code_challenge: challenge,
    code_challenge_method: 'S256',
    ...overrides,
  }).toString()}`;
}

export async function exchange(
  code: string,
  verifier: string,
  clientId = 'gsn-web',
): Promise<{ status: number; body: Record<string, any> }> {
  const res = await fetch(`${HYDRA}/oauth2/token`, {
    method: 'POST',
    headers: { 'content-type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({
      grant_type: 'authorization_code',
      client_id: clientId,
      code,
      redirect_uri: REDIRECT,
      code_verifier: verifier,
    }).toString(),
  });
  return { status: res.status, body: (await res.json()) as Record<string, any> };
}

export const claims = (jwt: string): Record<string, any> =>
  JSON.parse(Buffer.from(jwt.split('.')[1]!, 'base64url').toString()) as Record<string, any>;
