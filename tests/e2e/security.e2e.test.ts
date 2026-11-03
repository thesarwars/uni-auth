import type { NestFastifyApplication } from '@nestjs/platform-fastify';
import { METHOD_METADATA, PATH_METADATA } from '@nestjs/common/constants';
import { RequestMethod } from '@nestjs/common';
import { readdirSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { AppModule } from '../../src/app.module';
import { startApp } from '../support/app';
import {
  APP,
  HYDRA,
  HYDRA_ADMIN,
  REDIRECT,
  authorizeUrl,
  browser,
  claims,
  exchange,
  formFields,
  pkce,
  type Browser,
} from '../support/browser';
import { closeMembers, createMember, type Member } from '../support/members';

/**
 * The protocol and page hardening part 8 asks to be proved (auth-plan.md section 12.2, part 8;
 * section 7.4): a code goes only to a redirect URI registered exactly, only with PKCE, and only
 * once; no page can be framed or leak its URL; every form and every POST carries the CSRF token.
 */

let app: NestFastifyApplication;
let member: Member;

beforeAll(async () => {
  app = await startApp();
  member = await createMember();
});

afterAll(async () => {
  await app?.close();
  await closeMembers();
});

/** Signs the member in through `url` and returns where the browser is sent at the end. */
async function signIn(b: Browser, url: string): Promise<URL> {
  let page = (await b.follow(url)).hop;
  page = await b.post(`${APP}/login`, {
    ...formFields(page.html),
    action: 'identify',
    identifier: member.email,
  });
  page = await b.post(`${APP}/login`, {
    ...formFields(page.html),
    action: 'password',
    password: member.password,
  });
  expect(page.status).toBe(303);
  return new URL((await b.follow(page.location!)).url);
}

async function token(form: Record<string, string>) {
  const res = await fetch(`${HYDRA}/oauth2/token`, {
    method: 'POST',
    headers: { 'content-type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams(form).toString(),
  });
  return { status: res.status, body: (await res.json()) as Record<string, any> };
}

describe('redirect URIs match exactly', () => {
  // Each is a near miss of a registered URI; none may receive the browser, with or without a code.
  const nearMisses: [client: string, uri: string][] = [
    ['gsn-web', 'http://localhost:5173/callback/'],
    ['gsn-web', 'http://localhost:5173/callbackx'],
    ['gsn-web', 'http://localhost:5173/callback/../evil'],
    ['gsn-web', 'http://localhost:5173/Callback'],
    ['gsn-web', 'http://localhost:5173/callback?next=https://evil.example'],
    ['gsn-web', 'http://localhost:5173/callback#x'],
    ['gsn-web', 'http://localhost:5174/callback'],
    ['gsn-web', 'http://127.0.0.1:5173/callback'],
    ['gsn-web', 'https://localhost:5173/callback'],
    ['gsn-web', 'http://localhost:5173@evil.example/callback'],
    ['gsn-web', 'https://evil.example/callback'],
    ['gsn-web', 'gostyles://auth/callback'], // gsn-mobile's, not gsn-web's
    ['gsn-mobile', 'gostyles://auth/callback/'],
    ['gsn-mobile', 'gostyles://auth/callbackx'],
    ['gsn-mobile', 'gostyles://evil/callback'],
    ['gsn-mobile', REDIRECT], // gsn-web's, not gsn-mobile's
  ];
  for (const [client, uri] of nearMisses) {
    it(`${client} never sends the browser to ${uri}`, async () => {
      const { url } = await browser().follow(
        authorizeUrl(pkce().challenge, { client_id: client, redirect_uri: uri }),
      );
      expect(url.startsWith(`${APP}/error`)).toBe(true);
    });
  }

  it('refuses a code exchanged with another redirect URI than it was issued to', async () => {
    const { verifier, challenge } = pkce();
    const back = await signIn(browser(), authorizeUrl(challenge));
    const t = await token({
      grant_type: 'authorization_code',
      client_id: 'gsn-web',
      code: back.searchParams.get('code')!,
      redirect_uri: 'http://localhost:5173/callback/',
      code_verifier: verifier,
    });
    expect(t.status).toBe(400);
    expect(t.body.error).toBe('invalid_grant');
  });

  it('never redirects after sign-out to an unregistered address', async () => {
    const back = await signIn(browser(), authorizeUrl(pkce().challenge));
    expect(back.searchParams.get('code')).toBeTruthy();
    const q = new URLSearchParams({ post_logout_redirect_uri: 'https://evil.example/' });
    const { url } = await browser().follow(`${HYDRA}/oauth2/sessions/logout?${q.toString()}`);
    expect(url.startsWith('https://evil.example')).toBe(false);
  });
});

describe('PKCE is required of public clients', () => {
  // Hydra v25 checks the challenge when it issues the code, after the sign-in: the screen is
  // shown, but the client gets an error and never a code. Only a broken client sees it.
  const noChallenge = (client: string, redirect: string) =>
    authorizeUrl('', { client_id: client, redirect_uri: redirect }).replace(
      /&code_challenge=&code_challenge_method=S256/,
      '',
    );
  const cases: [string, string, string, RegExp][] = [
    ['gsn-web', REDIRECT, noChallenge('gsn-web', REDIRECT), /must include a code_challenge/],
    [
      'gsn-mobile',
      'gostyles://auth/callback',
      noChallenge('gsn-mobile', 'gostyles://auth/callback'),
      /must include a code_challenge/,
    ],
    [
      'gsn-web',
      REDIRECT,
      authorizeUrl(pkce().verifier, { code_challenge_method: 'plain' }),
      /plain is not allowed/,
    ],
  ];
  for (const [client, redirect, url, why] of cases) {
    it(`${client}: no code without an S256 challenge (${why.source})`, async () => {
      const back = await signIn(browser(), url);
      expect(`${back.protocol}//${back.host}${back.pathname}`).toBe(redirect);
      expect(back.searchParams.get('code')).toBeNull();
      expect(back.searchParams.get('error')).toBe('invalid_request');
      expect(back.searchParams.get('error_description')).toMatch(why);
    });
  }

  it('a code is not exchanged without its verifier, or with another', async () => {
    const { verifier, challenge } = pkce();
    const code = (await signIn(browser(), authorizeUrl(challenge))).searchParams.get('code')!;
    const base = {
      grant_type: 'authorization_code',
      client_id: 'gsn-web',
      code,
      redirect_uri: REDIRECT,
    };
    for (const attempt of [base, { ...base, code_verifier: pkce().verifier }]) {
      const t = await token(attempt);
      expect(t.status).toBe(400);
      expect(t.body.error).toBe('invalid_grant');
    }
    // Hydra spends a code on a failed attempt too, so the right verifier is now too late.
    expect((await exchange(code, verifier)).status).toBe(400);
  });
});

describe('a code is spent once', () => {
  it('refuses the replay and revokes what the first exchange issued', async () => {
    const { verifier, challenge } = pkce();
    const back = await signIn(browser(), authorizeUrl(challenge));
    const code = back.searchParams.get('code')!;
    const first = await exchange(code, verifier);
    expect(first.status).toBe(200);

    const replay = await exchange(code, verifier);
    expect(replay.status).toBe(400);
    expect(replay.body.error).toBe('invalid_grant');

    const refreshed = await token({
      grant_type: 'refresh_token',
      client_id: 'gsn-web',
      refresh_token: first.body.refresh_token,
    });
    expect(refreshed.status).not.toBe(200);
    const introspected = await fetch(`${HYDRA_ADMIN}/admin/oauth2/introspect`, {
      method: 'POST',
      headers: { 'content-type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({ token: first.body.access_token }).toString(),
    });
    expect(((await introspected.json()) as { active: boolean }).active).toBe(false);
    expect(claims(first.body.access_token).client_id).toBe('gsn-web');
  });

  it('echoes the state the client sent', async () => {
    const back = await signIn(browser(), authorizeUrl(pkce().challenge, { state: 'abc-123_XYZ' }));
    expect(back.searchParams.get('state')).toBe('abc-123_XYZ');
  });
});

describe('every page refuses framing and keeps its URL to itself', () => {
  const pages: [string, () => Promise<Headers>][] = [
    [
      'the sign-in screen',
      async () => (await browser().follow(authorizeUrl(pkce().challenge))).hop.headers,
    ],
    [
      'the expired page',
      async () => (await browser().get(`${APP}/login?login_challenge=nope`)).headers,
    ],
    [
      'the error page',
      async () => (await browser().get(`${APP}/error?error=invalid_request`)).headers,
    ],
    ['the signed-out page', async () => (await browser().get(`${APP}/signed-out`)).headers],
    [
      'an unknown sign-out',
      async () => (await browser().get(`${APP}/logout?logout_challenge=nope`)).headers,
    ],
    ['a refused POST', async () => (await browser().post(`${APP}/login`, {})).headers],
    [
      'a page that does not exist',
      async () => (await browser().get(`${APP}/nothing-here`)).headers,
    ],
  ];
  for (const [name, get] of pages) {
    it(name, async () => {
      const h = await get();
      expect(h.get('content-security-policy')).toContain("frame-ancestors 'none'");
      // Scripts from this origin only: public/password.js. No inline script, no other origin.
      expect(h.get('content-security-policy')).toContain("script-src 'self'");
      expect(h.get('content-security-policy')).not.toMatch(/script-src[^;]*(unsafe|https?:|\*)/);
      expect(h.get('x-frame-options')).toBe('DENY');
      expect(h.get('referrer-policy')).toBe('no-referrer');
      expect(h.get('x-content-type-options')).toBe('nosniff');
    });
  }
});

describe('the only script is our own file', () => {
  const views = join(__dirname, '..', '..', 'views');
  it('no view holds an inline script, an event handler attribute or another script', () => {
    const scripts: string[] = [];
    for (const file of readdirSync(views).filter((f) => f.endsWith('.eta'))) {
      const source = readFileSync(join(views, file), 'utf8');
      expect(source, file).not.toMatch(/\son[a-z]+\s*=/i);
      expect(source, file).not.toMatch(/javascript:/i);
      for (const [tag] of source.matchAll(/<script\b[^>]*>/g)) scripts.push(`${file}: ${tag}`);
    }
    expect(scripts).toEqual(['layout.eta: <script src="/assets/password.js" defer>']);
  });

  it('serves it as JavaScript, with nosniff', async () => {
    const res = await fetch(`${APP}/assets/password.js`);
    expect(res.status).toBe(200);
    expect(res.headers.get('content-type')).toMatch(/^text\/javascript/);
    expect(res.headers.get('x-content-type-options')).toBe('nosniff');
    expect(await res.text()).toContain("'use strict'");
  });
});

describe('every form carries the CSRF token', () => {
  const views = join(__dirname, '..', '..', 'views');
  const hidden = readFileSync(join(views, '_hidden.eta'), 'utf8');

  for (const file of readdirSync(views).filter((f) => f.endsWith('.eta'))) {
    const source = readFileSync(join(views, file), 'utf8');
    const forms = [...source.matchAll(/<form\b[^>]*>([\s\S]*?)<\/form>/g)];
    if (!forms.length) continue;
    it(`views/${file}`, () => {
      for (const [whole, body] of forms) {
        expect(whole).toMatch(/method="post"/);
        const own = /name="_csrf" value="<%= it\.csrfToken %>"/.test(body!);
        const included = /include\('\.\/_hidden'/.test(body!) && hidden.includes('name="_csrf"');
        expect(own || included).toBe(true);
      }
    });
  }
});

describe('every POST is checked for the CSRF token', () => {
  const CROSS_SITE = 'uni-auth:cross-site';
  // Posted by another party, and authenticated another way: Apple's form_post spends a one-time
  // state bound to this browser by a signed cookie; Hydra's refresh hook carries a shared secret.
  const crossSite = ['/upstream/apple/callback', '/hooks/refresh'];

  const posts: { path: string; crossSite: boolean }[] = [];
  for (const controller of Reflect.getMetadata('controllers', AppModule) as (new (
    ...args: never[]
  ) => object)[]) {
    const base = String(Reflect.getMetadata(PATH_METADATA, controller) ?? '');
    for (const name of Object.getOwnPropertyNames(controller.prototype)) {
      const handler = (controller.prototype as Record<string, object>)[name]!;
      if (Reflect.getMetadata(METHOD_METADATA, handler) !== RequestMethod.POST) continue;
      const path = `/${[base, Reflect.getMetadata(PATH_METADATA, handler)]
        .map((p) => String(p ?? '').replace(/^\/|\/$/g, ''))
        .filter(Boolean)
        .join('/')}`;
      posts.push({ path, crossSite: Reflect.getMetadata(CROSS_SITE, handler) === true });
    }
  }

  it('exempts only the routes another party posts to', () => {
    expect(
      posts
        .filter((p) => p.crossSite)
        .map((p) => p.path)
        .sort(),
    ).toEqual([...crossSite].sort());
    expect(posts.filter((p) => !p.crossSite).length).toBeGreaterThan(0);
  });

  it('refuses every other POST without the token', async () => {
    for (const { path } of posts.filter((p) => !p.crossSite)) {
      const res = await browser().post(`${APP}${path}`, { action: 'identify' });
      expect({ path, status: res.status }).toEqual({ path, status: 403 });
      expect(res.html).toContain('This page has expired');
    }
  });
});
