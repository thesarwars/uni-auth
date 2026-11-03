import type { NestFastifyApplication } from '@nestjs/platform-fastify';
import axe from 'axe-core';
import { JSDOM } from 'jsdom';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { Outbox } from '../../src/delivery/outbox';
import { startApp } from '../support/app';
import { APP, HYDRA, authorizeUrl, browser, formFields, pkce, type Hop } from '../support/browser';
import { closeMembers, createMember, type Member } from '../support/members';

/**
 * The WCAG 2.2 AA pass (auth-plan.md section 12.2, part 8; NFR-6): every screen, as the server
 * renders it on the way through a real sign-in, run through axe-core's WCAG 2.0-2.2 A and AA
 * rules. jsdom lays nothing out, so axe cannot measure colour contrast here; the colour tokens
 * are checked directly instead, in both colour schemes.
 */

let app: NestFastifyApplication;
let outbox: Outbox;
let member: Member;
const screens = new Map<string, string>();

async function audit(html: string) {
  const dom = new JSDOM(html, { url: APP, runScripts: 'outside-only' });
  const { window } = dom;
  window.eval(axe.source);
  const run = (window as unknown as { axe: typeof axe }).axe.run(window.document, {
    runOnly: { type: 'tag', values: ['wcag2a', 'wcag2aa', 'wcag21a', 'wcag21aa', 'wcag22aa'] },
    rules: { 'color-contrast': { enabled: false } },
  });
  const result = await run;
  window.close();
  return result.violations.map(
    (v) => `${v.id}: ${v.nodes.map((n) => n.target.join(' ')).join(', ')}`,
  );
}

beforeAll(async () => {
  app = await startApp();
  outbox = app.get(Outbox);
  member = await createMember();

  // Walk the flows once, keeping each screen as it was rendered.
  const keep = (name: string, hop: Hop) => {
    expect(hop.status, name).toBeLessThan(500);
    screens.set(name, hop.html);
    return hop;
  };
  const start = async () => {
    const b = browser();
    return { b, page: (await b.follow(authorizeUrl(pkce().challenge))).hop };
  };
  const post = (b: ReturnType<typeof browser>, page: Hop, f: Record<string, string>) =>
    b.post(`${APP}/login`, { ...formFields(page.html), ...f });

  let { b, page } = await start();
  keep('identifier', page);
  keep('identifier, refused', await post(b, page, { action: 'identify', identifier: 'x' }));
  page = keep('password', await post(b, page, { action: 'identify', identifier: member.email }));
  keep('password, wrong', await post(b, page, { action: 'password', password: 'Not-It-123' }));
  page = keep('code', await post(b, page, { action: 'send_code', purpose: 'recovery' }));
  const otp = { otp_id: /name="otp_id" value="([^"]+)"/.exec(page.html)![1]! };
  keep('code, wrong', await post(b, page, { action: 'verify_code', ...otp, code: '000000' }));
  page = keep(
    'new password',
    await post(b, page, { action: 'verify_code', ...otp, code: outbox.last(member.email)!.code }),
  );
  keep(
    'new password, refused',
    await post(b, page, { action: 'new_password', password: 'weak', confirm: 'other' }),
  );

  ({ b, page } = await start());
  page = await post(b, page, {
    action: 'identify',
    identifier: `new-${Date.now()}@example.com`,
  });
  keep('sign-up', page);
  keep(
    'sign-up, refused',
    await post(b, page, { action: 'signup', password: 'weak', confirm: 'weak' }),
  );

  const locked = await createMember();
  ({ b, page } = await start());
  page = await post(b, page, { action: 'identify', identifier: locked.email });
  let last = page;
  for (let i = 0; i < 5; i += 1) {
    last = await post(b, page, { action: 'password', password: `Wrong-Password-${i}` });
  }
  keep('lockout', last);

  ({ b, page } = await start());
  page = await post(b, page, { action: 'identify', identifier: member.email });
  page = await post(b, page, { action: 'password', password: member.password });
  await b.follow(page.location!);
  const logout = keep('sign-out', (await b.follow(`${HYDRA}/oauth2/sessions/logout`)).hop);
  keep(
    'still signed in',
    await b.post(`${APP}/logout`, { ...formFields(logout.html), action: 'cancel' }),
  );
  keep('signed out', await browser().get(`${APP}/signed-out`));
  keep('error', await browser().get(`${APP}/error?error=invalid_request`));
  keep('expired', await browser().get(`${APP}/login?login_challenge=nope`));
}, 120_000);

afterAll(async () => {
  await app?.close();
  await closeMembers();
});

describe('every screen passes axe-core (WCAG 2.2 A and AA)', () => {
  const names = [
    'identifier',
    'identifier, refused',
    'password',
    'password, wrong',
    'code',
    'code, wrong',
    'new password',
    'new password, refused',
    'sign-up',
    'sign-up, refused',
    'lockout',
    'sign-out',
    'still signed in',
    'signed out',
    'error',
    'expired',
  ];
  for (const name of names) {
    it(name, async () => {
      const html = screens.get(name);
      expect(html, `${name} was not reached`).toBeTruthy();
      expect(await audit(html!)).toEqual([]);
    });
  }

  it('the audit itself catches a broken page', async () => {
    const found = await audit(
      '<!doctype html><html><body><input type="text"><img src="x"></body></html>',
    );
    expect(found.map((v) => v.split(':')[0])).toEqual(
      expect.arrayContaining(['html-has-lang', 'document-title', 'label', 'image-alt']),
    );
  });

  it('refused fields say so, and point at why', () => {
    for (const name of ['identifier, refused', 'password, wrong', 'code, wrong']) {
      const doc = new JSDOM(screens.get(name)).window.document;
      const invalid = doc.querySelector('[aria-invalid="true"]');
      expect(invalid, name).not.toBeNull();
      const why = doc.getElementById(invalid!.getAttribute('aria-describedby')!.split(' ').pop()!);
      expect(why?.getAttribute('role'), name).toBe('alert');
    }
  });
});

// Contrast (1.4.3 text, 1.4.11 the edges of fields and buttons) from the layout's colour tokens.
describe('colour contrast', () => {
  const css = readFileSync(join(__dirname, '..', '..', 'views', 'layout.eta'), 'utf8');
  const tokens = (block: string) =>
    Object.fromEntries(
      [...block.matchAll(/--([a-z-]+):\s*#([0-9a-f]{6}|[0-9a-f]{3})\b/g)].map((m) => [
        m[1]!,
        `#${m[2]!.length === 3 ? [...m[2]!].map((c) => c + c).join('') : m[2]!}`,
      ]),
    );
  const light = tokens(/:root\s*{([^}]*)}/.exec(css)![1]!);
  const dark = tokens(/prefers-color-scheme: dark\)\s*{\s*:root\s*{([^}]*)}/.exec(css)![1]!);

  const luminance = (hex: string) => {
    const [r, g, b] = [1, 3, 5].map((i) => {
      const c = parseInt(hex.slice(i, i + 2), 16) / 255;
      return c <= 0.03928 ? c / 12.92 : ((c + 0.055) / 1.055) ** 2.4;
    });
    return 0.2126 * r! + 0.7152 * g! + 0.0722 * b!;
  };
  const ratio = (a: string, b: string) => {
    const [x, y] = [luminance(a), luminance(b)].sort((p, q) => q - p);
    return (x! + 0.05) / (y! + 0.05);
  };

  // [foreground, background, minimum]
  const pairs: [string, string, number][] = [
    ['ink', 'card', 4.5],
    ['ink', 'bg', 4.5],
    ['muted', 'card', 4.5],
    ['danger', 'card', 4.5],
    ['accent-ink', 'accent', 4.5],
    ['field', 'card', 3], // text inputs' and secondary buttons' edges
    ['danger', 'card', 3], // an invalid field's edge
    ['ink', 'card', 3], // the focus ring
  ];
  for (const [scheme, t] of [
    ['light', light],
    ['dark', dark],
  ] as const) {
    for (const [fg, bg, min] of pairs) {
      it(`${scheme}: ${fg} on ${bg} is at least ${min}:1`, () => {
        expect(t[fg], `--${fg}`).toBeDefined();
        expect(ratio(t[fg]!, t[bg]!)).toBeGreaterThanOrEqual(min);
      });
    }
  }
});
