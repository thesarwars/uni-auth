import type { NestFastifyApplication } from '@nestjs/platform-fastify';
import axe from 'axe-core';
import { JSDOM } from 'jsdom';
import { execFileSync } from 'node:child_process';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import sharp from 'sharp';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { Outbox } from '../../src/delivery/outbox';
import { Limits } from '../../src/limits/limits';
import { RedisService } from '../../src/redis/redis.service';
import { codeAt, fromBase32, stepAt } from '../../src/two-step/totp';
import { Authenticator } from '../support/authenticator';
import { startApp } from '../support/app';
import { chromePath, launchChrome, type Chrome } from '../support/chrome';
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
  keep('reset', await post(b, page, { action: 'reset' }));
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
  keep(
    'password updated',
    await post(b, page, {
      action: 'new_password',
      password: 'Brand-New-Pass-1',
      confirm: 'Brand-New-Pass-1',
    }),
  );
  member.password = 'Brand-New-Pass-1'; // the reset changed it

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

  // The account centre (account-plan.md parts 1-3).
  const holder = await createMember();
  const a = browser();
  let acct = (await a.follow(`${APP}/account`)).hop;
  acct = await a.post(`${APP}/login`, {
    ...formFields(acct.html),
    action: 'identify',
    identifier: holder.email,
  });
  acct = await a.post(`${APP}/login`, {
    ...formFields(acct.html),
    action: 'password',
    password: holder.password,
  });
  keep('account home', (acct = (await a.follow(acct.location!)).hop));
  const token = () => /name="_csrf" value="([^"]+)"/.exec(acct.html)![1]!;
  keep('account personal info', (acct = (await a.follow(`${APP}/account/personal`)).hop));
  keep(
    'account personal info, refused',
    await a.post(`${APP}/account/personal`, { _csrf: token(), display_name: 'x', locale: 'zz' }),
  );
  keep('account email and phone', (acct = (await a.follow(`${APP}/account/contact`)).hop));
  keep(
    'account email and phone, refused',
    await a.post(`${APP}/account/contact/add`, { _csrf: token(), kind: 'email', value: 'nope' }),
  );
  const added = `a11y-${Date.now()}@example.com`;
  keep(
    'account code',
    (acct = await a.post(`${APP}/account/contact/add`, {
      _csrf: token(),
      kind: 'email',
      value: added,
    })),
  );
  keep(
    'account code, wrong',
    await a.post(`${APP}/account/contact/verify`, {
      _csrf: token(),
      otp_id: /name="otp_id" value="([^"]+)"/.exec(acct.html)![1]!,
      code: '000000',
      destination: added,
      kind: 'email',
    }),
  );
  keep('account password', (acct = (await a.follow(`${APP}/account/password`)).hop));
  keep(
    'account password, refused',
    await a.post(`${APP}/account/password`, { _csrf: token(), password: 'weak', confirm: 'x' }),
  );
  keep('account signed out', await browser().get(`${APP}/account/signed-out`));

  // 2-step verification (account-plan.md part 4): the account pages, then the sign-in step.
  keep('account 2-step, off', (acct = (await a.follow(`${APP}/account/two-step`)).hop));
  keep('account 2-step setup', (acct = (await a.follow(`${APP}/account/two-step/setup`)).hop));
  const seed = fromBase32(/aria-label="Setup key">([A-Z2-7 ]+)</.exec(acct.html)![1]!);
  keep(
    'account 2-step setup, wrong',
    await a.post(`${APP}/account/two-step/setup`, { _csrf: token(), code: '000000' }),
  );
  keep(
    'account recovery codes',
    await a.post(`${APP}/account/two-step/setup`, {
      _csrf: token(),
      code: codeAt(seed, stepAt(Date.now())),
    }),
  );
  keep('account 2-step, on', await a.get(`${APP}/account/two-step`));

  // Passkeys (account-plan.md part 5).
  keep('account passkeys, none', await a.get(`${APP}/account/passkeys`));
  keep('account add passkey', (acct = (await a.follow(`${APP}/account/passkeys/add`)).hop));
  const options = JSON.parse((await a.get(`${APP}/account/passkeys/options`)).html);
  const holderKey = new Authenticator();
  keep(
    'account add passkey, refused',
    await a.post(`${APP}/account/passkeys/add`, { _csrf: token(), credential: '{}' }),
  );
  await a.post(`${APP}/account/passkeys/add`, {
    _csrf: token(),
    credential: holderKey.create(options),
  });
  keep('account passkeys', (acct = (await a.follow(`${APP}/account/passkeys`)).hop));
  const passkeyId = /name="id" value="([^"]+)"/.exec(acct.html)![1]!;
  keep('account rename passkey', await a.get(`${APP}/account/passkeys/rename?id=${passkeyId}`));
  keep(
    'account rename passkey, refused',
    await a.post(`${APP}/account/passkeys/rename`, { _csrf: token(), id: passkeyId, name: ' ' }),
  );
  // Data & privacy and Linked apps (account-plan.md part 6).
  keep('account linked apps', await a.get(`${APP}/account/apps`));
  keep('account data and privacy', await a.get(`${APP}/account/privacy`));
  keep('account download your data', await a.get(`${APP}/account/privacy/download`));
  keep('account delete your account', await a.get(`${APP}/account/privacy/delete`));
  // Profile photo: none yet, then a refused upload (the error), then one in place.
  keep('account profile photo', (acct = (await a.follow(`${APP}/account/personal/photo`)).hop));
  const photoForm = (data: Buffer, name: string, type: string) => {
    const form = new FormData();
    form.set('_csrf', token());
    form.set('photo', new Blob([new Uint8Array(data)], { type }), name);
    return form;
  };
  keep(
    'account profile photo, refused',
    await a.upload(
      `${APP}/account/personal/photo`,
      photoForm(Buffer.from('x'), 'a.txt', 'text/plain'),
    ),
  );
  const png = await sharp({
    create: { width: 300, height: 300, channels: 3, background: '#556677' },
  })
    .png()
    .toBuffer();
  await a.upload(`${APP}/account/personal/photo`, photoForm(png, 'me.png', 'image/png'));
  keep('account personal info, with photo', await a.get(`${APP}/account/personal`));
  keep('account profile photo, set', await a.get(`${APP}/account/personal/photo`));
  // A change refused because its budget is spent (part 8).
  acct = await a.get(`${APP}/account/personal/edit`);
  await app
    .get(RedisService)
    .client.set(app.get(Limits).key('personal', holder.identityId), '30', 'EX', 3600);
  keep(
    'account try again later',
    await a.post(`${APP}/account/personal`, {
      _csrf: token(),
      display_name: 'Too often',
      locale: 'en-GB',
    }),
  );
  // The operator console (part 8): its passkey step, search, and an account's page.
  execFileSync('node', ['scripts/operator.mjs', 'grant', holder.email, 'accessibility test']);
  acct = keep('operator confirm with a passkey', await a.get(`${APP}/account/operator`));
  const confirmHref = /href="(\/account\/operator\/confirm\?[^"]+)"/.exec(acct.html)![1]!;
  const login = (await a.follow(`${APP}${confirmHref.replace(/&amp;/g, '&')}`)).hop;
  const loginChallenge = /name="login_challenge" value="([^"]+)"/.exec(login.html)![1]!;
  const getOptions = JSON.parse(
    (
      await a.get(
        `${APP}/login/passkey/options?login_challenge=${encodeURIComponent(loginChallenge)}`,
      )
    ).html,
  );
  const signedIn = await a.post(`${APP}/login/passkey`, {
    _csrf: /name="_csrf" value="([^"]+)"/.exec(login.html)![1]!,
    login_challenge: loginChallenge,
    credential: holderKey.get(getOptions),
  });
  acct = keep('operator console', (await a.follow(signedIn.location!)).hop);
  expect(acct.html).toContain('Find account');
  keep(
    'operator console, not found',
    await a.post(`${APP}/account/operator`, { _csrf: token(), q: 'nobody@example.com' }),
  );
  acct = keep(
    'operator account page',
    await a.get(`${APP}/account/operator/identity?id=${member.identityId}`),
  );
  expect(acct.html).toContain('Suspend account');
  keep(
    'operator account page, refused',
    await a.post(`${APP}/account/operator/suspend`, {
      _csrf: token(),
      id: member.identityId,
      reason: ' ',
    }),
  );
  ({ b, page } = await start());
  page = await post(b, page, { action: 'identify', identifier: holder.email });
  page = await post(b, page, { action: 'password', password: holder.password });
  page = keep('two-step', (await b.follow(page.location!)).hop);
  const step = (mode: string) =>
    b.post(`${APP}/login/two-step`, {
      _csrf: /name="_csrf" value="([^"]+)"/.exec(page.html)![1]!,
      login_challenge: /name="login_challenge" value="([^"]+)"/.exec(page.html)![1]!,
      mode,
      code: '000000',
    });
  keep('two-step, wrong', await step('app'));
  keep('two-step, recovery code', await step('recovery'));
  // Account recovery (account-plan.md part 7): the help page, and a cancel link's two answers.
  keep(
    'two-step help',
    await b.get(
      `${APP}/login/two-step/help?login_challenge=${encodeURIComponent(
        /name="login_challenge" value="([^"]+)"/.exec(page.html)![1]!,
      )}`,
    ),
  );
  keep(
    'recovery cancel, unknown link',
    await browser().get(`${APP}/recovery/cancel?token=${'A'.repeat(43)}`),
  );
}, 120_000);

afterAll(async () => {
  await app?.close();
  await closeMembers();
});

describe('every screen passes axe-core (WCAG 2.2 A and AA)', () => {
  const names = [
    'identifier',
    'identifier, refused',
    'two-step',
    'two-step, wrong',
    'two-step, recovery code',
    'two-step help',
    'recovery cancel, unknown link',
    'account 2-step, off',
    'account 2-step setup',
    'account 2-step setup, wrong',
    'account recovery codes',
    'account 2-step, on',
    'account passkeys, none',
    'account add passkey',
    'account add passkey, refused',
    'account passkeys',
    'account rename passkey',
    'account rename passkey, refused',
    'account linked apps',
    'account data and privacy',
    'account download your data',
    'account delete your account',
    'password',
    'password, wrong',
    'reset',
    'code',
    'code, wrong',
    'new password',
    'new password, refused',
    'password updated',
    'sign-up',
    'sign-up, refused',
    'lockout',
    'sign-out',
    'still signed in',
    'signed out',
    'error',
    'expired',
    'account home',
    'account personal info',
    'account personal info, refused',
    'account email and phone',
    'account email and phone, refused',
    'account code',
    'account code, wrong',
    'account password',
    'account password, refused',
    'account signed out',
  ];
  for (const name of names) {
    it(name, async () => {
      const html = screens.get(name);
      expect(html, `${name} was not reached`).toBeTruthy();
      expect(await audit(html!)).toEqual([]);
    });
  }

  it('every script and stylesheet a screen links is served', async () => {
    const links = new Set<string>();
    for (const html of screens.values()) {
      for (const m of html.matchAll(/<(?:script|link)[^>]+(?:src|href)="(\/assets\/[^"]+)"/g))
        links.add(m[1]!);
    }
    for (const js of ['menu.js', 'photo.js', 'password.js', 'webauthn.js'])
      expect(
        [...links].some((l) => l.includes(js)),
        js,
      ).toBe(true);
    const missing: string[] = [];
    for (const l of links)
      if ((await fetch(APP + l.replace(/&amp;/g, '&'))).status !== 200) missing.push(l);
    expect(missing).toEqual([]);
  });

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

// Contrast (1.4.3 text, 1.4.11 the edges of fields and buttons) from the stylesheet's colour tokens.
// The design is light only. Alpha tokens (borders and rings that only decorate) are not checked.
describe('colour contrast', () => {
  const css = readFileSync(join(__dirname, '..', '..', 'public', 'entity-auth.css'), 'utf8');
  const t = Object.fromEntries(
    [.../:root\s*{([^}]*)}/.exec(css)![1]!.matchAll(/--([a-z-]+):\s*#([0-9a-f]{6})\b/g)].map(
      (m) => [m[1]!, `#${m[2]!}`],
    ),
  );

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
    ['text-primary', 'bg-surface', 4.5],
    ['text-primary', 'bg-page', 4.5],
    ['text-secondary', 'bg-surface', 4.5],
    ['text-secondary', 'bg-page', 4.5], // the footer, the account centre's page text
    ['text-tertiary', 'bg-surface', 4.5], // hints, rules not yet met
    ['text-tertiary', 'bg-page', 4.5],
    ['text-placeholder', 'bg-surface', 4.5], // placeholder text in a field
    ['status-error', 'bg-surface', 4.5],
    ['status-ok', 'bg-surface', 4.5], // rules met, passwords match
    ['status-error', 'status-error-bg', 4.5], // the "Not set" tag
    ['status-ok', 'status-ok-bg', 4.5], // a done message, the "Active" tag
    ['status-warn', 'status-warn-bg', 4.5], // "Try again later", the "Suspended" tag
    ['status-warn', 'bg-surface', 3], // a warning's edge
    ['status-ok', 'bg-surface', 3], // a done message's edge
    ['text-primary', 'tag-neutral', 4.5], // the "Verified" tag
    ['text-on-action', 'action-primary', 4.5],
    ['text-on-action', 'action-primary-hover', 4.5],
    ['text-on-action', 'text-secondary', 4.5], // initials on the avatar
    ['border-field', 'bg-surface', 3], // text inputs' and code boxes' edges
    ['status-error', 'bg-surface', 3], // an invalid field's edge
    ['border-focus', 'bg-surface', 3], // the focus ring
    ['check-done', 'bg-surface', 3], // a met rule's tick
  ];

  for (const [fg, bg, min] of pairs) {
    it(`${fg} on ${bg} is at least ${min}:1`, () => {
      expect(t[fg], `--${fg}`).toBeDefined();
      expect(t[bg], `--${bg}`).toBeDefined();
      expect(ratio(t[fg]!, t[bg]!)).toBeGreaterThanOrEqual(min);
    });
  }
});

// ---------------------------------------------------------------------------------------------
// In a real browser (part 8's accessibility pass): what jsdom can't see because it lays nothing
// out. Each screen kept above is drawn by Chrome at this server's origin, so its stylesheet,
// fonts and scripts load as they do for a member.
// ---------------------------------------------------------------------------------------------

const WCAG = ['wcag2a', 'wcag2aa', 'wcag21a', 'wcag21aa', 'wcag22aa'];

describe.skipIf(!chromePath())('in a real browser', () => {
  let chrome: Chrome;

  // Each screen is served at this server's own address by Chrome itself (the Fetch domain), so
  // its stylesheet, fonts and scripts come from the server as they do for a member.
  let current = '';
  beforeAll(async () => {
    chrome = await launchChrome();
    await chrome.send('Page.enable');
    await chrome.send('Fetch.enable', { patterns: [{ urlPattern: `${APP}/__screen/*` }] });
    chrome.on('Fetch.requestPaused', (p: { requestId: string }) => {
      void chrome.send('Fetch.fulfillRequest', {
        requestId: p.requestId,
        responseCode: 200,
        responseHeaders: [{ name: 'content-type', value: 'text/html; charset=utf-8' }],
        body: Buffer.from(current).toString('base64'),
      });
    });
  }, 60_000);
  afterAll(async () => {
    await chrome?.close();
  });

  let shown = 0;
  /** Draws `html` at `width` CSS pixels and waits for its stylesheet, fonts and scripts. */
  async function show(html: string, width: number): Promise<void> {
    await chrome.send('Emulation.setDeviceMetricsOverride', {
      width,
      height: 900,
      deviceScaleFactor: 1,
      mobile: width < 600,
    });
    current = html;
    const loaded = chrome.once('Page.loadEventFired');
    await chrome.send('Page.navigate', { url: `${APP}/__screen/${++shown}` });
    await loaded;
    await chrome.evaluate('document.fonts.ready.then(() => true)');
    // Without its stylesheet a page would pass trivially, on the browser's own focus ring.
    const styled = await chrome.evaluate<number>(
      `[...document.styleSheets].reduce((n, sh) => { try { return n + sh.cssRules.length; } catch { return n; } }, 0)`,
    );
    if (/stylesheet/.test(html)) expect(styled, 'stylesheet loaded').toBeGreaterThan(50);
  }

  async function axeInChrome(): Promise<string[]> {
    await chrome.evaluate(`window.axe ? true : (eval(${JSON.stringify(axe.source)}), true)`);
    return chrome.evaluate(
      `axe.run(document, { runOnly: { type: 'tag', values: ${JSON.stringify(WCAG)} } })
        .then((r) => r.violations.map((v) => v.id + ': ' + v.nodes.map((n) => n.target.join(' ') + (n.any[0] ? ' (' + n.any[0].message + ')' : '')).join(', ')))`,
    );
  }

  /** What sticks out past a 320px-wide window (1.4.10 Reflow), outside anything that scrolls. */
  const overflow = () =>
    chrome.evaluate<string[]>(`(() => {
      const w = document.documentElement.clientWidth;
      if (document.documentElement.scrollWidth <= w) return [];
      const scrolls = (el) => { for (let p = el.parentElement; p; p = p.parentElement) {
        const o = getComputedStyle(p).overflowX; if (o === 'auto' || o === 'scroll' || o === 'hidden') return true; } return false; };
      return [...document.body.querySelectorAll('*')]
        .filter((el) => el.getBoundingClientRect().right > w + 1 && !scrolls(el))
        .slice(0, 5)
        .map((el) => el.tagName.toLowerCase() + (el.className ? '.' + String(el.className).split(' ').join('.') : '') + ' right=' + Math.round(el.getBoundingClientRect().right));
    })()`);

  /**
   * Text cut off once spacing is widened as 1.4.12 (Text Spacing) allows: what a box with
   * overflow hidden can no longer show. Ellipsis truncation of long values is by design.
   */
  const clippedBySpacing = () =>
    chrome.evaluate<string[]>(`(() => {
      const st = document.createElement('style');
      st.textContent = '* { line-height: 1.5 !important; letter-spacing: 0.12em !important; word-spacing: 0.16em !important; } p { margin-bottom: 2em !important; }';
      document.head.appendChild(st);
      const out = [];
      for (const el of document.body.querySelectorAll('*')) {
        const s = getComputedStyle(el);
        if (!/hidden|clip/.test(s.overflowX + s.overflowY) || el.closest('.sr')) continue;
        const box = el.getBoundingClientRect();
        // Visible text drawn outside the box that clips it: what a reader can no longer see.
        const walker = document.createTreeWalker(el, NodeFilter.SHOW_TEXT);
        for (let t = walker.nextNode(); t; t = walker.nextNode()) {
          if (!t.textContent.trim() || t.parentElement.closest('.sr')) continue;
          const ps = getComputedStyle(t.parentElement);
          if (ps.textOverflow === 'ellipsis' || ps.visibility === 'hidden' || ps.display === 'none') continue;
          const range = document.createRange(); range.selectNodeContents(t);
          const r = range.getBoundingClientRect();
          if (r.width === 0) continue;
          if (r.right > box.right + 1 || r.bottom > box.bottom + 1 || r.left < box.left - 1 || r.top < box.top - 1) {
            out.push(el.tagName.toLowerCase() + '.' + String(el.className).split(' ').join('.') + ' cuts "' + t.textContent.trim().slice(0, 40) + '"');
            break;
          }
        }
        if (out.length >= 5) break;
      }
      st.remove();
      return out;
    })()`);

  /** Fields, buttons and boxes cut off by a container that hides what overflows it. */
  const cutOff = () =>
    chrome.evaluate<string[]>(`(() => {
      const out = [];
      for (const el of document.body.querySelectorAll('input:not([type=hidden]), button, a, select, textarea, .boxes span, img')) {
        if (el.closest('.sr, [hidden]')) continue;
        const r = el.getBoundingClientRect();
        if (r.width === 0 || r.height === 0) continue;
        for (let p = el.parentElement; p && p !== document.body; p = p.parentElement) {
          const s = getComputedStyle(p);
          if (!/hidden|clip/.test(s.overflowX)) continue;
          const b = p.getBoundingClientRect();
          if (r.right > b.right + 1 || r.left < b.left - 1)
            out.push(el.tagName.toLowerCase() + '.' + String(el.className).split(' ').join('.') + ' in ' + p.tagName.toLowerCase() + '.' + String(p.className).split(' ').join('.'));
          break;
        }
        if (out.length >= 5) break;
      }
      return out;
    })()`);

  const FOCUSABLE =
    'a[href],button:not([disabled]),input:not([type=hidden]):not([disabled]),select,textarea,summary,[tabindex]:not([tabindex="-1"])';

  /** Tabs through the page: what gets focus, and whether it then looks any different (2.4.7). */
  async function tabThrough(): Promise<{
    reached: string[];
    unseen: string[];
    hiddenFocus: string[];
  }> {
    const count = await chrome.evaluate<number>(`(() => {
      document.activeElement && document.activeElement.blur();
      const look = (el) => { const s = getComputedStyle(el);
        return [s.outlineStyle, s.outlineWidth, s.outlineColor, s.boxShadow, s.borderColor, s.backgroundColor, s.color, s.textDecorationLine].join('|'); };
      window.__look = look;
      window.__base = new Map([...document.querySelectorAll(${JSON.stringify(FOCUSABLE)})].map((el) => [el, look(el)]));
      return window.__base.size;
    })()`);
    const reached: string[] = [];
    const unseen: string[] = [];
    const hiddenFocus: string[] = [];
    for (let i = 0; i < count + 2; i++) {
      for (const type of ['keyDown', 'keyUp']) {
        await chrome.send('Input.dispatchKeyEvent', {
          type,
          key: 'Tab',
          code: 'Tab',
          windowsVirtualKeyCode: 9,
        });
      }
      const at = await chrome.evaluate<{
        desc: string;
        changed: boolean;
        visible: boolean;
      } | null>(`(() => {
        const el = document.activeElement;
        if (!el || el === document.body || !window.__base.has(el)) return el && el !== document.body ? { desc: 'unlisted ' + el.tagName, changed: true, visible: true } : null;
        const r = el.getBoundingClientRect();
        const name = (el.getAttribute('aria-label') || el.textContent || el.getAttribute('name') || el.id || '').trim().replace(/\\s+/g, ' ').slice(0, 40);
        return { desc: el.tagName.toLowerCase() + ' "' + name + '"', changed: window.__look(el) !== window.__base.get(el), visible: r.width > 0 && r.height > 0 };
      })()`);
      if (!at) break;
      if (reached.includes(at.desc) && reached[0] === at.desc) break;
      reached.push(at.desc);
      if (!at.changed) unseen.push(at.desc);
      if (!at.visible) hiddenFocus.push(at.desc);
    }
    return { reached, unseen, hiddenFocus };
  }

  it('the checks themselves catch a broken page', async () => {
    const page = (body: string) =>
      `<!doctype html><html lang="en"><head><meta name="viewport" content="width=device-width, initial-scale=1"><title>t</title><link rel="stylesheet" href="/assets/entity-auth.css"><style>${body}</style></head>` +
      `<body><main><h1>t</h1><a href="/x">Link</a><button>Go</button><div style="width:600px">wide</div><p style="color:#bbb">pale</p></main></body></html>`;
    await show(
      page('*:focus, *:focus-visible { outline: none !important; box-shadow: none !important; }'),
      1280,
    );
    expect((await tabThrough()).unseen).toEqual(['a "Link"', 'button "Go"']);
    expect((await axeInChrome()).map((v) => v.split(':')[0])).toContain('color-contrast');
    await show(page(''), 320);
    expect((await overflow()).length).toBeGreaterThan(0);
  });

  /** A key pressed as a person would: Enter also types its character, which is what activates. */
  const key = async (k: string, code: string, vk: number) => {
    const text = k === 'Enter' ? '\r' : undefined;
    await chrome.send('Input.dispatchKeyEvent', {
      type: text ? 'keyDown' : 'rawKeyDown',
      key: k,
      code,
      windowsVirtualKeyCode: vk,
      text,
    });
    await chrome.send('Input.dispatchKeyEvent', {
      type: 'keyUp',
      key: k,
      code,
      windowsVirtualKeyCode: vk,
    });
  };

  it('the profile menu opens from the keyboard, and Escape or Tab away closes it', async () => {
    await show(screens.get('account home')!, 1280);
    const focusSummary = `(() => { document.querySelector('details.me summary').focus(); return document.activeElement.tagName; })()`;
    expect(await chrome.evaluate(focusSummary)).toBe('SUMMARY');
    const open = () => chrome.evaluate<boolean>(`document.querySelector('details.me').open`);
    await key('Enter', 'Enter', 13);
    expect(await open()).toBe(true);
    await key('Escape', 'Escape', 27);
    expect(await open()).toBe(false);
    expect(await chrome.evaluate(`document.activeElement.tagName`)).toBe('SUMMARY');
    await key('Enter', 'Enter', 13);
    await key('Tab', 'Tab', 9); // to Sign out, inside
    expect(await open()).toBe(true);
    await key('Tab', 'Tab', 9); // out of the menu
    expect(await open()).toBe(false);
  });

  /**
   * Every screen, as Chrome draws it: axe-core with contrast as rendered; each control reached by
   * Tab looks different when focused (2.4.7) and is on screen; nothing sticks out sideways at
   * 320px (1.4.10, a phone, or 1280px zoomed to 400%) or 640px (zoomed to 200%); and no text is
   * cut off at 320px once spacing is widened as 1.4.12 allows.
   */
  it('every screen, drawn in Chrome', async () => {
    const problems: string[] = [];
    let checked = 0;
    for (const [name, html] of screens) {
      const found: string[] = [];
      await show(html, 1280);
      found.push(...(await axeInChrome()).map((v) => `axe ${v}`));
      const tab = await tabThrough();
      if (tab.unseen.length) found.push(`focus not visible: ${tab.unseen.join('; ')}`);
      if (tab.hiddenFocus.length)
        found.push(`focus on nothing visible: ${tab.hiddenFocus.join('; ')}`);
      await show(html, 640);
      const at640 = await overflow();
      if (at640.length) found.push(`sticks out at 640px: ${at640.join('; ')}`);
      await show(html, 320);
      const at320 = await overflow();
      if (at320.length) found.push(`sticks out at 320px: ${at320.join('; ')}`);
      const cut = await cutOff();
      if (cut.length) found.push(`cut off at 320px: ${cut.join('; ')}`);
      const spaced = await clippedBySpacing();
      if (spaced.length) found.push(`cut off with wider text spacing: ${spaced.join('; ')}`);
      if (found.length) problems.push(`${name}:\n  ${found.join('\n  ')}`);
      checked++;
    }
    expect(checked).toBe(screens.size);
    expect(problems.join('\n')).toBe('');
  }, 600_000);
});
