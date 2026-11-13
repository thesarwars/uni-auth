import { Eta } from 'eta';
import { JSDOM } from 'jsdom';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import { checkPassword, type PasswordPolicy } from '../../src/credentials/password.service';

/**
 * public/password.js against the real templates: the show/hide button, the rules ticking as the
 * member types (with the server's own tests) and the repeat check. The
 * script only advises; the server's checkPassword still decides on submit.
 */

const ROOT = join(__dirname, '..', '..');
const eta = new Eta({ views: join(ROOT, 'views') });
const script = readFileSync(join(ROOT, 'public', 'password.js'), 'utf8');
const policy: PasswordPolicy = {
  id: 'p',
  min_length: 8,
  require_uppercase: true,
  require_digit_or_symbol: true,
};

const base = {
  title: 't',
  providerName: 'uni-auth',
  challenge: 'c',
  clientName: 'Go Style Network',
  csrfToken: 'x',
  identifier: 'amelia@example.com',
  noun: 'email address',
  channel: 'email',
  error: null,
};

function screen(view: string, data: Record<string, unknown> = {}) {
  const html = eta.render(view, {
    ...base,
    rules: checkPassword(policy, ''),
    checked: false,
    ...data,
  });
  const dom = new JSDOM(html, { runScripts: 'outside-only' });
  const { window } = dom;
  window.eval(script);
  const $ = <T extends Element>(sel: string) => window.document.querySelector<T>(sel)!;
  const type = (id: string, value: string) => {
    const input = $<HTMLInputElement>(`#${id}`);
    input.value = value;
    input.dispatchEvent(new window.Event('input'));
  };
  const met = () =>
    [...window.document.querySelectorAll('#rules li')].map((li) => li.classList.contains('met'));
  return { window, html, $, type, met };
}

describe('the sign-up screen, with password.js', () => {
  it('reveals and hides each password field', () => {
    const { $ } = screen('signup');
    for (const id of ['password', 'confirm']) {
      const button = $<HTMLButtonElement>(`button[data-reveal=${id}]`);
      const input = $<HTMLInputElement>(`#${id}`);
      expect(button.hidden).toBe(false);
      expect(button.getAttribute('aria-label')).toBe('Show password');
      button.click();
      expect(input.type).toBe('text');
      expect(button.getAttribute('aria-pressed')).toBe('true');
      expect(button.getAttribute('aria-label')).toBe('Hide password');
      button.click();
      expect(input.type).toBe('password');
    }
  });

  it('hides a revealed password again before the form is sent', () => {
    const { $, window } = screen('signup');
    $<HTMLButtonElement>('button[data-reveal=password]').click();
    $<HTMLFormElement>('form').dispatchEvent(new window.Event('submit'));
    expect($<HTMLInputElement>('#password').type).toBe('password');
  });

  it('ticks each rule as it is met, exactly as the server would', () => {
    const { type, met, $ } = screen('signup');
    for (const pw of ['', 'abc', 'abcdefgh', 'Abcdefgh', 'Abcdefg1', 'ÉCOLE-été', 'a b c d e']) {
      type('password', pw);
      expect(met(), pw).toEqual(checkPassword(policy, pw).map((r) => r.met));
    }
    type('password', 'Abcdefg1');
    expect($('#rules li .state').textContent).toBe(' (done)');
  });

  it('says whether the repeat matches', () => {
    const { type, $ } = screen('signup');
    const match = $<HTMLElement>('#match');
    type('password', 'Abcdefg1');
    expect(match.hidden).toBe(true);
    type('confirm', 'Abcdef');
    expect([match.hidden, match.textContent]).toEqual([false, "Passwords don't match"]);
    type('confirm', 'Abcdefg1');
    expect([match.textContent, match.classList.contains('met')]).toEqual(['Passwords match', true]);
  });

  it('keeps the server marks until the member types again', () => {
    const { met, $, type } = screen('signup', {
      rules: checkPassword(policy, 'short'),
      checked: true,
      error: 'Choose a password that meets every rule.',
    });
    expect($('#rules li').classList.contains('unmet')).toBe(true);
    expect(met()).toEqual([false, false, false]);
    type('password', 'Abcdefg1');
    expect($('#rules li').classList.contains('unmet')).toBe(false);
  });

  it('marks each rule green when met and red when not, neutral when empty', () => {
    const { $, type } = screen('signup');
    const marks = () =>
      [...$('#rules').querySelectorAll('li')].map((li) =>
        li.classList.contains('met') ? 'ok' : li.classList.contains('unmet') ? 'bad' : '-',
      );
    expect(marks()).toEqual(['-', '-', '-']);
    type('password', 'abcdefgh');
    expect(marks()).toEqual(['ok', 'bad', 'bad']);
    type('password', 'Abcdefg1');
    expect(marks()).toEqual(['ok', 'ok', 'ok']);
    type('password', '');
    expect(marks()).toEqual(['-', '-', '-']);
  });
});

describe('sending a form', () => {
  it('sends it once: a second submit while the first is on its way is stopped', async () => {
    const { window, $ } = screen('signup');
    const form = $<HTMLFormElement>('form#signup, form');
    const submit = () => {
      const e = new window.Event('submit', { cancelable: true });
      form.dispatchEvent(e);
      return e.defaultPrevented;
    };
    expect(submit()).toBe(false);
    expect(submit()).toBe(true);
    expect(form.getAttribute('aria-busy')).toBe('true');
  });

  it('can be sent again after Back brings the page back', () => {
    const { window, $ } = screen('signup');
    const form = $<HTMLFormElement>('form');
    form.dispatchEvent(new window.Event('submit', { cancelable: true }));
    const back = new window.Event('pageshow') as Event & { persisted?: boolean };
    Object.defineProperty(back, 'persisted', { value: true });
    window.dispatchEvent(back);
    const again = new window.Event('submit', { cancelable: true });
    form.dispatchEvent(again);
    expect(again.defaultPrevented).toBe(false);
  });
});

describe('without JavaScript', () => {
  it('lists the rules and shows no control that would do nothing', () => {
    const html = eta.render('signup', {
      ...base,
      rules: checkPassword(policy, ''),
      checked: false,
    });
    const doc = new JSDOM(html).window.document;
    expect([...doc.querySelectorAll('#rules li')].map((li) => li.textContent)).toEqual([
      'At least 8 characters',
      'One uppercase letter',
      'One number or symbol',
    ]);
    for (const el of doc.querySelectorAll('button.reveal, #match')) {
      expect((el as HTMLElement).hidden).toBe(true);
    }
  });
});

describe('the sign-in and new-password screens', () => {
  it('give the sign-in password a show/hide button', () => {
    const { $, window } = screen('password', {
      remaining: null,
      codeChannel: 'email',
      notice: null,
    });
    expect($<HTMLButtonElement>('button[data-reveal=password]').hidden).toBe(false);
    expect(window.document.getElementById('rules')).toBeNull();
  });

  it('give a new password the same rules and repeat check', () => {
    const { type, met } = screen('new-password', {
      ticket: '00000000-0000-0000-0000-000000000000',
    });
    type('password', 'Abcdefg1');
    expect(met()).toEqual([true, true, true]);
  });
});
