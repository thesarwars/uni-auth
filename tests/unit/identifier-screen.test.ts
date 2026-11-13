import { JSDOM } from 'jsdom';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import { createEta } from '../../src/common/eta';

/**
 * The identifier screen with and without phone numbers. WHATSAPP_DELIVERY=off (a deployment
 * without WhatsApp) asks for an email address only; LoginController also refuses a phone
 * number posted anyway, so no code is ever made for one.
 */

const eta = createEta(join(__dirname, '..', '..', 'views'));
const base = {
  title: 't',
  providerName: 'uni-auth',
  challenge: 'c',
  clientName: 'Go Style Network',
  csrfToken: 'x',
  typed: '',
  error: null,
  upstreams: [],
};

function render(data: Record<string, unknown>) {
  return new JSDOM(eta.render('identifier', { ...base, ...data })).window.document;
}

describe('the identifier screen', () => {
  it('offers email or phone while WhatsApp delivers codes', () => {
    for (const create of [false, true]) {
      const doc = render({ create, phones: true });
      expect(doc.querySelector('label[for=identifier]')!.textContent).toBe('Email or phone');
      expect(doc.getElementById('identifier')!.getAttribute('placeholder')).toContain('+44');
    }
    expect(render({ create: true, phones: true }).body.textContent).toContain('One account for');
  });

  it('asks for an email address only when phones are off', () => {
    for (const create of [false, true]) {
      const doc = render({ create, phones: false });
      expect(doc.querySelector('label[for=identifier]')!.textContent).toBe('Email');
      expect(doc.body.textContent).not.toMatch(/phone|country code/i);
      expect(doc.getElementById('identifier')!.getAttribute('placeholder')).toBe('you@example.com');
    }
    expect(render({ create: true, phones: false }).body.textContent).toContain('One account for');
  });
});
