import { describe, expect, it } from 'vitest';
import { renderEmail } from '../../src/delivery/email-template';

const base = {
  provider: 'Entity',
  preview: 'preview',
  title: 'Your sign-in code',
  intro: 'Enter this code to sign in with Entity.',
  note: 'note',
  footer: 'footer',
};

describe('renderEmail', () => {
  it('shows the code, its note and the provider', () => {
    const html = renderEmail({ ...base, code: '427563', codeNote: 'Expires in 10 minutes.' });
    expect(html).toContain('427563');
    expect(html).toContain('Expires in 10 minutes.');
    expect(html).toContain('>Entity<');
  });

  it('escapes everything it is given', () => {
    const html = renderEmail({
      ...base,
      title: '<b>x</b>',
      lines: ['a <script>alert(1)</script> & "q"'],
      button: { label: 'Go', href: 'https://e.example/?a=1&b="2"' },
    });
    expect(html).not.toContain('<script>');
    expect(html).not.toContain('<b>x</b>');
    expect(html).toContain('&lt;script&gt;');
    expect(html).toContain('href="https://e.example/?a=1&amp;b=&quot;2&quot;"');
  });

  it('leaves out the code block and button when not given', () => {
    const html = renderEmail(base);
    expect(html).not.toContain('letter-spacing:10px');
    expect(html).not.toContain('<a href');
  });
});
