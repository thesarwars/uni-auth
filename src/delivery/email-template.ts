/**
 * The HTML of every email, in the sign-in screens' design: the grey page, a white card with a
 * large radius, the Entity mark, Geist where the client has it. Email clients need tables and
 * inline styles, and many block images, so the mark is drawn with HTML rather than loaded.
 * Everything put in here is escaped; the callers pass plain text.
 */

const FONT = `Geist, -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif`;
const MONO = `'Geist Mono', ui-monospace, SFMono-Regular, Menlo, Consolas, monospace`;

export interface EmailParts {
  provider: string;
  /** Shown in the inbox list after the subject; hidden in the message. */
  preview: string;
  title: string;
  intro: string;
  code?: string;
  /** Under the code, small. */
  codeNote?: string;
  lines?: string[];
  button?: { label: string; href: string };
  /** Below a divider, small: what to do if this wasn't you. */
  note: string;
  /** Under the card. */
  footer: string;
}

export function renderEmail(p: EmailParts): string {
  const e = escapeHtml;
  const lines = (p.lines ?? [])
    .map(
      (l) => `<p style="margin:0 0 12px;font-size:15px;line-height:22px;color:#262626">${e(l)}</p>`,
    )
    .join('');
  const code = p.code
    ? `<tr><td style="padding:24px 0 0">
        <table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0"><tr>
          <td align="center" bgcolor="#f5f5f5" style="background:#f5f5f5;border-radius:16px;padding:20px 12px;font-family:${MONO};font-size:34px;line-height:40px;font-weight:600;letter-spacing:10px;color:#000000">${e(p.code)}</td>
        </tr></table>
      </td></tr>` +
      (p.codeNote
        ? `<tr><td style="padding:12px 0 0;font-size:13px;line-height:20px;color:#525252" align="center">${e(p.codeNote)}</td></tr>`
        : '')
    : '';
  const button = p.button
    ? `<tr><td style="padding:12px 0 0">
        <table role="presentation" cellpadding="0" cellspacing="0" border="0"><tr>
          <td bgcolor="#000000" style="background:#000000;border-radius:999px">
            <a href="${e(p.button.href)}" style="display:inline-block;padding:12px 22px;font-family:${FONT};font-size:15px;line-height:20px;font-weight:500;color:#ffffff;text-decoration:none;border-radius:999px">${e(p.button.label)}</a>
          </td>
        </tr></table>
      </td></tr>`
    : '';

  return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="color-scheme" content="light">
<meta name="supported-color-schemes" content="light">
<title>${e(p.title)}</title>
<link href="https://fonts.googleapis.com/css2?family=Geist:wght@400;500;600&family=Geist+Mono:wght@600&display=swap" rel="stylesheet">
<style>
  body { margin: 0; padding: 0; }
  @media (max-width: 560px) {
    .card { padding: 32px 24px !important; border-radius: 24px !important; }
    .title { font-size: 24px !important; line-height: 30px !important; }
    .wrap { padding: 24px 12px !important; }
  }
</style>
</head>
<body style="margin:0;padding:0;background:#f5f5f5">
<div style="display:none;max-height:0;overflow:hidden;opacity:0;color:transparent">${e(p.preview)}</div>
<table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0" bgcolor="#f5f5f5" style="background:#f5f5f5">
<tr><td align="center" class="wrap" style="padding:40px 16px">
  <table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0" style="max-width:520px;font-family:${FONT}">
    <tr><td style="padding:0 8px 20px">
      <table role="presentation" cellpadding="0" cellspacing="0" border="0"><tr>
        <td width="28" height="28" align="center" valign="middle" bgcolor="#000000" style="width:28px;height:28px;background:#000000;border-radius:8px">
          <div style="width:11px;height:11px;border:2.5px solid #ffffff;border-radius:50%;margin:0 auto;font-size:0;line-height:0">
            <div style="width:4px;height:4px;background:#ffffff;border-radius:50%;margin:3.5px auto 0;font-size:0;line-height:0">&nbsp;</div>
          </div>
        </td>
        <td style="padding-left:10px;font-family:${FONT};font-size:17px;line-height:28px;font-weight:600;color:#000000;letter-spacing:-0.2px">${e(p.provider)}</td>
      </tr></table>
    </td></tr>
    <tr><td class="card" bgcolor="#ffffff" style="background:#ffffff;border-radius:28px;padding:40px">
      <table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0" style="font-family:${FONT}">
        <tr><td class="title" style="font-size:28px;line-height:34px;font-weight:600;letter-spacing:-0.6px;color:#000000;padding:0 0 12px">${e(p.title)}</td></tr>
        <tr><td style="font-size:15px;line-height:22px;color:#262626">${e(p.intro)}</td></tr>
        ${lines ? `<tr><td style="padding:16px 0 0">${lines}</td></tr>` : ''}
        ${code}
        ${button}
        <tr><td style="padding:28px 0 0"><div style="height:1px;background:#ebebeb;font-size:0;line-height:0">&nbsp;</div></td></tr>
        <tr><td style="padding:20px 0 0;font-size:13px;line-height:20px;color:#525252">${e(p.note)}</td></tr>
      </table>
    </td></tr>
    <tr><td style="padding:20px 8px 0;font-size:12px;line-height:18px;color:#737373">${e(p.footer)}</td></tr>
  </table>
</td></tr>
</table>
</body>
</html>`;
}

export const escapeHtml = (s: string): string =>
  s.replace(
    /[&<>"']/g,
    (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[c]!,
  );
