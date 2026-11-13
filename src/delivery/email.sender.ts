import { Injectable, Logger } from '@nestjs/common';
import nodemailer, { type Transporter } from 'nodemailer';
import { env } from '../config/env';
import { renderEmail } from './email-template';
import { Outbox } from './outbox';

/**
 * Email over SMTP, so any provider (SES, Postmark, SendGrid, Mailgun, Workspace) plugs in through
 * SMTP_* alone; locally it can point at Mailpit. With EMAIL_DELIVERY=log the message goes to the
 * log and the outbox instead. Carried over from the GSN API, without the GSN brand: the message
 * names the provider, because the code is for signing in to it.
 */
@Injectable()
export class EmailSender {
  private readonly logger = new Logger(EmailSender.name);
  private readonly transport: Transporter | null =
    env.EMAIL_DELIVERY === 'smtp'
      ? nodemailer.createTransport({
          host: env.SMTP_HOST,
          port: env.SMTP_PORT,
          secure: env.SMTP_SECURE,
          auth: env.SMTP_USER ? { user: env.SMTP_USER, pass: env.SMTP_PASS ?? '' } : undefined,
        })
      : null;

  constructor(private readonly outbox: Outbox) {}

  async sendCode(
    to: string,
    code: string,
    purpose: 'sign_in' | 'recovery' | 'signup' | 'add_identifier',
  ): Promise<void> {
    const minutes = Math.round(env.OTP_TTL_SECONDS / 60);
    const P = env.PROVIDER_NAME;
    const copy = {
      sign_in: { title: 'Your sign-in code', intro: `Enter this code to sign in with ${P}.` },
      signup: {
        title: 'Confirm your email',
        intro: `Enter this code to finish creating your ${P} account.`,
      },
      recovery: {
        title: 'Reset your password',
        intro: `Enter this code to choose a new password for your ${P} account.`,
      },
      add_identifier: {
        title: 'Confirm this email address',
        intro: `Enter this code to add this email address to your ${P} account.`,
      },
    }[purpose];
    const subject = `Your ${P} code: ${code}`;
    const note =
      "If you didn't ask for this code, you can ignore this email. Nobody can sign in without it, " +
      `and ${P} will never ask you to share it.`;
    const text =
      `${copy.title}\n\n${copy.intro}\n\n${code}\n\n` +
      `It expires in ${minutes} minutes and works once.\n\n${note}`;
    const html = renderEmail({
      provider: P,
      preview: `${code} is your code. It expires in ${minutes} minutes.`,
      title: copy.title,
      intro: copy.intro,
      code,
      codeNote: `Expires in ${minutes} minutes. Works once.`,
      note,
      footer: `You're getting this email because someone entered this address in ${P}.`,
    });

    if (!this.transport) {
      this.logger.warn(`EMAIL_DELIVERY=log; ${purpose} code for ${to} is ${code}`);
      this.outbox.record({ channel: 'email', to, code });
      return;
    }
    await this.transport.sendMail({ from: env.SMTP_FROM, to, subject, text, html });
  }

  /**
   * A security notice: something changed on the account (account-plan.md section 3). Always
   * sent, never optional. Best effort: the change has already happened, so a failed send is
   * logged, not thrown.
   */
  async sendNotice(to: string, subject: string, lines: string[]): Promise<void> {
    const P = env.PROVIDER_NAME;
    const footer =
      `If this wasn't you, sign in to your ${P} account, change your password ` +
      `and check your email addresses and phone numbers.`;
    const text = [...lines, '', footer].join('\n');
    const html = renderEmail({
      provider: P,
      preview: lines[0] ?? subject,
      title: subject,
      intro: lines[0] ?? '',
      lines: lines.slice(1),
      button: { label: 'Review your account', href: `${env.LOGIN_PUBLIC_URL}/account` },
      note: footer,
      footer: `Security notices about your ${P} account are always sent and can't be turned off.`,
    });
    if (!this.transport) {
      this.logger.warn(`EMAIL_DELIVERY=log; notice to ${to}: ${subject}`);
      this.outbox.notice({ to, subject, text });
      return;
    }
    try {
      await this.transport.sendMail({
        from: env.SMTP_FROM,
        to,
        subject: `${env.PROVIDER_NAME}: ${subject}`,
        text,
        html,
      });
    } catch (err) {
      this.logger.error(`could not send a notice to ${to}: ${(err as Error).message}`);
    }
  }
}
