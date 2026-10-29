import { Injectable, Logger } from '@nestjs/common';
import nodemailer, { type Transporter } from 'nodemailer';
import { env } from '../config/env';
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
    purpose: 'sign_in' | 'recovery' | 'signup',
  ): Promise<void> {
    const minutes = Math.round(env.OTP_TTL_SECONDS / 60);
    const what =
      purpose === 'recovery'
        ? 'reset your password'
        : purpose === 'signup'
          ? 'create your account'
          : 'sign in';
    const subject = `Your ${env.PROVIDER_NAME} code: ${code}`;
    const text =
      `Your code to ${what} is ${code}.\n\n` +
      `It expires in ${minutes} minutes and works once. ` +
      `If you did not ask for it, you can ignore this email; nobody can sign in without it.`;
    const html =
      `<p>Your code to ${what} is</p>` +
      `<p><strong style="font-size:24px;letter-spacing:4px">${code}</strong></p>` +
      `<p style="color:#666;font-size:13px">It expires in ${minutes} minutes and works once. ` +
      `If you did not ask for it, you can ignore this email; nobody can sign in without it.</p>`;

    if (!this.transport) {
      this.logger.warn(`EMAIL_DELIVERY=log; ${purpose} code for ${to} is ${code}`);
      this.outbox.record({ channel: 'email', to, code });
      return;
    }
    await this.transport.sendMail({ from: env.SMTP_FROM, to, subject, text, html });
  }
}
