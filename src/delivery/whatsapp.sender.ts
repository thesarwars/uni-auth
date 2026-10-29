import { Injectable, Logger } from '@nestjs/common';
import { env } from '../config/env';
import { Outbox } from './outbox';

/**
 * WhatsApp through Meta's Cloud API. Meta lets a business open a conversation only with an
 * approved template, so the code goes out as an AUTHENTICATION template whose body and
 * copy-code button both take the code as their one parameter. Carried over from the GSN API.
 */
@Injectable()
export class WhatsAppSender {
  private readonly logger = new Logger(WhatsAppSender.name);

  constructor(private readonly outbox: Outbox) {}

  async sendCode(toE164: string, code: string): Promise<void> {
    if (env.WHATSAPP_DELIVERY === 'log') {
      this.logger.warn(`WHATSAPP_DELIVERY=log; code for ${toE164} is ${code}`);
      this.outbox.record({ channel: 'whatsapp', to: toE164, code });
      return;
    }
    const url =
      `https://graph.facebook.com/${env.WHATSAPP_API_VERSION}/` +
      `${env.WHATSAPP_PHONE_NUMBER_ID}/messages`;
    const res = await fetch(url, {
      method: 'POST',
      headers: {
        Authorization: `Bearer ${env.WHATSAPP_ACCESS_TOKEN}`,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        messaging_product: 'whatsapp',
        to: toE164.replace(/^\+/, ''),
        type: 'template',
        template: {
          name: env.WHATSAPP_TEMPLATE_NAME,
          language: { code: env.WHATSAPP_TEMPLATE_LANGUAGE },
          components: [
            { type: 'body', parameters: [{ type: 'text', text: code }] },
            {
              type: 'button',
              sub_type: 'url',
              index: '0',
              parameters: [{ type: 'text', text: code }],
            },
          ],
        },
      }),
      signal: AbortSignal.timeout(10_000),
    });
    if (!res.ok) throw new Error(`WhatsApp send failed: ${res.status} ${await res.text()}`);
  }
}
