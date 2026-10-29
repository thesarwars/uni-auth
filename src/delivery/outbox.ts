import { Injectable } from '@nestjs/common';

export interface Delivered {
  channel: 'email' | 'whatsapp';
  to: string;
  code: string;
  at: Date;
}

/**
 * What the log-mode senders would have sent, kept in memory so the e2e suite can read a code
 * the way a member reads their inbox. Log mode is refused in production (src/config/env.ts), so
 * this never holds a real member's code.
 */
@Injectable()
export class Outbox {
  private readonly sent: Delivered[] = [];

  record(d: Omit<Delivered, 'at'>): void {
    this.sent.push({ ...d, at: new Date() });
    if (this.sent.length > 200) this.sent.shift();
  }

  /** The newest code sent to `to`, if any. */
  last(to: string): Delivered | undefined {
    return this.sent.findLast((d) => d.to === to);
  }

  count(to: string): number {
    return this.sent.filter((d) => d.to === to).length;
  }
}
