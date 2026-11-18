import { Injectable } from '@nestjs/common';
import { env } from '../config/env';
import { EmailSender } from '../delivery/email.sender';
import { RecoveryRepository, type CancelledBy, type Recovery } from './recovery.repository';

/** "18 November 2026", UK time. */
export const longDate = (d: Date): string =>
  d.toLocaleDateString('en-GB', {
    day: 'numeric',
    month: 'long',
    year: 'numeric',
    timeZone: 'Europe/London',
  });

/**
 * The emails of account recovery (account-plan.md part 7), to every verified email address on
 * the account, not only the primary: whoever asked may hold one of them, and the real owner must
 * hear wherever they still read mail. Best effort, as every notice: sendNotice never throws.
 */
@Injectable()
export class RecoveryMail {
  constructor(
    private readonly email: EmailSender,
    private readonly recoveries: RecoveryRepository,
  ) {}

  /** The request was made: when it takes effect, and the link that cancels it. */
  async requested(r: Recovery, cancelToken: string, review: boolean): Promise<void> {
    const href = `${env.LOGIN_PUBLIC_URL}/recovery/cancel?token=${encodeURIComponent(cancelToken)}`;
    await this.toAll(
      r.identityId,
      'Someone asked to remove 2-step verification',
      [
        `Someone signed in with your password and said they can't use any of your 2-step verification methods, so they asked for 2-step verification to be removed from your ${env.PROVIDER_NAME} account.`,
        review
          ? `Our team will check the request. If it's approved, 2-step verification is removed on ${longDate(r.eligibleAt)} at the earliest.`
          : `If nobody cancels it, 2-step verification is removed on ${longDate(r.eligibleAt)}, and your password alone will sign in.`,
        "If this was you, there's nothing to do.",
        "If it wasn't you, cancel the request now and change your password: whoever asked knows it.",
      ],
      { label: 'Cancel this request', href },
    );
  }

  async cancelled(r: Recovery, by: CancelledBy): Promise<void> {
    if (by === 'identity_closed') return;
    await this.toAll(r.identityId, 'The request to remove 2-step verification was cancelled', [
      by === 'sign_in'
        ? 'You signed in with 2-step verification, so we cancelled the request to remove it. Nothing has changed on your account.'
        : 'The request to remove 2-step verification from your account was cancelled. Nothing has changed on your account.',
      "If you didn't ask for 2-step verification to be removed, change your password: whoever asked knows it.",
    ]);
  }

  async rejected(r: Recovery): Promise<void> {
    await this.toAll(r.identityId, "The request to remove 2-step verification wasn't approved", [
      "Our team couldn't confirm the request to remove 2-step verification from your account, so it stays on.",
      'If you made the request, contact support. If you can find any of your 2-step methods or recovery codes, you can sign in with them as usual.',
    ]);
  }

  async completed(r: Recovery): Promise<void> {
    await this.toAll(r.identityId, '2-step verification was removed', [
      `As asked on ${longDate(r.requestedAt)}, 2-step verification was removed from your ${env.PROVIDER_NAME} account. Your password alone now signs in, and your old recovery codes no longer work.`,
      'Turn 2-step verification on again in your account, under Security & sign-in.',
    ]);
  }

  private async toAll(
    identityId: string,
    subject: string,
    lines: string[],
    action?: { label: string; href: string },
  ): Promise<void> {
    try {
      const to = await this.recoveries.emails(identityId);
      await Promise.all(
        to.map((address) => this.email.sendNotice(address, subject, lines, action)),
      );
    } catch {
      // A missed email must not undo what has already happened.
    }
  }
}
