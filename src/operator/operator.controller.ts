import { Body, Controller, Get, NotFoundException, Post, Query, Req, Res } from '@nestjs/common';
import type { FastifyReply, FastifyRequest } from 'fastify';
import { z } from 'zod';
import { redirect } from '../common/pages';
import { env } from '../config/env';
import { Database } from '../db/database.service';
import { EmailSender } from '../delivery/email.sender';
import { parse } from '../flows/login.controller';
import { GeoIp } from '../geo/geoip.service';
import { IdentityRepository } from '../identity/identity.repository';
import { Limits, tryAgainIn } from '../limits/limits';
import { longDate } from '../recovery/recovery-mail';
import { SessionEnder } from '../sessions/session-ender';
import { AccountPages, isFresh, signedInWithPasskey } from '../account/account-pages';
import type { AccountSession } from '../account/account-sessions';
import { activityView, describeDevice, devicesView, when } from '../account/device';
import {
  OperatorRepository,
  type OperatorActionKind,
  type RecoveryRow,
} from './operator.repository';

const HOME = '/account/operator';
/** How far back an account's activity is shown, as in Security activity. */
const ACTIVITY_DAYS = 90;

const SearchForm = z.object({ q: z.string().max(400) });
const ActionForm = z.object({ id: z.string().uuid(), reason: z.string().max(2000) });
const Id = z.string().uuid();
/** Where a passkey sign-in may return: the console's own pages only. */
const Back = z
  .string()
  .regex(/^\/account\/operator(\/identity\?id=[0-9a-f-]{36})?$/)
  .catch(HOME);

interface Operator {
  s: AccountSession;
  operatorId: string;
}

/** What each change is called, done, and told to the member. */
const CHANGES: Record<
  'suspend' | 'reinstate' | 'sign_out',
  { action: OperatorActionKind; done: string; subject: string; lines: string[] }
> = {
  suspend: {
    action: 'suspended',
    done: 'Account suspended. It has been signed out everywhere and can’t sign in.',
    subject: 'Your account has been suspended',
    lines: [
      `Your ${env.PROVIDER_NAME} account has been suspended by our support team, and signed out of every app.`,
      'If you think this is a mistake, reply to this email or contact support.',
    ],
  },
  reinstate: {
    action: 'reinstated',
    done: 'Account reinstated. It can sign in again.',
    subject: 'Your account is active again',
    lines: [`Your ${env.PROVIDER_NAME} account is active again. You can sign in as before.`],
  },
  sign_out: {
    action: 'signed_out',
    done: 'Signed out everywhere.',
    subject: 'You were signed out everywhere',
    lines: [
      `Our support team signed your ${env.PROVIDER_NAME} account out of every device and app. Sign in again to carry on.`,
      "If you didn't ask for this, change your password after you sign in.",
    ],
  },
};

/**
 * The operator console (account-plan.md part 8): find an account, see what happened on it,
 * suspend or reinstate it, sign it out everywhere, see its 2-step recovery requests.
 *
 * Only for an operator (db/migrations/0017, granted with scripts/operator.mjs) signed in with a
 * passkey (OQ-AC-6); a change needs that passkey sign-in to be recent. To anyone else the
 * console doesn't exist. Every search, view and change is logged with the operator's name, and
 * every change with their reason.
 */
@Controller('account/operator')
export class OperatorController {
  constructor(
    private readonly pages: AccountPages,
    private readonly operators: OperatorRepository,
    private readonly identities: IdentityRepository,
    private readonly db: Database,
    private readonly sessionEnder: SessionEnder,
    private readonly email: EmailSender,
    private readonly geo: GeoIp,
    private readonly limits: Limits,
  ) {}

  @Get()
  async home(@Req() req: FastifyRequest, @Res() reply: FastifyReply): Promise<void> {
    const op = await this.gate(req, reply, HOME);
    if (!op) return;
    await this.searchPage(reply, op.s, {});
  }

  /** A search is posted, so the address looked for stays out of URLs and access logs. */
  @Post()
  async search(
    @Body() body: unknown,
    @Req() req: FastifyRequest,
    @Res() reply: FastifyReply,
  ): Promise<void> {
    const op = await this.gate(req, reply, HOME);
    if (!op) return;
    const { q } = parse(SearchForm, body);
    const taken = await this.limits.take('operator_search', op.s.sub);
    if (!taken.ok) {
      await this.searchPage(
        reply,
        op.s,
        { typed: q, error: `That’s a lot of searches. Try again ${tryAgainIn(taken.retryAt)}.` },
        429,
      );
      return;
    }
    if (!q.trim()) {
      await this.searchPage(
        reply,
        op.s,
        { error: 'Enter an email address, phone number or account ID.' },
        422,
      );
      return;
    }
    const found = await this.operators.find(q);
    await this.operators.log({ ...this.seen(req, op), identityId: found, action: 'searched' });
    if (!found) {
      await this.searchPage(
        reply,
        op.s,
        { typed: q, error: 'No account has that email address, phone number or ID.' },
        404,
      );
      return;
    }
    await redirect(reply, `${HOME}/identity?id=${found}`);
  }

  @Get('identity')
  async identity(
    @Query('id') rawId: unknown,
    @Query('done') done: unknown,
    @Req() req: FastifyRequest,
    @Res() reply: FastifyReply,
  ): Promise<void> {
    const id = Id.safeParse(rawId);
    const op = await this.gate(req, reply, id.success ? `${HOME}/identity?id=${id.data}` : HOME);
    if (!op) return;
    if (!id.success) {
      await redirect(reply, HOME);
      return;
    }
    await this.identityPage(req, reply, op, id.data, { done });
  }

  /** Sends the operator to sign in again with a passkey, then back to where they were. */
  @Get('confirm')
  async confirm(
    @Query('return') back: unknown,
    @Req() req: FastifyRequest,
    @Res() reply: FastifyReply,
  ): Promise<void> {
    const returnTo = Back.parse(back);
    const s = await this.pages.current(req);
    if (!s) {
      await this.pages.startSignIn(reply, returnTo);
      return;
    }
    await this.pages.startSignIn(reply, returnTo, s);
  }

  @Post('suspend')
  async suspend(@Body() body: unknown, @Req() req: FastifyRequest, @Res() reply: FastifyReply) {
    await this.change('suspend', body, req, reply);
  }

  @Post('reinstate')
  async reinstate(@Body() body: unknown, @Req() req: FastifyRequest, @Res() reply: FastifyReply) {
    await this.change('reinstate', body, req, reply);
  }

  @Post('sign-out')
  async signOut(@Body() body: unknown, @Req() req: FastifyRequest, @Res() reply: FastifyReply) {
    await this.change('sign_out', body, req, reply);
  }

  // ---------------------------------------------------------------------------------------

  private async change(
    kind: keyof typeof CHANGES,
    body: unknown,
    req: FastifyRequest,
    reply: FastifyReply,
  ): Promise<void> {
    const form = parse(ActionForm, body);
    const back = `${HOME}/identity?id=${form.id}`;
    const op = await this.gate(req, reply, back, { change: true });
    if (!op) return;
    const reason = form.reason.trim().replace(/\s+/g, ' ');
    const refuse = (error: string, status: number) =>
      this.identityPage(req, reply, op, form.id, { error, reason, status, log: false });
    if (form.id === op.s.sub) {
      await refuse('You can’t do this to your own account.', 422);
      return;
    }
    if (!reason || reason.length > 500) {
      await refuse(
        reason
          ? 'Keep the reason to 500 characters or fewer.'
          : 'Say why, in a few words. It is kept with the change.',
        422,
      );
      return;
    }
    const c = CHANGES[kind];
    const seen = this.seen(req, op);
    const ended = await this.db.tx(async (db) => {
      let sids: string[];
      if (kind === 'suspend') {
        if (!(await this.operators.suspend(db, form.id))) return null;
        sids = await this.identities.sessionsEndedNow(db, form.id, 'identity_suspended');
      } else if (kind === 'reinstate') {
        if (!(await this.operators.reinstate(db, form.id))) return null;
        sids = [];
      } else {
        const subject = await this.operators.subject(form.id);
        if (!subject || subject.status === 'closed') return null;
        sids = await this.operators.endAllSessions(db, form.id);
      }
      await this.operators.log({ ...seen, identityId: form.id, action: c.action, reason }, db);
      await this.identities.event(
        {
          kind:
            kind === 'suspend'
              ? 'identity_suspended'
              : kind === 'reinstate'
                ? 'identity_reinstated'
                : 'session_revoked',
          outcome: 'success',
          identityId: form.id,
          detail:
            kind === 'sign_out' ? { by: 'operator', sessions: sids.length } : { by: 'operator' },
        },
        db,
      );
      return sids;
    });
    if (ended === null) {
      // Already in that state, or closed meanwhile: the page shows what is true now.
      await redirect(reply, back);
      return;
    }
    await this.sessionEnder.endAtHydra(ended);
    const to = (await this.identities.identifiers(form.id)).find(
      (r) => r.kind === 'email' && r.primary,
    );
    if (to) await this.email.sendNotice(to.value, c.subject, c.lines);
    await redirect(reply, `${back}&done=${kind}`);
  }

  /**
   * The operator, or null when the request has been answered: sent to sign in, refused as if
   * the console weren't there, or asked for a passkey. A change also needs it to be recent.
   */
  private async gate(
    req: FastifyRequest,
    reply: FastifyReply,
    returnTo: string,
    opts: { change?: boolean } = {},
  ): Promise<Operator | null> {
    const s = await this.pages.current(req);
    if (!s) {
      await this.pages.startSignIn(reply, returnTo);
      return null;
    }
    const operatorId = await this.operators.live(s.sub);
    // To anyone else, the console answers like a page that doesn't exist.
    if (!operatorId) throw new NotFoundException();
    const passkey = signedInWithPasskey(s);
    if (!passkey || (opts.change && !isFresh(s))) {
      const hasPasskey = (await this.identities.passkeys(s.sub)).length > 0;
      await this.pages.render(
        reply,
        s,
        'operator/passkey',
        'Confirm with a passkey',
        'operator',
        {
          hasPasskey,
          again: passkey,
          confirmUrl: `${HOME}/confirm?return=${encodeURIComponent(returnTo)}`,
        },
        401,
      );
      return null;
    }
    return { s, operatorId };
  }

  private async searchPage(
    reply: FastifyReply,
    s: AccountSession,
    data: { typed?: string; error?: string },
    status = 200,
  ): Promise<void> {
    await this.pages.render(
      reply,
      s,
      'operator/search',
      'Operator console',
      'operator',
      { typed: data.typed ?? '', error: data.error ?? null },
      status,
    );
  }

  /** The account's page. Returns false when there is no such account (answered 404). */
  private async identityPage(
    req: FastifyRequest,
    reply: FastifyReply,
    op: Operator,
    id: string,
    o: { done?: unknown; error?: string; reason?: string; status?: number; log?: boolean },
  ): Promise<boolean> {
    const subject = await this.operators.subject(id);
    if (!subject) {
      await this.searchPage(reply, op.s, { error: 'That account doesn’t exist.' }, 404);
      return false;
    }
    if (o.log !== false) {
      await this.operators.log({ ...this.seen(req, op), identityId: id, action: 'viewed' });
    }
    const [identifiers, twoStep, passkeys, sessions, events, recoveries, history] =
      await Promise.all([
        this.operators.identifiers(id),
        this.identities.twoStep(id),
        this.identities.passkeys(id),
        this.identities.liveSessions(id),
        this.identities.activity(id, ACTIVITY_DAYS, 200),
        this.operators.recoveries(id),
        this.operators.history(id),
      ]);
    const now = new Date();
    const done =
      typeof o.done === 'string' && o.done in CHANGES
        ? CHANGES[o.done as keyof typeof CHANGES].done
        : null;
    await this.pages.render(
      reply,
      op.s,
      'operator/identity',
      subject.displayName || identifiers[0]?.value || 'Account',
      'operator',
      {
        subject: {
          ...subject,
          heading: subject.erasedAt
            ? 'Erased account'
            : subject.displayName || identifiers[0]?.value || 'No name or address',
          created: longDate(subject.createdAt),
          statusLabel: statusLabel(subject),
          deletion: subject.deletionScheduledFor ? longDate(subject.deletionScheduledFor) : null,
        },
        self: id === op.s.sub,
        identifiers,
        methods: {
          password: subject.hasPassword,
          twoStep: twoStep.totp,
          passkeys: passkeys.length,
          providers: subject.providers,
        },
        devices: devicesView(sessions, '', this.geo.place, now),
        activity: events.map((e) => {
          const device = describeDevice(e.userAgent);
          return {
            title: activityView(e, undefined, now)?.title ?? e.kind.replace(/_/g, ' '),
            failed: e.outcome === 'failure',
            when: when(e.occurredAt, now),
            at: e.occurredAt.toISOString(),
            ip: e.ip,
            place: this.geo.place(e.ip),
            device: e.userAgent
              ? device.browser
                ? `${device.browser} on ${device.name}`
                : device.name
              : null,
            client: e.clientId,
          };
        }),
        days: ACTIVITY_DAYS,
        recoveries: recoveries.map(recoveryView),
        history: history.map((h) => ({
          what: ACTION_WORDS[h.action],
          reason: h.reason,
          by: h.by ?? 'A former operator',
          when: when(h.occurredAt, now),
        })),
        done,
        error: o.error ?? null,
        reason: o.reason ?? '',
      },
      o.status ?? 200,
    );
    return true;
  }

  private seen(req: FastifyRequest, op: Operator) {
    return {
      operatorId: op.operatorId,
      ip: req.ip,
      userAgent: req.headers['user-agent'] ?? null,
    };
  }
}

const ACTION_WORDS: Record<OperatorActionKind, string> = {
  searched: 'Searched',
  viewed: 'Viewed',
  suspended: 'Suspended',
  reinstated: 'Reinstated',
  signed_out: 'Signed out everywhere',
};

function statusLabel(s: {
  status: string;
  erasedAt: Date | null;
  suspendedAt: Date | null;
  closedAt: Date | null;
}): { text: string; tone: 'ok' | 'warn' | 'bad' } {
  if (s.erasedAt) return { text: `Erased ${longDate(s.erasedAt)}`, tone: 'bad' };
  if (s.status === 'closed') return { text: `Closed ${longDate(s.closedAt!)}`, tone: 'bad' };
  if (s.status === 'suspended')
    return { text: `Suspended ${longDate(s.suspendedAt!)}`, tone: 'warn' };
  return { text: 'Active', tone: 'ok' };
}

function recoveryView(r: RecoveryRow) {
  const state = r.completedAt
    ? `Completed ${longDate(r.completedAt)}: 2-step verification removed`
    : r.cancelledAt
      ? `Cancelled ${longDate(r.cancelledAt)}${
          r.cancelledBy === 'link'
            ? ' by the link in its email'
            : r.cancelledBy === 'sign_in'
              ? ' by signing in with 2-step verification'
              : ' when the account closed'
        }`
      : r.decision === 'rejected'
        ? 'Refused by an administrator'
        : `Waiting: 2-step verification is removed on ${longDate(r.eligibleAt)} at the earliest${
            r.review === 'required'
              ? r.decision === 'approved'
                ? ' (approved)'
                : ', once an administrator approves'
              : ''
          }`;
  return { requested: longDate(r.requestedAt), state };
}
