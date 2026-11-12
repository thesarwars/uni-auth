import { Body, Controller, Get, Post, Query, Req, Res } from '@nestjs/common';
import type { FastifyReply, FastifyRequest } from 'fastify';
import { z } from 'zod';
import { redirect, render } from '../common/pages';
import { env } from '../config/env';
import { OtpService } from '../credentials/otp.service';
import { checkPassword, PasswordService } from '../credentials/password.service';
import { Database } from '../db/database.service';
import { EmailSender } from '../delivery/email.sender';
import { WhatsAppSender } from '../delivery/whatsapp.sender';
import { parse } from '../flows/login.controller';
import { parseIdentifier, type Identifier } from '../identity/identifier';
import {
  AddressTaken,
  IdentityRepository,
  LastIdentifier,
  type IdentifierRow,
  type Profile,
} from '../identity/identity.repository';
import { SessionEnder } from '../sessions/session-ender';
import { ACCOUNT_CLIENT_ID, AccountOidc, AccountSignInFailed } from './account-oidc';
import { AccountSessions, type AccountSession } from './account-sessions';

const SESSION_COOKIE = 'ea_account';
const STATE_COOKIE = 'ea_account_state';

/** A sensitive change needs a sign-in this recent (account-plan.md AC-D2). */
export const FRESH_SECONDS = 10 * 60;

/** The languages the account centre offers; identity.locale takes any BCP 47 tag of this shape. */
export const LOCALES: { tag: string; label: string }[] = [
  { tag: 'en-GB', label: 'English (United Kingdom)' },
  { tag: 'en-US', label: 'English (United States)' },
  { tag: 'fr-FR', label: 'Français' },
  { tag: 'de-DE', label: 'Deutsch' },
  { tag: 'es-ES', label: 'Español' },
  { tag: 'it-IT', label: 'Italiano' },
];

/** What a redirect back to a page may say happened. Anything else in ?done= is ignored. */
const DONE: Record<string, string> = {
  profile: 'Your details are saved.',
  email_added: 'Email address added.',
  phone_added: 'Phone number added.',
  primary: 'Primary address changed.',
  removed: 'Removed.',
  password_changed: 'Password changed. Your other devices have been signed out.',
  password_set: 'Password set. You can now sign in with it.',
};

const ReturnTo = z
  .string()
  .regex(/^\/account(\/[a-z-]*)?$/)
  .catch('/account');

const ProfileForm = z.object({
  display_name: z.string().max(400),
  locale: z.string().max(20),
});
const AddForm = z.object({ kind: z.enum(['email', 'phone']), value: z.string().max(400) });
const VerifyForm = z.object({
  otp_id: z.string().uuid(),
  code: z.string().max(20),
  // Shown again on a wrong code; what is added is the address the code went to, not this.
  destination: z.string().max(400).default(''),
  kind: z.enum(['email', 'phone']).default('email'),
});
const IdForm = z.object({ id: z.string().uuid() });
const PasswordForm = z.object({ password: z.string().max(1024), confirm: z.string().max(1024) });

/**
 * The account centre (account-plan.md): a member's own entity-auth account - personal info,
 * email and phone, password. It is a client of entity-auth like any other (AC-D1): it signs the
 * member in through Hydra and keeps its own session, which ends when the provider session does.
 * Every change is checked again by the schema; the pages only ask.
 */
@Controller('account')
export class AccountController {
  constructor(
    private readonly oidc: AccountOidc,
    private readonly sessions: AccountSessions,
    private readonly identities: IdentityRepository,
    private readonly db: Database,
    private readonly passwords: PasswordService,
    private readonly otp: OtpService,
    private readonly email: EmailSender,
    private readonly whatsapp: WhatsAppSender,
    private readonly sessionEnder: SessionEnder,
  ) {}

  // ---------------------------------------------------------------------------------------
  // Signing in and out
  // ---------------------------------------------------------------------------------------

  @Get('sign-in')
  async signIn(
    @Query('return') back: unknown,
    @Req() req: FastifyRequest,
    @Res() reply: FastifyReply,
  ): Promise<void> {
    const returnTo = ReturnTo.parse(back);
    if (await this.current(req)) {
      await redirect(reply, returnTo);
      return;
    }
    await this.startSignIn(reply, returnTo);
  }

  @Get('callback')
  async callback(
    @Query('code') code: unknown,
    @Query('state') state: unknown,
    @Query('error') error: unknown,
    @Req() req: FastifyRequest,
    @Res() reply: FastifyReply,
  ): Promise<void> {
    const cookie = req.cookies[STATE_COOKIE];
    const bound = cookie ? req.unsignCookie(cookie) : null;
    reply.clearCookie(STATE_COOKIE, { path: '/account' });
    const pending =
      typeof state === 'string' && bound?.valid && bound.value === state
        ? await this.sessions.take(state)
        : null;
    const existing = await this.current(req);

    if (!pending || typeof code !== 'string' || error !== undefined) {
      // Cancelled at the sign-in screen, or a stale or foreign callback: nothing changes.
      if (existing) {
        await redirect(reply, '/account');
        return;
      }
      await render(reply, 'account/signed-out', 'Account', {
        heading: 'You are not signed in',
        detail: 'The sign-in was cancelled or took too long.',
      });
      return;
    }

    let signedIn;
    try {
      signedIn = await this.oidc.finish(code, pending.verifier, pending.nonce);
    } catch (err) {
      if (!(err instanceof AccountSignInFailed)) throw err;
      await render(
        reply,
        'account/signed-out',
        'Account',
        { heading: "We couldn't sign you in", detail: 'Please try again.' },
        502,
      );
      return;
    }
    const { idToken, claims } = signedIn;
    const fresh = { sid: claims.sid, idToken, authTime: claims.auth_time };
    let session: AccountSession;
    if (existing && existing.sub === claims.sub) {
      session = await this.sessions.refresh(existing, fresh);
    } else {
      if (existing) await this.sessions.end(existing.id);
      session = await this.sessions.open({ sub: claims.sub, ...fresh });
    }
    this.setSession(reply, session);
    await redirect(reply, pending.returnTo);
  }

  /** Ends the account session, then the provider session through Hydra's sign-out. */
  @Post('sign-out')
  async signOut(@Req() req: FastifyRequest, @Res() reply: FastifyReply): Promise<void> {
    const s = await this.current(req);
    reply.clearCookie(SESSION_COOKIE, { path: '/account' });
    if (!s) {
      await redirect(reply, '/account/signed-out');
      return;
    }
    await this.sessions.end(s.id);
    await redirect(reply, this.oidc.signOutUrl(s.idToken));
  }

  @Get('signed-out')
  async signedOut(@Res() reply: FastifyReply): Promise<void> {
    await render(reply, 'account/signed-out', 'Signed out', {
      heading: 'You have signed out',
      detail: 'You can close this window.',
    });
  }

  // ---------------------------------------------------------------------------------------
  // Home and personal info
  // ---------------------------------------------------------------------------------------

  @Get()
  async home(
    @Query('done') done: unknown,
    @Req() req: FastifyRequest,
    @Res() reply: FastifyReply,
  ): Promise<void> {
    const s = await this.guard(req, reply, '/account');
    if (!s) return;
    const { profile, identifiers } = await this.load(s);
    await this.page(reply, s, 'account/home', 'Your account', 'home', {
      profile,
      identifiers,
      done: flash(done),
    });
  }

  @Get('personal')
  async personal(
    @Query('done') done: unknown,
    @Req() req: FastifyRequest,
    @Res() reply: FastifyReply,
  ): Promise<void> {
    const s = await this.guard(req, reply, '/account/personal');
    if (!s) return;
    const { profile, identifiers } = await this.load(s);
    await this.page(reply, s, 'account/personal', 'Personal info', 'personal', {
      profile,
      identifiers,
      locales: LOCALES,
      done: flash(done),
      error: null,
    });
  }

  @Post('personal')
  async savePersonal(
    @Body() body: unknown,
    @Req() req: FastifyRequest,
    @Res() reply: FastifyReply,
  ): Promise<void> {
    const s = await this.guard(req, reply, '/account/personal');
    if (!s) return;
    const form = parse(ProfileForm, body);
    const name = form.display_name.trim().replace(/\s+/g, ' ');
    const locale = LOCALES.find((l) => l.tag === form.locale)?.tag;
    if (name.length > 200 || !locale) {
      const { profile, identifiers } = await this.load(s);
      await this.page(
        reply,
        s,
        'account/personal',
        'Personal info',
        'personal',
        {
          profile: { ...profile, displayName: name },
          identifiers,
          locales: LOCALES,
          done: null,
          error:
            name.length > 200 ? 'Use 200 characters or fewer.' : 'Choose a language from the list.',
        },
        422,
      );
      return;
    }
    await this.db.tx(async (db) => {
      await this.identities.updateProfile(db, s.sub, { displayName: name || null, locale });
      await this.identities.event(
        {
          ...this.seen(req, s),
          kind: 'profile_updated',
          outcome: 'success',
          detail: { fields: ['display_name', 'locale'] },
        },
        db,
      );
    });
    await redirect(reply, '/account/personal?done=profile');
  }

  // ---------------------------------------------------------------------------------------
  // Email and phone
  // ---------------------------------------------------------------------------------------

  @Get('contact')
  async contact(
    @Query('done') done: unknown,
    @Req() req: FastifyRequest,
    @Res() reply: FastifyReply,
  ): Promise<void> {
    const s = await this.guard(req, reply, '/account/contact', { fresh: true });
    if (!s) return;
    await this.contactPage(reply, s, { done: flash(done) });
  }

  @Post('contact/add')
  async addContact(
    @Body() body: unknown,
    @Req() req: FastifyRequest,
    @Res() reply: FastifyReply,
  ): Promise<void> {
    const s = await this.guard(req, reply, '/account/contact', { fresh: true });
    if (!s) return;
    const form = parse(AddForm, body);
    const id = parseIdentifier(form.value);
    const noun = form.kind === 'email' ? 'email address' : 'phone number';
    if (!id || id.kind !== form.kind || (id.kind === 'phone' && !phonesAccepted())) {
      await this.contactPage(
        reply,
        s,
        {
          adding: form.kind,
          typed: form.value,
          error:
            form.kind === 'email'
              ? 'Enter an email address, like name@example.com.'
              : 'Enter a phone number with its country code, like +44 7700 900123.',
        },
        422,
      );
      return;
    }
    const mine = await this.identities.identifiers(s.sub);
    if (mine.some((r) => r.kind === id.kind && r.value.toLowerCase() === id.value.toLowerCase())) {
      await this.contactPage(
        reply,
        s,
        { adding: form.kind, typed: form.value, error: `That ${noun} is already on your account.` },
        422,
      );
      return;
    }
    await this.sendAddCode(reply, s, id);
  }

  @Post('contact/verify')
  async verifyContact(
    @Body() body: unknown,
    @Req() req: FastifyRequest,
    @Res() reply: FastifyReply,
  ): Promise<void> {
    const s = await this.guard(req, reply, '/account/contact', { fresh: true });
    if (!s) return;
    const form = parse(VerifyForm, body);
    const outcome = await this.db.tx((db) =>
      this.otp.verify(db, { otpId: form.otp_id, flow: flowOf(s), code: form.code }),
    );
    if (outcome.kind === 'invalid') {
      await this.render(
        reply,
        s,
        'account/contact-code',
        'Confirm it',
        'contact',
        {
          destination: form.destination,
          kind: form.kind,
          channel: outcome.view.channel,
          otpId: outcome.view.otpId,
          codeLength: outcome.view.codeLength,
          error: "That code isn't right. Try again, or send a new code.",
          remaining: outcome.remaining <= 2 ? outcome.remaining : null,
        },
        422,
      );
      return;
    }
    if (
      outcome.kind !== 'verified' ||
      outcome.purpose !== 'add_identifier' ||
      outcome.identityId !== s.sub
    ) {
      await this.contactPage(
        reply,
        s,
        {
          error:
            outcome.kind === 'locked'
              ? 'Too many wrong codes. Try again later.'
              : 'That code has expired. Add the address again to get a new one.',
        },
        422,
      );
      return;
    }

    const id: Identifier = {
      kind: outcome.channel === 'email' ? 'email' : 'phone',
      value: outcome.destination,
    };
    try {
      await this.db.tx(async (db) => {
        await this.identities.addIdentifier(db, s.sub, id);
        await this.identities.event(
          {
            ...this.seen(req, s),
            kind: 'identifier_added',
            outcome: 'success',
            detail: { kind: id.kind },
          },
          db,
        );
      });
    } catch (err) {
      if (!(err instanceof AddressTaken)) throw err;
      await this.contactPage(
        reply,
        s,
        { error: 'Another account already uses that address.' },
        409,
      );
      return;
    }
    await this.notify(s.sub, 'An address was added to your account', [
      `${id.kind === 'email' ? 'The email address' : 'The phone number'} ${id.value} was added to your account.`,
    ]);
    await redirect(reply, `/account/contact?done=${id.kind}_added`);
  }

  @Post('contact/primary')
  async makePrimary(
    @Body() body: unknown,
    @Req() req: FastifyRequest,
    @Res() reply: FastifyReply,
  ): Promise<void> {
    const s = await this.guard(req, reply, '/account/contact', { fresh: true });
    if (!s) return;
    const { id } = parse(IdForm, body);
    const changed = await this.db.tx(async (db) => {
      const done = await this.identities.makePrimary(db, s.sub, id);
      if (done) {
        await this.identities.event(
          {
            ...this.seen(req, s),
            kind: 'profile_updated',
            outcome: 'success',
            detail: { primary: done.made.kind },
          },
          db,
        );
      }
      return done;
    });
    if (changed?.was?.kind === 'email') {
      // The old address hears of it: if this was a takeover, its owner has a way to know.
      await this.email.sendNotice(changed.was.value, 'Your primary email address changed', [
        `Your account's primary email address is now ${changed.made.value}.`,
        `This address (${changed.was.value}) is still on the account.`,
      ]);
    }
    await redirect(reply, changed ? '/account/contact?done=primary' : '/account/contact');
  }

  @Post('contact/remove')
  async removeContact(
    @Body() body: unknown,
    @Req() req: FastifyRequest,
    @Res() reply: FastifyReply,
  ): Promise<void> {
    const s = await this.guard(req, reply, '/account/contact', { fresh: true });
    if (!s) return;
    const { id } = parse(IdForm, body);
    let gone: IdentifierRow | null;
    try {
      gone = await this.db.tx(async (db) => {
        const removed = await this.identities.removeIdentifier(db, s.sub, id);
        if (removed) {
          await this.identities.event(
            {
              ...this.seen(req, s),
              kind: 'identifier_removed',
              outcome: 'success',
              detail: { kind: removed.kind },
            },
            db,
          );
        }
        return removed;
      });
    } catch (err) {
      if (!(err instanceof LastIdentifier)) throw err;
      await this.contactPage(
        reply,
        s,
        { error: 'Add another email address or phone number before you remove this one.' },
        422,
      );
      return;
    }
    if (gone) {
      const lines = [
        `${gone.kind === 'email' ? 'The email address' : 'The phone number'} ${gone.value} was removed from your account.`,
      ];
      if (gone.kind === 'email') {
        await this.email.sendNotice(gone.value, 'This address was removed from an account', lines);
      }
      await this.notify(s.sub, 'An address was removed from your account', lines);
    }
    await redirect(reply, gone ? '/account/contact?done=removed' : '/account/contact');
  }

  // ---------------------------------------------------------------------------------------
  // Password
  // ---------------------------------------------------------------------------------------

  @Get('password')
  async password(
    @Query('done') done: unknown,
    @Req() req: FastifyRequest,
    @Res() reply: FastifyReply,
  ): Promise<void> {
    const s = await this.guard(req, reply, '/account/password', { fresh: true });
    if (!s) return;
    await this.passwordPage(reply, s, { done: flash(done) });
  }

  @Post('password')
  async changePassword(
    @Body() body: unknown,
    @Req() req: FastifyRequest,
    @Res() reply: FastifyReply,
  ): Promise<void> {
    const s = await this.guard(req, reply, '/account/password', { fresh: true });
    if (!s) return;
    const form = parse(PasswordForm, body);
    const policy = await this.passwords.policyInEffect(this.db.asDb());
    const failed = checkPassword(policy, form.password).filter((r) => !r.met);
    if (failed.length > 0 || form.password !== form.confirm) {
      await this.passwordPage(
        reply,
        s,
        {
          typed: form.password,
          error:
            failed.length > 0
              ? 'Your new password does not meet every rule yet.'
              : 'The two passwords do not match.',
        },
        422,
      );
      return;
    }
    const before = await this.identities.profile(s.sub);
    const first = !before?.passwordSetAt;
    const secretHash = await this.passwords.hash(form.password);
    const { ended } = await this.db.tx(async (db) => {
      const done = await this.identities.changePassword(db, {
        identityId: s.sub,
        secretHash,
        keepSid: s.sid,
      });
      await this.identities.event(
        {
          ...this.seen(req, s),
          kind: first ? 'credential_added' : 'password_changed',
          outcome: 'success',
          credentialKind: 'password',
          detail: { signed_out: done.ended.length },
        },
        db,
      );
      return done;
    });
    // Each other device's apps hear of it by back-channel logout.
    await this.sessionEnder.endAtHydra(ended);
    await this.notify(
      s.sub,
      first ? 'A password was set on your account' : 'Your password was changed',
      [
        first
          ? 'A password was set on your account. You can now sign in with it.'
          : `Your password was changed. ${ended.length === 1 ? '1 other device was' : `${ended.length} other devices were`} signed out.`,
      ],
    );
    await redirect(reply, `/account/password?done=${first ? 'password_set' : 'password_changed'}`);
  }

  // ---------------------------------------------------------------------------------------
  // Helpers
  // ---------------------------------------------------------------------------------------

  /** The signed-in account session, if its provider session is still live. */
  private async current(req: FastifyRequest): Promise<AccountSession | null> {
    const raw = req.cookies[SESSION_COOKIE];
    const unsigned = raw ? req.unsignCookie(raw) : null;
    if (!unsigned?.valid || !unsigned.value) return null;
    const s = await this.sessions.get(unsigned.value);
    if (!s) return null;
    // Signed out elsewhere, revoked, or the identity suspended or closed: this ends too.
    if ((await this.identities.mayRefresh(s.sid)) !== true) {
      await this.sessions.end(s.id);
      return null;
    }
    return s;
  }

  /**
   * The session a page needs, or null once the browser has been sent to sign in - again, with
   * "Confirm it's you", when the page needs a recent sign-in and this one is older (AC-D2).
   */
  private async guard(
    req: FastifyRequest,
    reply: FastifyReply,
    returnTo: string,
    opts: { fresh?: boolean } = {},
  ): Promise<AccountSession | null> {
    const s = await this.current(req);
    if (!s) {
      await this.startSignIn(reply, returnTo);
      return null;
    }
    if (opts.fresh && !isFresh(s)) {
      await this.startSignIn(reply, returnTo, s);
      return null;
    }
    return s;
  }

  private async startSignIn(
    reply: FastifyReply,
    returnTo: string,
    confirm?: AccountSession,
  ): Promise<void> {
    const { url, state, verifier, nonce } = this.oidc.start(
      confirm ? { idToken: confirm.idToken } : undefined,
    );
    await this.sessions.hold(state, { verifier, nonce, returnTo });
    reply.setCookie(STATE_COOKIE, state, {
      signed: true,
      httpOnly: true,
      path: '/account',
      maxAge: 600,
      sameSite: 'lax',
      secure: env.NODE_ENV === 'production',
    });
    await redirect(reply, url);
  }

  private setSession(reply: FastifyReply, s: AccountSession): void {
    reply.setCookie(SESSION_COOKIE, s.id, {
      signed: true,
      httpOnly: true,
      path: '/account',
      maxAge: 12 * 60 * 60,
      sameSite: 'lax',
      secure: env.NODE_ENV === 'production',
    });
  }

  private async load(
    s: AccountSession,
  ): Promise<{ profile: Profile; identifiers: IdentifierRow[] }> {
    const [profile, identifiers] = await Promise.all([
      this.identities.profile(s.sub),
      this.identities.identifiers(s.sub),
    ]);
    return { profile: profile!, identifiers };
  }

  private async sendAddCode(reply: FastifyReply, s: AccountSession, id: Identifier): Promise<void> {
    let sent;
    try {
      sent = await this.db.tx((db) =>
        this.otp.send(db, {
          identityId: s.sub,
          purpose: 'add_identifier',
          to: id,
          flow: flowOf(s),
        }),
      );
    } catch (err) {
      // 0005: an address another identity holds verified gets no code.
      if ((err as { code?: string }).code !== '23514') throw err;
      await this.contactPage(
        reply,
        s,
        { adding: id.kind, typed: id.value, error: 'Another account already uses that address.' },
        409,
      );
      return;
    }
    if (sent.kind !== 'sent') {
      await this.contactPage(
        reply,
        s,
        {
          adding: id.kind,
          typed: id.value,
          error:
            sent.kind === 'locked'
              ? 'Too many wrong codes were tried for that address. Try again later.'
              : "We've sent as many codes to that address as we can for now. Try again in an hour.",
        },
        429,
      );
      return;
    }
    try {
      if (sent.view.channel === 'email') {
        await this.email.sendCode(sent.destination, sent.code, 'add_identifier');
      } else {
        await this.whatsapp.sendCode(sent.destination, sent.code);
      }
    } catch {
      await this.contactPage(
        reply,
        s,
        {
          adding: id.kind,
          typed: id.value,
          error: "We couldn't send the code. Please try again in a moment.",
        },
        502,
      );
      return;
    }
    await this.render(reply, s, 'account/contact-code', 'Confirm it', 'contact', {
      destination: id.value,
      kind: id.kind,
      channel: sent.view.channel,
      otpId: sent.view.otpId,
      codeLength: sent.view.codeLength,
      error: null,
      remaining: null,
    });
  }

  private async contactPage(
    reply: FastifyReply,
    s: AccountSession,
    state: { done?: string | null; error?: string; adding?: 'email' | 'phone'; typed?: string },
    status = 200,
  ): Promise<void> {
    const { profile, identifiers } = await this.load(s);
    await this.page(
      reply,
      s,
      'account/contact',
      'Email and phone',
      'contact',
      {
        profile,
        identifiers,
        phones: phonesAccepted(),
        done: state.done ?? null,
        error: state.error ?? null,
        adding: state.adding ?? null,
        typed: state.typed ?? '',
      },
      status,
    );
  }

  private async passwordPage(
    reply: FastifyReply,
    s: AccountSession,
    state: { done?: string | null; error?: string; typed?: string },
    status = 200,
  ): Promise<void> {
    const { profile, identifiers } = await this.load(s);
    const policy = await this.passwords.policyInEffect(this.db.asDb());
    await this.page(
      reply,
      s,
      'account/password',
      'Password',
      'password',
      {
        profile,
        identifiers,
        rules: checkPassword(policy, state.typed ?? ''),
        checked: state.typed !== undefined,
        done: state.done ?? null,
        error: state.error ?? null,
      },
      status,
    );
  }

  /** A page with the account layout's data: who is signed in, the navigation, a CSRF token. */
  private async page(
    reply: FastifyReply,
    s: AccountSession,
    view: string,
    title: string,
    nav: string,
    data: Record<string, unknown> & { identifiers: IdentifierRow[] },
    status = 200,
  ): Promise<void> {
    await this.render(reply, s, view, title, nav, data, status);
  }

  private async render(
    reply: FastifyReply,
    s: AccountSession,
    view: string,
    title: string,
    nav: string,
    data: Record<string, unknown>,
    status = 200,
  ): Promise<void> {
    const identifiers =
      (data.identifiers as IdentifierRow[] | undefined) ??
      (await this.identities.identifiers(s.sub));
    const who =
      identifiers.find((r) => r.primary && r.kind === 'email') ??
      identifiers.find((r) => r.primary);
    await render(
      reply,
      view,
      title,
      { ...data, nav, who: who?.value ?? '', csrfToken: reply.generateCsrf() },
      status,
    );
  }

  /** Tells the member at their primary email; they may have none (a phone-only account). */
  private async notify(identityId: string, subject: string, lines: string[]): Promise<void> {
    const to = (await this.identities.identifiers(identityId)).find(
      (r) => r.kind === 'email' && r.primary,
    );
    if (to) await this.email.sendNotice(to.value, subject, lines);
  }

  private seen(req: FastifyRequest, s: AccountSession) {
    return {
      identityId: s.sub,
      clientId: ACCOUNT_CLIENT_ID,
      ip: req.ip,
      userAgent: req.headers['user-agent'] ?? null,
    };
  }
}

const isFresh = (s: AccountSession): boolean => Date.now() / 1000 - s.authTime <= FRESH_SECONDS;

/** The flow a code from the account centre is bound to: this account session, nothing else. */
const flowOf = (s: AccountSession): string => `account:${s.id}`;

const phonesAccepted = (): boolean => env.WHATSAPP_DELIVERY !== 'off';

const flash = (done: unknown): string | null =>
  typeof done === 'string' && Object.hasOwn(DONE, done) ? DONE[done]! : null;
