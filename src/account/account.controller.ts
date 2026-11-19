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
import { AccountApps } from './account-apps';
import { AccountSessions, type AccountSession } from './account-sessions';
import { GeoIp } from '../geo/geoip.service';
import QRCode from 'qrcode';
import { MfaKeys } from '../two-step/mfa-keys';
import { newCodes, shown } from '../two-step/recovery-codes';
import { base32, grouped, matchStep, newSeed, otpauthUri } from '../two-step/totp';
import { TwoStepStore } from '../two-step/two-step.store';
import { Passkeys } from '../passkeys/passkeys.service';
import { activitiesView, describeDevice, devicesView } from './device';
import { DataExport } from './data-export';
import { HydraAdmin } from '../hydra/hydra-admin.service';
import { RedisService } from '../redis/redis.service';
import { Upstream, PROVIDERS, type Provider } from '../upstream/upstream.service';
import { PhotoRepository } from '../photos/photo.repository';
import { PhotoRefused, Photos } from '../photos/photos';
import { isUpload } from '../photos/upload';

const SESSION_COOKIE = 'ea_account';
const STATE_COOKIE = 'ea_account_state';

/** A sensitive change needs a sign-in this recent (account-plan.md AC-D2). */
export const FRESH_SECONDS = 10 * 60;

/** How far back Security activity looks (account-plan.md; retention is OQ-AC-5). */
const ACTIVITY_DAYS = 90;

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
  device_signed_out: 'That device has been signed out.',
  others_signed_out: 'Your other devices have been signed out.',
  two_step_on: '2-step verification is on.',
  two_step_off: '2-step verification is off.',
  codes_saved: 'New recovery codes are ready. Your old ones no longer work.',
  passkey_added: 'Passkey added. You can now sign in with it.',
  passkey_renamed: 'Passkey renamed.',
  passkey_removed: 'Passkey removed.',
  access_removed: 'Access removed. The app will ask you to sign in again next time.',
  unlinked: 'Unlinked. You can no longer sign in with that account.',
  photo: 'Your photo is saved.',
  photo_removed: 'Your photo is removed.',
};

/** Downloads of one's data an hour: plenty for a member, few enough to make scraping slow. */
const DOWNLOADS_PER_HOUR = 5;

/** Photo changes an hour: room to try a few, too few to use the bucket as storage. */
const PHOTOS_PER_HOUR = 20;

/** What a member gave an app, in plain words, by OpenID Connect scope. Others aren't shown. */
const SCOPE_WORDS: Record<string, string> = {
  openid: 'Know it’s you, by your Entity account ID',
  profile: 'See your name, language and photo',
  email: 'See your email address',
  phone: 'See your phone number',
  offline_access: 'Keep you signed in',
};

const ReturnTo = z
  .string()
  .regex(/^\/account(\/[a-z-]+){0,2}$/)
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
const TotpForm = z.object({ code: z.string().max(20) });
const PasskeyForm = z.object({ credential: z.string().min(2).max(40_000) });
const RenameForm = z.object({ id: z.string().uuid(), name: z.string().max(400) });
const AppForm = z.object({ id: z.string().min(1).max(255) });
const UnlinkForm = z.object({ provider: z.enum(['google', 'apple']) });

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
    private readonly apps: AccountApps,
    private readonly geo: GeoIp,
    private readonly mfa: MfaKeys,
    private readonly twoStepStore: TwoStepStore,
    private readonly passkeys: Passkeys,
    private readonly dataExport: DataExport,
    private readonly redis: RedisService,
    private readonly upstream: Upstream,
    private readonly hydra: HydraAdmin,
    private readonly photos: Photos,
    private readonly photoRecords: PhotoRepository,
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
    const [{ profile, identifiers }, apps] = await Promise.all([this.load(s), this.apps.list()]);
    await this.page(reply, s, 'account/home', 'Your account', 'home', {
      profile,
      identifiers,
      apps,
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
      language: LOCALES.find((l) => l.tag === profile.locale)?.label ?? profile.locale,
      done: flash(done),
    });
  }

  /** Name and language: the rows of Basic info lead here. */
  @Get('personal/edit')
  async editPersonal(@Req() req: FastifyRequest, @Res() reply: FastifyReply): Promise<void> {
    const s = await this.guard(req, reply, '/account/personal/edit');
    if (!s) return;
    const { profile, identifiers } = await this.load(s);
    await this.page(reply, s, 'account/personal-edit', 'Name and language', 'personal', {
      profile,
      identifiers,
      locales: LOCALES,
      error: null,
    });
  }

  /** How the member signs in: the password, and Google or Apple when linked. */
  @Get('security')
  async security(
    @Query('done') done: unknown,
    @Req() req: FastifyRequest,
    @Res() reply: FastifyReply,
  ): Promise<void> {
    const s = await this.guard(req, reply, '/account/security');
    if (!s) return;
    const [{ profile, identifiers }, sessions, events, twoStep, passkeys] = await Promise.all([
      this.load(s),
      this.identities.liveSessions(s.sub),
      this.identities.activity(s.sub, ACTIVITY_DAYS, 10),
      this.identities.twoStep(s.sub),
      this.identities.passkeys(s.sub),
    ]);
    await this.page(reply, s, 'account/security', 'Security & sign-in', 'security', {
      profile,
      identifiers,
      twoStep,
      twoStepAvailable: this.mfa.enabled,
      passkeyCount: passkeys.length,
      devices: devicesView(sessions, s.sid, this.geo.place).slice(0, 3),
      deviceCount: sessions.length,
      activity: activitiesView(events, this.geo.place).slice(0, 3),
      done: flash(done),
    });
  }

  // ---------------------------------------------------------------------------------------
  // Devices and security activity
  // ---------------------------------------------------------------------------------------

  /** Where the member is signed in. Signing a device out needs no fresh sign-in: it only ever helps. */
  @Get('devices')
  async devices(
    @Query('done') done: unknown,
    @Req() req: FastifyRequest,
    @Res() reply: FastifyReply,
  ): Promise<void> {
    const s = await this.guard(req, reply, '/account/devices');
    if (!s) return;
    const sessions = await this.identities.liveSessions(s.sub);
    await this.render(reply, s, 'account/devices', 'Your devices', 'security', {
      devices: devicesView(sessions, s.sid, this.geo.place),
      geoip: this.geo.enabled,
      done: flash(done),
    });
  }

  @Post('devices/sign-out')
  async signOutDevice(
    @Body() body: unknown,
    @Req() req: FastifyRequest,
    @Res() reply: FastifyReply,
  ): Promise<void> {
    const s = await this.guard(req, reply, '/account/devices');
    if (!s) return;
    const { id } = parse(IdForm, body);
    const ended = await this.db.tx(async (db) => {
      const gone = await this.identities.endDevice(db, s.sub, id, s.sid);
      if (gone) {
        await this.identities.event(
          {
            ...this.seen(req, s),
            kind: 'session_revoked',
            outcome: 'success',
            authSessionId: gone.id,
            detail: { device: describeDevice(gone.userAgent).name },
          },
          db,
        );
      }
      return gone;
    });
    // Already signed out, or not this member's: the list shows what is true now.
    if (!ended) {
      await redirect(reply, '/account/devices');
      return;
    }
    await this.sessionEnder.endAtHydra([ended.sid]);
    await redirect(reply, '/account/devices?done=device_signed_out');
  }

  @Post('devices/sign-out-others')
  async signOutOthers(@Req() req: FastifyRequest, @Res() reply: FastifyReply): Promise<void> {
    const s = await this.guard(req, reply, '/account/devices');
    if (!s) return;
    const ended = await this.db.tx(async (db) => {
      const sids = await this.identities.endOtherDevices(db, s.sub, s.sid);
      if (sids.length > 0) {
        await this.identities.event(
          {
            ...this.seen(req, s),
            kind: 'session_revoked',
            outcome: 'success',
            detail: { others: sids.length },
          },
          db,
        );
      }
      return sids;
    });
    await this.sessionEnder.endAtHydra(ended);
    await redirect(reply, `/account/devices${ended.length ? '?done=others_signed_out' : ''}`);
  }

  /** The last 90 days of the journal, in plain words (account-plan.md, Security activity). */
  @Get('activity')
  async activity(@Req() req: FastifyRequest, @Res() reply: FastifyReply): Promise<void> {
    const s = await this.guard(req, reply, '/account/activity');
    if (!s) return;
    const events = await this.identities.activity(s.sub, ACTIVITY_DAYS);
    await this.render(reply, s, 'account/activity', 'Security activity', 'security', {
      activity: activitiesView(events, this.geo.place),
      days: ACTIVITY_DAYS,
      geoip: this.geo.enabled,
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
        'account/personal-edit',
        'Name and language',
        'personal',
        {
          profile: { ...profile, displayName: name },
          identifiers,
          locales: LOCALES,
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

  /** Profile photo: shown here and, to apps given the profile scope, as the picture claim. */
  @Get('personal/photo')
  async photo(@Req() req: FastifyRequest, @Res() reply: FastifyReply): Promise<void> {
    const s = await this.guard(req, reply, '/account/personal/photo');
    if (!s) return;
    if (!this.photos.enabled) {
      await redirect(reply, '/account/personal');
      return;
    }
    await this.render(reply, s, 'account/personal-photo', 'Profile photo', 'personal', {
      error: null,
    });
  }

  @Post('personal/photo')
  async savePhoto(
    @Body() body: unknown,
    @Req() req: FastifyRequest,
    @Res() reply: FastifyReply,
  ): Promise<void> {
    const s = await this.guard(req, reply, '/account/personal/photo');
    if (!s) return;
    if (!this.photos.enabled) {
      await redirect(reply, '/account/personal');
      return;
    }
    const refuse = (error: string, status: number) =>
      this.render(
        reply,
        s,
        'account/personal-photo',
        'Profile photo',
        'personal',
        { error },
        status,
      );

    const upload = (body as { photo?: unknown } | undefined)?.photo;
    if (!isUpload(upload) || upload.data.length === 0) {
      await refuse('Choose a photo to upload.', 422);
      return;
    }
    if (upload.tooLarge) {
      await refuse('Choose a photo under 5 MB.', 413);
      return;
    }
    const key = `uni-auth:photo:${s.sub}`;
    const count = await this.redis.client.incr(key);
    if (count === 1) await this.redis.client.expire(key, 3600);
    if (count > PHOTOS_PER_HOUR) {
      await refuse(
        `You can change your photo ${PHOTOS_PER_HOUR} times an hour. Try again later.`,
        429,
      );
      return;
    }
    let stored: { key: string; bytes: number };
    try {
      stored = await this.photos.upload(upload.data);
    } catch (e) {
      if (e instanceof PhotoRefused) {
        await refuse(e.message, 422);
        return;
      }
      throw e;
    }
    await this.db.tx(async (db) => {
      await this.photoRecords.replace(db, s.sub, stored.key, stored.bytes);
      await this.identities.event(
        {
          ...this.seen(req, s),
          kind: 'profile_updated',
          outcome: 'success',
          detail: { fields: ['photo'] },
        },
        db,
      );
    });
    await redirect(reply, '/account/personal?done=photo');
  }

  @Post('personal/photo/remove')
  async removePhoto(@Req() req: FastifyRequest, @Res() reply: FastifyReply): Promise<void> {
    const s = await this.guard(req, reply, '/account/personal/photo');
    if (!s) return;
    const removed = await this.db.tx(async (db) => {
      if (!(await this.photoRecords.retire(db, s.sub))) return false;
      await this.identities.event(
        {
          ...this.seen(req, s),
          kind: 'profile_updated',
          outcome: 'success',
          detail: { fields: ['photo'], removed: true },
        },
        db,
      );
      return true;
    });
    await redirect(reply, removed ? '/account/personal?done=photo_removed' : '/account/personal');
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
        'personal',
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
  // 2-step verification (account-plan.md part 4)
  // ---------------------------------------------------------------------------------------

  /** Whether it is on, and what is set up. Changing anything needs a fresh sign-in (AC-D2). */
  @Get('two-step')
  async twoStep(
    @Query('done') done: unknown,
    @Req() req: FastifyRequest,
    @Res() reply: FastifyReply,
  ): Promise<void> {
    const s = await this.guard(req, reply, '/account/two-step');
    if (!s) return;
    await this.render(reply, s, 'account/two-step', '2-step verification', 'security', {
      twoStep: await this.identities.twoStep(s.sub),
      available: this.mfa.enabled,
      done: flash(done),
    });
  }

  /**
   * Step one of turning it on: a new seed as a QR code and as a key to type. The seed waits in
   * Redis, sealed, until a code from the app proves it was saved; a reload shows the same one.
   */
  @Get('two-step/setup')
  async twoStepSetup(@Req() req: FastifyRequest, @Res() reply: FastifyReply): Promise<void> {
    const s = await this.guard(req, reply, '/account/two-step/setup', { fresh: true });
    if (!s) return;
    if (!this.mfa.enabled || (await this.identities.hasTotp(s.sub))) {
      await redirect(reply, '/account/two-step');
      return;
    }
    await this.setupPage(reply, s);
  }

  @Post('two-step/setup')
  async enableTwoStep(
    @Body() body: unknown,
    @Req() req: FastifyRequest,
    @Res() reply: FastifyReply,
  ): Promise<void> {
    const s = await this.guard(req, reply, '/account/two-step/setup', { fresh: true });
    if (!s) return;
    const form = parse(TotpForm, body);
    const sealed = await this.twoStepStore.setup(s.id);
    if (!this.mfa.enabled || !sealed) {
      await redirect(reply, '/account/two-step/setup');
      return;
    }
    const step = matchStep(this.mfa.open(sealed, s.sub), form.code);
    if (step === null) {
      await this.setupPage(
        reply,
        s,
        "That code isn't right. Enter the 6-digit code your app shows now.",
      );
      return;
    }
    const codes = newCodes();
    try {
      await this.db.tx(async (db) => {
        await this.identities.enableTotp(db, {
          identityId: s.sub,
          sealed,
          step,
          codeHashes: codes.map((c) => this.mfa.hashCode(c)),
        });
        await this.identities.event(
          { ...this.seen(req, s), kind: 'mfa_enabled', outcome: 'success', credentialKind: 'totp' },
          db,
        );
      });
    } catch (err) {
      // On already (another tab got there first): the schema allows one authenticator.
      if ((err as { code?: string }).code !== '23505') throw err;
      await redirect(reply, '/account/two-step');
      return;
    }
    await this.twoStepStore.dropSetup(s.id);
    await this.notify(s.sub, '2-step verification was turned on', [
      '2-step verification is now on for your account. Signing in will also ask for a code from your authenticator app.',
      'Keep your recovery codes somewhere safe: they let you in if you lose your phone.',
    ]);
    await this.codesPage(reply, s, codes, true);
  }

  /** A new set of recovery codes; the old set stops working at once. */
  @Post('two-step/codes')
  async newRecoveryCodes(@Req() req: FastifyRequest, @Res() reply: FastifyReply): Promise<void> {
    const s = await this.guard(req, reply, '/account/two-step', { fresh: true });
    if (!s) return;
    if (!this.mfa.enabled || !(await this.identities.hasTotp(s.sub))) {
      await redirect(reply, '/account/two-step');
      return;
    }
    const codes = newCodes();
    await this.db.tx(async (db) => {
      await this.identities.replaceRecoveryCodes(
        db,
        s.sub,
        codes.map((c) => this.mfa.hashCode(c)),
      );
      await this.identities.event(
        {
          ...this.seen(req, s),
          kind: 'credential_added',
          outcome: 'success',
          credentialKind: 'recovery_codes',
          detail: { replaced: true },
        },
        db,
      );
    });
    await this.notify(s.sub, 'New recovery codes were made', [
      'A new set of recovery codes was made for your account. Your old recovery codes no longer work.',
    ]);
    await this.codesPage(reply, s, codes, false);
  }

  @Post('two-step/off')
  async disableTwoStep(@Req() req: FastifyRequest, @Res() reply: FastifyReply): Promise<void> {
    const s = await this.guard(req, reply, '/account/two-step', { fresh: true });
    if (!s) return;
    const off = await this.db.tx(async (db) => {
      const was = await this.identities.disableTotp(db, s.sub);
      if (was) {
        await this.identities.event(
          {
            ...this.seen(req, s),
            kind: 'mfa_disabled',
            outcome: 'success',
            credentialKind: 'totp',
          },
          db,
        );
      }
      return was;
    });
    if (!off) {
      await redirect(reply, '/account/two-step');
      return;
    }
    await this.notify(s.sub, '2-step verification was turned off', [
      '2-step verification was turned off for your account. Signing in now needs only your password or a code.',
      'Your recovery codes no longer work.',
    ]);
    await redirect(reply, '/account/two-step?done=two_step_off');
  }

  // ---------------------------------------------------------------------------------------
  // Passkeys (account-plan.md part 5)
  // ---------------------------------------------------------------------------------------

  @Get('passkeys')
  async passkeyList(
    @Query('done') done: unknown,
    @Req() req: FastifyRequest,
    @Res() reply: FastifyReply,
  ): Promise<void> {
    const s = await this.guard(req, reply, '/account/passkeys');
    if (!s) return;
    await this.render(reply, s, 'account/passkeys', 'Passkeys', 'security', {
      passkeys: await this.identities.passkeys(s.sub),
      done: flash(done),
    });
  }

  /** Adding one needs a fresh sign-in (AC-D2); the browser makes it (public/webauthn.js). */
  @Get('passkeys/add')
  async passkeyAdd(@Req() req: FastifyRequest, @Res() reply: FastifyReply): Promise<void> {
    const s = await this.guard(req, reply, '/account/passkeys/add', { fresh: true });
    if (!s) return;
    await this.passkeyAddPage(reply, s);
  }

  /**
   * navigator.credentials.create options. Asked for by the page's script, so a stale sign-in
   * is answered 401: the script reloads the page, whose guard asks the member to confirm.
   */
  @Get('passkeys/options')
  async passkeyOptions(@Req() req: FastifyRequest, @Res() reply: FastifyReply) {
    const s = await this.current(req);
    reply.header('cache-control', 'no-store');
    if (!s || !isFresh(s)) return reply.status(401).send({});
    return reply.send(await this.passkeys.addOptions(passkeyFlow(s), s.sub));
  }

  @Post('passkeys/add')
  async addPasskey(
    @Body() body: unknown,
    @Req() req: FastifyRequest,
    @Res() reply: FastifyReply,
  ): Promise<void> {
    const s = await this.guard(req, reply, '/account/passkeys/add', { fresh: true });
    if (!s) return;
    const form = parse(PasskeyForm, body);
    const made = await this.passkeys.verifyAdd(
      passkeyFlow(s),
      form.credential,
      req.headers['user-agent'] ?? null,
    );
    if (!made) {
      await this.passkeyAddPage(reply, s, "That passkey couldn't be saved. Try again.");
      return;
    }
    try {
      await this.db.tx(async (db) => {
        await this.identities.addPasskey(db, s.sub, made);
        await this.identities.event(
          {
            ...this.seen(req, s),
            kind: 'credential_added',
            outcome: 'success',
            credentialKind: 'passkey',
            detail: { name: made.nickname },
          },
          db,
        );
      });
    } catch (err) {
      const code = (err as { code?: string }).code;
      // 23505: already saved (sent twice). 23514: the twenty-passkey limit.
      if (code === '23505') {
        await redirect(reply, '/account/passkeys');
        return;
      }
      if (code !== '23514') throw err;
      await this.passkeyAddPage(
        reply,
        s,
        'You have 20 passkeys, the most an account can have. Remove one to add another.',
      );
      return;
    }
    await this.notify(s.sub, 'A passkey was added to your account', [
      `A passkey (“${made.nickname}”) was added to your account. It can now be used to sign in without a password.`,
    ]);
    await redirect(reply, '/account/passkeys?done=passkey_added');
  }

  @Get('passkeys/rename')
  async passkeyRename(
    @Query('id') id: unknown,
    @Req() req: FastifyRequest,
    @Res() reply: FastifyReply,
  ): Promise<void> {
    const s = await this.guard(req, reply, '/account/passkeys');
    if (!s) return;
    const passkey = await this.ownPasskey(s, id);
    if (!passkey) {
      await redirect(reply, '/account/passkeys');
      return;
    }
    await this.renamePage(reply, s, passkey.id, passkey.nickname);
  }

  /** A name only: no fresh sign-in needed. */
  @Post('passkeys/rename')
  async renamePasskey(
    @Body() body: unknown,
    @Req() req: FastifyRequest,
    @Res() reply: FastifyReply,
  ): Promise<void> {
    const s = await this.guard(req, reply, '/account/passkeys');
    if (!s) return;
    const form = parse(RenameForm, body);
    const name = form.name.trim().replace(/\s+/g, ' ');
    if (!name || Array.from(name).length > 60 || name.length > 60) {
      await this.renamePage(reply, s, form.id, form.name, 'Enter a name of up to 60 characters.');
      return;
    }
    if (!(await this.identities.renamePasskey(s.sub, form.id, name))) {
      await redirect(reply, '/account/passkeys');
      return;
    }
    await redirect(reply, '/account/passkeys?done=passkey_renamed');
  }

  @Post('passkeys/remove')
  async removePasskey(
    @Body() body: unknown,
    @Req() req: FastifyRequest,
    @Res() reply: FastifyReply,
  ): Promise<void> {
    const s = await this.guard(req, reply, '/account/passkeys', { fresh: true });
    if (!s) return;
    const { id } = parse(IdForm, body);
    const name = await this.db.tx(async (db) => {
      const was = await this.identities.removePasskey(db, s.sub, id);
      if (was) {
        await this.identities.event(
          {
            ...this.seen(req, s),
            kind: 'credential_revoked',
            outcome: 'success',
            credentialKind: 'passkey',
            detail: { name: was },
          },
          db,
        );
      }
      return was;
    });
    if (!name) {
      await redirect(reply, '/account/passkeys');
      return;
    }
    await this.notify(s.sub, 'A passkey was removed from your account', [
      `The passkey “${name}” was removed from your account. It can no longer be used to sign in.`,
    ]);
    await redirect(reply, '/account/passkeys?done=passkey_removed');
  }

  private async passkeyAddPage(
    reply: FastifyReply,
    s: AccountSession,
    error?: string,
  ): Promise<void> {
    await this.render(
      reply,
      s,
      'account/passkey-add',
      'Add a passkey',
      'security',
      { error: error ?? null },
      error ? 422 : 200,
    );
  }

  private async renamePage(
    reply: FastifyReply,
    s: AccountSession,
    id: string,
    name: string,
    error?: string,
  ): Promise<void> {
    await this.render(
      reply,
      s,
      'account/passkey-rename',
      'Rename passkey',
      'security',
      { id, name, error: error ?? null },
      error ? 422 : 200,
    );
  }

  private async ownPasskey(s: AccountSession, id: unknown) {
    const r = z.string().uuid().safeParse(id);
    if (!r.success) return null;
    return (await this.identities.passkeys(s.sub)).find((p) => p.id === r.data) ?? null;
  }

  private async setupPage(reply: FastifyReply, s: AccountSession, error?: string): Promise<void> {
    let sealed = await this.twoStepStore.setup(s.id);
    if (!sealed) {
      sealed = this.mfa.seal(newSeed(), s.sub);
      await this.twoStepStore.holdSetup(s.id, sealed);
    }
    const seed = this.mfa.open(sealed, s.sub);
    const account = (await this.identities.primaryIdentifier(s.sub))?.value ?? s.sub;
    const qr = await QRCode.toString(otpauthUri(seed, env.PROVIDER_NAME, account), {
      type: 'svg',
      errorCorrectionLevel: 'M',
      margin: 0,
      // Light modules see-through: the tile behind them (.qr) is the quiet zone and background.
      color: { dark: '#000000', light: '#0000' },
    });
    await this.render(
      reply,
      s,
      'account/two-step-setup',
      'Turn on 2-step verification',
      'security',
      { qr, key: grouped(base32(seed)), account, error: error ?? null },
      error ? 422 : 200,
    );
  }

  /** Shown once, straight from the request that made them: they are never stored readable. */
  private async codesPage(
    reply: FastifyReply,
    s: AccountSession,
    codes: string[],
    first: boolean,
  ): Promise<void> {
    const list = codes.map(shown);
    const file =
      `${env.PROVIDER_NAME} recovery codes\n` +
      `Each code works once, if you can't use your authenticator app.\n\n` +
      list.join('\n') +
      '\n';
    await this.render(reply, s, 'account/recovery-codes', 'Save your recovery codes', 'security', {
      codes: list,
      first,
      done: first ? DONE.two_step_on : null,
      download: `data:text/plain;charset=utf-8,${encodeURIComponent(file)}`,
    });
  }

  // ---------------------------------------------------------------------------------------
  // Linked apps (account-plan.md part 6): Google and Apple, and the apps using Entity
  // ---------------------------------------------------------------------------------------

  @Get('apps')
  async linkedApps(
    @Query('done') done: unknown,
    @Req() req: FastifyRequest,
    @Res() reply: FastifyReply,
  ): Promise<void> {
    const s = await this.guard(req, reply, '/account/apps');
    if (!s) return;
    const [linked, apps] = await Promise.all([
      this.identities.linkedProviders(s.sub),
      this.connectedApps(s.sub),
    ]);
    // Google and Apple: the linked ones, and the others this deployment offers.
    const providers = PROVIDERS.map((p) => {
      const link = linked.find((l) => l.kind === providerKind(p));
      return { id: p, name: providerLabel(p), linked: !!link, email: link?.email ?? null };
    }).filter((p) => p.linked || this.upstream.configured(p.id));
    await this.render(reply, s, 'account/apps', 'Linked apps', 'apps', {
      providers,
      apps,
      appsUnavailable: apps === null,
      done: flash(done),
    });
  }

  /** One app: what it can see, and removing its access. */
  @Get('apps/app')
  async linkedApp(
    @Query('id') id: unknown,
    @Req() req: FastifyRequest,
    @Res() reply: FastifyReply,
  ): Promise<void> {
    const s = await this.guard(req, reply, '/account/apps');
    if (!s) return;
    const app =
      typeof id === 'string' ? (await this.connectedApps(s.sub))?.find((a) => a.key === id) : null;
    if (!app) {
      await redirect(reply, '/account/apps');
      return;
    }
    await this.render(reply, s, 'account/app', app.name, 'apps', {
      app,
      access: app.scopes.map((sc) => SCOPE_WORDS[sc]).filter(Boolean),
    });
  }

  /**
   * Withdraws an app's access: Hydra revokes its consents and every token it holds for the
   * member. Other apps stay signed in. Like signing a device out, it only ever helps, so it needs
   * no fresh sign-in.
   */
  @Post('apps/remove')
  async removeApp(
    @Body() body: unknown,
    @Req() req: FastifyRequest,
    @Res() reply: FastifyReply,
  ): Promise<void> {
    const s = await this.guard(req, reply, '/account/apps');
    if (!s) return;
    const { id } = parse(AppForm, body);
    const app = (await this.connectedApps(s.sub))?.find((a) => a.key === id);
    if (!app) {
      await redirect(reply, '/account/apps');
      return;
    }
    for (const clientId of app.clientIds) {
      await this.hydra.revokeConsent(s.sub, clientId);
      await this.identities.event({
        ...this.seen(req, s),
        kind: 'consent_revoked',
        outcome: 'success',
        detail: { client: clientId, app: app.name },
      });
    }
    await redirect(reply, '/account/apps?done=access_removed');
  }

  /**
   * Unlinks Google or Apple. The member can still sign in: every identity keeps a verified
   * address for a code (0005), and usually a password or passkey too.
   */
  @Post('apps/unlink')
  async unlinkProvider(
    @Body() body: unknown,
    @Req() req: FastifyRequest,
    @Res() reply: FastifyReply,
  ): Promise<void> {
    const s = await this.guard(req, reply, '/account/apps', { fresh: true });
    if (!s) return;
    const { provider } = parse(UnlinkForm, body);
    const kind = providerKind(provider);
    const ended = await this.db.tx(async (db) => {
      const sids = await this.identities.unlinkProvider(db, s.sub, kind, s.sid);
      if (sids) {
        await this.identities.event(
          {
            ...this.seen(req, s),
            kind: 'credential_revoked',
            outcome: 'success',
            credentialKind: kind,
          },
          db,
        );
      }
      return sids;
    });
    if (!ended) {
      await redirect(reply, '/account/apps');
      return;
    }
    await this.sessionEnder.endAtHydra(ended);
    const name = providerLabel(provider);
    await this.notify(s.sub, `${name} was unlinked from your account`, [
      `Your ${name} account was unlinked from your ${env.PROVIDER_NAME} account. It can no longer be used to sign in.`,
      ...(ended.length
        ? [
            `${ended.length === 1 ? '1 device' : `${ended.length} devices`} signed in with ${name} ${ended.length === 1 ? 'was' : 'were'} signed out.`,
          ]
        : []),
    ]);
    await redirect(reply, '/account/apps?done=unlinked');
  }

  // ---------------------------------------------------------------------------------------
  // Data & privacy (account-plan.md part 6)
  // ---------------------------------------------------------------------------------------

  @Get('privacy')
  async privacy(
    @Query('done') done: unknown,
    @Req() req: FastifyRequest,
    @Res() reply: FastifyReply,
  ): Promise<void> {
    const s = await this.guard(req, reply, '/account/privacy');
    if (!s) return;
    await this.privacyPage(reply, s, { done: flash(done) });
  }

  /**
   * "Confirm it's you" comes back here before a download: the button that starts it, so the
   * file arrives on a page the member is looking at rather than at the end of a redirect.
   */
  @Get('privacy/download')
  async downloadPage(@Req() req: FastifyRequest, @Res() reply: FastifyReply): Promise<void> {
    const s = await this.guard(req, reply, '/account/privacy/download', { fresh: true });
    if (!s) return;
    await this.render(reply, s, 'account/privacy-download', 'Download your data', 'privacy', {});
  }

  /**
   * A copy of everything uni-auth holds about the member, as JSON, straight to the browser.
   * Nothing is stored. The journal records it and the member is told by email, so a download by
   * someone else on a signed-in device doesn't go unnoticed.
   */
  @Post('privacy/download')
  async download(@Req() req: FastifyRequest, @Res() reply: FastifyReply): Promise<void> {
    const s = await this.guard(req, reply, '/account/privacy/download', { fresh: true });
    if (!s) return;
    const key = `uni-auth:export:${s.sub}`;
    const count = await this.redis.client.incr(key);
    if (count === 1) await this.redis.client.expire(key, 3600);
    if (count > DOWNLOADS_PER_HOUR) {
      await this.privacyPage(
        reply,
        s,
        {
          error: `You can download your data ${DOWNLOADS_PER_HOUR} times an hour. Try again later.`,
        },
        429,
      );
      return;
    }
    const now = new Date();
    const data = await this.dataExport.build(s.sub, now);
    await this.identities.event({
      ...this.seen(req, s),
      kind: 'export_downloaded',
      outcome: 'success',
    });
    await this.notify(s.sub, 'A copy of your account data was downloaded', [
      `A copy of your ${env.PROVIDER_NAME} account data was downloaded from your account.`,
      "If this wasn't you, change your password and check your devices in your account now.",
    ]);
    const name = `${env.PROVIDER_NAME.toLowerCase().replace(/[^a-z0-9]+/g, '-')}-account-data-${now.toISOString().slice(0, 10)}.json`;
    await reply
      .status(200)
      .header('content-type', 'application/json; charset=utf-8')
      .header('content-disposition', `attachment; filename="${name}"`)
      .header('cache-control', 'no-store')
      .send(`${JSON.stringify(data, null, 2)}\n`);
  }

  /** Delete account, as a page: where "Confirm it's you" returns, and the dialog without script. */
  @Get('privacy/delete')
  async deletePage(@Req() req: FastifyRequest, @Res() reply: FastifyReply): Promise<void> {
    const s = await this.guard(req, reply, '/account/privacy/delete', { fresh: true });
    if (!s) return;
    await this.render(reply, s, 'account/privacy-delete', 'Delete your account', 'privacy', {
      graceDays: GRACE_DAYS,
    });
  }

  /**
   * Schedules the account's deletion 14 days on (OQ-AC-2) and signs the member out of every
   * device and app. Signing in again before then cancels it (SignIn); after, AccountDeletions
   * erases the identity and GSN is told.
   */
  @Post('privacy/delete')
  async deleteAccount(@Req() req: FastifyRequest, @Res() reply: FastifyReply): Promise<void> {
    const s = await this.guard(req, reply, '/account/privacy/delete', { fresh: true });
    if (!s) return;
    // Told before the sessions end: the address is still on the account either way.
    const { scheduledFor, ended } = await this.db.tx(async (db) => {
      const done = await this.identities.requestDeletion(db, s.sub);
      await this.identities.event(
        {
          ...this.seen(req, s),
          kind: 'deletion_requested',
          outcome: 'success',
          detail: { scheduled_for: done.scheduledFor.toISOString() },
        },
        db,
      );
      return done;
    });
    const on = longDate(scheduledFor);
    await this.notify(s.sub, 'Your account will be deleted', [
      `You asked us to delete your ${env.PROVIDER_NAME} account. It will be deleted on ${on}, and you've been signed out of every app that uses it.`,
      `Changed your mind? Sign in to any app with your ${env.PROVIDER_NAME} account before ${on} and the deletion is cancelled.`,
      "If you didn't ask for this, sign in now to keep your account, then change your password.",
    ]);
    await this.sessionEnder.endAtHydra(ended);
    await this.sessions.end(s.id);
    reply.clearCookie(SESSION_COOKIE, { path: '/account' });
    await render(reply, 'account/signed-out', 'Account deletion', {
      heading: 'Your account will be deleted',
      detail: `It will be deleted on ${on}, and you’ve been signed out everywhere. Changed your mind? Sign in before then to keep it.`,
    });
  }

  private async privacyPage(
    reply: FastifyReply,
    s: AccountSession,
    state: { done?: string | null; error?: string },
    status = 200,
  ): Promise<void> {
    await this.render(
      reply,
      s,
      'account/privacy',
      'Data & privacy',
      'privacy',
      {
        apps: await this.apps.list(),
        privacyUrl: env.PRIVACY_URL || null,
        termsUrl: env.TERMS_URL || null,
        graceDays: GRACE_DAYS,
        done: state.done ?? null,
        error: state.error ?? null,
      },
      status,
    );
  }

  /** The apps the member uses, or null when Hydra can't be asked: the page says so. */
  private async connectedApps(subject: string) {
    try {
      return await this.apps.connected(subject);
    } catch {
      return null;
    }
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
    await this.render(reply, s, 'account/contact-code', 'Confirm it', 'personal', {
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
      'personal',
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
      'security',
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
    const profile =
      (data.profile as Profile | undefined) ?? (await this.identities.profile(s.sub))!;
    const who =
      identifiers.find((r) => r.primary && r.kind === 'email') ??
      identifiers.find((r) => r.primary);
    await render(
      reply,
      view,
      title,
      {
        ...data,
        nav,
        who: who?.value ?? '',
        name: profile.displayName ?? '',
        initials: initials(profile.displayName, who?.value ?? ''),
        photo: await this.photos.path(s.sub),
        photos: this.photos.enabled,
        help: env.HELP_URL || null,
        csrfToken: reply.generateCsrf(),
      },
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

/** The passkey being added in this account session. */
const passkeyFlow = (s: AccountSession): string => `account-passkey:${s.id}`;

const phonesAccepted = (): boolean => env.WHATSAPP_DELIVERY !== 'off';

/** How long a deletion waits for the member to change their mind (0012; OQ-AC-2). */
const GRACE_DAYS = 14;

const providerKind = (p: Provider): 'oauth_google' | 'oauth_apple' =>
  p === 'google' ? 'oauth_google' : 'oauth_apple';
const providerLabel = (p: Provider): string => (p === 'google' ? 'Google' : 'Apple');

/** "2 December 2026", in UK time. */
const longDate = (d: Date): string =>
  d.toLocaleDateString('en-GB', {
    timeZone: 'Europe/London',
    day: 'numeric',
    month: 'long',
    year: 'numeric',
  });

const flash = (done: unknown): string | null =>
  typeof done === 'string' && Object.hasOwn(DONE, done) ? DONE[done]! : null;

/** One or two letters for the avatar: from the name, else the address. */
function initials(name: string | null, address: string): string {
  const words = (name ?? '').trim().split(/\s+/).filter(Boolean);
  if (words.length >= 2) return (words[0]![0]! + words[words.length - 1]![0]!).toUpperCase();
  if (words.length === 1) return Array.from(words[0]!)[0]!.toUpperCase();
  return (Array.from(address.replace(/^\+/, ''))[0] ?? '?').toUpperCase();
}
