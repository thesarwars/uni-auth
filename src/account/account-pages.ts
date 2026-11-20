import { Injectable } from '@nestjs/common';
import type { FastifyReply, FastifyRequest } from 'fastify';
import { redirect, render } from '../common/pages';
import { env } from '../config/env';
import {
  IdentityRepository,
  type IdentifierRow,
  type Profile,
} from '../identity/identity.repository';
import { OperatorRepository } from '../operator/operator.repository';
import { Photos } from '../photos/photos';
import { AccountOidc } from './account-oidc';
import { AccountSessions, type AccountSession } from './account-sessions';

export const SESSION_COOKIE = 'ea_account';
export const STATE_COOKIE = 'ea_account_state';

/** A sensitive change needs a sign-in this recent (account-plan.md AC-D2). */
export const FRESH_SECONDS = 10 * 60;

export const isFresh = (s: AccountSession): boolean =>
  Date.now() / 1000 - s.authTime <= FRESH_SECONDS;

/** RFC 8176's names for a passkey: one kept in a device, or one synced between them. */
export const signedInWithPasskey = (s: AccountSession): boolean =>
  (s.amr ?? []).some((m) => m === 'hwk' || m === 'swk');

/**
 * What every page under /account shares: the account session the cookie names, sending the
 * browser to sign in, and the page itself with the member in its top bar. The account centre
 * and the operator console both use it.
 */
@Injectable()
export class AccountPages {
  constructor(
    private readonly oidc: AccountOidc,
    private readonly sessions: AccountSessions,
    private readonly identities: IdentityRepository,
    private readonly photos: Photos,
    private readonly operators: OperatorRepository,
  ) {}

  /** The signed-in member, or null. */
  async current(req: FastifyRequest): Promise<AccountSession | null> {
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

  /** To the sign-in screen, and back to `returnTo`; with `confirm`, "Confirm it's you". */
  async startSignIn(
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

  setSession(reply: FastifyReply, s: AccountSession): void {
    reply.setCookie(SESSION_COOKIE, s.id, {
      signed: true,
      httpOnly: true,
      path: '/account',
      maxAge: 12 * 60 * 60,
      sameSite: 'lax',
      secure: env.NODE_ENV === 'production',
    });
  }

  /** An account page: `view` inside the account layout, with `nav` marked as where they are. */
  async render(
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
        // Operators see the console in the menu; no one else learns it exists.
        operator: (await this.operators.live(s.sub)) !== null,
        help: env.HELP_URL || null,
        csrfToken: reply.generateCsrf(),
      },
      status,
    );
  }
}

function initials(name: string | null, address: string): string {
  const words = (name ?? '').trim().split(/\s+/).filter(Boolean);
  if (words.length >= 2) return (words[0]![0]! + words[words.length - 1]![0]!).toUpperCase();
  if (words.length === 1) return Array.from(words[0]!)[0]!.toUpperCase();
  return (Array.from(address.replace(/^\+/, ''))[0] ?? '?').toUpperCase();
}
