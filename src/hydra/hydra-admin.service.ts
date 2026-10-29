import { Injectable } from '@nestjs/common';
import { z } from 'zod';
import { env } from '../config/env';

/**
 * Hydra's admin API, the half of the protocol this application answers. Hydra hands every
 * sign-in, consent and sign-out to us as a challenge; we read it here and accept or reject it,
 * and Hydra tells us where to send the browser next.
 *
 * Only the fields this application reads are parsed; the rest of each response is ignored.
 */

const Client = z.object({
  client_id: z.string(),
  client_name: z.string().optional().default(''),
  logo_uri: z.string().optional().default(''),
  metadata: z.record(z.string(), z.unknown()).nullish(),
});
export type HydraClient = z.infer<typeof Client>;

const LoginRequest = z.object({
  challenge: z.string(),
  skip: z.boolean(),
  subject: z.string(),
  client: Client,
  requested_scope: z.array(z.string()).nullish(),
  /** Hydra's login session id: the `sid` of every token this sign-in issues. */
  session_id: z.string().nullish(),
  /** The authorize URL that started the flow; following it again starts a fresh one. */
  request_url: z.string().nullish(),
});
export type LoginRequest = z.infer<typeof LoginRequest>;

const ConsentRequest = z.object({
  challenge: z.string(),
  skip: z.boolean().nullish(),
  subject: z.string(),
  client: Client,
  requested_scope: z.array(z.string()).nullish(),
  requested_access_token_audience: z.array(z.string()).nullish(),
  login_session_id: z.string().nullish(),
  acr: z.string().nullish(),
  amr: z.array(z.string()).nullish(),
  context: z.record(z.string(), z.unknown()).nullish(),
});
export type ConsentRequest = z.infer<typeof ConsentRequest>;

const LogoutRequest = z.object({
  challenge: z.string(),
  subject: z.string().nullish(),
  sid: z.string().nullish(),
  rp_initiated: z.boolean().nullish(),
  client: Client.nullish(),
});
export type LogoutRequest = z.infer<typeof LogoutRequest>;

const Redirect = z.object({ redirect_to: z.string().url() });

/** A challenge Hydra does not know: expired, forged, or from another provider. */
export class UnknownChallenge extends Error {
  constructor() {
    super('unknown or expired challenge');
  }
}

/**
 * A challenge Hydra reports as already answered (410), with where the browser belongs now;
 * sending it there is always safe, because the URL is Hydra's.
 *
 * Hydra v25 rarely says so for a login: its challenges are stateless, so one read back after
 * use still parses and the page renders again. That is not a replay hole - the flow is bound
 * to a CSRF cookie in the browser that started it, and Hydra refuses it anywhere else
 * (tests/e2e/flows.e2e.test.ts).
 */
export class HandledChallenge extends Error {
  constructor(readonly redirectTo: string) {
    super('challenge already handled');
  }
}

type Flow = 'login' | 'consent' | 'logout';

@Injectable()
export class HydraAdmin {
  getLogin(challenge: string): Promise<LoginRequest> {
    return this.get('login', challenge, LoginRequest);
  }

  acceptLogin(
    challenge: string,
    body: {
      subject: string;
      remember?: boolean;
      remember_for?: number;
      acr?: string;
      amr?: string[];
      context?: Record<string, unknown>;
    },
  ): Promise<string> {
    return this.put('login', challenge, 'accept', body);
  }

  rejectLogin(challenge: string, error: string, description: string): Promise<string> {
    return this.put('login', challenge, 'reject', { error, error_description: description });
  }

  /**
   * Ends one provider session at Hydra: its cookie stops granting single sign-on, so the next
   * authorize request shows the sign-in screen.
   */
  async revokeLoginSession(sid: string): Promise<void> {
    await this.call('DELETE', `/admin/oauth2/auth/sessions/login?sid=${enc(sid)}`);
  }

  getConsent(challenge: string): Promise<ConsentRequest> {
    return this.get('consent', challenge, ConsentRequest);
  }

  acceptConsent(
    challenge: string,
    body: {
      grant_scope: string[];
      grant_access_token_audience: string[];
      remember?: boolean;
      remember_for?: number;
      session: { access_token: Record<string, unknown>; id_token: Record<string, unknown> };
    },
  ): Promise<string> {
    return this.put('consent', challenge, 'accept', body);
  }

  rejectConsent(challenge: string, error: string, description: string): Promise<string> {
    return this.put('consent', challenge, 'reject', { error, error_description: description });
  }

  getLogout(challenge: string): Promise<LogoutRequest> {
    return this.get('logout', challenge, LogoutRequest);
  }

  acceptLogout(challenge: string): Promise<string> {
    return this.put('logout', challenge, 'accept');
  }

  /** Hydra answers a rejected logout with no redirect: the member simply stays signed in. */
  async rejectLogout(challenge: string): Promise<void> {
    await this.call(
      'PUT',
      `/admin/oauth2/auth/requests/logout/reject?logout_challenge=${enc(challenge)}`,
    );
  }

  async ready(): Promise<boolean> {
    try {
      const res = await fetch(`${env.HYDRA_ADMIN_URL}/health/ready`, {
        signal: AbortSignal.timeout(2000),
      });
      return res.ok;
    } catch {
      return false;
    }
  }

  private async get<S extends z.ZodTypeAny>(
    flow: Flow,
    challenge: string,
    schema: S,
  ): Promise<z.output<S>> {
    const res = await this.call(
      'GET',
      `/admin/oauth2/auth/requests/${flow}?${flow}_challenge=${enc(challenge)}`,
    );
    return schema.parse(await res.json());
  }

  private async put(
    flow: Flow,
    challenge: string,
    verb: 'accept' | 'reject',
    body?: unknown,
  ): Promise<string> {
    const res = await this.call(
      'PUT',
      `/admin/oauth2/auth/requests/${flow}/${verb}?${flow}_challenge=${enc(challenge)}`,
      body,
    );
    return Redirect.parse(await res.json()).redirect_to;
  }

  private async call(
    method: 'GET' | 'PUT' | 'DELETE',
    path: string,
    body?: unknown,
  ): Promise<Response> {
    const res = await fetch(`${env.HYDRA_ADMIN_URL}${path}`, {
      method,
      headers: body === undefined ? {} : { 'content-type': 'application/json' },
      body: body === undefined ? undefined : JSON.stringify(body),
      signal: AbortSignal.timeout(5000),
    });
    if (res.ok) return res;
    if (res.status === 404 || res.status === 400) throw new UnknownChallenge();
    if (res.status === 410) {
      const handled = Redirect.safeParse(await res.json().catch(() => null));
      if (handled.success) throw new HandledChallenge(handled.data.redirect_to);
      throw new UnknownChallenge();
    }
    throw new Error(
      `Hydra admin ${method} ${path.split('?')[0]}: ${res.status} ${await res.text()}`,
    );
  }
}

const enc = encodeURIComponent;
