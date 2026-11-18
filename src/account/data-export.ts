import { Injectable, Logger } from '@nestjs/common';
import { env } from '../config/env';
import { Database } from '../db/database.service';
import { HydraAdmin } from '../hydra/hydra-admin.service';

/**
 * "Download your data" (account-plan.md part 6; GDPR Articles 15 and 20): everything uni-auth
 * holds about one identity, as one JSON document - the account, its email addresses and phone
 * numbers, how it signs in, where it has been signed in, the journal, and the apps it has used.
 *
 * Nothing secret leaves: no password hash, authenticator seed, recovery code, passkey public key
 * or token. Each product keeps its own data (GSN's profile, orders and posts) and exports it
 * itself.
 *
 * Built in the request that asks for it and sent straight to the browser: nothing is stored.
 * When exports move to a background job and cloud storage, this stays the builder.
 */

/** A row as read: passed through to the file as it is, so its fields are never interpreted. */
type Row = Record<string, unknown>;

/** Bumped when a field changes meaning or goes away, for anyone reading these files by machine. */
export const EXPORT_FORMAT = 1;

@Injectable()
export class DataExport {
  private readonly logger = new Logger(DataExport.name);

  constructor(
    private readonly db: Database,
    private readonly hydra: HydraAdmin,
  ) {}

  async build(identityId: string, now = new Date()): Promise<Record<string, unknown>> {
    const [account, identifiers, methods, sessions, events, deletions, apps] = await Promise.all([
      this.db.rows<Row>(
        `SELECT id, status, display_name, locale, created_at FROM identity WHERE id = $1`,
        [identityId],
      ),
      this.db.rows<Row>(
        `SELECT kind, value, is_primary, verified_at, created_at, revoked_at
           FROM identity_identifier
          WHERE identity_id = $1 AND pii_scrubbed_at IS NULL
          ORDER BY created_at, id`,
        [identityId],
      ),
      this.db.rows<Row>(
        `SELECT c.kind, c.created_at, c.last_used_at, c.revoked_at, c.revoke_reason,
                c.provider_subject, c.provider_email, c.nickname, c.transports, c.aaguid,
                c.backup_eligible,
                CASE WHEN c.kind = 'recovery_codes' THEN
                  (SELECT count(*)::int FROM recovery_code r
                    WHERE r.credential_id = c.id AND r.used_at IS NULL) END AS codes_left
           FROM credential c
          WHERE c.identity_id = $1 AND c.pii_scrubbed_at IS NULL
          ORDER BY c.created_at, c.id`,
        [identityId],
      ),
      this.db.rows<Row>(
        `SELECT client_id, device_label, user_agent, host(ip_address) AS ip, geo_city, geo_country,
                created_at, last_seen_at, expires_at, revoked_at, revoke_reason
           FROM auth_session
          WHERE identity_id = $1
          ORDER BY created_at, id`,
        [identityId],
      ),
      this.db.rows<Row>(
        `SELECT occurred_at, kind, outcome, client_id, credential_kind, host(ip_address) AS ip,
                user_agent, detail
           FROM auth_event
          WHERE identity_id = $1
          ORDER BY occurred_at, id`,
        [identityId],
      ),
      this.db.rows<Row>(
        `SELECT requested_at, scheduled_for, cancelled_at, completed_at
           FROM account_deletion WHERE identity_id = $1 ORDER BY requested_at`,
        [identityId],
      ),
      this.apps(identityId),
    ]);
    const a = account[0]!;
    return {
      format: EXPORT_FORMAT,
      provider: env.PROVIDER_NAME,
      exported_at: now.toISOString(),
      about:
        `Everything ${env.PROVIDER_NAME} holds about your account. Passwords, authenticator ` +
        `keys, recovery codes and passkey keys are never included. Each app you use keeps its ` +
        `own data; ask the app for a copy of it.`,
      account: {
        id: a.id,
        status: a.status,
        name: a.display_name,
        language: a.locale,
        created_at: a.created_at,
      },
      email_addresses_and_phone_numbers: identifiers.map((r) => ({
        kind: r.kind,
        value: r.value,
        primary: r.is_primary,
        verified_at: r.verified_at,
        added_at: r.created_at,
        removed_at: r.revoked_at,
      })),
      sign_in_methods: methods.map(method),
      sessions: sessions.map((r) => ({
        app: r.client_id,
        device: r.device_label,
        user_agent: r.user_agent,
        ip_address: r.ip,
        city: r.geo_city,
        country: r.geo_country,
        signed_in_at: r.created_at,
        last_active_at: r.last_seen_at,
        expires_at: r.expires_at,
        ended_at: r.revoked_at,
        ended_because: r.revoke_reason,
      })),
      security_activity: events.map((r) => ({
        at: r.occurred_at,
        event: r.kind,
        outcome: r.outcome,
        app: r.client_id,
        method: r.credential_kind,
        ip_address: r.ip,
        user_agent: r.user_agent,
        detail: r.detail,
      })),
      apps: apps,
      deletion_requests: deletions,
    };
  }

  /** The apps the identity has signed in to, from Hydra; a note instead if Hydra can't say. */
  private async apps(identityId: string): Promise<unknown> {
    try {
      const consents = await this.hydra.listConsents(identityId);
      const byClient = new Map<
        string,
        { name: string; scopes: Set<string>; first: Date; last: Date }
      >();
      for (const c of consents) {
        const id = c.client.client_id;
        const seen = byClient.get(id);
        if (!seen) {
          byClient.set(id, {
            name: c.client.client_name || id,
            scopes: new Set(c.scopes),
            first: c.grantedAt,
            last: c.grantedAt,
          });
          continue;
        }
        c.scopes.forEach((s) => seen.scopes.add(s));
        if (c.grantedAt < seen.first) seen.first = c.grantedAt;
        if (c.grantedAt > seen.last) seen.last = c.grantedAt;
      }
      return [...byClient.entries()].map(([id, a]) => ({
        app: id,
        name: a.name,
        access: [...a.scopes].sort(),
        first_signed_in_at: a.first,
        last_signed_in_at: a.last,
      }));
    } catch (err) {
      this.logger.warn(`export: could not list apps: ${(err as Error).message}`);
      return 'Not available right now. Download again later to include the apps you use.';
    }
  }
}

/** A sign-in method, by what it is; never its secret. */
function method(r: Row): Record<string, unknown> {
  const common = {
    added_at: r.created_at,
    last_used_at: r.last_used_at,
    removed_at: r.revoked_at,
    removed_because: r.revoke_reason,
  };
  switch (r.kind) {
    case 'password':
      return { method: 'password', ...common };
    case 'oauth_google':
    case 'oauth_apple':
      return {
        method: r.kind === 'oauth_google' ? 'google' : 'apple',
        account_id: r.provider_subject,
        email: r.provider_email,
        ...common,
      };
    case 'passkey':
      return {
        method: 'passkey',
        name: r.nickname,
        syncs_between_devices: r.backup_eligible,
        authenticator_model: r.aaguid,
        transports: r.transports,
        ...common,
      };
    case 'totp':
      return { method: 'authenticator_app', ...common };
    case 'recovery_codes':
      return { method: 'recovery_codes', unused: r.codes_left, ...common };
    default:
      return { method: r.kind, ...common };
  }
}
