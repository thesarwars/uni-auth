import { Injectable, Logger } from '@nestjs/common';
import { env } from '../config/env';
import { clientLogo } from '../flows/assets.controller';
import { HydraAdmin, type HydraClient } from '../hydra/hydra-admin.service';

export interface AccountApp {
  name: string;
  url: string;
  logo: string | null;
  /** Where the app shows and exports its own data: metadata.data_uri, else its home page. */
  dataUrl: string;
  /** What data the app keeps, in a few words (metadata.data_summary), for Data & privacy. */
  dataSummary: string | null;
}

/** An app the member has signed in to, for Linked apps: one per product. */
export interface ConnectedApp {
  /** The product, or for an app outside Entity's own, its client id. */
  key: string;
  name: string;
  logo: string | null;
  clientIds: string[];
  scopes: string[];
  since: Date;
}

/** Hydra's clients change only when deploy/hydra/ is applied, so a few minutes' cache is plenty. */
const CACHE_MS = 5 * 60 * 1000;

/**
 * The apps an Entity account signs in to, for the account centre's home: every first-party
 * client with a home page (client_uri), one per product - the web and mobile clients of one
 * product are one app. Entity's own clients (product uni-auth) are left out. A new app appears
 * here once its client file in deploy/hydra/ has a client_uri.
 *
 * A member here is already signed in to Entity, so the tile should sign them in to the app
 * too, not land on its sign-in page. An app that can start a sign-in on request names that
 * page in its client metadata as `initiate_login_uri` (OpenID Connect Core section 4,
 * third-party initiated login); the tile goes there with `iss`, the app starts its usual
 * authorization request, and Hydra finds the Entity session and sends the member straight
 * back signed in. Without one, the tile opens the app's home page.
 *
 * Data & privacy lists the same apps under "Data in other apps": each keeps its own data, and
 * `data_uri` in its metadata names the page where the member manages it (its home page until
 * it has one); `data_summary` says what it keeps, in a few words.
 */
@Injectable()
export class AccountApps {
  private readonly logger = new Logger(AccountApps.name);
  private cached: { at: number; apps: AccountApp[] } | null = null;

  constructor(private readonly hydra: HydraAdmin) {}

  /**
   * The apps the member has signed in to with Entity and not removed, from the consents Hydra
   * holds (one per authorization, single sign-on included), oldest first. Entity's own clients
   * are left out: the account centre is not an app the member could remove.
   */
  async connected(subject: string): Promise<ConnectedApp[]> {
    const byKey = new Map<string, ConnectedApp>();
    for (const c of await this.hydra.listConsents(subject)) {
      const meta = c.client.metadata ?? {};
      const product = typeof meta.product === 'string' ? meta.product : '';
      if (product === 'uni-auth') continue;
      const firstParty = meta.first_party === true && product !== '';
      const key = firstParty ? product : c.client.client_id;
      const app = byKey.get(key);
      if (!app) {
        byKey.set(key, {
          key,
          name: c.client.client_name || c.client.client_id,
          logo: firstParty ? clientLogo(product) : null,
          clientIds: [c.client.client_id],
          scopes: [...new Set(c.scopes)],
          since: c.grantedAt,
        });
        continue;
      }
      if (!app.clientIds.includes(c.client.client_id)) app.clientIds.push(c.client.client_id);
      for (const s of c.scopes) if (!app.scopes.includes(s)) app.scopes.push(s);
      if (c.grantedAt < app.since) app.since = c.grantedAt;
    }
    return [...byKey.values()].sort((a, b) => a.since.getTime() - b.since.getTime());
  }

  async list(): Promise<AccountApp[]> {
    if (this.cached && Date.now() - this.cached.at < CACHE_MS) return this.cached.apps;
    try {
      const apps = appsFrom(await this.hydra.listClients(), env.HYDRA_PUBLIC_URL);
      this.cached = { at: Date.now(), apps };
      return apps;
    } catch (err) {
      // The list is a convenience: the page shows without it rather than failing.
      this.logger.warn(`could not list apps: ${(err as Error).message}`);
      return this.cached?.apps ?? [];
    }
  }
}

export function appsFrom(clients: HydraClient[], issuer: string): AccountApp[] {
  const byProduct = new Map<string, AccountApp>();
  for (const c of clients) {
    const meta = c.metadata ?? {};
    const product = typeof meta.product === 'string' ? meta.product : '';
    if (meta.first_party !== true || !product || product === 'uni-auth') continue;
    if (byProduct.has(product) || !isWebUrl(c.client_uri)) continue;
    const initiate = typeof meta.initiate_login_uri === 'string' ? meta.initiate_login_uri : '';
    const dataUri =
      typeof meta.data_uri === 'string' && isWebUrl(meta.data_uri) ? meta.data_uri : '';
    const summary = typeof meta.data_summary === 'string' ? meta.data_summary.slice(0, 120) : '';
    byProduct.set(product, {
      name: c.client_name || product,
      url: isWebUrl(initiate) ? withIssuer(initiate, issuer) : c.client_uri,
      logo: clientLogo(product),
      dataUrl: dataUri || c.client_uri,
      dataSummary: summary || null,
    });
  }
  return [...byProduct.values()].sort((a, b) => a.name.localeCompare(b.name));
}

/** The initiate-login URL with `iss`, the issuer the app should start its sign-in at. */
function withIssuer(uri: string, issuer: string): string {
  const u = new URL(uri);
  u.searchParams.set('iss', issuer.replace(/\/$/, ''));
  return u.toString();
}

function isWebUrl(s: string): boolean {
  try {
    const u = new URL(s);
    return u.protocol === 'https:' || u.protocol === 'http:';
  } catch {
    return false;
  }
}
