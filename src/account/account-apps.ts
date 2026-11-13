import { Injectable, Logger } from '@nestjs/common';
import { clientLogo } from '../flows/assets.controller';
import { HydraAdmin, type HydraClient } from '../hydra/hydra-admin.service';

export interface AccountApp {
  name: string;
  url: string;
  logo: string | null;
}

/** Hydra's clients change only when deploy/hydra/ is applied, so a few minutes' cache is plenty. */
const CACHE_MS = 5 * 60 * 1000;

/**
 * The apps an Entity account signs in to, for the account centre's home: every first-party
 * client with a home page (client_uri), one per product - the web and mobile clients of one
 * product are one app. Entity's own clients (product uni-auth) are left out. A new app appears
 * here once its client file in deploy/hydra/ has a client_uri.
 */
@Injectable()
export class AccountApps {
  private readonly logger = new Logger(AccountApps.name);
  private cached: { at: number; apps: AccountApp[] } | null = null;

  constructor(private readonly hydra: HydraAdmin) {}

  async list(): Promise<AccountApp[]> {
    if (this.cached && Date.now() - this.cached.at < CACHE_MS) return this.cached.apps;
    try {
      const apps = appsFrom(await this.hydra.listClients());
      this.cached = { at: Date.now(), apps };
      return apps;
    } catch (err) {
      // The list is a convenience: the page shows without it rather than failing.
      this.logger.warn(`could not list apps: ${(err as Error).message}`);
      return this.cached?.apps ?? [];
    }
  }
}

export function appsFrom(clients: HydraClient[]): AccountApp[] {
  const byProduct = new Map<string, AccountApp>();
  for (const c of clients) {
    const meta = c.metadata ?? {};
    const product = typeof meta.product === 'string' ? meta.product : '';
    if (meta.first_party !== true || !product || product === 'uni-auth') continue;
    if (byProduct.has(product) || !isWebUrl(c.client_uri)) continue;
    byProduct.set(product, {
      name: c.client_name || product,
      url: c.client_uri,
      logo: clientLogo(product),
    });
  }
  return [...byProduct.values()].sort((a, b) => a.name.localeCompare(b.name));
}

function isWebUrl(s: string): boolean {
  try {
    const u = new URL(s);
    return u.protocol === 'https:' || u.protocol === 'http:';
  } catch {
    return false;
  }
}
