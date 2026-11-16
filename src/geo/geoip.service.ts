import { Injectable, Logger, type OnModuleDestroy, type OnModuleInit } from '@nestjs/common';
import { existsSync } from 'node:fs';
import { isIP } from 'node:net';
import { open, type CityResponse, type Reader } from 'maxmind';
import { env } from '../config/env';

/** Where an IP address is, in words a member knows: a city, else a country. */
export type Place = (ip: string | null | undefined) => string | null;

/** What a session records at sign-in: the city, and the country as ISO 3166-1 alpha-2. */
export interface Located {
  city: string | null;
  country: string | null;
}

/**
 * Approximate location from a local MaxMind GeoLite2 City database (account-plan.md AC-D6,
 * OQ-AC-8): the lookup happens here, so no address is ever sent to a third party. The file is
 * kept up to date by MaxMind's geoipupdate (docker-compose.prod.yml) and re-read when it
 * changes. With no database, every place is unknown and the pages simply leave it out.
 */
@Injectable()
export class GeoIp implements OnModuleInit, OnModuleDestroy {
  private readonly logger = new Logger(GeoIp.name);
  private reader: Reader<CityResponse> | null = null;

  private waiting: NodeJS.Timeout | null = null;

  async onModuleInit(): Promise<void> {
    const path = env.GEOIP_DB_PATH;
    if (!path) return;
    if (await this.load(path)) return;
    // geoipupdate's first download can land after this starts: look again each minute.
    this.logger.warn(`GEOIP_DB_PATH ${path} not there yet; locations are left out until it is`);
    this.waiting = setInterval(() => {
      void this.load(path).then((ok) => {
        if (ok && this.waiting) {
          clearInterval(this.waiting);
          this.waiting = null;
        }
      });
    }, 60_000);
    this.waiting.unref();
  }

  onModuleDestroy(): void {
    if (this.waiting) clearInterval(this.waiting);
  }

  private async load(path: string): Promise<boolean> {
    if (!existsSync(path)) return false;
    try {
      // Re-read whenever geoipupdate replaces the file.
      this.reader = await open<CityResponse>(path, { watchForUpdates: true });
      this.logger.log(`GeoIP database loaded from ${path}`);
      return true;
    } catch (err) {
      this.logger.warn(`could not open ${path}: ${(err as Error).message}`);
      return false;
    }
  }

  get enabled(): boolean {
    return this.reader !== null;
  }

  readonly place: Place = (ip) => placeOf(this.find(ip));

  /** The city and country code to record with a new session; both null when unknown. */
  locate(ip: string | null | undefined): Located {
    return locatedOf(this.find(ip));
  }

  private find(ip: string | null | undefined): CityResponse | null {
    if (!this.reader || !ip || !isIP(ip)) return null;
    try {
      return this.reader.get(ip);
    } catch {
      return null;
    }
  }
}

export function locatedOf(r: CityResponse | null | undefined): Located {
  const city = r?.city?.names?.en?.slice(0, 100) || null;
  const iso = r?.country?.iso_code;
  return { city, country: iso && /^[A-Z]{2}$/.test(iso) ? iso : null };
}

const regions = new Intl.DisplayNames(['en'], { type: 'region' });

/** "GB" -> "United Kingdom"; null for no code. */
export function countryName(code: string | null | undefined): string | null {
  if (!code) return null;
  try {
    return regions.of(code) ?? null;
  } catch {
    return null;
  }
}

/** The English city name, else the country's; null for a private or unknown address. */
export function placeOf(r: CityResponse | null | undefined): string | null {
  return r?.city?.names?.en ?? r?.country?.names?.en ?? null;
}
