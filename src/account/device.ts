import { countryName, type Place } from '../geo/geoip.service';

/**
 * Plain words for the Devices and Security activity pages. Device names come from the user
 * agent, parsed here and nowhere else (account-plan.md AC-D6): no user agent leaves the
 * estate. Places come from the local GeoLite2 database (GeoIp), when there is one.
 */

/** No GeoIP database: every place unknown. */
export const noPlace: Place = () => null;

export type DeviceIcon = 'laptop' | 'mobile';

export interface Device {
  /** "iPhone", "Mac", "Windows PC" - what a member would call it. */
  name: string;
  /** "Chrome", "Safari" - or null when the user agent does not say. */
  browser: string | null;
  icon: DeviceIcon;
}

export function describeDevice(ua: string | null | undefined): Device {
  const s = ua ?? '';
  const name = deviceName(s);
  const icon: DeviceIcon = /iPhone|iPad|Android/.test(name) ? 'mobile' : 'laptop';
  return { name, browser: browserName(s), icon };
}

function deviceName(s: string): string {
  if (/iPhone/.test(s)) return 'iPhone';
  if (/iPad/.test(s)) return 'iPad';
  if (/Android/.test(s)) return /Mobile/.test(s) ? 'Android phone' : 'Android tablet';
  if (/CrOS/.test(s)) return 'Chromebook';
  if (/Macintosh|Mac OS X/.test(s)) return 'Mac';
  if (/Windows/.test(s)) return 'Windows PC';
  if (/Linux/.test(s)) return 'Linux PC';
  return 'Unknown device';
}

function browserName(s: string): string | null {
  if (/Edg(e|A|iOS)?\//.test(s)) return 'Edge';
  if (/OPR\/|Opera/.test(s)) return 'Opera';
  if (/SamsungBrowser\//.test(s)) return 'Samsung Internet';
  if (/Firefox\/|FxiOS\//.test(s)) return 'Firefox';
  if (/Chrome\/|CriOS\//.test(s)) return 'Chrome';
  if (/Safari\//.test(s) && /Version\//.test(s)) return 'Safari';
  return null;
}

/** Members are in the UK; every time on these pages is London time. */
const ZONE = 'Europe/London';

const dayKey = (d: Date) =>
  d.toLocaleDateString('en-GB', {
    timeZone: ZONE,
    year: 'numeric',
    month: '2-digit',
    day: '2-digit',
  });

/** "Today at 09:12", "Yesterday at 22:47", "3 Nov at 18:40", "3 Nov 2025 at 18:40". */
export function when(d: Date, now: Date = new Date()): string {
  const time = d.toLocaleTimeString('en-GB', {
    timeZone: ZONE,
    hour: '2-digit',
    minute: '2-digit',
  });
  if (dayKey(d) === dayKey(now)) return `Today at ${time}`;
  if (dayKey(d) === dayKey(new Date(now.getTime() - 86_400_000))) return `Yesterday at ${time}`;
  const sameYear =
    d.toLocaleDateString('en-GB', { timeZone: ZONE, year: 'numeric' }) ===
    now.toLocaleDateString('en-GB', { timeZone: ZONE, year: 'numeric' });
  const date = d.toLocaleDateString('en-GB', {
    timeZone: ZONE,
    day: 'numeric',
    month: 'short',
    ...(sameYear ? {} : { year: 'numeric' }),
  });
  return `${date} at ${time}`;
}

/** "Active now", "5 minutes ago", "2 hours ago", "Yesterday", "5 days ago". */
export function ago(d: Date, now: Date = new Date()): string {
  const minutes = Math.floor((now.getTime() - d.getTime()) / 60_000);
  if (minutes < 5) return 'Active now';
  if (minutes < 60) return `${minutes} minutes ago`;
  const hours = Math.floor(minutes / 60);
  if (hours < 24) return hours === 1 ? '1 hour ago' : `${hours} hours ago`;
  const days = Math.floor(hours / 24);
  return days === 1 ? 'Yesterday' : `${days} days ago`;
}

// ---------------------------------------------------------------------------------------------
// Devices
// ---------------------------------------------------------------------------------------------

export interface SessionRow {
  id: string;
  sid: string;
  userAgent: string | null;
  ip: string | null;
  /** Recorded at sign-in (0006_session_device.sql); null on a session opened before that. */
  deviceLabel?: string | null;
  geoCity?: string | null;
  geoCountry?: string | null;
  createdAt: Date;
  lastSeenAt: Date;
}

/**
 * Where a session was opened: the place recorded at sign-in, else (a session from before it
 * was recorded) a lookup of its address now.
 */
function sessionPlace(r: SessionRow, place: Place): string | null {
  return r.geoCity || countryName(r.geoCountry) || place(r.ip);
}

export interface DeviceView {
  id: string;
  name: string;
  icon: DeviceIcon;
  /** "Chrome, London. Active now." - browser and place, then how long since it was last used. */
  detail: string;
  current: boolean;
}

/** The member's signed-in devices, this one first, then the most recently used. */
export function devicesView(
  rows: SessionRow[],
  currentSid: string,
  place: Place = noPlace,
  now = new Date(),
): DeviceView[] {
  return [...rows]
    .sort(
      (a, b) =>
        Number(b.sid === currentSid) - Number(a.sid === currentSid) ||
        b.lastSeenAt.getTime() - a.lastSeenAt.getTime(),
    )
    .map((r) => {
      const d = describeDevice(r.userAgent);
      const current = r.sid === currentSid;
      const seen = current ? 'Active now' : ago(r.lastSeenAt, now);
      const where = [d.browser, sessionPlace(r, place)].filter(Boolean).join(', ');
      return {
        id: r.id,
        name: r.deviceLabel || d.name,
        icon: d.icon,
        detail: where ? `${where}. ${seen}.` : `${seen}.`,
        current,
      };
    });
}

// ---------------------------------------------------------------------------------------------
// Security activity
// ---------------------------------------------------------------------------------------------

export interface EventRow {
  kind: string;
  outcome: 'success' | 'failure';
  credentialKind: string | null;
  userAgent: string | null;
  ip: string | null;
  detail: Record<string, unknown>;
  occurredAt: Date;
}

export interface ActivityView {
  /** An icon in public/icons, without ".svg". */
  icon: string;
  title: string;
  /** "Today at 09:12, London" - or, with no place known, "Today at 09:12, Chrome on iPhone". */
  detail: string;
}

const PROVIDER: Record<string, string> = { oauth_google: 'Google', oauth_apple: 'Apple' };
const PROVIDER_ICON: Record<string, string> = { oauth_google: 'google', oauth_apple: 'apple' };

/** One journal row in plain words; null for a row the member has no use for. */
export function activityView(
  e: EventRow,
  place: Place = noPlace,
  now = new Date(),
): ActivityView | null {
  const device = describeDevice(e.userAgent);
  const on = e.userAgent
    ? device.browser
      ? `${device.browser} on ${device.name}`
      : device.name
    : null;
  const at = when(e.occurredAt, now);
  const where = place(e.ip) ?? on;
  const detail = where ? `${at}, ${where}` : at;
  const kindOf = (d: Record<string, unknown>) =>
    d.kind === 'phone' ? 'Phone number' : 'Email address';
  const what = describe();
  return what ? { ...what, detail } : null;

  function describe(): Omit<ActivityView, 'detail'> | null {
    switch (e.kind) {
      case 'sign_in':
        return e.outcome === 'success'
          ? { icon: device.icon, title: e.userAgent ? `Signed in on ${device.name}` : 'Signed in' }
          : { icon: 'alert-circle', title: 'Failed sign-in attempt' };
      case 'lockout':
        return { icon: 'alert-circle', title: 'Sign-in paused after too many attempts' };
      case 'sign_out':
        return {
          icon: device.icon,
          title: e.userAgent ? `Signed out on ${device.name}` : 'Signed out',
        };
      case 'session_revoked': {
        const n = typeof e.detail.others === 'number' ? e.detail.others : null;
        const name = typeof e.detail.device === 'string' ? e.detail.device : null;
        return {
          icon: 'logout',
          title:
            n !== null
              ? n === 1
                ? 'Signed out of 1 other device'
                : `Signed out of ${n} other devices`
              : name
                ? `Signed out of ${name}`
                : 'Signed out of a device',
        };
      }
      case 'password_changed':
        return { icon: 'lock-20', title: 'Password changed' };
      case 'password_reset':
        return { icon: 'lock-20', title: 'Password reset' };
      case 'mfa_enabled':
        return { icon: 'shield-20', title: '2-step verification turned on' };
      case 'mfa_disabled':
        return { icon: 'shield-20', title: '2-step verification turned off' };
      case 'recovery_code_used':
        return { icon: 'key', title: 'Recovery code used to sign in' };
      case 'credential_added':
        if (e.credentialKind === 'recovery_codes') {
          return { icon: 'key', title: 'New recovery codes made' };
        }
        if (e.credentialKind === 'passkey') return { icon: 'key', title: 'Passkey added' };
        if (e.credentialKind && PROVIDER[e.credentialKind]) {
          return {
            icon: PROVIDER_ICON[e.credentialKind]!,
            title: `${PROVIDER[e.credentialKind]} linked`,
          };
        }
        return { icon: 'lock-20', title: 'Password set' };
      case 'credential_revoked':
        if (e.credentialKind === 'passkey') return { icon: 'key', title: 'Passkey removed' };
        if (e.credentialKind && PROVIDER[e.credentialKind]) {
          return {
            icon: PROVIDER_ICON[e.credentialKind]!,
            title: `${PROVIDER[e.credentialKind]} unlinked`,
          };
        }
        return { icon: 'lock-20', title: 'Password removed' };
      case 'identifier_added':
        return { icon: 'mail', title: `${kindOf(e.detail)} added` };
      case 'identifier_verified':
        return { icon: 'mail', title: `${kindOf(e.detail)} confirmed` };
      case 'identifier_removed':
        return { icon: 'mail', title: `${kindOf(e.detail)} removed` };
      case 'profile_updated':
        return e.detail.primary
          ? {
              icon: 'mail',
              title: `Primary ${kindOf({ kind: e.detail.primary }).toLowerCase()} changed`,
            }
          : { icon: 'shield-20', title: 'Name or language changed' };
      case 'identity_created':
        return { icon: 'shield-20', title: 'Account created' };
      default:
        return null;
    }
  }
}

export function activitiesView(
  rows: EventRow[],
  place: Place = noPlace,
  now = new Date(),
): ActivityView[] {
  return rows.map((r) => activityView(r, place, now)).filter((v): v is ActivityView => v !== null);
}
