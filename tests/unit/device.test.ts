import { describe, expect, it } from 'vitest';
import { activityView, ago, describeDevice, devicesView, when } from '../../src/account/device';

const UA = {
  macChrome:
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36',
  iphoneSafari:
    'Mozilla/5.0 (iPhone; CPU iPhone OS 18_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.1 Mobile/15E148 Safari/604.1',
  windowsEdge:
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36 Edg/131.0.0.0',
  androidChrome:
    'Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Mobile Safari/537.36',
  linuxFirefox: 'Mozilla/5.0 (X11; Linux x86_64; rv:133.0) Gecko/20100101 Firefox/133.0',
};

describe('describeDevice', () => {
  it('names the device and browser from the user agent', () => {
    expect(describeDevice(UA.macChrome)).toEqual({
      name: 'Mac',
      browser: 'Chrome',
      icon: 'laptop',
    });
    expect(describeDevice(UA.iphoneSafari)).toEqual({
      name: 'iPhone',
      browser: 'Safari',
      icon: 'mobile',
    });
    expect(describeDevice(UA.windowsEdge)).toEqual({
      name: 'Windows PC',
      browser: 'Edge',
      icon: 'laptop',
    });
    expect(describeDevice(UA.androidChrome)).toEqual({
      name: 'Android phone',
      browser: 'Chrome',
      icon: 'mobile',
    });
    expect(describeDevice(UA.linuxFirefox).browser).toBe('Firefox');
  });

  it('says so when it cannot tell', () => {
    expect(describeDevice(null)).toEqual({ name: 'Unknown device', browser: null, icon: 'laptop' });
  });
});

describe('when and ago', () => {
  const now = new Date('2026-11-16T12:00:00Z');

  it('reads as today, yesterday, or a date, in London time', () => {
    expect(when(new Date('2026-11-16T09:12:00Z'), now)).toBe('Today at 09:12');
    expect(when(new Date('2026-11-15T22:47:00Z'), now)).toBe('Yesterday at 22:47');
    expect(when(new Date('2026-11-03T18:40:00Z'), now)).toBe('3 Nov at 18:40');
    expect(when(new Date('2025-11-03T18:40:00Z'), now)).toBe('3 Nov 2025 at 18:40');
    // British Summer Time: an hour ahead of UTC.
    expect(when(new Date('2026-07-01T08:30:00Z'), now)).toBe('1 Jul at 09:30');
  });

  it('counts time since last use', () => {
    const before = (ms: number) => new Date(now.getTime() - ms);
    expect(ago(before(60_000), now)).toBe('Active now');
    expect(ago(before(20 * 60_000), now)).toBe('20 minutes ago');
    expect(ago(before(2 * 3_600_000), now)).toBe('2 hours ago');
    expect(ago(before(30 * 3_600_000), now)).toBe('Yesterday');
    expect(ago(before(5 * 86_400_000), now)).toBe('5 days ago');
  });
});

describe('devicesView', () => {
  it('puts this device first and the rest by last use', () => {
    const now = new Date('2026-11-16T12:00:00Z');
    const row = (id: string, ua: string, hoursAgo: number) => ({
      id,
      sid: `sid-${id}`,
      userAgent: ua,
      createdAt: new Date(now.getTime() - 86_400_000 * 10),
      lastSeenAt: new Date(now.getTime() - hoursAgo * 3_600_000),
    });
    const v = devicesView(
      [row('a', UA.windowsEdge, 120), row('b', UA.iphoneSafari, 2), row('c', UA.macChrome, 30)],
      'sid-c',
      now,
    );
    expect(v.map((d) => [d.name, d.detail, d.current])).toEqual([
      ['Mac', 'Chrome. Active now.', true],
      ['iPhone', 'Safari. 2 hours ago.', false],
      ['Windows PC', 'Edge. 5 days ago.', false],
    ]);
  });
});

describe('activityView', () => {
  const now = new Date('2026-11-16T12:00:00Z');
  const ev = (over: Partial<Parameters<typeof activityView>[0]>) =>
    activityView(
      {
        kind: 'sign_in',
        outcome: 'success',
        credentialKind: null,
        userAgent: UA.iphoneSafari,
        detail: {},
        occurredAt: new Date('2026-11-16T09:12:00Z'),
        ...over,
      },
      now,
    );

  it('puts each event in plain words', () => {
    expect(ev({})).toEqual({
      icon: 'mobile',
      title: 'Signed in on iPhone',
      detail: 'Today at 09:12, Safari on iPhone',
    });
    expect(ev({ outcome: 'failure' })!.title).toBe('Failed sign-in attempt');
    expect(ev({ kind: 'password_changed' })!.title).toBe('Password changed');
    expect(ev({ kind: 'credential_added', credentialKind: 'oauth_google' })).toMatchObject({
      icon: 'google',
      title: 'Google linked',
    });
    expect(ev({ kind: 'credential_added', credentialKind: 'password' })!.title).toBe(
      'Password set',
    );
    expect(ev({ kind: 'identifier_added', detail: { kind: 'phone' } })!.title).toBe(
      'Phone number added',
    );
    expect(ev({ kind: 'profile_updated', detail: { primary: 'email' } })!.title).toBe(
      'Primary email address changed',
    );
    expect(ev({ kind: 'session_revoked', detail: { others: 3 } })!.title).toBe(
      'Signed out of 3 other devices',
    );
    expect(ev({ kind: 'session_revoked', detail: { device: 'Mac' } })!.title).toBe(
      'Signed out of Mac',
    );
  });

  it('leaves out what it has no words for', () => {
    expect(ev({ kind: 'something_new' })).toBeNull();
  });
});
