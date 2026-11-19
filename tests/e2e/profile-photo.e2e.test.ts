import type { NestFastifyApplication } from '@nestjs/platform-fastify';
import sharp from 'sharp';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { PhotoCleanup } from '../../src/photos/photo-cleanup';
import { PhotoStore } from '../../src/photos/photo-store';
import { Limits } from '../../src/limits/limits';
import { RedisService } from '../../src/redis/redis.service';
import { startApp } from '../support/app';
import {
  APP,
  authorizeUrl,
  browser,
  claims,
  exchange,
  formFields,
  pkce,
  type Browser,
  type Hop,
} from '../support/browser';
import { closeMembers, createMember, sql, type Member } from '../support/members';

/**
 * Profile photos: added, changed and removed in Personal info, kept in the bucket as a 256px WebP
 * with nothing of the original's metadata, served only while current, and given to apps that ask
 * for the profile scope as the picture claim.
 */

let app: NestFastifyApplication;
let store: PhotoStore;
let cleanup: PhotoCleanup;

beforeAll(async () => {
  app = await startApp();
  store = app.get(PhotoStore);
  cleanup = app.get(PhotoCleanup);
});
afterAll(async () => {
  await app?.close();
  await closeMembers();
});

const csrf = (page: Hop): string => /name="_csrf" value="([^"]+)"/.exec(page.html)![1]!;
const open = async (b: Browser, path: string): Promise<Hop> =>
  (await b.follow(`${APP}${path}`)).hop;
const photoPath = (html: string): string | null =>
  /<img src="(\/photos\/[A-Za-z0-9_-]{22}\.webp)"/.exec(html)?.[1] ?? null;

async function accountSignIn(m: Member, b: Browser = browser()): Promise<Browser> {
  let { hop: page } = await b.follow(`${APP}/account`);
  page = await b.post(`${APP}/login`, {
    ...formFields(page.html),
    action: 'identify',
    identifier: m.email,
  });
  page = await b.post(`${APP}/login`, {
    ...formFields(page.html),
    action: 'password',
    password: m.password,
  });
  expect(page.status).toBe(303);
  await b.follow(page.location!);
  return b;
}

/** A landscape photo, as a phone takes it: a JPEG with the camera and the place in its EXIF. */
const jpeg = (colour = '#c0392b') =>
  sharp({ create: { width: 900, height: 600, channels: 3, background: colour } })
    .jpeg()
    .withExif({
      IFD0: { Make: 'TestCam', Model: 'Phone 1' },
      IFD3: { GPSLatitudeRef: 'N', GPSLatitude: '51/1 30/1 0/1' },
    })
    .toBuffer();

async function upload(b: Browser, data: Buffer, name = 'me.jpg', type = 'image/jpeg') {
  const page = await open(b, '/account/personal/photo');
  const form = new FormData();
  form.set('_csrf', csrf(page));
  form.set('photo', new Blob([new Uint8Array(data)], { type }), name);
  return b.upload(`${APP}/account/personal/photo`, form);
}

describe('Profile photo', () => {
  it('starts as initials, with a Photo row in Basic info', async () => {
    const b = await accountSignIn(await createMember());
    const personal = await open(b, '/account/personal');
    expect(personal.html).toContain('href="/account/personal/photo"');
    expect(personal.html).toContain('Add a photo');
    expect(photoPath(personal.html)).toBeNull();
    const page = await open(b, '/account/personal/photo');
    expect(page.status).toBe(200);
    expect(page.html).toContain('<h1 id="title">Profile photo</h1>');
    expect(page.html).toContain('enctype="multipart/form-data"');
    expect(page.html).not.toContain('Remove photo');
  });

  it('is stored as a 256px WebP with no metadata, and shown in the account centre', async () => {
    const m = await createMember();
    const b = await accountSignIn(m);
    const res = await upload(b, await jpeg());
    expect(res.status).toBe(303);
    expect(new URL(res.location!).pathname + new URL(res.location!).search).toBe(
      '/account/personal?done=photo',
    );

    const personal = await open(b, '/account/personal?done=photo');
    expect(personal.html).toContain('Your photo is saved.');
    const path = photoPath(personal.html)!;
    expect(path).not.toBeNull();
    // The top bar and the home page show it too.
    const home = await open(b, '/account');
    expect(home.html.split(path).length - 1).toBe(2);

    const served = await fetch(`${APP}${path}`);
    expect(served.status).toBe(200);
    expect(served.headers.get('content-type')).toBe('image/webp');
    expect(served.headers.get('cache-control')).toBe('public, max-age=86400');
    const meta = await sharp(Buffer.from(await served.arrayBuffer())).metadata();
    expect(meta).toMatchObject({ format: 'webp', width: 256, height: 256 });
    expect(meta.exif).toBeUndefined();

    const [event] = await sql(
      `SELECT detail FROM auth_event WHERE identity_id = $1 AND kind = 'profile_updated'`,
      [m.identityId],
    );
    expect(event!.detail).toEqual({ fields: ['photo'] });
    const activity = await open(b, '/account/activity');
    expect(activity.html).toContain('Profile photo changed');
  });

  it('serves only the current photo; the cleanup deletes replaced ones from the bucket', async () => {
    const m = await createMember();
    const b = await accountSignIn(m);
    await upload(b, await jpeg('#2980b9'));
    const first = photoPath((await open(b, '/account/personal')).html)!;
    await upload(b, await jpeg('#27ae60'));
    const second = photoPath((await open(b, '/account/personal')).html)!;
    expect(second).not.toBe(first);

    expect((await fetch(`${APP}${first}`)).status).toBe(404);
    expect((await fetch(`${APP}${second}`)).status).toBe(200);
    expect(await store.get(first.slice(1))).not.toBeNull(); // not yet deleted

    await cleanup.run();
    expect(await store.get(first.slice(1))).toBeNull();
    expect(await store.get(second.slice(1))).not.toBeNull();
    const rows = await sql(
      `SELECT object_key, replaced_at IS NOT NULL AS replaced, object_deleted_at IS NOT NULL AS deleted
         FROM identity_photo WHERE identity_id = $1 ORDER BY created_at`,
      [m.identityId],
    );
    expect(rows).toEqual([
      { object_key: first.slice(1), replaced: true, deleted: true },
      { object_key: second.slice(1), replaced: false, deleted: false },
    ]);
  });

  it('can be removed, back to initials', async () => {
    const m = await createMember();
    const b = await accountSignIn(m);
    await upload(b, await jpeg());
    let page = await open(b, '/account/personal/photo');
    expect(page.html).toContain('Remove photo');
    const path = photoPath(page.html)!;
    const res = await b.post(`${APP}/account/personal/photo/remove`, { _csrf: csrf(page) });
    expect(res.status).toBe(303);
    expect(res.location).toContain('/account/personal?done=photo_removed');
    page = await open(b, '/account/personal?done=photo_removed');
    expect(page.html).toContain('Your photo is removed.');
    expect(photoPath(page.html)).toBeNull();
    expect((await fetch(`${APP}${path}`)).status).toBe(404);
    expect((await open(b, '/account/activity')).html).toContain('Profile photo removed');
  });

  it('refuses what isn’t a usable photo, saying why', async () => {
    const b = await accountSignIn(await createMember());
    const text = await upload(b, Buffer.from('not an image at all'), 'notes.txt', 'text/plain');
    expect(text.status).toBe(422);
    expect(text.html).toContain('That file isn’t a photo we can use. Choose a JPEG, PNG or WebP.');

    const gif = await sharp({ create: { width: 10, height: 10, channels: 3, background: '#000' } })
      .gif()
      .toBuffer();
    const refusedGif = await upload(b, gif, 'a.gif', 'image/gif');
    expect(refusedGif.status).toBe(422);

    const big = await upload(b, Buffer.alloc(5 * 1024 * 1024 + 10, 1));
    expect(big.status).toBe(413);
    expect(big.html).toContain('Choose a photo under 5 MB.');

    const empty = await upload(b, Buffer.alloc(0), '');
    expect(empty.status).toBe(422);
    expect(empty.html).toContain('Choose a photo to upload.');

    expect(photoPath((await open(b, '/account/personal')).html)).toBeNull();
  });

  it('needs the form’s CSRF token', async () => {
    const b = await accountSignIn(await createMember());
    const form = new FormData();
    form.set('photo', new Blob([new Uint8Array(await jpeg())], { type: 'image/jpeg' }), 'me.jpg');
    const res = await b.upload(`${APP}/account/personal/photo`, form);
    expect(res.status).toBe(403);
    expect(photoPath((await open(b, '/account/personal')).html)).toBeNull();
  });

  it('is changed at most 20 times an hour', async () => {
    const m = await createMember();
    const b = await accountSignIn(m);
    await app
      .get(RedisService)
      .client.set(app.get(Limits).key('photo', m.identityId), '20', 'EX', 3600);
    const res = await upload(b, await jpeg());
    expect(res.status).toBe(429);
    expect(res.html).toContain('You can change your photo 20 times an hour.');
  });

  it('is the picture claim for an app given the profile scope, and only then', async () => {
    const m = await createMember();
    const b = await accountSignIn(m);
    await upload(b, await jpeg());
    const path = photoPath((await open(b, '/account/personal')).html)!;

    const idToken = async (scope: string) => {
      const { verifier, challenge } = pkce();
      const { url } = await b.follow(authorizeUrl(challenge, { scope }));
      const code = new URL(url).searchParams.get('code')!;
      const tokens = await exchange(code, verifier);
      expect(tokens.status).toBe(200);
      return claims(tokens.body.id_token as string);
    };
    expect((await idToken('openid offline_access profile')).picture).toBe(`${APP}${path}`);
    expect((await idToken('openid offline_access')).picture).toBeUndefined();
  });

  it('is in the data download, and goes when the account is erased', async () => {
    const m = await createMember();
    const b = await accountSignIn(m);
    await upload(b, await jpeg());
    const path = photoPath((await open(b, '/account/personal')).html)!;

    const privacy = await open(b, '/account/privacy');
    const file = await b.post(`${APP}/account/privacy/download`, { _csrf: csrf(privacy) });
    expect(file.status).toBe(200);
    const data = JSON.parse(file.html) as { profile_photos: { url: string | null }[] };
    expect(data.profile_photos).toEqual([
      expect.objectContaining({ url: `${APP}${path}`, replaced_at: null }),
    ]);

    await sql(`UPDATE identity SET status = 'closed' WHERE id = $1`, [m.identityId]);
    await sql(`UPDATE identity SET erased_at = now() WHERE id = $1`, [m.identityId]);
    expect((await fetch(`${APP}${path}`)).status).toBe(404);
    await cleanup.run();
    expect(await store.get(path.slice(1))).toBeNull();
  });

  it('is never served by a name that isn’t one', async () => {
    expect((await fetch(`${APP}/photos/..%2F..%2Fetc%2Fpasswd`)).status).toBe(404);
    expect((await fetch(`${APP}/photos/AAAAAAAAAAAAAAAAAAAAAA.webp`)).status).toBe(404);
  });
});
