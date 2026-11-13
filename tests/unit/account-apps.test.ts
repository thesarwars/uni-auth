import { describe, expect, it } from 'vitest';
import { appsFrom } from '../../src/account/account-apps';
import type { HydraClient } from '../../src/hydra/hydra-admin.service';

const client = (c: Partial<HydraClient> & { client_id: string }): HydraClient => ({
  client_name: '',
  client_uri: '',
  logo_uri: '',
  policy_uri: '',
  tos_uri: '',
  metadata: null,
  ...c,
});

describe('the account centre app list', () => {
  it('lists each first-party product with a home page once, with its logo', () => {
    const apps = appsFrom([
      client({
        client_id: 'gsn-web',
        client_name: 'Go Style Network',
        client_uri: 'https://gsn.gostyle.uk',
        metadata: { first_party: true, product: 'gsn' },
      }),
      // The same product's mobile client: no home page, and already listed.
      client({
        client_id: 'gsn-mobile',
        client_name: 'Go Style Network',
        metadata: { first_party: true, product: 'gsn' },
      }),
    ]);
    expect(apps).toEqual([
      { name: 'Go Style Network', url: 'https://gsn.gostyle.uk', logo: '/assets/clients/gsn.png' },
    ]);
  });

  it("leaves out Entity's own clients, third parties and unsafe links", () => {
    const apps = appsFrom([
      client({
        client_id: 'entity-auth-account',
        client_uri: 'https://uni-auth.gostyle.uk/account',
        metadata: { first_party: true, product: 'uni-auth' },
      }),
      client({
        client_id: 'partner',
        client_uri: 'https://partner.example',
        metadata: { product: 'partner' },
      }),
      client({
        client_id: 'bad',
        client_uri: 'javascript:alert(1)',
        metadata: { first_party: true, product: 'bad' },
      }),
    ]);
    expect(apps).toEqual([]);
  });
});
