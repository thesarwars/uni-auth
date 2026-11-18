import { describe, expect, it } from 'vitest';
import { appsFrom } from '../../src/account/account-apps';
import type { HydraClient } from '../../src/hydra/hydra-admin.service';

const ISSUER = 'https://uni-auth.gostyle.uk';

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
    const apps = appsFrom(
      [
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
      ],
      ISSUER,
    );
    expect(apps).toEqual([
      {
        name: 'Go Style Network',
        url: 'https://gsn.gostyle.uk',
        logo: expect.stringMatching(/^\/assets\/clients\/gsn\.png\?v=[0-9a-f]{12}$/),
        // No data_uri or data_summary: Data & privacy links to its home page, with no summary.
        dataUrl: 'https://gsn.gostyle.uk',
        dataSummary: null,
      },
    ]);
  });

  it("leaves out Entity's own clients, third parties and unsafe links", () => {
    const apps = appsFrom(
      [
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
      ],
      ISSUER,
    );
    expect(apps).toEqual([]);
  });

  it("goes to the app's initiate-login page, with the issuer, when it has one", () => {
    const apps = appsFrom(
      [
        client({
          client_id: 'gsn-web',
          client_name: 'Go Style Network',
          client_uri: 'https://gsn.gostyle.uk',
          metadata: {
            first_party: true,
            product: 'gsn',
            initiate_login_uri: 'https://gsn.gostyle.uk/login',
          },
        }),
        client({
          client_id: 'other-web',
          client_name: 'Other',
          client_uri: 'https://other.example',
          metadata: { first_party: true, product: 'other', initiate_login_uri: 'javascript:x' },
        }),
      ],
      `${ISSUER}/`,
    );
    expect(apps.map((a) => a.url)).toEqual([
      'https://gsn.gostyle.uk/login?iss=https%3A%2F%2Funi-auth.gostyle.uk',
      'https://other.example',
    ]);
  });
});
