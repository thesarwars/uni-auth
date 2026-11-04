# Deploying uni-auth with Docker

Everything runs from the repository with one command. Hydra, its database, the identity
database, Redis and the login application are all containers. nginx on the host terminates TLS.

```
                 https://uni-auth.gostyle.uk  (nginx, TLS)
                 ├── /oauth2/*, /.well-known/*, /userinfo  ->  127.0.0.1:4444  Hydra (public)
                 ├── /hooks/*                              ->  404
                 └── everything else                       ->  127.0.0.1:3120  login application
```

Hydra's admin API (port 4445) is published on no interface. Only the login application and the
setup job reach it, inside the compose network (AU-2).

## The hosts

| Setting          | Example                      | What it is                                   |
| ---------------- | ---------------------------- | -------------------------------------------- |
| `UNI_AUTH_HOST`  | `uni-auth.gostyle.uk`        | uni-auth itself: the issuer and the screens. |
| `GSN_WEB_ORIGIN` | `https://gsn.gostyle.uk`     | The GSN web app (a client).                  |
| `GSN_API_URL`    | `https://gsn-api.gostyle.uk` | The GSN api, which trusts uni-auth's tokens. |

uni-auth needs its own host. That host is the token issuer, so it must not move once members
have signed in, because every token and session is tied to it.

## First time on the VPS

1. **DNS.** Add an A record for `UNI_AUTH_HOST` pointing at the VPS.
2. **Configuration.**
   ```sh
   cd /home/gsn/uni-auth
   cp .env.prod.example .env
   nano .env                     # the hosts, SMTP_PASS (the Resend API key)
   scripts/prod-secrets.sh       # fills every secret with a random value, once
   ```
   Back up `.env` somewhere safe. `HYDRA_SECRETS_SYSTEM` encrypts the signing keys: if it is
   lost, every member must sign in again. The database passwords must keep matching the
   volumes they created.
3. **Start.**
   ```sh
   docker compose up --build -d
   ```
   `.env` sets `COMPOSE_FILE=docker-compose.prod.yml`, so the plain command uses the
   production file. The `setup` service runs before the login application on every start.
   It applies the identity migrations, sets the database login role, creates the ES256
   signing keys if there are none, and registers the clients in `deploy/hydra/clients.prod/`.
   It is safe to repeat.
4. **nginx.**
   ```sh
   sudo cp deploy/nginx/uni-auth.conf /etc/nginx/sites-available/uni-auth.conf
   sudo sed -i 's/uni-auth.gostyle.uk/<UNI_AUTH_HOST>/g' /etc/nginx/sites-available/uni-auth.conf
   sudo ln -s /etc/nginx/sites-available/uni-auth.conf /etc/nginx/sites-enabled/
   sudo nginx -t && sudo systemctl reload nginx
   sudo certbot --nginx -d <UNI_AUTH_HOST>
   ```
5. **Check.**
   ```sh
   docker compose ps                                         # every service healthy, setup exited 0
   curl https://<UNI_AUTH_HOST>/.well-known/openid-configuration   # "issuer": "https://<UNI_AUTH_HOST>"
   curl -o /dev/null -w '%{http_code}\n' https://<UNI_AUTH_HOST>/hooks/refresh   # 404
   ```

## The products that trust it

- **GSN api** (`.env` of the api deployment): `UNI_AUTH_ISSUER=https://<UNI_AUTH_HOST>`.
  Without it the api ignores uni-auth's tokens.
- **GSN web** (build-time): `VITE_UNI_AUTH_ISSUER=https://<UNI_AUTH_HOST>`,
  `VITE_UNI_AUTH_CLIENT_ID=gsn-web`, `VITE_UNI_AUTH_AUDIENCE=gsn-api`.

The `gsn-web` client accepts exactly `${GSN_WEB_ORIGIN}/callback` as its redirect URI and
`${GSN_WEB_ORIGIN}/` after sign-out. A different origin needs a change to
`deploy/hydra/clients.prod/gsn-web.json` and a restart.

## Day to day

| Task                    | Command                                                                                                                |
| ----------------------- | ---------------------------------------------------------------------------------------------------------------------- |
| Update to a new version | `git pull && docker compose up --build -d`                                                                             |
| Logs                    | `docker compose logs -f login hydra`                                                                                   |
| Restart the application | `docker compose restart login`                                                                                         |
| Rotate the signing keys | `docker compose run --rm setup scripts/hydra-keys.sh --rotate` (then docs/key-rotation.md)                             |
| Back up the databases   | `docker compose exec identity-db pg_dump -U uni_auth_owner identity > identity.sql` (and `hydra-db`, `-U hydra hydra`) |

## Choices

- **Email codes** go through Resend's SMTP relay. Production refuses `EMAIL_DELIVERY=log`
  because a code in a log file is a credential.
- **Phone numbers** are refused (`WHATSAPP_DELIVERY=off`) until WhatsApp delivery is set up.
  The screens ask for an email address only.
- **Hydra runs without `--dev`.** The issuer is https, cookies are `Secure`, and nginx's
  `X-Forwarded-Proto: https` is believed only from private addresses
  (`hydra.prod.yml serve.tls.allow_termination_from`). The ports are bound to 127.0.0.1, so
  only the host's nginx can reach them.
- **Client addresses.** The login application believes `X-Forwarded-For` only from the
  compose network (`TRUSTED_PROXIES` = `UNI_AUTH_SUBNET`), which is how nginx's connection
  arrives. The per-address sign-in throttle therefore sees the member's own address.
