#!/usr/bin/env bash
# A deployment's one-time work, run by the `setup` service of docker-compose.prod.yml before
# the login application starts. Every step is idempotent, so it runs on every `up`:
#   1. the identity database's migrations, as the owner
#   2. the login role the application connects as
#   3. ES256 signing keys (once; rotation is docs/key-rotation.md)
#   4. the clients in deploy/hydra/clients.prod/, from their definitions
set -euo pipefail
cd "$(dirname "$0")/.."

node scripts/db-migrate.mjs
node scripts/db-login-role.mjs
scripts/hydra-keys.sh
scripts/hydra-clients.sh
echo "setup: done"
