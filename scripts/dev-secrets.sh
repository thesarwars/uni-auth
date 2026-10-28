#!/usr/bin/env bash
# Writes the local .env: random secrets and the login application's local settings. Adds any
# key that is missing and never changes one that is set - losing HYDRA_SECRETS_SYSTEM makes
# the stored signing keys unreadable.
set -euo pipefail
cd "$(dirname "$0")/.."
umask 077
touch .env
rand() { openssl rand -hex 32; }
add() { grep -q "^$1=" .env || { echo "$1=$2" >> .env; echo "added $1"; }; }

add HYDRA_DB_PASSWORD "$(rand)"
add HYDRA_SECRETS_SYSTEM "$(rand)"
add HYDRA_SECRETS_COOKIE "$(rand)"
add UNI_AUTH_SERVICE_SECRET "$(rand)"
add COOKIE_SECRET "$(rand)"
add HYDRA_ADMIN_URL "http://127.0.0.1:4445"
add DEV_TEST_SUBJECT "dev-member"
