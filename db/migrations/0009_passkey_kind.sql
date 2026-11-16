-- Passkeys (account-plan.md section 6, part 5), first of two migrations: the new enum value.
-- Postgres refuses a value in the transaction that added it, so the rules that name it are in
-- 0010_passkey.sql.

ALTER TYPE credential_kind ADD VALUE IF NOT EXISTS 'passkey';
