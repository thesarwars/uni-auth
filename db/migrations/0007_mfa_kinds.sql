-- 2-step verification (account-plan.md section 6, part 4), first of two migrations: the new
-- enum values. Postgres refuses a value in the transaction that added it, and each migration is
-- one transaction, so the rules that name these are in 0008_mfa.sql.

ALTER TYPE credential_kind ADD VALUE IF NOT EXISTS 'totp';
ALTER TYPE credential_kind ADD VALUE IF NOT EXISTS 'recovery_codes';

ALTER TYPE auth_event_kind ADD VALUE IF NOT EXISTS 'mfa_enabled';
ALTER TYPE auth_event_kind ADD VALUE IF NOT EXISTS 'mfa_disabled';
ALTER TYPE auth_event_kind ADD VALUE IF NOT EXISTS 'recovery_code_used';
