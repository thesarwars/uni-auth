-- Data and privacy (account-plan.md section 6, part 6), first of two migrations: the new journal
-- kinds. Postgres refuses a value in the transaction that added it, and each migration is one
-- transaction, so the rules that name these are in 0012_data_privacy.sql.

-- The member downloaded a copy of their data.
ALTER TYPE auth_event_kind ADD VALUE IF NOT EXISTS 'export_downloaded';
-- The member asked for their account to be deleted, or cancelled that by signing in again.
ALTER TYPE auth_event_kind ADD VALUE IF NOT EXISTS 'deletion_requested';
ALTER TYPE auth_event_kind ADD VALUE IF NOT EXISTS 'deletion_cancelled';
-- The member removed an app's access to their account.
ALTER TYPE auth_event_kind ADD VALUE IF NOT EXISTS 'consent_revoked';
