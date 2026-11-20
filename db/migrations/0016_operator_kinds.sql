-- The operator console (account-plan.md part 8): the journal's new events. Their own migration,
-- because a new enum value can't be used in the transaction that adds it (0017 uses them).

-- An operator suspended the identity: it can't sign in, and every session ended.
ALTER TYPE auth_event_kind ADD VALUE IF NOT EXISTS 'identity_suspended';
-- An operator lifted the suspension.
ALTER TYPE auth_event_kind ADD VALUE IF NOT EXISTS 'identity_reinstated';
