-- Account recovery without a second factor (account-plan.md part 7): the journal's new events.
-- Their own migration, because a new enum value can't be used in the transaction that adds it
-- (0014 uses them).

-- A member who can't use any of their 2-step methods asked for 2-step verification to be removed.
ALTER TYPE auth_event_kind ADD VALUE IF NOT EXISTS 'mfa_recovery_requested';
-- The request was cancelled: by the link in its email, or by signing in with a 2-step method.
ALTER TYPE auth_event_kind ADD VALUE IF NOT EXISTS 'mfa_recovery_cancelled';
-- An administrator of the product refused it.
ALTER TYPE auth_event_kind ADD VALUE IF NOT EXISTS 'mfa_recovery_rejected';
-- The waiting period passed (and, where needed, it was approved): 2-step verification removed.
ALTER TYPE auth_event_kind ADD VALUE IF NOT EXISTS 'mfa_recovery_completed';
