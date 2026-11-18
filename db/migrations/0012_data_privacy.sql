-- Data and privacy (account-plan.md section 6, part 6): deleting an account, with a grace period.
--
-- "Delete account" in the account centre does not erase at once. It writes an account_deletion
-- row due 14 days later (OQ-AC-2) and signs the member out everywhere. Signing in again before
-- then cancels it. When it falls due, the login application closes and erases the identity
-- through the path that already exists (0001: identity_effects; 0004: identity_notice), so GSN
-- hears of it as it would of any erasure.
--
-- Downloading a copy of one's data stores nothing: the file is built and sent in the request
-- that asks for it, and only the journal records it (export_downloaded).

CREATE TABLE account_deletion (
  id            uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  identity_id   uuid NOT NULL REFERENCES identity(id) ON DELETE RESTRICT,
  requested_at  timestamptz NOT NULL DEFAULT now(),
  scheduled_for timestamptz NOT NULL,
  cancelled_at  timestamptz,
  completed_at  timestamptz,
  CONSTRAINT account_deletion_grace CHECK (scheduled_for = requested_at + interval '14 days'),
  CONSTRAINT account_deletion_one_end CHECK (cancelled_at IS NULL OR completed_at IS NULL),
  CONSTRAINT account_deletion_ends_after_start
    CHECK ((cancelled_at IS NULL OR cancelled_at >= requested_at)
       AND (completed_at IS NULL OR completed_at >= requested_at))
);
-- At most one deletion waits per identity.
CREATE UNIQUE INDEX account_deletion_pending_once
  ON account_deletion (identity_id) WHERE cancelled_at IS NULL AND completed_at IS NULL;
CREATE INDEX account_deletion_due_idx
  ON account_deletion (scheduled_for) WHERE cancelled_at IS NULL AND completed_at IS NULL;

-- The server stamps every moment. A request is made only for an active identity; it then only
-- ends, once, by cancelling or by completing. When it is due is the deletion job's to judge
-- (src/lifecycle/account-deletions.ts): it completes only rows whose scheduled_for has passed.
CREATE FUNCTION account_deletion_guard() RETURNS trigger
  LANGUAGE plpgsql SET search_path = public, pg_temp AS $$
BEGIN
  IF TG_OP = 'INSERT' THEN
    IF NOT EXISTS (SELECT 1 FROM identity i WHERE i.id = NEW.identity_id AND i.status = 'active') THEN
      RAISE EXCEPTION 'account_deletion: only an active identity asks to be deleted'
        USING ERRCODE = 'check_violation';
    END IF;
    NEW.requested_at := now();
    NEW.scheduled_for := now() + interval '14 days';
    NEW.cancelled_at := NULL;
    NEW.completed_at := NULL;
    RETURN NEW;
  END IF;
  IF NEW.identity_id <> OLD.identity_id OR NEW.requested_at <> OLD.requested_at
     OR NEW.scheduled_for <> OLD.scheduled_for THEN
    RAISE EXCEPTION 'account_deletion %: who and when are fixed', OLD.id
      USING ERRCODE = 'restrict_violation';
  END IF;
  IF OLD.cancelled_at IS NOT NULL OR OLD.completed_at IS NOT NULL THEN
    RAISE EXCEPTION 'account_deletion %: a cancelled or completed deletion is final', OLD.id
      USING ERRCODE = 'restrict_violation';
  END IF;
  IF NEW.cancelled_at IS NOT NULL THEN NEW.cancelled_at := now(); END IF;
  IF NEW.completed_at IS NOT NULL THEN NEW.completed_at := now(); END IF;
  RETURN NEW;
END
$$;

CREATE TRIGGER account_deletion_guard
  BEFORE INSERT OR UPDATE ON account_deletion FOR EACH ROW EXECUTE FUNCTION account_deletion_guard();

-- Asking for deletion signs the member out of every device.
ALTER TABLE auth_session DROP CONSTRAINT auth_session_revoke_reason_known;
ALTER TABLE auth_session ADD CONSTRAINT auth_session_revoke_reason_known
  CHECK (revoke_reason IS NULL OR revoke_reason IN
         ('sign_out', 'identity_suspended', 'identity_closed', 'credential_revoked',
          'password_reset', 'password_changed', 'operator', 'deletion_requested'));

-- The record of a request outlives the identity it names, as the journal does.
REVOKE DELETE, TRUNCATE ON account_deletion FROM uni_auth_app;
