-- Account recovery without a second factor (account-plan.md part 7, OQ-AC-3).
--
-- A member with 2-step verification who has lost their authenticator, their passkeys and their
-- recovery codes asks, after passing their password, for 2-step verification to be removed.
-- Every verified email address is told at once, with a link that cancels the request; signing
-- in with a 2-step method cancels it too. Seven days later, if nobody has cancelled it, 2-step
-- verification is removed and the password alone signs in.
--
-- Accounts that handle money in a product also need an administrator there to approve it. The
-- login application asks the product (GSN) whether a person must check this one, and until the
-- product has answered, nothing is removed: an unanswered request waits, it never completes.

CREATE TABLE mfa_recovery (
  id                uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  identity_id       uuid NOT NULL REFERENCES identity(id) ON DELETE RESTRICT,
  requested_at      timestamptz NOT NULL DEFAULT now(),
  -- When the waiting period ends: the earliest 2-step verification may be removed.
  eligible_at       timestamptz NOT NULL,
  -- SHA-256 of the cancel link's token, which only the emails hold.
  cancel_token_hash bytea NOT NULL,
  -- Whether a person at the product must approve it: unknown until the product answers.
  review            text NOT NULL DEFAULT 'unknown',
  reviewed_at       timestamptz,
  -- The product's administrator's decision, where one was needed.
  decision          text,
  decided_at        timestamptz,
  cancelled_at      timestamptz,
  cancelled_by      text,
  completed_at      timestamptz,
  -- When the product was told that the request was cancelled.
  withdrawn_at      timestamptz,
  CONSTRAINT mfa_recovery_wait CHECK (eligible_at = requested_at + interval '7 days'),
  CONSTRAINT mfa_recovery_token_shape CHECK (length(cancel_token_hash) = 32),
  CONSTRAINT mfa_recovery_review_known
    CHECK (review IN ('unknown', 'required', 'not_required')),
  CONSTRAINT mfa_recovery_reviewed_when CHECK ((review = 'unknown') = (reviewed_at IS NULL)),
  CONSTRAINT mfa_recovery_decision_known
    CHECK (decision IS NULL OR (review = 'required' AND decision IN ('approved', 'rejected'))),
  CONSTRAINT mfa_recovery_decided_when CHECK ((decision IS NULL) = (decided_at IS NULL)),
  CONSTRAINT mfa_recovery_cancel_explained
    CHECK ((cancelled_at IS NULL) = (cancelled_by IS NULL)
       AND (cancelled_by IS NULL OR cancelled_by IN ('link', 'sign_in', 'identity_closed'))),
  -- Ends one way only: cancelled, refused or completed.
  CONSTRAINT mfa_recovery_one_end
    CHECK (num_nonnulls(cancelled_at, completed_at,
                        CASE WHEN decision = 'rejected' THEN decided_at END) <= 1),
  -- Completes only when no person had to check it, or one approved it. (IS NOT DISTINCT FROM:
  -- with no decision yet, "decision = 'approved'" is null, and a null check would pass.)
  CONSTRAINT mfa_recovery_completes_when_allowed
    CHECK (completed_at IS NULL OR review = 'not_required'
           OR decision IS NOT DISTINCT FROM 'approved'),
  -- A cancelled request is withdrawn at the product unless it said no person was checking it:
  -- also one cancelled before its answer arrived, which the product may have registered.
  CONSTRAINT mfa_recovery_withdrawn_after_cancel
    CHECK (withdrawn_at IS NULL OR (cancelled_at IS NOT NULL AND review <> 'not_required'))
);
CREATE UNIQUE INDEX mfa_recovery_token_key ON mfa_recovery (cancel_token_hash);
-- At most one request waits per identity.
CREATE UNIQUE INDEX mfa_recovery_pending_once
  ON mfa_recovery (identity_id)
  WHERE cancelled_at IS NULL AND completed_at IS NULL AND decision IS DISTINCT FROM 'rejected';
CREATE INDEX mfa_recovery_pending_idx
  ON mfa_recovery (eligible_at)
  WHERE cancelled_at IS NULL AND completed_at IS NULL AND decision IS DISTINCT FROM 'rejected';

-- The server stamps every moment. A request is made only by an active identity with 2-step
-- verification on. Who, when and the token never change; the product's answer and decision are
-- each given once; an ended request stays ended (only withdrawn_at may follow a cancel). When
-- the waiting period is over is the job's to judge (src/recovery/mfa-recoveries.ts), as for
-- account deletion: it completes only rows whose eligible_at has passed.
CREATE FUNCTION mfa_recovery_guard() RETURNS trigger
  LANGUAGE plpgsql SET search_path = public, pg_temp AS $$
DECLARE
  ended boolean;
BEGIN
  IF TG_OP = 'INSERT' THEN
    IF NOT EXISTS (SELECT 1 FROM identity i WHERE i.id = NEW.identity_id AND i.status = 'active') THEN
      RAISE EXCEPTION 'mfa_recovery: only an active identity asks for recovery'
        USING ERRCODE = 'check_violation';
    END IF;
    IF NOT EXISTS (SELECT 1 FROM credential c
                    WHERE c.identity_id = NEW.identity_id AND c.kind = 'totp'
                      AND c.revoked_at IS NULL) THEN
      RAISE EXCEPTION 'mfa_recovery: 2-step verification is not on for this identity'
        USING ERRCODE = 'check_violation';
    END IF;
    NEW.requested_at := now();
    NEW.eligible_at := now() + interval '7 days';
    NEW.review := 'unknown';
    NEW.reviewed_at := NULL;
    NEW.decision := NULL;
    NEW.decided_at := NULL;
    NEW.cancelled_at := NULL;
    NEW.cancelled_by := NULL;
    NEW.completed_at := NULL;
    NEW.withdrawn_at := NULL;
    RETURN NEW;
  END IF;

  IF NEW.identity_id <> OLD.identity_id OR NEW.requested_at <> OLD.requested_at
     OR NEW.eligible_at <> OLD.eligible_at OR NEW.cancel_token_hash <> OLD.cancel_token_hash THEN
    RAISE EXCEPTION 'mfa_recovery %: who, when and the token are fixed', OLD.id
      USING ERRCODE = 'restrict_violation';
  END IF;
  IF OLD.review <> 'unknown' AND NEW.review IS DISTINCT FROM OLD.review THEN
    RAISE EXCEPTION 'mfa_recovery %: the product has already answered', OLD.id
      USING ERRCODE = 'restrict_violation';
  END IF;
  IF OLD.decision IS NOT NULL AND NEW.decision IS DISTINCT FROM OLD.decision THEN
    RAISE EXCEPTION 'mfa_recovery %: the decision is final', OLD.id
      USING ERRCODE = 'restrict_violation';
  END IF;
  ended := OLD.cancelled_at IS NOT NULL OR OLD.completed_at IS NOT NULL
           OR OLD.decision = 'rejected';
  IF ended AND (NEW.cancelled_at IS DISTINCT FROM OLD.cancelled_at
                OR NEW.completed_at IS DISTINCT FROM OLD.completed_at
                OR NEW.decision IS DISTINCT FROM OLD.decision
                OR NEW.review IS DISTINCT FROM OLD.review) THEN
    RAISE EXCEPTION 'mfa_recovery %: an ended request is final', OLD.id
      USING ERRCODE = 'restrict_violation';
  END IF;
  IF OLD.withdrawn_at IS NOT NULL AND NEW.withdrawn_at IS DISTINCT FROM OLD.withdrawn_at THEN
    RAISE EXCEPTION 'mfa_recovery %: the product was already told', OLD.id
      USING ERRCODE = 'restrict_violation';
  END IF;

  IF OLD.review = 'unknown' AND NEW.review <> 'unknown' THEN NEW.reviewed_at := now(); END IF;
  IF OLD.decision IS NULL AND NEW.decision IS NOT NULL THEN NEW.decided_at := now(); END IF;
  IF OLD.cancelled_at IS NULL AND NEW.cancelled_at IS NOT NULL THEN NEW.cancelled_at := now(); END IF;
  IF OLD.completed_at IS NULL AND NEW.completed_at IS NOT NULL THEN NEW.completed_at := now(); END IF;
  IF OLD.withdrawn_at IS NULL AND NEW.withdrawn_at IS NOT NULL THEN NEW.withdrawn_at := now(); END IF;
  RETURN NEW;
END
$$;

CREATE TRIGGER mfa_recovery_guard
  BEFORE INSERT OR UPDATE ON mfa_recovery FOR EACH ROW EXECUTE FUNCTION mfa_recovery_guard();

-- Removing 2-step verification by recovery names itself on the credentials it revokes.
ALTER TABLE credential DROP CONSTRAINT credential_revoke_reason_known;
ALTER TABLE credential ADD CONSTRAINT credential_revoke_reason_known
  CHECK (revoke_reason IS NULL OR revoke_reason IN
         ('replaced', 'removed_by_member', 'identity_erased', 'operator', 'compromised',
          'password_reset', 'account_recovery'));

-- The record of a request outlives the identity it names, as the journal does.
REVOKE DELETE, TRUNCATE ON mfa_recovery FROM uni_auth_app;
