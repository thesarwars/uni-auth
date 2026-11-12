-- The account centre, first three sections (account-plan.md section 6, parts 1-3): personal
-- info, email and phone, password.
--
-- What the schema adds:
--   - a code to prove an address a signed-in member adds to their own identity;
--   - the rule that an identity keeps at least one verified way to be reached while it lives;
--   - a password change that keeps the member signed in on the device that made it, and signs
--     out every other one;
--   - journal kinds for a profile change.

-- ------------------------------------------------------------------------
-- A code for an address being added
-- ------------------------------------------------------------------------

-- Bound, like every code, to the flow that asked for it: here the account-centre session.
ALTER TYPE otp_purpose ADD VALUE IF NOT EXISTS 'add_identifier';

CREATE OR REPLACE FUNCTION otp_challenge_issue_guard() RETURNS trigger
  LANGUAGE plpgsql SET search_path = public, pg_temp AS $$
BEGIN
  NEW.issued_at := now();
  IF NEW.status <> 'issued' OR NEW.attempt_count <> 0 OR NEW.resend_count <> 0
     OR NEW.consumed_at IS NOT NULL OR NEW.locked_until IS NOT NULL
     OR NEW.pii_scrubbed_at IS NOT NULL THEN
    RAISE EXCEPTION 'otp_challenge: a challenge is born issued with no attempts or resends'
      USING ERRCODE = 'check_violation';
  END IF;
  PERFORM otp_assert_may_send(NEW.destination);
  -- A sign-in or recovery code goes only to an active identity, at a verified, live
  -- identifier of its own of the channel's kind.
  IF NEW.purpose IN ('sign_in', 'recovery') AND NOT EXISTS (
       SELECT 1 FROM identity i
         JOIN identity_identifier ii ON ii.identity_id = i.id
        WHERE i.id = NEW.identity_id AND i.status = 'active'
          AND ii.revoked_at IS NULL AND ii.verified_at IS NOT NULL
          AND ii.kind = CASE NEW.channel WHEN 'email' THEN 'email'::identifier_kind
                                         ELSE 'phone'::identifier_kind END
          AND ii.value = NEW.destination::citext) THEN
    RAISE EXCEPTION 'otp_challenge: a sign-in or recovery code goes only to a verified identifier of an active identity'
      USING ERRCODE = 'check_violation';
  END IF;
  -- A signup code, or a code for an address being added, goes only to an address no live
  -- identity holds verified; adding one also needs an active identity to add it to.
  IF NEW.purpose::text IN ('signup', 'add_identifier') AND EXISTS (
       SELECT 1 FROM identity_identifier ii
        WHERE ii.revoked_at IS NULL AND ii.verified_at IS NOT NULL
          AND ii.kind = CASE NEW.channel WHEN 'email' THEN 'email'::identifier_kind
                                         ELSE 'phone'::identifier_kind END
          AND ii.value = NEW.destination::citext) THEN
    RAISE EXCEPTION 'otp_challenge: a signup or add-identifier code goes only to an address no identity holds verified'
      USING ERRCODE = 'check_violation';
  END IF;
  IF NEW.purpose::text = 'add_identifier'
     AND NOT EXISTS (SELECT 1 FROM identity i WHERE i.id = NEW.identity_id AND i.status = 'active') THEN
    RAISE EXCEPTION 'otp_challenge: an address is added only to an active identity'
      USING ERRCODE = 'check_violation';
  END IF;
  RETURN NEW;
END
$$;

-- ------------------------------------------------------------------------
-- An identity keeps a way to be reached
-- ------------------------------------------------------------------------

-- Removing an identifier may never leave a live identity with no verified one: it could no
-- longer sign in by code, recover its password, or be told about its own account. A closed
-- identity is past this (erasure removes them all).
CREATE FUNCTION identity_identifier_keep_one() RETURNS trigger
  LANGUAGE plpgsql SET search_path = public, pg_temp AS $$
BEGIN
  IF EXISTS (SELECT 1 FROM identity i WHERE i.id = NEW.identity_id AND i.status <> 'closed')
     AND NOT EXISTS (
       SELECT 1 FROM identity_identifier ii
        WHERE ii.identity_id = NEW.identity_id AND ii.id <> NEW.id
          AND ii.revoked_at IS NULL AND ii.verified_at IS NOT NULL) THEN
    RAISE EXCEPTION 'identity_identifier %: an identity keeps at least one verified identifier', NEW.id
      USING ERRCODE = 'check_violation';
  END IF;
  RETURN NULL;
END
$$;

CREATE TRIGGER identity_identifier_keep_one
  AFTER UPDATE OF revoked_at ON identity_identifier
  FOR EACH ROW WHEN (OLD.revoked_at IS NULL AND NEW.revoked_at IS NOT NULL AND OLD.verified_at IS NOT NULL)
  EXECUTE FUNCTION identity_identifier_keep_one();

-- ------------------------------------------------------------------------
-- Changing the password while signed in
-- ------------------------------------------------------------------------

ALTER TABLE auth_session DROP CONSTRAINT auth_session_revoke_reason_known;
ALTER TABLE auth_session ADD CONSTRAINT auth_session_revoke_reason_known
  CHECK (revoke_reason IS NULL OR revoke_reason IN
         ('sign_out', 'identity_suspended', 'identity_closed', 'credential_revoked',
          'password_reset', 'password_changed', 'operator'));

-- Revoking a credential revokes the sessions it opened - except the one session a password
-- change names as its own (password_change below), which stays signed in.
CREATE OR REPLACE FUNCTION credential_revoke_sessions() RETURNS trigger
  LANGUAGE plpgsql SET search_path = public, pg_temp AS $$
BEGIN
  UPDATE auth_session s
     SET revoked_at = now(), revoke_reason = 'credential_revoked'
   WHERE s.credential_id = NEW.id AND s.revoked_at IS NULL
     AND s.sid IS DISTINCT FROM nullif(current_setting('uni_auth.keep_sid', true), '');
  RETURN NULL;
END
$$;

-- The member's new password, set from the account centre after a fresh sign-in. Every other
-- live session of the identity is revoked as 'password_changed'; p_keep_sid, the session the
-- change was made in, stays signed in. An identity with no password (Google or Apple only)
-- gains one the same way. Returns the new credential. Runs as the caller.
CREATE FUNCTION password_change(p_identity uuid, p_secret_hash bytea, p_keep_sid text)
  RETURNS uuid
  LANGUAGE plpgsql SET search_path = public, pg_temp AS $$
DECLARE
  v_credential uuid;
BEGIN
  IF NOT EXISTS (SELECT 1 FROM auth_session
                  WHERE identity_id = p_identity AND sid = p_keep_sid
                    AND revoked_at IS NULL AND expires_at > now()) THEN
    RAISE EXCEPTION 'password_change: % is not a live session of identity %', p_keep_sid, p_identity
      USING ERRCODE = 'check_violation';
  END IF;
  PERFORM set_config('uni_auth.keep_sid', p_keep_sid, true);
  UPDATE auth_session SET revoked_at = now(), revoke_reason = 'password_changed'
   WHERE identity_id = p_identity AND revoked_at IS NULL AND sid <> p_keep_sid;
  UPDATE credential SET revoked_at = now(), revoke_reason = 'replaced'
   WHERE identity_id = p_identity AND kind = 'password' AND revoked_at IS NULL;
  INSERT INTO credential (identity_id, kind, secret_hash, password_policy_id)
  VALUES (p_identity, 'password', p_secret_hash, password_policy_in_effect())
  RETURNING id INTO v_credential;
  PERFORM set_config('uni_auth.keep_sid', '', true);
  RETURN v_credential;
END
$$;

-- ------------------------------------------------------------------------
-- The journal
-- ------------------------------------------------------------------------

ALTER TYPE auth_event_kind ADD VALUE IF NOT EXISTS 'profile_updated';
