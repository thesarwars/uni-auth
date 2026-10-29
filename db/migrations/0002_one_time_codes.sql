-- One-time codes and password recovery (auth-plan.md section 8, part 4).
--
-- The caps are GSN's (schemas/01-onboarding.md, SEC-8), carried across as rules rather than
-- code: five attempts, then the destination is locked for thirty minutes; three resends; five
-- codes to one destination in any rolling hour, first issues and resends together; fifteen
-- minutes to use a code, once. The screens render what these triggers refuse and keep no
-- counter of their own.
--
-- Two things differ from GSN on purpose. A code is bound to the sign-in that asked for it
-- (flow_hash, the SHA-256 of Hydra's login challenge), so it can only be entered in that flow.
-- And recovery is a code, not a link: a link opens a new tab and loses the login challenge,
-- while a code keeps the member on the screen they were on.

-- ------------------------------------------------------------------------
-- otp_challenge
-- ------------------------------------------------------------------------

CREATE TYPE otp_purpose AS ENUM ('sign_in', 'recovery', 'signup');
CREATE TYPE otp_channel AS ENUM ('email', 'whatsapp');
CREATE TYPE otp_status AS ENUM ('issued', 'verified', 'expired', 'locked');

-- The key every cap is counted under: one address, however it was typed.
CREATE FUNCTION otp_destination_hash(p_destination text) RETURNS bytea
  LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE SET search_path = public, pg_temp
  RETURN sha256(convert_to(lower(p_destination), 'UTF8'));

CREATE TABLE otp_challenge (
  id               uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  identity_id      uuid REFERENCES identity(id) ON DELETE RESTRICT,
    -- whose identifier the code goes to; NULL only for signup, which has no identity yet
  purpose          otp_purpose NOT NULL,
  channel          otp_channel NOT NULL,
  destination      text,
    -- an email (lower-cased) or an E.164 number; NULL only once scrubbed
  flow_hash        bytea NOT NULL,
  code_hash        bytea NOT NULL,
  code_salt        bytea NOT NULL,
  code_length      smallint NOT NULL DEFAULT 6,
  status           otp_status NOT NULL DEFAULT 'issued',
  issued_at        timestamptz NOT NULL DEFAULT now(),
  expires_at       timestamptz NOT NULL,
  attempt_count    integer NOT NULL DEFAULT 0,
  max_attempts     integer NOT NULL DEFAULT 5,
  resend_count     integer NOT NULL DEFAULT 0,
  max_resends      integer NOT NULL DEFAULT 3,
  last_resent_at   timestamptz,
  locked_until     timestamptz,
  consumed_at      timestamptz,
  pii_scrubbed_at  timestamptz,
  created_at       timestamptz NOT NULL DEFAULT now(),
  updated_at       timestamptz NOT NULL DEFAULT now(),
  CONSTRAINT otp_challenge_destination_shape
    CHECK (destination IS NULL OR CASE channel
             WHEN 'whatsapp' THEN destination ~ '^\+[1-9][0-9]{6,14}$'
             ELSE destination ~ '^[^@[:space:]A-Z]+@[^@[:space:]A-Z]+\.[^@[:space:]A-Z]+$'
           END),
  CONSTRAINT otp_challenge_one_owner
    CHECK ((purpose = 'signup') = (identity_id IS NULL)),
  CONSTRAINT otp_challenge_flow_hash_sha256 CHECK (octet_length(flow_hash) = 32),
  CONSTRAINT otp_challenge_code_hash_sha256 CHECK (octet_length(code_hash) = 32),
  CONSTRAINT otp_challenge_code_salt_bounded CHECK (octet_length(code_salt) BETWEEN 16 AND 64),
  -- The screen draws code_length boxes, so the screen and the verifier cannot disagree.
  CONSTRAINT otp_challenge_code_length_bounded CHECK (code_length BETWEEN 4 AND 10),
  CONSTRAINT otp_challenge_short_lived
    CHECK (expires_at > issued_at
           AND expires_at <= COALESCE(last_resent_at, issued_at) + interval '15 minutes'),
  CONSTRAINT otp_challenge_attempts_bounded
    CHECK (max_attempts BETWEEN 1 AND 10 AND attempt_count BETWEEN 0 AND max_attempts),
  CONSTRAINT otp_challenge_resends_bounded
    CHECK (max_resends BETWEEN 0 AND 10 AND resend_count BETWEEN 0 AND max_resends),
  CONSTRAINT otp_challenge_resend_stamped
    CHECK ((resend_count = 0) = (last_resent_at IS NULL)),
  CONSTRAINT otp_challenge_consumed_is_verified
    CHECK ((status = 'verified') = (consumed_at IS NOT NULL)),
  CONSTRAINT otp_challenge_consumed_before_expiry
    CHECK (consumed_at IS NULL OR consumed_at <= expires_at),
  CONSTRAINT otp_challenge_locked_has_until
    CHECK (status <> 'locked' OR locked_until IS NOT NULL),
  CONSTRAINT otp_challenge_pii_scrub
    CHECK ((pii_scrubbed_at IS NULL) = (destination IS NOT NULL)
           AND (pii_scrubbed_at IS NULL OR status <> 'issued'))
);
-- One live code per sign-in and purpose: a new one retires the old.
CREATE UNIQUE INDEX otp_challenge_one_live_key
  ON otp_challenge (flow_hash, purpose) WHERE status = 'issued';
CREATE INDEX otp_challenge_locked_idx
  ON otp_challenge (otp_destination_hash(destination), locked_until) WHERE status = 'locked';
CREATE INDEX otp_challenge_identity_idx ON otp_challenge (identity_id) WHERE identity_id IS NOT NULL;

-- Every code sent - the first issue and each resend - is one row here, so the hourly cap counts
-- what was sent rather than what is still live. Only the hash is kept. A row is deleted when
-- the hour it counts towards is long past, or when erasure scrubs its challenge.
CREATE TABLE otp_send (
  id                uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  otp_challenge_id  uuid NOT NULL REFERENCES otp_challenge(id) ON DELETE RESTRICT,
  destination_hash  bytea NOT NULL,
  sent_at           timestamptz NOT NULL DEFAULT now(),
  CONSTRAINT otp_send_hash_sha256 CHECK (octet_length(destination_hash) = 32)
);
CREATE INDEX otp_send_destination_idx ON otp_send (destination_hash, sent_at DESC);
CREATE INDEX otp_send_challenge_idx ON otp_send (otp_challenge_id);

CREATE FUNCTION otp_sends_last_hour(p_destination text) RETURNS bigint
  LANGUAGE sql STABLE SET search_path = public, pg_temp
  RETURN (SELECT count(*) FROM otp_send s
           WHERE s.destination_hash = otp_destination_hash(p_destination)
             AND s.sent_at > now() - interval '1 hour');

-- When a lockout on this destination lifts, or NULL. A lockout holds the address, not just the
-- challenge that tripped it.
CREATE FUNCTION otp_locked_until(p_destination text) RETURNS timestamptz
  LANGUAGE sql STABLE SET search_path = public, pg_temp
  RETURN (SELECT max(o.locked_until) FROM otp_challenge o
           WHERE otp_destination_hash(o.destination) = otp_destination_hash(p_destination)
             AND o.status = 'locked' AND o.locked_until > now());

-- Refuses a send the caps forbid. Shared by a first issue and a resend.
CREATE FUNCTION otp_assert_may_send(p_destination text) RETURNS void
  LANGUAGE plpgsql SET search_path = public, pg_temp AS $$
BEGIN
  IF otp_locked_until(p_destination) IS NOT NULL THEN
    RAISE EXCEPTION 'otp_challenge: % is locked out; no new code until the lockout ends', p_destination
      USING ERRCODE = 'check_violation';
  END IF;
  IF otp_sends_last_hour(p_destination) >= 5 THEN
    RAISE EXCEPTION 'otp_challenge: % has had five codes in the last hour', p_destination
      USING ERRCODE = 'check_violation';
  END IF;
END
$$;

CREATE FUNCTION otp_challenge_issue_guard() RETURNS trigger
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
  RETURN NEW;
END
$$;

CREATE FUNCTION otp_challenge_guard() RETURNS trigger
  LANGUAGE plpgsql SET search_path = public, pg_temp AS $$
DECLARE
  v_ok boolean;
BEGIN
  IF OLD.pii_scrubbed_at IS NOT NULL THEN
    RAISE EXCEPTION 'otp_challenge %: a scrubbed challenge is final', OLD.id
      USING ERRCODE = 'restrict_violation';
  END IF;
  IF NEW.pii_scrubbed_at IS NOT NULL THEN
    -- the scrub nulls the destination and changes nothing else
    IF (to_jsonb(NEW) - ARRAY['destination', 'pii_scrubbed_at', 'updated_at'])
       <> (to_jsonb(OLD) - ARRAY['destination', 'pii_scrubbed_at', 'updated_at']) THEN
      RAISE EXCEPTION 'otp_challenge %: a scrub only nulls the destination', OLD.id
        USING ERRCODE = 'restrict_violation';
    END IF;
    NEW.pii_scrubbed_at := now();
    RETURN NEW;
  END IF;
  IF OLD.status IN ('verified', 'expired') THEN
    RAISE EXCEPTION 'otp_challenge %: % is final (single use)', OLD.id, OLD.status
      USING ERRCODE = 'restrict_violation';
  END IF;
  IF NEW.identity_id IS DISTINCT FROM OLD.identity_id
     OR NEW.purpose IS DISTINCT FROM OLD.purpose
     OR NEW.channel IS DISTINCT FROM OLD.channel
     OR NEW.destination IS DISTINCT FROM OLD.destination
     OR NEW.flow_hash IS DISTINCT FROM OLD.flow_hash
     OR NEW.issued_at IS DISTINCT FROM OLD.issued_at
     OR NEW.code_length IS DISTINCT FROM OLD.code_length
     OR NEW.max_attempts IS DISTINCT FROM OLD.max_attempts
     OR NEW.max_resends IS DISTINCT FROM OLD.max_resends THEN
    RAISE EXCEPTION 'otp_challenge %: a challenge is bound to one owner, purpose, channel, destination, flow, code length, issue time and caps', OLD.id
      USING ERRCODE = 'restrict_violation';
  END IF;
  IF NEW.attempt_count < OLD.attempt_count OR NEW.resend_count < OLD.resend_count THEN
    RAISE EXCEPTION 'otp_challenge %: attempt and resend counters only grow', OLD.id
      USING ERRCODE = 'check_violation';
  END IF;
  IF (NEW.code_hash IS DISTINCT FROM OLD.code_hash OR NEW.code_salt IS DISTINCT FROM OLD.code_salt)
     AND NEW.resend_count = OLD.resend_count THEN
    RAISE EXCEPTION 'otp_challenge %: a new code is issued only by a counted resend', OLD.id
      USING ERRCODE = 'check_violation';
  END IF;
  IF NEW.resend_count > OLD.resend_count THEN
    IF OLD.status <> 'issued' OR NEW.code_hash IS NOT DISTINCT FROM OLD.code_hash THEN
      RAISE EXCEPTION 'otp_challenge %: a resend issues a new code on a live challenge', OLD.id
        USING ERRCODE = 'check_violation';
    END IF;
    IF NEW.resend_count > OLD.resend_count + 1 THEN
      RAISE EXCEPTION 'otp_challenge %: one resend at a time', OLD.id
        USING ERRCODE = 'check_violation';
    END IF;
    PERFORM otp_assert_may_send(NEW.destination);
    NEW.last_resent_at := now();
    -- The attempt count carries over a resend, so resending cannot buy more guesses.
  END IF;

  -- The attempt that reaches the cap without verifying locks the challenge, and the address.
  IF OLD.status = 'issued' AND NEW.status = 'issued' AND NEW.attempt_count >= NEW.max_attempts THEN
    NEW.status := 'locked';
    NEW.locked_until := now() + interval '30 minutes';
  END IF;
  IF NEW.status <> OLD.status THEN
    v_ok := CASE OLD.status
      WHEN 'issued' THEN NEW.status IN ('verified', 'locked', 'expired')
      WHEN 'locked' THEN NEW.status = 'expired'
      ELSE false
    END;
    IF NOT v_ok THEN
      RAISE EXCEPTION 'otp_challenge %: % -> % is not a legal transition', OLD.id, OLD.status, NEW.status
        USING ERRCODE = 'check_violation';
    END IF;
    IF NEW.status = 'verified' THEN
      IF NEW.attempt_count <> OLD.attempt_count + 1 OR OLD.attempt_count >= OLD.max_attempts THEN
        RAISE EXCEPTION 'otp_challenge %: a code is verified only on one counted attempt inside the cap', OLD.id
          USING ERRCODE = 'check_violation';
      END IF;
      IF OLD.expires_at <= now() THEN
        RAISE EXCEPTION 'otp_challenge %: the code has expired', OLD.id
          USING ERRCODE = 'check_violation';
      END IF;
      NEW.consumed_at := now();
    END IF;
  END IF;
  -- Only the guard sets a lockout, at the attempt that trips it; nobody extends or lifts one.
  IF NEW.locked_until IS DISTINCT FROM OLD.locked_until
     AND NOT (OLD.status = 'issued' AND NEW.status = 'locked') THEN
    RAISE EXCEPTION 'otp_challenge %: a lockout is set only by the attempt that trips it', OLD.id
      USING ERRCODE = 'check_violation';
  END IF;
  RETURN NEW;
END
$$;

CREATE FUNCTION otp_challenge_record_send() RETURNS trigger
  LANGUAGE plpgsql SET search_path = public, pg_temp AS $$
BEGIN
  IF TG_OP = 'INSERT' OR NEW.resend_count > OLD.resend_count THEN
    INSERT INTO otp_send (otp_challenge_id, destination_hash)
    VALUES (NEW.id, otp_destination_hash(NEW.destination));
  END IF;
  RETURN NULL;
END
$$;

CREATE TRIGGER otp_challenge_issue_guard
  BEFORE INSERT ON otp_challenge FOR EACH ROW EXECUTE FUNCTION otp_challenge_issue_guard();
CREATE TRIGGER otp_challenge_guard
  BEFORE UPDATE ON otp_challenge FOR EACH ROW EXECUTE FUNCTION otp_challenge_guard();
CREATE TRIGGER otp_challenge_record_send
  AFTER INSERT OR UPDATE OF resend_count ON otp_challenge
  FOR EACH ROW EXECUTE FUNCTION otp_challenge_record_send();
CREATE TRIGGER otp_challenge_set_updated_at
  BEFORE UPDATE ON otp_challenge FOR EACH ROW EXECUTE FUNCTION set_updated_at();

CREATE FUNCTION otp_send_guard() RETURNS trigger
  LANGUAGE plpgsql SET search_path = public, pg_temp AS $$
BEGIN
  IF TG_OP = 'INSERT' THEN
    NEW.sent_at := now();
    RETURN NEW;
  END IF;
  IF TG_OP = 'DELETE' THEN
    IF OLD.sent_at < now() - interval '1 day'
       OR EXISTS (SELECT 1 FROM otp_challenge o
                   WHERE o.id = OLD.otp_challenge_id AND o.pii_scrubbed_at IS NOT NULL) THEN
      RETURN OLD;
    END IF;
    RAISE EXCEPTION 'otp_send %: a send counts towards its hour; it is deleted only when long past or erased', OLD.id
      USING ERRCODE = 'restrict_violation';
  END IF;
  RAISE EXCEPTION 'otp_send %: the send ledger is append-only', OLD.id
    USING ERRCODE = 'restrict_violation';
END
$$;

CREATE TRIGGER otp_send_guard
  BEFORE INSERT OR UPDATE OR DELETE ON otp_send FOR EACH ROW EXECUTE FUNCTION otp_send_guard();
CREATE TRIGGER otp_send_no_truncate
  BEFORE TRUNCATE ON otp_send FOR EACH STATEMENT EXECUTE FUNCTION forbid_mutation();

-- ------------------------------------------------------------------------
-- password_reset: a verified recovery code, joined to the new password
-- ------------------------------------------------------------------------

-- A verified recovery code and a new password are two unconnected facts until this ticket
-- joins them. It is opened from a recovery code verified in the last fifteen minutes, used
-- once, and completing it - password_reset_complete() - revokes every session the identity
-- has, because whoever forgot the password may not be the only one who had it.
CREATE TABLE password_reset (
  id                uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  identity_id       uuid NOT NULL REFERENCES identity(id) ON DELETE RESTRICT,
  otp_challenge_id  uuid NOT NULL UNIQUE REFERENCES otp_challenge(id) ON DELETE RESTRICT,
  expires_at        timestamptz NOT NULL,
  consumed_at       timestamptz,
  credential_id     uuid UNIQUE REFERENCES credential(id) ON DELETE RESTRICT,
    -- the password it set
  created_at        timestamptz NOT NULL DEFAULT now(),
  updated_at        timestamptz NOT NULL DEFAULT now(),
  CONSTRAINT password_reset_short_lived
    CHECK (expires_at > created_at AND expires_at <= created_at + interval '15 minutes'),
  CONSTRAINT password_reset_consumed_sets_password
    CHECK ((consumed_at IS NULL) = (credential_id IS NULL)),
  CONSTRAINT password_reset_consumed_before_expiry
    CHECK (consumed_at IS NULL OR consumed_at <= expires_at)
);
CREATE INDEX password_reset_identity_idx ON password_reset (identity_id);

CREATE FUNCTION password_reset_guard() RETURNS trigger
  LANGUAGE plpgsql SET search_path = public, pg_temp AS $$
BEGIN
  IF TG_OP = 'INSERT' THEN
    NEW.created_at := now();
    IF NEW.consumed_at IS NOT NULL OR NEW.credential_id IS NOT NULL THEN
      RAISE EXCEPTION 'password_reset: a ticket is born unused'
        USING ERRCODE = 'check_violation';
    END IF;
    IF NOT EXISTS (
         SELECT 1 FROM otp_challenge o JOIN identity i ON i.id = o.identity_id
          WHERE o.id = NEW.otp_challenge_id AND o.identity_id = NEW.identity_id
            AND o.purpose = 'recovery' AND o.status = 'verified'
            AND o.consumed_at > now() - interval '15 minutes'
            AND i.status = 'active') THEN
      RAISE EXCEPTION 'password_reset: a ticket opens only from a recovery code of its own active identity, verified in the last fifteen minutes'
        USING ERRCODE = 'check_violation';
    END IF;
    RETURN NEW;
  END IF;
  IF OLD.consumed_at IS NOT NULL THEN
    RAISE EXCEPTION 'password_reset %: a ticket is used once', OLD.id
      USING ERRCODE = 'restrict_violation';
  END IF;
  IF NEW.identity_id IS DISTINCT FROM OLD.identity_id
     OR NEW.otp_challenge_id IS DISTINCT FROM OLD.otp_challenge_id
     OR NEW.expires_at IS DISTINCT FROM OLD.expires_at
     OR NEW.created_at IS DISTINCT FROM OLD.created_at THEN
    RAISE EXCEPTION 'password_reset %: a ticket is bound to its identity, code and expiry', OLD.id
      USING ERRCODE = 'restrict_violation';
  END IF;
  IF NEW.consumed_at IS NOT NULL THEN
    IF OLD.expires_at <= now() THEN
      RAISE EXCEPTION 'password_reset %: the ticket has expired', OLD.id
        USING ERRCODE = 'check_violation';
    END IF;
    IF NOT EXISTS (SELECT 1 FROM credential c
                    WHERE c.id = NEW.credential_id AND c.identity_id = OLD.identity_id
                      AND c.kind = 'password' AND c.revoked_at IS NULL) THEN
      RAISE EXCEPTION 'password_reset %: a ticket is used by setting a live password of its own identity', OLD.id
        USING ERRCODE = 'check_violation';
    END IF;
    NEW.consumed_at := now();
  END IF;
  RETURN NEW;
END
$$;

CREATE TRIGGER password_reset_guard
  BEFORE INSERT OR UPDATE ON password_reset FOR EACH ROW EXECUTE FUNCTION password_reset_guard();
CREATE TRIGGER password_reset_set_updated_at
  BEFORE UPDATE ON password_reset FOR EACH ROW EXECUTE FUNCTION set_updated_at();

-- Using a ticket revokes every live session of the identity, whichever way it was opened.
CREATE FUNCTION password_reset_revoke_sessions() RETURNS trigger
  LANGUAGE plpgsql SET search_path = public, pg_temp AS $$
BEGIN
  UPDATE auth_session s
     SET revoked_at = now(), revoke_reason = 'password_reset'
   WHERE s.identity_id = NEW.identity_id AND s.revoked_at IS NULL;
  RETURN NULL;
END
$$;

CREATE TRIGGER password_reset_revoke_sessions
  AFTER UPDATE OF consumed_at ON password_reset
  FOR EACH ROW WHEN (OLD.consumed_at IS NULL AND NEW.consumed_at IS NOT NULL)
  EXECUTE FUNCTION password_reset_revoke_sessions();

ALTER TABLE credential DROP CONSTRAINT credential_revoke_reason_known;
ALTER TABLE credential ADD CONSTRAINT credential_revoke_reason_known
  CHECK (revoke_reason IS NULL OR revoke_reason IN
         ('replaced', 'removed_by_member', 'identity_erased', 'operator', 'compromised',
          'password_reset'));

-- The whole reset, in the order that names every revocation for what it was: the sessions as
-- 'password_reset' first, then the old password, then the new one, then the ticket. Runs as
-- the caller; every step is checked by the guards above as if it were issued one by one.
CREATE FUNCTION password_reset_complete(p_ticket uuid, p_secret_hash bytea) RETURNS uuid
  LANGUAGE plpgsql SET search_path = public, pg_temp AS $$
DECLARE
  v_identity uuid;
  v_credential uuid;
BEGIN
  SELECT identity_id INTO v_identity FROM password_reset
   WHERE id = p_ticket AND consumed_at IS NULL AND expires_at > now() FOR UPDATE;
  IF v_identity IS NULL THEN
    RAISE EXCEPTION 'password_reset %: no usable ticket', p_ticket
      USING ERRCODE = 'check_violation';
  END IF;
  UPDATE auth_session SET revoked_at = now(), revoke_reason = 'password_reset'
   WHERE identity_id = v_identity AND revoked_at IS NULL;
  UPDATE credential SET revoked_at = now(), revoke_reason = 'password_reset'
   WHERE identity_id = v_identity AND kind = 'password' AND revoked_at IS NULL;
  INSERT INTO credential (identity_id, kind, secret_hash, password_policy_id)
  VALUES (v_identity, 'password', p_secret_hash, password_policy_in_effect())
  RETURNING id INTO v_credential;
  UPDATE password_reset SET consumed_at = now(), credential_id = v_credential WHERE id = p_ticket;
  RETURN v_credential;
END
$$;

-- ------------------------------------------------------------------------
-- Erasure reaches the codes
-- ------------------------------------------------------------------------

-- Erasing an identity ends its live codes, scrubs every destination it was sent, and lets the
-- send ledger forget them.
CREATE FUNCTION identity_erase_codes() RETURNS trigger
  LANGUAGE plpgsql SET search_path = public, pg_temp AS $$
BEGIN
  UPDATE otp_challenge SET status = 'expired'
   WHERE identity_id = NEW.id AND status IN ('issued', 'locked');
  UPDATE otp_challenge SET destination = NULL, pii_scrubbed_at = now()
   WHERE identity_id = NEW.id AND pii_scrubbed_at IS NULL;
  DELETE FROM otp_send s USING otp_challenge o
   WHERE s.otp_challenge_id = o.id AND o.identity_id = NEW.id;
  RETURN NULL;
END
$$;

CREATE TRIGGER identity_erase_codes
  AFTER UPDATE OF erased_at ON identity
  FOR EACH ROW WHEN (OLD.erased_at IS NULL AND NEW.erased_at IS NOT NULL)
  EXECUTE FUNCTION identity_erase_codes();

-- ------------------------------------------------------------------------
-- Privileges
-- ------------------------------------------------------------------------

REVOKE DELETE, TRUNCATE ON otp_challenge, password_reset FROM uni_auth_app;
REVOKE UPDATE, TRUNCATE ON otp_send FROM uni_auth_app;
