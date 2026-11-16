-- 2-step verification with an authenticator app, and recovery codes (account-plan.md section 5
-- and section 6, part 4).
--
-- What the schema adds:
--   - a `totp` credential: the authenticator app's seed, encrypted by the login application
--     (AES-256-GCM under MFA_ENCRYPTION_KEY, which the database never sees), and the last time
--     step a code was accepted for, so no code works twice;
--   - a `recovery_codes` credential and its ten codes, each keyed-hashed and single-use;
--   - an identity holds at most one of each, and recovery codes only alongside an authenticator;
--     turning the authenticator off takes the codes with it;
--   - the assurance level a session was opened at, for step-up (acr aal1 or aal2);
--   - erasure scrubs the new secrets with the rest.

-- ------------------------------------------------------------------------
-- Credential shapes
-- ------------------------------------------------------------------------

ALTER TABLE credential
  ADD COLUMN secret_ciphertext bytea,
    -- totp only: version byte, IV, tag and ciphertext of the seed
  ADD COLUMN totp_last_step bigint;
    -- totp only: the RFC 6238 time step of the last code accepted

ALTER TABLE credential DROP CONSTRAINT credential_password_shape;
ALTER TABLE credential ADD CONSTRAINT credential_password_shape
  CHECK (kind <> 'password'
         OR (provider_subject IS NULL AND provider_email IS NULL AND password_policy_id IS NOT NULL
             AND secret_ciphertext IS NULL AND totp_last_step IS NULL
             AND (secret_hash IS NOT NULL OR pii_scrubbed_at IS NOT NULL)));

-- Was "everything that is not a password"; now Google and Apple only.
ALTER TABLE credential DROP CONSTRAINT credential_oauth_shape;
ALTER TABLE credential ADD CONSTRAINT credential_oauth_shape
  CHECK (kind NOT IN ('oauth_google', 'oauth_apple')
         OR (secret_hash IS NULL AND password_policy_id IS NULL
             AND secret_ciphertext IS NULL AND totp_last_step IS NULL
             AND (provider_subject IS NOT NULL OR pii_scrubbed_at IS NOT NULL)));

ALTER TABLE credential ADD CONSTRAINT credential_totp_shape
  CHECK (kind <> 'totp'
         OR (secret_hash IS NULL AND password_policy_id IS NULL
             AND provider_subject IS NULL AND provider_email IS NULL
             AND (secret_ciphertext IS NOT NULL OR pii_scrubbed_at IS NOT NULL)));

ALTER TABLE credential ADD CONSTRAINT credential_recovery_codes_shape
  CHECK (kind <> 'recovery_codes'
         OR (secret_hash IS NULL AND password_policy_id IS NULL
             AND provider_subject IS NULL AND provider_email IS NULL
             AND secret_ciphertext IS NULL AND totp_last_step IS NULL));

-- Version 1: 1 + 12 (IV) + 16 (tag) + the 20-byte seed. Room for a longer seed, never a
-- plaintext one: a base32 seed alone is 32 characters with no version byte in front.
ALTER TABLE credential ADD CONSTRAINT credential_secret_ciphertext_shape
  CHECK (secret_ciphertext IS NULL
         OR (get_byte(secret_ciphertext, 0) = 1 AND length(secret_ciphertext) BETWEEN 30 AND 200));

ALTER TABLE credential ADD CONSTRAINT credential_totp_last_step_positive
  CHECK (totp_last_step IS NULL OR totp_last_step > 0);

ALTER TABLE credential DROP CONSTRAINT credential_pii_scrub;
ALTER TABLE credential ADD CONSTRAINT credential_pii_scrub
  CHECK (pii_scrubbed_at IS NULL
         OR (revoked_at IS NOT NULL AND secret_hash IS NULL AND secret_ciphertext IS NULL
             AND provider_subject IS NULL AND provider_email IS NULL));

CREATE UNIQUE INDEX credential_one_live_totp_key
  ON credential (identity_id) WHERE kind = 'totp' AND revoked_at IS NULL;
CREATE UNIQUE INDEX credential_one_live_recovery_codes_key
  ON credential (identity_id) WHERE kind = 'recovery_codes' AND revoked_at IS NULL;

-- The seed is fixed for life, like every secret; only the erasure scrub nulls it. The last
-- accepted step only moves forward, which is what makes a code single-use. Recovery codes
-- belong beside a live authenticator.
CREATE FUNCTION credential_mfa_guard() RETURNS trigger
  LANGUAGE plpgsql SET search_path = public, pg_temp AS $$
BEGIN
  IF TG_OP = 'INSERT' THEN
    IF NEW.kind = 'recovery_codes'
       AND NOT EXISTS (SELECT 1 FROM credential c
                        WHERE c.identity_id = NEW.identity_id AND c.kind = 'totp'
                          AND c.revoked_at IS NULL) THEN
      RAISE EXCEPTION 'credential: recovery codes are made only beside a live authenticator'
        USING ERRCODE = 'check_violation';
    END IF;
    RETURN NEW;
  END IF;
  IF NEW.secret_ciphertext IS DISTINCT FROM OLD.secret_ciphertext
     AND (NEW.secret_ciphertext IS NOT NULL OR NEW.pii_scrubbed_at IS NULL) THEN
    RAISE EXCEPTION 'credential %: a credential is never edited; a new one is a new row', OLD.id
      USING ERRCODE = 'restrict_violation';
  END IF;
  IF OLD.totp_last_step IS NOT NULL
     AND (NEW.totp_last_step IS NULL OR NEW.totp_last_step <= OLD.totp_last_step)
     AND NEW.totp_last_step IS DISTINCT FROM OLD.totp_last_step THEN
    RAISE EXCEPTION 'credential %: the last accepted time step only moves forward', OLD.id
      USING ERRCODE = 'restrict_violation';
  END IF;
  IF NEW.totp_last_step IS DISTINCT FROM OLD.totp_last_step AND OLD.revoked_at IS NOT NULL THEN
    RAISE EXCEPTION 'credential %: a revoked authenticator accepts no code', OLD.id
      USING ERRCODE = 'restrict_violation';
  END IF;
  RETURN NEW;
END
$$;

CREATE TRIGGER credential_mfa_guard
  BEFORE INSERT OR UPDATE ON credential FOR EACH ROW EXECUTE FUNCTION credential_mfa_guard();

-- Turning the authenticator off, however it happens, takes the recovery codes with it.
CREATE FUNCTION credential_totp_revokes_recovery() RETURNS trigger
  LANGUAGE plpgsql SET search_path = public, pg_temp AS $$
BEGIN
  UPDATE credential
     SET revoked_at = now(), revoke_reason = NEW.revoke_reason
   WHERE identity_id = NEW.identity_id AND kind = 'recovery_codes' AND revoked_at IS NULL;
  RETURN NULL;
END
$$;

CREATE TRIGGER credential_totp_revokes_recovery
  AFTER UPDATE OF revoked_at ON credential
  FOR EACH ROW WHEN (NEW.kind = 'totp' AND OLD.revoked_at IS NULL AND NEW.revoked_at IS NOT NULL)
  EXECUTE FUNCTION credential_totp_revokes_recovery();

-- ------------------------------------------------------------------------
-- recovery_code: ten single-use codes per recovery_codes credential
-- ------------------------------------------------------------------------

-- code_hash is HMAC-SHA256 under a key derived from MFA_ENCRYPTION_KEY: a copy of this table
-- alone cannot be brute-forced. A code is spent by setting used_at, never by deleting it.
CREATE TABLE recovery_code (
  id             uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  credential_id  uuid NOT NULL REFERENCES credential(id) ON DELETE RESTRICT,
  code_hash      bytea,
  used_at        timestamptz,
  created_at     timestamptz NOT NULL DEFAULT now(),
  CONSTRAINT recovery_code_hash_shape CHECK (code_hash IS NULL OR length(code_hash) = 32),
  CONSTRAINT recovery_code_used_after_made CHECK (used_at IS NULL OR used_at >= created_at)
);
CREATE UNIQUE INDEX recovery_code_hash_key
  ON recovery_code (credential_id, code_hash) WHERE code_hash IS NOT NULL;
CREATE INDEX recovery_code_credential_idx ON recovery_code (credential_id);

CREATE FUNCTION recovery_code_guard() RETURNS trigger
  LANGUAGE plpgsql SET search_path = public, pg_temp AS $$
DECLARE
  v_revoked timestamptz;
  v_scrubbed timestamptz;
BEGIN
  IF TG_OP = 'INSERT' THEN
    IF NEW.used_at IS NOT NULL OR NEW.code_hash IS NULL THEN
      RAISE EXCEPTION 'recovery_code: a code is born unused, with its hash'
        USING ERRCODE = 'check_violation';
    END IF;
    IF NOT EXISTS (SELECT 1 FROM credential c
                    WHERE c.id = NEW.credential_id AND c.kind = 'recovery_codes'
                      AND c.revoked_at IS NULL) THEN
      RAISE EXCEPTION 'recovery_code: a code belongs to a live recovery_codes credential'
        USING ERRCODE = 'check_violation';
    END IF;
    IF (SELECT count(*) FROM recovery_code WHERE credential_id = NEW.credential_id) >= 10 THEN
      RAISE EXCEPTION 'recovery_code: a set holds ten codes'
        USING ERRCODE = 'check_violation';
    END IF;
    RETURN NEW;
  END IF;
  SELECT revoked_at, pii_scrubbed_at INTO v_revoked, v_scrubbed
    FROM credential WHERE id = OLD.credential_id;
  IF NEW.credential_id <> OLD.credential_id OR NEW.created_at <> OLD.created_at THEN
    RAISE EXCEPTION 'recovery_code %: fixed for life', OLD.id
      USING ERRCODE = 'restrict_violation';
  END IF;
  IF NEW.code_hash IS DISTINCT FROM OLD.code_hash
     AND (NEW.code_hash IS NOT NULL OR v_scrubbed IS NULL) THEN
    RAISE EXCEPTION 'recovery_code %: the hash is nulled only by the erasure scrub', OLD.id
      USING ERRCODE = 'restrict_violation';
  END IF;
  IF NEW.used_at IS DISTINCT FROM OLD.used_at THEN
    IF OLD.used_at IS NOT NULL THEN
      RAISE EXCEPTION 'recovery_code %: a code works once', OLD.id
        USING ERRCODE = 'restrict_violation';
    END IF;
    IF v_revoked IS NOT NULL THEN
      RAISE EXCEPTION 'recovery_code %: its set has been replaced or turned off', OLD.id
        USING ERRCODE = 'restrict_violation';
    END IF;
    NEW.used_at := now();
  END IF;
  RETURN NEW;
END
$$;

CREATE TRIGGER recovery_code_guard
  BEFORE INSERT OR UPDATE ON recovery_code FOR EACH ROW EXECUTE FUNCTION recovery_code_guard();

REVOKE DELETE, TRUNCATE ON recovery_code FROM uni_auth_app;

-- ------------------------------------------------------------------------
-- auth_session: the assurance level it was opened at
-- ------------------------------------------------------------------------

-- 1: one factor. 2: a second factor too (acr aal2). Single sign-on hands the same level on, and
-- signing in again on the same session can only raise it.
ALTER TABLE auth_session
  ADD COLUMN aal smallint NOT NULL DEFAULT 1,
  ADD CONSTRAINT auth_session_aal_known CHECK (aal IN (1, 2));

CREATE FUNCTION auth_session_aal_rises() RETURNS trigger
  LANGUAGE plpgsql SET search_path = public, pg_temp AS $$
BEGIN
  IF NEW.aal < OLD.aal THEN
    RAISE EXCEPTION 'auth_session %: the assurance level only rises', OLD.id
      USING ERRCODE = 'restrict_violation';
  END IF;
  RETURN NEW;
END
$$;

CREATE TRIGGER auth_session_aal_rises
  BEFORE UPDATE ON auth_session FOR EACH ROW EXECUTE FUNCTION auth_session_aal_rises();

-- ------------------------------------------------------------------------
-- Erasure: the new secrets go with the rest
-- ------------------------------------------------------------------------

CREATE OR REPLACE FUNCTION identity_effects() RETURNS trigger
  LANGUAGE plpgsql SET search_path = public, pg_temp AS $$
BEGIN
  IF NEW.status IS DISTINCT FROM OLD.status AND NEW.status IN ('suspended', 'closed') THEN
    UPDATE auth_session s
       SET revoked_at = now(),
           revoke_reason = CASE NEW.status WHEN 'closed' THEN 'identity_closed' ELSE 'identity_suspended' END
     WHERE s.identity_id = NEW.id AND s.revoked_at IS NULL;
  END IF;
  IF NEW.erased_at IS NOT NULL AND OLD.erased_at IS NULL THEN
    UPDATE identity_identifier
       SET is_primary = false, revoked_at = COALESCE(revoked_at, now()),
           value = NULL, pii_scrubbed_at = now()
     WHERE identity_id = NEW.id AND pii_scrubbed_at IS NULL;
    UPDATE credential
       SET revoked_at = COALESCE(revoked_at, now()),
           revoke_reason = COALESCE(revoke_reason, 'identity_erased'),
           secret_hash = NULL, secret_ciphertext = NULL, provider_subject = NULL,
           provider_email = NULL, provider_email_verified = NULL, pii_scrubbed_at = now()
     WHERE identity_id = NEW.id AND pii_scrubbed_at IS NULL;
    UPDATE recovery_code r
       SET code_hash = NULL
      FROM credential c
     WHERE c.id = r.credential_id AND c.identity_id = NEW.id AND r.code_hash IS NOT NULL;
    UPDATE auth_event
       SET identifier_hash = NULL, ip_address = NULL, user_agent = NULL,
           detail = '{}'::jsonb, pii_scrubbed_at = now()
     WHERE identity_id = NEW.id AND pii_scrubbed_at IS NULL;
    DELETE FROM auth_session WHERE identity_id = NEW.id;
  END IF;
  RETURN NULL;
END
$$;
