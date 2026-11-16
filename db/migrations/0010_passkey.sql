-- Passkeys (account-plan.md section 5 and section 6, part 5): WebAuthn credentials that sign a
-- member in without a password (AC-D5) or stand as the second step.
--
-- What the schema adds:
--   - a `passkey` credential: the authenticator's credential id, its COSE public key (never a
--     secret: the private key never leaves the device), the signature counter, transports,
--     AAGUID, backup flags and the member's name for it;
--   - the credential id and public key are fixed for life; the counter only moves forward, so a
--     cloned authenticator is refused; only the name and the backup state may change;
--   - at most twenty live passkeys per identity;
--   - erasure scrubs the id, the key and the name with the rest.

ALTER TABLE credential
  ADD COLUMN webauthn_credential_id bytea,
  ADD COLUMN public_key             bytea,
  ADD COLUMN sign_count             bigint,
  ADD COLUMN transports             text[],
  ADD COLUMN aaguid                 uuid,
  ADD COLUMN backup_eligible        boolean,
  ADD COLUMN backup_state           boolean,
  ADD COLUMN nickname               text;

-- The passkey columns belong to passkeys only.
ALTER TABLE credential ADD CONSTRAINT credential_passkey_columns
  CHECK (kind = 'passkey'
         OR (webauthn_credential_id IS NULL AND public_key IS NULL AND sign_count IS NULL
             AND transports IS NULL AND aaguid IS NULL AND backup_eligible IS NULL
             AND backup_state IS NULL AND nickname IS NULL));

ALTER TABLE credential ADD CONSTRAINT credential_passkey_shape
  CHECK (kind <> 'passkey'
         OR (secret_hash IS NULL AND password_policy_id IS NULL
             AND provider_subject IS NULL AND provider_email IS NULL
             AND secret_ciphertext IS NULL AND totp_last_step IS NULL
             AND sign_count IS NOT NULL AND backup_eligible IS NOT NULL
             AND backup_state IS NOT NULL AND transports IS NOT NULL
             AND ((webauthn_credential_id IS NOT NULL AND public_key IS NOT NULL
                   AND nickname IS NOT NULL)
                  OR pii_scrubbed_at IS NOT NULL)));

-- WebAuthn allows a credential id of up to 1023 bytes; authenticators use 16 to 64 or so.
ALTER TABLE credential ADD CONSTRAINT credential_webauthn_id_bounded
  CHECK (webauthn_credential_id IS NULL OR length(webauthn_credential_id) BETWEEN 16 AND 1023);
ALTER TABLE credential ADD CONSTRAINT credential_public_key_bounded
  CHECK (public_key IS NULL OR length(public_key) BETWEEN 32 AND 2048);
ALTER TABLE credential ADD CONSTRAINT credential_sign_count_range
  CHECK (sign_count IS NULL OR sign_count BETWEEN 0 AND 4294967295);
ALTER TABLE credential ADD CONSTRAINT credential_transports_known
  CHECK (transports IS NULL
         OR (cardinality(transports) <= 8
             AND transports <@ ARRAY['usb', 'nfc', 'ble', 'internal', 'hybrid', 'smart-card',
                                     'cable']::text[]));
ALTER TABLE credential ADD CONSTRAINT credential_nickname_bounded
  CHECK (nickname IS NULL OR (length(nickname) BETWEEN 1 AND 60 AND nickname = btrim(nickname)));
ALTER TABLE credential ADD CONSTRAINT credential_backup_needs_eligible
  CHECK (backup_state IS NOT TRUE OR backup_eligible IS TRUE);

ALTER TABLE credential DROP CONSTRAINT credential_pii_scrub;
ALTER TABLE credential ADD CONSTRAINT credential_pii_scrub
  CHECK (pii_scrubbed_at IS NULL
         OR (revoked_at IS NOT NULL AND secret_hash IS NULL AND secret_ciphertext IS NULL
             AND provider_subject IS NULL AND provider_email IS NULL
             AND webauthn_credential_id IS NULL AND public_key IS NULL AND nickname IS NULL));

-- A credential id names one live passkey, whoever holds it.
CREATE UNIQUE INDEX credential_webauthn_id_key
  ON credential (webauthn_credential_id)
  WHERE kind = 'passkey' AND revoked_at IS NULL AND webauthn_credential_id IS NOT NULL;

CREATE FUNCTION credential_passkey_guard() RETURNS trigger
  LANGUAGE plpgsql SET search_path = public, pg_temp AS $$
BEGIN
  IF TG_OP = 'INSERT' THEN
    IF NEW.kind = 'passkey'
       AND (SELECT count(*) FROM credential c
             WHERE c.identity_id = NEW.identity_id AND c.kind = 'passkey'
               AND c.revoked_at IS NULL) >= 20 THEN
      RAISE EXCEPTION 'credential: an identity holds at most twenty passkeys'
        USING ERRCODE = 'check_violation';
    END IF;
    RETURN NEW;
  END IF;
  IF OLD.kind <> 'passkey' THEN RETURN NEW; END IF;
  -- Fixed for life, except that the erasure scrub nulls the id and the key.
  IF NEW.aaguid IS DISTINCT FROM OLD.aaguid
     OR NEW.backup_eligible IS DISTINCT FROM OLD.backup_eligible
     OR NEW.transports IS DISTINCT FROM OLD.transports
     OR (NEW.webauthn_credential_id IS DISTINCT FROM OLD.webauthn_credential_id
         AND (NEW.webauthn_credential_id IS NOT NULL OR NEW.pii_scrubbed_at IS NULL))
     OR (NEW.public_key IS DISTINCT FROM OLD.public_key
         AND (NEW.public_key IS NOT NULL OR NEW.pii_scrubbed_at IS NULL)) THEN
    RAISE EXCEPTION 'credential %: a passkey is never edited; a new one is a new row', OLD.id
      USING ERRCODE = 'restrict_violation';
  END IF;
  IF NEW.nickname IS DISTINCT FROM OLD.nickname THEN
    IF NEW.nickname IS NULL AND NEW.pii_scrubbed_at IS NULL THEN
      RAISE EXCEPTION 'credential %: a passkey keeps a name', OLD.id
        USING ERRCODE = 'restrict_violation';
    END IF;
    IF NEW.nickname IS NOT NULL AND OLD.revoked_at IS NOT NULL THEN
      RAISE EXCEPTION 'credential %: a removed passkey is not renamed', OLD.id
        USING ERRCODE = 'restrict_violation';
    END IF;
  END IF;
  IF NEW.sign_count IS DISTINCT FROM OLD.sign_count OR NEW.backup_state IS DISTINCT FROM OLD.backup_state THEN
    IF OLD.revoked_at IS NOT NULL THEN
      RAISE EXCEPTION 'credential %: a removed passkey signs nothing in', OLD.id
        USING ERRCODE = 'restrict_violation';
    END IF;
    -- A counter that stands still or goes back means a copy of the key: refused. An
    -- authenticator that keeps no counter (most synced passkeys) always reports 0.
    IF NEW.sign_count IS NULL OR NEW.sign_count < OLD.sign_count
       OR (NEW.sign_count = OLD.sign_count AND NEW.sign_count <> 0) THEN
      RAISE EXCEPTION 'credential %: the signature counter only moves forward', OLD.id
        USING ERRCODE = 'restrict_violation';
    END IF;
  END IF;
  RETURN NEW;
END
$$;

CREATE TRIGGER credential_passkey_guard
  BEFORE INSERT OR UPDATE ON credential FOR EACH ROW EXECUTE FUNCTION credential_passkey_guard();

-- ------------------------------------------------------------------------
-- Erasure: the passkeys go with the rest
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
           provider_email = NULL, provider_email_verified = NULL,
           webauthn_credential_id = NULL, public_key = NULL, nickname = NULL,
           pii_scrubbed_at = now()
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
