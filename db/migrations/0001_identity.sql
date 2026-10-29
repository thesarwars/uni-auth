-- uni-auth's own user store (docs/dev-plan/auth-plan.md section 8).
--
-- uni-auth serves any product, so it owns the human being and every way they sign in, and no
-- product's concepts: no member id, no referral code, no role. A product links its own
-- account to an identity by the `sub` claim, which is identity.id.
--
-- Hand-written SQL, applied in order by scripts/db-migrate.mjs as the owner. The running
-- application connects as a login role that is a member of uni_auth_app, which holds no DDL,
-- no DELETE on anything that is tombstoned, and nothing at all on the journals but INSERT.
--
-- This migration holds identities, their identifiers and credentials, the password policy, the
-- provider sessions and the authentication journal. One-time codes and password recovery
-- arrive with the services that use them (part 4).

-- ------------------------------------------------------------------------
-- Prelude
-- ------------------------------------------------------------------------

CREATE EXTENSION IF NOT EXISTS citext;
CREATE EXTENSION IF NOT EXISTS btree_gist;

DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_catalog.pg_roles WHERE rolname = 'uni_auth_app') THEN
    CREATE ROLE uni_auth_app NOLOGIN;
  END IF;
END
$$;

GRANT USAGE ON SCHEMA public TO uni_auth_app;
ALTER DEFAULT PRIVILEGES IN SCHEMA public
  GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO uni_auth_app;
ALTER DEFAULT PRIVILEGES IN SCHEMA public
  GRANT USAGE, SELECT ON SEQUENCES TO uni_auth_app;

-- A temp table could shadow a real one inside a function whose search_path lists pg_temp
-- first; every function here pins its search_path, and nobody may create temp tables at all.
DO $$
BEGIN
  EXECUTE format('REVOKE TEMPORARY ON DATABASE %I FROM PUBLIC', current_database());
END
$$;

CREATE FUNCTION set_updated_at() RETURNS trigger
  LANGUAGE plpgsql SET search_path = public, pg_temp AS $$
BEGIN
  NEW.updated_at := now();
  RETURN NEW;
END
$$;

CREATE FUNCTION forbid_mutation() RETURNS trigger
  LANGUAGE plpgsql SET search_path = public, pg_temp AS $$
BEGIN
  RAISE EXCEPTION 'table %.% is append-only: % is not permitted',
                  TG_TABLE_SCHEMA, TG_TABLE_NAME, TG_OP
    USING ERRCODE = 'restrict_violation',
          HINT    = 'Append a compensating row instead of changing history.';
END
$$;

-- ------------------------------------------------------------------------
-- identity: the human being
-- ------------------------------------------------------------------------

CREATE TYPE identity_status AS ENUM ('active', 'suspended', 'closed');

-- Tombstoned, never deleted: an id once issued as a `sub` must never name someone else.
-- Erasure (the right to be forgotten) scrubs the row and everything beneath it instead.
CREATE TABLE identity (
  id            uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  status        identity_status NOT NULL DEFAULT 'active',
  display_name  text,
  locale        text NOT NULL DEFAULT 'en-GB',
  suspended_at  timestamptz,
  closed_at     timestamptz,
  erased_at     timestamptz,
  created_at    timestamptz NOT NULL DEFAULT now(),
  updated_at    timestamptz NOT NULL DEFAULT now(),
  CONSTRAINT identity_display_name_bounded
    CHECK (display_name IS NULL OR length(display_name) BETWEEN 1 AND 200),
  CONSTRAINT identity_locale_tag CHECK (locale ~ '^[a-z]{2,3}(-[A-Z]{2})?$'),
  CONSTRAINT identity_suspended_stamped CHECK ((status = 'suspended') = (suspended_at IS NOT NULL)),
  CONSTRAINT identity_closed_stamped CHECK ((status = 'closed') = (closed_at IS NOT NULL)),
  CONSTRAINT identity_erasure_is_a_scrub
    CHECK (erased_at IS NULL OR (status = 'closed' AND display_name IS NULL))
);

-- The server stamps every lifecycle moment; closed and erased are final.
CREATE FUNCTION identity_guard() RETURNS trigger
  LANGUAGE plpgsql SET search_path = public, pg_temp AS $$
BEGIN
  IF TG_OP = 'INSERT' THEN
    IF NEW.status <> 'active' OR NEW.erased_at IS NOT NULL THEN
      RAISE EXCEPTION 'identity: an identity is born active'
        USING ERRCODE = 'check_violation';
    END IF;
    NEW.suspended_at := NULL;
    NEW.closed_at := NULL;
    RETURN NEW;
  END IF;
  IF NEW.id <> OLD.id OR NEW.created_at <> OLD.created_at THEN
    RAISE EXCEPTION 'identity %: id and created_at are fixed', OLD.id
      USING ERRCODE = 'restrict_violation';
  END IF;
  IF OLD.status = 'closed' AND NEW.status <> 'closed' THEN
    RAISE EXCEPTION 'identity %: a closed identity stays closed', OLD.id
      USING ERRCODE = 'restrict_violation';
  END IF;
  IF OLD.erased_at IS NOT NULL AND NEW.erased_at IS DISTINCT FROM OLD.erased_at THEN
    RAISE EXCEPTION 'identity %: erasure is final', OLD.id
      USING ERRCODE = 'restrict_violation';
  END IF;
  IF NEW.status IS DISTINCT FROM OLD.status THEN
    NEW.suspended_at := CASE WHEN NEW.status = 'suspended' THEN now() END;
    NEW.closed_at := CASE WHEN NEW.status = 'closed' THEN now() ELSE OLD.closed_at END;
  ELSE
    NEW.suspended_at := OLD.suspended_at;
    NEW.closed_at := OLD.closed_at;
  END IF;
  IF NEW.erased_at IS NOT NULL AND OLD.erased_at IS NULL THEN
    NEW.erased_at := now();
    NEW.display_name := NULL;
  END IF;
  RETURN NEW;
END
$$;

CREATE TRIGGER identity_guard
  BEFORE INSERT OR UPDATE ON identity FOR EACH ROW EXECUTE FUNCTION identity_guard();
CREATE TRIGGER identity_set_updated_at
  BEFORE UPDATE ON identity FOR EACH ROW EXECUTE FUNCTION set_updated_at();
CREATE INDEX identity_status_idx ON identity (status) WHERE status <> 'closed';

-- ------------------------------------------------------------------------
-- identity_identifier: how a member names themselves at sign-in
-- ------------------------------------------------------------------------

CREATE TYPE identifier_kind AS ENUM ('email', 'phone');

-- An identifier is a claim until a code sent to it is consumed (verified_at). Only a verified,
-- live identifier signs anyone in, and only one identity may hold a given verified address -
-- so an address someone typed and never proved cannot lock its real owner out.
CREATE TABLE identity_identifier (
  id               uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  identity_id      uuid NOT NULL REFERENCES identity(id) ON DELETE RESTRICT,
  kind             identifier_kind NOT NULL,
  value            citext,
    -- email compared case-insensitively; phone in E.164. NULL only once scrubbed.
  verified_at      timestamptz,
  is_primary       boolean NOT NULL DEFAULT false,
  revoked_at       timestamptz,
  pii_scrubbed_at  timestamptz,
  created_at       timestamptz NOT NULL DEFAULT now(),
  updated_at       timestamptz NOT NULL DEFAULT now(),
  CONSTRAINT identity_identifier_phone_e164
    CHECK (kind <> 'phone' OR value IS NULL OR value ~ '^\+[1-9][0-9]{6,14}$'),
  CONSTRAINT identity_identifier_email_format
    CHECK (kind <> 'email' OR value IS NULL
           OR (value ~ '^[^@[:space:]]+@[^@[:space:]]+\.[^@[:space:]]+$' AND length(value) <= 320)),
  CONSTRAINT identity_identifier_pii_scrub
    CHECK ((pii_scrubbed_at IS NULL) = (value IS NOT NULL)
           AND (pii_scrubbed_at IS NULL OR (revoked_at IS NOT NULL AND NOT is_primary))),
  CONSTRAINT identity_identifier_primary_is_live
    CHECK (NOT is_primary OR (revoked_at IS NULL AND verified_at IS NOT NULL))
);
CREATE UNIQUE INDEX identity_identifier_verified_owner_key
  ON identity_identifier (kind, value) WHERE revoked_at IS NULL AND verified_at IS NOT NULL;
CREATE UNIQUE INDEX identity_identifier_one_primary_key
  ON identity_identifier (identity_id, kind) WHERE is_primary;
CREATE UNIQUE INDEX identity_identifier_once_per_identity_key
  ON identity_identifier (identity_id, kind, value) WHERE revoked_at IS NULL;
CREATE INDEX identity_identifier_identity_idx ON identity_identifier (identity_id);

CREATE FUNCTION identity_identifier_guard() RETURNS trigger
  LANGUAGE plpgsql SET search_path = public, pg_temp AS $$
BEGIN
  IF TG_OP = 'INSERT' THEN
    IF NEW.revoked_at IS NOT NULL OR NEW.pii_scrubbed_at IS NOT NULL THEN
      RAISE EXCEPTION 'identity_identifier: an identifier is born live'
        USING ERRCODE = 'check_violation';
    END IF;
    IF NOT EXISTS (SELECT 1 FROM identity i WHERE i.id = NEW.identity_id AND i.status <> 'closed') THEN
      RAISE EXCEPTION 'identity_identifier: identity % is closed', NEW.identity_id
        USING ERRCODE = 'check_violation';
    END IF;
    IF NEW.verified_at IS NOT NULL THEN NEW.verified_at := now(); END IF;
    RETURN NEW;
  END IF;
  IF NEW.identity_id <> OLD.identity_id OR NEW.kind <> OLD.kind OR NEW.created_at <> OLD.created_at
     OR (NEW.value IS DISTINCT FROM OLD.value AND NEW.value IS NOT NULL) THEN
    RAISE EXCEPTION 'identity_identifier %: owner, kind and value are fixed; a new address is a new row', OLD.id
      USING ERRCODE = 'restrict_violation';
  END IF;
  IF OLD.revoked_at IS NOT NULL AND (NEW.revoked_at IS DISTINCT FROM OLD.revoked_at
                                     OR NEW.verified_at IS DISTINCT FROM OLD.verified_at) THEN
    RAISE EXCEPTION 'identity_identifier %: a removed identifier stays removed', OLD.id
      USING ERRCODE = 'restrict_violation';
  END IF;
  IF OLD.verified_at IS NOT NULL AND NEW.verified_at IS DISTINCT FROM OLD.verified_at THEN
    RAISE EXCEPTION 'identity_identifier %: verification is stamped once', OLD.id
      USING ERRCODE = 'restrict_violation';
  END IF;
  IF OLD.verified_at IS NULL AND NEW.verified_at IS NOT NULL THEN NEW.verified_at := now(); END IF;
  IF OLD.revoked_at IS NULL AND NEW.revoked_at IS NOT NULL THEN NEW.revoked_at := now(); END IF;
  IF OLD.pii_scrubbed_at IS NULL AND NEW.pii_scrubbed_at IS NOT NULL THEN NEW.pii_scrubbed_at := now(); END IF;
  RETURN NEW;
END
$$;

CREATE TRIGGER identity_identifier_guard
  BEFORE INSERT OR UPDATE ON identity_identifier
  FOR EACH ROW EXECUTE FUNCTION identity_identifier_guard();
CREATE TRIGGER identity_identifier_set_updated_at
  BEFORE UPDATE ON identity_identifier FOR EACH ROW EXECUTE FUNCTION set_updated_at();

-- ------------------------------------------------------------------------
-- password_policy: versioned rules
-- ------------------------------------------------------------------------

-- A password credential names the policy its hash cleared, which must be the one in force
-- when the hash was written: a hash is evidence of the rules it met. The checklist the screens
-- render is generated from the rules, so the two cannot drift apart.
CREATE TABLE password_policy (
  id                      uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  min_length              smallint NOT NULL,
  require_uppercase       boolean NOT NULL,
  require_digit_or_symbol boolean NOT NULL,
  checklist_label         text NOT NULL GENERATED ALWAYS AS (
                            'At least ' || min_length::text || ' characters'
                            || CASE WHEN require_uppercase THEN ' / One uppercase letter' ELSE '' END
                            || CASE WHEN require_digit_or_symbol THEN ' / One number or symbol' ELSE '' END
                          ) STORED,
  effective               tstzrange NOT NULL,
  created_at              timestamptz NOT NULL DEFAULT now(),
  CONSTRAINT password_policy_min_length_floor CHECK (min_length BETWEEN 8 AND 128),
  CONSTRAINT password_policy_effective_nonempty
    CHECK (NOT isempty(effective) AND NOT lower_inf(effective)),
  CONSTRAINT password_policy_no_overlap EXCLUDE USING gist (effective WITH &&)
);

-- The rules GSN's screens already render.
INSERT INTO password_policy (min_length, require_uppercase, require_digit_or_symbol, effective)
VALUES (8, true, true, tstzrange('2026-01-01 00:00:00+00', NULL, '[)'));

CREATE FUNCTION password_policy_in_effect() RETURNS uuid
  LANGUAGE sql STABLE SET search_path = public, pg_temp AS $$
    SELECT id FROM password_policy WHERE effective @> now()
  $$;

-- ------------------------------------------------------------------------
-- credential: every way in
-- ------------------------------------------------------------------------

-- passkey and totp join this enum when they are built (auth-plan.md section 13, P2).
CREATE TYPE credential_kind AS ENUM ('password', 'oauth_google', 'oauth_apple');

-- A credential is never edited into a different one: a new password is a new row and the old
-- one is revoked. Revoking a credential revokes every session it opened.
CREATE TABLE credential (
  id                      uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  identity_id             uuid NOT NULL REFERENCES identity(id) ON DELETE RESTRICT,
  kind                    credential_kind NOT NULL,
  secret_hash             bytea,
    -- password only: the self-describing "scrypt$N$r$p$salt$hash" the password service writes
  password_policy_id      uuid REFERENCES password_policy(id) ON DELETE RESTRICT,
  provider_subject        text,
    -- oauth only: the upstream provider's `sub`, and nothing else from it is trusted
  provider_email          citext,
  provider_email_verified boolean,
  last_used_at            timestamptz,
  revoked_at              timestamptz,
  revoke_reason           text,
  pii_scrubbed_at         timestamptz,
  created_at              timestamptz NOT NULL DEFAULT now(),
  updated_at              timestamptz NOT NULL DEFAULT now(),
  CONSTRAINT credential_password_shape
    CHECK (kind <> 'password'
           OR (provider_subject IS NULL AND provider_email IS NULL AND password_policy_id IS NOT NULL
               AND (secret_hash IS NOT NULL OR pii_scrubbed_at IS NOT NULL))),
  CONSTRAINT credential_oauth_shape
    CHECK (kind = 'password'
           OR (secret_hash IS NULL AND password_policy_id IS NULL
               AND (provider_subject IS NOT NULL OR pii_scrubbed_at IS NOT NULL))),
  -- No plaintext can be stored by mistake: the column only takes the hash format.
  CONSTRAINT credential_secret_is_a_hash
    CHECK (secret_hash IS NULL OR convert_from(secret_hash, 'UTF8') ~ '^scrypt\$[0-9]+\$[0-9]+\$[0-9]+\$[A-Za-z0-9+/=]+\$[A-Za-z0-9+/=]+$'),
  CONSTRAINT credential_provider_subject_bounded
    CHECK (provider_subject IS NULL OR length(provider_subject) BETWEEN 1 AND 255),
  CONSTRAINT credential_provider_email_verified_with_email
    CHECK ((provider_email IS NULL) = (provider_email_verified IS NULL)),
  CONSTRAINT credential_revocation_explained
    CHECK ((revoked_at IS NULL) = (revoke_reason IS NULL)),
  CONSTRAINT credential_revoke_reason_known
    CHECK (revoke_reason IS NULL OR revoke_reason IN
           ('replaced', 'removed_by_member', 'identity_erased', 'operator', 'compromised')),
  CONSTRAINT credential_pii_scrub
    CHECK (pii_scrubbed_at IS NULL
           OR (revoked_at IS NOT NULL AND secret_hash IS NULL AND provider_subject IS NULL
               AND provider_email IS NULL))
);
CREATE UNIQUE INDEX credential_one_live_password_key
  ON credential (identity_id) WHERE kind = 'password' AND revoked_at IS NULL;
CREATE UNIQUE INDEX credential_provider_subject_key
  ON credential (kind, provider_subject) WHERE revoked_at IS NULL AND provider_subject IS NOT NULL;
CREATE INDEX credential_identity_idx ON credential (identity_id);

CREATE FUNCTION credential_guard() RETURNS trigger
  LANGUAGE plpgsql SET search_path = public, pg_temp AS $$
BEGIN
  IF TG_OP = 'INSERT' THEN
    IF NEW.revoked_at IS NOT NULL OR NEW.pii_scrubbed_at IS NOT NULL THEN
      RAISE EXCEPTION 'credential: a credential is born live'
        USING ERRCODE = 'check_violation';
    END IF;
    IF NOT EXISTS (SELECT 1 FROM identity i WHERE i.id = NEW.identity_id AND i.status <> 'closed') THEN
      RAISE EXCEPTION 'credential: identity % is closed', NEW.identity_id
        USING ERRCODE = 'check_violation';
    END IF;
    IF NEW.kind = 'password' AND NEW.password_policy_id IS DISTINCT FROM password_policy_in_effect() THEN
      RAISE EXCEPTION 'credential: a password is stamped with the policy in force when it is set'
        USING ERRCODE = 'check_violation';
    END IF;
    RETURN NEW;
  END IF;
  IF OLD.revoked_at IS NOT NULL
     AND (NEW.revoked_at IS DISTINCT FROM OLD.revoked_at OR NEW.revoke_reason IS DISTINCT FROM OLD.revoke_reason) THEN
    RAISE EXCEPTION 'credential %: a revoked credential stays revoked', OLD.id
      USING ERRCODE = 'restrict_violation';
  END IF;
  -- Fixed for life, except that the erasure scrub may null the secret and the provider's data.
  IF NEW.identity_id <> OLD.identity_id OR NEW.kind <> OLD.kind OR NEW.created_at <> OLD.created_at
     OR NEW.password_policy_id IS DISTINCT FROM OLD.password_policy_id
     OR (NEW.secret_hash IS DISTINCT FROM OLD.secret_hash AND NEW.secret_hash IS NOT NULL)
     OR (NEW.provider_subject IS DISTINCT FROM OLD.provider_subject AND NEW.provider_subject IS NOT NULL)
     OR (NEW.provider_email IS DISTINCT FROM OLD.provider_email AND NEW.provider_email IS NOT NULL) THEN
    RAISE EXCEPTION 'credential %: a credential is never edited; a new one is a new row', OLD.id
      USING ERRCODE = 'restrict_violation';
  END IF;
  IF NEW.pii_scrubbed_at IS NULL
     AND (NEW.secret_hash IS DISTINCT FROM OLD.secret_hash
          OR NEW.provider_subject IS DISTINCT FROM OLD.provider_subject
          OR NEW.provider_email IS DISTINCT FROM OLD.provider_email) THEN
    RAISE EXCEPTION 'credential %: secrets are nulled only by the erasure scrub', OLD.id
      USING ERRCODE = 'restrict_violation';
  END IF;
  IF OLD.revoked_at IS NULL AND NEW.revoked_at IS NOT NULL THEN NEW.revoked_at := now(); END IF;
  IF OLD.pii_scrubbed_at IS NULL AND NEW.pii_scrubbed_at IS NOT NULL THEN NEW.pii_scrubbed_at := now(); END IF;
  RETURN NEW;
END
$$;

CREATE TRIGGER credential_guard
  BEFORE INSERT OR UPDATE ON credential FOR EACH ROW EXECUTE FUNCTION credential_guard();
CREATE TRIGGER credential_set_updated_at
  BEFORE UPDATE ON credential FOR EACH ROW EXECUTE FUNCTION set_updated_at();

-- ------------------------------------------------------------------------
-- auth_session: one sign-in at the provider, on one device
-- ------------------------------------------------------------------------

-- Hydra holds the refresh tokens; this row is the sign-in itself, named by Hydra's login
-- session id - the `sid` claim. It is what the devices screen lists, what sign-out revokes and
-- what an API's denylist names (auth-plan.md section 9).
CREATE TABLE auth_session (
  id                  uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  identity_id         uuid NOT NULL REFERENCES identity(id) ON DELETE RESTRICT,
  sid                 text NOT NULL UNIQUE,
  credential_id       uuid REFERENCES credential(id) ON DELETE RESTRICT,
    -- the credential the session was opened with
  client_id           text,
    -- the client the member was signing in to when the session began
  device_fingerprint  text,
  ip_address          inet,
  user_agent          text,
  last_seen_at        timestamptz NOT NULL DEFAULT now(),
  expires_at          timestamptz NOT NULL,
  revoked_at          timestamptz,
  revoke_reason       text,
  created_at          timestamptz NOT NULL DEFAULT now(),
  updated_at          timestamptz NOT NULL DEFAULT now(),
  CONSTRAINT auth_session_sid_bounded CHECK (length(sid) BETWEEN 1 AND 128),
  CONSTRAINT auth_session_client_id_bounded
    CHECK (client_id IS NULL OR length(client_id) BETWEEN 1 AND 255),
  CONSTRAINT auth_session_lifetime
    CHECK (expires_at > created_at AND expires_at <= created_at + interval '90 days'),
  CONSTRAINT auth_session_seen_after_start CHECK (last_seen_at >= created_at),
  CONSTRAINT auth_session_revocation_explained
    CHECK ((revoked_at IS NULL) = (revoke_reason IS NULL)
       AND (revoked_at IS NULL OR revoked_at >= created_at)),
  CONSTRAINT auth_session_revoke_reason_known
    CHECK (revoke_reason IS NULL OR revoke_reason IN
           ('sign_out', 'identity_suspended', 'identity_closed', 'credential_revoked',
            'password_reset', 'operator'))
);
CREATE INDEX auth_session_live_idx ON auth_session (identity_id) WHERE revoked_at IS NULL;
CREATE INDEX auth_session_identity_idx ON auth_session (identity_id, created_at DESC, id DESC);
CREATE INDEX auth_session_credential_idx ON auth_session (credential_id) WHERE credential_id IS NOT NULL;
CREATE INDEX auth_session_expiry_idx ON auth_session (expires_at) WHERE revoked_at IS NULL;

CREATE FUNCTION auth_session_guard() RETURNS trigger
  LANGUAGE plpgsql SET search_path = public, pg_temp AS $$
BEGIN
  IF TG_OP = 'INSERT' THEN
    IF NEW.revoked_at IS NOT NULL THEN
      RAISE EXCEPTION 'auth_session: a session is born live'
        USING ERRCODE = 'check_violation';
    END IF;
    IF NOT EXISTS (SELECT 1 FROM identity i WHERE i.id = NEW.identity_id AND i.status = 'active') THEN
      RAISE EXCEPTION 'auth_session: identity % is suspended or closed; no session opens on it', NEW.identity_id
        USING ERRCODE = 'check_violation';
    END IF;
    IF NEW.credential_id IS NOT NULL
       AND NOT EXISTS (SELECT 1 FROM credential c
                       WHERE c.id = NEW.credential_id AND c.identity_id = NEW.identity_id
                         AND c.revoked_at IS NULL) THEN
      RAISE EXCEPTION 'auth_session: a session opens only on a live credential of its own identity'
        USING ERRCODE = 'check_violation';
    END IF;
    RETURN NEW;
  END IF;
  IF OLD.revoked_at IS NOT NULL THEN
    RAISE EXCEPTION 'auth_session %: a revoked session is final; sign in again', OLD.id
      USING ERRCODE = 'restrict_violation';
  END IF;
  IF NEW.identity_id <> OLD.identity_id OR NEW.sid <> OLD.sid
     OR NEW.credential_id IS DISTINCT FROM OLD.credential_id
     OR NEW.client_id IS DISTINCT FROM OLD.client_id
     OR NEW.created_at <> OLD.created_at OR NEW.expires_at > OLD.expires_at
     OR NEW.last_seen_at < OLD.last_seen_at THEN
    RAISE EXCEPTION 'auth_session %: identity, sid, credential, client and start are fixed, expiry only shortens and freshness only moves forward', OLD.id
      USING ERRCODE = 'restrict_violation';
  END IF;
  IF NEW.revoked_at IS NOT NULL THEN NEW.revoked_at := now(); END IF;
  RETURN NEW;
END
$$;

CREATE TRIGGER auth_session_guard
  BEFORE INSERT OR UPDATE ON auth_session FOR EACH ROW EXECUTE FUNCTION auth_session_guard();
CREATE TRIGGER auth_session_set_updated_at
  BEFORE UPDATE ON auth_session FOR EACH ROW EXECUTE FUNCTION set_updated_at();

-- ------------------------------------------------------------------------
-- auth_event: the authentication journal
-- ------------------------------------------------------------------------

CREATE TYPE auth_event_kind AS ENUM (
  'sign_in', 'sign_out', 'identity_created', 'session_revoked', 'lockout',
  'credential_added', 'credential_revoked', 'password_changed', 'password_reset',
  'identifier_added', 'identifier_verified', 'identifier_removed');

CREATE TYPE auth_event_outcome AS ENUM ('success', 'failure');

-- One row per authentication event: the evidence behind a lockout, the answer to a support
-- question, the first thing an incident review asks for. identity_id is NULL when a sign-in
-- names nobody; identifier_hash (SHA-256 of the normalised email or phone) then ties the
-- attempts together without storing the address. auth_session_id is a pointer, not a
-- reference: erasure deletes sessions, and the journal outlives them.
CREATE TABLE auth_event (
  id              uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  occurred_at     timestamptz NOT NULL DEFAULT now(),
  identity_id     uuid REFERENCES identity(id) ON DELETE RESTRICT,
  identifier_hash bytea,
  kind            auth_event_kind NOT NULL,
  outcome         auth_event_outcome NOT NULL,
  client_id       text,
  credential_kind credential_kind,
  auth_session_id uuid,
  ip_address      inet,
  user_agent      text,
  detail          jsonb NOT NULL DEFAULT '{}'::jsonb,
  pii_scrubbed_at timestamptz,
  created_at      timestamptz NOT NULL DEFAULT now(),
  CONSTRAINT auth_event_names_someone
    CHECK (num_nonnulls(identity_id, identifier_hash) >= 1 OR pii_scrubbed_at IS NOT NULL),
  CONSTRAINT auth_event_identifier_hash_sha256
    CHECK (identifier_hash IS NULL OR octet_length(identifier_hash) = 32),
  CONSTRAINT auth_event_client_id_bounded
    CHECK (client_id IS NULL OR length(client_id) BETWEEN 1 AND 255),
  CONSTRAINT auth_event_detail_is_object CHECK (jsonb_typeof(detail) = 'object'),
  CONSTRAINT auth_event_occurred_at_creation CHECK (occurred_at <= created_at),
  CONSTRAINT auth_event_pii_scrub
    CHECK (pii_scrubbed_at IS NULL
           OR (identifier_hash IS NULL AND ip_address IS NULL AND user_agent IS NULL
               AND detail = '{}'::jsonb AND pii_scrubbed_at >= created_at))
);
CREATE INDEX auth_event_identity_idx
  ON auth_event (identity_id, occurred_at DESC, id DESC) WHERE identity_id IS NOT NULL;
CREATE INDEX auth_event_identifier_idx
  ON auth_event (identifier_hash, occurred_at DESC) WHERE identifier_hash IS NOT NULL;
CREATE INDEX auth_event_session_idx ON auth_event (auth_session_id) WHERE auth_session_id IS NOT NULL;

-- Append-only, except the erasure scrub: once, personal data to NULL.
CREATE FUNCTION auth_event_guard() RETURNS trigger
  LANGUAGE plpgsql SET search_path = public, pg_temp AS $$
BEGIN
  IF TG_OP = 'INSERT' THEN
    NEW.occurred_at := now();        -- the server stamps the event, not the caller
    NEW.pii_scrubbed_at := NULL;     -- an event is born unscrubbed
    RETURN NEW;
  END IF;
  IF OLD.pii_scrubbed_at IS NULL AND NEW.pii_scrubbed_at IS NOT NULL
     AND NEW.identifier_hash IS NULL AND NEW.ip_address IS NULL AND NEW.user_agent IS NULL
     AND NEW.detail = '{}'::jsonb
     AND (to_jsonb(NEW) - ARRAY['identifier_hash', 'ip_address', 'user_agent', 'detail', 'pii_scrubbed_at'])
       = (to_jsonb(OLD) - ARRAY['identifier_hash', 'ip_address', 'user_agent', 'detail', 'pii_scrubbed_at']) THEN
    NEW.pii_scrubbed_at := now();
    RETURN NEW;
  END IF;
  RAISE EXCEPTION 'auth_event %: the journal is append-only; only the erasure scrub may change a row', OLD.id
    USING ERRCODE = 'restrict_violation',
          HINT    = 'Append a new event instead of changing history.';
END
$$;

CREATE TRIGGER auth_event_guard
  BEFORE INSERT OR UPDATE ON auth_event FOR EACH ROW EXECUTE FUNCTION auth_event_guard();
CREATE TRIGGER auth_event_no_delete
  BEFORE DELETE ON auth_event FOR EACH ROW EXECUTE FUNCTION forbid_mutation();
CREATE TRIGGER auth_event_no_truncate
  BEFORE TRUNCATE ON auth_event FOR EACH STATEMENT EXECUTE FUNCTION forbid_mutation();

-- ------------------------------------------------------------------------
-- Lifecycle effects
-- ------------------------------------------------------------------------

-- Revoking a credential revokes the sessions it opened.
CREATE FUNCTION credential_revoke_sessions() RETURNS trigger
  LANGUAGE plpgsql SET search_path = public, pg_temp AS $$
BEGIN
  UPDATE auth_session s
     SET revoked_at = now(), revoke_reason = 'credential_revoked'
   WHERE s.credential_id = NEW.id AND s.revoked_at IS NULL;
  RETURN NULL;
END
$$;

CREATE TRIGGER credential_revoke_sessions
  AFTER UPDATE OF revoked_at ON credential
  FOR EACH ROW WHEN (OLD.revoked_at IS NULL AND NEW.revoked_at IS NOT NULL)
  EXECUTE FUNCTION credential_revoke_sessions();

-- Suspending or closing an identity revokes every live session. Erasure scrubs everything
-- personal beneath it - identifiers, credentials, the journal - and deletes its sessions.
CREATE FUNCTION identity_effects() RETURNS trigger
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
           secret_hash = NULL, provider_subject = NULL,
           provider_email = NULL, provider_email_verified = NULL, pii_scrubbed_at = now()
     WHERE identity_id = NEW.id AND pii_scrubbed_at IS NULL;
    UPDATE auth_event
       SET identifier_hash = NULL, ip_address = NULL, user_agent = NULL,
           detail = '{}'::jsonb, pii_scrubbed_at = now()
     WHERE identity_id = NEW.id AND pii_scrubbed_at IS NULL;
    DELETE FROM auth_session WHERE identity_id = NEW.id;
  END IF;
  RETURN NULL;
END
$$;

CREATE TRIGGER identity_effects
  AFTER UPDATE ON identity FOR EACH ROW EXECUTE FUNCTION identity_effects();

-- ------------------------------------------------------------------------
-- Privileges
-- ------------------------------------------------------------------------

-- Tombstoned rows are never deleted, and the journal only grows. auth_session keeps DELETE:
-- erasure deletes sessions, and it runs as the caller.
REVOKE DELETE, TRUNCATE ON identity, identity_identifier, credential, password_policy FROM uni_auth_app;
REVOKE UPDATE ON password_policy FROM uni_auth_app;
REVOKE DELETE, TRUNCATE ON auth_event FROM uni_auth_app;
REVOKE TRUNCATE ON auth_session FROM uni_auth_app;
