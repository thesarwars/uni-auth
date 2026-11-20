-- The operator console (account-plan.md part 8): who may use it, and everything they did there.
--
-- Operators are granted and revoked by the owner role only (scripts/operator.mjs), never by the
-- application: a flaw in the running server can't make anyone an operator. The application
-- reads the list and appends to the log; it can't change or delete either.

-- ------------------------------------------------------------------------
-- operator: who may use the console
-- ------------------------------------------------------------------------

CREATE TABLE operator (
  id           uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  identity_id  uuid NOT NULL REFERENCES identity(id) ON DELETE RESTRICT,
  granted_at   timestamptz NOT NULL DEFAULT now(),
  -- Who asked for it and why, in a few words: "support team, ticket 123".
  grant_note   text NOT NULL,
  revoked_at   timestamptz,
  revoke_note  text,
  CONSTRAINT operator_grant_note_bounded CHECK (length(grant_note) BETWEEN 1 AND 500),
  CONSTRAINT operator_revocation_explained
    CHECK ((revoked_at IS NULL) = (revoke_note IS NULL)
       AND (revoke_note IS NULL OR length(revoke_note) BETWEEN 1 AND 500))
);

CREATE UNIQUE INDEX operator_live_once ON operator (identity_id) WHERE revoked_at IS NULL;

-- The server stamps the times; a grant is revoked once and never revived.
CREATE FUNCTION operator_guard() RETURNS trigger
  LANGUAGE plpgsql SET search_path = public, pg_temp AS $$
BEGIN
  IF TG_OP = 'INSERT' THEN
    IF NOT EXISTS (SELECT 1 FROM identity i WHERE i.id = NEW.identity_id AND i.status = 'active') THEN
      RAISE EXCEPTION 'operator: only an active identity is made an operator'
        USING ERRCODE = 'check_violation';
    END IF;
    NEW.granted_at := now();
    NEW.revoked_at := NULL;
    NEW.revoke_note := NULL;
    RETURN NEW;
  END IF;
  IF NEW.id <> OLD.id OR NEW.identity_id <> OLD.identity_id OR NEW.granted_at <> OLD.granted_at
     OR NEW.grant_note <> OLD.grant_note THEN
    RAISE EXCEPTION 'operator %: only revoked_at and revoke_note change', OLD.id
      USING ERRCODE = 'restrict_violation';
  END IF;
  IF OLD.revoked_at IS NOT NULL THEN
    RAISE EXCEPTION 'operator %: a revoked grant stays revoked', OLD.id
      USING ERRCODE = 'restrict_violation';
  END IF;
  IF NEW.revoked_at IS NOT NULL THEN
    NEW.revoked_at := now();
  END IF;
  RETURN NEW;
END
$$;

CREATE TRIGGER operator_guard
  BEFORE INSERT OR UPDATE ON operator FOR EACH ROW EXECUTE FUNCTION operator_guard();

-- Closing an identity ends its operator grant with it. SECURITY DEFINER: whoever closes the
-- identity - the application, whose role can't write this table - the grant ends with it.
CREATE FUNCTION operator_effects() RETURNS trigger
  LANGUAGE plpgsql SECURITY DEFINER SET search_path = public, pg_temp AS $$
BEGIN
  IF NEW.status = 'closed' AND OLD.status <> 'closed' THEN
    UPDATE operator SET revoked_at = now(), revoke_note = 'identity closed'
     WHERE identity_id = NEW.id AND revoked_at IS NULL;
  END IF;
  RETURN NEW;
END
$$;

CREATE TRIGGER operator_effects
  AFTER UPDATE OF status ON identity FOR EACH ROW EXECUTE FUNCTION operator_effects();

REVOKE INSERT, UPDATE, DELETE, TRUNCATE ON operator FROM uni_auth_app;

-- ------------------------------------------------------------------------
-- operator_action: everything done in the console, looking included
-- ------------------------------------------------------------------------

CREATE TABLE operator_action (
  id           uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  operator_id  uuid NOT NULL REFERENCES operator(id) ON DELETE RESTRICT,
  -- Whose account: null for a search that found no one.
  identity_id  uuid REFERENCES identity(id) ON DELETE RESTRICT,
  action       text NOT NULL,
  -- Why, in the operator's words: required for every change.
  reason       text,
  ip_address   inet,
  user_agent   text,
  occurred_at  timestamptz NOT NULL DEFAULT now(),
  CONSTRAINT operator_action_known
    CHECK (action IN ('searched', 'viewed', 'suspended', 'reinstated', 'signed_out')),
  CONSTRAINT operator_action_change_has_reason
    CHECK (action IN ('searched', 'viewed') OR length(reason) BETWEEN 1 AND 500),
  CONSTRAINT operator_action_reason_bounded CHECK (reason IS NULL OR length(reason) <= 500),
  CONSTRAINT operator_action_names_someone
    CHECK (action = 'searched' OR identity_id IS NOT NULL)
);

CREATE INDEX operator_action_identity_idx ON operator_action (identity_id, occurred_at DESC)
  WHERE identity_id IS NOT NULL;
CREATE INDEX operator_action_operator_idx ON operator_action (operator_id, occurred_at DESC);

-- Only a live operator acts, and the server stamps the time.
CREATE FUNCTION operator_action_guard() RETURNS trigger
  LANGUAGE plpgsql SET search_path = public, pg_temp AS $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM operator o WHERE o.id = NEW.operator_id AND o.revoked_at IS NULL) THEN
    RAISE EXCEPTION 'operator_action: only a live operator acts'
      USING ERRCODE = 'check_violation';
  END IF;
  NEW.occurred_at := now();
  RETURN NEW;
END
$$;

CREATE TRIGGER operator_action_guard
  BEFORE INSERT ON operator_action FOR EACH ROW EXECUTE FUNCTION operator_action_guard();

-- The log is append-only for the application.
REVOKE UPDATE, DELETE, TRUNCATE ON operator_action FROM uni_auth_app;
