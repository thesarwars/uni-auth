-- Identity notices (auth-plan.md section 12.2, part 7): what the products that trust uni-auth are
-- told when an identity closes or is erased, so a closed member does not stay live in them (AU-8).
--
-- A notice is written by the same transaction that closes or erases the identity, whoever runs
-- it - the login application, an operator's script, a future account screen - so none is ever
-- missed. The login application delivers it afterwards: it ends the identity's sessions at Hydra,
-- then tells each product, retrying until the product says it has acted. Delivery is
-- at-least-once; a product's handling is idempotent on (sub, event).

CREATE TABLE identity_notice (
  id                uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  identity_id       uuid NOT NULL REFERENCES identity(id) ON DELETE RESTRICT,
  event             text NOT NULL CHECK (event IN ('closed', 'erased')),
  occurred_at       timestamptz NOT NULL DEFAULT now(),
  -- The Hydra sessions are ended once, on the first attempt that reaches Hydra.
  sessions_ended_at timestamptz,
  attempts          integer NOT NULL DEFAULT 0 CHECK (attempts >= 0),
  next_attempt_at   timestamptz NOT NULL DEFAULT now(),
  last_error        text,
  delivered_at      timestamptz,
  CONSTRAINT identity_notice_once UNIQUE (identity_id, event)
);
CREATE INDEX identity_notice_due_idx ON identity_notice (next_attempt_at) WHERE delivered_at IS NULL;

-- A notice says what happened and when; only its delivery moves. Once delivered it is final.
CREATE FUNCTION identity_notice_guard() RETURNS trigger
  LANGUAGE plpgsql SET search_path = public, pg_temp AS $$
BEGIN
  IF NEW.identity_id IS DISTINCT FROM OLD.identity_id OR NEW.event IS DISTINCT FROM OLD.event
     OR NEW.occurred_at IS DISTINCT FROM OLD.occurred_at THEN
    RAISE EXCEPTION 'identity_notice %: what happened is immutable', OLD.id
      USING ERRCODE = 'restrict_violation';
  END IF;
  IF OLD.delivered_at IS NOT NULL THEN
    RAISE EXCEPTION 'identity_notice %: a delivered notice is final', OLD.id
      USING ERRCODE = 'restrict_violation';
  END IF;
  IF OLD.sessions_ended_at IS NOT NULL AND NEW.sessions_ended_at IS DISTINCT FROM OLD.sessions_ended_at THEN
    RAISE EXCEPTION 'identity_notice %: sessions_ended_at is permanent', OLD.id
      USING ERRCODE = 'restrict_violation';
  END IF;
  RETURN NEW;
END
$$;

CREATE TRIGGER identity_notice_guard
  BEFORE UPDATE ON identity_notice FOR EACH ROW EXECUTE FUNCTION identity_notice_guard();

CREATE FUNCTION identity_notice_issue() RETURNS trigger
  LANGUAGE plpgsql SET search_path = public, pg_temp AS $$
BEGIN
  IF NEW.status = 'closed' AND OLD.status IS DISTINCT FROM 'closed' THEN
    INSERT INTO identity_notice (identity_id, event) VALUES (NEW.id, 'closed')
      ON CONFLICT ON CONSTRAINT identity_notice_once DO NOTHING;
  END IF;
  IF NEW.erased_at IS NOT NULL AND OLD.erased_at IS NULL THEN
    INSERT INTO identity_notice (identity_id, event) VALUES (NEW.id, 'erased')
      ON CONFLICT ON CONSTRAINT identity_notice_once DO NOTHING;
  END IF;
  RETURN NULL;
END
$$;

CREATE TRIGGER identity_notice_issue
  AFTER UPDATE OF status, erased_at ON identity
  FOR EACH ROW EXECUTE FUNCTION identity_notice_issue();

-- The journal of what was told: never deleted.
REVOKE DELETE, TRUNCATE ON identity_notice FROM uni_auth_app;
