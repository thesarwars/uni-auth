-- A member's profile photo: shown in the account centre and, as the OIDC `picture` claim, to
-- apps that are granted the profile scope.
--
-- The image itself lives in object storage (S3_PHOTO_BUCKET), as a 256px WebP the server made
-- from the upload; this table is the record of every one ever stored. At most one is current per
-- identity. A replaced or removed photo stops being served at once and its object is deleted by
-- the PhotoCleanup job, which stamps object_deleted_at - so no object outlives its row unseen.

CREATE TABLE identity_photo (
  id                uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  identity_id       uuid NOT NULL REFERENCES identity(id) ON DELETE RESTRICT,
  -- photos/<22 random base64url characters>.webp: unguessable, so the public URL names no one
  object_key        text NOT NULL UNIQUE,
  bytes             integer NOT NULL,
  created_at        timestamptz NOT NULL DEFAULT now(),
  replaced_at       timestamptz,
  object_deleted_at timestamptz,
  CONSTRAINT identity_photo_key_shape CHECK (object_key ~ '^photos/[A-Za-z0-9_-]{22}\.webp$'),
  CONSTRAINT identity_photo_bytes_bounded CHECK (bytes BETWEEN 1 AND 1048576),
  CONSTRAINT identity_photo_deleted_after_replaced
    CHECK (object_deleted_at IS NULL OR replaced_at IS NOT NULL)
);

CREATE UNIQUE INDEX identity_photo_current_once
  ON identity_photo (identity_id) WHERE replaced_at IS NULL;
CREATE INDEX identity_photo_to_delete
  ON identity_photo (replaced_at) WHERE replaced_at IS NOT NULL AND object_deleted_at IS NULL;

-- The server stamps the times; a photo, once replaced, is never current again, and its key and
-- owner never change.
CREATE FUNCTION identity_photo_guard() RETURNS trigger
  LANGUAGE plpgsql SET search_path = public, pg_temp AS $$
BEGIN
  IF TG_OP = 'INSERT' THEN
    IF EXISTS (SELECT 1 FROM identity i WHERE i.id = NEW.identity_id AND i.status <> 'active') THEN
      RAISE EXCEPTION 'identity_photo: only an active identity takes a photo'
        USING ERRCODE = 'check_violation';
    END IF;
    NEW.created_at := now();
    NEW.replaced_at := NULL;
    NEW.object_deleted_at := NULL;
    RETURN NEW;
  END IF;
  IF NEW.id <> OLD.id OR NEW.identity_id <> OLD.identity_id OR NEW.object_key <> OLD.object_key
     OR NEW.bytes <> OLD.bytes OR NEW.created_at <> OLD.created_at THEN
    RAISE EXCEPTION 'identity_photo %: only replaced_at and object_deleted_at change', OLD.id
      USING ERRCODE = 'restrict_violation';
  END IF;
  IF OLD.replaced_at IS NOT NULL AND NEW.replaced_at IS DISTINCT FROM OLD.replaced_at THEN
    RAISE EXCEPTION 'identity_photo %: a replaced photo stays replaced', OLD.id
      USING ERRCODE = 'restrict_violation';
  END IF;
  IF OLD.object_deleted_at IS NOT NULL AND NEW.object_deleted_at IS DISTINCT FROM OLD.object_deleted_at THEN
    RAISE EXCEPTION 'identity_photo %: a deleted object stays deleted', OLD.id
      USING ERRCODE = 'restrict_violation';
  END IF;
  IF NEW.replaced_at IS NOT NULL AND OLD.replaced_at IS NULL THEN
    NEW.replaced_at := now();
  END IF;
  IF NEW.object_deleted_at IS NOT NULL AND OLD.object_deleted_at IS NULL THEN
    NEW.object_deleted_at := now();
  END IF;
  RETURN NEW;
END
$$;

CREATE TRIGGER identity_photo_guard
  BEFORE INSERT OR UPDATE ON identity_photo FOR EACH ROW EXECUTE FUNCTION identity_photo_guard();

-- Closing or erasing the identity takes its photo down: it stops being served, and the cleanup
-- job deletes the object.
CREATE FUNCTION identity_photo_effects() RETURNS trigger
  LANGUAGE plpgsql SET search_path = public, pg_temp AS $$
BEGIN
  IF (NEW.status = 'closed' AND OLD.status <> 'closed')
     OR (NEW.erased_at IS NOT NULL AND OLD.erased_at IS NULL) THEN
    UPDATE identity_photo SET replaced_at = now()
     WHERE identity_id = NEW.id AND replaced_at IS NULL;
  END IF;
  RETURN NULL;
END
$$;

CREATE TRIGGER identity_photo_effects
  AFTER UPDATE ON identity FOR EACH ROW EXECUTE FUNCTION identity_photo_effects();

-- The record of what was stored outlives the object, so a lost delete is always found again.
REVOKE DELETE, TRUNCATE ON identity_photo FROM uni_auth_app;
