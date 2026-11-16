-- The device and place a session was opened from, recorded at sign-in (account-plan.md
-- section 5, auth_session; part 1).
--
-- device_label is what a member would call the device ("iPhone", "Mac"), parsed from the user
-- agent by the login application. geo_city and geo_country come from the local GeoLite2
-- database, never a third party; either is null when the address is private or unknown. They
-- are facts about the sign-in, so they are fixed once written, and erasure takes them with the
-- session row it already deletes.

ALTER TABLE auth_session
  ADD COLUMN device_label text,
  ADD COLUMN geo_city     text,
  ADD COLUMN geo_country  char(2),
  ADD CONSTRAINT auth_session_device_label_bounded
    CHECK (device_label IS NULL OR length(device_label) BETWEEN 1 AND 100),
  ADD CONSTRAINT auth_session_geo_city_bounded
    CHECK (geo_city IS NULL OR length(geo_city) BETWEEN 1 AND 100),
  ADD CONSTRAINT auth_session_geo_country_iso
    CHECK (geo_country IS NULL OR geo_country ~ '^[A-Z]{2}$');

CREATE FUNCTION auth_session_device_fixed() RETURNS trigger
  LANGUAGE plpgsql SET search_path = public, pg_temp AS $$
BEGIN
  IF NEW.device_label IS DISTINCT FROM OLD.device_label
     OR NEW.geo_city IS DISTINCT FROM OLD.geo_city
     OR NEW.geo_country IS DISTINCT FROM OLD.geo_country THEN
    RAISE EXCEPTION 'auth_session %: the device and place it was opened from are fixed', OLD.id
      USING ERRCODE = 'restrict_violation';
  END IF;
  RETURN NEW;
END
$$;

CREATE TRIGGER auth_session_device_fixed
  BEFORE UPDATE ON auth_session FOR EACH ROW EXECUTE FUNCTION auth_session_device_fixed();
