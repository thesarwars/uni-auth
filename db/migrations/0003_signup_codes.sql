-- Sign-up codes (auth-plan.md section 12.2, part 5).
--
-- 0002 let a signup code go to any address, because it has no identity to check against. One
-- rule belongs to it all the same: a signup code goes only to an address no live identity holds
-- verified. Whoever owns that address signs in; they do not sign up again. An address someone
-- typed and never proved does not count, so it cannot block its real owner.

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
  IF NEW.purpose = 'signup' AND EXISTS (
       SELECT 1 FROM identity_identifier ii
        WHERE ii.revoked_at IS NULL AND ii.verified_at IS NOT NULL
          AND ii.kind = CASE NEW.channel WHEN 'email' THEN 'email'::identifier_kind
                                         ELSE 'phone'::identifier_kind END
          AND ii.value = NEW.destination::citext) THEN
    RAISE EXCEPTION 'otp_challenge: a signup code goes only to an address no identity holds verified'
      USING ERRCODE = 'check_violation';
  END IF;
  RETURN NEW;
END
$$;
