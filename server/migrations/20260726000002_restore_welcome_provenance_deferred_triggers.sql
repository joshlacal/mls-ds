-- Complete the Welcome provenance bridge only after frozen v4 succeeded.
-- Validate every existing disposition through the current v4 CAS and recovery
-- work assertions before restoring the original deferred trigger timing.

DO $$
DECLARE
    target_welcome UUID;
BEGIN
    IF to_regclass('chat.welcome_dispositions') IS NULL THEN
        RAISE EXCEPTION
            'Welcome provenance postflight requires chat.welcome_dispositions'
            USING ERRCODE = '42P01';
    END IF;
    IF to_regprocedure('chat.assert_welcome_disposition_cas(uuid)') IS NULL
       OR to_regprocedure('chat.assert_recovery_work_integrity(uuid)') IS NULL THEN
        RAISE EXCEPTION
            'Welcome provenance postflight requires current assertion functions'
            USING ERRCODE = '42883';
    END IF;

    FOR target_welcome IN
        SELECT welcome_id
          FROM chat.welcome_dispositions
         ORDER BY welcome_id
    LOOP
        PERFORM chat.assert_welcome_disposition_cas(target_welcome);
        PERFORM chat.assert_recovery_work_integrity(target_welcome);
    END LOOP;

    DROP TRIGGER IF EXISTS welcome_dispositions_delivery_cas_deferred
        ON chat.welcome_dispositions;
    CREATE CONSTRAINT TRIGGER welcome_dispositions_delivery_cas_deferred
    AFTER INSERT OR UPDATE OR DELETE ON chat.welcome_dispositions
    DEFERRABLE INITIALLY DEFERRED
    FOR EACH ROW EXECUTE FUNCTION chat.enforce_welcome_disposition_cas();

    DROP TRIGGER IF EXISTS welcome_dispositions_recovery_work_deferred
        ON chat.welcome_dispositions;
    CREATE CONSTRAINT TRIGGER welcome_dispositions_recovery_work_deferred
    AFTER INSERT OR UPDATE OR DELETE ON chat.welcome_dispositions
    DEFERRABLE INITIALLY DEFERRED
    FOR EACH ROW EXECUTE FUNCTION chat.enforce_recovery_work_integrity();
END
$$;
