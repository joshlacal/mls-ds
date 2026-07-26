-- Bridge existing pre-v4 Welcome dispositions through the frozen provenance
-- backfill. The frozen migration updates populated disposition rows and then
-- adds constraints on the same table. PostgreSQL refuses that ALTER TABLE when
-- INITIALLY DEFERRED trigger events from the UPDATE remain queued.
--
-- Keep both old invariants enabled and fail-closed, but validate them at each
-- statement boundary while v4 runs. The postflight migration restores their
-- original INITIALLY DEFERRED timing only after v4 succeeds.

DO $$
BEGIN
    IF to_regclass('chat.welcome_dispositions') IS NULL THEN
        RAISE EXCEPTION
            'Welcome provenance preflight requires chat.welcome_dispositions'
            USING ERRCODE = '42P01';
    END IF;

    DROP TRIGGER IF EXISTS welcome_dispositions_delivery_cas_deferred
        ON chat.welcome_dispositions;
    CREATE CONSTRAINT TRIGGER welcome_dispositions_delivery_cas_deferred
    AFTER INSERT OR UPDATE OR DELETE ON chat.welcome_dispositions
    DEFERRABLE INITIALLY IMMEDIATE
    FOR EACH ROW EXECUTE FUNCTION chat.enforce_welcome_disposition_cas();

    DROP TRIGGER IF EXISTS welcome_dispositions_recovery_work_deferred
        ON chat.welcome_dispositions;
    CREATE CONSTRAINT TRIGGER welcome_dispositions_recovery_work_deferred
    AFTER INSERT OR UPDATE OR DELETE ON chat.welcome_dispositions
    DEFERRABLE INITIALLY IMMEDIATE
    FOR EACH ROW EXECUTE FUNCTION chat.enforce_recovery_work_integrity();
END
$$;
