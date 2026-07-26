-- Keep old v1-v3 Welcome writers operable while the frozen v4 migration is
-- pending. Disposition rows are immutable at this boundary, so ordinary
-- UPDATE/DELETE cannot occur. Limiting these two constraint triggers to
-- INSERT/DELETE prevents frozen v4's temporary cause-only UPDATE from queuing
-- trigger events before it adds constraints to the same table.

DO $$
DECLARE
    immutable_trigger_count BIGINT;
BEGIN
    IF to_regclass('chat.welcome_dispositions') IS NULL THEN
        RAISE EXCEPTION
            'Welcome provenance quarantine requires chat.welcome_dispositions'
            USING ERRCODE = '42P01';
    END IF;

    SELECT count(*) INTO immutable_trigger_count
      FROM pg_trigger trigger_row
      JOIN pg_proc function_row
        ON function_row.oid = trigger_row.tgfoid
      JOIN pg_namespace function_namespace
        ON function_namespace.oid = function_row.pronamespace
     WHERE trigger_row.tgrelid = 'chat.welcome_dispositions'::regclass
       AND trigger_row.tgname = 'welcome_dispositions_immutable'
       AND NOT trigger_row.tgisinternal
       AND trigger_row.tgenabled = 'O'
       -- ROW + BEFORE + UPDATE + DELETE, and no other event bits.
       AND trigger_row.tgtype = 27
       AND trigger_row.tgnargs = 0
       AND function_namespace.nspname = 'chat'
       AND function_row.proname = 'enforce_immutable_identity';

    IF immutable_trigger_count <> 1 THEN
        RAISE EXCEPTION
            'Welcome provenance quarantine requires the enabled exact immutable identity trigger'
            USING ERRCODE = '55000';
    END IF;

    DROP TRIGGER IF EXISTS welcome_dispositions_delivery_cas_deferred
        ON chat.welcome_dispositions;
    CREATE CONSTRAINT TRIGGER welcome_dispositions_delivery_cas_deferred
    AFTER INSERT OR DELETE ON chat.welcome_dispositions
    DEFERRABLE INITIALLY DEFERRED
    FOR EACH ROW EXECUTE FUNCTION chat.enforce_welcome_disposition_cas();

    DROP TRIGGER IF EXISTS welcome_dispositions_recovery_work_deferred
        ON chat.welcome_dispositions;
    CREATE CONSTRAINT TRIGGER welcome_dispositions_recovery_work_deferred
    AFTER INSERT OR DELETE ON chat.welcome_dispositions
    DEFERRABLE INITIALLY DEFERRED
    FOR EACH ROW EXECUTE FUNCTION chat.enforce_recovery_work_integrity();
END
$$;
