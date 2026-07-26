-- Finalize the Welcome provenance bridge after frozen v4 and its sealed
-- postflight. Fail closed unless the two source columns and their exact v4
-- shape/FK constraints exist, validate all populated rows through the current
-- assertion functions, then restore the original full deferred trigger events.

DO $$
DECLARE
    target_welcome UUID;
    source_column_count BIGINT;
    shape_constraint_count BIGINT;
    transition_fk_count BIGINT;
    revocation_fk_count BIGINT;
BEGIN
    IF to_regclass('chat.welcome_dispositions') IS NULL THEN
        RAISE EXCEPTION
            'Welcome provenance finalizer requires chat.welcome_dispositions'
            USING ERRCODE = '42P01';
    END IF;
    IF to_regprocedure('chat.assert_welcome_disposition_cas(uuid)') IS NULL
       OR to_regprocedure('chat.assert_recovery_work_integrity(uuid)') IS NULL
       OR to_regprocedure('chat.enforce_welcome_disposition_cas()') IS NULL
       OR to_regprocedure('chat.enforce_recovery_work_integrity()') IS NULL THEN
        RAISE EXCEPTION
            'Welcome provenance finalizer requires current assertion and trigger functions'
            USING ERRCODE = '42883';
    END IF;

    SELECT count(*) INTO source_column_count
      FROM pg_attribute
     WHERE attrelid = 'chat.welcome_dispositions'::regclass
       AND attname IN ('terminal_transition_id', 'terminal_revocation_id')
       AND NOT attisdropped
       AND format_type(atttypid, atttypmod) = 'uuid'
       AND NOT attnotnull;
    IF source_column_count <> 2 THEN
        RAISE EXCEPTION
            'Welcome provenance finalizer requires both nullable UUID source columns'
            USING ERRCODE = '42703';
    END IF;

    SELECT count(*) INTO shape_constraint_count
      FROM pg_constraint
     WHERE conrelid = 'chat.welcome_dispositions'::regclass
       AND conname = 'welcome_dispositions_terminal_source_shape_check'
       AND contype = 'c'
       AND convalidated;
    IF shape_constraint_count <> 1 THEN
        RAISE EXCEPTION
            'Welcome provenance finalizer requires the validated source-shape constraint'
            USING ERRCODE = '55000';
    END IF;

    SELECT count(*) INTO transition_fk_count
      FROM pg_constraint constraint_row
      JOIN pg_attribute source_column
        ON source_column.attrelid = constraint_row.conrelid
       AND source_column.attnum = constraint_row.conkey[1]
      JOIN pg_attribute target_column
        ON target_column.attrelid = constraint_row.confrelid
       AND target_column.attnum = constraint_row.confkey[1]
     WHERE constraint_row.conrelid = 'chat.welcome_dispositions'::regclass
       AND constraint_row.conname = 'welcome_dispositions_terminal_transition_fk'
       AND constraint_row.contype = 'f'
       AND constraint_row.confrelid = 'chat.transitions'::regclass
       AND cardinality(constraint_row.conkey) = 1
       AND cardinality(constraint_row.confkey) = 1
       AND source_column.attname = 'terminal_transition_id'
       AND target_column.attname = 'transition_id'
       AND constraint_row.condeferrable
       AND constraint_row.condeferred
       AND constraint_row.convalidated;
    IF transition_fk_count <> 1 THEN
        RAISE EXCEPTION
            'Welcome provenance finalizer requires the exact deferred transition source FK'
            USING ERRCODE = '55000';
    END IF;

    SELECT count(*) INTO revocation_fk_count
      FROM pg_constraint constraint_row
      JOIN pg_attribute source_column
        ON source_column.attrelid = constraint_row.conrelid
       AND source_column.attnum = constraint_row.conkey[1]
      JOIN pg_attribute target_column
        ON target_column.attrelid = constraint_row.confrelid
       AND target_column.attnum = constraint_row.confkey[1]
     WHERE constraint_row.conrelid = 'chat.welcome_dispositions'::regclass
       AND constraint_row.conname = 'welcome_dispositions_terminal_revocation_fk'
       AND constraint_row.contype = 'f'
       AND constraint_row.confrelid = 'chat.device_revocations'::regclass
       AND cardinality(constraint_row.conkey) = 1
       AND cardinality(constraint_row.confkey) = 1
       AND source_column.attname = 'terminal_revocation_id'
       AND target_column.attname = 'revocation_id'
       AND constraint_row.condeferrable
       AND constraint_row.condeferred
       AND constraint_row.convalidated;
    IF revocation_fk_count <> 1 THEN
        RAISE EXCEPTION
            'Welcome provenance finalizer requires the exact deferred revocation source FK'
            USING ERRCODE = '55000';
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
