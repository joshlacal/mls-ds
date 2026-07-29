-- Enrollment reserves and claims the globally unique operation ID before it
-- creates the principal row. Defer only that claim-to-principal reference so
-- the enclosing transaction can establish principal, claim, effects, and the
-- exact completion receipt atomically. SQLx owns the transaction boundary.

LOCK TABLE chat.operation_claims IN ACCESS EXCLUSIVE MODE;

DO $$
DECLARE
    constraint_oid OID;
    actual_definition TEXT;
    actual_type "char";
    actual_validated BOOLEAN;
    actual_deferrable BOOLEAN;
    actual_deferred BOOLEAN;
    actual_referenced_table OID;
    actual_match_type "char";
    actual_update_action "char";
    actual_delete_action "char";
    actual_parent OID;
    actual_source_columns TEXT[];
    actual_referenced_columns TEXT[];
BEGIN
    SELECT
        constraint_row.oid,
        pg_get_constraintdef(constraint_row.oid, false),
        constraint_row.contype,
        constraint_row.convalidated,
        constraint_row.condeferrable,
        constraint_row.condeferred,
        constraint_row.confrelid,
        constraint_row.confmatchtype,
        constraint_row.confupdtype,
        constraint_row.confdeltype,
        constraint_row.conparentid,
        ARRAY(
            SELECT attribute.attname
              FROM unnest(constraint_row.conkey) WITH ORDINALITY
                   AS key(attnum, ordinal)
              JOIN pg_attribute attribute
                ON attribute.attrelid = constraint_row.conrelid
               AND attribute.attnum = key.attnum
             ORDER BY key.ordinal
        ),
        ARRAY(
            SELECT attribute.attname
              FROM unnest(constraint_row.confkey) WITH ORDINALITY
                   AS key(attnum, ordinal)
              JOIN pg_attribute attribute
                ON attribute.attrelid = constraint_row.confrelid
               AND attribute.attnum = key.attnum
             ORDER BY key.ordinal
        )
      INTO
        constraint_oid,
        actual_definition,
        actual_type,
        actual_validated,
        actual_deferrable,
        actual_deferred,
        actual_referenced_table,
        actual_match_type,
        actual_update_action,
        actual_delete_action,
        actual_parent,
        actual_source_columns,
        actual_referenced_columns
      FROM pg_constraint constraint_row
     WHERE constraint_row.conrelid = 'chat.operation_claims'::regclass
       AND constraint_row.connamespace = 'chat'::regnamespace
       AND constraint_row.conname = 'operation_claims_principal_fk';

    IF constraint_oid IS NULL
       OR actual_type IS DISTINCT FROM 'f'
       OR actual_validated IS DISTINCT FROM TRUE
       OR actual_deferrable IS DISTINCT FROM FALSE
       OR actual_deferred IS DISTINCT FROM FALSE
       OR actual_referenced_table IS DISTINCT FROM 'chat.principals'::regclass
       OR actual_match_type IS DISTINCT FROM 's'
       OR actual_update_action IS DISTINCT FROM 'a'
       OR actual_delete_action IS DISTINCT FROM 'a'
       OR actual_parent IS DISTINCT FROM 0
       OR actual_source_columns IS DISTINCT FROM ARRAY['principal_did']::TEXT[]
       OR actual_referenced_columns IS DISTINCT FROM ARRAY['user_did']::TEXT[]
    THEN
        RAISE EXCEPTION
            'operation_claims_principal_fk precondition mismatch: %',
            coalesce(actual_definition, '<missing>')
            USING ERRCODE = '55000';
    END IF;
END
$$;

ALTER TABLE chat.operation_claims
    DROP CONSTRAINT operation_claims_principal_fk;

ALTER TABLE chat.operation_claims
    ADD CONSTRAINT operation_claims_principal_fk
        FOREIGN KEY (principal_did)
        REFERENCES chat.principals(user_did)
        DEFERRABLE INITIALLY DEFERRED;

DO $$
DECLARE
    constraint_oid OID;
    actual_definition TEXT;
    actual_type "char";
    actual_validated BOOLEAN;
    actual_deferrable BOOLEAN;
    actual_deferred BOOLEAN;
    actual_referenced_table OID;
    actual_match_type "char";
    actual_update_action "char";
    actual_delete_action "char";
    actual_parent OID;
    actual_source_columns TEXT[];
    actual_referenced_columns TEXT[];
BEGIN
    SELECT
        constraint_row.oid,
        pg_get_constraintdef(constraint_row.oid, false),
        constraint_row.contype,
        constraint_row.convalidated,
        constraint_row.condeferrable,
        constraint_row.condeferred,
        constraint_row.confrelid,
        constraint_row.confmatchtype,
        constraint_row.confupdtype,
        constraint_row.confdeltype,
        constraint_row.conparentid,
        ARRAY(
            SELECT attribute.attname
              FROM unnest(constraint_row.conkey) WITH ORDINALITY
                   AS key(attnum, ordinal)
              JOIN pg_attribute attribute
                ON attribute.attrelid = constraint_row.conrelid
               AND attribute.attnum = key.attnum
             ORDER BY key.ordinal
        ),
        ARRAY(
            SELECT attribute.attname
              FROM unnest(constraint_row.confkey) WITH ORDINALITY
                   AS key(attnum, ordinal)
              JOIN pg_attribute attribute
                ON attribute.attrelid = constraint_row.confrelid
               AND attribute.attnum = key.attnum
             ORDER BY key.ordinal
        )
      INTO
        constraint_oid,
        actual_definition,
        actual_type,
        actual_validated,
        actual_deferrable,
        actual_deferred,
        actual_referenced_table,
        actual_match_type,
        actual_update_action,
        actual_delete_action,
        actual_parent,
        actual_source_columns,
        actual_referenced_columns
      FROM pg_constraint constraint_row
     WHERE constraint_row.conrelid = 'chat.operation_claims'::regclass
       AND constraint_row.connamespace = 'chat'::regnamespace
       AND constraint_row.conname = 'operation_claims_principal_fk';

    IF constraint_oid IS NULL
       OR actual_type IS DISTINCT FROM 'f'
       OR actual_validated IS DISTINCT FROM TRUE
       OR actual_deferrable IS DISTINCT FROM TRUE
       OR actual_deferred IS DISTINCT FROM TRUE
       OR actual_referenced_table IS DISTINCT FROM 'chat.principals'::regclass
       OR actual_match_type IS DISTINCT FROM 's'
       OR actual_update_action IS DISTINCT FROM 'a'
       OR actual_delete_action IS DISTINCT FROM 'a'
       OR actual_parent IS DISTINCT FROM 0
       OR actual_source_columns IS DISTINCT FROM ARRAY['principal_did']::TEXT[]
       OR actual_referenced_columns IS DISTINCT FROM ARRAY['user_did']::TEXT[]
    THEN
        RAISE EXCEPTION
            'operation_claims_principal_fk postcondition mismatch: %',
            coalesce(actual_definition, '<missing>')
            USING ERRCODE = '23514';
    END IF;
END
$$;
