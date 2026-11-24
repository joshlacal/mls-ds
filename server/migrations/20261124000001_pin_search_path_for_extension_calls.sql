-- pg_dump/pg_restore (and every nightly backup verification) run with an empty
-- search_path. Functions that call pgcrypto or uuid-ossp helpers unqualified,
-- such as digest() in chat.ed25519_key_id, then fail to resolve them. That
-- function backs the device_keys_key_id_binding_check CHECK constraint, so a
-- restore rejected every chat.device_keys row.
--
-- Pin search_path on every non-extension function that calls an
-- extension-provided function by its bare name. pg_catalog stays first so a
-- catalog name can never be shadowed; the extension schemas follow so the
-- existing unqualified calls keep resolving exactly as they do at runtime.
DO $$
DECLARE
    extension_path TEXT;
    target REGPROCEDURE;
BEGIN
    SELECT string_agg(DISTINCT quote_ident(n.nspname), ', ')
      INTO extension_path
      FROM pg_extension e
      JOIN pg_namespace n ON n.oid = e.extnamespace
     WHERE e.extname IN ('pgcrypto', 'uuid-ossp');

    IF extension_path IS NULL THEN
        RETURN;
    END IF;

    FOR target IN
        SELECT DISTINCT p.oid::regprocedure
          FROM pg_proc p
          JOIN pg_namespace n ON n.oid = p.pronamespace
          JOIN pg_language l ON l.oid = p.prolang
         WHERE n.nspname NOT IN ('pg_catalog', 'information_schema')
           AND n.nspname NOT LIKE 'pg\_%'
           AND l.lanname IN ('sql', 'plpgsql')
           AND p.proconfig IS NULL
           AND NOT EXISTS (
               SELECT 1 FROM pg_depend d
                WHERE d.classid = 'pg_proc'::regclass
                  AND d.objid = p.oid
                  AND d.deptype = 'e'
           )
           AND EXISTS (
               SELECT 1
                 FROM pg_proc ext
                 JOIN pg_depend d
                   ON d.classid = 'pg_proc'::regclass
                  AND d.objid = ext.oid
                  AND d.deptype = 'e'
                 JOIN pg_extension e ON e.oid = d.refobjid
                WHERE e.extname IN ('pgcrypto', 'uuid-ossp')
                  AND p.prosrc ~ ('(^|[^.A-Za-z0-9_"])' || ext.proname || '\s*\(')
           )
    LOOP
        EXECUTE format('ALTER FUNCTION %s SET search_path = pg_catalog, %s',
                       target, extension_path);
    END LOOP;
END
$$;
