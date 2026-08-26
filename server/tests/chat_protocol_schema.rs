//! Catalog, isolation, and fail-closed behavior contract for `blue.catbird.chat`.
//!
//! This test is intentionally destructive only inside one dedicated local
//! database. Every run proves rollback, ordered migration boundaries, the SQLx
//! ledger path, normalized catalog identity, and representative cross-table
//! protocol invariants from a fresh `chat` schema.
//!
//! Run against the dedicated local database:
//!   CHAT_OPERATION_CLAIM_ACTIVATION_APPROVED=handlers-and-legacy-apis-sealed \
//!   TEST_DATABASE_URL=postgresql://127.0.0.1:5432/catbird_chat_protocol_test_20260722 \
//!   cargo test --test chat_protocol_schema -- --test-threads=1

mod common;

use std::collections::{BTreeMap, BTreeSet};
use std::ffi::CString;
use std::fs::{File, OpenOptions};
use std::io::Write;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::LazyLock;

use chrono::{DateTime, Utc};
use futures::FutureExt;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256, Sha384};
use sqlx::{Connection, Executor, PgConnection, PgPool};
use std::panic::AssertUnwindSafe;

const TEST_DATABASE_NAME: &str = "catbird_chat_protocol_test_20260722";
static MIGRATION_VERSIONS: LazyLock<[i64; 23]> = LazyLock::new(|| {
    std::array::from_fn(|index| {
        crate::common::chat_protocol::CLEAN_PROTOCOL_13_MANIFEST[index]
            .migration
            .version
    })
});
static MIGRATION_FILES: LazyLock<[&'static str; 23]> = LazyLock::new(|| {
    std::array::from_fn(|index| {
        crate::common::chat_protocol::CLEAN_PROTOCOL_13_MANIFEST[index].filename
    })
});
static MIGRATION_DESCRIPTIONS: LazyLock<[&'static str; 23]> = LazyLock::new(|| {
    std::array::from_fn(|index| {
        crate::common::chat_protocol::CLEAN_PROTOCOL_13_MANIFEST[index]
            .migration
            .description
            .as_ref()
    })
});
// These are regenerated only from a reviewed, freshly applied migration
// snapshot. They deliberately make unreviewed catalog drift loud.
//
// Refreshed from the dedicated local database after applying the complete
// post-20260729000001 migration chain. The sequence catalog remained
// structurally unchanged.
const COLUMN_CATALOG_SHA256: &str =
    "5ca78b4db4fe77899613930487ddfa2dbf71c250eca6780c4c255fe03d346b12";
const CONSTRAINT_CATALOG_SHA256: &str =
    "54cc3605853acd7be5e4679eb785ba17bf8844b622d5b4e6c298ffdbd4e00530";
const INDEX_CATALOG_SHA256: &str =
    "69e3094a66adb4ca52d6a2bcd1427e98dca8eb80e1b267ee71a37b2fb2d9e160";
const FUNCTION_CATALOG_SHA256: &str =
    "04e3c4f157b281751d9bd9ed58b0a376e8bddd1f64b3861bc977eeff0e7716e1";
const TRIGGER_CATALOG_SHA256: &str =
    "f368418845b99186be3f9fb53b41eb10dc1e93b7bf2171b77198d13a8d78e9dc";
const SEQUENCE_CATALOG_SHA256: &str =
    "0f5fdcab044481afeaca50ac88cff13edd4b583df914da2c798e4a4194464abe";
// search_path dependency for CONSTRAINT_/FUNCTION_CATALOG_SHA256 above and
// A0_EXTENSION_OBJECT_CATALOG_SHA256 below. All three were derived under the
// connection default search_path `"$user", public` (effective
// ["pg_catalog","public"]), recorded by the smoke run. PostgreSQL qualifies an
// object in rendered SQL only when it is not visible on that path, so adding a
// `SET search_path` anywhere on the post-clean assertion path invalidates all
// three at once. Verified at the time of writing: the post-clean path sets none
// — the harness's only `SET LOCAL search_path TO pg_catalog` is confined to the
// legacy-fingerprint transaction and does not reach these assertions.
//
// Why CONSTRAINT and FUNCTION moved while COLUMN/INDEX/TRIGGER/SEQUENCE did
// not: they are the only two whose preimages embed rendered text that calls
// chat-schema functions. Two candidate causes remain indistinguishable without
// the superseded preimage — the server rendering differently than when the old
// values were recorded, or the underlying CHECK/function text having changed
// since. Both imply the same promoted values.
const OPERATION_CLAIM_00004_PRE_REPAIR_SHA384: &str =
    "d7f92b96421a33f0385789f44c0fc2986321e8c7487e79e96c9c4880a1853e4c9d7d32f36bf3dfd22ff07a1cd6fb1674";
const OPERATION_CLAIM_00004_REPAIRED_SHA384: &str =
    "7de97f6f84a9cfcbf535b990b5aec87930450cf6661c7d8cf11920bdf53fd0fe94623e9ed222a8eeb562c1ee596c5bd6";
const A0_EXACT_DATABASE_URL: &str =
    "postgresql://127.0.0.1:5432/catbird_chat_protocol_test_20260722";
const A0_EXACT_ADMIN_URL: &str = "postgresql://127.0.0.1:5432/postgres";
const A0_EXPECTED_LEGACY_OID: u32 = 17_744_199;
const A0_EXACT_OWNER: &str = "joshlacalamito";
const A0_ADMIN_LOCK_CLASS: i32 = 20_260_729;
const A0_ADMIN_LOCK_OBJECT: i32 = 700;
const A0_TARGET_LOCK_CLASS: i32 = 20_260_729;
const A0_TARGET_LOCK_OBJECT: i32 = 701;
const A0_LEGACY_LEDGER_SHA256: &str =
    "d205f5ab9a1e0927fce4c85e8682ec90f9a2f0e91022784e18b68ea77a29f971";
const A0_LEGACY_LEDGER_SHA384: &str =
    "9e156e6f39962d341388b81a94d3a7931f5b9882d35ebbfeff9d85c1caeae04a75482d977e3eecb4f8d005365b2a2bec";
const A0_LEGACY_CATALOG_SHA256: &str =
    "7712d1ea518550a4a4c7c353db8da8d2fbd40a77830300c7fbbf69169510f008";
const A0_LEGACY_CATALOG_SHA384: &str =
    "0ebbfbc6c716604c98b60ee839b9ad8a551e1145ec3538d0e3b2ffa60eebfd90c6664abbfea1c339cc42b406f61bc58c";
const A0_FINGERPRINT_SQL_SHA256: &str =
    "f9c136cddc3f34a800646c443419977747c6993bf3e51244e3e70a4d780d47ed";
const A0_FINGERPRINT_MD_SHA256: &str =
    "61e356c5405d5f2f4b23f4b09862fc09d709e7ff8dfb5dc30cbe768ebe225a1f";
// Self-contained mirrors of the reviewed Task-10 reproduction inputs. The
// original provenance paths and complete-byte hashes remain recorded above;
// runtime rehashing below rejects any edit to these embedded authorities.
const A0_FINGERPRINT_SQL_SOURCE: &str = r############"-- Read-only source rows for the stable, framed A0 authority fingerprint.
-- Invoke exactly one mode with psql -X -qAt -v ON_ERROR_STOP=1 and either
-- -v ledger=true or -v catalog=true. The companion Markdown contains the
-- required framing serializer. These JSON lines are parsed transport records,
-- not the authority bytes; transport newlines and outer JSON key order are inert.

\if :{?ledger}
BEGIN TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY;
SET LOCAL search_path TO pg_catalog;
SET LOCAL bytea_output TO hex;

SELECT jsonb_build_object(
  'version', version::text,
  'description', description,
  'success', success,
  'checksum_hex', encode(checksum, 'hex')
)::text
FROM public._sqlx_migrations
ORDER BY version;

COMMIT;
\elif :{?catalog}
BEGIN TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY;
SET LOCAL search_path TO pg_catalog;
SET LOCAL bytea_output TO hex;

WITH ns AS (
  SELECT oid, nspname FROM pg_namespace
  WHERE nspname !~ '^pg_' AND nspname <> 'information_schema'
), deps AS (
  SELECT d.classid, d.objid, d.objsubid, min(e.extname) AS extname
  FROM pg_depend d JOIN pg_extension e ON e.oid = d.refobjid
  WHERE d.deptype = 'e'
  GROUP BY d.classid, d.objid, d.objsubid
), constraint_ids AS (
  SELECT k.oid,
    format('%s.%I', COALESCE(
      format('%I.%I', rel_ns.nspname, rel_class.relname),
      format('%I.%I', type_ns.nspname, con_type.typname), '<none>'
    ), k.conname) AS identity
  FROM pg_constraint k
  JOIN ns n ON n.oid = k.connamespace
  LEFT JOIN pg_class rel_class ON rel_class.oid = k.conrelid
  LEFT JOIN pg_namespace rel_ns ON rel_ns.oid = rel_class.relnamespace
  LEFT JOIN pg_type con_type ON con_type.oid = k.contypid
  LEFT JOIN pg_namespace type_ns ON type_ns.oid = con_type.typnamespace
), db AS (
  SELECT d.*, ts.spcname AS tablespace_name
  FROM pg_database d
  LEFT JOIN pg_tablespace ts ON ts.oid = d.dattablespace
  WHERE d.datname = current_database()
), db_setting_rows AS (
  SELECT coalesce(r.rolname, '<database-default>') AS role_name, config
  FROM pg_db_role_setting s
  LEFT JOIN pg_roles r ON r.oid = s.setrole
  CROSS JOIN LATERAL unnest(s.setconfig) config
  WHERE s.setdatabase = (SELECT oid FROM db)
), class_counts AS (
  SELECT 'database_setting'::text AS class_name, count(*)::bigint AS object_count FROM db_setting_rows
  UNION ALL SELECT 'extension_member', count(*) FROM deps
  UNION ALL SELECT 'operator', count(*) FROM pg_operator o JOIN ns ON ns.oid=o.oprnamespace
  UNION ALL SELECT 'opclass', count(*) FROM pg_opclass o JOIN ns ON ns.oid=o.opcnamespace
  UNION ALL SELECT 'opfamily', count(*) FROM pg_opfamily o JOIN ns ON ns.oid=o.opfnamespace
  UNION ALL SELECT 'cast', count(*) FROM pg_cast
  UNION ALL SELECT 'collation', count(*) FROM pg_collation c JOIN ns ON ns.oid=c.collnamespace
  UNION ALL SELECT 'event_trigger', count(*) FROM pg_event_trigger
  UNION ALL SELECT 'inheritance_edge', count(*) FROM pg_inherits i JOIN pg_class c ON c.oid=i.inhrelid JOIN ns ON ns.oid=c.relnamespace
  UNION ALL SELECT 'foreign_data_wrapper', count(*) FROM pg_foreign_data_wrapper
  UNION ALL SELECT 'foreign_server', count(*) FROM pg_foreign_server
  UNION ALL SELECT 'user_mapping', count(*) FROM pg_user_mapping
  UNION ALL SELECT 'publication', count(*) FROM pg_publication
  UNION ALL SELECT 'subscription', count(*) FROM pg_subscription
  UNION ALL SELECT 'extended_statistics', count(*) FROM pg_statistic_ext s JOIN pg_class c ON c.oid=s.stxrelid JOIN ns ON ns.oid=c.relnamespace
  UNION ALL SELECT 'text_search_config', count(*) FROM pg_ts_config c JOIN ns ON ns.oid=c.cfgnamespace
  UNION ALL SELECT 'text_search_dictionary', count(*) FROM pg_ts_dict d JOIN ns ON ns.oid=d.dictnamespace
  UNION ALL SELECT 'text_search_parser', count(*) FROM pg_ts_parser p JOIN ns ON ns.oid=p.prsnamespace
  UNION ALL SELECT 'text_search_template', count(*) FROM pg_ts_template t JOIN ns ON ns.oid=t.tmplnamespace
  UNION ALL SELECT 'conversion', count(*) FROM pg_conversion c JOIN ns ON ns.oid=c.connamespace
  UNION ALL SELECT 'constraint_trigger', count(*) FROM pg_trigger g WHERE g.tgisinternal AND g.tgconstraint <> 0
), lines AS (
  SELECT jsonb_build_object(
    'class', 'database', 'identity', d.datname,
    'definition', jsonb_build_object(
      'owner', pg_get_userbyid(d.datdba), 'encoding', pg_encoding_to_char(d.encoding),
      'collate', d.datcollate, 'ctype', d.datctype, 'locale_provider', d.datlocprovider,
      'icu_locale', d.daticulocale, 'icu_rules', d.daticurules, 'is_template', d.datistemplate,
      'connection_limit', d.datconnlimit,
      'tablespace', d.tablespace_name, 'acl', d.datacl
    )::text
  )::text AS v
  FROM db d

  UNION ALL

  SELECT jsonb_build_object(
    'class', 'database_setting', 'identity', format('%I.%s', (SELECT datname FROM db), role_name),
    'definition', jsonb_build_object('role', role_name, 'config', config)::text
  )::text
  FROM db_setting_rows

  UNION ALL

  SELECT jsonb_build_object(
    'class', 'class_count', 'identity', class_name,
    'definition', jsonb_build_object('count', object_count)::text
  )::text
  FROM class_counts

  UNION ALL

  SELECT jsonb_build_object(
    'class', 'extension', 'identity', e.extname,
    'definition', jsonb_build_object(
      'version', e.extversion, 'schema', n.nspname, 'owner', pg_get_userbyid(e.extowner)
    )::text
  )::text AS v
  FROM pg_extension e JOIN pg_namespace n ON n.oid = e.extnamespace

  UNION ALL

  SELECT jsonb_build_object(
    'class', 'schema', 'identity', format('%I', n.nspname),
    'definition', jsonb_build_object(
      'owner', pg_get_userbyid(x.nspowner), 'acl', x.nspacl, 'extension_name', d.extname
    )::text
  )::text
  FROM ns n
  JOIN pg_namespace x ON x.oid = n.oid
  LEFT JOIN deps d ON d.classid = 'pg_namespace'::regclass AND d.objid = n.oid AND d.objsubid = 0

  UNION ALL

  SELECT jsonb_build_object(
    'class', 'relation', 'identity', format('%I.%I', n.nspname, c.relname),
    'definition', jsonb_build_object(
      'kind', c.relkind, 'owner', pg_get_userbyid(c.relowner), 'acl', c.relacl, 'persistence', c.relpersistence,
      'tablespace', ts.spcname, 'options', c.reloptions, 'row_security', c.relrowsecurity,
      'force_row_security', c.relforcerowsecurity, 'replica_identity', c.relreplident,
      'is_partition', c.relispartition, 'partition_key', pg_get_partkeydef(c.oid),
      'view_definition', CASE WHEN c.relkind IN ('v', 'm') THEN pg_get_viewdef(c.oid, true) END,
      'extension_name', d.extname
    )::text
  )::text
  FROM pg_class c
  JOIN ns n ON n.oid = c.relnamespace
  LEFT JOIN pg_tablespace ts ON ts.oid = c.reltablespace
  LEFT JOIN deps d ON d.classid = 'pg_class'::regclass AND d.objid = c.oid AND d.objsubid = 0
  WHERE c.relkind IN ('r', 'p', 'f', 'v', 'm', 'S')

  UNION ALL

  SELECT jsonb_build_object(
    'class', 'column', 'identity', format('%I.%I.%I', n.nspname, c.relname, a.attname),
    'definition', jsonb_build_object(
      'attnum', a.attnum, 'type', format_type(a.atttypid, a.atttypmod), 'not_null', a.attnotnull,
      'default', pg_get_expr(ad.adbin, ad.adrelid), 'identity', a.attidentity, 'generated', a.attgenerated,
      'collation', CASE WHEN coll.oid IS NULL THEN NULL ELSE format('%I.%I', coll_ns.nspname, coll.collname) END,
      'dropped', a.attisdropped, 'acl', a.attacl, 'extension_name', d.extname
    )::text
  )::text
  FROM pg_attribute a
  JOIN pg_class c ON c.oid = a.attrelid
  JOIN ns n ON n.oid = c.relnamespace
  LEFT JOIN pg_attrdef ad ON ad.adrelid = a.attrelid AND ad.adnum = a.attnum
  LEFT JOIN pg_collation coll ON coll.oid = a.attcollation
  LEFT JOIN pg_namespace coll_ns ON coll_ns.oid = coll.collnamespace
  LEFT JOIN deps d ON d.classid = 'pg_class'::regclass AND d.objid = c.oid AND d.objsubid = a.attnum
  WHERE c.relkind IN ('r', 'p', 'f', 'v', 'm', 'S') AND a.attnum > 0

  UNION ALL

  SELECT jsonb_build_object(
    'class', 'sequence', 'identity', format('%I.%I', n.nspname, c.relname),
    'definition', jsonb_build_object(
      'owner', pg_get_userbyid(c.relowner), 'start', s.seqstart, 'increment', s.seqincrement,
      'minimum', s.seqmin, 'maximum', s.seqmax, 'cache', s.seqcache, 'cycle', s.seqcycle,
      'type', format_type(s.seqtypid, NULL),
      'owned_by', CASE WHEN owner_table.oid IS NULL THEN NULL ELSE format('%I.%I.%I', owner_ns.nspname, owner_table.relname, owner_column.attname) END,
      'extension_name', d.extname
    )::text
  )::text
  FROM pg_sequence s
  JOIN pg_class c ON c.oid = s.seqrelid
  JOIN ns n ON n.oid = c.relnamespace
  LEFT JOIN deps d ON d.classid = 'pg_class'::regclass AND d.objid = c.oid AND d.objsubid = 0
  LEFT JOIN pg_depend ownership ON ownership.classid = 'pg_class'::regclass AND ownership.objid = c.oid AND ownership.objsubid = 0 AND ownership.refclassid = 'pg_class'::regclass AND ownership.deptype = 'a'
  LEFT JOIN pg_class owner_table ON owner_table.oid = ownership.refobjid
  LEFT JOIN pg_namespace owner_ns ON owner_ns.oid = owner_table.relnamespace
  LEFT JOIN pg_attribute owner_column ON owner_column.attrelid = owner_table.oid AND owner_column.attnum = ownership.refobjsubid

  UNION ALL

  SELECT jsonb_build_object(
    'class', 'index', 'identity', format('%I.%I', n.nspname, c.relname),
    'definition', jsonb_build_object(
      'owner', pg_get_userbyid(c.relowner), 'definition', pg_get_indexdef(c.oid),
      'valid', i.indisvalid, 'ready', i.indisready, 'live', i.indislive, 'clustered', i.indisclustered,
      'replica_identity', i.indisreplident, 'extension_name', d.extname
    )::text
  )::text
  FROM pg_class c
  JOIN ns n ON n.oid = c.relnamespace
  JOIN pg_index i ON i.indexrelid = c.oid
  LEFT JOIN deps d ON d.classid = 'pg_class'::regclass AND d.objid = c.oid AND d.objsubid = 0
  WHERE c.relkind IN ('i', 'I')

  UNION ALL

  SELECT jsonb_build_object(
    'class', 'function', 'identity', format('%I.%I(%s)', n.nspname, p.proname, pg_get_function_identity_arguments(p.oid)),
    'definition', jsonb_build_object(
      'owner', pg_get_userbyid(p.proowner), 'acl', p.proacl, 'kind', p.prokind,
      'definition', pg_get_functiondef(p.oid), 'extension_name', d.extname
    )::text
  )::text
  FROM pg_proc p
  JOIN ns n ON n.oid = p.pronamespace
  LEFT JOIN deps d ON d.classid = 'pg_proc'::regclass AND d.objid = p.oid AND d.objsubid = 0

  UNION ALL

  -- This covers every direct extension-owned function, including pg_catalog
  -- plpgsql handlers and public pgcrypto/uuid-ossp functions.
  SELECT jsonb_build_object(
    'class', 'extension_function',
    'identity', format('%I:%I.%I(%s)', d.extname, n.nspname, p.proname, pg_get_function_identity_arguments(p.oid)),
    'definition', jsonb_build_object(
      'extension_name', d.extname, 'owner', pg_get_userbyid(p.proowner), 'acl', p.proacl,
      'kind', p.prokind, 'definition', pg_get_functiondef(p.oid)
    )::text
  )::text
  FROM deps d
  JOIN pg_proc p ON d.classid = 'pg_proc'::regclass AND d.objid = p.oid AND d.objsubid = 0
  JOIN pg_namespace n ON n.oid = p.pronamespace

  UNION ALL

  SELECT jsonb_build_object(
    'class', 'extension_language', 'identity', format('%I:%I', d.extname, l.lanname),
    'definition', jsonb_build_object(
      'extension_name', d.extname, 'owner', pg_get_userbyid(l.lanowner), 'acl', l.lanacl,
      'trusted', l.lanpltrusted, 'procedural', l.lanispl,
      'handler', CASE WHEN call_proc.oid IS NULL THEN NULL ELSE format('%I.%I(%s)', call_ns.nspname, call_proc.proname, pg_get_function_identity_arguments(call_proc.oid)) END,
      'inline_handler', CASE WHEN inline_proc.oid IS NULL THEN NULL ELSE format('%I.%I(%s)', inline_ns.nspname, inline_proc.proname, pg_get_function_identity_arguments(inline_proc.oid)) END,
      'validator', CASE WHEN validator_proc.oid IS NULL THEN NULL ELSE format('%I.%I(%s)', validator_ns.nspname, validator_proc.proname, pg_get_function_identity_arguments(validator_proc.oid)) END
    )::text
  )::text
  FROM deps d
  JOIN pg_language l ON d.classid = 'pg_language'::regclass AND d.objid = l.oid AND d.objsubid = 0
  LEFT JOIN pg_proc call_proc ON call_proc.oid = l.lanplcallfoid
  LEFT JOIN pg_namespace call_ns ON call_ns.oid = call_proc.pronamespace
  LEFT JOIN pg_proc inline_proc ON inline_proc.oid = l.laninline
  LEFT JOIN pg_namespace inline_ns ON inline_ns.oid = inline_proc.pronamespace
  LEFT JOIN pg_proc validator_proc ON validator_proc.oid = l.lanvalidator
  LEFT JOIN pg_namespace validator_ns ON validator_ns.oid = validator_proc.pronamespace

  UNION ALL

  SELECT jsonb_build_object(
    'class', 'type', 'identity', format('%I.%I', n.nspname, t.typname),
    'definition', jsonb_build_object(
      'kind', t.typtype, 'category', t.typcategory, 'owner', pg_get_userbyid(t.typowner), 'acl', t.typacl,
      'element_type', CASE WHEN t.typelem = 0 THEN NULL ELSE format_type(t.typelem, NULL) END,
      'relation_type', CASE WHEN rel_class.oid IS NULL THEN NULL ELSE format('%I.%I', rel_ns.nspname, rel_class.relname) END,
      'not_null', t.typnotnull, 'default', t.typdefault, 'extension_name', d.extname
    )::text
  )::text
  FROM pg_type t
  JOIN ns n ON n.oid = t.typnamespace
  LEFT JOIN pg_class rel_class ON rel_class.oid = t.typrelid
  LEFT JOIN pg_namespace rel_ns ON rel_ns.oid = rel_class.relnamespace
  LEFT JOIN deps d ON d.classid = 'pg_type'::regclass AND d.objid = t.oid AND d.objsubid = 0

  UNION ALL

  SELECT jsonb_build_object(
    'class', 'enum_entry', 'identity', format('%I.%I', n.nspname, t.typname),
    'definition', jsonb_build_object('enumsortorder', e.enumsortorder, 'enumlabel', e.enumlabel)::text
  )::text
  FROM pg_enum e
  JOIN pg_type t ON t.oid = e.enumtypid
  JOIN ns n ON n.oid = t.typnamespace

  UNION ALL

  SELECT jsonb_build_object(
    'class', 'cast', 'identity', format('%s=>%s', format_type(c.castsource, NULL), format_type(c.casttarget, NULL)),
    'definition', jsonb_build_object(
      'context', c.castcontext, 'method', c.castmethod,
      'function', CASE WHEN cast_proc.oid IS NULL THEN NULL ELSE format('%I.%I(%s)', cast_ns.nspname, cast_proc.proname, pg_get_function_identity_arguments(cast_proc.oid)) END
    )::text
  )::text
  FROM pg_cast c
  LEFT JOIN pg_proc cast_proc ON cast_proc.oid = c.castfunc
  LEFT JOIN pg_namespace cast_ns ON cast_ns.oid = cast_proc.pronamespace

  UNION ALL

  SELECT jsonb_build_object(
    'class', 'constraint',
    'identity', format('%s.%I', COALESCE(
      format('%I.%I', rel_ns.nspname, rel_class.relname),
      format('%I.%I', type_ns.nspname, con_type.typname), '<none>'
    ), k.conname),
    'definition', jsonb_build_object(
      'type', k.contype, 'deferrable', k.condeferrable, 'initially_deferred', k.condeferred,
      'validated', k.convalidated, 'definition', pg_get_constraintdef(k.oid, true), 'extension_name', d.extname
    )::text
  )::text
  FROM pg_constraint k
  JOIN ns n ON n.oid = k.connamespace
  LEFT JOIN pg_class rel_class ON rel_class.oid = k.conrelid
  LEFT JOIN pg_namespace rel_ns ON rel_ns.oid = rel_class.relnamespace
  LEFT JOIN pg_type con_type ON con_type.oid = k.contypid
  LEFT JOIN pg_namespace type_ns ON type_ns.oid = con_type.typnamespace
  LEFT JOIN deps d ON d.classid = 'pg_constraint'::regclass AND d.objid = k.oid AND d.objsubid = 0

  UNION ALL

  SELECT jsonb_build_object(
    'class', 'policy', 'identity', format('%I.%I.%I', n.nspname, c.relname, p.polname),
    'definition', jsonb_build_object(
      'command', p.polcmd, 'permissive', p.polpermissive,
      'roles', ARRAY(SELECT CASE WHEN role_oid = 0 THEN 'PUBLIC' ELSE pg_get_userbyid(role_oid) END FROM unnest(p.polroles) role_oid ORDER BY 1),
      'using', pg_get_expr(p.polqual, p.polrelid), 'with_check', pg_get_expr(p.polwithcheck, p.polrelid)
    )::text
  )::text
  FROM pg_policy p
  JOIN pg_class c ON c.oid = p.polrelid
  JOIN ns n ON n.oid = c.relnamespace

  UNION ALL

  SELECT jsonb_build_object(
    'class', 'rule', 'identity', format('%I.%I.%I', n.nspname, c.relname, r.rulename),
    'definition', jsonb_build_object(
      'event_type', r.ev_type, 'enabled', r.ev_enabled, 'is_instead', r.is_instead,
      'definition', pg_get_ruledef(r.oid, true), 'extension_name', d.extname
    )::text
  )::text
  FROM pg_rewrite r
  JOIN pg_class c ON c.oid = r.ev_class
  JOIN ns n ON n.oid = c.relnamespace
  LEFT JOIN deps d ON d.classid = 'pg_rewrite'::regclass AND d.objid = r.oid AND d.objsubid = 0
  WHERE r.rulename <> '_RETURN'

  UNION ALL

  -- Internal FK/constraint triggers are keyed by constraint and semantics,
  -- never by PostgreSQL's generated trigger name or an object identifier.
  SELECT jsonb_build_object(
    'class', 'constraint_trigger',
    'identity', format('%s|%I.%I|%I.%I(%s)|%s|%s|%s',
      ci.identity, rel_ns.nspname, rel_class.relname, proc_ns.nspname, proc.proname,
      pg_get_function_identity_arguments(proc.oid),
      CASE WHEN (g.tgtype & 2) <> 0 THEN 'BEFORE' WHEN (g.tgtype & 64) <> 0 THEN 'INSTEAD OF' ELSE 'AFTER' END,
      concat_ws('+',
        CASE WHEN (g.tgtype & 4) <> 0 THEN 'INSERT' END,
        CASE WHEN (g.tgtype & 8) <> 0 THEN 'DELETE' END,
        CASE WHEN (g.tgtype & 16) <> 0 THEN 'UPDATE' END,
        CASE WHEN (g.tgtype & 32) <> 0 THEN 'TRUNCATE' END
      ),
      CASE WHEN (g.tgtype & 1) <> 0 THEN 'ROW' ELSE 'STATEMENT' END
    ),
    'definition', jsonb_build_object(
      'constraint', ci.identity, 'relation', format('%I.%I', rel_ns.nspname, rel_class.relname),
      'function', format('%I.%I(%s)', proc_ns.nspname, proc.proname, pg_get_function_identity_arguments(proc.oid)),
      'timing', CASE WHEN (g.tgtype & 2) <> 0 THEN 'BEFORE' WHEN (g.tgtype & 64) <> 0 THEN 'INSTEAD OF' ELSE 'AFTER' END,
      'events', concat_ws('+',
        CASE WHEN (g.tgtype & 4) <> 0 THEN 'INSERT' END,
        CASE WHEN (g.tgtype & 8) <> 0 THEN 'DELETE' END,
        CASE WHEN (g.tgtype & 16) <> 0 THEN 'UPDATE' END,
        CASE WHEN (g.tgtype & 32) <> 0 THEN 'TRUNCATE' END
      ),
      'for_each', CASE WHEN (g.tgtype & 1) <> 0 THEN 'ROW' ELSE 'STATEMENT' END,
      'enabled', g.tgenabled, 'deferrable', g.tgdeferrable, 'initially_deferred', g.tginitdeferred
    )::text
  )::text
  FROM pg_trigger g
  JOIN constraint_ids ci ON ci.oid = g.tgconstraint
  JOIN pg_class rel_class ON rel_class.oid = g.tgrelid
  JOIN pg_namespace rel_ns ON rel_ns.oid = rel_class.relnamespace
  JOIN pg_proc proc ON proc.oid = g.tgfoid
  JOIN pg_namespace proc_ns ON proc_ns.oid = proc.pronamespace
  WHERE g.tgisinternal AND g.tgconstraint <> 0

  UNION ALL

  SELECT jsonb_build_object(
    'class', 'trigger', 'identity', format('%I.%I.%I', n.nspname, c.relname, g.tgname),
    'definition', jsonb_build_object(
      'enabled', g.tgenabled, 'definition', pg_get_triggerdef(g.oid, true), 'extension_name', d.extname
    )::text
  )::text
  FROM pg_trigger g
  JOIN pg_class c ON c.oid = g.tgrelid
  JOIN ns n ON n.oid = c.relnamespace
  LEFT JOIN deps d ON d.classid = 'pg_trigger'::regclass AND d.objid = g.oid AND d.objsubid = 0
  WHERE NOT g.tgisinternal
)
SELECT v FROM lines;

COMMIT;
\else
\warn Provide exactly one of -v ledger=true or -v catalog=true.
\quit
\endif
"############;
const A0_FINGERPRINT_MD_SOURCE: &str = r############"# Task 10 A0 — stable legacy-target authority fingerprint (V1)

Scope: a read-only preflight binding for the one-time legacy cleanup target.
It is evidence only; it neither authorizes nor performs cleanup.

## Fixed target and exact reproduction

```sh
TARGET_DB='postgresql://127.0.0.1:5432/catbird_chat_protocol_test_20260722'
FINGERPRINT_SQL='.superpowers/sdd/2026-07-22-chat-protocol/task-10-a0-legacy-fingerprint.sql'

for MODE in ledger catalog; do
  node - "$TARGET_DB" "$FINGERPRINT_SQL" "$MODE" <<'NODE'
const { spawnSync } = require('node:child_process');
const crypto = require('node:crypto');
const [target, sql, mode] = process.argv.slice(2);
if (!['ledger', 'catalog'].includes(mode)) throw new Error('mode must be ledger or catalog');
const run = spawnSync('psql', [target, '-X', '-qAt', '-v', 'ON_ERROR_STOP=1', '-v', `${mode}=true`, '-f', sql], {
  encoding: 'utf8', env: { ...process.env, LC_ALL: 'C', PGCLIENTENCODING: 'UTF8' },
});
if (run.status !== 0) throw new Error(run.stderr || `psql exit ${run.status}`);
const records = run.stdout.split(/\n/).filter(Boolean).map((line) => JSON.parse(line));
const u32 = (n) => { if (!Number.isInteger(n) || n < 0 || n > 0xffffffff) throw new Error(`bad u32 ${n}`); const b = Buffer.alloc(4); b.writeUInt32BE(n); return b; };
const utf8 = (s) => Buffer.from(String(s), 'utf8');
const frame = (b) => Buffer.concat([u32(b.length), b]);
let bytes;
if (mode === 'ledger') {
  for (const r of records) if (!/^[0-9]+$/.test(r.version) || typeof r.description !== 'string' || typeof r.success !== 'boolean' || !/^[0-9a-f]{96}$/.test(r.checksum_hex)) throw new Error('invalid ledger record');
  records.sort((a, b) => BigInt(a.version) < BigInt(b.version) ? -1 : BigInt(a.version) > BigInt(b.version) ? 1 : 0);
  const parts = [Buffer.from('CATBIRD-G7-A0-LEGACY-LEDGER-V1\0', 'ascii'), u32(records.length)];
  for (const r of records) parts.push(frame(utf8(r.version)), frame(utf8(r.description)), frame(Buffer.of(r.success ? 1 : 0)), frame(Buffer.from(r.checksum_hex, 'hex')));
  bytes = Buffer.concat(parts);
} else {
  for (const r of records) if (typeof r.class !== 'string' || typeof r.identity !== 'string' || typeof r.definition !== 'string') throw new Error('invalid catalog record');
  const triple = (r) => [utf8(r.class), utf8(r.identity), utf8(r.definition)];
  records.sort((a, b) => { const x = triple(a), y = triple(b); return Buffer.compare(x[0], y[0]) || Buffer.compare(x[1], y[1]) || Buffer.compare(x[2], y[2]); });
  const parts = [Buffer.from('CATBIRD-G7-A0-LEGACY-CATALOG-V1\0', 'ascii'), u32(records.length)];
  for (const r of records) for (const field of triple(r)) parts.push(frame(field));
  bytes = Buffer.concat(parts);
}
for (const algorithm of ['sha256', 'sha384']) console.log(`${mode} ${algorithm} ${crypto.createHash(algorithm).update(bytes).digest('hex')}`);
NODE
done
```

Run the exact block twice; both runs must agree. `psql -X -qAt` prevents
`psqlrc`, formatting, and command tags from entering the parsed records.
Transport newlines (including the final one) are intentionally ignored after
JSON parsing. SQL runs `REPEATABLE READ READ ONLY`, sets `search_path` to
`pg_catalog`, and sets `bytea_output` to `hex`; Node fixes `LC_ALL=C` and
`PGCLIENTENCODING=UTF8`.

Expected V1 authority digests (two independent reproductions matched):

| Stream | SHA-256 | SHA-384 |
| --- | --- | --- |
| ledger | `d205f5ab9a1e0927fce4c85e8682ec90f9a2f0e91022784e18b68ea77a29f971` | `9e156e6f39962d341388b81a94d3a7931f5b9882d35ebbfeff9d85c1caeae04a75482d977e3eecb4f8d005365b2a2bec` |
| catalog | `7712d1ea518550a4a4c7c353db8da8d2fbd40a77830300c7fbbf69169510f008` | `0ebbfbc6c716604c98b60ee839b9ad8a551e1145ec3538d0e3b2ffa60eebfd90c6664abbfea1c339cc42b406f61bc58c` |

## V1 authority bytes

- Ledger prefix: ASCII `CATBIRD-G7-A0-LEGACY-LEDGER-V1\0`, then count as u32
  big-endian. Rows sort by numeric migration version. For each: u32be length +
  canonical decimal version UTF-8; description UTF-8; one-byte boolean (`00` or
  `01`, framed with length 1); raw 48-byte checksum, also framed. No execution
  time or OID is represented.
- Catalog prefix: ASCII `CATBIRD-G7-A0-LEGACY-CATALOG-V1\0`, then count as u32
  big-endian. Entries sort bytewise by UTF-8 `class`, then `identity`, then
  `definition`. Each field is u32be length + UTF-8 bytes.
- SQL emits no OID or OID-derived numeric/key field. It covers extensions,
  non-system schemas, relations (including ACL/RLS/replica/partition state),
  named columns (with stable attnum and ACL), sequences and all `pg_sequence`
  parameters, indexes, functions and ACLs, types and ACLs, enum entries,
  constraints, policies, non-view rules, all constraint-owned internal triggers,
  and noninternal triggers. The entry count binds the current absence of
  policies and non-view rules. Internal constraint triggers deliberately omit
  generated names: their stable key is owning constraint identity, relation,
  trigger function signature, decoded timing/events/row scope; their definition
  binds enabled, deferrable, and initially-deferred state. All direct
  extension dependencies serialize their extension name, never object
  identifiers. JSONB appears only as canonical definition text inside a parsed
  record.

The catalog also binds the current database name, owner, encoding, collate and
ctype, locale provider and ICU fields, template/connection-limit/tablespace state,
and database ACL. Per-database role settings are emitted by stable role name and
individual sorted configuration string; their `class_count` row binds an empty
setting set. Every direct extension member is emitted with a class-specific,
stable identity. On this target those are 49 extension functions (including the
three `pg_catalog` `plpgsql` procedures) and the `plpgsql` language, whose
trusted/procedural/owner/ACL/handler/inline/validator state is bound.

`pg_database.datallowconn` is deliberately omitted from the stable catalog
bytes. The cleanup state machine owns that one mutable fencing control: it must
check `true` before the fence, check `false` while the fence is held, then check
the addendum's restored-success or terminal-cleanup handling explicitly. It
cannot be fingerprinted while also requiring the same authority digest across
that intentional transition.

## Focused mutable-class audit

The rejected omission is closed by five `enum_entry` records for
`public.chat_request_status`, each binding its label and `enumsortorder`. The
three present `pg_sequence` rows bind all sequence parameters and sequence
owner. Relation, column, function, and type ACLs now bind their respective
mutable permission state; relation RLS, forced RLS, replica identity, and
partition state are bound as well. The entry count binds the observed absence
of policies and non-view rules, so either class becoming nonempty changes the
catalog authority bytes. The focused snapshot found no standalone composite
attributes, user ranges, foreign tables, partitioned tables, or user
collations. The 144 internal constraint triggers and all 229 `pg_cast` rows
are now emitted with stable semantic identities and their class counts. The
current class-count rows additionally bind zero ordinary operators, opclasses,
opfamilies, collations, event triggers,
inheritance edges, FDWs, foreign servers, user mappings, publications,
subscriptions, extended statistics, text-search objects, and conversions.
Thus every mutable behavioral class/state asserted by this catalog evidence is
now represented or its present absence is count-bound.

This is intentionally a behavioral-schema authority fingerprint. Comments are
excluded because they do not affect behavior; planner statistics and extended
physical statistics data are excluded because only their schema objects are
behavioral, and those object counts are bound; and `attmissingval` is excluded
because logical column default/type/nullability semantics are already bound and
the field is a physical fast-default storage optimization rather than an
independent protocol contract.

## Historical non-authority values

The earlier raw-psql hashes are deprecated and must not be used for authority:
ledger `6bd267c8b8c00b26eb999cca7767dce5ad06884c0dd7e2f12b14c15499c63c86` /
`77852f962a5ce1dcfa39627a254216fe4ac0bb534cb238bb79b25983ac69d2a5a4bd6be4c099bfe72794f61e3b480090`; catalog
`2b0b7f1ff0bee0504447b63851f82b8347661d5495ec9a01b226bfd5fc60ec8a` /
`f4ccaf95fe8f2ed5af78e6a26385e9044002101ae615858b1d31816089e6d2fef3abb84b859683088d586c85c56a61f9`.
The superseded pre-enum V1 catalog hashes are likewise deprecated:
`ba02d92f6a43fa00e2d88bae1396e15eb4cbdbdab42d9d3c4a66c335fa3c28f2` /
`b5b04840d0a4231ec1452a85ce23a539874dbedc2e3ad1627038a18e6eab5b4d334d21319de45889db4232279ad1e76c`.
The superseded pre-database/extension V1 catalog hashes are also deprecated:
`a1aa66f5df0601e4064634eda6c956541ac2eaba41d9b1131db71f23d6350cca` /
`cc11b60bf36a9cd2b1753fdfe97e1b0d5c632c6cae5a2b5161a63ae71f548a30bb4a901049cdcd3e9c07896b959ce75c`.
The superseded pre-cast/internal-trigger catalog hashes are also deprecated:
`3946c1aed5cc3f0e95a1bf528eabb34ee40e3a2e4697a025d08bb2a36fe8649d` /
`6796ab0bcf60043c870ba1a3ac15d0f091782566e5cb9b801d6245c0e9a25d3a88feb5f4141469b54f5b47861e02fd0d`.
The superseded pre-fence-normalization catalog hashes are also deprecated:
`4616b75ea6e29494bdffc6236a491b92113e8b47d1913304854fb3780525176e` /
`9f3eb8ffac098e1d9339de8a21b386c355c2f21f4d0be15ddfc9e5dd915e759329a4a10056d8adf7616ac07f46022cc2`.

## Expected target facts

- Target DB OID `17744199`, owner `joshlacalamito`, server `127.0.0.1:5432`.
- Non-system schema: only `public`; `chat` schema is absent.
- Counts: 53 tables, 2 views, 0 materialized views, 3 sequences, 211 indexes,
  52 functions, 112 types, 143 constraints, and 5 noninternal triggers.
- The 56 legacy migrations all succeeded; all 13 staged chat-protocol versions
  are absent from the target.
"############;
const A0_APPROVED_MANIFEST_DOMAIN: &[u8] = b"catbird-g7-a0-approved-manifest-v1\0";
const A0_APPROVED_PATHS: [&str; 8] = [
    "server/migrations/20260728000004_activate_operation_claim_completeness.sql",
    "server/docs/operation_claim_completeness_activation.sql",
    "server/migrations/20260729000001_chat_g7_inventory_entitlement.sql",
    "server/migrations/README.md",
    "server/tests/common/chat_protocol.rs",
    "server/tests/chat_protocol_schema.rs",
    "server/tests/chat_protocol_g7_schema.rs",
    "server/tests/chat_protocol_operation_claims.rs",
];
const A0_MARKER_PARENT: &str = "/Users/joshlacalamito/Developer/Catbird+Petrel/.codex-workspaces/mls-v2-stack/.superpowers/sdd/2026-07-22-chat-protocol";
const A0_INTENT_PATH: &str = "/Users/joshlacalamito/Developer/Catbird+Petrel/.codex-workspaces/mls-v2-stack/.superpowers/sdd/2026-07-22-chat-protocol/a0-reconciliation.intent";
const A0_CONSUMED_PATH: &str = "/Users/joshlacalamito/Developer/Catbird+Petrel/.codex-workspaces/mls-v2-stack/.superpowers/sdd/2026-07-22-chat-protocol/a0-reconciliation-consumed.json";
const A0_DISABLE_CONNECTIONS_SQL: &str =
    r#"ALTER DATABASE "catbird_chat_protocol_test_20260722" ALLOW_CONNECTIONS false"#;
const A0_RESTORE_CONNECTIONS_SQL: &str =
    r#"ALTER DATABASE "catbird_chat_protocol_test_20260722" ALLOW_CONNECTIONS true"#;
const A0_DROP_DATABASE_SQL: &str = r#"DROP DATABASE "catbird_chat_protocol_test_20260722""#;
const A0_CREATE_DATABASE_SQL: &str =
    r#"CREATE DATABASE "catbird_chat_protocol_test_20260722" OWNER "joshlacalamito""#;
// Clean-lineage extension-owned object count: pgcrypto 1.3 contributes 36
// functions, plpgsql 3 functions plus its language object. The same arithmetic
// over the legacy set (plus uuid-ossp 1.1's 10 functions) reproduces the
// previously pinned 50, which is what validates the method.
const A0_EXTENSION_OBJECT_COUNT: usize = 40;
// Promoted from the 2026-07-30 smoke run (preimage
// preimages/Q11-extension-objects-40.txt, 40 ordered lines matching the count
// above), independently recomputed before promotion. Direct evidence that this
// value is installation-determined: line 36 renders `public.gen_random_uuid()`
// schema-qualified while its 35 pgcrypto siblings render bare, because
// gen_random_uuid also exists in pg_catalog on PG13+ and pg_describe_object
// disambiguates. Subject to the search_path note above.
const A0_EXTENSION_OBJECT_CATALOG_SHA256: &str =
    "2f76f6f14fdcdbba08c6564be490e4330aaadf7418441f902db687621f89f4b0";
const A0_LEGACY_LEDGER_DOMAIN: &[u8] = b"CATBIRD-G7-A0-LEGACY-LEDGER-V1\0";
const A0_LEGACY_CATALOG_DOMAIN: &[u8] = b"CATBIRD-G7-A0-LEGACY-CATALOG-V1\0";

#[derive(Clone, Copy)]
struct A0LegacyLedgerManifestEntry {
    version: i64,
    description: &'static str,
    checksum_sha384: &'static str,
}

const A0_LEGACY_LEDGER_56_MANIFEST: [A0LegacyLedgerManifestEntry; 56] = [
    A0LegacyLedgerManifestEntry { version: 20250101000000, description: "greenfield schema", checksum_sha384: "c576503a14746c83ea90b19d3e370012efe9a244830cbe9188be669fe8cfefb321f6a771d880f8cc205761b671079bfe" },
    A0LegacyLedgerManifestEntry { version: 20251125000001, description: "opt in table", checksum_sha384: "110ade98598f25b55445eaf7ca7987a54ddb3200238faf2955c410a389e1cc9d7fb78d31c6b5e9e947b0dd325c50109e" },
    A0LegacyLedgerManifestEntry { version: 20251125000002, description: "read receipts", checksum_sha384: "7b6851f0beba789559c48e9ef2e08df7d422a75d68a824e4b5a388f49e9a1c44ce4a84ba78644596c9ec9c98271bc50b" },
    A0LegacyLedgerManifestEntry { version: 20251125000003, description: "add warn action", checksum_sha384: "682d1a58ac3a609cd2c37ef823b7ce18bca0139897e976e546b1e1daf6a0efa9e2da0f9e946917cd7dec47a6d698e8ae" },
    A0LegacyLedgerManifestEntry { version: 20251125000004, description: "max members", checksum_sha384: "99fa7ca60529ef2336c65a2499eda11d9ef52bd94ac87aafb5a4ebfdcd94ccc5444639e9b5a0fa65da1084c307ce11c0" },
    A0LegacyLedgerManifestEntry { version: 20251125000005, description: "pending device additions", checksum_sha384: "4f2d852085ee4b26dc1342a0cac11c0792f9fef4fe04956a31b24c4c3b947a23cdee53fcce7b2bd38c2021b3bbced55e" },
    A0LegacyLedgerManifestEntry { version: 20251125000006, description: "add moderator role", checksum_sha384: "ba0a93d9cb5e3d22731b550f8c293b2c9a1d5b7a93702fe34540c822abd24dbb0ec6762857b723aafdffbcf34e1a075b" },
    A0LegacyLedgerManifestEntry { version: 20251127000001, description: "welcome error tracking", checksum_sha384: "f6a317ded9426f0e5f6a5c426c699f625ad78c2f12268ecbe68f139838c1653cb30828b156a681d4940cc102d413054c" },
    A0LegacyLedgerManifestEntry { version: 20251206000001, description: "message reactions", checksum_sha384: "6db4bf11bd02a7c756c2a8c73544a83677773b35b374a4dd0f5dc1e52512634453a9c48259aa48057c3519fdba39774f" },
    A0LegacyLedgerManifestEntry { version: 20251210000000, description: "chat requests", checksum_sha384: "8e53bee9e3b613c2838a2ab97f63ae80cf13138f863dc30b46df48490dcfb80b57d20ed90237148413d0da5763165173" },
    A0LegacyLedgerManifestEntry { version: 20251213000001, description: "federation support", checksum_sha384: "e304ec2af1fed912f801764a55e914bf530a16e2a44ca2481d58d8f2d6acda0cde9ceb927241f1dc2ee25f18559f15fa" },
    A0LegacyLedgerManifestEntry { version: 20260213000001, description: "remove sender did storage", checksum_sha384: "dafb956de7fd1cbe46a22ca1066fbfa0ef904f1eea198ba8cc0e9f54a5b9f47a51ada04f184f97c5a75a9f6affcf0faf" },
    A0LegacyLedgerManifestEntry { version: 20260214000001, description: "federation peer policy", checksum_sha384: "6f53140fc1191cfc67a008c35abc7aa786364fb3e427c1404053782c1fa3c64bcc7e1d0a438ec263906db4285a37271a" },
    A0LegacyLedgerManifestEntry { version: 20260214000002, description: "auth jti nonce", checksum_sha384: "a653190a473ce3535c946769e8e269173fcf22c1cc6196063eb9461e4766bc084a57c61d2b3a4ffee4b5a1b4da06856b" },
    A0LegacyLedgerManifestEntry { version: 20260214000003, description: "federation commits", checksum_sha384: "8c68047ef3c3010d38bc7668a28eec61f0d70c36d6dfdec70fe4017fcf22acf52e52a77ecd7eefc87d69b51cd3796949" },
    A0LegacyLedgerManifestEntry { version: 20260214000004, description: "sequencer receipts", checksum_sha384: "12fcc8c8b446d37176dbe5f644dd2bd6cb52314c6eb22d47d6d77bbe86062cba7c72182250264d112b6c3b06569479dc" },
    A0LegacyLedgerManifestEntry { version: 20260214000005, description: "delivery acks", checksum_sha384: "a376b5cfabe46f25deafa58e780588a2d3e8f2d8dd3c6af96f15239f563652da06c8e748504ff4cb13faed9a88fc6c93" },
    A0LegacyLedgerManifestEntry { version: 20260214000006, description: "delivery acks unique", checksum_sha384: "674f31ce93a1d4887465b3567303b0e744d523ecabce9dbf5ecf2f56d9783b165deff3432f7bee6f1f98c9cee4d5bb53" },
    A0LegacyLedgerManifestEntry { version: 20260215000000, description: "idempotency cache caller did", checksum_sha384: "fd66c11ba60c87caf4efdee3e4bef6aea8224963b9c848e124c93127177e4956e4278ec0c9b4200c3eaac69df2382023" },
    A0LegacyLedgerManifestEntry { version: 20260215000001, description: "delivery ack verified", checksum_sha384: "d5e4d3278b6bd6bb1ac5320a4879f5827747a5d244bb9d4bc1e97137b786823121ecc367ea033d6fe8c6691a168db78a" },
    A0LegacyLedgerManifestEntry { version: 20260219000001, description: "federation clean break hardening", checksum_sha384: "c84fbe5d28ac614353208dd2b8357d5be5c943161ae1a6e1dc93ccc6be79c9891e1374c685547b2e1bd52ab6aab76d88" },
    A0LegacyLedgerManifestEntry { version: 20260222000001, description: "federation peer policy audit log", checksum_sha384: "ca9820176cdf6b5ee95dd22c089bf1a3c2650520c194d528d7bd0fbf47a08caf9ad791cd11a2773b45f4fc7c655b2e58" },
    A0LegacyLedgerManifestEntry { version: 20260311000001, description: "create blobs table", checksum_sha384: "99d73fedb97233bbc08245607d98681bc4c27424b920e584a62e292cb9cecf55c5d42e07fda084a4675c17426fe472a0" },
    A0LegacyLedgerManifestEntry { version: 20260312000001, description: "group metadata blobs", checksum_sha384: "5ac3c48ef3f94735334c704ce9cef4208793d2d7ed1e4e2f6459d4a87cc980ff9c0e51894ebd029ad860d3e347f8b948" },
    A0LegacyLedgerManifestEntry { version: 20260313000001, description: "blob convo id", checksum_sha384: "a6b2ca40d0db4d6926117fc0a66f3f225324737fd257554609f3dfb7b22c9654faedf2148bafb14793735ac4f9ca16e2" },
    A0LegacyLedgerManifestEntry { version: 20260316000001, description: "messages convo seq unique", checksum_sha384: "495b17877fec10c7e2197c0fe9012ed02d3c9b36883bcb339082afc86b347568089ad3845c41408d21eb3d9d5f1d0bf2" },
    A0LegacyLedgerManifestEntry { version: 20260403000000, description: "replace reports with spam reports", checksum_sha384: "4729f4e5552c743fcd30aba9c6d868cf5e0f4e3aa5a421ae4b22431170ef6c082ac1fa226a57cbf306d9472c1ff71763" },
    A0LegacyLedgerManifestEntry { version: 20260403100000, description: "drop read receipts", checksum_sha384: "8828c6d81fbfdc6e90cfda2a78856e40b6c95005e8c1cfcf870eef037881a013fad4f1d15dc712dcfbb6d4f0d9517b45" },
    A0LegacyLedgerManifestEntry { version: 20260404100000, description: "add confirmation tag", checksum_sha384: "bb87e7076ae562744562491c80e5b6e3a22d4be3866964e53f814c73e6eae904766c626cf8914bd4c04784775b047b0f" },
    A0LegacyLedgerManifestEntry { version: 20260405100000, description: "group reset support", checksum_sha384: "f9f391d25bebec023ce0be4264b65e2938920dedd68c4bb5cf62cce30eaae70d2a2f02fc8368a0c64b57d5c74c599d3c" },
    A0LegacyLedgerManifestEntry { version: 20260406100000, description: "drop message reactions", checksum_sha384: "44fe4959f49b81b88ee73ae89ec28b6bf162417a3a57ca09351ab07319be964b0a3e1884122a495c009bb47d028f0e20" },
    A0LegacyLedgerManifestEntry { version: 20260407100000, description: "recovery failures", checksum_sha384: "21c4341c16804297a58efdb9fb33a0cb7716bde28bb72c311debe5b76af4292b437b899f0fcda5ad0d46a5216891426d" },
    A0LegacyLedgerManifestEntry { version: 20260418100000, description: "reset votes and epoch authenticators", checksum_sha384: "8c746805af909ed4720aa7ad2f97c02b69f593ca8886e2b01f7d5c4c459b8b8b2bae5fe3e1a31ad5b26cac837ed12f1a" },
    A0LegacyLedgerManifestEntry { version: 20260425100000, description: "messages wire epoch", checksum_sha384: "56fae1ad437e6e2def1c67c0b4d112cd926b4350fc20d0f32ddd98fc581cab4f6f98af915fa10508a8f27cd43e3437e5" },
    A0LegacyLedgerManifestEntry { version: 20260426100000, description: "reset votes failure mode", checksum_sha384: "b7c4e5dd366214f34853a2fa7b890f9bea9ad7f6362cf413368b3eb8e6f97d843f76cfb2cd44e4132e1a312343c5dbfb" },
    A0LegacyLedgerManifestEntry { version: 20260427100000, description: "commit health columns", checksum_sha384: "27dc8b75d106103ac465847a800562ac4db9667de082d8f9ae78a28b817293f4a3f7b7225938a9a236de608266595157" },
    A0LegacyLedgerManifestEntry { version: 20260428100000, description: "groupinfo 404 health columns", checksum_sha384: "4fc14ba4c6752e62b234f08a5fa3c53118f417205a311c07148bb295ace302cf781f64caa1955cfc519d02c215460d57" },
    A0LegacyLedgerManifestEntry { version: 20260429000001, description: "crypto sessions and delivery events", checksum_sha384: "8e7efe2830d0c9800bd57763e827a98299905119a5f75735470175aff965188ac020217892b370f59f7ef9bf1275d2f3" },
    A0LegacyLedgerManifestEntry { version: 20260429000002, description: "key package state", checksum_sha384: "73e141e451b0c0fb9fc3a37a028e6406b542c54ca2a7b046b9f46a50933bace6cfd71c0b5cfa04dc66b2719194b63761" },
    A0LegacyLedgerManifestEntry { version: 20260429000003, description: "durable outbox", checksum_sha384: "047a332b3f7e87bab4d911c026f5a472fc34d62a53c7fabcea03d3b2fcb5b96be8009779cb4e290cde781518efcf0b74" },
    A0LegacyLedgerManifestEntry { version: 20260429000004, description: "reset reminder state", checksum_sha384: "3d031d2176a963bf20d8af29ab8a38e26425f8ff2f73f4752ea97590d7206e7369c1b7bab93240666f749965453cef96" },
    A0LegacyLedgerManifestEntry { version: 20260429000005, description: "message timeline seq index", checksum_sha384: "3d78a24e20947734b43a790418b20643e8c671e766d8d1a761ad01feb4b28ccf3e763f6cdd8fff90f08c32c19c2814ad" },
    A0LegacyLedgerManifestEntry { version: 20260429000006, description: "group metadata conversation scope", checksum_sha384: "2deb305652dbf872858212aae3e9144dfc989a1c3300ed237a4dc146e95b36e902fca3e058b37b8f68ccc9edfd6d39b7" },
    A0LegacyLedgerManifestEntry { version: 20260429000007, description: "drop plaintext metadata", checksum_sha384: "f0eda6dc4a152f6158298c7186ea7ed7a9a0b913565544f525ddf1ea0b2855da936d857754bece2c322b85bcccecd5f9" },
    A0LegacyLedgerManifestEntry { version: 20260508100000, description: "external commit audit and freeze", checksum_sha384: "dfabfec6d3ce41bac0f456356f83df0b3b1362f97db710e0d0085c30e52fec85345327f4b12396364f9718b5fa375df6" },
    A0LegacyLedgerManifestEntry { version: 20260508110000, description: "inline 404 bootstrap gate", checksum_sha384: "b5a13b49c640f2fc9d270eefba9a3133d6a7db97b3a352feb0ca6509f7ae8fea69407cf0ce7cb734852b619d30e91bd0" },
    A0LegacyLedgerManifestEntry { version: 20260515000001, description: "reissue welcome requests", checksum_sha384: "3a82b38436e479c3733924ec0d02b838de1c64ca02e3107fbb95fd4262b283c672d5de038637982b2cd909114afdd768" },
    A0LegacyLedgerManifestEntry { version: 20260515000002, description: "kp audit", checksum_sha384: "6f18c30f0164c6cbef1a08de8f8996ac4c09e59196d83c5fe49f2f2004e4cab2304c103f7f7175abed21ebdc4e334283" },
    A0LegacyLedgerManifestEntry { version: 20260618120000, description: "welcome messages recipient device id", checksum_sha384: "88815f2c9b11d28df5242f2da360646e8d9161b3db501352aab96375cca7400d5d2991025acb6044340759d4fe08da0d" },
    A0LegacyLedgerManifestEntry { version: 20260621000001, description: "unique open reissue requests", checksum_sha384: "e6f237fea6c4f8fecc7126cc30da9029a2a27b181e76d9d042288e0ddaf2d0890fae7a6f17cab88e3c893503d0e957d9" },
    A0LegacyLedgerManifestEntry { version: 20260622000001, description: "reissue request status", checksum_sha384: "b8296ead5b85c7f160643c91c8c8e3b8fc524f5a7180cb0cedb3474bd80fc3dfd7086720c1ceadf17f980e0ccc2051d3" },
    A0LegacyLedgerManifestEntry { version: 20260627000001, description: "key package reserved state", checksum_sha384: "a0783c08ff0788e5b9cab7e711769d2b673307dc39d751c0260e40fc620812c3ab5bcbb350cd24fec1307c096eb349e1" },
    A0LegacyLedgerManifestEntry { version: 20260630000001, description: "kp first served at", checksum_sha384: "c88584a6d44c225ae0ad637d0c4051cc73487b6e13dd6aa69b2ec755bac2e81f0e3f0b2e6dba0fd9501cd1a1d14785b9" },
    A0LegacyLedgerManifestEntry { version: 20260712000001, description: "mls transition authority", checksum_sha384: "db4df9d83f7030f5d9b4617a28d7d1130fb93acc8fc99a317e03ed2854aba2991dc262de3b21bf91b17680239b0c80ce" },
    A0LegacyLedgerManifestEntry { version: 20260713000001, description: "device auth binding", checksum_sha384: "97c6abc525bc50bab175130625551db85574d977e5d96b074554724fcd0cb1d7a620f31cf17cb6b765752193daaf3a66" },
    A0LegacyLedgerManifestEntry { version: 20260716000001, description: "sequencer receipt generation", checksum_sha384: "e178cc268e01aa4687b7b619d075368de481b55f437f1411713298efde61ce0669b45b70ae9a720425484689c0d1983b" },
];

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
struct A0ApprovedFileDigest {
    path: String,
    sha256: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct A0ApprovedRuntimeBinding {
    revision: String,
    manifest_sha256: String,
    files: Vec<A0ApprovedFileDigest>,
}
#[derive(Clone, Debug, Eq, PartialEq)]
struct A0CanonicalEvidence {
    decision: &'static str,
    material_deletion: bool,
    pre_oid: u32,
    post_oid: u32,
    migrations_applied: usize,
    pre_ledger_sha256: String,
    post_ledger_sha256: String,
    pre_catalog_sha256: String,
    post_catalog_sha256: String,
    classified_legacy_count: i64,
    classified_legacy_set_sha256: String,
    marker_state: &'static str,
    marker_sha256: Option<String>,
    approved_revision: String,
    approved_manifest_sha256: String,
    // Provenance of a marker written by a prior attempt. Wholly present or
    // wholly absent; absent leaves the canonical bytes unchanged.
    marker_legacy_ledger_sha256: Option<String>,
    marker_legacy_catalog_sha256: Option<String>,
    marker_approved_revision: Option<String>,
    marker_approved_manifest_sha256: Option<String>,
}

impl A0CanonicalEvidence {
    fn canonical_json(&self) -> String {
        assert!(matches!(
            self.decision,
            "already_reconciled" | "legacy_forward_reconcile" | "recovery_from_consumed_marker"
        ));
        assert!(matches!(
            self.marker_state,
            "absent" | "preexisting_consumed" | "created_consumed"
        ));
        for (label, value) in [
            ("pre ledger", self.pre_ledger_sha256.as_str()),
            ("post ledger", self.post_ledger_sha256.as_str()),
            ("pre catalog", self.pre_catalog_sha256.as_str()),
            ("post catalog", self.post_catalog_sha256.as_str()),
            (
                "classified legacy set",
                self.classified_legacy_set_sha256.as_str(),
            ),
            ("approved manifest", self.approved_manifest_sha256.as_str()),
        ] {
            assert!(
                a0_strict_lower_hex::<32>(Some(value), "invalid A0 evidence digest").is_ok(),
                "{label} digest is not strict lowercase SHA-256"
            );
        }
        assert!(
            a0_strict_lower_hex::<20>(
                Some(&self.approved_revision),
                "invalid A0 approved revision"
            )
            .is_ok(),
            "approved revision is not strict lowercase 40-hex"
        );
        if let Some(marker_sha256) = &self.marker_sha256 {
            assert!(
                a0_strict_lower_hex::<32>(Some(marker_sha256), "invalid A0 marker digest").is_ok(),
                "marker digest is not strict lowercase SHA-256"
            );
        }
        let marker_sha256 = self
            .marker_sha256
            .as_ref()
            .map(|value| serde_json::to_string(value).expect("serialize A0 marker digest"))
            .unwrap_or_else(|| "null".to_owned());
        let marker_provenance = match (
            &self.marker_legacy_ledger_sha256,
            &self.marker_legacy_catalog_sha256,
            &self.marker_approved_revision,
            &self.marker_approved_manifest_sha256,
        ) {
            (None, None, None, None) => String::new(),
            (Some(ledger), Some(catalog), Some(revision), Some(manifest)) => {
                for (label, value) in [
                    ("marker legacy ledger", ledger.as_str()),
                    ("marker legacy catalog", catalog.as_str()),
                    ("marker approved manifest", manifest.as_str()),
                ] {
                    assert!(
                        a0_strict_lower_hex::<32>(
                            Some(value),
                            "invalid A0 marker provenance digest"
                        )
                        .is_ok(),
                        "{label} digest is not strict lowercase SHA-256"
                    );
                }
                assert!(
                    a0_strict_lower_hex::<20>(
                        Some(revision),
                        "invalid A0 marker provenance revision"
                    )
                    .is_ok(),
                    "marker approved revision is not strict lowercase 40-hex"
                );
                format!(
                    concat!(
                        ",\"marker_legacy_ledger_sha256\":{}",
                        ",\"marker_legacy_catalog_sha256\":{}",
                        ",\"marker_approved_revision\":{}",
                        ",\"marker_approved_manifest_sha256\":{}"
                    ),
                    serde_json::to_string(ledger)
                        .expect("serialize A0 marker legacy ledger digest"),
                    serde_json::to_string(catalog)
                        .expect("serialize A0 marker legacy catalog digest"),
                    serde_json::to_string(revision).expect("serialize A0 marker approved revision"),
                    serde_json::to_string(manifest)
                        .expect("serialize A0 marker approved manifest digest"),
                )
            }
            _ => panic!("A0 marker provenance must be wholly present or wholly absent"),
        };
        format!(
            concat!(
                "{{\"schema\":\"CATBIRD_G7_A0_EVIDENCE_V1\",",
                "\"decision\":{},",
                "\"material_deletion\":{},",
                "\"target_database\":\"catbird_chat_protocol_test_20260722\",",
                "\"pre_oid\":{},",
                "\"post_oid\":{},",
                "\"oid_changed\":{},",
                "\"migrations_applied\":{},",
                "\"pre_ledger_sha256\":{},",
                "\"post_ledger_sha256\":{},",
                "\"pre_catalog_sha256\":{},",
                "\"post_catalog_sha256\":{},",
                "\"classified_legacy_count\":{},",
                "\"classified_legacy_set_sha256\":{},",
                "\"lock_order\":\"20260729/700>20260729/701>sqlx\",",
                "\"marker_state\":{},",
                "\"marker_sha256\":{},",
                "\"approved_revision\":{},",
                "\"approved_manifest_sha256\":{}",
                "{}",
                "}}"
            ),
            serde_json::to_string(self.decision).expect("serialize A0 decision"),
            self.material_deletion,
            self.pre_oid,
            self.post_oid,
            self.pre_oid != self.post_oid,
            self.migrations_applied,
            serde_json::to_string(&self.pre_ledger_sha256).expect("serialize A0 pre-ledger digest"),
            serde_json::to_string(&self.post_ledger_sha256)
                .expect("serialize A0 post-ledger digest"),
            serde_json::to_string(&self.pre_catalog_sha256)
                .expect("serialize A0 pre-catalog digest"),
            serde_json::to_string(&self.post_catalog_sha256)
                .expect("serialize A0 post-catalog digest"),
            self.classified_legacy_count,
            serde_json::to_string(&self.classified_legacy_set_sha256)
                .expect("serialize A0 classified legacy-set digest"),
            serde_json::to_string(self.marker_state).expect("serialize A0 marker state"),
            marker_sha256,
            serde_json::to_string(&self.approved_revision).expect("serialize A0 approved revision"),
            serde_json::to_string(&self.approved_manifest_sha256)
                .expect("serialize A0 approved manifest digest"),
            marker_provenance,
        )
    }

    fn emit(self) {
        println!("CATBIRD_G7_A0_EVIDENCE_V1 {}", self.canonical_json());
    }
}

fn a0_push_u32(bytes: &mut Vec<u8>, value: usize) -> Result<(), &'static str> {
    let value = u32::try_from(value).map_err(|_| "A0 framed field exceeds u32")?;
    bytes.extend_from_slice(&value.to_be_bytes());
    Ok(())
}

fn a0_push_frame(bytes: &mut Vec<u8>, field: &[u8]) -> Result<(), &'static str> {
    a0_push_u32(bytes, field.len())?;
    bytes.extend_from_slice(field);
    Ok(())
}

fn a0_manifest_bytes(files: &[(&str, [u8; 32])]) -> Result<Vec<u8>, &'static str> {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(A0_APPROVED_MANIFEST_DOMAIN);
    a0_push_u32(&mut bytes, files.len())?;
    for (path, digest) in files {
        a0_push_frame(&mut bytes, path.as_bytes())?;
        bytes.extend_from_slice(digest);
    }
    Ok(bytes)
}

fn a0_strict_lower_hex<const N: usize>(
    value: Option<&str>,
    label: &'static str,
) -> Result<[u8; N], &'static str> {
    let value = value.ok_or(label)?;
    if value.len() != N * 2
        || !value
            .as_bytes()
            .iter()
            .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
    {
        return Err(label);
    }
    let decoded = hex::decode(value).map_err(|_| label)?;
    decoded.try_into().map_err(|_| label)
}

fn a0_full_digest_match(expected: &[u8; 32], actual: &[u8; 32]) -> bool {
    let mut difference = 0_u8;
    for index in 0..32 {
        difference |= expected[index] ^ actual[index];
    }
    difference == 0
}

fn a0_workspace_root() -> Result<PathBuf, &'static str> {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .map(Path::to_path_buf)
        .ok_or("A0 workspace root is unavailable")
}

fn a0_bind_approved_runtime(
    revision: Option<&str>,
    expected_manifest: Option<&str>,
    workspace_root: &Path,
) -> Result<A0ApprovedRuntimeBinding, &'static str> {
    a0_strict_lower_hex::<20>(
        revision,
        "CHAT_G7_A0_APPROVED_REVISION must be 40 lowercase hexadecimal characters",
    )?;
    let expected = a0_strict_lower_hex::<32>(
        expected_manifest,
        "CHAT_G7_A0_APPROVED_MANIFEST_SHA256 must be 64 lowercase hexadecimal characters",
    )?;
    let mut manifest_fields = Vec::with_capacity(A0_APPROVED_PATHS.len());
    let mut files = Vec::with_capacity(A0_APPROVED_PATHS.len());
    for path in A0_APPROVED_PATHS {
        let complete_path = workspace_root.join(path);
        let file_bytes =
            std::fs::read(&complete_path).map_err(|_| "A0 approved manifest path is unreadable")?;
        let digest: [u8; 32] = Sha256::digest(&file_bytes).into();
        manifest_fields.push((path, digest));
        files.push(A0ApprovedFileDigest {
            path: path.to_owned(),
            sha256: hex::encode(digest),
        });
    }
    let canonical = a0_manifest_bytes(&manifest_fields)?;
    let actual: [u8; 32] = Sha256::digest(&canonical).into();
    if !a0_full_digest_match(&expected, &actual) {
        return Err("A0 approved eight-path manifest digest mismatch");
    }
    Ok(A0ApprovedRuntimeBinding {
        revision: revision
            .expect("validated A0 approved revision must remain present")
            .to_owned(),
        manifest_sha256: hex::encode(actual),
        files,
    })
}

fn a0_read_approved_runtime_binding() -> Result<A0ApprovedRuntimeBinding, &'static str> {
    let revision = std::env::var("CHAT_G7_A0_APPROVED_REVISION").ok();
    let manifest = std::env::var("CHAT_G7_A0_APPROVED_MANIFEST_SHA256").ok();
    let workspace_root = a0_workspace_root()?;
    a0_bind_approved_runtime(revision.as_deref(), manifest.as_deref(), &workspace_root)
}

#[derive(Clone, Debug, Deserialize)]
struct A0LegacyLedgerTransport {
    version: String,
    description: String,
    success: bool,
    checksum_hex: String,
}

#[derive(Clone, Debug, Deserialize)]
struct A0LegacyCatalogTransport {
    class: String,
    identity: String,
    definition: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct A0FingerprintDigests {
    row_count: usize,
    all_successful: bool,
    sha256: String,
    sha384: String,
}

fn a0_fingerprint_source_queries() -> Result<(&'static str, &'static str), &'static str> {
    if hex::encode(Sha256::digest(A0_FINGERPRINT_SQL_SOURCE.as_bytes()))
        != A0_FINGERPRINT_SQL_SHA256
        || hex::encode(Sha256::digest(A0_FINGERPRINT_MD_SOURCE.as_bytes()))
            != A0_FINGERPRINT_MD_SHA256
    {
        return Err("A0 reviewed fingerprint input hash mismatch");
    }
    let ledger_branch = A0_FINGERPRINT_SQL_SOURCE
        .split("\\if :{?ledger}\n")
        .nth(1)
        .and_then(|branch| branch.split("\n\\elif :{?catalog}\n").next())
        .ok_or("A0 reviewed ledger SQL branch is missing")?;
    let ledger_start = ledger_branch
        .find("SELECT jsonb_build_object(")
        .ok_or("A0 reviewed ledger query is missing")?;
    let ledger_end = ledger_branch[ledger_start..]
        .find("\n\nCOMMIT;")
        .map(|index| ledger_start + index)
        .ok_or("A0 reviewed ledger query terminator is missing")?;
    let catalog_branch = A0_FINGERPRINT_SQL_SOURCE
        .split("\n\\elif :{?catalog}\n")
        .nth(1)
        .and_then(|branch| branch.split("\n\\else\n").next())
        .ok_or("A0 reviewed catalog SQL branch is missing")?;
    let catalog_start = catalog_branch
        .find("WITH ns AS (")
        .ok_or("A0 reviewed catalog query is missing")?;
    let catalog_end = catalog_branch[catalog_start..]
        .find("\n\nCOMMIT;")
        .map(|index| catalog_start + index)
        .ok_or("A0 reviewed catalog query terminator is missing")?;
    Ok((
        &ledger_branch[ledger_start..ledger_end],
        &catalog_branch[catalog_start..catalog_end],
    ))
}

fn a0_serialize_legacy_ledger(
    transport_lines: &[String],
) -> Result<A0FingerprintDigests, &'static str> {
    let mut rows = transport_lines
        .iter()
        .map(|line| {
            serde_json::from_str::<A0LegacyLedgerTransport>(line)
                .map_err(|_| "A0 legacy ledger transport is not reviewed JSON")
        })
        .collect::<Result<Vec<_>, _>>()?;
    for row in &rows {
        let version = row
            .version
            .parse::<i64>()
            .map_err(|_| "A0 legacy ledger version is not canonical decimal")?;
        if version.to_string() != row.version
            || a0_strict_lower_hex::<48>(
                Some(&row.checksum_hex),
                "A0 legacy ledger checksum is not strict SHA-384",
            )
            .is_err()
        {
            return Err("A0 legacy ledger row shape mismatch");
        }
    }
    rows.sort_by_key(|row| row.version.parse::<i64>().expect("validated version"));
    if rows.len() != A0_LEGACY_LEDGER_56_MANIFEST.len() {
        return Err("A0 legacy ledger row count mismatch");
    }
    for (row, expected) in rows.iter().zip(A0_LEGACY_LEDGER_56_MANIFEST) {
        if row.version != expected.version.to_string()
            || row.description != expected.description
            || !row.success
            || row.checksum_hex != expected.checksum_sha384
        {
            return Err("A0 legacy ledger differs from the frozen 56-row manifest");
        }
    }
    let mut bytes = Vec::new();
    bytes.extend_from_slice(A0_LEGACY_LEDGER_DOMAIN);
    a0_push_u32(&mut bytes, rows.len())?;
    for row in &rows {
        a0_push_frame(&mut bytes, row.version.as_bytes())?;
        a0_push_frame(&mut bytes, row.description.as_bytes())?;
        a0_push_frame(&mut bytes, &[u8::from(row.success)])?;
        let checksum = a0_strict_lower_hex::<48>(
            Some(&row.checksum_hex),
            "A0 legacy ledger checksum is not strict SHA-384",
        )?;
        a0_push_frame(&mut bytes, &checksum)?;
    }
    Ok(A0FingerprintDigests {
        row_count: rows.len(),
        all_successful: rows.iter().all(|row| row.success),
        sha256: hex::encode(Sha256::digest(&bytes)),
        sha384: hex::encode(Sha384::digest(&bytes)),
    })
}

fn a0_serialize_legacy_catalog(
    transport_lines: &[String],
) -> Result<A0FingerprintDigests, &'static str> {
    let mut rows = transport_lines
        .iter()
        .map(|line| {
            serde_json::from_str::<A0LegacyCatalogTransport>(line)
                .map_err(|_| "A0 legacy catalog transport is not reviewed JSON")
        })
        .collect::<Result<Vec<_>, _>>()?;
    rows.sort_by(|left, right| {
        (
            left.class.as_bytes(),
            left.identity.as_bytes(),
            left.definition.as_bytes(),
        )
            .cmp(&(
                right.class.as_bytes(),
                right.identity.as_bytes(),
                right.definition.as_bytes(),
            ))
    });
    if rows.len() != 1_572 {
        return Err("A0 legacy catalog entry count mismatch");
    }
    let mut bytes = Vec::new();
    bytes.extend_from_slice(A0_LEGACY_CATALOG_DOMAIN);
    a0_push_u32(&mut bytes, rows.len())?;
    for row in &rows {
        a0_push_frame(&mut bytes, row.class.as_bytes())?;
        a0_push_frame(&mut bytes, row.identity.as_bytes())?;
        a0_push_frame(&mut bytes, row.definition.as_bytes())?;
    }
    Ok(A0FingerprintDigests {
        row_count: rows.len(),
        all_successful: true,
        sha256: hex::encode(Sha256::digest(&bytes)),
        sha384: hex::encode(Sha384::digest(&bytes)),
    })
}

async fn a0_read_legacy_fingerprint(
    connection: &mut PgConnection,
) -> Result<(A0FingerprintDigests, A0FingerprintDigests), String> {
    let (ledger_query, catalog_query) = a0_fingerprint_source_queries().map_err(str::to_owned)?;
    let mut transaction = connection
        .begin()
        .await
        .map_err(|error| format!("begin A0 fingerprint transaction: {error}"))?;
    sqlx::query("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY")
        .execute(&mut *transaction)
        .await
        .map_err(|error| format!("set A0 fingerprint isolation: {error}"))?;
    sqlx::query("SET LOCAL search_path TO pg_catalog")
        .execute(&mut *transaction)
        .await
        .map_err(|error| format!("set A0 fingerprint search path: {error}"))?;
    sqlx::query("SET LOCAL bytea_output TO hex")
        .execute(&mut *transaction)
        .await
        .map_err(|error| format!("set A0 fingerprint bytea output: {error}"))?;
    let ledger_transport: Vec<String> = sqlx::query_scalar(ledger_query)
        .fetch_all(&mut *transaction)
        .await
        .map_err(|error| format!("read A0 legacy ledger transport: {error}"))?;
    let catalog_transport: Vec<String> = sqlx::query_scalar(catalog_query)
        .fetch_all(&mut *transaction)
        .await
        .map_err(|error| format!("read A0 legacy catalog transport: {error}"))?;
    transaction
        .commit()
        .await
        .map_err(|error| format!("commit read-only A0 fingerprint transaction: {error}"))?;
    Ok((
        a0_serialize_legacy_ledger(&ledger_transport).map_err(str::to_owned)?,
        a0_serialize_legacy_catalog(&catalog_transport).map_err(str::to_owned)?,
    ))
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct A0LegacyFingerprintFacts {
    database_name: String,
    database_oid: u32,
    owner: String,
    current_role: String,
    server_address: String,
    server_port: u16,
    allow_connections: bool,
    role_can_create_database: bool,
    chat_schema_absent: bool,
    ledger_row_count: usize,
    ledger_all_successful: bool,
    ledger_sha256: String,
    ledger_sha384: String,
    catalog_sha256: String,
    catalog_sha384: String,
    exact13_overlap: usize,
    exact13_missing: usize,
    intent_absent: bool,
    consumed_absent: bool,
}

#[derive(Debug)]
struct A0LegacyForwardReconcileAuthority {
    expected_old_oid: u32,
    sealed_facts: A0LegacyFingerprintFacts,
}

fn a0_seal_legacy_forward_reconcile(
    facts: A0LegacyFingerprintFacts,
) -> Result<A0LegacyForwardReconcileAuthority, &'static str> {
    let exact = facts.database_name == TEST_DATABASE_NAME
        && facts.database_oid == A0_EXPECTED_LEGACY_OID
        && facts.owner == A0_EXACT_OWNER
        && facts.current_role == A0_EXACT_OWNER
        && facts.server_address == "127.0.0.1"
        && facts.server_port == 5432
        && facts.allow_connections
        && facts.role_can_create_database
        && facts.chat_schema_absent
        && facts.ledger_row_count == 56
        && facts.ledger_all_successful
        && facts.ledger_sha256 == A0_LEGACY_LEDGER_SHA256
        && facts.ledger_sha384 == A0_LEGACY_LEDGER_SHA384
        && facts.catalog_sha256 == A0_LEGACY_CATALOG_SHA256
        && facts.catalog_sha384 == A0_LEGACY_CATALOG_SHA384
        && facts.exact13_overlap == 0
        && facts.exact13_missing == 13
        && facts.intent_absent
        && facts.consumed_absent;
    if !exact {
        return Err("A0 legacy fingerprint mismatch; destructive authority denied");
    }
    Ok(A0LegacyForwardReconcileAuthority {
        expected_old_oid: A0_EXPECTED_LEGACY_OID,
        sealed_facts: facts,
    })
}

fn a0_revalidate_fenced_legacy(
    authority: &A0LegacyForwardReconcileAuthority,
    mut actual: A0LegacyFingerprintFacts,
) -> Result<(), &'static str> {
    if actual.allow_connections || !actual.intent_absent || actual.consumed_absent {
        return Err("A0 fenced legacy lifecycle facts are not false/absent/present");
    }
    actual.allow_connections = true;
    actual.consumed_absent = true;
    if actual != authority.sealed_facts {
        return Err("A0 fenced legacy fingerprint drift");
    }
    Ok(())
}

fn a0_connection_address_is_local(address: Option<&str>) -> bool {
    address.is_none_or(|address| matches!(address, "127.0.0.1" | "::1"))
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
struct A0MarkerPayload {
    database_name: String,
    expected_legacy_oid: u32,
    legacy_ledger_sha256: String,
    legacy_ledger_sha384: String,
    legacy_catalog_sha256: String,
    legacy_catalog_sha384: String,
    approved_revision: String,
    approved_manifest_sha256: String,
    approved_files: Vec<A0ApprovedFileDigest>,
    attempt_timestamp: DateTime<Utc>,
}

impl A0MarkerPayload {
    fn new(binding: &A0ApprovedRuntimeBinding, attempt_timestamp: DateTime<Utc>) -> Self {
        Self {
            database_name: TEST_DATABASE_NAME.to_owned(),
            expected_legacy_oid: A0_EXPECTED_LEGACY_OID,
            legacy_ledger_sha256: A0_LEGACY_LEDGER_SHA256.to_owned(),
            legacy_ledger_sha384: A0_LEGACY_LEDGER_SHA384.to_owned(),
            legacy_catalog_sha256: A0_LEGACY_CATALOG_SHA256.to_owned(),
            legacy_catalog_sha384: A0_LEGACY_CATALOG_SHA384.to_owned(),
            approved_revision: binding.revision.clone(),
            approved_manifest_sha256: binding.manifest_sha256.clone(),
            approved_files: binding.files.clone(),
            attempt_timestamp,
        }
    }

    fn canonical_bytes(&self) -> Vec<u8> {
        serde_json::to_vec(self).expect("serialize canonical A0 marker payload")
    }

    // Candidate-independent half: the fixed target and the compiled legacy
    // authority constants. Every candidate must satisfy this against any
    // marker, including one written by a superseded candidate.
    fn matches_legacy_constants(&self) -> bool {
        self.database_name == TEST_DATABASE_NAME
            && self.expected_legacy_oid == A0_EXPECTED_LEGACY_OID
            && self.legacy_ledger_sha256 == A0_LEGACY_LEDGER_SHA256
            && self.legacy_ledger_sha384 == A0_LEGACY_LEDGER_SHA384
            && self.legacy_catalog_sha256 == A0_LEGACY_CATALOG_SHA256
            && self.legacy_catalog_sha384 == A0_LEGACY_CATALOG_SHA384
    }

    // Candidate-dependent whole: only the candidate that wrote the marker can
    // satisfy this. It gates marker creation, never marker interpretation.
    fn matches_binding(&self, binding: &A0ApprovedRuntimeBinding) -> bool {
        self.matches_legacy_constants()
            && self.approved_revision == binding.revision
            && self.approved_manifest_sha256 == binding.manifest_sha256
            && self.approved_files == binding.files
    }
}

fn a0_sync_marker_parent(parent: &Path) -> std::io::Result<()> {
    File::open(parent)?.sync_all()
}

fn a0_validated_marker_parent() -> std::io::Result<PathBuf> {
    let expected = Path::new(A0_MARKER_PARENT);
    if !expected.is_absolute()
        || expected.join("a0-reconciliation.intent") != Path::new(A0_INTENT_PATH)
        || expected.join("a0-reconciliation-consumed.json") != Path::new(A0_CONSUMED_PATH)
    {
        return Err(std::io::Error::other("A0 marker literals are inconsistent"));
    }
    let mut inspected = PathBuf::from("/");
    for component in expected.components().skip(1) {
        inspected.push(component.as_os_str());
        let metadata = std::fs::symlink_metadata(&inspected)?;
        if metadata.file_type().is_symlink() || !metadata.is_dir() {
            return Err(std::io::Error::other(format!(
                "A0 marker parent component is not a real directory: {}",
                inspected.display()
            )));
        }
    }
    if expected.canonicalize()? != expected {
        return Err(std::io::Error::other(
            "A0 marker parent canonical identity mismatch",
        ));
    }
    Ok(expected.to_owned())
}

fn a0_read_consumed_marker() -> std::io::Result<Option<(A0MarkerPayload, Vec<u8>)>> {
    let parent = a0_validated_marker_parent()?;
    if Path::new(A0_INTENT_PATH).try_exists()? {
        return Err(std::io::Error::other(
            "A0 intent marker exists; prior attempt is incomplete or ambiguous",
        ));
    }
    let consumed = Path::new(A0_CONSUMED_PATH);
    if !consumed.try_exists()? {
        return Ok(None);
    }
    let metadata = std::fs::symlink_metadata(consumed)?;
    if metadata.file_type().is_symlink()
        || !metadata.is_file()
        || metadata.permissions().mode() & 0o777 != 0o600
        || consumed.parent() != Some(parent.as_path())
    {
        return Err(std::io::Error::other(
            "A0 consumed marker identity or mode mismatch",
        ));
    }
    let bytes = std::fs::read(consumed)?;
    let payload: A0MarkerPayload = serde_json::from_slice(&bytes)
        .map_err(|error| std::io::Error::new(std::io::ErrorKind::InvalidData, error))?;
    if payload.canonical_bytes() != bytes {
        return Err(std::io::Error::other(
            "A0 consumed marker is not canonical JSON",
        ));
    }
    Ok(Some((payload, bytes)))
}

struct A0DurablePreAlterIntent {
    parent: PathBuf,
}

impl A0DurablePreAlterIntent {
    fn create(payload: &A0MarkerPayload) -> std::io::Result<Self> {
        let parent = a0_validated_marker_parent()?;
        if Path::new(A0_INTENT_PATH).try_exists()? || Path::new(A0_CONSUMED_PATH).try_exists()? {
            return Err(std::io::Error::new(
                std::io::ErrorKind::AlreadyExists,
                "A0 marker already exists",
            ));
        }
        let bytes = payload.canonical_bytes();
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(A0_INTENT_PATH)?;
        let preparation = (|| -> std::io::Result<()> {
            file.write_all(&bytes)?;
            file.sync_all()?;
            let metadata = file.metadata()?;
            if metadata.permissions().mode() & 0o777 != 0o600 {
                return Err(std::io::Error::other("A0 intent mode is not 0600"));
            }
            a0_sync_marker_parent(&parent)
        })();
        if let Err(error) = preparation {
            drop(file);
            let removal =
                std::fs::remove_file(A0_INTENT_PATH).and_then(|()| a0_sync_marker_parent(&parent));
            return Err(std::io::Error::other(format!(
                "A0 pre-ALTER intent preparation failed: {error}; removal={removal:?}"
            )));
        }
        Ok(Self { parent })
    }

    fn remove_before_alter(self) -> std::io::Result<()> {
        std::fs::remove_file(A0_INTENT_PATH)?;
        a0_sync_marker_parent(&self.parent)
    }

    fn into_alter_attempted(self) -> A0AlterAttemptedIntent {
        A0AlterAttemptedIntent {
            parent: self.parent,
        }
    }
}

struct A0AlterAttemptedIntent {
    parent: PathBuf,
}

#[cfg(target_os = "macos")]
unsafe extern "C" {
    fn renamex_np(
        old_name: *const std::os::raw::c_char,
        new_name: *const std::os::raw::c_char,
        flags: u32,
    ) -> i32;
}

#[cfg(target_os = "linux")]
unsafe extern "C" {
    fn renameat2(
        old_directory: std::os::raw::c_int,
        old_name: *const std::os::raw::c_char,
        new_directory: std::os::raw::c_int,
        new_name: *const std::os::raw::c_char,
        flags: u32,
    ) -> std::os::raw::c_int;
}

#[cfg(not(any(target_os = "macos", target_os = "linux")))]
compile_error!("A0 durable no-replace promotion is reviewed only for macOS and Linux");

#[cfg(target_os = "macos")]
fn a0_rename_marker_no_replace(source: &CString, destination: &CString) -> std::io::Result<()> {
    const RENAME_EXCL: u32 = 0x0000_0004;
    // SAFETY: both C strings are NUL-terminated immutable literal paths and
    // RENAME_EXCL is the reviewed Darwin same-filesystem no-replace flag.
    let result = unsafe { renamex_np(source.as_ptr(), destination.as_ptr(), RENAME_EXCL) };
    if result == 0 {
        Ok(())
    } else {
        Err(std::io::Error::last_os_error())
    }
}

#[cfg(target_os = "linux")]
fn a0_rename_marker_no_replace(source: &CString, destination: &CString) -> std::io::Result<()> {
    const AT_FDCWD: std::os::raw::c_int = -100;
    const RENAME_NOREPLACE: u32 = 1;
    // SAFETY: both C strings are NUL-terminated immutable literal paths,
    // AT_FDCWD resolves those absolute paths directly, and RENAME_NOREPLACE
    // provides the Linux same-filesystem no-replace operation.
    let result = unsafe {
        renameat2(
            AT_FDCWD,
            source.as_ptr(),
            AT_FDCWD,
            destination.as_ptr(),
            RENAME_NOREPLACE,
        )
    };
    if result == 0 {
        Ok(())
    } else {
        Err(std::io::Error::last_os_error())
    }
}

impl A0AlterAttemptedIntent {
    fn promote_no_replace(self) -> std::io::Result<A0ConsumedMarker> {
        if Path::new(A0_CONSUMED_PATH).try_exists()? {
            return Err(std::io::Error::new(
                std::io::ErrorKind::AlreadyExists,
                "A0 consumed marker already exists",
            ));
        }
        let source = CString::new(Path::new(A0_INTENT_PATH).as_os_str().as_bytes())
            .expect("literal A0 intent path contains no NUL");
        let destination = CString::new(Path::new(A0_CONSUMED_PATH).as_os_str().as_bytes())
            .expect("literal A0 consumed path contains no NUL");
        a0_rename_marker_no_replace(&source, &destination)?;
        a0_sync_marker_parent(&self.parent)?;
        Ok(A0ConsumedMarker {
            parent: self.parent,
        })
    }
}

struct A0ConsumedMarker {
    parent: PathBuf,
}

impl A0ConsumedMarker {
    fn validate(&self, expected: &A0MarkerPayload) -> std::io::Result<Vec<u8>> {
        let (actual, bytes) = a0_read_consumed_marker()?
            .ok_or_else(|| std::io::Error::other("A0 consumed marker is missing"))?;
        if &actual != expected || Path::new(A0_CONSUMED_PATH).parent() != Some(&self.parent) {
            return Err(std::io::Error::other("A0 consumed marker payload drift"));
        }
        Ok(bytes)
    }
}

#[test]
fn a0_connection_preflight_is_fail_closed() {
    assert!(a0_connection_address_is_local(None));
    assert!(a0_connection_address_is_local(Some("127.0.0.1")));
    assert!(a0_connection_address_is_local(Some("::1")));
    assert!(!a0_connection_address_is_local(Some("10.0.0.9")));
}

fn a0_exact_legacy_fingerprint_facts() -> A0LegacyFingerprintFacts {
    A0LegacyFingerprintFacts {
        database_name: TEST_DATABASE_NAME.to_owned(),
        database_oid: A0_EXPECTED_LEGACY_OID,
        owner: A0_EXACT_OWNER.to_owned(),
        current_role: A0_EXACT_OWNER.to_owned(),
        server_address: "127.0.0.1".to_owned(),
        server_port: 5432,
        allow_connections: true,
        role_can_create_database: true,
        chat_schema_absent: true,
        ledger_row_count: 56,
        ledger_all_successful: true,
        ledger_sha256: A0_LEGACY_LEDGER_SHA256.to_owned(),
        ledger_sha384: A0_LEGACY_LEDGER_SHA384.to_owned(),
        catalog_sha256: A0_LEGACY_CATALOG_SHA256.to_owned(),
        catalog_sha384: A0_LEGACY_CATALOG_SHA384.to_owned(),
        exact13_overlap: 0,
        exact13_missing: 13,
        intent_absent: true,
        consumed_absent: true,
    }
}

#[test]
fn a0_legacy_forward_reconcile_classifier_rejects_every_drift_dimension() {
    let authority = a0_seal_legacy_forward_reconcile(a0_exact_legacy_fingerprint_facts()).unwrap();
    assert_eq!(authority.expected_old_oid, A0_EXPECTED_LEGACY_OID);
    let mut fenced = a0_exact_legacy_fingerprint_facts();
    fenced.allow_connections = false;
    fenced.consumed_absent = false;
    assert!(a0_revalidate_fenced_legacy(&authority, fenced.clone()).is_ok());
    fenced.catalog_sha256 = "00".repeat(32);
    assert!(a0_revalidate_fenced_legacy(&authority, fenced).is_err());

    macro_rules! reject_mutation {
        ($field:ident, $value:expr) => {{
            let mut facts = a0_exact_legacy_fingerprint_facts();
            facts.$field = $value;
            assert!(
                a0_seal_legacy_forward_reconcile(facts).is_err(),
                "A0 classifier accepted drift in {}",
                stringify!($field)
            );
        }};
    }

    reject_mutation!(database_name, "another_database".to_owned());
    reject_mutation!(database_oid, A0_EXPECTED_LEGACY_OID + 1);
    reject_mutation!(owner, "another_owner".to_owned());
    reject_mutation!(current_role, "another_role".to_owned());
    reject_mutation!(server_address, "::1".to_owned());
    reject_mutation!(server_port, 5433);
    reject_mutation!(allow_connections, false);
    reject_mutation!(role_can_create_database, false);
    reject_mutation!(chat_schema_absent, false);
    reject_mutation!(ledger_row_count, 55);
    reject_mutation!(ledger_all_successful, false);
    reject_mutation!(ledger_sha256, "00".repeat(32));
    reject_mutation!(ledger_sha384, "00".repeat(48));
    reject_mutation!(catalog_sha256, "00".repeat(32));
    reject_mutation!(catalog_sha384, "00".repeat(48));
    reject_mutation!(exact13_overlap, 1);
    reject_mutation!(exact13_missing, 12);
    reject_mutation!(intent_absent, false);
    reject_mutation!(consumed_absent, false);
}

#[test]
fn a0_legacy_fingerprint_serializer_matches_reviewed_v1_authority() {
    let ledger_transport = A0_LEGACY_LEDGER_56_MANIFEST
        .iter()
        .rev()
        .map(|entry| {
            serde_json::json!({
                "checksum_hex": entry.checksum_sha384,
                "success": true,
                "description": entry.description,
                "version": entry.version.to_string(),
            })
            .to_string()
        })
        .collect::<Vec<_>>();
    let ledger = a0_serialize_legacy_ledger(&ledger_transport).unwrap();
    assert_eq!(ledger.row_count, 56);
    assert!(ledger.all_successful);
    assert_eq!(ledger.sha256, A0_LEGACY_LEDGER_SHA256);
    assert_eq!(ledger.sha384, A0_LEGACY_LEDGER_SHA384);

    let (ledger_query, catalog_query) = a0_fingerprint_source_queries().unwrap();
    assert!(ledger_query.contains("FROM public._sqlx_migrations"));
    for required_surface in [
        "pg_database",
        "pg_db_role_setting",
        "pg_extension",
        "pg_sequence",
        "pg_enum",
        "pg_cast",
        "pg_policy",
        "pg_rewrite",
        "constraint_trigger",
        "pg_trigger",
        "datacl",
        "relacl",
        "attacl",
        "proacl",
        "typacl",
        "relrowsecurity",
        "relforcerowsecurity",
    ] {
        assert!(
            catalog_query.contains(required_surface),
            "reviewed A0 catalog query omitted {required_surface}"
        );
    }
    assert!(!catalog_query.contains("datallowconn"));
    assert!(A0_FINGERPRINT_MD_SOURCE.contains(A0_LEGACY_CATALOG_SHA256));
    assert!(A0_FINGERPRINT_MD_SOURCE.contains(A0_LEGACY_CATALOG_SHA384));
}

#[test]
fn a0_marker_payload_and_phase_types_are_fail_closed() {
    let timestamp = DateTime::parse_from_rfc3339("2026-07-29T12:34:56Z")
        .unwrap()
        .with_timezone(&Utc);
    let binding = A0ApprovedRuntimeBinding {
        revision: "a".repeat(40),
        manifest_sha256: "b".repeat(64),
        files: A0_APPROVED_PATHS
            .iter()
            .map(|path| A0ApprovedFileDigest {
                path: (*path).to_owned(),
                sha256: "c".repeat(64),
            })
            .collect(),
    };
    let payload = A0MarkerPayload::new(&binding, timestamp);
    let bytes = payload.canonical_bytes();
    assert_eq!(
        serde_json::from_slice::<A0MarkerPayload>(&bytes).unwrap(),
        payload
    );
    assert!(payload.matches_binding(&binding));
    let mut changed = binding.clone();
    changed.files[3].sha256 = "d".repeat(64);
    assert!(!payload.matches_binding(&changed));
    let schema_source = std::fs::read_to_string(
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests")
            .join("chat_protocol_schema.rs"),
    )
    .unwrap();
    let removal_method = ["fn remove_before_alter", "("].concat();
    assert_eq!(schema_source.matches(&removal_method).count(), 1);
    assert!(!schema_source
        .split("struct A0AlterAttemptedIntent")
        .nth(1)
        .expect("alter-attempted type")
        .split("struct A0ConsumedMarker")
        .next()
        .expect("alter-attempted implementation")
        .contains("remove_file"));
}

#[test]
fn a0_canonical_evidence_is_branch_stable_and_ordered() {
    let evidence = A0CanonicalEvidence {
        decision: "already_reconciled",
        material_deletion: false,
        pre_oid: 42,
        post_oid: 42,
        migrations_applied: 0,
        pre_ledger_sha256: "a".repeat(64),
        post_ledger_sha256: "a".repeat(64),
        pre_catalog_sha256: "b".repeat(64),
        post_catalog_sha256: "b".repeat(64),
        classified_legacy_count: 0,
        classified_legacy_set_sha256:
            "9261399e4289a8083ac006b4abb0191d2e2b13e7b8213b7292481f6559157530".to_owned(),
        marker_state: "absent",
        marker_sha256: None,
        approved_revision: "c".repeat(40),
        approved_manifest_sha256: "d".repeat(64),
        marker_legacy_ledger_sha256: None,
        marker_legacy_catalog_sha256: None,
        marker_approved_revision: None,
        marker_approved_manifest_sha256: None,
    };
    let canonical = evidence.canonical_json();
    assert_eq!(
        canonical,
        format!(
            concat!(
                "{{\"schema\":\"CATBIRD_G7_A0_EVIDENCE_V1\",",
                "\"decision\":\"already_reconciled\",",
                "\"material_deletion\":false,",
                "\"target_database\":\"catbird_chat_protocol_test_20260722\",",
                "\"pre_oid\":42,\"post_oid\":42,\"oid_changed\":false,",
                "\"migrations_applied\":0,",
                "\"pre_ledger_sha256\":\"{}\",",
                "\"post_ledger_sha256\":\"{}\",",
                "\"pre_catalog_sha256\":\"{}\",",
                "\"post_catalog_sha256\":\"{}\",",
                "\"classified_legacy_count\":0,",
                "\"classified_legacy_set_sha256\":",
                "\"9261399e4289a8083ac006b4abb0191d2e2b13e7b8213b7292481f6559157530\",",
                "\"lock_order\":\"20260729/700>20260729/701>sqlx\",",
                "\"marker_state\":\"absent\",\"marker_sha256\":null,",
                "\"approved_revision\":\"{}\",",
                "\"approved_manifest_sha256\":\"{}\"}}"
            ),
            "a".repeat(64),
            "a".repeat(64),
            "b".repeat(64),
            "b".repeat(64),
            "c".repeat(40),
            "d".repeat(64),
        )
    );
    assert!(!canonical.contains('\n'));
    assert!(!canonical.contains(": "));
    let parsed: serde_json::Value =
        serde_json::from_str(&canonical).expect("canonical A0 evidence is valid JSON");
    assert_eq!(parsed["oid_changed"], false);
    assert_eq!(parsed["marker_sha256"], serde_json::Value::Null);
    let source = std::fs::read_to_string(
        Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/chat_protocol_schema.rs"),
    )
    .expect("read A0 evidence source");
    let a0 = rust_function_body(
        &source,
        "forward_reconcile_exact_fingerprinted_legacy_local_chat_protocol_test_database",
    );
    assert_eq!(
        a0.matches("validate_durable_operation_claim_completeness")
            .count(),
        3,
        "all three A0 branches must call the shared durable validator"
    );
    assert_eq!(
        rust_code_projection(a0).matches(".emit()").count(),
        3,
        "the three exclusive A0 branches each need one final evidence emission"
    );
    assert!(!a0.contains("A0 decision=legacy_forward_reconcile"));
}

#[test]
fn a0_approved_runtime_binding_is_strict_and_domain_complete() {
    let known = [("alpha", [0_u8; 32]), ("\u{03b2}", [0xff_u8; 32])];
    assert_eq!(
        hex::encode(Sha256::digest(a0_manifest_bytes(&known).unwrap())),
        "e935397fa68679060c78b50025d627c275d85c0a29c088493a72b4605114b2a6"
    );
    assert_eq!(A0_APPROVED_PATHS.len(), 8);

    let directory = tempfile::tempdir().unwrap();
    for (index, path) in A0_APPROVED_PATHS.iter().enumerate() {
        let complete = directory.path().join(path);
        std::fs::create_dir_all(complete.parent().unwrap()).unwrap();
        std::fs::write(complete, [u8::try_from(index).unwrap(), 0xa5]).unwrap();
    }
    let manifest_fields = A0_APPROVED_PATHS
        .iter()
        .map(|path| {
            let digest: [u8; 32] =
                Sha256::digest(std::fs::read(directory.path().join(path)).unwrap()).into();
            (*path, digest)
        })
        .collect::<Vec<_>>();
    let expected = hex::encode(Sha256::digest(a0_manifest_bytes(&manifest_fields).unwrap()));
    let binding =
        a0_bind_approved_runtime(Some(&"a".repeat(40)), Some(&expected), directory.path()).unwrap();
    assert_eq!(binding.manifest_sha256, expected);
    assert_eq!(binding.files.len(), 8);

    for path in A0_APPROVED_PATHS {
        let complete = directory.path().join(path);
        let original = std::fs::read(&complete).unwrap();
        let mut changed = original.clone();
        changed[0] ^= 1;
        std::fs::write(&complete, &changed).unwrap();
        assert!(
            a0_bind_approved_runtime(
                Some(&"a".repeat(40)),
                Some(&binding.manifest_sha256),
                directory.path(),
            )
            .is_err(),
            "file-byte mutation was accepted for {path}"
        );
        std::fs::write(complete, original).unwrap();
    }
    let inaccessible_path = directory.path().join(A0_APPROVED_PATHS[0]);
    let inaccessible_bytes = std::fs::read(&inaccessible_path).unwrap();
    std::fs::remove_file(&inaccessible_path).unwrap();
    assert!(
        a0_bind_approved_runtime(
            Some(&"a".repeat(40)),
            Some(&binding.manifest_sha256),
            directory.path(),
        )
        .is_err(),
        "missing approved path was accepted"
    );
    std::fs::create_dir(&inaccessible_path).unwrap();
    assert!(
        a0_bind_approved_runtime(
            Some(&"a".repeat(40)),
            Some(&binding.manifest_sha256),
            directory.path(),
        )
        .is_err(),
        "unreadable approved path was accepted"
    );
    std::fs::remove_dir(&inaccessible_path).unwrap();
    std::fs::write(&inaccessible_path, inaccessible_bytes).unwrap();

    let original = manifest_fields.clone();
    let mut omitted = original.clone();
    omitted.remove(3);
    let mut added = original.clone();
    added.push(("server/unapproved", [9_u8; 32]));
    let mut reordered = original.clone();
    reordered.swap(2, 3);
    let mut renamed = original.clone();
    renamed[4].0 = "server/tests/common/renamed.rs";
    for changed in [&omitted, &added, &reordered, &renamed] {
        assert_ne!(
            Sha256::digest(a0_manifest_bytes(&original).unwrap()),
            Sha256::digest(a0_manifest_bytes(changed).unwrap())
        );
    }

    let uppercase_revision = "A".repeat(40);
    for revision in [
        None,
        Some(""),
        Some(uppercase_revision.as_str()),
        Some("abc"),
        Some("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"),
        Some("gggggggggggggggggggggggggggggggggggggggg"),
    ] {
        assert!(a0_bind_approved_runtime(
            revision,
            Some(&binding.manifest_sha256),
            directory.path()
        )
        .is_err());
    }
    let uppercase_digest = "A".repeat(64);
    for digest in [
        None,
        Some(""),
        Some(uppercase_digest.as_str()),
        Some("abc"),
        Some("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"),
        Some("gggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggg"),
    ] {
        assert!(a0_bind_approved_runtime(Some(&"a".repeat(40)), digest, directory.path()).is_err());
    }
    let actual: [u8; 32] = Sha256::digest(a0_manifest_bytes(&manifest_fields).unwrap()).into();
    assert!(a0_full_digest_match(&actual, &actual));
    for index in 0..32 {
        let mut changed = actual;
        changed[index] ^= 1;
        assert!(
            !a0_full_digest_match(&actual, &changed),
            "digest mismatch accepted at byte {index}"
        );
    }
}

#[test]
fn a0_approved_runtime_binding_source_guards() {
    let source = std::fs::read_to_string(
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests")
            .join("chat_protocol_schema.rs"),
    )
    .unwrap();
    for forbidden in [
        ["std::", "process"].concat(),
        ["Com", "mand"].concat(),
        ["\"j", "j\""].concat(),
    ] {
        assert!(
            !source.contains(&forbidden),
            "forbidden A0 shell seam: {forbidden}"
        );
    }
    let revision_name = ["CHAT_G7_A0_", "APPROVED_REVISION"].concat();
    let manifest_name = ["CHAT_G7_A0_", "APPROVED_MANIFEST_SHA256"].concat();
    assert_eq!(source.matches(&revision_name).count(), 2);
    assert_eq!(source.matches(&manifest_name).count(), 2);
    let reader = source
        .split("fn a0_read_approved_runtime_binding()")
        .nth(1)
        .unwrap()
        .split("\n}\n")
        .next()
        .unwrap();
    assert_eq!(reader.matches(&revision_name).count(), 1);
    assert_eq!(reader.matches(&manifest_name).count(), 1);
    let path_manifest_declaration = ["const A0_APPROVED_PATHS", ": [&str; 8]"].concat();
    assert_eq!(source.matches(&path_manifest_declaration).count(), 1);
    let comparator = source
        .split("fn a0_full_digest_match")
        .nth(1)
        .unwrap()
        .split("\n}\n")
        .next()
        .unwrap();
    assert!(comparator.contains("for index in 0..32"));
    assert!(comparator.contains("difference |="));
    assert!(!comparator.contains("return"));
    assert!(!comparator.contains("expected =="));
}

#[test]
fn a0_destructive_source_guards_are_closed() {
    let source = std::fs::read_to_string(
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests")
            .join("chat_protocol_schema.rs"),
    )
    .unwrap();
    let alter_literal = ["ALTER", " DATABASE ", "\""].concat();
    let drop_literal = ["DROP", " DATABASE ", "\""].concat();
    let create_literal = ["CREATE", " DATABASE ", "\""].concat();
    assert_eq!(source.matches(&alter_literal).count(), 2);
    assert_eq!(source.matches(&drop_literal).count(), 1);
    assert_eq!(source.matches(&create_literal).count(), 1);
    for statement in [
        "A0_DISABLE_CONNECTIONS_SQL",
        "A0_RESTORE_CONNECTIONS_SQL",
        "A0_DROP_DATABASE_SQL",
        "A0_CREATE_DATABASE_SQL",
    ] {
        assert_eq!(
            source.matches(statement).count(),
            3,
            "A0 static statement must have one declaration, one guard-list entry, and one use"
        );
    }
    let destructive = source
        .rsplit(
            "async fn forward_reconcile_exact_fingerprinted_legacy_local_chat_protocol_test_database",
        )
        .next()
        .unwrap()
        .split("async fn fresh_pool()")
        .next()
        .unwrap();
    for forbidden in [
        "pg_terminate_backend".to_owned(),
        "DROP DATABASE IF EXISTS".to_owned(),
        "CREATE DATABASE IF NOT EXISTS".to_owned(),
        ["DELETE FROM public.", "_sqlx_migrations"].concat(),
        ["INSERT INTO public.", "_sqlx_migrations"].concat(),
        ["UPDATE public.", "_sqlx_migrations"].concat(),
        "sqlx::query(&format".to_owned(),
        "sqlx::query(format".to_owned(),
    ] {
        assert!(
            !destructive.contains(&forbidden),
            "forbidden A0 authority seam: {forbidden}"
        );
    }
    assert!(destructive.contains("A0_EXPECTED_LEGACY_OID"));
    let classifier = source
        .split("fn a0_seal_legacy_forward_reconcile")
        .nth(1)
        .unwrap()
        .split("\n}\n")
        .next()
        .unwrap();
    assert!(classifier.contains("facts.database_oid == A0_EXPECTED_LEGACY_OID"));
    assert!(classifier.contains("expected_old_oid: A0_EXPECTED_LEGACY_OID"));
    assert!(source.contains("renamex_np(source.as_ptr(), destination.as_ptr(), RENAME_EXCL)"));
    assert!(source.contains("renameat2("));
    assert!(source.contains("RENAME_NOREPLACE"));
    assert!(source.contains(
        "compile_error!(\"A0 durable no-replace promotion is reviewed only for macOS and Linux\")"
    ));
    assert!(source.contains(".create_new(true)"));
    assert!(source.contains(".mode(0o600)"));
    assert!(source.contains("file.sync_all()?"));
    assert!(source.contains("a0_sync_marker_parent(&self.parent)?"));
    assert_eq!(A0_ADMIN_LOCK_OBJECT, 700);
    assert_eq!(A0_TARGET_LOCK_OBJECT, 701);

    let replacement = destructive
        .split("let mut replacement = PgConnection::connect(A0_EXACT_DATABASE_URL)")
        .nth(1)
        .expect("A0 replacement phase");
    assert!(
        replacement.find("a0_assert_lock(").unwrap()
            < replacement.find("a0_read_target_identity(").unwrap(),
        "A0 must reacquire target lock 701 before trusting replacement identity"
    );
    for complete_surface in [
        "a0_assert_post_clean_authority_surfaces",
        "relation.relkind IN ('v','m','f','p')",
        "type_row.typrelid=0",
        "FROM pg_policy policy",
        "FROM pg_rewrite rewrite",
        "trigger_row.tgisinternal",
        "relation.relrowsecurity",
        "relation.relreplident <> 'd'",
        "attribute.attacl IS NOT NULL",
        "procedure.proacl IS NULL",
        "privilege.grantee=0",
        "sequence_ownership",
        "public_owner, public_acl",
        "pg_database_owner|CREATE|pg_database_owner|false",
        "_sqlx_migrations_pkey",
        "public_ledger_triggers",
        "public_ledger_rules",
        "public_ledger_policies",
        "pg_get_triggerdef(trigger_row.oid,false)",
        "pg_get_ruledef(rewrite.oid,true)",
        "policy.polroles",
        "extension.extversion",
        "extension_member_authority_violations",
        "trigger_row.tgtype=5",
        "RI_FKey_check_ins",
        "unique_key_recheck",
        "invalid_internal_trigger_semantics",
        "expected_roles AS",
        "observed_roles AS",
        "EXCEPT ALL",
        "missing_internal_trigger_roles",
        "procedure_namespace.nspname <> 'pg_catalog'",
        "procedure.prorettype <> 'trigger'::regtype",
        "post_clean_public_ledger_attached_object_mutations_fail_closed",
        "a0_classify_public_ledger_closed_catalog",
        "PublicLedgerClosedCatalogError::Drift",
        "assert_expected_public_ledger_drift",
        "CREATE TRIGGER a0_unapproved_ledger_trigger",
        "CREATE RULE a0_unapproved_ledger_rule",
        "CREATE POLICY a0_unapproved_ledger_policy",
        "ENABLE ROW LEVEL SECURITY",
    ] {
        assert!(
            source.contains(complete_surface),
            "A0 post-clean authority omitted {complete_surface}"
        );
    }
    let public_mutation_helper = source
        .rsplit("async fn assert_public_ledger_mutation_rejected(")
        .next()
        .expect("public-ledger mutation helper")
        .split("\n}\n\n#[tokio::test]")
        .next()
        .expect("bounded public-ledger mutation helper");
    assert_eq!(
        public_mutation_helper
            .matches("a0_assert_post_clean_authority_surfaces")
            .count(),
        2,
        "public-ledger mutation helper must establish full clean pre/post baselines"
    );
    for required in [
        "SAVEPOINT unapproved_public_catalog",
        "a0_classify_public_ledger_closed_catalog",
        "PublicLedgerClosedCatalogError::Drift",
        "assert_expected_public_ledger_drift",
        "ROLLBACK TO SAVEPOINT unapproved_public_catalog",
        "RELEASE SAVEPOINT unapproved_public_catalog",
        "query failure cannot satisfy",
    ] {
        assert!(
            public_mutation_helper.contains(required),
            "public-ledger mutation helper omitted causal guard: {required}"
        );
    }
    for forbidden in [
        ["catch_", "unwind"].concat(),
        ["Assert", "UnwindSafe"].concat(),
        ["rejected", ".is_err()"].concat(),
    ] {
        assert!(
            !public_mutation_helper.contains(&forbidden),
            "public-ledger mutation helper retained an any-error oracle: {forbidden}"
        );
    }
    let public_mutation_classifier = source
        .rsplit("fn assert_expected_public_ledger_drift(")
        .next()
        .expect("public-ledger mutation classifier")
        .split("\n}\n\nasync fn assert_public_ledger_mutation_rejected(")
        .next()
        .expect("bounded public-ledger mutation classifier");
    for required in [
        "triggers.len(),\n                1",
        "public.a0_unapproved_ledger_trigger()",
        "CREATE TRIGGER a0_unapproved_ledger_trigger",
        "rules.len(),\n                1",
        "a0_unapproved_ledger_rule",
        "policies.len(),\n                1",
        "a0_unapproved_ledger_policy",
        "enabled && !forced",
    ] {
        assert!(
            public_mutation_classifier.contains(required),
            "public-ledger mutation classifier omitted positive observation: {required}"
        );
    }
    let public_mutation_test = source
        .rsplit("async fn post_clean_public_ledger_attached_object_mutations_fail_closed()")
        .next()
        .expect("public-ledger mutation test")
        .split("\n}\n\n#[tokio::test]")
        .next()
        .expect("bounded public-ledger mutation test");
    for required in [
        "let mut transaction = pool",
        ".begin()",
        "&mut transaction",
        ".rollback()",
        "PublicLedgerMutationExpectation::AttachedTrigger",
        "PublicLedgerMutationExpectation::AttachedRewriteRule",
        "PublicLedgerMutationExpectation::AttachedPolicy",
        "PublicLedgerMutationExpectation::RowLevelSecurity",
    ] {
        assert!(
            public_mutation_test.contains(required),
            "public-ledger mutation test omitted transaction/observation guard: {required}"
        );
    }
    let expected_includes = expected_populated_upgrade_source_includes();
    validate_closed_complete_source_authority(&source, &expected_includes)
        .expect("closed complete-source authority");

    let projected_compact: String = rust_code_projection(&source)
        .chars()
        .filter(|character| !character.is_ascii_whitespace())
        .collect();
    let runtime_migrator = ["Migrator::", "new("].concat();
    assert!(
        !projected_compact.contains(&runtime_migrator),
        "unreviewed runtime migration seam: {runtime_migrator}"
    );
    let complete_source_sink = ["sqlx::", "raw_sql("].concat();
    assert_eq!(
        projected_compact.matches(&complete_source_sink).count(),
        2,
        "the populated proof owns the only two complete-source execution seams"
    );
}

const CORE_TABLES: [&str; 23] = [
    "conversations",
    "device_keys",
    "device_revocations",
    "devices",
    "dpop_replays",
    "generation_states",
    "generations",
    "idempotency_records",
    "key_package_reservations",
    "key_packages",
    "leaf_recovery_requests",
    "leave_requests",
    "member_devices",
    "metadata_snapshots",
    "participants",
    "principals",
    "protocol_instances",
    "relationship_projection_declarations",
    "relationship_projection_relationships",
    "relationship_projection_revision_allocations",
    "relationship_projection_snapshots",
    "reset_requests",
    "transitions",
];

const DELIVERY_TABLES: [&str; 20] = [
    "application_intervals",
    "application_schedule_terminal_proofs",
    "device_inventory_items",
    "device_inventory_sessions",
    "entries",
    "entry_recipients",
    "event_recipients",
    "event_retention",
    "events",
    "inventory_conversation_items",
    "inventory_recovery_items",
    "inventory_sessions",
    "inventory_welcome_items",
    "message_sends",
    "outbox",
    "recovery_work_items",
    "subscription_tickets",
    "welcome_bundles",
    "welcome_deliveries",
    "welcome_dispositions",
];

const BLOB_TABLES: [&str; 4] = [
    "blob_bindings",
    "blob_upload_tickets",
    "blob_usage",
    "blobs",
];

const OPERATION_CLAIM_TABLES: [&str; 1] = ["operation_claims"];
const OPERATION_CLAIM_COMPLETENESS_TABLES: [&str; 1] = ["operation_claim_completeness_cutover"];
const G7_INVENTORY_TABLES: [&str; 2] = ["event_cursor_receipts", "inventory_page_receipts"];
const SERVICE_AUTH_TABLES: [&str; 1] = ["service_auth_admissions"];
const FEDERATION_RECEIPT_TABLES: [&str; 1] = ["federation_delivery_receipts"];
const PUBLIC_FEDERATION_TRANSPORT_RELATIONS: &[&str] = &[
    "federation_outbox",
    "federation_outbox_pkey",
    "federation_sync_state",
    "federation_sync_state_pkey",
    "idx_federation_outbox_due_v2",
    "idx_federation_outbox_lease",
    "outbound_queue",
    "outbound_queue_pkey",
    "idx_outbound_queue_due_v2",
    "idx_outbound_queue_lease",
];

fn expected_tables() -> BTreeSet<String> {
    CORE_TABLES
        .iter()
        .chain(DELIVERY_TABLES.iter())
        .chain(BLOB_TABLES.iter())
        .chain(OPERATION_CLAIM_TABLES.iter())
        .chain(OPERATION_CLAIM_COMPLETENESS_TABLES.iter())
        .chain(G7_INVENTORY_TABLES.iter())
        .chain(SERVICE_AUTH_TABLES.iter())
        .chain(FEDERATION_RECEIPT_TABLES.iter())
        .map(|name| (*name).to_owned())
        .collect()
}

fn migration_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("migrations")
}

#[test]
fn clean_chat_migration_inventory_orders_g7_entitlement_last() {
    assert_eq!(
        MIGRATION_VERSIONS.len(),
        MIGRATION_FILES.len(),
        "every migration version needs one exact file"
    );
    assert_eq!(
        MIGRATION_VERSIONS.len(),
        MIGRATION_DESCRIPTIONS.len(),
        "every migration version needs one SQLx description"
    );
    assert!(
        MIGRATION_VERSIONS.windows(2).all(|pair| pair[0] < pair[1]),
        "migration versions must remain strictly increasing"
    );
    assert_eq!(MIGRATION_VERSIONS.last(), Some(&20260824000005));
    assert_eq!(
        MIGRATION_FILES.last(),
        Some(&"20260824000005_chat_federation_outbox_retry.sql")
    );
    assert_eq!(
        MIGRATION_DESCRIPTIONS.last(),
        Some(&"chat federation outbox retry")
    );
    for file in MIGRATION_FILES.iter().copied() {
        assert!(
            migration_dir().join(file).is_file(),
            "missing migration inventory file: {file}"
        );
    }
    for entry in crate::common::chat_protocol::CLEAN_PROTOCOL_13_MANIFEST.iter() {
        let bytes = std::fs::read(migration_dir().join(entry.filename))
            .unwrap_or_else(|error| panic!("read reviewed migration {}: {error}", entry.filename));
        assert_eq!(
            hex::encode(Sha384::digest(&bytes)),
            entry.reviewed_sha384,
            "reviewed migration source hash drift: {}",
            entry.filename
        );
        assert_eq!(
            hex::encode(entry.migration.checksum.as_ref()),
            entry.reviewed_sha384,
            "constructed migration checksum drift: {}",
            entry.filename
        );
    }

    let activation_migration = std::fs::read(
        migration_dir().join("20260728000004_activate_operation_claim_completeness.sql"),
    )
    .expect("read operation-claim activation migration");
    let reviewed_activation_source = std::fs::read(
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("docs")
            .join("operation_claim_completeness_activation.sql"),
    )
    .expect("read reviewed operation-claim activation source");
    assert_eq!(
        activation_migration, reviewed_activation_source,
        "migration 00004 must remain byte-for-byte identical to its reviewed source"
    );
    let activation_sha384 = hex::encode(Sha384::digest(&activation_migration));
    assert_eq!(
        activation_sha384, OPERATION_CLAIM_00004_REPAIRED_SHA384,
        "migration 00004 repaired bytes require an explicit lineage reseal"
    );
    assert_ne!(
        activation_sha384, OPERATION_CLAIM_00004_PRE_REPAIR_SHA384,
        "the populated-upgrade repair must not masquerade as the old Task-9 checksum"
    );
    let migration_readme =
        std::fs::read_to_string(migration_dir().join("README.md")).expect("read migration README");
    for lineage_evidence in [
        OPERATION_CLAIM_00004_PRE_REPAIR_SHA384,
        OPERATION_CLAIM_00004_REPAIRED_SHA384,
        "No deployed reset action",
        "do not delete or rewrite any deployed",
        "no remote database was touched",
    ] {
        assert!(
            migration_readme.contains(lineage_evidence),
            "migration README is missing explicit 00004 lineage evidence: {lineage_evidence}"
        );
    }
}

#[tokio::test]
async fn fixed_target_helper_uses_one_closed_exact13_migrator_and_unchanged_api() {
    fn rust_sources(path: &Path, files: &mut Vec<PathBuf>) {
        for entry in std::fs::read_dir(path).expect("read integration-test source directory") {
            let path = entry.expect("read integration-test source entry").path();
            if path.is_dir() {
                rust_sources(&path, files);
            } else if path.extension().and_then(|extension| extension.to_str()) == Some("rs") {
                files.push(path);
            }
        }
    }

    let common_path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("common")
        .join("chat_protocol.rs");
    let schema_path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("chat_protocol_schema.rs");
    let g7_schema_path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("chat_protocol_g7_schema.rs");
    let common_source = std::fs::read_to_string(&common_path).expect("read common database helper");
    let schema_source = std::fs::read_to_string(&schema_path).expect("read schema test source");
    let g7_schema_source =
        std::fs::read_to_string(&g7_schema_path).expect("read G7 schema test source");
    let caller_needle = ["setup_chat_protocol_db", "("].concat();
    let schema_amendment_3_occurrences = [
        [
            ".split(\"pub async fn setup_chat_protocol_db",
            "(max_connections: u32) -> PgPool\")",
        ]
        .concat(),
        [
            "fresh_pool.contains(\"setup_chat_protocol_db",
            "(1).await\")",
        ]
        .concat(),
        [
            "g7.contains(\"let pool = common::chat_protocol::setup_chat_protocol_db",
            "(1).await;\")",
        ]
        .concat(),
        [
            "crate::common::chat_protocol::setup_chat_protocol_db",
            "(1).await",
        ]
        .concat(),
    ];
    for occurrence in &schema_amendment_3_occurrences {
        assert_eq!(
            schema_source.matches(occurrence).count(),
            1,
            "schema Amendment-3 setup call/guard inventory drift: {occurrence}"
        );
    }
    assert_eq!(
        schema_source.matches(&caller_needle).count(),
        schema_amendment_3_occurrences.len(),
        "schema target contains an unreviewed setup occurrence"
    );
    let g7_amendment_3_call = [
        "let pool = common::chat_protocol::setup_chat_protocol_db",
        "(1).await;",
    ]
    .concat();
    assert_eq!(
        g7_schema_source.matches(&g7_amendment_3_call).count(),
        3,
        "G7 schema Amendment-3 setup-call inventory drift"
    );
    assert_eq!(
        g7_schema_source.matches(&caller_needle).count(),
        3,
        "G7 schema target contains an unreviewed setup occurrence"
    );
    assert!(
        common_source.contains(concat!(
            "pub async fn setup_chat_protocol_db",
            "(max_connections: u32) -> PgPool"
        )),
        "fixed-target helper API changed"
    );
    assert_eq!(
        common_source
            .matches("pub static CLEAN_PROTOCOL_13_MANIFEST")
            .count(),
        1,
        "the common helper must define one canonical manifest"
    );
    assert_eq!(
        common_source
            .matches("pub struct CleanProtocol13MigrationSource")
            .count(),
        1,
        "the common helper must define one exact migration source"
    );
    assert_eq!(
        common_source
            .matches("pub async fn reviewed_clean_protocol_migrator()")
            .count(),
        1,
        "the common helper must define one reviewed migrator factory"
    );
    let whole_directory_macro = ["sqlx::migrate", "!"].concat();
    let path_migrator = ["Migrator::new", "(Path"].concat();
    let directory_migrator = ["Migrator::new", "(migration_dir"].concat();
    let literal_directory_migrator = ["Migrator::new", "(\"./migrations"].concat();
    for source in [&common_source, &schema_source] {
        assert!(
            !source.contains(&whole_directory_macro),
            "whole-directory SQLx migrator is forbidden in the fixed-target helper/A0 path"
        );
        assert!(
            !source.contains(&path_migrator)
                && !source.contains(&directory_migrator)
                && !source.contains(&literal_directory_migrator),
            "filesystem-directory migrator is forbidden in the fixed-target helper/A0 path"
        );
    }
    assert!(
        common_source
            .matches("reviewed_clean_protocol_migrator()")
            .count()
            >= 2,
        "the helper must invoke its sole reviewed migrator factory"
    );
    assert!(
        schema_source.contains(
            "forward_reconcile_exact_fingerprinted_legacy_local_chat_protocol_test_database"
        ) && schema_source
            .matches("reviewed_clean_protocol_migrator()")
            .count()
            >= 2,
        "A0 and schema setup must reuse the common reviewed migrator factory"
    );

    let mut sources = Vec::new();
    rust_sources(
        &Path::new(env!("CARGO_MANIFEST_DIR")).join("tests"),
        &mut sources,
    );
    let mut caller_targets = BTreeSet::new();
    let mut caller_occurrences = 0_usize;
    for path in sources {
        let source = std::fs::read_to_string(&path)
            .unwrap_or_else(|error| panic!("read {}: {error}", path.display()));
        let occurrences = source.matches(&caller_needle).count();
        caller_occurrences += occurrences;
        if occurrences > 0 && path != common_path && path != schema_path && path != g7_schema_path {
            caller_targets.insert(
                path.file_stem()
                    .and_then(|stem| stem.to_str())
                    .expect("UTF-8 integration-test target")
                    .to_owned(),
            );
        }
    }
    // Re-derived after the Task-4 federation-route/delivery-receipt tests landed:
    // the post-Task-4 tree has 259 setup calls. Four occurrences in this schema
    // and three in the G7 schema are the authorized Amendment-3 calls, leaving
    // 252 other fixed-target calls. This inventory catches unreviewed drift in
    // which tests depend on the shared database.
    assert_eq!(
        caller_occurrences, 259,
        "fixed-target setup caller inventory changed"
    );
    assert_eq!(
        caller_occurrences
            .checked_sub(schema_amendment_3_occurrences.len() + 3)
            .expect("Amendment-3 setup delta cannot exceed the closed inventory"),
        252,
        "the seven authorized Amendment-3 occurrences must be the only inventory delta"
    );
    let expected_targets: BTreeSet<String> = [
        "chat_protocol_blobs",
        "chat_protocol_concurrency",
        "chat_protocol_conversation_substrate",
        "chat_protocol_create_conversation_handlers",
        "chat_protocol_create_conversation_regression",
        "chat_protocol_delivery",
        "chat_protocol_delivery_read",
        "chat_protocol_device_directory",
        "chat_protocol_device_handlers",
        "chat_protocol_inventory",
        "chat_protocol_key_packages",
        "chat_protocol_operation_claims",
        "chat_protocol_production_cfg",
        "chat_protocol_relationship_repository",
        "chat_protocol_rollback",
        "chat_protocol_s3_lifecycle",
        "chat_protocol_ticket",
        "chat_protocol_transition_repository",
        "chat_protocol_welcome",
    ]
    .into_iter()
    .map(str::to_owned)
    .collect();
    assert_eq!(
        caller_targets, expected_targets,
        "fixed-target compatibility-matrix target inventory changed"
    );

    let migrator = crate::common::chat_protocol::reviewed_clean_protocol_migrator()
        .await
        .expect("construct reviewed exact-13 migrator");
    assert_eq!(migrator.iter().count(), 23);
    assert!(!migrator.ignore_missing);
    assert!(migrator.locking);
}

#[test]
fn fixed_target_url_validation_accepts_only_exact_literal_authority() {
    const EXACT: &str = "postgresql://127.0.0.1:5432/catbird_chat_protocol_test_20260722";
    assert_eq!(
        crate::common::chat_protocol::validate_chat_protocol_database_url(Some(EXACT)),
        Ok("catbird_chat_protocol_test_20260722")
    );
    for rejected in [
        None,
        Some(""),
        Some("postgres://127.0.0.1:5432/catbird_chat_protocol_test_20260722"),
        Some("postgresql://localhost:5432/catbird_chat_protocol_test_20260722"),
        Some("postgresql://[::1]:5432/catbird_chat_protocol_test_20260722"),
        Some("postgresql:///catbird_chat_protocol_test_20260722"),
        Some("postgresql://127.0.0.1/catbird_chat_protocol_test_20260722"),
        Some("postgresql://127.0.0.1:5433/catbird_chat_protocol_test_20260722"),
        Some("postgresql://user@127.0.0.1:5432/catbird_chat_protocol_test_20260722"),
        Some("postgresql://user:password@127.0.0.1:5432/catbird_chat_protocol_test_20260722"),
        Some("postgresql://127.0.0.1:5432/catbird_chat_protocol_test_20260722?sslmode=disable"),
        Some("postgresql://127.0.0.1:5432/catbird_chat_protocol_test_20260722#fragment"),
        Some("postgresql://127.0.0.1:5432/catbird_chat_protocol_test_20260722/"),
        Some("POSTGRESQL://127.0.0.1:5432/catbird_chat_protocol_test_20260722"),
        Some("postgresql://LOCALHOST:5432/catbird_chat_protocol_test_20260722"),
        Some("postgresql://127.0.0.1:5432/catbird%5fchat_protocol_test_20260722"),
        Some("postgresql://127.0.0.1:5432/postgres"),
        Some(" postgresql://127.0.0.1:5432/catbird_chat_protocol_test_20260722"),
        Some("postgresql://127.0.0.1:5432/catbird_chat_protocol_test_20260722 "),
        Some("postgresql://127.0.0.1:5432/catbird_chat_protocol_test_2026 0722"),
        Some("postgresql://127.0.0.1:5432/catbird_chat_protocol_test_2026%200722"),
    ] {
        assert!(
            crate::common::chat_protocol::validate_chat_protocol_database_url(rejected).is_err(),
            "nonliteral fixed-target URL was accepted: {rejected:?}"
        );
    }

    let common_source = std::fs::read_to_string(
        Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/common/chat_protocol.rs"),
    )
    .expect("read common fixed-target helper");
    let validator = common_source
        .split("pub fn validate_chat_protocol_database_url(")
        .nth(1)
        .expect("literal fixed-target validator")
        .split("\n}\n\n#[derive(Clone, Debug, Eq, PartialEq)]")
        .next()
        .expect("bounded literal fixed-target validator");
    assert!(validator.contains("Some(CHAT_PROTOCOL_TEST_DATABASE_URL)"));
    assert!(common_source.contains("pub const CHAT_PROTOCOL_TEST_DATABASE_URL: &str ="));
    assert!(common_source
        .contains("\"postgresql://127.0.0.1:5432/catbird_chat_protocol_test_20260722\";"));
    for forbidden in [
        "Url::",
        ".parse(",
        ".host_str(",
        ".scheme(",
        "localhost",
        "::1",
    ] {
        assert!(
            !validator.contains(forbidden),
            "literal fixed-target validator retained parser/alias logic: {forbidden}"
        );
    }
}

fn rust_code_projection(source: &str) -> String {
    let bytes = source.as_bytes();
    let mut projected = bytes.to_vec();
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index..].starts_with(b"//") {
            let end = bytes[index..]
                .iter()
                .position(|byte| *byte == b'\n')
                .map(|offset| index + offset)
                .unwrap_or(bytes.len());
            for byte in &mut projected[index..end] {
                *byte = b' ';
            }
            index = end;
            continue;
        }
        if bytes[index..].starts_with(b"/*") {
            let start = index;
            let mut depth = 1_usize;
            index += 2;
            while index < bytes.len() && depth != 0 {
                if bytes[index..].starts_with(b"/*") {
                    depth += 1;
                    index += 2;
                } else if bytes[index..].starts_with(b"*/") {
                    depth -= 1;
                    index += 2;
                } else {
                    index += 1;
                }
            }
            for byte in &mut projected[start..index] {
                if *byte != b'\n' {
                    *byte = b' ';
                }
            }
            continue;
        }

        let raw_prefix = if bytes[index] == b'r' {
            Some(index + 1)
        } else if bytes[index..].starts_with(b"br") {
            Some(index + 2)
        } else {
            None
        };
        if let Some(mut quote) = raw_prefix {
            while quote < bytes.len() && bytes[quote] == b'#' {
                quote += 1;
            }
            if quote < bytes.len() && bytes[quote] == b'"' {
                let hashes = quote - raw_prefix.expect("raw prefix exists");
                let start = index;
                index = quote + 1;
                while index < bytes.len() {
                    if bytes[index] == b'"'
                        && index + 1 + hashes <= bytes.len()
                        && bytes[index + 1..index + 1 + hashes]
                            .iter()
                            .all(|byte| *byte == b'#')
                    {
                        index += 1 + hashes;
                        break;
                    }
                    index += 1;
                }
                for byte in &mut projected[start..index] {
                    if *byte != b'\n' {
                        *byte = b' ';
                    }
                }
                continue;
            }
        }

        if bytes[index] == b'"' {
            let start = index;
            index += 1;
            while index < bytes.len() {
                if bytes[index] == b'\\' {
                    index = (index + 2).min(bytes.len());
                } else if bytes[index] == b'"' {
                    index += 1;
                    break;
                } else {
                    index += 1;
                }
            }
            for byte in &mut projected[start..index] {
                if *byte != b'\n' {
                    *byte = b' ';
                }
            }
            continue;
        }

        if bytes[index] == b'\'' {
            let candidate_end = bytes[index + 1..bytes.len().min(index + 12)]
                .iter()
                .position(|byte| *byte == b'\'')
                .map(|offset| index + 1 + offset);
            if let Some(end) = candidate_end {
                let start = index;
                index = end + 1;
                for byte in &mut projected[start..index] {
                    *byte = b' ';
                }
                continue;
            }
        }
        index += 1;
    }
    String::from_utf8(projected).expect("Rust source projection remains UTF-8")
}

fn rust_macro_invocations(source: &str, macro_name: &str) -> Vec<String> {
    let projected = rust_code_projection(source);
    let bytes = projected.as_bytes();
    let mut invocations = Vec::new();
    for (start, _) in projected.match_indices(macro_name) {
        let identifier_start = start == 0
            || !bytes[start - 1].is_ascii_alphanumeric()
                && bytes[start - 1] != b'_'
                && bytes[start - 1] != b':';
        let mut cursor = start + macro_name.len();
        let identifier_end = bytes
            .get(cursor)
            .is_none_or(|byte| !byte.is_ascii_alphanumeric() && *byte != b'_');
        if !identifier_start || !identifier_end {
            continue;
        }
        while bytes.get(cursor).is_some_and(u8::is_ascii_whitespace) {
            cursor += 1;
        }
        if bytes.get(cursor) != Some(&b'!') {
            continue;
        }
        cursor += 1;
        while bytes.get(cursor).is_some_and(u8::is_ascii_whitespace) {
            cursor += 1;
        }
        let first_close = match bytes.get(cursor) {
            Some(b'(') => b')',
            Some(b'[') => b']',
            Some(b'{') => b'}',
            _ => continue,
        };
        let mut delimiter_stack = vec![first_close];
        let mut end = None;
        let mut nested = cursor + 1;
        while nested < bytes.len() {
            match bytes[nested] {
                b'(' => delimiter_stack.push(b')'),
                b'[' => delimiter_stack.push(b']'),
                b'{' => delimiter_stack.push(b'}'),
                b')' | b']' | b'}' => {
                    let expected = delimiter_stack
                        .pop()
                        .expect("macro invocation delimiter stack");
                    assert_eq!(
                        bytes[nested], expected,
                        "mismatched delimiter in {macro_name} macro invocation"
                    );
                    if delimiter_stack.is_empty() {
                        end = Some(nested + 1);
                        break;
                    }
                }
                _ => {}
            }
            nested += 1;
        }
        let end = end.unwrap_or_else(|| panic!("unclosed {macro_name} macro invocation"));
        invocations.push(
            source[start..end]
                .chars()
                .filter(|character| !character.is_ascii_whitespace())
                .collect(),
        );
    }
    invocations
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct RustLexicalToken {
    text: String,
    start: usize,
    end: usize,
}

fn rust_lexical_token_spans(source: &str) -> Result<Vec<RustLexicalToken>, String> {
    let projected = rust_code_projection(source);
    let bytes = projected.as_bytes();
    let mut tokens = Vec::new();
    let mut cursor = 0;
    while cursor < bytes.len() {
        if bytes[cursor].is_ascii_whitespace() {
            cursor += 1;
            continue;
        }
        if bytes[cursor] == b'r'
            && bytes.get(cursor + 1) == Some(&b'#')
            && bytes
                .get(cursor + 2)
                .is_some_and(|byte| byte.is_ascii_alphabetic() || *byte == b'_')
        {
            let token_start = cursor;
            let start = cursor + 2;
            cursor = start + 1;
            while bytes
                .get(cursor)
                .is_some_and(|byte| byte.is_ascii_alphanumeric() || *byte == b'_')
            {
                cursor += 1;
            }
            tokens.push(RustLexicalToken {
                text: projected[start..cursor].to_owned(),
                start: token_start,
                end: cursor,
            });
            continue;
        }
        if bytes[cursor].is_ascii_alphabetic() || bytes[cursor] == b'_' {
            let start = cursor;
            cursor += 1;
            while bytes
                .get(cursor)
                .is_some_and(|byte| byte.is_ascii_alphanumeric() || *byte == b'_')
            {
                cursor += 1;
            }
            tokens.push(RustLexicalToken {
                text: projected[start..cursor].to_owned(),
                start,
                end: cursor,
            });
            continue;
        }
        if bytes[cursor..].starts_with(b"::") {
            tokens.push(RustLexicalToken {
                text: "::".to_owned(),
                start: cursor,
                end: cursor + 2,
            });
            cursor += 2;
            continue;
        }
        if !bytes[cursor].is_ascii() {
            return Err("unsupported non-ASCII Rust syntax outside comments/strings".to_owned());
        }
        tokens.push(RustLexicalToken {
            text: char::from(bytes[cursor]).to_string(),
            start: cursor,
            end: cursor + 1,
        });
        cursor += 1;
    }
    Ok(tokens)
}

fn rust_lexical_tokens(source: &str) -> Result<Vec<String>, String> {
    Ok(rust_lexical_token_spans(source)?
        .into_iter()
        .map(|token| token.text)
        .collect())
}

fn rust_balanced_statement(
    tokens: &[String],
    start: usize,
    label: &str,
) -> Result<(Vec<String>, usize), String> {
    let mut delimiter_stack = Vec::new();
    for cursor in start..tokens.len() {
        match tokens[cursor].as_str() {
            "(" => delimiter_stack.push(")"),
            "[" => delimiter_stack.push("]"),
            "{" => delimiter_stack.push("}"),
            ")" | "]" | "}" => {
                let expected = delimiter_stack
                    .pop()
                    .ok_or_else(|| format!("unopened delimiter in {label}"))?;
                if tokens[cursor] != expected {
                    return Err(format!("mismatched delimiter in {label}"));
                }
            }
            ";" if delimiter_stack.is_empty() => {
                return Ok((tokens[start..cursor].to_vec(), cursor));
            }
            _ => {}
        }
    }
    Err(format!("unterminated {label}"))
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct RustUseImport {
    path: Vec<String>,
    alias: Option<String>,
    glob: bool,
}

fn rust_use_identifier(token: &str) -> bool {
    token == "_"
        || token
            .as_bytes()
            .first()
            .is_some_and(|byte| byte.is_ascii_alphabetic() || *byte == b'_')
            && token
                .as_bytes()
                .iter()
                .all(|byte| byte.is_ascii_alphanumeric() || *byte == b'_')
}

fn parse_rust_use_group(
    tokens: &[String],
    cursor: &mut usize,
    prefix: &[String],
    imports: &mut Vec<RustUseImport>,
) -> Result<(), String> {
    if tokens.get(*cursor).map(String::as_str) != Some("{") {
        return Err("use-tree group must begin with `{`".to_owned());
    }
    *cursor += 1;
    loop {
        if tokens.get(*cursor).map(String::as_str) == Some("}") {
            *cursor += 1;
            return Ok(());
        }
        parse_rust_use_tree(tokens, cursor, prefix, imports)?;
        match tokens.get(*cursor).map(String::as_str) {
            Some(",") => {
                *cursor += 1;
            }
            Some("}") => {
                *cursor += 1;
                return Ok(());
            }
            _ => return Err("unsupported or unclosed use-tree group".to_owned()),
        }
    }
}

fn parse_rust_use_tree(
    tokens: &[String],
    cursor: &mut usize,
    prefix: &[String],
    imports: &mut Vec<RustUseImport>,
) -> Result<(), String> {
    if tokens.get(*cursor).map(String::as_str) == Some("::") {
        if !prefix.is_empty() {
            return Err("unsupported absolute path inside a nested use tree".to_owned());
        }
        *cursor += 1;
    }
    if tokens.get(*cursor).map(String::as_str) == Some("{") {
        return parse_rust_use_group(tokens, cursor, prefix, imports);
    }
    if tokens.get(*cursor).map(String::as_str) == Some("*") {
        *cursor += 1;
        imports.push(RustUseImport {
            path: prefix.to_vec(),
            alias: None,
            glob: true,
        });
        return Ok(());
    }

    let first = tokens
        .get(*cursor)
        .filter(|token| rust_use_identifier(token))
        .cloned()
        .ok_or_else(|| "unsupported use-tree path token".to_owned())?;
    *cursor += 1;
    let grouped_self = first == "self" && !prefix.is_empty();
    let mut path = prefix.to_vec();
    if !grouped_self {
        path.push(first);
    }

    loop {
        match tokens.get(*cursor).map(String::as_str) {
            Some("as") => {
                *cursor += 1;
                let alias = tokens
                    .get(*cursor)
                    .filter(|token| rust_use_identifier(token))
                    .cloned()
                    .ok_or_else(|| "unsupported use-tree alias".to_owned())?;
                *cursor += 1;
                imports.push(RustUseImport {
                    path,
                    alias: Some(alias),
                    glob: false,
                });
                return Ok(());
            }
            Some("::") => {
                if grouped_self {
                    return Err("unsupported path below grouped `self` import".to_owned());
                }
                *cursor += 1;
                match tokens.get(*cursor).map(String::as_str) {
                    Some("{") => return parse_rust_use_group(tokens, cursor, &path, imports),
                    Some("*") => {
                        *cursor += 1;
                        imports.push(RustUseImport {
                            path,
                            alias: None,
                            glob: true,
                        });
                        return Ok(());
                    }
                    Some(segment) if rust_use_identifier(segment) => {
                        path.push(segment.to_owned());
                        *cursor += 1;
                    }
                    _ => return Err("unsupported use-tree path continuation".to_owned()),
                }
            }
            Some(",") | Some("}") | None => {
                imports.push(RustUseImport {
                    path,
                    alias: None,
                    glob: false,
                });
                return Ok(());
            }
            _ => return Err("unsupported use-tree syntax".to_owned()),
        }
    }
}

fn rust_use_imports(tokens: &[String]) -> Result<Vec<RustUseImport>, String> {
    let mut imports = Vec::new();
    let mut cursor = 0;
    while cursor < tokens.len() {
        if tokens[cursor] == "extern" && tokens.get(cursor + 1).map(String::as_str) == Some("crate")
        {
            return Err("extern crate declarations are forbidden in the closed source".to_owned());
        }
        if tokens[cursor] != "use" {
            cursor += 1;
            continue;
        }
        let (statement, end) = rust_balanced_statement(tokens, cursor + 1, "use statement")?;
        let mut statement_cursor = 0;
        parse_rust_use_tree(&statement, &mut statement_cursor, &[], &mut imports)?;
        if statement_cursor != statement.len() {
            return Err("unsupported trailing use-tree syntax".to_owned());
        }
        cursor = end + 1;
    }
    Ok(imports)
}

fn rust_matching_delimiter_token(
    tokens: &[RustLexicalToken],
    open: usize,
) -> Result<usize, String> {
    let expected = match tokens.get(open).map(|token| token.text.as_str()) {
        Some("(") => ")",
        Some("[") => "]",
        Some("{") => "}",
        _ => return Err("matching-delimiter scan did not start on an opener".to_owned()),
    };
    let mut stack = vec![expected];
    for (cursor, token) in tokens.iter().enumerate().skip(open + 1) {
        match token.text.as_str() {
            "(" => stack.push(")"),
            "[" => stack.push("]"),
            "{" => stack.push("}"),
            ")" | "]" | "}" => {
                let close = stack
                    .pop()
                    .ok_or_else(|| "unopened Rust delimiter".to_owned())?;
                if token.text != close {
                    return Err("mismatched Rust delimiter".to_owned());
                }
                if stack.is_empty() {
                    return Ok(cursor);
                }
            }
            _ => {}
        }
    }
    Err("unterminated Rust delimiter".to_owned())
}

fn complete_source_module_token_bounds(
    tokens: &[RustLexicalToken],
) -> Result<(usize, usize, usize), String> {
    const OWNED_MODULE: &str = "populated_upgrade_rollback_only";
    let mut brace_depth = 0_usize;
    let mut owned = None;
    let mut reviewed_common = 0_usize;
    let mut cursor = 0_usize;
    while cursor < tokens.len() {
        if brace_depth == 0 && tokens[cursor].text == "mod" {
            let name = tokens
                .get(cursor + 1)
                .map(|token| token.text.as_str())
                .ok_or_else(|| "top-level module declaration omitted its name".to_owned())?;
            match (
                name,
                tokens.get(cursor + 2).map(|token| token.text.as_str()),
            ) {
                ("common", Some(";")) => {
                    if cursor != 0 {
                        return Err(
                            "reviewed `mod common;` may not be attribute- or cfg-wrapped"
                                .to_owned(),
                        );
                    }
                    reviewed_common += 1;
                }
                (OWNED_MODULE, Some("{")) => {
                    if owned.is_some() {
                        return Err("duplicate populated-upgrade owned module".to_owned());
                    }
                    let close = rust_matching_delimiter_token(tokens, cursor + 2)?;
                    owned = Some((cursor, cursor + 2, close));
                }
                _ => return Err(format!("unreviewed top-level module declaration: {name}")),
            }
        }
        match tokens[cursor].text.as_str() {
            "{" => brace_depth += 1,
            "}" => {
                brace_depth = brace_depth
                    .checked_sub(1)
                    .ok_or_else(|| "unopened top-level module delimiter".to_owned())?;
            }
            _ => {}
        }
        cursor += 1;
    }
    if brace_depth != 0 {
        return Err("unclosed top-level Rust block".to_owned());
    }
    if reviewed_common != 1 {
        return Err("the sole reviewed `mod common;` declaration changed".to_owned());
    }
    owned.ok_or_else(|| "missing private populated-upgrade owned module".to_owned())
}

fn rust_token_depths(tokens: &[RustLexicalToken]) -> Result<Vec<usize>, String> {
    let mut depths = Vec::with_capacity(tokens.len());
    let mut depth = 0_usize;
    for token in tokens {
        depths.push(depth);
        match token.text.as_str() {
            "{" => depth += 1,
            "}" => {
                depth = depth
                    .checked_sub(1)
                    .ok_or_else(|| "unopened Rust block".to_owned())?;
            }
            _ => {}
        }
    }
    if depth != 0 {
        return Err("unclosed Rust block".to_owned());
    }
    Ok(depths)
}

fn rust_attribute_names(tokens: &[RustLexicalToken]) -> Result<Vec<(String, usize)>, String> {
    let mut attributes = Vec::new();
    let mut cursor = 0_usize;
    while cursor < tokens.len() {
        if tokens[cursor].text != "#" {
            cursor += 1;
            continue;
        }
        let mut open = cursor + 1;
        if tokens.get(open).map(|token| token.text.as_str()) == Some("!") {
            open += 1;
        }
        if tokens.get(open).map(|token| token.text.as_str()) != Some("[") {
            return Err("unsupported attribute syntax".to_owned());
        }
        let close = rust_matching_delimiter_token(tokens, open)?;
        let name = tokens
            .get(open + 1)
            .map(|token| token.text.clone())
            .ok_or_else(|| "empty attribute is forbidden".to_owned())?;
        attributes.push((name, cursor));
        cursor = close + 1;
    }
    Ok(attributes)
}

fn validate_reviewed_foreign_authority(tokens: &[RustLexicalToken]) -> Result<(), String> {
    let extern_tokens = tokens
        .iter()
        .enumerate()
        .filter(|(_, token)| token.text == "extern")
        .map(|(cursor, _)| cursor)
        .collect::<Vec<_>>();
    let mut extern_symbols = Vec::new();
    for cursor in extern_tokens {
        if cursor == 0
            || tokens[cursor - 1].text != "unsafe"
            || tokens.get(cursor + 1).map(|token| token.text.as_str()) != Some("{")
        {
            return Err("unreviewed foreign/ABI declaration".to_owned());
        }
        let close = rust_matching_delimiter_token(tokens, cursor + 1)?;
        let body = &tokens[cursor + 2..close];
        let functions = body
            .windows(2)
            .filter_map(|window| (window[0].text == "fn").then_some(window[1].text.as_str()))
            .collect::<Vec<_>>();
        if functions.len() != 1
            || body
                .iter()
                .any(|token| matches!(token.text.as_str(), "static" | "pub" | "unsafe"))
        {
            return Err("foreign block item inventory changed".to_owned());
        }
        extern_symbols.push(functions[0]);
    }
    if extern_symbols != ["renamex_np", "renameat2"] {
        return Err("reviewed foreign symbol inventory changed".to_owned());
    }

    let unsafe_tokens = tokens
        .iter()
        .enumerate()
        .filter(|(_, token)| token.text == "unsafe")
        .map(|(cursor, _)| cursor)
        .collect::<Vec<_>>();
    if unsafe_tokens.len() != 4 {
        return Err("reviewed unsafe/foreign execution inventory changed".to_owned());
    }
    let mut unsafe_call_symbols = Vec::new();
    for cursor in unsafe_tokens {
        match tokens.get(cursor + 1).map(|token| token.text.as_str()) {
            Some("extern") => {}
            Some("{") => {
                let close = rust_matching_delimiter_token(tokens, cursor + 1)?;
                let symbol = tokens
                    .get(cursor + 2)
                    .map(|token| token.text.as_str())
                    .ok_or_else(|| "empty unsafe block".to_owned())?;
                if !["renamex_np", "renameat2"].contains(&symbol)
                    || tokens[cursor + 2..close]
                        .iter()
                        .any(|token| token.text == "extern")
                {
                    return Err("unreviewed unsafe call target".to_owned());
                }
                unsafe_call_symbols.push(symbol);
            }
            _ => return Err("unreviewed unsafe escape hatch".to_owned()),
        }
    }
    if unsafe_call_symbols != ["renamex_np", "renameat2"] {
        return Err("reviewed unsafe call inventory changed".to_owned());
    }

    let ffi_forbidden = [
        "libc",
        "libloading",
        "system",
        "dlopen",
        "dlsym",
        "execve",
        "posix_spawn",
        "asm",
        "global_asm",
        "naked_asm",
        "llvm_asm",
    ];
    if let Some(token) = tokens
        .iter()
        .find(|token| ffi_forbidden.contains(&token.text.as_str()))
    {
        return Err(format!(
            "unreviewed foreign execution symbol/path: {}",
            token.text
        ));
    }
    Ok(())
}

fn token_path_at(tokens: &[RustLexicalToken], cursor: usize, path: &[&str]) -> bool {
    let mut index = cursor;
    for (segment_index, segment) in path.iter().enumerate() {
        if tokens.get(index).map(|token| token.text.as_str()) != Some(*segment) {
            return false;
        }
        index += 1;
        if segment_index + 1 < path.len() {
            if tokens.get(index).map(|token| token.text.as_str()) != Some("::") {
                return false;
            }
            index += 1;
        }
    }
    true
}

fn rust_qualified_path_census(tokens: &[RustLexicalToken]) -> BTreeMap<String, usize> {
    let mut paths = BTreeMap::new();
    let mut cursor = 0_usize;
    while cursor < tokens.len() {
        let continues_existing_path = cursor >= 2
            && tokens[cursor - 1].text == "::"
            && rust_use_identifier(&tokens[cursor - 2].text);
        if !rust_use_identifier(&tokens[cursor].text) || continues_existing_path {
            cursor += 1;
            continue;
        }
        let mut segments = vec![tokens[cursor].text.as_str()];
        let mut end = cursor + 1;
        while tokens.get(end).map(|token| token.text.as_str()) == Some("::")
            && tokens
                .get(end + 1)
                .is_some_and(|token| rust_use_identifier(&token.text))
        {
            segments.push(tokens[end + 1].text.as_str());
            end += 2;
        }
        if segments.len() > 1 {
            *paths.entry(segments.join("::")).or_insert(0) += 1;
        }
        cursor = end.max(cursor + 1);
    }
    paths
}

fn rust_method_call_census(tokens: &[RustLexicalToken]) -> BTreeMap<String, usize> {
    let mut methods = BTreeMap::new();
    for window in tokens.windows(3) {
        if window[0].text == "." && rust_use_identifier(&window[1].text) && window[2].text == "(" {
            *methods.entry(window[1].text.clone()).or_insert(0) += 1;
        }
    }
    methods
}

fn rust_unqualified_call_census(tokens: &[RustLexicalToken]) -> BTreeMap<String, usize> {
    let mut calls = BTreeMap::new();
    for (cursor, token) in tokens.iter().enumerate() {
        if !rust_use_identifier(&token.text)
            || tokens.get(cursor + 1).map(|next| next.text.as_str()) != Some("(")
            || tokens
                .get(cursor.wrapping_sub(1))
                .is_some_and(|previous| matches!(previous.text.as_str(), "." | "::" | "!"))
            || ["if", "while", "for", "match", "loop"].contains(&token.text.as_str())
        {
            continue;
        }
        *calls.entry(token.text.clone()).or_insert(0) += 1;
    }
    calls
}

fn rust_statement_end_token(
    tokens: &[RustLexicalToken],
    start: usize,
    boundary: usize,
) -> Result<usize, String> {
    let mut stack = Vec::new();
    for cursor in start..boundary {
        match tokens[cursor].text.as_str() {
            "(" => stack.push(")"),
            "[" => stack.push("]"),
            "{" => stack.push("}"),
            ")" | "]" | "}" => {
                let expected = stack
                    .pop()
                    .ok_or_else(|| "unopened item delimiter".to_owned())?;
                if tokens[cursor].text != expected {
                    return Err("mismatched item delimiter".to_owned());
                }
            }
            ";" if stack.is_empty() => return Ok(cursor),
            _ => {}
        }
    }
    Err("unterminated direct item".to_owned())
}

fn owned_direct_item_inventory(
    tokens: &[RustLexicalToken],
    module_open: usize,
    module_close: usize,
) -> Result<Vec<String>, String> {
    let mut inventory = Vec::new();
    let mut cursor = module_open + 1;
    while cursor < module_close {
        while tokens.get(cursor).map(|token| token.text.as_str()) == Some("#") {
            let attribute_open =
                if tokens.get(cursor + 1).map(|token| token.text.as_str()) == Some("!") {
                    cursor + 2
                } else {
                    cursor + 1
                };
            if tokens.get(attribute_open).map(|token| token.text.as_str()) != Some("[") {
                return Err("unsupported owned direct attribute syntax".to_owned());
            }
            cursor = rust_matching_delimiter_token(tokens, attribute_open)? + 1;
        }
        if cursor >= module_close {
            return Err("owned attribute was not attached to an item".to_owned());
        }
        match tokens[cursor].text.as_str() {
            "use" => {
                inventory.push("use".to_owned());
                cursor = rust_statement_end_token(tokens, cursor, module_close)? + 1;
            }
            "struct" => {
                let name = tokens
                    .get(cursor + 1)
                    .filter(|token| rust_use_identifier(&token.text))
                    .map(|token| token.text.clone())
                    .ok_or_else(|| "owned struct omitted its name".to_owned())?;
                inventory.push(format!("struct:{name}"));
                let open = tokens[cursor + 2..module_close]
                    .iter()
                    .position(|token| token.text == "{")
                    .map(|offset| cursor + 2 + offset)
                    .ok_or_else(|| "owned struct omitted its body".to_owned())?;
                cursor = rust_matching_delimiter_token(tokens, open)? + 1;
            }
            "const" => {
                let name = tokens
                    .get(cursor + 1)
                    .filter(|token| rust_use_identifier(&token.text))
                    .map(|token| token.text.clone())
                    .ok_or_else(|| "owned const omitted its name".to_owned())?;
                inventory.push(format!("const:{name}"));
                cursor = rust_statement_end_token(tokens, cursor, module_close)? + 1;
            }
            "async" | "fn" => {
                let is_async = tokens[cursor].text == "async";
                let fn_token = if is_async {
                    if tokens.get(cursor + 1).map(|token| token.text.as_str()) != Some("fn") {
                        return Err("unsupported owned async item".to_owned());
                    }
                    cursor + 1
                } else {
                    cursor
                };
                let name = tokens
                    .get(fn_token + 1)
                    .filter(|token| rust_use_identifier(&token.text))
                    .map(|token| token.text.clone())
                    .ok_or_else(|| "owned function omitted its name".to_owned())?;
                inventory.push(format!(
                    "{}:{name}",
                    if is_async { "async-fn" } else { "fn" }
                ));
                let open = tokens[fn_token + 2..module_close]
                    .iter()
                    .position(|token| token.text == "{")
                    .map(|offset| fn_token + 2 + offset)
                    .ok_or_else(|| "owned function omitted its body".to_owned())?;
                cursor = rust_matching_delimiter_token(tokens, open)? + 1;
            }
            unexpected => {
                return Err(format!(
                    "unreviewed owned direct item head or macro invocation: {unexpected}"
                ))
            }
        }
    }
    Ok(inventory)
}

fn validate_owned_complete_source_module(
    source: &str,
    tokens: &[RustLexicalToken],
    module_open: usize,
    module_close: usize,
    expected_includes: &[String],
) -> Result<(), String> {
    let module_start = tokens[module_open].start;
    let module_end = tokens[module_close].end;
    let module_source = &source[module_start..module_end];
    let module_tokens = &tokens[module_open + 1..module_close];
    let module_token_text = module_tokens
        .iter()
        .map(|token| token.text.clone())
        .collect::<Vec<_>>();
    let direct_items = owned_direct_item_inventory(tokens, module_open, module_close)?;
    if direct_items
        != [
            "use",
            "use",
            "use",
            "use",
            "struct:PopulatedUpgradeMigration",
            "const:POPULATED_UPGRADE_PRE_00004_MANIFEST",
            "const:POPULATED_UPGRADE_00004_SOURCE",
            "const:POPULATED_UPGRADE_00004_MIRROR",
            "async-fn:operation_claim_completeness_populated_upgrade_is_atomic_and_rollback_only",
        ]
    {
        return Err(format!(
            "owned direct-item allowlist changed: {direct_items:?}"
        ));
    }

    let expected_imports = [
        "super::a0_assert_exact_ledger",
        "super::a0_assert_extension_allowlist",
        "super::a0_assert_post_clean_authority_surfaces",
        "super::a0_assert_post_clean_catalog",
        "super::a0_read_target_identity",
        "super::compact_sql",
        "super::OPERATION_CLAIM_00004_REPAIRED_SHA384",
        "sha2::Digest",
        "sha2::Sha384",
        "sqlx::Connection",
        "sqlx::PgConnection",
        "uuid::Uuid",
    ];
    let imports = rust_use_imports(&module_token_text)?;
    let observed_imports = imports
        .iter()
        .map(|import| import.path.join("::"))
        .collect::<Vec<_>>();
    if observed_imports != expected_imports {
        return Err("owned populated-upgrade module import inventory changed".to_owned());
    }
    if imports
        .iter()
        .any(|import| import.alias.is_some() || import.glob)
    {
        return Err("owned populated-upgrade imports may not alias or glob".to_owned());
    }

    let mut direct_depth = 0_usize;
    let mut direct_uses = 0_usize;
    let mut direct_structs = Vec::new();
    let mut direct_consts = Vec::new();
    let mut direct_functions = Vec::new();
    let mut direct_attributes = Vec::new();
    for (relative, token) in module_tokens.iter().enumerate() {
        if direct_depth == 0 {
            match token.text.as_str() {
                "use" => direct_uses += 1,
                "struct" => direct_structs.push(
                    module_tokens
                        .get(relative + 1)
                        .map(|token| token.text.clone())
                        .ok_or_else(|| "owned module struct omitted its name".to_owned())?,
                ),
                "const" => direct_consts.push(
                    module_tokens
                        .get(relative + 1)
                        .map(|token| token.text.clone())
                        .ok_or_else(|| "owned module const omitted its name".to_owned())?,
                ),
                "fn" => direct_functions.push(
                    module_tokens
                        .get(relative + 1)
                        .map(|token| token.text.clone())
                        .ok_or_else(|| "owned module function omitted its name".to_owned())?,
                ),
                "#" => {
                    let attribute_open = module_open + 1 + relative + 1;
                    let name = tokens
                        .get(attribute_open + 1)
                        .map(|token| token.text.clone())
                        .ok_or_else(|| "owned module attribute omitted its name".to_owned())?;
                    direct_attributes.push(name);
                }
                "pub" | "static" | "mod" | "macro_rules" | "trait" | "impl" | "type" | "union"
                | "extern" | "unsafe" => {
                    return Err(format!(
                        "unsupported owned populated-upgrade item: {}",
                        token.text
                    ))
                }
                _ => {}
            }
        }
        match token.text.as_str() {
            "{" => direct_depth += 1,
            "}" => {
                direct_depth = direct_depth
                    .checked_sub(1)
                    .ok_or_else(|| "unopened owned module block".to_owned())?;
            }
            _ => {}
        }
    }
    if direct_depth != 0
        || direct_uses != 4
        || direct_structs != ["PopulatedUpgradeMigration"]
        || direct_consts
            != [
                "POPULATED_UPGRADE_PRE_00004_MANIFEST",
                "POPULATED_UPGRADE_00004_SOURCE",
                "POPULATED_UPGRADE_00004_MIRROR",
            ]
        || direct_functions
            != ["operation_claim_completeness_populated_upgrade_is_atomic_and_rollback_only"]
        || direct_attributes != ["derive", "tokio", "ignore"]
    {
        return Err("owned populated-upgrade item inventory changed".to_owned());
    }
    if module_tokens
        .iter()
        .filter(|token| token.text == "const")
        .count()
        != 3
        || module_tokens
            .iter()
            .filter(|token| token.text == "fn")
            .count()
            != 1
        || module_tokens.iter().enumerate().any(|(cursor, token)| {
            matches!(
                token.text.as_str(),
                "pub"
                    | "mod"
                    | "macro_rules"
                    | "trait"
                    | "impl"
                    | "type"
                    | "union"
                    | "extern"
                    | "unsafe"
            ) || token.text == "static"
                && module_tokens
                    .get(cursor.wrapping_sub(1))
                    .is_none_or(|previous| previous.text != "'")
        })
    {
        return Err(
            "owned nested item/function-pointer/foreign execution inventory changed".to_owned(),
        );
    }
    if module_tokens
        .iter()
        .filter(|token| token.text == "super")
        .count()
        != 1
    {
        return Err("owned module may reach its parent only through its frozen imports".to_owned());
    }
    let allowed_crate_targets = [
        "validate_chat_protocol_database_url",
        "CLEAN_PROTOCOL_13_MANIFEST",
        "validate_durable_operation_claim_completeness",
        "canonical_legacy_receipt_set_sha256",
    ];
    for cursor in 0..module_tokens.len() {
        if module_tokens[cursor].text != "crate" {
            continue;
        }
        if !token_path_at(module_tokens, cursor, &["crate", "common", "chat_protocol"]) {
            return Err("owned module reached an unreviewed crate path".to_owned());
        }
        let target = module_tokens
            .get(cursor + 6)
            .map(|token| token.text.as_str())
            .ok_or_else(|| "owned crate path omitted its target".to_owned())?;
        if !allowed_crate_targets.contains(&target) {
            return Err(format!(
                "owned module reached an unreviewed crate target: {target}"
            ));
        }
    }

    let proof_name = "operation_claim_completeness_populated_upgrade_is_atomic_and_rollback_only";
    let proof_fn = module_tokens
        .windows(2)
        .position(|window| window[0].text == "fn" && window[1].text == proof_name)
        .ok_or_else(|| "owned populated proof function disappeared".to_owned())?;
    let proof_open = module_tokens[proof_fn + 2..]
        .iter()
        .position(|token| token.text == "{")
        .map(|offset| proof_fn + 2 + offset)
        .ok_or_else(|| "owned populated proof body disappeared".to_owned())?;
    let absolute_proof_open = module_open + 1 + proof_open;
    let absolute_proof_close = rust_matching_delimiter_token(tokens, absolute_proof_open)?;
    let proof_tokens = &tokens[absolute_proof_open + 1..absolute_proof_close];
    let observed_paths = rust_qualified_path_census(proof_tokens);
    let expected_paths = BTreeMap::from([
        ("PgConnection::connect".to_owned(), 2_usize),
        ("Sha384::digest".to_owned(), 2),
        ("Uuid::parse_str".to_owned(), 2),
        (
            "crate::common::chat_protocol::CLEAN_PROTOCOL_13_MANIFEST".to_owned(),
            1,
        ),
        (
            "crate::common::chat_protocol::canonical_legacy_receipt_set_sha256".to_owned(),
            1,
        ),
        (
            "crate::common::chat_protocol::validate_chat_protocol_database_url".to_owned(),
            1,
        ),
        (
            "crate::common::chat_protocol::validate_durable_operation_claim_completeness"
                .to_owned(),
            3,
        ),
        ("hex::encode".to_owned(), 2),
        ("sqlx::query".to_owned(), 12),
        ("sqlx::query_scalar".to_owned(), 8),
        ("sqlx::raw_sql".to_owned(), 2),
        ("std::env::var".to_owned(), 1),
    ]);
    if observed_paths != expected_paths {
        return Err(format!(
            "owned fully qualified call/path inventory changed: {observed_paths:?}"
        ));
    }
    let observed_methods = rust_method_call_census(proof_tokens);
    let expected_methods = BTreeMap::from([
        ("as_bytes".to_owned(), 4_usize),
        ("as_database_error".to_owned(), 1),
        ("as_deref".to_owned(), 1),
        ("begin".to_owned(), 1),
        ("bind".to_owned(), 13),
        ("close".to_owned(), 2),
        ("code".to_owned(), 1),
        ("constraint".to_owned(), 1),
        ("contains".to_owned(), 1),
        ("enumerate".to_owned(), 1),
        ("execute".to_owned(), 14),
        ("expect".to_owned(), 34),
        ("expect_err".to_owned(), 1),
        ("fetch_one".to_owned(), 8),
        ("iter".to_owned(), 1),
        ("rollback".to_owned(), 1),
        ("to_string".to_owned(), 1),
        ("unwrap_or_else".to_owned(), 1),
    ]);
    if observed_methods != expected_methods {
        return Err(format!(
            "owned method-call capability inventory changed: {observed_methods:?}"
        ));
    }
    let observed_calls = rust_unqualified_call_census(proof_tokens);
    let expected_calls = BTreeMap::from([
        ("Some".to_owned(), 3_usize),
        ("a0_assert_exact_ledger".to_owned(), 2),
        ("a0_assert_extension_allowlist".to_owned(), 2),
        ("a0_assert_post_clean_authority_surfaces".to_owned(), 2),
        ("a0_assert_post_clean_catalog".to_owned(), 2),
        ("a0_read_target_identity".to_owned(), 2),
        ("compact_sql".to_owned(), 1),
    ]);
    if observed_calls != expected_calls {
        return Err(format!(
            "owned unqualified-call capability inventory changed: {observed_calls:?}"
        ));
    }

    let source_depths = rust_token_depths(tokens)?;
    let mut observed_macro_invocations = Vec::new();
    let mut invocation_cursor = absolute_proof_open + 1;
    while invocation_cursor < absolute_proof_close {
        if tokens[invocation_cursor].text != "!" {
            invocation_cursor += 1;
            continue;
        }
        let Some(name_cursor) = invocation_cursor.checked_sub(1) else {
            return Err("owned proof macro invocation omitted its name".to_owned());
        };
        if !rust_use_identifier(&tokens[name_cursor].text) {
            invocation_cursor += 1;
            continue;
        }
        let Some(open) = tokens.get(invocation_cursor + 1) else {
            return Err("owned proof macro invocation omitted its delimiter".to_owned());
        };
        if !matches!(open.text.as_str(), "(" | "[" | "{") {
            invocation_cursor += 1;
            continue;
        }
        let open_cursor = invocation_cursor + 1;
        let close_cursor = rust_matching_delimiter_token(tokens, open_cursor)?;
        if close_cursor >= absolute_proof_close {
            return Err("owned proof macro invocation escaped its function body".to_owned());
        }

        let mut path_start = name_cursor;
        while path_start >= 2
            && tokens[path_start - 1].text == "::"
            && rust_use_identifier(&tokens[path_start - 2].text)
        {
            path_start -= 2;
        }
        let absolute_path = path_start > 0 && tokens[path_start - 1].text == "::";
        if absolute_path {
            path_start -= 1;
        }
        let path = tokens[path_start..=name_cursor]
            .iter()
            .map(|token| token.text.as_str())
            .collect::<String>();
        let delimiter = match open.text.as_str() {
            "(" => "()",
            "[" => "[]",
            "{" => "{}",
            _ => unreachable!("macro invocation opener was checked"),
        };
        let normalized_arguments = tokens[open_cursor + 1..close_cursor]
            .iter()
            .map(|token| token.text.as_str())
            .collect::<Vec<_>>()
            .join("\0");
        if normalized_arguments.is_empty() {
            return Err(format!(
                "owned proof macro invocation may not have an empty/opaque argument list: {path}"
            ));
        }
        let arguments_sha256 = hex::encode(Sha256::digest(normalized_arguments.as_bytes()));
        let raw_arguments_sha256 = hex::encode(Sha256::digest(
            source[tokens[open_cursor].end..tokens[close_cursor].start].as_bytes(),
        ));
        observed_macro_invocations.push(format!(
            "{path}|{delimiter}|proof_span={}..{}|depth={}|args_sha256={arguments_sha256}|\
             raw_args_sha256={raw_arguments_sha256}",
            tokens[path_start].start - tokens[absolute_proof_open].end,
            tokens[close_cursor].end - tokens[absolute_proof_open].end,
            source_depths[invocation_cursor],
        ));
        invocation_cursor = close_cursor + 1;
    }
    let observed_macro_paths = observed_macro_invocations
        .iter()
        .map(|invocation| {
            invocation
                .split('|')
                .next()
                .expect("macro invocation fingerprint has a path")
        })
        .fold(BTreeMap::new(), |mut counts, path| {
            *counts.entry(path).or_insert(0_usize) += 1;
            counts
        });
    let expected_macro_paths = BTreeMap::from([
        ("assert", 2_usize),
        ("assert_eq", 24),
        ("assert_ne", 1),
        ("panic", 1),
    ]);
    let observed_macro_delimiters = observed_macro_invocations
        .iter()
        .map(|invocation| {
            invocation
                .split('|')
                .nth(1)
                .expect("macro invocation fingerprint has a delimiter")
        })
        .fold(BTreeMap::new(), |mut counts, delimiter| {
            *counts.entry(delimiter).or_insert(0_usize) += 1;
            counts
        });
    let macro_invocation_authority_sha256 = hex::encode(Sha256::digest(
        observed_macro_invocations.join("\0").as_bytes(),
    ));
    if observed_macro_invocations.len() != 28
        || observed_macro_paths != expected_macro_paths
        || observed_macro_delimiters != BTreeMap::from([("()", 28_usize)])
        || macro_invocation_authority_sha256
            != "fef0e57cb4a1ec1e41d6ebeb4051a6b7c5b25e13a514cacc168140da11f5c49d"
    {
        return Err(format!(
            "owned proof macro-invocation authority changed: count={} paths={observed_macro_paths:?} \
             delimiters={observed_macro_delimiters:?} sha256={macro_invocation_authority_sha256} \
             inventory={observed_macro_invocations:#?}",
            observed_macro_invocations.len(),
        ));
    }

    let observed_includes = rust_macro_invocations(source, "include_str");
    if observed_includes != expected_includes {
        return Err("closed thirteen-entry include inventory changed".to_owned());
    }
    let include_tokens = tokens
        .iter()
        .filter(|token| token.text == "include_str")
        .collect::<Vec<_>>();
    if include_tokens.len() != 13
        || include_tokens
            .iter()
            .any(|token| token.start <= module_start || token.end >= module_end)
    {
        return Err("include_str identifiers escaped the owned module".to_owned());
    }

    let source_identifiers = [
        ("PopulatedUpgradeMigration", 13_usize),
        ("POPULATED_UPGRADE_PRE_00004_MANIFEST", 2),
        ("POPULATED_UPGRADE_00004_SOURCE", 5),
        ("POPULATED_UPGRADE_00004_MIRROR", 2),
    ];
    for (identifier, expected_count) in source_identifiers {
        let occurrences = tokens
            .iter()
            .filter(|token| token.text == identifier)
            .collect::<Vec<_>>();
        if occurrences.len() != expected_count
            || occurrences
                .iter()
                .any(|token| token.start <= module_start || token.end >= module_end)
        {
            return Err(format!(
                "source-bearing identifier `{identifier}` escaped or changed its frozen count"
            ));
        }
    }
    if module_tokens
        .iter()
        .filter(|token| token.text == "source")
        .count()
        != 14
    {
        return Err("owned source field/reference inventory changed".to_owned());
    }

    let mut raw_arguments = Vec::new();
    for cursor in 0..tokens.len() {
        if tokens[cursor].text != "raw_sql" {
            continue;
        }
        if cursor < 2
            || tokens[cursor - 2].text != "sqlx"
            || tokens[cursor - 1].text != "::"
            || tokens.get(cursor + 1).map(|token| token.text.as_str()) != Some("(")
        {
            return Err("complete-source sink must be an exact SQLx raw-SQL call".to_owned());
        }
        let close = rust_matching_delimiter_token(tokens, cursor + 1)?;
        raw_arguments.push(
            tokens[cursor + 2..close]
                .iter()
                .map(|token| token.text.clone())
                .collect::<Vec<_>>(),
        );
        if tokens[cursor].start <= module_start || tokens[cursor].end >= module_end {
            return Err("complete-source sink escaped the owned module".to_owned());
        }
        let expected_execution = [".", "execute", "(", "&", "mut", "*", "transaction", ")"];
        if tokens
            .get(close + 1..close + 1 + expected_execution.len())
            .is_none_or(|tail| {
                tail.iter()
                    .map(|token| token.text.as_str())
                    .ne(expected_execution)
            })
        {
            return Err(
                "complete-source raw-SQL call is not chained to the exact transaction executor"
                    .to_owned(),
            );
        }
    }
    if raw_arguments
        != [
            vec!["migration".to_owned(), ".".to_owned(), "source".to_owned()],
            vec!["POPULATED_UPGRADE_00004_SOURCE".to_owned()],
        ]
    {
        return Err("the two direct complete-source replay sinks changed".to_owned());
    }

    let command_identifier = ["Com", "mand"].concat();
    let forbidden_identifiers = [
        "Migration",
        "Migrator",
        "MigrationSource",
        "Migrate",
        "DEFAULT",
        "run",
        "run_direct",
        "apply",
        "include",
        "include_bytes",
        "execute_many",
        "fetch",
        "fetch_many",
        "File",
        "OpenOptions",
        "fs",
        "process",
        command_identifier.as_str(),
        "psql",
        "extern",
        "unsafe",
        "union",
        "CString",
        "libc",
        "libloading",
        "system",
        "dlopen",
        "dlsym",
        "execve",
        "posix_spawn",
        "asm",
        "global_asm",
        "naked_asm",
        "llvm_asm",
    ];
    for token in module_tokens {
        if forbidden_identifiers.contains(&token.text.as_str())
            || token.text.starts_with("query_file")
        {
            return Err(format!(
                "alternative complete-source seam in owned module: {}",
                token.text
            ));
        }
    }
    if module_tokens.iter().any(|token| token.text == "Executor") {
        return Err("Executor trait calls are forbidden in the owned module".to_owned());
    }
    let environment_paths = module_tokens
        .windows(5)
        .filter(|window| {
            window[0].text == "std"
                && window[1].text == "::"
                && window[2].text == "env"
                && window[3].text == "::"
                && window[4].text == "var"
        })
        .count();
    if environment_paths != 1
        || module_tokens
            .iter()
            .filter(|token| token.text == "env")
            .count()
            != 1
    {
        return Err("runtime environment loader inventory changed".to_owned());
    }

    for cursor in 0..module_tokens.len() {
        if !token_path_at(module_tokens, cursor, &["sqlx", "query"])
            && !token_path_at(module_tokens, cursor, &["sqlx", "query_scalar"])
            && !token_path_at(module_tokens, cursor, &["sqlx", "query_as"])
        {
            continue;
        }
        let open = cursor + 3;
        if module_tokens.get(open).map(|token| token.text.as_str()) != Some("(") {
            return Err("SQLx query constructor is not a direct call".to_owned());
        }
        let absolute_open = module_open + 1 + open;
        let absolute_close = rust_matching_delimiter_token(tokens, absolute_open)?;
        let argument_tokens = &tokens[absolute_open + 1..absolute_close];
        if !argument_tokens.is_empty()
            && !(argument_tokens.len() == 1 && argument_tokens[0].text == ",")
        {
            let arguments = argument_tokens
                .iter()
                .map(|token| token.text.as_str())
                .collect::<Vec<_>>()
                .join(" ");
            return Err(format!(
                "owned SQLx query constructors must receive only reviewed string literals: \
                 {arguments}"
            ));
        }
    }

    for cursor in 0..module_tokens.len() {
        if module_tokens[cursor].text != "execute"
            || module_tokens
                .get(cursor + 1)
                .map(|token| token.text.as_str())
                != Some("(")
        {
            continue;
        }
        let absolute_open = module_open + 1 + cursor + 1;
        let absolute_close = rust_matching_delimiter_token(tokens, absolute_open)?;
        let argument = tokens[absolute_open + 1..absolute_close]
            .iter()
            .map(|token| token.text.as_str())
            .collect::<Vec<_>>();
        if argument != ["&", "mut", "connection"] && argument != ["&", "mut", "*", "transaction"] {
            return Err(format!(
                "owned execute call received a non-executor/source-bearing argument: {}",
                argument.join(" ")
            ));
        }
    }

    if module_source.contains("pub ") || module_source.contains("pub(") {
        return Err("owned module may not export source-bearing authority".to_owned());
    }
    Ok(())
}

fn validate_no_sensitive_complete_source_aliases(source: &str) -> Result<(), String> {
    let tokens = rust_lexical_tokens(source)?;
    let sensitive_roots = ["std", "core", "builtin", "sqlx"];
    let sensitive_items = ["include_str", "include", "include_bytes", "raw_sql"];
    for import in rust_use_imports(&tokens)? {
        if import.glob {
            return Err(format!(
                "glob import can hide a complete-source alias: {}::*",
                import.path.join("::")
            ));
        }
        if import.path.is_empty() {
            return Err("empty use-tree import".to_owned());
        }
        if import.alias.is_some() {
            return Err(format!(
                "import aliases are forbidden in the closed source: {}",
                import.path.join("::")
            ));
        }
        if import
            .path
            .iter()
            .any(|segment| sensitive_items.contains(&segment.as_str()))
        {
            return Err(format!(
                "sensitive complete-source item import: {}",
                import.path.join("::")
            ));
        }
        let terminal = import.path.last().expect("nonempty import path");
        if terminal == "migrate" && import.path.iter().any(|segment| segment == "sqlx") {
            return Err(format!(
                "SQLx migrate macro/module alias import: {}",
                import.path.join("::")
            ));
        }
        if sensitive_roots.contains(&terminal.as_str()) {
            return Err(format!(
                "sensitive crate/module root import: {}",
                import.path.join("::")
            ));
        }
        if import.alias.as_ref().is_some_and(|alias| {
            sensitive_roots.contains(&alias.as_str())
                || sensitive_items.contains(&alias.as_str())
                || alias == "migrate"
        }) {
            return Err(format!(
                "sensitive local import alias: {}",
                import.alias.expect("checked alias")
            ));
        }
    }

    for cursor in 0..tokens.len() {
        if ["include_str", "include", "include_bytes"].contains(&tokens[cursor].as_str())
            && tokens.get(cursor + 1).map(String::as_str) == Some("!")
            && tokens.get(cursor.wrapping_sub(1)).map(String::as_str) == Some("::")
        {
            return Err(format!(
                "path-qualified include macro is forbidden: {}",
                tokens[cursor]
            ));
        }
        if tokens[cursor] == "migrate"
            && tokens.get(cursor + 1).map(String::as_str) == Some("!")
            && tokens.get(cursor.wrapping_sub(1)).map(String::as_str) == Some("::")
        {
            return Err("path-qualified migrate macro is forbidden".to_owned());
        }
        if tokens[cursor] == "sqlx"
            && tokens.get(cursor + 1).map(String::as_str) == Some("::")
            && tokens.get(cursor + 2).map(String::as_str) == Some("raw_sql")
        {
            if cursor > 0 && tokens[cursor - 1] == "::" {
                return Err("raw_sql must use the exact sqlx crate root".to_owned());
            }
            if tokens.get(cursor + 3).map(String::as_str) != Some("(") {
                return Err("sqlx::raw_sql may only appear as a direct call".to_owned());
            }
        }
    }
    Ok(())
}

fn validate_closed_complete_source_authority(
    source: &str,
    expected_includes: &[String],
) -> Result<(), String> {
    validate_closed_migration_macro_inventory(source, expected_includes)?;
    let tokens = rust_lexical_token_spans(source)?;
    let (module_declaration, module_open, module_close) =
        complete_source_module_token_bounds(&tokens)?;
    if module_declaration > 0 && tokens[module_declaration - 1].text != "}" {
        return Err("owned populated-upgrade module may not be attribute-wrapped".to_owned());
    }
    let depths = rust_token_depths(&tokens)?;
    let top_level_functions = tokens
        .iter()
        .enumerate()
        .filter_map(|(cursor, token)| {
            (depths[cursor] == 0 && token.text == "fn").then(|| {
                tokens
                    .get(cursor + 1)
                    .map(|name| name.text.clone())
                    .unwrap_or_else(|| "<missing>".to_owned())
            })
        })
        .collect::<Vec<_>>();
    let top_level_function_digest =
        hex::encode(Sha256::digest(top_level_functions.join("\0").as_bytes()));
    if top_level_functions.len() != 117
        || top_level_function_digest
            != "bf8bdfaf798a3cb6c32b9ac9c677476c660427361db6eda37587ac68e73344e9"
    {
        return Err(format!(
            "top-level callable item inventory changed: count={} sha256={} names={:?}",
            top_level_functions.len(),
            top_level_function_digest,
            top_level_functions
        ));
    }

    for (cursor, token) in tokens.iter().enumerate() {
        if token.text == "use"
            && depths[cursor] != 0
            && !(cursor > module_open && cursor < module_close && depths[cursor] == 1)
        {
            return Err("local use declarations are forbidden".to_owned());
        }
        if token.text == "pub" {
            let statement_end = tokens[cursor..]
                .iter()
                .position(|candidate| matches!(candidate.text.as_str(), ";" | "{" | "}"))
                .map(|offset| cursor + offset)
                .unwrap_or(tokens.len());
            if tokens[cursor..statement_end]
                .iter()
                .any(|candidate| candidate.text == "use" || candidate.text == "mod")
            {
                return Err("module exports and reexports are forbidden".to_owned());
            }
        }
    }

    let attributes = rust_attribute_names(&tokens)?;
    for (name, cursor) in &attributes {
        if [
            "path",
            "cfg_attr",
            "link",
            "link_name",
            "no_mangle",
            "export_name",
            "link_section",
            "unsafe",
        ]
        .contains(&name.as_str())
        {
            return Err(format!("source-loading attribute is forbidden: {name}"));
        }
        let attribute_open = if tokens.get(cursor + 1).map(|token| token.text.as_str()) == Some("!")
        {
            cursor + 2
        } else {
            cursor + 1
        };
        let attribute_close = rust_matching_delimiter_token(&tokens, attribute_open)?;
        if tokens[*cursor..=attribute_close].windows(3).any(|window| {
            window[0].text == "sqlx" && window[1].text == "::" && window[2].text == "test"
        }) {
            return Err("sqlx::test migration/fixture attributes are forbidden".to_owned());
        }
    }
    let owned_attributes = attributes
        .iter()
        .filter(|(_, cursor)| *cursor > module_open && *cursor < module_close)
        .map(|(name, _)| name.as_str())
        .collect::<Vec<_>>();
    if owned_attributes != ["derive", "tokio", "ignore"] {
        return Err("owned module attribute inventory changed".to_owned());
    }

    let mut macro_definitions = Vec::new();
    let mut macro_cursor = 0_usize;
    while macro_cursor < tokens.len() {
        if tokens[macro_cursor].text != "macro_rules"
            || tokens
                .get(macro_cursor + 1)
                .map(|token| token.text.as_str())
                != Some("!")
        {
            macro_cursor += 1;
            continue;
        }
        let name = tokens
            .get(macro_cursor + 2)
            .filter(|token| rust_use_identifier(&token.text))
            .map(|token| token.text.as_str())
            .ok_or_else(|| "macro_rules definition omitted its name".to_owned())?;
        let body_open = macro_cursor + 3;
        if tokens.get(body_open).map(|token| token.text.as_str()) != Some("{") {
            return Err(format!(
                "macro_rules definition `{name}` must use a braced definition body"
            ));
        }
        let body_close = rust_matching_delimiter_token(&tokens, body_open)?;

        let enclosing_function = tokens
            .iter()
            .enumerate()
            .filter(|(cursor, token)| depths[*cursor] == 0 && token.text == "fn")
            .find_map(|(function_cursor, _)| {
                let function_open = tokens[function_cursor + 2..]
                    .iter()
                    .position(|token| token.text == "{")
                    .map(|offset| function_cursor + 2 + offset)?;
                let function_close = rust_matching_delimiter_token(&tokens, function_open).ok()?;
                (macro_cursor > function_open && macro_cursor < function_close).then(|| {
                    tokens
                        .get(function_cursor + 1)
                        .map(|token| token.text.clone())
                        .unwrap_or_else(|| "<missing>".to_owned())
                })
            })
            .unwrap_or_else(|| "<module>".to_owned());
        let enclosing_module = tokens
            .iter()
            .enumerate()
            .filter(|(cursor, token)| token.text == "mod" && depths[*cursor] < depths[macro_cursor])
            .filter_map(|(module_cursor, _)| {
                let name = tokens.get(module_cursor + 1)?.text.as_str();
                let module_open =
                    (tokens.get(module_cursor + 2)?.text == "{").then_some(module_cursor + 2)?;
                let module_close = rust_matching_delimiter_token(&tokens, module_open).ok()?;
                (macro_cursor > module_open && macro_cursor < module_close)
                    .then_some((depths[module_cursor], name))
            })
            .max_by_key(|(depth, _)| *depth)
            .map(|(_, name)| name)
            .unwrap_or("<root>");

        let mut arms = Vec::new();
        let mut arm_cursor = body_open + 1;
        while arm_cursor < body_close {
            let matcher_open = arm_cursor;
            if !matches!(tokens[matcher_open].text.as_str(), "(" | "[" | "{") {
                return Err(format!(
                    "macro_rules definition `{name}` has an unsupported arm matcher"
                ));
            }
            let matcher_close = rust_matching_delimiter_token(&tokens, matcher_open)?;
            if tokens
                .get(matcher_close + 1)
                .map(|token| token.text.as_str())
                != Some("=")
                || tokens
                    .get(matcher_close + 2)
                    .map(|token| token.text.as_str())
                    != Some(">")
            {
                return Err(format!(
                    "macro_rules definition `{name}` arm omitted its exact expansion arrow"
                ));
            }
            let expansion_open = matcher_close + 3;
            if !tokens
                .get(expansion_open)
                .is_some_and(|token| matches!(token.text.as_str(), "(" | "[" | "{"))
            {
                return Err(format!(
                    "macro_rules definition `{name}` arm omitted its expansion delimiter"
                ));
            }
            let expansion_close = rust_matching_delimiter_token(&tokens, expansion_open)?;
            if expansion_close >= body_close {
                return Err(format!(
                    "macro_rules definition `{name}` arm escaped its definition body"
                ));
            }
            let matcher_delimiter = match tokens[matcher_open].text.as_str() {
                "(" => "()",
                "[" => "[]",
                "{" => "{}",
                _ => unreachable!("matcher opener was checked"),
            };
            let expansion_delimiter = match tokens[expansion_open].text.as_str() {
                "(" => "()",
                "[" => "[]",
                "{" => "{}",
                _ => unreachable!("expansion opener was checked"),
            };
            let matcher_tokens = tokens[matcher_open + 1..matcher_close]
                .iter()
                .map(|token| token.text.as_str())
                .collect::<Vec<_>>()
                .join("\0");
            let matcher_signature = tokens[matcher_open + 1..matcher_close]
                .iter()
                .map(|token| token.text.as_str())
                .collect::<Vec<_>>()
                .join(" ");
            let expansion_tokens = tokens[expansion_open + 1..expansion_close]
                .iter()
                .map(|token| token.text.as_str())
                .collect::<Vec<_>>()
                .join("\0");
            arms.push(format!(
                "{matcher_delimiter}->{expansion_delimiter}:matcher={matcher_signature}:\
                 matcher_sha256={}:\
                 expansion_sha256={}",
                hex::encode(Sha256::digest(matcher_tokens.as_bytes())),
                hex::encode(Sha256::digest(expansion_tokens.as_bytes())),
            ));
            arm_cursor = expansion_close + 1;
            if arm_cursor < body_close && matches!(tokens[arm_cursor].text.as_str(), ";" | ",") {
                arm_cursor += 1;
            }
        }

        let body_tokens = tokens[body_open + 1..body_close]
            .iter()
            .map(|token| token.text.as_str())
            .collect::<Vec<_>>();
        let command_identifier = ["Com", "mand"].concat();
        let psql_identifier = ["p", "sql"].concat();
        let forbidden_macro_body_identifiers = [
            "process",
            command_identifier.as_str(),
            psql_identifier.as_str(),
            "File",
            "OpenOptions",
            "fs",
            "include",
            "include_str",
            "include_bytes",
            "raw_sql",
            "Migration",
            "Migrator",
            "MigrationSource",
            "Migrate",
            "Executor",
            "CString",
            "extern",
            "unsafe",
            "libc",
            "libloading",
            "system",
            "dlopen",
            "dlsym",
            "execve",
            "posix_spawn",
            "asm",
            "global_asm",
            "naked_asm",
            "llvm_asm",
        ];
        if let Some(forbidden) = body_tokens.iter().find(|token| {
            forbidden_macro_body_identifiers.contains(token)
                || token.starts_with("query_file")
                || **token == "sqlx"
        }) {
            return Err(format!(
                "macro_rules definition `{name}` contains an external loader/process/FFI/SQL sink: {forbidden}"
            ));
        }
        let raw_body = &source[tokens[body_open].end..tokens[body_close].start];
        if raw_body.contains(&psql_identifier) {
            return Err(format!(
                "macro_rules definition `{name}` contains an external psql sink"
            ));
        }

        let normalized_definition = tokens[macro_cursor..=body_close]
            .iter()
            .map(|token| token.text.as_str())
            .collect::<Vec<_>>()
            .join("\0");
        let normalized_body = body_tokens.join("\0");
        macro_definitions.push(format!(
            "{name}|delimiter={{}}|{}..{}|depth={}|module={enclosing_module}|\
             scope={enclosing_function}|\
             arms={arms:?}|tokens_sha256={}|body_sha256={}|raw_sha256={}",
            tokens[macro_cursor].start,
            tokens[body_close].end,
            depths[macro_cursor],
            hex::encode(Sha256::digest(normalized_definition.as_bytes())),
            hex::encode(Sha256::digest(normalized_body.as_bytes())),
            hex::encode(Sha256::digest(
                source[tokens[macro_cursor].start..tokens[body_close].end].as_bytes()
            )),
        ));
        macro_cursor = body_close + 1;
    }
    let expected_macro_definitions = ["reject_mutation|delimiter={}|82830..83211|depth=1|\
         module=<root>|\
         scope=a0_legacy_forward_reconcile_classifier_rejects_every_drift_dimension|\
         arms=[\"()->{}:matcher=$ field : ident , $ value : expr:\
         matcher_sha256=00a4645da4ae7f2f8cb442757b0a4f4eff48fbdaa3bce9454657c5fdd7c6ee26:\
         expansion_sha256=3138eaac337a45d9ceb5682c1a415c7bd9ed01d5ded11ad67ccfcb6b7c26afd2\"]|\
         tokens_sha256=bdb3e917cf8e24f18728b2422a61a1b4ecbfca5da47bedfbf709e2f1b55d1588|\
         body_sha256=302d0c7969cc3ed5ba1ce20a90db28cfde98d26c161f1792ba79309bea53c129|\
         raw_sha256=81299f0027706b31443847622197134d4b3350a9cfd9df6c89136acfb16463bc"];
    if macro_definitions != expected_macro_definitions {
        return Err(format!(
            "macro_rules definition authority changed: count={} inventory={macro_definitions:#?}",
            macro_definitions.len()
        ));
    }

    validate_reviewed_foreign_authority(&tokens)?;
    validate_owned_complete_source_module(
        source,
        &tokens,
        module_open,
        module_close,
        expected_includes,
    )
}

fn expected_populated_upgrade_source_includes() -> Vec<String> {
    [
        "../migrations/20260722000001_chat_protocol_core.sql",
        "../migrations/20260722000002_chat_protocol_delivery.sql",
        "../migrations/20260722000003_chat_protocol_blobs.sql",
        "../migrations/20260725000001_prepare_welcome_provenance_backfill.sql",
        "../migrations/20260725000002_refine_welcome_provenance_quarantine.sql",
        "../migrations/20260726000001_welcome_supersession_provenance.sql",
        "../migrations/20260726000002_restore_welcome_provenance_deferred_triggers.sql",
        "../migrations/20260726000003_finalize_welcome_provenance_triggers.sql",
        "../migrations/20260728000001_chat_operation_claims.sql",
        "../migrations/20260728000002_exact_operation_claim_mutation_kind.sql",
        "../migrations/20260728000003_defer_operation_claim_principal_fk.sql",
        "../migrations/20260728000004_activate_operation_claim_completeness.sql",
        "../docs/operation_claim_completeness_activation.sql",
    ]
    .map(|path| format!("include_str!(\"{path}\")"))
    .to_vec()
}

fn validate_closed_migration_macro_inventory(
    source: &str,
    expected_includes: &[String],
) -> Result<(), String> {
    validate_no_sensitive_complete_source_aliases(source)?;
    let observed_includes = rust_macro_invocations(source, "include_str");
    if observed_includes != expected_includes {
        return Err(
            "only the reviewed eleven pre-00004 migrations, exact 00004, and mirror may be included"
                .to_owned(),
        );
    }
    for forbidden in [
        "include".to_owned(),
        ["include", "_bytes"].concat(),
        ["sqlx::", "migrate"].concat(),
    ] {
        if !rust_macro_invocations(source, &forbidden).is_empty() {
            return Err(format!(
                "unreviewed external-source or migration macro: {forbidden}"
            ));
        }
    }
    Ok(())
}

#[test]
fn alternate_delimiter_migration_macros_cannot_bypass_closed_inventory() {
    let expected_includes = expected_populated_upgrade_source_includes();
    let authorized_source = expected_includes.join("\n");
    assert!(
        validate_closed_migration_macro_inventory(&authorized_source, &expected_includes).is_ok(),
        "the exact ordered thirteen-entry include inventory must be accepted"
    );

    for unreviewed in [
        r#"include_str!["../migrations/unreviewed.sql"]"#,
        r#"include_str!{"../migrations/unreviewed.sql"}"#,
        r#"include_str!{concat!("../migrations/", nested!(["unreviewed.sql"]))}"#,
    ] {
        let candidate = format!("{authorized_source}\n{unreviewed}");
        assert!(
            validate_closed_migration_macro_inventory(&candidate, &expected_includes).is_err(),
            "alternate-delimiter include_str extra bypassed the closed inventory"
        );
    }

    for macro_name in [
        "include".to_owned(),
        ["include", "_bytes"].concat(),
        ["sqlx::", "migrate"].concat(),
    ] {
        for (open, close) in [('(', ')'), ('[', ']'), ('{', '}')] {
            let forbidden =
                format!("{macro_name}!{open}nested!([\"../migrations/unreviewed.sql\"]){close}");
            let candidate = format!("{authorized_source}\n{forbidden}");
            assert!(
                validate_closed_migration_macro_inventory(&candidate, &expected_includes).is_err(),
                "forbidden {macro_name} macro with {open}{close} evaded detection"
            );
        }
    }
}

#[test]
fn sensitive_complete_source_aliases_are_rejected_without_blocking_exact_direct_seams() {
    let expected_includes = expected_populated_upgrade_source_includes();
    let direct_complete_source_sink = ["sqlx::", "raw_sql"].concat();
    let authorized_source = format!(
        concat!(
            "use std::path::Path;\n",
            "use sqlx::{{Connection, Executor}};\n",
            "use sqlx::migrate::{{Migration, Migrator}};\n",
            "{}\n",
            "fn exact_direct_execution() {{\n",
            "    let _ = {}(\"SELECT 1\");\n",
            "    let _ = {}(\"SELECT 2\");\n",
            "}}\n"
        ),
        expected_includes.join("\n"),
        direct_complete_source_sink,
        direct_complete_source_sink
    );
    assert!(
        validate_closed_migration_macro_inventory(&authorized_source, &expected_includes).is_ok(),
        "the exact direct includes, raw-SQL seams, and migration types must remain accepted"
    );
    let complete_source_sink = ["sqlx::", "raw_sql"].concat();
    let projected_compact: String = rust_code_projection(&authorized_source)
        .chars()
        .filter(|character| !character.is_ascii_whitespace())
        .collect();
    assert_eq!(projected_compact.matches(&complete_source_sink).count(), 2);

    let adversarial_aliases = [
        r#"
            use std::include_str as extra_migration_source;
            const EXTRA: &str =
                extra_migration_source! {"../migrations/unreviewed.sql"};
        "#,
        r#"
            use sqlx::migrate as unreviewed_migrator;
            fn unreviewed() {
                let _ = unreviewed_migrator! {"./unreviewed-migrations"};
            }
        "#,
        r#"
            use sqlx::raw_sql as execute_complete_source;
            fn unreviewed(source: &str) {
                let _ = execute_complete_source(source);
            }
        "#,
        r#"
            use sqlx::{Connection, raw_sql as execute_complete_source};
        "#,
        r#"
            use sqlx::{migrate::{self as migration_module, Migrator}, Connection};
        "#,
        r#"
            use sqlx::{self as sx, Connection};
            fn unreviewed(source: &str) {
                let _ = sx::raw_sql(source);
            }
        "#,
        r#"
            use std::{self as s, path::Path};
            const EXTRA: &str = s::include_str! {"../migrations/unreviewed.sql"};
        "#,
        r#"
            use ::sqlx as sx;
            fn unreviewed(source: &str) {
                let _ = sx::raw_sql(source);
            }
        "#,
        r#"
            use {sqlx as sx, std as s};
        "#,
        r#"
            pub use sqlx::raw_sql as execute_complete_source;
        "#,
        r#"
            pub(crate) use std::{fs::File, include_bytes as load_bytes};
        "#,
        r#"
            extern crate sqlx as sx;
            fn unreviewed(source: &str) {
                let _ = sx::raw_sql(source);
            }
        "#,
        r#"
            extern crate std as s;
            const EXTRA: &str = s::include_str! {"../migrations/unreviewed.sql"};
        "#,
        r#"
            use sqlx::raw_sql;
            fn unreviewed(source: &str) {
                let _ = raw_sql(source);
            }
        "#,
        r#"
            use std::include_str;
            const EXTRA: &str = include_str! {"../migrations/unreviewed.sql"};
        "#,
        r#"
            use sqlx::migrate;
            fn unreviewed() {
                let _ = migrate! {"./unreviewed-migrations"};
            }
        "#,
        r#"
            fn unreviewed(source: &str) {
                let run = sqlx::raw_sql;
                let _ = run(source);
            }
        "#,
        r#"
            const RUN: fn(&str) = sqlx::raw_sql;
        "#,
        r#"
            static RUN: fn(&str) = sqlx::raw_sql;
        "#,
    ];
    for adversarial in adversarial_aliases {
        let candidate = format!("{authorized_source}\n{adversarial}");
        assert!(
            validate_closed_migration_macro_inventory(&candidate, &expected_includes).is_err(),
            "sensitive complete-source alias was accepted: {adversarial}"
        );
    }
}

fn inject_before_owned_complete_source_module_close(source: &str, addition: &str) -> String {
    let tokens = rust_lexical_token_spans(source).expect("tokenize fixture source");
    let (_, _, module_close) =
        complete_source_module_token_bounds(&tokens).expect("locate fixture owned module");
    let insertion = tokens[module_close].start;
    format!(
        "{}{}\n{}",
        &source[..insertion],
        addition,
        &source[insertion..]
    )
}

#[test]
fn complete_source_authority_equivalence_classes_are_closed() {
    let manifest = Path::new(env!("CARGO_MANIFEST_DIR"));
    let source = std::fs::read_to_string(manifest.join("tests/chat_protocol_schema.rs"))
        .expect("read complete-source authority fixture");
    let expected_includes = expected_populated_upgrade_source_includes();
    let direct_complete_source_sink = ["sqlx::", "raw_sql"].concat();
    validate_closed_complete_source_authority(&source, &expected_includes)
        .expect("reviewed complete-source authority must be accepted");

    let top_level_seams = [
        "use sqlx as sx;",
        "use sqlx::{self as sx, Executor};",
        "use sqlx::*;",
        "pub use sqlx::raw_sql as replay;",
        "extern crate sqlx as sx;",
        "use sqlx as r#sx;",
        "use r#sqlx as sx;",
        "use sqlx::r#raw_sql as replay;",
        "mod unreviewed_complete_source;",
        "#[path = \"unreviewed.rs\"] mod unreviewed_complete_source;",
        "#[cfg_attr(test, path = \"unreviewed.rs\")] mod unreviewed_complete_source;",
        "#[sqlx::test(migrations = \"./migrations\", fixtures(\"seed\"))] async fn loader() {}",
        "extern \"C\" { fn unreviewed_foreign_function(); }",
        "unsafe extern \"C\" { static UNREVIEWED_FOREIGN_STATIC: i32; }",
        "#[link(name = \"c\")] unsafe extern \"C\" { fn unreviewed_linked_function(); }",
    ];
    assert_eq!(
        top_level_seams.len(),
        15,
        "top-level complete-source equivalence inventory changed"
    );
    for seam in top_level_seams {
        let candidate = format!("{source}\n{seam}\n");
        assert!(
            validate_closed_complete_source_authority(&candidate, &expected_includes).is_err(),
            "top-level complete-source seam was accepted: {seam}"
        );
    }

    let inject_into_owned_proof = |fixture_source: &str, addition: &str| {
        let (_, proof_open, proof_end) = rust_function_bounds(
            fixture_source,
            "operation_claim_completeness_populated_upgrade_is_atomic_and_rollback_only",
        );
        let marker = fixture_source[proof_open..proof_end]
            .find("let mutation_boundary_peer_count")
            .map(|offset| proof_open + offset)
            .expect("locate owned proof post-transaction insertion point");
        format!(
            "{}{}\n{}",
            &fixture_source[..marker],
            addition,
            &fixture_source[marker..]
        )
    };
    let top_level_replay_helper = r#"
        async fn unreviewed_replay(
            transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
        ) {
            let sql = std::fs::read_to_string(
                "../migrations/unreviewed.sql",
            )
            .expect("read unreviewed migration");
            sqlx::query(sql.as_str())
                .execute(&mut **transaction)
                .await
                .expect("execute unreviewed migration");
        }
    "#;
    let helper_candidate = format!("{source}\n{top_level_replay_helper}\n");
    let helper_candidate = inject_into_owned_proof(
        &helper_candidate,
        "super::unreviewed_replay(&mut transaction).await;",
    );
    assert!(
        validate_closed_complete_source_authority(&helper_candidate, &expected_includes).is_err(),
        "top-level replay helper plus owned fully-qualified caller was accepted"
    );
    assert_eq!(
        top_level_seams.len() + 1,
        16,
        "composed top-level complete-source equivalence inventory changed"
    );

    let unexpected_body_call = [
        "let _ = crate::common::chat_protocol::setup_chat_protocol_db",
        "(1).await;",
    ]
    .concat();
    let owned_body_seams = [
        "let _ = sqlx::query_with(\"SELECT 1\", Default::default());",
        "let _ = sqlx::query_as_with::<_, ()>(\"SELECT 1\", Default::default());",
        "let _ = sqlx::query_scalar_with::<_, i64, _>(\"SELECT 1\", Default::default());",
        "let mut unreviewed_builder = sqlx::QueryBuilder::<sqlx::Postgres>::new(\"SELECT 1\"); let _ = unreviewed_builder.build();",
        "let _ = ::sqlx::query_with(\"SELECT 1\", Default::default());",
        unexpected_body_call.as_str(),
        "let _ = super::unreviewed_replay(&mut transaction).await;",
        "let _ = std::ffi::CString::new(\"psql --file unreviewed.sql\");",
        "let _ = transaction.execute(\"SELECT 1\").await;",
        "let _ = sqlx::query(\"SELECT 1\").fetch(&mut *transaction);",
    ];
    assert_eq!(
        owned_body_seams.len(),
        10,
        "owned proof-body capability equivalence inventory changed"
    );
    for seam in owned_body_seams {
        let candidate = inject_into_owned_proof(&source, seam);
        assert!(
            validate_closed_complete_source_authority(&candidate, &expected_includes).is_err(),
            "owned proof-body capability seam was accepted: {seam}"
        );
    }

    let source_tokens = rust_lexical_token_spans(&source).expect("tokenize reviewed source");
    let reviewed_macro_cursor = source_tokens
        .windows(3)
        .position(|window| {
            window[0].text == "macro_rules"
                && window[1].text == "!"
                && window[2].text == "reject_mutation"
        })
        .expect("locate reviewed reject_mutation definition");
    let reviewed_macro_open = reviewed_macro_cursor + 3;
    let reviewed_macro_close = rust_matching_delimiter_token(&source_tokens, reviewed_macro_open)
        .expect("bound reviewed reject_mutation definition");
    let reviewed_macro_start = source_tokens[reviewed_macro_cursor].start;
    let reviewed_macro_end = source_tokens[reviewed_macro_close].end;
    let reviewed_macro_definition = &source[reviewed_macro_start..reviewed_macro_end];
    let source_without_reviewed_macro = format!(
        "{}{}",
        &source[..reviewed_macro_start],
        &source[reviewed_macro_end..]
    );
    let relocate_reviewed_macro = |definition: &str| {
        let (function_start, _, _) = rust_function_bounds(
            &source_without_reviewed_macro,
            "a0_legacy_forward_reconcile_classifier_rejects_every_drift_dimension",
        );
        let attribute_start = source_without_reviewed_macro[..function_start]
            .rfind("#[test]")
            .expect("locate reviewed classifier test attribute");
        format!(
            "{}{definition}\n{}",
            &source_without_reviewed_macro[..attribute_start],
            &source_without_reviewed_macro[attribute_start..]
        )
    };
    let append_macro_arm = |definition: &str, arm: &str| {
        let final_close = definition
            .rfind('}')
            .expect("reviewed macro definition has a final close");
        format!(
            "{}\n{arm}\n{}",
            &definition[..final_close],
            &definition[final_close..]
        )
    };

    let empty_invocation = inject_into_owned_proof(&source, "unreviewed_complete_source_macro!();");
    let qualified_invocation = inject_into_owned_proof(&source, "std::assert!(true);");
    let alternate_delimiter_invocation = inject_into_owned_proof(&source, "assert!{true};");
    let forwarded_path_invocation = inject_into_owned_proof(
        &source,
        "assert!(crate::common::chat_protocol::CLEAN_PROTOCOL_13_MANIFEST.len() == 13);",
    );
    let extra_arm_definition = append_macro_arm(reviewed_macro_definition, "        () => {{}};");
    let extra_arm = format!(
        "{}{}{}",
        &source[..reviewed_macro_start],
        extra_arm_definition,
        &source[reviewed_macro_end..]
    );
    let mutated_definition = reviewed_macro_definition.replacen(
        "facts.$field = $value;",
        "facts.$field = Default::default();",
        1,
    );
    assert_ne!(
        mutated_definition, reviewed_macro_definition,
        "macro-body mutation fixture must alter the reviewed arm"
    );
    let body_mutation = format!(
        "{}{}{}",
        &source[..reviewed_macro_start],
        mutated_definition,
        &source[reviewed_macro_end..]
    );
    let scope_relocation = relocate_reviewed_macro(reviewed_macro_definition);

    let process_command = ["std::", "process::Com", "mand"].concat();
    let external_client = ["p", "sql"].concat();
    let top_level_external_definition = format!(
        r#"
macro_rules! unreviewed_external_loader {{
    () => {{
        let _ = {process_command}::new("{external_client}").status();
    }};
}}
"#
    );
    let top_level_external_macro = format!("{source}\n{top_level_external_definition}\n");
    let process_arm = format!(
        r#"        () => {{
            let status = {process_command}::new("{external_client}")
                .args([
                    "postgresql://127.0.0.1:5432/catbird_chat_protocol_test_20260722",
                    "-v",
                    "ON_ERROR_STOP=1",
                    "-f",
                    "../migrations/unreviewed.sql",
                ])
                .status()
                .expect("launch unreviewed migration");
            assert!(status.success());
        }};"#
    );
    let expanded_relocated_definition = append_macro_arm(reviewed_macro_definition, &process_arm);
    let relocated_process_macro = relocate_reviewed_macro(&expanded_relocated_definition);
    let relocated_process_invocation =
        inject_into_owned_proof(&relocated_process_macro, "reject_mutation!();");

    let macro_authority_seams = [
        ("owned empty macro invocation", empty_invocation),
        ("owned qualified macro invocation", qualified_invocation),
        (
            "owned alternate-delimiter macro invocation",
            alternate_delimiter_invocation,
        ),
        (
            "owned forwarded-path macro invocation",
            forwarded_path_invocation,
        ),
        ("reviewed macro extra arm", extra_arm),
        ("reviewed macro body mutation", body_mutation),
        ("reviewed macro scope relocation", scope_relocation),
        ("top-level external-loader macro", top_level_external_macro),
        (
            "relocated reviewed macro plus process arm and owned invocation",
            relocated_process_invocation,
        ),
    ];
    assert_eq!(
        macro_authority_seams.len(),
        9,
        "macro definition/invocation equivalence inventory changed"
    );
    for (description, candidate) in &macro_authority_seams {
        assert!(
            validate_closed_complete_source_authority(candidate, &expected_includes).is_err(),
            "macro definition/invocation authority seam was accepted: {description}"
        );
    }

    let migration_macro_seam = [
        "fn migrate_directory() { let _ = sqlx::",
        "migrate!(\"./migrations\"); }",
    ]
    .concat();
    let closure_forward_seam = format!(
        "fn closure_forward(source: &str) {{ let replay = |sql| \
         {direct_complete_source_sink}(sql); let _ = replay(source); }}"
    );
    let macro_forward_seam = format!(
        "macro_rules! forward_source {{ ($source:expr) => {{ \
         {direct_complete_source_sink}($source) }} }}"
    );
    let cfg_wrapped_seam = format!(
        "#[cfg(test)] fn cfg_wrapped(source: &str) {{ let _ = \
         {direct_complete_source_sink}(source); }}"
    );
    let proc_attribute_seam = format!(
        "#[unreviewed_source] fn proc_attribute_wrapped(source: &str) {{ let _ = \
         {direct_complete_source_sink}(source); }}"
    );
    let process_loader_seam = [
        "fn process_loader() { let _ = std::",
        "process::Com",
        "mand::new(\"psql\"); }",
    ]
    .concat();
    let ffi_external_execution_seam = r#"
        #[link(name = "c")]
        unsafe extern "C" {
            #[link_name = "system"]
            fn unreviewed_system(command: *const std::os::raw::c_char) -> std::os::raw::c_int;
        }
        #[unsafe(no_mangle)]
        unsafe extern "C" fn invoke_unreviewed_system() {
            let command = std::ffi::CString::new("psql --file unreviewed.sql").unwrap();
            unsafe { unreviewed_system(command.as_ptr()) };
        }
    "#;
    let ordinary_abi_seam =
        "extern \"C\" { fn unreviewed_foreign_function() -> std::os::raw::c_int; }";
    let unsafe_abi_seam =
        "unsafe extern \"C\" { fn unreviewed_unsafe_foreign_function() -> std::os::raw::c_int; }";
    let foreign_static_seam =
        "unsafe extern \"C\" { static UNREVIEWED_FOREIGN_STATIC: std::os::raw::c_int; }";
    let no_link_system_seam = r#"
        extern "C" {
            fn system(command: *const std::ffi::c_char) -> std::ffi::c_int;
        }
        fn invoke_system_without_link_attribute() {
            let command = std::ffi::CString::new("psql --file unreviewed.sql").unwrap();
            let status = unsafe { system(command.as_ptr()) };
            assert_eq!(status, 0);
        }
    "#;
    let unexpected_qualified_call_seam = [
        "async fn unexpected_fully_qualified_call() { let _ = \
         crate::common::chat_protocol::setup_chat_protocol_db",
        "(1).await; }",
    ]
    .concat();
    let owned_seams = [
        "use sqlx::raw_sql as replay;",
        "fn forward(source: &str) { let replay = sqlx::raw_sql; let _ = replay(source); }",
        closure_forward_seam.as_str(),
        "fn executor_source(executor: &mut sqlx::PgConnection, source: &str) { let _ = sqlx::Executor::execute(executor, source); }",
        "fn executor_method_source(connection: &mut sqlx::PgConnection, source: &str) { let _ = connection.execute(source); }",
        "fn query_source(source: &str) { let _ = sqlx::query(source); }",
        migration_macro_seam.as_str(),
        "fn migrator_path(path: &std::path::Path) { let _ = sqlx::migrate::Migrator::new(path); }",
        "fn migration_source(source: &str) { let _ = sqlx::migrate::Migration::new(1, std::borrow::Cow::Borrowed(\"x\"), sqlx::migrate::MigrationType::Simple, std::borrow::Cow::Borrowed(source), false); }",
        "fn migration_trait<T: sqlx::migrate::MigrationSource>(source: T) { let _ = source; }",
        "fn migrate_trait<T: sqlx::migrate::Migrate>(target: T) { let _ = target; }",
        "fn migration_methods(migrator: sqlx::migrate::Migrator, connection: &mut sqlx::PgConnection) { let _ = migrator.run(connection); let _ = migrator.run_direct(connection); let _ = migrator.apply(connection); let _ = sqlx::migrate::Migrator::DEFAULT; }",
        "fn query_file_loader() { let _ = sqlx::query_file!(\"../migrations/unreviewed.sql\"); }",
        "fn query_file_unchecked_loader() { let _ = sqlx::query_file_unchecked!(\"../migrations/unreviewed.sql\"); }",
        "fn query_file_as_loader() { let _ = sqlx::query_file_as_unchecked!((), \"../migrations/unreviewed.sql\"); }",
        "fn query_file_scalar_loader() { let _ = sqlx::query_file_scalar_unchecked!(\"../migrations/unreviewed.sql\"); }",
        "fn fs_loader() { let _ = std::fs::read_to_string(\"../migrations/unreviewed.sql\"); }",
        "fn file_loader() { let _ = std::fs::File::open(\"../migrations/unreviewed.sql\"); }",
        "fn env_loader() { let _ = std::env::var(\"UNREVIEWED_MIGRATION_PATH\"); }",
        process_loader_seam.as_str(),
        macro_forward_seam.as_str(),
        cfg_wrapped_seam.as_str(),
        proc_attribute_seam.as_str(),
        "const EXTRA_SOURCE: &str = include_str!(\"../migrations/unreviewed.sql\");",
        "const RAW_EXTRA_SOURCE: &str = r#include_str!(\"../migrations/unreviewed.sql\");",
        "static FORWARDED_SOURCE: &str = POPULATED_UPGRADE_00004_SOURCE;",
        ffi_external_execution_seam,
        ordinary_abi_seam,
        unsafe_abi_seam,
        foreign_static_seam,
        no_link_system_seam,
        "enum UnreviewedOwnedItem { Variant }",
        "union UnreviewedOwnedUnion { value: u64 }",
        "unreviewed_owned_item_macro!();",
        "fn alternate_query_with(arguments: sqlx::postgres::PgArguments) { let _ = sqlx::query_with(\"SELECT 1\", arguments); }",
        "fn alternate_query_as_with(arguments: sqlx::postgres::PgArguments) { let _ = sqlx::query_as_with::<_, ()>(\"SELECT 1\", arguments); }",
        "fn alternate_query_scalar_with(arguments: sqlx::postgres::PgArguments) { let _ = sqlx::query_scalar_with::<_, i64, _>(\"SELECT 1\", arguments); }",
        "fn alternate_query_builder() { let mut builder = sqlx::QueryBuilder::<sqlx::Postgres>::new(\"SELECT 1\"); let _ = builder.build(); }",
        unexpected_qualified_call_seam.as_str(),
        "fn assembly_escape() { unsafe { std::arch::asm!(\"nop\") }; }",
    ];
    assert_eq!(
        owned_seams.len(),
        40,
        "owned complete-source equivalence inventory changed"
    );
    for seam in owned_seams {
        let candidate = inject_before_owned_complete_source_module_close(&source, seam);
        assert!(
            validate_closed_complete_source_authority(&candidate, &expected_includes).is_err(),
            "owned complete-source seam was accepted: {seam}"
        );
    }
    assert_eq!(
        top_level_seams.len()
            + 1
            + owned_body_seams.len()
            + macro_authority_seams.len()
            + owned_seams.len(),
        75,
        "total complete-source equivalence inventory changed"
    );
}

fn rust_function_bounds(source: &str, name: &str) -> (usize, usize, usize) {
    let projected = rust_code_projection(source);
    let needle = format!("fn {name}");
    let function_start = projected
        .match_indices(&needle)
        .find_map(|(start, _)| {
            let after = start + needle.len();
            projected
                .as_bytes()
                .get(after)
                .is_some_and(|byte| byte.is_ascii_whitespace() || *byte == b'(' || *byte == b'<')
                .then_some(start)
        })
        .unwrap_or_else(|| panic!("missing exact Rust function {name}"));
    let open_brace = projected[function_start..]
        .find('{')
        .map(|offset| function_start + offset)
        .unwrap_or_else(|| panic!("missing body for Rust function {name}"));
    let mut depth = 0_usize;
    for (offset, byte) in projected.as_bytes()[open_brace..].iter().enumerate() {
        match byte {
            b'{' => depth += 1,
            b'}' => {
                depth -= 1;
                if depth == 0 {
                    return (function_start, open_brace, open_brace + offset + 1);
                }
            }
            _ => {}
        }
    }
    panic!("unbalanced body for Rust function {name}");
}

fn rust_function_body<'a>(source: &'a str, name: &str) -> &'a str {
    let (_, open, end) = rust_function_bounds(source, name);
    &source[open + 1..end - 1]
}

fn rust_function_is_ignored(source: &str, name: &str) -> bool {
    let (start, _, _) = rust_function_bounds(source, name);
    let prefix_start = source[..start]
        .rfind("\n\n")
        .map(|offset| offset + 2)
        .unwrap_or(0);
    source[prefix_start..start].contains("#[ignore")
}

#[test]
fn a_final_fixed_target_gates_are_validation_only() {
    let manifest = Path::new(env!("CARGO_MANIFEST_DIR"));
    let common = std::fs::read_to_string(manifest.join("tests/common/chat_protocol.rs"))
        .expect("read fixed-target helper");
    let schema = std::fs::read_to_string(manifest.join("tests/chat_protocol_schema.rs"))
        .expect("read schema gate");
    let g7 = std::fs::read_to_string(manifest.join("tests/chat_protocol_g7_schema.rs"))
        .expect("read G7 schema gate");
    let operation_claims =
        std::fs::read_to_string(manifest.join("tests/chat_protocol_operation_claims.rs"))
            .expect("read operation-claim gate");

    let helper = common
        .split("pub async fn setup_chat_protocol_db(max_connections: u32) -> PgPool")
        .nth(1)
        .expect("fixed-target helper body");
    let preflight = helper
        .find("let ledger_before = validate_exact_reviewed_ledger")
        .expect("validation-only ledger preflight");
    let migrator = helper
        .find("migrator.run_direct")
        .expect("reviewed exact-13 no-op");
    let postflight = helper
        .find("let ledger_after = validate_exact_reviewed_ledger")
        .expect("validation-only ledger postflight");
    assert!(preflight < migrator && migrator < postflight);
    assert!(helper.contains("ledger_after, ledger_before"));

    const POPULATED: &str =
        "operation_claim_completeness_populated_upgrade_is_atomic_and_rollback_only";
    assert!(
        rust_function_is_ignored(&schema, POPULATED),
        "sole populated-upgrade exception must remain ignored"
    );
    rust_function_bounds(
        &schema,
        "populated_upgrade_rollback_proof_is_transaction_bounded_and_source_pinned",
    );
    let (_, populated_open, populated_end) = rust_function_bounds(&schema, POPULATED);
    let mut schema_without_exception = schema.as_bytes().to_vec();
    for byte in &mut schema_without_exception[populated_open + 1..populated_end - 1] {
        if *byte != b'\n' {
            *byte = b' ';
        }
    }
    let schema_without_exception =
        String::from_utf8(schema_without_exception).expect("blanked schema source remains UTF-8");

    let drop_chat = ["DROP", " SCHEMA chat"].concat();
    let delete_ledger = ["DELETE FROM public.", "_sqlx_migrations"].concat();
    let whole_directory = ["sqlx::", "migrate!", "(\"./migrations\")"].concat();
    let manual_g7_replay = [".execute", "(g7_sql().as_str())"].concat();
    let manual_migration_replay = [".execute", "(sql.as_str())"].concat();
    let raw_sql_replay = ["sqlx::", "raw_sql("].concat();
    for (label, source) in [("schema", &schema_without_exception), ("g7", &g7)] {
        for forbidden in [
            &drop_chat,
            &delete_ledger,
            &whole_directory,
            &manual_g7_replay,
            &manual_migration_replay,
            &raw_sql_replay,
        ] {
            assert!(
                !source.contains(forbidden),
                "{label} fixed-target gate retained destructive/manual migration seam: \
                 {forbidden}"
            );
        }
    }

    let matrix = [
        (
            "schema",
            "operation_claim_completeness_cutover_matches_durable_classification",
        ),
        (
            "g7",
            "g7_receipt_shape_rejects_null_boolean_and_mixed_successor",
        ),
        (
            "g7",
            "g7_installed_interval_validator_is_snapshot_bound_and_deterministic",
        ),
        (
            "schema",
            "post_clean_public_ledger_attached_object_mutations_fail_closed",
        ),
        ("schema", "clean_chat_schema_is_exact_and_validation_only"),
        (
            "schema",
            "fixed_target_helper_uses_one_closed_exact13_migrator_and_unchanged_api",
        ),
        (
            "g7",
            "g7_live_catalog_has_closed_arms_receipts_and_trigger_guards",
        ),
        (
            "operation_claims",
            "operation_claim_completeness_migration_keeps_its_review_bytes",
        ),
        (
            "operation_claims",
            "completeness_activation_drains_writers_and_preserves_only_bounded_legacy_orphans",
        ),
        (
            "schema",
            "lane_a_rollback_write_manifest_is_complete_and_immediate",
        ),
        (
            "schema",
            "fixed_target_url_validation_accepts_only_exact_literal_authority",
        ),
        (
            "schema",
            "populated_upgrade_rollback_proof_is_transaction_bounded_and_source_pinned",
        ),
        ("schema", POPULATED),
        ("schema", "a_final_fixed_target_gates_are_validation_only"),
    ];
    assert_eq!(matrix.len(), 14);
    let drop_database = ["DROP", " DATABASE"].concat();
    let create_database = ["CREATE", " DATABASE"].concat();
    let admin_target = ["127.0.0.1:5432", "/postgres"].concat();
    let marker_intent = ["A0_", "INTENT_PATH"].concat();
    let marker_consumed = ["A0_", "CONSUMED_PATH"].concat();
    let reset = ["reset", "_chat"].concat();
    let commit_method = [".com", "mit()"].concat();
    let transaction_commit = ["Transaction::", "commit"].concat();
    for (target, test_name) in matrix {
        let source = match target {
            "schema" => &schema,
            "g7" => &g7,
            "operation_claims" => &operation_claims,
            _ => unreachable!("closed A-final target"),
        };
        let body = rust_function_body(source, test_name);
        if test_name == POPULATED {
            continue;
        }
        for forbidden in [
            drop_chat.as_str(),
            drop_database.as_str(),
            create_database.as_str(),
            admin_target.as_str(),
            marker_intent.as_str(),
            marker_consumed.as_str(),
            reset.as_str(),
            commit_method.as_str(),
            transaction_commit.as_str(),
            raw_sql_replay.as_str(),
        ] {
            if test_name == "fixed_target_url_validation_accepts_only_exact_literal_authority"
                && forbidden == admin_target
            {
                assert_eq!(
                    body.matches(admin_target.as_str()).count(),
                    1,
                    "literal-target negative inventory changed"
                );
                continue;
            }
            assert!(
                !body.contains(forbidden),
                "A-final matrix test {target}/{test_name} retained forbidden authority: \
                 {forbidden}"
            );
        }
    }
    assert!(
        rust_function_is_ignored(
            &schema,
            "post_clean_public_ledger_attached_object_mutations_fail_closed"
        ),
        "public-ledger mutation gate must remain ignored"
    );
    let public_body = rust_function_body(
        &schema,
        "post_clean_public_ledger_attached_object_mutations_fail_closed",
    );
    let public_code = rust_code_projection(public_body);
    let public_begin = public_code
        .find(".begin()")
        .expect("public mutation gate uses a real transaction");
    let public_baseline = public_code
        .find("durable_authority_before")
        .expect("public mutation complete pre-baseline");
    let public_immediate = public_body
        .find("SET CONSTRAINTS ALL IMMEDIATE")
        .expect("public mutation same-transaction immediate evaluation");
    let public_rollback = public_code
        .find(".rollback()")
        .expect("public mutation outer rollback");
    let public_observer = public_code
        .find("pool\n        .acquire()")
        .or_else(|| public_code.find("pool.acquire()"))
        .expect("public mutation durable observer");
    let public_post_baseline = public_code
        .find("durable_authority_after")
        .expect("public mutation complete durable post-baseline");
    assert!(
        public_begin < public_baseline
            && public_baseline < public_immediate
            && public_immediate < public_rollback
            && public_rollback < public_observer
            && public_observer < public_post_baseline
    );
    for required in [
        "durable_ledger_after, durable_ledger_before",
        "durable_catalog_after, durable_catalog_before",
        "observer",
        ".close()",
    ] {
        assert!(
            public_body.contains(required),
            "public mutation durable rollback proof omitted {required}"
        );
    }
    let public_helper = rust_function_body(&schema, "assert_public_ledger_mutation_rejected");
    let positive_observation = public_helper
        .find("observe_exact_public_ledger_mutation")
        .expect("positive exact public-mutation observation");
    let typed_classifier = public_helper
        .find("a0_classify_public_ledger_closed_catalog")
        .expect("typed public-ledger classifier");
    let savepoint_rollback = public_helper
        .find("ROLLBACK TO SAVEPOINT unapproved_public_catalog")
        .expect("per-case savepoint rollback");
    let savepoint_release = public_helper
        .find("RELEASE SAVEPOINT unapproved_public_catalog")
        .expect("per-case savepoint release");
    assert!(
        positive_observation < typed_classifier
            && typed_classifier < savepoint_rollback
            && savepoint_rollback < savepoint_release
    );
    for required in [
        "Err(PublicLedgerClosedCatalogError::Drift(drift))",
        "Err(PublicLedgerClosedCatalogError::Query",
        "Ok(_) => panic!",
        "clean_before",
        "clean_after",
        "clean_after, clean_before",
    ] {
        assert!(
            public_helper.contains(required),
            "public mutation typed causal proof omitted {required}"
        );
    }

    let fresh_pool = schema
        .split("async fn fresh_pool() -> PgPool")
        .nth(1)
        .expect("schema validation-only pool")
        .split("\n}\n")
        .next()
        .expect("bounded schema validation-only pool");
    assert!(fresh_pool.contains("setup_chat_protocol_db(1).await"));
    assert!(g7.contains("let pool = common::chat_protocol::setup_chat_protocol_db(1).await;"));
}

#[test]
fn populated_upgrade_rollback_proof_is_transaction_bounded_and_source_pinned() {
    const TEST_NAME: &str =
        "operation_claim_completeness_populated_upgrade_is_atomic_and_rollback_only";
    let source = std::fs::read_to_string(
        Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/chat_protocol_schema.rs"),
    )
    .expect("read populated-upgrade source");
    assert!(
        rust_function_is_ignored(&source, TEST_NAME),
        "populated-upgrade proof must remain ignored"
    );
    let body = rust_function_body(&source, TEST_NAME);
    let code = rust_code_projection(body);

    let exact_target = "postgresql://127.0.0.1:5432/catbird_chat_protocol_test_20260722";
    assert_eq!(body.matches(exact_target).count(), 3);
    let lock = "SELECT pg_advisory_lock(20260729,702)";
    let unlock = "SELECT pg_advisory_unlock(20260729,702)";
    assert_eq!(body.matches(lock).count(), 1);
    assert_eq!(body.matches(unlock).count(), 1);
    assert!(body.contains("let original_backend_pid = pre_identity.pid"));
    assert!(body.contains("post_identity.database_oid, pre_identity.database_oid"));
    assert!(body.contains("post_identity.pid, original_backend_pid"));
    assert_eq!(
        body.matches("backend_type='client backend' AND pid<>pg_backend_pid()")
            .count(),
        2,
        "populated proof needs initial and mutation-boundary peer observations"
    );
    assert_eq!(code.matches(".begin()").count(), 1);
    let begin = code
        .find(".begin()")
        .expect("one explicit outer transaction");
    let drop_schema = ["DROP SCHEMA", " chat CASCADE"].concat();
    assert_eq!(body.matches(&drop_schema).count(), 1);
    let drop_position = body
        .find(&drop_schema)
        .expect("transactional chat-schema drop");
    let boundary_peer_position = body
        .rfind("backend_type='client backend' AND pid<>pg_backend_pid()")
        .expect("mutation-boundary peer observation");
    assert!(begin < boundary_peer_position && boundary_peer_position < drop_position);

    let expected_manifest = [
        ("20260722000001_chat_protocol_core.sql", "dd48feea7beafae59fbc11516e8c1ae91382b356b80366056f71d2493c10923bd39ff0739fe08cb4b0452b0ec82132ff"),
        ("20260722000002_chat_protocol_delivery.sql", "86952763aaeb8f4cf8a8a18dd5d022a5357d450193e265a18da5a771513b9d4c7c8408bad27c4f4ba3b712b41b80e504"),
        ("20260722000003_chat_protocol_blobs.sql", "310101886f60d3a663ee5df829bbc86a96a45e23adee754220d3b06fd74acfd708d23a138124872a5177244d3e14e8eb"),
        ("20260725000001_prepare_welcome_provenance_backfill.sql", "3f3d1660193bc37aa8c9876e636a4918f59404f0e055f509b9a67158b6028d947adc299c4d776a693bf8b75e647d90a8"),
        ("20260725000002_refine_welcome_provenance_quarantine.sql", "8dd0a595288182e2c36aed67d7155138a0817deb5d236dd1eaea50f066a90d7949f60c0de6bff5c9e8bd28e4a1c50de2"),
        ("20260726000001_welcome_supersession_provenance.sql", "78c31ff78db5b8889fb00cb7024186a0f048975fc7a059c667e326162e3f338396d9760143367c9206802d21269484f4"),
        ("20260726000002_restore_welcome_provenance_deferred_triggers.sql", "1b29d045575aea2552ac10bdb61451662d51bca5afa75827e030e5dd859eee0d1664e12a69ecea9692e0fadb2a8df4af"),
        ("20260726000003_finalize_welcome_provenance_triggers.sql", "8bd956b8383bea542c6d591ae7721b92b898cb07e49b503131bedfbb511937147766569bcd2b23da11b226decffec495"),
        ("20260728000001_chat_operation_claims.sql", "fd71f2eb5235226371f113b5738b752b27e901b72810e9ec1e1f201e979606e0b09a16be087103e4146b4fb9f8bdff8f"),
        ("20260728000002_exact_operation_claim_mutation_kind.sql", "a5c0225818e350415e0ad3a88c5016d621a75bb64563f97023de9d27498cf113d8ef9d95c98621036c15ac3398dbee17"),
        ("20260728000003_defer_operation_claim_principal_fk.sql", "d42c64d98f6af2042ecf5d08b925aaadae01efcd7d1f6d1887c5485e0862d80304bb9ba54506a1876eba54b505d4114a"),
    ];
    let expected_includes = expected_populated_upgrade_source_includes();
    validate_closed_complete_source_authority(&source, &expected_includes)
        .expect("populated replay source authority remains closed");
    let tokens = rust_lexical_token_spans(&source).expect("tokenize populated replay source");
    let (_, module_open, module_close) =
        complete_source_module_token_bounds(&tokens).expect("locate populated replay module");
    let module_source = &source[tokens[module_open].start..tokens[module_close].end];
    for expected in expected_manifest {
        let include = format!("include_str!(\"../migrations/{}\")", expected.0);
        assert!(
            module_source.contains(&include),
            "populated manifest did not compile-include {}",
            expected.0
        );
        assert!(
            module_source.contains(expected.1),
            "populated manifest omitted reviewed digest for {}",
            expected.0
        );
    }
    assert!(module_source.contains(
        "include_str!(\"../migrations/\
         20260728000004_activate_operation_claim_completeness.sql\")"
    ));
    assert!(module_source
        .contains("include_str!(\"../docs/operation_claim_completeness_activation.sql\")"));
    assert!(module_source.contains("OPERATION_CLAIM_00004_REPAIRED_SHA384"));
    assert!(module_source.contains("compact_sql(POPULATED_UPGRADE_00004_SOURCE)"));
    let approval_set = body
        .find("SET LOCAL chat.operation_claim_activation_approved")
        .expect("exact local activation approval");
    assert!(body[approval_set..body.len().min(approval_set + 180)]
        .contains("'handlers-and-legacy-apis-sealed'"));
    let complete_source_sink = ["sqlx::", "raw_sql("].concat();
    assert_eq!(body.matches(&complete_source_sink).count(), 2);

    let fixture_insert = "INSERT INTO chat.idempotency_records";
    assert_eq!(
        body.matches(fixture_insert).count(),
        2,
        "one legacy receipt plus one savepoint-contained rejection are required"
    );
    let activation = body
        .find("POPULATED_UPGRADE_00004_SOURCE")
        .expect("actual 00004 source execution");
    let savepoint = body
        .find("SAVEPOINT post_cutover_receipt_without_claim")
        .expect("typed post-cutover rejection savepoint");
    assert!(drop_position < activation && activation < savepoint);
    assert!(body.contains("seeded_receipt_only_count, 1"));
    assert!(body.contains("validate_durable_operation_claim_completeness"));
    assert_eq!(
        body.matches("validate_durable_operation_claim_completeness")
            .count(),
        3,
        "pre, populated, and restored states must share one validator"
    );
    assert!(body.contains("database_error.code().as_deref(), Some(\"23503\")"));
    assert!(body.contains("Some(\"idempotency_records_operation_claim_fk\")"));
    assert!(body.contains("ROLLBACK TO SAVEPOINT post_cutover_receipt_without_claim"));
    assert!(body.contains("RELEASE SAVEPOINT post_cutover_receipt_without_claim"));

    assert_eq!(code.matches(".rollback()").count(), 1);
    let immediate = body
        .rfind("SET CONSTRAINTS ALL IMMEDIATE")
        .expect("outer immediate constraint proof");
    let rollback = code.find(".rollback()").expect("outer rollback finalizer");
    assert!(immediate < rollback);
    let observer_connect = code
        .rfind("PgConnection::connect(")
        .expect("fresh observer connection");
    assert!(
        rollback < observer_connect,
        "observer must not open before outer rollback"
    );
    assert_eq!(code.matches("PgConnection::connect(").count(), 2);
    let post_baseline = body
        .find("post_completeness")
        .expect("fresh observer full restoration proof");
    let observer_close = code.find(".close()").expect("fresh observer close");
    let unlock_position = body.find(unlock).expect("session unlock");
    let original_close = code.rfind(".close()").expect("original connection close");
    assert!(
        observer_connect < post_baseline
            && post_baseline < observer_close
            && observer_close < unlock_position
            && unlock_position < original_close
    );

    let commit_method = [".com", "mit()"].concat();
    let transaction_commit = ["Transaction::", "commit"].concat();
    let sql_commit = ["\"", "COMMIT", "\""].concat();
    let reset = ["reset", "_chat"].concat();
    let drop_database = ["DROP", " DATABASE"].concat();
    let create_database = ["A0_CREATE_", "DATABASE_SQL"].concat();
    let admin_target = ["127.0.0.1:5432", "/postgres"].concat();
    let marker_intent = ["A0_", "INTENT_PATH"].concat();
    let marker_consumed = ["A0_", "CONSUMED_PATH"].concat();
    let delete_ledger = ["DELETE FROM public.", "_sqlx_migrations"].concat();
    let update_ledger = ["UPDATE public.", "_sqlx_migrations"].concat();
    let insert_ledger = ["INSERT INTO public.", "_sqlx_migrations"].concat();
    let alter_ledger = ["ALTER TABLE public.", "_sqlx_migrations"].concat();
    let truncate_ledger = ["TRUNCATE public.", "_sqlx_migrations"].concat();
    let direct_classifier = ["operation_claim_required", " IS FALSE"].concat();
    for forbidden in [
        commit_method,
        transaction_commit,
        sql_commit,
        reset,
        drop_database,
        create_database,
        admin_target,
        marker_intent,
        marker_consumed,
        delete_ledger,
        update_ledger,
        insert_ledger,
        alter_ledger,
        truncate_ledger,
        direct_classifier,
    ] {
        assert!(
            !body.contains(&forbidden),
            "populated-upgrade exception retained forbidden seam: {forbidden}"
        );
    }
}

fn rust_tokio_test_names(source: &str) -> Vec<String> {
    let projected = rust_code_projection(source);
    let mut names = Vec::new();
    let mut cursor = 0_usize;
    while let Some(relative) = projected[cursor..].find("#[tokio::test]") {
        let attribute = cursor + relative;
        let function = projected[attribute..]
            .find("fn ")
            .map(|offset| attribute + offset + 3)
            .expect("tokio test attribute must bind a function");
        let end = projected.as_bytes()[function..]
            .iter()
            .position(|byte| !byte.is_ascii_alphanumeric() && *byte != b'_')
            .map(|offset| function + offset)
            .expect("tokio test name terminator");
        names.push(projected[function..end].to_owned());
        cursor = end;
    }
    names
}

#[test]
fn lane_a_rollback_write_manifest_is_complete_and_immediate() {
    let manifest = Path::new(env!("CARGO_MANIFEST_DIR"));
    let sources = [
        (
            "chat_protocol_operation_claims",
            std::fs::read_to_string(manifest.join("tests/chat_protocol_operation_claims.rs"))
                .expect("read operation-claim rollback target"),
        ),
        (
            "chat_protocol_schema",
            std::fs::read_to_string(manifest.join("tests/chat_protocol_schema.rs"))
                .expect("read schema rollback target"),
        ),
        (
            "chat_protocol_g7_schema",
            std::fs::read_to_string(manifest.join("tests/chat_protocol_g7_schema.rs"))
                .expect("read G7 rollback target"),
        ),
    ];
    assert_eq!(
        sources
            .iter()
            .map(|(target, _)| *target)
            .collect::<Vec<_>>(),
        [
            "chat_protocol_operation_claims",
            "chat_protocol_schema",
            "chat_protocol_g7_schema",
        ]
    );
    let expected: BTreeSet<(&str, &str)> = [
        (
            "chat_protocol_operation_claims",
            "deferred_mapping_rejects_allowed_but_wrong_exact_kind",
        ),
        (
            "chat_protocol_operation_claims",
            "deferred_mapping_rejects_endpoint_incompatible_submit_transition_kind",
        ),
        (
            "chat_protocol_operation_claims",
            "deferred_mapping_rejects_wrapper_kind_that_disagrees_with_transcript",
        ),
        (
            "chat_protocol_operation_claims",
            "exact_claim_receipt_mapping_passes_and_rollback_releases_the_id",
        ),
        (
            "chat_protocol_operation_claims",
            "claim_without_exactly_one_receipt_is_rejected_and_rollback_releases_the_id",
        ),
        (
            "chat_protocol_schema",
            "post_clean_public_ledger_attached_object_mutations_fail_closed",
        ),
        (
            "chat_protocol_schema",
            "operation_claim_completeness_populated_upgrade_is_atomic_and_rollback_only",
        ),
        (
            "chat_protocol_g7_schema",
            "g7_installed_interval_validator_is_snapshot_bound_and_deterministic",
        ),
        (
            "chat_protocol_g7_schema",
            "g7_receipt_shape_rejects_null_boolean_and_mixed_successor",
        ),
        (
            "chat_protocol_g7_schema",
            "g7_live_catalog_has_closed_arms_receipts_and_trigger_guards",
        ),
    ]
    .into_iter()
    .collect();
    assert_eq!(expected.len(), 10);

    let helper_name = "force_constraints_and_rollback";
    let commit_method = [".com", "mit()"].concat();
    let helper_source = &sources
        .iter()
        .find(|(target, _)| *target == "chat_protocol_g7_schema")
        .expect("G7 rollback target")
        .1;
    let helper_body = rust_function_body(helper_source, helper_name);
    let helper_code = rust_code_projection(helper_body);
    assert_eq!(helper_code.matches(".rollback()").count(), 1);
    assert_eq!(helper_code.matches(&commit_method).count(), 0);
    let helper_immediate = helper_body
        .find("SET CONSTRAINTS ALL IMMEDIATE")
        .expect("reviewed helper immediate evaluation");
    let helper_rollback = helper_code
        .find(".rollback()")
        .expect("reviewed helper rollback");
    assert!(helper_immediate < helper_rollback);
    assert!(
        helper_body[helper_immediate..helper_rollback].contains(".execute(&mut *transaction)"),
        "reviewed helper must evaluate constraints on its owned transaction"
    );
    assert!(!helper_code.contains("return transaction"));
    let by_value_signature = "transaction: sqlx::Transaction<'_, sqlx::Postgres>";
    let mut by_value_inventory = Vec::new();
    for (target, source) in &sources {
        let projected = rust_code_projection(source);
        by_value_inventory.extend(
            projected
                .match_indices(by_value_signature)
                .map(|(offset, _)| (*target, offset)),
        );
    }
    assert_eq!(
        by_value_inventory.len(),
        1,
        "unreviewed transaction-consuming helper inventory"
    );
    let (helper_start, _, _) = rust_function_bounds(helper_source, helper_name);
    assert!(
        by_value_inventory[0].0 == "chat_protocol_g7_schema"
            && by_value_inventory[0].1 > helper_start
            && by_value_inventory[0].1 < helper_start + 300,
        "sole by-value transaction owner is not the reviewed helper"
    );

    let mut discovered = BTreeSet::new();
    let mut helper_callers = Vec::new();
    for (target, source) in &sources {
        for test_name in rust_tokio_test_names(source) {
            let body = rust_function_body(source, &test_name);
            let code = rust_code_projection(body);
            let direct_rollbacks = code.match_indices(".rollback()").collect::<Vec<_>>();
            if !direct_rollbacks.is_empty() {
                assert_eq!(
                    direct_rollbacks.len(),
                    1,
                    "{target}/{test_name} has an unreviewed alternate rollback finalizer"
                );
                assert!(
                    !code.contains(&commit_method),
                    "{target}/{test_name} can commit a rollback-write transaction"
                );
                let immediate = body
                    .rfind("SET CONSTRAINTS ALL IMMEDIATE")
                    .unwrap_or_else(|| {
                        panic!("{target}/{test_name} omits same-transaction immediate evaluation")
                    });
                assert!(
                    immediate < direct_rollbacks[0].0,
                    "{target}/{test_name} rolls back before immediate evaluation"
                );
                assert!(
                    body[immediate..direct_rollbacks[0].0].contains(".execute(&mut *transaction)"),
                    "{target}/{test_name} does not evaluate constraints on its owned transaction"
                );
                discovered.insert((*target, test_name.clone()));
            }
            let helper_call = format!("{helper_name}(transaction)");
            if code.contains(&helper_call) {
                assert_eq!(
                    code.matches(&helper_call).count(),
                    1,
                    "{target}/{test_name} moves its transaction to the helper more than once"
                );
                assert!(
                    direct_rollbacks.is_empty() && !code.contains(&commit_method),
                    "{target}/{test_name} has an alternate transaction finalizer"
                );
                helper_callers.push((*target, test_name.clone()));
                discovered.insert((*target, test_name));
            }
        }
    }
    assert_eq!(
        helper_callers,
        [(
            "chat_protocol_g7_schema",
            "g7_live_catalog_has_closed_arms_receipts_and_trigger_guards".to_owned(),
        )]
    );
    let discovered: BTreeSet<(&str, &str)> = discovered
        .iter()
        .map(|(target, test)| (*target, test.as_str()))
        .collect();
    assert_eq!(
        discovered, expected,
        "Lane-A direct/helper rollback-write discovery drift"
    );
}

fn stable_multiset_delta(
    expected: &[&str],
    observed: &[&str],
) -> (BTreeMap<String, usize>, BTreeMap<String, usize>) {
    let counts = |values: &[&str]| {
        let mut result = BTreeMap::new();
        for value in values {
            *result.entry((*value).to_owned()).or_insert(0) += 1;
        }
        result
    };
    let expected_counts = counts(expected);
    let observed_counts = counts(observed);
    let mut missing = BTreeMap::new();
    let mut extra = BTreeMap::new();
    for (identity, expected_count) in &expected_counts {
        let observed_count = observed_counts.get(identity).copied().unwrap_or(0);
        if observed_count < *expected_count {
            missing.insert(identity.clone(), expected_count - observed_count);
        }
    }
    for (identity, observed_count) in &observed_counts {
        let expected_count = expected_counts.get(identity).copied().unwrap_or(0);
        if expected_count < *observed_count {
            extra.insert(identity.clone(), observed_count - expected_count);
        }
    }
    (missing, extra)
}

#[test]
fn internal_constraint_trigger_role_multiset_rejects_offsetting_and_signature_drift() {
    let child_insert = "items|items_parent_fk|items|child_insert|5|pg_catalog.RI_FKey_check_ins()";
    let child_update = "items|items_parent_fk|items|child_update|17|pg_catalog.RI_FKey_check_upd()";
    let parent_delete =
        "items|items_parent_fk|parents|parent_delete|9|pg_catalog.RI_FKey_noaction_del()";
    let parent_update =
        "items|items_parent_fk|parents|parent_update|17|pg_catalog.RI_FKey_noaction_upd()";
    let expected = [child_insert, child_update, parent_delete, parent_update];

    let offsetting = [child_insert, child_insert, parent_delete, parent_update];
    let (missing, extra) = stable_multiset_delta(&expected, &offsetting);
    assert_eq!(missing.get(child_update), Some(&1));
    assert_eq!(extra.get(child_insert), Some(&1));

    let wrong_namespace = "items|items_parent_fk|items|child_insert|5|chat.RI_FKey_check_ins()";
    let wrong_signature =
        "items|items_parent_fk|items|child_update|17|pg_catalog.RI_FKey_check_upd(oid)";
    let drifted = [
        wrong_namespace,
        wrong_signature,
        parent_delete,
        parent_update,
    ];
    let (missing, extra) = stable_multiset_delta(&expected, &drifted);
    assert_eq!(missing.len(), 2);
    assert_eq!(extra.len(), 2);
    assert_eq!(extra.get(wrong_namespace), Some(&1));
    assert_eq!(extra.get(wrong_signature), Some(&1));
}

fn compact_sql(sql: &str) -> String {
    sql.split_whitespace().collect::<Vec<_>>().join(" ")
}

fn create_table_block<'a>(sql: &'a str, table: &str, next: &str) -> &'a str {
    sql.split_once(&format!("CREATE TABLE chat.{table} ("))
        .unwrap_or_else(|| panic!("missing chat.{table} table"))
        .1
        .split_once(next)
        .unwrap_or_else(|| panic!("missing end marker for chat.{table}"))
        .0
}

fn function_block<'a>(sql: &'a str, function: &str, next: &str) -> &'a str {
    sql.split_once(function)
        .unwrap_or_else(|| panic!("missing function marker: {function}"))
        .1
        .split_once(next)
        .unwrap_or_else(|| panic!("missing end marker after {function}: {next}"))
        .0
}

fn assert_source_contract(cluster: &str, checks: &[(&str, bool)]) {
    let missing = checks
        .iter()
        .filter_map(|(contract, present)| (!present).then_some(*contract))
        .collect::<Vec<_>>();
    assert!(
        missing.is_empty(),
        "{cluster} source contract is incomplete:\n- {}",
        missing.join("\n- ")
    );
}

#[test]
fn audit_delivery_audiences_require_control_entries_and_exact_provenance() {
    let sql =
        std::fs::read_to_string(migration_dir().join("20260722000002_chat_protocol_delivery.sql"))
            .expect("read delivery migration");
    let compact = compact_sql(&sql);
    let entries = compact_sql(create_table_block(
        &sql,
        "entries",
        "ALTER TABLE chat.transitions",
    ));
    let recipients = compact_sql(create_table_block(
        &sql,
        "entry_recipients",
        "CREATE INDEX entry_recipients_device_scan_idx",
    ));
    let mapping = compact_sql(function_block(
        &sql,
        "CREATE FUNCTION chat.assert_entry_recipient_mapping(",
        "CREATE FUNCTION chat.enforce_entry_recipient_mapping()",
    ));

    assert_source_contract(
        "delivery audience",
        &[
            (
                "entry recipients retain the closed control/intervalClose/scheduleTerminal arms",
                recipients
                    .contains("entitlement_kind IN ('control','intervalClose','scheduleTerminal')"),
            ),
            (
                "application entries cannot acquire any entry_recipients audience row",
                mapping.contains("JOIN chat.entries entry")
                    && mapping.contains(
                        "entry.entry_kind <> 'blue.catbird.chat.defs#applicationEntry'",
                    ),
            ),
            (
                "the control arm is positively checked against a non-application entry",
                mapping.contains("recipient_kind = 'control'")
                    && mapping.contains("entry.entry_kind")
                    && mapping.contains("applicationEntry"),
            ),
            (
                // Relocated enforcement: the intervalClose "binds the exact closing
                // transition and outer fingerprint" invariant is now a hard composite
                // FK from chat.application_intervals -> chat.entries' transition/
                // fingerprint unique key, not inline plpgsql in
                // assert_entry_recipient_mapping. Assert the FK + its unique target.
                "intervalClose routing binds the exact closing transition and outer fingerprint",
                compact.contains(
                    "CONSTRAINT application_intervals_closing_provenance_fk FOREIGN KEY ( conversation_id, terminal_seq, closing_transition_id, closing_outer_entry_fingerprint ) REFERENCES chat.entries( conversation_id, seq, transition_id, outer_entry_fingerprint )",
                ) && compact.contains(
                    "CONSTRAINT entries_transition_fingerprint_uq UNIQUE ( conversation_id, seq, transition_id, outer_entry_fingerprint )",
                ),
            ),
            (
                // Relocated enforcement: the scheduleTerminal "binds the exact terminal
                // transition and outer fingerprint" invariant is now a hard composite
                // FK from chat.application_schedule_terminal_proofs -> chat.entries'
                // transition/fingerprint unique key. Assert the FK + its unique target.
                "scheduleTerminal routing binds the exact terminal transition and outer fingerprint",
                compact.contains(
                    "CONSTRAINT application_schedule_terminal_proofs_provenance_fk FOREIGN KEY ( conversation_id, terminal_seq, transition_id, outer_entry_fingerprint ) REFERENCES chat.entries( conversation_id, seq, transition_id, outer_entry_fingerprint )",
                ) && compact.contains(
                    "CONSTRAINT entries_transition_fingerprint_uq UNIQUE ( conversation_id, seq, transition_id, outer_entry_fingerprint )",
                ),
            ),
            (
                "entry fingerprints and signatures remain fixed-size protocol authority",
                entries.contains("octet_length(request_digest) = 32")
                    && entries.contains("octet_length(signature) = 64")
                    && entries.contains("octet_length(outer_entry_fingerprint) = 32"),
            ),
            (
                "schedule terminal proof completeness remains exact-device and once-per-schedule",
                compact.contains(
                    "PRIMARY KEY (conversation_id, recipient_did, recipient_device_id)",
                ) && compact.contains(
                    "CREATE FUNCTION chat.assert_conversation_terminal_schedules(target_conversation UUID)",
                ),
            ),
        ],
    );
}

#[test]
fn audit_inventory_items_bind_exact_device_sources_and_typed_terminal_proofs() {
    let sql =
        std::fs::read_to_string(migration_dir().join("20260722000002_chat_protocol_delivery.sql"))
            .expect("read delivery migration");
    let conversation_items = compact_sql(create_table_block(
        &sql,
        "inventory_conversation_items",
        "CREATE TABLE chat.inventory_welcome_items",
    ));
    let welcome_items = compact_sql(create_table_block(
        &sql,
        "inventory_welcome_items",
        "CREATE TABLE chat.inventory_recovery_items",
    ));
    let recovery_items = compact_sql(create_table_block(
        &sql,
        "inventory_recovery_items",
        "CREATE TABLE chat.device_inventory_sessions",
    ));
    let device_items = compact_sql(create_table_block(
        &sql,
        "device_inventory_items",
        "CREATE TABLE chat.subscription_tickets",
    ));
    let materialization = compact_sql(function_block(
        &sql,
        "CREATE FUNCTION chat.assert_inventory_materialization(target_session UUID)",
        "CREATE FUNCTION chat.enforce_inventory_materialization()",
    ));

    assert_source_contract(
        "inventory provenance",
        &[
            (
                "conversation inventory items repeat their exact recipient DID/device",
                conversation_items.contains("recipient_did TEXT NOT NULL")
                    && conversation_items.contains("recipient_device_id UUID NOT NULL"),
            ),
            (
                "conversation inventory has typed all-or-none schedule-terminal proof columns",
                conversation_items.contains("schedule_terminal_seq BIGINT")
                    && conversation_items.contains("schedule_terminal_transition_id UUID")
                    && conversation_items
                        .contains("schedule_terminal_outer_entry_fingerprint BYTEA")
                    && conversation_items
                        .contains("inventory_conversation_items_schedule_terminal_shape_check"),
            ),
            (
                "conversation inventory proof identity has an exact composite FK",
                conversation_items.contains(
                    "FOREIGN KEY ( conversation_id, recipient_did, recipient_device_id, schedule_terminal_seq, schedule_terminal_transition_id, schedule_terminal_outer_entry_fingerprint ) REFERENCES chat.application_schedule_terminal_proofs",
                ),
            ),
            (
                "Welcome inventory items repeat the source recipient and bind that delivery",
                welcome_items.contains("recipient_did TEXT NOT NULL")
                    && welcome_items.contains("recipient_device_id UUID NOT NULL")
                    && welcome_items.contains(
                        "FOREIGN KEY (welcome_id, recipient_did, recipient_device_id)",
                    ),
            ),
            (
                "recovery inventory items repeat the source recipient and bind either exact source",
                recovery_items.contains("recipient_did TEXT NOT NULL")
                    && recovery_items.contains("recipient_device_id UUID NOT NULL")
                    && recovery_items.contains(
                        "leaf_recovery_request_id, recipient_did, recipient_device_id",
                    )
                    && recovery_items
                        .contains("recovery_work_id, recipient_did, recipient_device_id"),
            ),
            (
                "device inventory items repeat the requesting exact-device session identity",
                device_items.contains("requester_did TEXT NOT NULL")
                    && device_items.contains("requester_device_id UUID NOT NULL"),
            ),
            (
                "materialization verifies session/device/source joins, not only hashes and counts",
                materialization.contains("JOIN chat.inventory_sessions session")
                    && materialization.contains("recipient_did = session.user_did")
                    && materialization.contains("recipient_device_id = session.device_id")
                    && materialization.contains("JOIN chat.application_schedule_terminal_proofs"),
            ),
            (
                "inventory tokens remain hash-only",
                sql.contains("token_hash BYTEA NOT NULL UNIQUE")
                    && !sql.contains("inventory_token TEXT"),
            ),
        ],
    );
}

#[test]
fn audit_inventory_is_bounded_gc_controlled_all_status_indexed_and_strictly_expiring() {
    let core =
        std::fs::read_to_string(migration_dir().join("20260722000001_chat_protocol_core.sql"))
            .expect("read core migration");
    let sql =
        std::fs::read_to_string(migration_dir().join("20260722000002_chat_protocol_delivery.sql"))
            .expect("read delivery migration");
    let compact = compact_sql(&sql);
    let sessions = compact_sql(create_table_block(
        &sql,
        "inventory_sessions",
        "CREATE TABLE chat.inventory_conversation_items",
    ));
    let device_sessions = compact_sql(create_table_block(
        &sql,
        "device_inventory_sessions",
        "CREATE TABLE chat.device_inventory_items",
    ));
    let tickets = compact_sql(create_table_block(
        &sql,
        "subscription_tickets",
        "CREATE FUNCTION chat.assert_inventory_session_identity",
    ));
    let welcomes = compact_sql(create_table_block(
        &sql,
        "welcome_deliveries",
        "CREATE INDEX welcome_deliveries_pending_device_idx",
    ));

    assert_source_contract(
        "bounded inventory lifecycle",
        &[
            (
                "item inserts do not invoke whole-session materialization rescans",
                !sql.contains("inventory_conversation_items_materialization_deferred")
                    && !sql.contains("inventory_welcome_items_materialization_deferred")
                    && !sql.contains("inventory_recovery_items_materialization_deferred")
                    && !sql.contains("device_inventory_items_materialization_deferred"),
            ),
            (
                "historical schedule close fanout has a structural configured ceiling",
                compact.contains("CREATE FUNCTION chat.max_historical_schedule_fanout()")
                    && compact.contains(
                        "CREATE FUNCTION chat.assert_historical_schedule_fanout(target_conversation UUID)",
                    )
                    && compact.contains("historical_schedule_fanout_exceeded"),
            ),
            (
                "shared inventory sessions have a finite maximum lifetime",
                sessions.contains("expires_at <= created_at + INTERVAL"),
            ),
            (
                "device inventory sessions have a finite maximum lifetime",
                device_sessions.contains("expires_at <= created_at + INTERVAL"),
            ),
            (
                "expired shared/device inventory sessions have bounded SKIP LOCKED GC",
                compact.contains(
                    "CREATE FUNCTION chat.gc_expired_inventory_sessions(batch_limit INTEGER",
                ) && compact.contains("FOR UPDATE SKIP LOCKED")
                    && compact.contains("LIMIT batch_limit")
                    && compact.contains("inventory_sessions_expiry_gc_idx")
                    && compact.contains("device_inventory_sessions_expiry_gc_idx"),
            ),
            (
                "active retained sessions per exact DID/device are capped under a device lock",
                compact.contains(
                    "CREATE FUNCTION chat.assert_exact_device_inventory_session_cap(",
                ) && compact.contains("max_active_inventory_sessions")
                    && compact.contains("FOR UPDATE"),
            ),
            (
                "leaf recovery has a non-partial exact-device all-status lookup index",
                core.contains("CREATE INDEX leaf_recovery_requests_device_all_status_idx")
                    && core.contains(
                        "ON chat.leaf_recovery_requests (requester_did, requester_device_id, status",
                    ),
            ),
            (
                "Welcome and recovery-work lookups have non-partial exact-device all-status indexes",
                compact.contains("CREATE INDEX welcome_deliveries_device_all_status_idx")
                    && compact.contains(
                        "ON chat.welcome_deliveries (recipient_did, recipient_device_id, status",
                    )
                    && compact.contains("CREATE INDEX recovery_work_items_device_all_status_idx")
                    && compact.contains(
                        "ON chat.recovery_work_items (recipient_did, recipient_device_id, status",
                    ),
            ),
            (
                "subscription ticket consumption rejects exact expiry",
                tickets.contains("consumed_at >= created_at AND consumed_at < expires_at")
                    && !tickets.contains("BETWEEN created_at AND expires_at"),
            ),
            (
                "non-expiry Welcome terminal decisions reject exact expiry",
                welcomes.contains("terminal_at < expires_at")
                    && !welcomes.contains("terminal_at <= expires_at"),
            ),
            (
                "protocol-instance event fencing remains present",
                compact.contains("events_protocol_instance_fk")
                    && compact.contains("event_retention_instance_fk"),
            ),
        ],
    );
}

#[test]
fn audit_blob_keys_binding_lifetimes_and_object_gc_are_unambiguous() {
    let sql =
        std::fs::read_to_string(migration_dir().join("20260722000003_chat_protocol_blobs.sql"))
            .expect("read blob migration");
    let compact = compact_sql(&sql);
    let blobs = compact_sql(create_table_block(
        &sql,
        "blobs",
        "CREATE INDEX blobs_live_owner_idx",
    ));
    let tickets = compact_sql(create_table_block(
        &sql,
        "blob_upload_tickets",
        "ALTER TABLE chat.metadata_snapshots",
    ));
    let bindings = compact_sql(create_table_block(
        &sql,
        "blob_bindings",
        "CREATE FUNCTION chat.assert_blob_binding_lifecycle",
    ));
    let lifecycle = compact_sql(function_block(
        &sql,
        "CREATE FUNCTION chat.enforce_blob_lifecycle_transition()",
        "CREATE UNIQUE INDEX blob_bindings_application_entry_uq",
    ));

    assert_source_contract(
        "blob identity and lifetime",
        &[
            (
                "non-null object-store keys uniquely identify one blob row",
                compact.contains("CREATE UNIQUE INDEX blobs_object_store_key_uq")
                    && compact.contains("ON chat.blobs (object_store_key)")
                    && compact.contains("WHERE object_store_key IS NOT NULL"),
            ),
            (
                "upload completion rejects the exact upload expiry instant",
                lifecycle.contains("NEW.uploaded_at >= NEW.upload_expires_at")
                    && !lifecycle.contains("NEW.uploaded_at > NEW.upload_expires_at"),
            ),
            (
                "blob-ticket consumption rejects exact expiry",
                tickets.contains("consumed_at >= created_at AND consumed_at < expires_at")
                    && !tickets.contains("BETWEEN created_at AND expires_at"),
            ),
            (
                "completedUnbound to bound proves uploaded_at <= bound_at < unbound_expires_at",
                blobs.contains("uploaded_at <= bound_at")
                    && blobs.contains("bound_at < unbound_expires_at"),
            ),
            (
                "the binding row carries the same strict bind-time ordering",
                bindings.contains("blob_bindings_bound_at_check")
                    && bindings.contains("bound_at <")
                    && bindings.contains("unbound_expires_at"),
            ),
            (
                "zero-reference object GC has explicit status/times and a claimable index",
                blobs.contains("object_gc_status TEXT")
                    && blobs.contains("object_gc_after TIMESTAMPTZ")
                    && blobs.contains("object_deleted_at TIMESTAMPTZ")
                    && compact.contains("CREATE INDEX blobs_object_gc_claim_idx")
                    && compact.contains("WHERE object_gc_status = 'pending'"),
            ),
            (
                "object GC is bounded and uses locked claims",
                compact.contains("CREATE FUNCTION chat.claim_blob_object_gc(batch_limit INTEGER")
                    && compact.contains("FOR UPDATE SKIP LOCKED")
                    && compact.contains("LIMIT batch_limit"),
            ),
            (
                "application/metadata binding purpose split remains closed",
                bindings.contains("binding_kind IN ('application','metadataAvatar')")
                    && bindings.contains("binding_kind = 'application' AND purpose = 'attachment'")
                    && bindings
                        .contains("binding_kind = 'metadataAvatar' AND purpose = 'metadata'"),
            ),
            (
                "blob upload secrets remain hash-only",
                tickets.contains("ticket_hash BYTEA PRIMARY KEY")
                    && !tickets.contains("ticket_token TEXT"),
            ),
        ],
    );
}

#[test]
fn audit_blob_accounting_is_incremental_bounded_and_cleanup_controlled() {
    let sql =
        std::fs::read_to_string(migration_dir().join("20260722000003_chat_protocol_blobs.sql"))
            .expect("read blob migration");
    let compact = compact_sql(&sql);
    let usage = compact_sql(create_table_block(
        &sql,
        "blob_usage",
        "CREATE TABLE chat.blobs",
    ));
    let reconciliation = compact_sql(function_block(
        &sql,
        "CREATE FUNCTION chat.assert_blob_usage(target_did TEXT)",
        "CREATE FUNCTION chat.enforce_blob_usage()",
    ));

    assert_source_contract(
        "blob accounting and cleanup",
        &[
            (
                "per-row blob mutations do not rescan full owner history",
                !reconciliation.contains("FROM chat.blobs")
                    && !reconciliation.contains("sum(ciphertext_size)")
                    && !reconciliation.contains("count(*) FILTER"),
            ),
            (
                "usage deltas are applied atomically under the principal anchor",
                compact.contains("CREATE FUNCTION chat.apply_blob_usage_delta(")
                    && compact.contains("UPDATE chat.blob_usage")
                    && compact.contains("FOR UPDATE"),
            ),
            (
                "the existing 500 MiB and 100-live-unbound owner caps remain",
                usage.contains("used_ciphertext_bytes + reserved_ciphertext_bytes <= 524288000")
                    && usage.contains("live_unbound_count <= 100"),
            ),
            (
                "active blobs have a bounded exact-device lookup index",
                compact.contains("CREATE INDEX blobs_active_device_idx")
                    && compact.contains("ON chat.blobs (owner_did, owner_device_id, status")
                    && compact.contains("WHERE status IN ('prepared','completedUnbound')"),
            ),
            (
                "active prepared/unbound rows per exact device have a hard cap",
                compact.contains("CREATE FUNCTION chat.assert_blob_device_active_cap(")
                    && compact.contains("max_active_blobs_per_device")
                    && compact.contains("FOR UPDATE"),
            ),
            (
                "terminal upload tickets have controlled bounded GC",
                compact.contains("blob_upload_tickets_terminal_gc_idx")
                    && compact.contains(
                        "CREATE FUNCTION chat.gc_terminal_blob_upload_tickets(batch_limit INTEGER",
                    )
                    && compact.contains("FOR UPDATE SKIP LOCKED")
                    && compact.contains("LIMIT batch_limit"),
            ),
            (
                "pending-CAS lifecycle remains terminal after ticket consumption",
                compact.contains("OLD.consumed_at IS NOT NULL AND NEW IS DISTINCT FROM OLD"),
            ),
        ],
    );
}

#[test]
fn recovery_schema_declares_closed_sources_and_collision_free_inventory_arms() {
    let sql =
        std::fs::read_to_string(migration_dir().join("20260722000002_chat_protocol_delivery.sql"))
            .expect("read delivery migration");
    let compact = compact_sql(&sql);
    let work = compact_sql(create_table_block(
        &sql,
        "recovery_work_items",
        "CREATE INDEX recovery_work_items_pending_device_idx",
    ));
    let inventory = compact_sql(create_table_block(
        &sql,
        "inventory_recovery_items",
        "CREATE TABLE chat.device_inventory_sessions",
    ));

    for required in [
        "terminal_revocation_id UUID",
        "CONSTRAINT recovery_work_items_coordinate_fk FOREIGN KEY (conversation_id, generation, state_version)",
        "REFERENCES chat.generation_states(conversation_id, generation, state_version) DEFERRABLE INITIALLY DEFERRED",
        "CONSTRAINT recovery_work_items_source_fk FOREIGN KEY (source_id) REFERENCES chat.welcome_dispositions(welcome_id) DEFERRABLE INITIALLY DEFERRED",
        "CONSTRAINT recovery_work_items_source_uq UNIQUE (source_id)",
        "CONSTRAINT recovery_work_items_terminal_revocation_fk FOREIGN KEY (recipient_did, recipient_device_id, terminal_revocation_id, terminal_at)",
        "num_nonnulls(terminal_transition_id, terminal_revocation_id) = 1",
    ] {
        assert!(work.contains(required), "missing recovery-work invariant: {required}");
    }
    assert!(
        work.contains("source_kind IN ('welcomeExpired','welcomeRejected')"),
        "recovery-work sources must be the two closed Welcome disposition arms"
    );
    for forbidden in ["poisonedState", "joinFailure"] {
        assert!(
            !work.contains(forbidden),
            "unmodeled recovery-work source remains admitted: {forbidden}"
        );
    }

    for required in [
        "item_kind TEXT NOT NULL",
        "leaf_recovery_request_id UUID",
        "recovery_work_id UUID",
        "item_kind IN ('leafRecoveryRequest','recoveryWork')",
        "octet_length(item_key_bytes) = 17",
        "decode('00', 'hex') || uuid_send(leaf_recovery_request_id)",
        "decode('01', 'hex') || uuid_send(recovery_work_id)",
        "CONSTRAINT inventory_recovery_items_request_fk FOREIGN KEY (leaf_recovery_request_id)",
        "CONSTRAINT inventory_recovery_items_work_fk FOREIGN KEY (recovery_work_id)",
        "CONSTRAINT inventory_recovery_items_request_uq UNIQUE (inventory_session_id, leaf_recovery_request_id)",
        "CONSTRAINT inventory_recovery_items_work_uq UNIQUE (inventory_session_id, recovery_work_id)",
    ] {
        assert!(inventory.contains(required), "missing recovery inventory invariant: {required}");
    }

    for required in [
        "CREATE FUNCTION chat.assert_recovery_work_integrity(target_welcome UUID)",
        "CREATE CONSTRAINT TRIGGER welcome_dispositions_recovery_work_deferred",
        "CREATE CONSTRAINT TRIGGER recovery_work_items_integrity_deferred",
        "work_row.status = 'superseded'",
        "transition.prior_generation = work_row.generation",
        "transition.prior_state_version = work_row.state_version",
        "(transition.next_generation, transition.next_state_version) IS DISTINCT FROM (work_row.generation, work_row.state_version)",
        "revocation.target_did = work_row.recipient_did",
        "revocation.target_device_id = work_row.recipient_device_id",
        "request.requester_did = work_row.recipient_did",
        "request.requester_device_id = work_row.recipient_device_id",
        "request.fulfilling_transition_id = work_row.terminal_transition_id",
        "transition.kind = 'leafRecovery'",
        "CREATE FUNCTION chat.assert_inventory_materialization(target_session UUID)",
        "int8send(ordinal) || item_key_bytes || payload_sha256",
        "'status', 'terminal_transition_id', 'terminal_revocation_id', 'terminal_at'",
    ] {
        assert!(
            compact.contains(required),
            "missing deferred/catalog invariant: {required}"
        );
    }
}

#[test]
fn welcome_supersession_schema_declares_exact_exclusive_durable_sources() {
    let build_script =
        std::fs::read_to_string(PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("build.rs"))
            .expect("read Cargo build script");
    assert!(
        build_script.contains("println!(\"cargo:rerun-if-changed=migrations\")"),
        "compile-time SQLx migration inventory must rebuild when migrations change"
    );

    let preflight = std::fs::read_to_string(
        migration_dir().join("20260725000001_prepare_welcome_provenance_backfill.sql"),
    )
    .expect("read Welcome provenance preflight migration");
    let quarantine = std::fs::read_to_string(
        migration_dir().join("20260725000002_refine_welcome_provenance_quarantine.sql"),
    )
    .expect("read Welcome provenance quarantine migration");
    let sql = std::fs::read_to_string(
        migration_dir().join("20260726000001_welcome_supersession_provenance.sql"),
    )
    .expect("read Welcome supersession provenance migration");
    let postflight = std::fs::read_to_string(
        migration_dir().join("20260726000002_restore_welcome_provenance_deferred_triggers.sql"),
    )
    .expect("read Welcome provenance postflight migration");
    let finalizer = std::fs::read_to_string(
        migration_dir().join("20260726000003_finalize_welcome_provenance_triggers.sql"),
    )
    .expect("read Welcome provenance finalizer migration");
    let preflight = compact_sql(&preflight);
    let quarantine = compact_sql(&quarantine);
    let compact = compact_sql(&sql);
    let postflight = compact_sql(&postflight);
    let finalizer = compact_sql(&finalizer);

    for required in [
        "CREATE CONSTRAINT TRIGGER welcome_dispositions_delivery_cas_deferred",
        "AFTER INSERT OR UPDATE OR DELETE ON chat.welcome_dispositions",
        "DEFERRABLE INITIALLY IMMEDIATE",
        "EXECUTE FUNCTION chat.enforce_welcome_disposition_cas()",
        "CREATE CONSTRAINT TRIGGER welcome_dispositions_recovery_work_deferred",
        "EXECUTE FUNCTION chat.enforce_recovery_work_integrity()",
    ] {
        assert!(
            preflight.contains(required),
            "missing Welcome provenance preflight invariant: {required}"
        );
    }

    for required in [
        "trigger_row.tgenabled = 'O'",
        "trigger_row.tgtype = 27",
        "function_namespace.nspname = 'chat'",
        "function_row.proname = 'enforce_immutable_identity'",
        "CREATE CONSTRAINT TRIGGER welcome_dispositions_delivery_cas_deferred",
        "AFTER INSERT OR DELETE ON chat.welcome_dispositions",
        "DEFERRABLE INITIALLY DEFERRED",
        "CREATE CONSTRAINT TRIGGER welcome_dispositions_recovery_work_deferred",
    ] {
        assert!(
            quarantine.contains(required),
            "missing Welcome provenance quarantine invariant: {required}"
        );
    }

    for required in [
        "ADD COLUMN IF NOT EXISTS terminal_transition_id UUID",
        "ADD COLUMN IF NOT EXISTS terminal_revocation_id UUID",
        "welcome_dispositions_terminal_source_shape_check",
        "num_nonnulls( terminal_transition_id, terminal_revocation_id ) = 1",
        "winner_kind <> 'superseded' AND terminal_transition_id IS NULL AND terminal_revocation_id IS NULL",
        "welcome_dispositions_terminal_transition_fk",
        "REFERENCES chat.transitions(transition_id) DEFERRABLE INITIALLY DEFERRED",
        "welcome_dispositions_terminal_revocation_fk",
        "REFERENCES chat.device_revocations(revocation_id) DEFERRABLE INITIALLY DEFERRED",
        "candidate_count <> 1",
        "transition_row.entry_seq > bundle.entry_seq",
        "transition_row.accepted_at = disposition.terminal_at",
        "transition_row.next_generation, transition_row.next_state_version",
        "prior_state.group_id = bundle.group_id",
        "prior_state.epoch = bundle.epoch",
        "prior_state.group_context_hash = bundle.group_context_hash",
        "prior_state.confirmation_tag = bundle.confirmation_tag",
        "revocation.target_did = delivery.recipient_did",
        "revocation.target_device_id = delivery.recipient_device_id",
        "revocation.accepted_at = disposition.terminal_at",
        "CREATE OR REPLACE FUNCTION chat.assert_welcome_disposition_cas",
        "RAISE EXCEPTION 'terminal Welcome disposition mismatch'",
    ] {
        assert!(
            compact.contains(required),
            "missing Welcome supersession provenance invariant: {required}"
        );
    }

    for required in [
        "FOR target_welcome IN SELECT welcome_id FROM chat.welcome_dispositions ORDER BY welcome_id",
        "PERFORM chat.assert_welcome_disposition_cas(target_welcome)",
        "PERFORM chat.assert_recovery_work_integrity(target_welcome)",
        "CREATE CONSTRAINT TRIGGER welcome_dispositions_delivery_cas_deferred",
        "AFTER INSERT OR UPDATE OR DELETE ON chat.welcome_dispositions",
        "DEFERRABLE INITIALLY DEFERRED",
        "EXECUTE FUNCTION chat.enforce_welcome_disposition_cas()",
        "CREATE CONSTRAINT TRIGGER welcome_dispositions_recovery_work_deferred",
        "EXECUTE FUNCTION chat.enforce_recovery_work_integrity()",
    ] {
        assert!(
            postflight.contains(required),
            "missing Welcome provenance postflight invariant: {required}"
        );
    }

    for required in [
        "format_type(atttypid, atttypmod) = 'uuid'",
        "welcome_dispositions_terminal_source_shape_check",
        "welcome_dispositions_terminal_transition_fk",
        "welcome_dispositions_terminal_revocation_fk",
        "FOR target_welcome IN SELECT welcome_id FROM chat.welcome_dispositions ORDER BY welcome_id",
        "PERFORM chat.assert_welcome_disposition_cas(target_welcome)",
        "PERFORM chat.assert_recovery_work_integrity(target_welcome)",
        "CREATE CONSTRAINT TRIGGER welcome_dispositions_delivery_cas_deferred",
        "AFTER INSERT OR UPDATE OR DELETE ON chat.welcome_dispositions",
        "DEFERRABLE INITIALLY DEFERRED",
        "CREATE CONSTRAINT TRIGGER welcome_dispositions_recovery_work_deferred",
    ] {
        assert!(
            finalizer.contains(required),
            "missing Welcome provenance finalizer invariant: {required}"
        );
    }
}

#[test]
fn relationship_schema_declares_bounded_fallback_and_revision_fences() {
    let sql =
        std::fs::read_to_string(migration_dir().join("20260722000001_chat_protocol_core.sql"))
            .expect("read core migration");
    let compact = compact_sql(&sql);
    let snapshots = compact_sql(create_table_block(
        &sql,
        "relationship_projection_snapshots",
        "CREATE INDEX relationship_projection_fallback_lookup_idx",
    ));
    let allocations = compact_sql(create_table_block(
        &sql,
        "relationship_projection_revision_allocations",
        "CREATE FUNCTION chat.allocate_relationship_projection_revision",
    ));
    let assertion = compact_sql(
        sql.split_once(
            "CREATE FUNCTION chat.assert_relationship_projection(target_projection UUID)",
        )
        .expect("missing relationship projection assertion")
        .1
        .split_once("CREATE FUNCTION chat.enforce_relationship_projection()")
        .expect("missing relationship projection enforcement function")
        .0,
    );

    assert!(
        compact.contains(
            "CREATE INDEX relationship_projection_fallback_lookup_idx ON chat.relationship_projection_snapshots (operation_scope, scope_digest, configuration_fingerprint, completed_at DESC, projection_revision DESC) WHERE evidence_kind = 'fallback';"
        ),
        "fallback lookup must be partial, scope-bound, and newest-first"
    );
    assert!(
        snapshots.contains("completed_at <= started_at + INTERVAL '30 seconds'"),
        "relationship collection window must be at most 30 seconds"
    );
    assert!(
        !snapshots.contains("completed_at <= started_at + INTERVAL '60 seconds'"),
        "stale 60-second relationship collection window remains"
    );
    for required in [
        "relation.fetch_revision = snapshot_row.projection_revision",
        "declaration.fetch_revision = snapshot_row.projection_revision",
    ] {
        assert!(
            assertion.contains(required),
            "child fetch revision can alias snapshot revision: {required}"
        );
    }
    for required in [
        "Direct-writer boundary:",
        "owner-only allocator function",
        "no raw DML or sequence privileges",
    ] {
        assert!(
            compact.contains(required),
            "missing documented projection persistence gate: {required}"
        );
    }
    for required in [
        "allocation_id UUID PRIMARY KEY",
        "projection_revision BIGINT NOT NULL",
        "CONSTRAINT relationship_projection_revision_allocations_revision_uq UNIQUE ( projection_revision )",
        "CONSTRAINT relationship_projection_revision_allocations_pair_uq UNIQUE ( allocation_id, projection_revision )",
        "consumed_projection_id UUID",
        "CONSTRAINT relationship_projection_revision_allocations_consumed_uq UNIQUE ( consumed_projection_id )",
        "(consumed_projection_id IS NULL AND consumed_at IS NULL)",
        "(consumed_projection_id IS NOT NULL AND consumed_at IS NOT NULL)",
    ] {
        assert!(
            allocations.contains(required),
            "missing durable projection allocation invariant: {required}"
        );
    }
    for required in [
        "CREATE FUNCTION chat.allocate_relationship_projection_revision() RETURNS TABLE(allocation_id UUID, projection_revision BIGINT)",
        "nextval('chat.relationship_projection_revision_seq')",
        "gen_random_uuid()",
        "REVOKE ALL ON FUNCTION chat.allocate_relationship_projection_revision() FROM PUBLIC",
        "projection_allocation_id UUID NOT NULL",
        "CONSTRAINT relationship_projection_snapshots_revision_uq UNIQUE (projection_revision)",
        "CONSTRAINT relationship_projection_snapshots_allocation_uq UNIQUE (projection_allocation_id)",
        "FOREIGN KEY ( projection_allocation_id, projection_revision ) REFERENCES chat.relationship_projection_revision_allocations( allocation_id, projection_revision )",
        "CREATE FUNCTION chat.consume_relationship_projection_revision_allocation()",
        "consumed_projection_id = NEW.projection_id",
        "allocation_id = NEW.projection_allocation_id",
        "projection_revision = NEW.projection_revision",
        "consumed_projection_id IS NULL",
        "TG_TABLE_NAME = 'relationship_projection_revision_allocations'",
        "OLD.consumed_projection_id IS NOT NULL",
        "CREATE TRIGGER relationship_projection_revision_allocations_identity_immutable",
        "CREATE TRIGGER relationship_projection_allocations_lifecycle_monotonic",
        "CREATE TRIGGER relationship_projection_snapshots_allocation_consumed",
        "CONSTRAINT relationship_projection_revision_allocations_snapshot_fk FOREIGN KEY (consumed_projection_id, allocation_id, projection_revision)",
        "REFERENCES chat.relationship_projection_snapshots( projection_id, projection_allocation_id, projection_revision ) DEFERRABLE INITIALLY DEFERRED",
    ] {
        assert!(
            compact.contains(required),
            "missing one-use projection allocation authority: {required}"
        );
    }
}

fn catalog_fingerprint(lines: &[String]) -> String {
    hex::encode(Sha256::digest(lines.join("\n").as_bytes()))
}

async fn chat_tables<'e, E>(executor: E) -> BTreeSet<String>
where
    E: Executor<'e, Database = sqlx::Postgres>,
{
    sqlx::query_scalar(
        r#"
        SELECT table_name::text
          FROM information_schema.tables
         WHERE table_schema = 'chat' AND table_type = 'BASE TABLE'
         ORDER BY table_name
        "#,
    )
    .fetch_all(executor)
    .await
    .expect("read chat table catalog")
    .into_iter()
    .collect()
}

async fn a0_assert_lock(
    connection: &mut PgConnection,
    lock_class: i32,
    lock_object: i32,
    label: &str,
) {
    let acquired: bool = sqlx::query_scalar("SELECT pg_try_advisory_lock($1,$2)")
        .bind(lock_class)
        .bind(lock_object)
        .fetch_one(&mut *connection)
        .await
        .unwrap_or_else(|error| panic!("{label} advisory-lock acquisition failed: {error}"));
    assert!(acquired, "{label} advisory lock is already held");
    let (own_granted, waiters): (i64, i64) = sqlx::query_as(
        r#"
        SELECT count(*) FILTER (WHERE granted AND pid=pg_backend_pid()),
               count(*) FILTER (WHERE NOT granted)
          FROM pg_locks
         WHERE locktype='advisory'
           AND classid=$1::oid
           AND objid=$2::oid
        "#,
    )
    .bind(lock_class)
    .bind(lock_object)
    .fetch_one(&mut *connection)
    .await
    .unwrap_or_else(|error| panic!("{label} advisory-lock inspection failed: {error}"));
    assert_eq!(
        (own_granted, waiters),
        (1, 0),
        "{label} advisory lock must have exactly this holder and no waiter"
    );
}

async fn a0_unlock(connection: &mut PgConnection, lock_class: i32, lock_object: i32, label: &str) {
    let unlocked: bool = sqlx::query_scalar("SELECT pg_advisory_unlock($1,$2)")
        .bind(lock_class)
        .bind(lock_object)
        .fetch_one(connection)
        .await
        .unwrap_or_else(|error| panic!("{label} advisory-lock release failed: {error}"));
    assert!(unlocked, "{label} advisory lock was not held at release");
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct A0TargetIdentity {
    database_oid: u32,
    database_name: String,
    owner: String,
    current_role: String,
    server_address: String,
    server_port: u16,
    allow_connections: bool,
    role_can_create_database: bool,
    pid: i32,
}

async fn a0_read_target_identity(connection: &mut PgConnection) -> A0TargetIdentity {
    let (
        database_oid,
        database_name,
        owner,
        current_role,
        server_address,
        server_port,
        allow_connections,
        role_can_create_database,
        pid,
    ): (
        i64,
        String,
        String,
        String,
        Option<String>,
        Option<i32>,
        bool,
        bool,
        i32,
    ) = sqlx::query_as(
        r#"
        SELECT database.oid::bigint,
               current_database(),
               pg_get_userbyid(database.datdba),
               current_user,
               host(inet_server_addr()),
               inet_server_port(),
               database.datallowconn,
               (role.rolcreatedb OR role.rolsuper),
               pg_backend_pid()
          FROM pg_database AS database
          JOIN pg_roles AS role ON role.rolname=current_user
         WHERE database.datname='catbird_chat_protocol_test_20260722'
           AND database.datname=current_database()
        "#,
    )
    .fetch_one(connection)
    .await
    .expect("A0 exact target identity must be readable");
    let database_oid = u32::try_from(database_oid).expect("PostgreSQL database OID fits u32");
    assert_eq!(database_name, TEST_DATABASE_NAME, "A0 target name drift");
    assert_eq!(owner, A0_EXACT_OWNER, "A0 target owner drift");
    assert_eq!(current_role, A0_EXACT_OWNER, "A0 current role drift");
    let server_address = server_address.expect("A0 target must use TCP");
    assert_eq!(
        server_address, "127.0.0.1",
        "A0 target server address drift"
    );
    let server_port = u16::try_from(server_port.expect("A0 target must expose a server port"))
        .expect("A0 target port fits u16");
    assert_eq!(server_port, 5432, "A0 target server port drift");
    assert!(
        role_can_create_database,
        "A0 current role must retain CREATEDB"
    );
    A0TargetIdentity {
        database_oid,
        database_name,
        owner,
        current_role,
        server_address,
        server_port,
        allow_connections,
        role_can_create_database,
        pid,
    }
}

async fn a0_collect_legacy_facts(
    connection: &mut PgConnection,
    identity: &A0TargetIdentity,
) -> Result<A0LegacyFingerprintFacts, String> {
    let chat_schema_absent: bool = sqlx::query_scalar("SELECT to_regnamespace('chat') IS NULL")
        .fetch_one(&mut *connection)
        .await
        .map_err(|error| format!("read A0 legacy chat-schema absence: {error}"))?;
    let ledger = a0_ledger(connection).await;
    let exact13_overlap = ledger
        .iter()
        .filter(|(version, _, _, _)| MIGRATION_VERSIONS.contains(version))
        .count();
    let exact13_missing = MIGRATION_VERSIONS.len().saturating_sub(exact13_overlap);
    let (ledger_fingerprint, catalog_fingerprint) = a0_read_legacy_fingerprint(connection).await?;
    let intent_absent = !Path::new(A0_INTENT_PATH)
        .try_exists()
        .map_err(|error| format!("inspect A0 intent marker: {error}"))?;
    let consumed_absent = !Path::new(A0_CONSUMED_PATH)
        .try_exists()
        .map_err(|error| format!("inspect A0 consumed marker: {error}"))?;
    Ok(A0LegacyFingerprintFacts {
        database_name: identity.database_name.clone(),
        database_oid: identity.database_oid,
        owner: identity.owner.clone(),
        current_role: identity.current_role.clone(),
        server_address: identity.server_address.clone(),
        server_port: identity.server_port,
        allow_connections: identity.allow_connections,
        role_can_create_database: identity.role_can_create_database,
        chat_schema_absent,
        ledger_row_count: ledger_fingerprint.row_count,
        ledger_all_successful: ledger_fingerprint.all_successful,
        ledger_sha256: ledger_fingerprint.sha256,
        ledger_sha384: ledger_fingerprint.sha384,
        catalog_sha256: catalog_fingerprint.sha256,
        catalog_sha384: catalog_fingerprint.sha384,
        exact13_overlap,
        exact13_missing,
        intent_absent,
        consumed_absent,
    })
}

async fn a0_assert_only_target_pid(admin: &mut PgConnection, target_pid: i32) {
    let sessions: Vec<(i32, Option<String>)> = sqlx::query_as(
        r#"
        SELECT pid,host(client_addr)
          FROM pg_stat_activity
         WHERE datname='catbird_chat_protocol_test_20260722'
         ORDER BY pid
        "#,
    )
    .fetch_all(admin)
    .await
    .expect("A0 exact-target job inventory must be readable");
    assert_eq!(sessions.len(), 1, "A0 refuses a peer target session");
    assert_eq!(sessions[0].0, target_pid, "A0 target PID drift");
    assert!(
        a0_connection_address_is_local(sessions[0].1.as_deref()),
        "A0 refuses a nonloopback target session"
    );
}

async fn a0_admin_database_state(
    admin: &mut PgConnection,
) -> Result<Option<(u32, bool, String)>, String> {
    let row: Option<(i64, bool, String)> = sqlx::query_as(
        "SELECT oid::bigint,datallowconn,pg_get_userbyid(datdba) \
         FROM pg_database WHERE datname='catbird_chat_protocol_test_20260722'",
    )
    .fetch_optional(admin)
    .await
    .map_err(|error| format!("read A0 admin database state: {error}"))?;
    row.map(|(oid, allow, owner)| {
        Ok((
            u32::try_from(oid).map_err(|_| "A0 database OID exceeds u32".to_owned())?,
            allow,
            owner,
        ))
    })
    .transpose()
}

async fn a0_guarded_restore_legacy_connections(admin: &mut PgConnection) -> Result<(), String> {
    let Some((oid, allow_connections, owner)) = a0_admin_database_state(admin).await? else {
        return Err("A0 guarded restoration target is absent".to_owned());
    };
    if oid != A0_EXPECTED_LEGACY_OID || owner != A0_EXACT_OWNER {
        return Err("A0 guarded restoration target identity mismatch".to_owned());
    }
    if !allow_connections {
        sqlx::query(A0_RESTORE_CONNECTIONS_SQL)
            .execute(&mut *admin)
            .await
            .map_err(|error| format!("A0 guarded connection restoration failed: {error}"))?;
    }
    let Some((restored_oid, restored_allow_connections, restored_owner)) =
        a0_admin_database_state(admin).await?
    else {
        return Err("A0 restored target disappeared".to_owned());
    };
    if restored_oid != A0_EXPECTED_LEGACY_OID
        || !restored_allow_connections
        || restored_owner != A0_EXACT_OWNER
    {
        return Err("A0 guarded connection restoration postcondition failed".to_owned());
    }
    Ok(())
}

async fn a0_extension_catalog(connection: &mut PgConnection) -> Vec<String> {
    sqlx::query_scalar(
        r#"
        SELECT extension.extname || '|' || extension_schema.nspname || '|' ||
               pg_describe_object(dependency.classid,dependency.objid,dependency.objsubid)
          FROM pg_depend AS dependency
          JOIN pg_extension AS extension ON extension.oid=dependency.refobjid
          JOIN pg_namespace AS extension_schema ON extension_schema.oid=extension.extnamespace
         WHERE dependency.refclassid='pg_extension'::regclass
           AND dependency.deptype='e'
         ORDER BY 1
        "#,
    )
    .fetch_all(connection)
    .await
    .expect("A0 extension-owned catalog must be readable")
}

async fn a0_assert_extension_allowlist(connection: &mut PgConnection) -> String {
    let extensions: Vec<String> = sqlx::query_scalar(
        r#"
        SELECT extension.extname || '|' || namespace.nspname || '|' ||
               pg_get_userbyid(extension.extowner) || '|' ||
               extension.extversion || '|' || extension.extrelocatable::text
          FROM pg_extension AS extension
          JOIN pg_namespace AS namespace ON namespace.oid=extension.extnamespace
         ORDER BY extension.extname
        "#,
    )
    .fetch_all(&mut *connection)
    .await
    .expect("A0 extension inventory must be readable");
    assert_eq!(
        extensions,
        // Clean-lineage set. Of the exact-13 migrations only
        // 20260722000001_chat_protocol_core.sql installs an extension, and it
        // installs pgcrypto alone; plpgsql arrives with the template. uuid-ossp
        // is legacy-only (20250101000000 and 20260429000001, neither in the set).
        vec![
            "pgcrypto|public|joshlacalamito|1.3|true".to_owned(),
            "plpgsql|pg_catalog|joshlacalamito|1.0|false".to_owned(),
        ],
        "A0 extension name/schema/owner/version/relocatability drift"
    );
    let extension_member_authority_violations: Vec<String> = sqlx::query_scalar(
        r#"
        WITH extension_members AS (
            SELECT dependency.classid,dependency.objid,extension.extname
              FROM pg_depend dependency
              JOIN pg_extension extension ON extension.oid=dependency.refobjid
             WHERE dependency.refclassid='pg_extension'::regclass
               AND dependency.deptype='e'
        )
        SELECT member_kind || '|' || extension_name || '|' || identity
          FROM (
                SELECT 'relation' AS member_kind,
                       member.extname AS extension_name,
                       namespace.nspname || '.' || relation.relname AS identity
                  FROM extension_members member
                  JOIN pg_class relation
                    ON member.classid='pg_class'::regclass
                   AND relation.oid=member.objid
                  JOIN pg_namespace namespace
                    ON namespace.oid=relation.relnamespace
                 WHERE pg_get_userbyid(relation.relowner) <> 'joshlacalamito'
                    OR relation.relacl IS NOT NULL
                    OR relation.relrowsecurity
                    OR relation.relforcerowsecurity
                    OR relation.relreplident <> 'd'
                    OR relation.relpersistence <> 'p'
                UNION ALL
                SELECT 'function',member.extname,
                       namespace.nspname || '.' || procedure.proname || '(' ||
                       pg_get_function_identity_arguments(procedure.oid) || ')'
                  FROM extension_members member
                  JOIN pg_proc procedure
                    ON member.classid='pg_proc'::regclass
                   AND procedure.oid=member.objid
                  JOIN pg_namespace namespace
                    ON namespace.oid=procedure.pronamespace
                 WHERE pg_get_userbyid(procedure.proowner) <> 'joshlacalamito'
                    OR procedure.proacl IS NOT NULL
                UNION ALL
                SELECT 'type',member.extname,
                       namespace.nspname || '.' || type_row.typname
                  FROM extension_members member
                  JOIN pg_type type_row
                    ON member.classid='pg_type'::regclass
                   AND type_row.oid=member.objid
                  JOIN pg_namespace namespace
                    ON namespace.oid=type_row.typnamespace
                 WHERE pg_get_userbyid(type_row.typowner) <> 'joshlacalamito'
                    OR type_row.typacl IS NOT NULL
                UNION ALL
                SELECT 'language',member.extname,language.lanname
                  FROM extension_members member
                  JOIN pg_language language
                    ON member.classid='pg_language'::regclass
                   AND language.oid=member.objid
                 WHERE pg_get_userbyid(language.lanowner) <> 'joshlacalamito'
                    OR language.lanacl IS NOT NULL
          ) violations
         ORDER BY member_kind,extension_name,identity
        "#,
    )
    .fetch_all(&mut *connection)
    .await
    .expect("A0 extension-member ownership/ACL authority must be readable");
    assert!(
        extension_member_authority_violations.is_empty(),
        "A0 extension-member owner/ACL/RLS/replica/persistence drift: \
         {extension_member_authority_violations:?}"
    );
    let extension_objects = a0_extension_catalog(connection).await;
    assert_eq!(
        extension_objects.len(),
        A0_EXTENSION_OBJECT_COUNT,
        "A0 extension-owned object count drift"
    );
    let fingerprint = catalog_fingerprint(&extension_objects);
    assert_eq!(
        fingerprint,
        A0_EXTENSION_OBJECT_CATALOG_SHA256,
        "A0 extension-owned object allowlist drift:\n{}",
        extension_objects.join("\n")
    );
    fingerprint
}

async fn a0_assert_pristine_extension_baseline(connection: &mut PgConnection) -> String {
    let extensions: Vec<String> = sqlx::query_scalar(
        r#"
        SELECT extension.extname || '|' || namespace.nspname || '|' ||
               pg_get_userbyid(extension.extowner) || '|' ||
               extension.extversion || '|' || extension.extrelocatable::text
          FROM pg_extension AS extension
          JOIN pg_namespace AS namespace ON namespace.oid=extension.extnamespace
         ORDER BY extension.extname
        "#,
    )
    .fetch_all(&mut *connection)
    .await
    .expect("A0 pristine extension inventory must be readable");
    assert_eq!(
        extensions,
        vec!["plpgsql|pg_catalog|joshlacalamito|1.0|false".to_owned()],
        "A0 pristine extension name/schema/owner/version/relocatability drift"
    );
    catalog_fingerprint(&a0_extension_catalog(connection).await)
}

async fn a0_nonextension_public_catalog(
    connection: &mut PgConnection,
) -> (Vec<String>, Vec<String>, Vec<String>) {
    let relations: Vec<String> = sqlx::query_scalar(
        r#"
        SELECT class.relname || '|' || class.relkind::text
          FROM pg_class AS class
          JOIN pg_namespace AS namespace ON namespace.oid=class.relnamespace
         WHERE namespace.nspname='public'
           AND NOT EXISTS (
               SELECT 1
                 FROM pg_depend AS dependency
                WHERE dependency.classid='pg_class'::regclass
                  AND dependency.objid=class.oid
                  AND dependency.refclassid='pg_extension'::regclass
                  AND dependency.deptype='e'
           )
         ORDER BY class.relname,class.relkind
        "#,
    )
    .fetch_all(&mut *connection)
    .await
    .expect("A0 public relation allowlist must be readable");
    let constraints: Vec<String> = sqlx::query_scalar(
        r#"
        SELECT constraint_row.conname || '|' || constraint_row.contype::text
          FROM pg_constraint AS constraint_row
          JOIN pg_namespace AS namespace ON namespace.oid=constraint_row.connamespace
         WHERE namespace.nspname='public'
         ORDER BY constraint_row.conname
        "#,
    )
    .fetch_all(&mut *connection)
    .await
    .expect("A0 public constraint allowlist must be readable");
    let standalone_objects: Vec<String> = sqlx::query_scalar(
        r#"
        SELECT object_kind || '|' || object_name
          FROM (
                SELECT 'function' AS object_kind,
                       procedure.proname || '(' ||
                       pg_get_function_identity_arguments(procedure.oid) || ')' AS object_name,
                       procedure.oid AS object_oid,
                       'pg_proc'::regclass AS class_oid
                  FROM pg_proc AS procedure
                  JOIN pg_namespace AS namespace ON namespace.oid=procedure.pronamespace
                 WHERE namespace.nspname='public'
                UNION ALL
                -- typelem=0 excludes the array type PostgreSQL creates
                -- automatically for every table's row type, matching the
                -- chat-scoped standalone-type query. Without it the SQLx ledger
                -- contributes __sqlx_migrations (the array type of
                -- _sqlx_migrations' row type) post-migration, which is not a
                -- standalone type: the table itself is already covered by the
                -- relation allowlist. The exclusion also keeps the pristine
                -- gate's installed_empty_ledger_catalog arm reachable — that
                -- arm tolerates the ledger table already existing, but the
                -- array type would then fail the standalone-object conjunct
                -- and force pristine false for the one state it must accept.
                SELECT 'standalone_type',type_row.typname,type_row.oid,'pg_type'::regclass
                  FROM pg_type AS type_row
                  JOIN pg_namespace AS namespace ON namespace.oid=type_row.typnamespace
                 WHERE namespace.nspname='public'
                   AND type_row.typrelid=0
                   AND type_row.typelem=0
                UNION ALL
                SELECT 'operator',operator.oprname,operator.oid,'pg_operator'::regclass
                  FROM pg_operator AS operator
                  JOIN pg_namespace AS namespace ON namespace.oid=operator.oprnamespace
                 WHERE namespace.nspname='public'
          ) AS candidate
         WHERE NOT EXISTS (
               SELECT 1
                 FROM pg_depend AS dependency
                WHERE dependency.classid=candidate.class_oid
                  AND dependency.objid=candidate.object_oid
                  AND dependency.refclassid='pg_extension'::regclass
                  AND dependency.deptype='e'
         )
         ORDER BY object_kind,object_name
        "#,
    )
    .fetch_all(connection)
    .await
    .expect("A0 public standalone-object allowlist must be readable");
    (relations, constraints, standalone_objects)
}

async fn a0_ledger(connection: &mut PgConnection) -> Vec<(i64, String, bool, Vec<u8>)> {
    let exists: bool =
        sqlx::query_scalar("SELECT to_regclass('public._sqlx_migrations') IS NOT NULL")
            .fetch_one(&mut *connection)
            .await
            .expect("A0 migration-ledger existence must be readable");
    if !exists {
        return Vec::new();
    }
    sqlx::query_as(
        "SELECT version,description,success,checksum FROM public._sqlx_migrations ORDER BY version",
    )
    .fetch_all(connection)
    .await
    .expect("A0 migration ledger must be readable")
}

fn a0_expected_ledger() -> Vec<(i64, String, bool, Vec<u8>)> {
    crate::common::chat_protocol::CLEAN_PROTOCOL_13_MANIFEST
        .iter()
        .map(|entry| {
            (
                entry.migration.version,
                entry.migration.description.to_string(),
                true,
                entry.migration.checksum.to_vec(),
            )
        })
        .collect()
}

fn a0_ledger_fingerprint(rows: &[(i64, String, bool, Vec<u8>)]) -> String {
    catalog_fingerprint(
        &rows
            .iter()
            .map(|(version, description, success, checksum)| {
                format!(
                    "{version}|{description}|{success}|{}",
                    hex::encode(checksum)
                )
            })
            .collect::<Vec<_>>(),
    )
}

async fn a0_assert_exact_ledger(connection: &mut PgConnection) -> String {
    let actual = a0_ledger(connection).await;
    let expected = a0_expected_ledger();
    assert_eq!(
        actual, expected,
        "A0 ledger must equal exactly the reviewed 13-entry manifest"
    );
    a0_ledger_fingerprint(&actual)
}

async fn a0_target_is_pristine(connection: &mut PgConnection) -> bool {
    let chat_schema_exists: bool = sqlx::query_scalar("SELECT to_regnamespace('chat') IS NOT NULL")
        .fetch_one(&mut *connection)
        .await
        .expect("A0 chat-schema probe must be readable");
    let ledger = a0_ledger(&mut *connection).await;
    let schemas: Vec<String> = sqlx::query_scalar(
        r#"
        SELECT nspname
          FROM pg_namespace
         WHERE nspname <> 'information_schema'
           AND nspname !~ '^pg_'
         ORDER BY nspname
        "#,
    )
    .fetch_all(&mut *connection)
    .await
    .expect("A0 user-schema inventory must be readable");
    let (relations, constraints, standalone_objects) =
        a0_nonextension_public_catalog(&mut *connection).await;
    let extension_hash = a0_assert_pristine_extension_baseline(connection).await;
    let empty_ledger_catalog = relations.is_empty() && constraints.is_empty();
    let installed_empty_ledger_catalog = relations
        == [
            "_sqlx_migrations|r".to_owned(),
            "_sqlx_migrations_pkey|i".to_owned(),
        ]
        && constraints == ["_sqlx_migrations_pkey|p"];
    let pristine = !chat_schema_exists
        && ledger.is_empty()
        && schemas == ["public"]
        && (empty_ledger_catalog || installed_empty_ledger_catalog)
        && standalone_objects.is_empty();
    eprintln!(
        "A0 pristine_proof chat_schema_exists={chat_schema_exists} ledger_rows={} \
         schemas={schemas:?} public_relations={relations:?} \
         public_constraints={constraints:?} standalone_objects={standalone_objects:?} \
         extension_catalog_sha256={extension_hash} pristine={pristine}",
        ledger.len(),
    );
    pristine
}

// Recovery-phase counterpart of `a0_target_is_pristine`. It asserts the same
// five facts over the same queries, but individually, so a post-destruction
// mismatch names the fact that failed instead of collapsing into one boolean.
// Returns the observed extension-object fingerprint of the pre-migration
// replacement, which the recovery evidence records as its pre-catalog value.
async fn a0_assert_recovery_target_is_pristine(connection: &mut PgConnection) -> String {
    let chat_schema_exists: bool = sqlx::query_scalar("SELECT to_regnamespace('chat') IS NOT NULL")
        .fetch_one(&mut *connection)
        .await
        .expect("A0 recovery chat-schema probe must be readable");
    assert!(
        !chat_schema_exists,
        "A0 recovery target already carries a chat schema"
    );
    let ledger = a0_ledger(&mut *connection).await;
    assert!(
        ledger.is_empty(),
        "A0 recovery target ledger is not empty: {} rows",
        ledger.len()
    );
    let schemas: Vec<String> = sqlx::query_scalar(
        r#"
        SELECT nspname
          FROM pg_namespace
         WHERE nspname <> 'information_schema'
           AND nspname !~ '^pg_'
         ORDER BY nspname
        "#,
    )
    .fetch_all(&mut *connection)
    .await
    .expect("A0 recovery user-schema inventory must be readable");
    assert_eq!(schemas, ["public"], "A0 recovery user-schema drift");
    let (relations, constraints, standalone_objects) =
        a0_nonextension_public_catalog(&mut *connection).await;
    let empty_ledger_catalog = relations.is_empty() && constraints.is_empty();
    let installed_empty_ledger_catalog = relations
        == [
            "_sqlx_migrations|r".to_owned(),
            "_sqlx_migrations_pkey|i".to_owned(),
        ]
        && constraints == ["_sqlx_migrations_pkey|p"];
    assert!(
        empty_ledger_catalog || installed_empty_ledger_catalog,
        "A0 recovery public catalog is neither empty nor ledger-only: \
         relations={relations:?} constraints={constraints:?}"
    );
    assert!(
        standalone_objects.is_empty(),
        "A0 recovery standalone-object drift: {standalone_objects:?}"
    );
    a0_assert_pristine_extension_baseline(connection).await
}

async fn a0_catalog_hash(
    connection: &mut PgConnection,
    query: &str,
    label: &str,
    expected: &str,
) -> String {
    let lines: Vec<String> = sqlx::query_scalar(query)
        .fetch_all(connection)
        .await
        .unwrap_or_else(|error| panic!("read A0 {label} catalog: {error}"));
    let actual = catalog_fingerprint(&lines);
    assert_eq!(
        actual,
        expected,
        "A0 {label} catalog allowlist drift:\n{}",
        lines.join("\n")
    );
    actual
}

#[derive(Debug, PartialEq, Eq)]
enum PublicLedgerClosedCatalogDrift {
    AttachedTriggers(Vec<String>),
    AttachedRewriteRules(Vec<String>),
    AttachedPolicies(Vec<String>),
    RowLevelSecurity { enabled: bool, forced: bool },
}

#[derive(Debug)]
enum PublicLedgerClosedCatalogError {
    Query {
        surface: &'static str,
        source: sqlx::Error,
    },
    Drift(PublicLedgerClosedCatalogDrift),
}

struct PublicLedgerClosedCatalog {
    triggers: Vec<String>,
    rules: Vec<String>,
    policies: Vec<String>,
}

async fn a0_classify_public_ledger_closed_catalog(
    connection: &mut PgConnection,
) -> Result<PublicLedgerClosedCatalog, PublicLedgerClosedCatalogError> {
    let (rls_enabled, rls_forced): (bool, bool) = sqlx::query_as(
        r#"
        SELECT relation.relrowsecurity,relation.relforcerowsecurity
          FROM pg_class relation
          JOIN pg_namespace namespace ON namespace.oid=relation.relnamespace
         WHERE namespace.nspname='public'
           AND relation.relname='_sqlx_migrations'
        "#,
    )
    .fetch_one(&mut *connection)
    .await
    .map_err(|source| PublicLedgerClosedCatalogError::Query {
        surface: "RLS state",
        source,
    })?;
    let triggers: Vec<String> = sqlx::query_scalar(
        r#"
        SELECT
            CASE WHEN trigger_row.tgisinternal THEN 'internal' ELSE 'user' END
            || '|' || pg_get_userbyid(procedure.proowner)
            || '|' || procedure_namespace.nspname || '.' || procedure.proname
            || '(' || pg_get_function_identity_arguments(procedure.oid) || ')'
            || '|' || trigger_row.tgenabled::text
            || '|' || trigger_row.tgtype::text
            || '|' || trigger_row.tgdeferrable::text
            || '|' || trigger_row.tginitdeferred::text
            || '|' || COALESCE(pg_get_expr(
                 trigger_row.tgqual,trigger_row.tgrelid,true
            ),'')
            || '|' || pg_get_triggerdef(trigger_row.oid,false)
          FROM pg_trigger trigger_row
          JOIN pg_class relation ON relation.oid=trigger_row.tgrelid
          JOIN pg_namespace namespace ON namespace.oid=relation.relnamespace
          JOIN pg_proc procedure ON procedure.oid=trigger_row.tgfoid
          JOIN pg_namespace procedure_namespace
            ON procedure_namespace.oid=procedure.pronamespace
         WHERE namespace.nspname='public'
           AND relation.relname='_sqlx_migrations'
         ORDER BY 1
        "#,
    )
    .fetch_all(&mut *connection)
    .await
    .map_err(|source| PublicLedgerClosedCatalogError::Query {
        surface: "attached triggers",
        source,
    })?;
    let rules: Vec<String> = sqlx::query_scalar(
        r#"
        SELECT rewrite.rulename || '|' || pg_get_userbyid(relation.relowner)
               || '|' || rewrite.ev_type::text
               || '|' || rewrite.is_instead::text
               || '|' || rewrite.ev_enabled::text
               || '|' || COALESCE(pg_get_expr(
                    rewrite.ev_qual,rewrite.ev_class,true
                  ),'')
               || '|' || pg_get_ruledef(rewrite.oid,true)
          FROM pg_rewrite rewrite
          JOIN pg_class relation ON relation.oid=rewrite.ev_class
          JOIN pg_namespace namespace ON namespace.oid=relation.relnamespace
         WHERE namespace.nspname='public'
           AND relation.relname='_sqlx_migrations'
           AND rewrite.rulename <> '_RETURN'
         ORDER BY rewrite.rulename
        "#,
    )
    .fetch_all(&mut *connection)
    .await
    .map_err(|source| PublicLedgerClosedCatalogError::Query {
        surface: "attached rewrite rules",
        source,
    })?;
    let policies: Vec<String> = sqlx::query_scalar(
        r#"
        SELECT policy.polname || '|' || pg_get_userbyid(relation.relowner)
               || '|' || policy.polcmd::text
               || '|' || policy.polpermissive::text
               || '|' || COALESCE((
                    SELECT string_agg(
                        CASE WHEN role_oid=0
                             THEN 'PUBLIC'
                             ELSE pg_get_userbyid(role_oid) END,
                        ',' ORDER BY
                        CASE WHEN role_oid=0
                             THEN 'PUBLIC'
                             ELSE pg_get_userbyid(role_oid) END
                    )
                      FROM unnest(policy.polroles) role_oid
                  ),'')
               || '|' || COALESCE(pg_get_expr(
                    policy.polqual,policy.polrelid,true
                  ),'')
               || '|' || COALESCE(pg_get_expr(
                    policy.polwithcheck,policy.polrelid,true
                  ),'')
          FROM pg_policy policy
          JOIN pg_class relation ON relation.oid=policy.polrelid
          JOIN pg_namespace namespace ON namespace.oid=relation.relnamespace
         WHERE namespace.nspname='public'
           AND relation.relname='_sqlx_migrations'
         ORDER BY policy.polname
        "#,
    )
    .fetch_all(&mut *connection)
    .await
    .map_err(|source| PublicLedgerClosedCatalogError::Query {
        surface: "attached policies",
        source,
    })?;

    if rls_enabled || rls_forced {
        return Err(PublicLedgerClosedCatalogError::Drift(
            PublicLedgerClosedCatalogDrift::RowLevelSecurity {
                enabled: rls_enabled,
                forced: rls_forced,
            },
        ));
    }
    if !triggers.is_empty() {
        return Err(PublicLedgerClosedCatalogError::Drift(
            PublicLedgerClosedCatalogDrift::AttachedTriggers(triggers),
        ));
    }
    if !rules.is_empty() {
        return Err(PublicLedgerClosedCatalogError::Drift(
            PublicLedgerClosedCatalogDrift::AttachedRewriteRules(rules),
        ));
    }
    if !policies.is_empty() {
        return Err(PublicLedgerClosedCatalogError::Drift(
            PublicLedgerClosedCatalogDrift::AttachedPolicies(policies),
        ));
    }
    Ok(PublicLedgerClosedCatalog {
        triggers,
        rules,
        policies,
    })
}

async fn a0_assert_post_clean_authority_surfaces(connection: &mut PgConnection) -> Vec<String> {
    let (database_owner, database_acl): (String, String) = sqlx::query_as(
        "SELECT pg_get_userbyid(datdba),COALESCE(datacl::text,'') \
         FROM pg_database WHERE datname=current_database()",
    )
    .fetch_one(&mut *connection)
    .await
    .expect("A0 final database ownership/ACL authority must be readable");
    assert_eq!(
        database_owner, A0_EXACT_OWNER,
        "A0 final database owner drift"
    );
    assert!(
        database_acl.is_empty(),
        "A0 final database ACL drift: {database_acl}"
    );

    let (public_owner, public_acl): (String, Vec<String>) = sqlx::query_as(
        r#"
        SELECT pg_get_userbyid(namespace.nspowner),
               ARRAY(
                   SELECT
                       CASE WHEN privilege.grantee=0
                            THEN 'PUBLIC'
                            ELSE pg_get_userbyid(privilege.grantee) END
                       || '|' || privilege.privilege_type
                       || '|' || pg_get_userbyid(privilege.grantor)
                       || '|' || privilege.is_grantable::text
                     FROM aclexplode(namespace.nspacl) privilege
                    ORDER BY 1
               )
          FROM pg_namespace namespace
         WHERE namespace.nspname='public'
        "#,
    )
    .fetch_one(&mut *connection)
    .await
    .expect("A0 final public-schema authority must be readable");
    assert_eq!(
        public_owner, "pg_database_owner",
        "A0 final public schema owner drift"
    );
    assert_eq!(
        public_acl,
        [
            "PUBLIC|USAGE|pg_database_owner|false".to_owned(),
            "pg_database_owner|CREATE|pg_database_owner|false".to_owned(),
            "pg_database_owner|USAGE|pg_database_owner|false".to_owned(),
        ],
        "A0 final public schema ACL drift"
    );
    let PublicLedgerClosedCatalog {
        triggers: public_ledger_triggers,
        rules: public_ledger_rules,
        policies: public_ledger_policies,
    } = match a0_classify_public_ledger_closed_catalog(&mut *connection).await {
        Ok(closed_catalog) => closed_catalog,
        Err(PublicLedgerClosedCatalogError::Query { surface, source }) => {
            panic!("A0 final SQLx-ledger {surface} authority must be readable: {source}")
        }
        Err(PublicLedgerClosedCatalogError::Drift(drift)) => {
            panic!("A0 final SQLx-ledger closed-catalog drift: {drift:?}")
        }
    };

    let public_ledger_relations: Vec<String> = sqlx::query_scalar(
        r#"
        SELECT relation.relname || '|' || relation.relkind::text || '|' ||
               pg_get_userbyid(relation.relowner) || '|' ||
               COALESCE(relation.relacl::text,'') || '|' ||
               relation.relrowsecurity::text || '|' ||
               relation.relforcerowsecurity::text || '|' ||
               relation.relreplident::text || '|' ||
               relation.relpersistence::text
          FROM pg_class relation
          JOIN pg_namespace namespace ON namespace.oid=relation.relnamespace
         WHERE namespace.nspname='public'
           AND relation.relname IN ('_sqlx_migrations','_sqlx_migrations_pkey')
         ORDER BY relation.relname
        "#,
    )
    .fetch_all(&mut *connection)
    .await
    .expect("A0 final SQLx-ledger relation authority must be readable");
    assert_eq!(
        public_ledger_relations,
        [
            "_sqlx_migrations|r|joshlacalamito||false|false|d|p".to_owned(),
            "_sqlx_migrations_pkey|i|joshlacalamito||false|false|n|p".to_owned(),
        ],
        "A0 final SQLx-ledger owner/ACL/RLS/replica/persistence drift"
    );
    let public_ledger_columns: Vec<String> = sqlx::query_scalar(
        r#"
        SELECT attribute.attnum::text || '|' || attribute.attname || '|' ||
               format_type(attribute.atttypid,attribute.atttypmod) || '|' ||
               attribute.attnotnull::text || '|' ||
               (attribute.attacl IS NULL)::text || '|' ||
               COALESCE(pg_get_expr(default_row.adbin,default_row.adrelid,true),'')
          FROM pg_attribute attribute
          JOIN pg_class relation ON relation.oid=attribute.attrelid
          JOIN pg_namespace namespace ON namespace.oid=relation.relnamespace
          LEFT JOIN pg_attrdef default_row
            ON default_row.adrelid=attribute.attrelid
           AND default_row.adnum=attribute.attnum
         WHERE namespace.nspname='public'
           AND relation.relname='_sqlx_migrations'
           AND attribute.attnum > 0
           AND NOT attribute.attisdropped
         ORDER BY attribute.attnum
        "#,
    )
    .fetch_all(&mut *connection)
    .await
    .expect("A0 final SQLx-ledger column authority must be readable");
    assert_eq!(
        public_ledger_columns,
        [
            "1|version|bigint|true|true|".to_owned(),
            "2|description|text|true|true|".to_owned(),
            "3|installed_on|timestamp with time zone|true|true|now()".to_owned(),
            "4|success|boolean|true|true|".to_owned(),
            "5|checksum|bytea|true|true|".to_owned(),
            "6|execution_time|bigint|true|true|".to_owned(),
        ],
        "A0 final SQLx-ledger column/type/default/ACL authority drift"
    );
    let public_ledger_constraint: String = sqlx::query_scalar(
        r#"
        SELECT constraint_row.contype::text || '|' ||
               constraint_row.condeferrable::text || '|' ||
               constraint_row.condeferred::text || '|' ||
               constraint_row.convalidated::text || '|' ||
               pg_get_constraintdef(constraint_row.oid,false) || '|' ||
               index_row.indisunique::text || '|' ||
               index_row.indisprimary::text || '|' ||
               index_row.indimmediate::text || '|' ||
               index_row.indisvalid::text || '|' ||
               index_row.indisready::text || '|' ||
               access_method.amname
          FROM pg_constraint constraint_row
          JOIN pg_class relation ON relation.oid=constraint_row.conrelid
          JOIN pg_namespace namespace ON namespace.oid=relation.relnamespace
          JOIN pg_index index_row ON index_row.indexrelid=constraint_row.conindid
          JOIN pg_class index_relation ON index_relation.oid=index_row.indexrelid
          JOIN pg_am access_method ON access_method.oid=index_relation.relam
         WHERE namespace.nspname='public'
           AND relation.relname='_sqlx_migrations'
           AND constraint_row.conname='_sqlx_migrations_pkey'
        "#,
    )
    .fetch_one(&mut *connection)
    .await
    .expect("A0 final SQLx-ledger primary-key authority must be readable");
    assert_eq!(
        public_ledger_constraint,
        "p|false|false|true|PRIMARY KEY (version)|true|true|true|true|true|btree",
        "A0 final SQLx-ledger primary-key semantics drift"
    );

    let (chat_owner, chat_acl): (String, String) = sqlx::query_as(
        "SELECT pg_get_userbyid(nspowner),COALESCE(nspacl::text,'') \
         FROM pg_namespace WHERE nspname='chat'",
    )
    .fetch_one(&mut *connection)
    .await
    .expect("A0 final chat-schema ownership/ACL authority must be readable");
    assert_eq!(
        chat_owner, A0_EXACT_OWNER,
        "A0 final chat schema owner drift"
    );
    assert!(
        chat_acl.is_empty(),
        "A0 final chat schema ACL drift: {chat_acl}"
    );

    let relation_authority_violations: Vec<String> = sqlx::query_scalar(
        r#"
        SELECT relation.relname
          FROM pg_class relation
          JOIN pg_namespace namespace ON namespace.oid=relation.relnamespace
         WHERE namespace.nspname='chat'
           AND (
                pg_get_userbyid(relation.relowner) <> 'joshlacalamito'
                OR relation.relacl IS NOT NULL
                OR (
                    relation.relkind IN ('r','p')
                    AND (
                        relation.relrowsecurity
                        OR relation.relforcerowsecurity
                        OR relation.relreplident <> 'd'
                        OR relation.relpersistence <> 'p'
                    )
                )
           )
         ORDER BY relation.relname
        "#,
    )
    .fetch_all(&mut *connection)
    .await
    .expect("A0 final relation authority must be readable");
    assert!(
        relation_authority_violations.is_empty(),
        "A0 final relation ownership/ACL/RLS/replica authority drift: \
         {relation_authority_violations:?}"
    );

    let column_acl_violations: Vec<String> = sqlx::query_scalar(
        r#"
        SELECT relation.relname || '.' || attribute.attname
          FROM pg_attribute attribute
          JOIN pg_class relation ON relation.oid=attribute.attrelid
          JOIN pg_namespace namespace ON namespace.oid=relation.relnamespace
         WHERE namespace.nspname='chat'
           AND attribute.attnum > 0
           AND NOT attribute.attisdropped
           AND attribute.attacl IS NOT NULL
         ORDER BY relation.relname,attribute.attnum
        "#,
    )
    .fetch_all(&mut *connection)
    .await
    .expect("A0 final column ACL authority must be readable");
    assert!(
        column_acl_violations.is_empty(),
        "A0 final column ACL drift: {column_acl_violations:?}"
    );

    let type_authority_violations: Vec<String> = sqlx::query_scalar(
        r#"
        SELECT type_row.typname
          FROM pg_type type_row
          JOIN pg_namespace namespace ON namespace.oid=type_row.typnamespace
         WHERE namespace.nspname='chat'
           AND (
                pg_get_userbyid(type_row.typowner) <> 'joshlacalamito'
                OR type_row.typacl IS NOT NULL
           )
         ORDER BY type_row.typname
        "#,
    )
    .fetch_all(&mut *connection)
    .await
    .expect("A0 final type authority must be readable");
    assert!(
        type_authority_violations.is_empty(),
        "A0 final type ownership/ACL drift: {type_authority_violations:?}"
    );
    let standalone_types: Vec<String> = sqlx::query_scalar(
        r#"
        SELECT type_row.typname
          FROM pg_type type_row
          JOIN pg_namespace namespace ON namespace.oid=type_row.typnamespace
         WHERE namespace.nspname='chat'
           AND type_row.typrelid=0
           AND type_row.typelem=0
         ORDER BY type_row.typname
        "#,
    )
    .fetch_all(&mut *connection)
    .await
    .expect("A0 final standalone-type allowlist must be readable");
    assert!(
        standalone_types.is_empty(),
        "A0 final standalone type drift: {standalone_types:?}"
    );

    let function_authority_violations: Vec<String> = sqlx::query_scalar(
        r#"
        SELECT procedure.proname || '(' ||
               pg_get_function_identity_arguments(procedure.oid) || ')'
          FROM pg_proc procedure
          JOIN pg_namespace namespace ON namespace.oid=procedure.pronamespace
         WHERE namespace.nspname='chat'
           AND (
                pg_get_userbyid(procedure.proowner) <> 'joshlacalamito'
                OR (
                    procedure.proname =
                        'allocate_relationship_projection_revision'
                    AND pg_get_function_identity_arguments(procedure.oid) = ''
                    AND (
                        procedure.proacl IS NULL
                        OR (
                            SELECT count(*)
                              FROM aclexplode(procedure.proacl)
                        ) <> 1
                        OR NOT EXISTS (
                            SELECT 1
                              FROM aclexplode(procedure.proacl) privilege
                             WHERE privilege.grantee=procedure.proowner
                               AND privilege.grantor=procedure.proowner
                               AND privilege.privilege_type='EXECUTE'
                               AND privilege.is_grantable IS FALSE
                        )
                        OR EXISTS (
                            SELECT 1
                              FROM aclexplode(procedure.proacl) privilege
                             WHERE privilege.grantee=0
                               AND privilege.privilege_type='EXECUTE'
                        )
                    )
                )
                OR (
                    NOT (
                        procedure.proname =
                            'allocate_relationship_projection_revision'
                        AND pg_get_function_identity_arguments(procedure.oid) = ''
                    )
                    AND procedure.proacl IS NOT NULL
                )
           )
         ORDER BY procedure.proname,
                  pg_get_function_identity_arguments(procedure.oid)
        "#,
    )
    .fetch_all(&mut *connection)
    .await
    .expect("A0 final function ownership/ACL authority must be readable");
    assert!(
        function_authority_violations.is_empty(),
        "A0 final function ownership/ACL or allocator PUBLIC-execute drift: \
         {function_authority_violations:?}"
    );

    let unexpected_relations: Vec<String> = sqlx::query_scalar(
        r#"
        SELECT relation.relname || '|' || relation.relkind::text
          FROM pg_class relation
          JOIN pg_namespace namespace ON namespace.oid=relation.relnamespace
         WHERE namespace.nspname='chat'
           AND relation.relkind IN ('v','m','f','p')
         ORDER BY relation.relname,relation.relkind
        "#,
    )
    .fetch_all(&mut *connection)
    .await
    .expect("A0 final view/materialized/foreign/partitioned allowlist must be readable");
    assert!(
        unexpected_relations.is_empty(),
        "A0 final view/materialized-view/foreign/partitioned relation drift: \
         {unexpected_relations:?}"
    );
    let policies: Vec<String> = sqlx::query_scalar(
        r#"
        SELECT relation.relname || '.' || policy.polname
          FROM pg_policy policy
          JOIN pg_class relation ON relation.oid=policy.polrelid
          JOIN pg_namespace namespace ON namespace.oid=relation.relnamespace
         WHERE namespace.nspname='chat'
         ORDER BY relation.relname,policy.polname
        "#,
    )
    .fetch_all(&mut *connection)
    .await
    .expect("A0 final policy allowlist must be readable");
    assert!(policies.is_empty(), "A0 final policy drift: {policies:?}");
    let non_view_rules: Vec<String> = sqlx::query_scalar(
        r#"
        SELECT relation.relname || '.' || rewrite.rulename
          FROM pg_rewrite rewrite
          JOIN pg_class relation ON relation.oid=rewrite.ev_class
          JOIN pg_namespace namespace ON namespace.oid=relation.relnamespace
         WHERE namespace.nspname='chat'
           AND rewrite.rulename <> '_RETURN'
         ORDER BY relation.relname,rewrite.rulename
        "#,
    )
    .fetch_all(&mut *connection)
    .await
    .expect("A0 final rule allowlist must be readable");
    assert!(
        non_view_rules.is_empty(),
        "A0 final non-view rule drift: {non_view_rules:?}"
    );

    let (missing_internal_trigger_roles, extra_internal_trigger_roles): (Vec<String>, Vec<String>) =
        sqlx::query_as(
            r#"
        WITH chat_constraints AS (
            SELECT constraint_row.*,
                   owner_relation.relname AS owner_relation_name,
                   referenced_relation.relname AS referenced_relation_name
              FROM pg_constraint constraint_row
              JOIN pg_namespace namespace
                ON namespace.oid=constraint_row.connamespace
              JOIN pg_class owner_relation
                ON owner_relation.oid=constraint_row.conrelid
              LEFT JOIN pg_class referenced_relation
                ON referenced_relation.oid=constraint_row.confrelid
             WHERE namespace.nspname='chat'
        ),
        expected_roles AS (
            SELECT concat_ws(
                       '|',constraint_row.owner_relation_name,
                       constraint_row.conname,
                       constraint_row.owner_relation_name,
                       'child_insert','5','pg_catalog.RI_FKey_check_ins()',
                       'O',constraint_row.condeferrable::text,
                       constraint_row.condeferred::text
                   ) AS identity
              FROM chat_constraints constraint_row
             WHERE constraint_row.contype='f'
            UNION ALL
            SELECT concat_ws(
                       '|',constraint_row.owner_relation_name,
                       constraint_row.conname,
                       constraint_row.owner_relation_name,
                       'child_update','17','pg_catalog.RI_FKey_check_upd()',
                       'O',constraint_row.condeferrable::text,
                       constraint_row.condeferred::text
                   )
              FROM chat_constraints constraint_row
             WHERE constraint_row.contype='f'
            UNION ALL
            SELECT concat_ws(
                       '|',constraint_row.owner_relation_name,
                       constraint_row.conname,
                       constraint_row.referenced_relation_name,
                       'parent_delete','9','pg_catalog.' ||
                       CASE constraint_row.confdeltype
                           WHEN 'a' THEN 'RI_FKey_noaction_del'
                           WHEN 'r' THEN 'RI_FKey_restrict_del'
                           WHEN 'c' THEN 'RI_FKey_cascade_del'
                           WHEN 'n' THEN 'RI_FKey_setnull_del'
                           WHEN 'd' THEN 'RI_FKey_setdefault_del'
                       END || '()',
                       'O',constraint_row.condeferrable::text,
                       constraint_row.condeferred::text
                   )
              FROM chat_constraints constraint_row
             WHERE constraint_row.contype='f'
            UNION ALL
            SELECT concat_ws(
                       '|',constraint_row.owner_relation_name,
                       constraint_row.conname,
                       constraint_row.referenced_relation_name,
                       'parent_update','17','pg_catalog.' ||
                       CASE constraint_row.confupdtype
                           WHEN 'a' THEN 'RI_FKey_noaction_upd'
                           WHEN 'r' THEN 'RI_FKey_restrict_upd'
                           WHEN 'c' THEN 'RI_FKey_cascade_upd'
                           WHEN 'n' THEN 'RI_FKey_setnull_upd'
                           WHEN 'd' THEN 'RI_FKey_setdefault_upd'
                       END || '()',
                       'O',constraint_row.condeferrable::text,
                       constraint_row.condeferred::text
                   )
              FROM chat_constraints constraint_row
             WHERE constraint_row.contype='f'
            UNION ALL
            SELECT concat_ws(
                       '|',constraint_row.owner_relation_name,
                       constraint_row.conname,
                       constraint_row.owner_relation_name,
                       'unique_recheck','21',
                       'pg_catalog.unique_key_recheck()',
                       'O',constraint_row.condeferrable::text,
                       constraint_row.condeferred::text
                   )
              FROM chat_constraints constraint_row
             WHERE constraint_row.contype IN ('p','u','x')
               AND constraint_row.condeferrable
        ),
        observed_roles AS (
            SELECT concat_ws(
                       '|',owner_relation.relname,constraint_row.conname,
                       trigger_relation.relname,
                       CASE
                           WHEN constraint_row.contype='f'
                                AND trigger_row.tgrelid=constraint_row.conrelid
                                AND trigger_row.tgtype=5
                               THEN 'child_insert'
                           -- The child- and parent-side update triggers share
                           -- tgtype=17, so for a self-referential FK
                           -- (conrelid=confrelid) the tgrelid test alone cannot
                           -- separate them and this arm would capture both,
                           -- making 'parent_update' unreachable. The RI
                           -- function is the ground truth: the child-side
                           -- update check is always RI_FKey_check_upd. Hence a
                           -- positive test here and a negative test below, so
                           -- the parent arm keeps matching cascade/setnull/
                           -- restrict/setdefault variants under any referential
                           -- action rather than an allow-list that would
                           -- silently drop them.
                           WHEN constraint_row.contype='f'
                                AND trigger_row.tgrelid=constraint_row.conrelid
                                AND trigger_row.tgtype=17
                                AND procedure.proname='RI_FKey_check_upd'
                               THEN 'child_update'
                           WHEN constraint_row.contype='f'
                                AND trigger_row.tgrelid=constraint_row.confrelid
                                AND trigger_row.tgtype=9
                               THEN 'parent_delete'
                           WHEN constraint_row.contype='f'
                                AND trigger_row.tgrelid=constraint_row.confrelid
                                AND trigger_row.tgtype=17
                                AND procedure.proname<>'RI_FKey_check_upd'
                               THEN 'parent_update'
                           WHEN constraint_row.contype IN ('p','u','x')
                                AND trigger_row.tgrelid=constraint_row.conrelid
                                AND trigger_row.tgtype=21
                               THEN 'unique_recheck'
                           ELSE 'unexpected'
                       END,
                       trigger_row.tgtype::text,
                       procedure_namespace.nspname || '.' ||
                       procedure.proname || '(' ||
                       pg_get_function_identity_arguments(procedure.oid) || ')',
                       trigger_row.tgenabled::text,
                       trigger_row.tgdeferrable::text,
                       trigger_row.tginitdeferred::text
                   ) AS identity
              FROM pg_trigger trigger_row
              JOIN pg_class trigger_relation
                ON trigger_relation.oid=trigger_row.tgrelid
              JOIN pg_namespace trigger_namespace
                ON trigger_namespace.oid=trigger_relation.relnamespace
              LEFT JOIN pg_constraint constraint_row
                ON constraint_row.oid=trigger_row.tgconstraint
              LEFT JOIN pg_class owner_relation
                ON owner_relation.oid=constraint_row.conrelid
              JOIN pg_proc procedure ON procedure.oid=trigger_row.tgfoid
              JOIN pg_namespace procedure_namespace
                ON procedure_namespace.oid=procedure.pronamespace
             WHERE trigger_namespace.nspname='chat'
               AND trigger_row.tgisinternal
        )
        SELECT
            ARRAY(
                SELECT identity
                  FROM (
                        SELECT identity FROM expected_roles
                        EXCEPT ALL
                        SELECT identity FROM observed_roles
                  ) missing
                 ORDER BY identity
            ),
            ARRAY(
                SELECT identity
                  FROM (
                        SELECT identity FROM observed_roles
                        EXCEPT ALL
                        SELECT identity FROM expected_roles
                  ) extra
                 ORDER BY identity
            )
        "#,
        )
        .fetch_one(&mut *connection)
        .await
        .expect("A0 final exact internal constraint-trigger roles must be readable");
    assert!(
        missing_internal_trigger_roles.is_empty() && extra_internal_trigger_roles.is_empty(),
        "A0 final internal constraint-trigger exact multiset drift; missing={:?} extra={:?}",
        missing_internal_trigger_roles,
        extra_internal_trigger_roles
    );
    let invalid_internal_trigger_semantics: Vec<String> = sqlx::query_scalar(
        r#"
        SELECT owner_relation.relname || '|' || constraint_row.conname || '|' ||
               trigger_relation.relname || '|' || procedure.proname
          FROM pg_trigger trigger_row
          JOIN pg_class trigger_relation
            ON trigger_relation.oid=trigger_row.tgrelid
          JOIN pg_namespace trigger_namespace
            ON trigger_namespace.oid=trigger_relation.relnamespace
          LEFT JOIN pg_constraint constraint_row
            ON constraint_row.oid=trigger_row.tgconstraint
          LEFT JOIN pg_class owner_relation
            ON owner_relation.oid=constraint_row.conrelid
          LEFT JOIN pg_proc procedure ON procedure.oid=trigger_row.tgfoid
          LEFT JOIN pg_namespace procedure_namespace
            ON procedure_namespace.oid=procedure.pronamespace
         WHERE trigger_namespace.nspname='chat'
           AND trigger_row.tgisinternal
           AND (
                constraint_row.oid IS NULL
                OR NOT constraint_row.convalidated
                OR trigger_row.tgenabled <> 'O'
                OR trigger_row.tgparentid <> 0
                OR trigger_row.tgqual IS NOT NULL
                OR octet_length(trigger_row.tgargs) <> 0
                OR procedure_namespace.nspname <> 'pg_catalog'
                OR pg_get_function_identity_arguments(procedure.oid) <> ''
                OR procedure.prorettype <> 'trigger'::regtype
                OR procedure.prokind <> 'f'
                OR (trigger_row.tgtype & 1) <> 1
                OR (trigger_row.tgtype & 2) <> 0
                OR (trigger_row.tgtype & 64) <> 0
                OR trigger_row.tgdeferrable
                       IS DISTINCT FROM constraint_row.condeferrable
                OR trigger_row.tginitdeferred
                       IS DISTINCT FROM constraint_row.condeferred
                OR (
                    constraint_row.contype='f'
                    AND NOT (
                        (
                            trigger_row.tgrelid=constraint_row.conrelid
                            AND trigger_row.tgtype=5
                            AND procedure.proname='RI_FKey_check_ins'
                        )
                        OR (
                            trigger_row.tgrelid=constraint_row.conrelid
                            AND trigger_row.tgtype=17
                            AND procedure.proname='RI_FKey_check_upd'
                        )
                        OR (
                            trigger_row.tgrelid=constraint_row.confrelid
                            AND trigger_row.tgtype=9
                            AND procedure.proname=CASE constraint_row.confdeltype
                                WHEN 'a' THEN 'RI_FKey_noaction_del'
                                WHEN 'r' THEN 'RI_FKey_restrict_del'
                                WHEN 'c' THEN 'RI_FKey_cascade_del'
                                WHEN 'n' THEN 'RI_FKey_setnull_del'
                                WHEN 'd' THEN 'RI_FKey_setdefault_del'
                            END
                        )
                        OR (
                            trigger_row.tgrelid=constraint_row.confrelid
                            AND trigger_row.tgtype=17
                            AND procedure.proname=CASE constraint_row.confupdtype
                                WHEN 'a' THEN 'RI_FKey_noaction_upd'
                                WHEN 'r' THEN 'RI_FKey_restrict_upd'
                                WHEN 'c' THEN 'RI_FKey_cascade_upd'
                                WHEN 'n' THEN 'RI_FKey_setnull_upd'
                                WHEN 'd' THEN 'RI_FKey_setdefault_upd'
                            END
                        )
                    )
                )
                OR (
                    constraint_row.contype IN ('p','u','x')
                    AND (
                        NOT constraint_row.condeferrable
                        OR trigger_row.tgrelid <> constraint_row.conrelid
                        OR trigger_row.tgtype <> 21
                        OR procedure.proname <> 'unique_key_recheck'
                    )
                )
                OR constraint_row.contype NOT IN ('f','p','u','x')
           )
         ORDER BY owner_relation.relname,constraint_row.conname,
                  trigger_relation.relname,procedure.proname
        "#,
    )
    .fetch_all(&mut *connection)
    .await
    .expect("A0 final internal trigger semantics must be readable");
    assert!(
        invalid_internal_trigger_semantics.is_empty(),
        "A0 final internal constraint-trigger function/timing/event/row/enabled/\
         deferrability drift: {invalid_internal_trigger_semantics:?}"
    );

    let sequence_ownership: Vec<String> = sqlx::query_scalar(
        r#"
        SELECT sequence.relname || '|' ||
               COALESCE(owner_relation.relname || '.' || attribute.attname,'')
          FROM pg_class sequence
          JOIN pg_namespace namespace ON namespace.oid=sequence.relnamespace
          LEFT JOIN pg_depend dependency
            ON dependency.classid='pg_class'::regclass
           AND dependency.objid=sequence.oid
           AND dependency.refclassid='pg_class'::regclass
           AND dependency.deptype IN ('a','i')
          LEFT JOIN pg_class owner_relation
            ON owner_relation.oid=dependency.refobjid
          LEFT JOIN pg_attribute attribute
            ON attribute.attrelid=dependency.refobjid
           AND attribute.attnum=dependency.refobjsubid
         WHERE namespace.nspname='chat'
           AND sequence.relkind='S'
         ORDER BY sequence.relname
        "#,
    )
    .fetch_all(connection)
    .await
    .expect("A0 final sequence ownership authority must be readable");
    assert_eq!(
        sequence_ownership,
        [
            "events_event_position_seq|events.event_position".to_owned(),
            "relationship_projection_revision_seq|".to_owned(),
        ],
        "A0 final sequence ownership drift"
    );

    vec![
        format!("database_owner={database_owner}|acl={database_acl}"),
        format!("public_owner={public_owner}|acl={}", public_acl.join(",")),
        format!(
            "sqlx_ledger_relations={}",
            public_ledger_relations.join(",")
        ),
        format!("sqlx_ledger_columns={}", public_ledger_columns.join(",")),
        format!("sqlx_ledger_constraint={public_ledger_constraint}"),
        format!("sqlx_ledger_triggers={}", public_ledger_triggers.join(",")),
        format!("sqlx_ledger_rules={}", public_ledger_rules.join(",")),
        format!("sqlx_ledger_policies={}", public_ledger_policies.join(",")),
        format!("chat_owner={chat_owner}|acl={chat_acl}"),
        "relations=owned,no-acl,no-rls,default-replica".to_owned(),
        "columns=no-acl".to_owned(),
        "types=owned,no-acl,no-standalone".to_owned(),
        "functions=owned,exact-allocator-acl".to_owned(),
        "views=0|materialized_views=0|policies=0|rules=0".to_owned(),
        format!(
            "internal_constraint_trigger_roles=exact|missing={}|extra={}",
            missing_internal_trigger_roles.len(),
            extra_internal_trigger_roles.len()
        ),
        format!("sequence_ownership={}", sequence_ownership.join(",")),
    ]
}

async fn a0_assert_post_clean_catalog(connection: &mut PgConnection) -> String {
    let schemas: Vec<String> = sqlx::query_scalar(
        r#"
        SELECT nspname
          FROM pg_namespace
         WHERE nspname <> 'information_schema'
           AND nspname !~ '^pg_'
         ORDER BY nspname
        "#,
    )
    .fetch_all(&mut *connection)
    .await
    .expect("A0 final schema allowlist must be readable");
    assert_eq!(schemas, ["chat", "public"], "A0 final user-schema drift");
    let extension_hash = a0_assert_extension_allowlist(&mut *connection).await;
    let (public_relations, public_constraints, standalone_objects) =
        a0_nonextension_public_catalog(&mut *connection).await;
    assert_eq!(
        public_relations,
        [
            "_sqlx_migrations|r".to_owned(),
            "_sqlx_migrations_pkey|i".to_owned(),
            "auth_jti_nonce|r".to_owned(),
            "auth_jti_nonce_pkey|i".to_owned(),
            "federation_outbox|r".to_owned(),
            "federation_outbox_pkey|i".to_owned(),
            "federation_sync_state|r".to_owned(),
            "federation_sync_state_pkey|i".to_owned(),
            "idx_auth_jti_nonce_expires|i".to_owned(),
            "idx_federation_outbox_due_v2|i".to_owned(),
            "idx_federation_outbox_lease|i".to_owned(),
            "idx_outbound_queue_due_v2|i".to_owned(),
            "idx_outbound_queue_lease|i".to_owned(),
            "outbound_queue|r".to_owned(),
            "outbound_queue_pkey|i".to_owned(),
        ],
        "A0 final public relation allowlist drift"
    );
    assert_eq!(
        public_constraints,
        [
            "_sqlx_migrations_pkey|p".to_owned(),
            "auth_jti_nonce_pkey|p".to_owned(),
            "federation_outbox_pkey|p".to_owned(),
            "federation_sync_state_pkey|p".to_owned(),
            "federation_sync_state_quarantine_shape_check|c".to_owned(),
            "federation_sync_state_status_check|c".to_owned(),
            "outbound_queue_pkey|p".to_owned(),
            "outbound_queue_status_check|c".to_owned(),
        ],
        "A0 final public constraint allowlist drift"
    );
    assert!(
        standalone_objects.is_empty(),
        "A0 final public standalone-object allowlist drift: {standalone_objects:?}"
    );
    let tables: BTreeSet<String> = sqlx::query_scalar(
        "SELECT table_name::text FROM information_schema.tables WHERE table_schema='chat' AND table_type='BASE TABLE' ORDER BY table_name",
    )
    .fetch_all(&mut *connection)
    .await
    .expect("A0 final table allowlist must be readable")
    .into_iter()
    .collect();
    assert_eq!(tables, expected_tables(), "A0 final chat table drift");
    let authority_surfaces = a0_assert_post_clean_authority_surfaces(&mut *connection).await;

    let column_hash = a0_catalog_hash(
        &mut *connection,
        r#"
        SELECT concat_ws('|',c.relname,a.attnum::text,a.attname,
                         format_type(a.atttypid,a.atttypmod),a.attnotnull::text,
                         coalesce(pg_get_expr(ad.adbin,ad.adrelid,true),''),
                         a.attidentity::text,a.attgenerated::text,
                         coalesce(coll.collname,''))
          FROM pg_attribute a
          JOIN pg_class c ON c.oid=a.attrelid
          JOIN pg_namespace n ON n.oid=c.relnamespace
          LEFT JOIN pg_attrdef ad ON ad.adrelid=a.attrelid AND ad.adnum=a.attnum
          LEFT JOIN pg_collation coll ON coll.oid=a.attcollation AND a.attcollation<>0
         WHERE n.nspname='chat' AND c.relkind='r' AND a.attnum>0 AND NOT a.attisdropped
         ORDER BY c.relname,a.attnum
        "#,
        "column",
        COLUMN_CATALOG_SHA256,
    )
    .await;
    let constraint_hash = a0_catalog_hash(
        &mut *connection,
        r#"
        SELECT concat_ws('|',c.relname,con.conname,con.contype::text,
                         con.condeferrable::text,con.condeferred::text,
                         con.convalidated::text,pg_get_constraintdef(con.oid,false))
          FROM pg_constraint con
          JOIN pg_class c ON c.oid=con.conrelid
          JOIN pg_namespace n ON n.oid=c.relnamespace
         WHERE n.nspname='chat'
         ORDER BY c.relname,con.conname
        "#,
        "constraint",
        CONSTRAINT_CATALOG_SHA256,
    )
    .await;
    let index_hash = a0_catalog_hash(
        &mut *connection,
        r#"
        SELECT concat_ws('|',t.relname,i.relname,x.indisunique::text,
                         x.indisprimary::text,x.indisvalid::text,x.indisready::text,
                         x.indisclustered::text,x.indisreplident::text,
                         pg_get_indexdef(i.oid),
                         coalesce(pg_get_expr(x.indpred,x.indrelid,false),''))
          FROM pg_index x
          JOIN pg_class i ON i.oid=x.indexrelid
          JOIN pg_class t ON t.oid=x.indrelid
          JOIN pg_namespace n ON n.oid=t.relnamespace
         WHERE n.nspname='chat'
         ORDER BY t.relname,i.relname
        "#,
        "index",
        INDEX_CATALOG_SHA256,
    )
    .await;
    let function_hash = a0_catalog_hash(
        &mut *connection,
        r#"
        SELECT concat_ws('|',p.proname,pg_get_function_identity_arguments(p.oid),
                         pg_get_function_result(p.oid),l.lanname,p.provolatile::text,
                         p.proisstrict::text,p.proparallel::text,p.prosecdef::text,
                         p.proleakproof::text,coalesce(array_to_string(p.proconfig,','),''),
                         encode(digest(pg_get_functiondef(p.oid),'sha256'),'hex'))
          FROM pg_proc p
          JOIN pg_namespace n ON n.oid=p.pronamespace
          JOIN pg_language l ON l.oid=p.prolang
         WHERE n.nspname='chat'
         ORDER BY p.proname,pg_get_function_identity_arguments(p.oid)
        "#,
        "function",
        FUNCTION_CATALOG_SHA256,
    )
    .await;
    let trigger_hash = a0_catalog_hash(
        &mut *connection,
        r#"
        SELECT concat_ws('|',c.relname,t.tgname,t.tgenabled::text,t.tgtype::text,
                         t.tgdeferrable::text,t.tginitdeferred::text,p.proname,
                         pg_get_triggerdef(t.oid,false))
          FROM pg_trigger t
          JOIN pg_class c ON c.oid=t.tgrelid
          JOIN pg_namespace n ON n.oid=c.relnamespace
          JOIN pg_proc p ON p.oid=t.tgfoid
         WHERE n.nspname='chat' AND NOT t.tgisinternal
         ORDER BY c.relname,t.tgname
        "#,
        "trigger",
        TRIGGER_CATALOG_SHA256,
    )
    .await;
    let sequence_hash = a0_catalog_hash(
        connection,
        r#"
        SELECT concat_ws('|',schemaname,sequencename,data_type,start_value::text,
                         min_value::text,max_value::text,increment_by::text,
                         cycle::text,cache_size::text)
          FROM pg_sequences
         WHERE schemaname='chat'
         ORDER BY sequencename
        "#,
        "sequence",
        SEQUENCE_CATALOG_SHA256,
    )
    .await;
    catalog_fingerprint(&[
        extension_hash,
        column_hash,
        constraint_hash,
        index_hash,
        function_hash,
        trigger_hash,
        sequence_hash,
        catalog_fingerprint(&authority_surfaces),
    ])
}

#[tokio::test]
#[ignore = "coordinator-only one-shot old-OID/full-fingerprint forward reconciliation"]
async fn forward_reconcile_exact_fingerprinted_legacy_local_chat_protocol_test_database() {
    // This runtime binding is intentionally first: malformed approval cannot
    // inspect a marker, open PostgreSQL, acquire a lock, or mutate anything.
    let binding = a0_read_approved_runtime_binding().expect("A0 approved runtime binding");
    let consumed_before = a0_read_consumed_marker().expect("A0 global marker preflight");
    if let Some((payload, _)) = &consumed_before {
        // A marker records the candidate that performed the destruction, which
        // is necessarily a prior one. Only its candidate-independent half may
        // be required here; requiring the running binding would make every
        // marker-present branch unreachable for every later candidate.
        assert!(
            payload.matches_legacy_constants(),
            "A0 consumed marker is not bound to the compiled legacy authority constants"
        );
    }
    let supplied_url = std::env::var("TEST_DATABASE_URL")
        .expect("A0 requires the exact disposable local clean-chat database URL");
    assert_eq!(
        supplied_url, A0_EXACT_DATABASE_URL,
        "A0 refuses an arbitrary, derived, remote, or differently named database URL"
    );
    let activation_approval = std::env::var("CHAT_OPERATION_CLAIM_ACTIVATION_APPROVED")
        .expect("A0 requires the exact operation-claim activation approval");
    crate::common::chat_protocol::validate_chat_protocol_activation_approval(Some(
        &activation_approval,
    ))
    .expect("A0 refuses an invalid operation-claim activation approval");
    let migrator = crate::common::chat_protocol::reviewed_clean_protocol_migrator()
        .await
        .expect("A0 exact-13 manifest must validate before opening PostgreSQL");

    let mut admin = PgConnection::connect(A0_EXACT_ADMIN_URL)
        .await
        .expect("A0 connect to literal local /postgres administration database");
    let (admin_database, admin_role, admin_address, admin_port, _admin_pid): (
        String,
        String,
        Option<String>,
        Option<i32>,
        i32,
    ) = sqlx::query_as(
        "SELECT current_database(),current_user,host(inet_server_addr()),\
         inet_server_port(),pg_backend_pid()",
    )
    .fetch_one(&mut admin)
    .await
    .expect("A0 admin identity must be readable");
    assert_eq!(admin_database, "postgres");
    assert_eq!(admin_role, A0_EXACT_OWNER);
    assert_eq!(admin_address.as_deref(), Some("127.0.0.1"));
    assert_eq!(admin_port, Some(5432));
    a0_assert_lock(
        &mut admin,
        A0_ADMIN_LOCK_CLASS,
        A0_ADMIN_LOCK_OBJECT,
        "A0 admin",
    )
    .await;
    let target_jobs_before: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM pg_stat_activity \
         WHERE datname='catbird_chat_protocol_test_20260722'",
    )
    .fetch_one(&mut admin)
    .await
    .expect("A0 pre-target job inventory must be readable");
    assert_eq!(
        target_jobs_before, 0,
        "A0 refuses any target database job before opening its own connection"
    );

    let mut target = PgConnection::connect(A0_EXACT_DATABASE_URL)
        .await
        .expect("A0 connect to literal exact target database");
    let target_identity = a0_read_target_identity(&mut target).await;
    assert!(
        target_identity.allow_connections,
        "A0 preflight requires datallowconn=true"
    );
    let target_pid = target_identity.pid;
    a0_assert_lock(
        &mut target,
        A0_TARGET_LOCK_CLASS,
        A0_TARGET_LOCK_OBJECT,
        "A0 target",
    )
    .await;
    a0_assert_only_target_pid(&mut admin, target_pid).await;

    let ledger_before = a0_ledger(&mut target).await;
    if ledger_before == a0_expected_ledger() {
        let pre_ledger_hash = a0_assert_exact_ledger(&mut target).await;
        let pre_catalog_hash = a0_assert_post_clean_catalog(&mut target).await;
        let marker_before = consumed_before.clone();
        sqlx::query(
            "SET chat.operation_claim_activation_approved = \
             'handlers-and-legacy-apis-sealed'",
        )
        .execute(&mut target)
        .await
        .expect("A0 set activation approval for exact-13 no-op");
        migrator
            .run_direct(&mut target)
            .await
            .expect("A0 exact-13 branch must be a SQLx no-op");
        sqlx::query("RESET chat.operation_claim_activation_approved")
            .execute(&mut target)
            .await
            .expect("A0 reset activation approval after exact-13 no-op");
        assert_eq!(
            a0_ledger(&mut target).await,
            ledger_before,
            "A0 exact-13 branch attempted a migration"
        );
        let post_ledger_hash = a0_assert_exact_ledger(&mut target).await;
        let post_catalog_hash = a0_assert_post_clean_catalog(&mut target).await;
        assert_eq!(
            post_ledger_hash, pre_ledger_hash,
            "A0 exact-13 ledger fingerprint changed"
        );
        assert_eq!(
            post_catalog_hash, pre_catalog_hash,
            "A0 exact-13 catalog fingerprint changed"
        );
        let durable_completeness =
            crate::common::chat_protocol::validate_durable_operation_claim_completeness(
                &mut target,
            )
            .await
            .expect("A0 exact-13 durable operation-claim completeness");
        let marker_after = a0_read_consumed_marker().expect("A0 exact-13 global marker postflight");
        assert_eq!(
            marker_after, marker_before,
            "A0 exact-13 branch changed the durable marker state"
        );
        // When a prior attempt's marker is present, this branch carries its
        // provenance too, so a post-migration recovery failure that lands here
        // on a later run still reports which authority performed the deletion.
        let (marker_state, marker_sha256, marker_provenance) = match marker_after {
            None => ("absent", None, None),
            Some((payload, bytes)) => (
                "preexisting_consumed",
                Some(hex::encode(Sha256::digest(bytes))),
                Some(payload),
            ),
        };
        let final_identity = a0_read_target_identity(&mut target).await;
        assert_eq!(final_identity.database_oid, target_identity.database_oid);
        assert!(final_identity.allow_connections);
        a0_assert_only_target_pid(&mut admin, target_pid).await;
        let final_evidence = A0CanonicalEvidence {
            decision: "already_reconciled",
            material_deletion: false,
            pre_oid: target_identity.database_oid,
            post_oid: final_identity.database_oid,
            migrations_applied: 0,
            pre_ledger_sha256: pre_ledger_hash,
            post_ledger_sha256: post_ledger_hash,
            pre_catalog_sha256: pre_catalog_hash,
            post_catalog_sha256: post_catalog_hash,
            classified_legacy_count: durable_completeness.legacy_receipt_count,
            classified_legacy_set_sha256: hex::encode(
                durable_completeness.legacy_receipt_set_sha256,
            ),
            marker_state,
            marker_sha256,
            approved_revision: binding.revision.clone(),
            approved_manifest_sha256: binding.manifest_sha256.clone(),
            marker_legacy_ledger_sha256: marker_provenance
                .as_ref()
                .map(|payload| payload.legacy_ledger_sha256.clone()),
            marker_legacy_catalog_sha256: marker_provenance
                .as_ref()
                .map(|payload| payload.legacy_catalog_sha256.clone()),
            marker_approved_revision: marker_provenance
                .as_ref()
                .map(|payload| payload.approved_revision.clone()),
            marker_approved_manifest_sha256: marker_provenance
                .as_ref()
                .map(|payload| payload.approved_manifest_sha256.clone()),
        };
        a0_unlock(
            &mut target,
            A0_TARGET_LOCK_CLASS,
            A0_TARGET_LOCK_OBJECT,
            "A0 target",
        )
        .await;
        target.close().await.expect("close A0 exact-13 target");
        a0_unlock(
            &mut admin,
            A0_ADMIN_LOCK_CLASS,
            A0_ADMIN_LOCK_OBJECT,
            "A0 admin",
        )
        .await;
        admin.close().await.expect("close A0 admin");
        final_evidence.emit();
        return;
    }

    // Recovery branch. The destruction already happened under a prior attempt
    // whose marker is the sole surviving authority for the legacy fingerprint.
    // This branch reads that marker, never rewrites it, never re-derives the
    // fingerprint, and references no destructive statement.
    if let Some((marker_payload, marker_bytes)) = &consumed_before {
        assert!(
            ledger_before.is_empty(),
            "A0 consumed marker with a non-empty, non-exact-13 ledger is not a recoverable \
             state: {} rows",
            ledger_before.len()
        );
        let pre_ledger_hash = a0_ledger_fingerprint(&ledger_before);
        let pre_catalog_hash = a0_assert_recovery_target_is_pristine(&mut target).await;
        assert_ne!(
            target_identity.database_oid, A0_EXPECTED_LEGACY_OID,
            "A0 recovery target still carries the compiled legacy OID"
        );

        sqlx::query(
            "SET chat.operation_claim_activation_approved = \
             'handlers-and-legacy-apis-sealed'",
        )
        .execute(&mut target)
        .await
        .expect("A0 set activation approval for recovery");
        let migration_result = migrator.run_direct(&mut target).await;
        sqlx::query("RESET chat.operation_claim_activation_approved")
            .execute(&mut target)
            .await
            .expect("A0 reset activation approval after recovery");
        migration_result.expect("A0 run only the reviewed exact-13 migrator on recovery");

        let post_ledger_hash = a0_assert_exact_ledger(&mut target).await;
        let post_catalog_hash = a0_assert_post_clean_catalog(&mut target).await;
        let durable_completeness =
            crate::common::chat_protocol::validate_durable_operation_claim_completeness(
                &mut target,
            )
            .await
            .expect("A0 recovery durable operation-claim completeness");
        let final_identity = a0_read_target_identity(&mut target).await;
        assert_eq!(
            final_identity.database_oid, target_identity.database_oid,
            "A0 recovery target OID drift"
        );
        assert!(final_identity.allow_connections);
        a0_assert_only_target_pid(&mut admin, target_pid).await;
        let marker_after = a0_read_consumed_marker().expect("A0 recovery global marker postflight");
        assert_eq!(
            marker_after.as_ref(),
            consumed_before.as_ref(),
            "A0 recovery branch changed the durable marker state"
        );
        let final_evidence = A0CanonicalEvidence {
            decision: "recovery_from_consumed_marker",
            material_deletion: false,
            pre_oid: target_identity.database_oid,
            post_oid: final_identity.database_oid,
            migrations_applied: 13,
            pre_ledger_sha256: pre_ledger_hash,
            post_ledger_sha256: post_ledger_hash,
            pre_catalog_sha256: pre_catalog_hash,
            post_catalog_sha256: post_catalog_hash,
            classified_legacy_count: durable_completeness.legacy_receipt_count,
            classified_legacy_set_sha256: hex::encode(
                durable_completeness.legacy_receipt_set_sha256,
            ),
            marker_state: "preexisting_consumed",
            marker_sha256: Some(hex::encode(Sha256::digest(marker_bytes))),
            approved_revision: binding.revision.clone(),
            approved_manifest_sha256: binding.manifest_sha256.clone(),
            marker_legacy_ledger_sha256: Some(marker_payload.legacy_ledger_sha256.clone()),
            marker_legacy_catalog_sha256: Some(marker_payload.legacy_catalog_sha256.clone()),
            marker_approved_revision: Some(marker_payload.approved_revision.clone()),
            marker_approved_manifest_sha256: Some(marker_payload.approved_manifest_sha256.clone()),
        };
        a0_unlock(
            &mut target,
            A0_TARGET_LOCK_CLASS,
            A0_TARGET_LOCK_OBJECT,
            "A0 recovery target",
        )
        .await;
        target.close().await.expect("close A0 recovery target");
        a0_unlock(
            &mut admin,
            A0_ADMIN_LOCK_CLASS,
            A0_ADMIN_LOCK_OBJECT,
            "A0 admin",
        )
        .await;
        admin.close().await.expect("close A0 admin");
        final_evidence.emit();
        return;
    }

    // Retained unchanged. With the recovery branch above returning or stopping
    // on every marker-present state, this is now a defence-in-depth invariant
    // rather than the sole gate.
    assert!(
        consumed_before.is_none(),
        "A0 consumed marker permits only the exact-13 validation branch"
    );
    let legacy_facts = a0_collect_legacy_facts(&mut target, &target_identity)
        .await
        .expect("A0 read exact legacy authority fingerprint");
    let target_identity_after_fingerprint = a0_read_target_identity(&mut target).await;
    assert_eq!(
        target_identity_after_fingerprint, target_identity,
        "A0 target identity drifted while collecting the legacy fingerprint"
    );
    a0_assert_only_target_pid(&mut admin, target_pid).await;
    let legacy_authority = a0_seal_legacy_forward_reconcile(legacy_facts)
        .expect("A0 target is neither exact-13 nor the authorized legacy fingerprint");
    let pre_ledger_hash = legacy_authority.sealed_facts.ledger_sha256.clone();
    let pre_catalog_hash = legacy_authority.sealed_facts.catalog_sha256.clone();
    assert_eq!(
        legacy_authority.expected_old_oid, A0_EXPECTED_LEGACY_OID,
        "A0 destructive authority is not bound to the compiled old OID"
    );
    assert!(
        !Path::new(A0_INTENT_PATH).try_exists().unwrap()
            && !Path::new(A0_CONSUMED_PATH).try_exists().unwrap(),
        "A0 destructive marker state changed under locks"
    );

    let marker_payload = A0MarkerPayload::new(&binding, Utc::now());
    let pre_alter_intent =
        A0DurablePreAlterIntent::create(&marker_payload).expect("create durable A0 intent");
    if Path::new(A0_CONSUMED_PATH)
        .try_exists()
        .expect("recheck A0 consumed marker before ALTER")
    {
        pre_alter_intent
            .remove_before_alter()
            .expect("remove pre-ALTER intent after destination race");
        panic!("A0 consumed marker appeared before ALTER");
    }
    let alter_attempted = pre_alter_intent.into_alter_attempted();
    sqlx::query(A0_DISABLE_CONNECTIONS_SQL)
        .execute(&mut admin)
        .await
        .expect("A0 static datallowconn=false fence failed; intent retained");
    let consumed_marker = alter_attempted
        .promote_no_replace()
        .expect("A0 atomic consumed-marker promotion failed; fence retained");
    let marker_bytes = consumed_marker
        .validate(&marker_payload)
        .expect("A0 consumed marker validation after promotion");

    let fenced_revalidation = AssertUnwindSafe(async {
        let identity = a0_read_target_identity(&mut target).await;
        if identity.database_oid != A0_EXPECTED_LEGACY_OID || identity.allow_connections {
            return Err("A0 fenced identity/OID/datallowconn drift".to_owned());
        }
        let Some((admin_oid, admin_allow_connections, admin_owner)) =
            a0_admin_database_state(&mut admin).await?
        else {
            return Err("A0 fenced target disappeared".to_owned());
        };
        if admin_oid != A0_EXPECTED_LEGACY_OID
            || admin_allow_connections
            || admin_owner != A0_EXACT_OWNER
        {
            return Err("A0 admin fence postcondition drift".to_owned());
        }
        a0_assert_only_target_pid(&mut admin, target_pid).await;
        let facts = a0_collect_legacy_facts(&mut target, &identity).await?;
        a0_revalidate_fenced_legacy(&legacy_authority, facts).map_err(str::to_owned)
    })
    .catch_unwind()
    .await;
    let fenced_error = match fenced_revalidation {
        Ok(Ok(())) => None,
        Ok(Err(error)) => Some(error),
        Err(_) => Some("A0 fenced legacy revalidation panicked".to_owned()),
    };
    if let Some(error) = fenced_error {
        let restore = a0_guarded_restore_legacy_connections(&mut admin).await;
        panic!("A0 pre-drop revalidation failed: {error}; guarded restoration={restore:?}");
    }

    if let Err(error) = target.close().await {
        let restore = a0_guarded_restore_legacy_connections(&mut admin).await;
        panic!("A0 old-target close failed before drop: {error}; guarded restoration={restore:?}");
    }

    // `drop_begun` is true immediately before this static statement. No
    // awaited work may intervene between DROP completion and CREATE submission.
    let drop_result = sqlx::query(A0_DROP_DATABASE_SQL).execute(&mut admin).await;
    let create_result = match drop_result {
        Ok(_) => {
            sqlx::query(A0_CREATE_DATABASE_SQL)
                .execute(&mut admin)
                .await
        }
        Err(error) => {
            let observed = a0_admin_database_state(&mut admin).await;
            panic!("A0 DROP failed after drop_begun: {error}; observed={observed:?}");
        }
    };
    if let Err(error) = create_result {
        let observed = a0_admin_database_state(&mut admin).await;
        panic!("A0 CREATE failed after drop_begun: {error}; observed={observed:?}");
    }

    let mut replacement = PgConnection::connect(A0_EXACT_DATABASE_URL)
        .await
        .expect("connect exact A0 replacement target");
    a0_assert_lock(
        &mut replacement,
        A0_TARGET_LOCK_CLASS,
        A0_TARGET_LOCK_OBJECT,
        "A0 replacement target",
    )
    .await;
    let replacement_identity = a0_read_target_identity(&mut replacement).await;
    assert_ne!(
        replacement_identity.database_oid, A0_EXPECTED_LEGACY_OID,
        "A0 replacement unexpectedly reused the compiled old OID"
    );
    assert!(
        replacement_identity.allow_connections,
        "A0 replacement requires datallowconn=true"
    );
    let replacement_pid = replacement_identity.pid;
    a0_assert_only_target_pid(&mut admin, replacement_pid).await;
    assert!(
        a0_target_is_pristine(&mut replacement).await,
        "A0 replacement database is outside the reviewed pristine allowlist"
    );

    sqlx::query(
        "SET chat.operation_claim_activation_approved = \
         'handlers-and-legacy-apis-sealed'",
    )
    .execute(&mut replacement)
    .await
    .expect("A0 set activation approval on replacement");
    let migration_result = migrator.run_direct(&mut replacement).await;
    sqlx::query("RESET chat.operation_claim_activation_approved")
        .execute(&mut replacement)
        .await
        .expect("A0 reset activation approval on replacement");
    migration_result.expect("A0 run only the reviewed exact-13 migrator on replacement");

    let ledger_hash = a0_assert_exact_ledger(&mut replacement).await;
    let catalog_hash = a0_assert_post_clean_catalog(&mut replacement).await;
    let durable_completeness =
        crate::common::chat_protocol::validate_durable_operation_claim_completeness(
            &mut replacement,
        )
        .await
        .expect("A0 replacement durable operation-claim completeness");
    let final_identity = a0_read_target_identity(&mut replacement).await;
    assert_eq!(
        final_identity.database_oid, replacement_identity.database_oid,
        "A0 replacement OID drift"
    );
    assert!(final_identity.allow_connections);
    a0_assert_only_target_pid(&mut admin, replacement_pid).await;
    assert!(!Path::new(A0_INTENT_PATH).try_exists().unwrap());
    let final_marker_bytes = consumed_marker
        .validate(&marker_payload)
        .expect("A0 final immutable consumed marker");
    assert_eq!(final_marker_bytes, marker_bytes);
    let final_evidence = A0CanonicalEvidence {
        decision: "legacy_forward_reconcile",
        material_deletion: true,
        pre_oid: A0_EXPECTED_LEGACY_OID,
        post_oid: final_identity.database_oid,
        migrations_applied: 13,
        pre_ledger_sha256: pre_ledger_hash,
        post_ledger_sha256: ledger_hash,
        pre_catalog_sha256: pre_catalog_hash,
        post_catalog_sha256: catalog_hash,
        classified_legacy_count: durable_completeness.legacy_receipt_count,
        classified_legacy_set_sha256: hex::encode(durable_completeness.legacy_receipt_set_sha256),
        marker_state: "created_consumed",
        marker_sha256: Some(hex::encode(Sha256::digest(&marker_bytes))),
        approved_revision: binding.revision.clone(),
        approved_manifest_sha256: binding.manifest_sha256.clone(),
        // This run created the marker, so its provenance is the running
        // binding already bound above; recording it again would be redundant.
        marker_legacy_ledger_sha256: None,
        marker_legacy_catalog_sha256: None,
        marker_approved_revision: None,
        marker_approved_manifest_sha256: None,
    };

    a0_unlock(
        &mut replacement,
        A0_TARGET_LOCK_CLASS,
        A0_TARGET_LOCK_OBJECT,
        "A0 replacement target",
    )
    .await;
    replacement.close().await.expect("close A0 replacement");
    a0_unlock(
        &mut admin,
        A0_ADMIN_LOCK_CLASS,
        A0_ADMIN_LOCK_OBJECT,
        "A0 admin",
    )
    .await;
    admin.close().await.expect("close A0 admin");
    final_evidence.emit();
}

async fn fresh_pool() -> PgPool {
    crate::common::chat_protocol::setup_chat_protocol_db(1).await
}

#[derive(Clone, Copy)]
enum PublicLedgerMutationExpectation {
    AttachedTrigger,
    AttachedRewriteRule,
    AttachedPolicy,
    RowLevelSecurity,
}

fn assert_expected_public_ledger_drift(
    expected: PublicLedgerMutationExpectation,
    drift: PublicLedgerClosedCatalogDrift,
) {
    match (expected, drift) {
        (
            PublicLedgerMutationExpectation::AttachedTrigger,
            PublicLedgerClosedCatalogDrift::AttachedTriggers(triggers),
        ) => {
            assert_eq!(
                triggers.len(),
                1,
                "trigger mutation must expose exactly one attached trigger"
            );
            assert!(
                triggers[0].contains("public.a0_unapproved_ledger_trigger()")
                    && triggers[0].contains("CREATE TRIGGER a0_unapproved_ledger_trigger"),
                "trigger mutation exposed the wrong closed-catalog object: {triggers:?}"
            );
        }
        (
            PublicLedgerMutationExpectation::AttachedRewriteRule,
            PublicLedgerClosedCatalogDrift::AttachedRewriteRules(rules),
        ) => {
            assert_eq!(
                rules.len(),
                1,
                "rewrite-rule mutation must expose exactly one attached rule"
            );
            assert!(
                rules[0].contains("a0_unapproved_ledger_rule") && rules[0].contains("CREATE RULE"),
                "rewrite-rule mutation exposed the wrong closed-catalog object: {rules:?}"
            );
        }
        (
            PublicLedgerMutationExpectation::AttachedPolicy,
            PublicLedgerClosedCatalogDrift::AttachedPolicies(policies),
        ) => {
            assert_eq!(
                policies.len(),
                1,
                "policy mutation must expose exactly one attached policy"
            );
            assert!(
                policies[0].contains("a0_unapproved_ledger_policy"),
                "policy mutation exposed the wrong closed-catalog object: {policies:?}"
            );
        }
        (
            PublicLedgerMutationExpectation::RowLevelSecurity,
            PublicLedgerClosedCatalogDrift::RowLevelSecurity { enabled, forced },
        ) => {
            assert!(
                enabled && !forced,
                "RLS mutation exposed the wrong closed-catalog state: \
                 enabled={enabled}, forced={forced}"
            );
        }
        (expected, actual) => {
            panic!(
                "public SQLx-ledger mutation produced the wrong classified drift: \
                 expected={}, actual={actual:?}",
                match expected {
                    PublicLedgerMutationExpectation::AttachedTrigger => "attached trigger",
                    PublicLedgerMutationExpectation::AttachedRewriteRule => {
                        "attached rewrite rule"
                    }
                    PublicLedgerMutationExpectation::AttachedPolicy => "attached policy",
                    PublicLedgerMutationExpectation::RowLevelSecurity => "RLS state",
                }
            );
        }
    }
}

async fn observe_exact_public_ledger_mutation(
    connection: &mut PgConnection,
    expected: PublicLedgerMutationExpectation,
) -> Result<bool, sqlx::Error> {
    match expected {
        PublicLedgerMutationExpectation::AttachedTrigger => {
            sqlx::query_scalar(
                "SELECT count(*)=1 \
                   FROM pg_trigger trigger_row \
                   JOIN pg_class relation ON relation.oid=trigger_row.tgrelid \
                   JOIN pg_namespace relation_namespace \
                     ON relation_namespace.oid=relation.relnamespace \
                   JOIN pg_proc procedure ON procedure.oid=trigger_row.tgfoid \
                   JOIN pg_namespace procedure_namespace \
                     ON procedure_namespace.oid=procedure.pronamespace \
                  WHERE relation_namespace.nspname='public' \
                    AND relation.relname='_sqlx_migrations' \
                    AND trigger_row.tgname='a0_unapproved_ledger_trigger' \
                    AND NOT trigger_row.tgisinternal \
                    AND procedure_namespace.nspname='public' \
                    AND procedure.proname='a0_unapproved_ledger_trigger' \
                    AND procedure.pronargs=0",
            )
            .fetch_one(connection)
            .await
        }
        PublicLedgerMutationExpectation::AttachedRewriteRule => {
            sqlx::query_scalar(
                "SELECT count(*)=1 \
                   FROM pg_rewrite rewrite \
                   JOIN pg_class relation ON relation.oid=rewrite.ev_class \
                   JOIN pg_namespace namespace ON namespace.oid=relation.relnamespace \
                  WHERE namespace.nspname='public' \
                    AND relation.relname='_sqlx_migrations' \
                    AND rewrite.rulename='a0_unapproved_ledger_rule'",
            )
            .fetch_one(connection)
            .await
        }
        PublicLedgerMutationExpectation::AttachedPolicy => {
            sqlx::query_scalar(
                "SELECT count(*)=1 \
                   FROM pg_policy policy \
                   JOIN pg_class relation ON relation.oid=policy.polrelid \
                   JOIN pg_namespace namespace ON namespace.oid=relation.relnamespace \
                  WHERE namespace.nspname='public' \
                    AND relation.relname='_sqlx_migrations' \
                    AND policy.polname='a0_unapproved_ledger_policy'",
            )
            .fetch_one(connection)
            .await
        }
        PublicLedgerMutationExpectation::RowLevelSecurity => {
            sqlx::query_scalar(
                "SELECT relation.relrowsecurity AND NOT relation.relforcerowsecurity \
                   FROM pg_class relation \
                   JOIN pg_namespace namespace ON namespace.oid=relation.relnamespace \
                  WHERE namespace.nspname='public' \
                    AND relation.relname='_sqlx_migrations'",
            )
            .fetch_one(connection)
            .await
        }
    }
}

async fn assert_public_ledger_mutation_rejected(
    connection: &mut PgConnection,
    statements: &[&str],
    label: &str,
    expected: PublicLedgerMutationExpectation,
) {
    let clean_before = a0_assert_post_clean_authority_surfaces(&mut *connection).await;

    sqlx::query("SAVEPOINT unapproved_public_catalog")
        .execute(&mut *connection)
        .await
        .expect("create unapproved-public-catalog savepoint");
    for statement in statements {
        sqlx::query(statement)
            .execute(&mut *connection)
            .await
            .unwrap_or_else(|error| panic!("install {label} mutation: {error}"));
    }
    let exact_mutation_observed = observe_exact_public_ledger_mutation(&mut *connection, expected)
        .await
        .unwrap_or_else(|error| panic!("observe exact {label} mutation: {error}"));
    assert!(
        exact_mutation_observed,
        "the exact attempted public {label} mutation was not installed"
    );
    match a0_classify_public_ledger_closed_catalog(&mut *connection).await {
        Err(PublicLedgerClosedCatalogError::Drift(drift)) => {
            assert_expected_public_ledger_drift(expected, drift);
        }
        Err(PublicLedgerClosedCatalogError::Query { surface, source }) => {
            panic!(
                "query failure cannot satisfy the {label} closed-catalog negative: \
                 surface={surface}, error={source}"
            );
        }
        Ok(_) => panic!("A0 closed-catalog authority accepted unapproved public {label}"),
    }
    sqlx::query("ROLLBACK TO SAVEPOINT unapproved_public_catalog")
        .execute(&mut *connection)
        .await
        .expect("roll back unapproved-public-catalog mutation");
    sqlx::query("RELEASE SAVEPOINT unapproved_public_catalog")
        .execute(&mut *connection)
        .await
        .expect("release unapproved-public-catalog savepoint");
    let clean_after = a0_assert_post_clean_authority_surfaces(&mut *connection).await;
    assert_eq!(
        clean_after, clean_before,
        "public-ledger savepoint rollback did not restore the complete baseline"
    );
}

#[tokio::test]
#[ignore = "compiled-only post-static-approval public attached-object mutation gate"]
async fn post_clean_public_ledger_attached_object_mutations_fail_closed() {
    let pool = fresh_pool().await;
    let mut transaction = pool
        .begin()
        .await
        .expect("begin public mutation probe transaction");
    let durable_authority_before = a0_assert_post_clean_authority_surfaces(&mut transaction).await;
    let durable_ledger_before = a0_assert_exact_ledger(&mut transaction).await;
    let durable_catalog_before = a0_assert_post_clean_catalog(&mut transaction).await;
    assert_public_ledger_mutation_rejected(
        &mut transaction,
        &[
            "CREATE FUNCTION public.a0_unapproved_ledger_trigger() RETURNS trigger \
             LANGUAGE plpgsql AS $$ BEGIN RETURN NEW; END $$",
            "CREATE TRIGGER a0_unapproved_ledger_trigger BEFORE INSERT \
             ON public._sqlx_migrations FOR EACH ROW \
             EXECUTE FUNCTION public.a0_unapproved_ledger_trigger()",
        ],
        "trigger",
        PublicLedgerMutationExpectation::AttachedTrigger,
    )
    .await;
    assert_public_ledger_mutation_rejected(
        &mut transaction,
        &["CREATE RULE a0_unapproved_ledger_rule AS ON UPDATE \
           TO public._sqlx_migrations DO INSTEAD NOTHING"],
        "DML rewrite rule",
        PublicLedgerMutationExpectation::AttachedRewriteRule,
    )
    .await;
    assert_public_ledger_mutation_rejected(
        &mut transaction,
        &["CREATE POLICY a0_unapproved_ledger_policy \
           ON public._sqlx_migrations TO PUBLIC \
           USING (true) WITH CHECK (true)"],
        "policy",
        PublicLedgerMutationExpectation::AttachedPolicy,
    )
    .await;
    assert_public_ledger_mutation_rejected(
        &mut transaction,
        &["ALTER TABLE public._sqlx_migrations ENABLE ROW LEVEL SECURITY"],
        "RLS state",
        PublicLedgerMutationExpectation::RowLevelSecurity,
    )
    .await;
    sqlx::query("SET CONSTRAINTS ALL IMMEDIATE")
        .execute(&mut *transaction)
        .await
        .expect("evaluate public mutation transaction constraints immediately");
    transaction
        .rollback()
        .await
        .expect("roll back public mutation probe transaction");
    let mut observer = pool
        .acquire()
        .await
        .expect("acquire durable public-mutation observer");
    let durable_authority_after = a0_assert_post_clean_authority_surfaces(&mut observer).await;
    let durable_ledger_after = a0_assert_exact_ledger(&mut observer).await;
    let durable_catalog_after = a0_assert_post_clean_catalog(&mut observer).await;
    assert_eq!(
        durable_authority_after, durable_authority_before,
        "public mutation rollback left durable authority residue"
    );
    assert_eq!(
        durable_ledger_after, durable_ledger_before,
        "public mutation rollback changed the durable ledger"
    );
    assert_eq!(
        durable_catalog_after, durable_catalog_before,
        "public mutation rollback changed the durable catalog"
    );
    observer
        .close()
        .await
        .expect("close durable public-mutation observer");
    pool.close().await;
}

mod populated_upgrade_rollback_only {
    use super::{
        a0_assert_exact_ledger, a0_assert_extension_allowlist,
        a0_assert_post_clean_authority_surfaces, a0_assert_post_clean_catalog,
        a0_read_target_identity, compact_sql, OPERATION_CLAIM_00004_REPAIRED_SHA384,
    };
    use sha2::{Digest, Sha384};
    use sqlx::{Connection, PgConnection};
    use uuid::Uuid;

    #[derive(Clone, Copy)]
    struct PopulatedUpgradeMigration {
        filename: &'static str,
        reviewed_sha384: &'static str,
        source: &'static str,
    }

    const POPULATED_UPGRADE_PRE_00004_MANIFEST: [PopulatedUpgradeMigration; 11] = [
        PopulatedUpgradeMigration {
            filename: "20260722000001_chat_protocol_core.sql",
            reviewed_sha384: "dd48feea7beafae59fbc11516e8c1ae91382b356b80366056f71d2493c10923bd39ff0739fe08cb4b0452b0ec82132ff",
            source: include_str!("../migrations/20260722000001_chat_protocol_core.sql"),
        },
        PopulatedUpgradeMigration {
            filename: "20260722000002_chat_protocol_delivery.sql",
            reviewed_sha384: "86952763aaeb8f4cf8a8a18dd5d022a5357d450193e265a18da5a771513b9d4c7c8408bad27c4f4ba3b712b41b80e504",
            source: include_str!("../migrations/20260722000002_chat_protocol_delivery.sql"),
        },
        PopulatedUpgradeMigration {
            filename: "20260722000003_chat_protocol_blobs.sql",
            reviewed_sha384: "310101886f60d3a663ee5df829bbc86a96a45e23adee754220d3b06fd74acfd708d23a138124872a5177244d3e14e8eb",
            source: include_str!("../migrations/20260722000003_chat_protocol_blobs.sql"),
        },
        PopulatedUpgradeMigration {
            filename: "20260725000001_prepare_welcome_provenance_backfill.sql",
            reviewed_sha384: "3f3d1660193bc37aa8c9876e636a4918f59404f0e055f509b9a67158b6028d947adc299c4d776a693bf8b75e647d90a8",
            source: include_str!("../migrations/20260725000001_prepare_welcome_provenance_backfill.sql"),
        },
        PopulatedUpgradeMigration {
            filename: "20260725000002_refine_welcome_provenance_quarantine.sql",
            reviewed_sha384: "8dd0a595288182e2c36aed67d7155138a0817deb5d236dd1eaea50f066a90d7949f60c0de6bff5c9e8bd28e4a1c50de2",
            source: include_str!("../migrations/20260725000002_refine_welcome_provenance_quarantine.sql"),
        },
        PopulatedUpgradeMigration {
            filename: "20260726000001_welcome_supersession_provenance.sql",
            reviewed_sha384: "78c31ff78db5b8889fb00cb7024186a0f048975fc7a059c667e326162e3f338396d9760143367c9206802d21269484f4",
            source: include_str!("../migrations/20260726000001_welcome_supersession_provenance.sql"),
        },
        PopulatedUpgradeMigration {
            filename: "20260726000002_restore_welcome_provenance_deferred_triggers.sql",
            reviewed_sha384: "1b29d045575aea2552ac10bdb61451662d51bca5afa75827e030e5dd859eee0d1664e12a69ecea9692e0fadb2a8df4af",
            source: include_str!("../migrations/20260726000002_restore_welcome_provenance_deferred_triggers.sql"),
        },
        PopulatedUpgradeMigration {
            filename: "20260726000003_finalize_welcome_provenance_triggers.sql",
            reviewed_sha384: "8bd956b8383bea542c6d591ae7721b92b898cb07e49b503131bedfbb511937147766569bcd2b23da11b226decffec495",
            source: include_str!("../migrations/20260726000003_finalize_welcome_provenance_triggers.sql"),
        },
        PopulatedUpgradeMigration {
            filename: "20260728000001_chat_operation_claims.sql",
            reviewed_sha384: "fd71f2eb5235226371f113b5738b752b27e901b72810e9ec1e1f201e979606e0b09a16be087103e4146b4fb9f8bdff8f",
            source: include_str!("../migrations/20260728000001_chat_operation_claims.sql"),
        },
        PopulatedUpgradeMigration {
            filename: "20260728000002_exact_operation_claim_mutation_kind.sql",
            reviewed_sha384: "a5c0225818e350415e0ad3a88c5016d621a75bb64563f97023de9d27498cf113d8ef9d95c98621036c15ac3398dbee17",
            source: include_str!("../migrations/20260728000002_exact_operation_claim_mutation_kind.sql"),
        },
        PopulatedUpgradeMigration {
            filename: "20260728000003_defer_operation_claim_principal_fk.sql",
            reviewed_sha384: "d42c64d98f6af2042ecf5d08b925aaadae01efcd7d1f6d1887c5485e0862d80304bb9ba54506a1876eba54b505d4114a",
            source: include_str!("../migrations/20260728000003_defer_operation_claim_principal_fk.sql"),
        },
    ];
    const POPULATED_UPGRADE_00004_SOURCE: &str =
        include_str!("../migrations/20260728000004_activate_operation_claim_completeness.sql");
    const POPULATED_UPGRADE_00004_MIRROR: &str =
        include_str!("../docs/operation_claim_completeness_activation.sql");

    #[tokio::test]
    #[ignore = "authorized A-final only: populated migration proof is atomic and rollback-only"]
    async fn operation_claim_completeness_populated_upgrade_is_atomic_and_rollback_only() {
        let supplied_url =
            std::env::var("TEST_DATABASE_URL").expect("populated proof requires exact target");
        crate::common::chat_protocol::validate_chat_protocol_database_url(Some(&supplied_url))
            .expect("populated proof refuses a nonliteral target");
        assert_eq!(
            supplied_url,
            "postgresql://127.0.0.1:5432/catbird_chat_protocol_test_20260722"
        );
        let mut connection = PgConnection::connect(
            "postgresql://127.0.0.1:5432/catbird_chat_protocol_test_20260722",
        )
        .await
        .expect("connect dedicated populated-proof target");
        sqlx::query("SELECT pg_advisory_lock(20260729,702)")
            .execute(&mut connection)
            .await
            .expect("acquire populated-proof session lock");
        let own_lock_count: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM pg_locks \
         WHERE locktype='advisory' AND classid=20260729::oid AND objid=702::oid \
           AND granted AND pid=pg_backend_pid()",
        )
        .fetch_one(&mut connection)
        .await
        .expect("inspect populated-proof session lock");
        assert_eq!(own_lock_count, 1, "populated-proof lock ownership drift");
        let initial_peer_count: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM pg_stat_activity \
         WHERE datname='catbird_chat_protocol_test_20260722' \
           AND backend_type='client backend' AND pid<>pg_backend_pid()",
        )
        .fetch_one(&mut connection)
        .await
        .expect("inspect populated-proof peer sessions");
        assert_eq!(
            initial_peer_count, 0,
            "populated proof requires coordinator quiescence and no observed peer"
        );

        let pre_identity = a0_read_target_identity(&mut connection).await;
        let original_backend_pid = pre_identity.pid;
        let pre_ledger_sha256 = a0_assert_exact_ledger(&mut connection).await;
        let pre_catalog_sha256 = a0_assert_post_clean_catalog(&mut connection).await;
        let pre_authority = a0_assert_post_clean_authority_surfaces(&mut connection).await;
        let pre_extension_sha256 = a0_assert_extension_allowlist(&mut connection).await;
        let pre_completeness =
            crate::common::chat_protocol::validate_durable_operation_claim_completeness(
                &mut connection,
            )
            .await
            .expect("read populated-proof durable pre-classification");
        let fixture_principal = "did:web:lane-a-populated.example.com";
        let legacy_operation = Uuid::parse_str("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaa1")
            .expect("valid legacy fixture UUID");
        let rejected_operation = Uuid::parse_str("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaa2")
            .expect("valid rejected fixture UUID");
        let pre_fixture_count: i64 = sqlx::query_scalar(
            "SELECT \
             (SELECT count(*) FROM chat.principals WHERE user_did=$1) + \
             (SELECT count(*) FROM chat.idempotency_records \
               WHERE operation_id IN ($2,$3)) + \
             (SELECT count(*) FROM chat.operation_claims \
               WHERE operation_id IN ($2,$3))",
        )
        .bind(fixture_principal)
        .bind(legacy_operation)
        .bind(rejected_operation)
        .fetch_one(&mut connection)
        .await
        .expect("inspect populated-proof fixture residue");
        assert_eq!(
            pre_fixture_count, 0,
            "populated-proof fixture already exists"
        );

        let mut transaction = connection
            .begin()
            .await
            .expect("begin one outer populated-upgrade transaction");
        let mutation_boundary_peer_count: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM pg_stat_activity \
         WHERE datname='catbird_chat_protocol_test_20260722' \
           AND backend_type='client backend' AND pid<>pg_backend_pid()",
        )
        .fetch_one(&mut *transaction)
        .await
        .expect("repeat populated-proof peer observation at mutation boundary");
        assert_eq!(
            mutation_boundary_peer_count, 0,
            "populated proof observed a peer at the schema-mutation boundary"
        );

        sqlx::query("DROP SCHEMA chat CASCADE")
            .execute(&mut *transaction)
            .await
            .expect("drop only chat inside populated-proof outer transaction");
        for (index, migration) in POPULATED_UPGRADE_PRE_00004_MANIFEST.iter().enumerate() {
            assert_eq!(
                hex::encode(Sha384::digest(migration.source.as_bytes())),
                migration.reviewed_sha384,
                "populated-proof migration hash drift for {}",
                migration.filename
            );
            assert_eq!(
                migration.filename,
                crate::common::chat_protocol::CLEAN_PROTOCOL_13_MANIFEST[index].filename,
                "populated-proof pre-00004 order drift"
            );
            sqlx::raw_sql(migration.source)
                .execute(&mut *transaction)
                .await
                .unwrap_or_else(|error| {
                    panic!(
                        "execute complete populated-proof source {}: {error}",
                        migration.filename
                    )
                });
        }
        let replay_extension_sha256 = a0_assert_extension_allowlist(&mut transaction).await;
        assert_eq!(
            replay_extension_sha256, pre_extension_sha256,
            "idempotent extension statement changed the extension catalog"
        );

        sqlx::query(
            "INSERT INTO chat.principals(user_did,created_at) \
         VALUES($1,clock_timestamp() - interval '2 seconds')",
        )
        .bind(fixture_principal)
        .execute(&mut *transaction)
        .await
        .expect("seed populated-proof principal");
        sqlx::query(
            "INSERT INTO chat.idempotency_records(\
             principal_did,endpoint_nsid,operation_id,request_digest,\
             accepted_request_bytes,signing_transcript_bytes,signature,\
             completed_status,response_bytes,response_sha256,event_position,\
             historical_jkt,current_jkt,completed_at\
         ) VALUES(\
             $1,'blue.catbird.chat.createConversation',$2,\
             digest(decode('01','hex'),'sha256'),\
             decode('02','hex'),decode('01','hex'),decode(repeat('03',64),'hex'),\
             200,decode('04','hex'),digest(decode('04','hex'),'sha256'),\
             NULL,NULL,NULL,clock_timestamp() - interval '1 second'\
         )",
        )
        .bind(fixture_principal)
        .bind(legacy_operation)
        .execute(&mut *transaction)
        .await
        .expect("seed exactly one receipt-only legacy row");
        let seeded_receipt_only_count: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM chat.idempotency_records receipt \
         LEFT JOIN chat.operation_claims claim \
           ON claim.operation_id=receipt.operation_id \
         WHERE receipt.operation_id=$1 AND claim.operation_id IS NULL",
        )
        .bind(legacy_operation)
        .fetch_one(&mut *transaction)
        .await
        .expect("observe exactly one receipt-only fixture");
        assert_eq!(seeded_receipt_only_count, 1);
        // The fixture seed queues an event for every INITIALLY DEFERRED
        // object on chat.idempotency_records: both row-integrity constraint
        // triggers and the idempotency_records_event_fk RI check (a deferred
        // FK INSERT always enqueues, even for the NULL event_position seed;
        // the NULL key no-ops at fire time). The reviewed activation source's
        // first ALTER TABLE refuses to run while any of those events are
        // pending (55006). The real migration is immune because nothing
        // writes the table earlier in its transaction. Drain exactly those
        // three constraints under the staged-tolerant mapping (a receipt-only
        // row passes pre-cutover) and restore their reviewed deferred mode.
        sqlx::query(
            "SET CONSTRAINTS \
         chat.idempotency_records_operation_claim_mapping_deferred, \
         chat.idempotency_records_revocation_mapping_deferred, \
         chat.idempotency_records_event_fk IMMEDIATE",
        )
        .execute(&mut *transaction)
        .await
        .expect("drain exactly the seeded deferred idempotency-record events");
        sqlx::query(
            "SET CONSTRAINTS \
         chat.idempotency_records_operation_claim_mapping_deferred, \
         chat.idempotency_records_revocation_mapping_deferred, \
         chat.idempotency_records_event_fk DEFERRED",
        )
        .execute(&mut *transaction)
        .await
        .expect("restore the reviewed deferred mode before activation replay");

        assert_eq!(
            hex::encode(Sha384::digest(POPULATED_UPGRADE_00004_SOURCE.as_bytes())),
            OPERATION_CLAIM_00004_REPAIRED_SHA384
        );
        assert_eq!(
            POPULATED_UPGRADE_00004_SOURCE.as_bytes(),
            POPULATED_UPGRADE_00004_MIRROR.as_bytes(),
            "activation migration and documentation mirror diverged"
        );
        assert!(compact_sql(POPULATED_UPGRADE_00004_SOURCE).contains(
            "current_setting( 'chat.operation_claim_activation_approved', true ) \
         IS DISTINCT FROM 'handlers-and-legacy-apis-sealed'"
        ));
        sqlx::query(
            "SET LOCAL chat.operation_claim_activation_approved = \
         'handlers-and-legacy-apis-sealed'",
        )
        .execute(&mut *transaction)
        .await
        .expect("set exact local populated-upgrade approval");
        sqlx::raw_sql(POPULATED_UPGRADE_00004_SOURCE)
            .execute(&mut *transaction)
            .await
            .expect("execute complete reviewed operation-claim activation source");

        let classified =
            crate::common::chat_protocol::validate_durable_operation_claim_completeness(
                &mut transaction,
            )
            .await
            .expect("validate populated operation-claim classification");
        assert_eq!(classified.total_receipt_count, 1);
        assert_eq!(classified.legacy_receipt_count, 1);
        assert_eq!(classified.required_receipt_count, 0);
        assert_eq!(
            classified.legacy_receipt_set_sha256,
            crate::common::chat_protocol::canonical_legacy_receipt_set_sha256(&[
                legacy_operation.to_string(),
            ])
        );

        sqlx::query("SAVEPOINT post_cutover_receipt_without_claim")
            .execute(&mut *transaction)
            .await
            .expect("create post-cutover rejection savepoint");
        let rejection = sqlx::query(
            "INSERT INTO chat.idempotency_records(\
             principal_did,endpoint_nsid,operation_id,request_digest,\
             accepted_request_bytes,signing_transcript_bytes,signature,\
             completed_status,response_bytes,response_sha256,event_position,\
             historical_jkt,current_jkt,completed_at\
         ) VALUES(\
             $1,'blue.catbird.chat.createConversation',$2,\
             digest(decode('11','hex'),'sha256'),\
             decode('12','hex'),decode('11','hex'),decode(repeat('13',64),'hex'),\
             200,decode('14','hex'),digest(decode('14','hex'),'sha256'),\
             NULL,NULL,NULL,clock_timestamp()\
         )",
        )
        .bind(fixture_principal)
        .bind(rejected_operation)
        .execute(&mut *transaction)
        .await
        .expect_err("post-cutover receipt without claim must fail its operation-claim fk");
        let database_error = rejection
            .as_database_error()
            .expect("post-cutover rejection must be a PostgreSQL invariant error");
        assert_eq!(database_error.code().as_deref(), Some("23503"));
        assert_eq!(
            database_error.constraint(),
            Some("idempotency_records_operation_claim_fk")
        );
        sqlx::query("ROLLBACK TO SAVEPOINT post_cutover_receipt_without_claim")
            .execute(&mut *transaction)
            .await
            .expect("roll back exact post-cutover rejection");
        sqlx::query("RELEASE SAVEPOINT post_cutover_receipt_without_claim")
            .execute(&mut *transaction)
            .await
            .expect("release exact post-cutover rejection savepoint");
        let outer_usable: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM chat.idempotency_records WHERE operation_id=$1",
        )
        .bind(legacy_operation)
        .fetch_one(&mut *transaction)
        .await
        .expect("prove populated outer transaction remains usable");
        assert_eq!(outer_usable, 1);
        sqlx::query("SET CONSTRAINTS ALL IMMEDIATE")
            .execute(&mut *transaction)
            .await
            .expect("evaluate every populated-upgrade deferred constraint");
        transaction
            .rollback()
            .await
            .expect("roll back the populated-upgrade outer transaction");

        let mut observer = PgConnection::connect(
            "postgresql://127.0.0.1:5432/catbird_chat_protocol_test_20260722",
        )
        .await
        .expect("open fresh populated-proof restoration observer");
        let post_identity = a0_read_target_identity(&mut observer).await;
        assert_ne!(
            post_identity.pid, original_backend_pid,
            "populated restoration proof did not use a fresh observer backend"
        );
        assert_eq!(
            post_identity.database_oid, pre_identity.database_oid,
            "populated proof changed the database OID"
        );
        let post_ledger_sha256 = a0_assert_exact_ledger(&mut observer).await;
        let post_catalog_sha256 = a0_assert_post_clean_catalog(&mut observer).await;
        let post_authority = a0_assert_post_clean_authority_surfaces(&mut observer).await;
        let post_completeness =
            crate::common::chat_protocol::validate_durable_operation_claim_completeness(
                &mut observer,
            )
            .await
            .expect("validate restored durable operation-claim classification");
        assert_eq!(post_ledger_sha256, pre_ledger_sha256);
        assert_eq!(post_catalog_sha256, pre_catalog_sha256);
        assert_eq!(post_authority, pre_authority);
        assert_eq!(post_completeness, pre_completeness);
        let post_fixture_count: i64 = sqlx::query_scalar(
            "SELECT \
             (SELECT count(*) FROM chat.principals WHERE user_did=$1) + \
             (SELECT count(*) FROM chat.idempotency_records \
               WHERE operation_id IN ($2,$3)) + \
             (SELECT count(*) FROM chat.operation_claims \
               WHERE operation_id IN ($2,$3))",
        )
        .bind(fixture_principal)
        .bind(legacy_operation)
        .bind(rejected_operation)
        .fetch_one(&mut observer)
        .await
        .expect("inspect restored populated-proof fixture residue");
        assert_eq!(
            post_fixture_count, 0,
            "populated-upgrade rollback left durable fixture residue"
        );
        observer
            .close()
            .await
            .expect("close populated-proof restoration observer");

        let unlocked: bool = sqlx::query_scalar("SELECT pg_advisory_unlock(20260729,702)")
            .fetch_one(&mut connection)
            .await
            .expect("release populated-proof session lock");
        assert!(unlocked, "populated-proof session lock was not retained");
        connection
            .close()
            .await
            .expect("close original populated-proof connection");
    }
}

#[test]
fn canonical_legacy_receipt_set_digest_is_domain_separated_and_ordered() {
    assert_eq!(
        hex::encode(crate::common::chat_protocol::canonical_legacy_receipt_set_sha256(&[])),
        "9261399e4289a8083ac006b4abb0191d2e2b13e7b8213b7292481f6559157530"
    );
    assert_eq!(
        hex::encode(
            crate::common::chat_protocol::canonical_legacy_receipt_set_sha256(&[
                "550e8400-e29b-41d4-a716-446655440000".to_owned(),
            ])
        ),
        "c62dbbaf1a82dcc2b1e221f06bf01774af27e9fc8131172131465353a2eac2ce"
    );
}

#[tokio::test]
async fn operation_claim_completeness_cutover_matches_durable_classification() {
    let database_url =
        std::env::var("TEST_DATABASE_URL").expect("live completeness proof requires exact target");
    crate::common::chat_protocol::validate_chat_protocol_database_url(Some(&database_url))
        .expect("live completeness proof refuses a nonliteral target");
    let mut connection = PgConnection::connect(&database_url)
        .await
        .expect("connect exact live completeness target");
    let (database_name, server_address, server_port): (String, Option<String>, Option<i32>) =
        sqlx::query_as("SELECT current_database(),host(inet_server_addr()),inet_server_port()")
            .fetch_one(&mut connection)
            .await
            .expect("read live completeness target identity");
    assert_eq!(database_name, TEST_DATABASE_NAME);
    assert_eq!(server_address.as_deref(), Some("127.0.0.1"));
    assert_eq!(server_port, Some(5432));
    a0_assert_exact_ledger(&mut connection).await;
    a0_assert_post_clean_catalog(&mut connection).await;
    let evidence = crate::common::chat_protocol::validate_durable_operation_claim_completeness(
        &mut connection,
    )
    .await
    .expect("live durable operation-claim classification");
    eprintln!(
        "CATBIRD_OPERATION_CLAIM_COMPLETENESS_V1 \
         legacy_receipt_count={} legacy_receipt_set_sha256={}",
        evidence.legacy_receipt_count,
        hex::encode(evidence.legacy_receipt_set_sha256),
    );
    connection
        .close()
        .await
        .expect("close live completeness connection");
}

#[tokio::test]
async fn clean_chat_schema_preserves_all_core_invariants_and_receipt_table() {
    let pool = fresh_pool().await;
    let mut connection = pool
        .acquire()
        .await
        .expect("acquire schema non-regression connection");

    let nullable_welcome_cols: Vec<String> = sqlx::query_scalar(
        r#"
        SELECT column_name
          FROM information_schema.columns
         WHERE table_schema = 'chat' AND table_name = 'welcome_bundles'
           AND column_name IN ('transition_id', 'entry_seq', 'generation', 'state_version', 'group_id', 'epoch', 'group_context_hash', 'confirmation_tag')
           AND is_nullable = 'YES'
        "#,
    )
    .fetch_all(&mut *connection)
    .await
    .expect("check welcome_bundles nullability");
    assert!(
        nullable_welcome_cols.is_empty(),
        "welcome_bundles columns must not be nullable: {:?}",
        nullable_welcome_cols
    );

    let recovery_id_nullable: String = sqlx::query_scalar(
        r#"
        SELECT is_nullable
          FROM information_schema.columns
         WHERE table_schema = 'chat' AND table_name = 'welcome_deliveries'
           AND column_name = 'recovery_request_id'
        "#,
    )
    .fetch_one(&mut *connection)
    .await
    .expect("check recovery_request_id nullability");
    assert_eq!(
        recovery_id_nullable, "NO",
        "recovery_request_id must remain NOT NULL"
    );

    let fk_names: Vec<String> = sqlx::query_scalar(
        r#"
        SELECT conname
          FROM pg_constraint c
          JOIN pg_namespace n ON n.oid = c.connamespace
         WHERE n.nspname = 'chat' AND c.contype = 'f'
        "#,
    )
    .fetch_all(&mut *connection)
    .await
    .expect("check FK constraints");

    for required_fk in [
        "generation_states_generation_fk",
        "entries_actor_key_fk",
        "entries_transition_fk",
        "participants_invitation_provenance_fk",
        "participants_acceptance_transition_fk",
        "federation_delivery_receipts_conversation_fk",
        "federation_delivery_receipts_source_entry_fk",
    ] {
        assert!(
            fk_names.iter().any(|k| k == required_fk),
            "missing required FK: {required_fk}"
        );
    }

    let uq_names: Vec<String> = sqlx::query_scalar(
        r#"
        SELECT conname
          FROM pg_constraint c
          JOIN pg_namespace n ON n.oid = c.connamespace
         WHERE n.nspname = 'chat' AND c.contype = 'u'
        "#,
    )
    .fetch_all(&mut *connection)
    .await
    .expect("check UQ constraints");

    assert!(
        uq_names
            .iter()
            .any(|k| k == "entries_delivery_receipt_source_uq"),
        "missing entries_delivery_receipt_source_uq"
    );

    let triggers: Vec<String> = sqlx::query_scalar(
        r#"
        SELECT tgname
          FROM pg_trigger tg
          JOIN pg_class c ON c.oid = tg.tgrelid
          JOIN pg_namespace n ON n.oid = c.relnamespace
         WHERE n.nspname = 'chat' AND NOT tg.tgisinternal
        "#,
    )
    .fetch_all(&mut *connection)
    .await
    .expect("check triggers");

    for required_tg in [
        "entries_immutable",
        "welcome_bundles_immutable",
        "welcome_deliveries_identity_immutable",
        "conversations_identity_immutable",
        "federation_delivery_receipts_immutable",
    ] {
        assert!(
            triggers.iter().any(|t| t == required_tg),
            "missing required trigger: {required_tg}"
        );
    }

    // Federation transport public catalog validation and rejection tests
    #[derive(Debug, PartialEq, Eq)]
    enum FederationTransportCatalogDrift {
        MissingRelation(String),
        UnexpectedRelation(String),
        WrongIndexPredicate {
            index: String,
            expected: String,
            actual: String,
        },
    }

    fn validate_federation_transport_catalog(
        actual_relations: &[&str],
        actual_predicates: &[(&str, &str)],
    ) -> Result<(), FederationTransportCatalogDrift> {
        let expected_relations: BTreeSet<&str> = PUBLIC_FEDERATION_TRANSPORT_RELATIONS
            .iter()
            .copied()
            .collect();
        let actual_set: BTreeSet<&str> = actual_relations.iter().copied().collect();

        for expected in &expected_relations {
            if !actual_set.contains(expected) {
                return Err(FederationTransportCatalogDrift::MissingRelation(
                    (*expected).to_owned(),
                ));
            }
        }
        for actual in &actual_set {
            if !expected_relations.contains(actual) {
                return Err(FederationTransportCatalogDrift::UnexpectedRelation(
                    (*actual).to_owned(),
                ));
            }
        }

        const EXPECTED_INDEX_PREDICATES: &[(&str, &str)] = &[
            ("idx_federation_outbox_due_v2", "(status = 'pending'::text)"),
            (
                "idx_federation_outbox_lease",
                "(status = 'in_flight'::text)",
            ),
            ("idx_outbound_queue_due_v2", "(status = 'pending'::text)"),
            ("idx_outbound_queue_lease", "(status = 'in_flight'::text)"),
        ];
        let actual_pred_map: BTreeMap<&str, &str> = actual_predicates.iter().copied().collect();
        for (index, expected_pred) in EXPECTED_INDEX_PREDICATES {
            if let Some(actual_pred) = actual_pred_map.get(index) {
                if actual_pred != expected_pred {
                    return Err(FederationTransportCatalogDrift::WrongIndexPredicate {
                        index: (*index).to_owned(),
                        expected: (*expected_pred).to_owned(),
                        actual: (*actual_pred).to_owned(),
                    });
                }
            }
        }

        Ok(())
    }

    let baseline_relations = PUBLIC_FEDERATION_TRANSPORT_RELATIONS;
    let baseline_predicates = [
        ("idx_federation_outbox_due_v2", "(status = 'pending'::text)"),
        (
            "idx_federation_outbox_lease",
            "(status = 'in_flight'::text)",
        ),
        ("idx_outbound_queue_due_v2", "(status = 'pending'::text)"),
        ("idx_outbound_queue_lease", "(status = 'in_flight'::text)"),
    ];

    // Positive control: exact catalog passes
    assert!(
        validate_federation_transport_catalog(baseline_relations, &baseline_predicates).is_ok()
    );

    // Negative 1: Missing relation
    let mut missing_relations = baseline_relations.to_vec();
    missing_relations.retain(|&r| r != "idx_federation_outbox_due_v2");
    assert_eq!(
        validate_federation_transport_catalog(&missing_relations, &baseline_predicates),
        Err(FederationTransportCatalogDrift::MissingRelation(
            "idx_federation_outbox_due_v2".to_owned()
        ))
    );

    // Negative 2: Unexpected relation
    let mut unexpected_relations = baseline_relations.to_vec();
    unexpected_relations.push("unapproved_federation_table");
    assert_eq!(
        validate_federation_transport_catalog(&unexpected_relations, &baseline_predicates),
        Err(FederationTransportCatalogDrift::UnexpectedRelation(
            "unapproved_federation_table".to_owned()
        ))
    );

    // Negative 3: Index with wrong predicate
    let wrong_predicates = [
        ("idx_federation_outbox_due_v2", "(status = 'done'::text)"),
        (
            "idx_federation_outbox_lease",
            "(status = 'in_flight'::text)",
        ),
        ("idx_outbound_queue_due_v2", "(status = 'pending'::text)"),
        ("idx_outbound_queue_lease", "(status = 'in_flight'::text)"),
    ];
    assert_eq!(
        validate_federation_transport_catalog(baseline_relations, &wrong_predicates),
        Err(FederationTransportCatalogDrift::WrongIndexPredicate {
            index: "idx_federation_outbox_due_v2".to_owned(),
            expected: "(status = 'pending'::text)".to_owned(),
            actual: "(status = 'done'::text)".to_owned(),
        })
    );

    // Live DB verification of actual federation transport index predicates
    let db_predicates: Vec<(String, Option<String>)> = sqlx::query_as(
        r#"
        SELECT i.relname, pg_get_expr(x.indpred, x.indrelid, false)
          FROM pg_index x
          JOIN pg_class i ON i.oid = x.indexrelid
          JOIN pg_class t ON t.oid = x.indrelid
          JOIN pg_namespace n ON n.oid = t.relnamespace
         WHERE n.nspname = 'public'
           AND i.relname IN (
               'idx_federation_outbox_due_v2',
               'idx_federation_outbox_lease',
               'idx_outbound_queue_due_v2',
               'idx_outbound_queue_lease'
           )
         ORDER BY i.relname
        "#,
    )
    .fetch_all(&mut *connection)
    .await
    .expect("fetch public federation transport index predicates");

    let live_predicates: Vec<(&str, &str)> = db_predicates
        .iter()
        .map(|(name, pred)| (name.as_str(), pred.as_deref().unwrap_or("")))
        .collect();
    assert!(
        validate_federation_transport_catalog(baseline_relations, &live_predicates).is_ok(),
        "live database federation transport index predicates drifted: {live_predicates:?}"
    );

    // Migration source audit
    let migration_sql = std::fs::read_to_string(
        migration_dir().join("20260824000005_chat_federation_outbox_retry.sql"),
    )
    .expect("read federation outbox retry migration");
    let compact_sql = compact_sql(&migration_sql);

    assert_source_contract(
        "federation transport index predicates",
        &[
            (
                "idx_federation_outbox_due_v2 is partial on status = 'pending'",
                compact_sql.contains("CREATE INDEX IF NOT EXISTS idx_federation_outbox_due_v2 ON federation_outbox(next_attempt_at) WHERE status = 'pending'"),
            ),
            (
                "idx_federation_outbox_lease is partial on status = 'in_flight'",
                compact_sql.contains("CREATE INDEX IF NOT EXISTS idx_federation_outbox_lease ON federation_outbox(claim_expires_at) WHERE status = 'in_flight'"),
            ),
            (
                "idx_outbound_queue_due_v2 is partial on status = 'pending'",
                compact_sql.contains("CREATE INDEX IF NOT EXISTS idx_outbound_queue_due_v2 ON outbound_queue(next_retry_at) WHERE status = 'pending'"),
            ),
            (
                "idx_outbound_queue_lease is partial on status = 'in_flight'",
                compact_sql.contains("CREATE INDEX IF NOT EXISTS idx_outbound_queue_lease ON outbound_queue(claim_expires_at) WHERE status = 'in_flight'"),
            ),
        ],
    );

    assert_source_contract(
        "federation sync state quarantine constraints",
        &[
            (
                "quarantine status check",
                compact_sql.contains("CHECK (status IN ('healthy', 'quarantined'))"),
            ),
            (
                "quarantine shape check",
                compact_sql.contains("CONSTRAINT federation_sync_state_quarantine_shape_check"),
            ),
        ],
    );

    connection.close().await.expect("close connection");
    pool.close().await;
}

#[tokio::test]
async fn clean_chat_schema_is_exact_and_validation_only() {
    let pool = fresh_pool().await;
    let mut connection = pool
        .acquire()
        .await
        .expect("acquire validation-only schema connection");
    assert_eq!(
        chat_tables(&mut *connection).await,
        expected_tables(),
        "unexpected exact-13 chat table set"
    );
    let ledger_hash = a0_assert_exact_ledger(&mut *connection).await;
    let catalog_hash = a0_assert_post_clean_catalog(&mut *connection).await;
    eprintln!(
        "A-final validation_only=true ledger_sha256={ledger_hash} \
         catalog_allowlist_sha256={catalog_hash}"
    );
    connection
        .close()
        .await
        .expect("close validation-only schema connection");
    pool.close().await;
}
