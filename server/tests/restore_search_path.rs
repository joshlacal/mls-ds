//! pg_dump/pg_restore and the nightly backup verification run with an empty
//! search_path. Any function that calls a pgcrypto or uuid-ossp helper by its
//! bare name must pin its own search_path, or a restore fails wherever that
//! function backs a CHECK constraint, default or index (it did for
//! chat.device_keys: migration 20261124000001).

mod common;

const UNPINNED_EXTENSION_CALLERS: &str = r#"
SELECT DISTINCT p.oid::regprocedure::text
  FROM pg_proc p
  JOIN pg_namespace n ON n.oid = p.pronamespace
  JOIN pg_language l ON l.oid = p.prolang
 WHERE n.nspname NOT IN ('pg_catalog', 'information_schema')
   AND n.nspname NOT LIKE 'pg\_%'
   AND l.lanname IN ('sql', 'plpgsql')
   AND p.proconfig IS NULL
   AND NOT EXISTS (
       SELECT 1 FROM pg_depend d
        WHERE d.classid = 'pg_proc'::regclass AND d.objid = p.oid AND d.deptype = 'e'
   )
   AND EXISTS (
       SELECT 1
         FROM pg_proc ext
         JOIN pg_depend d
           ON d.classid = 'pg_proc'::regclass AND d.objid = ext.oid AND d.deptype = 'e'
         JOIN pg_extension e ON e.oid = d.refobjid
        WHERE e.extname IN ('pgcrypto', 'uuid-ossp')
          AND p.prosrc ~ ('(^|[^.A-Za-z0-9_"])' || ext.proname || '\s*\(')
   )
 ORDER BY 1
"#;

#[tokio::test]
async fn extension_callers_survive_an_empty_search_path() {
    let database = common::fresh_db::fresh_fully_migrated_db("chat_restore_path_").await;
    let pool = database.connect(1).await;

    let unpinned: Vec<String> = sqlx::query_scalar(UNPINNED_EXTENSION_CALLERS)
        .fetch_all(&pool)
        .await
        .expect("scan functions for unqualified extension calls");
    assert!(
        unpinned.is_empty(),
        "these functions call pgcrypto/uuid-ossp unqualified without a pinned \
         search_path, so pg_restore cannot evaluate them: {unpinned:?}"
    );

    // The exact path pg_restore takes for the device_keys CHECK constraint.
    let mut tx = pool.begin().await.unwrap();
    sqlx::query("SET LOCAL search_path = ''")
        .execute(&mut *tx)
        .await
        .unwrap();
    let key_id: String =
        sqlx::query_scalar("SELECT chat.ed25519_key_id(decode(repeat('ab', 32), 'hex'))")
            .fetch_one(&mut *tx)
            .await
            .expect("chat.ed25519_key_id resolves digest() with an empty search_path");
    assert_eq!(key_id.len(), 43);
    tx.rollback().await.unwrap();
}
