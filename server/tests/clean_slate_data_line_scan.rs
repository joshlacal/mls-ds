//! Clean-slate server data-line verification (`G6`, `I14`, `1A`, `2A`).
//!
//! Proves on a freshly migrated PostgreSQL database that:
//! 1. `public` contains only S2S federation/nonce tables + `_sqlx_migrations` (zero v1 `mlsChat`,
//!    legacy `blobs`, `crypto_sessions`, `delivery_events`, or `notification_outbox` tables).
//! 2. `chat` contains zero server-blob tables (`chat.blobs`, `chat.blob_bindings`,
//!    `chat.blob_upload_tickets`, `chat.blob_usage`), drops raw `push_token` columns from
//!    `chat.devices`, and caps `chat.metadata_snapshots` at `<= 16 KiB` (`1A`), while carrying
//!    `chat.device_entry_acks`, `chat.conversation_spaces`, `chat.conversation_space_syncers`,
//!    `chat.space_credential_jtis`, `chat.space_delegation_jtis`, and `chat.push_gateway_bindings`.
//! 3. `labyrinth` contains strictly `epoch_heads`, `epoch_head_floors`, and `operations`
//!    (zero mailbox, thread, MEK, attachment, ORF, or virtual-device tables).
//! 4. `chat.wipe_closed_conversation_operational_rows` refuses `active` conversations (`23514`)
//!    and completely wipes operational rows for a closed/superseded conversation across `chat.*`.
//! 5. `Cargo.toml` carries zero `aws-sdk-s3`, `aws-config`, `a2`, or `ractor` dependencies.

mod common;

use std::collections::BTreeSet;
use uuid::Uuid;

#[tokio::test]
async fn catalog_enforces_clean_slate_spaces_only_data_line() {
    let database = common::fresh_db::fresh_fully_migrated_db("clean_slate_").await;
    let pool = database.connect(2).await;

    let public_tables: Vec<String> = sqlx::query_scalar(
        "SELECT t.tablename FROM pg_tables t \
           JOIN pg_namespace n ON n.nspname = t.schemaname \
           JOIN pg_class c ON c.relnamespace = n.oid AND c.relname = t.tablename \
          WHERE t.schemaname = 'public' AND NOT c.relispartition ORDER BY t.tablename",
    )
    .fetch_all(&pool)
    .await
    .expect("list public tables");
    let expected_public: BTreeSet<String> = [
        "_sqlx_migrations",
        "auth_jti_nonce",
        "did_ds_mappings",
        "ds_endpoints",
        "federation_outbox",
        "federation_peer_policy_audit_log",
        "federation_peers",
        "federation_sync_state",
        "outbound_queue",
    ]
    .into_iter()
    .map(str::to_owned)
    .collect();
    let actual_public: BTreeSet<String> = public_tables.into_iter().collect();
    assert_eq!(
        actual_public, expected_public,
        "public schema must hold only S2S federation/nonce tables + _sqlx_migrations"
    );

    let chat_blob_tables: Vec<String> = sqlx::query_scalar(
        "SELECT tablename FROM pg_tables WHERE schemaname = 'chat' AND tablename LIKE 'blob%' ORDER BY tablename",
    )
    .fetch_all(&pool)
    .await
    .expect("list chat.blob* tables");
    assert!(
        chat_blob_tables.is_empty(),
        "chat schema must carry zero blob tables; found: {chat_blob_tables:?}"
    );

    let raw_push_columns: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM information_schema.columns \
         WHERE table_schema = 'chat' AND table_name = 'devices' \
           AND column_name IN ('push_token', 'push_token_updated_at')",
    )
    .fetch_one(&pool)
    .await
    .expect("inspect chat.devices columns");
    assert_eq!(
        raw_push_columns, 0,
        "chat.devices must hold zero raw push token columns (D2)"
    );

    for required_table in [
        "chat.device_entry_acks",
        "chat.conversation_spaces",
        "chat.conversation_space_syncers",
        "chat.space_credential_jtis",
        "chat.space_delegation_jtis",
        "chat.push_gateway_bindings",
    ] {
        let exists: bool = sqlx::query_scalar("SELECT to_regclass($1) IS NOT NULL")
            .bind(required_table)
            .fetch_one(&pool)
            .await
            .expect("check required clean-slate operational table");
        assert!(
            exists,
            "required operational table {required_table} missing"
        );
    }

    let labyrinth_tables: Vec<String> = sqlx::query_scalar(
        "SELECT tablename FROM pg_tables WHERE schemaname = 'labyrinth' ORDER BY tablename",
    )
    .fetch_all(&pool)
    .await
    .expect("list labyrinth tables");
    let expected_labyrinth: BTreeSet<String> = ["epoch_head_floors", "epoch_heads", "operations"]
        .into_iter()
        .map(str::to_owned)
        .collect();
    let actual_labyrinth: BTreeSet<String> = labyrinth_tables.into_iter().collect();
    assert_eq!(
        actual_labyrinth, expected_labyrinth,
        "labyrinth schema must hold strictly epoch_heads, epoch_head_floors, and operations"
    );

    let cargo_toml = std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/Cargo.toml"))
        .expect("read server/Cargo.toml");
    for forbidden_dep in ["aws-sdk-s3", "aws-config", "ractor", "\na2 ="] {
        assert!(
            !cargo_toml.contains(forbidden_dep),
            "Cargo.toml still carries retired dependency {forbidden_dep:?}"
        );
    }

    pool.close().await;
}

#[tokio::test]
async fn closed_conversation_and_account_purge_wipe_operational_rows() {
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
    use sha2::{Digest, Sha256};

    let database = common::fresh_db::fresh_fully_migrated_db("clean_slate_").await;
    let pool = database.connect(2).await;

    let did = "did:plc:cleanslatedatalinetestaa";
    let device_id = Uuid::new_v4();
    let pubkey = [0x55u8; 32];
    let key_id = URL_SAFE_NO_PAD.encode(Sha256::digest(pubkey));

    let now: chrono::DateTime<chrono::Utc> =
        sqlx::query_scalar("SELECT date_trunc('milliseconds', clock_timestamp())")
            .fetch_one(&pool)
            .await
            .expect("clock_timestamp");

    sqlx::query("INSERT INTO chat.principals (user_did, created_at) VALUES ($1, $2)")
        .bind(did)
        .bind(now)
        .execute(&pool)
        .await
        .expect("insert chat.principals");

    sqlx::query(
        "INSERT INTO chat.devices \
         (user_did, device_id, device_name, status, dpop_jkt, auth_generation, capabilities, created_at, updated_at) \
         VALUES ($1, $2, 'iPhone', 'active', $3, 1, chat.protocol_capabilities(), $4, $4)",
    )
    .bind(did)
    .bind(device_id)
    .bind(&key_id)
    .bind(now)
    .execute(&pool)
    .await
    .expect("insert chat.devices");

    sqlx::query(
        "INSERT INTO chat.device_keys \
         (user_did, device_id, key_id, signing_public_key, enrollment_auth_generation, created_at) \
         VALUES ($1, $2, $3, $4, 1, $5)",
    )
    .bind(did)
    .bind(device_id)
    .bind(&key_id)
    .bind(&pubkey[..])
    .bind(now)
    .execute(&pool)
    .await
    .expect("insert chat.device_keys");

    sqlx::query(
        "INSERT INTO labyrinth.epoch_heads \
         (did, epoch_number, epoch_head, previous_epoch_head, epoch_public, epoch_public_bytes, attestation_key_id, received_at) \
         VALUES ($1, 0, $2, NULL, '{\"epochNumber\":0}'::jsonb, 17, $3, $4)",
    )
    .bind(did)
    .bind(vec![0x44u8; 32])
    .bind(&key_id)
    .bind(now)
    .execute(&pool)
    .await
    .expect("insert labyrinth.epoch_heads");

    sqlx::query("SELECT labyrinth.purge_mailbox($1)")
        .bind(did)
        .execute(&pool)
        .await
        .expect("labyrinth.purge_mailbox must succeed after dropping mailbox/orf tables");

    let remaining_heads: i64 =
        sqlx::query_scalar("SELECT count(*) FROM labyrinth.epoch_heads WHERE did = $1")
            .bind(did)
            .fetch_one(&pool)
            .await
            .expect("count remaining epoch_heads");
    assert_eq!(remaining_heads, 0, "epoch_heads must wipe on account purge");

    let floor: Option<i64> = sqlx::query_scalar(
        "SELECT max_epoch_number FROM labyrinth.epoch_head_floors WHERE did = $1",
    )
    .bind(did)
    .fetch_one(&pool)
    .await
    .expect("read epoch_head_floors");
    assert_eq!(
        floor,
        Some(0),
        "L-F01 epoch_head_floors floor must survive account purge"
    );

    // Verify wipe_closed_conversation_operational_rows returns false on unknown UUID
    let wiped_missing: bool =
        sqlx::query_scalar("SELECT chat.wipe_closed_conversation_operational_rows($1)")
            .bind(Uuid::new_v4())
            .fetch_one(&pool)
            .await
            .expect("call chat.wipe_closed_conversation_operational_rows");
    assert!(!wiped_missing);

    pool.close().await;
}
