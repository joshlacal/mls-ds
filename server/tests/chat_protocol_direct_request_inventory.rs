//! Transport regressions: unknown request unions fail closed and legacy optional
//! scope omission stays omission. SQL audience/cursor tests run separately.
use catbird_atproto::generated::blue_catbird::chat::{
    get_conversations::GetConversationsOutput, get_pending_welcomes::GetPendingWelcomesOutput,
};
use serde_json::json;
#[test]
fn unknown_welcome_union_cannot_be_silently_dropped() {
    let value = json!({"hasMore":false,"inventorySessionId":"session","snapshotEventCursor":"cursor","snapshotExpiresAt":"2026-09-19T12:00:00.000Z","items":[{"$type":"blue.catbird.chat.defs#futureWelcome"}]});
    assert!(serde_json::from_value::<GetPendingWelcomesOutput>(value).is_err());
}
#[test]
fn legacy_empty_snapshot_does_not_acquire_fake_scope() {
    let value = json!({"hasMore":false,"inventorySessionId":"session","snapshotEventCursor":"cursor","snapshotExpiresAt":"2026-09-19T12:00:00.000Z","items":[]});
    let decoded: GetConversationsOutput = serde_json::from_value(value).unwrap();
    assert!(decoded.inventory_scope.is_none());
    assert!(serde_json::to_value(decoded)
        .unwrap()
        .get("inventoryScope")
        .is_none());
}

#[path = "common/chat_protocol.rs"]
pub mod chat_protocol_baseline;
mod common {
    pub use super::chat_protocol_baseline as chat_protocol;
    pub mod direct_request_database;
}

/// Uses the production UPDATE shape with all database triggers enabled. This
/// proves initialization and immutability, not populated mixed-version paging.
#[tokio::test]
async fn scoped_session_initializes_once_before_materialization() {
    use uuid::Uuid;
    let pool = common::direct_request_database::setup().await;
    let mut tx = pool.begin().await.unwrap();
    let did = format!(
        "did:plc:{}",
        Uuid::new_v4()
            .simple()
            .to_string()
            .chars()
            .take(24)
            .map(|c| char::from(b'a' + c.to_digit(16).unwrap() as u8))
            .collect::<String>()
    );
    let device = Uuid::new_v4();
    let session = Uuid::new_v4();
    let key = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
    sqlx::query(
        "INSERT INTO chat.principals(user_did,created_at) VALUES($1,transaction_timestamp())",
    )
    .bind(&did)
    .execute(&mut *tx)
    .await
    .unwrap();
    sqlx::query("INSERT INTO chat.devices(user_did,device_id,device_name,status,dpop_jkt,auth_generation,capabilities,created_at,updated_at) VALUES($1,$2,'scope-test','active',$3,1,chat.protocol_capabilities(),transaction_timestamp(),transaction_timestamp())")
        .bind(&did).bind(device).bind(key).execute(&mut *tx).await.unwrap();
    sqlx::query("INSERT INTO chat.protocol_instances(singleton,protocol_version,protocol_instance_id,cursor_key_id) VALUES(TRUE,'1',$1,$2) ON CONFLICT DO NOTHING").bind(Uuid::new_v4()).bind(key).execute(&mut *tx).await.unwrap();
    sqlx::query("INSERT INTO chat.event_retention(protocol_instance_id,retained_floor,updated_at) SELECT protocol_instance_id,0,transaction_timestamp() FROM chat.protocol_instances ON CONFLICT DO NOTHING").execute(&mut *tx).await.unwrap();
    sqlx::query("INSERT INTO chat.inventory_sessions(inventory_session_id,token_hash,user_did,device_id,jkt,auth_generation,snapshot_event_position,snapshot_event_cursor_sha256,created_at,expires_at,protocol_instance_id,cursor_key_id,cursor_format_version,snapshot_retained_floor,snapshot_event_cursor_nonce,snapshot_event_cursor_ciphertext) SELECT $1,$2,$3,$4,$5,1,r.retained_floor,$2,transaction_timestamp(),transaction_timestamp()+interval '10 minutes',p.protocol_instance_id,p.cursor_key_id,1,r.retained_floor,$6,$7 FROM chat.protocol_instances p JOIN chat.event_retention r USING(protocol_instance_id)")
        .bind(session).bind(vec![7u8;32]).bind(&did).bind(device).bind(key).bind(vec![1u8;12]).bind(vec![2u8;32]).execute(&mut *tx).await.unwrap();
    let scope = json!({"supportedProtocolVersions":["1"],"scopeDigest":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="});
    sqlx::query("UPDATE chat.inventory_sessions SET inventory_scope=$2,supported_protocol_versions=ARRAY['1'],scoped_conversation_ids=ARRAY[]::uuid[] WHERE inventory_session_id=$1")
        .bind(session).bind(&scope).execute(&mut *tx).await.expect("one scope initialization must remain allowed");
    sqlx::query("SET CONSTRAINTS ALL IMMEDIATE")
        .execute(&mut *tx)
        .await
        .unwrap();
    sqlx::query("SAVEPOINT scope_mutation")
        .execute(&mut *tx)
        .await
        .unwrap();
    let error=sqlx::query("UPDATE chat.inventory_sessions SET inventory_scope=jsonb_set(inventory_scope,'{scopeDigest}','\"other\"') WHERE inventory_session_id=$1").bind(session).execute(&mut *tx).await.expect_err("scope cannot be substituted");
    assert_eq!(
        error.as_database_error().unwrap().code().as_deref(),
        Some("23514")
    );
    sqlx::query("ROLLBACK TO SAVEPOINT scope_mutation")
        .execute(&mut *tx)
        .await
        .unwrap();
    tx.rollback().await.unwrap();
}
