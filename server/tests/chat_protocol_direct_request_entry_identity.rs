//! Regression for keeping direct-request message identity in the signed request
//! graph rather than the ordinary application-send idempotency column.

#![allow(dead_code)]
#[path = "common/chat_protocol.rs"]
pub mod chat_protocol_baseline;
mod common {
    pub use super::chat_protocol_baseline as chat_protocol;
    pub mod direct_request_database;
}

use sqlx::Acquire;

#[test]
fn publication_insert_does_not_claim_an_application_message_send() {
    let source = include_str!("../src/chat_protocol/repository/direct_request_publication.rs");
    let insert = source
        .split("INSERT INTO chat.entries(")
        .nth(1)
        .expect("direct-request entry insert")
        .split("execute(&mut **tx)")
        .next()
        .expect("bounded direct-request entry insert");

    assert!(
        insert.contains("'blue.catbird.chat.defs#directRequestEntry'"),
        "test must inspect the direct-request entry insert"
    );
    assert!(
        !insert.contains("message_id"),
        "a direct-request entry must not claim an ordinary message_sends identity"
    );
    assert!(
        source.contains("first_message_id,actor_did"),
        "canonical firstMessageId must remain persisted on the typed publication"
    );
}

#[tokio::test]
async fn request_entry_identity_is_bound_without_application_message_send() {
    let pool = common::direct_request_database::setup().await;
    let mut tx = pool.begin().await.expect("begin identity regression");

    sqlx::raw_sql(include_str!(
        "../migrations/20260919000015_direct_request_entry_identity.sql"
    ))
    .execute(&mut *tx)
    .await
    .expect("apply reviewed identity migration in rollback probe");

    let unique_first_message_id: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM pg_constraint c \
         WHERE c.conrelid='chat.direct_request_publications'::regclass \
           AND c.contype='u' \
           AND c.conkey=ARRAY[(SELECT attnum FROM pg_attribute \
             WHERE attrelid=c.conrelid AND attname='first_message_id')]::smallint[])",
    )
    .fetch_one(&mut *tx)
    .await
    .expect("inspect canonical first-message uniqueness");
    assert!(
        unique_first_message_id,
        "typed publication firstMessageId remains globally unique"
    );

    let assertion: String = sqlx::query_scalar(
        "SELECT pg_get_functiondef('chat.assert_direct_request_publication(uuid)'::regprocedure)",
    )
    .fetch_one(&mut *tx)
    .await
    .expect("inspect deferred publication assertion");
    assert!(assertion.contains("e.message_id IS NULL"));
    assert!(assertion.contains("body.b->>'firstMessageId'=p.first_message_id::text"));
    assert!(assertion.contains("#>>'{signedRequest,body,firstMessageId}'=p.first_message_id::text"));

    sqlx::raw_sql(
        "CREATE TEMP TABLE direct_request_entry_shape_probe \
         (LIKE chat.entries INCLUDING DEFAULTS INCLUDING CONSTRAINTS) ON COMMIT DROP",
    )
    .execute(&mut *tx)
    .await
    .expect("create isolated entry-shape probe");

    let insert = "INSERT INTO direct_request_entry_shape_probe(\
        conversation_id,seq,entry_id,entry_kind,accepted_payload_bytes,\
        accepted_payload_sha256,signed_request_bytes,request_digest,signature,\
        server_fields_bytes,outer_entry_fingerprint,actor_did,actor_device_id,\
        actor_key_id,actor_auth_generation,generation,state_version,transition_id,\
        message_id,received_at) VALUES(\
        gen_random_uuid(),1,gen_random_uuid(),\
        'blue.catbird.chat.defs#directRequestEntry',decode('00','hex'),\
        digest(decode('00','hex'),'sha256'),decode('00','hex'),\
        decode(repeat('00',32),'hex'),decode(repeat('00',64),'hex'),\
        decode('00','hex'),decode(repeat('00',32),'hex'),'did:plc:aaaaaaaaaaaaaaaaaaaaaaaa',\
        gen_random_uuid(),'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA',1,0,1,\
        gen_random_uuid(),$1,transaction_timestamp())";

    sqlx::query(insert)
        .bind(Option::<uuid::Uuid>::None)
        .execute(&mut *tx)
        .await
        .expect("direct-request entry accepts NULL legacy message identity");

    let mut hostile = tx.begin().await.expect("begin hostile identity savepoint");
    let error = sqlx::query(insert)
        .bind(Some(uuid::Uuid::new_v4()))
        .execute(&mut *hostile)
        .await
        .expect_err("direct-request entry rejects ordinary message identity");
    let code = error
        .as_database_error()
        .and_then(|e| e.code().map(|code| code.into_owned()));
    assert_eq!(code.as_deref(), Some("23514"));
    hostile.rollback().await.expect("rollback hostile identity");

    tx.rollback().await.expect("rollback identity regression");
}
