//! Independent regression for the comparison-only projection introduced after
//! the real C01 publication exposed PostgreSQL jsonb's NUL limitation.
#![allow(dead_code)]
#[path = "common/chat_protocol.rs"]
pub mod chat_protocol_baseline;
mod common {
    pub use super::chat_protocol_baseline as chat_protocol;
    pub mod direct_request_database;
}

use serde_json::Value;
use sqlx::{Acquire, Postgres, Transaction};

async fn expect_projection_error(
    tx: &mut Transaction<'_, Postgres>,
    document: &[u8],
    code: &str,
    message: &str,
) {
    let mut savepoint = tx.begin().await.expect("open projection savepoint");
    let error =
        sqlx::query("SELECT chat.direct_request_json_projection(convert_from($1,'UTF8')::json)")
            .bind(document)
            .execute(&mut *savepoint)
            .await
            .expect_err("hostile projection input must fail");
    let database = error
        .as_database_error()
        .expect("database projection error");
    assert_eq!(database.code().as_deref(), Some(code));
    assert!(
        database.message().contains(message),
        "unexpected database message: {}",
        database.message()
    );
    savepoint
        .rollback()
        .await
        .expect("rollback failed projection case");
}

#[tokio::test]
async fn signed_json_projection_preserves_bytes_and_rejects_ambiguous_inputs() {
    let pool = common::direct_request_database::setup().await;
    let mut tx = pool.begin().await.expect("begin projection fixture");

    let signed = br#"{"body":{"signatureDomain":"CATBIRD-DIRECT-REQUEST-PUBLISH\u0000","nested":[{"signatureDomain":"CATBIRD-INNER\u0000","count":1}]},"signature":"AA=="}"#;
    let (projected, retained): (Value, Vec<u8>) = sqlx::query_as(
        "SELECT chat.direct_request_json_projection(convert_from(document,'UTF8')::json), document \
         FROM (VALUES ($1::bytea)) AS retained(document)",
    )
    .bind(signed.as_slice())
    .fetch_one(&mut *tx)
    .await
    .expect("project canonical signed wrapper");
    assert_eq!(retained, signed, "comparison must not rewrite signed bytes");
    assert_eq!(
        projected.pointer("/body/signatureDomain"),
        Some(&Value::String("CATBIRD-DIRECT-REQUEST-PUBLISH".to_owned()))
    );
    assert_eq!(
        projected.pointer("/body/nested/0/signatureDomain"),
        Some(&Value::String("CATBIRD-INNER".to_owned()))
    );
    assert_eq!(
        projected.pointer("/body/nested/0/count"),
        Some(&Value::from(1))
    );

    let alternate_ascii_escape = br#"{"body":{"signatureDomain":"\u0043ATBIRD-DIRECT-REQUEST-PUBLISH\u0000","nested":[{"signatureDomain":"CATBIRD-INNER\u0000","count":1}]},"signature":"AA=="}"#;
    let changed_domain = br#"{"body":{"signatureDomain":"CATBIRD-DIRECT-REQUEST-PREPARE\u0000","nested":[{"signatureDomain":"CATBIRD-INNER\u0000","count":1}]},"signature":"AA=="}"#;
    let changed_content = br#"{"body":{"signatureDomain":"CATBIRD-DIRECT-REQUEST-PUBLISH\u0000","nested":[{"signatureDomain":"CATBIRD-INNER\u0000","count":2}]},"signature":"AA=="}"#;
    let equality: (bool, bool, bool) = sqlx::query_as(
        "SELECT \
         chat.direct_request_json_projection(convert_from($1,'UTF8')::json) = \
           chat.direct_request_json_projection(convert_from($2,'UTF8')::json), \
         chat.direct_request_json_projection(convert_from($1,'UTF8')::json) = \
           chat.direct_request_json_projection(convert_from($3,'UTF8')::json), \
         chat.direct_request_json_projection(convert_from($1,'UTF8')::json) = \
           chat.direct_request_json_projection(convert_from($4,'UTF8')::json)",
    )
    .bind(signed.as_slice())
    .bind(alternate_ascii_escape.as_slice())
    .bind(changed_domain.as_slice())
    .bind(changed_content.as_slice())
    .fetch_one(&mut *tx)
    .await
    .expect("compare changed signed inputs");
    assert_eq!(equality, (true, false, false));

    expect_projection_error(
        &mut tx,
        br#"{"field":1,"field":2}"#,
        "23514",
        "duplicate request JSON field",
    )
    .await;
    expect_projection_error(
        &mut tx,
        br#"{"signatureDomain":7}"#,
        "23514",
        "request signature domain must be a string",
    )
    .await;
    expect_projection_error(
        &mut tx,
        br#"{"signatureDomain":"CATBIRD-MISSING-NUL"}"#,
        "23514",
        "request signature domain lacks terminal NUL",
    )
    .await;
    expect_projection_error(
        &mut tx,
        br#"{"signatureDomain":"CATBIRD-INTERNAL\u0000-NUL\u0000"}"#,
        "22P05",
        "unsupported Unicode escape sequence",
    )
    .await;
    expect_projection_error(
        &mut tx,
        br#"{"signatureDomain":"CATBIRD-LITERAL\\u0000"}"#,
        "22P02",
        "invalid input syntax for type json",
    )
    .await;
    expect_projection_error(
        &mut tx,
        br#"{"ordinary":"NUL\u0000must-still-fail"}"#,
        "22P05",
        "unsupported Unicode escape sequence",
    )
    .await;
    let deeply_nested = format!("{}0{}", "[".repeat(66), "]".repeat(66));
    expect_projection_error(
        &mut tx,
        deeply_nested.as_bytes(),
        "23514",
        "request JSON nesting exceeds comparison limit",
    )
    .await;

    tx.rollback().await.expect("rollback migration 13 fixture");
}
