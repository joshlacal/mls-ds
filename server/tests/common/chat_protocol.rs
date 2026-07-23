//! Shared database gate for clean `blue.catbird.chat` repository tests.
//!
//! The clean protocol never falls back to the legacy integration database.
//! Every connection is checked before the migrator or a test mutation runs.

#![allow(dead_code)]

use sqlx::{postgres::PgPoolOptions, PgPool};
use url::Url;

pub const CHAT_PROTOCOL_TEST_DATABASE_NAME: &str = "catbird_chat_protocol_test_20260722";

pub fn validate_chat_protocol_database_url(
    value: Option<&str>,
) -> Result<&'static str, &'static str> {
    let value = value
        .filter(|value| !value.is_empty())
        .ok_or("TEST_DATABASE_URL must explicitly name the dedicated clean-chat test database")?;
    let parsed = Url::parse(value).map_err(|_| "TEST_DATABASE_URL is not a valid URL")?;
    if !matches!(parsed.scheme(), "postgres" | "postgresql") {
        return Err("TEST_DATABASE_URL must use postgres or postgresql");
    }
    if parsed.query().is_some() || parsed.fragment().is_some() {
        return Err("TEST_DATABASE_URL may not override the dedicated database target");
    }
    if parsed.path() != format!("/{CHAT_PROTOCOL_TEST_DATABASE_NAME}") {
        return Err("TEST_DATABASE_URL names a database outside the clean-chat test gate");
    }
    if !matches!(parsed.host_str(), Some("localhost" | "127.0.0.1" | "::1")) {
        return Err("TEST_DATABASE_URL must target a loopback PostgreSQL server");
    }
    Ok(CHAT_PROTOCOL_TEST_DATABASE_NAME)
}

#[allow(dead_code)]
pub async fn setup_chat_protocol_db(max_connections: u32) -> PgPool {
    assert!(
        max_connections > 0,
        "clean-chat pool must have a connection"
    );
    let database_url = std::env::var("TEST_DATABASE_URL")
        .expect("TEST_DATABASE_URL must explicitly name catbird_chat_protocol_test_20260722");
    validate_chat_protocol_database_url(Some(&database_url))
        .expect("unsafe TEST_DATABASE_URL for clean-chat repository test");

    let pool = PgPoolOptions::new()
        .max_connections(max_connections)
        .connect(&database_url)
        .await
        .expect("connect to the dedicated clean-chat PostgreSQL database");

    let (current_database, current_user, database_owner, server_address): (
        String,
        String,
        String,
        Option<String>,
    ) = sqlx::query_as(
        r#"
        SELECT current_database(),
               current_user,
               pg_get_userbyid(d.datdba),
               inet_server_addr()::text
          FROM pg_database d
         WHERE d.datname = current_database()
        "#,
    )
    .fetch_one(&pool)
    .await
    .expect("inspect the clean-chat database gate before migration");
    assert_eq!(current_database, CHAT_PROTOCOL_TEST_DATABASE_NAME);
    assert_eq!(
        current_user, database_owner,
        "connected role is not database owner"
    );
    assert!(
        server_address.as_deref().is_none_or(|address| matches!(
            address,
            "127.0.0.1" | "127.0.0.1/32" | "::1" | "::1/128"
        )),
        "refusing a non-local clean-chat database at {server_address:?}",
    );

    sqlx::migrate!("./migrations")
        .run(&pool)
        .await
        .expect("run the production migration set on the dedicated clean-chat database");
    pool
}
