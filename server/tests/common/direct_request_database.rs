use sqlx::{
    migrate::{Migration, MigrationType, Migrator},
    postgres::PgPoolOptions,
    PgPool,
};
use std::borrow::Cow;

pub async fn setup() -> PgPool {
    let url = std::env::var("REQUEST_TEST_DATABASE_URL")
        .expect("explicit REQUEST_TEST_DATABASE_URL required");
    assert_eq!(
        url, "postgresql://127.0.0.1:5432/catbird_direct_requests_test_20260919",
        "refusing non-dedicated local DB"
    );
    let pool = PgPoolOptions::new()
        .max_connections(4)
        .connect(&url)
        .await
        .expect("connect dedicated request DB");
    let (name,user,owner,host):(String,String,String,Option<String>)=sqlx::query_as("SELECT current_database(),current_user,pg_get_userbyid(datdba),host(inet_server_addr()) FROM pg_database WHERE datname=current_database()")
        .fetch_one(&pool).await.unwrap();
    assert_eq!(name, "catbird_direct_requests_test_20260919");
    assert_eq!(user, owner);
    assert_eq!(host.as_deref(), Some("127.0.0.1"));
    let reviewed = super::chat_protocol::reviewed_clean_protocol_migrator()
        .await
        .expect("review historical bytes");
    let mut migrations = reviewed.migrations.to_vec();
    migrations.push(Migration::new(
        20260919000001,
        Cow::Borrowed("direct request preparation"),
        MigrationType::Simple,
        Cow::Borrowed(include_str!(
            "../../migrations/20260919000001_direct_request_preparation.sql"
        )),
    ));
    migrations.push(Migration::new(
        20260919000002,
        Cow::Borrowed("direct request publication"),
        MigrationType::Simple,
        Cow::Borrowed(include_str!(
            "../../migrations/20260919000002_direct_request_publication.sql"
        )),
    ));
    migrations.push(Migration::new(
        20260919000003,
        Cow::Borrowed("direct request lifecycle"),
        MigrationType::Simple,
        Cow::Borrowed(include_str!(
            "../../migrations/20260919000003_direct_request_lifecycle.sql"
        )),
    ));
    migrations.push(Migration::new(
        20260919000004,
        Cow::Borrowed("direct request welcome delivery"),
        MigrationType::Simple,
        Cow::Borrowed(include_str!(
            "../../migrations/20260919000004_direct_request_welcome_delivery.sql"
        )),
    ));
    migrations.push(Migration::new(
        20260919000005,
        Cow::Borrowed("direct request budget release"),
        MigrationType::Simple,
        Cow::Borrowed(include_str!(
            "../../migrations/20260919000005_direct_request_budget_release.sql"
        )),
    ));
    migrations.push(Migration::new(
        20260919000006,
        Cow::Borrowed("direct request attempt null fences"),
        MigrationType::Simple,
        Cow::Borrowed(include_str!(
            "../../migrations/20260919000006_direct_request_attempt_null_fences.sql"
        )),
    ));
    migrations.push(Migration::new(
        20260919000007,
        Cow::Borrowed("direct request publication integrity"),
        MigrationType::Simple,
        Cow::Borrowed(include_str!(
            "../../migrations/20260919000007_direct_request_publication_integrity.sql"
        )),
    ));
    migrations.push(Migration::new(
        20260919000008,
        Cow::Borrowed("direct request lifecycle fences"),
        MigrationType::Simple,
        Cow::Borrowed(include_str!(
            "../../migrations/20260919000008_direct_request_lifecycle_fences.sql"
        )),
    ));
    migrations.push(Migration::new(
        20260919000009,
        Cow::Borrowed("direct request acceptance claims"),
        MigrationType::Simple,
        Cow::Borrowed(include_str!(
            "../../migrations/20260919000009_direct_request_acceptance_claims.sql"
        )),
    ));
    migrations.push(Migration::new(
        20260919000010,
        Cow::Borrowed("direct request retained artifacts"),
        MigrationType::Simple,
        Cow::Borrowed(include_str!(
            "../../migrations/20260919000010_direct_request_retained_artifacts.sql"
        )),
    ));
    let migrator = Migrator {
        migrations: Cow::Owned(migrations),
        ignore_missing: false,
        locking: true,
    };
    let mut connection = pool.acquire().await.unwrap();
    sqlx::query("SET chat.operation_claim_activation_approved='handlers-and-legacy-apis-sealed'")
        .execute(&mut *connection)
        .await
        .unwrap();
    migrator
        .run_direct(&mut *connection)
        .await
        .expect("apply reviewed additive migration on guarded local DB");
    sqlx::query("RESET chat.operation_claim_activation_approved")
        .execute(&mut *connection)
        .await
        .unwrap();
    drop(connection);
    pool
}
