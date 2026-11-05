mod common;

use common::fresh_db::{acquire_migration_lock, fresh_fully_migrated_db, DisposableDatabase};
use futures::future::BoxFuture;
use sqlx::error::BoxDynError;
use sqlx::migrate::{Migration, MigrationSource, Migrator};
use sqlx::{Connection, Executor, PgConnection, PgPool};
use std::path::Path;

const PREVIOUS_VERSION: i64 = 20261104000011;
const CURRENT_VERSION: i64 = 20261104000012;
const PREFIX: &str = "mlsds_churn_";

#[derive(Debug)]
struct OwnedMigrations(Vec<Migration>);

impl MigrationSource<'static> for OwnedMigrations {
    fn resolve(self) -> BoxFuture<'static, Result<Vec<Migration>, BoxDynError>> {
        Box::pin(async move { Ok(self.0) })
    }
}

async fn migrate_through_previous(connection: &mut PgConnection) {
    let all = Migrator::new(Path::new("./migrations"))
        .await
        .expect("resolve production migrations");
    let previous = all
        .iter()
        .filter(|migration| migration.version <= PREVIOUS_VERSION)
        .cloned()
        .collect::<Vec<_>>();
    assert_eq!(
        previous.last().map(|migration| migration.version),
        Some(PREVIOUS_VERSION)
    );
    let migrator = Migrator::new(OwnedMigrations(previous))
        .await
        .expect("build previous-schema migrator");
    migrator
        .run(connection)
        .await
        .expect("install schema immediately before churn migration");
}

async fn assert_churn_schema(pool: &PgPool) {
    for table in ["outbound_queue", "federation_outbox"] {
        let kind: String =
            sqlx::query_scalar("SELECT relkind::text FROM pg_class WHERE oid = to_regclass($1)")
                .bind(format!("public.{table}"))
                .fetch_one(pool)
                .await
                .unwrap();
        assert_eq!(kind, "p", "{table} is a declarative partition parent");

        let default_partition: bool = sqlx::query_scalar(
            "SELECT EXISTS (\
                 SELECT 1 FROM pg_inherits inheritance \
                 JOIN pg_class child ON child.oid=inheritance.inhrelid \
                 WHERE inheritance.inhparent=to_regclass($1) \
                   AND child.relname=$2)",
        )
        .bind(format!("public.{table}"))
        .bind(format!("{table}_default"))
        .fetch_one(pool)
        .await
        .unwrap();
        assert!(
            default_partition,
            "{table} has its bounded active DEFAULT partition"
        );

        let monthly_partitions: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM pg_inherits inheritance \
             JOIN pg_class child ON child.oid=inheritance.inhrelid \
             WHERE inheritance.inhparent=to_regclass($1) \
               AND child.relname ~ ($2 || '_[0-9]{6}$')",
        )
        .bind(format!("public.{table}"))
        .bind(table)
        .fetch_one(pool)
        .await
        .unwrap();
        assert!(
            monthly_partitions >= 3,
            "{table} has current and two future months"
        );
    }

    let expected_options = vec![
        "autovacuum_analyze_scale_factor=0.01".to_owned(),
        "autovacuum_vacuum_scale_factor=0.01".to_owned(),
    ];
    for table in [
        "chat.key_packages",
        "chat.key_package_reservations",
        "chat.direct_request_lifecycle_reserves",
        "chat.direct_request_decision_slots",
        "chat.direct_request_welcome_slots",
        "chat.direct_request_remote_leases",
        "chat.direct_request_reservation_intents",
        "chat.direct_request_reserved_remote_packages",
        "chat.direct_request_retired_packages",
        "chat.group_key_package_exports",
        "chat.federated_key_package_reservations",
    ] {
        let mut options: Vec<String> =
            sqlx::query_scalar("SELECT unnest(reloptions) FROM pg_class WHERE oid=to_regclass($1)")
                .bind(table)
                .fetch_all(pool)
                .await
                .unwrap();
        options.sort();
        assert_eq!(
            options, expected_options,
            "exact churn reloptions for {table}"
        );
    }

    let conversation_options: Vec<String> = sqlx::query_scalar(
        "SELECT unnest(reloptions) FROM pg_class WHERE oid='chat.conversations'::regclass",
    )
    .fetch_all(pool)
    .await
    .unwrap();
    assert_eq!(conversation_options, vec!["fillfactor=70"]);
}

#[tokio::test]
#[ignore = "requires loopback PostgreSQL 16 with database creation privileges"]
async fn clean_postgres_16_install_has_partition_and_reloption_contract() {
    let database = fresh_fully_migrated_db(PREFIX).await;
    let pool = database.connect(2).await;
    let version: i32 = sqlx::query_scalar("SELECT current_setting('server_version_num')::int")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert!(
        (160000..170000).contains(&version),
        "test requires PostgreSQL 16"
    );
    assert_churn_schema(&pool).await;
}

#[tokio::test]
#[ignore = "requires loopback PostgreSQL 16 with database creation privileges"]
async fn previous_schema_upgrade_preserves_rows_and_drops_only_expired_partitions() {
    let _migration_guard = acquire_migration_lock().await;
    let database = DisposableDatabase::mint(PREFIX).await;
    let mut connection = PgConnection::connect(database.url()).await.unwrap();
    connection
        .execute("SET chat.operation_claim_activation_approved='handlers-and-legacy-apis-sealed'")
        .await
        .unwrap();
    migrate_through_previous(&mut connection).await;

    let before_kind: String = sqlx::query_scalar(
        "SELECT relkind::text FROM pg_class WHERE oid='public.outbound_queue'::regclass",
    )
    .fetch_one(&mut connection)
    .await
    .unwrap();
    assert_eq!(
        before_kind, "r",
        "fail-before: previous queue is not partitioned"
    );
    let before_function: bool = sqlx::query_scalar(
        "SELECT to_regprocedure(\
             'public.maintain_transport_partitions(regclass,interval,timestamp with time zone,boolean,integer)'\
         ) IS NOT NULL",
    )
    .fetch_one(&mut connection)
    .await
    .unwrap();
    assert!(
        !before_function,
        "fail-before: maintenance function is absent"
    );

    connection
        .execute(
            "INSERT INTO public.outbound_queue \
             (id,target_ds_did,target_endpoint,method,payload,convo_id,status,created_at) VALUES \
             ('upgrade-outbound-active','did:web:peer.example','https://peer.example','m',decode('01','hex'),'c','pending','2024-01-10Z'), \
             ('upgrade-outbound-terminal','did:web:peer.example','https://peer.example','m',decode('02','hex'),'c','dead','2024-01-15Z'); \
             INSERT INTO public.federation_outbox \
             (id,conversation_id,target_service_did,payload,status,created_at,updated_at) VALUES \
             ('upgrade-federation-active','c','did:web:peer.example',decode('03','hex'),'pending','2024-01-10Z','2024-01-10Z'), \
             ('upgrade-federation-terminal','c','did:web:peer.example',decode('04','hex'),'done','2024-01-15Z','2024-01-16Z')",
        )
        .await
        .unwrap();

    sqlx::migrate!("./migrations")
        .run(&mut connection)
        .await
        .expect("upgrade previous fixture through churn migration");
    let applied: i64 = sqlx::query_scalar("SELECT max(version) FROM _sqlx_migrations")
        .fetch_one(&mut connection)
        .await
        .unwrap();
    assert_eq!(applied, CURRENT_VERSION);

    let pool = database.connect(4).await;
    assert_churn_schema(&pool).await;
    for table in ["outbound_queue", "federation_outbox"] {
        let count: i64 = sqlx::query_scalar(&format!("SELECT count(*) FROM public.{table}"))
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(count, 2, "upgrade preserved every {table} fixture row");
    }

    let locations: Vec<(String, String)> = sqlx::query_as(
        "SELECT id, tableoid::regclass::text FROM public.outbound_queue ORDER BY id",
    )
    .fetch_all(&pool)
    .await
    .unwrap();
    assert_eq!(locations[0].1, "outbound_queue_default");
    assert!(locations[1].1.ends_with("outbound_queue_202401"));

    sqlx::query(
        "INSERT INTO public.outbound_queue \
         (id,target_ds_did,target_endpoint,method,payload,convo_id,status) \
         VALUES ('stable-terminal','did:web:peer.example','https://peer.example','m',decode('05','hex'),'c','pending')",
    )
    .execute(&pool)
    .await
    .unwrap();
    sqlx::query("UPDATE public.outbound_queue SET status='delivered' WHERE id='stable-terminal'")
        .execute(&pool)
        .await
        .unwrap();
    let first: (chrono::DateTime<chrono::Utc>, String) = sqlx::query_as(
        "SELECT terminal_at,tableoid::regclass::text FROM public.outbound_queue WHERE id='stable-terminal'",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    sqlx::query("UPDATE public.outbound_queue SET status='failed' WHERE id='stable-terminal'")
        .execute(&pool)
        .await
        .unwrap();
    let second: (chrono::DateTime<chrono::Utc>, String) = sqlx::query_as(
        "SELECT terminal_at,tableoid::regclass::text FROM public.outbound_queue WHERE id='stable-terminal'",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(
        second, first,
        "terminal retries never move partition months"
    );

    sqlx::query(
        "INSERT INTO public.outbound_queue \
         (id,target_ds_did,target_endpoint,method,payload,convo_id,status) \
         VALUES ('inserted-terminal','did:web:peer.example','https://peer.example','m',decode('0a','hex'),'c','dead')",
    )
    .execute(&pool)
    .await
    .unwrap();
    let inserted_terminal: (bool, bool) = sqlx::query_as(
        "SELECT terminal_at IS NOT NULL, tableoid <> 'public.outbound_queue_default'::regclass \
         FROM public.outbound_queue WHERE id='inserted-terminal'",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(
        inserted_terminal,
        (true, true),
        "direct terminal inserts are stamped and routed after insertion"
    );

    let duplicate = sqlx::query(
        "INSERT INTO public.outbound_queue \
         (id,target_ds_did,target_endpoint,method,payload,convo_id,status) \
         VALUES ('stable-terminal','did:web:peer.example','https://peer.example','m',decode('06','hex'),'c','pending')",
    )
    .execute(&pool)
    .await
    .expect_err("global id guard rejects a duplicate across partitions");
    assert_eq!(
        duplicate
            .as_database_error()
            .and_then(|error| error.code())
            .as_deref(),
        Some("23505")
    );

    sqlx::query(
        "INSERT INTO public.outbound_queue \
         (id,target_ds_did,target_endpoint,method,payload,convo_id,status,created_at,terminal_at) VALUES \
         ('expired-one','did:web:peer.example','https://peer.example','m',decode('07','hex'),'c','dead',clock_timestamp()-interval '1 year',clock_timestamp()-interval '3 months'), \
         ('expired-two','did:web:peer.example','https://peer.example','m',decode('08','hex'),'c','failed',clock_timestamp()-interval '1 year',clock_timestamp()-interval '3 months'), \
         ('old-but-live','did:web:peer.example','https://peer.example','m',decode('09','hex'),'c','pending',clock_timestamp()-interval '1 year',NULL)",
    )
    .execute(&pool)
    .await
    .unwrap();
    let expired_partition: String = sqlx::query_scalar(
        "SELECT tableoid::regclass::text FROM public.outbound_queue WHERE id='expired-one'",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(expired_partition, "outbound_queue_default");

    let dropped: i64 = sqlx::query_scalar(
        "SELECT public.maintain_transport_partitions(\
             'public.outbound_queue'::regclass,interval '7 days',clock_timestamp(),TRUE,2)",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert!(dropped >= 1);
    let survivors: Vec<String> = sqlx::query_scalar(
        "SELECT id FROM public.outbound_queue \
         WHERE id IN ('expired-one','expired-two','old-but-live') ORDER BY id",
    )
    .fetch_all(&pool)
    .await
    .unwrap();
    assert_eq!(survivors, vec!["old-but-live"]);
}
