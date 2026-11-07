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

    let maintenance_uses_utc: bool = sqlx::query_scalar(
        "SELECT EXISTS (\
             SELECT 1 FROM pg_proc p \
             CROSS JOIN LATERAL unnest(p.proconfig) AS config(setting) \
              WHERE p.oid = to_regprocedure(\
                  'public.maintain_transport_partitions(regclass,interval,timestamp with time zone,boolean,integer)'\
              ) AND lower(setting) = 'timezone=utc')",
    )
    .fetch_one(pool)
    .await
    .unwrap();
    assert!(
        maintenance_uses_utc,
        "partition-bound and retention arithmetic is catalog-pinned to UTC"
    );

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

async fn wait_for_backend_lock(pool: &PgPool, pid: i32, label: &str) {
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
    loop {
        let waiting: Option<bool> = sqlx::query_scalar(
            "SELECT COALESCE(wait_event_type = 'Lock', false) FROM pg_stat_activity WHERE pid = $1",
        )
        .bind(pid)
        .fetch_optional(pool)
        .await
        .unwrap();
        if waiting == Some(true) {
            return;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "{label} never reached its lock wait"
        );
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }
}

async fn assert_concurrent_terminal_replay_is_noop(
    pool: &PgPool,
    table: &str,
    first_insert: &'static str,
    replay_insert: &'static str,
    terminal_update: &'static str,
) {
    let id = format!("concurrent-terminal-replay-{table}");
    let mut winner = pool.begin().await.unwrap();
    let inserted = sqlx::query(first_insert)
        .bind(&id)
        .execute(&mut *winner)
        .await
        .unwrap();
    assert_eq!(inserted.rows_affected(), 1);

    let mut contender = pool.acquire().await.unwrap();
    let contender_pid: i32 = sqlx::query_scalar("SELECT pg_backend_pid()")
        .fetch_one(&mut *contender)
        .await
        .unwrap();
    let contender_id = id.clone();
    let replay = tokio::spawn(async move {
        let result = sqlx::query(replay_insert)
            .bind(contender_id)
            .execute(&mut *contender)
            .await?;
        Ok::<u64, sqlx::Error>(result.rows_affected())
    });
    wait_for_backend_lock(pool, contender_pid, table).await;

    sqlx::query(terminal_update)
        .bind(&id)
        .execute(&mut *winner)
        .await
        .unwrap();
    winner.commit().await.unwrap();
    assert_eq!(
        replay.await.unwrap().unwrap(),
        0,
        "the concurrent replay is the same no-op as ON CONFLICT DO NOTHING"
    );

    let count: i64 =
        sqlx::query_scalar(&format!("SELECT count(*) FROM public.{table} WHERE id=$1"))
            .bind(&id)
            .fetch_one(pool)
            .await
            .unwrap();
    assert_eq!(count, 1, "one deterministic transport id survives");
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
    assert!(
        applied >= CURRENT_VERSION,
        "upgrade ran through the churn migration"
    );

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
         VALUES ('stable-terminal','did:web:peer.example','https://peer.example','m',decode('06','hex'),'c','pending') \
         ON CONFLICT DO NOTHING",
    )
    .execute(&pool)
    .await
    .expect("a deterministic replay remains a no-op across partitions");
    assert_eq!(
        duplicate.rows_affected(),
        0,
        "the global id guard suppresses the replay just like ON CONFLICT DO NOTHING"
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

#[tokio::test]
#[ignore = "requires loopback PostgreSQL 16 with database creation privileges"]
async fn concurrent_replay_remains_a_noop_after_the_winner_routes_terminal() {
    let database = fresh_fully_migrated_db(PREFIX).await;
    let pool = database.connect(6).await;

    assert_concurrent_terminal_replay_is_noop(
        &pool,
        "outbound_queue",
        "INSERT INTO public.outbound_queue \
         (id,target_ds_did,target_endpoint,method,payload,convo_id,status) \
         VALUES ($1,'did:web:peer.example','https://peer.example','m',decode('11','hex'),'c','pending') \
         ON CONFLICT DO NOTHING",
        "INSERT INTO public.outbound_queue \
         (id,target_ds_did,target_endpoint,method,payload,convo_id,status) \
         SELECT $1,'did:web:peer.example','https://peer.example','m',decode('12','hex'),'c','pending' \
          WHERE NOT EXISTS(SELECT 1 FROM public.outbound_queue WHERE id=$1) \
         ON CONFLICT DO NOTHING",
        "UPDATE public.outbound_queue SET status='delivered' WHERE id=$1",
    )
    .await;
    assert_concurrent_terminal_replay_is_noop(
        &pool,
        "federation_outbox",
        "INSERT INTO public.federation_outbox \
         (id,conversation_id,target_service_did,payload,status) \
         VALUES ($1,'c','did:web:peer.example',decode('21','hex'),'pending') \
         ON CONFLICT DO NOTHING",
        "INSERT INTO public.federation_outbox \
         (id,conversation_id,target_service_did,payload,status) \
         SELECT $1,'c','did:web:peer.example',decode('22','hex'),'pending' \
          WHERE NOT EXISTS(SELECT 1 FROM public.federation_outbox WHERE id=$1) \
         ON CONFLICT DO NOTHING",
        "UPDATE public.federation_outbox SET status='done' WHERE id=$1",
    )
    .await;
}

#[tokio::test]
#[ignore = "requires loopback PostgreSQL 16 with database creation privileges"]
async fn maintenance_locks_the_parent_before_default_and_cannot_deadlock_enqueue() {
    let database = fresh_fully_migrated_db(PREFIX).await;
    let pool = database.connect(6).await;
    let mut producer = pool.begin().await.unwrap();
    sqlx::query("LOCK TABLE ONLY public.outbound_queue IN ROW EXCLUSIVE MODE")
        .execute(&mut *producer)
        .await
        .unwrap();

    let mut maintenance_connection = pool.acquire().await.unwrap();
    let maintenance_pid: i32 = sqlx::query_scalar("SELECT pg_backend_pid()")
        .fetch_one(&mut *maintenance_connection)
        .await
        .unwrap();
    let maintenance = tokio::spawn(async move {
        sqlx::query_scalar::<_, i64>(
            "SELECT public.maintain_transport_partitions(\
                 'public.outbound_queue'::regclass,interval '7 days',\
                 '2042-07-15T00:00:00Z'::timestamptz,FALSE,0)",
        )
        .fetch_one(&mut *maintenance_connection)
        .await
    });
    wait_for_backend_lock(&pool, maintenance_pid, "partition maintenance").await;

    sqlx::query("SET LOCAL lock_timeout='250ms'")
        .execute(&mut *producer)
        .await
        .unwrap();
    sqlx::query(
        "INSERT INTO public.outbound_queue \
         (id,target_ds_did,target_endpoint,method,payload,convo_id,status) \
         VALUES ('parent-first-producer','did:web:peer.example','https://peer.example',\
                 'm',decode('31','hex'),'c','pending')",
    )
    .execute(&mut *producer)
    .await
    .expect("maintenance waiting on the parent must not hold DEFAULT");
    producer.rollback().await.unwrap();
    maintenance
        .await
        .unwrap()
        .expect("maintenance proceeds after the producer releases the parent");
}

#[tokio::test]
#[ignore = "requires loopback PostgreSQL 16 with database creation privileges"]
async fn maintenance_month_arithmetic_is_utc_in_a_non_utc_session() {
    let database = fresh_fully_migrated_db(PREFIX).await;
    let pool = database.connect(3).await;
    let mut connection = pool.acquire().await.unwrap();
    sqlx::query("SET TIME ZONE 'America/New_York'")
        .execute(&mut *connection)
        .await
        .unwrap();
    sqlx::query_scalar::<_, i64>(
        "SELECT public.maintain_transport_partitions(\
             'public.outbound_queue'::regclass,interval '7 days',\
             '2026-03-15T00:00:00Z'::timestamptz,FALSE,0)",
    )
    .fetch_one(&mut *connection)
    .await
    .unwrap();
    let timezone: String = sqlx::query_scalar("SELECT current_setting('TimeZone')")
        .fetch_one(&mut *connection)
        .await
        .unwrap();
    assert_eq!(
        timezone, "America/New_York",
        "the function's UTC setting is call-local"
    );

    sqlx::query(
        "INSERT INTO public.outbound_queue \
         (id,target_ds_did,target_endpoint,method,payload,convo_id,status,terminal_at) \
         VALUES ('utc-month-end','did:web:peer.example','https://peer.example','m',\
                 decode('41','hex'),'c','dead','2026-03-31T12:00:00Z')",
    )
    .execute(&mut *connection)
    .await
    .unwrap();
    let location: String = sqlx::query_scalar(
        "SELECT tableoid::regclass::text FROM public.outbound_queue WHERE id='utc-month-end'",
    )
    .fetch_one(&mut *connection)
    .await
    .unwrap();
    assert_eq!(
        location, "outbound_queue_202603",
        "March's upper bound is April 1 UTC, not a DST-shifted local instant"
    );

    sqlx::query_scalar::<_, i64>(
        "SELECT public.maintain_transport_partitions(\
             'public.outbound_queue'::regclass,interval '7 days',\
             '2026-04-05T00:00:00Z'::timestamptz,TRUE,0)",
    )
    .fetch_one(&mut *connection)
    .await
    .unwrap();
    let retained: bool = sqlx::query_scalar(
        "SELECT to_regclass('public.outbound_queue_202603') IS NOT NULL \
             AND EXISTS(SELECT 1 FROM public.outbound_queue WHERE id='utc-month-end')",
    )
    .fetch_one(&mut *connection)
    .await
    .unwrap();
    assert!(
        retained,
        "the March partition contains rows younger than seven UTC days"
    );
}
