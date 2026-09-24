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
    let send_message =
        include_str!("../../migrations/20260816000001_enable_send_message_operation_claims.sql");
    use sha2::Digest as _;
    assert_eq!(format!("{:x}", sha2::Sha384::digest(send_message.as_bytes())),
        "ae9cc21dd145c3608a57e1f96654b67d53709dba17e3f347758aa8b93830c725d380230751d83f85c497132b8669a30e");
    migrations.push(Migration::new(
        20260816000001,
        Cow::Borrowed("enable send message operation claims"),
        MigrationType::Simple,
        Cow::Borrowed(send_message),
    ));

    // Existing service-auth ledger omitted from the original fourteen-file
    // test baseline. Keep that baseline immutable and pin this dependency.
    let service_auth =
        include_str!("../../migrations/20260820000001_chat_service_auth_admissions.sql");
    assert_eq!(format!("{:x}", sha2::Sha384::digest(service_auth.as_bytes())),
        "2e8cb6bf47498402e56ba5c2fc753114c1d46e0767c98aa243c47993eb4f51a84de89469a8ae9af6bfac751ddadd18ac");
    migrations.push(Migration::new(
        20260820000001,
        Cow::Borrowed("chat service auth admissions"),
        MigrationType::Simple,
        Cow::Borrowed(service_auth),
    ));
    let legacy_dpop =
        include_str!("../../migrations/20260820000002_chat_nullable_legacy_dpop_jkt.sql");
    assert_eq!(format!("{:x}", sha2::Sha384::digest(legacy_dpop.as_bytes())),
        "d1914c731e0fbf81f5b0a9bf9cd77c12f2943fd940c36b9a351b1156b5ca09b55f2b4b44c6810012b4377f6ac283955d");
    migrations.push(Migration::new(
        20260820000002,
        Cow::Borrowed("chat nullable legacy dpop jkt"),
        MigrationType::Simple,
        Cow::Borrowed(legacy_dpop),
    ));
    let inventory_gc =
        include_str!("../../migrations/20260821000001_fix_expired_inventory_session_gc.sql");
    assert_eq!(format!("{:x}", sha2::Sha384::digest(inventory_gc.as_bytes())),
        "42790274fbeb43bce44aa9638d23328223042933af03e6453a0c8c3640b9bcf236d0bc0b8cd76e1e5d846be7c6bfc78a");
    migrations.push(Migration::new(
        20260821000001,
        Cow::Borrowed("fix expired inventory session gc"),
        MigrationType::Simple,
        Cow::Borrowed(inventory_gc),
    ));
    let performance_indices =
        include_str!("../../migrations/20260824000001_chat_performance_indices.sql");
    assert_eq!(format!("{:x}", sha2::Sha384::digest(performance_indices.as_bytes())),
        "e5f3f169724d2afc84043d80057bf9e494fbc9ad617ced0feaebb469d1be68788e7c19e19a67fb36296b85ee803139e0");
    migrations.push(Migration::new(
        20260824000001,
        Cow::Borrowed("chat performance indices"),
        MigrationType::Simple,
        Cow::Borrowed(performance_indices),
    ));
    let pending_inventory =
        include_str!("../../migrations/20260907000001_chat_direct_pending_inventory.sql");
    assert_eq!(format!("{:x}",sha2::Sha384::digest(pending_inventory.as_bytes())),
        "82708d24b2deb72452ebdaf28749aa86ed95075f7ed920c4cc5526962e2ae9f9d8561a5029fc853ba654564d76ef63f1");
    migrations.push(Migration::new(
        20260907000001,
        Cow::Borrowed("chat direct pending inventory"),
        MigrationType::Simple,
        Cow::Borrowed(pending_inventory),
    ));
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
    migrations.push(Migration::new(
        20260919000011,
        Cow::Borrowed("direct request lifecycle slots"),
        MigrationType::Simple,
        Cow::Borrowed(include_str!(
            "../../migrations/20260919000011_direct_request_lifecycle_slots.sql"
        )),
    ));
    migrations.push(Migration::new(
        20260919000012,
        Cow::Borrowed("direct request welcome slot digest"),
        MigrationType::Simple,
        Cow::Borrowed(include_str!(
            "../../migrations/20260919000012_direct_request_welcome_slot_digest.sql"
        )),
    ));
    migrations.push(Migration::new(
        20260919000013,
        Cow::Borrowed("direct request signed json projection"),
        MigrationType::Simple,
        Cow::Borrowed(include_str!(
            "../../migrations/20260919000013_direct_request_signed_json_projection.sql"
        )),
    ));
    migrations.push(Migration::new(
        20260919000014,
        Cow::Borrowed("direct request nul comparison"),
        MigrationType::Simple,
        Cow::Borrowed(include_str!(
            "../../migrations/20260919000014_direct_request_nul_comparison.sql"
        )),
    ));
    migrations.push(Migration::new(
        20260919000015,
        Cow::Borrowed("direct request entry identity"),
        MigrationType::Simple,
        Cow::Borrowed(include_str!(
            "../../migrations/20260919000015_direct_request_entry_identity.sql"
        )),
    ));
    migrations.push(Migration::new(
        20260919000016,
        Cow::Borrowed("direct request push bindings"),
        MigrationType::Simple,
        Cow::Borrowed(include_str!(
            "../../migrations/20260919000016_direct_request_push_bindings.sql"
        )),
    ));
    migrations.push(Migration::new(
        20260919000017,
        Cow::Borrowed("direct request push outbox"),
        MigrationType::Simple,
        Cow::Borrowed(include_str!(
            "../../migrations/20260919000017_direct_request_push_outbox.sql"
        )),
    ));
    migrations.push(Migration::new(
        20260919000018,
        Cow::Borrowed("fix direct request lifecycle close fence"),
        MigrationType::Simple,
        Cow::Borrowed(include_str!(
            "../../migrations/20260919000018_fix_direct_request_lifecycle_close_fence.sql"
        )),
    ));
    // QuotaFix added this on mainline after the pinned baseline above stopped at
    // 000018. `ignore_missing: false` turns its absence into a hard
    // `VersionMissing(20260919000021)` for every direct-request target, so pin it
    // exactly the way `e2e-tests/tests/support/encrypted_requests.rs` does, with
    // the reviewed sha384 of the migration bytes.
    let capacity_abuse_fix =
        include_str!("../../migrations/20260919000021_direct_request_capacity_abuse_fix.sql");
    assert_eq!(
        format!("{:x}", sha2::Sha384::digest(capacity_abuse_fix.as_bytes())),
        "5b6d18e3f9a43bccf357ee37f0df7b322d956369fb55cd036fbbbdb4e63f5c291730ac10885b6de511a697cb365939ca"
    );
    migrations.push(Migration::new(
        20260919000021,
        Cow::Borrowed("direct request capacity abuse fix"),
        MigrationType::Simple,
        Cow::Borrowed(capacity_abuse_fix),
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
    let inventory_gc_contract: (bool, bool) = sqlx::query_as(
        "SELECT position('device_inventory_items' in immutable.prosrc)>0 AND position('session_replication_role' in immutable.prosrc)=0, count(gc.oid)=2 AND bool_and(position('session_replication_role' in gc.prosrc)=0) FROM pg_proc immutable JOIN pg_namespace immutable_ns ON immutable_ns.oid=immutable.pronamespace LEFT JOIN pg_proc gc ON gc.pronamespace=immutable.pronamespace AND gc.proname IN ('gc_expired_inventory_sessions','gc_expired_device_inventory_sessions') WHERE immutable_ns.nspname='chat' AND immutable.proname='enforce_immutable_identity' GROUP BY immutable.prosrc",
    )
    .fetch_one(&pool)
    .await
    .expect("read inventory GC contract");
    assert_eq!(inventory_gc_contract, (true, true));
    pool
}
