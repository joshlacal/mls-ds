//! Test-only child of the transport regression in the separate proof source.
//! All database access is guarded by the parent's exact loopback/owner/85-ledger checks.
#![cfg(all(test, feature = "test-support"))]
use super::*;

fn ticket_request(
    device: &http::Device,
    inventory: &Inventory,
) -> axum::http::Request<axum::body::Body> {
    http::unsigned_json_request(
        device,
        "blue.catbird.chat.getSubscriptionTicket",
        serde_json::to_vec(&json!({"actorDeviceId":device.device_id,
            "inventorySessionId":inventory.capability,"eventCursor":inventory.cursor}))
        .unwrap(),
    )
}

async fn raw_inventory_without_publication_wait(
    pool: &PgPool,
    router: &axum::Router,
    device: &http::Device,
) -> Inventory {
    let query = format!("?actorDeviceId={}&limit=100", device.device_id);
    let (status, response) = http::send(
        router.clone(),
        http::unsigned_request(device, "blue.catbird.chat.getConversations", "GET", &query),
    )
    .await;
    assert_eq!(
        status,
        axum::http::StatusCode::OK,
        "inventory error={:?}",
        response.get("error")
    );
    let observed_after_response = clock_now(pool).await;
    let capability = response["inventorySessionId"].as_str().unwrap().to_owned();
    let cursor = response["snapshotEventCursor"].as_str().unwrap().to_owned();
    let row: Value = sqlx::query_scalar("SELECT to_jsonb(session) FROM chat.inventory_sessions session WHERE token_hash=$1 AND user_did=$2 AND device_id=$3")
        .bind(capability_hash(&capability)).bind(&device.did).bind(device.device_id)
        .fetch_one(pool).await.unwrap();
    let created_at = DateTime::parse_from_rfc3339(row["created_at"].as_str().unwrap())
        .unwrap()
        .with_timezone(&Utc);
    assert!(
        observed_after_response >= created_at,
        "inventory response was published before its exact database creation bound"
    );
    for nsid in [
        "blue.catbird.chat.getPendingWelcomes",
        "blue.catbird.chat.getLeafRecoveryInbox",
    ] {
        let query = format!(
            "?actorDeviceId={}&inventorySessionId={capability}&limit=100",
            device.device_id
        );
        let (status, page) = http::send(
            router.clone(),
            http::unsigned_request(device, nsid, "GET", &query),
        )
        .await;
        assert_eq!(
            status,
            axum::http::StatusCode::OK,
            "domain error={:?}",
            page.get("error")
        );
        assert_eq!(page["inventorySessionId"], capability);
        assert_eq!(page["hasMore"], false);
    }
    Inventory {
        capability,
        cursor,
        session_id: Uuid::parse_str(row["inventory_session_id"].as_str().unwrap()).unwrap(),
        session_row: row,
    }
}

async fn singleton_setup(pool: &PgPool) -> (axum::Router, http::Device) {
    let fixture = build_test_creation_fixture(clock_now(pool).await);
    let device = seed_group_device(pool, &fixture).await;
    let router = http::router_for_authenticated_acceptance(pool.clone()).await;
    create_group(&router, &device, &fixture).await;
    (router, device)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn initial_inventory_response_allows_immediate_ticket_without_a_client_wait() {
    let _serial = SERIAL.lock().await;
    let pool = owned_database().await;
    let (router, device) = singleton_setup(&pool).await;
    // Align the test invocation early in a real database second so the old
    // ceil-created response defect cannot be hidden by ordinary test latency.
    timeout(StdDuration::from_secs(2), async {
        while clock_now(&pool).await.timestamp_subsec_millis() > 100 {
            sleep(StdDuration::from_millis(5)).await;
        }
    })
    .await
    .unwrap();
    let inventory = raw_inventory_without_publication_wait(&pool, &router, &device).await;
    let (status, body) = http::send(router.clone(), ticket_request(&device, &inventory)).await;
    assert_eq!(
        status,
        axum::http::StatusCode::OK,
        "fresh inventory must be immediately ticket-usable; error={:?}",
        body.get("error")
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn foreign_capability_is_rejected_before_locking_its_owners_session() {
    let _serial = SERIAL.lock().await;
    let pool = owned_database().await;
    let (router, owner) = singleton_setup(&pool).await;
    let foreign_fixture = build_test_creation_fixture(clock_now(&pool).await);
    let foreign = seed_group_device(&pool, &foreign_fixture).await;
    let inventory = inventory_roundtrip(&pool, &router, &owner).await;
    let before = row_by_session(&pool, inventory.session_id).await;
    let mut lock = pool.begin().await.unwrap();
    let blocker: i32 = sqlx::query_scalar("SELECT pg_backend_pid()")
        .fetch_one(&mut *lock)
        .await
        .unwrap();
    sqlx::query("SELECT inventory_session_id FROM chat.inventory_sessions WHERE inventory_session_id=$1 FOR UPDATE")
        .bind(inventory.session_id).fetch_one(&mut *lock).await.unwrap();
    let control_request = ticket_request(&owner, &inventory);
    let control_router = router.clone();
    let mut control =
        tokio::spawn(async move { http::send(control_router, control_request).await });
    let control_blocked = timeout(StdDuration::from_secs(2), async {
        loop {
            let blocked: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE $1 = ANY(pg_blocking_pids(pid)))")
                .bind(blocker).fetch_one(&pool).await.unwrap();
            if blocked { break; }
            sleep(StdDuration::from_millis(10)).await;
        }
    }).await;
    let foreign_result = timeout(
        StdDuration::from_millis(600),
        http::send(router.clone(), ticket_request(&foreign, &inventory)),
    )
    .await;
    control.abort();
    let _ = (&mut control).await;
    lock.rollback().await.unwrap();
    assert!(
        control_blocked.is_ok(),
        "control proved the exact owner session lock blocks its valid capability"
    );
    let (status, body) =
        foreign_result.expect("foreign capability must not wait on another device's session lock");
    assert_eq!(status, axum::http::StatusCode::BAD_REQUEST);
    assert!(body.get("error").and_then(Value::as_str).is_some());
    assert_eq!(row_by_session(&pool, inventory.session_id).await, before);
    let (status, _) = http::send(router, ticket_request(&owner, &inventory)).await;
    assert_eq!(
        status,
        axum::http::StatusCode::OK,
        "owner capability remains usable after rejected foreign request"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn both_ticket_inventory_lookup_failures_remain_storage_errors() {
    let _serial = SERIAL.lock().await;
    let pool = owned_database().await;
    let (router, device) = singleton_setup(&pool).await;
    let inventory = inventory_roundtrip(&pool, &router, &device).await;
    // Owned-schema fault injection only, with no row mutations. The first
    // relation fails the exact capability locator; the second fails the later
    // snapshot helper's live retention-fence query. Restore before assertions.
    for (table, temporary) in [
        ("inventory_sessions", "inventory_sessions_admission_fault"),
        ("event_retention", "event_retention_admission_fault"),
    ] {
        let before = inventory_rows(&pool).await;
        let original_oid: i64 = sqlx::query_scalar("SELECT to_regclass($1)::oid::bigint")
            .bind(format!("chat.{table}"))
            .fetch_one(&pool)
            .await
            .unwrap();
        let absent: bool = sqlx::query_scalar("SELECT to_regclass($1) IS NULL")
            .bind(format!("chat.{temporary}"))
            .fetch_one(&pool)
            .await
            .unwrap();
        assert!(absent, "owned fault name must be unused");
        sqlx::query(&format!("ALTER TABLE chat.{table} RENAME TO {temporary}"))
            .execute(&pool)
            .await
            .unwrap();
        let request = ticket_request(&device, &inventory);
        let fault_router = router.clone();
        let mut operation = tokio::spawn(async move { http::send(fault_router, request).await });
        let response = timeout(StdDuration::from_secs(3), &mut operation).await;
        if response.is_err() {
            operation.abort();
            let _ = operation.await;
        }
        let restored = sqlx::query(&format!("ALTER TABLE chat.{temporary} RENAME TO {table}"))
            .execute(&pool)
            .await;
        assert!(
            restored.is_ok(),
            "owned relation must be restored before diagnosing response"
        );
        let restored_oid: i64 = sqlx::query_scalar("SELECT to_regclass($1)::oid::bigint")
            .bind(format!("chat.{table}"))
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(restored_oid, original_oid);
        let (status, body) = response
            .expect("bounded storage failure")
            .expect("request task completed");
        assert_eq!(
            status,
            axum::http::StatusCode::INTERNAL_SERVER_ERROR,
            "storage failure must not become authority retirement; error={:?}",
            body.get("error")
        );
        assert_eq!(
            inventory_rows(&pool).await,
            before,
            "restored owned schema has identical retained data"
        );
        let (status, _) = http::send(router.clone(), ticket_request(&device, &inventory)).await;
        assert_eq!(
            status,
            axum::http::StatusCode::OK,
            "same original capability works after storage restoration"
        );
    }
}
