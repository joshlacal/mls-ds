// Non-shipping proof through real signed request and authenticated inventory
// facades. A third transaction pins the head to make the former device/head
// deadlock reproducible without changing production SQL or fabricating guards.
use super::production_proof_fixture::{
    admit_lifecycle, admit_read, coordinate_json, leaf_recovery_request,
    seed_durable_recovery_fulfillment_fixture_for_identities, FixtureIdentity,
};
use super::*;
use crate::chat_protocol::repository::inventory::{
    create_inventory_snapshot_and_first_page, InventoryDomain, InventoryPublicRequestBinding,
};
use crate::chat_protocol::{CursorSealer, OsSecureRandom};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use sha2::{Digest as _, Sha256};
use std::time::Duration;
use zeroize::Zeroizing;

struct AbortPendingTask(tokio::task::AbortHandle);
impl Drop for AbortPendingTask {
    fn drop(&mut self) {
        self.0.abort();
    }
}

async fn single_connection_pool(deadlock_timeout: &str) -> Result<(PgPool, i32), String> {
    let url = std::env::var("TEST_DATABASE_URL").map_err(|e| e.to_string())?;
    let pool = sqlx::postgres::PgPoolOptions::new()
        .max_connections(1)
        .connect(&url)
        .await
        .map_err(|e| e.to_string())?;
    // These pools belong only to this test. Let the writer detect the old
    // cycle first so inventory's existing read retry cannot hide SQLSTATE 40P01.
    // The same scheduling settings apply to the baseline and corrected trees.
    sqlx::query("SELECT set_config('deadlock_timeout', $1, false)")
        .bind(deadlock_timeout)
        .execute(&pool)
        .await
        .map_err(|e| e.to_string())?;
    let pid = sqlx::query_scalar("SELECT pg_backend_pid()")
        .fetch_one(&pool)
        .await
        .map_err(|e| e.to_string())?;
    Ok((pool, pid))
}

async fn wait_for_actual_lock(pool: &PgPool, pid: i32, stage: &str) -> Result<(), String> {
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            let waiting: bool = sqlx::query_scalar(
                "SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE pid=$1 AND wait_event_type='Lock')",
            ).bind(pid).fetch_one(pool).await.map_err(|e| e.to_string())?;
            if waiting {
                let (query, blockers): (String, Vec<i32>) = sqlx::query_as(
                    "SELECT query,pg_blocking_pids(pid) FROM pg_stat_activity WHERE pid=$1",
                ).bind(pid).fetch_one(pool).await.map_err(|e| e.to_string())?;
                eprintln!("{stage}: blockers={blockers:?}; SQL={query}");
                return Ok::<(), String>(());
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }).await.map_err(|_| format!("{stage} never reached its PostgreSQL lock"))?
}

pub(super) async fn run_request_inventory_concurrency(pool: &PgPool) -> Result<(), String> {
    require_local_owned_gate(pool).await?;
    let requester = FixtureIdentity::fresh(b"recovery-inventory-requester")?;
    let recipient = FixtureIdentity::fresh(b"recovery-inventory-recipient")?;
    mint_two_party_recovery_fallbacks(pool, &requester.did, &recipient.did).await?;
    let at = TrustedRequestInstant::capture().map_err(|e| format!("clock: {e:?}"))?;
    let fixture = seed_durable_recovery_fulfillment_fixture_for_identities(
        pool,
        &at,
        requester,
        recipient,
        Uuid::new_v4(),
    )
    .await?;
    let request = leaf_recovery_request(
        &fixture.requester,
        Uuid::new_v4(),
        coordinate_json(&fixture.prior),
        at.as_str(),
    )?;
    let admission = admit_lifecycle(
        pool,
        &fixture.requester,
        "blue.catbird.chat.requestLeafRecovery",
        &request,
        &at,
    )
    .await?;
    let read_admission = admit_read(
        pool,
        &fixture.fulfiller,
        "blue.catbird.chat.getConversations",
        &at,
    )
    .await?;
    let relationship = crate::chat_protocol::relationship_policy::ProductionRelationshipAuthority::from_startup_guard(
        crate::chat_protocol::repository::relationship::load_fixed_relationship_authority_startup_guard()
            .map_err(|e| format!("relationship: {e:?}"))?,
    );
    let cursor_key: String =
        sqlx::query_scalar("SELECT cursor_key_id FROM chat.protocol_instances WHERE singleton")
            .fetch_one(pool)
            .await
            .map_err(|e| e.to_string())?;
    let cursor_key: [u8; 32] = URL_SAFE_NO_PAD
        .decode(cursor_key)
        .map_err(|e| e.to_string())?
        .try_into()
        .map_err(|_| "invalid gate cursor key")?;
    // Private test capability encryption under the existing public key label;
    // fresh identity isolates all receipts from every existing client session.
    let sealer = CursorSealer::new(cursor_key, Zeroizing::new([0x78; 32]))
        .map_err(|e| format!("test sealer: {e:?}"))?;
    let binding = InventoryPublicRequestBinding::new(
        "blue.catbird.chat.getConversations",
        1,
        InventoryDomain::Conversations,
        100,
        Sha256::digest([]).into(),
    )
    .map_err(|e| format!("inventory request: {e:?}"))?;
    let (writer_pool, writer_pid) = single_connection_pool("50ms").await?;
    let (reader_pool, reader_pid) = single_connection_pool("5s").await?;
    let mut pin = pool.begin().await.map_err(|e| e.to_string())?;
    sqlx::query("SELECT 1 FROM chat.conversations WHERE conversation_id=$1 FOR UPDATE")
        .bind(fixture.conversation_id)
        .fetch_one(&mut *pin)
        .await
        .map_err(|e| e.to_string())?;
    let writer = tokio::spawn(async move {
        let mut tx = writer_pool.begin().await.map_err(|e| e.to_string())?;
        let prepared =
            crate::chat_protocol::repository::prelude::prepare_signed_operation(&mut tx, admission)
                .await
                .map_err(|e| format!("prepare request: {e:?}"))?;
        let outcome = execute_prepared_recovery(&mut tx, prepared, &relationship)
            .await
            .map_err(|e| format!("signed request facade: {e:?}"))?;
        if outcome.status() != 200 {
            return Err(format!("request status {}", outcome.status()));
        }
        tx.commit()
            .await
            .map_err(|e| format!("request commit: {e}"))
    });
    let writer_abort = AbortPendingTask(writer.abort_handle());
    wait_for_actual_lock(pool, writer_pid, "request waiting on pinned head").await?;
    let reader = tokio::spawn(async move {
        let mut random = OsSecureRandom::new();
        create_inventory_snapshot_and_first_page(
            &reader_pool,
            read_admission,
            binding,
            None,
            &sealer,
            &mut random,
        )
        .await
        .map(|r| r.into_bytes())
        .map_err(|e| format!("authenticated inventory facade: {e:?}"))
    });
    let reader_abort = AbortPendingTask(reader.abort_handle());
    wait_for_actual_lock(pool, reader_pid, "recipient inventory").await?;
    // Old actor-only scope: writer now owns the head and needs the reader's
    // device, while the reader owns its device and needs the writer's head.
    // Current scope: writer acquired all event recipients before the head;
    // reader is waiting on that prefix and can finish after the writer commits.
    pin.commit().await.map_err(|e| e.to_string())?;
    let (write, read) = tokio::time::timeout(Duration::from_secs(8), async {
        tokio::join!(writer, reader)
    })
    .await
    .map_err(|_| "request/inventory cycle did not complete within 8 seconds")?;
    drop(writer_abort);
    drop(reader_abort);
    write.map_err(|e| format!("writer task: {e}"))??;
    let bytes = read.map_err(|e| format!("reader task: {e}"))??;
    let response: Value = serde_json::from_slice(&bytes).map_err(|e| e.to_string())?;
    let items = response["items"]
        .as_array()
        .ok_or("inventory omitted items")?;
    if !items.iter().any(|item| {
        item["state"]["coordinates"]["conversationId"] == fixture.conversation_id.to_string()
    }) {
        return Err("inventory did not return the current conversation".into());
    }
    let counts: (i64, i64, i64) = sqlx::query_as(
        "SELECT (SELECT count(*) FROM chat.leaf_recovery_requests WHERE recovery_request_id=$1 AND status='open'),(SELECT count(*) FROM chat.key_package_reservations WHERE recovery_request_id=$1 AND status='active'),(SELECT count(*) FROM chat.idempotency_records WHERE operation_id=$1 AND completed_status=200)",
    ).bind(request.operation_id).fetch_one(pool).await.map_err(|e| e.to_string())?;
    if counts != (1, 1, 1) {
        return Err(format!(
            "request durable completion is not exact: {counts:?}"
        ));
    }
    Ok(())
}
