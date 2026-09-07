// Real sealed-read facade proof. Lock holders model the canonical mutation
// prefix; no test hook changes production SQL or bypasses request verification.
use super::production_proof_fixture::{admit_read, seed_identity, FixtureIdentity};
use super::*;
use crate::chat_protocol::repository::inventory::create_own_device_snapshot_for_admission;
use std::time::Duration;

pub(super) async fn run_inventory_lock_order(pool: &PgPool) -> Result<(), String> {
    require_local_owned_gate(pool).await?;
    let at = TrustedRequestInstant::capture().map_err(|e| format!("clock: {e:?}"))?;
    let a = FixtureIdentity::fresh(b"inventory-lock-a")?;
    let b = FixtureIdentity::fresh_for_did(&a.did, b"inventory-lock-b")?;
    seed_identity(pool, &a, &at).await?;
    seed_identity(pool, &b, &at).await?;
    let (first, second) = if a.device_id < b.device_id {
        (&a, &b)
    } else {
        (&b, &a)
    };
    let admission = admit_read(pool, second, "blue.catbird.chat.getOwnDevices", &at).await?;
    let url = std::env::var("TEST_DATABASE_URL").map_err(|e| e.to_string())?;
    let reader_pool = sqlx::postgres::PgPoolOptions::new()
        .max_connections(1)
        .connect(&url)
        .await
        .map_err(|e| e.to_string())?;
    let reader_pid: i32 = sqlx::query_scalar("SELECT pg_backend_pid()")
        .fetch_one(&reader_pool)
        .await
        .map_err(|e| e.to_string())?;
    let mut holder = pool.begin().await.map_err(|e| e.to_string())?;
    sqlx::query("SELECT user_did FROM chat.principals WHERE user_did=$1 FOR UPDATE")
        .bind(&first.did)
        .execute(&mut *holder)
        .await
        .map_err(|e| e.to_string())?;
    sqlx::query("SELECT device_id FROM chat.devices WHERE user_did=$1 AND device_id=$2 FOR UPDATE")
        .bind(&first.did)
        .bind(first.device_id)
        .execute(&mut *holder)
        .await
        .map_err(|e| e.to_string())?;
    let reader = tokio::spawn(async move {
        create_own_device_snapshot_for_admission(&reader_pool, admission)
            .await
            .map(|r| r.into_response_bytes())
            .map_err(|e| format!("signed snapshot: {e:?}"))
    });
    // Wait on the actual PostgreSQL lock, not a guessed scheduling delay.
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            let waiting: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE pid=$1 AND wait_event_type='Lock')")
                .bind(reader_pid).fetch_one(pool).await.map_err(|e| e.to_string())?;
            if waiting { return Ok::<(), String>(()); }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }).await.map_err(|_| "snapshot never reached its blocking SQL lock".to_owned())??;
    // Before the fix the snapshot has already locked `second` and is waiting
    // for `first` through its subject FK. This request completes the cycle.
    // After the fix it waits on the principal before taking any device row.
    let acquire = tokio::time::timeout(
        Duration::from_secs(4),
        sqlx::query(
            "SELECT device_id FROM chat.devices WHERE user_did=$1 AND device_id=$2 FOR UPDATE",
        )
        .bind(&second.did)
        .bind(second.device_id)
        .execute(&mut *holder),
    )
    .await;
    match acquire {
        Ok(Ok(_)) => holder.commit().await.map_err(|e| e.to_string())?,
        other => {
            let _ = holder.rollback().await;
            reader.abort();
            return Err(format!(
                "canonical mutation device prefix failed: {other:?}"
            ));
        }
    }
    let bytes = tokio::time::timeout(Duration::from_secs(5), reader)
        .await
        .map_err(|_| "snapshot did not finish after canonical writer committed".to_owned())?
        .map_err(|e| e.to_string())??;
    assert_subjects(&bytes, &[first.device_id, second.device_id])?;

    // Both authenticated siblings concurrently materialize the real facade.
    let at = TrustedRequestInstant::capture().map_err(|e| format!("clock: {e:?}"))?;
    // Fresh identities isolate this lock proof from retained-session GC policy.
    let sibling_a = FixtureIdentity::fresh(b"inventory-parallel-a")?;
    let sibling_b = FixtureIdentity::fresh_for_did(&sibling_a.did, b"inventory-parallel-b")?;
    seed_identity(pool, &sibling_a, &at).await?;
    seed_identity(pool, &sibling_b, &at).await?;
    let left = admit_read(pool, &sibling_a, "blue.catbird.chat.getOwnDevices", &at).await?;
    let right = admit_read(pool, &sibling_b, "blue.catbird.chat.getOwnDevices", &at).await?;
    let (left, right) = tokio::time::timeout(Duration::from_secs(5), async {
        tokio::join!(
            create_own_device_snapshot_for_admission(pool, left),
            create_own_device_snapshot_for_admission(pool, right)
        )
    })
    .await
    .map_err(|_| "concurrent sibling facades timed out".to_owned())?;
    for result in [left, right] {
        let bytes = result
            .map_err(|e| format!("parallel sibling snapshot: {e:?}"))?
            .into_response_bytes();
        assert_subjects(&bytes, &[sibling_a.device_id, sibling_b.device_id])?;
    }

    // Sealed admission cannot outlive revocation of the exact requester key.
    // Use a fresh third identity so zero durable sessions is non-ambiguous.
    let revoked = FixtureIdentity::fresh_for_did(&first.did, b"inventory-lock-revoked")?;
    seed_identity(pool, &revoked, &at).await?;
    let admission = admit_read(pool, &revoked, "blue.catbird.chat.getOwnDevices", &at).await?;
    sqlx::query("UPDATE chat.device_keys SET revoked_at=clock_timestamp() WHERE user_did=$1 AND device_id=$2")
        .bind(&revoked.did).bind(revoked.device_id).execute(pool).await.map_err(|e| e.to_string())?;
    match create_own_device_snapshot_for_admission(pool, admission).await {
        Err(
            crate::chat_protocol::repository::inventory::ExistingDeviceReadFacadeError::Invariant,
        ) => {}
        Err(other) => {
            return Err(format!(
                "revoked key failed for an unexpected reason: {other:?}"
            ))
        }
        Ok(_) => return Err("revoked exact key authorized an own-device snapshot".into()),
    }
    let sessions: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM chat.device_inventory_sessions WHERE user_did=$1 AND device_id=$2",
    )
    .bind(&revoked.did)
    .bind(revoked.device_id)
    .fetch_one(pool)
    .await
    .map_err(|e| e.to_string())?;
    if sessions != 0 {
        return Err("revoked key left durable snapshot material".into());
    }
    Ok(())
}

fn assert_subjects(bytes: &[u8], expected: &[Uuid]) -> Result<(), String> {
    let response: Value = serde_json::from_slice(bytes).map_err(|e| e.to_string())?;
    let items = response["items"]
        .as_array()
        .ok_or("snapshot items missing")?;
    let mut actual = items
        .iter()
        .map(|item| {
            let id = item["device"]["deviceId"]
                .as_str()
                .ok_or("subject device id missing")?;
            Uuid::parse_str(id).map_err(|_| "subject device id invalid")
        })
        .collect::<Result<Vec<_>, _>>()?;
    actual.sort();
    let mut expected = expected.to_vec();
    expected.sort();
    if actual != expected {
        return Err(format!(
            "snapshot subjects differ: {actual:?} != {expected:?}"
        ));
    }
    Ok(())
}
