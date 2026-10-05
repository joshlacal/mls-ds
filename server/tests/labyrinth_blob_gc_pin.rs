//! Labyrinth backend: attachment references pin their blob's stored object
//! against chat object GC, and release it when the last reference goes
//! (design §4; migration `20261004100007`).

mod common;

#[path = "common/labyrinth_harness.rs"]
mod harness;

use catbird_server::handlers::chat::reclaim_due_blob_objects_recording;
use curve25519_dalek::ristretto::RistrettoPoint;
use harness::*;
use serde_json::json;
use sha2::{Digest, Sha512};
use uuid::Uuid;

fn point(label: &[u8]) -> [u8; 32] {
    let h: [u8; 64] = Sha512::digest(label).into();
    RistrettoPoint::from_uniform_bytes(&h).compress().to_bytes()
}

/// Make a blob terminal with its object still stored and its GC grace over.
/// Chat never retires a bound blob today, so the fixture drops the binding
/// (as a future `chat.entries` horizon would) to reach a state chat's own
/// lifecycle checks accept.
async fn make_gc_due(env: &Env, blob: Uuid) {
    let mut tx = env.pool.begin().await.unwrap();
    sqlx::query("SET LOCAL session_replication_role = replica")
        .execute(&mut *tx)
        .await
        .unwrap();
    sqlx::query("DELETE FROM chat.blob_bindings WHERE blob_id = $1")
        .bind(blob)
        .execute(&mut *tx)
        .await
        .unwrap();
    tx.commit().await.unwrap();
    force_blob_state(env, blob, "expired").await;
    let mut tx = env.pool.begin().await.unwrap();
    sqlx::query("SET LOCAL session_replication_role = replica")
        .execute(&mut *tx)
        .await
        .unwrap();
    sqlx::query(
        "UPDATE chat.blobs SET object_gc_status = 'pending', \
           object_gc_after = clock_timestamp() - INTERVAL '1 hour' WHERE blob_id = $1",
    )
    .bind(blob)
    .execute(&mut *tx)
    .await
    .unwrap();
    tx.commit().await.unwrap();
}

/// `chat.claim_blob_object_gc` over the fixture rows. The fixture's blob
/// rows skip upload tickets, so chat's deferred ticket-lifecycle triggers
/// are suspended for this transaction; the claim logic itself runs as is.
async fn claim(env: &Env) -> Vec<Uuid> {
    let mut tx = env.pool.begin().await.unwrap();
    sqlx::query("SET LOCAL session_replication_role = replica")
        .execute(&mut *tx)
        .await
        .unwrap();
    let reclaimed = sqlx::query_scalar("SELECT blob_id FROM chat.claim_blob_object_gc(100)")
        .fetch_all(&mut *tx)
        .await
        .unwrap();
    tx.commit().await.unwrap();
    reclaimed
}

async fn gc_status(env: &Env, blob: Uuid) -> String {
    sqlx::query_scalar("SELECT object_gc_status FROM chat.blobs WHERE blob_id = $1")
        .bind(blob)
        .fetch_one(&env.pool)
        .await
        .unwrap()
}

#[tokio::test]
async fn referenced_blobs_survive_object_gc_until_the_reference_is_deleted() {
    let object = TestObject {
        key: "bafy-gc-pin".to_owned(),
        data: vec![0x44; 40],
    };
    let env = Env::with(true, Some(&object)).await;
    let alice = env.account().await;
    let thread = seed_conversation(
        &env,
        &[Leaf { device: &alice, joined_seq: 1, removed_seq: None }],
        10,
    )
    .await;
    grant_interval(&env, thread, &alice, 1, None).await;
    let (pinned, message) = seed_bound_attachment(&env, &alice, thread, &object, 5).await;
    let control_object = TestObject {
        key: "bafy-gc-control".to_owned(),
        data: object.data.clone(),
    };
    let (control, _) = seed_bound_attachment(&env, &alice, thread, &control_object, 6).await;

    let key = [0xC1; 32];
    alice
        .call("registerOrfState", &json!({ "deviceKeyPubkey": b(&key) }))
        .await
        .ok();
    alice
        .call(
            "putAttachmentRef",
            &json!({ "deviceKeyPubkey": b(&key), "blindedIndex": b(&point(b"i")),
                     "blindedTokenSalt": b(&point(b"t")), "blobId": pinned.to_string(),
                     "threadId": thread.to_string(), "messageId": message.to_string() }),
        )
        .await
        .ok();
    make_gc_due(&env, pinned).await;
    make_gc_due(&env, control).await;

    // The Rust worker claims only the unreferenced blob (positive control).
    let (claimed, _) = reclaim_due_blob_objects_recording(&env.pool, 100).await.unwrap();
    assert_eq!(claimed, 1, "only the unreferenced blob is due");
    // The SQL claim function reclaims the control and skips the pinned blob.
    let reclaimed = claim(&env).await;
    assert_eq!(reclaimed, vec![control]);
    assert_eq!(gc_status(&env, pinned).await, "pending");

    // Deleting the reference releases the pin.
    alice
        .call(
            "deleteAttachmentRef",
            &json!({ "deviceKeyPubkey": b(&key), "blindedIndex": b(&point(b"i")) }),
        )
        .await
        .ok();
    let (claimed, _) = reclaim_due_blob_objects_recording(&env.pool, 100).await.unwrap();
    assert_eq!(claimed, 1, "the released blob is due again");
    let reclaimed = claim(&env).await;
    assert_eq!(reclaimed, vec![pinned]);
    assert_eq!(gc_status(&env, pinned).await, "reclaimed");
}
