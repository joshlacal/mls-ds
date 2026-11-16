//! Real HTTP acceptance of the erasable Labyrinth recovery-share surface.
//!
//! Requires TEST_DATABASE_URL for disposable, migrated PostgreSQL databases.

mod common;
#[path = "common/labyrinth_harness.rs"]
mod harness;

use axum::{
    body::Body,
    http::{Request, StatusCode},
};
use catbird_server::labyrinth::recovery_crypto::{fetch_verifier, HPKE_INFO};
use harness::{b, send, unb, Device, Env, PREFIX};
use hpke_rs::{hpke_types::*, Hpke, Mode};
use hpke_rs_rust_crypto::HpkeRustCrypto;
use serde_json::{json, Value};
use uuid::Uuid;

async fn pending(env: &Env, device: &Device) {
    let mut tx = env.pool.begin().await.unwrap();
    sqlx::query("SET LOCAL session_replication_role = replica")
        .execute(&mut *tx)
        .await
        .unwrap();
    sqlx::query(
        "UPDATE chat.devices SET status='pending_approval' \
         WHERE user_did=$1 AND device_id=$2",
    )
    .bind(&device.did)
    .bind(device.device_id)
    .execute(&mut *tx)
    .await
    .unwrap();
    tx.commit().await.unwrap();
}

fn hpke_pair() -> (Hpke<HpkeRustCrypto>, hpke_rs::HpkePrivateKey, Vec<u8>) {
    let mut hpke = Hpke::<HpkeRustCrypto>::new(
        Mode::Base,
        KemAlgorithm::DhKem25519,
        KdfAlgorithm::HkdfSha256,
        AeadAlgorithm::Aes256Gcm,
    );
    let (sk, pk) = hpke.generate_key_pair().unwrap().into_keys();
    (hpke, sk, pk.as_slice().to_vec())
}

fn put_input(did: &str, vid: &[u8; 16], share: &[u8; 32], token: &[u8; 32]) -> Value {
    json!({
        "vdeviceId": b(vid),
        "share": b(share),
        "fetchVerifier": b(&fetch_verifier(did, vid, token)),
        "mechanism": "code",
    })
}

fn fetch_input(vid: &[u8; 16], token: &[u8; 32], public: &[u8], purpose: &str) -> Value {
    json!({
        "vdeviceId": b(vid),
        "fetchToken": b(token),
        "recipientPublicKey": b(public),
        "purpose": purpose,
    })
}

fn open(
    hpke: &Hpke<HpkeRustCrypto>,
    sk: &hpke_rs::HpkePrivateKey,
    did: &str,
    vid: &[u8; 16],
    reply: &Value,
) -> Vec<u8> {
    let mut aad = did.as_bytes().to_vec();
    aad.push(0);
    aad.extend_from_slice(vid);
    hpke.open(
        &unb(&reply["enc"]),
        sk,
        HPKE_INFO,
        &aad,
        &unb(&reply["sealedShare"]),
        None,
        None,
        None,
    )
    .unwrap()
}

async fn put_share(env: &Env) -> (Device, [u8; 16], [u8; 32], [u8; 32]) {
    let alice = env.account().await;
    let vid = [0x42; 16];
    let share = [0x17; 32];
    let token = [0x64; 32];
    let input = put_input(&alice.did, &vid, &share, &token);
    let first = alice.call("putRecoveryShare", &input).await;
    first.ok();
    let second = alice.call("putRecoveryShare", &input).await;
    assert_eq!(first.json, second.json, "same share is idempotent");
    (alice, vid, share, token)
}

#[tokio::test]
async fn capability_probe_fails_closed_without_kek_and_journal() {
    let env = Env::new().await;
    let caller = env.account().await;
    caller
        .query("getRecoveryShareCapabilities", &[])
        .await
        .fails(503, "ServiceUnavailable");
}

#[tokio::test]
async fn pending_fetch_is_hpke_sealed_and_did_scoped_without_operation_write() {
    let env = Env::recovery().await;
    let (alice, vid, share, token) = put_share(&env).await;
    let restoring = env.device_for(&alice.did, harness::random_seed()).await;
    pending(&env, &restoring).await;
    let bob = env.account().await;
    let capabilities = restoring.query("getRecoveryShareCapabilities", &[]).await;
    assert_eq!(
        capabilities.ok(),
        &json!({
            "supported": true,
            "version": 1,
            "hpkeSuite": "DHKEM_X25519_HKDF_SHA256_HKDF_SHA256_AES_256_GCM",
            "keyId": "test-key",
        })
    );
    let events_after_capability: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM labyrinth.recovery_share_events WHERE owner_did=$1",
    )
    .bind(&alice.did)
    .fetch_one(&env.pool)
    .await
    .unwrap();
    assert_eq!(events_after_capability, 1, "capability read has no event");

    let operations_before: i64 =
        sqlx::query_scalar("SELECT count(*) FROM labyrinth.operations WHERE owner_did=$1")
            .bind(&alice.did)
            .fetch_one(&env.pool)
            .await
            .unwrap();
    assert_eq!(
        operations_before, 2,
        "the capability read adds no operation"
    );
    let (hpke, sk, pk) = hpke_pair();
    let verified = alice
        .call(
            "getRecoveryShare",
            &fetch_input(&vid, &token, &pk, "verify"),
        )
        .await;
    assert_eq!(
        open(&hpke, &sk, &alice.did, &vid, verified.ok()),
        share.to_vec()
    );
    let input = fetch_input(&vid, &token, &pk, "restore");
    let fetched = restoring.call("getRecoveryShare", &input).await;
    let output = fetched.ok();
    assert_eq!(unb(&output["sealedShare"]).len(), 48);
    assert_eq!(open(&hpke, &sk, &alice.did, &vid, output), share.to_vec());
    assert!(!fetched
        .bytes
        .windows(share.len())
        .any(|window| window == share));
    let operations_after: i64 =
        sqlx::query_scalar("SELECT count(*) FROM labyrinth.operations WHERE owner_did=$1")
            .bind(&alice.did)
            .fetch_one(&env.pool)
            .await
            .unwrap();
    assert_eq!(operations_before, operations_after);

    // Even a valid account token for another DID cannot borrow Alice's chat
    // signature and device id to fetch her share.
    let nsid = format!("{PREFIX}getRecoveryShare");
    let body = serde_json::to_vec(&input).unwrap();
    let (write, signature) = alice.write_headers(&nsid, &body, *Uuid::new_v4().as_bytes());
    let wrong_issuer = Request::post(format!("/xrpc/{nsid}"))
        .header("content-type", "application/json")
        .header("authorization", format!("Bearer {}", bob.token(&nsid)))
        .header("catbird-labyrinth-write", write)
        .header("catbird-labyrinth-write-signature", signature)
        .body(Body::from(body))
        .unwrap();
    send(&env.router, wrong_issuer)
        .await
        .fails(401, "NotAuthorized");

    let wrong = [0x65; 32];
    restoring
        .call(
            "getRecoveryShare",
            &fetch_input(&vid, &wrong, &pk, "restore"),
        )
        .await
        .fails(404, "RecoveryShareUnavailable");
    restoring
        .call(
            "getRecoveryShare",
            &fetch_input(&[0x43; 16], &wrong, &pk, "restore"),
        )
        .await
        .fails(404, "RecoveryShareUnavailable");
    bob.call("getRecoveryShare", &input)
        .await
        .fails(404, "RecoveryShareUnavailable");
    restoring
        .call(
            "putRecoveryShare",
            &put_input(&alice.did, &[0x44; 16], &share, &token),
        )
        .await
        .fails(403, "ChatDeviceNotActive");
    restoring
        .call("deleteRecoveryShare", &json!({"vdeviceId": b(&vid)}))
        .await
        .fails(403, "ChatDeviceNotActive");
    restoring
        .query("listRecoveryShares", &[])
        .await
        .fails(403, "ChatDeviceNotActive");
    restoring
        .query("listRecoveryShareEvents", &[])
        .await
        .fails(403, "ChatDeviceNotActive");
    let listed = alice.query("listRecoveryShares", &[]).await;
    assert_eq!(listed.ok()["shares"].as_array().unwrap().len(), 1);
    assert_eq!(listed.json["shares"][0]["fetchCount"], 1);
    assert!(!listed
        .bytes
        .windows(share.len())
        .any(|window| window == share));
    let events = alice.query("listRecoveryShareEvents", &[]).await;
    let kinds: Vec<_> = events.ok()["events"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|event| event["kind"].as_str())
        .collect();
    assert!(kinds.contains(&"verify"));
    assert!(kinds.contains(&"fetch"));
}

#[tokio::test]
async fn revoked_chat_device_cannot_manage_shares() {
    let env = Env::recovery().await;
    let (alice, vid, share, token) = put_share(&env).await;
    env.revoke(&alice).await;
    alice
        .call(
            "putRecoveryShare",
            &put_input(&alice.did, &[0x44; 16], &share, &token),
        )
        .await
        .fails(401, "DeviceRevoked");
    alice
        .call("deleteRecoveryShare", &json!({"vdeviceId": b(&vid)}))
        .await
        .fails(401, "DeviceRevoked");
    alice
        .query("listRecoveryShares", &[])
        .await
        .fails(401, "DeviceRevoked");
    alice
        .query("listRecoveryShareEvents", &[])
        .await
        .fails(401, "DeviceRevoked");
}

#[tokio::test]
async fn thousand_bad_tokens_from_ghost_do_not_block_valid_fetch() {
    let env = Env::recovery().await;
    let (alice, vid, share, token) = put_share(&env).await;
    let ghost = env.device_for(&alice.did, harness::random_seed()).await;
    pending(&env, &ghost).await;
    let legitimate = env.device_for(&alice.did, harness::random_seed()).await;
    pending(&env, &legitimate).await;
    let (hpke, sk, pk) = hpke_pair();
    for attempt in 0_u32..1000 {
        let mut wrong = [0; 32];
        wrong[..4].copy_from_slice(&attempt.to_be_bytes());
        let response = ghost
            .call(
                "getRecoveryShare",
                &fetch_input(&vid, &wrong, &pk, "restore"),
            )
            .await;
        assert!(
            (response.status == StatusCode::NOT_FOUND
                && response.error() == "RecoveryShareUnavailable")
                || (response.status == StatusCode::TOO_MANY_REQUESTS
                    && response.error() == "RateLimited"),
            "unexpected bad-token response: {:?}",
            response
        );
    }
    let valid = legitimate
        .call(
            "getRecoveryShare",
            &fetch_input(&vid, &token, &pk, "restore"),
        )
        .await;
    assert_eq!(
        open(&hpke, &sk, &alice.did, &vid, valid.ok()),
        share.to_vec()
    );
    let operations: i64 =
        sqlx::query_scalar("SELECT count(*) FROM labyrinth.operations WHERE owner_did=$1")
            .bind(&alice.did)
            .fetch_one(&env.pool)
            .await
            .unwrap();
    assert_eq!(operations, 2, "only the two put operations are recorded");
}

#[tokio::test]
async fn deleting_erases_storage_and_replay_erases_restored_old_row() {
    let env = Env::recovery().await;
    let (alice, vid, share, token) = put_share(&env).await;
    let replay_op = [0x55; 16];
    let put_body = put_input(&alice.did, &vid, &share, &token);
    alice
        .call_op("putRecoveryShare", &put_body, replay_op)
        .await
        .ok();
    let (nonce, ciphertext, key_id, verifier): (
        Option<Vec<u8>>,
        Option<Vec<u8>>,
        Option<String>,
        Option<Vec<u8>>,
    ) = sqlx::query_as(
        "SELECT nonce, encrypted_share, kek_key_id, fetch_verifier \
         FROM labyrinth.recovery_shares \
         WHERE owner_did=$1 AND vdevice_id=$2",
    )
    .bind(&alice.did)
    .bind(vid.as_slice())
    .fetch_one(&env.pool)
    .await
    .unwrap();
    let deleted = alice
        .call("deleteRecoveryShare", &json!({"vdeviceId": b(&vid)}))
        .await;
    deleted.ok();
    let cleared: (
        Option<Vec<u8>>,
        Option<Vec<u8>>,
        Option<String>,
        Option<Vec<u8>>,
    ) = sqlx::query_as(
        "SELECT nonce, encrypted_share, kek_key_id, fetch_verifier \
         FROM labyrinth.recovery_shares \
         WHERE owner_did=$1 AND vdevice_id=$2",
    )
    .bind(&alice.did)
    .bind(vid.as_slice())
    .fetch_one(&env.pool)
    .await
    .unwrap();
    assert_eq!(cleared, (None, None, None, None));
    assert_eq!(
        alice.query("listRecoveryShares", &[]).await.ok()["shares"]
            .as_array()
            .unwrap()
            .len(),
        0
    );
    let (_, _, pk) = hpke_pair();
    alice
        .call(
            "getRecoveryShare",
            &fetch_input(&vid, &token, &pk, "restore"),
        )
        .await
        .fails(404, "RecoveryShareUnavailable");
    alice
        .call(
            "putRecoveryShare",
            &put_input(&alice.did, &vid, &share, &token),
        )
        .await
        .fails(409, "RecoveryShareConflict");
    alice
        .call_op("putRecoveryShare", &put_body, replay_op)
        .await
        .fails(409, "RecoveryShareConflict");

    // Simulate restoring a database snapshot taken before the deletion while
    // the independently mounted journal retains its synced tombstone.
    let mut tx = env.pool.begin().await.unwrap();
    sqlx::query("SET LOCAL session_replication_role = replica")
        .execute(&mut *tx)
        .await
        .unwrap();
    sqlx::query(
        "UPDATE labyrinth.recovery_shares \
         SET nonce=$3, encrypted_share=$4, kek_key_id=$5, fetch_verifier=$6, deleted_at=NULL \
         WHERE owner_did=$1 AND vdevice_id=$2",
    )
    .bind(&alice.did)
    .bind(vid.as_slice())
    .bind(nonce)
    .bind(ciphertext)
    .bind(key_id)
    .bind(verifier)
    .execute(&mut *tx)
    .await
    .unwrap();
    tx.commit().await.unwrap();
    let replayed = env
        .recovery_journal
        .as_ref()
        .unwrap()
        .replay(&env.pool)
        .await
        .unwrap();
    assert!(replayed >= 1);
    let cleared_again: (
        Option<Vec<u8>>,
        Option<Vec<u8>>,
        Option<String>,
        Option<Vec<u8>>,
    ) = sqlx::query_as(
        "SELECT nonce, encrypted_share, kek_key_id, fetch_verifier \
         FROM labyrinth.recovery_shares \
         WHERE owner_did=$1 AND vdevice_id=$2",
    )
    .bind(&alice.did)
    .bind(vid.as_slice())
    .fetch_one(&env.pool)
    .await
    .unwrap();
    assert_eq!(cleared_again, (None, None, None, None));
}

#[tokio::test]
async fn delete_account_data_purges_recovery_share() {
    let env = Env::recovery().await;
    let (alice, vid, _, token) = put_share(&env).await;
    alice.call("deleteAccountData", &json!({})).await.ok();
    let held: Option<Vec<u8>> = sqlx::query_scalar(
        "SELECT encrypted_share FROM labyrinth.recovery_shares \
         WHERE owner_did=$1 AND vdevice_id=$2",
    )
    .bind(&alice.did)
    .bind(vid.as_slice())
    .fetch_one(&env.pool)
    .await
    .unwrap();
    assert!(held.is_none());
    let (_, _, pk) = hpke_pair();
    alice
        .call(
            "getRecoveryShare",
            &fetch_input(&vid, &token, &pk, "restore"),
        )
        .await
        .fails(404, "RecoveryShareUnavailable");
}
