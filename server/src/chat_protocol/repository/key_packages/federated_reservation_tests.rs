//! GET `fetchKeyPackage` reservation regression on the fully migrated schema;
//! mounted only by the library test crate because it uses genuine KeyPackages.

use super::key_packages::{
    reserve_federated_key_package, reserve_federated_key_package_with_clock,
    reserve_locked_federated_key_package,
};
use crate::common::executor_seed::{
    clock_now,
    genuine_terminal_fixture::{build_genuine_invitee_key_package, AcceptanceInvitee},
    seed_actor_at, seed_genuine_key_package_at,
};
use chrono::{DateTime, Duration, Utc};
use ed25519_dalek::SigningKey;
use sha2::{Digest, Sha256};
use sqlx::PgPool;
use uuid::Uuid;

const REQUESTER: &str = "did:web:fetching-ds.example.com";

// The revocation regression drives the HTTP harness, which needs test-support.
#[cfg_attr(not(feature = "test-support"), allow(dead_code))]
struct Owner {
    did: String,
    device_id: Uuid,
    key_id: String,
    signing_key: SigningKey,
    signing_public_key: Vec<u8>,
}

async fn seed_owner_with_packages(pool: &PgPool, count: usize) -> Owner {
    let now = clock_now(pool).await;
    let did = format!("did:web:kp-{}.example.com", Uuid::new_v4().simple());
    let device_id = Uuid::new_v4();
    let seed: [u8; 32] = Sha256::digest(Uuid::new_v4().as_bytes()).into();
    let signing_key = SigningKey::from_bytes(&seed);
    let signing_public_key = signing_key.verifying_key().to_bytes().to_vec();
    let key_id = seed_actor_at(pool, &did, device_id, &signing_public_key, now).await;
    for _ in 0..count {
        let invitee = AcceptanceInvitee {
            did: did.clone(),
            device_id,
            key_id: key_id.clone(),
            signing_key: signing_key.clone(),
            participant_period_id: Uuid::new_v4(),
        };
        let (reference, wrapper, not_before, not_after) = build_genuine_invitee_key_package(
            &invitee,
            now,
            now - Duration::hours(1),
            now + Duration::hours(1),
        );
        seed_genuine_key_package_at(
            pool, &did, device_id, &key_id, &reference, &wrapper, not_before, not_after, now,
        )
        .await;
    }
    Owner {
        did,
        device_id,
        key_id,
        signing_key,
        signing_public_key,
    }
}

async fn fetch(
    pool: PgPool,
    owner_did: String,
    signing_public_key: Vec<u8>,
    now: DateTime<Utc>,
) -> Result<Option<(Vec<u8>, Vec<u8>)>, sqlx::Error> {
    let mut tx = pool.begin().await?;
    let reserved =
        reserve_federated_key_package(&mut tx, &owner_did, REQUESTER, &[signing_public_key], now)
            .await?;
    tx.commit().await?;
    Ok(reserved)
}

/// (reserved, available, reservation rows) for one owner, read after commit.
async fn package_state(pool: &PgPool, owner_did: &str) -> (i64, i64, i64) {
    sqlx::query_as(
        "SELECT count(*) FILTER (WHERE p.status = 'reserved'), \
                count(*) FILTER (WHERE p.status = 'available'), \
                count(r.key_package_ref) \
           FROM chat.key_packages p \
           LEFT JOIN chat.federated_key_package_reservations r \
             ON r.key_package_ref = p.key_package_ref AND r.requester_ds_did = $2 \
          WHERE p.owner_did = $1",
    )
    .bind(owner_did)
    .bind(REQUESTER)
    .fetch_one(pool)
    .await
    .unwrap()
}

#[tokio::test]
async fn concurrent_federated_fetches_reserve_each_package_exactly_once() {
    let db = crate::common::fresh_db::fresh_fully_migrated_db("chat_kpfetch_").await;
    let pool = db.connect(10).await;
    let owner = seed_owner_with_packages(&pool, 3).await;
    let now = clock_now(&pool).await;
    let fetches: Vec<_> = (0..6)
        .map(|_| {
            tokio::spawn(fetch(
                pool.clone(),
                owner.did.clone(),
                owner.signing_public_key.clone(),
                now,
            ))
        })
        .collect();
    let mut claimed = Vec::new();
    for fetch in fetches {
        let reserved = fetch
            .await
            .unwrap()
            .expect("no fetch deadlocks or fails its deferred reservation mapping");
        if let Some((wrapper, sha256)) = reserved {
            assert_eq!(sha256, Sha256::digest(&wrapper).to_vec());
            claimed.push(wrapper);
        }
    }
    assert_eq!(claimed.len(), 3, "three packages, three winners");
    claimed.sort();
    claimed.dedup();
    assert_eq!(claimed.len(), 3, "no package is handed out twice");
    assert_eq!(
        package_state(&pool, &owner.did).await,
        (3, 0, 3),
        "every committed reservation is visible with its row"
    );
    assert!(
        fetch(
            pool.clone(),
            owner.did.clone(),
            owner.signing_public_key.clone(),
            now
        )
        .await
        .unwrap()
        .is_none(),
        "an exhausted owner yields no package"
    );
}

#[tokio::test]
async fn reservation_cas_uses_a_fresh_trusted_expiry_after_locking() {
    let db = crate::common::fresh_db::fresh_fully_migrated_db("chat_kpfetch_").await;
    let pool = db.connect(4).await;
    let owner = seed_owner_with_packages(&pool, 1).await;
    let selected_at = clock_now(&pool).await;
    let mut tx = pool.begin().await.unwrap();
    let reserved = reserve_federated_key_package_with_clock(
        &mut tx,
        &owner.did,
        REQUESTER,
        std::slice::from_ref(&owner.signing_public_key),
        selected_at,
        || selected_at + Duration::hours(2),
    )
    .await
    .unwrap();
    assert!(
        reserved.is_none(),
        "a package that expires after selection is not reserved"
    );
    tx.commit().await.unwrap();
    assert_eq!(package_state(&pool, &owner.did).await, (0, 1, 0));
}

#[tokio::test]
async fn reservation_cas_rechecks_an_export_lease_after_candidate_selection() {
    let db = crate::common::fresh_db::fresh_fully_migrated_db("chat_kpfetch_").await;
    let pool = db.connect(4).await;
    let owner = seed_owner_with_packages(&pool, 1).await;
    let selected_at = clock_now(&pool).await;
    let key_package_ref: Vec<u8> =
        sqlx::query_scalar("SELECT key_package_ref FROM chat.key_packages WHERE owner_did=$1")
            .bind(&owner.did)
            .fetch_one(&pool)
            .await
            .unwrap();
    let conversation_id =
        crate::chat_protocol::test_support::seed_clean_slate_application_fixture_unsealed(
            &pool,
            false,
            "did:web:key-package-recipient.example.com",
            Some([0x67; 32]),
            None,
        )
        .await
        .unwrap()
        .conversation_id;
    sqlx::query(
        "INSERT INTO chat.group_key_package_exports(\
             key_package_ref,conversation_id,recovery_request_id,sequencer_did,expires_at\
         ) VALUES($1,$2,$3,'did:web:sequencer.example.com',$4)",
    )
    .bind(&key_package_ref)
    .bind(conversation_id)
    .bind(Uuid::new_v4())
    .bind(selected_at - Duration::seconds(1))
    .execute(&pool)
    .await
    .unwrap();

    let mut tx = pool.begin().await.unwrap();
    let locked: Vec<u8> = sqlx::query_scalar(
        "SELECT p.key_package_ref FROM chat.key_packages p \
          WHERE p.key_package_ref=$1 AND p.status='available' \
            AND NOT EXISTS(SELECT 1 FROM chat.group_key_package_exports e \
                WHERE e.key_package_ref=p.key_package_ref AND e.expires_at>$2) \
          FOR UPDATE OF p",
    )
    .bind(&key_package_ref)
    .bind(selected_at)
    .fetch_one(&mut *tx)
    .await
    .expect("the expired lease is eligible at candidate selection");
    sqlx::query("UPDATE chat.group_key_package_exports SET expires_at=$2 WHERE key_package_ref=$1")
        .bind(&locked)
        .bind(selected_at + Duration::minutes(5))
        .execute(&mut *tx)
        .await
        .unwrap();
    let reserved = reserve_locked_federated_key_package(&mut tx, &locked, REQUESTER, selected_at)
        .await
        .unwrap();
    assert!(
        reserved.is_none(),
        "the fresh CAS sees a lease that became live after candidate selection"
    );
    tx.commit().await.unwrap();
    assert_eq!(package_state(&pool, &owner.did).await, (0, 1, 0));
}

#[tokio::test]
async fn federated_fetch_locks_principal_first_and_rolls_back_cleanly() {
    let db = crate::common::fresh_db::fresh_fully_migrated_db("chat_kpfetch_").await;
    let pool = db.connect(6).await;
    let owner = seed_owner_with_packages(&pool, 2).await;
    let now = clock_now(&pool).await;

    let mut rolled_back = pool.begin().await.unwrap();
    assert!(reserve_federated_key_package(
        &mut rolled_back,
        &owner.did,
        REQUESTER,
        std::slice::from_ref(&owner.signing_public_key),
        now,
    )
    .await
    .unwrap()
    .is_some());
    rolled_back.rollback().await.unwrap();
    assert_eq!(
        package_state(&pool, &owner.did).await,
        (0, 2, 0),
        "a rolled-back reservation leaves neither status nor row"
    );

    // Recovery and direct requests lock the principal, then packages, and block
    // on package locks. A fetch holding a package while it waits for the
    // principal (its deferred mapping takes it at commit) would deadlock here.
    let mut canonical = pool.begin().await.unwrap();
    sqlx::query("SELECT 1 FROM chat.principals WHERE user_did = $1 FOR UPDATE")
        .bind(&owner.did)
        .execute(&mut *canonical)
        .await
        .unwrap();
    let waiting = tokio::spawn(fetch(
        pool.clone(),
        owner.did.clone(),
        owner.signing_public_key.clone(),
        now,
    ));
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
    loop {
        let waiters: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM pg_stat_activity \
              WHERE datname = current_database() AND wait_event_type = 'Lock'",
        )
        .fetch_one(&pool)
        .await
        .unwrap();
        if waiters > 0 {
            break;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "the fetch never queued behind the principal"
        );
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }
    let locked: Vec<Vec<u8>> = sqlx::query_scalar(
        "SELECT key_package_ref FROM chat.key_packages WHERE owner_did = $1 \
          ORDER BY key_package_ref FOR UPDATE",
    )
    .bind(&owner.did)
    .fetch_all(&mut *canonical)
    .await
    .expect("the waiting fetch holds no package lock");
    assert_eq!(locked.len(), 2);
    canonical.rollback().await.unwrap();
    assert!(waiting
        .await
        .unwrap()
        .expect("the fetch proceeds once the principal is free")
        .is_some());
    assert_eq!(package_state(&pool, &owner.did).await, (1, 1, 1));
}

/// A remote DS's GET fetch reserves a recovery package that names no
/// conversation; revoking its owner device must still retire it.
#[cfg(feature = "test-support")]
#[tokio::test]
async fn revoking_the_owner_device_revokes_its_federated_reserved_recovery_package() {
    use crate::common::http_acceptance as http;
    let db = crate::common::fresh_db::fresh_fully_migrated_db("chat_kpfetch_").await;
    let pool = db.connect(4).await;
    http::ensure_fence(&pool).await;
    let owner = seed_owner_with_packages(&pool, 1).await;
    let now = clock_now(&pool).await;
    assert!(fetch(
        pool.clone(),
        owner.did.clone(),
        owner.signing_public_key.clone(),
        now
    )
    .await
    .unwrap()
    .is_some());
    assert_eq!(package_state(&pool, &owner.did).await, (1, 0, 1));

    let auth_key = http::random_p256();
    let jwk = http::public_jwk(&auth_key);
    let device = http::Device {
        did: owner.did.clone(),
        device_id: owner.device_id,
        jkt: http::jwk_thumbprint(&jwk),
        signing: auth_key,
        jwk,
    };
    http::cache_device_did(&device).await;
    let revocation = serde_json::json!({
        "$type": "blue.catbird.chat.defs#deviceRevocationBody",
        "signatureDomain": "CATBIRD-CHAT-DEVICE-REVOKE\u{0000}",
        "idempotencyKey": Uuid::new_v4(),
        "actorDid": owner.did,
        "actorDeviceId": owner.device_id,
        "keyId": owner.key_id,
        "authGeneration": 1,
        "targetDeviceId": owner.device_id,
        "targetAuthGeneration": 1,
        "signedAt": Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
    });
    let signed = crate::chat_protocol::test_support::sign_mutation_json_for_test(
        &revocation,
        &owner.signing_key,
    )
    .unwrap();
    let (status, response) = http::send(
        http::router_for_authenticated_acceptance(pool.clone()).await,
        http::unsigned_json_request(
            &device,
            "blue.catbird.chat.revokeDevice",
            serde_json::to_vec(&serde_json::json!({ "signedRequest": signed })).unwrap(),
        ),
    )
    .await;
    assert_eq!(
        status,
        axum::http::StatusCode::OK,
        "revokeDevice with a federated reservation: {response}"
    );
    let statuses: Vec<String> =
        sqlx::query_scalar("SELECT status FROM chat.key_packages WHERE owner_did = $1")
            .bind(&owner.did)
            .fetch_all(&pool)
            .await
            .unwrap();
    assert_eq!(statuses, ["revoked"]);
}
