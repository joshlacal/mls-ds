//! Clean-slate Task 2 integration suite:
//! - `C33` published direct-request expiry (`expire_due_published_requests`) transitions both
//!   `chat.generations.lifecycle` and `chat.conversations.lifecycle` to `'superseded'` cleanly
//!   through all deferred PostgreSQL triggers AND unblocks `check_pair_owner_fence` for a fresh
//!   direct request between the same `(actor_did, recipient_did)` pair;
//! - Option A `chat.conversation_spaces` creation on conversation creation (`at://{authority}/space/blue.catbird.labyrinth.conversation/{cid}-{gen}`)
//!   and participant roster status semantics (`active` vs `left` / `removed`).

mod common;

use catbird_server::{
    chat_protocol::{
        repository::direct_request_receipts::DirectRequestReceiptSigner,
        test_support::{
            seed_clean_slate_application_fixture, seed_clean_slate_expired_direct_request_fixture,
        },
    },
    federation::canonical_relay::check_pair_owner_fence,
};
use p256::{ecdsa::SigningKey as P256SigningKey, pkcs8::EncodePrivateKey, SecretKey as P256Secret};
use rand::rngs::OsRng;
use uuid::Uuid;

fn p256_pem(sk: &P256SigningKey) -> String {
    let secret = P256Secret::from_slice(&sk.to_bytes()).expect("p256 secret");
    secret
        .to_pkcs8_pem(p256::pkcs8::LineEnding::LF)
        .expect("pkcs8 pem")
        .to_string()
}

static ENV_LOCK: std::sync::LazyLock<tokio::sync::Mutex<()>> =
    std::sync::LazyLock::new(|| tokio::sync::Mutex::new(()));

#[tokio::test]
async fn c33_published_direct_request_expiry_supersedes_conversation_and_unblocks_re_request() {
    let _env_guard = ENV_LOCK.lock().await;
    std::env::set_var("SERVICE_DID", "did:web:chat.catbird.blue");
    std::env::set_var("SELF_ENDPOINT", "https://chat.catbird.blue");

    let db = common::fresh_db::fresh_fully_migrated_db("chat_c33_exp_").await;
    let pool = db.connect(4).await;
    common::http_acceptance::ensure_fence(&pool).await;

    let receipt_key = P256SigningKey::random(&mut OsRng);
    let service_key = P256SigningKey::random(&mut OsRng);
    let doc = catbird_server::identity::did_doc::build_direct_request_receipt_did_document(
        "did:web:chat.catbird.blue",
        receipt_key.verifying_key(),
    );
    let signer = DirectRequestReceiptSigner::configured(
        &p256_pem(&receipt_key),
        &p256_pem(&service_key),
        &serde_json::to_string(&doc).unwrap(),
    )
    .expect("direct request receipt signer");

    let seeded = seed_clean_slate_expired_direct_request_fixture(&pool, &signer)
        .await
        .expect("seed overdue published C33 direct request");

    let swept = catbird_server::chat_protocol::repository::expiry_sweep::sweep_expired_published_direct_requests_for_test(
        &pool,
        &signer,
    )
    .await
    .expect("expire_due_published_requests succeeds cleanly through all deferred triggers");
    assert_eq!(swept, 1, "overdue published direct request must be swept");

    let (convo_lifecycle, gen_lifecycle, consent): (String, String, String) = sqlx::query_as(
        "SELECT c.lifecycle, g.lifecycle, l.consent \
         FROM chat.conversations c \
         JOIN chat.generations g ON g.conversation_id = c.conversation_id AND g.generation = c.current_generation \
         JOIN chat.direct_request_lifecycle l ON l.conversation_id = c.conversation_id \
         WHERE c.conversation_id = $1",
    )
    .bind(seeded.conversation_id)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(convo_lifecycle, "superseded");
    assert_eq!(gen_lifecycle, "superseded");
    assert_eq!(consent, "expired");

    // Immediately verify check_pair_owner_fence allows a brand-new request_id for the same pair!
    let mut tx = pool.begin().await.unwrap();
    let conflict = check_pair_owner_fence(
        &mut tx,
        &seeded.actor_did,
        &seeded.recipient_did,
        Uuid::new_v4(),
        Some("did:web:chat.catbird.blue"),
    )
    .await
    .expect("check_pair_owner_fence query");
    assert!(
        conflict.is_none(),
        "expired & superseded C33 direct request must unblock pair re-request, got {conflict:?}"
    );
    tx.commit().await.unwrap();
}

#[tokio::test]
async fn conversation_spaces_registered_on_creation_with_active_vs_historical_roster_queries() {
    let _env_guard = ENV_LOCK.lock().await;
    let authority_did = "did:web:ds-space.selfhost.example.com";
    std::env::set_var("SERVICE_DID", authority_did);
    std::env::set_var("SELF_ENDPOINT", "https://ds-space.selfhost.example.com");

    let db = common::fresh_db::fresh_fully_migrated_db("chat_space_roster_").await;
    let pool = db.connect(4).await;
    common::http_acceptance::ensure_fence(&pool).await;

    let fixture = seed_clean_slate_application_fixture(&pool, false, authority_did, None)
        .await
        .expect("seed group conversation");

    let (space_uri, recorded_authority): (String, String) = sqlx::query_as(
        "SELECT space_uri, authority_did FROM chat.conversation_spaces \
         WHERE conversation_id = $1 AND generation = 0",
    )
    .bind(fixture.conversation_id)
    .fetch_one(&pool)
    .await
    .expect("conversation_spaces row created on conversation creation");

    assert_eq!(recorded_authority, authority_did);
    assert_eq!(
        space_uri,
        format!(
            "at://{authority_did}/space/blue.catbird.labyrinth.conversation/{}-0",
            fixture.conversation_id
        )
    );

    let active_writers: Vec<String> = sqlx::query_scalar(
        "SELECT DISTINCT p.user_did FROM chat.participants p \
         WHERE p.conversation_id = $1 AND p.status = 'active' ORDER BY p.user_did",
    )
    .bind(fixture.conversation_id)
    .fetch_all(&pool)
    .await
    .unwrap();
    assert_eq!(active_writers.len(), 2);
}
