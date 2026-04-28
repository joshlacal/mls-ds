//! Repository seam tests, exercised against the in-memory fakes.
//!
//! These prove the trait surface and idempotency contracts that the
//! Phase 2 Postgres impls also satisfy. Phase 4 actor tests will drive
//! actor logic through these same fakes.

use chrono::{TimeZone, Utc};

use crate::models::{CryptoSession, NewCryptoSession, NewDeliveryEvent};
use crate::repositories::fakes::{InMemoryCryptoSessionRepository, InMemoryDeliveryLogRepository};
use crate::repositories::{CryptoSessionRepository, DeliveryLogRepository};

fn sample_session(id: &str, convo_id: &str, mls_group_id: &str, generation: i32) -> CryptoSession {
    CryptoSession {
        id: id.to_string(),
        conversation_id: convo_id.to_string(),
        generation,
        mls_group_id: mls_group_id.to_string(),
        state: "active".to_string(),
        cipher_suite: Some("MLS_256_XWING_CHACHA20POLY1305_SHA256_Ed25519".to_string()),
        last_observed_epoch: 7,
        last_confirmation_tag: Some(b"tag-bytes".to_vec()),
        group_info: None,
        group_info_epoch: None,
        group_info_updated_at: None,
        created_by_did: Some("did:plc:alice".to_string()),
        created_at: Utc.with_ymd_and_hms(2026, 4, 1, 0, 0, 0).unwrap(),
        activated_at: None,
        superseded_at: None,
        supersedes_id: None,
    }
}

fn new_session(id: &str, convo_id: &str, mls_group_id: &str, generation: i32) -> NewCryptoSession {
    NewCryptoSession {
        id: id.to_string(),
        conversation_id: convo_id.to_string(),
        generation,
        mls_group_id: mls_group_id.to_string(),
        state: "active".to_string(),
        cipher_suite: None,
        last_observed_epoch: 0,
        last_confirmation_tag: None,
        group_info: None,
        group_info_epoch: None,
        created_by_did: None,
        supersedes_id: None,
    }
}

fn new_event(convo_id: &str, session_id: &str, idempotency_key: &str) -> NewDeliveryEvent {
    NewDeliveryEvent {
        id: String::new(),
        conversation_id: convo_id.to_string(),
        crypto_session_id: Some(session_id.to_string()),
        event_type: "message".to_string(),
        sender_did: Some("did:plc:alice".to_string()),
        sender_device_id: Some("device-1".to_string()),
        mls_group_id: Some(format!("mls-group-{convo_id}")),
        mls_epoch: Some(1),
        idempotency_key: Some(idempotency_key.to_string()),
        payload: None,
        payload_json: None,
        origin_service_did: None,
        home_service_did: None,
        remote_event_id: None,
        auth_issuer_did: None,
        received_via: None,
        federation_trace_id: None,
    }
}

#[tokio::test]
async fn fake_returns_active_session_by_conversation_id() {
    let repo = InMemoryCryptoSessionRepository::new();
    repo.insert(sample_session("session-1", "convo-1", "mls-group-1", 0));

    let got = repo
        .get_active("convo-1")
        .await
        .expect("get_active should succeed");
    let session = got.expect("active session present");

    assert_eq!(session.id, "session-1");
    assert_eq!(session.conversation_id, "convo-1");
    assert_eq!(session.mls_group_id, "mls-group-1");
    assert_eq!(session.last_observed_epoch, 7);
    assert_eq!(session.state, "active");
}

#[tokio::test]
async fn fake_returns_none_for_unknown_conversation() {
    let repo = InMemoryCryptoSessionRepository::new();
    let got = repo.get_active("does-not-exist").await.unwrap();
    assert!(got.is_none());
}

#[tokio::test]
async fn fake_lookup_by_mls_group_id() {
    let repo = InMemoryCryptoSessionRepository::new();
    repo.insert(sample_session("session-2", "convo-2", "mls-group-2", 0));

    let got = repo
        .get_by_mls_group_id("mls-group-2")
        .await
        .expect("lookup ok")
        .expect("session present");

    assert_eq!(got.id, "session-2");
}

#[tokio::test]
async fn create_then_mark_superseded_via_trait() {
    let repo = InMemoryCryptoSessionRepository::new();
    let s0 = repo
        .create(new_session("session-3", "convo-3", "mls-group-3", 0))
        .await
        .expect("create gen=0");
    let s1 = repo
        .create({
            let mut n = new_session("session-4", "convo-3", "mls-group-3-new", 1);
            n.supersedes_id = Some(s0.id.clone());
            n
        })
        .await
        .expect("create gen=1");

    repo.mark_superseded(&s0.id, &s1.id)
        .await
        .expect("mark superseded");

    // Calling mark_superseded again on the already-superseded row is a
    // no-op (idempotent contract).
    repo.mark_superseded(&s0.id, &s1.id)
        .await
        .expect("mark superseded idempotent");

    let active = repo
        .get_active("convo-3")
        .await
        .unwrap()
        .expect("convo has active session");
    assert_eq!(active.id, "session-4");
    assert_eq!(active.supersedes_id.as_deref(), Some("session-3"));
}

#[tokio::test]
async fn fake_create_via_trait_yields_active_session() {
    let repo = InMemoryCryptoSessionRepository::new();

    let created = repo
        .create(new_session("session-5", "convo-5", "mls-group-5", 0))
        .await
        .expect("create on fake should succeed");

    assert_eq!(created.id, "session-5");
    assert_eq!(created.state, "active");

    let active = repo.get_active("convo-5").await.unwrap().expect("present");
    assert_eq!(active.id, "session-5");
}

#[tokio::test]
async fn create_is_idempotent_on_conversation_generation_pair() {
    // Phase 2 contract: two CREATEs with the same (conversation_id, generation)
    // resolve to the same row. Mirrors the Postgres UNIQUE constraint and
    // the `INSERT ... ON CONFLICT ... DO UPDATE SET id = crypto_sessions.id
    // RETURNING *` upsert used by the Postgres impl.
    let repo = InMemoryCryptoSessionRepository::new();
    let first = repo
        .create(new_session("session-A", "convo-A", "mls-group-A", 0))
        .await
        .expect("first create");

    // Second insert with same (conversation_id, generation) but a different
    // id — should return the first row's id, not allocate a new one.
    let second = repo
        .create(new_session("session-A2", "convo-A", "mls-group-A-different", 0))
        .await
        .expect("second create");

    assert_eq!(first.id, second.id, "same (convo,gen) tuple => same id");
    assert_eq!(first.mls_group_id, second.mls_group_id);
}

#[tokio::test]
async fn fake_delivery_log_appends_with_monotonic_seq() {
    let log = InMemoryDeliveryLogRepository::new();

    let event_a = log
        .append(new_event("convo-1", "session-1", "idem-a"))
        .await
        .unwrap();

    let event_b = log
        .append(new_event("convo-1", "session-1", "idem-b"))
        .await
        .unwrap();

    assert_eq!(event_a.seq, 1);
    assert_eq!(event_b.seq, 2);

    let range = log.read_range_by_session("session-1", 0, 10).await.unwrap();
    assert_eq!(range.len(), 2);
    assert_eq!(range[0].idempotency_key.as_deref(), Some("idem-a"));
    assert_eq!(range[1].idempotency_key.as_deref(), Some("idem-b"));
}

#[tokio::test]
async fn delivery_log_append_is_idempotent_on_idempotency_key() {
    // Phase 2 contract: duplicate retries with the same idempotency_key
    // (and same sender_did + sender_device_id + conversation_id) return
    // the original row, never a duplicate. This is the property the
    // Postgres impl enforces via UNIQUE (conversation_id, sender_did,
    // sender_device_id, idempotency_key).
    let log = InMemoryDeliveryLogRepository::new();

    let first = log
        .append(new_event("convo-r", "session-r", "retry-key"))
        .await
        .unwrap();
    let second = log
        .append(new_event("convo-r", "session-r", "retry-key"))
        .await
        .unwrap();

    assert_eq!(
        first.id, second.id,
        "duplicate idempotency_key => same event id"
    );
    assert_eq!(
        first.seq, second.seq,
        "duplicate idempotency_key => same seq"
    );

    // Only one row should be visible in the range.
    let range = log.read_range_by_session("session-r", 0, 10).await.unwrap();
    assert_eq!(range.len(), 1);
}

#[tokio::test]
async fn delivery_log_seq_is_per_conversation() {
    // Two conversations should each get their own seq=1, seq=2 streams.
    let log = InMemoryDeliveryLogRepository::new();

    let a1 = log
        .append(new_event("convo-A", "session-A", "a1"))
        .await
        .unwrap();
    let b1 = log
        .append(new_event("convo-B", "session-B", "b1"))
        .await
        .unwrap();
    let a2 = log
        .append(new_event("convo-A", "session-A", "a2"))
        .await
        .unwrap();

    assert_eq!(a1.seq, 1);
    assert_eq!(b1.seq, 1);
    assert_eq!(a2.seq, 2);
}

#[tokio::test]
async fn delivery_log_read_range_respects_from_seq_and_limit() {
    let log = InMemoryDeliveryLogRepository::new();
    for n in 0..5 {
        log.append(new_event(
            "convo-range",
            "session-range",
            &format!("k-{n}"),
        ))
        .await
        .unwrap();
    }

    // Skip the first event by from_seq=2, limit to 2.
    let range = log
        .read_range_by_session("session-range", 2, 2)
        .await
        .unwrap();
    assert_eq!(range.len(), 2);
    assert_eq!(range[0].seq, 2);
    assert_eq!(range[1].seq, 3);
}
