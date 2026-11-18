//! Remote transport pruning regression; mounted only by the library test crate
//! because it uses lib-only fixtures (`chat_protocol::test_support`).

use super::delivery::*;
use super::expiry_sweep::prune_expired_application_payloads;
use crate::chat_protocol::test_support::{
    seed_remote_group_application_routing_fixture, ApplicationRoutingFixture,
};
use chrono::{Duration, Utc};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::future::Future;
use uuid::Uuid;

/// Genuine signed requests keep the NUL-terminated signature domain that
/// PostgreSQL JSON rejects; every fixture below must carry it.
fn has_nul_domain(bytes: &[u8]) -> bool {
    bytes.windows(6).any(|window| window == b"\\u0000")
}

fn remote_application_entry(
    fixture: &ApplicationRoutingFixture,
    received_at: chrono::DateTime<Utc>,
) -> Value {
    json!({
        "$type": APPLICATION_ENTRY_KIND,
        "entryId": Uuid::new_v4(),
        "conversationId": fixture.conversation_id,
        "seq": 4,
        "receivedAt": received_at.to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
        "signedRequest": fixture.signed_request,
    })
}

fn pruned_projection(entry: &Value) -> Value {
    json!({
        "$type": APPLICATION_ENTRY_KIND,
        "conversationId": entry["conversationId"],
        "entryId": entry["entryId"],
        "seq": entry["seq"],
        "receivedAt": entry["receivedAt"],
        "payloadPruned": true,
    })
}

#[derive(Debug, PartialEq, sqlx::FromRow)]
struct TransportRow {
    entry_bytes: Vec<u8>,
    original_entry_sha256: Vec<u8>,
    application_message_id: Option<Uuid>,
    application_request_sha256: Option<Vec<u8>>,
    application_metadata_bytes: Option<Vec<u8>>,
    application_generation: Option<i64>,
    evidence_pending: bool,
    pruned: bool,
}

async fn transport_row(pool: &sqlx::PgPool, conversation_id: Uuid) -> TransportRow {
    sqlx::query_as(
        "SELECT entry_bytes, original_entry_sha256, application_message_id, \
                application_request_sha256, application_metadata_bytes, application_generation, \
                evidence_pending, payload_pruned_at IS NOT NULL AS pruned \
           FROM chat.direct_request_transport_entries WHERE conversation_id = $1 AND seq = 4",
    )
    .bind(conversation_id)
    .fetch_one(pool)
    .await
    .unwrap()
}

fn assert_application_evidence(
    row: &TransportRow,
    fixture: &ApplicationRoutingFixture,
    original: &[u8],
) {
    let mut metadata = fixture.signed_request.clone();
    metadata["body"]["applicationMessage"]
        .as_object_mut()
        .unwrap()
        .remove("bytes");
    assert_eq!(row.original_entry_sha256, Sha256::digest(original).to_vec());
    assert_eq!(row.application_message_id, Some(fixture.message_id));
    assert_eq!(
        row.application_request_sha256,
        Some(Sha256::digest(serde_json::to_vec(&fixture.signed_request).unwrap()).to_vec())
    );
    assert_eq!(
        row.application_metadata_bytes
            .as_deref()
            .map(|bytes| serde_json::from_slice::<Value>(bytes).unwrap()),
        Some(metadata),
        "signed metadata, including the NUL-terminated domain, survives without ciphertext"
    );
    assert_eq!(
        row.application_generation,
        fixture
            .signed_request
            .pointer("/body/prior/generation")
            .and_then(Value::as_i64)
    );
}

/// This DS's identity in every test below.
const PRUNING_HOME: &str = "did:web:pruning-home.example.com";

#[cfg(feature = "sim")]
fn pruning_home_hooks(
    home: &str,
    retain_application_ciphertext: bool,
) -> std::sync::Arc<crate::sim_hooks::SimDsHooks> {
    home_hooks(
        home,
        retain_application_ciphertext,
        std::sync::Arc::new(|_| {
            Box::pin(async { Err("unexpected pruning network request".into()) })
        }),
    )
}

#[cfg(feature = "sim")]
fn home_hooks(
    home: &str,
    retain_application_ciphertext: bool,
    http_transport: crate::sim_hooks::SimHttpTransport,
) -> std::sync::Arc<crate::sim_hooks::SimDsHooks> {
    std::sync::Arc::new(crate::sim_hooks::SimDsHooks {
        service_did: home.to_owned(),
        self_endpoint: "https://pruning-home.example.com".into(),
        signing_key_pem: None,
        group_relay_hmac_secret: None,
        http_transport,
        dns_resolver: std::sync::Arc::new(|_| Err("unexpected pruning DNS".into())),
        retain_application_ciphertext,
    })
}

/// Answers `deliverGroupEntry` with `router` in the caller's task, so the
/// handler runs inside the caller's DS scope; every other request is refused.
#[cfg(feature = "sim")]
fn in_process_deliveries(router: axum::Router) -> crate::sim_hooks::SimHttpTransport {
    use tower_util::ServiceExt as _;
    std::sync::Arc::new(move |request: crate::sim_hooks::SimHttpRequest| {
        let router = router.clone();
        Box::pin(async move {
            if request.url.path() != "/xrpc/blue.catbird.mlsDS.deliverGroupEntry" {
                return Err("unexpected pruning network request".into());
            }
            let mut builder = axum::http::Request::builder()
                .method(request.method)
                .uri(request.url.path());
            for (name, value) in &request.headers {
                builder = builder.header(name, value);
            }
            let body = axum::body::Body::from(request.body);
            let response = router
                .oneshot(builder.body(body).map_err(|error| error.to_string())?)
                .await
                .map_err(|error| error.to_string())?;
            let status = response.status();
            let body = axum::body::to_bytes(response.into_body(), 1 << 20)
                .await
                .map_err(|error| error.to_string())?;
            http::Response::builder()
                .status(status)
                .body(body.to_vec())
                .map_err(|error| error.to_string())
        })
    })
}

#[cfg(feature = "sim")]
fn retaining_hooks(home: &str) -> std::sync::Arc<crate::sim_hooks::SimDsHooks> {
    pruning_home_hooks(home, true)
}

/// Production pruning matches transport rows against this DS's own identity
/// (`identity::service_did_base`). Run each test as an explicit home DS rather
/// than inheriting whatever `SERVICE_DID` the process environment holds.
#[cfg(feature = "sim")]
async fn as_pruning_home<F: Future>(test: F) -> F::Output {
    crate::sim_hooks::scope_sim_ds(pruning_home_hooks(PRUNING_HOME, false), test).await
}

/// Without `sim` the identity can only come from `SERVICE_DID`: pin the same
/// explicit home under the crate-wide env lock and restore the prior value.
#[cfg(not(feature = "sim"))]
async fn as_pruning_home<F: Future>(test: F) -> F::Output {
    struct Restore(Option<std::ffi::OsString>);
    impl Drop for Restore {
        fn drop(&mut self) {
            match self.0.take() {
                Some(value) => std::env::set_var("SERVICE_DID", value),
                None => std::env::remove_var("SERVICE_DID"),
            }
        }
    }
    let _env = crate::auth::federation_fixture_tests::TEST_ENV_LOCK
        .lock()
        .await;
    let _restore = Restore(std::env::var_os("SERVICE_DID"));
    std::env::set_var("SERVICE_DID", PRUNING_HOME);
    test.await
}

#[tokio::test]
async fn unacked_remote_transport_application_expires_at_the_30_day_ceiling() {
    as_pruning_home(unacked_transport_expires_at_the_ceiling_as_home()).await
}

async fn unacked_transport_expires_at_the_ceiling_as_home() {
    let db = crate::common::fresh_db::fresh_fully_migrated_db("chat_pruning_").await;
    let pool = db.connect(4).await;
    let home = crate::identity::service_did_base();
    let fixture = seed_remote_group_application_routing_fixture(
        &pool,
        &home,
        "did:web:ceiling-sequencer.example.com",
    )
    .await
    .unwrap();
    let conversation_id = fixture.conversation_id;
    let stored_at = Utc::now();
    let entry = remote_application_entry(&fixture, stored_at);
    let original = serde_json::to_vec(&entry).unwrap();
    assert!(has_nul_domain(&original));
    let entry_id = Uuid::parse_str(entry["entryId"].as_str().unwrap()).unwrap();
    let mut connection = pool.acquire().await.unwrap();
    assert_eq!(
        insert_transport_entry(
            &mut connection,
            conversation_id,
            4,
            entry_id,
            &original,
            stored_at
        )
        .await
        .unwrap(),
        TransportEntryInsert::Inserted
    );
    let stored = transport_row(&pool, conversation_id).await;
    assert_eq!(stored.entry_bytes, original);
    assert!(!stored.evidence_pending && !stored.pruned);
    assert_application_evidence(&stored, &fixture, &original);
    let acks: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM chat.device_entry_acks WHERE conversation_id = $1",
    )
    .bind(conversation_id)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(acks, 0, "no local device ever acknowledged the entry");

    let sweep =
        |days: i64| prune_expired_application_payloads(&pool, stored_at + Duration::days(days));
    assert_eq!(sweep(29).await.unwrap(), 0, "inside the 30-day ceiling");
    assert_eq!(transport_row(&pool, conversation_id).await, stored);
    #[cfg(feature = "sim")]
    {
        let retained = crate::sim_hooks::scope_sim_ds(retaining_hooks(&home), sweep(31))
            .await
            .unwrap();
        assert_eq!(retained, 0, "P8 cannot report fake pruning");
        assert_eq!(transport_row(&pool, conversation_id).await, stored);
    }
    assert_eq!(sweep(31).await.unwrap(), 1);
    let pruned = transport_row(&pool, conversation_id).await;
    assert!(pruned.pruned && !pruned.evidence_pending);
    assert_application_evidence(&pruned, &fixture, &original);
    assert_eq!(
        serde_json::from_slice::<Value>(&pruned.entry_bytes).unwrap(),
        pruned_projection(&entry)
    );

    // Late redelivery compares the retained digest and never restores ciphertext.
    assert_eq!(
        insert_transport_entry(
            &mut connection,
            conversation_id,
            4,
            entry_id,
            &original,
            stored_at
        )
        .await
        .unwrap(),
        TransportEntryInsert::Duplicate
    );
    let mut changed = entry.clone();
    changed["receivedAt"] = json!("2030-01-01T00:00:00.000Z");
    assert_eq!(
        insert_transport_entry(
            &mut connection,
            conversation_id,
            4,
            entry_id,
            &serde_json::to_vec(&changed).unwrap(),
            stored_at,
        )
        .await
        .unwrap(),
        TransportEntryInsert::Conflict
    );
    drop(connection);
    assert_eq!(transport_row(&pool, conversation_id).await, pruned);
    assert!(sqlx::query(
        "UPDATE chat.direct_request_transport_entries SET entry_bytes = $2, payload_pruned_at = NULL \
          WHERE conversation_id = $1 AND seq = 4",
    )
    .bind(conversation_id)
    .bind(&original)
    .execute(&pool)
    .await
    .is_err());
    assert_eq!(sweep(60).await.unwrap(), 0, "pruning happens once");
}

#[tokio::test]
async fn nul_signed_legacy_transport_rows_migrate_classify_and_expire() {
    as_pruning_home(nul_signed_legacy_transport_rows_as_home()).await
}

async fn nul_signed_legacy_transport_rows_as_home() {
    let home = crate::identity::service_did_base();
    let source_db = crate::common::fresh_db::fresh_fully_migrated_db("chat_pruning_").await;
    let source = source_db.connect(2).await;
    let fixture = seed_remote_group_application_routing_fixture(
        &source,
        &home,
        "did:web:legacy-sequencer.example.com",
    )
    .await
    .unwrap();
    let conversation_id = fixture.conversation_id;
    let stored_at = Utc::now();
    let entry = remote_application_entry(&fixture, stored_at);
    let original = serde_json::to_vec(&entry).unwrap();
    assert!(has_nul_domain(&original));
    let entry_id = Uuid::parse_str(entry["entryId"].as_str().unwrap()).unwrap();

    // A home that stored the row before migration 20261103000001 existed.
    let home_db = {
        let _lock = crate::common::fresh_db::acquire_migration_lock().await;
        let db = crate::common::fresh_db::DisposableDatabase::mint("chat_pruning_").await;
        let pool = db.connect(1).await;
        let mut connection = pool.acquire().await.unwrap();
        sqlx::query(
            "SET chat.operation_claim_activation_approved = 'handlers-and-legacy-apis-sealed'",
        )
        .execute(&mut *connection)
        .await
        .unwrap();
        let all = sqlx::migrate!("./migrations");
        let earlier = sqlx::migrate::Migrator {
            migrations: all
                .iter()
                .filter(|migration| migration.version < 20261103000001)
                .cloned()
                .collect::<Vec<_>>()
                .into(),
            ..sqlx::migrate::Migrator::DEFAULT
        };
        earlier.run(&mut *connection).await.unwrap();
        sqlx::query(
            "INSERT INTO chat.direct_request_transport_entries \
             (conversation_id, seq, entry_id, entry_bytes, created_at) VALUES ($1, 4, $2, $3, $4)",
        )
        .bind(conversation_id)
        .bind(entry_id)
        .bind(&original)
        .bind(stored_at)
        .execute(&mut *connection)
        .await
        .unwrap();
        all.run(&mut *connection)
            .await
            .expect("the evidence migration never parses signed JSON");
        sqlx::query("RESET chat.operation_claim_activation_approved")
            .execute(&mut *connection)
            .await
            .unwrap();
        drop(connection);
        pool.close().await;
        db
    };
    let pool = home_db.connect(4).await;
    let legacy = transport_row(&pool, conversation_id).await;
    assert!(legacy.evidence_pending && !legacy.pruned);
    assert_eq!(legacy.entry_bytes, original);
    assert_eq!(
        legacy.original_entry_sha256,
        Sha256::digest(&original).to_vec()
    );
    assert_eq!(legacy.application_message_id, None);

    let sweep =
        |days: i64| prune_expired_application_payloads(&pool, stored_at + Duration::days(days));
    assert_eq!(
        sweep(29).await.unwrap(),
        0,
        "classified, still inside the 30-day ceiling"
    );
    let classified = transport_row(&pool, conversation_id).await;
    assert!(!classified.evidence_pending && !classified.pruned);
    assert_eq!(classified.entry_bytes, original);
    assert_application_evidence(&classified, &fixture, &original);
    assert!(sqlx::query(
        "UPDATE chat.direct_request_transport_entries \
            SET application_generation = application_generation + 1 \
          WHERE conversation_id = $1 AND seq = 4",
    )
    .bind(conversation_id)
    .execute(&pool)
    .await
    .is_err());

    assert_eq!(sweep(31).await.unwrap(), 1);
    let pruned = transport_row(&pool, conversation_id).await;
    assert!(pruned.pruned);
    assert_application_evidence(&pruned, &fixture, &original);
    assert_eq!(
        serde_json::from_slice::<Value>(&pruned.entry_bytes).unwrap(),
        pruned_projection(&entry)
    );
}

#[tokio::test]
async fn remote_group_transport_waits_for_sequencer_notice_after_all_local_acks() {
    as_pruning_home(remote_group_transport_waits_for_local_acks_as_home()).await
}

async fn remote_group_transport_waits_for_local_acks_as_home() {
    crate::federation::open_federation_for_test();
    let db = crate::common::fresh_db::fresh_fully_migrated_db("chat_pruning_").await;
    let pool = db.connect(4).await;
    let home = crate::identity::service_did_base();
    let fixture =
        crate::chat_protocol::test_support::seed_remote_group_application_routing_fixture(
            &pool,
            &home,
            "did:web:pruning-sequencer.example.com",
        )
        .await
        .unwrap();
    let audience: Vec<(String, Uuid)> = sqlx::query_as(
        "SELECT m.user_did, m.device_id FROM chat.member_devices m \
          JOIN chat.participants p USING (conversation_id, user_did) \
         WHERE m.conversation_id = $1 AND m.active \
           AND p.current_membership AND (p.ds_did IS NULL OR p.ds_did = $2) \
         ORDER BY m.user_did, m.device_id",
    )
    .bind(fixture.conversation_id)
    .bind(&home)
    .fetch_all(&pool)
    .await
    .unwrap();
    assert_eq!(audience.len(), 2);
    let entry_id = Uuid::new_v4();
    let now = Utc::now();
    let entry = json!({
        "$type": APPLICATION_ENTRY_KIND,
        "entryId": entry_id,
        "conversationId": fixture.conversation_id,
        "seq": 4,
        "receivedAt": now.to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
        "signedRequest": fixture.signed_request,
    });
    let original = serde_json::to_vec(&entry).unwrap();
    // A bootstrap mirror can also retain the same application in its local
    // append log. Freeze genuine verified bytes there, not a synthetic hash.
    let signed_bytes = serde_json::to_vec(&entry["signedRequest"]).unwrap();
    let key: Vec<u8> = sqlx::query_scalar(
        "SELECT signing_public_key FROM chat.device_keys \
          WHERE user_did = $1 AND device_id = $2 AND key_id = $3",
    )
    .bind(&fixture.sender_did)
    .bind(fixture.sender_device_id)
    .bind(entry["signedRequest"]["body"]["keyId"].as_str().unwrap())
    .fetch_one(&pool)
    .await
    .unwrap();
    let verified =
        crate::chat_protocol::transcript::decode_and_verify_signed_mutation(&signed_bytes, &key)
            .unwrap();
    let instant =
        crate::chat_protocol::validation::TrustedRequestInstant::from_datetime(now).unwrap();
    let product = crate::chat_protocol::transcript::build_verified_application_entry(
        verified,
        crate::chat_protocol::validation::CanonicalUuidV4::parse(&entry_id.to_string()).unwrap(),
        crate::chat_protocol::validation::CanonicalUuidV4::parse(
            &fixture.conversation_id.to_string(),
        )
        .unwrap(),
        4,
        &instant,
    )
    .unwrap();
    let mut mirror = pool.begin().await.unwrap();
    let outcome = resolve_application_send(
        &mut mirror,
        &ApplicationSend {
            entry: AppendEntry {
                conversation_id: fixture.conversation_id,
                entry_id,
                entry_kind: APPLICATION_ENTRY_KIND.into(),
                accepted_payload_bytes: product.canonical_entry_bytes().to_vec(),
                accepted_payload_sha256: product.accepted_payload_sha256().to_vec(),
                signed_request_bytes: signed_bytes,
                request_digest: product.mutation().request_digest().to_vec(),
                signature: product.mutation().signature().to_vec(),
                server_fields_bytes: serde_ipld_dagcbor::to_vec(&std::collections::BTreeMap::<
                    String,
                    String,
                >::new())
                .unwrap(),
                outer_entry_fingerprint: product.outer_application_fingerprint().to_vec(),
                actor_did: fixture.sender_did.clone(),
                actor_device_id: fixture.sender_device_id,
                actor_key_id: entry["signedRequest"]["body"]["keyId"]
                    .as_str()
                    .unwrap()
                    .into(),
                actor_auth_generation: 1,
                generation: Some(0),
                state_version: Some(2),
                transition_id: None,
                message_id: Some(fixture.message_id),
                received_at: instant.datetime(),
            },
            signing_transcript_bytes: product.mutation().transcript_bytes().to_vec(),
            outcome_bytes: serde_json::to_vec(&json!({"entry": entry})).unwrap(),
            epoch: 0,
            send_counter: 1,
        },
        ApplicationSendDisposition::Accept,
    )
    .await
    .unwrap();
    assert_eq!(outcome, ApplicationSendOutcome::Accepted { seq: 4 });
    mirror.commit().await.unwrap();
    assert!(has_nul_domain(&original));
    assert_eq!(
        insert_transport_entry(
            &mut pool.acquire().await.unwrap(),
            fixture.conversation_id,
            4,
            entry_id,
            &original,
            now,
        )
        .await
        .unwrap(),
        TransportEntryInsert::Inserted
    );
    for (did, device) in &audience {
        sqlx::query(
            "INSERT INTO chat.group_transport_entry_recipients \
             (conversation_id, seq, user_did, device_id) VALUES ($1, 4, $2, $3)",
        )
        .bind(fixture.conversation_id)
        .bind(did)
        .bind(device)
        .execute(&pool)
        .await
        .unwrap();
    }
    sqlx::query(
        "UPDATE chat.devices d SET dormant_at = $2 \
          WHERE EXISTS ( \
            SELECT 1 FROM chat.group_transport_entry_recipients r \
             WHERE r.conversation_id = $1 AND r.seq = 4 \
               AND r.user_did <> $3 \
               AND r.user_did = d.user_did AND r.device_id = d.device_id)",
    )
    .bind(fixture.conversation_id)
    .bind(now)
    .bind(&fixture.sender_did)
    .execute(&pool)
    .await
    .unwrap();
    let mut dormant_tx = pool.begin().await.unwrap();
    assert!(
        prune_acknowledged_application_payloads(
            &mut dormant_tx,
            fixture.conversation_id,
            0,
            4,
            true,
            now + chrono::Duration::hours(73),
        )
        .await
        .unwrap()
        .is_empty(),
        "a dormant non-sender mirror participant must not become a vacuous quorum"
    );
    dormant_tx.commit().await.unwrap();
    sqlx::query(
        "UPDATE chat.devices d SET dormant_at = NULL \
          WHERE EXISTS ( \
            SELECT 1 FROM chat.group_transport_entry_recipients r \
             WHERE r.conversation_id = $1 AND r.seq = 4 \
               AND r.user_did <> $2 \
               AND r.user_did = d.user_did AND r.device_id = d.device_id)",
    )
    .bind(fixture.conversation_id)
    .bind(&fixture.sender_did)
    .execute(&pool)
    .await
    .unwrap();
    for (index, (did, device)) in audience.iter().enumerate() {
        let mut tx = pool.begin().await.unwrap();
        sqlx::query(
            "INSERT INTO chat.device_entry_acks \
             (conversation_id, user_did, device_id, acked_through_seq, updated_at) \
             VALUES ($1, $2, $3, 4, $4)",
        )
        .bind(fixture.conversation_id)
        .bind(did)
        .bind(device)
        .bind(now)
        .execute(&mut *tx)
        .await
        .unwrap();
        #[cfg(feature = "sim")]
        if index == 1 {
            let hooks = retaining_hooks(&home);
            let retained = crate::sim_hooks::scope_sim_ds(
                hooks,
                prune_acknowledged_application_payloads(
                    &mut tx,
                    fixture.conversation_id,
                    0,
                    4,
                    true,
                    now + chrono::Duration::hours(73),
                ),
            )
            .await
            .unwrap();
            assert!(retained.is_empty(), "P8 cannot report fake pruning");
            let (acks, still_retained, local_retained): (i64, bool, bool) = sqlx::query_as(
                "SELECT (SELECT COUNT(*) FROM chat.device_entry_acks WHERE conversation_id = $1), \
                        EXISTS(SELECT 1 FROM chat.direct_request_transport_entries \
                                WHERE conversation_id = $1 AND seq = 4 \
                                  AND entry_bytes = $2 AND payload_pruned_at IS NULL), \
                        EXISTS(SELECT 1 FROM chat.entries \
                                WHERE conversation_id = $1 AND seq = 4 \
                                  AND accepted_payload_bytes IS NOT NULL \
                                  AND signed_request_bytes IS NOT NULL AND payload_pruned_at IS NULL)",
            )
            .bind(fixture.conversation_id)
            .bind(&original)
            .fetch_one(&mut *tx)
            .await
            .unwrap();
            assert_eq!(acks, 2, "P8 must not bypass durable ACK accounting");
            assert!(still_retained);
            assert!(local_retained, "P8 must retain both ciphertext copies");
        }
        let pruned = prune_acknowledged_application_payloads(
            &mut tx,
            fixture.conversation_id,
            0,
            4,
            true,
            now + chrono::Duration::hours(73),
        )
        .await
        .unwrap();
        assert!(
            pruned.is_empty(),
            "local ACKs cannot prove the global recipient quorum"
        );
        let local_pruned: bool = sqlx::query_scalar(
            "SELECT payload_pruned_at IS NOT NULL AND accepted_payload_bytes IS NULL \
                    AND signed_request_bytes IS NULL \
               FROM chat.entries WHERE conversation_id = $1 AND seq = 4",
        )
        .bind(fixture.conversation_id)
        .fetch_one(&mut *tx)
        .await
        .unwrap();
        assert!(
            !local_pruned,
            "the mirrored append log must wait for a sequencer notice"
        );
        tx.commit().await.unwrap();
    }
    let mut notice = pool.begin().await.unwrap();
    let erased = prune_transport_payloads_pruned_by_sequencer(
        &mut notice,
        fixture.conversation_id,
        0,
        &[4],
        now + chrono::Duration::hours(73),
    )
    .await
    .unwrap();
    assert_eq!(erased, vec![4]);
    notice.commit().await.unwrap();
    let (bytes, digest, metadata, pruned): (Vec<u8>, Vec<u8>, Vec<u8>, bool) = sqlx::query_as(
        "SELECT entry_bytes, original_entry_sha256, application_metadata_bytes, \
                payload_pruned_at IS NOT NULL \
           FROM chat.direct_request_transport_entries WHERE conversation_id = $1 AND seq = 4",
    )
    .bind(fixture.conversation_id)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert!(pruned);
    assert_eq!(digest, Sha256::digest(&original).to_vec());
    let projection: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(projection["payloadPruned"], true);
    assert_eq!(projection["seq"], 4);
    assert!(projection.get("signedRequest").is_none());
    let metadata: serde_json::Value = serde_json::from_slice(&metadata).unwrap();
    assert_eq!(metadata["signature"], entry["signedRequest"]["signature"]);
    assert_eq!(
        metadata["body"]["prior"],
        entry["signedRequest"]["body"]["prior"]
    );
    assert!(metadata.pointer("/body/applicationMessage/bytes").is_none());
    assert_eq!(
        metadata["body"]["applicationMessage"]["sha256"],
        entry["signedRequest"]["body"]["applicationMessage"]["sha256"]
    );
    use crate::federation::group_relay::{
        deliver_group_entry_to_remote_home, group_relay_router, DeliverGroupEntryRequest,
        GroupRelayState,
    };
    let secret = b"remote-pruning-delivery-regression";
    let state = GroupRelayState::for_test(pool.clone(), home.clone(), secret, None);
    let mut delivery = DeliverGroupEntryRequest {
        conversation_id: fixture.conversation_id,
        generation: 0,
        space_uri: format!(
            "at://did:web:pruning-sequencer.example.com/space/blue.catbird.labyrinth.conversation/{}-0",
            fixture.conversation_id
        ),
        recipient_dids: audience.iter().map(|(did, _)| did.clone()).collect(),
        recipient_devices: audience,
        entry: entry.clone(),
        close_authority: None,
    };
    // Every S2S call passes the home's inbound peer policy.
    sqlx::query(
        "INSERT INTO federation_peers(ds_did,status) VALUES($1,'allow') \
         ON CONFLICT(ds_did) DO UPDATE SET status='allow'",
    )
    .bind("did:web:pruning-sequencer.example.com")
    .execute(&pool)
    .await
    .unwrap();
    let sequencer = "did:web:pruning-sequencer.example.com";
    let deliver_late_then_altered =
        |endpoint: String, home: String, mut delivery: DeliverGroupEntryRequest| async move {
            let late =
                deliver_group_entry_to_remote_home(&endpoint, sequencer, &home, secret, &delivery)
                    .await;
            delivery.entry["receivedAt"] = json!("2030-01-01T00:00:00.000Z");
            let altered =
                deliver_group_entry_to_remote_home(&endpoint, sequencer, &home, secret, &delivery)
                    .await;
            (late, altered)
        };
    // The home's real router answers in-process inside this home's DS scope, so
    // its handler runs as this home, never as an ambient `SERVICE_DID`.
    #[cfg(feature = "sim")]
    let (late, altered) = crate::sim_hooks::scope_sim_ds(
        home_hooks(
            &home,
            false,
            in_process_deliveries(group_relay_router(state)),
        ),
        deliver_late_then_altered(
            "https://pruning-home.example.com".into(),
            home.clone(),
            delivery,
        ),
    )
    .await;
    // Without `sim` the identity can only come from `SERVICE_DID`: a loopback
    // server answers as it.
    #[cfg(not(feature = "sim"))]
    let (late, altered) = {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let endpoint = format!("http://{}", listener.local_addr().unwrap());
        let server = tokio::spawn(async move {
            axum::serve(listener, group_relay_router(state))
                .await
                .unwrap();
        });
        let delivered = deliver_late_then_altered(endpoint, home.clone(), delivery).await;
        server.abort();
        delivered
    };
    late.expect("late exact delivery compares the immutable original digest");
    assert!(altered.is_err());
    let retained: Vec<u8> = sqlx::query_scalar(
        "SELECT entry_bytes FROM chat.direct_request_transport_entries \
          WHERE conversation_id = $1 AND seq = 4 AND payload_pruned_at IS NOT NULL",
    )
    .bind(fixture.conversation_id)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(
        retained, bytes,
        "late delivery must never restore ciphertext"
    );
    assert!(sqlx::query(
        "UPDATE chat.direct_request_transport_entries SET entry_bytes = $2, payload_pruned_at = NULL \
          WHERE conversation_id = $1 AND seq = 4",
    )
    .bind(fixture.conversation_id)
    .bind(&original)
    .execute(&pool)
    .await
    .is_err());
}
