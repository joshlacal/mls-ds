#![cfg(feature = "test-support")]

//! Round-3 D1 control: group reset controls enter the same ordered remote-home stream.

mod common;

use std::{collections::BTreeMap, sync::Arc};

use axum::http::StatusCode;
use base64::{engine::general_purpose::STANDARD, Engine as _};
use catbird_server::chat_protocol::{
    repository::remote_prefix::test_support::test_apply_remote_clean_prefix,
    test_support::{
        seed_clean_slate_application_fixture_with_sender_home, sign_mutation_json_for_test,
        sign_reset_activation_for_test, CleanSlateApplicationFixture,
    },
};
use catbird_server::federation::{
    bootstrap::{
        RemoteDigestAnchor, RemotePrefixApplyOutcome, RemotePrefixBootstrapSelector,
        VerifiedRemotePrefixAdmission,
    },
    group_relay::{
        deliver_group_entry_to_remote_home, group_relay_router, relay_group_mutation_to_sequencer,
        DeliverGroupEntryRequest, GroupRelayState, RelayGroupMutationRequest,
    },
    reconciliation::{RemoteEvent, StrictCleanRemoteEvent},
    resolver::{build_resolver_http_client, DsResolver, ValidatedRemoteDestination},
};
use catbird_server::handlers::ds::get_convo_digest::CleanConvoDigestHasher;
use chrono::{SecondsFormat, Utc};
use common::http_acceptance as http;
use ed25519_dalek::SigningKey;
use serde_json::{json, Value};
use sha2::Digest as _;
use sqlx::Row;
use tokio::net::TcpListener;
use uuid::Uuid;

const SEQUENCER: &str = "did:web:r3-reset-sequencer.example.com";
const REMOTE_HOME: &str = "did:web:r3-reset-home.example.com";

fn fixture_device(did: &str, device_id: Uuid) -> http::Device {
    let signing = http::random_p256();
    let jwk = http::public_jwk(&signing);
    http::Device {
        did: did.to_owned(),
        device_id,
        jkt: http::jwk_thumbprint(&jwk),
        signing,
        jwk,
    }
}

fn recovery_key_package(device_signing: &SigningKey, credential: &[u8]) -> (Vec<u8>, Vec<u8>) {
    use openmls::prelude::{tls_codec::Serialize as _, *};
    use openmls_basic_credential::SignatureKeyPair;
    use openmls_traits::OpenMlsProvider;

    let provider = openmls_libcrux_crypto::Provider::new().unwrap();
    let ciphersuite = Ciphersuite::MLS_256_XWING_CHACHA20POLY1305_SHA256_Ed25519;
    let signer = SignatureKeyPair::from_raw(
        ciphersuite.signature_algorithm(),
        device_signing.to_bytes().to_vec(),
        device_signing.verifying_key().to_bytes().to_vec(),
    );
    signer.store(provider.storage()).unwrap();
    let now = Utc::now().timestamp() as u64;
    let package = KeyPackage::builder()
        .key_package_lifetime(Lifetime::init(now - 300, now + 3_600))
        .leaf_node_capabilities(Capabilities::new(
            Some(&[ProtocolVersion::Mls10]),
            Some(&[ciphersuite]),
            Some(&[]),
            Some(&[]),
            Some(&[CredentialType::Basic]),
        ))
        .build(
            ciphersuite,
            &provider,
            &signer,
            CredentialWithKey {
                credential: BasicCredential::new(credential.to_vec()).into(),
                signature_key: signer.to_public_vec().into(),
            },
        )
        .unwrap();
    let wrapped = MlsMessageOut::from(package.key_package().clone())
        .tls_serialize_detached()
        .unwrap();
    let reference = package
        .key_package()
        .hash_ref(provider.crypto())
        .unwrap()
        .as_slice()
        .to_vec();
    (wrapped, reference)
}

async fn assert_remote_sequencing_unavailable(
    router: axum::Router,
    pool: &sqlx::PgPool,
    device: &http::Device,
    endpoint: &'static str,
    signed_request: Value,
    conversation_id: Uuid,
) {
    let before: (i64, i64, i64) = sqlx::query_as(
        "SELECT count(*), \
                count(*) FILTER (WHERE sequencer_receipt_bytes IS NOT NULL), \
                coalesce(max(seq),0) \
         FROM chat.entries WHERE conversation_id=$1",
    )
    .bind(conversation_id)
    .fetch_one(pool)
    .await
    .unwrap();
    let queued_before: i64 =
        sqlx::query_scalar("SELECT count(*) FROM outbound_queue WHERE convo_id=$1")
            .bind(conversation_id.to_string())
            .fetch_one(pool)
            .await
            .unwrap();

    let (status, response) = http::send_bytes(
        router,
        http::unsigned_json_request(
            device,
            endpoint,
            serde_json::to_vec(&json!({"signedRequest": signed_request})).unwrap(),
        ),
    )
    .await;
    let response: Value = serde_json::from_slice(&response).unwrap();
    assert_eq!(
        status,
        StatusCode::SERVICE_UNAVAILABLE,
        "{endpoint}: {response}"
    );
    assert!(
        response["error"]
            .as_str()
            .is_some_and(|code| code != "ProtocolUpgradeRequired"),
        "{endpoint}: declared retryable error required: {response}"
    );
    let after: (i64, i64, i64) = sqlx::query_as(
        "SELECT count(*), \
                count(*) FILTER (WHERE sequencer_receipt_bytes IS NOT NULL), \
                coalesce(max(seq),0) \
         FROM chat.entries WHERE conversation_id=$1",
    )
    .bind(conversation_id)
    .fetch_one(pool)
    .await
    .unwrap();
    let queued_after: i64 =
        sqlx::query_scalar("SELECT count(*) FROM outbound_queue WHERE convo_id=$1")
            .bind(conversation_id.to_string())
            .fetch_one(pool)
            .await
            .unwrap();
    assert_eq!(
        after, before,
        "{endpoint} must not sequence or receipt locally"
    );
    assert_eq!(
        queued_after, queued_before,
        "{endpoint} is retryable and must not be silently queued"
    );
}

async fn queued_group_entries(pool: &sqlx::PgPool, conversation_id: Uuid) -> Vec<Value> {
    let payloads: Vec<Vec<u8>> = sqlx::query_scalar(
        "SELECT payload FROM outbound_queue \
         WHERE convo_id=$1 AND target_ds_did=$2 \
           AND method='blue.catbird.mlsDS.deliverGroupEntry' \
         ORDER BY id",
    )
    .bind(conversation_id.to_string())
    .bind(REMOTE_HOME)
    .fetch_all(pool)
    .await
    .unwrap();
    payloads
        .into_iter()
        .map(|bytes| serde_json::from_slice(&bytes).unwrap())
        .collect()
}

fn lifecycle_entry(response: &Value) -> Option<&Value> {
    response
        .get("entry")
        .or_else(|| response.pointer("/result/entry"))
}

async fn relay_lifecycle_and_deliver(
    router: axum::Router,
    device: &http::Device,
    endpoint: &'static str,
    signed_request: Value,
    sequencer: &sqlx::PgPool,
    home: &sqlx::PgPool,
    conversation_id: Uuid,
    home_endpoint: &str,
    secret: &[u8],
) -> (Vec<u8>, Value) {
    let home_before: (i64, i64, i64) = sqlx::query_as(
        "SELECT count(*), coalesce(max(seq),0), \
                count(*) FILTER (WHERE sequencer_receipt_bytes IS NOT NULL) \
         FROM chat.entries WHERE conversation_id=$1",
    )
    .bind(conversation_id)
    .fetch_one(home)
    .await
    .unwrap();
    let exact_signed_request = serde_json::to_vec(&signed_request).unwrap();
    let body = serde_json::to_vec(&json!({"signedRequest": signed_request})).unwrap();
    let (status, first) = http::send_bytes(
        router.clone(),
        http::unsigned_json_request(device, endpoint, body.clone()),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "{endpoint}: {}",
        String::from_utf8_lossy(&first)
    );
    let (replay_status, replay) =
        http::send_bytes(router, http::unsigned_json_request(device, endpoint, body)).await;
    assert_eq!(replay_status, StatusCode::OK, "{endpoint}");
    assert_eq!(replay, first, "{endpoint}: exact replay response bytes");
    let response: Value = serde_json::from_slice(&first).unwrap();
    let response_entry = lifecycle_entry(&response).cloned();
    let response_entry_id = response_entry
        .as_ref()
        .and_then(|entry| entry["entryId"].as_str())
        .and_then(|value| value.parse::<Uuid>().ok());
    let operation_id = serde_json::from_slice::<Value>(&exact_signed_request)
        .unwrap()
        .pointer("/body/idempotencyKey")
        .and_then(Value::as_str)
        .and_then(|value| value.parse::<Uuid>().ok())
        .unwrap();
    let delivery = match tokio::time::timeout(std::time::Duration::from_secs(5), async {
        loop {
            if let Some(delivery) = queued_group_entries(sequencer, conversation_id)
                .await
                .into_iter()
                .map(|value| serde_json::from_value(value).unwrap())
                .find(|delivery: &DeliverGroupEntryRequest| {
                    let delivered_entry_id = delivery.entry["entryId"]
                        .as_str()
                        .and_then(|value| value.parse::<Uuid>().ok());
                    response_entry_id
                        .map(|entry_id| delivered_entry_id == Some(entry_id))
                        .unwrap_or_else(|| {
                            delivery
                                .entry
                                .pointer("/signedRequest/body/idempotencyKey")
                                .and_then(Value::as_str)
                                .and_then(|value| value.parse::<Uuid>().ok())
                                == Some(operation_id)
                        })
                })
            {
                break delivery;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
    })
    .await
    {
        Ok(delivery) => delivery,
        Err(_) => panic!(
            "normal delivery queued the relayed entry; queued={:?}",
            queued_group_entries(sequencer, conversation_id).await
        ),
    };
    let entry_id: Uuid = delivery.entry["entryId"].as_str().unwrap().parse().unwrap();
    let entry = response_entry.unwrap_or_else(|| delivery.entry.clone());
    assert_eq!(
        entry["sequencerReceipt"]["sequencerDid"], SEQUENCER,
        "{endpoint}: sequencer signed"
    );
    let home_after: (i64, i64, i64) = sqlx::query_as(
        "SELECT count(*), coalesce(max(seq),0), \
                count(*) FILTER (WHERE sequencer_receipt_bytes IS NOT NULL) \
         FROM chat.entries WHERE conversation_id=$1",
    )
    .bind(conversation_id)
    .fetch_one(home)
    .await
    .unwrap();
    assert_eq!(
        home_after, home_before,
        "{endpoint}: home neither allocates a sequence nor signs"
    );
    assert_eq!(
        delivery.entry, entry,
        "{endpoint}: delivery carries sequencer entry"
    );
    deliver_group_entry_to_remote_home(home_endpoint, SEQUENCER, REMOTE_HOME, secret, &delivery)
        .await
        .expect("normal delivery reaches the mirror");
    let sequencer_material: (Vec<u8>, Vec<u8>) = sqlx::query_as(
        "SELECT signed_request_bytes,sequencer_receipt_bytes FROM chat.entries \
         WHERE conversation_id=$1 AND entry_id=$2",
    )
    .bind(conversation_id)
    .bind(entry_id)
    .fetch_one(sequencer)
    .await
    .unwrap();
    assert_eq!(
        sequencer_material.0.as_slice(),
        exact_signed_request.as_slice(),
        "{endpoint}: sequencer retained the exact member-signed bytes"
    );
    let mirrored_bytes: Vec<u8> = sqlx::query_scalar(
        "SELECT entry_bytes FROM chat.direct_request_transport_entries \
         WHERE conversation_id=$1 AND seq=$2",
    )
    .bind(conversation_id)
    .bind(entry["seq"].as_i64().unwrap())
    .fetch_one(home)
    .await
    .unwrap();
    let mirrored: Value = serde_json::from_slice(&mirrored_bytes).unwrap();
    assert_eq!(
        mirrored, entry,
        "{endpoint}: mirror retains the same signed request and I13 receipt"
    );
    (first, response)
}

async fn relay_entryless_lifecycle(
    router: axum::Router,
    device: &http::Device,
    endpoint: &'static str,
    signed_request: Value,
    operation_id: Uuid,
    sequencer: &sqlx::PgPool,
    home: &sqlx::PgPool,
    conversation_id: Uuid,
) -> Vec<u8> {
    let home_before: (i64, i64, i64) = sqlx::query_as(
        "SELECT count(*), coalesce(max(seq),0), \
                count(*) FILTER (WHERE sequencer_receipt_bytes IS NOT NULL) \
         FROM chat.entries WHERE conversation_id=$1",
    )
    .bind(conversation_id)
    .fetch_one(home)
    .await
    .unwrap();
    let body = serde_json::to_vec(&json!({"signedRequest": signed_request})).unwrap();
    let (status, first) = http::send_bytes(
        router.clone(),
        http::unsigned_json_request(device, endpoint, body.clone()),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "{endpoint}: {}",
        String::from_utf8_lossy(&first)
    );
    let (replay_status, replay) =
        http::send_bytes(router, http::unsigned_json_request(device, endpoint, body)).await;
    assert_eq!(replay_status, StatusCode::OK, "{endpoint}");
    assert_eq!(replay, first, "{endpoint}: exact replay response bytes");
    let stored: Vec<u8> = sqlx::query_scalar(
        "SELECT response_bytes FROM chat.idempotency_records WHERE operation_id=$1",
    )
    .bind(operation_id)
    .fetch_one(sequencer)
    .await
    .unwrap();
    let stored = catbird_server::chat_protocol::direct_request_transcript::present_endpoint_output(
        endpoint, stored,
    )
    .unwrap();
    assert_eq!(
        first, stored,
        "{endpoint}: home returns the sequencer's presented stored bytes"
    );
    let sequencer_claims: i64 =
        sqlx::query_scalar("SELECT count(*) FROM chat.operation_claims WHERE operation_id=$1")
            .bind(operation_id)
            .fetch_one(sequencer)
            .await
            .unwrap();
    assert_eq!(
        sequencer_claims, 1,
        "{endpoint}: sequencer retained one claim"
    );
    let home_after: (i64, i64, i64) = sqlx::query_as(
        "SELECT count(*), coalesce(max(seq),0), \
                count(*) FILTER (WHERE sequencer_receipt_bytes IS NOT NULL) \
         FROM chat.entries WHERE conversation_id=$1",
    )
    .bind(conversation_id)
    .fetch_one(home)
    .await
    .unwrap();
    assert_eq!(
        home_after, home_before,
        "{endpoint}: home neither allocates a sequence nor signs"
    );
    first
}

async fn mirror_group_membership(
    sequencer: &sqlx::PgPool,
    home: &sqlx::PgPool,
    fixture: &CleanSlateApplicationFixture,
    sequencer_destination: ValidatedRemoteDestination,
) {
    mirror_group_membership_fields(
        sequencer,
        home,
        fixture.conversation_id,
        &fixture.sender_did,
        &fixture.recipient_did,
        sequencer_destination,
    )
    .await;
}

async fn mirror_group_membership_fields(
    sequencer: &sqlx::PgPool,
    home: &sqlx::PgPool,
    conversation_id: Uuid,
    sender_did: &str,
    recipient_did: &str,
    sequencer_destination: ValidatedRemoteDestination,
) {
    mirror_group_prefix_entries(
        sequencer,
        home,
        conversation_id,
        3,
        BTreeMap::from([
            (sender_did.to_owned(), Some(SEQUENCER.to_owned())),
            (recipient_did.to_owned(), None),
        ]),
        sequencer_destination,
    )
    .await;
}

async fn mirror_group_prefix_entries(
    sequencer: &sqlx::PgPool,
    home: &sqlx::PgPool,
    conversation_id: Uuid,
    expected_len: usize,
    participant_routes: BTreeMap<String, Option<String>>,
    sequencer_destination: ValidatedRemoteDestination,
) {
    for table in ["principals", "devices", "device_keys"] {
        let rows: Value = sqlx::query_scalar(&format!(
            "SELECT jsonb_agg(to_jsonb(r)) FROM chat.{table} r"
        ))
        .fetch_one(sequencer)
        .await
        .unwrap();
        sqlx::query(&format!(
            "INSERT INTO chat.{table} SELECT * FROM \
             jsonb_populate_recordset(NULL::chat.{table}, $1) ON CONFLICT DO NOTHING"
        ))
        .bind(rows)
        .execute(home)
        .await
        .unwrap();
    }
    let packages: Value = sqlx::query_scalar(
        "SELECT jsonb_agg(to_jsonb(kp) || jsonb_build_object( \
         'status','available','terminal_transition_id',NULL, \
         'terminal_revocation_id',NULL,'terminal_at',NULL)) \
         FROM chat.key_packages kp",
    )
    .fetch_one(sequencer)
    .await
    .unwrap();
    sqlx::query(
        "INSERT INTO chat.key_packages \
         SELECT * FROM jsonb_populate_recordset(NULL::chat.key_packages, $1) \
         ON CONFLICT DO NOTHING",
    )
    .bind(packages)
    .execute(home)
    .await
    .unwrap();

    let rows = sqlx::query(
        "SELECT seq,generation,entry_id,entry_kind,accepted_payload_bytes, \
                accepted_payload_sha256,signed_request_bytes,outer_entry_fingerprint, \
                sequencer_receipt_bytes,received_at \
         FROM chat.entries WHERE conversation_id=$1 AND seq <= $2 ORDER BY seq",
    )
    .bind(conversation_id)
    .bind(expected_len as i64)
    .fetch_all(sequencer)
    .await
    .unwrap();
    assert_eq!(rows.len(), expected_len);
    let mut events = Vec::with_capacity(rows.len());
    let mut hasher = CleanConvoDigestHasher::new();
    let mut material_bytes = 0;
    for row in rows {
        let entry_id: Uuid = row.get("entry_id");
        let entry_kind: String = row.get("entry_kind");
        let event = StrictCleanRemoteEvent::try_from(RemoteEvent {
            seq: row.get("seq"),
            epoch: row.get("generation"),
            msg_id: entry_id.to_string(),
            message_type: entry_kind.clone(),
            ciphertext: row.get("accepted_payload_bytes"),
            padded_size: 0,
            created_at: row.get("received_at"),
            entry_id: Some(entry_id.to_string()),
            entry_kind: Some(entry_kind.clone()),
            accepted_payload_sha256: Some(row.get("accepted_payload_sha256")),
            signed_request: Some(row.get("signed_request_bytes")),
            outer_fingerprint: Some(row.get("outer_entry_fingerprint")),
            sequencer_receipt: Some(row.get("sequencer_receipt_bytes")),
            account_deleted_entry: None,
        })
        .unwrap();
        hasher.update_event(
            event.seq(),
            event.generation(),
            event.entry_id(),
            &entry_kind,
            event.accepted_payload_bytes(),
            event.signed_request(),
            event.outer_fingerprint(),
            event.received_at(),
        );
        material_bytes += event.accepted_payload_bytes().len()
            + event.signed_request().len()
            + event.sequencer_receipt().len();
        events.push(event);
    }
    let last = events.last().unwrap();
    let expected_last_seq = last.seq();
    let digest = RemoteDigestAnchor::new_for_test(
        conversation_id,
        SEQUENCER.to_owned(),
        0,
        last.seq(),
        events.len() as i64,
        last.generation(),
        hex::decode(hasher.finalize()).unwrap().try_into().unwrap(),
    );
    let admission = VerifiedRemotePrefixAdmission::new_for_test(
        RemotePrefixBootstrapSelector::new(conversation_id, SEQUENCER.to_owned(), 0).unwrap(),
        sequencer_destination,
        digest,
        events,
        participant_routes,
        material_bytes,
    );
    let mut tx = home.begin().await.unwrap();
    assert!(matches!(
        test_apply_remote_clean_prefix(&mut tx, admission)
            .await
            .expect("replay real signed membership into remote home"),
        RemotePrefixApplyOutcome::Applied { last_seq, .. } if last_seq == expected_last_seq
    ));
    tx.commit().await.unwrap();
}

#[tokio::test]
async fn group_reset_request_and_activation_queue_receipted_remote_home_entries_once() {
    std::env::set_var("SERVICE_DID", SEQUENCER);
    std::env::set_var("SELF_ENDPOINT", "https://r3-reset-sequencer.example.com");

    let database = common::fresh_db::fresh_fully_migrated_db("chat_fed_relay_").await;
    let pool = database.connect(4).await;
    http::ensure_fence(&pool).await;
    let fixture = seed_clean_slate_application_fixture_with_sender_home(
        &pool,
        false,
        REMOTE_HOME,
        Some([0x91; 32]),
        None,
    )
    .await
    .expect("two-home group fixture");
    let admin = fixture_device(&fixture.sender_did, fixture.sender_device_id);
    http::cache_device_did(&admin).await;
    let router = http::router_for_authenticated_acceptance(pool.clone()).await;

    let prior = fixture.signed_request["body"]["prior"].clone();
    let reset_request_id = Uuid::new_v4();
    let request = sign_mutation_json_for_test(
        &json!({
            "$type": "blue.catbird.chat.defs#resetRequestBody",
            "signatureDomain": "CATBIRD-CHAT-RESET-REQUEST\u{0000}",
            "resetRequestId": reset_request_id,
            "idempotencyKey": reset_request_id,
            "actorDid": fixture.sender_did,
            "actorDeviceId": fixture.sender_device_id,
            "keyId": fixture.sender_key_id,
            "authGeneration": 1,
            "prior": prior,
            "reason": "manualRecovery",
            "signedAt": Utc::now().to_rfc3339_opts(SecondsFormat::Millis, true),
        }),
        &SigningKey::from_bytes(&fixture.sender_ed25519_seed),
    )
    .expect("signed reset request");
    let request_bytes = serde_json::to_vec(&json!({"signedRequest": request})).unwrap();
    let send_request = || {
        http::send_bytes(
            router.clone(),
            http::unsigned_json_request(
                &admin,
                "blue.catbird.chat.requestReset",
                request_bytes.clone(),
            ),
        )
    };
    let (status, first_request) = send_request().await;
    assert_eq!(
        status,
        StatusCode::OK,
        "{}",
        String::from_utf8_lossy(&first_request)
    );
    let request_entry: Value = serde_json::from_slice(&first_request).unwrap();
    assert!(request_entry["entry"]["sequencerReceipt"].is_object());
    let queued = queued_group_entries(&pool, fixture.conversation_id).await;
    assert_eq!(
        queued.len(),
        1,
        "reset request must be queued to the remote home"
    );
    assert_eq!(queued[0]["entry"], request_entry["entry"]);
    assert_eq!(queued[0]["recipientDids"], json!([fixture.recipient_did]));

    let (status, replay_request) = send_request().await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(replay_request, first_request);
    assert_eq!(
        queued_group_entries(&pool, fixture.conversation_id)
            .await
            .len(),
        1
    );

    let participant_rows: Vec<(String, String, String, Option<Uuid>, String, Uuid)> =
        sqlx::query_as(
            "SELECT user_did,status,role,invitation_transition_id,created_by_did,created_by_device_id \
             FROM chat.participants WHERE conversation_id=$1 AND current_membership \
             ORDER BY convert_to(user_did,'UTF8')",
        )
        .bind(fixture.conversation_id)
        .fetch_all(&pool)
        .await
        .unwrap();
    let participants = participant_rows
        .into_iter()
        .map(
            |(did, status, role, invitation, invited_by, invited_device)| {
                let mut value = json!({"userDid":did,"status":status,"role":role});
                if let Some(invitation) = invitation {
                    value["invitationProvenance"] = json!({
                        "invitationTransitionId": invitation,
                        "invitedByDid": invited_by,
                        "invitedByDeviceId": invited_device,
                    });
                }
                value
            },
        )
        .collect::<Vec<_>>();
    let origin_seq: i64 = sqlx::query_scalar(
        "SELECT next_entry_seq FROM chat.conversations WHERE conversation_id=$1",
    )
    .bind(fixture.conversation_id)
    .fetch_one(&pool)
    .await
    .unwrap();
    let activation = sign_reset_activation_for_test(
        reset_request_id,
        &prior,
        json!(participants),
        origin_seq as u64,
        &fixture.sender_did,
        fixture.sender_device_id,
        &fixture.sender_key_id,
        fixture.sender_ed25519_seed,
    )
    .expect("signed reset activation");
    let activation_bytes = serde_json::to_vec(&json!({"signedRequest":activation})).unwrap();
    let send_activation = || {
        http::send_bytes(
            router.clone(),
            http::unsigned_json_request(
                &admin,
                "blue.catbird.chat.activateReset",
                activation_bytes.clone(),
            ),
        )
    };
    let (status, first_activation) = send_activation().await;
    assert_eq!(
        status,
        StatusCode::OK,
        "{}",
        String::from_utf8_lossy(&first_activation)
    );
    let activation_entry: Value = serde_json::from_slice(&first_activation).unwrap();
    assert!(activation_entry["entry"]["sequencerReceipt"].is_object());
    let queued = queued_group_entries(&pool, fixture.conversation_id).await;
    assert_eq!(
        queued.len(),
        2,
        "activation must follow the request in the same home stream"
    );
    assert_eq!(queued[0]["entry"], request_entry["entry"]);
    assert_eq!(queued[1]["entry"], activation_entry["entry"]);
    assert_eq!(
        queued
            .iter()
            .map(|item| item["entry"]["seq"].as_i64().unwrap())
            .collect::<Vec<_>>(),
        vec![
            request_entry["entry"]["seq"].as_i64().unwrap(),
            activation_entry["entry"]["seq"].as_i64().unwrap()
        ]
    );

    let (status, replay_activation) = send_activation().await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(replay_activation, first_activation);
    assert_eq!(
        queued_group_entries(&pool, fixture.conversation_id)
            .await
            .len(),
        2
    );

    catbird_server::federation::open_federation_for_test();
    let home_database = common::fresh_db::fresh_fully_migrated_db("chat_fed_relay_").await;
    let home_pool = home_database.connect(4).await;
    http::ensure_fence(&home_pool).await;
    sqlx::query(
        "INSERT INTO federation_peers(ds_did,status,trust_score,max_requests_per_minute) \
         VALUES($1,'allow',100,100)",
    )
    .bind(SEQUENCER)
    .execute(&home_pool)
    .await
    .unwrap();
    let secret = b"r3-reset-two-home-s2s-secret!!";
    let home_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let home_addr = home_listener.local_addr().unwrap();
    let home_state =
        GroupRelayState::for_test(home_pool.clone(), REMOTE_HOME.to_owned(), secret, None);
    tokio::spawn(async move {
        axum::serve(home_listener, group_relay_router(home_state))
            .await
            .unwrap();
    });
    mirror_group_membership(
        &pool,
        &home_pool,
        &fixture,
        ValidatedRemoteDestination {
            url: "http://127.0.0.1:9".parse().unwrap(),
            host: "127.0.0.1".to_owned(),
            addrs: vec!["127.0.0.1:9".parse().unwrap()],
        },
    )
    .await;

    let deliveries = queued
        .iter()
        .cloned()
        .map(serde_json::from_value::<DeliverGroupEntryRequest>)
        .collect::<Result<Vec<_>, _>>()
        .unwrap();
    for delivery in &deliveries {
        deliver_group_entry_to_remote_home(
            &format!("http://{home_addr}"),
            SEQUENCER,
            REMOTE_HOME,
            secret,
            delivery,
        )
        .await
        .expect("remote home consumes reset entry");
    }
    for delivery in &deliveries {
        deliver_group_entry_to_remote_home(
            &format!("http://{home_addr}"),
            SEQUENCER,
            REMOTE_HOME,
            secret,
            delivery,
        )
        .await
        .expect("exact remote-home reset replay");
    }
    let transport_rows: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM chat.direct_request_transport_entries \
         WHERE conversation_id=$1 AND seq IN ($2,$3)",
    )
    .bind(fixture.conversation_id)
    .bind(request_entry["entry"]["seq"].as_i64().unwrap())
    .bind(activation_entry["entry"]["seq"].as_i64().unwrap())
    .fetch_one(&home_pool)
    .await
    .unwrap();
    assert_eq!(transport_rows, 2, "exact relay replay creates no rows");

    let recipient = fixture_device(&fixture.recipient_did, fixture.recipient_device_id);
    http::cache_device_did(&recipient).await;
    let home_chat = http::router_for_authenticated_acceptance(home_pool.clone()).await;
    let (status, page) = http::send(
        home_chat,
        http::unsigned_get_request(
            &recipient,
            "blue.catbird.chat.getEntries",
            &format!(
                "actorDeviceId={}&conversationId={}&afterSeq=0&limit=50",
                fixture.recipient_device_id, fixture.conversation_id
            ),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{page}");
    let remote_entries = page["entries"].as_array().unwrap();
    let request_seq = request_entry["entry"]["seq"].as_i64().unwrap();
    let activation_seq = activation_entry["entry"]["seq"].as_i64().unwrap();
    let remote_request = remote_entries
        .iter()
        .find(|entry| entry["seq"].as_i64() == Some(request_seq))
        .expect("remote member sees reset request");
    let remote_activation = remote_entries
        .iter()
        .find(|entry| entry["seq"].as_i64() == Some(activation_seq))
        .expect("remote member sees reset activation");
    assert_eq!(remote_request, &request_entry["entry"]);
    assert_eq!(remote_activation, &activation_entry["entry"]);
    assert!(remote_request["sequencerReceipt"].is_object());
    assert!(remote_activation["sequencerReceipt"].is_object());
    assert_eq!(activation_seq, request_seq + 1);
    assert!(
        remote_activation["signedRequest"]["body"]["successor"]["generation"]
            .as_u64()
            .unwrap()
            > remote_request["signedRequest"]["body"]["prior"]["generation"]
                .as_u64()
                .unwrap(),
        "the remote member can advance to the activated recovery generation"
    );
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum RemoteLifecycleControl {
    LeaveRequest,
    CancelLeave,
    RequestLeafRecovery,
    CancelLeafRecovery,
    LeafRecoveryFulfillment,
    ZeroLeafLeaveNoLeaf,
    PendingInviteeZeroLeafLeave,
    CloseConversationRefusal,
    CloseConversationSuccess,
    RequestReset,
    ActivateReset,
}

static REMOTE_LIFECYCLE_CONTROL_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

/// A remote Group member's lifecycle call relays through its home. Each
/// operation owns a separate test so a later lifecycle failure cannot hide it.
#[cfg(feature = "sim")]
async fn run_remote_lifecycle_relay_control(operation: RemoteLifecycleControl) {
    let _ = tracing_subscriber::fmt()
        .with_max_level(tracing::Level::ERROR)
        .with_test_writer()
        .try_init();
    std::env::set_var("SERVICE_DID", SEQUENCER);
    std::env::set_var("SELF_ENDPOINT", "https://r3-reset-sequencer.example.com");

    let database = common::fresh_db::fresh_fully_migrated_db("chat_fed_relay_").await;
    let pool = database.connect(4).await;
    http::ensure_fence(&pool).await;
    sqlx::query(
        "INSERT INTO federation_peers(ds_did,status,trust_score,max_requests_per_minute) \
         VALUES($1,'allow',100,100) ON CONFLICT (ds_did) DO UPDATE SET status='allow'",
    )
    .bind(REMOTE_HOME)
    .execute(&pool)
    .await
    .unwrap();
    let fixture = seed_clean_slate_application_fixture_with_sender_home(
        &pool,
        false,
        REMOTE_HOME,
        Some([0x91; 32]),
        Some(REMOTE_HOME),
    )
    .await
    .expect("two-home group fixture");
    let admin = fixture_device(&fixture.sender_did, fixture.sender_device_id);
    http::cache_device_did(&admin).await;
    let recipient = fixture_device(&fixture.recipient_did, fixture.recipient_device_id);
    http::cache_device_did(&recipient).await;
    let (sequencer_router, sequencer_runtime) =
        http::router_and_runtime_for_authenticated_acceptance_with(pool.clone(), |runtime| {
            runtime.with_i13_receipt_signer(
                catbird_server::federation::receipt::I13ReceiptSigner::new(
                    p256::ecdsa::SigningKey::from_slice(&[0x92; 32]).unwrap(),
                    SEQUENCER.to_owned(),
                ),
            )
        })
        .await;
    let recipient_signing = SigningKey::from_bytes(&fixture.recipient_ed25519_seed);
    let credential = format!("{}#{}", fixture.recipient_did, fixture.recipient_device_id);
    let (wrapped, key_package_ref) =
        recovery_key_package(&recipient_signing, credential.as_bytes());
    let replenishment_id = Uuid::new_v4();
    let replenishment = sign_mutation_json_for_test(
        &json!({
            "$type": "blue.catbird.chat.defs#keyPackageReplenishmentBody",
            "signatureDomain": "CATBIRD-CHAT-DEVICE-REPLENISH\u{0}",
            "actorDid": fixture.recipient_did,
            "actorDeviceId": fixture.recipient_device_id,
            "authGeneration": 1,
            "keyId": fixture.recipient_key_id,
            "keyPackages": [{
                "framing": "mlsMessage",
                "contentType": "keyPackage",
                "bytes": STANDARD.encode(&wrapped),
                "sha256": STANDARD.encode(sha2::Sha256::digest(&wrapped)),
                "keyPackageRef": STANDARD.encode(&key_package_ref),
            }],
            "signaturePublicKey": STANDARD.encode(recipient_signing.verifying_key().to_bytes()),
            "idempotencyKey": replenishment_id,
            "signedAt": Utc::now().to_rfc3339_opts(SecondsFormat::Millis, true),
        }),
        &recipient_signing,
    )
    .unwrap();
    let (replenish_status, replenish_body) = http::send_bytes(
        sequencer_router.clone(),
        http::unsigned_json_request(
            &recipient,
            "blue.catbird.chat.replenishKeyPackages",
            serde_json::to_vec(&json!({"signedRequest": replenishment})).unwrap(),
        ),
    )
    .await;
    assert_eq!(
        replenish_status,
        StatusCode::OK,
        "{}",
        String::from_utf8_lossy(&replenish_body)
    );

    let prior = fixture.signed_request["body"]["prior"].clone();
    let initial_next_seq: i64 = sqlx::query_scalar(
        "SELECT next_entry_seq FROM chat.conversations WHERE conversation_id=$1",
    )
    .bind(fixture.conversation_id)
    .fetch_one(&pool)
    .await
    .unwrap();

    catbird_server::federation::open_federation_for_test();
    std::env::set_var("SERVICE_DID", REMOTE_HOME);
    std::env::set_var("SELF_ENDPOINT", "https://r3-reset-home.example.com");
    std::env::set_var(
        "FEDERATION_GROUP_RELAY_HMAC_SECRET",
        "r4b-mirror-home-two-home-secret!",
    );
    let home_database = common::fresh_db::fresh_fully_migrated_db("chat_fed_relay_").await;
    let home_pool = home_database.connect(4).await;
    http::ensure_fence(&home_pool).await;
    let _: i64 = sqlx::query_scalar("SELECT count(*) FROM chat.remote_lifecycle_recovery_bindings")
        .fetch_one(&home_pool)
        .await
        .unwrap();
    sqlx::query(
        "INSERT INTO federation_peers(ds_did,status,trust_score,max_requests_per_minute) \
         VALUES($1,'allow',100,100)",
    )
    .bind(SEQUENCER)
    .execute(&home_pool)
    .await
    .unwrap();
    let secret = b"r4b-mirror-home-two-home-secret!";
    let unavailable_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let unavailable_addr = unavailable_listener.local_addr().unwrap();
    drop(unavailable_listener);
    let home_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let home_addr = home_listener.local_addr().unwrap();
    let home_state =
        GroupRelayState::for_test(home_pool.clone(), REMOTE_HOME.to_owned(), secret, None);
    tokio::spawn(async move {
        axum::serve(home_listener, group_relay_router(home_state))
            .await
            .unwrap();
    });
    mirror_group_membership(
        &pool,
        &home_pool,
        &fixture,
        ValidatedRemoteDestination {
            url: format!("http://{unavailable_addr}").parse().unwrap(),
            host: "127.0.0.1".to_owned(),
            addrs: vec![unavailable_addr],
        },
    )
    .await;

    let mirror_before: (bool, Option<String>, i64) = sqlx::query_as(
        "SELECT is_remote,sequencer_ds,next_entry_seq FROM chat.conversations \
         WHERE conversation_id=$1",
    )
    .bind(fixture.conversation_id)
    .fetch_one(&home_pool)
    .await
    .unwrap();
    assert!(mirror_before.0);
    assert_eq!(mirror_before.1.as_deref(), Some(SEQUENCER));
    assert_eq!(mirror_before.2, initial_next_seq);

    let unavailable_destination = ValidatedRemoteDestination {
        url: format!("http://{unavailable_addr}").parse().unwrap(),
        host: "127.0.0.1".to_owned(),
        addrs: vec![unavailable_addr],
    };
    let resolver = DsResolver::new(
        home_pool.clone(),
        build_resolver_http_client(),
        REMOTE_HOME.to_owned(),
        "https://r3-reset-home.example.com".to_owned(),
        None,
        300,
    )
    .with_destination_resolver_hook(Arc::new(move |target| {
        if target != SEQUENCER {
            return None;
        }
        let destination = unavailable_destination.clone();
        Some(Box::pin(async move { Ok(destination) }))
    }));
    let home_chat =
        http::router_for_authenticated_acceptance_with(home_pool.clone(), move |runtime| {
            runtime.with_resolver(Arc::new(resolver))
        })
        .await;
    let leave_request_id = Uuid::new_v4();
    let leave = sign_mutation_json_for_test(
        &json!({
            "$type": "blue.catbird.chat.defs#leaveRequestBody",
            "signatureDomain": "CATBIRD-CHAT-LEAVE-REQUEST\u{0000}",
            "leaveRequestId": leave_request_id,
            "actorDid": fixture.recipient_did,
            "actorDeviceId": fixture.recipient_device_id,
            "keyId": fixture.recipient_key_id,
            "authGeneration": 1,
            "prior": fixture.signed_request["body"]["prior"],
            "idempotencyKey": leave_request_id,
            "signedAt": Utc::now().to_rfc3339_opts(SecondsFormat::Millis, true),
        }),
        &SigningKey::from_bytes(&fixture.recipient_ed25519_seed),
    )
    .expect("signed leave request");
    assert_remote_sequencing_unavailable(
        home_chat.clone(),
        &home_pool,
        &recipient,
        "blue.catbird.chat.requestLeave",
        leave.clone(),
        fixture.conversation_id,
    )
    .await;

    let mut zero_leaf_next = fixture.signed_request["body"]["prior"].clone();
    zero_leaf_next["stateVersion"] = json!(zero_leaf_next["stateVersion"].as_u64().unwrap() + 1);
    let transition_id = Uuid::new_v4();
    let zero_leaf = sign_mutation_json_for_test(
        &json!({
            "$type": "blue.catbird.chat.defs#zeroLeafLeaveBody",
            "signatureDomain": "CATBIRD-CHAT-LEAVE-ZERO-LEAF\u{0000}",
            "transitionId": transition_id,
            "actorDid": fixture.recipient_did,
            "actorDeviceId": fixture.recipient_device_id,
            "keyId": fixture.recipient_key_id,
            "authGeneration": 1,
            "prior": fixture.signed_request["body"]["prior"],
            "next": zero_leaf_next,
            "idempotencyKey": transition_id,
            "signedAt": Utc::now().to_rfc3339_opts(SecondsFormat::Millis, true),
        }),
        &SigningKey::from_bytes(&fixture.recipient_ed25519_seed),
    )
    .unwrap();
    assert_remote_sequencing_unavailable(
        home_chat.clone(),
        &home_pool,
        &recipient,
        "blue.catbird.chat.requestLeave",
        zero_leaf,
        fixture.conversation_id,
    )
    .await;

    let cancellation_id = Uuid::new_v4();
    let cancellation = sign_mutation_json_for_test(
        &json!({
            "$type": "blue.catbird.chat.defs#leaveCancellationBody",
            "signatureDomain": "CATBIRD-CHAT-LEAVE-CANCEL\u{0000}",
            "conversationId": fixture.conversation_id,
            "leaveRequestId": leave_request_id,
            "actorDid": fixture.recipient_did,
            "actorDeviceId": fixture.recipient_device_id,
            "keyId": fixture.recipient_key_id,
            "authGeneration": 1,
            "idempotencyKey": cancellation_id,
            "signedAt": Utc::now().to_rfc3339_opts(SecondsFormat::Millis, true),
        }),
        &SigningKey::from_bytes(&fixture.recipient_ed25519_seed),
    )
    .unwrap();
    assert_remote_sequencing_unavailable(
        home_chat.clone(),
        &home_pool,
        &recipient,
        "blue.catbird.chat.cancelLeave",
        cancellation.clone(),
        fixture.conversation_id,
    )
    .await;

    let mut retired = fixture.signed_request["body"]["prior"].clone();
    retired["stateVersion"] = json!(retired["stateVersion"].as_u64().unwrap() + 1);
    retired["lifecycle"] = json!("superseded");
    let close_id = Uuid::new_v4();
    let close = sign_mutation_json_for_test(
        &json!({
            "$type": "blue.catbird.chat.defs#conversationCloseBody",
            "signatureDomain": "CATBIRD-CHAT-CLOSE\u{0000}",
            "transitionId": close_id,
            "conversationKind": "group",
            "actorDid": fixture.sender_did,
            "actorDeviceId": fixture.sender_device_id,
            "keyId": fixture.sender_key_id,
            "authGeneration": 1,
            "prior": fixture.signed_request["body"]["prior"],
            "retired": retired,
            "idempotencyKey": close_id,
            "signedAt": Utc::now().to_rfc3339_opts(SecondsFormat::Millis, true),
        }),
        &SigningKey::from_bytes(&fixture.sender_ed25519_seed),
    )
    .unwrap();
    assert_remote_sequencing_unavailable(
        home_chat.clone(),
        &home_pool,
        &admin,
        "blue.catbird.chat.closeConversation",
        close.clone(),
        fixture.conversation_id,
    )
    .await;

    let remote_reset_id = Uuid::new_v4();
    let remote_reset = sign_mutation_json_for_test(
        &json!({
            "$type": "blue.catbird.chat.defs#resetRequestBody",
            "signatureDomain": "CATBIRD-CHAT-RESET-REQUEST\u{0000}",
            "resetRequestId": remote_reset_id,
            "idempotencyKey": remote_reset_id,
            "actorDid": fixture.sender_did,
            "actorDeviceId": fixture.sender_device_id,
            "keyId": fixture.sender_key_id,
            "authGeneration": 1,
            "prior": fixture.signed_request["body"]["prior"],
            "reason": "manualRecovery",
            "signedAt": Utc::now().to_rfc3339_opts(SecondsFormat::Millis, true),
        }),
        &SigningKey::from_bytes(&fixture.sender_ed25519_seed),
    )
    .unwrap();
    assert_remote_sequencing_unavailable(
        home_chat.clone(),
        &home_pool,
        &admin,
        "blue.catbird.chat.requestReset",
        remote_reset.clone(),
        fixture.conversation_id,
    )
    .await;

    let participant_rows: Vec<(String, String, String, Option<Uuid>, String, Uuid)> =
        sqlx::query_as(
            "SELECT user_did,status,role,invitation_transition_id,created_by_did,created_by_device_id \
             FROM chat.participants WHERE conversation_id=$1 AND current_membership ORDER BY convert_to(user_did,'UTF8')",
        )
        .bind(fixture.conversation_id)
        .fetch_all(&home_pool)
        .await
        .unwrap();
    let participants = participant_rows
        .into_iter()
        .map(
            |(did, status, role, invitation, invited_by, invited_device)| {
                let mut value = json!({"userDid":did,"status":status,"role":role});
                if let Some(invitation) = invitation {
                    value["invitationProvenance"] = json!({
                        "invitationTransitionId": invitation,
                        "invitedByDid": invited_by,
                        "invitedByDeviceId": invited_device,
                    });
                }
                value
            },
        )
        .collect::<Vec<_>>();
    let activation = sign_reset_activation_for_test(
        Uuid::new_v4(),
        &fixture.signed_request["body"]["prior"],
        json!(participants),
        initial_next_seq as u64,
        &fixture.sender_did,
        fixture.sender_device_id,
        &fixture.sender_key_id,
        fixture.sender_ed25519_seed,
    )
    .unwrap();
    assert_remote_sequencing_unavailable(
        home_chat.clone(),
        &home_pool,
        &admin,
        "blue.catbird.chat.activateReset",
        activation.clone(),
        fixture.conversation_id,
    )
    .await;

    let recovery_request_id = Uuid::new_v4();
    let recovery = sign_mutation_json_for_test(
        &json!({
            "$type": "blue.catbird.chat.defs#leafRecoveryRequestBody",
            "signatureDomain": "CATBIRD-CHAT-LEAF-RECOVERY-REQUEST\u{0000}",
            "recoveryRequestId": recovery_request_id,
            "actorDid": fixture.sender_did,
            "actorDeviceId": fixture.sender_device_id,
            "keyId": fixture.sender_key_id,
            "authGeneration": 1,
            "prior": fixture.signed_request["body"]["prior"],
            "recoveryKind": "replace",
            "idempotencyKey": recovery_request_id,
            "signedAt": Utc::now().to_rfc3339_opts(SecondsFormat::Millis, true),
        }),
        &SigningKey::from_bytes(&fixture.sender_ed25519_seed),
    )
    .unwrap();
    assert_remote_sequencing_unavailable(
        home_chat.clone(),
        &home_pool,
        &admin,
        "blue.catbird.chat.requestLeafRecovery",
        recovery.clone(),
        fixture.conversation_id,
    )
    .await;

    let existing_recovery_id: Uuid = sqlx::query_scalar(
        "SELECT recovery_request_id FROM chat.leaf_recovery_requests \
         WHERE conversation_id=$1 ORDER BY requested_at LIMIT 1",
    )
    .bind(fixture.conversation_id)
    .fetch_one(&home_pool)
    .await
    .unwrap();
    let recovery_cancellation_id = Uuid::new_v4();
    let recovery_cancellation = sign_mutation_json_for_test(
        &json!({
            "$type": "blue.catbird.chat.defs#leafRecoveryCancellationBody",
            "signatureDomain": "CATBIRD-CHAT-LEAF-RECOVERY-CANCEL\u{0000}",
            "recoveryRequestId": existing_recovery_id,
            "actorDid": fixture.recipient_did,
            "actorDeviceId": fixture.recipient_device_id,
            "keyId": fixture.recipient_key_id,
            "authGeneration": 1,
            "idempotencyKey": recovery_cancellation_id,
            "signedAt": Utc::now().to_rfc3339_opts(SecondsFormat::Millis, true),
        }),
        &SigningKey::from_bytes(&fixture.recipient_ed25519_seed),
    )
    .unwrap();
    assert_remote_sequencing_unavailable(
        home_chat.clone(),
        &home_pool,
        &recipient,
        "blue.catbird.chat.cancelLeafRecovery",
        recovery_cancellation.clone(),
        fixture.conversation_id,
    )
    .await;

    let fulfillment_bytes: Vec<u8> = sqlx::query_scalar(
        "SELECT signed_request_bytes FROM chat.entries \
         WHERE conversation_id=$1 AND seq=3",
    )
    .bind(fixture.conversation_id)
    .fetch_one(&home_pool)
    .await
    .unwrap();
    assert_remote_sequencing_unavailable(
        home_chat.clone(),
        &home_pool,
        &admin,
        "blue.catbird.chat.submitTransition",
        serde_json::from_slice(&fulfillment_bytes).unwrap(),
        fixture.conversation_id,
    )
    .await;

    let mirror_after: (i64,) =
        sqlx::query_as("SELECT next_entry_seq FROM chat.conversations WHERE conversation_id=$1")
            .bind(fixture.conversation_id)
            .fetch_one(&home_pool)
            .await
            .unwrap();
    let local_entry_at_position: i64 =
        sqlx::query_scalar("SELECT count(*) FROM chat.entries WHERE conversation_id=$1 AND seq=$2")
            .bind(fixture.conversation_id)
            .bind(initial_next_seq)
            .fetch_one(&home_pool)
            .await
            .unwrap();
    let relayed_rows: i64 =
        sqlx::query_scalar("SELECT count(*) FROM outbound_queue WHERE convo_id=$1")
            .bind(fixture.conversation_id.to_string())
            .fetch_one(&home_pool)
            .await
            .unwrap();
    assert_eq!(mirror_after.0, mirror_before.2);
    assert_eq!(
        local_entry_at_position, 0,
        "the home must not allocate or receipt the sequencer's next position"
    );
    assert_eq!(
        relayed_rows, 0,
        "failed lifecycle relays do not enqueue local sequence work"
    );

    // Bring the sequencer S2S route online. From here every client mutation
    // still enters through the member's home router.
    let sequencer_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let sequencer_addr = sequencer_listener.local_addr().unwrap();
    let sequencer_hooks = Arc::new(catbird_server::sim_hooks::SimDsHooks {
        service_did: SEQUENCER.to_owned(),
        self_endpoint: "https://r3-reset-sequencer.example.com".to_owned(),
        signing_key_pem: None,
        group_relay_hmac_secret: Some(String::from_utf8(secret.to_vec()).unwrap()),
        http_transport: Arc::new(|_| {
            Box::pin(async { Err("unexpected sequencer outbound HTTP".to_owned()) })
        }),
        dns_resolver: Arc::new(|_| Err("unexpected sequencer DNS lookup".to_owned())),
        retain_application_ciphertext: false,
    });
    let sequencer_state =
        GroupRelayState::for_test(pool.clone(), SEQUENCER.to_owned(), secret, None)
            .with_chat_runtime(sequencer_runtime)
            .with_sim_hooks(sequencer_hooks);
    tokio::spawn(async move {
        axum::serve(sequencer_listener, group_relay_router(sequencer_state))
            .await
            .unwrap();
    });
    let live_destination = ValidatedRemoteDestination {
        url: format!("http://{sequencer_addr}").parse().unwrap(),
        host: "127.0.0.1".to_owned(),
        addrs: vec![sequencer_addr],
    };
    let live_resolver = DsResolver::new(
        home_pool.clone(),
        build_resolver_http_client(),
        REMOTE_HOME.to_owned(),
        "https://r3-reset-home.example.com".to_owned(),
        None,
        300,
    )
    .with_destination_resolver_hook(Arc::new(move |target| {
        if target != SEQUENCER {
            return None;
        }
        let destination = live_destination.clone();
        Some(Box::pin(async move { Ok(destination) }))
    }));
    let live_home_chat =
        http::router_for_authenticated_acceptance_with(home_pool.clone(), move |runtime| {
            runtime.with_resolver(Arc::new(live_resolver))
        })
        .await;
    let sequencer_endpoint = format!("http://{sequencer_addr}");
    let sequencer_entries_before_security: i64 =
        sqlx::query_scalar("SELECT count(*) FROM chat.entries WHERE conversation_id=$1")
            .bind(fixture.conversation_id)
            .fetch_one(&pool)
            .await
            .unwrap();

    // A compromised home cannot bypass member signature or membership checks:
    // these requests go straight to the sequencer's S2S route.
    let mut invalid_signature = leave.clone();
    let mut signature = STANDARD
        .decode(invalid_signature["signature"].as_str().unwrap())
        .unwrap();
    signature[0] ^= 1;
    invalid_signature["signature"] = json!(STANDARD.encode(signature));
    let invalid_bytes = serde_json::to_vec(&invalid_signature).unwrap();
    let invalid_error = relay_group_mutation_to_sequencer(
        &sequencer_endpoint,
        REMOTE_HOME,
        SEQUENCER,
        secret,
        &RelayGroupMutationRequest {
            conversation_id: fixture.conversation_id,
            endpoint: "blue.catbird.chat.requestLeave".to_owned(),
            actor_did: fixture.recipient_did.clone(),
            actor_device_id: fixture.recipient_device_id,
            signed_request: invalid_signature,
            signed_request_bytes: Some(STANDARD.encode(invalid_bytes)),
        },
    )
    .await
    .unwrap_err();
    assert!(
        format!("{invalid_error:?}").contains("InvalidSignature"),
        "sequencer rejects the invalid member signature: {invalid_error:?}"
    );

    let mut outsider = leave.clone();
    let outsider_did = format!(
        "did:web:r3-outsider-{}.example.com",
        Uuid::new_v4().simple()
    );
    outsider["body"]["actorDid"] = json!(outsider_did);
    outsider["body"]["actorDeviceId"] = json!(Uuid::new_v4());
    outsider["body"]["keyId"] = json!(format!("{outsider_did}#device"));
    let outsider_device: Uuid = outsider["body"]["actorDeviceId"]
        .as_str()
        .unwrap()
        .parse()
        .unwrap();
    let outsider_bytes = serde_json::to_vec(&outsider).unwrap();
    let outsider_error = relay_group_mutation_to_sequencer(
        &sequencer_endpoint,
        REMOTE_HOME,
        SEQUENCER,
        secret,
        &RelayGroupMutationRequest {
            conversation_id: fixture.conversation_id,
            endpoint: "blue.catbird.chat.requestLeave".to_owned(),
            actor_did: outsider_did,
            actor_device_id: outsider_device,
            signed_request: outsider,
            signed_request_bytes: Some(STANDARD.encode(outsider_bytes)),
        },
    )
    .await
    .unwrap_err();
    assert!(
        format!("{outsider_error:?}").starts_with("Rejected("),
        "sequencer refuses a non-member before any effect: {outsider_error:?}"
    );

    let exact_leave_bytes = serde_json::to_vec(&leave).unwrap();
    let mut mismatched_envelope = leave.clone();
    mismatched_envelope["body"]["leaveRequestId"] = json!(Uuid::new_v4());
    let mismatch_error = relay_group_mutation_to_sequencer(
        &sequencer_endpoint,
        REMOTE_HOME,
        SEQUENCER,
        secret,
        &RelayGroupMutationRequest {
            conversation_id: fixture.conversation_id,
            endpoint: "blue.catbird.chat.requestLeave".to_owned(),
            actor_did: fixture.recipient_did.clone(),
            actor_device_id: fixture.recipient_device_id,
            signed_request: mismatched_envelope,
            signed_request_bytes: Some(STANDARD.encode(&exact_leave_bytes)),
        },
    )
    .await
    .unwrap_err();
    assert!(
        format!("{mismatch_error:?}").contains("InvalidRequest"),
        "sequencer refuses an envelope/exact-body mismatch: {mismatch_error:?}"
    );

    let wrong_home = format!(
        "did:web:r3-wrong-home-{}.example.com",
        Uuid::new_v4().simple()
    );
    sqlx::query(
        "INSERT INTO federation_peers(ds_did,status,trust_score,max_requests_per_minute) \
         VALUES($1,'allow',100,100)",
    )
    .bind(&wrong_home)
    .execute(&pool)
    .await
    .unwrap();
    let wrong_home_error = relay_group_mutation_to_sequencer(
        &sequencer_endpoint,
        &wrong_home,
        SEQUENCER,
        secret,
        &RelayGroupMutationRequest {
            conversation_id: fixture.conversation_id,
            endpoint: "blue.catbird.chat.requestLeave".to_owned(),
            actor_did: fixture.recipient_did.clone(),
            actor_device_id: fixture.recipient_device_id,
            signed_request: leave.clone(),
            signed_request_bytes: Some(STANDARD.encode(exact_leave_bytes)),
        },
    )
    .await
    .unwrap_err();
    assert!(
        format!("{wrong_home_error:?}").contains("NotAuthorized"),
        "sequencer refuses a caller other than the member's authoritative home: {wrong_home_error:?}"
    );
    let sequencer_entries_after_security: i64 =
        sqlx::query_scalar("SELECT count(*) FROM chat.entries WHERE conversation_id=$1")
            .bind(fixture.conversation_id)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(
        sequencer_entries_after_security, sequencer_entries_before_security,
        "sequencer refusals have no effect"
    );

    let home_endpoint = format!("http://{home_addr}");
    match operation {
        RemoteLifecycleControl::LeaveRequest => {
            relay_lifecycle_and_deliver(
                live_home_chat,
                &recipient,
                "blue.catbird.chat.requestLeave",
                leave,
                &pool,
                &home_pool,
                fixture.conversation_id,
                &home_endpoint,
                secret,
            )
            .await;
        }
        RemoteLifecycleControl::CancelLeave => {
            relay_lifecycle_and_deliver(
                live_home_chat.clone(),
                &recipient,
                "blue.catbird.chat.requestLeave",
                leave,
                &pool,
                &home_pool,
                fixture.conversation_id,
                &home_endpoint,
                secret,
            )
            .await;
            relay_lifecycle_and_deliver(
                live_home_chat,
                &recipient,
                "blue.catbird.chat.cancelLeave",
                cancellation,
                &pool,
                &home_pool,
                fixture.conversation_id,
                &home_endpoint,
                secret,
            )
            .await;
        }
        RemoteLifecycleControl::CloseConversationRefusal => {
            let before: (i64, i64) = sqlx::query_as(
                "SELECT next_entry_seq,(SELECT count(*) FROM chat.entries WHERE conversation_id=$1) \
                 FROM chat.conversations WHERE conversation_id=$1",
            )
            .bind(fixture.conversation_id)
            .fetch_one(&pool)
            .await
            .unwrap();
            let body = serde_json::to_vec(&json!({"signedRequest": close})).unwrap();
            let (status, first) = http::send_bytes(
                live_home_chat.clone(),
                http::unsigned_json_request(
                    &admin,
                    "blue.catbird.chat.closeConversation",
                    body.clone(),
                ),
            )
            .await;
            assert_eq!(status, StatusCode::BAD_REQUEST);
            assert_eq!(
                serde_json::from_slice::<Value>(&first).unwrap()["error"],
                "ConversationCloseNotAllowed"
            );
            let (replay_status, replay) = http::send_bytes(
                live_home_chat,
                http::unsigned_json_request(&admin, "blue.catbird.chat.closeConversation", body),
            )
            .await;
            assert_eq!(replay_status, StatusCode::BAD_REQUEST);
            assert_eq!(replay, first);
            let after: (i64, i64) = sqlx::query_as(
                "SELECT next_entry_seq,(SELECT count(*) FROM chat.entries WHERE conversation_id=$1) \
                 FROM chat.conversations WHERE conversation_id=$1",
            )
            .bind(fixture.conversation_id)
            .fetch_one(&pool)
            .await
            .unwrap();
            assert_eq!(after, before, "declared refusal has no sequencer effect");
        }
        RemoteLifecycleControl::CloseConversationSuccess => {
            std::env::set_var("SERVICE_DID", SEQUENCER);
            let genuine = catbird_server::chat_protocol::test_support::
                seed_genuine_leafless_group_relay_fixture(&pool, REMOTE_HOME, false, false)
                    .await
                    .expect("sole-admin group fixture");
            std::env::set_var("SERVICE_DID", REMOTE_HOME);
            let sole_admin = fixture_device(&genuine.admin_did, genuine.admin_device_id);
            http::cache_device_did(&sole_admin).await;
            mirror_group_prefix_entries(
                &pool,
                &home_pool,
                genuine.conversation_id,
                genuine.entry_count,
                BTreeMap::from([(genuine.admin_did.clone(), None)]),
                ValidatedRemoteDestination {
                    url: format!("http://{sequencer_addr}").parse().unwrap(),
                    host: "127.0.0.1".to_owned(),
                    addrs: vec![sequencer_addr],
                },
            )
            .await;
            let prior = genuine.prior.clone();
            let mut retired = prior.clone();
            retired["stateVersion"] = json!(prior["stateVersion"].as_u64().unwrap() + 1);
            retired["lifecycle"] = json!("superseded");
            let transition_id = Uuid::new_v4();
            let sole_admin_close = sign_mutation_json_for_test(
                &json!({
                    "$type": "blue.catbird.chat.defs#conversationCloseBody",
                    "signatureDomain": "CATBIRD-CHAT-CLOSE\u{0000}",
                    "transitionId": transition_id,
                    "conversationKind": "group",
                    "actorDid": genuine.admin_did,
                    "actorDeviceId": genuine.admin_device_id,
                    "keyId": genuine.admin_key_id,
                    "authGeneration": 1,
                    "prior": prior,
                    "retired": retired,
                    "idempotencyKey": transition_id,
                    "signedAt": Utc::now().to_rfc3339_opts(SecondsFormat::Millis, true),
                }),
                &SigningKey::from_bytes(&genuine.admin_ed25519_seed),
            )
            .unwrap();
            let body = serde_json::to_vec(&json!({"signedRequest": sole_admin_close})).unwrap();
            let (status, first) = http::send_bytes(
                live_home_chat.clone(),
                http::unsigned_json_request(
                    &sole_admin,
                    "blue.catbird.chat.closeConversation",
                    body.clone(),
                ),
            )
            .await;
            assert_eq!(
                status,
                StatusCode::OK,
                "sole-admin Group close through home: {}",
                String::from_utf8_lossy(&first)
            );
            let (replay_status, replay) = http::send_bytes(
                live_home_chat,
                http::unsigned_json_request(
                    &sole_admin,
                    "blue.catbird.chat.closeConversation",
                    body,
                ),
            )
            .await;
            assert_eq!(replay_status, StatusCode::OK);
            assert_eq!(replay, first, "home replays the coordinator's exact close");
            let response: Value = serde_json::from_slice(&first).unwrap();
            assert!(
                response.pointer("/result/entry/sequencerReceipt").is_some(),
                "close response must carry sequencer receipt: {response}"
            );
            let head_exists: bool = sqlx::query_scalar(
                "SELECT EXISTS(SELECT 1 FROM chat.conversations WHERE conversation_id=$1)",
            )
            .bind(genuine.conversation_id)
            .fetch_one(&pool)
            .await
            .unwrap();
            assert!(
                !head_exists,
                "sole-admin Group close purges the conversation head"
            );
        }
        RemoteLifecycleControl::RequestReset => {
            relay_lifecycle_and_deliver(
                live_home_chat,
                &admin,
                "blue.catbird.chat.requestReset",
                remote_reset,
                &pool,
                &home_pool,
                fixture.conversation_id,
                &home_endpoint,
                secret,
            )
            .await;
        }
        RemoteLifecycleControl::ActivateReset => {
            relay_lifecycle_and_deliver(
                live_home_chat.clone(),
                &admin,
                "blue.catbird.chat.requestReset",
                remote_reset,
                &pool,
                &home_pool,
                fixture.conversation_id,
                &home_endpoint,
                secret,
            )
            .await;
            let origin_seq: i64 = sqlx::query_scalar(
                "SELECT next_entry_seq FROM chat.conversations WHERE conversation_id=$1",
            )
            .bind(fixture.conversation_id)
            .fetch_one(&pool)
            .await
            .unwrap();
            let activation = sign_reset_activation_for_test(
                remote_reset_id,
                &fixture.signed_request["body"]["prior"],
                json!(participants),
                origin_seq as u64,
                &fixture.sender_did,
                fixture.sender_device_id,
                &fixture.sender_key_id,
                fixture.sender_ed25519_seed,
            )
            .unwrap();
            relay_lifecycle_and_deliver(
                live_home_chat,
                &admin,
                "blue.catbird.chat.activateReset",
                activation,
                &pool,
                &home_pool,
                fixture.conversation_id,
                &home_endpoint,
                secret,
            )
            .await;
        }
        RemoteLifecycleControl::RequestLeafRecovery
        | RemoteLifecycleControl::CancelLeafRecovery => {
            let relayed_recovery_id = Uuid::new_v4();
            let relayed_recovery = sign_mutation_json_for_test(
                &json!({
                    "$type": "blue.catbird.chat.defs#leafRecoveryRequestBody",
                    "signatureDomain": "CATBIRD-CHAT-LEAF-RECOVERY-REQUEST\u{0000}",
                    "recoveryRequestId": relayed_recovery_id,
                    "actorDid": fixture.recipient_did,
                    "actorDeviceId": fixture.recipient_device_id,
                    "keyId": fixture.recipient_key_id,
                    "authGeneration": 1,
                    "prior": prior,
                    "recoveryKind": "replace",
                    "idempotencyKey": relayed_recovery_id,
                    "signedAt": Utc::now().to_rfc3339_opts(SecondsFormat::Millis, true),
                }),
                &SigningKey::from_bytes(&fixture.recipient_ed25519_seed),
            )
            .unwrap();
            let request_response = relay_entryless_lifecycle(
                live_home_chat.clone(),
                &recipient,
                "blue.catbird.chat.requestLeafRecovery",
                relayed_recovery.clone(),
                relayed_recovery_id,
                &pool,
                &home_pool,
                fixture.conversation_id,
            )
            .await;
            let request_replay = relay_entryless_lifecycle(
                live_home_chat.clone(),
                &recipient,
                "blue.catbird.chat.requestLeafRecovery",
                relayed_recovery,
                relayed_recovery_id,
                &pool,
                &home_pool,
                fixture.conversation_id,
            )
            .await;
            assert_eq!(request_replay, request_response);
            let sequencer_status: String = sqlx::query_scalar(
                "SELECT status FROM chat.leaf_recovery_requests WHERE recovery_request_id=$1",
            )
            .bind(relayed_recovery_id)
            .fetch_one(&pool)
            .await
            .unwrap();
            assert_eq!(sequencer_status, "open");
            let home_requests: i64 = sqlx::query_scalar(
                "SELECT count(*) FROM chat.leaf_recovery_requests WHERE recovery_request_id=$1",
            )
            .bind(relayed_recovery_id)
            .fetch_one(&home_pool)
            .await
            .unwrap();
            assert_eq!(
                home_requests, 0,
                "entry-less relay must not create a home-owned recovery request"
            );
            let mirrored_response: Vec<u8> = sqlx::query_scalar(
                "SELECT response_bytes \
                 FROM chat.remote_lifecycle_recovery_bindings WHERE recovery_request_id=$1",
            )
            .bind(relayed_recovery_id)
            .fetch_one(&home_pool)
            .await
            .unwrap();
            assert_eq!(
                mirrored_response, request_response,
                "the home mirrors only the authenticated sequencer response and routing binding"
            );
            let (state_status, state) = http::send(
                live_home_chat.clone(),
                http::unsigned_get_request(
                    &admin,
                    "blue.catbird.chat.getConversationState",
                    &format!(
                        "actorDeviceId={}&conversationId={}",
                        fixture.sender_device_id, fixture.conversation_id
                    ),
                ),
            )
            .await;
            assert_eq!(
                state_status,
                StatusCode::OK,
                "home pending-request view: {state}"
            );
            let pending = state["pendingLeafRecoveryRequests"].as_array().unwrap();
            let sequencer_recovery: Value =
                serde_json::from_slice::<Value>(&request_response).unwrap()["recovery"].clone();
            assert_eq!(pending, &[sequencer_recovery]);
            if operation == RemoteLifecycleControl::CancelLeafRecovery {
                let cancel_recovery_id = Uuid::new_v4();
                let relayed_cancel_recovery = sign_mutation_json_for_test(
                    &json!({
                        "$type": "blue.catbird.chat.defs#leafRecoveryCancellationBody",
                        "signatureDomain": "CATBIRD-CHAT-LEAF-RECOVERY-CANCEL\u{0000}",
                        "recoveryRequestId": relayed_recovery_id,
                        "actorDid": fixture.recipient_did,
                        "actorDeviceId": fixture.recipient_device_id,
                        "keyId": fixture.recipient_key_id,
                        "authGeneration": 1,
                        "idempotencyKey": cancel_recovery_id,
                        "signedAt": Utc::now().to_rfc3339_opts(SecondsFormat::Millis, true),
                    }),
                    &SigningKey::from_bytes(&fixture.recipient_ed25519_seed),
                )
                .unwrap();
                let cancel_response = relay_entryless_lifecycle(
                    live_home_chat.clone(),
                    &recipient,
                    "blue.catbird.chat.cancelLeafRecovery",
                    relayed_cancel_recovery.clone(),
                    cancel_recovery_id,
                    &pool,
                    &home_pool,
                    fixture.conversation_id,
                )
                .await;
                let cancel_replay = relay_entryless_lifecycle(
                    live_home_chat.clone(),
                    &recipient,
                    "blue.catbird.chat.cancelLeafRecovery",
                    relayed_cancel_recovery,
                    cancel_recovery_id,
                    &pool,
                    &home_pool,
                    fixture.conversation_id,
                )
                .await;
                assert_eq!(cancel_replay, cancel_response);
                let sequencer_status: String = sqlx::query_scalar(
                    "SELECT status FROM chat.leaf_recovery_requests WHERE recovery_request_id=$1",
                )
                .bind(relayed_recovery_id)
                .fetch_one(&pool)
                .await
                .unwrap();
                assert_eq!(sequencer_status, "cancelled");
                let binding_count: i64 = sqlx::query_scalar(
                    "SELECT count(*) \
                     FROM chat.remote_lifecycle_recovery_bindings WHERE recovery_request_id=$1",
                )
                .bind(relayed_recovery_id)
                .fetch_one(&home_pool)
                .await
                .unwrap();
                assert_eq!(binding_count, 0, "cancellation deletes the routing binding");
                let (state_status, state) = http::send(
                    live_home_chat,
                    http::unsigned_get_request(
                        &admin,
                        "blue.catbird.chat.getConversationState",
                        &format!(
                            "actorDeviceId={}&conversationId={}",
                            fixture.sender_device_id, fixture.conversation_id
                        ),
                    ),
                )
                .await;
                assert_eq!(state_status, StatusCode::OK, "{state}");
                assert!(
                    state["pendingLeafRecoveryRequests"]
                        .as_array()
                        .unwrap()
                        .is_empty(),
                    "the cancellation removes the mirrored pending view: {state}"
                );
            }
        }
        RemoteLifecycleControl::LeafRecoveryFulfillment => {
            std::env::set_var("SERVICE_DID", SEQUENCER);
            let genuine =
                catbird_server::chat_protocol::test_support::seed_genuine_recovery_relay_fixture(
                    &pool,
                    REMOTE_HOME,
                )
                .await
                .expect("genuine pending Recovery fulfillment fixture");
            let roster = vec![genuine.requester_did.clone(), genuine.fulfiller_did.clone()];
            catbird_server::chat_protocol::test_support::seed_deterministic_recovery_reservation_fallback(
                &pool,
                roster.clone(),
            )
            .await
            .expect("recovery reservation fallback");
            catbird_server::chat_protocol::test_support::seed_deterministic_recovery_fulfillment_fallback(
                &pool,
                roster,
            )
            .await
            .expect("recovery fulfillment fallback");
            std::env::set_var("SERVICE_DID", REMOTE_HOME);
            let requester = fixture_device(&genuine.requester_did, genuine.requester_device_id);
            let fulfiller = fixture_device(&genuine.fulfiller_did, genuine.fulfiller_device_id);
            http::cache_device_did(&requester).await;
            http::cache_device_did(&fulfiller).await;
            mirror_group_membership_fields(
                &pool,
                &home_pool,
                genuine.conversation_id,
                &genuine.requester_did,
                &genuine.fulfiller_did,
                ValidatedRemoteDestination {
                    url: format!("http://{sequencer_addr}").parse().unwrap(),
                    host: "127.0.0.1".to_owned(),
                    addrs: vec![sequencer_addr],
                },
            )
            .await;
            let request_id: Uuid = genuine.request["body"]["idempotencyKey"]
                .as_str()
                .unwrap()
                .parse()
                .unwrap();
            relay_entryless_lifecycle(
                live_home_chat.clone(),
                &requester,
                "blue.catbird.chat.requestLeafRecovery",
                genuine.request,
                request_id,
                &pool,
                &home_pool,
                genuine.conversation_id,
            )
            .await;
            relay_lifecycle_and_deliver(
                live_home_chat,
                &fulfiller,
                "blue.catbird.chat.submitTransition",
                genuine.fulfillment,
                &pool,
                &home_pool,
                genuine.conversation_id,
                &home_endpoint,
                secret,
            )
            .await;
        }
        RemoteLifecycleControl::ZeroLeafLeaveNoLeaf
        | RemoteLifecycleControl::PendingInviteeZeroLeafLeave => {
            let pending = operation == RemoteLifecycleControl::PendingInviteeZeroLeafLeave;
            std::env::set_var("SERVICE_DID", SEQUENCER);
            let genuine = catbird_server::chat_protocol::test_support::
                seed_genuine_leafless_group_relay_fixture(&pool, REMOTE_HOME, true, !pending)
                    .await
                    .expect("genuine zero-leaf group fixture");
            std::env::set_var("SERVICE_DID", REMOTE_HOME);
            let departing_did = genuine.departing_did.as_ref().unwrap();
            let departing_device_id = genuine.departing_device_id.unwrap();
            let departing_key_id = genuine.departing_key_id.as_ref().unwrap();
            let departing_seed = genuine.departing_ed25519_seed.unwrap();
            let departing = fixture_device(departing_did, departing_device_id);
            http::cache_device_did(&departing).await;
            mirror_group_prefix_entries(
                &pool,
                &home_pool,
                genuine.conversation_id,
                genuine.entry_count,
                BTreeMap::from([
                    (genuine.admin_did.clone(), Some(SEQUENCER.to_owned())),
                    (departing_did.clone(), None),
                ]),
                ValidatedRemoteDestination {
                    url: format!("http://{sequencer_addr}").parse().unwrap(),
                    host: "127.0.0.1".to_owned(),
                    addrs: vec![sequencer_addr],
                },
            )
            .await;
            let prior = genuine.prior.clone();
            let mut next = prior.clone();
            next["stateVersion"] = json!(prior["stateVersion"].as_u64().unwrap() + 1);
            let transition_id = Uuid::new_v4();
            let zero_leaf_leave = sign_mutation_json_for_test(
                &json!({
                    "$type": "blue.catbird.chat.defs#zeroLeafLeaveBody",
                    "signatureDomain": "CATBIRD-CHAT-LEAVE-ZERO-LEAF\u{0000}",
                    "transitionId": transition_id,
                    "actorDid": departing_did,
                    "actorDeviceId": departing_device_id,
                    "keyId": departing_key_id,
                    "authGeneration": 1,
                    "prior": prior,
                    "next": next,
                    "idempotencyKey": transition_id,
                    "signedAt": Utc::now().to_rfc3339_opts(SecondsFormat::Millis, true),
                }),
                &SigningKey::from_bytes(&departing_seed),
            )
            .unwrap();
            let body = serde_json::to_vec(&json!({"signedRequest": zero_leaf_leave})).unwrap();
            let (status, first) = http::send_bytes(
                live_home_chat.clone(),
                http::unsigned_json_request(
                    &departing,
                    "blue.catbird.chat.requestLeave",
                    body.clone(),
                ),
            )
            .await;
            assert_eq!(
                status,
                StatusCode::OK,
                "valid zero-leaf leave through home: {}",
                String::from_utf8_lossy(&first)
            );
            let response: Value = serde_json::from_slice(&first).unwrap();
            assert!(
                response
                    .pointer("/entry/sequencerReceipt")
                    .or_else(|| response.pointer("/result/entry/sequencerReceipt"))
                    .is_some(),
                "sequencer response must carry the receipted leave entry: {response}"
            );
            let (replay_status, replay) = http::send_bytes(
                live_home_chat,
                http::unsigned_json_request(&departing, "blue.catbird.chat.requestLeave", body),
            )
            .await;
            assert_eq!(replay_status, StatusCode::OK);
            assert_eq!(replay, first);
            let current: bool = sqlx::query_scalar(
                "SELECT EXISTS(SELECT 1 FROM chat.participants \
                 WHERE conversation_id=$1 AND user_did=$2 AND current_membership)",
            )
            .bind(genuine.conversation_id)
            .bind(departing_did)
            .fetch_one(&pool)
            .await
            .unwrap();
            assert!(!current, "zero-leaf leave must remove the participant");
        }
    }
}

macro_rules! remote_lifecycle_control_test {
    ($name:ident, $operation:ident) => {
        #[cfg(feature = "sim")]
        #[tokio::test]
        async fn $name() {
            let _guard = REMOTE_LIFECYCLE_CONTROL_LOCK.lock().await;
            run_remote_lifecycle_relay_control(RemoteLifecycleControl::$operation).await;
        }
    };
}

remote_lifecycle_control_test!(remote_group_relay_leave_request, LeaveRequest);
remote_lifecycle_control_test!(remote_group_relay_cancel_leave, CancelLeave);
remote_lifecycle_control_test!(
    remote_group_relay_request_leaf_recovery,
    RequestLeafRecovery
);
remote_lifecycle_control_test!(remote_group_relay_cancel_leaf_recovery, CancelLeafRecovery);
remote_lifecycle_control_test!(
    remote_group_relay_leaf_recovery_fulfillment,
    LeafRecoveryFulfillment
);
remote_lifecycle_control_test!(
    remote_group_relay_zero_leaf_leave_without_remaining_leaf,
    ZeroLeafLeaveNoLeaf
);
remote_lifecycle_control_test!(
    remote_group_relay_pending_invitee_zero_leaf_leave,
    PendingInviteeZeroLeafLeave
);
remote_lifecycle_control_test!(
    remote_group_relay_close_conversation_declared_refusal,
    CloseConversationRefusal
);
remote_lifecycle_control_test!(
    remote_group_relay_sole_admin_close_success,
    CloseConversationSuccess
);
remote_lifecycle_control_test!(remote_group_relay_request_reset, RequestReset);
remote_lifecycle_control_test!(remote_group_relay_activate_reset, ActivateReset);

/// Receipt-less account-deletion rows remain exportable and carry the exact
/// authority-signed entry used by import verification.
#[tokio::test]
async fn get_convo_events_keeps_serving_a_group_after_an_account_deletion() {
    use axum::body::Body;
    use axum::http::Request;
    use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
    use base64::Engine as _;
    use catbird_server::auth::{
        cache_test_did_document, DidDocument, PublicKeyJwk, VerificationMethod,
    };
    use tower_util::ServiceExt as _;

    std::env::set_var("SERVICE_DID", SEQUENCER);
    std::env::set_var("SELF_ENDPOINT", "https://r3-reset-sequencer.example.com");
    let database = common::fresh_db::fresh_fully_migrated_db("chat_fed_relay_").await;
    let pool = database.connect(4).await;
    http::ensure_fence(&pool).await;
    let fixture = seed_clean_slate_application_fixture_with_sender_home(
        &pool,
        false,
        REMOTE_HOME,
        Some([0x91; 32]),
        None,
    )
    .await
    .expect("two-home group fixture");
    catbird_server::federation::open_federation_for_test();
    sqlx::query(
        "INSERT INTO federation_peers(ds_did,status,trust_score,max_requests_per_minute) \
         VALUES($1,'allow',100,100)",
    )
    .bind(REMOTE_HOME)
    .execute(&pool)
    .await
    .unwrap();

    let peer_key = p256::ecdsa::SigningKey::from_slice(&[0x5a; 32]).unwrap();
    let point = peer_key.verifying_key().to_encoded_point(false);
    let jwk: PublicKeyJwk = serde_json::from_value(json!({
        "kty": "EC",
        "crv": "P-256",
        "x": URL_SAFE_NO_PAD.encode(point.x().unwrap()),
        "y": URL_SAFE_NO_PAD.encode(point.y().unwrap()),
    }))
    .unwrap();
    cache_test_did_document(DidDocument {
        id: REMOTE_HOME.to_string(),
        verification_method: vec![VerificationMethod {
            id: format!("{REMOTE_HOME}#atproto"),
            key_type: "JsonWebKey2020".to_string(),
            controller: REMOTE_HOME.to_string(),
            public_key_jwk: Some(jwk),
            public_key_multibase: None,
        }],
        service: None,
    })
    .await;
    let router = axum::Router::new()
        .route(
            "/xrpc/blue.catbird.mlsDS.getConvoEvents",
            axum::routing::get(catbird_server::handlers::ds::get_convo_events),
        )
        .with_state(pool.clone());
    let export = || {
        let router = router.clone();
        let key = peer_key.clone();
        async move {
            let now = Utc::now().timestamp();
            let header = URL_SAFE_NO_PAD.encode(
                serde_json::to_vec(
                    &json!({"alg":"ES256","typ":"JWT","kid":format!("{REMOTE_HOME}#atproto")}),
                )
                .unwrap(),
            );
            let claims = URL_SAFE_NO_PAD.encode(
                serde_json::to_vec(&json!({
                    "iss": REMOTE_HOME,
                    "sub": REMOTE_HOME,
                    "aud": SEQUENCER,
                    "lxm": "blue.catbird.mlsDS.getConvoEvents",
                    "iat": now,
                    "exp": now + 60,
                    "jti": Uuid::new_v4().to_string(),
                }))
                .unwrap(),
            );
            let signing_input = format!("{header}.{claims}");
            let signature: p256::ecdsa::Signature =
                p256::ecdsa::signature::Signer::sign(&key, signing_input.as_bytes());
            let jwt = format!(
                "{signing_input}.{}",
                URL_SAFE_NO_PAD.encode(signature.to_bytes())
            );
            let response = router
                .oneshot(
                    Request::builder()
                        .method("GET")
                        .uri(format!(
                            "/xrpc/blue.catbird.mlsDS.getConvoEvents?convoId={}&afterSeq=0&limit=100",
                            fixture.conversation_id
                        ))
                        .header("authorization", format!("Bearer {jwt}"))
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            let status = response.status();
            let body = axum::body::to_bytes(response.into_body(), usize::MAX)
                .await
                .unwrap();
            (
                status,
                serde_json::from_slice::<Value>(&body).unwrap_or(Value::Null),
            )
        }
    };
    let peer_row = |pool: sqlx::PgPool| async move {
        sqlx::query_as::<_, (String, i32, i64)>(
            "SELECT status,trust_score,rejected_request_count \
             FROM federation_peers WHERE ds_did=$1",
        )
        .bind(REMOTE_HOME)
        .fetch_one(&pool)
        .await
        .unwrap()
    };
    let peer_before = peer_row(pool.clone()).await;

    let (status, page) = export().await;
    assert_eq!(status, StatusCode::OK, "{page}");
    let initial_events = page["events"].as_array().unwrap();
    assert!(
        !initial_events.is_empty()
            && initial_events
                .iter()
                .all(|event| event["sequencerReceipt"].is_object())
    );

    catbird_server::labyrinth::repo::retention::delete_account_data_with_conversations(
        &pool,
        &fixture.sender_did,
        Utc::now(),
        Some(&common::proof_i13_signer()),
    )
    .await
    .expect("account deletion");

    let mut statuses = Vec::new();
    let mut final_page = Value::Null;
    for _ in 0..27 {
        let (status, page) = export().await;
        statuses.push(status);
        final_page = page;
    }
    assert!(
        statuses.iter().all(|status| *status == StatusCode::OK),
        "account-deletion history export statuses: {statuses:?}"
    );
    let deletion = final_page["events"]
        .as_array()
        .unwrap()
        .iter()
        .find(|event| event["entryKind"] == "blue.catbird.chat.defs#accountDeletedEntry")
        .expect("account-deletion event is exported");
    assert!(deletion["sequencerReceipt"].is_null());
    assert!(deletion["accountDeletedEntry"]["sequencerAuthority"].is_object());

    use catbird_server::federation::reconciliation::{
        verify_remote_event_receipt, verify_remote_event_receipt_from_peer, RemoteEvent,
        StrictCleanRemoteEvent,
    };
    let proof_signer = common::proof_i13_signer();
    let proof_key = proof_signer.verifying_key();
    let resolver = catbird_server::federation::resolver::DsResolver::new(
        pool.clone(),
        catbird_server::federation::resolver::build_resolver_http_client(),
        REMOTE_HOME.to_owned(),
        "https://r3-reset-home.example.com".to_owned(),
        None,
        300,
    );
    let events = final_page["events"].as_array().unwrap();
    let mut keys = std::collections::HashMap::from([(proof_signer.key_id().to_owned(), proof_key)]);
    let mut receipt_coordinate = None;
    let mut deletion_predecessor = None;
    for event in events {
        if event["entryKind"] == "blue.catbird.chat.defs#accountDeletedEntry" {
            deletion_predecessor = receipt_coordinate.clone();
        }
        let strict = StrictCleanRemoteEvent::try_from(
            serde_json::from_value::<RemoteEvent>(event.clone()).unwrap(),
        )
        .unwrap();
        receipt_coordinate = Some(
            verify_remote_event_receipt(
                &resolver,
                SEQUENCER,
                fixture.conversation_id,
                &strict,
                &mut keys,
                receipt_coordinate.as_ref(),
            )
            .await
            .expect("importer verifies every exported event"),
        );
    }
    let mut mismatched_deletion = deletion.clone();
    let payload_bytes = STANDARD
        .decode(
            mismatched_deletion
                .pointer("/ciphertext/$bytes")
                .and_then(Value::as_str)
                .unwrap(),
        )
        .unwrap();
    let mut payload: Value = serde_json::from_slice(&payload_bytes).unwrap();
    payload["entryId"] = json!(Uuid::new_v4());
    let payload_bytes = serde_json::to_vec(&payload).unwrap();
    mismatched_deletion["ciphertext"] = json!({"$bytes": STANDARD.encode(&payload_bytes)});
    mismatched_deletion["signedRequest"] = json!({"$bytes": STANDARD.encode(&payload_bytes)});
    mismatched_deletion["acceptedPayloadSha256"] =
        json!({"$bytes": STANDARD.encode(sha2::Sha256::digest(&payload_bytes))});
    let mismatched = StrictCleanRemoteEvent::try_from(
        serde_json::from_value::<RemoteEvent>(mismatched_deletion).unwrap(),
    )
    .unwrap();
    let mut binding_keys = std::collections::HashMap::from([(
        proof_signer.key_id().to_owned(),
        proof_signer.verifying_key(),
    )]);
    assert!(
        verify_remote_event_receipt(
            &resolver,
            SEQUENCER,
            fixture.conversation_id,
            &mismatched,
            &mut binding_keys,
            deletion_predecessor.as_ref(),
        )
        .await
        .is_err(),
        "account-deletion event fields must remain bound to its signed entry"
    );
    let mut forged_deletion = deletion.clone();
    forged_deletion["accountDeletedEntry"]["sequencerAuthority"]["signature"] =
        json!({"$bytes": STANDARD.encode([0_u8; 64])});
    let forged = StrictCleanRemoteEvent::try_from(
        serde_json::from_value::<RemoteEvent>(forged_deletion).unwrap(),
    )
    .unwrap();
    let importer_database = common::fresh_db::fresh_fully_migrated_db("chat_fed_relay_").await;
    let importer_pool = importer_database.connect(4).await;
    http::ensure_fence(&importer_pool).await;
    sqlx::query(
        "INSERT INTO federation_peers(ds_did,status,trust_score,max_requests_per_minute) \
         VALUES($1,'allow',100,100)",
    )
    .bind(SEQUENCER)
    .execute(&importer_pool)
    .await
    .unwrap();
    let importer_resolver = catbird_server::federation::resolver::DsResolver::new(
        importer_pool.clone(),
        catbird_server::federation::resolver::build_resolver_http_client(),
        REMOTE_HOME.to_owned(),
        "https://r3-reset-home.example.com".to_owned(),
        None,
        300,
    );
    let mut forged_keys = std::collections::HashMap::from([(
        proof_signer.key_id().to_owned(),
        proof_signer.verifying_key(),
    )]);
    assert!(
        verify_remote_event_receipt_from_peer(
            &importer_pool,
            &importer_resolver,
            SEQUENCER,
            fixture.conversation_id,
            &forged,
            &mut forged_keys,
            deletion_predecessor.as_ref(),
        )
        .await
        .is_err(),
        "a forged account-deletion authority must be rejected"
    );
    let exporter_after: (String, i32, i64) = sqlx::query_as(
        "SELECT status,trust_score,rejected_request_count \
         FROM federation_peers WHERE ds_did=$1",
    )
    .bind(SEQUENCER)
    .fetch_one(&importer_pool)
    .await
    .unwrap();
    assert_eq!(
        exporter_after,
        ("allow".to_owned(), 95, 1),
        "the importer must charge the exporter that supplied the forged proof"
    );
    let peer_after = peer_row(pool.clone()).await;
    assert_eq!(peer_after.0, peer_before.0, "requester status changed");
    assert_eq!(
        peer_after.2, peer_before.2,
        "the server's receipt-less row penalised the requester"
    );
    assert!(
        peer_after.1 >= peer_before.1,
        "the server's receipt-less row lowered requester trust"
    );
}
