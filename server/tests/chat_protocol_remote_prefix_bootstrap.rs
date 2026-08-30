//! Integration tests for canonical remote-prefix bootstrap admission.

mod common;

pub use catbird_server::{auth, crypto, federation, handlers, identity, sqlx_jacquard, util};

#[path = "common/chat_protocol_harness.rs"]
mod chat_protocol;

mod repository {
    pub(crate) use crate::chat_protocol::repository::*;
}

#[allow(dead_code)]
mod snapshot {
    pub use catbird_server::chat_protocol::snapshot::*;
}

#[path = "common/executor_seed.rs"]
mod executor_seed;
use executor_seed::*;

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use axum::extract::Query;
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Json};
use axum::routing::get;
use axum::Router;
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use base64::Engine;
use chrono::{DateTime, SecondsFormat, Utc};
use ed25519_dalek::{Signer, SigningKey};
use jsonwebtoken::{decode, Algorithm, DecodingKey, Validation};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use sqlx::PgPool;
use tokio::net::TcpListener;
use tokio::sync::Mutex;
use uuid::Uuid;

use crate::chat_protocol::state_machine::{DeviceIdentity, PrincipalId};
use catbird_server::chat_protocol::repository::remote_prefix::test_support::{
    derive_bootstrap_local_id_for_test, test_apply_historical_acceptance_entry,
    test_apply_historical_creation_entry, test_apply_historical_policy_entry,
    test_apply_historical_recovery_fulfillment_entry, test_apply_remote_clean_prefix,
    test_verify_historical_authority,
};
use catbird_server::chat_protocol::snapshot::{
    PublicGroupSnapshotCoordinate, PublicGroupSnapshotLifecycle,
};
use catbird_server::db::DbConfig;
use catbird_server::federation::bootstrap::{
    bootstrap_remote_mailbox_from_selector, compute_bootstrap_advisory_lock_key,
    fetch_remote_prefix_admission, QuarantineReason, RemoteDigestAnchor, RemotePrefixApplyOutcome,
    RemotePrefixBootstrapError, RemotePrefixBootstrapSelector, VerifiedRemotePrefixAdmission,
};
use catbird_server::federation::reconciliation::StrictCleanRemoteEvent;
use catbird_server::federation::resolver::{DsResolver, ValidatedRemoteDestination};
use catbird_server::federation::service_auth::{ServiceAuthClaims, ServiceAuthClient};
use catbird_server::federation::{
    outbound::OutboundClient, CAPABILITY_CANONICAL_PREFIX_BOOTSTRAP_V1,
    CAPABILITY_RECONCILIATION_V1,
};
use catbird_server::handlers::ds::get_convo_digest::CleanConvoDigestHasher;
use executor_seed::genuine_terminal_fixture::{
    coordinate_json, AcceptanceInvitee, GenuinePolicyChange, GenuinePolicyControl,
    RealAcceptanceEntry, RealLeafRecoveryFulfillmentEntry,
};

const BOOTSTRAP_DB_PREFIX: &str = "chat_remoteprefix_";

const DIGEST_NSID: &str = "blue.catbird.mlsDS.getConvoDigest";
const EVENTS_NSID: &str = "blue.catbird.mlsDS.getConvoEvents";
const HEALTH_CHECK_NSID: &str = "blue.catbird.mlsDS.healthCheck";

const CREATION_ENTRY_TYPE_ID: &str = "blue.catbird.chat.defs#creationEntry";
const PARTICIPANT_ACCEPTANCE_ENTRY_TYPE_ID: &str =
    "blue.catbird.chat.defs#participantAcceptanceEntry";
const LEAF_RECOVERY_FULFILLMENT_ENTRY_TYPE_ID: &str =
    "blue.catbird.chat.defs#leafRecoveryFulfillmentEntry";

const POLICY_ENTRY_TYPE_ID: &str = "blue.catbird.chat.defs#policyEntry";
const APPLICATION_ENTRY_TYPE_ID: &str = "blue.catbird.chat.defs#applicationEntry";

pub use common::chat_protocol::{snapshot_db_content, DbContentSnapshot};

fn configure_security_env() {
    std::env::set_var("SERVICE_DID", "did:web:destination.catbird.blue");
    std::env::set_var("ENFORCE_LXM", "true");
    std::env::set_var("ENFORCE_JTI", "true");
    std::env::set_var("JTI_TTL_SECONDS", "120");
}

async fn setup_test_db() -> Option<(PgPool, common::fresh_db::DisposableDatabase)> {
    if std::env::var("TEST_DATABASE_URL").is_err() {
        eprintln!("Skipping test: TEST_DATABASE_URL not set");
        return None;
    }

    configure_security_env();

    let database = common::fresh_db::fresh_fully_migrated_db(BOOTSTRAP_DB_PREFIX).await;
    let config = DbConfig {
        database_url: database.url().to_owned(),
        max_connections: 5,
        min_connections: 1,
        acquire_timeout: Duration::from_secs(20),
        idle_timeout: Duration::from_secs(60),
    };
    let pool = catbird_server::db::init_db(config)
        .await
        .expect("init test db pool");
    Some((pool, database))
}

async fn seed_test_device(pool: &PgPool, user_did: &str, device_id: Uuid, status: &str) {
    let now = Utc::now();
    let dpop_jkt = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";

    sqlx::query(
        "INSERT INTO chat.principals (user_did, created_at) \
         VALUES ($1, $2) ON CONFLICT (user_did) DO NOTHING",
    )
    .bind(user_did)
    .bind(now)
    .execute(pool)
    .await
    .expect("seed principal");

    if status == "active" {
        sqlx::query(
            "INSERT INTO chat.devices (user_did, device_id, device_name, status, dpop_jkt, auth_generation, capabilities, created_at, updated_at) \
             VALUES ($1, $2, 'Test Device', 'active', $3, 1, chat.protocol_capabilities(), $4, $4) \
             ON CONFLICT (user_did, device_id) DO UPDATE SET status = 'active', revoked_at = NULL, revocation_id = NULL",
        )
        .bind(user_did)
        .bind(device_id)
        .bind(dpop_jkt)
        .bind(now)
        .execute(pool)
        .await
        .expect("seed active device");
    } else if status == "revoked" {
        seed_revoked_device(
            pool,
            user_did,
            device_id,
            now - chrono::Duration::minutes(1),
        )
        .await;
    } else {
        panic!("unsupported test device status: {status}");
    }
}

async fn seed_revoked_device(pool: &PgPool, did: &str, device_id: Uuid, created_at: DateTime<Utc>) {
    let jkt = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
    let existing_key_id: Option<String> = sqlx::query_scalar(
        "SELECT key_id FROM chat.device_keys WHERE user_did = $1 AND device_id = $2",
    )
    .bind(did)
    .bind(device_id)
    .fetch_optional(pool)
    .await
    .expect("fetch existing key id");

    let key_id = match existing_key_id {
        Some(k) => k,
        None => {
            let public_key = [7u8; 32];
            let k: String = sqlx::query_scalar("SELECT chat.ed25519_key_id($1)")
                .bind(&public_key[..])
                .fetch_one(pool)
                .await
                .expect("derive key id");

            sqlx::query(
                "INSERT INTO chat.principals (user_did, created_at) \
                 VALUES ($1, $2) ON CONFLICT (user_did) DO NOTHING",
            )
            .bind(did)
            .bind(created_at)
            .execute(pool)
            .await
            .expect("insert principal");

            sqlx::query(
                "INSERT INTO chat.devices(user_did, device_id, device_name, status, dpop_jkt, auth_generation, capabilities, created_at, updated_at) \
                 VALUES($1, $2, 'dev-revoked', 'active', $3, 1, chat.protocol_capabilities(), $4, $4) \
                 ON CONFLICT (user_did, device_id) DO NOTHING",
            )
            .bind(did)
            .bind(device_id)
            .bind(jkt)
            .bind(created_at)
            .execute(pool)
            .await
            .expect("insert active device to revoke");

            sqlx::query(
                "INSERT INTO chat.device_keys(user_did, device_id, key_id, signing_public_key, enrollment_auth_generation, created_at) \
                 VALUES($1, $2, $3, $4, 1, $5) \
                 ON CONFLICT (user_did, device_id) DO NOTHING",
            )
            .bind(did)
            .bind(device_id)
            .bind(&k)
            .bind(&public_key[..])
            .bind(created_at)
            .execute(pool)
            .await
            .expect("insert device key");
            k
        }
    };
    let accepted_at = created_at + chrono::Duration::seconds(30);
    let revocation_id = Uuid::new_v4();
    let accepted_request_bytes =
        br#"{"body":{"$type":"blue.catbird.chat.defs#deviceRevocationBody"}}"#.to_vec();
    let accepted_request_sha256: [u8; 32] = Sha256::digest(&accepted_request_bytes).into();
    let mut signing_transcript_bytes = b"CATBIRD-CHAT-DEVICE-REVOKE\0".to_vec();
    signing_transcript_bytes.extend_from_slice(&[8u8; 32]);
    let request_digest: [u8; 32] = Sha256::digest(&signing_transcript_bytes).into();
    let signature = [3u8; 64];
    let response = br#"{"revoked":true}"#;
    let response_sha256: [u8; 32] = Sha256::digest(response).into();

    let mut tx = pool.begin().await.expect("begin revocation");
    sqlx::query(
        r#"
        INSERT INTO chat.operation_claims (
            operation_id, principal_did, endpoint_nsid, mutation_kind,
            request_digest, accepted_request_sha256, signature, claimed_at
        ) VALUES ($1, $2, 'blue.catbird.chat.revokeDevice',
                  'blue.catbird.chat.defs#deviceRevocationBody', $3, $4, $5, $6)
        "#,
    )
    .bind(revocation_id)
    .bind(did)
    .bind(request_digest.as_slice())
    .bind(accepted_request_sha256.as_slice())
    .bind(signature.as_slice())
    .bind(accepted_at)
    .execute(&mut *tx)
    .await
    .expect("insert revokeDevice operation claim");

    sqlx::query(
        r#"
        INSERT INTO chat.idempotency_records (
            principal_did, endpoint_nsid, operation_id, request_digest,
            accepted_request_bytes, signing_transcript_bytes, signature,
            completed_status, response_bytes, response_sha256,
            historical_jkt, completed_at
        ) VALUES ($1, 'blue.catbird.chat.revokeDevice', $2, $3, $4, $5, $6, 200, $7, $8, $9, $10)
        "#,
    )
    .bind(did)
    .bind(revocation_id)
    .bind(request_digest.as_slice())
    .bind(&accepted_request_bytes)
    .bind(&signing_transcript_bytes)
    .bind(signature.as_slice())
    .bind(response.as_slice())
    .bind(response_sha256.as_slice())
    .bind(jkt)
    .bind(accepted_at)
    .execute(&mut *tx)
    .await
    .expect("insert revokeDevice receipt");

    sqlx::query(
        r#"
        INSERT INTO chat.device_revocations (
            revocation_id, actor_did, actor_device_id, actor_key_id,
            actor_auth_generation, target_did, target_device_id,
            target_auth_generation, accepted_request_bytes,
            signing_transcript_bytes, request_digest, signature,
            signed_at, accepted_at
        ) VALUES ($1, $2, $3, $4, 1, $2, $3, 1, $5, $6, $7, $8, $9, $9)
        "#,
    )
    .bind(revocation_id)
    .bind(did)
    .bind(device_id)
    .bind(&key_id)
    .bind(&accepted_request_bytes)
    .bind(&signing_transcript_bytes)
    .bind(request_digest.as_slice())
    .bind(signature.as_slice())
    .bind(accepted_at)
    .execute(&mut *tx)
    .await
    .expect("insert device revocation");

    sqlx::query(
        "UPDATE chat.devices SET status='revoked', updated_at=$3, revoked_at=$3, revocation_id=$4 \
         WHERE user_did=$1 AND device_id=$2",
    )
    .bind(did)
    .bind(device_id)
    .bind(accepted_at)
    .bind(revocation_id)
    .execute(&mut *tx)
    .await
    .expect("revoke target device");

    sqlx::query(
        "UPDATE chat.device_keys SET revoked_at=$3, revocation_id=$4 \
         WHERE user_did=$1 AND device_id=$2",
    )
    .bind(did)
    .bind(device_id)
    .bind(accepted_at)
    .bind(revocation_id)
    .execute(&mut *tx)
    .await
    .expect("revoke target device key");

    tx.commit().await.expect("commit revocation");
}

async fn seed_approved_peer(pool: &PgPool, ds_did: &str) {
    sqlx::query(
        "INSERT INTO federation_peers (ds_did, status, max_requests_per_minute, trust_score, rejected_request_count, invalid_token_count, created_at, updated_at) \
         VALUES ($1, 'allow', 100, 100, 0, 0, NOW(), NOW()) \
         ON CONFLICT (ds_did) DO UPDATE SET status = 'allow', updated_at = NOW()",
    )
    .bind(ds_did)
    .execute(pool)
    .await
    .expect("seed approved peer");
}

fn build_test_signed_creation(
    convo_id: Uuid,
    actor_did: &str,
    actor_device_id: Uuid,
    participant_dids: &[&str],
    now: DateTime<Utc>,
) -> Vec<u8> {
    let mut participants_json: Vec<Value> = participant_dids
        .iter()
        .map(|did| {
            json!({
                "userDid": did,
                "status": "active",
                "role": "admin"
            })
        })
        .collect();
    participants_json.sort_by(|a, b| a["userDid"].as_str().cmp(&b["userDid"].as_str()));

    let transition_id = Uuid::new_v4();
    let group_id = [1u8; 32];
    let group_context_hash = [2u8; 32];
    let confirmation_tag_32 = [3u8; 32];
    let metadata_ciphertext = [0x99u8; 32];
    let genesis_group_info = [0x42u8; 32];
    let key_id = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
    let signed_at = now.to_rfc3339_opts(SecondsFormat::Millis, true);

    let body = json!({
        "$type": "blue.catbird.chat.defs#creationBody",
        "signatureDomain": "CATBIRD-CHAT-CREATE\u{0000}",
        "conversationId": convo_id.to_string(),
        "transitionId": transition_id.to_string(),
        "conversationKind": "direct",
        "absence": true,
        "actorDid": actor_did,
        "actorDeviceId": actor_device_id.to_string(),
        "authGeneration": 1,
        "idempotencyKey": transition_id.to_string(),
        "keyId": key_id,
        "signedAt": signed_at,
        "manifest": {
            "actorLeaf": {
                "userDid": actor_did,
                "deviceId": actor_device_id.to_string(),
                "leafOrigin": "genesis"
            },
            "participants": participants_json
        },
        "genesisGroupInfo": {
            "framing": "mlsMessage",
            "contentType": "groupInfo",
            "bytes": STANDARD.encode(genesis_group_info),
            "sha256": STANDARD.encode(Sha256::digest(genesis_group_info))
        },
        "next": {
            "conversationId": convo_id.to_string(),
            "generation": 0,
            "stateVersion": 0,
            "groupId": STANDARD.encode(group_id),
            "epoch": 0,
            "groupContextHash": STANDARD.encode(group_context_hash),
            "confirmationTag": STANDARD.encode(confirmation_tag_32),
            "lifecycle": "active"
        },
        "metadataSnapshot": {
            "coordinate": {
                "conversationId": STANDARD.encode(convo_id.as_bytes()),
                "generation": 0,
                "groupId": STANDARD.encode(group_id),
                "epoch": 0,
                "groupContextHash": STANDARD.encode(group_context_hash),
                "confirmationTag": STANDARD.encode(confirmation_tag_32),
            },
            "originTransitionId": transition_id.to_string(),
            "metadataVersion": 1,
            "nonce": STANDARD.encode([0x73_u8; 12]),
            "ciphertext": STANDARD.encode(metadata_ciphertext),
            "ciphertextSha256": STANDARD.encode(Sha256::digest(metadata_ciphertext)),
            "ciphertextSize": metadata_ciphertext.len(),
            "authorProof": {
                "authorDid": actor_did,
                "authorDeviceId": actor_device_id.to_string(),
                "authorKeyId": key_id,
                "signaturePublicKey": STANDARD.encode([0u8; 32]),
                "authGenerationAtOrigin": 1,
                "originTransitionId": transition_id.to_string(),
                "originSeq": 1,
                "roleAtOrigin": "admin",
                "deviceStatusAtOrigin": "active",
            },
        }
    });

    let wrapper = json!({
        "body": body,
        "signature": STANDARD.encode([0u8; 64]),
    });
    serde_json::to_vec(&wrapper).expect("serialize signed creation")
}
fn build_test_signed_policy(
    convo_id: Uuid,
    actor_did: &str,
    actor_device_id: Uuid,
    participant_changes: Vec<Value>,
    now: DateTime<Utc>,
) -> Vec<u8> {
    let transition_id = Uuid::new_v4();
    let group_id = [1u8; 32];
    let group_context_hash = [2u8; 32];
    let confirmation_tag = [3u8; 32];
    let key_id = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
    let signed_at = now.to_rfc3339_opts(SecondsFormat::Millis, true);

    let prior_coordinate = json!({
        "conversationId": convo_id.to_string(),
        "generation": 0,
        "groupId": STANDARD.encode(group_id),
        "epoch": 0,
        "groupContextHash": STANDARD.encode(group_context_hash),
        "confirmationTag": STANDARD.encode(confirmation_tag),
        "stateVersion": 0,
    });

    let next_coordinate = json!({
        "conversationId": convo_id.to_string(),
        "generation": 0,
        "groupId": STANDARD.encode(group_id),
        "epoch": 0,
        "groupContextHash": STANDARD.encode(group_context_hash),
        "confirmationTag": STANDARD.encode(confirmation_tag),
        "stateVersion": 1,
        "lifecycle": "active"
    });

    let body = json!({
        "$type": "blue.catbird.chat.defs#policyTransitionBody",
        "signatureDomain": "CATBIRD-CHAT-POLICY\u{0000}",
        "conversationId": convo_id.to_string(),
        "transitionId": transition_id.to_string(),
        "actorDid": actor_did,
        "actorDeviceId": actor_device_id.to_string(),
        "keyId": key_id,
        "authGeneration": 1,
        "prior": prior_coordinate,
        "next": next_coordinate,
        "participantChanges": participant_changes,
        "idempotencyKey": transition_id.to_string(),
        "signedAt": signed_at,
    });

    let wrapper = json!({
        "body": body,
        "signature": STANDARD.encode([0u8; 64]),
    });
    serde_json::to_vec(&wrapper).expect("serialize signed policy")
}

fn build_test_event_json(
    seq: i64,
    epoch: i64,
    entry_id: Uuid,
    entry_kind_type_id: &str,
    ciphertext: &[u8],
    signed_request: &[u8],
    outer_fingerprint: &[u8; 32],
    received_at: DateTime<Utc>,
) -> Value {
    let payload_sha256: [u8; 32] = Sha256::digest(ciphertext).into();
    json!({
        "seq": seq,
        "epoch": epoch,
        "msgId": entry_id.to_string(),
        "messageType": entry_kind_type_id,
        "ciphertext": {"$bytes": STANDARD.encode(ciphertext)},
        "paddedSize": ciphertext.len() as i64,
        "createdAt": received_at.to_rfc3339_opts(SecondsFormat::Millis, true),
        "entryId": entry_id.to_string(),
        "entryKind": entry_kind_type_id,
        "acceptedPayloadSha256": {"$bytes": STANDARD.encode(&payload_sha256)},
        "signedRequest": {"$bytes": STANDARD.encode(signed_request)},
        "outerFingerprint": {"$bytes": STANDARD.encode(outer_fingerprint)},
    })
}

#[derive(Clone, Default)]
struct MockSequencerState {
    capabilities: Vec<String>,
    opening_digest: Option<Value>,
    closing_digest: Option<Value>,
    events_pages: Vec<Value>,
    recorded_requests: Arc<Mutex<Vec<(String, Option<String>)>>>,
    destination_hits: Arc<AtomicUsize>,
}

async fn spawn_mock_sequencer(state: MockSequencerState) -> (ValidatedRemoteDestination, String) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let local_addr = listener.local_addr().unwrap();

    let state_for_router = state.clone();
    let app = Router::new()
        .route(
            &format!("/xrpc/{}", HEALTH_CHECK_NSID),
            get({
                let state = state_for_router.clone();
                move |headers: HeaderMap| {
                    let state = state.clone();
                    async move {
                        state.destination_hits.fetch_add(1, Ordering::SeqCst);
                        let auth = headers
                            .get("authorization")
                            .and_then(|h| h.to_str().ok())
                            .map(|s| s.to_string());
                        state
                            .recorded_requests
                            .lock()
                            .await
                            .push((HEALTH_CHECK_NSID.to_string(), auth));
                        Json(json!({
                            "capabilities": state.capabilities
                        }))
                    }
                }
            }),
        )
        .route(
            &format!("/xrpc/{}", DIGEST_NSID),
            get({
                let state = state_for_router.clone();
                let call_count = Arc::new(AtomicUsize::new(0));
                move |headers: HeaderMap| {
                    let state = state.clone();
                    let call_count = call_count.clone();
                    async move {
                        state.destination_hits.fetch_add(1, Ordering::SeqCst);
                        let count = call_count.fetch_add(1, Ordering::SeqCst);
                        let auth = headers
                            .get("authorization")
                            .and_then(|h| h.to_str().ok())
                            .map(|s| s.to_string());
                        state
                            .recorded_requests
                            .lock()
                            .await
                            .push((DIGEST_NSID.to_string(), auth));
                        if count == 0 {
                            if let Some(d) = &state.opening_digest {
                                (StatusCode::OK, Json(d.clone())).into_response()
                            } else {
                                StatusCode::NOT_FOUND.into_response()
                            }
                        } else {
                            let digest = state
                                .closing_digest
                                .as_ref()
                                .or(state.opening_digest.as_ref());
                            if let Some(d) = digest {
                                (StatusCode::OK, Json(d.clone())).into_response()
                            } else {
                                StatusCode::NOT_FOUND.into_response()
                            }
                        }
                    }
                }
            }),
        )
        .route(
            &format!("/xrpc/{}", EVENTS_NSID),
            get({
                let state = state_for_router.clone();
                move |headers: HeaderMap, Query(params): Query<BTreeMap<String, String>>| {
                    let state = state.clone();
                    async move {
                        state.destination_hits.fetch_add(1, Ordering::SeqCst);
                        let auth = headers
                            .get("authorization")
                            .and_then(|h| h.to_str().ok())
                            .map(|s| s.to_string());
                        state
                            .recorded_requests
                            .lock()
                            .await
                            .push((EVENTS_NSID.to_string(), auth));
                        let after_seq: i64 = params
                            .get("afterSeq")
                            .and_then(|s| s.parse().ok())
                            .unwrap_or(0);
                        for page in &state.events_pages {
                            if let Some(from) =
                                page.get("fromSeqExclusive").and_then(|v| v.as_i64())
                            {
                                if from == after_seq {
                                    return (StatusCode::OK, Json(page.clone())).into_response();
                                }
                            }
                        }
                        if let Some(page) = state.events_pages.first() {
                            (StatusCode::OK, Json(page.clone())).into_response()
                        } else {
                            StatusCode::NOT_FOUND.into_response()
                        }
                    }
                }
            }),
        );

    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });

    let destination = ValidatedRemoteDestination {
        url: url::Url::parse(&format!("http://127.0.0.1:{}", local_addr.port())).unwrap(),
        host: "127.0.0.1".to_string(),
        addrs: vec![local_addr],
    };
    (
        destination,
        format!("http://127.0.0.1:{}", local_addr.port()),
    )
}

fn create_test_resolver(
    pool: PgPool,
    destination: ValidatedRemoteDestination,
    sequencer_did: &str,
) -> DsResolver {
    let dest_clone = destination.clone();
    let seq_did_owned = sequencer_did.to_string();
    DsResolver::new(
        pool,
        reqwest::Client::new(),
        "did:web:destination.catbird.blue".to_string(),
        "https://destination.catbird.blue".to_string(),
        None,
        3600,
    )
    .with_destination_resolver_hook(Arc::new(move |target: &str| {
        let dest = dest_clone.clone();
        if target == seq_did_owned || target.starts_with("http") {
            Some(Box::pin(async move { Ok(dest) }))
        } else {
            None
        }
    }))
    .with_user_did_resolver_hook(Arc::new(|user_did: &str| {
        let endpoint = if user_did == "did:web:remote-participant.catbird.blue" {
            catbird_server::federation::resolver::DsEndpoint {
                did: "did:web:remote-seq.catbird.blue".to_string(),
                endpoint: "https://remote-seq.catbird.blue".to_string(),
                supported_cipher_suites: None,
                federation_capabilities: None,
            }
        } else if user_did.starts_with("did:plc:") {
            catbird_server::federation::resolver::DsEndpoint {
                did: "did:web:destination.catbird.blue".to_string(),
                endpoint: "https://destination.catbird.blue".to_string(),
                supported_cipher_suites: None,
                federation_capabilities: None,
            }
        } else {
            return None;
        };
        Some(Ok(endpoint))
    }))
}

// 1. Selector validation tests
#[test]
fn admission_selector_accepts_term_0_and_max_safe_integer_rejects_invalid() {
    let convo_id = Uuid::new_v4();
    let valid_did = "did:web:sequencer.catbird.blue".to_string();

    assert!(RemotePrefixBootstrapSelector::new(convo_id, valid_did.clone(), 0).is_ok());
    assert!(RemotePrefixBootstrapSelector::new(convo_id, valid_did.clone(), 1).is_ok());
    assert!(
        RemotePrefixBootstrapSelector::new(convo_id, valid_did.clone(), 9007199254740991).is_ok()
    );

    assert_eq!(
        RemotePrefixBootstrapSelector::new(convo_id, valid_did.clone(), -1).unwrap_err(),
        RemotePrefixBootstrapError::InvalidSelector
    );
    assert_eq!(
        RemotePrefixBootstrapSelector::new(convo_id, valid_did.clone(), 9007199254740992)
            .unwrap_err(),
        RemotePrefixBootstrapError::InvalidSelector
    );
    assert_eq!(
        RemotePrefixBootstrapSelector::new(convo_id, "not-a-did".to_string(), 0).unwrap_err(),
        RemotePrefixBootstrapError::InvalidSelector
    );
}

// 2. Type guarantees: move-only semantics and no raw literal construction
#[test]
fn admission_raw_event_json_cannot_construct_admission() {
    fn _assert_move_only(admission: VerifiedRemotePrefixAdmission) -> Uuid {
        let moved = admission;
        moved.conversation_id()
    }
}

// 3. One retained destination across every query
#[tokio::test]
async fn admission_retains_single_destination_across_all_queries() {
    let Some((pool, _db_guard)) = setup_test_db().await else {
        return;
    };

    let convo_id = Uuid::new_v4();
    let sequencer_did = "did:web:seq.catbird.blue";
    let local_participant_did = "did:web:destination.catbird.blue";
    let local_device_id = Uuid::new_v4();

    seed_test_device(&pool, local_participant_did, local_device_id, "active").await;
    seed_approved_peer(&pool, sequencer_did).await;

    let now = Utc::now();
    let creation_signed = build_test_signed_creation(
        convo_id,
        local_participant_did,
        local_device_id,
        &[local_participant_did],
        now,
    );

    let entry_1 = Uuid::new_v4();
    let entry_2 = Uuid::new_v4();
    let entry_3 = Uuid::new_v4();

    let fp_1 = [1u8; 32];
    let fp_2 = [2u8; 32];
    let fp_3 = [3u8; 32];

    let ev1 = build_test_event_json(
        1,
        0,
        entry_1,
        CREATION_ENTRY_TYPE_ID,
        b"payload-1",
        &creation_signed,
        &fp_1,
        now,
    );
    let ev2 = build_test_event_json(
        2,
        0,
        entry_2,
        PARTICIPANT_ACCEPTANCE_ENTRY_TYPE_ID,
        b"payload-2",
        b"{\"signed\":{}}",
        &fp_2,
        now,
    );
    let ev3 = build_test_event_json(
        3,
        0,
        entry_3,
        LEAF_RECOVERY_FULFILLMENT_ENTRY_TYPE_ID,
        b"payload-3",
        b"{\"signed\":{}}",
        &fp_3,
        now,
    );

    let mut hasher = CleanConvoDigestHasher::new();

    hasher.update_event(
        1,
        0,
        entry_1,
        CREATION_ENTRY_TYPE_ID,
        b"payload-1",
        &creation_signed,
        &fp_1,
        now,
    );
    hasher.update_event(
        2,
        0,
        entry_2,
        PARTICIPANT_ACCEPTANCE_ENTRY_TYPE_ID,
        b"payload-2",
        b"{\"signed\":{}}",
        &fp_2,
        now,
    );
    hasher.update_event(
        3,
        0,
        entry_3,
        LEAF_RECOVERY_FULFILLMENT_ENTRY_TYPE_ID,
        b"payload-3",
        b"{\"signed\":{}}",
        &fp_3,
        now,
    );
    let digest_hex = hasher.finalize();

    let digest_json = json!({
        "convoId": convo_id.to_string(),
        "sequencerDsDid": sequencer_did,
        "sequencerTerm": 0,
        "epoch": 0,
        "lastSeq": 3,
        "eventCount": 3,
        "digestSha256": digest_hex,
        "generatedAt": now.to_rfc3339_opts(SecondsFormat::Millis, true)
    });

    let events_page = json!({
        "convoId": convo_id.to_string(),
        "fromSeqExclusive": 0,
        "toSeqInclusive": 3,
        "events": [ev1, ev2, ev3]
    });

    let mock_state = MockSequencerState {
        capabilities: vec![
            CAPABILITY_RECONCILIATION_V1.to_string(),
            CAPABILITY_CANONICAL_PREFIX_BOOTSTRAP_V1.to_string(),
        ],
        opening_digest: Some(digest_json.clone()),
        closing_digest: Some(digest_json),
        events_pages: vec![events_page],
        recorded_requests: Arc::new(Mutex::new(Vec::new())),
        destination_hits: Arc::new(AtomicUsize::new(0)),
    };

    let hits_counter = mock_state.destination_hits.clone();
    let (dest, _url) = spawn_mock_sequencer(mock_state).await;

    let resolver = create_test_resolver(pool.clone(), dest, sequencer_did);
    let outbound = OutboundClient::new(2, 2);

    let auth_client = ServiceAuthClient::from_shared_secret(
        "did:web:destination.catbird.blue".to_string(),
        b"test-secret",
    );
    let auth_sign = move |target: &str, method: &str| {
        auth_client
            .sign_request(target, method)
            .map_err(|e| e.to_string())
    };

    let selector =
        RemotePrefixBootstrapSelector::new(convo_id, sequencer_did.to_string(), 0).unwrap();

    let admission = match fetch_remote_prefix_admission(
        &pool, &resolver, &outbound, &auth_sign, selector,
    )
    .await
    {
        Ok(adm) => adm,
        Err(e) => panic!("admission must succeed, got {e:?}"),
    };

    assert_eq!(admission.event_count(), 3);
    assert_eq!(admission.conversation_id(), convo_id);
    // 4 queries: healthCheck (1) + opening digest (1) + events page (1) + closing digest (1) = 4 hits
    assert_eq!(hits_counter.load(Ordering::SeqCst), 4);
}

// 4. Fresh JTI and exact LXM each query
#[tokio::test]
async fn admission_mints_fresh_jti_and_exact_lxm_per_query() {
    let Some((pool, _db_guard)) = setup_test_db().await else {
        return;
    };

    let convo_id = Uuid::new_v4();
    let sequencer_did = "did:web:seq.catbird.blue";
    let local_participant_did = "did:web:destination.catbird.blue";
    let local_device_id = Uuid::new_v4();

    seed_test_device(&pool, local_participant_did, local_device_id, "active").await;
    seed_approved_peer(&pool, sequencer_did).await;

    let now = Utc::now();
    let creation_signed = build_test_signed_creation(
        convo_id,
        local_participant_did,
        local_device_id,
        &[local_participant_did],
        now,
    );

    let entry_1 = Uuid::new_v4();
    let entry_2 = Uuid::new_v4();
    let entry_3 = Uuid::new_v4();
    let fp = [1u8; 32];

    let ev1 = build_test_event_json(
        1,
        0,
        entry_1,
        CREATION_ENTRY_TYPE_ID,
        b"p1",
        &creation_signed,
        &fp,
        now,
    );
    let ev2 = build_test_event_json(
        2,
        0,
        entry_2,
        PARTICIPANT_ACCEPTANCE_ENTRY_TYPE_ID,
        b"p2",
        b"{\"signed\":{}}",
        &fp,
        now,
    );
    let ev3 = build_test_event_json(
        3,
        0,
        entry_3,
        LEAF_RECOVERY_FULFILLMENT_ENTRY_TYPE_ID,
        b"p3",
        b"{\"signed\":{}}",
        &fp,
        now,
    );

    let mut hasher = CleanConvoDigestHasher::new();
    hasher.update_event(
        1,
        0,
        entry_1,
        CREATION_ENTRY_TYPE_ID,
        b"p1",
        &creation_signed,
        &fp,
        now,
    );
    hasher.update_event(
        2,
        0,
        entry_2,
        PARTICIPANT_ACCEPTANCE_ENTRY_TYPE_ID,
        b"p2",
        b"{\"signed\":{}}",
        &fp,
        now,
    );
    hasher.update_event(
        3,
        0,
        entry_3,
        LEAF_RECOVERY_FULFILLMENT_ENTRY_TYPE_ID,
        b"p3",
        b"{\"signed\":{}}",
        &fp,
        now,
    );
    let digest_hex = hasher.finalize();

    let digest_json = json!({
        "convoId": convo_id.to_string(),
        "sequencerDsDid": sequencer_did,
        "sequencerTerm": 0,
        "epoch": 0,
        "lastSeq": 3,
        "eventCount": 3,
        "digestSha256": digest_hex,
        "generatedAt": now.to_rfc3339_opts(SecondsFormat::Millis, true)
    });

    let recorded = Arc::new(Mutex::new(Vec::new()));
    let mock_state = MockSequencerState {
        capabilities: vec![
            CAPABILITY_RECONCILIATION_V1.to_string(),
            CAPABILITY_CANONICAL_PREFIX_BOOTSTRAP_V1.to_string(),
        ],
        opening_digest: Some(digest_json.clone()),
        closing_digest: Some(digest_json),
        events_pages: vec![json!({
            "convoId": convo_id.to_string(),
            "fromSeqExclusive": 0,
            "toSeqInclusive": 3,
            "events": [ev1, ev2, ev3]
        })],
        recorded_requests: recorded.clone(),
        destination_hits: Arc::new(AtomicUsize::new(0)),
    };

    let (dest, _url) = spawn_mock_sequencer(mock_state).await;
    let resolver = create_test_resolver(pool.clone(), dest, sequencer_did);
    let outbound = OutboundClient::new(2, 2);

    let auth_client = ServiceAuthClient::from_shared_secret(
        "did:web:destination.catbird.blue".to_string(),
        b"test-secret",
    );
    let auth_sign = move |target: &str, method: &str| {
        auth_client
            .sign_request(target, method)
            .map_err(|e| e.to_string())
    };

    let selector =
        RemotePrefixBootstrapSelector::new(convo_id, sequencer_did.to_string(), 0).unwrap();
    let _admission = match fetch_remote_prefix_admission(
        &pool, &resolver, &outbound, &auth_sign, selector,
    )
    .await
    {
        Ok(adm) => adm,
        Err(e) => panic!("admission must succeed, got {e:?}"),
    };

    let reqs = recorded.lock().await;
    let mut jtis = std::collections::HashSet::new();

    // Authenticated queries: opening digest, events, closing digest (healthCheck is unauthenticated)
    let authenticated_queries: Vec<&(String, Option<String>)> =
        reqs.iter().filter(|(_, auth)| auth.is_some()).collect();

    assert_eq!(authenticated_queries.len(), 3);

    for (nsid, auth_opt) in authenticated_queries {
        let auth_str = auth_opt.as_ref().unwrap();
        let token = auth_str.trim_start_matches("Bearer ");
        let mut validation = Validation::new(Algorithm::HS256);
        validation.set_audience(&[sequencer_did]);
        let token_data = decode::<ServiceAuthClaims>(
            token,
            &DecodingKey::from_secret(b"test-secret"),
            &validation,
        )
        .expect("decode token");

        assert_eq!(&token_data.claims.lxm, nsid);
        assert!(
            jtis.insert(token_data.claims.jti),
            "JTI must be unique per query"
        );
    }
}

// 5. Missing capability produces no DB write
#[tokio::test]
async fn admission_fails_on_missing_bootstrap_capability_with_no_db_write() {
    let Some((pool, _db_guard)) = setup_test_db().await else {
        return;
    };

    let convo_id = Uuid::new_v4();
    let sequencer_did = "did:web:seq.catbird.blue";
    seed_approved_peer(&pool, sequencer_did).await;

    // Sequencer advertises only reconciliation-v1, not canonical-prefix-bootstrap-v1
    let mock_state = MockSequencerState {
        capabilities: vec![CAPABILITY_RECONCILIATION_V1.to_string()],
        opening_digest: None,
        closing_digest: None,
        events_pages: vec![],
        recorded_requests: Arc::new(Mutex::new(Vec::new())),
        destination_hits: Arc::new(AtomicUsize::new(0)),
    };

    let (dest, _url) = spawn_mock_sequencer(mock_state).await;
    let resolver = create_test_resolver(pool.clone(), dest, sequencer_did);
    let outbound = OutboundClient::new(2, 2);

    let auth_client = ServiceAuthClient::from_shared_secret(
        "did:web:destination.catbird.blue".to_string(),
        b"test-secret",
    );
    let auth_sign = move |target: &str, method: &str| {
        auth_client
            .sign_request(target, method)
            .map_err(|e| e.to_string())
    };

    let snapshot_before = snapshot_db_content(&pool).await;

    let selector =
        RemotePrefixBootstrapSelector::new(convo_id, sequencer_did.to_string(), 0).unwrap();
    let res =
        fetch_remote_prefix_admission(&pool, &resolver, &outbound, &auth_sign, selector).await;

    let err = match res {
        Err(e) => e,
        Ok(_) => panic!("expected Err, got Ok"),
    };
    assert_eq!(err, RemotePrefixBootstrapError::MissingCapability);

    let snapshot_after = snapshot_db_content(&pool).await;
    assert_eq!(
        snapshot_before, snapshot_after,
        "zero database writes on missing capability"
    );
}

// 6. Moving snapshot produces no DB write
#[tokio::test]
async fn admission_fails_on_moving_digest_snapshot_with_no_db_write() {
    let Some((pool, _db_guard)) = setup_test_db().await else {
        return;
    };

    let convo_id = Uuid::new_v4();
    let sequencer_did = "did:web:seq.catbird.blue";
    let local_participant_did = "did:web:destination.catbird.blue";
    let local_device_id = Uuid::new_v4();

    seed_test_device(&pool, local_participant_did, local_device_id, "active").await;
    seed_approved_peer(&pool, sequencer_did).await;

    let now = Utc::now();
    let creation_signed = build_test_signed_creation(
        convo_id,
        local_participant_did,
        local_device_id,
        &[local_participant_did],
        now,
    );

    let entry_1 = Uuid::new_v4();
    let entry_2 = Uuid::new_v4();
    let entry_3 = Uuid::new_v4();
    let fp = [1u8; 32];

    let ev1 = build_test_event_json(
        1,
        0,
        entry_1,
        CREATION_ENTRY_TYPE_ID,
        b"p1",
        &creation_signed,
        &fp,
        now,
    );
    let ev2 = build_test_event_json(
        2,
        0,
        entry_2,
        PARTICIPANT_ACCEPTANCE_ENTRY_TYPE_ID,
        b"p2",
        b"{\"signed\":{}}",
        &fp,
        now,
    );
    let ev3 = build_test_event_json(
        3,
        0,
        entry_3,
        LEAF_RECOVERY_FULFILLMENT_ENTRY_TYPE_ID,
        b"p3",
        b"{\"signed\":{}}",
        &fp,
        now,
    );

    let mut hasher = CleanConvoDigestHasher::new();
    hasher.update_event(
        1,
        0,
        entry_1,
        CREATION_ENTRY_TYPE_ID,
        b"p1",
        &creation_signed,
        &fp,
        now,
    );
    hasher.update_event(
        2,
        0,
        entry_2,
        PARTICIPANT_ACCEPTANCE_ENTRY_TYPE_ID,
        b"p2",
        b"{\"signed\":{}}",
        &fp,
        now,
    );
    hasher.update_event(
        3,
        0,
        entry_3,
        LEAF_RECOVERY_FULFILLMENT_ENTRY_TYPE_ID,
        b"p3",
        b"{\"signed\":{}}",
        &fp,
        now,
    );
    let digest_hex = hasher.finalize();

    let opening_digest = json!({
        "convoId": convo_id.to_string(),
        "sequencerDsDid": sequencer_did,
        "sequencerTerm": 0,
        "epoch": 0,
        "lastSeq": 3,
        "eventCount": 3,
        "digestSha256": digest_hex,
        "generatedAt": now.to_rfc3339_opts(SecondsFormat::Millis, true)
    });

    let closing_digest = json!({
        "convoId": convo_id.to_string(),
        "sequencerDsDid": sequencer_did,
        "sequencerTerm": 0,
        "epoch": 0,
        "lastSeq": 4, // Snapshot advanced concurrently
        "eventCount": 4,
        "digestSha256": "00".repeat(32),
        "generatedAt": now.to_rfc3339_opts(SecondsFormat::Millis, true)
    });

    let mock_state = MockSequencerState {
        capabilities: vec![
            CAPABILITY_RECONCILIATION_V1.to_string(),
            CAPABILITY_CANONICAL_PREFIX_BOOTSTRAP_V1.to_string(),
        ],
        opening_digest: Some(opening_digest),
        closing_digest: Some(closing_digest),
        events_pages: vec![json!({
            "convoId": convo_id.to_string(),
            "fromSeqExclusive": 0,
            "toSeqInclusive": 3,
            "events": [ev1, ev2, ev3]
        })],
        recorded_requests: Arc::new(Mutex::new(Vec::new())),
        destination_hits: Arc::new(AtomicUsize::new(0)),
    };

    let (dest, _url) = spawn_mock_sequencer(mock_state).await;
    let resolver = create_test_resolver(pool.clone(), dest, sequencer_did);
    let outbound = OutboundClient::new(2, 2);

    let auth_client = ServiceAuthClient::from_shared_secret(
        "did:web:destination.catbird.blue".to_string(),
        b"test-secret",
    );
    let auth_sign = move |target: &str, method: &str| {
        auth_client
            .sign_request(target, method)
            .map_err(|e| e.to_string())
    };

    let snapshot_before = snapshot_db_content(&pool).await;

    let selector =
        RemotePrefixBootstrapSelector::new(convo_id, sequencer_did.to_string(), 0).unwrap();
    let res =
        fetch_remote_prefix_admission(&pool, &resolver, &outbound, &auth_sign, selector).await;

    let err = match res {
        Err(e) => e,
        Ok(_) => panic!("expected Err, got Ok"),
    };
    assert_eq!(err, RemotePrefixBootstrapError::MovingSnapshot);

    let snapshot_after = snapshot_db_content(&pool).await;
    assert_eq!(
        snapshot_before, snapshot_after,
        "no DB write on moving snapshot"
    );
}

// 7. Event sequence gap produces no DB write
#[tokio::test]
async fn admission_fails_on_sequence_gap_with_no_db_write() {
    let Some((pool, _db_guard)) = setup_test_db().await else {
        return;
    };

    let convo_id = Uuid::new_v4();
    let sequencer_did = "did:web:seq.catbird.blue";
    let local_participant_did = "did:web:destination.catbird.blue";
    let local_device_id = Uuid::new_v4();

    seed_test_device(&pool, local_participant_did, local_device_id, "active").await;
    seed_approved_peer(&pool, sequencer_did).await;

    let now = Utc::now();
    let creation_signed = build_test_signed_creation(
        convo_id,
        local_participant_did,
        local_device_id,
        &[local_participant_did],
        now,
    );

    let entry_1 = Uuid::new_v4();
    let entry_3 = Uuid::new_v4(); // Gap: seq 1 then seq 3 (missing seq 2)
    let fp = [1u8; 32];

    let ev1 = build_test_event_json(
        1,
        0,
        entry_1,
        CREATION_ENTRY_TYPE_ID,
        b"p1",
        &creation_signed,
        &fp,
        now,
    );
    let ev3 = build_test_event_json(
        3,
        0,
        entry_3,
        PARTICIPANT_ACCEPTANCE_ENTRY_TYPE_ID,
        b"p3",
        b"{\"signed\":{}}",
        &fp,
        now,
    );

    let digest_json = json!({
        "convoId": convo_id.to_string(),
        "sequencerDsDid": sequencer_did,
        "sequencerTerm": 0,
        "epoch": 0,
        "lastSeq": 3,
        "eventCount": 2,
        "digestSha256": "00".repeat(32),
        "generatedAt": now.to_rfc3339_opts(SecondsFormat::Millis, true)
    });

    let mock_state = MockSequencerState {
        capabilities: vec![
            CAPABILITY_RECONCILIATION_V1.to_string(),
            CAPABILITY_CANONICAL_PREFIX_BOOTSTRAP_V1.to_string(),
        ],
        opening_digest: Some(digest_json.clone()),
        closing_digest: Some(digest_json),
        events_pages: vec![json!({
            "convoId": convo_id.to_string(),
            "fromSeqExclusive": 0,
            "toSeqInclusive": 3,
            "events": [ev1, ev3]
        })],
        recorded_requests: Arc::new(Mutex::new(Vec::new())),
        destination_hits: Arc::new(AtomicUsize::new(0)),
    };

    let (dest, _url) = spawn_mock_sequencer(mock_state).await;
    let resolver = create_test_resolver(pool.clone(), dest, sequencer_did);
    let outbound = OutboundClient::new(2, 2);

    let auth_client = ServiceAuthClient::from_shared_secret(
        "did:web:destination.catbird.blue".to_string(),
        b"test-secret",
    );
    let auth_sign = move |target: &str, method: &str| {
        auth_client
            .sign_request(target, method)
            .map_err(|e| e.to_string())
    };

    let snapshot_before = snapshot_db_content(&pool).await;

    let selector =
        RemotePrefixBootstrapSelector::new(convo_id, sequencer_did.to_string(), 0).unwrap();
    let res =
        fetch_remote_prefix_admission(&pool, &resolver, &outbound, &auth_sign, selector).await;

    let err = match res {
        Err(e) => e,
        Ok(_) => panic!("expected Err, got Ok"),
    };
    assert_eq!(err, RemotePrefixBootstrapError::InvalidEvent);

    let snapshot_after = snapshot_db_content(&pool).await;
    assert_eq!(
        snapshot_before, snapshot_after,
        "no DB write on sequence gap"
    );
}

// 8. Duplicate entry ID produces no DB write
#[tokio::test]
async fn admission_fails_on_duplicate_entry_id_with_no_db_write() {
    let Some((pool, _db_guard)) = setup_test_db().await else {
        return;
    };

    let convo_id = Uuid::new_v4();
    let sequencer_did = "did:web:seq.catbird.blue";
    let local_participant_did = "did:web:destination.catbird.blue";
    let local_device_id = Uuid::new_v4();

    seed_test_device(&pool, local_participant_did, local_device_id, "active").await;
    seed_approved_peer(&pool, sequencer_did).await;

    let now = Utc::now();
    let creation_signed = build_test_signed_creation(
        convo_id,
        local_participant_did,
        local_device_id,
        &[local_participant_did],
        now,
    );

    let duplicate_entry_id = Uuid::new_v4();
    let fp = [1u8; 32];

    let ev1 = build_test_event_json(
        1,
        0,
        duplicate_entry_id,
        CREATION_ENTRY_TYPE_ID,
        b"p1",
        &creation_signed,
        &fp,
        now,
    );
    let ev2 = build_test_event_json(
        2,
        0,
        duplicate_entry_id, // Duplicate entry UUID
        PARTICIPANT_ACCEPTANCE_ENTRY_TYPE_ID,
        b"p2",
        b"{\"signed\":{}}",
        &fp,
        now,
    );

    let digest_json = json!({
        "convoId": convo_id.to_string(),
        "sequencerDsDid": sequencer_did,
        "sequencerTerm": 0,
        "epoch": 0,
        "lastSeq": 2,
        "eventCount": 2,
        "digestSha256": "00".repeat(32),
        "generatedAt": now.to_rfc3339_opts(SecondsFormat::Millis, true)
    });

    let mock_state = MockSequencerState {
        capabilities: vec![
            CAPABILITY_RECONCILIATION_V1.to_string(),
            CAPABILITY_CANONICAL_PREFIX_BOOTSTRAP_V1.to_string(),
        ],
        opening_digest: Some(digest_json.clone()),
        closing_digest: Some(digest_json),
        events_pages: vec![json!({
            "convoId": convo_id.to_string(),
            "fromSeqExclusive": 0,
            "toSeqInclusive": 2,
            "events": [ev1, ev2]
        })],
        recorded_requests: Arc::new(Mutex::new(Vec::new())),
        destination_hits: Arc::new(AtomicUsize::new(0)),
    };

    let (dest, _url) = spawn_mock_sequencer(mock_state).await;
    let resolver = create_test_resolver(pool.clone(), dest, sequencer_did);
    let outbound = OutboundClient::new(2, 2);

    let auth_client = ServiceAuthClient::from_shared_secret(
        "did:web:destination.catbird.blue".to_string(),
        b"test-secret",
    );
    let auth_sign = move |target: &str, method: &str| {
        auth_client
            .sign_request(target, method)
            .map_err(|e| e.to_string())
    };

    let snapshot_before = snapshot_db_content(&pool).await;

    let selector =
        RemotePrefixBootstrapSelector::new(convo_id, sequencer_did.to_string(), 0).unwrap();
    let res =
        fetch_remote_prefix_admission(&pool, &resolver, &outbound, &auth_sign, selector).await;

    let err = match res {
        Err(e) => e,
        Ok(_) => panic!("expected Err, got Ok"),
    };
    assert_eq!(err, RemotePrefixBootstrapError::InvalidEvent);

    let snapshot_after = snapshot_db_content(&pool).await;
    assert_eq!(
        snapshot_before, snapshot_after,
        "no DB write on duplicate entry id"
    );
}

// 9. Event reorder produces no DB write
#[tokio::test]
async fn admission_fails_on_event_reorder_with_no_db_write() {
    let Some((pool, _db_guard)) = setup_test_db().await else {
        return;
    };

    let convo_id = Uuid::new_v4();
    let sequencer_did = "did:web:seq.catbird.blue";
    let local_participant_did = "did:web:destination.catbird.blue";
    let local_device_id = Uuid::new_v4();

    seed_test_device(&pool, local_participant_did, local_device_id, "active").await;
    seed_approved_peer(&pool, sequencer_did).await;

    let now = Utc::now();
    let creation_signed = build_test_signed_creation(
        convo_id,
        local_participant_did,
        local_device_id,
        &[local_participant_did],
        now,
    );

    let entry_1 = Uuid::new_v4();
    let entry_2 = Uuid::new_v4();
    let fp = [1u8; 32];

    let ev1 = build_test_event_json(
        1,
        0,
        entry_1,
        CREATION_ENTRY_TYPE_ID,
        b"p1",
        &creation_signed,
        &fp,
        now,
    );
    let ev2 = build_test_event_json(
        2,
        0,
        entry_2,
        PARTICIPANT_ACCEPTANCE_ENTRY_TYPE_ID,
        b"p2",
        b"{\"signed\":{}}",
        &fp,
        now,
    );

    let digest_json = json!({
        "convoId": convo_id.to_string(),
        "sequencerDsDid": sequencer_did,
        "sequencerTerm": 0,
        "epoch": 0,
        "lastSeq": 2,
        "eventCount": 2,
        "digestSha256": "00".repeat(32),
        "generatedAt": now.to_rfc3339_opts(SecondsFormat::Millis, true)
    });

    // Events in reverse sequence order [seq 2, seq 1]
    let mock_state = MockSequencerState {
        capabilities: vec![
            CAPABILITY_RECONCILIATION_V1.to_string(),
            CAPABILITY_CANONICAL_PREFIX_BOOTSTRAP_V1.to_string(),
        ],
        opening_digest: Some(digest_json.clone()),
        closing_digest: Some(digest_json),
        events_pages: vec![json!({
            "convoId": convo_id.to_string(),
            "fromSeqExclusive": 0,
            "toSeqInclusive": 2,
            "events": [ev2, ev1]
        })],
        recorded_requests: Arc::new(Mutex::new(Vec::new())),
        destination_hits: Arc::new(AtomicUsize::new(0)),
    };

    let (dest, _url) = spawn_mock_sequencer(mock_state).await;
    let resolver = create_test_resolver(pool.clone(), dest, sequencer_did);
    let outbound = OutboundClient::new(2, 2);

    let auth_client = ServiceAuthClient::from_shared_secret(
        "did:web:destination.catbird.blue".to_string(),
        b"test-secret",
    );
    let auth_sign = move |target: &str, method: &str| {
        auth_client
            .sign_request(target, method)
            .map_err(|e| e.to_string())
    };

    let snapshot_before = snapshot_db_content(&pool).await;

    let selector =
        RemotePrefixBootstrapSelector::new(convo_id, sequencer_did.to_string(), 0).unwrap();
    let res =
        fetch_remote_prefix_admission(&pool, &resolver, &outbound, &auth_sign, selector).await;

    let err = match res {
        Err(e) => e,
        Ok(_) => panic!("expected Err, got Ok"),
    };
    assert_eq!(err, RemotePrefixBootstrapError::InvalidEvent);

    let snapshot_after = snapshot_db_content(&pool).await;
    assert_eq!(
        snapshot_before, snapshot_after,
        "no DB write on event reorder"
    );
}

// 10. Page truncation produces no DB write
#[tokio::test]
async fn admission_fails_on_page_truncation_with_no_db_write() {
    let Some((pool, _db_guard)) = setup_test_db().await else {
        return;
    };

    let convo_id = Uuid::new_v4();
    let sequencer_did = "did:web:seq.catbird.blue";
    let local_participant_did = "did:web:destination.catbird.blue";
    let local_device_id = Uuid::new_v4();

    seed_test_device(&pool, local_participant_did, local_device_id, "active").await;
    seed_approved_peer(&pool, sequencer_did).await;

    let now = Utc::now();
    let creation_signed = build_test_signed_creation(
        convo_id,
        local_participant_did,
        local_device_id,
        &[local_participant_did],
        now,
    );

    let entry_1 = Uuid::new_v4();
    let entry_2 = Uuid::new_v4();
    let fp = [1u8; 32];

    let ev1 = build_test_event_json(
        1,
        0,
        entry_1,
        CREATION_ENTRY_TYPE_ID,
        b"p1",
        &creation_signed,
        &fp,
        now,
    );
    let ev2 = build_test_event_json(
        2,
        0,
        entry_2,
        PARTICIPANT_ACCEPTANCE_ENTRY_TYPE_ID,
        b"p2",
        b"{\"signed\":{}}",
        &fp,
        now,
    );

    let digest_json = json!({
        "convoId": convo_id.to_string(),
        "sequencerDsDid": sequencer_did,
        "sequencerTerm": 0,
        "epoch": 0,
        "lastSeq": 3,
        "eventCount": 3,
        "digestSha256": "00".repeat(32),
        "generatedAt": now.to_rfc3339_opts(SecondsFormat::Millis, true)
    });

    // Page claims toSeqInclusive = 3 but only provides 2 events (up to seq 2)
    let mock_state = MockSequencerState {
        capabilities: vec![
            CAPABILITY_RECONCILIATION_V1.to_string(),
            CAPABILITY_CANONICAL_PREFIX_BOOTSTRAP_V1.to_string(),
        ],
        opening_digest: Some(digest_json.clone()),
        closing_digest: Some(digest_json),
        events_pages: vec![json!({
            "convoId": convo_id.to_string(),
            "fromSeqExclusive": 0,
            "toSeqInclusive": 3,
            "events": [ev1, ev2]
        })],
        recorded_requests: Arc::new(Mutex::new(Vec::new())),
        destination_hits: Arc::new(AtomicUsize::new(0)),
    };

    let (dest, _url) = spawn_mock_sequencer(mock_state).await;
    let resolver = create_test_resolver(pool.clone(), dest, sequencer_did);
    let outbound = OutboundClient::new(2, 2);

    let auth_client = ServiceAuthClient::from_shared_secret(
        "did:web:destination.catbird.blue".to_string(),
        b"test-secret",
    );
    let auth_sign = move |target: &str, method: &str| {
        auth_client
            .sign_request(target, method)
            .map_err(|e| e.to_string())
    };

    let snapshot_before = snapshot_db_content(&pool).await;

    let selector =
        RemotePrefixBootstrapSelector::new(convo_id, sequencer_did.to_string(), 0).unwrap();
    let res =
        fetch_remote_prefix_admission(&pool, &resolver, &outbound, &auth_sign, selector).await;

    let err = match res {
        Err(e) => e,
        Ok(_) => panic!("expected Err, got Ok"),
    };
    assert_eq!(err, RemotePrefixBootstrapError::InvalidEvent);

    let snapshot_after = snapshot_db_content(&pool).await;
    assert_eq!(
        snapshot_before, snapshot_after,
        "no DB write on page truncation"
    );
}

// 11. Rolling digest mismatch produces no DB write
#[tokio::test]
async fn admission_fails_on_rolling_digest_mismatch_with_no_db_write() {
    let Some((pool, _db_guard)) = setup_test_db().await else {
        return;
    };

    let convo_id = Uuid::new_v4();
    let sequencer_did = "did:web:seq.catbird.blue";
    let local_participant_did = "did:web:destination.catbird.blue";
    let local_device_id = Uuid::new_v4();

    seed_test_device(&pool, local_participant_did, local_device_id, "active").await;
    seed_approved_peer(&pool, sequencer_did).await;

    let now = Utc::now();
    let creation_signed = build_test_signed_creation(
        convo_id,
        local_participant_did,
        local_device_id,
        &[local_participant_did],
        now,
    );

    let entry_1 = Uuid::new_v4();
    let entry_2 = Uuid::new_v4();
    let entry_3 = Uuid::new_v4();
    let fp = [1u8; 32];

    let ev1 = build_test_event_json(
        1,
        0,
        entry_1,
        CREATION_ENTRY_TYPE_ID,
        b"p1",
        &creation_signed,
        &fp,
        now,
    );
    let ev2 = build_test_event_json(
        2,
        0,
        entry_2,
        PARTICIPANT_ACCEPTANCE_ENTRY_TYPE_ID,
        b"p2",
        b"{\"signed\":{}}",
        &fp,
        now,
    );
    let ev3 = build_test_event_json(
        3,
        0,
        entry_3,
        LEAF_RECOVERY_FULFILLMENT_ENTRY_TYPE_ID,
        b"p3",
        b"{\"signed\":{}}",
        &fp,
        now,
    );

    // Opening digest declares a mismatched digest hash (all 0x77 bytes)
    let digest_json = json!({
        "convoId": convo_id.to_string(),
        "sequencerDsDid": sequencer_did,
        "sequencerTerm": 0,
        "epoch": 0,
        "lastSeq": 3,
        "eventCount": 3,
        "digestSha256": hex::encode([0x77u8; 32]),
        "generatedAt": now.to_rfc3339_opts(SecondsFormat::Millis, true)
    });

    let mock_state = MockSequencerState {
        capabilities: vec![
            CAPABILITY_RECONCILIATION_V1.to_string(),
            CAPABILITY_CANONICAL_PREFIX_BOOTSTRAP_V1.to_string(),
        ],
        opening_digest: Some(digest_json.clone()),
        closing_digest: Some(digest_json),
        events_pages: vec![json!({
            "convoId": convo_id.to_string(),
            "fromSeqExclusive": 0,
            "toSeqInclusive": 3,
            "events": [ev1, ev2, ev3]
        })],
        recorded_requests: Arc::new(Mutex::new(Vec::new())),
        destination_hits: Arc::new(AtomicUsize::new(0)),
    };

    let (dest, _url) = spawn_mock_sequencer(mock_state).await;
    let resolver = create_test_resolver(pool.clone(), dest, sequencer_did);
    let outbound = OutboundClient::new(2, 2);

    let auth_client = ServiceAuthClient::from_shared_secret(
        "did:web:destination.catbird.blue".to_string(),
        b"test-secret",
    );
    let auth_sign = move |target: &str, method: &str| {
        auth_client
            .sign_request(target, method)
            .map_err(|e| e.to_string())
    };

    let snapshot_before = snapshot_db_content(&pool).await;

    let selector =
        RemotePrefixBootstrapSelector::new(convo_id, sequencer_did.to_string(), 0).unwrap();
    let res =
        fetch_remote_prefix_admission(&pool, &resolver, &outbound, &auth_sign, selector).await;

    let err = match res {
        Err(e) => e,
        Ok(_) => panic!("expected Err, got Ok"),
    };
    assert_eq!(err, RemotePrefixBootstrapError::InvalidEvent);

    let snapshot_after = snapshot_db_content(&pool).await;
    assert_eq!(
        snapshot_before, snapshot_after,
        "no DB write on rolling digest mismatch"
    );
}

// 12. Event hash mismatch produces no DB write
#[tokio::test]
async fn admission_fails_on_event_hash_mismatch_with_no_db_write() {
    let Some((pool, _db_guard)) = setup_test_db().await else {
        return;
    };

    let convo_id = Uuid::new_v4();
    let sequencer_did = "did:web:seq.catbird.blue";
    let local_participant_did = "did:web:destination.catbird.blue";
    let local_device_id = Uuid::new_v4();

    seed_test_device(&pool, local_participant_did, local_device_id, "active").await;
    seed_approved_peer(&pool, sequencer_did).await;

    let now = Utc::now();
    let creation_signed = build_test_signed_creation(
        convo_id,
        local_participant_did,
        local_device_id,
        &[local_participant_did],
        now,
    );

    let entry_1 = Uuid::new_v4();
    let fp = [1u8; 32];

    let mut ev1 = build_test_event_json(
        1,
        0,
        entry_1,
        CREATION_ENTRY_TYPE_ID,
        b"p1",
        &creation_signed,
        &fp,
        now,
    );
    // Corrupt the acceptedPayloadSha256
    ev1["acceptedPayloadSha256"] = json!({"$bytes": STANDARD.encode([0xffu8; 32])});

    let digest_json = json!({
        "convoId": convo_id.to_string(),
        "sequencerDsDid": sequencer_did,
        "sequencerTerm": 0,
        "epoch": 0,
        "lastSeq": 1,
        "eventCount": 1,
        "digestSha256": "00".repeat(32),
        "generatedAt": now.to_rfc3339_opts(SecondsFormat::Millis, true)
    });

    let mock_state = MockSequencerState {
        capabilities: vec![
            CAPABILITY_RECONCILIATION_V1.to_string(),
            CAPABILITY_CANONICAL_PREFIX_BOOTSTRAP_V1.to_string(),
        ],
        opening_digest: Some(digest_json.clone()),
        closing_digest: Some(digest_json),
        events_pages: vec![json!({
            "convoId": convo_id.to_string(),
            "fromSeqExclusive": 0,
            "toSeqInclusive": 1,
            "events": [ev1]
        })],
        recorded_requests: Arc::new(Mutex::new(Vec::new())),
        destination_hits: Arc::new(AtomicUsize::new(0)),
    };

    let (dest, _url) = spawn_mock_sequencer(mock_state).await;
    let resolver = create_test_resolver(pool.clone(), dest, sequencer_did);
    let outbound = OutboundClient::new(2, 2);

    let auth_client = ServiceAuthClient::from_shared_secret(
        "did:web:destination.catbird.blue".to_string(),
        b"test-secret",
    );
    let auth_sign = move |target: &str, method: &str| {
        auth_client
            .sign_request(target, method)
            .map_err(|e| e.to_string())
    };

    let snapshot_before = snapshot_db_content(&pool).await;

    let selector =
        RemotePrefixBootstrapSelector::new(convo_id, sequencer_did.to_string(), 0).unwrap();
    let res =
        fetch_remote_prefix_admission(&pool, &resolver, &outbound, &auth_sign, selector).await;

    let err = match res {
        Err(e) => e,
        Ok(_) => panic!("expected Err, got Ok"),
    };
    assert_eq!(err, RemotePrefixBootstrapError::InvalidEvent);

    let snapshot_after = snapshot_db_content(&pool).await;
    assert_eq!(
        snapshot_before, snapshot_after,
        "no DB write on event hash mismatch"
    );
}

// 13. Declared oversized prefix produces no DB write
#[tokio::test]
async fn admission_fails_on_declared_oversized_prefix_with_no_db_write() {
    let Some((pool, _db_guard)) = setup_test_db().await else {
        return;
    };

    let convo_id = Uuid::new_v4();
    let sequencer_did = "did:web:seq.catbird.blue";

    seed_approved_peer(&pool, sequencer_did).await;
    let now = Utc::now();
    // Opening digest declares 501 events (> 500 limit)
    let digest_json = json!({
        "convoId": convo_id.to_string(),
        "sequencerDsDid": sequencer_did,
        "sequencerTerm": 0,
        "epoch": 0,
        "lastSeq": 501,
        "eventCount": 501,
        "digestSha256": "00".repeat(32),
        "generatedAt": now.to_rfc3339_opts(SecondsFormat::Millis, true)
    });

    let mock_state = MockSequencerState {
        capabilities: vec![
            CAPABILITY_RECONCILIATION_V1.to_string(),
            CAPABILITY_CANONICAL_PREFIX_BOOTSTRAP_V1.to_string(),
        ],
        opening_digest: Some(digest_json.clone()),
        closing_digest: Some(digest_json),
        events_pages: vec![],
        recorded_requests: Arc::new(Mutex::new(Vec::new())),
        destination_hits: Arc::new(AtomicUsize::new(0)),
    };

    let (dest, _url) = spawn_mock_sequencer(mock_state).await;
    let resolver = create_test_resolver(pool.clone(), dest, sequencer_did);
    let outbound = OutboundClient::new(2, 2);

    let auth_client = ServiceAuthClient::from_shared_secret(
        "did:web:destination.catbird.blue".to_string(),
        b"test-secret",
    );
    let auth_sign = move |target: &str, method: &str| {
        auth_client
            .sign_request(target, method)
            .map_err(|e| e.to_string())
    };

    let snapshot_before = snapshot_db_content(&pool).await;

    let selector =
        RemotePrefixBootstrapSelector::new(convo_id, sequencer_did.to_string(), 0).unwrap();
    let res =
        fetch_remote_prefix_admission(&pool, &resolver, &outbound, &auth_sign, selector).await;

    let err = match res {
        Err(e) => e,
        Ok(_) => panic!("expected Err, got Ok"),
    };
    assert_eq!(err, RemotePrefixBootstrapError::PrefixTooLarge);

    let snapshot_after = snapshot_db_content(&pool).await;
    assert_eq!(
        snapshot_before, snapshot_after,
        "no DB write on declared oversized prefix"
    );
}

// 14. Stream oversized event cap produces no DB write
#[tokio::test]
async fn admission_fails_on_stream_oversized_events_with_no_db_write() {
    let Some((pool, _db_guard)) = setup_test_db().await else {
        return;
    };

    let convo_id = Uuid::new_v4();
    let sequencer_did = "did:web:seq.catbird.blue";
    let local_participant_did = "did:web:destination.catbird.blue";
    let local_device_id = Uuid::new_v4();

    seed_test_device(&pool, local_participant_did, local_device_id, "active").await;
    seed_approved_peer(&pool, sequencer_did).await;

    let now = Utc::now();
    let creation_signed = build_test_signed_creation(
        convo_id,
        local_participant_did,
        local_device_id,
        &[local_participant_did],
        now,
    );

    // Generate 501 valid grammar events: Creation -> Acceptance -> Fulfillment -> (498 Applications)
    let mut events = Vec::with_capacity(501);
    let fp = [1u8; 32];
    events.push(build_test_event_json(
        1,
        0,
        Uuid::new_v4(),
        CREATION_ENTRY_TYPE_ID,
        b"p1",
        &creation_signed,
        &fp,
        now,
    ));
    events.push(build_test_event_json(
        2,
        0,
        Uuid::new_v4(),
        PARTICIPANT_ACCEPTANCE_ENTRY_TYPE_ID,
        b"p2",
        b"{\"signed\":{}}",
        &fp,
        now,
    ));
    events.push(build_test_event_json(
        3,
        0,
        Uuid::new_v4(),
        LEAF_RECOVERY_FULFILLMENT_ENTRY_TYPE_ID,
        b"p3",
        b"{\"signed\":{}}",
        &fp,
        now,
    ));
    for seq in 4..=501 {
        events.push(build_test_event_json(
            seq,
            0,
            Uuid::new_v4(),
            APPLICATION_ENTRY_TYPE_ID,
            b"app",
            b"{\"signed\":{}}",
            &fp,
            now,
        ));
    }

    // Split into normal bounded pages of <= 100 events each
    let mut pages = Vec::new();
    let mut from_seq = 0;
    while from_seq < 501 {
        let chunk_size = (501 - from_seq).min(100);
        let to_seq = from_seq + chunk_size;
        let page_events = events[from_seq..to_seq].to_vec();
        pages.push(json!({
            "convoId": convo_id.to_string(),
            "fromSeqExclusive": from_seq as i64,
            "toSeqInclusive": to_seq as i64,
            "events": page_events
        }));
        from_seq = to_seq;
    }

    // Opening digest declares lastSeq: 501, eventCount: 500 (passes initial check but fails in loop on 501st event)
    let digest_json = json!({
        "convoId": convo_id.to_string(),
        "sequencerDsDid": sequencer_did,
        "sequencerTerm": 0,
        "epoch": 0,
        "lastSeq": 501,
        "eventCount": 500,
        "digestSha256": "00".repeat(32),
        "generatedAt": now.to_rfc3339_opts(SecondsFormat::Millis, true)
    });

    let mock_state = MockSequencerState {
        capabilities: vec![
            CAPABILITY_RECONCILIATION_V1.to_string(),
            CAPABILITY_CANONICAL_PREFIX_BOOTSTRAP_V1.to_string(),
        ],
        opening_digest: Some(digest_json.clone()),
        closing_digest: Some(digest_json),
        events_pages: pages,
        recorded_requests: Arc::new(Mutex::new(Vec::new())),
        destination_hits: Arc::new(AtomicUsize::new(0)),
    };

    let (dest, _url) = spawn_mock_sequencer(mock_state).await;
    let resolver = create_test_resolver(pool.clone(), dest, sequencer_did);
    let outbound = OutboundClient::new(2, 2);

    let auth_client = ServiceAuthClient::from_shared_secret(
        "did:web:destination.catbird.blue".to_string(),
        b"test-secret",
    );
    let auth_sign = move |target: &str, method: &str| {
        auth_client
            .sign_request(target, method)
            .map_err(|e| e.to_string())
    };

    let snapshot_before = snapshot_db_content(&pool).await;

    let selector =
        RemotePrefixBootstrapSelector::new(convo_id, sequencer_did.to_string(), 0).unwrap();
    let res =
        fetch_remote_prefix_admission(&pool, &resolver, &outbound, &auth_sign, selector).await;

    let err = match res {
        Err(e) => e,
        Ok(_) => panic!("expected Err, got Ok"),
    };
    assert_eq!(err, RemotePrefixBootstrapError::PrefixTooLarge);

    let snapshot_after = snapshot_db_content(&pool).await;
    assert_eq!(
        snapshot_before, snapshot_after,
        "no DB write on stream oversized events"
    );
}

// 15. Material byte cap (>1 MiB) produces PrefixTooLarge with no DB write
#[tokio::test]
async fn admission_fails_on_material_byte_cap_exceeded_with_no_db_write() {
    let Some((pool, _db_guard)) = setup_test_db().await else {
        return;
    };

    let convo_id = Uuid::new_v4();
    let sequencer_did = "did:web:seq.catbird.blue";
    let local_participant_did = "did:web:destination.catbird.blue";
    let local_device_id = Uuid::new_v4();

    seed_test_device(&pool, local_participant_did, local_device_id, "active").await;
    seed_approved_peer(&pool, sequencer_did).await;

    let now = Utc::now();
    let creation_signed = build_test_signed_creation(
        convo_id,
        local_participant_did,
        local_device_id,
        &[local_participant_did],
        now,
    );

    // 100 events, each with 12 KB ciphertext: 100 * 12,000 = 1.2 MB > 1_048_576 (1 MiB)
    let chunk_payload = vec![0x42u8; 12_000];
    let mut events = Vec::with_capacity(100);
    let fp = [1u8; 32];
    events.push(build_test_event_json(
        1,
        0,
        Uuid::new_v4(),
        CREATION_ENTRY_TYPE_ID,
        &chunk_payload,
        &creation_signed,
        &fp,
        now,
    ));
    events.push(build_test_event_json(
        2,
        0,
        Uuid::new_v4(),
        PARTICIPANT_ACCEPTANCE_ENTRY_TYPE_ID,
        &chunk_payload,
        b"{\"signed\":{}}",
        &fp,
        now,
    ));
    events.push(build_test_event_json(
        3,
        0,
        Uuid::new_v4(),
        LEAF_RECOVERY_FULFILLMENT_ENTRY_TYPE_ID,
        &chunk_payload,
        b"{\"signed\":{}}",
        &fp,
        now,
    ));
    for seq in 4..=100 {
        events.push(build_test_event_json(
            seq,
            0,
            Uuid::new_v4(),
            APPLICATION_ENTRY_TYPE_ID,
            &chunk_payload,
            b"{\"signed\":{}}",
            &fp,
            now,
        ));
    }

    // Split into 10 bounded pages of 10 events each (120 KB per page, safely within HTTP transport)
    let mut pages = Vec::new();
    let mut from_seq = 0;
    while from_seq < 100 {
        let chunk_size = (100 - from_seq).min(10);
        let to_seq = from_seq + chunk_size;
        let page_events = events[from_seq..to_seq].to_vec();
        pages.push(json!({
            "convoId": convo_id.to_string(),
            "fromSeqExclusive": from_seq as i64,
            "toSeqInclusive": to_seq as i64,
            "events": page_events
        }));
        from_seq = to_seq;
    }

    let digest_json = json!({
        "convoId": convo_id.to_string(),
        "sequencerDsDid": sequencer_did,
        "sequencerTerm": 0,
        "epoch": 0,
        "lastSeq": 100,
        "eventCount": 100,
        "digestSha256": "00".repeat(32),
        "generatedAt": now.to_rfc3339_opts(SecondsFormat::Millis, true)
    });

    let mock_state = MockSequencerState {
        capabilities: vec![
            CAPABILITY_RECONCILIATION_V1.to_string(),
            CAPABILITY_CANONICAL_PREFIX_BOOTSTRAP_V1.to_string(),
        ],
        opening_digest: Some(digest_json.clone()),
        closing_digest: Some(digest_json),
        events_pages: pages,
        recorded_requests: Arc::new(Mutex::new(Vec::new())),
        destination_hits: Arc::new(AtomicUsize::new(0)),
    };

    let (dest, _url) = spawn_mock_sequencer(mock_state).await;
    let resolver = create_test_resolver(pool.clone(), dest, sequencer_did);
    let outbound = OutboundClient::new(2, 2);

    let auth_client = ServiceAuthClient::from_shared_secret(
        "did:web:destination.catbird.blue".to_string(),
        b"test-secret",
    );
    let auth_sign = move |target: &str, method: &str| {
        auth_client
            .sign_request(target, method)
            .map_err(|e| e.to_string())
    };

    let snapshot_before = snapshot_db_content(&pool).await;

    let selector =
        RemotePrefixBootstrapSelector::new(convo_id, sequencer_did.to_string(), 0).unwrap();
    let res =
        fetch_remote_prefix_admission(&pool, &resolver, &outbound, &auth_sign, selector).await;

    let err = match res {
        Err(e) => e,
        Ok(_) => panic!("expected Err, got Ok"),
    };
    assert_eq!(err, RemotePrefixBootstrapError::PrefixTooLarge);

    let snapshot_after = snapshot_db_content(&pool).await;
    assert_eq!(
        snapshot_before, snapshot_after,
        "no DB write on material byte cap exceeded"
    );
}

// 16. Disordered grammar produces InvalidEvent with no DB write
#[tokio::test]
async fn admission_fails_on_disordered_grammar_with_no_db_write() {
    let Some((pool, _db_guard)) = setup_test_db().await else {
        return;
    };

    let convo_id = Uuid::new_v4();
    let sequencer_did = "did:web:seq.catbird.blue";
    let local_participant_did = "did:web:destination.catbird.blue";
    let local_device_id = Uuid::new_v4();

    seed_test_device(&pool, local_participant_did, local_device_id, "active").await;
    seed_approved_peer(&pool, sequencer_did).await;

    let now = Utc::now();
    let creation_signed = build_test_signed_creation(
        convo_id,
        local_participant_did,
        local_device_id,
        &[local_participant_did],
        now,
    );

    let entry_1 = Uuid::new_v4();
    let entry_2 = Uuid::new_v4();
    let entry_3 = Uuid::new_v4();
    let entry_4 = Uuid::new_v4();
    let entry_5 = Uuid::new_v4();
    let fp = [1u8; 32];

    let ev1 = build_test_event_json(
        1,
        0,
        entry_1,
        CREATION_ENTRY_TYPE_ID,
        b"p1",
        &creation_signed,
        &fp,
        now,
    );
    let ev2 = build_test_event_json(
        2,
        0,
        entry_2,
        PARTICIPANT_ACCEPTANCE_ENTRY_TYPE_ID,
        b"p2",
        b"{\"signed\":{}}",
        &fp,
        now,
    );
    let ev3 = build_test_event_json(
        3,
        0,
        entry_3,
        LEAF_RECOVERY_FULFILLMENT_ENTRY_TYPE_ID,
        b"p3",
        b"{\"signed\":{}}",
        &fp,
        now,
    );
    let ev4 = build_test_event_json(
        4,
        0,
        entry_4,
        APPLICATION_ENTRY_TYPE_ID,
        b"p4",
        b"{\"signed\":{}}",
        &fp,
        now,
    );
    // Policy entry placed after Application entry (disordered grammar)
    let ev5 = build_test_event_json(
        5,
        0,
        entry_5,
        POLICY_ENTRY_TYPE_ID,
        b"p5",
        b"{\"signed\":{}}",
        &fp,
        now,
    );

    let mut hasher = CleanConvoDigestHasher::new();
    hasher.update_event(
        1,
        0,
        entry_1,
        CREATION_ENTRY_TYPE_ID,
        b"p1",
        &creation_signed,
        &fp,
        now,
    );
    hasher.update_event(
        2,
        0,
        entry_2,
        PARTICIPANT_ACCEPTANCE_ENTRY_TYPE_ID,
        b"p2",
        b"{\"signed\":{}}",
        &fp,
        now,
    );
    hasher.update_event(
        3,
        0,
        entry_3,
        LEAF_RECOVERY_FULFILLMENT_ENTRY_TYPE_ID,
        b"p3",
        b"{\"signed\":{}}",
        &fp,
        now,
    );
    hasher.update_event(
        4,
        0,
        entry_4,
        APPLICATION_ENTRY_TYPE_ID,
        b"p4",
        b"{\"signed\":{}}",
        &fp,
        now,
    );
    hasher.update_event(
        5,
        0,
        entry_5,
        POLICY_ENTRY_TYPE_ID,
        b"p5",
        b"{\"signed\":{}}",
        &fp,
        now,
    );
    let digest_hex = hasher.finalize();

    let digest_json = json!({
        "convoId": convo_id.to_string(),
        "sequencerDsDid": sequencer_did,
        "sequencerTerm": 0,
        "epoch": 0,
        "lastSeq": 5,
        "eventCount": 5,
        "digestSha256": digest_hex,
        "generatedAt": now.to_rfc3339_opts(SecondsFormat::Millis, true)
    });

    let mock_state = MockSequencerState {
        capabilities: vec![
            CAPABILITY_RECONCILIATION_V1.to_string(),
            CAPABILITY_CANONICAL_PREFIX_BOOTSTRAP_V1.to_string(),
        ],
        opening_digest: Some(digest_json.clone()),
        closing_digest: Some(digest_json),
        events_pages: vec![json!({
            "convoId": convo_id.to_string(),
            "fromSeqExclusive": 0,
            "toSeqInclusive": 5,
            "events": [ev1, ev2, ev3, ev4, ev5]
        })],
        recorded_requests: Arc::new(Mutex::new(Vec::new())),
        destination_hits: Arc::new(AtomicUsize::new(0)),
    };

    let (dest, _url) = spawn_mock_sequencer(mock_state).await;
    let resolver = create_test_resolver(pool.clone(), dest, sequencer_did);
    let outbound = OutboundClient::new(2, 2);

    let auth_client = ServiceAuthClient::from_shared_secret(
        "did:web:destination.catbird.blue".to_string(),
        b"test-secret",
    );
    let auth_sign = move |target: &str, method: &str| {
        auth_client
            .sign_request(target, method)
            .map_err(|e| e.to_string())
    };

    let snapshot_before = snapshot_db_content(&pool).await;

    let selector =
        RemotePrefixBootstrapSelector::new(convo_id, sequencer_did.to_string(), 0).unwrap();
    let res =
        fetch_remote_prefix_admission(&pool, &resolver, &outbound, &auth_sign, selector).await;

    let err = match res {
        Err(e) => e,
        Ok(_) => panic!("expected Err, got Ok"),
    };
    assert_eq!(err, RemotePrefixBootstrapError::InvalidEvent);

    let snapshot_after = snapshot_db_content(&pool).await;
    assert_eq!(
        snapshot_before, snapshot_after,
        "no DB write on disordered grammar"
    );
}

// 17. Policy with zero additions produces InvalidEvent with no DB write
#[tokio::test]
async fn admission_fails_on_policy_with_zero_additions_with_no_db_write() {
    let Some((pool, _db_guard)) = setup_test_db().await else {
        return;
    };

    let convo_id = Uuid::new_v4();
    let sequencer_did = "did:web:seq.catbird.blue";
    let local_participant_did = "did:web:destination.catbird.blue";
    let local_device_id = Uuid::new_v4();

    seed_test_device(&pool, local_participant_did, local_device_id, "active").await;
    seed_approved_peer(&pool, sequencer_did).await;

    let now = Utc::now();
    let creation_signed = build_test_signed_creation(
        convo_id,
        local_participant_did,
        local_device_id,
        &[local_participant_did],
        now,
    );
    // Policy mutation with empty participantChanges
    let policy_signed = build_test_signed_policy(
        convo_id,
        local_participant_did,
        local_device_id,
        vec![],
        now,
    );

    let entry_1 = Uuid::new_v4();
    let entry_2 = Uuid::new_v4();
    let entry_3 = Uuid::new_v4();
    let entry_4 = Uuid::new_v4();
    let fp = [1u8; 32];

    let ev1 = build_test_event_json(
        1,
        0,
        entry_1,
        CREATION_ENTRY_TYPE_ID,
        b"p1",
        &creation_signed,
        &fp,
        now,
    );
    let ev2 = build_test_event_json(
        2,
        0,
        entry_2,
        POLICY_ENTRY_TYPE_ID,
        b"p2",
        &policy_signed,
        &fp,
        now,
    );
    let ev3 = build_test_event_json(
        3,
        0,
        entry_3,
        PARTICIPANT_ACCEPTANCE_ENTRY_TYPE_ID,
        b"p3",
        b"{\"signed\":{}}",
        &fp,
        now,
    );
    let ev4 = build_test_event_json(
        4,
        0,
        entry_4,
        LEAF_RECOVERY_FULFILLMENT_ENTRY_TYPE_ID,
        b"p4",
        b"{\"signed\":{}}",
        &fp,
        now,
    );

    let mut hasher = CleanConvoDigestHasher::new();
    hasher.update_event(
        1,
        0,
        entry_1,
        CREATION_ENTRY_TYPE_ID,
        b"p1",
        &creation_signed,
        &fp,
        now,
    );
    hasher.update_event(
        2,
        0,
        entry_2,
        POLICY_ENTRY_TYPE_ID,
        b"p2",
        &policy_signed,
        &fp,
        now,
    );
    hasher.update_event(
        3,
        0,
        entry_3,
        PARTICIPANT_ACCEPTANCE_ENTRY_TYPE_ID,
        b"p3",
        b"{\"signed\":{}}",
        &fp,
        now,
    );
    hasher.update_event(
        4,
        0,
        entry_4,
        LEAF_RECOVERY_FULFILLMENT_ENTRY_TYPE_ID,
        b"p4",
        b"{\"signed\":{}}",
        &fp,
        now,
    );
    let digest_hex = hasher.finalize();

    let digest_json = json!({
        "convoId": convo_id.to_string(),
        "sequencerDsDid": sequencer_did,
        "sequencerTerm": 0,
        "epoch": 0,
        "lastSeq": 4,
        "eventCount": 4,
        "digestSha256": digest_hex,
        "generatedAt": now.to_rfc3339_opts(SecondsFormat::Millis, true)
    });

    let mock_state = MockSequencerState {
        capabilities: vec![
            CAPABILITY_RECONCILIATION_V1.to_string(),
            CAPABILITY_CANONICAL_PREFIX_BOOTSTRAP_V1.to_string(),
        ],
        opening_digest: Some(digest_json.clone()),
        closing_digest: Some(digest_json),
        events_pages: vec![json!({
            "convoId": convo_id.to_string(),
            "fromSeqExclusive": 0,
            "toSeqInclusive": 4,
            "events": [ev1, ev2, ev3, ev4]
        })],
        recorded_requests: Arc::new(Mutex::new(Vec::new())),
        destination_hits: Arc::new(AtomicUsize::new(0)),
    };

    let (dest, _url) = spawn_mock_sequencer(mock_state).await;
    let resolver = create_test_resolver(pool.clone(), dest, sequencer_did);
    let outbound = OutboundClient::new(2, 2);

    let auth_client = ServiceAuthClient::from_shared_secret(
        "did:web:destination.catbird.blue".to_string(),
        b"test-secret",
    );
    let auth_sign = move |target: &str, method: &str| {
        auth_client
            .sign_request(target, method)
            .map_err(|e| e.to_string())
    };

    let snapshot_before = snapshot_db_content(&pool).await;

    let selector =
        RemotePrefixBootstrapSelector::new(convo_id, sequencer_did.to_string(), 0).unwrap();
    let res =
        fetch_remote_prefix_admission(&pool, &resolver, &outbound, &auth_sign, selector).await;

    let err = match res {
        Err(e) => e,
        Ok(_) => panic!("expected Err, got Ok"),
    };
    assert_eq!(err, RemotePrefixBootstrapError::InvalidEvent);

    let snapshot_after = snapshot_db_content(&pool).await;
    assert_eq!(
        snapshot_before, snapshot_after,
        "no DB write on policy with zero additions"
    );
}

// 18. Policy with non-add changes produces InvalidEvent with no DB write
#[tokio::test]
async fn admission_fails_on_policy_with_non_add_changes_with_no_db_write() {
    let Some((pool, _db_guard)) = setup_test_db().await else {
        return;
    };

    let convo_id = Uuid::new_v4();
    let sequencer_did = "did:web:seq.catbird.blue";
    let local_participant_did = "did:web:destination.catbird.blue";
    let local_device_id = Uuid::new_v4();

    seed_test_device(&pool, local_participant_did, local_device_id, "active").await;
    seed_approved_peer(&pool, sequencer_did).await;

    let now = Utc::now();
    let creation_signed = build_test_signed_creation(
        convo_id,
        local_participant_did,
        local_device_id,
        &[local_participant_did],
        now,
    );
    // Policy mutation with removeParticipant instead of addParticipant
    let policy_signed = build_test_signed_policy(
        convo_id,
        local_participant_did,
        local_device_id,
        vec![json!({
            "$type": "blue.catbird.chat.defs#removeParticipant",
            "userDid": "did:web:departed.catbird.blue",
        })],
        now,
    );

    let entry_1 = Uuid::new_v4();
    let entry_2 = Uuid::new_v4();
    let entry_3 = Uuid::new_v4();
    let entry_4 = Uuid::new_v4();
    let fp = [1u8; 32];

    let ev1 = build_test_event_json(
        1,
        0,
        entry_1,
        CREATION_ENTRY_TYPE_ID,
        b"p1",
        &creation_signed,
        &fp,
        now,
    );
    let ev2 = build_test_event_json(
        2,
        0,
        entry_2,
        POLICY_ENTRY_TYPE_ID,
        b"p2",
        &policy_signed,
        &fp,
        now,
    );
    let ev3 = build_test_event_json(
        3,
        0,
        entry_3,
        PARTICIPANT_ACCEPTANCE_ENTRY_TYPE_ID,
        b"p3",
        b"{\"signed\":{}}",
        &fp,
        now,
    );
    let ev4 = build_test_event_json(
        4,
        0,
        entry_4,
        LEAF_RECOVERY_FULFILLMENT_ENTRY_TYPE_ID,
        b"p4",
        b"{\"signed\":{}}",
        &fp,
        now,
    );

    let mut hasher = CleanConvoDigestHasher::new();
    hasher.update_event(
        1,
        0,
        entry_1,
        CREATION_ENTRY_TYPE_ID,
        b"p1",
        &creation_signed,
        &fp,
        now,
    );
    hasher.update_event(
        2,
        0,
        entry_2,
        POLICY_ENTRY_TYPE_ID,
        b"p2",
        &policy_signed,
        &fp,
        now,
    );
    hasher.update_event(
        3,
        0,
        entry_3,
        PARTICIPANT_ACCEPTANCE_ENTRY_TYPE_ID,
        b"p3",
        b"{\"signed\":{}}",
        &fp,
        now,
    );
    hasher.update_event(
        4,
        0,
        entry_4,
        LEAF_RECOVERY_FULFILLMENT_ENTRY_TYPE_ID,
        b"p4",
        b"{\"signed\":{}}",
        &fp,
        now,
    );
    let digest_hex = hasher.finalize();

    let digest_json = json!({
        "convoId": convo_id.to_string(),
        "sequencerDsDid": sequencer_did,
        "sequencerTerm": 0,
        "epoch": 0,
        "lastSeq": 4,
        "eventCount": 4,
        "digestSha256": digest_hex,
        "generatedAt": now.to_rfc3339_opts(SecondsFormat::Millis, true)
    });

    let mock_state = MockSequencerState {
        capabilities: vec![
            CAPABILITY_RECONCILIATION_V1.to_string(),
            CAPABILITY_CANONICAL_PREFIX_BOOTSTRAP_V1.to_string(),
        ],
        opening_digest: Some(digest_json.clone()),
        closing_digest: Some(digest_json),
        events_pages: vec![json!({
            "convoId": convo_id.to_string(),
            "fromSeqExclusive": 0,
            "toSeqInclusive": 4,
            "events": [ev1, ev2, ev3, ev4]
        })],
        recorded_requests: Arc::new(Mutex::new(Vec::new())),
        destination_hits: Arc::new(AtomicUsize::new(0)),
    };

    let (dest, _url) = spawn_mock_sequencer(mock_state).await;
    let resolver = create_test_resolver(pool.clone(), dest, sequencer_did);
    let outbound = OutboundClient::new(2, 2);

    let auth_client = ServiceAuthClient::from_shared_secret(
        "did:web:destination.catbird.blue".to_string(),
        b"test-secret",
    );
    let auth_sign = move |target: &str, method: &str| {
        auth_client
            .sign_request(target, method)
            .map_err(|e| e.to_string())
    };

    let snapshot_before = snapshot_db_content(&pool).await;

    let selector =
        RemotePrefixBootstrapSelector::new(convo_id, sequencer_did.to_string(), 0).unwrap();
    let res =
        fetch_remote_prefix_admission(&pool, &resolver, &outbound, &auth_sign, selector).await;

    let err = match res {
        Err(e) => e,
        Ok(_) => panic!("expected Err, got Ok"),
    };
    assert_eq!(err, RemotePrefixBootstrapError::InvalidEvent);

    let snapshot_after = snapshot_db_content(&pool).await;
    assert_eq!(
        snapshot_before, snapshot_after,
        "no DB write on policy with non-add changes"
    );
}

// 19. Active local recipient required produces NoLocalParticipant with no DB write
#[tokio::test]
async fn admission_fails_when_no_active_local_device_exists() {
    let Some((pool, _db_guard)) = setup_test_db().await else {
        return;
    };

    let convo_id = Uuid::new_v4();
    let sequencer_did = "did:web:seq.catbird.blue";
    let local_participant_did = "did:web:destination.catbird.blue";
    let remote_participant_did = "did:web:remote-participant.catbird.blue";
    let local_device_id = Uuid::new_v4();

    // Device is REVOKED -> must fail with NoLocalParticipant
    seed_test_device(&pool, local_participant_did, local_device_id, "revoked").await;
    seed_approved_peer(&pool, sequencer_did).await;
    seed_approved_peer(&pool, "did:web:remote-seq.catbird.blue").await;

    let now = Utc::now();
    let creation_signed = build_test_signed_creation(
        convo_id,
        local_participant_did,
        local_device_id,
        &[local_participant_did, remote_participant_did],
        now,
    );
    let entry_1 = Uuid::new_v4();
    let entry_2 = Uuid::new_v4();
    let entry_3 = Uuid::new_v4();
    let fp = [1u8; 32];

    let ev1 = build_test_event_json(
        1,
        0,
        entry_1,
        CREATION_ENTRY_TYPE_ID,
        b"p1",
        &creation_signed,
        &fp,
        now,
    );
    let ev2 = build_test_event_json(
        2,
        0,
        entry_2,
        PARTICIPANT_ACCEPTANCE_ENTRY_TYPE_ID,
        b"p2",
        b"{\"signed\":{}}",
        &fp,
        now,
    );
    let ev3 = build_test_event_json(
        3,
        0,
        entry_3,
        LEAF_RECOVERY_FULFILLMENT_ENTRY_TYPE_ID,
        b"p3",
        b"{\"signed\":{}}",
        &fp,
        now,
    );

    let mut hasher = CleanConvoDigestHasher::new();
    hasher.update_event(
        1,
        0,
        entry_1,
        CREATION_ENTRY_TYPE_ID,
        b"p1",
        &creation_signed,
        &fp,
        now,
    );
    hasher.update_event(
        2,
        0,
        entry_2,
        PARTICIPANT_ACCEPTANCE_ENTRY_TYPE_ID,
        b"p2",
        b"{\"signed\":{}}",
        &fp,
        now,
    );
    hasher.update_event(
        3,
        0,
        entry_3,
        LEAF_RECOVERY_FULFILLMENT_ENTRY_TYPE_ID,
        b"p3",
        b"{\"signed\":{}}",
        &fp,
        now,
    );
    let digest_hex = hasher.finalize();

    let digest_json = json!({
        "convoId": convo_id.to_string(),
        "sequencerDsDid": sequencer_did,
        "sequencerTerm": 0,
        "epoch": 0,
        "lastSeq": 3,
        "eventCount": 3,
        "digestSha256": digest_hex,
        "generatedAt": now.to_rfc3339_opts(SecondsFormat::Millis, true)
    });

    let mock_state = MockSequencerState {
        capabilities: vec![
            CAPABILITY_RECONCILIATION_V1.to_string(),
            CAPABILITY_CANONICAL_PREFIX_BOOTSTRAP_V1.to_string(),
        ],
        opening_digest: Some(digest_json.clone()),
        closing_digest: Some(digest_json),
        events_pages: vec![json!({
            "convoId": convo_id.to_string(),
            "fromSeqExclusive": 0,
            "toSeqInclusive": 3,
            "events": [ev1, ev2, ev3]
        })],
        recorded_requests: Arc::new(Mutex::new(Vec::new())),
        destination_hits: Arc::new(AtomicUsize::new(0)),
    };

    let (dest, _url) = spawn_mock_sequencer(mock_state).await;
    let resolver = create_test_resolver(pool.clone(), dest, sequencer_did);
    let outbound = OutboundClient::new(2, 2);

    let auth_client = ServiceAuthClient::from_shared_secret(
        "did:web:destination.catbird.blue".to_string(),
        b"test-secret",
    );
    let auth_sign = move |target: &str, method: &str| {
        auth_client
            .sign_request(target, method)
            .map_err(|e| e.to_string())
    };

    let snapshot_before = snapshot_db_content(&pool).await;

    let selector =
        RemotePrefixBootstrapSelector::new(convo_id, sequencer_did.to_string(), 0).unwrap();
    let res =
        fetch_remote_prefix_admission(&pool, &resolver, &outbound, &auth_sign, selector).await;

    let err = match res {
        Err(e) => e,
        Ok(_) => panic!("expected Err, got Ok"),
    };
    assert_eq!(err, RemotePrefixBootstrapError::NoLocalParticipant);

    let snapshot_after = snapshot_db_content(&pool).await;
    assert_eq!(
        snapshot_before, snapshot_after,
        "no DB write when no active local device exists"
    );
}

// 20. Unapproved peer produces PeerDenied with no DB write
#[tokio::test]
async fn admission_fails_on_unapproved_peer_with_no_db_write() {
    let Some((pool, _db_guard)) = setup_test_db().await else {
        return;
    };

    let convo_id = Uuid::new_v4();
    let sequencer_did = "did:web:unapproved.catbird.blue";

    // Do NOT seed sequencer_did into federation_peers
    let mock_state = MockSequencerState {
        capabilities: vec![
            CAPABILITY_RECONCILIATION_V1.to_string(),
            CAPABILITY_CANONICAL_PREFIX_BOOTSTRAP_V1.to_string(),
        ],
        opening_digest: None,
        closing_digest: None,
        events_pages: vec![],
        recorded_requests: Arc::new(Mutex::new(Vec::new())),
        destination_hits: Arc::new(AtomicUsize::new(0)),
    };

    let (dest, _url) = spawn_mock_sequencer(mock_state).await;
    let resolver = create_test_resolver(pool.clone(), dest, sequencer_did);
    let outbound = OutboundClient::new(2, 2);

    let auth_client = ServiceAuthClient::from_shared_secret(
        "did:web:destination.catbird.blue".to_string(),
        b"test-secret",
    );
    let auth_sign = move |target: &str, method: &str| {
        auth_client
            .sign_request(target, method)
            .map_err(|e| e.to_string())
    };

    let snapshot_before = snapshot_db_content(&pool).await;

    let selector =
        RemotePrefixBootstrapSelector::new(convo_id, sequencer_did.to_string(), 0).unwrap();
    let res =
        fetch_remote_prefix_admission(&pool, &resolver, &outbound, &auth_sign, selector).await;

    let err = match res {
        Err(e) => e,
        Ok(_) => panic!("expected Err, got Ok"),
    };
    assert_eq!(err, RemotePrefixBootstrapError::PeerDenied);

    let snapshot_after = snapshot_db_content(&pool).await;
    assert_eq!(
        snapshot_before, snapshot_after,
        "no DB write on unapproved peer"
    );
}

// 21. Nonzero generation succeeds
#[tokio::test]
async fn admission_succeeds_with_nonzero_generation() {
    let Some((pool, _db_guard)) = setup_test_db().await else {
        return;
    };

    let convo_id = Uuid::new_v4();
    let sequencer_did = "did:web:seq.catbird.blue";
    let local_participant_did = "did:web:destination.catbird.blue";
    let local_device_id = Uuid::new_v4();

    seed_test_device(&pool, local_participant_did, local_device_id, "active").await;
    seed_approved_peer(&pool, sequencer_did).await;

    let now = Utc::now();
    let creation_signed = build_test_signed_creation(
        convo_id,
        local_participant_did,
        local_device_id,
        &[local_participant_did],
        now,
    );

    let entry_1 = Uuid::new_v4();
    let entry_2 = Uuid::new_v4();
    let entry_3 = Uuid::new_v4();
    let fp = [1u8; 32];

    // Epoch / generation = 2
    let ev1 = build_test_event_json(
        1,
        2,
        entry_1,
        CREATION_ENTRY_TYPE_ID,
        b"p1",
        &creation_signed,
        &fp,
        now,
    );
    let ev2 = build_test_event_json(
        2,
        2,
        entry_2,
        PARTICIPANT_ACCEPTANCE_ENTRY_TYPE_ID,
        b"p2",
        b"{\"signed\":{}}",
        &fp,
        now,
    );
    let ev3 = build_test_event_json(
        3,
        2,
        entry_3,
        LEAF_RECOVERY_FULFILLMENT_ENTRY_TYPE_ID,
        b"p3",
        b"{\"signed\":{}}",
        &fp,
        now,
    );

    let mut hasher = CleanConvoDigestHasher::new();
    hasher.update_event(
        1,
        2,
        entry_1,
        CREATION_ENTRY_TYPE_ID,
        b"p1",
        &creation_signed,
        &fp,
        now,
    );
    hasher.update_event(
        2,
        2,
        entry_2,
        PARTICIPANT_ACCEPTANCE_ENTRY_TYPE_ID,
        b"p2",
        b"{\"signed\":{}}",
        &fp,
        now,
    );
    hasher.update_event(
        3,
        2,
        entry_3,
        LEAF_RECOVERY_FULFILLMENT_ENTRY_TYPE_ID,
        b"p3",
        b"{\"signed\":{}}",
        &fp,
        now,
    );
    let digest_hex = hasher.finalize();

    let digest_json = json!({
        "convoId": convo_id.to_string(),
        "sequencerDsDid": sequencer_did,
        "sequencerTerm": 0,
        "epoch": 2,
        "lastSeq": 3,
        "eventCount": 3,
        "digestSha256": digest_hex,
        "generatedAt": now.to_rfc3339_opts(SecondsFormat::Millis, true)
    });

    let mock_state = MockSequencerState {
        capabilities: vec![
            CAPABILITY_RECONCILIATION_V1.to_string(),
            CAPABILITY_CANONICAL_PREFIX_BOOTSTRAP_V1.to_string(),
        ],
        opening_digest: Some(digest_json.clone()),
        closing_digest: Some(digest_json),
        events_pages: vec![json!({
            "convoId": convo_id.to_string(),
            "fromSeqExclusive": 0,
            "toSeqInclusive": 3,
            "events": [ev1, ev2, ev3]
        })],
        recorded_requests: Arc::new(Mutex::new(Vec::new())),
        destination_hits: Arc::new(AtomicUsize::new(0)),
    };

    let (dest, _url) = spawn_mock_sequencer(mock_state).await;
    let resolver = create_test_resolver(pool.clone(), dest, sequencer_did);
    let outbound = OutboundClient::new(2, 2);

    let auth_client = ServiceAuthClient::from_shared_secret(
        "did:web:destination.catbird.blue".to_string(),
        b"test-secret",
    );
    let auth_sign = move |target: &str, method: &str| {
        auth_client
            .sign_request(target, method)
            .map_err(|e| e.to_string())
    };

    let selector =
        RemotePrefixBootstrapSelector::new(convo_id, sequencer_did.to_string(), 0).unwrap();
    let admission = match fetch_remote_prefix_admission(
        &pool, &resolver, &outbound, &auth_sign, selector,
    )
    .await
    {
        Ok(adm) => adm,
        Err(e) => panic!("admission with nonzero generation must succeed, got {e:?}"),
    };

    assert_eq!(admission.event_count(), 3);
    assert_eq!(admission.conversation_id(), convo_id);
}

// 22. Generation mismatch produces InvalidEvent with no DB write
#[tokio::test]
async fn admission_fails_on_generation_mismatch_with_no_db_write() {
    let Some((pool, _db_guard)) = setup_test_db().await else {
        return;
    };

    let convo_id = Uuid::new_v4();
    let sequencer_did = "did:web:seq.catbird.blue";
    let local_participant_did = "did:web:destination.catbird.blue";
    let local_device_id = Uuid::new_v4();

    seed_test_device(&pool, local_participant_did, local_device_id, "active").await;
    seed_approved_peer(&pool, sequencer_did).await;

    let now = Utc::now();
    let creation_signed = build_test_signed_creation(
        convo_id,
        local_participant_did,
        local_device_id,
        &[local_participant_did],
        now,
    );

    let entry_1 = Uuid::new_v4();
    let entry_2 = Uuid::new_v4();
    let entry_3 = Uuid::new_v4();
    let fp = [1u8; 32];

    // Events have generation 1
    let ev1 = build_test_event_json(
        1,
        1,
        entry_1,
        CREATION_ENTRY_TYPE_ID,
        b"p1",
        &creation_signed,
        &fp,
        now,
    );
    let ev2 = build_test_event_json(
        2,
        1,
        entry_2,
        PARTICIPANT_ACCEPTANCE_ENTRY_TYPE_ID,
        b"p2",
        b"{\"signed\":{}}",
        &fp,
        now,
    );
    let ev3 = build_test_event_json(
        3,
        1,
        entry_3,
        LEAF_RECOVERY_FULFILLMENT_ENTRY_TYPE_ID,
        b"p3",
        b"{\"signed\":{}}",
        &fp,
        now,
    );

    let mut hasher = CleanConvoDigestHasher::new();
    hasher.update_event(
        1,
        1,
        entry_1,
        CREATION_ENTRY_TYPE_ID,
        b"p1",
        &creation_signed,
        &fp,
        now,
    );
    hasher.update_event(
        2,
        1,
        entry_2,
        PARTICIPANT_ACCEPTANCE_ENTRY_TYPE_ID,
        b"p2",
        b"{\"signed\":{}}",
        &fp,
        now,
    );
    hasher.update_event(
        3,
        1,
        entry_3,
        LEAF_RECOVERY_FULFILLMENT_ENTRY_TYPE_ID,
        b"p3",
        b"{\"signed\":{}}",
        &fp,
        now,
    );
    let digest_hex = hasher.finalize();

    // Digest declares epoch 2 (mismatched with events epoch 1)
    let digest_json = json!({
        "convoId": convo_id.to_string(),
        "sequencerDsDid": sequencer_did,
        "sequencerTerm": 0,
        "epoch": 2,
        "lastSeq": 3,
        "eventCount": 3,
        "digestSha256": digest_hex,
        "generatedAt": now.to_rfc3339_opts(SecondsFormat::Millis, true)
    });

    let mock_state = MockSequencerState {
        capabilities: vec![
            CAPABILITY_RECONCILIATION_V1.to_string(),
            CAPABILITY_CANONICAL_PREFIX_BOOTSTRAP_V1.to_string(),
        ],
        opening_digest: Some(digest_json.clone()),
        closing_digest: Some(digest_json),
        events_pages: vec![json!({
            "convoId": convo_id.to_string(),
            "fromSeqExclusive": 0,
            "toSeqInclusive": 3,
            "events": [ev1, ev2, ev3]
        })],
        recorded_requests: Arc::new(Mutex::new(Vec::new())),
        destination_hits: Arc::new(AtomicUsize::new(0)),
    };

    let (dest, _url) = spawn_mock_sequencer(mock_state).await;
    let resolver = create_test_resolver(pool.clone(), dest, sequencer_did);
    let outbound = OutboundClient::new(2, 2);

    let auth_client = ServiceAuthClient::from_shared_secret(
        "did:web:destination.catbird.blue".to_string(),
        b"test-secret",
    );
    let auth_sign = move |target: &str, method: &str| {
        auth_client
            .sign_request(target, method)
            .map_err(|e| e.to_string())
    };

    let snapshot_before = snapshot_db_content(&pool).await;

    let selector =
        RemotePrefixBootstrapSelector::new(convo_id, sequencer_did.to_string(), 0).unwrap();
    let res =
        fetch_remote_prefix_admission(&pool, &resolver, &outbound, &auth_sign, selector).await;

    let err = match res {
        Err(e) => e,
        Ok(_) => panic!("expected Err, got Ok"),
    };
    assert_eq!(err, RemotePrefixBootstrapError::InvalidEvent);

    let snapshot_after = snapshot_db_content(&pool).await;
    assert_eq!(
        snapshot_before, snapshot_after,
        "no DB write on generation mismatch"
    );
}

// ============================================================================
// Task 5: Deterministic historical execution authority and closed planners
// ============================================================================

fn corpus_evaluation_instant(offset_millis: i64) -> DateTime<Utc> {
    let manifest = corpus_manifest();
    let millis = manifest.evaluation_unix_seconds as i64 * 1_000 + offset_millis;
    DateTime::from_timestamp_millis(millis).unwrap()
}

fn random_plc_did() -> String {
    const ALPHABET: &[u8] = b"abcdefghijklmnopqrstuvwxyz234567";
    let mut bytes = Uuid::new_v4().as_bytes().to_vec();
    bytes.extend_from_slice(Uuid::new_v4().as_bytes());
    let suffix: String = bytes
        .iter()
        .take(24)
        .map(|byte| ALPHABET[(*byte % 32) as usize] as char)
        .collect();
    format!("did:plc:{suffix}")
}

fn fresh_bob() -> (DeviceIdentity, String) {
    let did = random_plc_did();
    let device = DeviceIdentity::new(
        PrincipalId::new(did.as_bytes().to_vec()).unwrap(),
        *Uuid::new_v4().as_bytes(),
    )
    .unwrap();
    (device, did)
}

fn genuine_creation_event(cid: Uuid, received_at: DateTime<Utc>) -> (RealCreationEntry, Value) {
    let manifest = corpus_manifest();
    let entry = build_real_corpus_creation_entry(*cid.as_bytes());
    let group_info = corpus_file("group-info.mls");
    let coordinate = coordinate_with_conversation(&genesis_coordinate(&manifest), *cid.as_bytes());
    let signed_at_str =
        (received_at - chrono::Duration::seconds(10)).to_rfc3339_opts(SecondsFormat::Millis, true);
    let received_at_str = received_at.to_rfc3339_opts(SecondsFormat::Millis, true);
    let entry = bind_creation_entry_to_group_info(
        entry,
        &group_info,
        &coordinate,
        &signed_at_str,
        &received_at_str,
    );
    let event = build_test_event_json(
        1,
        0,
        entry.entry_id,
        CREATION_ENTRY_TYPE_ID,
        &entry.public_row_json,
        &entry.raw_wrapper,
        &entry.outer_entry_fingerprint,
        received_at,
    );
    (entry, event)
}

fn vec_to_32(v: &[u8]) -> [u8; 32] {
    v.try_into().expect("32 bytes")
}

fn genuine_policy_event(
    entry: &RealCreationEntry,
    coordinate: &PublicGroupSnapshotCoordinate,
    invitee_did: &str,
    received_at: DateTime<Utc>,
) -> (GenuinePolicyControl, PublicGroupSnapshotCoordinate, Value) {
    let received_at_str = received_at.to_rfc3339_opts(SecondsFormat::Millis, true);
    let next_coordinate = PublicGroupSnapshotCoordinate::new(
        *coordinate.conversation_id(),
        coordinate.generation(),
        coordinate.state_version() + 1,
        *coordinate.group_id(),
        coordinate.epoch(),
        *coordinate.group_context_hash(),
        *coordinate.confirmation_tag(),
        PublicGroupSnapshotLifecycle::Active,
    );
    let policy = genuine_terminal_fixture::genuine_policy_control(
        entry,
        coordinate,
        2,
        &received_at_str,
        vec![GenuinePolicyChange::Add(invitee_did)],
    );
    let outer_fingerprint = vec_to_32(&policy.entry.outer_entry_fingerprint);
    let event = build_test_event_json(
        2,
        0,
        policy.entry.entry_id,
        POLICY_ENTRY_TYPE_ID,
        &policy.entry.accepted_payload_bytes,
        &policy.entry.signed_request_bytes,
        &outer_fingerprint,
        received_at,
    );
    (policy, next_coordinate, event)
}

fn genuine_acceptance_event(
    entry: &RealCreationEntry,
    invitee: &AcceptanceInvitee,
    invitation_transition_id: Uuid,
    prior_coordinate: &PublicGroupSnapshotCoordinate,
    corpus_package: Option<([u8; 32], Vec<u8>)>,
    received_at: DateTime<Utc>,
) -> (RealAcceptanceEntry, Value) {
    let signed_at = received_at.to_rfc3339_opts(SecondsFormat::Millis, true);
    let received_at_str = signed_at.clone();
    let expires_at =
        (received_at + chrono::Duration::minutes(5)).to_rfc3339_opts(SecondsFormat::Millis, true);
    let prior_json = coordinate_json(prior_coordinate);
    let acceptance = genuine_terminal_fixture::build_real_acceptance_entry_at(
        entry,
        invitee,
        invitation_transition_id,
        prior_json,
        3,
        &signed_at,
        &received_at_str,
        &expires_at,
        corpus_package,
    );
    let event = build_test_event_json(
        3,
        0,
        acceptance.entry_id,
        PARTICIPANT_ACCEPTANCE_ENTRY_TYPE_ID,
        &acceptance.public_row_json,
        &acceptance.raw_wrapper,
        &acceptance.outer_fingerprint,
        received_at,
    );
    (acceptance, event)
}

// 23. Exact historical instant preserved across state rows
#[tokio::test]
async fn historical_authority_preserves_exact_historical_instant() {
    let Some((pool, _db_guard)) = setup_test_db().await else {
        return;
    };

    let convo_id = Uuid::new_v4();
    let sequencer_did = "did:web:sequencer.catbird.blue";
    let historical_instant = corpus_evaluation_instant(1_000);

    let (entry, event_json) = genuine_creation_event(convo_id, historical_instant);
    let actor_created_at = corpus_evaluation_instant(0) - chrono::Duration::hours(1);
    seed_protocol_instance(&pool).await;
    seed_actor_at(
        &pool,
        &entry.actor_did,
        entry.actor_device_id,
        &entry.public_key,
        actor_created_at,
    )
    .await;

    let selector =
        RemotePrefixBootstrapSelector::new(convo_id, sequencer_did.to_string(), 0).unwrap();
    let admission_digest = [0x55u8; 32];
    let mut routes = BTreeMap::new();
    routes.insert(entry.actor_did.clone(), None);

    let mut tx = pool.begin().await.expect("begin tx");
    let outcome = test_apply_historical_creation_entry(
        &mut tx,
        admission_digest,
        1,
        selector,
        routes,
        event_json,
    )
    .await
    .expect("apply historical creation step");

    assert_eq!(outcome.allocated_seq, 1);
    assert_eq!(
        outcome.event_positions_count, 0,
        "historical step emits zero events"
    );

    tx.commit().await.expect("commit historical creation");

    let convo_created_at: DateTime<Utc> =
        sqlx::query_scalar("SELECT created_at FROM chat.conversations WHERE conversation_id = $1")
            .bind(convo_id)
            .fetch_one(&pool)
            .await
            .expect("fetch convo created_at");

    let entry_received_at: DateTime<Utc> = sqlx::query_scalar(
        "SELECT received_at FROM chat.entries WHERE conversation_id = $1 AND seq = 1",
    )
    .bind(convo_id)
    .fetch_one(&pool)
    .await
    .expect("fetch entry received_at");

    assert_eq!(
        convo_created_at.timestamp_millis(),
        historical_instant.timestamp_millis(),
        "conversation created_at matches historical instant"
    );
    assert_eq!(
        entry_received_at.timestamp_millis(),
        historical_instant.timestamp_millis(),
        "entry received_at matches historical instant"
    );
}

// 24. Signer missing, revoked, rebound, or auth-generation drift fails authority
#[tokio::test]
async fn historical_authority_fails_on_signer_drift_and_revocation() {
    let Some((pool, _db_guard)) = setup_test_db().await else {
        return;
    };

    let convo_id = Uuid::new_v4();
    let sequencer_did = "did:web:sequencer.catbird.blue";
    let now = corpus_evaluation_instant(1_000);

    let (entry, event_json) = genuine_creation_event(convo_id, now);
    let selector =
        RemotePrefixBootstrapSelector::new(convo_id, sequencer_did.to_string(), 0).unwrap();
    let admission_digest = [0x55u8; 32];
    let mut routes = BTreeMap::new();
    routes.insert(entry.actor_did.clone(), None);

    // Case A: Signer missing in DB
    {
        let mut tx = pool.begin().await.expect("begin tx");
        let res = test_verify_historical_authority(
            &mut tx,
            admission_digest,
            1,
            selector.clone(),
            routes.clone(),
            event_json.clone(),
        )
        .await;
        assert_eq!(res.err(), Some(RemotePrefixBootstrapError::Authority));
    }

    // Seed active device for subsequent tests
    let actor_created_at = corpus_evaluation_instant(0) - chrono::Duration::hours(1);
    seed_protocol_instance(&pool).await;
    seed_actor_at(
        &pool,
        &entry.actor_did,
        entry.actor_device_id,
        &entry.public_key,
        actor_created_at,
    )
    .await;

    // Case B: Signer revoked in DB with valid revocation shape & foreign keys in isolated transaction
    {
        let mut tx = pool.begin().await.expect("begin tx");
        let revocation_time = actor_created_at + chrono::Duration::seconds(10);
        let revocation_id = Uuid::new_v4();
        let accepted_request_bytes =
            br#"{"body":{"$type":"blue.catbird.chat.defs#deviceRevocationBody"}}"#.to_vec();
        let accepted_request_sha256: [u8; 32] = Sha256::digest(&accepted_request_bytes).into();
        let mut signing_transcript_bytes = b"CATBIRD-CHAT-DEVICE-REVOKE\0".to_vec();
        signing_transcript_bytes.extend_from_slice(&[0x42u8; 32]);
        let request_digest: [u8; 32] = Sha256::digest(&signing_transcript_bytes).into();
        let signature = [3_u8; 64];
        let response = br#"{"revoked":true}"#;
        let response_sha256: [u8; 32] = Sha256::digest(response).into();

        sqlx::query(
            "INSERT INTO chat.operation_claims (operation_id, principal_did, endpoint_nsid, mutation_kind, request_digest, accepted_request_sha256, signature, claimed_at) \
             VALUES ($1,$2,'blue.catbird.chat.revokeDevice','blue.catbird.chat.defs#deviceRevocationBody',$3,$4,$5,$6)",
        )
        .bind(revocation_id)
        .bind(&entry.actor_did)
        .bind(request_digest.as_slice())
        .bind(accepted_request_sha256.as_slice())
        .bind(signature.as_slice())
        .bind(revocation_time)
        .execute(&mut *tx)
        .await
        .expect("insert revokeDevice operation claim");

        sqlx::query(
            "INSERT INTO chat.idempotency_records (principal_did, endpoint_nsid, operation_id, request_digest, accepted_request_bytes, signing_transcript_bytes, signature, completed_status, response_bytes, response_sha256, historical_jkt, completed_at) \
             VALUES ($1,'blue.catbird.chat.revokeDevice',$2,$3,$4,$5,$6,200,$7,$8,'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA',$9)",
        )
        .bind(&entry.actor_did)
        .bind(revocation_id)
        .bind(request_digest.as_slice())
        .bind(&accepted_request_bytes)
        .bind(&signing_transcript_bytes)
        .bind(signature.as_slice())
        .bind(response.as_slice())
        .bind(response_sha256.as_slice())
        .bind(revocation_time)
        .execute(&mut *tx)
        .await
        .expect("insert revokeDevice receipt");

        sqlx::query(
            "INSERT INTO chat.device_revocations (revocation_id, actor_did, actor_device_id, actor_key_id, actor_auth_generation, target_did, target_device_id, target_auth_generation, accepted_request_bytes, signing_transcript_bytes, request_digest, signature, signed_at, accepted_at) \
             VALUES ($1,$2,$3,$4,1,$2,$3,1,$5,$6,$7,$8,$9,$9)",
        )
        .bind(revocation_id)
        .bind(&entry.actor_did)
        .bind(entry.actor_device_id)
        .bind(&entry.actor_key_id)
        .bind(&accepted_request_bytes)
        .bind(&signing_transcript_bytes)
        .bind(request_digest.as_slice())
        .bind(signature.as_slice())
        .bind(revocation_time)
        .execute(&mut *tx)
        .await
        .expect("insert device revocation");

        sqlx::query(
            "UPDATE chat.devices SET status='revoked', updated_at=$3, revoked_at=$3, revocation_id=$4 WHERE user_did=$1 AND device_id=$2",
        )
        .bind(&entry.actor_did)
        .bind(entry.actor_device_id)
        .bind(revocation_time)
        .bind(revocation_id)
        .execute(&mut *tx)
        .await
        .expect("revoke device");

        sqlx::query(
            "UPDATE chat.device_keys SET revoked_at=$3, revocation_id=$4 WHERE user_did=$1 AND device_id=$2",
        )
        .bind(&entry.actor_did)
        .bind(entry.actor_device_id)
        .bind(revocation_time)
        .bind(revocation_id)
        .execute(&mut *tx)
        .await
        .expect("revoke device key");

        let res = test_verify_historical_authority(
            &mut tx,
            admission_digest,
            1,
            selector.clone(),
            routes.clone(),
            event_json.clone(),
        )
        .await;
        assert_eq!(res.err(), Some(RemotePrefixBootstrapError::Authority));
        tx.rollback().await.expect("rollback revocation");
    }

    // Case C: Signer signature key mismatch (rebound) - seeded with different public key on fresh setup DB
    {
        let Some((rebound_pool, _rebound_guard)) = setup_test_db().await else {
            return;
        };
        seed_protocol_instance(&rebound_pool).await;
        let diff_signing_key = SigningKey::generate(&mut rand::thread_rng());
        let diff_public_key = diff_signing_key.verifying_key().to_bytes();
        seed_actor_at(
            &rebound_pool,
            &entry.actor_did,
            entry.actor_device_id,
            &diff_public_key,
            actor_created_at,
        )
        .await;

        let mut tx = rebound_pool.begin().await.expect("begin tx");
        let res = test_verify_historical_authority(
            &mut tx,
            admission_digest,
            1,
            selector.clone(),
            routes.clone(),
            event_json.clone(),
        )
        .await;
        assert_eq!(res.err(), Some(RemotePrefixBootstrapError::Authority));
    }

    // Case D: Auth generation drift via valid device rotation in isolated transaction
    {
        let mut tx = pool.begin().await.expect("begin tx");
        let rotation_time = actor_created_at + chrono::Duration::seconds(10);
        let canonical_jkt = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(Sha256::digest(b"historical-auth-generation-2"));
        sqlx::query(
            "UPDATE chat.devices SET auth_generation = 2, dpop_jkt = $3, updated_at = $4 WHERE user_did = $1 AND device_id = $2",
        )
        .bind(&entry.actor_did)
        .bind(entry.actor_device_id)
        .bind(&canonical_jkt)
        .bind(rotation_time)
        .execute(&mut *tx)
        .await
        .expect("rotate device auth generation to 2");
        let res = test_verify_historical_authority(
            &mut tx,
            admission_digest,
            1,
            selector.clone(),
            routes.clone(),
            event_json.clone(),
        )
        .await;
        assert_eq!(res.err(), Some(RemotePrefixBootstrapError::Authority));
        tx.rollback().await.expect("rollback drift");
    }
}

// 25. Package graph missing, different, expired, or terminal cases
#[tokio::test]
async fn historical_authority_fails_on_package_graph_drift() {
    let convo_id = Uuid::new_v4();
    let sequencer_did = "did:web:sequencer.catbird.blue";
    let creation_time = corpus_evaluation_instant(1_000);
    let policy_time = corpus_evaluation_instant(2_000);
    let acceptance_time = corpus_evaluation_instant(3_000);

    let actor_created_at = corpus_evaluation_instant(0) - chrono::Duration::hours(1);
    let (entry, creation_event) = genuine_creation_event(convo_id, creation_time);

    let (bob_device_identity, bob_did) = fresh_bob();
    let bob_device = Uuid::from_bytes(*bob_device_identity.device_id());
    let bob_signing_key = SigningKey::generate(&mut rand::thread_rng());
    let bob_public_key = bob_signing_key.verifying_key().to_bytes();

    let selector =
        RemotePrefixBootstrapSelector::new(convo_id, sequencer_did.to_string(), 0).unwrap();
    let admission_digest = [0x55u8; 32];
    let mut routes = BTreeMap::new();
    routes.insert(entry.actor_did.clone(), None);
    routes.insert(bob_did.clone(), None);

    let manifest = corpus_manifest();
    let coordinate =
        coordinate_with_conversation(&genesis_coordinate(&manifest), *convo_id.as_bytes());
    let (policy, policy_next_coordinate, policy_event) =
        genuine_policy_event(&entry, &coordinate, &bob_did, policy_time);

    let pkg_not_before = actor_created_at - chrono::Duration::hours(1);
    let pkg_not_after = actor_created_at + chrono::Duration::days(30);

    let build_test_state = || async {
        let Some((pool, _db_guard)) = setup_test_db().await else {
            return None;
        };
        seed_protocol_instance(&pool).await;
        seed_actor_at(
            &pool,
            &entry.actor_did,
            entry.actor_device_id,
            &entry.public_key,
            actor_created_at,
        )
        .await;
        let bob_key_id = seed_actor_at(
            &pool,
            &bob_did,
            bob_device,
            &bob_public_key,
            actor_created_at,
        )
        .await;

        let mut tx = pool.begin().await.expect("begin tx");
        test_apply_historical_creation_entry(
            &mut tx,
            admission_digest,
            2,
            selector.clone(),
            routes.clone(),
            creation_event.clone(),
        )
        .await
        .expect("apply creation");
        test_apply_historical_policy_entry(
            &mut tx,
            admission_digest,
            2,
            selector.clone(),
            routes.clone(),
            policy_event.clone(),
        )
        .await
        .expect("apply policy");
        tx.commit().await.expect("commit creation+policy");

        Some((pool, _db_guard, bob_key_id))
    };

    let Some((pool_a, _guard_a, bob_key_id)) = build_test_state().await else {
        return;
    };
    let invitee = AcceptanceInvitee {
        did: bob_did.clone(),
        device_id: bob_device,
        key_id: bob_key_id.clone(),
        signing_key: bob_signing_key.clone(),
        participant_period_id: Uuid::new_v4(),
    };
    let (pkg_ref, pkg_wrapper, not_before, not_after) =
        genuine_terminal_fixture::build_genuine_invitee_key_package(
            &invitee,
            acceptance_time,
            pkg_not_before,
            pkg_not_after,
        );
    let (_acceptance, event_json) = genuine_acceptance_event(
        &entry,
        &invitee,
        policy.transition_id,
        &policy_next_coordinate,
        Some((pkg_ref, pkg_wrapper.clone())),
        acceptance_time,
    );

    // Case A: Missing key package in DB
    {
        let mut tx = pool_a.begin().await.expect("begin tx");
        let res = test_apply_historical_acceptance_entry(
            &mut tx,
            admission_digest,
            3,
            selector.clone(),
            routes.clone(),
            event_json.clone(),
        )
        .await;
        assert_eq!(res.err(), Some(RemotePrefixBootstrapError::Authority));
    }

    // Case B: Expired key package in DB (seeded with past not_after)
    {
        let Some((pool_b, _guard_b, _)) = build_test_state().await else {
            return;
        };
        let expired_not_before = actor_created_at - chrono::Duration::hours(1);
        let expired_not_after = actor_created_at + chrono::Duration::minutes(30);
        let (expired_ref, expired_wrapper, exp_nb, exp_na) =
            genuine_terminal_fixture::build_genuine_invitee_key_package(
                &invitee,
                actor_created_at,
                expired_not_before,
                expired_not_after,
            );
        seed_genuine_key_package_at(
            &pool_b,
            &bob_did,
            bob_device,
            &bob_key_id,
            &expired_ref,
            &expired_wrapper,
            exp_nb,
            exp_na,
            actor_created_at,
        )
        .await;

        let (_exp_acceptance, exp_event_json) = genuine_acceptance_event(
            &entry,
            &invitee,
            policy.transition_id,
            &policy_next_coordinate,
            Some((expired_ref, expired_wrapper)),
            acceptance_time,
        );

        let mut tx = pool_b.begin().await.expect("begin tx");
        let res = test_apply_historical_acceptance_entry(
            &mut tx,
            admission_digest,
            3,
            selector.clone(),
            routes.clone(),
            exp_event_json,
        )
        .await;
        assert_eq!(res.err(), Some(RemotePrefixBootstrapError::Authority));
    }

    // Case C: Consumed key package in DB (terminal state)
    {
        let Some((pool_c, _guard_c, _)) = build_test_state().await else {
            return;
        };
        seed_genuine_key_package_at(
            &pool_c,
            &bob_did,
            bob_device,
            &bob_key_id,
            &pkg_ref,
            &pkg_wrapper,
            not_before,
            not_after,
            actor_created_at,
        )
        .await;
        sqlx::query(
            "UPDATE chat.key_packages SET status='expired', terminal_at=not_after WHERE owner_did=$1 AND owner_device_id=$2",
        )
        .bind(&bob_did)
        .bind(bob_device)
        .execute(&pool_c)
        .await
        .expect("expire key package");
        let mut tx = pool_c.begin().await.expect("begin tx");
        let res = test_apply_historical_acceptance_entry(
            &mut tx,
            admission_digest,
            3,
            selector.clone(),
            routes.clone(),
            event_json.clone(),
        )
        .await;
        assert_eq!(res.err(), Some(RemotePrefixBootstrapError::Authority));
    }

    // Case D: Package reference different / mismatch
    {
        let Some((pool_d, _guard_d, _)) = build_test_state().await else {
            return;
        };
        let diff_pkg_ref: [u8; 32] = [0xee_u8; 32];
        seed_genuine_key_package_at(
            &pool_d,
            &bob_did,
            bob_device,
            &bob_key_id,
            &diff_pkg_ref,
            &pkg_wrapper,
            not_before,
            not_after,
            actor_created_at,
        )
        .await;

        let mut tx = pool_d.begin().await.expect("begin tx");
        let res = test_apply_historical_acceptance_entry(
            &mut tx,
            admission_digest,
            3,
            selector.clone(),
            routes.clone(),
            event_json.clone(),
        )
        .await;
        assert_eq!(res.err(), Some(RemotePrefixBootstrapError::Authority));
    }
}

// 26. Historical policy changes other than None -> Pending are unconditionally rejected
#[tokio::test]
async fn historical_policy_rejects_non_pending_add_changes() {
    let Some((pool, _db_guard)) = setup_test_db().await else {
        return;
    };

    let convo_id = Uuid::new_v4();
    let sequencer_did = "did:web:sequencer.catbird.blue";
    let creation_time = corpus_evaluation_instant(1_000);
    let policy_time = corpus_evaluation_instant(2_000);

    let actor_created_at = corpus_evaluation_instant(0) - chrono::Duration::hours(1);
    let (entry, creation_event) = genuine_creation_event(convo_id, creation_time);
    seed_protocol_instance(&pool).await;
    seed_actor_at(
        &pool,
        &entry.actor_did,
        entry.actor_device_id,
        &entry.public_key,
        actor_created_at,
    )
    .await;

    let selector =
        RemotePrefixBootstrapSelector::new(convo_id, sequencer_did.to_string(), 0).unwrap();
    let admission_digest = [0x55u8; 32];
    let mut routes = BTreeMap::new();
    routes.insert(entry.actor_did.clone(), None);

    let mut tx = pool.begin().await.expect("begin tx");
    test_apply_historical_creation_entry(
        &mut tx,
        admission_digest,
        2,
        selector.clone(),
        routes.clone(),
        creation_event,
    )
    .await
    .expect("apply creation");
    tx.commit().await.expect("commit creation");

    // Construct bad policy with Remove change
    let manifest = corpus_manifest();
    let coordinate =
        coordinate_with_conversation(&genesis_coordinate(&manifest), *convo_id.as_bytes());
    let remove_did = random_plc_did();
    let bad_policy = genuine_terminal_fixture::genuine_policy_control(
        &entry,
        &coordinate,
        2,
        &policy_time.to_rfc3339_opts(SecondsFormat::Millis, true),
        vec![GenuinePolicyChange::Remove(&remove_did)],
    );
    let bad_policy_event = build_test_event_json(
        2,
        0,
        bad_policy.entry.entry_id,
        POLICY_ENTRY_TYPE_ID,
        &bad_policy.entry.accepted_payload_bytes,
        &bad_policy.entry.signed_request_bytes,
        &vec_to_32(&bad_policy.entry.outer_entry_fingerprint),
        policy_time,
    );

    let mut tx = pool.begin().await.expect("begin tx");
    let res = test_apply_historical_policy_entry(
        &mut tx,
        admission_digest,
        2,
        selector,
        routes,
        bad_policy_event,
    )
    .await;

    assert!(
        matches!(res, Err(RemotePrefixBootstrapError::Authority)),
        "non-add policy change must unconditionally be rejected with Authority error, got: {res:?}"
    );
}
// 27. Exact zero notifications, recipients, and outbox generation
#[tokio::test]
async fn historical_execution_produces_exact_zero_notifications_and_outbox() {
    let Some((pool, _db_guard)) = setup_test_db().await else {
        return;
    };

    let convo_id = Uuid::new_v4();
    let sequencer_did = "did:web:sequencer.catbird.blue";
    let now = corpus_evaluation_instant(1_000);

    let actor_created_at = corpus_evaluation_instant(0) - chrono::Duration::hours(1);
    let (entry, creation_event) = genuine_creation_event(convo_id, now);
    seed_protocol_instance(&pool).await;
    seed_actor_at(
        &pool,
        &entry.actor_did,
        entry.actor_device_id,
        &entry.public_key,
        actor_created_at,
    )
    .await;

    let selector =
        RemotePrefixBootstrapSelector::new(convo_id, sequencer_did.to_string(), 0).unwrap();
    let admission_digest = [0x55u8; 32];
    let mut routes = BTreeMap::new();
    routes.insert(entry.actor_did.clone(), None);

    // Capture baseline counts before historical execution:
    let events_before: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM chat.events")
        .fetch_one(&pool)
        .await
        .expect("count events before");
    let recipients_before: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM chat.event_recipients")
        .fetch_one(&pool)
        .await
        .expect("count recipients before");
    let outbox_before: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM chat.outbox")
        .fetch_one(&pool)
        .await
        .expect("count outbox before");
    let queue_before: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM outbound_queue")
        .fetch_one(&pool)
        .await
        .expect("count queue before");
    let fed_outbox_before: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM federation_outbox")
        .fetch_one(&pool)
        .await
        .expect("count fed outbox before");

    let mut tx = pool.begin().await.expect("begin tx");
    let outcome = test_apply_historical_creation_entry(
        &mut tx,
        admission_digest,
        1,
        selector,
        routes,
        creation_event,
    )
    .await
    .expect("apply creation");

    assert_eq!(outcome.allocated_seq, 1);
    assert_eq!(outcome.event_positions_count, 0);
    tx.commit().await.expect("commit creation");

    // Assert exact ZERO incremental rows:
    let events_after: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM chat.events")
        .fetch_one(&pool)
        .await
        .expect("count events after");
    assert_eq!(
        events_after, events_before,
        "must be exact 0 events written"
    );

    let recipients_after: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM chat.event_recipients")
        .fetch_one(&pool)
        .await
        .expect("count event recipients after");
    assert_eq!(
        recipients_after, recipients_before,
        "must be exact 0 event recipients written"
    );

    let outbox_after: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM chat.outbox")
        .fetch_one(&pool)
        .await
        .expect("count outbox after");
    assert_eq!(
        outbox_after, outbox_before,
        "must be exact 0 outbox written"
    );

    let queue_after: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM outbound_queue")
        .fetch_one(&pool)
        .await
        .expect("count queue after");
    assert_eq!(
        queue_after, queue_before,
        "must be exact 0 outbound_queue written"
    );
    let fed_outbox_after: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM federation_outbox")
        .fetch_one(&pool)
        .await
        .expect("count federation outbox after");
    assert_eq!(
        fed_outbox_after, fed_outbox_before,
        "must be exact 0 federation outbox written"
    );

    // Assert positive persistence in semantic tables:
    let convo_count: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM chat.conversations WHERE conversation_id = $1 AND is_remote = true",
    )
    .bind(convo_id)
    .fetch_one(&pool)
    .await
    .expect("count convo");
    assert_eq!(convo_count, 1, "conversation persisted as remote");

    let entries_count: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM chat.entries WHERE conversation_id = $1")
            .bind(convo_id)
            .fetch_one(&pool)
            .await
            .expect("count entries");
    assert_eq!(entries_count, 1, "entry persisted");

    let participant_count: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM chat.participants WHERE conversation_id = $1")
            .bind(convo_id)
            .fetch_one(&pool)
            .await
            .expect("count participants");
    assert_eq!(participant_count, 1, "participant persisted");
}

// 28. Positive four-step pipeline proves all four planners succeed with exact zero side effects
#[tokio::test]
async fn historical_planners_positive_pipeline_succeeds_with_zero_side_effects() {
    let Some((pool, _db_guard)) = setup_test_db().await else {
        return;
    };

    let convo_id = Uuid::new_v4();
    let sequencer_did = "did:web:sequencer.catbird.blue";
    let creation_time = corpus_evaluation_instant(1_000);
    let policy_time = corpus_evaluation_instant(2_000);
    let acceptance_time = corpus_evaluation_instant(3_000);
    let fulfillment_time = corpus_evaluation_instant(4_000);

    let actor_created_at = corpus_evaluation_instant(0) - chrono::Duration::hours(1);
    seed_protocol_instance(&pool).await;

    let (bob_device_identity, bob_did) = fresh_bob();
    let bob_device = Uuid::from_bytes(*bob_device_identity.device_id());
    let bob_signing_key = SigningKey::generate(&mut rand::thread_rng());
    let bob_public_key = bob_signing_key.verifying_key().to_bytes();
    let bob_key_id = seed_actor_at(
        &pool,
        &bob_did,
        bob_device,
        &bob_public_key,
        actor_created_at,
    )
    .await;
    let selector =
        RemotePrefixBootstrapSelector::new(convo_id, sequencer_did.to_string(), 0).unwrap();
    let admission_digest = [0x77u8; 32];

    let invitee = AcceptanceInvitee {
        did: bob_did.clone(),
        device_id: bob_device,
        key_id: bob_key_id.clone(),
        signing_key: bob_signing_key.clone(),
        participant_period_id: Uuid::new_v4(),
    };
    let pkg_not_before = actor_created_at - chrono::Duration::hours(1);
    let pkg_not_after = actor_created_at + chrono::Duration::days(30);

    let add_transition_id = Uuid::new_v4();
    let crypto_fixture = genuine_terminal_fixture::build_dynamic_two_leaf_crypto_fixture(
        convo_id,
        add_transition_id,
        invitee.clone(),
        creation_time,
        acceptance_time,
        fulfillment_time,
        pkg_not_before,
        pkg_not_after,
    );

    seed_actor_at(
        &pool,
        &crypto_fixture.entry.actor_did,
        crypto_fixture.entry.actor_device_id,
        &crypto_fixture.entry.public_key,
        actor_created_at,
    )
    .await;

    let mut routes = BTreeMap::new();
    routes.insert(crypto_fixture.entry.actor_did.clone(), None);
    routes.insert(
        bob_did.clone(),
        Some("did:web:remote-ds.catbird.blue".to_string()),
    );
    seed_genuine_key_package_at(
        &pool,
        &bob_did,
        bob_device,
        &bob_key_id,
        &crypto_fixture.key_package_ref,
        &crypto_fixture.key_package_wrapper,
        pkg_not_before,
        pkg_not_after,
        actor_created_at,
    )
    .await;

    // Baseline counts before pipeline:
    let events_before: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM chat.events")
        .fetch_one(&pool)
        .await
        .expect("count events before");
    let recipients_before: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM chat.event_recipients")
        .fetch_one(&pool)
        .await
        .expect("count recipients before");
    let outbox_before: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM chat.outbox")
        .fetch_one(&pool)
        .await
        .expect("count outbox before");
    let queue_before: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM outbound_queue")
        .fetch_one(&pool)
        .await
        .expect("count queue before");
    let fed_outbox_before: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM federation_outbox")
        .fetch_one(&pool)
        .await
        .expect("count fed outbox before");

    // Step 1: Historical Creation Entry (Planner 1: Creation)
    let signed_at_str = (creation_time - chrono::Duration::seconds(10))
        .to_rfc3339_opts(SecondsFormat::Millis, true);
    let received_at_str = creation_time.to_rfc3339_opts(SecondsFormat::Millis, true);
    let entry = bind_creation_entry_to_group_info(
        crypto_fixture.entry.clone(),
        &crypto_fixture.genesis_group_info,
        crypto_fixture.genesis.coordinate(),
        &signed_at_str,
        &received_at_str,
    );
    let creation_event = build_test_event_json(
        1,
        0,
        entry.entry_id,
        CREATION_ENTRY_TYPE_ID,
        &entry.public_row_json,
        &entry.raw_wrapper,
        &entry.outer_entry_fingerprint,
        creation_time,
    );
    let mut tx = pool.begin().await.expect("begin tx 1");
    let outcome1 = test_apply_historical_creation_entry(
        &mut tx,
        admission_digest,
        4,
        selector.clone(),
        routes.clone(),
        creation_event,
    )
    .await
    .expect("apply historical creation");
    assert_eq!(outcome1.allocated_seq, 1);
    assert_eq!(outcome1.event_positions_count, 0);
    tx.commit().await.expect("commit creation step");

    // Step 2: Historical Policy Add Entry (Planner 2: Policy Add)
    let (policy, policy_next_coordinate, policy_event) = genuine_policy_event(
        &entry,
        crypto_fixture.genesis.coordinate(),
        &bob_did,
        policy_time,
    );
    let mut tx = pool.begin().await.expect("begin tx 2");
    let outcome2 = test_apply_historical_policy_entry(
        &mut tx,
        admission_digest,
        4,
        selector.clone(),
        routes.clone(),
        policy_event,
    )
    .await
    .expect("apply historical policy add");
    assert_eq!(outcome2.allocated_seq, 2);
    assert_eq!(outcome2.event_positions_count, 0);
    tx.commit().await.expect("commit policy step");

    // Step 3: Historical Participant Acceptance Entry (Planner 3: Acceptance)
    let (acceptance, acceptance_event) = genuine_acceptance_event(
        &entry,
        &invitee,
        policy.transition_id,
        &policy_next_coordinate,
        Some((
            crypto_fixture.key_package_ref,
            crypto_fixture.key_package_wrapper.clone(),
        )),
        acceptance_time,
    );
    let mut tx = pool.begin().await.expect("begin tx 3");
    let outcome3 = test_apply_historical_acceptance_entry(
        &mut tx,
        admission_digest,
        4,
        selector.clone(),
        routes.clone(),
        acceptance_event,
    )
    .await
    .expect("apply historical acceptance");
    assert_eq!(outcome3.allocated_seq, 3);
    assert_eq!(outcome3.event_positions_count, 0);
    tx.commit().await.expect("commit acceptance step");

    // Step 4: Historical Leaf Recovery Fulfillment Entry (Planner 4: Recovery Fulfillment)
    let creation_transition_id = signed_creation_transition_id(&entry);
    let post_acceptance_coordinate = PublicGroupSnapshotCoordinate::new(
        *policy_next_coordinate.conversation_id(),
        policy_next_coordinate.generation(),
        policy_next_coordinate.state_version() + 1,
        *policy_next_coordinate.group_id(),
        policy_next_coordinate.epoch(),
        *policy_next_coordinate.group_context_hash(),
        *policy_next_coordinate.confirmation_tag(),
        PublicGroupSnapshotLifecycle::Active,
    );
    let signed_at = fulfillment_time.to_rfc3339_opts(SecondsFormat::Millis, true);
    let received_at_str = signed_at.clone();
    let fulfillment = genuine_terminal_fixture::build_genuine_add_fulfillment_entry_with_bytes(
        &entry,
        &invitee,
        &acceptance,
        creation_transition_id,
        &post_acceptance_coordinate,
        crypto_fixture.committed.coordinate(),
        add_transition_id,
        4,
        &signed_at,
        &received_at_str,
        crypto_fixture.commit.clone(),
        crypto_fixture.welcome.clone(),
        0x71,
        0x72,
    );
    let fulfillment_event = build_test_event_json(
        4,
        0,
        fulfillment.entry_id,
        LEAF_RECOVERY_FULFILLMENT_ENTRY_TYPE_ID,
        &fulfillment.public_row_json,
        &fulfillment.raw_wrapper,
        &fulfillment.outer_entry_fingerprint,
        fulfillment_time,
    );
    let mut tx = pool.begin().await.expect("begin tx 4");
    let outcome4 = test_apply_historical_recovery_fulfillment_entry(
        &mut tx,
        admission_digest,
        4,
        selector.clone(),
        routes.clone(),
        fulfillment_event,
    )
    .await
    .expect("apply historical recovery fulfillment");
    assert_eq!(outcome4.allocated_seq, 4);
    assert_eq!(outcome4.event_positions_count, 0);
    tx.commit().await.expect("commit recovery fulfillment step");

    // Verify exact zero side-effects across the entire four-step execution:
    let events_after: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM chat.events")
        .fetch_one(&pool)
        .await
        .expect("count events after");
    assert_eq!(
        events_after, events_before,
        "must be exact 0 events written"
    );

    let recipients_after: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM chat.event_recipients")
        .fetch_one(&pool)
        .await
        .expect("count event recipients after");
    assert_eq!(
        recipients_after, recipients_before,
        "must be exact 0 event recipients written"
    );

    let outbox_after: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM chat.outbox")
        .fetch_one(&pool)
        .await
        .expect("count outbox after");
    assert_eq!(
        outbox_after, outbox_before,
        "must be exact 0 outbox written"
    );

    let queue_after: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM outbound_queue")
        .fetch_one(&pool)
        .await
        .expect("count queue after");
    assert_eq!(
        queue_after, queue_before,
        "must be exact 0 outbound_queue written"
    );
    let fed_outbox_after: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM federation_outbox")
        .fetch_one(&pool)
        .await
        .expect("count federation outbox after");
    assert_eq!(
        fed_outbox_after, fed_outbox_before,
        "must be exact 0 federation outbox written"
    );

    // Verify semantic state in DB
    let entries_count: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM chat.entries WHERE conversation_id = $1")
            .bind(convo_id)
            .fetch_one(&pool)
            .await
            .expect("count entries");
    assert_eq!(entries_count, 4, "4 entries persisted in history");
}

async fn seal_historical_prefix_for_test(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    conversation_id: Uuid,
    sequencer_did: &str,
    last_seq: i64,
) {
    let sync_rows = sqlx::query(
        r#"
        INSERT INTO federation_sync_state
            (convo_id, sequencer_ds_did, sequencer_term, last_seq, last_epoch,
             last_digest, last_reconciled_at, drift_count, updated_at, status)
        VALUES ($1, $2, 0, $3, 0, $4, NOW(), 0, NOW(), 'healthy')
        "#,
    )
    .bind(conversation_id.to_string())
    .bind(sequencer_did)
    .bind(last_seq)
    .bind(hex::encode([0u8; 32]))
    .execute(&mut **tx)
    .await
    .expect("insert matching healthy sync state")
    .rows_affected();
    assert_eq!(sync_rows, 1);

    let cutoff_rows = sqlx::query(
        "UPDATE chat.conversations SET historical_bootstrap_last_seq = $2 \
         WHERE conversation_id = $1",
    )
    .bind(conversation_id)
    .bind(last_seq)
    .execute(&mut **tx)
    .await
    .expect("seal historical prefix cutoff")
    .rows_affected();
    assert_eq!(cutoff_rows, 1);

    sqlx::query("SET CONSTRAINTS ALL IMMEDIATE")
        .execute(&mut **tx)
        .await
        .expect("sealed historical prefix satisfies deferred constraints");
}

// 29. Historical bootstrap ignores exhausted live invitation quota and mutates zero quota rows
#[tokio::test]
async fn historical_bootstrap_ignores_exhausted_live_invitation_quota_and_mutates_zero_quota_rows()
{
    let Some((pool, _db_guard)) = setup_test_db().await else {
        return;
    };

    let convo_id = Uuid::new_v4();
    let sequencer_did = "did:web:sequencer.catbird.blue";
    let creation_time = corpus_evaluation_instant(1_000);
    let policy_time = corpus_evaluation_instant(2_000);

    let actor_created_at = corpus_evaluation_instant(0) - chrono::Duration::hours(1);
    let (entry, creation_event) = genuine_creation_event(convo_id, creation_time);
    seed_protocol_instance(&pool).await;
    seed_actor_at(
        &pool,
        &entry.actor_did,
        entry.actor_device_id,
        &entry.public_key,
        actor_created_at,
    )
    .await;

    let (bob_device_identity, bob_did) = fresh_bob();
    let bob_device = Uuid::from_bytes(*bob_device_identity.device_id());
    let bob_signing_key = SigningKey::generate(&mut rand::thread_rng());
    let bob_public_key = bob_signing_key.verifying_key().to_bytes();
    seed_actor_at(
        &pool,
        &bob_did,
        bob_device,
        &bob_public_key,
        actor_created_at,
    )
    .await;

    let admission_digest = [0x55u8; 32];
    let mut routes = BTreeMap::new();
    routes.insert(entry.actor_did.clone(), None);
    routes.insert(bob_did.clone(), None);

    // Seed 5 committed pending invitations for (Alice -> Bob) across 5 distinct remote conversations
    for _ in 0..5 {
        let existing_cid = Uuid::new_v4();
        let (existing_entry, existing_creation) =
            genuine_creation_event(existing_cid, creation_time);
        let existing_sel =
            RemotePrefixBootstrapSelector::new(existing_cid, sequencer_did.to_string(), 0).unwrap();
        let mut tx = pool.begin().await.expect("begin setup tx");
        test_apply_historical_creation_entry(
            &mut tx,
            admission_digest,
            2,
            existing_sel.clone(),
            routes.clone(),
            existing_creation,
        )
        .await
        .expect("setup creation");

        let manifest = corpus_manifest();
        let coordinate =
            coordinate_with_conversation(&genesis_coordinate(&manifest), *existing_cid.as_bytes());
        let (_policy, _, policy_ev) =
            genuine_policy_event(&existing_entry, &coordinate, &bob_did, policy_time);
        test_apply_historical_policy_entry(
            &mut tx,
            admission_digest,
            2,
            existing_sel,
            routes.clone(),
            policy_ev,
        )
        .await
        .expect("setup policy");
        seal_historical_prefix_for_test(&mut tx, existing_cid, sequencer_did, 2).await;
        tx.commit().await.expect("commit historical invitation");
    }

    // Verify 5 live pending invitations exist in DB for (Alice -> Bob)
    let live_pending_before: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM chat.participants WHERE created_by_did = $1 AND user_did = $2 AND current_membership AND status = 'pending'",
    )
    .bind(&entry.actor_did)
    .bind(&bob_did)
    .fetch_one(&pool)
    .await
    .expect("count live pending");
    assert_eq!(
        live_pending_before, 5,
        "5 live pending invitations exist (live quota is exhausted at limit 5)"
    );

    // Snapshot preexisting DB state
    let conversations_before: i64 = sqlx::query_scalar("SELECT count(*) FROM chat.conversations")
        .fetch_one(&pool)
        .await
        .expect("count convos before");

    // Now import the 6th remote conversation with the same (Alice -> Bob) pending invitation
    let sixth_convo_id = Uuid::new_v4();
    let (sixth_entry, sixth_creation) = genuine_creation_event(sixth_convo_id, creation_time);
    let sixth_sel =
        RemotePrefixBootstrapSelector::new(sixth_convo_id, sequencer_did.to_string(), 0).unwrap();

    let mut tx = pool.begin().await.expect("begin 6th tx");
    test_apply_historical_creation_entry(
        &mut tx,
        admission_digest,
        2,
        sixth_sel.clone(),
        routes.clone(),
        sixth_creation,
    )
    .await
    .expect("apply 6th creation");

    let manifest = corpus_manifest();
    let coordinate =
        coordinate_with_conversation(&genesis_coordinate(&manifest), *sixth_convo_id.as_bytes());
    let (_policy, _, sixth_policy_ev) =
        genuine_policy_event(&sixth_entry, &coordinate, &bob_did, policy_time);
    test_apply_historical_policy_entry(
        &mut tx,
        admission_digest,
        2,
        sixth_sel,
        routes.clone(),
        sixth_policy_ev,
    )
    .await
    .expect("apply 6th policy");
    seal_historical_prefix_for_test(&mut tx, sixth_convo_id, sequencer_did, 2).await;
    tx.commit().await.expect("commit 6th conversation");

    let conversations_after: i64 = sqlx::query_scalar("SELECT count(*) FROM chat.conversations")
        .fetch_one(&pool)
        .await
        .expect("count convos after");
    assert_eq!(
        conversations_after,
        conversations_before + 1,
        "exactly one 6th conversation added"
    );

    let live_pending_after: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM chat.participants WHERE created_by_did = $1 AND user_did = $2 AND current_membership AND status = 'pending'",
    )
    .bind(&entry.actor_did)
    .bind(&bob_did)
    .fetch_one(&pool)
    .await
    .expect("count live pending after");
    assert_eq!(
        live_pending_after, 6,
        "6th historical pending invitation recorded without quota block"
    );
    // Ordinary live/unauthorized insert of a 7th pending invitation for (Alice -> Bob) without the historical session variable fails with quota error 23514
    let seventh_convo_id = Uuid::new_v4();
    let (seventh_entry, seventh_creation) = genuine_creation_event(seventh_convo_id, creation_time);
    let seventh_sel =
        RemotePrefixBootstrapSelector::new(seventh_convo_id, sequencer_did.to_string(), 0).unwrap();

    let mut ordinary_tx = pool.begin().await.expect("begin 7th tx");
    test_apply_historical_creation_entry(
        &mut ordinary_tx,
        admission_digest,
        1,
        seventh_sel.clone(),
        routes.clone(),
        seventh_creation,
    )
    .await
    .expect("apply 7th creation");

    let manifest = corpus_manifest();
    let coordinate =
        coordinate_with_conversation(&genesis_coordinate(&manifest), *seventh_convo_id.as_bytes());
    let (_policy, _, seventh_policy_ev) =
        genuine_policy_event(&seventh_entry, &coordinate, &bob_did, policy_time);
    test_apply_historical_policy_entry(
        &mut ordinary_tx,
        admission_digest,
        2,
        seventh_sel,
        routes,
        seventh_policy_ev,
    )
    .await
    .expect("plan and apply 7th policy step");

    let err = sqlx::query("SET CONSTRAINTS ALL IMMEDIATE")
        .execute(&mut *ordinary_tx)
        .await
        .expect_err("entry above cutoff must trip live invitation quota limit (23514)");
    let db_err = err.as_database_error().expect("must be a database error");
    assert_eq!(
        db_err.code().as_deref(),
        Some("23514"),
        "expected SQLSTATE 23514 check violation"
    );
}

#[tokio::test]
async fn hostile_custom_guc_is_completely_inert() {
    let Some((pool, _db_guard)) = setup_test_db().await else {
        return;
    };

    let sequencer_did = "did:web:sequencer.catbird.blue";
    let creation_time = corpus_evaluation_instant(1_000);
    let policy_time = corpus_evaluation_instant(2_000);
    let actor_created_at = corpus_evaluation_instant(0) - chrono::Duration::hours(1);
    let admission_digest = [0x77; 32];
    seed_protocol_instance(&pool).await;

    let (actor, _) = genuine_creation_event(Uuid::new_v4(), creation_time);
    seed_actor_at(
        &pool,
        &actor.actor_did,
        actor.actor_device_id,
        &actor.public_key,
        actor_created_at,
    )
    .await;
    let (bob_identity, bob_did) = fresh_bob();
    let bob_device = Uuid::from_bytes(*bob_identity.device_id());
    let bob_signing_key = SigningKey::generate(&mut rand::thread_rng());
    seed_actor_at(
        &pool,
        &bob_did,
        bob_device,
        &bob_signing_key.verifying_key().to_bytes(),
        actor_created_at,
    )
    .await;
    let mut routes = BTreeMap::new();
    routes.insert(actor.actor_did.clone(), None);
    routes.insert(bob_did.clone(), None);

    for _ in 0..5 {
        let conversation_id = Uuid::new_v4();
        let (entry, creation_event) = genuine_creation_event(conversation_id, creation_time);
        let selector =
            RemotePrefixBootstrapSelector::new(conversation_id, sequencer_did.to_string(), 0)
                .unwrap();
        let coordinate = coordinate_with_conversation(
            &genesis_coordinate(&corpus_manifest()),
            *conversation_id.as_bytes(),
        );
        let (_, _, policy_event) = genuine_policy_event(&entry, &coordinate, &bob_did, policy_time);
        let mut tx = pool.begin().await.unwrap();
        test_apply_historical_creation_entry(
            &mut tx,
            admission_digest,
            2,
            selector.clone(),
            routes.clone(),
            creation_event,
        )
        .await
        .unwrap();
        test_apply_historical_policy_entry(
            &mut tx,
            admission_digest,
            2,
            selector,
            routes.clone(),
            policy_event,
        )
        .await
        .unwrap();
        seal_historical_prefix_for_test(&mut tx, conversation_id, sequencer_did, 2).await;
        tx.commit().await.unwrap();
    }

    let target_id = Uuid::new_v4();
    let (entry, creation_event) = genuine_creation_event(target_id, creation_time);
    let selector =
        RemotePrefixBootstrapSelector::new(target_id, sequencer_did.to_string(), 0).unwrap();
    let coordinate = coordinate_with_conversation(
        &genesis_coordinate(&corpus_manifest()),
        *target_id.as_bytes(),
    );
    let (_, _, policy_event) = genuine_policy_event(&entry, &coordinate, &bob_did, policy_time);
    let mut tx = pool.begin().await.unwrap();
    sqlx::query("SELECT set_config('catbird.historical_bootstrap_conversation', $1, true)")
        .bind(target_id.to_string())
        .execute(&mut *tx)
        .await
        .unwrap();
    test_apply_historical_creation_entry(
        &mut tx,
        admission_digest,
        2,
        selector.clone(),
        routes.clone(),
        creation_event,
    )
    .await
    .unwrap();
    test_apply_historical_policy_entry(
        &mut tx,
        admission_digest,
        2,
        selector,
        routes,
        policy_event,
    )
    .await
    .unwrap();

    let err = sqlx::query("SET CONSTRAINTS ALL IMMEDIATE")
        .execute(&mut *tx)
        .await
        .expect_err("hostile custom GUC must not bypass live invitation quota");
    assert_eq!(
        err.as_database_error().unwrap().code().as_deref(),
        Some("23514")
    );
    tx.rollback().await.unwrap();

    for migration in [
        include_str!("../migrations/20260828000001_chat_historical_bootstrap_quota.sql"),
        include_str!("../migrations/20260828000002_chat_historical_bootstrap_application.sql"),
    ] {
        assert!(!migration.contains("current_setting"));
        assert!(!migration.contains("catbird.historical_bootstrap_conversation"));
    }
}

#[tokio::test]
async fn historical_application_send_mirroring_violates_xor_constraint() {
    let Some((pool, _db_guard)) = setup_test_db().await else {
        return;
    };

    let convo_id = Uuid::new_v4();
    let sequencer_did = "did:web:sequencer.catbird.blue";
    let actor_created_at = corpus_evaluation_instant(0) - chrono::Duration::hours(1);

    seed_approved_peer(&pool, sequencer_did).await;
    seed_protocol_instance(&pool).await;

    let fixture = build_full_5_event_prefix_fixture(convo_id, sequencer_did, actor_created_at);
    seed_full_test_authority(&pool, &fixture, actor_created_at).await;

    // Apply the 5-event historical prefix (cutoff = 5)
    let admission = test_admission_from_events(&fixture, fixture.events.clone());
    let mut tx = pool.begin().await.unwrap();
    let outcome = test_apply_remote_clean_prefix(&mut tx, admission)
        .await
        .unwrap();
    assert!(matches!(outcome, RemotePrefixApplyOutcome::Applied { .. }));
    tx.commit().await.unwrap();

    // Verify cutoff is 5
    let cutoff: Option<i64> = sqlx::query_scalar(
        "SELECT historical_bootstrap_last_seq FROM chat.conversations WHERE conversation_id = $1",
    )
    .bind(convo_id)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(cutoff, Some(5));

    // Historical application entry is at seq 5
    let (app_msg_id, signed_request_bytes, request_digest, signature, received_at): (
        Uuid,
        Vec<u8>,
        Vec<u8>,
        Vec<u8>,
        DateTime<Utc>,
    ) = sqlx::query_as(
        "SELECT message_id, signed_request_bytes, request_digest, signature, received_at \
         FROM chat.entries WHERE conversation_id = $1 AND seq = 5",
    )
    .bind(convo_id)
    .fetch_one(&pool)
    .await
    .unwrap();
    let verified = crate::chat_protocol::transcript::decode_and_verify_signed_mutation(
        &signed_request_bytes,
        &fixture.actor_public_key,
    )
    .unwrap();
    let transcript_bytes = verified.transcript_bytes().to_vec();
    assert_eq!(verified.request_digest().as_slice(), request_digest);

    // Attempt to insert the exact accepted send mirror for the historical application entry.
    let outcome_bytes = b"{}".as_slice();
    let mut bad_tx = pool.begin().await.unwrap();
    sqlx::query(
        r#"
        INSERT INTO chat.message_sends (
            conversation_id, message_id, signed_request_bytes,
            signing_transcript_bytes, request_digest, signature,
            status, accepted_entry_seq, outcome_bytes, outcome_sha256, received_at
        )
        VALUES ($1, $2, $3, $4, $5, $6, 'accepted', 5, $7, $8, $9)
        "#,
    )
    .bind(convo_id)
    .bind(app_msg_id)
    .bind(&signed_request_bytes)
    .bind(&transcript_bytes)
    .bind(&request_digest)
    .bind(&signature)
    .bind(outcome_bytes)
    .bind(Sha256::digest(outcome_bytes).as_slice())
    .bind(received_at)
    .execute(&mut *bad_tx)
    .await
    .unwrap();

    // SET CONSTRAINTS ALL IMMEDIATE must fail with 23514 due to XOR constraint
    let err = sqlx::query("SET CONSTRAINTS ALL IMMEDIATE")
        .execute(&mut *bad_tx)
        .await
        .expect_err("mirroring send for historical prefix entry must violate XOR constraint");
    let db_err = err.as_database_error().expect("db error");
    assert_eq!(
        db_err.code().as_deref(),
        Some("23514"),
        "expected SQLSTATE 23514 check violation"
    );
    bad_tx.rollback().await.unwrap();
}

#[tokio::test]
async fn cutoff_integrity_and_immutability() {
    let Some((pool, _db_guard)) = setup_test_db().await else {
        return;
    };

    let now = corpus_evaluation_instant(1_000);
    seed_protocol_instance(&pool).await;

    // 1-3. The cutoff shape check rejects a local conversation, seq 0, and any
    // value outside the safe-integer range.
    let remote_seq = Some("did:web:seq.catbird.blue");
    for (is_remote, sequencer_ds, cutoff, case) in [
        (false, None, 5_i64, "cutoff on local conversation"),
        (true, remote_seq, 0, "cutoff = 0"),
        (true, remote_seq, 1 << 53, "cutoff > 2^53 - 1"),
    ] {
        let err = sqlx::query(
            r#"
            INSERT INTO chat.conversations (
                conversation_id, kind, lifecycle, current_generation,
                current_state_version, next_entry_seq, created_at,
                is_remote, sequencer_ds, sequencer_term,
                historical_bootstrap_last_seq
            )
            VALUES ($1, 'group', 'active', 0, 0, 1, $2, $3, $4, 0, $5)
            "#,
        )
        .bind(Uuid::new_v4())
        .bind(now)
        .bind(is_remote)
        .bind(sequencer_ds)
        .bind(cutoff)
        .execute(&pool)
        .await
        .expect_err(&format!("{case} must fail check constraint"));
        assert_eq!(
            err.as_database_error().unwrap().code().as_deref(),
            Some("23514"),
            "{case}"
        );
    }

    // 4. A genuinely bootstrapped remote conversation cannot change its birth cutoff.
    let sequencer_did = "did:web:sequencer.catbird.blue";
    let actor_created_at = corpus_evaluation_instant(0) - chrono::Duration::hours(1);
    seed_approved_peer(&pool, sequencer_did).await;
    let fixture =
        build_full_5_event_prefix_fixture(Uuid::new_v4(), sequencer_did, actor_created_at);
    seed_full_test_authority(&pool, &fixture, actor_created_at).await;
    let admission = test_admission_from_events(&fixture, fixture.events.clone());
    let mut tx = pool.begin().await.expect("begin valid bootstrap");
    let outcome = test_apply_remote_clean_prefix(&mut tx, admission)
        .await
        .expect("apply valid bootstrap");
    assert!(matches!(outcome, RemotePrefixApplyOutcome::Applied { .. }));
    tx.commit().await.expect("commit valid bootstrap");
    let valid_convo_id = fixture.convo_id;

    let err_update = sqlx::query(
        "UPDATE chat.conversations SET historical_bootstrap_last_seq = 6 WHERE conversation_id = $1",
    )
    .bind(valid_convo_id)
    .execute(&pool)
    .await
    .expect_err("updating historical_bootstrap_last_seq must fail immutable identity trigger");
    assert_eq!(
        err_update.as_database_error().unwrap().code().as_deref(),
        Some("23514")
    );
}

// ============================================================================
// Task 6: Apply, replay, and quarantine the prefix atomically
// ============================================================================

fn genuine_application_event(
    convo_id: Uuid,
    seq: i64,
    actor_did: &str,
    actor_device_id: Uuid,
    actor_key_id: &str,
    actor_signing_key: &SigningKey,
    actor_public_key: &[u8],
    prior_coord: &PublicGroupSnapshotCoordinate,
    received_at: DateTime<Utc>,
) -> Value {
    let msg_id = Uuid::new_v4();
    let entry_id = Uuid::new_v4();
    let msg_bytes = vec![0x31u8; 8];
    let now_str = received_at.to_rfc3339_opts(SecondsFormat::Millis, true);

    let unsigned = json!({
        "$type": "blue.catbird.chat.defs#applicationSendBody",
        "signatureDomain": "CATBIRD-CHAT-MESSAGE\u{0}",
        "messageId": msg_id.to_string(),
        "actorDid": actor_did,
        "actorDeviceId": actor_device_id.to_string(),
        "keyId": actor_key_id,
        "authGeneration": 1,
        "prior": {
            "conversationId": convo_id.to_string(),
            "generation": prior_coord.generation(),
            "stateVersion": prior_coord.state_version(),
            "groupId": STANDARD.encode(prior_coord.group_id()),
            "epoch": prior_coord.epoch(),
            "groupContextHash": STANDARD.encode(prior_coord.group_context_hash()),
            "confirmationTag": STANDARD.encode(prior_coord.confirmation_tag()),
            "lifecycle": "active"
        },
        "aad": {
            "protocolVersion": "1",
            "conversationId": STANDARD.encode(convo_id.as_bytes()),
            "generation": prior_coord.generation(),
            "messageId": STANDARD.encode(msg_id.as_bytes()),
            "prior": {
                "conversationId": STANDARD.encode(convo_id.as_bytes()),
                "generation": prior_coord.generation(),
                "stateVersion": prior_coord.state_version(),
                "groupId": STANDARD.encode(prior_coord.group_id()),
                "epoch": prior_coord.epoch(),
                "groupContextHash": STANDARD.encode(prior_coord.group_context_hash()),
                "confirmationTag": STANDARD.encode(prior_coord.confirmation_tag()),
                "lifecycle": "active"
            }
        },
        "applicationMessage": {
            "framing": "mlsMessage",
            "contentType": "privateMessageApplication",
            "bytes": STANDARD.encode(&msg_bytes),
            "sha256": STANDARD.encode(Sha256::digest(&msg_bytes))
        },
        "blobBindings": [],
        "signedAt": now_str,
    });

    let mut wrapper = json!({
        "body": unsigned,
        "signature": STANDARD.encode([0u8; 64]),
    });
    let unsigned_bytes = serde_json::to_vec(&wrapper).unwrap();
    let mutation =
        crate::chat_protocol::transcript::decode_canonical_signed_mutation(&unsigned_bytes)
            .unwrap();
    let sig = actor_signing_key.sign(mutation.transcript_bytes());

    wrapper["signature"] = Value::String(STANDARD.encode(sig.to_bytes()));
    let signed_bytes = serde_json::to_vec(&wrapper).unwrap();

    let verified_mutation = crate::chat_protocol::transcript::decode_and_verify_signed_mutation(
        &signed_bytes,
        actor_public_key,
    )
    .unwrap();

    let received_at_instant =
        crate::chat_protocol::validation::TrustedRequestInstant::from_canonical_for_test(
            crate::chat_protocol::validation::CanonicalTimestamp::parse(&now_str).unwrap(),
        );
    let built = crate::chat_protocol::transcript::build_verified_application_entry(
        verified_mutation,
        crate::chat_protocol::validation::CanonicalUuidV4::parse(&entry_id.to_string()).unwrap(),
        crate::chat_protocol::validation::CanonicalUuidV4::parse(&convo_id.to_string()).unwrap(),
        seq as u64,
        &received_at_instant,
    )
    .unwrap();

    let ciphertext = built.canonical_entry_bytes().to_vec();
    let outer_fp = *built.outer_application_fingerprint();

    build_test_event_json(
        seq,
        0,
        entry_id,
        APPLICATION_ENTRY_TYPE_ID,
        &ciphertext,
        &signed_bytes,
        &outer_fp,
        received_at,
    )
}

struct FullTestPrefixFixture {
    convo_id: Uuid,
    sequencer_did: String,
    actor_did: String,
    actor_device: Uuid,
    actor_key_id: String,
    actor_public_key: Vec<u8>,
    bob_did: String,
    bob_device: Uuid,
    bob_key_id: String,
    bob_public_key: Vec<u8>,
    events: Vec<Value>,
    opening_digest: Value,
    closing_digest: Value,
    digest_sha256: [u8; 32],
    key_package_ref: [u8; 32],
    key_package_wrapper: Vec<u8>,
    pkg_not_before: DateTime<Utc>,
    pkg_not_after: DateTime<Utc>,
    creation_entry_id: Uuid,
    policy_entry_id: Uuid,
    policy_transition_id: Uuid,
    acceptance_entry_id: Uuid,
    fulfillment_entry_id: Uuid,
    app_entry_id: Uuid,
    creation_entry: RealCreationEntry,
    invitee: AcceptanceInvitee,
    acceptance: RealAcceptanceEntry,
    pre_acceptance_coordinate: PublicGroupSnapshotCoordinate,
    post_acceptance_coordinate: PublicGroupSnapshotCoordinate,
    committed_coordinate: PublicGroupSnapshotCoordinate,
    add_transition_id: Uuid,
    commit_bytes: Vec<u8>,
    welcome_bytes: Vec<u8>,
}

fn build_full_5_event_prefix_fixture(
    convo_id: Uuid,
    sequencer_did: &str,
    actor_created_at: DateTime<Utc>,
) -> FullTestPrefixFixture {
    let creation_time = corpus_evaluation_instant(1_000);
    let policy_time = corpus_evaluation_instant(2_000);
    let acceptance_time = corpus_evaluation_instant(3_000);
    let fulfillment_time = corpus_evaluation_instant(4_000);
    let app_time = corpus_evaluation_instant(5_000);

    let (bob_device_identity, bob_did) = fresh_bob();
    let bob_device = Uuid::from_bytes(*bob_device_identity.device_id());
    let bob_signing_key = SigningKey::generate(&mut rand::thread_rng());
    let bob_public_key = bob_signing_key.verifying_key().to_bytes().to_vec();
    let bob_key_id = crate::chat_protocol::validation::ed25519_key_id(&bob_public_key)
        .unwrap()
        .as_str()
        .to_string();

    let invitee = AcceptanceInvitee {
        did: bob_did.clone(),
        device_id: bob_device,
        key_id: bob_key_id.clone(),
        signing_key: bob_signing_key.clone(),
        participant_period_id: Uuid::new_v4(),
    };
    let pkg_not_before = actor_created_at - chrono::Duration::hours(1);
    let pkg_not_after = actor_created_at + chrono::Duration::days(30);
    let add_transition_id = Uuid::new_v4();

    let crypto_fixture = genuine_terminal_fixture::build_dynamic_two_leaf_crypto_fixture(
        convo_id,
        add_transition_id,
        invitee.clone(),
        creation_time,
        acceptance_time,
        fulfillment_time,
        pkg_not_before,
        pkg_not_after,
    );

    let signed_at_str = (creation_time - chrono::Duration::seconds(10))
        .to_rfc3339_opts(SecondsFormat::Millis, true);
    let received_at_str = creation_time.to_rfc3339_opts(SecondsFormat::Millis, true);
    let entry = bind_creation_entry_to_group_info(
        crypto_fixture.entry.clone(),
        &crypto_fixture.genesis_group_info,
        crypto_fixture.genesis.coordinate(),
        &signed_at_str,
        &received_at_str,
    );

    // Event 1: Creation
    let ev1 = build_test_event_json(
        1,
        0,
        entry.entry_id,
        CREATION_ENTRY_TYPE_ID,
        &entry.public_row_json,
        &entry.raw_wrapper,
        &entry.outer_entry_fingerprint,
        creation_time,
    );
    let creation_entry_id = entry.entry_id;

    // Event 2: Policy
    let (policy, policy_next_coordinate, ev2) = genuine_policy_event(
        &entry,
        crypto_fixture.genesis.coordinate(),
        &bob_did,
        policy_time,
    );
    let policy_entry_id = policy.entry.entry_id;

    // Event 3: Acceptance
    let (acceptance, ev3) = genuine_acceptance_event(
        &entry,
        &invitee,
        policy.transition_id,
        &policy_next_coordinate,
        Some((
            crypto_fixture.key_package_ref,
            crypto_fixture.key_package_wrapper.clone(),
        )),
        acceptance_time,
    );
    let acceptance_entry_id = acceptance.entry_id;

    // Event 4: Fulfillment
    let creation_transition_id = signed_creation_transition_id(&entry);
    let post_acceptance_coordinate = PublicGroupSnapshotCoordinate::new(
        *policy_next_coordinate.conversation_id(),
        policy_next_coordinate.generation(),
        policy_next_coordinate.state_version() + 1,
        *policy_next_coordinate.group_id(),
        policy_next_coordinate.epoch(),
        *policy_next_coordinate.group_context_hash(),
        *policy_next_coordinate.confirmation_tag(),
        PublicGroupSnapshotLifecycle::Active,
    );
    let signed_at = fulfillment_time.to_rfc3339_opts(SecondsFormat::Millis, true);
    let received_at_str = signed_at.clone();
    let fulfillment = genuine_terminal_fixture::build_genuine_add_fulfillment_entry_with_bytes(
        &entry,
        &invitee,
        &acceptance,
        creation_transition_id,
        &post_acceptance_coordinate,
        crypto_fixture.committed.coordinate(),
        add_transition_id,
        4,
        &signed_at,
        &received_at_str,
        crypto_fixture.commit.clone(),
        crypto_fixture.welcome.clone(),
        0x71,
        0x72,
    );
    let ev4 = build_test_event_json(
        4,
        0,
        fulfillment.entry_id,
        LEAF_RECOVERY_FULFILLMENT_ENTRY_TYPE_ID,
        &fulfillment.public_row_json,
        &fulfillment.raw_wrapper,
        &fulfillment.outer_entry_fingerprint,
        fulfillment_time,
    );
    let fulfillment_entry_id = fulfillment.entry_id;

    // Event 5: Application using actual committed coordinate
    let alice_signing_key = SigningKey::from_bytes(&entry.signing_seed);
    let ev5 = genuine_application_event(
        convo_id,
        5,
        &entry.actor_did,
        entry.actor_device_id,
        &entry.actor_key_id,
        &alice_signing_key,
        &entry.public_key,
        crypto_fixture.committed.coordinate(),
        app_time,
    );
    let app_entry_id = Uuid::parse_str(ev5["entryId"].as_str().unwrap()).unwrap();

    let events = vec![ev1, ev2, ev3, ev4, ev5];

    let mut hasher = CleanConvoDigestHasher::new();
    for ev in &events {
        let strict = StrictCleanRemoteEvent::try_from(
            serde_json::from_value::<crate::federation::reconciliation::RemoteEvent>(ev.clone())
                .unwrap(),
        )
        .unwrap();
        hasher.update_event(
            strict.seq(),
            strict.generation(),
            strict.entry_id(),
            ev["entryKind"].as_str().unwrap(),
            strict.accepted_payload_bytes(),
            strict.signed_request(),
            strict.outer_fingerprint(),
            strict.received_at(),
        );
    }
    let digest_hex = hasher.finalize();
    let digest_sha256 = hex::decode(&digest_hex).unwrap().try_into().unwrap();

    let opening_digest = json!({
        "convoId": convo_id.to_string(),
        "sequencerDsDid": sequencer_did,
        "sequencerTerm": 0,
        "lastSeq": 5,
        "eventCount": 5,
        "epoch": 0,
        "digestSha256": digest_hex,
        "generatedAt": app_time.to_rfc3339_opts(SecondsFormat::Millis, true),
    });
    let closing_digest = opening_digest.clone();

    FullTestPrefixFixture {
        convo_id,
        sequencer_did: sequencer_did.to_string(),
        actor_did: entry.actor_did.clone(),
        actor_device: entry.actor_device_id,
        actor_key_id: entry.actor_key_id.clone(),
        actor_public_key: entry.public_key.clone(),
        bob_did: bob_did.clone(),
        bob_device,
        bob_key_id: bob_key_id.clone(),
        bob_public_key,
        events,
        opening_digest,
        closing_digest,
        digest_sha256,
        key_package_ref: crypto_fixture.key_package_ref,
        key_package_wrapper: crypto_fixture.key_package_wrapper.clone(),
        pkg_not_before,
        pkg_not_after,
        creation_entry_id,
        policy_entry_id,
        policy_transition_id: policy.transition_id,
        acceptance_entry_id,
        fulfillment_entry_id,
        app_entry_id,
        creation_entry: entry,
        invitee,
        acceptance,
        pre_acceptance_coordinate: policy_next_coordinate,
        post_acceptance_coordinate,
        committed_coordinate: crypto_fixture.committed.coordinate().clone(),
        add_transition_id,
        commit_bytes: crypto_fixture.commit,
        welcome_bytes: crypto_fixture.welcome,
    }
}

fn test_admission_from_events(
    fixture: &FullTestPrefixFixture,
    events: Vec<Value>,
) -> VerifiedRemotePrefixAdmission {
    let mut strict_events = Vec::with_capacity(events.len());
    let mut hasher = CleanConvoDigestHasher::new();
    for event in events {
        let entry_kind = event["entryKind"].as_str().unwrap().to_string();
        let event = StrictCleanRemoteEvent::try_from(
            serde_json::from_value::<crate::federation::reconciliation::RemoteEvent>(event)
                .unwrap(),
        )
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
        strict_events.push(event);
    }
    let digest_sha256 = hex::decode(hasher.finalize()).unwrap().try_into().unwrap();
    let last = strict_events.last().unwrap();
    let digest_anchor = RemoteDigestAnchor::new_for_test(
        fixture.convo_id,
        fixture.sequencer_did.clone(),
        0,
        last.seq(),
        strict_events.len() as i64,
        i64::from(last.generation()),
        digest_sha256,
    );
    let mut participant_routes = BTreeMap::new();
    participant_routes.insert(fixture.actor_did.clone(), None);
    participant_routes.insert(fixture.bob_did.clone(), None);

    VerifiedRemotePrefixAdmission::new_for_test(
        RemotePrefixBootstrapSelector::new(fixture.convo_id, fixture.sequencer_did.clone(), 0)
            .unwrap(),
        ValidatedRemoteDestination {
            url: url::Url::parse("https://127.0.0.1:8080").unwrap(),
            host: "127.0.0.1".to_string(),
            addrs: vec!["127.0.0.1:8080".parse().unwrap()],
        },
        digest_anchor,
        strict_events,
        participant_routes,
        0,
    )
}

fn corrupt_accepted_payload(event: &mut Value) {
    let mut payload = STANDARD
        .decode(event["ciphertext"]["$bytes"].as_str().unwrap())
        .unwrap();
    payload[0] ^= 0xff;
    event["ciphertext"]["$bytes"] = json!(STANDARD.encode(&payload));
    event["acceptedPayloadSha256"]["$bytes"] = json!(STANDARD.encode(Sha256::digest(&payload)));
}

fn build_corrupted_group_info_creation_event(convo_id: Uuid, received_at: DateTime<Utc>) -> Value {
    let manifest = corpus_manifest();
    let entry = build_real_corpus_creation_entry(*convo_id.as_bytes());
    let bad_group_info = vec![0xff; 64];
    let coordinate =
        coordinate_with_conversation(&genesis_coordinate(&manifest), *convo_id.as_bytes());
    let signed_at_str =
        (received_at - chrono::Duration::seconds(10)).to_rfc3339_opts(SecondsFormat::Millis, true);
    let received_at_str = received_at.to_rfc3339_opts(SecondsFormat::Millis, true);
    let entry = bind_creation_entry_to_group_info(
        entry,
        &bad_group_info,
        &coordinate,
        &signed_at_str,
        &received_at_str,
    );
    build_test_event_json(
        1,
        0,
        entry.entry_id,
        CREATION_ENTRY_TYPE_ID,
        &entry.public_row_json,
        &entry.raw_wrapper,
        &entry.outer_entry_fingerprint,
        received_at,
    )
}

async fn seed_full_test_authority(
    pool: &PgPool,
    fixture: &FullTestPrefixFixture,
    actor_created_at: DateTime<Utc>,
) {
    seed_actor_at(
        pool,
        &fixture.actor_did,
        fixture.actor_device,
        &fixture.actor_public_key,
        actor_created_at,
    )
    .await;
    seed_actor_at(
        pool,
        &fixture.bob_did,
        fixture.bob_device,
        &fixture.bob_public_key,
        actor_created_at,
    )
    .await;
    seed_genuine_key_package_at(
        pool,
        &fixture.bob_did,
        fixture.bob_device,
        &fixture.bob_key_id,
        &fixture.key_package_ref,
        &fixture.key_package_wrapper,
        fixture.pkg_not_before,
        fixture.pkg_not_after,
        actor_created_at,
    )
    .await;
}

async fn prepare_bootstrap_toctou_case() -> Option<(
    PgPool,
    common::fresh_db::DisposableDatabase,
    FullTestPrefixFixture,
    VerifiedRemotePrefixAdmission,
)> {
    let (pool, db_guard) = setup_test_db().await?;
    let sequencer_did = "did:web:sequencer.catbird.blue";
    let actor_created_at = corpus_evaluation_instant(0) - chrono::Duration::hours(1);
    seed_approved_peer(&pool, sequencer_did).await;
    seed_protocol_instance(&pool).await;
    let fixture =
        build_full_5_event_prefix_fixture(Uuid::new_v4(), sequencer_did, actor_created_at);
    seed_full_test_authority(&pool, &fixture, actor_created_at).await;
    let admission = test_admission_from_events(&fixture, fixture.events.clone());
    Some((pool, db_guard, fixture, admission))
}

// 30. Advisory lock fixed vector test
#[test]
fn advisory_lock_fixed_vector_matches_plan() {
    let convo_id = Uuid::parse_str("00112233-4455-4677-8899-aabbccddeeff").unwrap();
    let lock_key = compute_bootstrap_advisory_lock_key(convo_id);
    assert_eq!(lock_key, 5165015785976850088);
    assert_eq!(format!("{:016x}", lock_key as u64), "47add27dee6f66a8");
}

// 31. Positive bootstrap application test with full wire, deterministic DB IDs, zero message_sends, and hydrated graph assertions
#[tokio::test]
async fn bootstrap_remote_prefix_positive_apply_succeeds_with_all_checks() {
    let Some((pool, _db_guard)) = setup_test_db().await else {
        return;
    };

    let convo_id = Uuid::new_v4();
    let sequencer_did = "did:web:sequencer.catbird.blue";
    let actor_created_at = corpus_evaluation_instant(0) - chrono::Duration::hours(1);

    seed_approved_peer(&pool, sequencer_did).await;
    seed_protocol_instance(&pool).await;

    let fixture = build_full_5_event_prefix_fixture(convo_id, sequencer_did, actor_created_at);

    seed_full_test_authority(&pool, &fixture, actor_created_at).await;

    let mock_state = MockSequencerState {
        capabilities: vec![
            CAPABILITY_RECONCILIATION_V1.to_string(),
            CAPABILITY_CANONICAL_PREFIX_BOOTSTRAP_V1.to_string(),
        ],
        opening_digest: Some(fixture.opening_digest.clone()),
        closing_digest: Some(fixture.closing_digest.clone()),
        events_pages: vec![json!({
            "convoId": fixture.convo_id.to_string(),
            "fromSeqExclusive": 0,
            "toSeqInclusive": 5,
            "events": fixture.events.clone(),
        })],
        ..Default::default()
    };

    let (destination, _base_url) = spawn_mock_sequencer(mock_state).await;
    let resolver = create_test_resolver(pool.clone(), destination, sequencer_did);
    let outbound = OutboundClient::new(2, 2);

    let auth_client = ServiceAuthClient::from_shared_secret(
        "did:web:destination.catbird.blue".to_string(),
        b"test-secret",
    );
    let auth_sign = move |target: &str, method: &str| {
        auth_client
            .sign_request(target, method)
            .map_err(|e| e.to_string())
    };

    let selector =
        RemotePrefixBootstrapSelector::new(fixture.convo_id, fixture.sequencer_did.clone(), 0)
            .unwrap();

    let outcome =
        bootstrap_remote_mailbox_from_selector(&pool, &resolver, &outbound, &auth_sign, selector)
            .await
            .expect("bootstrap must succeed");

    let RemotePrefixApplyOutcome::Applied {
        conversation_id,
        sequencer_term,
        last_seq,
        digest_sha256,
    } = outcome
    else {
        panic!("expected RemotePrefixApplyOutcome::Applied, got {outcome:?}");
    };

    assert_eq!(conversation_id, fixture.convo_id);
    assert_eq!(sequencer_term, 0);
    assert_eq!(last_seq, 5);
    assert_eq!(digest_sha256, fixture.digest_sha256);

    // 1. Check chat.conversations state
    let convo_row: (bool, Option<String>, i64, i64, Option<i64>) = sqlx::query_as(
        "SELECT is_remote, sequencer_ds, sequencer_term, next_entry_seq, historical_bootstrap_last_seq FROM chat.conversations WHERE conversation_id = $1",
    )
    .bind(fixture.convo_id)
    .fetch_one(&pool)
    .await
    .expect("fetch conversation");

    assert!(convo_row.0, "must be remote conversation");
    assert_eq!(convo_row.1.as_deref(), Some(sequencer_did));
    assert_eq!(convo_row.2, 0);
    assert_eq!(convo_row.3, 6);
    assert_eq!(
        convo_row.4,
        Some(5),
        "historical_bootstrap_last_seq must equal closing last_seq (5)"
    );
    // 2. Check exact wire rows in chat.entries
    let entry_rows: Vec<(i64, Uuid, String)> = sqlx::query_as(
        "SELECT CAST(seq AS BIGINT), entry_id, entry_kind FROM chat.entries WHERE conversation_id = $1 ORDER BY seq ASC",
    )
    .bind(fixture.convo_id)
    .fetch_all(&pool)
    .await
    .expect("fetch entries");
    assert_eq!(entry_rows.len(), 5);
    assert_eq!(
        entry_rows[0],
        (
            1,
            fixture.creation_entry_id,
            CREATION_ENTRY_TYPE_ID.to_string()
        )
    );
    assert_eq!(
        entry_rows[1],
        (2, fixture.policy_entry_id, POLICY_ENTRY_TYPE_ID.to_string())
    );
    assert_eq!(
        entry_rows[2],
        (
            3,
            fixture.acceptance_entry_id,
            PARTICIPANT_ACCEPTANCE_ENTRY_TYPE_ID.to_string()
        )
    );
    assert_eq!(
        entry_rows[3],
        (
            4,
            fixture.fulfillment_entry_id,
            LEAF_RECOVERY_FULFILLMENT_ENTRY_TYPE_ID.to_string()
        )
    );
    assert_eq!(
        entry_rows[4],
        (
            5,
            fixture.app_entry_id,
            APPLICATION_ENTRY_TYPE_ID.to_string()
        )
    );

    let wire_rows: Vec<(i64, Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>, DateTime<Utc>)> = sqlx::query_as(
        r#"
        SELECT CAST(seq AS BIGINT),
               accepted_payload_bytes,
               accepted_payload_sha256,
               signed_request_bytes,
               outer_entry_fingerprint,
               received_at
          FROM chat.entries
         WHERE conversation_id = $1
         ORDER BY seq ASC
        "#,
    )
    .bind(fixture.convo_id)
    .fetch_all(&pool)
    .await
    .expect("fetch immutable wire fields");
    for (index, (row, source)) in wire_rows.iter().zip(&fixture.events).enumerate() {
        let source_bytes = |field: &str| {
            STANDARD
                .decode(source[field]["$bytes"].as_str().unwrap())
                .unwrap()
        };
        assert_eq!(row.0, index as i64 + 1);
        assert_eq!(row.1, source_bytes("ciphertext"));
        assert_eq!(row.2, source_bytes("acceptedPayloadSha256"));
        assert_eq!(row.3, source_bytes("signedRequest"));
        assert_eq!(row.4, source_bytes("outerFingerprint"));
        assert_eq!(
            row.5.timestamp_millis(),
            DateTime::parse_from_rfc3339(source["createdAt"].as_str().unwrap())
                .unwrap()
                .timestamp_millis()
        );
    }

    // 3. Check deterministic destination DB IDs
    let expected_meta_snapshot_id = derive_bootstrap_local_id_for_test(
        fixture.convo_id,
        fixture.creation_entry_id,
        "metadata-snapshot",
        b"",
    );
    let meta_exists: Option<i32> = sqlx::query_scalar(
        "SELECT 1 FROM chat.metadata_snapshots WHERE conversation_id = $1 AND metadata_snapshot_id = $2",
    )
    .bind(fixture.convo_id)
    .bind(expected_meta_snapshot_id)
    .fetch_optional(&pool)
    .await
    .expect("check metadata snapshot id");
    assert!(
        meta_exists.is_some(),
        "metadata snapshot id must match derived deterministic UUID"
    );

    let expected_alice_period_id = derive_bootstrap_local_id_for_test(
        fixture.convo_id,
        fixture.creation_entry_id,
        "participant-period",
        fixture.actor_did.as_bytes(),
    );
    let alice_p_exists: Option<i32> = sqlx::query_scalar(
        "SELECT 1 FROM chat.participants WHERE conversation_id = $1 AND user_did = $2 AND participant_period_id = $3",
    )
    .bind(fixture.convo_id)
    .bind(&fixture.actor_did)
    .bind(expected_alice_period_id)
    .fetch_optional(&pool)
    .await
    .expect("check alice participant period");
    assert!(
        alice_p_exists.is_some(),
        "alice participant period must match derived deterministic UUID"
    );

    let expected_bob_period_id = derive_bootstrap_local_id_for_test(
        fixture.convo_id,
        fixture.policy_entry_id,
        "participant-period",
        fixture.bob_did.as_bytes(),
    );
    let bob_p_exists: Option<i32> = sqlx::query_scalar(
        "SELECT 1 FROM chat.participants WHERE conversation_id = $1 AND user_did = $2 AND participant_period_id = $3",
    )
    .bind(fixture.convo_id)
    .bind(&fixture.bob_did)
    .bind(expected_bob_period_id)
    .fetch_optional(&pool)
    .await
    .expect("check bob participant period");
    assert!(
        bob_p_exists.is_some(),
        "bob participant period must match derived deterministic UUID"
    );

    for (did, device_id, source_entry_id) in [
        (
            fixture.actor_did.as_str(),
            fixture.actor_device,
            fixture.creation_entry_id,
        ),
        (
            fixture.bob_did.as_str(),
            fixture.bob_device,
            fixture.fulfillment_entry_id,
        ),
    ] {
        let leaf_key = [did.as_bytes(), &[0], device_id.as_bytes()].concat();
        let expected_leaf_id = derive_bootstrap_local_id_for_test(
            fixture.convo_id,
            source_entry_id,
            "leaf-period",
            &leaf_key,
        );
        let actual_leaf_id: Uuid = sqlx::query_scalar(
            "SELECT leaf_period_id FROM chat.member_devices WHERE conversation_id = $1 AND user_did = $2 AND device_id = $3",
        )
        .bind(fixture.convo_id)
        .bind(did)
        .bind(device_id)
        .fetch_one(&pool)
        .await
        .expect("fetch deterministic leaf period");
        assert_eq!(actual_leaf_id, expected_leaf_id);
    }

    let participant_routes: Vec<(String, Option<String>)> = sqlx::query_as(
        "SELECT user_did, ds_did FROM chat.participants WHERE conversation_id = $1 ORDER BY user_did",
    )
    .bind(fixture.convo_id)
    .fetch_all(&pool)
    .await
    .expect("fetch participant routing");
    assert_eq!(participant_routes.len(), 2);
    assert!(
        participant_routes
            .iter()
            .all(|(_, ds_did)| ds_did.is_none()),
        "both seeded destination-local participants must retain local routing"
    );

    // 4. Verify zero synthetic claims / message_sends rows created during bootstrap and non-NULL canonical message_id
    let app_entries: Vec<(i64, Option<Uuid>)> = sqlx::query_as(
        "SELECT CAST(seq AS BIGINT), message_id FROM chat.entries WHERE conversation_id = $1 AND entry_kind = $2 ORDER BY seq ASC",
    )
    .bind(fixture.convo_id)
    .bind(APPLICATION_ENTRY_TYPE_ID)
    .fetch_all(&pool)
    .await
    .expect("fetch application entries");
    assert_eq!(app_entries.len(), 1);
    assert_eq!(app_entries[0].0, 5);
    assert!(
        app_entries[0].1.is_some(),
        "persisted application entry message_id must be non-NULL and canonical"
    );

    let msg_sends_count: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM chat.message_sends WHERE conversation_id = $1")
            .bind(fixture.convo_id)
            .fetch_one(&pool)
            .await
            .expect("count message sends");
    assert_eq!(
        msg_sends_count, 0,
        "historical bootstrap must create zero chat.message_sends rows"
    );

    // 5. Verify the persisted semantic graph hydrates to the final transcript head.
    let mut tx = pool.begin().await.expect("begin tx for hydration check");
    let graph =
        catbird_server::chat_protocol::repository::remote_prefix::test_support::test_hydrated_graph_summary(
            &mut tx,
            fixture.convo_id,
            corpus_evaluation_instant(5_000),
        )
        .await
        .expect("applied mailbox must hydrate");
    assert_eq!(graph.next_entry_seq, 6);
    assert_eq!(graph.generation, 0);
    assert_eq!(graph.state_version, 3);
    assert_eq!(graph.epoch, 1);
    tx.rollback().await.unwrap();

    // 6. Check healthy federation_sync_state
    let sync_status: String = sqlx::query_scalar(
        "SELECT status FROM federation_sync_state WHERE convo_id = $1 AND sequencer_ds_did = $2",
    )
    .bind(fixture.convo_id.to_string())
    .bind(sequencer_did)
    .fetch_one(&pool)
    .await
    .expect("fetch sync status");
    assert_eq!(sync_status, "healthy");
}

// 32. Mid-transaction rollback on event 2 failure (proves sequence 1 write was rolled back)
#[tokio::test]
async fn bootstrap_rollback_on_corrupt_event_2_leaves_zero_database_rows() {
    let Some((pool, _db_guard)) = setup_test_db().await else {
        return;
    };

    let convo_id = Uuid::new_v4();
    let sequencer_did = "did:web:sequencer.catbird.blue";
    let actor_created_at = corpus_evaluation_instant(0) - chrono::Duration::hours(1);
    seed_approved_peer(&pool, sequencer_did).await;
    seed_protocol_instance(&pool).await;

    let fixture = build_full_5_event_prefix_fixture(convo_id, sequencer_did, actor_created_at);
    seed_full_test_authority(&pool, &fixture, actor_created_at).await;

    let mut events = fixture.events.clone();
    corrupt_accepted_payload(&mut events[1]);
    let admission = test_admission_from_events(&fixture, events);
    let before_snapshot = snapshot_db_content(&pool).await;

    let mut tx = pool.begin().await.expect("begin test tx");
    let err = test_apply_remote_clean_prefix(&mut tx, admission)
        .await
        .expect_err("corrupt event 2 must fail after applying event 1");
    assert_eq!(err, RemotePrefixBootstrapError::Authority);
    tx.rollback().await.unwrap();

    assert_eq!(
        before_snapshot,
        snapshot_db_content(&pool).await,
        "event 2 failure must roll back event 1 exactly"
    );
}

// 33. Mid-transaction rollback on application tail failure (proves control steps 1..4 were rolled back)
#[tokio::test]
async fn bootstrap_rollback_on_corrupt_application_tail_leaves_zero_database_rows() {
    let Some((pool, _db_guard)) = setup_test_db().await else {
        return;
    };

    let convo_id = Uuid::new_v4();
    let sequencer_did = "did:web:sequencer.catbird.blue";
    let actor_created_at = corpus_evaluation_instant(0) - chrono::Duration::hours(1);
    seed_approved_peer(&pool, sequencer_did).await;
    seed_protocol_instance(&pool).await;

    let fixture = build_full_5_event_prefix_fixture(convo_id, sequencer_did, actor_created_at);
    seed_full_test_authority(&pool, &fixture, actor_created_at).await;

    let mut events = fixture.events.clone();
    corrupt_accepted_payload(&mut events[4]);
    let admission = test_admission_from_events(&fixture, events);
    let before_snapshot = snapshot_db_content(&pool).await;

    let mut tx = pool.begin().await.expect("begin test tx");
    let err = test_apply_remote_clean_prefix(&mut tx, admission)
        .await
        .expect_err("corrupt application tail must fail after applying controls 1 through 4");
    assert_eq!(err, RemotePrefixBootstrapError::Authority);
    tx.rollback().await.unwrap();

    assert_eq!(
        before_snapshot,
        snapshot_db_content(&pool).await,
        "application failure must roll back all preceding controls exactly"
    );
}

// 34. Closed grammar rejection tests directly tested in the reducer with full zero-write snapshots
#[tokio::test]
async fn bootstrap_closed_grammar_rejects_invalid_event_sequences() {
    let Some((pool, _db_guard)) = setup_test_db().await else {
        return;
    };

    let convo_id = Uuid::new_v4();
    let sequencer_did = "did:web:sequencer.catbird.blue";
    let actor_created_at = corpus_evaluation_instant(0) - chrono::Duration::hours(1);

    seed_approved_peer(&pool, sequencer_did).await;
    seed_protocol_instance(&pool).await;

    let fixture = build_full_5_event_prefix_fixture(convo_id, sequencer_did, actor_created_at);

    let selector =
        RemotePrefixBootstrapSelector::new(convo_id, sequencer_did.to_string(), 0).unwrap();
    let destination = ValidatedRemoteDestination {
        url: url::Url::parse("https://127.0.0.1:8080").unwrap(),
        host: "127.0.0.1".to_string(),
        addrs: vec!["127.0.0.1:8080".parse().unwrap()],
    };
    let mut routes = BTreeMap::new();
    routes.insert(fixture.actor_did.clone(), None);
    routes.insert(
        fixture.bob_did.clone(),
        Some("did:web:remote-ds.catbird.blue".to_string()),
    );

    // Build a forbidden-kind event (e.g. commitEntry) for the closed grammar wildcard test
    let mut commit_event = fixture.events[1].clone();
    commit_event["entryKind"] = json!("blue.catbird.chat.defs#commitEntry");
    commit_event["messageType"] = json!("blue.catbird.chat.defs#commitEntry");

    let invalid_cases: Vec<(&str, Vec<Value>)> = vec![
        ("starts with policy", vec![fixture.events[1].clone()]),
        ("starts with acceptance", vec![fixture.events[2].clone()]),
        ("starts with fulfillment", vec![fixture.events[3].clone()]),
        ("starts with application", vec![fixture.events[4].clone()]),
        (
            "creation then fulfillment (skips policy/acceptance)",
            vec![fixture.events[0].clone(), fixture.events[3].clone()],
        ),
        (
            "creation then application (skips policy/acceptance/fulfillment)",
            vec![fixture.events[0].clone(), fixture.events[4].clone()],
        ),
        (
            "creation then policy then fulfillment (skips acceptance)",
            vec![
                fixture.events[0].clone(),
                fixture.events[1].clone(),
                fixture.events[3].clone(),
            ],
        ),
        (
            "creation then policy then acceptance then policy (policy after acceptance in ExpectFulfillment)",
            vec![
                fixture.events[0].clone(),
                fixture.events[1].clone(),
                fixture.events[2].clone(),
                fixture.events[1].clone(),
            ],
        ),
        (
            "creation then policy then acceptance then acceptance (acceptance after acceptance in ExpectFulfillment)",
            vec![
                fixture.events[0].clone(),
                fixture.events[1].clone(),
                fixture.events[2].clone(),
                fixture.events[2].clone(),
            ],
        ),
        (
            "creation then policy then acceptance then application (skips fulfillment in ExpectFulfillment)",
            vec![
                fixture.events[0].clone(),
                fixture.events[1].clone(),
                fixture.events[2].clone(),
                fixture.events[4].clone(),
            ],
        ),
        (
            "creation then policy then acceptance then fulfillment then policy (policy in ApplicationTail)",
            vec![
                fixture.events[0].clone(),
                fixture.events[1].clone(),
                fixture.events[2].clone(),
                fixture.events[3].clone(),
                fixture.events[1].clone(),
            ],
        ),
        (
            "creation then policy then acceptance then fulfillment then acceptance (acceptance in ApplicationTail)",
            vec![
                fixture.events[0].clone(),
                fixture.events[1].clone(),
                fixture.events[2].clone(),
                fixture.events[3].clone(),
                fixture.events[2].clone(),
            ],
        ),
        (
            "creation then policy then acceptance then fulfillment then fulfillment (fulfillment in ApplicationTail)",
            vec![
                fixture.events[0].clone(),
                fixture.events[1].clone(),
                fixture.events[2].clone(),
                fixture.events[3].clone(),
                fixture.events[3].clone(),
            ],
        ),
        (
            "creation then forbidden commitEntry (reaches _ => Err in PolicyOrAcceptance)",
            vec![fixture.events[0].clone(), commit_event],
        ),
    ];

    for (name, mut invalid_events) in invalid_cases {
        // Renumber events strictly to 1..=n with distinct entry IDs so sequence contiguity succeeds and BootstrapPhase transition is the sole rejection reason
        for (idx, event) in invalid_events.iter_mut().enumerate() {
            let seq = (idx + 1) as i64;
            event["seq"] = json!(seq);
            let unique_entry_id = Uuid::new_v4();
            event["entryId"] = json!(unique_entry_id);
            event["msgId"] = json!(unique_entry_id);
        }
        let invalid_events: Vec<StrictCleanRemoteEvent> = invalid_events
            .into_iter()
            .map(|event| {
                StrictCleanRemoteEvent::try_from(
                    serde_json::from_value::<crate::federation::reconciliation::RemoteEvent>(event)
                        .unwrap(),
                )
                .unwrap()
            })
            .collect();
        let before_snapshot = snapshot_db_content(&pool).await;

        let digest_anchor = RemoteDigestAnchor::new_for_test(
            convo_id,
            sequencer_did.to_string(),
            0,
            invalid_events.len() as i64,
            invalid_events.len() as i64,
            0,
            [0x11u8; 32],
        );

        let admission = VerifiedRemotePrefixAdmission::new_for_test(
            selector.clone(),
            destination.clone(),
            digest_anchor,
            invalid_events,
            routes.clone(),
            1024,
        );

        let mut tx = pool.begin().await.expect("begin test tx");
        let err = test_apply_remote_clean_prefix(&mut tx, admission)
            .await
            .expect_err(&format!("case '{name}' must fail closed in reducer"));
        assert_eq!(
            err,
            RemotePrefixBootstrapError::InvalidEvent,
            "case '{name}' must fail with InvalidEvent due to closed grammar phase rejection"
        );
        tx.rollback().await.unwrap();

        let after_snapshot = snapshot_db_content(&pool).await;
        assert_eq!(
            before_snapshot, after_snapshot,
            "case '{name}' must leave database in exact zero-write state"
        );
    }
}

// 35. Concurrency: Two absent bootstraps serialize under the advisory lock
#[tokio::test]
async fn bootstrap_absent_bootstraps_serialize_cleanly() {
    let Some((pool, _db_guard)) = setup_test_db().await else {
        return;
    };

    let convo_id = Uuid::new_v4();
    let sequencer_did = "did:web:sequencer.catbird.blue";
    let actor_created_at = corpus_evaluation_instant(0) - chrono::Duration::hours(1);

    seed_approved_peer(&pool, sequencer_did).await;
    seed_protocol_instance(&pool).await;

    let fixture = build_full_5_event_prefix_fixture(convo_id, sequencer_did, actor_created_at);

    seed_full_test_authority(&pool, &fixture, actor_created_at).await;

    let mock_state = MockSequencerState {
        capabilities: vec![
            CAPABILITY_RECONCILIATION_V1.to_string(),
            CAPABILITY_CANONICAL_PREFIX_BOOTSTRAP_V1.to_string(),
        ],
        opening_digest: Some(fixture.opening_digest.clone()),
        closing_digest: Some(fixture.closing_digest.clone()),
        events_pages: vec![json!({
            "convoId": fixture.convo_id.to_string(),
            "fromSeqExclusive": 0,
            "toSeqInclusive": 5,
            "events": fixture.events.clone(),
        })],
        ..Default::default()
    };

    let (destination, _base_url) = spawn_mock_sequencer(mock_state).await;
    let resolver = create_test_resolver(pool.clone(), destination, sequencer_did);
    let outbound1 = OutboundClient::new(2, 2);
    let outbound2 = OutboundClient::new(2, 2);

    let auth_client = ServiceAuthClient::from_shared_secret(
        "did:web:destination.catbird.blue".to_string(),
        b"test-secret",
    );
    let auth_sign = Arc::new(move |target: &str, method: &str| {
        auth_client
            .sign_request(target, method)
            .map_err(|e| e.to_string())
    });

    let selector =
        RemotePrefixBootstrapSelector::new(fixture.convo_id, fixture.sequencer_did.clone(), 0)
            .unwrap();

    let pool1 = pool.clone();
    let resolver1 = resolver.clone();
    let outbound1 = outbound1;
    let auth_sign1 = auth_sign.clone();
    let selector1 = selector.clone();

    let pool2 = pool.clone();
    let resolver2 = resolver.clone();
    let outbound2 = outbound2;
    let auth_sign2 = auth_sign.clone();
    let selector2 = selector.clone();

    let h1 = tokio::spawn(async move {
        bootstrap_remote_mailbox_from_selector(
            &pool1,
            &resolver1,
            &outbound1,
            auth_sign1.as_ref(),
            selector1,
        )
        .await
    });

    let h2 = tokio::spawn(async move {
        bootstrap_remote_mailbox_from_selector(
            &pool2,
            &resolver2,
            &outbound2,
            auth_sign2.as_ref(),
            selector2,
        )
        .await
    });

    let (r1, r2) = tokio::join!(h1, h2);
    let out1 = r1.unwrap().expect("call 1");
    let out2 = r2.unwrap().expect("call 2");

    let applied_count = match (&out1, &out2) {
        (
            RemotePrefixApplyOutcome::Applied { .. },
            RemotePrefixApplyOutcome::ExactReplay { .. },
        ) => 1,
        (
            RemotePrefixApplyOutcome::ExactReplay { .. },
            RemotePrefixApplyOutcome::Applied { .. },
        ) => 1,
        _ => 0,
    };
    assert_eq!(
        applied_count, 1,
        "concurrent bootstrap must yield exactly one Applied and one ExactReplay: out1={out1:?}, out2={out2:?}"
    );

    let cutoff: Option<i64> = sqlx::query_scalar(
        "SELECT historical_bootstrap_last_seq FROM chat.conversations WHERE conversation_id = $1",
    )
    .bind(fixture.convo_id)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(cutoff, Some(5), "persisted cutoff must equal 5");

    let sends_count: i64 =
        sqlx::query_scalar("SELECT count(*) FROM chat.message_sends WHERE conversation_id = $1")
            .bind(fixture.convo_id)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(sends_count, 0, "must create zero message_sends rows");
}

// 36. TOCTOU mutation zero-write validation for peer policy, device key, key package, and device revocation
#[tokio::test]
async fn bootstrap_toctou_mutation_rolls_back_with_zero_writes() {
    for case in [
        "peer policy",
        "local entitlement",
        "device key",
        "key package",
    ] {
        let Some((pool, _db_guard, fixture, admission)) = prepare_bootstrap_toctou_case().await
        else {
            return;
        };

        let expected = match case {
            "peer policy" => {
                sqlx::query("UPDATE federation_peers SET status = 'suspend' WHERE ds_did = $1")
                    .bind(&fixture.sequencer_did)
                    .execute(&pool)
                    .await
                    .unwrap();
                RemotePrefixBootstrapError::PeerDenied
            }
            "local entitlement" => {
                sqlx::query(
                    r#"
                    UPDATE chat.devices
                       SET status = 'revoked', revoked_at = NOW()
                     WHERE (user_did = $1 AND device_id = $2)
                        OR (user_did = $3 AND device_id = $4)
                    "#,
                )
                .bind(&fixture.actor_did)
                .bind(fixture.actor_device)
                .bind(&fixture.bob_did)
                .bind(fixture.bob_device)
                .execute(&pool)
                .await
                .unwrap();
                RemotePrefixBootstrapError::NoLocalParticipant
            }
            "device key" => {
                sqlx::query(
                    "UPDATE chat.device_keys SET revoked_at = NOW() WHERE user_did = $1 AND device_id = $2 AND key_id = $3",
                )
                .bind(&fixture.actor_did)
                .bind(fixture.actor_device)
                .bind(&fixture.actor_key_id)
                .execute(&pool)
                .await
                .unwrap();
                RemotePrefixBootstrapError::Authority
            }
            "key package" => {
                sqlx::query(
                    "UPDATE chat.key_packages SET status = 'expired', terminal_at = not_after WHERE key_package_ref = $1",
                )
                .bind(fixture.key_package_ref.as_slice())
                .execute(&pool)
                .await
                .unwrap();
                RemotePrefixBootstrapError::Authority
            }
            _ => unreachable!(),
        };

        let after_mutation = snapshot_db_content(&pool).await;
        let mut tx = pool.begin().await.unwrap();
        let error = test_apply_remote_clean_prefix(&mut tx, admission)
            .await
            .expect_err(case);
        assert_eq!(error, expected, "{case}");
        tx.rollback().await.unwrap();
        assert_eq!(
            snapshot_db_content(&pool).await,
            after_mutation,
            "{case} TOCTOU rejection must write nothing"
        );
    }
}

// 37. Hard-coded fixed vectors for all 3 deterministic ID labels
#[test]
fn deterministic_local_ids_satisfy_hard_coded_fixed_vectors() {
    let cid = Uuid::parse_str("00112233-4455-4677-8899-aabbccddeeff").unwrap();
    let entry_id = Uuid::parse_str("11223344-5566-4788-99aa-bbccddeeff00").unwrap();

    let p_id =
        derive_bootstrap_local_id_for_test(cid, entry_id, "participant-period", b"did:plc:alice");
    assert_eq!(
        p_id.to_string(),
        "a55f3c00-bdac-4839-89a1-5ba29c65cc6a",
        "participant-period fixed vector mismatch"
    );
    assert_eq!(p_id.get_version_num(), 4);
    assert_eq!(p_id.get_variant(), uuid::Variant::RFC4122);

    let dev_id = Uuid::parse_str("22334455-6677-4899-aabb-ccddeeff0011").unwrap();
    let leaf_key = [b"did:plc:alice\0".as_ref(), dev_id.as_bytes()].concat();
    let l_id = derive_bootstrap_local_id_for_test(cid, entry_id, "leaf-period", &leaf_key);
    assert_eq!(
        l_id.to_string(),
        "9ea73838-96c7-48a4-beb8-a790869aea28",
        "leaf-period fixed vector mismatch"
    );
    assert_eq!(l_id.get_version_num(), 4);
    assert_eq!(l_id.get_variant(), uuid::Variant::RFC4122);

    let m_id = derive_bootstrap_local_id_for_test(cid, entry_id, "metadata-snapshot", b"");
    assert_eq!(
        m_id.to_string(),
        "14bc0328-1811-49af-b3d7-f806ca9421cb",
        "metadata-snapshot fixed vector mismatch"
    );
    assert_eq!(m_id.get_version_num(), 4);
    assert_eq!(m_id.get_variant(), uuid::Variant::RFC4122);
}

// 38. Exact replay full zero-write test
#[tokio::test]
async fn bootstrap_exact_replay_produces_zero_database_writes() {
    let Some((pool, _db_guard)) = setup_test_db().await else {
        return;
    };

    let convo_id = Uuid::new_v4();
    let sequencer_did = "did:web:sequencer.catbird.blue";
    let actor_created_at = corpus_evaluation_instant(0) - chrono::Duration::hours(1);

    seed_approved_peer(&pool, sequencer_did).await;
    seed_protocol_instance(&pool).await;

    let fixture = build_full_5_event_prefix_fixture(convo_id, sequencer_did, actor_created_at);

    seed_full_test_authority(&pool, &fixture, actor_created_at).await;

    let mock_state = MockSequencerState {
        capabilities: vec![
            CAPABILITY_RECONCILIATION_V1.to_string(),
            CAPABILITY_CANONICAL_PREFIX_BOOTSTRAP_V1.to_string(),
        ],
        opening_digest: Some(fixture.opening_digest.clone()),
        closing_digest: Some(fixture.closing_digest.clone()),
        events_pages: vec![json!({
            "convoId": fixture.convo_id.to_string(),
            "fromSeqExclusive": 0,
            "toSeqInclusive": 5,
            "events": fixture.events.clone(),
        })],
        ..Default::default()
    };

    let (destination, _base_url) = spawn_mock_sequencer(mock_state).await;
    let resolver = create_test_resolver(pool.clone(), destination, sequencer_did);
    let outbound = OutboundClient::new(2, 2);
    let auth_client = ServiceAuthClient::from_shared_secret(
        "did:web:destination.catbird.blue".to_string(),
        b"test-secret",
    );
    let auth_sign = move |target: &str, method: &str| {
        auth_client
            .sign_request(target, method)
            .map_err(|e| e.to_string())
    };

    let selector =
        RemotePrefixBootstrapSelector::new(fixture.convo_id, fixture.sequencer_did.clone(), 0)
            .unwrap();

    let outcome1 = bootstrap_remote_mailbox_from_selector(
        &pool,
        &resolver,
        &outbound,
        &auth_sign,
        selector.clone(),
    )
    .await
    .expect("first apply succeeds");
    assert!(matches!(outcome1, RemotePrefixApplyOutcome::Applied { .. }));

    let snapshot_after_apply = snapshot_db_content(&pool).await;

    // Apply the sealed identical admission directly to prove reducer replay semantics.
    let admission =
        fetch_remote_prefix_admission(&pool, &resolver, &outbound, &auth_sign, selector.clone())
            .await
            .expect("second admission succeeds");
    let mut replay_tx = pool.begin().await.expect("begin replay transaction");
    let outcome2 = test_apply_remote_clean_prefix(&mut replay_tx, admission)
        .await
        .expect("second apply succeeds");
    replay_tx.commit().await.expect("commit exact replay");

    let RemotePrefixApplyOutcome::ExactReplay {
        conversation_id,
        sequencer_term,
        last_seq,
        digest_sha256,
    } = outcome2
    else {
        panic!("expected RemotePrefixApplyOutcome::ExactReplay, got {outcome2:?}");
    };
    assert_eq!(conversation_id, fixture.convo_id);
    assert_eq!(sequencer_term, 0);
    assert_eq!(last_seq, 5);
    assert_eq!(digest_sha256, fixture.digest_sha256);

    let snapshot_after_replay = snapshot_db_content(&pool).await;
    assert_eq!(
        snapshot_after_apply, snapshot_after_replay,
        "exact replay must make exact zero writes across all database tables"
    );

    // Boundary regression: apply an OrdinaryReconciliation application at cutoff + 1 (seq 6)
    let alice_signing_key = SigningKey::from_bytes(&fixture.creation_entry.signing_seed);
    let ev6 = genuine_application_event(
        fixture.convo_id,
        6,
        &fixture.actor_did,
        fixture.actor_device,
        &fixture.actor_key_id,
        &alice_signing_key,
        &fixture.actor_public_key,
        &fixture.committed_coordinate,
        corpus_evaluation_instant(6_000),
    );

    let mut hasher6 = CleanConvoDigestHasher::new();
    for ev in &fixture.events {
        let strict = StrictCleanRemoteEvent::try_from(
            serde_json::from_value::<crate::federation::reconciliation::RemoteEvent>(ev.clone())
                .unwrap(),
        )
        .unwrap();
        hasher6.update_event(
            strict.seq(),
            strict.generation(),
            strict.entry_id(),
            ev["entryKind"].as_str().unwrap(),
            strict.accepted_payload_bytes(),
            strict.signed_request(),
            strict.outer_fingerprint(),
            strict.received_at(),
        );
    }
    let strict6 = StrictCleanRemoteEvent::try_from(
        serde_json::from_value::<crate::federation::reconciliation::RemoteEvent>(ev6.clone())
            .unwrap(),
    )
    .unwrap();
    hasher6.update_event(
        strict6.seq(),
        strict6.generation(),
        strict6.entry_id(),
        ev6["entryKind"].as_str().unwrap(),
        strict6.accepted_payload_bytes(),
        strict6.signed_request(),
        strict6.outer_fingerprint(),
        strict6.received_at(),
    );
    let digest_sha256_6: [u8; 32] = hex::decode(hasher6.finalize()).unwrap().try_into().unwrap();

    let digest6 = json!({
        "convoId": fixture.convo_id.to_string(),
        "sequencerDsDid": sequencer_did,
        "sequencerTerm": 0,
        "epoch": 0,
        "lastSeq": 6,
        "eventCount": 6,
        "digestSha256": hex::encode(digest_sha256_6),
        "generatedAt": corpus_evaluation_instant(6_000).to_rfc3339_opts(SecondsFormat::Millis, true),
    });

    let mut events6 = fixture.events.clone();
    events6.push(ev6.clone());
    let mock_state_suffix = MockSequencerState {
        capabilities: vec![CAPABILITY_RECONCILIATION_V1.to_string()],
        opening_digest: Some(digest6.clone()),
        closing_digest: Some(digest6),
        events_pages: vec![json!({
            "convoId": fixture.convo_id.to_string(),
            "fromSeqExclusive": 0,
            "toSeqInclusive": 6,
            "events": events6,
        })],
        ..Default::default()
    };

    let (dest_recon, _) = spawn_mock_sequencer(mock_state_suffix).await;
    let resolver_recon = create_test_resolver(pool.clone(), dest_recon, sequencer_did);
    let recon_res = catbird_server::federation::reconciliation::reconcile_conversation(
        &pool,
        &resolver_recon,
        &outbound,
        &auth_sign,
        &fixture.convo_id.to_string(),
        sequencer_did,
    )
    .await;
    assert!(
        recon_res.is_ok(),
        "reconciliation at cutoff+1 must succeed: {recon_res:?}"
    );

    let sends_after_recon: Vec<(Uuid, String)> = sqlx::query_as(
        "SELECT message_id, status FROM chat.message_sends WHERE conversation_id = $1",
    )
    .bind(fixture.convo_id)
    .fetch_all(&pool)
    .await
    .expect("fetch message_sends after reconciliation");
    assert_eq!(
        sends_after_recon.len(),
        1,
        "ordinary reconciliation at cutoff+1 must create exactly one chat.message_sends row"
    );
    assert_eq!(sends_after_recon[0].1, "accepted");
}

// 39. Conflict and quarantine classification matrix (all branches + local ahead + shorter prefix + sticky evidence preservation)
#[tokio::test]
async fn bootstrap_conflict_and_quarantine_classification_matrix() {
    let Some((pool, _db_guard)) = setup_test_db().await else {
        return;
    };

    let sequencer_did = "did:web:sequencer.catbird.blue";
    let actor_created_at = corpus_evaluation_instant(0) - chrono::Duration::hours(1);
    seed_approved_peer(&pool, sequencer_did).await;
    seed_protocol_instance(&pool).await;

    for (name, is_remote, stored_sequencer, stored_term) in [
        ("local", false, None, 0_i64),
        (
            "different sequencer",
            true,
            Some("did:web:other-sequencer.catbird.blue"),
            0,
        ),
        ("different term", true, Some(sequencer_did), 1),
    ] {
        let fixture =
            build_full_5_event_prefix_fixture(Uuid::new_v4(), sequencer_did, actor_created_at);
        let admission = test_admission_from_events(&fixture, fixture.events.clone());
        let mut tx = pool.begin().await.unwrap();
        sqlx::query(
            r#"
            INSERT INTO chat.conversations (
                conversation_id, kind, lifecycle, current_generation,
                current_state_version, next_entry_seq, created_at,
                is_remote, sequencer_ds, sequencer_term
            )
            VALUES ($1, 'group', 'active', 0, 0, 1, $2, $3, $4, $5)
            "#,
        )
        .bind(fixture.convo_id)
        .bind(actor_created_at)
        .bind(is_remote)
        .bind(stored_sequencer)
        .bind(stored_term)
        .execute(&mut *tx)
        .await
        .unwrap();

        let error = test_apply_remote_clean_prefix(&mut tx, admission)
            .await
            .expect_err(name);
        assert_eq!(error, RemotePrefixBootstrapError::Conflict, "{name}");
        let quarantine_count: i64 =
            sqlx::query_scalar("SELECT count(*) FROM federation_sync_state WHERE convo_id = $1")
                .bind(fixture.convo_id.to_string())
                .fetch_one(&mut *tx)
                .await
                .unwrap();
        assert_eq!(quarantine_count, 0, "{name} must not quarantine");
        tx.rollback().await.unwrap();
    }

    // A valid local four-entry prefix is shorter than the offered five-entry prefix.
    let shorter_fixture =
        build_full_5_event_prefix_fixture(Uuid::new_v4(), sequencer_did, actor_created_at);
    seed_full_test_authority(&pool, &shorter_fixture, actor_created_at).await;
    let mut tx = pool.begin().await.unwrap();
    let outcome = test_apply_remote_clean_prefix(
        &mut tx,
        test_admission_from_events(&shorter_fixture, shorter_fixture.events[..4].to_vec()),
    )
    .await
    .unwrap();
    assert!(matches!(outcome, RemotePrefixApplyOutcome::Applied { .. }));
    tx.commit().await.unwrap();

    let before_shorter_conflict = snapshot_db_content(&pool).await;
    let mut tx = pool.begin().await.unwrap();
    let error = test_apply_remote_clean_prefix(
        &mut tx,
        test_admission_from_events(&shorter_fixture, shorter_fixture.events.clone()),
    )
    .await
    .expect_err("existing shorter prefix must conflict");
    assert_eq!(error, RemotePrefixBootstrapError::Conflict);
    tx.rollback().await.unwrap();
    assert_eq!(
        before_shorter_conflict,
        snapshot_db_content(&pool).await,
        "shorter-prefix conflict must write nothing"
    );

    // Same-length overlap mismatch quarantines at the first differing sequence.
    let mismatch_fixture =
        build_full_5_event_prefix_fixture(Uuid::new_v4(), sequencer_did, actor_created_at);
    seed_full_test_authority(&pool, &mismatch_fixture, actor_created_at).await;
    let mut tx = pool.begin().await.unwrap();
    test_apply_remote_clean_prefix(
        &mut tx,
        test_admission_from_events(&mismatch_fixture, mismatch_fixture.events.clone()),
    )
    .await
    .unwrap();
    tx.commit().await.unwrap();

    let mut mismatch_events = mismatch_fixture.events.clone();
    mismatch_events[2]["entryId"] = json!(Uuid::new_v4());
    let mut tx = pool.begin().await.unwrap();
    let mismatch_outcome = test_apply_remote_clean_prefix(
        &mut tx,
        test_admission_from_events(&mismatch_fixture, mismatch_events.clone()),
    )
    .await
    .unwrap();
    assert_eq!(
        mismatch_outcome,
        RemotePrefixApplyOutcome::Quarantined {
            conversation_id: mismatch_fixture.convo_id,
            first_mismatch_seq: 3,
            reason: QuarantineReason::PrefixMismatch,
        }
    );
    tx.commit().await.unwrap();

    let mismatch_quarantined_at: DateTime<Utc> = sqlx::query_scalar(
        "SELECT quarantined_at FROM federation_sync_state WHERE convo_id = $1 AND sequencer_ds_did = $2",
    )
    .bind(mismatch_fixture.convo_id.to_string())
    .bind(sequencer_did)
    .fetch_one(&pool)
    .await
    .unwrap();
    let mut tx = pool.begin().await.unwrap();
    let sticky_mismatch = test_apply_remote_clean_prefix(
        &mut tx,
        test_admission_from_events(&mismatch_fixture, mismatch_events),
    )
    .await
    .unwrap();
    tx.commit().await.unwrap();
    assert_eq!(sticky_mismatch, mismatch_outcome);
    let mismatch_quarantined_at_after: DateTime<Utc> = sqlx::query_scalar(
        "SELECT quarantined_at FROM federation_sync_state WHERE convo_id = $1 AND sequencer_ds_did = $2",
    )
    .bind(mismatch_fixture.convo_id.to_string())
    .bind(sequencer_did)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(mismatch_quarantined_at_after, mismatch_quarantined_at);

    // A shorter offered prefix against a longer local prefix quarantines as local-ahead.
    let ahead_fixture =
        build_full_5_event_prefix_fixture(Uuid::new_v4(), sequencer_did, actor_created_at);
    seed_full_test_authority(&pool, &ahead_fixture, actor_created_at).await;
    let mut tx = pool.begin().await.unwrap();
    test_apply_remote_clean_prefix(
        &mut tx,
        test_admission_from_events(&ahead_fixture, ahead_fixture.events.clone()),
    )
    .await
    .unwrap();
    tx.commit().await.unwrap();

    let ahead_events = ahead_fixture.events[..4].to_vec();
    let mut tx = pool.begin().await.unwrap();
    let ahead_outcome = test_apply_remote_clean_prefix(
        &mut tx,
        test_admission_from_events(&ahead_fixture, ahead_events.clone()),
    )
    .await
    .unwrap();
    assert_eq!(
        ahead_outcome,
        RemotePrefixApplyOutcome::Quarantined {
            conversation_id: ahead_fixture.convo_id,
            first_mismatch_seq: 5,
            reason: QuarantineReason::LocalAhead,
        }
    );
    tx.commit().await.unwrap();

    let (status, reason, mismatch_seq, quarantined_at): (
        String,
        Option<String>,
        Option<i64>,
        Option<DateTime<Utc>>,
    ) = sqlx::query_as(
        "SELECT status, quarantine_reason, first_mismatch_seq, quarantined_at FROM federation_sync_state WHERE convo_id = $1 AND sequencer_ds_did = $2",
    )
    .bind(ahead_fixture.convo_id.to_string())
    .bind(sequencer_did)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(status, "quarantined");
    assert_eq!(reason.as_deref(), Some("local_ahead"));
    assert_eq!(mismatch_seq, Some(5));

    let mut tx = pool.begin().await.unwrap();
    let sticky_ahead = test_apply_remote_clean_prefix(
        &mut tx,
        test_admission_from_events(&ahead_fixture, ahead_events),
    )
    .await
    .unwrap();
    tx.commit().await.unwrap();
    assert_eq!(sticky_ahead, ahead_outcome);
    let quarantined_at_after: Option<DateTime<Utc>> = sqlx::query_scalar(
        "SELECT quarantined_at FROM federation_sync_state WHERE convo_id = $1 AND sequencer_ds_did = $2",
    )
    .bind(ahead_fixture.convo_id.to_string())
    .bind(sequencer_did)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(quarantined_at_after, quarantined_at);
}

// ============================================================================
// Task 7: Prove the bootstrap authority against hostile peers
// ============================================================================

// 40. Full hostile network admission matrix with full-row zero-write snapshots
#[tokio::test]
async fn test_hostile_network_admission_matrix() {
    let Some((pool, _db_guard)) = setup_test_db().await else {
        return;
    };

    let sequencer_did = "did:web:sequencer.catbird.blue";
    let actor_created_at = corpus_evaluation_instant(0) - chrono::Duration::hours(1);
    seed_approved_peer(&pool, sequencer_did).await;
    seed_protocol_instance(&pool).await;

    let fixture =
        build_full_5_event_prefix_fixture(Uuid::new_v4(), sequencer_did, actor_created_at);
    seed_full_test_authority(&pool, &fixture, actor_created_at).await;

    let base_mock_state = || MockSequencerState {
        capabilities: vec![
            CAPABILITY_RECONCILIATION_V1.to_string(),
            CAPABILITY_CANONICAL_PREFIX_BOOTSTRAP_V1.to_string(),
        ],
        opening_digest: Some(fixture.opening_digest.clone()),
        closing_digest: Some(fixture.closing_digest.clone()),
        events_pages: vec![json!({
            "convoId": fixture.convo_id.to_string(),
            "fromSeqExclusive": 0,
            "toSeqInclusive": 5,
            "events": fixture.events.clone(),
        })],
        ..Default::default()
    };

    // 1. Blocked peer in federation_peers
    {
        let blocked_did = "did:web:blocked-peer.catbird.blue";
        sqlx::query("INSERT INTO federation_peers (ds_did, status, updated_at) VALUES ($1, 'block', NOW()) ON CONFLICT (ds_did) DO UPDATE SET status = 'block'")
            .bind(blocked_did)
            .execute(&pool)
            .await
            .unwrap();
        let selector =
            RemotePrefixBootstrapSelector::new(fixture.convo_id, blocked_did.to_string(), 0)
                .unwrap();
        let destination = ValidatedRemoteDestination {
            url: url::Url::parse("https://127.0.0.1:8080").unwrap(),
            host: "127.0.0.1".to_string(),
            addrs: vec!["127.0.0.1:8080".parse().unwrap()],
        };
        let resolver = create_test_resolver(pool.clone(), destination, blocked_did);
        let outbound = OutboundClient::new(2, 2);
        let auth_client = ServiceAuthClient::from_shared_secret(
            "did:web:destination.catbird.blue".to_string(),
            b"test-secret",
        );
        let auth_sign = move |target: &str, method: &str| {
            auth_client
                .sign_request(target, method)
                .map_err(|e| e.to_string())
        };

        let before_snapshot = snapshot_db_content(&pool).await;
        let err = bootstrap_remote_mailbox_from_selector(
            &pool, &resolver, &outbound, &auth_sign, selector,
        )
        .await
        .expect_err("blocked peer must fail");
        assert_eq!(err, RemotePrefixBootstrapError::PeerDenied);
        assert_eq!(
            before_snapshot,
            snapshot_db_content(&pool).await,
            "blocked peer must write nothing"
        );
    }

    // 2. Suspended peer in federation_peers
    {
        let suspended_did = "did:web:suspended-peer.catbird.blue";
        sqlx::query("INSERT INTO federation_peers (ds_did, status, updated_at) VALUES ($1, 'suspend', NOW()) ON CONFLICT (ds_did) DO UPDATE SET status = 'suspend'")
            .bind(suspended_did)
            .execute(&pool)
            .await
            .unwrap();
        let selector =
            RemotePrefixBootstrapSelector::new(fixture.convo_id, suspended_did.to_string(), 0)
                .unwrap();
        let destination = ValidatedRemoteDestination {
            url: url::Url::parse("https://127.0.0.1:8080").unwrap(),
            host: "127.0.0.1".to_string(),
            addrs: vec!["127.0.0.1:8080".parse().unwrap()],
        };
        let resolver = create_test_resolver(pool.clone(), destination, suspended_did);
        let outbound = OutboundClient::new(2, 2);
        let auth_client = ServiceAuthClient::from_shared_secret(
            "did:web:destination.catbird.blue".to_string(),
            b"test-secret",
        );
        let auth_sign = move |target: &str, method: &str| {
            auth_client
                .sign_request(target, method)
                .map_err(|e| e.to_string())
        };

        let before_snapshot = snapshot_db_content(&pool).await;
        let err = bootstrap_remote_mailbox_from_selector(
            &pool, &resolver, &outbound, &auth_sign, selector,
        )
        .await
        .expect_err("suspended peer must fail");
        assert_eq!(err, RemotePrefixBootstrapError::PeerDenied);
        assert_eq!(
            before_snapshot,
            snapshot_db_content(&pool).await,
            "suspended peer must write nothing"
        );
    }

    // 3. Unapproved peer (not present in federation_peers)
    {
        let unapproved_did = "did:web:unapproved-peer.catbird.blue";
        let selector =
            RemotePrefixBootstrapSelector::new(fixture.convo_id, unapproved_did.to_string(), 0)
                .unwrap();
        let destination = ValidatedRemoteDestination {
            url: url::Url::parse("https://127.0.0.1:8080").unwrap(),
            host: "127.0.0.1".to_string(),
            addrs: vec!["127.0.0.1:8080".parse().unwrap()],
        };
        let resolver = create_test_resolver(pool.clone(), destination, unapproved_did);
        let outbound = OutboundClient::new(2, 2);
        let auth_client = ServiceAuthClient::from_shared_secret(
            "did:web:destination.catbird.blue".to_string(),
            b"test-secret",
        );
        let auth_sign = move |target: &str, method: &str| {
            auth_client
                .sign_request(target, method)
                .map_err(|e| e.to_string())
        };

        let before_snapshot = snapshot_db_content(&pool).await;
        let err = bootstrap_remote_mailbox_from_selector(
            &pool, &resolver, &outbound, &auth_sign, selector,
        )
        .await
        .expect_err("unapproved peer must fail");
        assert_eq!(err, RemotePrefixBootstrapError::PeerDenied);
        assert_eq!(
            before_snapshot,
            snapshot_db_content(&pool).await,
            "unapproved peer must write nothing"
        );
    }

    // 4. Missing bootstrap capability
    {
        let mut state = base_mock_state();
        state.capabilities = vec![CAPABILITY_RECONCILIATION_V1.to_string()]; // lacks CAPABILITY_CANONICAL_PREFIX_BOOTSTRAP_V1
        let (destination, _base_url) = spawn_mock_sequencer(state).await;
        let resolver = create_test_resolver(pool.clone(), destination, sequencer_did);
        let outbound = OutboundClient::new(2, 2);
        let auth_client = ServiceAuthClient::from_shared_secret(
            "did:web:destination.catbird.blue".to_string(),
            b"test-secret",
        );
        let auth_sign = move |target: &str, method: &str| {
            auth_client
                .sign_request(target, method)
                .map_err(|e| e.to_string())
        };
        let selector =
            RemotePrefixBootstrapSelector::new(fixture.convo_id, fixture.sequencer_did.clone(), 0)
                .unwrap();

        let before_snapshot = snapshot_db_content(&pool).await;
        let err = bootstrap_remote_mailbox_from_selector(
            &pool, &resolver, &outbound, &auth_sign, selector,
        )
        .await
        .expect_err("missing capability must fail");
        assert_eq!(err, RemotePrefixBootstrapError::MissingCapability);
        assert_eq!(
            before_snapshot,
            snapshot_db_content(&pool).await,
            "missing capability must write nothing"
        );
    }

    // 5. Auth sign error (service auth failure)
    {
        let (destination, _base_url) = spawn_mock_sequencer(base_mock_state()).await;
        let resolver = create_test_resolver(pool.clone(), destination, sequencer_did);
        let outbound = OutboundClient::new(2, 2);
        let auth_sign =
            |_target: &str, _method: &str| Err("simulated service auth signing error".to_string());
        let selector =
            RemotePrefixBootstrapSelector::new(fixture.convo_id, fixture.sequencer_did.clone(), 0)
                .unwrap();

        let before_snapshot = snapshot_db_content(&pool).await;
        let err = bootstrap_remote_mailbox_from_selector(
            &pool, &resolver, &outbound, &auth_sign, selector,
        )
        .await
        .expect_err("auth signing failure must fail");
        assert_eq!(err, RemotePrefixBootstrapError::ServiceAuth);
        assert_eq!(
            before_snapshot,
            snapshot_db_content(&pool).await,
            "service auth failure must write nothing"
        );
    }

    // 6. Opening digest term mismatch
    {
        let mut state = base_mock_state();
        let mut opening = fixture.opening_digest.clone();
        opening["sequencerTerm"] = json!(1); // mismatch with selector term 0
        state.opening_digest = Some(opening);
        let (destination, _base_url) = spawn_mock_sequencer(state).await;
        let resolver = create_test_resolver(pool.clone(), destination, sequencer_did);
        let outbound = OutboundClient::new(2, 2);
        let auth_client = ServiceAuthClient::from_shared_secret(
            "did:web:destination.catbird.blue".to_string(),
            b"test-secret",
        );
        let auth_sign = move |target: &str, method: &str| {
            auth_client
                .sign_request(target, method)
                .map_err(|e| e.to_string())
        };
        let selector =
            RemotePrefixBootstrapSelector::new(fixture.convo_id, fixture.sequencer_did.clone(), 0)
                .unwrap();

        let before_snapshot = snapshot_db_content(&pool).await;
        let err = bootstrap_remote_mailbox_from_selector(
            &pool, &resolver, &outbound, &auth_sign, selector,
        )
        .await
        .expect_err("opening digest term mismatch must fail");
        assert_eq!(err, RemotePrefixBootstrapError::InvalidDigest);
        assert_eq!(
            before_snapshot,
            snapshot_db_content(&pool).await,
            "opening digest term mismatch must write nothing"
        );
    }

    // 7. Closing digest term change
    {
        let mut state = base_mock_state();
        let mut closing = fixture.closing_digest.clone();
        closing["sequencerTerm"] = json!(1);
        state.closing_digest = Some(closing);
        let (destination, _base_url) = spawn_mock_sequencer(state).await;
        let resolver = create_test_resolver(pool.clone(), destination, sequencer_did);
        let outbound = OutboundClient::new(2, 2);
        let auth_client = ServiceAuthClient::from_shared_secret(
            "did:web:destination.catbird.blue".to_string(),
            b"test-secret",
        );
        let auth_sign = move |target: &str, method: &str| {
            auth_client
                .sign_request(target, method)
                .map_err(|e| e.to_string())
        };
        let selector =
            RemotePrefixBootstrapSelector::new(fixture.convo_id, fixture.sequencer_did.clone(), 0)
                .unwrap();

        let before_snapshot = snapshot_db_content(&pool).await;
        let err = bootstrap_remote_mailbox_from_selector(
            &pool, &resolver, &outbound, &auth_sign, selector,
        )
        .await
        .expect_err("closing digest term change must fail");
        assert_eq!(err, RemotePrefixBootstrapError::MovingSnapshot);
        assert_eq!(
            before_snapshot,
            snapshot_db_content(&pool).await,
            "closing digest term change must write nothing"
        );
    }

    // 8. Closing digest head change
    {
        let mut state = base_mock_state();
        let mut closing = fixture.closing_digest.clone();
        closing["lastSeq"] = json!(6);
        state.closing_digest = Some(closing);
        let (destination, _base_url) = spawn_mock_sequencer(state).await;
        let resolver = create_test_resolver(pool.clone(), destination, sequencer_did);
        let outbound = OutboundClient::new(2, 2);
        let auth_client = ServiceAuthClient::from_shared_secret(
            "did:web:destination.catbird.blue".to_string(),
            b"test-secret",
        );
        let auth_sign = move |target: &str, method: &str| {
            auth_client
                .sign_request(target, method)
                .map_err(|e| e.to_string())
        };
        let selector =
            RemotePrefixBootstrapSelector::new(fixture.convo_id, fixture.sequencer_did.clone(), 0)
                .unwrap();

        let before_snapshot = snapshot_db_content(&pool).await;
        let err = bootstrap_remote_mailbox_from_selector(
            &pool, &resolver, &outbound, &auth_sign, selector,
        )
        .await
        .expect_err("closing digest head change must fail");
        assert_eq!(err, RemotePrefixBootstrapError::MovingSnapshot);
        assert_eq!(
            before_snapshot,
            snapshot_db_content(&pool).await,
            "closing digest head change must write nothing"
        );
    }

    // 9. Closing digest count change
    {
        let mut state = base_mock_state();
        let mut closing = fixture.closing_digest.clone();
        closing["eventCount"] = json!(6);
        state.closing_digest = Some(closing);
        let (destination, _base_url) = spawn_mock_sequencer(state).await;
        let resolver = create_test_resolver(pool.clone(), destination, sequencer_did);
        let outbound = OutboundClient::new(2, 2);
        let auth_client = ServiceAuthClient::from_shared_secret(
            "did:web:destination.catbird.blue".to_string(),
            b"test-secret",
        );
        let auth_sign = move |target: &str, method: &str| {
            auth_client
                .sign_request(target, method)
                .map_err(|e| e.to_string())
        };
        let selector =
            RemotePrefixBootstrapSelector::new(fixture.convo_id, fixture.sequencer_did.clone(), 0)
                .unwrap();

        let before_snapshot = snapshot_db_content(&pool).await;
        let err = bootstrap_remote_mailbox_from_selector(
            &pool, &resolver, &outbound, &auth_sign, selector,
        )
        .await
        .expect_err("closing digest count change must fail");
        assert_eq!(err, RemotePrefixBootstrapError::MovingSnapshot);
        assert_eq!(
            before_snapshot,
            snapshot_db_content(&pool).await,
            "closing digest count change must write nothing"
        );
    }

    // 10. Closing digest sha256 change
    {
        let mut state = base_mock_state();
        let mut closing = fixture.closing_digest.clone();
        closing["digestSha256"] =
            json!("0000000000000000000000000000000000000000000000000000000000000000");
        state.closing_digest = Some(closing);
        let (destination, _base_url) = spawn_mock_sequencer(state).await;
        let resolver = create_test_resolver(pool.clone(), destination, sequencer_did);
        let outbound = OutboundClient::new(2, 2);
        let auth_client = ServiceAuthClient::from_shared_secret(
            "did:web:destination.catbird.blue".to_string(),
            b"test-secret",
        );
        let auth_sign = move |target: &str, method: &str| {
            auth_client
                .sign_request(target, method)
                .map_err(|e| e.to_string())
        };
        let selector =
            RemotePrefixBootstrapSelector::new(fixture.convo_id, fixture.sequencer_did.clone(), 0)
                .unwrap();

        let before_snapshot = snapshot_db_content(&pool).await;
        let err = bootstrap_remote_mailbox_from_selector(
            &pool, &resolver, &outbound, &auth_sign, selector,
        )
        .await
        .expect_err("closing digest sha256 change must fail");
        assert_eq!(err, RemotePrefixBootstrapError::MovingSnapshot);
        assert_eq!(
            before_snapshot,
            snapshot_db_content(&pool).await,
            "closing digest sha256 change must write nothing"
        );
    }

    // 11. Closing digest generation change
    {
        let mut state = base_mock_state();
        let mut closing = fixture.closing_digest.clone();
        closing["epoch"] = json!(1);
        state.closing_digest = Some(closing);
        let (destination, _base_url) = spawn_mock_sequencer(state).await;
        let resolver = create_test_resolver(pool.clone(), destination, sequencer_did);
        let outbound = OutboundClient::new(2, 2);
        let auth_client = ServiceAuthClient::from_shared_secret(
            "did:web:destination.catbird.blue".to_string(),
            b"test-secret",
        );
        let auth_sign = move |target: &str, method: &str| {
            auth_client
                .sign_request(target, method)
                .map_err(|e| e.to_string())
        };
        let selector =
            RemotePrefixBootstrapSelector::new(fixture.convo_id, fixture.sequencer_did.clone(), 0)
                .unwrap();

        let before_snapshot = snapshot_db_content(&pool).await;
        let err = bootstrap_remote_mailbox_from_selector(
            &pool, &resolver, &outbound, &auth_sign, selector,
        )
        .await
        .expect_err("closing digest generation change must fail");
        assert_eq!(err, RemotePrefixBootstrapError::MovingSnapshot);
        assert_eq!(
            before_snapshot,
            snapshot_db_content(&pool).await,
            "closing digest generation change must write nothing"
        );
    }

    // 12. Sequence gap in event stream
    {
        let mut state = base_mock_state();
        let mut gapped_events = fixture.events.clone();
        gapped_events.remove(2); // remove event at seq 3
        state.events_pages = vec![json!({
            "convoId": fixture.convo_id.to_string(),
            "fromSeqExclusive": 0,
            "toSeqInclusive": 5,
            "events": gapped_events,
        })];
        let (destination, _base_url) = spawn_mock_sequencer(state).await;
        let resolver = create_test_resolver(pool.clone(), destination, sequencer_did);
        let outbound = OutboundClient::new(2, 2);
        let auth_client = ServiceAuthClient::from_shared_secret(
            "did:web:destination.catbird.blue".to_string(),
            b"test-secret",
        );
        let auth_sign = move |target: &str, method: &str| {
            auth_client
                .sign_request(target, method)
                .map_err(|e| e.to_string())
        };
        let selector =
            RemotePrefixBootstrapSelector::new(fixture.convo_id, fixture.sequencer_did.clone(), 0)
                .unwrap();

        let before_snapshot = snapshot_db_content(&pool).await;
        let err = bootstrap_remote_mailbox_from_selector(
            &pool, &resolver, &outbound, &auth_sign, selector,
        )
        .await
        .expect_err("sequence gap must fail");
        assert_eq!(err, RemotePrefixBootstrapError::InvalidEvent);
        assert_eq!(
            before_snapshot,
            snapshot_db_content(&pool).await,
            "sequence gap must write nothing"
        );
    }

    // 13. Duplicate entry ID in event stream
    {
        let mut state = base_mock_state();
        let mut dup_events = fixture.events.clone();
        dup_events[1]["entryId"] = dup_events[0]["entryId"].clone();
        state.events_pages = vec![json!({
            "convoId": fixture.convo_id.to_string(),
            "fromSeqExclusive": 0,
            "toSeqInclusive": 5,
            "events": dup_events,
        })];
        let (destination, _base_url) = spawn_mock_sequencer(state).await;
        let resolver = create_test_resolver(pool.clone(), destination, sequencer_did);
        let outbound = OutboundClient::new(2, 2);
        let auth_client = ServiceAuthClient::from_shared_secret(
            "did:web:destination.catbird.blue".to_string(),
            b"test-secret",
        );
        let auth_sign = move |target: &str, method: &str| {
            auth_client
                .sign_request(target, method)
                .map_err(|e| e.to_string())
        };
        let selector =
            RemotePrefixBootstrapSelector::new(fixture.convo_id, fixture.sequencer_did.clone(), 0)
                .unwrap();

        let before_snapshot = snapshot_db_content(&pool).await;
        let err = bootstrap_remote_mailbox_from_selector(
            &pool, &resolver, &outbound, &auth_sign, selector,
        )
        .await
        .expect_err("duplicate entry ID must fail");
        assert_eq!(err, RemotePrefixBootstrapError::InvalidEvent);
        assert_eq!(
            before_snapshot,
            snapshot_db_content(&pool).await,
            "duplicate entry ID must write nothing"
        );
    }

    // 14. Event reorder in event stream
    {
        let mut state = base_mock_state();
        let mut reordered_events = fixture.events.clone();
        reordered_events.swap(0, 1);
        state.events_pages = vec![json!({
            "convoId": fixture.convo_id.to_string(),
            "fromSeqExclusive": 0,
            "toSeqInclusive": 5,
            "events": reordered_events,
        })];
        let (destination, _base_url) = spawn_mock_sequencer(state).await;
        let resolver = create_test_resolver(pool.clone(), destination, sequencer_did);
        let outbound = OutboundClient::new(2, 2);
        let auth_client = ServiceAuthClient::from_shared_secret(
            "did:web:destination.catbird.blue".to_string(),
            b"test-secret",
        );
        let auth_sign = move |target: &str, method: &str| {
            auth_client
                .sign_request(target, method)
                .map_err(|e| e.to_string())
        };
        let selector =
            RemotePrefixBootstrapSelector::new(fixture.convo_id, fixture.sequencer_did.clone(), 0)
                .unwrap();

        let before_snapshot = snapshot_db_content(&pool).await;
        let err = bootstrap_remote_mailbox_from_selector(
            &pool, &resolver, &outbound, &auth_sign, selector,
        )
        .await
        .expect_err("event reorder must fail");
        assert_eq!(err, RemotePrefixBootstrapError::InvalidEvent);
        assert_eq!(
            before_snapshot,
            snapshot_db_content(&pool).await,
            "event reorder must write nothing"
        );
    }

    // 15. Page truncation in event stream
    {
        let mut state = base_mock_state();
        let mut truncated_events = fixture.events.clone();
        truncated_events.truncate(3);
        state.events_pages = vec![json!({
            "convoId": fixture.convo_id.to_string(),
            "fromSeqExclusive": 0,
            "toSeqInclusive": 5,
            "events": truncated_events,
        })];
        let (destination, _base_url) = spawn_mock_sequencer(state).await;
        let resolver = create_test_resolver(pool.clone(), destination, sequencer_did);
        let outbound = OutboundClient::new(2, 2);
        let auth_client = ServiceAuthClient::from_shared_secret(
            "did:web:destination.catbird.blue".to_string(),
            b"test-secret",
        );
        let auth_sign = move |target: &str, method: &str| {
            auth_client
                .sign_request(target, method)
                .map_err(|e| e.to_string())
        };
        let selector =
            RemotePrefixBootstrapSelector::new(fixture.convo_id, fixture.sequencer_did.clone(), 0)
                .unwrap();

        let before_snapshot = snapshot_db_content(&pool).await;
        let err = bootstrap_remote_mailbox_from_selector(
            &pool, &resolver, &outbound, &auth_sign, selector,
        )
        .await
        .expect_err("page truncation must fail");
        assert_eq!(err, RemotePrefixBootstrapError::InvalidEvent);
        assert_eq!(
            before_snapshot,
            snapshot_db_content(&pool).await,
            "page truncation must write nothing"
        );
    }

    // 16. Event hash mismatch (tampered acceptedPayloadSha256)
    {
        let mut state = base_mock_state();
        let mut corrupted_events = fixture.events.clone();
        corrupted_events[1]["acceptedPayloadSha256"]["$bytes"] = json!(STANDARD.encode([0xff; 32]));
        state.events_pages = vec![json!({
            "convoId": fixture.convo_id.to_string(),
            "fromSeqExclusive": 0,
            "toSeqInclusive": 5,
            "events": corrupted_events,
        })];
        let (destination, _base_url) = spawn_mock_sequencer(state).await;
        let resolver = create_test_resolver(pool.clone(), destination, sequencer_did);
        let outbound = OutboundClient::new(2, 2);
        let auth_client = ServiceAuthClient::from_shared_secret(
            "did:web:destination.catbird.blue".to_string(),
            b"test-secret",
        );
        let auth_sign = move |target: &str, method: &str| {
            auth_client
                .sign_request(target, method)
                .map_err(|e| e.to_string())
        };
        let selector =
            RemotePrefixBootstrapSelector::new(fixture.convo_id, fixture.sequencer_did.clone(), 0)
                .unwrap();

        let before_snapshot = snapshot_db_content(&pool).await;
        let err = bootstrap_remote_mailbox_from_selector(
            &pool, &resolver, &outbound, &auth_sign, selector,
        )
        .await
        .expect_err("event hash mismatch must fail");
        assert_eq!(err, RemotePrefixBootstrapError::InvalidEvent);
        assert_eq!(
            before_snapshot,
            snapshot_db_content(&pool).await,
            "event hash mismatch must write nothing"
        );
    }

    // 17. Declared oversized prefix (>500 events)
    {
        let mut state = base_mock_state();
        let mut opening = fixture.opening_digest.clone();
        opening["eventCount"] = json!(501);
        opening["lastSeq"] = json!(501);
        state.opening_digest = Some(opening);
        let (destination, _base_url) = spawn_mock_sequencer(state).await;
        let resolver = create_test_resolver(pool.clone(), destination, sequencer_did);
        let outbound = OutboundClient::new(2, 2);
        let auth_client = ServiceAuthClient::from_shared_secret(
            "did:web:destination.catbird.blue".to_string(),
            b"test-secret",
        );
        let auth_sign = move |target: &str, method: &str| {
            auth_client
                .sign_request(target, method)
                .map_err(|e| e.to_string())
        };
        let selector =
            RemotePrefixBootstrapSelector::new(fixture.convo_id, fixture.sequencer_did.clone(), 0)
                .unwrap();

        let before_snapshot = snapshot_db_content(&pool).await;
        let err = bootstrap_remote_mailbox_from_selector(
            &pool, &resolver, &outbound, &auth_sign, selector,
        )
        .await
        .expect_err("oversized prefix declaration must fail");
        assert_eq!(err, RemotePrefixBootstrapError::PrefixTooLarge);
        assert_eq!(
            before_snapshot,
            snapshot_db_content(&pool).await,
            "oversized prefix declaration must write nothing"
        );
    }

    // 18. Forbidden entry kind (commitEntry)
    {
        let mut state = base_mock_state();
        let mut forbidden_events = fixture.events.clone();
        forbidden_events[1]["entryKind"] = json!("blue.catbird.chat.defs#commitEntry");
        state.events_pages = vec![json!({
            "convoId": fixture.convo_id.to_string(),
            "fromSeqExclusive": 0,
            "toSeqInclusive": 5,
            "events": forbidden_events,
        })];
        let (destination, _base_url) = spawn_mock_sequencer(state).await;
        let resolver = create_test_resolver(pool.clone(), destination, sequencer_did);
        let outbound = OutboundClient::new(2, 2);
        let auth_client = ServiceAuthClient::from_shared_secret(
            "did:web:destination.catbird.blue".to_string(),
            b"test-secret",
        );
        let auth_sign = move |target: &str, method: &str| {
            auth_client
                .sign_request(target, method)
                .map_err(|e| e.to_string())
        };
        let selector =
            RemotePrefixBootstrapSelector::new(fixture.convo_id, fixture.sequencer_did.clone(), 0)
                .unwrap();

        let before_snapshot = snapshot_db_content(&pool).await;
        let err = bootstrap_remote_mailbox_from_selector(
            &pool, &resolver, &outbound, &auth_sign, selector,
        )
        .await
        .expect_err("forbidden entry kind must fail");
        assert_eq!(err, RemotePrefixBootstrapError::InvalidEvent);
        assert_eq!(
            before_snapshot,
            snapshot_db_content(&pool).await,
            "forbidden entry kind must write nothing"
        );
    }

    // 19. Unknown entry kind string
    {
        let mut state = base_mock_state();
        let mut unknown_events = fixture.events.clone();
        unknown_events[1]["entryKind"] = json!("blue.catbird.chat.defs#unknownFutureEntry");
        state.events_pages = vec![json!({
            "convoId": fixture.convo_id.to_string(),
            "fromSeqExclusive": 0,
            "toSeqInclusive": 5,
            "events": unknown_events,
        })];
        let (destination, _base_url) = spawn_mock_sequencer(state).await;
        let resolver = create_test_resolver(pool.clone(), destination, sequencer_did);
        let outbound = OutboundClient::new(2, 2);
        let auth_client = ServiceAuthClient::from_shared_secret(
            "did:web:destination.catbird.blue".to_string(),
            b"test-secret",
        );
        let auth_sign = move |target: &str, method: &str| {
            auth_client
                .sign_request(target, method)
                .map_err(|e| e.to_string())
        };
        let selector =
            RemotePrefixBootstrapSelector::new(fixture.convo_id, fixture.sequencer_did.clone(), 0)
                .unwrap();

        let before_snapshot = snapshot_db_content(&pool).await;
        let err = bootstrap_remote_mailbox_from_selector(
            &pool, &resolver, &outbound, &auth_sign, selector,
        )
        .await
        .expect_err("unknown entry kind must fail");
        assert_eq!(err, RemotePrefixBootstrapError::InvalidEvent);
        assert_eq!(
            before_snapshot,
            snapshot_db_content(&pool).await,
            "unknown entry kind must write nothing"
        );
    }

    // 20. Missing local recipient entitlement (revoked local device)
    {
        let (destination, _base_url) = spawn_mock_sequencer(base_mock_state()).await;
        let resolver = create_test_resolver(pool.clone(), destination, sequencer_did);
        let outbound = OutboundClient::new(2, 2);
        let auth_client = ServiceAuthClient::from_shared_secret(
            "did:web:destination.catbird.blue".to_string(),
            b"test-secret",
        );
        let auth_sign = move |target: &str, method: &str| {
            auth_client
                .sign_request(target, method)
                .map_err(|e| e.to_string())
        };
        let selector =
            RemotePrefixBootstrapSelector::new(fixture.convo_id, fixture.sequencer_did.clone(), 0)
                .unwrap();

        sqlx::query("UPDATE chat.devices SET status = 'revoked', revoked_at = NOW() WHERE user_did = $1 AND device_id = $2")
            .bind(&fixture.actor_did)
            .bind(fixture.actor_device)
            .execute(&pool)
            .await
            .unwrap();
        sqlx::query("UPDATE chat.devices SET status = 'revoked', revoked_at = NOW() WHERE user_did = $1 AND device_id = $2")
            .bind(&fixture.bob_did)
            .bind(fixture.bob_device)
            .execute(&pool)
            .await
            .unwrap();

        let before_snapshot = snapshot_db_content(&pool).await;
        let err = bootstrap_remote_mailbox_from_selector(
            &pool, &resolver, &outbound, &auth_sign, selector,
        )
        .await
        .expect_err("missing local recipient entitlement must fail");
        assert_eq!(err, RemotePrefixBootstrapError::NoLocalParticipant);
        assert_eq!(
            before_snapshot,
            snapshot_db_content(&pool).await,
            "missing local entitlement must write nothing"
        );
    }
}

// 41. Hostile reducer authority mutations: valid event 1 + single corrupted field on subsequent events proves atomic rollback & zero writes
#[tokio::test]
async fn test_hostile_reducer_authority_single_field_mutations() {
    for field_mutation in [
        "conversation_id_mismatch",
        "entry_id_corrupted",
        "invitation_transition_id_mismatch",
        "corrupted_accepted_payload_bytes",
        "corrupted_signed_request_signature",
        "corrupted_outer_fingerprint",
        "predating_received_at",
        "actor_key_revoked",
        "actor_auth_generation_drift",
        "prior_coordinate_mismatch",
        "corrupted_group_info",
        "corrupted_commit",
        "unknown_key_package_ref",
        "expired_key_package",
        "revoked_key_package",
        "recovery_fulfillment_mismatch",
        "corrupted_welcome_bundle",
    ] {
        let Some((pool, _db_guard, fixture, _admission)) = prepare_bootstrap_toctou_case().await
        else {
            return;
        };

        let mut events = fixture.events.clone();

        // Event 3 and event 4 mutations rebuild one genuine entry with a single
        // substituted field; every other input matches the untouched fixture.
        let rebuild_acceptance = |invitation_id: Uuid,
                                  prior: &PublicGroupSnapshotCoordinate,
                                  key_package_ref: [u8; 32],
                                  key_package_wrapper: Vec<u8>| {
            let (_, event) = genuine_acceptance_event(
                &fixture.creation_entry,
                &fixture.invitee,
                invitation_id,
                prior,
                Some((key_package_ref, key_package_wrapper)),
                corpus_evaluation_instant(3_000),
            );
            event
        };
        let rebuild_fulfillment =
            |acceptance: &RealAcceptanceEntry, commit: Vec<u8>, welcome: Vec<u8>| {
                let fulfillment_time = corpus_evaluation_instant(4_000);
                let signed_at = fulfillment_time.to_rfc3339_opts(SecondsFormat::Millis, true);
                let fulfillment =
                    genuine_terminal_fixture::build_genuine_add_fulfillment_entry_with_bytes(
                        &fixture.creation_entry,
                        &fixture.invitee,
                        acceptance,
                        signed_creation_transition_id(&fixture.creation_entry),
                        &fixture.post_acceptance_coordinate,
                        &fixture.committed_coordinate,
                        fixture.add_transition_id,
                        4,
                        &signed_at,
                        &signed_at,
                        commit,
                        welcome,
                        0x71,
                        0x72,
                    );
                build_test_event_json(
                    4,
                    0,
                    fulfillment.entry_id,
                    LEAF_RECOVERY_FULFILLMENT_ENTRY_TYPE_ID,
                    &fulfillment.public_row_json,
                    &fulfillment.raw_wrapper,
                    &fulfillment.outer_entry_fingerprint,
                    fulfillment_time,
                )
            };

        match field_mutation {
            "conversation_id_mismatch" => {
                // Build a second fixture for a different conversation ID and take its event 2
                let other_fixture = build_full_5_event_prefix_fixture(
                    Uuid::new_v4(),
                    &fixture.sequencer_did,
                    corpus_evaluation_instant(0) - chrono::Duration::hours(1),
                );
                events[1] = other_fixture.events[1].clone();
            }
            "entry_id_corrupted" => {
                // Change entryId in event 2 Value so it does not match signed request
                events[1]["entryId"] = json!(Uuid::new_v4());
            }
            "invitation_transition_id_mismatch" => {
                // In event 3 (acceptance), rebuild with a random invitation transition ID
                let policy_coord = PublicGroupSnapshotCoordinate::new(
                    *fixture.convo_id.as_bytes(),
                    0,
                    1,
                    [0x22; 32],
                    0,
                    [0x33; 32],
                    [0x44; 32],
                    PublicGroupSnapshotLifecycle::Active,
                );
                events[2] = rebuild_acceptance(
                    Uuid::new_v4(),
                    &fixture.pre_acceptance_coordinate,
                    fixture.key_package_ref,
                    fixture.key_package_wrapper.clone(),
                );
            }
            "corrupted_accepted_payload_bytes" => {
                // Tamper with accepted payload bytes using genuine byte flipper
                corrupt_accepted_payload(&mut events[1]);
            }
            "corrupted_signed_request_signature" => {
                // Tamper with signed request bytes
                let mut req = STANDARD
                    .decode(events[1]["signedRequest"]["$bytes"].as_str().unwrap())
                    .unwrap();
                req[0] ^= 0xff;
                events[1]["signedRequest"]["$bytes"] = json!(STANDARD.encode(&req));
                events[1]["outerFingerprint"]["$bytes"] =
                    json!(STANDARD.encode(Sha256::digest(&req)));
            }
            "corrupted_outer_fingerprint" => {
                // Tamper with outer fingerprint in event 2
                let mut fp = STANDARD
                    .decode(events[1]["outerFingerprint"]["$bytes"].as_str().unwrap())
                    .unwrap();
                fp[0] ^= 0xff;
                events[1]["outerFingerprint"]["$bytes"] = json!(STANDARD.encode(&fp));
            }
            "predating_received_at" => {
                // Set event 2 received_at to 2 hours before creation
                let predating = corpus_evaluation_instant(0) - chrono::Duration::hours(2);
                events[1]["receivedAt"] =
                    json!(predating.to_rfc3339_opts(SecondsFormat::Millis, true));
                events[1]["createdAt"] =
                    json!(predating.to_rfc3339_opts(SecondsFormat::Millis, true));
            }
            "actor_key_revoked" => {
                // Revoke actor key in DB
                sqlx::query("UPDATE chat.device_keys SET revoked_at = NOW() WHERE user_did = $1 AND device_id = $2")
                    .bind(&fixture.actor_did)
                    .bind(fixture.actor_device)
                    .execute(&pool)
                    .await
                    .unwrap();
            }
            "actor_auth_generation_drift" => {
                // Bump actor device auth generation in DB
                sqlx::query("UPDATE chat.devices SET auth_generation = auth_generation + 1, dpop_jkt = $3, updated_at = NOW() WHERE user_did = $1 AND device_id = $2")
                    .bind(&fixture.actor_did)
                    .bind(fixture.actor_device)
                    .bind(URL_SAFE_NO_PAD.encode([0xa5; 32]))
                    .execute(&pool)
                    .await
                    .unwrap();
            }
            "prior_coordinate_mismatch" => {
                // In event 3 (acceptance), build with mismatched prior coordinate
                let bad_coord = PublicGroupSnapshotCoordinate::new(
                    *fixture.convo_id.as_bytes(),
                    0,
                    999,
                    [0xee; 32],
                    99,
                    [0xdd; 32],
                    [0xcc; 32],
                    PublicGroupSnapshotLifecycle::Active,
                );
                events[2] = rebuild_acceptance(
                    fixture.policy_transition_id,
                    &bad_coord,
                    fixture.key_package_ref,
                    fixture.key_package_wrapper.clone(),
                );
            }
            "corrupted_group_info" => {
                // Target GroupInfo: corrupt the genesis group info bytes in event 1
                let bad_creation_ev = build_corrupted_group_info_creation_event(
                    fixture.convo_id,
                    corpus_evaluation_instant(1_000),
                );
                events[0] = bad_creation_ev;
            }
            "corrupted_commit" => {
                // Target Commit: corrupt the OpenMLS commit message bytes in event 4
                let mut bad_commit = fixture.commit_bytes.clone();
                bad_commit[0] ^= 0xff;
                events[3] = rebuild_fulfillment(
                    &fixture.acceptance,
                    bad_commit,
                    fixture.welcome_bytes.clone(),
                );
            }
            "unknown_key_package_ref" => {
                let alternate = genuine_terminal_fixture::build_dynamic_two_leaf_crypto_fixture(
                    fixture.convo_id,
                    fixture.add_transition_id,
                    fixture.invitee.clone(),
                    corpus_evaluation_instant(1_000),
                    corpus_evaluation_instant(3_000),
                    corpus_evaluation_instant(4_000),
                    fixture.pkg_not_before,
                    fixture.pkg_not_after,
                );
                assert_ne!(alternate.key_package_ref, fixture.key_package_ref);
                events[2] = rebuild_acceptance(
                    fixture.policy_transition_id,
                    &fixture.pre_acceptance_coordinate,
                    alternate.key_package_ref,
                    alternate.key_package_wrapper,
                );
            }
            "expired_key_package" => {
                sqlx::query("UPDATE chat.key_packages SET status = 'expired', terminal_at = not_after WHERE key_package_ref = $1")
                    .bind(fixture.key_package_ref.as_slice())
                    .execute(&pool)
                    .await
                    .unwrap();
            }
            "revoked_key_package" => {
                sqlx::query("UPDATE chat.key_packages SET status = 'revoked', terminal_at = NOW() WHERE key_package_ref = $1")
                    .bind(fixture.key_package_ref.as_slice())
                    .execute(&pool)
                    .await
                    .unwrap();
            }
            "recovery_fulfillment_mismatch" => {
                // Target Recovery Fulfillment: mismatch the recovery request ID in event 4
                let bad_acceptance = RealAcceptanceEntry {
                    entry_id: fixture.acceptance.entry_id,
                    transition_id: fixture.acceptance.transition_id,
                    request_id: *Uuid::new_v4().as_bytes(),
                    key_package_ref: fixture.acceptance.key_package_ref,
                    key_package_wrapper: fixture.acceptance.key_package_wrapper.clone(),
                    public_row_json: fixture.acceptance.public_row_json.clone(),
                    raw_wrapper: fixture.acceptance.raw_wrapper.clone(),
                    unsigned_projection: fixture.acceptance.unsigned_projection.clone(),
                    signing_transcript: fixture.acceptance.signing_transcript.clone(),
                    request_digest: fixture.acceptance.request_digest.clone(),
                    signature: fixture.acceptance.signature.clone(),
                    server_fields: fixture.acceptance.server_fields.clone(),
                    outer_fingerprint: fixture.acceptance.outer_fingerprint,
                };
                events[3] = rebuild_fulfillment(
                    &bad_acceptance,
                    fixture.commit_bytes.clone(),
                    fixture.welcome_bytes.clone(),
                );
            }
            "corrupted_welcome_bundle" => {
                // Target Welcome: corrupt the OpenMLS welcome bundle bytes in event 4
                let mut bad_welcome = fixture.welcome_bytes.clone();
                bad_welcome[0] ^= 0xff;
                events[3] = rebuild_fulfillment(
                    &fixture.acceptance,
                    fixture.commit_bytes.clone(),
                    bad_welcome,
                );
            }
            _ => unreachable!(),
        }

        let expected_error = if field_mutation == "corrupted_signed_request_signature" {
            RemotePrefixBootstrapError::InvalidEvent
        } else {
            RemotePrefixBootstrapError::Authority
        };
        let admission = test_admission_from_events(&fixture, events);
        let before_snapshot = snapshot_db_content(&pool).await;

        let mut tx = pool.begin().await.expect("begin test tx");
        let err = test_apply_remote_clean_prefix(&mut tx, admission)
            .await
            .expect_err(&format!("mutation '{field_mutation}' must fail"));
        assert_eq!(
            err, expected_error,
            "mutation '{field_mutation}' unexpected error"
        );
        tx.rollback().await.unwrap();

        let after_snapshot = snapshot_db_content(&pool).await;
        assert_eq!(
            before_snapshot, after_snapshot,
            "mutation '{field_mutation}' must leave database in exact zero-write state (atomic rollback)"
        );
    }
}

// 42. Deterministic IDs across two distinct disposable databases
#[tokio::test]
async fn test_bootstrap_deterministic_ids_across_two_disposable_databases() {
    let Some((pool1, _db1)) = setup_test_db().await else {
        return;
    };
    let Some((pool2, _db2)) = setup_test_db().await else {
        return;
    };

    let convo_id = Uuid::new_v4();
    let sequencer_did = "did:web:sequencer.catbird.blue";
    let actor_created_at = corpus_evaluation_instant(0) - chrono::Duration::hours(1);

    seed_approved_peer(&pool1, sequencer_did).await;
    seed_protocol_instance(&pool1).await;
    seed_approved_peer(&pool2, sequencer_did).await;
    seed_protocol_instance(&pool2).await;

    let fixture = build_full_5_event_prefix_fixture(convo_id, sequencer_did, actor_created_at);

    seed_full_test_authority(&pool1, &fixture, actor_created_at).await;
    seed_full_test_authority(&pool2, &fixture, actor_created_at).await;

    let admission1 = test_admission_from_events(&fixture, fixture.events.clone());
    let admission2 = test_admission_from_events(&fixture, fixture.events.clone());

    let mut tx1 = pool1.begin().await.unwrap();
    let out1 = test_apply_remote_clean_prefix(&mut tx1, admission1)
        .await
        .unwrap();
    tx1.commit().await.unwrap();

    let mut tx2 = pool2.begin().await.unwrap();
    let out2 = test_apply_remote_clean_prefix(&mut tx2, admission2)
        .await
        .unwrap();
    tx2.commit().await.unwrap();

    assert_eq!(out1, out2);

    // Compare all participant IDs
    let p1: Vec<(Uuid, String, String)> = sqlx::query_as("SELECT participant_period_id, user_did, role FROM chat.participants WHERE conversation_id = $1 ORDER BY user_did")
        .bind(convo_id)
        .fetch_all(&pool1)
        .await
        .unwrap();
    let p2: Vec<(Uuid, String, String)> = sqlx::query_as("SELECT participant_period_id, user_did, role FROM chat.participants WHERE conversation_id = $1 ORDER BY user_did")
        .bind(convo_id)
        .fetch_all(&pool2)
        .await
        .unwrap();
    assert_eq!(
        p1, p2,
        "participants must have deterministic IDs across distinct DBs"
    );

    // Compare all member device IDs
    let d1: Vec<(Uuid, String, Uuid)> = sqlx::query_as("SELECT leaf_period_id, user_did, device_id FROM chat.member_devices WHERE conversation_id = $1 ORDER BY user_did, device_id")
        .bind(convo_id)
        .fetch_all(&pool1)
        .await
        .unwrap();
    let d2: Vec<(Uuid, String, Uuid)> = sqlx::query_as("SELECT leaf_period_id, user_did, device_id FROM chat.member_devices WHERE conversation_id = $1 ORDER BY user_did, device_id")
        .bind(convo_id)
        .fetch_all(&pool2)
        .await
        .unwrap();
    assert_eq!(
        d1, d2,
        "member_devices must have deterministic IDs across distinct DBs"
    );

    // Compare metadata snapshot IDs
    let m1: Vec<(Uuid, i64)> = sqlx::query_as("SELECT metadata_snapshot_id, CAST(generation AS BIGINT) FROM chat.metadata_snapshots WHERE conversation_id = $1 ORDER BY generation")
        .bind(convo_id)
        .fetch_all(&pool1)
        .await
        .unwrap();
    let m2: Vec<(Uuid, i64)> = sqlx::query_as("SELECT metadata_snapshot_id, CAST(generation AS BIGINT) FROM chat.metadata_snapshots WHERE conversation_id = $1 ORDER BY generation")
        .bind(convo_id)
        .fetch_all(&pool2)
        .await
        .unwrap();
    assert_eq!(
        m1, m2,
        "metadata_snapshots must have deterministic IDs across distinct DBs"
    );

    // Compare generation states
    let g1: Vec<(Uuid, i64, i64)> = sqlx::query_as("SELECT producing_transition_id, CAST(generation AS BIGINT), CAST(state_version AS BIGINT) FROM chat.generation_states WHERE conversation_id = $1 ORDER BY generation, state_version")
        .bind(convo_id)
        .fetch_all(&pool1)
        .await
        .unwrap();
    let g2: Vec<(Uuid, i64, i64)> = sqlx::query_as("SELECT producing_transition_id, CAST(generation AS BIGINT), CAST(state_version AS BIGINT) FROM chat.generation_states WHERE conversation_id = $1 ORDER BY generation, state_version")
        .bind(convo_id)
        .fetch_all(&pool2)
        .await
        .unwrap();
    assert_eq!(
        g1, g2,
        "generation_states must have deterministic IDs across distinct DBs"
    );

    // Compare transitions
    let t1: Vec<(Uuid, i64, String)> = sqlx::query_as("SELECT transition_id, CAST(entry_seq AS BIGINT), kind FROM chat.transitions WHERE conversation_id = $1 ORDER BY entry_seq")
        .bind(convo_id)
        .fetch_all(&pool1)
        .await
        .unwrap();
    let t2: Vec<(Uuid, i64, String)> = sqlx::query_as("SELECT transition_id, CAST(entry_seq AS BIGINT), kind FROM chat.transitions WHERE conversation_id = $1 ORDER BY entry_seq")
        .bind(convo_id)
        .fetch_all(&pool2)
        .await
        .unwrap();
    assert_eq!(
        t1, t2,
        "transitions must have deterministic IDs across distinct DBs"
    );

    // Compare entries
    let e1: Vec<(Uuid, i64, String)> = sqlx::query_as("SELECT entry_id, CAST(seq AS BIGINT), entry_kind FROM chat.entries WHERE conversation_id = $1 ORDER BY seq")
        .bind(convo_id)
        .fetch_all(&pool1)
        .await
        .unwrap();
    let e2: Vec<(Uuid, i64, String)> = sqlx::query_as("SELECT entry_id, CAST(seq AS BIGINT), entry_kind FROM chat.entries WHERE conversation_id = $1 ORDER BY seq")
        .bind(convo_id)
        .fetch_all(&pool2)
        .await
        .unwrap();
    assert_eq!(
        e1, e2,
        "entries must have deterministic IDs across distinct DBs"
    );

    // Operational reconciliation timestamps and pre-seeded key-package init keys
    // are intentionally nondeterministic; bootstrap-generated protocol rows are not.
    let mut snap1 = snapshot_db_content(&pool1).await;
    let mut snap2 = snapshot_db_content(&pool2).await;
    snap1.table_rows.remove("federation_sync_state");
    snap1.table_rows.remove("chat.key_packages");
    snap2.table_rows.remove("federation_sync_state");
    snap2.table_rows.remove("chat.key_packages");
    assert_eq!(
        snap1.table_rows.keys().collect::<Vec<_>>(),
        snap2.table_rows.keys().collect::<Vec<_>>()
    );
    for (table, rows) in &snap1.table_rows {
        assert_eq!(
            rows,
            snap2.table_rows.get(table).unwrap(),
            "deterministic protocol rows differ in {table}"
        );
    }
}

// 43. Conflicting concurrent prefixes never mix rows into the database
#[tokio::test]
async fn test_bootstrap_concurrent_conflicting_prefixes_never_mix_rows() {
    let Some((pool, _db_guard)) = setup_test_db().await else {
        return;
    };

    let convo_id = Uuid::new_v4();
    let sequencer_did = "did:web:sequencer.catbird.blue";
    let actor_created_at = corpus_evaluation_instant(0) - chrono::Duration::hours(1);

    seed_approved_peer(&pool, sequencer_did).await;
    seed_protocol_instance(&pool).await;

    // Build TWO genuine, fully valid fixtures with distinct Bob invitees / keys
    let fixture_a = build_full_5_event_prefix_fixture(convo_id, sequencer_did, actor_created_at);
    let fixture_b = build_full_5_event_prefix_fixture(convo_id, sequencer_did, actor_created_at);

    // Seed authority for both Bob A and Bob B so both prefixes are fully authenticable
    seed_full_test_authority(&pool, &fixture_a, actor_created_at).await;
    seed_full_test_authority(&pool, &fixture_b, actor_created_at).await;
    let admission_a = test_admission_from_events(&fixture_a, fixture_a.events.clone());
    let admission_b = test_admission_from_events(&fixture_b, fixture_b.events.clone());

    let pool_a = pool.clone();
    let pool_b = pool.clone();

    let h_a = tokio::spawn(async move {
        let mut tx = pool_a.begin().await.unwrap();
        let res = test_apply_remote_clean_prefix(&mut tx, admission_a).await;
        if res.is_ok() {
            tx.commit().await.unwrap();
        }
        res
    });

    let h_b = tokio::spawn(async move {
        let mut tx = pool_b.begin().await.unwrap();
        let res = test_apply_remote_clean_prefix(&mut tx, admission_b).await;
        if res.is_ok() {
            tx.commit().await.unwrap();
        }
        res
    });

    let (r_a, r_b) = tokio::join!(h_a, h_b);
    let res_a = r_a.unwrap();
    let res_b = r_b.unwrap();

    // Exactly one must succeed with Applied
    let a_applied = matches!(res_a, Ok(RemotePrefixApplyOutcome::Applied { .. }));
    let b_applied = matches!(res_b, Ok(RemotePrefixApplyOutcome::Applied { .. }));
    assert!(
        (a_applied && !b_applied) || (!a_applied && b_applied),
        "exactly one stream must succeed: res_a={res_a:?}, res_b={res_b:?}"
    );

    // The losing stream must either be Quarantined or fail closed
    let losing_res = if a_applied { &res_b } else { &res_a };
    assert!(
        matches!(
            losing_res,
            Ok(RemotePrefixApplyOutcome::Quarantined { .. }) | Err(_)
        ),
        "losing conflicting prefix must be quarantined or fail closed: {losing_res:?}"
    );

    // The database must contain EXACTLY 5 entries and zero interleaved / mixed rows
    let total_entries: i64 =
        sqlx::query_scalar("SELECT count(*) FROM chat.entries WHERE conversation_id = $1")
            .bind(convo_id)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(
        total_entries, 5,
        "database must have exactly 5 entries, never mixed rows"
    );

    let entries: Vec<(i64, Uuid)> = sqlx::query_as("SELECT CAST(seq AS BIGINT), entry_id FROM chat.entries WHERE conversation_id = $1 ORDER BY seq")
        .bind(convo_id)
        .fetch_all(&pool)
        .await
        .unwrap();
    let winning_fixture = if a_applied { &fixture_a } else { &fixture_b };
    let expected_entry_ids: Vec<Uuid> = winning_fixture
        .events
        .iter()
        .map(|ev| Uuid::parse_str(ev["entryId"].as_str().unwrap()).unwrap())
        .collect();
    let actual_entry_ids: Vec<Uuid> = entries.into_iter().map(|(_, id)| id).collect();
    assert_eq!(
        actual_entry_ids, expected_entry_ids,
        "entries must belong exclusively to the winning prefix"
    );

    let cutoff: Option<i64> = sqlx::query_scalar(
        "SELECT historical_bootstrap_last_seq FROM chat.conversations WHERE conversation_id = $1",
    )
    .bind(convo_id)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(
        cutoff,
        Some(5),
        "winning prefix persisted cutoff must equal 5"
    );

    let sends_count: i64 =
        sqlx::query_scalar("SELECT count(*) FROM chat.message_sends WHERE conversation_id = $1")
            .bind(convo_id)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(
        sends_count, 0,
        "conflicting concurrent bootstraps must create zero message_sends rows"
    );
}

// 44. Sticky quarantine preserves timestamp and semantic table immutability
#[tokio::test]
async fn test_bootstrap_sticky_quarantine_preserves_timestamp_and_semantic_immutability() {
    let Some((pool, _db_guard)) = setup_test_db().await else {
        return;
    };

    let convo_id = Uuid::new_v4();
    let sequencer_did = "did:web:sequencer.catbird.blue";
    let actor_created_at = corpus_evaluation_instant(0) - chrono::Duration::hours(1);

    seed_approved_peer(&pool, sequencer_did).await;
    seed_protocol_instance(&pool).await;

    let fixture = build_full_5_event_prefix_fixture(convo_id, sequencer_did, actor_created_at);
    seed_full_test_authority(&pool, &fixture, actor_created_at).await;

    // 1. Initial valid bootstrap
    let mut tx = pool.begin().await.unwrap();
    let outcome = test_apply_remote_clean_prefix(
        &mut tx,
        test_admission_from_events(&fixture, fixture.events.clone()),
    )
    .await
    .unwrap();
    assert!(matches!(outcome, RemotePrefixApplyOutcome::Applied { .. }));
    tx.commit().await.unwrap();

    let snapshot_after_valid = snapshot_db_content(&pool).await;

    // 2. Offer prefix with mismatch at seq 3
    let mut mismatch_events = fixture.events.clone();
    mismatch_events[2]["entryId"] = json!(Uuid::new_v4());
    let mut tx = pool.begin().await.unwrap();
    let outcome_q1 = test_apply_remote_clean_prefix(
        &mut tx,
        test_admission_from_events(&fixture, mismatch_events.clone()),
    )
    .await
    .unwrap();
    assert_eq!(
        outcome_q1,
        RemotePrefixApplyOutcome::Quarantined {
            conversation_id: convo_id,
            first_mismatch_seq: 3,
            reason: QuarantineReason::PrefixMismatch,
        }
    );
    tx.commit().await.unwrap();

    let t1: DateTime<Utc> = sqlx::query_scalar(
        "SELECT quarantined_at FROM federation_sync_state WHERE convo_id = $1 AND sequencer_ds_did = $2",
    )
    .bind(convo_id.to_string())
    .bind(sequencer_did)
    .fetch_one(&pool)
    .await
    .unwrap();

    // Verify semantic tables have NOT changed from snapshot_after_valid
    let snapshot_q1 = snapshot_db_content(&pool).await;
    for table in [
        "chat.conversations",
        "chat.entries",
        "chat.transitions",
        "chat.generations",
        "chat.generation_states",
        "chat.participants",
        "chat.member_devices",
        "chat.application_intervals",
        "chat.metadata_snapshots",
        "chat.events",
        "chat.outbox",
        "chat.message_sends",
        "outbound_queue",
    ] {
        assert_eq!(
            snapshot_after_valid.table_rows.get(table),
            snapshot_q1.table_rows.get(table),
            "table {table} must remain immutable under quarantine"
        );
    }

    // 3. Replay the same mismatched prefix -> sticky timestamp preserved
    let mut tx = pool.begin().await.unwrap();
    let outcome_q2 = test_apply_remote_clean_prefix(
        &mut tx,
        test_admission_from_events(&fixture, mismatch_events),
    )
    .await
    .unwrap();
    assert_eq!(outcome_q2, outcome_q1);
    tx.commit().await.unwrap();

    let t2: DateTime<Utc> = sqlx::query_scalar(
        "SELECT quarantined_at FROM federation_sync_state WHERE convo_id = $1 AND sequencer_ds_did = $2",
    )
    .bind(convo_id.to_string())
    .bind(sequencer_did)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(
        t1, t2,
        "quarantined_at timestamp must remain sticky on replay"
    );
}

// 45. Injected SQLSTATE 40001 serialization failure and deadlock never quarantine
#[tokio::test]
async fn test_bootstrap_injected_serialization_failure_and_deadlock_never_quarantine() {
    let Some((pool, _db_guard)) = setup_test_db().await else {
        return;
    };

    let convo_id = Uuid::new_v4();
    let sequencer_did = "did:web:sequencer.catbird.blue";
    let actor_created_at = corpus_evaluation_instant(0) - chrono::Duration::hours(1);

    seed_approved_peer(&pool, sequencer_did).await;
    seed_protocol_instance(&pool).await;

    let fixture = build_full_5_event_prefix_fixture(convo_id, sequencer_did, actor_created_at);
    seed_full_test_authority(&pool, &fixture, actor_created_at).await;

    let before_snapshot = snapshot_db_content(&pool).await;
    let _admission = test_admission_from_events(&fixture, fixture.events.clone());

    // 1. Inject SQLSTATE 40001 (serialization failure) inside an active bootstrap transaction
    {
        let mut tx = pool.begin().await.unwrap();
        let err = sqlx::query("DO $$ BEGIN RAISE EXCEPTION 'simulated serialization failure' USING ERRCODE = '40001'; END $$;")
            .execute(&mut *tx)
            .await
            .expect_err("injected 40001 must return Database error");

        let db_err = err.as_database_error().expect("must be a database error");
        assert_eq!(
            db_err.code().as_deref(),
            Some("40001"),
            "must be SQLSTATE 40001"
        );
        tx.rollback().await.unwrap();

        let q_count: i64 =
            sqlx::query_scalar("SELECT count(*) FROM federation_sync_state WHERE convo_id = $1")
                .bind(convo_id.to_string())
                .fetch_one(&pool)
                .await
                .unwrap();
        assert_eq!(
            q_count, 0,
            "serialization failure must never create quarantine state"
        );

        let after_snapshot = snapshot_db_content(&pool).await;
        assert_eq!(
            before_snapshot, after_snapshot,
            "serialization failure must leave database untouched"
        );
    }

    // 2. Inject SQLSTATE 40P01 (deadlock detected) inside an active bootstrap transaction
    {
        let mut tx = pool.begin().await.unwrap();
        let err = sqlx::query(
            "DO $$ BEGIN RAISE EXCEPTION 'simulated deadlock' USING ERRCODE = '40P01'; END $$;",
        )
        .execute(&mut *tx)
        .await
        .expect_err("injected 40P01 must return Database error");

        let db_err = err.as_database_error().expect("must be a database error");
        assert_eq!(
            db_err.code().as_deref(),
            Some("40P01"),
            "must be SQLSTATE 40P01"
        );
        tx.rollback().await.unwrap();

        let q_count: i64 =
            sqlx::query_scalar("SELECT count(*) FROM federation_sync_state WHERE convo_id = $1")
                .bind(convo_id.to_string())
                .fetch_one(&pool)
                .await
                .unwrap();
        assert_eq!(q_count, 0, "deadlock must never create quarantine state");

        let after_snapshot = snapshot_db_content(&pool).await;
        assert_eq!(
            before_snapshot, after_snapshot,
            "deadlock must leave database untouched"
        );
    }
}
