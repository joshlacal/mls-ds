//! Test support helpers for clean-chat protocol tests.
//!
//! Provides deterministic relationship projection fixtures and mock transports
//! without exposing production authority or relaxing crate-private visibility in
//! production binaries.

// Reuse the genuine signed Creation -> Acceptance -> Add fixture. This module
// is only compiled for tests/test-support; requests still enter the real router.
#[allow(dead_code)]
#[path = "repository/recovery/production_proof_fixture.rs"]
mod application_routing_fixture;

/// Initial state for the production sendMessage routing regression. No request
/// admission, operation completion, message entry, or federation job is seeded.
pub struct ApplicationRoutingFixture {
    pub conversation_id: uuid::Uuid,
    pub message_id: uuid::Uuid,
    pub sender_did: String,
    pub sender_device_id: uuid::Uuid,
    pub recipient_did: String,
    pub signed_request: serde_json::Value,
}

#[derive(Clone)]
struct ApplicationRoutingTransport {
    sender_did: String,
    recipient_did: String,
}

#[async_trait::async_trait]
impl PublicTransport for ApplicationRoutingTransport {
    async fn get(&self, request: PublicGet) -> Result<PublicResponse, TransportError> {
        // External relationship evidence is a deterministic fixture. The real
        // collector, sealer, persistence writer and send-time consumer still run.
        // The runtime pair resolver receives no hook and cannot resolve these
        // unique example.com fixture homes; that is the direct-kind negative control.
        const FIXTURE_DID_PATH: &str = "/.well-known/did.json"; // did-web-test: fixture match
        let actor = format!("did:web:{}", request.url.host_str().unwrap_or_default());
        if (actor == self.sender_did || actor == self.recipient_did)
            && request.url.path() == FIXTURE_DID_PATH
        {
            return Ok(PublicResponse::json(
                200,
                serde_json::json!({
                    "id": actor,
                    "service": [{
                        "id": format!("{actor}#atproto_pds"),
                        "type": "AtprotoPersonalDataServer",
                        "serviceEndpoint": "https://pds.example.net"
                    }]
                }),
            ));
        }
        DeterministicTestTransport.get(request).await
    }
}

/// Seed a genuine ready two-leaf group/direct history and a request-bound native
/// MLS application, plus validated relationship fallback evidence for that pair.
/// Callers must submit the returned wrapper through the production HTTP router.
pub async fn seed_application_routing_fixture(
    pool: &sqlx::PgPool,
    direct: bool,
    recipient_service_did: &str,
) -> Result<ApplicationRoutingFixture, String> {
    seed_application_routing_fixture_with_sequencer(pool, direct, recipient_service_did, None).await
}

/// Seed a remote group replica at insertion time, preserving the immutable
/// routing identity and every normal history/leaf/operation constraint.
pub async fn seed_remote_group_application_routing_fixture(
    pool: &sqlx::PgPool,
    recipient_service_did: &str,
    sequencer_service_did: &str,
) -> Result<ApplicationRoutingFixture, String> {
    seed_application_routing_fixture_with_sequencer(
        pool,
        false,
        recipient_service_did,
        Some(sequencer_service_did),
    )
    .await
}

async fn seed_application_routing_fixture_with_sequencer(
    pool: &sqlx::PgPool,
    direct: bool,
    recipient_service_did: &str,
    sequencer_service_did: Option<&str>,
) -> Result<ApplicationRoutingFixture, String> {
    use base64::{engine::general_purpose::STANDARD, Engine as _};
    use chrono::SecondsFormat;
    use ed25519_dalek::Signer as _;
    use sha2::{Digest as _, Sha256};

    let at: chrono::DateTime<chrono::Utc> = sqlx::query_scalar("SELECT clock_timestamp()")
        .fetch_one(pool)
        .await
        .map_err(|error| error.to_string())?;
    let trusted =
        super::validation::TrustedRequestInstant::from_datetime(at - chrono::Duration::seconds(2))
            .map_err(|error| format!("routing fixture instant: {error:?}"))?;
    let fixture_id = uuid::Uuid::new_v4().simple().to_string();
    let sender = application_routing_fixture::FixtureIdentity::fresh_for_did(
        &format!("did:web:sender-{fixture_id}.routing.example.com"),
        b"send-routing-sender",
    )?;
    let recipient = application_routing_fixture::FixtureIdentity::fresh_for_did(
        &format!("did:web:recipient-{fixture_id}.routing.example.com"),
        b"send-routing-recipient",
    )?;
    let transport = ApplicationRoutingTransport {
        sender_did: sender.did.clone(),
        recipient_did: recipient.did.clone(),
    };
    let message_id = uuid::Uuid::new_v4();
    let mut fixture = application_routing_fixture::seed_application_routing_fixture(
        pool,
        &trusted,
        sender,
        recipient,
        direct,
        message_id,
        recipient_service_did,
        sequencer_service_did,
    )
    .await?;
    let authority = RelationshipAuthority::new(
        fixed_production_relationship_policy_config()
            .map_err(|error| format!("routing relationship policy: {error:?}"))?,
        transport,
    );
    let mut roster = vec![fixture.requester.did.clone(), fixture.fulfiller.did.clone()];
    roster.sort();
    let mut tx = pool.begin().await.map_err(|error| error.to_string())?;
    let live_allocation = allocate_projection_revision(&mut tx)
        .await
        .map_err(|error| format!("routing live allocation: {error:?}"))?;
    let fallback_allocation = allocate_projection_revision(&mut tx)
        .await
        .map_err(|error| format!("routing fallback allocation: {error:?}"))?;
    let clock = anchor_projection_clock(&mut *tx)
        .await
        .map_err(|error| format!("routing projection clock: {error}"))?;
    let live = authority
        .collect_traffic_projection(
            &clock,
            live_allocation,
            fixture.requester.did.clone(),
            roster,
        )
        .await
        .map_err(|error| format!("routing traffic collection: {error:?}"))?;
    let observation = observe_relationship_persistence(&clock);
    let fallback = live
        .export_persisted_fallback(fallback_allocation, &authority, &observation)
        .map_err(|error| format!("routing traffic sealing: {error:?}"))?;
    persist_traffic_projection(&mut tx, fallback)
        .await
        .map_err(|error| format!("routing traffic persistence: {error:?}"))?;
    tx.commit().await.map_err(|error| error.to_string())?;

    let application = fixture.application_messages.remove(0);
    let body = serde_json::json!({
        "$type": "blue.catbird.chat.defs#applicationSendBody",
        "signatureDomain": "CATBIRD-CHAT-MESSAGE\u{0000}",
        "messageId": message_id,
        "actorDid": fixture.requester.did,
        "actorDeviceId": fixture.requester.device_id,
        "keyId": fixture.requester.key_id,
        "authGeneration": 1,
        "prior": application_routing_fixture::coordinate_json(&fixture.prior),
        "signedAt": chrono::Utc::now().to_rfc3339_opts(SecondsFormat::Millis, true),
        "blobBindings": [],
        "aad": application_routing_fixture::application_routing_aad(&fixture.prior, message_id),
        "applicationMessage": {
            "framing": "mlsMessage", "contentType": "privateMessageApplication",
            "bytes": STANDARD.encode(&application),
            "sha256": STANDARD.encode(Sha256::digest(&application))
        }
    });
    let mut wrapper = serde_json::json!({"body": body, "signature": STANDARD.encode([0_u8; 64])});
    let unsigned = serde_json::to_vec(&wrapper).map_err(|error| error.to_string())?;
    let canonical = super::transcript::decode_canonical_signed_mutation(&unsigned)
        .map_err(|error| format!("routing message transcript: {error:?}"))?;
    wrapper["signature"] = serde_json::json!(STANDARD.encode(
        fixture
            .requester
            .signing_key
            .sign(canonical.transcript_bytes())
            .to_bytes(),
    ));
    let signed_bytes = serde_json::to_vec(&wrapper).map_err(|error| error.to_string())?;
    let verified = super::transcript::decode_and_verify_signed_mutation(
        &signed_bytes,
        &fixture.requester.signing_key.verifying_key().to_bytes(),
    )
    .map_err(|error| format!("verify routing application signature: {error:?}"))?;
    let super::transcript::VerifiedMutationProjection::ApplicationSend(projection) =
        verified.projection()
    else {
        return Err("routing fixture did not produce an application projection".to_owned());
    };
    let mut expected_aad = b"CATBIRD-CHAT-MLS-AAD-MESSAGE\0".to_vec();
    expected_aad.extend_from_slice(&projection.aad().canonical_dag_cbor());
    let native = super::wire::validate_private_application(
        &application,
        super::wire::MAX_PRIVATE_MESSAGE_WIRE_BYTES,
    )
    .map_err(|error| format!("verify native routing application: {error:?}"))?;
    if native.aad() != expected_aad {
        return Err("native MLS AAD differs from the signed request projection".to_owned());
    }
    Ok(ApplicationRoutingFixture {
        conversation_id: fixture.conversation_id,
        message_id,
        sender_did: fixture.requester.did,
        sender_device_id: fixture.requester.device_id,
        recipient_did: fixture.fulfiller.did,
        signed_request: wrapper,
    })
}

#[cfg(any(test, feature = "test-support"))]
pub use super::relationship_policy::AdmissionOperation;
#[cfg(any(test, feature = "test-support"))]
pub use super::transcript::decode_canonical_signed_mutation;
#[cfg(any(test, feature = "test-support"))]
pub use super::validation::ed25519_key_id;
#[cfg(any(test, feature = "test-support"))]
pub use super::validation::CanonicalTimestamp;
pub mod repository {
    pub use crate::chat_protocol::repository::delivery::AppendEntry;
    pub use crate::chat_protocol::repository::federation::*;
}
#[cfg(any(test, feature = "test-support"))]
pub async fn execute_creation_with_routing_test(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    pool: &sqlx::PgPool,
    runtime: &crate::handlers::chat::ChatRuntime,
    headers: &axum::http::HeaderMap,
    body: &[u8],
    routing: Option<super::federation_routing::ConversationRoutingIntent>,
) -> Result<(), String> {
    let admission = crate::handlers::chat::admit_signed_operation_for_test(
        pool,
        runtime,
        super::error::ChatEndpoint::CreateConversation,
        headers,
        body,
    )
    .await
    .map_err(|e| format!("admission error: {e:?}"))?;

    let prepared = super::repository::prelude::prepare_signed_operation(transaction, admission)
        .await
        .map_err(|e| format!("prelude error: {e:?}"))?;

    super::repository::creation::execute_prepared_creation(
        transaction,
        prepared,
        runtime.relationship_authority().as_ref(),
        routing,
    )
    .await
    .map_err(|e| format!("creation error: {e:?}"))?;

    Ok(())
}

#[cfg(any(test, feature = "test-support"))]
pub async fn cas_conversation_head_test(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    conversation_id: uuid::Uuid,
    expected_generation: i64,
    expected_state_version: i64,
    expected_next_entry_seq: i64,
    successor_generation: i64,
    successor_state_version: i64,
    successor_next_entry_seq: i64,
) -> Result<(), String> {
    let cas = super::repository::transition::ConversationHeadCas {
        conversation_id,
        expected_generation,
        expected_state_version,
        expected_next_entry_seq,
        successor_generation,
        successor_state_version,
        successor_next_entry_seq,
        close: None,
    };
    super::repository::transition::cas_conversation_head(transaction, &cas)
        .await
        .map_err(|e| format!("head CAS error: {e:?}"))
}
use super::relationship_policy::*;
#[cfg(any(test, feature = "test-support"))]
use super::repository::relationship::*;
#[cfg(any(test, feature = "test-support"))]
use serde_json::json;
#[cfg(any(test, feature = "test-support"))]
use sqlx::PgPool;

#[cfg(any(test, feature = "test-support"))]
#[derive(Clone, Copy)]
pub struct DeterministicTestTransport;

#[cfg(any(test, feature = "test-support"))]
#[async_trait::async_trait]
impl PublicTransport for DeterministicTestTransport {
    async fn get(&self, request: PublicGet) -> Result<PublicResponse, TransportError> {
        let path = request.url.path();
        if path.starts_with("/did:plc:") {
            let actor = path.trim_start_matches('/');
            return Ok(PublicResponse::json(
                200,
                json!({
                    "id": actor,
                    "service": [{
                        "id": format!("{actor}#atproto_pds"),
                        "type": "AtprotoPersonalDataServer",
                        "serviceEndpoint": "https://pds.example.net"
                    }]
                }),
            ));
        }
        if path == "/xrpc/com.atproto.repo.getRecord" {
            let actor = request
                .url
                .query_pairs()
                .find(|(k, _)| k == "repo")
                .map(|(_, v)| v.into_owned())
                .unwrap_or_default();
            return Ok(PublicResponse::json(
                200,
                json!({
                    "uri": format!("at://{actor}/blue.catbird.chat.declaration/self"),
                    "cid": "bafyreihdwdcefgh4dqkjv67uzcmw7ojee6xedzdetojuzjevtenxquvyku",
                    "value": {
                        "$type": "blue.catbird.chat.declaration",
                        "allowIncoming": "all",
                        "deliveryService": "did:web:chat.catbird.blue",
                        "protocolVersion": "1",
                        "createdAt": "2026-08-29T00:00:00Z"
                    }
                }),
            ));
        }
        if path == "/xrpc/app.bsky.graph.getRelationships" {
            let actor = request
                .url
                .query_pairs()
                .find(|(k, _)| k == "actor")
                .map(|(_, v)| v.into_owned())
                .unwrap_or_default();
            let others = request
                .url
                .query_pairs()
                .filter(|(k, _)| k == "others")
                .map(|(_, v)| {
                    json!({
                        "$type": "app.bsky.graph.defs#relationship",
                        "did": v,
                        "following": format!("at://{actor}/app.bsky.graph.follow/test")
                    })
                })
                .collect::<Vec<_>>();
            return Ok(PublicResponse::json(
                200,
                json!({"actor": actor, "relationships": others}),
            ));
        }
        panic!("unexpected public get: {}", request.url);
    }
}

pub async fn seed_deterministic_creation_fallback(
    pool: &PgPool,
    inviter: &str,
    mut roster: Vec<String>,
    pending_recipients: Vec<String>,
    operation: AdmissionOperation,
) -> Result<(), String> {
    let rel_authority = RelationshipAuthority::new(
        fixed_production_relationship_policy_config()
            .map_err(|e| format!("fixed config error: {e:?}"))?,
        DeterministicTestTransport,
    );
    roster.sort();
    let admission_req = AdmissionRequest {
        inviter: inviter.to_string(),
        roster,
        pending_recipients,
        operation,
    };
    let mut fallback_tx = pool
        .begin()
        .await
        .map_err(|e| format!("begin fallback tx: {e}"))?;
    let live_allocation = allocate_projection_revision(&mut fallback_tx)
        .await
        .map_err(|e| format!("allocate live revision: {e:?}"))?;
    let fallback_allocation = allocate_projection_revision(&mut fallback_tx)
        .await
        .map_err(|e| format!("allocate fallback revision: {e:?}"))?;
    // Encrypted-requests: collection and persistence observe the database clock.
    let clock = anchor_projection_clock(&mut *fallback_tx)
        .await
        .map_err(|e| format!("anchor projection clock: {e}"))?;
    let live_rel = rel_authority
        .collect_admission_projection(
            &clock,
            live_allocation,
            ProjectionOperationScope::Creation,
            admission_req,
        )
        .await
        .map_err(|e| format!("collect admission projection: {e:?}"))?;
    let observation = observe_relationship_persistence(&clock);
    let sealed_fallback = live_rel
        .export_persisted_fallback(fallback_allocation, &rel_authority, &observation)
        .map_err(|e| format!("seal fallback: {e:?}"))?;
    persist_relationship_projection(&mut fallback_tx, sealed_fallback)
        .await
        .map_err(|e| format!("persist fallback: {e:?}"))?;
    fallback_tx
        .commit()
        .await
        .map_err(|e| format!("commit fallback tx: {e}"))?;
    Ok(())
}

pub async fn seed_deterministic_pending_add_fallback(
    pool: &PgPool,
    inviter: &str,
    mut roster: Vec<String>,
    pending_recipients: Vec<String>,
) -> Result<(), String> {
    let rel_authority = RelationshipAuthority::new(
        fixed_production_relationship_policy_config()
            .map_err(|e| format!("fixed config error: {e:?}"))?,
        DeterministicTestTransport,
    );
    roster.sort();
    let admission_req = AdmissionRequest {
        inviter: inviter.to_string(),
        roster,
        pending_recipients,
        operation: AdmissionOperation::Group,
    };
    let mut fallback_tx = pool
        .begin()
        .await
        .map_err(|e| format!("begin fallback tx: {e}"))?;
    let live_allocation = allocate_projection_revision(&mut fallback_tx)
        .await
        .map_err(|e| format!("allocate live revision: {e:?}"))?;
    let fallback_allocation = allocate_projection_revision(&mut fallback_tx)
        .await
        .map_err(|e| format!("allocate fallback revision: {e:?}"))?;
    // Encrypted-requests: collection and persistence observe the database clock.
    let clock = anchor_projection_clock(&mut *fallback_tx)
        .await
        .map_err(|e| format!("anchor projection clock: {e}"))?;
    let live_rel = rel_authority
        .collect_admission_projection(
            &clock,
            live_allocation,
            ProjectionOperationScope::PendingAdd,
            admission_req,
        )
        .await
        .map_err(|e| format!("collect admission projection: {e:?}"))?;
    let observation = observe_relationship_persistence(&clock);
    let sealed_fallback = live_rel
        .export_persisted_fallback(fallback_allocation, &rel_authority, &observation)
        .map_err(|e| format!("seal fallback: {e:?}"))?;
    persist_relationship_projection(&mut fallback_tx, sealed_fallback)
        .await
        .map_err(|e| format!("persist fallback: {e:?}"))?;
    fallback_tx
        .commit()
        .await
        .map_err(|e| format!("commit fallback tx: {e}"))?;
    Ok(())
}

#[cfg(feature = "test-support")]
#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct FederationFixtureInput {
    conversation_id: uuid::Uuid,
    configured_sequencer_did: String,
    configured_sequencer_term: i64,
}

#[cfg(feature = "test-support")]
#[derive(serde::Serialize)]
#[serde(rename_all = "camelCase")]
struct CompactOutcomeOutput {
    outcome: &'static str,
    conversation_id: uuid::Uuid,
    sequencer_term: i64,
    head_seq: i64,
    digest_sha256: String,
}

#[cfg(feature = "test-support")]
pub fn with_federation_test_user_routes(
    resolver: crate::federation::DsResolver,
    config: &crate::federation::FederationConfig,
) -> Result<crate::federation::DsResolver, String> {
    if std::env::var("APP_ENV").as_deref() != Ok("test") {
        return Err("test user routing requires APP_ENV=test".to_string());
    }
    let local_user_dids = std::env::var("FEDERATION_TEST_LOCAL_USER_DIDS")
        .map_err(|_| "FEDERATION_TEST_LOCAL_USER_DIDS must be configured".to_string())?
        .split(',')
        .map(str::trim)
        .filter(|did| !did.is_empty())
        .map(str::to_owned)
        .collect::<Vec<_>>();
    if local_user_dids.is_empty() {
        return Err("FEDERATION_TEST_LOCAL_USER_DIDS must not be empty".to_string());
    }
    let local_did = config.self_did.clone();
    let local_endpoint = config.self_endpoint.clone();
    let (peer_did, peer_endpoint) = config.default_ds.clone().ok_or_else(|| {
        "test user routing requires DEFAULT_DS_DID and DEFAULT_DS_ENDPOINT".to_string()
    })?;

    Ok(
        resolver.with_user_did_resolver_hook(std::sync::Arc::new(move |user_did| {
            let (did, endpoint) = if local_user_dids.iter().any(|did| did == user_did) {
                (local_did.clone(), local_endpoint.clone())
            } else {
                (peer_did.clone(), peer_endpoint.clone())
            };
            Some(Ok(crate::federation::DsEndpoint {
                did,
                endpoint,
                supported_cipher_suites: None,
                federation_capabilities: None,
            }))
        })),
    )
}

#[cfg(feature = "test-support")]
pub async fn run_federation_fixture() -> Result<(), String> {
    let app_env = std::env::var("APP_ENV")
        .map_err(|_| "APP_ENV must be set to 'test' to run federation_fixture".to_string())?;
    if app_env != "test" {
        return Err(format!(
            "refusing to run federation_fixture outside of APP_ENV=test (found APP_ENV={app_env})"
        ));
    }

    let args: Vec<String> = std::env::args().collect();
    if args.len() != 2 {
        return Err("usage: federation_fixture <path-to-selector-json>".to_string());
    }
    let file_path = &args[1];

    use std::io::Read;
    let mut file = std::fs::File::open(file_path)
        .map_err(|e| format!("failed to open selector file '{file_path}': {e}"))?;
    let mut buffer = Vec::new();
    let bytes_read = (&mut file)
        .take(4097)
        .read_to_end(&mut buffer)
        .map_err(|e| format!("failed to read selector file '{file_path}': {e}"))?;
    if bytes_read > 4096 {
        return Err(format!(
            "selector file '{file_path}' exceeds maximum allowed size of 4096 bytes (read {bytes_read} bytes)"
        ));
    }

    let input: FederationFixtureInput = serde_json::from_slice(&buffer)
        .map_err(|e| format!("failed to parse selector JSON: {e}"))?;

    // Conversation ids minted by the server and the e2e harness are UUIDv4; a
    // nil or other-version id in a selector is a malformed fixture, not a
    // conversation, so refuse it before any database or network work.
    if input.conversation_id.get_version_num() != 4 {
        return Err("invalid bootstrap selector: conversationId must be a UUIDv4".to_string());
    }

    let selector = crate::federation::RemotePrefixBootstrapSelector::new(
        input.conversation_id,
        input.configured_sequencer_did,
        input.configured_sequencer_term,
    )
    .map_err(|e| format!("invalid bootstrap selector: {e}"))?;

    crate::auth::load_test_did_fixtures_from_env()
        .await
        .map_err(|e| format!("failed to load test did fixtures: {e}"))?;

    let pool = crate::db::init_db_default()
        .await
        .map_err(|e| format!("failed to initialize database pool: {e}"))?;

    let fed_config = crate::federation::FederationConfig::from_env();

    let http_client = reqwest::Client::builder()
        .connect_timeout(std::time::Duration::from_secs(
            fed_config.outbound_connect_timeout_secs,
        ))
        .timeout(std::time::Duration::from_secs(
            fed_config.outbound_timeout_secs,
        ))
        .user_agent("catbird-mls-ds/1.0")
        .build()
        .map_err(|e| format!("failed to build http client: {e}"))?;

    let (peer_did, peer_endpoint) = fed_config.default_ds.clone().ok_or_else(|| {
        "federation fixture requires DEFAULT_DS_DID and DEFAULT_DS_ENDPOINT".to_string()
    })?;
    if peer_did != selector.configured_sequencer_did() {
        return Err("fixture sequencer DID must match DEFAULT_DS_DID".to_string());
    }

    let resolver_peer_did = peer_did.clone();
    let resolver_peer_endpoint = peer_endpoint.clone();
    let resolver = crate::federation::DsResolver::new(
        pool.clone(),
        http_client,
        fed_config.self_did.clone(),
        fed_config.self_endpoint.clone(),
        fed_config.default_ds.clone(),
        fed_config.endpoint_cache_ttl_secs,
    )
    .with_destination_resolver_hook(std::sync::Arc::new(move |target| {
        if target != resolver_peer_did && target != resolver_peer_endpoint {
            return None;
        }

        let endpoint = resolver_peer_endpoint.clone();
        Some(Box::pin(async move {
            crate::federation::resolver::validate_and_resolve_destination(&endpoint, None).await
        }))
    }));
    let resolver = with_federation_test_user_routes(resolver, &fed_config)?;

    let outbound = crate::federation::outbound::OutboundClient::new(
        fed_config.outbound_connect_timeout_secs,
        fed_config.outbound_timeout_secs,
    );

    let signing_pem = fed_config
        .signing_key_pem
        .as_ref()
        .ok_or_else(|| "federation service auth signing key is not configured".to_string())?;

    let service_auth = crate::federation::ServiceAuthClient::from_es256_pem(
        fed_config.self_did.clone(),
        signing_pem.as_bytes(),
        None,
    )
    .map_err(|e| format!("failed to create service auth client: {e}"))?;

    let auth_sign = move |target_did: &str, method: &str| -> Result<String, String> {
        service_auth
            .sign_request(target_did, method)
            .map_err(|e| e.to_string())
    };

    let outcome = crate::federation::bootstrap::bootstrap_remote_mailbox_from_selector(
        &pool, &resolver, &outbound, &auth_sign, selector,
    )
    .await
    .map_err(|e| format!("bootstrap remote mailbox failed: {e}"))?;

    let output = match outcome {
        crate::federation::RemotePrefixApplyOutcome::Applied {
            conversation_id,
            sequencer_term,
            last_seq,
            digest_sha256,
        } => CompactOutcomeOutput {
            outcome: "applied",
            conversation_id,
            sequencer_term,
            head_seq: last_seq,
            digest_sha256: hex::encode(digest_sha256),
        },
        crate::federation::RemotePrefixApplyOutcome::ExactReplay {
            conversation_id,
            sequencer_term,
            last_seq,
            digest_sha256,
        } => CompactOutcomeOutput {
            outcome: "exactReplay",
            conversation_id,
            sequencer_term,
            head_seq: last_seq,
            digest_sha256: hex::encode(digest_sha256),
        },
        crate::federation::RemotePrefixApplyOutcome::Quarantined {
            first_mismatch_seq,
            reason,
            ..
        } => {
            return Err(format!(
                "bootstrap remote mailbox quarantined at seq {first_mismatch_seq}: {}",
                reason.as_str()
            ));
        }
    };

    let json_bytes =
        serde_json::to_string(&output).map_err(|e| format!("failed to serialize outcome: {e}"))?;
    println!("{json_bytes}");
    Ok(())
}
