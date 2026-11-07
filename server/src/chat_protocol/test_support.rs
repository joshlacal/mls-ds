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
        "sendCounter": 1,
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

/// Extended clean-slate two-member fixture exposing both devices' Ed25519 seeds/key IDs
/// and optional `I13` `archiveCommitment` binding in `applicationSendBody.aad`.
pub struct CleanSlateApplicationFixture {
    pub conversation_id: uuid::Uuid,
    pub message_id: uuid::Uuid,
    pub sender_did: String,
    pub sender_device_id: uuid::Uuid,
    pub sender_key_id: String,
    pub sender_ed25519_seed: [u8; 32],
    pub recipient_did: String,
    pub recipient_device_id: uuid::Uuid,
    pub recipient_key_id: String,
    pub recipient_ed25519_seed: [u8; 32],
    pub signed_request: serde_json::Value,
    sender_signed_requests: Vec<serde_json::Value>,
    recipient_signed_requests: Vec<serde_json::Value>,
    sender_request_index: std::sync::atomic::AtomicUsize,
    recipient_request_index: std::sync::atomic::AtomicUsize,
}

impl CleanSlateApplicationFixture {
    pub(crate) fn next_sender_signed_request(&self) -> serde_json::Value {
        let index = self
            .sender_request_index
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        self.sender_signed_requests
            .get(index)
            .expect("clean-slate sender application fixture capacity")
            .clone()
    }

    pub(crate) fn next_recipient_signed_request(&self) -> serde_json::Value {
        let index = self
            .recipient_request_index
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        self.recipient_signed_requests
            .get(index)
            .expect("clean-slate recipient application fixture capacity")
            .clone()
    }
}

pub async fn seed_clean_slate_application_fixture(
    pool: &sqlx::PgPool,
    direct: bool,
    recipient_service_did: &str,
    archive_commitment: Option<[u8; 32]>,
) -> Result<CleanSlateApplicationFixture, String> {
    seed_clean_slate_application_fixture_with_sender_home(
        pool,
        direct,
        recipient_service_did,
        archive_commitment,
        None,
    )
    .await
}

/// Seed immutable participant home routing at insertion time, retaining the
/// genuine signed membership history and native application fixture.
pub async fn seed_clean_slate_application_fixture_with_sender_home(
    pool: &sqlx::PgPool,
    direct: bool,
    recipient_service_did: &str,
    archive_commitment: Option<[u8; 32]>,
    sender_service_did: Option<&str>,
) -> Result<CleanSlateApplicationFixture, String> {
    seed_clean_slate_application_fixture_inner(
        pool,
        direct,
        recipient_service_did,
        archive_commitment,
        sender_service_did,
        None,
        true,
    )
    .await
}

/// The clean-slate fixture as a running DS serves it: no traffic fallback is pre-sealed, so
/// the sender's first send collects its relationship evidence through that DS's own
/// configured authority, as in production. A seal from this fixture's routing transport is
/// another source's evidence, which a DS with a different authority refuses to hydrate.
/// `sender_service_did` routes the sender home as
/// [`seed_clean_slate_application_fixture_with_sender_home`] does.
pub async fn seed_clean_slate_application_fixture_unsealed(
    pool: &sqlx::PgPool,
    direct: bool,
    recipient_service_did: &str,
    archive_commitment: Option<[u8; 32]>,
    sender_service_did: Option<&str>,
) -> Result<CleanSlateApplicationFixture, String> {
    seed_clean_slate_application_fixture_inner(
        pool,
        direct,
        recipient_service_did,
        archive_commitment,
        sender_service_did,
        None,
        false,
    )
    .await
}

/// Genuine remote group mirror, exposing its actor keys for signed relay tests.
pub async fn seed_remote_clean_slate_application_fixture(
    pool: &sqlx::PgPool,
    recipient_service_did: &str,
    sequencer_service_did: &str,
    archive_commitment: Option<[u8; 32]>,
) -> Result<CleanSlateApplicationFixture, String> {
    seed_clean_slate_application_fixture_inner(
        pool,
        false,
        recipient_service_did,
        archive_commitment,
        None,
        Some(sequencer_service_did),
        true,
    )
    .await
}

async fn seed_clean_slate_application_fixture_inner(
    pool: &sqlx::PgPool,
    direct: bool,
    recipient_service_did: &str,
    archive_commitment: Option<[u8; 32]>,
    sender_service_did: Option<&str>,
    sequencer_service_did: Option<&str>,
    seal_traffic: bool,
) -> Result<CleanSlateApplicationFixture, String> {
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
            .map_err(|error| format!("clean-slate fixture instant: {error:?}"))?;
    let fixture_id = uuid::Uuid::new_v4().simple().to_string();
    let sender = application_routing_fixture::FixtureIdentity::fresh_for_did(
        &format!("did:web:sender-{fixture_id}.routing.example.com"),
        b"clean-slate-sender",
    )?;
    let recipient = application_routing_fixture::FixtureIdentity::fresh_for_did(
        &format!("did:web:recipient-{fixture_id}.routing.example.com"),
        b"clean-slate-recipient",
    )?;
    let transport = ApplicationRoutingTransport {
        sender_did: sender.did.clone(),
        recipient_did: recipient.did.clone(),
    };
    let message_id = uuid::Uuid::new_v4();
    let mut fixture =
        application_routing_fixture::seed_application_routing_fixture_with_commitment(
            pool,
            &trusted,
            sender,
            recipient,
            direct,
            message_id,
            archive_commitment,
            recipient_service_did,
            sequencer_service_did,
            sender_service_did,
        )
        .await?;
    if seal_traffic {
        let authority = RelationshipAuthority::new(
            fixed_production_relationship_policy_config()
                .map_err(|error| format!("clean-slate relationship policy: {error:?}"))?,
            transport,
        );
        let mut roster = vec![fixture.requester.did.clone(), fixture.fulfiller.did.clone()];
        roster.sort();
        let mut tx = pool.begin().await.map_err(|error| error.to_string())?;
        let live_allocation = allocate_projection_revision(&mut tx)
            .await
            .map_err(|error| format!("clean-slate live allocation: {error:?}"))?;
        let fallback_allocation = allocate_projection_revision(&mut tx)
            .await
            .map_err(|error| format!("clean-slate fallback allocation: {error:?}"))?;
        let clock = anchor_projection_clock(&mut *tx)
            .await
            .map_err(|error| format!("clean-slate projection clock: {error}"))?;
        let live = authority
            .collect_traffic_projection(
                &clock,
                live_allocation,
                fixture.requester.did.clone(),
                roster,
            )
            .await
            .map_err(|error| format!("clean-slate traffic collection: {error:?}"))?;
        let observation = observe_relationship_persistence(&clock);
        let fallback = live
            .export_persisted_fallback(fallback_allocation, &authority, &observation)
            .map_err(|error| format!("clean-slate traffic sealing: {error:?}"))?;
        persist_traffic_projection(&mut tx, fallback)
            .await
            .map_err(|error| format!("clean-slate traffic persistence: {error:?}"))?;
        tx.commit().await.map_err(|error| error.to_string())?;
    }

    let aad = match archive_commitment.as_ref() {
        Some(commitment) => application_routing_fixture::application_routing_aad_with_commitment(
            &fixture.prior,
            message_id,
            commitment,
            &fixture.requester,
        ),
        None => application_routing_fixture::application_routing_aad(&fixture.prior, message_id),
    };
    let application = fixture.application_messages.remove(0);
    let body = serde_json::json!({
        "$type": "blue.catbird.chat.defs#applicationSendBody",
        "signatureDomain": "CATBIRD-CHAT-MESSAGE\u{0000}",
        "messageId": message_id,
        "actorDid": fixture.requester.did,
        "actorDeviceId": fixture.requester.device_id,
        "keyId": fixture.requester.key_id,
        "authGeneration": 1,
        "sendCounter": 1,
        "prior": application_routing_fixture::coordinate_json(&fixture.prior),
        "signedAt": chrono::Utc::now().to_rfc3339_opts(SecondsFormat::Millis, true),
        "blobBindings": [],
        "aad": aad,
        "applicationMessage": {
            "framing": "mlsMessage",
            "contentType": "privateMessageApplication",
            "bytes": STANDARD.encode(&application),
            "sha256": STANDARD.encode(Sha256::digest(&application)),
        }
    });
    let wrapper = sign_mutation_json_for_test(&body, &fixture.requester.signing_key)?;
    let signed_bytes = serde_json::to_vec(&wrapper).map_err(|error| error.to_string())?;
    let verified = super::transcript::decode_and_verify_signed_mutation(
        &signed_bytes,
        &fixture.requester.signing_key.verifying_key().to_bytes(),
    )
    .map_err(|error| format!("verify clean-slate application signature: {error:?}"))?;
    let super::transcript::VerifiedMutationProjection::ApplicationSend(projection) =
        verified.projection()
    else {
        return Err("clean-slate fixture did not produce an application projection".to_owned());
    };
    let mut expected_aad = b"CATBIRD-CHAT-MLS-AAD-MESSAGE\0".to_vec();
    expected_aad.extend_from_slice(&projection.aad().canonical_dag_cbor());
    let native = super::wire::validate_private_application(
        &application,
        super::wire::MAX_PRIVATE_MESSAGE_WIRE_BYTES,
    )
    .map_err(|error| format!("verify native clean-slate application: {error:?}"))?;
    if native.aad() != expected_aad {
        return Err(
            "native MLS AAD differs from the clean-slate signed request projection".to_owned(),
        );
    }
    // Each device's frames were encrypted in order: the sender's main
    // application first, so its supplemental counters start at 2.
    let supplemental_requests = |identity: &application_routing_fixture::FixtureIdentity,
                                 messages: &[(uuid::Uuid, Vec<u8>)],
                                 first_counter: usize|
     -> Result<Vec<serde_json::Value>, String> {
        if messages.is_empty() {
            return Ok(Vec::new());
        }
        let commitment = archive_commitment
            .as_ref()
            .ok_or("supplemental application fixtures require an archive commitment")?;
        messages
            .iter()
            .enumerate()
            .map(|(index, (message_id, application))| {
                let body = serde_json::json!({
                    "$type": "blue.catbird.chat.defs#applicationSendBody",
                    "signatureDomain": "CATBIRD-CHAT-MESSAGE\u{0000}",
                    "messageId": message_id,
                    "actorDid": identity.did,
                    "actorDeviceId": identity.device_id,
                    "keyId": identity.key_id,
                    "authGeneration": 1,
                    "sendCounter": first_counter + index,
                    "prior": application_routing_fixture::coordinate_json(&fixture.prior),
                    "signedAt": chrono::Utc::now()
                        .to_rfc3339_opts(SecondsFormat::Millis, true),
                    "blobBindings": [],
                    "aad": application_routing_fixture::application_routing_aad_with_commitment(
                        &fixture.prior,
                        *message_id,
                        commitment,
                        identity,
                    ),
                    "applicationMessage": {
                        "framing": "mlsMessage",
                        "contentType": "privateMessageApplication",
                        "bytes": STANDARD.encode(application),
                        "sha256": STANDARD.encode(Sha256::digest(application)),
                    },
                });
                sign_mutation_json_for_test(&body, &identity.signing_key)
            })
            .collect()
    };
    let sender_signed_requests = supplemental_requests(
        &fixture.requester,
        &fixture.supplemental_requester_application_messages,
        2,
    )?;
    let recipient_signed_requests = supplemental_requests(
        &fixture.fulfiller,
        &fixture.supplemental_fulfiller_application_messages,
        1,
    )?;

    Ok(CleanSlateApplicationFixture {
        conversation_id: fixture.conversation_id,
        message_id,
        sender_did: fixture.requester.did,
        sender_device_id: fixture.requester.device_id,
        sender_key_id: fixture.requester.key_id,
        sender_ed25519_seed: fixture.requester.signing_key.to_bytes(),
        recipient_did: fixture.fulfiller.did,
        recipient_device_id: fixture.fulfiller.device_id,
        recipient_key_id: fixture.fulfiller.key_id,
        recipient_ed25519_seed: fixture.fulfiller.signing_key.to_bytes(),
        signed_request: wrapper,
        sender_signed_requests,
        recipient_signed_requests,
        sender_request_index: std::sync::atomic::AtomicUsize::new(0),
        recipient_request_index: std::sync::atomic::AtomicUsize::new(0),
    })
}

/// Sign any canonical `blue.catbird.chat.defs#*Body` JSON object with an Ed25519 device key.
pub fn sign_mutation_json_for_test(
    body: &serde_json::Value,
    signing_key: &ed25519_dalek::SigningKey,
) -> Result<serde_json::Value, String> {
    use base64::{engine::general_purpose::STANDARD, Engine as _};
    use ed25519_dalek::Signer as _;

    let mut wrapper = serde_json::json!({
        "body": body,
        "signature": STANDARD.encode([0_u8; 64]),
    });
    let unsigned = serde_json::to_vec(&wrapper).map_err(|e| e.to_string())?;
    let canonical = super::transcript::decode_canonical_signed_mutation(&unsigned)
        .map_err(|e| format!("decode canonical signed mutation: {e:?}"))?;
    let sig = signing_key.sign(canonical.transcript_bytes());
    wrapper["signature"] = serde_json::json!(STANDARD.encode(sig.to_bytes()));
    Ok(wrapper)
}
pub(crate) use super::state_machine::direct_request::original_sender_attestation_json_for_test;

/// Seeded overdue `C33` published direct request (`created_at <= now - 31 days`) satisfying all
/// PostgreSQL deferred publication, state-output, key-package, and lifecycle-reserve triggers.
pub struct CleanSlateExpiredDirectRequestFixture {
    pub request_id: uuid::Uuid,
    pub conversation_id: uuid::Uuid,
    pub actor_did: String,
    pub actor_device_id: uuid::Uuid,
    pub actor_ed25519_seed: [u8; 32],
    pub recipient_did: String,
}

pub async fn seed_clean_slate_expired_direct_request_fixture(
    pool: &sqlx::PgPool,
    signer: &super::repository::direct_request_receipts::DirectRequestReceiptSigner,
) -> Result<CleanSlateExpiredDirectRequestFixture, String> {
    let actor = application_routing_fixture::FixtureIdentity::fresh(b"c33-expired-actor")?;
    let recipient = application_routing_fixture::FixtureIdentity::fresh(b"c33-expired-recipient")?;
    seed_published_direct_request(pool, signer, &actor, &recipient, chrono::Duration::days(31))
        .await
        .map(|(fixture, _)| fixture)
}

/// A live published `C33` request at its coordinator from `actor_did`, its
/// active local sender, to the pending `recipient_did`, with both devices'
/// signing keys and the conversation's current coordinate. Its publication is
/// not genuinely signed, so the state machine cannot hydrate it.
pub struct CleanSlatePendingDirectRequestFixture {
    pub request_id: uuid::Uuid,
    pub conversation_id: uuid::Uuid,
    pub actor_did: String,
    pub actor_device_id: uuid::Uuid,
    pub actor_key_id: String,
    pub actor_ed25519_seed: [u8; 32],
    pub recipient_did: String,
    pub recipient_device_id: uuid::Uuid,
    pub recipient_key_id: String,
    pub recipient_ed25519_seed: [u8; 32],
    pub prior: serde_json::Value,
}

pub async fn seed_clean_slate_pending_direct_request_fixture(
    pool: &sqlx::PgPool,
    signer: &super::repository::direct_request_receipts::DirectRequestReceiptSigner,
    actor_did: &str,
    recipient_did: &str,
) -> Result<CleanSlatePendingDirectRequestFixture, String> {
    let actor = application_routing_fixture::FixtureIdentity::fresh_for_did(
        actor_did,
        b"c33-pending-actor",
    )?;
    let recipient = application_routing_fixture::FixtureIdentity::fresh_for_did(
        recipient_did,
        b"c33-pending-recipient",
    )?;
    let (published, prior) = seed_published_direct_request(
        pool,
        signer,
        &actor,
        &recipient,
        chrono::Duration::minutes(1),
    )
    .await?;
    Ok(CleanSlatePendingDirectRequestFixture {
        request_id: published.request_id,
        conversation_id: published.conversation_id,
        actor_did: published.actor_did,
        actor_device_id: actor.device_id,
        actor_key_id: actor.key_id,
        actor_ed25519_seed: actor.signing_key.to_bytes(),
        recipient_did: published.recipient_did,
        recipient_device_id: recipient.device_id,
        recipient_key_id: recipient.key_id,
        recipient_ed25519_seed: recipient.signing_key.to_bytes(),
        prior,
    })
}

/// `actor`'s published request to `recipient`, created `age` ago, and the
/// conversation's current coordinate.
async fn seed_published_direct_request(
    pool: &sqlx::PgPool,
    signer: &super::repository::direct_request_receipts::DirectRequestReceiptSigner,
    actor: &application_routing_fixture::FixtureIdentity,
    recipient: &application_routing_fixture::FixtureIdentity,
    age: chrono::Duration,
) -> Result<(CleanSlateExpiredDirectRequestFixture, serde_json::Value), String> {
    use base64::{engine::general_purpose::STANDARD, Engine as _};
    use chrono::{Duration, SecondsFormat};
    use sha2::{Digest as _, Sha256};
    use uuid::Uuid;

    signer.validate_and_retain_keys(pool).await?;

    let now_db: chrono::DateTime<chrono::Utc> =
        sqlx::query_scalar("SELECT date_trunc('milliseconds', clock_timestamp())")
            .fetch_one(pool)
            .await
            .map_err(|e| e.to_string())?;
    let created_at = now_db - age;
    let prepared_at = created_at - Duration::seconds(10);
    let lease_expires_at = prepared_at + Duration::seconds(60);
    let import_until = created_at + Duration::days(30);
    let kp_not_before = created_at - Duration::minutes(5);
    let kp_not_after = created_at + Duration::days(36);

    let trusted_past = super::validation::TrustedRequestInstant::from_datetime(prepared_at)
        .map_err(|e| format!("trusted instant: {e:?}"))?;
    application_routing_fixture::seed_identity(pool, &actor, &trusted_past).await?;
    application_routing_fixture::seed_identity(pool, &recipient, &trusted_past).await?;

    let request_id = Uuid::new_v4();
    let conversation_id = Uuid::new_v4();
    let first_message_id = Uuid::new_v4();
    let entry_id = Uuid::new_v4();
    let metadata_snapshot_id = Uuid::new_v4();
    let grant_id = Uuid::new_v4();
    let actor_participant_id = Uuid::new_v4();
    let recipient_participant_id = Uuid::new_v4();
    let actor_leaf_id = Uuid::new_v4();
    let recipient_leaf_id = Uuid::new_v4();

    let (
        genesis_info,
        final_state,
        tree_bytes,
        tree_sha256,
        final_info,
        welcome_bytes,
        initial_ct,
        kp_ref,
        kp_wrapper,
        kp_init_key,
    ) = application_routing_fixture::build_c33_two_leaf_artifacts(
        &actor,
        &recipient,
        conversation_id,
        request_id,
        created_at,
    )?;

    let context_hash = [0x31_u8; 32];
    let prepare_digest = [0x32_u8; 32];
    let preparation_digest = [0x33_u8; 32];
    let grant_digest = [0x34_u8; 32];
    let metadata_nonce = [0x52_u8; 12];
    let metadata_ciphertext = [0x5A_u8; 16];
    let metadata_json_obj = serde_json::json!({
        "metadataVersion": 1,
        "nonce": STANDARD.encode(metadata_nonce),
        "ciphertext": STANDARD.encode(metadata_ciphertext),
    });
    let metadata_bytes = serde_json::to_vec(&metadata_json_obj).map_err(|e| e.to_string())?;
    let archive_commitment: [u8; 32] = Sha256::digest(&initial_ct).into();

    let pub_body = serde_json::json!({
        "requestId": request_id.to_string(),
        "conversationId": conversation_id.to_string(),
        "firstMessageId": first_message_id.to_string(),
        "actorDid": actor.did,
        "recipientDid": recipient.did,
        "actorDeviceId": actor.device_id.to_string(),
        "keyId": actor.key_id,
        "authGeneration": 1_i64,
        "contextHash": STANDARD.encode(context_hash),
        "preparationDigest": STANDARD.encode(preparation_digest),
        "archiveCommitment": STANDARD.encode(archive_commitment),
        "originalSenderAttestation": original_sender_attestation_json_for_test(
            &actor.did,
            actor.device_id,
            &actor.signing_key,
            &conversation_id.to_string(),
            &first_message_id.to_string(),
            &archive_commitment,
        ),
        "importUntil": import_until.to_rfc3339_opts(SecondsFormat::Millis, true),
        "artifacts": {
            "finalGroupInfo": {
                "bytes": STANDARD.encode(&final_info),
            },
            "welcome": {
                "opaqueWelcome": STANDARD.encode(&welcome_bytes),
            },
            "initialCiphertext": STANDARD.encode(&initial_ct),
            "metadataSnapshot": metadata_json_obj,
        },
    });
    let signed_pub_val = serde_json::json!({
        "body": pub_body,
        "signature": STANDARD.encode([0x77_u8; 64]),
    });
    let signed_publication = serde_json::to_vec(&signed_pub_val).map_err(|e| e.to_string())?;
    let unsigned_body_bytes =
        serde_json::to_vec(&signed_pub_val["body"]).map_err(|e| e.to_string())?;
    let publication_digest: [u8; 32] = Sha256::digest(&unsigned_body_bytes).into();
    let request_entry_val = serde_json::json!({
        "$type": "blue.catbird.chat.defs#directRequestEntry",
        "entryId": entry_id.to_string(),
        "conversationId": conversation_id.to_string(),
        "seq": 1_i64,
        "signedRequest": signed_pub_val,
        "receivedAt": created_at.to_rfc3339_opts(SecondsFormat::Millis, true),
    });
    let request_entry = serde_json::to_vec(&request_entry_val).map_err(|e| e.to_string())?;
    let request_entry_sha256: [u8; 32] = Sha256::digest(&request_entry).into();
    let outer_fp: [u8; 32] = Sha256::digest(&request_entry).into();
    let terminal_response = b"{\"status\":\"published\"}".to_vec();
    let terminal_response_sha256: [u8; 32] = Sha256::digest(&terminal_response).into();
    let provenance_bytes = b"{\"grant\":\"ok\"}".to_vec();
    let provenance_sha256: [u8; 32] = Sha256::digest(&provenance_bytes).into();
    let server_fields = serde_json::to_vec(&serde_json::json!({
        "entryId": entry_id.to_string(),
        "conversationId": conversation_id.to_string(),
        "seq": 1_i64,
        "receivedAt": created_at.to_rfc3339_opts(SecondsFormat::Millis, true),
    }))
    .map_err(|e| e.to_string())?;

    let (low_did, high_did) = if actor.did < recipient.did {
        (&actor.did, &recipient.did)
    } else {
        (&recipient.did, &actor.did)
    };

    let mut tx = pool.begin().await.map_err(|e| e.to_string())?;

    sqlx::query(
        "INSERT INTO chat.key_packages( \
             key_package_ref, wrapper_bytes, wrapper_sha256, init_key, \
             owner_did, owner_device_id, owner_key_id, owner_auth_generation, \
             not_before, not_after, status, terminal_transition_id, terminal_at, \
             created_at, usage_scope \
         ) VALUES ($1,$2,$3,$4,$5,$6,$7,1,$8,$9,'consumed',$10,$11,$12,'direct-request')",
    )
    .bind(kp_ref.as_slice())
    .bind(&kp_wrapper)
    .bind(Sha256::digest(&kp_wrapper).as_slice())
    .bind(&kp_init_key)
    .bind(&recipient.did)
    .bind(recipient.device_id)
    .bind(&recipient.key_id)
    .bind(kp_not_before)
    .bind(kp_not_after)
    .bind(request_id)
    .bind(created_at)
    .bind(prepared_at)
    .execute(&mut *tx)
    .await
    .map_err(|e| format!("insert c33 key_package: {e}"))?;

    sqlx::query(
        "INSERT INTO chat.direct_request_grants( \
             grant_id, revision, owner_did, owner_device_id, owner_key_id, auth_generation, \
             capability_revision, key_package_ref, usage_scope, purpose, protocol_version, \
             profile, signed_grant, grant_digest, expires_at, created_at \
         ) VALUES ($1,1,$2,$3,$4,1,1,$5,'direct-request','direct-request-bootstrap','2','xwing',$6,$7,$8,$9)",
    )
    .bind(grant_id)
    .bind(&recipient.did)
    .bind(recipient.device_id)
    .bind(&recipient.key_id)
    .bind(kp_ref.as_slice())
    .bind(b"{\"grant\":true}".as_slice())
    .bind(grant_digest.as_slice())
    .bind(kp_not_after)
    .bind(prepared_at)
    .execute(&mut *tx)
    .await
    .map_err(|e| format!("insert c33 grant: {e}"))?;

    sqlx::query(
        "INSERT INTO chat.direct_request_attempts( \
             request_id, actor_did, actor_device_id, actor_key_id, actor_auth_generation, \
             recipient_did, prepare_digest, status, prepare_response, selected_digest, \
             prepared_at, lease_expires_at, terminal_at, terminal_response, \
             terminal_response_sha256, publication_digest, reserved_bytes, created_at \
         ) VALUES ($1,$2,$3,$4,1,$5,$6,'published',$7,$8,$9,$10,$11,$12,$13,$14,16000000,$9)",
    )
    .bind(request_id)
    .bind(&actor.did)
    .bind(actor.device_id)
    .bind(&actor.key_id)
    .bind(&recipient.did)
    .bind(prepare_digest.as_slice())
    .bind(b"{\"prepared\":true}".as_slice())
    .bind(preparation_digest.as_slice())
    .bind(prepared_at)
    .bind(lease_expires_at)
    .bind(created_at)
    .bind(&terminal_response)
    .bind(terminal_response_sha256.as_slice())
    .bind(publication_digest.as_slice())
    .execute(&mut *tx)
    .await
    .map_err(|e| format!("insert c33 attempt: {e}"))?;

    sqlx::query(
        "INSERT INTO chat.direct_request_retained_charges( \
             request_id, charged_bytes, model_version, recorded_at \
         ) VALUES ($1, 16000000, 1, $2)",
    )
    .bind(request_id)
    .bind(created_at)
    .execute(&mut *tx)
    .await
    .map_err(|e| format!("insert c33 retained_charge: {e}"))?;

    sqlx::query(
        "UPDATE chat.direct_request_budget SET retained_bytes = retained_bytes + 16000000 WHERE singleton",
    )
    .execute(&mut *tx)
    .await
    .map_err(|e| format!("update c33 budget: {e}"))?;

    sqlx::query(
        "INSERT INTO chat.direct_request_selected_devices( \
             request_id, owner_did, owner_device_id, owner_key_id, auth_generation, \
             grant_id, grant_digest, capability_revision, key_package_ref \
         ) VALUES ($1,$2,$3,$4,1,$5,$6,1,$7)",
    )
    .bind(request_id)
    .bind(&recipient.did)
    .bind(recipient.device_id)
    .bind(&recipient.key_id)
    .bind(grant_id)
    .bind(grant_digest.as_slice())
    .bind(kp_ref.as_slice())
    .execute(&mut *tx)
    .await
    .map_err(|e| format!("insert c33 selected_device: {e}"))?;

    sqlx::query(
        "INSERT INTO chat.conversations( \
             conversation_id, kind, lifecycle, current_generation, current_state_version, \
             next_entry_seq, direct_did_low, direct_did_high, created_at, protocol_version \
         ) VALUES ($1,'direct','active',0,1,2,$2,$3,$4,'2')",
    )
    .bind(conversation_id)
    .bind(low_did)
    .bind(high_did)
    .bind(created_at)
    .execute(&mut *tx)
    .await
    .map_err(|e| format!("insert c33 conversation: {e}"))?;

    sqlx::query(
        "INSERT INTO chat.generations( \
             conversation_id, generation, group_id, lifecycle, genesis_group_info_bytes, \
             genesis_group_info_sha256, current_state_version, activated_seq, activated_at \
         ) VALUES ($1,0,$2,'active',$3,$4,1,1,$5)",
    )
    .bind(conversation_id)
    .bind(final_state.coordinate().group_id().as_slice())
    .bind(&genesis_info)
    .bind(Sha256::digest(&genesis_info).as_slice())
    .bind(created_at)
    .execute(&mut *tx)
    .await
    .map_err(|e| format!("insert c33 generation: {e}"))?;

    super::repository::transition::register_conversation_space_if_migrated(
        &mut *tx,
        conversation_id,
        0,
        created_at,
        crate::identity::service_did_base_opt().as_deref(),
    )
    .await
    .map_err(|e| format!("register c33 space: {e}"))?;

    sqlx::query(
        "INSERT INTO chat.generation_states( \
             conversation_id, generation, state_version, group_id, epoch, group_context_hash, \
             confirmation_tag, lifecycle, state_kind, producing_transition_id, \
             public_snapshot_bytes, snapshot_sha256, tree_summary_bytes, tree_summary_sha256, \
             leaf_count, created_at \
         ) VALUES ($1,0,1,$2,1,$3,$4,'active','directRequestPublication',$5,$6,$7,$8,$9,2,$10)",
    )
    .bind(conversation_id)
    .bind(final_state.coordinate().group_id().as_slice())
    .bind(final_state.coordinate().group_context_hash().as_slice())
    .bind(final_state.coordinate().confirmation_tag().as_slice())
    .bind(request_id)
    .bind(final_state.snapshot())
    .bind(final_state.snapshot_sha256().as_slice())
    .bind(&tree_bytes)
    .bind(&tree_sha256)
    .bind(created_at)
    .execute(&mut *tx)
    .await
    .map_err(|e| format!("insert c33 generation_state: {e}"))?;

    sqlx::query(
        "INSERT INTO chat.transitions( \
             transition_id, conversation_id, kind, actor_did, actor_device_id, actor_key_id, \
             actor_auth_generation, actor_role, actor_device_status, signed_request_bytes, \
             unsigned_projection_bytes, signing_transcript_bytes, request_digest, signature, \
             next_generation, next_state_version, metadata_snapshot_id, entry_seq, accepted_at \
         ) VALUES ($1,$2,'directRequestPublication',$3,$4,$5,1,'admin','active',$6,$7,$8,$9,$10,0,1,$11,1,$12)",
    )
    .bind(request_id)
    .bind(conversation_id)
    .bind(&actor.did)
    .bind(actor.device_id)
    .bind(&actor.key_id)
    .bind(&signed_publication)
    .bind(&unsigned_body_bytes)
    .bind(&unsigned_body_bytes)
    .bind(publication_digest.as_slice())
    .bind([0x77_u8; 64].as_slice())
    .bind(metadata_snapshot_id)
    .bind(created_at)
    .execute(&mut *tx)
    .await
    .map_err(|e| format!("insert c33 transition: {e}"))?;

    sqlx::query(
        "INSERT INTO chat.entries( \
             conversation_id, seq, entry_id, entry_kind, accepted_payload_bytes, \
             accepted_payload_sha256, signed_request_bytes, request_digest, signature, \
             server_fields_bytes, outer_entry_fingerprint, actor_did, actor_device_id, \
             actor_key_id, actor_auth_generation, generation, state_version, transition_id, received_at \
         ) VALUES ($1,1,$2,'blue.catbird.chat.defs#directRequestEntry',$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,1,0,1,$13,$14)",
    )
    .bind(conversation_id)
    .bind(entry_id)
    .bind(&request_entry)
    .bind(request_entry_sha256.as_slice())
    .bind(&signed_publication)
    .bind(publication_digest.as_slice())
    .bind([0x77_u8; 64].as_slice())
    .bind(&server_fields)
    .bind(outer_fp.as_slice())
    .bind(&actor.did)
    .bind(actor.device_id)
    .bind(&actor.key_id)
    .bind(request_id)
    .bind(created_at)
    .execute(&mut *tx)
    .await
    .map_err(|e| format!("insert c33 entry: {e}"))?;

    sqlx::query(
        "INSERT INTO chat.metadata_snapshots( \
             metadata_snapshot_id, conversation_id, generation, state_version, group_id, epoch, \
             group_context_hash, confirmation_tag, producing_transition_id, origin_transition_id, \
             metadata_version, nonce, ciphertext, ciphertext_sha256, ciphertext_size, \
             author_did, author_device_id, author_key_id, author_public_key, \
             author_auth_generation, author_origin_seq, author_role, author_device_status, created_at \
         ) VALUES ($1,$2,0,1,$3,1,$4,$5,$6,$6,1,$7,$8,$9,16,$10,$11,$12,$13,1,1,'admin','active',$14)",
    )
    .bind(metadata_snapshot_id)
    .bind(conversation_id)
    .bind(final_state.coordinate().group_id().as_slice())
    .bind(final_state.coordinate().group_context_hash().as_slice())
    .bind(final_state.coordinate().confirmation_tag().as_slice())
    .bind(request_id)
    .bind(metadata_nonce.as_slice())
    .bind(metadata_ciphertext.as_slice())
    .bind(Sha256::digest(metadata_ciphertext).as_slice())
    .bind(&actor.did)
    .bind(actor.device_id)
    .bind(&actor.key_id)
    .bind(actor.signing_public_key().as_slice())
    .bind(created_at)
    .execute(&mut *tx)
    .await
    .map_err(|e| format!("insert c33 metadata: {e}"))?;

    sqlx::query(
        "INSERT INTO chat.participants( \
             participant_period_id, conversation_id, user_did, status, role, role_transition_id, \
             role_changed_at, created_by_did, created_by_device_id, current_membership, created_at \
         ) VALUES ($1,$2,$3,'active','admin',$4,$5,$3,$6,true,$5)",
    )
    .bind(actor_participant_id)
    .bind(conversation_id)
    .bind(&actor.did)
    .bind(request_id)
    .bind(created_at)
    .bind(actor.device_id)
    .execute(&mut *tx)
    .await
    .map_err(|e| format!("insert c33 actor participant: {e}"))?;

    sqlx::query(
        "INSERT INTO chat.participants( \
             participant_period_id, conversation_id, user_did, status, role, role_transition_id, \
             role_changed_at, created_by_did, created_by_device_id, invitation_transition_id, \
             invitation_entry_id, invited_at, current_membership, created_at \
         ) VALUES ($1,$2,$3,'pending','admin',$4,$5,$6,$7,$4,$8,$5,true,$5)",
    )
    .bind(recipient_participant_id)
    .bind(conversation_id)
    .bind(&recipient.did)
    .bind(request_id)
    .bind(created_at)
    .bind(&actor.did)
    .bind(actor.device_id)
    .bind(entry_id)
    .execute(&mut *tx)
    .await
    .map_err(|e| format!("insert c33 recipient participant: {e}"))?;

    sqlx::query(
        "INSERT INTO chat.direct_request_publications( \
             request_id, conversation_id, generation, state_version, first_message_id, \
             actor_did, actor_device_id, actor_key_id, recipient_did, context_hash, \
             preparation_digest, publication_digest, signed_publication, request_entry, \
             request_entry_sha256, final_group_info, final_group_info_sha256, full_welcome, \
             full_welcome_sha256, initial_ciphertext, initial_ciphertext_sha256, \
             metadata_snapshot, metadata_snapshot_sha256, import_until, created_at, actor_auth_generation \
         ) VALUES ($1,$2,0,1,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21,$22,$23,1)",
    )
    .bind(request_id)
    .bind(conversation_id)
    .bind(first_message_id)
    .bind(&actor.did)
    .bind(actor.device_id)
    .bind(&actor.key_id)
    .bind(&recipient.did)
    .bind(context_hash.as_slice())
    .bind(preparation_digest.as_slice())
    .bind(publication_digest.as_slice())
    .bind(&signed_publication)
    .bind(&request_entry)
    .bind(request_entry_sha256.as_slice())
    .bind(&final_info)
    .bind(Sha256::digest(&final_info).as_slice())
    .bind(&welcome_bytes)
    .bind(Sha256::digest(&welcome_bytes).as_slice())
    .bind(&initial_ct)
    .bind(Sha256::digest(&initial_ct).as_slice())
    .bind(&metadata_bytes)
    .bind(Sha256::digest(&metadata_bytes).as_slice())
    .bind(import_until)
    .bind(created_at)
    .execute(&mut *tx)
    .await
    .map_err(|e| format!("insert c33 publication: {e}"))?;

    sqlx::query(
        "INSERT INTO chat.direct_request_lifecycle_reserves( \
             request_id, decision_bytes, welcome_bytes_per_delivery, delivery_count \
         ) VALUES ($1, 8388608, 524288, 1)",
    )
    .bind(request_id)
    .execute(&mut *tx)
    .await
    .map_err(|e| format!("insert c33 lifecycle_reserve: {e}"))?;

    let leaves = final_state.binding().tree_summary().leaves();
    let actor_leaf = leaves
        .iter()
        .find(|l| l.basic_credential() == format!("{}#{}", actor.did, actor.device_id).as_bytes())
        .ok_or_else(|| "missing actor leaf in c33 final_state".to_owned())?;
    let recipient_leaf = leaves
        .iter()
        .find(|l| {
            l.basic_credential() == format!("{}#{}", recipient.did, recipient.device_id).as_bytes()
        })
        .ok_or_else(|| "missing recipient leaf in c33 final_state".to_owned())?;

    sqlx::query(
        "INSERT INTO chat.member_devices( \
             leaf_period_id, participant_period_id, conversation_id, generation, user_did, \
             device_id, leaf_index, basic_credential, leaf_signature_key, leaf_key_id, \
             leaf_auth_generation, origin, join_key_package_ref, joined_state_version, \
             joined_transition_id, joined_seq, active, created_at \
         ) VALUES ($1,$2,$3,0,$4,$5,$6,$7,$8,$9,1,'genesis',NULL,1,$10,1,true,$11)",
    )
    .bind(actor_leaf_id)
    .bind(actor_participant_id)
    .bind(conversation_id)
    .bind(&actor.did)
    .bind(actor.device_id)
    .bind(actor_leaf.leaf_index() as i64)
    .bind(actor_leaf.basic_credential())
    .bind(actor_leaf.signature_key())
    .bind(&actor.key_id)
    .bind(request_id)
    .bind(created_at)
    .execute(&mut *tx)
    .await
    .map_err(|e| format!("insert c33 actor member_device: {e}"))?;

    sqlx::query(
        "INSERT INTO chat.member_devices( \
             leaf_period_id, participant_period_id, conversation_id, generation, user_did, \
             device_id, leaf_index, basic_credential, leaf_signature_key, leaf_key_id, \
             leaf_auth_generation, origin, join_key_package_ref, joined_state_version, \
             joined_transition_id, joined_seq, active, created_at \
         ) VALUES ($1,$2,$3,0,$4,$5,$6,$7,$8,$9,1,'keyPackage',$10,1,$11,1,true,$12)",
    )
    .bind(recipient_leaf_id)
    .bind(recipient_participant_id)
    .bind(conversation_id)
    .bind(&recipient.did)
    .bind(recipient.device_id)
    .bind(recipient_leaf.leaf_index() as i64)
    .bind(recipient_leaf.basic_credential())
    .bind(recipient_leaf.signature_key())
    .bind(&recipient.key_id)
    .bind(kp_ref.as_slice())
    .bind(request_id)
    .bind(created_at)
    .execute(&mut *tx)
    .await
    .map_err(|e| format!("insert c33 recipient member_device: {e}"))?;

    for (did, dev_id, leaf_id) in [
        (&actor.did, actor.device_id, actor_leaf_id),
        (&recipient.did, recipient.device_id, recipient_leaf_id),
    ] {
        sqlx::query(
            "INSERT INTO chat.entry_recipients(conversation_id, seq, user_did, device_id, entitlement_kind) \
             VALUES ($1,1,$2,$3,'control')",
        )
        .bind(conversation_id)
        .bind(did)
        .bind(dev_id)
        .execute(&mut *tx)
        .await
        .map_err(|e| format!("insert c33 entry_recipient: {e}"))?;

        sqlx::query(
            "INSERT INTO chat.application_intervals( \
                 membership_interval_id, conversation_id, generation, recipient_did, \
                 recipient_device_id, start_seq, opening_kind, opening_transition_id, \
                 opening_outer_entry_fingerprint, opening_state_version, opening_group_id, \
                 opening_epoch, opening_group_context_hash, opening_confirmation_tag, \
                 opening_leaf_period_id, created_at \
             ) VALUES ($1,$2,0,$3,$4,1,'directRequest',$5,$6,1,$7,1,$8,$9,$10,$11)",
        )
        .bind(Uuid::new_v4())
        .bind(conversation_id)
        .bind(did)
        .bind(dev_id)
        .bind(request_id)
        .bind(outer_fp.as_slice())
        .bind(final_state.coordinate().group_id().as_slice())
        .bind(final_state.coordinate().group_context_hash().as_slice())
        .bind(final_state.coordinate().confirmation_tag().as_slice())
        .bind(leaf_id)
        .bind(created_at)
        .execute(&mut *tx)
        .await
        .map_err(|e| format!("insert c33 application_interval: {e}"))?;
    }

    sqlx::query(
        "INSERT INTO chat.direct_request_device_deliveries( \
             request_id, owner_did, owner_device_id, owner_key_id, auth_generation, \
             key_package_ref, grant_id, grant_revision, grant_digest, leaf_index, \
             import_until, provenance, provenance_sha256 \
         ) VALUES ($1,$2,$3,$4,1,$5,$6,1,$7,$8,$9,$10,$11)",
    )
    .bind(request_id)
    .bind(&recipient.did)
    .bind(recipient.device_id)
    .bind(&recipient.key_id)
    .bind(kp_ref.as_slice())
    .bind(grant_id)
    .bind(grant_digest.as_slice())
    .bind(recipient_leaf.leaf_index() as i64)
    .bind(import_until)
    .bind(&provenance_bytes)
    .bind(provenance_sha256.as_slice())
    .execute(&mut *tx)
    .await
    .map_err(|e| format!("insert c33 device_delivery: {e}"))?;

    let event_id = Uuid::new_v4();
    let event_bytes = serde_json::to_vec(&serde_json::json!({
        "$type": "blue.catbird.chat.defs#conversationChangedEvent",
        "conversationId": conversation_id.to_string(),
    }))
    .unwrap();
    let event_position: i64 = sqlx::query_scalar(
        "INSERT INTO chat.events(event_id, event_kind, payload_bytes, payload_sha256, created_at, protocol_instance_id) \
         SELECT $1, 'conversationChanged', $2, $3, $4, protocol_instance_id \
           FROM chat.protocol_instances \
         RETURNING event_position",
    )
    .bind(event_id)
    .bind(&event_bytes)
    .bind(Sha256::digest(&event_bytes).as_slice())
    .bind(created_at)
    .fetch_one(&mut *tx)
    .await
    .map_err(|e| format!("insert c33 event: {e}"))?;

    sqlx::query(
        "INSERT INTO chat.event_recipients(event_position, user_did, device_id, entitlement_kind, audience_predecessor_position) \
         SELECT $1, r.user_did, r.device_id, 'leaf', \
                (SELECT max(previous.event_position) FROM chat.event_recipients previous WHERE previous.user_did = r.user_did AND previous.device_id = r.device_id) \
           FROM chat.entry_recipients r \
          WHERE r.conversation_id = $2 AND r.seq = 1 \
          ORDER BY r.user_did, r.device_id",
    )
    .bind(event_position)
    .bind(conversation_id)
    .execute(&mut *tx)
    .await
    .map_err(|e| format!("insert c33 event_recipients: {e}"))?;

    let stream_outbox = Uuid::new_v4();
    let notification_outbox = Uuid::new_v4();
    for (outbox_id, kind) in [
        (stream_outbox, "stream"),
        (notification_outbox, "notification"),
    ] {
        sqlx::query(
            "INSERT INTO chat.outbox(outbox_id, event_position, work_kind, status, next_attempt_at, created_at) \
             VALUES ($1, $2, $3, 'pending', $4, $4)",
        )
        .bind(outbox_id)
        .bind(event_position)
        .bind(kind)
        .bind(created_at)
        .execute(&mut *tx)
        .await
        .map_err(|e| format!("insert c33 outbox: {e}"))?;
    }

    sqlx::query(
        "INSERT INTO chat.direct_request_push_events( \
             event_id, request_id, event_position, outbox_id, conversation_id, first_message_id, \
             sender_did, recipient_did, payload_digest, created_at \
         ) VALUES ( \
             $1, $2, $3, $4, $5, $6, $7, $8, \
             chat.direct_request_push_payload_digest($1, $2, $5, $6, $7, $8, ARRAY[$9::uuid]), \
             $10 \
         )",
    )
    .bind(event_id)
    .bind(request_id)
    .bind(event_position)
    .bind(notification_outbox)
    .bind(conversation_id)
    .bind(first_message_id)
    .bind(&actor.did)
    .bind(&recipient.did)
    .bind(recipient.device_id)
    .bind(created_at)
    .execute(&mut *tx)
    .await
    .map_err(|e| format!("insert c33 push_event: {e}"))?;

    sqlx::query(
        "INSERT INTO chat.direct_request_push_event_recipients( \
             event_id, request_id, recipient_did, recipient_device_id \
         ) VALUES ($1, $2, $3, $4)",
    )
    .bind(event_id)
    .bind(request_id)
    .bind(&recipient.did)
    .bind(recipient.device_id)
    .execute(&mut *tx)
    .await
    .map_err(|e| format!("insert c33 push_event_recipient: {e}"))?;

    tx.commit()
        .await
        .map_err(|e| format!("commit c33 expired publication fixture: {e}"))?;

    Ok((
        CleanSlateExpiredDirectRequestFixture {
            request_id,
            conversation_id,
            actor_did: actor.did.clone(),
            actor_device_id: actor.device_id,
            actor_ed25519_seed: actor.signing_key.to_bytes(),
            recipient_did: recipient.did.clone(),
        },
        application_routing_fixture::coordinate_json(final_state.coordinate()),
    ))
}

/// A genuinely published C33 request, driven through the production
/// keys → prepare → publish repository pipeline: both devices' real keys, the
/// recipient's real request KeyPackage and signed grant, the sender's real MLS
/// bootstrap, the DS receipts and every row the publication executor writes.
/// The recipient device still holds its pending request Welcome.
pub(crate) struct GenuinePendingDirectRequest {
    pub(crate) request_id: uuid::Uuid,
    pub(crate) conversation_id: uuid::Uuid,
    pub(crate) recipient_did: String,
    pub(crate) recipient_device_id: uuid::Uuid,
    recipient: application_routing_fixture::FixtureIdentity,
    sender: application_routing_fixture::FixtureIdentity,
    next: serde_json::Value,
}

impl GenuinePendingDirectRequest {
    /// `(did, deviceId, keyId, Ed25519 seed)` of the sender's device.
    pub(crate) fn sender_identity(&self) -> (String, uuid::Uuid, String, [u8; 32]) {
        identity(&self.sender)
    }

    /// `(did, deviceId, keyId, Ed25519 seed)` of the recipient's device.
    pub(crate) fn recipient_identity(&self) -> (String, uuid::Uuid, String, [u8; 32]) {
        identity(&self.recipient)
    }

    /// The published conversation's current coordinate.
    pub(crate) fn coordinate(&self) -> &serde_json::Value {
        &self.next
    }

    /// The recipient device's own `acknowledgeWelcome`, or `rejectWelcome`
    /// (`invalidWelcome`), naming the published request Welcome.
    fn signed_welcome_terminal(
        &self,
        reject: bool,
        signed_at: &str,
    ) -> Result<application_routing_fixture::SignedRecoveryEnvelope, String> {
        use super::transcript::SignedMutationKind;
        let kind = if reject {
            SignedMutationKind::WelcomeRejection
        } else {
            SignedMutationKind::WelcomeAcknowledgement
        };
        let mut body = serde_json::json!({
            "$type": kind.type_id(),
            "signatureDomain": String::from_utf8(kind.domain().to_vec()).map_err(|e| e.to_string())?,
            "actorDid": self.recipient.did,
            "actorDeviceId": self.recipient.device_id,
            "keyId": self.recipient.key_id,
            "authGeneration": 1,
            "idempotencyKey": uuid::Uuid::new_v4(),
            "signedAt": signed_at,
            "welcomeId": self.request_id,
            "transitionSeq": 1,
            "coordinates": self.next,
        });
        if reject {
            body["reason"] = serde_json::json!("invalidWelcome");
        }
        application_routing_fixture::sign_canonical_wrapper(&self.recipient, body, kind)
    }

    /// That request, verified against the recipient's own public key.
    pub(crate) fn verified_welcome_terminal(
        &self,
        reject: bool,
    ) -> Result<super::transcript::VerifiedSignedMutation, String> {
        let trusted = super::validation::TrustedRequestInstant::capture()
            .map_err(|e| format!("Welcome terminal instant: {e:?}"))?;
        let envelope = self.signed_welcome_terminal(reject, trusted.as_str())?;
        super::transcript::decode_and_verify_signed_mutation(
            &envelope.raw_wrapper,
            &self.recipient.signing_public_key(),
        )
        .map_err(|e| format!("verify Welcome terminal: {e:?}"))
    }

    /// That request admitted as the handler admits it: Nest JWT + DPoP
    /// verification, replay consumption and the Ed25519 check against the
    /// recipient's registered key. Returns the admission and the HTTP body.
    pub(crate) async fn admit_welcome_terminal(
        &self,
        pool: &sqlx::PgPool,
        reject: bool,
    ) -> Result<(super::repository::auth::SignedOperationAdmission, Vec<u8>), String> {
        let trusted = super::validation::TrustedRequestInstant::capture()
            .map_err(|e| format!("Welcome terminal instant: {e:?}"))?;
        let envelope = self.signed_welcome_terminal(reject, trusted.as_str())?;
        let endpoint = if reject {
            "blue.catbird.chat.rejectWelcome"
        } else {
            "blue.catbird.chat.acknowledgeWelcome"
        };
        let admission = application_routing_fixture::admit_lifecycle(
            pool,
            &self.recipient,
            endpoint,
            &envelope,
            &trusted,
        )
        .await?;
        let signed: serde_json::Value =
            serde_json::from_slice(&envelope.raw_wrapper).map_err(|e| e.to_string())?;
        let body = serde_json::to_vec(&serde_json::json!({ "signedRequest": signed }))
            .map_err(|e| e.to_string())?;
        Ok((admission, body))
    }
}

fn identity(
    identity: &application_routing_fixture::FixtureIdentity,
) -> (String, uuid::Uuid, String, [u8; 32]) {
    (
        identity.did.clone(),
        identity.device_id,
        identity.key_id.clone(),
        identity.signing_key.to_bytes(),
    )
}

pub(crate) async fn seed_genuine_pending_direct_request(
    pool: &sqlx::PgPool,
) -> Result<GenuinePendingDirectRequest, String> {
    seed_genuine_pending_direct_request_between(
        pool,
        application_routing_fixture::FixtureIdentity::fresh(b"genuine-direct-request-sender")?,
        application_routing_fixture::FixtureIdentity::fresh(b"genuine-direct-request-recipient")?,
    )
    .await
}

/// [`seed_genuine_pending_direct_request`] from `sender_did` to `recipient_did`,
/// so a federation test can declare the pair's homes.
#[cfg(all(test, feature = "sim"))]
pub(crate) async fn seed_genuine_pending_direct_request_for_pair(
    pool: &sqlx::PgPool,
    sender_did: &str,
    recipient_did: &str,
) -> Result<GenuinePendingDirectRequest, String> {
    seed_genuine_pending_direct_request_between(
        pool,
        application_routing_fixture::FixtureIdentity::fresh_for_did(
            sender_did,
            b"genuine-direct-request-sender",
        )?,
        application_routing_fixture::FixtureIdentity::fresh_for_did(
            recipient_did,
            b"genuine-direct-request-recipient",
        )?,
    )
    .await
}

/// `did`, seeded on `pool` with one device that published `packages` request
/// KeyPackages and their grants, as its home holds them: the device's Ed25519
/// public key and each package's ref.
#[cfg(all(test, feature = "sim"))]
pub(crate) async fn seed_published_request_keys(
    pool: &sqlx::PgPool,
    did: &str,
    packages: usize,
) -> Result<([u8; 32], Vec<[u8; 32]>), String> {
    let identity = application_routing_fixture::FixtureIdentity::fresh_for_did(
        did,
        b"published-request-keys",
    )?;
    let registered = super::validation::TrustedRequestInstant::capture()
        .map_err(|e| format!("registration instant: {e:?}"))?;
    application_routing_fixture::seed_identity(pool, &identity, &registered).await?;
    let published = publish_request_keys(pool, &identity, packages).await?;
    Ok((
        identity.signing_public_key(),
        published.iter().map(|key| key.key_package_ref).collect(),
    ))
}

/// One request KeyPackage a recipient device published with its grant.
struct PublishedRequestKey {
    package: openmls::prelude::KeyPackage,
    key_package_ref: [u8; 32],
    grant_id: uuid::Uuid,
}

/// `recipient`'s device publishes `count` request KeyPackages, each with its
/// signed grant, through the production `publishDirectRequestKeys` path.
async fn publish_request_keys(
    pool: &sqlx::PgPool,
    recipient: &application_routing_fixture::FixtureIdentity,
    count: usize,
) -> Result<Vec<PublishedRequestKey>, String> {
    use super::direct_request_transcript::{direct_request_signing_bytes, DirectRequestKind};
    use base64::{engine::general_purpose::STANDARD, Engine as _};
    use chrono::{Duration, SecondsFormat};
    use ed25519_dalek::Signer as _;
    use serde_json::{json, Value};
    use sha2::{Digest as _, Sha256};
    use uuid::Uuid;

    let now = || {
        super::validation::TrustedRequestInstant::capture()
            .map(|instant| instant.datetime())
            .map_err(|e| format!("request instant: {e:?}"))
    };
    let sign = |kind, body: Value| -> Result<Value, String> {
        let body_bytes = serde_json::to_vec(&body).map_err(|e| e.to_string())?;
        let message = direct_request_signing_bytes(kind, &body_bytes)
            .map_err(|e| format!("{kind:?}: {e}"))?;
        let signature = STANDARD.encode(recipient.signing_key.sign(&message).to_bytes());
        Ok(json!({ "body": body, "signature": signature }))
    };
    let at = now()?;
    let signed_at = at.to_rfc3339_opts(SecondsFormat::Millis, true);
    let expires_at = (at + Duration::days(29)).to_rfc3339_opts(SecondsFormat::Millis, true);
    let (mut published, mut keys) = (Vec::with_capacity(count), Vec::with_capacity(count));
    for _ in 0..count {
        let (package, bytes, key_package_ref) =
            application_routing_fixture::build_direct_request_key_package(recipient, at)?;
        let grant_id = Uuid::new_v4();
        let grant = sign(
            DirectRequestKind::Grant,
            json!({
                "$type": "blue.catbird.chat.defs#directRequestGrantBody",
                "signatureDomain": "CATBIRD-DIRECT-REQUEST-GRANT\u{0}",
                "protocolVersion": "2",
                "actorDid": recipient.did,
                "actorDeviceId": recipient.device_id,
                "keyId": recipient.key_id,
                "authGeneration": 1,
                "grantId": grant_id,
                "grantRevision": 1,
                "purpose": "direct-request-bootstrap",
                "profile": "encryptedIntroduction1",
                "keyPackageRef": STANDARD.encode(key_package_ref),
                "keyPackageSha256": STANDARD.encode(Sha256::digest(&bytes)),
                "expiresAt": expires_at,
                "idempotencyKey": grant_id,
                "signedAt": signed_at,
            }),
        )?;
        keys.push(json!({
            "keyPackage": {
                "framing": "mlsMessage",
                "contentType": "keyPackage",
                "bytes": STANDARD.encode(&bytes),
                "sha256": STANDARD.encode(Sha256::digest(&bytes)),
                "keyPackageRef": STANDARD.encode(key_package_ref),
            },
            "grant": grant,
        }));
        published.push(PublishedRequestKey {
            package,
            key_package_ref,
            grant_id,
        });
    }
    let publication = sign(
        DirectRequestKind::Keys,
        json!({
            "$type": "blue.catbird.chat.defs#directRequestKeysPublicationBody",
            "signatureDomain": "CATBIRD-DIRECT-REQUEST-KEYS\u{0}",
            "protocolVersion": "2",
            "actorDid": recipient.did,
            "actorDeviceId": recipient.device_id,
            "keyId": recipient.key_id,
            "authGeneration": 1,
            "revision": 1,
            "enabled": true,
            "keys": keys,
            "idempotencyKey": Uuid::new_v4(),
            "signedAt": signed_at,
        }),
    )?;
    let mut tx = pool.begin().await.map_err(|e| e.to_string())?;
    super::repository::direct_request_preparation::publish_direct_request_keys(
        &mut tx,
        &crate::auth::VerifiedServicePrincipal::for_federated_s2s(
            &recipient.did,
            "blue.catbird.chat.publishDirectRequestKeys",
        ),
        &serde_json::to_vec(&publication).map_err(|e| e.to_string())?,
        now()?,
    )
    .await
    .map_err(|e| format!("publish request keys: {e:?}"))?;
    tx.commit().await.map_err(|e| e.to_string())?;
    Ok(published)
}

async fn seed_genuine_pending_direct_request_between(
    pool: &sqlx::PgPool,
    actor: application_routing_fixture::FixtureIdentity,
    recipient: application_routing_fixture::FixtureIdentity,
) -> Result<GenuinePendingDirectRequest, String> {
    use super::direct_request_transcript::{
        direct_request_context_hash, direct_request_signing_bytes, verify_signed_request,
        DirectRequestKind,
    };
    use super::repository::{
        direct_request_preparation::{self as preparation, DirectRequestResult},
        direct_request_publication::{self as publication, PublicationPreparation},
        direct_request_receipts::DirectRequestReceiptSigner,
    };
    use application_routing_fixture::FixtureIdentity;
    use base64::{engine::general_purpose::STANDARD, Engine as _};
    use chrono::{DateTime, Duration, SecondsFormat, Utc};
    use ed25519_dalek::Signer as _;
    use p256::pkcs8::EncodePrivateKey as _;
    use serde_json::{json, Value};
    use sha2::{Digest as _, Sha256};
    use uuid::Uuid;

    let es256 = |seed: u8| -> Result<(p256::ecdsa::SigningKey, String), String> {
        let key = p256::ecdsa::SigningKey::from_slice(&[seed; 32]).map_err(|e| e.to_string())?;
        let pem = p256::SecretKey::from_slice(&key.to_bytes())
            .map_err(|e| e.to_string())?
            .to_pkcs8_pem(p256::pkcs8::LineEnding::LF)
            .map_err(|e| e.to_string())?
            .to_string();
        Ok((key, pem))
    };
    let (receipt_key, receipt_pem) = es256(21)?;
    let (_, service_pem) = es256(22)?;
    let (sequencer_key, _) = es256(23)?;
    let document = crate::identity::did_doc::build_direct_request_receipt_did_document(
        "did:web:chat.catbird.blue",
        receipt_key.verifying_key(),
    );
    let signer = DirectRequestReceiptSigner::configured(
        &receipt_pem,
        &service_pem,
        &serde_json::to_string(&document).map_err(|e| e.to_string())?,
    )
    .map_err(|e| format!("request receipt signer: {e:?}"))?;
    signer.validate_and_retain_keys(pool).await?;
    let sequencer = crate::federation::receipt::I13ReceiptSigner::from_signing_key_for_test(
        signer.authority_did().to_owned(),
        sequencer_key,
    );
    let policy = RelationshipAuthority::new(
        fixed_production_relationship_policy_config().map_err(|e| format!("{e:?}"))?,
        DeterministicTestTransport,
    );
    // Publication appends its event to this instance's stream.
    let cursor_key: String = sqlx::query_scalar("SELECT chat.ed25519_key_id($1)")
        .bind(vec![0x51_u8; 32])
        .fetch_one(pool)
        .await
        .map_err(|e| e.to_string())?;
    sqlx::query(
        "INSERT INTO chat.protocol_instances(singleton,protocol_version,protocol_instance_id,cursor_key_id) \
         VALUES(TRUE,'1',$1,$2) ON CONFLICT DO NOTHING",
    )
    .bind(Uuid::new_v4())
    .bind(&cursor_key)
    .execute(pool)
    .await
    .map_err(|e| format!("protocol instance: {e}"))?;
    sqlx::query(
        "INSERT INTO chat.event_retention(protocol_instance_id,retained_floor,updated_at) \
         SELECT protocol_instance_id,0,clock_timestamp() FROM chat.protocol_instances \
         ON CONFLICT DO NOTHING",
    )
    .execute(pool)
    .await
    .map_err(|e| format!("event retention: {e}"))?;

    let registered = super::validation::TrustedRequestInstant::capture()
        .map_err(|e| format!("registration instant: {e:?}"))?;
    application_routing_fixture::seed_identity(pool, &actor, &registered).await?;
    application_routing_fixture::seed_identity(pool, &recipient, &registered).await?;
    let now = || -> Result<DateTime<Utc>, String> {
        super::validation::TrustedRequestInstant::capture()
            .map(|instant| instant.datetime())
            .map_err(|e| format!("request instant: {e:?}"))
    };
    let text = |instant: DateTime<Utc>| instant.to_rfc3339_opts(SecondsFormat::Millis, true);
    let sign = |identity: &FixtureIdentity, kind, body: &Value| -> Result<Vec<u8>, String> {
        let body_bytes = serde_json::to_vec(body).map_err(|e| e.to_string())?;
        let message = direct_request_signing_bytes(kind, &body_bytes)
            .map_err(|e| format!("{kind:?}: {e}"))?;
        let signature = STANDARD.encode(identity.signing_key.sign(&message).to_bytes());
        serde_json::to_vec(&json!({ "body": body, "signature": signature }))
            .map_err(|e| e.to_string())
    };
    let principal =
        |did: &str, nsid: &str| crate::auth::VerifiedServicePrincipal::for_federated_s2s(did, nsid);

    // 1. The recipient device publishes one request KeyPackage and its grant.
    let PublishedRequestKey {
        package,
        key_package_ref: package_ref,
        grant_id,
    } = publish_request_keys(pool, &recipient, 1).await?.remove(0);

    // 2. The sender prepares against that published capability.
    let (request_id, conversation_id, first_message_id) =
        (Uuid::new_v4(), Uuid::new_v4(), Uuid::new_v4());
    let prepare_body = json!({
        "$type": "blue.catbird.chat.defs#directRequestPreparationBody",
        "signatureDomain": "CATBIRD-DIRECT-REQUEST-PREPARE\u{0}",
        "protocolVersion": "2",
        "actorDid": actor.did,
        "actorDeviceId": actor.device_id,
        "keyId": actor.key_id,
        "authGeneration": 1,
        "requestId": request_id,
        "firstMessageId": first_message_id,
        "conversationId": conversation_id,
        "recipientDid": recipient.did,
        "origin": { "$type": "blue.catbird.chat.defs#freshDirectOrigin" },
        "profile": "encryptedIntroduction1",
        "idempotencyKey": request_id,
        "signedAt": text(now()?),
    });
    let prepare = sign(&actor, DirectRequestKind::Prepare, &prepare_body)?;
    let mut tx = pool.begin().await.map_err(|e| e.to_string())?;
    let prepared = match preparation::prepare_direct_request(
        &mut tx,
        &principal(&actor.did, "blue.catbird.chat.prepareDirectRequest"),
        &prepare,
        &signer,
        &policy,
        now()?,
        None,
    )
    .await
    .map_err(|e| format!("prepare request: {e:?}"))?
    {
        DirectRequestResult::Prepared(bytes) => bytes,
        DirectRequestResult::Terminal(bytes) => {
            return Err(format!(
                "preparation refused: {}",
                String::from_utf8_lossy(&bytes)
            ))
        }
        _ => return Err("preparation returned no preparation".to_owned()),
    };
    tx.commit().await.map_err(|e| e.to_string())?;
    let snapshot: Value = serde_json::from_slice(&prepared).map_err(|e| e.to_string())?;
    let selected: Vec<&Value> = snapshot["selectedDevices"]
        .as_array()
        .into_iter()
        .flatten()
        .map(|device| &device["keyPackage"]["keyPackageRef"])
        .collect();
    if selected != [&json!(STANDARD.encode(package_ref))] {
        return Err(format!("preparation selected another audience: {snapshot}"));
    }
    let preparation_digest = snapshot["preparationDigest"].clone();

    // 3. The sender client's MLS bootstrap for that exact preparation.
    let context = json!({
        "protocolVersion": "2",
        "requestId": request_id,
        "firstMessageId": first_message_id,
        "conversationId": conversation_id,
        "origin": prepare_body["origin"],
        "actorDid": actor.did,
        "actorDeviceId": actor.device_id,
        "actorKeyId": actor.key_id,
        "recipientDid": recipient.did,
        "preparationDigest": preparation_digest,
    });
    let context_hash =
        direct_request_context_hash(&serde_json::to_vec(&context).map_err(|e| e.to_string())?)
            .map_err(|e| format!("request context: {e}"))?;
    let archive_commitment = [0x6d_u8; 32];
    let at = now()?;
    let bootstrap = application_routing_fixture::build_direct_request_bootstrap(
        &actor,
        package,
        conversation_id,
        &context_hash,
        first_message_id,
        &archive_commitment,
        at,
    )?;
    // Whole seconds, past the seven-day import floor, inside the sender leaf.
    let import_until = text(
        DateTime::from_timestamp((at + Duration::days(7) + Duration::hours(1)).timestamp(), 0)
            .ok_or_else(|| "import horizon".to_owned())?,
    );
    let artifact = |bytes: &[u8], content_type: &str| {
        json!({
            "framing": "mlsMessage",
            "contentType": content_type,
            "bytes": STANDARD.encode(bytes),
            "sha256": STANDARD.encode(Sha256::digest(bytes)),
        })
    };
    let mut metadata_coordinate = bootstrap.next.clone();
    let fields = metadata_coordinate
        .as_object_mut()
        .ok_or_else(|| "published coordinate".to_owned())?;
    fields.remove("stateVersion");
    fields.remove("lifecycle");
    fields.insert(
        "conversationId".to_owned(),
        json!(STANDARD.encode(conversation_id.as_bytes())),
    );
    let metadata = [0x5a_u8; 32];
    let mut publish_body = prepare_body;
    publish_body["$type"] = json!("blue.catbird.chat.defs#directRequestPublicationBody");
    publish_body["signatureDomain"] = json!("CATBIRD-DIRECT-REQUEST-PUBLISH\u{0}");
    publish_body["signedAt"] = json!(text(now()?));
    publish_body["preparationDigest"] = preparation_digest.clone();
    publish_body["preparationRequestDigest"] = json!(STANDARD.encode(
        verify_signed_request(
            DirectRequestKind::Prepare,
            &prepare,
            &actor.signing_public_key()
        )
        .map_err(|e| format!("prepare digest: {e}"))?
        .request_digest()
    ));
    publish_body["contextHash"] = json!(STANDARD.encode(context_hash));
    publish_body["archiveCommitment"] = json!(STANDARD.encode(archive_commitment));
    publish_body["originalSenderAttestation"] = original_sender_attestation_json_for_test(
        &actor.did,
        actor.device_id,
        &actor.signing_key,
        &conversation_id.to_string(),
        &first_message_id.to_string(),
        &archive_commitment,
    );
    publish_body["next"] = bootstrap.next.clone();
    publish_body["importUntil"] = json!(import_until);
    publish_body["artifacts"] = json!({
        "genesisGroupInfo": artifact(&bootstrap.genesis_group_info, "groupInfo"),
        "addCommit": artifact(&bootstrap.add_commit, "publicMessageCommit"),
        "finalGroupInfo": artifact(&bootstrap.final_group_info, "groupInfo"),
        "welcome": {
            "opaqueWelcome": STANDARD.encode(&bootstrap.welcome),
            "sha256": STANDARD.encode(Sha256::digest(&bootstrap.welcome)),
            "deliveries": [{
                "recipientDid": recipient.did,
                "recipientDeviceId": recipient.device_id,
                "provenance": {
                    "requestId": request_id,
                    "preparationDigest": preparation_digest,
                    "contextHash": STANDARD.encode(context_hash),
                    "grantId": grant_id,
                    "grantRevision": 1,
                    "keyPackageRef": STANDARD.encode(package_ref),
                    "importUntil": import_until,
                },
            }],
        },
        "initialCiphertext": STANDARD.encode(&bootstrap.initial_ciphertext),
        "metadataSnapshot": {
            "coordinate": metadata_coordinate,
            "originTransitionId": request_id,
            "metadataVersion": 1,
            "nonce": STANDARD.encode([0x52_u8; 12]),
            "ciphertext": STANDARD.encode(metadata),
            "ciphertextSha256": STANDARD.encode(Sha256::digest(metadata)),
            "ciphertextSize": metadata.len(),
            "authorProof": {
                "authorDid": actor.did,
                "authorDeviceId": actor.device_id,
                "authorKeyId": actor.key_id,
                "signaturePublicKey": STANDARD.encode(actor.signing_public_key()),
                "authGenerationAtOrigin": 1,
                "originTransitionId": request_id,
                "originSeq": 1,
                "roleAtOrigin": "admin",
                "deviceStatusAtOrigin": "active",
            },
        },
    });
    let signed_publication = sign(&actor, DirectRequestKind::Publish, &publish_body)?;

    // 4. The production publication planner and executor, one transaction.
    let mut tx = pool.begin().await.map_err(|e| e.to_string())?;
    let receipt = match publication::prepare_publication(
        &mut tx,
        &principal(&actor.did, "blue.catbird.chat.publishDirectRequest"),
        &signed_publication,
        &signer,
        &policy,
        now()?,
        true,
    )
    .await
    .map_err(|e| format!("plan publication: {e:?}"))?
    {
        PublicationPreparation::Ready(prepared) => {
            publication::execute_publication(&mut tx, *prepared, &signer, Some(&sequencer), &policy)
                .await
                .map_err(|e| format!("execute publication: {e:?}"))?
        }
        PublicationPreparation::Terminal(bytes) => {
            return Err(format!(
                "publication refused: {}",
                String::from_utf8_lossy(&bytes)
            ))
        }
    };
    let receipt: Value = serde_json::from_slice(&receipt).map_err(|e| e.to_string())?;
    if receipt["body"]["receipt"]["$type"] != "blue.catbird.chat.defs#directRequestPublishedReceipt"
    {
        return Err(format!("publication rejected: {receipt}"));
    }
    tx.commit().await.map_err(|e| e.to_string())?;
    Ok(GenuinePendingDirectRequest {
        request_id,
        conversation_id,
        recipient_did: recipient.did.clone(),
        recipient_device_id: recipient.device_id,
        recipient,
        sender: actor,
        next: bootstrap.next,
    })
}

/// Seed a 3rd active zero-leaf participant into an existing clean-slate group conversation
/// (via committed `'policy'` invitation + `'acceptConversation'` acceptance transitions) for SpaceHost tests.
#[cfg(any(test, feature = "test-support"))]
pub async fn seed_clean_slate_active_zero_leaf_member_for_test(
    pool: &sqlx::PgPool,
    conversation_id: uuid::Uuid,
    admin_did: &str,
    member_did: &str,
) -> Result<(), String> {
    use chrono::SecondsFormat;
    use sha2::{Digest as _, Sha256};
    use uuid::Uuid;

    let now: chrono::DateTime<chrono::Utc> = sqlx::query_scalar("SELECT clock_timestamp()")
        .fetch_one(pool)
        .await
        .map_err(|e| e.to_string())?;
    let trusted_past =
        super::validation::TrustedRequestInstant::from_datetime(now - chrono::Duration::seconds(5))
            .map_err(|e| format!("trusted instant: {e:?}"))?;
    let member_ident = application_routing_fixture::FixtureIdentity::fresh_for_did(
        member_did,
        b"space-zero-leaf",
    )?;
    application_routing_fixture::seed_identity(pool, &member_ident, &trusted_past).await?;

    let (gen, cur_sv, next_seq): (i64, i64, i64) = sqlx::query_as(
        "SELECT current_generation, current_state_version, next_entry_seq \
           FROM chat.conversations WHERE conversation_id = $1",
    )
    .bind(conversation_id)
    .fetch_one(pool)
    .await
    .map_err(|e| e.to_string())?;

    let (admin_dev, admin_kid): (Uuid, String) = sqlx::query_as(
        "SELECT d.device_id, k.key_id \
           FROM chat.devices d \
           JOIN chat.device_keys k USING (user_did, device_id) \
          WHERE d.user_did = $1 AND d.status = 'active' LIMIT 1",
    )
    .bind(admin_did)
    .fetch_one(pool)
    .await
    .map_err(|e| e.to_string())?;

    let (group_id, epoch, gch, ct, snap, snap_sha, tree, tree_sha, leaf_count): (
        Vec<u8>,
        i64,
        Vec<u8>,
        Vec<u8>,
        Vec<u8>,
        Vec<u8>,
        Vec<u8>,
        Vec<u8>,
        i64,
    ) = sqlx::query_as(
        "SELECT group_id, epoch, group_context_hash, confirmation_tag, public_snapshot_bytes, \
                snapshot_sha256, tree_summary_bytes, tree_summary_sha256, leaf_count \
           FROM chat.generation_states \
          WHERE conversation_id = $1 AND generation = $2 AND state_version = $3",
    )
    .bind(conversation_id)
    .bind(gen)
    .bind(cur_sv)
    .fetch_one(pool)
    .await
    .map_err(|e| e.to_string())?;

    let inv_tid = Uuid::new_v4();
    let inv_eid = Uuid::new_v4();
    let inv_at = now;
    let inv_seq = next_seq;
    let inv_sv = cur_sv + 1;

    let acc_tid = Uuid::new_v4();
    let acc_eid = Uuid::new_v4();
    let acc_at = now + chrono::Duration::milliseconds(10);
    let acc_seq = next_seq + 1;
    let acc_sv = cur_sv + 2;

    let mut tx = pool.begin().await.map_err(|e| e.to_string())?;

    for (
        tid,
        eid,
        kind,
        entry_kind,
        prior_sv,
        next_sv,
        seq,
        ts,
        actor_d,
        actor_dev,
        actor_k,
        actor_r,
    ) in [
        (
            inv_tid,
            inv_eid,
            "policy",
            "blue.catbird.chat.defs#policyEntry",
            cur_sv,
            inv_sv,
            inv_seq,
            inv_at,
            admin_did,
            admin_dev,
            admin_kid.as_str(),
            "admin",
        ),
        (
            acc_tid,
            acc_eid,
            "acceptConversation",
            "blue.catbird.chat.defs#participantAcceptanceEntry",
            inv_sv,
            acc_sv,
            acc_seq,
            acc_at,
            member_did,
            member_ident.device_id,
            member_ident.key_id.as_str(),
            "member",
        ),
    ] {
        let req_bytes = format!("{{\"transitionId\":\"{tid}\"}}").into_bytes();
        let req_digest: [u8; 32] = Sha256::digest(&req_bytes).into();
        let payload = serde_json::to_vec(&serde_json::json!({
            "$type": entry_kind,
            "entryId": eid.to_string(),
            "conversationId": conversation_id.to_string(),
            "seq": seq,
            "receivedAt": ts.to_rfc3339_opts(SecondsFormat::Millis, true),
        }))
        .map_err(|e| e.to_string())?;
        let payload_sha: [u8; 32] = Sha256::digest(&payload).into();
        let server_fields = serde_json::to_vec(&serde_json::json!({
            "entryId": eid.to_string(),
            "conversationId": conversation_id.to_string(),
            "seq": seq,
            "receivedAt": ts.to_rfc3339_opts(SecondsFormat::Millis, true),
        }))
        .map_err(|e| e.to_string())?;

        sqlx::query(
            "INSERT INTO chat.generation_states( \
                 conversation_id, generation, state_version, group_id, epoch, group_context_hash, \
                 confirmation_tag, lifecycle, state_kind, producing_transition_id, \
                 public_snapshot_bytes, snapshot_sha256, tree_summary_bytes, tree_summary_sha256, \
                 leaf_count, created_at \
             ) VALUES ($1,$2,$3,$4,$5,$6,$7,'active',$8,$9,$10,$11,$12,$13,$14,$15)",
        )
        .bind(conversation_id)
        .bind(gen)
        .bind(next_sv)
        .bind(&group_id)
        .bind(epoch)
        .bind(&gch)
        .bind(&ct)
        .bind(kind)
        .bind(tid)
        .bind(&snap)
        .bind(&snap_sha)
        .bind(&tree)
        .bind(&tree_sha)
        .bind(leaf_count)
        .bind(ts)
        .execute(&mut *tx)
        .await
        .map_err(|e| format!("insert {kind} state: {e}"))?;

        sqlx::query(
            "INSERT INTO chat.transitions( \
                 transition_id, conversation_id, kind, actor_did, actor_device_id, actor_key_id, \
                 actor_auth_generation, actor_role, actor_device_status, signed_request_bytes, \
                 unsigned_projection_bytes, signing_transcript_bytes, request_digest, signature, \
                 prior_generation, prior_state_version, next_generation, next_state_version, \
                 entry_seq, accepted_at \
             ) VALUES ($1,$2,$3,$4,$5,$6,1,$7,'active',$8,$8,$8,$9,$10,$11,$12,$11,$13,$14,$15)",
        )
        .bind(tid)
        .bind(conversation_id)
        .bind(kind)
        .bind(actor_d)
        .bind(actor_dev)
        .bind(actor_k)
        .bind(actor_r)
        .bind(&req_bytes)
        .bind(req_digest.as_slice())
        .bind([0x55_u8; 64].as_slice())
        .bind(gen)
        .bind(prior_sv)
        .bind(next_sv)
        .bind(seq)
        .bind(ts)
        .execute(&mut *tx)
        .await
        .map_err(|e| format!("insert {kind} transition: {e}"))?;

        sqlx::query(
            "INSERT INTO chat.entries( \
                 conversation_id, seq, entry_id, entry_kind, accepted_payload_bytes, \
                 accepted_payload_sha256, signed_request_bytes, request_digest, signature, \
                 server_fields_bytes, outer_entry_fingerprint, actor_did, actor_device_id, \
                 actor_key_id, actor_auth_generation, generation, state_version, transition_id, received_at \
             ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$6,$11,$12,$13,1,$14,$15,$16,$17)",
        )
        .bind(conversation_id)
        .bind(seq)
        .bind(eid)
        .bind(entry_kind)
        .bind(&payload)
        .bind(payload_sha.as_slice())
        .bind(&req_bytes)
        .bind(req_digest.as_slice())
        .bind([0x55_u8; 64].as_slice())
        .bind(&server_fields)
        .bind(actor_d)
        .bind(actor_dev)
        .bind(actor_k)
        .bind(gen)
        .bind(next_sv)
        .bind(tid)
        .bind(ts)
        .execute(&mut *tx)
        .await
        .map_err(|e| format!("insert {kind} entry: {e}"))?;
    }

    sqlx::query(
        "INSERT INTO chat.participants( \
             participant_period_id, conversation_id, user_did, status, role, role_transition_id, \
             role_changed_at, created_by_did, created_by_device_id, invitation_transition_id, \
             invitation_entry_id, invited_at, acceptance_transition_id, acceptance_entry_id, \
             accepted_at, current_membership, created_at \
         ) VALUES ($1,$2,$3,'active','member',$4,$5,$6,$7,$4,$8,$5,$9,$10,$11,true,$5)",
    )
    .bind(Uuid::new_v4())
    .bind(conversation_id)
    .bind(member_did)
    .bind(inv_tid)
    .bind(inv_at)
    .bind(admin_did)
    .bind(admin_dev)
    .bind(inv_eid)
    .bind(acc_tid)
    .bind(acc_eid)
    .bind(acc_at)
    .execute(&mut *tx)
    .await
    .map_err(|e| format!("insert zero-leaf participant: {e}"))?;

    sqlx::query("UPDATE chat.generations SET current_state_version = $3 WHERE conversation_id = $1 AND generation = $2")
        .bind(conversation_id)
        .bind(gen)
        .bind(acc_sv)
        .execute(&mut *tx)
        .await
        .map_err(|e| e.to_string())?;

    sqlx::query("UPDATE chat.conversations SET current_state_version = $2, next_entry_seq = $3 WHERE conversation_id = $1")
        .bind(conversation_id)
        .bind(acc_sv)
        .bind(acc_seq + 1)
        .execute(&mut *tx)
        .await
        .map_err(|e| e.to_string())?;

    tx.commit()
        .await
        .map_err(|e| format!("commit zero-leaf member: {e}"))?;
    Ok(())
}

/// Remove a zero-leaf active participant via a committed `'policy'` removal transition (`D3` / SpaceHost tests).
#[cfg(any(test, feature = "test-support"))]
pub async fn seed_clean_slate_remove_zero_leaf_member_for_test(
    pool: &sqlx::PgPool,
    conversation_id: uuid::Uuid,
    admin_did: &str,
    member_did: &str,
) -> Result<(), String> {
    use chrono::SecondsFormat;
    use sha2::{Digest as _, Sha256};
    use uuid::Uuid;

    let now: chrono::DateTime<chrono::Utc> = sqlx::query_scalar("SELECT clock_timestamp()")
        .fetch_one(pool)
        .await
        .map_err(|e| e.to_string())?;

    let (gen, cur_sv, next_seq): (i64, i64, i64) = sqlx::query_as(
        "SELECT current_generation, current_state_version, next_entry_seq \
           FROM chat.conversations WHERE conversation_id = $1",
    )
    .bind(conversation_id)
    .fetch_one(pool)
    .await
    .map_err(|e| e.to_string())?;

    let (admin_dev, admin_kid): (Uuid, String) = sqlx::query_as(
        "SELECT d.device_id, k.key_id \
           FROM chat.devices d \
           JOIN chat.device_keys k USING (user_did, device_id) \
          WHERE d.user_did = $1 AND d.status = 'active' LIMIT 1",
    )
    .bind(admin_did)
    .fetch_one(pool)
    .await
    .map_err(|e| e.to_string())?;

    let (group_id, epoch, gch, ct, snap, snap_sha, tree, tree_sha, leaf_count): (
        Vec<u8>,
        i64,
        Vec<u8>,
        Vec<u8>,
        Vec<u8>,
        Vec<u8>,
        Vec<u8>,
        Vec<u8>,
        i64,
    ) = sqlx::query_as(
        "SELECT group_id, epoch, group_context_hash, confirmation_tag, public_snapshot_bytes, \
                snapshot_sha256, tree_summary_bytes, tree_summary_sha256, leaf_count \
           FROM chat.generation_states \
          WHERE conversation_id = $1 AND generation = $2 AND state_version = $3",
    )
    .bind(conversation_id)
    .bind(gen)
    .bind(cur_sv)
    .fetch_one(pool)
    .await
    .map_err(|e| e.to_string())?;

    let rem_tid = Uuid::new_v4();
    let rem_eid = Uuid::new_v4();
    let rem_sv = cur_sv + 1;
    let rem_seq = next_seq;
    let req_bytes = format!("{{\"transitionId\":\"{rem_tid}\"}}").into_bytes();
    let req_digest: [u8; 32] = Sha256::digest(&req_bytes).into();
    let payload = serde_json::to_vec(&serde_json::json!({
        "$type": "blue.catbird.chat.defs#policyEntry",
        "entryId": rem_eid.to_string(),
        "conversationId": conversation_id.to_string(),
        "seq": rem_seq,
        "receivedAt": now.to_rfc3339_opts(SecondsFormat::Millis, true),
    }))
    .map_err(|e| e.to_string())?;
    let payload_sha: [u8; 32] = Sha256::digest(&payload).into();
    let server_fields = serde_json::to_vec(&serde_json::json!({
        "entryId": rem_eid.to_string(),
        "conversationId": conversation_id.to_string(),
        "seq": rem_seq,
        "receivedAt": now.to_rfc3339_opts(SecondsFormat::Millis, true),
    }))
    .map_err(|e| e.to_string())?;

    let mut tx = pool.begin().await.map_err(|e| e.to_string())?;

    sqlx::query(
        "INSERT INTO chat.generation_states( \
             conversation_id, generation, state_version, group_id, epoch, group_context_hash, \
             confirmation_tag, lifecycle, state_kind, producing_transition_id, \
             public_snapshot_bytes, snapshot_sha256, tree_summary_bytes, tree_summary_sha256, \
             leaf_count, created_at \
         ) VALUES ($1,$2,$3,$4,$5,$6,$7,'active','policy',$8,$9,$10,$11,$12,$13,$14)",
    )
    .bind(conversation_id)
    .bind(gen)
    .bind(rem_sv)
    .bind(&group_id)
    .bind(epoch)
    .bind(&gch)
    .bind(&ct)
    .bind(rem_tid)
    .bind(&snap)
    .bind(&snap_sha)
    .bind(&tree)
    .bind(&tree_sha)
    .bind(leaf_count)
    .bind(now)
    .execute(&mut *tx)
    .await
    .map_err(|e| format!("insert remove state: {e}"))?;

    sqlx::query(
        "INSERT INTO chat.transitions( \
             transition_id, conversation_id, kind, actor_did, actor_device_id, actor_key_id, \
             actor_auth_generation, actor_role, actor_device_status, signed_request_bytes, \
             unsigned_projection_bytes, signing_transcript_bytes, request_digest, signature, \
             prior_generation, prior_state_version, next_generation, next_state_version, \
             entry_seq, accepted_at \
         ) VALUES ($1,$2,'policy',$3,$4,$5,1,'admin','active',$6,$6,$6,$7,$8,$9,$10,$9,$11,$12,$13)",
    )
    .bind(rem_tid)
    .bind(conversation_id)
    .bind(admin_did)
    .bind(admin_dev)
    .bind(&admin_kid)
    .bind(&req_bytes)
    .bind(req_digest.as_slice())
    .bind([0x66_u8; 64].as_slice())
    .bind(gen)
    .bind(cur_sv)
    .bind(rem_sv)
    .bind(rem_seq)
    .bind(now)
    .execute(&mut *tx)
    .await
    .map_err(|e| format!("insert remove transition: {e}"))?;

    sqlx::query(
        "INSERT INTO chat.entries( \
             conversation_id, seq, entry_id, entry_kind, accepted_payload_bytes, \
             accepted_payload_sha256, signed_request_bytes, request_digest, signature, \
             server_fields_bytes, outer_entry_fingerprint, actor_did, actor_device_id, \
             actor_key_id, actor_auth_generation, generation, state_version, transition_id, received_at \
         ) VALUES ($1,$2,$3,'blue.catbird.chat.defs#policyEntry',$4,$5,$6,$7,$8,$9,$5,$10,$11,$12,1,$13,$14,$15,$16)",
    )
    .bind(conversation_id)
    .bind(rem_seq)
    .bind(rem_eid)
    .bind(&payload)
    .bind(payload_sha.as_slice())
    .bind(&req_bytes)
    .bind(req_digest.as_slice())
    .bind([0x66_u8; 64].as_slice())
    .bind(&server_fields)
    .bind(admin_did)
    .bind(admin_dev)
    .bind(&admin_kid)
    .bind(gen)
    .bind(rem_sv)
    .bind(rem_tid)
    .bind(now)
    .execute(&mut *tx)
    .await
    .map_err(|e| format!("insert remove entry: {e}"))?;

    sqlx::query(
        "UPDATE chat.participants \
            SET current_membership = FALSE, removing_transition_id = $3, removing_seq = $4, removed_at = $5 \
          WHERE conversation_id = $1 AND user_did = $2 AND current_membership = TRUE",
    )
    .bind(conversation_id)
    .bind(member_did)
    .bind(rem_tid)
    .bind(rem_seq)
    .bind(now)
    .execute(&mut *tx)
    .await
    .map_err(|e| format!("terminalize removed participant: {e}"))?;

    sqlx::query("UPDATE chat.generations SET current_state_version = $3 WHERE conversation_id = $1 AND generation = $2")
        .bind(conversation_id)
        .bind(gen)
        .bind(rem_sv)
        .execute(&mut *tx)
        .await
        .map_err(|e| e.to_string())?;

    sqlx::query("UPDATE chat.conversations SET current_state_version = $2, next_entry_seq = $3 WHERE conversation_id = $1")
        .bind(conversation_id)
        .bind(rem_sv)
        .bind(rem_seq + 1)
        .execute(&mut *tx)
        .await
        .map_err(|e| e.to_string())?;

    tx.commit()
        .await
        .map_err(|e| format!("commit remove zero-leaf member: {e}"))?;
    Ok(())
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
        // A did:plc document from the directory, or a did:web one from its host.
        let document = match path.strip_prefix("/did:plc:") {
            Some(_) => Some(path.trim_start_matches('/').to_owned()),
            None if path == /* did-web-test */ "/.well-known/did.json" => {
                request.url.host_str().map(|host| format!("did:web:{host}"))
            }
            None => None,
        };
        if let Some(actor) = document {
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
