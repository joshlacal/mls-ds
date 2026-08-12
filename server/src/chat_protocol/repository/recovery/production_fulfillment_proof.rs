// Production-shaped `submitRecoveryFulfillment` proof.
//
// This source is included only by `recovery::production_composition_proof`.
// It owns no authority constructor: both client operations cross ordinary
// Nest JWT + DPoP verification, repository authorization, operation
// arbitration, canonical identity-scope locking, Recovery hydration, the
// production relationship fallback loader, the private planner/executor graph,
// and operation completion.

use super::production_proof_fixture::{
    authorize, coordinate_json, leaf_recovery_fulfillment, leaf_recovery_request,
    seed_durable_recovery_fulfillment_fixture_for_identities, DurableRecoveryFulfillmentFixture,
    FixtureIdentity, SignedRecoveryEnvelope,
};
use super::*;
use base64::engine::general_purpose::STANDARD;
use serde_json::{json, Value};
use sha2::Sha256;
use sqlx::{FromRow, PgPool, Postgres, Transaction};
use uuid::Uuid;

const REQUEST_ENDPOINT: &str = "blue.catbird.chat.requestLeafRecovery";
const FULFILLMENT_ENDPOINT: &str = "blue.catbird.chat.submitTransition";
const FULFILLMENT_MUTATION_KIND: &str = "blue.catbird.chat.defs#leafRecoveryFulfillmentBody";
const DID_SET_MAGIC: &[u8] = b"CBDID001";

struct FulfillmentProof {
    fixture: DurableRecoveryFulfillmentFixture,
    relationship_authority:
        crate::chat_protocol::relationship_policy::ProductionRelationshipAuthority,
    request_trusted: TrustedRequestInstant,
    request: SignedRecoveryEnvelope,
    fulfillment_transition_id: Uuid,
}

fn parse_exact_two_party_did_set(bytes: &[u8]) -> Result<[String; 2], String> {
    if bytes.len() < DID_SET_MAGIC.len() + 2 || &bytes[..DID_SET_MAGIC.len()] != DID_SET_MAGIC {
        return Err("persisted relationship fallback has a noncanonical DID-set prefix".to_owned());
    }
    let mut cursor = DID_SET_MAGIC.len();
    let count = u16::from_be_bytes(
        bytes
            .get(cursor..cursor + 2)
            .ok_or_else(|| "persisted relationship fallback truncates its DID count".to_owned())?
            .try_into()
            .map_err(|_| "persisted relationship fallback has an invalid DID count".to_owned())?,
    );
    cursor += 2;
    if count != 2 {
        return Err(format!(
            "Recovery fulfillment production proof requires an exact two-party fallback, got {count} DIDs"
        ));
    }
    let mut dids = Vec::with_capacity(2);
    for _ in 0..count {
        let length = usize::from(u16::from_be_bytes(
            bytes
                .get(cursor..cursor + 2)
                .ok_or_else(|| "persisted relationship fallback truncates a DID length".to_owned())?
                .try_into()
                .map_err(|_| {
                    "persisted relationship fallback has an invalid DID length".to_owned()
                })?,
        ));
        cursor += 2;
        let did = std::str::from_utf8(
            bytes
                .get(cursor..cursor + length)
                .ok_or_else(|| "persisted relationship fallback truncates a DID".to_owned())?,
        )
        .map_err(|_| "persisted relationship fallback contains a non-UTF-8 DID".to_owned())?;
        crate::chat_protocol::validation::BareDid::parse(did)
            .map_err(|error| format!("parse persisted relationship fallback DID: {error:?}"))?;
        dids.push(did.to_owned());
        cursor += length;
    }
    if cursor != bytes.len() || dids[0].as_bytes() >= dids[1].as_bytes() || dids[0] == dids[1] {
        return Err(
            "persisted relationship fallback is not an exact canonical two-party DID set"
                .to_owned(),
        );
    }
    dids.try_into()
        .map_err(|_| "persisted relationship fallback did not yield two DIDs".to_owned())
}

/// Select one real, still-fresh pair of immutable fallback projections over
/// the same exact two-DID BlockOnly scope. The production loaders later lock,
/// validate, and consume each projection under the current startup guard.
async fn fresh_two_party_fallback_dids(pool: &PgPool) -> Result<[String; 2], String> {
    let rows: Vec<Vec<u8>> = sqlx::query_scalar(
        "SELECT reservation.canonical_did_set_bytes \
           FROM chat.relationship_projection_snapshots reservation \
           JOIN chat.relationship_projection_snapshots fulfillment \
             ON fulfillment.canonical_did_set_bytes=reservation.canonical_did_set_bytes \
            AND fulfillment.canonical_did_set_sha256=reservation.canonical_did_set_sha256 \
          WHERE reservation.operation_scope='recoveryReservation' \
            AND reservation.evidence_kind='fallback' \
            AND reservation.completed_at <= clock_timestamp() \
            AND clock_timestamp()-reservation.completed_at <= interval '60 seconds' \
            AND fulfillment.operation_scope='recoveryFulfillment' \
            AND fulfillment.evidence_kind='fallback' \
            AND fulfillment.completed_at <= clock_timestamp() \
            AND clock_timestamp()-fulfillment.completed_at <= interval '60 seconds' \
          ORDER BY LEAST(reservation.completed_at,fulfillment.completed_at) DESC, \
                   reservation.projection_revision DESC, \
                   fulfillment.projection_revision DESC",
    )
    .fetch_all(pool)
    .await
    .map_err(|error| format!("inspect Recovery fulfillment fallback prerequisites: {error}"))?;
    for row in rows {
        if let Ok(dids) = parse_exact_two_party_did_set(&row) {
            return Ok(dids);
        }
    }
    Err(
        "Recovery fulfillment production proof requires fresh persisted fallback projections \
         for both recoveryReservation and recoveryFulfillment over the same exact canonical \
         two-party DID set; it will not mint or weaken relationship evidence"
            .to_owned(),
    )
}

fn production_relationship_authority(
) -> Result<crate::chat_protocol::relationship_policy::ProductionRelationshipAuthority, String> {
    let guard =
        crate::chat_protocol::repository::relationship::load_fixed_relationship_authority_startup_guard()
            .map_err(|error| {
                format!("load fixed Recovery fulfillment relationship authority: {error:?}")
            })?;
    Ok(
        crate::chat_protocol::relationship_policy::ProductionRelationshipAuthority::from_startup_guard(
            guard,
        ),
    )
}

async fn prepare_request(
    transaction: &mut Transaction<'_, Postgres>,
    authority: &VerifiedChatDeviceRequest,
    relationship_authority: &crate::chat_protocol::relationship_policy::ProductionRelationshipAuthority,
    trusted: &TrustedRequestInstant,
) -> Result<PreparedRecoveryMutation, String> {
    let reservation = match crate::chat_protocol::repository::prelude::arbitrate_operation(
        transaction,
        authority,
    )
    .await
    .map_err(|error| format!("arbitrate committed Recovery prerequisite request: {error:?}"))?
    {
        crate::chat_protocol::repository::prelude::OperationArbitration::First(value) => value,
        crate::chat_protocol::repository::prelude::OperationArbitration::Replay(_) => {
            return Err(
                "fresh Recovery fulfillment prerequisite request unexpectedly replayed".to_owned(),
            )
        }
    };
    let prelude = crate::chat_protocol::repository::prelude::prepare_actor_prelude(
        transaction,
        authority,
        reservation,
    )
    .await
    .map_err(|error| format!("prepare Recovery prerequisite request prelude: {error:?}"))?;
    let mutation = authority.mutation().ok_or_else(|| {
        "authorized Recovery prerequisite lacks its canonical mutation".to_owned()
    })?;
    let authority = prepare_recovery_request_authority(transaction, prelude, mutation)
        .await
        .map_err(|error| format!("prepare Recovery prerequisite authority: {error:?}"))?;
    let input = authority
        .into_plan_input(transaction, relationship_authority, trusted)
        .await
        .map_err(|error| {
            format!("load immutable Recovery reservation fallback prerequisite: {error:?}")
        })?;
    plan_recovery_request(input, relationship_authority)
        .map_err(|error| format!("plan committed Recovery prerequisite request: {error:?}"))
}

async fn commit_request_prerequisite(
    pool: &PgPool,
    proof: &FulfillmentProof,
) -> Result<(), String> {
    let authority = authorize(
        pool,
        &proof.fixture.requester,
        REQUEST_ENDPOINT,
        &proof.request,
        &proof.request_trusted,
    )
    .await?;
    if authority.repository_receipt().operation_id() != Some(proof.request.operation_id) {
        return Err(
            "authorized Recovery prerequisite lost its canonical operation identity".to_owned(),
        );
    }
    let mut transaction = pool
        .begin()
        .await
        .map_err(|error| format!("begin committed Recovery prerequisite: {error}"))?;
    let prepared = prepare_request(
        &mut transaction,
        &authority,
        &proof.relationship_authority,
        &proof.request_trusted,
    )
    .await?;
    let applied = prepared
        .apply(&mut transaction)
        .await
        .map_err(|error| format!("apply committed Recovery prerequisite: {error:?}"))?;
    let (transition, scope, completion, material, response) = client_completion(applied);
    if !matches!(
        material,
        RecoveryCanonicalMaterial::Requested {
            recovery_request_id
        } if recovery_request_id == proof.request.operation_id
    ) || transition.event_positions.len() != 1
    {
        return Err(
            "Recovery prerequisite apply returned non-request material or wrong event count"
                .to_owned(),
        );
    }
    let response = response
        .filter(|response| response.endpoint() == RecoveryOperationEndpoint::RequestLeafRecovery)
        .ok_or_else(|| {
            "fulfillment prerequisite graph returned no canonical request response".to_owned()
        })?
        .as_bytes()
        .to_vec();
    crate::chat_protocol::repository::prelude::complete_operation(
        &mut transaction,
        &authority,
        scope,
        completion,
        200,
        &response,
        Some(transition.event_positions[0]),
    )
    .await
    .map_err(|error| format!("complete committed Recovery prerequisite: {error:?}"))?;
    let stored: Vec<u8> = sqlx::query_scalar(
        "SELECT response_bytes FROM chat.idempotency_records WHERE operation_id=$1",
    )
    .bind(proof.request.operation_id)
    .fetch_one(&mut *transaction)
    .await
    .map_err(|error| format!("read committed Recovery prerequisite receipt: {error}"))?;
    if stored != response {
        return Err("Recovery prerequisite completion bytes are not exact".to_owned());
    }
    transaction
        .commit()
        .await
        .map_err(|error| format!("commit genuine Recovery prerequisite request: {error}"))
}

fn fulfillment_body(proof: &FulfillmentProof, trusted: &TrustedRequestInstant) -> (Value, Uuid) {
    let requester = &proof.fixture.requester;
    let transition_id = proof.fulfillment_transition_id;
    let request_id = proof.request.operation_id;
    let welcome_id = Uuid::new_v4();
    let metadata_ciphertext = vec![0x64_u8; 16];
    let body = json!({
        "recoveryRequestId": request_id.hyphenated().to_string(),
        "transitionId": transition_id.hyphenated().to_string(),
        "prior": coordinate_json(&proof.fixture.prior),
        "next": coordinate_json(proof.fixture.next.coordinate()),
        "aad": {
            "protocolVersion": "1",
            "conversationId": STANDARD.encode(proof.fixture.conversation_id.as_bytes()),
            "generation": proof.fixture.prior.generation(),
            "transitionId": STANDARD.encode(transition_id.as_bytes()),
            "prior": {
                "conversationId": STANDARD.encode(proof.fixture.conversation_id.as_bytes()),
                "generation": proof.fixture.prior.generation(),
                "stateVersion": proof.fixture.prior.state_version(),
                "groupId": STANDARD.encode(proof.fixture.prior.group_id()),
                "epoch": proof.fixture.prior.epoch(),
                "groupContextHash": STANDARD.encode(proof.fixture.prior.group_context_hash()),
                "confirmationTag": STANDARD.encode(proof.fixture.prior.confirmation_tag()),
                "lifecycle": "active",
            },
        },
        "manifest": {
            "participantChanges": [],
            "leafChanges": [
                {
                    "$type": "blue.catbird.chat.defs#removeLeaf",
                    "userDid": requester.did,
                    "deviceId": requester.device_id.hyphenated().to_string(),
                },
                {
                    "$type": "blue.catbird.chat.defs#addLeafByRecovery",
                    "userDid": requester.did,
                    "deviceId": requester.device_id.hyphenated().to_string(),
                    "recoveryRequestId": request_id.hyphenated().to_string(),
                    "keyPackageRef": STANDARD.encode(proof.fixture.requester_key_package_ref),
                }
            ],
            "leafRecoveryRequestId": request_id.hyphenated().to_string(),
            "welcomeBundle": {
                "welcomeId": welcome_id.hyphenated().to_string(),
                "framing": "mlsMessage",
                "contentType": "welcome",
                "opaqueWelcome": STANDARD.encode(&proof.fixture.welcome),
                "sha256": STANDARD.encode(Sha256::digest(&proof.fixture.welcome)),
                "deliveries": [{
                    "recipientDid": requester.did,
                    "recipientDeviceId": requester.device_id.hyphenated().to_string(),
                    "provenance": {
                        "recoveryRequestId": request_id.hyphenated().to_string(),
                        "keyPackageRef": STANDARD.encode(proof.fixture.requester_key_package_ref),
                    },
                }],
            },
        },
        "commit": {
            "framing": "mlsMessage",
            "contentType": "publicMessageCommit",
            "bytes": STANDARD.encode(&proof.fixture.commit),
            "sha256": STANDARD.encode(Sha256::digest(&proof.fixture.commit)),
        },
        "metadataSnapshot": {
            "coordinate": {
                "conversationId": STANDARD.encode(proof.fixture.conversation_id.as_bytes()),
                "generation": proof.fixture.next.coordinate().generation(),
                "groupId": STANDARD.encode(proof.fixture.next.coordinate().group_id()),
                "epoch": proof.fixture.next.coordinate().epoch(),
                "groupContextHash": STANDARD.encode(
                    proof.fixture.next.coordinate().group_context_hash()
                ),
                "confirmationTag": STANDARD.encode(
                    proof.fixture.next.coordinate().confirmation_tag()
                ),
            },
            "originTransitionId": proof.fixture.creation_transition_id.hyphenated().to_string(),
            "metadataVersion": 1,
            "nonce": STANDARD.encode([0x63_u8; 12]),
            "ciphertext": STANDARD.encode(&metadata_ciphertext),
            "ciphertextSha256": STANDARD.encode(Sha256::digest(&metadata_ciphertext)),
            "ciphertextSize": metadata_ciphertext.len(),
            "authorProof": {
                "authorDid": requester.did,
                "authorDeviceId": requester.device_id.hyphenated().to_string(),
                "authorKeyId": requester.key_id,
                "signaturePublicKey": STANDARD.encode(requester.signing_public_key()),
                "authGenerationAtOrigin": 1,
                "originTransitionId": proof.fixture.creation_transition_id.hyphenated().to_string(),
                "originSeq": 1,
                "roleAtOrigin": "admin",
                "deviceStatusAtOrigin": "active",
            },
        },
        "idempotencyKey": transition_id.hyphenated().to_string(),
        "signedAt": trusted.as_str(),
    });
    (body, welcome_id)
}

#[derive(Debug, Eq, FromRow, PartialEq)]
struct FulfillmentResidue {
    generation: i64,
    state_version: i64,
    next_entry_seq: i64,
    protocol_instance_id: Uuid,
    request_status: String,
    reservation_status: String,
    package_status: String,
    fulfilling_transition_id: Option<Uuid>,
    reservation_transition_id: Option<Uuid>,
    package_transition_id: Option<Uuid>,
    generation_state_count: i64,
    transition_count: i64,
    entry_count: i64,
    welcome_count: i64,
    welcome_delivery_count: i64,
    event_count: i64,
    outbox_count: i64,
    claim_count: i64,
    exact_claim_binding_count: i64,
    completion_count: i64,
}

async fn observe_fulfillment_residue(
    transaction: &mut Transaction<'_, Postgres>,
    proof: &FulfillmentProof,
    envelope: &SignedRecoveryEnvelope,
    trusted: &TrustedRequestInstant,
) -> Result<FulfillmentResidue, String> {
    sqlx::query_as(
        "SELECT conversation.current_generation AS generation,\
                conversation.current_state_version AS state_version,\
                conversation.next_entry_seq,\
                (SELECT protocol_instance_id FROM chat.protocol_instances \
                  WHERE singleton) AS protocol_instance_id,\
                request.status AS request_status,reservation.status AS reservation_status,\
                package.status AS package_status,request.fulfilling_transition_id,\
                reservation.consumed_transition_id AS reservation_transition_id,\
                package.terminal_transition_id AS package_transition_id,\
                (SELECT count(*) FROM chat.generation_states state \
                  WHERE state.conversation_id=conversation.conversation_id)\
                    AS generation_state_count,\
                (SELECT count(*) FROM chat.transitions transition \
                  WHERE transition.conversation_id=conversation.conversation_id)\
                    AS transition_count,\
                (SELECT count(*) FROM chat.entries entry \
                  WHERE entry.conversation_id=conversation.conversation_id) AS entry_count,\
                (SELECT count(*) FROM chat.welcome_bundles welcome \
                  WHERE welcome.conversation_id=conversation.conversation_id) AS welcome_count,\
                (SELECT count(*) FROM chat.welcome_deliveries delivery \
                   JOIN chat.welcome_bundles welcome USING(welcome_id)\
                  WHERE welcome.conversation_id=conversation.conversation_id)\
                    AS welcome_delivery_count,\
                (SELECT count(*) FROM chat.events event \
                  WHERE event.protocol_instance_id=(SELECT protocol_instance_id \
                          FROM chat.protocol_instances WHERE singleton))\
                    AS event_count,\
                (SELECT count(*) FROM chat.outbox outbox \
                   JOIN chat.events event USING(event_position)\
                  WHERE event.protocol_instance_id=(SELECT protocol_instance_id \
                          FROM chat.protocol_instances WHERE singleton))\
                    AS outbox_count,\
                (SELECT count(*) FROM chat.operation_claims claim \
                  WHERE claim.operation_id=$2) AS claim_count,\
                (SELECT count(*) FROM chat.operation_claims claim \
                  WHERE claim.operation_id=$2 \
                    AND claim.principal_did=$3 \
                    AND claim.endpoint_nsid=$4 \
                    AND claim.mutation_kind=$5 \
                    AND claim.request_digest=$6 \
                    AND claim.accepted_request_sha256=$7 \
                    AND claim.signature=$8 \
                    AND claim.claimed_at=$9) AS exact_claim_binding_count,\
                (SELECT count(*) FROM chat.idempotency_records receipt \
                  WHERE receipt.operation_id=$2) AS completion_count \
           FROM chat.leaf_recovery_requests request \
           JOIN chat.key_package_reservations reservation \
             ON reservation.recovery_request_id=request.recovery_request_id \
           JOIN chat.key_packages package \
             ON package.key_package_ref=reservation.key_package_ref \
           JOIN chat.conversations conversation \
             ON conversation.conversation_id=request.conversation_id \
          WHERE request.recovery_request_id=$1",
    )
    .bind(proof.request.operation_id)
    .bind(proof.fulfillment_transition_id)
    .bind(&proof.fixture.fulfiller.did)
    .bind(FULFILLMENT_ENDPOINT)
    .bind(FULFILLMENT_MUTATION_KIND)
    .bind(envelope.request_digest.as_slice())
    .bind(Sha256::digest(&envelope.raw_wrapper).as_slice())
    .bind(envelope.signature.as_slice())
    .bind(trusted.datetime())
    .fetch_one(&mut **transaction)
    .await
    .map_err(|error| format!("observe Recovery fulfillment residue: {error}"))
}

async fn observe_fulfillment_residue_fresh(
    pool: &PgPool,
    proof: &FulfillmentProof,
    envelope: &SignedRecoveryEnvelope,
    trusted: &TrustedRequestInstant,
) -> Result<FulfillmentResidue, String> {
    let mut transaction = pool
        .begin()
        .await
        .map_err(|error| format!("begin fresh post-rollback fulfillment read: {error}"))?;
    let residue = observe_fulfillment_residue(&mut transaction, proof, envelope, trusted).await?;
    transaction
        .rollback()
        .await
        .map_err(|error| format!("rollback fresh post-rollback fulfillment read: {error}"))?;
    Ok(residue)
}

async fn require_exact_post_rollback_baseline(
    pool: &PgPool,
    proof: &FulfillmentProof,
    envelope: &SignedRecoveryEnvelope,
    trusted: &TrustedRequestInstant,
    baseline: &FulfillmentResidue,
) -> Result<(), String> {
    let fresh = observe_fulfillment_residue_fresh(pool, proof, envelope, trusted).await?;
    if fresh != *baseline {
        return Err(format!(
            "Recovery fulfillment rollback left claim/completion/business/event/outbox residue: \
             baseline={baseline:?} fresh={fresh:?}"
        ));
    }
    Ok(())
}

async fn verify_successor_and_delivery(
    transaction: &mut Transaction<'_, Postgres>,
    proof: &FulfillmentProof,
    applied: &AppliedTransition,
    before: &FulfillmentResidue,
    after: &FulfillmentResidue,
) -> Result<(), String> {
    let next = proof.fixture.next.coordinate();
    if applied.successor_coordinate.as_ref() != Some(next)
        || applied.allocated_seq
            != u64::try_from(before.next_entry_seq)
                .map_err(|_| "negative pre-fulfillment next entry sequence".to_owned())?
        || applied.entry_id != proof.fulfillment_transition_id
        || applied.event_positions.len() != 1
    {
        return Err(format!(
            "Recovery fulfillment returned the wrong applied transition: {applied:?}"
        ));
    }
    let successor_exact: bool = sqlx::query_scalar(
        "SELECT count(*)=1 AND bool_and(\
                group_id=$4 AND epoch=$5 AND group_context_hash=$6 AND confirmation_tag=$7 \
                AND lifecycle='active' AND state_kind='commit' \
                AND producing_transition_id=$8 AND public_snapshot_bytes=$9 \
                AND snapshot_sha256=$10 AND leaf_count=2) \
           FROM chat.generation_states \
          WHERE conversation_id=$1 AND generation=$2 AND state_version=$3",
    )
    .bind(proof.fixture.conversation_id)
    .bind(
        i64::try_from(next.generation())
            .map_err(|_| "successor generation overflows SQL".to_owned())?,
    )
    .bind(
        i64::try_from(next.state_version())
            .map_err(|_| "successor state version overflows SQL".to_owned())?,
    )
    .bind(next.group_id().as_slice())
    .bind(i64::try_from(next.epoch()).map_err(|_| "successor epoch overflows SQL".to_owned())?)
    .bind(next.group_context_hash().as_slice())
    .bind(next.confirmation_tag().as_slice())
    .bind(proof.fulfillment_transition_id)
    .bind(proof.fixture.next.snapshot())
    .bind(proof.fixture.next.snapshot_sha256().as_slice())
    .fetch_one(&mut **transaction)
    .await
    .map_err(|error| format!("verify exact Recovery successor state: {error}"))?;
    let event_position = applied.event_positions[0];
    let (event_kind, protocol_instance_id, recipient_rows, outbox_rows): (String, Uuid, i64, i64) =
        sqlx::query_as(
            "SELECT event.event_kind,event.protocol_instance_id,\
                (SELECT count(*) FROM chat.event_recipients recipient \
                  WHERE recipient.event_position=event.event_position),\
                (SELECT count(*) FROM chat.outbox outbox \
                  WHERE outbox.event_position=event.event_position) \
           FROM chat.events event WHERE event.event_position=$1",
        )
        .bind(event_position)
        .fetch_one(&mut **transaction)
        .await
        .map_err(|error| format!("verify Recovery fulfillment event topology: {error}"))?;
    if !successor_exact
        || after.generation
            != i64::try_from(next.generation())
                .map_err(|_| "successor generation overflows SQL".to_owned())?
        || after.state_version
            != i64::try_from(next.state_version())
                .map_err(|_| "successor state version overflows SQL".to_owned())?
        || after.next_entry_seq != before.next_entry_seq + 1
        || after.generation_state_count != before.generation_state_count + 1
        || after.transition_count != before.transition_count + 1
        || after.entry_count != before.entry_count + 1
        || after.welcome_count != before.welcome_count + 1
        || after.welcome_delivery_count != before.welcome_delivery_count + 1
        || after.event_count != before.event_count + 1
        || after.outbox_count != before.outbox_count + 1
        || after.claim_count != before.claim_count + 1
        || after.exact_claim_binding_count != before.exact_claim_binding_count + 1
        || after.completion_count != before.completion_count + 1
        || event_kind != "welcomeAvailable"
        || protocol_instance_id != before.protocol_instance_id
        || recipient_rows != 2
        || outbox_rows != 1
    {
        return Err(format!(
            "Recovery fulfillment successor/event/outbox/idempotency delta mismatch: \
             before={before:?} after={after:?} successor_exact={successor_exact} \
             event_kind={event_kind:?} protocol_instance_id={protocol_instance_id} \
             recipient_rows={recipient_rows} outbox_rows={outbox_rows}"
        ));
    }
    Ok(())
}

async fn prepare_fulfillment_read(
    transaction: &mut Transaction<'_, Postgres>,
    authority: &VerifiedChatDeviceRequest,
) -> Result<RecoveryFulfillmentRead, String> {
    let reservation = match crate::chat_protocol::repository::prelude::arbitrate_operation(
        transaction,
        authority,
    )
    .await
    .map_err(|error| format!("arbitrate Recovery fulfillment operation: {error:?}"))?
    {
        crate::chat_protocol::repository::prelude::OperationArbitration::First(value) => value,
        crate::chat_protocol::repository::prelude::OperationArbitration::Replay(_) => {
            return Err("fresh Recovery fulfillment unexpectedly replayed".to_owned())
        }
    };
    let mutation = authority
        .mutation()
        .ok_or_else(|| "authorized Recovery fulfillment lacks canonical mutation".to_owned())?;
    let scope = discover_recovery_fulfillment_terminal_scope(transaction, authority, mutation)
        .await
        .map_err(|error| format!("discover exact Recovery fulfillment scope: {error:?}"))?;
    let prelude = crate::chat_protocol::repository::prelude::prepare_identity_scope_prelude(
        transaction,
        authority,
        reservation,
        scope,
    )
    .await
    .map_err(|error| format!("prepare exact Recovery fulfillment scope prelude: {error:?}"))?;
    prepare_recovery_fulfillment_authority(transaction, prelude, mutation)
        .await
        .map_err(|error| format!("prepare Recovery fulfillment authority: {error:?}"))
}

async fn prepare_fulfillment(
    transaction: &mut Transaction<'_, Postgres>,
    authority: &VerifiedChatDeviceRequest,
    relationship_authority: &crate::chat_protocol::relationship_policy::ProductionRelationshipAuthority,
    trusted: &TrustedRequestInstant,
) -> Result<PreparedRecoveryMutation, String> {
    let authority = match prepare_fulfillment_read(transaction, authority).await? {
        RecoveryFulfillmentRead::Execute(authority) => authority,
        RecoveryFulfillmentRead::DueForExpiry(_) => {
            return Err(
                "fresh live Recovery fulfillment unexpectedly classified DueForExpiry".to_owned(),
            )
        }
        RecoveryFulfillmentRead::Classified(_) => {
            return Err(
                "fresh live Recovery fulfillment unexpectedly reached a retained classification"
                    .to_owned(),
            )
        }
    };
    let input = authority
        .into_plan_input(transaction, relationship_authority, trusted)
        .await
        .map_err(|error| {
            format!("load immutable Recovery fulfillment relationship fallback: {error:?}")
        })?;
    plan_recovery_fulfillment(input, relationship_authority)
        .map_err(|error| format!("plan genuine Recovery fulfillment: {error:?}"))
}

async fn new_fulfillment_proof(pool: &PgPool) -> Result<FulfillmentProof, String> {
    let dids = fresh_two_party_fallback_dids(pool).await?;
    let requester =
        FixtureIdentity::fresh_for_did(&dids[0], b"recovery-fulfillment-proof-requester")?;
    let fulfiller =
        FixtureIdentity::fresh_for_did(&dids[1], b"recovery-fulfillment-proof-fulfiller")?;
    let request_trusted = TrustedRequestInstant::capture()
        .map_err(|error| format!("capture Recovery prerequisite instant: {error:?}"))?;
    let fulfillment_transition_id = Uuid::new_v4();
    let fixture = seed_durable_recovery_fulfillment_fixture_for_identities(
        pool,
        &request_trusted,
        requester,
        fulfiller,
        fulfillment_transition_id,
    )
    .await?;
    let request = leaf_recovery_request(
        &fixture.requester,
        Uuid::new_v4(),
        coordinate_json(&fixture.prior),
        request_trusted.as_str(),
    )?;
    crate::chat_protocol::transcript::decode_canonical_signed_mutation(&request.raw_wrapper)
        .map_err(|error| format!("decode canonical Recovery prerequisite request: {error:?}"))?;
    Ok(FulfillmentProof {
        fixture,
        relationship_authority: production_relationship_authority()?,
        request_trusted,
        request,
        fulfillment_transition_id,
    })
}

#[doc(hidden)]
pub(super) async fn run_leaf_recovery_fulfillment_happy_path(pool: &PgPool) -> Result<(), String> {
    // The database ownership/locality guard is deliberately the first DB read.
    require_local_owned_gate(pool).await?;
    let proof = new_fulfillment_proof(pool).await?;
    commit_request_prerequisite(pool, &proof).await?;

    let trusted = TrustedRequestInstant::capture()
        .map_err(|error| format!("capture Recovery fulfillment instant: {error:?}"))?;
    let (body, _welcome_id) = fulfillment_body(&proof, &trusted);
    let envelope = leaf_recovery_fulfillment(&proof.fixture.fulfiller, body)?;
    if envelope.operation_id != proof.fulfillment_transition_id {
        return Err(
            "canonical Recovery fulfillment operation does not equal transitionId".to_owned(),
        );
    }
    crate::chat_protocol::transcript::decode_canonical_signed_mutation(&envelope.raw_wrapper)
        .map_err(|error| format!("decode canonical Recovery fulfillment: {error:?}"))?;
    let authority = authorize(
        pool,
        &proof.fixture.fulfiller,
        FULFILLMENT_ENDPOINT,
        &envelope,
        &trusted,
    )
    .await?;
    if authority.repository_receipt().operation_id() != Some(proof.fulfillment_transition_id) {
        return Err(
            "authorized Recovery fulfillment lost its canonical transition identity".to_owned(),
        );
    }

    let mut transaction = pool
        .begin()
        .await
        .map_err(|error| format!("begin Recovery fulfillment proof: {error}"))?;
    let before = observe_fulfillment_residue(&mut transaction, &proof, &envelope, &trusted).await?;
    if before.request_status != "open"
        || before.reservation_status != "active"
        || before.package_status != "reserved"
        || before.fulfilling_transition_id.is_some()
        || before.reservation_transition_id.is_some()
        || before.package_transition_id.is_some()
        || before.claim_count != 0
        || before.exact_claim_binding_count != 0
        || before.completion_count != 0
    {
        return Err(format!(
            "Recovery fulfillment prerequisite is not the exact open/active/reserved triple: \
             {before:?}"
        ));
    }
    let prepared = prepare_fulfillment(
        &mut transaction,
        &authority,
        &proof.relationship_authority,
        &trusted,
    )
    .await?;
    let applied = prepared
        .apply(&mut transaction)
        .await
        .map_err(|error| format!("apply genuine Recovery fulfillment: {error:?}"))?;
    let (transition, scope, completion, material, response) = client_completion(applied);
    if !matches!(
        material,
        RecoveryCanonicalMaterial::Fulfilled {
            recovery_request_id,
            transition_id,
        } if recovery_request_id == proof.request.operation_id
            && transition_id == proof.fulfillment_transition_id
    ) || transition.event_positions.len() != 1
    {
        return Err("Recovery fulfillment returned non-fulfillment canonical material".to_owned());
    }
    let response = response
        .filter(|response| {
            response.endpoint() == RecoveryOperationEndpoint::SubmitRecoveryFulfillment
        })
        .ok_or_else(|| {
            "fulfillment graph returned no canonical submitTransition response".to_owned()
        })?
        .as_bytes()
        .to_vec();
    crate::chat_protocol::repository::prelude::complete_operation(
        &mut transaction,
        &authority,
        scope,
        completion,
        200,
        &response,
        transition.event_positions.first().copied(),
    )
    .await
    .map_err(|error| format!("complete genuine Recovery fulfillment: {error:?}"))?;
    let after = observe_fulfillment_residue(&mut transaction, &proof, &envelope, &trusted).await?;
    if after.request_status != "fulfilled"
        || after.reservation_status != "consumed"
        || after.package_status != "consumed"
        || after.fulfilling_transition_id != Some(proof.fulfillment_transition_id)
        || after.reservation_transition_id != Some(proof.fulfillment_transition_id)
        || after.package_transition_id != Some(proof.fulfillment_transition_id)
    {
        return Err(format!(
            "Recovery fulfillment did not terminalize the exact Fulfilled/Consumed/Consumed triple: \
             {after:?}"
        ));
    }
    verify_successor_and_delivery(&mut transaction, &proof, &transition, &before, &after).await?;
    let stored: Vec<u8> = sqlx::query_scalar(
        "SELECT response_bytes FROM chat.idempotency_records WHERE operation_id=$1",
    )
    .bind(proof.fulfillment_transition_id)
    .fetch_one(&mut *transaction)
    .await
    .map_err(|error| format!("read exact Recovery fulfillment completion: {error}"))?;
    if stored != response {
        return Err("Recovery fulfillment completion response was not exact".to_owned());
    }
    transaction
        .rollback()
        .await
        .map_err(|error| format!("rollback Recovery fulfillment proof edge: {error}"))?;
    require_exact_post_rollback_baseline(pool, &proof, &envelope, &trusted, &before).await
}

/// Gate-fixture clock positioning shared in shape with the client cancellation
/// proof. It mutates only the already-committed proof request/reservation pair;
/// no relationship, identity, or authority row is fabricated.
async fn force_due_boundary(
    pool: &PgPool,
    request_id: Uuid,
    at: &TrustedRequestInstant,
) -> Result<(), String> {
    require_local_owned_gate(pool).await?;
    let mut transaction = pool
        .begin()
        .await
        .map_err(|error| format!("begin fulfillment DueForExpiry positioning: {error}"))?;
    sqlx::query("SET LOCAL session_replication_role='replica'")
        .execute(&mut *transaction)
        .await
        .map_err(|error| format!("enter fulfillment DueForExpiry positioning: {error}"))?;
    let request_rows = sqlx::query(
        "UPDATE chat.leaf_recovery_requests SET expires_at=$2 \
          WHERE recovery_request_id=$1 AND status='open'",
    )
    .bind(request_id)
    .bind(at.datetime())
    .execute(&mut *transaction)
    .await
    .map_err(|error| format!("position fulfillment request at exact expiry: {error}"))?
    .rows_affected();
    let reservation_rows = sqlx::query(
        "UPDATE chat.key_package_reservations SET expires_at=$2 \
          WHERE recovery_request_id=$1 AND status='active'",
    )
    .bind(request_id)
    .bind(at.datetime())
    .execute(&mut *transaction)
    .await
    .map_err(|error| format!("position fulfillment reservation at exact expiry: {error}"))?
    .rows_affected();
    sqlx::query("SET LOCAL session_replication_role='origin'")
        .execute(&mut *transaction)
        .await
        .map_err(|error| format!("leave fulfillment DueForExpiry positioning: {error}"))?;
    if request_rows != 1 || reservation_rows != 1 {
        return Err(format!(
            "fulfillment DueForExpiry positioning expected one exact pair, changed \
             request={request_rows} reservation={reservation_rows}"
        ));
    }
    transaction
        .commit()
        .await
        .map_err(|error| format!("commit fulfillment DueForExpiry positioning: {error}"))
}

async fn verify_due_for_expiry_delta(
    transaction: &mut Transaction<'_, Postgres>,
    applied: &AppliedTransition,
    before: &FulfillmentResidue,
    after: &FulfillmentResidue,
) -> Result<(), String> {
    if applied.event_positions.len() != 1 {
        return Err(format!(
            "fulfillment DueForExpiry emitted {} events, expected one",
            applied.event_positions.len()
        ));
    }
    let (event_kind, protocol_instance_id, outbox_rows): (String, Uuid, i64) = sqlx::query_as(
        "SELECT event.event_kind,event.protocol_instance_id,\
                    (SELECT count(*) FROM chat.outbox outbox \
                      WHERE outbox.event_position=event.event_position) \
               FROM chat.events event WHERE event.event_position=$1",
    )
    .bind(applied.event_positions[0])
    .fetch_one(&mut **transaction)
    .await
    .map_err(|error| format!("verify fulfillment DueForExpiry event: {error}"))?;
    if after.request_status != "expired"
        || after.reservation_status != "expired"
        || after.package_status != "available"
        || after.fulfilling_transition_id.is_some()
        || after.reservation_transition_id.is_some()
        || after.package_transition_id.is_some()
        || after.generation != before.generation
        || after.state_version != before.state_version
        || after.next_entry_seq != before.next_entry_seq
        || after.generation_state_count != before.generation_state_count
        || after.transition_count != before.transition_count
        || after.entry_count != before.entry_count
        || after.welcome_count != before.welcome_count
        || after.welcome_delivery_count != before.welcome_delivery_count
        || after.event_count != before.event_count + 1
        || after.outbox_count != before.outbox_count + 1
        || after.claim_count != before.claim_count + 1
        || after.exact_claim_binding_count != before.exact_claim_binding_count + 1
        || after.completion_count != before.completion_count + 1
        || event_kind != "leafRecovery"
        || protocol_instance_id != before.protocol_instance_id
        || outbox_rows != 1
    {
        return Err(format!(
            "fulfillment DueForExpiry delta mismatch: before={before:?} after={after:?} \
             event_kind={event_kind:?} protocol_instance_id={protocol_instance_id} \
             outbox_rows={outbox_rows}"
        ));
    }
    Ok(())
}

/// Proves that a genuine distinct-member fulfillment request reaching the
/// expiry boundary feeds the same sealed client-expiry planner/executor as the
/// cancellation path, while retaining the fulfiller+requester canonical scope.
#[doc(hidden)]
pub(super) async fn run_leaf_recovery_fulfillment_due_for_expiry_ordering(
    pool: &PgPool,
) -> Result<(), String> {
    require_local_owned_gate(pool).await?;
    let proof = new_fulfillment_proof(pool).await?;
    commit_request_prerequisite(pool, &proof).await?;
    let trusted = TrustedRequestInstant::capture()
        .map_err(|error| format!("capture fulfillment DueForExpiry instant: {error:?}"))?;
    force_due_boundary(pool, proof.request.operation_id, &trusted).await?;
    let (body, _) = fulfillment_body(&proof, &trusted);
    let envelope = leaf_recovery_fulfillment(&proof.fixture.fulfiller, body)?;
    if envelope.operation_id != proof.fulfillment_transition_id {
        return Err(
            "canonical DueForExpiry fulfillment operation does not equal transitionId".to_owned(),
        );
    }
    let authority = authorize(
        pool,
        &proof.fixture.fulfiller,
        FULFILLMENT_ENDPOINT,
        &envelope,
        &trusted,
    )
    .await?;
    if authority.repository_receipt().operation_id() != Some(proof.fulfillment_transition_id) {
        return Err(
            "authorized DueForExpiry fulfillment lost its canonical transition identity".to_owned(),
        );
    }
    let mut transaction = pool
        .begin()
        .await
        .map_err(|error| format!("begin fulfillment DueForExpiry proof: {error}"))?;
    let before = observe_fulfillment_residue(&mut transaction, &proof, &envelope, &trusted).await?;
    if before.request_status != "open"
        || before.reservation_status != "active"
        || before.package_status != "reserved"
        || before.fulfilling_transition_id.is_some()
        || before.reservation_transition_id.is_some()
        || before.package_transition_id.is_some()
        || before.claim_count != 0
        || before.exact_claim_binding_count != 0
        || before.completion_count != 0
    {
        return Err(format!(
            "DueForExpiry fulfillment prerequisite is not the exact open/active/reserved triple: \
             {before:?}"
        ));
    }
    let due = match prepare_fulfillment_read(&mut transaction, &authority).await? {
        RecoveryFulfillmentRead::DueForExpiry(due) => due,
        RecoveryFulfillmentRead::Execute(_) => {
            return Err("exact fulfillment expiry boundary incorrectly produced Execute".to_owned())
        }
        RecoveryFulfillmentRead::Classified(_) => {
            return Err(
                "exact fulfillment expiry boundary incorrectly produced retained classification"
                    .to_owned(),
            )
        }
    };
    let applied = plan_client_recovery_expiry(
        due.into_plan_input(&trusted)
            .map_err(|error| format!("build fulfillment client-expiry input: {error:?}"))?,
    )
    .map_err(|error| format!("plan fulfillment client expiry: {error:?}"))?
    .apply(&mut transaction)
    .await
    .map_err(|error| format!("apply fulfillment client expiry: {error:?}"))?;
    let (transition, scope, completion, material, response) = client_completion(applied);
    if response.is_some()
        || !matches!(
            material,
            RecoveryCanonicalMaterial::ClientExpired {
                recovery_request_id,
                post_apply_error: RecoveryClientTerminalError::RecoveryExpired,
                ..
            } if recovery_request_id == proof.request.operation_id
        )
        || transition.event_positions.len() != 1
    {
        return Err(
            "fulfillment DueForExpiry returned the wrong canonical material/event count".to_owned(),
        );
    }
    let response = serde_json::to_vec(&json!({
        "error": "LeafRecoveryExpired",
        "message": "the leaf recovery request expired before fulfillment",
    }))
    .map_err(|error| format!("encode fulfillment DueForExpiry response: {error}"))?;
    crate::chat_protocol::repository::prelude::complete_operation(
        &mut transaction,
        &authority,
        scope,
        completion,
        400,
        &response,
        Some(transition.event_positions[0]),
    )
    .await
    .map_err(|error| format!("complete fulfillment DueForExpiry operation: {error:?}"))?;
    let after = observe_fulfillment_residue(&mut transaction, &proof, &envelope, &trusted).await?;
    verify_due_for_expiry_delta(&mut transaction, &transition, &before, &after).await?;
    let stored: Vec<u8> = sqlx::query_scalar(
        "SELECT response_bytes FROM chat.idempotency_records WHERE operation_id=$1",
    )
    .bind(proof.fulfillment_transition_id)
    .fetch_one(&mut *transaction)
    .await
    .map_err(|error| format!("read exact fulfillment DueForExpiry completion: {error}"))?;
    if stored != response {
        return Err("fulfillment DueForExpiry completion response was not exact".to_owned());
    }
    transaction
        .rollback()
        .await
        .map_err(|error| format!("rollback fulfillment DueForExpiry proof edge: {error}"))?;
    require_exact_post_rollback_baseline(pool, &proof, &envelope, &trusted, &before).await
}
