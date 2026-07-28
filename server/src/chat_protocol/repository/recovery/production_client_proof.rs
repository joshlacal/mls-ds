// Client-shaped Recovery production-proof runners. These are gate-only and
// never manufacture relationship evidence, repository authority, a prelude,
// a private Recovery graph, or completion material.

use super::production_proof_fixture::{
    authorize, coordinate_json, leaf_recovery_cancellation, leaf_recovery_request,
    seed_durable_recovery_fixture_for_identity, DurableRecoveryFixture, FixtureIdentity,
    SignedRecoveryEnvelope,
};
use super::*;
use base64::{engine::general_purpose::STANDARD, Engine as _};
use chrono::{DateTime, SecondsFormat, Utc};
use serde_json::json;
use sqlx::{Executor, FromRow};
use uuid::Uuid;

const RECOVERY_ENDPOINT: &str = "blue.catbird.chat.requestLeafRecovery";
const DID_SET_MAGIC: &[u8] = b"CBDID001";

struct ClientRequestProof {
    fixture: DurableRecoveryFixture,
    trusted: TrustedRequestInstant,
    envelope: SignedRecoveryEnvelope,
    authority: VerifiedChatDeviceRequest,
    relationship_authority:
        crate::chat_protocol::relationship_policy::ProductionRelationshipAuthority,
}

fn singleton_fallback_did(bytes: &[u8]) -> Option<&str> {
    if bytes.len() < DID_SET_MAGIC.len() + 4
        || &bytes[..DID_SET_MAGIC.len()] != DID_SET_MAGIC
        || bytes[DID_SET_MAGIC.len()..DID_SET_MAGIC.len() + 2] != [0, 1]
    {
        return None;
    }
    let length = usize::from(u16::from_be_bytes([
        bytes[DID_SET_MAGIC.len() + 2],
        bytes[DID_SET_MAGIC.len() + 3],
    ]));
    let did = bytes.get(DID_SET_MAGIC.len() + 4..)?;
    (did.len() == length)
        .then(|| std::str::from_utf8(did).ok())
        .flatten()
}

/// Selects only an existing, fresh, immutable singleton recovery fallback.
/// A singleton is required because the durable proof aggregate has one active
/// participant; production loading subsequently verifies this scope digest and
/// the fixed configuration fingerprint itself.
async fn fresh_singleton_fallback_identity(pool: &PgPool) -> Result<FixtureIdentity, String> {
    let sets: Vec<Vec<u8>> = sqlx::query_scalar(
        "SELECT canonical_did_set_bytes \
           FROM chat.relationship_projection_snapshots \
          WHERE operation_scope='recoveryReservation' \
            AND evidence_kind='fallback' \
            AND completed_at <= clock_timestamp() \
            AND clock_timestamp()-completed_at <= interval '60 seconds' \
          ORDER BY completed_at DESC,projection_revision DESC",
    )
    .fetch_all(pool)
    .await
    .map_err(|error| format!("inspect singleton Recovery fallback precondition: {error}"))?;
    let did = sets
        .iter()
        .filter_map(|set| singleton_fallback_did(set))
        .find(|did| crate::chat_protocol::validation::BareDid::parse(did).is_ok())
        .ok_or_else(|| {
            "client Recovery production proof requires a fresh persisted singleton \
             recoveryReservation fallback projection; it will not mint one"
                .to_owned()
        })?;
    FixtureIdentity::fresh_for_did(did, b"recovery-client-production-proof-fallback")
        .map_err(|error| format!("bind singleton Recovery fallback identity: {error}"))
}

fn production_relationship_authority(
) -> Result<crate::chat_protocol::relationship_policy::ProductionRelationshipAuthority, String> {
    let guard = crate::chat_protocol::repository::relationship::load_fixed_relationship_authority_startup_guard()
        .map_err(|error| format!("load fixed Recovery relationship authority: {error:?}"))?;
    Ok(crate::chat_protocol::relationship_policy::ProductionRelationshipAuthority::from_startup_guard(guard))
}

async fn new_client_request_proof(pool: &PgPool) -> Result<ClientRequestProof, String> {
    require_local_owned_gate(pool).await?;
    let identity = fresh_singleton_fallback_identity(pool).await?;
    let trusted = TrustedRequestInstant::capture()
        .map_err(|error| format!("capture client Recovery proof instant: {error:?}"))?;
    let fixture = seed_durable_recovery_fixture_for_identity(pool, &trusted, identity).await?;
    let envelope = leaf_recovery_request(
        &fixture.identity,
        Uuid::new_v4(),
        coordinate_json(&fixture.prior),
        trusted.as_str(),
    )?;
    // Decode independently before the real authorizer does the same canonical
    // decode as part of normal Nest JWT + DPoP replay consumption.
    crate::chat_protocol::transcript::decode_canonical_signed_mutation(&envelope.raw_wrapper)
        .map_err(|error| format!("decode canonical client Recovery request: {error:?}"))?;
    let authority = authorize(
        pool,
        &fixture.identity,
        RECOVERY_ENDPOINT,
        &envelope,
        &trusted,
    )
    .await?;
    if authority.repository_receipt().operation_id() != Some(envelope.operation_id) {
        return Err("authorized Recovery request lost its canonical operation identity".to_owned());
    }
    Ok(ClientRequestProof {
        fixture,
        trusted,
        envelope,
        authority,
        relationship_authority: production_relationship_authority()?,
    })
}

async fn prepare_request(
    proof: &ClientRequestProof,
    transaction: &mut Transaction<'_, Postgres>,
) -> Result<PreparedRecoveryMutation, String> {
    let reservation = match crate::chat_protocol::repository::prelude::arbitrate_operation(
        transaction,
        &proof.authority,
    )
    .await
    .map_err(|error| format!("arbitrate client Recovery operation: {error:?}"))?
    {
        crate::chat_protocol::repository::prelude::OperationArbitration::First(value) => value,
        crate::chat_protocol::repository::prelude::OperationArbitration::Replay(_) => {
            return Err("fresh client Recovery proof unexpectedly replayed".to_owned())
        }
    };
    let prelude = crate::chat_protocol::repository::prelude::prepare_actor_prelude(
        transaction,
        &proof.authority,
        reservation,
    )
    .await
    .map_err(|error| format!("prepare client Recovery actor/scope prelude: {error:?}"))?;
    let mutation = proof
        .authority
        .mutation()
        .ok_or_else(|| "authorized Recovery request lacks canonical mutation".to_owned())?;
    let authority = prepare_recovery_request_authority(transaction, prelude, mutation)
        .await
        .map_err(|error| format!("prepare client Recovery authority: {error:?}"))?;
    let input = authority
        .into_plan_input(transaction, &proof.relationship_authority, &proof.trusted)
        .await
        .map_err(|error| format!("load immutable client Recovery fallback: {error:?}"))?;
    plan_recovery_request(input, &proof.relationship_authority)
        .map_err(|error| format!("plan client Recovery request: {error:?}"))
}

#[derive(FromRow)]
struct ResponseRow {
    conversation_id: Uuid,
    requester_did: String,
    requester_device_id: Uuid,
    requester_key_id: String,
    requester_auth_generation: i64,
    recovery_kind: String,
    request_status: String,
    requested_at: DateTime<Utc>,
    expires_at: DateTime<Utc>,
    reservation_status: String,
    key_package_ref: Vec<u8>,
    wrapper_bytes: Vec<u8>,
    wrapper_sha256: Vec<u8>,
}

async fn exact_request_response(
    transaction: &mut Transaction<'_, Postgres>,
    proof: &ClientRequestProof,
) -> Result<Vec<u8>, String> {
    exact_recovery_view_response(transaction, proof, "open", "active").await
}

/// Serialize the endpoint's exact `{recovery: leafRecoveryView}` from the
/// terminal rows, never from a hand-written status surrogate.
async fn exact_recovery_view_response(
    transaction: &mut Transaction<'_, Postgres>,
    proof: &ClientRequestProof,
    expected_request_status: &str,
    expected_reservation_status: &str,
) -> Result<Vec<u8>, String> {
    let row: ResponseRow = sqlx::query_as(
        "SELECT request.conversation_id,request.requester_did,request.requester_device_id,\
                request.requester_key_id,request.requester_auth_generation,request.recovery_kind,\
                request.status AS request_status,request.requested_at,request.expires_at,\
                reservation.status AS reservation_status,package.key_package_ref,\
                package.wrapper_bytes,package.wrapper_sha256 \
           FROM chat.leaf_recovery_requests request \
           JOIN chat.key_package_reservations reservation \
             ON reservation.recovery_request_id=request.recovery_request_id \
           JOIN chat.key_packages package ON package.key_package_ref=request.key_package_ref \
          WHERE request.recovery_request_id=$1",
    )
    .bind(proof.envelope.operation_id)
    .fetch_one(&mut **transaction)
    .await
    .map_err(|error| format!("read exact client Recovery response: {error}"))?;
    if row.conversation_id != proof.fixture.conversation_id
        || row.requester_did != proof.fixture.identity.did
        || row.requester_device_id != proof.fixture.identity.device_id
        || row.requester_key_id != proof.fixture.identity.key_id
        || row.requester_auth_generation != 1
        || row.recovery_kind != "replace"
        || row.request_status != expected_request_status
        || row.reservation_status != expected_reservation_status
        || row.key_package_ref.as_slice() != proof.fixture.available_key_package_ref
        || row.wrapper_bytes != proof.fixture.available_key_package_wrapper
    {
        return Err(
            "client Recovery view rows do not exactly match the persisted fixture".to_owned(),
        );
    }
    let prior = coordinate_json(&proof.fixture.prior);
    serde_json::to_vec(&json!({"recovery": {
        "recoveryRequestId": proof.envelope.operation_id.hyphenated().to_string(),
        "conversationId": row.conversation_id.hyphenated().to_string(),
        "requesterDid": row.requester_did,
        "requesterDeviceId": row.requester_device_id.hyphenated().to_string(),
        "recoveryKind": row.recovery_kind,
        "boundCoordinate": prior,
        "reservation": {
            "recoveryRequestId": proof.envelope.operation_id.hyphenated().to_string(),
            "conversationId": row.conversation_id.hyphenated().to_string(),
            "boundCoordinate": coordinate_json(&proof.fixture.prior),
            "requesterDid": proof.fixture.identity.did,
            "requesterDeviceId": proof.fixture.identity.device_id.hyphenated().to_string(),
            "requesterKeyId": proof.fixture.identity.key_id,
            "requesterAuthGeneration": 1,
            "keyPackageRef": STANDARD.encode(&row.key_package_ref),
            "cipherSuite": "MLS_256_XWING_CHACHA20POLY1305_SHA256_Ed25519",
            "purpose": "leafRecovery",
            "status": row.reservation_status,
            "expiresAt": row.expires_at.to_rfc3339_opts(SecondsFormat::Millis, true),
            "keyPackage": {"framing":"mlsMessage","contentType":"keyPackage",
                "bytes":STANDARD.encode(&row.wrapper_bytes),
                "sha256":STANDARD.encode(&row.wrapper_sha256),
                "keyPackageRef":STANDARD.encode(&row.key_package_ref)}
        },
        "status": row.request_status,
        "requestedAt": row.requested_at.to_rfc3339_opts(SecondsFormat::Millis, true),
        "expiresAt": row.expires_at.to_rfc3339_opts(SecondsFormat::Millis, true)
    }}))
    .map_err(|error| format!("encode exact client Recovery response: {error}"))
}

async fn require_exact_completion_response(
    transaction: &mut Transaction<'_, Postgres>,
    operation_id: Uuid,
    response: &[u8],
) -> Result<(), String> {
    let stored: Vec<u8> = sqlx::query_scalar(
        "SELECT response_bytes FROM chat.idempotency_records WHERE operation_id=$1",
    )
    .bind(operation_id)
    .fetch_one(&mut **transaction)
    .await
    .map_err(|error| format!("read exact terminal Recovery completion: {error}"))?;
    (stored == response)
        .then_some(())
        .ok_or_else(|| "terminal Recovery completion bytes were not exact".to_owned())
}

async fn corrupt_operation_claim(
    transaction: &mut Transaction<'_, Postgres>,
    operation_id: Uuid,
) -> Result<(), String> {
    sqlx::query("SET LOCAL session_replication_role='replica'")
        .execute(&mut **transaction)
        .await
        .map_err(|e| format!("enter claim drift: {e}"))?;
    let changed = sqlx::query("UPDATE chat.operation_claims SET claimed_at=claimed_at+interval '1 millisecond' WHERE operation_id=$1")
        .bind(operation_id).execute(&mut **transaction).await.map_err(|e| format!("drift operation claim: {e}"))?.rows_affected();
    sqlx::query("SET LOCAL session_replication_role='origin'")
        .execute(&mut **transaction)
        .await
        .map_err(|e| format!("leave claim drift: {e}"))?;
    (changed == 1)
        .then_some(())
        .ok_or_else(|| "operation-claim drift changed no exact row".to_owned())
}

async fn corrupt_scope_dpop(
    transaction: &mut Transaction<'_, Postgres>,
    proof: &ClientRequestProof,
) -> Result<(), String> {
    let alternate =
        if proof.fixture.identity.dpop_jkt() == "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB" {
            "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        } else {
            "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"
        };
    sqlx::query("SET LOCAL session_replication_role='replica'")
        .execute(&mut **transaction)
        .await
        .map_err(|e| format!("enter scope drift: {e}"))?;
    let changed =
        sqlx::query("UPDATE chat.devices SET dpop_jkt=$3 WHERE user_did=$1 AND device_id=$2")
            .bind(&proof.fixture.identity.did)
            .bind(proof.fixture.identity.device_id)
            .bind(alternate)
            .execute(&mut **transaction)
            .await
            .map_err(|e| format!("drift canonical scope: {e}"))?
            .rows_affected();
    sqlx::query("SET LOCAL session_replication_role='origin'")
        .execute(&mut **transaction)
        .await
        .map_err(|e| format!("leave scope drift: {e}"))?;
    (changed == 1)
        .then_some(())
        .ok_or_else(|| "canonical-scope drift changed no exact row".to_owned())
}

fn require_prewrite_authority_mismatch(error: RecoveryRepositoryError) -> Result<(), String> {
    matches!(
        error,
        RecoveryRepositoryError::ExecutionHydration(
            ExecutionContextHydrationError::AuthorityMismatch
        )
    )
    .then_some(())
    .ok_or_else(|| format!("expected executor-prewrite AuthorityMismatch, got {error:?}"))
}

#[derive(Debug, Eq, PartialEq)]
struct ClientResidue {
    target_request: i64,
    target_reservation: i64,
    target_request_status: Option<String>,
    target_reservation_status: Option<String>,
    completion: i64,
    operation_claim: i64,
    event: i64,
    outbox: i64,
    package_status: String,
    actor_dpop_jkt: String,
}

async fn observe_client_residue<'e, E>(
    executor: E,
    fixture: &DurableRecoveryFixture,
    operation_id: Uuid,
    target_request_id: Uuid,
) -> Result<ClientResidue, String>
where
    E: Executor<'e, Database = Postgres>,
{
    let (target_request, target_reservation, target_request_status, target_reservation_status, completion, operation_claim, event, outbox, package_status, actor_dpop_jkt):
        (i64, i64, Option<String>, Option<String>, i64, i64, i64, i64, String, String) = sqlx::query_as(
        "SELECT (SELECT count(*) FROM chat.leaf_recovery_requests WHERE recovery_request_id=$2),\
                (SELECT count(*) FROM chat.key_package_reservations WHERE recovery_request_id=$2),\
                (SELECT status FROM chat.leaf_recovery_requests WHERE recovery_request_id=$2),\
                (SELECT status FROM chat.key_package_reservations WHERE recovery_request_id=$2),\
                (SELECT count(*) FROM chat.idempotency_records WHERE operation_id=$1),\
                (SELECT count(*) FROM chat.operation_claims WHERE operation_id=$1),\
                (SELECT count(*) FROM chat.events event JOIN chat.conversations conversation\
                   ON conversation.protocol_instance_id=event.protocol_instance_id\
                  WHERE conversation.conversation_id=$3),\
                (SELECT count(*) FROM chat.outbox outbox JOIN chat.events event\
                   ON event.event_position=outbox.event_position JOIN chat.conversations conversation\
                   ON conversation.protocol_instance_id=event.protocol_instance_id\
                  WHERE conversation.conversation_id=$3),\
                (SELECT status FROM chat.key_packages WHERE key_package_ref=$4),\
                (SELECT dpop_jkt FROM chat.devices WHERE user_did=$5 AND device_id=$6)",
    )
    .bind(operation_id).bind(target_request_id).bind(fixture.conversation_id).bind(fixture.available_key_package_ref.as_slice())
    .bind(&fixture.identity.did).bind(fixture.identity.device_id)
    .fetch_one(executor).await.map_err(|e| format!("observe client Recovery residue: {e}"))?;
    Ok(ClientResidue {
        target_request,
        target_reservation,
        target_request_status,
        target_reservation_status,
        completion,
        operation_claim,
        event,
        outbox,
        package_status,
        actor_dpop_jkt,
    })
}

fn require_terminal_delta(
    before: &ClientResidue,
    after: &ClientResidue,
    request_status: &str,
    reservation_status: &str,
) -> Result<(), String> {
    let expected = ClientResidue {
        target_request: before.target_request,
        target_reservation: before.target_reservation,
        target_request_status: Some(request_status.to_owned()),
        target_reservation_status: Some(reservation_status.to_owned()),
        completion: before.completion + 1,
        operation_claim: before.operation_claim + 1,
        event: before.event + 1,
        outbox: before.outbox + 1,
        package_status: "available".to_owned(),
        actor_dpop_jkt: before.actor_dpop_jkt.clone(),
    };
    if after == &expected
        && before.target_request == 1
        && before.target_reservation == 1
        && before.target_request_status.as_deref() == Some("open")
        && before.target_reservation_status.as_deref() == Some("active")
        && before.completion == 0
        && before.operation_claim == 0
        && before.package_status == "available"
    {
        Ok(())
    } else {
        Err(format!(
            "client Recovery terminal mutation did not have the exact scoped delta before={before:?} after={after:?} expected={expected:?}"
        ))
    }
}

fn require_request_delta(before: &ClientResidue, after: &ClientResidue) -> Result<(), String> {
    let expected = ClientResidue {
        target_request: before.target_request + 1,
        target_reservation: before.target_reservation + 1,
        target_request_status: Some("open".to_owned()),
        target_reservation_status: Some("active".to_owned()),
        completion: before.completion + 1,
        operation_claim: before.operation_claim + 1,
        event: before.event + 1,
        outbox: before.outbox + 1,
        package_status: "reserved".to_owned(),
        actor_dpop_jkt: before.actor_dpop_jkt.clone(),
    };
    if after == &expected
        && before.target_request == 0
        && before.target_reservation == 0
        && before.target_request_status.is_none()
        && before.target_reservation_status.is_none()
        && before.completion == 0
        && before.operation_claim == 0
        && before.package_status == "available"
    {
        Ok(())
    } else {
        Err(format!(
            "client Recovery request did not have the exact scoped delta \
             before={before:?} after={after:?} expected={expected:?}"
        ))
    }
}

async fn require_exact_event_outbox(
    transaction: &mut Transaction<'_, Postgres>,
    fixture: &DurableRecoveryFixture,
    event_position: i64,
) -> Result<(), String> {
    let (kind, protocol_instance_id, outbox_count): (String, Uuid, i64) = sqlx::query_as(
        "SELECT event.event_kind,event.protocol_instance_id,\
                (SELECT count(*) FROM chat.outbox WHERE event_position=event.event_position)\
           FROM chat.events event\
          WHERE event.event_position=$1",
    )
    .bind(event_position)
    .fetch_one(&mut **transaction)
    .await
    .map_err(|error| format!("read exact Recovery event/outbox linkage: {error}"))?;
    let expected_protocol_instance_id: Uuid = sqlx::query_scalar(
        "SELECT protocol_instance_id FROM chat.conversations WHERE conversation_id=$1",
    )
    .bind(fixture.conversation_id)
    .fetch_one(&mut **transaction)
    .await
    .map_err(|error| format!("read Recovery fixture protocol instance: {error}"))?;
    if kind == "leafRecovery"
        && protocol_instance_id == expected_protocol_instance_id
        && outbox_count == 1
    {
        Ok(())
    } else {
        Err(format!(
            "unexpected Recovery event/outbox linkage position={event_position} kind={kind} \
             protocol_instance_id={protocol_instance_id} expected_protocol_instance_id={expected_protocol_instance_id} \
             outbox={outbox_count}"
        ))
    }
}

fn require_residue_unchanged(before: &ClientResidue, after: &ClientResidue) -> Result<(), String> {
    if before == after {
        Ok(())
    } else {
        Err(format!(
            "client Recovery rollback left scoped residue before={before:?} after={after:?}"
        ))
    }
}

#[doc(hidden)]
pub(super) async fn run_request_leaf_recovery_happy_path(pool: &PgPool) -> Result<(), String> {
    let proof = new_client_request_proof(pool).await?;
    let operation_id = proof.envelope.operation_id;
    let before =
        observe_client_residue(pool, &proof.fixture, operation_id, operation_id).await?;
    let mut transaction = pool
        .begin()
        .await
        .map_err(|e| format!("begin client Recovery proof: {e}"))?;
    let prepared = prepare_request(&proof, &mut transaction).await?;
    let applied = prepared
        .apply(&mut transaction)
        .await
        .map_err(|e| format!("apply client Recovery request: {e:?}"))?;
    let (transition, scope, completion, material) = client_completion(applied);
    if !matches!(material, RecoveryCanonicalMaterial::Requested { recovery_request_id } if recovery_request_id == proof.envelope.operation_id)
        || transition.event_positions.len() != 1
    {
        return Err(
            "client Recovery apply returned non-request material or wrong event count".to_owned(),
        );
    }
    require_exact_event_outbox(
        &mut transaction,
        &proof.fixture,
        transition.event_positions[0],
    )
    .await?;
    let response = exact_request_response(&mut transaction, &proof).await?;
    crate::chat_protocol::repository::prelude::complete_operation(
        &mut transaction,
        &proof.authority,
        scope,
        completion,
        200,
        &response,
        Some(transition.event_positions[0]),
    )
    .await
    .map_err(|e| format!("complete client Recovery operation: {e:?}"))?;
    let stored: Vec<u8> = sqlx::query_scalar(
        "SELECT response_bytes FROM chat.idempotency_records WHERE operation_id=$1",
    )
    .bind(proof.envelope.operation_id)
    .fetch_one(&mut *transaction)
    .await
    .map_err(|e| format!("read exact client Recovery completion: {e}"))?;
    if stored != response {
        return Err("client Recovery completion response was not exact".to_owned());
    }
    let during =
        observe_client_residue(&mut *transaction, &proof.fixture, operation_id, operation_id)
            .await?;
    require_request_delta(&before, &during)?;
    transaction
        .rollback()
        .await
        .map_err(|e| format!("rollback client Recovery happy proof: {e}"))?;
    let after = observe_client_residue(pool, &proof.fixture, operation_id, operation_id).await?;
    require_residue_unchanged(&before, &after)
}

async fn run_prewrite_drift(pool: &PgPool, scope: bool) -> Result<(), String> {
    let proof = new_client_request_proof(pool).await?;
    let operation_id = proof.envelope.operation_id;
    let before = observe_client_residue(pool, &proof.fixture, operation_id, operation_id).await?;
    let mut transaction = pool
        .begin()
        .await
        .map_err(|e| format!("begin client Recovery drift proof: {e}"))?;
    let prepared = prepare_request(&proof, &mut transaction).await?;
    if scope {
        corrupt_scope_dpop(&mut transaction, &proof).await?;
    } else {
        corrupt_operation_claim(&mut transaction, operation_id).await?;
    }
    let error = match prepared.apply(&mut transaction).await {
        Ok(_) => return Err("client Recovery drift reached executor writes".to_owned()),
        Err(error) => error,
    };
    require_prewrite_authority_mismatch(error)?;
    transaction
        .rollback()
        .await
        .map_err(|e| format!("rollback client Recovery drift proof: {e}"))?;
    require_residue_unchanged(
        &before,
        &observe_client_residue(pool, &proof.fixture, operation_id, operation_id).await?,
    )
}

#[doc(hidden)]
pub(super) async fn run_request_leaf_recovery_operation_claim_drift_negative(
    pool: &PgPool,
) -> Result<(), String> {
    run_prewrite_drift(pool, false).await
}

#[doc(hidden)]
pub(super) async fn run_request_leaf_recovery_scope_drift_negative(
    pool: &PgPool,
) -> Result<(), String> {
    run_prewrite_drift(pool, true).await
}

#[doc(hidden)]
pub(super) async fn run_request_leaf_recovery_completion_rollback_negative(
    pool: &PgPool,
) -> Result<(), String> {
    let proof = new_client_request_proof(pool).await?;
    // This independently verified request consumes a distinct committed auth
    // replay set. It is never used to plan; it is only the real mismatching
    // completion authority after A has successfully applied.
    let second = leaf_recovery_request(
        &proof.fixture.identity,
        Uuid::new_v4(),
        coordinate_json(&proof.fixture.prior),
        proof.trusted.as_str(),
    )?;
    let wrong_authority = authorize(
        pool,
        &proof.fixture.identity,
        RECOVERY_ENDPOINT,
        &second,
        &proof.trusted,
    )
    .await?;
    let operation_id = proof.envelope.operation_id;
    let before = observe_client_residue(pool, &proof.fixture, operation_id, operation_id).await?;
    let mut observer = pool
        .acquire()
        .await
        .map_err(|e| format!("acquire separate rollback observer: {e}"))?;
    let mut transaction = pool
        .begin()
        .await
        .map_err(|e| format!("begin completion rollback proof: {e}"))?;
    let prepared = prepare_request(&proof, &mut transaction).await?;
    let applied = prepared
        .apply(&mut transaction)
        .await
        .map_err(|e| format!("apply before completion mismatch: {e:?}"))?;
    let (transition, scope, completion, _) = client_completion(applied);
    let error = crate::chat_protocol::repository::prelude::complete_operation(
        &mut transaction,
        &wrong_authority,
        scope,
        completion,
        200,
        b"{}",
        Some(transition.event_positions[0]),
    )
    .await
    .expect_err("wrong verified completion authority must reject");
    if !matches!(
        error,
        crate::chat_protocol::repository::prelude::PreludeError::ForeignTransaction
    ) {
        return Err(format!(
            "expected post-apply completion ForeignTransaction, got {error:?}"
        ));
    }
    transaction
        .rollback()
        .await
        .map_err(|e| format!("rollback completion mismatch proof: {e}"))?;
    let after =
        observe_client_residue(&mut *observer, &proof.fixture, operation_id, operation_id).await?;
    require_residue_unchanged(&before, &after)
}

async fn commit_open_request(pool: &PgPool) -> Result<ClientRequestProof, String> {
    let proof = new_client_request_proof(pool).await?;
    let mut transaction = pool
        .begin()
        .await
        .map_err(|e| format!("begin durable client Recovery request: {e}"))?;
    let prepared = prepare_request(&proof, &mut transaction).await?;
    let applied = prepared
        .apply(&mut transaction)
        .await
        .map_err(|e| format!("apply durable client Recovery request: {e:?}"))?;
    let (transition, scope, completion, material) = client_completion(applied);
    if !matches!(material, RecoveryCanonicalMaterial::Requested { recovery_request_id } if recovery_request_id == proof.envelope.operation_id)
        || transition.event_positions.len() != 1
    {
        return Err("durable client Recovery request returned wrong material".to_owned());
    }
    let response = exact_request_response(&mut transaction, &proof).await?;
    crate::chat_protocol::repository::prelude::complete_operation(
        &mut transaction,
        &proof.authority,
        scope,
        completion,
        200,
        &response,
        Some(transition.event_positions[0]),
    )
    .await
    .map_err(|e| format!("complete durable client Recovery request: {e:?}"))?;
    transaction
        .commit()
        .await
        .map_err(|e| format!("commit durable client Recovery request: {e}"))?;
    Ok(proof)
}

async fn prepare_cancellation(
    proof: &ClientRequestProof,
    authority: &VerifiedChatDeviceRequest,
    trusted: &TrustedRequestInstant,
    transaction: &mut Transaction<'_, Postgres>,
) -> Result<RecoveryCancellationRead, String> {
    let reservation = match crate::chat_protocol::repository::prelude::arbitrate_operation(
        transaction,
        authority,
    )
    .await
    .map_err(|e| format!("arbitrate Recovery cancellation: {e:?}"))?
    {
        crate::chat_protocol::repository::prelude::OperationArbitration::First(value) => value,
        crate::chat_protocol::repository::prelude::OperationArbitration::Replay(_) => {
            return Err("fresh Recovery cancellation unexpectedly replayed".to_owned())
        }
    };
    let prelude = crate::chat_protocol::repository::prelude::prepare_actor_prelude(
        transaction,
        authority,
        reservation,
    )
    .await
    .map_err(|e| format!("prepare Recovery cancellation prelude: {e:?}"))?;
    let mutation = authority
        .mutation()
        .ok_or_else(|| "authorized Recovery cancellation lacks canonical mutation".to_owned())?;
    let read = prepare_recovery_cancellation_authority(transaction, prelude, mutation)
        .await
        .map_err(|e| format!("prepare Recovery cancellation authority: {e:?}"))?;
    let _ = (proof, trusted); // pins the caller's matching proof clock at this seam.
    Ok(read)
}

fn leaf_recovery_not_found_response() -> Result<Vec<u8>, String> {
    // This is exactly the public ChatFailure shape for the action-specific
    // post-apply error, not a terminal recovery success DTO.
    serde_json::to_vec(&json!({
        "error": "LeafRecoveryNotFound",
        "message": "LeafRecoveryNotFound",
    }))
    .map_err(|error| format!("encode LeafRecoveryNotFound response: {error}"))
}

async fn assert_terminal_triple(
    transaction: &mut Transaction<'_, Postgres>,
    proof: &ClientRequestProof,
    request_status: &str,
    reservation_status: &str,
) -> Result<(), String> {
    let (request, reservation, package): (String, String, String) = sqlx::query_as(
        "SELECT request.status,reservation.status,package.status \
           FROM chat.leaf_recovery_requests request \
           JOIN chat.key_package_reservations reservation USING(recovery_request_id) \
           JOIN chat.key_packages package ON package.key_package_ref=request.key_package_ref \
          WHERE request.recovery_request_id=$1",
    )
    .bind(proof.envelope.operation_id)
    .fetch_one(&mut **transaction)
    .await
    .map_err(|e| format!("read Recovery terminal triple: {e}"))?;
    if request == request_status && reservation == reservation_status && package == "available" {
        Ok(())
    } else {
        Err(format!("unexpected Recovery terminal triple request={request} reservation={reservation} package={package}"))
    }
}

#[doc(hidden)]
pub(super) async fn run_leaf_recovery_cancellation_happy_path(pool: &PgPool) -> Result<(), String> {
    let proof = commit_open_request(pool).await?;
    let trusted = TrustedRequestInstant::capture()
        .map_err(|e| format!("capture cancellation instant: {e:?}"))?;
    let envelope = leaf_recovery_cancellation(
        &proof.fixture.identity,
        proof.envelope.operation_id,
        trusted.as_str(),
    )?;
    if envelope.operation_id == proof.envelope.operation_id {
        return Err("cancellation reused target recovery operation id".to_owned());
    }
    let authority = authorize(
        pool,
        &proof.fixture.identity,
        "blue.catbird.chat.cancelLeafRecovery",
        &envelope,
        &trusted,
    )
    .await?;
    let before = observe_client_residue(
        pool,
        &proof.fixture,
        envelope.operation_id,
        proof.envelope.operation_id,
    )
    .await?;
    let mut transaction = pool
        .begin()
        .await
        .map_err(|e| format!("begin cancellation proof: {e}"))?;
    let read = prepare_cancellation(&proof, &authority, &trusted, &mut transaction).await?;
    let RecoveryCancellationRead::Execute(cancellation_authority) = read else {
        return Err("open Recovery cancellation did not produce Execute authority".to_owned());
    };
    let applied = cancellation(cancellation_authority, &mut transaction, &trusted)
        .await
        .map_err(|e| format!("apply Recovery cancellation: {e:?}"))?;
    let (transition, scope, completion, material) = client_completion(applied);
    if !matches!(material, RecoveryCanonicalMaterial::Cancelled { recovery_request_id } if recovery_request_id == proof.envelope.operation_id)
        || transition.event_positions.len() != 1
    {
        return Err("cancellation returned wrong material/event count".to_owned());
    }
    assert_terminal_triple(&mut transaction, &proof, "cancelled", "released").await?;
    require_exact_event_outbox(
        &mut transaction,
        &proof.fixture,
        transition.event_positions[0],
    )
    .await?;
    let response =
        exact_recovery_view_response(&mut transaction, &proof, "cancelled", "released").await?;
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
    .map_err(|e| format!("complete Recovery cancellation: {e:?}"))?;
    require_exact_completion_response(&mut transaction, envelope.operation_id, &response).await?;
    let during = observe_client_residue(
        &mut *transaction,
        &proof.fixture,
        envelope.operation_id,
        proof.envelope.operation_id,
    )
    .await?;
    require_terminal_delta(&before, &during, "cancelled", "released")?;
    transaction
        .rollback()
        .await
        .map_err(|e| format!("rollback cancellation proof: {e}"))?;
    require_residue_unchanged(
        &before,
        &observe_client_residue(
            pool,
            &proof.fixture,
            envelope.operation_id,
            proof.envelope.operation_id,
        )
        .await?,
    )
}

async fn force_due_boundary(
    pool: &PgPool,
    request_id: Uuid,
    at: &TrustedRequestInstant,
) -> Result<(), String> {
    require_local_owned_gate(pool).await?;
    let mut transaction = pool
        .begin()
        .await
        .map_err(|e| format!("begin due-boundary fixture mutation: {e}"))?;
    sqlx::query("SET LOCAL session_replication_role='replica'")
        .execute(&mut *transaction)
        .await
        .map_err(|e| format!("enter due-boundary fixture mutation: {e}"))?;
    let changed = sqlx::query(
        "UPDATE chat.leaf_recovery_requests SET expires_at=$2 WHERE recovery_request_id=$1",
    )
    .bind(request_id)
    .bind(at.datetime())
    .execute(&mut *transaction)
    .await
    .map_err(|e| format!("set exact request expiry boundary: {e}"))?
    .rows_affected();
    let reservation_changed = sqlx::query(
        "UPDATE chat.key_package_reservations SET expires_at=$2 WHERE recovery_request_id=$1",
    )
    .bind(request_id)
    .bind(at.datetime())
    .execute(&mut *transaction)
    .await
    .map_err(|e| format!("set exact reservation expiry boundary: {e}"))?
    .rows_affected();
    sqlx::query("SET LOCAL session_replication_role='origin'")
        .execute(&mut *transaction)
        .await
        .map_err(|e| format!("leave due-boundary fixture mutation: {e}"))?;
    if changed != 1 || reservation_changed != 1 {
        return Err(format!(
            "due-boundary fixture changed request={changed} reservation={reservation_changed}"
        ));
    }
    transaction
        .commit()
        .await
        .map_err(|e| format!("commit due-boundary fixture mutation: {e}"))
}

#[doc(hidden)]
pub(super) async fn run_leaf_recovery_cancellation_due_for_expiry_ordering(
    pool: &PgPool,
) -> Result<(), String> {
    let proof = commit_open_request(pool).await?;
    let trusted = TrustedRequestInstant::capture()
        .map_err(|e| format!("capture DueForExpiry instant: {e:?}"))?;
    force_due_boundary(pool, proof.envelope.operation_id, &trusted).await?;
    let envelope = leaf_recovery_cancellation(
        &proof.fixture.identity,
        proof.envelope.operation_id,
        trusted.as_str(),
    )?;
    if envelope.operation_id == proof.envelope.operation_id {
        return Err("DueForExpiry cancellation reused target recovery operation id".to_owned());
    }
    let authority = authorize(
        pool,
        &proof.fixture.identity,
        "blue.catbird.chat.cancelLeafRecovery",
        &envelope,
        &trusted,
    )
    .await?;
    let before = observe_client_residue(
        pool,
        &proof.fixture,
        envelope.operation_id,
        proof.envelope.operation_id,
    )
    .await?;
    let mut transaction = pool
        .begin()
        .await
        .map_err(|e| format!("begin DueForExpiry proof: {e}"))?;
    let read = prepare_cancellation(&proof, &authority, &trusted, &mut transaction).await?;
    let RecoveryCancellationRead::DueForExpiry(due) = read else {
        return Err("exact expiry boundary did not produce cancellation DueForExpiry".to_owned());
    };
    let applied = client_expiry(
        due.into_plan_input(&trusted)
            .map_err(|e| format!("build client expiry input: {e:?}"))?,
        &mut transaction,
    )
    .await
    .map_err(|e| format!("apply client Recovery expiry: {e:?}"))?;
    let (transition, scope, completion, material) = client_completion(applied);
    if !matches!(material, RecoveryCanonicalMaterial::ClientExpired { recovery_request_id, post_apply_error: RecoveryClientTerminalError::RecoveryNotFound, .. } if recovery_request_id == proof.envelope.operation_id)
        || transition.event_positions.len() != 1
    {
        return Err("client DueForExpiry returned wrong material/event count".to_owned());
    }
    assert_terminal_triple(&mut transaction, &proof, "expired", "expired").await?;
    require_exact_event_outbox(
        &mut transaction,
        &proof.fixture,
        transition.event_positions[0],
    )
    .await?;
    let response = leaf_recovery_not_found_response()?;
    crate::chat_protocol::repository::prelude::complete_operation(
        &mut transaction,
        &authority,
        scope,
        completion,
        404,
        &response,
        Some(transition.event_positions[0]),
    )
    .await
    .map_err(|e| format!("complete client Recovery expiry: {e:?}"))?;
    require_exact_completion_response(&mut transaction, envelope.operation_id, &response).await?;
    let during = observe_client_residue(
        &mut *transaction,
        &proof.fixture,
        envelope.operation_id,
        proof.envelope.operation_id,
    )
    .await?;
    require_terminal_delta(&before, &during, "expired", "expired")?;
    transaction
        .rollback()
        .await
        .map_err(|e| format!("rollback DueForExpiry proof: {e}"))?;
    require_residue_unchanged(
        &before,
        &observe_client_residue(
            pool,
            &proof.fixture,
            envelope.operation_id,
            proof.envelope.operation_id,
        )
        .await?,
    )
}
