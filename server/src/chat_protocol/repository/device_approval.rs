// Transaction-owning cross-device enrollment approval (`blue.catbird.chat.approveDevice`, D-2).
//
// An already-active device on `actor_did` promotes a sibling `'pending_approval'`
// device on the same `actor_did` to `'active'` after verifying the sibling's
// `deviceId`, `keyId`, `signaturePublicKey`, and `authGeneration`. Self-approval
// (`actorDeviceId == targetDeviceId`) is rejected fail-closed (`InvalidRequest`),
// an already-active target returns `DeviceAlreadyActive`, and a revoked target
// returns `DeviceRevoked`.

use chrono::{DateTime, Utc};
use jacquard_common::deps::{bytes::Bytes, smol_str::SmolStr};
use jacquard_common::DefaultStr;
use sha2::{Digest, Sha256};
use sqlx::{Postgres, Transaction};
use thiserror::Error;
use uuid::Uuid;

use super::super::{
    dpop::VerifiedChatDeviceRequest,
    transcript::{
        CanonicalValueRef, SignedMutationKind, VerifiedMutationProjection, VerifiedSignedMutation,
    },
    validation::ed25519_key_id,
};
use super::{
    auth::CompletedIdempotentResponse,
    device_directory::DeviceDirectoryView,
    prelude::{
        complete_operation, lock_signed_operation_replay_authority, prepare_identity_scope_prelude,
        release_signed_operation_replay, CanonicalDeviceIdentity, CanonicalLockScope,
        LockedSignedOperationReplayAuthority, OperationReservationGuard, PreludeError,
        PreparedSignedOperation, PreparedSignedOperationState, SignedOperationReplayPostStateProof,
    },
};
use catbird_atproto::generated::blue_catbird::chat as chat_dto;

const APPROVE_DEVICE_NSID: &str = "blue.catbird.chat.approveDevice";
const DEVICE_APPROVAL_REPLAY_POST_STATE_DOMAIN: &[u8] =
    b"CATBIRD-CHAT-DEVICE-APPROVAL-REPLAY-POST-STATE\0";

#[derive(Debug, Error)]
pub(crate) enum DeviceApprovalFacadeError {
    #[error(transparent)]
    Prelude(#[from] PreludeError),
    #[error("device cannot approve itself")]
    SelfApproval,
    #[error("device approval target is missing")]
    TargetMissing,
    #[error("device approval target is already active")]
    TargetAlreadyActive,
    #[error("device approval target is revoked")]
    TargetRevoked,
    #[error("device approval target authentication generation changed")]
    AuthenticationGenerationConflict,
    #[error("device approval target key binding does not match stored key")]
    TargetBindingMismatch,
    #[error("device approval request or durable post-state is inconsistent")]
    Integrity,
    #[error("device approval database error: {0}")]
    Database(#[from] sqlx::Error),
}

pub(crate) enum DeviceApprovalTransactionOutcome {
    First {
        target_did: String,
        target_device_id: Uuid,
        status: i32,
        response_bytes: Vec<u8>,
    },
    Replay(CompletedIdempotentResponse),
}

struct ExactApprovalInput {
    operation_id: Uuid,
    actor_did: String,
    actor_device_id: Uuid,
    actor_key_id: String,
    actor_auth_generation: u64,
    target_did: String,
    target_device_id: Uuid,
    target_key_id: String,
    target_signing_public_key: [u8; 32],
    target_auth_generation: u64,
    signed_at: DateTime<Utc>,
    accepted_request_bytes: Vec<u8>,
    signing_transcript_bytes: Vec<u8>,
    request_digest: [u8; 32],
    accepted_request_sha256: [u8; 32],
    signature: [u8; 64],
}

fn exact_approval_input(
    mutation: &VerifiedSignedMutation,
) -> Result<ExactApprovalInput, DeviceApprovalFacadeError> {
    let body = match mutation.projection() {
        VerifiedMutationProjection::DeviceApproval(value) => value.body(),
        _ => return Err(DeviceApprovalFacadeError::Integrity),
    };
    let operation_id = match body.get("idempotencyKey") {
        Some(CanonicalValueRef::Uuid(value)) => Uuid::from_bytes(*value.as_bytes()),
        _ => return Err(DeviceApprovalFacadeError::Integrity),
    };
    let target_device_id = match body.get("targetDeviceId") {
        Some(CanonicalValueRef::Uuid(value)) => Uuid::from_bytes(*value.as_bytes()),
        _ => return Err(DeviceApprovalFacadeError::Integrity),
    };
    let target_key_id = match body.get("targetKeyId") {
        Some(CanonicalValueRef::Thumbprint(value)) => value.as_str().to_owned(),
        _ => return Err(DeviceApprovalFacadeError::Integrity),
    };
    let target_signing_public_key: [u8; 32] = match body.get("targetSignaturePublicKey") {
        Some(CanonicalValueRef::Bytes(bytes)) => bytes
            .try_into()
            .map_err(|_| DeviceApprovalFacadeError::TargetBindingMismatch)?,
        _ => return Err(DeviceApprovalFacadeError::Integrity),
    };
    let target_auth_generation = match body.get("targetAuthGeneration") {
        Some(CanonicalValueRef::Integer(value)) => value,
        _ => return Err(DeviceApprovalFacadeError::Integrity),
    };
    let accepted_request_bytes = mutation
        .accepted_wrapper_bytes()
        .filter(|bytes| !bytes.is_empty())
        .ok_or(DeviceApprovalFacadeError::Integrity)?
        .to_vec();
    if operation_id.get_version_num() != 4
        || target_device_id.get_version_num() != 4
        || target_auth_generation == 0
        || mutation.kind() != SignedMutationKind::DeviceApproval
    {
        return Err(DeviceApprovalFacadeError::Integrity);
    }
    let derived_key_id = ed25519_key_id(&target_signing_public_key)
        .map_err(|_| DeviceApprovalFacadeError::TargetBindingMismatch)?;
    if derived_key_id.as_str() != target_key_id {
        return Err(DeviceApprovalFacadeError::TargetBindingMismatch);
    }
    let actor_did = mutation.actor_did().as_str().to_owned();
    let actor_device_id = Uuid::from_bytes(*mutation.actor_device_id().as_bytes());
    if actor_device_id == target_device_id {
        return Err(DeviceApprovalFacadeError::SelfApproval);
    }
    Ok(ExactApprovalInput {
        operation_id,
        actor_did: actor_did.clone(),
        actor_device_id,
        actor_key_id: mutation.key_id().as_str().to_owned(),
        actor_auth_generation: mutation.auth_generation(),
        target_did: actor_did,
        target_device_id,
        target_key_id,
        target_signing_public_key,
        target_auth_generation,
        signed_at: mutation.signed_at().datetime(),
        accepted_request_sha256: Sha256::digest(&accepted_request_bytes).into(),
        accepted_request_bytes,
        signing_transcript_bytes: mutation.transcript_bytes().to_vec(),
        request_digest: *mutation.request_digest(),
        signature: *mutation.signature(),
    })
}

pub(crate) async fn execute_device_approval(
    transaction: &mut Transaction<'_, Postgres>,
    operation: PreparedSignedOperation,
) -> Result<DeviceApprovalTransactionOutcome, DeviceApprovalFacadeError> {
    match operation.into_state() {
        PreparedSignedOperationState::First {
            authority,
            reservation,
        } => execute_first_device_approval(transaction, authority, reservation).await,
        PreparedSignedOperationState::Replay { authority, replay } => {
            let locked =
                lock_signed_operation_replay_authority(transaction, authority, replay).await?;
            prepare_device_approval_replay(transaction, locked).await
        }
    }
}

#[derive(sqlx::FromRow)]
struct ApprovalTargetRow {
    device_id: Uuid,
    device_name: String,
    key_id: String,
    signing_public_key: Vec<u8>,
    auth_generation: i64,
    dpop_jkt: Option<String>,
    status: String,
    created_at: DateTime<Utc>,
    updated_at: DateTime<Utc>,
    last_active_at: DateTime<Utc>,
    dormant_at: Option<DateTime<Utc>>,
    device_revoked_at: Option<DateTime<Utc>>,
    key_revoked_at: Option<DateTime<Utc>>,
    capabilities_json: String,
    available_package_count: i64,
    reserved_package_count: i64,
    request_available_package_count: i64,
    request_reserved_package_count: i64,
}

async fn execute_first_device_approval(
    transaction: &mut Transaction<'_, Postgres>,
    authority: VerifiedChatDeviceRequest,
    reservation: OperationReservationGuard,
) -> Result<DeviceApprovalTransactionOutcome, DeviceApprovalFacadeError> {
    if authority.endpoint().as_str() != APPROVE_DEVICE_NSID {
        return Err(DeviceApprovalFacadeError::Integrity);
    }
    let input = exact_approval_input(
        authority
            .mutation()
            .ok_or(DeviceApprovalFacadeError::Integrity)?,
    )?;
    let lock_scope = CanonicalLockScope::new(
        vec![input.actor_did.clone()],
        vec![
            CanonicalDeviceIdentity::new(&input.actor_did, input.actor_device_id),
            CanonicalDeviceIdentity::new(&input.target_did, input.target_device_id),
        ],
    )?;
    let prepared = prepare_identity_scope_prelude(transaction, &authority, reservation, lock_scope)
        .await
        .map_err(|error| match error {
            PreludeError::MissingDevice => DeviceApprovalFacadeError::TargetMissing,
            other => DeviceApprovalFacadeError::Prelude(other),
        })?;
    let prepared = prepared.verify_device_approval_operation(
        input.operation_id,
        authority
            .mutation()
            .ok_or(DeviceApprovalFacadeError::Integrity)?,
    )?;

    let target: ApprovalTargetRow = sqlx::query_as(
        r#"
        SELECT device.device_id,
               device.device_name,
               device_key.key_id,
               device_key.signing_public_key,
               device.auth_generation,
               device.dpop_jkt,
               device.status,
               device.created_at,
               device.updated_at,
               device.last_active_at,
               device.dormant_at,
               device.revoked_at AS device_revoked_at,
               device_key.revoked_at AS key_revoked_at,
               device.capabilities::text AS capabilities_json,
               (SELECT count(*)
                  FROM chat.key_packages kp
                 WHERE kp.owner_did = device.user_did
                   AND kp.owner_device_id = device.device_id
                   AND kp.usage_scope = 'recovery' AND kp.status = 'available') AS available_package_count,
               (SELECT count(*)
                  FROM chat.key_packages kp
                 WHERE kp.owner_did = device.user_did
                   AND kp.owner_device_id = device.device_id
                   AND kp.usage_scope = 'recovery' AND kp.status = 'reserved') AS reserved_package_count,
               (SELECT count(*)
                  FROM chat.key_packages kp
                 WHERE kp.owner_did = device.user_did
                   AND kp.owner_device_id = device.device_id
                   AND kp.usage_scope = 'direct-request' AND kp.status = 'available') AS request_available_package_count,
               (SELECT count(*)
                  FROM chat.key_packages kp
                 WHERE kp.owner_did = device.user_did
                   AND kp.owner_device_id = device.device_id
                   AND kp.usage_scope = 'direct-request' AND kp.status = 'reserved') AS request_reserved_package_count
          FROM chat.devices device
          JOIN chat.device_keys device_key
            ON device_key.user_did = device.user_did
           AND device_key.device_id = device.device_id
           AND device_key.enrollment_auth_generation <= device.auth_generation
           AND NOT EXISTS (
               SELECT 1 FROM chat.device_keys newer
                WHERE newer.user_did = device_key.user_did
                  AND newer.device_id = device_key.device_id
                  AND newer.enrollment_auth_generation > device_key.enrollment_auth_generation
                  AND newer.enrollment_auth_generation <= device.auth_generation
           )
         WHERE device.user_did = $1
           AND device.device_id = $2
         FOR UPDATE OF device, device_key
        "#,
    )
    .bind(&input.target_did)
    .bind(input.target_device_id)
    .fetch_optional(&mut **transaction)
    .await?
    .ok_or(DeviceApprovalFacadeError::TargetMissing)?;

    match target.status.as_str() {
        "revoked" => return Err(DeviceApprovalFacadeError::TargetRevoked),
        "active" => return Err(DeviceApprovalFacadeError::TargetAlreadyActive),
        "pending_approval" => {}
        _ => return Err(DeviceApprovalFacadeError::Integrity),
    }
    if target.device_revoked_at.is_some() || target.key_revoked_at.is_some() {
        return Err(DeviceApprovalFacadeError::TargetRevoked);
    }
    let expected_target_gen = i64::try_from(input.target_auth_generation)
        .map_err(|_| DeviceApprovalFacadeError::AuthenticationGenerationConflict)?;
    if target.auth_generation != expected_target_gen {
        return Err(DeviceApprovalFacadeError::AuthenticationGenerationConflict);
    }
    if target.key_id != input.target_key_id
        || target.signing_public_key.as_slice() != input.target_signing_public_key.as_slice()
    {
        return Err(DeviceApprovalFacadeError::TargetBindingMismatch);
    }

    let trusted_instant = prepared.scope_authority().trusted_instant();
    let accepted_at = DateTime::from_timestamp_millis(trusted_instant.timestamp_millis())
        .ok_or(DeviceApprovalFacadeError::Integrity)?;
    if accepted_at < target.updated_at {
        return Err(DeviceApprovalFacadeError::Integrity);
    }
    let actor_auth_generation = i64::try_from(input.actor_auth_generation)
        .map_err(|_| DeviceApprovalFacadeError::Integrity)?;

    let updated = sqlx::query(
        r#"
        UPDATE chat.devices
           SET status = 'active',
               updated_at = $4
         WHERE user_did = $1
           AND device_id = $2
           AND status = 'pending_approval'
           AND auth_generation = $3
        "#,
    )
    .bind(&input.target_did)
    .bind(input.target_device_id)
    .bind(expected_target_gen)
    .bind(accepted_at)
    .execute(&mut **transaction)
    .await?;
    if updated.rows_affected() != 1 {
        return Err(DeviceApprovalFacadeError::Integrity);
    }

    sqlx::query(
        r#"
        INSERT INTO chat.device_approvals (
            approval_id, actor_did, actor_device_id, actor_key_id, actor_auth_generation,
            target_did, target_device_id, target_key_id, target_signing_public_key,
            target_auth_generation, accepted_request_bytes, signing_transcript_bytes,
            request_digest, signature, signed_at, accepted_at
        ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16)
        "#,
    )
    .bind(input.operation_id)
    .bind(&input.actor_did)
    .bind(input.actor_device_id)
    .bind(&input.actor_key_id)
    .bind(actor_auth_generation)
    .bind(&input.target_did)
    .bind(input.target_device_id)
    .bind(&input.target_key_id)
    .bind(input.target_signing_public_key.as_slice())
    .bind(expected_target_gen)
    .bind(&input.accepted_request_bytes)
    .bind(&input.signing_transcript_bytes)
    .bind(input.request_digest.as_slice())
    .bind(input.signature.as_slice())
    .bind(input.signed_at)
    .bind(accepted_at)
    .execute(&mut **transaction)
    .await?;

    let approved_view = DeviceDirectoryView {
        device_id: target.device_id,
        device_name: target.device_name,
        key_id: target.key_id,
        signing_public_key: target.signing_public_key,
        auth_generation: target.auth_generation,
        dpop_jkt: target.dpop_jkt,
        status: "active".to_owned(),
        created_at: target.created_at,
        updated_at: accepted_at,
        last_active_at: target.last_active_at,
        dormant_at: target.dormant_at,
        available_package_count: target.available_package_count,
        reserved_package_count: target.reserved_package_count,
        request_available_package_count: target.request_available_package_count,
        request_reserved_package_count: target.request_reserved_package_count,
        capabilities_json: target.capabilities_json,
    };
    let output = chat_dto::approve_device::ApproveDeviceOutput::<DefaultStr> {
        device: chat_dto::DeviceView {
            auth_generation: approved_view.auth_generation,
            available_package_count: approved_view.available_package_count,
            created_at: crate::sqlx_jacquard::chrono_to_datetime(approved_view.created_at),
            device_id: SmolStr::from(approved_view.device_id.to_string()),
            device_name: Some(SmolStr::from(approved_view.device_name.as_str())),
            dormant_at: approved_view
                .dormant_at
                .map(crate::sqlx_jacquard::chrono_to_datetime),
            key_id: SmolStr::from(approved_view.key_id.as_str()),
            last_active_at: Some(crate::sqlx_jacquard::chrono_to_datetime(
                approved_view.last_active_at,
            )),
            reserved_package_count: approved_view.reserved_package_count,
            signature_public_key: Bytes::from(approved_view.signing_public_key.clone()),
            status: SmolStr::from(approved_view.status.as_str()),
            updated_at: crate::sqlx_jacquard::chrono_to_datetime(approved_view.updated_at),
            extra_data: None,
        },
        extra_data: None,
    };
    let response_bytes =
        serde_json::to_vec(&output).map_err(|_| DeviceApprovalFacadeError::Integrity)?;
    let (scope, completion) = prepared.into_execution_parts();
    complete_operation(
        transaction,
        &authority,
        scope,
        completion,
        200,
        &response_bytes,
        None,
    )
    .await?;

    Ok(DeviceApprovalTransactionOutcome::First {
        target_did: input.target_did,
        target_device_id: input.target_device_id,
        status: 200,
        response_bytes,
    })
}

#[derive(sqlx::FromRow)]
struct DurableDeviceApprovalRow {
    approval_id: Uuid,
    actor_did: String,
    actor_device_id: Uuid,
    actor_key_id: String,
    actor_auth_generation: i64,
    target_did: String,
    target_device_id: Uuid,
    target_key_id: String,
    target_signing_public_key: Vec<u8>,
    target_auth_generation: i64,
    accepted_request_bytes: Vec<u8>,
    signing_transcript_bytes: Vec<u8>,
    request_digest: Vec<u8>,
    signature: Vec<u8>,
    signed_at: DateTime<Utc>,
    accepted_at: DateTime<Utc>,
}

pub(in crate::chat_protocol::repository) struct DeviceApprovalReplayPostStateProof {
    transaction_id: Box<str>,
    operation_id: Uuid,
    principal_did: Box<str>,
    request_digest: [u8; 32],
    accepted_request_sha256: [u8; 32],
    signature: [u8; 64],
    accepted_at: DateTime<Utc>,
    target_device_id: Uuid,
    expected_response_sha256: [u8; 32],
    expected_status: i32,
    post_state_digest: [u8; 32],
}

impl DeviceApprovalReplayPostStateProof {
    pub(in crate::chat_protocol::repository) fn transaction_id(&self) -> &str {
        &self.transaction_id
    }

    pub(in crate::chat_protocol::repository) fn operation_id(&self) -> Uuid {
        self.operation_id
    }

    pub(in crate::chat_protocol::repository) fn principal_did(&self) -> &str {
        &self.principal_did
    }

    pub(in crate::chat_protocol::repository) fn endpoint_nsid(&self) -> &str {
        APPROVE_DEVICE_NSID
    }

    pub(in crate::chat_protocol::repository) fn mutation_kind(&self) -> SignedMutationKind {
        SignedMutationKind::DeviceApproval
    }

    pub(in crate::chat_protocol::repository) fn request_digest(&self) -> &[u8; 32] {
        &self.request_digest
    }

    pub(in crate::chat_protocol::repository) fn accepted_request_sha256(&self) -> &[u8; 32] {
        &self.accepted_request_sha256
    }

    pub(in crate::chat_protocol::repository) fn signature(&self) -> &[u8; 64] {
        &self.signature
    }

    pub(in crate::chat_protocol::repository) fn expected_response_sha256(&self) -> &[u8; 32] {
        &self.expected_response_sha256
    }

    pub(in crate::chat_protocol::repository) fn expected_status(&self) -> i32 {
        self.expected_status
    }

    pub(in crate::chat_protocol::repository) fn post_state_digest(&self) -> &[u8; 32] {
        &self.post_state_digest
    }

    pub(in crate::chat_protocol::repository) fn validates_seal(&self) -> bool {
        self.post_state_digest
            == device_approval_replay_post_state_digest(
                &self.transaction_id,
                self.operation_id,
                &self.principal_did,
                &self.request_digest,
                &self.accepted_request_sha256,
                &self.signature,
                self.accepted_at,
                self.target_device_id,
                self.expected_status,
                &self.expected_response_sha256,
            )
    }
}

#[allow(clippy::too_many_arguments)]
fn device_approval_replay_post_state_digest(
    transaction_id: &str,
    operation_id: Uuid,
    principal_did: &str,
    request_digest: &[u8; 32],
    accepted_request_sha256: &[u8; 32],
    signature: &[u8; 64],
    accepted_at: DateTime<Utc>,
    target_device_id: Uuid,
    expected_status: i32,
    expected_response_sha256: &[u8; 32],
) -> [u8; 32] {
    let mut digest = Sha256::new();
    digest.update(DEVICE_APPROVAL_REPLAY_POST_STATE_DOMAIN);
    for value in [transaction_id.as_bytes(), principal_did.as_bytes()] {
        digest.update((value.len() as u64).to_be_bytes());
        digest.update(value);
    }
    digest.update(operation_id.as_bytes());
    digest.update(request_digest);
    digest.update(accepted_request_sha256);
    digest.update(signature);
    digest.update(accepted_at.timestamp_millis().to_be_bytes());
    digest.update(target_device_id.as_bytes());
    digest.update(expected_status.to_be_bytes());
    digest.update(expected_response_sha256);
    digest.finalize().into()
}

async fn prepare_device_approval_replay(
    transaction: &mut Transaction<'_, Postgres>,
    locked: LockedSignedOperationReplayAuthority,
) -> Result<DeviceApprovalTransactionOutcome, DeviceApprovalFacadeError> {
    let authority = locked.authority();
    if authority.endpoint().as_str() != APPROVE_DEVICE_NSID {
        return Err(DeviceApprovalFacadeError::Integrity);
    }
    let input = exact_approval_input(authority.mutation())?;
    if authority.subject().as_str() != input.actor_did
        || Uuid::from_bytes(*authority.device_id().as_bytes()) != input.actor_device_id
    {
        return Err(DeviceApprovalFacadeError::Integrity);
    }
    let transaction_id: String = sqlx::query_scalar("SELECT txid_current()::text")
        .fetch_one(&mut **transaction)
        .await?;
    let approval: DurableDeviceApprovalRow = sqlx::query_as(
        r#"
        SELECT approval_id, actor_did, actor_device_id, actor_key_id,
               actor_auth_generation, target_did, target_device_id,
               target_key_id, target_signing_public_key, target_auth_generation,
               accepted_request_bytes, signing_transcript_bytes, request_digest,
               signature, signed_at, accepted_at
          FROM chat.device_approvals
         WHERE approval_id = $1
         FOR SHARE
        "#,
    )
    .bind(input.operation_id)
    .fetch_optional(&mut **transaction)
    .await?
    .ok_or(DeviceApprovalFacadeError::Integrity)?;

    let actor_auth_generation = i64::try_from(input.actor_auth_generation)
        .map_err(|_| DeviceApprovalFacadeError::Integrity)?;
    let target_auth_generation = i64::try_from(input.target_auth_generation)
        .map_err(|_| DeviceApprovalFacadeError::Integrity)?;
    if approval.approval_id != input.operation_id
        || approval.actor_did != input.actor_did
        || approval.actor_device_id != input.actor_device_id
        || approval.actor_key_id != input.actor_key_id
        || approval.actor_auth_generation != actor_auth_generation
        || approval.target_did != input.target_did
        || approval.target_device_id != input.target_device_id
        || approval.target_key_id != input.target_key_id
        || approval.target_signing_public_key.as_slice()
            != input.target_signing_public_key.as_slice()
        || approval.target_auth_generation != target_auth_generation
        || approval.accepted_request_bytes != input.accepted_request_bytes
        || approval.signing_transcript_bytes != input.signing_transcript_bytes
        || approval.request_digest.as_slice() != input.request_digest
        || approval.signature.as_slice() != input.signature
        || approval.signed_at != input.signed_at
    {
        return Err(DeviceApprovalFacadeError::Integrity);
    }

    let (current_status, current_updated_at, current_auth_gen): (String, DateTime<Utc>, i64) =
        sqlx::query_as(
            "SELECT status, updated_at, auth_generation FROM chat.devices WHERE user_did = $1 AND device_id = $2 FOR SHARE",
        )
        .bind(&input.target_did)
        .bind(input.target_device_id)
        .fetch_optional(&mut **transaction)
        .await?
        .ok_or(DeviceApprovalFacadeError::Integrity)?;
    if !matches!(current_status.as_str(), "active" | "revoked")
        || current_updated_at < approval.accepted_at
        || current_auth_gen < target_auth_generation
    {
        return Err(DeviceApprovalFacadeError::Integrity);
    }

    let stored_response_bytes: Vec<u8> = sqlx::query_scalar(
        "SELECT response_bytes FROM chat.idempotency_records WHERE principal_did = $1 AND endpoint_nsid = $2 AND operation_id = $3 FOR SHARE",
    )
    .bind(&input.actor_did)
    .bind(APPROVE_DEVICE_NSID)
    .bind(input.operation_id)
    .fetch_optional(&mut **transaction)
    .await?
    .flatten()
    .ok_or(DeviceApprovalFacadeError::Integrity)?;

    let decoded: chat_dto::approve_device::ApproveDeviceOutput<DefaultStr> =
        serde_json::from_slice(&stored_response_bytes)
            .map_err(|_| DeviceApprovalFacadeError::Integrity)?;
    if decoded.device.device_id.as_str() != input.target_device_id.to_string()
        || decoded.device.key_id.as_str() != input.target_key_id
        || decoded.device.signature_public_key.as_ref()
            != input.target_signing_public_key.as_slice()
        || decoded.device.auth_generation != target_auth_generation
        || decoded.device.status.as_str() != "active"
        || decoded.device.updated_at
            != crate::sqlx_jacquard::chrono_to_datetime(approval.accepted_at)
    {
        return Err(DeviceApprovalFacadeError::Integrity);
    }

    let expected_response_sha256: [u8; 32] = Sha256::digest(&stored_response_bytes).into();
    let post_state_digest = device_approval_replay_post_state_digest(
        &transaction_id,
        input.operation_id,
        &input.actor_did,
        &input.request_digest,
        &input.accepted_request_sha256,
        &input.signature,
        approval.accepted_at,
        input.target_device_id,
        200,
        &expected_response_sha256,
    );
    let post_state = DeviceApprovalReplayPostStateProof {
        transaction_id: transaction_id.into_boxed_str(),
        operation_id: input.operation_id,
        principal_did: input.actor_did.into_boxed_str(),
        request_digest: input.request_digest,
        accepted_request_sha256: input.accepted_request_sha256,
        signature: input.signature,
        accepted_at: approval.accepted_at,
        target_device_id: input.target_device_id,
        expected_response_sha256,
        expected_status: 200,
        post_state_digest,
    };
    let response = release_signed_operation_replay(
        transaction,
        locked,
        SignedOperationReplayPostStateProof::DeviceApproval(post_state),
    )
    .await?;
    if response.status() != 200
        || response.event_position().is_some()
        || response.completed_at() != approval.accepted_at
    {
        return Err(DeviceApprovalFacadeError::Integrity);
    }
    Ok(DeviceApprovalTransactionOutcome::Replay(response))
}
