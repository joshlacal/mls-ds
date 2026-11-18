//! Retention endpoints (`purgeMailbox`, `deleteAccountData`).

use std::sync::Arc;

use axum::{
    body::Bytes,
    extract::State,
    http::{HeaderMap, StatusCode},
    response::Response,
};
use ed25519_dalek::{Signature, VerifyingKey};
use serde::Deserialize;
use serde_json::json;

use super::params::{admit_procedure, begin_write};
use super::respond;
use crate::federation::receipt::{AccountDeletionActorWrite, AccountDeletionEvidence};
use crate::federation::space_read_relay::{
    fetch_chat_device_key_proof, fetch_chat_device_revocation_proof,
    verify_supplied_chat_device_key_proof, verify_supplied_chat_device_revocation_proof,
    SpaceRelayError,
};
use crate::handlers::chat::ChatRuntime;
use crate::labyrinth::auth;
use crate::labyrinth::error::{LabyrinthError, LabyrinthResult};
use crate::labyrinth::repo::retention as repo;
use crate::labyrinth::wire::io::{body, to_bytes};
use crate::storage::DbPool;

type Pool = State<DbPool>;
type Runtime = State<Arc<ChatRuntime>>;

/// An input object with no fields.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct EmptyIn {}

pub async fn purge_mailbox(
    State(pool): Pool,
    State(rt): Runtime,
    headers: HeaderMap,
    bytes: Bytes,
) -> Response {
    respond(
        async {
            let adm = admit_procedure(&pool, &rt, "purgeMailbox", &headers, &bytes).await?;
            let EmptyIn {} = body(&bytes)?;
            let mut w = begin_write!(&pool, adm);
            let caller = w.caller.clone();
            repo::purge_mailbox(&mut w.tx, &caller.did).await?;
            w.finish_write(to_bytes(&json!({}))?).await
        }
        .await,
    )
}

fn decode_optional_proof_header(
    headers: &HeaderMap,
    header_name: &str,
    label: &str,
) -> LabyrinthResult<Option<Vec<u8>>> {
    headers
        .get(header_name)
        .map(|value| {
            let value = value
                .to_str()
                .map_err(|_| LabyrinthError::invalid(format!("{label} is not base64url")))?;
            auth::decode_b64(label, value)
        })
        .transpose()
}

/// The evidence every `accountDeletedEntry` of this deletion carries: the exact
/// `labyrinthWriteBody` and signature `admit_procedure` verified, and the
/// device's optional `keyProof` and `revocationProof`, decoded from headers.
/// Supplied proofs are verified independently; absent ones are fetched from
/// the PDS before purge.
fn deletion_evidence(
    headers: &HeaderMap,
    bytes: &Bytes,
) -> LabyrinthResult<AccountDeletionEvidence> {
    let (write_body, signature) = auth::write_headers(headers)?;
    let key_proof = decode_optional_proof_header(headers, auth::KEY_PROOF_HEADER, "keyProof")?;
    let revocation_proof =
        decode_optional_proof_header(headers, auth::REVOCATION_PROOF_HEADER, "revocationProof")?;
    let evidence = AccountDeletionEvidence {
        actor_write: AccountDeletionActorWrite {
            write_body: auth::decode_b64(auth::WRITE_BODY_HEADER, &write_body)?,
            signature: auth::decode_b64(auth::WRITE_SIGNATURE_HEADER, &signature)?,
            payload_bytes: Some(bytes.to_vec()),
        },
        key_proof,
        revocation_proof,
    };
    evidence.check_shape().map_err(LabyrinthError::invalid)?;
    Ok(evidence)
}

fn key_proof_unavailable(error: SpaceRelayError) -> LabyrinthError {
    tracing::warn!(%error, "deleteAccountData refused: device repository proof unavailable");
    LabyrinthError::new(
        StatusCode::SERVICE_UNAVAILABLE,
        "ServiceUnavailable",
        "the deleting device's signed repository proof could not be verified; retry before removing the PDS repository",
    )
    .with_retry_after(5)
}

fn verify_admitted_key(
    evidence: &AccountDeletionEvidence,
    signing_key: &[u8; 32],
) -> LabyrinthResult<()> {
    let key = VerifyingKey::from_bytes(signing_key).map_err(|_| LabyrinthError::internal())?;
    let signature: [u8; 64] = evidence
        .actor_write
        .signature
        .as_slice()
        .try_into()
        .map_err(|_| LabyrinthError::invalid("write signature must be 64 bytes"))?;
    let mut message =
        Vec::with_capacity(auth::WRITE_DOMAIN.len() + evidence.actor_write.write_body.len());
    message.extend_from_slice(auth::WRITE_DOMAIN);
    message.extend_from_slice(&evidence.actor_write.write_body);
    key.verify_strict(&message, &Signature::from_bytes(&signature))
        .map_err(|_| {
            LabyrinthError::new(
                StatusCode::UNAUTHORIZED,
                "InvalidSignature",
                "deletion write no longer verifies under the current device key",
            )
        })
}

pub async fn delete_account_data(
    State(pool): Pool,
    State(rt): Runtime,
    headers: HeaderMap,
    bytes: Bytes,
) -> Response {
    respond(
        async {
            let adm = auth::admit_account_deletion(
                &pool,
                rt.cutover_enabled(),
                crate::federation::receipt::DELETE_ACCOUNT_DATA_NSID,
                &headers,
                &bytes,
            )
            .await?;
            let EmptyIn {} = body(&bytes)?;
            let require_completion = match headers.get("catbird-require-erasure-completion") {
                None => false,
                Some(value) if value == "1" => true,
                Some(_) => return Err(LabyrinthError::invalid("invalid hosted erasure completion preference")),
            };
            let completed = delete_admitted(&pool, &rt, &headers, &bytes, adm.clone()).await?;
            if !require_completion {
                return Ok(completed);
            }
            let operation = &adm.write.as_ref().ok_or_else(LabyrinthError::internal)?.operation_id;
            if repo::has_pending_peer_erasure(&pool, &adm.did, operation).await? {
                return Err(LabyrinthError::new(StatusCode::SERVICE_UNAVAILABLE, "PeerErasurePending",
                    "Remote erasure deliveries are pending. Keep the account and retry this operation.").with_retry_after(5));
            }
            // A local reply records admission. Legacy rows, an empty queue and first-hop
            // delivery cannot establish complete lifetime coverage or downstream erasure.
            Err(LabyrinthError::new(StatusCode::SERVICE_UNAVAILABLE, "PeerErasureUnverified",
                "Complete peer erasure cannot be verified. Keep the account available for recovery."))
        }
        .await,
    )
}

async fn delete_admitted(
    pool: &DbPool,
    rt: &ChatRuntime,
    headers: &HeaderMap,
    bytes: &Bytes,
    adm: auth::Admission,
) -> LabyrinthResult<Vec<u8>> {
    // A completed operation replays without asking a repository that may
    // have been deleted since the first call. A fresh probe releases its
    // device lock before any DID/PDS HTTP work (M-F04).
    let probe = begin_write!(pool, adm.clone());
    let admitted_key = probe.caller.signing_key;
    (*probe).abort().await?;
    let mut evidence = deletion_evidence(headers, bytes)?;
    verify_admitted_key(&evidence, &admitted_key)?;
    let resolver = match rt.resolver() {
        Some(resolver) => resolver,
        None => {
            if let Some(response) = auth::completed_write_for_admission(pool, &adm).await? {
                return Ok(response);
            }
            return Err(LabyrinthError::new(
                StatusCode::SERVICE_UNAVAILABLE,
                "ServiceUnavailable",
                "device repository proof resolver is unavailable",
            ));
        }
    };
    let device_id = adm.device_id.to_string();
    let has_supplied_key_proof = evidence.key_proof.is_some();
    let proof_result = match evidence.key_proof.take() {
        Some(proof) => verify_supplied_chat_device_key_proof(
            resolver,
            &adm.did,
            &device_id,
            &admitted_key,
            &proof,
        )
        .await
        .map(|()| proof),
        None => fetch_chat_device_key_proof(resolver, &adm.did, &device_id, &admitted_key).await,
    };
    let proof = match proof_result {
        Ok(proof) => proof,
        Err(error) => {
            // Another identical request may have committed while this
            // one was fetching. Return its result before requiring a
            // repository that deletion itself may have removed.
            if let Some(response) = auth::completed_write_for_admission(pool, &adm).await? {
                return Ok(response);
            }
            if has_supplied_key_proof {
                if let SpaceRelayError::InvalidRequest(msg) | SpaceRelayError::UpstreamError(msg) =
                    error
                {
                    return Err(LabyrinthError::invalid(msg));
                }
            }
            return Err(key_proof_unavailable(error));
        }
    };
    evidence.key_proof = Some(proof);
    let expected_operation_id = evidence.operation_id().map_err(LabyrinthError::invalid)?;
    let expected_signed_at = evidence.signed_at().map_err(LabyrinthError::invalid)?;
    let has_supplied_revocation_proof = evidence.revocation_proof.is_some();
    let revocation_result = match evidence.revocation_proof.take() {
        Some(proof) => verify_supplied_chat_device_revocation_proof(
            resolver,
            &adm.did,
            &device_id,
            &admitted_key,
            &expected_operation_id,
            expected_signed_at,
            &proof,
        )
        .await
        .map(|()| proof),
        None => {
            fetch_chat_device_revocation_proof(
                resolver,
                &adm.did,
                &device_id,
                &admitted_key,
                &expected_operation_id,
                expected_signed_at,
            )
            .await
        }
    };
    let revocation_proof = match revocation_result {
        Ok(proof) => proof,
        Err(SpaceRelayError::DeviceRevoked(reason)) => {
            tracing::warn!(%reason, "deleteAccountData refused: device revocation proof rejected device");
            if let Some(response) = auth::completed_write_for_admission(pool, &adm).await? {
                return Ok(response);
            }
            return Err(LabyrinthError::device_revoked());
        }
        Err(error) => {
            if let Some(response) = auth::completed_write_for_admission(pool, &adm).await? {
                return Ok(response);
            }
            if has_supplied_revocation_proof {
                if let SpaceRelayError::InvalidRequest(msg) | SpaceRelayError::UpstreamError(msg) =
                    error
                {
                    return Err(LabyrinthError::invalid(msg));
                }
            }
            return Err(key_proof_unavailable(error));
        }
    };
    evidence.revocation_proof = Some(revocation_proof);
    // Peer homes resolve over HTTP, so before the transaction opens (M-F04).
    let c33_peers = match repo::resolve_c33_peer_homes(pool, &adm.did).await {
        Ok(peers) => peers,
        Err(error) => {
            if let Some(response) = auth::completed_write_for_admission(pool, &adm).await? {
                return Ok(response);
            }
            return Err(error);
        }
    };
    let mut w = begin_write!(pool, adm);
    // The device row is locked again after the external read. A rotation
    // or revocation during that window cannot bind a proof for the old
    // key to a write admitted under the new one.
    if w.caller.signing_key != admitted_key {
        return Err(LabyrinthError::device_revoked());
    }
    let (caller, at) = (w.caller.clone(), w.instant);
    let sequenced = repo::purge_account_with_recovery(
        &mut w.tx,
        &caller.did,
        at,
        rt.i13_receipt_signer(),
        &c33_peers,
        Some(&evidence),
        rt.recovery_tombstones().map(Arc::as_ref),
    )
    .await?;
    let resp = w.finish_write(to_bytes(&json!({}))?).await?;
    if sequenced > 0 {
        rt.notify_events();
    }
    Ok(resp)
}
