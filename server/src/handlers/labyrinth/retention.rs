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
    fetch_chat_device_key_proof, verify_supplied_chat_device_key_proof, SpaceRelayError,
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

/// The evidence every `accountDeletedEntry` of this deletion carries: the exact
/// `labyrinthWriteBody` and signature `admit_procedure` verified, and the
/// device's optional `keyProof`, decoded from its header. A supplied proof is
/// verified independently; an absent one is fetched from the PDS before purge.
fn deletion_evidence(
    headers: &HeaderMap,
    bytes: &Bytes,
) -> LabyrinthResult<AccountDeletionEvidence> {
    let (write_body, signature) = auth::write_headers(headers)?;
    let key_proof = headers
        .get(auth::KEY_PROOF_HEADER)
        .map(|value| {
            let value = value
                .to_str()
                .map_err(|_| LabyrinthError::invalid("keyProof is not base64url"))?;
            auth::decode_b64("keyProof", value)
        })
        .transpose()?;
    let evidence = AccountDeletionEvidence {
        actor_write: AccountDeletionActorWrite {
            write_body: auth::decode_b64(auth::WRITE_BODY_HEADER, &write_body)?,
            signature: auth::decode_b64(auth::WRITE_SIGNATURE_HEADER, &signature)?,
            payload_bytes: Some(bytes.to_vec()),
        },
        key_proof,
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
            let admitted = auth::admit_account_deletion(
                &pool,
                rt.cutover_enabled(),
                crate::federation::receipt::DELETE_ACCOUNT_DATA_NSID,
                &headers,
                &bytes,
            )
            .await?;
            let EmptyIn {} = body(&bytes)?;
            let adm = match admitted {
                auth::AccountDeletionAdmission::Device(adm) => adm,
                // No local device can sign: only answer success if there is no
                // account data that a deletion could erase or label unsigned.
                auth::AccountDeletionAdmission::NeverEnrolled {
                    did,
                    principal,
                    intent_sha256,
                } => {
                    let mut tx = pool.begin().await?;
                    // Both local enrollment and remote device staging take
                    // this DID lock before their device/principal writes. It
                    // also works when there is no principal row to lock, and
                    // leaves no synthetic account row after deletion.
                    crate::chat_protocol::lock_account_lifecycle(&mut tx, &did).await?;
                    let enrolled: bool = sqlx::query_scalar(
                        "SELECT EXISTS(SELECT 1 FROM chat.devices WHERE user_did = $1)",
                    )
                    .bind(&did)
                    .fetch_one(&mut *tx)
                    .await?;
                    if enrolled {
                        return Err(LabyrinthError::not_authorized(
                            "a chat device enrolled during deletion; retry with its signed write",
                        ));
                    }
                    // Home-only indexes, transport inboxes, Space records,
                    // participants and old backups can name a DID without any
                    // local device. They must not be erased or labelled by an
                    // unsigned deletion. Signed chat entries require a device
                    // key by FK, so zero devices excludes authored entries.
                    let has_history: bool = sqlx::query_scalar(
                        "SELECT EXISTS(SELECT 1 FROM chat.principals WHERE user_did = $1) \
                             OR EXISTS(SELECT 1 FROM chat.participants WHERE user_did = $1) \
                             OR EXISTS(SELECT 1 FROM chat.conversations \
                                       WHERE direct_did_low = $1 OR direct_did_high = $1) \
                             OR EXISTS(SELECT 1 FROM chat.remote_group_memberships \
                                       WHERE user_did = $1) \
                             OR EXISTS(SELECT 1 FROM chat.direct_request_transport_inbox \
                                       WHERE sender_did = $1 OR recipient_did = $1) \
                             OR EXISTS(SELECT 1 FROM chat.direct_request_remote_leases \
                                       WHERE sender_did = $1 OR recipient_did = $1) \
                             OR EXISTS(SELECT 1 FROM chat.conversation_space_records \
                                       WHERE writer_did = $1) \
                             OR EXISTS(SELECT 1 FROM chat.managed_space_members \
                                       WHERE member_did = $1) \
                             OR EXISTS(SELECT 1 FROM chat.conversation_space_writers \
                                       WHERE writer_did = $1) \
                             OR EXISTS(SELECT 1 FROM chat.space_credential_jtis \
                                       WHERE writer_did = $1) \
                             OR EXISTS(SELECT 1 FROM chat.space_delegation_jtis \
                                       WHERE authority_did = $1) \
                             OR EXISTS(SELECT 1 FROM chat.push_gateway_bindings \
                                       WHERE user_did = $1) \
                             OR EXISTS(SELECT 1 FROM chat.idempotency_records \
                                       WHERE principal_did = $1) \
                             OR EXISTS(SELECT 1 FROM labyrinth.mailboxes WHERE owner_did = $1) \
                             OR EXISTS(SELECT 1 FROM labyrinth.epoch_heads WHERE did = $1) \
                             OR EXISTS(SELECT 1 FROM labyrinth.epoch_head_floors WHERE did = $1) \
                             OR EXISTS(SELECT 1 FROM labyrinth.recovery_shares \
                                       WHERE owner_did = $1) \
                             OR EXISTS(SELECT 1 FROM labyrinth.recovery_share_events \
                                       WHERE owner_did = $1) \
                             OR EXISTS(SELECT 1 FROM labyrinth.operations WHERE owner_did = $1)",
                    )
                    .bind(&did)
                    .fetch_one(&mut *tx)
                    .await?;
                    if has_history {
                        return Err(LabyrinthError::not_authorized(
                            "chat or backup history requires a device-signed account deletion",
                        ));
                    }
                    auth::bind_account_deletion_nonce(&principal, &pool, intent_sha256).await?;
                    // The guarded account has no rows to purge. A full purge
                    // here could race a remote inbox/index writer that does
                    // not take this DID lock and emit unsigned evidence.
                    tx.commit().await?;
                    return to_bytes(&json!({}));
                }
            };
            // A completed operation replays without asking a repository that may
            // have been deleted since the first call. A fresh probe releases its
            // device lock before any DID/PDS HTTP work (M-F04).
            let probe = begin_write!(&pool, adm.clone());
            let admitted_key = probe.caller.signing_key;
            (*probe).abort().await?;
            let mut evidence = deletion_evidence(&headers, &bytes)?;
            verify_admitted_key(&evidence, &admitted_key)?;
            let resolver = match rt.resolver() {
                Some(resolver) => resolver,
                None => {
                    if let Some(response) = auth::completed_write_for_admission(&pool, &adm).await?
                    {
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
                None => {
                    fetch_chat_device_key_proof(resolver, &adm.did, &device_id, &admitted_key).await
                }
            };
            let proof = match proof_result {
                Ok(proof) => proof,
                Err(error) => {
                    // Another identical request may have committed while this
                    // one was fetching. Return its result before requiring a
                    // repository that deletion itself may have removed.
                    if let Some(response) = auth::completed_write_for_admission(&pool, &adm).await?
                    {
                        return Ok(response);
                    }
                    return Err(key_proof_unavailable(error));
                }
            };
            evidence.key_proof = Some(proof);
            // Peer homes resolve over HTTP, so before the transaction opens (M-F04).
            let c33_peers = match repo::resolve_c33_peer_homes(&pool, &adm.did).await {
                Ok(peers) => peers,
                Err(error) => {
                    if let Some(response) = auth::completed_write_for_admission(&pool, &adm).await?
                    {
                        return Ok(response);
                    }
                    return Err(error);
                }
            };
            let mut w = begin_write!(&pool, adm);
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
        .await,
    )
}
