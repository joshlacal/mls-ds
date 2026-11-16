//! Retention endpoints (`purgeMailbox`, `deleteAccountData`).

use std::sync::Arc;

use axum::{body::Bytes, extract::State, http::HeaderMap, response::Response};
use serde::Deserialize;
use serde_json::json;

use super::params::{admit_procedure, begin_write};
use super::respond;
use crate::federation::receipt::{AccountDeletionActorWrite, AccountDeletionEvidence};
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
/// device's optional `keyProof`, each decoded from its header unchanged.
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
                // Nothing here was ever signed by this account's device: purge
                // what the DID alone owns, which a repeat finds already gone.
                auth::AccountDeletionAdmission::NeverEnrolled { did, instant } => {
                    let c33_peers = repo::resolve_c33_peer_homes(&pool, &did).await?;
                    let mut conn = pool.acquire().await?;
                    repo::purge_account_with_recovery(
                        &mut *conn,
                        &did,
                        instant,
                        rt.i13_receipt_signer(),
                        &c33_peers,
                        None,
                        rt.recovery_tombstones().map(Arc::as_ref),
                    )
                    .await?;
                    return to_bytes(&json!({}));
                }
            };
            let evidence = deletion_evidence(&headers, &bytes)?;
            // Peer homes resolve over HTTP, so before the transaction opens (M-F04).
            let c33_peers = repo::resolve_c33_peer_homes(&pool, &adm.did).await?;
            let mut w = begin_write!(&pool, adm);
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
