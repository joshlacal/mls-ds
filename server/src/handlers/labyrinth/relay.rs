//! The sequencer side of `labyrinthRelay` (`crate::labyrinth::relay`).

use std::sync::Arc;

use axum::{body::Bytes, extract::State, response::Response};

use super::respond;
use super::thread::{exec_read, exec_write, read_params, write_thread};
use crate::auth::AuthUser;
use crate::handlers::chat::ChatRuntime;
use crate::handlers::ds::deliver_message::enforce_ds_request_security;
use crate::labyrinth::auth::{decode_b64, relayed_read, verify_signed_write};
use crate::labyrinth::error::{LabyrinthError, LabyrinthResult};
use crate::labyrinth::read_auth::{canonical_query, Expected, ReadProof};
use crate::labyrinth::relay::{not_home_ds, not_sequencer, RelayOp, RelayRequest, NSID};
use crate::labyrinth::repo::retention::home_ds;
use crate::labyrinth::repo::thread::parse_thread_id;
use crate::labyrinth::wire::bytes::check_did;
use crate::labyrinth::wire::io::body;
use crate::storage::DbPool;

fn peer_refused(error: crate::federation::FederationError) -> LabyrinthError {
    tracing::warn!(%error, "labyrinth relay peer refused");
    LabyrinthError::not_authorized("the requesting DS is not admitted")
}

/// The conversation must be sequenced here and the peer must be the actor's
/// home DS in it.
async fn require_home(
    pool: &DbPool,
    conversation: uuid::Uuid,
    actor: &str,
    requester: &str,
) -> LabyrinthResult<()> {
    let remote: Option<bool> =
        sqlx::query_scalar("SELECT is_remote FROM chat.conversations WHERE conversation_id = $1")
            .bind(conversation)
            .fetch_optional(pool)
            .await?;
    if remote != Some(false) {
        return Err(not_sequencer());
    }
    let mut conn = pool.acquire().await?;
    match home_ds(&mut conn, conversation, actor).await? {
        Some(Some(ds)) if crate::identity::dids_equivalent(&ds, requester) => Ok(()),
        _ => Err(not_home_ds()),
    }
}

async fn relay(
    pool: &DbPool,
    rt: &ChatRuntime,
    auth_user: &AuthUser,
    bytes: &[u8],
) -> LabyrinthResult<Vec<u8>> {
    if !rt.cutover_enabled() {
        return Err(LabyrinthError::new(
            axum::http::StatusCode::BAD_REQUEST,
            "CutoverRequired",
            "the clean-chat protocol is not active on this service",
        ));
    }
    let security = enforce_ds_request_security(pool, auth_user, NSID, None)
        .await
        .map_err(peer_refused)?;
    let requester = security.requester_ds;
    let req: RelayRequest = body(bytes)?;
    let op = RelayOp::parse(&req.op)?;
    check_did("actorDid", &req.actor_did)?;
    if op.is_write() {
        let (Some(payload), Some(write_body), Some(write_signature), None) = (
            &req.payload,
            &req.write_body,
            &req.write_signature,
            &req.query,
        ) else {
            return Err(LabyrinthError::invalid(
                "a relayed write carries payload, writeBody and writeSignature only",
            ));
        };
        let adm = verify_signed_write(
            pool,
            &req.actor_did,
            &op.signed_nsid(),
            &decode_b64("writeBody", write_body)?,
            &decode_b64("writeSignature", write_signature)?,
            &payload.0,
        )
        .await?;
        if adm.device_id.hyphenated().to_string() != req.actor_device_id {
            return Err(LabyrinthError::invalid(
                "actorDeviceId differs from the signed write body",
            ));
        }
        if op != RelayOp::PurgeAuthor {
            let thread = write_thread(op, &payload.0)
                .ok_or_else(|| LabyrinthError::invalid("the payload names no conversation"))?;
            require_home(pool, thread, &req.actor_did, &requester).await?;
        }
        exec_write(pool, op, adm, &payload.0, Some(&requester)).await
    } else {
        let (Some(query), None, None, None, Some(header), Some(signature)) = (
            &req.query,
            &req.payload,
            &req.write_body,
            &req.write_signature,
            req.read_header.clone(),
            req.read_signature.clone(),
        ) else {
            return Err(LabyrinthError::invalid(
                "a relayed read carries query, readHeader and readSignature only",
            ));
        };
        let p = super::params::Params::parse(Some(query), read_params(op))?;
        let nsid = op.read_nsid();
        let canonical = canonical_query(Some(query));
        let expected = Expected {
            did: &req.actor_did,
            nsid: &nsid,
            // messageLive is asked on behalf of getAttachmentBlob, whose
            // signed query names the same thread and message (checked below).
            query: (op != RelayOp::MessageLive).then_some(canonical.as_str()),
        };
        let proof = ReadProof { header, signature };
        let (adm, claim) = relayed_read(pool, proof, expected, &req.actor_device_id).await?;
        if op == RelayOp::MessageLive {
            let signed = super::params::Params::parse_any(&claim.query);
            for key in ["threadId", "messageId"] {
                if signed.get(key).map(String::as_str) != Some(p.req(key)?) {
                    return Err(LabyrinthError::invalid(
                        "the signed read does not name this message",
                    ));
                }
            }
        }
        if op == RelayOp::ListThreads {
            // Filtered in SQL to the conversations sequenced here in which
            // the requester is the actor's home DS.
            return exec_read(pool, op, adm, Some(query), Some(&requester)).await;
        }
        let thread = parse_thread_id(p.req("threadId")?)?;
        require_home(pool, thread, &req.actor_did, &requester).await?;
        exec_read(pool, op, adm, Some(query), None).await
    }
}

/// `POST /xrpc/blue.catbird.labyrinth.labyrinthRelay` (server-to-server).
pub async fn labyrinth_relay(
    State(pool): State<DbPool>,
    State(rt): State<Arc<ChatRuntime>>,
    auth_user: AuthUser,
    bytes: Bytes,
) -> Response {
    respond(relay(&pool, &rt, &auth_user, &bytes).await)
}
