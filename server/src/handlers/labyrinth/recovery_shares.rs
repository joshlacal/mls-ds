//! The private erasable recovery-share XRPCs.
//!
//! A fetch is a POST solely to keep the fetch token out of URLs. It uses
//! signed procedure admission followed by a read transaction, so neither a
//! token nor its sealed response enters `labyrinth.operations`.

use std::{net::SocketAddr, sync::Arc};

use axum::{
    body::Bytes,
    extract::{connect_info::ConnectInfo, RawQuery, State},
    http::{HeaderMap, StatusCode},
    response::Response,
    Extension,
};
use once_cell::sync::Lazy;
use serde::Deserialize;
use serde_json::json;
use uuid::Uuid;

use super::params::{admit_procedure_allowing_pending, admit_query_allowing_pending, begin_write};
use super::respond;
use crate::handlers::chat::ChatRuntime;
use crate::labyrinth::auth;
use crate::labyrinth::error::{LabyrinthError, LabyrinthResult};
use crate::labyrinth::recovery_crypto::{
    fetch_verifier, seal_to_ephemeral_key, verifier_matches, RecoveryCrypto,
};
use crate::labyrinth::recovery_tombstones::RecoveryTombstones;
use crate::labyrinth::repo::recovery_shares as repo;
use crate::labyrinth::wire::bytes::Bytes as AtBytes;
use crate::labyrinth::wire::io::{body, datetime, to_bytes};
use crate::middleware::rate_limit::RateLimiter;
use crate::storage::DbPool;

type Pool = State<DbPool>;
type Runtime = State<Arc<ChatRuntime>>;

static BAD_DEVICE_LIMITER: Lazy<RateLimiter> = Lazy::new(|| RateLimiter::new(32, 32.0 / 60.0));
static BAD_IP_LIMITER: Lazy<RateLimiter> = Lazy::new(|| RateLimiter::new(256, 256.0 / 60.0));

fn unavailable() -> LabyrinthError {
    LabyrinthError::new(
        StatusCode::NOT_FOUND,
        "RecoveryShareUnavailable",
        "recovery share unavailable",
    )
}

fn not_configured() -> LabyrinthError {
    LabyrinthError::new(
        StatusCode::SERVICE_UNAVAILABLE,
        "ServiceUnavailable",
        "recovery-share service is not configured",
    )
    .with_retry_after(5)
}

fn require_active_status(status: &str) -> LabyrinthResult<()> {
    if status == "active" {
        Ok(())
    } else {
        Err(LabyrinthError::forbidden(
            "ChatDeviceNotActive",
            "the calling chat device is not active",
        ))
    }
}

fn service(rt: &ChatRuntime) -> LabyrinthResult<(&RecoveryCrypto, &RecoveryTombstones)> {
    let crypto = rt.recovery_crypto().ok_or_else(not_configured)?;
    let tombstones = rt.recovery_tombstones().ok_or_else(not_configured)?;
    Ok((crypto.as_ref(), tombstones.as_ref()))
}

fn throttle_bad_fetch(
    actor: Uuid,
    headers: &HeaderMap,
    peer: Option<Extension<ConnectInfo<SocketAddr>>>,
) -> LabyrinthResult<()> {
    let device_key = format!("recovery-share:bad-device:{actor}");
    let peer = peer.map(|Extension(ConnectInfo(socket))| socket);
    let ip = crate::middleware::rate_limit::recovery_client_ip(headers, peer);
    let ip_key = format!("recovery-share:bad-ip:{ip}");
    let device_retry = BAD_DEVICE_LIMITER.check(&device_key).err();
    let ip_retry = BAD_IP_LIMITER.check(&ip_key).err();
    let retry_after = device_retry.or(ip_retry);
    match retry_after {
        Some(seconds) => {
            Err(
                LabyrinthError::new(StatusCode::TOO_MANY_REQUESTS, "RateLimited", "rate limited")
                    .with_retry_after(seconds.max(1)),
            )
        }
        None => Ok(()),
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct PutIn {
    vdevice_id: AtBytes,
    share: AtBytes,
    fetch_verifier: AtBytes,
    mechanism: String,
}

pub async fn put_recovery_share(
    State(pool): Pool,
    State(rt): Runtime,
    headers: HeaderMap,
    bytes: Bytes,
) -> Response {
    respond(
        async {
            let adm =
                admit_procedure_allowing_pending(&pool, &rt, "putRecoveryShare", &headers, &bytes)
                    .await?;
            require_active_status(&adm.caller_status)?;
            let input: PutIn = body(&bytes)?;
            let vid = input.vdevice_id.array::<16>("vdeviceId")?;
            let share = input.share.array::<32>("share")?;
            let verifier = input.fetch_verifier.array::<32>("fetchVerifier")?;
            if !matches!(input.mechanism.as_str(), "code" | "passkey") {
                return Err(LabyrinthError::invalid("mechanism must be code or passkey"));
            }
            let (crypto, journal) = service(&rt)?;
            // Erasure supersedes historical idempotency: the operations table
            // may still hold the original put response for seven days.
            if journal.contains(&adm.did, &vid) {
                return Err(LabyrinthError::new(
                    StatusCode::CONFLICT,
                    "RecoveryShareConflict",
                    "recovery share was deleted",
                ));
            }
            let mut w = begin_write!(&pool, adm);
            repo::require_active_chat_device(&mut w.tx, &w.caller).await?;
            let created_at = repo::put(
                &mut w.tx,
                &w.caller.did,
                &vid,
                &share,
                &verifier,
                &input.mechanism,
                w.caller.device_id,
                w.instant,
                crypto,
                journal,
            )
            .await?;
            w.finish_write(to_bytes(&json!({
                "vdeviceId": AtBytes::from_slice(&vid),
                "createdAt": datetime(created_at),
            }))?)
            .await
        }
        .await,
    )
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct GetIn {
    vdevice_id: AtBytes,
    fetch_token: AtBytes,
    recipient_public_key: AtBytes,
    purpose: Option<String>,
}

pub async fn get_recovery_share(
    State(pool): Pool,
    State(rt): Runtime,
    peer: Option<Extension<ConnectInfo<SocketAddr>>>,
    headers: HeaderMap,
    bytes: Bytes,
) -> Response {
    respond(
        async {
            // This is deliberately not begin_write: no response or fetchToken
            // may enter the 7-day operations replay table.
            let adm =
                admit_procedure_allowing_pending(&pool, &rt, "getRecoveryShare", &headers, &bytes)
                    .await?;
            let input: GetIn = body(&bytes)?;
            let vid = input.vdevice_id.array::<16>("vdeviceId")?;
            let token = input.fetch_token.array::<32>("fetchToken")?;
            let recipient_key = input
                .recipient_public_key
                .array::<32>("recipientPublicKey")?;
            if input
                .purpose
                .as_deref()
                .is_some_and(|p| !matches!(p, "restore" | "verify"))
            {
                return Err(LabyrinthError::invalid("purpose must be restore or verify"));
            }
            let (crypto, journal) = service(&rt)?;
            let mut read = auth::begin_read_allowing_pending(&pool, adm).await?;
            let did = read.caller.did.clone();
            let stored = repo::get(&mut read.tx, &did, &vid, journal).await?;
            let supplied = fetch_verifier(&did, &vid, &token);
            let matches = stored
                .as_ref()
                .is_some_and(|row| verifier_matches(&row.fetch_verifier, &supplied));
            if !matches {
                throttle_bad_fetch(read.caller.device_id, &headers, peer)?;
                repo::record_denied(
                    &mut read.tx,
                    &did,
                    &vid,
                    read.caller.device_id,
                    read.instant,
                )
                .await?;
                read.finish_read().await?;
                return Err(unavailable());
            }
            let stored = stored.expect("matched row");
            let share = crypto.decrypt_share(
                &did,
                &vid,
                &stored.kek_key_id,
                &stored.nonce,
                &stored.encrypted_share,
            )?;
            let (enc, sealed) = seal_to_ephemeral_key(&did, &vid, &recipient_key, share.as_ref())?;
            let verify = input.purpose.as_deref() == Some("verify")
                && read.caller.status == "active"
                && stored.created_by_device_id == read.caller.device_id;
            repo::record_fetch(
                &mut read.tx,
                &did,
                &vid,
                read.caller.device_id,
                read.instant,
                verify,
                journal,
            )
            .await?;
            read.finish_read().await?;
            if journal.contains(&did, &vid) {
                return Err(unavailable());
            }
            to_bytes(&json!({
                "vdeviceId": AtBytes::from_slice(&vid),
                "enc": AtBytes::from_slice(&enc),
                "sealedShare": AtBytes::from_slice(&sealed),
            }))
        }
        .await,
    )
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct DeleteIn {
    vdevice_id: AtBytes,
}

pub async fn delete_recovery_share(
    State(pool): Pool,
    State(rt): Runtime,
    headers: HeaderMap,
    bytes: Bytes,
) -> Response {
    respond(
        async {
            let adm = admit_procedure_allowing_pending(
                &pool,
                &rt,
                "deleteRecoveryShare",
                &headers,
                &bytes,
            )
            .await?;
            require_active_status(&adm.caller_status)?;
            let input: DeleteIn = body(&bytes)?;
            let vid = input.vdevice_id.array::<16>("vdeviceId")?;
            let (_, journal) = service(&rt)?;
            let mut w = begin_write!(&pool, adm);
            repo::require_active_chat_device(&mut w.tx, &w.caller).await?;
            let deleted_at = repo::delete(
                &mut w.tx,
                &w.caller.did,
                &vid,
                w.caller.device_id,
                w.instant,
                journal,
            )
            .await?
            .ok_or_else(|| LabyrinthError::not_found("RecoveryShareNotFound"))?;
            w.finish_write(to_bytes(&json!({
                "vdeviceId": AtBytes::from_slice(&vid),
                "deletedAt": datetime(deleted_at),
            }))?)
            .await
        }
        .await,
    )
}

pub async fn list_recovery_shares(
    State(pool): Pool,
    State(rt): Runtime,
    headers: HeaderMap,
    RawQuery(query): RawQuery,
) -> Response {
    respond(
        async {
            let (adm, params) = admit_query_allowing_pending(
                &pool,
                &rt,
                "listRecoveryShares",
                &headers,
                query.as_deref(),
                &["cursor", "limit"],
            )
            .await?;
            require_active_status(&adm.caller_status)?;
            let _ = service(&rt)?;
            let page = params.page()?;
            let mut read = auth::begin_read(&pool, adm).await?;
            repo::require_active_chat_device(&mut read.tx, &read.caller).await?;
            let (shares, cursor) = repo::list(
                &mut read.tx,
                &read.caller.did,
                page.cursor.as_deref(),
                page.limit(),
                rt.recovery_tombstones().expect("checked service"),
            )
            .await?;
            read.finish_read().await?;
            let shares: Vec<_> = shares
                .into_iter()
                .map(|share| {
                    let mut view = json!({
                        "vdeviceId": AtBytes::from_slice(&share.vdevice_id),
                        "mechanism": share.mechanism,
                        "createdAt": datetime(share.created_at),
                        "createdByDeviceId": share.created_by_device_id.to_string(),
                        "fetchCount": share.fetch_count,
                    });
                    if let Some(at) = share.last_fetched_at {
                        view["lastFetchedAt"] = json!(datetime(at));
                    }
                    view
                })
                .collect();
            let mut output = json!({ "shares": shares });
            if let Some(cursor) = cursor {
                output["cursor"] = json!(cursor);
            }
            to_bytes(&output)
        }
        .await,
    )
}

pub async fn list_recovery_share_events(
    State(pool): Pool,
    State(rt): Runtime,
    headers: HeaderMap,
    RawQuery(query): RawQuery,
) -> Response {
    respond(
        async {
            let (adm, params) = admit_query_allowing_pending(
                &pool,
                &rt,
                "listRecoveryShareEvents",
                &headers,
                query.as_deref(),
                &["cursor", "limit"],
            )
            .await?;
            require_active_status(&adm.caller_status)?;
            let _ = service(&rt)?;
            let page = params.page()?;
            let mut read = auth::begin_read(&pool, adm).await?;
            repo::require_active_chat_device(&mut read.tx, &read.caller).await?;
            let (events, cursor) = repo::list_events(
                &mut read.tx,
                &read.caller.did,
                page.cursor.as_deref(),
                page.limit(),
            )
            .await?;
            read.finish_read().await?;
            let events: Vec<_> = events
                .into_iter()
                .map(|event| {
                    let mut view = json!({
                        "id": event.id.to_string(),
                        "vdeviceId": AtBytes::from_slice(&event.vdevice_id),
                        "kind": event.kind,
                        "at": datetime(event.at),
                    });
                    if let Some(actor) = event.actor_device_id {
                        view["actorDeviceId"] = json!(actor.to_string());
                    }
                    view
                })
                .collect();
            let mut output = json!({ "events": events });
            if let Some(cursor) = cursor {
                output["cursor"] = json!(cursor);
            }
            to_bytes(&output)
        }
        .await,
    )
}

/// Signed, account-bound capability probe for a pending or active device.
/// It has no share selector, token, or Labyrinth operations-table record.
pub async fn get_recovery_share_capabilities(
    State(pool): Pool,
    State(rt): Runtime,
    headers: HeaderMap,
    RawQuery(query): RawQuery,
) -> Response {
    respond(
        async {
            let (adm, _) = admit_query_allowing_pending(
                &pool,
                &rt,
                "getRecoveryShareCapabilities",
                &headers,
                query.as_deref(),
                &[],
            )
            .await?;
            let (crypto, _) = service(&rt)?;
            let read = auth::begin_read_allowing_pending(&pool, adm).await?;
            read.finish_read().await?;
            to_bytes(&json!({
                "supported": true,
                "version": 1,
                "hpkeSuite": "DHKEM_X25519_HKDF_SHA256_HKDF_SHA256_AES_256_GCM",
                "keyId": crypto.key_id(),
            }))
        }
        .await,
    )
}
