use axum::{extract::Query, extract::State, http::StatusCode, Json};
use serde::Deserialize;
use serde_json::json;
use tracing::warn;

use crate::{
    auth::{enforce_standard, AuthUser},
    federation::{peer_policy, FederationError},
    identity::canonical_did,
    storage::DbPool,
};

const LIST_NSID: &str = "blue.catbird.mls.admin.getFederationPeers";
const UPSERT_NSID: &str = "blue.catbird.mls.admin.upsertFederationPeer";
const DELETE_NSID: &str = "blue.catbird.mls.admin.deleteFederationPeer";

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ListPeersParams {
    pub status: Option<String>,
    pub limit: Option<u32>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UpsertPeerInput {
    pub ds_did: String,
    pub status: String,
    pub max_requests_per_minute: Option<u32>,
    pub note: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DeletePeerInput {
    pub ds_did: String,
}

pub async fn get_federation_peers(
    State(pool): State<DbPool>,
    auth_user: AuthUser,
    Query(params): Query<ListPeersParams>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    enforce_standard(&auth_user.claims, LIST_NSID).map_err(|_| StatusCode::UNAUTHORIZED)?;
    require_federation_admin(&auth_user)?;

    let status_filter = match params.status.as_deref() {
        Some(raw) => Some(peer_policy::PeerStatus::from_str(raw).ok_or(StatusCode::BAD_REQUEST)?),
        None => None,
    };
    let records =
        peer_policy::list_peer_policies(&pool, status_filter, params.limit.unwrap_or(100))
            .await
            .map_err(map_federation_error)?;

    Ok(Json(json!({
        "peers": records.into_iter().map(|record| {
            json!({
                "dsDid": record.ds_did,
                "status": record.status,
                "trustScore": record.trust_score,
                "maxRequestsPerMinute": record.max_requests_per_minute,
                "note": record.note,
                "invalidTokenCount": record.invalid_token_count,
                "rejectedRequestCount": record.rejected_request_count,
                "successfulRequestCount": record.successful_request_count,
                "lastSeenAt": record.last_seen_at,
                "createdAt": record.created_at,
                "updatedAt": record.updated_at,
            })
        }).collect::<Vec<_>>()
    })))
}

pub async fn upsert_federation_peer(
    State(pool): State<DbPool>,
    auth_user: AuthUser,
    Json(input): Json<UpsertPeerInput>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    enforce_standard(&auth_user.claims, UPSERT_NSID).map_err(|_| StatusCode::UNAUTHORIZED)?;
    require_federation_admin(&auth_user)?;

    let status = peer_policy::PeerStatus::from_str(&input.status).ok_or(StatusCode::BAD_REQUEST)?;
    let record = peer_policy::upsert_peer_policy(
        &pool,
        &input.ds_did,
        status,
        input.max_requests_per_minute,
        input.note.as_deref(),
    )
    .await
    .map_err(map_federation_error)?;

    Ok(Json(json!({
        "updated": true,
        "peer": {
            "dsDid": record.ds_did,
            "status": record.status,
            "trustScore": record.trust_score,
            "maxRequestsPerMinute": record.max_requests_per_minute,
            "note": record.note,
            "invalidTokenCount": record.invalid_token_count,
            "rejectedRequestCount": record.rejected_request_count,
            "successfulRequestCount": record.successful_request_count,
            "lastSeenAt": record.last_seen_at,
            "createdAt": record.created_at,
            "updatedAt": record.updated_at,
        }
    })))
}

pub async fn delete_federation_peer(
    State(pool): State<DbPool>,
    auth_user: AuthUser,
    Json(input): Json<DeletePeerInput>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    enforce_standard(&auth_user.claims, DELETE_NSID).map_err(|_| StatusCode::UNAUTHORIZED)?;
    require_federation_admin(&auth_user)?;

    let deleted = peer_policy::delete_peer_policy(&pool, &input.ds_did)
        .await
        .map_err(map_federation_error)?;
    if !deleted {
        return Err(StatusCode::NOT_FOUND);
    }

    Ok(Json(json!({
        "deleted": true,
        "dsDid": canonical_did(&input.ds_did),
    })))
}

fn parse_admin_dids() -> Vec<String> {
    std::env::var("FEDERATION_ADMIN_DIDS")
        .ok()
        .map(|raw| {
            raw.split(',')
                .map(str::trim)
                .filter(|entry| !entry.is_empty())
                .map(|entry| canonical_did(entry).to_string())
                .collect::<Vec<_>>()
        })
        .unwrap_or_default()
}

fn require_federation_admin(auth_user: &AuthUser) -> Result<(), StatusCode> {
    let allowed = parse_admin_dids();
    let requester = canonical_did(&auth_user.did);
    if allowed.iter().any(|did| did == requester) {
        return Ok(());
    }
    warn!(
        requester = %requester,
        "Rejected federation peer admin request from non-admin DID"
    );
    Err(StatusCode::FORBIDDEN)
}

fn map_federation_error(error: FederationError) -> StatusCode {
    error.status_code()
}
