//! Axum HTTP handlers for Option A Conversation `SpaceHost` (`com.atproto.space.*`).

use std::{collections::BTreeMap, sync::Arc};

use atproto_spaces::{
    http_signature::verify_credential_request,
    kem::decode_p256_did_key,
    tokens::{SpaceTokenClaims, SpaceTokenKind, CREDENTIAL_DEFAULT_LIFETIME_SECS},
    SpaceUri, SpacesError,
};
use axum::{
    body::Bytes,
    extract::{Query, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use base64::{
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
    Engine as _,
};
use chrono::{SecondsFormat, TimeZone as _, Utc};
use serde::Deserialize;
use serde_json::{json, Value};
use sqlx::FromRow;
use uuid::Uuid;

use super::{decode_tid_micros, SpaceHostRuntime};
use crate::storage::DbPool;

pub fn space_host_router(runtime: Arc<SpaceHostRuntime>) -> Router {
    Router::new()
        .route(
            "/xrpc/com.atproto.space.getSpaceCredential",
            get(get_space_credential),
        )
        .route("/xrpc/com.atproto.space.listRepos", get(list_repos))
        .route("/xrpc/com.atproto.space.getSpace", get(get_space))
        .route("/xrpc/com.atproto.space.notifyWrite", post(notify_write))
        .route("/xrpc/com.atproto.space.removeWriter", post(remove_writer))
        .route(
            "/xrpc/com.atproto.space.registerNotify",
            post(register_notify),
        )
        .route(
            "/xrpc/com.atproto.space.unregisterNotify",
            post(unregister_notify),
        )
        .with_state(runtime)
}

#[derive(Debug, FromRow)]
pub(crate) struct SpaceStatusRow {
    pub conversation_id: Uuid,
    pub generation: i64,
    pub authority_did: String,
    pub latest_space_rev: Option<String>,
    pub deleted_at: Option<chrono::DateTime<Utc>>,
    pub conv_lifecycle: String,
    pub gen_lifecycle: String,
}

fn xrpc_err(status: StatusCode, code: &str, message: impl Into<String>) -> Response {
    (
        status,
        Json(json!({
            "error": code,
            "message": message.into(),
        })),
    )
        .into_response()
}

pub(crate) async fn load_active_space_status(
    pool: &DbPool,
    space_uri: &str,
) -> Result<SpaceStatusRow, Response> {
    let row: Option<SpaceStatusRow> = sqlx::query_as(
        "SELECT cs.conversation_id, \
                cs.generation, \
                cs.authority_did, \
                cs.latest_space_rev, \
                cs.deleted_at, \
                c.lifecycle AS conv_lifecycle, \
                g.lifecycle AS gen_lifecycle \
           FROM chat.conversation_spaces cs \
           JOIN chat.conversations c ON c.conversation_id = cs.conversation_id \
           JOIN chat.generations g \
             ON g.conversation_id = cs.conversation_id AND g.generation = cs.generation \
          WHERE cs.space_uri = $1",
    )
    .bind(space_uri)
    .fetch_optional(pool)
    .await
    .map_err(|e| {
        xrpc_err(
            StatusCode::INTERNAL_SERVER_ERROR,
            "InternalServerError",
            e.to_string(),
        )
    })?;

    let Some(row) = row else {
        return Err(xrpc_err(
            StatusCode::NOT_FOUND,
            "SpaceNotFound",
            format!("space not found: {space_uri}"),
        ));
    };

    if row.deleted_at.is_some() || row.conv_lifecycle != "active" || row.gen_lifecycle != "active" {
        return Err(xrpc_err(
            StatusCode::GONE,
            "SpaceDeleted",
            format!("space has been closed/deleted: {space_uri}"),
        ));
    }

    Ok(row)
}

/// Active member check with ZERO `NOT c.is_remote` local-only guard (`atproto#5187` / Spec §6.2).
async fn is_active_space_member(
    pool: &DbPool,
    conversation_id: Uuid,
    user_did: &str,
) -> Result<bool, Response> {
    let active: bool = sqlx::query_scalar(
        "SELECT EXISTS( \
             SELECT 1 FROM chat.participants p \
              WHERE p.conversation_id = $1 \
                AND p.user_did = $2 \
                AND p.current_membership = TRUE \
                AND p.status = 'active' \
         )",
    )
    .bind(conversation_id)
    .bind(user_did)
    .fetch_one(pool)
    .await
    .map_err(|e| {
        xrpc_err(
            StatusCode::INTERNAL_SERVER_ERROR,
            "InternalServerError",
            e.to_string(),
        )
    })?;
    Ok(active)
}

async fn authenticate_credential_request(
    runtime: &SpaceHostRuntime,
    headers: &HeaderMap,
    space_uri: &str,
) -> Result<(SpaceStatusRow, SpaceTokenClaims), Response> {
    let status = load_active_space_status(runtime.pool(), space_uri).await?;
    let now_sec = Utc::now().timestamp().max(0) as u64;

    let auth_hdr = headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .map(str::trim)
        .ok_or_else(|| {
            xrpc_err(
                StatusCode::UNAUTHORIZED,
                "InvalidSpaceCredential",
                "missing Authorization header",
            )
        })?;
    let prefix = "atproto-space-credential ";
    if auth_hdr.len() <= prefix.len() || !auth_hdr[..prefix.len()].eq_ignore_ascii_case(prefix) {
        return Err(xrpc_err(
            StatusCode::UNAUTHORIZED,
            "InvalidSpaceCredential",
            "expected Atproto-Space-Credential scheme",
        ));
    }
    let cred_jwt = auth_hdr[prefix.len()..].trim();

    let claims = runtime
        .verify_space_token_send(SpaceTokenKind::Credential, cred_jwt, now_sec)
        .await
        .map_err(|e| {
            xrpc_err(
                StatusCode::UNAUTHORIZED,
                "InvalidSpaceCredential",
                e.to_string(),
            )
        })?;

    if claims.iss != runtime.authority_did() || claims.sub != space_uri {
        return Err(xrpc_err(
            StatusCode::UNAUTHORIZED,
            "InvalidSpaceCredential",
            "credential issuer or subject mismatch",
        ));
    }

    let cnf_kid = claims.cnf_kid.as_deref().ok_or_else(|| {
        xrpc_err(
            StatusCode::UNAUTHORIZED,
            "InvalidSpaceCredential",
            "credential missing cnf.kid",
        )
    })?;

    let verified_hdrs = verify_credential_request(headers, cnf_kid, now_sec)
        .map_err(|e| xrpc_err(StatusCode::UNAUTHORIZED, "BadSpaceSignature", e.to_string()))?;

    if crate::identity::canonical_did(&verified_hdrs.audience_did) != runtime.authority_did() {
        return Err(xrpc_err(
            StatusCode::UNAUTHORIZED,
            "BadSpaceSignature",
            "Atproto-Space-Audience mismatch",
        ));
    }

    let jti_row: Option<(Option<chrono::DateTime<Utc>>, chrono::DateTime<Utc>)> = sqlx::query_as(
        "SELECT revoked_at, expires_at FROM chat.space_credential_jtis WHERE jti = $1 AND space_uri = $2",
    )
    .bind(&claims.jti)
    .bind(space_uri)
    .fetch_optional(runtime.pool())
    .await
    .map_err(|e| xrpc_err(StatusCode::INTERNAL_SERVER_ERROR, "InternalServerError", e.to_string()))?;

    let Some((revoked_at, expires_at)) = jti_row else {
        return Err(xrpc_err(
            StatusCode::UNAUTHORIZED,
            "CredentialRevoked",
            "unknown or pruned credential jti",
        ));
    };
    if revoked_at.is_some() || expires_at <= Utc::now() {
        return Err(xrpc_err(
            StatusCode::UNAUTHORIZED,
            "CredentialRevoked",
            "space credential has been revoked or expired",
        ));
    }

    Ok((status, claims))
}

async fn authenticate_service_jwt(
    runtime: &SpaceHostRuntime,
    headers: &HeaderMap,
    expected_lxm: &str,
) -> Result<String, Response> {
    let auth_hdr = headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .map(str::trim)
        .ok_or_else(|| {
            xrpc_err(
                StatusCode::UNAUTHORIZED,
                "AuthMissing",
                "missing Bearer Authorization header",
            )
        })?;
    let Some(jwt) = auth_hdr.strip_prefix("Bearer ").map(str::trim) else {
        return Err(xrpc_err(
            StatusCode::UNAUTHORIZED,
            "AuthMissing",
            "expected Bearer token",
        ));
    };
    let parts: Vec<&str> = jwt.split('.').collect();
    if parts.len() != 3 {
        return Err(xrpc_err(
            StatusCode::UNAUTHORIZED,
            "InvalidToken",
            "malformed JWT",
        ));
    }
    let header_json: Value = serde_json::from_slice(
        &URL_SAFE_NO_PAD
            .decode(parts[0])
            .map_err(|_| xrpc_err(StatusCode::UNAUTHORIZED, "InvalidToken", "bad JWT header"))?,
    )
    .map_err(|_| {
        xrpc_err(
            StatusCode::UNAUTHORIZED,
            "InvalidToken",
            "bad JWT header JSON",
        )
    })?;
    let claims_json: Value = serde_json::from_slice(
        &URL_SAFE_NO_PAD
            .decode(parts[1])
            .map_err(|_| xrpc_err(StatusCode::UNAUTHORIZED, "InvalidToken", "bad JWT claims"))?,
    )
    .map_err(|_| {
        xrpc_err(
            StatusCode::UNAUTHORIZED,
            "InvalidToken",
            "bad JWT claims JSON",
        )
    })?;
    let sig_bytes = URL_SAFE_NO_PAD.decode(parts[2]).map_err(|_| {
        xrpc_err(
            StatusCode::UNAUTHORIZED,
            "InvalidToken",
            "bad JWT signature",
        )
    })?;

    let alg = header_json
        .get("alg")
        .and_then(Value::as_str)
        .unwrap_or_default();
    let iss = claims_json
        .get("iss")
        .and_then(Value::as_str)
        .ok_or_else(|| xrpc_err(StatusCode::UNAUTHORIZED, "InvalidToken", "missing iss"))?;
    let aud = claims_json
        .get("aud")
        .and_then(Value::as_str)
        .unwrap_or_default();
    let lxm = claims_json
        .get("lxm")
        .and_then(Value::as_str)
        .unwrap_or_default();
    let exp = claims_json.get("exp").and_then(Value::as_i64).unwrap_or(0);
    let now = Utc::now().timestamp();
    if exp + 30 < now {
        return Err(xrpc_err(
            StatusCode::UNAUTHORIZED,
            "TokenExpired",
            "service JWT expired",
        ));
    }
    if lxm != expected_lxm {
        return Err(xrpc_err(
            StatusCode::UNAUTHORIZED,
            "InvalidToken",
            "service JWT lxm mismatch",
        ));
    }
    if crate::identity::canonical_did(aud) != runtime.authority_did() {
        return Err(xrpc_err(
            StatusCode::UNAUTHORIZED,
            "InvalidToken",
            "service JWT aud mismatch",
        ));
    }

    let signing_input = format!("{}.{}", parts[0], parts[1]);
    let (vk, _, _) = runtime
        .resolve_did_entry(iss, false)
        .await
        .map_err(|e| xrpc_err(StatusCode::UNAUTHORIZED, "InvalidToken", e.to_string()))?;
    if !vk.verify_raw(alg, signing_input.as_bytes(), &sig_bytes) {
        let (vk_refreshed, _, _) = runtime
            .resolve_did_entry(iss, true)
            .await
            .map_err(|e| xrpc_err(StatusCode::UNAUTHORIZED, "InvalidToken", e.to_string()))?;
        if !vk_refreshed.verify_raw(alg, signing_input.as_bytes(), &sig_bytes) {
            return Err(xrpc_err(
                StatusCode::UNAUTHORIZED,
                "InvalidToken",
                "service JWT signature verification failed",
            ));
        }
    }

    Ok(crate::identity::canonical_did(iss).to_string())
}

async fn get_space_credential(
    State(runtime): State<Arc<SpaceHostRuntime>>,
    Query(params): Query<BTreeMap<String, String>>,
) -> Response {
    let Some(space_uri) = params.get("space").map(String::as_str) else {
        return xrpc_err(StatusCode::BAD_REQUEST, "InvalidRequest", "missing space");
    };
    let parsed_space = match SpaceUri::parse(space_uri) {
        Ok(s) => s,
        Err(e) => return xrpc_err(StatusCode::BAD_REQUEST, "InvalidSpaceUri", e.to_string()),
    };
    if parsed_space.authority != runtime.authority_did() {
        return xrpc_err(
            StatusCode::BAD_REQUEST,
            "InvalidSpaceUri",
            "space authority mismatch",
        );
    }

    let status = match load_active_space_status(runtime.pool(), space_uri).await {
        Ok(s) => s,
        Err(resp) => return resp,
    };

    let Some(credential_kid) = params
        .get("credentialKid")
        .or_else(|| params.get("cnfKey"))
        .map(String::as_str)
    else {
        return xrpc_err(
            StatusCode::BAD_REQUEST,
            "InvalidRequest",
            "missing credentialKid",
        );
    };
    if let Err(e) = decode_p256_did_key(credential_kid) {
        return xrpc_err(StatusCode::BAD_REQUEST, "InvalidDidKey", e.to_string());
    }

    let Some(delegation_jwt) = params.get("delegationToken").map(String::as_str) else {
        return xrpc_err(
            StatusCode::FORBIDDEN,
            "Forbidden",
            "delegationToken required for member-restricted Space",
        );
    };

    let now_sec = Utc::now().timestamp().max(0) as u64;
    let del_claims = match runtime
        .verify_space_token_send(SpaceTokenKind::Delegation, delegation_jwt, now_sec)
        .await
    {
        Ok(c) => c,
        Err(SpacesError::InvalidDelegationToken(msg)) => {
            return xrpc_err(StatusCode::UNAUTHORIZED, "InvalidDelegationToken", msg);
        }
        Err(e) => {
            return xrpc_err(
                StatusCode::UNAUTHORIZED,
                "InvalidDelegationToken",
                e.to_string(),
            );
        }
    };

    if del_claims.sub != space_uri
        || del_claims
            .cnf_kid
            .as_deref()
            .is_some_and(|kid| kid != credential_kid)
    {
        return xrpc_err(
            StatusCode::UNAUTHORIZED,
            "InvalidDelegationToken",
            "delegation sub or cnf.kid mismatch",
        );
    }
    let Some(ref del_aud) = del_claims.aud else {
        return xrpc_err(
            StatusCode::UNAUTHORIZED,
            "InvalidDelegationToken",
            "delegation missing aud",
        );
    };
    if crate::identity::canonical_did(del_aud) != runtime.authority_did() {
        return xrpc_err(
            StatusCode::UNAUTHORIZED,
            "InvalidDelegationToken",
            "delegation aud mismatch",
        );
    }

    // Active member check (excludes pending C33 direct-request targets, left, and removed members)
    match is_active_space_member(runtime.pool(), status.conversation_id, &del_claims.iss).await {
        Ok(true) => {}
        Ok(false) => {
            return xrpc_err(
                StatusCode::FORBIDDEN,
                "Forbidden",
                "requester is not an active member of this conversation Space",
            );
        }
        Err(resp) => return resp,
    }

    // Single-use 60s delegation jti replay cache
    let _ =
        sqlx::query("DELETE FROM chat.space_delegation_jtis WHERE expires_at <= clock_timestamp()")
            .execute(runtime.pool())
            .await;
    let del_exp = Utc
        .timestamp_opt(del_claims.exp as i64, 0)
        .single()
        .unwrap_or_else(|| Utc::now() + chrono::Duration::seconds(60));
    let inserted = match sqlx::query(
        "INSERT INTO chat.space_delegation_jtis (authority_did, jti, expires_at, created_at) \
         VALUES ($1, $2, $3, clock_timestamp()) \
         ON CONFLICT (authority_did, jti) DO NOTHING",
    )
    .bind(runtime.authority_did())
    .bind(&del_claims.jti)
    .bind(del_exp)
    .execute(runtime.pool())
    .await
    {
        Ok(res) => res.rows_affected(),
        Err(e) => {
            return xrpc_err(
                StatusCode::INTERNAL_SERVER_ERROR,
                "InternalServerError",
                e.to_string(),
            );
        }
    };
    if inserted == 0 {
        return xrpc_err(
            StatusCode::UNAUTHORIZED,
            "InvalidDelegationToken",
            "replayed delegation jti",
        );
    }

    let cred_jti = Uuid::new_v4().to_string();
    let exp_sec = now_sec + CREDENTIAL_DEFAULT_LIFETIME_SECS;
    let exp_dt = Utc
        .timestamp_opt(exp_sec as i64, 0)
        .single()
        .unwrap_or_else(|| Utc::now() + chrono::Duration::seconds(600));

    let cred_claims = SpaceTokenClaims {
        iss: runtime.authority_did().to_string(),
        sub: space_uri.to_string(),
        aud: None,
        iat: now_sec,
        exp: exp_sec,
        jti: cred_jti.clone(),
        cnf_kid: Some(credential_kid.to_string()),
    };
    let cred_jwt = match runtime.mint_credential(&cred_claims) {
        Ok(jwt) => jwt,
        Err(e) => {
            return xrpc_err(
                StatusCode::INTERNAL_SERVER_ERROR,
                "InternalServerError",
                e.to_string(),
            );
        }
    };

    if let Err(e) = sqlx::query(
        "INSERT INTO chat.space_credential_jtis (jti, space_uri, writer_did, expires_at, created_at) \
         VALUES ($1, $2, $3, $4, clock_timestamp())",
    )
    .bind(&cred_jti)
    .bind(space_uri)
    .bind(&del_claims.iss)
    .bind(exp_dt)
    .execute(runtime.pool())
    .await
    {
        return xrpc_err(
            StatusCode::INTERNAL_SERVER_ERROR,
            "InternalServerError",
            e.to_string(),
        );
    }

    (
        StatusCode::OK,
        Json(json!({
            "credential": cred_jwt,
            "expiresAt": exp_dt.to_rfc3339_opts(SecondsFormat::Millis, true),
        })),
    )
        .into_response()
}

#[derive(Debug, FromRow)]
struct WriterRow {
    writer_did: String,
    repo_rev: String,
    space_rev: String,
    data_cid: Vec<u8>,
}

async fn list_repos(
    State(runtime): State<Arc<SpaceHostRuntime>>,
    headers: HeaderMap,
    Query(params): Query<BTreeMap<String, String>>,
) -> Response {
    let Some(space_uri) = params.get("space").map(String::as_str) else {
        return xrpc_err(StatusCode::BAD_REQUEST, "InvalidRequest", "missing space");
    };
    let (status, _claims) =
        match authenticate_credential_request(&runtime, &headers, space_uri).await {
            Ok(v) => v,
            Err(resp) => return resp,
        };

    let cursor = params.get("cursor").cloned();
    let limit = params
        .get("limit")
        .and_then(|s| s.parse::<i64>().ok())
        .unwrap_or(100)
        .clamp(1, 1000);

    // Historical writer inclusion: ('active', 'left', 'removed') in ascending spaceRev order,
    // strictly excluding 'pending' / declined C33 targets without duplicating multi-period DIDs!
    let rows: Vec<WriterRow> = match sqlx::query_as(
        "SELECT w.writer_did, w.repo_rev, w.space_rev, w.data_cid \
           FROM chat.conversation_space_writers w \
          WHERE w.space_uri = $2 \
            AND EXISTS ( \
                SELECT 1 \
                  FROM chat.participants p \
                 WHERE p.conversation_id = $1 \
                   AND p.user_did = w.writer_did \
                   AND p.status IN ('active', 'left', 'removed') \
            ) \
            AND ($3::TEXT IS NULL OR w.space_rev > $3) \
          ORDER BY w.space_rev ASC \
          LIMIT $4",
    )
    .bind(status.conversation_id)
    .bind(space_uri)
    .bind(cursor.as_deref())
    .bind(limit + 1)
    .fetch_all(runtime.pool())
    .await
    {
        Ok(r) => r,
        Err(e) => {
            return xrpc_err(
                StatusCode::INTERNAL_SERVER_ERROR,
                "InternalServerError",
                e.to_string(),
            );
        }
    };

    let has_more = rows.len() as i64 > limit;
    let take_len = (limit as usize).min(rows.len());
    let next_cursor = if has_more {
        rows.get(take_len.saturating_sub(1))
            .map(|r| r.space_rev.clone())
    } else {
        None
    };

    let repos: Vec<Value> = rows
        .into_iter()
        .take(take_len)
        .map(|r| {
            json!({
                "did": r.writer_did,
                "repoRev": r.repo_rev,
                "spaceRev": r.space_rev,
                "data": { "$bytes": STANDARD.encode(&r.data_cid) },
            })
        })
        .collect();

    let mut out = json!({ "repos": repos });
    if let Some(c) = next_cursor {
        out["cursor"] = json!(c);
    }
    (StatusCode::OK, Json(out)).into_response()
}

async fn get_space(
    State(runtime): State<Arc<SpaceHostRuntime>>,
    headers: HeaderMap,
    Query(params): Query<BTreeMap<String, String>>,
) -> Response {
    let Some(space_uri) = params.get("space").map(String::as_str) else {
        return xrpc_err(StatusCode::BAD_REQUEST, "InvalidRequest", "missing space");
    };
    let (status, _claims) =
        match authenticate_credential_request(&runtime, &headers, space_uri).await {
            Ok(v) => v,
            Err(resp) => return resp,
        };

    let members: Vec<String> = match sqlx::query_scalar(
        "SELECT user_did FROM chat.participants \
          WHERE conversation_id = $1 AND current_membership = TRUE AND status = 'active' \
          ORDER BY user_did ASC",
    )
    .bind(status.conversation_id)
    .fetch_all(runtime.pool())
    .await
    {
        Ok(m) => m,
        Err(e) => {
            return xrpc_err(
                StatusCode::INTERNAL_SERVER_ERROR,
                "InternalServerError",
                e.to_string(),
            );
        }
    };

    let mut out = json!({
        "uri": space_uri,
        "policy": {
            "$type": "blue.catbird.labyrinth.conversationPolicy",
            "authority": status.authority_did,
            "members": members,
        }
    });
    if let Some(rev) = status.latest_space_rev {
        out["latestSpaceRev"] = json!(rev);
    }
    (StatusCode::OK, Json(out)).into_response()
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct NotifyWriteInput {
    space: String,
    repo: String,
    repo_rev: String,
    data: Value,
}

fn decode_32_byte_data(val: &Value) -> Option<[u8; 32]> {
    let b64 = val
        .get("$bytes")
        .and_then(Value::as_str)
        .or_else(|| val.as_str())?;
    let bytes = STANDARD.decode(b64).ok()?;
    bytes.try_into().ok()
}

async fn notify_write(
    State(runtime): State<Arc<SpaceHostRuntime>>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let caller_did =
        match authenticate_service_jwt(&runtime, &headers, "com.atproto.space.notifyWrite").await {
            Ok(d) => d,
            Err(resp) => return resp,
        };

    let input: NotifyWriteInput = match serde_json::from_slice(&body) {
        Ok(v) => v,
        Err(e) => return xrpc_err(StatusCode::BAD_REQUEST, "InvalidRequest", e.to_string()),
    };

    if caller_did != crate::identity::canonical_did(&input.repo) {
        return xrpc_err(
            StatusCode::FORBIDDEN,
            "Forbidden",
            "notifyWrite issuer must match repo DID",
        );
    }

    let status = match load_active_space_status(runtime.pool(), &input.space).await {
        Ok(s) => s,
        Err(resp) => return resp,
    };

    match is_active_space_member(runtime.pool(), status.conversation_id, &caller_did).await {
        Ok(true) => {}
        Ok(false) => {
            return xrpc_err(
                StatusCode::FORBIDDEN,
                "Forbidden",
                "writer is not an active member of this Space",
            );
        }
        Err(resp) => return resp,
    }

    let now_sec = Utc::now().timestamp().max(0) as u64;
    let Some(repo_micros) = decode_tid_micros(&input.repo_rev) else {
        return xrpc_err(
            StatusCode::BAD_REQUEST,
            "InvalidRequest",
            "invalid repoRev TID",
        );
    };
    if repo_micros > now_sec.saturating_add(300).saturating_mul(1_000_000) {
        return xrpc_err(
            StatusCode::BAD_REQUEST,
            "FutureRev",
            "repoRev is too far in the future",
        );
    }

    let Some(data_cid) = decode_32_byte_data(&input.data) else {
        return xrpc_err(
            StatusCode::BAD_REQUEST,
            "InvalidRequest",
            "data must decode to 32 bytes",
        );
    };

    let existing_repo_rev: Option<String> = match sqlx::query_scalar(
        "SELECT repo_rev FROM chat.conversation_space_writers WHERE space_uri = $1 AND writer_did = $2",
    )
    .bind(&input.space)
    .bind(&caller_did)
    .fetch_optional(runtime.pool())
    .await
    {
        Ok(v) => v,
        Err(e) => {
            return xrpc_err(
                StatusCode::INTERNAL_SERVER_ERROR,
                "InternalServerError",
                e.to_string(),
            );
        }
    };
    if let Some(prev_repo_rev) = existing_repo_rev {
        if input.repo_rev <= prev_repo_rev {
            return xrpc_err(
                StatusCode::BAD_REQUEST,
                "FutureRev",
                "repoRev must be strictly monotonic",
            );
        }
    }

    let space_rev = runtime.next_monotonic_tid(now_sec, status.latest_space_rev.as_deref());

    let mut tx = match runtime.pool().begin().await {
        Ok(tx) => tx,
        Err(e) => {
            return xrpc_err(
                StatusCode::INTERNAL_SERVER_ERROR,
                "InternalServerError",
                e.to_string(),
            );
        }
    };

    if let Err(e) = sqlx::query(
        "INSERT INTO chat.conversation_space_writers ( \
             space_uri, writer_did, repo_rev, space_rev, data_cid, updated_at \
         ) VALUES ($1, $2, $3, $4, $5, clock_timestamp()) \
         ON CONFLICT (space_uri, writer_did) DO UPDATE SET \
             repo_rev = EXCLUDED.repo_rev, \
             space_rev = EXCLUDED.space_rev, \
             data_cid = EXCLUDED.data_cid, \
             updated_at = EXCLUDED.updated_at",
    )
    .bind(&input.space)
    .bind(&caller_did)
    .bind(&input.repo_rev)
    .bind(&space_rev)
    .bind(data_cid.as_slice())
    .execute(&mut *tx)
    .await
    {
        return xrpc_err(
            StatusCode::INTERNAL_SERVER_ERROR,
            "InternalServerError",
            e.to_string(),
        );
    }

    if let Err(e) = sqlx::query(
        "UPDATE chat.conversation_spaces SET latest_space_rev = $2 WHERE space_uri = $1",
    )
    .bind(&input.space)
    .bind(&space_rev)
    .execute(&mut *tx)
    .await
    {
        return xrpc_err(
            StatusCode::INTERNAL_SERVER_ERROR,
            "InternalServerError",
            e.to_string(),
        );
    }

    if let Err(e) = tx.commit().await {
        return xrpc_err(
            StatusCode::INTERNAL_SERVER_ERROR,
            "InternalServerError",
            e.to_string(),
        );
    }

    // Post-commit best-effort fan-out to registered syncers (never inside open SQL tx, M-F04)
    let _ = super::revocation_fanout::fan_out_notify_write_to_syncers(
        &runtime,
        &input.space,
        &caller_did,
        &input.repo_rev,
        &space_rev,
        &data_cid,
    )
    .await;

    (
        StatusCode::OK,
        Json(json!({
            "spaceRev": space_rev,
        })),
    )
        .into_response()
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct RemoveWriterInput {
    space: String,
    writer: String,
}

async fn remove_writer(
    State(runtime): State<Arc<SpaceHostRuntime>>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let caller_did = match authenticate_service_jwt(
        &runtime,
        &headers,
        "com.atproto.space.removeWriter",
    )
    .await
    {
        Ok(d) => d,
        Err(resp) => return resp,
    };

    let input: RemoveWriterInput = match serde_json::from_slice(&body) {
        Ok(v) => v,
        Err(e) => return xrpc_err(StatusCode::BAD_REQUEST, "InvalidRequest", e.to_string()),
    };

    let status = match load_active_space_status(runtime.pool(), &input.space).await {
        Ok(s) => s,
        Err(resp) => return resp,
    };

    let writer_did = crate::identity::canonical_did(&input.writer).to_string();
    if caller_did != status.authority_did && caller_did != writer_did {
        return xrpc_err(
            StatusCode::FORBIDDEN,
            "NotSpaceOwner",
            "only Space authority or self-deleting account may remove writer",
        );
    }

    let _ = sqlx::query(
        "DELETE FROM chat.conversation_space_writers WHERE space_uri = $1 AND writer_did = $2",
    )
    .bind(&input.space)
    .bind(&writer_did)
    .execute(runtime.pool())
    .await;

    let _ = sqlx::query(
        "UPDATE chat.space_credential_jtis \
            SET revoked_at = COALESCE(revoked_at, clock_timestamp()) \
          WHERE space_uri = $1 AND writer_did = $2",
    )
    .bind(&input.space)
    .bind(&writer_did)
    .execute(runtime.pool())
    .await;

    (StatusCode::OK, Json(json!({}))).into_response()
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct RegisterNotifyInput {
    space: String,
    service: String,
}

async fn register_notify(
    State(runtime): State<Arc<SpaceHostRuntime>>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let input: RegisterNotifyInput = match serde_json::from_slice(&body) {
        Ok(v) => v,
        Err(e) => return xrpc_err(StatusCode::BAD_REQUEST, "InvalidRequest", e.to_string()),
    };

    if let Err(resp) = authenticate_credential_request(&runtime, &headers, &input.space).await {
        return resp;
    }

    let service_did = crate::identity::canonical_did(&input.service).to_string();
    let (_, endpoint_url, _) = match runtime.resolve_did_entry(&input.service, false).await {
        Ok(v) if !v.1.is_empty() => v,
        Ok(_) => {
            return xrpc_err(
                StatusCode::BAD_REQUEST,
                "InvalidService",
                "service DID document has no endpoint",
            )
        }
        Err(e) => return xrpc_err(StatusCode::BAD_REQUEST, "InvalidService", e.to_string()),
    };

    let expires_at = Utc::now() + chrono::Duration::hours(24);
    if let Err(e) = sqlx::query(
        "INSERT INTO chat.conversation_space_syncers ( \
             space_uri, service_did, service_ref, endpoint_url, registered_at, expires_at \
         ) VALUES ($1, $2, $3, $4, clock_timestamp(), $5) \
         ON CONFLICT (space_uri, service_ref) DO UPDATE SET \
             service_did = EXCLUDED.service_did, \
             endpoint_url = EXCLUDED.endpoint_url, \
             registered_at = EXCLUDED.registered_at, \
             expires_at = EXCLUDED.expires_at",
    )
    .bind(&input.space)
    .bind(&service_did)
    .bind(&input.service)
    .bind(&endpoint_url)
    .bind(expires_at)
    .execute(runtime.pool())
    .await
    {
        return xrpc_err(
            StatusCode::INTERNAL_SERVER_ERROR,
            "InternalServerError",
            e.to_string(),
        );
    }

    (
        StatusCode::OK,
        Json(json!({
            "expiresAt": expires_at.to_rfc3339_opts(SecondsFormat::Millis, true),
        })),
    )
        .into_response()
}

async fn unregister_notify(
    State(runtime): State<Arc<SpaceHostRuntime>>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let input: RegisterNotifyInput = match serde_json::from_slice(&body) {
        Ok(v) => v,
        Err(e) => return xrpc_err(StatusCode::BAD_REQUEST, "InvalidRequest", e.to_string()),
    };

    if let Err(resp) = authenticate_credential_request(&runtime, &headers, &input.space).await {
        return resp;
    }

    let _ = sqlx::query(
        "DELETE FROM chat.conversation_space_syncers WHERE space_uri = $1 AND service_ref = $2",
    )
    .bind(&input.space)
    .bind(&input.service)
    .execute(runtime.pool())
    .await;

    (StatusCode::OK, Json(json!({}))).into_response()
}
