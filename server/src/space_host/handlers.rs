//! Axum HTTP handlers for Option A Conversation `SpaceHost` (`com.atproto.space.*`, Nov-12).

use std::{collections::BTreeMap, future::Future, sync::Arc, time::Duration};

use atproto_spaces::{
    http_signature::verify_credential_request,
    kem::{decapsulate_p256, decode_p256_did_key},
    lthash::{compute_dagcbor_cid, LtHash},
    mac::{
        parse_accept_signature, sign_commit_mac, sign_record_mac, MacProfile,
        ACCEPT_SIGNATURE_HEADER,
    },
    star::{validate_canonical_dagcbor_record, write_star_repo, StarRecordEntry, MAX_RECORD_BYTES},
    tokens::{SpaceTokenClaims, SpaceTokenKind, CREDENTIAL_DEFAULT_LIFETIME_SECS},
    SpaceUri, SpacesError,
};
use axum::{
    body::Bytes,
    extract::{Query, State},
    http::{
        header::{CONTENT_TYPE, VARY},
        HeaderMap, HeaderValue, StatusCode,
    },
    response::{IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use base64::{
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
    Engine as _,
};
use chrono::{DateTime, TimeZone as _, Utc};
use hmac::{Hmac, Mac as _};
use serde::Deserialize;
use serde_json::{json, Value};
use sha2::{Digest as _, Sha256};
use sqlx::FromRow;
use uuid::Uuid;

use super::{
    decode_tid_micros,
    revocation_fanout::{allow_loopback_space_endpoint, build_space_webhook_client},
    SpaceHostRuntime,
};
use crate::{
    storage::DbPool,
    util::outbound_body::{collect_bounded, ResponseBodyBudget, PROFILE_OR_DEVICE_MAX_BYTES},
};

#[derive(Clone, Copy)]
struct ClockScoped<H>(H);

impl<H, T> axum::handler::Handler<T, Arc<SpaceHostRuntime>> for ClockScoped<H>
where
    H: axum::handler::Handler<T, Arc<SpaceHostRuntime>>,
    T: 'static,
{
    type Future = std::pin::Pin<Box<dyn Future<Output = Response> + Send>>;

    fn call(self, req: axum::extract::Request, state: Arc<SpaceHostRuntime>) -> Self::Future {
        let clock = Arc::clone(state.clock());
        let inner = self.0.call(req, state);
        Box::pin(async move {
            let deterministic = clock.is_deterministic();
            let scoped = crate::sim_hooks::scope_ds_clock(clock, inner);
            if deterministic {
                crate::sim_hooks::drive_sim_io(scoped).await
            } else {
                scoped.await
            }
        })
    }
}

pub fn space_host_router(runtime: Arc<SpaceHostRuntime>) -> Router {
    Router::new()
        .route(
            "/xrpc/com.atproto.space.authorizeSpaceSync",
            post(ClockScoped(authorize_space_sync)),
        )
        .route(
            "/xrpc/com.atproto.space.listWriters",
            get(ClockScoped(list_writers)),
        )
        .route(
            "/xrpc/com.atproto.space.getSpace",
            get(ClockScoped(get_space)),
        )
        .route(
            "/xrpc/com.atproto.space.notifyRepoUpdate",
            post(ClockScoped(notify_repo_update)),
        )
        .route(
            "/xrpc/com.atproto.space.removeWriter",
            post(ClockScoped(remove_writer)),
        )
        .route(
            "/xrpc/com.atproto.space.putRecord",
            post(ClockScoped(put_record)),
        )
        .route(
            "/xrpc/com.atproto.space.getRecord",
            get(ClockScoped(get_record)),
        )
        .route(
            "/xrpc/com.atproto.space.getRepo",
            get(ClockScoped(get_repo)),
        )
        .route(
            "/xrpc/com.atproto.memberspace.putMembers",
            post(ClockScoped(put_members)),
        )
        .route(
            "/xrpc/com.atproto.memberspace.removeMembers",
            post(ClockScoped(remove_members)),
        )
        .route(
            "/xrpc/com.atproto.memberspace.listMembers",
            get(ClockScoped(list_members)),
        )
        .route(
            "/xrpc/com.atproto.managedspace.checkAccess",
            get(ClockScoped(check_access)),
        )
        .with_state(runtime)
}

#[derive(Debug, FromRow)]
pub(crate) struct SpaceStatusRow {
    pub conversation_id: Uuid,
    pub generation: i64,
    /// The MLS group of `generation`, bound into a signed membership refusal.
    pub group_id: Vec<u8>,
    pub authority_did: String,
    pub latest_space_rev: Option<String>,
    pub deleted_at: Option<DateTime<Utc>>,
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

#[allow(clippy::result_large_err)]
fn parse_canonical_space_uri(raw: &str, expected_authority: &str) -> Result<SpaceUri, Response> {
    let parsed = SpaceUri::parse_hedged(raw)
        .map_err(|e| xrpc_err(StatusCode::BAD_REQUEST, "InvalidSpaceUri", e.to_string()))?;
    if parsed.authority != expected_authority {
        return Err(xrpc_err(
            StatusCode::BAD_REQUEST,
            "InvalidSpaceUri",
            "space authority mismatch",
        ));
    }
    Ok(parsed)
}

pub(crate) async fn load_active_space_status(
    pool: &DbPool,
    space_uri: &str,
) -> Result<SpaceStatusRow, Response> {
    let row: Option<SpaceStatusRow> = sqlx::query_as(
        "SELECT cs.conversation_id, \
                cs.generation, \
                g.group_id, \
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

async fn has_space_read_access(
    pool: &DbPool,
    conversation_id: Uuid,
    space_uri: &str,
    user_did: &str,
) -> Result<bool, Response> {
    let allowed: bool = sqlx::query_scalar(
        "SELECT EXISTS( \
             SELECT 1 FROM chat.participants p \
              WHERE p.conversation_id = $1 \
                AND p.user_did = $2 \
                AND p.current_membership = TRUE \
                AND p.status = 'active' \
         ) OR EXISTS( \
             SELECT 1 FROM chat.managed_space_members m \
              WHERE m.space_uri = $3 \
                AND m.member_did = $2 \
                AND m.can_read = TRUE \
         )",
    )
    .bind(conversation_id)
    .bind(user_did)
    .bind(space_uri)
    .fetch_one(pool)
    .await
    .map_err(|e| {
        xrpc_err(
            StatusCode::INTERNAL_SERVER_ERROR,
            "InternalServerError",
            e.to_string(),
        )
    })?;
    Ok(allowed)
}

async fn has_space_write_access(
    pool: &DbPool,
    conversation_id: Uuid,
    space_uri: &str,
    user_did: &str,
) -> Result<bool, Response> {
    let allowed: bool = sqlx::query_scalar(
        "SELECT EXISTS( \
             SELECT 1 FROM chat.participants p \
              WHERE p.conversation_id = $1 \
                AND p.user_did = $2 \
                AND p.current_membership = TRUE \
                AND p.status = 'active' \
         ) OR EXISTS( \
             SELECT 1 FROM chat.managed_space_members m \
              WHERE m.space_uri = $3 \
                AND m.member_did = $2 \
                AND m.can_write = TRUE \
         )",
    )
    .bind(conversation_id)
    .bind(user_did)
    .bind(space_uri)
    .fetch_one(pool)
    .await
    .map_err(|e| {
        xrpc_err(
            StatusCode::INTERNAL_SERVER_ERROR,
            "InternalServerError",
            e.to_string(),
        )
    })?;
    Ok(allowed)
}

async fn authenticate_credential_request(
    runtime: &SpaceHostRuntime,
    headers: &HeaderMap,
    space_uri: &str,
) -> Result<(SpaceStatusRow, SpaceTokenClaims), Response> {
    authenticate_credential_request_allowing_repo_audience(runtime, headers, space_uri, None).await
}

async fn authenticate_credential_request_allowing_repo_audience(
    runtime: &SpaceHostRuntime,
    headers: &HeaderMap,
    space_uri: &str,
    extra_audience_did: Option<&str>,
) -> Result<(SpaceStatusRow, SpaceTokenClaims), Response> {
    let status = load_active_space_status(runtime.pool(), space_uri).await?;
    let now = crate::sim_hooks::current_utc();
    let now_sec = now.timestamp().max(0) as u64;

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

    let claims_space = SpaceUri::parse_hedged(&claims.sub).ok().map(|s| s.raw);
    if claims.iss != runtime.authority_did() || claims_space.as_deref() != Some(space_uri) {
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

    let verified_hdrs = verify_credential_request(headers, cnf_kid, now_sec).map_err(|e| {
        xrpc_err(
            StatusCode::UNAUTHORIZED,
            "InvalidSpaceSignature",
            e.to_string(),
        )
    })?;

    let aud_canon = crate::identity::canonical_did(&verified_hdrs.audience_did);
    let matches_authority = aud_canon == runtime.authority_did();
    let matches_repo =
        extra_audience_did.is_some_and(|repo| aud_canon == crate::identity::canonical_did(repo));
    if !matches_authority && !matches_repo {
        return Err(xrpc_err(
            StatusCode::UNAUTHORIZED,
            "InvalidSpaceSignature",
            "Atproto-Space-Audience mismatch",
        ));
    }

    let jti_row: Option<(Option<DateTime<Utc>>, DateTime<Utc>)> = sqlx::query_as(
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
    if revoked_at.is_some() || expires_at <= now {
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
    let now = crate::sim_hooks::current_utc().timestamp();
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

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct NotifyRegistrationInput {
    endpoint: String,
    token: String,
}

fn deserialize_non_null_notify<'de, D>(
    deserializer: D,
) -> Result<Option<NotifyRegistrationInput>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    NotifyRegistrationInput::deserialize(deserializer).map(Some)
}

#[derive(Debug, Deserialize)]
struct ConfirmRegistrationOutput {
    challenge: String,
}

/// Lexicon procedure input for `com.atproto.space.authorizeSpaceSync`.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct AuthorizeSpaceSyncInput {
    space: String,
    credential_key: String,
    delegation_token: Option<String>,
    client_attestation: Option<String>,
    #[serde(default, deserialize_with = "deserialize_non_null_notify")]
    notify: Option<NotifyRegistrationInput>,
}

async fn confirm_and_upsert_subscriber(
    runtime: &SpaceHostRuntime,
    space_uri: &str,
    notify: &NotifyRegistrationInput,
    expires_at: DateTime<Utc>,
    now: DateTime<Utc>,
) -> Result<(), Response> {
    let endpoint_base = notify.endpoint.trim().trim_end_matches('/').to_string();
    let token = notify.token.as_str();
    if endpoint_base.is_empty()
        || endpoint_base.len() > 512
        || !(16..=512).contains(&token.len())
        || token.bytes().any(|b| b <= 0x20 || b == 0x7f)
    {
        return Err(xrpc_err(
            StatusCode::BAD_REQUEST,
            "InvalidRequest",
            "invalid notify endpoint or token",
        ));
    }

    let already_confirmed: Option<bool> = sqlx::query_scalar(
        "SELECT confirmed FROM chat.conversation_space_subscribers \
          WHERE space_uri = $1 AND endpoint_url = $2 AND token = $3",
    )
    .bind(space_uri)
    .bind(&endpoint_base)
    .bind(token)
    .fetch_optional(runtime.pool())
    .await
    .map_err(|e| {
        xrpc_err(
            StatusCode::INTERNAL_SERVER_ERROR,
            "InternalServerError",
            e.to_string(),
        )
    })?;

    if already_confirmed != Some(true) {
        let confirm_url = format!("{endpoint_base}/xrpc/com.atproto.space.confirmRegistration");
        let is_override = allow_loopback_space_endpoint(&confirm_url);
        let (effective_url, client) = build_space_webhook_client(&confirm_url, is_override)
            .map_err(|e| xrpc_err(StatusCode::BAD_REQUEST, "RegistrationNotConfirmed", e))?;
        let challenge = runtime.mint_credential_jti(space_uri, &format!("confirm:{endpoint_base}"));
        let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
        let resp = crate::sim_hooks::send_reqwest(
            client
                .post(&effective_url)
                .header(reqwest::header::CONTENT_TYPE, "application/json")
                .json(&json!({
                    "space": space_uri,
                    "token": token,
                    "challenge": &challenge,
                })),
        )
        .await
        .map_err(|e| xrpc_err(StatusCode::BAD_REQUEST, "RegistrationNotConfirmed", e))?;

        if !resp.status().is_success() {
            return Err(xrpc_err(
                StatusCode::BAD_REQUEST,
                "RegistrationNotConfirmed",
                format!(
                    "confirmRegistration returned HTTP {}",
                    resp.status().as_u16()
                ),
            ));
        }
        let body = collect_bounded(
            resp,
            ResponseBodyBudget::new(PROFILE_OR_DEVICE_MAX_BYTES, deadline),
        )
        .await
        .map_err(|e| {
            xrpc_err(
                StatusCode::BAD_REQUEST,
                "RegistrationNotConfirmed",
                e.to_string(),
            )
        })?;
        let echoed: ConfirmRegistrationOutput = serde_json::from_slice(&body).map_err(|e| {
            xrpc_err(
                StatusCode::BAD_REQUEST,
                "RegistrationNotConfirmed",
                e.to_string(),
            )
        })?;
        if echoed.challenge != challenge {
            return Err(xrpc_err(
                StatusCode::BAD_REQUEST,
                "RegistrationNotConfirmed",
                "confirmRegistration challenge mismatch",
            ));
        }
    }

    sqlx::query(
        "INSERT INTO chat.conversation_space_subscribers ( \
             space_uri, endpoint_url, token, expires_at, confirmed, notified_expired, updated_at \
         ) VALUES ($1, $2, $3, $4, TRUE, FALSE, $5) \
         ON CONFLICT (space_uri, endpoint_url, token) DO UPDATE SET \
             expires_at = EXCLUDED.expires_at, \
             confirmed = TRUE, \
             notified_expired = FALSE, \
             updated_at = EXCLUDED.updated_at",
    )
    .bind(space_uri)
    .bind(&endpoint_base)
    .bind(token)
    .bind(expires_at)
    .bind(now)
    .execute(runtime.pool())
    .await
    .map_err(|e| {
        xrpc_err(
            StatusCode::INTERNAL_SERVER_ERROR,
            "InternalServerError",
            e.to_string(),
        )
    })?;

    Ok(())
}

async fn authorize_space_sync(
    State(runtime): State<Arc<SpaceHostRuntime>>,
    body: Bytes,
) -> Response {
    let input: AuthorizeSpaceSyncInput = match serde_json::from_slice(&body) {
        Ok(input) => input,
        Err(e) => return xrpc_err(StatusCode::BAD_REQUEST, "InvalidRequest", e.to_string()),
    };
    let parsed_space = match parse_canonical_space_uri(&input.space, runtime.authority_did()) {
        Ok(s) => s,
        Err(resp) => return resp,
    };
    let space_uri = parsed_space.as_str();

    let credential_key = input.credential_key.as_str();
    if let Err(e) = decode_p256_did_key(credential_key) {
        return xrpc_err(StatusCode::BAD_REQUEST, "InvalidDidKey", e.to_string());
    }

    // Check Space existence/deletion BEFORE delegationToken so unauthenticated syncers
    // probing `{ space, credentialKey }` receive authoritative 404/410 status!
    let status = match load_active_space_status(runtime.pool(), space_uri).await {
        Ok(s) => s,
        Err(resp) => return resp,
    };

    let Some(delegation_jwt) = input.delegation_token.as_deref() else {
        return xrpc_err(
            StatusCode::FORBIDDEN,
            "AccountNotAuthorized",
            "delegationToken required for member-restricted Space",
        );
    };

    let now = crate::sim_hooks::current_utc();
    let now_sec = now.timestamp().max(0) as u64;
    if let Some(att_jwt) = input.client_attestation.as_deref() {
        let att_claims = match runtime
            .verify_space_token_send(SpaceTokenKind::ClientAttestation, att_jwt, now_sec)
            .await
        {
            Ok(c) => c,
            Err(SpacesError::InvalidClientAttestation(msg)) => {
                return xrpc_err(StatusCode::BAD_REQUEST, "InvalidClientAttestation", msg);
            }
            Err(e) => {
                return xrpc_err(
                    StatusCode::BAD_REQUEST,
                    "InvalidClientAttestation",
                    e.to_string(),
                );
            }
        };
        let expected_aud = format!("{}#atproto_pds", runtime.authority_did());
        if att_claims.aud.as_deref() != Some(expected_aud.as_str()) {
            return xrpc_err(
                StatusCode::BAD_REQUEST,
                "InvalidClientAttestation",
                "client attestation aud mismatch",
            );
        }
        if att_claims
            .cnf_kid
            .as_deref()
            .is_some_and(|kid| kid != credential_key)
        {
            return xrpc_err(
                StatusCode::BAD_REQUEST,
                "InvalidClientAttestation",
                "client attestation cnf.kid mismatch",
            );
        }
    }

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

    let del_sub = SpaceUri::parse_hedged(&del_claims.sub).ok().map(|s| s.raw);
    if del_sub.as_deref() != Some(space_uri)
        || del_claims
            .cnf_kid
            .as_deref()
            .is_some_and(|kid| kid != credential_key)
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

    // Active read-access check (excludes pending C33 direct-request targets, left, and removed members,
    // while honoring `com.atproto.memberspace` read grants).
    // If unauthorized, withdraw any carried notify registration and return the authority's signed denial.
    match has_space_read_access(
        runtime.pool(),
        status.conversation_id,
        space_uri,
        &del_claims.iss,
    )
    .await
    {
        Ok(true) => {}
        Ok(false) => {
            if let Some(ref notify) = input.notify {
                let endpoint_base = notify.endpoint.trim().trim_end_matches('/');
                let _ = sqlx::query(
                    "DELETE FROM chat.conversation_space_subscribers \
                      WHERE space_uri = $1 AND endpoint_url = $2 AND token = $3",
                )
                .bind(space_uri)
                .bind(endpoint_base)
                .bind(&notify.token)
                .execute(runtime.pool())
                .await;
            }
            let coordinates = (
                status.conversation_id,
                status.generation,
                status.group_id.as_slice(),
            );
            return match runtime.mint_space_denial(
                space_uri,
                &del_claims.iss,
                credential_key,
                coordinates,
                now_sec,
            ) {
                Ok(denial) => (
                    StatusCode::FORBIDDEN,
                    Json(json!({
                        "error": "NotAuthorized",
                        "message": "requester is not an active member of this conversation Space",
                        "denial": denial,
                    })),
                )
                    .into_response(),
                Err(e) => xrpc_err(StatusCode::INTERNAL_SERVER_ERROR, "InternalServerError", e),
            };
        }
        Err(resp) => return resp,
    }

    // Single-use 60s delegation jti replay cache
    let _ = sqlx::query("DELETE FROM chat.space_delegation_jtis WHERE expires_at <= $1")
        .bind(now)
        .execute(runtime.pool())
        .await;
    let del_exp = Utc
        .timestamp_opt(del_claims.exp as i64, 0)
        .single()
        .unwrap_or_else(|| now + chrono::Duration::seconds(60));
    let inserted = match sqlx::query(
        "INSERT INTO chat.space_delegation_jtis (authority_did, jti, expires_at, created_at) \
         VALUES ($1, $2, $3, $4) \
         ON CONFLICT (authority_did, jti) DO NOTHING",
    )
    .bind(runtime.authority_did())
    .bind(&del_claims.jti)
    .bind(del_exp)
    .bind(now)
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

    let exp_sec = now_sec + CREDENTIAL_DEFAULT_LIFETIME_SECS;
    let exp_dt = Utc
        .timestamp_opt(exp_sec as i64, 0)
        .single()
        .unwrap_or_else(|| now + chrono::Duration::seconds(600));

    if let Some(ref notify) = input.notify {
        if let Err(resp) =
            confirm_and_upsert_subscriber(&runtime, space_uri, notify, exp_dt, now).await
        {
            return resp;
        }
    }

    let cred_jti = runtime.mint_credential_jti(space_uri, &del_claims.iss);
    let cred_claims = SpaceTokenClaims {
        iss: runtime.authority_did().to_string(),
        sub: space_uri.to_string(),
        aud: None,
        iat: now_sec,
        exp: exp_sec,
        jti: cred_jti.clone(),
        cnf_kid: Some(credential_key.to_string()),
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
         VALUES ($1, $2, $3, $4, $5)",
    )
    .bind(&cred_jti)
    .bind(space_uri)
    .bind(&del_claims.iss)
    .bind(exp_dt)
    .bind(now)
    .execute(runtime.pool())
    .await
    {
        return xrpc_err(
            StatusCode::INTERNAL_SERVER_ERROR,
            "InternalServerError",
            e.to_string(),
        );
    }

    let mut out = json!({
        "credential": cred_jwt,
    });
    if let Some(space_rev) = status.latest_space_rev {
        out["spaceRev"] = json!(space_rev);
    }

    (StatusCode::OK, Json(out)).into_response()
}

#[derive(Debug, FromRow)]
struct WriterRow {
    writer_did: String,
    repo_rev: Option<String>,
    space_rev: String,
    data_cid: Option<Vec<u8>>,
    removed_at: Option<DateTime<Utc>>,
}

const EMPTY_SPACE_SNAPSHOT_REV: &str = "2222222222222";
const MAX_SNAPSHOT_WRITERS: i64 = 16_384;
const REMOVED_WRITER_RETENTION_HOURS: i64 = 72;
const INVENTORY_CURSOR_DOMAIN: &[u8] = b"catbird-space-inventory-cursor-v1";
type HmacSha256 = Hmac<Sha256>;

#[derive(Debug)]
struct InventoryCursor {
    snapshot_rev: String,
    commitment: [u8; 32],
    offset: usize,
}

#[derive(Debug)]
struct InventoryFailure {
    status: StatusCode,
    code: &'static str,
    message: &'static str,
}

impl IntoResponse for InventoryFailure {
    fn into_response(self) -> Response {
        xrpc_err(self.status, self.code, self.message)
    }
}

fn inventory_failure(
    status: StatusCode,
    code: &'static str,
    message: &'static str,
) -> InventoryFailure {
    InventoryFailure {
        status,
        code,
        message,
    }
}

fn inventory_commitment(rows: &[WriterRow]) -> Result<[u8; 32], InventoryFailure> {
    let mut hash = LtHash::empty();
    let mut previous_did: Option<&str> = None;
    for row in rows {
        let Some(repo_rev) = row.repo_rev.as_deref() else {
            return Err(inventory_failure(
                StatusCode::INTERNAL_SERVER_ERROR,
                "InternalServerError",
                "active writer inventory row missing repo_rev",
            ));
        };
        let Some(raw_cid) = row.data_cid.as_deref() else {
            return Err(inventory_failure(
                StatusCode::INTERNAL_SERVER_ERROR,
                "InternalServerError",
                "active writer inventory row missing data_cid",
            ));
        };
        if row.removed_at.is_some()
            || !atproto_spaces::is_valid_did(&row.writer_did)
            || repo_rev.len() != 13
            || decode_tid_micros(repo_rev).is_none()
            || row.space_rev.len() != 13
            || decode_tid_micros(&row.space_rev).is_none()
            || previous_did.is_some_and(|did| did >= row.writer_did.as_str())
        {
            return Err(inventory_failure(
                StatusCode::INTERNAL_SERVER_ERROR,
                "InternalServerError",
                "invalid or duplicate writer inventory row",
            ));
        }
        let data: &[u8; 32] = raw_cid.try_into().map_err(|_| {
            inventory_failure(
                StatusCode::INTERNAL_SERVER_ERROR,
                "InternalServerError",
                "writer inventory commitment is not 32 bytes",
            )
        })?;
        hash.add_inventory_entry(&row.writer_did, repo_rev, &row.space_rev, data)
            .map_err(|_| {
                inventory_failure(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "InternalServerError",
                    "writer inventory commitment could not be computed",
                )
            })?;
        previous_did = Some(&row.writer_did);
    }
    Ok(hash.commitment())
}

fn cursor_mac(key: &[u8; 32], payload: &[u8]) -> [u8; 32] {
    let mut mac = HmacSha256::new_from_slice(key).expect("HMAC accepts a 32-byte key");
    mac.update(INVENTORY_CURSOR_DOMAIN);
    mac.update(payload);
    mac.finalize().into_bytes().into()
}

fn encode_inventory_cursor(
    key: &[u8; 32],
    space_uri: &str,
    snapshot_rev: &str,
    commitment: &[u8; 32],
    offset: usize,
) -> Result<String, InventoryFailure> {
    let rev_len = u16::try_from(snapshot_rev.len()).map_err(|_| {
        inventory_failure(
            StatusCode::INTERNAL_SERVER_ERROR,
            "InternalServerError",
            "snapshot revision is too long",
        )
    })?;
    let offset = u32::try_from(offset).map_err(|_| {
        inventory_failure(
            StatusCode::PAYLOAD_TOO_LARGE,
            "InventoryTooLarge",
            "writer inventory exceeds the cursor range",
        )
    })?;
    let mut payload = Vec::with_capacity(1 + 32 + 2 + snapshot_rev.len() + 32 + 4);
    payload.push(1);
    payload.extend_from_slice(&Sha256::digest(space_uri.as_bytes()));
    payload.extend_from_slice(&rev_len.to_be_bytes());
    payload.extend_from_slice(snapshot_rev.as_bytes());
    payload.extend_from_slice(commitment);
    payload.extend_from_slice(&offset.to_be_bytes());
    let tag = cursor_mac(key, &payload);
    payload.extend_from_slice(&tag);
    Ok(URL_SAFE_NO_PAD.encode(payload))
}

fn decode_inventory_cursor(
    key: &[u8; 32],
    space_uri: &str,
    cursor: &str,
) -> Result<InventoryCursor, InventoryFailure> {
    if cursor.is_empty() || cursor.len() > 512 {
        return Err(inventory_failure(
            StatusCode::BAD_REQUEST,
            "InvalidCursor",
            "inventory cursor is not valid",
        ));
    }
    let bytes = URL_SAFE_NO_PAD.decode(cursor).map_err(|_| {
        inventory_failure(
            StatusCode::BAD_REQUEST,
            "InvalidCursor",
            "inventory cursor is not base64url",
        )
    })?;
    if bytes.len() < 1 + 32 + 2 + 1 + 32 + 4 + 32 {
        return Err(inventory_failure(
            StatusCode::BAD_REQUEST,
            "InvalidCursor",
            "inventory cursor is truncated",
        ));
    }
    let (payload, tag) = bytes.split_at(bytes.len() - 32);
    let mut mac = HmacSha256::new_from_slice(key).expect("HMAC accepts a 32-byte key");
    mac.update(INVENTORY_CURSOR_DOMAIN);
    mac.update(payload);
    if mac.verify_slice(tag).is_err() || payload[0] != 1 {
        return Err(inventory_failure(
            StatusCode::BAD_REQUEST,
            "InvalidCursor",
            "inventory cursor authentication failed",
        ));
    }
    let expected_space = Sha256::digest(space_uri.as_bytes());
    if payload[1..33] != expected_space[..] {
        return Err(inventory_failure(
            StatusCode::BAD_REQUEST,
            "InvalidCursor",
            "inventory cursor belongs to another Space",
        ));
    }
    let rev_len = u16::from_be_bytes([payload[33], payload[34]]) as usize;
    let rev_start = 35usize;
    let Some(rev_end) = rev_start.checked_add(rev_len) else {
        return Err(inventory_failure(
            StatusCode::BAD_REQUEST,
            "InvalidCursor",
            "inventory cursor has an invalid shape",
        ));
    };
    let Some(expected_len) = rev_end.checked_add(32 + 4) else {
        return Err(inventory_failure(
            StatusCode::BAD_REQUEST,
            "InvalidCursor",
            "inventory cursor has an invalid shape",
        ));
    };
    if rev_len == 0 || payload.len() != expected_len {
        return Err(inventory_failure(
            StatusCode::BAD_REQUEST,
            "InvalidCursor",
            "inventory cursor has an invalid shape",
        ));
    }
    let snapshot_rev = std::str::from_utf8(&payload[rev_start..rev_end])
        .map_err(|_| {
            inventory_failure(
                StatusCode::BAD_REQUEST,
                "InvalidCursor",
                "inventory cursor revision is not UTF-8",
            )
        })?
        .to_owned();
    let commitment: [u8; 32] = payload[rev_end..rev_end + 32]
        .try_into()
        .expect("cursor commitment bounds checked");
    let offset = u32::from_be_bytes(
        payload[rev_end + 32..expected_len]
            .try_into()
            .expect("cursor offset bounds checked"),
    ) as usize;
    Ok(InventoryCursor {
        snapshot_rev,
        commitment,
        offset,
    })
}

async fn load_complete_writer_inventory(
    runtime: &SpaceHostRuntime,
    conversation_id: Uuid,
    space_uri: &str,
) -> Result<(String, Vec<WriterRow>, [u8; 32]), InventoryFailure> {
    let mut tx = runtime.pool().begin().await.map_err(|_| {
        inventory_failure(
            StatusCode::INTERNAL_SERVER_ERROR,
            "InternalServerError",
            "could not begin inventory snapshot",
        )
    })?;
    sqlx::query("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY")
        .execute(&mut *tx)
        .await
        .map_err(|_| {
            inventory_failure(
                StatusCode::INTERNAL_SERVER_ERROR,
                "InternalServerError",
                "could not establish inventory snapshot",
            )
        })?;
    let status: Option<(Option<String>, Option<DateTime<Utc>>)> = sqlx::query_as(
        "SELECT latest_space_rev, deleted_at FROM chat.conversation_spaces WHERE space_uri = $1",
    )
    .bind(space_uri)
    .fetch_optional(&mut *tx)
    .await
    .map_err(|_| {
        inventory_failure(
            StatusCode::INTERNAL_SERVER_ERROR,
            "InternalServerError",
            "could not read inventory snapshot revision",
        )
    })?;
    let Some((latest_space_rev, deleted_at)) = status else {
        return Err(inventory_failure(
            StatusCode::NOT_FOUND,
            "SpaceNotFound",
            "Space is not hosted here",
        ));
    };
    if deleted_at.is_some() {
        return Err(inventory_failure(
            StatusCode::GONE,
            "SpaceDeleted",
            "Space generation is closed",
        ));
    }
    let rows: Vec<WriterRow> = sqlx::query_as(
        "SELECT w.writer_did, w.repo_rev, w.space_rev, w.data_cid, w.removed_at \
           FROM chat.conversation_space_writers w \
          WHERE w.space_uri = $2 \
            AND w.removed_at IS NULL \
            AND ( \
                EXISTS ( \
                    SELECT 1 \
                      FROM chat.participants p \
                     WHERE p.conversation_id = $1 \
                       AND p.user_did = w.writer_did \
                       AND p.status IN ('active', 'left', 'removed') \
                ) \
                OR EXISTS ( \
                    SELECT 1 \
                      FROM chat.managed_space_members m \
                     WHERE m.space_uri = w.space_uri \
                       AND m.member_did = w.writer_did \
                       AND m.can_write = TRUE \
                ) \
            ) \
          ORDER BY w.writer_did ASC \
          LIMIT $3",
    )
    .bind(conversation_id)
    .bind(space_uri)
    .bind(MAX_SNAPSHOT_WRITERS + 1)
    .fetch_all(&mut *tx)
    .await
    .map_err(|_| {
        inventory_failure(
            StatusCode::INTERNAL_SERVER_ERROR,
            "InternalServerError",
            "could not read writer inventory",
        )
    })?;
    tx.commit().await.map_err(|_| {
        inventory_failure(
            StatusCode::INTERNAL_SERVER_ERROR,
            "InternalServerError",
            "could not finish inventory snapshot",
        )
    })?;
    if rows.len() as i64 > MAX_SNAPSHOT_WRITERS {
        return Err(inventory_failure(
            StatusCode::PAYLOAD_TOO_LARGE,
            "InventoryTooLarge",
            "writer inventory exceeds the supported snapshot size",
        ));
    }
    let snapshot_rev = latest_space_rev
        .or_else(|| rows.iter().map(|row| row.space_rev.clone()).max())
        .unwrap_or_else(|| EMPTY_SPACE_SNAPSHOT_REV.to_owned());
    if snapshot_rev.len() != 13 || decode_tid_micros(&snapshot_rev).is_none() {
        return Err(inventory_failure(
            StatusCode::INTERNAL_SERVER_ERROR,
            "InternalServerError",
            "Space snapshot revision is invalid",
        ));
    }
    if rows
        .iter()
        .any(|row| row.space_rev.as_str() > snapshot_rev.as_str())
    {
        return Err(inventory_failure(
            StatusCode::INTERNAL_SERVER_ERROR,
            "InternalServerError",
            "Space revision precedes a writer revision",
        ));
    }
    let commitment = inventory_commitment(&rows)?;
    Ok((snapshot_rev, rows, commitment))
}

fn writer_row_to_json(row: &WriterRow) -> Result<Value, StatusCode> {
    if row.removed_at.is_some() {
        Ok(json!({
            "$type": "com.atproto.space.defs#repoRemoved",
            "repo": &row.writer_did,
            "spaceRev": &row.space_rev,
        }))
    } else {
        let (Some(repo_rev), Some(data_cid)) = (row.repo_rev.as_deref(), row.data_cid.as_deref())
        else {
            return Err(StatusCode::INTERNAL_SERVER_ERROR);
        };
        Ok(json!({
            "$type": "com.atproto.space.defs#repoWrite",
            "repo": &row.writer_did,
            "repoRev": repo_rev,
            "spaceRev": &row.space_rev,
            "data": { "$bytes": STANDARD.encode(data_cid) },
        }))
    }
}

async fn list_writers_snapshot(
    runtime: &SpaceHostRuntime,
    status: &SpaceStatusRow,
    headers: &HeaderMap,
    params: &BTreeMap<String, String>,
    space_uri: &str,
) -> Result<Response, InventoryFailure> {
    if params
        .keys()
        .any(|key| !matches!(key.as_str(), "space" | "cursor" | "limit"))
    {
        return Err(inventory_failure(
            StatusCode::BAD_REQUEST,
            "InvalidRequest",
            "unknown inventory parameter",
        ));
    }
    let accept_sig = headers
        .get(ACCEPT_SIGNATURE_HEADER)
        .and_then(|value| value.to_str().ok())
        .ok_or_else(|| {
            inventory_failure(
                StatusCode::BAD_REQUEST,
                "InvalidSpaceMac",
                "inventory snapshot requires Accept-Signature",
            )
        })?;
    let (label, key_share) =
        parse_accept_signature(accept_sig, MacProfile::Commit).map_err(|_| {
            inventory_failure(
                StatusCode::BAD_REQUEST,
                "InvalidSpaceMac",
                "invalid Accept-Signature commit MAC request",
            )
        })?;
    let shared_secret = decapsulate_p256(runtime.kem_key(), &key_share).map_err(|_| {
        inventory_failure(
            StatusCode::BAD_REQUEST,
            "InvalidSpaceMac",
            "invalid Accept-Signature KEM key share",
        )
    })?;
    let limit = match params.get("limit") {
        None => 100,
        Some(value) => value
            .parse::<usize>()
            .ok()
            .filter(|limit| (1..=1000).contains(limit))
            .ok_or_else(|| {
                inventory_failure(
                    StatusCode::BAD_REQUEST,
                    "InvalidRequest",
                    "limit must be 1..=1000",
                )
            })?,
    };
    let cursor = params
        .get("cursor")
        .map(|cursor| decode_inventory_cursor(runtime.inventory_cursor_key(), space_uri, cursor))
        .transpose()?;
    let (snapshot_rev, rows, commitment) =
        load_complete_writer_inventory(runtime, status.conversation_id, space_uri).await?;
    let offset = cursor.as_ref().map_or(0, |cursor| cursor.offset);
    if let Some(cursor) = cursor {
        if cursor.snapshot_rev != snapshot_rev || cursor.commitment != commitment {
            return Err(inventory_failure(
                StatusCode::CONFLICT,
                "SnapshotChanged",
                "writer inventory changed during pagination",
            ));
        }
    }
    if offset >= rows.len() && !(offset == 0 && rows.is_empty()) {
        return Err(inventory_failure(
            StatusCode::BAD_REQUEST,
            "InvalidCursor",
            "inventory cursor is past the terminal page",
        ));
    }
    let end = offset.saturating_add(limit).min(rows.len());
    let complete = end == rows.len();
    let mut repos = Vec::with_capacity(end.saturating_sub(offset));
    for row in &rows[offset..end] {
        repos.push(writer_row_to_json(row).map_err(|_| {
            inventory_failure(
                StatusCode::INTERNAL_SERVER_ERROR,
                "InternalServerError",
                "malformed writer inventory row",
            )
        })?);
    }
    let mut output = json!({
        "repos": repos,
        "complete": complete,
        "commit": {
            "space": space_uri,
            "repo": &status.authority_did,
            "rev": &snapshot_rev,
            "ver": 1,
            "data": { "$bytes": STANDARD.encode(commitment) },
        },
    });
    if !complete {
        output["cursor"] = json!(encode_inventory_cursor(
            runtime.inventory_cursor_key(),
            space_uri,
            &snapshot_rev,
            &commitment,
            end,
        )?);
    }
    let (mac_headers, _) = sign_commit_mac(
        &shared_secret,
        &key_share,
        &label,
        space_uri,
        &status.authority_did,
        &snapshot_rev,
        &commitment,
    )
    .map_err(|_| {
        inventory_failure(
            StatusCode::INTERNAL_SERVER_ERROR,
            "InternalServerError",
            "could not authenticate inventory commitment",
        )
    })?;
    let mut response = (StatusCode::OK, Json(output)).into_response();
    mac_headers.apply_to(response.headers_mut()).map_err(|_| {
        inventory_failure(
            StatusCode::INTERNAL_SERVER_ERROR,
            "InternalServerError",
            "could not format inventory MAC headers",
        )
    })?;
    response
        .headers_mut()
        .insert(VARY, HeaderValue::from_static("Accept-Signature"));
    Ok(response)
}

async fn list_writers(
    State(runtime): State<Arc<SpaceHostRuntime>>,
    headers: HeaderMap,
    Query(params): Query<BTreeMap<String, String>>,
) -> Response {
    let Some(raw_space) = params.get("space").map(String::as_str) else {
        return xrpc_err(StatusCode::BAD_REQUEST, "InvalidRequest", "missing space");
    };
    let parsed_space = match parse_canonical_space_uri(raw_space, runtime.authority_did()) {
        Ok(s) => s,
        Err(resp) => return resp,
    };
    let space_uri = parsed_space.as_str();
    let (status, _claims) =
        match authenticate_credential_request(&runtime, &headers, space_uri).await {
            Ok(v) => v,
            Err(resp) => return resp,
        };

    // An Accept-Signature commit-MAC request opts into the archive snapshot contract.
    if headers.contains_key(ACCEPT_SIGNATURE_HEADER) {
        return match list_writers_snapshot(&runtime, &status, &headers, &params, space_uri).await {
            Ok(response) => response,
            Err(error) => error.into_response(),
        };
    }

    let cursor = params.get("cursor").cloned();
    let limit = match params.get("limit") {
        None => 100_i64,
        Some(s) => match s.parse::<i64>().ok().filter(|n| (1..=1000).contains(n)) {
            Some(n) => n,
            None => {
                return xrpc_err(
                    StatusCode::BAD_REQUEST,
                    "InvalidRequest",
                    "limit must be 1..=1000",
                )
            }
        },
    };
    let removed_cutoff =
        crate::sim_hooks::current_utc() - chrono::Duration::hours(REMOVED_WRITER_RETENTION_HOURS);

    // Historical writer inclusion: ('active', 'left', 'removed') in ascending spaceRev order,
    // plus explicitly removed writers (#repoRemoved) within 72h, strictly excluding 'pending' C33 targets!
    let rows: Vec<WriterRow> = match sqlx::query_as(
        "SELECT w.writer_did, w.repo_rev, w.space_rev, w.data_cid, w.removed_at \
           FROM chat.conversation_space_writers w \
          WHERE w.space_uri = $2 \
            AND ( \
                (w.removed_at IS NULL AND ( \
                    EXISTS ( \
                        SELECT 1 \
                          FROM chat.participants p \
                         WHERE p.conversation_id = $1 \
                           AND p.user_did = w.writer_did \
                           AND p.status IN ('active', 'left', 'removed') \
                    ) \
                    OR EXISTS ( \
                        SELECT 1 \
                          FROM chat.managed_space_members m \
                         WHERE m.space_uri = w.space_uri \
                           AND m.member_did = w.writer_did \
                           AND m.can_write = TRUE \
                    ) \
                )) \
                OR (w.removed_at IS NOT NULL AND w.removed_at > $5) \
            ) \
            AND ($3::TEXT IS NULL OR w.space_rev > $3) \
          ORDER BY w.space_rev ASC \
          LIMIT $4",
    )
    .bind(status.conversation_id)
    .bind(space_uri)
    .bind(cursor.as_deref())
    .bind(limit + 1)
    .bind(removed_cutoff)
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

    let mut repos = Vec::with_capacity(take_len);
    for row in rows.iter().take(take_len) {
        match writer_row_to_json(row) {
            Ok(item) => repos.push(item),
            Err(status_code) => {
                return xrpc_err(
                    status_code,
                    "InternalServerError",
                    "malformed writer inventory row",
                )
            }
        }
    }

    let mut out = json!({ "repos": repos });
    if let Some(c) = next_cursor {
        out["cursor"] = json!(c);
    }
    let mut resp = (StatusCode::OK, Json(out)).into_response();
    resp.headers_mut()
        .insert(VARY, HeaderValue::from_static("Accept-Signature"));
    resp
}

async fn get_space(
    State(runtime): State<Arc<SpaceHostRuntime>>,
    headers: HeaderMap,
    Query(params): Query<BTreeMap<String, String>>,
) -> Response {
    let Some(raw_space) = params.get("space").map(String::as_str) else {
        return xrpc_err(StatusCode::BAD_REQUEST, "InvalidRequest", "missing space");
    };
    let parsed_space = match parse_canonical_space_uri(raw_space, runtime.authority_did()) {
        Ok(s) => s,
        Err(resp) => return resp,
    };
    let space_uri = parsed_space.as_str();
    let (status, _claims) =
        match authenticate_credential_request(&runtime, &headers, space_uri).await {
            Ok(v) => v,
            Err(resp) => return resp,
        };

    let members: Vec<String> = match sqlx::query_scalar(
        "SELECT did FROM ( \
             SELECT user_did AS did FROM chat.participants \
              WHERE conversation_id = $1 AND current_membership = TRUE AND status = 'active' \
             UNION \
             SELECT member_did AS did FROM chat.managed_space_members \
              WHERE space_uri = $2 AND can_read = TRUE \
         ) combined \
         ORDER BY did ASC",
    )
    .bind(status.conversation_id)
    .bind(space_uri)
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
        "space": space_uri,
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
struct NotifyRepoUpdateInput {
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

async fn notify_repo_update(
    State(runtime): State<Arc<SpaceHostRuntime>>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let caller_did =
        match authenticate_service_jwt(&runtime, &headers, "com.atproto.space.notifyRepoUpdate")
            .await
        {
            Ok(d) => d,
            Err(resp) => return resp,
        };

    let input: NotifyRepoUpdateInput = match serde_json::from_slice(&body) {
        Ok(v) => v,
        Err(e) => return xrpc_err(StatusCode::BAD_REQUEST, "InvalidRequest", e.to_string()),
    };

    let parsed_space = match parse_canonical_space_uri(&input.space, runtime.authority_did()) {
        Ok(s) => s,
        Err(resp) => return resp,
    };
    let space_uri = parsed_space.as_str();

    if caller_did != crate::identity::canonical_did(&input.repo) {
        return xrpc_err(
            StatusCode::FORBIDDEN,
            "NotAuthorized",
            "notifyRepoUpdate issuer must match repo DID",
        );
    }

    let status = match load_active_space_status(runtime.pool(), space_uri).await {
        Ok(s) => s,
        Err(resp) => return resp,
    };

    match has_space_write_access(
        runtime.pool(),
        status.conversation_id,
        space_uri,
        &caller_did,
    )
    .await
    {
        Ok(true) => {}
        Ok(false) => {
            return xrpc_err(
                StatusCode::FORBIDDEN,
                "NotAuthorized",
                "writer does not have write access to this Space",
            );
        }
        Err(resp) => return resp,
    }

    let now = crate::sim_hooks::current_utc();
    let now_sec = now.timestamp().max(0) as u64;
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
        "SELECT repo_rev FROM chat.conversation_space_writers \
          WHERE space_uri = $1 AND writer_did = $2 AND removed_at IS NULL",
    )
    .bind(space_uri)
    .bind(&caller_did)
    .fetch_optional(runtime.pool())
    .await
    {
        Ok(v) => v.flatten(),
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

    let prev_space_rev = status.latest_space_rev.clone();
    let space_rev = runtime.next_monotonic_tid(now_sec, prev_space_rev.as_deref());

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
             space_uri, writer_did, repo_rev, space_rev, prev_space_rev, data_cid, removed_at, updated_at \
         ) VALUES ($1, $2, $3, $4, $5, $6, NULL, $7) \
         ON CONFLICT (space_uri, writer_did) DO UPDATE SET \
             repo_rev = EXCLUDED.repo_rev, \
             space_rev = EXCLUDED.space_rev, \
             prev_space_rev = EXCLUDED.prev_space_rev, \
             data_cid = EXCLUDED.data_cid, \
             removed_at = NULL, \
             updated_at = EXCLUDED.updated_at",
    )
    .bind(space_uri)
    .bind(&caller_did)
    .bind(&input.repo_rev)
    .bind(&space_rev)
    .bind(prev_space_rev.as_deref())
    .bind(data_cid.as_slice())
    .bind(now)
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
    .bind(space_uri)
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

    // Post-commit best-effort fan-out to confirmed subscribers (never inside open SQL tx, M-F04)
    let _ = super::revocation_fanout::fan_out_repo_write_to_subscribers(
        &runtime,
        space_uri,
        &caller_did,
        &input.repo_rev,
        &space_rev,
        prev_space_rev.as_deref(),
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
    repo: String,
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

    let parsed_space = match parse_canonical_space_uri(&input.space, runtime.authority_did()) {
        Ok(s) => s,
        Err(resp) => return resp,
    };
    let space_uri = parsed_space.as_str();

    let status = match load_active_space_status(runtime.pool(), space_uri).await {
        Ok(s) => s,
        Err(resp) => return resp,
    };

    let writer_did = crate::identity::canonical_did(&input.repo).to_string();
    if caller_did != status.authority_did && caller_did != writer_did {
        return xrpc_err(
            StatusCode::FORBIDDEN,
            "NotAuthorized",
            "only Space authority or self-removing account may remove writer",
        );
    }

    let now = crate::sim_hooks::current_utc();
    let now_sec = now.timestamp().max(0) as u64;
    let prev_space_rev = status.latest_space_rev.clone();
    let new_space_rev = runtime.next_monotonic_tid(now_sec, prev_space_rev.as_deref());

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

    let updated = match sqlx::query(
        "UPDATE chat.conversation_space_writers \
            SET repo_rev = NULL, \
                data_cid = NULL, \
                prev_space_rev = $3, \
                space_rev = $4, \
                removed_at = $5, \
                updated_at = $5 \
          WHERE space_uri = $1 AND writer_did = $2 AND removed_at IS NULL",
    )
    .bind(space_uri)
    .bind(&writer_did)
    .bind(prev_space_rev.as_deref())
    .bind(&new_space_rev)
    .bind(now)
    .execute(&mut *tx)
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

    if let Err(e) = sqlx::query(
        "DELETE FROM chat.conversation_space_records WHERE space_uri = $1 AND writer_did = $2",
    )
    .bind(space_uri)
    .bind(&writer_did)
    .execute(&mut *tx)
    .await
    {
        return xrpc_err(
            StatusCode::INTERNAL_SERVER_ERROR,
            "InternalServerError",
            e.to_string(),
        );
    }

    if updated > 0 {
        if let Err(e) = sqlx::query(
            "UPDATE chat.conversation_spaces SET latest_space_rev = $2 WHERE space_uri = $1",
        )
        .bind(space_uri)
        .bind(&new_space_rev)
        .execute(&mut *tx)
        .await
        {
            return xrpc_err(
                StatusCode::INTERNAL_SERVER_ERROR,
                "InternalServerError",
                e.to_string(),
            );
        }
    }

    if let Err(e) = tx.commit().await {
        return xrpc_err(
            StatusCode::INTERNAL_SERVER_ERROR,
            "InternalServerError",
            e.to_string(),
        );
    }

    let _ = super::revocation_fanout::revoke_member_space_credentials_and_fan_out(
        &runtime,
        status.conversation_id,
        status.generation,
        &writer_did,
    )
    .await;

    if updated > 0 {
        let _ = super::revocation_fanout::fan_out_repo_removed_to_subscribers(
            &runtime,
            space_uri,
            &writer_did,
            &new_space_rev,
            prev_space_rev.as_deref(),
        )
        .await;
    }

    StatusCode::OK.into_response()
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ManagedMemberInput {
    did: String,
    read: bool,
    write: bool,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct PutMembersInput {
    space: String,
    members: Vec<ManagedMemberInput>,
}

async fn put_members(
    State(runtime): State<Arc<SpaceHostRuntime>>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let caller_did =
        match authenticate_service_jwt(&runtime, &headers, "com.atproto.memberspace.putMembers")
            .await
        {
            Ok(d) => d,
            Err(resp) => return resp,
        };

    let input: PutMembersInput = match serde_json::from_slice(&body) {
        Ok(v) => v,
        Err(e) => return xrpc_err(StatusCode::BAD_REQUEST, "InvalidRequest", e.to_string()),
    };
    if input.members.len() > 1_000 {
        return xrpc_err(
            StatusCode::BAD_REQUEST,
            "InvalidRequest",
            "members batch exceeds 1000",
        );
    }

    let parsed_space = match parse_canonical_space_uri(&input.space, runtime.authority_did()) {
        Ok(s) => s,
        Err(resp) => return resp,
    };
    let space_uri = parsed_space.as_str();

    let status = match load_active_space_status(runtime.pool(), space_uri).await {
        Ok(s) => s,
        Err(resp) => return resp,
    };
    if caller_did != status.authority_did {
        return xrpc_err(
            StatusCode::FORBIDDEN,
            "NotAuthorized",
            "only Space authority may mutate memberspace ACL",
        );
    }

    let mut normalized = Vec::with_capacity(input.members.len());
    for member in &input.members {
        let bare = crate::identity::canonical_did(&member.did).to_string();
        if bare != member.did || !atproto_spaces::is_atproto_did(&bare) {
            return xrpc_err(
                StatusCode::BAD_REQUEST,
                "InvalidRequest",
                "member DID must be a canonical bare ATProto DID",
            );
        }
        normalized.push((bare, member.read, member.write));
    }

    let now = crate::sim_hooks::current_utc();
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
    for (did, can_read, can_write) in &normalized {
        if let Err(e) = sqlx::query(
            "INSERT INTO chat.managed_space_members (space_uri, member_did, can_read, can_write, updated_at) \
             VALUES ($1, $2, $3, $4, $5) \
             ON CONFLICT (space_uri, member_did) DO UPDATE SET \
                 can_read = EXCLUDED.can_read, \
                 can_write = EXCLUDED.can_write, \
                 updated_at = EXCLUDED.updated_at",
        )
        .bind(space_uri)
        .bind(did)
        .bind(*can_read)
        .bind(*can_write)
        .bind(now)
        .execute(&mut *tx)
        .await
        {
            return xrpc_err(
                StatusCode::INTERNAL_SERVER_ERROR,
                "InternalServerError",
                e.to_string(),
            );
        }
    }
    if let Err(e) = tx.commit().await {
        return xrpc_err(
            StatusCode::INTERNAL_SERVER_ERROR,
            "InternalServerError",
            e.to_string(),
        );
    }

    for (did, can_read, _) in &normalized {
        if !*can_read {
            if let Ok(false) =
                is_active_space_member(runtime.pool(), status.conversation_id, did).await
            {
                let _ = super::revocation_fanout::revoke_member_space_credentials_and_fan_out(
                    &runtime,
                    status.conversation_id,
                    status.generation,
                    did,
                )
                .await;
            }
        }
    }

    StatusCode::OK.into_response()
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct RemoveMembersInput {
    space: String,
    dids: Vec<String>,
}

async fn remove_members(
    State(runtime): State<Arc<SpaceHostRuntime>>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let caller_did =
        match authenticate_service_jwt(&runtime, &headers, "com.atproto.memberspace.removeMembers")
            .await
        {
            Ok(d) => d,
            Err(resp) => return resp,
        };

    let input: RemoveMembersInput = match serde_json::from_slice(&body) {
        Ok(v) => v,
        Err(e) => return xrpc_err(StatusCode::BAD_REQUEST, "InvalidRequest", e.to_string()),
    };
    if input.dids.len() > 1_000 {
        return xrpc_err(
            StatusCode::BAD_REQUEST,
            "InvalidRequest",
            "dids batch exceeds 1000",
        );
    }

    let parsed_space = match parse_canonical_space_uri(&input.space, runtime.authority_did()) {
        Ok(s) => s,
        Err(resp) => return resp,
    };
    let space_uri = parsed_space.as_str();

    let status = match load_active_space_status(runtime.pool(), space_uri).await {
        Ok(s) => s,
        Err(resp) => return resp,
    };
    if caller_did != status.authority_did {
        return xrpc_err(
            StatusCode::FORBIDDEN,
            "NotAuthorized",
            "only Space authority may mutate memberspace ACL",
        );
    }

    let mut bare_dids = Vec::with_capacity(input.dids.len());
    for did in &input.dids {
        let bare = crate::identity::canonical_did(did).to_string();
        if bare != *did || !atproto_spaces::is_atproto_did(&bare) {
            return xrpc_err(
                StatusCode::BAD_REQUEST,
                "InvalidRequest",
                "member DID must be a canonical bare ATProto DID",
            );
        }
        bare_dids.push(bare);
    }

    if !bare_dids.is_empty() {
        if let Err(e) = sqlx::query(
            "DELETE FROM chat.managed_space_members WHERE space_uri = $1 AND member_did = ANY($2)",
        )
        .bind(space_uri)
        .bind(&bare_dids)
        .execute(runtime.pool())
        .await
        {
            return xrpc_err(
                StatusCode::INTERNAL_SERVER_ERROR,
                "InternalServerError",
                e.to_string(),
            );
        }
    }

    for did in &bare_dids {
        if let Ok(false) = is_active_space_member(runtime.pool(), status.conversation_id, did).await
        {
            let _ = super::revocation_fanout::revoke_member_space_credentials_and_fan_out(
                &runtime,
                status.conversation_id,
                status.generation,
                did,
            )
            .await;
        }
    }

    StatusCode::OK.into_response()
}

#[derive(Debug, FromRow)]
struct ManagedMemberRow {
    did: String,
    can_read: bool,
    can_write: bool,
}

async fn list_members(
    State(runtime): State<Arc<SpaceHostRuntime>>,
    headers: HeaderMap,
    Query(params): Query<BTreeMap<String, String>>,
) -> Response {
    if params
        .keys()
        .any(|k| !matches!(k.as_str(), "space" | "cursor" | "limit"))
    {
        return xrpc_err(
            StatusCode::BAD_REQUEST,
            "InvalidRequest",
            "unknown listMembers query parameter",
        );
    }
    let Some(raw_space) = params.get("space").map(String::as_str) else {
        return xrpc_err(StatusCode::BAD_REQUEST, "InvalidRequest", "missing space");
    };
    let parsed_space = match parse_canonical_space_uri(raw_space, runtime.authority_did()) {
        Ok(s) => s,
        Err(resp) => return resp,
    };
    let space_uri = parsed_space.as_str();

    let auth_is_bearer = headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|s| s.trim_start().starts_with("Bearer "));

    let status = if auth_is_bearer {
        let caller_did = match authenticate_service_jwt(
            &runtime,
            &headers,
            "com.atproto.memberspace.listMembers",
        )
        .await
        {
            Ok(d) => d,
            Err(resp) => return resp,
        };
        let s = match load_active_space_status(runtime.pool(), space_uri).await {
            Ok(s) => s,
            Err(resp) => return resp,
        };
        if caller_did != s.authority_did {
            match has_space_read_access(runtime.pool(), s.conversation_id, space_uri, &caller_did)
                .await
            {
                Ok(true) => {}
                Ok(false) => {
                    return xrpc_err(
                        StatusCode::FORBIDDEN,
                        "NotAuthorized",
                        "caller is not authorized to list members of this Space",
                    );
                }
                Err(resp) => return resp,
            }
        }
        s
    } else {
        match authenticate_credential_request(&runtime, &headers, space_uri).await {
            Ok((s, _)) => s,
            Err(resp) => return resp,
        }
    };

    let limit = match params.get("limit") {
        None => 100_i64,
        Some(s) => match s.parse::<i64>().ok().filter(|n| (1..=1000).contains(n)) {
            Some(n) => n,
            None => {
                return xrpc_err(
                    StatusCode::BAD_REQUEST,
                    "InvalidRequest",
                    "limit must be 1..=1000",
                );
            }
        },
    };
    let cursor = params.get("cursor").cloned();

    let rows: Vec<ManagedMemberRow> = match sqlx::query_as(
        "SELECT combined.did, \
                BOOL_OR(combined.can_read) AS can_read, \
                BOOL_OR(combined.can_write) AS can_write \
           FROM ( \
               SELECT p.user_did AS did, TRUE AS can_read, TRUE AS can_write \
                 FROM chat.participants p \
                WHERE p.conversation_id = $1 \
                  AND p.current_membership = TRUE \
                  AND p.status = 'active' \
               UNION ALL \
               SELECT m.member_did AS did, m.can_read, m.can_write \
                 FROM chat.managed_space_members m \
                WHERE m.space_uri = $2 \
           ) combined \
          WHERE ($3::TEXT IS NULL OR combined.did > $3) \
          GROUP BY combined.did \
          ORDER BY combined.did ASC \
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
        rows.get(take_len.saturating_sub(1)).map(|r| r.did.clone())
    } else {
        None
    };

    let members: Vec<Value> = rows
        .into_iter()
        .take(take_len)
        .map(|r| {
            json!({
                "did": r.did,
                "read": r.can_read,
                "write": r.can_write,
            })
        })
        .collect();

    let mut out = json!({ "members": members });
    if let Some(c) = next_cursor {
        out["cursor"] = json!(c);
    }
    (StatusCode::OK, Json(out)).into_response()
}

async fn check_access(
    State(runtime): State<Arc<SpaceHostRuntime>>,
    headers: HeaderMap,
    Query(params): Query<BTreeMap<String, String>>,
) -> Response {
    if params
        .keys()
        .any(|k| !matches!(k.as_str(), "space" | "repo" | "clientId"))
    {
        return xrpc_err(
            StatusCode::BAD_REQUEST,
            "InvalidRequest",
            "unknown checkAccess query parameter",
        );
    }
    let Some(raw_space) = params.get("space").map(String::as_str) else {
        return xrpc_err(StatusCode::BAD_REQUEST, "InvalidRequest", "missing space");
    };

    if let Err(resp) =
        authenticate_service_jwt(&runtime, &headers, "com.atproto.managedspace.checkAccess").await
    {
        return resp;
    }

    let parsed_space = match parse_canonical_space_uri(raw_space, runtime.authority_did()) {
        Ok(s) => s,
        Err(resp) => return resp,
    };
    let space_uri = parsed_space.as_str();

    let status = match load_active_space_status(runtime.pool(), space_uri).await {
        Ok(s) => s,
        Err(resp) => return resp,
    };

    if let Some(client_id) = params.get("clientId") {
        let valid_client = url::Url::parse(client_id)
            .ok()
            .is_some_and(|u| u.scheme() == "https" && u.as_str() == client_id);
        if !valid_client {
            return xrpc_err(
                StatusCode::BAD_REQUEST,
                "InvalidRequest",
                "clientId must be a canonical https URL",
            );
        }
    }

    let (can_read, can_write) = if let Some(raw_repo) = params.get("repo") {
        let bare = crate::identity::canonical_did(raw_repo);
        if bare != raw_repo || !atproto_spaces::is_atproto_did(bare) {
            return xrpc_err(
                StatusCode::BAD_REQUEST,
                "InvalidRequest",
                "repo must be a canonical bare ATProto DID",
            );
        }
        let r = match has_space_read_access(runtime.pool(), status.conversation_id, space_uri, bare)
            .await
        {
            Ok(v) => v,
            Err(resp) => return resp,
        };
        let w =
            match has_space_write_access(runtime.pool(), status.conversation_id, space_uri, bare)
                .await
            {
                Ok(v) => v,
                Err(resp) => return resp,
            };
        (r, w)
    } else {
        (false, false)
    };

    (
        StatusCode::OK,
        Json(json!({
            "read": can_read,
            "write": can_write,
        })),
    )
        .into_response()
}

fn write_dagcbor_head(out: &mut Vec<u8>, major: u8, val: u64) {
    let tag = major << 5;
    if val < 24 {
        out.push(tag | (val as u8));
    } else if val <= u8::MAX as u64 {
        out.push(tag | 24);
        out.push(val as u8);
    } else if val <= u16::MAX as u64 {
        out.push(tag | 25);
        out.extend_from_slice(&(val as u16).to_be_bytes());
    } else if val <= u32::MAX as u64 {
        out.push(tag | 26);
        out.extend_from_slice(&(val as u32).to_be_bytes());
    } else {
        out.push(tag | 27);
        out.extend_from_slice(&val.to_be_bytes());
    }
}

fn encode_atproto_json_item(value: &Value, out: &mut Vec<u8>, depth: usize) -> Result<(), String> {
    if depth > 64 {
        return Err("record nesting depth exceeds 64".into());
    }
    match value {
        Value::Null => out.push(0xf6),
        Value::Bool(false) => out.push(0xf4),
        Value::Bool(true) => out.push(0xf5),
        Value::Number(n) => {
            if let Some(u) = n.as_u64() {
                write_dagcbor_head(out, 0, u);
            } else if let Some(i) = n.as_i64() {
                let mag = (-1i128 - (i as i128)) as u64;
                write_dagcbor_head(out, 1, mag);
            } else {
                return Err("floating-point values are forbidden in ATProto DAG-CBOR".into());
            }
        }
        Value::String(s) => {
            write_dagcbor_head(out, 3, s.len() as u64);
            out.extend_from_slice(s.as_bytes());
        }
        Value::Array(arr) => {
            write_dagcbor_head(out, 4, arr.len() as u64);
            for item in arr {
                encode_atproto_json_item(item, out, depth + 1)?;
            }
        }
        Value::Object(map) => {
            if map.len() == 1 {
                if let Some(b64_val) = map.get("$bytes") {
                    let Some(b64) = b64_val.as_str() else {
                        return Err("$bytes value must be a base64 string".into());
                    };
                    let raw = STANDARD
                        .decode(b64)
                        .map_err(|e| format!("invalid $bytes base64: {e}"))?;
                    write_dagcbor_head(out, 2, raw.len() as u64);
                    out.extend_from_slice(&raw);
                    return Ok(());
                }
                if let Some(link_val) = map.get("$link") {
                    let Some(cid_str) = link_val.as_str() else {
                        return Err("$link value must be a CID string".into());
                    };
                    let parsed: cid::Cid = cid_str
                        .parse()
                        .map_err(|e| format!("invalid $link CID: {e}"))?;
                    write_dagcbor_head(out, 6, 42);
                    let raw = parsed.to_bytes();
                    write_dagcbor_head(out, 2, (raw.len() + 1) as u64);
                    out.push(0x00);
                    out.extend_from_slice(&raw);
                    return Ok(());
                }
            }
            let mut entries: Vec<(&str, &Value)> =
                map.iter().map(|(k, v)| (k.as_str(), v)).collect();
            entries.sort_by(|(a, _), (b, _)| (a.len(), a.as_bytes()).cmp(&(b.len(), b.as_bytes())));
            write_dagcbor_head(out, 5, entries.len() as u64);
            for (k, v) in entries {
                write_dagcbor_head(out, 3, k.len() as u64);
                out.extend_from_slice(k.as_bytes());
                encode_atproto_json_item(v, out, depth + 1)?;
            }
        }
    }
    Ok(())
}

fn atproto_json_to_canonical_dagcbor(record: &Value) -> Result<Vec<u8>, String> {
    if !record.is_object() {
        return Err("record must be a JSON object".into());
    }
    let mut out = Vec::new();
    encode_atproto_json_item(record, &mut out, 0)?;
    if out.is_empty() || out.len() > MAX_RECORD_BYTES {
        return Err(format!("encoded record exceeds {MAX_RECORD_BYTES} bytes"));
    }
    validate_canonical_dagcbor_record(&out).map_err(|e| e.to_string())?;
    Ok(out)
}

fn canonical_dagcbor_to_atproto_json(bytes: &[u8]) -> Result<Value, String> {
    let data: jacquard_common::types::value::Data =
        serde_ipld_dagcbor::from_slice(bytes).map_err(|e| e.to_string())?;
    serde_json::to_value(data).map_err(|e| e.to_string())
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct PutSpaceRecordInput {
    repo: String,
    space: String,
    collection: String,
    rkey: String,
    record: Value,
    #[allow(dead_code)]
    validate: Option<bool>,
}

async fn put_record(
    State(runtime): State<Arc<SpaceHostRuntime>>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let caller_did =
        match authenticate_service_jwt(&runtime, &headers, "com.atproto.space.putRecord").await {
            Ok(d) => d,
            Err(resp) => return resp,
        };

    let input: PutSpaceRecordInput = match serde_json::from_slice(&body) {
        Ok(v) => v,
        Err(e) => return xrpc_err(StatusCode::BAD_REQUEST, "InvalidRequest", e.to_string()),
    };

    let parsed_space = match parse_canonical_space_uri(&input.space, runtime.authority_did()) {
        Ok(s) => s,
        Err(resp) => return resp,
    };
    let space_uri = parsed_space.as_str();

    let repo_did = crate::identity::canonical_did(&input.repo).to_string();
    if repo_did != input.repo || !atproto_spaces::is_atproto_did(&repo_did) {
        return xrpc_err(
            StatusCode::BAD_REQUEST,
            "InvalidRequest",
            "repo must be a canonical bare ATProto DID",
        );
    }
    if caller_did != repo_did {
        return xrpc_err(
            StatusCode::FORBIDDEN,
            "NotAuthorized",
            "putRecord issuer must match repo DID",
        );
    }
    if !atproto_spaces::is_valid_nsid(&input.collection)
        || input.collection.starts_with("com.atproto.space.")
        || !atproto_spaces::is_valid_rkey(&input.rkey)
    {
        return xrpc_err(
            StatusCode::BAD_REQUEST,
            "InvalidRequest",
            "invalid collection NSID or record key",
        );
    }

    let record_uri = match parsed_space.record_uri(&repo_did, &input.collection, &input.rkey) {
        Ok(u) => u,
        Err(e) => return xrpc_err(StatusCode::BAD_REQUEST, "InvalidRequest", e.to_string()),
    };

    let status = match load_active_space_status(runtime.pool(), space_uri).await {
        Ok(s) => s,
        Err(resp) => return resp,
    };
    match has_space_write_access(
        runtime.pool(),
        status.conversation_id,
        space_uri,
        &caller_did,
    )
    .await
    {
        Ok(true) => {}
        Ok(false) => {
            return xrpc_err(
                StatusCode::FORBIDDEN,
                "NotAuthorized",
                "writer does not have write access to this Space",
            );
        }
        Err(resp) => return resp,
    }

    let record_cbor = match atproto_json_to_canonical_dagcbor(&input.record) {
        Ok(b) => b,
        Err(msg) => return xrpc_err(StatusCode::BAD_REQUEST, "InvalidRequest", msg),
    };
    let record_cid = compute_dagcbor_cid(&record_cbor);
    let record_cid_str = record_cid.to_string();

    let now = crate::sim_hooks::current_utc();
    let now_sec = now.timestamp().max(0) as u64;

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

    let prev_repo_rev: Option<String> = match sqlx::query_scalar(
        "SELECT repo_rev FROM chat.conversation_space_writers \
          WHERE space_uri = $1 AND writer_did = $2 AND removed_at IS NULL \
          FOR UPDATE",
    )
    .bind(space_uri)
    .bind(&caller_did)
    .fetch_optional(&mut *tx)
    .await
    {
        Ok(v) => v.flatten(),
        Err(e) => {
            return xrpc_err(
                StatusCode::INTERNAL_SERVER_ERROR,
                "InternalServerError",
                e.to_string(),
            );
        }
    };

    let prev_space_rev: Option<String> = match sqlx::query_scalar(
        "SELECT latest_space_rev FROM chat.conversation_spaces WHERE space_uri = $1 FOR UPDATE",
    )
    .bind(space_uri)
    .fetch_optional(&mut *tx)
    .await
    {
        Ok(v) => v.flatten(),
        Err(e) => {
            return xrpc_err(
                StatusCode::INTERNAL_SERVER_ERROR,
                "InternalServerError",
                e.to_string(),
            );
        }
    };

    let repo_rev = runtime.next_monotonic_tid(now_sec, prev_repo_rev.as_deref());
    let space_rev = runtime.next_monotonic_tid(now_sec, prev_space_rev.as_deref());

    if let Err(e) = sqlx::query(
        "INSERT INTO chat.conversation_space_records ( \
             space_uri, writer_did, collection, rkey, cid, record_cbor, repo_rev, updated_at \
         ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8) \
         ON CONFLICT (space_uri, writer_did, collection, rkey) DO UPDATE SET \
             cid = EXCLUDED.cid, \
             record_cbor = EXCLUDED.record_cbor, \
             repo_rev = EXCLUDED.repo_rev, \
             updated_at = EXCLUDED.updated_at",
    )
    .bind(space_uri)
    .bind(&caller_did)
    .bind(&input.collection)
    .bind(&input.rkey)
    .bind(&record_cid_str)
    .bind(&record_cbor)
    .bind(&repo_rev)
    .bind(now)
    .execute(&mut *tx)
    .await
    {
        return xrpc_err(
            StatusCode::INTERNAL_SERVER_ERROR,
            "InternalServerError",
            e.to_string(),
        );
    }

    let all_records: Vec<(String, String, String)> = match sqlx::query_as(
        "SELECT collection, rkey, cid \
           FROM chat.conversation_space_records \
          WHERE space_uri = $1 AND writer_did = $2 \
          ORDER BY collection ASC, rkey ASC",
    )
    .bind(space_uri)
    .bind(&caller_did)
    .fetch_all(&mut *tx)
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

    let mut lt = LtHash::empty();
    for (col, rk, cid_s) in &all_records {
        let Ok(parsed_cid) = cid_s.parse::<cid::Cid>() else {
            return xrpc_err(
                StatusCode::INTERNAL_SERVER_ERROR,
                "InternalServerError",
                "stored record CID is malformed",
            );
        };
        lt.add_record(col, rk, &parsed_cid);
    }
    let data_cid = lt.commitment();

    if let Err(e) = sqlx::query(
        "INSERT INTO chat.conversation_space_writers ( \
             space_uri, writer_did, repo_rev, space_rev, prev_space_rev, data_cid, removed_at, updated_at \
         ) VALUES ($1, $2, $3, $4, $5, $6, NULL, $7) \
         ON CONFLICT (space_uri, writer_did) DO UPDATE SET \
             repo_rev = EXCLUDED.repo_rev, \
             space_rev = EXCLUDED.space_rev, \
             prev_space_rev = EXCLUDED.prev_space_rev, \
             data_cid = EXCLUDED.data_cid, \
             removed_at = NULL, \
             updated_at = EXCLUDED.updated_at",
    )
    .bind(space_uri)
    .bind(&caller_did)
    .bind(&repo_rev)
    .bind(&space_rev)
    .bind(prev_space_rev.as_deref())
    .bind(data_cid.as_slice())
    .bind(now)
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
    .bind(space_uri)
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

    let _ = super::revocation_fanout::fan_out_repo_write_to_subscribers(
        &runtime,
        space_uri,
        &caller_did,
        &repo_rev,
        &space_rev,
        prev_space_rev.as_deref(),
        &data_cid,
    )
    .await;

    (
        StatusCode::OK,
        Json(json!({
            "uri": record_uri,
            "cid": record_cid_str,
            "validationStatus": "unknown",
        })),
    )
        .into_response()
}

async fn authenticate_space_repo_read(
    runtime: &SpaceHostRuntime,
    headers: &HeaderMap,
    space_uri: &str,
    repo_did: &str,
    expected_lxm: &str,
) -> Result<SpaceStatusRow, Response> {
    let auth_is_bearer = headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|s| s.trim_start().starts_with("Bearer "));

    if auth_is_bearer {
        let caller_did = authenticate_service_jwt(runtime, headers, expected_lxm).await?;
        let status = load_active_space_status(runtime.pool(), space_uri).await?;
        if caller_did != status.authority_did
            && !has_space_read_access(
                runtime.pool(),
                status.conversation_id,
                space_uri,
                &caller_did,
            )
            .await?
        {
            return Err(xrpc_err(
                StatusCode::FORBIDDEN,
                "AccountNotAuthorized",
                "caller does not have read access to this Space",
            ));
        }
        Ok(status)
    } else {
        let (status, _) = authenticate_credential_request_allowing_repo_audience(
            runtime,
            headers,
            space_uri,
            Some(repo_did),
        )
        .await?;
        Ok(status)
    }
}

async fn get_record(
    State(runtime): State<Arc<SpaceHostRuntime>>,
    headers: HeaderMap,
    Query(params): Query<BTreeMap<String, String>>,
) -> Response {
    if params
        .keys()
        .any(|k| !matches!(k.as_str(), "space" | "repo" | "collection" | "rkey"))
    {
        return xrpc_err(
            StatusCode::BAD_REQUEST,
            "InvalidRequest",
            "unknown getRecord query parameter",
        );
    }
    let (Some(raw_space), Some(raw_repo), Some(collection), Some(rkey)) = (
        params.get("space").map(String::as_str),
        params.get("repo").map(String::as_str),
        params.get("collection").map(String::as_str),
        params.get("rkey").map(String::as_str),
    ) else {
        return xrpc_err(
            StatusCode::BAD_REQUEST,
            "InvalidRequest",
            "missing required getRecord query parameter",
        );
    };

    let parsed_space = match parse_canonical_space_uri(raw_space, runtime.authority_did()) {
        Ok(s) => s,
        Err(resp) => return resp,
    };
    let space_uri = parsed_space.as_str();

    let repo_did = crate::identity::canonical_did(raw_repo);
    if repo_did != raw_repo
        || !atproto_spaces::is_atproto_did(repo_did)
        || !atproto_spaces::is_valid_nsid(collection)
        || !atproto_spaces::is_valid_rkey(rkey)
    {
        return xrpc_err(
            StatusCode::BAD_REQUEST,
            "InvalidRequest",
            "invalid repo, collection, or rkey",
        );
    }
    let record_uri = match parsed_space.record_uri(repo_did, collection, rkey) {
        Ok(u) => u,
        Err(e) => return xrpc_err(StatusCode::BAD_REQUEST, "InvalidRequest", e.to_string()),
    };

    if let Err(resp) = authenticate_space_repo_read(
        &runtime,
        &headers,
        space_uri,
        repo_did,
        "com.atproto.space.getRecord",
    )
    .await
    {
        return resp;
    }

    let requested_mac = if let Some(raw_sig) = headers.get(ACCEPT_SIGNATURE_HEADER) {
        let Ok(sig_str) = raw_sig.to_str() else {
            return xrpc_err(
                StatusCode::BAD_REQUEST,
                "InvalidSpaceMac",
                "non-ASCII Accept-Signature header",
            );
        };
        let Ok((label, key_share)) = parse_accept_signature(sig_str, MacProfile::Record) else {
            return xrpc_err(
                StatusCode::BAD_REQUEST,
                "InvalidSpaceMac",
                "invalid Accept-Signature record MAC request",
            );
        };
        let Ok(shared_secret) = decapsulate_p256(runtime.kem_key(), &key_share) else {
            return xrpc_err(
                StatusCode::BAD_REQUEST,
                "InvalidSpaceMac",
                "invalid Accept-Signature KEM key share",
            );
        };
        Some((label, key_share, shared_secret))
    } else {
        None
    };

    let row: Option<(String, Vec<u8>)> = match sqlx::query_as(
        "SELECT cid, record_cbor FROM chat.conversation_space_records \
          WHERE space_uri = $1 AND writer_did = $2 AND collection = $3 AND rkey = $4",
    )
    .bind(space_uri)
    .bind(repo_did)
    .bind(collection)
    .bind(rkey)
    .fetch_optional(runtime.pool())
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
    let Some((cid, record_cbor)) = row else {
        return xrpc_err(
            StatusCode::NOT_FOUND,
            "RecordNotFound",
            format!("record not found: {record_uri}"),
        );
    };

    let value = match canonical_dagcbor_to_atproto_json(&record_cbor) {
        Ok(v) => v,
        Err(e) => {
            return xrpc_err(StatusCode::INTERNAL_SERVER_ERROR, "InternalServerError", e);
        }
    };

    let mut response = (
        StatusCode::OK,
        Json(json!({
            "uri": record_uri,
            "cid": cid,
            "value": value,
        })),
    )
        .into_response();

    if let Some((label, key_share, shared_secret)) = requested_mac {
        let Ok((mac_headers, _)) =
            sign_record_mac(&shared_secret, &key_share, &label, &record_uri, &cid)
        else {
            return xrpc_err(
                StatusCode::INTERNAL_SERVER_ERROR,
                "InternalServerError",
                "failed to sign record MAC",
            );
        };
        if mac_headers.apply_to(response.headers_mut()).is_err() {
            return xrpc_err(
                StatusCode::INTERNAL_SERVER_ERROR,
                "InternalServerError",
                "failed to apply record MAC headers",
            );
        }
    }
    response
        .headers_mut()
        .insert(VARY, HeaderValue::from_static("Accept-Signature"));
    response
}

async fn get_repo(
    State(runtime): State<Arc<SpaceHostRuntime>>,
    headers: HeaderMap,
    Query(params): Query<BTreeMap<String, String>>,
) -> Response {
    if params
        .keys()
        .any(|k| !matches!(k.as_str(), "space" | "repo"))
    {
        return xrpc_err(
            StatusCode::BAD_REQUEST,
            "InvalidRequest",
            "unknown getRepo query parameter",
        );
    }
    let (Some(raw_space), Some(raw_repo)) = (
        params.get("space").map(String::as_str),
        params.get("repo").map(String::as_str),
    ) else {
        return xrpc_err(
            StatusCode::BAD_REQUEST,
            "InvalidRequest",
            "missing space or repo parameter",
        );
    };

    let parsed_space = match parse_canonical_space_uri(raw_space, runtime.authority_did()) {
        Ok(s) => s,
        Err(resp) => return resp,
    };
    let space_uri = parsed_space.as_str();

    let repo_did = crate::identity::canonical_did(raw_repo);
    if repo_did != raw_repo || !atproto_spaces::is_atproto_did(repo_did) {
        return xrpc_err(
            StatusCode::BAD_REQUEST,
            "InvalidRequest",
            "repo must be a canonical bare ATProto DID",
        );
    }

    if let Err(resp) = authenticate_space_repo_read(
        &runtime,
        &headers,
        space_uri,
        repo_did,
        "com.atproto.space.getRepo",
    )
    .await
    {
        return resp;
    }

    let requested_mac = if let Some(raw_sig) = headers.get(ACCEPT_SIGNATURE_HEADER) {
        let Ok(sig_str) = raw_sig.to_str() else {
            return xrpc_err(
                StatusCode::BAD_REQUEST,
                "InvalidSpaceMac",
                "non-ASCII Accept-Signature header",
            );
        };
        let Ok((label, key_share)) = parse_accept_signature(sig_str, MacProfile::Commit) else {
            return xrpc_err(
                StatusCode::BAD_REQUEST,
                "InvalidSpaceMac",
                "invalid Accept-Signature commit MAC request",
            );
        };
        let Ok(shared_secret) = decapsulate_p256(runtime.kem_key(), &key_share) else {
            return xrpc_err(
                StatusCode::BAD_REQUEST,
                "InvalidSpaceMac",
                "invalid Accept-Signature KEM key share",
            );
        };
        Some((label, key_share, shared_secret))
    } else {
        None
    };

    let writer_row: Option<(Option<String>, Option<Vec<u8>>)> = match sqlx::query_as(
        "SELECT repo_rev, data_cid FROM chat.conversation_space_writers \
          WHERE space_uri = $1 AND writer_did = $2 AND removed_at IS NULL",
    )
    .bind(space_uri)
    .bind(repo_did)
    .fetch_optional(runtime.pool())
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
    let Some((Some(repo_rev), Some(raw_data_cid))) = writer_row else {
        return xrpc_err(
            StatusCode::NOT_FOUND,
            "RepoNotFound",
            format!("no active hosted Space repository for {repo_did}"),
        );
    };
    let Ok(data_32): Result<[u8; 32], _> = raw_data_cid.as_slice().try_into() else {
        return xrpc_err(
            StatusCode::INTERNAL_SERVER_ERROR,
            "InternalServerError",
            "writer data_cid is not 32 bytes",
        );
    };

    let record_rows: Vec<(String, String, Vec<u8>)> = match sqlx::query_as(
        "SELECT collection, rkey, record_cbor \
           FROM chat.conversation_space_records \
          WHERE space_uri = $1 AND writer_did = $2",
    )
    .bind(space_uri)
    .bind(repo_did)
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

    let mut entries: Vec<StarRecordEntry> = record_rows
        .into_iter()
        .map(|(col, rk, record_dagcbor)| StarRecordEntry {
            path: format!("{col}/{rk}"),
            record_dagcbor,
        })
        .collect();
    entries.sort_by(|a, b| a.path.as_bytes().cmp(b.path.as_bytes()));

    let star_bytes = match write_star_repo(space_uri, repo_did, &repo_rev, &data_32, &entries) {
        Ok(b) => b,
        Err(e) => {
            return xrpc_err(
                StatusCode::INTERNAL_SERVER_ERROR,
                "InternalServerError",
                e.to_string(),
            );
        }
    };

    let mut response = (StatusCode::OK, star_bytes).into_response();
    response.headers_mut().insert(
        CONTENT_TYPE,
        HeaderValue::from_static("application/vnd.dasl.star"),
    );

    if let Some((label, key_share, shared_secret)) = requested_mac {
        let Ok((mac_headers, _)) = sign_commit_mac(
            &shared_secret,
            &key_share,
            &label,
            space_uri,
            repo_did,
            &repo_rev,
            &data_32,
        ) else {
            return xrpc_err(
                StatusCode::INTERNAL_SERVER_ERROR,
                "InternalServerError",
                "failed to sign commit MAC",
            );
        };
        if mac_headers.apply_to(response.headers_mut()).is_err() {
            return xrpc_err(
                StatusCode::INTERNAL_SERVER_ERROR,
                "InternalServerError",
                "failed to apply commit MAC headers",
            );
        }
    }
    response
        .headers_mut()
        .insert(VARY, HeaderValue::from_static("Accept-Signature"));
    response
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        sim_hooks::{scope_ds_clock, with_ds_clock, ManualDsClock},
        space_host::SpaceHostConfig,
    };
    use axum::{body::Body, http::Request};
    use p256::ecdsa::SigningKey;
    use tower_util::ServiceExt;

    #[tokio::test]
    async fn space_host_router_uses_runtime_clock_for_service_auth() {
        let now = chrono::DateTime::from_timestamp(1_600_000_000, 0).unwrap();
        let clock = Arc::new(ManualDsClock::new(now));
        let pool = sqlx::postgres::PgPoolOptions::new()
            .connect_lazy("postgres://127.0.0.1/space_clock_test")
            .unwrap();
        let authority = "did:web:space-clock.test";
        let runtime = Arc::new(
            SpaceHostRuntime::new(
                pool,
                SpaceHostConfig::for_test(
                    authority.to_string(),
                    SigningKey::from_slice(&[1; 32]).unwrap(),
                ),
            )
            .with_clock(clock.clone()),
        );
        let jwt = with_ds_clock(clock, || {
            runtime
                .mint_service_jwt(authority, "com.atproto.space.notifyRepoUpdate")
                .unwrap()
        });
        let request = Request::builder()
            .method("POST")
            .uri("/xrpc/com.atproto.space.notifyRepoUpdate")
            .header("authorization", format!("Bearer {jwt}"))
            .body(Body::from("{"))
            .unwrap();
        let ambient = Arc::new(ManualDsClock::new(now + chrono::Duration::days(1)));
        let response = scope_ds_clock(ambient, space_host_router(runtime).oneshot(request))
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        let bytes = axum::body::to_bytes(response.into_body(), 1024)
            .await
            .unwrap();
        let error: Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(error["error"], "InvalidRequest");
    }

    #[test]
    fn inventory_commitment_and_cursor_reject_reorder_duplicate_and_tamper() {
        let row = |did: &str, rev: &str, byte: u8| WriterRow {
            writer_did: did.to_owned(),
            repo_rev: Some(rev.to_owned()),
            space_rev: rev.to_owned(),
            data_cid: Some(vec![byte; 32]),
            removed_at: None,
        };
        let rows = vec![
            row("did:web:a.example", "3l2aaaaaaaaaa", 1),
            row("did:web:b.example", "3l2aaaaaaaaab", 2),
        ];
        let commitment = inventory_commitment(&rows).unwrap();
        let changed = vec![
            row("did:web:a.example", "3l2aaaaaaaaaa", 1),
            row("did:web:b.example", "3l2aaaaaaaaab", 3),
        ];
        assert_ne!(inventory_commitment(&changed).unwrap(), commitment);
        let reordered = vec![
            row("did:web:b.example", "3l2aaaaaaaaab", 2),
            row("did:web:a.example", "3l2aaaaaaaaaa", 1),
        ];
        assert!(inventory_commitment(&reordered).is_err());
        let duplicate = vec![
            row("did:web:a.example", "3l2aaaaaaaaaa", 1),
            row("did:web:a.example", "3l2aaaaaaaaab", 2),
        ];
        assert!(inventory_commitment(&duplicate).is_err());

        let key = [9u8; 32];
        let space = "at://did:web:authority.example/space/blue.catbird.labyrinth.conversation/test";
        let cursor =
            encode_inventory_cursor(&key, space, "3l2aaaaaaaaab", &commitment, 100).unwrap();
        let decoded = decode_inventory_cursor(&key, space, &cursor).unwrap();
        assert_eq!(decoded.snapshot_rev, "3l2aaaaaaaaab");
        assert_eq!(decoded.commitment, commitment);
        assert_eq!(decoded.offset, 100);
        assert!(
            decode_inventory_cursor(&key, "at://did:web:other.example/space/x/y", &cursor).is_err()
        );
        let mut tampered = cursor.into_bytes();
        let midpoint = tampered.len() / 2;
        tampered[midpoint] = if tampered[midpoint] == b'A' {
            b'B'
        } else {
            b'A'
        };
        assert!(
            decode_inventory_cursor(&key, space, std::str::from_utf8(&tampered).unwrap()).is_err()
        );
    }
}
