//! Authenticated home/sequencer membership handoff for ordinary groups.

use super::super::{outbound::OutboundError, FederationError};
use super::*;
use crate::chat_protocol::{
    dpop,
    error::{ChatEndpoint, ChatProtocolErrorCode},
    repository::auth,
    transcript::{decode_canonical_signed_mutation, VerifiedMutationProjection},
    validation::{BareDid, CanonicalHttpMethod, CanonicalUuidV4, TrustedRequestInstant},
};
use base64::Engine as _;
use chrono::{DateTime, Utc};
use sha2::Digest as _;
use sqlx::{Postgres, Transaction};

const DIRECTORY_NSID: &str = "blue.catbird.mlsDS.resolveGroupDevices";
const PACKAGE_NSID: &str = "blue.catbird.mlsDS.fetchKeyPackage";
const LABYRINTH_DIRECTORY_NSID: &str = "blue.catbird.mlsDS.getLabyrinthDirectory";
const GROUP_STATE_NSID: &str = "blue.catbird.mlsDS.getGroupConversationState";
const LABYRINTH_MEMBER_DEVICES_ENDPOINT: &str = "blue.catbird.labyrinth.getMemberDevices";
const GROUP_WELCOMES_NSID: &str = "blue.catbird.mlsDS.getGroupPendingWelcomes";

const CLAIM_GROUP_PACKAGE_EXPORT_SQL: &str = r#"
    INSERT INTO chat.group_key_package_exports AS lease
        (key_package_ref,conversation_id,recovery_request_id,sequencer_did,expires_at)
    VALUES($1,$2,$3,$4,$5)
    ON CONFLICT(key_package_ref) DO UPDATE SET
        conversation_id=EXCLUDED.conversation_id,recovery_request_id=EXCLUDED.recovery_request_id,
        sequencer_did=EXCLUDED.sequencer_did,expires_at=EXCLUDED.expires_at
    WHERE lease.expires_at <= $6 OR
        (lease.conversation_id,lease.recovery_request_id,lease.sequencer_did) =
        (EXCLUDED.conversation_id,EXCLUDED.recovery_request_id,EXCLUDED.sequencer_did)
"#;

#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct GroupDevice {
    user_did: String,
    device_id: Uuid,
    key_id: String,
    auth_generation: i64,
    signing_public_key: Vec<u8>,
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct GroupPackage {
    device: GroupDevice,
    wrapper: Vec<u8>,
    created_at: DateTime<Utc>,
}

pub(super) fn routes() -> Router<GroupRelayState> {
    Router::new()
        .route(
            "/xrpc/blue.catbird.mlsDS.resolveGroupDevices",
            post(ClockScoped(resolve_devices)),
        )
        .route(
            "/xrpc/blue.catbird.mlsDS.fetchKeyPackage",
            post(ClockScoped(fetch_package))
                .layer(DefaultBodyLimit::max(SINGLE_MLS_ARTIFACT_BODY_LIMIT_BYTES)),
        )
        .route(
            "/xrpc/blue.catbird.mlsDS.getLabyrinthDirectory",
            post(ClockScoped(get_labyrinth_directory)).layer(DefaultBodyLimit::max(65_536)),
        )
        .route(
            "/xrpc/blue.catbird.mlsDS.getGroupConversationState",
            post(ClockScoped(get_group_state)).layer(DefaultBodyLimit::max(65_536)),
        )
        .route(
            "/xrpc/blue.catbird.mlsDS.getGroupPendingWelcomes",
            post(ClockScoped(get_group_pending_welcomes)).layer(DefaultBodyLimit::max(65_536)),
        )
}

fn resolver(pool: &DbPool) -> super::super::resolver::DsResolver {
    super::super::resolver::DsResolver::new(
        pool.clone(),
        super::super::resolver::build_resolver_http_client(),
        crate::identity::service_did_base(),
        crate::identity::self_endpoint(),
        None,
        300,
    )
}

fn service_auth() -> Result<super::super::service_auth::ServiceAuthClient, String> {
    let pem = super::super::canonical_relay::configured_s2s_signing_key_pem()
        .map_err(|e| e.to_string())?;
    super::super::service_auth::ServiceAuthClient::from_es256_pem(
        crate::identity::service_did_base(),
        pem.as_bytes(),
        Some("#atproto".to_owned()),
    )
    .map_err(|e| e.to_string())
}

async fn call_home(
    pool: &DbPool,
    home: &str,
    nsid: &str,
    payload: &Value,
) -> Result<Value, FederationError> {
    let (status, response) = call_home_response(pool, home, nsid, payload).await?;
    if !(200..300).contains(&status) {
        return Err(FederationError::RemoteError {
            status,
            body: String::from_utf8_lossy(&response).into_owned(),
        });
    }
    Ok(serde_json::from_slice(&response)?)
}

/// One membership call to a peer home. A closed federation gate refuses it
/// before any resolution, DNS lookup or connection; the typed error keeps what
/// decided nothing (`FederationError::is_retryable`) apart from a refusal.
async fn call_home_response(
    pool: &DbPool,
    home: &str,
    nsid: &str,
    payload: &Value,
) -> Result<(u16, Vec<u8>), FederationError> {
    call_home_response_via(pool, None, home, nsid, payload).await
}

async fn call_home_response_via(
    pool: &DbPool,
    route_resolver: Option<&super::super::resolver::DsResolver>,
    home: &str,
    nsid: &str,
    payload: &Value,
) -> Result<(u16, Vec<u8>), FederationError> {
    super::super::peer_policy::ensure_federation_open()?;
    let destination = match route_resolver {
        Some(resolver) => resolver.resolve_ds_destination(home).await?,
        None => resolver(pool).resolve_ds_destination(home).await?,
    };
    let token = service_auth()
        .map_err(|reason| FederationError::ConfigError { reason })?
        .mint_token(home, nsid)?;
    super::super::outbound::OutboundClient::new(10, 15)
        .call_procedure_pinned_raw(
            &destination,
            nsid,
            &token,
            payload,
            SINGLE_MLS_ARTIFACT_BODY_LIMIT_BYTES,
        )
        .await
        .map_err(|error| match error {
            OutboundError::FederationDisabled { reason } => {
                FederationError::FederationDisabled { reason }
            }
            error if error.is_retryable() => FederationError::DsUnreachable {
                endpoint: destination.host.clone(),
                reason: error.to_string(),
            },
            error => FederationError::InvalidEnvelope {
                reason: error.to_string(),
            },
        })
}

/// This home's directory of `user_did`'s current devices, each authorized by
/// the user's PDS. A resolver, PDS or store that could not answer now stays
/// retryable (`FederationError::is_retryable`); anything else is a refusal.
async fn devices_for_user(
    pool: &DbPool,
    user_did: &str,
) -> Result<Vec<GroupDevice>, FederationError> {
    let refused = |reason: &str| FederationError::Forbidden(reason.to_owned());
    BareDid::parse(user_did).map_err(|e| refused(&e.to_string()))?;
    let resolver = resolver(pool);
    let home = resolver.resolve_authoritative_ds(user_did).await?;
    if !crate::identity::dids_equivalent(&home.did, resolver.self_did()) {
        return Err(refused(
            "device directory request is not at the user's home",
        ));
    }
    let keys = resolver.resolve_authorized_device_keys(user_did).await?;
    let rows: Vec<(Uuid, String, i64, Vec<u8>)> = sqlx::query_as(
        "SELECT d.device_id, k.key_id, d.auth_generation, k.signing_public_key \
           FROM chat.devices d JOIN chat.device_keys k USING (user_did, device_id) \
          WHERE d.user_did = $1 AND d.status = 'active' AND d.revoked_at IS NULL \
            AND k.revoked_at IS NULL AND k.enrollment_auth_generation <= d.auth_generation \
            AND NOT EXISTS (SELECT 1 FROM chat.device_keys newer \
                WHERE newer.user_did=k.user_did AND newer.device_id=k.device_id \
                  AND newer.enrollment_auth_generation>k.enrollment_auth_generation \
                  AND newer.enrollment_auth_generation<=d.auth_generation) \
          ORDER BY d.device_id, k.key_id",
    )
    .bind(user_did)
    .fetch_all(pool)
    .await?;
    let devices: Vec<_> = rows
        .into_iter()
        .filter_map(|(device_id, key_id, auth_generation, key)| {
            keys.iter()
                .any(|authorized| authorized == &key)
                .then(|| GroupDevice {
                    user_did: user_did.to_owned(),
                    device_id,
                    key_id,
                    auth_generation,
                    signing_public_key: key,
                })
        })
        .collect();
    if devices.is_empty() {
        return Err(refused("user has no active PDS-authorized group device"));
    }
    Ok(devices)
}

/// Obtain only current, home-vouched directory authority; this never stages rows.
/// A home, PDS or store that could not answer now stays retryable
/// (`FederationError::is_retryable`); a key no home vouches for is `Forbidden`.
pub(crate) async fn active_device_key(
    pool: &DbPool,
    user_did: &str,
    device_id: Uuid,
    key_id: &str,
) -> Result<(Vec<u8>, i64), FederationError> {
    let resolver = resolver(pool);
    let home = resolver.resolve_authoritative_ds(user_did).await?;
    let devices = if crate::identity::dids_equivalent(&home.did, resolver.self_did()) {
        devices_for_user(pool, user_did).await?
    } else {
        remote_devices(
            pool,
            &BTreeMap::from([(user_did.to_owned(), Some(home.did))]),
        )
        .await?
    };
    devices
        .into_iter()
        .find(|device| device.device_id == device_id && device.key_id == key_id)
        .map(|device| (device.signing_public_key, device.auth_generation))
        .ok_or_else(|| {
            FederationError::Forbidden("device key is not current at its authoritative home".into())
        })
}

async fn resolve_devices(
    State(state): State<GroupRelayState>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    if let Err(response) = verify_s2s_caller(&state, &headers, DIRECTORY_NSID, &body).await {
        return response;
    }
    let request: Value = match serde_json::from_slice(&body) {
        Ok(request) => request,
        Err(e) => return s2s_err(StatusCode::BAD_REQUEST, "InvalidRequest", e.to_string()),
    };
    let Some(user) = request.get("userDid").and_then(Value::as_str) else {
        return s2s_err(StatusCode::BAD_REQUEST, "InvalidRequest", "missing userDid");
    };
    match devices_for_user(&state.pool, user).await {
        Ok(devices) => Json(json!({ "devices": devices })).into_response(),
        // Its caller keeps a 4xx as a refusal; this home deciding nothing now
        // must stay retryable there.
        Err(e) if e.is_retryable() => s2s_err(
            StatusCode::SERVICE_UNAVAILABLE,
            "ServiceUnavailable",
            e.to_string(),
        ),
        Err(e) => s2s_err(StatusCode::FORBIDDEN, "NotAuthorized", e.to_string()),
    }
}

/// Every device a remote member's home vouches for, each authorized by the
/// member's PDS. A home or PDS that could not answer now stays retryable; an
/// invalid or unauthorized directory is a refusal (`Forbidden`).
async fn remote_devices(
    pool: &DbPool,
    routes: &BTreeMap<String, Option<String>>,
) -> Result<Vec<GroupDevice>, FederationError> {
    let refused = |reason: &str| FederationError::Forbidden(reason.to_owned());
    let resolver = resolver(pool);
    let mut devices = Vec::new();
    for (user, home) in routes {
        let Some(home) = home else { continue };
        let response = call_home(pool, home, DIRECTORY_NSID, &json!({ "userDid": user })).await?;
        let rows: Vec<GroupDevice> = serde_json::from_value(response["devices"].clone())?;
        let authorized = resolver.resolve_authorized_device_keys(user).await?;
        if rows.is_empty() {
            return Err(refused("empty remote group device directory"));
        }
        for device in rows {
            if device.user_did != *user
                || device.device_id.get_version_num() != 4
                || !(1..=9_007_199_254_740_991).contains(&device.auth_generation)
                || device.signing_public_key.len() != 32
                || crate::chat_protocol::validation::ed25519_key_id(&device.signing_public_key)
                    .map_err(|e| FederationError::Forbidden(e.to_string()))?
                    .as_str()
                    != device.key_id
                || !authorized
                    .iter()
                    .any(|key| key == &device.signing_public_key)
            {
                return Err(refused("remote group device is not PDS-authorized"));
            }
            devices.push(device);
        }
    }
    devices.sort_by(|left, right| {
        (&left.user_did, left.device_id, &left.key_id).cmp(&(
            &right.user_did,
            right.device_id,
            &right.key_id,
        ))
    });
    if devices
        .windows(2)
        .any(|pair| pair[0].user_did == pair[1].user_did && pair[0].device_id == pair[1].device_id)
    {
        return Err(refused("duplicate remote group device"));
    }
    Ok(devices)
}

async fn stage_devices(
    tx: &mut Transaction<'_, Postgres>,
    devices: &[GroupDevice],
    at: DateTime<Utc>,
) -> Result<(), FederationError> {
    for device in devices {
        stage_verified_remote_device(
            tx,
            &device.user_did,
            device.device_id,
            &device.key_id,
            device.auth_generation,
            &device.signing_public_key,
            at,
        )
        .await?;
    }
    Ok(())
}

/// Reconcile a home/PDS-verified key without replacing any historical identity.
/// A conflicting or invalid identity is `Forbidden`; this store failing is
/// `Database`.
pub(crate) async fn stage_verified_remote_device(
    tx: &mut Transaction<'_, Postgres>,
    user_did: &str,
    device_id: Uuid,
    key_id: &str,
    auth_generation: i64,
    signing_public_key: &[u8],
    at: DateTime<Utc>,
) -> Result<(), FederationError> {
    let refused = |reason: &str| FederationError::Forbidden(reason.to_owned());
    BareDid::parse(user_did).map_err(|e| refused(&e.to_string()))?;
    if device_id.get_version_num() != 4
        || !(1..=9_007_199_254_740_991).contains(&auth_generation)
        || crate::chat_protocol::validation::ed25519_key_id(signing_public_key)
            .map_err(|e| refused(&e.to_string()))?
            .as_str()
            != key_id
    {
        return Err(refused("invalid verified remote device identity"));
    }
    // Share enrollment's identity-slot lock, including the absent-device case.
    sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1, 0))")
        .bind(format!("{user_did}#{device_id}"))
        .execute(&mut **tx)
        .await?;
    let current: Option<(String, i64, Option<String>)> = sqlx::query_as(
        "SELECT status,auth_generation,dpop_jkt FROM chat.devices \
         WHERE user_did=$1 AND device_id=$2 FOR UPDATE",
    )
    .bind(user_did)
    .bind(device_id)
    .fetch_optional(&mut **tx)
    .await?;
    if let Some((status, generation, jkt)) = current {
        if status != "active" || generation > auth_generation {
            return Err(refused(
                "remote group device is revoked or its generation regressed",
            ));
        }
        if jkt.is_some() && generation != auth_generation {
            return Err(refused(
                "remote directory cannot rebind a local DPoP device",
            ));
        }
        let key: Option<(String, Vec<u8>, i64, Option<DateTime<Utc>>)> = sqlx::query_as(
            "SELECT key_id,signing_public_key,enrollment_auth_generation,revoked_at \
             FROM chat.device_keys WHERE user_did=$1 AND device_id=$2 \
             ORDER BY enrollment_auth_generation DESC LIMIT 1 FOR UPDATE",
        )
        .bind(user_did)
        .bind(device_id)
        .fetch_optional(&mut **tx)
        .await?;
        let Some((current_key_id, key, activated, revoked_at)) = key else {
            return Err(refused("remote group device has no enrolled signing key"));
        };
        if activated > generation || revoked_at.is_some() {
            return Err(refused(
                "remote group device key is revoked or not yet active",
            ));
        }
        if current_key_id == key_id {
            if key != signing_public_key {
                return Err(refused("conflicting remote group device key"));
            }
        } else {
            let reused: bool = sqlx::query_scalar(
                "SELECT EXISTS(SELECT 1 FROM chat.device_keys WHERE user_did=$1 AND device_id=$2 AND key_id=$3)",
            ).bind(user_did).bind(device_id).bind(key_id).fetch_one(&mut **tx).await?;
            if generation == auth_generation || reused {
                return Err(refused(
                    "remote group device key conflicts or reactivates a superseded key",
                ));
            }
        }
    }
    sqlx::query(
        "INSERT INTO chat.principals(user_did,created_at) VALUES($1,$2) ON CONFLICT DO NOTHING",
    )
    .bind(user_did)
    .bind(at)
    .execute(&mut **tx)
    .await?;
    let coarse_active_at = crate::chat_protocol::device_activity::coarse_activity_day(at);
    sqlx::query(
        "INSERT INTO chat.devices(user_did,device_id,device_name,status,dpop_jkt,auth_generation,capabilities,last_active_at,dormant_at,created_at,updated_at) \
         VALUES($1,$2,'federated-group-device','active',NULL,$3,chat.protocol_capabilities(),$5,NULL,$4,$4) \
         ON CONFLICT(user_did,device_id) DO UPDATE SET \
           auth_generation=GREATEST(chat.devices.auth_generation,EXCLUDED.auth_generation), \
           last_active_at=GREATEST(chat.devices.last_active_at,EXCLUDED.last_active_at), \
           dormant_at=NULL, \
           updated_at=GREATEST(chat.devices.updated_at,EXCLUDED.updated_at) \
         WHERE chat.devices.status='active'",
    )
    .bind(user_did)
    .bind(device_id)
    .bind(auth_generation)
    .bind(at)
    .bind(coarse_active_at)
    .execute(&mut **tx)
    .await?;
    sqlx::query(
        "INSERT INTO chat.device_keys(user_did,device_id,key_id,signing_public_key,enrollment_auth_generation,created_at) \
         VALUES($1,$2,$3,$4,$5,$6) ON CONFLICT(user_did,device_id,key_id) DO NOTHING",
    ).bind(user_did).bind(device_id).bind(key_id).bind(signing_public_key).bind(auth_generation).bind(at)
        .execute(&mut **tx).await?;
    Ok(())
}

/// Stage every device the remote members' homes vouch for. Only local routes
/// stage nothing; any remote route needs an open federation gate.
pub(crate) async fn stage_remote_group_participants(
    pool: &DbPool,
    routes: &BTreeMap<String, Option<String>>,
) -> Result<(), FederationError> {
    if !routes.values().any(Option::is_some) {
        return Ok(());
    }
    let devices = remote_devices(pool, routes).await?;
    let mut tx = pool.begin().await?;
    stage_devices(&mut tx, &devices, crate::sim_hooks::current_utc()).await?;
    Ok(tx.commit().await?)
}

/// Stage a home-exported recovery KeyPackage. A package that does not validate
/// for its device is `Forbidden`; this store failing is `Database`.
async fn stage_package(
    tx: &mut Transaction<'_, Postgres>,
    package: &GroupPackage,
    at: DateTime<Utc>,
) -> Result<(), FederationError> {
    let refused = |error: &dyn std::fmt::Display| FederationError::Forbidden(error.to_string());
    let device = &package.device;
    let credential = crate::chat_protocol::validation::basic_credential_identity(
        &BareDid::parse(&device.user_did).map_err(|e| refused(&e))?,
        &CanonicalUuidV4::parse(&device.device_id.to_string()).map_err(|e| refused(&e))?,
    );
    let valid = crate::chat_protocol::wire::validate_key_package(
        &package.wrapper,
        crate::chat_protocol::wire::KeyPackageValidationPolicy {
            expected_basic_credential: &credential,
            expected_signature_key: &device.signing_public_key,
            now_unix_seconds: u64::try_from(at.timestamp()).map_err(|e| refused(&e))?,
            max_bytes: crate::chat_protocol::wire::MAX_KEY_PACKAGE_WIRE_BYTES,
        },
    )
    .map_err(|e| refused(&e))?;
    let not_before = DateTime::from_timestamp(valid.not_before() as i64, 0)
        .ok_or_else(|| refused(&"invalid package lifetime"))?;
    let not_after = DateTime::from_timestamp(valid.not_after() as i64, 0)
        .ok_or_else(|| refused(&"invalid package lifetime"))?;
    sqlx::query(
        "INSERT INTO chat.key_packages(key_package_ref,wrapper_bytes,wrapper_sha256,init_key,owner_did,owner_device_id,owner_key_id,owner_auth_generation,not_before,not_after,status,created_at,usage_scope) \
         VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,'available',$11,'recovery') ON CONFLICT DO NOTHING",
    ).bind(valid.key_package_ref().as_slice()).bind(&package.wrapper).bind(Sha256::digest(&package.wrapper).as_slice())
        .bind(valid.init_key()).bind(&device.user_did).bind(device.device_id).bind(&device.key_id).bind(device.auth_generation)
        .bind(not_before).bind(not_after).bind(package.created_at.min(at))
        .execute(&mut **tx).await?;
    Ok(())
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct PackageRequest {
    conversation_id: Uuid,
    user_did: String,
    device_id: Uuid,
    key_id: String,
    recovery_request_id: Uuid,
    signed_request: Value,
}

async fn fetch_package(
    State(state): State<GroupRelayState>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let caller = match verify_s2s_caller(&state, &headers, PACKAGE_NSID, &body).await {
        Ok(caller) => caller,
        Err(response) => return response,
    };
    let request: PackageRequest = match serde_json::from_slice(&body) {
        Ok(request) => request,
        Err(e) => return s2s_err(StatusCode::BAD_REQUEST, "InvalidRequest", e.to_string()),
    };
    match export_package(&state.pool, &caller, &request).await {
        Ok(package) => Json(json!({ "package": package })).into_response(),
        Err(failure) => failure.into_response(),
    }
}

async fn export_package(
    pool: &DbPool,
    caller: &str,
    request: &PackageRequest,
) -> Result<GroupPackage, RelayFailure> {
    let device = devices_for_user(pool, &request.user_did)
        .await
        .map_err(RelayFailure::federation)?
        .into_iter()
        .find(|d| d.device_id == request.device_id && d.key_id == request.key_id)
        .ok_or_else(|| {
            RelayFailure::denied("requested package owner is not an active home device")
        })?;
    let signed = serde_json::to_vec(&request.signed_request).map_err(RelayFailure::denied)?;
    let mutation = crate::chat_protocol::transcript::decode_and_verify_signed_mutation(
        &signed,
        &device.signing_public_key,
    )
    .map_err(RelayFailure::denied)?;
    let VerifiedMutationProjection::ParticipantAcceptance(acceptance) = mutation.projection()
    else {
        return Err(RelayFailure::denied(
            "package export requires signed participant acceptance",
        ));
    };
    if mutation.actor_did().as_str() != request.user_did
        || mutation.actor_device_id().as_bytes() != request.device_id.as_bytes()
        || mutation.auth_generation() != device.auth_generation as u64
        || acceptance.recovery_request_id().as_bytes() != request.recovery_request_id.as_bytes()
        || acceptance
            .prior()
            .get("conversationId")
            .and_then(|v| match v {
                crate::chat_protocol::transcript::CanonicalValueRef::Uuid(id) => {
                    Some(id.as_bytes())
                }
                _ => None,
            })
            != Some(request.conversation_id.as_bytes())
    {
        return Err(RelayFailure::denied(
            "package export acceptance binding mismatch",
        ));
    }
    let now = crate::sim_hooks::current_utc();
    let mut tx = pool.begin().await.map_err(RelayFailure::storage)?;
    // The invitee is a clean-graph participant or a pending/active member of
    // the stored sequencer's verified index; an index removal always refuses.
    let allowed: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM chat.conversations c \
          WHERE c.conversation_id=$1 AND c.kind='group' AND c.is_remote AND c.sequencer_ds=$2 \
            AND (EXISTS(SELECT 1 FROM chat.participants p \
                  WHERE p.conversation_id=c.conversation_id AND p.user_did=$3 \
                    AND p.current_membership AND p.status IN ('pending','active')) \
                 OR EXISTS(SELECT 1 FROM chat.remote_group_memberships m \
                  WHERE m.conversation_id=c.conversation_id AND m.user_did=$3 \
                    AND m.sequencer_did=c.sequencer_ds AND m.status IN ('pending','active'))) \
            AND NOT EXISTS(SELECT 1 FROM chat.remote_group_memberships m \
                  WHERE m.conversation_id=c.conversation_id AND m.user_did=$3 \
                    AND m.status='removed'))",
    )
    .bind(request.conversation_id)
    .bind(caller)
    .bind(&request.user_did)
    .fetch_one(&mut *tx)
    .await
    .map_err(RelayFailure::storage)?;
    if !allowed {
        return Err(RelayFailure::denied(
            "package requester is not this invitation's sequencer",
        ));
    }
    let candidate: Option<(Vec<u8>, Vec<u8>, DateTime<Utc>, DateTime<Utc>)> = sqlx::query_as(
        "SELECT kp.key_package_ref,kp.wrapper_bytes,kp.created_at,kp.not_after FROM chat.key_packages kp \
          LEFT JOIN chat.group_key_package_exports e USING(key_package_ref) \
         WHERE kp.owner_did=$1 AND kp.owner_device_id=$2 AND kp.owner_key_id=$3 \
           AND kp.owner_auth_generation=$4 AND kp.usage_scope='recovery' AND kp.status='available' \
           AND kp.not_before < $5 AND $5 < kp.not_after \
           AND (e.key_package_ref IS NULL OR e.expires_at <= $5 OR (e.conversation_id=$6 AND e.recovery_request_id=$7 AND e.sequencer_did=$8)) \
         ORDER BY (e.recovery_request_id=$7) DESC NULLS LAST,kp.created_at,kp.key_package_ref LIMIT 1 FOR UPDATE OF kp",
    ).bind(&device.user_did).bind(device.device_id).bind(&device.key_id).bind(device.auth_generation).bind(now)
        .bind(request.conversation_id).bind(request.recovery_request_id).bind(caller)
        .fetch_optional(&mut *tx).await.map_err(RelayFailure::storage)?;
    let Some((reference, wrapper, created_at, not_after)) = candidate else {
        return Err(RelayFailure::Protocol(
            ChatProtocolErrorCode::KeyPackageUnavailable,
        ));
    };
    // This is a fresh statement after the KeyPackage lock. Its conflict predicate
    // also rechecks the winning lease after any concurrent UPSERT wait.
    let claimed = sqlx::query(CLAIM_GROUP_PACKAGE_EXPORT_SQL)
        .bind(reference)
        .bind(request.conversation_id)
        .bind(request.recovery_request_id)
        .bind(caller)
        .bind((now + chrono::Duration::minutes(5)).min(not_after))
        .bind(now)
        .execute(&mut *tx)
        .await
        .map_err(RelayFailure::storage)?;
    if claimed.rows_affected() != 1 {
        return Err(RelayFailure::Protocol(
            ChatProtocolErrorCode::KeyPackageUnavailable,
        ));
    }
    tx.commit().await.map_err(RelayFailure::storage)?;
    Ok(GroupPackage {
        device,
        wrapper,
        created_at,
    })
}

/// Catch this home's mirror of `conversation_id` up to its sequencer's
/// verified prefix. This store (or its S2S signing configuration) failing is
/// `Storage`; a sequencer, resolver or member home that could not answer now,
/// or a prefix that moved while it was fetched, is `Unavailable`; a prefix or
/// route this mirror cannot admit is `Denied`.
pub(super) async fn bootstrap_home_group(
    pool: &DbPool,
    conversation_id: Uuid,
    sequencer: &str,
) -> Result<(), RelayFailure> {
    let resolver = resolver(pool);
    let destination = resolver
        .resolve_ds_destination(sequencer)
        .await
        .map_err(RelayFailure::federation)?;
    let auth = service_auth().map_err(RelayFailure::Storage)?;
    let outbound = super::super::outbound::OutboundClient::new(10, 15);
    let digest_token = auth
        .mint_token(sequencer, super::super::reconciliation::DIGEST_NSID)
        .map_err(RelayFailure::federation)?;
    let digest = super::super::reconciliation::query_remote_digest(
        &outbound,
        &destination,
        &digest_token,
        &conversation_id.to_string(),
    )
    .await
    .map_err(RelayFailure::outbound)?;
    let selector = super::super::bootstrap::RemotePrefixBootstrapSelector::new(
        conversation_id,
        sequencer.to_owned(),
        digest.sequencer_term,
    )
    .map_err(RelayFailure::bootstrap)?;
    let sign =
        |target: &str, method: &str| auth.mint_token(target, method).map_err(|e| e.to_string());
    let admission = super::super::bootstrap::fetch_remote_prefix_admission(
        pool, &resolver, &outbound, &sign, selector,
    )
    .await
    .map_err(RelayFailure::bootstrap)?;
    let devices = remote_devices(pool, admission.participant_routes())
        .await
        .map_err(RelayFailure::federation)?;
    let mut tx = pool.begin().await.map_err(RelayFailure::storage)?;
    let earliest = admission
        .events()
        .first()
        .ok_or_else(|| RelayFailure::denied("empty group prefix"))?
        .received_at();
    stage_devices(&mut tx, &devices, earliest)
        .await
        .map_err(RelayFailure::federation)?;
    for event in admission.events() {
        let canonical = decode_canonical_signed_mutation(event.signed_request())
            .map_err(RelayFailure::denied)?;
        if canonical.kind()
            != crate::chat_protocol::transcript::SignedMutationKind::ParticipantAcceptance
        {
            continue;
        }
        let entry: Value =
            serde_json::from_slice(event.accepted_payload_bytes()).map_err(RelayFailure::denied)?;
        let wrapper = decode_bytes(
            entry
                .pointer("/recovery/reservation/keyPackage/bytes")
                .ok_or_else(|| RelayFailure::denied("acceptance has no package"))?,
        )
        .map_err(RelayFailure::Denied)?;
        let did = canonical.actor_did().as_str();
        let device_id = Uuid::from_bytes(*canonical.actor_device_id().as_bytes());
        let key_id = canonical.key_id().as_str();
        let key: Vec<u8> = sqlx::query_scalar("SELECT signing_public_key FROM chat.device_keys WHERE user_did=$1 AND device_id=$2 AND key_id=$3 AND revoked_at IS NULL")
            .bind(did).bind(device_id).bind(key_id).fetch_one(&mut *tx).await
            .map_err(|error| match error {
                // An acceptance by a device no member home vouched for.
                sqlx::Error::RowNotFound => RelayFailure::denied("acceptance device is not staged"),
                error => RelayFailure::storage(error),
            })?;
        stage_package(
            &mut tx,
            &GroupPackage {
                device: GroupDevice {
                    user_did: did.to_owned(),
                    device_id,
                    key_id: key_id.to_owned(),
                    auth_generation: canonical.auth_generation() as i64,
                    signing_public_key: key,
                },
                wrapper,
                created_at: event.received_at(),
            },
            event.received_at(),
        )
        .await
        .map_err(RelayFailure::federation)?;
    }
    let outcome = crate::chat_protocol::repository::remote_prefix::apply_remote_clean_prefix(
        &mut tx, admission,
    )
    .await
    .map_err(RelayFailure::bootstrap)?;
    if matches!(
        outcome,
        super::super::bootstrap::RemotePrefixApplyOutcome::Quarantined { .. }
    ) {
        return Err(RelayFailure::denied("group prefix was quarantined"));
    }
    tx.commit().await.map_err(RelayFailure::storage)
}

fn decode_bytes(value: &Value) -> Result<Vec<u8>, String> {
    let encoded = value
        .as_str()
        .or_else(|| value.get("$bytes").and_then(Value::as_str))
        .ok_or("invalid byte string")?;
    STANDARD
        .decode(encoded)
        .or_else(|_| URL_SAFE_NO_PAD.decode(encoded))
        .map_err(|e| e.to_string())
}

/// A failed S2S membership step, classified for the calling DS.
#[derive(Debug)]
pub(super) enum RelayFailure {
    /// The caller, signed request or peer answer lacks authority for this
    /// step; retrying cannot change that.
    Denied(String),
    /// The authoritative sequencer has no such conversation.
    NotFound(String),
    /// A declared clean-chat protocol error the client must see.
    Protocol(ChatProtocolErrorCode),
    /// A dependency could not answer now; the caller may retry.
    Unavailable(String),
    /// This DS's own store (or configuration) failed; the caller may retry.
    Storage(String),
}

impl RelayFailure {
    fn denied(error: impl std::fmt::Display) -> Self {
        Self::Denied(error.to_string())
    }

    fn not_found(error: impl std::fmt::Display) -> Self {
        Self::NotFound(error.to_string())
    }

    fn unavailable(error: impl std::fmt::Display) -> Self {
        Self::Unavailable(error.to_string())
    }

    fn storage(error: impl std::fmt::Display) -> Self {
        Self::Storage(error.to_string())
    }

    /// `Database` is matched before `is_retryable`, which also holds for it;
    /// any other failure of this DS (`status_code` 5xx: configuration,
    /// signer) is `Storage`; every remaining failure refuses the step.
    fn federation(error: FederationError) -> Self {
        match error {
            FederationError::Database(error) => Self::storage(error),
            error if error.is_retryable() => Self::unavailable(error),
            error if error.status_code().is_server_error() => Self::storage(error),
            error => Self::denied(error),
        }
    }

    fn outbound(error: OutboundError) -> Self {
        if error.is_retryable() {
            Self::unavailable(error)
        } else {
            Self::denied(error)
        }
    }

    fn bootstrap(error: super::super::bootstrap::RemotePrefixBootstrapError) -> Self {
        use super::super::bootstrap::RemotePrefixBootstrapError as E;
        match error {
            E::Database | E::ServiceAuth => Self::storage(error),
            _ if error.is_retryable() => Self::unavailable(error),
            _ => Self::denied(error),
        }
    }

    pub(super) fn into_response(self) -> Response {
        match self {
            Self::Denied(error) => s2s_err(StatusCode::FORBIDDEN, "NotAuthorized", error),
            Self::NotFound(error) => s2s_err(StatusCode::NOT_FOUND, "ConversationNotFound", error),
            Self::Protocol(code) => s2s_err(StatusCode::BAD_REQUEST, code.as_str(), code.as_str()),
            Self::Unavailable(error) => {
                s2s_err(StatusCode::SERVICE_UNAVAILABLE, "ServiceUnavailable", error)
            }
            Self::Storage(error) => s2s_err(
                StatusCode::INTERNAL_SERVER_ERROR,
                "InternalServerError",
                error,
            ),
        }
    }
}

pub(crate) async fn try_relay_home_group_operation(
    pool: &DbPool,
    actor: &str,
    device: Uuid,
    endpoint: &str,
    body: &[u8],
) -> Result<Option<Value>, GroupRelayError> {
    let internal = |error: String| GroupRelayError::Internal(error);
    let Ok(value) = serde_json::from_slice::<Value>(body) else {
        return Ok(None);
    };
    let signed = value.get("signedRequest").unwrap_or(&value);
    let conversation = signed
        .pointer("/body/prior/conversationId")
        .or_else(|| signed.pointer("/body/coordinates/conversationId"))
        .or_else(|| signed.get("conversationId"))
        .and_then(Value::as_str)
        .and_then(|id| Uuid::parse_str(id).ok());
    let Some(conversation_id) = conversation else {
        return Ok(None);
    };
    // A quarantined mirror relays nothing: the local path answers with the
    // endpoint's declared conflict until reconciliation clears the quarantine.
    let sequencer: Option<String> = sqlx::query_scalar(
        "SELECT sequencer_ds FROM chat.conversations WHERE conversation_id=$1 AND kind='group' AND is_remote \
           AND NOT EXISTS(SELECT 1 FROM federation_sync_state WHERE convo_id=$1::text AND status='quarantined')",
    ).bind(conversation_id).fetch_optional(pool).await.map_err(|e| internal(e.to_string()))?.flatten();
    let Some(sequencer) = sequencer else {
        return Ok(None);
    };
    let request = RelayGroupMutationRequest {
        conversation_id,
        endpoint: endpoint.to_owned(),
        actor_did: actor.to_owned(),
        actor_device_id: device,
        signed_request: signed.clone(),
        signed_request_bytes: None,
    };
    let payload = serde_json::to_value(request).map_err(|e| internal(e.to_string()))?;
    let (status, bytes) = call_home_response(
        pool,
        &sequencer,
        "blue.catbird.mlsDS.relayGroupMutation",
        &payload,
    )
    .await
    .map_err(GroupRelayError::from_local)?;
    if (200..300).contains(&status) {
        // An answered Welcome is no longer pending at the sequencer.
        if matches!(
            endpoint,
            "blue.catbird.chat.acknowledgeWelcome" | "blue.catbird.chat.rejectWelcome"
        ) {
            if let Some(welcome) = signed
                .pointer("/body/welcomeId")
                .and_then(Value::as_str)
                .and_then(|id| Uuid::parse_str(id).ok())
            {
                // Best-effort: the next `getPendingWelcomes` read forgets
                // every marker its sequencer no longer holds pending, and the
                // committed disposition stays this request's answer.
                if let Err(error) =
                    super::forget_pending_welcomes(pool, conversation_id, actor, device, &[welcome])
                        .await
                {
                    tracing::warn!(conversation_id = %crate::crypto::redact_for_log(&conversation_id.to_string()), %error, "answered Welcome marker kept");
                }
            }
        }
        return serde_json::from_slice(&bytes)
            .map(Some)
            .map_err(|e| GroupRelayError::Unavailable(e.to_string()));
    }
    let failure = GroupRelayError::from_response(status, &bytes);
    // A definitive rejection rolled back the sequencer; free the exported package.
    if matches!(failure, GroupRelayError::Rejected(_))
        && endpoint == "blue.catbird.chat.acceptConversation"
    {
        if let Some(recovery_request_id) = signed
            .pointer("/body/recoveryRequestId")
            .and_then(Value::as_str)
            .and_then(|id| Uuid::parse_str(id).ok())
        {
            let _ = sqlx::query(
                "DELETE FROM chat.group_key_package_exports \
                  WHERE conversation_id = $1 AND recovery_request_id = $2",
            )
            .bind(conversation_id)
            .bind(recovery_request_id)
            .execute(pool)
            .await;
        }
    }
    Err(failure)
}

/// Relay a signed Welcome disposition and seal the sequencer's answer as the
/// response bytes when the actor is a member only the home's remote-group index
/// knows: that Welcome has no local mailbox row, so the sequencer's disposition
/// is the whole answer. `None` leaves the disposition to the local facade.
pub(crate) async fn try_relay_index_only_welcome(
    pool: &DbPool,
    actor: &str,
    device: Uuid,
    endpoint: ChatEndpoint,
    body: &[u8],
) -> Result<Option<Vec<u8>>, crate::handlers::chat::ChatFailure> {
    use crate::chat_protocol::repository::entry_read::{
        remote_group_standing, RemoteGroupStanding,
    };
    use crate::handlers::chat::ChatFailure;

    let Some(output) = try_relay_home_group_operation(pool, actor, device, endpoint.nsid(), body)
        .await
        .map_err(|error| error.into_failure(endpoint))?
    else {
        return Ok(None);
    };
    let Some(conversation_id) = serde_json::from_slice::<Value>(body)
        .ok()
        .and_then(|value| {
            let signed = value.get("signedRequest").unwrap_or(&value);
            signed
                .pointer("/body/coordinates/conversationId")
                .and_then(Value::as_str)
                .and_then(|id| Uuid::parse_str(id).ok())
        })
    else {
        return Ok(None);
    };
    let mut conn = pool
        .acquire()
        .await
        .map_err(|_| ChatFailure::storage(endpoint))?;
    let standing = remote_group_standing(&mut conn, conversation_id, actor)
        .await
        .map_err(|_| ChatFailure::storage(endpoint))?;
    if standing != RemoteGroupStanding::IndexOnly {
        return Ok(None);
    }
    serde_json::to_vec(&output)
        .map(Some)
        .map_err(|_| ChatFailure::invariant(endpoint))
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct GroupStateRequest {
    conversation_id: Uuid,
    actor_did: String,
    actor_device_id: Uuid,
    #[serde(default)]
    deletions_after: Option<i64>,
}

/// Read a remote conversation's state from its sequencer for a local device: a
/// remote group's, or a C33 pair's whose sender this DS homes as the pair's
/// transport-only home, which holds no leaf authority for the peer's devices.
/// `None` when this DS holds neither for the conversation.
pub(crate) async fn try_relay_group_state(
    pool: &DbPool,
    actor_did: &str,
    actor_device_id: Uuid,
    conversation_id: Uuid,
) -> Result<Option<Vec<u8>>, GroupRelayError> {
    try_relay_group_state_page(pool, actor_did, actor_device_id, conversation_id, None).await
}

pub(crate) async fn try_relay_group_state_page(
    pool: &DbPool,
    actor_did: &str,
    actor_device_id: Uuid,
    conversation_id: Uuid,
    deletions_after: Option<i64>,
) -> Result<Option<Vec<u8>>, GroupRelayError> {
    let sequencer: Option<String> = sqlx::query_scalar(
        "SELECT sequencer_ds FROM chat.conversations \
          WHERE conversation_id=$1 AND kind='group' AND is_remote \
         UNION ALL \
         SELECT i.coordinator_did FROM chat.direct_request_transport_inbox i \
           JOIN chat.direct_request_outbound_routes o \
             ON o.request_id = i.request_id AND o.actor_did = i.sender_did \
          WHERE i.conversation_id=$1 AND i.sender_did=$2 \
         LIMIT 1",
    )
    .bind(conversation_id)
    .bind(actor_did)
    .fetch_optional(pool)
    .await
    .map_err(|e| GroupRelayError::Internal(e.to_string()))?
    .flatten();
    let Some(sequencer) = sequencer else {
        return Ok(None);
    };
    let mut payload = json!({
        "conversationId": conversation_id,
        "actorDid": actor_did,
        "actorDeviceId": actor_device_id,
    });
    if let Some(after) = deletions_after {
        payload["deletionsAfter"] = json!(after);
    }
    let (status, bytes) = call_home_response(pool, &sequencer, GROUP_STATE_NSID, &payload)
        .await
        .map_err(GroupRelayError::from_local)?;
    if (200..300).contains(&status) {
        return Ok(Some(bytes));
    }
    Err(GroupRelayError::from_response(status, &bytes))
}

/// The sequencer answers a home-relayed state read with its own read
/// authority; the home vouches only for its device.
async fn get_group_state(
    State(state): State<GroupRelayState>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let caller = match verify_s2s_caller(&state, &headers, GROUP_STATE_NSID, &body).await {
        Ok(caller) => caller,
        Err(response) => return response,
    };
    let request: GroupStateRequest = match serde_json::from_slice(&body) {
        Ok(request) => request,
        Err(e) => return s2s_err(StatusCode::BAD_REQUEST, "InvalidRequest", e.to_string()),
    };
    if request
        .deletions_after
        .is_some_and(|n| !(0..=9_007_199_254_740_991).contains(&n))
    {
        return s2s_err(
            StatusCode::BAD_REQUEST,
            "InvalidRequest",
            "invalid deletionsAfter",
        );
    }
    match resolver(&state.pool)
        .resolve_authoritative_ds(&request.actor_did)
        .await
    {
        Ok(home) if crate::identity::dids_equivalent(&home.did, &caller) => {}
        Ok(_) => {
            return s2s_err(
                StatusCode::FORBIDDEN,
                "NotAuthorized",
                "caller is not actor's home",
            )
        }
        Err(e) => return RelayFailure::federation(e).into_response(),
    }
    let staged: bool = match sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM chat.devices WHERE user_did=$1 AND device_id=$2)",
    )
    .bind(&request.actor_did)
    .bind(request.actor_device_id)
    .fetch_one(&state.pool)
    .await
    {
        Ok(staged) => staged,
        Err(e) => return RelayFailure::storage(e).into_response(),
    };
    if !staged {
        let routes = BTreeMap::from([(request.actor_did.clone(), Some(caller))]);
        if let Err(e) = stage_remote_group_participants(&state.pool, &routes).await {
            return RelayFailure::federation(e).into_response();
        }
    }
    let principal = crate::auth::VerifiedServicePrincipal::for_federated_s2s(
        &request.actor_did,
        "blue.catbird.chat.getConversationState",
    );
    crate::handlers::chat::execute_federated_conversation_state_read(
        &state.pool,
        principal,
        request.actor_device_id,
        request.conversation_id,
        request.deletions_after,
    )
    .await
    .unwrap_or_else(IntoResponse::into_response)
}

/// Read the pending Welcomes a remote group's sequencer holds for one local
/// device. `None` when this DS holds no remote group mirror for the
/// conversation.
pub(crate) async fn try_relay_group_pending_welcomes(
    pool: &DbPool,
    actor_did: &str,
    actor_device_id: Uuid,
    conversation_id: Uuid,
) -> Result<Option<Vec<Value>>, GroupRelayError> {
    let sequencer: Option<String> = sqlx::query_scalar(
        "SELECT sequencer_ds FROM chat.conversations WHERE conversation_id=$1 AND kind='group' AND is_remote",
    )
    .bind(conversation_id)
    .fetch_optional(pool)
    .await
    .map_err(|e| GroupRelayError::Internal(e.to_string()))?
    .flatten();
    let Some(sequencer) = sequencer else {
        return Ok(None);
    };
    let payload = json!({
        "conversationId": conversation_id,
        "actorDid": actor_did,
        "actorDeviceId": actor_device_id,
    });
    let (status, bytes) = call_home_response(pool, &sequencer, GROUP_WELCOMES_NSID, &payload)
        .await
        .map_err(GroupRelayError::from_local)?;
    if !(200..300).contains(&status) {
        return Err(GroupRelayError::from_response(status, &bytes));
    }
    // A malformed answer is as definitive as an unknown 4xx.
    let malformed = || {
        GroupRelayError::Rejected(
            crate::chat_protocol::error::ChatProtocolErrorCode::InvalidRequest,
        )
    };
    let mut body: Value = serde_json::from_slice(&bytes).map_err(|_| malformed())?;
    match body.get_mut("items").map(Value::take) {
        Some(Value::Array(items)) => Ok(Some(items)),
        _ => Err(malformed()),
    }
}

/// The sequencer answers a home-relayed pending-Welcome read for a device of
/// one of its group's remote participants, from its own Welcome deliveries.
async fn get_group_pending_welcomes(
    State(state): State<GroupRelayState>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let caller = match verify_s2s_caller(&state, &headers, GROUP_WELCOMES_NSID, &body).await {
        Ok(caller) => caller,
        Err(response) => return response,
    };
    let request: GroupStateRequest = match serde_json::from_slice(&body) {
        Ok(request) => request,
        Err(e) => return s2s_err(StatusCode::BAD_REQUEST, "InvalidRequest", e.to_string()),
    };
    match resolver(&state.pool)
        .resolve_authoritative_ds(&request.actor_did)
        .await
    {
        Ok(home) if crate::identity::dids_equivalent(&home.did, &caller) => {}
        Ok(_) => {
            return s2s_err(
                StatusCode::FORBIDDEN,
                "NotAuthorized",
                "caller is not actor's home",
            )
        }
        Err(e) => return RelayFailure::federation(e).into_response(),
    }
    let read = async {
        let mut tx = state.pool.begin().await?;
        let participant: bool = sqlx::query_scalar(
            "SELECT EXISTS(SELECT 1 FROM chat.conversations c JOIN chat.participants p USING (conversation_id) \
              WHERE c.conversation_id = $1 AND c.kind = 'group' AND NOT c.is_remote \
                AND p.user_did = $2 AND p.ds_did = $3 AND p.current_membership \
                AND p.status IN ('pending', 'active'))",
        )
        .bind(request.conversation_id)
        .bind(&request.actor_did)
        .bind(&caller)
        .fetch_one(&mut *tx)
        .await?;
        let views = if participant {
            crate::chat_protocol::repository::inventory::pending_welcome_views_for_conversation(
                &mut tx,
                request.conversation_id,
                &request.actor_did,
                request.actor_device_id,
            )
            .await
            .map_err(|error| sqlx::Error::Protocol(format!("{error:?}")))?
        } else {
            Vec::new()
        };
        tx.rollback().await?;
        Ok::<_, sqlx::Error>((participant, views))
    }
    .await;
    match read {
        Ok((true, views)) => Json(json!({ "items": views })).into_response(),
        Ok((false, _)) => s2s_err(
            StatusCode::FORBIDDEN,
            "NotAuthorized",
            "actor is not a current participant homed at the caller",
        ),
        Err(error) => RelayFailure::storage(error).into_response(),
    }
}

pub(super) async fn relay_membership(
    state: &GroupRelayState,
    caller: &str,
    request: &RelayGroupMutationRequest,
) -> Response {
    relay_membership_inner(state, caller, request)
        .await
        .unwrap_or_else(RelayFailure::into_response)
}

async fn relay_membership_inner(
    state: &GroupRelayState,
    caller: &str,
    request: &RelayGroupMutationRequest,
) -> Result<Response, RelayFailure> {
    // This DS's authorization store failing, or a corrupt record of its own,
    // is internal; every other admission failure refuses the relayed step.
    let admission_failure = |error: auth::AuthRepositoryError| match error {
        auth::AuthRepositoryError::Database(_)
        | auth::AuthRepositoryError::CorruptIdempotencyRecord
        | auth::AuthRepositoryError::InvalidCompletion => RelayFailure::storage(error),
        error => RelayFailure::denied(error),
    };
    let resolver = resolver(&state.pool);
    let home = resolver
        .resolve_authoritative_ds(&request.actor_did)
        .await
        .map_err(RelayFailure::federation)?;
    if !crate::identity::dids_equivalent(&home.did, caller) {
        return Err(RelayFailure::denied("caller is not actor's home"));
    }
    let allowed: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM chat.conversations c JOIN chat.participants p USING(conversation_id) \
          WHERE c.conversation_id=$1 AND c.kind='group' AND NOT c.is_remote \
            AND p.current_membership AND p.user_did=$2 AND p.ds_did=$3 AND p.status IN ('pending','active'))",
    ).bind(request.conversation_id).bind(&request.actor_did).bind(caller).fetch_one(&state.pool).await.map_err(RelayFailure::storage)?;
    if !allowed {
        return Err(RelayFailure::denied(
            "caller has no participant authority for this group",
        ));
    }
    let principal = crate::auth::VerifiedServicePrincipal::for_federated_s2s(
        &request.actor_did,
        &request.endpoint,
    );
    let bytes = serde_json::to_vec(&request.signed_request).map_err(RelayFailure::denied)?;
    let canonical = decode_canonical_signed_mutation(&bytes).map_err(RelayFailure::denied)?;
    if canonical.actor_did().as_str() != request.actor_did
        || canonical.actor_device_id().as_bytes() != request.actor_device_id.as_bytes()
    {
        return Err(RelayFailure::denied("relayed group actor binding mismatch"));
    }
    let actor_key_id = canonical.key_id().as_str().to_owned();
    let actor_auth_generation = canonical.auth_generation();
    let pre_replay = dpop::standard_service_auth_evidence(
        principal,
        &request.actor_device_id.to_string(),
        CanonicalHttpMethod::parse("POST").map_err(RelayFailure::storage)?,
        TrustedRequestInstant::capture().map_err(RelayFailure::storage)?,
        None,
    )
    .map_err(RelayFailure::denied)?;
    let admission = auth::authorize_signed_operation_only(&state.pool, pre_replay, canonical)
        .await
        .map_err(admission_failure)?;
    let completed = auth::preflight_completed_response(&state.pool, &admission)
        .await
        .map_err(admission_failure)?
        .is_some();
    let accept = request.endpoint == "blue.catbird.chat.acceptConversation";
    if accept && !completed {
        let recovery = request
            .signed_request
            .pointer("/body/recoveryRequestId")
            .and_then(Value::as_str)
            .ok_or(RelayFailure::Protocol(
                ChatProtocolErrorCode::InvalidRequest,
            ))?;
        let payload = json!({ "conversationId": request.conversation_id, "userDid": request.actor_did,
            "deviceId": request.actor_device_id, "keyId": actor_key_id, "recoveryRequestId": recovery,
            "signedRequest": request.signed_request });
        let (status, response) = call_home_response(&state.pool, caller, PACKAGE_NSID, &payload)
            .await
            .map_err(RelayFailure::federation)?;
        if !(200..300).contains(&status) {
            return Err(match GroupRelayError::from_response(status, &response) {
                GroupRelayError::Rejected(code) => RelayFailure::Protocol(code),
                GroupRelayError::Unavailable(reason) => {
                    RelayFailure::Unavailable(format!("{PACKAGE_NSID}: {reason}"))
                }
                GroupRelayError::Internal(reason) => RelayFailure::Storage(reason),
            });
        }
        // The home answered success with no usable package: as definitive as
        // its refusal.
        let exported: Value = serde_json::from_slice(&response).map_err(RelayFailure::denied)?;
        let package: GroupPackage =
            serde_json::from_value(exported["package"].clone()).map_err(RelayFailure::denied)?;
        let authorized = resolver
            .resolve_authorized_device_keys(&request.actor_did)
            .await
            .map_err(RelayFailure::federation)?;
        if package.device.user_did != request.actor_did
            || package.device.device_id != request.actor_device_id
            || package.device.key_id != actor_key_id
            || package.device.auth_generation as u64 != actor_auth_generation
            || !authorized
                .iter()
                .any(|key| key == &package.device.signing_public_key)
        {
            return Err(RelayFailure::denied(
                "exported package owner is not authoritative",
            ));
        }
        let mut tx = state.pool.begin().await.map_err(RelayFailure::storage)?;
        stage_devices(
            &mut tx,
            std::slice::from_ref(&package.device),
            crate::sim_hooks::current_utc(),
        )
        .await
        .map_err(RelayFailure::federation)?;
        stage_package(&mut tx, &package, crate::sim_hooks::current_utc())
            .await
            .map_err(RelayFailure::federation)?;
        tx.commit().await.map_err(RelayFailure::storage)?;
    }
    if accept {
        let relationship = state
            .relationship_authority()
            .map_err(RelayFailure::Unavailable)?;
        Ok(crate::handlers::chat::execute_federated_group_acceptance(
            &state.pool,
            admission,
            relationship.as_ref(),
            state.i13_receipt_signer(),
        )
        .await
        .unwrap_or_else(IntoResponse::into_response))
    } else {
        let endpoint = match request.endpoint.as_str() {
            "blue.catbird.chat.acknowledgeWelcome" => ChatEndpoint::AcknowledgeWelcome,
            "blue.catbird.chat.rejectWelcome" => ChatEndpoint::RejectWelcome,
            _ => {
                return Err(RelayFailure::Protocol(
                    ChatProtocolErrorCode::InvalidRequest,
                ))
            }
        };
        let body = serde_json::to_vec(&json!({ "signedRequest": request.signed_request }))
            .map_err(RelayFailure::denied)?;
        Ok(crate::handlers::chat::execute_federated_group_welcome(
            &state.pool,
            admission,
            endpoint,
            &body,
        )
        .await
        .unwrap_or_else(IntoResponse::into_response))
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct LabyrinthDirectoryRequest {
    endpoint: String,
    query: String,
    actor_did: String,
    actor_device_id: Uuid,
    sequencer_term: Option<i64>,
    read_header: String,
    read_signature: String,
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct LabyrinthMemberDevicesResponse {
    endpoint: String,
    query: String,
    sequencer_did: String,
    sequencer_term: i64,
    actor_did: String,
    actor_device_id: Uuid,
    conversation_id: Uuid,
    subject_did: String,
    page: LabyrinthMemberDevicesPage,
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct LabyrinthMemberDevicesPage {
    items: Vec<LabyrinthMemberDevice>,
    #[serde(skip_serializing_if = "Option::is_none")]
    cursor: Option<String>,
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct LabyrinthMemberDevice {
    key_id: String,
    signing_public_key: crate::labyrinth::wire::bytes::Bytes,
    joined_seq: i64,
    #[serde(skip_serializing_if = "Option::is_none")]
    removed_seq: Option<i64>,
}

async fn member_devices_sequencer(
    pool: &DbPool,
    conversation_id: Uuid,
    actor_did: &str,
) -> crate::labyrinth::error::LabyrinthResult<Option<(String, i64)>> {
    let route = sqlx::query_as(
        "SELECT sequencer, term FROM (\
             SELECT sequencer_ds AS sequencer, sequencer_term AS term, 0 AS priority \
               FROM chat.conversations \
              WHERE conversation_id=$1 AND is_remote \
             UNION ALL \
             SELECT i.coordinator_did, 0::bigint, 1 \
               FROM chat.direct_request_transport_inbox i \
               JOIN chat.direct_request_outbound_routes o \
                 ON o.request_id=i.request_id AND o.actor_did=i.sender_did \
              WHERE i.conversation_id=$1 AND i.sender_did=$2 \
             UNION ALL \
             SELECT i.coordinator_did, 0::bigint, 2 \
               FROM chat.direct_request_transport_inbox i \
              WHERE i.conversation_id=$1 AND i.recipient_did=$2 AND i.status='accepted'\
         ) routes ORDER BY priority LIMIT 1",
    )
    .bind(conversation_id)
    .bind(actor_did)
    .fetch_optional(pool)
    .await?;
    Ok(route)
}

fn member_devices_relay_denied(message: &'static str) -> crate::labyrinth::error::LabyrinthError {
    crate::labyrinth::error::LabyrinthError::forbidden("NotAuthorized", message)
}

fn decode_member_devices_relay(
    bytes: &[u8],
    sequencer: &str,
    sequencer_term: i64,
    admission: &crate::labyrinth::auth::Admission,
    conversation_id: Uuid,
    subject_did: &str,
    query: &str,
) -> crate::labyrinth::error::LabyrinthResult<Vec<u8>> {
    let response: LabyrinthMemberDevicesResponse = serde_json::from_slice(bytes)
        .map_err(|_| member_devices_relay_denied("invalid member device relay response"))?;
    if response.endpoint != LABYRINTH_MEMBER_DEVICES_ENDPOINT
        || response.query != query
        || response.sequencer_did != sequencer
        || response.sequencer_term != sequencer_term
        || response.actor_did != admission.did
        || response.actor_device_id != admission.device_id
        || response.conversation_id != conversation_id
        || response.subject_did != subject_did
    {
        return Err(member_devices_relay_denied(
            "member device relay response binding mismatch",
        ));
    }
    if response.page.items.len() > crate::labyrinth::repo::MAX_PAGE as usize
        || response
            .page
            .cursor
            .as_ref()
            .is_some_and(|cursor| cursor.len() > 64)
    {
        return Err(member_devices_relay_denied(
            "invalid member device relay page",
        ));
    }
    for item in &response.page.items {
        let safe_seq = |seq: i64| (0..=9_007_199_254_740_991).contains(&seq);
        let expected_key_id =
            crate::chat_protocol::validation::ed25519_key_id(&item.signing_public_key.0)
                .map(|key| key.as_str().to_owned())
                .map_err(|_| member_devices_relay_denied("invalid member device relay page"))?;
        if item.key_id.is_empty()
            || item.key_id.len() > 128
            || item.key_id != expected_key_id
            || !safe_seq(item.joined_seq)
            || item
                .removed_seq
                .is_some_and(|seq| !safe_seq(seq) || seq < item.joined_seq)
        {
            return Err(member_devices_relay_denied(
                "invalid member device relay page",
            ));
        }
    }
    serde_json::to_vec(&response.page)
        .map_err(|_| crate::labyrinth::error::LabyrinthError::internal())
}

pub(crate) async fn try_relay_labyrinth_member_devices(
    pool: &DbPool,
    resolver: Option<&super::super::resolver::DsResolver>,
    admission: &crate::labyrinth::auth::Admission,
    conversation_id: Uuid,
    subject_did: &str,
    query: Option<&str>,
) -> crate::labyrinth::error::LabyrinthResult<Option<Vec<u8>>> {
    let Some((sequencer, sequencer_term)) =
        member_devices_sequencer(pool, conversation_id, &admission.did).await?
    else {
        return Ok(None);
    };
    let resolver =
        resolver.ok_or_else(crate::labyrinth::error::LabyrinthError::relay_unavailable)?;
    if crate::identity::dids_equivalent(&sequencer, resolver.self_did()) {
        return Ok(None);
    }
    super::super::peer_policy::ensure_federation_open().map_err(labyrinth_relay_failure)?;
    super::super::peer_policy::enforce_outbound_peer_policy(pool, &sequencer)
        .await
        .map_err(labyrinth_relay_failure)?;
    crate::labyrinth::auth::begin_read(pool, admission.clone())
        .await?
        .finish_read()
        .await?;
    let proof = admission
        .read
        .as_ref()
        .ok_or_else(crate::labyrinth::error::LabyrinthError::internal)?;
    let query = crate::labyrinth::read_auth::canonical_query(query);
    let payload = json!({
        "endpoint": LABYRINTH_MEMBER_DEVICES_ENDPOINT,
        "query": query,
        "sequencerTerm": sequencer_term,
        "actorDid": admission.did,
        "actorDeviceId": admission.device_id,
        "readHeader": proof.header,
        "readSignature": proof.signature,
    });
    let (status, bytes) = call_home_response_via(
        pool,
        Some(resolver),
        &sequencer,
        LABYRINTH_DIRECTORY_NSID,
        &payload,
    )
    .await
    .map_err(labyrinth_relay_failure)?;
    if !(200..300).contains(&status) {
        return Err(labyrinth_peer_failure(status, &bytes));
    }
    let page = decode_member_devices_relay(
        &bytes,
        &sequencer,
        sequencer_term,
        admission,
        conversation_id,
        subject_did,
        &query,
    )?;
    match member_devices_sequencer(pool, conversation_id, &admission.did).await? {
        Some((current, term)) if current == sequencer && term == sequencer_term => Ok(Some(page)),
        _ => Err(member_devices_relay_denied(
            "member device sequencer route changed during the read",
        )),
    }
}

pub(crate) async fn try_relay_labyrinth_directory(
    pool: &DbPool,
    resolver: Option<&super::super::resolver::DsResolver>,
    admission: &crate::labyrinth::auth::Admission,
    target_did: &str,
    endpoint: &str,
    query: Option<&str>,
) -> crate::labyrinth::error::LabyrinthResult<Option<Vec<u8>>> {
    let Some(resolver) = resolver else {
        return Ok(None);
    };
    let target = resolver
        .resolve_authoritative_ds(target_did)
        .await
        .map_err(labyrinth_relay_failure)?;
    if crate::identity::dids_equivalent(&target.did, resolver.self_did()) {
        return Ok(None);
    }
    super::super::peer_policy::enforce_outbound_peer_policy(pool, &target.did)
        .await
        .map_err(labyrinth_relay_failure)?;
    // Recheck the home device, then release its connection and lock before S2S.
    crate::labyrinth::auth::begin_read(pool, admission.clone())
        .await?
        .finish_read()
        .await?;
    let proof = admission
        .read
        .as_ref()
        .ok_or_else(crate::labyrinth::error::LabyrinthError::internal)?;
    let payload = json!({
        "endpoint": endpoint,
        "query": crate::labyrinth::read_auth::canonical_query(query),
        "actorDid": admission.did,
        "actorDeviceId": admission.device_id,
        "readHeader": proof.header,
        "readSignature": proof.signature,
    });
    let (status, bytes) = call_home_response(pool, &target.did, LABYRINTH_DIRECTORY_NSID, &payload)
        .await
        .map_err(labyrinth_relay_failure)?;
    if (200..300).contains(&status) {
        return Ok(Some(bytes));
    }
    Err(labyrinth_peer_failure(status, &bytes))
}

/// A directory relay that failed on this side: this store or configuration
/// failing is internal; a gate, home or resolver that could not answer now is
/// `RelayUnavailable` with a retry; a target home this DS permanently cannot
/// route to (resolution or peer-policy refusal) is `403 NotAuthorized`.
fn labyrinth_relay_failure(error: FederationError) -> crate::labyrinth::error::LabyrinthError {
    use crate::labyrinth::error::LabyrinthError;
    tracing::warn!(%error, "Labyrinth directory relay failed");
    match error {
        FederationError::Database(_) => LabyrinthError::internal(),
        error if error.is_retryable() => LabyrinthError::relay_unavailable(),
        error if error.status_code().is_server_error() => LabyrinthError::internal(),
        error => LabyrinthError::forbidden("NotAuthorized", error.to_string()),
    }
}

/// The target home's non-2xx answer. A 5xx or 429 decided nothing:
/// `RelayUnavailable` with a retry. Any other answer is the home's refusal:
/// its declared name and status, `400 InvalidRequest` for a name this relay
/// does not forward.
fn labyrinth_peer_failure(status: u16, body: &[u8]) -> crate::labyrinth::error::LabyrinthError {
    use crate::labyrinth::error::LabyrinthError;
    if status >= 500 || status == 429 {
        return LabyrinthError::relay_unavailable();
    }
    let error: Value = serde_json::from_slice(body).unwrap_or_default();
    let message = error
        .get("message")
        .and_then(Value::as_str)
        .unwrap_or("remote directory rejected the read");
    let name = match error.get("error").and_then(Value::as_str) {
        Some("EpochNotFound") => "EpochNotFound",
        Some("ConversationNotFound") => "ConversationNotFound",
        Some("InvalidSignature") => "InvalidSignature",
        Some("NotAuthorized") => "NotAuthorized",
        Some("DeviceRevoked") => "DeviceRevoked",
        _ => return LabyrinthError::invalid(message),
    };
    LabyrinthError::new(
        StatusCode::from_u16(status).unwrap_or(StatusCode::BAD_REQUEST),
        name,
        message,
    )
}

async fn get_labyrinth_directory(
    State(state): State<GroupRelayState>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let caller = match verify_s2s_caller(&state, &headers, LABYRINTH_DIRECTORY_NSID, &body).await {
        Ok(caller) => caller,
        Err(response) => return response,
    };
    let request: LabyrinthDirectoryRequest = match serde_json::from_slice(&body) {
        Ok(request) => request,
        Err(e) => return s2s_err(StatusCode::BAD_REQUEST, "InvalidRequest", e.to_string()),
    };
    if !matches!(
        request.endpoint.as_str(),
        "blue.catbird.labyrinth.getEpochHead"
            | "blue.catbird.labyrinth.getChatDeviceKeys"
            | LABYRINTH_MEMBER_DEVICES_ENDPOINT
    ) {
        return s2s_err(
            StatusCode::BAD_REQUEST,
            "InvalidRequest",
            "unsupported directory endpoint",
        );
    }
    let result: Result<Option<(Uuid, String, i64)>, RelayFailure> = async {
        let resolver = resolver(&state.pool);
        if request.endpoint == LABYRINTH_MEMBER_DEVICES_ENDPOINT {
            if request.query != crate::labyrinth::read_auth::canonical_query(Some(&request.query)) {
                return Err(RelayFailure::denied(
                    "member device directory query is not canonical",
                ));
            }
            let mut conversation = None;
            let mut subject = None;
            for (key, value) in url::form_urlencoded::parse(request.query.as_bytes()) {
                match key.as_ref() {
                    "threadId" if conversation.is_none() => {
                        conversation = Some(
                            crate::labyrinth::repo::parse_thread_id(&value)
                                .map_err(RelayFailure::denied)?,
                        );
                    }
                    "did" if subject.is_none() => {
                        crate::labyrinth::wire::bytes::check_did("did", &value)
                            .map_err(RelayFailure::denied)?;
                        subject = Some(value.into_owned());
                    }
                    "threadId" | "did" => {
                        return Err(RelayFailure::denied(
                            "member device directory selector is duplicated",
                        ))
                    }
                    _ => {}
                }
            }
            let conversation = conversation.ok_or_else(|| {
                RelayFailure::denied("member device directory query has no conversation")
            })?;
            let subject = subject.ok_or_else(|| {
                RelayFailure::denied("member device directory query has no target DID")
            })?;
            let route: Option<(bool, Option<String>, i64)> = sqlx::query_as(
                "SELECT is_remote, sequencer_ds, sequencer_term FROM chat.conversations \
                  WHERE conversation_id=$1",
            )
            .bind(conversation)
            .fetch_optional(&state.pool)
            .await
            .map_err(RelayFailure::storage)?;
            let sequencer_term = match route {
                None => {
                    return Err(RelayFailure::not_found(
                        "conversation is not present at this sequencer",
                    ))
                }
                Some((false, None, term)) if request.sequencer_term == Some(term) => term,
                Some((false, None, _)) => {
                    return Err(RelayFailure::denied(
                        "member device directory sequencer term is stale",
                    ))
                }
                Some(_) => {
                    return Err(RelayFailure::denied(
                        "conversation is not authoritative at this sequencer",
                    ))
                }
            };
            let participant_route_matches: bool = sqlx::query_scalar(
                "SELECT EXISTS(SELECT 1 FROM chat.participants \
                  WHERE conversation_id=$1 AND user_did=$2 AND ds_did=$3 \
                    AND status IN ('active','left','removed'))",
            )
            .bind(conversation)
            .bind(&request.actor_did)
            .bind(&caller)
            .fetch_one(&state.pool)
            .await
            .map_err(RelayFailure::storage)?;
            if !participant_route_matches {
                let historical_member: bool = sqlx::query_scalar(
                    "SELECT EXISTS(SELECT 1 FROM chat.member_devices \
                      WHERE conversation_id=$1 AND user_did=$2)",
                )
                .bind(conversation)
                .bind(&request.actor_did)
                .fetch_one(&state.pool)
                .await
                .map_err(RelayFailure::storage)?;
                let actor_home = resolver
                    .resolve_authoritative_ds(&request.actor_did)
                    .await
                    .map_err(RelayFailure::federation)?;
                if !historical_member || !crate::identity::dids_equivalent(&actor_home.did, &caller)
                {
                    return Err(RelayFailure::denied(
                        "caller has no participant authority at this conversation sequencer",
                    ));
                }
            }
            let staged: bool = sqlx::query_scalar(
                "SELECT EXISTS(SELECT 1 FROM chat.devices WHERE user_did=$1 AND device_id=$2)",
            )
            .bind(&request.actor_did)
            .bind(request.actor_device_id)
            .fetch_one(&state.pool)
            .await
            .map_err(RelayFailure::storage)?;
            if !staged {
                let routes = BTreeMap::from([(request.actor_did.clone(), Some(caller.clone()))]);
                stage_remote_group_participants(&state.pool, &routes)
                    .await
                    .map_err(RelayFailure::federation)?;
            }
            return Ok(Some((conversation, subject, sequencer_term)));
        }

        let actor_home = resolver
            .resolve_authoritative_ds(&request.actor_did)
            .await
            .map_err(RelayFailure::federation)?;
        if !crate::identity::dids_equivalent(&actor_home.did, &caller) {
            return Err(RelayFailure::denied(
                "directory caller is not the actor's home",
            ));
        }
        let target = url::form_urlencoded::parse(request.query.as_bytes())
            .find_map(|(key, value)| (key == "did").then(|| value.into_owned()))
            .ok_or_else(|| RelayFailure::denied("directory query has no target DID"))?;
        let target_home = resolver
            .resolve_authoritative_ds(&target)
            .await
            .map_err(RelayFailure::federation)?;
        if !crate::identity::dids_equivalent(&target_home.did, &state.self_did) {
            return Err(RelayFailure::denied(
                "directory query is not at its authoritative home",
            ));
        }
        let routes = BTreeMap::from([(request.actor_did.clone(), Some(caller))]);
        stage_remote_group_participants(&state.pool, &routes)
            .await
            .map_err(RelayFailure::federation)?;
        Ok(None)
    }
    .await;
    let member_binding = match result {
        Ok(binding) => binding,
        Err(failure) => return failure.into_response(),
    };
    match crate::handlers::labyrinth::read_federated_directory(
        &state.pool,
        &request.endpoint,
        &request.query,
        &request.actor_did,
        request.actor_device_id,
        crate::labyrinth::read_auth::ReadProof {
            header: request.read_header,
            signature: request.read_signature,
        },
    )
    .await
    {
        Ok(bytes) => {
            let Some((conversation_id, subject_did, sequencer_term)) = member_binding else {
                return (
                    [(axum::http::header::CONTENT_TYPE, "application/json")],
                    bytes,
                )
                    .into_response();
            };
            let current_term: Option<i64> = match sqlx::query_scalar(
                "SELECT sequencer_term FROM chat.conversations \
                  WHERE conversation_id=$1 AND NOT is_remote AND sequencer_ds IS NULL",
            )
            .bind(conversation_id)
            .fetch_optional(&state.pool)
            .await
            {
                Ok(term) => term,
                Err(error) => return RelayFailure::storage(error).into_response(),
            };
            if current_term != Some(sequencer_term) {
                return RelayFailure::denied(
                    "member device sequencer route changed during the read",
                )
                .into_response();
            }
            let page: LabyrinthMemberDevicesPage = match serde_json::from_slice(&bytes) {
                Ok(page) => page,
                Err(error) => {
                    tracing::error!(?error, "sequencer produced an invalid member device page");
                    return RelayFailure::storage(error).into_response();
                }
            };
            Json(LabyrinthMemberDevicesResponse {
                endpoint: request.endpoint,
                query: request.query,
                sequencer_did: state.self_did,
                sequencer_term,
                actor_did: request.actor_did,
                actor_device_id: request.actor_device_id,
                conversation_id,
                subject_did,
                page,
            })
            .into_response()
        }
        Err(error) => error.into_response(),
    }
}

#[cfg(test)]
mod labyrinth_relay_tests {
    use super::*;
    use crate::federation::errors::ResolutionFailureKind;

    /// The status, error name and `Retry-After` a Labyrinth client receives.
    fn wire(error: crate::labyrinth::error::LabyrinthError) -> (u16, &'static str, Option<String>) {
        let name = error.name();
        let response = error.into_response();
        let retry_after = response
            .headers()
            .get(axum::http::header::RETRY_AFTER)
            .and_then(|value| value.to_str().ok())
            .map(str::to_owned);
        (response.status().as_u16(), name, retry_after)
    }

    /// A directory read relayed to the target's home: what decided nothing is
    /// `503 RelayUnavailable` with `Retry-After: 5`, a refusal stays a 4xx, and
    /// this store failing is a 500.
    #[test]
    fn a_relayed_directory_read_is_retryable_only_while_the_home_cannot_answer() {
        let retry = (503, "RelayUnavailable", Some("5".to_owned()));
        let resolution = |kind| FederationError::ResolutionFailed {
            did: "did:web:home.example.com".into(),
            kind,
        };
        for error in [
            FederationError::DsUnreachable {
                endpoint: "home.example.com".into(),
                reason: "timed out".into(),
            },
            FederationError::FederationDisabled {
                reason: "gate closed".into(),
            },
            resolution(ResolutionFailureKind::DnsTimeout("home.example.com".into())),
        ] {
            assert_eq!(wire(labyrinth_relay_failure(error)), retry);
        }
        for status in [500, 502, 503, 429] {
            let body = br#"{"error":"NotAuthorized","message":"busy"}"#;
            assert_eq!(
                wire(labyrinth_peer_failure(status, body)),
                retry,
                "{status}"
            );
        }

        for error in [
            resolution(ResolutionFailureKind::DnsNxdomain(
                "home.example.com".into(),
            )),
            FederationError::AuthFailed {
                reason: "Peer DS is blocklisted".into(),
            },
        ] {
            assert_eq!(
                wire(labyrinth_relay_failure(error)),
                (403, "NotAuthorized", None)
            );
        }
        assert_eq!(
            wire(labyrinth_peer_failure(404, br#"{"error":"EpochNotFound"}"#)),
            (404, "EpochNotFound", None)
        );
        assert_eq!(
            wire(labyrinth_peer_failure(
                404,
                br#"{"error":"ConversationNotFound"}"#
            )),
            (404, "ConversationNotFound", None)
        );
        assert_eq!(
            wire(labyrinth_peer_failure(403, br#"{"error":"NotAuthorized"}"#)),
            (403, "NotAuthorized", None)
        );
        assert_eq!(
            wire(labyrinth_peer_failure(418, b"not json")),
            (400, "InvalidRequest", None)
        );
        assert_eq!(
            wire(labyrinth_relay_failure(FederationError::Database(
                sqlx::Error::PoolClosed
            ))),
            (500, "InternalServerError", None)
        );
    }
}

// `crate::common::http_acceptance` (its protocol-instance fence) is `test-support` only.
#[cfg(all(test, feature = "test-support"))]
mod reenrollment_tests {
    use super::*;
    use crate::chat_protocol::{
        repository::auth::{recheck_existing_business_authority_for_test, AuthRepositoryError},
        test_support::{seed_clean_slate_application_fixture, sign_mutation_json_for_test},
        transcript::decode_and_verify_control_entry,
        validation::ed25519_key_id,
    };
    use ed25519_dalek::SigningKey;

    async fn admit(
        pool: &DbPool,
        device: &GroupDevice,
        key: &SigningKey,
        generation: i64,
    ) -> Result<(), AuthRepositoryError> {
        // Admission alone: a revocation of an unknown device never reaches
        // business preparation here.
        let body = json!({
            "$type": "blue.catbird.chat.defs#deviceRevocationBody",
            "signatureDomain": "CATBIRD-CHAT-DEVICE-REVOKE\u{0000}",
            "actorDid": device.user_did, "actorDeviceId": device.device_id,
            "keyId": device.key_id, "authGeneration": generation,
            "targetDeviceId": Uuid::new_v4(), "targetAuthGeneration": 1,
            "idempotencyKey": Uuid::new_v4(),
            "signedAt": Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
        });
        let signed = sign_mutation_json_for_test(&body, key).unwrap();
        let pre_replay = dpop::standard_service_auth_evidence(
            crate::auth::VerifiedServicePrincipal::for_federated_s2s(
                &device.user_did,
                "blue.catbird.chat.revokeDevice",
            ),
            &device.device_id.to_string(),
            CanonicalHttpMethod::parse("POST").unwrap(),
            TrustedRequestInstant::capture().unwrap(),
            None,
        )
        .unwrap();
        auth::authorize_signed_operation_only(
            pool,
            pre_replay,
            decode_canonical_signed_mutation(&serde_json::to_vec(&signed).unwrap()).unwrap(),
        )
        .await
        .map(|_| ())
    }

    #[tokio::test]
    async fn remote_reenrollment_keeps_historical_proofs_and_rejects_stale_authority() {
        let db = crate::common::fresh_db::fresh_fully_migrated_db("chat_remote_reenroll_").await;
        let pool = db.connect(4).await;
        // Revocation application appends events under the server's protocol
        // instance, which startup seeds in production.
        crate::common::http_acceptance::ensure_fence(&pool).await;
        let fixture =
            seed_clean_slate_application_fixture(&pool, false, "did:web:remote.example.com", None)
                .await
                .unwrap();
        // Standard service auth has no JKT; the nullable lifecycle deliberately
        // permits this conversion without rewriting the initial key or proofs.
        sqlx::query("UPDATE chat.devices SET dpop_jkt=NULL WHERE user_did=$1 AND device_id=$2")
            .bind(&fixture.sender_did)
            .bind(fixture.sender_device_id)
            .execute(&pool)
            .await
            .unwrap();
        let old_key = SigningKey::from_bytes(&fixture.sender_ed25519_seed);
        let old = GroupDevice {
            user_did: fixture.sender_did.clone(),
            device_id: fixture.sender_device_id,
            key_id: fixture.sender_key_id.clone(),
            auth_generation: 1,
            signing_public_key: old_key.verifying_key().to_bytes().to_vec(),
        };
        let history_sql = "SELECT e.entry_id,e.accepted_payload_bytes,k.signing_public_key \
            FROM chat.entries e JOIN chat.device_keys k \
              ON k.user_did=e.actor_did AND k.device_id=e.actor_device_id AND k.key_id=e.actor_key_id \
            WHERE e.conversation_id=$1 AND e.actor_did=$2 AND e.actor_device_id=$3 ORDER BY e.seq";
        let history: Vec<(Uuid, Vec<u8>, Vec<u8>)> = sqlx::query_as(history_sql)
            .bind(fixture.conversation_id)
            .bind(&old.user_did)
            .bind(old.device_id)
            .fetch_all(&pool)
            .await
            .unwrap();
        assert!(!history.is_empty());
        for (_, bytes, key) in &history {
            decode_and_verify_control_entry(bytes, key).unwrap();
        }
        let original: (Vec<u8>, i64, DateTime<Utc>) = sqlx::query_as(
            "SELECT signing_public_key,enrollment_auth_generation,created_at FROM chat.device_keys WHERE key_id=$1",
        ).bind(&old.key_id).fetch_one(&pool).await.unwrap();
        let next_key = SigningKey::from_bytes(&[0x79; 32]);
        let next = GroupDevice {
            key_id: ed25519_key_id(next_key.verifying_key().as_bytes())
                .unwrap()
                .as_str()
                .to_owned(),
            signing_public_key: next_key.verifying_key().to_bytes().to_vec(),
            auth_generation: 2,
            ..old.clone()
        };
        let at = DateTime::from_timestamp_millis(Utc::now().timestamp_millis()).unwrap();
        let mut tx = pool.begin().await.unwrap();
        stage_devices(&mut tx, std::slice::from_ref(&next), at)
            .await
            .unwrap();
        tx.commit().await.unwrap();
        let unchanged: (Vec<u8>, i64, DateTime<Utc>) = sqlx::query_as(
            "SELECT signing_public_key,enrollment_auth_generation,created_at FROM chat.device_keys WHERE key_id=$1",
        ).bind(&old.key_id).fetch_one(&pool).await.unwrap();
        assert_eq!(original, unchanged);
        let retained: Vec<(Uuid, Vec<u8>, Vec<u8>)> = sqlx::query_as(history_sql)
            .bind(fixture.conversation_id)
            .bind(&old.user_did)
            .bind(old.device_id)
            .fetch_all(&pool)
            .await
            .unwrap();
        assert_eq!(history, retained);
        for (_, bytes, key) in &retained {
            decode_and_verify_control_entry(bytes, key).unwrap();
        }
        admit(&pool, &next, &next_key, 2).await.unwrap();
        assert!(matches!(
            admit(&pool, &next, &next_key, 1).await,
            Err(AuthRepositoryError::AuthenticationGenerationMismatch)
        ));
        assert!(admit(&pool, &old, &old_key, 1).await.is_err());
        assert!(admit(&pool, &old, &old_key, 2).await.is_err());
        for rejected in [
            old.clone(),
            GroupDevice {
                auth_generation: 3,
                ..old.clone()
            },
        ] {
            let mut tx = pool.begin().await.unwrap();
            assert!(stage_devices(&mut tx, &[rejected], at).await.is_err());
            // Rejection precedes mutable writes, even if a caller commits.
            tx.commit().await.unwrap();
        }
        let mut tx = pool.begin().await.unwrap();
        let guard = recheck_existing_business_authority_for_test(
            &mut tx,
            &next.user_did,
            next.device_id,
            at,
        )
        .await
        .unwrap();
        assert_eq!(guard.stored_key_id(), Some(next.key_id.as_str()));
        assert_eq!(guard.stored_auth_generation(), Some(2));
        tx.rollback().await.unwrap();
        for sql in [
            "UPDATE chat.device_keys SET enrollment_auth_generation=2 WHERE key_id=$1",
            "DELETE FROM chat.device_keys WHERE key_id=$1",
        ] {
            let mut tx = pool.begin().await.unwrap();
            let error = sqlx::query(sql)
                .bind(&old.key_id)
                .execute(&mut *tx)
                .await
                .unwrap_err();
            assert_eq!(
                error.as_database_error().unwrap().code().as_deref(),
                Some("23514")
            );
            tx.rollback().await.unwrap();
        }
        // A remote device publishes KeyPackages only at its home: the fixture's
        // local generation-1 recovery package cannot stay live here once the
        // device's authority moved to generation 2 (revocation's G6 fanout
        // requires every live package at the revoked generation).
        sqlx::query(
            "UPDATE chat.key_packages SET status='expired',terminal_at=not_after \
              WHERE owner_did=$1 AND owner_device_id=$2 AND owner_auth_generation<2 \
                AND status='available'",
        )
        .bind(&next.user_did)
        .bind(next.device_id)
        .execute(&pool)
        .await
        .unwrap();
        // Execute a real self-revocation through admission, G6 preparation,
        // savepoint application, receipt completion and the deferred DB guards.
        let revocation_id = Uuid::new_v4();
        let revoke = sign_mutation_json_for_test(
            &json!({
                "$type": "blue.catbird.chat.defs#deviceRevocationBody",
                "signatureDomain": "CATBIRD-CHAT-DEVICE-REVOKE\u{0000}",
                "actorDid": next.user_did, "actorDeviceId": next.device_id,
                "keyId": next.key_id, "authGeneration": 2,
                "targetDeviceId": next.device_id, "targetAuthGeneration": 2,
                "idempotencyKey": revocation_id,
                "signedAt": Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
            }),
            &next_key,
        )
        .unwrap();
        let evidence = dpop::standard_service_auth_evidence(
            crate::auth::VerifiedServicePrincipal::for_federated_s2s(
                &next.user_did,
                "blue.catbird.chat.revokeDevice",
            ),
            &next.device_id.to_string(),
            CanonicalHttpMethod::parse("POST").unwrap(),
            TrustedRequestInstant::capture().unwrap(),
            None,
        )
        .unwrap();
        let admission = auth::authorize_signed_operation_only(
            &pool,
            evidence,
            decode_canonical_signed_mutation(&serde_json::to_vec(&revoke).unwrap()).unwrap(),
        )
        .await
        .unwrap();
        let mut tx = pool.begin().await.unwrap();
        let operation =
            crate::chat_protocol::repository::prelude::prepare_signed_operation(&mut tx, admission)
                .await
                .unwrap();
        use crate::chat_protocol::repository::revocation::{
            prepare_device_revocation, DeviceRevocationTransactionOutcome,
        };
        let DeviceRevocationTransactionOutcome::First(mut first) =
            prepare_device_revocation(&mut tx, operation).await.unwrap()
        else {
            panic!("a fresh revocation cannot be a replay")
        };
        let application = first.prepare_application(&mut tx).await.unwrap();
        let seal = application.apply().await.unwrap();
        let applied = first.finish(seal).unwrap();
        applied.complete(&mut tx).await.unwrap();
        tx.commit().await.unwrap();
        let key_states: Vec<(String, Option<Uuid>)> = sqlx::query_as(
            "SELECT key_id,revocation_id FROM chat.device_keys WHERE user_did=$1 AND device_id=$2 ORDER BY enrollment_auth_generation",
        ).bind(&next.user_did).bind(next.device_id).fetch_all(&pool).await.unwrap();
        assert_eq!(
            key_states,
            vec![
                (old.key_id.clone(), None),
                (next.key_id.clone(), Some(revocation_id))
            ]
        );
        assert!(matches!(
            admit(&pool, &next, &next_key, 2).await,
            Err(AuthRepositoryError::DeviceRevoked)
        ));
        let mut tx = pool.begin().await.unwrap();
        let resurrection = GroupDevice {
            auth_generation: 3,
            ..next.clone()
        };
        assert!(stage_devices(&mut tx, &[resurrection], at).await.is_err());
        tx.commit().await.unwrap();
        let retained_after_revocation: Vec<(Uuid, Vec<u8>, Vec<u8>)> = sqlx::query_as(history_sql)
            .bind(fixture.conversation_id)
            .bind(&old.user_did)
            .bind(old.device_id)
            .fetch_all(&pool)
            .await
            .unwrap();
        // Device revocation may append a server entry, but every original
        // signed control and its immutable key remain byte-identical.
        for prior in &history {
            assert!(retained_after_revocation.contains(prior));
            decode_and_verify_control_entry(&prior.1, &prior.2).unwrap();
        }
        // A same-key 1→2 rebind retains the original immutable activation.
        let same_key = SigningKey::from_bytes(&[0x7a; 32]);
        let mut same = GroupDevice {
            user_did: "did:web:same-key.example.com".into(),
            device_id: Uuid::new_v4(),
            key_id: ed25519_key_id(same_key.verifying_key().as_bytes())
                .unwrap()
                .as_str()
                .to_owned(),
            signing_public_key: same_key.verifying_key().to_bytes().to_vec(),
            auth_generation: 1,
        };
        for generation in [1, 2, 7] {
            same.auth_generation = generation;
            let mut tx = pool.begin().await.unwrap();
            stage_devices(&mut tx, std::slice::from_ref(&same), at)
                .await
                .unwrap();
            tx.commit().await.unwrap();
            admit(&pool, &same, &same_key, generation).await.unwrap();
        }
        let activations: Vec<i64> = sqlx::query_scalar(
            "SELECT enrollment_auth_generation FROM chat.device_keys WHERE user_did=$1 AND device_id=$2",
        ).bind(&same.user_did).bind(same.device_id).fetch_all(&pool).await.unwrap();
        assert_eq!(activations, vec![1]);
        assert!(matches!(
            admit(&pool, &same, &same_key, 2).await,
            Err(AuthRepositoryError::AuthenticationGenerationMismatch)
        ));
        pool.close().await;
    }

    #[tokio::test]
    async fn package_export_cannot_steal_a_lease_after_a_stale_candidate_snapshot() {
        let db = crate::common::fresh_db::fresh_fully_migrated_db("chat_remote_export_").await;
        let pool = db.connect(3).await;
        let fixture =
            seed_clean_slate_application_fixture(&pool, false, "did:web:remote.example.com", None)
                .await
                .unwrap();
        let reference: Vec<u8> = sqlx::query_scalar(
            "SELECT key_package_ref FROM chat.key_packages ORDER BY key_package_ref LIMIT 1",
        )
        .fetch_one(&pool)
        .await
        .unwrap();
        let now = Utc::now();
        let expires_at = now + chrono::Duration::minutes(5);
        let first_request = Uuid::new_v4();
        let other_request = Uuid::new_v4();
        let sequencer = "did:web:sequencer.example.com";
        let mut first = pool.begin().await.unwrap();
        sqlx::query(
            "SELECT key_package_ref FROM chat.key_packages WHERE key_package_ref=$1 FOR UPDATE",
        )
        .bind(&reference)
        .fetch_one(&mut *first)
        .await
        .unwrap();
        sqlx::query(CLAIM_GROUP_PACKAGE_EXPORT_SQL)
            .bind(&reference)
            .bind(fixture.conversation_id)
            .bind(first_request)
            .bind(sequencer)
            .bind(expires_at)
            .bind(now)
            .execute(&mut *first)
            .await
            .unwrap();
        let mut second = pool.begin().await.unwrap();
        let stale: bool = sqlx::query_scalar(
            "SELECT EXISTS(SELECT 1 FROM chat.group_key_package_exports WHERE key_package_ref=$1)",
        )
        .bind(&reference)
        .fetch_one(&mut *second)
        .await
        .unwrap();
        assert!(
            !stale,
            "the competing candidate snapshot precedes the first export commit"
        );
        first.commit().await.unwrap();
        sqlx::query(
            "SELECT key_package_ref FROM chat.key_packages WHERE key_package_ref=$1 FOR UPDATE",
        )
        .bind(&reference)
        .fetch_one(&mut *second)
        .await
        .unwrap();
        let lost = sqlx::query(CLAIM_GROUP_PACKAGE_EXPORT_SQL)
            .bind(&reference)
            .bind(fixture.conversation_id)
            .bind(other_request)
            .bind(sequencer)
            .bind(expires_at)
            .bind(now)
            .execute(&mut *second)
            .await
            .unwrap();
        assert_eq!(lost.rows_affected(), 0);
        let retry = sqlx::query(CLAIM_GROUP_PACKAGE_EXPORT_SQL)
            .bind(&reference)
            .bind(fixture.conversation_id)
            .bind(first_request)
            .bind(sequencer)
            .bind(expires_at)
            .bind(now)
            .execute(&mut *second)
            .await
            .unwrap();
        assert_eq!(retry.rows_affected(), 1);
        let reclaimed = sqlx::query(CLAIM_GROUP_PACKAGE_EXPORT_SQL)
            .bind(&reference)
            .bind(fixture.conversation_id)
            .bind(other_request)
            .bind(sequencer)
            .bind(expires_at + chrono::Duration::minutes(6))
            .bind(expires_at + chrono::Duration::minutes(1))
            .execute(&mut *second)
            .await
            .unwrap();
        assert_eq!(reclaimed.rows_affected(), 1);
        second.commit().await.unwrap();
        pool.close().await;
    }
}

#[cfg(test)]
#[path = "group_membership_c2_unit_tests.rs"]
mod c2_unit_tests;
