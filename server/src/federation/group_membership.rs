//! Authenticated home/sequencer membership handoff for ordinary groups.

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
) -> Result<Value, String> {
    let (status, response) = call_home_response(pool, home, nsid, payload).await?;
    if !(200..300).contains(&status) {
        return Err(format!(
            "{nsid} returned HTTP {status}: {}",
            String::from_utf8_lossy(&response)
        ));
    }
    serde_json::from_slice(&response).map_err(|e| e.to_string())
}

async fn call_home_response(
    pool: &DbPool,
    home: &str,
    nsid: &str,
    payload: &Value,
) -> Result<(u16, Vec<u8>), String> {
    let destination = resolver(pool)
        .resolve_ds_destination(home)
        .await
        .map_err(|e| e.to_string())?;
    let token = service_auth()?
        .mint_token(home, nsid)
        .map_err(|e| e.to_string())?;
    super::super::outbound::OutboundClient::new(10, 15)
        .call_procedure_pinned_raw(
            &destination,
            nsid,
            &token,
            payload,
            SINGLE_MLS_ARTIFACT_BODY_LIMIT_BYTES,
        )
        .await
        .map_err(|e| e.to_string())
}

async fn devices_for_user(pool: &DbPool, user_did: &str) -> Result<Vec<GroupDevice>, String> {
    BareDid::parse(user_did).map_err(|e| e.to_string())?;
    let resolver = resolver(pool);
    let home = resolver
        .resolve(user_did)
        .await
        .map_err(|e| e.to_string())?;
    if !crate::identity::dids_equivalent(&home.did, resolver.self_did()) {
        return Err("device directory request is not at the user's home".into());
    }
    let keys = resolver
        .resolve_authorized_device_keys(user_did)
        .await
        .map_err(|e| e.to_string())?;
    let rows: Vec<(Uuid, String, i64, Vec<u8>)> = sqlx::query_as(
        "SELECT d.device_id, k.key_id, d.auth_generation, k.signing_public_key \
           FROM chat.devices d JOIN chat.device_keys k USING (user_did, device_id) \
          WHERE d.user_did = $1 AND d.status = 'active' AND d.revoked_at IS NULL \
            AND k.revoked_at IS NULL AND k.enrollment_auth_generation = d.auth_generation \
          ORDER BY d.device_id, k.key_id",
    )
    .bind(user_did)
    .fetch_all(pool)
    .await
    .map_err(|e| e.to_string())?;
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
        return Err("user has no active PDS-authorized group device".into());
    }
    Ok(devices)
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
        Err(e) => s2s_err(StatusCode::FORBIDDEN, "NotAuthorized", e),
    }
}

async fn remote_devices(
    pool: &DbPool,
    routes: &BTreeMap<String, Option<String>>,
) -> Result<Vec<GroupDevice>, String> {
    let resolver = resolver(pool);
    let mut devices = Vec::new();
    for (user, home) in routes {
        let Some(home) = home else { continue };
        let response = call_home(pool, home, DIRECTORY_NSID, &json!({ "userDid": user })).await?;
        let rows: Vec<GroupDevice> =
            serde_json::from_value(response["devices"].clone()).map_err(|e| e.to_string())?;
        let authorized = resolver
            .resolve_authorized_device_keys(user)
            .await
            .map_err(|e| e.to_string())?;
        if rows.is_empty() {
            return Err("empty remote group device directory".into());
        }
        for device in rows {
            if device.user_did != *user
                || device.device_id.get_version_num() != 4
                || device.auth_generation < 1
                || device.signing_public_key.len() != 32
                || crate::chat_protocol::validation::ed25519_key_id(&device.signing_public_key)
                    .map_err(|e| e.to_string())?
                    .as_str()
                    != device.key_id
                || !authorized
                    .iter()
                    .any(|key| key == &device.signing_public_key)
            {
                return Err("remote group device is not PDS-authorized".into());
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
    Ok(devices)
}

async fn stage_devices(
    tx: &mut Transaction<'_, Postgres>,
    devices: &[GroupDevice],
    at: DateTime<Utc>,
) -> Result<(), String> {
    for device in devices {
        let current: Option<(String, i64)> = sqlx::query_as(
            "SELECT status, auth_generation FROM chat.devices WHERE user_did = $1 AND device_id = $2 FOR UPDATE",
        ).bind(&device.user_did).bind(device.device_id).fetch_optional(&mut **tx).await.map_err(|e| e.to_string())?;
        if current.is_some_and(|(status, generation)| {
            status != "active" || generation > device.auth_generation
        }) {
            return Err("remote group device is revoked or its generation regressed".into());
        }
        sqlx::query(
            "INSERT INTO chat.principals(user_did,created_at) VALUES($1,$2) ON CONFLICT DO NOTHING",
        )
        .bind(&device.user_did)
        .bind(at)
        .execute(&mut **tx)
        .await
        .map_err(|e| e.to_string())?;
        sqlx::query(
            "INSERT INTO chat.devices(user_did,device_id,device_name,status,dpop_jkt,auth_generation,capabilities,created_at,updated_at) \
             VALUES($1,$2,'federated-group-device','active',NULL,$3,chat.protocol_capabilities(),$4,$4) \
             ON CONFLICT(user_did,device_id) DO UPDATE SET auth_generation = EXCLUDED.auth_generation, updated_at = GREATEST(chat.devices.updated_at, EXCLUDED.updated_at) \
             WHERE chat.devices.auth_generation < EXCLUDED.auth_generation",
        ).bind(&device.user_did).bind(device.device_id).bind(device.auth_generation).bind(at)
            .execute(&mut **tx).await.map_err(|e| e.to_string())?;
        sqlx::query(
            "INSERT INTO chat.device_keys(user_did,device_id,key_id,signing_public_key,enrollment_auth_generation,created_at) \
             VALUES($1,$2,$3,$4,$5,$6) ON CONFLICT DO NOTHING",
        ).bind(&device.user_did).bind(device.device_id).bind(&device.key_id).bind(&device.signing_public_key)
            .bind(device.auth_generation).bind(at).execute(&mut **tx).await.map_err(|e| e.to_string())?;
        let matches: bool = sqlx::query_scalar(
            "SELECT signing_public_key = $4 AND enrollment_auth_generation = $5 AND revoked_at IS NULL \
               FROM chat.device_keys WHERE user_did = $1 AND device_id = $2 AND key_id = $3",
        ).bind(&device.user_did).bind(device.device_id).bind(&device.key_id).bind(&device.signing_public_key)
            .bind(device.auth_generation).fetch_one(&mut **tx).await.map_err(|e| e.to_string())?;
        if !matches {
            return Err("conflicting remote group device key".into());
        }
    }
    Ok(())
}

pub(crate) async fn stage_remote_group_participants(
    pool: &DbPool,
    routes: &BTreeMap<String, Option<String>>,
) -> Result<(), String> {
    if !routes.values().any(Option::is_some) {
        return Ok(());
    }
    let devices = remote_devices(pool, routes).await?;
    let mut tx = pool.begin().await.map_err(|e| e.to_string())?;
    stage_devices(&mut tx, &devices, crate::sim_hooks::current_utc()).await?;
    tx.commit().await.map_err(|e| e.to_string())
}

async fn stage_package(
    tx: &mut Transaction<'_, Postgres>,
    package: &GroupPackage,
    at: DateTime<Utc>,
) -> Result<(), String> {
    let device = &package.device;
    let credential = crate::chat_protocol::validation::basic_credential_identity(
        &BareDid::parse(&device.user_did).map_err(|e| e.to_string())?,
        &CanonicalUuidV4::parse(&device.device_id.to_string()).map_err(|e| e.to_string())?,
    );
    let valid = crate::chat_protocol::wire::validate_key_package(
        &package.wrapper,
        crate::chat_protocol::wire::KeyPackageValidationPolicy {
            expected_basic_credential: &credential,
            expected_signature_key: &device.signing_public_key,
            now_unix_seconds: u64::try_from(at.timestamp()).map_err(|e| e.to_string())?,
            max_bytes: crate::chat_protocol::wire::MAX_KEY_PACKAGE_WIRE_BYTES,
        },
    )
    .map_err(|e| e.to_string())?;
    let not_before =
        DateTime::from_timestamp(valid.not_before() as i64, 0).ok_or("invalid package lifetime")?;
    let not_after =
        DateTime::from_timestamp(valid.not_after() as i64, 0).ok_or("invalid package lifetime")?;
    sqlx::query(
        "INSERT INTO chat.key_packages(key_package_ref,wrapper_bytes,wrapper_sha256,init_key,owner_did,owner_device_id,owner_key_id,owner_auth_generation,not_before,not_after,status,created_at,usage_scope) \
         VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,'available',$11,'recovery') ON CONFLICT DO NOTHING",
    ).bind(valid.key_package_ref().as_slice()).bind(&package.wrapper).bind(Sha256::digest(&package.wrapper).as_slice())
        .bind(valid.init_key()).bind(&device.user_did).bind(device.device_id).bind(&device.key_id).bind(device.auth_generation)
        .bind(not_before).bind(not_after).bind(package.created_at.min(at))
        .execute(&mut **tx).await.map_err(|e| e.to_string())?;
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
        .map_err(RelayFailure::Unavailable)?
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
    let mut tx = pool.begin().await.map_err(RelayFailure::unavailable)?;
    let allowed: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM chat.conversations c JOIN chat.participants p USING(conversation_id) \
          WHERE c.conversation_id=$1 AND c.kind='group' AND c.is_remote AND c.sequencer_ds=$2 \
            AND p.user_did=$3 AND p.current_membership AND p.status IN ('pending','active'))",
    ).bind(request.conversation_id).bind(caller).bind(&request.user_did).fetch_one(&mut *tx).await.map_err(RelayFailure::unavailable)?;
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
        .fetch_optional(&mut *tx).await.map_err(RelayFailure::unavailable)?;
    let Some((reference, wrapper, created_at, not_after)) = candidate else {
        return Err(RelayFailure::Protocol(
            ChatProtocolErrorCode::KeyPackageUnavailable,
        ));
    };
    sqlx::query(
        "INSERT INTO chat.group_key_package_exports(key_package_ref,conversation_id,recovery_request_id,sequencer_did,expires_at) \
         VALUES($1,$2,$3,$4,$5) ON CONFLICT(key_package_ref) DO UPDATE SET \
           conversation_id=EXCLUDED.conversation_id,recovery_request_id=EXCLUDED.recovery_request_id,sequencer_did=EXCLUDED.sequencer_did,expires_at=EXCLUDED.expires_at",
    ).bind(reference).bind(request.conversation_id).bind(request.recovery_request_id).bind(caller)
        .bind((now + chrono::Duration::minutes(5)).min(not_after)).execute(&mut *tx).await.map_err(RelayFailure::unavailable)?;
    tx.commit().await.map_err(RelayFailure::unavailable)?;
    Ok(GroupPackage {
        device,
        wrapper,
        created_at,
    })
}

pub(crate) async fn bootstrap_home_group(
    pool: &DbPool,
    conversation_id: Uuid,
    sequencer: &str,
) -> Result<(), String> {
    let resolver = resolver(pool);
    let destination = resolver
        .resolve_ds_destination(sequencer)
        .await
        .map_err(|e| e.to_string())?;
    let auth = service_auth()?;
    let outbound = super::super::outbound::OutboundClient::new(10, 15);
    let digest_token = auth
        .mint_token(sequencer, super::super::reconciliation::DIGEST_NSID)
        .map_err(|e| e.to_string())?;
    let digest = super::super::reconciliation::query_remote_digest(
        &outbound,
        &destination,
        &digest_token,
        &conversation_id.to_string(),
    )
    .await
    .map_err(|e| e.to_string())?;
    let selector = super::super::bootstrap::RemotePrefixBootstrapSelector::new(
        conversation_id,
        sequencer.to_owned(),
        digest.sequencer_term,
    )
    .map_err(|e| e.to_string())?;
    let sign =
        |target: &str, method: &str| auth.mint_token(target, method).map_err(|e| e.to_string());
    let admission = super::super::bootstrap::fetch_remote_prefix_admission(
        pool, &resolver, &outbound, &sign, selector,
    )
    .await
    .map_err(|e| e.to_string())?;
    let devices = remote_devices(pool, admission.participant_routes()).await?;
    let mut tx = pool.begin().await.map_err(|e| e.to_string())?;
    let earliest = admission
        .events()
        .first()
        .ok_or("empty group prefix")?
        .received_at();
    stage_devices(&mut tx, &devices, earliest).await?;
    for event in admission.events() {
        let canonical =
            decode_canonical_signed_mutation(event.signed_request()).map_err(|e| e.to_string())?;
        if canonical.kind()
            != crate::chat_protocol::transcript::SignedMutationKind::ParticipantAcceptance
        {
            continue;
        }
        let entry: Value =
            serde_json::from_slice(event.accepted_payload_bytes()).map_err(|e| e.to_string())?;
        let wrapper = decode_bytes(
            entry
                .pointer("/recovery/reservation/keyPackage/bytes")
                .ok_or("acceptance has no package")?,
        )?;
        let did = canonical.actor_did().as_str();
        let device_id = Uuid::from_bytes(*canonical.actor_device_id().as_bytes());
        let key_id = canonical.key_id().as_str();
        let key: Vec<u8> = sqlx::query_scalar("SELECT signing_public_key FROM chat.device_keys WHERE user_did=$1 AND device_id=$2 AND key_id=$3 AND revoked_at IS NULL")
            .bind(did).bind(device_id).bind(key_id).fetch_one(&mut *tx).await.map_err(|e| e.to_string())?;
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
        .await?;
    }
    let outcome = crate::chat_protocol::repository::remote_prefix::apply_remote_clean_prefix(
        &mut tx, admission,
    )
    .await
    .map_err(|e| e.to_string())?;
    if matches!(
        outcome,
        super::super::bootstrap::RemotePrefixApplyOutcome::Quarantined { .. }
    ) {
        return Err("group prefix was quarantined".into());
    }
    tx.commit().await.map_err(|e| e.to_string())
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
enum RelayFailure {
    /// The caller or signed request lacks authority for this step.
    Denied(String),
    /// A declared clean-chat protocol error the client must see.
    Protocol(ChatProtocolErrorCode),
    /// A dependency failed; the caller may retry.
    Unavailable(String),
}

impl RelayFailure {
    fn denied(error: impl std::fmt::Display) -> Self {
        Self::Denied(error.to_string())
    }

    fn unavailable(error: impl std::fmt::Display) -> Self {
        Self::Unavailable(error.to_string())
    }

    fn into_response(self) -> Response {
        match self {
            Self::Denied(error) => s2s_err(StatusCode::FORBIDDEN, "NotAuthorized", error),
            Self::Protocol(code) => s2s_err(StatusCode::BAD_REQUEST, code.as_str(), code.as_str()),
            Self::Unavailable(error) => {
                s2s_err(StatusCode::SERVICE_UNAVAILABLE, "ServiceUnavailable", error)
            }
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
    let unavailable = |error: String| GroupRelayError::Unavailable(error);
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
    let sequencer: Option<String> = sqlx::query_scalar(
        "SELECT sequencer_ds FROM chat.conversations WHERE conversation_id=$1 AND kind='group' AND is_remote",
    ).bind(conversation_id).fetch_optional(pool).await.map_err(|e| unavailable(e.to_string()))?.flatten();
    let Some(sequencer) = sequencer else {
        return Ok(None);
    };
    let request = RelayGroupMutationRequest {
        conversation_id,
        endpoint: endpoint.to_owned(),
        actor_did: actor.to_owned(),
        actor_device_id: device,
        signed_request: signed.clone(),
    };
    let payload = serde_json::to_value(request).map_err(|e| unavailable(e.to_string()))?;
    let (status, bytes) = call_home_response(
        pool,
        &sequencer,
        "blue.catbird.mlsDS.relayGroupMutation",
        &payload,
    )
    .await
    .map_err(unavailable)?;
    if (200..300).contains(&status) {
        return serde_json::from_slice(&bytes)
            .map(Some)
            .map_err(|e| unavailable(e.to_string()));
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

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct GroupStateRequest {
    conversation_id: Uuid,
    actor_did: String,
    actor_device_id: Uuid,
}

/// Read a remote group's state from its sequencer for a local device. `None`
/// when this DS holds no remote group mirror for the conversation.
pub(crate) async fn try_relay_group_state(
    pool: &DbPool,
    actor_did: &str,
    actor_device_id: Uuid,
    conversation_id: Uuid,
) -> Result<Option<Vec<u8>>, GroupRelayError> {
    let sequencer: Option<String> = sqlx::query_scalar(
        "SELECT sequencer_ds FROM chat.conversations WHERE conversation_id=$1 AND kind='group' AND is_remote",
    )
    .bind(conversation_id)
    .fetch_optional(pool)
    .await
    .map_err(|e| GroupRelayError::Unavailable(e.to_string()))?
    .flatten();
    let Some(sequencer) = sequencer else {
        return Ok(None);
    };
    let payload = json!({
        "conversationId": conversation_id,
        "actorDid": actor_did,
        "actorDeviceId": actor_device_id,
    });
    let (status, bytes) = call_home_response(pool, &sequencer, GROUP_STATE_NSID, &payload)
        .await
        .map_err(GroupRelayError::Unavailable)?;
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
    match resolver(&state.pool).resolve(&request.actor_did).await {
        Ok(home) if crate::identity::dids_equivalent(&home.did, &caller) => {}
        Ok(_) => {
            return s2s_err(
                StatusCode::FORBIDDEN,
                "NotAuthorized",
                "caller is not actor's home",
            )
        }
        Err(e) => {
            return s2s_err(
                StatusCode::SERVICE_UNAVAILABLE,
                "ServiceUnavailable",
                e.to_string(),
            )
        }
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
        Err(e) => {
            return s2s_err(
                StatusCode::SERVICE_UNAVAILABLE,
                "ServiceUnavailable",
                e.to_string(),
            )
        }
    };
    if !staged {
        let routes = BTreeMap::from([(request.actor_did.clone(), Some(caller))]);
        if let Err(e) = stage_remote_group_participants(&state.pool, &routes).await {
            return s2s_err(StatusCode::SERVICE_UNAVAILABLE, "ServiceUnavailable", e);
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
    )
    .await
    .unwrap_or_else(IntoResponse::into_response)
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
    let resolver = resolver(&state.pool);
    let home = resolver
        .resolve(&request.actor_did)
        .await
        .map_err(RelayFailure::unavailable)?;
    if !crate::identity::dids_equivalent(&home.did, caller) {
        return Err(RelayFailure::denied("caller is not actor's home"));
    }
    let allowed: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM chat.conversations c JOIN chat.participants p USING(conversation_id) \
          WHERE c.conversation_id=$1 AND c.kind='group' AND NOT c.is_remote \
            AND p.current_membership AND p.user_did=$2 AND p.ds_did=$3 AND p.status IN ('pending','active'))",
    ).bind(request.conversation_id).bind(&request.actor_did).bind(caller).fetch_one(&state.pool).await.map_err(RelayFailure::unavailable)?;
    if !allowed {
        return Err(RelayFailure::denied(
            "caller has no participant authority for this group",
        ));
    }
    let principal = crate::auth::VerifiedServicePrincipal::for_federated_s2s(
        &request.actor_did,
        &request.endpoint,
    );
    if request.endpoint == "blue.catbird.chat.acknowledgeEntries" {
        let body = serde_json::to_vec(&request.signed_request).map_err(RelayFailure::denied)?;
        return Ok(crate::handlers::chat::execute_federated_group_entries_ack(
            &state.pool,
            principal,
            &body,
        )
        .await
        .unwrap_or_else(IntoResponse::into_response));
    }
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
        CanonicalHttpMethod::parse("POST").map_err(RelayFailure::unavailable)?,
        TrustedRequestInstant::capture().map_err(RelayFailure::unavailable)?,
        None,
    )
    .map_err(RelayFailure::denied)?;
    let admission = auth::authorize_signed_operation_only(&state.pool, pre_replay, canonical)
        .await
        .map_err(RelayFailure::denied)?;
    let completed = auth::preflight_completed_response(&state.pool, &admission)
        .await
        .map_err(RelayFailure::unavailable)?
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
            .map_err(RelayFailure::Unavailable)?;
        if !(200..300).contains(&status) {
            return Err(match GroupRelayError::from_response(status, &response) {
                GroupRelayError::Rejected(code) => RelayFailure::Protocol(code),
                GroupRelayError::Unavailable(reason) => {
                    RelayFailure::Unavailable(format!("{PACKAGE_NSID}: {reason}"))
                }
            });
        }
        let exported: Value =
            serde_json::from_slice(&response).map_err(RelayFailure::unavailable)?;
        let package: GroupPackage = serde_json::from_value(exported["package"].clone())
            .map_err(RelayFailure::unavailable)?;
        let authorized = resolver
            .resolve_authorized_device_keys(&request.actor_did)
            .await
            .map_err(RelayFailure::unavailable)?;
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
        let mut tx = state
            .pool
            .begin()
            .await
            .map_err(RelayFailure::unavailable)?;
        stage_devices(
            &mut tx,
            std::slice::from_ref(&package.device),
            crate::sim_hooks::current_utc(),
        )
        .await
        .map_err(RelayFailure::Unavailable)?;
        stage_package(&mut tx, &package, crate::sim_hooks::current_utc())
            .await
            .map_err(RelayFailure::Unavailable)?;
        tx.commit().await.map_err(RelayFailure::unavailable)?;
    }
    if accept {
        let relationship = relationship_authority(state).map_err(RelayFailure::Unavailable)?;
        Ok(crate::handlers::chat::execute_federated_group_acceptance(
            &state.pool,
            admission,
            &relationship,
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

fn relationship_authority(
    state: &GroupRelayState,
) -> Result<crate::chat_protocol::relationship_policy::ProductionRelationshipAuthority, String> {
    if state.clock.is_deterministic() {
        crate::chat_protocol::relationship_policy::ProductionRelationshipAuthority::sim_allow_all()
            .map_err(|e| format!("{e:?}"))
    } else {
        Ok(crate::chat_protocol::relationship_policy::ProductionRelationshipAuthority::from_startup_guard(
            crate::chat_protocol::repository::relationship::load_fixed_relationship_authority_startup_guard().map_err(|e| format!("{e:?}"))?,
        ))
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct LabyrinthDirectoryRequest {
    endpoint: String,
    query: String,
    actor_did: String,
    actor_device_id: Uuid,
    read_header: String,
    read_signature: String,
}

pub(crate) async fn try_relay_labyrinth_directory(
    pool: &DbPool,
    resolver: Option<&super::super::resolver::DsResolver>,
    admission: &crate::labyrinth::auth::Admission,
    target_did: &str,
    endpoint: &str,
    query: Option<&str>,
) -> crate::labyrinth::error::LabyrinthResult<Option<Vec<u8>>> {
    use crate::labyrinth::error::LabyrinthError;
    let Some(resolver) = resolver else {
        return Ok(None);
    };
    let target = resolver
        .resolve(target_did)
        .await
        .map_err(|_| LabyrinthError::relay_unavailable())?;
    if crate::identity::dids_equivalent(&target.did, resolver.self_did()) {
        return Ok(None);
    }
    super::super::peer_policy::enforce_outbound_peer_policy(pool, &target.did)
        .await
        .map_err(|_| LabyrinthError::relay_unavailable())?;
    // Recheck the home device, then release its connection and lock before S2S.
    crate::labyrinth::auth::begin_read(pool, admission.clone())
        .await?
        .finish_read()
        .await?;
    let proof = admission
        .read
        .as_ref()
        .ok_or_else(LabyrinthError::internal)?;
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
        .map_err(|_| LabyrinthError::relay_unavailable())?;
    if (200..300).contains(&status) {
        return Ok(Some(bytes));
    }
    let error: Value =
        serde_json::from_slice(&bytes).map_err(|_| LabyrinthError::relay_unavailable())?;
    let name = match error.get("error").and_then(Value::as_str) {
        Some("EpochNotFound") => "EpochNotFound",
        Some("InvalidRequest") => "InvalidRequest",
        Some("InvalidSignature") => "InvalidSignature",
        Some("NotAuthorized") => "NotAuthorized",
        Some("DeviceRevoked") => "DeviceRevoked",
        Some("RateLimited") => "RateLimited",
        _ => return Err(LabyrinthError::relay_unavailable()),
    };
    Err(LabyrinthError::new(
        StatusCode::from_u16(status).map_err(|_| LabyrinthError::relay_unavailable())?,
        name,
        error
            .get("message")
            .and_then(Value::as_str)
            .unwrap_or("remote directory rejected the read"),
    ))
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
        "blue.catbird.labyrinth.getEpochHead" | "blue.catbird.labyrinth.getChatDeviceKeys"
    ) {
        return s2s_err(
            StatusCode::BAD_REQUEST,
            "InvalidRequest",
            "unsupported directory endpoint",
        );
    }
    let result = async {
        let resolver = resolver(&state.pool);
        let actor_home = resolver
            .resolve(&request.actor_did)
            .await
            .map_err(|e| e.to_string())?;
        if !crate::identity::dids_equivalent(&actor_home.did, &caller) {
            return Err("directory caller is not the actor's home".to_string());
        }
        let target = url::form_urlencoded::parse(request.query.as_bytes())
            .find_map(|(key, value)| (key == "did").then(|| value.into_owned()))
            .ok_or("directory query has no target DID")?;
        let target_home = resolver.resolve(&target).await.map_err(|e| e.to_string())?;
        if !crate::identity::dids_equivalent(&target_home.did, &state.self_did) {
            return Err("directory query is not at its authoritative home".to_string());
        }
        let routes = BTreeMap::from([(request.actor_did.clone(), Some(caller))]);
        stage_remote_group_participants(&state.pool, &routes).await
    }
    .await;
    if let Err(error) = result {
        return s2s_err(StatusCode::FORBIDDEN, "NotAuthorized", error);
    }
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
        Ok(bytes) => (
            [(axum::http::header::CONTENT_TYPE, "application/json")],
            bytes,
        )
            .into_response(),
        Err(error) => error.into_response(),
    }
}
