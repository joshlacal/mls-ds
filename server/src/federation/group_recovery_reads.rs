//! Resolve the exact restored leaf's current read window at its sequencer.
//! Entry bodies stay on the ordinary, device-granted transport read path.

use super::*;
use crate::chat_protocol::repository::entry_read::{
    self, PageRequest, RecoveryReadWindow, RemoteGroupStanding,
};

const NSID: &str = "blue.catbird.mlsDS.getGroupRecoveryReadWindow";

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Request {
    conversation_id: Uuid,
    actor_did: String,
    actor_device_id: Uuid,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    post_erasure: Option<PageRequest>,
}

pub(super) fn route() -> Router<GroupRelayState> {
    Router::new().route(
        "/xrpc/blue.catbird.mlsDS.getGroupRecoveryReadWindow",
        post(ClockScoped(window)).layer(DefaultBodyLimit::max(8192)),
    )
}

async fn window(State(state): State<GroupRelayState>, headers: HeaderMap, body: Bytes) -> Response {
    let caller = match verify_s2s_caller(&state, &headers, NSID, &body).await {
        Ok(caller) => caller,
        Err(response) => return response,
    };
    if crate::identity::dids_equivalent(&state.self_did, &caller) {
        return RelayFailure::denied("recovery read requires the actor's remote home")
            .into_response();
    }
    let request: Request = match serde_json::from_slice(&body) {
        Ok(request) => request,
        Err(_) => {
            return s2s_err(
                StatusCode::BAD_REQUEST,
                "InvalidRequest",
                "invalid recovery read window request",
            )
        }
    };
    match resolver(&state.pool)
        .resolve_authoritative_ds(&request.actor_did)
        .await
    {
        Ok(home) if crate::identity::dids_equivalent(&home.did, &caller) => {}
        Ok(_) => return RelayFailure::denied("caller is not the actor's home").into_response(),
        Err(error) => return RelayFailure::federation(error).into_response(),
    }
    let post_erasure = match request.post_erasure {
        Some(page) => {
            match surviving_enrollment(&state.pool, &request.actor_did, request.actor_device_id)
                .await
            {
                Ok((key_id, generation)) => Some((page, key_id, generation)),
                Err(error) => return error.into_response(),
            }
        }
        None => None,
    };
    let principal = crate::auth::VerifiedServicePrincipal::for_federated_s2s(
        &request.actor_did,
        "blue.catbird.chat.getEntries",
    );
    crate::handlers::chat::federated_recovery_read_window(
        &state.pool,
        principal,
        request.actor_device_id,
        request.conversation_id,
        &state.self_did,
        post_erasure,
    )
    .await
    .unwrap_or_else(IntoResponse::into_response)
}

/// Check the exact current enrollment at the actor's independently resolved PDS.
/// The caller binds this result to the locked enrollment in the read transaction.
async fn surviving_enrollment(
    pool: &DbPool,
    did: &str,
    device: Uuid,
) -> Result<(String, i64), RelayFailure> {
    use crate::federation::space_read_relay::{verify_live_recovered_enrollment, SpaceRelayError};

    let (key_id, generation, public_key) = sqlx::query_as::<_, (String, i64, Vec<u8>)>(
        "SELECT k.key_id,d.auth_generation,k.signing_public_key FROM chat.devices d \
         JOIN LATERAL (SELECT key_id,signing_public_key,revoked_at FROM chat.device_keys \
           WHERE user_did=d.user_did AND device_id=d.device_id AND enrollment_auth_generation<=d.auth_generation \
           ORDER BY enrollment_auth_generation DESC LIMIT 1) k ON k.revoked_at IS NULL \
         WHERE d.user_did=$1 AND d.device_id=$2 AND d.status='active' AND d.revoked_at IS NULL",
    )
    .bind(did)
    .bind(device)
    .fetch_optional(pool)
    .await
    .map_err(RelayFailure::storage)?
    .ok_or_else(|| RelayFailure::denied("surviving device has no current enrollment"))?;
    let key = public_key
        .try_into()
        .map_err(|_| RelayFailure::storage("invalid stored signing key"))?;
    verify_live_recovered_enrollment(&resolver(pool), did, &device.to_string(), &key)
        .await
        .map_err(|error| match error {
            SpaceRelayError::UpstreamUnavailable(_) => RelayFailure::unavailable(error),
            _ => RelayFailure::denied("surviving device lacks a matching current repository proof"),
        })?;
    Ok((key_id, generation))
}

pub(crate) async fn try_relay_recovery_entries(
    pool: &DbPool,
    destination_resolver: &super::super::super::resolver::DsResolver,
    conversation: Uuid,
    did: &str,
    device: Uuid,
    after: u64,
    limit: i64,
) -> Result<Option<Vec<u8>>, crate::handlers::chat::ChatFailure> {
    let Some((sequencer, window)) = recovery_window_for_home(
        pool,
        Some(destination_resolver),
        ChatEndpoint::GetEntries,
        conversation,
        did,
        device,
        PageRequest { after, limit },
    )
    .await?
    else {
        return Ok(None);
    };
    entry_read::granted_recovery_page(
        pool,
        window,
        &sequencer,
        conversation,
        did,
        device,
        after,
        limit,
    )
    .await
    .map(Some)
    .map_err(crate::handlers::chat::entries_read_failure)
}

pub(crate) async fn recovery_window_for_home(
    pool: &DbPool,
    destination_resolver: Option<&super::super::super::resolver::DsResolver>,
    endpoint: ChatEndpoint,
    conversation: Uuid,
    did: &str,
    device: Uuid,
    page: PageRequest,
) -> Result<Option<(String, RecoveryReadWindow)>, crate::handlers::chat::ChatFailure> {
    use crate::handlers::chat::ChatFailure;
    let mut conn = pool
        .acquire()
        .await
        .map_err(|_| ChatFailure::storage(endpoint))?;
    let erased = match entry_read::remote_group_standing(&mut conn, conversation, did)
        .await
        .map_err(|_| ChatFailure::storage(endpoint))?
    {
        RemoteGroupStanding::CleanMember => false,
        RemoteGroupStanding::Untracked => true,
        _ => return Ok(None),
    };
    // Pinned pre-federation schemas and non-group reads have no recovery grant path.
    if erased {
        let tracked:bool=sqlx::query_scalar("SELECT to_regclass('chat.group_transport_entry_recipients') IS NOT NULL AND to_regclass('chat.remote_group_memberships') IS NOT NULL")
            .fetch_one(&mut *conn).await.map_err(|_|ChatFailure::storage(endpoint))?;
        if !tracked {
            return Ok(None);
        }
    }
    let home: Option<String> = sqlx::query_scalar(
        "SELECT c.sequencer_ds FROM chat.conversations c LEFT JOIN chat.remote_group_memberships m \
         ON (m.conversation_id,m.sequencer_did)=(c.conversation_id,c.sequencer_ds) AND m.user_did=$2 \
         WHERE c.conversation_id=$1 AND c.kind='group' AND c.is_remote AND c.lifecycle='active' \
           AND (m.status='active' OR ($4 AND m.user_did IS NULL AND EXISTS(SELECT 1 FROM chat.participants p \
             WHERE p.conversation_id=c.conversation_id AND p.user_did=$2 AND p.current_membership AND p.status='active'))) AND EXISTS(SELECT 1 FROM chat.group_transport_entry_recipients r \
             WHERE r.conversation_id=c.conversation_id AND r.user_did=$2 AND r.device_id=$3) \
           AND NOT EXISTS(SELECT 1 FROM federation_sync_state WHERE convo_id=c.conversation_id::text AND status='quarantined')",
    )
    .bind(conversation)
    .bind(did)
    .bind(device)
    .bind(erased)
    .fetch_optional(&mut *conn)
    .await
    .map_err(|_| ChatFailure::storage(endpoint))?;
    drop(conn);
    let Some(sequencer) = home else {
        return Ok(None);
    };
    let request = json!(Request {
        conversation_id: conversation,
        actor_did: did.to_owned(),
        actor_device_id: device,
        post_erasure: erased.then_some(page),
    });
    let (status, bytes) =
        call_home_response_via(pool, destination_resolver, &sequencer, NSID, &request)
            .await
            .map_err(|e| GroupRelayError::from_local(e).into_failure(endpoint))?;
    if !(200..300).contains(&status) {
        let error = GroupRelayError::from_response(status, &bytes);
        if endpoint == ChatEndpoint::AcknowledgeEntries
            && matches!(&error, GroupRelayError::Rejected(code) if !endpoint.declares(*code))
        {
            return Err(ChatFailure::protocol(
                endpoint,
                ChatProtocolErrorCode::DeviceNotLeaf,
            ));
        }
        return Err(error.into_failure(endpoint));
    }
    let window: RecoveryReadWindow =
        serde_json::from_slice(&bytes).map_err(|_| ChatFailure::invariant(endpoint))?;
    Ok(Some((sequencer, window)))
}
