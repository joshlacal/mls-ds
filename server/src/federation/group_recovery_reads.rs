//! Resolve the exact restored leaf's current read window at its sequencer.
//! Entry bodies stay on the ordinary, device-granted transport read path.

use super::*;
use crate::chat_protocol::repository::entry_read::{self, RecoveryReadWindow, RemoteGroupStanding};

const NSID: &str = "blue.catbird.mlsDS.getGroupRecoveryReadWindow";

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Request {
    conversation_id: Uuid,
    actor_did: String,
    actor_device_id: Uuid,
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
    )
    .await
    .unwrap_or_else(IntoResponse::into_response)
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
) -> Result<Option<(String, RecoveryReadWindow)>, crate::handlers::chat::ChatFailure> {
    use crate::handlers::chat::ChatFailure;
    let mut conn = pool
        .acquire()
        .await
        .map_err(|_| ChatFailure::storage(endpoint))?;
    if entry_read::remote_group_standing(&mut conn, conversation, did)
        .await
        .map_err(|_| ChatFailure::storage(endpoint))?
        != RemoteGroupStanding::CleanMember
    {
        return Ok(None);
    }
    let home: Option<String> = sqlx::query_scalar(
        "SELECT c.sequencer_ds FROM chat.conversations c JOIN chat.remote_group_memberships m \
         ON (m.conversation_id,m.sequencer_did)=(c.conversation_id,c.sequencer_ds) \
         WHERE c.conversation_id=$1 AND c.kind='group' AND c.is_remote AND c.lifecycle='active' \
           AND m.user_did=$2 AND m.status='active' AND EXISTS(SELECT 1 FROM chat.group_transport_entry_recipients r \
             WHERE r.conversation_id=c.conversation_id AND r.user_did=$2 AND r.device_id=$3) \
           AND NOT EXISTS(SELECT 1 FROM federation_sync_state WHERE convo_id=c.conversation_id::text AND status='quarantined')",
    )
    .bind(conversation)
    .bind(did)
    .bind(device)
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
        actor_device_id: device
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
