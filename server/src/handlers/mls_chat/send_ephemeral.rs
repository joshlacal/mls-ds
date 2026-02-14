// E2EE ephemeral message endpoint — typing indicators, read receipts, and
// presence signals sent as encrypted MLS application messages.
//
// The encrypted payload is an MLS application message containing:
// {
//   "type": "typing" | "read" | "presence" | "text" | "media",
//   "data": { ... type-specific fields ... }
// }
//
// The server CANNOT see this — it's encrypted by MLS.
// All types are padded to identical sizes, so the server cannot
// distinguish typing indicators from text messages by size.
//
// Ephemeral types (typing, read, presence) use the v2.sendEphemeral
// endpoint which doesn't persist messages. Regular types (text, media)
// use v2.sendMessage which persists to the messages table.

use axum::{extract::State, http::StatusCode, Json};
use jacquard_axum::ExtractXrpc;
use std::sync::Arc;
use tracing::{error, info};

use crate::{
    auth::AuthUser,
    generated::blue_catbird::mlsChat::send_ephemeral::{
        SendEphemeralOutput as GenOutput, SendEphemeralRequest,
    },
    generated_types::MessageView,
    realtime::{SseState, StreamEvent},
    storage::DbPool,
};

const NSID: &str = "blue.catbird.mlsChat.sendEphemeral";

// ---------------------------------------------------------------------------
// Handler
// ---------------------------------------------------------------------------

/// Send an encrypted ephemeral message (typing, read receipt, presence).
///
/// POST /xrpc/blue.catbird.mlsChat.sendEphemeral
///
/// Behaves like `sendMessage` but:
/// - Does NOT persist to the `messages` table
/// - Does NOT create envelopes or trigger push notifications
/// - Emits a `MessageEvent` with `ephemeral: true` so clients skip chat history
/// - The server sees only opaque ciphertext — it cannot distinguish typing
///   indicators from text messages
#[tracing::instrument(skip(pool, sse_state, auth_user, input))]
pub async fn send_ephemeral(
    State(pool): State<DbPool>,
    State(sse_state): State<Arc<SseState>>,
    auth_user: AuthUser,
    ExtractXrpc(input): ExtractXrpc<SendEphemeralRequest>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    // Enforce authorization
    if let Err(_e) = crate::auth::enforce_standard(&auth_user.claims, NSID) {
        error!("❌ [v2.sendEphemeral] Unauthorized");
        return Err(StatusCode::UNAUTHORIZED);
    }

    let convo_id = input.convo_id.to_string();

    // Check membership
    let is_member = crate::storage::is_member(&pool, &auth_user.did, &convo_id)
        .await
        .map_err(|e| {
            error!("❌ [v2.sendEphemeral] Membership check failed: {}", e);
            StatusCode::INTERNAL_SERVER_ERROR
        })?;

    if !is_member {
        error!("❌ [v2.sendEphemeral] Not a member of conversation");
        return Err(StatusCode::FORBIDDEN);
    }

    // ciphertext is already decoded bytes (jacquard handles base64)
    let ciphertext_bytes = input.ciphertext;

    // Validate padding: ciphertext length must match padded_size
    if ciphertext_bytes.len() as i64 != input.padded_size {
        error!(
            "❌ [v2.sendEphemeral] Ciphertext length ({}) != paddedSize ({})",
            ciphertext_bytes.len(),
            input.padded_size
        );
        return Err(StatusCode::BAD_REQUEST);
    }

    // Generate cursor and synthetic message ID
    let cursor = sse_state.cursor_gen.next(&convo_id, "messageEvent").await;
    let msg_id = ulid::Ulid::new().to_string();

    // Construct a MessageView identical to a regular message — the server
    // treats it as opaque ciphertext. The `ephemeral` flag on the StreamEvent
    // tells clients not to insert it into chat history.
    let message_view = MessageView {
        id: msg_id,
        convo_id: convo_id.clone(),
        ciphertext: ciphertext_bytes.to_vec(),
        epoch: input.epoch,
        seq: 0, // Ephemeral messages don't get a real sequence number
        created_at: chrono::Utc::now(),
        message_type: "app".to_string(),
        reactions: None,
    };

    let event = StreamEvent::MessageEvent {
        cursor: cursor.clone(),
        message: message_view,
        ephemeral: true,
    };

    // Emit to conversation subscribers — no persistence, no envelopes, no push
    if let Err(e) = sse_state.emit(&convo_id, event).await {
        error!("❌ [v2.sendEphemeral] Failed to emit SSE event: {}", e);
        // Best-effort — don't fail the request
    }

    info!("✅ [v2.sendEphemeral] Ephemeral message emitted");

    let output = GenOutput {
        cursor: cursor.into(),
        ..Default::default()
    };
    Ok(Json(serde_json::to_value(output).unwrap()))
}

#[cfg(test)]
mod tests {
    use crate::generated::blue_catbird::mlsChat::send_ephemeral::{
        SendEphemeral, SendEphemeralOutput,
    };

    #[test]
    fn test_ephemeral_input_deserialize() {
        let json = serde_json::json!({
            "convoId": "convo-123",
            "ciphertext": { "$bytes": "AQID" },
            "epoch": 5,
            "paddedSize": 3
        });

        let input: SendEphemeral = serde_json::from_value(json).unwrap();
        assert_eq!(input.convo_id.as_ref(), "convo-123");
        assert_eq!(input.ciphertext.as_ref(), &[1, 2, 3]);
        assert_eq!(input.epoch, 5);
        assert_eq!(input.padded_size, 3);
    }

    #[test]
    fn test_ephemeral_output_serialize() {
        let output = SendEphemeralOutput {
            cursor: "01ARZ3NDEKTSV4RRFFQ69G5FAV".into(),
            ..Default::default()
        };

        let json = serde_json::to_value(&output).unwrap();
        assert_eq!(json["cursor"], "01ARZ3NDEKTSV4RRFFQ69G5FAV");
    }
}
