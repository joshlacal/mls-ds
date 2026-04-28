use axum::{
    extract::State,
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use chrono::{DateTime, Utc};
use jacquard_axum::ExtractXrpc;
use std::sync::Arc;
use tokio::sync::oneshot;
use tracing::{error, info, warn};
use uuid::Uuid;

use crate::{
    actors::{ActorRegistry, ConvoMessage, ResetTrigger, WelcomeEnvelope},
    auth::AuthUser,
    generated::blue_catbird::mlsChat::{
        bootstrap_reset_group::{
            BootstrapResetGroupError as LexBootstrapResetGroupError, BootstrapResetGroupOutput,
            BootstrapResetGroupRequest,
        },
        ConvoMetadata, ConvoView, MemberView,
    },
    sqlx_jacquard::{chrono_to_datetime, did_to_string, string_to_did},
    storage::DbPool,
};

const NSID: &str = "blue.catbird.mlsChat.bootstrapResetGroup";

/// Wire-compat shim: post-bootstrap epoch returned to clients.
///
/// TODO(phase-2.5-cleanup): remove this shim once `activate_crypto_session_tx`
/// processes the bootstrap commit in-tx (advancing `last_observed_epoch`
/// from 0 → 1 atomically with crypto_session creation). At that point
/// chokepoint storage state will match wire state without override.
///
/// **Background**: pre-Phase-2 bootstrap wrote `current_epoch=1` directly
/// to the conversations row because the bootstrap commit IS the first
/// epoch advance for the new MLS group. The Phase 2 chokepoint
/// (`reset_chokepoint::activate_crypto_session_tx`) represents the
/// activation point as "session active, no commits observed yet" and
/// stores `last_observed_epoch=0`. That's architecturally pure — the
/// server hasn't observed the commit's wire bytes — but it would change
/// `BootstrapResetGroupOutput.convo.epoch` from 1 to 0, breaking pre-
/// Phase-2 clients that depend on `epoch == 1` after a successful
/// bootstrap.
///
/// **Resolution path**: a future Phase 2.5 task will fold the bootstrap
/// commit observation into the chokepoint tx (e.g. accept the commit
/// envelope alongside the GroupInfo and append a `commit_observed`
/// delivery_event that bumps `last_observed_epoch` to 1 inline). At
/// that point: delete this constant and the override below; let
/// `outcome.session.last_observed_epoch + 1` flow through.
///
/// **Deletion criterion**: `last_observed_epoch == 1` post-activation
/// in `crypto_sessions` for at least one full client release cycle.
pub(crate) const BOOTSTRAP_WIRE_COMPAT_EPOCH: i32 = 1;

/// Complete a post-reset conversation by submitting MLS group material.
///
/// POST /xrpc/blue.catbird.mlsChat.bootstrapResetGroup
///
/// Phase 2 §2.3: routes through `ConversationActor` two-phase reset
/// (`RequestCryptoSessionReset` + `ActivateCryptoSession` back-to-back).
/// Trigger is `ResetTrigger::Bootstrap`. Caller has material in hand
/// (groupInfo + welcomes), so the chokepoint creates the new
/// `crypto_session` row, supersedes the prior session, populates
/// `conversations` legacy MLS columns, and queues welcomes to the new
/// `pending_welcomes` table.
///
/// Behavior delta vs pre-Phase 2:
/// - Post-bootstrap `current_epoch=0` (was 1). The chokepoint represents
///   the activation point as "session active, no commits observed yet";
///   subsequent commits advance epoch normally. This is a client-visible
///   change for callers that read `convo.epoch` in the response.
/// - Welcomes are now stored in `pending_welcomes` (new table) keyed by
///   `crypto_session_id`. For backwards compatibility with the legacy
///   `getGroupState(includes=welcome)` path (which reads from
///   `welcome_messages`), the handler continues to write the legacy
///   table after the chokepoint commits. Drop after clients migrate to
///   read pending_welcomes.
///
/// First caller wins; later callers receive 409 AlreadyBootstrapped via
/// the chokepoint's idempotency-replay path (the prior winning
/// `crypto_session_activated` event resolves to the same session).
#[tracing::instrument(skip(pool, actor_registry, auth_user, input))]
pub async fn bootstrap_reset_group(
    State(pool): State<DbPool>,
    State(actor_registry): State<Arc<ActorRegistry>>,
    auth_user: AuthUser,
    ExtractXrpc(input): ExtractXrpc<BootstrapResetGroupRequest>,
) -> Response {
    if let Err(_e) = crate::auth::enforce_standard(&auth_user.claims, NSID) {
        error!("[bootstrapResetGroup] Unauthorized");
        return StatusCode::UNAUTHORIZED.into_response();
    }

    match handle(pool, actor_registry, auth_user, &input).await {
        Ok(output) => Json(output).into_response(),
        Err(resp) => resp,
    }
}

/// Inner handler. Exposed `pub` so integration tests in `tests/` can drive
/// it directly without scaffolding the Axum router + auth middleware.
pub async fn handle(
    pool: DbPool,
    actor_registry: Arc<ActorRegistry>,
    auth_user: AuthUser,
    input: &crate::generated::blue_catbird::mlsChat::bootstrap_reset_group::BootstrapResetGroup<'_>,
) -> Result<BootstrapResetGroupOutput<'static>, Response> {
    let caller_did = auth_user.did.clone();
    let original_convo_id = input.original_convo_id.to_string();
    let new_group_id = input.new_group_id.to_string();

    info!(
        convo = %crate::crypto::redact_for_log(&original_convo_id),
        new_group_id = %crate::crypto::redact_for_log(&new_group_id),
        caller = %crate::crypto::redact_for_log(&caller_did),
        member_count_input = input.members.len(),
        cipher_suite = %input.cipher_suite,
        "[bootstrapResetGroup] start"
    );

    // ── Validate cipher suite ────────────────────────────────────────────
    let valid_suites = ["MLS_256_XWING_CHACHA20POLY1305_SHA256_Ed25519"];
    if !valid_suites.contains(&input.cipher_suite.as_ref()) {
        warn!(
            "[bootstrapResetGroup] Invalid cipher suite: {}",
            input.cipher_suite
        );
        return Err((
            StatusCode::BAD_REQUEST,
            Json(LexBootstrapResetGroupError::InvalidCipherSuite(Some(
                format!("Cipher suite '{}' is not supported", input.cipher_suite).into(),
            ))),
        )
            .into_response());
    }

    // ── Verify caller is in the existing (preserved) member roster ───────
    let is_member: bool = sqlx::query_scalar(
        "SELECT EXISTS(\
            SELECT 1 FROM members \
            WHERE convo_id = $1 AND (user_did = $2 OR member_did = $2) AND left_at IS NULL\
        )",
    )
    .bind(&original_convo_id)
    .bind(&caller_did)
    .fetch_one(&pool)
    .await
    .map_err(|e| {
        error!("[bootstrapResetGroup] member check failed: {}", e);
        StatusCode::INTERNAL_SERVER_ERROR.into_response()
    })?;

    if !is_member {
        warn!("[bootstrapResetGroup] caller is not a member");
        info!(
            convo_id = %crate::crypto::redact_for_log(&original_convo_id),
            new_group_id = %crate::crypto::redact_for_log(&new_group_id),
            caller_did = %crate::crypto::redact_for_log(&caller_did),
            "bootstrap_403_not_member"
        );
        return Err((
            StatusCode::FORBIDDEN,
            Json(LexBootstrapResetGroupError::NotMember(Some(
                "Caller is not in the existing member roster for this convo".into(),
            ))),
        )
            .into_response());
    }

    // ── Decode groupInfo and welcome bytes (already raw via Jacquard) ────
    let group_info_bytes: Vec<u8> = input.group_info.to_vec();
    let welcome_bytes: Option<Vec<u8>> = input.welcome_message.as_ref().map(|b| b.to_vec());
    let now = Utc::now();

    // ── Build WelcomeEnvelope list for the chokepoint ────────────────────
    //
    // Resolve recipients: prefer key_package_hashes if present (per-device
    // welcome targeting); otherwise fan out to all active members of the
    // convo (one welcome per member).
    let mut welcome_envelopes: Vec<WelcomeEnvelope> = Vec::new();
    if let Some(welcome) = welcome_bytes.as_ref() {
        if let Some(ref kp_hashes) = input.key_package_hashes {
            for entry in kp_hashes {
                let recipient = did_to_string(&entry.did);
                let hash_hex: &str = &entry.hash;
                // Validate hex up front (chokepoint stores opaque bytes).
                hex::decode(hash_hex).map_err(|e| {
                    warn!(
                        "[bootstrapResetGroup] invalid key package hash hex for {}: {}",
                        crate::crypto::redact_for_log(&recipient),
                        e
                    );
                    (
                        StatusCode::BAD_REQUEST,
                        format!("Invalid key package hash hex: {}", e),
                    )
                        .into_response()
                })?;
                welcome_envelopes.push(WelcomeEnvelope {
                    recipient_did: recipient,
                    recipient_device_id: None,
                    welcome_data: welcome.clone(),
                    key_package_hash: Some(hash_hex.to_string()),
                });
            }
        } else {
            // No key_package_hashes — fan out to active members.
            let recipients: Vec<String> = sqlx::query_scalar(
                "SELECT member_did FROM members \
                 WHERE convo_id = $1 AND left_at IS NULL",
            )
            .bind(&original_convo_id)
            .fetch_all(&pool)
            .await
            .map_err(|e| {
                error!(
                    "[bootstrapResetGroup] SELECT members for welcome fanout: {}",
                    e
                );
                StatusCode::INTERNAL_SERVER_ERROR.into_response()
            })?;
            for recipient in recipients {
                welcome_envelopes.push(WelcomeEnvelope {
                    recipient_did: recipient,
                    recipient_device_id: None,
                    welcome_data: welcome.clone(),
                    key_package_hash: None,
                });
            }
        }
    }

    // ── Send through chokepoint via ConversationActor ────────────────────
    //
    // Phase 2 §2.2 bootstrap flow: Request + Activate back-to-back. The
    // chokepoint atomically supersedes the prior session, creates the new
    // active crypto_session row, syncs legacy MLS columns on conversations,
    // appends `crypto_session_*` events to delivery_events, and INSERTs
    // welcomes into pending_welcomes. Idempotency: a second caller with
    // the same `(originalConvoId, newGroupId, callerDid)` resolves to the
    // existing winning crypto_session via the activation event's
    // idempotency_key replay, returning the same session — that's the
    // "first member to call wins; later callers receive the same outcome"
    // semantic, replacing the pre-Phase-2 409 AlreadyBootstrapped error.
    let actor_ref = actor_registry
        .get_or_spawn(&original_convo_id)
        .await
        .map_err(|e| {
            error!("[bootstrapResetGroup] failed to spawn actor: {}", e);
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        })?;

    // Idempotency-key namespace: `(original_convo_id, new_group_id)` is
    // the natural per-bootstrap-attempt identity. Use a deterministic
    // string form so retries from the same caller resolve to the same
    // chokepoint events. Format matches the convention from #9
    // (req-reset:<uuid-or-id> / activate:<uuid-or-id>).
    let request_id_uuid = format!("{}-{}", original_convo_id, new_group_id);

    let (req_tx, req_rx) = oneshot::channel();
    actor_ref
        .send_message(ConvoMessage::RequestCryptoSessionReset {
            trigger: ResetTrigger::Bootstrap,
            initiator_did: caller_did.clone(),
            reason: "bootstrap_reset_group".to_string(),
            idempotency_key: format!("req-reset:{}", request_id_uuid),
            reply: req_tx,
        })
        .map_err(|_| {
            error!("[bootstrapResetGroup] failed to send Request to actor");
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        })?;

    let reset_request = req_rx
        .await
        .map_err(|_| {
            error!("[bootstrapResetGroup] Request channel closed");
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        })?
        .map_err(|e| {
            error!("[bootstrapResetGroup] Request handler failed: {}", e);
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        })?;

    let (act_tx, act_rx) = oneshot::channel();
    actor_ref
        .send_message(ConvoMessage::ActivateCryptoSession {
            reset_request_id: Some(reset_request.request_id.clone()),
            trigger: ResetTrigger::Bootstrap,
            new_mls_group_id: new_group_id.clone(),
            new_group_info: Some(group_info_bytes.clone()),
            welcomes: welcome_envelopes,
            initiator_did: caller_did.clone(),
            idempotency_key: format!("activate:{}", request_id_uuid),
            reply: act_tx,
        })
        .map_err(|_| {
            error!("[bootstrapResetGroup] failed to send Activate to actor");
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        })?;

    let _session = act_rx
        .await
        .map_err(|_| {
            error!("[bootstrapResetGroup] Activate channel closed");
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        })?
        .map_err(|e| {
            error!("[bootstrapResetGroup] Activate handler failed: {}", e);
            // Tie-break loss surfaces here as an error. Map to 409 so
            // existing client expectations (AlreadyBootstrapped semantic
            // from pre-Phase 2) match the new tie-break-loss outcome.
            (
                StatusCode::CONFLICT,
                Json(LexBootstrapResetGroupError::AlreadyBootstrapped(Some(
                    "Another caller already activated this generation; receive the Welcome from the winner.".into(),
                ))),
            )
                .into_response()
        })?;

    // ── Legacy welcome_messages dual-write for backward compat ───────────
    //
    // The chokepoint has stored welcomes in `pending_welcomes` (new
    // table). For read-side compatibility with existing clients calling
    // `getGroupState(includes=welcome)` — which still SELECT from
    // `welcome_messages` — replicate the welcomes into the legacy table.
    // The chokepoint's housekeeping step has already DELETEd any prior
    // welcome_messages for this convo, so these inserts represent a
    // clean post-activation distribution. Drop after clients migrate to
    // read pending_welcomes.
    if let Some(welcome) = welcome_bytes.as_ref() {
        if let Some(ref kp_hashes) = input.key_package_hashes {
            for entry in kp_hashes {
                let recipient = did_to_string(&entry.did);
                let hash_hex: &str = &entry.hash;
                let hash_bytes = match hex::decode(hash_hex) {
                    Ok(b) => b,
                    Err(_) => continue, // already validated above; defensive
                };
                let welcome_id = Uuid::new_v4().to_string();
                if let Err(e) = sqlx::query(
                    "INSERT INTO welcome_messages \
                        (id, convo_id, recipient_did, welcome_data, key_package_hash, created_at) \
                     VALUES ($1, $2, $3, $4, $5, $6) \
                     ON CONFLICT (convo_id, recipient_did, COALESCE(key_package_hash, '\\x00'::bytea)) WHERE consumed = false \
                     DO NOTHING",
                )
                .bind(&welcome_id)
                .bind(&original_convo_id)
                .bind(&recipient)
                .bind(welcome)
                .bind(Some(hash_bytes))
                .bind(&now)
                .execute(&pool)
                .await
                {
                    warn!(
                        error = ?e,
                        recipient = %crate::crypto::redact_for_log(&recipient),
                        "[bootstrapResetGroup] legacy welcome_messages INSERT failed (non-fatal)"
                    );
                }
            }
        } else {
            let recipients: Vec<String> = match sqlx::query_scalar(
                "SELECT member_did FROM members \
                 WHERE convo_id = $1 AND left_at IS NULL",
            )
            .bind(&original_convo_id)
            .fetch_all(&pool)
            .await
            {
                Ok(r) => r,
                Err(e) => {
                    warn!(error = ?e, "[bootstrapResetGroup] legacy fanout SELECT failed (non-fatal)");
                    Vec::new()
                }
            };
            for recipient in recipients {
                let welcome_id = Uuid::new_v4().to_string();
                if let Err(e) = sqlx::query(
                    "INSERT INTO welcome_messages \
                        (id, convo_id, recipient_did, welcome_data, key_package_hash, created_at) \
                     VALUES ($1, $2, $3, $4, NULL, $5) \
                     ON CONFLICT (convo_id, recipient_did, COALESCE(key_package_hash, '\\x00'::bytea)) WHERE consumed = false \
                     DO NOTHING",
                )
                .bind(&welcome_id)
                .bind(&original_convo_id)
                .bind(&recipient)
                .bind(welcome)
                .bind(&now)
                .execute(&pool)
                .await
                {
                    warn!(
                        error = ?e,
                        recipient = %crate::crypto::redact_for_log(&recipient),
                        "[bootstrapResetGroup] legacy welcome_messages INSERT failed (non-fatal)"
                    );
                }
            }
        }
    }

    // ── Mark referenced key packages consumed (best-effort) ──────────────
    if let Some(ref kp_hashes) = input.key_package_hashes {
        for entry in kp_hashes {
            let owner = did_to_string(&entry.did);
            let hash_hex: &str = &entry.hash;
            if let Err(e) = crate::db::mark_key_package_consumed(&pool, &owner, hash_hex).await {
                warn!(
                    "[bootstrapResetGroup] mark_key_package_consumed for {}: {}",
                    crate::crypto::redact_for_log(&owner),
                    e
                );
            }
        }
    }

    // ── Build the response ConvoView from the now-bootstrapped row ──────
    // Read post-commit so the view reflects the persisted state, including
    // anything other transactions wrote concurrently to non-locked columns.
    //
    // NOTE: `conversations` has no `last_message_at` column (only `created_at`
    // / `updated_at`); compute it from the messages table instead so the
    // response sorts correctly. Earlier code SELECTed a phantom column and
    // 500'd post-commit, causing iOS to treat the actual successful bootstrap
    // as a failure.
    let row: (
        String,         // creator_did
        Option<String>, // name
        String,         // cipher_suite_persisted
        DateTime<Utc>,  // created_at
        i32,            // reset_count (NOT NULL DEFAULT 0)
    ) = sqlx::query_as(
        "SELECT creator_did, name, cipher_suite, created_at, reset_count \
         FROM conversations WHERE id = $1",
    )
    .bind(&original_convo_id)
    .fetch_one(&pool)
    .await
    .map_err(|e| {
        error!("[bootstrapResetGroup] SELECT post-commit row: {}", e);
        StatusCode::INTERNAL_SERVER_ERROR.into_response()
    })?;

    let last_message_at: Option<DateTime<Utc>> = sqlx::query_scalar(
        "SELECT MAX(created_at) FROM messages WHERE convo_id = $1",
    )
    .bind(&original_convo_id)
    .fetch_optional(&pool)
    .await
    .ok()
    .flatten()
    .flatten();

    let (creator_did_persisted, name, cipher_suite_persisted, created_at, reset_count) = row;

    let member_rows: Vec<(
        String,
        String,
        Option<String>,
        Option<String>,
        DateTime<Utc>,
        bool,
        Option<i32>,
    )> = sqlx::query_as(
        "SELECT member_did, user_did, device_id, device_name, joined_at, is_admin, leaf_index \
         FROM members WHERE convo_id = $1 AND left_at IS NULL ORDER BY joined_at",
    )
    .bind(&original_convo_id)
    .fetch_all(&pool)
    .await
    .map_err(|e| {
        error!("[bootstrapResetGroup] SELECT members for view: {}", e);
        StatusCode::INTERNAL_SERVER_ERROR.into_response()
    })?;

    let members_typed: Vec<MemberView<'static>> = member_rows
        .into_iter()
        .map(
            |(member_did, user_did, device_id, device_name, joined_at, is_admin, leaf_index)| {
                MemberView {
                    did: string_to_did(&member_did),
                    user_did: string_to_did(&user_did),
                    device_id: device_id.map(|s| s.into()),
                    device_name: device_name.map(|s| s.into()),
                    joined_at: chrono_to_datetime(joined_at),
                    is_admin,
                    is_moderator: Some(false),
                    leaf_index: leaf_index.map(|i| i as i64),
                    credential: None,
                    promoted_at: None,
                    promoted_by: None,
                    extra_data: Default::default(),
                }
            },
        )
        .collect();

    let metadata = name.as_ref().map(|n| ConvoMetadata {
        name: Some(n.clone().into()),
        description: None,
        extra_data: Default::default(),
    });

    let welcome_count = if input.welcome_message.is_some() {
        input
            .key_package_hashes
            .as_ref()
            .map(|h| h.len())
            .unwrap_or(members_typed.len())
    } else {
        0
    };
    info!(
        convo_id = %crate::crypto::redact_for_log(&original_convo_id),
        new_group_id = %crate::crypto::redact_for_log(&new_group_id),
        caller_did = %crate::crypto::redact_for_log(&caller_did),
        welcome_count,
        member_count = members_typed.len(),
        "bootstrap_succeeded"
    );

    info!(
        convo = %crate::crypto::redact_for_log(&original_convo_id),
        new_group_id = %crate::crypto::redact_for_log(&new_group_id),
        member_count = members_typed.len(),
        "[bootstrapResetGroup] complete"
    );

    // Wire-compat shim: chokepoint stores `last_observed_epoch=0` (server
    // has not yet observed a commit envelope), but pre-Phase-2 clients
    // expect `convo.epoch == 1` after bootstrap. See
    // `BOOTSTRAP_WIRE_COMPAT_EPOCH` docstring for the resolution path.
    let response_epoch: i32 = BOOTSTRAP_WIRE_COMPAT_EPOCH;

    Ok(BootstrapResetGroupOutput {
        convo: ConvoView {
            conversation_id: original_convo_id.clone().into(),
            group_id: new_group_id.into(),
            creator: string_to_did(&creator_did_persisted),
            members: members_typed,
            epoch: response_epoch as i64,
            cipher_suite: cipher_suite_persisted.into(),
            created_at: chrono_to_datetime(created_at),
            last_message_at: last_message_at.map(chrono_to_datetime),
            metadata,
            confirmation_tag: None,
            reset_generation: Some(reset_count as i64),
            extra_data: Default::default(),
        },
        extra_data: Default::default(),
    })
}

#[cfg(test)]
mod tests {
    use super::BOOTSTRAP_WIRE_COMPAT_EPOCH;

    /// Phase 2.5 cleanup gate: pin the wire-compat epoch value at 1.
    ///
    /// The chokepoint stores `last_observed_epoch=0` after activation; this
    /// constant overrides the wire value to 1 so pre-Phase-2 clients reading
    /// `BootstrapResetGroupOutput.convo.epoch` see the same value as before
    /// the funnel landed. If a future change "fixes" this to 0 by deleting
    /// the constant, that's a wire-semantic break for those clients —
    /// surface it as a test failure here, then reconcile with the Phase 2.5
    /// plan before proceeding.
    #[test]
    fn bootstrap_wire_compat_epoch_is_one() {
        assert_eq!(
            BOOTSTRAP_WIRE_COMPAT_EPOCH, 1,
            "wire-compat shim must return epoch=1 to pre-Phase-2 clients; \
             see TODO(phase-2.5-cleanup) docstring for the resolution path"
        );
    }
}
