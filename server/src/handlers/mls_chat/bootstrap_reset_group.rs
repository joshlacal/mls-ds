use axum::{
    extract::State,
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use chrono::{DateTime, Utc};
use jacquard_axum::ExtractXrpc;
use std::collections::BTreeSet;
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
        ConvoView, MemberView,
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

    // ── Auth precondition: state-driven dispatch ─────────────────────────
    //
    // Bootstrap is the activator side of the two-phase reset. The
    // permitted preconditions are:
    //
    //   (a) `state='reset_requested'` — the standard activator path. An
    //       upstream caller (admin via reset_group(no material), quorum,
    //       sweep) issued `RequestCryptoSessionReset` and we're providing
    //       the MLS material to activate.
    //
    //   (b) **SERVER F (#68)**: `state='active' AND group_info IS NULL` —
    //       self-heal first-responder path. The legacy `do_reset_group`
    //       (Phase 2.5 Stage 1) creates such "orphan" rows when the
    //       indirect-funneling flow runs without an admin follow-up. Any
    //       active member can race to be the first-responder bootstrap;
    //       the chokepoint UPDATE-tie-break (`WHERE group_info IS NULL`)
    //       serializes concurrent self-healers so the audit trail
    //       remains coherent.
    //
    // Anything else returns 409 (the standard auth-bypass guard Codex
    // flagged in the original review).
    //
    // Single SELECT carries both the state and a `gi_null` discriminator
    // so the dispatch is one round-trip.
    let precondition: Option<(String, bool)> = sqlx::query_as(
        "SELECT state, group_info IS NULL AS gi_null \
         FROM crypto_sessions \
         WHERE conversation_id = $1 \
           AND state IN ('active', 'reset_requested', 'superseding') \
         ORDER BY generation DESC \
         LIMIT 1",
    )
    .bind(&original_convo_id)
    .fetch_optional(&pool)
    .await
    .map_err(|e| {
        error!("[bootstrapResetGroup] state precondition lookup: {}", e);
        StatusCode::INTERNAL_SERVER_ERROR.into_response()
    })?;

    /// Internal dispatch tag for the activator path.
    enum Path {
        /// Standard activator — `state='reset_requested'`. Routes to
        /// `ActivateCryptoSession` actor message.
        Activate,
        /// SERVER F self-heal — `state='active' AND group_info IS NULL`.
        /// Routes to `SelfHealOrphanSession` actor message.
        SelfHeal,
    }

    let path = match precondition.as_ref() {
        Some((state, _)) if state == "reset_requested" => Path::Activate,
        Some((state, gi_null)) if state == "active" && *gi_null => {
            // SERVER F #68 self-heal precondition. The actual welcome-
            // fanout completeness check runs INSIDE the `Path::SelfHeal`
            // dispatch arm below (after `welcome_envelopes` is built)
            // so partial-fanout requests fail fast with a 400 before
            // hitting the chokepoint. Strand-by-incomplete-bootstrap
            // is the failure mode being prevented: once a self-healer
            // wins with welcomes for only a subset of active members,
            // the omitted members' own self-heal calls would be
            // rejected by the chokepoint precondition (group_info now
            // populated), permanently stranding them until the next
            // reset cycle.
            info!(
                convo_id = %crate::crypto::redact_for_log(&original_convo_id),
                new_group_id = %crate::crypto::redact_for_log(&new_group_id),
                caller_did = %crate::crypto::redact_for_log(&caller_did),
                "bootstrap_self_heal_path"
            );
            Path::SelfHeal
        }
        Some((state, gi_null)) => {
            warn!(
                convo_id = %crate::crypto::redact_for_log(&original_convo_id),
                new_group_id = %crate::crypto::redact_for_log(&new_group_id),
                caller_did = %crate::crypto::redact_for_log(&caller_did),
                state = %state,
                gi_null = %gi_null,
                "bootstrap_409_state_mismatch"
            );
            return Err((
                StatusCode::CONFLICT,
                Json(LexBootstrapResetGroupError::AlreadyBootstrapped(Some(
                    "Conversation is not in a pending-reset state and is not eligible for first-responder self-heal. Either an upstream reset request hasn't been issued, group_info is already populated, or another caller already activated. Fall back to receiving the Welcome from the winner.".into(),
                ))),
            )
                .into_response());
        }
        None => {
            error!(
                "[bootstrapResetGroup] no active/reset_requested/superseding crypto_session for convo {}",
                crate::crypto::redact_for_log(&original_convo_id)
            );
            return Err((
                StatusCode::NOT_FOUND,
                Json(LexBootstrapResetGroupError::BootstrapTargetNotFound(Some(
                    "No current crypto_session found for this conversation.".into(),
                ))),
            )
                .into_response());
        }
    };

    // Idempotency-key namespace: `(original_convo_id, new_group_id)` is
    // the natural per-bootstrap-attempt identity. Different namespaces
    // for activate vs self-heal prevent accidental cross-path replay if
    // the same caller hits both flows on different conversations.
    let request_id_uuid = format!("{}-{}", original_convo_id, new_group_id);

    // SERVER M (#75): the chokepoint reply carries the activated/self-healed
    // `crypto_session`. We surface its `generation` to the response so iOS
    // can seed `pendingResetGeneration` on bootstrap success and short-circuit
    // historical SSE replay events whose `gen` is now stale (otherwise
    // `handleGroupReset` would call `deleteGroup` on the just-bootstrapped
    // group). Captured into the outer scope so the post-match output builder
    // can read it from either dispatch arm.
    let session_generation: i32 = match path {
        Path::Activate => {
            // Standard activator: send `ActivateCryptoSession`. Upstream
            // Request that put the session into `reset_requested` carries
            // its own `req-reset:` key in delivery_events; correlation
            // across the audit log is via (conversation_id, generation,
            // event_type) tuple lookup at query time. `reset_request_id:
            // None` — we don't need to inline the upstream id here.
            let (act_tx, act_rx) = oneshot::channel();
            actor_ref
                .send_message(ConvoMessage::ActivateCryptoSession {
                    reset_request_id: None,
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

            let session = act_rx
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
            session.generation
        }
        Path::SelfHeal => {
            // SERVER F #68: validate welcome-fanout completeness BEFORE
            // dispatching to the chokepoint. Strand-by-incomplete-
            // bootstrap is the failure mode: if a self-healer wins
            // the tie-break with welcomes for only a subset of active
            // members, the omitted recipients can never recover via
            // their own self-heal because the chokepoint precondition
            // (state='active' AND group_info IS NULL) no longer holds
            // — group_info is now populated by the partial winner.
            // Those recipients are stranded until the next reset cycle.
            //
            // Required: `welcome_envelopes` covers every active member
            // EXCEPT the caller (who already has the new group state
            // locally because they're submitting the bootstrap material).
            //
            // NOTE: this check is intentionally placed inline (not as
            // a Lexicon-typed error) because `BootstrapResetGroupError`
            // does not currently expose an `InvalidWelcomeFanout`
            // variant. Adding one would require a Lexicon revision +
            // codegen across catbird-atproto, Petrel, and the Kotlin
            // bindings; deferred to follow-up work. Raw 400 with a
            // JSON body describing the shape is acceptable for now —
            // the handler is new (just landed) so no client depends
            // on the response shape yet.
            let active_members: Vec<String> = sqlx::query_scalar(
                "SELECT member_did FROM members \
                 WHERE convo_id = $1 AND left_at IS NULL",
            )
            .bind(&original_convo_id)
            .fetch_all(&pool)
            .await
            .map_err(|e| {
                error!(
                    "[bootstrapResetGroup] active-member SELECT for fanout validation: {}",
                    e
                );
                StatusCode::INTERNAL_SERVER_ERROR.into_response()
            })?;

            let expected_recipients: BTreeSet<&str> = active_members
                .iter()
                .map(|d| d.as_str())
                .filter(|d| *d != caller_did.as_str())
                .collect();
            let provided_recipients: BTreeSet<&str> = welcome_envelopes
                .iter()
                .map(|w| w.recipient_did.as_str())
                .collect();
            let missing: Vec<&str> = expected_recipients
                .difference(&provided_recipients)
                .copied()
                .collect();

            if !missing.is_empty() {
                // Logs are redacted (journald may aggregate into less-
                // trusted destinations). Wire body returns raw DIDs:
                // the caller is an authenticated member of this convo
                // and already has roster visibility via `getConvos`,
                // so disclosure inside the response is acceptable —
                // and necessary, since the client developer needs to
                // know which recipients they forgot.
                let missing_redacted: Vec<String> = missing
                    .iter()
                    .map(|d| crate::crypto::redact_for_log(d))
                    .collect();
                warn!(
                    convo_id = %crate::crypto::redact_for_log(&original_convo_id),
                    new_group_id = %crate::crypto::redact_for_log(&new_group_id),
                    caller_did = %crate::crypto::redact_for_log(&caller_did),
                    missing_count = missing.len(),
                    expected_count = expected_recipients.len(),
                    provided_count = provided_recipients.len(),
                    missing = ?missing_redacted,
                    "bootstrap_self_heal_invalid_welcome_fanout"
                );
                return Err((
                    StatusCode::BAD_REQUEST,
                    Json(serde_json::json!({
                        "error": "InvalidWelcomeFanout",
                        "message": format!(
                            "Self-heal requires welcomes for all active non-initiator members; missing: {:?}",
                            missing
                        ),
                    })),
                )
                    .into_response());
            }

            // SERVER F #68: send `SelfHealOrphanSession`. The chokepoint
            // UPDATEs the orphan row in place; idempotency-key namespace
            // is `selfheal:` to keep this distinct from any prior or
            // future `activate:` retries on the same convo.
            let (sh_tx, sh_rx) = oneshot::channel();
            actor_ref
                .send_message(ConvoMessage::SelfHealOrphanSession {
                    new_mls_group_id: new_group_id.clone(),
                    new_group_info: group_info_bytes.clone(),
                    welcomes: welcome_envelopes,
                    initiator_did: caller_did.clone(),
                    idempotency_key: format!("selfheal:{}", request_id_uuid),
                    reply: sh_tx,
                })
                .map_err(|_| {
                    error!("[bootstrapResetGroup] failed to send SelfHeal to actor");
                    StatusCode::INTERNAL_SERVER_ERROR.into_response()
                })?;

            let session = sh_rx
                .await
                .map_err(|_| {
                    error!("[bootstrapResetGroup] SelfHeal channel closed");
                    StatusCode::INTERNAL_SERVER_ERROR.into_response()
                })?
                .map_err(|e| {
                    error!("[bootstrapResetGroup] SelfHeal handler failed: {}", e);
                    (
                        StatusCode::CONFLICT,
                        Json(LexBootstrapResetGroupError::AlreadyBootstrapped(Some(
                            "Another responder already self-healed this conversation, or a tardy admin populated group_info first; receive the Welcome from the winner.".into(),
                        ))),
                    )
                        .into_response()
                })?;
            // Self-heal preserves the prior session's generation (no +1).
            // This is the value clients should seed `pendingResetGeneration`
            // with so future SSE replay events for the same generation are
            // recognized as the current state, not a stale reset notice.
            session.generation
        }
    };

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
                .bind(now)
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
                .bind(now)
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
        String,        // creator_did
        String,        // cipher_suite_persisted
        DateTime<Utc>, // created_at
        i32,           // reset_count (NOT NULL DEFAULT 0)
    ) = sqlx::query_as(
        "SELECT creator_did, cipher_suite, created_at, reset_count \
         FROM conversations WHERE id = $1",
    )
    .bind(&original_convo_id)
    .fetch_one(&pool)
    .await
    .map_err(|e| {
        error!("[bootstrapResetGroup] SELECT post-commit row: {}", e);
        StatusCode::INTERNAL_SERVER_ERROR.into_response()
    })?;

    let last_message_at: Option<DateTime<Utc>> =
        sqlx::query_scalar("SELECT MAX(created_at) FROM messages WHERE convo_id = $1")
            .bind(&original_convo_id)
            .fetch_optional(&pool)
            .await
            .ok()
            .flatten()
            .flatten();

    let (creator_did_persisted, cipher_suite_persisted, created_at, reset_count) = row;

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
            confirmation_tag: None,
            reset_generation: Some(reset_count as i64),
            extra_data: Default::default(),
        },
        // SERVER M (#75): expose `crypto_session.generation` so iOS can seed
        // `pendingResetGeneration` on bootstrap success. Distinct from
        // `convo.reset_generation` (which is `conversations.reset_count`,
        // a separate counter); this is the session-level identity used by
        // clients to recognize SSE replay events for the now-current state.
        // See also: lexicon `output.generation` (optional for wire-compat).
        generation: Some(session_generation as i64),
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
