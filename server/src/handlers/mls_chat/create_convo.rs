use axum::{
    extract::State,
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use chrono::{DateTime, Utc};
use jacquard_axum::ExtractXrpc;
use std::sync::Arc;
use tracing::{error, info, warn};

use crate::{
    auth::{verify_is_admin, AuthUser},
    block_sync::BlockSyncService,
    generated::blue_catbird::mlsChat::{
        create_convo::{
            CreateConvoError as LexCreateConvoError, CreateConvoOutput, CreateConvoRequest,
        },
        ConvoView, MemberView,
    },
    sqlx_jacquard::{chrono_to_datetime, did_to_string, string_to_did},
    storage::DbPool,
};

const NSID: &str = "blue.catbird.mlsChat.createConvo";

#[cfg(test)]
static TEST_ABORT_AFTER_WELCOME: std::sync::atomic::AtomicBool =
    std::sync::atomic::AtomicBool::new(false);

#[cfg(test)]
struct CreateConvoAbortAfterWelcomeGuard;

#[cfg(test)]
impl Drop for CreateConvoAbortAfterWelcomeGuard {
    fn drop(&mut self) {
        TEST_ABORT_AFTER_WELCOME.store(false, std::sync::atomic::Ordering::SeqCst);
    }
}

#[cfg(test)]
fn enable_create_convo_abort_after_welcome_for_test() -> CreateConvoAbortAfterWelcomeGuard {
    TEST_ABORT_AFTER_WELCOME.store(true, std::sync::atomic::Ordering::SeqCst);
    CreateConvoAbortAfterWelcomeGuard
}

#[allow(clippy::result_large_err)] // Test-only abort seam must match the handler's Response error.
fn maybe_abort_create_convo_after_welcome_for_test() -> Result<(), Response> {
    #[cfg(test)]
    if TEST_ABORT_AFTER_WELCOME.load(std::sync::atomic::Ordering::SeqCst) {
        return Err(StatusCode::INTERNAL_SERVER_ERROR.into_response());
    }

    Ok(())
}

fn bootstrap_epoch_for_create(has_welcome: bool) -> i32 {
    if has_welcome {
        1
    } else {
        0
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct WelcomeRowsForCreate {
    expected_rows: usize,
    used_per_device_path: bool,
}

fn expected_welcome_rows_for_create(
    key_package_hash_count: usize,
    fallback_member_count: usize,
) -> WelcomeRowsForCreate {
    if key_package_hash_count > 0 {
        WelcomeRowsForCreate {
            expected_rows: key_package_hash_count,
            used_per_device_path: true,
        }
    } else {
        WelcomeRowsForCreate {
            expected_rows: fallback_member_count,
            used_per_device_path: false,
        }
    }
}

fn validate_initial_members_have_welcome(
    initial_members: Option<&[jacquard_common::types::string::Did<'_>]>,
    creator_did: &str,
    has_welcome: bool,
) -> Result<(), String> {
    if has_welcome {
        return Ok(());
    }

    let creator_user_form = creator_did
        .split_once('#')
        .map(|(user, _device)| user)
        .unwrap_or(creator_did);

    let has_non_creator_initial_member = initial_members
        .unwrap_or_default()
        .iter()
        .map(did_to_string)
        .any(|did| did != creator_did && did != creator_user_form);

    if has_non_creator_initial_member {
        return Err(
            "initialMembers that include another user require welcomeMessage bootstrap material"
                .to_string(),
        );
    }

    Ok(())
}

fn validate_initial_group_info(
    has_welcome: bool,
    group_info: Option<&bytes::Bytes>,
) -> Result<Option<Vec<u8>>, String> {
    let Some(group_info) = group_info else {
        return if has_welcome {
            Err(
                "welcomeMessage bootstrap material requires groupInfo for recovery fallback"
                    .to_string(),
            )
        } else {
            Ok(None)
        };
    };

    let len = group_info.len();
    if len < crate::group_info::MIN_GROUP_INFO_SIZE {
        return Err(format!(
            "groupInfo is too small: {} bytes (minimum {})",
            len,
            crate::group_info::MIN_GROUP_INFO_SIZE
        ));
    }
    if len > crate::group_info::MAX_GROUP_INFO_SIZE {
        return Err(format!(
            "groupInfo is too large: {} bytes (maximum {})",
            len,
            crate::group_info::MAX_GROUP_INFO_SIZE
        ));
    }

    Ok(Some(group_info.to_vec()))
}

// ---------------------------------------------------------------------------
// Handler (v2 – inline SQL, no v1 delegation)
// ---------------------------------------------------------------------------

/// Consolidated conversation creation and invite management endpoint.
///
/// POST /xrpc/blue.catbird.mlsChat.createConvo
///
/// The generated CreateConvo type is used for direct creation. Invite management
/// actions are dispatched via the optional `invite.action` field.
#[tracing::instrument(skip(pool, block_sync, auth_user, input))]
pub async fn create_convo(
    State(pool): State<DbPool>,
    State(block_sync): State<Arc<BlockSyncService>>,
    auth_user: AuthUser,
    ExtractXrpc(input): ExtractXrpc<CreateConvoRequest>,
) -> Response {
    if let Err(_e) = crate::auth::enforce_standard(&auth_user.claims, NSID) {
        error!("❌ [v2.createConvo] Unauthorized");
        return StatusCode::UNAUTHORIZED.into_response();
    }

    // ── Invite revocation branch ─────────────────────────────────────────
    if let Some(ref invite) = input.invite {
        if invite.action.as_ref() == "revoke" {
            return handle_revoke_invite(&pool, &auth_user, invite).await;
        }
        // "create" or unknown action – fall through to create convo flow
    }

    // ── Standard conversation creation ───────────────────────────────────
    match handle_create_convo(pool, block_sync, auth_user, &input).await {
        Ok(json) => Json(json).into_response(),
        Err(resp) => resp,
    }
}

// ---------------------------------------------------------------------------
// Revoke invite (inline – replaces v1 revoke_invite delegation)
// ---------------------------------------------------------------------------

async fn handle_revoke_invite(
    pool: &DbPool,
    auth_user: &AuthUser,
    invite: &crate::generated::blue_catbird::mlsChat::create_convo::InviteAction<'_>,
) -> Response {
    let invite_id = invite.code.as_deref().unwrap_or_default().to_string();
    let caller_did = &auth_user.did;

    info!(invite_id = %invite_id, caller = %crate::crypto::redact_for_log(caller_did), "v2.createConvo: revoking invite");

    // Get conversation ID from invite
    let convo_id: Option<String> = sqlx::query_scalar("SELECT convo_id FROM invites WHERE id = $1")
        .bind(&invite_id)
        .fetch_optional(pool)
        .await
        .unwrap_or(None);

    let convo_id = match convo_id {
        Some(cid) => cid,
        None => {
            warn!("Invite not found: {}", invite_id);
            return (StatusCode::NOT_FOUND, "Invite not found").into_response();
        }
    };

    // Verify caller is admin
    if let Err(e) = verify_is_admin(pool, &convo_id, caller_did).await {
        error!("Admin verification failed: {:?}", e);
        return (StatusCode::FORBIDDEN, "Not an admin").into_response();
    }

    // Revoke the invite
    let rows_affected = match sqlx::query(
        r#"UPDATE invites
           SET revoked = true, revoked_at = NOW(), revoked_by_did = $1
           WHERE id = $2 AND revoked = false"#,
    )
    .bind(caller_did)
    .bind(&invite_id)
    .execute(pool)
    .await
    {
        Ok(r) => r.rows_affected(),
        Err(e) => {
            error!("Database error revoking invite: {}", e);
            return StatusCode::INTERNAL_SERVER_ERROR.into_response();
        }
    };

    if rows_affected == 0 {
        warn!("Invite already revoked or not found: {}", invite_id);
        return (StatusCode::NOT_FOUND, "Invite already revoked or not found").into_response();
    }

    info!(invite_id = %invite_id, convo_id = %crate::crypto::redact_for_log(&convo_id), "Invite revoked successfully");
    // TODO: No generated output type for invite revocation response — fields don't match
    // CreateConvoOutput. Define a lexicon output for revoke or use a shared success type.
    Json(serde_json::json!({"success": true})).into_response()
}

// ---------------------------------------------------------------------------
// Create conversation (inline – replaces v1 create_convo delegation)
// ---------------------------------------------------------------------------

async fn handle_create_convo(
    pool: DbPool,
    block_sync: Arc<BlockSyncService>,
    auth_user: AuthUser,
    input: &crate::generated::blue_catbird::mlsChat::create_convo::CreateConvo<'_>,
) -> Result<CreateConvoOutput<'static>, Response> {
    tracing::debug!("🔷 [v2.createConvo] incoming create request");

    info!(
        creator = %crate::crypto::redact_for_log(&auth_user.did),
        group = %crate::crypto::redact_for_log(&input.group_id),
        initial_members = input.initial_members.as_ref().map(|m| m.len()).unwrap_or(0),
        has_welcome = input.welcome_message.is_some(),
        "[v2.createConvo] start"
    );

    // Parse creator DID
    let creator_did: String = auth_user.did.clone();

    // Validate cipher suite
    let valid_suites = ["MLS_256_XWING_CHACHA20POLY1305_SHA256_Ed25519"];
    if !valid_suites.contains(&input.cipher_suite.as_str()) {
        warn!(
            "❌ [v2.createConvo] Invalid cipher suite: {}",
            input.cipher_suite
        );
        return Err((
            StatusCode::BAD_REQUEST,
            Json(LexCreateConvoError::InvalidCipherSuite(Some(
                format!("Cipher suite '{}' is not supported", input.cipher_suite).into(),
            ))),
        )
            .into_response());
    }

    // Validate initial members count
    if let Some(ref members) = input.initial_members {
        let total_member_count = members.len() + 1;
        let max_members = 1000;
        if total_member_count > max_members {
            warn!(
                "❌ [v2.createConvo] Too many members: {}",
                total_member_count
            );
            return Err((
                StatusCode::BAD_REQUEST,
                Json(LexCreateConvoError::TooManyMembers(Some(
                    format!(
                        "Cannot add more than {} initial members (got {} including creator)",
                        max_members, total_member_count
                    )
                    .into(),
                ))),
            )
                .into_response());
        }
    }

    if let Err(message) = validate_initial_members_have_welcome(
        input.initial_members.as_deref(),
        &auth_user.did,
        input.welcome_message.is_some(),
    ) {
        warn!("❌ [v2.createConvo] Malformed MLS bootstrap: {message}");
        return Err((
            StatusCode::BAD_REQUEST,
            Json(LexCreateConvoError::KeyPackageNotFound(Some(
                message.into(),
            ))),
        )
            .into_response());
    }

    let initial_group_info =
        validate_initial_group_info(input.welcome_message.is_some(), input.group_info.as_ref())
            .map_err(|message| {
                warn!("❌ [v2.createConvo] Malformed MLS groupInfo bootstrap: {message}");
                (
                    StatusCode::BAD_REQUEST,
                    Json(LexCreateConvoError::KeyPackageNotFound(Some(
                        message.into(),
                    ))),
                )
                    .into_response()
            })?;

    // ── Block detection ──────────────────────────────────────────────────
    let mut all_member_dids_for_block_check = vec![auth_user.did.clone()];
    if let Some(ref members) = input.initial_members {
        for member_did in members.iter() {
            let member_did_str = did_to_string(member_did);
            if member_did_str != auth_user.did {
                all_member_dids_for_block_check.push(member_did_str);
            }
        }
    }

    if all_member_dids_for_block_check.len() > 1 {
        match block_sync
            .check_block_conflicts(&all_member_dids_for_block_check)
            .await
        {
            Ok(conflicts) => {
                if !conflicts.is_empty() {
                    for (blocker, _blocked) in &conflicts {
                        if let Err(e) = block_sync.sync_blocks_to_db(&pool, blocker).await {
                            warn!("Failed to sync blocks to DB: {}", e);
                        }
                    }
                    warn!(
                        "❌ [v2.createConvo] Block detected: {} blocks found via PDS",
                        conflicts.len()
                    );
                    return Err((
                        StatusCode::FORBIDDEN,
                        Json(LexCreateConvoError::MutualBlockDetected(Some(
                            "Cannot create conversation: one or more members have blocked each other".into(),
                        ))),
                    )
                        .into_response());
                }
            }
            Err(e) => {
                // Fallback to local DB
                warn!("PDS block check failed, falling back to local DB: {}", e);
                let blocks: Vec<(String, String)> = sqlx::query_as(
                    "SELECT user_did, target_did FROM bsky_blocks WHERE user_did = ANY($1) AND target_did = ANY($1)",
                )
                .bind(&all_member_dids_for_block_check)
                .fetch_all(&pool)
                .await
                .map_err(|e| {
                    error!("❌ [v2.createConvo] Failed to check blocks: {}", e);
                    StatusCode::INTERNAL_SERVER_ERROR.into_response()
                })?;

                if !blocks.is_empty() {
                    warn!(
                        "❌ [v2.createConvo] Block detected: {} blocks (DB cache)",
                        blocks.len()
                    );
                    return Err((
                        StatusCode::FORBIDDEN,
                        Json(LexCreateConvoError::MutualBlockDetected(Some(
                            "Cannot create conversation: one or more members have blocked each other".into(),
                        ))),
                    )
                        .into_response());
                }
            }
        }
    }

    // ── Conversation ID ─────────────────────────────────────────────────
    let convo_id = input.group_id.to_string();
    let now = Utc::now();
    let bootstrap_epoch = bootstrap_epoch_for_create(input.welcome_message.is_some());
    let initial_group_info_epoch = initial_group_info.as_ref().map(|_| bootstrap_epoch);
    let initial_group_info_updated_at = initial_group_info.as_ref().map(|_| now);
    if let Some(client_epoch) = input.current_epoch {
        if client_epoch != bootstrap_epoch as i64 {
            warn!(
                client_epoch,
                bootstrap_epoch,
                convo = %crate::crypto::redact_for_log(&convo_id),
                "[v2.createConvo] ignoring inconsistent client currentEpoch"
            );
        }
    }

    // Plaintext metadata is no longer accepted by the createConvo schema.
    // Group metadata is server-blind: clients encrypt name/description/avatar
    // via the `group_metadata_blobs` blob path.

    let welcome_row_expectation = input.welcome_message.as_ref().map(|_| {
        expected_welcome_rows_for_create(
            input
                .key_package_hashes
                .as_ref()
                .map(|hashes| hashes.len())
                .unwrap_or(0),
            all_member_dids_for_block_check.len(),
        )
    });

    // ── Idempotency / first-responder race check ────────────────────────
    // Fetch the existing creator (if any) so we can distinguish:
    //   - same caller → legitimate retry within the idempotency window (200)
    //   - different caller → first-responder race loss; the winner already
    //     bound this groupId to their conversation. Returning 200 here would
    //     silently desync MLS state. Return 409 ConvoAlreadyExists so the
    //     loser knows to fall back to receiving the Welcome.
    let existing_creator_did: Option<String> =
        sqlx::query_scalar("SELECT creator_did FROM conversations WHERE id = $1")
            .bind(&convo_id)
            .fetch_optional(&pool)
            .await
            .map_err(|e| {
                error!("❌ [v2.createConvo] idempotency check: {}", e);
                StatusCode::INTERNAL_SERVER_ERROR.into_response()
            })?;

    if let Some(ref existing_creator) = existing_creator_did {
        if existing_creator != &auth_user.did {
            warn!(
                convo = %crate::crypto::redact_for_log(&convo_id),
                caller = %crate::crypto::redact_for_log(&auth_user.did),
                existing_creator = %crate::crypto::redact_for_log(existing_creator),
                "[v2.createConvo] race-loss: convo already exists, created by different DID"
            );
            return Err((
                StatusCode::CONFLICT,
                Json(LexCreateConvoError::ConvoAlreadyExists(Some(
                    "Conversation already exists at this groupId, created by a different DID"
                        .into(),
                ))),
            )
                .into_response());
        }

        tracing::debug!("📍 [v2.createConvo] Idempotency: returning existing conversation");

        // Fetch existing members
        let existing_members: Vec<(
            String,
            String,
            Option<String>,
            Option<String>,
            DateTime<Utc>,
            bool,
            Option<i32>,
        )> = sqlx::query_as(
            "SELECT member_did, user_did, device_id, device_name, joined_at, is_admin, leaf_index
             FROM members WHERE convo_id = $1 AND left_at IS NULL ORDER BY joined_at",
        )
        .bind(&convo_id)
        .fetch_all(&pool)
        .await
        .map_err(|e| {
            error!("❌ [v2.createConvo] fetch existing members: {}", e);
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        })?;

        let members_typed: Vec<MemberView<'static>> = existing_members
            .into_iter()
            .map(
                |(
                    member_did,
                    user_did,
                    device_id,
                    device_name,
                    joined_at,
                    is_admin,
                    leaf_index,
                )| {
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

        let existing_epoch: i32 =
            sqlx::query_scalar("SELECT current_epoch FROM conversations WHERE id = $1")
                .bind(&convo_id)
                .fetch_one(&pool)
                .await
                .map_err(|e| {
                    error!("❌ [v2.createConvo] fetch existing epoch: {}", e);
                    StatusCode::INTERNAL_SERVER_ERROR.into_response()
                })?;

        return Ok(CreateConvoOutput {
            convo: ConvoView {
                conversation_id: convo_id.clone().into(),
                group_id: convo_id.into(),
                creator: string_to_did(&creator_did),
                members: members_typed,
                epoch: existing_epoch as i64,
                cipher_suite: input.cipher_suite.as_ref().to_string().into(),
                created_at: chrono_to_datetime(now),
                last_message_at: None,
                confirmation_tag: None,
                reset_generation: Some(0),
                // ADR-010 D4 (rung 2): a convo created here is sequenced
                // locally; rows keep sequencer_ds = NULL, the view
                // materializes the local DS DID.
                sequencer_did: crate::identity::service_did_base_opt()
                    .and_then(|d| crate::sqlx_jacquard::try_string_to_did(&d).ok()),
                extra_data: Default::default(),
            },
            invite_code: None,
            sequencer_ds: None,
            extra_data: Default::default(),
        });
    }

    // ── Create conversation + seed crypto_session ────────────────────────
    //
    // bug_003 (ultrareview): the chokepoint and the read paths assume a
    // crypto_sessions row exists for every conversation. The migration
    // backfills one per existing convo, but createConvo wasn't seeding
    // for new ones — every post-Phase-2 createConvo would land a
    // conversation with `active_crypto_session_id IS NULL` and the
    // chokepoint's read_current_session_for_update would return None,
    // so resetGroup 500'd and bootstrapResetGroup 404'd on every new
    // convo.
    //
    // Fix: wrap the conversations INSERT, crypto_sessions INSERT,
    // active_crypto_session_id UPDATE, and crypto_session_created
    // delivery_event APPEND in a single tx. Match the migration
    // backfill shape: state='active', generation=0, mls_group_id=
    // convo_id (createConvo's group_id is the same as the convo id). Epoch is
    // 1 only when Welcome material was supplied for an initial add commit;
    // creator-only groups start at epoch 0 so their first real commit is not
    // rejected as stale.
    tracing::debug!("📍 [v2.createConvo] creating conversation in database");

    let mut tx = pool.begin().await.map_err(|e| {
        error!("❌ [v2.createConvo] Failed to begin tx: {}", e);
        StatusCode::INTERNAL_SERVER_ERROR.into_response()
    })?;

    sqlx::query(
        "INSERT INTO conversations (
            id, creator_did, current_epoch, created_at, updated_at,
            cipher_suite, sequencer_ds, is_remote, group_id,
            group_info, group_info_epoch, group_info_updated_at,
            bootstrap_completed_at
         )
         VALUES ($1, $2, $5, $3, $3, $4, NULL, false, $1, $6, $7, $8, $8)",
    )
    .bind(&convo_id)
    .bind(&auth_user.did)
    .bind(now)
    .bind(input.cipher_suite.as_ref())
    .bind(bootstrap_epoch)
    .bind(initial_group_info.as_deref())
    .bind(initial_group_info_epoch)
    .bind(initial_group_info_updated_at)
    .execute(&mut *tx)
    .await
    .map_err(|e| {
        error!("❌ [v2.createConvo] Failed to create conversation: {}", e);
        StatusCode::INTERNAL_SERVER_ERROR.into_response()
    })?;

    // crypto_sessions seed: generation=0 active session for this convo.
    let crypto_session_id: String = sqlx::query_scalar(
        "INSERT INTO crypto_sessions ( \
            id, conversation_id, generation, mls_group_id, state, \
            cipher_suite, last_observed_epoch, created_by_did, \
            created_at, activated_at, group_info, group_info_epoch, \
            group_info_updated_at \
         ) VALUES (gen_random_uuid()::TEXT, $1, 0, $1, 'active', \
                   $2, $5, $3, $4, $4, $6, $7, $8) \
         RETURNING id",
    )
    .bind(&convo_id)
    .bind(input.cipher_suite.as_ref())
    .bind(&auth_user.did)
    .bind(now)
    .bind(bootstrap_epoch)
    .bind(initial_group_info.as_deref())
    .bind(initial_group_info_epoch)
    .bind(initial_group_info_updated_at)
    .fetch_one(&mut *tx)
    .await
    .map_err(|e| {
        error!("❌ [v2.createConvo] Failed to seed crypto_session: {}", e);
        StatusCode::INTERNAL_SERVER_ERROR.into_response()
    })?;

    sqlx::query("UPDATE conversations SET active_crypto_session_id = $1 WHERE id = $2")
        .bind(&crypto_session_id)
        .bind(&convo_id)
        .execute(&mut *tx)
        .await
        .map_err(|e| {
            error!(
                "❌ [v2.createConvo] Failed to set active_crypto_session_id: {}",
                e
            );
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        })?;

    // crypto_session_created delivery event at seq=0 (matches the migration
    // backfill's per-conversation seed event). idempotency_key keeps
    // re-runs of createConvo safe in case the lexicon-level idempotency
    // ever permits it.
    sqlx::query(
        "INSERT INTO delivery_events ( \
            id, conversation_id, seq, crypto_session_id, event_type, \
            mls_group_id, mls_epoch, idempotency_key, created_at \
         ) VALUES (gen_random_uuid()::TEXT, $1, 0, $2, \
                   'crypto_session_created', $1, $5, $3, $4)",
    )
    .bind(&convo_id)
    .bind(&crypto_session_id)
    .bind(format!("create:{}", convo_id))
    .bind(now)
    .bind(bootstrap_epoch)
    .execute(&mut *tx)
    .await
    .map_err(|e| {
        error!(
            "❌ [v2.createConvo] Failed to seed crypto_session_created event: {}",
            e
        );
        StatusCode::INTERNAL_SERVER_ERROR.into_response()
    })?;

    // ── Add creator as admin member + initial members ──────────────────
    // Per-device when kp_hashes provided; user-flat fallback otherwise.
    // The kp_hashes path resolves device_id from key_packages and inserts
    // member_did = "{user_did}#{device_id}" (Task 7 helper) so SSE/push
    // fan-out can target individual devices instead of flooding every
    // active session for a user. Mirrors Task 7's addMembers refactor
    // (commit 110fcce) and Task 4's per-device welcome shape (commit
    // 2b95378). See
    // docs/superpowers/plans/2026-05-04-mls-per-device-welcome-and-members-routing.md.
    //
    // Behavior delta vs the prior two auto-commit inserts (admin at
    // ~488, members loop at ~528): when kp_hashes is Some(non-empty) but
    // does not include an entry for some member_did, that member no
    // longer receives a user-flat row. Authorized by the plan ("you may
    // consolidate to a single per-device path with fallback") — the
    // omitted row is dead storage anyway since the MLS Welcome cannot
    // decrypt for a recipient whose key package wasn't included by the
    // creator. Fallback path (kp_hashes None/empty) preserves legacy
    // every-member behavior unchanged.
    //
    // Keep conversation seed, memberships, and any Welcome rows in the same
    // transaction. A successful createConvo must never publish a membership
    // without the corresponding per-device Welcome being durable.

    let used_per_device_members_path = match input.key_package_hashes.as_ref() {
        Some(hashes) if !hashes.is_empty() => {
            // Convert from create_convo::KeyPackageHashEntry to
            // bootstrap_reset_group::KeyPackageHashEntry (helper's accepted type).
            // jacquard generates nominally distinct types per lexicon module even
            // though their fields are identical — see Task 3 (commit a60b8af).
            let converted: Vec<crate::generated::blue_catbird::mlsChat::bootstrap_reset_group::KeyPackageHashEntry> = hashes
                .iter()
                .map(|e| crate::generated::blue_catbird::mlsChat::bootstrap_reset_group::KeyPackageHashEntry {
                    did: e.did.clone(),
                    hash: e.hash.clone(),
                    extra_data: Default::default(),
                })
                .collect();

            // Partition kp_hashes into admin (creator's devices) and non-admin
            // (everyone else's devices). The lexicon `Did<'_>` regex rejects
            // '#', so `did_to_string(&e.did)` is always user-form. By contrast,
            // `auth_user.did` may be device-form (e.g. "did:plc:alice#deviceA")
            // for some callers — Task 1's verification was INDIRECT for the
            // iOS issuance path. Comparing user-form to a raw device-form
            // string would always be false, mis-classifying every creator
            // device as a non-admin member.
            //
            // Defensive fix: derive the user-form half of `auth_user.did`
            // first (split at '#' if present, else use the string verbatim)
            // and partition against that. No-op when `auth_user.did` is
            // already user-form; correct partitioning when it's device-form.
            let caller_user_form: String = match auth_user.did.split_once('#') {
                Some((user, _device)) => user.to_string(),
                None => auth_user.did.clone(),
            };
            let (admin_entries, member_entries): (Vec<_>, Vec<_>) = converted
                .into_iter()
                .partition(|e| did_to_string(&e.did) == caller_user_form);

            // Admin: one row per creator device when kp_hashes covers any of them.
            // Fallback to legacy single-row admin insert when the creator omitted
            // their own kp from kp_hashes (some clients only include invitee kps).
            if !admin_entries.is_empty() {
                let admin_count = admin_entries.len();
                crate::db::insert_members_per_device_in_tx(
                    &mut tx,
                    &convo_id,
                    &admin_entries,
                    now,
                    true,
                )
                .await
                .map_err(|e| {
                    error!(
                        "❌ [v2.createConvo] failed to insert per-device admin: {}",
                        e
                    );
                    StatusCode::INTERNAL_SERVER_ERROR.into_response()
                })?;
                info!(
                    "createConvo: inserted {} per-device admin rows for convo {}",
                    admin_count,
                    crate::crypto::redact_for_log(&convo_id)
                );
            } else {
                // No admin kp in kp_hashes — preserve legacy single-row admin so
                // the creator stays a member of the conversation regardless.
                //
                // Defensive against device-form vs user-form ambiguity in
                // `auth_user.did`: bind `member_did = auth_user.did` (preserving
                // device-form when present so per-device fan-out can address it)
                // but use `caller_user_form` for the `user_did` column, which
                // canonically holds the user-form DID. ON CONFLICT clause
                // makes this idempotent in case the per-device helper above
                // also wrote a row keyed by the same `(convo_id, member_did)`.
                sqlx::query(
                    "INSERT INTO members (convo_id, member_did, user_did, joined_at, is_admin) \
                     VALUES ($1, $2, $3, $4, true) \
                     ON CONFLICT (convo_id, member_did) DO UPDATE SET \
                       is_admin = true, \
                       left_at = NULL, \
                       needs_rejoin = false",
                )
                .bind(&convo_id)
                .bind(&auth_user.did)
                .bind(&caller_user_form)
                .bind(now)
                .execute(&mut *tx)
                .await
                .map_err(|e| {
                    error!(
                        "❌ [v2.createConvo] Failed to add creator membership (legacy fallback): {}",
                        e
                    );
                    StatusCode::INTERNAL_SERVER_ERROR.into_response()
                })?;
                info!(
                    "createConvo: kp_hashes had no entry for creator — wrote single user-flat admin row for convo {}",
                    crate::crypto::redact_for_log(&convo_id)
                );
            }

            // Non-admin members: one row per device.
            if !member_entries.is_empty() {
                let member_count = member_entries.len();
                crate::db::insert_members_per_device_in_tx(
                    &mut tx,
                    &convo_id,
                    &member_entries,
                    now,
                    false,
                )
                .await
                .map_err(|e| {
                    error!(
                        "❌ [v2.createConvo] failed to insert per-device members: {}",
                        e
                    );
                    StatusCode::INTERNAL_SERVER_ERROR.into_response()
                })?;
                info!(
                    "createConvo: inserted {} per-device member rows for convo {}",
                    member_count,
                    crate::crypto::redact_for_log(&convo_id)
                );
            }
            true
        }
        _ => false,
    };

    if !used_per_device_members_path {
        // Legacy user-flat fallback — kp_hashes was None or empty.
        warn!(
            "createConvo: key_package_hashes absent/empty — falling back to user-flat members storage for convo {}",
            crate::crypto::redact_for_log(&convo_id)
        );
        tracing::debug!("📍 [v2.createConvo] adding creator membership (legacy)");

        // Defensive against device-form vs user-form ambiguity in
        // `auth_user.did` (mirrors the same fix in the per-device admin
        // fallback above): bind `member_did = auth_user.did` verbatim but
        // use the parsed user-form for the `user_did` column. ON CONFLICT
        // makes the INSERT idempotent so a retry or a sibling per-device
        // helper insert keyed on the same (convo_id, member_did) can't
        // collide.
        let caller_user_form: String = match auth_user.did.split_once('#') {
            Some((user, _device)) => user.to_string(),
            None => auth_user.did.clone(),
        };
        sqlx::query(
            "INSERT INTO members (convo_id, member_did, user_did, joined_at, is_admin) \
             VALUES ($1, $2, $3, $4, true) \
             ON CONFLICT (convo_id, member_did) DO UPDATE SET \
               is_admin = true, \
               left_at = NULL, \
               needs_rejoin = false",
        )
        .bind(&convo_id)
        .bind(&auth_user.did)
        .bind(&caller_user_form)
        .bind(now)
        .execute(&mut *tx)
        .await
        .map_err(|e| {
            error!(
                "❌ [v2.createConvo] Failed to add creator membership: {}",
                e
            );
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        })?;

        if let Some(ref initial_members) = input.initial_members {
            tracing::debug!("📍 [v2.createConvo] adding initial members (legacy)");
            for (idx, member_did) in initial_members.iter().enumerate() {
                let member_did_str = did_to_string(member_did);

                if member_did_str == auth_user.did {
                    continue;
                }

                info!("📍 [v2.createConvo] Adding member {} (legacy)", idx + 1);
                sqlx::query(
                    "INSERT INTO members (convo_id, member_did, user_did, joined_at, is_admin) VALUES ($1, $2, $3, $4, false)",
                )
                .bind(&convo_id)
                .bind(&member_did_str)
                .bind(&member_did_str)
                .bind(now)
                .execute(&mut *tx)
                .await
                .map_err(|e| {
                    error!("❌ [v2.createConvo] Failed to add member: {}", e);
                    StatusCode::INTERNAL_SERVER_ERROR.into_response()
                })?;
            }
        }
    }

    // Build MemberView list for the response unchanged (per-device storage is
    // a server-side roster representation; the lexicon-level MemberView still
    // models user-flat semantics with leaf_index ordering for now).
    let mut members_typed: Vec<MemberView<'static>> = vec![MemberView {
        did: string_to_did(&creator_did),
        user_did: string_to_did(&creator_did),
        joined_at: chrono_to_datetime(now),
        is_admin: true,
        is_moderator: Some(false),
        leaf_index: Some(0),
        device_id: None,
        device_name: None,
        credential: None,
        promoted_at: None,
        promoted_by: None,
        extra_data: Default::default(),
    }];

    if let Some(ref initial_members) = input.initial_members {
        for (idx, member_did) in initial_members.iter().enumerate() {
            let member_did_str = did_to_string(member_did);

            if member_did_str == auth_user.did {
                continue;
            }

            members_typed.push(MemberView {
                did: string_to_did(&member_did_str),
                user_did: string_to_did(&member_did_str),
                joined_at: chrono_to_datetime(now),
                is_admin: false,
                is_moderator: Some(false),
                leaf_index: Some((idx + 1) as i64),
                device_id: None,
                device_name: None,
                credential: None,
                promoted_at: None,
                promoted_by: None,
                extra_data: Default::default(),
            });
        }
    }

    // ── Store Welcome message ────────────────────────────────────────────
    if let Some(ref welcome_bytes) = input.welcome_message {
        info!("📍 [v2.createConvo] Processing Welcome message...");

        // Jacquard generates `welcome_message: Option<bytes::Bytes>` from the
        // lexicon `bytes` type — already raw bytes. The earlier handler
        // base64-decoded these (legacy from when ATProto bytes were
        // wire-encoded as base64 strings), which made every createConvo
        // request 400 with "Invalid base64 welcome: 6-bit remainder" once
        // Jacquard switched to raw bytes via the `$bytes` JSON envelope.
        // Mirror what `bootstrap_reset_group.rs:192` does.
        let welcome_data: Vec<u8> = welcome_bytes.to_vec();

        info!(
            "📨 [v2.createConvo] Welcome message for convo {}: {} bytes",
            input.group_id,
            welcome_data.len()
        );

        // Validate key package hashes exist (key packages are already consumed
        // at getKeyPackages time, so we only check existence, not availability)
        if let Some(ref kp_hashes) = input.key_package_hashes {
            info!(
                "📍 [v2.createConvo] Validating {} key package hashes...",
                kp_hashes.len()
            );
            for entry in kp_hashes {
                let member_did_str = did_to_string(&entry.did);
                let hash_hex: &str = &entry.hash;

                let exists: bool = sqlx::query_scalar(
                    r#"SELECT EXISTS(
                        SELECT 1 FROM key_packages
                        WHERE owner_did = $1
                          AND key_package_hash = $2
                    )"#,
                )
                .bind(&member_did_str)
                .bind(hash_hex)
                .fetch_one(&pool)
                .await
                .map_err(|e| {
                    error!("❌ [v2.createConvo] key package check: {}", e);
                    StatusCode::INTERNAL_SERVER_ERROR.into_response()
                })?;

                if !exists {
                    warn!(
                        "❌ [v2.createConvo] Key package hash not found for {}",
                        crate::crypto::redact_for_log(&member_did_str),
                    );
                    return Err((
                        StatusCode::BAD_REQUEST,
                        Json(LexCreateConvoError::KeyPackageNotFound(Some(
                            format!(
                                "Key package hash not found for {}: hash={}",
                                member_did_str, hash_hex
                            )
                            .into(),
                        ))),
                    )
                        .into_response());
                }
            }
            info!(
                "✅ [v2.createConvo] All {} key package hashes validated",
                kp_hashes.len()
            );
        }

        // Collect all member DIDs (creator + initial_members)
        let mut all_member_dids = vec![auth_user.did.clone()];
        if let Some(ref member_list) = input.initial_members {
            for member_did in member_list.iter() {
                let member_did_str = did_to_string(member_did);
                if member_did_str != auth_user.did {
                    all_member_dids.push(member_did_str);
                }
            }
        }

        info!(
            "📍 [v2.createConvo] Storing Welcome for {} total members",
            all_member_dids.len()
        );

        // ── Store welcome (per-device when kp_hashes provided; user-flat fallback otherwise) ──
        // Mirrors Task 4's addMembers shape (commit 1284301): top-level conditional, single
        // path through the per-device helper when kp_hashes are present, legacy user-flat path
        // otherwise. The MLS welcome_bytes is itself a multi-recipient blob — each device
        // decrypts only its own EncryptedGroupSecrets entry — so storing identical welcome_data
        // across N rows is correct. The helper persists recipient_device_id when resolvable,
        // while key_package_hash remains the hash discriminator/fallback/audit value. See
        // docs/superpowers/plans/2026-05-04-mls-per-device-welcome-and-members-routing.md.
        //
        // Behavior delta vs the prior per-member loop: when kp_hashes is Some(non-empty) but
        // does not include an entry for some `member_did`, that member no longer receives a
        // user-flat fallback row. This is intentional and authorized by the plan ("you may
        // consolidate to a single per-device path with fallback"): a member whose key package
        // wasn't included in the inviter's Welcome cannot decrypt it anyway, so the omitted
        // row was dead storage. The fallback path (kp_hashes None/empty) preserves the legacy
        // every-member behavior unchanged.
        //
        let kp_hashes_for_welcomes = input.key_package_hashes.as_ref();
        let used_per_device_path = match kp_hashes_for_welcomes {
            Some(hashes) if !hashes.is_empty() => {
                // Convert from create_convo::KeyPackageHashEntry to
                // bootstrap_reset_group::KeyPackageHashEntry (helper's accepted type).
                // jacquard generates nominally distinct types per lexicon module even
                // though their fields are identical — see Task 3 (commit a60b8af) for
                // context. The conversion is a mechanical field copy.
                let converted: Vec<crate::generated::blue_catbird::mlsChat::bootstrap_reset_group::KeyPackageHashEntry> = hashes
                    .iter()
                    .map(|e| crate::generated::blue_catbird::mlsChat::bootstrap_reset_group::KeyPackageHashEntry {
                        did: e.did.clone(),
                        hash: e.hash.clone(),
                        extra_data: Default::default(),
                    })
                    .collect();
                let count = converted.len();
                crate::db::store_welcomes_per_device_in_tx(
                    &mut tx,
                    &convo_id,
                    &welcome_data,
                    &converted,
                    &auth_user.did,
                )
                .await
                .map_err(|e| {
                    error!(
                        "❌ [v2.createConvo] failed to store per-device welcomes: {}",
                        e
                    );
                    StatusCode::INTERNAL_SERVER_ERROR.into_response()
                })?;
                info!(
                    "createConvo: stored {} per-device welcome rows for convo {}",
                    count,
                    crate::crypto::redact_for_log(&convo_id)
                );
                true
            }
            _ => false,
        };

        // Legacy user-flat fallback: only runs when kp_hashes was None or empty.
        if !used_per_device_path {
            warn!(
                "createConvo: key_package_hashes absent/empty — falling back to user-flat welcome storage for convo {}",
                crate::crypto::redact_for_log(&convo_id)
            );
            for member_did_str in all_member_dids.iter() {
                let welcome_id = uuid::Uuid::new_v4().to_string();
                sqlx::query(
                    "INSERT INTO welcome_messages (id, convo_id, recipient_did, welcome_data, key_package_hash, created_at)
                     VALUES ($1, $2, $3, $4, $5, $6)
                     ON CONFLICT (convo_id, recipient_did, COALESCE(key_package_hash, '\\x00'::bytea)) WHERE consumed = false
                     DO NOTHING",
                )
                .bind(&welcome_id)
                .bind(&convo_id)
                .bind(member_did_str)
                .bind(&welcome_data)
                .bind::<Option<Vec<u8>>>(None)
                .bind(now)
                .execute(&mut *tx)
                .await
                .map_err(|e| {
                    error!("❌ [v2.createConvo] store user-flat welcome for {}: {}", crate::crypto::redact_for_log(member_did_str), e);
                    StatusCode::INTERNAL_SERVER_ERROR.into_response()
                })?;
            }
        }
    }

    maybe_abort_create_convo_after_welcome_for_test()?;

    tx.commit().await.map_err(|e| {
        error!(
            "❌ [v2.createConvo] Failed to commit atomic createConvo tx: {}",
            e
        );
        StatusCode::INTERNAL_SERVER_ERROR.into_response()
    })?;

    if let Some(expectation) = welcome_row_expectation {
        let stored_rows: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM welcome_messages WHERE convo_id = $1 AND consumed = false",
        )
        .bind(&convo_id)
        .fetch_one(&pool)
        .await
        .unwrap_or(-1);
        let matched_expected = stored_rows >= 0 && stored_rows == expectation.expected_rows as i64;
        if matched_expected {
            info!(
                convo_id = %crate::crypto::redact_for_log(&convo_id),
                expected_welcome_rows = expectation.expected_rows,
                stored_welcome_rows = stored_rows,
                used_per_device_path = expectation.used_per_device_path,
                matched_expected,
                "createConvo: Welcome rows durable after commit"
            );
        } else {
            warn!(
                convo_id = %crate::crypto::redact_for_log(&convo_id),
                expected_welcome_rows = expectation.expected_rows,
                stored_welcome_rows = stored_rows,
                used_per_device_path = expectation.used_per_device_path,
                matched_expected,
                has_welcome_message = input.welcome_message.is_some(),
                has_group_info = input.group_info.is_some(),
                key_package_hash_count = input.key_package_hashes.as_ref().map_or(0, Vec::len),
                auth_lxm = ?auth_user.claims.lxm,
                auth_jti_present = auth_user.claims.jti.is_some(),
                "createConvo: Welcome row count mismatch after commit"
            );
        }
    }

    // Commit reserved key packages after the atomic create succeeds.
    // getKeyPackages reserves packages at fetch time; successful create is the
    // first server-side point where those packages are durably bound to Welcomes.
    if let Some(ref kp_hashes) = input.key_package_hashes {
        for entry in kp_hashes {
            let member_did_str = did_to_string(&entry.did);
            let hash_hex: &str = &entry.hash;

            match crate::db::mark_key_package_consumed(&pool, &member_did_str, hash_hex).await {
                Ok(consumed) => {
                    if consumed {
                        tracing::debug!(
                            "✅ [v2.createConvo] key package consumed for {}",
                            crate::crypto::redact_for_log(&member_did_str)
                        );
                    } else {
                        tracing::warn!(
                            "⚠️ [v2.createConvo] key package not found/already consumed for {}",
                            crate::crypto::redact_for_log(&member_did_str)
                        );
                    }
                }
                Err(e) => {
                    tracing::warn!("⚠️ [v2.createConvo] mark key package consumed: {}", e);
                }
            }
        }
    }

    info!(
        convo = %crate::crypto::redact_for_log(&convo_id),
        member_count = members_typed.len(),
        epoch = bootstrap_epoch,
        "✅ [v2.createConvo] complete"
    );

    // ── Build response ───────────────────────────────────────────────────
    Ok(CreateConvoOutput {
        convo: ConvoView {
            conversation_id: convo_id.clone().into(),
            group_id: convo_id.into(),
            creator: string_to_did(&creator_did),
            members: members_typed,
            epoch: bootstrap_epoch as i64,
            cipher_suite: input.cipher_suite.as_ref().to_string().into(),
            created_at: chrono_to_datetime(now),
            last_message_at: None,
            confirmation_tag: None,
            reset_generation: Some(0),
            // ADR-010 D4 (rung 2): a convo created here is sequenced
            // locally; rows keep sequencer_ds = NULL, the view materializes
            // the local DS DID.
            sequencer_did: crate::identity::service_did_base_opt()
                .and_then(|d| crate::sqlx_jacquard::try_string_to_did(&d).ok()),
            extra_data: Default::default(),
        },
        invite_code: None,
        sequencer_ds: None,
        extra_data: Default::default(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::Bytes;
    use jacquard_axum::ExtractXrpc;
    use sqlx::Row;
    use std::{sync::Arc, time::Duration};

    use crate::{
        auth::{AtProtoClaims, AuthUser},
        block_sync::BlockSyncService,
        db::{init_db, DbConfig},
    };

    #[test]
    fn bootstrap_epoch_is_zero_without_welcome() {
        assert_eq!(bootstrap_epoch_for_create(false), 0);
    }

    #[test]
    fn bootstrap_epoch_is_one_with_welcome() {
        assert_eq!(bootstrap_epoch_for_create(true), 1);
    }

    #[test]
    fn initial_non_creator_members_require_welcome() {
        let members = vec![string_to_did("did:plc:bob")];

        let err = validate_initial_members_have_welcome(Some(&members), "did:plc:alice", false)
            .expect_err("non-creator initial members without Welcome must fail");

        assert!(err.contains("welcomeMessage"));
    }

    #[test]
    fn creator_only_initial_members_do_not_require_welcome() {
        let members = vec![string_to_did("did:plc:alice")];

        validate_initial_members_have_welcome(Some(&members), "did:plc:alice", false)
            .expect("creator-only initial members are a no-op");
    }

    #[test]
    fn welcome_bootstrap_requires_group_info() {
        let err = validate_initial_group_info(true, None)
            .expect_err("Welcome bootstrap without GroupInfo must fail");

        assert!(err.contains("groupInfo"));
    }

    #[test]
    fn group_info_must_be_large_enough() {
        let tiny_group_info = bytes::Bytes::from_static(b"too-small");

        let err = validate_initial_group_info(true, Some(&tiny_group_info))
            .expect_err("tiny GroupInfo must fail validation");

        assert!(err.contains("too small"));
    }

    #[test]
    fn valid_group_info_is_preserved_verbatim() {
        let group_info = bytes::Bytes::from(vec![0xAB; crate::group_info::MIN_GROUP_INFO_SIZE]);

        let validated = validate_initial_group_info(true, Some(&group_info))
            .expect("valid GroupInfo must be accepted");

        assert_eq!(validated.as_deref(), Some(group_info.as_ref()));
    }

    #[test]
    fn expected_welcome_rows_prefers_per_device_hash_count() {
        let expected = expected_welcome_rows_for_create(2, 5);

        assert_eq!(expected.expected_rows, 2);
        assert!(expected.used_per_device_path);
    }

    #[test]
    fn expected_welcome_rows_falls_back_to_member_count_without_hashes() {
        let expected = expected_welcome_rows_for_create(0, 4);

        assert_eq!(expected.expected_rows, 4);
        assert!(!expected.used_per_device_path);
    }

    async fn setup_test_db() -> DbPool {
        init_db(DbConfig {
            database_url: std::env::var("TEST_DATABASE_URL")
                .unwrap_or_else(|_| "postgres://localhost/catbird_test".to_string()),
            max_connections: 4,
            min_connections: 1,
            acquire_timeout: Duration::from_secs(30),
            idle_timeout: Duration::from_secs(600),
        })
        .await
        .expect("initialize test database")
    }

    async fn cleanup_test_actor_data(pool: &DbPool, convo_id: &str, owner_did: &str) {
        let _ = sqlx::query("DELETE FROM key_packages WHERE owner_did = $1")
            .bind(owner_did)
            .execute(pool)
            .await;
        let _ = sqlx::query("DELETE FROM users WHERE did = $1")
            .bind(owner_did)
            .execute(pool)
            .await;
        let _ = sqlx::query("DELETE FROM conversations WHERE id = $1")
            .bind(convo_id)
            .execute(pool)
            .await;
    }

    async fn seed_key_package(pool: &DbPool, owner_did: &str, device_id: &str, hash_hex: &str) {
        sqlx::query(
            "INSERT INTO key_packages \
                (id, owner_did, device_id, cipher_suite, key_package, key_package_hash, created_at, expires_at, state) \
             VALUES ($1, $2, $3, $4, $5, $6, NOW(), NOW() + INTERVAL '30 days', 'available')",
        )
        .bind(uuid::Uuid::new_v4().to_string())
        .bind(owner_did)
        .bind(device_id)
        .bind("MLS_256_XWING_CHACHA20POLY1305_SHA256_Ed25519")
        .bind::<&[u8]>(&[0xA5])
        .bind(hash_hex)
        .execute(pool)
        .await
        .expect("seed key package");
    }

    #[tokio::test]
    #[ignore = "requires live Postgres (TEST_DATABASE_URL)"]
    async fn create_convo_rollback_clears_conversation_members_and_welcomes() {
        let pool = setup_test_db().await;
        let suffix = uuid::Uuid::new_v4().simple().to_string();
        let owner_did = format!("did:plc:createatomic{}", &suffix[..10]);
        let convo_id = format!("convo-create-atomic-{suffix}");
        let hash_a = "2d83a9f4d9d3f0dfe3fdce4e31d7836ed8b58f4f4f49f7eec46fd882ba8d2222".to_string();
        let hash_b = "7b6abf7ac8c65d1234567890abcdefabcdef1234567890abcdef1234567890".to_string();

        cleanup_test_actor_data(&pool, &convo_id, &owner_did).await;
        sqlx::query("INSERT INTO users (did) VALUES ($1) ON CONFLICT DO NOTHING")
            .bind(&owner_did)
            .execute(&pool)
            .await
            .expect("seed user");
        seed_key_package(&pool, &owner_did, "device-a", &hash_a).await;
        seed_key_package(&pool, &owner_did, "device-b", &hash_b).await;

        let auth_user = AuthUser {
            did: owner_did.clone(),
            claims: AtProtoClaims {
                iss: owner_did.clone(),
                aud: "did:web:mls.example.test".to_string(),
                exp: Utc::now().timestamp() + 300,
                iat: Some(Utc::now().timestamp()),
                sub: Some(owner_did.clone()),
                lxm: Some(NSID.to_string()),
                jti: Some(format!("jti-{suffix}")),
            },
        };
        let input = crate::generated::blue_catbird::mlsChat::create_convo::CreateConvo {
            cipher_suite: "MLS_256_XWING_CHACHA20POLY1305_SHA256_Ed25519".into(),
            current_epoch: Some(1),
            group_id: convo_id.clone().into(),
            group_info: Some(Bytes::from(vec![
                0xAB;
                crate::group_info::MIN_GROUP_INFO_SIZE
            ])),
            key_package_hashes: Some(vec![
                crate::generated::blue_catbird::mlsChat::create_convo::KeyPackageHashEntry {
                    did: string_to_did(&owner_did),
                    hash: hash_a.clone().into(),
                    extra_data: Default::default(),
                },
                crate::generated::blue_catbird::mlsChat::create_convo::KeyPackageHashEntry {
                    did: string_to_did(&owner_did),
                    hash: hash_b.clone().into(),
                    extra_data: Default::default(),
                },
            ]),
            welcome_message: Some(Bytes::from_static(b"welcome-envelope")),
            ..Default::default()
        };

        let _rollback_guard = enable_create_convo_abort_after_welcome_for_test();
        let response = create_convo(
            State(pool.clone()),
            State(Arc::new(BlockSyncService::new())),
            auth_user,
            ExtractXrpc(input),
        )
        .await;

        assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);

        let conversation_count: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM conversations WHERE id = $1")
                .bind(&convo_id)
                .fetch_one(&pool)
                .await
                .expect("count conversations");
        let member_count: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM members WHERE convo_id = $1")
                .bind(&convo_id)
                .fetch_one(&pool)
                .await
                .expect("count members");
        let welcome_count: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM welcome_messages WHERE convo_id = $1")
                .bind(&convo_id)
                .fetch_one(&pool)
                .await
                .expect("count welcomes");

        assert_eq!(
            conversation_count, 0,
            "rollback must clear the conversation row"
        );
        assert_eq!(member_count, 0, "rollback must clear staged member rows");
        assert_eq!(welcome_count, 0, "rollback must clear staged Welcome rows");

        cleanup_test_actor_data(&pool, &convo_id, &owner_did).await;
    }

    #[tokio::test]
    #[ignore = "requires live Postgres (TEST_DATABASE_URL)"]
    async fn create_convo_preserves_unconsumed_welcome_rows_with_per_device_members() {
        let pool = setup_test_db().await;
        let suffix = uuid::Uuid::new_v4().simple().to_string();
        let owner_did = format!("did:plc:createwelcome{}", &suffix[..10]);
        let convo_id = format!("convo-create-welcome-{suffix}");
        let hash_a = "4d83a9f4d9d3f0dfe3fdce4e31d7836ed8b58f4f4f49f7eec46fd882ba8d1111".to_string();
        let hash_b = "8b6abf7ac8c65d1234567890abcdefabcdef1234567890abcdef1234567890".to_string();

        cleanup_test_actor_data(&pool, &convo_id, &owner_did).await;
        sqlx::query("INSERT INTO users (did) VALUES ($1) ON CONFLICT DO NOTHING")
            .bind(&owner_did)
            .execute(&pool)
            .await
            .expect("seed user");
        seed_key_package(&pool, &owner_did, "device-a", &hash_a).await;
        seed_key_package(&pool, &owner_did, "device-b", &hash_b).await;

        let auth_user = AuthUser {
            did: owner_did.clone(),
            claims: AtProtoClaims {
                iss: owner_did.clone(),
                aud: "did:web:mls.example.test".to_string(),
                exp: Utc::now().timestamp() + 300,
                iat: Some(Utc::now().timestamp()),
                sub: Some(owner_did.clone()),
                lxm: None,
                jti: Some(format!("jti-{suffix}")),
            },
        };
        let input = crate::generated::blue_catbird::mlsChat::create_convo::CreateConvo {
            cipher_suite: "MLS_256_XWING_CHACHA20POLY1305_SHA256_Ed25519".into(),
            current_epoch: Some(1),
            group_id: convo_id.clone().into(),
            group_info: Some(Bytes::from(vec![
                0xAB;
                crate::group_info::MIN_GROUP_INFO_SIZE
            ])),
            key_package_hashes: Some(vec![
                crate::generated::blue_catbird::mlsChat::create_convo::KeyPackageHashEntry {
                    did: string_to_did(&owner_did),
                    hash: hash_a.clone().into(),
                    extra_data: Default::default(),
                },
                crate::generated::blue_catbird::mlsChat::create_convo::KeyPackageHashEntry {
                    did: string_to_did(&owner_did),
                    hash: hash_b.clone().into(),
                    extra_data: Default::default(),
                },
            ]),
            welcome_message: Some(Bytes::from_static(b"welcome-envelope")),
            ..Default::default()
        };

        let output = handle_create_convo(
            pool.clone(),
            Arc::new(BlockSyncService::new()),
            auth_user,
            &input,
        )
        .await
        .expect("createConvo succeeds");

        assert_eq!(output.convo.epoch, 1);

        let member_rows = sqlx::query(
            "SELECT member_did, user_did, device_id, is_admin \
             FROM members \
             WHERE convo_id = $1 AND left_at IS NULL \
             ORDER BY device_id",
        )
        .bind(&convo_id)
        .fetch_all(&pool)
        .await
        .expect("fetch members");
        assert_eq!(member_rows.len(), 2, "one active member row per device");
        assert_eq!(
            member_rows[0].get::<String, _>("member_did"),
            format!("{owner_did}#device-a")
        );
        assert_eq!(
            member_rows[1].get::<String, _>("member_did"),
            format!("{owner_did}#device-b")
        );
        assert!(
            member_rows.iter().all(|row| row.get::<bool, _>("is_admin")),
            "creator device rows must stay admin"
        );

        let welcome_rows = sqlx::query(
            "SELECT recipient_did, recipient_device_id, encode(key_package_hash, 'hex') AS hash_hex, consumed \
             FROM welcome_messages \
             WHERE convo_id = $1 \
             ORDER BY recipient_device_id",
        )
        .bind(&convo_id)
        .fetch_all(&pool)
        .await
        .expect("fetch welcome rows");
        assert_eq!(welcome_rows.len(), 2, "one pending Welcome per device");
        assert_eq!(welcome_rows[0].get::<String, _>("recipient_did"), owner_did);
        assert_eq!(
            welcome_rows[0].get::<Option<String>, _>("recipient_device_id"),
            Some("device-a".to_string())
        );
        assert_eq!(welcome_rows[0].get::<String, _>("hash_hex"), hash_a);
        assert!(
            !welcome_rows[0].get::<bool, _>("consumed"),
            "fresh Welcome rows must stay unconsumed"
        );
        assert_eq!(
            welcome_rows[1].get::<Option<String>, _>("recipient_device_id"),
            Some("device-b".to_string())
        );
        assert_eq!(welcome_rows[1].get::<String, _>("hash_hex"), hash_b);

        cleanup_test_actor_data(&pool, &convo_id, &owner_did).await;
    }
}
