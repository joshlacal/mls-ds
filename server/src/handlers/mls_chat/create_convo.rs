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
        ConvoMetadata, ConvoView, MemberView,
    },
    sqlx_jacquard::{chrono_to_datetime, did_to_string, string_to_did},
    storage::DbPool,
};

const NSID: &str = "blue.catbird.mlsChat.createConvo";

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

    // ── Conversation ID and metadata ─────────────────────────────────────
    let convo_id = input.group_id.to_string();
    let now = Utc::now();

    let (name, description) = if let Some(ref meta) = input.metadata {
        (
            meta.name.as_deref().map(String::from),
            meta.description.as_deref().map(String::from),
        )
    } else {
        (None, None)
    };

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

        let metadata = if name.is_some() || description.is_some() {
            Some(ConvoMetadata {
                name: name.map(|s| s.into()),
                description: description.map(|s| s.into()),
                extra_data: Default::default(),
            })
        } else {
            None
        };

        return Ok(CreateConvoOutput {
            convo: ConvoView {
                conversation_id: convo_id.clone().into(),
                group_id: convo_id.into(),
                creator: string_to_did(&creator_did),
                members: members_typed,
                epoch: 1,
                cipher_suite: input.cipher_suite.as_ref().to_string().into(),
                created_at: chrono_to_datetime(now),
                last_message_at: None,
                metadata,
                confirmation_tag: None,
                reset_generation: Some(0),
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
    // convo_id (createConvo's group_id is the same as the convo id),
    // last_observed_epoch=1 (matching conversations.current_epoch=1
    // which represents "group exists at MLS epoch 1 post-creation").
    tracing::debug!("📍 [v2.createConvo] creating conversation in database");

    let mut tx = pool.begin().await.map_err(|e| {
        error!("❌ [v2.createConvo] Failed to begin tx: {}", e);
        StatusCode::INTERNAL_SERVER_ERROR.into_response()
    })?;

    sqlx::query(
        "INSERT INTO conversations (id, creator_did, current_epoch, created_at, updated_at, name, cipher_suite, sequencer_ds, is_remote, group_id)
         VALUES ($1, $2, 1, $3, $3, $4, $5, NULL, false, $1)",
    )
    .bind(&convo_id)
    .bind(&auth_user.did)
    .bind(now)
    .bind(&name)
    .bind(input.cipher_suite.as_ref())
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
            created_at, activated_at \
         ) VALUES (gen_random_uuid()::TEXT, $1, 0, $1, 'active', \
                   $2, 1, $3, $4, $4) \
         RETURNING id",
    )
    .bind(&convo_id)
    .bind(input.cipher_suite.as_ref())
    .bind(&auth_user.did)
    .bind(&now)
    .fetch_one(&mut *tx)
    .await
    .map_err(|e| {
        error!("❌ [v2.createConvo] Failed to seed crypto_session: {}", e);
        StatusCode::INTERNAL_SERVER_ERROR.into_response()
    })?;

    sqlx::query(
        "UPDATE conversations SET active_crypto_session_id = $1 WHERE id = $2",
    )
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
                   'crypto_session_created', $1, 1, $3, $4)",
    )
    .bind(&convo_id)
    .bind(&crypto_session_id)
    .bind(format!("create:{}", convo_id))
    .bind(&now)
    .execute(&mut *tx)
    .await
    .map_err(|e| {
        error!(
            "❌ [v2.createConvo] Failed to seed crypto_session_created event: {}",
            e
        );
        StatusCode::INTERNAL_SERVER_ERROR.into_response()
    })?;

    tx.commit().await.map_err(|e| {
        error!("❌ [v2.createConvo] Failed to commit createConvo tx: {}", e);
        StatusCode::INTERNAL_SERVER_ERROR.into_response()
    })?;

    // ── Add creator as admin member ──────────────────────────────────────
    tracing::debug!("📍 [v2.createConvo] adding creator membership");
    sqlx::query(
        "INSERT INTO members (convo_id, member_did, user_did, joined_at, is_admin) VALUES ($1, $2, $3, $4, true)",
    )
    .bind(&convo_id)
    .bind(&auth_user.did)
    .bind(&auth_user.did)
    .bind(now)
    .execute(&pool)
    .await
    .map_err(|e| {
        error!("❌ [v2.createConvo] Failed to add creator membership: {}", e);
        StatusCode::INTERNAL_SERVER_ERROR.into_response()
    })?;

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

    // ── Add initial members ──────────────────────────────────────────────
    if let Some(ref initial_members) = input.initial_members {
        tracing::debug!("📍 [v2.createConvo] adding initial members");
        for (idx, member_did) in initial_members.iter().enumerate() {
            let member_did_str = did_to_string(member_did);

            if member_did_str == auth_user.did {
                continue;
            }

            info!("📍 [v2.createConvo] Adding member {}", idx + 1);
            sqlx::query(
                "INSERT INTO members (convo_id, member_did, user_did, joined_at, is_admin) VALUES ($1, $2, $3, $4, false)",
            )
            .bind(&convo_id)
            .bind(&member_did_str)
            .bind(&member_did_str)
            .bind(now)
            .execute(&pool)
            .await
            .map_err(|e| {
                error!("❌ [v2.createConvo] Failed to add member: {}", e);
                StatusCode::INTERNAL_SERVER_ERROR.into_response()
            })?;

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

        for member_did_str in all_member_dids.iter() {
            let member_hashes: Vec<Vec<u8>> = input
                .key_package_hashes
                .as_ref()
                .map(|hashes| {
                    hashes
                        .iter()
                        .filter(|entry| did_to_string(&entry.did) == *member_did_str)
                        .filter_map(|entry| hex::decode(&*entry.hash).ok())
                        .collect()
                })
                .unwrap_or_default();

            if member_hashes.is_empty() {
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
                .execute(&pool)
                .await
                .map_err(|e| {
                    error!("❌ [v2.createConvo] store welcome for {}: {}", crate::crypto::redact_for_log(member_did_str), e);
                    StatusCode::INTERNAL_SERVER_ERROR.into_response()
                })?;
            } else {
                for hash in member_hashes {
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
                    .bind(Some(hash))
                    .bind(now)
                    .execute(&pool)
                    .await
                    .map_err(|e| {
                        error!("❌ [v2.createConvo] store welcome for {}: {}", crate::crypto::redact_for_log(member_did_str), e);
                        StatusCode::INTERNAL_SERVER_ERROR.into_response()
                    })?;
                }
            }
        }

        // Mark key packages as consumed
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
    }

    info!(
        convo = %crate::crypto::redact_for_log(&convo_id),
        member_count = members_typed.len(),
        epoch = 1,
        "✅ [v2.createConvo] complete"
    );

    // ── Build response ───────────────────────────────────────────────────
    let metadata = if name.is_some() || description.is_some() {
        Some(ConvoMetadata {
            name: name.map(|s| s.into()),
            description: description.map(|s| s.into()),
            extra_data: Default::default(),
        })
    } else {
        None
    };

    Ok(CreateConvoOutput {
        convo: ConvoView {
            conversation_id: convo_id.clone().into(),
            group_id: convo_id.into(),
            creator: string_to_did(&creator_did),
            members: members_typed,
            epoch: 1,
            cipher_suite: input.cipher_suite.as_ref().to_string().into(),
            created_at: chrono_to_datetime(now),
            last_message_at: None,
            metadata,
            confirmation_tag: None,
            reset_generation: Some(0),
            extra_data: Default::default(),
        },
        invite_code: None,
        sequencer_ds: None,
        extra_data: Default::default(),
    })
}
