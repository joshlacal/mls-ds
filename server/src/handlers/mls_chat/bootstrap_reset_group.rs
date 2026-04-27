use axum::{
    extract::State,
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use chrono::{DateTime, Utc};
use jacquard_axum::ExtractXrpc;
use tracing::{error, info, warn};

use crate::{
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

/// Complete a post-auto-reset conversation in place.
///
/// POST /xrpc/blue.catbird.mlsChat.bootstrapResetGroup
///
/// After auto-reset (`actors::conversation::record_reset_vote` quorum path) or
/// admin reset without an inline `groupInfo`, the conversation row sits with
/// `id = originalConvoId`, `group_id = newGroupId`, `group_info = NULL`,
/// `current_epoch = 0`, and the member roster preserved. This endpoint
/// UPDATEs that row in place — it does NOT INSERT a new conversation
/// (createConvo would orphan the post-reset row by INSERTing at
/// `id = newGroupId`).
///
/// First member to call wins; later callers receive 409 AlreadyBootstrapped
/// and fall back to receiving the Welcome from the winner.
#[tracing::instrument(skip(pool, auth_user, input))]
pub async fn bootstrap_reset_group(
    State(pool): State<DbPool>,
    auth_user: AuthUser,
    ExtractXrpc(input): ExtractXrpc<BootstrapResetGroupRequest>,
) -> Response {
    if let Err(_e) = crate::auth::enforce_standard(&auth_user.claims, NSID) {
        error!("[bootstrapResetGroup] Unauthorized");
        return StatusCode::UNAUTHORIZED.into_response();
    }

    match handle(pool, auth_user, &input).await {
        Ok(output) => Json(output).into_response(),
        Err(resp) => resp,
    }
}

/// Inner handler. Exposed `pub` so integration tests in `tests/` can drive
/// it directly without scaffolding the Axum router + auth middleware.
pub async fn handle(
    pool: DbPool,
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

    // ── Begin transaction with row lock ──────────────────────────────────
    let mut tx = pool.begin().await.map_err(|e| {
        error!("[bootstrapResetGroup] begin tx: {}", e);
        StatusCode::INTERNAL_SERVER_ERROR.into_response()
    })?;

    // FOR UPDATE locks the row so concurrent bootstrap calls serialize on it.
    // Returns (group_info, current_epoch) — None if no row matches; if row
    // matches but group_info IS NOT NULL, the bootstrap already happened.
    // current_epoch is INT4 in the schema; decode as i32 (every other reader
    // — db.rs, models.rs, federation, mls_auth, actors — uses i32 too).
    let target_row: Option<(Option<Vec<u8>>, i32)> = sqlx::query_as(
        "SELECT group_info, current_epoch FROM conversations \
         WHERE id = $1 AND group_id = $2 \
         FOR UPDATE",
    )
    .bind(&original_convo_id)
    .bind(&new_group_id)
    .fetch_optional(&mut *tx)
    .await
    .map_err(|e| {
        error!("[bootstrapResetGroup] target row lookup: {}", e);
        StatusCode::INTERNAL_SERVER_ERROR.into_response()
    })?;

    let (existing_group_info, _current_epoch) = match target_row {
        Some(row) => row,
        None => {
            tx.rollback().await.ok();
            warn!(
                "[bootstrapResetGroup] target row not found (originalConvoId, newGroupId mismatch)"
            );
            info!(
                convo_id = %crate::crypto::redact_for_log(&original_convo_id),
                new_group_id = %crate::crypto::redact_for_log(&new_group_id),
                caller_did = %crate::crypto::redact_for_log(&caller_did),
                "bootstrap_404_not_found"
            );
            return Err((
                StatusCode::NOT_FOUND,
                Json(LexBootstrapResetGroupError::BootstrapTargetNotFound(Some(
                    "No conversation row matches (originalConvoId, newGroupId). The convo may not exist or the post-reset group_id may have been overwritten.".into(),
                ))),
            )
                .into_response());
        }
    };

    if existing_group_info.is_some() {
        tx.rollback().await.ok();
        warn!("[bootstrapResetGroup] race-loss: group_info already populated by another caller");
        info!(
            convo_id = %crate::crypto::redact_for_log(&original_convo_id),
            new_group_id = %crate::crypto::redact_for_log(&new_group_id),
            caller_did = %crate::crypto::redact_for_log(&caller_did),
            "bootstrap_409_already_bootstrapped"
        );
        return Err((
            StatusCode::CONFLICT,
            Json(LexBootstrapResetGroupError::AlreadyBootstrapped(Some(
                "The post-reset row has already been bootstrapped by another caller. Fall back to receiving the Welcome from the winner.".into(),
            ))),
        )
            .into_response());
    }

    // ── Decode groupInfo and welcome bytes (already raw via Jacquard) ────
    let group_info_bytes: Vec<u8> = input.group_info.to_vec();
    let welcome_bytes: Option<Vec<u8>> = input.welcome_message.as_ref().map(|b| b.to_vec());

    // ── UPDATE the conversation in place ─────────────────────────────────
    let now = Utc::now();
    let rows_affected = sqlx::query(
        "UPDATE conversations SET \
            group_info = $1, \
            group_info_epoch = 1, \
            group_info_updated_at = $2, \
            current_epoch = 1, \
            cipher_suite = $3, \
            confirmation_tag = NULL, \
            updated_at = $2 \
         WHERE id = $4 AND group_id = $5",
    )
    .bind(&group_info_bytes)
    .bind(&now)
    .bind(input.cipher_suite.as_ref())
    .bind(&original_convo_id)
    .bind(&new_group_id)
    .execute(&mut *tx)
    .await
    .map_err(|e| {
        error!("[bootstrapResetGroup] UPDATE conversations: {}", e);
        StatusCode::INTERNAL_SERVER_ERROR.into_response()
    })?
    .rows_affected();

    if rows_affected != 1 {
        tx.rollback().await.ok();
        error!(
            "[bootstrapResetGroup] UPDATE affected {} rows (expected 1)",
            rows_affected
        );
        return Err(StatusCode::INTERNAL_SERVER_ERROR.into_response());
    }

    // ── Insert welcome_messages (one per recipient_did from kp hashes) ───
    if let Some(welcome) = welcome_bytes.as_ref() {
        // Recipients: derived from keyPackageHashes if present, else from the
        // persisted member roster. The hashes include per-member key package
        // selection, so prefer that authoritative path.
        if let Some(ref kp_hashes) = input.key_package_hashes {
            for entry in kp_hashes {
                let recipient = did_to_string(&entry.did);
                let hash_hex: &str = &entry.hash;
                let hash_bytes = hex::decode(hash_hex).map_err(|e| {
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

                let welcome_id = uuid::Uuid::new_v4().to_string();
                sqlx::query(
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
                .execute(&mut *tx)
                .await
                .map_err(|e| {
                    error!(
                        "[bootstrapResetGroup] INSERT welcome_message for {}: {}",
                        crate::crypto::redact_for_log(&recipient),
                        e
                    );
                    StatusCode::INTERNAL_SERVER_ERROR.into_response()
                })?;
            }
        } else {
            // No keyPackageHashes — store one Welcome per existing member.
            let recipients: Vec<String> = sqlx::query_scalar(
                "SELECT member_did FROM members \
                 WHERE convo_id = $1 AND left_at IS NULL",
            )
            .bind(&original_convo_id)
            .fetch_all(&mut *tx)
            .await
            .map_err(|e| {
                error!(
                    "[bootstrapResetGroup] SELECT members for welcome fanout: {}",
                    e
                );
                StatusCode::INTERNAL_SERVER_ERROR.into_response()
            })?;

            for recipient in recipients {
                let welcome_id = uuid::Uuid::new_v4().to_string();
                sqlx::query(
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
                .execute(&mut *tx)
                .await
                .map_err(|e| {
                    error!(
                        "[bootstrapResetGroup] INSERT welcome_message (no-hash) for {}: {}",
                        crate::crypto::redact_for_log(&recipient),
                        e
                    );
                    StatusCode::INTERNAL_SERVER_ERROR.into_response()
                })?;
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

    tx.commit().await.map_err(|e| {
        error!("[bootstrapResetGroup] commit tx: {}", e);
        StatusCode::INTERNAL_SERVER_ERROR.into_response()
    })?;

    // ── Build the response ConvoView from the now-bootstrapped row ──────
    // Read post-commit so the view reflects the persisted state, including
    // anything other transactions wrote concurrently to non-locked columns.
    let row: (
        String,                // creator_did
        Option<String>,        // name
        String,                // cipher_suite_persisted
        DateTime<Utc>,         // created_at
        Option<DateTime<Utc>>, // last_message_at
        Option<i32>,           // reset_count
    ) = sqlx::query_as(
        "SELECT creator_did, name, cipher_suite, created_at, last_message_at, reset_count \
         FROM conversations WHERE id = $1",
    )
    .bind(&original_convo_id)
    .fetch_one(&pool)
    .await
    .map_err(|e| {
        error!("[bootstrapResetGroup] SELECT post-commit row: {}", e);
        StatusCode::INTERNAL_SERVER_ERROR.into_response()
    })?;

    let (
        creator_did_persisted,
        name,
        cipher_suite_persisted,
        created_at,
        last_message_at,
        reset_count,
    ) = row;

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

    Ok(BootstrapResetGroupOutput {
        convo: ConvoView {
            conversation_id: original_convo_id.clone().into(),
            group_id: new_group_id.into(),
            creator: string_to_did(&creator_did_persisted),
            members: members_typed,
            epoch: 1,
            cipher_suite: cipher_suite_persisted.into(),
            created_at: chrono_to_datetime(created_at),
            last_message_at: last_message_at.map(chrono_to_datetime),
            metadata,
            confirmation_tag: None,
            reset_generation: reset_count.map(|c| c as i64),
            extra_data: Default::default(),
        },
        extra_data: Default::default(),
    })
}
