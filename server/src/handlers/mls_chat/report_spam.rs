use axum::{extract::State, http::StatusCode, Json};
use jacquard_axum::ExtractXrpc;
use tracing::{error, info, warn};

use crate::{
    auth::{enforce_standard, verify_is_member, AuthUser},
    generated::blue_catbird::mlsChat::report_spam::{ReportSpamOutput, ReportSpamRequest},
    sqlx_jacquard::chrono_to_datetime,
    storage::DbPool,
};

const NSID: &str = "blue.catbird.mlsChat.reportSpam";

/// Report an account as spam in an MLS conversation.
/// POST /xrpc/blue.catbird.mlsChat.reportSpam
#[tracing::instrument(skip(pool, auth_user, input))]
pub async fn report_spam_post(
    State(pool): State<DbPool>,
    auth_user: AuthUser,
    ExtractXrpc(input): ExtractXrpc<ReportSpamRequest>,
) -> Result<Json<ReportSpamOutput>, StatusCode> {
    if let Err(_e) = enforce_standard(&auth_user.claims, NSID) {
        return Err(StatusCode::UNAUTHORIZED);
    }

    let convo_id = input.convo_id.as_ref();
    let reported_did = input.reported_did.as_ref();
    let reason = input.reason.as_deref();

    // Verify conversation exists
    let convo_exists: Option<bool> =
        sqlx::query_scalar("SELECT TRUE FROM conversations WHERE id = $1")
            .bind(convo_id)
            .fetch_optional(&pool)
            .await
            .map_err(|e| {
                error!("Database query failed: {}", e);
                StatusCode::INTERNAL_SERVER_ERROR
            })?;

    if convo_exists.is_none() {
        warn!(
            "Conversation not found: {}",
            crate::crypto::redact_for_log(convo_id)
        );
        return Err(StatusCode::NOT_FOUND);
    }

    // Verify reporter is a member
    verify_is_member(&pool, convo_id, &auth_user.did).await?;

    let now = chrono::Utc::now();
    let report_id = uuid::Uuid::new_v4().to_string();

    let result = sqlx::query(
        "INSERT INTO spam_reports (id, convo_id, reporter_did, reported_did, reason, created_at)
         VALUES ($1, $2, $3, $4, $5, $6)",
    )
    .bind(&report_id)
    .bind(convo_id)
    .bind(&auth_user.did)
    .bind(reported_did)
    .bind(reason)
    .bind(now)
    .execute(&pool)
    .await;

    match result {
        Ok(_) => {
            info!(
                "Spam report {} created: {} reported {} in {}",
                report_id,
                crate::crypto::redact_for_log(&auth_user.did),
                crate::crypto::redact_for_log(reported_did),
                crate::crypto::redact_for_log(convo_id),
            );

            Ok(Json(ReportSpamOutput {
                id: report_id.into(),
                created_at: chrono_to_datetime(now),
                extra_data: Default::default(),
            }))
        }
        Err(e) => {
            // Check for unique constraint violation (already reported)
            let err_str = e.to_string();
            if err_str.contains("unique constraint")
                || err_str.contains("duplicate key")
                || err_str.contains("UNIQUE constraint")
            {
                warn!(
                    "Duplicate spam report: {} already reported {} in {}",
                    crate::crypto::redact_for_log(&auth_user.did),
                    crate::crypto::redact_for_log(reported_did),
                    crate::crypto::redact_for_log(convo_id),
                );
                return Err(StatusCode::CONFLICT);
            }

            error!("Database insert failed: {}", e);
            Err(StatusCode::INTERNAL_SERVER_ERROR)
        }
    }
}
