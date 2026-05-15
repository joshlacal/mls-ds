use axum::{extract::State, http::StatusCode, Json};
use chrono::Utc;
use serde::{Deserialize, Serialize};
use tracing::{error, warn};
use uuid::Uuid;

use crate::{
    auth::AuthUser,
    device_utils::{bucket_device_id, parse_device_did},
    storage::DbPool,
};

const NSID: &str = "blue.catbird.mlsChat.invalidateKeyPackage";

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct InvalidateKeyPackageRequest {
    pub device_did: String,
    pub key_package_hash: String,
    pub reason: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct InvalidateKeyPackageOutput {
    pub marked: bool,
    pub already_dead: bool,
}

pub fn valid_dead_reason(reason: &str) -> bool {
    matches!(
        reason,
        "noMatchingKeyPackage" | "corruptInvitee" | "unowned"
    )
}

fn authorize_device(auth_did: &str, device_did: &str) -> Result<(String, String), StatusCode> {
    let (auth_owner_did, _) = parse_device_did(auth_did).map_err(|e| {
        warn!("invalidateKeyPackage: invalid auth DID: {}", e);
        StatusCode::BAD_REQUEST
    })?;
    let (owner_did, device_id) = parse_device_did(device_did).map_err(|e| {
        warn!("invalidateKeyPackage: invalid device DID: {}", e);
        StatusCode::BAD_REQUEST
    })?;
    if owner_did != auth_owner_did {
        warn!("invalidateKeyPackage: caller tried to invalidate another user's device");
        return Err(StatusCode::FORBIDDEN);
    }
    Ok((owner_did, device_id))
}

#[tracing::instrument(skip(pool, auth_user, input))]
pub async fn invalidate_key_package(
    State(pool): State<DbPool>,
    auth_user: AuthUser,
    Json(input): Json<InvalidateKeyPackageRequest>,
) -> Result<Json<InvalidateKeyPackageOutput>, StatusCode> {
    if let Err(_e) = crate::auth::enforce_standard(&auth_user.claims, NSID) {
        return Err(StatusCode::UNAUTHORIZED);
    }

    if !valid_dead_reason(&input.reason) {
        warn!("invalidateKeyPackage: invalid reason {}", input.reason);
        return Err(StatusCode::BAD_REQUEST);
    }

    let (owner_did, device_id) = authorize_device(&auth_user.did, &input.device_did)?;
    let bucketed_device_id = bucket_device_id(&owner_did, &device_id);

    let existing: Option<Option<chrono::DateTime<Utc>>> = sqlx::query_scalar(
        r#"
        SELECT dead_at
        FROM key_packages
        WHERE owner_did = $1
          AND (device_id = $2 OR device_id = $3 OR device_id IS NULL)
          AND key_package_hash = $4
        LIMIT 1
        "#,
    )
    .bind(&owner_did)
    .bind(&bucketed_device_id)
    .bind(&device_id)
    .bind(&input.key_package_hash)
    .fetch_optional(&pool)
    .await
    .map_err(|e| {
        error!("invalidateKeyPackage: lookup failed: {}", e);
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    let Some(dead_at) = existing else {
        warn!("invalidateKeyPackage: key package not found");
        return Err(StatusCode::NOT_FOUND);
    };

    let already_dead = dead_at.is_some();
    let marked = if already_dead {
        false
    } else {
        let result = sqlx::query(
            r#"
            UPDATE key_packages
            SET dead_at = NOW(),
                dead_reason = $5,
                state = 'revoked'
            WHERE owner_did = $1
              AND (device_id = $2 OR device_id = $3 OR device_id IS NULL)
              AND key_package_hash = $4
              AND dead_at IS NULL
            "#,
        )
        .bind(&owner_did)
        .bind(&bucketed_device_id)
        .bind(&device_id)
        .bind(&input.key_package_hash)
        .bind(&input.reason)
        .execute(&pool)
        .await
        .map_err(|e| {
            error!("invalidateKeyPackage: update failed: {}", e);
            StatusCode::INTERNAL_SERVER_ERROR
        })?;
        result.rows_affected() > 0
    };

    sqlx::query(
        r#"
        INSERT INTO key_package_audit
            (id, action, owner_did, device_did, device_id, key_package_hash,
             reason, already_dead, actor_did, created_at)
        VALUES ($1, 'invalidate', $2, $3, $4, $5, $6, $7, $8, $9)
        "#,
    )
    .bind(Uuid::new_v4().to_string())
    .bind(&owner_did)
    .bind(&input.device_did)
    .bind(&bucketed_device_id)
    .bind(&input.key_package_hash)
    .bind(&input.reason)
    .bind(already_dead)
    .bind(&auth_user.did)
    .bind(Utc::now())
    .execute(&pool)
    .await
    .map_err(|e| {
        error!("invalidateKeyPackage: audit insert failed: {}", e);
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    Ok(Json(InvalidateKeyPackageOutput {
        marked,
        already_dead,
    }))
}

#[cfg(test)]
mod tests {
    use super::valid_dead_reason;

    #[test]
    fn accepts_known_reasons_only() {
        assert!(valid_dead_reason("noMatchingKeyPackage"));
        assert!(valid_dead_reason("corruptInvitee"));
        assert!(valid_dead_reason("unowned"));
        assert!(!valid_dead_reason("anythingElse"));
    }
}
