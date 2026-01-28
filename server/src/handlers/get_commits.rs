use axum::{
    extract::{Query, State},
    http::StatusCode,
    Json,
};
use serde::{Deserialize, Serialize};
use tracing::{error, info, warn};

use crate::{
    auth::AuthUser,
    storage::{is_member, DbPool},
};

#[derive(Debug, Deserialize)]
pub struct GetCommitsParams {
    #[serde(rename = "convoId")]
    pub convo_id: String,
    #[serde(rename = "fromEpoch")]
    pub from_epoch: i64,
    #[serde(rename = "toEpoch")]
    pub to_epoch: Option<i64>,
}

#[derive(Debug, Serialize, sqlx::FromRow)]
pub struct CommitMessage {
    pub id: String,
    pub epoch: i64,
    #[serde(rename = "commitData")]
    #[sqlx(rename = "ciphertext")]
    pub commit_data: Vec<u8>,
    #[serde(rename = "sender")]
    pub sender_did: String,
    #[serde(rename = "createdAt")]
    pub created_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Debug, Serialize)]
pub struct CommitsResponse {
    #[serde(rename = "convoId")]
    pub convo_id: String,
    pub commits: Vec<CommitMessage>,
}

/// Get commit messages within an epoch range
/// GET /xrpc/blue.catbird.mls.getCommits
#[tracing::instrument(skip(pool))]
pub async fn get_commits(
    State(pool): State<DbPool>,
    auth_user: AuthUser,
    Query(params): Query<GetCommitsParams>,
) -> Result<Json<CommitsResponse>, StatusCode> {
    if let Err(_e) = crate::auth::enforce_standard(&auth_user.claims, "blue.catbird.mls.getCommits")
    {
        return Err(StatusCode::UNAUTHORIZED);
    }

    let did = &auth_user.did;

    // Validate input
    if params.convo_id.is_empty() {
        warn!("Empty convo_id provided");
        return Err(StatusCode::BAD_REQUEST);
    }

    if params.from_epoch < 0 {
        warn!("Invalid from_epoch: {}", params.from_epoch);
        return Err(StatusCode::BAD_REQUEST);
    }

    // Check if user is a member
    if !is_member(&pool, did, &params.convo_id).await.map_err(|e| {
        error!("Failed to check membership: {}", e);
        StatusCode::INTERNAL_SERVER_ERROR
    })? {
        warn!("User is not a member of conversation");
        return Err(StatusCode::FORBIDDEN);
    }

    // Determine end epoch - default to current epoch if not specified
    let to_epoch = if let Some(to) = params.to_epoch {
        to
    } else {
        // Get current epoch
        let current_epoch: i32 =
            sqlx::query_scalar("SELECT current_epoch FROM conversations WHERE id = $1")
                .bind(&params.convo_id)
                .fetch_one(&pool)
                .await
                .map_err(|e| {
                    error!("Failed to fetch current epoch: {}", e);
                    match e {
                        sqlx::Error::RowNotFound => StatusCode::NOT_FOUND,
                        _ => StatusCode::INTERNAL_SERVER_ERROR,
                    }
                })?;
        current_epoch as i64
    };

    // Validate epoch range
    if params.from_epoch > to_epoch {
        warn!("Invalid epoch range: {} to {}", params.from_epoch, to_epoch);
        return Err(StatusCode::BAD_REQUEST);
    }

    info!(
        "Fetching commits for conversation {} from epoch {} to {}",
        params.convo_id, params.from_epoch, to_epoch
    );

    // Fetch commit messages in epoch range
    let commits = sqlx::query_as::<_, CommitMessage>(
        "SELECT id, epoch, ciphertext, sender_did, created_at 
         FROM messages 
         WHERE convo_id = $1 
           AND message_type = 'commit'
           AND epoch >= $2 
           AND epoch <= $3
         ORDER BY epoch ASC, created_at ASC",
    )
    .bind(&params.convo_id)
    .bind(params.from_epoch)
    .bind(to_epoch)
    .fetch_all(&pool)
    .await
    .map_err(|e| {
        error!("Failed to fetch commits: {}", e);
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    info!("Fetched {} commits", commits.len());

    Ok(Json(CommitsResponse {
        convo_id: params.convo_id,
        commits,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn setup_test_convo_with_commits(
        pool: &DbPool,
        creator: &str,
        convo_id: &str,
        epochs: &[i64],
    ) {
        let now = chrono::Utc::now();

        // Create conversation
        let max_epoch = epochs.iter().max().unwrap_or(&0);
        sqlx::query(
            "INSERT INTO conversations (id, creator_did, current_epoch, created_at, updated_at) 
             VALUES ($1, $2, $3, $4, $4)",
        )
        .bind(convo_id)
        .bind(creator)
        .bind(*max_epoch as i32)
        .bind(&now)
        .execute(pool)
        .await
        .unwrap();

        // Add member
        sqlx::query(
            "INSERT INTO members (convo_id, member_did, joined_at) 
             VALUES ($1, $2, $3)",
        )
        .bind(convo_id)
        .bind(creator)
        .bind(&now)
        .execute(pool)
        .await
        .unwrap();

        // Add commit messages
        for (idx, &epoch) in epochs.iter().enumerate() {
            let msg_id = format!("commit-{}", idx);
            let ciphertext = format!("commit-data-epoch-{}", epoch);
            sqlx::query(
                "INSERT INTO messages (id, convo_id, sender_did, message_type, epoch, seq, ciphertext, created_at) 
                 VALUES ($1, $2, $3, 'commit', $4, $5, $6, $7)"
            )
            .bind(&msg_id)
            .bind(convo_id)
            .bind(creator)
            .bind(epoch)
            .bind(idx as i64)
            .bind(ciphertext.as_bytes())
            .bind(&now)
            .execute(pool)
            .await
            .unwrap();
        }
    }

    #[tokio::test]
    async fn test_get_commits_success() {
        let Ok(db_url) = std::env::var("TEST_DATABASE_URL") else {
            return;
        };
        let pool = crate::db::init_db(crate::db::DbConfig {
            database_url: db_url,
            max_connections: 5,
            min_connections: 1,
            acquire_timeout: std::time::Duration::from_secs(5),
            idle_timeout: std::time::Duration::from_secs(30),
        })
        .await
        .unwrap();

        let convo_id = "test-commits-convo-1";
        let user = "did:plc:user";

        setup_test_convo_with_commits(&pool, user, convo_id, &[1, 2, 3, 5, 8]).await;

        let auth_user = AuthUser {
            did: user.to_string(),
            claims: crate::auth::AtProtoClaims {
                iss: user.to_string(),
                aud: "test".to_string(),
                exp: 9999999999,
                iat: None,
                sub: None,
                jti: Some("test-jti".to_string()),
                lxm: None,
            },
        };

        // Test fetching range 2-5
        let params = GetCommitsParams {
            convo_id: convo_id.to_string(),
            from_epoch: 2,
            to_epoch: Some(5),
        };

        let result = get_commits(State(pool.clone()), auth_user.clone(), Query(params)).await;
        assert!(result.is_ok());

        let response = result.unwrap().0;
        assert_eq!(response.commits.len(), 3); // epochs 2, 3, 5
        assert_eq!(response.commits[0].epoch, 2);
        assert_eq!(response.commits[1].epoch, 3);
        assert_eq!(response.commits[2].epoch, 5);

        // Test fetching from epoch 1 to current (should get all)
        let params2 = GetCommitsParams {
            convo_id: convo_id.to_string(),
            from_epoch: 1,
            to_epoch: None,
        };

        let result2 = get_commits(State(pool), auth_user, Query(params2)).await;
        assert!(result2.is_ok());

        let response2 = result2.unwrap().0;
        assert_eq!(response2.commits.len(), 5); // all commits
    }

    #[tokio::test]
    async fn test_get_commits_not_member() {
        let Ok(db_url) = std::env::var("TEST_DATABASE_URL") else {
            return;
        };
        let pool = crate::db::init_db(crate::db::DbConfig {
            database_url: db_url,
            max_connections: 5,
            min_connections: 1,
            acquire_timeout: std::time::Duration::from_secs(5),
            idle_timeout: std::time::Duration::from_secs(30),
        })
        .await
        .unwrap();

        let convo_id = "test-commits-convo-2";
        let creator = "did:plc:creator";

        setup_test_convo_with_commits(&pool, creator, convo_id, &[1, 2]).await;

        let auth_user = AuthUser {
            did: "did:plc:outsider".to_string(),
            claims: crate::auth::AtProtoClaims {
                iss: "did:plc:outsider".to_string(),
                aud: "test".to_string(),
                exp: 9999999999,
                iat: None,
                sub: None,
                jti: Some("test-jti".to_string()),
                lxm: None,
            },
        };

        let params = GetCommitsParams {
            convo_id: convo_id.to_string(),
            from_epoch: 1,
            to_epoch: Some(2),
        };

        let result = get_commits(State(pool), auth_user, Query(params)).await;
        assert_eq!(result.unwrap_err(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn test_get_commits_invalid_range() {
        let Ok(db_url) = std::env::var("TEST_DATABASE_URL") else {
            return;
        };
        let pool = crate::db::init_db(crate::db::DbConfig {
            database_url: db_url,
            max_connections: 5,
            min_connections: 1,
            acquire_timeout: std::time::Duration::from_secs(5),
            idle_timeout: std::time::Duration::from_secs(30),
        })
        .await
        .unwrap();

        let convo_id = "test-commits-convo-3";
        let user = "did:plc:user";

        setup_test_convo_with_commits(&pool, user, convo_id, &[1, 2]).await;

        let auth_user = AuthUser {
            did: user.to_string(),
            claims: crate::auth::AtProtoClaims {
                iss: user.to_string(),
                aud: "test".to_string(),
                exp: 9999999999,
                iat: None,
                sub: None,
                jti: Some("test-jti".to_string()),
                lxm: None,
            },
        };

        // from_epoch > to_epoch
        let params = GetCommitsParams {
            convo_id: convo_id.to_string(),
            from_epoch: 5,
            to_epoch: Some(2),
        };

        let result = get_commits(State(pool), auth_user, Query(params)).await;
        assert_eq!(result.unwrap_err(), StatusCode::BAD_REQUEST);
    }
}
