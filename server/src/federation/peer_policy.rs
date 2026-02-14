use sqlx::PgPool;

use super::errors::FederationError;
use crate::identity::canonical_did;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PeerStatus {
    Pending,
    Allow,
    Suspend,
    Block,
}

impl PeerStatus {
    pub fn from_str(status: &str) -> Option<Self> {
        match status {
            "pending" => Some(Self::Pending),
            "allow" => Some(Self::Allow),
            "suspend" => Some(Self::Suspend),
            "block" => Some(Self::Block),
            _ => None,
        }
    }

    pub fn as_db_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Allow => "allow",
            Self::Suspend => "suspend",
            Self::Block => "block",
        }
    }
}

#[derive(Debug, Clone)]
pub struct PeerPolicy {
    pub status: PeerStatus,
    pub max_requests_per_minute: Option<u32>,
    pub trust_score: i32,
}

fn parse_status(status: &str) -> PeerStatus {
    PeerStatus::from_str(status).unwrap_or(PeerStatus::Pending)
}

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct FederationPeerRecord {
    pub ds_did: String,
    pub status: String,
    pub trust_score: i32,
    pub max_requests_per_minute: Option<i32>,
    pub note: Option<String>,
    pub invalid_token_count: i64,
    pub rejected_request_count: i64,
    pub successful_request_count: i64,
    pub last_seen_at: Option<chrono::DateTime<chrono::Utc>>,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub updated_at: chrono::DateTime<chrono::Utc>,
}

pub async fn enforce_inbound_peer_policy(
    pool: &PgPool,
    ds_did: &str,
) -> Result<PeerPolicy, FederationError> {
    let ds_did = canonical_did(ds_did);
    let (status, max_requests_per_minute, trust_score): (String, Option<i32>, i32) =
        sqlx::query_as(
            "INSERT INTO federation_peers (ds_did, last_seen_at, updated_at) \
             VALUES ($1, NOW(), NOW()) \
             ON CONFLICT (ds_did) DO UPDATE SET \
               last_seen_at = NOW(), \
               updated_at = NOW() \
             RETURNING status, max_requests_per_minute, trust_score",
        )
        .bind(ds_did)
        .fetch_one(pool)
        .await
        .map_err(FederationError::Database)?;

    let policy = PeerPolicy {
        status: parse_status(&status),
        max_requests_per_minute: max_requests_per_minute.map(|v| v.max(1) as u32),
        trust_score,
    };

    match policy.status {
        PeerStatus::Allow => Ok(policy),
        PeerStatus::Pending => Err(FederationError::AuthFailed {
            reason: format!("Peer DS '{}' is pending approval", ds_did),
        }),
        PeerStatus::Suspend => Err(FederationError::AuthFailed {
            reason: format!("Peer DS '{}' is suspended", ds_did),
        }),
        PeerStatus::Block => Err(FederationError::AuthFailed {
            reason: format!("Peer DS '{}' is blocklisted", ds_did),
        }),
    }
}

pub async fn record_success(pool: &PgPool, ds_did: &str) {
    let ds_did = canonical_did(ds_did);
    let _ = sqlx::query(
        "INSERT INTO federation_peers (ds_did, successful_request_count, trust_score, last_seen_at, updated_at) \
         VALUES ($1, 1, 1, NOW(), NOW()) \
         ON CONFLICT (ds_did) DO UPDATE SET \
           successful_request_count = federation_peers.successful_request_count + 1, \
           trust_score = LEAST(federation_peers.trust_score + 1, 1000), \
           last_seen_at = NOW(), \
           updated_at = NOW()",
    )
    .bind(ds_did)
    .execute(pool)
    .await;
}

pub async fn record_rejected(pool: &PgPool, ds_did: &str) {
    let ds_did = canonical_did(ds_did);
    let _ = sqlx::query(
        "INSERT INTO federation_peers (ds_did, rejected_request_count, trust_score, last_seen_at, updated_at) \
         VALUES ($1, 1, -5, NOW(), NOW()) \
         ON CONFLICT (ds_did) DO UPDATE SET \
           rejected_request_count = federation_peers.rejected_request_count + 1, \
           trust_score = GREATEST(federation_peers.trust_score - 5, -1000), \
           last_seen_at = NOW(), \
           updated_at = NOW()",
    )
    .bind(ds_did)
    .execute(pool)
    .await;
}

pub async fn record_invalid_token(pool: &PgPool, ds_did: &str) {
    let ds_did = canonical_did(ds_did);
    let _ = sqlx::query(
        "INSERT INTO federation_peers (ds_did, invalid_token_count, trust_score, last_seen_at, updated_at) \
         VALUES ($1, 1, -10, NOW(), NOW()) \
         ON CONFLICT (ds_did) DO UPDATE SET \
           invalid_token_count = federation_peers.invalid_token_count + 1, \
           trust_score = GREATEST(federation_peers.trust_score - 10, -1000), \
           last_seen_at = NOW(), \
           updated_at = NOW()",
    )
    .bind(ds_did)
    .execute(pool)
    .await;
}

pub async fn list_peer_policies(
    pool: &PgPool,
    status_filter: Option<PeerStatus>,
    limit: u32,
) -> Result<Vec<FederationPeerRecord>, FederationError> {
    let limit = limit.clamp(1, 500) as i64;
    let status_filter = status_filter.map(|s| s.as_db_str().to_string());

    sqlx::query_as::<_, FederationPeerRecord>(
        "SELECT ds_did, status, trust_score, max_requests_per_minute, note, \
                invalid_token_count, rejected_request_count, successful_request_count, \
                last_seen_at, created_at, updated_at \
         FROM federation_peers \
         WHERE ($1::TEXT IS NULL OR status = $1) \
         ORDER BY updated_at DESC \
         LIMIT $2",
    )
    .bind(status_filter)
    .bind(limit)
    .fetch_all(pool)
    .await
    .map_err(FederationError::Database)
}

pub async fn upsert_peer_policy(
    pool: &PgPool,
    ds_did: &str,
    status: PeerStatus,
    max_requests_per_minute: Option<u32>,
    note: Option<&str>,
) -> Result<FederationPeerRecord, FederationError> {
    let ds_did = canonical_did(ds_did);
    let max_requests_per_minute = max_requests_per_minute.map(|v| v.max(1) as i32);

    sqlx::query_as::<_, FederationPeerRecord>(
        "INSERT INTO federation_peers \
            (ds_did, status, max_requests_per_minute, note, updated_at, last_seen_at) \
         VALUES ($1, $2, $3, $4, NOW(), NOW()) \
         ON CONFLICT (ds_did) DO UPDATE SET \
           status = EXCLUDED.status, \
           max_requests_per_minute = EXCLUDED.max_requests_per_minute, \
           note = EXCLUDED.note, \
           updated_at = NOW() \
         RETURNING ds_did, status, trust_score, max_requests_per_minute, note, \
                   invalid_token_count, rejected_request_count, successful_request_count, \
                   last_seen_at, created_at, updated_at",
    )
    .bind(ds_did)
    .bind(status.as_db_str())
    .bind(max_requests_per_minute)
    .bind(note)
    .fetch_one(pool)
    .await
    .map_err(FederationError::Database)
}

pub async fn delete_peer_policy(pool: &PgPool, ds_did: &str) -> Result<bool, FederationError> {
    let ds_did = canonical_did(ds_did);
    let result = sqlx::query("DELETE FROM federation_peers WHERE ds_did = $1")
        .bind(ds_did)
        .execute(pool)
        .await
        .map_err(FederationError::Database)?;

    Ok(result.rows_affected() > 0)
}
