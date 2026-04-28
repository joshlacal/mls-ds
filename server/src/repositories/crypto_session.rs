//! `CryptoSessionRepository` — public observable MLS metadata for one group
//! generation.
//!
//! Phase 1: `get_active` and `get_by_mls_group_id` are real (project from
//! `conversations`); `create` and `mark_superseded` return
//! `RepositoryError::NotImplemented`. Phase 2 wires the latter to the new
//! `crypto_sessions` table.

use async_trait::async_trait;
use sqlx::PgPool;

use crate::models::{CryptoSession, NewCryptoSession};
use crate::repositories::{RepositoryError, RepositoryResult};

#[async_trait]
pub trait CryptoSessionRepository: Send + Sync {
    /// The currently-active session for a conversation, if any.
    async fn get_active(&self, conversation_id: &str) -> RepositoryResult<Option<CryptoSession>>;

    /// Lookup by MLS group id (for incoming envelopes).
    async fn get_by_mls_group_id(
        &self,
        mls_group_id: &str,
    ) -> RepositoryResult<Option<CryptoSession>>;

    /// Insert a candidate or new active session. Phase 2 enforces the
    /// `(conversation_id, generation)` UNIQUE tie-break.
    async fn create(&self, session: NewCryptoSession) -> RepositoryResult<CryptoSession>;

    /// Mark `id` as superseded by `superseded_by_id`.
    async fn mark_superseded(
        &self,
        id: &str,
        superseded_by_id: &str,
    ) -> RepositoryResult<()>;
}

pub struct PostgresCryptoSessionRepository {
    pool: PgPool,
}

impl PostgresCryptoSessionRepository {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl CryptoSessionRepository for PostgresCryptoSessionRepository {
    async fn get_active(&self, conversation_id: &str) -> RepositoryResult<Option<CryptoSession>> {
        // Phase 1: project from `conversations`. The `conversations` table
        // already carries the active MLS metadata; the dedicated
        // `crypto_sessions` table arrives in Phase 2.
        let row: Option<(
            String,
            Option<String>,
            String,
            i32,
            Option<Vec<u8>>,
            Option<i32>,
            Option<String>,
            Option<Vec<u8>>,
            Option<i32>,
            Option<chrono::DateTime<chrono::Utc>>,
            chrono::DateTime<chrono::Utc>,
        )> = sqlx::query_as(
            "SELECT id, group_id, creator_did, current_epoch, confirmation_tag, \
             reset_count, cipher_suite, group_info, group_info_epoch, \
             group_info_updated_at, created_at \
             FROM conversations WHERE id = $1",
        )
        .bind(conversation_id)
        .fetch_optional(&self.pool)
        .await?;

        Ok(row.map(
            |(
                id,
                group_id,
                creator_did,
                current_epoch,
                confirmation_tag,
                reset_count,
                cipher_suite,
                group_info,
                group_info_epoch,
                group_info_updated_at,
                created_at,
            )| {
                CryptoSession {
                    id: id.clone(),
                    conversation_id: id.clone(),
                    generation: reset_count.unwrap_or(0),
                    mls_group_id: group_id.unwrap_or_else(|| id.clone()),
                    state: "active".to_string(),
                    cipher_suite,
                    last_observed_epoch: current_epoch,
                    last_confirmation_tag: confirmation_tag,
                    group_info,
                    group_info_epoch,
                    group_info_updated_at,
                    created_by_did: Some(creator_did),
                    created_at,
                    activated_at: None,
                    superseded_at: None,
                    supersedes_id: None,
                }
            },
        ))
    }

    async fn get_by_mls_group_id(
        &self,
        mls_group_id: &str,
    ) -> RepositoryResult<Option<CryptoSession>> {
        // The `conversations` table indexes the active MLS group id either by
        // `id` (when reset_count = 0) or by `group_id` (after reset).
        let row: Option<(
            String,
            Option<String>,
            String,
            i32,
            Option<Vec<u8>>,
            Option<i32>,
            Option<String>,
            Option<Vec<u8>>,
            Option<i32>,
            Option<chrono::DateTime<chrono::Utc>>,
            chrono::DateTime<chrono::Utc>,
        )> = sqlx::query_as(
            "SELECT id, group_id, creator_did, current_epoch, confirmation_tag, \
             reset_count, cipher_suite, group_info, group_info_epoch, \
             group_info_updated_at, created_at \
             FROM conversations WHERE group_id = $1 OR id = $1",
        )
        .bind(mls_group_id)
        .fetch_optional(&self.pool)
        .await?;

        Ok(row.map(
            |(
                id,
                group_id,
                creator_did,
                current_epoch,
                confirmation_tag,
                reset_count,
                cipher_suite,
                group_info,
                group_info_epoch,
                group_info_updated_at,
                created_at,
            )| {
                CryptoSession {
                    id: id.clone(),
                    conversation_id: id.clone(),
                    generation: reset_count.unwrap_or(0),
                    mls_group_id: group_id.unwrap_or_else(|| id.clone()),
                    state: "active".to_string(),
                    cipher_suite,
                    last_observed_epoch: current_epoch,
                    last_confirmation_tag: confirmation_tag,
                    group_info,
                    group_info_epoch,
                    group_info_updated_at,
                    created_by_did: Some(creator_did),
                    created_at,
                    activated_at: None,
                    superseded_at: None,
                    supersedes_id: None,
                }
            },
        ))
    }

    async fn create(&self, _session: NewCryptoSession) -> RepositoryResult<CryptoSession> {
        Err(RepositoryError::NotImplemented)
    }

    async fn mark_superseded(
        &self,
        _id: &str,
        _superseded_by_id: &str,
    ) -> RepositoryResult<()> {
        Err(RepositoryError::NotImplemented)
    }
}
