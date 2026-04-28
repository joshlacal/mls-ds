//! `CryptoSessionRepository` — public observable MLS metadata for one group
//! generation.
//!
//! Phase 2: backed by `crypto_sessions` table. Reads prefer the new table
//! and fall back to projecting from `conversations` legacy MLS columns
//! during the compatibility window. The fallback path emits the
//! `mls_ds_legacy_crypto_session_fallback_total` counter so the cleanup
//! migration can be telemetry-gated per locked decision #1 in the plan.

use async_trait::async_trait;
use sqlx::PgPool;
use uuid::Uuid;

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

    /// Insert a candidate or new active session. Idempotent on
    /// `(conversation_id, generation)` — duplicate calls return the existing
    /// row instead of erroring.
    async fn create(&self, session: NewCryptoSession) -> RepositoryResult<CryptoSession>;

    /// Mark `id` as superseded by `superseded_by_id`. Idempotent — a no-op
    /// if the row is already superseded by the same id.
    async fn mark_superseded(&self, id: &str, superseded_by_id: &str) -> RepositoryResult<()>;
}

pub struct PostgresCryptoSessionRepository {
    pool: PgPool,
}

impl PostgresCryptoSessionRepository {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

/// Tuple of `crypto_sessions` columns in canonical order for `query_as`.
type CryptoSessionRow = (
    String,                                // id
    String,                                // conversation_id
    i32,                                   // generation
    String,                                // mls_group_id
    String,                                // state
    Option<String>,                        // supersedes_id
    Option<String>,                        // cipher_suite
    i32,                                   // last_observed_epoch
    Option<Vec<u8>>,                       // last_confirmation_tag
    Option<Vec<u8>>,                       // group_info
    Option<i32>,                           // group_info_epoch
    Option<chrono::DateTime<chrono::Utc>>, // group_info_updated_at
    Option<String>,                        // created_by_did
    chrono::DateTime<chrono::Utc>,         // created_at
    Option<chrono::DateTime<chrono::Utc>>, // activated_at
    Option<chrono::DateTime<chrono::Utc>>, // superseded_at
);

const SELECT_CRYPTO_SESSION_COLS: &str = "id, conversation_id, generation, mls_group_id, state, \
    supersedes_id, cipher_suite, last_observed_epoch, last_confirmation_tag, group_info, \
    group_info_epoch, group_info_updated_at, created_by_did, created_at, activated_at, \
    superseded_at";

fn row_to_session(r: CryptoSessionRow) -> CryptoSession {
    CryptoSession {
        id: r.0,
        conversation_id: r.1,
        generation: r.2,
        mls_group_id: r.3,
        state: r.4,
        supersedes_id: r.5,
        cipher_suite: r.6,
        last_observed_epoch: r.7,
        last_confirmation_tag: r.8,
        group_info: r.9,
        group_info_epoch: r.10,
        group_info_updated_at: r.11,
        created_by_did: r.12,
        created_at: r.13,
        activated_at: r.14,
        superseded_at: r.15,
    }
}

/// Type for the legacy `conversations` projection used during the compat window.
type LegacyConversationRow = (
    String,                                // id
    Option<String>, // group_id (NOT NULL post-20260405 but typed as Option for safety)
    String,         // creator_did
    i32,            // current_epoch
    Option<Vec<u8>>, // confirmation_tag
    Option<i32>,    // reset_count
    Option<String>, // cipher_suite
    Option<Vec<u8>>, // group_info
    Option<i32>,    // group_info_epoch
    Option<chrono::DateTime<chrono::Utc>>, // group_info_updated_at
    chrono::DateTime<chrono::Utc>, // created_at
);

const SELECT_LEGACY_COLS: &str = "id, group_id, creator_did, current_epoch, confirmation_tag, \
    reset_count, cipher_suite, group_info, group_info_epoch, group_info_updated_at, created_at";

fn legacy_row_to_session(row: LegacyConversationRow) -> CryptoSession {
    let (
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
    ) = row;
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
}

#[async_trait]
impl CryptoSessionRepository for PostgresCryptoSessionRepository {
    async fn get_active(&self, conversation_id: &str) -> RepositoryResult<Option<CryptoSession>> {
        // Phase 2 primary path: read from crypto_sessions WHERE state = 'active'.
        let row: Option<CryptoSessionRow> = sqlx::query_as(&format!(
            "SELECT {SELECT_CRYPTO_SESSION_COLS} FROM crypto_sessions \
             WHERE conversation_id = $1 AND state = 'active'"
        ))
        .bind(conversation_id)
        .fetch_optional(&self.pool)
        .await?;

        if let Some(r) = row {
            return Ok(Some(row_to_session(r)));
        }

        // Legacy fallback: this conversation has no crypto_sessions row yet.
        // Post-backfill this should never happen — emit telemetry so the
        // cleanup migration can be telemetry-gated.
        let legacy: Option<LegacyConversationRow> = sqlx::query_as(&format!(
            "SELECT {SELECT_LEGACY_COLS} FROM conversations WHERE id = $1"
        ))
        .bind(conversation_id)
        .fetch_optional(&self.pool)
        .await?;

        if let Some(r) = legacy {
            metrics::counter!(
                "mls_ds_legacy_crypto_session_fallback_total",
                1,
                "method" => "get_active",
                "reason" => "no_crypto_session_row"
            );
            return Ok(Some(legacy_row_to_session(r)));
        }

        Ok(None)
    }

    async fn get_by_mls_group_id(
        &self,
        mls_group_id: &str,
    ) -> RepositoryResult<Option<CryptoSession>> {
        // Phase 2 primary path: crypto_sessions.mls_group_id is UNIQUE.
        let row: Option<CryptoSessionRow> = sqlx::query_as(&format!(
            "SELECT {SELECT_CRYPTO_SESSION_COLS} FROM crypto_sessions WHERE mls_group_id = $1"
        ))
        .bind(mls_group_id)
        .fetch_optional(&self.pool)
        .await?;

        if let Some(r) = row {
            return Ok(Some(row_to_session(r)));
        }

        // Legacy fallback: conversation may carry the group id on the
        // `conversations` row but not yet have a crypto_sessions entry.
        let legacy: Option<LegacyConversationRow> = sqlx::query_as(&format!(
            "SELECT {SELECT_LEGACY_COLS} FROM conversations WHERE group_id = $1 OR id = $1"
        ))
        .bind(mls_group_id)
        .fetch_optional(&self.pool)
        .await?;

        if let Some(r) = legacy {
            metrics::counter!(
                "mls_ds_legacy_crypto_session_fallback_total",
                1,
                "method" => "get_by_mls_group_id",
                "reason" => "no_crypto_session_row"
            );
            return Ok(Some(legacy_row_to_session(r)));
        }

        Ok(None)
    }

    async fn create(&self, session: NewCryptoSession) -> RepositoryResult<CryptoSession> {
        // Use a stable id: caller may supply one, otherwise allocate v4.
        let id = if session.id.is_empty() {
            Uuid::new_v4().to_string()
        } else {
            session.id.clone()
        };

        // INSERT-or-fetch in one query: ON CONFLICT (conversation_id, generation)
        // DO UPDATE SET id = crypto_sessions.id RETURNING * — the DO UPDATE
        // is a deliberate no-op so we get RETURNING semantics on conflict.
        // This is the canonical Postgres "upsert returning existing" pattern.
        let inserted: Option<CryptoSessionRow> = sqlx::query_as(&format!(
            "INSERT INTO crypto_sessions ( \
                id, conversation_id, generation, mls_group_id, state, supersedes_id, \
                cipher_suite, last_observed_epoch, last_confirmation_tag, group_info, \
                group_info_epoch, created_by_did, activated_at \
             ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, \
                CASE WHEN $5 = 'active' THEN NOW() ELSE NULL END) \
             ON CONFLICT (conversation_id, generation) \
             DO UPDATE SET id = crypto_sessions.id \
             RETURNING {SELECT_CRYPTO_SESSION_COLS}"
        ))
        .bind(&id)
        .bind(&session.conversation_id)
        .bind(session.generation)
        .bind(&session.mls_group_id)
        .bind(&session.state)
        .bind(&session.supersedes_id)
        .bind(&session.cipher_suite)
        .bind(session.last_observed_epoch)
        .bind(&session.last_confirmation_tag)
        .bind(&session.group_info)
        .bind(session.group_info_epoch)
        .bind(&session.created_by_did)
        .fetch_optional(&self.pool)
        .await?;

        inserted
            .map(row_to_session)
            .ok_or_else(|| RepositoryError::Database(sqlx::Error::RowNotFound))
    }

    async fn mark_superseded(&self, id: &str, superseded_by_id: &str) -> RepositoryResult<()> {
        // Idempotent: transitions from any non-terminal state — `active`
        // (no reset request), `reset_requested` (Request fired but no
        // candidate yet), or `superseding` (candidate accepted, transition
        // in flight). If already `superseded`/`failed`/`archived`, zero
        // rows affected and the call is a no-op (no error).
        //
        // Bug 002 (ultrareview): the prior filter `('active', 'superseding')`
        // missed the `reset_requested` case, so every successful reset
        // (Request → Activate happy path) left an orphaned row in
        // `reset_requested` state forever. The active session pointer
        // moves correctly but the prior row never transitions out, leaking
        // a row per reset.
        sqlx::query(
            "UPDATE crypto_sessions \
             SET state = 'superseded', \
                 superseded_at = NOW(), \
                 superseded_by_id = $2 \
             WHERE id = $1 \
               AND state IN ('active', 'reset_requested', 'superseding')",
        )
        .bind(id)
        .bind(superseded_by_id)
        .execute(&self.pool)
        .await?;

        Ok(())
    }
}
