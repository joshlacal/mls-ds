//! `CryptoSessionRepository` — public observable MLS metadata for one group
//! generation.
//!
//! Phase 2: backed by `crypto_sessions` table. Reads prefer the new table
//! and fall back to projecting from `conversations` legacy MLS columns
//! during the compatibility window. The fallback path emits the
//! `mls_ds_legacy_crypto_session_fallback_total` counter so the cleanup
//! migration can be telemetry-gated per locked decision #1 in the plan.

use async_trait::async_trait;
use sqlx::{PgPool, Postgres, Transaction};
use uuid::Uuid;

use crate::mls_transition::ValidatedMlsTransition;
use crate::models::{
    AppliedMlsTransition, CryptoSession, NewCryptoSession, ResolvedMlsContext, SequencerReceiptRef,
};
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

    /// Resolve the unique active authority for a stable conversation id.
    async fn resolve_active(
        &self,
        conversation_id: &str,
        local_service_did: &str,
    ) -> RepositoryResult<Option<ResolvedMlsContext>>;

    /// Resolve by mutable MLS group identity. Superseded groups do not resolve.
    async fn resolve_active_by_mls_group_id(
        &self,
        mls_group_id: &str,
        local_service_did: &str,
    ) -> RepositoryResult<Option<ResolvedMlsContext>>;

    /// Apply one validated normal transition with an exact context CAS.
    async fn apply_transition(
        &self,
        transition: ValidatedMlsTransition,
    ) -> RepositoryResult<AppliedMlsTransition>;

    /// Append an operation-verified receipt, rejecting equivocation.
    async fn record_verified_receipt(
        &self,
        context: &ResolvedMlsContext,
        receipt: SequencerReceiptRef,
    ) -> RepositoryResult<SequencerReceiptRef>;
}

pub struct PostgresCryptoSessionRepository {
    pool: PgPool,
}

impl PostgresCryptoSessionRepository {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    async fn resolve_with_predicate(
        &self,
        column: &str,
        value: &str,
        local_service_did: &str,
    ) -> RepositoryResult<Option<ResolvedMlsContext>> {
        if !matches!(column, "conversation_id" | "mls_group_id") {
            return Err(RepositoryError::InvalidContext(
                "unsupported context lookup".into(),
            ));
        }
        let rows: Vec<ResolvedContextRow> = sqlx::query_as(&format!(
            "SELECT cs.conversation_id, cs.id, cs.mls_group_id, cs.generation, cs.state, \
                    cs.last_observed_epoch, cs.last_confirmation_tag, \
                    COALESCE(cs.sequencer_did, c.sequencer_ds, $2), \
                    cs.sequencer_term, c.active_crypto_session_id, c.group_id, \
                    c.reset_count, c.current_epoch, c.confirmation_tag, c.sequencer_term \
             FROM crypto_sessions cs \
             JOIN conversations c ON c.id = cs.conversation_id \
             WHERE cs.{column} = $1 AND cs.state = 'active'"
        ))
        .bind(value)
        .bind(local_service_did)
        .fetch_all(&self.pool)
        .await?;

        match rows.as_slice() {
            [] => Ok(None),
            [row] => row.to_context().map(Some),
            _ => Err(RepositoryError::InvalidContext(
                "multiple active crypto sessions resolved".into(),
            )),
        }
    }
}

type ResolvedContextRow = (
    String,
    String,
    String,
    i32,
    String,
    i32,
    Option<Vec<u8>>,
    String,
    i64,
    Option<String>,
    Option<String>,
    Option<i32>,
    i32,
    Option<Vec<u8>>,
    i64,
);

trait ResolvedContextRowExt {
    fn to_context(&self) -> RepositoryResult<ResolvedMlsContext>;
}

impl ResolvedContextRowExt for ResolvedContextRow {
    fn to_context(&self) -> RepositoryResult<ResolvedMlsContext> {
        let sequencer = crate::identity::canonical_did(&self.7);
        if !sequencer.starts_with("did:") || sequencer.is_empty() || sequencer != self.7 {
            return Err(RepositoryError::InvalidContext(
                "sequencer DID is missing or non-canonical".into(),
            ));
        }
        if self.9.as_deref() != Some(self.1.as_str())
            || self.10.as_deref() != Some(self.2.as_str())
            || self.11.unwrap_or(0) != self.3
            || self.12 != self.5
            || self.13 != self.6
            || self.14 != self.8
        {
            metrics::counter!("mls_ds_resolved_context_mismatch_total", 1);
            return Err(RepositoryError::InvalidContext(
                "legacy projection disagrees with active crypto session".into(),
            ));
        }
        Ok(ResolvedMlsContext {
            conversation_id: self.0.clone(),
            crypto_session_id: self.1.clone(),
            mls_group_id: self.2.clone(),
            reset_generation: self.3,
            state: self.4.clone(),
            authoritative_epoch: self.5,
            confirmation_tag: self.6.clone(),
            sequencer_did: sequencer.to_string(),
            sequencer_term: self.8,
            receipt: None,
        })
    }
}

type ReceiptRow = (Vec<u8>, i32, i64, String, Vec<u8>, i64, Vec<u8>);

fn receipt_from_row(row: ReceiptRow) -> SequencerReceiptRef {
    SequencerReceiptRef {
        receipt_hash: row.0,
        epoch: row.1,
        term: row.2,
        sequencer_did: row.3,
        commit_hash: row.4,
        issued_at: row.5,
        signature: row.6,
    }
}

async fn append_receipt_tx(
    tx: &mut Transaction<'_, Postgres>,
    context: &ResolvedMlsContext,
    receipt: &SequencerReceiptRef,
) -> RepositoryResult<SequencerReceiptRef> {
    if receipt.epoch != context.authoritative_epoch + 1
        || receipt.term != context.sequencer_term
        || receipt.sequencer_did != context.sequencer_did
        || crate::identity::canonical_did(&receipt.sequencer_did) != receipt.sequencer_did
    {
        return Err(RepositoryError::InvalidContext(
            "receipt does not bind resolved authority".into(),
        ));
    }
    sqlx::query(
        "INSERT INTO sequencer_receipts \
         (convo_id, epoch, sequencer_term, commit_hash, sequencer_did, issued_at, signature, receipt_hash) \
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8) ON CONFLICT (convo_id, epoch) DO NOTHING",
    )
    .bind(&context.conversation_id)
    .bind(receipt.epoch)
    .bind(receipt.term)
    .bind(&receipt.commit_hash)
    .bind(&receipt.sequencer_did)
    .bind(receipt.issued_at)
    .bind(&receipt.signature)
    .bind(&receipt.receipt_hash)
    .execute(&mut **tx)
    .await?;
    let row: ReceiptRow = sqlx::query_as(
        "SELECT receipt_hash, epoch, sequencer_term, sequencer_did, commit_hash, issued_at, signature \
         FROM sequencer_receipts WHERE convo_id = $1 AND epoch = $2",
    )
    .bind(&context.conversation_id)
    .bind(receipt.epoch)
    .fetch_one(&mut **tx)
    .await?;
    let stored = receipt_from_row(row);
    if stored != *receipt {
        return Err(RepositoryError::ReceiptEquivocation);
    }
    Ok(stored)
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

    async fn resolve_active(
        &self,
        conversation_id: &str,
        local_service_did: &str,
    ) -> RepositoryResult<Option<ResolvedMlsContext>> {
        self.resolve_with_predicate("conversation_id", conversation_id, local_service_did)
            .await
    }

    async fn resolve_active_by_mls_group_id(
        &self,
        mls_group_id: &str,
        local_service_did: &str,
    ) -> RepositoryResult<Option<ResolvedMlsContext>> {
        self.resolve_with_predicate("mls_group_id", mls_group_id, local_service_did)
            .await
    }

    async fn apply_transition(
        &self,
        transition: ValidatedMlsTransition,
    ) -> RepositoryResult<AppliedMlsTransition> {
        let mut tx = self.pool.begin().await?;
        let updated: Option<(i32, Option<Vec<u8>>)> = sqlx::query_as(
            "UPDATE crypto_sessions SET last_observed_epoch=$1, last_confirmation_tag=$2, \
                    group_info=$3, group_info_epoch=$1, group_info_updated_at=NOW() \
             WHERE id=$4 AND conversation_id=$5 AND mls_group_id=$6 AND generation=$7 \
               AND state='active' AND last_observed_epoch=$8 AND sequencer_term=$9 \
             RETURNING last_observed_epoch, last_confirmation_tag",
        )
        .bind(transition.next_epoch)
        .bind(&transition.confirmation_tag)
        .bind(&transition.group_info)
        .bind(&transition.context.crypto_session_id)
        .bind(&transition.context.conversation_id)
        .bind(&transition.context.mls_group_id)
        .bind(transition.context.reset_generation)
        .bind(transition.context.authoritative_epoch)
        .bind(transition.context.sequencer_term)
        .fetch_optional(&mut *tx)
        .await?;
        if updated.is_none() {
            return Err(RepositoryError::StaleContext);
        }

        let mirrored = sqlx::query(
            "UPDATE conversations SET current_epoch=$1, confirmation_tag=$2, group_info=$3, \
                    group_info_epoch=$1, group_info_updated_at=NOW() \
             WHERE id=$4 AND active_crypto_session_id=$5 AND group_id=$6 \
               AND COALESCE(reset_count,0)=$7 AND current_epoch=$8 AND sequencer_term=$9",
        )
        .bind(transition.next_epoch)
        .bind(&transition.confirmation_tag)
        .bind(&transition.group_info)
        .bind(&transition.context.conversation_id)
        .bind(&transition.context.crypto_session_id)
        .bind(&transition.context.mls_group_id)
        .bind(transition.context.reset_generation)
        .bind(transition.context.authoritative_epoch)
        .bind(transition.context.sequencer_term)
        .execute(&mut *tx)
        .await?;
        if mirrored.rows_affected() != 1 {
            return Err(RepositoryError::StaleContext);
        }

        let stored_receipt = match transition.receipt.as_ref() {
            Some(receipt) => Some(append_receipt_tx(&mut tx, &transition.context, receipt).await?),
            None => None,
        };
        let event_id = Uuid::new_v4().to_string();
        let sequence: i64 = sqlx::query_scalar(
            "INSERT INTO delivery_events \
             (id, conversation_id, seq, crypto_session_id, event_type, sender_did, \
              sender_device_id, mls_group_id, mls_epoch, payload, payload_json) \
             SELECT $1,$2,COALESCE(MAX(seq),0)+1,$3,$4,$5,$6,$7,$8,$9,$10 \
             FROM delivery_events WHERE conversation_id=$2 RETURNING seq",
        )
        .bind(&event_id)
        .bind(&transition.context.conversation_id)
        .bind(&transition.context.crypto_session_id)
        .bind(transition.event_type())
        .bind(&transition.actor_did)
        .bind(&transition.actor_device_id)
        .bind(&transition.context.mls_group_id)
        .bind(i64::from(transition.next_epoch))
        .bind(&transition.commit_hash)
        .bind(serde_json::json!({"groupInfoHash": hex::encode(&transition.group_info_hash)}))
        .fetch_one(&mut *tx)
        .await?;
        tx.commit().await?;

        let mut context = transition.context;
        context.authoritative_epoch = transition.next_epoch;
        context.confirmation_tag = transition.confirmation_tag;
        context.receipt = stored_receipt.clone();
        Ok(AppliedMlsTransition {
            context,
            delivery_event_id: event_id,
            delivery_sequence: sequence,
            receipt: stored_receipt,
        })
    }

    async fn record_verified_receipt(
        &self,
        context: &ResolvedMlsContext,
        receipt: SequencerReceiptRef,
    ) -> RepositoryResult<SequencerReceiptRef> {
        let mut tx = self.pool.begin().await?;
        let stored = append_receipt_tx(&mut tx, context, &receipt).await?;
        tx.commit().await?;
        Ok(stored)
    }
}

#[cfg(test)]
mod transition_repository_tests {
    use super::*;
    use crate::mls_transition::{TransitionKind, ValidatedMlsTransition};

    async fn test_pool() -> PgPool {
        let url = std::env::var("TEST_DATABASE_URL")
            .expect("TEST_DATABASE_URL is required for ignored transition repository tests");
        let pool = PgPool::connect(&url).await.expect("connect test postgres");
        sqlx::migrate!().run(&pool).await.expect("run migrations");
        pool
    }

    #[tokio::test]
    #[ignore = "requires TEST_DATABASE_URL with migration privileges"]
    async fn postgres_mls_transition_cas_and_projection_are_atomic() {
        let pool = test_pool().await;
        let suffix = Uuid::new_v4().to_string();
        let conversation_id = format!("transition-convo-{suffix}");
        let group_id = format!("transition-group-{suffix}");
        sqlx::query(
            "INSERT INTO conversations \
             (id, creator_did, current_epoch, sequencer_term, sequencer_ds, is_remote, \
              group_id, reset_count, confirmation_tag, group_info, group_info_epoch) \
             VALUES ($1,'did:plc:alice',9,4,'did:web:mls.example.com',false,$2,2,$3,$4,9)",
        )
        .bind(&conversation_id)
        .bind(&group_id)
        .bind(vec![1_u8, 2, 3])
        .bind(vec![0xAA_u8; 128])
        .execute(&pool)
        .await
        .unwrap();
        let session_id = Uuid::new_v4().to_string();
        sqlx::query(
            "INSERT INTO crypto_sessions \
             (id,conversation_id,generation,mls_group_id,state,last_observed_epoch, \
              last_confirmation_tag,group_info,group_info_epoch,sequencer_did,sequencer_term) \
             VALUES ($1,$2,2,$3,'active',9,$4,$5,9,'did:web:mls.example.com',4)",
        )
        .bind(&session_id)
        .bind(&conversation_id)
        .bind(&group_id)
        .bind(vec![1_u8, 2, 3])
        .bind(vec![0xAA_u8; 128])
        .execute(&pool)
        .await
        .unwrap();
        sqlx::query("UPDATE conversations SET active_crypto_session_id=$1 WHERE id=$2")
            .bind(&session_id)
            .bind(&conversation_id)
            .execute(&pool)
            .await
            .unwrap();

        let repo = PostgresCryptoSessionRepository::new(pool.clone());
        let context = repo
            .resolve_active(&conversation_id, "did:web:mls.example.com")
            .await
            .unwrap()
            .unwrap();
        let candidate = ValidatedMlsTransition::new_observed(
            context.clone(),
            TransitionKind::Commit,
            "did:plc:alice".into(),
            "device-a".into(),
            group_id.clone(),
            10,
            vec![0xBB; 128],
            Some(vec![4, 5, 6]),
            vec![0xCC; 32],
            None,
        )
        .unwrap();
        let winner = repo.apply_transition(candidate.clone()).await.unwrap();
        assert_eq!(winner.context.authoritative_epoch, 10);
        assert!(matches!(
            repo.apply_transition(candidate).await,
            Err(RepositoryError::StaleContext)
        ));
        let projection: (i32, i32, Vec<u8>, Vec<u8>) = sqlx::query_as(
            "SELECT c.current_epoch,cs.last_observed_epoch,c.group_info,cs.group_info \
             FROM conversations c JOIN crypto_sessions cs ON cs.id=c.active_crypto_session_id \
             WHERE c.id=$1",
        )
        .bind(&conversation_id)
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(projection.0, 10);
        assert_eq!(projection.0, projection.1);
        assert_eq!(projection.2, projection.3);
        sqlx::query("DELETE FROM delivery_events WHERE conversation_id=$1")
            .bind(&conversation_id)
            .execute(&pool)
            .await
            .unwrap();
        sqlx::query("DELETE FROM sequencer_receipts WHERE convo_id=$1")
            .bind(&conversation_id)
            .execute(&pool)
            .await
            .unwrap();
        sqlx::query("DELETE FROM conversations WHERE id=$1")
            .bind(&conversation_id)
            .execute(&pool)
            .await
            .unwrap();
    }

    #[tokio::test]
    #[ignore = "requires TEST_DATABASE_URL with migration privileges"]
    async fn mls_transition_migration_is_idempotent() {
        let pool = test_pool().await;
        sqlx::migrate!()
            .run(&pool)
            .await
            .expect("second migration run");
        let columns: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM information_schema.columns \
             WHERE table_name='crypto_sessions' AND column_name IN ('sequencer_did','sequencer_term')",
        )
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(columns, 2);
    }
}
