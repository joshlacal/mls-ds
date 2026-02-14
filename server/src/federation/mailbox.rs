use anyhow::Result;
use async_trait::async_trait;
use sqlx::PgPool;
use tracing::debug;

use crate::fanout::{Envelope, MailboxBackend};
use crate::identity::canonical_did;

/// Federated mailbox backend that routes messages to local SSE or remote DSes.
pub struct FederatedBackend {
    pool: PgPool,
    self_did: String,
    federation_enabled: bool,
}

impl FederatedBackend {
    pub fn new(pool: PgPool, self_did: String, federation_enabled: bool) -> Self {
        Self {
            pool,
            self_did,
            federation_enabled,
        }
    }

    /// Check if a member is local (served by this DS) for a conversation.
    async fn is_local_member(&self, convo_id: &str, member_did: &str) -> Result<bool> {
        if !self.federation_enabled {
            return Ok(true);
        }

        // Index note: members PRIMARY KEY is (convo_id, member_did)
        // (see server/migrations/20250101000000_greenfield_schema.sql),
        // so this is a single-row PK lookup; `left_at IS NULL` is an in-row filter.
        let ds_did = sqlx::query_scalar::<_, Option<String>>(
            "SELECT ds_did FROM members WHERE convo_id = $1 AND member_did = $2 AND left_at IS NULL LIMIT 1",
        )
    .bind(convo_id)
    .bind(member_did)
    .fetch_optional(&self.pool)
    .await?;

        Ok(ds_did
            .flatten()
            .map_or(true, |did| canonical_did(&did) == canonical_did(&self.self_did)))
    }

    /// Get the sequencer DS DID for a conversation.
    pub async fn get_sequencer_ds(&self, convo_id: &str) -> Result<Option<String>> {
        let result = sqlx::query_scalar::<_, Option<String>>(
            "SELECT sequencer_ds FROM conversations WHERE id = $1",
        )
        .bind(convo_id)
        .fetch_optional(&self.pool)
        .await?;
        Ok(result.flatten())
    }

    /// Check if this DS is the sequencer for a conversation.
    pub async fn is_sequencer(&self, convo_id: &str) -> Result<bool> {
        let sequencer_ds = self.get_sequencer_ds(convo_id).await?;
        Ok(sequencer_ds
            .as_deref()
            .map(|did| canonical_did(did) == canonical_did(&self.self_did))
            .unwrap_or(true))
    }

    /// Get distinct DS DIDs for all members of a conversation.
    pub async fn get_participant_ds_dids(&self, convo_id: &str) -> Result<Vec<String>> {
        let rows = sqlx::query_scalar::<_, Option<String>>(
            "SELECT DISTINCT COALESCE(split_part(ds_did, '#', 1), $2) FROM members \
       WHERE convo_id = $1",
        )
        .bind(convo_id)
        .bind(&self.self_did)
        .fetch_all(&self.pool)
        .await?;

        Ok(rows.into_iter().flatten().collect())
    }
}

#[async_trait]
impl MailboxBackend for FederatedBackend {
    async fn notify(&self, envelope: &Envelope) -> Result<()> {
        if !self.federation_enabled {
            debug!(
              convo_id = %envelope.convo_id,
              recipient = %envelope.recipient_did,
              "Local delivery (federation disabled)"
            );
            return Ok(());
        }

        if self
            .is_local_member(&envelope.convo_id, &envelope.recipient_did)
            .await?
        {
            debug!(
              convo_id = %envelope.convo_id,
              recipient = %envelope.recipient_did,
              "Local delivery via SSE"
            );
        } else {
            debug!(
              convo_id = %envelope.convo_id,
              recipient = %envelope.recipient_did,
              "Remote recipient — delivery handled by fan-out"
            );
        }

        Ok(())
    }

    fn provider_name(&self) -> &'static str {
        "federated"
    }
}
