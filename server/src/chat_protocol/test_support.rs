//! Test support helpers for clean-chat protocol tests.
//!
//! Provides deterministic relationship projection fixtures and mock transports
//! without exposing production authority or relaxing crate-private visibility in
//! production binaries.

#[cfg(any(test, feature = "test-support"))]
pub use super::relationship_policy::AdmissionOperation;
#[cfg(any(test, feature = "test-support"))]
pub mod repository {
    pub use crate::chat_protocol::repository::delivery::AppendEntry;
    pub use crate::chat_protocol::repository::federation::*;
}
#[cfg(any(test, feature = "test-support"))]
pub async fn execute_creation_with_routing_test(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    pool: &sqlx::PgPool,
    runtime: &crate::handlers::chat::ChatRuntime,
    headers: &axum::http::HeaderMap,
    body: &[u8],
    routing: Option<super::federation_routing::ConversationRoutingIntent>,
) -> Result<(), String> {
    let admission = crate::handlers::chat::admit_signed_operation_for_test(
        pool,
        runtime,
        super::error::ChatEndpoint::CreateConversation,
        headers,
        body,
    )
    .await
    .map_err(|e| format!("admission error: {e:?}"))?;

    let prepared = super::repository::prelude::prepare_signed_operation(transaction, admission)
        .await
        .map_err(|e| format!("prelude error: {e:?}"))?;

    super::repository::creation::execute_prepared_creation(
        transaction,
        prepared,
        runtime.relationship_authority().as_ref(),
        routing,
    )
    .await
    .map_err(|e| format!("creation error: {e:?}"))?;

    Ok(())
}

#[cfg(any(test, feature = "test-support"))]
pub async fn cas_conversation_head_test(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    conversation_id: uuid::Uuid,
    expected_generation: i64,
    expected_state_version: i64,
    expected_next_entry_seq: i64,
    successor_generation: i64,
    successor_state_version: i64,
    successor_next_entry_seq: i64,
) -> Result<(), String> {
    let cas = super::repository::transition::ConversationHeadCas {
        conversation_id,
        expected_generation,
        expected_state_version,
        expected_next_entry_seq,
        successor_generation,
        successor_state_version,
        successor_next_entry_seq,
        close: None,
    };
    super::repository::transition::cas_conversation_head(transaction, &cas)
        .await
        .map_err(|e| format!("head CAS error: {e:?}"))
}
use super::relationship_policy::*;
#[cfg(any(test, feature = "test-support"))]
use super::repository::relationship::*;
#[cfg(any(test, feature = "test-support"))]
use serde_json::json;
#[cfg(any(test, feature = "test-support"))]
use sqlx::PgPool;

#[cfg(any(test, feature = "test-support"))]
#[derive(Clone, Copy)]
pub struct DeterministicTestTransport;

#[cfg(any(test, feature = "test-support"))]
#[async_trait::async_trait]
impl PublicTransport for DeterministicTestTransport {
    async fn get(&self, request: PublicGet) -> Result<PublicResponse, TransportError> {
        let path = request.url.path();
        if path.starts_with("/did:plc:") {
            let actor = path.trim_start_matches('/');
            return Ok(PublicResponse::json(
                200,
                json!({
                    "id": actor,
                    "service": [{
                        "id": format!("{actor}#atproto_pds"),
                        "type": "AtprotoPersonalDataServer",
                        "serviceEndpoint": "https://pds.example.net"
                    }]
                }),
            ));
        }
        if path == "/xrpc/com.atproto.repo.getRecord" {
            let actor = request
                .url
                .query_pairs()
                .find(|(k, _)| k == "repo")
                .map(|(_, v)| v.into_owned())
                .unwrap_or_default();
            return Ok(PublicResponse::json(
                200,
                json!({
                    "uri": format!("at://{actor}/chat.bsky.actor.declaration/self"),
                    "cid": "bafyreihdwdcefgh4dqkjv67uzcmw7ojee6xedzdetojuzjevtenxquvyku",
                    "value": {
                        "$type": "chat.bsky.actor.declaration",
                        "allowIncoming": "all",
                        "allowGroupInvites": "all"
                    }
                }),
            ));
        }
        if path == "/xrpc/app.bsky.graph.getRelationships" {
            let actor = request
                .url
                .query_pairs()
                .find(|(k, _)| k == "actor")
                .map(|(_, v)| v.into_owned())
                .unwrap_or_default();
            let others = request
                .url
                .query_pairs()
                .filter(|(k, _)| k == "others")
                .map(|(_, v)| {
                    json!({
                        "$type": "app.bsky.graph.defs#relationship",
                        "did": v,
                        "following": format!("at://{actor}/app.bsky.graph.follow/test")
                    })
                })
                .collect::<Vec<_>>();
            return Ok(PublicResponse::json(
                200,
                json!({"actor": actor, "relationships": others}),
            ));
        }
        panic!("unexpected public get: {}", request.url);
    }
}

pub async fn seed_deterministic_creation_fallback(
    pool: &PgPool,
    inviter: &str,
    mut roster: Vec<String>,
    pending_recipients: Vec<String>,
    operation: AdmissionOperation,
) -> Result<(), String> {
    let rel_authority = RelationshipAuthority::new(
        fixed_production_relationship_policy_config()
            .map_err(|e| format!("fixed config error: {e:?}"))?,
        DeterministicTestTransport,
    );
    roster.sort();
    let admission_req = AdmissionRequest {
        inviter: inviter.to_string(),
        roster,
        pending_recipients,
        operation,
    };
    let mut fallback_tx = pool
        .begin()
        .await
        .map_err(|e| format!("begin fallback tx: {e}"))?;
    let live_allocation = allocate_projection_revision(&mut fallback_tx)
        .await
        .map_err(|e| format!("allocate live revision: {e:?}"))?;
    let fallback_allocation = allocate_projection_revision(&mut fallback_tx)
        .await
        .map_err(|e| format!("allocate fallback revision: {e:?}"))?;
    let live_rel = rel_authority
        .collect_admission_projection(
            live_allocation,
            ProjectionOperationScope::Creation,
            admission_req,
        )
        .await
        .map_err(|e| format!("collect admission projection: {e:?}"))?;
    let observation = observe_relationship_persistence();
    let sealed_fallback = live_rel
        .export_persisted_fallback(fallback_allocation, &rel_authority, &observation)
        .map_err(|e| format!("seal fallback: {e:?}"))?;
    persist_relationship_projection(&mut fallback_tx, sealed_fallback)
        .await
        .map_err(|e| format!("persist fallback: {e:?}"))?;
    fallback_tx
        .commit()
        .await
        .map_err(|e| format!("commit fallback tx: {e}"))?;
    Ok(())
}

pub async fn seed_deterministic_pending_add_fallback(
    pool: &PgPool,
    inviter: &str,
    mut roster: Vec<String>,
    pending_recipients: Vec<String>,
) -> Result<(), String> {
    let rel_authority = RelationshipAuthority::new(
        fixed_production_relationship_policy_config()
            .map_err(|e| format!("fixed config error: {e:?}"))?,
        DeterministicTestTransport,
    );
    roster.sort();
    let admission_req = AdmissionRequest {
        inviter: inviter.to_string(),
        roster,
        pending_recipients,
        operation: AdmissionOperation::Group,
    };
    let mut fallback_tx = pool
        .begin()
        .await
        .map_err(|e| format!("begin fallback tx: {e}"))?;
    let live_allocation = allocate_projection_revision(&mut fallback_tx)
        .await
        .map_err(|e| format!("allocate live revision: {e:?}"))?;
    let fallback_allocation = allocate_projection_revision(&mut fallback_tx)
        .await
        .map_err(|e| format!("allocate fallback revision: {e:?}"))?;
    let live_rel = rel_authority
        .collect_admission_projection(
            live_allocation,
            ProjectionOperationScope::PendingAdd,
            admission_req,
        )
        .await
        .map_err(|e| format!("collect admission projection: {e:?}"))?;
    let observation = observe_relationship_persistence();
    let sealed_fallback = live_rel
        .export_persisted_fallback(fallback_allocation, &rel_authority, &observation)
        .map_err(|e| format!("seal fallback: {e:?}"))?;
    persist_relationship_projection(&mut fallback_tx, sealed_fallback)
        .await
        .map_err(|e| format!("persist fallback: {e:?}"))?;
    fallback_tx
        .commit()
        .await
        .map_err(|e| format!("commit fallback tx: {e}"))?;
    Ok(())
}
