//! Canonical S2S Relay and Coordination for blue.catbird.chat direct requests.
//!
//! Provides deterministic coordinator resolution, staged remote reservation,
//! authenticated XRPC relaying, remote Welcome/entry delivery, and acceptance/reply routing
//! across independent chat authorities with zero legacy fallback.

use super::{
    errors::FederationError,
    outbound::OutboundClient,
    receipt::{verify_control_receipt, I13ControlReceiptInput},
    resolver::{DsEndpoint, DsResolver},
    service_auth::ServiceAuthClient,
};
use crate::chat_protocol::validation::TrustedRequestInstant;
use crate::handlers::chat::ChatRuntime;
use crate::identity::canonical_did;
use crate::realtime::SseState;
use crate::storage::DbPool;
use base64::{
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
    Engine,
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use sqlx::{Postgres, Row, Transaction};
use std::sync::Arc;
use tracing::{debug, error, info, warn};
use uuid::Uuid;

/// Deterministic pair coordinator calculation.
///
/// A pair of account-home chat authority DIDs has ONE deterministic canonical coordinator,
/// the lexicographical minimum of their normalized authority DIDs, including opposite-direction sends.
#[derive(Debug, Clone)]
pub struct CanonicalPairCoordinator {
    pub sender_home: DsEndpoint,
    pub recipient_home: DsEndpoint,
    pub coordinator_did: String,
    pub is_coordinator: bool,
    pub is_sender_home: bool,
    pub is_recipient_home: bool,
}

impl CanonicalPairCoordinator {
    pub fn coordinator_endpoint(&self) -> &str {
        if canonical_did(&self.sender_home.did) == canonical_did(&self.coordinator_did) {
            &self.sender_home.endpoint
        } else {
            &self.recipient_home.endpoint
        }
    }
}

/// Resolve the deterministic pair coordinator for a sender and recipient pair.
pub async fn resolve_pair_coordinator(
    pool: &DbPool,
    sender_did: &str,
    recipient_did: &str,
) -> Result<CanonicalPairCoordinator, FederationError> {
    let resolver = pair_resolver(pool);

    let sender_home = resolver.resolve_authoritative_ds(sender_did).await?;
    let recipient_home = resolver.resolve_authoritative_ds(recipient_did).await?;
    Ok(pair_coordinator(&resolver, sender_home, recipient_home))
}

/// [`resolve_pair_coordinator`] for `prepareDirectRequest` (C33). The sender's
/// home must resolve. A recipient whose home does not is placed on this
/// authority's canonical path and its resolution error returned, so the caller
/// can keep an undeclared recipient or durably refuse an unusable declaration.
pub async fn resolve_prepare_pair_coordinator(
    pool: &DbPool,
    sender_did: &str,
    recipient_did: &str,
) -> Result<(CanonicalPairCoordinator, Option<FederationError>), FederationError> {
    let resolver = pair_resolver(pool);

    let sender_home = resolver.resolve_authoritative_ds(sender_did).await?;
    let (recipient_home, unresolved) = match resolver.resolve_authoritative_ds(recipient_did).await
    {
        Ok(home) => (home, None),
        Err(error) => (
            resolver
                .resolve_authority_ds_endpoint(resolver.self_did())
                .await?,
            Some(error),
        ),
    };
    Ok((
        pair_coordinator(&resolver, sender_home, recipient_home),
        unresolved,
    ))
}

fn pair_coordinator(
    resolver: &DsResolver,
    sender_home: DsEndpoint,
    recipient_home: DsEndpoint,
) -> CanonicalPairCoordinator {
    let sender_home_did = canonical_did(&sender_home.did).to_string();
    let recipient_home_did = canonical_did(&recipient_home.did).to_string();

    let coordinator_did = if sender_home_did <= recipient_home_did {
        sender_home_did.clone()
    } else {
        recipient_home_did.clone()
    };

    let is_coordinator = resolver.is_self(&coordinator_did);
    let is_sender_home = resolver.is_self(&sender_home_did);
    let is_recipient_home = resolver.is_self(&recipient_home_did);

    CanonicalPairCoordinator {
        sender_home,
        recipient_home,
        coordinator_did,
        is_coordinator,
        is_sender_home,
        is_recipient_home,
    }
}

fn pair_resolver(pool: &DbPool) -> DsResolver {
    let cache_ttl: u64 = std::env::var("ENDPOINT_CACHE_TTL")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(3600);
    DsResolver::with_default_endpoint(
        pool.clone(),
        super::resolver::build_resolver_http_client(),
        crate::identity::service_did(),
        crate::identity::self_endpoint(),
        std::env::var("DEFAULT_DS_ENDPOINT").ok(),
        cache_ttl,
    )
}

/// The coordinator a C33 transport-only home recorded for its pair, resolved
/// from that delivery service's own DID document under this DS's peer policy,
/// never re-derived from both parties' declarations: a deleted party's is
/// typically gone.
pub async fn resolve_recorded_coordinator(
    pool: &DbPool,
    coordinator_did: &str,
) -> Result<DsEndpoint, FederationError> {
    let resolver = pair_resolver(pool);
    let coordinator = resolver
        .resolve_authority_ds_endpoint(coordinator_did)
        .await?;
    if !resolver.is_self(&coordinator.did) {
        super::peer_policy::enforce_outbound_peer_policy(pool, &coordinator.did).await?;
    }
    Ok(coordinator)
}

/// Whether `did` has an `accountDeletedEntry` sequenced here in `conversation_id`.
/// A C33 coordinator delivers none of that conversation's later entries to such a
/// party's home, and decides so before resolving that home: a deleted account's
/// declaration is typically gone.
// `pub`: repository/acceptance.rs calls it, and the integration harness compiles that
// file into its own crate against this one.
pub async fn account_deleted_in<'e>(
    executor: impl sqlx::PgExecutor<'e>,
    conversation_id: Uuid,
    did: &str,
) -> Result<bool, sqlx::Error> {
    // Every control entry has a NULL `message_id`, so `entries_message_idx`
    // skips the conversation's applications.
    sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM chat.entries \
          WHERE conversation_id = $1 AND message_id IS NULL \
            AND entry_kind = 'blue.catbird.chat.defs#accountDeletedEntry' \
            AND actor_did = $2)",
    )
    .bind(conversation_id)
    .bind(did)
    .fetch_one(executor)
    .await
}

/// Durable, verifiable pair fence conflict classifications.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PairFenceConflict {
    ForeignCoordinator {
        coordinator_did: String,
        source: &'static str,
        status: String,
    },
    LocalConflict {
        source: &'static str,
        status: String,
    },
}

impl std::fmt::Display for PairFenceConflict {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PairFenceConflict::ForeignCoordinator {
                coordinator_did,
                source,
                status,
            } => {
                write!(f, "pair already owned by coordinator {coordinator_did} (source: {source}, status: {status})")
            }
            PairFenceConflict::LocalConflict { source, status } => {
                write!(
                    f,
                    "pair conflict exists (source: {source}, status: {status})"
                )
            }
        }
    }
}

/// Durable, verifiable pair owner fence across both authorities.
///
/// Verifies across all local and federated repository state that no active,
/// pending, or finalized pair already exists under another coordinator or conflicting attempt.
/// A sender home's outbound route binds its pair once the coordinator answered it; a route no
/// coordinator answered binds only until `binding_expires_at`, when no preparation its signed
/// prepare could produce is still live.
pub async fn check_pair_owner_fence(
    tx: &mut Transaction<'_, Postgres>,
    actor_did: &str,
    recipient_did: &str,
    request_id: Uuid,
    expected_coordinator_did: Option<&str>,
) -> Result<Option<PairFenceConflict>, FederationError> {
    let service_did = crate::identity::service_did();
    let row: Option<(Option<String>, String, String)> = sqlx::query_as(
        "SELECT coordinator_did, source_table, status FROM ( \
            SELECT \
                NULL::text AS coordinator_did, \
                'attempts'::text AS source_table, \
                a.status, \
                a.created_at \
            FROM chat.direct_request_attempts a \
            WHERE ((a.actor_did = $1 AND a.recipient_did = $2) OR (a.actor_did = $2 AND a.recipient_did = $1)) \
              AND a.request_id <> $3 \
              AND ( \
                  (a.status = 'prepared' AND a.lease_expires_at > $6) \
                  OR (a.status IN ('published', 'existing-direct') \
                      AND NOT EXISTS ( \
                          SELECT 1 FROM chat.direct_request_lifecycle l \
                          WHERE l.request_id = a.request_id \
                            AND l.consent IN ('expired', 'rejected', 'closed') \
                      )) \
              ) \
            UNION ALL \
            SELECT \
                NULL::text AS coordinator_did, \
                'conversations'::text AS source_table, \
                lifecycle AS status, \
                created_at \
            FROM chat.conversations c \
            WHERE c.kind = 'direct' \
              AND c.direct_did_low = LEAST($1 COLLATE \"C\", $2 COLLATE \"C\") \
              AND c.direct_did_high = GREATEST($1 COLLATE \"C\", $2 COLLATE \"C\") \
              AND c.lifecycle = 'active' \
              AND NOT EXISTS ( \
                  SELECT 1 FROM chat.direct_request_publications p \
                  WHERE p.conversation_id = c.conversation_id AND p.request_id = $3 \
              ) \
              AND NOT EXISTS ( \
                  SELECT 1 FROM chat.direct_request_transport_inbox t \
                  WHERE t.conversation_id = c.conversation_id AND t.request_id = $3 \
              ) \
            UNION ALL \
            SELECT \
                coordinator_did, \
                'transport_inbox'::text AS source_table, \
                status, \
                created_at \
            FROM chat.direct_request_transport_inbox \
            WHERE ((sender_did = $1 AND recipient_did = $2) OR (sender_did = $2 AND recipient_did = $1)) \
              AND request_id <> $3 \
              AND status IN ('pending', 'accepted') \
            UNION ALL \
            SELECT \
                r.coordinator_did, \
                'remote_leases'::text AS source_table, \
                r.status, \
                r.leased_at AS created_at \
            FROM chat.direct_request_remote_leases r \
            WHERE ((r.sender_did = $1 AND r.recipient_did = $2) OR (r.sender_did = $2 AND r.recipient_did = $1)) \
              AND r.request_id <> $3 \
              AND ( \
                  (r.status = 'active' AND r.expires_at > $6) \
                  OR (r.status = 'finalized' \
                      AND NOT EXISTS ( \
                          SELECT 1 FROM chat.direct_request_transport_inbox t \
                          WHERE t.request_id = r.request_id \
                            AND t.status IN ('expired', 'rejected', 'closed') \
                      )) \
              ) \
            UNION ALL \
            SELECT \
                o.coordinator_did, \
                'outbound_routes'::text AS source_table, \
                'routed'::text AS status, \
                o.created_at \
            FROM chat.direct_request_outbound_routes o \
            WHERE ((o.actor_did = $1 AND o.recipient_did = $2) OR (o.actor_did = $2 AND o.recipient_did = $1)) \
              AND o.request_id <> $3 \
              AND (o.binding_expires_at IS NULL OR o.binding_expires_at > $6) \
              AND NOT EXISTS ( \
                  SELECT 1 FROM chat.direct_request_lifecycle l \
                  WHERE l.request_id = o.request_id \
                    AND l.consent IN ('expired', 'rejected', 'closed') \
              ) \
              AND NOT EXISTS ( \
                  SELECT 1 FROM chat.direct_request_transport_inbox t \
                  WHERE t.request_id = o.request_id \
                    AND t.status IN ('expired', 'rejected', 'closed') \
              ) \
        ) AS pair_records \
        WHERE (source_table = 'attempts' AND status = 'prepared') \
           OR ($4::text IS NOT NULL AND split_part(coalesce(coordinator_did, $5), '#', 1) <> split_part($4, '#', 1)) \
        ORDER BY ($4::text IS NOT NULL AND split_part(coalesce(coordinator_did, $5), '#', 1) <> split_part($4, '#', 1)) DESC, created_at DESC \
        LIMIT 1"
    )
    .bind(actor_did)
    .bind(recipient_did)
    .bind(request_id)
    .bind(expected_coordinator_did)
    .bind(&service_did)
    .bind(crate::sim_hooks::current_utc())
    .fetch_optional(&mut **tx)
    .await
    .map_err(|e| FederationError::Storage(e.to_string()))?;

    let Some((coord_did_opt, source_table, status)) = row else {
        return Ok(None);
    };
    let effective_coord = coord_did_opt.as_deref().unwrap_or(&service_did);
    if let Some(expected) = expected_coordinator_did {
        if canonical_did(effective_coord) != canonical_did(expected) {
            return Ok(Some(PairFenceConflict::ForeignCoordinator {
                coordinator_did: effective_coord.to_owned(),
                source: match source_table.as_str() {
                    "transport_inbox" => "transport_inbox",
                    "remote_leases" => "remote_leases",
                    "outbound_routes" => "outbound_routes",
                    "conversations" => "conversations",
                    "attempts" => "attempts",
                    _ => "federated",
                },
                status,
            }));
        }
    }
    Ok(Some(PairFenceConflict::LocalConflict {
        source: match source_table.as_str() {
            "attempts" => "attempts",
            "conversations" => "conversations",
            "transport_inbox" => "transport_inbox",
            "remote_leases" => "remote_leases",
            _ => "local",
        },
        status,
    }))
}

/// Mint an authenticated S2S service token with explicit target audience and method NSID.
pub fn mint_s2s_auth_token(target_did: &str, method: &str) -> Result<String, FederationError> {
    let service_did = crate::identity::service_did();
    let signing_key_pem = configured_s2s_signing_key_pem()?;
    let client = ServiceAuthClient::from_es256_pem(service_did, signing_key_pem.as_bytes(), None)
        .map_err(|e| FederationError::ConfigError {
        reason: format!("ServiceAuthClient error: {e}"),
    })?;
    client
        .mint_token(target_did, method)
        .map_err(|e| FederationError::AuthFailed {
            reason: format!("mint S2S token error: {e}"),
        })
}

pub(crate) fn configured_s2s_signing_key_pem() -> Result<String, FederationError> {
    #[cfg(feature = "sim")]
    if let Some(hooks) = crate::sim_hooks::active_sim_ds() {
        if let Some(pem) = hooks
            .signing_key_pem
            .as_ref()
            .filter(|pem| !pem.trim().is_empty())
        {
            return Ok(pem.clone());
        }
    }
    std::env::var("SIGNING_KEY_PEM").map_err(|_| FederationError::ConfigError {
        reason: "SIGNING_KEY_PEM is required for S2S federation".to_string(),
    })
}

// ---------------------------------------------------------------------------
// DTOs for S2S Canonical Messages
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RemoteDeviceBootstrap {
    pub owner_did: String,
    pub owner_device_id: Uuid,
    pub owner_key_id: String,
    pub auth_generation: i64,
    pub grant_id: Uuid,
    pub grant_digest: String,
    pub capability_revision: i64,
    pub key_package_ref: String,
    pub wrapper_bytes: String,
    pub signed_grant: Value,
    pub expires_at: String,
    pub signature_public_key: String,
    pub signed_keys_publication: Value,
    pub publication_digest: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ReserveRecipientBootstrapInput {
    pub request_id: Uuid,
    pub sender_did: String,
    pub recipient_did: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signed_prepare: Option<Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub request_digest: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ReserveRecipientBootstrapOutput {
    pub selected_devices: Vec<RemoteDeviceBootstrap>,
}
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ReleaseRecipientBootstrapInput {
    pub request_id: Uuid,
    pub recipient_did: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DeliverDirectRequestInput {
    pub request_id: Uuid,
    pub conversation_id: Uuid,
    pub first_message_id: Uuid,
    pub entry: Value,
    pub deliveries: Vec<Value>,
    pub publication_receipt: Value,
    pub coordinator_did: String,
    #[serde(default)]
    pub full_welcome_bytes: Option<String>,
    #[serde(default)]
    pub signed_publication: Option<Value>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DeliverAcceptanceInput {
    pub conversation_id: Uuid,
    pub direct_request: Value,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DeliverAcceptanceOutput {
    pub outcome_bytes: String,
    pub entry: Value,
    pub acceptance_proof: Value,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DeliverAcceptanceEntryInput {
    pub conversation_id: Uuid,
    pub entry: Value,
    pub acceptance_proof: Value,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RelaySendMessageInput {
    pub conversation_id: Uuid,
    pub message: Value,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DeliverMessageEntryInput {
    pub conversation_id: Uuid,
    pub entry: Value,
}

// ---------------------------------------------------------------------------
// Outbound S2S Operations
// ---------------------------------------------------------------------------

/// A relayed direct-request call's failure, by class. The peer's own HTTP
/// answer keeps its status, so its 4xx stays a refusal. A closed gate, a
/// destination that cannot resolve now or no connection is retryable; a
/// destination or answer no retry cures (an invalid or blocked URL, NXDOMAIN,
/// a malformed response) is a refusal.
fn relay_error(
    endpoint: &str,
    method: &str,
    error: super::outbound::OutboundError,
) -> FederationError {
    use super::outbound::OutboundError as E;
    match error {
        E::RemoteError {
            status: 400,
            error_name: Some(error_name),
            ..
        } if error_name == "BlockedRelationship" => FederationError::BlockedRelationship,
        E::RemoteError {
            status: 409,
            error_name: Some(error_name),
            ..
        } if error_name == "StaleSend" => FederationError::StaleSend,
        E::RemoteError { status, body, .. } => FederationError::RemoteError { status, body },
        E::ResolutionFailed { did, kind } => FederationError::ResolutionFailed { did, kind },
        E::FederationDisabled { reason } => FederationError::FederationDisabled { reason },
        error if error.is_retryable() => FederationError::DsUnreachable {
            endpoint: endpoint.to_owned(),
            reason: format!("{method}: {error}"),
        },
        error => FederationError::InvalidRequest(format!("{method} failed: {error}")),
    }
}

/// `enqueue_c33_in_tx` at an S2S coordinator: a full outbound queue decided
/// nothing, so it is the retryable 503; a peer-policy refusal, a conflicting
/// replay and this database keep their own answers.
fn queue_full_unavailable(error: FederationError) -> FederationError {
    match error {
        FederationError::OutboundQueuePeerCapExceeded { .. }
        | FederationError::OutboundQueueConvoPeerCapExceeded { .. } => {
            FederationError::RemoteError {
                status: 503,
                body: error.to_string(),
            }
        }
        other => other,
    }
}

pub async fn reserve_remote_recipient_bootstrap(
    pool: &DbPool,
    endpoint: &str,
    target_did: &str,
    request_id: Uuid,
    sender_did: &str,
    recipient_did: &str,
    signed_prepare: Option<Value>,
) -> Result<Vec<RemoteDeviceBootstrap>, FederationError> {
    // Mandatory durable intent and identity fence before making outbound RPC
    let actor_device_id_opt: Option<Uuid> = signed_prepare.as_ref().and_then(|p| {
        p.pointer("/body/actorDeviceId")
            .or_else(|| p.get("actorDeviceId"))
            .and_then(|v| v.as_str())
            .and_then(|s| Uuid::parse_str(s).ok())
    });

    // Mandatory durable intent and identity fence before making outbound RPC
    let existing_intent: Option<(String, Option<Uuid>, String, String, String)> = sqlx::query_as(
        "SELECT actor_did, actor_device_id, recipient_did, recipient_ds_did, status \
         FROM chat.direct_request_reservation_intents \
         WHERE request_id = $1",
    )
    .bind(request_id)
    .fetch_optional(pool)
    .await
    .map_err(|e| FederationError::Storage(format!("intent check failed: {e}")))?;

    if let Some((existing_actor, existing_dev, existing_rec, existing_ds, status)) = existing_intent
    {
        if canonical_did(&existing_actor) != canonical_did(sender_did)
            || canonical_did(&existing_rec) != canonical_did(recipient_did)
            || canonical_did(&existing_ds) != canonical_did(target_did)
            || (actor_device_id_opt.is_some()
                && existing_dev.is_some()
                && actor_device_id_opt != existing_dev)
        {
            return Err(FederationError::InvalidRequest(format!(
                "request_id {request_id} re-used with conflicting intent identity ({existing_actor} -> {existing_rec} @ {existing_ds})"
            )));
        }
        if status == "cancelled" {
            return Err(FederationError::InvalidRequest(format!(
                "reservation intent for request_id {request_id} was already cancelled"
            )));
        }
    } else {
        sqlx::query(
            "INSERT INTO chat.direct_request_reservation_intents (request_id, actor_did, actor_device_id, recipient_did, recipient_ds_did, status, created_at) \
             VALUES ($1, $2, $3, $4, $5, 'pending', $6)"
        )
        .bind(request_id)
        .bind(sender_did)
        .bind(actor_device_id_opt)
        .bind(recipient_did)
        .bind(target_did)
        .bind(crate::sim_hooks::current_utc())
        .execute(pool)
        .await
        .map_err(|e| FederationError::Storage(format!("mandatory intent insertion failed: {e}")))?;
    }

    let request_digest = signed_prepare.as_ref().and_then(|p| {
        serde_json::to_vec(p)
            .ok()
            .map(|b| hex::encode(Sha256::digest(&b)))
    });

    let token = mint_s2s_auth_token(target_did, "blue.catbird.mlsDS.reserveRecipientBootstrap")?;
    let outbound = OutboundClient::new(5, 15);
    let input = ReserveRecipientBootstrapInput {
        request_id,
        sender_did: sender_did.to_string(),
        recipient_did: recipient_did.to_string(),
        signed_prepare,
        request_digest,
    };
    let resp = outbound
        .call_procedure_json(
            endpoint,
            "blue.catbird.mlsDS.reserveRecipientBootstrap",
            &token,
            &input,
        )
        .await
        .map_err(|e| relay_error(endpoint, "reserveRecipientBootstrap", e))?;
    let output: ReserveRecipientBootstrapOutput = serde_json::from_value(resp).map_err(|e| {
        FederationError::InvalidRequest(format!(
            "malformed reserveRecipientBootstrap response: {e}"
        ))
    })?;
    Ok(output.selected_devices)
}
pub async fn release_remote_recipient_bootstrap(
    pool: &DbPool,
    endpoint: &str,
    target_did: &str,
    request_id: Uuid,
    recipient_did: &str,
) -> Result<(), FederationError> {
    sqlx::query(
        "UPDATE chat.direct_request_reservation_intents SET status = 'cancelled' WHERE request_id = $1"
    )
    .bind(request_id)
    .execute(pool)
    .await
    .map_err(|e| FederationError::Storage(format!("cancel intent failed: {e}")))?;

    sqlx::query("DELETE FROM chat.direct_request_reserved_remote_packages WHERE request_id = $1")
        .bind(request_id)
        .execute(pool)
        .await
        .map_err(|e| FederationError::Storage(format!("clear reserved packages failed: {e}")))?;

    let token = mint_s2s_auth_token(target_did, "blue.catbird.mlsDS.releaseRecipientBootstrap")?;
    let outbound = OutboundClient::new(5, 15);
    let input = ReleaseRecipientBootstrapInput {
        request_id,
        recipient_did: recipient_did.to_string(),
    };
    outbound
        .call_procedure_json(
            endpoint,
            "blue.catbird.mlsDS.releaseRecipientBootstrap",
            &token,
            &input,
        )
        .await
        .map_err(|e| relay_error(endpoint, "releaseRecipientBootstrap", e))?;
    Ok(())
}

pub async fn relay_prepare_direct_request(
    endpoint: &str,
    target_did: &str,
    payload_or_request: &Value,
) -> Result<Value, FederationError> {
    let token = mint_s2s_auth_token(target_did, "blue.catbird.mlsDS.prepareDirectRequest")?;
    let outbound = OutboundClient::new(5, 15);
    let payload = if payload_or_request.get("signedRequest").is_some() {
        payload_or_request.clone()
    } else {
        json!({ "signedRequest": payload_or_request })
    };
    outbound
        .call_procedure_json(
            endpoint,
            "blue.catbird.mlsDS.prepareDirectRequest",
            &token,
            &payload,
        )
        .await
        .map_err(|e| relay_error(endpoint, "prepareDirectRequest", e))
}

pub async fn relay_publish_direct_request(
    endpoint: &str,
    target_did: &str,
    signed_request: &Value,
) -> Result<Value, FederationError> {
    let token = mint_s2s_auth_token(target_did, "blue.catbird.mlsDS.publishDirectRequest")?;
    let outbound = OutboundClient::new(10, 30);
    let payload = json!({ "signedRequest": signed_request });
    outbound
        .call_procedure_json(
            endpoint,
            "blue.catbird.mlsDS.publishDirectRequest",
            &token,
            &payload,
        )
        .await
        .map_err(|e| relay_error(endpoint, "publishDirectRequest", e))
}

pub async fn deliver_direct_request_to_peer(
    endpoint: &str,
    target_did: &str,
    payload: DeliverDirectRequestInput,
) -> Result<(), FederationError> {
    let token = mint_s2s_auth_token(target_did, "blue.catbird.mlsDS.deliverDirectRequest")?;
    let outbound = OutboundClient::new(10, 30);
    outbound
        .call_procedure_json(
            endpoint,
            "blue.catbird.mlsDS.deliverDirectRequest",
            &token,
            &payload,
        )
        .await
        .map_err(|e| relay_error(endpoint, "deliverDirectRequest", e))?;
    Ok(())
}

pub async fn relay_acceptance_to_coordinator(
    endpoint: &str,
    target_did: &str,
    payload: DeliverAcceptanceInput,
) -> Result<DeliverAcceptanceOutput, FederationError> {
    let token = mint_s2s_auth_token(target_did, "blue.catbird.mlsDS.deliverAcceptance")?;
    let outbound = OutboundClient::new(5, 15);
    let resp = outbound
        .call_procedure_json(
            endpoint,
            "blue.catbird.mlsDS.deliverAcceptance",
            &token,
            &payload,
        )
        .await
        .map_err(|e| relay_error(endpoint, "deliverAcceptance", e))?;
    serde_json::from_value(resp).map_err(|e| {
        FederationError::InvalidRequest(format!("malformed deliverAcceptance response: {e}"))
    })
}

pub async fn deliver_acceptance_entry_to_peer(
    endpoint: &str,
    target_did: &str,
    payload: DeliverAcceptanceEntryInput,
) -> Result<(), FederationError> {
    let token = mint_s2s_auth_token(target_did, "blue.catbird.mlsDS.deliverAcceptanceEntry")?;
    let outbound = OutboundClient::new(5, 15);
    outbound
        .call_procedure_json(
            endpoint,
            "blue.catbird.mlsDS.deliverAcceptanceEntry",
            &token,
            &payload,
        )
        .await
        .map_err(|e| relay_error(endpoint, "deliverAcceptanceEntry", e))?;
    Ok(())
}

pub async fn relay_message_to_coordinator(
    endpoint: &str,
    target_did: &str,
    payload: RelaySendMessageInput,
) -> Result<Value, FederationError> {
    let token = mint_s2s_auth_token(target_did, "blue.catbird.mlsDS.relaySendMessage")?;
    let outbound = OutboundClient::new(5, 15);
    outbound
        .call_procedure_json(
            endpoint,
            "blue.catbird.mlsDS.relaySendMessage",
            &token,
            &payload,
        )
        .await
        .map_err(|e| relay_error(endpoint, "relaySendMessage", e))
}

pub async fn deliver_message_entry_to_peer(
    endpoint: &str,
    target_did: &str,
    payload: DeliverMessageEntryInput,
) -> Result<(), FederationError> {
    let token = mint_s2s_auth_token(target_did, "blue.catbird.mlsDS.deliverMessageEntry")?;
    let outbound = OutboundClient::new(5, 15);
    outbound
        .call_procedure_json(
            endpoint,
            "blue.catbird.mlsDS.deliverMessageEntry",
            &token,
            &payload,
        )
        .await
        .map_err(|e| relay_error(endpoint, "deliverMessageEntry", e))?;
    Ok(())
}

pub async fn relay_get_outcome(
    endpoint: &str,
    target_did: &str,
    request_id: Uuid,
    actor_device_id: Uuid,
) -> Result<Value, FederationError> {
    let token = mint_s2s_auth_token(target_did, "blue.catbird.mlsDS.getDirectRequestOutcome")?;
    let outbound = OutboundClient::new(5, 15);
    let req_str = request_id.to_string();
    let dev_str = actor_device_id.to_string();
    let params = [
        ("requestId", req_str.as_str()),
        ("actorDeviceId", dev_str.as_str()),
    ];
    outbound
        .call_query_json_validated(
            endpoint,
            "blue.catbird.mlsDS.getDirectRequestOutcome",
            &token,
            &params,
        )
        .await
        .map_err(|e| relay_error(endpoint, "getDirectRequestOutcome", e))
}

// ---------------------------------------------------------------------------
// Local Staging and Ingestion
// ---------------------------------------------------------------------------

/// Resolve recipient key authority before opening the staging transaction.
pub(crate) async fn resolve_remote_recipient_device_keys(
    pool: &DbPool,
    recipient_did: &str,
) -> Result<Vec<Vec<u8>>, FederationError> {
    let resolver = DsResolver::with_default_endpoint(
        pool.clone(),
        super::resolver::build_resolver_http_client(),
        crate::identity::service_did(),
        crate::identity::self_endpoint(),
        None,
        0,
    );
    let keys = resolver
        .resolve_authorized_device_keys(recipient_did)
        .await?;
    if keys.is_empty() {
        return Err(FederationError::Forbidden(
            "recipient PDS authorizes no MLS device keys".into(),
        ));
    }
    Ok(keys)
}

/// The key `key_id` names among `actor_did`'s PDS-authorized device keys, or
/// `None` when its PDS answered without it (rotated after commit: the lease's
/// retained proof decides). A failed lookup is returned typed, retryable while
/// the PDS cannot answer, and never read as an empty key set.
pub(super) async fn live_actor_key(
    resolver: &DsResolver,
    actor_did: &str,
    key_id: &str,
) -> Result<Option<Vec<u8>>, FederationError> {
    Ok(resolver
        .resolve_authorized_device_keys(actor_did)
        .await?
        .into_iter()
        .find(|k| {
            URL_SAFE_NO_PAD.encode(Sha256::digest(k)) == key_id
                || STANDARD.encode(k) == key_id
                || crate::chat_protocol::validation::ed25519_key_id(k)
                    .map(|id| id.as_str() == key_id)
                    .unwrap_or(false)
        }))
}

/// Stage remote recipient device packages using authority resolved before the transaction.
///
/// Cryptographically verifies Ed25519 thumbprint, signed grant, and MLS KeyPackage
/// before atomically inserting into coordinator repository tables. No network or
/// second pool connection may be used while the transaction is held.
pub async fn stage_remote_recipient_devices(
    tx: &mut Transaction<'_, Postgres>,
    request_id: Uuid,
    devices: &[RemoteDeviceBootstrap],
    authorized_keys: &[Vec<u8>],
    now: DateTime<Utc>,
) -> Result<(), FederationError> {
    let recipient_did = devices
        .first()
        .ok_or_else(|| {
            FederationError::InvalidRequest("recipient home selected no devices".into())
        })?
        .owner_did
        .as_str();
    if authorized_keys.is_empty() {
        return Err(FederationError::Forbidden(
            "recipient PDS authorizes no MLS device keys".into(),
        ));
    }
    for b in devices {
        if b.owner_did != recipient_did {
            return Err(FederationError::InvalidRequest(
                "recipient bootstrap mixes account DIDs".into(),
            ));
        }
        let pub_key_bytes = STANDARD.decode(&b.signature_public_key).map_err(|e| {
            FederationError::InvalidRequest(format!("invalid signature_public_key base64: {e}"))
        })?;
        if !authorized_keys.iter().any(|key| key == &pub_key_bytes) {
            return Err(FederationError::Forbidden(
                "recipient key is not authorized by the PDS".into(),
            ));
        }
        let wrapper = STANDARD.decode(&b.wrapper_bytes).map_err(|e| {
            FederationError::InvalidRequest(format!("invalid wrapper_bytes base64: {e}"))
        })?;
        let expected_key_ref = STANDARD.decode(&b.key_package_ref).map_err(|e| {
            FederationError::InvalidRequest(format!("invalid key_package_ref base64: {e}"))
        })?;

        // 1. Verify device key ID thumbprint
        let calculated_key_id = crate::chat_protocol::validation::ed25519_key_id(&pub_key_bytes)
            .map_err(|e| {
                FederationError::InvalidRequest(format!("invalid ed25519 public key: {e:?}"))
            })?;
        if calculated_key_id.as_str() != b.owner_key_id {
            return Err(FederationError::InvalidRequest(
                "keyId does not match public key thumbprint".into(),
            ));
        }

        let dev_id_str = b.owner_device_id.to_string();

        // 2. Verify signed Keys publication
        let signed_keys_bytes =
            serde_json::to_vec(&b.signed_keys_publication).map_err(FederationError::Json)?;
        let verified_keys = crate::chat_protocol::direct_request_transcript::verify_signed_request(
            crate::chat_protocol::direct_request_transcript::DirectRequestKind::Keys,
            &signed_keys_bytes,
            &pub_key_bytes,
        )
        .map_err(|e| {
            FederationError::InvalidRequest(format!(
                "keys publication signature verification failed: {e:?}"
            ))
        })?;

        if verified_keys.actor_did() != Some(b.owner_did.as_str())
            || verified_keys.actor_device_id() != Some(dev_id_str.as_str())
            || verified_keys.key_id() != b.owner_key_id.as_str()
            || verified_keys.auth_generation() != Some(b.auth_generation as u64)
        {
            return Err(FederationError::InvalidRequest(
                "keys publication actor identity mismatch".into(),
            ));
        }

        let pub_digest_bytes = STANDARD.decode(&b.publication_digest).map_err(|e| {
            FederationError::InvalidRequest(format!("invalid publication_digest base64: {e}"))
        })?;
        if pub_digest_bytes.len() != 32
            || pub_digest_bytes.as_slice() != verified_keys.request_digest()
        {
            return Err(FederationError::InvalidRequest(
                "publication digest mismatch".into(),
            ));
        }
        let keys_body = verified_keys.body();
        if keys_body.get("revision").and_then(|v| v.as_i64()) != Some(b.capability_revision) {
            return Err(FederationError::InvalidRequest(
                "keys publication revision mismatch".into(),
            ));
        }
        if keys_body.get("enabled").and_then(|v| v.as_bool()) != Some(true) {
            return Err(FederationError::InvalidRequest(
                "keys publication not enabled".into(),
            ));
        }

        // 3. Verify signed grant
        let signed_grant_bytes =
            serde_json::to_vec(&b.signed_grant).map_err(FederationError::Json)?;
        let verified_grant =
            crate::chat_protocol::direct_request_transcript::verify_signed_request(
                crate::chat_protocol::direct_request_transcript::DirectRequestKind::Grant,
                &signed_grant_bytes,
                &pub_key_bytes,
            )
            .map_err(|e| {
                FederationError::InvalidRequest(format!(
                    "grant signature verification failed: {e:?}"
                ))
            })?;

        if verified_grant.actor_did() != Some(b.owner_did.as_str())
            || verified_grant.actor_device_id() != Some(dev_id_str.as_str())
            || verified_grant.key_id() != b.owner_key_id.as_str()
            || verified_grant.auth_generation() != Some(b.auth_generation as u64)
        {
            return Err(FederationError::InvalidRequest(
                "grant actor identity mismatch".into(),
            ));
        }

        let grant_digest_bytes = STANDARD.decode(&b.grant_digest).map_err(|e| {
            FederationError::InvalidRequest(format!("invalid grant_digest base64: {e}"))
        })?;
        if grant_digest_bytes.len() != 32
            || grant_digest_bytes.as_slice() != verified_grant.request_digest()
        {
            return Err(FederationError::InvalidRequest(
                "grant digest mismatch".into(),
            ));
        }

        let grant_body = verified_grant.body();
        let grant_pkg_ref_str = grant_body
            .get("keyPackageRef")
            .and_then(|v| v.as_str())
            .ok_or_else(|| FederationError::InvalidRequest("grant missing keyPackageRef".into()))?;
        let grant_pkg_ref = STANDARD.decode(grant_pkg_ref_str).map_err(|e| {
            FederationError::InvalidRequest(format!("invalid grant keyPackageRef base64: {e}"))
        })?;
        if grant_pkg_ref != expected_key_ref {
            return Err(FederationError::InvalidRequest(
                "grant keyPackageRef does not bind to KeyPackage".into(),
            ));
        }

        let grant_sha256_str = grant_body
            .get("keyPackageSha256")
            .and_then(|v| v.as_str())
            .ok_or_else(|| {
                FederationError::InvalidRequest("grant missing keyPackageSha256".into())
            })?;
        let grant_sha256 = STANDARD.decode(grant_sha256_str).map_err(|e| {
            FederationError::InvalidRequest(format!("invalid grant keyPackageSha256 base64: {e}"))
        })?;
        if grant_sha256 != Sha256::digest(&wrapper).as_slice() {
            return Err(FederationError::InvalidRequest(
                "grant keyPackageSha256 mismatch".into(),
            ));
        }
        // Verify that the grant and key package are present in the signed keys publication
        let keys_array = keys_body
            .get("keys")
            .and_then(|v| v.as_array())
            .ok_or_else(|| {
                FederationError::InvalidRequest("keys publication missing keys array".into())
            })?;

        let grant_id_str = b.grant_id.to_string();
        let _matching_key_entry = keys_array
            .iter()
            .find(|k| {
                let pkg_ref_match = k
                    .pointer("/keyPackage/keyPackageRef")
                    .and_then(|v| v.as_str())
                    == Some(b.key_package_ref.as_str());
                let grant_id_match = k.pointer("/grant/body/grantId").and_then(|v| v.as_str())
                    == Some(&grant_id_str);
                pkg_ref_match && grant_id_match
            })
            .ok_or_else(|| {
                FederationError::InvalidRequest(format!(
                    "grant {} with keyPackageRef {} not found in signed keys publication",
                    b.grant_id, b.key_package_ref
                ))
            })?;

        let grant_rev = grant_body
            .get("revision")
            .and_then(|v| v.as_i64())
            .unwrap_or(1);
        let grant_purpose = grant_body
            .get("purpose")
            .and_then(|v| v.as_str())
            .unwrap_or("direct-request-bootstrap");
        let grant_proto = grant_body
            .get("protocolVersion")
            .and_then(|v| v.as_str())
            .unwrap_or("2");
        let grant_profile = grant_body
            .get("profile")
            .and_then(|v| v.as_str())
            .unwrap_or("encryptedIntroduction1");

        // 4. Verify MLS KeyPackage wrapper
        let bare_did = crate::chat_protocol::validation::BareDid::parse(&b.owner_did)
            .map_err(|_| FederationError::InvalidRequest("invalid owner DID".into()))?;
        let canon_device_id = crate::chat_protocol::validation::CanonicalUuidV4::parse(&dev_id_str)
            .map_err(|_| FederationError::InvalidRequest("invalid device UUID".into()))?;
        let credential = crate::chat_protocol::validation::basic_credential_identity(
            &bare_did,
            &canon_device_id,
        );

        let valid_pkg = crate::chat_protocol::wire::validate_direct_request_key_package(
            &wrapper,
            crate::chat_protocol::wire::KeyPackageValidationPolicy {
                expected_basic_credential: &credential,
                expected_signature_key: &pub_key_bytes,
                now_unix_seconds: now.timestamp() as u64,
                max_bytes: 65536,
            },
        )
        .map_err(|e| {
            FederationError::InvalidRequest(format!("KeyPackage validation failed: {e:?}"))
        })?;

        if grant_body.get("grantId").and_then(|v| v.as_str()) != Some(&b.grant_id.to_string()) {
            return Err(FederationError::InvalidRequest("grantId mismatch".into()));
        }
        let signed_expiry = grant_body
            .get("expiresAt")
            .and_then(|v| v.as_str())
            .and_then(|value| DateTime::parse_from_rfc3339(value).ok());
        let selected_expiry = DateTime::parse_from_rfc3339(&b.expires_at).ok();
        if signed_expiry.is_none()
            || selected_expiry.is_none()
            || selected_expiry > signed_expiry
            || selected_expiry.is_some_and(|expiry| expiry <= now)
        {
            return Err(FederationError::InvalidRequest(
                "selected import horizon exceeds signed grant or is expired".into(),
            ));
        }

        if valid_pkg.key_package_ref() != expected_key_ref.as_slice() {
            return Err(FederationError::InvalidRequest(
                "KeyPackage ref mismatch".into(),
            ));
        }

        // 5. Fail-closed temporal bounds
        let expires_at = DateTime::parse_from_rfc3339(&b.expires_at)
            .map_err(|e| {
                FederationError::InvalidRequest(format!("invalid expires_at format: {e}"))
            })?
            .with_timezone(&Utc);
        if expires_at <= now {
            return Err(FederationError::InvalidRequest("grant is expired".into()));
        }

        let not_before =
            DateTime::from_timestamp(valid_pkg.not_before() as i64, 0).ok_or_else(|| {
                FederationError::InvalidRequest("invalid not_before timestamp".into())
            })?;
        let not_after = DateTime::from_timestamp(valid_pkg.not_after() as i64, 0)
            .ok_or_else(|| FederationError::InvalidRequest("invalid not_after timestamp".into()))?;
        if not_after <= now {
            return Err(FederationError::InvalidRequest(
                "KeyPackage is expired".into(),
            ));
        }

        // Use the same immutable activation history as group directory staging.
        super::group_relay::stage_verified_remote_device(
            tx,
            &b.owner_did,
            b.owner_device_id,
            &b.owner_key_id,
            b.auth_generation,
            &pub_key_bytes,
            now,
        )
        .await?;

        sqlx::query(
            "INSERT INTO chat.direct_request_capabilities (owner_did, owner_device_id, owner_key_id, auth_generation, revision, enabled, protocol_version, signed_publication, publication_digest, updated_at) \
             VALUES ($1, $2, $3, $4, $5, true, '2', $6, $7, $8) \
             ON CONFLICT (owner_did, owner_device_id) DO UPDATE SET \
                owner_key_id = EXCLUDED.owner_key_id, \
                auth_generation = EXCLUDED.auth_generation, \
                revision = EXCLUDED.revision, \
                enabled = EXCLUDED.enabled, \
                signed_publication = EXCLUDED.signed_publication, \
                publication_digest = EXCLUDED.publication_digest, \
                updated_at = EXCLUDED.updated_at \
             WHERE chat.direct_request_capabilities.revision <= EXCLUDED.revision"
        )
        .bind(&b.owner_did)
        .bind(b.owner_device_id)
        .bind(&b.owner_key_id)
        .bind(b.auth_generation)
        .bind(b.capability_revision)
        .bind(&signed_keys_bytes)
        .bind(&pub_digest_bytes)
        .bind(now)
        .execute(&mut **tx)
        .await
        .map_err(|e| FederationError::Storage(e.to_string()))?;

        sqlx::query(
            "INSERT INTO chat.key_packages (key_package_ref, wrapper_bytes, wrapper_sha256, init_key, owner_did, owner_device_id, owner_key_id, owner_auth_generation, not_before, not_after, status, created_at, usage_scope) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, 'available', $11, 'direct-request') \
             ON CONFLICT (key_package_ref) DO NOTHING"
        )
        .bind(&expected_key_ref)
        .bind(&wrapper)
        .bind(Sha256::digest(&wrapper).as_slice())
        .bind(valid_pkg.init_key())
        .bind(&b.owner_did)
        .bind(b.owner_device_id)
        .bind(&b.owner_key_id)
        .bind(b.auth_generation)
        .bind(not_before)
        .bind(not_after)
        .bind(now)
        .execute(&mut **tx)
        .await
        .map_err(|e| FederationError::Storage(e.to_string()))?;

        sqlx::query(
            "INSERT INTO chat.direct_request_grants (grant_id, revision, owner_did, owner_device_id, owner_key_id, auth_generation, capability_revision, key_package_ref, purpose, protocol_version, profile, signed_grant, grant_digest, expires_at, created_at) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15) \
             ON CONFLICT (grant_id) DO NOTHING"
        )
        .bind(b.grant_id)
        .bind(grant_rev)
        .bind(&b.owner_did)
        .bind(b.owner_device_id)
        .bind(&b.owner_key_id)
        .bind(b.auth_generation)
        .bind(b.capability_revision)
        .bind(&expected_key_ref)
        .bind(grant_purpose)
        .bind(grant_proto)
        .bind(grant_profile)
        .bind(&signed_grant_bytes)
        .bind(&grant_digest_bytes)
        .bind(expires_at)
        .bind(now)
        .execute(&mut **tx)
        .await
        .map_err(|e| FederationError::Storage(e.to_string()))?;
        sqlx::query(
            "INSERT INTO chat.direct_request_reserved_remote_packages (request_id, owner_did, owner_device_id, key_package_ref, created_at) \
             VALUES ($1, $2, $3, $4, $5) \
             ON CONFLICT (request_id, owner_device_id, key_package_ref) DO NOTHING"
        )
        .bind(request_id)
        .bind(&b.owner_did)
        .bind(b.owner_device_id)
        .bind(&expected_key_ref)
        .bind(now)
        .execute(&mut **tx)
        .await
        .map_err(|e| FederationError::Storage(e.to_string()))?;
    }
    Ok(())
}

/// Reserve recipient bootstrap packages locally on the recipient's home DS.
///
/// Direct-request packages stay in 'available' status with a request-bound lease
/// in `chat.direct_request_remote_leases` to avoid deferred trigger violations.
pub async fn local_reserve_recipient_bootstrap(
    pool: &DbPool,
    requester_ds: &str,
    input: &ReserveRecipientBootstrapInput,
) -> Result<Vec<RemoteDeviceBootstrap>, FederationError> {
    let coord = resolve_pair_coordinator(pool, &input.sender_did, &input.recipient_did).await?;
    if !coord.is_recipient_home {
        return Err(FederationError::Forbidden(
            "Local node is not recipient home DS".into(),
        ));
    }
    if canonical_did(&coord.coordinator_did) != canonical_did(requester_ds) {
        return Err(FederationError::AuthFailed {
            reason: format!(
                "Requester {requester_ds} is not resolved coordinator {}",
                coord.coordinator_did
            ),
        });
    }

    // C33-LEASE-003: Require and independently verify actor signed prepare
    let signed_prep = input.signed_prepare.as_ref().ok_or_else(|| {
        FederationError::InvalidRequest(
            "signedPrepare is required for remote bootstrap reservation".into(),
        )
    })?;
    let sender_device_id_opt: Option<Uuid> = signed_prep
        .pointer("/body/actorDeviceId")
        .or_else(|| signed_prep.get("actorDeviceId"))
        .and_then(|v| v.as_str())
        .and_then(|s| Uuid::parse_str(s).ok());
    let actor_did = signed_prep
        .pointer("/body/actorDid")
        .and_then(|v| v.as_str())
        .ok_or_else(|| {
            FederationError::InvalidRequest("missing actorDid in signedPrepare".into())
        })?;
    let rec_did = signed_prep
        .pointer("/body/recipientDid")
        .or_else(|| signed_prep.get("recipientDid"))
        .and_then(|v| v.as_str())
        .ok_or_else(|| {
            FederationError::InvalidRequest("missing recipientDid in signedPrepare".into())
        })?;
    let req_id_str = signed_prep
        .pointer("/body/requestId")
        .or_else(|| signed_prep.get("requestId"))
        .and_then(|v| v.as_str())
        .ok_or_else(|| {
            FederationError::InvalidRequest("missing requestId in signedPrepare".into())
        })?;

    if canonical_did(actor_did) != canonical_did(&input.sender_did)
        || canonical_did(rec_did) != canonical_did(&input.recipient_did)
        || req_id_str != input.request_id.to_string()
    {
        return Err(FederationError::InvalidRequest(
            "signedPrepare does not match reservation input".into(),
        ));
    }

    let http = super::resolver::build_resolver_http_client();
    let resolver = DsResolver::with_default_endpoint(
        pool.clone(),
        http,
        crate::identity::service_did(),
        crate::identity::self_endpoint(),
        std::env::var("DEFAULT_DS_ENDPOINT").ok(),
        3600,
    );
    let authorized_keys = resolver
        .resolve_authorized_device_keys(&input.sender_did)
        .await?;
    let prep_key_id = signed_prep
        .pointer("/body/keyId")
        .and_then(|v| v.as_str())
        .unwrap_or_default();
    let matching_key = authorized_device_key(&authorized_keys, prep_key_id).ok_or_else(|| {
        FederationError::Forbidden(format!("sender key {prep_key_id} is not authorized by PDS"))
    })?;

    let signed_prep_bytes = serde_json::to_vec(signed_prep).map_err(FederationError::Json)?;
    crate::chat_protocol::direct_request_transcript::verify_signed_request(
        crate::chat_protocol::direct_request_transcript::DirectRequestKind::Prepare,
        &signed_prep_bytes,
        matching_key,
    )
    .map_err(|e| {
        FederationError::InvalidRequest(format!(
            "signedPrepare signature verification failed: {e:?}"
        ))
    })?;

    if let Some(expected_digest) = &input.request_digest {
        let actual_hex = hex::encode(Sha256::digest(&signed_prep_bytes));
        let actual_b64 = STANDARD.encode(Sha256::digest(&signed_prep_bytes));
        if expected_digest != &actual_hex && expected_digest != &actual_b64 {
            return Err(FederationError::InvalidRequest(
                "requestDigest mismatch".into(),
            ));
        }
    }

    let sender_signing_key_bytes = matching_key;
    let prepare_digest_bytes = Sha256::digest(&signed_prep_bytes).to_vec();
    let mut tx = pool
        .begin()
        .await
        .map_err(|e| FederationError::Storage(e.to_string()))?;
    let (p1, p2) = if input.sender_did <= input.recipient_did {
        (&input.sender_did, &input.recipient_did)
    } else {
        (&input.recipient_did, &input.sender_did)
    };
    let pair_lock_key = format!("chat-direct-request-pair:{p1}:{p2}");
    sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1, 0))")
        .bind(&pair_lock_key)
        .execute(&mut *tx)
        .await
        .map_err(|e| FederationError::Storage(e.to_string()))?;

    if let Some(conflict) = check_pair_owner_fence(
        &mut tx,
        &input.sender_did,
        &input.recipient_did,
        input.request_id,
        Some(requester_ds),
    )
    .await?
    {
        if let PairFenceConflict::ForeignCoordinator {
            coordinator_did, ..
        } = conflict
        {
            return Err(FederationError::RemoteError {
                status: 409,
                body: format!(
                    "{{\"error\":\"PreparationConflict\",\"message\":\"Direct request or pair already owned by coordinator {coordinator_did}\"}}"
                ),
            });
        }
    }

    // ponytail: global advisory xact lock for remote lease capacity and idempotency; per-peer locks if throughput matters
    sqlx::query(
        "SELECT pg_advisory_xact_lock(hashtextextended('chat.direct_request_remote_leases', 0))",
    )
    .execute(&mut *tx)
    .await
    .map_err(|e| FederationError::Storage(e.to_string()))?;
    // C33-LEASE-003: Immutable exact request identity and digest check on replay
    let existing_lease_meta: Option<(String, String, Option<Uuid>, Option<Vec<u8>>)> =
        sqlx::query_as(
            "SELECT coordinator_did, sender_did, sender_device_id, prepare_digest \
         FROM chat.direct_request_remote_leases \
         WHERE request_id = $1 AND recipient_did = $2 LIMIT 1",
        )
        .bind(input.request_id)
        .bind(&input.recipient_did)
        .fetch_optional(&mut *tx)
        .await
        .map_err(|e| FederationError::Storage(e.to_string()))?;

    if let Some((stored_coord, stored_sender, stored_sender_dev, stored_digest)) =
        existing_lease_meta
    {
        if canonical_did(&stored_coord) != canonical_did(&coord.coordinator_did)
            || canonical_did(&stored_sender) != canonical_did(&input.sender_did)
            || (sender_device_id_opt.is_some()
                && stored_sender_dev.is_some()
                && sender_device_id_opt != stored_sender_dev)
            || (stored_digest.is_some() && stored_digest.as_deref() != Some(&prepare_digest_bytes))
        {
            return Err(FederationError::InvalidRequest(format!(
                "request_id {} replayed with conflicting sender/coordinator identity or prepare digest",
                input.request_id
            )));
        }
    }

    // Idempotency: return existing active lease if already reserved for this request_id
    let now = crate::sim_hooks::current_utc();
    let existing_rows = sqlx::query(
        "SELECT p.owner_did, p.owner_device_id, p.owner_key_id, p.owner_auth_generation, \
                g.grant_id, g.grant_digest, c.revision AS capability_revision, \
                p.key_package_ref, p.wrapper_bytes, g.signed_grant, \
                LEAST(p.not_after, g.expires_at) AS expires_at, k.signing_public_key, \
                c.signed_publication, c.publication_digest \
           FROM chat.direct_request_remote_leases l \
           JOIN chat.key_packages p ON p.key_package_ref = l.key_package_ref \
           JOIN chat.devices d ON d.user_did = p.owner_did AND d.device_id = p.owner_device_id \
           JOIN chat.device_keys k ON k.user_did = p.owner_did AND k.device_id = p.owner_device_id AND k.key_id = p.owner_key_id \
           JOIN chat.direct_request_capabilities c ON c.owner_did = p.owner_did AND c.owner_device_id = p.owner_device_id \
           JOIN chat.direct_request_grants g ON g.key_package_ref = p.key_package_ref \
          WHERE l.request_id = $1 AND l.recipient_did = $2 \
            AND l.status = 'active' AND l.expires_at > $3 \
            AND d.status='active' AND d.revoked_at IS NULL AND k.revoked_at IS NULL \
            AND p.owner_auth_generation=d.auth_generation \
            AND k.enrollment_auth_generation<=d.auth_generation \
            AND NOT EXISTS(SELECT 1 FROM chat.device_keys newer \
                WHERE newer.user_did=k.user_did AND newer.device_id=k.device_id \
                  AND newer.enrollment_auth_generation>k.enrollment_auth_generation \
                  AND newer.enrollment_auth_generation<=d.auth_generation)"
    )
    .bind(input.request_id)
    .bind(&input.recipient_did)
    .bind(now)
    .fetch_all(&mut *tx)
    .await
    .map_err(|e| FederationError::Storage(e.to_string()))?;

    if !existing_rows.is_empty() {
        let mut bootstraps = Vec::with_capacity(existing_rows.len());
        for row in existing_rows {
            let grant_digest: Vec<u8> = row
                .try_get("grant_digest")
                .map_err(|e| FederationError::Storage(e.to_string()))?;
            let key_pkg_ref: Vec<u8> = row
                .try_get("key_package_ref")
                .map_err(|e| FederationError::Storage(e.to_string()))?;
            let wrapper: Vec<u8> = row
                .try_get("wrapper_bytes")
                .map_err(|e| FederationError::Storage(e.to_string()))?;
            let sig_pub: Vec<u8> = row
                .try_get("signing_public_key")
                .map_err(|e| FederationError::Storage(e.to_string()))?;
            let exp: DateTime<Utc> = row
                .try_get("expires_at")
                .map_err(|e| FederationError::Storage(e.to_string()))?;
            let signed_keys_bytes: Vec<u8> = row
                .try_get("signed_publication")
                .map_err(|e| FederationError::Storage(e.to_string()))?;
            let signed_keys_pub: Value = serde_json::from_slice(&signed_keys_bytes)
                .map_err(|e| FederationError::Storage(e.to_string()))?;
            let pub_digest: Vec<u8> = row
                .try_get("publication_digest")
                .map_err(|e| FederationError::Storage(e.to_string()))?;

            bootstraps.push(RemoteDeviceBootstrap {
                owner_did: row
                    .try_get("owner_did")
                    .map_err(|e| FederationError::Storage(e.to_string()))?,
                owner_device_id: row
                    .try_get("owner_device_id")
                    .map_err(|e| FederationError::Storage(e.to_string()))?,
                owner_key_id: row
                    .try_get("owner_key_id")
                    .map_err(|e| FederationError::Storage(e.to_string()))?,
                auth_generation: row
                    .try_get("owner_auth_generation")
                    .map_err(|e| FederationError::Storage(e.to_string()))?,
                grant_id: row
                    .try_get("grant_id")
                    .map_err(|e| FederationError::Storage(e.to_string()))?,
                grant_digest: STANDARD.encode(&grant_digest),
                capability_revision: row
                    .try_get("capability_revision")
                    .map_err(|e| FederationError::Storage(e.to_string()))?,
                key_package_ref: STANDARD.encode(&key_pkg_ref),
                wrapper_bytes: STANDARD.encode(&wrapper),
                signed_grant: serde_json::from_slice::<Value>(
                    &row.try_get::<Vec<u8>, _>("signed_grant")
                        .map_err(|e| FederationError::Storage(e.to_string()))?,
                )
                .map_err(|e| FederationError::Storage(e.to_string()))?,
                expires_at: exp.to_rfc3339(),
                signature_public_key: STANDARD.encode(&sig_pub),
                signed_keys_publication: signed_keys_pub,
                publication_digest: STANDARD.encode(&pub_digest),
            });
        }
        tx.commit()
            .await
            .map_err(|e| FederationError::Storage(e.to_string()))?;
        return Ok(bootstraps);
    }

    let horizon = now + chrono::Duration::seconds(605_100);

    // Expiry marks a lease unresolved; the package remains reserved until the
    // coordinator proves cancellation or its committed publication is delivered.
    sqlx::query(
        "UPDATE chat.direct_request_remote_leases \
         SET status = 'expired' \
         WHERE recipient_did = $1 AND status = 'active' AND expires_at <= $2",
    )
    .bind(&input.recipient_did)
    .bind(now)
    .execute(&mut *tx)
    .await
    .map_err(|error| FederationError::Storage(error.to_string()))?;
    // C33-LEASE-003: Reconcile expired leases only via authenticated coordinator outcome.
    // If coordinator proves request is unknown or terminal, release the package; otherwise keep reserved.
    let expired_candidates: Vec<(Uuid, String, Option<Uuid>)> = sqlx::query_as(
        "SELECT request_id, coordinator_did, sender_device_id \
         FROM chat.direct_request_remote_leases \
         WHERE recipient_did = $1 AND status = 'expired' AND sender_device_id IS NOT NULL \
         LIMIT 5",
    )
    .bind(&input.recipient_did)
    .fetch_all(&mut *tx)
    .await
    .map_err(|e| FederationError::Storage(e.to_string()))?;

    for (exp_req_id, exp_coord_did, exp_dev_id) in expired_candidates {
        if canonical_did(&exp_coord_did) == canonical_did(&coord.coordinator_did) {
            if let Some(actor_device_id) = exp_dev_id {
                if let Ok(outcome) = relay_get_outcome(
                    coord.coordinator_endpoint(),
                    &coord.coordinator_did,
                    exp_req_id,
                    actor_device_id,
                )
                .await
                {
                    let outcome_val = outcome.get("outcome").unwrap_or(&outcome);
                    let outcome_type = outcome_val
                        .pointer("/receipt/$type")
                        .or_else(|| outcome_val.pointer("/$type"))
                        .and_then(|v| v.as_str())
                        .unwrap_or_default();
                    let is_terminal = outcome_type
                        == "blue.catbird.chat.defs#directRequestUnknownOutcome"
                        || outcome_type == "blue.catbird.chat.defs#directRequestRejectedReceipt"
                        || outcome_type == "blue.catbird.chat.defs#directRequestExpiredReceipt"
                        || outcome_type == "blue.catbird.chat.defs#directRequestCancelledReceipt";
                    if is_terminal {
                        let _ = sqlx::query(
                            "UPDATE chat.direct_request_remote_leases \
                             SET status = 'released', released_at = $3 \
                             WHERE request_id = $1 AND recipient_did = $2 AND status = 'expired'",
                        )
                        .bind(exp_req_id)
                        .bind(&input.recipient_did)
                        .bind(now)
                        .execute(&mut *tx)
                        .await;
                    }
                }
            }
        }
    }

    // C33-LEASE-003: Enforce atomic limits on unresolved (active + expired) leases
    let peer_unresolved: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM chat.direct_request_remote_leases WHERE coordinator_did = $1 AND status IN ('active', 'expired')"
    )
    .bind(&coord.coordinator_did)
    .fetch_one(&mut *tx)
    .await
    .map_err(|e| FederationError::Storage(e.to_string()))?;
    if peer_unresolved >= 100 {
        return Err(FederationError::RemoteError {
            status: 429,
            body: "{\"error\":\"CapacityExceeded\",\"message\":\"Per-coordinator remote lease capacity exceeded\"}".into(),
        });
    }

    let sender_unresolved: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM chat.direct_request_remote_leases WHERE sender_did = $1 AND status IN ('active', 'expired')"
    )
    .bind(&input.sender_did)
    .fetch_one(&mut *tx)
    .await
    .map_err(|e| FederationError::Storage(e.to_string()))?;
    if sender_unresolved >= 20 {
        return Err(FederationError::RemoteError {
            status: 429,
            body: "{\"error\":\"CapacityExceeded\",\"message\":\"Per-sender remote lease capacity exceeded\"}".into(),
        });
    }

    let recipient_unresolved: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM chat.direct_request_remote_leases WHERE recipient_did = $1 AND status IN ('active', 'expired')"
    )
    .bind(&input.recipient_did)
    .fetch_one(&mut *tx)
    .await
    .map_err(|e| FederationError::Storage(e.to_string()))?;
    if recipient_unresolved >= 32 {
        return Err(FederationError::RemoteError {
            status: 429,
            body: "{\"error\":\"CapacityExceeded\",\"message\":\"Per-recipient remote lease capacity exceeded\"}".into(),
        });
    }

    let global_unresolved: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM chat.direct_request_remote_leases WHERE status IN ('active', 'expired')"
    )
    .fetch_one(&mut *tx)
    .await
    .map_err(|e| FederationError::Storage(e.to_string()))?;
    if global_unresolved >= 1000 {
        return Err(FederationError::RemoteError {
            status: 429,
            body: "{\"error\":\"CapacityExceeded\",\"message\":\"Global remote lease capacity exceeded\"}".into(),
        });
    }

    // Select available packages for recipient devices under row lock
    // Select available packages for recipient devices under row lock (no DISTINCT in SQL to satisfy PostgreSQL FOR UPDATE rules)
    let rows = sqlx::query(
        "SELECT p.owner_did, p.owner_device_id, p.owner_key_id, p.owner_auth_generation, \
                g.grant_id, g.grant_digest, c.revision AS capability_revision, \
                p.key_package_ref, p.wrapper_bytes, \
                g.signed_grant, LEAST(p.not_after, g.expires_at) AS expires_at, \
                k.signing_public_key, \
                c.signed_publication, c.publication_digest \
           FROM chat.key_packages p \
           JOIN chat.devices d ON d.user_did = p.owner_did AND d.device_id = p.owner_device_id \
           JOIN chat.device_keys k ON k.user_did = p.owner_did AND k.device_id = p.owner_device_id AND k.key_id = p.owner_key_id \
           JOIN chat.direct_request_capabilities c ON c.owner_did = p.owner_did AND c.owner_device_id = p.owner_device_id \
           JOIN chat.direct_request_grants g ON g.key_package_ref = p.key_package_ref \
          WHERE p.owner_did = $1 \
            AND d.status = 'active' \
            AND k.revoked_at IS NULL \
            AND p.owner_auth_generation = d.auth_generation \
            AND k.enrollment_auth_generation<=d.auth_generation \
            AND NOT EXISTS(SELECT 1 FROM chat.device_keys newer \
                WHERE newer.user_did=k.user_did AND newer.device_id=k.device_id \
                  AND newer.enrollment_auth_generation>k.enrollment_auth_generation \
                  AND newer.enrollment_auth_generation<=d.auth_generation) \
            AND c.enabled AND c.protocol_version = '2' AND c.auth_generation = d.auth_generation AND c.owner_key_id = k.key_id \
            AND g.revoked_at IS NULL AND g.auth_generation = d.auth_generation \
            AND g.protocol_version = '2' AND g.profile = 'encryptedIntroduction1' AND g.expires_at >= $2 \
            AND p.usage_scope = 'direct-request' AND p.status = 'available' AND p.not_before < $3 AND p.not_after >= $2 \
            AND NOT EXISTS (SELECT 1 FROM chat.direct_request_selected_devices s WHERE s.key_package_ref = p.key_package_ref) \
            AND NOT EXISTS (SELECT 1 FROM chat.direct_request_retired_packages r WHERE r.key_package_ref = p.key_package_ref) \
            AND NOT EXISTS ( \
                SELECT 1 FROM chat.direct_request_remote_leases l \
                 WHERE l.key_package_ref = p.key_package_ref \
                   AND l.status IN ('active', 'expired') \
            ) \
          ORDER BY p.owner_device_id, p.created_at, p.key_package_ref \
          FOR UPDATE OF p SKIP LOCKED"
    )
    .bind(&input.recipient_did)
    .bind(horizon)
    .bind(now)
    .fetch_all(&mut *tx)
    .await
    .map_err(|e| FederationError::Storage(e.to_string()))?;

    let lease_expires_at = now + chrono::Duration::seconds(300);
    let mut seen_devices = std::collections::HashSet::new();
    let mut bootstraps = Vec::new();

    for r in rows {
        let owner_device_id: Uuid = r
            .try_get("owner_device_id")
            .map_err(|e| FederationError::Storage(e.to_string()))?;
        if !seen_devices.insert(owner_device_id) {
            continue;
        }

        let key_package_ref: Vec<u8> = r
            .try_get("key_package_ref")
            .map_err(|e| FederationError::Storage(e.to_string()))?;
        let owner_did: String = r
            .try_get("owner_did")
            .map_err(|e| FederationError::Storage(e.to_string()))?;
        let owner_key_id: String = r
            .try_get("owner_key_id")
            .map_err(|e| FederationError::Storage(e.to_string()))?;
        let auth_generation: i64 = r
            .try_get("owner_auth_generation")
            .map_err(|e| FederationError::Storage(e.to_string()))?;
        let grant_id: Uuid = r
            .try_get("grant_id")
            .map_err(|e| FederationError::Storage(e.to_string()))?;
        let grant_digest: Vec<u8> = r
            .try_get("grant_digest")
            .map_err(|e| FederationError::Storage(e.to_string()))?;
        let capability_revision: i64 = r
            .try_get("capability_revision")
            .map_err(|e| FederationError::Storage(e.to_string()))?;
        let wrapper_bytes: Vec<u8> = r
            .try_get("wrapper_bytes")
            .map_err(|e| FederationError::Storage(e.to_string()))?;
        let signed_grant_bytes: Vec<u8> = r
            .try_get("signed_grant")
            .map_err(|e| FederationError::Storage(e.to_string()))?;
        let signed_grant: Value = serde_json::from_slice(&signed_grant_bytes)
            .map_err(|e| FederationError::Storage(e.to_string()))?;
        let expires_at: DateTime<Utc> = r
            .try_get("expires_at")
            .map_err(|e| FederationError::Storage(e.to_string()))?;
        let signing_public_key: Vec<u8> = r
            .try_get("signing_public_key")
            .map_err(|e| FederationError::Storage(e.to_string()))?;
        let signed_keys_bytes: Vec<u8> = r
            .try_get("signed_publication")
            .map_err(|e| FederationError::Storage(e.to_string()))?;
        let signed_keys_pub: Value = serde_json::from_slice(&signed_keys_bytes)
            .map_err(|e| FederationError::Storage(e.to_string()))?;
        let pub_digest: Vec<u8> = r
            .try_get("publication_digest")
            .map_err(|e| FederationError::Storage(e.to_string()))?;

        sqlx::query(
            "INSERT INTO chat.direct_request_remote_leases ( \
                request_id, coordinator_did, sender_did, recipient_did, \
                key_package_ref, owner_device_id, sender_device_id, sender_signing_key, prepare_digest, status, leased_at, expires_at \
            ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, 'active', $10, $11)"
        )
        .bind(input.request_id)
        .bind(&coord.coordinator_did)
        .bind(&input.sender_did)
        .bind(&input.recipient_did)
        .bind(&key_package_ref)
        .bind(owner_device_id)
        .bind(sender_device_id_opt)
        .bind(&sender_signing_key_bytes)
        .bind(&prepare_digest_bytes)
        .bind(now)
        .bind(lease_expires_at)
        .execute(&mut *tx)
        .await
        .map_err(|e| FederationError::Storage(e.to_string()))?;

        bootstraps.push(RemoteDeviceBootstrap {
            owner_did,
            owner_device_id,
            owner_key_id,
            auth_generation,
            grant_id,
            grant_digest: STANDARD.encode(&grant_digest),
            capability_revision,
            key_package_ref: STANDARD.encode(&key_package_ref),
            wrapper_bytes: STANDARD.encode(&wrapper_bytes),
            signed_grant,
            expires_at: expires_at.to_rfc3339(),
            signature_public_key: STANDARD.encode(&signing_public_key),
            signed_keys_publication: signed_keys_pub,
            publication_digest: STANDARD.encode(&pub_digest),
        });
    }

    if bootstraps.is_empty() {
        return Err(FederationError::NotFound(
            "Recipient has no available direct-request key packages".into(),
        ));
    }

    tx.commit()
        .await
        .map_err(|e| FederationError::Storage(e.to_string()))?;
    Ok(bootstraps)
}
/// Compensating release of remote recipient bootstrap leases on reservation failure.
pub async fn local_release_recipient_bootstrap(
    pool: &DbPool,
    requester_ds: &str,
    request_id: Uuid,
    recipient_did: &str,
) -> Result<(), FederationError> {
    let existing_coord: Option<String> = sqlx::query_scalar(
        "SELECT coordinator_did FROM chat.direct_request_remote_leases \
         WHERE request_id = $1 AND recipient_did = $2 AND status IN ('active', 'expired') LIMIT 1",
    )
    .bind(request_id)
    .bind(recipient_did)
    .fetch_optional(pool)
    .await
    .map_err(|e| FederationError::Storage(e.to_string()))?;

    if let Some(coord_did) = existing_coord {
        if canonical_did(&coord_did) != canonical_did(requester_ds) {
            return Err(FederationError::AuthFailed {
                reason: format!("Requester {requester_ds} is not recorded coordinator {coord_did}"),
            });
        }
    }

    sqlx::query(
        "UPDATE chat.direct_request_remote_leases \
         SET status = 'released', released_at = $4 \
         WHERE request_id = $1 AND recipient_did = $2 AND coordinator_did = $3 AND status IN ('active', 'expired')"
    )
    .bind(request_id)
    .bind(recipient_did)
    .bind(requester_ds)
    .bind(crate::sim_hooks::current_utc())
    .execute(pool)
    .await
    .map_err(|e| FederationError::Storage(e.to_string()))?;
    Ok(())
}

/// Ingest an inbound direct request delivery on the recipient's home DS.
///
/// Stores verified Welcome + request entry in `chat.direct_request_transport_inbox`,
/// finalizes the remote lease, and transitions packages to 'consumed'.
pub async fn ingest_remote_direct_request_delivery(
    pool: &DbPool,
    _sse: Option<&Arc<SseState>>,
    requester_ds: &str,
    mut input: DeliverDirectRequestInput,
) -> Result<(), FederationError> {
    input.entry = crate::chat_protocol::direct_request_transcript::normalize_read_presentation(
        &serde_json::to_vec(&input.entry).map_err(FederationError::Json)?,
        "directRequestEntry",
        true,
    )
    .map_err(|_| FederationError::InvalidProof)?;
    let actor_did = input
        .entry
        .pointer("/signedRequest/body/actorDid")
        .or_else(|| input.entry.pointer("/body/actorDid"))
        .and_then(|v| v.as_str())
        .ok_or_else(|| {
            FederationError::InvalidRequest("missing actorDid in delivery entry".into())
        })?;
    let recipient_did = input
        .entry
        .pointer("/signedRequest/body/recipientDid")
        .or_else(|| input.entry.pointer("/body/recipientDid"))
        .and_then(|v| v.as_str())
        .ok_or_else(|| {
            FederationError::InvalidRequest("missing recipientDid in delivery entry".into())
        })?;
    let sender_device_id_str = input
        .entry
        .pointer("/signedRequest/body/actorDeviceId")
        .or_else(|| input.entry.pointer("/body/actorDeviceId"))
        .and_then(|v| v.as_str())
        .ok_or_else(|| {
            FederationError::InvalidRequest("missing actorDeviceId in delivery entry".into())
        })?;
    let sender_device_id = Uuid::parse_str(sender_device_id_str)
        .map_err(|e| FederationError::InvalidRequest(format!("invalid actorDeviceId UUID: {e}")))?;
    let key_id = input
        .entry
        .pointer("/signedRequest/body/keyId")
        .or_else(|| input.entry.pointer("/body/keyId"))
        .and_then(|v| v.as_str())
        .ok_or_else(|| FederationError::InvalidRequest("missing keyId in delivery entry".into()))?;

    let entry_req_id_str = input
        .entry
        .pointer("/signedRequest/body/requestId")
        .or_else(|| input.entry.pointer("/body/requestId"))
        .and_then(|v| v.as_str())
        .ok_or_else(|| {
            FederationError::InvalidRequest("missing requestId in delivery entry".into())
        })?;
    let entry_req_id = Uuid::parse_str(entry_req_id_str)
        .map_err(|e| FederationError::InvalidRequest(format!("invalid requestId UUID: {e}")))?;
    if entry_req_id != input.request_id {
        return Err(FederationError::InvalidRequest(
            "requestId mismatch between input and entry".into(),
        ));
    }

    let entry_convo_str = input
        .entry
        .pointer("/signedRequest/body/conversationId")
        .or_else(|| input.entry.pointer("/body/conversationId"))
        .and_then(|v| v.as_str())
        .ok_or_else(|| {
            FederationError::InvalidRequest("missing conversationId in delivery entry".into())
        })?;
    let entry_convo_id = Uuid::parse_str(entry_convo_str).map_err(|e| {
        FederationError::InvalidRequest(format!("invalid conversationId UUID: {e}"))
    })?;
    if entry_convo_id != input.conversation_id {
        return Err(FederationError::InvalidRequest(
            "conversationId mismatch between input and entry".into(),
        ));
    }

    let entry_msg_str = input
        .entry
        .pointer("/signedRequest/body/firstMessageId")
        .or_else(|| input.entry.pointer("/body/firstMessageId"))
        .and_then(|v| v.as_str())
        .ok_or_else(|| {
            FederationError::InvalidRequest("missing firstMessageId in delivery entry".into())
        })?;
    let entry_first_msg_id = Uuid::parse_str(entry_msg_str).map_err(|e| {
        FederationError::InvalidRequest(format!("invalid firstMessageId UUID: {e}"))
    })?;
    if entry_first_msg_id != input.first_message_id {
        return Err(FederationError::InvalidRequest(
            "firstMessageId mismatch between input and entry".into(),
        ));
    }

    let coord = resolve_pair_coordinator(pool, actor_did, recipient_did).await?;

    if !coord.is_recipient_home {
        return Err(FederationError::Forbidden(
            "Local node is not recipient home DS".into(),
        ));
    }
    if canonical_did(&coord.coordinator_did) != canonical_did(requester_ds)
        || canonical_did(&input.coordinator_did) != canonical_did(requester_ds)
    {
        return Err(FederationError::AuthFailed {
            reason: format!(
                "Requester {requester_ds} is not resolved coordinator {}",
                coord.coordinator_did
            ),
        });
    }

    let now = crate::sim_hooks::current_utc();

    // 1. Determine full_welcome bytes and sha256 (fail closed)
    let full_welcome = if let Some(b64) = &input.full_welcome_bytes {
        STANDARD.decode(b64).map_err(|e| {
            FederationError::InvalidRequest(format!("invalid full_welcome_bytes base64: {e}"))
        })?
    } else if let Some(b64) = input
        .publication_receipt
        .pointer("/receipt/artifacts/welcome/opaqueWelcome")
        .and_then(|v| v.as_str())
    {
        STANDARD.decode(b64).map_err(|e| {
            FederationError::InvalidRequest(format!("invalid opaqueWelcome base64: {e}"))
        })?
    } else if let Some(b64) = input
        .entry
        .pointer("/signedRequest/artifacts/welcome/opaqueWelcome")
        .and_then(|v| v.as_str())
    {
        STANDARD.decode(b64).map_err(|e| {
            FederationError::InvalidRequest(format!("invalid opaqueWelcome base64: {e}"))
        })?
    } else {
        return Err(FederationError::InvalidRequest(
            "missing full_welcome in delivery input".into(),
        ));
    };
    if full_welcome.is_empty() {
        return Err(FederationError::InvalidRequest(
            "empty full_welcome in delivery input".into(),
        ));
    }
    let full_welcome_sha256 = Sha256::digest(&full_welcome).to_vec();

    let request_entry_bytes = serde_json::to_vec(&input.entry).map_err(FederationError::Json)?;

    let signed_pub_val = input
        .signed_publication
        .as_ref()
        .or_else(|| input.entry.get("signedRequest"))
        .unwrap_or(&input.entry);
    let signed_pub_bytes = serde_json::to_vec(signed_pub_val).map_err(FederationError::Json)?;

    let import_until_str = input
        .publication_receipt
        .pointer("/receipt/importUntil")
        .or_else(|| input.entry.pointer("/signedRequest/body/importUntil"))
        .and_then(|v| v.as_str())
        .ok_or_else(|| {
            FederationError::InvalidRequest("missing importUntil in delivery input".into())
        })?;
    let import_until = DateTime::parse_from_rfc3339(import_until_str)
        .map_err(|e| FederationError::InvalidRequest(format!("invalid importUntil format: {e}")))?
        .with_timezone(&Utc);
    if import_until <= now {
        return Err(FederationError::InvalidRequest(
            "importUntil is in the past".into(),
        ));
    }

    // 2. Independently verify trusted coordinator DID doc receipt signature (M-F04: before tx)
    let http = super::resolver::build_resolver_http_client();
    let resolver = DsResolver::with_default_endpoint(
        pool.clone(),
        http,
        crate::identity::service_did(),
        crate::identity::self_endpoint(),
        std::env::var("DEFAULT_DS_ENDPOINT").ok(),
        3600,
    );

    let receipt_val = &input.publication_receipt;
    let receipt_bytes = serde_json::to_vec(receipt_val).map_err(FederationError::Json)?;

    let receipt_authority_did = receipt_val
        .pointer("/body/authorityDid")
        .or_else(|| receipt_val.pointer("/receipt/authorityDid"))
        .or_else(|| receipt_val.get("authorityDid"))
        .and_then(|v| v.as_str())
        .ok_or_else(|| {
            FederationError::InvalidRequest("missing authorityDid in publication receipt".into())
        })?;
    if canonical_did(receipt_authority_did) != canonical_did(&coord.coordinator_did) {
        return Err(FederationError::AuthFailed {
            reason: format!(
                "receipt authorityDid {receipt_authority_did} does not match coordinator {}",
                coord.coordinator_did
            ),
        });
    }

    let receipt_key_id = receipt_val
        .pointer("/body/keyId")
        .or_else(|| receipt_val.pointer("/receipt/keyId"))
        .or_else(|| receipt_val.get("keyId"))
        .and_then(|v| v.as_str())
        .ok_or_else(|| {
            FederationError::InvalidRequest("missing keyId in publication receipt".into())
        })?;

    let receipt_public_key = resolver
        .resolve_coordinator_receipt_key(pool, receipt_authority_did, receipt_key_id)
        .await?;

    let verified_receipt =
        crate::chat_protocol::direct_request_transcript::verify_received_signed_request(
            crate::chat_protocol::direct_request_transcript::DirectRequestKind::Outcome,
            &receipt_bytes,
            &receipt_public_key,
        )
        .map_err(|e| {
            FederationError::InvalidRequest(format!(
                "coordinator receipt signature verification failed: {e:?}"
            ))
        })?;
    let i13_key_id = input
        .entry
        .pointer("/sequencerReceipt/kid")
        .and_then(|kid| kid.as_str())
        .ok_or(FederationError::InvalidProof)?;
    let i13_public_key = resolver
        .resolve_i13_receipt_key(&coord.coordinator_did, i13_key_id)
        .await?;

    // 3. Verify actor signature: live PDS or commit-time proof (M-F04: HTTP before tx).
    // Only a PDS that answered without the key defers to the lease's retained proof.
    let matching_key = live_actor_key(&resolver, actor_did, key_id).await?;

    let mut tx = pool
        .begin()
        .await
        .map_err(|e| FederationError::Storage(e.to_string()))?;

    let matching_key = match matching_key {
        Some(k) => k,
        None => {
            // Finding C33-AUTH-002: If actor rotated their device key after commit,
            // query the PDS-verified sender signing key retained in the remote lease
            let lease_key_row: Option<(Vec<u8>, Option<Uuid>, Option<Vec<u8>>)> = sqlx::query_as(
                "SELECT sender_signing_key, sender_device_id, prepare_digest \
                 FROM chat.direct_request_remote_leases \
                 WHERE request_id = $1 AND recipient_did = $2 AND status IN ('active', 'expired') \
                   AND sender_signing_key IS NOT NULL LIMIT 1",
            )
            .bind(input.request_id)
            .bind(recipient_did)
            .fetch_optional(&mut *tx)
            .await
            .map_err(|e| FederationError::Storage(e.to_string()))?;

            let (retained_key, stored_dev_id, _stored_prep_digest) = lease_key_row.ok_or_else(|| {
                FederationError::Forbidden(format!(
                    "actor {actor_did} key {key_id} is not authorized by PDS and no PDS-verified lease key was retained"
                ))
            })?;

            // Validate sender_device_id matches entry
            if let Some(dev_id) = stored_dev_id {
                if dev_id != sender_device_id {
                    return Err(FederationError::InvalidRequest(format!(
                        "delivery sender_device_id {sender_device_id} does not match lease {dev_id}"
                    )));
                }
            }

            // Validate thumbprint matches key_id
            let calculated_thumbprint = URL_SAFE_NO_PAD.encode(Sha256::digest(&retained_key));
            let calculated_key_id = crate::chat_protocol::validation::ed25519_key_id(&retained_key)
                .map(|id| id.to_string())
                .unwrap_or_default();
            if key_id != calculated_thumbprint
                && key_id != calculated_key_id
                && key_id != STANDARD.encode(&retained_key)
            {
                return Err(FederationError::InvalidRequest(format!(
                    "keyId {key_id} does not match retained public key thumbprint"
                )));
            }

            retained_key
        }
    };

    let verified_pub = crate::chat_protocol::direct_request_transcript::verify_signed_request(
        crate::chat_protocol::direct_request_transcript::DirectRequestKind::Publish,
        &signed_pub_bytes,
        &matching_key,
    )
    .map_err(|e| {
        FederationError::InvalidRequest(format!("actor signature verification failed: {e:?}"))
    })?;
    crate::chat_protocol::direct_request_transcript::verify_direct_request_opening_receipt(
        &verified_pub,
        &input.entry,
        &verified_receipt,
        &coord.coordinator_did,
        &i13_public_key,
    )
    .map_err(|_| FederationError::InvalidProof)?;
    let publication_body = verified_pub.body();
    let signed_welcome = publication_body
        .pointer("/artifacts/welcome/opaqueWelcome")
        .and_then(|value| value.as_str())
        .and_then(|encoded| STANDARD.decode(encoded).ok())
        .ok_or_else(|| {
            FederationError::InvalidRequest("signed publication lacks a valid Welcome".into())
        })?;
    if input.entry.get("signedRequest") != Some(signed_pub_val)
        || full_welcome != signed_welcome
        || publication_body
            .pointer("/artifacts/welcome/deliveries")
            .and_then(|value| value.as_array())
            .map(Vec::as_slice)
            != Some(input.deliveries.as_slice())
    {
        return Err(FederationError::InvalidRequest(
            "transport artifacts differ from sender-signed publication".into(),
        ));
    }
    // 4. Verify exact cross-bindings
    let receipt_req_digest_b64 = verified_receipt
        .body()
        .pointer("/receipt/requestDigest")
        .or_else(|| verified_receipt.body().get("requestDigest"))
        .and_then(|v| v.as_str())
        .ok_or_else(|| {
            FederationError::InvalidRequest("missing requestDigest in receipt body".into())
        })?;
    let receipt_req_digest = STANDARD.decode(receipt_req_digest_b64).map_err(|e| {
        FederationError::InvalidRequest(format!("invalid requestDigest base64: {e}"))
    })?;
    if receipt_req_digest.as_slice() != verified_pub.request_digest() {
        return Err(FederationError::InvalidRequest(
            "receipt requestDigest does not match publication digest".into(),
        ));
    }

    let receipt_req_id = verified_receipt
        .body()
        .pointer("/receipt/requestId")
        .or_else(|| verified_receipt.body().get("requestId"))
        .and_then(|v| v.as_str())
        .ok_or_else(|| {
            FederationError::InvalidRequest("missing requestId in receipt body".into())
        })?;
    if receipt_req_id != input.request_id.to_string() {
        return Err(FederationError::InvalidRequest(
            "receipt requestId mismatch".into(),
        ));
    }

    if verified_receipt.body().pointer("/receipt/coordinates") != publication_body.get("next")
        || verified_receipt
            .body()
            .pointer("/receipt/conversationId")
            .and_then(|value| value.as_str())
            != Some(input.conversation_id.to_string().as_str())
        || verified_receipt
            .body()
            .pointer("/receipt/firstMessageId")
            .and_then(|value| value.as_str())
            != Some(input.first_message_id.to_string().as_str())
        || verified_receipt
            .body()
            .pointer("/receipt/actorDid")
            .and_then(|value| value.as_str())
            != Some(actor_did)
        || verified_receipt
            .body()
            .pointer("/receipt/requestKind")
            .and_then(|value| value.as_str())
            != Some("publish")
    {
        return Err(FederationError::InvalidRequest(
            "signed receipt does not bind published conversation".into(),
        ));
    }

    // 5. Validate deliveries and provenance
    if input.deliveries.is_empty() {
        return Err(FederationError::InvalidRequest(
            "deliveries array cannot be empty".into(),
        ));
    }

    for d in &input.deliveries {
        let rec_did = d["recipientDid"].as_str().ok_or_else(|| {
            FederationError::InvalidRequest("missing recipientDid in delivery item".into())
        })?;
        if rec_did != recipient_did && rec_did != actor_did {
            return Err(FederationError::InvalidRequest(
                "delivery is not for a signed pair member".into(),
            ));
        }
        let rec_device_str = d["recipientDeviceId"].as_str().ok_or_else(|| {
            FederationError::InvalidRequest("missing recipientDeviceId in delivery item".into())
        })?;
        let _ = Uuid::parse_str(rec_device_str).map_err(|e| {
            FederationError::InvalidRequest(format!("invalid recipientDeviceId UUID: {e}"))
        })?;
        let provenance = d.get("provenance").ok_or_else(|| {
            FederationError::InvalidRequest("missing provenance in delivery item".into())
        })?;
        if provenance.get("requestId").and_then(|v| v.as_str())
            != Some(&input.request_id.to_string())
        {
            return Err(FederationError::InvalidRequest(
                "provenance requestId mismatch".into(),
            ));
        }
    }

    // 6. Check existing inbox for idempotent replay
    // Replays compare the digest frozen at insert, so a pruned opening (O7)
    // still recognizes its duplicate and is never restored.
    let existing_inbox: Vec<(Vec<u8>, Vec<u8>)> = sqlx::query_as(
        "SELECT full_welcome_sha256, request_entry_sha256 \
         FROM chat.direct_request_transport_inbox \
         WHERE request_id = $1",
    )
    .bind(input.request_id)
    .fetch_all(&mut *tx)
    .await
    .map_err(|e| FederationError::Storage(e.to_string()))?;

    if !existing_inbox.is_empty() {
        let request_entry_sha256 = Sha256::digest(&request_entry_bytes).to_vec();
        for (stored_hash, stored_entry_sha256) in &existing_inbox {
            if stored_hash != &full_welcome_sha256 || stored_entry_sha256 != &request_entry_sha256 {
                return Err(FederationError::CommitConflict {
                    convo_id: input.conversation_id.to_string(),
                    current_epoch: 0,
                });
            }
        }
        tx.commit()
            .await
            .map_err(|e| FederationError::Storage(e.to_string()))?;
        return Ok(());
    }

    // 7. Finalize active or expired remote lease
    let leased_packages: Vec<(Uuid, Vec<u8>, Uuid)> = sqlx::query_as(
        "UPDATE chat.direct_request_remote_leases \
         SET status = 'finalized', finalized_at = $1 \
         WHERE request_id = $2 AND recipient_did = $3 AND coordinator_did = $4 \
           AND status IN ('active', 'expired') \
         RETURNING lease_id, key_package_ref, owner_device_id",
    )
    .bind(now)
    .bind(input.request_id)
    .bind(recipient_did)
    .bind(&coord.coordinator_did)
    .fetch_all(&mut *tx)
    .await
    .map_err(|e| FederationError::Storage(e.to_string()))?;

    if leased_packages.is_empty() {
        return Err(FederationError::InvalidRequest(
            "no lease found for request".into(),
        ));
    }

    if leased_packages.len()
        != input
            .deliveries
            .iter()
            .filter(|delivery| delivery["recipientDid"].as_str() == Some(recipient_did))
            .count()
    {
        return Err(FederationError::InvalidRequest(
            "leased recipient packages differ from signed local deliveries".into(),
        ));
    }

    for d in &input.deliveries {
        if d["recipientDid"].as_str() != Some(recipient_did) {
            continue;
        }
        let rec_device_id = Uuid::parse_str(d["recipientDeviceId"].as_str().unwrap()).unwrap();
        let prov_key_pkg_b64 = d["provenance"]["keyPackageRef"].as_str().ok_or_else(|| {
            FederationError::InvalidRequest("missing keyPackageRef in provenance".into())
        })?;
        let prov_key_pkg = STANDARD.decode(prov_key_pkg_b64).map_err(|e| {
            FederationError::InvalidRequest(format!("invalid keyPackageRef in provenance: {e}"))
        })?;

        let matching_lease = leased_packages
            .iter()
            .find(|(_, pkg_ref, dev_id)| *dev_id == rec_device_id && *pkg_ref == prov_key_pkg);

        if matching_lease.is_none() {
            return Err(FederationError::InvalidRequest(format!(
                "delivery device {rec_device_id} does not match any leased package for this request"
            )));
        }
    }

    // 8. Insert into chat.direct_request_transport_inbox
    let publication_receipt_bytes =
        serde_json::to_vec(&input.publication_receipt).map_err(FederationError::Json)?;

    for d in &input.deliveries {
        if d["recipientDid"].as_str() != Some(recipient_did) {
            continue;
        }
        let rec_did = d["recipientDid"].as_str().unwrap();
        let rec_device_id = Uuid::parse_str(d["recipientDeviceId"].as_str().unwrap()).unwrap();
        let prov_bytes = serde_json::to_vec(&d["provenance"]).map_err(FederationError::Json)?;

        // Explicit id: inventory session identity hashes delivery_id, so a DB-random
        // default would break byte-identical sim replay (random in production too).
        let delivery_id = crate::sim_hooks::mint_entry_uuid_v4(
            b"chat.direct_request_transport_inbox",
            &[
                &input.request_id.as_bytes()[..],
                &rec_device_id.as_bytes()[..],
            ],
        );
        sqlx::query(
            "INSERT INTO chat.direct_request_transport_inbox ( \
                request_id, conversation_id, first_message_id, coordinator_did, \
                sender_did, sender_device_id, recipient_did, recipient_device_id, \
                request_entry, signed_publication, full_welcome, full_welcome_sha256, \
                provenance, publication_receipt, import_until, status, created_at, updated_at, \
                delivery_id \
            ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, 'pending', $16, $16, $17) \
            ON CONFLICT (request_id, recipient_device_id) DO NOTHING"
        )
        .bind(input.request_id)
        .bind(input.conversation_id)
        .bind(input.first_message_id)
        .bind(&coord.coordinator_did)
        .bind(actor_did)
        .bind(sender_device_id)
        .bind(rec_did)
        .bind(rec_device_id)
        .bind(&request_entry_bytes)
        .bind(&signed_pub_bytes)
        .bind(&full_welcome)
        .bind(&full_welcome_sha256)
        .bind(&prov_bytes)
        .bind(&publication_receipt_bytes)
        .bind(import_until)
        .bind(now)
        .bind(delivery_id)
        .execute(&mut *tx)
        .await
        .map_err(|e| FederationError::Storage(e.to_string()))?;
    }

    // 9. Mark key packages consumed on recipient home DS referencing the finalized remote lease
    for (lease_id, pkg_ref, _device_id) in &leased_packages {
        let res = sqlx::query(
            "UPDATE chat.key_packages \
             SET status = 'consumed', terminal_remote_lease_id = $1, terminal_at = $2 \
             WHERE key_package_ref = $3 AND status = 'available'",
        )
        .bind(lease_id)
        .bind(now)
        .bind(pkg_ref)
        .execute(&mut *tx)
        .await
        .map_err(|e| FederationError::Storage(e.to_string()))?;

        if res.rows_affected() != 1 {
            return Err(FederationError::InvalidRequest(
                "key package was not available for consumption".into(),
            ));
        }
    }

    // 10. Insert initial introduction entry into chat.direct_request_transport_entries
    let seq = input.entry.get("seq").and_then(|v| v.as_i64()).unwrap_or(1);
    if seq != 1 {
        return Err(FederationError::InvalidRequest(
            "initial entry seq must be 1".into(),
        ));
    }
    let entry_id_str = input.entry.get("entryId").and_then(|v| v.as_str());
    let entry_id = entry_id_str
        .and_then(|s| Uuid::parse_str(s).ok())
        .unwrap_or(input.request_id);

    let stored = crate::chat_protocol::repository::delivery::insert_transport_entry(
        &mut tx,
        input.conversation_id,
        seq,
        entry_id,
        &request_entry_bytes,
        now,
    )
    .await
    .map_err(|e| FederationError::Storage(e.to_string()))?;
    if stored == crate::chat_protocol::repository::delivery::TransportEntryInsert::Conflict {
        return Err(FederationError::CommitConflict {
            convo_id: input.conversation_id.to_string(),
            current_epoch: 0,
        });
    }

    tx.commit()
        .await
        .map_err(|e| FederationError::Storage(e.to_string()))?;
    Ok(())
}

pub(crate) async fn verify_remote_acceptance_evidence(
    pool: &DbPool,
    expected_sequencer: &str,
    expected_conversation_id: Uuid,
    entry: &Value,
    acceptance_proof: &Value,
    actor_public_key: &[u8],
) -> Result<Value, FederationError> {
    use crate::chat_protocol::direct_request_transcript::{
        direct_request_signing_bytes, verify_received_direct_request_acceptance_proof,
        DirectRequestKind,
    };

    let receipt = entry
        .get("sequencerReceipt")
        .filter(|value| value.is_object())
        .ok_or(FederationError::InvalidProof)?;
    if acceptance_proof.pointer("/entry/sequencerReceipt") != Some(receipt) {
        return Err(FederationError::InvalidProof);
    }
    let mut actor_entry = entry.clone();
    let actor_fields = actor_entry
        .as_object_mut()
        .ok_or_else(|| FederationError::InvalidRequest("invalid acceptance entry".into()))?;
    actor_fields.remove("$type");
    actor_fields.remove("sequencerReceipt");
    if actor_entry["conversationId"]
        .as_str()
        .and_then(|value| Uuid::parse_str(value).ok())
        != Some(expected_conversation_id)
    {
        return Err(FederationError::InvalidProof);
    }
    let mut legacy_proof = acceptance_proof.clone();
    legacy_proof["entry"]
        .as_object_mut()
        .ok_or(FederationError::InvalidProof)?
        .remove("sequencerReceipt")
        .ok_or(FederationError::InvalidProof)?;
    if legacy_proof.get("entry") != Some(&actor_entry) {
        return Err(FederationError::InvalidProof);
    }
    if crate::identity::canonical_did(
        legacy_proof["receipt"]["body"]["authorityDid"]
            .as_str()
            .ok_or(FederationError::InvalidProof)?,
    ) != crate::identity::canonical_did(expected_sequencer)
    {
        return Err(FederationError::InvalidProof);
    }

    let resolver = DsResolver::with_default_endpoint(
        pool.clone(),
        super::resolver::build_resolver_http_client(),
        crate::identity::service_did(),
        crate::identity::self_endpoint(),
        std::env::var("DEFAULT_DS_ENDPOINT").ok(),
        3600,
    );
    let legacy_key_id = legacy_proof
        .pointer("/receipt/body/keyId")
        .and_then(Value::as_str)
        .ok_or(FederationError::InvalidProof)?;
    let legacy_key = resolver
        .resolve_coordinator_receipt_key(pool, expected_sequencer, legacy_key_id)
        .await?;
    let verified = verify_received_direct_request_acceptance_proof(
        &serde_json::to_vec(&legacy_proof).map_err(FederationError::Json)?,
        &legacy_key,
        actor_public_key,
    )
    .map_err(|_| FederationError::InvalidProof)?;
    if verified.get("entry") != Some(&actor_entry) {
        return Err(FederationError::InvalidProof);
    }

    let body = &verified["entry"]["signedRequest"]["body"];
    let transcript = direct_request_signing_bytes(
        DirectRequestKind::Accept,
        &serde_json::to_vec(body).map_err(FederationError::Json)?,
    )
    .map_err(|_| FederationError::InvalidProof)?;
    let request_digest: [u8; 32] = Sha256::digest(transcript).into();
    let input = I13ControlReceiptInput::from_fields(
        actor_entry["conversationId"]
            .as_str()
            .ok_or(FederationError::InvalidProof)?,
        actor_entry["entryId"]
            .as_str()
            .ok_or(FederationError::InvalidProof)?,
        actor_entry["seq"]
            .as_u64()
            .ok_or(FederationError::InvalidProof)?,
        actor_entry["receivedAt"]
            .as_str()
            .ok_or(FederationError::InvalidProof)?,
        body["actorDid"]
            .as_str()
            .ok_or(FederationError::InvalidProof)?,
        body["actorDeviceId"]
            .as_str()
            .ok_or(FederationError::InvalidProof)?,
        request_digest,
    )
    .map_err(|_| FederationError::InvalidProof)?;
    let i13_key_id = receipt["kid"]
        .as_str()
        .ok_or(FederationError::InvalidProof)?;
    let i13_key = resolver
        .resolve_i13_receipt_key(expected_sequencer, i13_key_id)
        .await?;
    let i13_key = p256::ecdsa::VerifyingKey::from_sec1_bytes(&i13_key)
        .map_err(|_| FederationError::InvalidProof)?;
    verify_control_receipt(receipt, &i13_key, expected_sequencer, &input, &body["next"])
        .map_err(|_| FederationError::InvalidProof)?;
    Ok(verified)
}

/// Ingest an inbound acceptance entry on a remote DS.
pub async fn ingest_remote_acceptance_entry(
    pool: &DbPool,
    _sse: Option<&Arc<SseState>>,
    requester_ds: &str,
    conversation_id: Uuid,
    entry: &Value,
    acceptance_proof: &Value,
) -> Result<(), FederationError> {
    let signed_acceptance = entry
        .get("signedRequest")
        .ok_or_else(|| FederationError::InvalidRequest("missing signed acceptance".into()))?;
    let actor_device_id = signed_acceptance
        .pointer("/body/actorDeviceId")
        .and_then(Value::as_str)
        .and_then(|value| Uuid::parse_str(value).ok())
        .ok_or_else(|| FederationError::InvalidRequest("invalid accepting device".into()))?;
    let convo_info: Option<(String, String, String, String)> = sqlx::query_as(
        "SELECT coordinator_did, sender_did, recipient_did, status \
         FROM chat.direct_request_transport_inbox \
         WHERE conversation_id=$1 AND recipient_device_id=$2 LIMIT 1",
    )
    .bind(conversation_id)
    .bind(actor_device_id)
    .fetch_optional(pool)
    .await
    .map_err(|e| FederationError::Storage(e.to_string()))?;

    let (coord_did, _sender_did, recipient_did, _status) = convo_info.ok_or_else(|| {
        FederationError::NotFound(format!(
            "conversation {conversation_id} not found in transport inbox"
        ))
    })?;

    if canonical_did(&coord_did) != canonical_did(requester_ds) {
        return Err(FederationError::AuthFailed {
            reason: format!("Requester {requester_ds} is not the retained coordinator {coord_did}"),
        });
    }

    let proof_receipt = acceptance_proof
        .pointer("/receipt/body")
        .ok_or_else(|| FederationError::InvalidRequest("missing signed acceptance proof".into()))?;
    if proof_receipt["authorityDid"].as_str() != Some(coord_did.as_str())
        || signed_acceptance
            .pointer("/body/actorDid")
            .and_then(Value::as_str)
            != Some(recipient_did.as_str())
    {
        return Err(FederationError::InvalidRequest(
            "acceptance actor or authority mismatch".into(),
        ));
    }
    let signer_key_id = signed_acceptance
        .pointer("/body/keyId")
        .and_then(Value::as_str)
        .ok_or_else(|| FederationError::InvalidRequest("missing accepting device key".into()))?;
    let resolver = DsResolver::with_default_endpoint(
        pool.clone(),
        super::resolver::build_resolver_http_client(),
        crate::identity::service_did(),
        crate::identity::self_endpoint(),
        std::env::var("DEFAULT_DS_ENDPOINT").ok(),
        3600,
    );
    let authorized_keys = resolver
        .resolve_authorized_device_keys(&recipient_did)
        .await?;
    let actor_key = authorized_keys
        .iter()
        .find(|key| URL_SAFE_NO_PAD.encode(Sha256::digest(key)) == signer_key_id)
        .ok_or_else(|| {
            FederationError::Forbidden("accepting device key is not PDS-authorized".into())
        })?;
    verify_remote_acceptance_evidence(
        pool,
        &coord_did,
        conversation_id,
        entry,
        acceptance_proof,
        actor_key,
    )
    .await?;

    let entry_convo = entry
        .get("conversationId")
        .and_then(Value::as_str)
        .and_then(|value| Uuid::parse_str(value).ok());
    if entry_convo != Some(conversation_id) {
        return Err(FederationError::InvalidRequest(
            "conversationId mismatch in acceptance entry".into(),
        ));
    }

    if let Some(t) = entry.get("$type").and_then(|v| v.as_str()) {
        if t != "blue.catbird.chat.defs#directRequestAcceptanceEntry" {
            return Err(FederationError::InvalidRequest(format!(
                "invalid entry $type {t} for acceptance"
            )));
        }
    }

    let seq = entry
        .get("seq")
        .and_then(|v| v.as_i64())
        .ok_or_else(|| FederationError::InvalidRequest("missing seq in acceptance entry".into()))?;
    if seq != 2 {
        return Err(FederationError::InvalidRequest(format!(
            "acceptance entry seq must be 2, got {seq}"
        )));
    }

    // The opening entry, or once its ciphertext was pruned its redacted entry (O7):
    // the signed coordinates are the same in both.
    let intro_bytes: Vec<u8> = sqlx::query_scalar(
        "SELECT COALESCE(request_entry, redacted_request_entry) \
           FROM chat.direct_request_transport_inbox \
          WHERE conversation_id=$1 ORDER BY delivery_id LIMIT 1",
    )
    .bind(conversation_id)
    .fetch_one(pool)
    .await
    .map_err(|_| FederationError::InvalidProof)?;
    let intro: Value = serde_json::from_slice(&intro_bytes).map_err(FederationError::Json)?;
    if intro.pointer("/signedRequest/body/next") != signed_acceptance.pointer("/body/prior") {
        return Err(FederationError::InvalidRequest(
            "acceptance prior differs from verified introduction".into(),
        ));
    }

    let now = crate::sim_hooks::current_utc();
    let mut tx = pool
        .begin()
        .await
        .map_err(|e| FederationError::Storage(e.to_string()))?;

    let proof_bytes = serde_json::to_vec(acceptance_proof).map_err(FederationError::Json)?;
    let outcome_bytes = serde_json::to_vec(&json!({
        "entry": entry,
        "acceptanceProof": acceptance_proof,
    }))
    .map_err(FederationError::Json)?;

    sqlx::query(
        "UPDATE chat.direct_request_transport_inbox \
         SET status = 'accepted', acceptance_proof = $2, acceptance_outcome = $3, updated_at = $4 \
         WHERE conversation_id = $1",
    )
    .bind(conversation_id)
    .bind(&proof_bytes)
    .bind(&outcome_bytes)
    .bind(now)
    .execute(&mut *tx)
    .await
    .map_err(|e| FederationError::Storage(e.to_string()))?;

    let entry_id_str = entry
        .get("entryId")
        .and_then(|v| v.as_str())
        .unwrap_or_default();
    let entry_id = Uuid::parse_str(entry_id_str)
        .map_err(|e| FederationError::InvalidRequest(format!("invalid entryId UUID: {e}")))?;
    let entry_bytes = serde_json::to_vec(entry).map_err(FederationError::Json)?;

    let stored = crate::chat_protocol::repository::delivery::insert_transport_entry(
        &mut tx,
        conversation_id,
        seq,
        entry_id,
        &entry_bytes,
        now,
    )
    .await
    .map_err(|e| FederationError::Storage(e.to_string()))?;
    if stored == crate::chat_protocol::repository::delivery::TransportEntryInsert::Conflict {
        return Err(FederationError::CommitConflict {
            convo_id: conversation_id.to_string(),
            current_epoch: 0,
        });
    }

    tx.commit()
        .await
        .map_err(|e| FederationError::Storage(e.to_string()))?;
    Ok(())
}

fn coordinate_bytes32(coordinate: &Value, field: &str) -> Option<[u8; 32]> {
    let encoded = coordinate.get(field).and_then(|value| {
        value
            .as_str()
            .or_else(|| value.get("$bytes").and_then(Value::as_str))
    })?;
    let mut decoded = [0_u8; 48];
    let len = STANDARD
        .decode_slice(encoded, &mut decoded)
        .or_else(|_| URL_SAFE_NO_PAD.decode_slice(encoded, &mut decoded))
        .ok()?;
    (len == 32).then(|| decoded[..32].try_into().expect("length checked"))
}

fn same_transport_coordinate(left: &Value, right: &Value) -> bool {
    let same_text = |field| {
        matches!(
            (
                left.get(field).and_then(Value::as_str),
                right.get(field).and_then(Value::as_str),
            ),
            (Some(left), Some(right)) if left == right
        )
    };
    let same_integer = |field| {
        matches!(
            (
                left.get(field).and_then(Value::as_u64),
                right.get(field).and_then(Value::as_u64),
            ),
            (Some(left), Some(right)) if left == right
        )
    };
    same_text("conversationId")
        && same_integer("generation")
        && same_integer("stateVersion")
        && same_integer("epoch")
        && same_text("lifecycle")
        && ["groupId", "groupContextHash", "confirmationTag"]
            .into_iter()
            .all(|field| {
                matches!(
                    (
                        coordinate_bytes32(left, field),
                        coordinate_bytes32(right, field),
                    ),
                    (Some(left), Some(right)) if left == right
                )
            })
}

/// Ingest an inbound application message entry on a remote DS.
pub async fn ingest_remote_message_entry(
    pool: &DbPool,
    _sse: Option<&Arc<SseState>>,
    requester_ds: &str,
    conversation_id: Uuid,
    entry: &Value,
) -> Result<(), FederationError> {
    let signed_message = entry.get("signedRequest").ok_or_else(|| {
        FederationError::InvalidRequest("missing signed application message".into())
    })?;
    let actor_did = signed_message
        .pointer("/body/actorDid")
        .and_then(Value::as_str)
        .ok_or_else(|| FederationError::InvalidRequest("missing message actor".into()))?;
    let actor_device_id = signed_message
        .pointer("/body/actorDeviceId")
        .and_then(Value::as_str)
        .and_then(|value| Uuid::parse_str(value).ok())
        .ok_or_else(|| FederationError::InvalidRequest("invalid message actor device".into()))?;
    let signer_key_id = signed_message
        .pointer("/body/keyId")
        .and_then(Value::as_str)
        .ok_or_else(|| FederationError::InvalidRequest("missing message key ID".into()))?;
    let coord_info: Option<(String, String)> = sqlx::query_as(
        "SELECT coordinator_did, status FROM chat.direct_request_transport_inbox \
         WHERE conversation_id=$1 AND \
           ((sender_did=$2 AND sender_device_id=$3) OR \
            (recipient_did=$2 AND recipient_device_id=$3)) LIMIT 1",
    )
    .bind(conversation_id)
    .bind(actor_did)
    .bind(actor_device_id)
    .fetch_optional(pool)
    .await
    .map_err(|e| FederationError::Storage(e.to_string()))?;
    let (coord_did, status) = coord_info.ok_or_else(|| {
        FederationError::Forbidden("message actor is not an entitled pair device".into())
    })?;
    if status != "accepted" {
        return Err(FederationError::Forbidden(
            "direct request has not been accepted".into(),
        ));
    }

    if canonical_did(&coord_did) != canonical_did(requester_ds) {
        return Err(FederationError::AuthFailed {
            reason: format!("Requester {requester_ds} is not the retained coordinator {coord_did}"),
        });
    }
    let resolver = DsResolver::with_default_endpoint(
        pool.clone(),
        super::resolver::build_resolver_http_client(),
        crate::identity::service_did(),
        crate::identity::self_endpoint(),
        std::env::var("DEFAULT_DS_ENDPOINT").ok(),
        3600,
    );
    let authorized_keys = resolver.resolve_authorized_device_keys(actor_did).await?;
    let actor_key = authorized_keys
        .iter()
        .find(|key| URL_SAFE_NO_PAD.encode(Sha256::digest(key)) == signer_key_id)
        .ok_or_else(|| {
            FederationError::Forbidden("message signing key is not PDS-authorized".into())
        })?;
    let signed_bytes = serde_json::to_vec(signed_message).map_err(FederationError::Json)?;
    let verified = crate::chat_protocol::transcript::decode_and_verify_signed_mutation(
        &signed_bytes,
        actor_key,
    )
    .map_err(|_| FederationError::InvalidProof)?;
    if !matches!(
        verified.projection(),
        crate::chat_protocol::transcript::VerifiedMutationProjection::ApplicationSend(_)
    ) {
        return Err(FederationError::InvalidRequest(
            "relayed entry is not an application send".into(),
        ));
    }

    let entry_convo = entry.get("conversationId").and_then(|v| v.as_str());
    if entry_convo != Some(&conversation_id.to_string()) {
        return Err(FederationError::InvalidRequest(
            "conversationId mismatch in message entry".into(),
        ));
    }

    if entry.get("$type").and_then(Value::as_str) != Some("blue.catbird.chat.defs#applicationEntry")
    {
        return Err(FederationError::InvalidRequest(
            "invalid application entry type".into(),
        ));
    }

    let seq = entry
        .get("seq")
        .and_then(|v| v.as_i64())
        .ok_or_else(|| FederationError::InvalidRequest("missing seq in message entry".into()))?;
    if seq < 3 {
        return Err(FederationError::InvalidRequest(format!(
            "message entry seq must be >= 3, got {seq}"
        )));
    }

    // The sequencer's previous entry must already be stored here: a gap is
    // retried. Control entries, such as `accountDeletedEntry`, carry no
    // coordinates, so the prior is compared against the nearest preceding entry
    // that does: a transition's `next`, or an application's `prior`, read from
    // its immutable signed metadata once its ciphertext is pruned. Signed
    // requests carry NUL escapes PostgreSQL JSON rejects, so both are parsed here.
    let contiguous: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM chat.direct_request_transport_entries \
                        WHERE conversation_id = $1 AND seq = $2) \
             OR EXISTS(SELECT 1 FROM chat.entries WHERE conversation_id = $1 AND seq = $2)",
    )
    .bind(conversation_id)
    .bind(seq - 1)
    .fetch_one(pool)
    .await
    .map_err(|e| FederationError::Storage(e.to_string()))?;
    if !contiguous {
        return Err(FederationError::PredecessorMissing {
            reason: "missing signed predecessor entry".into(),
        });
    }
    let mut before = seq;
    let predecessor_prior = loop {
        let stored: Option<(i64, Option<Vec<u8>>, Option<Vec<u8>>)> = sqlx::query_as(
            "SELECT s.seq, COALESCE(t.entry_bytes, e.accepted_payload_bytes), \
                    (to_jsonb(t)->>'application_metadata_bytes')::bytea \
               FROM (SELECT max(seq) AS seq FROM ( \
                       SELECT seq FROM chat.direct_request_transport_entries \
                        WHERE conversation_id = $1 AND seq < $2 \
                       UNION ALL \
                       SELECT seq FROM chat.entries WHERE conversation_id = $1 AND seq < $2 \
                     ) earlier) s \
               LEFT JOIN chat.direct_request_transport_entries t \
                 ON t.conversation_id = $1 AND t.seq = s.seq \
               LEFT JOIN chat.entries e ON e.conversation_id = $1 AND e.seq = s.seq \
              WHERE s.seq IS NOT NULL",
        )
        .bind(conversation_id)
        .bind(before)
        .fetch_optional(pool)
        .await
        .map_err(|e| FederationError::Storage(e.to_string()))?;
        let Some((at, payload, metadata)) = stored else {
            break None;
        };
        let coordinate = match (metadata, payload) {
            (Some(metadata), _) => serde_json::from_slice::<Value>(&metadata)
                .map_err(FederationError::Json)?
                .pointer("/body/prior")
                .cloned(),
            (None, Some(payload)) => {
                let stored: Value =
                    serde_json::from_slice(&payload).map_err(FederationError::Json)?;
                stored
                    .pointer("/signedRequest/body/next")
                    .or_else(|| stored.pointer("/signedRequest/body/prior"))
                    .cloned()
            }
            (None, None) => None,
        };
        if coordinate.is_some() {
            break coordinate;
        }
        before = at;
    };
    let prior = signed_message
        .pointer("/body/prior")
        .ok_or_else(|| FederationError::InvalidRequest("message coordinates are missing".into()))?;
    if predecessor_prior
        .as_ref()
        .is_none_or(|predecessor| !same_transport_coordinate(prior, predecessor))
    {
        return Err(FederationError::InvalidRequest(
            "message coordinates differ from retained predecessor".into(),
        ));
    }

    let entry_id_str = entry
        .get("entryId")
        .and_then(|v| v.as_str())
        .ok_or_else(|| {
            FederationError::InvalidRequest("missing entryId in message entry".into())
        })?;
    let entry_id = Uuid::parse_str(entry_id_str)
        .map_err(|e| FederationError::InvalidRequest(format!("invalid entryId UUID: {e}")))?;

    let entry_bytes = serde_json::to_vec(entry).map_err(FederationError::Json)?;

    let mut tx = pool
        .begin()
        .await
        .map_err(|e| FederationError::Storage(e.to_string()))?;

    let stored = crate::chat_protocol::repository::delivery::insert_transport_entry(
        &mut tx,
        conversation_id,
        seq,
        entry_id,
        &entry_bytes,
        crate::sim_hooks::current_utc(),
    )
    .await
    .map_err(|e| FederationError::Storage(e.to_string()))?;
    if stored == crate::chat_protocol::repository::delivery::TransportEntryInsert::Conflict {
        return Err(FederationError::CommitConflict {
            convo_id: conversation_id.to_string(),
            current_epoch: 0,
        });
    }

    tx.commit()
        .await
        .map_err(|e| FederationError::Storage(e.to_string()))?;
    Ok(())
}

/// Coordinator execution for prepareDirectRequest relayed from sender home DS or direct.
pub async fn coordinator_prepare_direct_request(
    pool: &DbPool,
    runtime: &Arc<ChatRuntime>,
    requester_ds: &str,
    input: &Value,
) -> Result<Value, FederationError> {
    let signed_req = input.get("signedRequest").unwrap_or(input);
    let actor_did = signed_req["body"]["actorDid"]
        .as_str()
        .ok_or_else(|| FederationError::InvalidRequest("missing actorDid".into()))?;
    let recipient_did = signed_req["body"]["recipientDid"]
        .as_str()
        .ok_or_else(|| FederationError::InvalidRequest("missing recipientDid".into()))?;
    let request_id_str = signed_req["body"]["requestId"]
        .as_str()
        .ok_or_else(|| FederationError::InvalidRequest("missing requestId".into()))?;
    let request_id = Uuid::parse_str(request_id_str)
        .map_err(|_| FederationError::InvalidRequest("invalid requestId".into()))?;

    let coord = resolve_pair_coordinator(pool, actor_did, recipient_did).await?;
    if !coord.is_coordinator {
        return Err(FederationError::Forbidden(
            "Local node is not coordinator".into(),
        ));
    }
    if canonical_did(&coord.sender_home.did) != canonical_did(requester_ds) {
        return Err(FederationError::AuthFailed {
            reason: format!(
                "Requester {requester_ds} is not sender home DS {}",
                coord.sender_home.did
            ),
        });
    }

    let now = TrustedRequestInstant::capture()
        .map_err(|_| FederationError::Invariant("trusted instant".into()))?
        .datetime();

    let (p1, p2) = if actor_did <= recipient_did {
        (actor_did, recipient_did)
    } else {
        (recipient_did, actor_did)
    };
    let pair_lock_key = format!("chat-direct-request-pair:{p1}:{p2}");

    // M-F04: Validate and PDS-authorize senderDeviceKey BEFORE opening PostgreSQL transaction
    let verified_sender_key = if !coord.is_sender_home {
        let sender_key = match input.get("senderDeviceKey") {
            Some(k) => k,
            None => {
                return Err(FederationError::InvalidRequest(
                    "missing senderDeviceKey from sender home DS".into(),
                ));
            }
        };
        let device_id_str = match sender_key["deviceId"].as_str() {
            Some(s) => s,
            None => {
                return Err(FederationError::InvalidRequest(
                    "missing senderDeviceKey.deviceId".into(),
                ));
            }
        };
        let key_id = match sender_key["keyId"].as_str() {
            Some(k) => k.to_string(),
            None => {
                return Err(FederationError::InvalidRequest(
                    "missing senderDeviceKey.keyId".into(),
                ));
            }
        };
        let auth_gen = match sender_key["authGeneration"].as_i64() {
            Some(g) => g,
            None => {
                return Err(FederationError::InvalidRequest(
                    "missing senderDeviceKey.authGeneration".into(),
                ));
            }
        };
        let pub_key_b64 = match sender_key["signingPublicKey"].as_str() {
            Some(p) => p,
            None => {
                return Err(FederationError::InvalidRequest(
                    "missing senderDeviceKey.signingPublicKey".into(),
                ));
            }
        };
        let device_id = match Uuid::parse_str(device_id_str) {
            Ok(d) => d,
            Err(_) => {
                return Err(FederationError::InvalidRequest(
                    "invalid senderDeviceKey.deviceId".into(),
                ));
            }
        };
        let pub_key = match STANDARD.decode(pub_key_b64) {
            Ok(k) => k,
            Err(_) => {
                return Err(FederationError::InvalidRequest(
                    "invalid senderDeviceKey.signingPublicKey base64".into(),
                ));
            }
        };

        if signed_req["body"]["actorDeviceId"].as_str() != Some(device_id_str)
            || signed_req["body"]["keyId"].as_str() != Some(key_id.as_str())
            || signed_req["body"]["authGeneration"].as_i64() != Some(auth_gen)
        {
            return Err(FederationError::InvalidRequest(
                "signedRequest fields do not match senderDeviceKey".into(),
            ));
        }
        let http = super::resolver::build_resolver_http_client();
        let resolver = DsResolver::with_default_endpoint(
            pool.clone(),
            http,
            crate::identity::service_did(),
            crate::identity::self_endpoint(),
            std::env::var("DEFAULT_DS_ENDPOINT").ok(),
            3600,
        );
        let authorized_keys = resolver.resolve_authorized_device_keys(actor_did).await?;
        if !authorized_keys.contains(&pub_key) {
            return Err(FederationError::Forbidden(format!(
                "sender key {key_id} is not authorized by actor {actor_did}'s PDS"
            )));
        }
        let signed_bytes = serde_json::to_vec(signed_req).map_err(FederationError::Json)?;
        if let Err(e) = crate::chat_protocol::direct_request_transcript::verify_signed_request(
            crate::chat_protocol::direct_request_transcript::DirectRequestKind::Prepare,
            &signed_bytes,
            &pub_key,
        ) {
            return Err(FederationError::InvalidRequest(format!(
                "prepare signature verification failed against senderDeviceKey: {e:?}"
            )));
        }
        let calculated_key_id = match crate::chat_protocol::validation::ed25519_key_id(&pub_key) {
            Ok(k) => k,
            Err(e) => {
                return Err(FederationError::InvalidRequest(format!(
                    "invalid ed25519 public key: {e:?}"
                )));
            }
        };
        if calculated_key_id.as_str() != key_id {
            return Err(FederationError::InvalidRequest(
                "senderDeviceKey keyId does not match public key thumbprint".into(),
            ));
        }
        Some((device_id, key_id, auth_gen, pub_key))
    } else {
        None
    };

    // Quick pre-check before remote reservation HTTP so replays/conflicts do not unnecessarily reserve
    let has_existing_attempt: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM chat.direct_request_attempts WHERE request_id=$1)",
    )
    .bind(request_id)
    .fetch_one(pool)
    .await
    .map_err(|e| FederationError::Storage(e.to_string()))?;

    let reserved_remote_devices = if !has_existing_attempt && !coord.is_recipient_home {
        let authorized_keys = resolve_remote_recipient_device_keys(pool, recipient_did).await?;
        let devices = reserve_remote_recipient_bootstrap(
            pool,
            &coord.recipient_home.endpoint,
            &coord.recipient_home.did,
            request_id,
            actor_did,
            recipient_did,
            Some(signed_req.clone()),
        )
        .await?;
        Some((devices, authorized_keys))
    } else {
        None
    };

    let mut tx = pool
        .begin()
        .await
        .map_err(|e| FederationError::Storage(e.to_string()))?;

    // Acquire transaction advisory lock for the unordered participant pair. A
    // database failure decides nothing: any reservation stays for the identical retry.
    sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1, 0))")
        .bind(&pair_lock_key)
        .execute(&mut *tx)
        .await
        .map_err(|e| FederationError::Storage(e.to_string()))?;

    if let Some(conflict) = check_pair_owner_fence(
        &mut tx,
        actor_did,
        recipient_did,
        request_id,
        Some(&coord.coordinator_did),
    )
    .await?
    {
        let msg = match conflict {
            PairFenceConflict::ForeignCoordinator {
                coordinator_did, ..
            } => {
                format!("Direct request or pair already owned by coordinator {coordinator_did}")
            }
            PairFenceConflict::LocalConflict { .. } => {
                "Direct request already in progress for this pair".to_string()
            }
        };
        tx.rollback()
            .await
            .map_err(|error| FederationError::Storage(error.to_string()))?;
        if reserved_remote_devices.is_some() {
            let _ = release_remote_recipient_bootstrap(
                pool,
                &coord.recipient_home.endpoint,
                &coord.recipient_home.did,
                request_id,
                recipient_did,
            )
            .await;
        }
        return Err(FederationError::RemoteError {
            status: 409,
            body: format!("{{\"error\":\"PreparationConflict\",\"message\":\"{msg}\"}}"),
        });
    }
    let existing_attempt: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM chat.direct_request_attempts WHERE request_id=$1)",
    )
    .bind(request_id)
    .fetch_one(&mut *tx)
    .await
    .map_err(|e| FederationError::Storage(e.to_string()))?;
    if existing_attempt {
        let signer =
            runtime
                .request_receipt_signer()
                .ok_or_else(|| FederationError::ConfigError {
                    reason: "request receipt signer not configured".into(),
                })?;
        let principal = crate::auth::VerifiedServicePrincipal::for_federated_s2s(
            actor_did,
            "blue.catbird.chat.prepareDirectRequest",
        );
        let signed_bytes = serde_json::to_vec(signed_req).map_err(FederationError::Json)?;
        let result =
            crate::chat_protocol::repository::direct_request_preparation::prepare_direct_request(
                &mut tx,
                &principal,
                &signed_bytes,
                signer,
                runtime.relationship_authority().as_ref(),
                now,
                None,
            )
            .await
            // A source that could not answer now, or this database, decided
            // nothing; only a refusal is the definitive conflict.
            .map_err(|error| FederationError::RemoteError {
                status: if error.is_transient() { 503 } else { 409 },
                body: format!("prepare replay rejected: {error:?}"),
            })?;
        let rejected = matches!(&result,
            crate::chat_protocol::repository::direct_request_preparation::DirectRequestResult::Terminal(_));
        let outcome = match result {
            crate::chat_protocol::repository::direct_request_preparation::DirectRequestResult::Prepared(bytes) => {
                json!({"$type":"blue.catbird.chat.defs#directRequestPreparedOutcome",
                    "preparation": serde_json::from_slice::<Value>(&bytes).map_err(FederationError::Json)?})
            }
            crate::chat_protocol::repository::direct_request_preparation::DirectRequestResult::Terminal(bytes) => {
                let mut receipt: Value = serde_json::from_slice(&bytes).map_err(FederationError::Json)?;
                receipt["$type"] = json!("blue.catbird.chat.defs#signedDirectRequestReceipt");
                receipt
            }
            _ => return Err(FederationError::Invariant("invalid retained preparation outcome".into())),
        };
        tx.commit()
            .await
            .map_err(|e| FederationError::Storage(e.to_string()))?;
        if rejected && !coord.is_recipient_home {
            release_remote_recipient_bootstrap(
                pool,
                &coord.recipient_home.endpoint,
                &coord.recipient_home.did,
                request_id,
                recipient_did,
            )
            .await?;
        }
        return Ok(json!({"outcome": outcome}));
    }

    if let Some((device_id, ref key_id, auth_gen, ref pub_key)) = verified_sender_key {
        if let Err(error) = super::group_relay::stage_verified_remote_device(
            &mut tx,
            actor_did,
            device_id,
            key_id.as_str(),
            auth_gen,
            pub_key,
            now,
        )
        .await
        {
            tx.rollback()
                .await
                .map_err(|error| FederationError::Storage(error.to_string()))?;
            if reserved_remote_devices.is_some() {
                let _ = release_remote_recipient_bootstrap(
                    pool,
                    &coord.recipient_home.endpoint,
                    &coord.recipient_home.did,
                    request_id,
                    recipient_did,
                )
                .await;
            }
            return Err(error);
        }
    }

    let signer = runtime
        .request_receipt_signer()
        .ok_or_else(|| FederationError::ConfigError {
            reason: "request receipt signer not configured".into(),
        })?;
    let principal = crate::auth::VerifiedServicePrincipal::for_federated_s2s(
        actor_did,
        "blue.catbird.chat.prepareDirectRequest",
    );

    let signed_bytes = serde_json::to_vec(signed_req).map_err(FederationError::Json)?;
    if let Some((remote_devices, authorized_keys)) = reserved_remote_devices.as_ref() {
        if let Err(e) = stage_remote_recipient_devices(
            &mut tx,
            request_id,
            remote_devices,
            authorized_keys,
            now,
        )
        .await
        {
            tx.rollback()
                .await
                .map_err(|error| FederationError::Storage(error.to_string()))?;
            release_remote_recipient_bootstrap(
                pool,
                &coord.recipient_home.endpoint,
                &coord.recipient_home.did,
                request_id,
                recipient_did,
            )
            .await?;
            return Err(e);
        }
    }

    let result =
        match crate::chat_protocol::repository::direct_request_preparation::prepare_direct_request(
            &mut tx,
            &principal,
            &signed_bytes,
            signer,
            runtime.relationship_authority().as_ref(),
            now,
            None,
        )
        .await
        {
            Ok(r) => r,
            Err(e) => {
                tx.rollback()
                    .await
                    .map_err(|error| FederationError::Storage(error.to_string()))?;
                // An unavailable source or this database decided nothing: the
                // reservation stays for the identical retry, and the sender home
                // reports the 503 as retryable.
                let transient = e.is_transient();
                if reserved_remote_devices.is_some() && !transient {
                    release_remote_recipient_bootstrap(
                        pool,
                        &coord.recipient_home.endpoint,
                        &coord.recipient_home.did,
                        request_id,
                        recipient_did,
                    )
                    .await?;
                }
                return Err(FederationError::RemoteError {
                    status: if transient { 503 } else { 400 },
                    body: format!("prepare_direct_request error: {e:?}"),
                });
            }
        };
    let should_release_remote = reserved_remote_devices.is_some()
        && !matches!(&result,
            crate::chat_protocol::repository::direct_request_preparation::DirectRequestResult::Prepared(_));

    let output_val = match result {
        crate::chat_protocol::repository::direct_request_preparation::DirectRequestResult::Keys(bytes) => {
            serde_json::from_slice(&bytes).unwrap_or(Value::Null)
        }
        crate::chat_protocol::repository::direct_request_preparation::DirectRequestResult::Unknown(id) => {
            json!({"$type":"blue.catbird.chat.defs#directRequestUnknownOutcome","requestId":id.to_string()})
        }
        crate::chat_protocol::repository::direct_request_preparation::DirectRequestResult::Prepared(bytes) => {
            let prep: Value = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
            json!({"$type":"blue.catbird.chat.defs#directRequestPreparedOutcome","preparation":prep})
        }
        crate::chat_protocol::repository::direct_request_preparation::DirectRequestResult::Terminal(bytes) => {
            let mut val: Value = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
            val["$type"] = json!("blue.catbird.chat.defs#signedDirectRequestReceipt");
            val
        }
    };

    tx.commit()
        .await
        .map_err(|e| FederationError::Storage(e.to_string()))?;
    if should_release_remote {
        release_remote_recipient_bootstrap(
            pool,
            &coord.recipient_home.endpoint,
            &coord.recipient_home.did,
            request_id,
            recipient_did,
        )
        .await?;
    }
    Ok(json!({ "outcome": output_val }))
}

/// Coordinator execution for publishDirectRequest relayed from sender home DS or direct.
pub async fn coordinator_publish_direct_request(
    pool: &DbPool,
    runtime: &Arc<ChatRuntime>,
    requester_ds: &str,
    input: &Value,
) -> Result<Value, FederationError> {
    let signed_req = input.get("signedRequest").unwrap_or(input);
    let actor_did = signed_req["body"]["actorDid"]
        .as_str()
        .ok_or_else(|| FederationError::InvalidRequest("missing actorDid".into()))?;
    let recipient_did = signed_req["body"]["recipientDid"]
        .as_str()
        .ok_or_else(|| FederationError::InvalidRequest("missing recipientDid".into()))?;

    let coord = resolve_pair_coordinator(pool, actor_did, recipient_did).await?;
    if !coord.is_coordinator {
        return Err(FederationError::Forbidden(
            "Local node is not coordinator".into(),
        ));
    }
    if canonical_did(&coord.sender_home.did) != canonical_did(requester_ds) {
        return Err(FederationError::AuthFailed {
            reason: format!(
                "Requester {requester_ds} is not sender home DS {}",
                coord.sender_home.did
            ),
        });
    }

    let signer = runtime
        .request_receipt_signer()
        .ok_or_else(|| FederationError::ConfigError {
            reason: "request receipt signer not configured".into(),
        })?;
    let principal = crate::auth::VerifiedServicePrincipal::for_federated_s2s(
        actor_did,
        "blue.catbird.chat.publishDirectRequest",
    );

    let signed_bytes = serde_json::to_vec(signed_req).map_err(FederationError::Json)?;

    let now = TrustedRequestInstant::capture()
        .map_err(|_| FederationError::Invariant("trusted instant".into()))?
        .datetime();

    // M-F04 + C33-AUTH-002: Resolve actor and recipient PDS device keys BEFORE opening PostgreSQL transaction
    let http = super::resolver::build_resolver_http_client();
    let resolver = DsResolver::with_default_endpoint(
        pool.clone(),
        http,
        crate::identity::service_did(),
        crate::identity::self_endpoint(),
        std::env::var("DEFAULT_DS_ENDPOINT").ok(),
        3600,
    );
    let actor_authorized_keys = resolver.resolve_authorized_device_keys(actor_did).await?;
    let actor_key_id = signed_req
        .pointer("/body/keyId")
        .and_then(|v| v.as_str())
        .unwrap_or_default();
    let actor_key_authorized = actor_authorized_keys.iter().any(|k| {
        URL_SAFE_NO_PAD.encode(Sha256::digest(k)) == actor_key_id
            || STANDARD.encode(k) == actor_key_id
            || crate::chat_protocol::validation::ed25519_key_id(k)
                .map(|id| id.as_str() == actor_key_id)
                .unwrap_or(false)
    });
    if !actor_key_authorized {
        return Err(FederationError::Forbidden(format!(
            "actor {actor_did} key {actor_key_id} is not authorized by PDS at publication commit"
        )));
    }

    let recipient_authorized_keys = resolver
        .resolve_authorized_device_keys(recipient_did)
        .await?;
    if recipient_authorized_keys.is_empty() {
        return Err(FederationError::Forbidden(format!(
            "recipient {recipient_did} authorizes no MLS device keys on PDS at publication commit"
        )));
    }

    let mut tx = pool
        .begin()
        .await
        .map_err(|e| FederationError::Storage(e.to_string()))?;

    let request_id = Uuid::parse_str(signed_req["body"]["requestId"].as_str().unwrap_or_default())
        .unwrap_or_default();
    let conversation_id = Uuid::parse_str(
        signed_req["body"]["conversationId"]
            .as_str()
            .unwrap_or_default(),
    )
    .unwrap_or_default();
    let first_message_id = Uuid::parse_str(
        signed_req["body"]["firstMessageId"]
            .as_str()
            .unwrap_or_default(),
    )
    .unwrap_or_default();
    let (p1, p2) = if actor_did <= recipient_did {
        (actor_did, recipient_did)
    } else {
        (recipient_did, actor_did)
    };
    let pair_lock_key = format!("chat-direct-request-pair:{p1}:{p2}");
    sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1, 0))")
        .bind(&pair_lock_key)
        .execute(&mut *tx)
        .await
        .map_err(|e| FederationError::Storage(e.to_string()))?;

    if let Some(conflict) = check_pair_owner_fence(
        &mut tx,
        actor_did,
        recipient_did,
        request_id,
        Some(&coord.coordinator_did),
    )
    .await?
    {
        let msg = match conflict {
            PairFenceConflict::ForeignCoordinator {
                coordinator_did, ..
            } => {
                format!("Direct request or pair already owned by coordinator {coordinator_did}")
            }
            PairFenceConflict::LocalConflict { .. } => {
                "Direct request or pair already in progress for this pair".to_string()
            }
        };
        return Err(FederationError::RemoteError {
            status: 409,
            body: format!("{{\"error\":\"PreparationConflict\",\"message\":\"{msg}\"}}"),
        });
    }

    let selected_recipient_keys: Vec<Vec<u8>> = sqlx::query_scalar(
        "SELECT k.signing_public_key \
         FROM chat.direct_request_selected_devices s \
         JOIN chat.device_keys k ON k.user_did = s.owner_did AND k.device_id = s.owner_device_id AND k.key_id = s.owner_key_id \
         WHERE s.request_id = $1 AND s.owner_did = $2"
    )
    .bind(request_id)
    .bind(recipient_did)
    .fetch_all(&mut *tx)
    .await
    .map_err(|e| FederationError::Storage(e.to_string()))?;

    for pk in &selected_recipient_keys {
        if !recipient_authorized_keys.iter().any(|k| k == pk) {
            return Err(FederationError::Forbidden(format!(
                "selected recipient key for {recipient_did} is no longer authorized by PDS at publication commit"
            )));
        }
    }

    let prepared =
        crate::chat_protocol::repository::direct_request_publication::prepare_publication(
            &mut tx,
            &principal,
            &signed_bytes,
            signer,
            runtime.relationship_authority().as_ref(),
            now,
            runtime.request_producers_enabled(),
        )
        .await
        .map_err(|e| FederationError::RemoteError {
            status: if e.is_transient() { 503 } else { 400 },
            body: format!("prepare_publication error: {e:?}"),
        })?;

    let receipt_bytes = match prepared {
        crate::chat_protocol::repository::direct_request_publication::PublicationPreparation::Terminal(bytes) => bytes,
        crate::chat_protocol::repository::direct_request_publication::PublicationPreparation::Ready(ready) => {
            crate::chat_protocol::repository::direct_request_publication::execute_publication(
                &mut tx,
                *ready,
                signer,
                runtime.i13_receipt_signer(),
                runtime.relationship_authority().as_ref(),
            )
            .await
            .map_err(|e| FederationError::RemoteError {
                status: if e.is_transient() { 503 } else { 400 },
                body: format!("execute_publication error: {e:?}"),
            })?
        }
    };

    let mut receipt: Value =
        serde_json::from_slice(&receipt_bytes).map_err(FederationError::Json)?;
    receipt["$type"] = json!("blue.catbird.chat.defs#signedDirectRequestReceipt");
    if receipt
        .pointer("/body/receipt/$type")
        .and_then(Value::as_str)
        != Some("blue.catbird.chat.defs#directRequestPublishedReceipt")
    {
        tx.commit()
            .await
            .map_err(|e| FederationError::Storage(e.to_string()))?;
        return Ok(json!({"outcome":receipt}));
    }

    let (entry_val, opening_pruned) =
        crate::chat_protocol::repository::direct_request_opening::coordinator_opening_response(
            &mut *tx, request_id,
        )
        .await
        .map_err(|e| FederationError::Storage(e.to_string()))?
        .ok_or_else(|| {
            FederationError::Invariant("published request lacks opening entry".into())
        })?;
    if opening_pruned {
        // A duplicate publish after the opening's ciphertext was pruned (O7) is
        // recognized by its digest-bound receipt; the opening is never delivered again.
        tx.commit()
            .await
            .map_err(|e| FederationError::Storage(e.to_string()))?;
        return Ok(json!({"outcome":receipt,"entry":entry_val}));
    }

    let deliveries = signed_req
        .pointer("/body/artifacts/welcome/deliveries")
        .or_else(|| signed_req.pointer("/artifacts/welcome/deliveries"))
        .or_else(|| receipt.pointer("/receipt/artifacts/welcome/deliveries"))
        .or_else(|| receipt.pointer("/artifacts/welcome/deliveries"))
        .and_then(|v| v.as_array())
        .cloned()
        .unwrap_or_default();

    let pub_row: Option<(Vec<u8>, Vec<u8>)> = sqlx::query_as(
        "SELECT full_welcome, signed_publication FROM chat.direct_request_publications WHERE request_id = $1"
    )
    .bind(request_id)
    .fetch_optional(&mut *tx)
    .await
    .map_err(|e| FederationError::Storage(e.to_string()))?;

    let (welcome, signed_pub) = pub_row
        .ok_or_else(|| FederationError::Invariant("published request lacks artifacts".into()))?;
    let full_welcome_b64 = Some(STANDARD.encode(&welcome));
    let signed_pub_val = Some(serde_json::from_slice(&signed_pub).map_err(FederationError::Json)?);

    let deliver_input = DeliverDirectRequestInput {
        request_id,
        conversation_id,
        first_message_id,
        entry: entry_val.clone(),
        deliveries,
        publication_receipt: receipt.clone(),
        coordinator_did: coord.coordinator_did.clone(),
        full_welcome_bytes: full_welcome_b64,
        signed_publication: signed_pub_val,
    };

    let queue_id = format!("direct-request-delivery-{}", deliver_input.request_id);
    if !coord.is_recipient_home {
        let payload_bytes = serde_json::to_vec(&deliver_input).map_err(FederationError::Json)?;
        crate::federation::queue::enqueue_c33_in_tx(
            pool,
            &mut tx,
            &queue_id,
            &coord.recipient_home.did,
            &coord.recipient_home.endpoint,
            "blue.catbird.mlsDS.deliverDirectRequest",
            &payload_bytes,
            &deliver_input.conversation_id.to_string(),
            "",
        )
        .await
        .map_err(queue_full_unavailable)?;
    }

    tx.commit()
        .await
        .map_err(|e| FederationError::Storage(e.to_string()))?;

    if !coord.is_recipient_home {
        if let Ok(()) = deliver_direct_request_to_peer(
            &coord.recipient_home.endpoint,
            &coord.recipient_home.did,
            deliver_input,
        )
        .await
        {
            let _ = crate::federation::queue::mark_delivered_by_id(pool, &queue_id).await;
        }
    }

    Ok(json!({"outcome":receipt,"entry":entry_val}))
}

/// Coordinator execution for acceptDirectRequest relayed from recipient home DS.
pub async fn coordinator_accept_direct_request(
    pool: &DbPool,
    runtime: &Arc<ChatRuntime>,
    requester_ds: &str,
    conversation_id: Uuid,
    direct_request: &Value,
) -> Result<DeliverAcceptanceOutput, FederationError> {
    let actor_did = direct_request["body"]["actorDid"]
        .as_str()
        .ok_or_else(|| FederationError::InvalidRequest("missing actorDid".into()))?;
    let signed_conversation_id = direct_request
        .pointer("/body/prior/conversationId")
        .and_then(Value::as_str)
        .and_then(|value| Uuid::parse_str(value).ok())
        .ok_or_else(|| {
            FederationError::InvalidRequest(
                "missing or invalid prior conversationId in direct request body".into(),
            )
        })?;
    if signed_conversation_id != conversation_id {
        return Err(FederationError::InvalidRequest(
            "outer conversationId does not match signed acceptance".into(),
        ));
    }

    let request_id_str = direct_request["body"]["requestId"]
        .as_str()
        .ok_or_else(|| {
            FederationError::InvalidRequest("missing requestId in direct request body".into())
        })?;
    let request_id = Uuid::parse_str(request_id_str)
        .map_err(|_| FederationError::InvalidRequest("invalid requestId".into()))?;

    let stored_pair: Option<(String, String, Option<Uuid>)> = sqlx::query_as(
        "SELECT a.actor_did,a.recipient_did,p.conversation_id \
           FROM chat.direct_request_attempts a \
           LEFT JOIN chat.direct_request_publications p USING(request_id) \
          WHERE a.request_id=$1",
    )
    .bind(request_id)
    .fetch_optional(pool)
    .await
    .map_err(|e| FederationError::Storage(e.to_string()))?;

    let (sender_did, expected_recipient_did, stored_conversation_id) =
        stored_pair.ok_or_else(|| {
            FederationError::NotFound(format!(
                "direct request {request_id} not found on coordinator"
            ))
        })?;
    if stored_conversation_id.is_some_and(|stored| stored != conversation_id) {
        return Err(FederationError::InvalidRequest(
            "outer conversationId does not match stored direct request".into(),
        ));
    }

    if actor_did != expected_recipient_did {
        return Err(FederationError::Forbidden(format!(
            "actor {actor_did} is not the recipient {expected_recipient_did} for request {request_id}"
        )));
    }

    let coord = resolve_pair_coordinator(pool, &sender_did, &expected_recipient_did).await?;
    if !coord.is_coordinator {
        return Err(FederationError::Forbidden(
            "Local node is not coordinator".into(),
        ));
    }
    if canonical_did(&coord.recipient_home.did) != canonical_did(requester_ds) {
        return Err(FederationError::AuthFailed {
            reason: format!(
                "Requester {requester_ds} is not recipient home DS {}",
                coord.recipient_home.did
            ),
        });
    }

    let raw_bytes = serde_json::to_vec(direct_request).map_err(FederationError::Json)?;

    let now = TrustedRequestInstant::capture()
        .map_err(|_| FederationError::Invariant("trusted instant".into()))?
        .datetime();

    let signer = runtime
        .request_receipt_signer()
        .ok_or_else(|| FederationError::ConfigError {
            reason: "request receipt signer not configured".into(),
        })?;
    let principal = crate::auth::VerifiedServicePrincipal::for_federated_s2s(
        actor_did,
        "blue.catbird.chat.acceptConversation",
    );

    let mut tx = pool
        .begin()
        .await
        .map_err(|e| FederationError::Storage(e.to_string()))?;
    let bytes = crate::chat_protocol::repository::acceptance::accept_direct_request(
        &mut tx,
        &principal,
        &raw_bytes,
        signer,
        runtime.i13_receipt_signer(),
        runtime.relationship_authority().as_ref(),
        now,
    )
    .await
    .map_err(|error| {
        use crate::chat_protocol::repository::{
            acceptance::DirectAcceptanceError as E, direct_request_retention::RetentionError as R,
        };
        match error {
            E::Database(error) | E::Retention(R::Database(error)) => {
                FederationError::Database(error)
            }
            E::PolicySourceUnavailable => FederationError::RelationshipPolicyUnavailable {
                reason: "acceptance relationship source could not answer".into(),
            },
            E::Blocked => FederationError::BlockedRelationship,
            error => FederationError::RemoteError {
                status: 400,
                body: format!("accept_direct_request error: {error:?}"),
            },
        }
    })?;

    let entry_row: Option<Vec<u8>> = sqlx::query_scalar(
        "SELECT accepted_payload_bytes FROM chat.entries WHERE conversation_id = $1 AND seq = 2",
    )
    .bind(conversation_id)
    .fetch_optional(&mut *tx)
    .await
    .map_err(|e| FederationError::Storage(e.to_string()))?;

    let entry: Value = entry_row
        .and_then(|b| serde_json::from_slice(&b).ok())
        .unwrap_or(json!({}));

    let outcome: Value = serde_json::from_slice(&bytes).map_err(FederationError::Json)?;
    let acceptance_proof = outcome.get("acceptanceProof").cloned().ok_or_else(|| {
        FederationError::Invariant("accepted outcome lacks signed acceptance proof".into())
    })?;

    let self_did = crate::identity::service_did();
    let deliver_payload = DeliverAcceptanceEntryInput {
        conversation_id,
        entry: entry.clone(),
        acceptance_proof: acceptance_proof.clone(),
    };
    let queue_id = format!("acceptance-delivery-{conversation_id}");

    if canonical_did(&coord.sender_home.did) != canonical_did(&self_did) {
        let payload_bytes = serde_json::to_vec(&deliver_payload).map_err(FederationError::Json)?;
        crate::federation::queue::enqueue_c33_in_tx(
            pool,
            &mut tx,
            &queue_id,
            &coord.sender_home.did,
            &coord.sender_home.endpoint,
            "blue.catbird.mlsDS.deliverAcceptanceEntry",
            &payload_bytes,
            &conversation_id.to_string(),
            "",
        )
        .await
        .map_err(queue_full_unavailable)?;
    }

    tx.commit()
        .await
        .map_err(|e| FederationError::Storage(e.to_string()))?;

    if canonical_did(&coord.sender_home.did) != canonical_did(&self_did) {
        if let Ok(()) = deliver_acceptance_entry_to_peer(
            &coord.sender_home.endpoint,
            &coord.sender_home.did,
            deliver_payload,
        )
        .await
        {
            let _ = crate::federation::queue::mark_delivered_by_id(pool, &queue_id).await;
        }
    }

    Ok(DeliverAcceptanceOutput {
        outcome_bytes: STANDARD.encode(&bytes),
        entry,
        acceptance_proof,
    })
}

/// Coordinator execution for relaySendMessage.
pub async fn coordinator_handle_message(
    pool: &DbPool,
    runtime: &Arc<ChatRuntime>,
    requester_ds: &str,
    conversation_id: Uuid,
    message: &Value,
) -> Result<Value, FederationError> {
    let actor_did = message
        .pointer("/body/actorDid")
        .and_then(|v| v.as_str())
        .ok_or_else(|| {
            FederationError::InvalidRequest("missing actorDid in message body".into())
        })?;
    let actor_device_id_str = message
        .pointer("/body/actorDeviceId")
        .and_then(|v| v.as_str())
        .ok_or_else(|| {
            FederationError::InvalidRequest("missing actorDeviceId in message body".into())
        })?;
    let actor_device_id = Uuid::parse_str(actor_device_id_str)
        .map_err(|_| FederationError::InvalidRequest("invalid actorDeviceId".into()))?;
    let key_id = message
        .pointer("/body/keyId")
        .and_then(|v| v.as_str())
        .ok_or_else(|| FederationError::InvalidRequest("missing keyId in message body".into()))?;
    let message_id_str = message
        .pointer("/body/messageId")
        .and_then(|v| v.as_str())
        .ok_or_else(|| {
            FederationError::InvalidRequest("missing messageId in message body".into())
        })?;
    let message_id = Uuid::parse_str(message_id_str)
        .map_err(|_| FederationError::InvalidRequest("invalid messageId".into()))?;

    // 1. Verify actor membership in conversation
    let actor_participant: Option<(String, bool, String)> = sqlx::query_as(
        "SELECT role, current_membership, status FROM chat.participants \
         WHERE conversation_id = $1 AND user_did = $2",
    )
    .bind(conversation_id)
    .bind(actor_did)
    .fetch_optional(pool)
    .await
    .map_err(|e| FederationError::Storage(e.to_string()))?;

    let (role, current_membership, status) = actor_participant.ok_or_else(|| {
        FederationError::Forbidden("actor is not a participant in this conversation".into())
    })?;

    if !current_membership || status != "active" || (role != "member" && role != "admin") {
        return Err(FederationError::Forbidden(
            "actor is not an active member in this conversation".into(),
        ));
    }

    // 2. Query conversation to check direct conversation rules and find peer
    let convo_row = sqlx::query(
        "SELECT kind, direct_did_low, direct_did_high FROM chat.conversations WHERE conversation_id = $1"
    )
    .bind(conversation_id)
    .fetch_optional(pool)
    .await
    .map_err(|e| FederationError::Storage(e.to_string()))?
    .ok_or_else(|| FederationError::NotFound(format!("conversation {conversation_id} not found")))?;

    let kind: String = convo_row
        .try_get("kind")
        .map_err(|e| FederationError::Storage(e.to_string()))?;
    let peer_did: String = if kind == "direct" {
        let low: String = convo_row
            .try_get("direct_did_low")
            .map_err(|e| FederationError::Storage(e.to_string()))?;
        let high: String = convo_row
            .try_get("direct_did_high")
            .map_err(|e| FederationError::Storage(e.to_string()))?;
        if actor_did == low {
            high
        } else if actor_did == high {
            low
        } else {
            return Err(FederationError::Forbidden(
                "actor does not belong to direct conversation".into(),
            ));
        }
    } else {
        let peer: Option<String> = sqlx::query_scalar(
            "SELECT user_did FROM chat.participants WHERE conversation_id = $1 AND user_did <> $2 AND current_membership LIMIT 1"
        )
        .bind(conversation_id)
        .bind(actor_did)
        .fetch_optional(pool)
        .await
        .map_err(|e| FederationError::Storage(e.to_string()))?;
        peer.unwrap_or_default()
    };

    // 3. Authenticate that requester_ds is the authoritative home DS of actor_did.
    // A peer deleted here is owed nothing and its declaration is typically gone:
    // sequencing the pair's conversation is then this DS's evidence that it
    // coordinates the pair, and only the actor's declared home is resolved.
    let coord = if account_deleted_in(pool, conversation_id, &peer_did)
        .await
        .map_err(|e| FederationError::Storage(e.to_string()))?
    {
        None
    } else {
        let coord = resolve_pair_coordinator(pool, actor_did, &peer_did).await?;
        if !coord.is_coordinator {
            return Err(FederationError::Forbidden(
                "Local node is not coordinator".into(),
            ));
        }
        Some(coord)
    };
    let sender_home = match &coord {
        Some(coord) => coord.sender_home.did.clone(),
        None => {
            pair_resolver(pool)
                .resolve_authoritative_ds(actor_did)
                .await?
                .did
        }
    };
    if canonical_did(&sender_home) != canonical_did(requester_ds) {
        return Err(FederationError::AuthFailed {
            reason: format!(
                "Requester {requester_ds} is not actor {actor_did} home DS {sender_home}"
            ),
        });
    }

    // 4. Verify active device key on coordinator & mutation signature
    let key_row: Option<(Vec<u8>, i64)> = sqlx::query_as(
        "SELECT k.signing_public_key, d.auth_generation \
         FROM chat.device_keys k \
         JOIN chat.devices d ON d.user_did = k.user_did AND d.device_id = k.device_id \
         WHERE k.user_did = $1 AND k.device_id = $2 AND k.key_id = $3 \
           AND k.revoked_at IS NULL AND d.status='active' AND d.revoked_at IS NULL \
           AND k.enrollment_auth_generation<=d.auth_generation \
           AND NOT EXISTS(SELECT 1 FROM chat.device_keys newer \
                WHERE newer.user_did=k.user_did AND newer.device_id=k.device_id \
                  AND newer.enrollment_auth_generation>k.enrollment_auth_generation \
                  AND newer.enrollment_auth_generation<=d.auth_generation)",
    )
    .bind(actor_did)
    .bind(actor_device_id)
    .bind(key_id)
    .fetch_optional(pool)
    .await
    .map_err(|e| FederationError::Storage(e.to_string()))?;

    let (signing_public_key, auth_generation) = key_row.ok_or_else(|| {
        FederationError::NotFound(format!(
            "Active device key {key_id} not found on coordinator"
        ))
    })?;

    let signed_bytes = serde_json::to_vec(message).map_err(FederationError::Json)?;

    let verified = crate::chat_protocol::transcript::decode_and_verify_signed_mutation(
        &signed_bytes,
        &signing_public_key,
    )
    .map_err(|e| {
        FederationError::InvalidRequest(format!("mutation signature verification failed: {e:?}"))
    })?;
    if verified.auth_generation() != auth_generation as u64 {
        return Err(FederationError::Forbidden(
            "stale authentication generation".into(),
        ));
    }

    // 5. Validate application message and AAD from projection
    let projection = match verified.projection() {
        crate::chat_protocol::transcript::VerifiedMutationProjection::ApplicationSend(p) => p,
        _ => {
            return Err(FederationError::InvalidRequest(
                "mutation is not an application send".into(),
            ))
        }
    };

    let app_msg = projection.application_message();
    let msg_bytes = match app_msg.get("bytes") {
        Some(crate::chat_protocol::transcript::CanonicalValueRef::Bytes(b)) => b,
        _ => {
            return Err(FederationError::InvalidRequest(
                "invalid application message bytes".into(),
            ))
        }
    };
    let msg_hash = match app_msg.get("sha256") {
        Some(crate::chat_protocol::transcript::CanonicalValueRef::Bytes(b)) if b.len() == 32 => b,
        _ => {
            return Err(FederationError::InvalidRequest(
                "invalid application message sha256".into(),
            ))
        }
    };
    if Sha256::digest(msg_bytes).as_slice() != msg_hash
        || !matches!(
            app_msg.get("framing"),
            Some(crate::chat_protocol::transcript::CanonicalValueRef::Text(
                "mlsMessage"
            ))
        )
        || !matches!(
            app_msg.get("contentType"),
            Some(crate::chat_protocol::transcript::CanonicalValueRef::Text(
                "privateMessageApplication"
            ))
        )
    {
        return Err(FederationError::InvalidRequest(
            "application message framing or digest mismatch".into(),
        ));
    }

    let aad = projection.aad();
    let aad_convo = match aad.get("conversationId") {
        Some(crate::chat_protocol::transcript::CanonicalValueRef::Bytes(v)) if v.len() == 16 => {
            Uuid::from_slice(v)
                .map_err(|_| FederationError::InvalidRequest("invalid aad convo".into()))?
        }
        _ => {
            return Err(FederationError::InvalidRequest(
                "invalid aad conversationId".into(),
            ))
        }
    };
    let aad_msg = match aad.get("messageId") {
        Some(crate::chat_protocol::transcript::CanonicalValueRef::Bytes(v)) if v.len() == 16 => {
            Uuid::from_slice(v)
                .map_err(|_| FederationError::InvalidRequest("invalid aad msg".into()))?
        }
        _ => {
            return Err(FederationError::InvalidRequest(
                "invalid aad messageId".into(),
            ))
        }
    };
    if aad_convo != conversation_id || aad_msg != message_id {
        return Err(FederationError::InvalidRequest(
            "aad conversationId or messageId mismatch".into(),
        ));
    }

    // 6. Idempotency check with replay redrive
    let mut tx = pool
        .begin()
        .await
        .map_err(|e| FederationError::Storage(e.to_string()))?;

    // 7. Lock conversation head and check coordinates
    let head_row = sqlx::query(
        "SELECT c.next_entry_seq, c.current_generation, c.current_state_version, \
                g.group_id, s.epoch, s.group_context_hash, s.confirmation_tag, c.lifecycle \
           FROM chat.conversations c \
           JOIN chat.generations g ON g.conversation_id = c.conversation_id AND g.generation = c.current_generation \
           JOIN chat.generation_states s ON s.conversation_id = c.conversation_id AND s.generation = c.current_generation AND s.state_version = c.current_state_version \
          WHERE c.conversation_id = $1 FOR UPDATE"
    )
    .bind(conversation_id)
    .fetch_optional(&mut *tx)
    .await
    .map_err(|e| FederationError::Storage(e.to_string()))?
    .ok_or_else(|| FederationError::NotFound("conversation head not found".into()))?;
    // A deleted peer's home gets none of this conversation's later entries.
    let deliver_to_peer = if distinct_nonempty_peer(&peer_did, actor_did) {
        should_deliver_to_peer(
            &peer_did,
            actor_did,
            account_deleted_in(&mut *tx, conversation_id, &peer_did)
                .await
                .map_err(|e| FederationError::Storage(e.to_string()))?,
        )
    } else {
        false
    };
    let self_did = crate::identity::service_did();
    let peer_home = coord
        .as_ref()
        .map(|coord| &coord.recipient_home)
        .filter(|home| deliver_to_peer && canonical_did(&home.did) != canonical_did(&self_did));
    let existing_send: Option<(String, Option<i64>, Vec<u8>, Option<Vec<u8>>)> = sqlx::query_as(
        "SELECT status, accepted_entry_seq, request_digest, outcome_bytes \
         FROM chat.message_sends \
         WHERE conversation_id = $1 AND message_id = $2",
    )
    .bind(conversation_id)
    .bind(message_id)
    .fetch_optional(&mut *tx)
    .await
    .map_err(|e| FederationError::Storage(e.to_string()))?;

    if let Some((status, _seq, stored_digest, outcome_bytes)) = existing_send {
        if stored_digest != verified.request_digest() {
            return Err(FederationError::CommitConflict {
                convo_id: conversation_id.to_string(),
                current_epoch: 0,
            });
        }
        if status == "accepted" {
            // A pruned send (O7) replays as its entry exactly as `getEntries`
            // serves it, `payloadPruned`: the accepted outcome, with no
            // ciphertext left to redeliver.
            let Some(outcome_bytes) = outcome_bytes else {
                let entry = crate::chat_protocol::repository::entry_read::sent_application_entry(
                    &mut tx,
                    conversation_id,
                    message_id,
                    &stored_digest,
                )
                .await
                .map_err(|e| FederationError::Storage(e.to_string()))?
                .ok_or_else(|| {
                    FederationError::Invariant("accepted message entry is missing".into())
                })?;
                return Ok(
                    crate::chat_protocol::repository::entry_read::accepted_send_outcome(entry),
                );
            };
            let mut resp_val: Value =
                serde_json::from_slice(&outcome_bytes).map_err(FederationError::Json)?;
            tx.commit()
                .await
                .map_err(|e| FederationError::Storage(e.to_string()))?;

            // Redrive peer delivery if remote peer
            let response_entry = resp_val.get_mut("entry").ok_or_else(|| {
                FederationError::Invariant("retained message outcome lacks entry".into())
            })?;
            response_entry["$type"] = json!("blue.catbird.chat.defs#applicationEntry");
            let response_entry = response_entry.clone();
            if let Some(home) = peer_home {
                let deliver_payload = DeliverMessageEntryInput {
                    conversation_id,
                    entry: response_entry,
                };
                // The send is committed and its delivery queued: a failed
                // redrive leaves that queue to deliver it, and the replay
                // still answers the accepted send.
                if let Err(error) =
                    deliver_message_entry_to_peer(&home.endpoint, &home.did, deliver_payload).await
                {
                    warn!(%error, %conversation_id, "replayed send's delivery redrive failed");
                }
            }

            return Ok(resp_val);
        }
    }

    let lifecycle: String = head_row
        .try_get("lifecycle")
        .map_err(|e| FederationError::Storage(e.to_string()))?;
    if lifecycle != "active" {
        return Err(FederationError::InvalidRequest(
            "conversation is not active".into(),
        ));
    }

    let head_generation: i64 = head_row
        .try_get("current_generation")
        .map_err(|e| FederationError::Storage(e.to_string()))?;
    let head_state_version: i64 = head_row
        .try_get("current_state_version")
        .map_err(|e| FederationError::Storage(e.to_string()))?;
    let head_group_id: Vec<u8> = head_row
        .try_get("group_id")
        .map_err(|e| FederationError::Storage(e.to_string()))?;
    let head_epoch: i64 = head_row
        .try_get("epoch")
        .map_err(|e| FederationError::Storage(e.to_string()))?;
    let head_gch: Vec<u8> = head_row
        .try_get("group_context_hash")
        .map_err(|e| FederationError::Storage(e.to_string()))?;
    let head_confirm_tag: Vec<u8> = head_row
        .try_get("confirmation_tag")
        .map_err(|e| FederationError::Storage(e.to_string()))?;
    let next_seq: i64 = head_row
        .try_get("next_entry_seq")
        .map_err(|e| FederationError::Storage(e.to_string()))?;

    let prior = projection.prior();
    let prior_gen = match prior.get("generation") {
        Some(crate::chat_protocol::transcript::CanonicalValueRef::Integer(v)) => {
            i64::try_from(v)
                .map_err(|_| FederationError::InvalidRequest("invalid prior gen".into()))?
        }
        _ => {
            return Err(FederationError::InvalidRequest(
                "missing prior generation".into(),
            ))
        }
    };
    let prior_ver = match prior.get("stateVersion") {
        Some(crate::chat_protocol::transcript::CanonicalValueRef::Integer(v)) => {
            i64::try_from(v)
                .map_err(|_| FederationError::InvalidRequest("invalid prior ver".into()))?
        }
        _ => {
            return Err(FederationError::InvalidRequest(
                "missing prior stateVersion".into(),
            ))
        }
    };
    let prior_epoch = match prior.get("epoch") {
        Some(crate::chat_protocol::transcript::CanonicalValueRef::Integer(v)) => {
            i64::try_from(v)
                .map_err(|_| FederationError::InvalidRequest("invalid prior epoch".into()))?
        }
        _ => {
            return Err(FederationError::InvalidRequest(
                "missing prior epoch".into(),
            ))
        }
    };
    let prior_group_id = match prior.get("groupId") {
        Some(crate::chat_protocol::transcript::CanonicalValueRef::Bytes(v)) => v,
        _ => {
            return Err(FederationError::InvalidRequest(
                "missing prior groupId".into(),
            ))
        }
    };
    let prior_gch = match prior.get("groupContextHash") {
        Some(crate::chat_protocol::transcript::CanonicalValueRef::Bytes(v)) => v,
        _ => {
            return Err(FederationError::InvalidRequest(
                "missing prior groupContextHash".into(),
            ))
        }
    };
    let prior_tag = match prior.get("confirmationTag") {
        Some(crate::chat_protocol::transcript::CanonicalValueRef::Bytes(v)) => v,
        _ => {
            return Err(FederationError::InvalidRequest(
                "missing prior confirmationTag".into(),
            ))
        }
    };

    if prior_gen != head_generation
        || prior_ver != head_state_version
        || prior_epoch != head_epoch
        || prior_group_id != head_group_id.as_slice()
        || prior_gch != head_gch.as_slice()
        || prior_tag != head_confirm_tag.as_slice()
    {
        return Err(FederationError::InvalidRequest(
            "stale application coordinates".into(),
        ));
    }
    let send_counter = i64::try_from(projection.send_counter())
        .map_err(|_| FederationError::InvalidRequest("invalid sendCounter".into()))?;

    // 8. Device leaf check
    let is_leaf: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM chat.application_intervals \
          WHERE conversation_id = $1 AND generation = $2 AND recipient_did = $3 AND recipient_device_id = $4 \
            AND start_seq <= (SELECT next_entry_seq - 1 FROM chat.conversations WHERE conversation_id = $1) \
            AND (terminal_seq IS NULL OR terminal_seq >= (SELECT next_entry_seq - 1 FROM chat.conversations WHERE conversation_id = $1)) \
            AND opening_state_version <= $5)"
    )
    .bind(conversation_id)
    .bind(head_generation)
    .bind(actor_did)
    .bind(actor_device_id)
    .bind(head_state_version)
    .fetch_one(&mut *tx)
    .await
    .map_err(|error| FederationError::Storage(error.to_string()))?;

    if !is_leaf {
        return Err(FederationError::Forbidden(
            "actor device is not a leaf in conversation".into(),
        ));
    }

    // 9. Recipient readiness
    let recipient_ready: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM chat.application_intervals i \
          JOIN chat.participants p ON p.conversation_id = i.conversation_id AND p.user_did = i.recipient_did \
          WHERE i.conversation_id = $1 AND i.generation = $2 \
            AND p.user_did = $3 \
            AND p.current_membership AND p.status = 'active' \
            AND (p.accepted_at IS NOT NULL OR p.invitation_transition_id IS NULL) \
            AND i.start_seq <= (SELECT next_entry_seq - 1 FROM chat.conversations WHERE conversation_id = $1) \
            AND (i.terminal_seq IS NULL OR i.terminal_seq >= (SELECT next_entry_seq - 1 FROM chat.conversations WHERE conversation_id = $1)))"
    )
    .bind(conversation_id)
    .bind(head_generation)
    .bind(&peer_did)
    .fetch_one(&mut *tx)
    .await
    .map_err(|error| FederationError::Storage(error.to_string()))?;

    if !recipient_ready {
        return Err(FederationError::Forbidden(
            "recipient not ready or has not accepted conversation".into(),
        ));
    }

    let mut head_binding = Sha256::new();
    head_binding.update(conversation_id.as_bytes());
    head_binding.update(head_generation.to_be_bytes());
    head_binding.update(head_state_version.to_be_bytes());
    head_binding.update(next_seq.to_be_bytes());
    head_binding.update(&head_gch);
    let allowed = crate::chat_protocol::repository::relationship::verify_federated_send_policy(
        &mut tx,
        actor_did,
        &peer_did,
        Sha256::digest(&signed_bytes).into(),
        head_binding.finalize().into(),
        runtime.relationship_authority().as_ref(),
    )
    .await
    .map_err(|error| {
        use crate::chat_protocol::repository::relationship::RelationshipRepositoryError as R;
        match error {
            R::Database(error) => FederationError::Database(error),
            // A source that could not answer now, or this DS's relationship
            // authority unconfigured, decided nothing.
            error @ (R::Unavailable | R::InvalidAuthorityConfiguration(_)) => {
                FederationError::RelationshipPolicyUnavailable {
                    reason: format!("federated send policy: {error:?}"),
                }
            }
            R::InvalidProjection => FederationError::InvalidProof,
        }
    })?;
    if !allowed {
        return Err(FederationError::BlockedRelationship);
    }

    // 11. Build verified entry and commit send
    let trusted_instant = crate::chat_protocol::validation::TrustedRequestInstant::capture()
        .map_err(|_| FederationError::Invariant("trusted instant".into()))?;
    let trusted_now = trusted_instant.datetime();
    let canonical_now_str = trusted_now.to_rfc3339_opts(chrono::SecondsFormat::Millis, true);

    let entry_id = crate::sim_hooks::mint_entry_uuid_v4(
        b"mlsDS.relaySendMessage",
        &[
            conversation_id.as_bytes(),
            &next_seq.to_be_bytes(),
            message_id.as_bytes(),
        ],
    );
    let entry_id_str = entry_id.to_string();

    let canon_entry_id = crate::chat_protocol::validation::CanonicalUuidV4::parse(&entry_id_str)
        .map_err(|_| FederationError::Invariant("invalid entry_id".into()))?;
    let canon_convo_id =
        crate::chat_protocol::validation::CanonicalUuidV4::parse(&conversation_id.to_string())
            .map_err(|_| FederationError::Invariant("invalid convo_id".into()))?;

    let archive = crate::chat_protocol::transcript::verify_application_archive_attestation(
        projection.aad(),
        actor_did,
        actor_device_id,
        &signing_public_key,
        conversation_id,
        message_id,
    )
    .map_err(|error| FederationError::InvalidRequest(error.to_string()))?;

    let entry_product = crate::chat_protocol::transcript::build_verified_application_entry(
        verified,
        canon_entry_id,
        canon_convo_id,
        next_seq as u64,
        &trusted_instant,
    )
    .map_err(|e| FederationError::InvalidRequest(format!("build entry failed: {e:?}")))?;

    let accepted_payload_bytes = entry_product.canonical_entry_bytes().to_vec();
    let accepted_payload_sha256 = entry_product.accepted_payload_sha256().to_vec();
    let request_digest = entry_product.mutation().request_digest().to_vec();
    let signature = entry_product.mutation().signature().to_vec();
    let fingerprint = entry_product.outer_application_fingerprint().to_vec();
    let server_fields =
        serde_ipld_dagcbor::to_vec(&std::collections::BTreeMap::<String, String>::new())
            .map_err(|_| FederationError::Invariant("server fields".into()))?;
    let i13_receipt_json = match (archive, runtime.i13_receipt_signer()) {
        (Some(archive), Some(signer)) => {
            let signed_receipt = signer
                .sign_application_receipt(
                    &conversation_id.to_string(),
                    &head_group_id,
                    head_epoch.max(0) as u64,
                    actor_did,
                    &actor_device_id.to_string(),
                    &entry_id_str,
                    archive.commitment(),
                    next_seq.max(0) as u64,
                    trusted_now.timestamp_millis(),
                )
                .map_err(|e| FederationError::Invariant(e.to_string()))?;
            Some(
                crate::federation::receipt::I13ReceiptSigner::receipt_wire_json(
                    &signed_receipt,
                    head_generation.max(0) as u64,
                    actor_did,
                    &actor_device_id.to_string(),
                ),
            )
        }
        (None, Some(_)) => {
            return Err(FederationError::InvalidRequest(
                "application archive commitment is required when receipt issuance is enabled"
                    .into(),
            ))
        }
        (_, None) => None,
    };

    let mut entry_for_outcome = json!({
        "entryId": entry_id_str,
        "conversationId": conversation_id.to_string(),
        "seq": next_seq,
        "signedRequest": message,
        "receivedAt": canonical_now_str
    });
    let mut outcome_json = json!({ "entry": entry_for_outcome });
    if let Some(ref rcpt) = i13_receipt_json {
        entry_for_outcome["sequencerReceipt"] = rcpt.clone();
        outcome_json = json!({
            "entry": entry_for_outcome,
            "sequencerReceipt": rcpt.clone(),
        });
    }
    let outcome_bytes = serde_json::to_vec(&outcome_json).map_err(FederationError::Json)?;

    let append_entry = crate::chat_protocol::repository::delivery::AppendEntry {
        conversation_id,
        entry_id,
        entry_kind: "blue.catbird.chat.defs#applicationEntry".to_string(),
        accepted_payload_bytes,
        accepted_payload_sha256,
        signed_request_bytes: signed_bytes,
        request_digest,
        signature,
        server_fields_bytes: server_fields,
        outer_entry_fingerprint: fingerprint,
        actor_did: actor_did.to_string(),
        actor_device_id,
        actor_key_id: key_id.to_string(),
        actor_auth_generation: auth_generation,
        generation: Some(head_generation),
        state_version: Some(head_state_version),
        transition_id: None,
        message_id: Some(message_id),
        received_at: trusted_now,
    };

    let app_send = crate::chat_protocol::repository::delivery::ApplicationSend {
        entry: append_entry,
        signing_transcript_bytes: entry_product.mutation().transcript_bytes().to_vec(),
        outcome_bytes,
        epoch: prior_epoch,
        send_counter,
    };

    let outcome = crate::chat_protocol::repository::delivery::resolve_application_send(
        &mut tx,
        &app_send,
        crate::chat_protocol::repository::delivery::ApplicationSendDisposition::Accept,
    )
    .await
    .map_err(|e| match e {
        crate::chat_protocol::repository::delivery::DeliveryRepositoryError::MessageSendConflict => {
            FederationError::CommitConflict {
                convo_id: conversation_id.to_string(),
                current_epoch: 0,
            }
        }
        other => FederationError::Storage(format!("{other:?}")),
    })?;

    let seq = match outcome {
        crate::chat_protocol::repository::delivery::ApplicationSendOutcome::Accepted { seq } => seq,
        crate::chat_protocol::repository::delivery::ApplicationSendOutcome::Stale => {
            return Err(FederationError::InvalidRequest(
                "stale application coordinates".into(),
            ));
        }
        crate::chat_protocol::repository::delivery::ApplicationSendOutcome::StaleSend => {
            return Err(FederationError::StaleSend);
        }
    };
    // A replay returns its stored seq; this receipt signs only a fresh append.
    if let (true, Some(rcpt)) = (seq as i64 == next_seq, &i13_receipt_json) {
        let rcpt_bytes = serde_json::to_vec(rcpt).map_err(FederationError::Json)?;
        crate::chat_protocol::repository::delivery::set_entry_sequencer_receipt(
            &mut tx,
            conversation_id,
            seq,
            &rcpt_bytes,
        )
        .await
        .map_err(|e| FederationError::Storage(format!("{e:?}")))?;
    }

    let _ = crate::chat_protocol::repository::message_event::append_message_available_event(
        &mut tx,
        conversation_id,
        0,
        seq,
        trusted_now,
    )
    .await;

    let mut response_entry = json!({
        "$type": "blue.catbird.chat.defs#applicationEntry",
        "entryId": entry_id_str,
        "conversationId": conversation_id.to_string(),
        "seq": seq,
        "signedRequest": message,
        "receivedAt": canonical_now_str
    });
    if let Some(ref rcpt) = i13_receipt_json {
        response_entry["sequencerReceipt"] = rcpt.clone();
    }

    let deliver_payload = DeliverMessageEntryInput {
        conversation_id,
        entry: response_entry.clone(),
    };
    let queue_id = format!("msg-delivery-{conversation_id}-{seq}");

    if let Some(home) = peer_home {
        let payload_bytes = serde_json::to_vec(&deliver_payload).map_err(FederationError::Json)?;
        crate::federation::queue::enqueue_c33_in_tx(
            pool,
            &mut tx,
            &queue_id,
            &home.did,
            &home.endpoint,
            "blue.catbird.mlsDS.deliverMessageEntry",
            &payload_bytes,
            &conversation_id.to_string(),
            "",
        )
        .await
        .map_err(queue_full_unavailable)?;
    }

    tx.commit()
        .await
        .map_err(|e| FederationError::Storage(e.to_string()))?;

    runtime.notify_events();

    if let Some(push_client) = runtime.push_gateway_client() {
        let local_devices: Vec<(String, Uuid)> = sqlx::query_as(
            "SELECT recipient_did, recipient_device_id FROM chat.application_intervals \
              WHERE conversation_id = $1 AND generation = $2 \
                AND recipient_did != $3 \
                AND terminal_seq IS NULL",
        )
        .bind(conversation_id)
        .bind(head_generation)
        .bind(actor_did)
        .fetch_all(pool)
        .await
        .unwrap_or_default();
        if !local_devices.is_empty() {
            let ct = message
                .pointer("/body/applicationMessage/bytes")
                .and_then(|v| {
                    v.as_str()
                        .or_else(|| v.get("$bytes").and_then(Value::as_str))
                })
                .and_then(|s| {
                    STANDARD
                        .decode(s)
                        .or_else(|_| URL_SAFE_NO_PAD.decode(s))
                        .ok()
                });
            let _ = push_client
                .dispatch_for_local_recipients(
                    pool,
                    &local_devices,
                    crate::push_gateway::client::PushWakeDispatch {
                        wake_kind: crate::push_gateway::client::PushWakeKind::ApplicationMessage,
                        conversation_id,
                        generation: head_generation,
                        seq: seq as i64,
                        epoch: head_epoch,
                        ciphertext: ct,
                    },
                )
                .await;
        }
    }

    if let Some(home) = peer_home {
        if let Ok(()) =
            deliver_message_entry_to_peer(&home.endpoint, &home.did, deliver_payload).await
        {
            let _ = crate::federation::queue::mark_delivered_by_id(pool, &queue_id).await;
        }
    }
    let mut out = json!({ "entry": response_entry });
    if let Some(rcpt) = i13_receipt_json {
        out["sequencerReceipt"] = rcpt;
    }
    Ok(out)
}

/// Coordinator execution for getDirectRequestOutcome.
pub async fn coordinator_get_outcome(
    pool: &DbPool,
    runtime: &Arc<ChatRuntime>,
    requester_ds: &str,
    request_id: Uuid,
    actor_device_id: Uuid,
) -> Result<Value, FederationError> {
    let attempt: Option<(String, String)> = sqlx::query_as(
        "SELECT actor_did, recipient_did FROM chat.direct_request_attempts WHERE request_id = $1",
    )
    .bind(request_id)
    .fetch_optional(pool)
    .await
    .map_err(|e| FederationError::Storage(e.to_string()))?;

    let (actor_did, recipient_did) = match attempt {
        Some((a, r)) => (a, r),
        None => {
            // Coordinator pre-commit crash or cancelled intent: check durable reservation intent
            let intent: Option<(String, Option<Uuid>, String, String, String, DateTime<Utc>)> = sqlx::query_as(
                "SELECT actor_did, actor_device_id, recipient_did, recipient_ds_did, status, created_at \
                 FROM chat.direct_request_reservation_intents \
                 WHERE request_id = $1"
            )
            .bind(request_id)
            .fetch_optional(pool)
            .await
            .map_err(|e| FederationError::Storage(e.to_string()))?;

            if let Some((_actor, intent_actor_dev, _rec, rec_ds, status, created_at)) = intent {
                // Must authenticate requester as the recipient's declared home DS
                if canonical_did(&rec_ds) != canonical_did(requester_ds) {
                    return Err(FederationError::AuthFailed {
                        reason: format!("Requester {requester_ds} is not the declared recipient home DS {rec_ds}"),
                    });
                }

                // Bind queried actor_device_id to persisted intent.actor_device_id
                if let Some(expected_dev) = intent_actor_dev {
                    if expected_dev != actor_device_id {
                        return Err(FederationError::AuthFailed {
                            reason: format!("actor_device_id {actor_device_id} does not match intent {expected_dev}"),
                        });
                    }
                }

                let now = crate::sim_hooks::current_utc();
                if status == "cancelled" {
                    return Ok(json!({
                        "outcome": {
                            "$type": "blue.catbird.chat.defs#directRequestCancelledReceipt",
                            "requestId": request_id.to_string()
                        }
                    }));
                } else if created_at <= now - chrono::Duration::seconds(300) {
                    // Pre-commit crash: intent is >300s old and no attempt was ever committed.
                    // Authenticated coordinator authoritatively returns directRequestUnknownOutcome.
                    return Ok(json!({
                        "outcome": {
                            "$type": "blue.catbird.chat.defs#directRequestUnknownOutcome",
                            "requestId": request_id.to_string()
                        }
                    }));
                } else {
                    // Intent is still within active prepare window (<300s old): cannot prove unknown yet
                    return Err(FederationError::NotFound(
                        "attempt in flight or not found".into(),
                    ));
                }
            }
            return Err(FederationError::NotFound("attempt not found".into()));
        }
    };
    let coord = resolve_pair_coordinator(pool, &actor_did, &recipient_did).await;
    let authorized = match &coord {
        Ok(c) => {
            canonical_did(&c.sender_home.did) == canonical_did(requester_ds)
                || canonical_did(&c.recipient_home.did) == canonical_did(requester_ds)
                || canonical_did(&c.coordinator_did) == canonical_did(requester_ds)
        }
        Err(_) => false,
    };
    if !authorized {
        let http = super::resolver::build_resolver_http_client();
        let resolver = DsResolver::with_default_endpoint(
            pool.clone(),
            http,
            crate::identity::service_did(),
            crate::identity::self_endpoint(),
            std::env::var("DEFAULT_DS_ENDPOINT").ok(),
            3600,
        );
        // Either party's declared home may read it. A home that could not be
        // resolved now, or this database, decided nothing: that failure is the
        // answer, never an authentication refusal.
        let mut home_matches = false;
        let mut undecided = None;
        for did in [&actor_did, &recipient_did] {
            match resolver.resolve_authoritative_ds(did).await {
                Ok(home) => home_matches |= canonical_did(&home.did) == canonical_did(requester_ds),
                Err(error) if error.is_retryable() => undecided = Some(error),
                Err(_) => {}
            }
        }
        if !home_matches {
            return Err(undecided.unwrap_or_else(|| FederationError::AuthFailed {
                reason: format!("Requester {requester_ds} is not authorized for outcome of request {request_id}"),
            }));
        }
    }

    let now = TrustedRequestInstant::capture()
        .map_err(|_| FederationError::Invariant("trusted instant".into()))?
        .datetime();
    let signer = runtime
        .request_receipt_signer()
        .ok_or_else(|| FederationError::ConfigError {
            reason: "request receipt signer not configured".into(),
        })?;

    let principal = crate::auth::VerifiedServicePrincipal::for_federated_s2s(
        &actor_did,
        "blue.catbird.chat.getDirectRequestOutcome",
    );

    let mut tx = pool
        .begin()
        .await
        .map_err(|e| FederationError::Storage(e.to_string()))?;
    let result =
        crate::chat_protocol::repository::direct_request_preparation::get_direct_request_outcome(
            &mut tx,
            &principal,
            actor_device_id,
            request_id,
            signer,
            now,
        )
        .await
        .map_err(|e| FederationError::RemoteError {
            status: if e.is_transient() { 503 } else { 400 },
            body: format!("get_direct_request_outcome error: {e:?}"),
        })?;

    let outcome_val = match result {
        crate::chat_protocol::repository::direct_request_preparation::DirectRequestResult::Keys(bytes) => {
            serde_json::from_slice(&bytes).map_err(FederationError::Json)?
        }
        crate::chat_protocol::repository::direct_request_preparation::DirectRequestResult::Unknown(id) => {
            json!({"$type":"blue.catbird.chat.defs#directRequestUnknownOutcome","requestId":id.to_string()})
        }
        crate::chat_protocol::repository::direct_request_preparation::DirectRequestResult::Prepared(bytes) => {
            let prep: Value = serde_json::from_slice(&bytes).map_err(FederationError::Json)?;
            json!({"$type":"blue.catbird.chat.defs#directRequestPreparedOutcome","preparation":prep})
        }
        crate::chat_protocol::repository::direct_request_preparation::DirectRequestResult::Terminal(bytes) => {
            let mut val: Value = serde_json::from_slice(&bytes).map_err(FederationError::Json)?;
            val["$type"] = json!("blue.catbird.chat.defs#signedDirectRequestReceipt");
            val
        }
    };
    tx.commit()
        .await
        .map_err(|e| FederationError::Storage(e.to_string()))?;

    let entry_val =
        crate::chat_protocol::repository::direct_request_opening::coordinator_opening_response(
            &mut *pool
                .acquire()
                .await
                .map_err(|e| FederationError::Storage(e.to_string()))?,
            request_id,
        )
        .await
        .map_err(|e| FederationError::Storage(e.to_string()))?
        .map(|(entry, _)| entry);
    if outcome_val
        .pointer("/body/receipt/$type")
        .and_then(Value::as_str)
        == Some("blue.catbird.chat.defs#directRequestPublishedReceipt")
        && entry_val.is_none()
    {
        return Err(FederationError::Invariant(
            "published outcome lacks opening evidence".into(),
        ));
    }
    let mut resp = json!({ "outcome": outcome_val });
    if let Some(entry) = entry_val {
        resp["entry"] = entry;
    }
    Ok(resp)
}

fn authorized_device_key<'a>(keys: &'a [Vec<u8>], key_id: &str) -> Option<&'a [u8]> {
    keys.iter()
        .find(|key| {
            URL_SAFE_NO_PAD.encode(Sha256::digest(key)) == key_id
                || STANDARD.encode(key) == key_id
                || crate::chat_protocol::validation::ed25519_key_id(key)
                    .map(|id| id.as_str() == key_id)
                    .unwrap_or(false)
        })
        .map(Vec::as_slice)
        .or_else(|| {
            if keys.len() == 1 {
                keys.first().map(Vec::as_slice)
            } else {
                None
            }
        })
}

fn distinct_nonempty_peer(peer_did: &str, actor_did: &str) -> bool {
    !peer_did.is_empty() && peer_did != actor_did
}

fn should_deliver_to_peer(peer_did: &str, actor_did: &str, account_deleted: bool) -> bool {
    distinct_nonempty_peer(peer_did, actor_did) && !account_deleted
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unknown_device_key_falls_back_only_for_one_authorized_key() {
        let first = vec![0x11; 32];
        let second = vec![0x22; 32];
        assert_eq!(
            authorized_device_key(std::slice::from_ref(&first), "legacy-id"),
            Some(first.as_slice())
        );
        assert!(authorized_device_key(&[first, second], "unknown-id").is_none());
    }

    #[test]
    fn peer_delivery_requires_a_distinct_nonempty_live_peer() {
        assert!(should_deliver_to_peer(
            "did:plc:bob",
            "did:plc:alice",
            false
        ));
        assert!(!should_deliver_to_peer("", "did:plc:alice", false));
        assert!(!should_deliver_to_peer(
            "did:plc:alice",
            "did:plc:alice",
            false
        ));
        assert!(!should_deliver_to_peer(
            "did:plc:bob",
            "did:plc:alice",
            true
        ));
    }
}

#[cfg(test)]
#[path = "canonical_relay_c2_unit_tests.rs"]
mod c2_unit_tests;
