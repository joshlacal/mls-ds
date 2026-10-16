//! Canonical S2S Relay and Coordination for blue.catbird.chat direct requests.
//!
//! Provides deterministic coordinator resolution, staged remote reservation,
//! authenticated XRPC relaying, remote Welcome/entry delivery, and acceptance/reply routing
//! across independent chat authorities with zero legacy fallback.

use std::sync::Arc;
use base64::{engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD}, Engine};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sqlx::{Postgres, Row, Transaction};
use tracing::{debug, error, info, warn};
use uuid::Uuid;
use sha2::{Digest, Sha256};
use crate::chat_protocol::validation::TrustedRequestInstant;
use crate::identity::canonical_did;
use crate::realtime::SseState;
use crate::storage::DbPool;
use crate::handlers::chat::ChatRuntime;
use super::{
    errors::FederationError,
    outbound::OutboundClient,
    resolver::{DsEndpoint, DsResolver},
    service_auth::ServiceAuthClient,
};

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

/// Which side of a pair failed to resolve to an admitted chat authority.
#[derive(Debug)]
pub enum PairResolutionError {
    Sender(FederationError),
    /// The sender's home resolved. `declared_authority` is the delivery
    /// service the recipient's declaration names, when it could be read.
    Recipient {
        sender_home: DsEndpoint,
        declared_authority: Option<String>,
        error: FederationError,
    },
}

impl PairResolutionError {
    pub fn into_federation_error(self) -> FederationError {
        match self {
            Self::Sender(error) | Self::Recipient { error, .. } => error,
        }
    }

    /// When the sender is homed on `self_did` and the recipient has no chat authority
    /// this DS could ever join (no declaration, a malformed or unsupported
    /// one, or an authority that is not an allowed peer), this DS coordinates
    /// the attempt alone so the repository can sign its terminal refusal.
    /// Clients verify receipts against the lower of the two authority DIDs, so
    /// a declared authority that sorts below this one gets no signed refusal.
    /// Transient failures are not refusals and return `None`.
    pub fn local_refusal_coordinator(&self, self_did: &str) -> Option<CanonicalPairCoordinator> {
        let Self::Recipient {
            sender_home,
            declared_authority,
            error,
        } = self
        else {
            return None;
        };
        let home = canonical_did(&sender_home.did);
        if home != canonical_did(self_did) {
            return None;
        }
        let refusal = matches!(
            error,
            FederationError::Unsupported(_)
                | FederationError::AuthFailed { .. }
                | FederationError::ResolutionFailed {
                    kind: super::errors::ResolutionFailureKind::InvalidDeclaration(_),
                    ..
                }
        );
        if !refusal
            || declared_authority
                .as_deref()
                .is_some_and(|a| canonical_did(a) < home)
        {
            return None;
        }
        Some(CanonicalPairCoordinator {
            sender_home: sender_home.clone(),
            recipient_home: sender_home.clone(),
            coordinator_did: home.to_string(),
            is_coordinator: true,
            is_sender_home: true,
            is_recipient_home: true,
        })
    }
}

/// Resolve the deterministic pair coordinator for a sender and recipient pair.
pub async fn resolve_pair_coordinator(
    pool: &DbPool,
    sender_did: &str,
    recipient_did: &str,
) -> Result<CanonicalPairCoordinator, FederationError> {
    resolve_pair_coordinator_by_side(pool, sender_did, recipient_did)
        .await
        .map_err(PairResolutionError::into_federation_error)
}

/// [`resolve_pair_coordinator`], saying which side failed.
pub async fn resolve_pair_coordinator_by_side(
    pool: &DbPool,
    sender_did: &str,
    recipient_did: &str,
) -> Result<CanonicalPairCoordinator, PairResolutionError> {
    let self_did = crate::identity::service_did();
    let self_endpoint = crate::identity::self_endpoint();
    let default_ds = std::env::var("DEFAULT_DS_ENDPOINT").ok();
    let cache_ttl: u64 = std::env::var("ENDPOINT_CACHE_TTL")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(3600);

    let http = super::resolver::build_resolver_http_client();

    let resolver = DsResolver::with_default_endpoint(
        pool.clone(),
        http,
        self_did,
        self_endpoint,
        default_ds,
        cache_ttl,
    );

    let sender_home = resolver
        .resolve_authoritative_ds(sender_did)
        .await
        .map_err(PairResolutionError::Sender)?;
    let declared_authority = match resolver.resolve_declared_authority(recipient_did).await {
        Ok(authority) => authority,
        Err(error) => {
            return Err(PairResolutionError::Recipient {
                sender_home,
                declared_authority: None,
                error,
            })
        }
    };
    let recipient_home = match resolver.admit_declared_authority(&declared_authority).await {
        Ok(home) => home,
        Err(error) => {
            return Err(PairResolutionError::Recipient {
                sender_home,
                declared_authority: Some(declared_authority),
                error,
            })
        }
    };
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

    Ok(CanonicalPairCoordinator {
        sender_home,
        recipient_home,
        coordinator_did,
        is_coordinator,
        is_sender_home,
        is_recipient_home,
    })
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
            PairFenceConflict::ForeignCoordinator { coordinator_did, source, status } => {
                write!(f, "pair already owned by coordinator {coordinator_did} (source: {source}, status: {status})")
            }
            PairFenceConflict::LocalConflict { source, status } => {
                write!(f, "pair conflict exists (source: {source}, status: {status})")
            }
        }
    }
}

/// Durable, verifiable pair owner fence across both authorities.
///
/// Verifies across all local and federated repository state that no active,
/// pending, or finalized pair already exists under another coordinator or conflicting attempt.
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
                  (a.status = 'prepared' AND a.lease_expires_at > clock_timestamp()) \
                  OR a.status IN ('published', 'existing-direct') \
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
                coordinator_did, \
                'remote_leases'::text AS source_table, \
                status, \
                leased_at AS created_at \
            FROM chat.direct_request_remote_leases \
            WHERE ((sender_did = $1 AND recipient_did = $2) OR (sender_did = $2 AND recipient_did = $1)) \
              AND request_id <> $3 \
              AND ( \
                  (status = 'active' AND expires_at > clock_timestamp()) \
                  OR status = 'finalized' \
              ) \
            UNION ALL \
            SELECT \
                coordinator_did, \
                'outbound_routes'::text AS source_table, \
                'routed'::text AS status, \
                created_at \
            FROM chat.direct_request_outbound_routes \
            WHERE ((actor_did = $1 AND recipient_did = $2) OR (actor_did = $2 AND recipient_did = $1)) \
              AND request_id <> $3 \
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
    let signing_key_pem = std::env::var("SIGNING_KEY_PEM").map_err(|_| {
        FederationError::ConfigError {
            reason: "SIGNING_KEY_PEM is required for S2S federation".to_string(),
        }
    })?;
    let client = ServiceAuthClient::from_es256_pem(
        service_did,
        signing_key_pem.as_bytes(),
        None,
    )
    .map_err(|e| FederationError::ConfigError {
        reason: format!("ServiceAuthClient error: {e}"),
    })?;
    client.mint_token(target_did, method).map_err(|e| {
        FederationError::AuthFailed {
            reason: format!("mint S2S token error: {e}"),
        }
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
         WHERE request_id = $1"
    )
    .bind(request_id)
    .fetch_optional(pool)
    .await
    .map_err(|e| FederationError::Storage(format!("intent check failed: {e}")))?;

    if let Some((existing_actor, existing_dev, existing_rec, existing_ds, status)) = existing_intent {
        if canonical_did(&existing_actor) != canonical_did(sender_did)
            || canonical_did(&existing_rec) != canonical_did(recipient_did)
            || canonical_did(&existing_ds) != canonical_did(target_did)
            || (actor_device_id_opt.is_some() && existing_dev.is_some() && actor_device_id_opt != existing_dev)
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
             VALUES ($1, $2, $3, $4, $5, 'pending', clock_timestamp())"
        )
        .bind(request_id)
        .bind(sender_did)
        .bind(actor_device_id_opt)
        .bind(recipient_did)
        .bind(target_did)
        .execute(pool)
        .await
        .map_err(|e| FederationError::Storage(format!("mandatory intent insertion failed: {e}")))?;
    }

    let request_digest = signed_prepare.as_ref().and_then(|p| {
        serde_json::to_vec(p).ok().map(|b| hex::encode(Sha256::digest(&b)))
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
        .map_err(|e| FederationError::RemoteError {
            status: 502,
            body: format!("reserveRecipientBootstrap RPC failed: {e}"),
        })?;
    let output: ReserveRecipientBootstrapOutput = serde_json::from_value(resp).map_err(|e| {
        FederationError::RemoteError {
            status: 502,
            body: format!("malformed reserveRecipientBootstrap response: {e}"),
        }
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

    sqlx::query(
        "DELETE FROM chat.direct_request_reserved_remote_packages WHERE request_id = $1"
    )
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
        .map_err(|error| FederationError::RemoteError {
            status: 502,
            body: format!("releaseRecipientBootstrap failed: {error}"),
        })?;
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
        .map_err(|e| match e {
            crate::federation::outbound::OutboundError::RemoteError { status, body, .. } => {
                FederationError::RemoteError { status, body }
            }
            other => FederationError::RemoteError {
                status: 502,
                body: format!("relay prepareDirectRequest failed: {other}"),
            },
        })
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
        .map_err(|e| match e {
            crate::federation::outbound::OutboundError::RemoteError { status, body, .. } => {
                FederationError::RemoteError { status, body }
            }
            other => FederationError::RemoteError {
                status: 502,
                body: format!("relay publishDirectRequest failed: {other}"),
            },
        })
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
        .map_err(|e| FederationError::RemoteError {
            status: 502,
            body: format!("deliverDirectRequest failed: {e}"),
        })?;
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
        .map_err(|e| match e {
            crate::federation::outbound::OutboundError::RemoteError { status, body, .. } => {
                FederationError::RemoteError { status, body }
            }
            other => FederationError::RemoteError {
                status: 502,
                body: format!("deliverAcceptance failed: {other}"),
            },
        })?;
    serde_json::from_value(resp).map_err(|e| FederationError::RemoteError {
        status: 502,
        body: format!("malformed deliverAcceptance response: {e}"),
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
        .map_err(|e| FederationError::RemoteError {
            status: 502,
            body: format!("deliverAcceptanceEntry failed: {e}"),
        })?;
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
        .map_err(|e| match e {
            crate::federation::outbound::OutboundError::RemoteError { status, body, .. } => {
                FederationError::RemoteError { status, body }
            }
            other => FederationError::RemoteError {
                status: 502,
                body: format!("relaySendMessage failed: {other}"),
            },
        })
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
        .map_err(|e| FederationError::RemoteError {
            status: 502,
            body: format!("deliverMessageEntry failed: {e}"),
        })?;
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
        .map_err(|e| FederationError::RemoteError {
            status: 502,
            body: format!("getDirectRequestOutcome relay failed: {e}"),
        })
}

// ---------------------------------------------------------------------------
// Local Staging and Ingestion
// ---------------------------------------------------------------------------

/// Stage remote recipient device packages into the coordinator's local tables.
///
/// Cryptographically verifies Ed25519 thumbprint, signed grant, and MLS KeyPackage
/// before atomically inserting into coordinator repository tables.
pub async fn stage_remote_recipient_devices(
    pool: &DbPool,
    tx: &mut Transaction<'_, Postgres>,
    request_id: Uuid,
    devices: &[RemoteDeviceBootstrap],
    now: DateTime<Utc>,
) -> Result<(), FederationError> {
    let recipient_did = devices.first()
        .ok_or_else(|| FederationError::InvalidRequest("recipient home selected no devices".into()))?
        .owner_did.as_str();
    let resolver = DsResolver::with_default_endpoint(
        pool.clone(),
        super::resolver::build_resolver_http_client(),
        crate::identity::service_did(),
        crate::identity::self_endpoint(),
        None,
        0,
    );
    let authorized_keys = resolver.resolve_authorized_device_keys(recipient_did).await?;
    if authorized_keys.is_empty() {
        return Err(FederationError::Forbidden("recipient PDS authorizes no MLS device keys".into()));
    }
    for b in devices {
        if b.owner_did != recipient_did {
            return Err(FederationError::InvalidRequest("recipient bootstrap mixes account DIDs".into()));
        }
        let pub_key_bytes = STANDARD.decode(&b.signature_public_key)
            .map_err(|e| FederationError::InvalidRequest(format!("invalid signature_public_key base64: {e}")))?;
        if !authorized_keys.iter().any(|key| key == &pub_key_bytes) {
            return Err(FederationError::Forbidden("recipient key is not authorized by the PDS".into()));
        }
        let wrapper = STANDARD.decode(&b.wrapper_bytes)
            .map_err(|e| FederationError::InvalidRequest(format!("invalid wrapper_bytes base64: {e}")))?;
        let expected_key_ref = STANDARD.decode(&b.key_package_ref)
            .map_err(|e| FederationError::InvalidRequest(format!("invalid key_package_ref base64: {e}")))?;

        // 1. Verify device key ID thumbprint
        let calculated_key_id = crate::chat_protocol::validation::ed25519_key_id(&pub_key_bytes)
            .map_err(|e| FederationError::InvalidRequest(format!("invalid ed25519 public key: {e:?}")))?;
        if calculated_key_id.as_str() != b.owner_key_id {
            return Err(FederationError::InvalidRequest("keyId does not match public key thumbprint".into()));
        }

        let dev_id_str = b.owner_device_id.to_string();

        // 2. Verify signed Keys publication
        let signed_keys_bytes = serde_json::to_vec(&b.signed_keys_publication)
            .map_err(FederationError::Json)?;
        let verified_keys = crate::chat_protocol::direct_request_transcript::verify_signed_request(
            crate::chat_protocol::direct_request_transcript::DirectRequestKind::Keys,
            &signed_keys_bytes,
            &pub_key_bytes,
        )
        .map_err(|e| FederationError::InvalidRequest(format!("keys publication signature verification failed: {e:?}")))?;

        if verified_keys.actor_did() != Some(b.owner_did.as_str())
            || verified_keys.actor_device_id() != Some(dev_id_str.as_str())
            || verified_keys.key_id() != b.owner_key_id.as_str()
            || verified_keys.auth_generation() != Some(b.auth_generation as u64)
        {
            return Err(FederationError::InvalidRequest("keys publication actor identity mismatch".into()));
        }

        let pub_digest_bytes = STANDARD.decode(&b.publication_digest)
            .map_err(|e| FederationError::InvalidRequest(format!("invalid publication_digest base64: {e}")))?;
        if pub_digest_bytes.len() != 32 || pub_digest_bytes.as_slice() != verified_keys.request_digest() {
            return Err(FederationError::InvalidRequest("publication digest mismatch".into()));
        }
        let keys_body = verified_keys.body();
        if keys_body.get("revision").and_then(|v| v.as_i64()) != Some(b.capability_revision) {
            return Err(FederationError::InvalidRequest("keys publication revision mismatch".into()));
        }
        if keys_body.get("enabled").and_then(|v| v.as_bool()) != Some(true) {
            return Err(FederationError::InvalidRequest("keys publication not enabled".into()));
        }


        // 3. Verify signed grant
        let signed_grant_bytes = serde_json::to_vec(&b.signed_grant)
            .map_err(FederationError::Json)?;
        let verified_grant = crate::chat_protocol::direct_request_transcript::verify_signed_request(
            crate::chat_protocol::direct_request_transcript::DirectRequestKind::Grant,
            &signed_grant_bytes,
            &pub_key_bytes,
        )
        .map_err(|e| FederationError::InvalidRequest(format!("grant signature verification failed: {e:?}")))?;

        if verified_grant.actor_did() != Some(b.owner_did.as_str())
            || verified_grant.actor_device_id() != Some(dev_id_str.as_str())
            || verified_grant.key_id() != b.owner_key_id.as_str()
            || verified_grant.auth_generation() != Some(b.auth_generation as u64)
        {
            return Err(FederationError::InvalidRequest("grant actor identity mismatch".into()));
        }

        let grant_digest_bytes = STANDARD.decode(&b.grant_digest)
            .map_err(|e| FederationError::InvalidRequest(format!("invalid grant_digest base64: {e}")))?;
        if grant_digest_bytes.len() != 32 || grant_digest_bytes.as_slice() != verified_grant.request_digest() {
            return Err(FederationError::InvalidRequest("grant digest mismatch".into()));
        }

        let grant_body = verified_grant.body();
        let grant_pkg_ref_str = grant_body.get("keyPackageRef")
            .and_then(|v| v.as_str())
            .ok_or_else(|| FederationError::InvalidRequest("grant missing keyPackageRef".into()))?;
        let grant_pkg_ref = STANDARD.decode(grant_pkg_ref_str)
            .map_err(|e| FederationError::InvalidRequest(format!("invalid grant keyPackageRef base64: {e}")))?;
        if grant_pkg_ref != expected_key_ref {
            return Err(FederationError::InvalidRequest("grant keyPackageRef does not bind to KeyPackage".into()));
        }

        let grant_sha256_str = grant_body.get("keyPackageSha256")
            .and_then(|v| v.as_str())
            .ok_or_else(|| FederationError::InvalidRequest("grant missing keyPackageSha256".into()))?;
        let grant_sha256 = STANDARD.decode(grant_sha256_str)
            .map_err(|e| FederationError::InvalidRequest(format!("invalid grant keyPackageSha256 base64: {e}")))?;
        if grant_sha256 != Sha256::digest(&wrapper).as_slice() {
            return Err(FederationError::InvalidRequest("grant keyPackageSha256 mismatch".into()));
        }
        // Verify that the grant and key package are present in the signed keys publication
        let keys_array = keys_body.get("keys").and_then(|v| v.as_array()).ok_or_else(|| {
            FederationError::InvalidRequest("keys publication missing keys array".into())
        })?;

        let grant_id_str = b.grant_id.to_string();
        let _matching_key_entry = keys_array.iter().find(|k| {
            let pkg_ref_match = k.pointer("/keyPackage/keyPackageRef").and_then(|v| v.as_str()) == Some(b.key_package_ref.as_str());
            let grant_id_match = k.pointer("/grant/body/grantId").and_then(|v| v.as_str()) == Some(&grant_id_str);
            pkg_ref_match && grant_id_match
        }).ok_or_else(|| {
            FederationError::InvalidRequest(format!(
                "grant {} with keyPackageRef {} not found in signed keys publication",
                b.grant_id, b.key_package_ref
            ))
        })?;

        let grant_rev = grant_body.get("revision").and_then(|v| v.as_i64()).unwrap_or(1);
        let grant_purpose = grant_body.get("purpose").and_then(|v| v.as_str()).unwrap_or("direct-request-bootstrap");
        let grant_proto = grant_body.get("protocolVersion").and_then(|v| v.as_str()).unwrap_or("2");
        let grant_profile = grant_body.get("profile").and_then(|v| v.as_str()).unwrap_or("encryptedIntroduction1");

        // 4. Verify MLS KeyPackage wrapper
        let bare_did = crate::chat_protocol::validation::BareDid::parse(&b.owner_did)
            .map_err(|_| FederationError::InvalidRequest("invalid owner DID".into()))?;
        let canon_device_id = crate::chat_protocol::validation::CanonicalUuidV4::parse(&dev_id_str)
            .map_err(|_| FederationError::InvalidRequest("invalid device UUID".into()))?;
        let credential = crate::chat_protocol::validation::basic_credential_identity(&bare_did, &canon_device_id);

        let valid_pkg = crate::chat_protocol::wire::validate_key_package(
            &wrapper,
            crate::chat_protocol::wire::KeyPackageValidationPolicy {
                expected_basic_credential: &credential,
                expected_signature_key: &pub_key_bytes,
                now_unix_seconds: now.timestamp() as u64,
                max_bytes: 65536,
            },
        )
        .map_err(|e| FederationError::InvalidRequest(format!("KeyPackage validation failed: {e:?}")))?;

        if grant_body.get("grantId").and_then(|v| v.as_str()) != Some(&b.grant_id.to_string()) {
            return Err(FederationError::InvalidRequest("grantId mismatch".into()));
        }
        let signed_expiry = grant_body.get("expiresAt").and_then(|v| v.as_str())
            .and_then(|value| DateTime::parse_from_rfc3339(value).ok());
        let selected_expiry = DateTime::parse_from_rfc3339(&b.expires_at).ok();
        if signed_expiry.is_none() || selected_expiry.is_none()
            || selected_expiry > signed_expiry
            || selected_expiry.is_some_and(|expiry| expiry <= now)
        {
            return Err(FederationError::InvalidRequest("selected import horizon exceeds signed grant or is expired".into()));
        }

        let existing_device: Option<(String, i64)> = sqlx::query_as(
            "SELECT status, auth_generation FROM chat.devices WHERE user_did = $1 AND device_id = $2"
        )
        .bind(&b.owner_did)
        .bind(b.owner_device_id)
        .fetch_optional(&mut **tx)
        .await
        .map_err(|e| FederationError::Storage(e.to_string()))?;

        if let Some((status, gen)) = existing_device {
            if status != "active" {
                return Err(FederationError::Forbidden("recipient device is not active".into()));
            }
            if b.auth_generation < gen {
                return Err(FederationError::InvalidRequest("device auth_generation rollback".into()));
            }
        }

        let existing_key: Option<Vec<u8>> = sqlx::query_scalar(
            "SELECT signing_public_key FROM chat.device_keys WHERE user_did = $1 AND device_id = $2 AND key_id = $3"
        )
        .bind(&b.owner_did)
        .bind(b.owner_device_id)
        .bind(&b.owner_key_id)
        .fetch_optional(&mut **tx)
        .await
        .map_err(|e| FederationError::Storage(e.to_string()))?;

        if let Some(existing_pk) = existing_key {
            if existing_pk != pub_key_bytes {
                return Err(FederationError::InvalidRequest("device signing public key mismatch with existing key".into()));
            }
        }

        if valid_pkg.key_package_ref() != expected_key_ref.as_slice() {
            return Err(FederationError::InvalidRequest("KeyPackage ref mismatch".into()));
        }

        // 5. Fail-closed temporal bounds
        let expires_at = DateTime::parse_from_rfc3339(&b.expires_at)
            .map_err(|e| FederationError::InvalidRequest(format!("invalid expires_at format: {e}")))?
            .with_timezone(&Utc);
        if expires_at <= now {
            return Err(FederationError::InvalidRequest("grant is expired".into()));
        }

        let not_before = DateTime::from_timestamp(valid_pkg.not_before() as i64, 0)
            .ok_or_else(|| FederationError::InvalidRequest("invalid not_before timestamp".into()))?;
        let not_after = DateTime::from_timestamp(valid_pkg.not_after() as i64, 0)
            .ok_or_else(|| FederationError::InvalidRequest("invalid not_after timestamp".into()))?;
        if not_after <= now {
            return Err(FederationError::InvalidRequest("KeyPackage is expired".into()));
        }

        // 6. Stage into coordinator DB
        sqlx::query(
            "INSERT INTO chat.principals (user_did, created_at) \
             VALUES ($1, $2) \
             ON CONFLICT (user_did) DO NOTHING"
        )
        .bind(&b.owner_did)
        .bind(now)
        .execute(&mut **tx)
        .await
        .map_err(|e| FederationError::Storage(e.to_string()))?;

        sqlx::query(
            "INSERT INTO chat.devices (user_did, device_id, device_name, status, dpop_jkt, auth_generation, capabilities, created_at, updated_at) \
             VALUES ($1, $2, 'federated-device', 'active', NULL, $3, chat.protocol_capabilities(), $4, $4) \
             ON CONFLICT (user_did, device_id) DO UPDATE SET \
                auth_generation = GREATEST(chat.devices.auth_generation, EXCLUDED.auth_generation), \
                updated_at = EXCLUDED.updated_at \
             WHERE chat.devices.status = 'active'"
        )
        .bind(&b.owner_did)
        .bind(b.owner_device_id)
        .bind(b.auth_generation)
        .bind(now)
        .execute(&mut **tx)
        .await
        .map_err(|e| FederationError::Storage(e.to_string()))?;

        sqlx::query(
            "INSERT INTO chat.device_keys (user_did, device_id, key_id, signing_public_key, enrollment_auth_generation, created_at) \
             VALUES ($1, $2, $3, $4, $5, $6) \
             ON CONFLICT (user_did, device_id, key_id) DO NOTHING"
        )
        .bind(&b.owner_did)
        .bind(b.owner_device_id)
        .bind(&b.owner_key_id)
        .bind(&pub_key_bytes)
        .bind(b.auth_generation)
        .bind(now)
        .execute(&mut **tx)
        .await
        .map_err(|e| FederationError::Storage(e.to_string()))?;

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
        return Err(FederationError::Forbidden("Local node is not recipient home DS".into()));
    }
    if canonical_did(&coord.coordinator_did) != canonical_did(requester_ds) {
        return Err(FederationError::AuthFailed {
            reason: format!("Requester {requester_ds} is not resolved coordinator {}", coord.coordinator_did),
        });
    }

    // C33-LEASE-003: Require and independently verify actor signed prepare
    let signed_prep = input.signed_prepare.as_ref().ok_or_else(|| {
        FederationError::InvalidRequest("signedPrepare is required for remote bootstrap reservation".into())
    })?;
    let sender_device_id_opt: Option<Uuid> = signed_prep
        .pointer("/body/actorDeviceId")
        .or_else(|| signed_prep.get("actorDeviceId"))
        .and_then(|v| v.as_str())
        .and_then(|s| Uuid::parse_str(s).ok());
    let actor_did = signed_prep.pointer("/body/actorDid")
        .and_then(|v| v.as_str())
        .ok_or_else(|| FederationError::InvalidRequest("missing actorDid in signedPrepare".into()))?;
    let rec_did = signed_prep.pointer("/body/recipientDid")
        .or_else(|| signed_prep.get("recipientDid"))
        .and_then(|v| v.as_str())
        .ok_or_else(|| FederationError::InvalidRequest("missing recipientDid in signedPrepare".into()))?;
    let req_id_str = signed_prep.pointer("/body/requestId")
        .or_else(|| signed_prep.get("requestId"))
        .and_then(|v| v.as_str())
        .ok_or_else(|| FederationError::InvalidRequest("missing requestId in signedPrepare".into()))?;

    if canonical_did(actor_did) != canonical_did(&input.sender_did)
        || canonical_did(rec_did) != canonical_did(&input.recipient_did)
        || req_id_str != input.request_id.to_string()
    {
        return Err(FederationError::InvalidRequest("signedPrepare does not match reservation input".into()));
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
    let authorized_keys = resolver.resolve_authorized_device_keys(&input.sender_did).await?;
    let prep_key_id = signed_prep.pointer("/body/keyId").and_then(|v| v.as_str()).unwrap_or_default();
    let matching_key = authorized_keys.iter().find(|k| {
        URL_SAFE_NO_PAD.encode(Sha256::digest(k)) == prep_key_id
            || STANDARD.encode(k) == prep_key_id
            || crate::chat_protocol::validation::ed25519_key_id(k).map(|id| id.as_str() == prep_key_id).unwrap_or(false)
    }).or_else(|| {
        if authorized_keys.len() == 1 {
            authorized_keys.first()
        } else {
            None
        }
    }).ok_or_else(|| {
        FederationError::Forbidden(format!("sender key {prep_key_id} is not authorized by PDS"))
    })?;

    let signed_prep_bytes = serde_json::to_vec(signed_prep).map_err(FederationError::Json)?;
    crate::chat_protocol::direct_request_transcript::verify_signed_request(
        crate::chat_protocol::direct_request_transcript::DirectRequestKind::Prepare,
        &signed_prep_bytes,
        matching_key,
    )
    .map_err(|e| FederationError::InvalidRequest(format!("signedPrepare signature verification failed: {e:?}")))?;

    if let Some(expected_digest) = &input.request_digest {
        let actual_hex = hex::encode(Sha256::digest(&signed_prep_bytes));
        let actual_b64 = STANDARD.encode(Sha256::digest(&signed_prep_bytes));
        if expected_digest != &actual_hex && expected_digest != &actual_b64 {
            return Err(FederationError::InvalidRequest("requestDigest mismatch".into()));
        }
    }

    let sender_signing_key_bytes = matching_key.clone();
    let prepare_digest_bytes = Sha256::digest(&signed_prep_bytes).to_vec();
    let mut tx = pool.begin().await.map_err(|e| FederationError::Storage(e.to_string()))?;
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
    .await? {
        if let PairFenceConflict::ForeignCoordinator { coordinator_did, .. } = conflict {
            return Err(FederationError::RemoteError {
                status: 409,
                body: format!(
                    "{{\"error\":\"PreparationConflict\",\"message\":\"Direct request or pair already owned by coordinator {coordinator_did}\"}}"
                ),
            });
        }
    }


    // ponytail: global advisory xact lock for remote lease capacity and idempotency; per-peer locks if throughput matters
    sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended('chat.direct_request_remote_leases', 0))")
        .execute(&mut *tx)
        .await
        .map_err(|e| FederationError::Storage(e.to_string()))?;
    // C33-LEASE-003: Immutable exact request identity and digest check on replay
    let existing_lease_meta: Option<(String, String, Option<Uuid>, Option<Vec<u8>>)> = sqlx::query_as(
        "SELECT coordinator_did, sender_did, sender_device_id, prepare_digest \
         FROM chat.direct_request_remote_leases \
         WHERE request_id = $1 AND recipient_did = $2 LIMIT 1"
    )
    .bind(input.request_id)
    .bind(&input.recipient_did)
    .fetch_optional(&mut *tx)
    .await
    .map_err(|e| FederationError::Storage(e.to_string()))?;

    if let Some((stored_coord, stored_sender, stored_sender_dev, stored_digest)) = existing_lease_meta {
        if canonical_did(&stored_coord) != canonical_did(&coord.coordinator_did)
            || canonical_did(&stored_sender) != canonical_did(&input.sender_did)
            || (sender_device_id_opt.is_some() && stored_sender_dev.is_some() && sender_device_id_opt != stored_sender_dev)
            || (stored_digest.is_some() && stored_digest.as_deref() != Some(&prepare_digest_bytes))
        {
            return Err(FederationError::InvalidRequest(format!(
                "request_id {} replayed with conflicting sender/coordinator identity or prepare digest",
                input.request_id
            )));
        }
    }

    // Idempotency: return existing active lease if already reserved for this request_id
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
            AND l.status = 'active' AND l.expires_at > clock_timestamp()"
    )
    .bind(input.request_id)
    .bind(&input.recipient_did)
    .fetch_all(&mut *tx)
    .await
    .map_err(|e| FederationError::Storage(e.to_string()))?;

    if !existing_rows.is_empty() {
        let mut bootstraps = Vec::with_capacity(existing_rows.len());
        for row in existing_rows {
            let grant_digest: Vec<u8> = row.try_get("grant_digest").map_err(|e| FederationError::Storage(e.to_string()))?;
            let key_pkg_ref: Vec<u8> = row.try_get("key_package_ref").map_err(|e| FederationError::Storage(e.to_string()))?;
            let wrapper: Vec<u8> = row.try_get("wrapper_bytes").map_err(|e| FederationError::Storage(e.to_string()))?;
            let sig_pub: Vec<u8> = row.try_get("signing_public_key").map_err(|e| FederationError::Storage(e.to_string()))?;
            let exp: DateTime<Utc> = row.try_get("expires_at").map_err(|e| FederationError::Storage(e.to_string()))?;
            let signed_keys_bytes: Vec<u8> = row.try_get("signed_publication").map_err(|e| FederationError::Storage(e.to_string()))?;
            let signed_keys_pub: Value = serde_json::from_slice(&signed_keys_bytes).map_err(|e| FederationError::Storage(e.to_string()))?;
            let pub_digest: Vec<u8> = row.try_get("publication_digest").map_err(|e| FederationError::Storage(e.to_string()))?;

            bootstraps.push(RemoteDeviceBootstrap {
                owner_did: row.try_get("owner_did").map_err(|e| FederationError::Storage(e.to_string()))?,
                owner_device_id: row.try_get("owner_device_id").map_err(|e| FederationError::Storage(e.to_string()))?,
                owner_key_id: row.try_get("owner_key_id").map_err(|e| FederationError::Storage(e.to_string()))?,
                auth_generation: row.try_get("owner_auth_generation").map_err(|e| FederationError::Storage(e.to_string()))?,
                grant_id: row.try_get("grant_id").map_err(|e| FederationError::Storage(e.to_string()))?,
                grant_digest: STANDARD.encode(&grant_digest),
                capability_revision: row.try_get("capability_revision").map_err(|e| FederationError::Storage(e.to_string()))?,
                key_package_ref: STANDARD.encode(&key_pkg_ref),
                wrapper_bytes: STANDARD.encode(&wrapper),
                signed_grant: serde_json::from_slice::<Value>(&row.try_get::<Vec<u8>, _>("signed_grant").map_err(|e| FederationError::Storage(e.to_string()))?).map_err(|e| FederationError::Storage(e.to_string()))?,
                expires_at: exp.to_rfc3339(),
                signature_public_key: STANDARD.encode(&sig_pub),
                signed_keys_publication: signed_keys_pub,
                publication_digest: STANDARD.encode(&pub_digest),
            });
        }
        tx.commit().await.map_err(|e| FederationError::Storage(e.to_string()))?;
        return Ok(bootstraps);
    }

    let now = Utc::now();
    let horizon = now + chrono::Duration::seconds(605_100);

    // Expiry marks a lease unresolved; the package remains reserved until the
    // coordinator proves cancellation or its committed publication is delivered.
    sqlx::query(
        "UPDATE chat.direct_request_remote_leases \
         SET status = 'expired' \
         WHERE recipient_did = $1 AND status = 'active' AND expires_at <= clock_timestamp()"
    )
    .bind(&input.recipient_did)
    .execute(&mut *tx)
    .await
    .map_err(|error| FederationError::Storage(error.to_string()))?;
    // C33-LEASE-003: Reconcile expired leases only via authenticated coordinator outcome.
    // If coordinator proves request is unknown or terminal, release the package; otherwise keep reserved.
    let expired_candidates: Vec<(Uuid, String, Option<Uuid>)> = sqlx::query_as(
        "SELECT request_id, coordinator_did, sender_device_id \
         FROM chat.direct_request_remote_leases \
         WHERE recipient_did = $1 AND status = 'expired' AND sender_device_id IS NOT NULL \
         LIMIT 5"
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
                ).await {
                    let outcome_val = outcome.get("outcome").unwrap_or(&outcome);
                    let outcome_type = outcome_val.pointer("/receipt/$type")
                        .or_else(|| outcome_val.pointer("/$type"))
                        .and_then(|v| v.as_str())
                        .unwrap_or_default();
                    let is_terminal = outcome_type == "blue.catbird.chat.defs#directRequestUnknownOutcome"
                        || outcome_type == "blue.catbird.chat.defs#directRequestRejectedReceipt"
                        || outcome_type == "blue.catbird.chat.defs#directRequestExpiredReceipt"
                        || outcome_type == "blue.catbird.chat.defs#directRequestCancelledReceipt";
                    if is_terminal {
                        let _ = sqlx::query(
                            "UPDATE chat.direct_request_remote_leases \
                             SET status = 'released', released_at = clock_timestamp() \
                             WHERE request_id = $1 AND recipient_did = $2 AND status = 'expired'"
                        )
                        .bind(exp_req_id)
                        .bind(&input.recipient_did)
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
        let owner_device_id: Uuid = r.try_get("owner_device_id").map_err(|e| FederationError::Storage(e.to_string()))?;
        if !seen_devices.insert(owner_device_id) {
            continue;
        }

        let key_package_ref: Vec<u8> = r.try_get("key_package_ref").map_err(|e| FederationError::Storage(e.to_string()))?;
        let owner_did: String = r.try_get("owner_did").map_err(|e| FederationError::Storage(e.to_string()))?;
        let owner_key_id: String = r.try_get("owner_key_id").map_err(|e| FederationError::Storage(e.to_string()))?;
        let auth_generation: i64 = r.try_get("owner_auth_generation").map_err(|e| FederationError::Storage(e.to_string()))?;
        let grant_id: Uuid = r.try_get("grant_id").map_err(|e| FederationError::Storage(e.to_string()))?;
        let grant_digest: Vec<u8> = r.try_get("grant_digest").map_err(|e| FederationError::Storage(e.to_string()))?;
        let capability_revision: i64 = r.try_get("capability_revision").map_err(|e| FederationError::Storage(e.to_string()))?;
        let wrapper_bytes: Vec<u8> = r.try_get("wrapper_bytes").map_err(|e| FederationError::Storage(e.to_string()))?;
        let signed_grant_bytes: Vec<u8> = r.try_get("signed_grant").map_err(|e| FederationError::Storage(e.to_string()))?;
        let signed_grant: Value = serde_json::from_slice(&signed_grant_bytes).map_err(|e| FederationError::Storage(e.to_string()))?;
        let expires_at: DateTime<Utc> = r.try_get("expires_at").map_err(|e| FederationError::Storage(e.to_string()))?;
        let signing_public_key: Vec<u8> = r.try_get("signing_public_key").map_err(|e| FederationError::Storage(e.to_string()))?;
        let signed_keys_bytes: Vec<u8> = r.try_get("signed_publication").map_err(|e| FederationError::Storage(e.to_string()))?;
        let signed_keys_pub: Value = serde_json::from_slice(&signed_keys_bytes).map_err(|e| FederationError::Storage(e.to_string()))?;
        let pub_digest: Vec<u8> = r.try_get("publication_digest").map_err(|e| FederationError::Storage(e.to_string()))?;

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

    tx.commit().await.map_err(|e| FederationError::Storage(e.to_string()))?;
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
         WHERE request_id = $1 AND recipient_did = $2 AND status IN ('active', 'expired') LIMIT 1"
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
         SET status = 'released', released_at = clock_timestamp() \
         WHERE request_id = $1 AND recipient_did = $2 AND coordinator_did = $3 AND status IN ('active', 'expired')"
    )
    .bind(request_id)
    .bind(recipient_did)
    .bind(requester_ds)
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
    input: DeliverDirectRequestInput,
) -> Result<(), FederationError> {
    let actor_did = input.entry.pointer("/signedRequest/body/actorDid")
        .or_else(|| input.entry.pointer("/body/actorDid"))
        .and_then(|v| v.as_str())
        .ok_or_else(|| FederationError::InvalidRequest("missing actorDid in delivery entry".into()))?;
    let recipient_did = input.entry.pointer("/signedRequest/body/recipientDid")
        .or_else(|| input.entry.pointer("/body/recipientDid"))
        .and_then(|v| v.as_str())
        .ok_or_else(|| FederationError::InvalidRequest("missing recipientDid in delivery entry".into()))?;
    let sender_device_id_str = input.entry.pointer("/signedRequest/body/actorDeviceId")
        .or_else(|| input.entry.pointer("/body/actorDeviceId"))
        .and_then(|v| v.as_str())
        .ok_or_else(|| FederationError::InvalidRequest("missing actorDeviceId in delivery entry".into()))?;
    let sender_device_id = Uuid::parse_str(sender_device_id_str)
        .map_err(|e| FederationError::InvalidRequest(format!("invalid actorDeviceId UUID: {e}")))?;
    let key_id = input.entry.pointer("/signedRequest/body/keyId")
        .or_else(|| input.entry.pointer("/body/keyId"))
        .and_then(|v| v.as_str())
        .ok_or_else(|| FederationError::InvalidRequest("missing keyId in delivery entry".into()))?;

    let entry_req_id_str = input.entry.pointer("/signedRequest/body/requestId")
        .or_else(|| input.entry.pointer("/body/requestId"))
        .and_then(|v| v.as_str())
        .ok_or_else(|| FederationError::InvalidRequest("missing requestId in delivery entry".into()))?;
    let entry_req_id = Uuid::parse_str(entry_req_id_str)
        .map_err(|e| FederationError::InvalidRequest(format!("invalid requestId UUID: {e}")))?;
    if entry_req_id != input.request_id {
        return Err(FederationError::InvalidRequest("requestId mismatch between input and entry".into()));
    }

    let entry_convo_str = input.entry.pointer("/signedRequest/body/conversationId")
        .or_else(|| input.entry.pointer("/body/conversationId"))
        .and_then(|v| v.as_str())
        .ok_or_else(|| FederationError::InvalidRequest("missing conversationId in delivery entry".into()))?;
    let entry_convo_id = Uuid::parse_str(entry_convo_str)
        .map_err(|e| FederationError::InvalidRequest(format!("invalid conversationId UUID: {e}")))?;
    if entry_convo_id != input.conversation_id {
        return Err(FederationError::InvalidRequest("conversationId mismatch between input and entry".into()));
    }

    let entry_msg_str = input.entry.pointer("/signedRequest/body/firstMessageId")
        .or_else(|| input.entry.pointer("/body/firstMessageId"))
        .and_then(|v| v.as_str())
        .ok_or_else(|| FederationError::InvalidRequest("missing firstMessageId in delivery entry".into()))?;
    let entry_first_msg_id = Uuid::parse_str(entry_msg_str)
        .map_err(|e| FederationError::InvalidRequest(format!("invalid firstMessageId UUID: {e}")))?;
    if entry_first_msg_id != input.first_message_id {
        return Err(FederationError::InvalidRequest("firstMessageId mismatch between input and entry".into()));
    }

    let coord = resolve_pair_coordinator(pool, actor_did, recipient_did).await?;

    if !coord.is_recipient_home {
        return Err(FederationError::Forbidden("Local node is not recipient home DS".into()));
    }
    if canonical_did(&coord.coordinator_did) != canonical_did(requester_ds)
        || canonical_did(&input.coordinator_did) != canonical_did(requester_ds)
    {
        return Err(FederationError::AuthFailed {
            reason: format!("Requester {requester_ds} is not resolved coordinator {}", coord.coordinator_did),
        });
    }

    let now = Utc::now();
    let mut tx = pool.begin().await.map_err(|e| FederationError::Storage(e.to_string()))?;

    // 1. Determine full_welcome bytes and sha256 (fail closed)
    let full_welcome = if let Some(b64) = &input.full_welcome_bytes {
        STANDARD.decode(b64).map_err(|e| FederationError::InvalidRequest(format!("invalid full_welcome_bytes base64: {e}")))?
    } else if let Some(b64) = input.publication_receipt.pointer("/receipt/artifacts/welcome/opaqueWelcome").and_then(|v| v.as_str()) {
        STANDARD.decode(b64).map_err(|e| FederationError::InvalidRequest(format!("invalid opaqueWelcome base64: {e}")))?
    } else if let Some(b64) = input.entry.pointer("/signedRequest/artifacts/welcome/opaqueWelcome").and_then(|v| v.as_str()) {
        STANDARD.decode(b64).map_err(|e| FederationError::InvalidRequest(format!("invalid opaqueWelcome base64: {e}")))?
    } else {
        return Err(FederationError::InvalidRequest("missing full_welcome in delivery input".into()));
    };
    if full_welcome.is_empty() {
        return Err(FederationError::InvalidRequest("empty full_welcome in delivery input".into()));
    }
    let full_welcome_sha256 = Sha256::digest(&full_welcome).to_vec();

    let request_entry_bytes = serde_json::to_vec(&input.entry)
        .map_err(FederationError::Json)?;

    let signed_pub_val = input.signed_publication.as_ref()
        .or_else(|| input.entry.get("signedRequest"))
        .unwrap_or(&input.entry);
    let signed_pub_bytes = serde_json::to_vec(signed_pub_val)
        .map_err(FederationError::Json)?;

    let import_until_str = input.publication_receipt.pointer("/receipt/importUntil")
        .or_else(|| input.entry.pointer("/signedRequest/body/importUntil"))
        .and_then(|v| v.as_str())
        .ok_or_else(|| FederationError::InvalidRequest("missing importUntil in delivery input".into()))?;
    let import_until = DateTime::parse_from_rfc3339(import_until_str)
        .map_err(|e| FederationError::InvalidRequest(format!("invalid importUntil format: {e}")))?
        .with_timezone(&Utc);
    if import_until <= now {
        return Err(FederationError::InvalidRequest("importUntil is in the past".into()));
    }

    // 2. Independently verify trusted coordinator DID doc receipt signature
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
    let receipt_bytes = serde_json::to_vec(receipt_val)
        .map_err(FederationError::Json)?;

    let receipt_authority_did = receipt_val.pointer("/body/authorityDid")
        .or_else(|| receipt_val.pointer("/receipt/authorityDid"))
        .or_else(|| receipt_val.get("authorityDid"))
        .and_then(|v| v.as_str())
        .ok_or_else(|| FederationError::InvalidRequest("missing authorityDid in publication receipt".into()))?;
    if canonical_did(receipt_authority_did) != canonical_did(&coord.coordinator_did) {
        return Err(FederationError::AuthFailed {
            reason: format!("receipt authorityDid {receipt_authority_did} does not match coordinator {}", coord.coordinator_did),
        });
    }

    let receipt_key_id = receipt_val.pointer("/body/keyId")
        .or_else(|| receipt_val.pointer("/receipt/keyId"))
        .or_else(|| receipt_val.get("keyId"))
        .and_then(|v| v.as_str())
        .ok_or_else(|| FederationError::InvalidRequest("missing keyId in publication receipt".into()))?;

    let receipt_public_key = resolver.resolve_coordinator_receipt_key(pool, receipt_authority_did, receipt_key_id).await?;

    let verified_receipt = crate::chat_protocol::direct_request_transcript::verify_received_signed_request(
        crate::chat_protocol::direct_request_transcript::DirectRequestKind::Outcome,
        &receipt_bytes,
        &receipt_public_key,
    )
    .map_err(|e| FederationError::InvalidRequest(format!("coordinator receipt signature verification failed: {e:?}")))?;

    // 3. Verify actor signature: live PDS or commit-time proof
    let authorized_keys = resolver.resolve_authorized_device_keys(actor_did).await.unwrap_or_default();
    let matching_key = authorized_keys.iter().find(|k| {
        URL_SAFE_NO_PAD.encode(Sha256::digest(k)) == key_id
            || STANDARD.encode(k) == key_id
            || crate::chat_protocol::validation::ed25519_key_id(k).map(|id| id.as_str() == key_id).unwrap_or(false)
    }).cloned();

    let matching_key = match matching_key {
        Some(k) => k,
        None => {
            // Finding C33-AUTH-002: If actor rotated their device key after commit,
            // query the PDS-verified sender signing key retained in the remote lease
            let lease_key_row: Option<(Vec<u8>, Option<Uuid>, Option<Vec<u8>>)> = sqlx::query_as(
                "SELECT sender_signing_key, sender_device_id, prepare_digest \
                 FROM chat.direct_request_remote_leases \
                 WHERE request_id = $1 AND recipient_did = $2 AND status IN ('active', 'expired') \
                   AND sender_signing_key IS NOT NULL LIMIT 1"
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
            if key_id != calculated_thumbprint && key_id != calculated_key_id && key_id != STANDARD.encode(&retained_key) {
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
    .map_err(|e| FederationError::InvalidRequest(format!("actor signature verification failed: {e:?}")))?;
    let publication_body = verified_pub.body();
    let signed_welcome = publication_body.pointer("/artifacts/welcome/opaqueWelcome")
        .and_then(|value| value.as_str())
        .and_then(|encoded| STANDARD.decode(encoded).ok())
        .ok_or_else(|| FederationError::InvalidRequest("signed publication lacks a valid Welcome".into()))?;
    if input.entry.get("signedRequest") != Some(signed_pub_val)
        || full_welcome != signed_welcome
        || publication_body.pointer("/artifacts/welcome/deliveries")
            .and_then(|value| value.as_array())
            .map(Vec::as_slice) != Some(input.deliveries.as_slice())
    {
        return Err(FederationError::InvalidRequest("transport artifacts differ from sender-signed publication".into()));
    }
    // 4. Verify exact cross-bindings
    let receipt_req_digest_b64 = verified_receipt.body().pointer("/receipt/requestDigest")
        .or_else(|| verified_receipt.body().get("requestDigest"))
        .and_then(|v| v.as_str())
        .ok_or_else(|| FederationError::InvalidRequest("missing requestDigest in receipt body".into()))?;
    let receipt_req_digest = STANDARD.decode(receipt_req_digest_b64)
        .map_err(|e| FederationError::InvalidRequest(format!("invalid requestDigest base64: {e}")))?;
    if receipt_req_digest.as_slice() != verified_pub.request_digest() {
        return Err(FederationError::InvalidRequest("receipt requestDigest does not match publication digest".into()));
    }

    let receipt_req_id = verified_receipt.body().pointer("/receipt/requestId")
        .or_else(|| verified_receipt.body().get("requestId"))
        .and_then(|v| v.as_str())
        .ok_or_else(|| FederationError::InvalidRequest("missing requestId in receipt body".into()))?;
    if receipt_req_id != input.request_id.to_string() {
        return Err(FederationError::InvalidRequest("receipt requestId mismatch".into()));
    }

    if verified_receipt.body().pointer("/receipt/coordinates") != publication_body.get("next")
        || verified_receipt.body().pointer("/receipt/conversationId")
            .and_then(|value| value.as_str()) != Some(input.conversation_id.to_string().as_str())
        || verified_receipt.body().pointer("/receipt/firstMessageId")
            .and_then(|value| value.as_str()) != Some(input.first_message_id.to_string().as_str())
        || verified_receipt.body().pointer("/receipt/actorDid")
            .and_then(|value| value.as_str()) != Some(actor_did)
        || verified_receipt.body().pointer("/receipt/requestKind")
            .and_then(|value| value.as_str()) != Some("publish")
    {
        return Err(FederationError::InvalidRequest("signed receipt does not bind published conversation".into()));
    }

    if let Some(entry_hash_b64) = verified_receipt.body().pointer("/receipt/entryHash").and_then(|v| v.as_str()) {
        let expected_hash = STANDARD.decode(entry_hash_b64)
            .map_err(|_| FederationError::InvalidRequest("invalid receipt entry hash".into()))?;
        let mut untagged_entry = input.entry.clone();
        untagged_entry.as_object_mut()
            .ok_or_else(|| FederationError::InvalidRequest("invalid canonical entry".into()))?
            .remove("$type");
        let untagged_bytes = serde_json::to_vec(&untagged_entry).map_err(FederationError::Json)?;
        let actual_hash = crate::chat_protocol::direct_request_transcript::direct_request_entry_hash(&untagged_bytes)
            .map_err(|_| FederationError::InvalidRequest("invalid canonical entry hash".into()))?;
        if expected_hash != actual_hash {
            return Err(FederationError::InvalidRequest("receipt entryHash does not match canonical entry".into()));
        }
    }

    // 5. Validate deliveries and provenance
    if input.deliveries.is_empty() {
        return Err(FederationError::InvalidRequest("deliveries array cannot be empty".into()));
    }

    for d in &input.deliveries {
        let rec_did = d["recipientDid"].as_str().ok_or_else(|| {
            FederationError::InvalidRequest("missing recipientDid in delivery item".into())
        })?;
        if rec_did != recipient_did && rec_did != actor_did {
            return Err(FederationError::InvalidRequest("delivery is not for a signed pair member".into()));
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
        if provenance.get("requestId").and_then(|v| v.as_str()) != Some(&input.request_id.to_string()) {
            return Err(FederationError::InvalidRequest("provenance requestId mismatch".into()));
        }
    }

    // 6. Check existing inbox for idempotent replay
    let existing_inbox: Vec<(Vec<u8>, Vec<u8>)> = sqlx::query_as(
        "SELECT full_welcome_sha256, request_entry \
         FROM chat.direct_request_transport_inbox \
         WHERE request_id = $1"
    )
    .bind(input.request_id)
    .fetch_all(&mut *tx)
    .await
    .map_err(|e| FederationError::Storage(e.to_string()))?;

    if !existing_inbox.is_empty() {
        for (stored_hash, stored_entry) in &existing_inbox {
            if stored_hash != &full_welcome_sha256 || stored_entry != &request_entry_bytes {
                return Err(FederationError::CommitConflict {
                    convo_id: input.conversation_id.to_string(),
                    current_epoch: 0,
                });
            }
        }
        tx.commit().await.map_err(|e| FederationError::Storage(e.to_string()))?;
        return Ok(());
    }

    // 7. Finalize active or expired remote lease
    let leased_packages: Vec<(Uuid, Vec<u8>, Uuid)> = sqlx::query_as(
        "UPDATE chat.direct_request_remote_leases \
         SET status = 'finalized', finalized_at = $1 \
         WHERE request_id = $2 AND recipient_did = $3 AND coordinator_did = $4 \
           AND status IN ('active', 'expired') \
         RETURNING lease_id, key_package_ref, owner_device_id"
    )
    .bind(now)
    .bind(input.request_id)
    .bind(recipient_did)
    .bind(&coord.coordinator_did)
    .fetch_all(&mut *tx)
    .await
    .map_err(|e| FederationError::Storage(e.to_string()))?;

    if leased_packages.is_empty() {
        return Err(FederationError::InvalidRequest("no lease found for request".into()));
    }

    if leased_packages.len() != input.deliveries.iter()
        .filter(|delivery| delivery["recipientDid"].as_str() == Some(recipient_did))
        .count()
    {
        return Err(FederationError::InvalidRequest(
            "leased recipient packages differ from signed local deliveries".into()
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

        let matching_lease = leased_packages.iter().find(|(_, pkg_ref, dev_id)| {
            *dev_id == rec_device_id && *pkg_ref == prov_key_pkg
        });

        if matching_lease.is_none() {
            return Err(FederationError::InvalidRequest(format!(
                "delivery device {rec_device_id} does not match any leased package for this request"
            )));
        }
    }

    // 8. Insert into chat.direct_request_transport_inbox
    let publication_receipt_bytes = serde_json::to_vec(&input.publication_receipt)
        .map_err(FederationError::Json)?;

    for d in &input.deliveries {
        if d["recipientDid"].as_str() != Some(recipient_did) {
            continue;
        }
        let rec_did = d["recipientDid"].as_str().unwrap();
        let rec_device_id = Uuid::parse_str(d["recipientDeviceId"].as_str().unwrap()).unwrap();
        let prov_bytes = serde_json::to_vec(&d["provenance"]).map_err(FederationError::Json)?;

        sqlx::query(
            "INSERT INTO chat.direct_request_transport_inbox ( \
                request_id, conversation_id, first_message_id, coordinator_did, \
                sender_did, sender_device_id, recipient_did, recipient_device_id, \
                request_entry, signed_publication, full_welcome, full_welcome_sha256, \
                provenance, publication_receipt, import_until, status, created_at, updated_at \
            ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, 'pending', $16, $16) \
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
        .execute(&mut *tx)
        .await
        .map_err(|e| FederationError::Storage(e.to_string()))?;
    }

    // 9. Mark key packages consumed on recipient home DS referencing the finalized remote lease
    for (lease_id, pkg_ref, _device_id) in &leased_packages {
        let res = sqlx::query(
            "UPDATE chat.key_packages \
             SET status = 'consumed', terminal_remote_lease_id = $1, terminal_at = $2 \
             WHERE key_package_ref = $3 AND status = 'available'"
        )
        .bind(lease_id)
        .bind(now)
        .bind(pkg_ref)
        .execute(&mut *tx)
        .await
        .map_err(|e| FederationError::Storage(e.to_string()))?;

        if res.rows_affected() != 1 {
            return Err(FederationError::InvalidRequest("key package was not available for consumption".into()));
        }
    }

    // 10. Insert initial introduction entry into chat.direct_request_transport_entries
    let seq = input.entry.get("seq").and_then(|v| v.as_i64()).unwrap_or(1);
    if seq != 1 {
        return Err(FederationError::InvalidRequest("initial entry seq must be 1".into()));
    }
    let entry_id_str = input.entry.get("entryId").and_then(|v| v.as_str());
    let entry_id = entry_id_str.and_then(|s| Uuid::parse_str(s).ok()).unwrap_or(input.request_id);

    let res = sqlx::query(
        "INSERT INTO chat.direct_request_transport_entries ( \
            conversation_id, seq, entry_id, entry_bytes, created_at \
         ) VALUES ($1, $2, $3, $4, clock_timestamp()) \
         ON CONFLICT (conversation_id, seq) DO NOTHING"
    )
    .bind(input.conversation_id)
    .bind(seq)
    .bind(entry_id)
    .bind(&request_entry_bytes)
    .execute(&mut *tx)
    .await
    .map_err(|e| FederationError::Storage(e.to_string()))?;

    if res.rows_affected() == 0 {
        let existing: Option<Vec<u8>> = sqlx::query_scalar(
            "SELECT entry_bytes FROM chat.direct_request_transport_entries WHERE conversation_id = $1 AND seq = $2"
        )
        .bind(input.conversation_id)
        .bind(seq)
        .fetch_optional(&mut *tx)
        .await
        .map_err(|e| FederationError::Storage(e.to_string()))?;

        if let Some(bytes) = existing {
            if bytes != request_entry_bytes {
                return Err(FederationError::CommitConflict {
                    convo_id: input.conversation_id.to_string(),
                    current_epoch: 0,
                });
            }
        }
    }

    tx.commit().await.map_err(|e| FederationError::Storage(e.to_string()))?;
    Ok(())
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
    let signed_acceptance = entry.get("signedRequest")
        .ok_or_else(|| FederationError::InvalidRequest("missing signed acceptance".into()))?;
    let actor_device_id = signed_acceptance.pointer("/body/actorDeviceId")
        .and_then(Value::as_str)
        .and_then(|value| Uuid::parse_str(value).ok())
        .ok_or_else(|| FederationError::InvalidRequest("invalid accepting device".into()))?;
    let convo_info: Option<(String, String, String, String)> = sqlx::query_as(
        "SELECT coordinator_did, sender_did, recipient_did, status \
         FROM chat.direct_request_transport_inbox \
         WHERE conversation_id=$1 AND recipient_device_id=$2 LIMIT 1"
    )
    .bind(conversation_id)
    .bind(actor_device_id)
    .fetch_optional(pool)
    .await
    .map_err(|e| FederationError::Storage(e.to_string()))?;

    let (coord_did, _sender_did, recipient_did, _status) = convo_info.ok_or_else(|| {
        FederationError::NotFound(format!("conversation {conversation_id} not found in transport inbox"))
    })?;

    if canonical_did(&coord_did) != canonical_did(requester_ds) {
        return Err(FederationError::AuthFailed {
            reason: format!("Requester {requester_ds} is not the retained coordinator {coord_did}"),
        });
    }

    let proof_receipt = acceptance_proof.pointer("/receipt/body")
        .ok_or_else(|| FederationError::InvalidRequest("missing signed acceptance proof".into()))?;
    if proof_receipt["authorityDid"].as_str() != Some(coord_did.as_str())
        || signed_acceptance.pointer("/body/actorDid").and_then(Value::as_str) != Some(recipient_did.as_str())
    {
        return Err(FederationError::InvalidRequest("acceptance actor or authority mismatch".into()));
    }
    let key_id = proof_receipt["keyId"].as_str()
        .ok_or_else(|| FederationError::InvalidRequest("missing acceptance receipt key".into()))?;
    let signer_key_id = signed_acceptance.pointer("/body/keyId").and_then(Value::as_str)
        .ok_or_else(|| FederationError::InvalidRequest("missing accepting device key".into()))?;
    let resolver = DsResolver::with_default_endpoint(
        pool.clone(),
        super::resolver::build_resolver_http_client(),
        crate::identity::service_did(),
        crate::identity::self_endpoint(),
        std::env::var("DEFAULT_DS_ENDPOINT").ok(),
        3600,
    );
    let authority_key = resolver.resolve_coordinator_receipt_key(pool, &coord_did, key_id).await?;
    let authorized_keys = resolver.resolve_authorized_device_keys(&recipient_did).await?;
    let actor_key = authorized_keys.iter()
        .find(|key| URL_SAFE_NO_PAD.encode(Sha256::digest(key)) == signer_key_id)
        .ok_or_else(|| FederationError::Forbidden("accepting device key is not PDS-authorized".into()))?;
    let proof_bytes = serde_json::to_vec(acceptance_proof).map_err(FederationError::Json)?;
    let verified_proof = crate::chat_protocol::direct_request_transcript::verify_received_direct_request_acceptance_proof(
        &proof_bytes, &authority_key, actor_key,
    ).map_err(|_| FederationError::InvalidProof)?;
    let mut untagged_entry = entry.clone();
    untagged_entry.as_object_mut()
        .ok_or_else(|| FederationError::InvalidRequest("invalid acceptance entry".into()))?
        .remove("$type");
    if verified_proof.get("entry") != Some(&untagged_entry) {
        return Err(FederationError::InvalidRequest("acceptance proof does not bind delivered entry".into()));
    }

    let entry_convo = entry.get("conversationId").and_then(|v| v.as_str());
    if entry_convo != Some(&conversation_id.to_string()) {
        return Err(FederationError::InvalidRequest("conversationId mismatch in acceptance entry".into()));
    }

    if let Some(t) = entry.get("$type").and_then(|v| v.as_str()) {
        if t != "blue.catbird.chat.defs#directRequestAcceptanceEntry" {
            return Err(FederationError::InvalidRequest(format!("invalid entry $type {t} for acceptance")));
        }
    }

    let seq = entry.get("seq").and_then(|v| v.as_i64()).ok_or_else(|| {
        FederationError::InvalidRequest("missing seq in acceptance entry".into())
    })?;
    if seq != 2 {
        return Err(FederationError::InvalidRequest(format!("acceptance entry seq must be 2, got {seq}")));
    }

    let intro_bytes: Vec<u8> = sqlx::query_scalar(
        "SELECT entry_bytes FROM chat.direct_request_transport_entries \
         WHERE conversation_id=$1 AND seq=1"
    )
    .bind(conversation_id)
    .fetch_one(pool)
    .await
    .map_err(|_| FederationError::InvalidProof)?;
    let intro: Value = serde_json::from_slice(&intro_bytes).map_err(FederationError::Json)?;
    if intro.pointer("/signedRequest/body/next")
        != signed_acceptance.pointer("/body/prior")
    {
        return Err(FederationError::InvalidRequest("acceptance prior differs from verified introduction".into()));
    }

    let mut tx = pool.begin().await.map_err(|e| FederationError::Storage(e.to_string()))?;

    let outcome_bytes = serde_json::to_vec(&json!({
        "entry": entry,
        "acceptanceProof": acceptance_proof,
    })).map_err(FederationError::Json)?;

    sqlx::query(
        "UPDATE chat.direct_request_transport_inbox \
         SET status = 'accepted', acceptance_proof = $2, acceptance_outcome = $3, updated_at = clock_timestamp() \
         WHERE conversation_id = $1"
    )
    .bind(conversation_id)
    .bind(&proof_bytes)
    .bind(&outcome_bytes)
    .execute(&mut *tx)
    .await
    .map_err(|e| FederationError::Storage(e.to_string()))?;

    let entry_id_str = entry.get("entryId").and_then(|v| v.as_str()).unwrap_or_default();
    let entry_id = Uuid::parse_str(entry_id_str).map_err(|e| {
        FederationError::InvalidRequest(format!("invalid entryId UUID: {e}"))
    })?;
    let entry_bytes = serde_json::to_vec(entry).map_err(FederationError::Json)?;

    let res = sqlx::query(
        "INSERT INTO chat.direct_request_transport_entries ( \
            conversation_id, seq, entry_id, entry_bytes, created_at \
         ) VALUES ($1, $2, $3, $4, clock_timestamp()) \
         ON CONFLICT (conversation_id, seq) DO NOTHING"
    )
    .bind(conversation_id)
    .bind(seq)
    .bind(entry_id)
    .bind(&entry_bytes)
    .execute(&mut *tx)
    .await
    .map_err(|e| FederationError::Storage(e.to_string()))?;

    if res.rows_affected() == 0 {
        let existing: Option<Vec<u8>> = sqlx::query_scalar(
            "SELECT entry_bytes FROM chat.direct_request_transport_entries WHERE conversation_id = $1 AND seq = $2"
        )
        .bind(conversation_id)
        .bind(seq)
        .fetch_optional(&mut *tx)
        .await
        .map_err(|e| FederationError::Storage(e.to_string()))?;

        if let Some(bytes) = existing {
            if bytes != entry_bytes {
                return Err(FederationError::CommitConflict {
                    convo_id: conversation_id.to_string(),
                    current_epoch: 0,
                });
            }
        }
    }

    tx.commit().await.map_err(|e| FederationError::Storage(e.to_string()))?;
    Ok(())
}

/// Ingest an inbound application message entry on a remote DS.
pub async fn ingest_remote_message_entry(
    pool: &DbPool,
    _sse: Option<&Arc<SseState>>,
    requester_ds: &str,
    conversation_id: Uuid,
    entry: &Value,
) -> Result<(), FederationError> {
    let signed_message = entry.get("signedRequest")
        .ok_or_else(|| FederationError::InvalidRequest("missing signed application message".into()))?;
    let actor_did = signed_message.pointer("/body/actorDid").and_then(Value::as_str)
        .ok_or_else(|| FederationError::InvalidRequest("missing message actor".into()))?;
    let actor_device_id = signed_message.pointer("/body/actorDeviceId").and_then(Value::as_str)
        .and_then(|value| Uuid::parse_str(value).ok())
        .ok_or_else(|| FederationError::InvalidRequest("invalid message actor device".into()))?;
    let signer_key_id = signed_message.pointer("/body/keyId").and_then(Value::as_str)
        .ok_or_else(|| FederationError::InvalidRequest("missing message key ID".into()))?;
    let coord_info: Option<(String, String)> = sqlx::query_as(
        "SELECT coordinator_did, status FROM chat.direct_request_transport_inbox \
         WHERE conversation_id=$1 AND \
           ((sender_did=$2 AND sender_device_id=$3) OR \
            (recipient_did=$2 AND recipient_device_id=$3)) LIMIT 1"
    )
    .bind(conversation_id)
    .bind(actor_did)
    .bind(actor_device_id)
    .fetch_optional(pool)
    .await
    .map_err(|e| FederationError::Storage(e.to_string()))?;
    let (coord_did, status) = coord_info
        .ok_or_else(|| FederationError::Forbidden("message actor is not an entitled pair device".into()))?;
    if status != "accepted" {
        return Err(FederationError::Forbidden("direct request has not been accepted".into()));
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
    let actor_key = authorized_keys.iter()
        .find(|key| URL_SAFE_NO_PAD.encode(Sha256::digest(key)) == signer_key_id)
        .ok_or_else(|| FederationError::Forbidden("message signing key is not PDS-authorized".into()))?;
    let signed_bytes = serde_json::to_vec(signed_message).map_err(FederationError::Json)?;
    let verified = crate::chat_protocol::transcript::decode_and_verify_signed_mutation(
        &signed_bytes, actor_key,
    ).map_err(|_| FederationError::InvalidProof)?;
    if !matches!(verified.projection(), crate::chat_protocol::transcript::VerifiedMutationProjection::ApplicationSend(_)) {
        return Err(FederationError::InvalidRequest("relayed entry is not an application send".into()));
    }

    let entry_convo = entry.get("conversationId").and_then(|v| v.as_str());
    if entry_convo != Some(&conversation_id.to_string()) {
        return Err(FederationError::InvalidRequest("conversationId mismatch in message entry".into()));
    }

    if entry.get("$type").and_then(Value::as_str) != Some("blue.catbird.chat.defs#applicationEntry") {
        return Err(FederationError::InvalidRequest("invalid application entry type".into()));
    }

    let seq = entry.get("seq").and_then(|v| v.as_i64()).ok_or_else(|| {
        FederationError::InvalidRequest("missing seq in message entry".into())
    })?;
    if seq < 3 {
        return Err(FederationError::InvalidRequest(format!("message entry seq must be >= 3, got {seq}")));
    }

    let predecessor_bytes: Vec<u8> = sqlx::query_scalar(
        "SELECT COALESCE( \
           (SELECT entry_bytes FROM chat.direct_request_transport_entries WHERE conversation_id=$1 AND seq=$2), \
           (SELECT accepted_payload_bytes FROM chat.entries WHERE conversation_id=$1 AND seq=$2))"
    )
    .bind(conversation_id)
    .bind(seq - 1)
    .fetch_one(pool)
    .await
    .map_err(|_| FederationError::InvalidRequest("missing signed predecessor entry".into()))?;
    let predecessor: Value = serde_json::from_slice(&predecessor_bytes).map_err(FederationError::Json)?;
    let prior = signed_message.pointer("/body/prior");
    let prior_entry = if seq == 3 {
        predecessor.pointer("/signedRequest/body/next")
    } else {
        predecessor.pointer("/signedRequest/body/prior")
    };
    if prior.is_none() || prior != prior_entry {
        return Err(FederationError::InvalidRequest("message coordinates differ from retained predecessor".into()));
    }

    let entry_id_str = entry.get("entryId").and_then(|v| v.as_str()).ok_or_else(|| {
        FederationError::InvalidRequest("missing entryId in message entry".into())
    })?;
    let entry_id = Uuid::parse_str(entry_id_str).map_err(|e| {
        FederationError::InvalidRequest(format!("invalid entryId UUID: {e}"))
    })?;

    let entry_bytes = serde_json::to_vec(entry)
        .map_err(FederationError::Json)?;

    let mut tx = pool.begin().await.map_err(|e| FederationError::Storage(e.to_string()))?;

    let res = sqlx::query(
        "INSERT INTO chat.direct_request_transport_entries ( \
            conversation_id, seq, entry_id, entry_bytes, created_at \
         ) VALUES ($1, $2, $3, $4, clock_timestamp()) \
         ON CONFLICT (conversation_id, seq) DO NOTHING"
    )
    .bind(conversation_id)
    .bind(seq)
    .bind(entry_id)
    .bind(&entry_bytes)
    .execute(&mut *tx)
    .await
    .map_err(|e| FederationError::Storage(e.to_string()))?;

    if res.rows_affected() == 0 {
        let existing: Option<Vec<u8>> = sqlx::query_scalar(
            "SELECT entry_bytes FROM chat.direct_request_transport_entries WHERE conversation_id = $1 AND seq = $2"
        )
        .bind(conversation_id)
        .bind(seq)
        .fetch_optional(&mut *tx)
        .await
        .map_err(|e| FederationError::Storage(e.to_string()))?;

        if let Some(bytes) = existing {
            if bytes != entry_bytes {
                return Err(FederationError::CommitConflict {
                    convo_id: conversation_id.to_string(),
                    current_epoch: 0,
                });
            }
        }
    }

    tx.commit().await.map_err(|e| FederationError::Storage(e.to_string()))?;
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
    let actor_did = signed_req["body"]["actorDid"].as_str().ok_or_else(|| {
        FederationError::InvalidRequest("missing actorDid".into())
    })?;
    let recipient_did = signed_req["body"]["recipientDid"].as_str().ok_or_else(|| {
        FederationError::InvalidRequest("missing recipientDid".into())
    })?;
    let request_id_str = signed_req["body"]["requestId"].as_str().ok_or_else(|| {
        FederationError::InvalidRequest("missing requestId".into())
    })?;
    let request_id = Uuid::parse_str(request_id_str).map_err(|_| {
        FederationError::InvalidRequest("invalid requestId".into())
    })?;

    let coord = resolve_pair_coordinator(pool, actor_did, recipient_did).await?;
    if !coord.is_coordinator {
        return Err(FederationError::Forbidden("Local node is not coordinator".into()));
    }
    if canonical_did(&coord.sender_home.did) != canonical_did(requester_ds) {
        return Err(FederationError::AuthFailed {
            reason: format!("Requester {requester_ds} is not sender home DS {}", coord.sender_home.did),
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

    let mut tx = pool.begin().await.map_err(|e| FederationError::Storage(e.to_string()))?;

    // Acquire transaction advisory lock for the unordered participant pair
    sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1, 0))")
        .bind(&pair_lock_key)
        .execute(&mut *tx)
        .await
        .map_err(|e| FederationError::Storage(e.to_string()))?;

    // An existing attempt replays before the pair fence, as on a local
    // prepare: the replay can only return its stored outcome, its live
    // preparation or its own expiry, so another request holding the pair
    // does not change its answer (C12).
    let existing_attempt: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM chat.direct_request_attempts WHERE request_id=$1)"
    )
    .bind(request_id)
    .fetch_one(&mut *tx)
    .await
    .map_err(|e| FederationError::Storage(e.to_string()))?;
    if existing_attempt {
        let signer = runtime.request_receipt_signer().ok_or_else(|| {
            FederationError::ConfigError { reason: "request receipt signer not configured".into() }
        })?;
        let principal = crate::auth::VerifiedServicePrincipal::for_federated_s2s(
            actor_did, "blue.catbird.chat.prepareDirectRequest",
        );
        let signed_bytes = serde_json::to_vec(signed_req).map_err(FederationError::Json)?;
        let result = crate::chat_protocol::repository::direct_request_preparation::prepare_direct_request(
            &mut tx, &principal, &signed_bytes, signer,
            runtime.relationship_authority().as_ref(), &coord.sender_home.did, now,
        ).await.map_err(|error| FederationError::RemoteError {
            status: 409, body: format!("prepare replay rejected: {error:?}"),
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
        if rejected && !coord.is_recipient_home {
            release_remote_recipient_bootstrap(
                pool,
                &coord.recipient_home.endpoint,
                &coord.recipient_home.did,
                request_id,
                recipient_did,
            ).await?;
        }
        tx.commit().await.map_err(|e| FederationError::Storage(e.to_string()))?;
        return Ok(json!({"outcome": outcome}));
    }

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
        return Err(FederationError::RemoteError {
            status: 409,
            body: format!("{{\"error\":\"PreparationConflict\",\"message\":\"{msg}\"}}"),
        });
    }

    if !coord.is_sender_home {
        let sender_key = match input.get("senderDeviceKey") {
            Some(k) => k,
            None => {
                return Err(FederationError::InvalidRequest("missing senderDeviceKey from sender home DS".into()));
            }
        };
        let device_id_str = match sender_key["deviceId"].as_str() {
            Some(s) => s,
            None => {
                return Err(FederationError::InvalidRequest("missing senderDeviceKey.deviceId".into()));
            }
        };
        let key_id = match sender_key["keyId"].as_str() {
            Some(k) => k,
            None => {
                return Err(FederationError::InvalidRequest("missing senderDeviceKey.keyId".into()));
            }
        };
        let auth_gen = match sender_key["authGeneration"].as_i64() {
            Some(g) => g,
            None => {
                return Err(FederationError::InvalidRequest("missing senderDeviceKey.authGeneration".into()));
            }
        };
        let pub_key_b64 = match sender_key["signingPublicKey"].as_str() {
            Some(p) => p,
            None => {
                return Err(FederationError::InvalidRequest("missing senderDeviceKey.signingPublicKey".into()));
            }
        };
        let device_id = match Uuid::parse_str(device_id_str) {
            Ok(d) => d,
            Err(_) => {
                return Err(FederationError::InvalidRequest("invalid senderDeviceKey.deviceId".into()));
            }
        };
        let pub_key = match STANDARD.decode(pub_key_b64) {
            Ok(k) => k,
            Err(_) => {
                return Err(FederationError::InvalidRequest("invalid senderDeviceKey.signingPublicKey base64".into()));
            }
        };

        // Bind signedRequest fields to senderDeviceKey
        if signed_req["body"]["actorDeviceId"].as_str() != Some(device_id_str)
            || signed_req["body"]["keyId"].as_str() != Some(key_id)
            || signed_req["body"]["authGeneration"].as_i64() != Some(auth_gen)
        {
            return Err(FederationError::InvalidRequest("signedRequest fields do not match senderDeviceKey".into()));
        }
        // Independently authorize senderDeviceKey against the actor's PDS
        let http = super::resolver::build_resolver_http_client();
        let resolver = DsResolver::with_default_endpoint(
            pool.clone(),
            http,
            crate::identity::service_did(),
            crate::identity::self_endpoint(),
            std::env::var("DEFAULT_DS_ENDPOINT").ok(),
            3600,
        );
        let authorized_keys = match resolver.resolve_authorized_device_keys(actor_did).await {
            Ok(keys) => keys,
            Err(e) => {
                return Err(e);
            }
        };
        if !authorized_keys.contains(&pub_key) {
            return Err(FederationError::Forbidden(format!(
                "sender key {key_id} is not authorized by actor {actor_did}'s PDS"
            )));
        }

        // Verify signed prepare request against sender's signing key
        let signed_bytes = serde_json::to_vec(signed_req).map_err(FederationError::Json)?;
        if let Err(e) = crate::chat_protocol::direct_request_transcript::verify_signed_request(
            crate::chat_protocol::direct_request_transcript::DirectRequestKind::Prepare,
            &signed_bytes,
            &pub_key,
        ) {
            return Err(FederationError::InvalidRequest(format!("prepare signature verification failed against senderDeviceKey: {e:?}")));
        }

        // Verify sender key ID matches thumbprint
        let calculated_key_id = match crate::chat_protocol::validation::ed25519_key_id(&pub_key) {
            Ok(k) => k,
            Err(e) => {
                return Err(FederationError::InvalidRequest(format!("invalid ed25519 public key: {e:?}")));
            }
        };
        if calculated_key_id.as_str() != key_id {
            return Err(FederationError::InvalidRequest("senderDeviceKey keyId does not match public key thumbprint".into()));
        }

        let existing_device: Option<(String, i64)> = sqlx::query_as(
            "SELECT status, auth_generation FROM chat.devices WHERE user_did = $1 AND device_id = $2"
        )
        .bind(actor_did)
        .bind(device_id)
        .fetch_optional(&mut *tx)
        .await
        .map_err(|e| FederationError::Storage(e.to_string()))?;

        if let Some((status, gen)) = existing_device {
            if status != "active" {
                return Err(FederationError::Forbidden("sender device is not active".into()));
            }
            if auth_gen < gen {
                return Err(FederationError::InvalidRequest("sender device auth_generation rollback".into()));
            }
        }

        let existing_key: Option<Vec<u8>> = sqlx::query_scalar(
            "SELECT signing_public_key FROM chat.device_keys WHERE user_did = $1 AND device_id = $2 AND key_id = $3"
        )
        .bind(actor_did)
        .bind(device_id)
        .bind(key_id)
        .fetch_optional(&mut *tx)
        .await
        .map_err(|e| FederationError::Storage(e.to_string()))?;

        if let Some(existing_pk) = existing_key {
            if existing_pk != pub_key {
                return Err(FederationError::InvalidRequest("sender signing key mismatch with existing coordinator key".into()));
            }
        }

        sqlx::query(
            "INSERT INTO chat.principals (user_did, created_at) VALUES ($1, $2) ON CONFLICT (user_did) DO NOTHING"
        )
        .bind(actor_did)
        .bind(now)
        .execute(&mut *tx)
        .await
        .map_err(|e| FederationError::Storage(e.to_string()))?;

        sqlx::query(
            "INSERT INTO chat.devices (user_did, device_id, device_name, status, dpop_jkt, auth_generation, capabilities, created_at, updated_at) \
             VALUES ($1, $2, 'federated-sender', 'active', NULL, $3, chat.protocol_capabilities(), $4, $4) \
             ON CONFLICT (user_did, device_id) DO UPDATE SET \
                auth_generation = GREATEST(chat.devices.auth_generation, EXCLUDED.auth_generation), \
                updated_at = EXCLUDED.updated_at \
             WHERE chat.devices.status = 'active'"
        )
        .bind(actor_did)
        .bind(device_id)
        .bind(auth_gen)
        .bind(now)
        .execute(&mut *tx)
        .await
        .map_err(|e| FederationError::Storage(e.to_string()))?;

        sqlx::query(
            "INSERT INTO chat.device_keys (user_did, device_id, key_id, signing_public_key, enrollment_auth_generation, created_at) \
             VALUES ($1, $2, $3, $4, $5, $6) \
             ON CONFLICT (user_did, device_id, key_id) DO NOTHING"
        )
        .bind(actor_did)
        .bind(device_id)
        .bind(key_id)
        .bind(&pub_key)
        .bind(auth_gen)
        .bind(now)
        .execute(&mut *tx)
        .await
        .map_err(|e| FederationError::Storage(e.to_string()))?;
    }

    let signer = runtime.request_receipt_signer().ok_or_else(|| {
        FederationError::ConfigError {
            reason: "request receipt signer not configured".into(),
        }
    })?;
    let principal = crate::auth::VerifiedServicePrincipal::for_federated_s2s(
        actor_did,
        "blue.catbird.chat.prepareDirectRequest",
    );

    let signed_bytes = serde_json::to_vec(signed_req)
        .map_err(FederationError::Json)?;
    if !coord.is_recipient_home {
        let remote_devices = reserve_remote_recipient_bootstrap(
            pool,
            &coord.recipient_home.endpoint,
            &coord.recipient_home.did,
            request_id,
            actor_did,
            recipient_did,
            Some(signed_req.clone()),
        )
        .await?;
        if let Err(e) = stage_remote_recipient_devices(pool, &mut tx, request_id, &remote_devices, now).await {
            release_remote_recipient_bootstrap(
                pool,
                &coord.recipient_home.endpoint,
                &coord.recipient_home.did,
                request_id,
                recipient_did,
            ).await?;
            return Err(e);
        }
    }

    let result = match crate::chat_protocol::repository::direct_request_preparation::prepare_direct_request(
        &mut tx,
        &principal,
        &signed_bytes,
        signer,
        runtime.relationship_authority().as_ref(),
        &coord.sender_home.did,
        now,
    )
    .await {
        Ok(r) => r,
        Err(e) => {
            if !coord.is_recipient_home {
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
                status: 400,
                body: format!("prepare_direct_request error: {e:?}"),
            });
        }
    };
    if !coord.is_recipient_home
        && !matches!(&result,
            crate::chat_protocol::repository::direct_request_preparation::DirectRequestResult::Prepared(_))
    {
        release_remote_recipient_bootstrap(
            pool,
            &coord.recipient_home.endpoint,
            &coord.recipient_home.did,
            request_id,
            recipient_did,
        ).await?;
    }

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

    tx.commit().await.map_err(|e| FederationError::Storage(e.to_string()))?;
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
    let actor_did = signed_req["body"]["actorDid"].as_str().ok_or_else(|| {
        FederationError::InvalidRequest("missing actorDid".into())
    })?;
    let recipient_did = signed_req["body"]["recipientDid"].as_str().ok_or_else(|| {
        FederationError::InvalidRequest("missing recipientDid".into())
    })?;

    let coord = resolve_pair_coordinator(pool, actor_did, recipient_did).await?;
    if !coord.is_coordinator {
        return Err(FederationError::Forbidden("Local node is not coordinator".into()));
    }
    if canonical_did(&coord.sender_home.did) != canonical_did(requester_ds) {
        return Err(FederationError::AuthFailed {
            reason: format!("Requester {requester_ds} is not sender home DS {}", coord.sender_home.did),
        });
    }


    let signer = runtime.request_receipt_signer().ok_or_else(|| {
        FederationError::ConfigError {
            reason: "request receipt signer not configured".into(),
        }
    })?;
    let principal = crate::auth::VerifiedServicePrincipal::for_federated_s2s(
        actor_did,
        "blue.catbird.chat.publishDirectRequest",
    );

    let signed_bytes = serde_json::to_vec(signed_req)
        .map_err(FederationError::Json)?;

    let now = TrustedRequestInstant::capture()
        .map_err(|_| FederationError::Invariant("trusted instant".into()))?
        .datetime();

    let mut tx = pool.begin().await.map_err(|e| FederationError::Storage(e.to_string()))?;

    let request_id = Uuid::parse_str(signed_req["body"]["requestId"].as_str().unwrap_or_default())
        .unwrap_or_default();
    let conversation_id = Uuid::parse_str(signed_req["body"]["conversationId"].as_str().unwrap_or_default())
        .unwrap_or_default();
    let first_message_id = Uuid::parse_str(signed_req["body"]["firstMessageId"].as_str().unwrap_or_default())
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

    // As on a local publish: a request that ended without a publication only
    // replays its stored receipt, so neither the pair fence nor the PDS
    // revalidation below applies to it (C12, C14).
    let ended_unpublished: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM chat.direct_request_attempts \
         WHERE request_id=$1 AND actor_did=$2 AND recipient_did=$3 \
           AND status IN ('cancelled','expired','rejected','existing-direct'))",
    )
    .bind(request_id)
    .bind(actor_did)
    .bind(recipient_did)
    .fetch_one(&mut *tx)
    .await
    .map_err(|e| FederationError::Storage(e.to_string()))?;

    if !ended_unpublished {
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

        // C33-AUTH-002: Revalidate actor and every selected recipient key against fresh PDS snapshot at commit boundary
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
    }

    let prepared = crate::chat_protocol::repository::direct_request_publication::prepare_publication(
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
        status: 400,
        body: format!("prepare_publication error: {e:?}"),
    })?;

    let receipt_bytes = match prepared {
        crate::chat_protocol::repository::direct_request_publication::PublicationPreparation::Terminal(bytes) => bytes,
        crate::chat_protocol::repository::direct_request_publication::PublicationPreparation::Ready(ready) => {
            crate::chat_protocol::repository::direct_request_publication::execute_publication(
                &mut tx,
                *ready,
                signer,
                runtime.relationship_authority().as_ref(),
            )
            .await
            .map_err(|e| FederationError::RemoteError {
                status: 400,
                body: format!("execute_publication error: {e:?}"),
            })?
        }
    };

    let mut receipt: Value = serde_json::from_slice(&receipt_bytes)
        .map_err(FederationError::Json)?;
    receipt["$type"] = json!("blue.catbird.chat.defs#signedDirectRequestReceipt");

    let entry_row: Option<Vec<u8>> = sqlx::query_scalar("SELECT accepted_payload_bytes FROM chat.entries WHERE transition_id = $1")
        .bind(request_id)
        .fetch_optional(&mut *tx)
        .await
        .map_err(|e| FederationError::Storage(e.to_string()))?;

    let entry_val: Option<Value> = entry_row
        .and_then(|b| serde_json::from_slice(&b).ok());

    let deliveries = signed_req.pointer("/body/artifacts/welcome/deliveries")
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

    let (full_welcome_b64, signed_pub_val) = if let Some((welcome, signed_pub)) = pub_row {
        (
            Some(STANDARD.encode(&welcome)),
            serde_json::from_slice(&signed_pub).ok(),
        )
    } else {
        (None, None)
    };

    let deliver_input = DeliverDirectRequestInput {
        request_id,
        conversation_id,
        first_message_id,
        entry: entry_val.clone().unwrap_or(json!({})),
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
        .await?;
    }

    tx.commit().await.map_err(|e| FederationError::Storage(e.to_string()))?;

    if !coord.is_recipient_home {
        if let Ok(()) = deliver_direct_request_to_peer(
            &coord.recipient_home.endpoint,
            &coord.recipient_home.did,
            deliver_input,
        )
        .await {
            let _ = crate::federation::queue::mark_delivered_by_id(pool, &queue_id).await;
        }
    }

    let mut response = json!({ "outcome": receipt });
    if let Some(entry) = entry_val {
        response["entry"] = entry;
    }
    Ok(response)
}

/// Coordinator execution for acceptDirectRequest relayed from recipient home DS.
pub async fn coordinator_accept_direct_request(
    pool: &DbPool,
    runtime: &Arc<ChatRuntime>,
    requester_ds: &str,
    conversation_id: Uuid,
    direct_request: &Value,
) -> Result<DeliverAcceptanceOutput, FederationError> {
    let actor_did = direct_request["body"]["actorDid"].as_str().ok_or_else(|| {
        FederationError::InvalidRequest("missing actorDid".into())
    })?;
    let request_id_str = direct_request["body"]["requestId"].as_str().ok_or_else(|| {
        FederationError::InvalidRequest("missing requestId in direct request body".into())
    })?;
    let request_id = Uuid::parse_str(request_id_str).map_err(|_| {
        FederationError::InvalidRequest("invalid requestId".into())
    })?;

    let stored_pair: Option<(String, String)> = sqlx::query_as(
        "SELECT actor_did, recipient_did FROM chat.direct_request_publications WHERE request_id = $1 \
         UNION ALL \
         SELECT actor_did, recipient_did FROM chat.direct_request_attempts WHERE request_id = $1 LIMIT 1"
    )
    .bind(request_id)
    .fetch_optional(pool)
    .await
    .map_err(|e| FederationError::Storage(e.to_string()))?;

    let (sender_did, expected_recipient_did) = stored_pair.ok_or_else(|| {
        FederationError::NotFound(format!("direct request {request_id} not found on coordinator"))
    })?;

    if actor_did != expected_recipient_did {
        return Err(FederationError::Forbidden(format!(
            "actor {actor_did} is not the recipient {expected_recipient_did} for request {request_id}"
        )));
    }

    let coord = resolve_pair_coordinator(pool, &sender_did, &expected_recipient_did).await?;
    if !coord.is_coordinator {
        return Err(FederationError::Forbidden("Local node is not coordinator".into()));
    }
    if canonical_did(&coord.recipient_home.did) != canonical_did(requester_ds) {
        return Err(FederationError::AuthFailed {
            reason: format!("Requester {requester_ds} is not recipient home DS {}", coord.recipient_home.did),
        });
    }

    let raw_bytes = serde_json::to_vec(direct_request)
        .map_err(FederationError::Json)?;

    let now = TrustedRequestInstant::capture()
        .map_err(|_| FederationError::Invariant("trusted instant".into()))?
        .datetime();

    let signer = runtime.request_receipt_signer().ok_or_else(|| {
        FederationError::ConfigError {
            reason: "request receipt signer not configured".into(),
        }
    })?;
    let principal = crate::auth::VerifiedServicePrincipal::for_federated_s2s(
        actor_did,
        "blue.catbird.chat.acceptConversation",
    );

    let mut tx = pool.begin().await.map_err(|e| FederationError::Storage(e.to_string()))?;
    let bytes = crate::chat_protocol::repository::acceptance::accept_direct_request(
        &mut tx,
        &principal,
        &raw_bytes,
        signer,
        runtime.relationship_authority().as_ref(),
        now,
    )
    .await
    .map_err(|e| FederationError::RemoteError {
        status: 400,
        body: format!("accept_direct_request error: {e:?}"),
    })?;

    let entry_row: Option<Vec<u8>> = sqlx::query_scalar("SELECT accepted_payload_bytes FROM chat.entries WHERE conversation_id = $1 AND seq = 2")
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
        .await?;
    }

    tx.commit().await.map_err(|e| FederationError::Storage(e.to_string()))?;

    if canonical_did(&coord.sender_home.did) != canonical_did(&self_did) {
        if let Ok(()) = deliver_acceptance_entry_to_peer(
            &coord.sender_home.endpoint,
            &coord.sender_home.did,
            deliver_payload,
        ).await {
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
    let actor_did = message.pointer("/body/actorDid").and_then(|v| v.as_str()).ok_or_else(|| {
        FederationError::InvalidRequest("missing actorDid in message body".into())
    })?;
    let actor_device_id_str = message.pointer("/body/actorDeviceId").and_then(|v| v.as_str()).ok_or_else(|| {
        FederationError::InvalidRequest("missing actorDeviceId in message body".into())
    })?;
    let actor_device_id = Uuid::parse_str(actor_device_id_str).map_err(|_| {
        FederationError::InvalidRequest("invalid actorDeviceId".into())
    })?;
    let key_id = message.pointer("/body/keyId").and_then(|v| v.as_str()).ok_or_else(|| {
        FederationError::InvalidRequest("missing keyId in message body".into())
    })?;
    let message_id_str = message.pointer("/body/messageId").and_then(|v| v.as_str()).ok_or_else(|| {
        FederationError::InvalidRequest("missing messageId in message body".into())
    })?;
    let message_id = Uuid::parse_str(message_id_str).map_err(|_| {
        FederationError::InvalidRequest("invalid messageId".into())
    })?;

    // 1. Verify actor membership in conversation
    let actor_participant: Option<(String, bool, String)> = sqlx::query_as(
        "SELECT role, current_membership, status FROM chat.participants \
         WHERE conversation_id = $1 AND user_did = $2"
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
        return Err(FederationError::Forbidden("actor is not an active member in this conversation".into()));
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

    let kind: String = convo_row.try_get("kind").map_err(|e| FederationError::Storage(e.to_string()))?;
    let peer_did: String = if kind == "direct" {
        let low: String = convo_row.try_get("direct_did_low").map_err(|e| FederationError::Storage(e.to_string()))?;
        let high: String = convo_row.try_get("direct_did_high").map_err(|e| FederationError::Storage(e.to_string()))?;
        if actor_did == low {
            high
        } else if actor_did == high {
            low
        } else {
            return Err(FederationError::Forbidden("actor does not belong to direct conversation".into()));
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

    // 3. Authenticate that requester_ds is the authoritative home DS of actor_did
    let coord = resolve_pair_coordinator(pool, actor_did, &peer_did).await?;
    if !coord.is_coordinator {
        return Err(FederationError::Forbidden("Local node is not coordinator".into()));
    }
    if canonical_did(&coord.sender_home.did) != canonical_did(requester_ds) {
        return Err(FederationError::AuthFailed {
            reason: format!("Requester {requester_ds} is not actor {actor_did} home DS {}", coord.sender_home.did),
        });
    }

    // 4. Verify active device key on coordinator & mutation signature
    let key_row: Option<(Vec<u8>, i64)> = sqlx::query_as(
        "SELECT k.signing_public_key, k.enrollment_auth_generation \
         FROM chat.device_keys k \
         JOIN chat.devices d ON d.user_did = k.user_did AND d.device_id = k.device_id \
         WHERE k.user_did = $1 AND k.device_id = $2 AND k.key_id = $3 \
           AND k.revoked_at IS NULL AND d.status = 'active' AND d.auth_generation = k.enrollment_auth_generation"
    )
    .bind(actor_did)
    .bind(actor_device_id)
    .bind(key_id)
    .fetch_optional(pool)
    .await
    .map_err(|e| FederationError::Storage(e.to_string()))?;

    let (signing_public_key, auth_generation) = key_row.ok_or_else(|| {
        FederationError::NotFound(format!("Active device key {key_id} not found on coordinator"))
    })?;

    let signed_bytes = serde_json::to_vec(message).map_err(FederationError::Json)?;

    let verified = crate::chat_protocol::transcript::decode_and_verify_signed_mutation(
        &signed_bytes,
        &signing_public_key,
    )
    .map_err(|e| FederationError::InvalidRequest(format!("mutation signature verification failed: {e:?}")))?;

    // 5. Validate application message and AAD from projection
    let projection = match verified.projection() {
        crate::chat_protocol::transcript::VerifiedMutationProjection::ApplicationSend(p) => p,
        _ => return Err(FederationError::InvalidRequest("mutation is not an application send".into())),
    };

    let app_msg = projection.application_message();
    let msg_bytes = match app_msg.get("bytes") {
        Some(crate::chat_protocol::transcript::CanonicalValueRef::Bytes(b)) => b,
        _ => return Err(FederationError::InvalidRequest("invalid application message bytes".into())),
    };
    let msg_hash = match app_msg.get("sha256") {
        Some(crate::chat_protocol::transcript::CanonicalValueRef::Bytes(b)) if b.len() == 32 => b,
        _ => return Err(FederationError::InvalidRequest("invalid application message sha256".into())),
    };
    if Sha256::digest(msg_bytes).as_slice() != msg_hash
        || !matches!(app_msg.get("framing"), Some(crate::chat_protocol::transcript::CanonicalValueRef::Text("mlsMessage")))
        || !matches!(app_msg.get("contentType"), Some(crate::chat_protocol::transcript::CanonicalValueRef::Text("privateMessageApplication")))
    {
        return Err(FederationError::InvalidRequest("application message framing or digest mismatch".into()));
    }

    let aad = projection.aad();
    let aad_convo = match aad.get("conversationId") {
        Some(crate::chat_protocol::transcript::CanonicalValueRef::Bytes(v)) if v.len() == 16 => {
            Uuid::from_slice(v).map_err(|_| FederationError::InvalidRequest("invalid aad convo".into()))?
        }
        _ => return Err(FederationError::InvalidRequest("invalid aad conversationId".into())),
    };
    let aad_msg = match aad.get("messageId") {
        Some(crate::chat_protocol::transcript::CanonicalValueRef::Bytes(v)) if v.len() == 16 => {
            Uuid::from_slice(v).map_err(|_| FederationError::InvalidRequest("invalid aad msg".into()))?
        }
        _ => return Err(FederationError::InvalidRequest("invalid aad messageId".into())),
    };
    if aad_convo != conversation_id || aad_msg != message_id {
        return Err(FederationError::InvalidRequest("aad conversationId or messageId mismatch".into()));
    }

    // 6. Idempotency check with replay redrive
    let mut tx = pool.begin().await.map_err(|e| FederationError::Storage(e.to_string()))?;


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
    let existing_send: Option<(String, Option<i64>, Vec<u8>, Vec<u8>)> = sqlx::query_as(
        "SELECT status, accepted_entry_seq, request_digest, outcome_bytes \
         FROM chat.message_sends \
         WHERE conversation_id = $1 AND message_id = $2"
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
            let mut resp_val: Value = serde_json::from_slice(&outcome_bytes).map_err(FederationError::Json)?;
            tx.commit().await.map_err(|e| FederationError::Storage(e.to_string()))?;

            // Redrive peer delivery if remote peer
            let response_entry = resp_val.get_mut("entry")
                .ok_or_else(|| FederationError::Invariant("retained message outcome lacks entry".into()))?;
            response_entry["$type"] = json!("blue.catbird.chat.defs#applicationEntry");
            let response_entry = response_entry.clone();
            let self_did = crate::identity::service_did();
            if !peer_did.is_empty() && peer_did != actor_did {
                let (target_endpoint, target_did) = (coord.recipient_home.endpoint.as_str(), coord.recipient_home.did.as_str());
                if canonical_did(target_did) != canonical_did(&self_did) {
                    let deliver_payload = DeliverMessageEntryInput {
                        conversation_id,
                        entry: response_entry,
                    };
                    deliver_message_entry_to_peer(target_endpoint, target_did, deliver_payload).await?;
                }
            }

            return Ok(resp_val);
        }
    }

    let lifecycle: String = head_row.try_get("lifecycle").map_err(|e| FederationError::Storage(e.to_string()))?;
    if lifecycle != "active" {
        return Err(FederationError::InvalidRequest("conversation is not active".into()));
    }

    let head_generation: i64 = head_row.try_get("current_generation").map_err(|e| FederationError::Storage(e.to_string()))?;
    let head_state_version: i64 = head_row.try_get("current_state_version").map_err(|e| FederationError::Storage(e.to_string()))?;
    let head_group_id: Vec<u8> = head_row.try_get("group_id").map_err(|e| FederationError::Storage(e.to_string()))?;
    let head_epoch: i64 = head_row.try_get("epoch").map_err(|e| FederationError::Storage(e.to_string()))?;
    let head_gch: Vec<u8> = head_row.try_get("group_context_hash").map_err(|e| FederationError::Storage(e.to_string()))?;
    let head_confirm_tag: Vec<u8> = head_row.try_get("confirmation_tag").map_err(|e| FederationError::Storage(e.to_string()))?;
    let next_seq: i64 = head_row.try_get("next_entry_seq").map_err(|e| FederationError::Storage(e.to_string()))?;

    let prior = projection.prior();
    let prior_gen = match prior.get("generation") {
        Some(crate::chat_protocol::transcript::CanonicalValueRef::Integer(v)) => i64::try_from(v).map_err(|_| FederationError::InvalidRequest("invalid prior gen".into()))?,
        _ => return Err(FederationError::InvalidRequest("missing prior generation".into())),
    };
    let prior_ver = match prior.get("stateVersion") {
        Some(crate::chat_protocol::transcript::CanonicalValueRef::Integer(v)) => i64::try_from(v).map_err(|_| FederationError::InvalidRequest("invalid prior ver".into()))?,
        _ => return Err(FederationError::InvalidRequest("missing prior stateVersion".into())),
    };
    let prior_epoch = match prior.get("epoch") {
        Some(crate::chat_protocol::transcript::CanonicalValueRef::Integer(v)) => i64::try_from(v).map_err(|_| FederationError::InvalidRequest("invalid prior epoch".into()))?,
        _ => return Err(FederationError::InvalidRequest("missing prior epoch".into())),
    };
    let prior_group_id = match prior.get("groupId") {
        Some(crate::chat_protocol::transcript::CanonicalValueRef::Bytes(v)) => v,
        _ => return Err(FederationError::InvalidRequest("missing prior groupId".into())),
    };
    let prior_gch = match prior.get("groupContextHash") {
        Some(crate::chat_protocol::transcript::CanonicalValueRef::Bytes(v)) => v,
        _ => return Err(FederationError::InvalidRequest("missing prior groupContextHash".into())),
    };
    let prior_tag = match prior.get("confirmationTag") {
        Some(crate::chat_protocol::transcript::CanonicalValueRef::Bytes(v)) => v,
        _ => return Err(FederationError::InvalidRequest("missing prior confirmationTag".into())),
    };

    if prior_gen != head_generation
        || prior_ver != head_state_version
        || prior_epoch != head_epoch
        || prior_group_id != head_group_id.as_slice()
        || prior_gch != head_gch.as_slice()
        || prior_tag != head_confirm_tag.as_slice()
    {
        return Err(FederationError::InvalidRequest("stale application coordinates".into()));
    }

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
        return Err(FederationError::Forbidden("actor device is not a leaf in conversation".into()));
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
        return Err(FederationError::Forbidden("recipient not ready or has not accepted conversation".into()));
    }

    let mut head_binding = Sha256::new();
    head_binding.update(conversation_id.as_bytes());
    head_binding.update(head_generation.to_be_bytes());
    head_binding.update(head_state_version.to_be_bytes());
    head_binding.update(next_seq.to_be_bytes());
    head_binding.update(&head_gch);
    crate::chat_protocol::repository::relationship::verify_federated_send_policy(
        &mut tx,
        actor_did,
        &peer_did,
        Sha256::digest(&signed_bytes).into(),
        head_binding.finalize().into(),
        runtime.relationship_authority().as_ref(),
    )
    .await
    .map_err(|error| match error {
        crate::chat_protocol::repository::relationship::RelationshipConsumptionError::PolicyDenied =>
            FederationError::Forbidden("blocked by relationship policy".into()),
        crate::chat_protocol::repository::relationship::RelationshipConsumptionError::InvalidWitness =>
            FederationError::InvalidProof,
    })?;

    // 11. Build verified entry and commit send
    let trusted_instant = crate::chat_protocol::validation::TrustedRequestInstant::capture()
        .map_err(|_| FederationError::Invariant("trusted instant".into()))?;
    let trusted_now = trusted_instant.datetime();
    let canonical_now_str = trusted_now.to_rfc3339_opts(chrono::SecondsFormat::Millis, true);

    let entry_id = Uuid::new_v4();
    let entry_id_str = entry_id.to_string();

    let canon_entry_id = crate::chat_protocol::validation::CanonicalUuidV4::parse(&entry_id_str)
        .map_err(|_| FederationError::Invariant("invalid entry_id".into()))?;
    let canon_convo_id = crate::chat_protocol::validation::CanonicalUuidV4::parse(&conversation_id.to_string())
        .map_err(|_| FederationError::Invariant("invalid convo_id".into()))?;

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
    let server_fields = serde_ipld_dagcbor::to_vec(&std::collections::BTreeMap::<String, String>::new())
        .map_err(|_| FederationError::Invariant("server fields".into()))?;

    let outcome_json = json!({
        "entry": {
            "entryId": entry_id_str,
            "conversationId": conversation_id.to_string(),
            "seq": next_seq,
            "signedRequest": message,
            "receivedAt": canonical_now_str
        }
    });
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
            return Err(FederationError::InvalidRequest("stale application coordinates".into()));
        }
    };

    let _ = crate::chat_protocol::repository::message_event::append_message_available_event(
        &mut tx,
        conversation_id,
        0,
        seq,
        trusted_now,
    )
    .await;

    let response_entry = json!({
        "$type": "blue.catbird.chat.defs#applicationEntry",
        "entryId": entry_id_str,
        "conversationId": conversation_id.to_string(),
        "seq": seq,
        "signedRequest": message,
        "receivedAt": canonical_now_str
    });

    let self_did = crate::identity::service_did();
    let deliver_payload = DeliverMessageEntryInput {
        conversation_id,
        entry: response_entry.clone(),
    };
    let queue_id = format!("msg-delivery-{conversation_id}-{seq}");

    if !peer_did.is_empty() && peer_did != actor_did {
        if canonical_did(&coord.recipient_home.did) != canonical_did(&self_did) {
            let payload_bytes = serde_json::to_vec(&deliver_payload).map_err(FederationError::Json)?;
            crate::federation::queue::enqueue_c33_in_tx(
                pool,
                &mut tx,
                &queue_id,
                &coord.recipient_home.did,
                &coord.recipient_home.endpoint,
                "blue.catbird.mlsDS.deliverMessageEntry",
                &payload_bytes,
                &conversation_id.to_string(),
                "",
            )
            .await?;
        }
    }

    tx.commit().await.map_err(|e| FederationError::Storage(e.to_string()))?;

    if !peer_did.is_empty() && peer_did != actor_did {
        if canonical_did(&coord.recipient_home.did) != canonical_did(&self_did) {
            if let Ok(()) = deliver_message_entry_to_peer(
                &coord.recipient_home.endpoint,
                &coord.recipient_home.did,
                deliver_payload,
            ).await {
                let _ = crate::federation::queue::mark_delivered_by_id(pool, &queue_id).await;
            }
        }
    }
    Ok(json!({ "entry": response_entry }))
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
        "SELECT actor_did, recipient_did FROM chat.direct_request_attempts WHERE request_id = $1"
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

                let now = Utc::now();
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
                    return Err(FederationError::NotFound("attempt in flight or not found".into()));
                }
            }
            return Err(FederationError::NotFound("attempt not found".into()));
        }
    };
    let coord = resolve_pair_coordinator(pool, &actor_did, &recipient_did).await;
    let authorized = match &coord {
        Ok(c) => canonical_did(&c.sender_home.did) == canonical_did(requester_ds)
            || canonical_did(&c.recipient_home.did) == canonical_did(requester_ds)
            || canonical_did(&c.coordinator_did) == canonical_did(requester_ds),
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
        let actor_home = resolver.resolve_authoritative_ds(&actor_did).await.ok();
        let rec_home = resolver.resolve_authoritative_ds(&recipient_did).await.ok();
        let home_matches = actor_home.as_ref().is_some_and(|h| canonical_did(&h.did) == canonical_did(requester_ds))
            || rec_home.as_ref().is_some_and(|h| canonical_did(&h.did) == canonical_did(requester_ds));
        if !home_matches {
            return Err(FederationError::AuthFailed {
                reason: format!("Requester {requester_ds} is not authorized for outcome of request {request_id}"),
            });
        }
    }

    let now = TrustedRequestInstant::capture()
        .map_err(|_| FederationError::Invariant("trusted instant".into()))?
        .datetime();
    let signer = runtime.request_receipt_signer().ok_or_else(|| {
        FederationError::ConfigError {
            reason: "request receipt signer not configured".into(),
        }
    })?;

    let principal = crate::auth::VerifiedServicePrincipal::for_federated_s2s(
        &actor_did,
        "blue.catbird.chat.getDirectRequestOutcome",
    );

    let mut tx = pool.begin().await.map_err(|e| FederationError::Storage(e.to_string()))?;
    let result = crate::chat_protocol::repository::direct_request_preparation::get_direct_request_outcome(
        &mut tx,
        &principal,
        actor_device_id,
        request_id,
        signer,
        now,
    )
    .await
    .map_err(|e| FederationError::RemoteError {
        status: 400,
        body: format!("get_direct_request_outcome error: {e:?}"),
    })?;

    let outcome_val = match result {
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
    tx.commit().await.map_err(|e| FederationError::Storage(e.to_string()))?;

    let entry_row: Option<Vec<u8>> = sqlx::query_scalar("SELECT accepted_payload_bytes FROM chat.entries WHERE transition_id = $1")
        .bind(request_id)
        .fetch_optional(pool)
        .await
        .ok()
        .flatten();

    let entry_val: Option<Value> = entry_row.and_then(|b| serde_json::from_slice(&b).ok());
    let mut resp = json!({ "outcome": outcome_val });
    if let Some(entry) = entry_val {
        resp["entry"] = entry;
    }
    Ok(resp)
}

#[cfg(test)]
mod pair_resolution_tests {
    use super::*;
    use crate::federation::errors::ResolutionFailureKind;

    const HOME: &str = "did:web:chat.catbird.blue";

    fn home(did: &str) -> DsEndpoint {
        DsEndpoint {
            did: did.to_string(),
            endpoint: format!("https://{}", did.trim_start_matches("did:web:")),
            supported_cipher_suites: None,
            federation_capabilities: None,
        }
    }

    fn recipient(declared: Option<&str>, error: FederationError) -> PairResolutionError {
        PairResolutionError::Recipient {
            sender_home: home(HOME),
            declared_authority: declared.map(str::to_string),
            error,
        }
    }

    fn unpeered(did: &str) -> FederationError {
        FederationError::AuthFailed {
            reason: format!("Peer DS '{did}' is not allowlisted"),
        }
    }

    #[test]
    fn refused_recipient_authorities_get_a_local_refusal() {
        for error in [
            recipient(None, FederationError::Unsupported("absent".into())),
            recipient(
                None,
                FederationError::ResolutionFailed {
                    did: "did:web:bob.test".into(),
                    kind: ResolutionFailureKind::InvalidDeclaration("non-public".into()),
                },
            ),
            recipient(
                Some("did:web:chat.federated-peer.org"),
                unpeered("did:web:chat.federated-peer.org"),
            ),
        ] {
            let coord = error
                .local_refusal_coordinator(HOME)
                .expect("local refusal");
            assert_eq!(coord.coordinator_did, HOME);
            assert!(coord.is_coordinator && coord.is_sender_home && coord.is_recipient_home);
        }
    }

    #[test]
    fn no_local_refusal_when_it_would_not_verify_or_is_not_final() {
        // Clients verify receipts against the lower authority DID.
        assert!(recipient(
            Some("did:web:aaa.example-peer.org"),
            unpeered("did:web:aaa.example-peer.org")
        )
        .local_refusal_coordinator(HOME)
        .is_none());
        // A transient failure is not a refusal.
        assert!(recipient(
            Some("did:web:chat.federated-peer.org"),
            FederationError::ResolutionFailed {
                did: "did:web:chat.federated-peer.org".into(),
                kind: ResolutionFailureKind::Timeout("slow".into()),
            },
        )
        .local_refusal_coordinator(HOME)
        .is_none());
        // Only the sender's own home may refuse alone.
        assert!(
            recipient(None, FederationError::Unsupported("absent".into()))
                .local_refusal_coordinator("did:web:other.catbird.blue")
                .is_none()
        );
        assert!(
            PairResolutionError::Sender(FederationError::Unsupported("absent".into()))
                .local_refusal_coordinator(HOME)
                .is_none()
        );
    }
}
