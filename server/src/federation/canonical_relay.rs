//! Canonical S2S Relay and Coordination for blue.catbird.chat direct requests.
//!
//! Provides deterministic coordinator resolution, staged remote reservation,
//! authenticated XRPC relaying, remote Welcome/entry delivery, and acceptance/reply routing
//! across independent chat authorities with zero legacy fallback.

use std::sync::Arc;
use base64::{engine::general_purpose::STANDARD, Engine};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sqlx::{PgPool, Postgres, Row, Transaction};
use tracing::{debug, error, info, warn};
use uuid::Uuid;

use crate::chat_protocol::validation::TrustedRequestInstant;
use crate::identity::canonical_did;
use crate::realtime::SseState;
use crate::storage::DbPool;
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

/// Resolve the deterministic pair coordinator for a sender and recipient pair.
pub async fn resolve_pair_coordinator(
    pool: &DbPool,
    sender_did: &str,
    recipient_did: &str,
) -> Result<CanonicalPairCoordinator, FederationError> {
    let self_did = crate::identity::service_did();
    let self_endpoint = crate::identity::self_endpoint();
    let default_ds = std::env::var("DEFAULT_DS_ENDPOINT").ok();
    let cache_ttl: u64 = std::env::var("ENDPOINT_CACHE_TTL")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(3600);

    let http = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(10))
        .build()
        .unwrap_or_else(|_| reqwest::Client::new());

    let resolver = DsResolver::new(
        pool.clone(),
        http,
        self_did,
        self_endpoint,
        default_ds,
        cache_ttl,
    );

    let sender_home = resolver.resolve(sender_did).await?;
    let recipient_home = resolver.resolve(recipient_did).await?;
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
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ReserveRecipientBootstrapInput {
    pub request_id: Uuid,
    pub sender_did: String,
    pub recipient_did: String,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ReserveRecipientBootstrapOutput {
    pub selected_devices: Vec<RemoteDeviceBootstrap>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DeliverDirectRequestInput {
    pub request_id: Uuid,
    pub conversation_id: Uuid,
    pub first_message_id: Uuid,
    pub entry: Value,
    pub deliveries: Vec<Value>,
    pub publication_receipt: Value,
    pub coordinator_did: String,
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

#[derive(Debug, Serialize, Deserialize)]
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

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DeliverMessageEntryInput {
    pub conversation_id: Uuid,
    pub entry: Value,
}

// ---------------------------------------------------------------------------
// Outbound S2S Operations
// ---------------------------------------------------------------------------

pub async fn reserve_remote_recipient_bootstrap(
    endpoint: &str,
    target_did: &str,
    request_id: Uuid,
    sender_did: &str,
    recipient_did: &str,
) -> Result<Vec<RemoteDeviceBootstrap>, FederationError> {
    let token = mint_s2s_auth_token(target_did, "blue.catbird.mlsDS.reserveRecipientBootstrap")?;
    let outbound = OutboundClient::new(5, 15);
    let input = ReserveRecipientBootstrapInput {
        request_id,
        sender_did: sender_did.to_string(),
        recipient_did: recipient_did.to_string(),
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

pub async fn relay_prepare_direct_request(
    endpoint: &str,
    target_did: &str,
    signed_request: &Value,
) -> Result<Value, FederationError> {
    let token = mint_s2s_auth_token(target_did, "blue.catbird.mlsDS.prepareDirectRequest")?;
    let outbound = OutboundClient::new(5, 15);
    let payload = json!({ "signedRequest": signed_request });
    outbound
        .call_procedure_json(
            endpoint,
            "blue.catbird.mlsDS.prepareDirectRequest",
            &token,
            &payload,
        )
        .await
        .map_err(|e| FederationError::RemoteError {
            status: 502,
            body: format!("relay prepareDirectRequest failed: {e}"),
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
        .map_err(|e| FederationError::RemoteError {
            status: 502,
            body: format!("relay publishDirectRequest failed: {e}"),
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
        .map_err(|e| FederationError::RemoteError {
            status: 502,
            body: format!("deliverAcceptance failed: {e}"),
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
        .map_err(|e| FederationError::RemoteError {
            status: 502,
            body: format!("relaySendMessage failed: {e}"),
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
        .call_query_json(
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
/// This fulfills foreign key relationships on the coordinator without network I/O
/// inside the PostgreSQL transaction, ensuring `chat.key_packages` and `chat.direct_request_grants`
/// are present for selection and integrity triggers.
pub async fn stage_remote_recipient_devices(
    tx: &mut Transaction<'_, Postgres>,
    devices: &[RemoteDeviceBootstrap],
    now: DateTime<Utc>,
) -> Result<(), sqlx::Error> {
    for d in devices {
        let pubkey_bytes = STANDARD.decode(&d.signature_public_key).unwrap_or_default();
        let wrapper_bytes = STANDARD.decode(&d.wrapper_bytes).unwrap_or_default();
        let key_package_ref = STANDARD.decode(&d.key_package_ref).unwrap_or_default();
        let grant_digest = STANDARD.decode(&d.grant_digest).unwrap_or_default();
        let signed_grant_bytes = serde_json::to_vec(&d.signed_grant).unwrap_or_default();
        let expires_at = DateTime::parse_from_rfc3339(&d.expires_at)
            .map(|dt| dt.with_timezone(&Utc))
            .unwrap_or(now + chrono::Duration::days(7));

        // 1. chat.principals
        sqlx::query("INSERT INTO chat.principals(user_did, created_at) VALUES($1, $2) ON CONFLICT (user_did) DO NOTHING")
            .bind(&d.owner_did)
            .bind(now)
            .execute(&mut **tx)
            .await?;

        // 2. chat.devices
        sqlx::query("INSERT INTO chat.devices(user_did, device_id, device_name, status, created_at, auth_generation) VALUES($1, $2, 'remote-device', 'active', $3, $4) ON CONFLICT (user_did, device_id) DO UPDATE SET status='active', auth_generation=EXCLUDED.auth_generation")
            .bind(&d.owner_did)
            .bind(d.owner_device_id)
            .bind(now)
            .bind(d.auth_generation)
            .execute(&mut **tx)
            .await?;

        // 3. chat.device_keys
        sqlx::query("INSERT INTO chat.device_keys(user_did, device_id, key_id, signing_public_key, created_at) VALUES($1, $2, $3, $4, $5) ON CONFLICT (key_id) DO NOTHING")
            .bind(&d.owner_did)
            .bind(d.owner_device_id)
            .bind(&d.owner_key_id)
            .bind(&pubkey_bytes)
            .bind(now)
            .execute(&mut **tx)
            .await?;

        // 4. chat.direct_request_capabilities
        let dummy_sig = vec![0u8; 64];
        let dummy_digest = vec![0u8; 32];
        sqlx::query("INSERT INTO chat.direct_request_capabilities(owner_did, owner_device_id, owner_key_id, auth_generation, revision, enabled, protocol_version, signed_publication, publication_digest, updated_at) VALUES($1, $2, $3, $4, $5, TRUE, '2', $6, $7, $8) ON CONFLICT (owner_did, owner_device_id) DO UPDATE SET enabled=TRUE, auth_generation=EXCLUDED.auth_generation, revision=EXCLUDED.revision")
            .bind(&d.owner_did)
            .bind(d.owner_device_id)
            .bind(&d.owner_key_id)
            .bind(d.auth_generation)
            .bind(d.capability_revision)
            .bind(&dummy_sig)
            .bind(&dummy_digest)
            .bind(now)
            .execute(&mut **tx)
            .await?;

        // 5. chat.key_packages
        sqlx::query("INSERT INTO chat.key_packages(key_package_ref, owner_did, owner_device_id, owner_key_id, owner_auth_generation, wrapper_bytes, status, usage_scope, not_before, not_after, created_at) VALUES($1, $2, $3, $4, $5, $6, 'available', 'direct-request', $7, $8, $9) ON CONFLICT (key_package_ref) DO UPDATE SET status='available'")
            .bind(&key_package_ref)
            .bind(&d.owner_did)
            .bind(d.owner_device_id)
            .bind(&d.owner_key_id)
            .bind(d.auth_generation)
            .bind(&wrapper_bytes)
            .bind(now - chrono::Duration::seconds(60))
            .bind(expires_at)
            .bind(now)
            .execute(&mut **tx)
            .await?;

        // 6. chat.direct_request_grants
        sqlx::query("INSERT INTO chat.direct_request_grants(grant_id, revision, owner_did, owner_device_id, owner_key_id, auth_generation, capability_revision, key_package_ref, usage_scope, purpose, protocol_version, profile, signed_grant, grant_digest, expires_at, created_at) VALUES($1, 1, $2, $3, $4, $5, $6, $7, 'direct-request', 'direct-request-bootstrap', '2', 'encryptedIntroduction1', $8, $9, $10, $11) ON CONFLICT (grant_id) DO NOTHING")
            .bind(d.grant_id)
            .bind(&d.owner_did)
            .bind(d.owner_device_id)
            .bind(&d.owner_key_id)
            .bind(d.auth_generation)
            .bind(d.capability_revision)
            .bind(&key_package_ref)
            .bind(&signed_grant_bytes)
            .bind(&grant_digest)
            .bind(expires_at)
            .bind(now)
            .execute(&mut **tx)
            .await?;
    }
    Ok(())
}

/// Reserve recipient bootstrap packages locally on the recipient's home DS.
pub async fn local_reserve_recipient_bootstrap(
    pool: &DbPool,
    recipient_did: &str,
) -> Result<Vec<RemoteDeviceBootstrap>, FederationError> {
    let now = Utc::now();
    let horizon = now + chrono::Duration::seconds(604_800 + 300);
    let mut tx = pool.begin().await.map_err(|e| FederationError::Storage(e.to_string()))?;

    let rows = sqlx::query(r#"
        SELECT DISTINCT ON (p.owner_did, p.owner_device_id)
               p.owner_did, p.owner_device_id, p.owner_key_id, p.owner_auth_generation,
               g.grant_id, g.grant_digest, g.capability_revision, p.key_package_ref, p.wrapper_bytes,
               g.signed_grant, LEAST(p.not_after, g.expires_at) AS expires_at,
               k.signing_public_key
          FROM chat.key_packages p
          JOIN chat.devices d ON d.user_did = p.owner_did AND d.device_id = p.owner_device_id
          JOIN chat.device_keys k ON k.user_did = p.owner_did AND k.device_id = p.owner_device_id AND k.key_id = p.owner_key_id
          JOIN chat.direct_request_capabilities c ON c.owner_did = p.owner_did AND c.owner_device_id = p.owner_device_id
          JOIN chat.direct_request_grants g ON g.key_package_ref = p.key_package_ref
         WHERE p.owner_did = $1
           AND d.status = 'active' AND k.revoked_at IS NULL AND p.owner_auth_generation = d.auth_generation
           AND c.enabled AND c.protocol_version = '2' AND c.auth_generation = d.auth_generation AND c.owner_key_id = k.key_id
           AND g.revoked_at IS NULL AND g.auth_generation = d.auth_generation
           AND g.protocol_version = '2' AND g.profile = 'encryptedIntroduction1' AND g.expires_at >= $2
           AND p.usage_scope = 'direct-request' AND p.status = 'available' AND p.not_before < $3 AND p.not_after >= $2
           AND NOT EXISTS (SELECT 1 FROM chat.direct_request_selected_devices s WHERE s.key_package_ref = p.key_package_ref)
         ORDER BY p.owner_did, p.owner_device_id, p.created_at, p.key_package_ref
    "#)
    .bind(recipient_did)
    .bind(horizon)
    .bind(now)
    .fetch_all(&mut *tx)
    .await
    .map_err(|e| FederationError::Storage(e.to_string()))?;

    if rows.is_empty() {
        return Err(FederationError::NotFound("recipient keys unavailable".into()));
    }

    let mut result = Vec::with_capacity(rows.len());
    for row in rows {
        let key_package_ref: Vec<u8> = row.get("key_package_ref");
        sqlx::query("UPDATE chat.key_packages SET status = 'reserved' WHERE key_package_ref = $1")
            .bind(&key_package_ref)
            .execute(&mut *tx)
            .await
            .map_err(|e| FederationError::Storage(e.to_string()))?;

        let grant_json: Value = serde_json::from_slice(&row.get::<Vec<u8>, _>("signed_grant"))
            .unwrap_or(Value::Null);

        let expires_at_dt: DateTime<Utc> = row.get("expires_at");

        result.push(RemoteDeviceBootstrap {
            owner_did: row.get("owner_did"),
            owner_device_id: row.get("owner_device_id"),
            owner_key_id: row.get("owner_key_id"),
            auth_generation: row.get("owner_auth_generation"),
            grant_id: row.get("grant_id"),
            grant_digest: STANDARD.encode(&row.get::<Vec<u8>, _>("grant_digest")),
            capability_revision: row.get("capability_revision"),
            key_package_ref: STANDARD.encode(&key_package_ref),
            wrapper_bytes: STANDARD.encode(&row.get::<Vec<u8>, _>("wrapper_bytes")),
            signed_grant: grant_json,
            expires_at: expires_at_dt.to_rfc3339(),
            signature_public_key: STANDARD.encode(&row.get::<Vec<u8>, _>("signing_public_key")),
        });
    }

    tx.commit().await.map_err(|e| FederationError::Storage(e.to_string()))?;
    Ok(result)
}

/// Ingest an inbound direct request delivery on the recipient's home DS.
///
/// Records the canonical entry, conversation, publication, and Welcome deliveries
/// into the recipient home's database so local clients can discover and import
/// the Welcome via `getPendingWelcomes` and receive SSE notifications.
pub async fn ingest_remote_direct_request_delivery(
    pool: &DbPool,
    sse: Option<&Arc<SseState>>,
    input: DeliverDirectRequestInput,
) -> Result<(), FederationError> {
    let now = Utc::now();
    let mut tx = pool.begin().await.map_err(|e| FederationError::Storage(e.to_string()))?;

    let entry = input.entry;
    let seq: i64 = entry["seq"].as_i64().unwrap_or(1);
    let entry_id = Uuid::parse_str(entry["entryId"].as_str().unwrap_or_default())
        .unwrap_or(input.request_id);
    let conversation_id = input.conversation_id;
    let actor_did = entry["signedRequest"]["body"]["actorDid"].as_str().unwrap_or_default();
    let recipient_did = entry["signedRequest"]["body"]["recipientDid"].as_str().unwrap_or_default();

    let direct_did_low = std::cmp::min(actor_did, recipient_did);
    let direct_did_high = std::cmp::max(actor_did, recipient_did);

    // 1. Ensure principals
    sqlx::query("INSERT INTO chat.principals(user_did, created_at) VALUES($1, $2) ON CONFLICT (user_did) DO NOTHING")
        .bind(actor_did)
        .bind(now)
        .execute(&mut *tx)
        .await
        .map_err(|e| FederationError::Storage(e.to_string()))?;
    sqlx::query("INSERT INTO chat.principals(user_did, created_at) VALUES($1, $2) ON CONFLICT (user_did) DO NOTHING")
        .bind(recipient_did)
        .bind(now)
        .execute(&mut *tx)
        .await
        .map_err(|e| FederationError::Storage(e.to_string()))?;

    // 2. Insert conversation
    sqlx::query(r#"
        INSERT INTO chat.conversations(
            conversation_id, kind, lifecycle, protocol_version,
            current_generation, current_state_version, next_entry_seq,
            direct_did_low, direct_did_high, created_at, updated_at
        ) VALUES($1, 'direct', 'active', '2', 0, 1, $2, $3, $4, $5, $5)
        ON CONFLICT (conversation_id) DO UPDATE SET updated_at = EXCLUDED.updated_at
    "#)
    .bind(conversation_id)
    .bind(seq + 1)
    .bind(direct_did_low)
    .bind(direct_did_high)
    .bind(now)
    .execute(&mut *tx)
    .await
    .map_err(|e| FederationError::Storage(e.to_string()))?;

    // 3. Insert participants
    sqlx::query(r#"
        INSERT INTO chat.participants(
            conversation_id, user_did, status, role, current_membership,
            invitation_transition_id, created_by_did, created_at, updated_at
        ) VALUES($1, $2, 'active', 'admin', TRUE, NULL, $2, $3, $3)
        ON CONFLICT DO NOTHING
    "#)
    .bind(conversation_id)
    .bind(actor_did)
    .bind(now)
    .execute(&mut *tx)
    .await
    .map_err(|e| FederationError::Storage(e.to_string()))?;

    sqlx::query(r#"
        INSERT INTO chat.participants(
            conversation_id, user_did, status, role, current_membership,
            invitation_transition_id, created_by_did, created_at, updated_at
        ) VALUES($1, $2, 'pending', 'member', TRUE, $3, $4, $5, $5)
        ON CONFLICT DO NOTHING
    "#)
    .bind(conversation_id)
    .bind(recipient_did)
    .bind(input.request_id)
    .bind(actor_did)
    .bind(now)
    .execute(&mut *tx)
    .await
    .map_err(|e| FederationError::Storage(e.to_string()))?;

    // 4. Insert entry
    let entry_bytes = serde_json::to_vec(&entry).unwrap_or_default();
    let signed_bytes = serde_json::to_vec(&entry["signedRequest"]).unwrap_or_default();
    let actor_device_id = Uuid::parse_str(entry["signedRequest"]["body"]["actorDeviceId"].as_str().unwrap_or_default()).unwrap_or_default();
    let actor_key_id = entry["signedRequest"]["body"]["keyId"].as_str().unwrap_or_default();
    let actor_auth_generation = entry["signedRequest"]["body"]["authGeneration"].as_i64().unwrap_or(1);

    sqlx::query(r#"
        INSERT INTO chat.entries(
            conversation_id, seq, entry_id, entry_kind,
            accepted_payload_bytes, accepted_payload_sha256,
            signed_request_bytes, request_digest, signature,
            server_fields_bytes, outer_entry_fingerprint,
            actor_did, actor_device_id, actor_key_id, actor_auth_generation,
            generation, state_version, transition_id, received_at
        ) VALUES(
            $1, $2, $3, 'blue.catbird.chat.defs#directRequestEntry',
            $4, digest($4, 'sha256'),
            $5, digest($5, 'sha256'), E'\\x00'::bytea,
            '{}'::jsonb::text::bytea, digest($4, 'sha256'),
            $6, $7, $8, $9,
            0, 1, $10, $11
        )
        ON CONFLICT DO NOTHING
    "#)
    .bind(conversation_id)
    .bind(seq)
    .bind(entry_id)
    .bind(&entry_bytes)
    .bind(&signed_bytes)
    .bind(actor_did)
    .bind(actor_device_id)
    .bind(actor_key_id)
    .bind(actor_auth_generation)
    .bind(input.request_id)
    .bind(now)
    .execute(&mut *tx)
    .await
    .map_err(|e| FederationError::Storage(e.to_string()))?;

    // 5. Insert direct_request_publications
    let pub_receipt = input.publication_receipt;
    let full_welcome = STANDARD.decode(pub_receipt["receipt"]["artifacts"]["welcome"]["opaqueWelcome"].as_str().unwrap_or_default()).unwrap_or_default();
    let full_welcome_sha256 = STANDARD.decode(pub_receipt["receipt"]["artifacts"]["welcome"]["sha256"].as_str().unwrap_or_default()).unwrap_or_default();
    let import_until_str = pub_receipt["receipt"]["importUntil"].as_str().unwrap_or_default();
    let import_until = DateTime::parse_from_rfc3339(import_until_str)
        .map(|dt| dt.with_timezone(&Utc))
        .unwrap_or(now + chrono::Duration::days(7));

    let pub_digest = STANDARD.decode(pub_receipt["receipt"]["requestDigest"].as_str().unwrap_or_default()).unwrap_or_else(|_| vec![0u8; 32]);
    let prep_digest = STANDARD.decode(pub_receipt["receipt"]["preparationRequestDigest"].as_str().unwrap_or_default()).unwrap_or_else(|_| vec![0u8; 32]);
    let context_hash = STANDARD.decode(pub_receipt["receipt"]["contextHash"].as_str().unwrap_or_default()).unwrap_or_else(|_| vec![0u8; 32]);

    sqlx::query(r#"
        INSERT INTO chat.direct_request_publications(
            request_id, conversation_id, actor_did, actor_device_id, actor_key_id,
            actor_auth_generation, signed_publication, unsigned_body, transcript,
            request_digest, signature, prior_generation, prior_state_version,
            generation, state_version, epoch, group_id, metadata_id, metadata_version,
            title, description, avatar_blob_locator, avatar_content_type,
            first_message_id, initial_ciphertext, full_welcome, full_welcome_sha256,
            import_until, recipient_did, context_hash, preparation_digest,
            publication_digest, request_entry, created_at
        ) VALUES(
            $1, $2, $3, $4, $5,
            $6, $7, '{}'::jsonb::text::bytea, 'trans'::bytea,
            $8, E'\\x00'::bytea, NULL, NULL,
            0, 1, 1, E'\\x00'::bytea, NULL, NULL,
            NULL, NULL, NULL, NULL,
            $9, E'\\x00'::bytea, $10, $11,
            $12, $13, $14, $15,
            $16, $17, $18
        )
        ON CONFLICT DO NOTHING
    "#)
    .bind(input.request_id)
    .bind(conversation_id)
    .bind(actor_did)
    .bind(actor_device_id)
    .bind(actor_key_id)
    .bind(actor_auth_generation)
    .bind(serde_json::to_vec(&pub_receipt["receipt"]).unwrap_or_default())
    .bind(&pub_digest)
    .bind(input.first_message_id)
    .bind(&full_welcome)
    .bind(&full_welcome_sha256)
    .bind(import_until)
    .bind(recipient_did)
    .bind(&context_hash)
    .bind(&prep_digest)
    .bind(&pub_digest)
    .bind(&entry_bytes)
    .bind(now)
    .execute(&mut *tx)
    .await
    .map_err(|e| FederationError::Storage(e.to_string()))?;

    // 6. Insert direct_request_device_deliveries
    for d in input.deliveries {
        let recipient_did_dev = d["recipientDid"].as_str().unwrap_or(recipient_did);
        let recipient_device_id = Uuid::parse_str(d["recipientDeviceId"].as_str().unwrap_or_default()).unwrap_or_default();
        let provenance_json = &d["provenance"];
        let provenance_bytes = serde_json::to_vec(provenance_json).unwrap_or_default();
        let grant_id = Uuid::parse_str(provenance_json["grantId"].as_str().unwrap_or_default()).unwrap_or_default();
        let grant_revision = provenance_json["grantRevision"].as_i64().unwrap_or(1);
        let package_ref = STANDARD.decode(provenance_json["keyPackageRef"].as_str().unwrap_or_default()).unwrap_or_default();

        sqlx::query(r#"
            INSERT INTO chat.direct_request_device_deliveries(
                request_id, owner_did, owner_device_id, owner_key_id,
                auth_generation, key_package_ref, grant_id, grant_revision,
                grant_digest, leaf_index, import_until, provenance, provenance_sha256
            ) VALUES(
                $1, $2, $3, 'key-1',
                1, $4, $5, $6,
                digest('grant', 'sha256'), 1, $7, $8, digest($8, 'sha256')
            )
            ON CONFLICT DO NOTHING
        "#)
        .bind(input.request_id)
        .bind(recipient_did_dev)
        .bind(recipient_device_id)
        .bind(&package_ref)
        .bind(grant_id)
        .bind(grant_revision)
        .bind(import_until)
        .bind(&provenance_bytes)
        .execute(&mut *tx)
        .await
        .map_err(|e| FederationError::Storage(e.to_string()))?;
    }

    tx.commit().await.map_err(|e| FederationError::Storage(e.to_string()))?;

    // Emit realtime event if SSE state is available
    if let Some(sse_state) = sse {
        sse_state.broadcast(
            "conversationChanged",
            &json!({
                "$type": "blue.catbird.chat.defs#conversationChangedEvent",
                "conversationId": conversation_id.to_string()
            }).to_string(),
        );
        sse_state.broadcast(
            "welcomeAvailable",
            &json!({
                "$type": "blue.catbird.chat.defs#welcomeAvailableEvent",
                "welcomeId": input.request_id.to_string(),
                "conversationId": conversation_id.to_string()
            }).to_string(),
        );
    }

    Ok(())
}

/// Ingest an inbound acceptance entry on a remote DS.
pub async fn ingest_remote_acceptance_entry(
    pool: &DbPool,
    sse: Option<&Arc<SseState>>,
    conversation_id: Uuid,
    entry: &Value,
    acceptance_proof: &Value,
) -> Result<(), FederationError> {
    let now = Utc::now();
    let mut tx = pool.begin().await.map_err(|e| FederationError::Storage(e.to_string()))?;

    let seq = entry["seq"].as_i64().unwrap_or(2);
    let entry_id = Uuid::parse_str(entry["entryId"].as_str().unwrap_or_default()).unwrap_or_else(|_| Uuid::new_v4());
    let entry_bytes = serde_json::to_vec(entry).unwrap_or_default();
    let signed_bytes = serde_json::to_vec(&entry["signedRequest"]).unwrap_or_default();
    let actor_did = entry["signedRequest"]["body"]["actorDid"].as_str().unwrap_or_default();
    let actor_device_id = Uuid::parse_str(entry["signedRequest"]["body"]["actorDeviceId"].as_str().unwrap_or_default()).unwrap_or_default();
    let actor_key_id = entry["signedRequest"]["body"]["keyId"].as_str().unwrap_or_default();
    let actor_auth_gen = entry["signedRequest"]["body"]["authGeneration"].as_i64().unwrap_or(1);

    // 1. Insert acceptance entry
    sqlx::query(r#"
        INSERT INTO chat.entries(
            conversation_id, seq, entry_id, entry_kind,
            accepted_payload_bytes, accepted_payload_sha256,
            signed_request_bytes, request_digest, signature,
            server_fields_bytes, outer_entry_fingerprint,
            actor_did, actor_device_id, actor_key_id, actor_auth_generation,
            generation, state_version, transition_id, received_at
        ) VALUES(
            $1, $2, $3, 'blue.catbird.chat.defs#participantAcceptanceEntry',
            $4, digest($4, 'sha256'),
            $5, digest($5, 'sha256'), E'\\x00'::bytea,
            '{}'::jsonb::text::bytea, digest($4, 'sha256'),
            $6, $7, $8, $9,
            0, 2, $3, $10
        )
        ON CONFLICT DO NOTHING
    "#)
    .bind(conversation_id)
    .bind(seq)
    .bind(entry_id)
    .bind(&entry_bytes)
    .bind(&signed_bytes)
    .bind(actor_did)
    .bind(actor_device_id)
    .bind(actor_key_id)
    .bind(actor_auth_gen)
    .bind(now)
    .execute(&mut *tx)
    .await
    .map_err(|e| FederationError::Storage(e.to_string()))?;

    // 2. Update participant status to accepted
    sqlx::query("UPDATE chat.participants SET status = 'accepted', updated_at = $3 WHERE conversation_id = $1 AND user_did = $2")
        .bind(conversation_id)
        .bind(actor_did)
        .bind(now)
        .execute(&mut *tx)
        .await
        .map_err(|e| FederationError::Storage(e.to_string()))?;

    // 3. Update conversation state
    sqlx::query("UPDATE chat.conversations SET current_state_version = 2, next_entry_seq = $2, updated_at = $3 WHERE conversation_id = $1")
        .bind(conversation_id)
        .bind(seq + 1)
        .bind(now)
        .execute(&mut *tx)
        .await
        .map_err(|e| FederationError::Storage(e.to_string()))?;

    tx.commit().await.map_err(|e| FederationError::Storage(e.to_string()))?;

    if let Some(sse_state) = sse {
        sse_state.broadcast(
            "conversationChanged",
            &json!({
                "$type": "blue.catbird.chat.defs#conversationChangedEvent",
                "conversationId": conversation_id.to_string()
            }).to_string(),
        );
    }

    Ok(())
}

/// Ingest an inbound application message entry on a remote DS.
pub async fn ingest_remote_message_entry(
    pool: &DbPool,
    sse: Option<&Arc<SseState>>,
    conversation_id: Uuid,
    entry: &Value,
) -> Result<(), FederationError> {
    let now = Utc::now();
    let mut tx = pool.begin().await.map_err(|e| FederationError::Storage(e.to_string()))?;

    let seq = entry["seq"].as_i64().unwrap_or(3);
    let entry_id = Uuid::parse_str(entry["entryId"].as_str().unwrap_or_default()).unwrap_or_else(|_| Uuid::new_v4());
    let entry_bytes = serde_json::to_vec(entry).unwrap_or_default();
    let signed_bytes = serde_json::to_vec(&entry["signedRequest"]).unwrap_or_default();
    let actor_did = entry["signedRequest"]["body"]["actorDid"].as_str().unwrap_or_default();
    let actor_device_id = Uuid::parse_str(entry["signedRequest"]["body"]["actorDeviceId"].as_str().unwrap_or_default()).unwrap_or_default();
    let actor_key_id = entry["signedRequest"]["body"]["keyId"].as_str().unwrap_or_default();
    let actor_auth_gen = entry["signedRequest"]["body"]["authGeneration"].as_i64().unwrap_or(1);

    // 1. Insert application entry
    sqlx::query(r#"
        INSERT INTO chat.entries(
            conversation_id, seq, entry_id, entry_kind,
            accepted_payload_bytes, accepted_payload_sha256,
            signed_request_bytes, request_digest, signature,
            server_fields_bytes, outer_entry_fingerprint,
            actor_did, actor_device_id, actor_key_id, actor_auth_generation,
            generation, state_version, transition_id, received_at
        ) VALUES(
            $1, $2, $3, 'blue.catbird.chat.defs#applicationEntry',
            $4, digest($4, 'sha256'),
            $5, digest($5, 'sha256'), E'\\x00'::bytea,
            '{}'::jsonb::text::bytea, digest($4, 'sha256'),
            $6, $7, $8, $9,
            0, 3, $3, $10
        )
        ON CONFLICT DO NOTHING
    "#)
    .bind(conversation_id)
    .bind(seq)
    .bind(entry_id)
    .bind(&entry_bytes)
    .bind(&signed_bytes)
    .bind(actor_did)
    .bind(actor_device_id)
    .bind(actor_key_id)
    .bind(actor_auth_gen)
    .bind(now)
    .execute(&mut *tx)
    .await
    .map_err(|e| FederationError::Storage(e.to_string()))?;

    // 2. Update conversation sequence
    sqlx::query("UPDATE chat.conversations SET next_entry_seq = $2, updated_at = $3 WHERE conversation_id = $1")
        .bind(conversation_id)
        .bind(seq + 1)
        .bind(now)
        .execute(&mut *tx)
        .await
        .map_err(|e| FederationError::Storage(e.to_string()))?;

    tx.commit().await.map_err(|e| FederationError::Storage(e.to_string()))?;

    if let Some(sse_state) = sse {
        sse_state.broadcast(
            "messageAvailable",
            &json!({
                "$type": "blue.catbird.chat.defs#messageAvailableEvent",
                "conversationId": conversation_id.to_string(),
                "seq": seq
            }).to_string(),
        );
        sse_state.broadcast(
            "conversationChanged",
            &json!({
                "$type": "blue.catbird.chat.defs#conversationChangedEvent",
                "conversationId": conversation_id.to_string()
            }).to_string(),
        );
    }

    Ok(())
}

/// Coordinator execution for prepareDirectRequest relayed from sender home DS or direct.
pub async fn coordinator_prepare_direct_request(
    pool: &DbPool,
    runtime: &Arc<ChatRuntime>,
    input: &Value,
) -> Result<Value, FederationError> {
    let signed_req = input.get("signedRequest").unwrap_or(input);
    let actor_did = signed_req["body"]["actorDid"].as_str().ok_or_else(|| {
        FederationError::InvalidRequest("missing actorDid".into())
    })?;
    let recipient_did = signed_req["body"]["recipientDid"].as_str().ok_or_else(|| {
        FederationError::InvalidRequest("missing recipientDid".into())
    })?;
    let request_id = Uuid::parse_str(signed_req["body"]["requestId"].as_str().unwrap_or_default())
        .map_err(|_| FederationError::InvalidRequest("invalid requestId".into()))?;

    let coordinator = resolve_pair_coordinator(pool, actor_did, recipient_did).await?;
    let now = TrustedRequestInstant::capture()
        .map_err(|_| FederationError::Invariant("trusted instant".into()))?
        .datetime();

    // If recipient is on a remote node, stage the reservation first outside of local PG tx
    if !coordinator.is_recipient_home {
        let remote_devices = reserve_remote_recipient_bootstrap(
            &coordinator.recipient_home.endpoint,
            &coordinator.recipient_home.did,
            request_id,
            actor_did,
            recipient_did,
        )
        .await?;

        let mut tx = pool.begin().await.map_err(|e| FederationError::Storage(e.to_string()))?;
        stage_remote_recipient_devices(&mut tx, &remote_devices, now)
            .await
            .map_err(|e| FederationError::Storage(e.to_string()))?;
        tx.commit().await.map_err(|e| FederationError::Storage(e.to_string()))?;
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

    let mut tx = pool.begin().await.map_err(|e| FederationError::Storage(e.to_string()))?;
    let result = crate::chat_protocol::repository::direct_request_preparation::prepare_direct_request(
        &mut tx,
        &principal,
        &signed_bytes,
        signer,
        runtime.relationship_authority().as_ref(),
        now,
    )
    .await
    .map_err(|e| FederationError::RemoteError {
        status: 400,
        body: format!("prepare_direct_request error: {e:?}"),
    })?;

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
    input: &Value,
) -> Result<Value, FederationError> {
    let signed_req = input.get("signedRequest").unwrap_or(input);
    let actor_did = signed_req["body"]["actorDid"].as_str().ok_or_else(|| {
        FederationError::InvalidRequest("missing actorDid".into())
    })?;
    let recipient_did = signed_req["body"]["recipientDid"].as_str().ok_or_else(|| {
        FederationError::InvalidRequest("missing recipientDid".into())
    })?;
    let request_id = Uuid::parse_str(signed_req["body"]["requestId"].as_str().unwrap_or_default())
        .map_err(|_| FederationError::InvalidRequest("invalid requestId".into()))?;
    let conversation_id = Uuid::parse_str(signed_req["body"]["conversationId"].as_str().unwrap_or_default())
        .map_err(|_| FederationError::InvalidRequest("invalid conversationId".into()))?;
    let first_message_id = Uuid::parse_str(signed_req["body"]["firstMessageId"].as_str().unwrap_or_default())
        .map_err(|_| FederationError::InvalidRequest("invalid firstMessageId".into()))?;

    let coordinator = resolve_pair_coordinator(pool, actor_did, recipient_did).await?;
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
        "blue.catbird.chat.publishDirectRequest",
    );

    let signed_bytes = serde_json::to_vec(signed_req)
        .map_err(FederationError::Json)?;

    let mut tx = pool.begin().await.map_err(|e| FederationError::Storage(e.to_string()))?;

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

    tx.commit().await.map_err(|e| FederationError::Storage(e.to_string()))?;

    // If recipient is on a remote node, deliver the direct request and Welcome to the recipient's home DS!
    if !coordinator.is_recipient_home {
        let entry_row: Option<Vec<u8>> = sqlx::query_scalar("SELECT accepted_payload_bytes FROM chat.entries WHERE transition_id = $1")
            .bind(request_id)
            .fetch_optional(pool)
            .await
            .ok()
            .flatten();

        let entry_val: Value = entry_row
            .and_then(|b| serde_json::from_slice(&b).ok())
            .unwrap_or(json!({}));

        let deliveries = signed_req["artifacts"]["welcome"]["deliveries"].as_array().cloned().unwrap_or_default();

        let deliver_input = DeliverDirectRequestInput {
            request_id,
            conversation_id,
            first_message_id,
            entry: entry_val,
            deliveries,
            publication_receipt: receipt.clone(),
            coordinator_did: coordinator.coordinator_did.clone(),
        };

        if let Err(e) = deliver_direct_request_to_peer(
            &coordinator.recipient_home.endpoint,
            &coordinator.recipient_home.did,
            deliver_input,
        ).await {
            warn!("Failed to deliver direct request to recipient peer: {e}");
        }
    }

    Ok(json!({ "outcome": receipt }))
}

/// Coordinator execution for acceptDirectRequest relayed from recipient home DS.
pub async fn coordinator_accept_direct_request(
    pool: &DbPool,
    runtime: &Arc<ChatRuntime>,
    conversation_id: Uuid,
    direct_request: &Value,
) -> Result<DeliverAcceptanceOutput, FederationError> {
    let raw_bytes = serde_json::to_vec(direct_request)
        .map_err(FederationError::Json)?;
    let actor_did = direct_request["body"]["actorDid"].as_str().unwrap_or_default();

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

    tx.commit().await.map_err(|e| FederationError::Storage(e.to_string()))?;

    let outcome_val: Value = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
    let acceptance_proof = outcome_val.get("acceptanceProof").cloned().unwrap_or(Value::Null);

    let entry_row: Option<Vec<u8>> = sqlx::query_scalar("SELECT accepted_payload_bytes FROM chat.entries WHERE conversation_id = $1 AND seq = 2")
        .bind(conversation_id)
        .fetch_optional(pool)
        .await
        .ok()
        .flatten();

    let entry: Value = entry_row
        .and_then(|b| serde_json::from_slice(&b).ok())
        .unwrap_or(json!({}));

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
    conversation_id: Uuid,
    message: &Value,
) -> Result<Value, FederationError> {
    let entry_row: Value = message.clone();
    let seq = entry_row["seq"].as_i64().unwrap_or(3);
    ingest_remote_message_entry(pool, Some(runtime.sse_state()), conversation_id, &entry_row).await?;
    Ok(json!({ "ok": true, "seq": seq }))
}

/// Coordinator execution for getDirectRequestOutcome.
pub async fn coordinator_get_outcome(
    pool: &DbPool,
    runtime: &Arc<ChatRuntime>,
    request_id: Uuid,
    actor_device_id: Uuid,
) -> Result<Value, FederationError> {
    let now = TrustedRequestInstant::capture()
        .map_err(|_| FederationError::Invariant("trusted instant".into()))?
        .datetime();
    let signer = runtime.request_receipt_signer().ok_or_else(|| {
        FederationError::ConfigError {
            reason: "request receipt signer not configured".into(),
        }
    })?;

    let actor_did: Option<String> = sqlx::query_scalar("SELECT actor_did FROM chat.direct_request_attempts WHERE request_id = $1")
        .bind(request_id)
        .fetch_optional(pool)
        .await
        .map_err(|e| FederationError::Storage(e.to_string()))?;

    let actor_did = actor_did.ok_or_else(|| FederationError::NotFound("attempt not found".into()))?;
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
    Ok(json!({ "outcome": outcome_val }))
}
