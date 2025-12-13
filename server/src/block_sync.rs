//! Block synchronization module for fetching Bluesky block records from user PDSes.
//!
//! This module provides functionality to:
//! 1. Resolve a user's DID to find their PDS endpoint
//! 2. Query the PDS for app.bsky.graph.block records
//! 3. Sync blocks to the local bsky_blocks table
//! 4. Check for block conflicts between users

use chrono::{DateTime, Utc};
use moka::future::Cache;
use serde::{Deserialize, Serialize};
use std::time::Duration;
use thiserror::Error;
use tracing::{debug, error, info, warn};

use crate::storage::DbPool;

/// Errors that can occur during block synchronization
#[derive(Debug, Error)]
pub enum BlockSyncError {
    #[error("Failed to resolve DID: {0}")]
    DidResolutionFailed(String),

    #[error("PDS endpoint not found in DID document")]
    PdsEndpointNotFound,

    #[error("HTTP request failed: {0}")]
    HttpError(String),

    #[error("Failed to parse response: {0}")]
    ParseError(String),

    #[error("Database error: {0}")]
    DatabaseError(String),

    #[error("Invalid DID format: {0}")]
    InvalidDid(String),
}

/// A block record from the PDS
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlockRecord {
    /// The DID of the user who created the block
    pub blocker_did: String,
    /// The DID of the user who was blocked
    pub blocked_did: String,
    /// AT-URI of the block record
    pub uri: String,
    /// CID of the block record
    pub cid: String,
    /// When the block was created
    pub created_at: Option<DateTime<Utc>>,
}

/// DID Document structure (matching auth.rs but standalone for this module)
#[derive(Debug, Clone, Serialize, Deserialize)]
struct DidDocument {
    id: String,
    #[serde(default)]
    service: Option<Vec<Service>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct Service {
    id: String,
    #[serde(rename = "type")]
    service_type: String,
    #[serde(rename = "serviceEndpoint")]
    service_endpoint: String,
}

/// Response from com.atproto.repo.listRecords
#[derive(Debug, Deserialize)]
struct ListRecordsResponse {
    records: Vec<RecordEntry>,
    cursor: Option<String>,
}

#[derive(Debug, Deserialize)]
struct RecordEntry {
    uri: String,
    cid: String,
    value: BlockValue,
}

/// The value of an app.bsky.graph.block record
#[derive(Debug, Deserialize)]
struct BlockValue {
    #[serde(rename = "$type")]
    record_type: Option<String>,
    subject: String,
    #[serde(rename = "createdAt")]
    created_at: Option<String>,
}

/// Block sync service for fetching and caching block data from PDSes
#[derive(Clone)]
pub struct BlockSyncService {
    http_client: reqwest::Client,
    /// Cache of DID -> PDS endpoint, TTL 5 minutes
    pds_cache: Cache<String, String>,
    /// Cache of DID -> Vec<BlockRecord>, TTL 1 minute (short for freshness)
    blocks_cache: Cache<String, Vec<BlockRecord>>,
}

impl BlockSyncService {
    /// Create a new BlockSyncService
    pub fn new() -> Self {
        Self {
            http_client: reqwest::Client::builder()
                .timeout(Duration::from_secs(10))
                .user_agent("Catbird-MLS/1.0")
                .build()
                .expect("Failed to create HTTP client"),
            pds_cache: Cache::builder()
                .time_to_live(Duration::from_secs(300)) // 5 minutes
                .max_capacity(10_000)
                .build(),
            blocks_cache: Cache::builder()
                .time_to_live(Duration::from_secs(60)) // 1 minute - short for freshness
                .max_capacity(10_000)
                .build(),
        }
    }

    /// Resolve a DID to get the PDS endpoint
    pub async fn get_pds_endpoint(&self, did: &str) -> Result<String, BlockSyncError> {
        // Check cache first
        if let Some(endpoint) = self.pds_cache.get(did).await {
            debug!("PDS cache hit for {}", crate::crypto::redact_for_log(did));
            return Ok(endpoint);
        }

        // Resolve DID document
        let doc = self.resolve_did(did).await?;

        // Extract PDS endpoint from services
        let endpoint = doc
            .service
            .and_then(|services| {
                services.into_iter().find(|s| {
                    (s.id == "#atproto_pds" || s.id == format!("{}#atproto_pds", doc.id))
                        && s.service_type == "AtprotoPersonalDataServer"
                })
            })
            .map(|s| s.service_endpoint)
            .ok_or(BlockSyncError::PdsEndpointNotFound)?;

        // Cache the endpoint
        self.pds_cache
            .insert(did.to_string(), endpoint.clone())
            .await;

        Ok(endpoint)
    }

    /// Resolve a DID document
    async fn resolve_did(&self, did: &str) -> Result<DidDocument, BlockSyncError> {
        if !did.starts_with("did:") {
            return Err(BlockSyncError::InvalidDid(format!(
                "DID must start with 'did:': {}",
                did
            )));
        }

        let url = if did.starts_with("did:plc:") {
            format!("https://plc.directory/{}", did)
        } else if did.starts_with("did:web:") {
            let web_path = did
                .strip_prefix("did:web:")
                .ok_or_else(|| BlockSyncError::InvalidDid(did.to_string()))?;
            let domain = web_path.replace(':', "/");
            format!("https://{}/.well-known/did.json", domain)
        } else {
            return Err(BlockSyncError::InvalidDid(format!(
                "Unsupported DID method: {}",
                did
            )));
        };

        let response = self
            .http_client
            .get(&url)
            .send()
            .await
            .map_err(|e| BlockSyncError::HttpError(e.to_string()))?;

        if !response.status().is_success() {
            return Err(BlockSyncError::DidResolutionFailed(format!(
                "HTTP {} from DID resolver",
                response.status()
            )));
        }

        response
            .json::<DidDocument>()
            .await
            .map_err(|e| BlockSyncError::ParseError(e.to_string()))
    }

    /// Fetch all block records for a user from their PDS
    ///
    /// This calls com.atproto.repo.listRecords with collection="app.bsky.graph.block"
    /// and paginates through all results.
    pub async fn fetch_blocks_from_pds(
        &self,
        did: &str,
    ) -> Result<Vec<BlockRecord>, BlockSyncError> {
        // Check cache first
        if let Some(blocks) = self.blocks_cache.get(did).await {
            debug!(
                "Blocks cache hit for {} ({} blocks)",
                crate::crypto::redact_for_log(did),
                blocks.len()
            );
            return Ok(blocks);
        }

        let pds_endpoint = self.get_pds_endpoint(did).await?;
        let mut all_blocks = Vec::new();
        let mut cursor: Option<String> = None;

        loop {
            let mut url = format!(
                "{}/xrpc/com.atproto.repo.listRecords?repo={}&collection=app.bsky.graph.block&limit=100",
                pds_endpoint.trim_end_matches('/'),
                urlencoding::encode(did)
            );

            if let Some(ref c) = cursor {
                url.push_str(&format!("&cursor={}", urlencoding::encode(c)));
            }

            debug!(
                "Fetching blocks from PDS for {}",
                crate::crypto::redact_for_log(did)
            );

            let response = self
                .http_client
                .get(&url)
                .send()
                .await
                .map_err(|e| BlockSyncError::HttpError(e.to_string()))?;

            if !response.status().is_success() {
                // 400 might mean no blocks exist, which is fine
                if response.status() == reqwest::StatusCode::BAD_REQUEST {
                    debug!(
                        "No block records found for {}",
                        crate::crypto::redact_for_log(did)
                    );
                    break;
                }
                return Err(BlockSyncError::HttpError(format!(
                    "PDS returned HTTP {}",
                    response.status()
                )));
            }

            let list_response: ListRecordsResponse = response
                .json()
                .await
                .map_err(|e| BlockSyncError::ParseError(e.to_string()))?;

            for record in list_response.records {
                // Parse created_at if present
                let created_at = record.value.created_at.as_ref().and_then(|s| {
                    DateTime::parse_from_rfc3339(s)
                        .ok()
                        .map(|dt| dt.with_timezone(&Utc))
                });

                all_blocks.push(BlockRecord {
                    blocker_did: did.to_string(),
                    blocked_did: record.value.subject,
                    uri: record.uri,
                    cid: record.cid,
                    created_at,
                });
            }

            cursor = list_response.cursor;
            if cursor.is_none() {
                break;
            }
        }

        info!(
            "Fetched {} blocks from PDS for {}",
            all_blocks.len(),
            crate::crypto::redact_for_log(did)
        );

        // Cache the results
        self.blocks_cache
            .insert(did.to_string(), all_blocks.clone())
            .await;

        Ok(all_blocks)
    }

    /// Check if user A blocks user B by querying A's PDS
    pub async fn check_blocks_bidirectional(
        &self,
        did_a: &str,
        did_b: &str,
    ) -> Result<bool, BlockSyncError> {
        // Check A's blocks
        let a_blocks = self.fetch_blocks_from_pds(did_a).await?;
        if a_blocks.iter().any(|b| b.blocked_did == did_b) {
            return Ok(true);
        }

        // Check B's blocks
        let b_blocks = self.fetch_blocks_from_pds(did_b).await?;
        if b_blocks.iter().any(|b| b.blocked_did == did_a) {
            return Ok(true);
        }

        Ok(false)
    }

    /// Check for any block conflicts among a set of DIDs
    /// Returns a list of (blocker, blocked) pairs
    pub async fn check_block_conflicts(
        &self,
        dids: &[String],
    ) -> Result<Vec<(String, String)>, BlockSyncError> {
        let mut conflicts = Vec::new();

        // For each user, fetch their blocks
        for did in dids {
            match self.fetch_blocks_from_pds(did).await {
                Ok(blocks) => {
                    // Check if any of their blocks target other members
                    for block in blocks {
                        if dids.contains(&block.blocked_did) {
                            conflicts.push((block.blocker_did, block.blocked_did));
                        }
                    }
                }
                Err(e) => {
                    warn!(
                        "Failed to fetch blocks for {}: {}",
                        crate::crypto::redact_for_log(did),
                        e
                    );
                    // Continue checking others - don't fail the whole operation
                }
            }
        }

        Ok(conflicts)
    }

    /// Sync blocks from PDS to the local database for a user
    pub async fn sync_blocks_to_db(
        &self,
        pool: &DbPool,
        did: &str,
    ) -> Result<usize, BlockSyncError> {
        let blocks = self.fetch_blocks_from_pds(did).await?;
        let now = chrono::Utc::now();

        // Delete existing blocks for this user and insert fresh ones
        // Using a transaction for atomicity
        let mut tx = pool
            .begin()
            .await
            .map_err(|e| BlockSyncError::DatabaseError(e.to_string()))?;

        // Delete old blocks for this user
        sqlx::query("DELETE FROM bsky_blocks WHERE user_did = $1")
            .bind(did)
            .execute(&mut *tx)
            .await
            .map_err(|e| BlockSyncError::DatabaseError(e.to_string()))?;

        // Insert new blocks
        for block in &blocks {
            sqlx::query(
                "INSERT INTO bsky_blocks (user_did, target_did, source, synced_at)
                 VALUES ($1, $2, 'pds', $3)
                 ON CONFLICT (user_did, target_did) DO UPDATE SET synced_at = $3",
            )
            .bind(&block.blocker_did)
            .bind(&block.blocked_did)
            .bind(&now)
            .execute(&mut *tx)
            .await
            .map_err(|e| BlockSyncError::DatabaseError(e.to_string()))?;
        }

        tx.commit()
            .await
            .map_err(|e| BlockSyncError::DatabaseError(e.to_string()))?;

        info!(
            "Synced {} blocks to DB for {}",
            blocks.len(),
            crate::crypto::redact_for_log(did)
        );

        Ok(blocks.len())
    }

    /// Invalidate cached blocks for a user (call after handleBlockChange)
    pub async fn invalidate_cache(&self, did: &str) {
        self.blocks_cache.invalidate(did).await;
    }
}

impl Default for BlockSyncService {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_pds_endpoint_resolution() {
        let service = BlockSyncService::new();

        // Test with a known DID (bsky.app's DID)
        // This is a real test - it will hit the network
        // Skip in CI if needed
        if std::env::var("SKIP_NETWORK_TESTS").is_ok() {
            return;
        }

        let result = service
            .get_pds_endpoint("did:plc:z72i7hdynmk6r22z27h6tvur")
            .await;
        assert!(result.is_ok(), "Failed to resolve PDS: {:?}", result);

        let endpoint = result.unwrap();
        assert!(
            endpoint.starts_with("https://"),
            "PDS endpoint should be HTTPS"
        );
    }

    #[test]
    fn test_invalid_did_format() {
        let service = BlockSyncService::new();

        let rt = tokio::runtime::Runtime::new().unwrap();
        let result = rt.block_on(service.resolve_did("not-a-did"));

        assert!(matches!(result, Err(BlockSyncError::InvalidDid(_))));
    }
}
