use moka::future::Cache;
use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use std::time::Duration;
use tracing::{debug, error};

use super::errors::FederationError;
use super::resolver::DsResolver;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceRecord {
    pub uri: String,
    pub cid: String,
    pub value: DeviceRecordValue,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceRecordValue {
    #[serde(rename = "$type")]
    pub record_type: Option<String>,
    #[serde(rename = "deviceId")]
    pub device_id: String,
    #[serde(rename = "deviceName")]
    pub device_name: Option<String>,
    #[serde(rename = "mlsSignaturePublicKey")]
    pub mls_signature_public_key: Option<BytesWrapper>,
    pub algorithm: Option<String>,
    pub platform: Option<String>,
    #[serde(rename = "createdAt")]
    pub created_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BytesWrapper {
    #[serde(rename = "$bytes")]
    pub bytes: String,
}

/// A simple client to fetch and cache user device records from their PDS.
#[derive(Clone)]
pub struct DeviceRecordClient {
    http: Client,
    resolver: Arc<DsResolver>,
    /// Map DID -> List of device records
    cache: Cache<String, Vec<DeviceRecord>>,
}

impl DeviceRecordClient {
    pub fn new(http: Client, resolver: Arc<DsResolver>) -> Self {
        // Short, small cache: 5 minutes TTL, max 1000 users
        let cache = Cache::builder()
            .time_to_live(Duration::from_secs(300))
            .max_capacity(1000)
            .build();

        Self {
            http,
            resolver,
            cache,
        }
    }

    /// Fetch device records for a DID.
    ///
    /// This method:
    /// 1. Checks the local short-term cache.
    /// 2. If missing, resolves the user's PDS via DsResolver.
    /// 3. Queries com.atproto.repo.listRecords on the PDS.
    /// 4. Caches and returns the records.
    pub async fn fetch_device_records(
        &self,
        did: &str,
    ) -> Result<Vec<DeviceRecord>, FederationError> {
        if let Some(cached) = self.cache.get(did).await {
            return Ok(cached);
        }

        let records = self.fetch_from_pds(did).await?;

        // Cache even if empty (user might not have registered any devices yet)
        self.cache.insert(did.to_string(), records.clone()).await;

        Ok(records)
    }

    async fn fetch_from_pds(&self, did: &str) -> Result<Vec<DeviceRecord>, FederationError> {
        let pds_endpoint = self.resolver.resolve_did_to_pds(did).await?;

        // com.atproto.repo.listRecords
        // Using "blue.catbird.mlsChat.device" collection
        let url = format!(
            "{}/xrpc/com.atproto.repo.listRecords?repo={}&collection=blue.catbird.mlsChat.device&limit=100",
            pds_endpoint,
            urlencoding::encode(did)
        );

        debug!("Fetching device records for {} from {}", did, url);

        let resp = self
            .http
            .get(&url)
            .timeout(Duration::from_secs(10))
            .send()
            .await
            .map_err(|e| FederationError::ResolutionFailed {
                did: did.to_string(),
                reason: format!("HTTP request failed: {}", e),
            })?;

        if !resp.status().is_success() {
            return Err(FederationError::ResolutionFailed {
                did: did.to_string(),
                reason: format!("PDS returned status {}", resp.status()),
            });
        }

        let body: serde_json::Value =
            resp.json()
                .await
                .map_err(|e| FederationError::ResolutionFailed {
                    did: did.to_string(),
                    reason: format!("Invalid JSON response: {}", e),
                })?;

        // Extract records array
        let records_json = body
            .get("records")
            .and_then(|v| v.as_array())
            .ok_or_else(|| FederationError::ResolutionFailed {
                did: did.to_string(),
                reason: "No 'records' field in listRecords response".to_string(),
            })?;

        let mut records = Vec::new();
        for record_json in records_json {
            match serde_json::from_value::<DeviceRecord>(record_json.clone()) {
                Ok(record) => records.push(record),
                Err(e) => {
                    // Log but don't fail entire fetch
                    error!("Failed to parse device record for {}: {}", did, e);
                    debug!("Record JSON: {:?}", record_json);
                }
            }
        }

        Ok(records)
    }

    /// Fetch the current chat policy for a user from their PDS.
    ///
    /// Reads the single `blue.catbird.mlsChat.policy/self` record via
    /// `com.atproto.repo.getRecord`.
    pub async fn get_chat_policy(&self, did: &str) -> Result<MLSChatPolicy, FederationError> {
        let pds_endpoint = self.resolver.resolve_did_to_pds(did).await?;

        let url = format!(
            "{}/xrpc/com.atproto.repo.getRecord?repo={}&collection=blue.catbird.mlsChat.policy&rkey=self",
            pds_endpoint,
            urlencoding::encode(did)
        );

        debug!("Fetching chat policy for {} from {}", did, url);

        let resp = self
            .http
            .get(&url)
            .timeout(Duration::from_secs(10))
            .send()
            .await
            .map_err(|e| FederationError::ResolutionFailed {
                did: did.to_string(),
                reason: format!("HTTP request failed: {}", e),
            })?;

        if !resp.status().is_success() {
            // 400/404 is expected if user hasn't set a policy yet
            debug!(
                "No policy record for {} (status {}), returning defaults",
                did,
                resp.status()
            );
            return Ok(MLSChatPolicy::default());
        }

        let body: serde_json::Value =
            resp.json()
                .await
                .map_err(|e| FederationError::ResolutionFailed {
                    did: did.to_string(),
                    reason: format!("Invalid JSON response: {}", e),
                })?;

        // The record value is in body.value
        let value = body.get("value").unwrap_or(&body);

        let policy = MLSChatPolicy {
            allow_followers_bypass: value
                .get("allowFollowersBypass")
                .and_then(|v| v.as_bool()),
            allow_following_bypass: value
                .get("allowFollowingBypass")
                .and_then(|v| v.as_bool()),
            who_can_message_me: value
                .get("whoCanMessageMe")
                .and_then(|v| v.as_str())
                .map(|s| s.to_string()),
            auto_expire_days: value
                .get("autoExpireDays")
                .and_then(|v| v.as_i64())
                .map(|v| v as i32),
        };

        Ok(policy)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct MLSChatPolicy {
    pub allow_followers_bypass: Option<bool>,
    pub allow_following_bypass: Option<bool>,
    pub who_can_message_me: Option<String>,
    pub auto_expire_days: Option<i32>,
}
