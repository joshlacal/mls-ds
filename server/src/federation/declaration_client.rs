use moka::future::Cache;
use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use std::time::Duration;
use tracing::{debug, error};

use super::errors::FederationError;
use super::resolver::DsResolver;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeclarationRecord {
    pub uri: String,
    pub cid: String,
    pub value: DeclarationValue,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeclarationValue {
    #[serde(rename = "$type")]
    pub record_type: String,
    pub createdAt: String,
    pub did: String,
    pub epoch: i64,
    pub seq: i64,
    pub prev: Option<String>,
    pub event: DeclarationEvent,
    pub proofs: DeclarationProofs,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "$type")]
pub enum DeclarationEvent {
    #[serde(rename = "blue.catbird.mlsChat.declaration#rootInit")]
    RootInit { note: Option<String> },
    #[serde(rename = "blue.catbird.mlsChat.declaration#deviceAdd")]
    DeviceAdd {
        deviceId: Option<String>,
        deviceKey: String,
    },
    #[serde(rename = "blue.catbird.mlsChat.declaration#deviceRevoke")]
    DeviceRevoke {
        deviceId: Option<String>,
        deviceKey: Option<String>,
        reason: Option<String>,
    },
    #[serde(rename = "blue.catbird.mlsChat.declaration#rootRotate")]
    RootRotate { newRoot: String, newRootAlg: String },
    #[serde(rename = "blue.catbird.mlsChat.declaration#chatPolicyUpdate")]
    ChatPolicyUpdate {
        #[serde(rename = "allowFollowersBypass")]
        allow_followers_bypass: Option<bool>,
        #[serde(rename = "allowFollowingBypass")]
        allow_following_bypass: Option<bool>,
        #[serde(rename = "whoCanMessageMe")]
        who_can_message_me: Option<String>, // "everyone", "mutuals", "following", "nobody"
        #[serde(rename = "autoExpireDays")]
        auto_expire_days: Option<i32>,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeclarationProofs {
    pub sig: BytesWrapper,
    pub sigAlg: String,
    pub coSig: Option<BytesWrapper>,
    pub coSigAlg: Option<String>,
    pub deviceProof: Option<BytesWrapper>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BytesWrapper {
    #[serde(rename = "$bytes")]
    pub bytes: String, // base64 encoded
}

/// A simple client to fetch and cache user declaration chains.
#[derive(Clone)]
pub struct DeclarationClient {
    http: Client,
    resolver: Arc<DsResolver>,
    // Map DID -> List of Records
    cache: Cache<String, Vec<DeclarationRecord>>,
}

impl DeclarationClient {
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

    /// Fetch declaration records for a DID.
    ///
    /// This method:
    /// 1. Checks the local short-term cache.
    /// 2. If missing, resolves the user's PDS via DsResolver.
    /// 3. Queries com.atproto.repo.listRecords on the PDS.
    /// 4. Caches and returns the records.
    pub async fn fetch_declarations(
        &self,
        did: &str,
    ) -> Result<Vec<DeclarationRecord>, FederationError> {
        if let Some(cached) = self.cache.get(did).await {
            return Ok(cached);
        }

        let records = self.fetch_from_pds(did).await?;

        // Cache even if empty (user might not have initialized MLS yet)
        self.cache.insert(did.to_string(), records.clone()).await;

        Ok(records)
    }

    async fn fetch_from_pds(&self, did: &str) -> Result<Vec<DeclarationRecord>, FederationError> {
        let pds_endpoint = self.resolver.resolve_did_to_pds(did).await?;

        // com.atproto.repo.listRecords
        // Using "blue.catbird.mlsChat.declaration" collection
        let url = format!(
            "{}/xrpc/com.atproto.repo.listRecords?repo={}&collection=blue.catbird.mlsChat.declaration&limit=100",
            pds_endpoint,
            urlencoding::encode(did)
        );

        debug!("Fetching declarations for {} from {}", did, url);

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
            // PDS might return 400/404 if repo doesn't exist, which is valid failure
            // but let's propagate it as resolution failed for now.
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
            // Use serde_json::from_value to decode into DeclarationRecord
            // Since `value` inside listRecords response is typically `value` field
            match serde_json::from_value::<DeclarationRecord>(record_json.clone()) {
                Ok(record) => records.push(record),
                Err(e) => {
                    // Log but don't fail entire fetch
                    error!("Failed to parse declaration record for {}: {}", did, e);
                    debug!("Record JSON: {:?}", record_json);
                }
            }
        }

        // Sort by seq (though listRecords usually returns reverse chronological, or maybe random?
        // We probably want to sort by seq ASC for processing)
        records.sort_by_key(|r| r.value.seq);

        Ok(records)
    }

    /// Fetch and compute the current chat policy for a user.
    pub async fn get_chat_policy(&self, did: &str) -> Result<MLSChatPolicy, FederationError> {
        let records = self.fetch_declarations(did).await?;

        // Replay events to build policy
        let mut policy = MLSChatPolicy::default();

        for record in records {
            if let DeclarationEvent::ChatPolicyUpdate {
                allow_followers_bypass,
                allow_following_bypass,
                who_can_message_me,
                auto_expire_days,
            } = record.value.event
            {
                if let Some(val) = allow_followers_bypass {
                    policy.allow_followers_bypass = Some(val);
                }
                if let Some(val) = allow_following_bypass {
                    policy.allow_following_bypass = Some(val);
                }
                if let Some(val) = who_can_message_me {
                    policy.who_can_message_me = Some(val);
                }
                if let Some(val) = auto_expire_days {
                    policy.auto_expire_days = Some(val);
                }
            }
        }

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
