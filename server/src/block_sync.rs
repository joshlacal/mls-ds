//! Block synchronization module for fetching Bluesky block records from user PDSes.
//!
//! This module provides functionality to:
//! 1. Resolve a user's DID to find their PDS endpoint
//! 2. Query the PDS for app.bsky.graph.block records
//! 3. Sync blocks to the local bsky_blocks table
//! 4. Check for block conflicts between users

use chrono::{DateTime, Utc};
use moka::future::Cache;
use reqwest::{redirect::Policy, Response, Url};
use serde::{Deserialize, Serialize};
use std::{
    collections::HashSet,
    mem::size_of,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    time::Duration,
};
use thiserror::Error;
use tracing::{debug, info};

use crate::util::outbound_body::{
    decode_json_bounded, OutboundBodyError, ResponseBodyBudget, DID_DOCUMENT_MAX_BYTES,
};
use crate::{identity::did_web_document_url, storage::DbPool};

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

    #[error("Resource limit exceeded for {resource} (limit: {limit})")]
    ResourceLimitExceeded {
        resource: &'static str,
        limit: usize,
    },

    #[error("Deadline exceeded for {operation}")]
    DeadlineExceeded { operation: &'static str },

    #[error("Unsafe outbound destination: {0}")]
    UnsafeDestination(String),

    #[error("Outbound redirect rejected (HTTP {status})")]
    RedirectRejected { status: reqwest::StatusCode },
}

#[derive(Debug)]
struct ValidatedDestination {
    url: Url,
    host: String,
    addrs: Vec<SocketAddr>,
}

#[cfg(test)]
#[derive(Debug, Clone)]
struct TestDnsAnswer {
    addrs: Vec<SocketAddr>,
    allow_insecure_fixture: bool,
}

#[cfg(test)]
#[derive(Debug, Default)]
struct TestDestinationFixture {
    answers: std::sync::Mutex<
        std::collections::HashMap<String, std::collections::VecDeque<TestDnsAnswer>>,
    >,
    allow_literal_loopback_http: bool,
    validation_delay: Duration,
    lookups: std::sync::atomic::AtomicUsize,
}

#[cfg(test)]
impl TestDestinationFixture {
    fn local_http() -> std::sync::Arc<Self> {
        std::sync::Arc::new(Self {
            allow_literal_loopback_http: true,
            ..Self::default()
        })
    }

    fn with_answers(
        answers: impl IntoIterator<Item = (String, Vec<TestDnsAnswer>)>,
    ) -> std::sync::Arc<Self> {
        std::sync::Arc::new(Self {
            answers: std::sync::Mutex::new(
                answers
                    .into_iter()
                    .map(|(host, answers)| (host, answers.into()))
                    .collect(),
            ),
            ..Self::default()
        })
    }

    fn with_answers_and_delay(
        answers: impl IntoIterator<Item = (String, Vec<TestDnsAnswer>)>,
        validation_delay: Duration,
    ) -> std::sync::Arc<Self> {
        std::sync::Arc::new(Self {
            answers: std::sync::Mutex::new(
                answers
                    .into_iter()
                    .map(|(host, answers)| (host, answers.into()))
                    .collect(),
            ),
            validation_delay,
            ..Self::default()
        })
    }

    fn resolve(&self, host: &str, port: u16) -> Option<TestDnsAnswer> {
        self.lookups
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        if let Some(answers) = self.answers.lock().unwrap().get_mut(host) {
            if answers.len() > 1 {
                return answers.pop_front();
            }
            return answers.front().cloned();
        }

        let ip = host.parse::<IpAddr>().ok()?;
        (self.allow_literal_loopback_http && ip.is_loopback()).then_some(TestDnsAnswer {
            addrs: vec![SocketAddr::new(ip, port)],
            allow_insecure_fixture: true,
        })
    }

    fn lookup_count(&self) -> usize {
        self.lookups.load(std::sync::atomic::Ordering::SeqCst)
    }
}

#[derive(Debug, Clone, Copy)]
struct ResourceLimits {
    max_conflict_dids: usize,
    max_pages_per_did: usize,
    max_records_per_did: usize,
    max_page_bytes: usize,
    max_aggregate_bytes_per_did: usize,
    max_cursor_bytes: usize,
    did_deadline: Duration,
    did_document_deadline: Duration,
    conflict_deadline: Duration,
    max_conflict_edges: usize,
    block_cache_capacity_bytes: u64,
    #[cfg(test)]
    cache_lookup_delay: Duration,
    #[cfg(test)]
    cache_insert_delay: Duration,
}

impl Default for ResourceLimits {
    fn default() -> Self {
        Self {
            max_conflict_dids: 100,
            max_pages_per_did: 100,
            max_records_per_did: 10_000,
            max_page_bytes: 256 * 1024,
            max_aggregate_bytes_per_did: 2 * 1024 * 1024,
            max_cursor_bytes: 4 * 1024,
            did_deadline: Duration::from_secs(20),
            did_document_deadline: Duration::from_secs(10),
            conflict_deadline: Duration::from_secs(30),
            max_conflict_edges: 10_000,
            block_cache_capacity_bytes: 64 * 1024 * 1024,
            #[cfg(test)]
            cache_lookup_delay: Duration::ZERO,
            #[cfg(test)]
            cache_insert_delay: Duration::ZERO,
        }
    }
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
    /// `$type` discriminator. Decoded for shape validation but not consulted
    /// by the BlockSync logic — the type is enforced via the listRecords URL.
    /// TODO(phase-2.5-cleanup): assert it equals `app.bsky.graph.block` or drop.
    #[serde(rename = "$type")]
    #[allow(dead_code)]
    record_type: Option<String>,
    subject: String,
    #[serde(rename = "createdAt")]
    created_at: Option<String>,
}

/// Block sync service for fetching and caching block data from PDSes
#[derive(Clone)]
pub struct BlockSyncService {
    /// Cache of DID -> PDS endpoint, TTL 5 minutes
    pds_cache: Cache<String, String>,
    /// Cache of DID -> Vec<BlockRecord>, TTL 1 minute (short for freshness)
    blocks_cache: Cache<String, Vec<BlockRecord>>,
    limits: ResourceLimits,
    #[cfg(test)]
    destination_fixture: Option<std::sync::Arc<TestDestinationFixture>>,
}

fn block_cache_entry_weight(did_capacity: usize, blocks: &[BlockRecord]) -> u32 {
    let retained_bytes = size_of::<String>()
        .saturating_add(did_capacity)
        .saturating_add(size_of::<Vec<BlockRecord>>())
        .saturating_add(blocks.iter().fold(0_usize, |total, block| {
            total
                .saturating_add(size_of::<BlockRecord>())
                .saturating_add(block.blocker_did.capacity())
                .saturating_add(block.blocked_did.capacity())
                .saturating_add(block.uri.capacity())
                .saturating_add(block.cid.capacity())
        }));

    u32::try_from(retained_bytes).unwrap_or(u32::MAX)
}

impl BlockSyncService {
    /// Create a new BlockSyncService
    pub fn new() -> Self {
        Self::with_limits(ResourceLimits::default())
    }

    fn with_limits(limits: ResourceLimits) -> Self {
        Self {
            pds_cache: Cache::builder()
                .time_to_live(Duration::from_secs(300)) // 5 minutes
                .max_capacity(10_000)
                .build(),
            blocks_cache: Cache::builder()
                .time_to_live(Duration::from_secs(60)) // 1 minute - short for freshness
                .max_capacity(limits.block_cache_capacity_bytes)
                .weigher(|did: &String, blocks: &Vec<BlockRecord>| {
                    block_cache_entry_weight(did.capacity(), blocks)
                })
                .build(),
            limits,
            #[cfg(test)]
            destination_fixture: None,
        }
    }

    #[cfg(test)]
    fn with_limits_for_test(limits: ResourceLimits) -> Self {
        Self::with_limits(limits)
    }

    #[cfg(test)]
    fn with_test_destination_fixture(
        limits: ResourceLimits,
        fixture: std::sync::Arc<TestDestinationFixture>,
    ) -> Self {
        let mut service = Self::with_limits(limits);
        service.destination_fixture = Some(fixture);
        service
    }

    fn ipv4_is_global(ip: Ipv4Addr) -> bool {
        let octets = ip.octets();
        !(octets[0] == 0
            || octets[0] == 10
            || octets[0] == 127
            || (octets[0] == 100 && (64..=127).contains(&octets[1]))
            || (octets[0] == 169 && octets[1] == 254)
            || (octets[0] == 172 && (16..=31).contains(&octets[1]))
            || (octets[0] == 192
                && octets[1] == 0
                && octets[2] == 0
                && octets[3] != 9
                && octets[3] != 10)
            || (octets[0] == 192 && octets[1] == 0 && octets[2] == 2)
            || (octets[0] == 192 && octets[1] == 88 && octets[2] == 99)
            || (octets[0] == 192 && octets[1] == 168)
            || (octets[0] == 198 && (octets[1] == 18 || octets[1] == 19))
            || (octets[0] == 198 && octets[1] == 51 && octets[2] == 100)
            || (octets[0] == 203 && octets[1] == 0 && octets[2] == 113)
            || octets[0] >= 224)
    }

    fn ipv6_is_global(ip: Ipv6Addr) -> bool {
        let segments = ip.segments();
        let numeric = u128::from_be_bytes(ip.octets());
        if matches!(segments, [0x64, 0xff9b, 0, 0, 0, 0, _, _]) {
            let embedded = Ipv4Addr::new(
                (segments[6] >> 8) as u8,
                segments[6] as u8,
                (segments[7] >> 8) as u8,
                segments[7] as u8,
            );
            return Self::ipv4_is_global(embedded);
        }
        !(ip.is_unspecified()
            || ip.is_loopback()
            || ip.is_multicast()
            || ip.is_unicast_link_local()
            || matches!(segments, [0, 0, 0, 0, 0, 0, _, _])
            || matches!(segments, [0, 0, 0, 0, 0, 0xffff, _, _])
            || matches!(segments, [0x64, 0xff9b, 1, _, _, _, _, _])
            || (segments[0] & 0xfe00) == 0xfc00
            || (segments[0] & 0xffc0) == 0xfec0
            || matches!(segments, [0x0100, 0, 0, 0, _, _, _, _])
            || matches!(segments, [0x0100, 0, 0, 1, _, _, _, _])
            || (matches!(segments, [0x2001, second, _, _, _, _, _, _] if second < 0x0200)
                && !(numeric == 0x2001_0001_0000_0000_0000_0000_0000_0001
                    || numeric == 0x2001_0001_0000_0000_0000_0000_0000_0002
                    || numeric == 0x2001_0001_0000_0000_0000_0000_0000_0003
                    || matches!(segments, [0x2001, 3, _, _, _, _, _, _])
                    || matches!(segments, [0x2001, 4, 0x0112, _, _, _, _, _])
                    || matches!(segments, [0x2001, second, _, _, _, _, _, _]
                        if (0x20..=0x3f).contains(&second))))
            || matches!(segments, [0x2002, _, _, _, _, _, _, _])
            || matches!(segments, [0x2001, 0x0db8, ..])
            || matches!(segments, [0x3fff, second, ..] if second <= 0x0fff)
            || matches!(segments, [0x5f00, ..]))
    }

    fn ip_is_global(ip: IpAddr) -> bool {
        match ip {
            IpAddr::V4(ip) => Self::ipv4_is_global(ip),
            IpAddr::V6(ip) => Self::ipv6_is_global(ip),
        }
    }

    async fn validate_destination(
        &self,
        raw_url: &str,
    ) -> Result<ValidatedDestination, BlockSyncError> {
        let url = Url::parse(raw_url)
            .map_err(|error| BlockSyncError::UnsafeDestination(error.to_string()))?;
        #[cfg(test)]
        let mut url = url;
        let host = url
            .host_str()
            .filter(|host| !host.is_empty())
            .ok_or_else(|| BlockSyncError::UnsafeDestination("URL has no host".into()))?
            .to_string();
        if host.eq_ignore_ascii_case("localhost")
            || host.to_ascii_lowercase().ends_with(".localhost")
        {
            return Err(BlockSyncError::UnsafeDestination(
                "localhost names are not allowed".into(),
            ));
        }
        if !url.username().is_empty() || url.password().is_some() {
            return Err(BlockSyncError::UnsafeDestination(
                "URL userinfo is not allowed".into(),
            ));
        }
        let port = url.port_or_known_default().ok_or_else(|| {
            BlockSyncError::UnsafeDestination("URL has no valid transport port".into())
        })?;

        #[cfg(test)]
        if let Some(fixture) = &self.destination_fixture {
            tokio::time::sleep(fixture.validation_delay).await;
        }

        #[cfg(test)]
        let fixture_answer = self
            .destination_fixture
            .as_ref()
            .and_then(|fixture| fixture.resolve(&host, port));
        #[cfg(test)]
        let allow_insecure_fixture = fixture_answer
            .as_ref()
            .is_some_and(|answer| answer.allow_insecure_fixture);
        #[cfg(not(test))]
        let allow_insecure_fixture = false;

        // Local HTTP exists only as a same-address test transport. Production
        // builds do not have a fixture field or this rewrite path.
        #[cfg(test)]
        if allow_insecure_fixture && url.scheme() == "https" {
            url.set_scheme("http")
                .expect("HTTP is a valid fixture URL scheme");
        }

        if url.scheme() != "https" && !allow_insecure_fixture {
            return Err(BlockSyncError::UnsafeDestination(
                "only HTTPS destinations are allowed".into(),
            ));
        }

        #[cfg(test)]
        let addrs = if let Some(answer) = fixture_answer {
            answer.addrs
        } else {
            Self::resolve_system_host(&host, port).await?
        };
        #[cfg(not(test))]
        let addrs = Self::resolve_system_host(&host, port).await?;

        if addrs.is_empty() {
            return Err(BlockSyncError::UnsafeDestination(
                "DNS returned no addresses".into(),
            ));
        }
        if !allow_insecure_fixture {
            if let Some(forbidden) = addrs.iter().find(|addr| !Self::ip_is_global(addr.ip())) {
                return Err(BlockSyncError::UnsafeDestination(format!(
                    "destination resolved to non-global address {}",
                    forbidden.ip()
                )));
            }
        }

        Ok(ValidatedDestination { url, host, addrs })
    }

    async fn resolve_system_host(host: &str, port: u16) -> Result<Vec<SocketAddr>, BlockSyncError> {
        let mut addrs = tokio::net::lookup_host((host, port))
            .await
            .map_err(|error| BlockSyncError::UnsafeDestination(error.to_string()))?
            .collect::<Vec<_>>();
        addrs.sort_unstable();
        addrs.dedup();
        Ok(addrs)
    }

    async fn send_validated(&self, raw_url: &str) -> Result<Response, BlockSyncError> {
        let destination = self.validate_destination(raw_url).await?;
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(10))
            .user_agent("Catbird-MLS/1.0")
            .no_proxy()
            .redirect(Policy::none())
            .resolve_to_addrs(&destination.host, &destination.addrs)
            .build()
            .map_err(|error| BlockSyncError::HttpError(error.to_string()))?;
        let response = client
            .get(destination.url)
            .send()
            .await
            .map_err(|error| BlockSyncError::HttpError(error.to_string()))?;
        if response.status().is_redirection() {
            return Err(BlockSyncError::RedirectRejected {
                status: response.status(),
            });
        }
        Ok(response)
    }

    async fn send_did_request_before(
        &self,
        raw_url: &str,
        deadline: tokio::time::Instant,
    ) -> Result<Response, BlockSyncError> {
        let destination = tokio::time::timeout_at(deadline, self.validate_destination(raw_url))
            .await
            .map_err(|_| BlockSyncError::DeadlineExceeded {
                operation: "did_resolution",
            })??;
        let client = reqwest::Client::builder()
            .user_agent("Catbird-MLS/1.0")
            .no_proxy()
            .redirect(Policy::none())
            .resolve_to_addrs(&destination.host, &destination.addrs)
            .build()
            .map_err(|_| BlockSyncError::HttpError("DID resolver client setup failed".into()))?;
        let response = tokio::time::timeout_at(deadline, client.get(destination.url).send())
            .await
            .map_err(|_| BlockSyncError::DeadlineExceeded {
                operation: "did_resolution",
            })?
            .map_err(|error| {
                if error.is_timeout() {
                    BlockSyncError::DeadlineExceeded {
                        operation: "did_resolution",
                    }
                } else {
                    BlockSyncError::HttpError("DID resolver request failed".into())
                }
            })?;
        if response.status().is_redirection() {
            return Err(BlockSyncError::RedirectRejected {
                status: response.status(),
            });
        }
        Ok(response)
    }

    fn map_did_body_error(error: OutboundBodyError) -> BlockSyncError {
        match error {
            OutboundBodyError::DeclaredTooLarge { .. }
            | OutboundBodyError::StreamedTooLarge { .. }
            | OutboundBodyError::LengthOverflow => {
                BlockSyncError::ParseError("DID document response exceeded size limit".into())
            }
            OutboundBodyError::DeadlineExceeded => BlockSyncError::DeadlineExceeded {
                operation: "did_resolution",
            },
            OutboundBodyError::ReadFailed(source) if source.is_timeout() => {
                BlockSyncError::DeadlineExceeded {
                    operation: "did_resolution",
                }
            }
            OutboundBodyError::ReadFailed(_) => {
                BlockSyncError::HttpError("DID document response body read failed".into())
            }
            OutboundBodyError::InvalidJson(_) => {
                BlockSyncError::ParseError("DID document response JSON was invalid".into())
            }
        }
    }

    fn resource_limit(resource: &'static str, limit: usize) -> BlockSyncError {
        BlockSyncError::ResourceLimitExceeded { resource, limit }
    }

    async fn before_blocks_cache_lookup(&self) {
        #[cfg(test)]
        tokio::time::sleep(self.limits.cache_lookup_delay).await;
        #[cfg(not(test))]
        let _ = self;
    }

    async fn before_blocks_cache_insert(&self) {
        #[cfg(test)]
        tokio::time::sleep(self.limits.cache_insert_delay).await;
        #[cfg(not(test))]
        let _ = self;
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

        // Cache admission is conditional on the same destination policy used by
        // every actual request. The request itself resolves again and pins that
        // fresh answer set to its connection, closing admission/use rebinding.
        self.validate_destination(&endpoint).await?;

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
            did_web_document_url(did).ok_or_else(|| BlockSyncError::InvalidDid(did.to_string()))?
        } else {
            return Err(BlockSyncError::InvalidDid(format!(
                "Unsupported DID method: {}",
                did
            )));
        };

        let deadline = tokio::time::Instant::now()
            .checked_add(self.limits.did_document_deadline)
            .ok_or(BlockSyncError::DeadlineExceeded {
                operation: "did_resolution",
            })?;
        let response = self.send_did_request_before(&url, deadline).await?;

        if !response.status().is_success() {
            return Err(BlockSyncError::DidResolutionFailed(format!(
                "HTTP {} from DID resolver",
                response.status()
            )));
        }

        decode_json_bounded(
            response,
            ResponseBodyBudget::new(DID_DOCUMENT_MAX_BYTES, deadline),
        )
        .await
        .map_err(Self::map_did_body_error)
    }

    /// Fetch all block records for a user from their PDS
    ///
    /// This calls com.atproto.repo.listRecords with collection="app.bsky.graph.block"
    /// and paginates through all results.
    pub async fn fetch_blocks_from_pds(
        &self,
        did: &str,
    ) -> Result<Vec<BlockRecord>, BlockSyncError> {
        tokio::time::timeout(self.limits.did_deadline, self.fetch_blocks_with_cache(did))
            .await
            .map_err(|_| BlockSyncError::DeadlineExceeded {
                operation: "did_fetch",
            })?
    }

    async fn fetch_blocks_with_cache(&self, did: &str) -> Result<Vec<BlockRecord>, BlockSyncError> {
        self.before_blocks_cache_lookup().await;
        // Check cache first
        if let Some(blocks) = self.blocks_cache.get(did).await {
            debug!(
                "Blocks cache hit for {} ({} blocks)",
                crate::crypto::redact_for_log(did),
                blocks.len()
            );
            return Ok(blocks);
        }

        let blocks = self.fetch_blocks_uncached(did).await?;

        self.before_blocks_cache_insert().await;
        self.blocks_cache
            .insert(did.to_string(), blocks.clone())
            .await;

        Ok(blocks)
    }

    async fn fetch_blocks_uncached(&self, did: &str) -> Result<Vec<BlockRecord>, BlockSyncError> {
        let pds_endpoint = self.get_pds_endpoint(did).await?;
        let mut all_blocks = Vec::new();
        let mut cursor: Option<String> = None;
        let mut seen_cursors = HashSet::new();
        let mut pages = 0_usize;
        let mut aggregate_bytes = 0_usize;

        loop {
            if pages >= self.limits.max_pages_per_did {
                return Err(Self::resource_limit(
                    "pages_per_did",
                    self.limits.max_pages_per_did,
                ));
            }

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

            let mut response = self.send_validated(&url).await?;

            if !response.status().is_success() {
                // Preserve the existing compatibility rule that a 400 means the
                // block collection is absent. Discard any rows accumulated from
                // earlier pages so a partial projection is never returned or cached.
                if response.status() == reqwest::StatusCode::BAD_REQUEST {
                    debug!(
                        "No block records found for {}",
                        crate::crypto::redact_for_log(did)
                    );
                    all_blocks.clear();
                    break;
                }
                return Err(BlockSyncError::HttpError(format!(
                    "PDS returned HTTP {}",
                    response.status()
                )));
            }

            if response
                .content_length()
                .is_some_and(|length| length > self.limits.max_page_bytes as u64)
            {
                return Err(Self::resource_limit(
                    "page_bytes",
                    self.limits.max_page_bytes,
                ));
            }

            if response.content_length().is_some_and(|length| {
                length
                    > self
                        .limits
                        .max_aggregate_bytes_per_did
                        .saturating_sub(aggregate_bytes) as u64
            }) {
                return Err(Self::resource_limit(
                    "aggregate_bytes_per_did",
                    self.limits.max_aggregate_bytes_per_did,
                ));
            }

            let mut page_bytes = Vec::new();
            while let Some(chunk) = response
                .chunk()
                .await
                .map_err(|e| BlockSyncError::HttpError(e.to_string()))?
            {
                let next_page_bytes = page_bytes.len().saturating_add(chunk.len());
                if next_page_bytes > self.limits.max_page_bytes {
                    return Err(Self::resource_limit(
                        "page_bytes",
                        self.limits.max_page_bytes,
                    ));
                }

                let next_aggregate_bytes = aggregate_bytes.saturating_add(chunk.len());
                if next_aggregate_bytes > self.limits.max_aggregate_bytes_per_did {
                    return Err(Self::resource_limit(
                        "aggregate_bytes_per_did",
                        self.limits.max_aggregate_bytes_per_did,
                    ));
                }

                page_bytes.extend_from_slice(&chunk);
                aggregate_bytes = next_aggregate_bytes;
            }

            let list_response: ListRecordsResponse = serde_json::from_slice(&page_bytes)
                .map_err(|e| BlockSyncError::ParseError(e.to_string()))?;

            pages = pages.saturating_add(1);
            if list_response.records.len()
                > self
                    .limits
                    .max_records_per_did
                    .saturating_sub(all_blocks.len())
            {
                return Err(Self::resource_limit(
                    "records_per_did",
                    self.limits.max_records_per_did,
                ));
            }

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

            match list_response.cursor {
                Some(next_cursor) => {
                    if next_cursor.len() > self.limits.max_cursor_bytes {
                        return Err(Self::resource_limit(
                            "cursor_bytes",
                            self.limits.max_cursor_bytes,
                        ));
                    }
                    if !seen_cursors.insert(next_cursor.clone()) {
                        return Err(Self::resource_limit(
                            "cursor_cycle",
                            self.limits.max_pages_per_did,
                        ));
                    }
                    if pages >= self.limits.max_pages_per_did {
                        return Err(Self::resource_limit(
                            "pages_per_did",
                            self.limits.max_pages_per_did,
                        ));
                    }
                    cursor = Some(next_cursor);
                }
                None => break,
            }
        }

        info!(
            "Fetched {} blocks from PDS for {}",
            all_blocks.len(),
            crate::crypto::redact_for_log(did)
        );

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
        if dids.len() > self.limits.max_conflict_dids {
            return Err(Self::resource_limit(
                "conflict_dids",
                self.limits.max_conflict_dids,
            ));
        }

        tokio::time::timeout(self.limits.conflict_deadline, async {
            let mut conflicts = Vec::new();

            for did in dids {
                let blocks = self.fetch_blocks_from_pds(did).await?;
                for block in blocks {
                    if dids.contains(&block.blocked_did) {
                        if conflicts.len() >= self.limits.max_conflict_edges {
                            return Err(Self::resource_limit(
                                "conflict_edges",
                                self.limits.max_conflict_edges,
                            ));
                        }
                        conflicts.push((block.blocker_did, block.blocked_did));
                    }
                }
            }

            Ok(conflicts)
        })
        .await
        .map_err(|_| BlockSyncError::DeadlineExceeded {
            operation: "conflict_check",
        })?
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
            .bind(now)
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

    /// Invalidate cached blocks for a user (call after block/unblock events)
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
    use axum::{
        body::Body,
        extract::Query,
        http::{Response, StatusCode},
        response::IntoResponse,
        routing::get,
        Json, Router,
    };
    use bytes::Bytes;
    use futures::stream;
    use serde_json::{json, Value};
    use std::{
        collections::HashMap,
        convert::Infallible,
        sync::{
            atomic::{AtomicUsize, Ordering},
            Arc,
        },
    };
    use tokio::net::TcpListener;

    fn test_limits() -> ResourceLimits {
        ResourceLimits {
            max_conflict_dids: 100,
            max_pages_per_did: 3,
            max_records_per_did: 10,
            max_page_bytes: 4 * 1024,
            max_aggregate_bytes_per_did: 8 * 1024,
            max_cursor_bytes: 32,
            did_deadline: Duration::from_secs(2),
            did_document_deadline: Duration::from_secs(10),
            conflict_deadline: Duration::from_secs(3),
            max_conflict_edges: 10,
            block_cache_capacity_bytes: 64 * 1024 * 1024,
            cache_lookup_delay: Duration::ZERO,
            cache_insert_delay: Duration::ZERO,
        }
    }

    fn record(subject: &str, suffix: usize) -> Value {
        json!({
            "uri": format!("at://did:example:alice/app.bsky.graph.block/{suffix}"),
            "cid": format!("cid-{suffix}"),
            "value": {
                "$type": "app.bsky.graph.block",
                "subject": subject,
                "createdAt": "2026-07-15T00:00:00Z"
            }
        })
    }

    fn page(records: Vec<Value>, cursor: Option<String>) -> Response<Body> {
        Json(json!({ "records": records, "cursor": cursor })).into_response()
    }

    async fn spawn_pds(router: Router) -> String {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, router).await.unwrap();
        });
        format!("http://{address}")
    }

    fn did_document(did: &str, endpoint: &str) -> Vec<u8> {
        serde_json::to_vec(&json!({
            "id": did,
            "service": [{
                "id": "#atproto_pds",
                "type": "AtprotoPersonalDataServer",
                "serviceEndpoint": endpoint
            }]
        }))
        .unwrap()
    }

    fn did_web_service_for_endpoint(
        local_endpoint: &str,
        host: &str,
    ) -> (BlockSyncService, String) {
        let answer = fixture_answer(local_endpoint, true);
        let fixture = TestDestinationFixture::with_answers([(
            host.to_string(),
            vec![answer.clone(), answer],
        )]);
        let service = BlockSyncService::with_test_destination_fixture(test_limits(), fixture);
        let port = Url::parse(local_endpoint).unwrap().port().unwrap();
        (service, format!("did:web:{host}%3A{port}"))
    }

    async fn did_web_service(router: Router, host: &str) -> (BlockSyncService, String) {
        let local_endpoint = spawn_pds(router).await;
        did_web_service_for_endpoint(&local_endpoint, host)
    }

    async fn service_for_pds(
        dids: &[&str],
        endpoint: &str,
        limits: ResourceLimits,
    ) -> BlockSyncService {
        let service = BlockSyncService::with_test_destination_fixture(
            limits,
            TestDestinationFixture::local_http(),
        );
        for did in dids {
            service
                .pds_cache
                .insert((*did).to_string(), endpoint.to_string())
                .await;
        }
        service
    }

    fn assert_resource_limit(error: BlockSyncError, expected_resource: &'static str) {
        assert!(
            matches!(
                error,
                BlockSyncError::ResourceLimitExceeded { resource, .. }
                    if resource == expected_resource
            ),
            "expected {expected_resource} resource limit, got {error:?}"
        );
    }

    fn fixture_answer(endpoint: &str, allow_insecure_fixture: bool) -> TestDnsAnswer {
        let url = Url::parse(endpoint).unwrap();
        let ip = url.host_str().unwrap().parse::<IpAddr>().unwrap();
        TestDnsAnswer {
            addrs: vec![SocketAddr::new(ip, url.port_or_known_default().unwrap())],
            allow_insecure_fixture,
        }
    }

    fn fixture_endpoint(endpoint: &str, host: &str) -> String {
        let url = Url::parse(endpoint).unwrap();
        format!("http://{host}:{}", url.port().unwrap())
    }

    #[test]
    fn outbound_policy_rejects_all_non_global_address_classes() {
        let forbidden = [
            "0.0.0.0",
            "10.0.0.1",
            "100.64.0.1",
            "127.0.0.1",
            "169.254.169.254",
            "172.16.0.1",
            "192.0.0.1",
            "192.0.2.1",
            "192.88.99.1",
            "192.168.0.1",
            "198.18.0.1",
            "198.51.100.1",
            "203.0.113.1",
            "224.0.0.1",
            "255.255.255.255",
            "::",
            "::1",
            "::8.8.8.8",
            "::ffff:8.8.8.8",
            "64:ff9b::127.0.0.1",
            "64:ff9b:1::1",
            "100::1",
            "100:0:0:1::1",
            "2001::1",
            "2001:2::1",
            "2001:db8::1",
            "2002::1",
            "3fff::1",
            "5f00::1",
            "fc00::1",
            "fec0::1",
            "fe80::1",
            "ff02::1",
        ];
        for raw_ip in forbidden {
            let ip = raw_ip.parse::<IpAddr>().unwrap();
            assert!(!BlockSyncService::ip_is_global(ip), "accepted {raw_ip}");
        }

        for raw_ip in [
            "8.8.8.8",
            "1.1.1.1",
            "64:ff9b::8.8.8.8",
            "2001:1::3",
            "2001:4860:4860::8888",
        ] {
            let ip = raw_ip.parse::<IpAddr>().unwrap();
            assert!(BlockSyncService::ip_is_global(ip), "rejected {raw_ip}");
        }
    }

    #[tokio::test]
    async fn outbound_policy_rejects_invalid_url_forms_and_localhost() {
        let service = BlockSyncService::with_limits_for_test(test_limits());
        for url in [
            "http://example.com/path",
            "https://user@example.com/path",
            "https://user:password@example.com/path",
            "https://example.com:invalid/path",
            "https:///hostless",
            "https://127.0.0.1/path",
            "https://[::1]/path",
            "https://169.254.169.254/latest/meta-data",
            "https://localhost/path",
        ] {
            let error = service.validate_destination(url).await.unwrap_err();
            assert!(
                matches!(error, BlockSyncError::UnsafeDestination(_)),
                "accepted {url}: {error:?}"
            );
        }
    }

    #[tokio::test]
    async fn localhost_names_are_rejected_before_dns_even_if_resolver_claims_public() {
        let fixture = TestDestinationFixture::with_answers([(
            "attacker.localhost".into(),
            vec![TestDnsAnswer {
                addrs: vec!["93.184.216.34:443".parse().unwrap()],
                allow_insecure_fixture: false,
            }],
        )]);
        let service =
            BlockSyncService::with_test_destination_fixture(test_limits(), fixture.clone());

        let error = service
            .validate_destination("https://attacker.localhost/path")
            .await
            .unwrap_err();

        assert!(matches!(error, BlockSyncError::UnsafeDestination(_)));
        assert_eq!(fixture.lookup_count(), 0);
    }

    #[tokio::test]
    async fn mixed_public_private_answers_are_rejected_before_connection() {
        let fixture = TestDestinationFixture::with_answers([(
            "mixed.test".into(),
            vec![TestDnsAnswer {
                addrs: vec![
                    "93.184.216.34:443".parse().unwrap(),
                    "127.0.0.1:443".parse().unwrap(),
                ],
                allow_insecure_fixture: false,
            }],
        )]);
        let service =
            BlockSyncService::with_test_destination_fixture(test_limits(), fixture.clone());
        service
            .pds_cache
            .insert("did:example:alice".into(), "https://mixed.test".into())
            .await;

        let error = service
            .fetch_blocks_from_pds("did:example:alice")
            .await
            .unwrap_err();

        assert!(matches!(error, BlockSyncError::UnsafeDestination(_)));
        assert_eq!(fixture.lookup_count(), 1);
        assert!(service
            .blocks_cache
            .get("did:example:alice")
            .await
            .is_none());
    }

    #[tokio::test]
    async fn validated_addresses_are_pinned_to_connection_without_second_lookup() {
        let router = Router::new().route(
            "/xrpc/com.atproto.repo.listRecords",
            get(|| async { page(Vec::new(), None) }),
        );
        let local_endpoint = spawn_pds(router).await;
        let fixture = TestDestinationFixture::with_answers([(
            "fixture.test".into(),
            vec![fixture_answer(&local_endpoint, true)],
        )]);
        let service =
            BlockSyncService::with_test_destination_fixture(test_limits(), fixture.clone());
        service
            .pds_cache
            .insert(
                "did:example:alice".into(),
                fixture_endpoint(&local_endpoint, "fixture.test"),
            )
            .await;

        let blocks = service
            .fetch_blocks_from_pds("did:example:alice")
            .await
            .unwrap();

        assert!(blocks.is_empty());
        assert_eq!(fixture.lookup_count(), 1);
    }

    #[tokio::test]
    async fn hostile_proxy_environment_cannot_bypass_validated_addresses() {
        if std::env::var_os("BLOCK_SYNC_HOSTILE_PROXY_CHILD").is_some() {
            let target_endpoint =
                std::env::var("BLOCK_SYNC_HOSTILE_PROXY_TARGET").expect("target endpoint");
            let fixture = TestDestinationFixture::with_answers([(
                "proxy-bypass.test".into(),
                vec![fixture_answer(&target_endpoint, true)],
            )]);
            let service =
                BlockSyncService::with_test_destination_fixture(test_limits(), fixture.clone());
            service
                .pds_cache
                .insert(
                    "did:example:alice".into(),
                    fixture_endpoint(&target_endpoint, "proxy-bypass.test"),
                )
                .await;

            let blocks = service
                .fetch_blocks_from_pds("did:example:alice")
                .await
                .unwrap();

            assert!(blocks.is_empty());
            assert_eq!(fixture.lookup_count(), 1);
            return;
        }

        let target_requests = Arc::new(AtomicUsize::new(0));
        let target_counter = target_requests.clone();
        let target = spawn_pds(Router::new().fallback(get(move || {
            let target_counter = target_counter.clone();
            async move {
                target_counter.fetch_add(1, Ordering::SeqCst);
                page(Vec::new(), None)
            }
        })))
        .await;

        let proxy_requests = Arc::new(AtomicUsize::new(0));
        let proxy_counter = proxy_requests.clone();
        let proxy = spawn_pds(Router::new().fallback(get(move || {
            let proxy_counter = proxy_counter.clone();
            async move {
                proxy_counter.fetch_add(1, Ordering::SeqCst);
                page(Vec::new(), None)
            }
        })))
        .await;

        // Proxy variables are mutated only in a subprocess. That keeps this
        // regression deterministic when the rest of the test binary runs in
        // parallel and avoids unsafe process-global environment mutation.
        let output = tokio::process::Command::new(std::env::current_exe().unwrap())
            .arg("--exact")
            .arg("block_sync::tests::hostile_proxy_environment_cannot_bypass_validated_addresses")
            .arg("--nocapture")
            .arg("--test-threads=1")
            .env("BLOCK_SYNC_HOSTILE_PROXY_CHILD", "1")
            .env("BLOCK_SYNC_HOSTILE_PROXY_TARGET", &target)
            .env("HTTP_PROXY", &proxy)
            .env("HTTPS_PROXY", &proxy)
            .env("ALL_PROXY", &proxy)
            .env("http_proxy", &proxy)
            .env("https_proxy", &proxy)
            .env("all_proxy", &proxy)
            .env("NO_PROXY", "")
            .env("no_proxy", "")
            .env_remove("REQUEST_METHOD")
            .output()
            .await
            .unwrap();

        assert!(
            output.status.success(),
            "child failed:\nstdout:\n{}\nstderr:\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        assert_eq!(proxy_requests.load(Ordering::SeqCst), 0);
        assert_eq!(target_requests.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn redirects_are_not_followed_or_cached() {
        let target_requests = Arc::new(AtomicUsize::new(0));
        let target_counter = target_requests.clone();
        let target = spawn_pds(Router::new().fallback(get(move || {
            let target_counter = target_counter.clone();
            async move {
                target_counter.fetch_add(1, Ordering::SeqCst);
                page(Vec::new(), None)
            }
        })))
        .await;
        let location = format!("{target}/private");
        let source = spawn_pds(Router::new().route(
            "/xrpc/com.atproto.repo.listRecords",
            get(move || {
                let location = location.clone();
                async move {
                    Response::builder()
                        .status(StatusCode::FOUND)
                        .header("location", location)
                        .body(Body::empty())
                        .unwrap()
                }
            }),
        ))
        .await;
        let service = service_for_pds(&["did:example:alice"], &source, test_limits()).await;

        let error = service
            .fetch_blocks_from_pds("did:example:alice")
            .await
            .unwrap_err();

        assert!(matches!(error, BlockSyncError::RedirectRejected { .. }));
        assert_eq!(target_requests.load(Ordering::SeqCst), 0);
        assert!(service
            .blocks_cache
            .get("did:example:alice")
            .await
            .is_none());
    }

    #[tokio::test]
    async fn cached_pds_is_revalidated_after_public_to_private_rebinding() {
        let fixture = TestDestinationFixture::with_answers([(
            "rebind.test".into(),
            vec![
                TestDnsAnswer {
                    addrs: vec!["93.184.216.34:443".parse().unwrap()],
                    allow_insecure_fixture: false,
                },
                TestDnsAnswer {
                    addrs: vec!["127.0.0.1:443".parse().unwrap()],
                    allow_insecure_fixture: false,
                },
            ],
        )]);
        let service =
            BlockSyncService::with_test_destination_fixture(test_limits(), fixture.clone());
        let endpoint = "https://rebind.test";
        service.validate_destination(endpoint).await.unwrap();
        service
            .pds_cache
            .insert("did:example:alice".into(), endpoint.into())
            .await;

        let error = service
            .fetch_blocks_from_pds("did:example:alice")
            .await
            .unwrap_err();

        assert!(matches!(error, BlockSyncError::UnsafeDestination(_)));
        assert_eq!(fixture.lookup_count(), 2);
        assert!(service
            .blocks_cache
            .get("did:example:alice")
            .await
            .is_none());
    }

    #[tokio::test]
    async fn every_pagination_request_gets_fresh_pinned_validation() {
        let router = Router::new().route(
            "/xrpc/com.atproto.repo.listRecords",
            get(|Query(query): Query<HashMap<String, String>>| async move {
                page(
                    Vec::new(),
                    (!query.contains_key("cursor")).then(|| "next".into()),
                )
            }),
        );
        let local_endpoint = spawn_pds(router).await;
        let answer = fixture_answer(&local_endpoint, true);
        let fixture = TestDestinationFixture::with_answers([(
            "pages.test".into(),
            vec![answer.clone(), answer],
        )]);
        let service =
            BlockSyncService::with_test_destination_fixture(test_limits(), fixture.clone());
        service
            .pds_cache
            .insert(
                "did:example:alice".into(),
                fixture_endpoint(&local_endpoint, "pages.test"),
            )
            .await;

        service
            .fetch_blocks_from_pds("did:example:alice")
            .await
            .unwrap();

        assert_eq!(fixture.lookup_count(), 2);
    }

    #[tokio::test]
    async fn did_document_fetch_uses_same_pinned_policy_and_preserves_valid_parsing() {
        let router = Router::new().route(
            concat!("/.well-known/", "did.json"),
            get(|| async {
                Json(json!({
                    "id": "did:web:fixture.test",
                    "service": [{
                        "id": "#atproto_pds",
                        "type": "AtprotoPersonalDataServer",
                        "serviceEndpoint": "https://fixture.test"
                    }]
                }))
            }),
        );
        let local_endpoint = spawn_pds(router).await;
        let answer = fixture_answer(&local_endpoint, true);
        let fixture = TestDestinationFixture::with_answers([(
            "fixture.test".into(),
            vec![answer.clone(), answer],
        )]);
        let service =
            BlockSyncService::with_test_destination_fixture(test_limits(), fixture.clone());
        let port = Url::parse(&local_endpoint).unwrap().port().unwrap();

        let endpoint = service
            .get_pds_endpoint(&format!("did:web:fixture.test%3A{port}"))
            .await
            .unwrap();

        assert_eq!(endpoint, "https://fixture.test");
        assert_eq!(fixture.lookup_count(), 2);
    }

    #[tokio::test]
    async fn did_document_mixed_answers_fail_before_request_or_pds_cache_admission() {
        let fixture = TestDestinationFixture::with_answers([(
            "mixed-did.test".into(),
            vec![TestDnsAnswer {
                addrs: vec![
                    "93.184.216.34:443".parse().unwrap(),
                    "127.0.0.1:443".parse().unwrap(),
                ],
                allow_insecure_fixture: false,
            }],
        )]);
        let service =
            BlockSyncService::with_test_destination_fixture(test_limits(), fixture.clone());
        let did = "did:web:mixed-did.test";

        let error = service.get_pds_endpoint(did).await.unwrap_err();

        assert!(matches!(error, BlockSyncError::UnsafeDestination(_)));
        assert_eq!(fixture.lookup_count(), 1);
        assert!(service.pds_cache.get(did).await.is_none());
    }

    #[tokio::test]
    async fn bounded_plc_and_web_documents_admit_the_pds_endpoint() {
        let endpoint = "https://pds.test";
        let body = did_document("did:plc:bounded", endpoint);
        let router = Router::new().fallback(get(move || {
            let body = body.clone();
            async move {
                Response::builder()
                    .status(StatusCode::OK)
                    .body(Body::from(body))
                    .unwrap()
            }
        }));
        let local_endpoint = spawn_pds(router).await;
        let answer = fixture_answer(&local_endpoint, true);
        let fixture = TestDestinationFixture::with_answers([
            ("plc.directory".into(), vec![answer.clone()]),
            ("bounded-web.test".into(), vec![answer.clone()]),
            ("pds.test".into(), vec![answer]),
        ]);
        let service = BlockSyncService::with_test_destination_fixture(test_limits(), fixture);
        let port = Url::parse(&local_endpoint).unwrap().port().unwrap();
        let web_did = format!("did:web:bounded-web.test%3A{port}");

        assert_eq!(
            service.get_pds_endpoint("did:plc:bounded").await.unwrap(),
            endpoint
        );
        assert_eq!(service.get_pds_endpoint(&web_did).await.unwrap(), endpoint);
        assert_eq!(
            service.pds_cache.get("did:plc:bounded").await.as_deref(),
            Some(endpoint)
        );
        assert_eq!(
            service.pds_cache.get(&web_did).await.as_deref(),
            Some(endpoint)
        );
    }

    #[tokio::test]
    async fn declared_oversize_did_document_is_rejected_before_cache_admission() {
        let oversized = vec![b'x'; crate::util::outbound_body::DID_DOCUMENT_MAX_BYTES + 1];
        let router = Router::new().fallback(get(move || {
            let oversized = oversized.clone();
            async move {
                Response::builder()
                    .status(StatusCode::OK)
                    .header("content-length", oversized.len())
                    .body(Body::from(oversized))
                    .unwrap()
            }
        }));
        let (service, did) = did_web_service(router, "declared-did.test").await;

        let error = service.get_pds_endpoint(&did).await.unwrap_err();

        assert!(matches!(error, BlockSyncError::ParseError(_)));
        assert_eq!(
            error.to_string(),
            "Failed to parse response: DID document response exceeded size limit"
        );
        assert!(service.pds_cache.get(&did).await.is_none());
    }

    #[tokio::test]
    async fn chunked_oversize_did_document_is_rejected_before_cache_admission() {
        let router = Router::new().fallback(get(|| async {
            let chunks = vec![
                Ok::<_, Infallible>(Bytes::from(vec![
                    b'x';
                    crate::util::outbound_body::DID_DOCUMENT_MAX_BYTES
                ])),
                Ok::<_, Infallible>(Bytes::from_static(b"x")),
            ];
            Response::builder()
                .status(StatusCode::OK)
                .body(Body::from_stream(stream::iter(chunks)))
                .unwrap()
        }));
        let (service, did) = did_web_service(router, "chunked-did.test").await;

        let error = service.get_pds_endpoint(&did).await.unwrap_err();

        assert!(matches!(error, BlockSyncError::ParseError(_)));
        assert_eq!(
            error.to_string(),
            "Failed to parse response: DID document response exceeded size limit"
        );
        assert!(service.pds_cache.get(&did).await.is_none());
    }

    #[tokio::test]
    async fn malformed_did_document_diagnostics_are_content_free_and_not_cached() {
        let body_canary = "BODY_SECRET_CANARY";
        let router = Router::new().fallback(get(move || async move {
            Response::builder()
                .status(StatusCode::OK)
                .body(Body::from(format!("{{not-json:{body_canary}")))
                .unwrap()
        }));
        let (service, did) = did_web_service(router, "diagnostic-did.test").await;

        let error = service.get_pds_endpoint(&did).await.unwrap_err();
        let diagnostic = format!("{error} {error:?}");

        assert!(!diagnostic.contains(body_canary), "{diagnostic}");
        assert!(!diagnostic.contains(&did), "{diagnostic}");
        assert!(!diagnostic.contains("diagnostic-did.test"), "{diagnostic}");
        assert!(service.pds_cache.get(&did).await.is_none());
    }

    #[tokio::test]
    async fn truncated_did_body_failure_is_sanitized_and_not_cached() {
        use tokio::io::AsyncWriteExt;

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            socket
                .write_all(
                    b"HTTP/1.1 200 OK\r\nContent-Length: 1024\r\nConnection: close\r\n\r\ntruncated",
                )
                .await
                .unwrap();
        });
        let local_endpoint = format!("http://{address}");
        let (service, did) = did_web_service_for_endpoint(&local_endpoint, "transport-canary.test");

        let error = service.get_pds_endpoint(&did).await.unwrap_err();
        let diagnostic = format!("{error} {error:?}");

        assert_eq!(
            error.to_string(),
            "HTTP request failed: DID document response body read failed"
        );
        assert!(!diagnostic.contains(&did), "{diagnostic}");
        assert!(
            !diagnostic.contains("transport-canary.test"),
            "{diagnostic}"
        );
        assert!(service.pds_cache.get(&did).await.is_none());
    }

    #[tokio::test]
    async fn validation_headers_and_body_share_one_did_deadline() {
        let body = did_document("did:web:deadline.test", "https://pds.test");
        let router = Router::new().fallback(get(move || {
            let body = body.clone();
            async move {
                tokio::time::sleep(Duration::from_millis(40)).await;
                let stream = stream::once(async move {
                    tokio::time::sleep(Duration::from_millis(40)).await;
                    Ok::<_, Infallible>(Bytes::from(body))
                });
                Response::builder()
                    .status(StatusCode::OK)
                    .body(Body::from_stream(stream))
                    .unwrap()
            }
        }));
        let local_endpoint = spawn_pds(router).await;
        let answer = fixture_answer(&local_endpoint, true);
        let fixture = TestDestinationFixture::with_answers_and_delay(
            [("deadline.test".into(), vec![answer])],
            Duration::from_millis(40),
        );
        let mut limits = test_limits();
        limits.did_document_deadline = Duration::from_millis(90);
        let service = BlockSyncService::with_test_destination_fixture(limits, fixture);
        let port = Url::parse(&local_endpoint).unwrap().port().unwrap();
        let did = format!("did:web:deadline.test%3A{port}");

        let error = service.get_pds_endpoint(&did).await.unwrap_err();

        assert!(matches!(
            error,
            BlockSyncError::DeadlineExceeded {
                operation: "did_resolution"
            }
        ));
        assert!(service.pds_cache.get(&did).await.is_none());
    }

    #[tokio::test]
    async fn non_success_did_status_mapping_does_not_collect_body() {
        let router = Router::new().fallback(get(|| async {
            let chunks = stream::once(async {
                tokio::time::sleep(Duration::from_secs(1)).await;
                Ok::<_, Infallible>(Bytes::from_static(b"unused-secret-body"))
            });
            Response::builder()
                .status(StatusCode::NOT_FOUND)
                .body(Body::from_stream(chunks))
                .unwrap()
        }));
        let (service, did) = did_web_service(router, "status-did.test").await;
        let started = tokio::time::Instant::now();

        let error = service.get_pds_endpoint(&did).await.unwrap_err();

        assert_eq!(
            error.to_string(),
            "Failed to resolve DID: HTTP 404 Not Found from DID resolver"
        );
        assert!(started.elapsed() < Duration::from_millis(250));
        assert!(service.pds_cache.get(&did).await.is_none());
    }

    #[test]
    fn production_limits_match_frozen_task_card() {
        let limits = ResourceLimits::default();
        assert_eq!(limits.max_conflict_dids, 100);
        assert_eq!(limits.max_pages_per_did, 100);
        assert_eq!(limits.max_records_per_did, 10_000);
        assert_eq!(limits.max_page_bytes, 256 * 1024);
        assert_eq!(limits.max_aggregate_bytes_per_did, 2 * 1024 * 1024);
        assert_eq!(limits.max_cursor_bytes, 4 * 1024);
        assert_eq!(limits.did_deadline, Duration::from_secs(20));
        assert_eq!(limits.did_document_deadline, Duration::from_secs(10));
        assert_eq!(limits.conflict_deadline, Duration::from_secs(30));
        assert_eq!(limits.max_conflict_edges, 10_000);
        assert_eq!(limits.block_cache_capacity_bytes, 64 * 1024 * 1024);
    }

    #[tokio::test]
    async fn repeated_cursor_is_rejected_and_failed_fetch_is_not_cached() {
        let requests = Arc::new(AtomicUsize::new(0));
        let request_counter = requests.clone();
        let router = Router::new().route(
            "/xrpc/com.atproto.repo.listRecords",
            get(move || {
                let request_counter = request_counter.clone();
                async move {
                    let request = request_counter.fetch_add(1, Ordering::SeqCst);
                    page(
                        vec![record("did:example:bob", request)],
                        Some("same".into()),
                    )
                }
            }),
        );
        let endpoint = spawn_pds(router).await;
        let service = service_for_pds(&["did:example:alice"], &endpoint, test_limits()).await;

        let first = service
            .fetch_blocks_from_pds("did:example:alice")
            .await
            .unwrap_err();
        assert_resource_limit(first, "cursor_cycle");
        assert_eq!(requests.load(Ordering::SeqCst), 2);
        assert!(service
            .blocks_cache
            .get("did:example:alice")
            .await
            .is_none());

        let second = service
            .fetch_blocks_from_pds("did:example:alice")
            .await
            .unwrap_err();
        assert_resource_limit(second, "cursor_cycle");
        assert_eq!(requests.load(Ordering::SeqCst), 4);
    }

    #[tokio::test]
    async fn cyclic_cursor_sequence_is_rejected() {
        let requests = Arc::new(AtomicUsize::new(0));
        let request_counter = requests.clone();
        let router = Router::new().route(
            "/xrpc/com.atproto.repo.listRecords",
            get(move || {
                let request_counter = request_counter.clone();
                async move {
                    let request = request_counter.fetch_add(1, Ordering::SeqCst);
                    let cursor = ["a", "b", "a"][request.min(2)].to_string();
                    page(Vec::new(), Some(cursor))
                }
            }),
        );
        let endpoint = spawn_pds(router).await;
        let mut limits = test_limits();
        limits.max_pages_per_did = 5;
        let service = service_for_pds(&["did:example:alice"], &endpoint, limits).await;

        let error = service
            .fetch_blocks_from_pds("did:example:alice")
            .await
            .unwrap_err();
        assert_resource_limit(error, "cursor_cycle");
        assert_eq!(requests.load(Ordering::SeqCst), 3);
    }

    #[tokio::test]
    async fn fresh_cursors_stop_at_page_budget() {
        let requests = Arc::new(AtomicUsize::new(0));
        let request_counter = requests.clone();
        let router = Router::new().route(
            "/xrpc/com.atproto.repo.listRecords",
            get(move || {
                let request_counter = request_counter.clone();
                async move {
                    let request = request_counter.fetch_add(1, Ordering::SeqCst);
                    page(Vec::new(), Some(format!("cursor-{request}")))
                }
            }),
        );
        let endpoint = spawn_pds(router).await;
        let mut limits = test_limits();
        limits.max_pages_per_did = 2;
        let service = service_for_pds(&["did:example:alice"], &endpoint, limits).await;

        let error = service
            .fetch_blocks_from_pds("did:example:alice")
            .await
            .unwrap_err();
        assert_resource_limit(error, "pages_per_did");
        assert_eq!(requests.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn oversized_content_length_is_rejected_before_body_read() {
        let router = Router::new().route(
            "/xrpc/com.atproto.repo.listRecords",
            get(|| async {
                Response::builder()
                    .status(StatusCode::OK)
                    .body(Body::from(vec![b' '; 4096]))
                    .unwrap()
            }),
        );
        let endpoint = spawn_pds(router).await;
        let mut limits = test_limits();
        limits.max_page_bytes = 128;
        let service = service_for_pds(&["did:example:alice"], &endpoint, limits).await;

        let error = service
            .fetch_blocks_from_pds("did:example:alice")
            .await
            .unwrap_err();
        assert_resource_limit(error, "page_bytes");
    }

    #[tokio::test]
    async fn chunked_body_is_rejected_when_stream_crosses_page_limit() {
        let router = Router::new().route(
            "/xrpc/com.atproto.repo.listRecords",
            get(|| async {
                let chunks = vec![
                    Ok::<_, Infallible>(Bytes::from(vec![b' '; 80])),
                    Ok::<_, Infallible>(Bytes::from(vec![b' '; 80])),
                ];
                Response::builder()
                    .status(StatusCode::OK)
                    .body(Body::from_stream(stream::iter(chunks)))
                    .unwrap()
            }),
        );
        let endpoint = spawn_pds(router).await;
        let mut limits = test_limits();
        limits.max_page_bytes = 128;
        let service = service_for_pds(&["did:example:alice"], &endpoint, limits).await;

        let error = service
            .fetch_blocks_from_pds("did:example:alice")
            .await
            .unwrap_err();
        assert_resource_limit(error, "page_bytes");
    }

    #[tokio::test]
    async fn aggregate_response_bytes_are_bounded_across_pages() {
        let router = Router::new().route(
            "/xrpc/com.atproto.repo.listRecords",
            get(|Query(query): Query<HashMap<String, String>>| async move {
                let cursor = query.get("cursor").cloned();
                if cursor.is_none() {
                    page(Vec::new(), Some("next".into()))
                } else {
                    page(vec![record(&"x".repeat(200), 1)], None)
                }
            }),
        );
        let endpoint = spawn_pds(router).await;
        let mut limits = test_limits();
        limits.max_page_bytes = 1024;
        limits.max_aggregate_bytes_per_did = 300;
        let service = service_for_pds(&["did:example:alice"], &endpoint, limits).await;

        let error = service
            .fetch_blocks_from_pds("did:example:alice")
            .await
            .unwrap_err();
        assert_resource_limit(error, "aggregate_bytes_per_did");
    }

    #[tokio::test]
    async fn record_count_is_bounded_across_pages() {
        let router = Router::new().route(
            "/xrpc/com.atproto.repo.listRecords",
            get(|Query(query): Query<HashMap<String, String>>| async move {
                let cursor = query.get("cursor").cloned();
                if cursor.is_none() {
                    page(
                        vec![record("did:example:bob", 0), record("did:example:bob", 1)],
                        Some("next".into()),
                    )
                } else {
                    page(
                        vec![record("did:example:bob", 2), record("did:example:bob", 3)],
                        None,
                    )
                }
            }),
        );
        let endpoint = spawn_pds(router).await;
        let mut limits = test_limits();
        limits.max_records_per_did = 3;
        let service = service_for_pds(&["did:example:alice"], &endpoint, limits).await;

        let error = service
            .fetch_blocks_from_pds("did:example:alice")
            .await
            .unwrap_err();
        assert_resource_limit(error, "records_per_did");
    }

    #[tokio::test]
    async fn oversized_cursor_is_rejected_before_next_request() {
        let requests = Arc::new(AtomicUsize::new(0));
        let request_counter = requests.clone();
        let router = Router::new().route(
            "/xrpc/com.atproto.repo.listRecords",
            get(move || {
                let request_counter = request_counter.clone();
                async move {
                    request_counter.fetch_add(1, Ordering::SeqCst);
                    page(Vec::new(), Some("x".repeat(33)))
                }
            }),
        );
        let endpoint = spawn_pds(router).await;
        let service = service_for_pds(&["did:example:alice"], &endpoint, test_limits()).await;

        let error = service
            .fetch_blocks_from_pds("did:example:alice")
            .await
            .unwrap_err();
        assert_resource_limit(error, "cursor_bytes");
        assert_eq!(requests.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn per_did_deadline_bounds_successive_slow_pages() {
        let router = Router::new().route(
            "/xrpc/com.atproto.repo.listRecords",
            get(|Query(query): Query<HashMap<String, String>>| async move {
                tokio::time::sleep(Duration::from_millis(25)).await;
                let cursor = query.get("cursor").cloned();
                page(Vec::new(), cursor.is_none().then(|| "next".into()))
            }),
        );
        let endpoint = spawn_pds(router).await;
        let mut limits = test_limits();
        limits.did_deadline = Duration::from_millis(40);
        let service = service_for_pds(&["did:example:alice"], &endpoint, limits).await;

        let error = service
            .fetch_blocks_from_pds("did:example:alice")
            .await
            .unwrap_err();
        assert!(matches!(
            error,
            BlockSyncError::DeadlineExceeded {
                operation: "did_fetch"
            }
        ));
    }

    #[tokio::test]
    async fn conflict_deadline_bounds_multiple_individually_successful_fetches() {
        let router = Router::new().route(
            "/xrpc/com.atproto.repo.listRecords",
            get(|| async {
                tokio::time::sleep(Duration::from_millis(35)).await;
                page(Vec::new(), None)
            }),
        );
        let endpoint = spawn_pds(router).await;
        let mut limits = test_limits();
        limits.did_deadline = Duration::from_millis(100);
        limits.conflict_deadline = Duration::from_millis(50);
        let service =
            service_for_pds(&["did:example:alice", "did:example:bob"], &endpoint, limits).await;

        let error = service
            .check_block_conflicts(&["did:example:alice".into(), "did:example:bob".into()])
            .await
            .unwrap_err();
        assert!(matches!(
            error,
            BlockSyncError::DeadlineExceeded {
                operation: "conflict_check"
            }
        ));
    }

    #[tokio::test]
    async fn conflict_check_limits_dids_and_edges() {
        let no_requests = Arc::new(AtomicUsize::new(0));
        let request_counter = no_requests.clone();
        let router = Router::new().route(
            "/xrpc/com.atproto.repo.listRecords",
            get(move || {
                let request_counter = request_counter.clone();
                async move {
                    request_counter.fetch_add(1, Ordering::SeqCst);
                    page(
                        vec![record("did:example:bob", 0), record("did:example:carol", 1)],
                        None,
                    )
                }
            }),
        );
        let endpoint = spawn_pds(router).await;
        let mut did_limits = test_limits();
        did_limits.max_conflict_dids = 1;
        let did_service = service_for_pds(&[], &endpoint, did_limits).await;
        let did_error = did_service
            .check_block_conflicts(&["did:example:alice".into(), "did:example:bob".into()])
            .await
            .unwrap_err();
        assert_resource_limit(did_error, "conflict_dids");
        assert_eq!(no_requests.load(Ordering::SeqCst), 0);

        let mut edge_limits = test_limits();
        edge_limits.max_conflict_edges = 1;
        let edge_service = service_for_pds(&["did:example:alice"], &endpoint, edge_limits).await;
        let edge_error = edge_service
            .check_block_conflicts(&[
                "did:example:alice".into(),
                "did:example:bob".into(),
                "did:example:carol".into(),
            ])
            .await
            .unwrap_err();
        assert_resource_limit(edge_error, "conflict_edges");
    }

    #[tokio::test]
    async fn conflict_check_propagates_first_fetch_failure_without_partial_success() {
        let router = Router::new().route(
            "/xrpc/com.atproto.repo.listRecords",
            get(|Query(query): Query<HashMap<String, String>>| async move {
                match query.get("repo").map(String::as_str) {
                    Some("did:example:alice") => page(vec![record("did:example:bob", 0)], None),
                    _ => Response::builder()
                        .status(StatusCode::INTERNAL_SERVER_ERROR)
                        .body(Body::empty())
                        .unwrap(),
                }
            }),
        );
        let endpoint = spawn_pds(router).await;
        let service = service_for_pds(
            &["did:example:alice", "did:example:bob"],
            &endpoint,
            test_limits(),
        )
        .await;

        let error = service
            .check_block_conflicts(&["did:example:alice".into(), "did:example:bob".into()])
            .await
            .unwrap_err();
        assert!(matches!(error, BlockSyncError::HttpError(_)));
    }

    #[tokio::test]
    async fn finite_boundary_result_is_complete_and_cached() {
        let requests = Arc::new(AtomicUsize::new(0));
        let request_counter = requests.clone();
        let router = Router::new().route(
            "/xrpc/com.atproto.repo.listRecords",
            get(move |Query(query): Query<HashMap<String, String>>| {
                let request_counter = request_counter.clone();
                async move {
                    request_counter.fetch_add(1, Ordering::SeqCst);
                    if !query.contains_key("cursor") {
                        page(
                            vec![record("did:example:bob", 0), record("did:example:bob", 1)],
                            Some("next".into()),
                        )
                    } else {
                        page(
                            vec![record("did:example:bob", 2), record("did:example:bob", 3)],
                            None,
                        )
                    }
                }
            }),
        );
        let endpoint = spawn_pds(router).await;
        let mut limits = test_limits();
        limits.max_pages_per_did = 2;
        limits.max_records_per_did = 4;
        let service = service_for_pds(&["did:example:alice"], &endpoint, limits).await;

        let first = service
            .fetch_blocks_from_pds("did:example:alice")
            .await
            .unwrap();
        assert_eq!(first.len(), 4);
        assert_eq!(first[0].blocker_did, "did:example:alice");
        assert_eq!(first[0].blocked_did, "did:example:bob");
        assert_eq!(
            first[0].uri,
            "at://did:example:alice/app.bsky.graph.block/0"
        );
        assert_eq!(first[0].cid, "cid-0");
        assert_eq!(
            first[0].created_at,
            DateTime::parse_from_rfc3339("2026-07-15T00:00:00Z")
                .ok()
                .map(|timestamp| timestamp.with_timezone(&Utc))
        );
        assert_eq!(requests.load(Ordering::SeqCst), 2);

        let second = service
            .fetch_blocks_from_pds("did:example:alice")
            .await
            .unwrap();
        assert_eq!(second.len(), 4);
        assert_eq!(requests.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn bad_request_remains_an_empty_cached_block_projection() {
        let requests = Arc::new(AtomicUsize::new(0));
        let request_counter = requests.clone();
        let router = Router::new().route(
            "/xrpc/com.atproto.repo.listRecords",
            get(move || {
                let request_counter = request_counter.clone();
                async move {
                    request_counter.fetch_add(1, Ordering::SeqCst);
                    Response::builder()
                        .status(StatusCode::BAD_REQUEST)
                        .body(Body::from(vec![b' '; 16 * 1024]))
                        .unwrap()
                }
            }),
        );
        let endpoint = spawn_pds(router).await;
        let service = service_for_pds(&["did:example:alice"], &endpoint, test_limits()).await;

        assert!(service
            .fetch_blocks_from_pds("did:example:alice")
            .await
            .unwrap()
            .is_empty());
        assert!(service
            .fetch_blocks_from_pds("did:example:alice")
            .await
            .unwrap()
            .is_empty());
        assert_eq!(requests.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn bad_request_after_pagination_starts_discards_partial_records_before_caching_empty() {
        let requests = Arc::new(AtomicUsize::new(0));
        let request_counter = requests.clone();
        let router = Router::new().route(
            "/xrpc/com.atproto.repo.listRecords",
            get(move |Query(query): Query<HashMap<String, String>>| {
                let request_counter = request_counter.clone();
                async move {
                    request_counter.fetch_add(1, Ordering::SeqCst);
                    if query.contains_key("cursor") {
                        Response::builder()
                            .status(StatusCode::BAD_REQUEST)
                            .body(Body::empty())
                            .unwrap()
                    } else {
                        page(vec![record("did:example:bob", 0)], Some("next".into()))
                    }
                }
            }),
        );
        let endpoint = spawn_pds(router).await;
        let service = service_for_pds(&["did:example:alice"], &endpoint, test_limits()).await;

        let first = service
            .fetch_blocks_from_pds("did:example:alice")
            .await
            .unwrap();
        assert!(first.is_empty());
        assert_eq!(requests.load(Ordering::SeqCst), 2);
        assert!(service
            .blocks_cache
            .get("did:example:alice")
            .await
            .is_some_and(|blocks| blocks.is_empty()));

        let second = service
            .fetch_blocks_from_pds("did:example:alice")
            .await
            .unwrap();
        assert!(second.is_empty());
        assert_eq!(requests.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn cached_http_pds_endpoint_is_rejected_before_connection_or_cache_admission() {
        let requests = Arc::new(AtomicUsize::new(0));
        let request_counter = requests.clone();
        let router = Router::new().route(
            "/xrpc/com.atproto.repo.listRecords",
            get(move || {
                let request_counter = request_counter.clone();
                async move {
                    request_counter.fetch_add(1, Ordering::SeqCst);
                    page(Vec::new(), None)
                }
            }),
        );
        let endpoint = spawn_pds(router).await;
        let service = BlockSyncService::with_limits_for_test(test_limits());
        service
            .pds_cache
            .insert("did:example:alice".into(), endpoint)
            .await;

        let error = service
            .fetch_blocks_from_pds("did:example:alice")
            .await
            .unwrap_err();

        assert!(matches!(error, BlockSyncError::UnsafeDestination(_)));
        assert_eq!(requests.load(Ordering::SeqCst), 0);
        assert!(service
            .blocks_cache
            .get("did:example:alice")
            .await
            .is_none());
    }

    #[tokio::test]
    async fn per_did_deadline_includes_cache_lookup() {
        let mut limits = test_limits();
        limits.did_deadline = Duration::from_millis(20);
        limits.cache_lookup_delay = Duration::from_millis(50);
        let service = BlockSyncService::with_limits_for_test(limits);
        service
            .blocks_cache
            .insert("did:example:alice".into(), Vec::new())
            .await;

        let error = service
            .fetch_blocks_from_pds("did:example:alice")
            .await
            .unwrap_err();
        assert!(matches!(
            error,
            BlockSyncError::DeadlineExceeded {
                operation: "did_fetch"
            }
        ));
    }

    #[tokio::test]
    async fn per_did_deadline_includes_successful_cache_admission() {
        let router = Router::new().route(
            "/xrpc/com.atproto.repo.listRecords",
            get(|| async { page(Vec::new(), None) }),
        );
        let endpoint = spawn_pds(router).await;
        let mut limits = test_limits();
        limits.did_deadline = Duration::from_millis(20);
        limits.cache_insert_delay = Duration::from_millis(50);
        let service = service_for_pds(&["did:example:alice"], &endpoint, limits).await;

        let error = service
            .fetch_blocks_from_pds("did:example:alice")
            .await
            .unwrap_err();
        assert!(matches!(
            error,
            BlockSyncError::DeadlineExceeded {
                operation: "did_fetch"
            }
        ));
        assert!(service
            .blocks_cache
            .get("did:example:alice")
            .await
            .is_none());
    }

    #[tokio::test]
    async fn retained_cache_weight_stays_within_capacity_under_insert_pressure() {
        let limits = ResourceLimits::default();
        let service = BlockSyncService::with_limits_for_test(limits);
        let mut inserted_weight = 0_u64;

        for index in 0..80 {
            let did = format!("did:example:{index}");
            let blocks = vec![BlockRecord {
                blocker_did: did.clone(),
                blocked_did: "x".repeat(1024 * 1024),
                uri: format!("at://{did}/app.bsky.graph.block/{index}"),
                cid: "c".repeat(256),
                created_at: None,
            }];
            inserted_weight += u64::from(block_cache_entry_weight(did.capacity(), &blocks));
            service.blocks_cache.insert(did, blocks).await;
        }
        service.blocks_cache.run_pending_tasks().await;

        assert!(inserted_weight > limits.block_cache_capacity_bytes);
        assert!(
            service.blocks_cache.weighted_size() <= limits.block_cache_capacity_bytes,
            "cache retained {} bytes above {} byte capacity",
            service.blocks_cache.weighted_size(),
            limits.block_cache_capacity_bytes
        );
    }

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
