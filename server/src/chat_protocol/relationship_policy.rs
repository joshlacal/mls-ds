//! Fail-closed relationship and declaration authority for `blue.catbird.chat`.
//!
//! This module deliberately has no dependency on the superseded MLS-chat
//! policy, federation, authentication, handlers, or tables.  Network evidence
//! is collected outside a mutation transaction and becomes usable only after
//! the complete, exact projection is fenced again under that transaction.

use crate::util::outbound_body;

use async_trait::async_trait;
use chrono::{DateTime, TimeDelta, Utc};
use futures::future::join_all;
use jacquard_common::types::cid::IpldCid;
use reqwest::redirect::Policy as RedirectPolicy;
use serde::de::{Deserializer, MapAccess, SeqAccess, Visitor};
use serde_json::{Map, Number, Value};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::sync::{Mutex as AsyncMutex, Semaphore};
use tokio::time::Instant;
use url::Url;
use uuid::Uuid;

use self::outbound_body::{collect_bounded, ResponseBodyBudget};
use super::validation::TrustedRequestInstant;

use super::repository::relationship::RelationshipAuthorityStartupGuard;

pub(crate) use super::repository::core::AllocatedProjectionRevisionGuard;
pub(crate) use super::repository::relationship::{
    RelationshipProjectionLoadGuard, TrafficProjectionLoadGuard,
    TrustedRelationshipDecisionInstant, TrustedRelationshipPersistenceInstant,
};

pub const MAX_ROSTER_SIZE: usize = 100;
pub const GRAPH_OTHERS_MAX: usize = 30;
pub const MAX_ADMISSION_GRAPH_CALLS: usize = 198;
pub const MAX_DECLARATION_HTTP_CALLS: usize = 198;
pub const MAX_ADMISSION_SOURCE_CALLS: usize = 396;
pub const MAX_TRAFFIC_GRAPH_CALLS: usize = 4;
pub const MAX_PROJECTION_AGE: TimeDelta = TimeDelta::seconds(60);

pub const HARD_MAX_CONCURRENCY: usize = 32;
pub const HARD_MAX_REQUEST_RATE: u32 = 1_000;
pub const HARD_MAX_REQUEST_BURST: u32 = MAX_ADMISSION_SOURCE_CALLS as u32;
pub const HARD_MAX_TOTAL_DEADLINE: Duration = Duration::from_secs(30);
pub const HARD_MAX_RESPONSE_BYTES: usize = 512 * 1024;
pub const HARD_MAX_DNS_ANSWERS: usize = 16;
const MAX_PERSISTED_AGGREGATE_BYTES: usize = 8 * 1024 * 1024;
const MAX_PERSISTED_SAFE_INTEGER: u64 = 9_007_199_254_740_991;
const CANONICAL_DID_SET_MAGIC: &[u8; 8] = b"CBDID001";
const CANONICAL_RELATIONSHIP_EVIDENCE_MAGIC: &[u8; 8] = b"CBREL001";
const MAX_PINNED_CLIENT_POOL_ENTRIES: usize = MAX_ROSTER_SIZE * 2 + 2;
const HARDENED_SOURCE_PROFILE_V1: &[u8] =
    b"reqwest-pinned-system-dns/no-proxy/no-redirect/public-only/credential-free/v1";
#[cfg(test)]
const UNTRUSTED_TEST_SOURCE_PROFILE: &[u8] = b"untrusted-test-source";
#[cfg(feature = "test-support")]
const FEDERATION_TEST_SOURCE_PROFILE: &[u8] = b"federation-test-allow-all/v1";

const GRAPH_PATH: &str = "/xrpc/app.bsky.graph.getRelationships";
const GET_RECORD_PATH: &str = "/xrpc/com.atproto.repo.getRecord";
const DECLARATION_COLLECTION: &str = "chat.bsky.actor.declaration";
const DECLARATION_RKEY: &str = "self";
const RELATIONSHIP_TYPE: &str = "app.bsky.graph.defs#relationship";
const DECLARATION_TYPE: &str = "chat.bsky.actor.declaration";

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum RelationshipPolicyConfigError {
    InvalidOrigin,
    InvalidLimit,
    InsufficientCapacity,
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct PlannerCapacityProof {
    roster_sizes_verified: usize,
    max_admission_graph_calls: usize,
    max_declaration_http_calls: usize,
    max_admission_source_calls: usize,
    max_traffic_graph_calls: usize,
}

impl PlannerCapacityProof {
    pub fn roster_sizes_verified(&self) -> usize {
        self.roster_sizes_verified
    }

    pub fn max_admission_graph_calls(&self) -> usize {
        self.max_admission_graph_calls
    }

    pub fn max_declaration_http_calls(&self) -> usize {
        self.max_declaration_http_calls
    }

    pub fn max_admission_source_calls(&self) -> usize {
        self.max_admission_source_calls
    }

    pub fn max_traffic_graph_calls(&self) -> usize {
        self.max_traffic_graph_calls
    }
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub enum RelationshipAuthorityReadiness {
    Ready(PlannerCapacityProof),
}

#[derive(Debug, Clone)]
pub struct RelationshipPolicyConfigInput {
    pub appview_origin: String,
    pub plc_directory_origin: String,
    pub max_concurrency: usize,
    pub request_rate_per_second: u32,
    pub request_burst: u32,
    pub total_deadline: Duration,
    pub max_response_bytes: usize,
    pub max_dns_answers: usize,
    pub admission_graph_capacity: usize,
    pub declaration_http_capacity: usize,
    pub admission_source_capacity: usize,
    pub traffic_graph_capacity: usize,
}

impl From<&RelationshipPolicyConfig> for RelationshipPolicyConfigInput {
    fn from(value: &RelationshipPolicyConfig) -> Self {
        Self {
            appview_origin: value.appview_origin.as_str().to_owned(),
            plc_directory_origin: value.plc_directory_origin.as_str().to_owned(),
            max_concurrency: value.max_concurrency,
            request_rate_per_second: value.request_rate_per_second,
            request_burst: value.request_burst,
            total_deadline: value.total_deadline,
            max_response_bytes: value.max_response_bytes,
            max_dns_answers: value.max_dns_answers,
            admission_graph_capacity: value.admission_graph_capacity,
            declaration_http_capacity: value.declaration_http_capacity,
            admission_source_capacity: value.admission_source_capacity,
            traffic_graph_capacity: value.traffic_graph_capacity,
        }
    }
}

#[derive(Debug, Clone)]
pub struct RelationshipPolicyConfig {
    appview_origin: CanonicalOrigin,
    plc_directory_origin: CanonicalOrigin,
    max_concurrency: usize,
    request_rate_per_second: u32,
    request_burst: u32,
    total_deadline: Duration,
    max_response_bytes: usize,
    max_dns_answers: usize,
    admission_graph_capacity: usize,
    declaration_http_capacity: usize,
    admission_source_capacity: usize,
    traffic_graph_capacity: usize,
    fingerprint: [u8; 32],
    readiness: RelationshipAuthorityReadiness,
}

impl RelationshipPolicyConfig {
    fn validate_and_build(
        input: RelationshipPolicyConfigInput,
    ) -> Result<Self, RelationshipPolicyConfigError> {
        let appview_origin = CanonicalOrigin::parse(&input.appview_origin)
            .map_err(|_| RelationshipPolicyConfigError::InvalidOrigin)?;
        let plc_directory_origin = CanonicalOrigin::parse(&input.plc_directory_origin)
            .map_err(|_| RelationshipPolicyConfigError::InvalidOrigin)?;
        if input.max_concurrency == 0
            || input.max_concurrency > HARD_MAX_CONCURRENCY
            || input.request_rate_per_second == 0
            || input.request_rate_per_second > HARD_MAX_REQUEST_RATE
            || input.request_burst == 0
            || input.request_burst > HARD_MAX_REQUEST_BURST
            || input.total_deadline.is_zero()
            || input.total_deadline > HARD_MAX_TOTAL_DEADLINE
            || input.max_response_bytes == 0
            || input.max_response_bytes > HARD_MAX_RESPONSE_BYTES
            || input.max_dns_answers == 0
            || input.max_dns_answers > HARD_MAX_DNS_ANSWERS
        {
            return Err(RelationshipPolicyConfigError::InvalidLimit);
        }
        if input.admission_graph_capacity != MAX_ADMISSION_GRAPH_CALLS
            || input.declaration_http_capacity != MAX_DECLARATION_HTTP_CALLS
            || input.admission_source_capacity != MAX_ADMISSION_SOURCE_CALLS
            || input.traffic_graph_capacity != MAX_TRAFFIC_GRAPH_CALLS
        {
            return Err(RelationshipPolicyConfigError::InsufficientCapacity);
        }
        let rate_capacity = (u128::from(input.request_rate_per_second)
            * input.total_deadline.as_nanos())
            / 1_000_000_000
            + u128::from(input.request_burst);
        if rate_capacity < MAX_ADMISSION_SOURCE_CALLS as u128 {
            return Err(RelationshipPolicyConfigError::InsufficientCapacity);
        }

        let readiness = prove_planner_readiness()?;
        let RelationshipAuthorityReadiness::Ready(proof) = &readiness;
        if proof.max_admission_graph_calls > input.admission_graph_capacity
            || proof.max_declaration_http_calls > input.declaration_http_capacity
            || proof.max_admission_source_calls > input.admission_source_capacity
            || proof.max_traffic_graph_calls > input.traffic_graph_capacity
        {
            return Err(RelationshipPolicyConfigError::InsufficientCapacity);
        }

        let fingerprint = config_fingerprint(&input, &appview_origin, &plc_directory_origin);
        Ok(Self {
            appview_origin,
            plc_directory_origin,
            max_concurrency: input.max_concurrency,
            request_rate_per_second: input.request_rate_per_second,
            request_burst: input.request_burst,
            total_deadline: input.total_deadline,
            max_response_bytes: input.max_response_bytes,
            max_dns_answers: input.max_dns_answers,
            admission_graph_capacity: input.admission_graph_capacity,
            declaration_http_capacity: input.declaration_http_capacity,
            admission_source_capacity: input.admission_source_capacity,
            traffic_graph_capacity: input.traffic_graph_capacity,
            fingerprint,
            readiness,
        })
    }

    #[cfg(test)]
    pub fn new(
        input: RelationshipPolicyConfigInput,
    ) -> Result<Self, RelationshipPolicyConfigError> {
        Self::validate_and_build(input)
    }

    pub fn appview_origin(&self) -> &CanonicalOrigin {
        &self.appview_origin
    }

    pub fn plc_directory_origin(&self) -> &CanonicalOrigin {
        &self.plc_directory_origin
    }

    pub fn fingerprint(&self) -> [u8; 32] {
        self.fingerprint
    }

    pub fn readiness(&self) -> &RelationshipAuthorityReadiness {
        &self.readiness
    }

    pub(crate) fn max_dns_answers(&self) -> usize {
        self.max_dns_answers
    }
}

/// The production relationship authority has one fixed, audited network
/// configuration. No production API accepts caller-selected origins, limits,
/// fingerprints, transport, or time authority.
pub(crate) fn fixed_production_relationship_policy_config(
) -> Result<RelationshipPolicyConfig, RelationshipPolicyConfigError> {
    RelationshipPolicyConfig::validate_and_build(RelationshipPolicyConfigInput {
        appview_origin: concat!("https://", "public", ".api.bsky.app").into(),
        plc_directory_origin: "https://plc.directory".into(),
        max_concurrency: 16,
        request_rate_per_second: HARD_MAX_REQUEST_RATE,
        request_burst: HARD_MAX_REQUEST_BURST,
        total_deadline: Duration::from_secs(20),
        max_response_bytes: 256 * 1024,
        max_dns_answers: 8,
        admission_graph_capacity: MAX_ADMISSION_GRAPH_CALLS,
        declaration_http_capacity: MAX_DECLARATION_HTTP_CALLS,
        admission_source_capacity: MAX_ADMISSION_SOURCE_CALLS,
        traffic_graph_capacity: MAX_TRAFFIC_GRAPH_CALLS,
    })
}

fn config_fingerprint(
    input: &RelationshipPolicyConfigInput,
    appview: &CanonicalOrigin,
    plc: &CanonicalOrigin,
) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(b"CATBIRD-CHAT-RELATIONSHIP-CONFIG\0");
    hash_len_bytes(&mut hash, appview.as_str().as_bytes());
    hash_len_bytes(&mut hash, plc.as_str().as_bytes());
    for value in [
        input.max_concurrency as u128,
        input.request_rate_per_second as u128,
        input.request_burst as u128,
        input.max_response_bytes as u128,
        input.max_dns_answers as u128,
        input.admission_graph_capacity as u128,
        input.declaration_http_capacity as u128,
        input.admission_source_capacity as u128,
        input.traffic_graph_capacity as u128,
    ] {
        hash.update(value.to_be_bytes());
    }
    hash.update(input.total_deadline.as_secs().to_be_bytes());
    hash.update(input.total_deadline.subsec_nanos().to_be_bytes());
    hash.finalize().into()
}

fn relationship_source_identity(
    config: &RelationshipPolicyConfig,
    source_profile: &[u8],
) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(b"CATBIRD-CHAT-RELATIONSHIP-SOURCE\0");
    hash_len_bytes(&mut hash, source_profile);
    hash_len_bytes(&mut hash, config.appview_origin.as_str().as_bytes());
    hash_len_bytes(&mut hash, config.plc_directory_origin.as_str().as_bytes());
    hash.update(config.fingerprint);
    hash.finalize().into()
}

fn hash_len_bytes(hash: &mut Sha256, bytes: &[u8]) {
    hash.update((bytes.len() as u64).to_be_bytes());
    hash.update(bytes);
}

#[derive(Debug, Clone, Eq, PartialEq, Ord, PartialOrd)]
pub struct CanonicalOrigin {
    serialized: String,
}

impl CanonicalOrigin {
    pub fn parse(raw: &str) -> Result<Self, RelationshipPolicyConfigError> {
        if !raw.is_ascii() || !raw.starts_with("https://") {
            return Err(RelationshipPolicyConfigError::InvalidOrigin);
        }
        let url = Url::parse(raw).map_err(|_| RelationshipPolicyConfigError::InvalidOrigin)?;
        if url.scheme() != "https"
            || !url.username().is_empty()
            || url.password().is_some()
            || url.query().is_some()
            || url.fragment().is_some()
            || url.path() != "/"
        {
            return Err(RelationshipPolicyConfigError::InvalidOrigin);
        }
        let host = url
            .host_str()
            .ok_or(RelationshipPolicyConfigError::InvalidOrigin)?;
        if host != host.to_ascii_lowercase()
            || !validate_public_hostname(host)
            || raw.ends_with('/')
            || url.port() == Some(443)
        {
            return Err(RelationshipPolicyConfigError::InvalidOrigin);
        }
        let expected = match url.port() {
            Some(port) => format!("https://{host}:{port}"),
            None => format!("https://{host}"),
        };
        if raw != expected {
            return Err(RelationshipPolicyConfigError::InvalidOrigin);
        }
        Ok(Self {
            serialized: expected,
        })
    }

    pub fn as_str(&self) -> &str {
        &self.serialized
    }

    fn append_path(&self, path: &str) -> Result<Url, AuthorityError> {
        Url::parse(&format!("{}{}", self.serialized, path)).map_err(|_| AuthorityError::Malformed)
    }
}

fn validate_public_hostname(host: &str) -> bool {
    if host.is_empty()
        || host.len() > 253
        || host.ends_with('.')
        || host.eq_ignore_ascii_case("localhost")
        || host.parse::<IpAddr>().is_ok()
    {
        return false;
    }
    let labels: Vec<_> = host.split('.').collect();
    if labels.len() < 2 {
        return false;
    }
    if labels.iter().any(|label| {
        label.is_empty()
            || label.len() > 63
            || !label.is_ascii()
            || !label
                .bytes()
                .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
            || !label.as_bytes()[0].is_ascii_alphanumeric()
            || !label.as_bytes()[label.len() - 1].is_ascii_alphanumeric()
    }) {
        return false;
    }
    let tld = labels.last().expect("at least two labels");
    if !tld.as_bytes()[0].is_ascii_lowercase() {
        return false;
    }
    !matches!(
        *tld,
        "alt"
            | "arpa"
            | "example"
            | "internal"
            | "invalid"
            | "local"
            | "localhost"
            | "onion"
            | "test"
    )
}

fn validate_bare_did(did: &str) -> bool {
    if !did.is_ascii() || !(12..=261).contains(&did.len()) {
        return false;
    }
    if let Some(value) = did.strip_prefix("did:plc:") {
        return value.len() == 24
            && value
                .bytes()
                .all(|byte| byte.is_ascii_lowercase() || (b'2'..=b'7').contains(&byte));
    }
    did.strip_prefix("did:web:")
        .is_some_and(validate_public_hostname)
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct GraphRequest {
    pub actor: String,
    pub others: Vec<String>,
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct AdmissionGraphScope {
    pub members: Vec<String>,
    pub sink: String,
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct AdmissionGraphPlan {
    pub scope: AdmissionGraphScope,
    pub requests: Vec<GraphRequest>,
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct TrafficGraphScope {
    pub actor: String,
    pub members: Vec<String>,
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct TrafficGraphPlan {
    pub scope: TrafficGraphScope,
    pub requests: Vec<GraphRequest>,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum PlanError {
    InvalidRoster,
    Capacity,
}

fn canonical_roster(roster: &[String]) -> Result<Vec<String>, PlanError> {
    if roster.is_empty() || roster.len() > MAX_ROSTER_SIZE {
        return Err(PlanError::InvalidRoster);
    }
    if roster.iter().any(|did| !validate_bare_did(did)) {
        return Err(PlanError::InvalidRoster);
    }
    let mut members = roster.to_vec();
    members.sort();
    if members.windows(2).any(|pair| pair[0] == pair[1]) {
        return Err(PlanError::InvalidRoster);
    }
    Ok(members)
}

pub fn plan_admission_graph(
    roster: &[String],
    inviter_sink: &str,
) -> Result<AdmissionGraphPlan, PlanError> {
    let members = canonical_roster(roster)?;
    if !members.iter().any(|member| member == inviter_sink) {
        return Err(PlanError::InvalidRoster);
    }
    orient_admission(members, inviter_sink.to_owned())
}

pub fn plan_block_only_graph(roster: &[String]) -> Result<AdmissionGraphPlan, PlanError> {
    let members = canonical_roster(roster)?;
    let sink = members[0].clone();
    orient_admission(members, sink)
}

fn orient_admission(members: Vec<String>, sink: String) -> Result<AdmissionGraphPlan, PlanError> {
    let non_sink: Vec<_> = members
        .iter()
        .filter(|member| **member != sink)
        .cloned()
        .collect();
    let count = non_sink.len();
    let mut requests = Vec::new();
    for (index, actor) in non_sink.iter().enumerate() {
        let mut targets = vec![sink.clone()];
        for (other_index, target) in non_sink.iter().enumerate() {
            if index == other_index {
                continue;
            }
            let distance = (other_index + count - index) % count;
            let oriented = if count % 2 == 1 {
                distance <= count / 2
            } else if distance < count / 2 {
                true
            } else if distance == count / 2 {
                index < other_index
            } else {
                false
            };
            if oriented {
                targets.push(target.clone());
            }
        }
        targets.sort();
        for chunk in targets.chunks(GRAPH_OTHERS_MAX) {
            requests.push(GraphRequest {
                actor: actor.clone(),
                others: chunk.to_vec(),
            });
        }
    }
    if requests.len() > MAX_ADMISSION_GRAPH_CALLS {
        return Err(PlanError::Capacity);
    }
    Ok(AdmissionGraphPlan {
        scope: AdmissionGraphScope { members, sink },
        requests,
    })
}

pub fn plan_traffic_graph(actor: &str, roster: &[String]) -> Result<TrafficGraphPlan, PlanError> {
    let members = canonical_roster(roster)?;
    if !members.iter().any(|member| member == actor) {
        return Err(PlanError::InvalidRoster);
    }
    let others: Vec<_> = members
        .iter()
        .filter(|member| member.as_str() != actor)
        .cloned()
        .collect();
    let requests: Vec<_> = others
        .chunks(GRAPH_OTHERS_MAX)
        .map(|chunk| GraphRequest {
            actor: actor.to_owned(),
            others: chunk.to_vec(),
        })
        .collect();
    if requests.len() > MAX_TRAFFIC_GRAPH_CALLS {
        return Err(PlanError::Capacity);
    }
    Ok(TrafficGraphPlan {
        scope: TrafficGraphScope {
            actor: actor.to_owned(),
            members,
        },
        requests,
    })
}

fn prove_planner_readiness() -> Result<RelationshipAuthorityReadiness, RelationshipPolicyConfigError>
{
    let mut proof = PlannerCapacityProof {
        roster_sizes_verified: 0,
        max_admission_graph_calls: 0,
        max_declaration_http_calls: 0,
        max_admission_source_calls: 0,
        max_traffic_graph_calls: 0,
    };
    for size in 1..=MAX_ROSTER_SIZE {
        let roster = readiness_roster(size);
        let sink = &roster[0];
        let admission = plan_admission_graph(&roster, sink)
            .map_err(|_| RelationshipPolicyConfigError::InsufficientCapacity)?;
        let admission_repeat = plan_admission_graph(&roster, sink)
            .map_err(|_| RelationshipPolicyConfigError::InsufficientCapacity)?;
        let block = plan_block_only_graph(&roster)
            .map_err(|_| RelationshipPolicyConfigError::InsufficientCapacity)?;
        let traffic = plan_traffic_graph(sink, &roster)
            .map_err(|_| RelationshipPolicyConfigError::InsufficientCapacity)?;
        if admission != admission_repeat || admission != block {
            return Err(RelationshipPolicyConfigError::InsufficientCapacity);
        }
        let declaration_calls = size.saturating_sub(1) * 2;
        proof.roster_sizes_verified += 1;
        proof.max_admission_graph_calls = proof
            .max_admission_graph_calls
            .max(admission.requests.len());
        proof.max_declaration_http_calls = proof.max_declaration_http_calls.max(declaration_calls);
        proof.max_admission_source_calls = proof
            .max_admission_source_calls
            .max(admission.requests.len() + declaration_calls);
        proof.max_traffic_graph_calls = proof.max_traffic_graph_calls.max(traffic.requests.len());
    }
    if proof.roster_sizes_verified != MAX_ROSTER_SIZE
        || proof.max_admission_graph_calls != MAX_ADMISSION_GRAPH_CALLS
        || proof.max_declaration_http_calls != MAX_DECLARATION_HTTP_CALLS
        || proof.max_admission_source_calls != MAX_ADMISSION_SOURCE_CALLS
        || proof.max_traffic_graph_calls != MAX_TRAFFIC_GRAPH_CALLS
    {
        return Err(RelationshipPolicyConfigError::InsufficientCapacity);
    }
    Ok(RelationshipAuthorityReadiness::Ready(proof))
}

fn readiness_roster(size: usize) -> Vec<String> {
    const DIGITS: &[u8] = b"abcdefghijklmnopqrstuvwxyz234567";
    let mut roster = Vec::with_capacity(size);
    for index in 0..size {
        let mut suffix = [b'a'; 24];
        let mut value = index;
        for slot in suffix.iter_mut().rev().take(4) {
            *slot = DIGITS[value % DIGITS.len()];
            value /= DIGITS.len();
        }
        roster.push(format!(
            "did:plc:{}",
            String::from_utf8(suffix.to_vec()).expect("fixed ASCII alphabet")
        ));
    }
    roster.sort();
    roster
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum PublicCredentials {
    None,
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct PublicGet {
    pub url: Url,
    pub deadline: Instant,
    pub max_body_bytes: usize,
    pub credentials: PublicCredentials,
}

impl PublicGet {
    pub fn new(url: Url, deadline: Instant, max_body_bytes: usize) -> Self {
        Self {
            url,
            deadline,
            max_body_bytes,
            credentials: PublicCredentials::None,
        }
    }
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct PublicResponse {
    pub status: u16,
    pub body: Vec<u8>,
}

impl PublicResponse {
    pub fn new(status: u16, body: Vec<u8>) -> Self {
        Self { status, body }
    }

    pub fn json(status: u16, value: Value) -> Self {
        Self::new(
            status,
            serde_json::to_vec(&value).expect("JSON fixture serializes"),
        )
    }
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum TransportError {
    InvalidRequest,
    UnsafeDestination,
    DnsCapacity,
    DnsRebinding,
    Redirect,
    Deadline,
    BodyTooLarge,
    Network,
}

#[async_trait]
pub trait PublicTransport: Clone + Send + Sync + 'static {
    async fn get(&self, request: PublicGet) -> Result<PublicResponse, TransportError>;
}

#[async_trait]
pub trait DnsResolver: Clone + Send + Sync + 'static {
    async fn resolve(&self, host: &str, port: u16) -> Result<Vec<SocketAddr>, TransportError>;
}

#[derive(Debug, Clone, Copy, Default)]
pub struct SystemDnsResolver;

#[async_trait]
impl DnsResolver for SystemDnsResolver {
    async fn resolve(&self, host: &str, port: u16) -> Result<Vec<SocketAddr>, TransportError> {
        let mut addresses: Vec<_> = tokio::net::lookup_host((host, port))
            .await
            .map_err(|_| TransportError::Network)?
            .collect();
        addresses.sort_unstable();
        addresses.dedup();
        Ok(addresses)
    }
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub struct TransportSecurityProfile {
    pub no_proxy: bool,
    pub reject_redirects: bool,
    pub dns_pinned: bool,
    pub public_only: bool,
    pub credential_free: bool,
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct PinnedDestination {
    url: Url,
    host: String,
    addresses: Vec<SocketAddr>,
}

impl PinnedDestination {
    pub fn addresses(&self) -> &[SocketAddr] {
        &self.addresses
    }
}

#[derive(Debug, Clone)]
pub struct ReqwestPinnedTransport<R: DnsResolver> {
    resolver: R,
    max_dns_answers: usize,
    clients: PinnedClientPool,
}

type PinnedClientKey = (String, Vec<SocketAddr>);
type PinnedClientPool = Arc<AsyncMutex<BTreeMap<PinnedClientKey, reqwest::Client>>>;

impl<R: DnsResolver> ReqwestPinnedTransport<R> {
    pub fn new(resolver: R, max_dns_answers: usize) -> Result<Self, TransportError> {
        if max_dns_answers == 0 || max_dns_answers > HARD_MAX_DNS_ANSWERS {
            return Err(TransportError::DnsCapacity);
        }
        Ok(Self {
            resolver,
            max_dns_answers,
            clients: Arc::new(AsyncMutex::new(BTreeMap::new())),
        })
    }

    pub fn security_profile() -> TransportSecurityProfile {
        TransportSecurityProfile {
            no_proxy: true,
            reject_redirects: true,
            dns_pinned: true,
            public_only: true,
            credential_free: true,
        }
    }

    pub async fn pin_destination(
        &self,
        request: &PublicGet,
    ) -> Result<PinnedDestination, TransportError> {
        validate_public_request_url(&request.url)?;
        let host = request
            .url
            .host_str()
            .ok_or(TransportError::UnsafeDestination)?
            .to_owned();
        let port = request
            .url
            .port_or_known_default()
            .ok_or(TransportError::UnsafeDestination)?;
        let mut addresses =
            tokio::time::timeout_at(request.deadline, self.resolver.resolve(&host, port))
                .await
                .map_err(|_| TransportError::Deadline)??;
        addresses.sort_unstable();
        addresses.dedup();
        if addresses.is_empty() {
            return Err(TransportError::UnsafeDestination);
        }
        if addresses.len() > self.max_dns_answers {
            return Err(TransportError::DnsCapacity);
        }
        if addresses
            .iter()
            .any(|address| address.port() != port || !ip_is_public(address.ip()))
        {
            return Err(TransportError::UnsafeDestination);
        }
        Ok(PinnedDestination {
            url: request.url.clone(),
            host,
            addresses,
        })
    }
}

fn validate_public_request_url(url: &Url) -> Result<(), TransportError> {
    let host = url.host_str().ok_or(TransportError::UnsafeDestination)?;
    if url.scheme() != "https"
        || !url.username().is_empty()
        || url.password().is_some()
        || !validate_public_hostname(host)
    {
        return Err(TransportError::UnsafeDestination);
    }
    Ok(())
}

#[async_trait]
impl<R: DnsResolver> PublicTransport for ReqwestPinnedTransport<R> {
    async fn get(&self, request: PublicGet) -> Result<PublicResponse, TransportError> {
        if request.max_body_bytes == 0 || request.max_body_bytes > HARD_MAX_RESPONSE_BYTES {
            return Err(TransportError::InvalidRequest);
        }
        let destination = self.pin_destination(&request).await?;
        let client_key = (destination.host.clone(), destination.addresses.clone());
        let client = {
            let mut clients = self.clients.lock().await;
            if let Some(client) = clients.get(&client_key) {
                client.clone()
            } else {
                let client = reqwest::Client::builder()
                    .user_agent("catbird-chat-authority/1")
                    .no_proxy()
                    .redirect(RedirectPolicy::none())
                    .resolve_to_addrs(&destination.host, &destination.addresses)
                    .build()
                    .map_err(|_| TransportError::Network)?;
                if clients.len() < MAX_PINNED_CLIENT_POOL_ENTRIES {
                    clients.insert(client_key, client.clone());
                }
                client
            }
        };
        let response =
            tokio::time::timeout_at(request.deadline, client.get(destination.url).send())
                .await
                .map_err(|_| TransportError::Deadline)?
                .map_err(|error| {
                    if error.is_timeout() {
                        TransportError::Deadline
                    } else {
                        TransportError::Network
                    }
                })?;
        if response.status().is_redirection() {
            return Err(TransportError::Redirect);
        }
        let status = response.status().as_u16();
        let body = collect_bounded(
            response,
            ResponseBodyBudget::new(request.max_body_bytes, request.deadline),
        )
        .await
        .map_err(|error| match error {
            outbound_body::OutboundBodyError::DeclaredTooLarge { .. }
            | outbound_body::OutboundBodyError::StreamedTooLarge { .. }
            | outbound_body::OutboundBodyError::LengthOverflow => TransportError::BodyTooLarge,
            outbound_body::OutboundBodyError::DeadlineExceeded => TransportError::Deadline,
            outbound_body::OutboundBodyError::ReadFailed(source) if source.is_timeout() => {
                TransportError::Deadline
            }
            outbound_body::OutboundBodyError::ReadFailed(_)
            | outbound_body::OutboundBodyError::InvalidJson(_) => TransportError::Network,
        })?;
        Ok(PublicResponse::new(status, body.to_vec()))
    }
}

pub fn ip_is_public(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ip) => ipv4_is_public(ip),
        IpAddr::V6(ip) => ipv6_is_public(ip),
    }
}

fn ipv4_is_public(ip: Ipv4Addr) -> bool {
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

fn ipv6_is_public(ip: Ipv6Addr) -> bool {
    let segments = ip.segments();
    let numeric = u128::from_be_bytes(ip.octets());
    if matches!(segments, [0x64, 0xff9b, 0, 0, 0, 0, _, _]) {
        let embedded = Ipv4Addr::new(
            (segments[6] >> 8) as u8,
            segments[6] as u8,
            (segments[7] >> 8) as u8,
            segments[7] as u8,
        );
        return ipv4_is_public(embedded);
    }
    // The only generally routable IPv6 destination space is global unicast
    // 2000::/3, plus the explicitly handled well-known NAT64 prefix above.
    // Deny every other allocation before considering exceptions within that
    // range; this closes reserved/unallocated destinations such as 4000::/3.
    if (segments[0] & 0xe000) != 0x2000 {
        return false;
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
                || matches!(segments, [0x2001, second, _, _, _, _, _, _] if (0x20..=0x3f).contains(&second))))
        || matches!(segments, [0x2002, _, _, _, _, _, _, _])
        || matches!(segments, [0x2001, 0x0db8, ..])
        || matches!(segments, [0x3fff, second, ..] if second <= 0x0fff)
        || matches!(segments, [0x5f00, ..]))
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum AuthorityError {
    Unavailable,
    Malformed,
    Capacity,
}

fn strict_json(bytes: &[u8]) -> Result<Value, AuthorityError> {
    let mut deserializer = serde_json::Deserializer::from_slice(bytes);
    let value = deserializer
        .deserialize_any(StrictJsonVisitor)
        .map_err(|_| AuthorityError::Malformed)?;
    deserializer.end().map_err(|_| AuthorityError::Malformed)?;
    Ok(value)
}

struct StrictJsonVisitor;

impl<'de> Visitor<'de> for StrictJsonVisitor {
    type Value = Value;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("strict JSON")
    }

    fn visit_bool<E>(self, value: bool) -> Result<Self::Value, E> {
        Ok(Value::Bool(value))
    }

    fn visit_i64<E>(self, value: i64) -> Result<Self::Value, E> {
        Ok(Value::Number(Number::from(value)))
    }

    fn visit_u64<E>(self, value: u64) -> Result<Self::Value, E> {
        Ok(Value::Number(Number::from(value)))
    }

    fn visit_f64<E>(self, value: f64) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        Number::from_f64(value)
            .map(Value::Number)
            .ok_or_else(|| E::custom("non-finite number"))
    }

    fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        Ok(Value::String(value.to_owned()))
    }

    fn visit_string<E>(self, value: String) -> Result<Self::Value, E> {
        Ok(Value::String(value))
    }

    fn visit_none<E>(self) -> Result<Self::Value, E> {
        Ok(Value::Null)
    }

    fn visit_unit<E>(self) -> Result<Self::Value, E> {
        Ok(Value::Null)
    }

    fn visit_seq<A>(self, mut sequence: A) -> Result<Self::Value, A::Error>
    where
        A: SeqAccess<'de>,
    {
        let mut values = Vec::new();
        while let Some(value) = sequence.next_element_seed(StrictSeed)? {
            values.push(value);
        }
        Ok(Value::Array(values))
    }

    fn visit_map<A>(self, mut input: A) -> Result<Self::Value, A::Error>
    where
        A: MapAccess<'de>,
    {
        let mut values = Map::new();
        while let Some(key) = input.next_key::<String>()? {
            if values.contains_key(&key) {
                return Err(serde::de::Error::custom("duplicate JSON key"));
            }
            values.insert(key, input.next_value_seed(StrictSeed)?);
        }
        Ok(Value::Object(values))
    }
}

struct StrictSeed;

impl<'de> serde::de::DeserializeSeed<'de> for StrictSeed {
    type Value = Value;

    fn deserialize<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_any(StrictJsonVisitor)
    }
}

fn object(value: &Value) -> Result<&Map<String, Value>, AuthorityError> {
    value.as_object().ok_or(AuthorityError::Malformed)
}

fn required_string<'a>(
    object: &'a Map<String, Value>,
    key: &str,
) -> Result<&'a str, AuthorityError> {
    object
        .get(key)
        .and_then(Value::as_str)
        .ok_or(AuthorityError::Malformed)
}

fn reject_unknown(object: &Map<String, Value>, allowed: &[&str]) -> Result<(), AuthorityError> {
    if object.keys().any(|key| !allowed.contains(&key.as_str())) {
        Err(AuthorityError::Malformed)
    } else {
        Ok(())
    }
}

#[derive(Debug, Clone, Eq, PartialEq)]
struct ResolvedPdsService {
    service_id: String,
    origin: CanonicalOrigin,
}

pub fn parse_did_document(
    expected_did: &str,
    bytes: &[u8],
) -> Result<CanonicalOrigin, AuthorityError> {
    Ok(parse_did_document_service(expected_did, bytes)?.origin)
}

fn parse_did_document_service(
    expected_did: &str,
    bytes: &[u8],
) -> Result<ResolvedPdsService, AuthorityError> {
    if !validate_bare_did(expected_did) {
        return Err(AuthorityError::Malformed);
    }
    let value = strict_json(bytes)?;
    let root = object(&value)?;
    if required_string(root, "id")? != expected_did {
        return Err(AuthorityError::Malformed);
    }
    let services = root
        .get("service")
        .and_then(Value::as_array)
        .ok_or(AuthorityError::Malformed)?;
    let short_id = "#atproto_pds";
    let full_id = format!("{expected_did}#atproto_pds");
    let mut endpoint = None;
    for service in services {
        let service = object(service)?;
        let id = required_string(service, "id")?;
        if id != short_id && id != full_id {
            continue;
        }
        if endpoint.is_some() || required_string(service, "type")? != "AtprotoPersonalDataServer" {
            return Err(AuthorityError::Malformed);
        }
        let raw_endpoint = required_string(service, "serviceEndpoint")?;
        endpoint = Some(ResolvedPdsService {
            service_id: id.to_owned(),
            origin: CanonicalOrigin::parse(raw_endpoint).map_err(|_| AuthorityError::Malformed)?,
        });
    }
    endpoint.ok_or(AuthorityError::Malformed)
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum IncomingPolicy {
    All,
    None,
    Following,
}

impl IncomingPolicy {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::All => "all",
            Self::None => "none",
            Self::Following => "following",
        }
    }

    fn parse(value: &str) -> Result<Self, AuthorityError> {
        match value {
            "all" => Ok(Self::All),
            "none" => Ok(Self::None),
            "following" => Ok(Self::Following),
            _ => Err(AuthorityError::Malformed),
        }
    }
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct DeclarationRecord {
    incoming: IncomingPolicy,
    group: IncomingPolicy,
    allow_group_invites: Option<IncomingPolicy>,
    absent: bool,
    cid: Option<String>,
}

impl DeclarationRecord {
    pub fn incoming(&self) -> IncomingPolicy {
        self.incoming
    }

    pub fn group(&self) -> IncomingPolicy {
        self.group
    }

    pub fn is_absent(&self) -> bool {
        self.absent
    }
}

pub fn parse_declaration_response(
    recipient: &str,
    status: u16,
    bytes: &[u8],
) -> Result<DeclarationRecord, AuthorityError> {
    if !validate_bare_did(recipient) {
        return Err(AuthorityError::Malformed);
    }
    let value = strict_json(bytes)?;
    let root = object(&value)?;
    if status != 200 {
        if status != 400 && status != 404 {
            return Err(AuthorityError::Unavailable);
        }
        reject_unknown(root, &["error", "message"])?;
        if required_string(root, "error")? != "RecordNotFound" {
            return Err(AuthorityError::Unavailable);
        }
        if let Some(message) = root.get("message") {
            if !message.is_string() {
                return Err(AuthorityError::Malformed);
            }
        }
        return Ok(DeclarationRecord {
            incoming: IncomingPolicy::Following,
            group: IncomingPolicy::Following,
            allow_group_invites: None,
            absent: true,
            cid: None,
        });
    }
    reject_unknown(root, &["uri", "cid", "value"])?;
    let expected_uri = format!("at://{recipient}/{DECLARATION_COLLECTION}/{DECLARATION_RKEY}");
    if required_string(root, "uri")? != expected_uri {
        return Err(AuthorityError::Malformed);
    }
    let cid = match root.get("cid") {
        Some(value) => {
            let value = value.as_str().ok_or(AuthorityError::Malformed)?;
            if !valid_cid(value) {
                return Err(AuthorityError::Malformed);
            }
            Some(value.to_owned())
        }
        None => None,
    };
    let record = root
        .get("value")
        .ok_or(AuthorityError::Malformed)
        .and_then(object)?;
    reject_unknown(record, &["$type", "allowIncoming", "allowGroupInvites"])?;
    if required_string(record, "$type")? != DECLARATION_TYPE {
        return Err(AuthorityError::Malformed);
    }
    let incoming = IncomingPolicy::parse(required_string(record, "allowIncoming")?)?;
    let allow_group_invites = record
        .get("allowGroupInvites")
        .map(|value| IncomingPolicy::parse(value.as_str().ok_or(AuthorityError::Malformed)?))
        .transpose()?;
    let group = allow_group_invites.unwrap_or(incoming);
    Ok(DeclarationRecord {
        incoming,
        group,
        allow_group_invites,
        absent: false,
        cid,
    })
}

fn valid_cid(cid: &str) -> bool {
    if !(2..=128).contains(&cid.len()) || !cid.is_ascii() {
        return false;
    }
    IpldCid::try_from(cid).is_ok_and(|parsed| parsed.to_string() == cid)
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct GraphRelation {
    pub actor: String,
    pub target: String,
    pub following: bool,
    pub followed_by: bool,
    pub blocking: bool,
    pub blocked_by: bool,
    pub blocking_by_list: bool,
    pub blocked_by_list: bool,
}

impl GraphRelation {
    fn is_blocked(&self) -> bool {
        self.blocking || self.blocked_by || self.blocking_by_list || self.blocked_by_list
    }
}

pub fn parse_graph_response(
    actor: &str,
    requested_targets: &[String],
    bytes: &[u8],
) -> Result<Vec<GraphRelation>, AuthorityError> {
    if !validate_bare_did(actor)
        || requested_targets.is_empty()
        || requested_targets.len() > GRAPH_OTHERS_MAX
    {
        return Err(AuthorityError::Malformed);
    }
    let expected: BTreeSet<_> = requested_targets.iter().cloned().collect();
    if expected.len() != requested_targets.len()
        || expected
            .iter()
            .any(|target| !validate_bare_did(target) || target == actor)
    {
        return Err(AuthorityError::Malformed);
    }
    let value = strict_json(bytes)?;
    let root = object(&value)?;
    reject_unknown(root, &["actor", "relationships"])?;
    if let Some(returned_actor) = root.get("actor") {
        if returned_actor.as_str() != Some(actor) {
            return Err(AuthorityError::Malformed);
        }
    }
    let rows = root
        .get("relationships")
        .and_then(Value::as_array)
        .ok_or(AuthorityError::Malformed)?;
    if rows.len() != expected.len() {
        return Err(AuthorityError::Malformed);
    }
    let mut parsed = BTreeMap::new();
    for row in rows {
        let row = object(row)?;
        reject_unknown(
            row,
            &[
                "$type",
                "did",
                "following",
                "followedBy",
                "blocking",
                "blockedBy",
                "blockingByList",
                "blockedByList",
            ],
        )?;
        if required_string(row, "$type")? != RELATIONSHIP_TYPE {
            return Err(AuthorityError::Malformed);
        }
        let target = required_string(row, "did")?;
        if !expected.contains(target) || parsed.contains_key(target) {
            return Err(AuthorityError::Malformed);
        }
        let relation = GraphRelation {
            actor: actor.to_owned(),
            target: target.to_owned(),
            following: optional_policy_uri(row, "following")?,
            followed_by: optional_policy_uri(row, "followedBy")?,
            blocking: optional_policy_uri(row, "blocking")?,
            blocked_by: optional_policy_uri(row, "blockedBy")?,
            blocking_by_list: optional_policy_uri(row, "blockingByList")?,
            blocked_by_list: optional_policy_uri(row, "blockedByList")?,
        };
        parsed.insert(target.to_owned(), relation);
    }
    requested_targets
        .iter()
        .map(|target| parsed.remove(target).ok_or(AuthorityError::Malformed))
        .collect()
}

fn optional_policy_uri(object: &Map<String, Value>, key: &str) -> Result<bool, AuthorityError> {
    match object.get(key) {
        None => Ok(false),
        Some(value) => {
            let uri = value.as_str().ok_or(AuthorityError::Malformed)?;
            if !valid_policy_at_uri(uri) {
                return Err(AuthorityError::Malformed);
            }
            Ok(true)
        }
    }
}

fn valid_policy_at_uri(uri: &str) -> bool {
    if !uri.is_ascii()
        || uri.len() > 2_048
        || uri
            .bytes()
            .any(|byte| byte.is_ascii_control() || byte.is_ascii_whitespace())
        || uri.contains(['%', '?', '#', '\\'])
    {
        return false;
    }
    let Some(rest) = uri.strip_prefix("at://") else {
        return false;
    };
    let components: Vec<_> = rest.split('/').collect();
    if components.len() != 3 {
        return false;
    }
    let authority = components[0];
    if !validate_bare_did(authority) && !validate_public_hostname(authority) {
        return false;
    }
    valid_nsid(components[1]) && valid_record_key(components[2])
}

fn valid_nsid(nsid: &str) -> bool {
    if nsid.is_empty() || nsid.len() > 317 || !nsid.is_ascii() {
        return false;
    }
    let Some((authority, name)) = nsid.rsplit_once('.') else {
        return false;
    };
    if authority.len() > 253
        || authority.split('.').count() < 2
        || name.is_empty()
        || name.len() > 63
        || !name.as_bytes()[0].is_ascii_alphabetic()
        || !name.bytes().all(|byte| byte.is_ascii_alphanumeric())
    {
        return false;
    }
    authority.split('.').enumerate().all(|(index, label)| {
        !label.is_empty()
            && label.len() <= 63
            && label.as_bytes()[0].is_ascii_alphanumeric()
            && (index != 0 || label.as_bytes()[0].is_ascii_alphabetic())
            && label.as_bytes()[label.len() - 1].is_ascii_alphanumeric()
            && label
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
    })
}

fn valid_record_key(rkey: &str) -> bool {
    (1..=512).contains(&rkey.len())
        && rkey != "."
        && rkey != ".."
        && rkey.is_ascii()
        && rkey.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b':' | b'~' | b'-')
        })
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum AdmissionOperation {
    Direct,
    Group,
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct AdmissionRequest {
    pub inviter: String,
    pub roster: Vec<String>,
    pub pending_recipients: Vec<String>,
    pub operation: AdmissionOperation,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq, Ord, PartialOrd)]
pub enum EvidenceKind {
    Live,
    Fallback,
}

impl EvidenceKind {
    pub(crate) const fn as_persisted_str(self) -> &'static str {
        match self {
            Self::Live => "live",
            Self::Fallback => "fallback",
        }
    }

    pub(crate) fn from_persisted_str(value: &str) -> Result<Self, ProjectionPersistenceError> {
        match value {
            "live" => Ok(Self::Live),
            "fallback" => Ok(Self::Fallback),
            _ => Err(ProjectionPersistenceError::Invalid),
        }
    }
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub(crate) enum ProjectionOperationScope {
    Creation,
    PendingAdd,
    Acceptance,
    RecoveryReservation,
    RecoveryFulfillment,
    Traffic,
}

impl ProjectionOperationScope {
    pub(crate) const fn as_persisted_str(self) -> &'static str {
        match self {
            Self::Creation => "creation",
            Self::PendingAdd => "pendingAdd",
            Self::Acceptance => "acceptance",
            Self::RecoveryReservation => "recoveryReservation",
            Self::RecoveryFulfillment => "recoveryFulfillment",
            Self::Traffic => "traffic",
        }
    }

    pub(crate) fn from_persisted_str(value: &str) -> Result<Self, ProjectionPersistenceError> {
        match value {
            "creation" => Ok(Self::Creation),
            "pendingAdd" => Ok(Self::PendingAdd),
            "acceptance" => Ok(Self::Acceptance),
            "recoveryReservation" => Ok(Self::RecoveryReservation),
            "recoveryFulfillment" => Ok(Self::RecoveryFulfillment),
            "traffic" => Ok(Self::Traffic),
            _ => Err(ProjectionPersistenceError::Invalid),
        }
    }
}

#[derive(Debug, Clone, Eq, PartialEq)]
struct DeclarationEvidence {
    projection_id: Uuid,
    recipient: String,
    incoming: IncomingPolicy,
    group: IncomingPolicy,
    allow_group_invites: Option<IncomingPolicy>,
    absent: bool,
    cid: Option<String>,
    service_id: String,
    resolved_pds_origin: CanonicalOrigin,
    did_request_digest: [u8; 32],
    did_document_digest: [u8; 32],
    record_request_digest: [u8; 32],
    record_response_digest: [u8; 32],
    fetch_revision: u64,
    fetched_at: DateTime<Utc>,
    evidence_kind: EvidenceKind,
}

#[derive(Debug, Clone, Eq, PartialEq)]
struct GraphBatchEvidence {
    projection_id: Uuid,
    actor: String,
    targets: Vec<String>,
    relationships: Vec<GraphRelation>,
    request_digest: [u8; 32],
    response_digest: [u8; 32],
    fetch_revision: u64,
    fetched_at: DateTime<Utc>,
    evidence_kind: EvidenceKind,
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub enum ProjectionScope {
    Admission(AdmissionRequest),
    BlockOnly(AdmissionGraphScope),
}

#[derive(Debug)]
#[cfg_attr(test, derive(Clone, PartialEq))]
pub struct RelationshipProjection {
    projection_id: Uuid,
    operation_scope: ProjectionOperationScope,
    scope: ProjectionScope,
    scope_digest: [u8; 32],
    appview_base: CanonicalOrigin,
    config_fingerprint: [u8; 32],
    source_identity: [u8; 32],
    projection_revision: u64,
    persistence_authority: ProjectionPersistenceAuthority,
    source_call_count: u64,
    started_at: DateTime<Utc>,
    completed_at: DateTime<Utc>,
    evidence_kind: EvidenceKind,
    declarations: Vec<DeclarationEvidence>,
    graph_batches: Vec<GraphBatchEvidence>,
    evidence_digest: [u8; 32],
}

#[derive(Debug)]
#[cfg_attr(test, derive(Clone, PartialEq))]
pub struct TrafficProjection {
    projection_id: Uuid,
    operation_scope: ProjectionOperationScope,
    scope: TrafficGraphScope,
    scope_digest: [u8; 32],
    appview_base: CanonicalOrigin,
    config_fingerprint: [u8; 32],
    source_identity: [u8; 32],
    projection_revision: u64,
    persistence_authority: ProjectionPersistenceAuthority,
    source_call_count: u64,
    started_at: DateTime<Utc>,
    completed_at: DateTime<Utc>,
    evidence_kind: EvidenceKind,
    graph_batches: Vec<GraphBatchEvidence>,
    evidence_digest: [u8; 32],
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct ProjectionRefreshFailure {
    started_at: DateTime<Utc>,
    failure_count: usize,
}

/// Linear persistence authority retained by a freshly collected projection.
/// Hydrated projections carry an empty authority and therefore cannot be
/// re-persisted. The mutex permits the public projection to remain borrowable
/// after sealing while still atomically consuming the one exact allocation.
#[derive(Debug)]
struct ProjectionPersistenceAuthority(Mutex<Option<AllocatedProjectionRevisionGuard>>);

impl ProjectionPersistenceAuthority {
    fn allocated(guard: AllocatedProjectionRevisionGuard) -> Self {
        Self(Mutex::new(Some(guard)))
    }

    fn hydrated() -> Self {
        Self(Mutex::new(None))
    }

    fn take(&self) -> Option<AllocatedProjectionRevisionGuard> {
        self.0.lock().ok()?.take()
    }
}

#[cfg(test)]
impl Clone for ProjectionPersistenceAuthority {
    fn clone(&self) -> Self {
        let guard = self.0.lock().expect("test authority lock");
        if guard.is_some() {
            panic!("AllocatedProjectionRevisionGuard is linear and cannot be cloned");
        }
        Self(Mutex::new(None))
    }
}

#[cfg(test)]
impl PartialEq for ProjectionPersistenceAuthority {
    fn eq(&self, other: &Self) -> bool {
        let left = self.0.lock().expect("test authority lock");
        let right = other.0.lock().expect("test authority lock");
        left.is_some() == right.is_some()
    }
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub(crate) enum ProjectionPersistenceError {
    Invalid,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub(crate) enum DeclarationRecordEvidenceKind {
    RecordPresent,
    StructuredRecordNotFound,
}

impl DeclarationRecordEvidenceKind {
    pub(crate) const fn as_persisted_str(self) -> &'static str {
        match self {
            Self::RecordPresent => "recordPresent",
            Self::StructuredRecordNotFound => "structuredRecordNotFound",
        }
    }

    pub(crate) fn from_persisted_str(value: &str) -> Result<Self, ProjectionPersistenceError> {
        match value {
            "recordPresent" => Ok(Self::RecordPresent),
            "structuredRecordNotFound" => Ok(Self::StructuredRecordNotFound),
            _ => Err(ProjectionPersistenceError::Invalid),
        }
    }
}

macro_rules! define_persisted_projection_types {
    ($field_visibility:vis) => {
        #[derive(Debug, Clone, Eq, PartialEq)]
        pub(crate) struct PersistedDeclarationEvidence {
            $field_visibility projection_id: String,
            $field_visibility recipient: String,
            $field_visibility incoming: IncomingPolicy,
            $field_visibility allow_group_invites: Option<IncomingPolicy>,
            $field_visibility resolved_group_policy: IncomingPolicy,
            $field_visibility record_evidence_kind: DeclarationRecordEvidenceKind,
            $field_visibility cid: Option<String>,
            $field_visibility service_id: String,
            $field_visibility resolved_pds_origin: String,
            $field_visibility did_request_digest: [u8; 32],
            $field_visibility did_document_digest: [u8; 32],
            $field_visibility record_request_digest: [u8; 32],
            $field_visibility record_response_digest: [u8; 32],
            $field_visibility fetch_revision: u64,
            $field_visibility fetched_at: DateTime<Utc>,
            $field_visibility evidence_kind: EvidenceKind,
        }

        #[derive(Debug, Clone, Eq, PartialEq)]
        pub(crate) struct PersistedGraphRelationshipEvidence {
            $field_visibility projection_id: String,
            $field_visibility actor: String,
            $field_visibility target: String,
            $field_visibility batch_ordinal: u16,
            $field_visibility following: bool,
            $field_visibility followed_by: bool,
            $field_visibility blocking: bool,
            $field_visibility blocked_by: bool,
            $field_visibility blocking_by_list: bool,
            $field_visibility blocked_by_list: bool,
            $field_visibility request_digest: [u8; 32],
            $field_visibility response_digest: [u8; 32],
            $field_visibility fetch_revision: u64,
            $field_visibility fetched_at: DateTime<Utc>,
            $field_visibility evidence_kind: EvidenceKind,
        }

        #[derive(Debug, Clone, Eq, PartialEq)]
        pub(crate) struct PersistedRelationshipProjection {
            $field_visibility projection_id: String,
            $field_visibility operation_scope: ProjectionOperationScope,
            $field_visibility scope: ProjectionScope,
            $field_visibility scope_digest: [u8; 32],
            $field_visibility canonical_did_set_bytes: Vec<u8>,
            $field_visibility canonical_did_set_sha256: [u8; 32],
            $field_visibility appview_base: String,
            $field_visibility configuration_fingerprint: [u8; 32],
            $field_visibility projection_revision: u64,
            $field_visibility source_call_count: u64,
            $field_visibility started_at: DateTime<Utc>,
            $field_visibility completed_at: DateTime<Utc>,
            $field_visibility evidence_kind: EvidenceKind,
            $field_visibility declarations: Vec<PersistedDeclarationEvidence>,
            $field_visibility relationships: Vec<PersistedGraphRelationshipEvidence>,
            $field_visibility aggregate_evidence_bytes: Vec<u8>,
            $field_visibility aggregate_evidence_sha256: [u8; 32],
        }

        #[derive(Debug, Clone, Eq, PartialEq)]
        pub(crate) struct PersistedTrafficProjection {
            $field_visibility projection_id: String,
            $field_visibility operation_scope: ProjectionOperationScope,
            $field_visibility scope: TrafficGraphScope,
            $field_visibility scope_digest: [u8; 32],
            $field_visibility canonical_did_set_bytes: Vec<u8>,
            $field_visibility canonical_did_set_sha256: [u8; 32],
            $field_visibility appview_base: String,
            $field_visibility configuration_fingerprint: [u8; 32],
            $field_visibility projection_revision: u64,
            $field_visibility source_call_count: u64,
            $field_visibility started_at: DateTime<Utc>,
            $field_visibility completed_at: DateTime<Utc>,
            $field_visibility evidence_kind: EvidenceKind,
            $field_visibility relationships: Vec<PersistedGraphRelationshipEvidence>,
            $field_visibility aggregate_evidence_bytes: Vec<u8>,
            $field_visibility aggregate_evidence_sha256: [u8; 32],
        }
    };
}

#[cfg(not(test))]
define_persisted_projection_types!(pub(super));
#[cfg(test)]
define_persisted_projection_types!(pub(crate));

/// Only this non-Clone value can cross the repository's insert boundary. Its
/// allocation identity is private and is paired with values derived from the
/// exact projection that consumed the corresponding SQL allocation guard.
#[derive(Debug)]
#[cfg_attr(test, derive(Clone))]
pub(crate) struct SealedRelationshipProjection {
    allocation_id: Uuid,
    values: PersistedRelationshipProjection,
}

#[derive(Debug)]
#[cfg_attr(test, derive(Clone))]
pub(crate) struct SealedTrafficProjection {
    allocation_id: Uuid,
    values: PersistedTrafficProjection,
}

impl SealedRelationshipProjection {
    pub(super) fn into_parts(self) -> (Uuid, PersistedRelationshipProjection) {
        (self.allocation_id, self.values)
    }
}

impl SealedTrafficProjection {
    pub(super) fn into_parts(self) -> (Uuid, PersistedTrafficProjection) {
        (self.allocation_id, self.values)
    }
}

// Corruption tests exercise the strict hydration and SQL-validation fences.
// Production has no Clone or field access for either sealed projection.
#[cfg(test)]
macro_rules! impl_sealed_projection_test_access {
    ($sealed:ident, $values:ident) => {
        impl std::ops::Deref for $sealed {
            type Target = $values;

            fn deref(&self) -> &Self::Target {
                &self.values
            }
        }

        impl std::ops::DerefMut for $sealed {
            fn deref_mut(&mut self) -> &mut Self::Target {
                &mut self.values
            }
        }

        impl From<$sealed> for $values {
            fn from(sealed: $sealed) -> Self {
                sealed.values
            }
        }
    };
}

#[cfg(test)]
impl_sealed_projection_test_access!(
    SealedRelationshipProjection,
    PersistedRelationshipProjection
);
#[cfg(test)]
impl_sealed_projection_test_access!(SealedTrafficProjection, PersistedTrafficProjection);

impl ProjectionRefreshFailure {
    fn new(started_at: DateTime<Utc>, failure_count: usize) -> Self {
        Self {
            started_at,
            failure_count: failure_count.max(1),
        }
    }

    pub fn started_at(&self) -> DateTime<Utc> {
        self.started_at
    }

    pub fn failure_count(&self) -> usize {
        self.failure_count
    }
}

impl RelationshipProjection {
    pub fn projection_id(&self) -> Uuid {
        self.projection_id
    }

    pub fn scope(&self) -> &ProjectionScope {
        &self.scope
    }

    pub(crate) fn operation_scope(&self) -> ProjectionOperationScope {
        self.operation_scope
    }

    pub fn projection_revision(&self) -> u64 {
        self.projection_revision
    }

    pub fn started_at(&self) -> DateTime<Utc> {
        self.started_at
    }

    pub fn completed_at(&self) -> DateTime<Utc> {
        self.completed_at
    }

    pub fn declaration_count(&self) -> usize {
        self.declarations.len()
    }

    pub fn graph_batch_count(&self) -> usize {
        self.graph_batches.len()
    }

    pub fn evidence_digest(&self) -> [u8; 32] {
        self.evidence_digest
    }

    fn integrity_valid(&self) -> bool {
        uuid_is_canonical_v4(self.projection_id)
            && relationship_operation_scope_matches(self.operation_scope, &self.scope)
            && self.appview_base.as_str() != ""
            && self.source_identity != [0; 32]
            && persisted_revision_valid(self.projection_revision)
            && persisted_time_is_canonical(self.started_at)
            && persisted_time_is_canonical(self.completed_at)
            && self.source_call_count == relationship_source_call_count(self)
            && self.declarations.iter().all(|row| {
                row.projection_id == self.projection_id
                    && persisted_revision_valid(row.fetch_revision)
                    && persisted_time_is_canonical(row.fetched_at)
            })
            && self.graph_batches.iter().all(|row| {
                row.projection_id == self.projection_id
                    && persisted_revision_valid(row.fetch_revision)
                    && persisted_time_is_canonical(row.fetched_at)
            })
            && self.evidence_digest == relationship_evidence_digest(self)
    }

    pub(crate) fn export_persisted<T: PublicTransport>(
        &self,
        authority: &RelationshipAuthority<T>,
        persistence_observation: &TrustedRelationshipPersistenceInstant,
    ) -> Result<SealedRelationshipProjection, ProjectionPersistenceError> {
        if !relationship_projection_persistence_valid(
            self,
            self.operation_scope,
            &self.scope,
            authority,
            persistence_observation,
        ) {
            return Err(ProjectionPersistenceError::Invalid);
        }
        let values = persist_relationship_projection(self)?;
        let allocation = self
            .persistence_authority
            .take()
            .ok_or(ProjectionPersistenceError::Invalid)?;
        let (allocation_id, projection_revision) = allocation.into_allocation();
        if projection_revision != values.projection_revision {
            return Err(ProjectionPersistenceError::Invalid);
        }
        Ok(SealedRelationshipProjection {
            allocation_id,
            values,
        })
    }

    pub(crate) fn export_persisted_fallback<T: PublicTransport>(
        &self,
        allocated_revision: AllocatedProjectionRevisionGuard,
        authority: &RelationshipAuthority<T>,
        persistence_observation: &TrustedRelationshipPersistenceInstant,
    ) -> Result<SealedRelationshipProjection, ProjectionPersistenceError> {
        if self.evidence_kind != EvidenceKind::Live {
            return Err(ProjectionPersistenceError::Invalid);
        }
        if !relationship_projection_persistence_valid(
            self,
            self.operation_scope,
            &self.scope,
            authority,
            persistence_observation,
        ) {
            return Err(ProjectionPersistenceError::Invalid);
        }
        let fallback_revision = allocated_revision.projection_revision();
        let mut fallback = RelationshipProjection {
            projection_id: Uuid::new_v4(),
            operation_scope: self.operation_scope,
            scope: self.scope.clone(),
            scope_digest: self.scope_digest,
            appview_base: self.appview_base.clone(),
            config_fingerprint: self.config_fingerprint,
            source_identity: self.source_identity,
            projection_revision: fallback_revision,
            persistence_authority: ProjectionPersistenceAuthority::hydrated(),
            source_call_count: self.source_call_count,
            started_at: self.started_at,
            completed_at: self.completed_at,
            evidence_kind: EvidenceKind::Fallback,
            declarations: self.declarations.clone(),
            graph_batches: self.graph_batches.clone(),
            evidence_digest: [0; 32],
        };
        for row in &mut fallback.declarations {
            row.projection_id = fallback.projection_id;
            row.evidence_kind = EvidenceKind::Fallback;
        }
        for row in &mut fallback.graph_batches {
            row.projection_id = fallback.projection_id;
            row.evidence_kind = EvidenceKind::Fallback;
        }
        remap_relationship_fetch_revisions(&mut fallback)?;
        fallback.evidence_digest = relationship_evidence_digest(&fallback);
        if !relationship_projection_persistence_valid(
            &fallback,
            fallback.operation_scope,
            &fallback.scope,
            authority,
            persistence_observation,
        ) {
            return Err(ProjectionPersistenceError::Invalid);
        }
        let values = persist_relationship_projection(&fallback)?;
        let (allocation_id, projection_revision) = allocated_revision.into_allocation();
        if projection_revision != values.projection_revision {
            return Err(ProjectionPersistenceError::Invalid);
        }
        Ok(SealedRelationshipProjection {
            allocation_id,
            values,
        })
    }
}

impl TrafficProjection {
    pub fn projection_id(&self) -> Uuid {
        self.projection_id
    }

    pub fn scope(&self) -> &TrafficGraphScope {
        &self.scope
    }

    pub(crate) fn operation_scope(&self) -> ProjectionOperationScope {
        self.operation_scope
    }

    pub fn projection_revision(&self) -> u64 {
        self.projection_revision
    }

    pub fn started_at(&self) -> DateTime<Utc> {
        self.started_at
    }

    pub fn completed_at(&self) -> DateTime<Utc> {
        self.completed_at
    }

    pub fn graph_batch_count(&self) -> usize {
        self.graph_batches.len()
    }

    pub fn evidence_digest(&self) -> [u8; 32] {
        self.evidence_digest
    }

    fn integrity_valid(&self) -> bool {
        uuid_is_canonical_v4(self.projection_id)
            && self.operation_scope == ProjectionOperationScope::Traffic
            && self.appview_base.as_str() != ""
            && self.source_identity != [0; 32]
            && persisted_revision_valid(self.projection_revision)
            && persisted_time_is_canonical(self.started_at)
            && persisted_time_is_canonical(self.completed_at)
            && self.source_call_count == traffic_source_call_count(self)
            && self.graph_batches.iter().all(|row| {
                row.projection_id == self.projection_id
                    && persisted_revision_valid(row.fetch_revision)
                    && persisted_time_is_canonical(row.fetched_at)
            })
            && self.evidence_digest == traffic_evidence_digest(self)
    }

    pub(crate) fn export_persisted<T: PublicTransport>(
        &self,
        authority: &RelationshipAuthority<T>,
        persistence_observation: &TrustedRelationshipPersistenceInstant,
    ) -> Result<SealedTrafficProjection, ProjectionPersistenceError> {
        if !traffic_projection_persistence_valid(
            self,
            &self.scope,
            authority,
            persistence_observation,
        ) {
            return Err(ProjectionPersistenceError::Invalid);
        }
        let values = persist_traffic_projection(self)?;
        let allocation = self
            .persistence_authority
            .take()
            .ok_or(ProjectionPersistenceError::Invalid)?;
        let (allocation_id, projection_revision) = allocation.into_allocation();
        if projection_revision != values.projection_revision {
            return Err(ProjectionPersistenceError::Invalid);
        }
        Ok(SealedTrafficProjection {
            allocation_id,
            values,
        })
    }

    pub(crate) fn export_persisted_fallback<T: PublicTransport>(
        &self,
        allocated_revision: AllocatedProjectionRevisionGuard,
        authority: &RelationshipAuthority<T>,
        persistence_observation: &TrustedRelationshipPersistenceInstant,
    ) -> Result<SealedTrafficProjection, ProjectionPersistenceError> {
        if self.evidence_kind != EvidenceKind::Live {
            return Err(ProjectionPersistenceError::Invalid);
        }
        if !traffic_projection_persistence_valid(
            self,
            &self.scope,
            authority,
            persistence_observation,
        ) {
            return Err(ProjectionPersistenceError::Invalid);
        }
        let fallback_revision = allocated_revision.projection_revision();
        let mut fallback = TrafficProjection {
            projection_id: Uuid::new_v4(),
            operation_scope: ProjectionOperationScope::Traffic,
            scope: self.scope.clone(),
            scope_digest: self.scope_digest,
            appview_base: self.appview_base.clone(),
            config_fingerprint: self.config_fingerprint,
            source_identity: self.source_identity,
            projection_revision: fallback_revision,
            persistence_authority: ProjectionPersistenceAuthority::hydrated(),
            source_call_count: self.source_call_count,
            started_at: self.started_at,
            completed_at: self.completed_at,
            evidence_kind: EvidenceKind::Fallback,
            graph_batches: self.graph_batches.clone(),
            evidence_digest: [0; 32],
        };
        for row in &mut fallback.graph_batches {
            row.projection_id = fallback.projection_id;
            row.evidence_kind = EvidenceKind::Fallback;
        }
        remap_traffic_fetch_revisions(&mut fallback)?;
        fallback.evidence_digest = traffic_evidence_digest(&fallback);
        if !traffic_projection_persistence_valid(
            &fallback,
            &fallback.scope,
            authority,
            persistence_observation,
        ) {
            return Err(ProjectionPersistenceError::Invalid);
        }
        let values = persist_traffic_projection(&fallback)?;
        let (allocation_id, projection_revision) = allocated_revision.into_allocation();
        if projection_revision != values.projection_revision {
            return Err(ProjectionPersistenceError::Invalid);
        }
        Ok(SealedTrafficProjection {
            allocation_id,
            values,
        })
    }
}

fn uuid_is_canonical_v4(id: Uuid) -> bool {
    id.get_version_num() == 4 && id.get_variant() == uuid::Variant::RFC4122
}

fn canonical_uuid_string(id: Uuid) -> String {
    id.hyphenated().to_string()
}

fn parse_canonical_projection_uuid(raw: &str) -> Result<Uuid, ProjectionPersistenceError> {
    let id = Uuid::parse_str(raw).map_err(|_| ProjectionPersistenceError::Invalid)?;
    if !uuid_is_canonical_v4(id) || canonical_uuid_string(id) != raw {
        return Err(ProjectionPersistenceError::Invalid);
    }
    Ok(id)
}

fn persist_declaration_evidence(row: &DeclarationEvidence) -> PersistedDeclarationEvidence {
    PersistedDeclarationEvidence {
        projection_id: canonical_uuid_string(row.projection_id),
        recipient: row.recipient.clone(),
        incoming: row.incoming,
        allow_group_invites: row.allow_group_invites,
        resolved_group_policy: row.group,
        record_evidence_kind: if row.absent {
            DeclarationRecordEvidenceKind::StructuredRecordNotFound
        } else {
            DeclarationRecordEvidenceKind::RecordPresent
        },
        cid: row.cid.clone(),
        service_id: row.service_id.clone(),
        resolved_pds_origin: row.resolved_pds_origin.as_str().to_owned(),
        did_request_digest: row.did_request_digest,
        did_document_digest: row.did_document_digest,
        record_request_digest: row.record_request_digest,
        record_response_digest: row.record_response_digest,
        fetch_revision: row.fetch_revision,
        fetched_at: row.fetched_at,
        evidence_kind: row.evidence_kind,
    }
}

fn persist_graph_evidence(row: &GraphBatchEvidence) -> Vec<PersistedGraphRelationshipEvidence> {
    row.relationships
        .iter()
        .enumerate()
        .map(
            |(target_ordinal, relationship)| PersistedGraphRelationshipEvidence {
                projection_id: canonical_uuid_string(row.projection_id),
                actor: relationship.actor.clone(),
                target: relationship.target.clone(),
                batch_ordinal: u16::try_from(target_ordinal)
                    .expect("bounded graph target ordinal fits u16"),
                following: relationship.following,
                followed_by: relationship.followed_by,
                blocking: relationship.blocking,
                blocked_by: relationship.blocked_by,
                blocking_by_list: relationship.blocking_by_list,
                blocked_by_list: relationship.blocked_by_list,
                request_digest: row.request_digest,
                response_digest: row.response_digest,
                fetch_revision: row.fetch_revision,
                fetched_at: row.fetched_at,
                evidence_kind: row.evidence_kind,
            },
        )
        .collect()
}

fn persist_relationship_projection(
    projection: &RelationshipProjection,
) -> Result<PersistedRelationshipProjection, ProjectionPersistenceError> {
    if !projection.integrity_valid() {
        return Err(ProjectionPersistenceError::Invalid);
    }
    let canonical_did_set_bytes =
        encode_canonical_did_set(relationship_scope_dids(&projection.scope))
            .ok_or(ProjectionPersistenceError::Invalid)?;
    let aggregate_evidence_bytes = canonical_persisted_relationship_evidence_bytes(projection);
    if aggregate_evidence_bytes.is_empty()
        || aggregate_evidence_bytes.len() > MAX_PERSISTED_AGGREGATE_BYTES
    {
        return Err(ProjectionPersistenceError::Invalid);
    }
    Ok(PersistedRelationshipProjection {
        projection_id: canonical_uuid_string(projection.projection_id),
        operation_scope: projection.operation_scope,
        scope: projection.scope.clone(),
        scope_digest: projection.scope_digest,
        canonical_did_set_sha256: sha256(&canonical_did_set_bytes),
        canonical_did_set_bytes,
        appview_base: projection.appview_base.as_str().to_owned(),
        configuration_fingerprint: projection.config_fingerprint,
        projection_revision: projection.projection_revision,
        source_call_count: projection.source_call_count,
        started_at: projection.started_at,
        completed_at: projection.completed_at,
        evidence_kind: projection.evidence_kind,
        declarations: projection
            .declarations
            .iter()
            .map(persist_declaration_evidence)
            .collect(),
        relationships: projection
            .graph_batches
            .iter()
            .flat_map(persist_graph_evidence)
            .collect(),
        aggregate_evidence_sha256: sha256(&aggregate_evidence_bytes),
        aggregate_evidence_bytes,
    })
}

fn persist_traffic_projection(
    projection: &TrafficProjection,
) -> Result<PersistedTrafficProjection, ProjectionPersistenceError> {
    if !projection.integrity_valid() {
        return Err(ProjectionPersistenceError::Invalid);
    }
    let canonical_did_set_bytes = encode_canonical_did_set(&projection.scope.members)
        .ok_or(ProjectionPersistenceError::Invalid)?;
    let aggregate_evidence_bytes = canonical_traffic_evidence_bytes(projection);
    if aggregate_evidence_bytes.is_empty()
        || aggregate_evidence_bytes.len() > MAX_PERSISTED_AGGREGATE_BYTES
    {
        return Err(ProjectionPersistenceError::Invalid);
    }
    Ok(PersistedTrafficProjection {
        projection_id: canonical_uuid_string(projection.projection_id),
        operation_scope: projection.operation_scope,
        scope: projection.scope.clone(),
        scope_digest: projection.scope_digest,
        canonical_did_set_sha256: sha256(&canonical_did_set_bytes),
        canonical_did_set_bytes,
        appview_base: projection.appview_base.as_str().to_owned(),
        configuration_fingerprint: projection.config_fingerprint,
        projection_revision: projection.projection_revision,
        source_call_count: projection.source_call_count,
        started_at: projection.started_at,
        completed_at: projection.completed_at,
        evidence_kind: projection.evidence_kind,
        relationships: projection
            .graph_batches
            .iter()
            .flat_map(persist_graph_evidence)
            .collect(),
        aggregate_evidence_sha256: sha256(&aggregate_evidence_bytes),
        aggregate_evidence_bytes,
    })
}

fn hydrate_declaration_evidence(
    values: PersistedDeclarationEvidence,
    projection_id: Uuid,
    expected_recipient: &str,
    expected_config: &RelationshipPolicyConfig,
    authority_kind: EvidenceKind,
    started_at: DateTime<Utc>,
    completed_at: DateTime<Utc>,
) -> Result<DeclarationEvidence, ProjectionPersistenceError> {
    let row_projection_id = parse_canonical_projection_uuid(&values.projection_id)?;
    let expected_full_service_id = format!("{}#atproto_pds", values.recipient);
    let resolved_pds_origin = CanonicalOrigin::parse(&values.resolved_pds_origin)
        .map_err(|_| ProjectionPersistenceError::Invalid)?;
    let expected_did_request_digest = request_evidence_digest(
        &did_document_url(expected_config, expected_recipient)
            .map_err(|_| ProjectionPersistenceError::Invalid)?,
    );
    let expected_record_request_digest = request_evidence_digest(
        &declaration_record_url(&resolved_pds_origin, expected_recipient)
            .map_err(|_| ProjectionPersistenceError::Invalid)?,
    );
    let absent = match values.record_evidence_kind {
        DeclarationRecordEvidenceKind::RecordPresent => false,
        DeclarationRecordEvidenceKind::StructuredRecordNotFound => true,
    };
    if row_projection_id != projection_id
        || values.recipient != expected_recipient
        || !validate_bare_did(&values.recipient)
        || (values.service_id != "#atproto_pds" && values.service_id != expected_full_service_id)
        || values.evidence_kind != authority_kind
        || values.did_request_digest == [0; 32]
        || values.did_request_digest != expected_did_request_digest
        || values.did_document_digest == [0; 32]
        || values.record_request_digest == [0; 32]
        || values.record_request_digest != expected_record_request_digest
        || values.record_response_digest == [0; 32]
        || values.fetch_revision == 0
        || values.fetched_at < started_at
        || values.fetched_at > completed_at
        || values.resolved_group_policy != values.allow_group_invites.unwrap_or(values.incoming)
        || values.cid.as_deref().is_some_and(|cid| !valid_cid(cid))
        || (absent
            && (values.cid.is_some()
                || values.incoming != IncomingPolicy::Following
                || values.allow_group_invites.is_some()
                || values.resolved_group_policy != IncomingPolicy::Following))
    {
        return Err(ProjectionPersistenceError::Invalid);
    }
    Ok(DeclarationEvidence {
        projection_id,
        recipient: values.recipient,
        incoming: values.incoming,
        group: values.resolved_group_policy,
        allow_group_invites: values.allow_group_invites,
        absent,
        cid: values.cid,
        service_id: values.service_id,
        resolved_pds_origin,
        did_request_digest: values.did_request_digest,
        did_document_digest: values.did_document_digest,
        record_request_digest: values.record_request_digest,
        record_response_digest: values.record_response_digest,
        fetch_revision: values.fetch_revision,
        fetched_at: values.fetched_at,
        evidence_kind: values.evidence_kind,
    })
}

fn hydrate_graph_evidence(
    values: Vec<PersistedGraphRelationshipEvidence>,
    expected_requests: &[GraphRequest],
    projection_id: Uuid,
    expected_config: &RelationshipPolicyConfig,
    authority_kind: EvidenceKind,
    started_at: DateTime<Utc>,
    completed_at: DateTime<Utc>,
) -> Result<Vec<GraphBatchEvidence>, ProjectionPersistenceError> {
    let expected_row_count: usize = expected_requests
        .iter()
        .map(|request| request.others.len())
        .sum();
    if values.len() != expected_row_count {
        return Err(ProjectionPersistenceError::Invalid);
    }
    let mut batches = BTreeMap::<u64, Vec<PersistedGraphRelationshipEvidence>>::new();
    for row in values {
        batches.entry(row.fetch_revision).or_default().push(row);
    }
    if batches.len() != expected_requests.len() {
        return Err(ProjectionPersistenceError::Invalid);
    }
    for (fetch_revision, rows) in &mut batches {
        if *fetch_revision == 0 || rows.is_empty() || rows.len() > GRAPH_OTHERS_MAX {
            return Err(ProjectionPersistenceError::Invalid);
        }
        rows.sort_by_key(|row| row.batch_ordinal);
        let binding = (
            rows[0].actor.clone(),
            rows[0].request_digest,
            rows[0].response_digest,
            rows[0].fetched_at,
        );
        for (target_ordinal, row) in rows.iter().enumerate() {
            let row_projection_id = parse_canonical_projection_uuid(&row.projection_id)?;
            if row_projection_id != projection_id
                || row.fetch_revision != *fetch_revision
                || row.actor != binding.0
                || usize::from(row.batch_ordinal) != target_ordinal
                || row.evidence_kind != authority_kind
                || row.request_digest == [0; 32]
                || row.request_digest != binding.1
                || row.response_digest == [0; 32]
                || row.response_digest != binding.2
                || row.fetched_at != binding.3
                || row.fetched_at < started_at
                || row.fetched_at > completed_at
            {
                return Err(ProjectionPersistenceError::Invalid);
            }
        }
    }
    let mut result = Vec::with_capacity(expected_requests.len());
    for request in expected_requests {
        if request.others.is_empty() || request.others.len() > GRAPH_OTHERS_MAX {
            return Err(ProjectionPersistenceError::Invalid);
        }
        let matching_revisions = batches
            .iter()
            .filter_map(|(fetch_revision, rows)| {
                (rows.len() == request.others.len()
                    && rows[0].actor == request.actor
                    && rows
                        .iter()
                        .zip(&request.others)
                        .all(|(row, target)| row.target == *target))
                .then_some(*fetch_revision)
            })
            .collect::<Vec<_>>();
        if matching_revisions.len() != 1 {
            return Err(ProjectionPersistenceError::Invalid);
        }
        let rows = batches
            .remove(&matching_revisions[0])
            .ok_or(ProjectionPersistenceError::Invalid)?;
        let expected_request_digest = request_evidence_digest(
            &graph_request_url(&expected_config.appview_origin, request)
                .map_err(|_| ProjectionPersistenceError::Invalid)?,
        );
        let fetch_revision = matching_revisions[0];
        let request_digest = rows[0].request_digest;
        let response_digest = rows[0].response_digest;
        let fetched_at = rows[0].fetched_at;
        if request_digest != expected_request_digest {
            return Err(ProjectionPersistenceError::Invalid);
        }
        let relationships = rows
            .into_iter()
            .map(|row| GraphRelation {
                actor: row.actor,
                target: row.target,
                following: row.following,
                followed_by: row.followed_by,
                blocking: row.blocking,
                blocked_by: row.blocked_by,
                blocking_by_list: row.blocking_by_list,
                blocked_by_list: row.blocked_by_list,
            })
            .collect();
        result.push(GraphBatchEvidence {
            projection_id,
            actor: request.actor.clone(),
            targets: request.others.clone(),
            relationships,
            request_digest,
            response_digest,
            fetch_revision,
            fetched_at,
            evidence_kind: authority_kind,
        });
    }
    if !batches.is_empty() {
        return Err(ProjectionPersistenceError::Invalid);
    }
    Ok(result)
}

fn hydrate_persisted_relationship_projection_with_kind<T: PublicTransport>(
    values: PersistedRelationshipProjection,
    expected_evidence_kind: EvidenceKind,
    expected_operation_scope: ProjectionOperationScope,
    expected_scope: &ProjectionScope,
    authority: &RelationshipAuthority<T>,
    decision: &TrustedRelationshipDecisionInstant,
) -> Result<RelationshipProjection, ProjectionPersistenceError> {
    let expected_did_set_bytes = encode_canonical_did_set(relationship_scope_dids(&values.scope))
        .ok_or(ProjectionPersistenceError::Invalid)?;
    if values.operation_scope != expected_operation_scope
        || &values.scope != expected_scope
        || values.evidence_kind != expected_evidence_kind
        || !relationship_operation_scope_matches(values.operation_scope, &values.scope)
        || values.scope_digest != projection_scope_digest(&values.scope)
        || values.appview_base != authority.config.appview_origin.as_str()
        || values.configuration_fingerprint != authority.config.fingerprint
        || values.canonical_did_set_bytes.is_empty()
        || values.canonical_did_set_sha256 != sha256(&values.canonical_did_set_bytes)
        || values.canonical_did_set_bytes != expected_did_set_bytes
        || values.aggregate_evidence_bytes.is_empty()
        || values.aggregate_evidence_bytes.len() > MAX_PERSISTED_AGGREGATE_BYTES
        || values.aggregate_evidence_sha256 != sha256(&values.aggregate_evidence_bytes)
    {
        return Err(ProjectionPersistenceError::Invalid);
    }
    let expected_requests = relationship_scope_graph_requests(&values.scope)?;
    let expected_recipients = relationship_scope_declaration_recipients(&values.scope);
    if values.declarations.len() != expected_recipients.len() {
        return Err(ProjectionPersistenceError::Invalid);
    }
    let projection_id = parse_canonical_projection_uuid(&values.projection_id)?;
    let mut declaration_rows = BTreeMap::new();
    for row in values.declarations {
        if declaration_rows
            .insert(row.recipient.clone(), row)
            .is_some()
        {
            return Err(ProjectionPersistenceError::Invalid);
        }
    }
    let declarations = expected_recipients
        .iter()
        .map(|recipient| {
            let row = declaration_rows
                .remove(recipient.as_str())
                .ok_or(ProjectionPersistenceError::Invalid)?;
            hydrate_declaration_evidence(
                row,
                projection_id,
                recipient,
                &authority.config,
                values.evidence_kind,
                values.started_at,
                values.completed_at,
            )
        })
        .collect::<Result<Vec<_>, _>>()?;
    if !declaration_rows.is_empty() {
        return Err(ProjectionPersistenceError::Invalid);
    }
    let graph_batches = hydrate_graph_evidence(
        values.relationships,
        &expected_requests,
        projection_id,
        &authority.config,
        values.evidence_kind,
        values.started_at,
        values.completed_at,
    )?;
    let projection = RelationshipProjection {
        projection_id,
        operation_scope: values.operation_scope,
        scope: values.scope,
        scope_digest: values.scope_digest,
        appview_base: CanonicalOrigin::parse(&values.appview_base)
            .map_err(|_| ProjectionPersistenceError::Invalid)?,
        config_fingerprint: values.configuration_fingerprint,
        source_identity: authority.source_identity,
        projection_revision: values.projection_revision,
        persistence_authority: ProjectionPersistenceAuthority::hydrated(),
        source_call_count: values.source_call_count,
        started_at: values.started_at,
        completed_at: values.completed_at,
        evidence_kind: values.evidence_kind,
        declarations,
        graph_batches,
        evidence_digest: [0; 32],
    };
    let mut projection = projection;
    projection.evidence_digest = relationship_evidence_digest(&projection);
    if canonical_persisted_relationship_evidence_bytes(&projection)
        != values.aggregate_evidence_bytes
    {
        return Err(ProjectionPersistenceError::Invalid);
    }
    if !relationship_projection_fence_valid(
        &projection,
        projection.operation_scope,
        &projection.scope,
        authority,
        decision,
    ) {
        return Err(ProjectionPersistenceError::Invalid);
    }
    Ok(projection)
}

#[cfg(test)]
pub(crate) fn hydrate_persisted_live_relationship_projection<
    T: PublicTransport,
    V: Into<PersistedRelationshipProjection>,
>(
    values: V,
    load_guard: RelationshipProjectionLoadGuard,
    authority: &RelationshipAuthority<T>,
    decision: &TrustedRelationshipDecisionInstant,
) -> Result<RelationshipProjection, ProjectionPersistenceError> {
    let values = values.into();
    let (expected_operation_scope, expected_scope) = load_guard.into_parts();
    hydrate_persisted_relationship_projection_with_kind(
        values,
        EvidenceKind::Live,
        expected_operation_scope,
        &expected_scope,
        authority,
        decision,
    )
}

pub(super) fn hydrate_persisted_fallback_relationship_projection<
    T: PublicTransport,
    V: Into<PersistedRelationshipProjection>,
>(
    values: V,
    load_guard: RelationshipProjectionLoadGuard,
    authority: &RelationshipAuthority<T>,
    decision: &TrustedRelationshipDecisionInstant,
) -> Result<RelationshipProjection, ProjectionPersistenceError> {
    let values = values.into();
    let (expected_operation_scope, expected_scope) = load_guard.into_parts();
    hydrate_persisted_relationship_projection_with_kind(
        values,
        EvidenceKind::Fallback,
        expected_operation_scope,
        &expected_scope,
        authority,
        decision,
    )
}

#[cfg(test)]
pub(crate) fn hydrate_persisted_fallback_relationship_projection_for_test<
    T: PublicTransport,
    V: Into<PersistedRelationshipProjection>,
>(
    values: V,
    load_guard: RelationshipProjectionLoadGuard,
    authority: &RelationshipAuthority<T>,
    decision: &TrustedRelationshipDecisionInstant,
) -> Result<RelationshipProjection, ProjectionPersistenceError> {
    hydrate_persisted_fallback_relationship_projection(values, load_guard, authority, decision)
}

#[cfg(test)]
pub(crate) fn hydrate_persisted_relationship_projection<
    T: PublicTransport,
    V: Into<PersistedRelationshipProjection>,
>(
    values: V,
    authority: &RelationshipAuthority<T>,
    decision: &TrustedRelationshipDecisionInstant,
) -> Result<RelationshipProjection, ProjectionPersistenceError> {
    let values = values.into();
    let load_guard =
        RelationshipProjectionLoadGuard::for_test(values.operation_scope, values.scope.clone());
    match values.evidence_kind {
        EvidenceKind::Live => {
            hydrate_persisted_live_relationship_projection(values, load_guard, authority, decision)
        }
        EvidenceKind::Fallback => hydrate_persisted_fallback_relationship_projection(
            values, load_guard, authority, decision,
        ),
    }
}

fn hydrate_persisted_traffic_projection_with_kind<T: PublicTransport>(
    values: PersistedTrafficProjection,
    expected_evidence_kind: EvidenceKind,
    expected_scope: &TrafficGraphScope,
    authority: &RelationshipAuthority<T>,
    decision: &TrustedRelationshipDecisionInstant,
) -> Result<TrafficProjection, ProjectionPersistenceError> {
    let expected_did_set_bytes = encode_canonical_did_set(&values.scope.members)
        .ok_or(ProjectionPersistenceError::Invalid)?;
    if values.operation_scope != ProjectionOperationScope::Traffic
        || &values.scope != expected_scope
        || values.evidence_kind != expected_evidence_kind
        || values.scope_digest != traffic_scope_digest(&values.scope)
        || values.appview_base != authority.config.appview_origin.as_str()
        || values.configuration_fingerprint != authority.config.fingerprint
        || values.canonical_did_set_bytes.is_empty()
        || values.canonical_did_set_sha256 != sha256(&values.canonical_did_set_bytes)
        || values.canonical_did_set_bytes != expected_did_set_bytes
        || values.aggregate_evidence_bytes.is_empty()
        || values.aggregate_evidence_bytes.len() > MAX_PERSISTED_AGGREGATE_BYTES
        || values.aggregate_evidence_sha256 != sha256(&values.aggregate_evidence_bytes)
    {
        return Err(ProjectionPersistenceError::Invalid);
    }
    let expected_requests = plan_traffic_graph(&values.scope.actor, &values.scope.members)
        .map_err(|_| ProjectionPersistenceError::Invalid)?
        .requests;
    let projection_id = parse_canonical_projection_uuid(&values.projection_id)?;
    let graph_batches = hydrate_graph_evidence(
        values.relationships,
        &expected_requests,
        projection_id,
        &authority.config,
        values.evidence_kind,
        values.started_at,
        values.completed_at,
    )?;
    let projection = TrafficProjection {
        projection_id,
        operation_scope: values.operation_scope,
        scope: values.scope,
        scope_digest: values.scope_digest,
        appview_base: CanonicalOrigin::parse(&values.appview_base)
            .map_err(|_| ProjectionPersistenceError::Invalid)?,
        config_fingerprint: values.configuration_fingerprint,
        source_identity: authority.source_identity,
        projection_revision: values.projection_revision,
        persistence_authority: ProjectionPersistenceAuthority::hydrated(),
        source_call_count: values.source_call_count,
        started_at: values.started_at,
        completed_at: values.completed_at,
        evidence_kind: values.evidence_kind,
        graph_batches,
        evidence_digest: [0; 32],
    };
    let mut projection = projection;
    projection.evidence_digest = traffic_evidence_digest(&projection);
    if canonical_traffic_evidence_bytes(&projection) != values.aggregate_evidence_bytes {
        return Err(ProjectionPersistenceError::Invalid);
    }
    if !traffic_projection_fence_valid(&projection, &projection.scope, authority, decision) {
        return Err(ProjectionPersistenceError::Invalid);
    }
    Ok(projection)
}

#[cfg(test)]
pub(crate) fn hydrate_persisted_live_traffic_projection<
    T: PublicTransport,
    V: Into<PersistedTrafficProjection>,
>(
    values: V,
    load_guard: TrafficProjectionLoadGuard,
    authority: &RelationshipAuthority<T>,
    decision: &TrustedRelationshipDecisionInstant,
) -> Result<TrafficProjection, ProjectionPersistenceError> {
    let values = values.into();
    let expected_scope = load_guard.into_scope();
    hydrate_persisted_traffic_projection_with_kind(
        values,
        EvidenceKind::Live,
        &expected_scope,
        authority,
        decision,
    )
}

pub(super) fn hydrate_persisted_fallback_traffic_projection<
    T: PublicTransport,
    V: Into<PersistedTrafficProjection>,
>(
    values: V,
    load_guard: TrafficProjectionLoadGuard,
    authority: &RelationshipAuthority<T>,
    decision: &TrustedRelationshipDecisionInstant,
) -> Result<TrafficProjection, ProjectionPersistenceError> {
    let values = values.into();
    let expected_scope = load_guard.into_scope();
    hydrate_persisted_traffic_projection_with_kind(
        values,
        EvidenceKind::Fallback,
        &expected_scope,
        authority,
        decision,
    )
}

#[cfg(test)]
pub(crate) fn hydrate_persisted_fallback_traffic_projection_for_test<
    T: PublicTransport,
    V: Into<PersistedTrafficProjection>,
>(
    values: V,
    load_guard: TrafficProjectionLoadGuard,
    authority: &RelationshipAuthority<T>,
    decision: &TrustedRelationshipDecisionInstant,
) -> Result<TrafficProjection, ProjectionPersistenceError> {
    hydrate_persisted_fallback_traffic_projection(values, load_guard, authority, decision)
}

#[cfg(test)]
pub(crate) fn hydrate_persisted_traffic_projection<
    T: PublicTransport,
    V: Into<PersistedTrafficProjection>,
>(
    values: V,
    authority: &RelationshipAuthority<T>,
    decision: &TrustedRelationshipDecisionInstant,
) -> Result<TrafficProjection, ProjectionPersistenceError> {
    let values = values.into();
    let load_guard = TrafficProjectionLoadGuard::for_test(values.scope.clone());
    match values.evidence_kind {
        EvidenceKind::Live => {
            hydrate_persisted_live_traffic_projection(values, load_guard, authority, decision)
        }
        EvidenceKind::Fallback => {
            hydrate_persisted_fallback_traffic_projection(values, load_guard, authority, decision)
        }
    }
}

pub trait ProjectionClock: Send + Sync {
    fn now(&self) -> DateTime<Utc>;
}

#[derive(Debug, Clone, Copy, Default)]
pub struct SystemProjectionClock;

impl ProjectionClock for SystemProjectionClock {
    fn now(&self) -> DateTime<Utc> {
        Utc::now()
    }
}

pub struct RelationshipAuthority<T: PublicTransport> {
    config: RelationshipPolicyConfig,
    transport: T,
    concurrency: Arc<Semaphore>,
    rate_gate: Arc<RequestRateGate>,
    source_identity: [u8; 32],
}

/// The production build has exactly the audited pinned transport. The
/// `test-support` build can instead select an explicit, synthetic federation
/// transport for the container E2E suite.
#[cfg(not(feature = "test-support"))]
pub(crate) type ProductionRelationshipAuthority =
    RelationshipAuthority<ReqwestPinnedTransport<SystemDnsResolver>>;
#[cfg(feature = "test-support")]
pub(crate) type ProductionRelationshipAuthority =
    RelationshipAuthority<TestSupportRelationshipTransport>;

#[cfg(feature = "test-support")]
#[derive(Clone)]
pub(crate) enum TestSupportRelationshipTransport {
    Production(ReqwestPinnedTransport<SystemDnsResolver>),
    FederationAllowAll,
}

#[cfg(feature = "test-support")]
#[async_trait]
impl PublicTransport for TestSupportRelationshipTransport {
    async fn get(&self, request: PublicGet) -> Result<PublicResponse, TransportError> {
        match self {
            Self::Production(transport) => transport.get(request).await,
            Self::FederationAllowAll => federation_allow_all_response(&request),
        }
    }
}

#[cfg(feature = "test-support")]
fn federation_allow_all_response(request: &PublicGet) -> Result<PublicResponse, TransportError> {
    let path = request.url.path();
    if path == /* did-web-test */ "/.well-known/did.json" {
        let host = request
            .url
            .host_str()
            .ok_or(TransportError::InvalidRequest)?;
        let actor = format!("did:web:{host}");
        return Ok(PublicResponse::json(
            200,
            serde_json::json!({
                "id": actor,
                "service": [{
                    "id": format!("{actor}#atproto_pds"),
                    "type": "AtprotoPersonalDataServer",
                    "serviceEndpoint": "https://pds.example.net",
                }],
            }),
        ));
    }
    if path == GET_RECORD_PATH {
        let actor = request
            .url
            .query_pairs()
            .find(|(name, _)| name == "repo")
            .map(|(_, value)| value.into_owned())
            .ok_or(TransportError::InvalidRequest)?;
        return Ok(PublicResponse::json(
            200,
            serde_json::json!({
                "uri": format!("at://{actor}/{DECLARATION_COLLECTION}/{DECLARATION_RKEY}"),
                "cid": "bafyreihdwdcefgh4dqkjv67uzcmw7ojee6xedzdetojuzjevtenxquvyku",
                "value": {
                    "$type": DECLARATION_TYPE,
                    "allowIncoming": "all",
                    "allowGroupInvites": "all",
                },
            }),
        ));
    }
    if path == GRAPH_PATH {
        let actor = request
            .url
            .query_pairs()
            .find(|(name, _)| name == "actor")
            .map(|(_, value)| value.into_owned())
            .ok_or(TransportError::InvalidRequest)?;
        let relationships = request
            .url
            .query_pairs()
            .filter(|(name, _)| name == "others")
            .map(|(_, did)| {
                serde_json::json!({
                    "$type": RELATIONSHIP_TYPE,
                    "did": did,
                    "following": format!("at://{actor}/app.bsky.graph.follow/federation-test"),
                })
            })
            .collect::<Vec<_>>();
        return Ok(PublicResponse::json(
            200,
            serde_json::json!({"actor": actor, "relationships": relationships}),
        ));
    }
    Err(TransportError::InvalidRequest)
}

#[cfg(test)]
pub type HttpRelationshipSource<T> = RelationshipAuthority<T>;

#[derive(Debug)]
struct RequestRateGate {
    rate_per_second: f64,
    burst: f64,
    state: AsyncMutex<RequestRateState>,
}

#[derive(Debug)]
struct RequestRateState {
    tokens: f64,
    updated_at: Instant,
}

impl RequestRateGate {
    fn new(rate_per_second: u32, burst: u32) -> Self {
        Self {
            rate_per_second: f64::from(rate_per_second),
            burst: f64::from(burst),
            state: AsyncMutex::new(RequestRateState {
                tokens: f64::from(burst),
                updated_at: Instant::now(),
            }),
        }
    }

    async fn acquire(&self, deadline: Instant) -> Result<(), AuthorityError> {
        loop {
            let wait = {
                let mut state = self.state.lock().await;
                let now = Instant::now();
                let elapsed = now.saturating_duration_since(state.updated_at);
                state.tokens =
                    (state.tokens + elapsed.as_secs_f64() * self.rate_per_second).min(self.burst);
                state.updated_at = now;
                if state.tokens >= 1.0 {
                    state.tokens -= 1.0;
                    None
                } else {
                    Some(Duration::from_secs_f64(
                        (1.0 - state.tokens) / self.rate_per_second,
                    ))
                }
            };
            let Some(wait) = wait else {
                return Ok(());
            };
            tokio::time::timeout_at(deadline, tokio::time::sleep(wait))
                .await
                .map_err(|_| AuthorityError::Unavailable)?;
        }
    }
}

impl<T: PublicTransport> RelationshipAuthority<T> {
    fn from_parts(config: RelationshipPolicyConfig, transport: T, source_profile: &[u8]) -> Self {
        let concurrency = Arc::new(Semaphore::new(config.max_concurrency));
        let rate_gate = Arc::new(RequestRateGate::new(
            config.request_rate_per_second,
            config.request_burst,
        ));
        let source_identity = relationship_source_identity(&config, source_profile);
        Self {
            config,
            transport,
            concurrency,
            rate_gate,
            source_identity,
        }
    }
    #[cfg(any(test, feature = "test-support"))]
    pub fn new(config: RelationshipPolicyConfig, transport: T) -> Self {
        Self::from_parts(config, transport, HARDENED_SOURCE_PROFILE_V1)
    }

    #[cfg(test)]
    pub(crate) fn with_untrusted_source_for_test(
        config: RelationshipPolicyConfig,
        transport: T,
    ) -> Self {
        Self::from_parts(config, transport, UNTRUSTED_TEST_SOURCE_PROFILE)
    }

    #[cfg(test)]
    pub fn config(&self) -> &RelationshipPolicyConfig {
        &self.config
    }

    pub(crate) async fn collect_admission_projection(
        &self,
        allocated_revision: AllocatedProjectionRevisionGuard,
        operation_scope: ProjectionOperationScope,
        request: AdmissionRequest,
    ) -> Result<RelationshipProjection, ProjectionRefreshFailure> {
        collect_admission_projection_with_kind(
            self,
            &SystemProjectionClock,
            allocated_revision,
            operation_scope,
            request,
            EvidenceKind::Live,
        )
        .await
    }

    pub(crate) async fn collect_block_projection(
        &self,
        allocated_revision: AllocatedProjectionRevisionGuard,
        operation_scope: ProjectionOperationScope,
        roster: Vec<String>,
    ) -> Result<RelationshipProjection, ProjectionRefreshFailure> {
        collect_block_projection_with_kind(
            self,
            &SystemProjectionClock,
            allocated_revision,
            operation_scope,
            roster,
            EvidenceKind::Live,
        )
        .await
    }

    pub(crate) async fn collect_traffic_projection(
        &self,
        allocated_revision: AllocatedProjectionRevisionGuard,
        actor: String,
        roster: Vec<String>,
    ) -> Result<TrafficProjection, ProjectionRefreshFailure> {
        collect_traffic_projection_with_kind(
            self,
            &SystemProjectionClock,
            allocated_revision,
            actor,
            roster,
            EvidenceKind::Live,
        )
        .await
    }

    async fn send_public(&self, request: PublicGet) -> Result<PublicResponse, AuthorityError> {
        let deadline = request.deadline;
        self.rate_gate.acquire(deadline).await?;
        let permit = tokio::time::timeout_at(deadline, self.concurrency.acquire())
            .await
            .map_err(|_| AuthorityError::Unavailable)?
            .map_err(|_| AuthorityError::Unavailable)?;
        let response = tokio::time::timeout_at(deadline, self.transport.get(request))
            .await
            .map_err(|_| AuthorityError::Unavailable)?
            .map_err(map_transport_error);
        drop(permit);
        response
    }

    async fn declaration(
        &self,
        recipient: &str,
        deadline: Instant,
    ) -> Result<
        (
            DeclarationRecord,
            ResolvedPdsService,
            [u8; 32],
            [u8; 32],
            [u8; 32],
            [u8; 32],
        ),
        AuthorityError,
    > {
        let did_url = did_document_url(&self.config, recipient)?;
        let did_request_digest = request_evidence_digest(&did_url);
        let did_response = self
            .send_public(PublicGet::new(
                did_url,
                deadline,
                self.config.max_response_bytes,
            ))
            .await?;
        ensure_body_cap(&did_response, self.config.max_response_bytes)?;
        if did_response.status != 200 {
            return Err(AuthorityError::Unavailable);
        }
        let did_digest = sha256(&did_response.body);
        let pds = parse_did_document_service(recipient, &did_response.body)?;
        let record_url = declaration_record_url(&pds.origin, recipient)?;
        let record_request_digest = request_evidence_digest(&record_url);
        let record_response = self
            .send_public(PublicGet::new(
                record_url,
                deadline,
                self.config.max_response_bytes,
            ))
            .await?;
        ensure_body_cap(&record_response, self.config.max_response_bytes)?;
        let record_digest = sha256(&record_response.body);
        let record =
            parse_declaration_response(recipient, record_response.status, &record_response.body)?;
        Ok((
            record,
            pds,
            did_request_digest,
            did_digest,
            record_request_digest,
            record_digest,
        ))
    }

    async fn graph(
        &self,
        request: &GraphRequest,
        deadline: Instant,
    ) -> Result<(Vec<GraphRelation>, [u8; 32], [u8; 32]), AuthorityError> {
        let url = graph_request_url(&self.config.appview_origin, request)?;
        let request_digest = request_evidence_digest(&url);
        let response = self
            .send_public(PublicGet::new(
                url,
                deadline,
                self.config.max_response_bytes,
            ))
            .await?;
        ensure_body_cap(&response, self.config.max_response_bytes)?;
        if response.status != 200 {
            return Err(AuthorityError::Unavailable);
        }
        let digest = sha256(&response.body);
        let relationships = parse_graph_response(&request.actor, &request.others, &response.body)?;
        Ok((relationships, request_digest, digest))
    }
}

impl ProductionRelationshipAuthority {
    pub(crate) fn from_startup_guard(guard: RelationshipAuthorityStartupGuard) -> Self {
        let (config, transport) = guard.into_parts();
        #[cfg(feature = "test-support")]
        let transport = TestSupportRelationshipTransport::Production(transport);
        Self::from_parts(config, transport, HARDENED_SOURCE_PROFILE_V1)
    }

    #[cfg(feature = "test-support")]
    pub(crate) fn federation_allow_all_for_test() -> Result<Self, RelationshipPolicyConfigError> {
        Ok(Self::from_parts(
            fixed_production_relationship_policy_config()?,
            TestSupportRelationshipTransport::FederationAllowAll,
            FEDERATION_TEST_SOURCE_PROFILE,
        ))
    }
}

fn did_document_url(config: &RelationshipPolicyConfig, did: &str) -> Result<Url, AuthorityError> {
    if !validate_bare_did(did) {
        return Err(AuthorityError::Malformed);
    }
    if did.starts_with("did:plc:") {
        return config.plc_directory_origin.append_path(&format!("/{did}"));
    }
    let raw_url = crate::identity::did_web_document_url(did).ok_or(AuthorityError::Malformed)?;
    Url::parse(&raw_url).map_err(|_| AuthorityError::Malformed)
}

fn declaration_record_url(
    pds_origin: &CanonicalOrigin,
    recipient: &str,
) -> Result<Url, AuthorityError> {
    if !validate_bare_did(recipient) {
        return Err(AuthorityError::Malformed);
    }
    let mut url = pds_origin.append_path(GET_RECORD_PATH)?;
    url.query_pairs_mut()
        .append_pair("repo", recipient)
        .append_pair("collection", DECLARATION_COLLECTION)
        .append_pair("rkey", DECLARATION_RKEY);
    Ok(url)
}

fn graph_request_url(
    appview_origin: &CanonicalOrigin,
    request: &GraphRequest,
) -> Result<Url, AuthorityError> {
    if !validate_bare_did(&request.actor)
        || request.others.is_empty()
        || request.others.len() > GRAPH_OTHERS_MAX
        || request
            .others
            .iter()
            .any(|target| !validate_bare_did(target) || target == &request.actor)
    {
        return Err(AuthorityError::Malformed);
    }
    let mut url = appview_origin.append_path(GRAPH_PATH)?;
    let mut query = url.query_pairs_mut();
    query.append_pair("actor", &request.actor);
    for other in &request.others {
        query.append_pair("others", other);
    }
    drop(query);
    Ok(url)
}

fn map_transport_error(error: TransportError) -> AuthorityError {
    match error {
        TransportError::BodyTooLarge | TransportError::DnsCapacity => AuthorityError::Capacity,
        _ => AuthorityError::Unavailable,
    }
}

fn ensure_body_cap(response: &PublicResponse, cap: usize) -> Result<(), AuthorityError> {
    if response.body.len() > cap {
        Err(AuthorityError::Capacity)
    } else if (300..400).contains(&response.status) {
        Err(AuthorityError::Unavailable)
    } else {
        Ok(())
    }
}

fn sha256(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}

fn request_evidence_digest(url: &Url) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(b"CATBIRD-CHAT-RELATIONSHIP-PUBLIC-GET\0");
    hash_len_bytes(&mut hash, url.as_str().as_bytes());
    hash.finalize().into()
}

fn persisted_revision_valid(revision: u64) -> bool {
    (1..=MAX_PERSISTED_SAFE_INTEGER).contains(&revision)
}

fn canonicalize_persisted_time(value: DateTime<Utc>) -> Option<DateTime<Utc>> {
    DateTime::from_timestamp(
        value.timestamp(),
        value.timestamp_subsec_micros().checked_mul(1_000)?,
    )
}

fn persisted_time_is_canonical(value: DateTime<Utc>) -> bool {
    canonicalize_persisted_time(value).is_some_and(|canonical| canonical == value)
}

fn next_fetch_revision(next: &mut u64, projection_revision: u64) -> Option<u64> {
    loop {
        let candidate = *next;
        if !persisted_revision_valid(candidate) {
            return None;
        }
        *next = candidate.checked_add(1)?;
        if candidate != projection_revision {
            return Some(candidate);
        }
    }
}

fn remap_relationship_fetch_revisions(
    projection: &mut RelationshipProjection,
) -> Result<(), ProjectionPersistenceError> {
    let mut next = 1;
    for declaration in &mut projection.declarations {
        declaration.fetch_revision = next_fetch_revision(&mut next, projection.projection_revision)
            .ok_or(ProjectionPersistenceError::Invalid)?;
    }
    for batch in &mut projection.graph_batches {
        batch.fetch_revision = next_fetch_revision(&mut next, projection.projection_revision)
            .ok_or(ProjectionPersistenceError::Invalid)?;
    }
    Ok(())
}

fn remap_traffic_fetch_revisions(
    projection: &mut TrafficProjection,
) -> Result<(), ProjectionPersistenceError> {
    let mut next = 1;
    for batch in &mut projection.graph_batches {
        batch.fetch_revision = next_fetch_revision(&mut next, projection.projection_revision)
            .ok_or(ProjectionPersistenceError::Invalid)?;
    }
    Ok(())
}

#[cfg(test)]
pub(crate) async fn collect_admission_projection<T: PublicTransport, C: ProjectionClock>(
    source: &RelationshipAuthority<T>,
    clock: &C,
    allocated_revision: AllocatedProjectionRevisionGuard,
    operation_scope: ProjectionOperationScope,
    request: AdmissionRequest,
) -> Result<RelationshipProjection, ProjectionRefreshFailure> {
    collect_admission_projection_with_kind(
        source,
        clock,
        allocated_revision,
        operation_scope,
        request,
        EvidenceKind::Live,
    )
    .await
}

async fn collect_admission_projection_with_kind<T: PublicTransport, C: ProjectionClock>(
    source: &RelationshipAuthority<T>,
    clock: &C,
    allocated_revision: AllocatedProjectionRevisionGuard,
    operation_scope: ProjectionOperationScope,
    request: AdmissionRequest,
    evidence_kind: EvidenceKind,
) -> Result<RelationshipProjection, ProjectionRefreshFailure> {
    let projection_revision = allocated_revision.projection_revision();
    let observed_started_at = clock.now();
    let Some(started_at) = canonicalize_persisted_time(observed_started_at) else {
        return Err(ProjectionRefreshFailure::new(observed_started_at, 1));
    };
    let scope = ProjectionScope::Admission(request.clone());
    if !persisted_revision_valid(projection_revision)
        || !relationship_operation_scope_matches(operation_scope, &scope)
        || validate_admission_request(&request).is_err()
    {
        return Err(ProjectionRefreshFailure::new(started_at, 1));
    }
    let plan = plan_admission_graph(&request.roster, &request.inviter)
        .map_err(|_| ProjectionRefreshFailure::new(started_at, 1))?;
    let scope_digest = projection_scope_digest(&scope);
    let projection_id = Uuid::new_v4();
    let mut next_fetch_revision_value = 1;
    let deadline = Instant::now() + source.config.total_deadline;
    let mut declarations = Vec::new();
    let mut failures = 0_usize;

    // Recipient chains are independent and run concurrently, while DID
    // resolution and the declaration request remain strictly ordered inside
    // each chain. All chains finish before graph collection, preserving the
    // global PDS-first authority boundary without serializing the roster.
    let declaration_results = join_all(request.pending_recipients.iter().map(
        |recipient| async move { (recipient, source.declaration(recipient, deadline).await) },
    ))
    .await;
    for (recipient, result) in declaration_results {
        match result {
            Ok((
                record,
                resolved_pds_service,
                did_request_digest,
                did_document_digest,
                record_request_digest,
                record_response_digest,
            )) => {
                let Some(fetched_at) = canonicalize_persisted_time(clock.now()) else {
                    failures += 1;
                    continue;
                };
                let Some(fetch_revision) =
                    next_fetch_revision(&mut next_fetch_revision_value, projection_revision)
                else {
                    failures += 1;
                    continue;
                };
                declarations.push(DeclarationEvidence {
                    projection_id,
                    recipient: recipient.clone(),
                    incoming: record.incoming,
                    group: record.group,
                    allow_group_invites: record.allow_group_invites,
                    absent: record.absent,
                    cid: record.cid,
                    service_id: resolved_pds_service.service_id,
                    resolved_pds_origin: resolved_pds_service.origin,
                    did_request_digest,
                    did_document_digest,
                    record_request_digest,
                    record_response_digest,
                    fetch_revision,
                    fetched_at,
                    evidence_kind,
                });
            }
            Err(_) => failures += 1,
        }
    }
    let (graph_batches, graph_failures) = collect_graph_evidence(
        source,
        clock,
        projection_id,
        plan.requests,
        deadline,
        evidence_kind,
        projection_revision,
        &mut next_fetch_revision_value,
    )
    .await;
    failures += graph_failures;
    if failures != 0 {
        return Err(ProjectionRefreshFailure::new(started_at, failures));
    }
    let Some(completed_at) = canonicalize_persisted_time(clock.now()) else {
        return Err(ProjectionRefreshFailure::new(started_at, 1));
    };
    if !collection_window_valid(started_at, completed_at) {
        return Err(ProjectionRefreshFailure::new(started_at, 1));
    }
    let mut projection = RelationshipProjection {
        projection_id,
        operation_scope,
        scope,
        scope_digest,
        appview_base: source.config.appview_origin.clone(),
        config_fingerprint: source.config.fingerprint,
        source_identity: source.source_identity,
        projection_revision,
        persistence_authority: ProjectionPersistenceAuthority::allocated(allocated_revision),
        source_call_count: u64::try_from(2 * declarations.len() + graph_batches.len())
            .expect("bounded projection source count fits u64"),
        started_at,
        completed_at,
        evidence_kind,
        declarations,
        graph_batches,
        evidence_digest: [0; 32],
    };
    projection.evidence_digest = relationship_evidence_digest(&projection);
    if !projection.integrity_valid() {
        return Err(ProjectionRefreshFailure::new(started_at, 1));
    }
    Ok(projection)
}

#[cfg(test)]
pub(crate) async fn collect_block_projection<T: PublicTransport, C: ProjectionClock>(
    source: &RelationshipAuthority<T>,
    clock: &C,
    allocated_revision: AllocatedProjectionRevisionGuard,
    operation_scope: ProjectionOperationScope,
    roster: Vec<String>,
) -> Result<RelationshipProjection, ProjectionRefreshFailure> {
    collect_block_projection_with_kind(
        source,
        clock,
        allocated_revision,
        operation_scope,
        roster,
        EvidenceKind::Live,
    )
    .await
}

async fn collect_block_projection_with_kind<T: PublicTransport, C: ProjectionClock>(
    source: &RelationshipAuthority<T>,
    clock: &C,
    allocated_revision: AllocatedProjectionRevisionGuard,
    operation_scope: ProjectionOperationScope,
    roster: Vec<String>,
    evidence_kind: EvidenceKind,
) -> Result<RelationshipProjection, ProjectionRefreshFailure> {
    let projection_revision = allocated_revision.projection_revision();
    let observed_started_at = clock.now();
    let Some(started_at) = canonicalize_persisted_time(observed_started_at) else {
        return Err(ProjectionRefreshFailure::new(observed_started_at, 1));
    };
    if !persisted_revision_valid(projection_revision) {
        return Err(ProjectionRefreshFailure::new(started_at, 1));
    }
    let plan =
        plan_block_only_graph(&roster).map_err(|_| ProjectionRefreshFailure::new(started_at, 1))?;
    let scope = ProjectionScope::BlockOnly(plan.scope.clone());
    if !relationship_operation_scope_matches(operation_scope, &scope) {
        return Err(ProjectionRefreshFailure::new(started_at, 1));
    }
    let scope_digest = projection_scope_digest(&scope);
    let projection_id = Uuid::new_v4();
    let mut next_fetch_revision_value = 1;
    let deadline = Instant::now() + source.config.total_deadline;
    let (graph_batches, failures) = collect_graph_evidence(
        source,
        clock,
        projection_id,
        plan.requests,
        deadline,
        evidence_kind,
        projection_revision,
        &mut next_fetch_revision_value,
    )
    .await;
    if failures != 0 {
        return Err(ProjectionRefreshFailure::new(started_at, failures));
    }
    let Some(completed_at) = canonicalize_persisted_time(clock.now()) else {
        return Err(ProjectionRefreshFailure::new(started_at, 1));
    };
    if !collection_window_valid(started_at, completed_at) {
        return Err(ProjectionRefreshFailure::new(started_at, 1));
    }
    let mut projection = RelationshipProjection {
        projection_id,
        operation_scope,
        scope,
        scope_digest,
        appview_base: source.config.appview_origin.clone(),
        config_fingerprint: source.config.fingerprint,
        source_identity: source.source_identity,
        projection_revision,
        persistence_authority: ProjectionPersistenceAuthority::allocated(allocated_revision),
        source_call_count: u64::try_from(graph_batches.len())
            .expect("bounded projection source count fits u64"),
        started_at,
        completed_at,
        evidence_kind,
        declarations: Vec::new(),
        graph_batches,
        evidence_digest: [0; 32],
    };
    projection.evidence_digest = relationship_evidence_digest(&projection);
    if !projection.integrity_valid() {
        return Err(ProjectionRefreshFailure::new(started_at, 1));
    }
    Ok(projection)
}

#[cfg(test)]
pub(crate) async fn collect_traffic_projection<T: PublicTransport, C: ProjectionClock>(
    source: &RelationshipAuthority<T>,
    clock: &C,
    allocated_revision: AllocatedProjectionRevisionGuard,
    actor: String,
    roster: Vec<String>,
) -> Result<TrafficProjection, ProjectionRefreshFailure> {
    collect_traffic_projection_with_kind(
        source,
        clock,
        allocated_revision,
        actor,
        roster,
        EvidenceKind::Live,
    )
    .await
}

async fn collect_traffic_projection_with_kind<T: PublicTransport, C: ProjectionClock>(
    source: &RelationshipAuthority<T>,
    clock: &C,
    allocated_revision: AllocatedProjectionRevisionGuard,
    actor: String,
    roster: Vec<String>,
    evidence_kind: EvidenceKind,
) -> Result<TrafficProjection, ProjectionRefreshFailure> {
    let projection_revision = allocated_revision.projection_revision();
    let observed_started_at = clock.now();
    let Some(started_at) = canonicalize_persisted_time(observed_started_at) else {
        return Err(ProjectionRefreshFailure::new(observed_started_at, 1));
    };
    if !persisted_revision_valid(projection_revision) {
        return Err(ProjectionRefreshFailure::new(started_at, 1));
    }
    let plan = plan_traffic_graph(&actor, &roster)
        .map_err(|_| ProjectionRefreshFailure::new(started_at, 1))?;
    let scope = plan.scope.clone();
    let scope_digest = traffic_scope_digest(&scope);
    let projection_id = Uuid::new_v4();
    let mut next_fetch_revision_value = 1;
    let deadline = Instant::now() + source.config.total_deadline;
    let (graph_batches, failures) = collect_graph_evidence(
        source,
        clock,
        projection_id,
        plan.requests,
        deadline,
        evidence_kind,
        projection_revision,
        &mut next_fetch_revision_value,
    )
    .await;
    if failures != 0 {
        return Err(ProjectionRefreshFailure::new(started_at, failures));
    }
    let Some(completed_at) = canonicalize_persisted_time(clock.now()) else {
        return Err(ProjectionRefreshFailure::new(started_at, 1));
    };
    if !collection_window_valid(started_at, completed_at) {
        return Err(ProjectionRefreshFailure::new(started_at, 1));
    }
    let mut projection = TrafficProjection {
        projection_id,
        operation_scope: ProjectionOperationScope::Traffic,
        scope,
        scope_digest,
        appview_base: source.config.appview_origin.clone(),
        config_fingerprint: source.config.fingerprint,
        source_identity: source.source_identity,
        projection_revision,
        persistence_authority: ProjectionPersistenceAuthority::allocated(allocated_revision),
        source_call_count: u64::try_from(graph_batches.len())
            .expect("bounded projection source count fits u64"),
        started_at,
        completed_at,
        evidence_kind,
        graph_batches,
        evidence_digest: [0; 32],
    };
    projection.evidence_digest = traffic_evidence_digest(&projection);
    if !projection.integrity_valid() {
        return Err(ProjectionRefreshFailure::new(started_at, 1));
    }
    Ok(projection)
}

async fn collect_graph_evidence<T: PublicTransport, C: ProjectionClock>(
    source: &RelationshipAuthority<T>,
    clock: &C,
    projection_id: Uuid,
    requests: Vec<GraphRequest>,
    deadline: Instant,
    evidence_kind: EvidenceKind,
    projection_revision: u64,
    next_fetch_revision_value: &mut u64,
) -> (Vec<GraphBatchEvidence>, usize) {
    let results = join_all(requests.into_iter().map(|request| async move {
        let result = source.graph(&request, deadline).await;
        (request, result)
    }))
    .await;
    let mut evidence = Vec::with_capacity(results.len());
    let mut failures = 0;
    for (request, result) in results {
        match result {
            Ok((relationships, request_digest, response_digest)) => {
                let Some(fetched_at) = canonicalize_persisted_time(clock.now()) else {
                    failures += 1;
                    continue;
                };
                let Some(fetch_revision) =
                    next_fetch_revision(next_fetch_revision_value, projection_revision)
                else {
                    failures += 1;
                    continue;
                };
                evidence.push(GraphBatchEvidence {
                    projection_id,
                    actor: request.actor,
                    targets: request.others,
                    relationships,
                    request_digest,
                    response_digest,
                    fetch_revision,
                    fetched_at,
                    evidence_kind,
                });
            }
            Err(_) => failures += 1,
        }
    }
    (evidence, failures)
}

fn collection_window_valid(started_at: DateTime<Utc>, completed_at: DateTime<Utc>) -> bool {
    completed_at >= started_at && completed_at - started_at <= TimeDelta::seconds(30)
}

fn validate_admission_request(request: &AdmissionRequest) -> Result<(), PlanError> {
    let members = canonical_roster(&request.roster)?;
    if members != request.roster
        || !members.contains(&request.inviter)
        || request.pending_recipients.is_empty()
    {
        return Err(PlanError::InvalidRoster);
    }
    let mut recipients = request.pending_recipients.clone();
    recipients.sort();
    if recipients != request.pending_recipients
        || recipients.windows(2).any(|pair| pair[0] == pair[1])
        || recipients
            .iter()
            .any(|recipient| recipient == &request.inviter || !members.contains(recipient))
    {
        return Err(PlanError::InvalidRoster);
    }
    match request.operation {
        AdmissionOperation::Direct if members.len() != 2 || recipients.len() != 1 => {
            Err(PlanError::InvalidRoster)
        }
        _ => Ok(()),
    }
}

fn projection_scope_digest(scope: &ProjectionScope) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(b"CATBIRD-CHAT-RELATIONSHIP-SCOPE\0");
    hash_projection_scope(&mut hash, scope);
    hash.finalize().into()
}

fn hash_projection_scope(hash: &mut Sha256, scope: &ProjectionScope) {
    match scope {
        ProjectionScope::Admission(request) => {
            hash.update([0]);
            hash.update([match request.operation {
                AdmissionOperation::Direct => 0,
                AdmissionOperation::Group => 1,
            }]);
            hash_len_bytes(hash, request.inviter.as_bytes());
            hash_string_list(hash, &request.roster);
            hash_string_list(hash, &request.pending_recipients);
        }
        ProjectionScope::BlockOnly(scope) => {
            hash.update([1]);
            hash_len_bytes(hash, scope.sink.as_bytes());
            hash_string_list(hash, &scope.members);
        }
    }
}

fn traffic_scope_digest(scope: &TrafficGraphScope) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(b"CATBIRD-CHAT-RELATIONSHIP-TRAFFIC-SCOPE\0");
    hash_traffic_scope(&mut hash, scope);
    hash.finalize().into()
}

fn hash_traffic_scope(hash: &mut Sha256, scope: &TrafficGraphScope) {
    hash_len_bytes(hash, scope.actor.as_bytes());
    hash_string_list(hash, &scope.members);
}

fn hash_string_list(hash: &mut Sha256, values: &[String]) {
    hash.update((values.len() as u64).to_be_bytes());
    for value in values {
        hash_len_bytes(hash, value.as_bytes());
    }
}

fn relationship_operation_scope_matches(
    operation_scope: ProjectionOperationScope,
    scope: &ProjectionScope,
) -> bool {
    matches!(
        (operation_scope, scope),
        (
            ProjectionOperationScope::Creation
                | ProjectionOperationScope::PendingAdd
                | ProjectionOperationScope::Acceptance,
            ProjectionScope::Admission(_)
        ) | (
            ProjectionOperationScope::RecoveryReservation
                | ProjectionOperationScope::RecoveryFulfillment,
            ProjectionScope::BlockOnly(_)
        )
    )
}

fn relationship_scope_dids(scope: &ProjectionScope) -> &[String] {
    match scope {
        ProjectionScope::Admission(request) => &request.roster,
        ProjectionScope::BlockOnly(scope) => &scope.members,
    }
}

fn relationship_scope_declaration_recipients(scope: &ProjectionScope) -> &[String] {
    match scope {
        ProjectionScope::Admission(request) => &request.pending_recipients,
        ProjectionScope::BlockOnly(_) => &[],
    }
}

fn relationship_scope_graph_requests(
    scope: &ProjectionScope,
) -> Result<Vec<GraphRequest>, ProjectionPersistenceError> {
    match scope {
        ProjectionScope::Admission(request) => {
            validate_admission_request(request).map_err(|_| ProjectionPersistenceError::Invalid)?;
            plan_admission_graph(&request.roster, &request.inviter)
                .map(|plan| plan.requests)
                .map_err(|_| ProjectionPersistenceError::Invalid)
        }
        ProjectionScope::BlockOnly(scope) => plan_block_only_graph(&scope.members)
            .and_then(|plan| {
                if plan.scope == *scope {
                    Ok(plan.requests)
                } else {
                    Err(PlanError::InvalidRoster)
                }
            })
            .map_err(|_| ProjectionPersistenceError::Invalid),
    }
}

fn relationship_source_call_count(projection: &RelationshipProjection) -> u64 {
    projection
        .declarations
        .len()
        .checked_mul(2)
        .and_then(|count| count.checked_add(projection.graph_batches.len()))
        .and_then(|count| u64::try_from(count).ok())
        .unwrap_or(u64::MAX)
}

fn traffic_source_call_count(projection: &TrafficProjection) -> u64 {
    u64::try_from(projection.graph_batches.len()).unwrap_or(u64::MAX)
}

fn encode_canonical_did_set(dids: &[String]) -> Option<Vec<u8>> {
    if canonical_roster(dids).ok()?.as_slice() != dids {
        return None;
    }
    let count = u16::try_from(dids.len()).ok()?;
    let capacity = dids.iter().try_fold(
        CANONICAL_DID_SET_MAGIC.len().checked_add(2)?,
        |capacity, did| capacity.checked_add(2)?.checked_add(did.len()),
    )?;
    let mut output = Vec::with_capacity(capacity);
    output.extend_from_slice(CANONICAL_DID_SET_MAGIC);
    output.extend_from_slice(&count.to_be_bytes());
    for did in dids {
        output.extend_from_slice(&u16::try_from(did.len()).ok()?.to_be_bytes());
        output.extend_from_slice(did.as_bytes());
    }
    Some(output)
}

fn put_u8(output: &mut Vec<u8>, value: u8) {
    output.push(value);
}

fn put_u16(output: &mut Vec<u8>, value: u16) {
    output.extend_from_slice(&value.to_be_bytes());
}

fn put_u64(output: &mut Vec<u8>, value: u64) {
    output.extend_from_slice(&value.to_be_bytes());
}

fn put_i64(output: &mut Vec<u8>, value: i64) {
    output.extend_from_slice(&value.to_be_bytes());
}

fn put_bytes(output: &mut Vec<u8>, bytes: &[u8]) {
    put_u64(
        output,
        u64::try_from(bytes.len()).expect("bounded canonical evidence length fits u64"),
    );
    output.extend_from_slice(bytes);
}

fn put_string(output: &mut Vec<u8>, value: &str) {
    put_bytes(output, value.as_bytes());
}

fn put_string_list(output: &mut Vec<u8>, values: &[String]) {
    put_u64(
        output,
        u64::try_from(values.len()).expect("bounded canonical evidence count fits u64"),
    );
    for value in values {
        put_string(output, value);
    }
}

fn put_datetime(output: &mut Vec<u8>, value: DateTime<Utc>) {
    put_i64(output, value.timestamp());
    output.extend_from_slice(&value.timestamp_subsec_nanos().to_be_bytes());
}

fn put_optional_string(output: &mut Vec<u8>, value: Option<&str>) {
    match value {
        Some(value) => {
            put_u8(output, 1);
            put_string(output, value);
        }
        None => put_u8(output, 0),
    }
}

fn put_optional_policy(output: &mut Vec<u8>, value: Option<IncomingPolicy>) {
    match value {
        Some(value) => {
            put_u8(output, 1);
            put_u8(output, incoming_policy_tag(value));
        }
        None => put_u8(output, 0),
    }
}

fn put_projection_scope(output: &mut Vec<u8>, scope: &ProjectionScope) {
    match scope {
        ProjectionScope::Admission(request) => {
            put_u8(output, 0);
            put_u8(
                output,
                match request.operation {
                    AdmissionOperation::Direct => 0,
                    AdmissionOperation::Group => 1,
                },
            );
            put_string(output, &request.inviter);
            put_string_list(output, &request.roster);
            put_string_list(output, &request.pending_recipients);
        }
        ProjectionScope::BlockOnly(scope) => {
            put_u8(output, 1);
            put_string(output, &scope.sink);
            put_string_list(output, &scope.members);
        }
    }
}

fn put_traffic_scope(output: &mut Vec<u8>, scope: &TrafficGraphScope) {
    put_string(output, &scope.actor);
    put_string_list(output, &scope.members);
}

fn put_declaration_evidence(output: &mut Vec<u8>, evidence: &DeclarationEvidence) {
    put_bytes(output, evidence.projection_id.as_bytes());
    put_string(output, &evidence.recipient);
    put_u8(output, incoming_policy_tag(evidence.incoming));
    put_optional_policy(output, evidence.allow_group_invites);
    put_u8(output, incoming_policy_tag(evidence.group));
    put_u8(output, u8::from(evidence.absent));
    put_optional_string(output, evidence.cid.as_deref());
    put_string(output, &evidence.service_id);
    put_string(output, evidence.resolved_pds_origin.as_str());
    output.extend_from_slice(&evidence.did_request_digest);
    output.extend_from_slice(&evidence.did_document_digest);
    output.extend_from_slice(&evidence.record_request_digest);
    output.extend_from_slice(&evidence.record_response_digest);
    put_u64(output, evidence.fetch_revision);
    put_datetime(output, evidence.fetched_at);
    put_u8(output, evidence_kind_tag(evidence.evidence_kind));
}

fn put_graph_evidence(output: &mut Vec<u8>, batch_ordinal: usize, evidence: &GraphBatchEvidence) {
    put_u16(
        output,
        u16::try_from(batch_ordinal).expect("bounded graph batch ordinal fits u16"),
    );
    put_bytes(output, evidence.projection_id.as_bytes());
    put_string(output, &evidence.actor);
    put_string_list(output, &evidence.targets);
    put_u64(
        output,
        u64::try_from(evidence.relationships.len()).expect("bounded relationship count fits u64"),
    );
    for relation in &evidence.relationships {
        put_string(output, &relation.actor);
        put_string(output, &relation.target);
        for decision in [
            relation.following,
            relation.followed_by,
            relation.blocking,
            relation.blocked_by,
            relation.blocking_by_list,
            relation.blocked_by_list,
        ] {
            put_u8(output, u8::from(decision));
        }
    }
    output.extend_from_slice(&evidence.request_digest);
    output.extend_from_slice(&evidence.response_digest);
    put_u64(output, evidence.fetch_revision);
    put_datetime(output, evidence.fetched_at);
    put_u8(output, evidence_kind_tag(evidence.evidence_kind));
}

fn canonical_relationship_evidence_bytes(projection: &RelationshipProjection) -> Vec<u8> {
    let mut output = Vec::new();
    output.extend_from_slice(CANONICAL_RELATIONSHIP_EVIDENCE_MAGIC);
    put_u8(&mut output, 0);
    put_bytes(&mut output, projection.projection_id.as_bytes());
    put_u8(
        &mut output,
        projection_operation_scope_tag(projection.operation_scope),
    );
    put_projection_scope(&mut output, &projection.scope);
    output.extend_from_slice(&projection.scope_digest);
    let Some(did_set) = encode_canonical_did_set(relationship_scope_dids(&projection.scope)) else {
        return Vec::new();
    };
    put_bytes(&mut output, &did_set);
    output.extend_from_slice(&sha256(&did_set));
    put_string(&mut output, projection.appview_base.as_str());
    output.extend_from_slice(&projection.config_fingerprint);
    output.extend_from_slice(&projection.source_identity);
    put_u64(&mut output, projection.projection_revision);
    put_u64(&mut output, projection.source_call_count);
    put_datetime(&mut output, projection.started_at);
    put_datetime(&mut output, projection.completed_at);
    put_u8(&mut output, evidence_kind_tag(projection.evidence_kind));
    put_u64(
        &mut output,
        u64::try_from(projection.declarations.len()).expect("bounded declaration count fits u64"),
    );
    for evidence in &projection.declarations {
        put_declaration_evidence(&mut output, evidence);
    }
    put_u64(
        &mut output,
        u64::try_from(projection.graph_batches.len()).expect("bounded graph count fits u64"),
    );
    for (index, evidence) in projection.graph_batches.iter().enumerate() {
        put_graph_evidence(&mut output, index, evidence);
    }
    output
}

fn canonical_persisted_relationship_evidence_bytes(projection: &RelationshipProjection) -> Vec<u8> {
    let mut output = Vec::new();
    output.extend_from_slice(CANONICAL_RELATIONSHIP_EVIDENCE_MAGIC);
    put_u8(&mut output, 3);
    put_bytes(
        &mut output,
        &canonical_relationship_evidence_bytes(projection),
    );
    output
}

fn canonical_traffic_evidence_bytes(projection: &TrafficProjection) -> Vec<u8> {
    let mut output = Vec::new();
    output.extend_from_slice(CANONICAL_RELATIONSHIP_EVIDENCE_MAGIC);
    put_u8(&mut output, 1);
    put_u8(
        &mut output,
        projection_operation_scope_tag(projection.operation_scope),
    );
    put_bytes(&mut output, projection.projection_id.as_bytes());
    put_traffic_scope(&mut output, &projection.scope);
    output.extend_from_slice(&projection.scope_digest);
    let Some(did_set) = encode_canonical_did_set(&projection.scope.members) else {
        return Vec::new();
    };
    put_bytes(&mut output, &did_set);
    output.extend_from_slice(&sha256(&did_set));
    put_string(&mut output, projection.appview_base.as_str());
    output.extend_from_slice(&projection.config_fingerprint);
    output.extend_from_slice(&projection.source_identity);
    put_u64(&mut output, projection.projection_revision);
    put_u64(&mut output, projection.source_call_count);
    put_datetime(&mut output, projection.started_at);
    put_datetime(&mut output, projection.completed_at);
    put_u8(&mut output, evidence_kind_tag(projection.evidence_kind));
    put_u64(
        &mut output,
        u64::try_from(projection.graph_batches.len()).expect("bounded graph count fits u64"),
    );
    for (index, evidence) in projection.graph_batches.iter().enumerate() {
        put_graph_evidence(&mut output, index, evidence);
    }
    output
}

fn relationship_evidence_digest(projection: &RelationshipProjection) -> [u8; 32] {
    sha256(&canonical_relationship_evidence_bytes(projection))
}

fn traffic_evidence_digest(projection: &TrafficProjection) -> [u8; 32] {
    sha256(&canonical_traffic_evidence_bytes(projection))
}

fn incoming_policy_tag(policy: IncomingPolicy) -> u8 {
    match policy {
        IncomingPolicy::All => 0,
        IncomingPolicy::None => 1,
        IncomingPolicy::Following => 2,
    }
}

fn evidence_kind_tag(kind: EvidenceKind) -> u8 {
    match kind {
        EvidenceKind::Live => 0,
        EvidenceKind::Fallback => 1,
    }
}

fn projection_operation_scope_tag(scope: ProjectionOperationScope) -> u8 {
    match scope {
        ProjectionOperationScope::Creation => 0,
        ProjectionOperationScope::PendingAdd => 1,
        ProjectionOperationScope::Acceptance => 2,
        ProjectionOperationScope::RecoveryReservation => 3,
        ProjectionOperationScope::RecoveryFulfillment => 4,
        ProjectionOperationScope::Traffic => 5,
    }
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum PolicyDenial {
    RelationshipPolicyUnavailable,
    BlockedRelationship,
    MessagesDisabled,
    GroupInvitesDisabled,
    NotFollowedByRecipient,
    InvitationLimitReached,
}

pub fn consume_admission_projection<T: PublicTransport>(
    projection: &RelationshipProjection,
    expected_operation_scope: ProjectionOperationScope,
    expected_request: &AdmissionRequest,
    authority: &RelationshipAuthority<T>,
    decision: &TrustedRelationshipDecisionInstant,
    invitation_quota_exceeded: bool,
) -> Result<(), PolicyDenial> {
    let expected_scope = ProjectionScope::Admission(expected_request.clone());
    if !decision.relationship_scope_matches(expected_operation_scope, &expected_scope)
        || !admission_fence_valid_at(
            projection,
            expected_operation_scope,
            expected_request,
            authority,
            decision.datetime(),
        )
    {
        return Err(PolicyDenial::RelationshipPolicyUnavailable);
    }
    if projection
        .graph_batches
        .iter()
        .flat_map(|batch| &batch.relationships)
        .any(GraphRelation::is_blocked)
    {
        return Err(PolicyDenial::BlockedRelationship);
    }
    let policy_for = |recipient: &String| {
        let declaration = projection
            .declarations
            .iter()
            .find(|evidence| &evidence.recipient == recipient)
            .expect("fence proves declaration completeness");
        match expected_request.operation {
            AdmissionOperation::Direct => declaration.incoming,
            AdmissionOperation::Group => declaration.group,
        }
    };
    if expected_request
        .pending_recipients
        .iter()
        .any(|recipient| policy_for(recipient) == IncomingPolicy::None)
    {
        return Err(match expected_request.operation {
            AdmissionOperation::Direct => PolicyDenial::MessagesDisabled,
            AdmissionOperation::Group => PolicyDenial::GroupInvitesDisabled,
        });
    }
    for recipient in &expected_request.pending_recipients {
        let policy = policy_for(recipient);
        if policy == IncomingPolicy::Following {
            let follows = projection
                .graph_batches
                .iter()
                .flat_map(|batch| &batch.relationships)
                .find(|row| row.actor == *recipient && row.target == expected_request.inviter)
                .is_some_and(|row| row.following);
            if !follows {
                return Err(PolicyDenial::NotFollowedByRecipient);
            }
        }
    }
    if invitation_quota_exceeded {
        return Err(PolicyDenial::InvitationLimitReached);
    }
    Ok(())
}

fn admission_fence_valid_at<T: PublicTransport>(
    projection: &RelationshipProjection,
    expected_operation_scope: ProjectionOperationScope,
    expected_request: &AdmissionRequest,
    authority: &RelationshipAuthority<T>,
    observed_at: DateTime<Utc>,
) -> bool {
    if validate_admission_request(expected_request).is_err()
        || !projection.integrity_valid()
        || projection.operation_scope != expected_operation_scope
        || !relationship_operation_scope_matches(expected_operation_scope, &projection.scope)
        || projection.scope != ProjectionScope::Admission(expected_request.clone())
        || projection.scope_digest != projection_scope_digest(&projection.scope)
        || projection.appview_base != authority.config.appview_origin
        || projection.config_fingerprint != authority.config.fingerprint
        || projection.source_identity != authority.source_identity
        || projection.projection_revision == 0
        || !fresh_window(projection.started_at, projection.completed_at, observed_at)
    {
        return false;
    }
    let Ok(plan) = plan_admission_graph(&expected_request.roster, &expected_request.inviter) else {
        return false;
    };
    if projection.declarations.len() != expected_request.pending_recipients.len()
        || projection.graph_batches.len() != plan.requests.len()
    {
        return false;
    }
    let mut kinds = BTreeSet::new();
    let mut revisions = BTreeSet::from([projection.projection_revision]);
    for (recipient, evidence) in expected_request
        .pending_recipients
        .iter()
        .zip(&projection.declarations)
    {
        if evidence.recipient != *recipient
            || evidence.evidence_kind != projection.evidence_kind
            || evidence.did_request_digest == [0; 32]
            || evidence.did_document_digest == [0; 32]
            || evidence.record_request_digest == [0; 32]
            || evidence.record_response_digest == [0; 32]
            || evidence.fetch_revision == 0
            || evidence.fetched_at < projection.started_at
            || evidence.fetched_at > projection.completed_at
            || !revisions.insert(evidence.fetch_revision)
        {
            return false;
        }
        kinds.insert(evidence.evidence_kind);
    }
    for (request, evidence) in plan.requests.iter().zip(&projection.graph_batches) {
        if evidence.actor != request.actor
            || evidence.evidence_kind != projection.evidence_kind
            || evidence.targets != request.others
            || evidence.relationships.len() != request.others.len()
            || evidence.request_digest == [0; 32]
            || evidence.response_digest == [0; 32]
            || evidence.fetch_revision == 0
            || evidence.fetched_at < projection.started_at
            || evidence.fetched_at > projection.completed_at
            || !revisions.insert(evidence.fetch_revision)
        {
            return false;
        }
        for (target, relation) in request.others.iter().zip(&evidence.relationships) {
            if relation.actor != request.actor || relation.target != *target {
                return false;
            }
        }
        kinds.insert(evidence.evidence_kind);
    }
    kinds.len() == 1
}

fn relationship_projection_fence_valid<T: PublicTransport>(
    projection: &RelationshipProjection,
    expected_operation_scope: ProjectionOperationScope,
    expected_scope: &ProjectionScope,
    authority: &RelationshipAuthority<T>,
    decision: &TrustedRelationshipDecisionInstant,
) -> bool {
    if projection.operation_scope != expected_operation_scope
        || &projection.scope != expected_scope
        || !decision.relationship_scope_matches(expected_operation_scope, expected_scope)
    {
        return false;
    }
    match expected_scope {
        ProjectionScope::Admission(request) => admission_fence_valid_at(
            projection,
            expected_operation_scope,
            request,
            authority,
            decision.datetime(),
        ),
        ProjectionScope::BlockOnly(scope) => block_projection_fence_valid_at(
            projection,
            expected_operation_scope,
            &scope.members,
            authority,
            decision.datetime(),
        ),
    }
}

fn relationship_projection_persistence_valid<T: PublicTransport>(
    projection: &RelationshipProjection,
    expected_operation_scope: ProjectionOperationScope,
    expected_scope: &ProjectionScope,
    authority: &RelationshipAuthority<T>,
    observation: &TrustedRelationshipPersistenceInstant,
) -> bool {
    if projection.operation_scope != expected_operation_scope || &projection.scope != expected_scope
    {
        return false;
    }
    match expected_scope {
        ProjectionScope::Admission(request) => admission_fence_valid_at(
            projection,
            expected_operation_scope,
            request,
            authority,
            observation.datetime(),
        ),
        ProjectionScope::BlockOnly(scope) => block_projection_fence_valid_at(
            projection,
            expected_operation_scope,
            &scope.members,
            authority,
            observation.datetime(),
        ),
    }
}

fn fresh_window(
    started_at: DateTime<Utc>,
    completed_at: DateTime<Utc>,
    now: DateTime<Utc>,
) -> bool {
    completed_at >= started_at
        && completed_at - started_at <= TimeDelta::seconds(30)
        && now >= completed_at
        && now - completed_at <= MAX_PROJECTION_AGE
}

/// Consumes an exact all-pairs graph projection for recovery reservation or
/// final Add authorization.  Declaration preferences are intentionally absent
/// from this checkpoint; all four block directions remain mandatory.
pub fn consume_block_projection<T: PublicTransport>(
    projection: &RelationshipProjection,
    expected_operation_scope: ProjectionOperationScope,
    expected_roster: &[String],
    authority: &RelationshipAuthority<T>,
    decision: &TrustedRelationshipDecisionInstant,
) -> Result<(), PolicyDenial> {
    let expected_scope = match plan_block_only_graph(expected_roster) {
        Ok(plan) => ProjectionScope::BlockOnly(plan.scope),
        Err(_) => return Err(PolicyDenial::RelationshipPolicyUnavailable),
    };
    if !decision.relationship_scope_matches(expected_operation_scope, &expected_scope)
        || !block_projection_fence_valid_at(
            projection,
            expected_operation_scope,
            expected_roster,
            authority,
            decision.datetime(),
        )
    {
        return Err(PolicyDenial::RelationshipPolicyUnavailable);
    }
    if projection
        .graph_batches
        .iter()
        .flat_map(|batch| &batch.relationships)
        .any(GraphRelation::is_blocked)
    {
        return Err(PolicyDenial::BlockedRelationship);
    }
    Ok(())
}

fn block_projection_fence_valid_at<T: PublicTransport>(
    projection: &RelationshipProjection,
    expected_operation_scope: ProjectionOperationScope,
    expected_roster: &[String],
    authority: &RelationshipAuthority<T>,
    observed_at: DateTime<Utc>,
) -> bool {
    let Ok(plan) = plan_block_only_graph(expected_roster) else {
        return false;
    };
    if !projection.integrity_valid()
        || projection.operation_scope != expected_operation_scope
        || !relationship_operation_scope_matches(expected_operation_scope, &projection.scope)
        || projection.scope != ProjectionScope::BlockOnly(plan.scope.clone())
        || projection.scope_digest != projection_scope_digest(&projection.scope)
        || projection.appview_base != authority.config.appview_origin
        || projection.config_fingerprint != authority.config.fingerprint
        || projection.source_identity != authority.source_identity
        || projection.projection_revision == 0
        || !projection.declarations.is_empty()
        || !fresh_window(projection.started_at, projection.completed_at, observed_at)
        || projection.graph_batches.len() != plan.requests.len()
    {
        return false;
    }
    let mut kinds = BTreeSet::new();
    let mut revisions = BTreeSet::from([projection.projection_revision]);
    let valid = plan
        .requests
        .iter()
        .zip(&projection.graph_batches)
        .all(|(request, evidence)| {
            kinds.insert(evidence.evidence_kind);
            evidence.evidence_kind == projection.evidence_kind
                && evidence.actor == request.actor
                && evidence.targets == request.others
                && evidence.request_digest != [0; 32]
                && evidence.response_digest != [0; 32]
                && evidence.fetch_revision > 0
                && revisions.insert(evidence.fetch_revision)
                && evidence.fetched_at >= projection.started_at
                && evidence.fetched_at <= projection.completed_at
                && evidence.relationships.len() == request.others.len()
                && request
                    .others
                    .iter()
                    .zip(&evidence.relationships)
                    .all(|(target, row)| row.actor == request.actor && row.target == *target)
        });
    if !valid || kinds.len() > 1 || (!plan.requests.is_empty() && kinds.len() != 1) {
        return false;
    }
    true
}

pub fn consume_traffic_projection<T: PublicTransport>(
    projection: &TrafficProjection,
    authority: &RelationshipAuthority<T>,
    decision: &TrustedRelationshipDecisionInstant,
) -> Result<(), PolicyDenial> {
    let Some(expected_scope) = decision.traffic_scope() else {
        return Err(PolicyDenial::RelationshipPolicyUnavailable);
    };
    if !traffic_projection_fence_valid(projection, expected_scope, authority, decision) {
        return Err(PolicyDenial::RelationshipPolicyUnavailable);
    }
    if projection
        .graph_batches
        .iter()
        .flat_map(|batch| &batch.relationships)
        .any(GraphRelation::is_blocked)
    {
        return Err(PolicyDenial::BlockedRelationship);
    }
    Ok(())
}

fn traffic_projection_fence_valid<T: PublicTransport>(
    projection: &TrafficProjection,
    expected_scope: &TrafficGraphScope,
    authority: &RelationshipAuthority<T>,
    decision: &TrustedRelationshipDecisionInstant,
) -> bool {
    decision.traffic_scope_matches(expected_scope)
        && traffic_projection_fence_valid_at(
            projection,
            expected_scope,
            authority,
            decision.datetime(),
        )
}

fn traffic_projection_persistence_valid<T: PublicTransport>(
    projection: &TrafficProjection,
    expected_scope: &TrafficGraphScope,
    authority: &RelationshipAuthority<T>,
    observation: &TrustedRelationshipPersistenceInstant,
) -> bool {
    traffic_projection_fence_valid_at(
        projection,
        expected_scope,
        authority,
        observation.datetime(),
    )
}

fn traffic_projection_fence_valid_at<T: PublicTransport>(
    projection: &TrafficProjection,
    expected_scope: &TrafficGraphScope,
    authority: &RelationshipAuthority<T>,
    observed_at: DateTime<Utc>,
) -> bool {
    let Ok(plan) = plan_traffic_graph(&expected_scope.actor, &expected_scope.members) else {
        return false;
    };
    if !projection.integrity_valid()
        || projection.operation_scope != ProjectionOperationScope::Traffic
        || &projection.scope != expected_scope
        || projection.scope != plan.scope
        || projection.scope_digest != traffic_scope_digest(&projection.scope)
        || projection.appview_base != authority.config.appview_origin
        || projection.config_fingerprint != authority.config.fingerprint
        || projection.source_identity != authority.source_identity
        || projection.projection_revision == 0
        || !fresh_window(projection.started_at, projection.completed_at, observed_at)
        || projection.graph_batches.len() != plan.requests.len()
    {
        return false;
    }
    let mut kinds = BTreeSet::new();
    let mut revisions = BTreeSet::from([projection.projection_revision]);
    let valid = plan
        .requests
        .iter()
        .zip(&projection.graph_batches)
        .all(|(request, evidence)| {
            kinds.insert(evidence.evidence_kind);
            evidence.evidence_kind == projection.evidence_kind
                && evidence.actor == request.actor
                && evidence.targets == request.others
                && evidence.request_digest != [0; 32]
                && evidence.response_digest != [0; 32]
                && evidence.fetch_revision > 0
                && revisions.insert(evidence.fetch_revision)
                && evidence.fetched_at >= projection.started_at
                && evidence.fetched_at <= projection.completed_at
                && evidence.relationships.len() == request.others.len()
                && request
                    .others
                    .iter()
                    .zip(&evidence.relationships)
                    .all(|(target, row)| row.actor == request.actor && row.target == *target)
        });
    if !valid || (kinds.len() > 1) {
        return false;
    }
    true
}

#[cfg(test)]
mod projection_integrity_tests {
    use super::super::validation::CanonicalTimestamp;
    use super::*;
    use chrono::{SecondsFormat, TimeZone};

    #[derive(Clone)]
    struct NeverTransport;

    #[async_trait]
    impl PublicTransport for NeverTransport {
        async fn get(&self, _request: PublicGet) -> Result<PublicResponse, TransportError> {
            Err(TransportError::Network)
        }
    }

    fn persistence_config() -> RelationshipPolicyConfig {
        RelationshipPolicyConfig::new(RelationshipPolicyConfigInput {
            appview_origin: concat!("https://", "public", ".api.bsky.app").into(),
            plc_directory_origin: "https://plc.directory".into(),
            max_concurrency: 16,
            request_rate_per_second: HARD_MAX_REQUEST_RATE,
            request_burst: HARD_MAX_REQUEST_BURST,
            total_deadline: Duration::from_secs(20),
            max_response_bytes: 256 * 1024,
            max_dns_answers: 8,
            admission_graph_capacity: MAX_ADMISSION_GRAPH_CALLS,
            declaration_http_capacity: MAX_DECLARATION_HTTP_CALLS,
            admission_source_capacity: MAX_ADMISSION_SOURCE_CALLS,
            traffic_graph_capacity: MAX_TRAFFIC_GRAPH_CALLS,
        })
        .unwrap()
    }

    fn persistence_authority() -> RelationshipAuthority<NeverTransport> {
        RelationshipAuthority::new(persistence_config(), NeverTransport)
    }

    fn trusted_at(value: DateTime<Utc>) -> TrustedRequestInstant {
        let submillisecond_nanos = value.timestamp_subsec_nanos() % 1_000_000;
        let canonical_value = if submillisecond_nanos == 0 {
            value
        } else {
            value + TimeDelta::nanoseconds(i64::from(1_000_000 - submillisecond_nanos))
        };
        let canonical = canonical_value.to_rfc3339_opts(SecondsFormat::Millis, true);
        TrustedRequestInstant::from_canonical_for_test(
            CanonicalTimestamp::parse(&canonical).expect("canonical test request time"),
        )
    }

    fn sealed_admission(kind: EvidenceKind) -> (RelationshipProjection, AdmissionRequest) {
        let roster = readiness_roster(2);
        let request = AdmissionRequest {
            inviter: roster[0].clone(),
            roster: roster.clone(),
            pending_recipients: vec![roster[1].clone()],
            operation: AdmissionOperation::Direct,
        };
        let projection_id = Uuid::new_v4();
        let started_at = Utc.with_ymd_and_hms(2026, 7, 22, 12, 0, 0).unwrap();
        let completed_at = started_at + TimeDelta::seconds(1);
        let scope = ProjectionScope::Admission(request.clone());
        let authority = persistence_authority();
        let declaration = DeclarationEvidence {
            projection_id,
            recipient: roster[1].clone(),
            incoming: IncomingPolicy::Following,
            group: IncomingPolicy::Following,
            allow_group_invites: None,
            absent: false,
            cid: Some("bafyreihdwdcefgh4dqkjv67uzcmw7ojee6xedzdetojuzjevtenxquvyku".to_owned()),
            service_id: format!("{}#atproto_pds", roster[1]),
            resolved_pds_origin: CanonicalOrigin::parse("https://pds.example.net").unwrap(),
            did_request_digest: [1; 32],
            did_document_digest: [2; 32],
            record_request_digest: [3; 32],
            record_response_digest: [4; 32],
            fetch_revision: 2,
            fetched_at: started_at + TimeDelta::milliseconds(250),
            evidence_kind: kind,
        };
        let graph = GraphBatchEvidence {
            projection_id,
            actor: roster[1].clone(),
            targets: vec![roster[0].clone()],
            relationships: vec![GraphRelation {
                actor: roster[1].clone(),
                target: roster[0].clone(),
                following: true,
                followed_by: false,
                blocking: false,
                blocked_by: false,
                blocking_by_list: false,
                blocked_by_list: false,
            }],
            request_digest: [5; 32],
            response_digest: [6; 32],
            fetch_revision: 3,
            fetched_at: started_at + TimeDelta::milliseconds(500),
            evidence_kind: kind,
        };
        let mut projection = RelationshipProjection {
            projection_id,
            operation_scope: ProjectionOperationScope::Creation,
            scope_digest: projection_scope_digest(&scope),
            scope,
            appview_base: authority.config.appview_origin.clone(),
            config_fingerprint: authority.config.fingerprint,
            source_identity: authority.source_identity,
            projection_revision: 1,
            persistence_authority: ProjectionPersistenceAuthority::hydrated(),
            source_call_count: 3,
            started_at,
            completed_at,
            evidence_kind: kind,
            declarations: vec![declaration],
            graph_batches: vec![graph],
            evidence_digest: [0; 32],
        };
        projection.evidence_digest = relationship_evidence_digest(&projection);
        (projection, request)
    }

    fn assert_admission_rejected(projection: &RelationshipProjection, request: &AdmissionRequest) {
        let authority = persistence_authority();
        assert!(!projection.integrity_valid());
        assert_eq!(
            consume_admission_projection(
                projection,
                ProjectionOperationScope::Creation,
                request,
                &authority,
                &TrustedRelationshipDecisionInstant::for_test_relationship(
                    "4242".to_owned(),
                    ProjectionOperationScope::Creation,
                    ProjectionScope::Admission(request.clone()),
                    [0x91; 32],
                    projection.completed_at,
                ),
                false,
            ),
            Err(PolicyDenial::RelationshipPolicyUnavailable)
        );
    }

    #[test]
    fn all_fallback_projection_is_positive_and_every_decision_is_digest_bound() {
        let (projection, request) = sealed_admission(EvidenceKind::Fallback);
        let authority = persistence_authority();
        assert!(projection.integrity_valid());
        assert_eq!(
            consume_admission_projection(
                &projection,
                ProjectionOperationScope::Creation,
                &request,
                &authority,
                &TrustedRelationshipDecisionInstant::for_test_relationship(
                    "4242".to_owned(),
                    ProjectionOperationScope::Creation,
                    ProjectionScope::Admission(request.clone()),
                    [0x91; 32],
                    projection.completed_at,
                ),
                false,
            ),
            Ok(())
        );

        for decision in 0..8 {
            let mut changed = projection.clone();
            match decision {
                0 => changed.declarations[0].incoming = IncomingPolicy::None,
                1 => changed.declarations[0].group = IncomingPolicy::None,
                2 => changed.graph_batches[0].relationships[0].following = false,
                3 => changed.graph_batches[0].relationships[0].followed_by = true,
                4 => changed.graph_batches[0].relationships[0].blocking = true,
                5 => changed.graph_batches[0].relationships[0].blocked_by = true,
                6 => changed.graph_batches[0].relationships[0].blocking_by_list = true,
                7 => changed.graph_batches[0].relationships[0].blocked_by_list = true,
                _ => unreachable!(),
            }
            assert_admission_rejected(&changed, &request);
        }
    }

    #[test]
    fn every_evidence_digest_and_row_identity_is_aggregate_bound() {
        let (projection, request) = sealed_admission(EvidenceKind::Live);
        for digest in 0..6 {
            let mut changed = projection.clone();
            match digest {
                0 => changed.declarations[0].did_request_digest[0] ^= 1,
                1 => changed.declarations[0].did_document_digest[0] ^= 1,
                2 => changed.declarations[0].record_request_digest[0] ^= 1,
                3 => changed.declarations[0].record_response_digest[0] ^= 1,
                4 => changed.graph_batches[0].request_digest[0] ^= 1,
                5 => changed.graph_batches[0].response_digest[0] ^= 1,
                _ => unreachable!(),
            }
            assert_admission_rejected(&changed, &request);
        }

        let mut changed = projection.clone();
        changed.declarations[0].resolved_pds_origin =
            CanonicalOrigin::parse("https://other.example.net").unwrap();
        assert_admission_rejected(&changed, &request);

        let mut changed = projection.clone();
        changed.declarations[0].evidence_kind = EvidenceKind::Fallback;
        assert_admission_rejected(&changed, &request);

        let mut changed = projection.clone();
        changed.graph_batches[0].fetch_revision += 1;
        assert_admission_rejected(&changed, &request);

        let mut changed = projection.clone();
        changed.evidence_digest[0] ^= 1;
        assert_admission_rejected(&changed, &request);
    }

    #[test]
    fn projection_or_row_mixing_rejects_even_if_an_internal_caller_rehashes() {
        let (projection, request) = sealed_admission(EvidenceKind::Live);
        let (other, _) = sealed_admission(EvidenceKind::Live);

        let mut changed = projection.clone();
        changed.projection_id = other.projection_id;
        assert_admission_rejected(&changed, &request);

        let mut changed = projection.clone();
        changed.declarations[0] = other.declarations[0].clone();
        changed.evidence_digest = relationship_evidence_digest(&changed);
        assert_admission_rejected(&changed, &request);

        let mut changed = projection.clone();
        changed.graph_batches[0] = other.graph_batches[0].clone();
        changed.evidence_digest = relationship_evidence_digest(&changed);
        assert_admission_rejected(&changed, &request);
    }

    #[test]
    fn hydrate_rederives_every_public_request_digest_from_exact_authority_and_scope() {
        let (mut projection, _request) = sealed_admission(EvidenceKind::Live);
        let authority = persistence_authority();
        projection.evidence_digest = relationship_evidence_digest(&projection);

        for digest in 0..3 {
            let mut changed = projection.clone();
            match digest {
                0 => changed.declarations[0].did_request_digest[0] ^= 1,
                1 => changed.declarations[0].record_request_digest[0] ^= 1,
                2 => changed.graph_batches[0].request_digest[0] ^= 1,
                _ => unreachable!(),
            }
            changed.evidence_digest = relationship_evidence_digest(&changed);
            let values = persist_relationship_projection(&changed).unwrap();
            assert!(hydrate_persisted_relationship_projection(
                values,
                &authority,
                &TrustedRelationshipDecisionInstant::for_test_relationship(
                    "4242".to_owned(),
                    changed.operation_scope,
                    changed.scope.clone(),
                    [0x91; 32],
                    changed.completed_at,
                ),
            )
            .is_err());
        }
    }

    #[test]
    fn persistence_rejects_postgres_unrepresentable_revision_and_timestamp() {
        let (projection, _) = sealed_admission(EvidenceKind::Live);

        let mut unsafe_revision = projection.clone();
        unsafe_revision.projection_revision = 9_007_199_254_740_992;
        unsafe_revision.evidence_digest = relationship_evidence_digest(&unsafe_revision);
        assert_eq!(
            persist_relationship_projection(&unsafe_revision),
            Err(ProjectionPersistenceError::Invalid)
        );

        let mut submicrosecond_time = projection;
        submicrosecond_time.started_at += TimeDelta::nanoseconds(1);
        submicrosecond_time.evidence_digest = relationship_evidence_digest(&submicrosecond_time);
        assert_eq!(
            persist_relationship_projection(&submicrosecond_time),
            Err(ProjectionPersistenceError::Invalid)
        );
    }

    fn sealed_traffic(duplicate_revision: bool) -> TrafficProjection {
        let members = readiness_roster(32);
        let plan = plan_traffic_graph(&members[0], &members).unwrap();
        let projection_id = Uuid::new_v4();
        let started_at = Utc.with_ymd_and_hms(2026, 7, 22, 12, 0, 0).unwrap();
        let completed_at = started_at + TimeDelta::seconds(1);
        let authority = persistence_authority();
        let graph_batches: Vec<GraphBatchEvidence> = plan
            .requests
            .iter()
            .enumerate()
            .map(|(index, request)| GraphBatchEvidence {
                projection_id,
                actor: request.actor.clone(),
                targets: request.others.clone(),
                relationships: request
                    .others
                    .iter()
                    .map(|target| GraphRelation {
                        actor: request.actor.clone(),
                        target: target.clone(),
                        following: false,
                        followed_by: false,
                        blocking: false,
                        blocked_by: false,
                        blocking_by_list: false,
                        blocked_by_list: false,
                    })
                    .collect(),
                request_digest: [7 + index as u8; 32],
                response_digest: [17 + index as u8; 32],
                fetch_revision: if duplicate_revision {
                    2
                } else {
                    2 + index as u64
                },
                fetched_at: started_at + TimeDelta::milliseconds(100 + index as i64),
                evidence_kind: EvidenceKind::Fallback,
            })
            .collect();
        let mut projection = TrafficProjection {
            projection_id,
            operation_scope: ProjectionOperationScope::Traffic,
            scope_digest: traffic_scope_digest(&plan.scope),
            scope: plan.scope,
            appview_base: authority.config.appview_origin.clone(),
            config_fingerprint: authority.config.fingerprint,
            source_identity: authority.source_identity,
            projection_revision: 1,
            persistence_authority: ProjectionPersistenceAuthority::hydrated(),
            source_call_count: u64::try_from(graph_batches.len()).unwrap(),
            started_at,
            completed_at,
            evidence_kind: EvidenceKind::Fallback,
            graph_batches,
            evidence_digest: [0; 32],
        };
        projection.evidence_digest = traffic_evidence_digest(&projection);
        projection
    }

    #[test]
    fn traffic_requires_unique_local_fetch_revisions() {
        let authority = persistence_authority();
        let duplicate = sealed_traffic(true);
        assert!(duplicate.integrity_valid());
        assert_eq!(
            consume_traffic_projection(
                &duplicate,
                &authority,
                &TrustedRelationshipDecisionInstant::for_test_traffic(
                    "4242".to_owned(),
                    duplicate.scope.clone(),
                    [0x91; 32],
                    duplicate.completed_at,
                ),
            ),
            Err(PolicyDenial::RelationshipPolicyUnavailable)
        );

        let unique = sealed_traffic(false);
        assert_eq!(
            consume_traffic_projection(
                &unique,
                &authority,
                &TrustedRelationshipDecisionInstant::for_test_traffic(
                    "4242".to_owned(),
                    unique.scope.clone(),
                    [0x91; 32],
                    unique.completed_at,
                ),
            ),
            Ok(())
        );
    }
}
