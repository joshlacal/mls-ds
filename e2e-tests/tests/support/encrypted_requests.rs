//! Fail-closed support for the encrypted direct-request acceptance suite.
//!
//! This module deliberately owns no product behavior. It establishes the local
//! authority boundary for later request tests: one exact PostgreSQL database,
//! the immutable 14-migration clean-chat baseline, an executable shipping
//! server artifact, and separate real MLS stores for every enrolled device.
//! Until the request handlers and isolated preparation API land, methods that
//! need them return a typed dependency error rather than manufacturing a pass.

#![allow(dead_code)]

use std::{
    collections::HashMap,
    io::{BufRead, BufReader},
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    sync::{Mutex, OnceLock},
};

use anyhow::{bail, Context, Result};
use base64::{
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
    Engine as _,
};
use catbird_mls::chat_v2::transcript::direct_request::{self as protocol, DirectRequestKind};
use mls_e2e_tests::mls_engine::MlsEngine;
use p256::{
    ecdsa::{signature::Signer as _, Signature, SigningKey},
    pkcs8::{EncodePrivateKey, LineEnding},
};
use reqwest::StatusCode;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256, Sha384};
use uuid::Uuid;

pub const REQUEST_TEST_DATABASE_NAME: &str = "catbird_direct_requests_test_20260919";
pub const REQUEST_TEST_DATABASE_URL: &str =
    "postgresql://127.0.0.1:5432/catbird_direct_requests_test_20260919";
pub const REQUEST_TEST_DATABASE_ENV: &str = "REQUEST_TEST_DATABASE_URL";
pub const REQUEST_SERVER_BINARY_ENV: &str = "REQUEST_SERVER_BINARY";
pub const REQUEST_AUTH_FIXTURE_ENV: &str = "REQUEST_AUTH_FIXTURE";
pub const REQUEST_SERVER_FIXTURE_BINARY_ENV: &str = "REQUEST_SERVER_FIXTURE_BINARY";
pub const RELATIONSHIP_APPVIEW_HOST: &str = "public.api.bsky.app";
const AUTH_JTI_MIGRATION: &str =
    include_str!("../../../server/migrations/20260214000002_auth_jti_nonce.sql");
const AUTH_JTI_MIGRATION_SHA384: &str =
    "a653190a473ce3535c946769e8e269173fcf22c1cc6196063eb9461e4766bc084a57c61d2b3a4ffee4b5a1b4da06856b";
const SERVICE_AUTH_MIGRATION: &str =
    include_str!("../../../server/migrations/20260820000001_chat_service_auth_admissions.sql");
const SERVICE_AUTH_MIGRATION_SHA384: &str =
    "2e8cb6bf47498402e56ba5c2fc753114c1d46e0767c98aa243c47993eb4f51a84de89469a8ae9af6bfac751ddadd18ac";
const SERVICE_AUTH_MIGRATION_VERSION: i64 = 20260820000001;
const SERVICE_AUTH_MIGRATION_DESCRIPTION: &str = "chat service auth admissions";

static DATABASE_SETUP_LOCK: OnceLock<Mutex<()>> = OnceLock::new();

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum FaultBoundary {
    BeforeRequest,
    AfterRequestBeforeResponse,
    AfterCommittedResponse,
}

#[derive(Clone, Debug, Default)]
pub struct DeterministicFaultTransport {
    remaining: HashMap<FaultBoundary, usize>,
    trace: Vec<FaultBoundary>,
}

impl DeterministicFaultTransport {
    pub fn fail_on(mut self, boundary: FaultBoundary, occurrence: usize) -> Result<Self> {
        anyhow::ensure!(occurrence > 0, "fault occurrence must be positive");
        self.remaining.insert(boundary, occurrence);
        Ok(self)
    }

    pub fn checkpoint(&mut self, boundary: FaultBoundary) -> Result<()> {
        self.trace.push(boundary);
        if let Some(remaining) = self.remaining.get_mut(&boundary) {
            *remaining -= 1;
            if *remaining == 0 {
                self.remaining.remove(&boundary);
                bail!("deterministic transport fault at {boundary:?}")
            }
        }
        Ok(())
    }

    pub fn trace(&self) -> &[FaultBoundary] {
        &self.trace
    }

    pub async fn post_json(
        &mut self,
        client: &reqwest::Client,
        url: &str,
        body: &Value,
    ) -> Result<reqwest::Response> {
        self.checkpoint(FaultBoundary::BeforeRequest)?;
        let response = client
            .post(url)
            .json(body)
            .send()
            .await
            .context("deterministic request transport")?;
        // Failing here deliberately discards a real response after the server
        // could have committed, reproducing an unknown publication outcome.
        self.checkpoint(FaultBoundary::AfterRequestBeforeResponse)?;
        self.checkpoint(FaultBoundary::AfterCommittedResponse)?;
        Ok(response)
    }
}

#[derive(Clone, Debug)]
pub struct BaselineMigration {
    pub filename: &'static str,
    pub version: i64,
    pub description: &'static str,
    pub reviewed_sha384: &'static str,
    pub sql: &'static str,
}

macro_rules! baseline {
    ($version:literal, $description:literal, $filename:literal, $sha384:literal) => {
        BaselineMigration {
            filename: $filename,
            version: $version,
            description: $description,
            reviewed_sha384: $sha384,
            sql: include_str!(concat!("../../../server/migrations/", $filename)),
        }
    };
}

pub fn reviewed_baseline() -> [BaselineMigration; 14] {
    [
        baseline!(20260722000001, "chat protocol core", "20260722000001_chat_protocol_core.sql", "dd48feea7beafae59fbc11516e8c1ae91382b356b80366056f71d2493c10923bd39ff0739fe08cb4b0452b0ec82132ff"),
        baseline!(20260722000002, "chat protocol delivery", "20260722000002_chat_protocol_delivery.sql", "86952763aaeb8f4cf8a8a18dd5d022a5357d450193e265a18da5a771513b9d4c7c8408bad27c4f4ba3b712b41b80e504"),
        baseline!(20260722000003, "chat protocol blobs", "20260722000003_chat_protocol_blobs.sql", "310101886f60d3a663ee5df829bbc86a96a45e23adee754220d3b06fd74acfd708d23a138124872a5177244d3e14e8eb"),
        baseline!(20260725000001, "prepare welcome provenance backfill", "20260725000001_prepare_welcome_provenance_backfill.sql", "3f3d1660193bc37aa8c9876e636a4918f59404f0e055f509b9a67158b6028d947adc299c4d776a693bf8b75e647d90a8"),
        baseline!(20260725000002, "refine welcome provenance quarantine", "20260725000002_refine_welcome_provenance_quarantine.sql", "8dd0a595288182e2c36aed67d7155138a0817deb5d236dd1eaea50f066a90d7949f60c0de6bff5c9e8bd28e4a1c50de2"),
        baseline!(20260726000001, "welcome supersession provenance", "20260726000001_welcome_supersession_provenance.sql", "78c31ff78db5b8889fb00cb7024186a0f048975fc7a059c667e326162e3f338396d9760143367c9206802d21269484f4"),
        baseline!(20260726000002, "restore welcome provenance deferred triggers", "20260726000002_restore_welcome_provenance_deferred_triggers.sql", "1b29d045575aea2552ac10bdb61451662d51bca5afa75827e030e5dd859eee0d1664e12a69ecea9692e0fadb2a8df4af"),
        baseline!(20260726000003, "finalize welcome provenance triggers", "20260726000003_finalize_welcome_provenance_triggers.sql", "8bd956b8383bea542c6d591ae7721b92b898cb07e49b503131bedfbb511937147766569bcd2b23da11b226decffec495"),
        baseline!(20260728000001, "chat operation claims", "20260728000001_chat_operation_claims.sql", "fd71f2eb5235226371f113b5738b752b27e901b72810e9ec1e1f201e979606e0b09a16be087103e4146b4fb9f8bdff8f"),
        baseline!(20260728000002, "exact operation claim mutation kind", "20260728000002_exact_operation_claim_mutation_kind.sql", "a5c0225818e350415e0ad3a88c5016d621a75bb64563f97023de9d27498cf113d8ef9d95c98621036c15ac3398dbee17"),
        baseline!(20260728000003, "defer operation claim principal fk", "20260728000003_defer_operation_claim_principal_fk.sql", "d42c64d98f6af2042ecf5d08b925aaadae01efcd7d1f6d1887c5485e0862d80304bb9ba54506a1876eba54b505d4114a"),
        baseline!(20260728000004, "activate operation claim completeness", "20260728000004_activate_operation_claim_completeness.sql", "7de97f6f84a9cfcbf535b990b5aec87930450cf6661c7d8cf11920bdf53fd0fe94623e9ed222a8eeb562c1ee596c5bd6"),
        baseline!(20260729000001, "chat g7 inventory entitlement", "20260729000001_chat_g7_inventory_entitlement.sql", "2c00fc11f1d96b79c3c86320e769d70d52fecb477a8a2bc351151fd2d01e3d4c5df19cbf7a3ac482edbe16a33a0dd60e"),
        baseline!(20260730000001, "reset request revocation terminal", "20260730000001_reset_request_revocation_terminal.sql", "36ea55abb2cc644213fad4edd21df3e3ee10e680d63e714a22193eaf483fb022cf76106bf79fdd8a4ba1c285eb64d28b"),
    ]
}

pub fn reviewed_request_migrations() -> [BaselineMigration; 19] {
    [
        baseline!(20260919000001, "direct request preparation", "20260919000001_direct_request_preparation.sql", "d4d3527aa77b8fe91d8d754f72290b682571cc6731866d72c059f10d4b2f7cf8ef629069737addeedaabd6f6eee682ca"),
        baseline!(20260919000002, "direct request publication", "20260919000002_direct_request_publication.sql", "7fda0b09fcdef20e4da2e1701f6a56c12f636f7881b46e2f6e249cb0d5fc2aa63c734dc07cbb543169398253e29cec9e"),
        baseline!(20260919000003, "direct request lifecycle", "20260919000003_direct_request_lifecycle.sql", "c51bc3851c68556437867249e163fd320fd792f62401695df1c5e9182aa5141687c5e193fdb9d11a37d7ff6be3811572"),
        baseline!(20260919000004, "direct request welcome delivery", "20260919000004_direct_request_welcome_delivery.sql", "a93682f234ab1c2efdf98d6da51c444d89d750a224b67117f65e34045d54e6ada28c69858433bfc93be70c8e4b7827c4"),
        baseline!(20260919000005, "direct request budget release", "20260919000005_direct_request_budget_release.sql", "0c2e4c2b2b5f3fe662e5d91ae85969825ac932ad708e4840cfa3f426414462d678547e49e481ff9eeda531f40828fad0"),
        baseline!(20260919000006, "direct request attempt null fences", "20260919000006_direct_request_attempt_null_fences.sql", "871e44752b1f8e35a684589ada95e2bdfdf88c667c6e371bdbae15f8ff2e6bb513fbc369b74bc4bd9244c6e693f9ac4c"),
        baseline!(20260919000007, "direct request publication integrity", "20260919000007_direct_request_publication_integrity.sql", "6f6192cd5d620becadd5bcd47cb38e50b30ab999ea7c3c410804a527bcb23aaa10f3913098211ce072cafdb6591af6db"),
        baseline!(20260919000008, "direct request lifecycle fences", "20260919000008_direct_request_lifecycle_fences.sql", "64dcfb75a6adc3ed3509cdb6e439ff745813286e7baad2b0ad3c71bc5722694eef13bd4e12e048636e5c27a2964e65d0"),
        baseline!(20260919000009, "direct request acceptance claims", "20260919000009_direct_request_acceptance_claims.sql", "c1210eb15ecc821c380acd4fbc3fff471d6b42304d38f60f6c6acb9e7b91f233421e32ce18d99802b9e6fdd050d72e9a"),
        baseline!(20260919000010, "direct request retained artifacts", "20260919000010_direct_request_retained_artifacts.sql", "598aea96b9a02d6c3c24937e81929c14496cdb24698dd8be9a091609c8d40975f5957242a5a81aeeedab2cb79cb36288"),
        baseline!(20260919000011, "direct request lifecycle slots", "20260919000011_direct_request_lifecycle_slots.sql", "158cee3681184afb77ba824c3357717f945027d93ba75c33b1f5d5cc568d6098e33b0874a5465a6d76cbca72a2d604bf"),
        baseline!(20260919000012, "direct request welcome slot digest", "20260919000012_direct_request_welcome_slot_digest.sql", "dbe9835b66cba3edd3c21ca1756ae1ee2b13a8c0fbb67fea3dc3b1f754bc5eca90d7a36fff1ff10c6ad568f52eb3312d"),
        baseline!(20260919000013, "direct request signed json projection", "20260919000013_direct_request_signed_json_projection.sql", "d8170f613b3c2c2fc087b8ab7c5f24d15dd4379ba3605048390beccbdecdd85a525f5d70c3b340d98d053c543d924156"),
        baseline!(20260919000014, "direct request nul comparison", "20260919000014_direct_request_nul_comparison.sql", "2f47a3019d459b7989f544773da035e10914af95b85ad553afd70e84367189085a3c8507b7314bfa84d4cc4335a1d8b8"),
        baseline!(20260919000015, "direct request entry identity", "20260919000015_direct_request_entry_identity.sql", "157cac50d04bd77388897fe386acd915ece5046c40923dec21675726ed091ac5b709691664a57241f67c8415e73cf29d"),
        baseline!(20260919000016, "direct request push bindings", "20260919000016_direct_request_push_bindings.sql", "483aee1650f60a488d2a6498c11e4ce229906889ca1a655c37f080fefccf610bc4f552b06a63719ff471f95c060360f8"),
        baseline!(20260919000017, "direct request push outbox", "20260919000017_direct_request_push_outbox.sql", "813c165f4e1739fb81d1cd26b2e1cea505745b1df77d22d6ca4882ba44bf2a9446a0929be20320e04a22c93e2bdc380b"),
        baseline!(20260919000018, "fix direct request lifecycle close fence", "20260919000018_fix_direct_request_lifecycle_close_fence.sql", "db45c270c4f162078319724213518f3d3186ab5883ff75729e253663874738a001fa61af41791065eeca2f8c76bc1974"),
        baseline!(20260919000021, "direct request capacity abuse fix", "20260919000021_direct_request_capacity_abuse_fix.sql", "5b6d18e3f9a43bccf357ee37f0df7b322d956369fb55cd036fbbbdb4e63f5c291730ac10885b6de511a697cb365939ca"),
    ]
}

/// The only alternatives to the shared guarded database, each dedicated to
/// one test and loopback-only. Returns the database name when `url` is:
/// - `127.0.0.1:<port != 5432>/catbird_direct_requests_faketime_<[a-z0-9_]{1,40}>`,
///   a private cluster from `e2e-tests/support/faketime_postgres.py` whose
///   clock the test advances; or
/// - `127.0.0.1:5432/catbird_direct_requests_fault_<16 lowercase hex>`, a
///   dedicated fault-injection clone on the shared cluster.
pub fn dedicated_request_database_name(url: &str) -> Option<&str> {
    let (port, name) = url
        .strip_prefix("postgresql://127.0.0.1:")?
        .split_once('/')?;
    if !port.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let port = port.parse::<u16>().ok()?;
    let valid = if let Some(suffix) = name.strip_prefix("catbird_direct_requests_faketime_") {
        port != 0
            && port != 5432
            && (1..=40).contains(&suffix.len())
            && suffix
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_')
    } else if let Some(suffix) = name.strip_prefix("catbird_direct_requests_fault_") {
        url == format!("postgresql://127.0.0.1:5432/{name}")
            && suffix.len() == 16
            && suffix
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    } else {
        false
    };
    valid.then_some(name)
}

pub fn validate_request_test_database_url(value: Option<&str>) -> Result<String> {
    match value {
        Some(REQUEST_TEST_DATABASE_URL) => Ok(REQUEST_TEST_DATABASE_NAME.to_owned()),
        Some(url) => match dedicated_request_database_name(url) {
            Some(name) => Ok(name.to_owned()),
            None => bail!(
                "{REQUEST_TEST_DATABASE_ENV} must equal {REQUEST_TEST_DATABASE_URL} or name a dedicated faketime/fault request database"
            ),
        },
        None => bail!("{REQUEST_TEST_DATABASE_ENV} is required"),
    }
}

static ROUTED_DATABASE_URL: OnceLock<String> = OnceLock::new();

/// Target of every harness psql, fixture, and guarded-connection call. Fixed
/// once per process: an explicit `route_to_dedicated_database`, else a
/// dedicated `REQUEST_TEST_DATABASE_URL`, else the shared guarded database.
pub fn request_database_url() -> &'static str {
    ROUTED_DATABASE_URL.get_or_init(|| match std::env::var(REQUEST_TEST_DATABASE_ENV) {
        Ok(url) if dedicated_request_database_name(&url).is_some() => url,
        _ => REQUEST_TEST_DATABASE_URL.to_owned(),
    })
}

/// Route this whole test process to one dedicated database. Must precede the
/// first harness database use; rerouting to a different target fails.
pub fn route_to_dedicated_database(url: &str) -> Result<()> {
    anyhow::ensure!(
        dedicated_request_database_name(url).is_some(),
        "{url} is not a dedicated faketime/fault request database"
    );
    let routed = ROUTED_DATABASE_URL.get_or_init(|| url.to_owned());
    anyhow::ensure!(
        routed == url,
        "request harness already routed to {routed}; cannot reroute to {url}"
    );
    Ok(())
}

fn reviewed_send_message_prerequisite() -> BaselineMigration {
    baseline!(20260816000001, "enable send message operation claims", "20260816000001_enable_send_message_operation_claims.sql", "ae9cc21dd145c3608a57e1f96654b67d53709dba17e3f347758aa8b93830c725d380230751d83f85c497132b8669a30e")
}

fn reviewed_inventory_gc_prerequisite() -> BaselineMigration {
    baseline!(20260821000001, "fix expired inventory session gc", "20260821000001_fix_expired_inventory_session_gc.sql", "42790274fbeb43bce44aa9638d23328223042933af03e6453a0c8c3640b9bcf236d0bc0b8cd76e1e5d846be7c6bfc78a")
}

fn reviewed_pending_inventory_prerequisite() -> BaselineMigration {
    baseline!(20260907000001, "chat direct pending inventory", "20260907000001_chat_direct_pending_inventory.sql", "82708d24b2deb72452ebdaf28749aa86ed95075f7ed920c4cc5526962e2ae9f9d8561a5029fc853ba654564d76ef63f1")
}

fn reviewed_service_auth_prerequisite() -> BaselineMigration {
    baseline!(20260820000001, "chat service auth admissions", "20260820000001_chat_service_auth_admissions.sql", "2e8cb6bf47498402e56ba5c2fc753114c1d46e0767c98aa243c47993eb4f51a84de89469a8ae9af6bfac751ddadd18ac")
}

fn reviewed_legacy_dpop_prerequisite() -> BaselineMigration {
    baseline!(20260820000002, "chat nullable legacy dpop jkt", "20260820000002_chat_nullable_legacy_dpop_jkt.sql", "d1914c731e0fbf81f5b0a9bf9cd77c12f2943fd940c36b9a351b1156b5ca09b55f2b4b44c6810012b4377f6ac283955d")
}

fn reviewed_performance_indices_prerequisite() -> BaselineMigration {
    baseline!(20260824000001, "chat performance indices", "20260824000001_chat_performance_indices.sql", "e5f3f169724d2afc84043d80057bf9e494fbc9ad617ced0feaebb469d1be68788e7c19e19a67fb36296b85ee803139e0")
}

/// Every reviewed prerequisite between the immutable baseline and the request
/// migrations, in production version order. The guarded ledger prefix must
/// match this exact sequence.
fn reviewed_prerequisites() -> [BaselineMigration; 6] {
    [
        reviewed_send_message_prerequisite(),
        reviewed_service_auth_prerequisite(),
        reviewed_legacy_dpop_prerequisite(),
        reviewed_inventory_gc_prerequisite(),
        reviewed_performance_indices_prerequisite(),
        reviewed_pending_inventory_prerequisite(),
    ]
}

fn validate_reviewed_baseline_source() -> Result<()> {
    let baseline = reviewed_baseline();
    anyhow::ensure!(
        baseline.len() == 14,
        "reviewed baseline must contain 14 migrations"
    );
    for (index, entry) in baseline.iter().enumerate() {
        let bytes = entry.sql.as_bytes();
        anyhow::ensure!(
            hex::encode(Sha384::digest(bytes)) == entry.reviewed_sha384,
            "reviewed migration checksum mismatch for {}",
            entry.filename
        );
        let filename_version = entry
            .filename
            .split_once('_')
            .and_then(|(version, _)| version.parse::<i64>().ok())
            .context("invalid reviewed migration filename")?;
        anyhow::ensure!(
            filename_version == entry.version,
            "filename/version mismatch"
        );
        if index > 0 {
            anyhow::ensure!(
                baseline[index - 1].version < entry.version,
                "reviewed migrations are not strictly ordered"
            );
        }
    }
    Ok(())
}

fn validate_reviewed_request_sources() -> Result<()> {
    let migrations = reviewed_request_migrations();
    for (index, entry) in migrations.iter().enumerate() {
        anyhow::ensure!(
            hex::encode(Sha384::digest(entry.sql.as_bytes())) == entry.reviewed_sha384,
            "reviewed request migration checksum mismatch for {}",
            entry.filename
        );
        if index > 0 {
            anyhow::ensure!(
                migrations[index - 1].version < entry.version,
                "reviewed request migrations are not strictly ordered"
            );
        }
    }
    Ok(())
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DatabaseAuthority {
    pub database: String,
    pub user: String,
    pub owner: String,
    pub server_address: String,
    pub baseline_migrations: usize,
    pub additive_migrations: usize,
}

pub async fn connect_guarded_request_database(max_connections: u32) -> Result<DatabaseAuthority> {
    anyhow::ensure!(
        max_connections > 0,
        "request test pool must have a connection"
    );
    let raw = std::env::var(REQUEST_TEST_DATABASE_ENV).ok();
    validate_request_test_database_url(raw.as_deref())?;
    let expected_database = validate_request_test_database_url(Some(request_database_url()))?;
    let _setup = DATABASE_SETUP_LOCK
        .get_or_init(|| Mutex::new(()))
        .lock()
        .map_err(|_| anyhow::anyhow!("encrypted-request database setup lock poisoned"))?;
    let authority = psql_query(
        "SELECT current_database(),current_user,pg_get_userbyid(d.datdba),host(inet_server_addr()) FROM pg_database d WHERE d.datname=current_database()",
    )?;
    let fields = authority.trim().split('\t').collect::<Vec<_>>();
    anyhow::ensure!(
        fields.len() == 4,
        "unexpected database authority projection"
    );
    let database = fields[0].to_owned();
    let user = fields[1].to_owned();
    let owner = fields[2].to_owned();
    let server_address = fields[3].to_owned();
    anyhow::ensure!(
        database == expected_database,
        "unexpected request database {database}"
    );
    anyhow::ensure!(
        user == owner,
        "request database role {user} is not owner {owner}"
    );
    anyhow::ensure!(
        server_address == "127.0.0.1",
        "request database is not loopback: {server_address:?}"
    );

    install_or_validate_reviewed_baseline()?;
    install_auth_replay_prerequisite()?;
    install_service_auth_prerequisite()?;
    let ledger: Vec<InstalledMigration> = serde_json::from_str(&psql_query(
        "SELECT coalesce(json_agg(json_build_object('version',version,'description',description,'success',success,'checksum',encode(checksum,'hex')) ORDER BY version),'[]'::json)::text FROM public._sqlx_migrations",
    )?)
    .context("decode encrypted-request migration ledger")?;
    let baseline = reviewed_baseline();
    anyhow::ensure!(
        ledger.len() >= baseline.len(),
        "migration ledger lost reviewed baseline rows"
    );
    for (actual, expected) in ledger.iter().take(14).zip(baseline.iter()) {
        anyhow::ensure!(
            actual.version == expected.version,
            "reviewed baseline version drift"
        );
        anyhow::ensure!(
            actual.description == expected.description,
            "reviewed baseline description drift"
        );
        anyhow::ensure!(
            actual.success,
            "reviewed baseline contains a failed migration"
        );
        anyhow::ensure!(
            actual.checksum == hex::encode(Sha384::digest(expected.sql.as_bytes())),
            "reviewed baseline checksum drift"
        );
    }
    let prerequisites = reviewed_prerequisites();
    anyhow::ensure!(
        ledger.len() >= baseline.len() + prerequisites.len(),
        "migration ledger lost reviewed prerequisite rows"
    );
    for (actual, expected) in ledger[baseline.len()..]
        .iter()
        .zip(prerequisites.iter())
    {
        anyhow::ensure!(
            actual.version == expected.version
                && actual.description == expected.description
                && actual.success
                && actual.checksum == expected.reviewed_sha384,
            "reviewed prerequisite ledger drift at {}",
            expected.version
        );
    }
    let expected_request = reviewed_request_migrations();
    let actual_request = &ledger[baseline.len() + prerequisites.len()..];
    anyhow::ensure!(
        actual_request.len() == expected_request.len(),
        "request migration ledger count drift: expected {}, found {}",
        expected_request.len(),
        actual_request.len()
    );
    for (row, expected) in actual_request.iter().zip(expected_request.iter()) {
        anyhow::ensure!(
            row.version == expected.version,
            "request migration version drift"
        );
        anyhow::ensure!(
            row.description == expected.description,
            "request migration description drift at {}",
            row.version
        );
        anyhow::ensure!(
            row.success,
            "request additive migration {} failed",
            row.version
        );
        anyhow::ensure!(
            row.checksum == expected.reviewed_sha384,
            "request migration checksum drift at {}",
            row.version
        );
    }
    Ok(DatabaseAuthority {
        database,
        user,
        owner,
        server_address,
        baseline_migrations: 14,
        additive_migrations: actual_request.len(),
    })
}

fn install_auth_replay_prerequisite() -> Result<()> {
    anyhow::ensure!(
        hex::encode(Sha384::digest(AUTH_JTI_MIGRATION.as_bytes())) == AUTH_JTI_MIGRATION_SHA384,
        "canonical auth JTI migration checksum drift"
    );
    psql_exec(AUTH_JTI_MIGRATION)?;
    anyhow::ensure!(
        psql_query("SELECT to_regclass('public.auth_jti_nonce')::text")?.trim() == "auth_jti_nonce",
        "canonical auth JTI replay store is unavailable"
    );
    Ok(())
}

fn install_service_auth_prerequisite() -> Result<()> {
    anyhow::ensure!(
        hex::encode(Sha384::digest(SERVICE_AUTH_MIGRATION.as_bytes()))
            == SERVICE_AUTH_MIGRATION_SHA384,
        "canonical service-auth admission migration checksum drift"
    );
    let exists =
        psql_query("SELECT to_regclass('chat.service_auth_admissions') IS NOT NULL")? == "t\n";
    if !exists {
        psql_exec(SERVICE_AUTH_MIGRATION)?;
    }
    let columns = psql_query(
        "SELECT string_agg(attname||':'||format_type(atttypid,atttypmod)||':'||attnotnull::text,',' ORDER BY attnum) \
         FROM pg_attribute WHERE attrelid='chat.service_auth_admissions'::regclass \
         AND attnum>0 AND NOT attisdropped",
    )?;
    anyhow::ensure!(
        columns.trim() == "admission_id:uuid:true,issuer_did:text:true,endpoint_nsid:text:true,device_id:uuid:true,jti_sha256:bytea:true,token_sha256:bytea:true,token_iat:timestamp with time zone:true,token_exp:timestamp with time zone:true,consumed_at:timestamp with time zone:true",
        "service-auth admission column contract drift"
    );
    let constraints = psql_query(
        "SELECT string_agg(conname,',' ORDER BY conname) FROM pg_constraint \
         WHERE conrelid='chat.service_auth_admissions'::regclass",
    )?;
    anyhow::ensure!(
        constraints.trim() == "service_auth_admissions_endpoint_chat,service_auth_admissions_issuer_nonempty,service_auth_admissions_jti_digest,service_auth_admissions_jti_once,service_auth_admissions_pkey,service_auth_admissions_time_profile,service_auth_admissions_token_digest",
        "service-auth admission constraint contract drift"
    );
    anyhow::ensure!(
        psql_query("SELECT to_regclass('chat.service_auth_admissions_expiry_idx')::text")?.trim()
            == "chat.service_auth_admissions_expiry_idx",
        "service-auth admission expiry index is unavailable"
    );
    let ledger_row = psql_query(&format!(
        "SELECT description||E'\\t'||success::text||E'\\t'||encode(checksum,'hex') \
         FROM public._sqlx_migrations WHERE version={SERVICE_AUTH_MIGRATION_VERSION}"
    ))?;
    if ledger_row.trim().is_empty() {
        psql_exec(&format!(
            "INSERT INTO public._sqlx_migrations(version,description,success,checksum,execution_time) \
             VALUES({SERVICE_AUTH_MIGRATION_VERSION},'{SERVICE_AUTH_MIGRATION_DESCRIPTION}',TRUE,decode('{SERVICE_AUTH_MIGRATION_SHA384}','hex'),0)"
        ))?;
    }
    let ledger_row = psql_query(&format!(
        "SELECT description||E'\\t'||success::text||E'\\t'||encode(checksum,'hex') \
         FROM public._sqlx_migrations WHERE version={SERVICE_AUTH_MIGRATION_VERSION}"
    ))?;
    anyhow::ensure!(
        ledger_row.trim()
            == format!(
                "{SERVICE_AUTH_MIGRATION_DESCRIPTION}\ttrue\t{SERVICE_AUTH_MIGRATION_SHA384}"
            ),
        "service-auth migration ledger row conflicts with reviewed source"
    );
    Ok(())
}

#[derive(Deserialize)]
struct InstalledMigration {
    version: i64,
    description: String,
    success: bool,
    checksum: String,
}

fn install_or_validate_reviewed_baseline() -> Result<()> {
    validate_reviewed_baseline_source()?;
    validate_reviewed_request_sources()?;
    let ledger_exists = psql_query(
        "SELECT CASE WHEN to_regclass('public._sqlx_migrations') IS NULL THEN '0' ELSE '1' END",
    )? == "1\n";
    let installed_versions = if ledger_exists {
        psql_query("SELECT version::text FROM public._sqlx_migrations ORDER BY version")?
            .lines()
            .map(str::parse::<i64>)
            .collect::<std::result::Result<Vec<_>, _>>()
            .context("parse installed migration versions")?
    } else {
        Vec::new()
    };
    if !installed_versions.is_empty() && installed_versions.len() < 14 {
        bail!("encrypted-request database contains a partial reviewed baseline")
    }
    if installed_versions.is_empty() {
        psql_exec(
            "CREATE TABLE IF NOT EXISTS public._sqlx_migrations (version BIGINT PRIMARY KEY, description TEXT NOT NULL, installed_on TIMESTAMPTZ NOT NULL DEFAULT now(), success BOOLEAN NOT NULL, checksum BYTEA NOT NULL, execution_time BIGINT NOT NULL)",
        )?;
        for migration in reviewed_baseline() {
            apply_migration(&migration)?;
        }
    }

    let send_message = reviewed_send_message_prerequisite();
    anyhow::ensure!(
        hex::encode(Sha384::digest(send_message.sql.as_bytes())) == send_message.reviewed_sha384,
        "send-message prerequisite source checksum mismatch"
    );
    if !installed_versions.contains(&send_message.version) {
        apply_migration(&send_message)?;
    }
    let inventory_gc = reviewed_inventory_gc_prerequisite();
    anyhow::ensure!(
        hex::encode(Sha384::digest(inventory_gc.sql.as_bytes())) == inventory_gc.reviewed_sha384,
        "inventory-GC prerequisite source checksum mismatch"
    );
    if !installed_versions.contains(&inventory_gc.version) {
        apply_migration(&inventory_gc)?;
    }
    let inventory_gc_contract = psql_query(
        "SELECT (position('device_inventory_items' in immutable.prosrc)>0 AND position('session_replication_role' in immutable.prosrc)=0)::text||E'\\t'||(count(gc.oid)=2 AND bool_and(position('session_replication_role' in gc.prosrc)=0))::text FROM pg_proc immutable JOIN pg_namespace immutable_ns ON immutable_ns.oid=immutable.pronamespace LEFT JOIN pg_proc gc ON gc.pronamespace=immutable.pronamespace AND gc.proname IN ('gc_expired_inventory_sessions','gc_expired_device_inventory_sessions') WHERE immutable_ns.nspname='chat' AND immutable.proname='enforce_immutable_identity' GROUP BY immutable.prosrc",
    )?;
    anyhow::ensure!(
        inventory_gc_contract.trim() == "true\ttrue",
        "inventory-GC immutable-row allowlist contract is unavailable"
    );
    let legacy_dpop = reviewed_legacy_dpop_prerequisite();
    anyhow::ensure!(
        hex::encode(Sha384::digest(legacy_dpop.sql.as_bytes())) == legacy_dpop.reviewed_sha384,
        "legacy-DPoP prerequisite source checksum mismatch"
    );
    if !installed_versions.contains(&legacy_dpop.version) {
        apply_migration(&legacy_dpop)?;
    }
    let performance_indices = reviewed_performance_indices_prerequisite();
    anyhow::ensure!(
        hex::encode(Sha384::digest(performance_indices.sql.as_bytes()))
            == performance_indices.reviewed_sha384,
        "performance-indices prerequisite source checksum mismatch"
    );
    if !installed_versions.contains(&performance_indices.version) {
        apply_migration(&performance_indices)?;
    }
    let pending_inventory = reviewed_pending_inventory_prerequisite();
    anyhow::ensure!(
        hex::encode(Sha384::digest(pending_inventory.sql.as_bytes()))
            == pending_inventory.reviewed_sha384,
        "pending-inventory prerequisite source checksum mismatch"
    );
    if !installed_versions.contains(&pending_inventory.version) {
        apply_migration(&pending_inventory)?;
    }
    for migration in reviewed_request_migrations() {
        if !installed_versions.contains(&migration.version) {
            apply_migration(&migration)?;
        }
    }
    Ok(())
}

fn apply_migration(migration: &BaselineMigration) -> Result<()> {
    let checksum = hex::encode(Sha384::digest(migration.sql.as_bytes()));
    let escaped_description = migration.description.replace('\'', "''");
    let script = format!(
        "BEGIN; SELECT pg_advisory_xact_lock(20260919); SET LOCAL chat.operation_claim_activation_approved = 'handlers-and-legacy-apis-sealed'; {}\nINSERT INTO public._sqlx_migrations(version,description,success,checksum,execution_time) VALUES({},'{}',TRUE,decode('{}','hex'),0); COMMIT;",
        migration.sql, migration.version, escaped_description, checksum
    );
    psql_exec(&script).with_context(|| format!("apply {}", migration.filename))
}

fn psql_query(sql: &str) -> Result<String> {
    let output = Command::new("psql")
        .args([
            "-X",
            "-v",
            "ON_ERROR_STOP=1",
            "-A",
            "-t",
            "-F",
            "\t",
            "-d",
            request_database_url(),
            "-c",
            sql,
        ])
        .output()
        .context("launch psql for encrypted-request harness")?;
    anyhow::ensure!(
        output.status.success(),
        "psql query failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout).context("psql returned non-UTF8 output")
}

fn psql_exec(sql: &str) -> Result<()> {
    let output = Command::new("psql")
        .args([
            "-X",
            "-v",
            "ON_ERROR_STOP=1",
            "-q",
            "-d",
            request_database_url(),
            "-c",
            sql,
        ])
        .output()
        .context("launch psql mutation for encrypted-request harness")?;
    anyhow::ensure!(
        output.status.success(),
        "psql mutation failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    Ok(())
}

#[derive(Clone, Debug)]
pub struct HarnessPrerequisites {
    pub server_binary: PathBuf,
    pub auth_fixture: PathBuf,
}

impl HarnessPrerequisites {
    pub fn from_env() -> Result<Self> {
        let server_binary = required_file(REQUEST_SERVER_BINARY_ENV)?;
        let auth_fixture = required_file(REQUEST_AUTH_FIXTURE_ENV)?;
        let metadata = std::fs::metadata(&server_binary)
            .with_context(|| format!("stat server binary {}", server_binary.display()))?;
        anyhow::ensure!(
            metadata.is_file() && metadata.len() > 0,
            "server binary is empty"
        );
        anyhow::ensure!(
            server_binary.file_name().and_then(|name| name.to_str()) == Some("catbird-server"),
            "{REQUEST_SERVER_BINARY_ENV} must name the shipping catbird-server executable"
        );
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            anyhow::ensure!(
                metadata.permissions().mode() & 0o111 != 0,
                "server binary is not executable"
            );
        }
        let fixture_bytes = std::fs::read(&auth_fixture)
            .with_context(|| format!("read auth fixture {}", auth_fixture.display()))?;
        serde_json::from_slice::<Value>(&fixture_bytes).context("auth fixture is not JSON")?;
        Ok(Self {
            server_binary,
            auth_fixture,
        })
    }
}

fn required_file(variable: &str) -> Result<PathBuf> {
    let path = std::env::var_os(variable).context(format!("{variable} is required"))?;
    let path = PathBuf::from(path);
    anyhow::ensure!(path.is_absolute(), "{variable} must be an absolute path");
    anyhow::ensure!(
        path.is_file(),
        "{variable} does not name a file: {}",
        path.display()
    );
    Ok(path)
}

#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct RequestCapabilities {
    pub can_preview: bool,
    pub can_accept: bool,
    pub can_close: bool,
    pub can_send: bool,
    pub can_emit_receipts: bool,
    pub can_administer: bool,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum RequestConsent {
    IncomingPending,
    OutgoingPending,
    Accepted,
    Closed,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct RequestPreview {
    pub text: String,
    pub consent: RequestConsent,
    pub capabilities: RequestCapabilities,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SentRequest {
    pub conversation_id: String,
    pub message_id: String,
    pub request_id: String,
}

#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct ObservedEffects {
    pub typing: usize,
    pub receipts: usize,
    pub application_sends: usize,
    pub notifications_with_plaintext: usize,
}

impl ObservedEffects {
    pub fn consent_sensitive_count(&self) -> usize {
        self.typing + self.receipts + self.application_sends + self.notifications_with_plaintext
    }
}

#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct ServerSnapshot {
    pub request_rows: usize,
    pub message_rows: usize,
    pub welcome_rows: usize,
    pub plaintext_matches: usize,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PushAuthSnapshot {
    pub device_auth_generation: i64,
    pub key_enrollment_auth_generation: i64,
    pub registration_id: Uuid,
    pub token_generation: i64,
    pub binding_digest_hex: String,
    pub service_jti_rows: usize,
    pub chat_admission_rows: usize,
}

pub struct FixtureProcess {
    child: Child,
}

impl Drop for FixtureProcess {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

pub struct HttpsDidFixture {
    pub port: u16,
    pub ca_pem: PathBuf,
    pub root: PathBuf,
    pub hosts: Vec<String>,
    _process: FixtureProcess,
}

impl HttpsDidFixture {
    pub fn reserve_port() -> Result<u16> {
        Ok(std::net::TcpListener::bind("127.0.0.1:0")
            .context("reserve HTTPS DID fixture port")?
            .local_addr()?
            .port())
    }

    pub fn start(port: u16, documents: &[(String, Value)]) -> Result<Self> {
        let root = std::env::temp_dir().join(format!(
            "catbird-request-did-{}-{}",
            std::process::id(),
            Uuid::new_v4().simple()
        ));
        std::fs::create_dir_all(&root)?;
        let ca_key = root.join("ca-key.pem");
        let ca_pem = root.join("ca.pem");
        let server_key = root.join("server-key.pem");
        let server_csr = root.join("server.csr");
        let server_pem = root.join("server.pem");
        let extension = root.join("server.ext");
        let mut hosts = documents
            .iter()
            .map(|(did, _)| {
                did.strip_prefix("did:web:")
                    .context("fixture identity is not did:web")
                    .map(str::to_owned)
            })
            .collect::<Result<Vec<_>>>()?;
        anyhow::ensure!(
            hosts.len() == documents.len() && hosts.iter().all(|host| !host.contains(':')),
            "fixture identities must be bare did:web hosts"
        );
        hosts.push(RELATIONSHIP_APPVIEW_HOST.to_owned());
        hosts.sort();
        hosts.dedup();
        let subject_alt_names = hosts
            .iter()
            .map(|host| format!("DNS:{host}"))
            .collect::<Vec<_>>()
            .join(",");
        std::fs::write(
            &extension,
            format!("subjectAltName={subject_alt_names}\nextendedKeyUsage=serverAuth\nbasicConstraints=CA:FALSE\n"),
        )?;
        run_checked(
            Command::new("openssl")
                .args([
                    "req",
                    "-x509",
                    "-newkey",
                    "rsa:2048",
                    "-nodes",
                    "-days",
                    // Covers faketime runs that advance every clock past the
                    // seven-day request import horizon.
                    "90",
                    "-subj",
                    "/CN=Catbird Request Fixture CA",
                    "-addext",
                    "basicConstraints=critical,CA:TRUE",
                    "-addext",
                    "keyUsage=critical,keyCertSign,cRLSign",
                    "-keyout",
                ])
                .arg(&ca_key)
                .arg("-out")
                .arg(&ca_pem),
            "generate HTTPS fixture CA",
        )?;
        run_checked(
            Command::new("openssl")
                .args([
                    "req",
                    "-newkey",
                    "rsa:2048",
                    "-nodes",
                    "-subj",
                    "/CN=request-fixture.catbird.blue",
                    "-keyout",
                ])
                .arg(&server_key)
                .arg("-out")
                .arg(&server_csr),
            "generate HTTPS fixture CSR",
        )?;
        run_checked(
            Command::new("openssl")
                .args([
                    "x509",
                    "-req",
                    "-days",
                    // Covers faketime runs that advance every clock past the
                    // seven-day request import horizon.
                    "90",
                    "-sha256",
                    "-CAcreateserial",
                    "-in",
                ])
                .arg(&server_csr)
                .arg("-CA")
                .arg(&ca_pem)
                .arg("-CAkey")
                .arg(&ca_key)
                .arg("-extfile")
                .arg(&extension)
                .arg("-out")
                .arg(&server_pem),
            "sign HTTPS fixture certificate",
        )?;
        let mut full_chain = std::fs::read(&server_pem)?;
        full_chain.push(b'\n');
        full_chain.extend_from_slice(&std::fs::read(&ca_pem)?);
        std::fs::write(&server_pem, full_chain)?;
        for (did, document) in documents {
            let host = did
                .strip_prefix("did:web:")
                .context("fixture identity is not did:web")?;
            anyhow::ensure!(
                !host.contains(':'),
                "fixture identity must be a bare did:web"
            );
            let directory = root.join(host).join(".well-known");
            std::fs::create_dir_all(&directory)?;
            std::fs::write(directory.join("did.json"), serde_json::to_vec(document)?)?;
        }
        let script = Path::new(env!("CARGO_MANIFEST_DIR")).join("support/https_did_fixture.py");
        let mut child = Command::new("python3")
            .arg(script)
            .arg(&root)
            .arg(&server_pem)
            .arg(&server_key)
            .arg(port.to_string())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()
            .context("start HTTPS DID fixture")?;
        let ready = read_child_line(&mut child, "HTTPS DID fixture")?;
        let ready: Value = serde_json::from_str(&ready)?;
        anyhow::ensure!(ready["port"] == port, "HTTPS DID fixture port drift");
        Ok(Self {
            port,
            ca_pem,
            root,
            hosts,
            _process: FixtureProcess { child },
        })
    }
}

fn run_checked(command: &mut Command, label: &str) -> Result<()> {
    let output = command.output().with_context(|| label.to_owned())?;
    anyhow::ensure!(
        output.status.success(),
        "{label}: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    Ok(())
}

fn read_child_line(child: &mut Child, label: &str) -> Result<String> {
    let stdout = child.stdout.take().context(format!("{label} stdout"))?;
    let mut line = String::new();
    BufReader::new(stdout)
        .read_line(&mut line)
        .with_context(|| format!("read {label} readiness"))?;
    anyhow::ensure!(!line.trim().is_empty(), "{label} exited before readiness");
    Ok(line)
}

#[derive(Clone)]
pub struct ServiceIdentity {
    pub did: String,
    pub device_id: Uuid,
    jwt_key: SigningKey,
    jwt_jwk: Value,
}

impl ServiceIdentity {
    pub fn new(did: String) -> Self {
        let jwt_key = SigningKey::random(&mut rand::thread_rng());
        let point = jwt_key.verifying_key().to_encoded_point(false);
        let jwt_jwk = json!({
            "kty":"EC", "crv":"P-256",
            "x":URL_SAFE_NO_PAD.encode(point.x().expect("P256 x")),
            "y":URL_SAFE_NO_PAD.encode(point.y().expect("P256 y"))
        });
        Self {
            did,
            device_id: Uuid::new_v4(),
            jwt_key,
            jwt_jwk,
        }
    }

    pub fn did_document(&self) -> Value {
        let pds_host = self.did.strip_prefix("did:web:").expect("fixture did:web");
        json!({
            "id":self.did,
            "verificationMethod":[{
                "id":format!("{}#atproto", self.did),
                "type":"JsonWebKey2020",
                "controller":self.did,
                "publicKeyJwk":self.jwt_jwk
            }],
            "service":[{
                "id":"#atproto_pds",
                "type":"AtprotoPersonalDataServer",
                "serviceEndpoint":format!("https://{pds_host}")
            }]
        })
    }

    fn jwt_with_jti(&self, nsid: &str, valid_signature: bool, jti: Uuid) -> String {
        let now = monotonic_utc_now().timestamp();
        let header = URL_SAFE_NO_PAD.encode(
            serde_json::to_vec(
                &json!({"alg":"ES256","typ":"JWT","kid":format!("{}#atproto",self.did)}),
            )
            .unwrap(),
        );
        let claims = URL_SAFE_NO_PAD.encode(
            serde_json::to_vec(&json!({"iss":self.did,"aud":"did:web:chat.catbird.blue#atproto_mls","lxm":nsid,"iat":now,"exp":now+60,"jti":jti.to_string()})).unwrap(),
        );
        let input = format!("{header}.{claims}");
        let signature: Signature = if valid_signature {
            self.jwt_key.sign(input.as_bytes())
        } else {
            SigningKey::from_bytes((&[99_u8; 32]).into())
                .expect("negative key")
                .sign(input.as_bytes())
        };
        format!("{input}.{}", URL_SAFE_NO_PAD.encode(signature.to_bytes()))
    }

    fn jwt(&self, nsid: &str, valid_signature: bool) -> String {
        self.jwt_with_jti(nsid, valid_signature, Uuid::new_v4())
    }

    /// Mint a short-lived exact-NSID fixture token with a caller-selected JTI.
    /// The signing key remains process-local; this exists only so the shipping
    /// router replay store can be exercised with the exact same bearer twice.
    pub fn scoped_jwt_with_jti(&self, nsid: &str, jti: Uuid) -> String {
        self.jwt_with_jti(nsid, true, jti)
    }

    pub async fn post(
        &self,
        client: &reqwest::Client,
        base_url: &str,
        nsid: &str,
        body: &Value,
        valid_signature: bool,
    ) -> Result<(StatusCode, Vec<u8>)> {
        let response = client
            .post(format!("{base_url}/xrpc/{nsid}"))
            .bearer_auth(self.jwt(nsid, valid_signature))
            .json(body)
            .send()
            .await
            .context("shipping router request")?;
        let status = response.status();
        let bytes = response.bytes().await?.to_vec();
        Ok((status, bytes))
    }

    pub async fn get(
        &self,
        client: &reqwest::Client,
        base_url: &str,
        nsid: &str,
        parameters: &[(String, String)],
    ) -> Result<(StatusCode, Vec<u8>)> {
        anyhow::ensure!(
            !parameters.iter().any(|(key, _)| key == "actorDeviceId"),
            "actor is supplied by fixture identity"
        );
        let mut query = vec![("actorDeviceId".to_owned(), self.device_id.to_string())];
        query.extend_from_slice(parameters);
        let response = client
            .get(format!("{base_url}/xrpc/{nsid}"))
            .bearer_auth(self.jwt(nsid, true))
            .query(&query)
            .send()
            .await
            .context("shipping authenticated read")?;
        let status = response.status();
        Ok((status, response.bytes().await?.to_vec()))
    }

    /// Forward one exact client-produced XRPC body/query through the normal
    /// scoped service-auth verifier. The synthetic identity and signing key
    /// stay process-local; this helper neither injects actor coordinates nor
    /// parses and reserializes the client's wire bytes.
    pub async fn forward_exact_service_request(
        &self,
        client: &reqwest::Client,
        base_url: &str,
        method: reqwest::Method,
        nsid: &str,
        encoded_query: Option<&str>,
        body: Option<&[u8]>,
    ) -> Result<(StatusCode, Vec<u8>)> {
        let suffix = nsid
            .strip_prefix("blue.catbird.chat.")
            .context("local fixture only forwards blue.catbird.chat endpoints")?;
        anyhow::ensure!(
            !suffix.is_empty()
                && suffix
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_'),
            "invalid local fixture endpoint NSID"
        );
        anyhow::ensure!(
            encoded_query.is_none_or(|query| !query.starts_with('?') && !query.contains('#')),
            "encoded query must omit '?' and fragments"
        );
        match method {
            reqwest::Method::GET => anyhow::ensure!(body.is_none(), "GET body is forbidden"),
            reqwest::Method::POST => {
                anyhow::ensure!(body.is_some(), "POST body is required")
            }
            _ => anyhow::bail!("local fixture permits only GET and POST"),
        }
        let mut url = format!("{base_url}/xrpc/{nsid}");
        if let Some(query) = encoded_query.filter(|query| !query.is_empty()) {
            url.push('?');
            url.push_str(query);
        }
        let mut request = client
            .request(method, url)
            .bearer_auth(self.jwt(nsid, true));
        if let Some(body) = body {
            request = request
                .header(reqwest::header::CONTENT_TYPE, "application/json")
                .body(body.to_vec());
        }
        let response = request
            .send()
            .await
            .context("local fixture exact service forwarding")?;
        let status = response.status();
        Ok((status, response.bytes().await?.to_vec()))
    }

    pub async fn get_device_key(
        &self,
        client: &reqwest::Client,
        base_url: &str,
        owner_did: &str,
        device_id: Uuid,
        key_id: &str,
    ) -> Result<(StatusCode, Vec<u8>)> {
        const NSID: &str = "blue.catbird.chat.getDeviceKey";
        let response = client
            .get(format!("{base_url}/xrpc/{NSID}"))
            .bearer_auth(self.jwt(NSID, true))
            .query(&[
                ("actorDeviceId", self.device_id.to_string()),
                ("ownerDid", owner_did.to_owned()),
                ("deviceId", device_id.to_string()),
                ("keyId", key_id.to_owned()),
            ])
            .send()
            .await
            .context("shipping router device-key request")?;
        let status = response.status();
        let bytes = response.bytes().await?.to_vec();
        Ok((status, bytes))
    }
}

pub fn seed_service_device(identity: &ServiceIdentity, mls_public_key: &[u8]) -> Result<()> {
    let jkt = jwk_thumbprint(&identity.jwt_jwk)?;
    let key_id = URL_SAFE_NO_PAD.encode(Sha256::digest(mls_public_key));
    let public_hex = hex::encode(mls_public_key);
    psql_exec(&format!(
        "BEGIN; \
         INSERT INTO chat.principals(user_did,created_at) VALUES('{did}',clock_timestamp()) ON CONFLICT DO NOTHING; \
         INSERT INTO chat.devices(user_did,device_id,device_name,status,dpop_jkt,auth_generation,capabilities,created_at,updated_at) \
         VALUES('{did}','{device}','c01-fixture','active','{jkt}',1,chat.protocol_capabilities(),clock_timestamp(),clock_timestamp()) \
         ON CONFLICT(user_did,device_id) DO NOTHING; \
         INSERT INTO chat.device_keys(user_did,device_id,key_id,signing_public_key,enrollment_auth_generation,created_at) \
         VALUES('{did}','{device}','{key_id}',decode('{public_hex}','hex'),1,clock_timestamp()) \
         ON CONFLICT(user_did,device_id,key_id) DO NOTHING; COMMIT;",
        did = identity.did,
        device = identity.device_id,
    ))
}

fn jwk_thumbprint(jwk: &Value) -> Result<String> {
    let canonical = format!(
        "{{\"crv\":\"P-256\",\"kty\":\"EC\",\"x\":\"{}\",\"y\":\"{}\"}}",
        jwk["x"].as_str().context("JWK x")?,
        jwk["y"].as_str().context("JWK y")?
    );
    Ok(URL_SAFE_NO_PAD.encode(Sha256::digest(canonical.as_bytes())))
}

pub fn signed_mls_request(
    engine: &MlsEngine,
    identity: &str,
    kind: DirectRequestKind,
    body: Value,
) -> Result<Value> {
    let transcript = protocol::direct_request_signing_bytes(kind, &serde_json::to_vec(&body)?)?;
    let signature = engine.sign_identity(identity, transcript)?;
    let wrapper = json!({"body":body,"signature":STANDARD.encode(signature)});
    let public = engine.identity_public_key(identity)?;
    protocol::verify_signed_request(kind, &serde_json::to_vec(&wrapper)?, &public)?;
    Ok(wrapper)
}

static LAST_OBSERVED_UTC_NOW: std::sync::atomic::AtomicI64 = std::sync::atomic::AtomicI64::new(0);

pub fn monotonic_utc_now() -> chrono::DateTime<chrono::Utc> {
    for _ in 0..10 {
        let now = chrono::Utc::now();
        let ts = now.timestamp();
        let last = LAST_OBSERVED_UTC_NOW.load(std::sync::atomic::Ordering::Relaxed);
        if last == 0 || ts + 5 >= last {
            LAST_OBSERVED_UTC_NOW.fetch_max(ts, std::sync::atomic::Ordering::Relaxed);
            return now;
        }
        std::thread::yield_now();
    }
    chrono::Utc::now()
}

pub fn canonical_now() -> String {
    monotonic_utc_now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true)
}

pub fn canonical_future(days: i64) -> String {
    (monotonic_utc_now() + chrono::Duration::days(days))
        .to_rfc3339_opts(chrono::SecondsFormat::Millis, true)
}

pub fn request_database_snapshot(request_id: Uuid) -> Result<ServerSnapshot> {
    let row = psql_query(&format!(
        "SELECT \
          (SELECT count(*) FROM chat.direct_request_attempts WHERE request_id='{request_id}'), \
          (SELECT count(*) FROM chat.entries WHERE transition_id='{request_id}'), \
          (SELECT count(*) FROM chat.direct_request_device_deliveries WHERE request_id='{request_id}'), \
          (SELECT count(*) FROM chat.entries WHERE transition_id='{request_id}' AND position(convert_to('Real encrypted first contact','UTF8') in accepted_payload_bytes)>0)"
    ))?;
    let fields = row.trim().split('\t').collect::<Vec<_>>();
    anyhow::ensure!(fields.len() == 4, "unexpected request snapshot");
    Ok(ServerSnapshot {
        request_rows: fields[0].parse()?,
        message_rows: fields[1].parse()?,
        welcome_rows: fields[2].parse()?,
        plaintext_matches: fields[3].parse()?,
    })
}

pub fn push_auth_snapshot(identity: &ServiceIdentity, provider: &str) -> Result<PushAuthSnapshot> {
    anyhow::ensure!(
        provider
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte == b'-'),
        "push provider is not canonical"
    );
    let row = psql_query(&format!(
        "SELECT d.auth_generation,k.enrollment_auth_generation,b.registration_id,b.token_generation,encode(b.binding_digest,'hex'), \
          (SELECT count(*) FROM auth_jti_nonce WHERE issuer_did='{did}'), \
          (SELECT count(*) FROM chat.service_auth_admissions WHERE issuer_did='{did}') \
         FROM chat.devices d \
         JOIN chat.device_keys k USING(user_did,device_id) \
         JOIN chat.request_push_bindings b USING(user_did,device_id) \
         WHERE d.user_did='{did}' AND d.device_id='{device}' AND b.provider='{provider}'",
        did = identity.did,
        device = identity.device_id,
    ))?;
    let fields = row.trim().split('\t').collect::<Vec<_>>();
    anyhow::ensure!(fields.len() == 7, "unexpected push auth snapshot");
    Ok(PushAuthSnapshot {
        device_auth_generation: fields[0].parse()?,
        key_enrollment_auth_generation: fields[1].parse()?,
        registration_id: Uuid::parse_str(fields[2])?,
        token_generation: fields[3].parse()?,
        binding_digest_hex: fields[4].to_owned(),
        service_jti_rows: fields[5].parse()?,
        chat_admission_rows: fields[6].parse()?,
    })
}

/// Process-local test configuration; deliberately has no Debug implementation.
pub struct PushFixtureConfig {
    pub listen_port: u16,
    pub event_url: String,
    pub eligibility_bearer: String,
    pub event_id: Uuid,
    pub trigger_path: PathBuf,
    pub result_path: PathBuf,
}

pub fn request_push_event_id(request_id: Uuid) -> Result<Uuid> {
    let id = psql_query(&format!(
        "SELECT event_id FROM chat.direct_request_push_events WHERE request_id='{request_id}'"
    ))?;
    Uuid::parse_str(id.trim()).context("exact request push event identity")
}

pub struct ShippingServerFixture {
    pub base_url: String,
    pub receipt_document: Vec<u8>,
    pub receipt_public_key: Vec<u8>,
    _process: FixtureProcess,
}

impl ShippingServerFixture {
    pub fn start(https: &HttpsDidFixture) -> Result<Self> {
        Self::start_configured(https, None, None)
    }
    pub fn start_with_client_runtime(
        https: &HttpsDidFixture,
        subscription_endpoint: &str,
    ) -> Result<Self> {
        let endpoint = reqwest::Url::parse(subscription_endpoint)
            .context("client runtime subscription endpoint is not a URL")?;
        anyhow::ensure!(
            endpoint.scheme() == "wss"
                && endpoint.host_str() == Some("chat.catbird.blue")
                && endpoint.port().is_none()
                && endpoint.username().is_empty()
                && endpoint.password().is_none()
                && endpoint.query().is_none()
                && endpoint.fragment().is_none()
                && endpoint.path() == "/xrpc/blue.catbird.chat.subscribeEvents",
            "client runtime subscription endpoint must be canonical chat.catbird.blue wss subscribeEvents URL"
        );
        Self::start_configured(https, None, Some(subscription_endpoint))
    }
    pub fn start_with_push(https: &HttpsDidFixture, push: &PushFixtureConfig) -> Result<Self> {
        anyhow::ensure!(
            push.listen_port != 0
                && push.trigger_path.is_absolute()
                && push.result_path.is_absolute(),
            "push listen port must be nonzero and trigger/result paths absolute"
        );
        Self::start_configured(https, Some(push), None)
    }
    fn start_configured(
        https: &HttpsDidFixture,
        push: Option<&PushFixtureConfig>,
        subscription_endpoint: Option<&str>,
    ) -> Result<Self> {
        let binary = required_file(REQUEST_SERVER_FIXTURE_BINARY_ENV)?;
        anyhow::ensure!(
            binary.file_name().and_then(|name| name.to_str())
                == Some("encrypted_request_server_fixture"),
            "{REQUEST_SERVER_FIXTURE_BINARY_ENV} must name encrypted_request_server_fixture"
        );
        let receipt = SigningKey::from_bytes((&[41_u8; 32]).into())?;
        let service = SigningKey::from_bytes((&[42_u8; 32]).into())?;
        let receipt_point = receipt.verifying_key().to_encoded_point(true);
        let receipt_key_id = protocol::direct_request_receipt_key_id(receipt_point.as_bytes())?;
        let retained_keys: Value = serde_json::from_str(&psql_query(
            "SELECT coalesce(json_agg(json_build_object('keyId',key_id,'publicKey',encode(public_key,'base64')) ORDER BY key_id),'[]'::json)::text FROM chat.direct_request_receipt_keys",
        )?)?;
        let mut methods = retained_keys
            .as_array()
            .context("request receipt key registry projection")?
            .iter()
            .map(|retained| -> Result<Value> {
                let key = STANDARD.decode(
                    retained["publicKey"]
                        .as_str()
                        .context("retained receipt public key")?,
                )?;
                anyhow::ensure!(
                    protocol::direct_request_receipt_key_id(&key)? == retained["keyId"],
                    "retained receipt key ID mismatch"
                );
                let mut multikey = vec![0x80, 0x24];
                multikey.extend_from_slice(&key);
                Ok(json!({
                    "id":retained["keyId"],
                    "controller":"did:web:chat.catbird.blue",
                    "type":"Multikey",
                    "publicKeyMultibase":multibase::encode(multibase::Base::Base58Btc,multikey)
                }))
            })
            .collect::<Result<Vec<_>>>()?;
        if !methods.iter().any(|method| method["id"] == receipt_key_id) {
            let mut multikey = vec![0x80, 0x24];
            multikey.extend_from_slice(receipt_point.as_bytes());
            methods.push(json!({
                "id":receipt_key_id,
                "controller":"did:web:chat.catbird.blue",
                "type":"Multikey",
                "publicKeyMultibase":multibase::encode(multibase::Base::Base58Btc,multikey)
            }));
        }
        let receipt_document = serde_json::to_vec(&json!({
            "id":"did:web:chat.catbird.blue",
            "verificationMethod":methods
        }))?;
        let cursor_key_id = URL_SAFE_NO_PAD.encode([0xC1_u8; 32]);
        psql_exec(&format!(
            "BEGIN; \
             INSERT INTO chat.protocol_instances(singleton,protocol_version,protocol_instance_id,cursor_key_id) \
             VALUES(TRUE,'1','00000000-0000-4000-8000-000000000001','{cursor_key_id}') \
             ON CONFLICT(singleton) DO NOTHING; \
             INSERT INTO chat.event_retention(protocol_instance_id,retained_floor,updated_at) \
             SELECT protocol_instance_id,0,clock_timestamp() FROM chat.protocol_instances WHERE singleton=TRUE \
             ON CONFLICT(protocol_instance_id) DO NOTHING; COMMIT;",
        ))?;
        anyhow::ensure!(
            psql_query("SELECT cursor_key_id FROM chat.protocol_instances WHERE singleton=TRUE")?
                .trim()
                == cursor_key_id,
            "guarded database cursor fence differs from fixture key"
        );
        let mut command = Command::new(binary);
        command
            .env("TEST_DATABASE_URL", request_database_url())
            .env("REQUEST_FIXTURE_DID_HOSTS", https.hosts.join(","))
            .env("REQUEST_FIXTURE_DID_PORT", https.port.to_string())
            .env("REQUEST_FIXTURE_DID_CA_PEM", &https.ca_pem)
            .env("DID_RESOLUTION_HOST_ALLOWLIST", https.hosts.join(","))
            .env("CHAT_CUTOVER_ENABLED", "1")
            .env("CHAT_DIRECT_REQUESTS_ENABLED", "1")
            .env("CHAT_CURSOR_KEY_ID", &cursor_key_id)
            .env(
                "CHAT_CURSOR_SEALING_SECRET",
                URL_SAFE_NO_PAD.encode([0xA5_u8; 32]),
            )
            .env(
                "CHAT_SUBSCRIPTION_ENDPOINT",
                subscription_endpoint
                    .unwrap_or("wss://chat.example.test/xrpc/blue.catbird.chat.subscribeEvents"),
            )
            .env(
                "CHAT_REQUEST_RECEIPT_SIGNING_KEY_PEM",
                receipt.to_pkcs8_pem(LineEnding::LF)?.as_str(),
            )
            .env(
                "SIGNING_KEY_PEM",
                service.to_pkcs8_pem(LineEnding::LF)?.as_str(),
            )
            .env(
                "CHAT_REQUEST_RECEIPT_DID_DOCUMENT_JSON",
                String::from_utf8(receipt_document.clone())?,
            )
            .env(
                "RUST_LOG",
                std::env::var("REQUEST_SERVER_RUST_LOG").unwrap_or_else(|_| "warn".into()),
            )
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit());
        if let Some(push) = push {
            command
                .env(
                    "REQUEST_FIXTURE_LISTEN",
                    format!("127.0.0.1:{}", push.listen_port),
                )
                .env("REQUEST_FIXTURE_PUSH_EVENT_URL", &push.event_url)
                .env(
                    "REQUEST_FIXTURE_PUSH_ELIGIBILITY_BEARER",
                    &push.eligibility_bearer,
                )
                .env("REQUEST_FIXTURE_PUSH_EVENT_ID", push.event_id.to_string())
                .env("REQUEST_FIXTURE_PUSH_TRIGGER", &push.trigger_path)
                .env("REQUEST_FIXTURE_PUSH_RESULT", &push.result_path);
        }
        let mut child = command.spawn().context("start shipping router fixture")?;
        let ready = read_child_line(&mut child, "shipping router fixture")?;
        let ready: Value = serde_json::from_str(&ready)?;
        let base_url = ready["baseUrl"]
            .as_str()
            .context("shipping router readiness lacks baseUrl")?
            .to_owned();
        Ok(Self {
            base_url,
            receipt_document,
            receipt_public_key: receipt_point.as_bytes().to_vec(),
            _process: FixtureProcess { child },
        })
    }
}

struct AccountState {
    devices: Vec<MlsEngine>,
    offline: bool,
    effects: ObservedEffects,
}

/// Real local acceptance rig. The database and MLS contexts are real; request
/// operations stay fail-closed until the corresponding production interfaces
/// are present and can be invoked without a test-only success path.
pub struct RequestRig {
    pub database_authority: DatabaseAuthority,
    pub prerequisites: HarnessPrerequisites,
    accounts: HashMap<String, AccountState>,
    pub fault_transport: DeterministicFaultTransport,
}

impl RequestRig {
    pub async fn local() -> Result<Self> {
        let prerequisites = HarnessPrerequisites::from_env()?;
        let database_authority = connect_guarded_request_database(5).await?;
        Ok(Self {
            database_authority,
            prerequisites,
            accounts: HashMap::new(),
            fault_transport: DeterministicFaultTransport::default(),
        })
    }

    pub async fn enroll(&mut self, account: &str, device_count: usize) -> Result<()> {
        anyhow::ensure!(!account.is_empty(), "account label is empty");
        anyhow::ensure!(device_count > 0, "device_count must be positive");
        anyhow::ensure!(
            !self.accounts.contains_key(account),
            "account already enrolled"
        );
        let mut devices = Vec::with_capacity(device_count);
        for index in 0..device_count {
            let engine = MlsEngine::new(&format!("direct-request-{account}-{index}"))?;
            let (package, hash_ref) = engine.create_key_package(account)?;
            anyhow::ensure!(
                !package.is_empty() && !hash_ref.is_empty(),
                "real key package generation returned empty material"
            );
            devices.push(engine);
        }
        self.accounts.insert(
            account.to_owned(),
            AccountState {
                devices,
                offline: false,
                effects: ObservedEffects::default(),
            },
        );
        Ok(())
    }

    pub async fn start_request(
        &mut self,
        _account: &str,
        _peer: &str,
        _text: &str,
    ) -> Result<SentRequest> {
        bail!("request production preparation/publication handlers are not installed; T02/T03/T04 are required")
    }

    pub async fn set_offline(&mut self, account: &str) -> Result<()> {
        self.accounts
            .get_mut(account)
            .context("unknown account")?
            .offline = true;
        Ok(())
    }

    pub async fn restart(&mut self, _account: &str) -> Result<()> {
        bail!("durable request-journal restart is not installed; T02/T06 are required")
    }

    pub async fn preview(&self, _account: &str, _conversation: &str) -> Result<RequestPreview> {
        bail!("request preview handler is not installed; T04/T05/T06 are required")
    }

    pub async fn accept(&mut self, _account: &str, _conversation: &str) -> Result<()> {
        bail!("versioned request acceptance handler is not installed; T05 is required")
    }

    pub async fn reply(&mut self, _account: &str, _conversation: &str, _text: &str) -> Result<()> {
        bail!("accepted request reply path is not installed; T05/T06 are required")
    }

    pub async fn server_snapshot(&self) -> Result<ServerSnapshot> {
        let request_table =
            psql_query("SELECT coalesce(to_regclass('chat.direct_request_operations')::text,'')")?;
        anyhow::ensure!(
            !request_table.trim().is_empty(),
            "direct-request schema is not installed; T03 is required"
        );
        bail!("T03 must expose the finalized request schema before snapshot queries can be frozen")
    }

    pub async fn effects(&self, account: &str) -> Result<ObservedEffects> {
        Ok(self
            .accounts
            .get(account)
            .context("unknown account")?
            .effects
            .clone())
    }

    pub fn independent_device_count(&self, account: &str) -> Result<usize> {
        Ok(self
            .accounts
            .get(account)
            .context("unknown account")?
            .devices
            .len())
    }
}

pub async fn assert_endpoint_absent(base_url: &str, nsid: &str) -> Result<StatusCode> {
    let response = reqwest::Client::new()
        .post(format!("{}/xrpc/{nsid}", base_url.trim_end_matches('/')))
        .json(&serde_json::json!({}))
        .send()
        .await
        .context("probe production endpoint")?;
    Ok(response.status())
}

pub fn file_sha256(path: &Path) -> Result<String> {
    let bytes = std::fs::read(path).with_context(|| format!("read {}", path.display()))?;
    Ok(hex::encode(sha2::Sha256::digest(bytes)))
}
