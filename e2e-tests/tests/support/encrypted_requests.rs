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
    path::{Path, PathBuf},
    process::Command,
    sync::{Mutex, OnceLock},
};

use anyhow::{bail, Context, Result};
use mls_e2e_tests::mls_engine::MlsEngine;
use reqwest::StatusCode;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha384};

pub const REQUEST_TEST_DATABASE_NAME: &str = "catbird_direct_requests_test_20260919";
pub const REQUEST_TEST_DATABASE_URL: &str =
    "postgresql://127.0.0.1:5432/catbird_direct_requests_test_20260919";
pub const REQUEST_TEST_DATABASE_ENV: &str = "REQUEST_TEST_DATABASE_URL";
pub const REQUEST_SERVER_BINARY_ENV: &str = "REQUEST_SERVER_BINARY";
pub const REQUEST_AUTH_FIXTURE_ENV: &str = "REQUEST_AUTH_FIXTURE";

static DATABASE_SETUP_LOCK: OnceLock<Mutex<()>> = OnceLock::new();

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

pub fn validate_request_test_database_url(value: Option<&str>) -> Result<&'static str> {
    match value {
        Some(REQUEST_TEST_DATABASE_URL) => Ok(REQUEST_TEST_DATABASE_NAME),
        Some(_) => {
            bail!("{REQUEST_TEST_DATABASE_ENV} must exactly equal {REQUEST_TEST_DATABASE_URL}")
        }
        None => bail!("{REQUEST_TEST_DATABASE_ENV} is required"),
    }
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
        database == REQUEST_TEST_DATABASE_NAME,
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
    for row in ledger.iter().skip(14) {
        anyhow::ensure!(
            row.version >= 20260919000000 && row.version < 20260920000000,
            "non-request additive migration {} is installed in the request database",
            row.version
        );
        anyhow::ensure!(
            row.success,
            "request additive migration {} failed",
            row.version
        );
    }
    Ok(DatabaseAuthority {
        database,
        user,
        owner,
        server_address,
        baseline_migrations: 14,
        additive_migrations: ledger.len() - 14,
    })
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

    let migration_dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("../server/migrations");
    let mut additive_paths = std::fs::read_dir(&migration_dir)
        .with_context(|| format!("read migration directory {}", migration_dir.display()))?
        .filter_map(|entry| entry.ok().map(|entry| entry.path()))
        .filter(|path| {
            path.file_name()
                .and_then(|name| name.to_str())
                .is_some_and(|name| name.starts_with("20260919") && name.ends_with(".sql"))
        })
        .collect::<Vec<_>>();
    additive_paths.sort();
    anyhow::ensure!(
        !additive_paths.is_empty(),
        "no encrypted-request additive migration is present"
    );
    for path in additive_paths {
        let filename = path
            .file_name()
            .and_then(|name| name.to_str())
            .context("non-UTF8 migration filename")?;
        let (raw_version, description) = filename
            .trim_end_matches(".sql")
            .split_once('_')
            .context("invalid additive migration filename")?;
        let version = raw_version
            .parse::<i64>()
            .context("invalid additive migration version")?;
        anyhow::ensure!(
            (20260919000000..20260920000000).contains(&version),
            "additive migration outside reserved day range"
        );
        if !installed_versions.contains(&version) {
            let sql = std::fs::read_to_string(&path)
                .with_context(|| format!("read {}", path.display()))?;
            let migration = BaselineMigration {
                filename: Box::leak(filename.to_owned().into_boxed_str()),
                version,
                description: Box::leak(description.replace('_', " ").into_boxed_str()),
                reviewed_sha384: "",
                sql: Box::leak(sql.into_boxed_str()),
            };
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
            REQUEST_TEST_DATABASE_URL,
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
            REQUEST_TEST_DATABASE_URL,
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
}

impl RequestRig {
    pub async fn local() -> Result<Self> {
        let prerequisites = HarnessPrerequisites::from_env()?;
        let database_authority = connect_guarded_request_database(5).await?;
        Ok(Self {
            database_authority,
            prerequisites,
            accounts: HashMap::new(),
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
