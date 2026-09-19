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
pub const ALICE_DID_HOST: &str = "alice.request-fixture.catbird.blue";
pub const BOB_DID_HOST: &str = "bob.request-fixture.catbird.blue";
pub const RELATIONSHIP_APPVIEW_HOST: &str = "public.api.bsky.app";
const AUTH_JTI_MIGRATION: &str =
    include_str!("../../../server/migrations/20260214000002_auth_jti_nonce.sql");
const AUTH_JTI_MIGRATION_SHA384: &str =
    "a653190a473ce3535c946769e8e269173fcf22c1cc6196063eb9461e4766bc084a57c61d2b3a4ffee4b5a1b4da06856b";

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
    install_auth_replay_prerequisite()?;
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
        std::fs::write(
            &extension,
            &format!("subjectAltName=DNS:{ALICE_DID_HOST},DNS:{BOB_DID_HOST},DNS:{RELATIONSHIP_APPVIEW_HOST}\nextendedKeyUsage=serverAuth\nbasicConstraints=CA:FALSE\n"),
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
                    "1",
                    "-subj",
                    "/CN=Catbird Request Fixture CA",
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
                    "/CN=alice.request-fixture.catbird.blue",
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
                    "1",
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
    pub jwt_key: SigningKey,
    pub jwt_jwk: Value,
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

    fn jwt(&self, nsid: &str, valid_signature: bool) -> String {
        let now = chrono::Utc::now().timestamp();
        let header = URL_SAFE_NO_PAD.encode(
            serde_json::to_vec(
                &json!({"alg":"ES256","typ":"JWT","kid":format!("{}#atproto",self.did)}),
            )
            .unwrap(),
        );
        let claims = URL_SAFE_NO_PAD.encode(
            serde_json::to_vec(&json!({"iss":self.did,"aud":"did:web:chat.catbird.blue#atproto_mls","lxm":nsid,"iat":now,"exp":now+60,"jti":Uuid::new_v4().to_string()})).unwrap(),
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

pub fn canonical_now() -> String {
    chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true)
}

pub fn canonical_future(days: i64) -> String {
    (chrono::Utc::now() + chrono::Duration::days(days))
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

pub struct ShippingServerFixture {
    pub base_url: String,
    pub receipt_document: Vec<u8>,
    pub receipt_public_key: Vec<u8>,
    _process: FixtureProcess,
}

impl ShippingServerFixture {
    pub fn start(https: &HttpsDidFixture) -> Result<Self> {
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
        let mut child = Command::new(binary)
            .env("TEST_DATABASE_URL", REQUEST_TEST_DATABASE_URL)
            .env(
                "REQUEST_FIXTURE_DID_HOSTS",
                format!("{ALICE_DID_HOST},{BOB_DID_HOST},{RELATIONSHIP_APPVIEW_HOST}"),
            )
            .env("REQUEST_FIXTURE_DID_PORT", https.port.to_string())
            .env("REQUEST_FIXTURE_DID_CA_PEM", &https.ca_pem)
            .env(
                "DID_RESOLUTION_HOST_ALLOWLIST",
                format!("{ALICE_DID_HOST},{BOB_DID_HOST}"),
            )
            .env("CHAT_CUTOVER_ENABLED", "1")
            .env("CHAT_DIRECT_REQUESTS_ENABLED", "1")
            .env("CHAT_CURSOR_KEY_ID", &cursor_key_id)
            .env(
                "CHAT_CURSOR_SEALING_SECRET",
                URL_SAFE_NO_PAD.encode([0xA5_u8; 32]),
            )
            .env(
                "CHAT_SUBSCRIPTION_ENDPOINT",
                "wss://chat.example.test/xrpc/blue.catbird.chat.subscribeEvents",
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
            .env("RUST_LOG", "warn")
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()
            .context("start shipping router fixture")?;
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
