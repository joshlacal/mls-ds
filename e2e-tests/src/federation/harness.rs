//! Two-node federation harness.
//!
//! Spins up a 2-DS federated cluster via docker-compose for integration
//! testing. See `mls-ds/e2e-tests/docker-compose.federation.yml` for the
//! container topology.

use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use chrono::Utc;
use p256::ecdsa::{signature::Signer, signature::Verifier, Signature as P256Signature, SigningKey, VerifyingKey};
use p256::pkcs8::DecodePrivateKey;
use serde_json::{json, Value};
use tokio_postgres::NoTls;
use uuid::Uuid;
use crate::TestClient;

pub const DS1_DEFAULT_SERVICE_DID: &str = "did:web:ds1.catbird.blue";
pub const DS2_DEFAULT_SERVICE_DID: &str = "did:web:ds2.catbird.blue";

/// Configuration for booting the cluster.
#[derive(Debug, Clone)]
pub struct HarnessConfig {
    pub project_name: String,
    pub boot_timeout: Duration,
    pub compose_file: PathBuf,
}

impl Default for HarnessConfig {
    fn default() -> Self {
        let project_name = std::env::var("FED_HARNESS_PROJECT_NAME")
            .unwrap_or_else(|_| format!("mls-fed-{}", Uuid::new_v4().simple()));
        let compose_file = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("docker-compose.federation.yml");
        Self {
            project_name,
            boot_timeout: Duration::from_secs(90),
            compose_file,
        }
    }
}

/// Result of booting a two-DS federated cluster.
pub struct TwoNodeCluster {
    pub ds1_url: String,
    pub ds2_url: String,
    pub ds1_db_url: String,
    pub ds2_db_url: String,
    pub ds1_service_did: String,
    pub ds2_service_did: String,
    pub ds1_signing_key: SigningKey,
    pub ds2_signing_key: SigningKey,
    pub ds1_verifying_key: VerifyingKey,
    pub ds2_verifying_key: VerifyingKey,
    pub compose_project: String,
    pub compose_file: PathBuf,
    pub http_client: reqwest::Client,
    cleaned_up: bool,
}

impl std::fmt::Debug for TwoNodeCluster {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TwoNodeCluster")
            .field("ds1_url", &self.ds1_url)
            .field("ds2_url", &self.ds2_url)
            .field("ds1_db_url", &self.ds1_db_url)
            .field("ds2_db_url", &self.ds2_db_url)
            .field("ds1_service_did", &self.ds1_service_did)
            .field("ds2_service_did", &self.ds2_service_did)
            .field("compose_project", &self.compose_project)
            .finish()
    }
}

impl Drop for TwoNodeCluster {
    fn drop(&mut self) {
        if !self.cleaned_up {
            self.teardown_sync();
        }
    }
}

impl TwoNodeCluster {
    /// Build a [`TestClient`] targeting DS1.
    pub fn ds1_client(&self) -> TestClient {
        TestClient::new(&self.ds1_url, "test-jwt-secret")
    }

    /// Build a [`TestClient`] targeting DS2.
    pub fn ds2_client(&self) -> TestClient {
        TestClient::new(&self.ds2_url, "test-jwt-secret")
    }

    /// Connect to DS1 PostgreSQL database.
    pub async fn connect_ds1_db(&self) -> Result<tokio_postgres::Client> {
        let (client, connection) = tokio_postgres::connect(&self.ds1_db_url, NoTls)
            .await
            .with_context(|| format!("connect to DS1 DB at {}", self.ds1_db_url))?;
        tokio::spawn(async move {
            if let Err(e) = connection.await {
                tracing::warn!("DS1 Postgres connection error: {e}");
            }
        });
        Ok(client)
    }

    /// Connect to DS2 PostgreSQL database.
    pub async fn connect_ds2_db(&self) -> Result<tokio_postgres::Client> {
        let (client, connection) = tokio_postgres::connect(&self.ds2_db_url, NoTls)
            .await
            .with_context(|| format!("connect to DS2 DB at {}", self.ds2_db_url))?;
        tokio::spawn(async move {
            if let Err(e) = connection.await {
                tracing::warn!("DS2 Postgres connection error: {e}");
            }
        });
        Ok(client)
    }

    /// Mint an ES256 service JWT for DS1 as issuer.
    pub fn mint_ds1_jwt(&self, audience: &str, endpoint_nsid: &str) -> String {
        self.mint_jwt(&self.ds1_service_did, &self.ds1_signing_key, audience, endpoint_nsid, None)
    }

    /// Mint an ES256 service JWT for DS2 as issuer.
    pub fn mint_ds2_jwt(&self, audience: &str, endpoint_nsid: &str) -> String {
        self.mint_jwt(&self.ds2_service_did, &self.ds2_signing_key, audience, endpoint_nsid, None)
    }

    /// Mint an ES256 service JWT with custom issuer, audience, and lxm.
    pub fn mint_jwt(
        &self,
        issuer: &str,
        key: &SigningKey,
        audience: &str,
        endpoint_nsid: &str,
        custom_jti: Option<&str>,
    ) -> String {
        let now = Utc::now().timestamp();
        let jti = custom_jti
            .map(|s| s.to_string())
            .unwrap_or_else(|| Uuid::new_v4().to_string());
        let header = json!({
            "alg": "ES256",
            "typ": "JWT",
            "kid": format!("{issuer}#atproto")
        });
        let claims = json!({
            "iss": issuer,
            "sub": issuer,
            "aud": audience,
            "lxm": endpoint_nsid,
            "iat": now,
            "exp": now + 120,
            "jti": jti
        });

        let h_b64 = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&header).unwrap());
        let c_b64 = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&claims).unwrap());
        let signing_input = format!("{h_b64}.{c_b64}");
        let signature: P256Signature = key.sign(signing_input.as_bytes());
        let sig_bytes = signature.to_bytes();
        let s_b64 = URL_SAFE_NO_PAD.encode(sig_bytes);
        format!("{signing_input}.{s_b64}")
    }

    /// Verify an ES256 signature against DS1 verifying key.
    pub fn verify_ds1_signature(&self, message: &[u8], signature_bytes: &[u8]) -> Result<()> {
        let signature = P256Signature::try_from(signature_bytes)
            .map_err(|e| anyhow::anyhow!("invalid P256 signature bytes: {e}"))?;
        self.ds1_verifying_key
            .verify(message, &signature)
            .map_err(|e| anyhow::anyhow!("DS1 signature verification failed: {e}"))
    }

    /// Verify an ES256 signature against DS2 verifying key.
    pub fn verify_ds2_signature(&self, message: &[u8], signature_bytes: &[u8]) -> Result<()> {
        let signature = P256Signature::try_from(signature_bytes)
            .map_err(|e| anyhow::anyhow!("invalid P256 signature bytes: {e}"))?;
        self.ds2_verifying_key
            .verify(message, &signature)
            .map_err(|e| anyhow::anyhow!("DS2 signature verification failed: {e}"))
    }

    /// Capture diagnostic snapshots (ps, logs, and database tables) on failure.
    pub fn capture_diagnostics(&self) {
        println!("=== FEDERATION TWO-NODE DIAGNOSTICS ({}) ===", self.compose_project);
        let repo_root = self.compose_file.parent().unwrap().parent().unwrap();

        // 1. docker compose ps
        let ps_output = Command::new("docker")
            .args([
                "compose",
                "-p",
                &self.compose_project,
                "-f",
                self.compose_file.to_str().unwrap(),
                "ps",
                "-a",
            ])
            .current_dir(repo_root)
            .output();
        if let Ok(out) = ps_output {
            println!("--- Docker Compose PS ---");
            println!("{}", String::from_utf8_lossy(&out.stdout));
        }

        // 2. docker compose logs
        let logs_output = Command::new("docker")
            .args([
                "compose",
                "-p",
                &self.compose_project,
                "-f",
                self.compose_file.to_str().unwrap(),
                "logs",
                "--tail=100",
                "ds1",
                "ds2",
            ])
            .current_dir(repo_root)
            .output();
        if let Ok(out) = logs_output {
            println!("--- Docker Compose Logs (ds1, ds2) ---");
            println!("{}", String::from_utf8_lossy(&out.stdout));
            println!("{}", String::from_utf8_lossy(&out.stderr));
        }
    }

    /// Synchronous teardown helper used by Drop.
    fn teardown_sync(&mut self) {
        self.cleaned_up = true;
        let repo_root = self.compose_file.parent().unwrap().parent().unwrap();
        let _ = Command::new("docker")
            .args([
                "compose",
                "-p",
                &self.compose_project,
                "-f",
                self.compose_file.to_str().unwrap(),
                "down",
                "--volumes",
                "--remove-orphans",
            ])
            .current_dir(repo_root)
            .output();
    }

    /// Explicit asynchronous shutdown.
    pub async fn shutdown(mut self) {
        self.teardown_sync();
    }
}

/// Verify that Docker is available, or fail loudly.
pub fn ensure_docker_available() -> Result<()> {
    let output = Command::new("docker")
        .arg("info")
        .output()
        .map_err(|e| anyhow::anyhow!("Failed to execute `docker info`: {e}. Please ensure Docker or Colima is installed."))?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        anyhow::bail!(
            "Docker / Colima is unavailable (exit code {:?}): {}. Please start Colima (`colima start`) before running federation tests.",
            output.status.code(),
            stderr.trim()
        );
    }
    Ok(())
}

/// Boot a two-DS federated cluster via docker-compose with default config.
pub async fn boot_two_node_cluster() -> Result<TwoNodeCluster> {
    boot_two_node_cluster_with(HarnessConfig::default()).await
}

/// Boot a two-DS federated cluster via docker-compose with custom config.
pub async fn boot_two_node_cluster_with(config: HarnessConfig) -> Result<TwoNodeCluster> {
    ensure_docker_available()?;

    let repo_root = config
        .compose_file
        .parent()
        .context("compose_file parent")?
        .parent()
        .context("repo root")?;
    let fixtures_dir = config.compose_file.parent().unwrap().join("fixtures");

    let ds1_key_path = fixtures_dir.join("ds1-key.pem");
    let ds2_key_path = fixtures_dir.join("ds2-key.pem");

    let ds1_pem = std::fs::read_to_string(&ds1_key_path)
        .with_context(|| format!("read ds1-key.pem at {:?}", ds1_key_path))?;
    let ds2_pem = std::fs::read_to_string(&ds2_key_path)
        .with_context(|| format!("read ds2-key.pem at {:?}", ds2_key_path))?;

    let ds1_signing_key = SigningKey::from_pkcs8_pem(&ds1_pem)
        .map_err(|e| anyhow::anyhow!("parse ds1-key.pem: {e}"))?;
    let ds2_signing_key = SigningKey::from_pkcs8_pem(&ds2_pem)
        .map_err(|e| anyhow::anyhow!("parse ds2-key.pem: {e}"))?;

    let ds1_verifying_key = *ds1_signing_key.verifying_key();
    let ds2_verifying_key = *ds2_signing_key.verifying_key();

    tracing::info!(
        project = %config.project_name,
        "Booting two-node federation cluster via docker-compose..."
    );

    // 1. Run docker compose up -d
    let up_status = Command::new("docker")
        .args([
            "compose",
            "-p",
            &config.project_name,
            "-f",
            config.compose_file.to_str().unwrap(),
            "up",
            "-d",
        ])
        .current_dir(repo_root)
        .status()
        .context("run docker compose up -d")?;

    if !up_status.success() {
        anyhow::bail!(
            "docker compose up -d failed with exit status: {:?}",
            up_status.code()
        );
    }

    let discover_port = |service: &str, container_port: u16| -> Result<u16> {
        let output = Command::new("docker")
            .args([
                "compose",
                "-p",
                &config.project_name,
                "-f",
                config.compose_file.to_str().unwrap(),
                "port",
                service,
                &container_port.to_string(),
            ])
            .current_dir(repo_root)
            .output()
            .with_context(|| format!("discover port for {service}:{container_port}"))?;
        let stdout = String::from_utf8_lossy(&output.stdout);
        let trimmed = stdout.trim();
        // format: 0.0.0.0:12345 or [::]:12345 or 127.0.0.1:12345
        let host_port_str = trimmed
            .rsplit(':')
            .next()
            .context("parse host port from docker compose port output")?;
        let port: u16 = host_port_str
            .parse()
            .with_context(|| format!("parse port integer from '{host_port_str}' (raw='{trimmed}')"))?;
        Ok(port)
    };

    let ds1_host_port = discover_port("ds1", 3001)?;
    let ds2_host_port = discover_port("ds2", 3001)?;
    let ds1_db_port = discover_port("ds1-postgres", 5432)?;
    let ds2_db_port = discover_port("ds2-postgres", 5432)?;

    let ds1_url = format!("http://127.0.0.1:{ds1_host_port}");
    let ds2_url = format!("http://127.0.0.1:{ds2_host_port}");
    let ds1_db_url = format!("postgres://catbird:catbird@127.0.0.1:{ds1_db_port}/catbird");
    let ds2_db_url = format!("postgres://catbird:catbird@127.0.0.1:{ds2_db_port}/catbird");

    let http_client = reqwest::Client::builder()
        .timeout(Duration::from_secs(10))
        .build()?;

    let cluster = TwoNodeCluster {
        ds1_url: ds1_url.clone(),
        ds2_url: ds2_url.clone(),
        ds1_db_url,
        ds2_db_url,
        ds1_service_did: DS1_DEFAULT_SERVICE_DID.to_string(),
        ds2_service_did: DS2_DEFAULT_SERVICE_DID.to_string(),
        ds1_signing_key,
        ds2_signing_key,
        ds1_verifying_key,
        ds2_verifying_key,
        compose_project: config.project_name.clone(),
        compose_file: config.compose_file.clone(),
        http_client: http_client.clone(),
        cleaned_up: false,
    };

    // 2. Poll readiness for DS1 and DS2
    let start = Instant::now();
    let mut ds1_ready = false;
    let mut ds2_ready = false;

    while start.elapsed() < config.boot_timeout {
        if !ds1_ready {
            let ready_res = http_client.get(format!("{ds1_url}/health/ready")).send().await;
            let health_res = http_client
                .get(format!("{ds1_url}/xrpc/blue.catbird.mlsDS.healthCheck"))
                .send()
                .await;
            if let (Ok(r1), Ok(r2)) = (ready_res, health_res) {
                if r1.status().is_success() && r2.status().is_success() {
                    ds1_ready = true;
                }
            }
        }

        if !ds2_ready {
            let ready_res = http_client.get(format!("{ds2_url}/health/ready")).send().await;
            let health_res = http_client
                .get(format!("{ds2_url}/xrpc/blue.catbird.mlsDS.healthCheck"))
                .send()
                .await;
            if let (Ok(r1), Ok(r2)) = (ready_res, health_res) {
                if r1.status().is_success() && r2.status().is_success() {
                    ds2_ready = true;
                }
            }
        }

        if ds1_ready && ds2_ready {
            tracing::info!(
                elapsed = ?start.elapsed(),
                "Two-node federation cluster is ready and healthy"
            );
            return Ok(cluster);
        }

        tokio::time::sleep(Duration::from_millis(500)).await;
    }

    cluster.capture_diagnostics();
    anyhow::bail!(
        "Timed out waiting for two-node federation cluster readiness after {:?}",
        config.boot_timeout
    );
}
