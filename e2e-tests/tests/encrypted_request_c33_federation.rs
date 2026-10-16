//! C33: Two-Authority Canonical Federation Qualification.
//!
//! Mandatory assertions:
//! 1. Single authoritative encrypted introduction across two independent authorities (DS-A and DS-B).
//! 2. Deterministic canonical pair coordinator = min(normalized DS DIDs) for both send directions.
//! 3. Staged S2S reservation of remote recipient key packages/grants before local transaction.
//! 4. Remote Welcome and entry delivery to recipient's home DS without legacy tables.
//! 5. Lost peer/client response replay: identical publication retry returns cached receipt idempotently after peer restart.
//! 6. Remote Welcome import and introduction decryption by recipient on home DS.
//! 7. Acceptance relayed to coordinator, committed at seq 2 with coordinator's signed commit receipt.
//! 8. Bi-directional reply: recipient replies with real MLS encryption, entry synchronized across nodes, both decrypt plaintext.
//! 9. Contended opposite-direction prepares (20 ms stagger after barrier) converge on one direct; losing lease is inactive.
//! 10. Zero legacy fallback: verify no legacy table interaction and one canonical DB graph.
//! 11. Lost-peer and lost-client-response retry preserve single Welcome/package consumption.
//! 12. Recipient getEntries seq=2 acceptance entry hashes to the returned acceptance proof entry.
//! 13. A sender's cancel reaches the pair's coordinator through the sender's home, and only the coordinator signs it.
#![allow(dead_code, unused_imports)]
#[path = "support/encrypted_requests.rs"]
mod encrypted_requests;

use anyhow::Context as _;
use base64::{
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
    Engine as _,
};
use catbird_mls::{
    chat_v2::transcript::direct_request::{self as protocol, DirectRequestKind},
    metadata::GroupMetadataV1,
    orchestrator::{
        canonical_application_aad_bytes,
        direct_request_bootstrap::{
            metadata_coordinate, DirectRequestBootstrap, DirectRequestBootstrapInput,
            DirectRequestIntroductionResult, DirectRequestWelcomeInput,
        },
        MLSMessagePayload,
    },
};
use encrypted_requests::{
    canonical_future, canonical_now, signed_mls_request, DeterministicFaultTransport,
    FaultBoundary, HttpsDidFixture, PairLockBarrier, ServiceIdentity,
};
use mls_e2e_tests::mls_engine::MlsEngine;
use p256::ecdsa::SigningKey;
use p256::pkcs8::EncodePrivateKey;
use reqwest::StatusCode;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::net::TcpListener;
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::sync::Arc;
use uuid::Uuid;

const MAINTENANCE_URL: &str = "postgresql://127.0.0.1:5432/postgres";

struct DedicatedDatabase(String);

impl Drop for DedicatedDatabase {
    fn drop(&mut self) {
        let name = &self.0;
        let _ = psql_maintenance(&format!(
            "SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE datname='{name}' AND pid<>pg_backend_pid()"
        ));
        let _ = psql_maintenance(&format!("DROP DATABASE IF EXISTS {name}"));
    }
}

fn psql_maintenance(sql: &str) -> anyhow::Result<()> {
    let output = Command::new("psql")
        .args([MAINTENANCE_URL, "-X", "-q", "-v", "ON_ERROR_STOP=1", "-c", sql])
        .output()?;
    anyhow::ensure!(
        output.status.success(),
        "psql maintenance failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    Ok(())
}

fn psql_on(db_url: &str, sql: &str) -> anyhow::Result<()> {
    let output = Command::new("psql")
        .args([db_url, "-X", "-q", "-v", "ON_ERROR_STOP=1", "-c", sql])
        .output()?;
    anyhow::ensure!(
        output.status.success(),
        "psql on {db_url} failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    Ok(())
}

fn psql_value(db_url: &str, sql: &str) -> anyhow::Result<String> {
    let output = Command::new("psql")
        .args([db_url, "-X", "-q", "-A", "-t", "-v", "ON_ERROR_STOP=1", "-c", sql])
        .output()?;
    anyhow::ensure!(
        output.status.success(),
        "psql query failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    Ok(String::from_utf8(output.stdout)?.trim().to_owned())
}

fn psql_count(db_url: &str, sql: &str) -> anyhow::Result<i64> {
    Ok(psql_value(db_url, sql)?.parse()?)
}

fn create_database_clone(source: &str, target: &str) -> anyhow::Result<DedicatedDatabase> {
    psql_maintenance(&format!("CREATE DATABASE {target} TEMPLATE {source}"))?;
    Ok(DedicatedDatabase(target.to_string()))
}

fn require_federation_tables(db_url: &str) -> anyhow::Result<()> {
    // The guarded template holds the server's whole migration catalog, which
    // already creates the public federation schema this node relies on.
    for table in [
        "ds_endpoints",
        "outbound_queue",
        "federation_peers",
        "auth_jti_nonce",
        "federation_peer_policy_audit_log",
    ] {
        anyhow::ensure!(
            psql_value(db_url, &format!("SELECT to_regclass('public.{table}') IS NOT NULL"))? == "t",
            "guarded template lacks public.{table}"
        );
    }
    Ok(())
}

fn reserve_loopback_port() -> anyhow::Result<u16> {
    let listener = TcpListener::bind("127.0.0.1:0")?;
    Ok(listener.local_addr()?.port())
}

fn quote(part: &str) -> String {
    part.bytes()
        .map(|b| {
            if b.is_ascii_alphanumeric() || b"_.-~".contains(&b) {
                (b as char).to_string()
            } else {
                format!("%{b:02X}")
            }
        })
        .collect()
}

fn declare_chat_authority(root: &Path, did: &str, delivery_service: &str) -> anyhow::Result<()> {
    let dir = root.join("_policy").join("catbirdDeclaration");
    std::fs::create_dir_all(&dir)?;
    std::fs::write(
        dir.join(quote(did)),
        serde_json::to_vec(&json!({
            "$type": "blue.catbird.chat.declaration",
            "allowIncoming": "all",
            "deliveryService": delivery_service,
            "protocolVersion": "1",
            "createdAt": canonical_now(),
        }))?,
    )?;
    Ok(())
}
fn publish_pds_device_key(root: &Path, party: &FederatedParty) -> anyhow::Result<()> {
    anyhow::ensure!(party.public.len() == 32, "native MLS signer is {} bytes; PDS fixture expects Ed25519", party.public.len());
    let dir = root.join("_policy").join("deviceKeys");
    std::fs::create_dir_all(&dir)?;
    std::fs::write(
        dir.join(quote(&party.svc.did)),
        serde_json::to_vec(&json!({
            "records": [{
                "value": {
                    "algorithm": "ed25519",
                    "mlsSignaturePublicKey": {"$bytes": STANDARD.encode(&party.public)},
                    "createdAt": canonical_now(),
                }
            }]
        }))?,
    )?;
    Ok(())
}


fn ds_did_document(
    did: &str,
    server_url: &str,
    seed_byte: u8,
) -> anyhow::Result<(Value, Vec<u8>, String)> {
    let receipt_key = SigningKey::from_bytes((&[seed_byte; 32]).into())?;
    let service_key = SigningKey::from_bytes((&[seed_byte + 1; 32]).into())?;
    let receipt_point = receipt_key.verifying_key().to_encoded_point(true);
    let receipt_key_id = format!(
        "{}#chat-request-receipt-{}",
        did,
        hex::encode(Sha256::digest(receipt_point.as_bytes()))
    );

    let mut multikey = vec![0x80, 0x24];
    multikey.extend_from_slice(receipt_point.as_bytes());

    let service_point = service_key.verifying_key().to_encoded_point(false);
    let service_jwk = json!({
        "kty": "EC",
        "crv": "P-256",
        "x": URL_SAFE_NO_PAD.encode(service_point.x().expect("P256 x")),
        "y": URL_SAFE_NO_PAD.encode(service_point.y().expect("P256 y"))
    });

    let doc = json!({
        "id": did,
        "verificationMethod": [
            {
                "id": format!("{did}#atproto"),
                "type": "JsonWebKey2020",
                "controller": did,
                "publicKeyJwk": service_jwk
            },
            {
                "id": receipt_key_id.clone(),
                "controller": did,
                "type": "Multikey",
                "publicKeyMultibase": multibase::encode(multibase::Base::Base58Btc, multikey)
            }
        ],
        "service": [{
            "id": format!("{did}#atproto_mls"),
            "type": "AtprotoMLSDeliveryService",
            "serviceEndpoint": server_url
        }]
    });
    let receipt_public_key = receipt_point.as_bytes().to_vec();
    Ok((doc, receipt_public_key, receipt_key_id))
}

struct FixtureChild(Child);

impl Drop for FixtureChild {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

pub struct FederatedAuthorityServer {
    pub did: String,
    pub base_url: String,
    pub database_url: String,
    pub receipt_public_key: Vec<u8>,
    pub receipt_key_id: String,
    pub receipt_document: Vec<u8>,
    _child: FixtureChild,
    _db: DedicatedDatabase,
}

impl FederatedAuthorityServer {
    pub fn start(
        did: &str,
        port: u16,
        db_name: &str,
        https: &HttpsDidFixture,
        seed_byte: u8,
    ) -> anyhow::Result<Self> {
        let db_url = format!("postgresql://127.0.0.1:5432/{db_name}");
        let db = create_database_clone("catbird_direct_requests_test_20260919", db_name)?;
        if psql_value(&db_url, "SELECT to_regclass('chat.direct_request_remote_leases') IS NULL")? == "t" {
            psql_on(
                &db_url,
                include_str!("../../server/migrations/20260919000022_federated_transport_inbox.sql"),
            )?;
        }
        if psql_value(&db_url, "SELECT to_regclass('chat.direct_request_outbound_routes_actor_recent') IS NULL")? == "t" {
            psql_on(
                &db_url,
                include_str!("../../server/migrations/20260919000023_expired_federated_lease_release.sql"),
            )?;
        }
        psql_on(
            &db_url,
            include_str!("../../server/migrations/20260919000024_c33_coordinator_hardening.sql"),
        )?;
        psql_on(
            &db_url,
            include_str!("../../server/migrations/20260919000025_federated_inventory_conversation_items.sql"),
        )?;
        require_federation_tables(&db_url)?;
        // Each private clone is a new authority; discard the base fixture's unrelated receipt history.
        psql_on(&db_url, "TRUNCATE chat.direct_request_receipt_keys")?;

        let self_endpoint = format!("http://127.0.0.1:{port}");
        let (ds_doc, receipt_public_key, receipt_key_id) =
            ds_did_document(did, &self_endpoint, seed_byte)?;
        let receipt_document = serde_json::to_vec(&ds_doc)?;

        let receipt_key = SigningKey::from_bytes((&[seed_byte; 32]).into())?;
        let service_key = SigningKey::from_bytes((&[seed_byte + 1; 32]).into())?;

        // The cloned database's immutable protocol identity must match the runtime.
        let cursor_key_id = psql_value(
            &db_url,
            "SELECT cursor_key_id FROM chat.protocol_instances WHERE singleton=TRUE",
        )?;
        anyhow::ensure!(!cursor_key_id.is_empty(), "fixture clone lacks protocol identity");

        let binary = std::env::var("REQUEST_SERVER_FIXTURE_BINARY")
            .map(std::path::PathBuf::from)
            .unwrap_or_else(|_| {
                let mut path = std::env::current_exe().unwrap();
                path.pop();
                path.push("encrypted_request_server_fixture");
                path
            });

        let mut command = Command::new(binary);
        command
            .env("TEST_DATABASE_URL", &db_url)
            .env("SERVICE_DID", did)
            .env("REQUEST_FIXTURE_LISTEN", format!("127.0.0.1:{port}"))
            .env("SELF_ENDPOINT", &self_endpoint)
            .env("REQUEST_FIXTURE_DID_HOSTS", https.hosts.join(","))
            .env("REQUEST_FIXTURE_DID_PORT", https.port.to_string())
            .env("REQUEST_FIXTURE_DID_CA_PEM", &https.ca_pem)
            .env("DID_RESOLUTION_HOST_ALLOWLIST", https.hosts.join(","))
            .env("CHAT_CUTOVER_ENABLED", "1")
            .env("CHAT_DIRECT_REQUESTS_ENABLED", "1")
            .env("CHAT_SUBSCRIPTION_ENDPOINT", "wss://chat.example.test/xrpc/blue.catbird.chat.subscribeEvents")
            .env("FEDERATION_ALLOW_INSECURE_HTTP", "true")
            .env("FEDERATION_MODE", "open_intelligent")
            .env("CHAT_CURSOR_KEY_ID", &cursor_key_id)
            .env("CHAT_CURSOR_SEALING_SECRET", URL_SAFE_NO_PAD.encode([0xA5_u8; 32]))
            .env(
                "CHAT_REQUEST_RECEIPT_SIGNING_KEY_PEM",
                receipt_key.to_pkcs8_pem(p256::pkcs8::LineEnding::LF)?.as_str(),
            )
            .env(
                "SIGNING_KEY_PEM",
                service_key.to_pkcs8_pem(p256::pkcs8::LineEnding::LF)?.as_str(),
            )
            .env(
                "CHAT_REQUEST_RECEIPT_DID_DOCUMENT_JSON",
                String::from_utf8(receipt_document.clone())?,
            )
            .env("REQUEST_FIXTURE_OUTBOUND_WORKER", "1")
            .env("OUTBOUND_QUEUE_TICK_INTERVAL_MS", "100")
            .env("OUTBOUND_QUEUE_RETRY_DELAY_MS", "200")
            .env("RUST_LOG", "warn")
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit());

        let mut child = command.spawn().context("spawn server fixture")?;
        let mut reader = std::io::BufReader::new(child.stdout.take().context("take stdout")?);
        let mut line = String::new();
        std::io::BufRead::read_line(&mut reader, &mut line)?;
        let ready: Value = serde_json::from_str(&line)?;
        let base_url = ready["baseUrl"].as_str().context("missing baseUrl")?.to_owned();
        anyhow::ensure!(
            base_url == self_endpoint,
            "server fixture bound to {base_url} but expected {self_endpoint}"
        );

        Ok(Self {
            did: did.to_string(),
            base_url,
            database_url: db_url,
            receipt_public_key,
            receipt_key_id,
            receipt_document,
            _child: FixtureChild(child),
            _db: db,
        })
    }

    pub fn restart(
        &mut self,
        port: u16,
        https: &HttpsDidFixture,
        seed_byte: u8,
    ) -> anyhow::Result<()> {
        self.restart_with_env(port, https, seed_byte, &[])
    }

    pub fn restart_with_env(
        &mut self,
        port: u16,
        https: &HttpsDidFixture,
        seed_byte: u8,
        extra_env: &[(&str, &str)],
    ) -> anyhow::Result<()> {
        let receipt_key = SigningKey::from_bytes((&[seed_byte; 32]).into())?;
        let service_key = SigningKey::from_bytes((&[seed_byte + 1; 32]).into())?;
        let cursor_key_id = psql_value(
            &self.database_url,
            "SELECT cursor_key_id FROM chat.protocol_instances WHERE singleton=TRUE",
        )?;
        let self_endpoint = format!("http://127.0.0.1:{port}");

        let binary = std::env::var("REQUEST_SERVER_FIXTURE_BINARY")
            .map(std::path::PathBuf::from)
            .unwrap_or_else(|_| {
                let mut path = std::env::current_exe().unwrap();
                path.pop();
                path.push("encrypted_request_server_fixture");
                path
            });

        let mut command = Command::new(binary);
        command
            .env("TEST_DATABASE_URL", &self.database_url)
            .env("SERVICE_DID", &self.did)
            .env("REQUEST_FIXTURE_LISTEN", format!("127.0.0.1:{port}"))
            .env("SELF_ENDPOINT", &self_endpoint)
            .env("REQUEST_FIXTURE_DID_HOSTS", https.hosts.join(","))
            .env("REQUEST_FIXTURE_DID_PORT", https.port.to_string())
            .env("REQUEST_FIXTURE_DID_CA_PEM", &https.ca_pem)
            .env("DID_RESOLUTION_HOST_ALLOWLIST", https.hosts.join(","))
            .env("CHAT_CUTOVER_ENABLED", "1")
            .env("CHAT_DIRECT_REQUESTS_ENABLED", "1")
            .env("CHAT_SUBSCRIPTION_ENDPOINT", "wss://chat.example.test/xrpc/blue.catbird.chat.subscribeEvents")
            .env("FEDERATION_ALLOW_INSECURE_HTTP", "true")
            .env("FEDERATION_MODE", "open_intelligent")
            .env("CHAT_CURSOR_KEY_ID", &cursor_key_id)
            .env("CHAT_CURSOR_SEALING_SECRET", URL_SAFE_NO_PAD.encode([0xA5_u8; 32]))
            .env(
                "CHAT_REQUEST_RECEIPT_SIGNING_KEY_PEM",
                receipt_key.to_pkcs8_pem(p256::pkcs8::LineEnding::LF)?.as_str(),
            )
            .env(
                "SIGNING_KEY_PEM",
                service_key.to_pkcs8_pem(p256::pkcs8::LineEnding::LF)?.as_str(),
            )
            .env(
                "CHAT_REQUEST_RECEIPT_DID_DOCUMENT_JSON",
                String::from_utf8(self.receipt_document.clone())?,
            )
            .env("REQUEST_FIXTURE_OUTBOUND_WORKER", "1")
            .env("OUTBOUND_QUEUE_TICK_INTERVAL_MS", "100")
            .env("OUTBOUND_QUEUE_RETRY_DELAY_MS", "200")
            .env("RUST_LOG", "warn")
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit());
        command.envs(extra_env.iter().copied());

        let _ = self._child.0.kill();
        let _ = self._child.0.wait();

        let mut child = command.spawn().context("spawn server fixture restart")?;
        let mut reader = std::io::BufReader::new(child.stdout.take().context("take stdout")?);
        let mut line = String::new();
        std::io::BufRead::read_line(&mut reader, &mut line)?;
        let ready: Value = serde_json::from_str(&line)?;
        let base_url = ready["baseUrl"].as_str().context("missing baseUrl")?.to_owned();
        anyhow::ensure!(
            base_url == self_endpoint,
            "restarted server fixture bound to {base_url} but expected {self_endpoint}"
        );

        self._child = FixtureChild(child);
        self.base_url = base_url;
        Ok(())
    }
}

struct FederatedParty {
    svc: ServiceIdentity,
    engine: MlsEngine,
    identity: String,
    public: Vec<u8>,
    key_id: String,
}

impl FederatedParty {
    fn new(did: String, label: &str, home_did: &str) -> anyhow::Result<Self> {
        let svc = ServiceIdentity::new(did).with_audience(home_did);
        let engine = MlsEngine::new(label)?;
        let identity = format!("{}#{}", svc.did, svc.device_id);
        engine.create_key_package(&identity)?;
        let public = engine.identity_public_key(&identity)?;
        let key_id = URL_SAFE_NO_PAD.encode(Sha256::digest(&public));
        Ok(Self {
            svc,
            engine,
            identity,
            public,
            key_id,
        })
    }

    fn seed_into_database(&self, db_url: &str) -> anyhow::Result<()> {
        let jkt = jwk_thumbprint(&self.svc.jwt_jwk)?;
        let public_hex = hex::encode(&self.public);
        psql_on(
            db_url,
            &format!(
                "BEGIN; \
                 INSERT INTO chat.principals(user_did,created_at) VALUES('{did}',clock_timestamp()) ON CONFLICT DO NOTHING; \
                 INSERT INTO chat.devices(user_did,device_id,device_name,status,dpop_jkt,auth_generation,capabilities,created_at,updated_at) \
                 VALUES('{did}','{device}','c33-fixture','active','{jkt}',1,chat.protocol_capabilities(),clock_timestamp(),clock_timestamp()) \
                 ON CONFLICT(user_did,device_id) DO NOTHING; \
                 INSERT INTO chat.device_keys(user_did,device_id,key_id,signing_public_key,enrollment_auth_generation,created_at) \
                 VALUES('{did}','{device}','{key_id}',decode('{public_hex}','hex'),1,clock_timestamp()) \
                 ON CONFLICT(user_did,device_id,key_id) DO NOTHING; COMMIT;",
                did = self.svc.did,
                device = self.svc.device_id,
                key_id = self.key_id,
            ),
        )?;
        Ok(())
    }

    fn key_entry(&self) -> anyhow::Result<Value> {
        let (package, reference) = self.engine.create_key_package(&self.identity)?;
        let grant_id = Uuid::new_v4();
        let grant = signed_mls_request(
            &self.engine,
            &self.identity,
            DirectRequestKind::Grant,
            json!({
                "$type": "blue.catbird.chat.defs#directRequestGrantBody",
                "signatureDomain": "CATBIRD-DIRECT-REQUEST-GRANT\0",
                "protocolVersion": "2",
                "actorDid": self.svc.did,
                "actorDeviceId": self.svc.device_id.to_string(),
                "keyId": self.key_id,
                "authGeneration": 1,
                "grantId": grant_id.to_string(),
                "grantRevision": 1,
                "purpose": "direct-request-bootstrap",
                "profile": "encryptedIntroduction1",
                "keyPackageRef": STANDARD.encode(&reference),
                "keyPackageSha256": STANDARD.encode(Sha256::digest(&package)),
                "expiresAt": canonical_future(29),
                "idempotencyKey": grant_id.to_string(),
                "signedAt": canonical_now()
            }),
        )?;
        let keys = signed_mls_request(
            &self.engine,
            &self.identity,
            DirectRequestKind::Keys,
            json!({
                "$type": "blue.catbird.chat.defs#directRequestKeysPublicationBody",
                "signatureDomain": "CATBIRD-DIRECT-REQUEST-KEYS\0",
                "protocolVersion": "2",
                "actorDid": self.svc.did,
                "actorDeviceId": self.svc.device_id.to_string(),
                "keyId": self.key_id,
                "authGeneration": 1,
                "revision": 1,
                "enabled": true,
                "keys": [{
                    "keyPackage": {
                        "framing": "mlsMessage",
                        "contentType": "keyPackage",
                        "bytes": STANDARD.encode(&package),
                        "sha256": STANDARD.encode(Sha256::digest(&package)),
                        "keyPackageRef": STANDARD.encode(&reference)
                    },
                    "grant": grant
                }],
                "idempotencyKey": Uuid::new_v4().to_string(),
                "signedAt": canonical_now()
            }),
        )?;
        Ok(json!({"signedRequest": keys}))
    }
}

/// Verify a signed receipt outcome against an authority's receipt key and
/// return its refusal code.
fn receipt_code(response: &Value, authority: &str, key: &[u8]) -> anyhow::Result<Option<String>> {
    anyhow::ensure!(
        response["outcome"]["$type"] == "blue.catbird.chat.defs#signedDirectRequestReceipt",
        "expected a signed receipt, got {response}"
    );
    let mut signed = response["outcome"].clone();
    signed.as_object_mut().context("receipt object")?.remove("$type");
    let verified = protocol::verify_received_signed_request_for_authority(
        authority,
        DirectRequestKind::Outcome,
        &serde_json::to_vec(&signed)?,
        key,
    )?;
    Ok(verified.body()["receipt"]["code"].as_str().map(str::to_owned))
}

fn signed_ordinary(engine: &MlsEngine, identity: &str, body: Value) -> anyhow::Result<Value> {
    use catbird_mls::chat_v2::transcript::{
        decode_strict_json, project_signed_body, SignedMutationKind, SigningTranscript,
        VerifiedMutation,
    };
    let canonical = project_signed_body(
        SignedMutationKind::from_type_id(body["$type"].as_str().context("signed type")?)
            .context("signed kind")?,
        &decode_strict_json(&serde_json::to_vec(&body)?)?,
    )?;
    let transcript = SigningTranscript::build(&canonical)?;
    let signature = engine.sign_identity(identity, transcript.bytes().to_vec())?;
    VerifiedMutation::verify(
        canonical,
        signature
            .clone()
            .try_into()
            .map_err(|_| anyhow::anyhow!("signature length"))?,
        &engine.identity_public_key(identity)?,
    )?;
    Ok(json!({"body":body,"signature":STANDARD.encode(signature)}))
}

fn jwk_thumbprint(jwk: &Value) -> anyhow::Result<String> {
    let canonical = format!(
        "{{\"crv\":\"P-256\",\"kty\":\"EC\",\"x\":\"{}\",\"y\":\"{}\"}}",
        jwk["x"].as_str().context("JWK x")?,
        jwk["y"].as_str().context("JWK y")?
    );
    Ok(URL_SAFE_NO_PAD.encode(Sha256::digest(canonical.as_bytes())))
}

#[tokio::test(flavor = "multi_thread")]
async fn c33_two_authority_canonical_federation_e2e() -> anyhow::Result<()> {
    run_c33_orientation(false).await?;
    run_c33_orientation(true).await
}

async fn run_c33_orientation(reverse: bool) -> anyhow::Result<()> {
    // The shared guarded template is read-only; every mutation below targets a private clone.
    let template = "postgresql://127.0.0.1:5432/catbird_direct_requests_test_20260919";
    anyhow::ensure!(
        std::env::var("REQUEST_TEST_DATABASE_URL").as_deref() == Ok(template),
        "C33 requires the exact guarded local synthetic template"
    );
    anyhow::ensure!(
        psql_value(template, "SELECT to_regclass('chat.protocol_instances') IS NOT NULL")? == "t",
        "guarded synthetic template has no chat schema"
    );

    let did_port = HttpsDidFixture::reserve_port()?;
    let run = Uuid::new_v4().simple().to_string();

    // Use .catbird.blue domain: passes chat.is_bare_did (no reserved TLD restriction)
    let ds1_did = format!("did:web:ds1-{run}.catbird.blue");
    let ds2_did = format!("did:web:ds2-{run}.catbird.blue");

    let alice = FederatedParty::new(format!("did:web:alice-{run}.catbird.blue"), "c33-alice",
        if reverse { &ds2_did } else { &ds1_did })?;
    let bob = FederatedParty::new(format!("did:web:bob-{run}.catbird.blue"), "c33-bob",
        if reverse { &ds1_did } else { &ds2_did })?;
    let charlie = FederatedParty::new(format!("did:web:charlie-{run}.catbird.blue"), "c33-charlie", &ds1_did)?;
    let dana = FederatedParty::new(format!("did:web:dana-{run}.catbird.blue"), "c33-dana", &ds2_did)?;

    // Pre-reserve loopback ports before starting HttpsDidFixture and servers
    let port_a = reserve_loopback_port()?;
    let port_b = reserve_loopback_port()?;
    let server_a_url = format!("http://127.0.0.1:{port_a}");
    let server_b_url = format!("http://127.0.0.1:{port_b}");

    let home_document = |party: &FederatedParty, endpoint: &str| -> anyhow::Result<Value> {
        let mut doc = party.svc.did_document();
        doc["service"]
            .as_array_mut()
            .context("account DID document services")?
            .push(json!({
                "id": format!("{}#atproto_mls", party.svc.did),
                "type": "AtprotoMLSDeliveryService",
                "serviceEndpoint": endpoint
            }));
        Ok(doc)
    };

    let (ds1_doc, _, _) = ds_did_document(&ds1_did, &server_a_url, 61)?;
    let (ds2_doc, _, _) = ds_did_document(&ds2_did, &server_b_url, 71)?;

    let https = HttpsDidFixture::start(
        did_port,
        &[
            (ds1_did.clone(), ds1_doc),
            (ds2_did.clone(), ds2_doc),
            (alice.svc.did.clone(), home_document(&alice, if reverse { &server_b_url } else { &server_a_url })?),
            (bob.svc.did.clone(), home_document(&bob, if reverse { &server_a_url } else { &server_b_url })?),
            (charlie.svc.did.clone(), home_document(&charlie, &server_a_url)?),
            (dana.svc.did.clone(), home_document(&dana, &server_b_url)?),
        ],
    )?;

    // Each orientation has the same deterministic coordinator, but a different sender home.
    declare_chat_authority(&https.root, &alice.svc.did, if reverse { &ds2_did } else { &ds1_did })?;
    declare_chat_authority(&https.root, &bob.svc.did, if reverse { &ds1_did } else { &ds2_did })?;
    declare_chat_authority(&https.root, &charlie.svc.did, &ds1_did)?;
    declare_chat_authority(&https.root, &dana.svc.did, &ds2_did)?;
    for party in [&alice, &bob, &charlie, &dana] {
        publish_pds_device_key(&https.root, party)?;
    }


    let client = reqwest::Client::builder().build()?;

    let db1_name = format!("catbird_direct_requests_fault_{}", &Uuid::new_v4().simple().to_string()[..16]);
    let db2_name = format!("catbird_direct_requests_fault_{}", &Uuid::new_v4().simple().to_string()[..16]);

    // 2. Launch two independent server processes with independent databases on reserved ports
    let server_a = FederatedAuthorityServer::start(&ds1_did, port_a, &db1_name, &https, 61)?;
    let mut server_b = FederatedAuthorityServer::start(&ds2_did, port_b, &db2_name, &https, 71)?;

    // Only private per-authority databases are seeded.
    if reverse {
        alice.seed_into_database(&server_b.database_url)?;
        bob.seed_into_database(&server_a.database_url)?;
    } else {
        alice.seed_into_database(&server_a.database_url)?;
        bob.seed_into_database(&server_b.database_url)?;
    }
    charlie.seed_into_database(&server_a.database_url)?;
    dana.seed_into_database(&server_b.database_url)?;

    // Seed mutual trust policy in federation_peers on each independent database
    psql_on(
        &server_a.database_url,
        &format!("INSERT INTO federation_peers(ds_did, status) VALUES('{ds2_did}', 'allow') ON CONFLICT DO NOTHING;"),
    )?;
    psql_on(
        &server_b.database_url,
        &format!("INSERT INTO federation_peers(ds_did, status) VALUES('{ds1_did}', 'allow') ON CONFLICT DO NOTHING;"),
    )?;
    let alice_home = if reverse { server_b.base_url.clone() } else { server_a.base_url.clone() };
    let bob_home = if reverse { server_a.base_url.clone() } else { server_b.base_url.clone() };


    // -------------------------------------------------------------------------
    // Step 1: Pre-provision Bob's direct request key on his independent home DS.
    // -------------------------------------------------------------------------
    let bob_keys_input = bob.key_entry()?;
    let (key_status, key_bytes) = bob
        .svc
        .post(
            &client,
            &bob_home,
            "blue.catbird.chat.publishDirectRequestKeys",
            &bob_keys_input,
            true,
        )
        .await?;
    anyhow::ensure!(
        key_status == StatusCode::OK,
        "bob failed to publish direct request keys on his home DS: {key_status}: {}",
        String::from_utf8_lossy(&key_bytes)
    );

    // -------------------------------------------------------------------------
    // Step 2: Encrypted introduction from Alice's home to Bob's home.
    // -------------------------------------------------------------------------
    let request_id = Uuid::new_v4();
    let first_message_id = Uuid::new_v4();
    let conversation_id = Uuid::new_v4();

    let prepare_body = json!({
        "$type": "blue.catbird.chat.defs#directRequestPreparationBody",
        "signatureDomain": "CATBIRD-DIRECT-REQUEST-PREPARE\0",
        "protocolVersion": "2",
        "actorDid": alice.svc.did,
        "actorDeviceId": alice.svc.device_id.to_string(),
        "keyId": alice.key_id,
        "authGeneration": 1,
        "requestId": request_id.to_string(),
        "firstMessageId": first_message_id.to_string(),
        "conversationId": conversation_id.to_string(),
        "recipientDid": bob.svc.did,
        "origin": { "$type": "blue.catbird.chat.defs#freshDirectOrigin" },
        "profile": "encryptedIntroduction1",
        "idempotencyKey": request_id.to_string(),
        "signedAt": canonical_now()
    });

    let prepare_signed = signed_mls_request(
        &alice.engine,
        &alice.identity,
        DirectRequestKind::Prepare,
        prepare_body.clone(),
    )?;
    if !reverse {
        // The peer DS cannot supply a self-consistent key absent from Bob's PDS.
        let unauthorized_request_id = Uuid::new_v4();
        let mut unauthorized_body = prepare_body.clone();
        unauthorized_body["requestId"] = json!(unauthorized_request_id.to_string());
        unauthorized_body["idempotencyKey"] = json!(unauthorized_request_id.to_string());
        unauthorized_body["firstMessageId"] = json!(Uuid::new_v4().to_string());
        unauthorized_body["conversationId"] = json!(Uuid::new_v4().to_string());
        let unauthorized_signed = signed_mls_request(
            &alice.engine, &alice.identity, DirectRequestKind::Prepare, unauthorized_body,
        )?;
        let pds_record = https.root.join("_policy").join("deviceKeys").join(quote(&bob.svc.did));
        let authorized = std::fs::read(&pds_record)?;
        std::fs::write(&pds_record, b"{\"records\":[]}")?;
        let (status, bytes) = alice.svc.post(
            &client, &alice_home, "blue.catbird.chat.prepareDirectRequest",
            &json!({ "signedRequest": unauthorized_signed }), true,
        ).await?;
        std::fs::write(&pds_record, authorized)?;
        anyhow::ensure!(status == StatusCode::BAD_REQUEST
            && serde_json::from_slice::<Value>(&bytes)?["error"] == "RecipientKeysUnavailable",
            "PDS-unauthorized recipient key accepted: {status} {}", String::from_utf8_lossy(&bytes));
        assert_eq!(psql_count(&server_a.database_url,
            &format!("SELECT count(*) FROM chat.direct_request_attempts WHERE request_id='{unauthorized_request_id}'"))?, 0);
        assert_eq!(psql_count(&server_b.database_url,
            &format!("SELECT count(*) FROM chat.direct_request_remote_leases WHERE request_id='{unauthorized_request_id}' AND status='active'"))?, 0,
            "failed recipient authorization left an active peer package reservation");
    }


    // Alice calls her own DS; the coordinator is always DS-A.
    let (prep_status, prep_bytes) = alice
        .svc
        .post(
            &client,
            &alice_home,
            "blue.catbird.chat.prepareDirectRequest",
            &json!({ "signedRequest": prepare_signed }),
            true,
        )
        .await?;

    anyhow::ensure!(
        prep_status == StatusCode::OK,
        "prepareDirectRequest failed on Alice's home: {prep_status}: {}",
        String::from_utf8_lossy(&prep_bytes)
    );

    let prep_resp: Value = serde_json::from_slice(&prep_bytes)?;
    let raw_preparation = prep_resp
        .pointer("/outcome/preparation")
        .context("missing preparation outcome")?;
    // Use the verified, normalized snapshot: HTTP bytes wrappers are not signing-body bytes.
    let preparation = protocol::verify_direct_request_preparation_for_authority(
        &server_a.did, &serde_json::to_vec(raw_preparation)?, &server_a.receipt_public_key
    )?;

    let selected = preparation["selectedDevices"]
        .as_array()
        .context("preparation selectedDevices missing")?;
    anyhow::ensure!(
        selected.len() == 1,
        "preparation must select exactly Bob's device"
    );

    // -------------------------------------------------------------------------
    // Bob may have opened inventory before Alice publishes; the later S2S
    // delivery must not replay that empty, receipt-bound snapshot.
    let (before_status, before_bytes) = bob.svc.get(
        &client,
        &bob_home,
        "blue.catbird.chat.getConversations",
        &[
            ("supportedProtocolVersions".into(), "1".into()),
            ("supportedProtocolVersions".into(), "2".into()),
        ],
    ).await?;
    anyhow::ensure!(before_status == StatusCode::OK, "prepublication inventory failed");
    let before_inventory: Value = serde_json::from_slice(&before_bytes)?;
    let before_session = before_inventory["inventorySessionId"].as_str()
        .context("missing prepublication session")?.to_owned();
    anyhow::ensure!(before_inventory["items"].as_array().is_some_and(Vec::is_empty),
        "Bob must have no conversation before publication");

    // Step 3: Publish Encrypted Introduction on Server A
    // -------------------------------------------------------------------------
    let context_val = json!({
        "protocolVersion": "2",
        "requestId": request_id.to_string(),
        "firstMessageId": first_message_id.to_string(),
        "conversationId": conversation_id.to_string(),
        "origin": { "$type": "blue.catbird.chat.defs#freshDirectOrigin" },
        "actorDid": alice.svc.did,
        "actorDeviceId": alice.svc.device_id.to_string(),
        "actorKeyId": alice.key_id,
        "recipientDid": bob.svc.did,
        "preparationDigest": preparation["preparationDigest"]
    });

    let verified_prepare = protocol::verify_signed_request(
        DirectRequestKind::Prepare,
        &serde_json::to_vec(&prepare_signed)?,
        &alice.public,
    )?;

    let journal = alice.engine.prepare_direct_request(&DirectRequestBootstrapInput {
        draft_id: Uuid::new_v4().to_string(),
        context_json: serde_json::to_vec(&context_val)?,
        group_id: rand::random::<[u8; 32]>().to_vec(),
        generation: 0,
        state_version: 1,
        key_packages: selected
            .iter()
            .map(|device| {
                Ok(STANDARD.decode(
                    device["keyPackage"]["bytes"]["$bytes"]
                        .as_str()
                        .or_else(|| device["keyPackage"]["bytes"].as_str())
                        .context("selected package bytes")?,
                )?)
            })
            .collect::<anyhow::Result<Vec<_>>>()?,
        expected_package_refs: selected
            .iter()
            .map(|device| {
                Ok(STANDARD.decode(
                    device["keyPackage"]["keyPackageRef"]["$bytes"]
                        .as_str()
                        .or_else(|| device["keyPackage"]["keyPackageRef"].as_str())
                        .context("selected package ref")?,
                )?)
            })
            .collect::<anyhow::Result<Vec<_>>>()?,
        authority_import_until: 4_000_000_000,
        preparation_request_digest: *verified_prepare.request_digest(),
        receipt_authority_key: server_a.receipt_public_key.clone(),
        text: "Hello from Alice over Catbird MLS Federation".into(),
        invitation: None,
        metadata: GroupMetadataV1 {
            version: 1,
            title: String::new(),
            description: String::new(),
            avatar_blob_locator: None,
            avatar_content_type: None,
        },
    })?;

    let bootstrap = &journal.bootstrap;
    let mut publish_body = prepare_signed["body"].clone();
    publish_body["$type"] = json!("blue.catbird.chat.defs#directRequestPublicationBody");
    publish_body["signatureDomain"] = json!("CATBIRD-DIRECT-REQUEST-PUBLISH\0");
    publish_body["signedAt"] = json!(canonical_now());
    publish_body["preparationDigest"] = preparation["preparationDigest"].clone();
    publish_body["preparationRequestDigest"] =
        json!(STANDARD.encode(verified_prepare.request_digest()));
    publish_body["contextHash"] = json!(STANDARD.encode(bootstrap.context_hash));
    publish_body["next"] = bootstrap.coordinates.clone();
    publish_body["importUntil"] = json!(
        chrono::DateTime::from_timestamp(bootstrap.import_until as i64, 0)
            .context("MLS final-tree import deadline")?
            .to_rfc3339_opts(chrono::SecondsFormat::Millis, true)
    );

    let artifact = |data: &[u8], content_type: &str| {
        json!({
            "framing": "mlsMessage",
            "contentType": content_type,
            "bytes": STANDARD.encode(data),
            "sha256": STANDARD.encode(Sha256::digest(data))
        })
    };

    let deliveries = selected
        .iter()
        .map(|device| {
            json!({
                "recipientDid": device["actorDid"],
                "recipientDeviceId": device["actorDeviceId"],
                "provenance": {
                    "requestId": request_id.to_string(),
                    "preparationDigest": preparation["preparationDigest"],
                    "contextHash": STANDARD.encode(bootstrap.context_hash),
                    "grantId": device["grant"]["body"]["grantId"],
                    "grantRevision": device["grant"]["body"]["grantRevision"],
                    "keyPackageRef": device["keyPackage"]["keyPackageRef"],
                    "importUntil": publish_body["importUntil"]
                }
            })
        })
        .collect::<Vec<_>>();

    let author = json!({
        "authorDid": alice.svc.did,
        "authorDeviceId": alice.svc.device_id.to_string(),
        "authorKeyId": alice.key_id,
        "signaturePublicKey": STANDARD.encode(&alice.public),
        "authGenerationAtOrigin": 1,
        "originTransitionId": request_id.to_string(),
        "originSeq": 1,
        "roleAtOrigin": "admin",
        "deviceStatusAtOrigin": "active"
    });

    let metadata_snapshot = json!({
        "coordinate": metadata_coordinate(&bootstrap.coordinates)?,
        "originTransitionId": request_id.to_string(),
        "metadataVersion": 1,
        "nonce": STANDARD.encode(&bootstrap.metadata_nonce),
        "ciphertext": STANDARD.encode(&bootstrap.metadata_ciphertext),
        "ciphertextSha256": STANDARD.encode(Sha256::digest(&bootstrap.metadata_ciphertext)),
        "ciphertextSize": bootstrap.metadata_ciphertext.len(),
        "authorProof": author
    });

    publish_body["artifacts"] = json!({
        "genesisGroupInfo": artifact(&bootstrap.genesis_group_info, "groupInfo"),
        "addCommit": artifact(&bootstrap.add_commit, "publicMessageCommit"),
        "finalGroupInfo": artifact(&bootstrap.final_group_info, "groupInfo"),
        "welcome": {
            "opaqueWelcome": STANDARD.encode(&bootstrap.welcome),
            "sha256": STANDARD.encode(Sha256::digest(&bootstrap.welcome)),
            "deliveries": deliveries
        },
        "metadataSnapshot": metadata_snapshot,
        "initialCiphertext": STANDARD.encode(&bootstrap.initial_ciphertext)
    });

    let publish_signed = signed_mls_request(
        &alice.engine,
        &alice.identity,
        DirectRequestKind::Publish,
        publish_body,
    )?;
    alice.engine.persist_request_publication(&journal.request_id, &serde_json::to_vec(&publish_signed)?)?;


    // In the sender-coordinator orientation, commit while the recipient authority is offline.
    // A lost HTTP response must not turn the durable publication into a second request.
    if !reverse {
        server_b._child.0.kill()?;
        server_b._child.0.wait()?;
    }
    let mut transport = DeterministicFaultTransport::default()
        .fail_on(FaultBoundary::AfterRequestBeforeResponse, 1)?;
    let mut headers = reqwest::header::HeaderMap::new();
    headers.insert(
        reqwest::header::AUTHORIZATION,
        format!("Bearer {}", alice.svc.scoped_jwt_with_jti(
            "blue.catbird.chat.publishDirectRequest", Uuid::new_v4()
        )).parse()?,
    );
    let fault_client = reqwest::Client::builder().default_headers(headers).build()?;
    let lost = transport.post_json(
        &fault_client,
        &format!("{alice_home}/xrpc/blue.catbird.chat.publishDirectRequest"),
        &json!({ "signedRequest": publish_signed }),
    ).await.expect_err("publication response must be lost after server commits");
    anyhow::ensure!(lost.to_string().contains("AfterRequestBeforeResponse"),
        "unexpected transport failure: {lost:#}");
    assert_eq!(transport.trace(),
        &[FaultBoundary::BeforeRequest, FaultBoundary::AfterRequestBeforeResponse]);
    let first_commit_count = psql_value(&server_a.database_url,
        &format!("SELECT count(*) FROM chat.direct_request_publications WHERE request_id='{request_id}'"))?;
    if !reverse {
        assert_eq!(psql_count(&server_b.database_url,
            &format!("SELECT count(*) FROM chat.direct_request_transport_inbox WHERE request_id='{request_id}'"))?, 0,
            "offline recipient received an introduction");
        assert_eq!(psql_count(&server_a.database_url,
            &format!("SELECT count(*) FROM outbound_queue WHERE id='direct-request-delivery-{request_id}' AND status='pending'"))?, 1,
            "committed introduction was not durably queued after peer failure");
        psql_on(
            &server_a.database_url,
            &format!("UPDATE outbound_queue SET retry_count=max_retries, next_retry_at=NOW() WHERE id='direct-request-delivery-{request_id}'"),
        )?;
        let mut retry_after_limit = false;
        for _ in 0..100 {
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
            if psql_count(&server_a.database_url, &format!(
                "SELECT count(*) FROM outbound_queue WHERE id='direct-request-delivery-{request_id}' AND status='pending' AND retry_count>max_retries"
            ))? == 1 {
                retry_after_limit = true;
                break;
            }
        }
        anyhow::ensure!(retry_after_limit, "C33 queued introduction stopped retrying after five peer failures");
        server_b.restart(port_b, &https, 71)?;
        psql_on(
            &server_a.database_url,
            &format!("UPDATE outbound_queue SET next_retry_at = NOW() WHERE id='direct-request-delivery-{request_id}'"),
        )?;
        let mut auto_delivered = false;
        for _ in 0..100 {
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
            let queue_delivered = psql_count(
                &server_a.database_url,
                &format!("SELECT count(*) FROM outbound_queue WHERE id='direct-request-delivery-{request_id}' AND status='delivered'"),
            )?;
            let inbox_delivered = psql_count(
                &server_b.database_url,
                &format!("SELECT count(*) FROM chat.direct_request_transport_inbox WHERE request_id='{request_id}'"),
            )?;
            if queue_delivered == 1 && inbox_delivered == 1 {
                auto_delivered = true;
                break;
            }
        }
        anyhow::ensure!(
            auto_delivered,
            "outbound queue worker failed to auto-replay delivery to recovered peer before client retry"
        );
    }
    let (pub_status, pub_bytes) = alice.svc.post(
        &client, &alice_home, "blue.catbird.chat.publishDirectRequest",
        &json!({ "signedRequest": publish_signed }), true
    ).await?;
    anyhow::ensure!(pub_status == StatusCode::OK,
        "publishDirectRequest replay failed {pub_status} (first committed={first_commit_count}): {}",
        String::from_utf8_lossy(&pub_bytes));
    anyhow::ensure!(first_commit_count == "1",
        "publication not committed after lost client response; signed outcome: {}",
        String::from_utf8_lossy(&pub_bytes));
    let pub_resp: Value = serde_json::from_slice(&pub_bytes)?;
    let first_published_receipt = pub_resp.pointer("/outcome")
        .context("missing committed publication receipt")?.clone();
    if reverse {
        let (status, bytes) = alice.svc.get(
            &client, &alice_home, "blue.catbird.chat.getDirectRequestOutcome",
            &[
                ("requestId".into(), request_id.to_string()),
            ],
        ).await?;
        anyhow::ensure!(status == StatusCode::OK,
            "remote sender-home outcome reconciliation failed {status}: {}",
            String::from_utf8_lossy(&bytes));
        let recovered: Value = serde_json::from_slice(&bytes)?;
        assert_eq!(recovered["outcome"], first_published_receipt,
            "sender-home outcome must be the authoritative coordinator receipt after lost response");
    }
    alice.engine.confirm_request_publication(
        &journal.request_id,
        &serde_json::to_vec(&first_published_receipt)?,
        &server_a.receipt_public_key,
    )?;

    // -------------------------------------------------------------------------
    // Step 4: Lost Peer / Client Response Replay Proof (with Peer Restart)
    // -------------------------------------------------------------------------
    // Restart again to prove a delivered peer response remains idempotent.
    server_b.restart(port_b, &https, 71)?;

    let (replay_status, replay_bytes) = alice
        .svc
        .post(
            &client,
            &alice_home,
            "blue.catbird.chat.publishDirectRequest",
            &json!({ "signedRequest": publish_signed }),
            true,
        )
        .await?;

    anyhow::ensure!(
        replay_status == StatusCode::OK,
        "idempotent replay failed {replay_status}"
    );

    let replay_resp: Value = serde_json::from_slice(&replay_bytes)?;
    let replayed_receipt = replay_resp
        .pointer("/outcome")
        .context("missing replayed outcome receipt")?
        .clone();

    assert_eq!(
        first_published_receipt, replayed_receipt,
        "replayed publication must return exact identical outcome receipt"
    );

    // A cancel that comes after the publication gets the coordinator's
    // published receipt, through Alice's home when the coordinator is not
    // her home, and changes nothing on either DS.
    let inbox_count = |db: &str| {
        psql_count(db, &format!("SELECT count(*) FROM chat.direct_request_transport_inbox WHERE request_id='{request_id}'"))
    };
    let inbox_before = (
        inbox_count(&server_a.database_url)?,
        inbox_count(&server_b.database_url)?,
    );
    // When the coordinator is not Alice's home, her home rebuilds a lost
    // mirror of the publication from the cancel's answer, as a relayed
    // publish would. The rows are immutable, so the loss is staged with
    // triggers off.
    let mirror = || {
        psql_value(&server_b.database_url, &format!(
            "SELECT (SELECT count(*) FROM chat.direct_request_transport_inbox \
                     WHERE request_id='{request_id}' AND sender_did='{}' AND coordinator_did='{}')||'|'||\
                    (SELECT count(*) FROM chat.direct_request_transport_entries WHERE conversation_id='{conversation_id}')",
            alice.svc.did, server_a.did
        ))
    };
    let mirror_before = mirror()?;
    if reverse {
        anyhow::ensure!(
            mirror_before != "0|0",
            "Alice's home mirrors the publication"
        );
        psql_on(&server_b.database_url, &format!(
            "BEGIN; SET LOCAL session_replication_role = replica; \
             DELETE FROM chat.direct_request_transport_inbox WHERE request_id='{request_id}' AND sender_did='{}'; \
             DELETE FROM chat.direct_request_transport_entries WHERE conversation_id='{conversation_id}'; COMMIT;",
            alice.svc.did
        ))?;
        assert_eq!(mirror()?, "0|0");
    }
    let (status, late_cancel) = post_json(
        &alice,
        &client,
        &alice_home,
        "blue.catbird.chat.cancelDirectRequestPreparation",
        &signed_cancel(&alice, &prepare_signed)?,
    )
    .await?;
    anyhow::ensure!(
        status == StatusCode::OK,
        "cancel after publication {status}: {late_cancel}"
    );
    let late_receipt =
        authority_receipt(&late_cancel, &server_a.did, &server_a.receipt_public_key)?;
    assert_eq!(
        late_receipt["$type"],
        "blue.catbird.chat.defs#directRequestPublishedReceipt"
    );
    assert_eq!(
        bare_bytes(&late_cancel["outcome"]),
        bare_bytes(&first_published_receipt),
        "a cancel after publication answers with the publication"
    );
    assert_eq!(
        psql_value(
            &server_a.database_url,
            &format!(
                "SELECT status FROM chat.direct_request_attempts WHERE request_id='{request_id}'"
            )
        )?,
        "published"
    );
    assert_eq!(
        (
            inbox_count(&server_a.database_url)?,
            inbox_count(&server_b.database_url)?
        ),
        inbox_before,
        "the cancel writes no delivery"
    );
    assert_eq!(
        mirror()?,
        mirror_before,
        "the cancel restores Alice's home's mirror"
    );

    // -------------------------------------------------------------------------
    // Step 5: Bob imports the actual Welcome through his own DS.
    // -------------------------------------------------------------------------
    let (inventory_status, inventory_bytes) = bob.svc.get(
        &client,
        &bob_home,
        "blue.catbird.chat.getConversations",
        &[
            ("supportedProtocolVersions".into(), "1".into()),
            ("supportedProtocolVersions".into(), "2".into()),
        ],
    ).await?;
    anyhow::ensure!(inventory_status == StatusCode::OK,
        "recipient inventory failed {inventory_status}: {}", String::from_utf8_lossy(&inventory_bytes));
    let inventory: Value = serde_json::from_slice(&inventory_bytes)?;
    let inventory_session = inventory["inventorySessionId"].as_str().context("missing recipient inventory session")?;
    anyhow::ensure!(
        inventory_session != before_session,
        "recipient home replayed its prepublication empty inventory session"
    );
    let inventory_items = inventory["items"]
        .as_array()
        .context("missing items in recipient inventory")?;
    let conv_item = inventory_items
        .iter()
        .find(|item| {
            item.pointer("/state/coordinates/conversationId")
                .or_else(|| item.pointer("/conversationId"))
                .and_then(|v| v.as_str()) == Some(conversation_id.to_string().as_str())
        })
        .context("Bob did not receive remote direct request conversation in getConversations")?;
    let conv_consent = conv_item
        .pointer("/directRequest/consent")
        .or_else(|| conv_item.pointer("/state/directRequest/consent"))
        .and_then(|v| v.as_str());
    anyhow::ensure!(
        conv_consent == Some("incomingPending"),
        "expected incomingPending in getConversations, got {conv_consent:?}"
    );

    let (state_status, state_bytes) = bob
        .svc
        .get(
            &client,
            &bob_home,
            "blue.catbird.chat.getConversationState",
            &[("conversationId".into(), conversation_id.to_string())],
        )
        .await?;
    anyhow::ensure!(
        state_status == StatusCode::OK,
        "getConversationState on Server B failed {state_status}: {}",
        String::from_utf8_lossy(&state_bytes)
    );
    let state_json: Value = serde_json::from_slice(&state_bytes)?;
    let state_consent = state_json
        .pointer("/state/directRequest/consent")
        .and_then(|v| v.as_str());
    anyhow::ensure!(
        state_consent == Some("incomingPending"),
        "expected incomingPending in getConversationState, got {state_consent:?}"
    );

    let wrong_device_id = Uuid::new_v4();
    let (wrong_dev_status, wrong_dev_bytes) = bob
        .svc
        .forward_exact_service_request(
            &client,
            &bob_home,
            reqwest::Method::GET,
            "blue.catbird.chat.getConversationState",
            Some(&format!(
                "conversationId={conversation_id}&actorDeviceId={wrong_device_id}"
            )),
            None,
        )
        .await?;
    anyhow::ensure!(
        wrong_dev_status == StatusCode::UNAUTHORIZED
            || wrong_dev_status == StatusCode::FORBIDDEN
            || wrong_dev_status == StatusCode::BAD_REQUEST,
        "expected wrong-device refusal (401/403/400), got {wrong_dev_status}: {}",
        String::from_utf8_lossy(&wrong_dev_bytes)
    );

    let wrong_user = if reverse { &charlie } else { &dana };
    let (wrong_user_status, wrong_user_bytes) = wrong_user
        .svc
        .get(
            &client,
            &bob_home,
            "blue.catbird.chat.getConversationState",
            &[("conversationId".into(), conversation_id.to_string())],
        )
        .await?;
    let wrong_user_error: Value = serde_json::from_slice(&wrong_user_bytes)?;
    anyhow::ensure!(
        wrong_user_status.is_client_error()
            && (wrong_user_error["error"] == "ConversationNotFound"
                || wrong_user_error["error"] == "NotEntitled"),
        "same-home wrong user must not see Bob's remote state: {wrong_user_status} {}",
        String::from_utf8_lossy(&wrong_user_bytes)
    );


    let (welcomes_status, welcomes_bytes) = bob
        .svc
        .get(
            &client,
            &bob_home,
            "blue.catbird.chat.getPendingWelcomes",
            &[
                ("inventorySessionId".into(), inventory_session.into()),
                ("limit".into(), "10".into()),
                ("supportedProtocolVersions".into(), "1".into()),
                ("supportedProtocolVersions".into(), "2".into()),
            ],
        )
        .await?;

    anyhow::ensure!(
        welcomes_status == StatusCode::OK,
        "getPendingWelcomes on Server B failed {welcomes_status}: {}",
        String::from_utf8_lossy(&welcomes_bytes)
    );

    let welcomes_resp: Value = serde_json::from_slice(&welcomes_bytes)?;
    let items = welcomes_resp["items"]
        .as_array()
        .context("pending welcomes items missing on Server B")?;

    let welcome_item = items
        .iter()
        .find(|item| item["welcomeId"] == request_id.to_string())
        .context("Bob did not receive pending Welcome on Server B")?;

    let delivered_welcome = STANDARD.decode(
        welcome_item["opaqueWelcome"]["$bytes"].as_str()
            .or_else(|| welcome_item["opaqueWelcome"].as_str())
            .context("recipient home did not deliver encrypted Welcome bytes")?
    )?;
    anyhow::ensure!(!delivered_welcome.is_empty(), "empty recipient-home Welcome");
    let (entry_status, entry_bytes) = bob.svc.get(
        &client, &bob_home, "blue.catbird.chat.getEntries",
        &[
            ("conversationId".into(), conversation_id.to_string()),
            ("afterSeq".into(), "0".into()),
            ("limit".into(), "10".into()),
        ],
    ).await?;
    anyhow::ensure!(entry_status == StatusCode::OK,
        "Bob did not receive signed introduction {entry_status}: {}",
        String::from_utf8_lossy(&entry_bytes));
    let entry_page: Value = serde_json::from_slice(&entry_bytes)?;
    let introduction_entry = entry_page["entries"].as_array().context("Bob entries missing")?
        .iter()
        .find(|entry| entry["seq"] == 1)
        .context("signed introduction absent from recipient home")?;
    anyhow::ensure!(
        introduction_entry.get("publicationReceipt").is_none(),
        "recipient entry must not carry a field absent from the signed directRequestEntry lexicon"
    );
    let remote_publication = introduction_entry["signedRequest"].clone();
    let (status, bytes) = bob.svc.get(
        &client, &bob_home, "blue.catbird.chat.getDirectRequestOutcome",
        &[("requestId".into(), request_id.to_string())],
    ).await?;
    anyhow::ensure!(status == StatusCode::OK,
        "recipient home did not return publication outcome {status}: {}",
        String::from_utf8_lossy(&bytes));
    let remote_receipt = serde_json::from_slice::<Value>(&bytes)?["outcome"].clone();
    anyhow::ensure!(remote_publication.is_object() && remote_receipt.is_object(),
        "recipient home omitted signed publication or coordinator receipt: {introduction_entry}");
    anyhow::ensure!(
        introduction_entry["receivedAt"] == remote_receipt["body"]["receipt"]["recordedAt"],
        "recipient entry timestamp must bind to the coordinator's signed publication receipt"
    );
    let verified_publication = protocol::verify_received_signed_request_for_authority(
        &server_a.did, DirectRequestKind::Publish,
        &serde_json::to_vec(&remote_publication)?, &alice.public
    ).context("recipient-sourced signed publication verification")?;
    let verified_receipt = protocol::verify_received_signed_request_for_authority(
        &server_a.did, DirectRequestKind::Outcome,
        &serde_json::to_vec(&remote_receipt)?, &server_a.receipt_public_key
    ).context("recipient-sourced coordinator receipt verification")?;
    anyhow::ensure!(verified_publication.body()["requestId"] == request_id.to_string()
        && verified_receipt.body()["receipt"]["requestId"] == request_id.to_string(),
        "recipient did not receive independently verified introduction and receipt");
    let publication = verified_publication.body();
    let artifacts = &publication["artifacts"];
    let wire_bytes = |value: &Value| -> anyhow::Result<Vec<u8>> {
        Ok(STANDARD.decode(value.as_str().or_else(|| value["$bytes"].as_str())
            .context("missing delivered byte field")?)?)
    };
    let recipient_context = json!({
        "protocolVersion": "2",
        "requestId": publication["requestId"],
        "firstMessageId": publication["firstMessageId"],
        "conversationId": publication["conversationId"],
        "origin": publication["origin"],
        "actorDid": publication["actorDid"],
        "actorDeviceId": publication["actorDeviceId"],
        "actorKeyId": publication["keyId"],
        "recipientDid": publication["recipientDid"],
        "preparationDigest": publication["preparationDigest"],
    });
    let delivered_bootstrap = DirectRequestBootstrap {
        context_json: serde_json::to_vec(&recipient_context)?,
        context_hash: wire_bytes(&publication["contextHash"])?.try_into()
            .map_err(|_| anyhow::anyhow!("invalid delivered context hash"))?,
        coordinates: publication["next"].clone(),
        import_until: chrono::DateTime::parse_from_rfc3339(
            publication["importUntil"].as_str().context("missing import deadline")?
        )?.timestamp().try_into()?,
        expected_package_refs: artifacts["welcome"]["deliveries"].as_array()
            .context("missing signed deliveries")?.iter()
            .map(|delivery| wire_bytes(&delivery["provenance"]["keyPackageRef"]))
            .collect::<anyhow::Result<Vec<_>>>()?,
        genesis_group_info: wire_bytes(&artifacts["genesisGroupInfo"]["bytes"])?,
        add_commit: wire_bytes(&artifacts["addCommit"]["bytes"])?,
        final_group_info: wire_bytes(&artifacts["finalGroupInfo"]["bytes"])?,
        welcome: delivered_welcome,
        metadata_nonce: wire_bytes(&artifacts["metadataSnapshot"]["nonce"])?,
        metadata_ciphertext: wire_bytes(&artifacts["metadataSnapshot"]["ciphertext"])?,
        initial_ciphertext: wire_bytes(&artifacts["initialCiphertext"])?,
    };
    let welcome_input = DirectRequestWelcomeInput {
        bootstrap: delivered_bootstrap,
        local_identity: bob.identity.as_bytes().to_vec(),
        local_package_ref: wire_bytes(&welcome_item["provenance"]["keyPackageRef"])?,
        publication_request: serde_json::to_vec(&remote_publication)?,
        actor_signature_public_key: alice.public.clone(),
        published_receipt: serde_json::to_vec(&remote_receipt)?,
        receipt_authority_did: server_a.did.clone(),
        receipt_authority_key: server_a.receipt_public_key.clone(),
        preparation_request_digest: wire_bytes(&publication["preparationRequestDigest"])?
            .try_into().map_err(|_| anyhow::anyhow!("invalid preparation digest"))?,
    };

    bob.engine.process_direct_request(&welcome_input)?;
    let decrypted = bob.engine.decrypt_direct_request(&welcome_input)?;
    let DirectRequestIntroductionResult::Ready { plaintext } = decrypted else {
        anyhow::bail!("Bob introduction decryption not ready");
    };
    let introduction = protocol::decode_direct_request_introduction(&plaintext)?;
    assert_eq!(
        introduction["text"],
        "Hello from Alice over Catbird MLS Federation",
        "Bob successfully decrypted Alice's encrypted introduction on Server B"
    );

    // -------------------------------------------------------------------------
    // Step 6: Acceptance (Bob accepts on Server B, relayed to Coordinator Server A)
    // -------------------------------------------------------------------------
    let transition_id = Uuid::new_v4();
    let accept_body = json!({
        "$type": "blue.catbird.chat.defs#directRequestAcceptanceBody",
        "signatureDomain": "CATBIRD-DIRECT-REQUEST-ACCEPT\0",
        "protocolVersion": "2",
        "actorDid": bob.svc.did,
        "actorDeviceId": bob.svc.device_id.to_string(),
        "keyId": bob.key_id,
        "authGeneration": 1,
        "requestId": request_id.to_string(),
        "transitionId": transition_id.to_string(),
        "prior": bootstrap.coordinates.clone(),
        "next": {
            "conversationId": conversation_id.to_string(),
            "generation": 0,
            "stateVersion": 2,
            "groupId": bootstrap.coordinates["groupId"],
            "epoch": bootstrap.coordinates["epoch"],
            "groupContextHash": bootstrap.coordinates["groupContextHash"],
            "confirmationTag": bootstrap.coordinates["confirmationTag"],
            "lifecycle": "active"
        },
        "invitationProvenance": {
            "invitationTransitionId": request_id.to_string(),
            "invitedByDid": alice.svc.did,
            "invitedByDeviceId": alice.svc.device_id.to_string()
        },
        "idempotencyKey": transition_id.to_string(),
        "signedAt": canonical_now()
    });

    let accept_signed = signed_mls_request(
        &bob.engine,
        &bob.identity,
        DirectRequestKind::Accept,
        accept_body.clone(),
    )?;
    let accept_replay = accept_signed.clone();

    let (accept_status, accept_bytes) = bob
        .svc
        .post(
            &client,
            &bob_home,
            "blue.catbird.chat.acceptConversation",
            &json!({ "directRequest": accept_signed }),
            true,
        )
        .await?;

    anyhow::ensure!(
        accept_status == StatusCode::OK,
        "acceptConversation on Bob's home failed {accept_status}: {}",
        String::from_utf8_lossy(&accept_bytes)
    );

    let accept_resp: Value = serde_json::from_slice(&accept_bytes)?;
    let acceptance_proof = accept_resp
        .pointer("/acceptanceProof/receipt")
        .context("missing acceptance proof receipt")?;
    assert_eq!(
        acceptance_proof["body"]["requestId"],
        request_id.to_string(),
        "acceptance proof binds to the exact request ID"
    );
    let (replay_status, replay_bytes) = bob.svc.post(
        &client, &bob_home, "blue.catbird.chat.acceptConversation",
        &json!({ "directRequest": accept_replay }), true,
    ).await?;
    anyhow::ensure!(replay_status == StatusCode::OK
        && serde_json::from_slice::<Value>(&replay_bytes)? == accept_resp,
        "lost acceptance response did not replay the verified outcome: {replay_status}: {}",
        String::from_utf8_lossy(&replay_bytes));
    assert_eq!(psql_count(
        &server_a.database_url,
        &format!("SELECT count(*) FROM chat.entries WHERE conversation_id='{conversation_id}' AND seq=2"),
    )?, 1, "acceptance response replay duplicated the canonical transition");
    // Parent invariant check: recipient home getEntries seq=2 normalized directRequestAcceptanceEntry
    // hash must equal accept_resp.acceptanceProof.entry canonical entry hash
    let (accept_entry_status, accept_entry_bytes) = bob.svc.get(
        &client,
        &bob_home,
        "blue.catbird.chat.getEntries",
        &[
            ("conversationId".into(), conversation_id.to_string()),
            ("afterSeq".into(), "1".into()),
            ("limit".into(), "10".into()),
        ],
    ).await?;
    anyhow::ensure!(
        accept_entry_status == StatusCode::OK,
        "recipient home getEntries seq=2 failed {accept_entry_status}: {}",
        String::from_utf8_lossy(&accept_entry_bytes)
    );
    let accept_entry_page: Value = serde_json::from_slice(&accept_entry_bytes)?;
    let fetched_accept_entry = accept_entry_page["entries"]
        .as_array()
        .context("recipient home entries missing after accept")?
        .iter()
        .find(|entry| entry["seq"] == 2)
        .context("recipient home getEntries missing seq=2 acceptance entry")?;
    let proof_entry = accept_resp
        .pointer("/acceptanceProof/entry")
        .context("missing acceptanceProof.entry in accept response")?;
    anyhow::ensure!(fetched_accept_entry.get("acceptanceProof").is_none(),
        "recipient acceptance entry must not embed a proof outside its lexicon");
    let mut proof_entry = proof_entry.clone();
    proof_entry.as_object_mut().context("acceptance proof entry object")?.remove("$type");
    let proof_entry = protocol::normalize_read_presentation(
        &serde_json::to_vec(&proof_entry)?, "directRequestAcceptanceEntry", false)?;
    let mut fetched_entry = protocol::normalize_read_presentation(
        &serde_json::to_vec(fetched_accept_entry)?, "directRequestAcceptanceEntry", true)?;
    fetched_entry.as_object_mut().context("recipient acceptance entry object")?.remove("$type");
    let proof_entry_hash = protocol::direct_request_acceptance_entry_hash(
        &serde_json::to_vec(&proof_entry)?)?;
    let fetched_entry_hash = protocol::direct_request_acceptance_entry_hash(
        &serde_json::to_vec(&fetched_entry)?)?;
    assert_eq!(
        fetched_entry_hash, proof_entry_hash,
        "recipient home getEntries seq=2 normalized directRequestAcceptanceEntry hash must equal accept_resp.acceptanceProof.entry canonical entry hash"
    );
    let (accepted_status, accepted_bytes) = bob.svc.get(
        &client,
        &bob_home,
        "blue.catbird.chat.getConversations",
        &[
            ("supportedProtocolVersions".into(), "1".into()),
            ("supportedProtocolVersions".into(), "2".into()),
        ],
    ).await?;
    anyhow::ensure!(accepted_status == StatusCode::OK,
        "accepted recipient inventory failed {accepted_status}: {}", String::from_utf8_lossy(&accepted_bytes));
    let accepted_inventory: Value = serde_json::from_slice(&accepted_bytes)?;
    let accepted_item = accepted_inventory["items"].as_array()
        .and_then(|items| items.iter().find(|item|
            item.pointer("/state/coordinates/conversationId")
                .or_else(|| item.pointer("/conversationId"))
                .and_then(Value::as_str) == Some(conversation_id.to_string().as_str())))
        .context("accepted remote conversation disappeared from recipient inventory")?;
    anyhow::ensure!(
        accepted_item.pointer("/state/directRequest/consent")
            .or_else(|| accepted_item.pointer("/directRequest/consent"))
            .and_then(Value::as_str) == Some("accepted"),
        "recipient inventory did not project accepted remote consent"
    );


    // -------------------------------------------------------------------------
    // Step 7: Bi-Directional Reply with Real MLS Encryption & Decryption
    // -------------------------------------------------------------------------
    let group_id_str = bootstrap.coordinates["groupId"]
        .as_str()
        .or_else(|| bootstrap.coordinates["groupId"]["$bytes"].as_str())
        .context("missing groupId in coordinates")?;
    let group_id_bytes = STANDARD.decode(group_id_str)?;
    let epoch = bootstrap.coordinates["epoch"].as_u64().context("missing MLS epoch")?;
    for (sender, sender_home, recipient, recipient_home, seq, text) in [
        (&bob, &bob_home, &alice, &alice_home, 3, "Bob's encrypted reply"),
        (&alice, &alice_home, &bob, &bob_home, 4, "Alice's encrypted reply"),
    ] {
        let message_id = Uuid::new_v4();
        let mut aad_prior = accept_body["next"].clone();
        aad_prior["conversationId"] = json!(STANDARD.encode(conversation_id.as_bytes()));
        let aad = json!({
            "protocolVersion": "1",
            "conversationId": STANDARD.encode(conversation_id.as_bytes()),
            "generation": 0,
            "messageId": STANDARD.encode(message_id.as_bytes()),
            "prior": aad_prior
        });
        let plaintext = MLSMessagePayload::text(text).encode()?;
        let ciphertext = sender.engine.encrypt_canonical(
            &group_id_bytes,
            &plaintext,
            canonical_application_aad_bytes(&aad)?,
            epoch,
        )?;
        let body = json!({
            "$type": "blue.catbird.chat.defs#applicationSendBody",
            "signatureDomain": "CATBIRD-CHAT-MESSAGE\0",
            "messageId": message_id.to_string(),
            "actorDid": sender.svc.did,
            "actorDeviceId": sender.svc.device_id.to_string(),
            "keyId": sender.key_id,
            "authGeneration": 1,
            "prior": accept_body["next"],
            "aad": aad,
            "applicationMessage": {
                "framing": "mlsMessage",
                "contentType": "privateMessageApplication",
                "bytes": STANDARD.encode(&ciphertext),
                "sha256": STANDARD.encode(Sha256::digest(&ciphertext))
            },
            "blobBindings": [],
            "signedAt": canonical_now()
        });
        let signed = signed_ordinary(&sender.engine, &sender.identity, body.clone())?;
        let retry_signed = signed.clone();
        let (status, response_bytes) = sender.svc.post(
            &client, sender_home, "blue.catbird.chat.sendMessage",
            &json!({ "signedRequest": signed }), true
        ).await?;
        anyhow::ensure!(status == StatusCode::OK,
            "sendMessage from {} failed {status}: {}",
            sender.svc.did, String::from_utf8_lossy(&response_bytes));
        let response: Value = serde_json::from_slice(&response_bytes)?;
        assert_eq!(response["entry"]["seq"], seq);
        anyhow::ensure!(response["entry"].as_object().is_some_and(|entry|
            entry.len() == 5 && !entry.contains_key("$type")),
            "XRPC sendMessage response must expose the five-field client entry, not the internally tagged S2S delivery entry");
        if seq == 3 {
            let (retry_status, retry_bytes) = sender.svc.post(
                &client, sender_home, "blue.catbird.chat.sendMessage",
                &json!({ "signedRequest": retry_signed }), true,
            ).await?;
            anyhow::ensure!(retry_status == StatusCode::OK
                && serde_json::from_slice::<Value>(&retry_bytes)? == response,
                "remote exact send retry must replay the same five-field accepted entry");
            let mut changed = body;
            changed["signedAt"] = json!(canonical_now());
            let changed_signed = signed_ordinary(&sender.engine, &sender.identity, changed)?;
            let (conflict, error_bytes) = sender.svc.post(
                &client, sender_home, "blue.catbird.chat.sendMessage",
                &json!({ "signedRequest": changed_signed }), true,
            ).await?;
            assert_eq!(conflict, StatusCode::BAD_REQUEST,
                "same message ID with different signed request was falsely acknowledged");
            assert_eq!(serde_json::from_slice::<Value>(&error_bytes)?["error"], "IdempotencyConflict");
        }

        let (status, bytes) = recipient.svc.get(
            &client, recipient_home, "blue.catbird.chat.getEntries",
            &[
                ("conversationId".into(), conversation_id.to_string()),
                ("afterSeq".into(), (seq - 1).to_string()),
                ("limit".into(), "10".into()),
            ],
        ).await?;
        anyhow::ensure!(status == StatusCode::OK,
            "recipient {} getEntries failed {status}: {}",
            recipient.svc.did, String::from_utf8_lossy(&bytes));
        let page: Value = serde_json::from_slice(&bytes)?;
        let entry = page["entries"].as_array().context("entries missing")?
            .iter()
            .find(|e| e["$type"] == "blue.catbird.chat.defs#applicationEntry"
                && e["seq"] == seq)
            .with_context(|| format!("recipient {} did not serve encrypted reply seq {seq}: {page}", recipient.svc.did))?;
        let fetched_b64 = entry.pointer("/signedRequest/body/applicationMessage/bytes")
            .and_then(|v| v.as_str().or_else(|| v["$bytes"].as_str()))
            .context("missing ciphertext in fetched reply entry")?;
        anyhow::ensure!(STANDARD.decode(fetched_b64)? == ciphertext,
            "recipient home delivered ciphertext other than the signed application message");
        let authenticated = recipient.engine.decrypt_authenticated(
            &group_id_bytes, &STANDARD.decode(fetched_b64)?
        )?;
        let decoded = MLSMessagePayload::decode(&authenticated.plaintext)?;
        assert_eq!(decoded.display_text(), text, "peer could not decrypt shipped MLS reply");
    }

    // -------------------------------------------------------------------------
    // Step 8: simultaneous first-send attempts for a fresh pair, one per home DS.
    for (party, home) in [
        (&charlie, &server_a.base_url),
        (&dana, &server_b.base_url),
    ] {
        let (status, response) = party
            .svc
            .post(
                &client,
                home,
                "blue.catbird.chat.publishDirectRequestKeys",
                &party.key_entry()?,
                true,
            )
            .await?;
        anyhow::ensure!(
            status == StatusCode::OK,
            "fresh-pair key publication failed: {status}: {}",
            String::from_utf8_lossy(&response)
        );
    }
    let race_prepare = |sender: &FederatedParty, recipient: &FederatedParty| {
        let request_id = Uuid::new_v4();
        signed_mls_request(
            &sender.engine,
            &sender.identity,
            DirectRequestKind::Prepare,
            json!({
                "$type": "blue.catbird.chat.defs#directRequestPreparationBody",
                "signatureDomain": "CATBIRD-DIRECT-REQUEST-PREPARE\0",
                "protocolVersion": "2",
                "actorDid": sender.svc.did,
                "actorDeviceId": sender.svc.device_id.to_string(),
                "keyId": sender.key_id,
                "authGeneration": 1,
                "requestId": request_id.to_string(),
                "firstMessageId": Uuid::new_v4().to_string(),
                "conversationId": Uuid::new_v4().to_string(),
                "recipientDid": recipient.svc.did,
                "origin": { "$type": "blue.catbird.chat.defs#freshDirectOrigin" },
                "profile": "encryptedIntroduction1",
                "idempotencyKey": request_id.to_string(),
                "signedAt": canonical_now()
            }),
        )
    };
    let dana_request = race_prepare(&dana, &charlie)?;
    let dana_replay = dana_request.clone();
    let charlie_request = race_prepare(&charlie, &dana)?;
    let dana_request_id = dana_replay["body"]["requestId"].as_str().context("Dana request ID")?.to_owned();
    let charlie_request_id = charlie_request["body"]["requestId"].as_str().context("Charlie request ID")?.to_owned();
    let barrier = Arc::new(tokio::sync::Barrier::new(2));
    let dana_task = {
        let gate = barrier.clone();
        let svc = dana.svc.clone();
        let client = client.clone();
        let home = server_b.base_url.clone();
        tokio::spawn(async move {
            gate.wait().await;
            svc.post(
                &client,
                &home,
                "blue.catbird.chat.prepareDirectRequest",
                &json!({ "signedRequest": dana_request }),
                true,
            )
            .await
        })
    };
    let charlie_task = {
        let gate = barrier.clone();
        let svc = charlie.svc.clone();
        let client = client.clone();
        let home = server_a.base_url.clone();
        tokio::spawn(async move {
            gate.wait().await;
            svc.post(
                &client,
                &home,
                "blue.catbird.chat.prepareDirectRequest",
                &json!({ "signedRequest": charlie_request }),
                true,
            )
            .await
        })
    };
    let (dana_result, charlie_result) = tokio::try_join!(dana_task, charlie_task)?;
    let (dana_status, dana_bytes) = dana_result?;
    let (charlie_status, charlie_bytes) = charlie_result?;
    let prepared = |status: StatusCode, bytes: &[u8]| -> anyhow::Result<bool> {
        let value: Value = serde_json::from_slice(bytes)?;
        if status == StatusCode::BAD_REQUEST && value["error"] == "PreparationConflict" {
            return Ok(false);
        }
        anyhow::ensure!(status == StatusCode::OK, "first-send race failed {status}: {value}");
        if value.pointer("/outcome/preparation").is_some() {
            return Ok(true);
        }
        anyhow::ensure!(
            value.pointer("/outcome/receipt").is_some(),
            "losing first-send must have a signed, typed outcome: {value}"
        );
        Ok(false)
    };
    let dana_prepared = prepared(dana_status, &dana_bytes)?;
    let charlie_prepared = prepared(charlie_status, &charlie_bytes)?;
    assert_eq!(
        u8::from(dana_prepared) + u8::from(charlie_prepared),
        1,
        "opposite-direction first sends must not create two preparations"
    );
    let (losing_recipient_db, losing_request_id) = if dana_prepared {
        (&server_b.database_url, charlie_request_id)
    } else {
        (&server_a.database_url, dana_request_id)
    };
    assert_eq!(psql_count(
        losing_recipient_db,
        &format!("SELECT count(*) FROM chat.direct_request_remote_leases WHERE request_id='{losing_request_id}' AND status='active'"),
    )?, 0, "losing signed terminal preparation retained a recipient package reservation");
    let pair_attempts = format!(
        "SELECT count(*) FROM chat.direct_request_attempts \
         WHERE (actor_did='{}' AND recipient_did='{}') \
            OR (actor_did='{}' AND recipient_did='{}')",
        charlie.svc.did, dana.svc.did, dana.svc.did, charlie.svc.did
    );
    assert_eq!(psql_count(&server_a.database_url, &pair_attempts)?, 1);
    assert_eq!(psql_count(&server_b.database_url, &pair_attempts)?, 0);
    // Sender-home routes are bounded even when the coordinator rejects the
    // attempt; a retained request ID remains replayable at the limit.
    assert_eq!(psql_count(
        &server_b.database_url,
        &format!("SELECT count(*) FROM chat.direct_request_outbound_routes WHERE actor_did='{}'", dana.svc.did),
    )?, 1);
    psql_on(
        &server_b.database_url,
        &format!(
            "INSERT INTO chat.direct_request_outbound_routes \
             (request_id, actor_did, actor_device_id, recipient_did, coordinator_did) \
             SELECT gen_random_uuid(), '{}', '{}', '{}', '{}' FROM generate_series(1,19)",
            dana.svc.did, dana.svc.device_id, charlie.svc.did, server_a.did,
        ),
    )?;
    let (cap_status, cap_bytes) = dana.svc.post(
        &client, &server_b.base_url, "blue.catbird.chat.prepareDirectRequest",
        &json!({ "signedRequest": race_prepare(&dana, &charlie)? }), true,
    ).await?;
    assert_eq!(cap_status, StatusCode::BAD_REQUEST);
    assert_eq!(serde_json::from_slice::<Value>(&cap_bytes)?["error"], "CapacityUnavailable");
    let (_, replay_bytes) = dana.svc.post(
        &client, &server_b.base_url, "blue.catbird.chat.prepareDirectRequest",
        &json!({ "signedRequest": dana_replay }), true,
    ).await?;
    assert_ne!(serde_json::from_slice::<Value>(&replay_bytes)?["error"], "CapacityUnavailable");

    // -------------------------------------------------------------------------
    // Step 9: Zero Legacy Fallback and Exact Canonical DB Graph Assertion
    // -------------------------------------------------------------------------
    for (node, database_url) in [
        ("A", &server_a.database_url),
        ("B", &server_b.database_url),
    ] {
        // The catalog still creates the legacy tables; a canonical node never
        // writes to them.
        for table in ["messages", "welcome_messages", "pending_welcomes"] {
            assert_eq!(
                psql_count(database_url, &format!("SELECT count(*) FROM public.{table}"))?,
                0,
                "Server {node} must not use the legacy {table} table"
            );
        }
        assert_eq!(
            psql_count(
                database_url,
                &format!("SELECT count(*) FROM chat.inventory_welcome_items WHERE welcome_id='{request_id}' AND legacy_welcome_id IS NOT NULL")
            )?,
            0,
            "Server {node} must not write legacy Welcome deliveries"
        );
        let expected_conversations = if node == "A" { 1 } else { 0 };
        let expected_entries = if node == "A" { 4 } else { 0 };
        assert_eq!(
            psql_count(
                database_url,
                &format!("SELECT count(*) FROM chat.conversations WHERE conversation_id = '{conversation_id}'")
            )?,
            expected_conversations,
            "only the coordinator has the canonical conversation"
        );
        assert_eq!(
            psql_count(
                database_url,
                &format!("SELECT count(*) FROM chat.entries WHERE conversation_id = '{conversation_id}'")
            )?,
            expected_entries,
            "only the coordinator sequences introduction, acceptance, and both encrypted replies"
        );
        assert_eq!(
            psql_count(
                database_url,
                &format!("SELECT count(*) FROM chat.direct_request_transport_inbox WHERE conversation_id = '{conversation_id}'")
            )?,
            if node == "B" { 1 } else { 0 },
            "only recipient home retains the verified encrypted Welcome"
        );
    }

    // -------------------------------------------------------------------------
    // Step 10: Mutable Coordinator Split-Brain Defense under PDS Declaration Churn
    // -------------------------------------------------------------------------
    // Whichever participant started on DS1 (Alice if !reverse, Bob if reverse)
    // migrates their PDS declaration to DS2. Both participants now declare DS2
    // as their home authority, making DS2 the newly calculated deterministic coordinator.
    //
    // The pair owner fence on DS2 must detect the prior coordinator (DS1) across
    // transport_inbox, remote_leases, and outbound_routes, and fail closed without
    // creating duplicate direct conversations or split-brain attempts.
    let (ds1_party, ds2_party) = if reverse {
        (&bob, &alice)
    } else {
        (&alice, &bob)
    };

    declare_chat_authority(&https.root, &ds1_party.svc.did, &ds2_did)?;
    ds1_party.seed_into_database(&server_b.database_url)?;

    let churn_request_id = Uuid::new_v4();
    let churn_body = json!({
        "$type": "blue.catbird.chat.defs#directRequestPreparationBody",
        "signatureDomain": "CATBIRD-DIRECT-REQUEST-PREPARE\0",
        "protocolVersion": "2",
        "actorDid": ds1_party.svc.did,
        "actorDeviceId": ds1_party.svc.device_id.to_string(),
        "keyId": ds1_party.key_id,
        "authGeneration": 1,
        "requestId": churn_request_id.to_string(),
        "firstMessageId": Uuid::new_v4().to_string(),
        "conversationId": Uuid::new_v4().to_string(),
        "recipientDid": ds2_party.svc.did,
        "origin": { "$type": "blue.catbird.chat.defs#freshDirectOrigin" },
        "profile": "encryptedIntroduction1",
        "idempotencyKey": churn_request_id.to_string(),
        "signedAt": canonical_now()
    });

    let churn_signed = signed_mls_request(
        &ds1_party.engine,
        &ds1_party.identity,
        DirectRequestKind::Prepare,
        churn_body,
    )?;

    let caller = ds1_party.svc.clone().with_audience(&ds2_did);
    let (churn_status, churn_bytes) = caller
        .post(
            &client,
            &server_b.base_url,
            "blue.catbird.chat.prepareDirectRequest",
            &json!({ "signedRequest": churn_signed }),
            true,
        )
        .await?;

    assert_eq!(churn_status, StatusCode::BAD_REQUEST);
    let churn_val: Value = serde_json::from_slice(&churn_bytes)?;
    assert_eq!(
        churn_val["error"], "PreparationConflict",
        "PDS declaration churn must be rejected with PreparationConflict under pair owner fence: {churn_val}"
    );

    // Verify DS-B did not create a split-brain attempt or direct conversation
    assert_eq!(
        psql_count(
            &server_b.database_url,
            &format!("SELECT count(*) FROM chat.direct_request_attempts WHERE request_id = '{churn_request_id}'")
        )?,
        0,
        "rejected churn attempt must not write to direct_request_attempts"
    );
    assert_eq!(
        psql_count(
            &server_b.database_url,
            &format!(
                "SELECT count(*) FROM chat.conversations \
                 WHERE kind = 'direct' \
                   AND direct_did_low=LEAST('{}' COLLATE \"C\", '{}' COLLATE \"C\") \
                   AND direct_did_high=GREATEST('{}' COLLATE \"C\", '{}' COLLATE \"C\")",
                ds1_party.svc.did, ds2_party.svc.did, ds1_party.svc.did, ds2_party.svc.did
            )
        )?,
        0,
        "DS-B must not create a duplicate direct conversation under declaration churn"
    );

    // Also assert the opposite send direction on DS2 (from ds2_party to ds1_party) is fenced
    let churn_rev_id = Uuid::new_v4();
    let churn_rev_body = json!({
        "$type": "blue.catbird.chat.defs#directRequestPreparationBody",
        "signatureDomain": "CATBIRD-DIRECT-REQUEST-PREPARE\0",
        "protocolVersion": "2",
        "actorDid": ds2_party.svc.did,
        "actorDeviceId": ds2_party.svc.device_id.to_string(),
        "keyId": ds2_party.key_id,
        "authGeneration": 1,
        "requestId": churn_rev_id.to_string(),
        "firstMessageId": Uuid::new_v4().to_string(),
        "conversationId": Uuid::new_v4().to_string(),
        "recipientDid": ds1_party.svc.did,
        "origin": { "$type": "blue.catbird.chat.defs#freshDirectOrigin" },
        "profile": "encryptedIntroduction1",
        "idempotencyKey": churn_rev_id.to_string(),
        "signedAt": canonical_now()
    });
    let churn_rev_signed = signed_mls_request(
        &ds2_party.engine,
        &ds2_party.identity,
        DirectRequestKind::Prepare,
        churn_rev_body,
    )?;
    let caller2 = ds2_party.svc.clone().with_audience(&ds2_did);
    let (rev_status, rev_bytes) = caller2
        .post(
            &client,
            &server_b.base_url,
            "blue.catbird.chat.prepareDirectRequest",
            &json!({ "signedRequest": churn_rev_signed }),
            true,
        )
        .await?;
    assert_eq!(rev_status, StatusCode::BAD_REQUEST);
    let rev_val: Value = serde_json::from_slice(&rev_bytes)?;
    assert_eq!(
        rev_val["error"], "PreparationConflict",
        "opposite-direction churn must also be rejected with PreparationConflict under pair owner fence: {rev_val}"
    );

    // Restore declaration back to original home
    declare_chat_authority(&https.root, &ds1_party.svc.did, &ds1_did)?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn c33_two_authority_concurrent_first_sends_and_delivery_retry_e2e() -> anyhow::Result<()> {
    let template = "postgresql://127.0.0.1:5432/catbird_direct_requests_test_20260919";
    anyhow::ensure!(
        std::env::var("REQUEST_TEST_DATABASE_URL").as_deref() == Ok(template),
        "C33 requires the exact guarded local synthetic template"
    );
    anyhow::ensure!(
        psql_value(template, "SELECT to_regclass('chat.protocol_instances') IS NOT NULL")? == "t",
        "guarded synthetic template has no chat schema"
    );

    let did_port = HttpsDidFixture::reserve_port()?;
    let run = Uuid::new_v4().simple().to_string();

    // Use .catbird.blue domain: passes chat.is_bare_did
    let ds1_did = format!("did:web:ds1-{run}.catbird.blue");
    let ds2_did = format!("did:web:ds2-{run}.catbird.blue");
    // Ensure ds1 < ds2 so ds1 (Server A) is the deterministic coordinator min(ds1, ds2)
    anyhow::ensure!(ds1_did < ds2_did, "ds1_did must sort before ds2_did");

    let alice = FederatedParty::new(format!("did:web:alice-{run}.catbird.blue"), "c33-simul-alice", &ds1_did)?;
    let bob = FederatedParty::new(format!("did:web:bob-{run}.catbird.blue"), "c33-simul-bob-1", &ds2_did)?;

    let port_a = reserve_loopback_port()?;
    let port_b = reserve_loopback_port()?;
    let server_a_url = format!("http://127.0.0.1:{port_a}");
    let server_b_url = format!("http://127.0.0.1:{port_b}");

    let home_document = |party: &FederatedParty, endpoint: &str| -> anyhow::Result<Value> {
        let mut doc = party.svc.did_document();
        doc["service"]
            .as_array_mut()
            .context("account DID document services")?
            .push(json!({
                "id": format!("{}#atproto_mls", party.svc.did),
                "type": "AtprotoMLSDeliveryService",
                "serviceEndpoint": endpoint
            }));
        Ok(doc)
    };

    let (ds1_doc, _, _) = ds_did_document(&ds1_did, &server_a_url, 61)?;
    let (ds2_doc, _, _) = ds_did_document(&ds2_did, &server_b_url, 71)?;

    let https = HttpsDidFixture::start(
        did_port,
        &[
            (ds1_did.clone(), ds1_doc),
            (ds2_did.clone(), ds2_doc),
            (alice.svc.did.clone(), home_document(&alice, &server_a_url)?),
            (bob.svc.did.clone(), home_document(&bob, &server_b_url)?),
        ],
    )?;

    declare_chat_authority(&https.root, &alice.svc.did, &ds1_did)?;
    declare_chat_authority(&https.root, &bob.svc.did, &ds2_did)?;

    publish_pds_device_key(&https.root, &alice)?;
    publish_pds_device_key(&https.root, &bob)?;

    let db1_name = format!("catbird_direct_requests_fault_{}", &run[..16]);
    let db2_name = format!("catbird_direct_requests_fault_{}", &run[16..]);

    let server_a = FederatedAuthorityServer::start(&ds1_did, port_a, &db1_name, &https, 61)?;
    let mut server_b = FederatedAuthorityServer::start(&ds2_did, port_b, &db2_name, &https, 71)?;

    alice.seed_into_database(&server_a.database_url)?;
    bob.seed_into_database(&server_b.database_url)?;
    psql_on(&server_a.database_url,
        &format!("INSERT INTO federation_peers(ds_did, status) VALUES('{ds2_did}', 'allow') ON CONFLICT DO NOTHING;"))?;
    psql_on(&server_b.database_url,
        &format!("INSERT INTO federation_peers(ds_did, status) VALUES('{ds1_did}', 'allow') ON CONFLICT DO NOTHING;"))?;

    let client = reqwest::Client::new();

    // C12/C14 on a federated pair. Bob's request R0 is relayed from his home to
    // the coordinator before Alice has published request keys, so it ends in a
    // signed RecipientKeysUnavailable rejection that the coordinator keeps.
    // Phase 2 replays it while Alice's preparation holds the pair.
    let r0_req_id = Uuid::new_v4();
    let r0_convo_id = Uuid::new_v4();
    let r0_first_msg_id = Uuid::new_v4();
    let r0_prepare_signed = signed_mls_request(
        &bob.engine,
        &bob.identity,
        DirectRequestKind::Prepare,
        json!({
            "$type": "blue.catbird.chat.defs#directRequestPreparationBody",
            "signatureDomain": "CATBIRD-DIRECT-REQUEST-PREPARE\0",
            "protocolVersion": "2",
            "actorDid": bob.svc.did,
            "actorDeviceId": bob.svc.device_id.to_string(),
            "keyId": bob.key_id,
            "authGeneration": 1,
            "requestId": r0_req_id.to_string(),
            "firstMessageId": r0_first_msg_id.to_string(),
            "conversationId": r0_convo_id.to_string(),
            "recipientDid": alice.svc.did,
            "origin": { "$type": "blue.catbird.chat.defs#freshDirectOrigin" },
            "profile": "encryptedIntroduction1",
            "idempotencyKey": r0_req_id.to_string(),
            "signedAt": canonical_now()
        }),
    )?;
    let (r0_status, r0_bytes) = bob.svc.post(
        &client,
        &server_b.base_url,
        "blue.catbird.chat.prepareDirectRequest",
        &json!({ "signedRequest": r0_prepare_signed }),
        true,
    ).await?;
    anyhow::ensure!(r0_status == StatusCode::OK, "R0 prepare: {r0_status}: {}", String::from_utf8_lossy(&r0_bytes));
    let r0_outcome: Value = serde_json::from_slice(&r0_bytes)?;
    anyhow::ensure!(
        receipt_code(&r0_outcome, &server_a.did, &server_a.receipt_public_key)?.as_deref() == Some("RecipientKeysUnavailable"),
        "R0 must end in the coordinator's signed RecipientKeysUnavailable rejection: {r0_outcome}"
    );
    assert_eq!(
        psql_value(&server_a.database_url, &format!("SELECT status FROM chat.direct_request_attempts WHERE request_id='{r0_req_id}'"))?,
        "rejected",
        "the coordinator keeps R0's rejection"
    );

    // C33 on the relay path. The coordinator chooses itself from Alice's
    // declaration and its repository reads the declaration again. When it
    // moves in between to an authority other than the coordinator, clients
    // check receipts against min(Bob's home, that authority), so the
    // coordinator signs nothing and Bob's home answers unsigned.
    let moved_req_id = Uuid::new_v4();
    let moved_prepare = signed_mls_request(
        &bob.engine,
        &bob.identity,
        DirectRequestKind::Prepare,
        json!({
            "$type": "blue.catbird.chat.defs#directRequestPreparationBody",
            "signatureDomain": "CATBIRD-DIRECT-REQUEST-PREPARE\0",
            "protocolVersion": "2",
            "actorDid": bob.svc.did,
            "actorDeviceId": bob.svc.device_id.to_string(),
            "keyId": bob.key_id,
            "authGeneration": 1,
            "requestId": moved_req_id.to_string(),
            "firstMessageId": Uuid::new_v4().to_string(),
            "conversationId": Uuid::new_v4().to_string(),
            "recipientDid": alice.svc.did,
            "origin": { "$type": "blue.catbird.chat.defs#freshDirectOrigin" },
            "profile": "encryptedIntroduction1",
            "idempotencyKey": moved_req_id.to_string(),
            "signedAt": canonical_now()
        }),
    )?;
    let barrier = PairLockBarrier::hold(&server_a.database_url, &bob.svc.did, &alice.svc.did).await?;
    let mover = async {
        barrier.wait_for_router().await?;
        declare_chat_authority(&https.root, &alice.svc.did, "did:web:chat.federated-peer.org")?;
        barrier.release().await
    };
    let moved_body = json!({ "signedRequest": moved_prepare });
    let ((moved_status, moved_bytes), ()) = tokio::try_join!(
        bob.svc.post(
            &client,
            &server_b.base_url,
            "blue.catbird.chat.prepareDirectRequest",
            &moved_body,
            true,
        ),
        mover,
    )?;
    declare_chat_authority(&https.root, &alice.svc.did, &ds1_did)?;
    let moved: Value = serde_json::from_slice(&moved_bytes).unwrap_or(Value::Null);
    anyhow::ensure!(
        moved_status == StatusCode::BAD_REQUEST && moved.get("outcome").is_none(),
        "a request whose recipient moved must get no receipt: {moved_status}: {}",
        String::from_utf8_lossy(&moved_bytes)
    );
    assert_eq!(
        psql_count(&server_a.database_url, &format!(
            "SELECT count(*) FROM chat.direct_request_attempts WHERE request_id='{moved_req_id}'"
        ))?,
        0,
        "the coordinator keeps no attempt for the moved request"
    );

    // Publish direct request keys on home servers:
    // Alice on Server A:
    let (a_key_status, a_key_bytes) = alice.svc.post(
        &client,
        &server_a.base_url,
        "blue.catbird.chat.publishDirectRequestKeys",
        &alice.key_entry()?,
        true,
    ).await?;
    anyhow::ensure!(a_key_status == StatusCode::OK, "Alice key publish failed: {a_key_status}: {}", String::from_utf8_lossy(&a_key_bytes));

    // Bob Device 1 on Server B:
    let (b_key_status, b_key_bytes) = bob.svc.post(
        &client,
        &server_b.base_url,
        "blue.catbird.chat.publishDirectRequestKeys",
        &bob.key_entry()?,
        true,
    ).await?;
    anyhow::ensure!(b_key_status == StatusCode::OK, "Bob Dev 1 key publish failed: {b_key_status}: {}", String::from_utf8_lossy(&b_key_bytes));
    // Bob Device 2 does NOT publish keys; it remains an unaddressed sibling device.

    // -------------------------------------------------------------------------
    // Phase 1: Simultaneous Alice->Bob and Bob->Alice first sends (Crossed Starts)
    // -------------------------------------------------------------------------
    let alice_req_id = Uuid::new_v4();
    let alice_first_msg_id = Uuid::new_v4();
    let alice_convo_id = Uuid::new_v4();

    let bob_req_id = Uuid::new_v4();
    let bob_first_msg_id = Uuid::new_v4();
    let bob_convo_id = Uuid::new_v4();

    let alice_prepare_body = json!({
        "$type": "blue.catbird.chat.defs#directRequestPreparationBody",
        "signatureDomain": "CATBIRD-DIRECT-REQUEST-PREPARE\0",
        "protocolVersion": "2",
        "actorDid": alice.svc.did,
        "actorDeviceId": alice.svc.device_id.to_string(),
        "keyId": alice.key_id,
        "authGeneration": 1,
        "requestId": alice_req_id.to_string(),
        "firstMessageId": alice_first_msg_id.to_string(),
        "conversationId": alice_convo_id.to_string(),
        "recipientDid": bob.svc.did,
        "origin": { "$type": "blue.catbird.chat.defs#freshDirectOrigin" },
        "profile": "encryptedIntroduction1",
        "idempotencyKey": alice_req_id.to_string(),
        "signedAt": canonical_now()
    });

    let bob_prepare_body = json!({
        "$type": "blue.catbird.chat.defs#directRequestPreparationBody",
        "signatureDomain": "CATBIRD-DIRECT-REQUEST-PREPARE\0",
        "protocolVersion": "2",
        "actorDid": bob.svc.did,
        "actorDeviceId": bob.svc.device_id.to_string(),
        "keyId": bob.key_id,
        "authGeneration": 1,
        "requestId": bob_req_id.to_string(),
        "firstMessageId": bob_first_msg_id.to_string(),
        "conversationId": bob_convo_id.to_string(),
        "recipientDid": alice.svc.did,
        "origin": { "$type": "blue.catbird.chat.defs#freshDirectOrigin" },
        "profile": "encryptedIntroduction1",
        "idempotencyKey": bob_req_id.to_string(),
        "signedAt": canonical_now()
    });

    let alice_prepare_signed = signed_mls_request(
        &alice.engine,
        &alice.identity,
        DirectRequestKind::Prepare,
        alice_prepare_body.clone(),
    )?;

    let bob_prepare_signed = signed_mls_request(
        &bob.engine,
        &bob.identity,
        DirectRequestKind::Prepare,
        bob_prepare_body.clone(),
    )?;

    // Synchronize concurrent submission through a tokio Barrier
    let barrier = Arc::new(tokio::sync::Barrier::new(2));
    let alice_task = {
        let gate = barrier.clone();
        let svc = alice.svc.clone();
        let client = client.clone();
        let home = server_a.base_url.clone();
        let signed = alice_prepare_signed.clone();
        tokio::spawn(async move {
            gate.wait().await;
            svc.post(&client, &home, "blue.catbird.chat.prepareDirectRequest",
                &json!({ "signedRequest": signed }), true).await
        })
    };
    let bob_task = {
        let gate = barrier.clone();
        let svc = bob.svc.clone();
        let client = client.clone();
        let home = server_b.base_url.clone();
        let signed = bob_prepare_signed.clone();
        tokio::spawn(async move {
            gate.wait().await;
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
            svc.post(&client, &home, "blue.catbird.chat.prepareDirectRequest",
                &json!({ "signedRequest": signed }), true).await
        })
    };

    let (alice_prep_res, bob_prep_res) = tokio::try_join!(alice_task, bob_task)?;
    let (alice_prep_status, alice_prep_bytes) = alice_prep_res?;
    let (bob_prep_status, bob_prep_bytes) = bob_prep_res?;

    let is_prepared = |status: StatusCode, bytes: &[u8]| -> anyhow::Result<bool> {
        let val: Value = serde_json::from_slice(bytes)?;
        if status == StatusCode::BAD_REQUEST && val["error"] == "PreparationConflict" {
            return Ok(false);
        }
        if status == StatusCode::OK && val.pointer("/outcome/preparation").is_some() {
            return Ok(true);
        }
        if val.pointer("/outcome/receipt").is_some() {
            return Ok(false);
        }
        anyhow::bail!("unexpected prepare outcome {status}: {val}");
    };

    let alice_prepared = is_prepared(alice_prep_status, &alice_prep_bytes)?;
    let bob_prepared = is_prepared(bob_prep_status, &bob_prep_bytes)?;

    assert_eq!(
        u8::from(alice_prepared) + u8::from(bob_prepared),
        1,
        "contended opposite-direction first sends must converge on exactly one preparation"
    );
    anyhow::ensure!(alice_prepared, "fault-injection continuation requires Alice on DS-A to win this staggered race");

    // The losing preparation must not retain an active remote lease.
    let (winner_is_alice, winner_req_id, winner_convo_id, winner_first_msg_id, winner_prep_bytes, winner_prep_body) =
        if alice_prepared {
            assert_eq!(
                psql_count(
                    &server_a.database_url,
                    &format!("SELECT count(*) FROM chat.direct_request_remote_leases WHERE request_id='{bob_req_id}' AND status='active'")
                )?,
                0,
                "losing Bob preparation must not retain an active remote lease"
            );
            (true, alice_req_id, alice_convo_id, alice_first_msg_id, alice_prep_bytes, alice_prepare_body)
        } else {
            assert_eq!(
                psql_count(
                    &server_b.database_url,
                    &format!("SELECT count(*) FROM chat.direct_request_remote_leases WHERE request_id='{alice_req_id}' AND status='active'")
                )?,
                0,
                "losing Alice preparation must not retain an active remote lease"
            );
            (false, bob_req_id, bob_convo_id, bob_first_msg_id, bob_prep_bytes, bob_prepare_body)
        };

    // -------------------------------------------------------------------------
    // Phase 2: Winner First Send with Lost-Peer and Lost-Client-Response Retry
    // -------------------------------------------------------------------------
    let (winner_party, winner_home, recipient_party) = if winner_is_alice {
        (&alice, server_a.base_url.clone(), &bob)
    } else {
        (&bob, server_b.base_url.clone(), &alice)
    };

    let prep_resp: Value = serde_json::from_slice(&winner_prep_bytes)?;
    let raw_preparation = prep_resp.pointer("/outcome/preparation").context("winner preparation")?;
    let preparation = protocol::verify_direct_request_preparation_for_authority(
        &server_a.did, &serde_json::to_vec(raw_preparation)?, &server_a.receipt_public_key
    )?;
    let selected = preparation["selectedDevices"].as_array().context("selected devices")?;
    anyhow::ensure!(selected.len() == 1, "preparation must select exactly one recipient device");
    anyhow::ensure!(
        selected[0]["actorDeviceId"] == recipient_party.svc.device_id.to_string(),
        "selected device must match recipient's primary device (Device 1), never sibling Device 2"
    );

    let context_val = json!({
        "protocolVersion": "2",
        "requestId": winner_req_id.to_string(),
        "firstMessageId": winner_first_msg_id.to_string(),
        "conversationId": winner_convo_id.to_string(),
        "origin": { "$type": "blue.catbird.chat.defs#freshDirectOrigin" },
        "actorDid": winner_party.svc.did,
        "actorDeviceId": winner_party.svc.device_id.to_string(),
        "actorKeyId": winner_party.key_id,
        "recipientDid": recipient_party.svc.did,
        "preparationDigest": preparation["preparationDigest"]
    });

    let verified_prepare = protocol::verify_signed_request(
        DirectRequestKind::Prepare,
        &serde_json::to_vec(if winner_is_alice { &alice_prepare_signed } else { &bob_prepare_signed })?,
        &winner_party.public,
    )?;

    let journal = winner_party.engine.prepare_direct_request(&DirectRequestBootstrapInput {
        draft_id: Uuid::new_v4().to_string(),
        context_json: serde_json::to_vec(&context_val)?,
        group_id: rand::random::<[u8; 32]>().to_vec(),
        generation: 0,
        state_version: 1,
        key_packages: selected
            .iter()
            .map(|device| {
                Ok(STANDARD.decode(
                    device["keyPackage"]["bytes"]["$bytes"]
                        .as_str()
                        .or_else(|| device["keyPackage"]["bytes"].as_str())
                        .context("selected package bytes")?,
                )?)
            })
            .collect::<anyhow::Result<Vec<_>>>()?,
        expected_package_refs: selected
            .iter()
            .map(|device| {
                Ok(STANDARD.decode(
                    device["keyPackage"]["keyPackageRef"]["$bytes"]
                        .as_str()
                        .or_else(|| device["keyPackage"]["keyPackageRef"].as_str())
                        .context("selected package ref")?,
                )?)
            })
            .collect::<anyhow::Result<Vec<_>>>()?,
        authority_import_until: 4_000_000_000,
        preparation_request_digest: *verified_prepare.request_digest(),
        receipt_authority_key: server_a.receipt_public_key.clone(),
        text: "Converged authoritative direct request".into(),
        invitation: None,
        metadata: GroupMetadataV1 {
            version: 1,
            title: String::new(),
            description: String::new(),
            avatar_blob_locator: None,
            avatar_content_type: None,
        },
    })?;

    let bootstrap = &journal.bootstrap;
    let mut publish_body = winner_prep_body.clone();
    publish_body["$type"] = json!("blue.catbird.chat.defs#directRequestPublicationBody");
    publish_body["signatureDomain"] = json!("CATBIRD-DIRECT-REQUEST-PUBLISH\0");
    publish_body["signedAt"] = json!(canonical_now());
    publish_body["preparationDigest"] = preparation["preparationDigest"].clone();
    publish_body["preparationRequestDigest"] = json!(STANDARD.encode(verified_prepare.request_digest()));
    publish_body["contextHash"] = json!(STANDARD.encode(bootstrap.context_hash));
    publish_body["next"] = bootstrap.coordinates.clone();
    publish_body["importUntil"] = json!(
        chrono::DateTime::from_timestamp(bootstrap.import_until as i64, 0)
            .context("MLS final-tree import deadline")?
            .to_rfc3339_opts(chrono::SecondsFormat::Millis, true)
    );

    let artifact = |data: &[u8], content_type: &str| {
        json!({
            "framing": "mlsMessage",
            "contentType": content_type,
            "bytes": STANDARD.encode(data),
            "sha256": STANDARD.encode(Sha256::digest(data))
        })
    };

    let deliveries = selected
        .iter()
        .map(|device| {
            json!({
                "recipientDid": device["actorDid"],
                "recipientDeviceId": device["actorDeviceId"],
                "provenance": {
                    "requestId": winner_req_id.to_string(),
                    "preparationDigest": preparation["preparationDigest"],
                    "contextHash": STANDARD.encode(bootstrap.context_hash),
                    "grantId": device["grant"]["body"]["grantId"],
                    "grantRevision": device["grant"]["body"]["grantRevision"],
                    "keyPackageRef": device["keyPackage"]["keyPackageRef"],
                    "importUntil": publish_body["importUntil"]
                }
            })
        })
        .collect::<Vec<_>>();

    let author = json!({
        "authorDid": winner_party.svc.did,
        "authorDeviceId": winner_party.svc.device_id.to_string(),
        "authorKeyId": winner_party.key_id,
        "signaturePublicKey": STANDARD.encode(&winner_party.public),
        "authGenerationAtOrigin": 1,
        "originTransitionId": winner_req_id.to_string(),
        "originSeq": 1,
        "roleAtOrigin": "admin",
        "deviceStatusAtOrigin": "active"
    });

    let metadata_snapshot = json!({
        "coordinate": metadata_coordinate(&bootstrap.coordinates)?,
        "originTransitionId": winner_req_id.to_string(),
        "metadataVersion": 1,
        "nonce": STANDARD.encode(&bootstrap.metadata_nonce),
        "ciphertext": STANDARD.encode(&bootstrap.metadata_ciphertext),
        "ciphertextSha256": STANDARD.encode(Sha256::digest(&bootstrap.metadata_ciphertext)),
        "ciphertextSize": bootstrap.metadata_ciphertext.len(),
        "authorProof": author
    });

    publish_body["artifacts"] = json!({
        "genesisGroupInfo": artifact(&bootstrap.genesis_group_info, "groupInfo"),
        "addCommit": artifact(&bootstrap.add_commit, "publicMessageCommit"),
        "finalGroupInfo": artifact(&bootstrap.final_group_info, "groupInfo"),
        "welcome": {
            "opaqueWelcome": STANDARD.encode(&bootstrap.welcome),
            "sha256": STANDARD.encode(Sha256::digest(&bootstrap.welcome)),
            "deliveries": deliveries
        },
        "metadataSnapshot": metadata_snapshot,
        "initialCiphertext": STANDARD.encode(&bootstrap.initial_ciphertext)
    });

    let publish_signed = signed_mls_request(
        &winner_party.engine,
        &winner_party.identity,
        DirectRequestKind::Publish,
        publish_body,
    )?;
    winner_party.engine.persist_request_publication(&journal.request_id, &serde_json::to_vec(&publish_signed)?)?;

    // Alice's preparation still holds the pair. A late prepare of R0, and a
    // late publish under R0's identity, replay the coordinator's stored
    // rejection instead of meeting the pair fence. The publish replay reads no
    // PDS either, so it holds with Bob's device key withdrawn from his PDS.
    anyhow::ensure!(winner_is_alice, "R0 replays need Alice's preparation to hold the pair");
    let (late_status, late_bytes) = bob.svc.post(
        &client,
        &server_b.base_url,
        "blue.catbird.chat.prepareDirectRequest",
        &json!({ "signedRequest": r0_prepare_signed }),
        true,
    ).await?;
    anyhow::ensure!(late_status == StatusCode::OK, "late R0 prepare: {late_status}: {}", String::from_utf8_lossy(&late_bytes));
    let late_prepare: Value = serde_json::from_slice(&late_bytes)?;
    assert_eq!(late_prepare["outcome"], r0_outcome["outcome"], "late R0 prepare replays the stored rejection");

    let r0_prepare_digest = *protocol::verify_signed_request(
        DirectRequestKind::Prepare,
        &serde_json::to_vec(&r0_prepare_signed)?,
        &bob.public,
    )?
    .request_digest();
    let mut r0_publish_body = publish_signed["body"].clone();
    r0_publish_body["actorDid"] = json!(bob.svc.did);
    r0_publish_body["actorDeviceId"] = json!(bob.svc.device_id.to_string());
    r0_publish_body["keyId"] = json!(bob.key_id);
    r0_publish_body["recipientDid"] = json!(alice.svc.did);
    r0_publish_body["requestId"] = json!(r0_req_id.to_string());
    r0_publish_body["conversationId"] = json!(r0_convo_id.to_string());
    r0_publish_body["firstMessageId"] = json!(r0_first_msg_id.to_string());
    r0_publish_body["idempotencyKey"] = json!(r0_req_id.to_string());
    r0_publish_body["preparationRequestDigest"] = json!(STANDARD.encode(r0_prepare_digest));
    r0_publish_body["signedAt"] = json!(canonical_now());
    let r0_publish_signed = signed_mls_request(&bob.engine, &bob.identity, DirectRequestKind::Publish, r0_publish_body)?;
    std::fs::write(
        https.root.join("_policy").join("deviceKeys").join(quote(&bob.svc.did)),
        br#"{"records":[]}"#,
    )?;
    let late_pub = bob.svc.post(
        &client,
        &server_b.base_url,
        "blue.catbird.chat.publishDirectRequest",
        &json!({ "signedRequest": r0_publish_signed }),
        true,
    ).await;
    publish_pds_device_key(&https.root, &bob)?;
    let (late_pub_status, late_pub_bytes) = late_pub?;
    anyhow::ensure!(late_pub_status == StatusCode::OK, "late R0 publish: {late_pub_status}: {}", String::from_utf8_lossy(&late_pub_bytes));
    let late_publish: Value = serde_json::from_slice(&late_pub_bytes)?;
    assert_eq!(late_publish["outcome"], r0_outcome["outcome"], "late R0 publish replays the stored rejection");
    assert_eq!(
        psql_value(
            &server_a.database_url,
            &format!(
                "SELECT (SELECT string_agg(status, ',') FROM chat.direct_request_attempts WHERE request_id='{r0_req_id}')||'|'||\
                        (SELECT count(*) FROM chat.direct_request_publications WHERE request_id='{r0_req_id}')"
            )
        )?,
        "rejected|0",
        "R0 replays change nothing on the coordinator"
    );
    assert_eq!(
        psql_count(
            &server_a.database_url,
            &format!("SELECT count(*) FROM chat.direct_request_attempts WHERE request_id='{winner_req_id}' AND status='prepared'")
        )?,
        1,
        "Alice's preparation still holds the pair"
    );

    // C12 for cancels on a federated pair, while Alice's preparation holds
    // it. Bob's cancel of R0 reaches the coordinator and replays its stored
    // rejection. His cancel of R5, which neither DS has seen, leaves the
    // coordinator's tombstone, and a late prepare and a late publish of R5
    // replay it.
    const CANCEL: &str = "blue.catbird.chat.cancelDirectRequestPreparation";
    let (status, r0_cancel) = post_json(
        &bob,
        &client,
        &server_b.base_url,
        CANCEL,
        &signed_cancel(&bob, &r0_prepare_signed)?,
    )
    .await?;
    anyhow::ensure!(status == StatusCode::OK, "R0 cancel {status}: {r0_cancel}");
    authority_receipt(&r0_cancel, &server_a.did, &server_a.receipt_public_key)?;
    assert_eq!(
        bare_bytes(&r0_cancel["outcome"]),
        bare_bytes(&r0_outcome["outcome"]),
        "R0's cancel replays its rejection"
    );
    let r5_id = Uuid::new_v4();
    let r5_prepare = signed_prepare(&bob, &alice.svc.did, r5_id)?;
    let (status, r5_cancel) = post_json(
        &bob,
        &client,
        &server_b.base_url,
        CANCEL,
        &signed_cancel(&bob, &r5_prepare)?,
    )
    .await?;
    anyhow::ensure!(status == StatusCode::OK, "R5 cancel {status}: {r5_cancel}");
    let r5_receipt = authority_receipt(&r5_cancel, &server_a.did, &server_a.receipt_public_key)?;
    assert_eq!(
        r5_receipt["$type"],
        "blue.catbird.chat.defs#directRequestCancelledReceipt"
    );
    let (status, late) = post_json(
        &bob,
        &client,
        &server_b.base_url,
        "blue.catbird.chat.prepareDirectRequest",
        &r5_prepare,
    )
    .await?;
    anyhow::ensure!(status == StatusCode::OK, "late R5 prepare {status}: {late}");
    assert_eq!(
        bare_bytes(&late["outcome"]),
        bare_bytes(&r5_cancel["outcome"]),
        "a late R5 prepare replays the tombstone"
    );
    let mut r5_publish_body = r0_publish_signed["body"].clone();
    for field in [
        "requestId",
        "conversationId",
        "firstMessageId",
        "idempotencyKey",
    ] {
        r5_publish_body[field] = r5_prepare["body"][field].clone();
    }
    r5_publish_body["preparationRequestDigest"] = json!(STANDARD.encode(request_digest(
        &bob,
        DirectRequestKind::Prepare,
        &r5_prepare
    )?));
    r5_publish_body["signedAt"] = json!(canonical_now());
    let r5_publish = signed_mls_request(
        &bob.engine,
        &bob.identity,
        DirectRequestKind::Publish,
        r5_publish_body,
    )?;
    let (status, late) = post_json(
        &bob,
        &client,
        &server_b.base_url,
        "blue.catbird.chat.publishDirectRequest",
        &r5_publish,
    )
    .await?;
    anyhow::ensure!(status == StatusCode::OK, "late R5 publish {status}: {late}");
    assert_eq!(
        bare_bytes(&late["outcome"]),
        bare_bytes(&r5_cancel["outcome"]),
        "a late R5 publish replays the tombstone"
    );
    assert_eq!(
        psql_value(
            &server_a.database_url,
            &format!(
                "SELECT (SELECT string_agg(status, ',') FROM chat.direct_request_attempts WHERE request_id IN ('{r0_req_id}','{r5_id}'))||'|'||\
                        (SELECT count(*) FROM chat.direct_request_publications WHERE request_id IN ('{r0_req_id}','{r5_id}'))"
            )
        )?
        .split('|')
        .map(|part| {
            let mut statuses = part.split(',').collect::<Vec<_>>();
            statuses.sort();
            statuses.join(",")
        })
        .collect::<Vec<_>>()
        .join("|"),
        "cancelled,rejected|0",
        "the coordinator keeps R0's rejection and R5's tombstone and publishes neither"
    );
    assert_eq!(
        psql_count(
            &server_b.database_url,
            &format!("SELECT count(*) FROM chat.direct_request_attempts WHERE request_id IN ('{r0_req_id}','{r5_id}')")
        )?,
        0,
        "Bob's home writes no tombstone of its own"
    );

    // Simulate lost peer: recipient server is killed before publication commits
    server_b._child.0.kill()?;
    server_b._child.0.wait()?;

    // Simulate lost client response: transport drops response after server commits
    let mut transport = DeterministicFaultTransport::default()
        .fail_on(FaultBoundary::AfterRequestBeforeResponse, 1)?;
    let mut headers = reqwest::header::HeaderMap::new();
    headers.insert(
        reqwest::header::AUTHORIZATION,
        format!("Bearer {}", winner_party.svc.scoped_jwt_with_jti(
            "blue.catbird.chat.publishDirectRequest", Uuid::new_v4()
        )).parse()?,
    );
    let fault_client = reqwest::Client::builder().default_headers(headers).build()?;
    let lost = transport.post_json(
        &fault_client,
        &format!("{winner_home}/xrpc/blue.catbird.chat.publishDirectRequest"),
        &json!({ "signedRequest": publish_signed }),
    ).await.expect_err("publication response must be lost after server commits");
    anyhow::ensure!(
        lost.to_string().contains("AfterRequestBeforeResponse"),
        "unexpected transport failure: {lost:#}"
    );

    // Assert coordinator committed exactly once despite lost client response
    assert_eq!(
        psql_count(
            &server_a.database_url,
            &format!("SELECT count(*) FROM chat.direct_request_publications WHERE request_id='{winner_req_id}'")
        )?,
        1,
        "publication must be committed on coordinator after lost response"
    );

    // Assert outbound queue holds pending delivery for offline peer
    assert_eq!(
        psql_count(
            &server_a.database_url,
            &format!("SELECT count(*) FROM outbound_queue WHERE id='direct-request-delivery-{winner_req_id}' AND status='pending'")
        )?,
        1,
        "outbound queue must retain pending delivery to offline peer"
    );

    // Restart Server B
    server_b.restart(port_b, &https, 71)?;

    // Trigger retry in outbound queue and wait for automatic delivery
    psql_on(
        &server_a.database_url,
        &format!("UPDATE outbound_queue SET next_retry_at = NOW() WHERE id='direct-request-delivery-{winner_req_id}'"),
    )?;

    let mut auto_delivered = false;
    for _ in 0..100 {
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        let queue_delivered = psql_count(
            &server_a.database_url,
            &format!("SELECT count(*) FROM outbound_queue WHERE id='direct-request-delivery-{winner_req_id}' AND status='delivered'"),
        )?;
        let inbox_delivered = psql_count(
            &server_b.database_url,
            &format!("SELECT count(*) FROM chat.direct_request_transport_inbox WHERE request_id='{winner_req_id}'"),
        )?;
        if queue_delivered == 1 && inbox_delivered == 1 {
            auto_delivered = true;
            break;
        }
    }
    anyhow::ensure!(auto_delivered, "outbound queue delivery to recovered Server B timed out");

    // Idempotent publication replay from winner returns identical published outcome
    let (replay_status, replay_bytes) = winner_party.svc.post(
        &client,
        &winner_home,
        "blue.catbird.chat.publishDirectRequest",
        &json!({ "signedRequest": publish_signed }),
        true,
    ).await?;
    anyhow::ensure!(replay_status == StatusCode::OK, "idempotent publication retry failed: {replay_status}");
    let replay_resp: Value = serde_json::from_slice(&replay_bytes)?;
    let published_receipt = replay_resp.pointer("/outcome").context("published outcome receipt")?.clone();

    winner_party.engine.confirm_request_publication(
        &journal.request_id,
        &serde_json::to_vec(&published_receipt)?,
        &server_a.receipt_public_key,
    ).context("sender native published receipt confirmation")?;

    // -------------------------------------------------------------------------
    // Phase 3: Preserving Single Welcome / Single Package Invariants
    // -------------------------------------------------------------------------
    // Coordinator (Server A) assertions:
    assert_eq!(
        psql_count(
            &server_a.database_url,
            &format!("SELECT count(*) FROM chat.direct_request_publications WHERE request_id='{winner_req_id}'")
        )?,
        1,
        "coordinator must contain exactly one publication for the winning request"
    );
    assert_eq!(
        psql_count(
            &server_a.database_url,
            &format!("SELECT count(*) FROM chat.conversations WHERE conversation_id='{winner_convo_id}'")
        )?,
        1,
        "coordinator must contain exactly one conversation for the winning request"
    );
    assert_eq!(
        psql_count(
            &server_a.database_url,
            &format!(
                "SELECT count(*) FROM chat.conversations WHERE kind='direct' AND direct_did_low=LEAST('{a}','{b}') AND direct_did_high=GREATEST('{a}','{b}')",
                a = alice.svc.did, b = bob.svc.did
            )
        )?,
        1,
        "pair must converge on exactly one authoritative direct conversation"
    );
    assert_eq!(
        psql_count(
            &server_a.database_url,
            &format!("SELECT count(*) FROM chat.direct_request_device_deliveries WHERE request_id='{winner_req_id}'")
        )?,
        1,
        "exactly one device delivery record must be recorded"
    );

    // Recipient Home (Server B) assertions:
    assert_eq!(
        psql_count(
            &server_b.database_url,
            &format!("SELECT count(*) FROM chat.direct_request_transport_inbox WHERE request_id='{winner_req_id}'")
        )?,
        1,
        "recipient home must retain exactly one transport inbox Welcome entry"
    );
    assert_eq!(
        psql_count(
            &server_b.database_url,
            &format!("SELECT count(*) FROM chat.key_packages WHERE owner_did='{}' AND status='consumed'", bob.svc.did)
        )?,
        1,
        "retry and peer recovery must preserve single consumed key package, no package draining"
    );

    // Bob Device 1 (addressed primary device):
    let (inv_status, inv_bytes) = bob.svc.get(
        &client,
        &server_b.base_url,
        "blue.catbird.chat.getConversations",
        &[
            ("supportedProtocolVersions".into(), "1".into()),
            ("supportedProtocolVersions".into(), "2".into()),
        ],
    ).await?;
    assert_eq!(inv_status, StatusCode::OK);
    let inventory: Value = serde_json::from_slice(&inv_bytes)?;
    let inventory_session = inventory["inventorySessionId"].as_str().context("missing recipient inventory session")?;

    let (welcomes_status, welcomes_bytes) = bob.svc.get(
        &client,
        &server_b.base_url,
        "blue.catbird.chat.getPendingWelcomes",
        &[
            ("inventorySessionId".into(), inventory_session.into()),
            ("limit".into(), "10".into()),
            ("supportedProtocolVersions".into(), "1".into()),
            ("supportedProtocolVersions".into(), "2".into()),
        ],
    ).await?;
    assert_eq!(welcomes_status, StatusCode::OK);
    let welcomes_resp: Value = serde_json::from_slice(&welcomes_bytes)?;
    let welcome_item = welcomes_resp["items"].as_array().context("items")?
        .iter()
        .find(|item| item["welcomeId"] == winner_req_id.to_string())
        .context("Bob Dev 1 must receive pending Welcome on Server B")?;

    let delivered_welcome = STANDARD.decode(
        welcome_item["opaqueWelcome"]["$bytes"].as_str()
            .or_else(|| welcome_item["opaqueWelcome"].as_str())
            .context("missing delivered welcome bytes")?
    )?;
    assert!(!delivered_welcome.is_empty(), "delivered welcome must not be empty");

    let (entry_status, entry_bytes) = bob.svc.get(
        &client,
        &server_b.base_url,
        "blue.catbird.chat.getEntries",
        &[
            ("conversationId".into(), winner_convo_id.to_string()),
            ("afterSeq".into(), "0".into()),
            ("limit".into(), "10".into()),
        ],
    ).await?;
    assert_eq!(entry_status, StatusCode::OK);
    let entry_page: Value = serde_json::from_slice(&entry_bytes)?;
    let introduction_entry = entry_page["entries"].as_array().context("Bob entries")?
        .iter()
        .find(|entry| entry["seq"] == 1)
        .context("signed introduction entry seq 1 must be present for Bob Dev 1")?;

    let remote_publication = introduction_entry["signedRequest"].clone();
    let (outcome_status, outcome_bytes) = bob.svc.get(
        &client,
        &server_b.base_url,
        "blue.catbird.chat.getDirectRequestOutcome",
        &[("requestId".into(), winner_req_id.to_string())],
    ).await?;
    assert_eq!(outcome_status, StatusCode::OK);
    let remote_receipt = serde_json::from_slice::<Value>(&outcome_bytes)?["outcome"].clone();

    let wire_bytes = |value: &Value| -> anyhow::Result<Vec<u8>> {
        Ok(STANDARD.decode(
            value.as_str().or_else(|| value["$bytes"].as_str())
                .context("missing delivered byte field")?,
        )?)
    };

    let delivered_bootstrap = DirectRequestBootstrap {
        context_json: serde_json::to_vec(&context_val)?,
        context_hash: wire_bytes(&remote_publication["body"]["contextHash"])?.try_into()
            .map_err(|_| anyhow::anyhow!("invalid delivered context hash"))?,
        coordinates: bootstrap.coordinates.clone(),
        import_until: chrono::DateTime::parse_from_rfc3339(
            remote_publication["body"]["importUntil"].as_str().context("missing import deadline")?
        )?.timestamp().try_into()?,
        expected_package_refs: remote_publication["body"]["artifacts"]["welcome"]["deliveries"]
            .as_array().context("deliveries")?.iter()
            .map(|delivery| wire_bytes(&delivery["provenance"]["keyPackageRef"]))
            .collect::<anyhow::Result<Vec<_>>>()?,
        genesis_group_info: wire_bytes(&remote_publication["body"]["artifacts"]["genesisGroupInfo"]["bytes"])?,
        add_commit: wire_bytes(&remote_publication["body"]["artifacts"]["addCommit"]["bytes"])?,
        final_group_info: wire_bytes(&remote_publication["body"]["artifacts"]["finalGroupInfo"]["bytes"])?,
        welcome: delivered_welcome,
        metadata_nonce: wire_bytes(&remote_publication["body"]["artifacts"]["metadataSnapshot"]["nonce"])?,
        metadata_ciphertext: wire_bytes(&remote_publication["body"]["artifacts"]["metadataSnapshot"]["ciphertext"])?,
        initial_ciphertext: wire_bytes(&remote_publication["body"]["artifacts"]["initialCiphertext"])?,
    };

    let welcome_input = DirectRequestWelcomeInput {
        bootstrap: delivered_bootstrap,
        local_identity: bob.identity.as_bytes().to_vec(),
        local_package_ref: wire_bytes(&welcome_item["provenance"]["keyPackageRef"])?,
        publication_request: serde_json::to_vec(&remote_publication)?,
        actor_signature_public_key: winner_party.public.clone(),
        published_receipt: serde_json::to_vec(&remote_receipt)?,
        receipt_authority_did: server_a.did.clone(),
        receipt_authority_key: server_a.receipt_public_key.clone(),
        preparation_request_digest: wire_bytes(&remote_publication["body"]["preparationRequestDigest"])?
            .try_into().map_err(|_| anyhow::anyhow!("invalid preparation digest"))?,
    };

    bob.engine.process_direct_request(&welcome_input).context("recipient native Welcome import")?;
    let decrypted = bob.engine.decrypt_direct_request(&welcome_input).context("recipient native introduction decrypt")?;
    let DirectRequestIntroductionResult::Ready { plaintext } = decrypted else {
        anyhow::bail!("Bob introduction decryption failed: not ready");
    };
    let introduction = protocol::decode_direct_request_introduction(&plaintext).context("recipient canonical introduction decode")?;
    assert_eq!(
        introduction["text"],
        "Converged authoritative direct request",
        "Bob successfully decrypted winner's introduction on Server B"
    );

    // -------------------------------------------------------------------------
    // Phase 5: Acceptance and Bi-Directional MLS Replies
    // -------------------------------------------------------------------------
    let transition_id = Uuid::new_v4();
    let accept_body = json!({
        "$type": "blue.catbird.chat.defs#directRequestAcceptanceBody",
        "signatureDomain": "CATBIRD-DIRECT-REQUEST-ACCEPT\0",
        "protocolVersion": "2",
        "actorDid": bob.svc.did,
        "actorDeviceId": bob.svc.device_id.to_string(),
        "keyId": bob.key_id,
        "authGeneration": 1,
        "requestId": winner_req_id.to_string(),
        "transitionId": transition_id.to_string(),
        "prior": bootstrap.coordinates.clone(),
        "next": {
            "conversationId": winner_convo_id.to_string(),
            "generation": 0,
            "stateVersion": 2,
            "groupId": bootstrap.coordinates["groupId"],
            "epoch": bootstrap.coordinates["epoch"],
            "groupContextHash": bootstrap.coordinates["groupContextHash"],
            "confirmationTag": bootstrap.coordinates["confirmationTag"],
            "lifecycle": "active"
        },
        "invitationProvenance": {
            "invitationTransitionId": winner_req_id.to_string(),
            "invitedByDid": winner_party.svc.did,
            "invitedByDeviceId": winner_party.svc.device_id.to_string()
        },
        "idempotencyKey": transition_id.to_string(),
        "signedAt": canonical_now()
    });

    let accept_signed = signed_mls_request(
        &bob.engine,
        &bob.identity,
        DirectRequestKind::Accept,
        accept_body.clone(),
    )?;

    let (accept_status, accept_bytes) = bob.svc.post(
        &client,
        &server_b.base_url,
        "blue.catbird.chat.acceptConversation",
        &json!({ "directRequest": accept_signed }),
        true,
    ).await?;
    anyhow::ensure!(accept_status == StatusCode::OK, "acceptConversation failed: {accept_status}: {}", String::from_utf8_lossy(&accept_bytes));
    let accept_resp: Value = serde_json::from_slice(&accept_bytes)?;

    // Parent invariant check: recipient home getEntries seq=2 normalized directRequestAcceptanceEntry
    // hash must equal accept_resp.acceptanceProof.entry canonical entry hash
    let (accept_entry_status, accept_entry_bytes) = bob.svc.get(
        &client,
        &server_b.base_url,
        "blue.catbird.chat.getEntries",
        &[
            ("conversationId".into(), winner_convo_id.to_string()),
            ("afterSeq".into(), "1".into()),
            ("limit".into(), "10".into()),
        ],
    ).await?;
    anyhow::ensure!(
        accept_entry_status == StatusCode::OK,
        "recipient home getEntries seq=2 failed {accept_entry_status}: {}",
        String::from_utf8_lossy(&accept_entry_bytes)
    );
    let accept_entry_page: Value = serde_json::from_slice(&accept_entry_bytes)?;
    let fetched_accept_entry = accept_entry_page["entries"]
        .as_array()
        .context("recipient home entries missing after accept")?
        .iter()
        .find(|entry| entry["seq"] == 2)
        .context("recipient home getEntries missing seq=2 acceptance entry")?;
    let proof_entry = accept_resp
        .pointer("/acceptanceProof/entry")
        .context("missing acceptanceProof.entry in accept response")?;
    anyhow::ensure!(fetched_accept_entry.get("acceptanceProof").is_none(),
        "recipient acceptance entry must not embed a proof outside its lexicon");
    let mut proof_entry = proof_entry.clone();
    proof_entry.as_object_mut().context("acceptance proof entry object")?.remove("$type");
    let proof_entry = protocol::normalize_read_presentation(
        &serde_json::to_vec(&proof_entry)?, "directRequestAcceptanceEntry", false)?;
    let mut fetched_entry = protocol::normalize_read_presentation(
        &serde_json::to_vec(fetched_accept_entry)?, "directRequestAcceptanceEntry", true)?;
    fetched_entry.as_object_mut().context("recipient acceptance entry object")?.remove("$type");
    let proof_entry_hash = protocol::direct_request_acceptance_entry_hash(
        &serde_json::to_vec(&proof_entry)?)?;
    let fetched_entry_hash = protocol::direct_request_acceptance_entry_hash(
        &serde_json::to_vec(&fetched_entry)?)?;
    assert_eq!(
        fetched_entry_hash, proof_entry_hash,
        "recipient home getEntries seq=2 normalized directRequestAcceptanceEntry hash must equal accept_resp.acceptanceProof.entry canonical entry hash"
    );

    let group_id_str = bootstrap.coordinates["groupId"]
        .as_str()
        .or_else(|| bootstrap.coordinates["groupId"]["$bytes"].as_str())
        .context("missing groupId in coordinates")?;
    let group_id_bytes = STANDARD.decode(group_id_str)?;
    let epoch = bootstrap.coordinates["epoch"].as_u64().context("missing MLS epoch")?;

    // Bi-directional replies: Bob replies (seq 3), then Alice replies (seq 4)
    for (sender, sender_home, recipient, recipient_home, seq, text) in [
        (&bob, &server_b.base_url, &alice, &server_a.base_url, 3, "Bob's converged reply"),
        (&alice, &server_a.base_url, &bob, &server_b.base_url, 4, "Alice's converged reply"),
    ] {
        let message_id = Uuid::new_v4();
        let mut aad_prior = accept_body["next"].clone();
        aad_prior["conversationId"] = json!(STANDARD.encode(winner_convo_id.as_bytes()));
        let aad = json!({
            "protocolVersion": "1",
            "conversationId": STANDARD.encode(winner_convo_id.as_bytes()),
            "generation": 0,
            "messageId": STANDARD.encode(message_id.as_bytes()),
            "prior": aad_prior
        });
        let plaintext = MLSMessagePayload::text(text).encode()?;
        let ciphertext = sender.engine.encrypt_canonical(
            &group_id_bytes,
            &plaintext,
            canonical_application_aad_bytes(&aad)?,
            epoch,
        )?;
        let body = json!({
            "$type": "blue.catbird.chat.defs#applicationSendBody",
            "signatureDomain": "CATBIRD-CHAT-MESSAGE\0",
            "messageId": message_id.to_string(),
            "actorDid": sender.svc.did,
            "actorDeviceId": sender.svc.device_id.to_string(),
            "keyId": sender.key_id,
            "authGeneration": 1,
            "prior": accept_body["next"],
            "aad": aad,
            "applicationMessage": {
                "framing": "mlsMessage",
                "contentType": "privateMessageApplication",
                "bytes": STANDARD.encode(&ciphertext),
                "sha256": STANDARD.encode(Sha256::digest(&ciphertext))
            },
            "blobBindings": [],
            "signedAt": canonical_now()
        });
        let signed = signed_ordinary(&sender.engine, &sender.identity, body)?;
        let (send_status, send_bytes) = sender.svc.post(
            &client, sender_home, "blue.catbird.chat.sendMessage",
            &json!({ "signedRequest": signed }), true
        ).await?;
        anyhow::ensure!(send_status == StatusCode::OK, "sendMessage failed {send_status}: {}", String::from_utf8_lossy(&send_bytes));

        let (rec_status, rec_bytes) = recipient.svc.get(
            &client, recipient_home, "blue.catbird.chat.getEntries",
            &[
                ("conversationId".into(), winner_convo_id.to_string()),
                ("afterSeq".into(), (seq - 1).to_string()),
                ("limit".into(), "10".into()),
            ],
        ).await?;
        anyhow::ensure!(rec_status == StatusCode::OK, "getEntries for reply failed: {rec_status}");
        let page: Value = serde_json::from_slice(&rec_bytes)?;
        let entry = page["entries"].as_array().context("entries")?
            .iter()
            .find(|e| e["seq"] == seq)
            .context("missing reply entry")?;
        let fetched_b64 = entry.pointer("/signedRequest/body/applicationMessage/bytes")
            .and_then(|v| v.as_str().or_else(|| v["$bytes"].as_str()))
            .context("missing ciphertext")?;
        let authenticated = recipient.engine.decrypt_authenticated(
            &group_id_bytes, &STANDARD.decode(fetched_b64)?
        )?;
        let decoded = MLSMessagePayload::decode(&authenticated.plaintext)?;
        assert_eq!(decoded.display_text(), text, "peer successfully decrypted converged MLS reply");
    }

    Ok(())
}

fn signed_prepare(
    party: &FederatedParty,
    recipient_did: &str,
    request_id: Uuid,
) -> anyhow::Result<Value> {
    signed_mls_request(
        &party.engine,
        &party.identity,
        DirectRequestKind::Prepare,
        json!({
            "$type": "blue.catbird.chat.defs#directRequestPreparationBody",
            "signatureDomain": "CATBIRD-DIRECT-REQUEST-PREPARE\0",
            "protocolVersion": "2",
            "actorDid": party.svc.did,
            "actorDeviceId": party.svc.device_id.to_string(),
            "keyId": party.key_id,
            "authGeneration": 1,
            "requestId": request_id.to_string(),
            "firstMessageId": Uuid::new_v4().to_string(),
            "conversationId": Uuid::new_v4().to_string(),
            "recipientDid": recipient_did,
            "origin": { "$type": "blue.catbird.chat.defs#freshDirectOrigin" },
            "profile": "encryptedIntroduction1",
            "idempotencyKey": request_id.to_string(),
            "signedAt": canonical_now()
        }),
    )
}

fn request_digest(
    party: &FederatedParty,
    kind: DirectRequestKind,
    signed: &Value,
) -> anyhow::Result<[u8; 32]> {
    Ok(
        *protocol::verify_signed_request(kind, &serde_json::to_vec(signed)?, &party.public)?
            .request_digest(),
    )
}

/// `party`'s cancel of the request it signed as `prepare`.
fn signed_cancel(party: &FederatedParty, prepare: &Value) -> anyhow::Result<Value> {
    signed_mls_request(
        &party.engine,
        &party.identity,
        DirectRequestKind::Cancel,
        json!({
            "$type": "blue.catbird.chat.defs#directRequestCancellationBody",
            "signatureDomain": "CATBIRD-DIRECT-REQUEST-CANCEL\0",
            "protocolVersion": "2",
            "actorDid": party.svc.did,
            "actorDeviceId": party.svc.device_id.to_string(),
            "keyId": party.key_id,
            "authGeneration": 1,
            "requestId": prepare["body"]["requestId"],
            "recipientDid": prepare["body"]["recipientDid"],
            "preparationRequestDigest": STANDARD.encode(request_digest(party, DirectRequestKind::Prepare, prepare)?),
            "idempotencyKey": Uuid::new_v4().to_string(),
            "signedAt": canonical_now()
        }),
    )
}

/// A response with `{"$bytes"}` presentations folded to bare base64, so a
/// receipt compares equal however the DS that returned it presented it.
fn bare_bytes(value: &Value) -> Value {
    match value {
        Value::Object(map) if map.len() == 1 && map.get("$bytes").is_some_and(Value::is_string) => {
            map["$bytes"].clone()
        }
        Value::Object(map) => Value::Object(
            map.iter()
                .map(|(k, v)| (k.clone(), bare_bytes(v)))
                .collect(),
        ),
        Value::Array(items) => Value::Array(items.iter().map(bare_bytes).collect()),
        other => other.clone(),
    }
}

/// The receipt in a cancel response, which must be exactly `{"outcome"}`
/// (the client refuses anything else) and verify for `authority`.
fn authority_receipt(response: &Value, authority: &str, key: &[u8]) -> anyhow::Result<Value> {
    anyhow::ensure!(
        response.as_object().is_some_and(|object| object.len() == 1),
        "a cancel answers with the outcome alone: {response}"
    );
    anyhow::ensure!(
        response["outcome"]["$type"] == "blue.catbird.chat.defs#signedDirectRequestReceipt",
        "expected a signed receipt, got {response}"
    );
    let mut signed = response["outcome"].clone();
    signed
        .as_object_mut()
        .context("receipt object")?
        .remove("$type");
    let verified = protocol::verify_received_signed_request_for_authority(
        authority,
        DirectRequestKind::Outcome,
        &serde_json::to_vec(&signed)?,
        key,
    )?;
    Ok(verified.body()["receipt"].clone())
}

async fn post_json(
    party: &FederatedParty,
    client: &reqwest::Client,
    base_url: &str,
    nsid: &str,
    signed: &Value,
) -> anyhow::Result<(StatusCode, Value)> {
    let (status, bytes) = party
        .svc
        .post(
            client,
            base_url,
            nsid,
            &json!({ "signedRequest": signed }),
            true,
        )
        .await?;
    Ok((
        status,
        serde_json::from_slice(&bytes).unwrap_or(Value::Null),
    ))
}

/// C33 cancel on a federated pair. A sender's cancel reaches the pair's
/// coordinator through the sender's home, and the coordinator signs it: the
/// client checks the receipt against the coordinator it pinned. The cancel
/// releases the pair, replays after the PDS withdraws the key, gives back a remote
/// reservation when the coordinator is the sender's own home, and still gets
/// the coordinator's stored answer from a coordinator that predates it.
#[tokio::test(flavor = "multi_thread")]
async fn c33_two_authority_relayed_cancel_e2e() -> anyhow::Result<()> {
    let template = "postgresql://127.0.0.1:5432/catbird_direct_requests_test_20260919";
    anyhow::ensure!(
        std::env::var("REQUEST_TEST_DATABASE_URL").as_deref() == Ok(template),
        "C33 requires the exact guarded local synthetic template"
    );

    let did_port = HttpsDidFixture::reserve_port()?;
    let run = Uuid::new_v4().simple().to_string();
    let ds1_did = format!("did:web:ds1-{run}.catbird.blue");
    let ds2_did = format!("did:web:ds2-{run}.catbird.blue");
    anyhow::ensure!(ds1_did < ds2_did, "ds1 must be the pair coordinator");

    // Alice is homed on the coordinator; Bob and Carol on the other DS.
    let alice = FederatedParty::new(
        format!("did:web:alice-{run}.catbird.blue"),
        "c33-cancel-alice",
        &ds1_did,
    )?;
    let bob = FederatedParty::new(
        format!("did:web:bob-{run}.catbird.blue"),
        "c33-cancel-bob",
        &ds2_did,
    )?;
    let carol = FederatedParty::new(
        format!("did:web:carol-{run}.catbird.blue"),
        "c33-cancel-carol",
        &ds2_did,
    )?;

    let port_a = reserve_loopback_port()?;
    let port_b = reserve_loopback_port()?;
    let server_a_url = format!("http://127.0.0.1:{port_a}");
    let server_b_url = format!("http://127.0.0.1:{port_b}");
    let home_document = |party: &FederatedParty, endpoint: &str| -> anyhow::Result<Value> {
        let mut doc = party.svc.did_document();
        doc["service"]
            .as_array_mut()
            .context("account DID document services")?
            .push(json!({
                "id": format!("{}#atproto_mls", party.svc.did),
                "type": "AtprotoMLSDeliveryService",
                "serviceEndpoint": endpoint
            }));
        Ok(doc)
    };
    let (ds1_doc, _, _) = ds_did_document(&ds1_did, &server_a_url, 81)?;
    let (ds2_doc, _, _) = ds_did_document(&ds2_did, &server_b_url, 91)?;
    let https = HttpsDidFixture::start(
        did_port,
        &[
            (ds1_did.clone(), ds1_doc),
            (ds2_did.clone(), ds2_doc),
            (alice.svc.did.clone(), home_document(&alice, &server_a_url)?),
            (bob.svc.did.clone(), home_document(&bob, &server_b_url)?),
            (carol.svc.did.clone(), home_document(&carol, &server_b_url)?),
        ],
    )?;
    declare_chat_authority(&https.root, &alice.svc.did, &ds1_did)?;
    declare_chat_authority(&https.root, &bob.svc.did, &ds2_did)?;
    declare_chat_authority(&https.root, &carol.svc.did, &ds2_did)?;
    publish_pds_device_key(&https.root, &alice)?;
    publish_pds_device_key(&https.root, &bob)?;
    publish_pds_device_key(&https.root, &carol)?;

    let db1_name = format!("catbird_direct_requests_fault_{}", &run[..16]);
    let db2_name = format!("catbird_direct_requests_fault_{}", &run[16..]);
    let mut server_a = FederatedAuthorityServer::start(&ds1_did, port_a, &db1_name, &https, 81)?;
    let server_b = FederatedAuthorityServer::start(&ds2_did, port_b, &db2_name, &https, 91)?;
    alice.seed_into_database(&server_a.database_url)?;
    bob.seed_into_database(&server_b.database_url)?;
    carol.seed_into_database(&server_b.database_url)?;
    psql_on(&server_a.database_url,
        &format!("INSERT INTO federation_peers(ds_did, status) VALUES('{ds2_did}', 'allow') ON CONFLICT DO NOTHING;"))?;
    psql_on(&server_b.database_url,
        &format!("INSERT INTO federation_peers(ds_did, status) VALUES('{ds1_did}', 'allow') ON CONFLICT DO NOTHING;"))?;

    let client = reqwest::Client::new();
    let a_db = server_a.database_url.clone();
    let a_count = |sql: String| psql_count(&a_db, &sql);
    let b_count = |sql: String| psql_count(&server_b.database_url, &sql);
    const CANCEL: &str = "blue.catbird.chat.cancelDirectRequestPreparation";
    const PREPARE: &str = "blue.catbird.chat.prepareDirectRequest";

    for (party, home) in [(&alice, &server_a.base_url), (&bob, &server_b.base_url)] {
        let (status, bytes) = party
            .svc
            .post(
                &client,
                home,
                "blue.catbird.chat.publishDirectRequestKeys",
                &party.key_entry()?,
                true,
            )
            .await?;
        anyhow::ensure!(
            status == StatusCode::OK,
            "key publish {status}: {}",
            String::from_utf8_lossy(&bytes)
        );
    }

    // A cancel can be the first either DS hears of a request, from a device
    // the coordinator has never seen. The coordinator authorizes Carol's key
    // against her PDS, mirrors her device and keeps a tombstone; her home
    // keeps only the route, so a late prepare and an outcome read reach the
    // coordinator and get the same tombstone.
    let c1_id = Uuid::new_v4();
    let c1_prepare = signed_prepare(&carol, &alice.svc.did, c1_id)?;
    let c1_cancel = signed_cancel(&carol, &c1_prepare)?;
    let (status, c1_response) =
        post_json(&carol, &client, &server_b.base_url, CANCEL, &c1_cancel).await?;
    anyhow::ensure!(
        status == StatusCode::OK,
        "cold cancel {status}: {c1_response}"
    );
    let c1_receipt = authority_receipt(&c1_response, &server_a.did, &server_a.receipt_public_key)?;
    assert_eq!(
        c1_receipt["$type"],
        "blue.catbird.chat.defs#directRequestCancelledReceipt"
    );
    assert_eq!(c1_receipt["requestKind"], "cancel");
    assert_eq!(
        c1_receipt["requestDigest"],
        STANDARD.encode(request_digest(
            &carol,
            DirectRequestKind::Cancel,
            &c1_cancel
        )?)
    );
    assert_eq!(
        c1_receipt["preparationRequestDigest"],
        STANDARD.encode(request_digest(
            &carol,
            DirectRequestKind::Prepare,
            &c1_prepare
        )?)
    );
    assert_eq!(
        psql_value(&server_a.database_url, &format!(
            "SELECT (SELECT status FROM chat.direct_request_attempts WHERE request_id='{c1_id}')||'|'||\
                    (SELECT device_name FROM chat.devices WHERE user_did='{}' AND device_id='{}')",
            carol.svc.did, carol.svc.device_id
        ))?,
        "cancelled|federated-sender",
        "the coordinator keeps the tombstone and mirrors Carol's device"
    );
    assert_eq!(
        b_count(format!(
            "SELECT (SELECT count(*) FROM chat.direct_request_attempts WHERE request_id='{c1_id}') + \
                    (SELECT count(*) FROM chat.direct_request_retained_charges WHERE request_id='{c1_id}')"
        ))?,
        0,
        "the sender's home signs and charges nothing for a request it routed"
    );
    assert_eq!(
        b_count(format!(
            "SELECT count(*) FROM chat.direct_request_outbound_routes WHERE request_id='{c1_id}' AND coordinator_did='{ds1_did}'"
        ))?,
        1,
        "Carol's home routes the request to the coordinator"
    );
    let (status, late) =
        post_json(&carol, &client, &server_b.base_url, PREPARE, &c1_prepare).await?;
    anyhow::ensure!(
        status == StatusCode::OK,
        "late prepare after a cold cancel {status}: {late}"
    );
    assert_eq!(
        bare_bytes(&late["outcome"]),
        bare_bytes(&c1_response["outcome"]),
        "a late prepare replays the tombstone"
    );
    let (status, outcome_bytes) = carol
        .svc
        .get(
            &client,
            &server_b.base_url,
            "blue.catbird.chat.getDirectRequestOutcome",
            &[("requestId".into(), c1_id.to_string())],
        )
        .await?;
    anyhow::ensure!(
        status == StatusCode::OK,
        "outcome read {status}: {}",
        String::from_utf8_lossy(&outcome_bytes)
    );
    let outcome: Value = serde_json::from_slice(&outcome_bytes)?;
    assert_eq!(
        bare_bytes(&outcome["outcome"]),
        bare_bytes(&c1_response["outcome"]),
        "the outcome read returns the tombstone"
    );

    // Carol's home rebinds her device. The coordinator mirrored it at the
    // first generation, and the home now vouches for the second, which the
    // coordinator records before it checks her next cancel.
    psql_on(&server_b.database_url, &format!(
        "UPDATE chat.devices SET auth_generation=2, dpop_jkt=translate(rtrim(encode(sha256(random()::text::bytea),'base64'),'='),'+/','-_'), updated_at=now() \
         WHERE user_did='{}' AND device_id='{}';",
        carol.svc.did, carol.svc.device_id
    ))?;
    let c2_id = Uuid::new_v4();
    let mut c2_body =
        signed_cancel(&carol, &signed_prepare(&carol, &alice.svc.did, c2_id)?)?["body"].clone();
    c2_body["authGeneration"] = json!(2);
    let c2_cancel = signed_mls_request(
        &carol.engine,
        &carol.identity,
        DirectRequestKind::Cancel,
        c2_body,
    )?;
    let (status, c2_response) =
        post_json(&carol, &client, &server_b.base_url, CANCEL, &c2_cancel).await?;
    anyhow::ensure!(
        status == StatusCode::OK,
        "cancel after a device rebind {status}: {c2_response}"
    );
    let c2_receipt = authority_receipt(&c2_response, &server_a.did, &server_a.receipt_public_key)?;
    assert_eq!(
        c2_receipt["$type"],
        "blue.catbird.chat.defs#directRequestCancelledReceipt"
    );
    assert_eq!(
        psql_value(&server_a.database_url, &format!(
            "SELECT (SELECT status FROM chat.direct_request_attempts WHERE request_id='{c2_id}')||'|'||\
                    (SELECT auth_generation FROM chat.devices WHERE user_did='{}' AND device_id='{}')",
            carol.svc.did, carol.svc.device_id
        ))?,
        "cancelled|2",
        "the coordinator mirrors the rebound generation"
    );

    // While the recipient's declaration cannot be read, Carol's home cannot
    // tell which coordinator her client pinned, so it signs nothing and keeps
    // nothing, for a recipient homed with her as for one homed elsewhere.
    // Once the read succeeds, the same cancel is answered by that coordinator.
    let carol_cancel = |recipient: &str, id: Uuid| -> anyhow::Result<Value> {
        let mut body =
            signed_cancel(&carol, &signed_prepare(&carol, recipient, id)?)?["body"].clone();
        body["authGeneration"] = json!(2);
        signed_mls_request(
            &carol.engine,
            &carol.identity,
            DirectRequestKind::Cancel,
            body,
        )
    };
    let declarations = https.root.join("_policy").join("catbirdDeclaration");
    for (recipient, authority, coordinator) in
        [(&bob, &ds2_did, &server_b), (&alice, &ds1_did, &server_a)]
    {
        let id = Uuid::new_v4();
        let cancel = carol_cancel(&recipient.svc.did, id)?;
        std::fs::write(declarations.join(quote(&recipient.svc.did)), b"[]")?;
        let outage = post_json(&carol, &client, &server_b.base_url, CANCEL, &cancel).await;
        declare_chat_authority(&https.root, &recipient.svc.did, authority)?;
        let (status, unanswered) = outage?;
        anyhow::ensure!(
            status != StatusCode::OK && unanswered.get("outcome").is_none(),
            "a cancel during an outage stays unanswered: {status}: {unanswered}"
        );
        assert_eq!(
            b_count(format!(
                "SELECT (SELECT count(*) FROM chat.direct_request_attempts WHERE request_id='{id}') + \
                        (SELECT count(*) FROM chat.direct_request_outbound_routes WHERE request_id='{id}')"
            ))?,
            0,
            "Carol's home keeps nothing for a cancel it could not route"
        );
        let (status, response) =
            post_json(&carol, &client, &server_b.base_url, CANCEL, &cancel).await?;
        anyhow::ensure!(
            status == StatusCode::OK,
            "the same cancel after the outage {status}: {response}"
        );
        let receipt =
            authority_receipt(&response, &coordinator.did, &coordinator.receipt_public_key)?;
        assert_eq!(
            receipt["$type"],
            "blue.catbird.chat.defs#directRequestCancelledReceipt"
        );
    }
    // A sender without a declaration has a client that pins the canonical
    // authority, which Carol's home is not, so it signs nothing for her.
    let id = Uuid::new_v4();
    std::fs::remove_file(declarations.join(quote(&carol.svc.did)))?;
    let undeclared = post_json(
        &carol,
        &client,
        &server_b.base_url,
        CANCEL,
        &carol_cancel(&bob.svc.did, id)?,
    )
    .await;
    declare_chat_authority(&https.root, &carol.svc.did, &ds2_did)?;
    let (status, unanswered) = undeclared?;
    anyhow::ensure!(
        status != StatusCode::OK && unanswered.get("outcome").is_none(),
        "an undeclared sender's cancel on a non-canonical DS stays unanswered: {status}: {unanswered}"
    );
    assert_eq!(
        b_count(format!(
            "SELECT count(*) FROM chat.direct_request_attempts WHERE request_id='{id}'"
        ))?,
        0
    );

    // Bob's request R is relayed to the coordinator and holds the pair, so
    // Alice cannot start her own.
    let r_id = Uuid::new_v4();
    let r_prepare = signed_prepare(&bob, &alice.svc.did, r_id)?;
    let (status, prepared) =
        post_json(&bob, &client, &server_b.base_url, PREPARE, &r_prepare).await?;
    anyhow::ensure!(
        status == StatusCode::OK
            && prepared["outcome"]["$type"]
                == "blue.catbird.chat.defs#directRequestPreparedOutcome",
        "R prepare {status}: {prepared}"
    );
    let a_id = Uuid::new_v4();
    let a_prepare = signed_prepare(&alice, &bob.svc.did, a_id)?;
    let (status, fenced) =
        post_json(&alice, &client, &server_a.base_url, PREPARE, &a_prepare).await?;
    anyhow::ensure!(
        status != StatusCode::OK
            && fenced.get("outcome").is_none()
            && fenced["error"] == "PreparationConflict",
        "R holds the pair: {status}: {fenced}"
    );

    // Bob cancels R at his home, and the coordinator signs the cancellation.
    let r_cancel = signed_cancel(&bob, &r_prepare)?;
    let (status, r_response) =
        post_json(&bob, &client, &server_b.base_url, CANCEL, &r_cancel).await?;
    anyhow::ensure!(
        status == StatusCode::OK,
        "relayed cancel {status}: {r_response}"
    );
    let r_receipt = authority_receipt(&r_response, &server_a.did, &server_a.receipt_public_key)?;
    assert_eq!(
        r_receipt["$type"],
        "blue.catbird.chat.defs#directRequestCancelledReceipt"
    );
    assert_eq!(
        r_receipt["requestDigest"],
        STANDARD.encode(request_digest(&bob, DirectRequestKind::Cancel, &r_cancel)?)
    );
    assert_eq!(
        psql_value(&server_a.database_url, &format!(
            "SELECT (SELECT status FROM chat.direct_request_attempts WHERE request_id='{r_id}')||'|'||\
                    (SELECT count(*) FROM chat.direct_request_publications WHERE request_id='{r_id}')||'|'||\
                    (SELECT count(*) FROM outbound_queue WHERE id='direct-request-delivery-{r_id}')||'|'||\
                    (SELECT count(*) FROM chat.direct_request_retained_charges WHERE request_id='{r_id}')"
        ))?,
        "cancelled|0|0|1",
        "the coordinator cancels R and publishes nothing"
    );
    assert_eq!(
        psql_value(&server_b.database_url, &format!(
            "SELECT (SELECT count(*) FROM chat.direct_request_attempts WHERE request_id='{r_id}')||'|'||\
                    (SELECT count(*) FROM chat.direct_request_outbound_routes WHERE request_id='{r_id}')||'|'||\
                    (SELECT count(*) FROM chat.direct_request_transport_inbox WHERE request_id='{r_id}')"
        ))?,
        "0|1|0",
        "Bob's home writes no tombstone of its own"
    );

    // Replays get the same receipt and charge nothing more: the same bytes,
    // a cancel signed again, and one sent after Bob's PDS stops listing his
    // key, since the coordinator already holds his device.
    let charge = |id: Uuid| {
        psql_value(&a_db, &format!(
            "SELECT count(*)||'|'||encode((SELECT terminal_response_sha256 FROM chat.direct_request_attempts WHERE request_id='{id}'),'hex') \
             FROM chat.direct_request_retained_charges WHERE request_id='{id}'"
        ))
    };
    let r_charge = charge(r_id)?;
    let (status, replay) = post_json(&bob, &client, &server_b.base_url, CANCEL, &r_cancel).await?;
    anyhow::ensure!(status == StatusCode::OK, "cancel replay {status}: {replay}");
    assert_eq!(
        replay, r_response,
        "the same cancel replays the same receipt"
    );
    let (status, resigned) = post_json(
        &bob,
        &client,
        &server_b.base_url,
        CANCEL,
        &signed_cancel(&bob, &r_prepare)?,
    )
    .await?;
    anyhow::ensure!(
        status == StatusCode::OK,
        "re-signed cancel {status}: {resigned}"
    );
    assert_eq!(
        resigned, r_response,
        "a cancel signed again gets the stored receipt"
    );
    let bob_keys = https
        .root
        .join("_policy")
        .join("deviceKeys")
        .join(quote(&bob.svc.did));
    std::fs::write(&bob_keys, br#"{"records":[]}"#)?;
    let without_pds = post_json(&bob, &client, &server_b.base_url, CANCEL, &r_cancel).await;
    publish_pds_device_key(&https.root, &bob)?;
    let (status, without_pds) = without_pds?;
    anyhow::ensure!(
        status == StatusCode::OK,
        "cancel replay without the PDS key {status}: {without_pds}"
    );
    assert_eq!(
        without_pds, r_response,
        "a replay for a mirrored device does not re-read the PDS key list"
    );
    assert_eq!(charge(r_id)?, r_charge, "replays add no retained charge");
    // The receipt authority stays with the attempt. Once Alice's declaration
    // names another authority, Bob's home still relays to the coordinator it
    // recorded, and the coordinator still answers for the attempt it holds.
    declare_chat_authority(
        &https.root,
        &alice.svc.did,
        "did:web:chat.federated-peer.org",
    )?;
    let moved = post_json(&bob, &client, &server_b.base_url, CANCEL, &r_cancel).await;
    declare_chat_authority(&https.root, &alice.svc.did, &ds1_did)?;
    let (status, moved) = moved?;
    anyhow::ensure!(
        status == StatusCode::OK,
        "cancel replay after a declaration move {status}: {moved}"
    );
    assert_eq!(
        moved, r_response,
        "the recorded coordinator answers after a declaration move"
    );
    let mut wrong = r_cancel["body"].clone();
    wrong["preparationRequestDigest"] = json!(STANDARD.encode([7u8; 32]));
    wrong["signedAt"] = json!(canonical_now());
    let wrong = signed_mls_request(&bob.engine, &bob.identity, DirectRequestKind::Cancel, wrong)?;
    let (status, refused) = post_json(&bob, &client, &server_b.base_url, CANCEL, &wrong).await?;
    anyhow::ensure!(
        status.is_client_error() && refused.get("outcome").is_none(),
        "a cancel of another preparation is refused: {status}: {refused}"
    );

    // The cancellation released the pair: Alice's request now prepares, and
    // reserves Bob's packages on his home.
    let (status, prepared) =
        post_json(&alice, &client, &server_a.base_url, PREPARE, &a_prepare).await?;
    anyhow::ensure!(
        status == StatusCode::OK
            && prepared["outcome"]["$type"]
                == "blue.catbird.chat.defs#directRequestPreparedOutcome",
        "A prepare after the cancel {status}: {prepared}"
    );
    let lease = |id: Uuid| {
        psql_value(&server_b.database_url, &format!(
            "SELECT coalesce(string_agg(status||'@'||coordinator_did, ','), '') FROM chat.direct_request_remote_leases WHERE request_id='{id}'"
        ))
    };
    assert_eq!(
        lease(a_id)?,
        format!("active@{ds1_did}"),
        "the coordinator leases Bob's packages for A"
    );

    // A late prepare of R replays the tombstone while A holds the pair.
    let (status, late) = post_json(&bob, &client, &server_b.base_url, PREPARE, &r_prepare).await?;
    anyhow::ensure!(status == StatusCode::OK, "late R prepare {status}: {late}");
    assert_eq!(
        bare_bytes(&late["outcome"]),
        bare_bytes(&r_response["outcome"]),
        "a late prepare replays the tombstone"
    );

    // The coordinator is Alice's own home, so her cancel is answered there,
    // and it gives Bob's packages back to his home. The attempt her home
    // holds answers even beside a route to another DS, which a prepare retry
    // relayed after a declaration move would have left.
    psql_on(
        &server_a.database_url,
        &format!(
            "INSERT INTO chat.direct_request_outbound_routes \
            (request_id, actor_did, actor_device_id, recipient_did, coordinator_did) \
         VALUES ('{a_id}', '{}', '{}', '{}', '{ds2_did}');",
            alice.svc.did, alice.svc.device_id, bob.svc.did
        ),
    )?;
    let a_cancel = signed_cancel(&alice, &a_prepare)?;
    let (status, a_response) =
        post_json(&alice, &client, &server_a.base_url, CANCEL, &a_cancel).await?;
    anyhow::ensure!(
        status == StatusCode::OK,
        "local cancel {status}: {a_response}"
    );
    let a_receipt = authority_receipt(&a_response, &server_a.did, &server_a.receipt_public_key)?;
    assert_eq!(
        a_receipt["$type"],
        "blue.catbird.chat.defs#directRequestCancelledReceipt"
    );
    assert_eq!(
        lease(a_id)?,
        format!("released@{ds1_did}"),
        "the cancel releases the remote lease"
    );
    assert_eq!(
        a_count(format!(
            "SELECT count(*) FROM chat.direct_request_reservation_intents WHERE request_id='{a_id}' AND status='cancelled'"
        ))?,
        1
    );

    // A coordinator that predates the procedure answers 404. Bob's home then
    // reads the coordinator's stored outcome, which still answers R. For a
    // request the coordinator never saw there is nothing to read, so the
    // cancel stays unanswered and nobody keeps a tombstone.
    server_a.restart_with_env(
        port_a,
        &https,
        81,
        &[("CATBIRD_TEST_DISABLE_MLSDS_CANCEL", "1")],
    )?;
    let (status, old) = post_json(&bob, &client, &server_b.base_url, CANCEL, &r_cancel).await?;
    anyhow::ensure!(
        status == StatusCode::OK,
        "cancel through an old coordinator {status}: {old}"
    );
    assert_eq!(
        old, r_response,
        "the old coordinator's stored outcome answers the cancel"
    );
    let r6_id = Uuid::new_v4();
    let r6_prepare = signed_prepare(&bob, &alice.svc.did, r6_id)?;
    let (status, unanswered) = post_json(
        &bob,
        &client,
        &server_b.base_url,
        CANCEL,
        &signed_cancel(&bob, &r6_prepare)?,
    )
    .await?;
    anyhow::ensure!(
        status == StatusCode::INTERNAL_SERVER_ERROR && unanswered.get("outcome").is_none(),
        "an old coordinator that never saw the request leaves the cancel unanswered: {status}: {unanswered}"
    );
    assert_eq!(
        a_count(format!(
            "SELECT count(*) FROM chat.direct_request_attempts WHERE request_id='{r6_id}'"
        ))?,
        0
    );
    assert_eq!(
        b_count(format!(
            "SELECT count(*) FROM chat.direct_request_attempts WHERE request_id='{r6_id}'"
        ))?,
        0
    );
    Ok(())
}
