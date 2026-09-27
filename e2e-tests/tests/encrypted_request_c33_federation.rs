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
//! 9. Opposite-direction race convergence: concurrent first sends in both directions via barrier converge on single winner.
//! 10. Zero legacy fallback: verify no legacy table (messages, welcome_messages, pending_welcomes) interaction and exact canonical DB graph.
//! 11. Simultaneous Alice→Bob and Bob→Alice first sends converging on one authoritative direct pair.
//! 12. Lost-peer and lost-client-response retry preserving single Welcome/package without package draining or duplication.
//! 13. Exact-device authorization: unaddressed sibling device receives 0 Welcomes and cannot access intro entry, while addressed device imports and decrypts.
//! 14. Recipient home getEntries seq=2 normalized directRequestAcceptanceEntry hash equals accept_resp.acceptanceProof.entry canonical entry hash.
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
    FaultBoundary, HttpsDidFixture, ServiceIdentity,
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

fn bootstrap_federation_tables(db_url: &str) -> anyhow::Result<()> {
    // The guarded chat template deliberately omits the older public federation schema.
    psql_on(
        db_url,
        "CREATE TABLE ds_endpoints( \
            did TEXT PRIMARY KEY, endpoint TEXT NOT NULL, supported_cipher_suites TEXT, \
            resolved_at TIMESTAMPTZ NOT NULL DEFAULT NOW(), \
            expires_at TIMESTAMPTZ NOT NULL DEFAULT NOW() + INTERVAL '1 hour')",
    )?;
    psql_on(
        db_url,
        "CREATE TABLE outbound_queue( \
            id TEXT PRIMARY KEY, target_ds_did TEXT NOT NULL, target_endpoint TEXT NOT NULL, \
            method TEXT NOT NULL, payload BYTEA NOT NULL, convo_id TEXT NOT NULL, \
            created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(), \
            next_retry_at TIMESTAMPTZ NOT NULL DEFAULT NOW(), \
            retry_count INTEGER NOT NULL DEFAULT 0, max_retries INTEGER NOT NULL DEFAULT 5, \
            last_error TEXT, status TEXT NOT NULL DEFAULT 'pending')",
    )?;
    for migration in [
        include_str!("../../server/migrations/20260214000001_federation_peer_policy.sql"),
        include_str!("../../server/migrations/20260214000002_auth_jti_nonce.sql"),
        include_str!("../../server/migrations/20260222000001_federation_peer_policy_audit_log.sql"),
    ] {
        psql_on(db_url, migration)?;
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
        bootstrap_federation_tables(&db_url)?;
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
    let proof_entry_hash = protocol::direct_request_acceptance_entry_hash(
        &serde_json::to_vec(proof_entry)?,
    )?;
    let fetched_entry_hash = protocol::direct_request_acceptance_entry_hash(
        &serde_json::to_vec(fetched_accept_entry)?,
    )?;
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
        let (status, response_bytes) = sender.svc.post(
            &client, sender_home, "blue.catbird.chat.sendMessage",
            &json!({ "signedRequest": signed }), true
        ).await?;
        anyhow::ensure!(status == StatusCode::OK,
            "sendMessage from {} failed {status}: {}",
            sender.svc.did, String::from_utf8_lossy(&response_bytes));
        let response: Value = serde_json::from_slice(&response_bytes)?;
        assert_eq!(response["entry"]["seq"], seq);
        if seq == 3 {
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
        for table in ["messages", "welcome_messages", "pending_welcomes"] {
            assert_eq!(
                psql_value(database_url, &format!("SELECT to_regclass('public.{table}') IS NULL"))?,
                "t",
                "Server {node} must not use a legacy {table} table"
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
async fn c33_two_authority_simultaneous_first_sends_and_device_auth_e2e() -> anyhow::Result<()> {
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
    // Bob Device 2: sibling device with same DID, distinct device_id and keys for exact-device authorization
    let bob_dev2 = FederatedParty::new(bob.svc.did.clone(), "c33-simul-bob-2", &ds2_did)?;
    anyhow::ensure!(
        bob.svc.did == bob_dev2.svc.did && bob.svc.device_id != bob_dev2.svc.device_id,
        "bob_dev2 must be a sibling device on the same account with distinct device ID"
    );

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

    let db1_name = format!("catbird_c33_simul_a_{run}");
    let db2_name = format!("catbird_c33_simul_b_{run}");

    let server_a = FederatedAuthorityServer::start(&ds1_did, port_a, &db1_name, &https, 61)?;
    let mut server_b = FederatedAuthorityServer::start(&ds2_did, port_b, &db2_name, &https, 71)?;

    alice.seed_into_database(&server_a.database_url)?;
    bob.seed_into_database(&server_b.database_url)?;
    bob_dev2.seed_into_database(&server_b.database_url)?;

    let client = reqwest::Client::new();

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
        "simultaneous opposite-direction first sends must converge on exactly one preparation"
    );

    // Verify loser retained 0 active remote leases and cannot publish speculative ciphertext
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

    // The loser must not be able to publish
    let (loser_party, loser_home, loser_req_id, loser_convo_id, loser_first_msg_id) = if winner_is_alice {
        (&bob, &server_b.base_url, bob_req_id, bob_convo_id, bob_first_msg_id)
     } else {
        (&alice, &server_a.base_url, alice_req_id, alice_convo_id, alice_first_msg_id)
    };

    let loser_author = json!({
        "authorDid": loser_party.svc.did,
        "authorDeviceId": loser_party.svc.device_id.to_string(),
        "authorKeyId": loser_party.key_id,
        "signaturePublicKey": STANDARD.encode(&loser_party.public),
        "authGenerationAtOrigin": 1,
        "originTransitionId": loser_req_id.to_string(),
        "originSeq": 1,
        "roleAtOrigin": "admin",
        "deviceStatusAtOrigin": "active"
    });
    let loser_metadata = json!({
        "coordinate": { "conversationId": loser_convo_id.to_string(), "generation": 0, "stateVersion": 1 },
        "originTransitionId": loser_req_id.to_string(),
        "metadataVersion": 1,
        "nonce": STANDARD.encode([0u8; 12]),
        "ciphertext": "",
        "ciphertextSha256": "",
        "ciphertextSize": 0,
        "authorProof": loser_author
    });
    let loser_artifacts = json!({
        "genesisGroupInfo": { "framing": "mlsMessage", "contentType": "groupInfo", "bytes": "", "sha256": "" },
        "addCommit": { "framing": "mlsMessage", "contentType": "publicMessageCommit", "bytes": "", "sha256": "" },
        "finalGroupInfo": { "framing": "mlsMessage", "contentType": "groupInfo", "bytes": "", "sha256": "" },
        "welcome": { "opaqueWelcome": "", "sha256": "", "deliveries": [] },
        "metadataSnapshot": loser_metadata,
        "initialCiphertext": ""
    });
    let loser_next = json!({
        "conversationId": loser_convo_id.to_string(),
        "generation": 0,
        "stateVersion": 1,
        "groupId": STANDARD.encode([0u8; 32]),
        "epoch": 1,
        "groupContextHash": STANDARD.encode([0u8; 32]),
        "confirmationTag": STANDARD.encode([0u8; 32]),
        "lifecycle": "pending"
    });
    let mut loser_publish_body = json!({
        "$type": "blue.catbird.chat.defs#directRequestPublicationBody",
        "signatureDomain": "CATBIRD-DIRECT-REQUEST-PUBLISH\0",
        "protocolVersion": "2",
        "actorDid": loser_party.svc.did,
        "actorDeviceId": loser_party.svc.device_id.to_string(),
        "keyId": loser_party.key_id,
        "authGeneration": 1,
        "requestId": loser_req_id.to_string(),
        "firstMessageId": loser_first_msg_id.to_string(),
        "conversationId": loser_convo_id.to_string(),
        "recipientDid": if winner_is_alice { &alice.svc.did } else { &bob.svc.did },
        "origin": { "$type": "blue.catbird.chat.defs#freshDirectOrigin" },
        "profile": "encryptedIntroduction1",
        "idempotencyKey": loser_req_id.to_string(),
        "preparationDigest": URL_SAFE_NO_PAD.encode([0u8; 32]),
        "preparationRequestDigest": STANDARD.encode([0u8; 32]),
        "contextHash": STANDARD.encode([0u8; 32]),
        "next": loser_next,
        "importUntil": canonical_future(14),
        "signedAt": canonical_now()
    });
    loser_publish_body["artifacts"] = loser_artifacts;

    let speculative_loser_publish = signed_mls_request(
        &loser_party.engine,
        &loser_party.identity,
        DirectRequestKind::Publish,
        loser_publish_body,
    )?;

    let (loser_pub_status, loser_pub_bytes) = loser_party.svc.post(
        &client,
        loser_home,
        "blue.catbird.chat.publishDirectRequest",
        &json!({ "signedRequest": speculative_loser_publish }),
        true,
    ).await?;
    assert_ne!(
        loser_pub_status,
        StatusCode::OK,
        "loser of crossed starts race must not be permitted to publish: {loser_pub_status} {}",
        String::from_utf8_lossy(&loser_pub_bytes)
    );

    // -------------------------------------------------------------------------
    // Phase 2: Winner First Send with Lost-Peer and Lost-Client-Response Retry
    // -------------------------------------------------------------------------
    let (winner_party, winner_home, recipient_party, recipient_home) = if winner_is_alice {
        (&alice, &server_a.base_url, &bob, &server_b.base_url)
    } else {
        (&bob, &server_b.base_url, &alice, &server_a.base_url)
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
        winner_home,
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
    )?;

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

    // -------------------------------------------------------------------------
    // Phase 4: Exact-Device Authorization (Unaddressed Sibling vs Addressed Device)
    // -------------------------------------------------------------------------
    // Bob Device 2 (unaddressed sibling):
    let (dev2_inv_status, dev2_inv_bytes) = bob_dev2.svc.get(
        &client,
        &server_b.base_url,
        "blue.catbird.chat.getConversations",
        &[
            ("supportedProtocolVersions".into(), "1".into()),
            ("supportedProtocolVersions".into(), "2".into()),
        ],
    ).await?;
    assert_eq!(dev2_inv_status, StatusCode::OK);
    let dev2_inv: Value = serde_json::from_slice(&dev2_inv_bytes)?;
    let dev2_session = dev2_inv["inventorySessionId"].as_str().context("missing dev2 session")?;

    let (dev2_welcomes_status, dev2_welcomes_bytes) = bob_dev2.svc.get(
        &client,
        &server_b.base_url,
        "blue.catbird.chat.getPendingWelcomes",
        &[
            ("inventorySessionId".into(), dev2_session.into()),
            ("limit".into(), "10".into()),
            ("supportedProtocolVersions".into(), "1".into()),
            ("supportedProtocolVersions".into(), "2".into()),
        ],
    ).await?;
    assert_eq!(dev2_welcomes_status, StatusCode::OK);
    let dev2_welcomes: Value = serde_json::from_slice(&dev2_welcomes_bytes)?;
    let dev2_items = dev2_welcomes["items"].as_array().context("dev2 items")?;
    assert!(
        dev2_items.iter().find(|item| item["welcomeId"] == winner_req_id.to_string()).is_none(),
        "unaddressed sibling device (Dev 2) must receive ZERO pending Welcomes for this request"
    );

    let (dev2_entry_status, dev2_entry_bytes) = bob_dev2.svc.get(
        &client,
        &server_b.base_url,
        "blue.catbird.chat.getEntries",
        &[
            ("conversationId".into(), winner_convo_id.to_string()),
            ("afterSeq".into(), "0".into()),
            ("limit".into(), "10".into()),
        ],
    ).await?;
    if dev2_entry_status == StatusCode::OK {
        let dev2_page: Value = serde_json::from_slice(&dev2_entry_bytes)?;
        let has_intro = dev2_page["entries"]
            .as_array()
            .map(|entries| entries.iter().any(|e| e["seq"] == 1))
            .unwrap_or(false);
        assert!(!has_intro, "unaddressed sibling device must not receive the introduction entry");
    }

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
        coordinates: remote_publication["body"]["next"].clone(),
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

    bob.engine.process_direct_request(&welcome_input)?;
    let decrypted = bob.engine.decrypt_direct_request(&welcome_input)?;
    let DirectRequestIntroductionResult::Ready { plaintext } = decrypted else {
        anyhow::bail!("Bob introduction decryption failed: not ready");
    };
    let introduction = protocol::decode_direct_request_introduction(&plaintext)?;
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
        "firstMessageId": winner_first_msg_id.to_string(),
        "conversationId": winner_convo_id.to_string(),
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
    let proof_entry_hash = protocol::direct_request_acceptance_entry_hash(
        &serde_json::to_vec(proof_entry)?,
    )?;
    let fetched_entry_hash = protocol::direct_request_acceptance_entry_hash(
        &serde_json::to_vec(fetched_accept_entry)?,
    )?;
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
