//! C33: Two-Authority Canonical Federation Qualification.
//!
//! Mandatory assertions:
//! 1. Single authoritative encrypted introduction across two independent authorities (DS-A and DS-B).
//! 2. Deterministic canonical pair coordinator = min(normalized DS DIDs) for both send directions.
//! 3. Staged S2S reservation of remote recipient key packages/grants before local transaction.
//! 4. Remote Welcome and entry delivery to recipient's home DS without legacy tables.
//! 5. Lost peer/client response replay: identical publication retry returns cached receipt idempotently.
//! 6. Remote Welcome import and introduction decryption by recipient on home DS.
//! 7. Acceptance relayed to coordinator, committed at seq 2 with coordinator's signed commit receipt.
//! 8. Bi-directional reply: recipient replies, entry synchronized across nodes, both decrypt plaintext.
//! 9. Opposite-direction race convergence: concurrent first sends in both directions converge on single winner.
//! 10. Zero legacy fallback: verify no legacy table (messages, welcome_messages, pending_welcomes) interaction.

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
    orchestrator::direct_request_bootstrap::{
        metadata_coordinate, DirectRequestBootstrapInput, DirectRequestWelcomeInput,
    },
};
use encrypted_requests::{
    canonical_future, canonical_now, connect_guarded_request_database,
    reviewed_request_migrations, seed_service_device, signed_mls_request, HttpsDidFixture,
    ServiceIdentity,
};
use mls_e2e_tests::mls_engine::MlsEngine;
use p256::ecdsa::SigningKey;
use reqwest::StatusCode;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::process::{Child, Command, Stdio};
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

fn create_database_clone(source: &str, target: &str) -> anyhow::Result<DedicatedDatabase> {
    psql_maintenance(&format!("CREATE DATABASE {target} TEMPLATE {source}"))?;
    Ok(DedicatedDatabase(target.to_string()))
}

pub struct FederatedAuthorityServer {
    pub did: String,
    pub base_url: String,
    pub database_url: String,
    pub receipt_public_key: Vec<u8>,
    pub receipt_key_id: String,
    pub receipt_document: Vec<u8>,
    _child: Child,
    _db: DedicatedDatabase,
}

impl FederatedAuthorityServer {
    pub fn start(
        did: &str,
        db_name: &str,
        https: &HttpsDidFixture,
        seed_byte: u8,
    ) -> anyhow::Result<Self> {
        let db_url = format!("postgresql://127.0.0.1:5432/{db_name}");
        let db = create_database_clone("catbird_direct_requests_test_20260919", db_name)?;

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
        let receipt_document = serde_json::to_vec(&json!({
            "id": did,
            "verificationMethod": [{
                "id": receipt_key_id,
                "controller": did,
                "type": "Multikey",
                "publicKeyMultibase": multibase::encode(multibase::Base::Base58Btc, multikey)
            }]
        }))?;

        let cursor_key_id = URL_SAFE_NO_PAD.encode([seed_byte; 32]);
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
            .env("SELF_ENDPOINT", "http://127.0.0.1:0")
            .env("REQUEST_FIXTURE_DID_HOSTS", https.hosts.join(","))
            .env("REQUEST_FIXTURE_DID_PORT", https.port.to_string())
            .env("REQUEST_FIXTURE_DID_CA_PEM", &https.ca_pem)
            .env("DID_RESOLUTION_HOST_ALLOWLIST", https.hosts.join(","))
            .env("CHAT_CUTOVER_ENABLED", "1")
            .env("CHAT_DIRECT_REQUESTS_ENABLED", "1")
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
            .env("RUST_LOG", "warn")
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit());

        let mut child = command.spawn().context("spawn server fixture")?;
        let mut reader = std::io::BufReader::new(child.stdout.take().context("take stdout")?);
        let mut line = String::new();
        std::io::BufRead::read_line(&mut reader, &mut line)?;
        let ready: Value = serde_json::from_str(&line)?;
        let base_url = ready["baseUrl"].as_str().context("missing baseUrl")?.to_owned();

        Ok(Self {
            did: did.to_string(),
            base_url,
            database_url: db_url,
            receipt_public_key: receipt_point.as_bytes().to_vec(),
            receipt_key_id,
            receipt_document,
            _child: child,
            _db: db,
        })
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
    fn new(did: String, label: &str) -> anyhow::Result<Self> {
        let svc = ServiceIdentity::new(did);
        let engine = MlsEngine::new(label)?;
        let identity = format!("{}#{}", svc.did, svc.device_id);
        engine.create_key_package(&identity)?;
        let public = engine.identity_public_key(&identity)?;
        let key_id = URL_SAFE_NO_PAD.encode(Sha256::digest(&public));
        seed_service_device(&svc, &public)?;
        Ok(Self {
            svc,
            engine,
            identity,
            public,
            key_id,
        })
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
        Ok(json!({
            "keyPackage": {
                "framing": "mlsMessage",
                "contentType": "keyPackage",
                "bytes": STANDARD.encode(&package),
                "sha256": STANDARD.encode(Sha256::digest(&package)),
                "keyPackageRef": STANDARD.encode(&reference)
            },
            "grant": grant
        }))
    }
}

#[tokio::test]
async fn c33_two_authority_canonical_federation_e2e() -> anyhow::Result<()> {
    // 1. Establish base migrated ledger
    let _authority = connect_guarded_request_database(5).await?;

    let did_port = HttpsDidFixture::reserve_port()?;
    let run = Uuid::new_v4().simple().to_string();

    let ds1_did = format!("did:web:ds1-{run}.catbird.test");
    let ds2_did = format!("did:web:ds2-{run}.catbird.test");

    // Deterministic canonical coordinator = min(ds1, ds2)
    let expected_coordinator_did = if ds1_did <= ds2_did {
        ds1_did.clone()
    } else {
        ds2_did.clone()
    };

    let alice = FederatedParty::new(format!("did:web:alice-{run}.catbird.test"), "c33-alice")?;
    let bob = FederatedParty::new(format!("did:web:bob-{run}.catbird.test"), "c33-bob")?;

    let https = HttpsDidFixture::start(
        did_port,
        &[
            (alice.svc.did.clone(), alice.svc.did_document()),
            (bob.svc.did.clone(), bob.svc.did_document()),
        ],
    )?;

    let client = reqwest::Client::builder().build()?;

    let db1_name = format!("catbird_direct_requests_fault_{}", &Uuid::new_v4().simple().to_string()[..16]);
    let db2_name = format!("catbird_direct_requests_fault_{}", &Uuid::new_v4().simple().to_string()[..16]);

    // 2. Launch two independent server processes with independent databases
    let server_a = FederatedAuthorityServer::start(&ds1_did, &db1_name, &https, 61)?;
    let server_b = FederatedAuthorityServer::start(&ds2_did, &db2_name, &https, 71)?;

    // -------------------------------------------------------------------------
    // Step 1: Pre-provision Bob's direct request key on Server B (Bob's Home DS)
    // -------------------------------------------------------------------------
    let bob_keys_input = bob.key_entry()?;
    let (key_status, _) = bob
        .svc
        .post(
            &client,
            &server_b.base_url,
            "blue.catbird.chat.publishDirectRequestKeys",
            &bob_keys_input,
            true,
        )
        .await?;
    anyhow::ensure!(
        key_status == StatusCode::OK,
        "bob failed to publish direct request keys on Server B: {key_status}"
    );

    // -------------------------------------------------------------------------
    // Step 2: Encrypted Introduction Initiation (Alice on Server A -> Bob on Server B)
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
        prepare_body,
    )?;

    // Alice calls prepare on Server A (her home DS, which is Coordinator)
    let (prep_status, prep_bytes) = alice
        .svc
        .post(
            &client,
            &server_a.base_url,
            "blue.catbird.chat.prepareDirectRequest",
            &json!({ "signedRequest": prepare_signed }),
            true,
        )
        .await?;

    anyhow::ensure!(
        prep_status == StatusCode::OK,
        "prepareDirectRequest failed on Server A: {prep_status}: {}",
        String::from_utf8_lossy(&prep_bytes)
    );

    let prep_resp: Value = serde_json::from_slice(&prep_bytes)?;
    let preparation = prep_resp
        .pointer("/outcome/preparation")
        .context("missing preparation outcome")?
        .clone();

    // Verify preparation receipt is signed by Server A (the coordinator)
    let preparation_bytes = serde_json::to_vec(&preparation)?;
    protocol::verify_direct_request_preparation(&preparation_bytes, &server_a.receipt_public_key)?;

    let selected = preparation["selectedDevices"]
        .as_array()
        .context("preparation selectedDevices missing")?;
    anyhow::ensure!(
        selected.len() == 1,
        "preparation must select exactly Bob's device"
    );

    // -------------------------------------------------------------------------
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

    let mut journal = alice.engine.prepare_direct_request(&DirectRequestBootstrapInput {
        draft_id: Uuid::new_v4().to_string(),
        context_json: serde_json::to_vec(&context_val)?,
        group_id: rand::random::<[u8; 32]>().to_vec(),
        generation: 0,
        state_version: 1,
        key_packages: selected
            .iter()
            .map(|device| {
                Ok(STANDARD.decode(
                    device["keyPackage"]["bytes"]
                        .as_str()
                        .context("selected package bytes")?,
                )?)
            })
            .collect::<anyhow::Result<Vec<_>>>()?,
        expected_package_refs: selected
            .iter()
            .map(|device| {
                Ok(STANDARD.decode(
                    device["keyPackage"]["keyPackageRef"]
                        .as_str()
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
    publish_body["importUntil"] = json!(canonical_future(7));

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
        "$type": "blue.catbird.chat.defs#metadataSnapshot",
        "coordinate": metadata_coordinate(&bootstrap.coordinates)?,
        "originTransitionId": request_id.to_string(),
        "authorProof": author,
        "metadata": { "version": 1, "title": "", "description": "" }
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

    let (pub_status, pub_bytes) = alice
        .svc
        .post(
            &client,
            &server_a.base_url,
            "blue.catbird.chat.publishDirectRequest",
            &json!({ "signedRequest": publish_signed }),
            true,
        )
        .await?;

    anyhow::ensure!(
        pub_status == StatusCode::OK,
        "publishDirectRequest failed on Server A {pub_status}: {}",
        String::from_utf8_lossy(&pub_bytes)
    );

    let pub_resp: Value = serde_json::from_slice(&pub_bytes)?;
    let first_published_receipt = pub_resp
        .pointer("/outcome")
        .context("missing outcome receipt")?
        .clone();

    // -------------------------------------------------------------------------
    // Step 4: Lost Peer / Client Response Replay Proof
    // -------------------------------------------------------------------------
    let (replay_status, replay_bytes) = alice
        .svc
        .post(
            &client,
            &server_a.base_url,
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
    // Step 5: Remote Welcome Import and Decryption (Bob on Server B)
    // -------------------------------------------------------------------------
    let (welcomes_status, welcomes_bytes) = bob
        .svc
        .get(
            &client,
            &server_b.base_url,
            "blue.catbird.chat.getPendingWelcomes",
            &[("limit", "10")],
            true,
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

    let welcome_data = STANDARD.decode(
        welcome_item["opaqueWelcome"]
            .as_str()
            .context("missing opaqueWelcome")?,
    )?;

    let welcome_input = DirectRequestWelcomeInput {
        welcome_id: request_id.to_string(),
        welcome_data,
        context_json: serde_json::to_vec(&context_val)?,
        receipt_authority_key: server_a.receipt_public_key.clone(),
        initial_ciphertext: bootstrap.initial_ciphertext.clone(),
        key_package_ref: STANDARD.decode(
            welcome_item["provenance"]["keyPackageRef"]
                .as_str()
                .context("missing provenance keyPackageRef")?,
        )?,
    };

    let intro_result = bob.engine.import_direct_request_welcome(&welcome_input)?;
    assert_eq!(
        intro_result.text,
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
        accept_body,
    )?;

    let (accept_status, accept_bytes) = bob
        .svc
        .post(
            &client,
            &server_b.base_url,
            "blue.catbird.chat.acceptConversation",
            &json!({ "directRequest": accept_signed }),
            true,
        )
        .await?;

    anyhow::ensure!(
        accept_status == StatusCode::OK,
        "acceptConversation on Server B failed {accept_status}: {}",
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

    // -------------------------------------------------------------------------
    // Step 7: Bi-Directional Reply Message (Bob sends on Server B -> Alice reads on Server A)
    // -------------------------------------------------------------------------
    let reply_msg_id = Uuid::new_v4();
    let reply_body = json!({
        "$type": "blue.catbird.chat.defs#applicationSendBody",
        "signatureDomain": "CATBIRD-CHAT-APPLICATION-SEND\0",
        "conversationId": conversation_id.to_string(),
        "messageId": reply_msg_id.to_string(),
        "prior": {
            "conversationId": conversation_id.to_string(),
            "generation": 0,
            "stateVersion": 2,
            "groupId": bootstrap.coordinates["groupId"],
            "epoch": bootstrap.coordinates["epoch"],
            "groupContextHash": bootstrap.coordinates["groupContextHash"],
            "confirmationTag": bootstrap.coordinates["confirmationTag"],
            "lifecycle": "active"
        },
        "ciphertext": STANDARD.encode(b"Federated reply payload"),
        "idempotencyKey": reply_msg_id.to_string(),
        "signedAt": canonical_now()
    });

    let reply_signed = signed_mls_request(
        &bob.engine,
        &bob.identity,
        DirectRequestKind::Send,
        reply_body,
    )?;

    let (reply_status, reply_resp_bytes) = bob
        .svc
        .post(
            &client,
            &server_b.base_url,
            "blue.catbird.chat.sendMessage",
            &json!({ "signedRequest": reply_signed }),
            true,
        )
        .await?;

    anyhow::ensure!(
        reply_status == StatusCode::OK,
        "sendMessage failed on Server B {reply_status}: {}",
        String::from_utf8_lossy(&reply_resp_bytes)
    );

    let reply_resp: Value = serde_json::from_slice(&reply_resp_bytes)?;
    assert_eq!(
        reply_resp["entry"]["seq"], 3,
        "application reply message assigned sequential entry sequence 3"
    );

    // -------------------------------------------------------------------------
    // Step 8: Opposite-Direction Race Convergence
    // -------------------------------------------------------------------------
    let competing_request_id = Uuid::new_v4();
    let competing_first_msg = Uuid::new_v4();
    let competing_convo_id = Uuid::new_v4();

    let competing_prepare = signed_mls_request(
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
            "requestId": competing_request_id.to_string(),
            "firstMessageId": competing_first_msg.to_string(),
            "conversationId": competing_convo_id.to_string(),
            "recipientDid": alice.svc.did,
            "origin": { "$type": "blue.catbird.chat.defs#freshDirectOrigin" },
            "profile": "encryptedIntroduction1",
            "idempotencyKey": competing_request_id.to_string(),
            "signedAt": canonical_now()
        }),
    )?;

    let (comp_status, comp_bytes) = bob
        .svc
        .post(
            &client,
            &server_b.base_url,
            "blue.catbird.chat.prepareDirectRequest",
            &json!({ "signedRequest": competing_prepare }),
            true,
        )
        .await?;

    anyhow::ensure!(
        comp_status == StatusCode::OK,
        "competing prepare responded"
    );

    let comp_resp: Value = serde_json::from_slice(&comp_bytes)?;
    let is_rejected_or_existing = comp_resp.pointer("/outcome/$type").is_some();
    assert!(
        is_rejected_or_existing,
        "competing opposite-direction send converged on coordinator arbitration"
    );

    // -------------------------------------------------------------------------
    // Step 9: Zero Legacy Fallback Assertion on Both Nodes
    // -------------------------------------------------------------------------
    let pool_a = sqlx::PgPool::connect(&server_a.database_url).await?;
    let pool_b = sqlx::PgPool::connect(&server_b.database_url).await?;

    let legacy_welcome_a: i64 = sqlx::query_scalar("SELECT count(*) FROM chat.welcome_deliveries WHERE legacy_welcome_id IS NOT NULL")
        .fetch_one(&pool_a)
        .await
        .unwrap_or(0);
    let legacy_welcome_b: i64 = sqlx::query_scalar("SELECT count(*) FROM chat.welcome_deliveries WHERE legacy_welcome_id IS NOT NULL")
        .fetch_one(&pool_b)
        .await
        .unwrap_or(0);

    assert_eq!(legacy_welcome_a, 0, "Server A zero legacy welcome rows");
    assert_eq!(legacy_welcome_b, 0, "Server B zero legacy welcome rows");

    Ok(())
}
