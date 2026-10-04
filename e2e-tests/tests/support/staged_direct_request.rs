//! Real first contact staged up to, but not including, the publish POST.
//!
//! The sender runs on a real SQLCipher `MLSContext` whose keychain is a
//! directory on disk, so the exact same store can be reopened by a different
//! OS process (the in-memory `MlsEngine` keychain cannot cross a process).
//! Staging persists the exact signed publication in the durable journal
//! (phase `OutcomeUnknown`) before any transport, as the production client does.
use super::encrypted_requests::{
    canonical_future, canonical_now, connect_guarded_request_database, seed_service_device,
    signed_mls_request, DeterministicFaultTransport, HttpsDidFixture, ServiceIdentity,
    ShippingServerFixture,
};
use anyhow::Context as _;
use base64::{
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
    Engine as _,
};
use catbird_mls::{
    chat_v2::transcript::direct_request::{self as protocol, DirectRequestKind},
    metadata::GroupMetadataV1,
    orchestrator::{
        direct_request_bootstrap::{
            metadata_coordinate, DirectRequestBootstrap, DirectRequestBootstrapInput,
            DirectRequestWelcomeInput,
        },
        direct_request_journal::DirectRequestJournal,
        direct_requests::DirectRequestIntent,
        MlsCryptoContext,
    },
    DirectRequestInput, KeychainAccess, MLSContext, MLSError,
};
use mls_e2e_tests::mls_engine::MlsEngine;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{
    path::{Path, PathBuf},
    sync::Arc,
};
use uuid::Uuid;

pub const PUBLISH_NSID: &str = "blue.catbird.chat.publishDirectRequest";
pub const OUTCOME_NSID: &str = "blue.catbird.chat.getDirectRequestOutcome";
const STORE_KEY: &str = "c10-c11-durable-sender-0123456789abcdef0123456789abcdef";

/// Platform-keychain stand-in that survives process exit (one file per key).
#[derive(Clone)]
struct FileKeychain(PathBuf);

impl FileKeychain {
    fn path(&self, key: &str) -> PathBuf {
        self.0.join(hex::encode(Sha256::digest(key.as_bytes())))
    }
}

#[async_trait::async_trait]
impl KeychainAccess for FileKeychain {
    async fn read(&self, key: String) -> Result<Option<Vec<u8>>, MLSError> {
        match std::fs::read(self.path(&key)) {
            Ok(bytes) => Ok(Some(bytes)),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(_) => Err(MLSError::StorageFailed),
        }
    }
    async fn write(&self, key: String, value: Vec<u8>) -> Result<(), MLSError> {
        std::fs::write(self.path(&key), value).map_err(|_| MLSError::StorageFailed)
    }
    async fn delete(&self, key: String) -> Result<(), MLSError> {
        match std::fs::remove_file(self.path(&key)) {
            Err(error) if error.kind() != std::io::ErrorKind::NotFound => {
                Err(MLSError::StorageFailed)
            }
            _ => Ok(()),
        }
    }
}

/// Directory holding the sender's SQLCipher store and keychain files.
pub fn open_sender_store(dir: &Path) -> anyhow::Result<Arc<MLSContext>> {
    std::fs::create_dir_all(dir.join("keychain"))?;
    MLSContext::new(
        dir.join("sender.db").to_string_lossy().into_owned(),
        STORE_KEY.into(),
        Box::new(FileKeychain(dir.join("keychain"))),
    )
    .map_err(|error| anyhow::anyhow!("open durable sender store: {error}"))
}

pub fn close_sender_store(ctx: Arc<MLSContext>) -> anyhow::Result<()> {
    ctx.flush_and_prepare_close()
        .map_err(|error| anyhow::anyhow!("close durable sender store: {error}"))?;
    drop(ctx);
    Ok(())
}

/// Exactly one durable journal row for `request_id`.
pub fn journal(ctx: &MLSContext, request_id: Uuid) -> anyhow::Result<DirectRequestJournal> {
    let rows = ctx
        .list_direct_request_journal()
        .map_err(|error| anyhow::anyhow!("list journal: {error}"))?
        .into_iter()
        .filter(|row| row.request_id == request_id.to_string())
        .collect::<Vec<_>>();
    anyhow::ensure!(rows.len() == 1, "expected one journal row, found {}", rows.len());
    Ok(rows.into_iter().next().unwrap())
}

fn sign_sender(
    ctx: &MLSContext,
    identity: &str,
    kind: DirectRequestKind,
    body: Value,
) -> anyhow::Result<Value> {
    let transcript = protocol::direct_request_signing_bytes(kind, &serde_json::to_vec(&body)?)?;
    let signature = ctx
        .sign_with_identity_key(identity.to_owned(), transcript)
        .map_err(|error| anyhow::anyhow!("sender sign: {error}"))?;
    let wrapper = json!({"body":body,"signature":STANDARD.encode(signature)});
    let public = ctx
        .identity_public_key(identity.to_owned())
        .map_err(|error| anyhow::anyhow!("sender public key: {error}"))?;
    protocol::verify_signed_request(kind, &serde_json::to_vec(&wrapper)?, &public)?;
    Ok(wrapper)
}

pub struct StagedRequest {
    pub alice: ServiceIdentity,
    pub bob: ServiceIdentity,
    pub sender_dir: PathBuf,
    pub sender: Option<Arc<MLSContext>>,
    pub bob_engine: MlsEngine,
    pub server: ShippingServerFixture,
    pub client: reqwest::Client,
    pub draft_id: String,
    pub request_id: Uuid,
    pub conversation_id: Uuid,
    pub first_message_id: Uuid,
    pub bob_identity: String,
    pub bob_package_ref: Vec<u8>,
    pub alice_public: Vec<u8>,
    pub preparation_request_digest: [u8; 32],
    pub publication: Value,
    /// Exact bytes persisted in the durable journal and sent as the POST body.
    pub exact_publication: Vec<u8>,
    pub _https: HttpsDidFixture,
}

impl Drop for StagedRequest {
    fn drop(&mut self) {
        if let Some(ctx) = self.sender.take() {
            let _ = ctx.flush_and_prepare_close();
        }
        let _ = std::fs::remove_dir_all(&self.sender_dir);
    }
}

/// Keys publication, preparation, native bootstrap and durable journal record
/// through the shipping router; the publish request itself is left to the case.
pub async fn stage_request(label: &str) -> anyhow::Result<StagedRequest> {
    connect_guarded_request_database(5).await?;
    let run = Uuid::new_v4().simple().to_string();
    let alice = ServiceIdentity::new(format!("did:web:alice-{run}.request-fixture.catbird.blue"));
    let bob = ServiceIdentity::new(format!("did:web:bob-{run}.request-fixture.catbird.blue"));
    let https = HttpsDidFixture::start(
        HttpsDidFixture::reserve_port()?,
        &[
            (alice.did.clone(), alice.did_document()),
            (bob.did.clone(), bob.did_document()),
        ],
    )?;
    let sender_dir = std::env::temp_dir().join(format!("{label}-sender-{run}"));
    let sender = open_sender_store(&sender_dir)?;
    let bob_engine = MlsEngine::new(&format!("{label}-bob"))?;
    let alice_identity = format!("{}#{}", alice.did, alice.device_id);
    let bob_identity = format!("{}#{}", bob.did, bob.device_id);
    sender
        .create_key_package(alice_identity.as_bytes().to_vec())
        .map_err(|error| anyhow::anyhow!("sender key package: {error}"))?;
    let (bob_package, bob_package_ref) = bob_engine.create_key_package(&bob_identity)?;
    let alice_public = sender
        .identity_public_key(alice_identity.clone())
        .map_err(|error| anyhow::anyhow!("sender public key: {error}"))?;
    let bob_public = bob_engine.identity_public_key(&bob_identity)?;
    seed_service_device(&alice, &alice_public)?;
    seed_service_device(&bob, &bob_public)?;
    let server = ShippingServerFixture::start(&https)?;
    let client = reqwest::Client::builder().build()?;

    let bob_key_id = URL_SAFE_NO_PAD.encode(Sha256::digest(&bob_public));
    let alice_key_id = URL_SAFE_NO_PAD.encode(Sha256::digest(&alice_public));
    let grant_id = Uuid::new_v4();
    let grant = signed_mls_request(
        &bob_engine,
        &bob_identity,
        DirectRequestKind::Grant,
        json!({
            "$type":"blue.catbird.chat.defs#directRequestGrantBody",
            "signatureDomain":"CATBIRD-DIRECT-REQUEST-GRANT\0","protocolVersion":"2",
            "actorDid":bob.did,"actorDeviceId":bob.device_id.to_string(),"keyId":bob_key_id,
            "authGeneration":1,"grantId":grant_id.to_string(),"grantRevision":1,
            "purpose":"direct-request-bootstrap","profile":"encryptedIntroduction1",
            "keyPackageRef":STANDARD.encode(&bob_package_ref),
            "keyPackageSha256":STANDARD.encode(Sha256::digest(&bob_package)),
            "expiresAt":canonical_future(29),"idempotencyKey":grant_id.to_string(),
            "signedAt":canonical_now()
        }),
    )?;
    let keys_operation = Uuid::new_v4();
    let keys = signed_mls_request(
        &bob_engine,
        &bob_identity,
        DirectRequestKind::Keys,
        json!({
            "$type":"blue.catbird.chat.defs#directRequestKeysPublicationBody",
            "signatureDomain":"CATBIRD-DIRECT-REQUEST-KEYS\0","protocolVersion":"2",
            "actorDid":bob.did,"actorDeviceId":bob.device_id.to_string(),"keyId":bob_key_id,
            "authGeneration":1,"revision":1,"enabled":true,
            "keys":[{"keyPackage":{"framing":"mlsMessage","contentType":"keyPackage",
                "bytes":STANDARD.encode(&bob_package),
                "sha256":STANDARD.encode(Sha256::digest(&bob_package)),
                "keyPackageRef":STANDARD.encode(&bob_package_ref)},"grant":grant}],
            "idempotencyKey":keys_operation.to_string(),"signedAt":canonical_now()
        }),
    )?;
    let (keys_status, keys_response) = bob
        .post(
            &client,
            &server.base_url,
            "blue.catbird.chat.publishDirectRequestKeys",
            &json!({"signedRequest":keys}),
            true,
        )
        .await?;
    anyhow::ensure!(
        keys_status == reqwest::StatusCode::OK,
        "publish keys failed {keys_status}: {}",
        String::from_utf8_lossy(&keys_response)
    );

    let request_id = Uuid::new_v4();
    let first_message_id = Uuid::new_v4();
    let conversation_id = Uuid::new_v4();
    let prepare = sign_sender(
        &sender,
        &alice_identity,
        DirectRequestKind::Prepare,
        json!({
            "$type":"blue.catbird.chat.defs#directRequestPreparationBody",
            "signatureDomain":"CATBIRD-DIRECT-REQUEST-PREPARE\0","protocolVersion":"2",
            "actorDid":alice.did,"actorDeviceId":alice.device_id.to_string(),"keyId":alice_key_id,
            "authGeneration":1,"requestId":request_id.to_string(),
            "firstMessageId":first_message_id.to_string(),
            "conversationId":conversation_id.to_string(),"recipientDid":bob.did,
            "origin":{"$type":"blue.catbird.chat.defs#freshDirectOrigin"},
            "profile":"encryptedIntroduction1","idempotencyKey":request_id.to_string(),
            "signedAt":canonical_now()
        }),
    )?;
    let (prepare_status, prepare_response) = alice
        .post(
            &client,
            &server.base_url,
            "blue.catbird.chat.prepareDirectRequest",
            &json!({"signedRequest":prepare}),
            true,
        )
        .await?;
    anyhow::ensure!(
        prepare_status == reqwest::StatusCode::OK,
        "prepare failed {prepare_status}: {}",
        String::from_utf8_lossy(&prepare_response)
    );
    let response: Value = serde_json::from_slice(&prepare_response)?;
    let preparation = response
        .pointer("/outcome/preparation")
        .filter(|value| !value.is_null())
        .cloned()
        .with_context(|| format!("prepare returned no live preparation: {response}"))?;
    let preparation = protocol::verify_direct_request_preparation(
        &serde_json::to_vec(&preparation)?,
        &server.receipt_public_key,
    )?;
    let verified_prepare = protocol::verify_signed_request(
        DirectRequestKind::Prepare,
        &serde_json::to_vec(&prepare)?,
        &alice_public,
    )?;
    let selected = preparation["selectedDevices"]
        .as_array()
        .context("preparation selectedDevices")?
        .clone();
    anyhow::ensure!(selected.len() == 1, "expected one selected recipient device");
    let grant = protocol::verify_signed_request(
        DirectRequestKind::Grant,
        &serde_json::to_vec(&selected[0]["grant"])?,
        &bob_public,
    )?;
    let authority_import_until = u64::try_from(
        chrono::DateTime::parse_from_rfc3339(
            grant.body()["expiresAt"].as_str().context("grant expiresAt")?,
        )?
        .timestamp(),
    )?;
    let context = json!({
        "protocolVersion":"2","requestId":request_id.to_string(),
        "firstMessageId":first_message_id.to_string(),
        "conversationId":conversation_id.to_string(),
        "origin":{"$type":"blue.catbird.chat.defs#freshDirectOrigin"},
        "actorDid":alice.did,"actorDeviceId":alice.device_id.to_string(),
        "actorKeyId":alice_key_id,"recipientDid":bob.did,
        "preparationDigest":preparation["preparationDigest"]
    });
    let draft_id = Uuid::new_v4().to_string();
    let journal_record = sender
        .prepare_direct_request_bootstrap(&DirectRequestBootstrapInput {
            draft_id: draft_id.clone(),
            context_json: serde_json::to_vec(&context)?,
            group_id: rand::random::<[u8; 32]>().to_vec(),
            generation: 0,
            state_version: 1,
            key_packages: vec![STANDARD.decode(
                selected[0]["keyPackage"]["bytes"]
                    .as_str()
                    .context("selected package bytes")?,
            )?],
            expected_package_refs: vec![STANDARD.decode(
                selected[0]["keyPackage"]["keyPackageRef"]
                    .as_str()
                    .context("selected package ref")?,
            )?],
            authority_import_until,
            preparation_request_digest: *verified_prepare.request_digest(),
            receipt_authority_key: server.receipt_public_key.clone(),
            text: "Real encrypted first contact".into(),
            invitation: None,
            metadata: GroupMetadataV1 {
                version: 1,
                title: String::new(),
                description: String::new(),
                avatar_blob_locator: None,
                avatar_content_type: None,
            },
        })
        .map_err(|error| anyhow::anyhow!("prepare_direct_request_bootstrap: {error}"))?;
    let bootstrap = &journal_record.bootstrap;
    let mut body = prepare["body"].clone();
    body["$type"] = json!("blue.catbird.chat.defs#directRequestPublicationBody");
    body["signatureDomain"] = json!("CATBIRD-DIRECT-REQUEST-PUBLISH\0");
    body["signedAt"] = json!(canonical_now());
    body["preparationDigest"] = preparation["preparationDigest"].clone();
    body["preparationRequestDigest"] = json!(STANDARD.encode(verified_prepare.request_digest()));
    body["contextHash"] = json!(STANDARD.encode(bootstrap.context_hash));
    body["next"] = bootstrap.coordinates.clone();
    body["importUntil"] = json!(chrono::DateTime::from_timestamp(
        bootstrap.import_until as i64,
        0
    )
    .context("import timestamp")?
    .to_rfc3339_opts(chrono::SecondsFormat::Millis, true));
    let artifact = |data: &[u8], content_type: &str| {
        json!({"framing":"mlsMessage","contentType":content_type,
            "bytes":STANDARD.encode(data),"sha256":STANDARD.encode(Sha256::digest(data))})
    };
    let delivery = json!({
        "recipientDid":selected[0]["actorDid"],
        "recipientDeviceId":selected[0]["actorDeviceId"],
        "provenance":{
            "requestId":request_id.to_string(),
            "preparationDigest":preparation["preparationDigest"],
            "contextHash":STANDARD.encode(bootstrap.context_hash),
            "grantId":selected[0]["grant"]["body"]["grantId"],
            "grantRevision":selected[0]["grant"]["body"]["grantRevision"],
            "keyPackageRef":selected[0]["keyPackage"]["keyPackageRef"],
            "importUntil":body["importUntil"]
        }
    });
    let author = json!({
        "authorDid":alice.did,"authorDeviceId":alice.device_id.to_string(),
        "authorKeyId":alice_key_id,"signaturePublicKey":STANDARD.encode(&alice_public),
        "authGenerationAtOrigin":1,"originTransitionId":request_id.to_string(),"originSeq":1,
        "roleAtOrigin":"admin","deviceStatusAtOrigin":"active"
    });
    body["artifacts"] = json!({
        "genesisGroupInfo":artifact(&bootstrap.genesis_group_info,"groupInfo"),
        "addCommit":artifact(&bootstrap.add_commit,"publicMessageCommit"),
        "finalGroupInfo":artifact(&bootstrap.final_group_info,"groupInfo"),
        "welcome":{"opaqueWelcome":STANDARD.encode(&bootstrap.welcome),
            "sha256":STANDARD.encode(Sha256::digest(&bootstrap.welcome)),"deliveries":[delivery]},
        "initialCiphertext":STANDARD.encode(&bootstrap.initial_ciphertext),
        "metadataSnapshot":{
            "coordinate":metadata_coordinate(&bootstrap.coordinates)?,
            "originTransitionId":request_id.to_string(),"metadataVersion":1,
            "nonce":STANDARD.encode(&bootstrap.metadata_nonce),
            "ciphertext":STANDARD.encode(&bootstrap.metadata_ciphertext),
            "ciphertextSha256":STANDARD.encode(Sha256::digest(&bootstrap.metadata_ciphertext)),
            "ciphertextSize":bootstrap.metadata_ciphertext.len(),"authorProof":author
        }
    });
    let publication = sign_sender(&sender, &alice_identity, DirectRequestKind::Publish, body)?;
    let exact_publication = serde_json::to_vec(&json!({"signedRequest":publication}))?;
    sender
        .persist_direct_request_publish(&request_id.to_string(), &exact_publication)
        .map_err(|error| anyhow::anyhow!("persist publication: {error}"))?;
    let intent = DirectRequestIntent {
        input: DirectRequestInput {
            draft_id: draft_id.clone(),
            recipient_did: bob.did.clone(),
            text: "Real encrypted first contact".into(),
            invitation: None,
        },
        actor_did: alice.did.clone(),
        actor_device_id: alice.device_id.to_string(),
        actor_public_key: alice_public.clone(),
        prepare_wrapper: serde_json::to_vec(&prepare)?,
        legacy_origin_snapshot: None,
        trusted_authority_document: server.receipt_document.clone(),
        preparation_response: Some(serde_json::to_vec(&preparation)?),
        cancel_wrapper: None,
        publication_wrapper: Some(serde_json::to_vec(&publication)?),
        terminal_response: None,
        publication_attempted: true,
        cancellation_requested: false,
        projection_completed: false,
        previous_attempts: Vec::new(),
    };
    sender
        .compare_exchange_direct_request_intent(&draft_id, None, &intent.encode()?)
        .map_err(|error| anyhow::anyhow!("persist intent: {error}"))?;
    Ok(StagedRequest {
        alice,
        bob,
        sender_dir,
        sender: Some(sender),
        bob_engine,
        server,
        client,
        draft_id,
        request_id,
        conversation_id,
        first_message_id,
        bob_identity,
        bob_package_ref,
        alice_public,
        preparation_request_digest: *verified_prepare.request_digest(),
        publication,
        exact_publication,
        _https: https,
    })
}

impl StagedRequest {
    /// POST the exact journal bytes through a deterministic transport. The
    /// bearer is attached as a default header so the transport body is unchanged.
    pub async fn post_publication(
        &self,
        transport: &mut DeterministicFaultTransport,
    ) -> anyhow::Result<(reqwest::StatusCode, Vec<u8>)> {
        let mut headers = reqwest::header::HeaderMap::new();
        headers.insert(
            reqwest::header::AUTHORIZATION,
            format!(
                "Bearer {}",
                self.alice.scoped_jwt_with_jti(PUBLISH_NSID, Uuid::new_v4())
            )
            .parse()?,
        );
        let client = reqwest::Client::builder()
            .default_headers(headers)
            .build()?;
        let body: Value = serde_json::from_slice(&self.exact_publication)?;
        anyhow::ensure!(
            serde_json::to_vec(&body)? == self.exact_publication,
            "transport body must be the exact journal bytes"
        );
        let response = transport
            .post_json(
                &client,
                &format!("{}/xrpc/{PUBLISH_NSID}", self.server.base_url),
                &body,
            )
            .await?;
        let status = response.status();
        Ok((status, response.bytes().await?.to_vec()))
    }

    /// Verify a published outcome (with or without `$type`) against the
    /// receipt authority and this exact request; returns the untyped receipt.
    pub fn verified_published_receipt(&self, outcome: &Value) -> anyhow::Result<Value> {
        let mut receipt = outcome.clone();
        receipt
            .as_object_mut()
            .context("outcome object")?
            .remove("$type");
        let verified = protocol::verify_received_signed_request(
            DirectRequestKind::Outcome,
            &serde_json::to_vec(&receipt)?,
            &self.server.receipt_public_key,
        )?;
        let proof = &verified.body()["receipt"];
        let publication = protocol::verify_signed_request(
            DirectRequestKind::Publish,
            &serde_json::to_vec(&self.publication)?,
            &self.alice_public,
        )?;
        anyhow::ensure!(
            proof["$type"] == "blue.catbird.chat.defs#directRequestPublishedReceipt"
                && proof["requestId"] == self.request_id.to_string()
                && proof["conversationId"] == self.conversation_id.to_string()
                && proof["firstMessageId"] == self.first_message_id.to_string()
                && proof["requestDigest"] == STANDARD.encode(publication.request_digest()),
            "outcome is not this request's published receipt: {proof}"
        );
        Ok(receipt)
    }

    pub fn welcome_input(
        &self,
        bootstrap: DirectRequestBootstrap,
        receipt: &Value,
    ) -> anyhow::Result<DirectRequestWelcomeInput> {
        Ok(DirectRequestWelcomeInput {
            bootstrap,
            local_identity: self.bob_identity.as_bytes().to_vec(),
            local_package_ref: self.bob_package_ref.clone(),
            publication_request: serde_json::to_vec(&self.publication)?,
            actor_signature_public_key: self.alice_public.clone(),
            published_receipt: serde_json::to_vec(receipt)?,
            receipt_authority_did: "did:web:chat.catbird.blue".into(),
            receipt_authority_key: self.server.receipt_public_key.clone(),
            preparation_request_digest: self.preparation_request_digest,
        })
    }
}
