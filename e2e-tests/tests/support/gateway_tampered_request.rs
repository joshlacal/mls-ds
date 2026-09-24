//! Malicious-but-authentic sender for runtime clients behind the local client
//! runtime gateway.
//!
//! This is the C03 `publish_request_with_unverifiable_introduction` pattern
//! pointed at an externally owned recipient, such as a real bot or app device.
//! The sender holds a real MLS group and signing key. It runs the real
//! prepare/publish router path through the gateway using its own synthetic
//! session. It flips one byte of the AEAD-protected introduction with the
//! unchanged tamper routine, then consistently re-signs the publication.
//! Only the recipient's real OpenMLS AEAD can reject the result.
//!
//! The recipient is never simulated. Its request keys, grant and device must
//! already have been published by the recipient client itself.
#![cfg(feature = "local-runtime-fixture")]

use anyhow::{ensure, Context, Result};
use base64::{engine::general_purpose::STANDARD, Engine as _};
use catbird_mls::{
    chat_v2::transcript::direct_request::{self as protocol, DirectRequestKind},
    metadata::GroupMetadataV1,
    orchestrator::direct_request_bootstrap::{metadata_coordinate, DirectRequestBootstrapInput},
};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::local_runtime_fixture::{canonical_now, signed_mls_request};
use crate::mls_engine::MlsEngine;
use crate::tamper_introduction_ciphertext;

/// A gateway-authenticated sender whose device was preseeded through
/// `/fixture/enroll` with `engine`'s public key for `did#device_id`.
pub struct GatewaySender<'a> {
    /// Client that trusts only the fixture CA and maps fixture hosts to loopback.
    pub http: &'a reqwest::Client,
    pub origin: &'a str,
    pub session: &'a str,
    pub did: &'a str,
    pub device_id: &'a str,
    pub engine: &'a MlsEngine,
}

/// Identifiers of the published request, as acknowledged by the router receipt.
pub struct PublishedTamperedRequest {
    pub request_id: String,
    pub conversation_id: String,
    pub first_message_id: String,
}

fn bytes_field(value: &Value) -> Result<Vec<u8>> {
    let text = value
        .as_str()
        .or_else(|| value.get("$bytes").and_then(Value::as_str))
        .context("bytes field")?;
    Ok(STANDARD.decode(text)?)
}

impl GatewaySender<'_> {
    fn identity(&self) -> String {
        format!("{}#{}", self.did, self.device_id)
    }

    async fn post(&self, nsid: &str, body: &Value) -> Result<(reqwest::StatusCode, Vec<u8>)> {
        let response = self
            .http
            .post(format!("{}/xrpc/{nsid}", self.origin))
            .bearer_auth(self.session)
            .json(body)
            .send()
            .await?;
        Ok((response.status(), response.bytes().await?.to_vec()))
    }

    async fn receipt_document(&self) -> Result<Vec<u8>> {
        let response = self
            .http
            .get("https://chat.catbird.blue/.well-known/did.json")
            .send()
            .await?
            .error_for_status()?;
        Ok(response.bytes().await?.to_vec())
    }

    /// Publishes one request to `recipient_did` whose introduction the
    /// recipient cannot authenticate. `recipient_public_key` is the recipient
    /// device's real signing key. It authenticates the recipient-published
    /// grant that the router selected.
    pub async fn publish_unverifiable_introduction(
        &self,
        recipient_did: &str,
        recipient_public_key: &[u8],
    ) -> Result<PublishedTamperedRequest> {
        let identity = self.identity();
        let public = self.engine.identity_public_key(&identity)?;
        let key_id = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(Sha256::digest(&public));
        let request_id = Uuid::new_v4();
        let first_message_id = Uuid::new_v4();
        let conversation_id = Uuid::new_v4();
        let prepare = signed_mls_request(
            self.engine,
            &identity,
            DirectRequestKind::Prepare,
            json!({
                "$type":"blue.catbird.chat.defs#directRequestPreparationBody",
                "signatureDomain":"CATBIRD-DIRECT-REQUEST-PREPARE\0",
                "protocolVersion":"2",
                "actorDid":self.did,
                "actorDeviceId":self.device_id,
                "keyId":key_id,
                "authGeneration":1,
                "requestId":request_id.to_string(),
                "firstMessageId":first_message_id.to_string(),
                "conversationId":conversation_id.to_string(),
                "recipientDid":recipient_did,
                "origin":{"$type":"blue.catbird.chat.defs#freshDirectOrigin"},
                "profile":"encryptedIntroduction1",
                "idempotencyKey":request_id.to_string(),
                "signedAt":canonical_now()
            }),
        )?;
        let (status, body) = self
            .post("blue.catbird.chat.prepareDirectRequest", &json!({"signedRequest":prepare}))
            .await?;
        ensure!(status == reqwest::StatusCode::OK, "prepare failed {status}: {}", String::from_utf8_lossy(&body));
        let response: Value = serde_json::from_slice(&body)?;
        let preparation = response
            .pointer("/outcome/preparation")
            .filter(|value| !value.is_null())
            .cloned()
            .with_context(|| format!("prepare returned no live preparation: {response}"))?;
        let document = self.receipt_document().await?;
        let receipt_key = protocol::resolve_direct_request_receipt_key(
            &document,
            preparation["receiptKeyId"].as_str().context("receiptKeyId")?,
        )?;
        // Continue with the verified value: reads present `{"$bytes"}`, and only
        // the verifier's normalized projection may feed the strict signer.
        let preparation =
            protocol::verify_direct_request_preparation(&serde_json::to_vec(&preparation)?, &receipt_key)?;
        let verified_prepare = protocol::verify_signed_request(
            DirectRequestKind::Prepare,
            &serde_json::to_vec(&prepare)?,
            &public,
        )?;
        let selected = preparation["selectedDevices"]
            .as_array()
            .context("preparation selectedDevices")?
            .clone();
        ensure!(!selected.is_empty(), "preparation selected no recipient device");
        let minimum_import_until = chrono::DateTime::parse_from_rfc3339(
            preparation["minimumImportUntil"].as_str().context("minimumImportUntil")?,
        )?
        .timestamp();
        let mut authority_import_until = i64::MAX;
        for device in &selected {
            ensure!(device["actorDid"] == recipient_did, "preparation selected a foreign device");
            let grant = protocol::verify_signed_request(
                DirectRequestKind::Grant,
                &serde_json::to_vec(&device["grant"])?,
                recipient_public_key,
            )?;
            let expires = chrono::DateTime::parse_from_rfc3339(
                grant.body()["expiresAt"].as_str().context("grant expiresAt")?,
            )?
            .timestamp();
            authority_import_until = authority_import_until.min(expires);
        }
        ensure!(authority_import_until >= minimum_import_until, "grant expires before import floor");
        let context = json!({
            "protocolVersion":"2",
            "requestId":request_id.to_string(),
            "firstMessageId":first_message_id.to_string(),
            "conversationId":conversation_id.to_string(),
            "origin":{"$type":"blue.catbird.chat.defs#freshDirectOrigin"},
            "actorDid":self.did,
            "actorDeviceId":self.device_id,
            "actorKeyId":key_id,
            "recipientDid":recipient_did,
            "preparationDigest":preparation["preparationDigest"]
        });
        let mut journal = self.engine.prepare_direct_request(&DirectRequestBootstrapInput {
            draft_id: Uuid::new_v4().to_string(),
            context_json: serde_json::to_vec(&context)?,
            group_id: rand::random::<[u8; 32]>().to_vec(),
            generation: 0,
            state_version: 1,
            key_packages: selected
                .iter()
                .map(|d| bytes_field(&d["keyPackage"]["bytes"]))
                .collect::<Result<Vec<_>>>()?,
            expected_package_refs: selected
                .iter()
                .map(|d| bytes_field(&d["keyPackage"]["keyPackageRef"]))
                .collect::<Result<Vec<_>>>()?,
            authority_import_until: u64::try_from(authority_import_until)?,
            preparation_request_digest: *verified_prepare.request_digest(),
            receipt_authority_key: receipt_key.clone(),
            text: "Unverifiable introduction the recipient must never surface".into(),
            invitation: None,
            metadata: GroupMetadataV1 {
                version: 1,
                title: String::new(),
                description: String::new(),
                avatar_blob_locator: None,
                avatar_content_type: None,
            },
        })?;
        tamper_introduction_ciphertext(&mut journal.bootstrap)?;
        let bootstrap = &journal.bootstrap;
        let mut publish_body = prepare["body"].clone();
        publish_body["$type"] = json!("blue.catbird.chat.defs#directRequestPublicationBody");
        publish_body["signatureDomain"] = json!("CATBIRD-DIRECT-REQUEST-PUBLISH\0");
        publish_body["signedAt"] = json!(canonical_now());
        publish_body["preparationDigest"] = preparation["preparationDigest"].clone();
        publish_body["preparationRequestDigest"] = json!(STANDARD.encode(verified_prepare.request_digest()));
        publish_body["contextHash"] = json!(STANDARD.encode(bootstrap.context_hash));
        publish_body["next"] = bootstrap.coordinates.clone();
        publish_body["importUntil"] = json!(chrono::DateTime::from_timestamp(bootstrap.import_until as i64, 0)
            .context("import timestamp")?
            .to_rfc3339_opts(chrono::SecondsFormat::Millis, true));
        let artifact = |data: &[u8], content_type: &str| {
            json!({"framing":"mlsMessage","contentType":content_type,
                   "bytes":STANDARD.encode(data),"sha256":STANDARD.encode(Sha256::digest(data))})
        };
        let deliveries = selected
            .iter()
            .map(|device| {
                json!({
                    "recipientDid":device["actorDid"],
                    "recipientDeviceId":device["actorDeviceId"],
                    "provenance":{
                        "requestId":request_id.to_string(),
                        "preparationDigest":preparation["preparationDigest"],
                        "contextHash":STANDARD.encode(bootstrap.context_hash),
                        "grantId":device["grant"]["body"]["grantId"],
                        "grantRevision":device["grant"]["body"]["grantRevision"],
                        "keyPackageRef":device["keyPackage"]["keyPackageRef"],
                        "importUntil":publish_body["importUntil"]
                    }
                })
            })
            .collect::<Vec<_>>();
        let author = json!({
            "authorDid":self.did,"authorDeviceId":self.device_id,"authorKeyId":key_id,
            "signaturePublicKey":STANDARD.encode(&public),"authGenerationAtOrigin":1,
            "originTransitionId":request_id.to_string(),"originSeq":1,"roleAtOrigin":"admin",
            "deviceStatusAtOrigin":"active"
        });
        publish_body["artifacts"] = json!({
            "genesisGroupInfo":artifact(&bootstrap.genesis_group_info,"groupInfo"),
            "addCommit":artifact(&bootstrap.add_commit,"publicMessageCommit"),
            "finalGroupInfo":artifact(&bootstrap.final_group_info,"groupInfo"),
            "welcome":{"opaqueWelcome":STANDARD.encode(&bootstrap.welcome),"sha256":STANDARD.encode(Sha256::digest(&bootstrap.welcome)),"deliveries":deliveries},
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
        let publication = signed_mls_request(self.engine, &identity, DirectRequestKind::Publish, publish_body)?;
        let (status, body) = self
            .post("blue.catbird.chat.publishDirectRequest", &json!({"signedRequest":publication}))
            .await?;
        ensure!(status == reqwest::StatusCode::OK, "publish failed {status}: {}", String::from_utf8_lossy(&body));
        let published: Value = serde_json::from_slice(&body)?;
        let mut receipt = published["outcome"].clone();
        receipt.as_object_mut().context("published outcome object")?.remove("$type");
        let verified_receipt = protocol::verify_received_signed_request(
            DirectRequestKind::Outcome,
            &serde_json::to_vec(&receipt)?,
            &receipt_key,
        )?;
        let proof = &verified_receipt.body()["receipt"];
        ensure!(
            proof["requestId"] == request_id.to_string()
                && proof["conversationId"] == conversation_id.to_string()
                && proof["requestKind"] == "publish",
            "router receipt does not bind the tampered publication"
        );
        Ok(PublishedTamperedRequest {
            request_id: request_id.to_string(),
            conversation_id: conversation_id.to_string(),
            first_message_id: first_message_id.to_string(),
        })
    }
}
