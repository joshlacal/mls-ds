extern crate self as mls_e2e_tests;

pub mod auth;
pub mod federation;
pub mod mls_engine;

/// Guarded local delivery-service facade for real client runtime fixtures.
///
/// This feature exports the same HTTPS DID/auth/relationship and external
/// shipping-router process used by the encrypted-request evidence suite. It
/// never changes production authentication or receipt trust.
#[cfg(feature = "local-runtime-fixture")]
#[path = "../tests/support/encrypted_requests.rs"]
pub mod local_runtime_fixture;

/// Malicious-but-authentic sender aimed at an externally owned runtime client
/// behind the local client runtime gateway (reuses the C03 tamper routine).
#[cfg(feature = "local-runtime-fixture")]
#[path = "../tests/support/gateway_tampered_request.rs"]
pub mod gateway_tampered_request;

/// Flip the final byte of the AEAD-protected application ciphertext body. Every
/// outer framing byte, the canonical wire encoding, the message AAD, the group
/// id/epoch and every server-side digest stay valid, and the publication is
/// re-signed after this, so only the recipient's real OpenMLS AEAD can reject it.
pub fn tamper_introduction_ciphertext(
    bootstrap: &mut catbird_mls::orchestrator::direct_request_bootstrap::DirectRequestBootstrap,
) -> anyhow::Result<()> {
    let raw = &mut bootstrap.initial_ciphertext;
    anyhow::ensure!(!raw.is_empty(), "prepared introduction ciphertext is empty");
    let last = raw.len() - 1;
    raw[last] ^= 1;
    Ok(())
}

use anyhow::{Context, Result};
use base64::Engine;
use rand::RngCore;
use serde_json::{json, Value};
use std::sync::Arc;
use uuid::Uuid;

use mls_engine::MlsEngine;
/// Bind the canonical, sender-signed archive attestation emitted with a real
/// direct-request bootstrap into its publication body.
pub fn bind_publication_original_sender_attestation(
    body: &mut Value,
    bootstrap: &catbird_mls::orchestrator::direct_request_bootstrap::DirectRequestBootstrap,
) -> Result<()> {
    let conversation_id = body["conversationId"]
        .as_str()
        .context("publication conversationId")?;
    let message_id = body["firstMessageId"]
        .as_str()
        .context("publication firstMessageId")?;
    let attestation = &bootstrap.original_sender_attestation;
    anyhow::ensure!(
        body["actorDid"].as_str() == Some(attestation.sender_did.as_str())
            && body["actorDeviceId"].as_str() == Some(attestation.sender_device_id.as_str()),
        "publication sender differs from original sender attestation"
    );
    attestation
        .verify(conversation_id, message_id, &bootstrap.archive_commitment)
        .context("verify original sender archive attestation")?;
    body["archiveCommitment"] =
        json!(base64::engine::general_purpose::STANDARD.encode(bootstrap.archive_commitment));
    body["originalSenderAttestation"] = json!({
        "senderDid": attestation.sender_did,
        "senderDeviceId": attestation.sender_device_id,
        "senderTransportPubkey": base64::engine::general_purpose::STANDARD
            .encode(&attestation.sender_transport_public_key),
        "signature": base64::engine::general_purpose::STANDARD.encode(&attestation.signature),
    });
    Ok(())
}

/// Verify the legacy acceptance inclusion proof and the I13 receipt that the
/// shipping server adds after computing that proof's entry hash.
pub fn verify_received_direct_request_acceptance_proof_with_i13(
    raw_proof: &[u8],
    authority_did: &str,
    receipt_public_key: &[u8],
    sequencer_receipt_public_key: &[u8],
    recipient_device_key: &[u8],
) -> Result<Value> {
    use catbird_mls::chat_v2::transcript::direct_request::{self as protocol, DirectRequestKind};
    use sha2::{Digest as _, Sha256};

    let mut proof: Value = serde_json::from_slice(raw_proof)?;
    let receipt = proof
        .pointer_mut("/entry")
        .and_then(Value::as_object_mut)
        .and_then(|entry| entry.remove("sequencerReceipt"))
        .context("acceptance proof missing sequencerReceipt")?;
    let mut verified = protocol::verify_received_direct_request_acceptance_proof_for_authority(
        authority_did,
        &serde_json::to_vec(&proof)?,
        receipt_public_key,
        recipient_device_key,
    )?;
    let receipt = protocol::normalize_read_presentation(
        &serde_json::to_vec(&receipt)?,
        "sequencerReceipt",
        false,
    )?;
    let entry = &verified["entry"];
    let body = &entry["signedRequest"]["body"];
    let digest: [u8; 32] = Sha256::digest(protocol::direct_request_signing_bytes(
        DirectRequestKind::Accept,
        &serde_json::to_vec(body)?,
    )?)
    .into();
    catbird_mls::client::chat_wire::verify_control_sequencer_receipt(
        &receipt,
        sequencer_receipt_public_key,
        authority_did,
        entry["conversationId"]
            .as_str()
            .context("acceptance entry conversationId")?,
        entry["entryId"]
            .as_str()
            .context("acceptance entry entryId")?,
        entry["seq"].as_i64().context("acceptance entry seq")?,
        body["actorDid"].as_str().context("acceptance actorDid")?,
        body["actorDeviceId"]
            .as_str()
            .context("acceptance actorDeviceId")?,
        &body["next"],
        &digest,
    )?;
    verified["entry"]["sequencerReceipt"] = receipt;
    Ok(verified)
}

/// Produce the same archive-bound AAD and encrypted inner plaintext used by
/// the shipping Task 5 senders.
pub fn archive_bound_application(
    engine: &MlsEngine,
    identity: &str,
    mut aad: Value,
    canonical_payload: &[u8],
) -> Result<(Value, Vec<u8>, Vec<u8>)> {
    use catbird_mls::messaging::receive::{
        OriginalSenderArchiveAttestationEnvelope, PrivateMessagePlaintextEnvelope,
    };

    let (sender_did, sender_device_id) = identity
        .rsplit_once('#')
        .context("sender identity lacks device fragment")?;
    let uuid_field = |field: &str| -> Result<Uuid> {
        let value = &aad[field];
        let encoded = value
            .as_str()
            .or_else(|| value["$bytes"].as_str())
            .with_context(|| format!("application AAD {field}"))?;
        Ok(Uuid::from_slice(
            &base64::engine::general_purpose::STANDARD.decode(encoded)?,
        )?)
    };
    let conversation_id = uuid_field("conversationId")?;
    let message_id = uuid_field("messageId")?;
    let canonical_conversation_id = conversation_id.hyphenated().to_string();
    let canonical_message_id = message_id.hyphenated().to_string();
    let frame_nonce: [u8; 32] = rand::random();
    let archive_commitment =
        labyrinth_protocol::receipt::compute_archive_commitment(&frame_nonce, canonical_payload);
    let attestation = OriginalSenderArchiveAttestationEnvelope {
        sender_did: sender_did.to_owned(),
        sender_device_id: sender_device_id.to_owned(),
        sender_transport_public_key: engine.identity_public_key(identity)?,
        signature: engine.sign_with_identity_key(
            identity,
            &labyrinth_protocol::transcripts::original_sender_archive_transcript(
                &canonical_conversation_id,
                &canonical_message_id,
                &archive_commitment,
            ),
        )?,
    };
    attestation.verify(
        &canonical_conversation_id,
        &canonical_message_id,
        &archive_commitment,
    )?;
    aad["archiveCommitment"] =
        json!(base64::engine::general_purpose::STANDARD.encode(archive_commitment));
    aad["originalSenderAttestation"] = json!({
        "senderDid": attestation.sender_did,
        "senderDeviceId": attestation.sender_device_id,
        "senderTransportPubkey": base64::engine::general_purpose::STANDARD
            .encode(&attestation.sender_transport_public_key),
        "signature": base64::engine::general_purpose::STANDARD.encode(&attestation.signature),
    });
    let aad_bytes = catbird_mls::orchestrator::canonical_application_aad_bytes(&aad)
        .map_err(|error| anyhow::anyhow!(error.to_string()))?;
    let plaintext = serde_json::to_vec(&PrivateMessagePlaintextEnvelope {
        frame_nonce,
        canonical_payload_bytes: canonical_payload.to_vec(),
        original_sender_attestation: Some(attestation),
    })?;
    Ok((aad, aad_bytes, plaintext))
}

const DEFAULT_AUDIENCE: &str = "did:web:localhost";
const DEFAULT_CIPHER_SUITE: &str = "MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519";

/// Shared inner state for TestClient (cheaply cloneable via Arc).
struct Inner {
    client: reqwest::Client,
    base_url: String,
    jwt_secret: String,
}

/// HTTP test client for the mls-ds delivery service.
#[derive(Clone)]
pub struct TestClient {
    inner: Arc<Inner>,
}

impl TestClient {
    /// Create a new test client pointing at `base_url` (e.g. `http://localhost:3000`).
    pub fn new(base_url: &str, jwt_secret: &str) -> Self {
        Self {
            inner: Arc::new(Inner {
                client: reqwest::Client::new(),
                base_url: base_url.trim_end_matches('/').to_string(),
                jwt_secret: jwt_secret.to_string(),
            }),
        }
    }

    /// Generate a Bearer token for `did`.
    pub fn generate_token(&self, did: &str) -> String {
        auth::generate_jwt(&self.inner.jwt_secret, did, DEFAULT_AUDIENCE)
    }

    /// Create a [`TestUser`] with a unique `did:plc:` DID and a real MLS engine.
    pub fn test_user(&self, name: &str) -> TestUser {
        let did = format!("did:plc:e2e-{}-{}", name, Uuid::new_v4().simple());
        let mls = MlsEngine::new(name).expect("failed to create MlsEngine");
        TestUser {
            did,
            device_id: None,
            mls_did: None,
            mls,
            groups: std::collections::HashMap::new(),
            client: self.clone(),
        }
    }
}

/// A test user that can call mls-ds endpoints.
/// Backed by a real `MlsEngine` for genuine MLS crypto operations.
pub struct TestUser {
    pub did: String,
    pub device_id: Option<String>,
    pub mls_did: Option<String>,
    /// Real MLS engine for key packages, group ops, encryption.
    pub mls: MlsEngine,
    /// Binary group_id → hex string mapping for active groups.
    pub groups: std::collections::HashMap<String, Vec<u8>>,
    client: TestClient,
}

impl TestUser {
    fn token(&self) -> String {
        // Always use bare DID for HTTP auth — device identity is MLS-layer, not auth-layer
        self.client.generate_token(&self.did)
    }

    fn url(&self, path: &str) -> String {
        format!("{}{}", self.client.inner.base_url, path)
    }

    /// Generate `n` bytes of random data (mock MLS payload).
    pub fn random_bytes(n: usize) -> Vec<u8> {
        let mut buf = vec![0u8; n];
        rand::thread_rng().fill_bytes(&mut buf);
        buf
    }

    /// Generic XRPC POST helper for tests that need to hit an endpoint
    /// without a dedicated wrapper. Returns the raw [`reqwest::Response`] so
    /// callers can inspect status + body.
    pub async fn raw_post_xrpc(&self, nsid: &str, body: &Value) -> Result<reqwest::Response> {
        let resp = self
            .client
            .inner
            .client
            .post(self.url(&format!("/xrpc/{}", nsid)))
            .bearer_auth(self.token())
            .json(body)
            .send()
            .await
            .context(format!("{} request failed", nsid))?;
        Ok(resp)
    }

    // ── registerDevice ─────────────────────────────────────────────

    /// Register a device with real MLS key packages from the MLS engine.
    pub async fn register_device(&mut self) -> Result<Value> {
        // Generate a real key package via OpenMLS
        let (kp_bytes, _hash_ref) = self
            .mls
            .create_key_package(&self.did)
            .context("create_key_package for registerDevice")?;

        // Extract the real signature public key from the key package
        let sig_key = MlsEngine::extract_key_package_sig_key(&kp_bytes)
            .context("extract sig key from key package")?;
        let sig_key_b64 = base64::engine::general_purpose::STANDARD.encode(&sig_key);

        let kp_b64 = base64::engine::general_purpose::STANDARD.encode(&kp_bytes);

        let expires = (chrono::Utc::now() + chrono::Duration::days(30))
            .format("%Y-%m-%dT%H:%M:%SZ")
            .to_string();

        let device_uuid = Uuid::new_v4().to_string();

        let body = json!({
            "action": "register",
            "deviceName": "E2E Test Device",
            "signaturePublicKey": { "$bytes": sig_key_b64 },
            "keyPackages": [
                {
                    "keyPackage": kp_b64,
                    "cipherSuite": DEFAULT_CIPHER_SUITE,
                    "expires": expires
                }
            ],
            "deviceUuid": device_uuid
        });

        let resp = self
            .client
            .inner
            .client
            .post(self.url("/xrpc/blue.catbird.mlsChat.registerDevice"))
            .bearer_auth(self.token())
            .json(&body)
            .send()
            .await
            .context("registerDevice request failed")?;

        let status = resp.status();
        let text = resp
            .text()
            .await
            .context("registerDevice: failed to read body")?;
        if !status.is_success() {
            anyhow::bail!("registerDevice returned {}: {}", status, text);
        }
        let json: Value = serde_json::from_str(&text)
            .with_context(|| format!("registerDevice: invalid JSON in response: {:?}", text))?;

        if let Some(device_id) = json.get("deviceId").and_then(|v| v.as_str()) {
            self.device_id = Some(device_id.to_string());
        }
        if let Some(mls_did) = json.get("mlsDid").and_then(|v| v.as_str()) {
            self.mls_did = Some(mls_did.to_string());
        }

        Ok(json)
    }

    // ── publishKeyPackages ─────────────────────────────────────────

    /// Publish real MLS key packages generated by the engine.
    /// `count` key packages are generated and uploaded.
    pub async fn publish_key_packages(&self, count: usize) -> Result<Value> {
        let expires = (chrono::Utc::now() + chrono::Duration::days(30))
            .format("%Y-%m-%dT%H:%M:%SZ")
            .to_string();

        let mut items = Vec::with_capacity(count);
        for _ in 0..count {
            let (kp_bytes, _hash_ref) = self
                .mls
                .create_key_package(&self.did)
                .context("create_key_package for publish")?;
            items.push(json!({
                "keyPackage": base64::engine::general_purpose::STANDARD.encode(&kp_bytes),
                "cipherSuite": DEFAULT_CIPHER_SUITE,
                "expires": expires,
                "deviceId": self.device_id.as_deref().unwrap_or_default()
            }));
        }

        let body = json!({ "action": "publishBatch", "keyPackages": items });

        let resp = self
            .client
            .inner
            .client
            .post(self.url("/xrpc/blue.catbird.mlsChat.publishKeyPackages"))
            .bearer_auth(self.token())
            .json(&body)
            .send()
            .await
            .context("publishKeyPackages request failed")?;

        let status = resp.status();
        let json: Value = resp
            .json()
            .await
            .context("publishKeyPackages: invalid JSON")?;

        anyhow::ensure!(
            status.is_success(),
            "publishKeyPackages returned {}: {}",
            status,
            json
        );

        Ok(json)
    }

    // ── createConvo ────────────────────────────────────────────────

    /// Create a conversation backed by a real MLS group.
    ///
    /// Creates a real MLS group via the engine, then registers it with the
    /// delivery service. Returns the full ConvoView JSON response.
    /// The binary group_id is stored in `self.groups` keyed by hex string.
    pub async fn create_convo(
        &mut self,
        members: &[String],
        welcome: Option<&[u8]>,
    ) -> Result<Value> {
        // Create a real MLS group locally
        let group_id_bytes = self
            .mls
            .create_group(&self.did)
            .context("MLS create_group")?;
        let group_id = hex::encode(&group_id_bytes);
        let idempotency_key = Uuid::new_v4().to_string();

        let mut body = json!({
            "groupId": group_id,
            "cipherSuite": DEFAULT_CIPHER_SUITE,
            "idempotencyKey": idempotency_key,
        });

        if !members.is_empty() {
            body["initialMembers"] = json!(members);
        }
        if let Some(w) = welcome {
            body["welcomeMessage"] = json!(base64::engine::general_purpose::STANDARD.encode(w));
        }

        tracing::debug!(
            "createConvo body: {}",
            serde_json::to_string_pretty(&body).unwrap()
        );

        let resp = self
            .client
            .inner
            .client
            .post(self.url("/xrpc/blue.catbird.mlsChat.createConvo"))
            .bearer_auth(self.token())
            .json(&body)
            .send()
            .await
            .context("createConvo request failed")?;

        let status = resp.status();
        let text = resp
            .text()
            .await
            .context("createConvo: failed to read body")?;
        if !status.is_success() {
            anyhow::bail!("createConvo returned {}: {}", status, text);
        }
        let json: Value = serde_json::from_str(&text)
            .with_context(|| format!("createConvo: invalid JSON: {:?}", text))?;

        tracing::debug!(
            "createConvo response: {}",
            serde_json::to_string_pretty(&json).unwrap()
        );

        // Track the group locally so we can encrypt against it later
        if let Some(gid) = json.get("groupId").and_then(|v| v.as_str()) {
            self.groups.insert(gid.to_string(), group_id_bytes);
        }

        Ok(json)
    }

    // ── sendMessage ────────────────────────────────────────────────

    /// Send a message to a conversation.
    ///
    /// If the group is tracked in `self.groups`, encrypts `plaintext` using
    /// real MLS. Otherwise falls back to sending raw `ciphertext` bytes.
    pub async fn send_message(
        &self,
        convo_id: &str,
        ciphertext: &[u8],
        epoch: i64,
    ) -> Result<Value> {
        let msg_id = Uuid::new_v4().to_string();
        let ct_b64 = base64::engine::general_purpose::STANDARD.encode(ciphertext);

        let body = json!({
            "convoId": convo_id,
            "msgId": msg_id,
            "epoch": epoch,
            "ciphertext": { "$bytes": ct_b64 },
            "paddedSize": ciphertext.len() as i64,
        });

        let resp = self
            .client
            .inner
            .client
            .post(self.url("/xrpc/blue.catbird.mlsChat.sendMessage"))
            .bearer_auth(self.token())
            .json(&body)
            .send()
            .await
            .context("sendMessage request failed")?;

        let status = resp.status();
        let text = resp
            .text()
            .await
            .context("sendMessage: failed to read body")?;
        if !status.is_success() {
            anyhow::bail!("sendMessage returned {}: {}", status, text);
        }
        let json: Value = serde_json::from_str(&text)
            .with_context(|| format!("sendMessage: invalid JSON: {:?}", text))?;

        Ok(json)
    }

    /// Build a ciphertext buffer padded to a valid bucket size.
    pub fn padded_ciphertext(payload: &[u8]) -> Vec<u8> {
        let buckets = [512, 1024, 2048, 4096, 8192];
        let target = buckets
            .iter()
            .find(|&&b| b >= payload.len())
            .copied()
            .unwrap_or_else(|| {
                // Round up to next multiple of 8192
                payload.len().div_ceil(8192) * 8192
            });
        let mut buf = vec![0u8; target];
        buf[..payload.len()].copy_from_slice(payload);
        buf
    }

    /// Encrypt plaintext with real MLS and send to the delivery service.
    /// Requires the group to be tracked via a prior `create_convo` call.
    pub async fn encrypt_and_send(
        &self,
        convo_id: &str,
        plaintext: &[u8],
        epoch: i64,
    ) -> Result<Value> {
        let group_id_bytes = self
            .groups
            .get(convo_id)
            .with_context(|| format!("group {convo_id} not tracked — call create_convo first"))?;

        let (ciphertext, padded_size) = self
            .mls
            .encrypt(group_id_bytes, plaintext)
            .context("MLS encrypt_message")?;

        let msg_id = Uuid::new_v4().to_string();
        let ct_b64 = base64::engine::general_purpose::STANDARD.encode(&ciphertext);

        let body = json!({
            "convoId": convo_id,
            "msgId": msg_id,
            "epoch": epoch,
            "ciphertext": { "$bytes": ct_b64 },
            "paddedSize": padded_size as i64,
        });

        let resp = self
            .client
            .inner
            .client
            .post(self.url("/xrpc/blue.catbird.mlsChat.sendMessage"))
            .bearer_auth(self.token())
            .json(&body)
            .send()
            .await
            .context("sendMessage request failed")?;

        let status = resp.status();
        let text = resp
            .text()
            .await
            .context("sendMessage: failed to read body")?;
        if !status.is_success() {
            anyhow::bail!("sendMessage returned {}: {}", status, text);
        }
        let json: Value = serde_json::from_str(&text)
            .with_context(|| format!("sendMessage: invalid JSON: {:?}", text))?;

        Ok(json)
    }

    // ── getMessages ────────────────────────────────────────────────

    /// Get messages from a conversation.
    ///
    /// Query params: `convoId`, optional `sinceSeq`, optional `limit`.
    pub async fn get_messages(&self, convo_id: &str, since_seq: Option<i64>) -> Result<Value> {
        self.get_messages_with_limit(convo_id, since_seq, None)
            .await
    }

    pub async fn get_messages_with_limit(
        &self,
        convo_id: &str,
        since_seq: Option<i64>,
        limit: Option<i32>,
    ) -> Result<Value> {
        let mut params = vec![("convoId", convo_id.to_string())];
        if let Some(seq) = since_seq {
            params.push(("sinceSeq", seq.to_string()));
        }
        if let Some(l) = limit {
            params.push(("limit", l.to_string()));
        }

        let resp = self
            .client
            .inner
            .client
            .get(self.url("/xrpc/blue.catbird.mlsChat.getMessages"))
            .bearer_auth(self.token())
            .query(&params)
            .send()
            .await
            .context("getMessages request failed")?;

        let status = resp.status();
        let json: Value = resp.json().await.context("getMessages: invalid JSON")?;

        anyhow::ensure!(
            status.is_success(),
            "getMessages returned {}: {}",
            status,
            json
        );

        Ok(json)
    }

    // ── getConvos ──────────────────────────────────────────────────

    /// Get all conversations for this user.
    pub async fn get_convos(&self) -> Result<Value> {
        let resp = self
            .client
            .inner
            .client
            .get(self.url("/xrpc/blue.catbird.mlsChat.getConvos"))
            .bearer_auth(self.token())
            .send()
            .await
            .context("getConvos request failed")?;

        let status = resp.status();
        let json: Value = resp.json().await.context("getConvos: invalid JSON")?;

        anyhow::ensure!(
            status.is_success(),
            "getConvos returned {}: {}",
            status,
            json
        );

        Ok(json)
    }

    // ── updateCursor ───────────────────────────────────────────────

    /// Update the read cursor for a conversation.
    ///
    /// Input JSON: `{ "convoId": "...", "cursor": "..." }`
    pub async fn update_cursor(&self, convo_id: &str, cursor: &str) -> Result<Value> {
        let body = json!({
            "convoId": convo_id,
            "cursor": cursor,
        });

        let resp = self
            .client
            .inner
            .client
            .post(self.url("/xrpc/blue.catbird.mlsChat.updateCursor"))
            .bearer_auth(self.token())
            .json(&body)
            .send()
            .await
            .context("updateCursor request failed")?;

        let status = resp.status();
        let text = resp
            .text()
            .await
            .context("updateCursor: failed to read body")?;

        anyhow::ensure!(
            status.is_success(),
            "updateCursor returned {}: {}",
            status,
            text
        );

        // Server may return empty body on success
        if text.is_empty() {
            return Ok(json!({"success": true}));
        }
        serde_json::from_str(&text)
            .with_context(|| format!("updateCursor: invalid JSON: {:?}", text))
    }
}

/// Compute latency statistics from a collection of durations.
/// Returns a formatted string with count, avg, p50, p99, and total.
pub fn latency_stats(durations: &mut [std::time::Duration]) -> String {
    durations.sort();
    let n = durations.len();
    if n == 0 {
        return "no data".into();
    }
    let total: std::time::Duration = durations.iter().sum();
    let avg = total / n as u32;
    let p50 = durations[n / 2];
    let p99_idx = ((n as f64 * 0.99) as usize).min(n - 1);
    let p99 = durations[p99_idx];
    format!("n={n}, avg={avg:?}, p50={p50:?}, p99={p99:?}, total={total:?}")
}

/// Initialize tracing for E2E tests (call once at start of test binary).
pub fn init_tracing() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "mls_e2e_tests=info".parse().unwrap()),
        )
        .try_init();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_padded_ciphertext_sizes() {
        assert_eq!(TestUser::padded_ciphertext(b"hello").len(), 512);
        assert_eq!(TestUser::padded_ciphertext(&[0u8; 513]).len(), 1024);
        assert_eq!(TestUser::padded_ciphertext(&[0u8; 4097]).len(), 8192);
        assert_eq!(TestUser::padded_ciphertext(&[0u8; 8193]).len(), 16384);
    }

    #[test]
    fn test_client_creates_unique_users() {
        let client = TestClient::new("http://localhost:3000", "secret");
        let u1 = client.test_user("alice");
        let u2 = client.test_user("alice");
        assert_ne!(u1.did, u2.did);
        assert!(u1.did.starts_with("did:plc:e2e-alice-"));
    }
}
