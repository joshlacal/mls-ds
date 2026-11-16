use chrono::{DateTime, SecondsFormat, Utc};
use p256::ecdsa::{signature::Verifier, Signature, SigningKey, VerifyingKey};
use p256::pkcs8::DecodePrivateKey;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use super::envelope::{DELIVER_MESSAGE_NSID, DELIVER_WELCOME_NSID, SUBMIT_COMMIT_NSID};
use super::errors::FederationError;
use catbird_atproto::generated::blue_catbird::chat::submit_transition::SubmitTransitionOutput;
use catbird_atproto::generated::blue_catbird::chat::ConversationEntry;
use catbird_atproto::generated::blue_catbird::mlsDS::submit_commit::SubmitCommitOutput;
use serde_json::Value;
use uuid::Uuid;
/// Baseline verification method used before the first receipt-key rotation.
///
/// Operators rotate to `#mls-receipt-2`, `-3`, … and retain every prior
/// method in the DID document so archived receipts remain verifiable.
pub const RECEIPT_VERIFICATION_METHOD: &str = "did:web:chat.catbird.blue#mls-receipt-1";

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum ReceiptConfigError {
    #[error("RECEIPT_ISSUANCE_MODE must be disabled or issue")]
    InvalidIssuanceMode,
    #[error("RECEIPT_SIGNING_KEY_PEM is required when receipt issuance is enabled")]
    MissingSigningKey,
    #[error("RECEIPT_SIGNING_KEY_PEM is not a valid ES256 PKCS#8 private key")]
    MalformedSigningKey,
    #[error("RECEIPT_VERIFICATION_METHOD must name a versioned MLS receipt method")]
    UnexpectedVerificationMethod,
    #[error("SERVICE_DID must own the configured MLS receipt verification method")]
    VerificationMethodOwnerMismatch,
    #[error("the receipt-signing key must be distinct from the service-auth key")]
    ServiceAuthKeyReuse,
    #[error("SIGNING_KEY_PEM is required to prove receipt/service key separation")]
    MissingServiceAuthKey,
    #[error("SIGNING_KEY_PEM is not a valid ES256 PKCS#8 private key")]
    MalformedServiceAuthKey,
    #[error("RECEIPT_DID_DOCUMENT_JSON is required when receipt issuance is enabled")]
    MissingPublishedDidDocument,
    #[error("published receipt DID document is invalid: {0}")]
    InvalidPublishedDidDocument(#[from] ReceiptDidDocumentError),
}

/// Fail-closed validation errors for the receipt verification method published
/// by the sequencer's DID document.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum ReceiptDidDocumentError {
    #[error("receipt DID document is not valid JSON")]
    MalformedDocument,
    #[error("receipt DID document id does not own the configured verification method")]
    DocumentOwnerMismatch,
    #[error("receipt DID document omits a required receipt verification method")]
    MissingReceiptMethod,
    #[error("receipt DID document defines a receipt verification method more than once")]
    AmbiguousReceiptMethod,
    #[error("receipt verification method controller does not match the document owner")]
    ControllerMismatch,
    #[error("receipt verification method must be a P-256 Multikey")]
    UnsupportedReceiptKey,
    #[error("published receipt key does not match the configured receipt signer")]
    SignerKeyMismatch,
    #[error("published receipt key must be distinct from the service-auth key")]
    ServiceAuthKeyReuse,
    #[error("receipt DID document must retain every prior key generation")]
    ReceiptHistoryGap,
    #[error("configured receipt verification method is not the newest generation")]
    ConfiguredMethodNotCurrent,
}

/// Validate the baseline receipt verification method in a resolved DID document.
pub fn validate_receipt_did_document(
    document: &str,
    expected_receipt_key: &VerifyingKey,
    service_auth_key: Option<&VerifyingKey>,
) -> Result<(), ReceiptDidDocumentError> {
    let method_owner = RECEIPT_VERIFICATION_METHOD
        .split_once('#')
        .map(|(did, _)| did)
        .expect("baseline receipt verification method contains a fragment");
    validate_receipt_did_document_method_for_service(
        document,
        method_owner,
        RECEIPT_VERIFICATION_METHOD,
        expected_receipt_key,
        service_auth_key,
    )
}

/// Validate the configured method and the retained, contiguous receipt-key
/// history in a resolved DID document.
pub fn validate_receipt_did_document_method_for_service(
    document: &str,
    service_did: &str,
    configured_method_id: &str,
    expected_receipt_key: &VerifyingKey,
    service_auth_key: Option<&VerifyingKey>,
) -> Result<(), ReceiptDidDocumentError> {
    let document: serde_json::Value =
        serde_json::from_str(document).map_err(|_| ReceiptDidDocumentError::MalformedDocument)?;
    let method_owner = crate::identity::canonical_did(service_did);
    let configured_generation =
        labyrinth_protocol::receipt::receipt_key_generation(method_owner, configured_method_id)
            .map_err(|_| ReceiptDidDocumentError::DocumentOwnerMismatch)?;
    let receipt_methods = receipt_key_history(&document, method_owner, service_auth_key)?;
    let Some(current_key) = receipt_methods.get(&configured_generation) else {
        return Err(ReceiptDidDocumentError::MissingReceiptMethod);
    };
    if receipt_methods.keys().next_back().copied() != Some(configured_generation) {
        return Err(ReceiptDidDocumentError::ConfiguredMethodNotCurrent);
    }
    if current_key != expected_receipt_key {
        return Err(ReceiptDidDocumentError::SignerKeyMismatch);
    }
    Ok(())
}

/// The key of the exact receipt method `key_id` (a proof's signed `kid`) in
/// `sequencer_did`'s resolved DID document. The published history must hold as
/// it does at issuance, but the method need not be the newest generation: a
/// proof signed before a rotation still verifies against its retained method.
pub fn retained_receipt_key(
    document: &serde_json::Value,
    sequencer_did: &str,
    key_id: &str,
) -> Result<VerifyingKey, ReceiptDidDocumentError> {
    let method_owner = crate::identity::canonical_did(sequencer_did);
    let generation = labyrinth_protocol::receipt::receipt_key_generation(method_owner, key_id)
        .map_err(|_| ReceiptDidDocumentError::DocumentOwnerMismatch)?;
    receipt_key_history(document, method_owner, None)?
        .remove(&generation)
        .ok_or(ReceiptDidDocumentError::MissingReceiptMethod)
}

/// Every receipt method `document` publishes for `method_owner`, by generation:
/// each a P-256 Multikey its owner controls, never the service-auth key, and
/// the generations exactly `1..=N`, since a rotation retains every prior method.
fn receipt_key_history(
    document: &serde_json::Value,
    method_owner: &str,
    service_auth_key: Option<&VerifyingKey>,
) -> Result<std::collections::BTreeMap<u64, VerifyingKey>, ReceiptDidDocumentError> {
    if document.get("id").and_then(serde_json::Value::as_str) != Some(method_owner) {
        return Err(ReceiptDidDocumentError::DocumentOwnerMismatch);
    }
    let methods = document
        .get("verificationMethod")
        .and_then(serde_json::Value::as_array)
        .ok_or(ReceiptDidDocumentError::MissingReceiptMethod)?;
    let mut receipt_methods = std::collections::BTreeMap::new();
    for method in methods {
        let Some(method_id) = method.get("id").and_then(serde_json::Value::as_str) else {
            continue;
        };
        let Ok(generation) =
            labyrinth_protocol::receipt::receipt_key_generation(method_owner, method_id)
        else {
            continue;
        };
        if method.get("controller").and_then(serde_json::Value::as_str) != Some(method_owner) {
            return Err(ReceiptDidDocumentError::ControllerMismatch);
        }
        if method.get("type").and_then(serde_json::Value::as_str) != Some("Multikey") {
            return Err(ReceiptDidDocumentError::UnsupportedReceiptKey);
        }
        let encoded = method
            .get("publicKeyMultibase")
            .and_then(serde_json::Value::as_str)
            .ok_or(ReceiptDidDocumentError::UnsupportedReceiptKey)?;
        let (_, decoded) = multibase::decode(encoded)
            .map_err(|_| ReceiptDidDocumentError::UnsupportedReceiptKey)?;
        if !decoded.starts_with(&[0x80, 0x24]) || decoded.len() != 2 + 33 {
            return Err(ReceiptDidDocumentError::UnsupportedReceiptKey);
        }
        let published_key = VerifyingKey::from_sec1_bytes(&decoded[2..])
            .map_err(|_| ReceiptDidDocumentError::UnsupportedReceiptKey)?;
        if service_auth_key == Some(&published_key) {
            return Err(ReceiptDidDocumentError::ServiceAuthKeyReuse);
        }
        if receipt_methods.insert(generation, published_key).is_some() {
            return Err(ReceiptDidDocumentError::AmbiguousReceiptMethod);
        }
    }
    if !receipt_methods
        .keys()
        .copied()
        .eq(1..=receipt_methods.len() as u64)
    {
        return Err(ReceiptDidDocumentError::ReceiptHistoryGap);
    }
    Ok(receipt_methods)
}

/// Build the process's one receipt signer from its dedicated configuration.
/// Disabled mode yields no signer, so a configured key signs nothing. Process
/// startup refuses that result when chat cutover is enabled; signer-less
/// runtime constructors remain valid for tests and historical migrations.
///
/// `SIGNING_KEY_PEM` is accepted only for a public-key separation check. It is
/// never used to construct the receipt signer and is never a fallback for a
/// missing `RECEIPT_SIGNING_KEY_PEM`.
pub fn configured_receipt_signer(
    issuance_mode: Option<&str>,
    receipt_signing_key_pem: Option<&str>,
    receipt_verification_method: Option<&str>,
    service_auth_signing_key_pem: Option<&str>,
    service_did: &str,
    published_did_document: Option<&str>,
) -> Result<Option<I13ReceiptSigner>, ReceiptConfigError> {
    let mode = issuance_mode.unwrap_or("disabled").trim();
    if mode.eq_ignore_ascii_case("disabled") || mode.eq_ignore_ascii_case("off") {
        return Ok(None);
    }
    if !mode.eq_ignore_ascii_case("issue") {
        return Err(ReceiptConfigError::InvalidIssuanceMode);
    }

    let method_id =
        receipt_verification_method.ok_or(ReceiptConfigError::UnexpectedVerificationMethod)?;
    let Some((method_owner, _)) = method_id.split_once('#').filter(|(did, _)| {
        !did.is_empty()
            && (did.starts_with("did:web:") || did.starts_with("did:plc:"))
            && labyrinth_protocol::receipt::receipt_key_generation(did, method_id).is_ok()
    }) else {
        return Err(ReceiptConfigError::UnexpectedVerificationMethod);
    };
    if crate::identity::canonical_did(service_did) != method_owner {
        return Err(ReceiptConfigError::VerificationMethodOwnerMismatch);
    }

    let pem = receipt_signing_key_pem.ok_or(ReceiptConfigError::MissingSigningKey)?;
    let receipt_key =
        SigningKey::from_pkcs8_pem(pem).map_err(|_| ReceiptConfigError::MalformedSigningKey)?;

    let service_pem =
        service_auth_signing_key_pem.ok_or(ReceiptConfigError::MissingServiceAuthKey)?;
    let service_key = SigningKey::from_pkcs8_pem(service_pem)
        .map_err(|_| ReceiptConfigError::MalformedServiceAuthKey)?;
    if service_key.verifying_key() == receipt_key.verifying_key() {
        return Err(ReceiptConfigError::ServiceAuthKeyReuse);
    }

    let published_did_document =
        published_did_document.ok_or(ReceiptConfigError::MissingPublishedDidDocument)?;
    validate_receipt_did_document_method_for_service(
        published_did_document,
        method_owner,
        method_id,
        receipt_key.verifying_key(),
        Some(service_key.verifying_key()),
    )?;

    I13ReceiptSigner::new_with_key_id(receipt_key, service_did.to_string(), method_id.to_owned())
        .map(Some)
        .map_err(|_| ReceiptConfigError::UnexpectedVerificationMethod)
}

/// Clean-slate `I13` ES256 sequencer receipt signer
/// (`{sequencer_did}#mls-receipt-N`).
#[derive(Debug, Clone)]
pub struct I13ReceiptSigner {
    signing_key: SigningKey,
    sequencer_did: String,
    key_id: String,
}

/// The sequencing DS's dedicated receipt-key attestation that an exact group
/// close was authorized by its final, singleton active-admin roster.
///
/// This is not a replacement for the actor's device signature. Receivers must
/// verify that signature with the actor's current authoritative signing key too.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TerminalCloseAuthority {
    pub sequencer_did: String,
    pub conversation_id: Uuid,
    pub close_entry_sha256: [u8; 32],
    pub final_roster_sha256: [u8; 32],
    pub actor_did: String,
    pub actor_device_id: Uuid,
    pub actor_key_id: String,
    pub actor_auth_generation: u64,
    pub key_id: String,
    pub signature: Vec<u8>,
}

impl TerminalCloseAuthority {
    pub fn verify(
        &self,
        verifying_key: &VerifyingKey,
        expected_sequencer: &str,
        conversation_id: Uuid,
        entry: &Value,
    ) -> Result<(), String> {
        let expected_sequencer = crate::identity::canonical_did(expected_sequencer);
        if self.sequencer_did != expected_sequencer
            || labyrinth_protocol::receipt::receipt_key_generation(expected_sequencer, &self.key_id)
                .is_err()
            || self.conversation_id != conversation_id
            || self.close_entry_sha256 != terminal_close_entry_sha256(entry)?
        {
            return Err("terminal close authority binding mismatch".to_string());
        }
        let mutation = terminal_close_mutation(conversation_id, entry)?;
        if self.actor_did != mutation.actor_did().as_str()
            || self.actor_device_id != Uuid::from_bytes(*mutation.actor_device_id().as_bytes())
            || self.actor_key_id != mutation.key_id().as_str()
            || self.actor_auth_generation != mutation.auth_generation()
            || self.final_roster_sha256
                != terminal_close_roster_sha256(mutation.actor_did().as_str())
        {
            return Err("terminal close actor or final roster mismatch".to_string());
        }
        let signature = Signature::from_slice(&self.signature)
            .map_err(|_| "invalid terminal close signature")?;
        verifying_key
            .verify(&self.signing_bytes(), &signature)
            .map_err(|_| "invalid terminal close authority signature".to_string())
    }

    fn signing_bytes(&self) -> Vec<u8> {
        const DOMAIN: &[u8] = b"CATBIRD-TERMINAL-CLOSE-AUTHORITY-V1\0";
        let fields = [
            self.sequencer_did.as_bytes(),
            self.key_id.as_bytes(),
            self.actor_did.as_bytes(),
            self.actor_key_id.as_bytes(),
        ];
        let mut bytes = Vec::with_capacity(
            DOMAIN.len()
                + 4 * 4
                + fields.iter().map(|field| field.len()).sum::<usize>()
                + 16
                + 16
                + 8
                + 32
                + 32,
        );
        bytes.extend_from_slice(DOMAIN);
        for field in fields {
            bytes.extend_from_slice(&(field.len() as u32).to_be_bytes());
            bytes.extend_from_slice(field);
        }
        bytes.extend_from_slice(self.conversation_id.as_bytes());
        bytes.extend_from_slice(self.actor_device_id.as_bytes());
        bytes.extend_from_slice(&self.actor_auth_generation.to_be_bytes());
        bytes.extend_from_slice(&self.close_entry_sha256);
        bytes.extend_from_slice(&self.final_roster_sha256);
        bytes
    }
}

const ACCOUNT_DELETED_ENTRY_TYPE: &str = "blue.catbird.chat.defs#accountDeletedEntry";

/// The endpoint every `actorWrite` names: the deleting device's own `deleteAccountData`.
pub const DELETE_ACCOUNT_DATA_NSID: &str = "blue.catbird.labyrinth.deleteAccountData";
/// Lexicon `accountDeletionActorWrite.writeBody` maximum length.
pub const ACTOR_WRITE_BODY_MAX_BYTES: usize = 1024;
/// Lexicon `accountDeletedEntry.keyProof` maximum length.
pub const KEY_PROOF_MAX_BYTES: usize = 16_384;
/// Upper bound on one serialized `accountDeletedEntry`, which holds the largest
/// `actorWrite` and `keyProof` the lexicon admits.
pub const ACCOUNT_DELETED_ENTRY_MAX_BYTES: usize = 32 * 1024;

/// One sequenced `blue.catbird.chat.defs#accountDeletedEntry`: everything its
/// [`AccountDeletionAuthority`] binds, plus the deleting device's own evidence,
/// which that authority does not bind. `deleted_at` is the entry's `receivedAt`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AccountDeletion {
    pub sequencer_did: String,
    pub conversation_id: Uuid,
    pub deleted_did: String,
    pub seq: i64,
    pub entry_id: Uuid,
    pub deleted_at: DateTime<Utc>,
    /// The deleting device's signed `deleteAccountData` write and repository
    /// proof, exactly as its home verified them. Absent on deletions sequenced
    /// before entries carried them.
    pub evidence: Option<AccountDeletionEvidence>,
}

/// Lexicon `blue.catbird.chat.defs#accountDeletionActorWrite`: the deleting device's
/// exact `labyrinthWriteBody` bytes and its Ed25519 signature over
/// `CATBIRD-LABYRINTH-WRITE\0 || writeBody`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AccountDeletionActorWrite {
    #[serde(with = "crate::atproto_bytes")]
    pub write_body: Vec<u8>,
    #[serde(with = "crate::atproto_bytes")]
    pub signature: Vec<u8>,
}

/// What an `accountDeletedEntry` carries from the deleting device: its signed
/// write and, when the device sent one, the repository proof of its key.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AccountDeletionEvidence {
    pub actor_write: AccountDeletionActorWrite,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        with = "crate::atproto_bytes::option"
    )]
    pub key_proof: Option<Vec<u8>>,
}

impl AccountDeletionEvidence {
    /// The `signedAt` of a well-formed `writeBody`.
    pub fn signed_at(&self) -> Result<DateTime<Utc>, String> {
        let wire: crate::labyrinth::auth::WriteBodyWire =
            serde_json::from_slice(&self.actor_write.write_body)
                .map_err(|error| format!("actorWrite.writeBody: {error}"))?;
        DateTime::parse_from_rfc3339(&wire.signed_at)
            .map(|at| at.with_timezone(&Utc))
            .map_err(|_| "actorWrite.writeBody.signedAt is not RFC 3339".to_string())
    }

    /// Check the lexicon shape: a `labyrinthWriteBody` of `deleteAccountData` of
    /// at most 1024 bytes, a 64-byte signature, and a non-empty `keyProof` of at
    /// most 16384 bytes. The signature and the proof are for clients to verify.
    pub fn check_shape(&self) -> Result<(), String> {
        let write_body = &self.actor_write.write_body;
        if write_body.is_empty() || write_body.len() > ACTOR_WRITE_BODY_MAX_BYTES {
            return Err("actorWrite.writeBody length is out of range".to_string());
        }
        if self.actor_write.signature.len() != 64 {
            return Err("actorWrite.signature must be 64 bytes".to_string());
        }
        if let Some(key_proof) = &self.key_proof {
            if key_proof.is_empty() || key_proof.len() > KEY_PROOF_MAX_BYTES {
                return Err("keyProof length is out of range".to_string());
            }
        }
        let wire: crate::labyrinth::auth::WriteBodyWire = serde_json::from_slice(write_body)
            .map_err(|error| format!("actorWrite.writeBody: {error}"))?;
        if wire.endpoint_nsid != DELETE_ACCOUNT_DATA_NSID {
            return Err("actorWrite.writeBody names another endpoint".to_string());
        }
        crate::labyrinth::auth::parse_device_id(&wire.actor_device_id)
            .map_err(|_| "actorWrite.writeBody.actorDeviceId is not a UUID".to_string())?;
        self.signed_at().map(|_| ())
    }

    /// Evidence as a device holding `device_key` signs it: the `labyrinthWriteBody`
    /// of `deleteAccountData` over the body `{}` under `operation_id` at `signed_at`,
    /// right-padded with JSON whitespace to `pad_to` bytes when that is longer.
    #[cfg(any(test, feature = "test-support"))]
    pub fn signed_for_test(
        device_key: &ed25519_dalek::SigningKey,
        device_id: Uuid,
        operation_id: [u8; 16],
        signed_at: DateTime<Utc>,
        pad_to: usize,
        key_proof: Option<Vec<u8>>,
    ) -> Self {
        use ed25519_dalek::Signer as _;
        let mut write_body = serde_json::to_vec(&serde_json::json!({
            "operationId": hex::encode(operation_id),
            "actorDeviceId": device_id.to_string(),
            "endpointNsid": DELETE_ACCOUNT_DATA_NSID,
            "payloadSha256": hex::encode(Sha256::digest(b"{}")),
            "signedAt": signed_at.to_rfc3339_opts(SecondsFormat::Millis, true),
        }))
        .expect("write body");
        if write_body.len() < pad_to {
            write_body.resize(pad_to, b' ');
        }
        let signature = device_key
            .sign(&[b"CATBIRD-LABYRINTH-WRITE\0".as_slice(), &write_body].concat())
            .to_bytes()
            .to_vec();
        Self {
            actor_write: AccountDeletionActorWrite {
                write_body,
                signature,
            },
            key_proof,
        }
    }
}

/// `blue.catbird.chat.defs#accountDeletionAuthority`: the sequencer's signature
/// over one [`AccountDeletion`] and the exact dedicated versioned receipt-key ID,
/// never its service-auth key.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AccountDeletionAuthority {
    pub sequencer_did: String,
    pub key_id: String,
    /// Low-S ES256 `r || s`, as lexicon `{"$bytes": …}`.
    #[serde(with = "crate::atproto_bytes")]
    pub signature: Vec<u8>,
}

impl AccountDeletion {
    /// `catbird-mls-account-deletion-v1\0`, then sequencerDid, conversationId,
    /// deletedDid, seq (decimal), entryId and deletedAt (RFC 3339 UTC with
    /// milliseconds), each as u32-BE length-prefixed UTF-8.
    pub fn signing_bytes(&self) -> Vec<u8> {
        let (conversation_id, seq, entry_id, deleted_at) = (
            self.conversation_id.to_string(),
            self.seq.to_string(),
            self.entry_id.to_string(),
            self.deleted_at_text(),
        );
        let mut bytes = b"catbird-mls-account-deletion-v1\0".to_vec();
        for field in [
            self.sequencer_did.as_str(),
            &conversation_id,
            &self.deleted_did,
            &seq,
            &entry_id,
            &deleted_at,
        ] {
            bytes.extend_from_slice(&(field.len() as u32).to_be_bytes());
            bytes.extend_from_slice(field.as_bytes());
        }
        bytes
    }

    fn deleted_at_text(&self) -> String {
        self.deleted_at.to_rfc3339_opts(SecondsFormat::Millis, true)
    }

    /// The canonical entry, exactly as every home stores and `getEntries` presents it.
    pub fn entry(&self, authority: &AccountDeletionAuthority) -> Value {
        let mut entry = serde_json::json!({
            "$type": ACCOUNT_DELETED_ENTRY_TYPE,
            "conversationId": self.conversation_id,
            "deletedDid": self.deleted_did,
            "entryId": self.entry_id,
            "receivedAt": self.deleted_at_text(),
            "seq": self.seq,
            "sequencerAuthority": authority,
            "sequencerDid": self.sequencer_did,
        });
        if let (Some(evidence), Some(object)) = (&self.evidence, entry.as_object_mut()) {
            // The evidence serializes as exactly the lexicon's `actorWrite` and `keyProof`.
            if let Ok(Value::Object(fields)) = serde_json::to_value(evidence) {
                object.extend(fields);
            }
        }
        entry
    }

    /// Parse an entry that is exactly [`Self::entry`]'s canonical form. This
    /// authenticates nothing: verify the returned authority.
    pub fn from_entry(entry: &Value) -> Result<(Self, AccountDeletionAuthority), String> {
        #[derive(Deserialize)]
        #[serde(rename_all = "camelCase", deny_unknown_fields)]
        struct Wire {
            #[serde(rename = "$type")]
            kind: String,
            conversation_id: Uuid,
            deleted_did: String,
            entry_id: Uuid,
            received_at: DateTime<Utc>,
            seq: i64,
            sequencer_authority: AccountDeletionAuthority,
            sequencer_did: String,
            #[serde(default)]
            actor_write: Option<AccountDeletionActorWrite>,
            #[serde(default, with = "crate::atproto_bytes::option")]
            key_proof: Option<Vec<u8>>,
        }
        let wire = Wire::deserialize(entry)
            .map_err(|error| format!("invalid account-deleted entry: {error}"))?;
        let evidence = match (wire.actor_write, wire.key_proof) {
            (Some(actor_write), key_proof) => Some(AccountDeletionEvidence {
                actor_write,
                key_proof,
            }),
            (None, None) => None,
            (None, Some(_)) => {
                return Err("account-deleted keyProof requires its actorWrite".to_string())
            }
        };
        if let Some(evidence) = &evidence {
            evidence.check_shape()?;
        }
        let deletion = Self {
            sequencer_did: wire.sequencer_did,
            conversation_id: wire.conversation_id,
            deleted_did: wire.deleted_did,
            seq: wire.seq,
            entry_id: wire.entry_id,
            deleted_at: wire.received_at,
            evidence,
        };
        if wire.kind != ACCOUNT_DELETED_ENTRY_TYPE
            || deletion.seq < 1
            || deletion.entry(&wire.sequencer_authority) != *entry
        {
            return Err("account-deleted entry is not canonical".to_string());
        }
        if serde_json::to_vec(entry).map_or(usize::MAX, |bytes| bytes.len())
            > ACCOUNT_DELETED_ENTRY_MAX_BYTES
        {
            return Err("account-deleted entry exceeds its size bound".to_string());
        }
        Ok((deletion, wire.sequencer_authority))
    }
}

impl AccountDeletionAuthority {
    /// Verify that `deletion`'s own sequencer signed it with the exact versioned receipt key.
    pub fn verify(
        &self,
        verifying_key: &VerifyingKey,
        deletion: &AccountDeletion,
    ) -> Result<(), String> {
        if self.sequencer_did != deletion.sequencer_did
            || labyrinth_protocol::receipt::receipt_key_generation(
                &deletion.sequencer_did,
                &self.key_id,
            )
            .is_err()
        {
            return Err("account deletion authority binding mismatch".to_string());
        }
        let signature = Signature::from_slice(&self.signature)
            .ok()
            .filter(|signature| signature.normalize_s().is_none())
            .ok_or_else(|| "account deletion signature is not low-S ES256".to_string())?;
        verifying_key
            .verify(
                &account_deletion_authority_signing_bytes(deletion, &self.key_id),
                &signature,
            )
            .map_err(|_| "invalid account deletion authority signature".to_string())
    }
}

fn account_deletion_authority_signing_bytes(deletion: &AccountDeletion, key_id: &str) -> Vec<u8> {
    let deletion_bytes = deletion.signing_bytes();
    let mut bytes = Vec::with_capacity(
        b"catbird-mls-account-deletion-authority-v2\0".len()
            + 4
            + key_id.len()
            + deletion_bytes.len(),
    );
    bytes.extend_from_slice(b"catbird-mls-account-deletion-authority-v2\0");
    bytes.extend_from_slice(&(key_id.len() as u32).to_be_bytes());
    bytes.extend_from_slice(key_id.as_bytes());
    bytes.extend_from_slice(&deletion_bytes);
    bytes
}

fn terminal_close_entry_sha256(entry: &Value) -> Result<[u8; 32], String> {
    // Match the retained terminal attachment's exact JSON-byte digest.
    let bytes = serde_json::to_vec(entry).map_err(|error| error.to_string())?;
    Ok(Sha256::digest(bytes).into())
}

fn terminal_close_roster_sha256(actor_did: &str) -> [u8; 32] {
    let mut digest = Sha256::new();
    digest.update(b"CATBIRD-TERMINAL-CLOSE-ROSTER-V1\0");
    digest.update(1_u32.to_be_bytes());
    for field in [actor_did.as_bytes(), b"active", b"admin"] {
        digest.update((field.len() as u32).to_be_bytes());
        digest.update(field);
    }
    digest.finalize().into()
}

fn terminal_close_mutation(
    conversation_id: Uuid,
    entry: &Value,
) -> Result<crate::chat_protocol::transcript::CanonicalSignedMutation, String> {
    let entry_conversation = entry
        .get("conversationId")
        .and_then(Value::as_str)
        .and_then(|value| Uuid::parse_str(value).ok());
    let prior_conversation = entry
        .pointer("/signedRequest/body/prior/conversationId")
        .and_then(Value::as_str)
        .and_then(|value| Uuid::parse_str(value).ok());
    if entry_conversation != Some(conversation_id)
        || prior_conversation != Some(conversation_id)
        || entry.get("$type").and_then(Value::as_str)
            != Some("blue.catbird.chat.defs#conversationCloseEntry")
        || entry
            .pointer("/signedRequest/body/conversationKind")
            .and_then(Value::as_str)
            != Some("group")
    {
        return Err("terminal close authority requires the exact group close entry".to_string());
    }
    // `sequencerReceipt` is appended after the actor signs the closed control projection.
    let mut actor_entry = entry.clone();
    actor_entry
        .as_object_mut()
        .ok_or_else(|| "terminal close entry is not an object".to_string())?
        .remove("sequencerReceipt");
    let bytes = serde_json::to_vec(&actor_entry).map_err(|error| error.to_string())?;
    let mutation =
        crate::chat_protocol::transcript::decode_control_entry_mutation_unverified(&bytes)
            .map_err(|error| format!("invalid terminal close entry: {error:?}"))?;
    if mutation.kind() != crate::chat_protocol::transcript::SignedMutationKind::ConversationClose {
        return Err("terminal close authority requires a close mutation".to_string());
    }
    Ok(mutation)
}

/// Immutable actor-signed material captured before a control entry is moved into its state plan.
#[derive(Debug, Clone)]
pub struct I13ControlReceiptInput {
    conversation_id: String,
    entry_id: String,
    seq: u64,
    issued_at_ms: i64,
    sender_did: String,
    sender_device_id: String,
    request_digest: [u8; 32],
}
impl I13ControlReceiptInput {
    pub fn from_fields(
        conversation_id: &str,
        entry_id: &str,
        seq: u64,
        received_at: &str,
        sender_did: &str,
        sender_device_id: &str,
        request_digest: [u8; 32],
    ) -> Result<Self, String> {
        let issued_at_ms = DateTime::parse_from_rfc3339(received_at)
            .map_err(|_| "control entry receivedAt is not canonical RFC3339".to_owned())?
            .timestamp_millis();
        Ok(Self {
            conversation_id: conversation_id.to_owned(),
            entry_id: entry_id.to_owned(),
            seq,
            issued_at_ms,
            sender_did: sender_did.to_owned(),
            sender_device_id: sender_device_id.to_owned(),
            request_digest,
        })
    }
}

/// Select the one authoritative coordinate a control kind's sequencer signs.
///
/// Coordinate-less cancellations retain the immediately preceding
/// authoritative coordinate; callers must supply that exact predecessor.
pub(crate) fn control_receipt_coordinate<'a>(
    kind: crate::chat_protocol::transcript::SignedMutationKind,
    body: &'a serde_json::Map<String, Value>,
    predecessor: Option<&'a Value>,
) -> Result<&'a Value, String> {
    use crate::chat_protocol::transcript::SignedMutationKind as K;

    let field = match kind {
        K::ResetActivation => Some("successor"),
        K::ConversationClose => Some("retired"),
        K::ResetRequest | K::LeafRecoveryRequest | K::LeaveRequest => Some("prior"),
        K::LeafRecoveryCancellation | K::LeaveCancellation => None,
        K::DirectRequestPublication
        | K::DirectRequestAcceptance
        | K::CommitTransition
        | K::PolicyTransition
        | K::MetadataTransition
        | K::Creation
        | K::ParticipantAcceptance
        | K::LeafRecoveryFulfillment
        | K::ZeroLeafLeave
        | K::LeaveCommitFulfillment => Some("next"),
        _ => return Err("mutation kind has no control receipt coordinate".to_owned()),
    };
    let coordinate = match field {
        Some(field) => body.get(field),
        None => predecessor,
    }
    .filter(|value| value.is_object())
    .ok_or_else(|| "control entry has no authoritative receipt coordinate".to_owned())?;
    Ok(coordinate)
}

/// Verify an I13 control receipt against the actor-signed mutation and its successor coordinate.
pub fn verify_control_receipt(
    receipt: &Value,
    verifying_key: &VerifyingKey,
    expected_sequencer: &str,
    input: &I13ControlReceiptInput,
    coordinate: &Value,
) -> Result<(), String> {
    use base64::{engine::general_purpose::STANDARD, Engine as _};

    let text = |field: &str| {
        receipt[field]
            .as_str()
            .ok_or_else(|| format!("control receipt {field}"))
    };
    let bytes = |field: &str| {
        receipt[field]
            .as_str()
            .or_else(|| receipt[field]["$bytes"].as_str())
            .ok_or_else(|| format!("control receipt {field}"))
            .and_then(|encoded| STANDARD.decode(encoded).map_err(|error| error.to_string()))
    };
    let number = |field: &str| {
        receipt[field]
            .as_u64()
            .ok_or_else(|| format!("control receipt {field}"))
    };
    let group_id = bytes("groupId")?;
    let archive_commitment: [u8; 32] = bytes("archiveCommitment")?
        .try_into()
        .map_err(|_| "control receipt archiveCommitment length".to_owned())?;
    let signature: [u8; 64] = bytes("signature")?
        .try_into()
        .map_err(|_| "control receipt signature length".to_owned())?;
    let coordinate_group_id = coordinate["groupId"]
        .as_str()
        .or_else(|| coordinate["groupId"]["$bytes"].as_str())
        .ok_or_else(|| "control receipt coordinate groupId".to_owned())
        .and_then(|encoded| STANDARD.decode(encoded).map_err(|error| error.to_string()))?;
    let receipt_generation = number("generation")?;
    let coordinate_generation = coordinate["generation"]
        .as_u64()
        .ok_or_else(|| "control receipt coordinate generation".to_owned())?;
    let coordinate_epoch = coordinate["epoch"]
        .as_u64()
        .ok_or_else(|| "control receipt coordinate epoch".to_owned())?;
    let expected_sequencer = crate::identity::canonical_did(expected_sequencer);
    if crate::identity::canonical_did(text("sequencerDid")?) != expected_sequencer
        || text("conversationId")? != input.conversation_id
        || coordinate["conversationId"].as_str() != Some(input.conversation_id.as_str())
        || text("entryId")? != input.entry_id
        || number("seq")? != input.seq
        || receipt["issuedAtMs"].as_i64() != Some(input.issued_at_ms)
        || text("senderDid")? != input.sender_did
        || text("senderDeviceId")? != input.sender_device_id
        || archive_commitment != input.request_digest
        || receipt_generation != coordinate_generation
        || number("epoch")? != coordinate_epoch
        || group_id != coordinate_group_id
    {
        return Err("control receipt binding mismatch".to_owned());
    }
    labyrinth_protocol::receipt::verify_sequencer_receipt(
        verifying_key,
        expected_sequencer,
        &labyrinth_protocol::receipt::SignedSequencerReceipt {
            payload: labyrinth_protocol::receipt::SequencerReceiptPayload {
                sequencer_did: expected_sequencer.to_owned(),
                conversation_id: input.conversation_id.clone(),
                group_id,
                epoch: number("epoch")?,
                sender_device_did_url: format!("{}#{}", input.sender_did, input.sender_device_id),
                entry_id: input.entry_id.clone(),
                archive_commitment,
                seq: input.seq,
                issued_at_ms: input.issued_at_ms,
            },
            key_id: text("kid")?.to_owned(),
            signature,
        },
    )
    .map_err(|error| error.to_string())
}

impl I13ReceiptSigner {
    pub fn new(signing_key: SigningKey, sequencer_did: String) -> Self {
        let base = crate::identity::canonical_did(&sequencer_did).to_string();
        let key_id = labyrinth_protocol::receipt::expected_receipt_key_id(&base);
        Self {
            signing_key,
            sequencer_did: base,
            key_id,
        }
    }

    pub fn new_with_key_id(
        signing_key: SigningKey,
        sequencer_did: String,
        key_id: String,
    ) -> Result<Self, String> {
        let base = crate::identity::canonical_did(&sequencer_did).to_string();
        labyrinth_protocol::receipt::receipt_key_generation(&base, &key_id)
            .map_err(|_| "receipt key ID does not name this sequencer".to_owned())?;
        Ok(Self {
            signing_key,
            sequencer_did: base,
            key_id,
        })
    }

    #[cfg(any(test, feature = "test-support"))]
    pub fn from_signing_key_for_test(sequencer_did: String, signing_key: SigningKey) -> Self {
        Self::new(signing_key, sequencer_did)
    }

    pub fn sequencer_did(&self) -> &str {
        &self.sequencer_did
    }

    pub fn key_id(&self) -> &str {
        &self.key_id
    }

    pub fn verifying_key(&self) -> VerifyingKey {
        *self.signing_key.verifying_key()
    }

    /// Sign a `CATBIRD-RECEIPT-V1` commit receipt with the dedicated key.
    ///
    /// Hashes the raw commit ciphertext with SHA-256, constructs canonical bytes,
    /// and produces an ES256 signature.
    pub fn sign_receipt(
        &self,
        convo_id: &str,
        epoch: i32,
        sequencer_term: u64,
        commit_ciphertext: &[u8],
    ) -> SequencerReceipt {
        let commit_hash = hash_commit(commit_ciphertext);
        let issued_at = crate::sim_hooks::current_utc().timestamp();
        let canonical = canonical_receipt_bytes(
            convo_id,
            epoch,
            sequencer_term,
            &commit_hash,
            &self.sequencer_did,
            issued_at,
        );

        let sig: Signature = p256::ecdsa::signature::Signer::sign(&self.signing_key, &canonical);

        SequencerReceipt {
            convo_id: convo_id.to_string(),
            epoch,
            sequencer_term,
            commit_hash: commit_hash.to_vec(),
            sequencer_did: self.sequencer_did.clone(),
            issued_at,
            signature: sig.to_bytes().to_vec(),
        }
    }

    /// Attest an already-authorized group close, using only the dedicated I13 key.
    /// The caller must prove the applied close and current actor/roster in its
    /// transaction before calling this method; see `attach_close_authority`.
    pub fn sign_terminal_close_authority(
        &self,
        conversation_id: Uuid,
        entry: &Value,
    ) -> Result<TerminalCloseAuthority, String> {
        let mutation = terminal_close_mutation(conversation_id, entry)?;
        let mut authority = TerminalCloseAuthority {
            sequencer_did: self.sequencer_did.clone(),
            conversation_id,
            close_entry_sha256: terminal_close_entry_sha256(entry)?,
            final_roster_sha256: terminal_close_roster_sha256(mutation.actor_did().as_str()),
            actor_did: mutation.actor_did().as_str().to_string(),
            actor_device_id: Uuid::from_bytes(*mutation.actor_device_id().as_bytes()),
            actor_key_id: mutation.key_id().as_str().to_string(),
            actor_auth_generation: mutation.auth_generation(),
            key_id: self.key_id.clone(),
            signature: Vec::new(),
        };
        let signature: Signature =
            p256::ecdsa::signature::Signer::sign(&self.signing_key, &authority.signing_bytes());
        authority.signature = signature
            .normalize_s()
            .unwrap_or(signature)
            .to_bytes()
            .to_vec();
        Ok(authority)
    }

    /// Sign `deletion`, which must name this sequencer, with only the dedicated I13 key.
    pub fn sign_account_deletion(
        &self,
        deletion: &AccountDeletion,
    ) -> Result<AccountDeletionAuthority, String> {
        if deletion.sequencer_did != self.sequencer_did {
            return Err("account deletion names another sequencer".to_string());
        }
        let signature: Signature = p256::ecdsa::signature::Signer::sign(
            &self.signing_key,
            &account_deletion_authority_signing_bytes(deletion, &self.key_id),
        );
        Ok(AccountDeletionAuthority {
            sequencer_did: self.sequencer_did.clone(),
            key_id: self.key_id.clone(),
            signature: signature
                .normalize_s()
                .unwrap_or(signature)
                .to_bytes()
                .to_vec(),
        })
    }

    /// Sign an `I13` `SequencerReceiptPayload` binding `archive_commitment` to the sequenced entry.
    pub fn sign_application_receipt(
        &self,
        conversation_id: &str,
        group_id: &[u8],
        epoch: u64,
        sender_did: &str,
        sender_device_id: &str,
        entry_id: &str,
        archive_commitment: &[u8; 32],
        seq: u64,
        issued_at_ms: i64,
    ) -> Result<
        labyrinth_protocol::receipt::SignedSequencerReceipt,
        labyrinth_protocol::ProtocolError,
    > {
        let payload = labyrinth_protocol::receipt::SequencerReceiptPayload {
            sequencer_did: self.sequencer_did.clone(),
            conversation_id: conversation_id.to_string(),
            group_id: group_id.to_vec(),
            epoch,
            sender_device_did_url: format!("{sender_did}#{sender_device_id}"),
            entry_id: entry_id.to_string(),
            archive_commitment: *archive_commitment,
            seq,
            issued_at_ms,
        };
        labyrinth_protocol::receipt::sign_sequencer_receipt(
            &self.signing_key,
            &self.key_id,
            &payload,
        )
    }

    /// Capture scalar control fields from the server's transcript module.
    pub fn control_receipt_input(
        &self,
        entry: &crate::chat_protocol::transcript::VerifiedControlEntry,
    ) -> Result<I13ControlReceiptInput, String> {
        I13ControlReceiptInput::from_fields(
            entry.conversation_id().as_str(),
            entry.entry_id().as_str(),
            entry.seq(),
            entry.received_at().as_str(),
            entry.mutation().actor_did().as_str(),
            entry.mutation().actor_device_id().as_str(),
            *entry.mutation().request_digest(),
        )
    }

    /// Sign one control entry from scalar coordinate fields so repository modules included by
    /// integration tests do not have to exchange their duplicate transcript/snapshot types.
    pub fn sign_control_receipt_at(
        &self,
        input: &I13ControlReceiptInput,
        coordinate_conversation_id: &str,
        generation: u64,
        group_id: &[u8],
        epoch: u64,
    ) -> Result<Value, String> {
        if coordinate_conversation_id != input.conversation_id {
            return Err("control receipt coordinate conversation mismatch".into());
        }
        let signed = self
            .sign_application_receipt(
                &input.conversation_id,
                group_id,
                epoch,
                &input.sender_did,
                &input.sender_device_id,
                &input.entry_id,
                &input.request_digest,
                input.seq,
                input.issued_at_ms,
            )
            .map_err(|error| format!("sign control receipt: {error}"))?;
        Ok(Self::receipt_wire_json(
            &signed,
            generation,
            &input.sender_did,
            &input.sender_device_id,
        ))
    }

    /// Sign one control entry at the coordinate its transition produced. The request digest is
    /// carried in the existing I13 archive-commitment slot, binding the receipt to the exact
    /// actor-signed control bytes as well as `(conversation, seq, entry, generation, epoch)`.
    pub fn sign_control_receipt(
        &self,
        input: &I13ControlReceiptInput,
        coordinate: &crate::chat_protocol::snapshot::PublicGroupSnapshotCoordinate,
    ) -> Result<Value, String> {
        let coordinate_conversation = Uuid::from_bytes(*coordinate.conversation_id())
            .hyphenated()
            .to_string();
        self.sign_control_receipt_at(
            input,
            &coordinate_conversation,
            coordinate.generation(),
            coordinate.group_id(),
            coordinate.epoch(),
        )
    }

    /// Add a verified server-generated receipt to a generated control-entry JSON projection.
    pub fn attach_control_receipt(
        canonical_entry: &[u8],
        receipt: &Value,
    ) -> Result<Vec<u8>, String> {
        let mut entry: Value =
            serde_json::from_slice(canonical_entry).map_err(|error| error.to_string())?;
        let fields = entry
            .as_object_mut()
            .ok_or_else(|| "control entry projection is not an object".to_owned())?;
        let canonical_receipt =
            crate::chat_protocol::read_projection::encode_canonical_generated_chat_json_v1(
                receipt,
                "blue.catbird.chat.defs#sequencerReceipt",
            )
            .map_err(|error| error.to_string())?;
        let presented_receipt: Value =
            serde_json::from_slice(canonical_receipt.bytes()).map_err(|error| error.to_string())?;
        if fields
            .insert("sequencerReceipt".to_owned(), presented_receipt)
            .is_some()
        {
            return Err("control entry already carries a sequencer receipt".into());
        }
        serde_json::to_vec(&entry).map_err(|error| error.to_string())
    }

    /// Project a `SignedSequencerReceipt` + `generation` into the canonical `blue.catbird.chat.defs#sequencerReceipt` JSON object (bare base64 for internal storage; `present_endpoint_output` / `encode_canonical_generated_chat_json_v1` wrap `$bytes` on wire).
    pub fn receipt_wire_json(
        signed: &labyrinth_protocol::receipt::SignedSequencerReceipt,
        generation: u64,
        sender_did: &str,
        sender_device_id: &str,
    ) -> serde_json::Value {
        use base64::{engine::general_purpose::STANDARD, Engine as _};
        serde_json::json!({
            "conversationId": signed.payload.conversation_id,
            "generation": generation,
            "groupId": STANDARD.encode(&signed.payload.group_id),
            "epoch": signed.payload.epoch,
            "entryId": signed.payload.entry_id,
            "seq": signed.payload.seq,
            "senderDid": sender_did,
            "senderDeviceId": sender_device_id,
            "archiveCommitment": STANDARD.encode(signed.payload.archive_commitment),
            "issuedAtMs": signed.payload.issued_at_ms,
            "sequencerDid": signed.payload.sequencer_did,
            "kid": signed.key_id,
            "signature": STANDARD.encode(signed.signature),
        })
    }
}

/// A signed receipt proving the sequencer accepted and ordered a commit.
///
/// The receipt binds a conversation, epoch, and commit hash together with the
/// sequencer's ES256 signature, allowing any participant to verify the ordering
/// decision without trusting the sequencer blindly.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SequencerReceipt {
    pub convo_id: String,
    pub epoch: i32,
    pub sequencer_term: u64,
    /// SHA-256 hash of the commit ciphertext.
    pub commit_hash: Vec<u8>,
    /// DID of the sequencer that issued this receipt.
    pub sequencer_did: String,
    /// Unix timestamp (seconds) when the receipt was issued.
    pub issued_at: i64,
    /// ES256 signature over the canonical receipt bytes.
    pub signature: Vec<u8>,
}

impl SequencerReceipt {
    /// Verify the receipt signature against a known verifying key.
    ///
    /// Reconstructs the canonical byte representation and checks the ES256
    /// signature. Returns `true` if the signature is valid.
    pub fn verify(&self, verifying_key: &VerifyingKey) -> bool {
        let canonical = canonical_receipt_bytes(
            &self.convo_id,
            self.epoch,
            self.sequencer_term,
            &self.commit_hash,
            &self.sequencer_did,
            self.issued_at,
        );
        let Ok(sig) = Signature::from_slice(&self.signature) else {
            return false;
        };
        verifying_key.verify(&canonical, &sig).is_ok()
    }
}

/// Compute the SHA-256 hash of commit ciphertext.
pub fn hash_commit(ciphertext: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(ciphertext);
    hasher.finalize().into()
}

/// Build the canonical byte representation for signing/verification.
///
/// Format: `"CATBIRD-RECEIPT-V1:" || len(convo_id) (LE u32) || convo_id_bytes || epoch (BE i32) || sequencer_term (BE u64) || commit_hash || len(sequencer_did) (LE u32) || sequencer_did_bytes || issued_at (BE i64)`
pub fn canonical_receipt_bytes(
    convo_id: &str,
    epoch: i32,
    sequencer_term: u64,
    commit_hash: &[u8],
    sequencer_did: &str,
    issued_at: i64,
) -> Vec<u8> {
    let mut buf = Vec::with_capacity(
        19 + 4 + convo_id.len() + 4 + 8 + commit_hash.len() + 4 + sequencer_did.len() + 8,
    );
    // Domain separator prevents cross-protocol signature reuse
    buf.extend_from_slice(b"CATBIRD-RECEIPT-V1:");
    // Length-prefixed strings prevent collision attacks
    buf.extend_from_slice(&(convo_id.len() as u32).to_le_bytes());
    buf.extend_from_slice(convo_id.as_bytes());
    buf.extend_from_slice(&epoch.to_be_bytes());
    buf.extend_from_slice(&sequencer_term.to_be_bytes());
    buf.extend_from_slice(commit_hash);
    buf.extend_from_slice(&(sequencer_did.len() as u32).to_le_bytes());
    buf.extend_from_slice(sequencer_did.as_bytes());
    buf.extend_from_slice(&issued_at.to_be_bytes());
    buf
}

/// Reconstruct the canonical method-specific result bytes for verification against receipt `resultSha256`.
pub(crate) fn result_bytes_for_receipt(
    method: &str,
    response_bytes: &[u8],
) -> Result<Vec<u8>, FederationError> {
    match method {
        DELIVER_WELCOME_NSID | DELIVER_MESSAGE_NSID => Ok(b"{\"accepted\":true}".to_vec()),
        SUBMIT_COMMIT_NSID => {
            let output: SubmitCommitOutput =
                serde_json::from_slice(response_bytes).map_err(|e| {
                    FederationError::InvalidEnvelope {
                        reason: format!(
                            "failed to parse submitCommit response for receipt result: {e}"
                        ),
                    }
                })?;
            let st_output = SubmitTransitionOutput {
                coordinates: output.coordinates,
                entry: ConversationEntry::CommitEntry(Box::new(output.commit_entry)),
                welcomes: vec![],
                extra_data: None,
            };
            serde_json::to_vec(&st_output).map_err(|e| FederationError::InvalidEnvelope {
                reason: format!("failed to serialize reconstructed submitTransition response: {e}"),
            })
        }
        _ => Err(FederationError::InvalidEnvelope {
            reason: format!("unsupported method for receipt result reconstruction: {method}"),
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use p256::ecdsa::SigningKey;
    use p256::pkcs8::{EncodePrivateKey, LineEnding};
    use rand::rngs::OsRng;

    #[test]
    fn every_receipted_control_kind_selects_only_its_signed_coordinate() {
        use crate::chat_protocol::transcript::SignedMutationKind as K;
        use base64::{engine::general_purpose::STANDARD, Engine as _};
        use serde_json::json;

        let sequencer = "did:web:all-control-receipts.example.com";
        let conversation_id = "11111111-1111-4111-8111-111111111111";
        let coordinate = |source: &str, generation: u64, group_id: u8, epoch: u64| {
            json!({
                "source": source,
                "conversationId": conversation_id,
                "generation": generation,
                "groupId": STANDARD.encode([group_id; 32]),
                "epoch": epoch,
            })
        };
        let body = json!({
            "next": coordinate("next", 1, 0x11, 2),
            "prior": coordinate("prior", 0, 0x22, 1),
            "successor": coordinate("successor", 2, 0x33, 3),
            "retired": coordinate("retired", 3, 0x44, 4),
        });
        let body = body.as_object().unwrap();
        let predecessor = coordinate("predecessor", 4, 0x55, 5);
        let signer = I13ReceiptSigner::from_signing_key_for_test(
            sequencer.to_owned(),
            SigningKey::from_slice(&[0x41; 32]).unwrap(),
        );
        let input = I13ControlReceiptInput::from_fields(
            conversation_id,
            "22222222-2222-4222-8222-222222222222",
            7,
            "2026-11-13T12:00:00.000Z",
            "did:plc:allcontrolreceiptactor",
            "33333333-3333-4333-8333-333333333333",
            [0x66; 32],
        )
        .unwrap();
        for (kind, source) in [
            (K::DirectRequestPublication, "next"),
            (K::DirectRequestAcceptance, "next"),
            (K::CommitTransition, "next"),
            (K::PolicyTransition, "next"),
            (K::MetadataTransition, "next"),
            (K::Creation, "next"),
            (K::ParticipantAcceptance, "next"),
            (K::ConversationClose, "retired"),
            (K::ResetRequest, "prior"),
            (K::ResetActivation, "successor"),
            (K::LeafRecoveryRequest, "prior"),
            (K::LeafRecoveryCancellation, "predecessor"),
            (K::LeafRecoveryFulfillment, "next"),
            (K::LeaveRequest, "prior"),
            (K::ZeroLeafLeave, "next"),
            (K::LeaveCancellation, "predecessor"),
            (K::LeaveCommitFulfillment, "next"),
        ] {
            let selected = control_receipt_coordinate(kind, body, Some(&predecessor)).unwrap();
            assert_eq!(selected["source"], source, "{kind:?}");
            let group_id = STANDARD
                .decode(selected["groupId"].as_str().unwrap())
                .unwrap();
            let receipt = signer
                .sign_control_receipt_at(
                    &input,
                    conversation_id,
                    selected["generation"].as_u64().unwrap(),
                    &group_id,
                    selected["epoch"].as_u64().unwrap(),
                )
                .unwrap();
            verify_control_receipt(
                &receipt,
                &signer.verifying_key(),
                sequencer,
                &input,
                selected,
            )
            .unwrap();
        }

        let body_without_successor = json!({
            "next": {"source": "next"},
            "prior": {"source": "prior"},
        });
        assert!(
            control_receipt_coordinate(
                K::ResetActivation,
                body_without_successor.as_object().unwrap(),
                Some(&predecessor),
            )
            .is_err(),
            "reset activation must never fall back to another coordinate"
        );
    }

    #[test]
    fn control_receipt_verifier_accepts_only_the_signed_coordinate() {
        use base64::{engine::general_purpose::STANDARD, Engine as _};
        use serde_json::json;

        let sequencer = "did:web:receipt-coordinate.example.com";
        let conversation_id = "11111111-1111-4111-8111-111111111111";
        let signer = I13ReceiptSigner::from_signing_key_for_test(
            sequencer.to_owned(),
            SigningKey::from_slice(&[0x42; 32]).unwrap(),
        );
        let input = I13ControlReceiptInput::from_fields(
            conversation_id,
            "22222222-2222-4222-8222-222222222222",
            7,
            "2026-11-13T12:00:00.000Z",
            "did:plc:receiptcoordinateactor",
            "33333333-3333-4333-8333-333333333333",
            [0x33; 32],
        )
        .unwrap();
        let successor_group_id = [0x22; 32];
        let successor = json!({
            "conversationId": conversation_id,
            "generation": 3,
            "groupId": STANDARD.encode(successor_group_id),
            "epoch": 5,
        });
        let exact = signer
            .sign_control_receipt_at(&input, conversation_id, 3, &successor_group_id, 5)
            .unwrap();
        verify_control_receipt(
            &exact,
            &signer.verifying_key(),
            sequencer,
            &input,
            &successor,
        )
        .unwrap();

        let wrong = signer
            .sign_control_receipt_at(&input, conversation_id, 2, &[0x11; 32], 4)
            .unwrap();
        assert_eq!(
            verify_control_receipt(
                &wrong,
                &signer.verifying_key(),
                sequencer,
                &input,
                &successor,
            )
            .unwrap_err(),
            "control receipt binding mismatch"
        );
    }

    fn terminal_close_fixture() -> (Uuid, Value, [u8; 32]) {
        use base64::{engine::general_purpose::STANDARD, Engine as _};
        use serde_json::json;

        let conversation_id = Uuid::parse_str("11111111-1111-4111-8111-111111111111").unwrap();
        let actor_device = "22222222-2222-4222-8222-222222222222";
        // `.example` alone is a reserved TLD that DID validation rejects.
        let actor = "did:web:terminal-admin.example.com";
        let device_key = ed25519_dalek::SigningKey::from_bytes(&[9; 32]);
        let device_public = device_key.verifying_key().to_bytes();
        let key_id = crate::chat_protocol::validation::ed25519_key_id(&device_public).unwrap();
        let prior = json!({
            "conversationId": conversation_id,
            "generation": 0,
            "stateVersion": 4,
            "groupId": STANDARD.encode([1; 32]),
            "epoch": 3,
            "groupContextHash": STANDARD.encode([2; 32]),
            "confirmationTag": STANDARD.encode([3; 32]),
            "lifecycle": "active",
        });
        let mut retired = prior.clone();
        retired["stateVersion"] = json!(5);
        retired["lifecycle"] = json!("superseded");
        let body = json!({
            "$type": "blue.catbird.chat.defs#conversationCloseBody",
            "signatureDomain": "CATBIRD-CHAT-CLOSE\u{0}",
            "actorDid": actor,
            "actorDeviceId": actor_device,
            "keyId": key_id.as_str(),
            "authGeneration": 3,
            "signedAt": "2026-11-03T00:00:00.000Z",
            "idempotencyKey": "33333333-3333-4333-8333-333333333333",
            "transitionId": "44444444-4444-4444-8444-444444444444",
            "conversationKind": "group",
            "prior": prior,
            "retired": retired,
        });
        let mut signed: Value = serde_json::from_slice(
            &crate::sim_hooks::sign_sim_chat_body(body, &device_key).unwrap(),
        )
        .unwrap();
        // Sequenced entries present the wrapper signature as lexicon bytes.
        signed["signature"] = json!({ "$bytes": signed["signature"].clone() });
        let entry = json!({
            "$type": "blue.catbird.chat.defs#conversationCloseEntry",
            "conversationId": conversation_id,
            "entryId": "55555555-5555-4555-8555-555555555555",
            "seq": 10,
            "receivedAt": "2026-11-03T00:00:01.000Z",
            "signedRequest": signed,
            "tombstone": {
                "conversationId": conversation_id,
                "conversationKind": "group",
                "retired": retired,
                "closedByDid": actor,
                "closedByDeviceId": actor_device,
                "terminalSeq": 10,
                "closedAt": "2026-11-03T00:00:01.000Z",
            },
        });
        (conversation_id, entry, device_public)
    }

    #[test]
    fn terminal_close_authority_is_deterministic_and_binds_the_exact_group_close() {
        use serde_json::json;

        let (conversation_id, mut entry, device_public) = terminal_close_fixture();
        crate::chat_protocol::transcript::decode_and_verify_control_entry(
            &serde_json::to_vec(&entry).unwrap(),
            &device_public,
        )
        .unwrap();
        entry["sequencerReceipt"] = json!({"seq": 10, "signature": {"$bytes": "AA=="}});
        let key = SigningKey::from_slice(&[7; 32]).unwrap();
        let signer = I13ReceiptSigner::new(key.clone(), "did:web:sequencer.example".to_string());
        let proof = signer
            .sign_terminal_close_authority(conversation_id, &entry)
            .unwrap();
        assert_eq!(
            proof,
            signer
                .sign_terminal_close_authority(conversation_id, &entry)
                .unwrap()
        );
        let wire = serde_json::to_vec(&proof).unwrap();
        let decoded: TerminalCloseAuthority = serde_json::from_slice(&wire).unwrap();
        decoded
            .verify(
                &signer.verifying_key(),
                signer.sequencer_did(),
                conversation_id,
                &entry,
            )
            .unwrap();
        assert_eq!(proof.actor_auth_generation, 3);
        assert_eq!(
            proof.final_roster_sha256,
            terminal_close_roster_sha256(&proof.actor_did)
        );
        let other_id = Uuid::parse_str("66666666-6666-4666-8666-666666666666").unwrap();
        assert!(proof
            .verify(
                &signer.verifying_key(),
                signer.sequencer_did(),
                other_id,
                &entry
            )
            .is_err());
        assert!(proof
            .verify(
                &signer.verifying_key(),
                "did:web:other.example",
                conversation_id,
                &entry
            )
            .is_err());
        let other_key = SigningKey::from_slice(&[8; 32]).unwrap();
        assert!(proof
            .verify(
                other_key.verifying_key(),
                signer.sequencer_did(),
                conversation_id,
                &entry
            )
            .is_err());

        for (path, value) in [
            ("/seq", json!(11)),
            (
                "/signedRequest/body/actorDid",
                json!("did:web:attacker.example.com"),
            ),
            ("/signedRequest/body/actorDeviceId", json!(other_id)),
            ("/signedRequest/body/keyId", json!("different-key")),
            ("/signedRequest/body/authGeneration", json!(4)),
            ("/signedRequest/body/transitionId", json!(other_id)),
            ("/signedRequest/body/prior/stateVersion", json!(3)),
            ("/signedRequest/body/retired/stateVersion", json!(6)),
            ("/tombstone/closedByDid", json!("did:web:attacker.example")),
        ] {
            let mut changed = entry.clone();
            *changed.pointer_mut(path).unwrap() = value;
            assert!(
                proof
                    .verify(
                        &signer.verifying_key(),
                        signer.sequencer_did(),
                        conversation_id,
                        &changed
                    )
                    .is_err(),
                "{path}"
            );
        }
        for (field, value) in [
            ("sequencerDid", json!("did:web:other.example")),
            ("conversationId", json!(other_id)),
            ("closeEntrySha256", json!(vec![0_u8; 32])),
            ("finalRosterSha256", json!(vec![0_u8; 32])),
            ("actorDid", json!("did:web:attacker.example")),
            ("actorDeviceId", json!(other_id)),
            ("actorKeyId", json!("different-key")),
            ("actorAuthGeneration", json!(4)),
            ("keyId", json!("did:web:sequencer.example#atproto")),
            ("signature", json!(vec![0_u8; 64])),
        ] {
            let mut changed: Value = serde_json::from_slice(&wire).unwrap();
            changed[field] = value;
            let changed: TerminalCloseAuthority = serde_json::from_value(changed).unwrap();
            assert!(
                changed
                    .verify(
                        &signer.verifying_key(),
                        signer.sequencer_did(),
                        conversation_id,
                        &entry
                    )
                    .is_err(),
                "{field}"
            );
        }
        let mut cross_protocol = proof;
        cross_protocol.signature = I13ReceiptSigner::new(key, signer.sequencer_did().to_string())
            .sign_receipt(&conversation_id.to_string(), 3, 0, b"commit")
            .signature;
        assert!(cross_protocol
            .verify(
                &signer.verifying_key(),
                signer.sequencer_did(),
                conversation_id,
                &entry
            )
            .is_err());

        let mut direct = entry.clone();
        direct["signedRequest"]["body"]["conversationKind"] = json!("direct");
        assert!(signer
            .sign_terminal_close_authority(conversation_id, &direct)
            .is_err());
        assert!(signer
            .sign_terminal_close_authority(other_id, &entry)
            .is_err());
    }

    fn pem(key: &SigningKey) -> String {
        key.to_pkcs8_pem(LineEnding::LF)
            .expect("encode test key")
            .to_string()
    }

    fn did_document(method_id: &str, controller: &str, key: &VerifyingKey) -> String {
        let mut multikey = vec![0x80, 0x24]; // unsigned-varint multicodec p256-pub (0x1200)
        multikey.extend_from_slice(key.to_encoded_point(true).as_bytes());
        let public_key_multibase = multibase::encode(multibase::Base::Base58Btc, multikey);
        serde_json::json!({
            "id": "did:web:chat.catbird.blue",
            "verificationMethod": [{
                "id": method_id,
                "type": "Multikey",
                "controller": controller,
                "publicKeyMultibase": public_key_multibase,
            }],
        })
        .to_string()
    }

    #[test]
    fn receipt_did_document_requires_fixed_method() {
        let receipt_key = SigningKey::random(&mut OsRng);
        let document = did_document(
            "did:web:chat.catbird.blue#atproto",
            "did:web:chat.catbird.blue",
            receipt_key.verifying_key(),
        );

        assert_eq!(
            validate_receipt_did_document(&document, receipt_key.verifying_key(), None),
            Err(ReceiptDidDocumentError::MissingReceiptMethod)
        );
    }

    #[test]
    fn receipt_did_document_rejects_wrong_controller() {
        let receipt_key = SigningKey::random(&mut OsRng);
        let document = did_document(
            RECEIPT_VERIFICATION_METHOD,
            "did:web:attacker.example",
            receipt_key.verifying_key(),
        );

        assert_eq!(
            validate_receipt_did_document(&document, receipt_key.verifying_key(), None),
            Err(ReceiptDidDocumentError::ControllerMismatch)
        );
    }

    #[test]
    fn receipt_did_document_rejects_duplicate_fixed_method() {
        let receipt_key = SigningKey::random(&mut OsRng);
        let document = did_document(
            RECEIPT_VERIFICATION_METHOD,
            "did:web:chat.catbird.blue",
            receipt_key.verifying_key(),
        );
        let mut document: serde_json::Value = serde_json::from_str(&document).unwrap();
        let duplicate = document["verificationMethod"][0].clone();
        document["verificationMethod"]
            .as_array_mut()
            .unwrap()
            .push(duplicate);

        assert_eq!(
            validate_receipt_did_document(
                &serde_json::to_string(&document).unwrap(),
                receipt_key.verifying_key(),
                None,
            ),
            Err(ReceiptDidDocumentError::AmbiguousReceiptMethod)
        );
    }

    #[test]
    fn receipt_did_document_rejects_service_auth_key_reuse() {
        let shared_key = SigningKey::random(&mut OsRng);
        let document = did_document(
            RECEIPT_VERIFICATION_METHOD,
            "did:web:chat.catbird.blue",
            shared_key.verifying_key(),
        );

        assert_eq!(
            validate_receipt_did_document(
                &document,
                shared_key.verifying_key(),
                Some(shared_key.verifying_key()),
            ),
            Err(ReceiptDidDocumentError::ServiceAuthKeyReuse)
        );
    }

    #[test]
    fn receipt_did_document_rejects_signer_key_mismatch() {
        let published_key = SigningKey::random(&mut OsRng);
        let signer_key = SigningKey::random(&mut OsRng);
        let document = did_document(
            RECEIPT_VERIFICATION_METHOD,
            "did:web:chat.catbird.blue",
            published_key.verifying_key(),
        );

        assert_eq!(
            validate_receipt_did_document(&document, signer_key.verifying_key(), None),
            Err(ReceiptDidDocumentError::SignerKeyMismatch)
        );
    }

    #[test]
    fn receipt_did_document_accepts_dedicated_published_key() {
        let receipt_key = SigningKey::random(&mut OsRng);
        let service_key = SigningKey::random(&mut OsRng);
        let document = did_document(
            RECEIPT_VERIFICATION_METHOD,
            "did:web:chat.catbird.blue",
            receipt_key.verifying_key(),
        );

        assert_eq!(
            validate_receipt_did_document(
                &document,
                receipt_key.verifying_key(),
                Some(service_key.verifying_key()),
            ),
            Ok(())
        );
    }

    #[test]
    fn receipt_rotation_requires_retained_contiguous_history_and_selects_exact_key_id() {
        let key1 = SigningKey::random(&mut OsRng);
        let key2 = SigningKey::random(&mut OsRng);
        let service_key = SigningKey::random(&mut OsRng);
        let key2_id = "did:web:chat.catbird.blue#mls-receipt-2";
        let method1: serde_json::Value = serde_json::from_str(&did_document(
            RECEIPT_VERIFICATION_METHOD,
            "did:web:chat.catbird.blue",
            key1.verifying_key(),
        ))
        .unwrap();
        let method2: serde_json::Value = serde_json::from_str(&did_document(
            key2_id,
            "did:web:chat.catbird.blue",
            key2.verifying_key(),
        ))
        .unwrap();
        let document = serde_json::json!({
            "id": "did:web:chat.catbird.blue",
            "verificationMethod": [
                method1["verificationMethod"][0].clone(),
                method2["verificationMethod"][0].clone(),
            ],
        })
        .to_string();

        assert_eq!(
            validate_receipt_did_document_method_for_service(
                &document,
                "did:web:chat.catbird.blue",
                key2_id,
                key2.verifying_key(),
                Some(service_key.verifying_key()),
            ),
            Ok(())
        );
        let signer = I13ReceiptSigner::new_with_key_id(
            key2.clone(),
            "did:web:chat.catbird.blue".to_owned(),
            key2_id.to_owned(),
        )
        .unwrap();
        assert_eq!(signer.key_id(), key2_id);
        let configured = configured_receipt_signer(
            Some("issue"),
            Some(&pem(&key2)),
            Some(key2_id),
            Some(&pem(&service_key)),
            "did:web:chat.catbird.blue",
            Some(&document),
        )
        .unwrap()
        .expect("issue mode signer");
        assert_eq!(configured.key_id(), key2_id);

        let missing_history =
            did_document(key2_id, "did:web:chat.catbird.blue", key2.verifying_key());
        assert_eq!(
            validate_receipt_did_document_method_for_service(
                &missing_history,
                "did:web:chat.catbird.blue",
                key2_id,
                key2.verifying_key(),
                None,
            ),
            Err(ReceiptDidDocumentError::ReceiptHistoryGap)
        );
        assert_eq!(
            validate_receipt_did_document_method_for_service(
                &document,
                "did:web:chat.catbird.blue",
                RECEIPT_VERIFICATION_METHOD,
                key1.verifying_key(),
                None,
            ),
            Err(ReceiptDidDocumentError::ConfiguredMethodNotCurrent)
        );

        // A verifier selects the exact retained method a proof's `kid` names,
        // newest or not, and still requires the whole history.
        let owner = "did:web:chat.catbird.blue";
        let resolved: serde_json::Value = serde_json::from_str(&document).unwrap();
        for (key_id, key) in [(RECEIPT_VERIFICATION_METHOD, &key1), (key2_id, &key2)] {
            assert_eq!(
                retained_receipt_key(&resolved, owner, key_id),
                Ok(*key.verifying_key())
            );
        }
        let gap: serde_json::Value = serde_json::from_str(&missing_history).unwrap();
        assert_eq!(
            retained_receipt_key(&gap, owner, key2_id),
            Err(ReceiptDidDocumentError::ReceiptHistoryGap)
        );
        assert_eq!(
            retained_receipt_key(&resolved, owner, &format!("{owner}#mls-receipt-3")),
            Err(ReceiptDidDocumentError::MissingReceiptMethod)
        );
        assert_eq!(
            retained_receipt_key(&resolved, owner, "did:web:attacker.example#mls-receipt-1"),
            Err(ReceiptDidDocumentError::DocumentOwnerMismatch)
        );
    }

    #[test]
    fn issue_mode_requires_dedicated_receipt_key() {
        let service_key = SigningKey::random(&mut OsRng);
        let error = configured_receipt_signer(
            Some("issue"),
            None,
            Some(RECEIPT_VERIFICATION_METHOD),
            Some(&pem(&service_key)),
            "did:web:chat.catbird.blue",
            None,
        )
        .expect_err("missing dedicated receipt key must fail closed");

        assert_eq!(error, ReceiptConfigError::MissingSigningKey);
    }

    #[test]
    fn issue_mode_rejects_malformed_receipt_key() {
        let service_key = SigningKey::random(&mut OsRng);
        let error = configured_receipt_signer(
            Some("issue"),
            Some("not-a-private-key"),
            Some(RECEIPT_VERIFICATION_METHOD),
            Some(&pem(&service_key)),
            "did:web:chat.catbird.blue",
            None,
        )
        .expect_err("malformed dedicated receipt key must fail closed");

        assert_eq!(error, ReceiptConfigError::MalformedSigningKey);
    }

    #[test]
    fn issue_mode_requires_fixed_verification_method() {
        let receipt_key = SigningKey::random(&mut OsRng);
        let service_key = SigningKey::random(&mut OsRng);
        let error = configured_receipt_signer(
            Some("issue"),
            Some(&pem(&receipt_key)),
            Some("did:web:chat.catbird.blue#service-auth"),
            Some(&pem(&service_key)),
            "did:web:chat.catbird.blue",
            None,
        )
        .expect_err("a different verification method must fail closed");

        assert_eq!(error, ReceiptConfigError::UnexpectedVerificationMethod);
    }

    #[test]
    fn issue_mode_requires_service_did_to_own_fixed_method() {
        let receipt_key = SigningKey::random(&mut OsRng);
        let service_key = SigningKey::random(&mut OsRng);
        let error = configured_receipt_signer(
            Some("issue"),
            Some(&pem(&receipt_key)),
            Some(RECEIPT_VERIFICATION_METHOD),
            Some(&pem(&service_key)),
            "did:web:other.example",
            None,
        )
        .expect_err("the configured service DID must own the receipt method");

        assert_eq!(error, ReceiptConfigError::VerificationMethodOwnerMismatch);
    }

    #[test]
    fn issue_mode_rejects_service_auth_key_reuse() {
        let shared_key = SigningKey::random(&mut OsRng);
        let shared_pem = pem(&shared_key);
        let error = configured_receipt_signer(
            Some("issue"),
            Some(&shared_pem),
            Some(RECEIPT_VERIFICATION_METHOD),
            Some(&shared_pem),
            "did:web:chat.catbird.blue",
            None,
        )
        .expect_err("receipt and service-auth keys must be distinct");

        assert_eq!(error, ReceiptConfigError::ServiceAuthKeyReuse);
    }

    #[test]
    fn issue_mode_builds_signer_only_from_dedicated_key() {
        let receipt_key = SigningKey::random(&mut OsRng);
        let service_key = SigningKey::random(&mut OsRng);
        let document = did_document(
            RECEIPT_VERIFICATION_METHOD,
            "did:web:chat.catbird.blue",
            receipt_key.verifying_key(),
        );
        let signer = configured_receipt_signer(
            Some("issue"),
            Some(&pem(&receipt_key)),
            Some(RECEIPT_VERIFICATION_METHOD),
            Some(&pem(&service_key)),
            "did:web:chat.catbird.blue",
            Some(&document),
        )
        .expect("valid receipt configuration")
        .expect("issue mode signer");

        assert_eq!(signer.verifying_key(), *receipt_key.verifying_key());
        assert_ne!(signer.verifying_key(), *service_key.verifying_key());
    }

    #[test]
    fn disabled_mode_does_not_fall_back_to_service_auth_key() {
        let service_key = SigningKey::random(&mut OsRng);
        let signer = configured_receipt_signer(
            Some("disabled"),
            None,
            None,
            Some(&pem(&service_key)),
            "did:web:chat.catbird.blue",
            None,
        )
        .expect("disabled mode is valid");

        assert!(signer.is_none());
    }

    #[test]
    fn issue_mode_requires_valid_service_auth_key_for_separation() {
        let receipt_key = SigningKey::random(&mut OsRng);
        let document = did_document(
            RECEIPT_VERIFICATION_METHOD,
            "did:web:chat.catbird.blue",
            receipt_key.verifying_key(),
        );
        let missing = configured_receipt_signer(
            Some("issue"),
            Some(&pem(&receipt_key)),
            Some(RECEIPT_VERIFICATION_METHOD),
            None,
            "did:web:chat.catbird.blue",
            Some(&document),
        )
        .expect_err("missing service key cannot prove key separation");
        assert_eq!(missing, ReceiptConfigError::MissingServiceAuthKey);

        let malformed = configured_receipt_signer(
            Some("issue"),
            Some(&pem(&receipt_key)),
            Some(RECEIPT_VERIFICATION_METHOD),
            Some("not-a-private-key"),
            "did:web:chat.catbird.blue",
            Some(&document),
        )
        .expect_err("malformed service key cannot prove key separation");
        assert_eq!(malformed, ReceiptConfigError::MalformedServiceAuthKey);
    }

    #[test]
    fn issue_mode_requires_published_did_document() {
        let receipt_key = SigningKey::random(&mut OsRng);
        let service_key = SigningKey::random(&mut OsRng);
        let error = configured_receipt_signer(
            Some("issue"),
            Some(&pem(&receipt_key)),
            Some(RECEIPT_VERIFICATION_METHOD),
            Some(&pem(&service_key)),
            "did:web:chat.catbird.blue",
            None,
        )
        .expect_err("issue mode without the published document must fail startup");
        assert_eq!(error, ReceiptConfigError::MissingPublishedDidDocument);
    }

    #[test]
    fn issue_mode_rejects_tampered_or_wrong_published_did_document() {
        let receipt_key = SigningKey::random(&mut OsRng);
        let service_key = SigningKey::random(&mut OsRng);
        let wrong_key = SigningKey::random(&mut OsRng);
        let wrong_key_document = did_document(
            RECEIPT_VERIFICATION_METHOD,
            "did:web:chat.catbird.blue",
            wrong_key.verifying_key(),
        );
        let wrong_key_error = configured_receipt_signer(
            Some("issue"),
            Some(&pem(&receipt_key)),
            Some(RECEIPT_VERIFICATION_METHOD),
            Some(&pem(&service_key)),
            "did:web:chat.catbird.blue",
            Some(&wrong_key_document),
        )
        .expect_err("a document publishing another key must fail startup");
        assert_eq!(
            wrong_key_error,
            ReceiptConfigError::InvalidPublishedDidDocument(
                ReceiptDidDocumentError::SignerKeyMismatch
            )
        );

        let tampered_controller = did_document(
            RECEIPT_VERIFICATION_METHOD,
            "did:web:attacker.example",
            receipt_key.verifying_key(),
        );
        let tamper_error = configured_receipt_signer(
            Some("issue"),
            Some(&pem(&receipt_key)),
            Some(RECEIPT_VERIFICATION_METHOD),
            Some(&pem(&service_key)),
            "did:web:chat.catbird.blue",
            Some(&tampered_controller),
        )
        .expect_err("a tampered controller must fail startup");
        assert_eq!(
            tamper_error,
            ReceiptConfigError::InvalidPublishedDidDocument(
                ReceiptDidDocumentError::ControllerMismatch
            )
        );
    }

    #[test]
    fn canonical_receipt_v1_golden_includes_sequencer_term() {
        let bytes = canonical_receipt_bytes(
            "c",
            0x0102_0304,
            0x0102_0304_0506_0708,
            &[0xabu8; 32],
            "did:web:chat.catbird.blue",
            0x0102_0304_0506_0708,
        );

        assert_eq!(
            hex::encode(bytes),
            "434154424952442d524543454950542d56313a0100000063010203040102030405060708abababababababababababababababababababababababababababababababab190000006469643a7765623a636861742e636174626972642e626c75650102030405060708"
        );
    }

    #[test]
    fn sign_and_verify_round_trip() {
        let sk = SigningKey::random(&mut OsRng);
        let signer = I13ReceiptSigner::new(sk.clone(), "did:web:ds.example.com".to_string());
        let vk = signer.verifying_key();

        let receipt = signer.sign_receipt("convo-123", 5, 2, b"fake-commit-ciphertext");

        assert_eq!(receipt.convo_id, "convo-123");
        assert_eq!(receipt.epoch, 5);
        assert_eq!(receipt.sequencer_term, 2);
        assert_eq!(
            receipt.commit_hash,
            hash_commit(b"fake-commit-ciphertext").to_vec()
        );
        assert_eq!(receipt.sequencer_did, "did:web:ds.example.com");
        assert!(
            receipt.verify(&vk),
            "receipt should verify with correct key"
        );
    }

    #[test]
    fn signer_canonicalizes_fragmented_service_did() {
        let signer = I13ReceiptSigner::new(
            SigningKey::random(&mut OsRng),
            "did:web:ds.example.com#mls".to_string(),
        );

        let receipt = signer.sign_receipt("convo-fragment", 6, 3, b"commit");

        assert_eq!(receipt.sequencer_did, "did:web:ds.example.com");
    }

    #[test]
    fn verify_rejects_wrong_key() {
        let sk = SigningKey::random(&mut OsRng);
        let signer = I13ReceiptSigner::new(sk, "did:web:ds.example.com".to_string());
        let receipt = signer.sign_receipt("convo-456", 1, 1, b"data");

        let other_sk = SigningKey::random(&mut OsRng);
        let wrong_vk = *other_sk.verifying_key();
        assert!(
            !receipt.verify(&wrong_vk),
            "receipt should not verify with wrong key"
        );
    }

    #[test]
    fn verify_rejects_tampered_receipt() {
        let sk = SigningKey::random(&mut OsRng);
        let signer = I13ReceiptSigner::new(sk.clone(), "did:web:ds.example.com".to_string());
        let vk = signer.verifying_key();

        let mut receipt = signer.sign_receipt("convo-789", 3, 9, b"original");
        receipt.epoch = 4; // tamper
        assert!(!receipt.verify(&vk), "tampered receipt should not verify");
    }

    #[test]
    fn verify_rejects_each_authority_binding_tamper() {
        let signer = I13ReceiptSigner::new(
            SigningKey::random(&mut OsRng),
            "did:web:ds.example.com".to_string(),
        );
        let verifying_key = signer.verifying_key();
        let receipt = signer.sign_receipt("convo-bound", 7, 11, b"commit");

        let mut conversation = receipt.clone();
        conversation.convo_id = "convo-other".into();
        assert!(!conversation.verify(&verifying_key));

        let mut epoch = receipt.clone();
        epoch.epoch += 1;
        assert!(!epoch.verify(&verifying_key));

        let mut term = receipt.clone();
        term.sequencer_term += 1;
        assert!(!term.verify(&verifying_key));

        let mut digest = receipt;
        digest.commit_hash[0] ^= 0xff;
        assert!(!digest.verify(&verifying_key));
    }

    #[test]
    fn hash_commit_is_deterministic() {
        let h1 = hash_commit(b"hello world");
        let h2 = hash_commit(b"hello world");
        assert_eq!(h1, h2);
        assert_ne!(hash_commit(b"hello world"), hash_commit(b"other data"));
    }

    #[test]
    fn serde_round_trip() {
        let sk = SigningKey::random(&mut OsRng);
        let signer = I13ReceiptSigner::new(sk, "did:web:ds.example.com".to_string());
        let receipt = signer.sign_receipt("convo-serde", 10, 3, b"ciphertext");

        let json = serde_json::to_string(&receipt).expect("serialize");
        let deserialized: SequencerReceipt = serde_json::from_str(&json).expect("deserialize");

        assert_eq!(deserialized.convo_id, receipt.convo_id);
        assert_eq!(deserialized.epoch, receipt.epoch);
        assert_eq!(deserialized.commit_hash, receipt.commit_hash);
        assert_eq!(deserialized.signature, receipt.signature);

        let vk = signer.verifying_key();
        assert!(
            deserialized.verify(&vk),
            "deserialized receipt should verify"
        );
    }

    #[test]
    fn result_bytes_for_receipt_deliver_welcome_and_message() {
        let welcome_bytes = result_bytes_for_receipt(DELIVER_WELCOME_NSID, b"{}").unwrap();
        assert_eq!(welcome_bytes, b"{\"accepted\":true}");

        let msg_bytes =
            result_bytes_for_receipt(DELIVER_MESSAGE_NSID, b"{\"extra\":\"value\"}").unwrap();
        assert_eq!(msg_bytes, b"{\"accepted\":true}");
    }

    #[test]
    fn result_bytes_for_receipt_submit_commit() {
        use base64::engine::general_purpose::STANDARD;
        use base64::Engine as _;
        let b64_32 = STANDARD.encode([1u8; 32]);
        let b64_48 = STANDARD.encode([1u8; 48]);
        let b64_12 = STANDARD.encode([1u8; 12]);
        let b64_64 = STANDARD.encode([1u8; 64]);
        let b0_32 = STANDARD.encode([0u8; 32]);
        let b32_arr = serde_json::to_string(&vec![1u8; 32]).unwrap();
        let b16 = serde_json::to_string(&vec![1u8; 16]).unwrap();

        let json_str = format!(
            r#"{{
            "commitEntry": {{
                "conversationId": "convo-1",
                "entryId": "entry-1",
                "receivedAt": "2026-08-25T12:00:00Z",
                "seq": 1,
                "signedRequest": {{
                    "body": {{
                        "$type": "blue.catbird.chat.defs#commitTransitionBody",
                        "signatureDomain": "CATBIRD-CHAT-COMMIT\u0000",
                        "transitionId": "t-1",
                        "idempotencyKey": "idem-1",
                        "actorDid": "did:plc:alice",
                        "actorDeviceId": "dev-1",
                        "keyId": "k-1",
                        "authGeneration": 1,
                        "signedAt": "2026-08-25T12:00:00Z",
                        "conversationId": "convo-1",
                        "prior": {{
                            "conversationId": "convo-1",
                            "generation": 0,
                            "stateVersion": 0,
                            "groupId": {{"$bytes": "{b64_32}"}},
                            "epoch": 0,
                            "groupContextHash": {{"$bytes": "{b64_32}"}},
                            "confirmationTag": {{"$bytes": "{b64_32}"}},
                            "lifecycle": "active"
                        }},
                        "next": {{
                            "conversationId": "convo-1",
                            "generation": 0,
                            "stateVersion": 1,
                            "groupId": {{"$bytes": "{b64_32}"}},
                            "epoch": 1,
                            "groupContextHash": {{"$bytes": "{b64_32}"}},
                            "confirmationTag": {{"$bytes": "{b64_32}"}},
                            "lifecycle": "active"
                        }},
                        "aad": {{
                            "protocolVersion": "1",
                            "conversationId": {b16},
                            "generation": 0,
                            "transitionId": {b16},
                            "prior": {{
                                "conversationId": {b16},
                                "generation": 0,
                                "stateVersion": 0,
                                "groupId": {{"$bytes": "{b64_32}"}},
                                "epoch": 0,
                                "groupContextHash": {{"$bytes": "{b64_32}"}},
                                "confirmationTag": {{"$bytes": "{b64_32}"}},
                                "lifecycle": "active"
                            }}
                        }},
                        "manifest": {{
                            "participantChanges": [],
                            "leafChanges": []
                        }},
                        "commit": {{
                            "framing": "mlsMessage",
                            "contentType": "publicMessageCommit",
                            "bytes": {{"$bytes": "{b64_48}"}},
                            "sha256": {b32_arr}
                        }},
                        "metadataSnapshot": {{
                            "coordinate": {{
                                "conversationId": {b16},
                                "generation": 0,
                                "groupId": {{"$bytes": "{b64_32}"}},
                                "epoch": 1,
                                "groupContextHash": {{"$bytes": "{b64_32}"}},
                                "confirmationTag": {{"$bytes": "{b64_32}"}}
                            }},
                            "originTransitionId": "t-0",
                            "metadataVersion": 1,
                            "nonce": {{"$bytes": "{b64_12}"}},
                            "ciphertext": {{"$bytes": "{b64_48}"}},
                            "ciphertextSha256": {b32_arr},
                            "ciphertextSize": 48,
                            "authorProof": {{
                                "authorDid": "did:plc:alice",
                                "authorDeviceId": "dev-1",
                                "authorKeyId": "k-1",
                                "signaturePublicKey": {{"$bytes": "{b64_32}"}},
                                "authGenerationAtOrigin": 1,
                                "originTransitionId": "t-0",
                                "originSeq": 1,
                                "roleAtOrigin": "admin",
                                "deviceStatusAtOrigin": "active"
                            }}
                        }}
                    }},
                    "signature": {{"$bytes": "{b64_64}"}}
                }}
            }},
            "coordinates": {{
                "confirmationTag": {{"$bytes": "{b64_32}"}},
                "conversationId": "convo-1",
                "epoch": 1,
                "generation": 0,
                "groupContextHash": {{"$bytes": "{b64_32}"}},
                "groupId": {{"$bytes": "{b64_32}"}},
                "lifecycle": "active",
                "stateVersion": 1
            }},
            "receipt": {{
                "protocolVersion": "1",
                "deliveryId": "deliv-1",
                "endpoint": "blue.catbird.mlsDS.submitCommit",
                "conversationId": "convo-1",
                "senderDsDid": "did:web:sender.example",
                "receiverDsDid": "did:web:receiver.example",
                "sequencerDid": "did:web:sequencer.example",
                "sequencerTerm": 1,
                "envelopeSha256": {{"$bytes": "{b0_32}"}},
                "resultSha256": {{"$bytes": "{b0_32}"}},
                "sourceLocator": {{
                    "entryId": "entry-1",
                    "seq": 1,
                    "acceptedPayloadSha256": {{"$bytes": "{b64_32}"}},
                    "outerEntryFingerprint": {{"$bytes": "{b64_32}"}}
                }},
                "signature": {{"$bytes": "{b64_64}"}},
                "completedAt": "2026-08-25T12:00:00Z"
            }},
            "welcomes": []
        }}"#
        );
        let resp_bytes = json_str.into_bytes();
        let result = result_bytes_for_receipt(SUBMIT_COMMIT_NSID, &resp_bytes).unwrap();

        let parsed_st: serde_json::Value = serde_json::from_slice(&result).unwrap();
        assert_eq!(parsed_st["coordinates"]["epoch"], 1);
        assert_eq!(parsed_st["entry"]["seq"], 1);
    }

    #[test]
    fn result_bytes_for_receipt_rejects_unknown_method_and_malformed_json() {
        assert!(result_bytes_for_receipt("blue.catbird.mlsDS.unknown", b"{}").is_err());
        assert!(result_bytes_for_receipt(SUBMIT_COMMIT_NSID, b"not json").is_err());
    }

    #[test]
    fn an_account_deletion_authority_binds_every_field_of_its_canonical_entry() {
        use base64::{engine::general_purpose::STANDARD, Engine as _};
        use serde_json::json;

        const SEQUENCER: &str = "did:web:sequencer.example.com";
        const CONVERSATION: &str = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";
        const ENTRY: &str = "33333333-3333-4333-8333-333333333333";
        let signer = I13ReceiptSigner::new(
            SigningKey::from_slice(&[7; 32]).unwrap(),
            SEQUENCER.to_string(),
        );
        let key = signer.verifying_key();
        let deletion = AccountDeletion {
            sequencer_did: SEQUENCER.to_string(),
            conversation_id: Uuid::parse_str(CONVERSATION).unwrap(),
            deleted_did: "did:web:deleted.example.com".to_string(),
            seq: 12,
            entry_id: Uuid::parse_str(ENTRY).unwrap(),
            deleted_at: "2026-11-03T12:00:00.123Z".parse().unwrap(),
            evidence: None,
        };
        let mut expected = b"catbird-mls-account-deletion-v1\0".to_vec();
        for field in [
            SEQUENCER,
            CONVERSATION,
            "did:web:deleted.example.com",
            "12",
            ENTRY,
            "2026-11-03T12:00:00.123Z",
        ] {
            expected.extend_from_slice(&(field.len() as u32).to_be_bytes());
            expected.extend_from_slice(field.as_bytes());
        }
        assert_eq!(deletion.signing_bytes(), expected);

        let authority = signer.sign_account_deletion(&deletion).unwrap();
        assert_eq!(authority, signer.sign_account_deletion(&deletion).unwrap());
        assert_eq!(authority.key_id, format!("{SEQUENCER}#mls-receipt-1"));
        authority.verify(&key, &deletion).unwrap();
        let entry = deletion.entry(&authority);
        assert_eq!(
            entry["sequencerAuthority"]["signature"]["$bytes"],
            STANDARD.encode(&authority.signature)
        );
        assert_eq!(
            AccountDeletion::from_entry(&entry).unwrap(),
            (deletion.clone(), authority.clone())
        );

        // Every bound field, altered after signing.
        for edit in [
            (|d: &mut AccountDeletion| d.sequencer_did = "did:web:other.example.com".into())
                as fn(&mut AccountDeletion),
            |d| d.conversation_id = Uuid::new_v4(),
            |d| d.deleted_did = "did:web:other.example.com".into(),
            |d| d.seq += 1,
            |d| d.entry_id = Uuid::new_v4(),
            |d| d.deleted_at += chrono::TimeDelta::milliseconds(1),
        ] {
            let mut changed = deletion.clone();
            edit(&mut changed);
            assert!(authority.verify(&key, &changed).is_err(), "{changed:?}");
        }
        // Another key id, another sequencer's key, or the high-S twin.
        let mut other_method = authority.clone();
        other_method.key_id = format!("{SEQUENCER}#atproto");
        assert!(other_method.verify(&key, &deletion).is_err());
        let mut other_generation = authority.clone();
        other_generation.key_id = format!("{SEQUENCER}#mls-receipt-2");
        assert!(other_generation.verify(&key, &deletion).is_err());
        let other_key = SigningKey::from_slice(&[8; 32]).unwrap();
        assert!(authority
            .verify(other_key.verifying_key(), &deletion)
            .is_err());
        let (r, s) = Signature::from_slice(&authority.signature)
            .unwrap()
            .split_scalars();
        let mut high_s = authority.clone();
        high_s.signature = Signature::from_scalars(r, -s).unwrap().to_bytes().to_vec();
        assert!(high_s.verify(&key, &deletion).is_err());
        let mut foreign = deletion.clone();
        foreign.sequencer_did = "did:web:other.example.com".into();
        assert!(signer.sign_account_deletion(&foreign).is_err());

        // Only the exact canonical entry parses.
        for edit in [
            (|e: &mut Value| e["receivedAt"] = json!("2026-11-03T12:00:00.123+00:00"))
                as fn(&mut Value),
            |e| e["receivedAt"] = json!("2026-11-03T12:00:00Z"),
            |e| e["conversationId"] = json!(CONVERSATION.to_uppercase()),
            |e| e["seq"] = json!(0),
            |e| e["$type"] = json!("blue.catbird.chat.defs#applicationEntry"),
            |e| e["signature"] = json!(STANDARD.encode([0; 64])),
            |e| {
                e.as_object_mut().unwrap().remove("sequencerAuthority");
            },
            |e| {
                let bare = e["sequencerAuthority"]["signature"]["$bytes"].clone();
                e["sequencerAuthority"]["signature"] = bare;
            },
        ] {
            let mut changed = entry.clone();
            edit(&mut changed);
            assert!(AccountDeletion::from_entry(&changed).is_err(), "{changed}");
        }
    }

    fn evidenced_deletion(evidence: Option<AccountDeletionEvidence>) -> AccountDeletion {
        AccountDeletion {
            sequencer_did: "did:web:sequencer.example.com".to_string(),
            conversation_id: Uuid::parse_str("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa").unwrap(),
            deleted_did: "did:web:deleted.example.com".to_string(),
            seq: 12,
            entry_id: Uuid::parse_str("33333333-3333-4333-8333-333333333333").unwrap(),
            deleted_at: "2026-11-03T12:00:00.123Z".parse().unwrap(),
            evidence,
        }
    }

    fn device_evidence(pad_to: usize, key_proof: Option<Vec<u8>>) -> AccountDeletionEvidence {
        AccountDeletionEvidence::signed_for_test(
            &ed25519_dalek::SigningKey::from_bytes(&[9; 32]),
            Uuid::parse_str("44444444-4444-4444-8444-444444444444").unwrap(),
            [0x0D; 16],
            "2026-11-03T12:00:00.100Z".parse().unwrap(),
            pad_to,
            key_proof,
        )
    }

    #[test]
    fn an_account_deleted_entry_carries_its_devices_signed_write_and_key_proof_verbatim() {
        use base64::{engine::general_purpose::STANDARD, Engine as _};
        use serde_json::json;

        let signer = I13ReceiptSigner::new(
            SigningKey::from_slice(&[7; 32]).unwrap(),
            "did:web:sequencer.example.com".to_string(),
        );
        let evidence = device_evidence(0, Some(vec![0xAB; 300]));
        let bare = evidenced_deletion(None);
        let deletion = evidenced_deletion(Some(evidence.clone()));
        // The sequencer's authority binds exactly what it always did.
        assert_eq!(deletion.signing_bytes(), bare.signing_bytes());
        let authority = signer.sign_account_deletion(&deletion).unwrap();
        authority.verify(&signer.verifying_key(), &bare).unwrap();

        let entry = deletion.entry(&authority);
        assert_eq!(
            entry["actorWrite"],
            json!({
                "writeBody": { "$bytes": STANDARD.encode(&evidence.actor_write.write_body) },
                "signature": { "$bytes": STANDARD.encode(&evidence.actor_write.signature) },
            })
        );
        assert_eq!(
            entry["keyProof"],
            json!({ "$bytes": STANDARD.encode([0xAB; 300]) })
        );
        let (parsed, parsed_authority) = AccountDeletion::from_entry(&entry).unwrap();
        assert_eq!((&parsed, &parsed_authority), (&deletion, &authority));
        assert_eq!(parsed.entry(&parsed_authority), entry);

        // An actorWrite without a keyProof, and an entry stored before either.
        let without_proof = evidenced_deletion(Some(device_evidence(0, None)));
        let entry_without_proof = without_proof.entry(&authority);
        assert!(entry_without_proof.get("keyProof").is_none());
        assert_eq!(
            AccountDeletion::from_entry(&entry_without_proof).unwrap().0,
            without_proof
        );
        let old = bare.entry(&authority);
        assert!(old.get("actorWrite").is_none() && old.get("keyProof").is_none());
        assert_eq!(AccountDeletion::from_entry(&old).unwrap().0, bare);

        // The largest evidence the lexicon admits still fits the entry bound.
        let largest = evidenced_deletion(Some(device_evidence(
            ACTOR_WRITE_BODY_MAX_BYTES,
            Some(vec![0xFF; KEY_PROOF_MAX_BYTES]),
        )));
        let largest_entry = largest.entry(&authority);
        let size = serde_json::to_vec(&largest_entry).unwrap().len();
        assert!(size < ACCOUNT_DELETED_ENTRY_MAX_BYTES, "{size}");
        assert_eq!(
            AccountDeletion::from_entry(&largest_entry).unwrap().0,
            largest
        );

        // Only lexicon-shaped evidence parses.
        let reshaped = |edit: &dyn Fn(&mut AccountDeletionEvidence)| {
            let mut evidence = evidence.clone();
            edit(&mut evidence);
            evidenced_deletion(Some(evidence)).entry(&authority)
        };
        let other_endpoint = AccountDeletionEvidence::signed_for_test(
            &ed25519_dalek::SigningKey::from_bytes(&[9; 32]),
            Uuid::new_v4(),
            [0x0D; 16],
            Utc::now(),
            0,
            None,
        );
        let mut other_endpoint_body: Value =
            serde_json::from_slice(&other_endpoint.actor_write.write_body).unwrap();
        other_endpoint_body["endpointNsid"] = json!("blue.catbird.labyrinth.purgeMailbox");
        let other_endpoint_body = serde_json::to_vec(&other_endpoint_body).unwrap();
        for changed in [
            reshaped(&|e| e.actor_write.signature.truncate(63)),
            reshaped(&|e| e.actor_write.write_body.clear()),
            reshaped(&|e| {
                e.actor_write
                    .write_body
                    .resize(ACTOR_WRITE_BODY_MAX_BYTES + 1, b' ')
            }),
            reshaped(&|e| e.actor_write.write_body = b"{}".to_vec()),
            reshaped(&|e| e.actor_write.write_body = other_endpoint_body.clone()),
            reshaped(&|e| e.key_proof = Some(Vec::new())),
            reshaped(&|e| e.key_proof = Some(vec![0; KEY_PROOF_MAX_BYTES + 1])),
            {
                let mut proof_alone = old.clone();
                proof_alone["keyProof"] = json!({ "$bytes": STANDARD.encode([1; 8]) });
                proof_alone
            },
            {
                let mut unknown = entry.clone();
                unknown["actorWrite"]["extra"] = json!(1);
                unknown
            },
        ] {
            assert!(AccountDeletion::from_entry(&changed).is_err(), "{changed}");
        }
    }
}
