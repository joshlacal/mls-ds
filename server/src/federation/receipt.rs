use chrono::Utc;
use p256::ecdsa::{signature::Verifier, Signature, SigningKey, VerifyingKey};
use p256::pkcs8::DecodePrivateKey;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use super::envelope::{DELIVER_MESSAGE_NSID, DELIVER_WELCOME_NSID, SUBMIT_COMMIT_NSID};
use super::errors::FederationError;
use catbird_atproto::generated::blue_catbird::chat::submit_transition::SubmitTransitionOutput;
use catbird_atproto::generated::blue_catbird::chat::ConversationEntry;
use catbird_atproto::generated::blue_catbird::mlsDS::submit_commit::SubmitCommitOutput;
/// The only verification method clients may resolve for V1 sequencer receipts.
///
/// The DID document itself is published by the edge/operations layer. The
/// server validates this fixed identifier before enabling receipt issuance so
/// configuration cannot silently select the service-auth verification method.
pub const RECEIPT_VERIFICATION_METHOD: &str = "did:web:chat.catbird.blue#mls-receipt-1";

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum ReceiptConfigError {
    #[error("RECEIPT_ISSUANCE_MODE must be disabled or issue")]
    InvalidIssuanceMode,
    #[error("RECEIPT_SIGNING_KEY_PEM is required when receipt issuance is enabled")]
    MissingSigningKey,
    #[error("RECEIPT_SIGNING_KEY_PEM is not a valid ES256 PKCS#8 private key")]
    MalformedSigningKey,
    #[error("RECEIPT_VERIFICATION_METHOD must name the fixed MLS receipt method")]
    UnexpectedVerificationMethod,
    #[error("SERVICE_DID must own the fixed MLS receipt verification method")]
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
    #[error("receipt DID document id does not own the fixed verification method")]
    DocumentOwnerMismatch,
    #[error("receipt DID document omits the fixed receipt verification method")]
    MissingReceiptMethod,
    #[error("receipt DID document defines the fixed verification method more than once")]
    AmbiguousReceiptMethod,
    #[error("receipt verification method controller does not match the document owner")]
    ControllerMismatch,
    #[error("receipt verification method must be a P-256 Multikey")]
    UnsupportedReceiptKey,
    #[error("published receipt key does not match the configured receipt signer")]
    SignerKeyMismatch,
    #[error("published receipt key must be distinct from the service-auth key")]
    ServiceAuthKeyReuse,
}

/// Validate the fixed receipt verification method in a resolved DID document.
///
/// This is deliberately separate from generic service authentication. Receipt
/// issuance may only be enabled after the exact method resolves to the
/// configured P-256 signer and is distinct from the service-auth key.
pub fn validate_receipt_did_document(
    document: &str,
    expected_receipt_key: &VerifyingKey,
    service_auth_key: Option<&VerifyingKey>,
) -> Result<(), ReceiptDidDocumentError> {
    let document: serde_json::Value =
        serde_json::from_str(document).map_err(|_| ReceiptDidDocumentError::MalformedDocument)?;
    let method_owner = RECEIPT_VERIFICATION_METHOD
        .split_once('#')
        .map(|(did, _)| did)
        .expect("fixed receipt verification method contains a fragment");
    if document.get("id").and_then(serde_json::Value::as_str) != Some(method_owner) {
        return Err(ReceiptDidDocumentError::DocumentOwnerMismatch);
    }
    let methods = document
        .get("verificationMethod")
        .and_then(serde_json::Value::as_array)
        .ok_or(ReceiptDidDocumentError::MissingReceiptMethod)?;
    let mut matching_methods = methods.iter().filter(|method| {
        method.get("id").and_then(serde_json::Value::as_str) == Some(RECEIPT_VERIFICATION_METHOD)
    });
    let method = matching_methods
        .next()
        .ok_or(ReceiptDidDocumentError::MissingReceiptMethod)?;
    if matching_methods.next().is_some() {
        return Err(ReceiptDidDocumentError::AmbiguousReceiptMethod);
    }
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
    let (_, decoded) =
        multibase::decode(encoded).map_err(|_| ReceiptDidDocumentError::UnsupportedReceiptKey)?;
    // p256-pub has multicodec value 0x1200, encoded as unsigned varint 0x80 0x24.
    if !decoded.starts_with(&[0x80, 0x24]) || decoded.len() != 2 + 33 {
        return Err(ReceiptDidDocumentError::UnsupportedReceiptKey);
    }
    let published_key = VerifyingKey::from_sec1_bytes(&decoded[2..])
        .map_err(|_| ReceiptDidDocumentError::UnsupportedReceiptKey)?;
    if &published_key != expected_receipt_key {
        return Err(ReceiptDidDocumentError::SignerKeyMismatch);
    }
    if service_auth_key == Some(&published_key) {
        return Err(ReceiptDidDocumentError::ServiceAuthKeyReuse);
    }
    Ok(())
}

/// Build the optional receipt signer from its dedicated configuration.
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
) -> Result<Option<ReceiptSigner>, ReceiptConfigError> {
    let mode = issuance_mode.unwrap_or("disabled").trim();
    if mode.eq_ignore_ascii_case("disabled") || mode.eq_ignore_ascii_case("off") {
        return Ok(None);
    }
    if !mode.eq_ignore_ascii_case("issue") {
        return Err(ReceiptConfigError::InvalidIssuanceMode);
    }

    if receipt_verification_method != Some(RECEIPT_VERIFICATION_METHOD) {
        return Err(ReceiptConfigError::UnexpectedVerificationMethod);
    }
    let method_owner = RECEIPT_VERIFICATION_METHOD
        .split_once('#')
        .map(|(did, _)| did)
        .expect("fixed receipt verification method contains a fragment");
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
    validate_receipt_did_document(
        published_did_document,
        receipt_key.verifying_key(),
        Some(service_key.verifying_key()),
    )?;

    Ok(Some(ReceiptSigner::new(
        receipt_key,
        service_did.to_string(),
    )))
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

/// Signs sequencer receipts using an ES256 private key.
#[derive(Debug)]
pub struct ReceiptSigner {
    signing_key: SigningKey,
    sequencer_did: String,
}

impl ReceiptSigner {
    /// Create a new receipt signer from an ES256 signing key and the sequencer's DID.
    pub fn new(signing_key: SigningKey, sequencer_did: String) -> Self {
        Self {
            signing_key,
            sequencer_did: crate::identity::canonical_did(&sequencer_did).to_string(),
        }
    }

    /// Sign a receipt for a commit.
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
        let issued_at = Utc::now().timestamp();
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

    /// Return the verifying (public) key corresponding to this signer.
    pub fn verifying_key(&self) -> VerifyingKey {
        *self.signing_key.verifying_key()
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
                serde_json::from_slice(response_bytes).map_err(|e| FederationError::InvalidEnvelope {
                    reason: format!("failed to parse submitCommit response for receipt result: {e}"),
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
        let signer = ReceiptSigner::new(sk.clone(), "did:web:ds.example.com".to_string());
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
        let signer = ReceiptSigner::new(
            SigningKey::random(&mut OsRng),
            "did:web:ds.example.com#mls".to_string(),
        );

        let receipt = signer.sign_receipt("convo-fragment", 6, 3, b"commit");

        assert_eq!(receipt.sequencer_did, "did:web:ds.example.com");
    }

    #[test]
    fn verify_rejects_wrong_key() {
        let sk = SigningKey::random(&mut OsRng);
        let signer = ReceiptSigner::new(sk, "did:web:ds.example.com".to_string());
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
        let signer = ReceiptSigner::new(sk.clone(), "did:web:ds.example.com".to_string());
        let vk = signer.verifying_key();

        let mut receipt = signer.sign_receipt("convo-789", 3, 9, b"original");
        receipt.epoch = 4; // tamper
        assert!(!receipt.verify(&vk), "tampered receipt should not verify");
    }

    #[test]
    fn verify_rejects_each_authority_binding_tamper() {
        let signer = ReceiptSigner::new(
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
        let signer = ReceiptSigner::new(sk, "did:web:ds.example.com".to_string());
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

        let msg_bytes = result_bytes_for_receipt(DELIVER_MESSAGE_NSID, b"{\"extra\":\"value\"}").unwrap();
        assert_eq!(msg_bytes, b"{\"accepted\":true}");
    }

    #[test]
    fn result_bytes_for_receipt_submit_commit() {
        use base64::Engine as _;
        use base64::engine::general_purpose::STANDARD;
        let b64_32 = STANDARD.encode([1u8; 32]);
        let b64_48 = STANDARD.encode([1u8; 48]);
        let b64_12 = STANDARD.encode([1u8; 12]);
        let b64_64 = STANDARD.encode([1u8; 64]);
        let b0_32 = STANDARD.encode([0u8; 32]);
        let b32_arr = serde_json::to_string(&vec![1u8; 32]).unwrap();
        let b16 = serde_json::to_string(&vec![1u8; 16]).unwrap();

        let json_str = format!(r#"{{
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
        }}"#);
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
}
