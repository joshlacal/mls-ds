use chrono::Utc;
use p256::ecdsa::{signature::Verifier, Signature, SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// A signed receipt proving the sequencer accepted and ordered a commit.
///
/// The receipt binds a conversation, epoch, and commit hash together with the
/// sequencer's ES256 signature, allowing any participant to verify the ordering
/// decision without trusting the sequencer blindly.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SequencerReceipt {
    pub convo_id: String,
    pub epoch: i32,
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
        let canonical = canonical_bytes(
            &self.convo_id,
            self.epoch,
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
pub struct ReceiptSigner {
    signing_key: SigningKey,
    sequencer_did: String,
}

impl ReceiptSigner {
    /// Create a new receipt signer from an ES256 signing key and the sequencer's DID.
    pub fn new(signing_key: SigningKey, sequencer_did: String) -> Self {
        Self {
            signing_key,
            sequencer_did,
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
        commit_ciphertext: &[u8],
    ) -> SequencerReceipt {
        let commit_hash = hash_commit(commit_ciphertext);
        let issued_at = Utc::now().timestamp();
        let canonical = canonical_bytes(
            convo_id,
            epoch,
            &commit_hash,
            &self.sequencer_did,
            issued_at,
        );

        let sig: Signature = p256::ecdsa::signature::Signer::sign(&self.signing_key, &canonical);

        SequencerReceipt {
            convo_id: convo_id.to_string(),
            epoch,
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
/// Format: `"CATBIRD-RECEIPT-V1:" || len(convo_id) (LE u32) || convo_id_bytes || epoch (BE i32) || commit_hash || len(sequencer_did) (LE u32) || sequencer_did_bytes || issued_at (BE i64)`
fn canonical_bytes(
    convo_id: &str,
    epoch: i32,
    commit_hash: &[u8],
    sequencer_did: &str,
    issued_at: i64,
) -> Vec<u8> {
    let mut buf = Vec::with_capacity(
        19 + 4 + convo_id.len() + 4 + commit_hash.len() + 4 + sequencer_did.len() + 8,
    );
    // Domain separator prevents cross-protocol signature reuse
    buf.extend_from_slice(b"CATBIRD-RECEIPT-V1:");
    // Length-prefixed strings prevent collision attacks
    buf.extend_from_slice(&(convo_id.len() as u32).to_le_bytes());
    buf.extend_from_slice(convo_id.as_bytes());
    buf.extend_from_slice(&epoch.to_be_bytes());
    buf.extend_from_slice(commit_hash);
    buf.extend_from_slice(&(sequencer_did.len() as u32).to_le_bytes());
    buf.extend_from_slice(sequencer_did.as_bytes());
    buf.extend_from_slice(&issued_at.to_be_bytes());
    buf
}

#[cfg(test)]
mod tests {
    use super::*;
    use p256::ecdsa::SigningKey;
    use rand::rngs::OsRng;

    #[test]
    fn sign_and_verify_round_trip() {
        let sk = SigningKey::random(&mut OsRng);
        let signer = ReceiptSigner::new(sk.clone(), "did:web:ds.example.com".to_string());
        let vk = signer.verifying_key();

        let receipt = signer.sign_receipt("convo-123", 5, b"fake-commit-ciphertext");

        assert_eq!(receipt.convo_id, "convo-123");
        assert_eq!(receipt.epoch, 5);
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
    fn verify_rejects_wrong_key() {
        let sk = SigningKey::random(&mut OsRng);
        let signer = ReceiptSigner::new(sk, "did:web:ds.example.com".to_string());
        let receipt = signer.sign_receipt("convo-456", 1, b"data");

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

        let mut receipt = signer.sign_receipt("convo-789", 3, b"original");
        receipt.epoch = 4; // tamper
        assert!(!receipt.verify(&vk), "tampered receipt should not verify");
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
        let receipt = signer.sign_receipt("convo-serde", 10, b"ciphertext");

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
}
