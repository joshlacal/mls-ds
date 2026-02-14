//! Delivery acknowledgment types and signing/verification.
//!
//! When a DS receives a federated message on behalf of a local user,
//! it produces a [`DeliveryAck`] signed with its ES256 service key.
//! The originating DS can later verify the ack using the receiver's
//! public verifying key.

use chrono::Utc;
use p256::ecdsa::{signature::Signer, signature::Verifier, Signature, SigningKey, VerifyingKey};
use p256::pkcs8::DecodePrivateKey;
use serde::{Deserialize, Serialize};

/// Signed acknowledgment that a message was delivered to a receiver DS.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeliveryAck {
    /// Opaque message identifier (typically a ULID).
    pub message_id: String,
    /// Conversation / group identifier.
    pub convo_id: String,
    /// MLS epoch at the time of delivery.
    pub epoch: i32,
    /// DID of the DS that received the message.
    pub receiver_ds_did: String,
    /// Unix timestamp (seconds) when the ack was created.
    pub acked_at: i64,
    /// ES256 signature over the canonical byte representation.
    pub signature: Vec<u8>,
}

impl DeliveryAck {
    /// Verify this ack's signature against the given ES256 verifying key.
    ///
    /// Reconstructs the canonical byte payload and checks the signature.
    /// Returns `true` if the signature is valid.
    pub fn verify(&self, verifying_key: &VerifyingKey) -> bool {
        let canonical = canonical_bytes(
            &self.message_id,
            &self.convo_id,
            self.epoch,
            &self.receiver_ds_did,
            self.acked_at,
        );
        let Ok(sig) = Signature::from_slice(&self.signature) else {
            return false;
        };
        verifying_key.verify(&canonical, &sig).is_ok()
    }
}

/// Signs delivery acknowledgments with an ES256 key.
#[derive(Clone)]
pub struct AckSigner {
    signing_key: SigningKey,
    ds_did: String,
}

impl AckSigner {
    /// Create a new signer from an ES256 signing key and the local DS DID.
    pub fn new(signing_key: SigningKey, ds_did: String) -> Self {
        Self {
            signing_key,
            ds_did,
        }
    }

    /// Create from a PEM-encoded ES256 (P-256) private key.
    pub fn from_pem(pem: &str, ds_did: String) -> Result<Self, String> {
        let signing_key =
            SigningKey::from_pkcs8_pem(pem).map_err(|e| format!("Invalid ES256 PEM: {e}"))?;
        Ok(Self {
            signing_key,
            ds_did,
        })
    }

    /// Produce a signed [`DeliveryAck`] for a delivered message.
    pub fn sign_ack(&self, message_id: &str, convo_id: &str, epoch: i32) -> DeliveryAck {
        let acked_at = Utc::now().timestamp();
        let canonical = canonical_bytes(message_id, convo_id, epoch, &self.ds_did, acked_at);
        let sig: Signature = self.signing_key.sign(&canonical);

        DeliveryAck {
            message_id: message_id.to_string(),
            convo_id: convo_id.to_string(),
            epoch,
            receiver_ds_did: self.ds_did.clone(),
            acked_at,
            signature: sig.to_bytes().to_vec(),
        }
    }

    /// The DID of this delivery service.
    pub fn ds_did(&self) -> &str {
        &self.ds_did
    }
}

/// Build the canonical byte representation for signing/verification.
///
/// Format: `"CATBIRD-ACK-V1:" || len(message_id) || message_id || len(convo_id) || convo_id || epoch (big-endian i32) || len(receiver_ds_did) || receiver_ds_did || acked_at (big-endian i64)`
fn canonical_bytes(
    message_id: &str,
    convo_id: &str,
    epoch: i32,
    receiver_ds_did: &str,
    acked_at: i64,
) -> Vec<u8> {
    let mut buf = Vec::with_capacity(
        15 + 4 + message_id.len() + 4 + convo_id.len() + 4 + 4 + receiver_ds_did.len() + 8,
    );
    // Domain separator prevents cross-protocol signature reuse
    buf.extend_from_slice(b"CATBIRD-ACK-V1:");
    // Length-prefixed strings prevent collision attacks
    buf.extend_from_slice(&(message_id.len() as u32).to_le_bytes());
    buf.extend_from_slice(message_id.as_bytes());
    buf.extend_from_slice(&(convo_id.len() as u32).to_le_bytes());
    buf.extend_from_slice(convo_id.as_bytes());
    buf.extend_from_slice(&epoch.to_be_bytes());
    buf.extend_from_slice(&(receiver_ds_did.len() as u32).to_le_bytes());
    buf.extend_from_slice(receiver_ds_did.as_bytes());
    buf.extend_from_slice(&acked_at.to_be_bytes());
    buf
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_keypair() -> (SigningKey, VerifyingKey) {
        let sk = SigningKey::random(&mut rand::thread_rng());
        let vk = VerifyingKey::from(&sk);
        (sk, vk)
    }

    #[test]
    fn sign_and_verify_roundtrip() {
        let (sk, vk) = test_keypair();
        let signer = AckSigner::new(sk, "did:web:ds-a.example.com".to_string());

        let ack = signer.sign_ack("msg-001", "convo-abc", 5);

        assert_eq!(ack.message_id, "msg-001");
        assert_eq!(ack.convo_id, "convo-abc");
        assert_eq!(ack.epoch, 5);
        assert_eq!(ack.receiver_ds_did, "did:web:ds-a.example.com");
        assert!(ack.verify(&vk), "signature should verify with correct key");
    }

    #[test]
    fn verify_fails_with_wrong_key() {
        let (sk, _) = test_keypair();
        let (_, wrong_vk) = test_keypair();
        let signer = AckSigner::new(sk, "did:web:ds.example.com".to_string());

        let ack = signer.sign_ack("msg-002", "convo-xyz", 10);

        assert!(
            !ack.verify(&wrong_vk),
            "signature should not verify with wrong key"
        );
    }

    #[test]
    fn verify_fails_on_tampered_ack() {
        let (sk, vk) = test_keypair();
        let signer = AckSigner::new(sk, "did:web:ds.example.com".to_string());

        let mut ack = signer.sign_ack("msg-003", "convo-123", 1);
        ack.epoch = 999; // tamper

        assert!(
            !ack.verify(&vk),
            "signature should not verify after tampering"
        );
    }

    #[test]
    fn serde_roundtrip() {
        let (sk, vk) = test_keypair();
        let signer = AckSigner::new(sk, "did:web:ds.example.com".to_string());
        let ack = signer.sign_ack("msg-004", "convo-serde", 42);

        let json = serde_json::to_string(&ack).expect("serialize");
        let decoded: DeliveryAck = serde_json::from_str(&json).expect("deserialize");

        assert_eq!(decoded.message_id, ack.message_id);
        assert!(decoded.verify(&vk));
    }
}
