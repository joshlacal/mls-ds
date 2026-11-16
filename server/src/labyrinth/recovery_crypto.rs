//! Recovery-share encryption at rest and single-use-key response sealing.
//!
//! The KEK is supplied by a separate mounted file. It is never stored in
//! PostgreSQL, in the tombstone journal, or in an idempotency response.

use std::path::Path;

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Nonce};
use hpke_rs::{hpke_types::*, Hpke, HpkePublicKey, Mode};
use hpke_rs_rust_crypto::HpkeRustCrypto;
use rand::{rngs::OsRng, RngCore};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

use super::error::{LabyrinthError, LabyrinthResult};

pub const FETCH_PREFIX: &[u8] = b"catbird.labyrinth.recovery_share.fetch.v1|";
pub const HPKE_INFO: &[u8] = b"catbird.labyrinth.recovery_share.seal.v1";
const STORAGE_AAD: &[u8] = b"catbird.labyrinth.recovery_share.storage.v1\0";
const CANARY: &[u8] = b"catbird.labyrinth.recovery_share.kek.canary.v1";

/// One configured KEK. Rotation requires explicit rewrapping of every live
/// row; startup checks all stored key IDs and refuses mismatches.
pub struct RecoveryCrypto {
    key_id: String,
    key: Zeroizing<[u8; 32]>,
}

impl std::fmt::Debug for RecoveryCrypto {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RecoveryCrypto")
            .field("key_id", &self.key_id)
            .field("key", &"<redacted>")
            .finish()
    }
}

impl RecoveryCrypto {
    /// Load a raw 32-byte KEK from a mounted file. Both environment variables
    /// must be present together; a partial configuration is a startup error.
    pub fn from_env() -> Result<Option<Self>, String> {
        let path = std::env::var("LABYRINTH_RECOVERY_SHARE_KEK_FILE").ok();
        let key_id = std::env::var("LABYRINTH_RECOVERY_SHARE_KEK_ID").ok();
        match (path, key_id) {
            (None, None) => Ok(None),
            (Some(path), Some(key_id)) => {
                let path = Path::new(&path);
                let metadata = std::fs::metadata(path)
                    .map_err(|e| format!("read recovery-share KEK metadata: {e}"))?;
                if !metadata.is_file() {
                    return Err("recovery-share KEK path is not a regular file".into());
                }
                #[cfg(unix)]
                {
                    use std::os::unix::fs::PermissionsExt;
                    if metadata.permissions().mode() & 0o077 != 0 {
                        return Err("recovery-share KEK file permits group/other access".into());
                    }
                }
                let key = std::fs::read(path)
                    .map_err(|e| format!("read recovery-share KEK file: {e}"))?;
                Self::new(key_id, key).map(Some)
            }
            _ => Err("set both LABYRINTH_RECOVERY_SHARE_KEK_FILE and _KEK_ID".into()),
        }
    }

    /// Construct from key material and perform a canary encrypt/decrypt.
    pub fn new(key_id: String, key: Vec<u8>) -> Result<Self, String> {
        if key_id.is_empty()
            || key_id.len() > 64
            || !key_id
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.'))
        {
            return Err("recovery-share KEK ID must be 1..=64 ASCII token bytes".into());
        }
        let key = Zeroizing::new(key);
        let key: [u8; 32] = key
            .as_slice()
            .try_into()
            .map_err(|_| "recovery-share KEK must be exactly 32 bytes".to_owned())?;
        let this = Self {
            key_id,
            key: Zeroizing::new(key),
        };
        let mut nonce = [0u8; 12];
        OsRng.fill_bytes(&mut nonce);
        let cipher = this
            .cipher()
            .encrypt(
                Nonce::from_slice(&nonce),
                Payload {
                    msg: CANARY,
                    aad: STORAGE_AAD,
                },
            )
            .map_err(|_| "recovery-share KEK canary seal failed")?;
        let opened = this
            .cipher()
            .decrypt(
                Nonce::from_slice(&nonce),
                Payload {
                    msg: &cipher,
                    aad: STORAGE_AAD,
                },
            )
            .map_err(|_| "recovery-share KEK canary open failed")?;
        if opened != CANARY {
            return Err("recovery-share KEK canary mismatch".into());
        }
        Ok(this)
    }

    pub fn key_id(&self) -> &str {
        &self.key_id
    }

    /// A separate MAC key for the append-only erasure journal.
    pub fn journal_key(&self) -> [u8; 32] {
        let mut hash = Sha256::new();
        hash.update(b"catbird.labyrinth.recovery_share.journal_key.v1\0");
        hash.update(&self.key[..]);
        hash.finalize().into()
    }

    fn cipher(&self) -> Aes256Gcm {
        Aes256Gcm::new_from_slice(&self.key[..]).expect("32-byte KEK")
    }

    fn storage_aad(&self, did: &str, vid: &[u8; 16]) -> Vec<u8> {
        let mut aad =
            Vec::with_capacity(STORAGE_AAD.len() + did.len() + 1 + vid.len() + self.key_id.len());
        aad.extend_from_slice(STORAGE_AAD);
        aad.extend_from_slice(did.as_bytes());
        aad.push(0);
        aad.extend_from_slice(vid);
        aad.extend_from_slice(self.key_id.as_bytes());
        aad
    }

    /// Returns (12-byte random nonce, 48-byte AES-GCM ciphertext).
    pub fn encrypt_share(
        &self,
        did: &str,
        vid: &[u8; 16],
        share: &[u8; 32],
    ) -> LabyrinthResult<([u8; 12], Vec<u8>)> {
        let mut nonce = [0u8; 12];
        OsRng.fill_bytes(&mut nonce);
        let sealed = self
            .cipher()
            .encrypt(
                Nonce::from_slice(&nonce),
                Payload {
                    msg: share,
                    aad: &self.storage_aad(did, vid),
                },
            )
            .map_err(|_| LabyrinthError::internal())?;
        Ok((nonce, sealed))
    }

    /// Storage-layer representation, including the key ID that must match on
    /// every subsequent read and at startup.
    pub fn encrypt(
        &self,
        did: &str,
        vid: &[u8; 16],
        share: &[u8; 32],
    ) -> LabyrinthResult<(String, [u8; 12], [u8; 48])> {
        let (nonce, sealed) = self.encrypt_share(did, vid, share)?;
        let sealed = sealed
            .as_slice()
            .try_into()
            .map_err(|_| LabyrinthError::internal())?;
        Ok((self.key_id.clone(), nonce, sealed))
    }

    pub fn decrypt_share(
        &self,
        did: &str,
        vid: &[u8; 16],
        key_id: &str,
        nonce: &[u8],
        ciphertext: &[u8],
    ) -> LabyrinthResult<Zeroizing<[u8; 32]>> {
        if key_id != self.key_id || nonce.len() != 12 || ciphertext.len() != 48 {
            return Err(LabyrinthError::internal());
        }
        let opened = self
            .cipher()
            .decrypt(
                Nonce::from_slice(nonce),
                Payload {
                    msg: ciphertext,
                    aad: &self.storage_aad(did, vid),
                },
            )
            .map_err(|_| LabyrinthError::internal())?;
        let opened = Zeroizing::new(opened);
        let share: [u8; 32] = opened
            .as_slice()
            .try_into()
            .map_err(|_| LabyrinthError::internal())?;
        Ok(Zeroizing::new(share))
    }
}

/// The verifier is scoped to the authenticated account and recovery method.
pub fn fetch_verifier(did: &str, vid: &[u8; 16], token: &[u8; 32]) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(FETCH_PREFIX);
    hash.update(did.as_bytes());
    hash.update(b"|");
    hash.update(hex::encode(vid).as_bytes());
    hash.update(b"|");
    hash.update(token);
    hash.finalize().into()
}

pub fn verifier_matches(stored: &[u8], supplied: &[u8; 32]) -> bool {
    let expected: [u8; 32] = match stored.try_into() {
        Ok(value) => value,
        Err(_) => return false,
    };
    bool::from(expected.ct_eq(supplied))
}

/// RFC 9180 base-mode DHKEM(X25519, HKDF-SHA256), HKDF-SHA256,
/// AES-256-GCM. The receiver's public key is fresh for this fetch.
pub fn seal_to_ephemeral_key(
    did: &str,
    vid: &[u8; 16],
    recipient_public_key: &[u8; 32],
    share: &[u8; 32],
) -> LabyrinthResult<([u8; 32], [u8; 48])> {
    let mut aad = Vec::with_capacity(did.len() + 1 + vid.len());
    aad.extend_from_slice(did.as_bytes());
    aad.push(0);
    aad.extend_from_slice(vid);
    let mut hpke = Hpke::<HpkeRustCrypto>::new(
        Mode::Base,
        KemAlgorithm::DhKem25519,
        KdfAlgorithm::HkdfSha256,
        AeadAlgorithm::Aes256Gcm,
    );
    let pk = HpkePublicKey::new(recipient_public_key.to_vec());
    let (enc, sealed) = hpke
        .seal(&pk, HPKE_INFO, &aad, share, None, None, None)
        .map_err(|_| LabyrinthError::invalid("recipientPublicKey is unusable"))?;
    let enc: [u8; 32] = enc
        .as_slice()
        .try_into()
        .map_err(|_| LabyrinthError::internal())?;
    let sealed: [u8; 48] = sealed
        .as_slice()
        .try_into()
        .map_err(|_| LabyrinthError::internal())?;
    Ok((enc, sealed))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn storage_binds_did_vid_and_key_id() {
        let c = RecoveryCrypto::new("a".into(), vec![7; 32]).unwrap();
        let vid = [9; 16];
        let share = [3; 32];
        let (nonce, sealed) = c
            .encrypt_share("did:plc:abcdefghijklmnopqrstuvwx", &vid, &share)
            .unwrap();
        assert_eq!(
            c.decrypt_share(
                "did:plc:abcdefghijklmnopqrstuvwx",
                &vid,
                "a",
                &nonce,
                &sealed
            )
            .unwrap()
            .as_ref(),
            &share
        );
        assert!(c
            .decrypt_share(
                "did:plc:abcdefghijklmnopqrstuvwy",
                &vid,
                "a",
                &nonce,
                &sealed
            )
            .is_err());
        assert!(c
            .decrypt_share(
                "did:plc:abcdefghijklmnopqrstuvwx",
                &[8; 16],
                "a",
                &nonce,
                &sealed
            )
            .is_err());
        assert!(c
            .decrypt_share(
                "did:plc:abcdefghijklmnopqrstuvwx",
                &vid,
                "b",
                &nonce,
                &sealed
            )
            .is_err());
    }
}
