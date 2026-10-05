//! Keyed digests for attachment references (decision J4; migration
//! `20261004100005`).
//!
//! The reference table keeps the owner DID and the (conversation, message)
//! pair only as HMAC-SHA256 digests under a server key that lives outside the
//! database (`LABYRINTH_ATTACHMENT_DIGEST_KEY`, 32 bytes base64url). A
//! database reader therefore cannot link accounts, messages and attachments;
//! the server can still answer point queries, the limit the whitepaper
//! states for Messenger (v1.1 p.49 caveat 4). Rotating the key orphans every
//! existing reference.
//!
//! The access token MAC follows the paper's shape: the key is the ORF output
//! for the client's blinded token salt, the message is the JSON array
//! `[threadId, messageId]` (serde_json compact encoding).

use std::sync::OnceLock;

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use hmac::{Hmac, Mac};
use sha2::Sha256;

use super::error::{LabyrinthError, LabyrinthResult};

/// Environment variable holding the digest key.
pub const KEY_ENV: &str = "LABYRINTH_ATTACHMENT_DIGEST_KEY";

fn configured() -> Option<[u8; 32]> {
    static KEY: OnceLock<Option<[u8; 32]>> = OnceLock::new();
    *KEY.get_or_init(|| {
        let raw = std::env::var(KEY_ENV).ok()?;
        let key = URL_SAFE_NO_PAD.decode(raw.trim()).ok()?;
        match <[u8; 32]>::try_from(key.as_slice()) {
            Ok(k) => Some(k),
            Err(_) => {
                tracing::error!("{KEY_ENV} must be 32 bytes base64url; attachments disabled");
                None
            }
        }
    })
}

/// The digest key, or `503 AttachmentsUnavailable`.
pub fn key() -> LabyrinthResult<[u8; 32]> {
    configured().ok_or_else(|| {
        LabyrinthError::new(
            axum::http::StatusCode::SERVICE_UNAVAILABLE,
            "AttachmentsUnavailable",
            "attachment references are not configured on this service",
        )
    })
}

/// Whether the key is configured (purges skip reference cleanup without it).
pub fn configured_key() -> Option<[u8; 32]> {
    configured()
}

fn hmac(key: &[u8], parts: &[&[u8]]) -> [u8; 32] {
    let mut mac = Hmac::<Sha256>::new_from_slice(key).expect("HMAC accepts any key length");
    for part in parts {
        mac.update(&(part.len() as u64).to_be_bytes());
        mac.update(part);
    }
    mac.finalize().into_bytes().into()
}

/// Digest of a reference owner.
pub fn owner(key: &[u8; 32], did: &str) -> [u8; 32] {
    hmac(key, &[b"catbird.labyrinth.attachment_owner", did.as_bytes()])
}

/// Digest of the message an attachment belongs to.
pub fn message(key: &[u8; 32], thread_id: &str, message_id: &str) -> [u8; 32] {
    hmac(
        key,
        &[
            b"catbird.labyrinth.attachment_message",
            thread_id.as_bytes(),
            message_id.as_bytes(),
        ],
    )
}

/// The access token MAC: `HMAC(salt, json([threadId, messageId]))`.
pub fn token_mac(salt: &[u8; 32], thread_id: &str, message_id: &str) -> [u8; 32] {
    let json = serde_json::to_vec(&[thread_id, message_id]).expect("strings serialize");
    let mut mac = Hmac::<Sha256>::new_from_slice(salt).expect("HMAC accepts any key length");
    mac.update(&json);
    mac.finalize().into_bytes().into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn digests_are_length_prefixed_and_domain_separated() {
        let k = [7u8; 32];
        assert_ne!(message(&k, "ab", "c"), message(&k, "a", "bc"));
        assert_ne!(owner(&k, "did:plc:x"), message(&k, "did:plc:x", ""));
        assert_ne!(owner(&k, "did:plc:x"), owner(&[8u8; 32], "did:plc:x"));
    }

    #[test]
    fn token_mac_covers_the_json_pair() {
        let salt = [1u8; 32];
        let mut mac = Hmac::<Sha256>::new_from_slice(&salt).unwrap();
        mac.update(br#"["t","m\"1"]"#);
        let want: [u8; 32] = mac.finalize().into_bytes().into();
        assert_eq!(token_mac(&salt, "t", "m\"1"), want);
    }
}
