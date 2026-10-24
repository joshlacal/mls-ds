//! Server-signed account-deletion redactions (second security review,
//! finding 7).
//!
//! When `deleteAccountData` (or a relayed `purgeAuthor`) redacts an item, the
//! redaction carries `by` (this DS's DID), `reason: "accountDeleted"` and,
//! when `LABYRINTH_REDACTION_SIGNING_KEY` (a 32-byte Ed25519 seed, base64url)
//! is configured, `sig`: Ed25519 over the UTF-8 string
//!
//! ```text
//! catbird.labyrinth.ds_redaction:by=<by>;did=<author>;message_id=<messageId>;
//!   reason=accountDeleted;redacted_at=<redactedAt as stored>;thread_id=<hex(utf8 threadId)>
//! ```
//!
//! (one line, no break). Clients verify `sig` against the key published for
//! the conversation's sequencer DID and otherwise render the item as
//! "removed by server", never as an author unsend. Without the key the
//! marker is still written, unsigned: honest, just unverifiable.

use std::sync::OnceLock;

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use chrono::{DateTime, Utc};
use ed25519_dalek::{Signer, SigningKey};
use serde_json::{json, Value};

use super::wire::bytes::Bytes;

/// Environment variable holding the redaction signing seed.
pub const KEY_ENV: &str = "LABYRINTH_REDACTION_SIGNING_KEY";
pub const PREFIX: &str = "catbird.labyrinth.ds_redaction:";
pub const REASON_ACCOUNT_DELETED: &str = "accountDeleted";

fn signing_key() -> Option<&'static SigningKey> {
    static KEY: OnceLock<Option<SigningKey>> = OnceLock::new();
    KEY.get_or_init(|| {
        let raw = std::env::var(KEY_ENV).ok()?;
        match URL_SAFE_NO_PAD
            .decode(raw.trim())
            .ok()
            .and_then(|k| <[u8; 32]>::try_from(k.as_slice()).ok())
        {
            Some(seed) => Some(SigningKey::from_bytes(&seed)),
            None => {
                tracing::error!("{KEY_ENV} must be 32 bytes base64url; redactions stay unsigned");
                None
            }
        }
    })
    .as_ref()
}

/// The public half of the configured key, if any.
pub fn public_key() -> Option<[u8; 32]> {
    signing_key().map(|k| k.verifying_key().to_bytes())
}

/// `redactedAt` exactly as `labyrinth.redact_items` stores it.
pub fn redacted_at_text(at: DateTime<Utc>) -> String {
    at.format("%Y-%m-%dT%H:%M:%S%.3fZ").to_string()
}

/// The signed message.
pub fn message(by: &str, author: &str, message_id: &str, redacted_at: &str, thread_id: &str) -> String {
    format!(
        "{PREFIX}by={by};did={author};message_id={message_id};reason={REASON_ACCOUNT_DELETED};\
         redacted_at={redacted_at};thread_id={}",
        hex::encode(thread_id.as_bytes())
    )
}

/// The redaction marker of one account-deletion redacted message.
pub fn marker(author: &str, thread_id: &str, message_id: &str, at: DateTime<Utc>) -> Value {
    let by = crate::identity::service_did();
    let redacted_at = redacted_at_text(at);
    let mut marker = json!({
        "by": by,
        "reason": REASON_ACCOUNT_DELETED,
        "redactedAt": redacted_at,
    });
    if let Some(key) = signing_key() {
        let sig = key.sign(message(&by, author, message_id, &redacted_at, thread_id).as_bytes());
        marker["sig"] = json!(Bytes(sig.to_bytes().to_vec()));
    }
    marker
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn message_shape_and_timestamp_text() {
        let at = DateTime::from_timestamp_millis(1_791_000_000_123).unwrap();
        assert_eq!(redacted_at_text(at), "2026-10-03T04:00:00.123Z");
        assert_eq!(
            message("did:web:ds.example", "did:plc:a", "m1", "2026-10-03T04:00:00.123Z", "t"),
            "catbird.labyrinth.ds_redaction:by=did:web:ds.example;did=did:plc:a;message_id=m1;\
             reason=accountDeleted;redacted_at=2026-10-03T04:00:00.123Z;thread_id=74"
        );
    }
}
