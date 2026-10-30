//! The sequencer's check of a relayed `purgeAuthor` (second security review,
//! finding 4).
//!
//! The home DS delivers the remote part of `deleteAccountData` from a durable
//! outbox, possibly long after the device signed it, and possibly after that
//! device was revoked. The sequencer therefore accepts the device's signed
//! `deleteAccountData` write body when:
//!
//! * it names `blue.catbird.labyrinth.deleteAccountData` and the payload's
//!   sha256;
//! * `signedAt` is at most 5 minutes in the future and at most
//!   `PURGE_MAX_AGE_DAYS` in the past;
//! * it verifies under a chat key of that device that was current *at
//!   `signedAt`* (created before, not revoked before, device not revoked
//!   before).
//!
//! The redaction then only reaches items the sequencer received before
//! `signedAt` + 5 minutes, so an old purge can never erase what the account
//! wrote after re-enrolling.

use chrono::{DateTime, Duration, Utc};
use ed25519_dalek::{Signature, VerifyingKey};
use sha2::{Digest, Sha256};

use super::auth::{parse_device_id, WriteBodyWire, WRITE_DOMAIN, WRITE_SKEW_SECONDS};
use super::error::{LabyrinthError, LabyrinthResult};
use super::repo::outbox::PURGE_MAX_AGE_DAYS;
use super::wire::bytes::hex_array;
use crate::storage::DbPool;

const NSID: &str = "blue.catbird.labyrinth.deleteAccountData";

fn bad_signature() -> LabyrinthError {
    LabyrinthError::new(
        axum::http::StatusCode::UNAUTHORIZED,
        "InvalidSignature",
        "purgeAuthor write body does not verify under a key of that device at signedAt",
    )
}

/// Verify a relayed `purgeAuthor`; returns the redaction bound (items
/// received at or before it are redacted).
pub async fn verify(
    pool: &DbPool,
    did: &str,
    device_id: &str,
    signed: &[u8],
    sig: &[u8],
    payload: &[u8],
    now: DateTime<Utc>,
) -> LabyrinthResult<DateTime<Utc>> {
    let wire: WriteBodyWire = serde_json::from_slice(signed)
        .map_err(|e| LabyrinthError::invalid(format!("labyrinthWriteBody: {e}")))?;
    let device = parse_device_id(&wire.actor_device_id)?;
    if device.hyphenated().to_string() != device_id {
        return Err(LabyrinthError::invalid(
            "actorDeviceId differs from the signed write body",
        ));
    }
    if wire.endpoint_nsid != NSID {
        return Err(LabyrinthError::invalid(
            "purgeAuthor carries a deleteAccountData write body only",
        ));
    }
    let digest: [u8; 32] = Sha256::digest(payload).into();
    if hex_array::<32>("payloadSha256", &wire.payload_sha256)? != digest {
        return Err(LabyrinthError::invalid(
            "labyrinthWriteBody.payloadSha256 does not match the payload",
        ));
    }
    let signed_at = DateTime::parse_from_rfc3339(&wire.signed_at)
        .map_err(|_| LabyrinthError::invalid("signedAt is not an RFC 3339 datetime"))?
        .with_timezone(&Utc);
    let skew = Duration::seconds(WRITE_SKEW_SECONDS);
    if signed_at > now + skew || now - signed_at > Duration::days(PURGE_MAX_AGE_DAYS) {
        return Err(LabyrinthError::invalid(
            "signedAt is outside the purge acceptance window",
        ));
    }
    let sig: [u8; 64] = sig
        .try_into()
        .map_err(|_| LabyrinthError::invalid("write signature must be 64 bytes"))?;
    let keys: Vec<Vec<u8>> = sqlx::query_scalar(
        "SELECT k.signing_public_key FROM chat.device_keys k \
           JOIN chat.devices d ON d.user_did = k.user_did AND d.device_id = k.device_id \
          WHERE k.user_did = $1 AND k.device_id = $2 AND k.created_at <= $3 \
            AND (k.revoked_at IS NULL OR k.revoked_at > $3) \
            AND (d.revoked_at IS NULL OR d.revoked_at > $3)",
    )
    .bind(did)
    .bind(device)
    .bind(signed_at)
    .fetch_all(pool)
    .await?;
    let message = [WRITE_DOMAIN, signed].concat();
    let signature = Signature::from_bytes(&sig);
    let ok = keys.iter().any(|k| {
        <[u8; 32]>::try_from(k.as_slice())
            .ok()
            .and_then(|k| VerifyingKey::from_bytes(&k).ok())
            .is_some_and(|k| k.verify_strict(&message, &signature).is_ok())
    });
    if !ok {
        return Err(bad_signature());
    }
    Ok(signed_at + skew)
}
