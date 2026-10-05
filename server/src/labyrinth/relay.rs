//! `blue.catbird.labyrinth.labyrinthRelay` (design §3 "Federation", Y3).
//!
//! Thread records live on the conversation's sequencer DS, the only place
//! where `chatSeq` and `receivedAt` share a clock with MLS ordering. A
//! device homed on another DS talks to its home DS as usual; the home DS
//! authenticates it (service auth, device lock, write signature) and
//! forwards the operation here with DS-to-DS service auth. The sequencer then:
//!
//! 1. admits the peer through `enforce_ds_request_security` (kill switch,
//!    federation mode, `lxm`, peer policy, per-peer rate limit);
//! 2. requires that the peer is the actor's home DS in the conversation's
//!    participant rows (`chat.participants.ds_did` of the actor's latest
//!    period);
//! 3. requires the actor's chat device to be current in its replicated
//!    device table, and for writes re-verifies the device's own
//!    `labyrinthWriteBody` signature over the forwarded payload, so a home DS
//!    cannot write in a device's name without that device's key;
//! 4. runs the same handler code a local device reaches, and answers with
//!    the endpoint's exact output or typed error.

use serde::{Deserialize, Serialize};

use super::error::{LabyrinthError, LabyrinthResult};
use super::wire::bytes::Bytes;

pub const NSID: &str = "blue.catbird.labyrinth.labyrinthRelay";

/// The relayed operations.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RelayOp {
    CreateMek,
    AppendBatch,
    RedactMessage,
    FindMeks,
    ListBatches,
    /// Whether a message of the conversation is stored unredacted and
    /// readable by the actor (attachment access on the home DS).
    MessageLive,
    /// The remote part of `deleteAccountData`.
    PurgeAuthor,
}

impl RelayOp {
    pub fn parse(value: &str) -> LabyrinthResult<Self> {
        Ok(match value {
            "createMek" => Self::CreateMek,
            "appendBatch" => Self::AppendBatch,
            "redactMessage" => Self::RedactMessage,
            "findMeks" => Self::FindMeks,
            "listBatches" => Self::ListBatches,
            "messageLive" => Self::MessageLive,
            "purgeAuthor" => Self::PurgeAuthor,
            _ => return Err(LabyrinthError::invalid("unknown relay op")),
        })
    }

    pub fn name(self) -> &'static str {
        match self {
            Self::CreateMek => "createMek",
            Self::AppendBatch => "appendBatch",
            Self::RedactMessage => "redactMessage",
            Self::FindMeks => "findMeks",
            Self::ListBatches => "listBatches",
            Self::MessageLive => "messageLive",
            Self::PurgeAuthor => "purgeAuthor",
        }
    }

    /// Writes carry the device's signed write body.
    pub fn is_write(self) -> bool {
        matches!(
            self,
            Self::CreateMek | Self::AppendBatch | Self::RedactMessage | Self::PurgeAuthor
        )
    }

    /// The endpoint the device signed its write body for.
    pub fn signed_nsid(self) -> String {
        let endpoint = match self {
            Self::PurgeAuthor => "deleteAccountData",
            other => other.name(),
        };
        format!("blue.catbird.labyrinth.{endpoint}")
    }
}

/// `labyrinthRelay` input.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RelayRequest {
    pub op: String,
    pub actor_did: String,
    pub actor_device_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub query: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub payload: Option<Bytes>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub write_body: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub write_signature: Option<String>,
}

pub fn not_home_ds() -> LabyrinthError {
    LabyrinthError::forbidden(
        "NotHomeDs",
        "the requesting DS is not the actor's home DS in this conversation",
    )
}

pub fn not_sequencer() -> LabyrinthError {
    LabyrinthError::invalid_named("NotSequencer", "this DS does not sequence the conversation")
}

/// Error names a sequencer may answer with that the home DS passes through
/// unchanged (each is a `&'static str` in `LabyrinthError`).
const PASSTHROUGH: &[&str] = &[
    "NotParticipant",
    "RecipientNotParticipant",
    "SenderMismatch",
    "AttestationNotCurrent",
    "UnknownMek",
    "MixedMekBatch",
    "SenderKeyMismatch",
    "NotRecipient",
    "RecordAlreadyExists",
    "InvalidRequest",
    "InvalidRedaction",
    "InvalidSignature",
    "IdempotencyConflict",
    "DeviceRevoked",
    "NotAuthorized",
    "QuotaExceeded",
    "ConversationMoved",
    "NotHomeDs",
    "NotSequencer",
    "RateLimited",
    "CutoverRequired",
    "PayloadTooLarge",
];

/// Map a sequencer's error response to the typed error the device sees.
/// Anything unrecognized is the relay's own failure.
pub fn passthrough_error(status: u16, body: &[u8]) -> LabyrinthError {
    #[derive(Deserialize)]
    struct Wire {
        error: String,
        #[serde(default)]
        message: String,
    }
    let parsed: Option<Wire> = serde_json::from_slice(body).ok();
    let code = axum::http::StatusCode::from_u16(status).ok();
    match (parsed, code) {
        (Some(wire), Some(code)) if code.is_client_error() => {
            match PASSTHROUGH.iter().find(|n| **n == wire.error) {
                Some(name) => LabyrinthError::new(code, name, wire.message),
                None => {
                    tracing::warn!(status, error = %wire.error, "unrecognized relay error");
                    LabyrinthError::relay_unavailable()
                }
            }
        }
        _ => {
            tracing::warn!(status, "labyrinth relay failed upstream");
            LabyrinthError::relay_unavailable()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ops_round_trip_and_writes_sign_their_endpoint() {
        for op in [
            RelayOp::CreateMek,
            RelayOp::AppendBatch,
            RelayOp::RedactMessage,
            RelayOp::FindMeks,
            RelayOp::ListBatches,
            RelayOp::MessageLive,
            RelayOp::PurgeAuthor,
        ] {
            assert_eq!(RelayOp::parse(op.name()).unwrap(), op);
        }
        assert_eq!(
            RelayOp::PurgeAuthor.signed_nsid(),
            "blue.catbird.labyrinth.deleteAccountData"
        );
        assert!(!RelayOp::MessageLive.is_write());
    }

    #[test]
    fn only_known_client_errors_pass_through() {
        let e = passthrough_error(403, br#"{"error":"NotRecipient","message":"m"}"#);
        assert_eq!((e.status().as_u16(), e.name()), (403, "NotRecipient"));
        let e = passthrough_error(400, br#"{"error":"Surprise","message":"m"}"#);
        assert_eq!(e.name(), "RelayUnavailable");
        let e = passthrough_error(500, br#"{"error":"InternalServerError"}"#);
        assert_eq!(e.name(), "RelayUnavailable");
    }
}
