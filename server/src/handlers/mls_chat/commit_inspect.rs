//! Defense-in-depth framing inspector for MLS commit bytes.
//!
//! catbird-mls uses `PURE_CIPHERTEXT_WIRE_FORMAT_POLICY`, so every handshake
//! commit reaching the DS is a `PrivateMessage` with proposal bodies encrypted
//! under the group's handshake key. The server doesn't hold that key, so it
//! cannot decide "does this commit contain an Add proposal." It CAN cheaply
//! confirm the bytes decode as a handshake MLS message of `ContentType::Commit`
//! — rejecting malformed bytes, Application data, or bare Proposal messages
//! before they reach the epoch CAS.
//!
//! See docs/superpowers/plans/2026-04-16-commit-add-proposal-gate.md.

use openmls::prelude::{ContentType, MlsMessageBodyIn, MlsMessageIn, ProtocolMessage, WireFormat};
use tls_codec::Deserialize as _;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CommitShape {
    pub wire_format: WireFormat,
    pub content_type: ContentType,
    pub epoch: u64,
}

#[derive(Debug, thiserror::Error)]
pub enum CommitInspectError {
    #[error("commit bytes failed TLS decode: {0}")]
    Decode(String),
    #[error("unexpected MlsMessage body (expected handshake)")]
    NotHandshake,
    #[error("content type is {0:?}, expected ContentType::Commit")]
    WrongContentType(ContentType),
}

/// Decode an MLS message and confirm it is a handshake Commit.
/// Does not attempt to decrypt proposal bodies (cannot, under PURE_CIPHERTEXT).
pub fn inspect_commit_shape(bytes: &[u8]) -> Result<CommitShape, CommitInspectError> {
    let msg = MlsMessageIn::tls_deserialize(&mut &*bytes)
        .map_err(|e| CommitInspectError::Decode(format!("{e:?}")))?;
    let protocol_msg: ProtocolMessage = match msg.extract() {
        MlsMessageBodyIn::PublicMessage(m) => m.into(),
        MlsMessageBodyIn::PrivateMessage(m) => ProtocolMessage::PrivateMessage(m),
        _ => return Err(CommitInspectError::NotHandshake),
    };
    let content_type = protocol_msg.content_type();
    if content_type != ContentType::Commit {
        return Err(CommitInspectError::WrongContentType(content_type));
    }
    Ok(CommitShape {
        wire_format: protocol_msg.wire_format(),
        content_type,
        epoch: protocol_msg.epoch().as_u64(),
    })
}

/// Why a `commit` / `updateMetadata` request was rejected by the
/// action→shape contract. Distinguishes the three defense-in-depth cases so
/// the handler can emit distinct log messages and (future) metric labels.
#[derive(Debug, thiserror::Error)]
pub enum CommitActionContractError {
    #[error("welcome field is only valid with action=addMembers")]
    WelcomeSet,
    #[error("memberDids is only valid with action=addMembers")]
    MemberDidsSet,
    #[error("Invalid commit framing: {0}")]
    BadFraming(#[from] CommitInspectError),
}

/// Enforce the action→shape contract on `action: "commit"` /
/// `"updateMetadata"` requests.
///
/// Under `PURE_CIPHERTEXT_WIRE_FORMAT_POLICY` the server cannot inspect
/// proposal bodies, so we gate on surface markers plus framing well-formedness:
///
/// 1. `welcome` must be absent (Welcomes only accompany Add proposals).
/// 2. `member_dids` must be empty (only addMembers attaches new DIDs).
/// 3. `commit_bytes` must decode as a handshake `Commit`.
///
/// Returns the decoded `CommitShape` on success so the handler can log framing
/// telemetry.
///
/// See docs/superpowers/plans/2026-04-16-commit-add-proposal-gate.md.
pub fn enforce_non_add_action_contract(
    welcome_present: bool,
    member_dids_nonempty: bool,
    commit_bytes: &[u8],
) -> Result<CommitShape, CommitActionContractError> {
    if welcome_present {
        return Err(CommitActionContractError::WelcomeSet);
    }
    if member_dids_nonempty {
        return Err(CommitActionContractError::MemberDidsSet);
    }
    let shape = inspect_commit_shape(commit_bytes)?;
    Ok(shape)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn malformed_bytes_return_decode_error() {
        assert!(matches!(
            inspect_commit_shape(&[0, 1, 2]).unwrap_err(),
            CommitInspectError::Decode(_)
        ));
    }

    #[test]
    fn empty_bytes_return_decode_error() {
        assert!(matches!(
            inspect_commit_shape(&[]).unwrap_err(),
            CommitInspectError::Decode(_)
        ));
    }

    // ── enforce_non_add_action_contract ───────────────────────────────────
    //
    // TDD: these tests drive Phase 2's defense-in-depth gate on the
    // commit / updateMetadata branch of commit_group_change.

    #[test]
    fn action_contract_rejects_welcome_even_with_valid_bytes() {
        // Even if the commit bytes are garbage, welcome-present should trip
        // first (cheaper check, and the primary Add signature).
        let bogus_commit = [0u8; 8];
        let err = enforce_non_add_action_contract(true, false, &bogus_commit).unwrap_err();
        assert!(matches!(err, CommitActionContractError::WelcomeSet));
    }

    #[test]
    fn action_contract_rejects_nonempty_member_dids() {
        let bogus_commit = [0u8; 8];
        let err = enforce_non_add_action_contract(false, true, &bogus_commit).unwrap_err();
        assert!(matches!(err, CommitActionContractError::MemberDidsSet));
    }

    #[test]
    fn action_contract_rejects_malformed_commit_bytes() {
        let err =
            enforce_non_add_action_contract(false, false, &vec![0xFFu8; 64]).unwrap_err();
        assert!(matches!(
            err,
            CommitActionContractError::BadFraming(CommitInspectError::Decode(_))
        ));
    }

    #[test]
    fn action_contract_rejects_empty_commit_bytes() {
        let err = enforce_non_add_action_contract(false, false, &[]).unwrap_err();
        assert!(matches!(
            err,
            CommitActionContractError::BadFraming(CommitInspectError::Decode(_))
        ));
    }

    #[test]
    fn action_contract_welcome_precedes_member_dids() {
        // When both markers are set, welcome wins (more specific signature).
        let bogus_commit = [0u8; 8];
        let err = enforce_non_add_action_contract(true, true, &bogus_commit).unwrap_err();
        assert!(matches!(err, CommitActionContractError::WelcomeSet));
    }
}
