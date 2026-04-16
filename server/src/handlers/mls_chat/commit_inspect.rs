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
pub(crate) struct CommitShape {
    pub(crate) wire_format: WireFormat,
    pub(crate) content_type: ContentType,
}

#[derive(Debug, thiserror::Error)]
pub(crate) enum CommitInspectError {
    #[error("commit bytes failed TLS decode: {0}")]
    Decode(String),
    #[error("unexpected MlsMessage body (expected handshake)")]
    NotHandshake,
    #[error("content type is {0:?}, expected ContentType::Commit")]
    WrongContentType(ContentType),
}

/// Decode an MLS message and confirm it is a handshake Commit.
/// Does not attempt to decrypt proposal bodies (cannot, under PURE_CIPHERTEXT).
pub(crate) fn inspect_commit_shape(bytes: &[u8]) -> Result<CommitShape, CommitInspectError> {
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
    })
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
}
