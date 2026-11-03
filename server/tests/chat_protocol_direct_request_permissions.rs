//! Regression table compiled from the production pending-consent policy.
#![allow(dead_code)]
pub use catbird_server::sim_hooks;
#[path = "../src/chat_protocol/model.rs"]
mod model;
#[path = "../src/chat_protocol/read_projection.rs"]
mod read_projection;
#[path = "../src/chat_protocol/transcript.rs"]
mod transcript;
#[path = "../src/chat_protocol/validation.rs"]
mod validation;
// Compile the actual canonical encoder used by transcript.rs's request-view
// tests. An empty-byte stand-in cannot exercise its round-trip contract.
mod chat_protocol {
    pub(crate) use crate::read_projection;
    pub use catbird_server::chat_protocol::direct_request_transcript;
    pub mod transcript {
        pub use crate::transcript::*;
    }
}
#[path = "../src/chat_protocol/repository/direct_request_permissions.rs"]
mod policy;
use chat_protocol::transcript::SignedMutationKind as K;

#[test]
fn both_accounts_pending_are_denied_every_content_and_recovery_mutation() {
    for _account_role in ["incoming recipient", "active creator"] {
        for kind in [
            K::ApplicationSend,
            K::Typing,
            K::BlobUploadPreparation,
            K::BlobDeletion,
            K::CommitTransition,
            K::PolicyTransition,
            K::ParticipantAcceptance,
            K::MetadataTransition,
            K::ResetRequest,
            K::ResetActivation,
            K::LeafRecoveryRequest,
            K::LeafRecoveryCancellation,
            K::LeafRecoveryFulfillment,
            K::LeaveRequest,
            K::ZeroLeafLeave,
            K::LeaveCancellation,
            K::LeaveCommitFulfillment,
        ] {
            assert!(!policy::allowed_while_pending(kind), "{kind:?}");
        }
    }
}
#[test]
fn close_and_private_welcome_disposition_remain_available() {
    for kind in [
        K::ConversationClose,
        K::WelcomeAcknowledgement,
        K::WelcomeRejection,
    ] {
        assert!(policy::allowed_while_pending(kind));
    }
}
