//! Regression table compiled from the production pending-consent policy.
#![allow(dead_code)]
#[path = "../src/chat_protocol/model.rs"]
mod model;
#[path = "../src/chat_protocol/transcript.rs"]
mod transcript;
#[path = "../src/chat_protocol/validation.rs"]
mod validation;
mod chat_protocol {
    pub mod read_projection {
        pub struct DummyCanonical;
        impl DummyCanonical {
            pub fn bytes(&self) -> &[u8] { &[] }
        }
        pub fn encode_canonical_generated_chat_json_v1<T: serde::Serialize>(
            _value: &T,
            _schema: &str,
        ) -> Result<DummyCanonical, String> {
            Ok(DummyCanonical)
        }
    }
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
