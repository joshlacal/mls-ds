//! Test harness mounting of chat_protocol modules for integration test suites.
//!
//! Provides the complete `chat_protocol` module tree in its canonical hierarchy
//! without modifying production rustdoc or relaxing production visibility.

#[allow(dead_code)]
#[path = "../../../server/src/chat_protocol/cursor.rs"]
pub mod cursor;

pub(crate) use cursor::{
    mint_capability_token, CursorCodecError, CursorSealer, OsSecureRandom, SealedCapability,
    SealerBinding, SecureRandom,
};

#[allow(dead_code)]
#[path = "../../../server/src/chat_protocol/model.rs"]
pub mod model;

#[allow(dead_code)]
#[path = "../../../server/src/chat_protocol/transcript.rs"]
pub mod transcript;

#[allow(dead_code)]
#[path = "../../../server/src/chat_protocol/validation.rs"]
pub mod validation;

#[allow(dead_code)]
#[path = "../../../server/src/chat_protocol/relationship_policy.rs"]
pub mod relationship_policy;

#[allow(dead_code)]
#[path = "../../../server/src/chat_protocol/read_projection.rs"]
pub mod read_projection;

#[allow(dead_code)]
#[path = "../../../server/src/chat_protocol/federation_routing.rs"]
pub mod federation_routing;

#[allow(dead_code)]
#[path = "../../../server/src/chat_protocol/read_authority.rs"]
pub mod read_authority;

#[allow(dead_code)]
#[path = "../../../server/src/chat_protocol/dpop.rs"]
pub mod dpop;

#[allow(dead_code)]
#[path = "../../../server/src/chat_protocol/public_state.rs"]
pub mod public_state;
pub mod snapshot {
    pub use catbird_server::chat_protocol::snapshot::*;
}
pub mod wire {
    pub use catbird_server::chat_protocol::wire::*;
}

#[allow(dead_code)]
#[path = "."]
pub mod repository {
    #[path = "../../../server/src/chat_protocol/repository/acceptance.rs"]
    pub mod acceptance;
    #[path = "../../../server/src/chat_protocol/repository/auth.rs"]
    pub mod auth;
    #[path = "../../../server/src/chat_protocol/repository/blobs.rs"]
    pub mod blobs;
    #[path = "../../../server/src/chat_protocol/repository/conversation.rs"]
    pub mod conversation;
    #[path = "../../../server/src/chat_protocol/repository/coordinate.rs"]
    pub mod coordinate;
    #[path = "../../../server/src/chat_protocol/repository/core.rs"]
    pub mod core;
    #[path = "../../../server/src/chat_protocol/repository/creation.rs"]
    pub mod creation;
    #[path = "../../../server/src/chat_protocol/repository/delivery.rs"]
    pub mod delivery;
    #[path = "../../../server/src/chat_protocol/repository/device_directory.rs"]
    pub mod device_directory;
    #[path = "../../../server/src/chat_protocol/repository/entry_read.rs"]
    pub mod entry_read;
    #[path = "../../../server/src/chat_protocol/repository/execution_context.rs"]
    pub mod execution_context;
    #[path = "../../../server/src/chat_protocol/repository/expiry_sweep.rs"]
    pub mod expiry_sweep;
    #[path = "../../../server/src/chat_protocol/repository/inventory.rs"]
    pub mod inventory;
    #[path = "../../../server/src/chat_protocol/repository/key_packages.rs"]
    pub mod key_packages;
    #[path = "../../../server/src/chat_protocol/repository/leave.rs"]
    pub mod leave;
    #[path = "../../../server/src/chat_protocol/repository/message_delivery.rs"]
    pub mod message_delivery;
    #[path = "../../../server/src/chat_protocol/repository/prelude.rs"]
    pub mod prelude;
    #[path = "../../../server/src/chat_protocol/repository/recovery.rs"]
    pub mod recovery;
    #[path = "../../../server/src/chat_protocol/repository/relationship.rs"]
    pub mod relationship;
    #[path = "../../../server/src/chat_protocol/repository/reset.rs"]
    pub mod reset;
    #[path = "../../../server/src/chat_protocol/repository/revocation.rs"]
    pub mod revocation;
    #[path = "../../../server/src/chat_protocol/repository/submit_transition.rs"]
    pub mod submit_transition;
    #[path = "../../../server/src/chat_protocol/repository/subscription.rs"]
    pub mod subscription;
    #[path = "../../../server/src/chat_protocol/repository/ticket.rs"]
    pub mod ticket;
    #[path = "../../../server/src/chat_protocol/repository/transition.rs"]
    pub mod transition;
    #[path = "../../../server/src/chat_protocol/repository/welcome.rs"]
    pub mod welcome;
    #[path = "../../../server/src/chat_protocol/repository/welcome_terminal.rs"]
    pub mod welcome_terminal;
    pub mod federation {
        use catbird_atproto::generated::blue_catbird::chat::ConversationCoordinates;
        use catbird_atproto::generated::blue_catbird::mlsDS::submit_commit::SubmitCommit;
        use jacquard_common::DefaultStr;
        use uuid::Uuid;

        #[allow(clippy::too_many_arguments)]
        pub async fn enqueue_federated_welcome_job(
            _transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
            _conversation_id: Uuid,
            _target_ds_did: &str,
            _recipient_did_str: &str,
            _recipient_device_id: Uuid,
            _welcome_id: Uuid,
            _recovery_request_id: Uuid,
            _reserved_ref: &[u8; 32],
            _opaque_welcome: &[u8],
            _sha256: &[u8; 32],
            _append: &super::delivery::AppendEntry,
            _seq: u64,
            _coordinates: ConversationCoordinates,
            _pub_snap_sha: &[u8; 32],
            _tree_sum_sha: &[u8; 32],
            _sequencer_term: u64,
        ) -> Result<Uuid, super::super::state_machine::ExecutorError> {
            Ok(Uuid::nil())
        }

        pub async fn enqueue_clean_federation_message_jobs(
            _tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
            _conversation_id: Uuid,
            _entry: &super::delivery::AppendEntry,
            _seq: u64,
            _sequencer_term: u64,
        ) -> Result<usize, catbird_server::federation::errors::FederationError> {
            Ok(0)
        }

        pub fn build_federated_commit_envelope(
            _conversation_id: Uuid,
            _transition_id: Uuid,
            _sequencer_ds_did: &str,
            _signed_request_bytes: &[u8],
            _sequencer_term: u64,
            _received_at: &crate::chat_protocol::validation::CanonicalTimestamp,
        ) -> Result<SubmitCommit<DefaultStr>, catbird_server::federation::errors::FederationError>
        {
            Err(
                catbird_server::federation::errors::FederationError::InvalidEnvelope {
                    reason: "test stub".to_string(),
                },
            )
        }
    }
}

#[allow(dead_code)]
#[path = "../../../server/src/chat_protocol/state_machine.rs"]
pub mod state_machine;
