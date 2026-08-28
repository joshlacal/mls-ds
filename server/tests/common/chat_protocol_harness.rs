//! Test harness mounting of chat_protocol modules for integration test suites.
//!
//! Provides the complete `chat_protocol` module tree in its canonical hierarchy
//! without modifying production rustdoc or relaxing production visibility.

#[allow(dead_code)]
#[path = "../../../server/src/chat_protocol/cursor.rs"]
pub mod cursor;

#[allow(unused_imports)]
pub(crate) use cursor::{
    decode_capability_token, mint_capability_token, CapabilityToken, CursorCodec, CursorCodecError,
    CursorSealer, DeviceCursorBinding, EventCursor, InventoryPageBinding, InventoryPageDomain,
    InventoryPageLocator, InventorySessionBinding, InventorySessionToken,
    LockedInventoryPageVerification, OsSecureRandom, OwnDeviceCursorBinding, SealedCapability,
    SealerBinding, SealerError, SecureRandom, SecureRandomError, VerifiedInventoryPageCursor,
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
    pub mod remote_prefix {
        use sha2::{Digest, Sha256};
        use uuid::Uuid;
        #[derive(Debug)]
        pub struct HistoricalWriteWitness {
            _sealed: (),
        }
        #[derive(Clone, Copy, Debug, PartialEq, Eq)]
        pub enum BootstrapLocalIdLabel {
            ParticipantPeriod,
            LeafPeriod,
            MetadataSnapshot,
        }
        impl BootstrapLocalIdLabel {
            pub fn as_str(&self) -> &'static str {
                match self {
                    Self::ParticipantPeriod => "participant-period",
                    Self::LeafPeriod => "leaf-period",
                    Self::MetadataSnapshot => "metadata-snapshot",
                }
            }
        }

        pub fn derive_bootstrap_local_id(
            conversation_id: Uuid,
            source_entry_id: Uuid,
            label: BootstrapLocalIdLabel,
            entity_key: &[u8],
        ) -> Uuid {
            let mut hasher = Sha256::new();
            hasher.update(b"CATBIRD-CLEAN-REMOTE-BOOTSTRAP-LOCAL-ID-V1\0");
            hasher.update(conversation_id.as_bytes());
            hasher.update(source_entry_id.as_bytes());
            let label = label.as_str().as_bytes();
            hasher.update((label.len() as u16).to_be_bytes());
            hasher.update(label);
            hasher.update((entity_key.len() as u32).to_be_bytes());
            hasher.update(entity_key);
            let mut bytes: [u8; 16] = hasher.finalize()[..16].try_into().expect("fixed length");
            bytes[6] = (bytes[6] & 0x0f) | 0x40;
            bytes[8] = (bytes[8] & 0x3f) | 0x80;
            Uuid::from_bytes(bytes)
        }
    }
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

#[allow(dead_code)]
pub(crate) fn mint_signed_repository_authority(
    pre_replay: dpop::PreReplayCryptographicVerification,
    canonical: transcript::CanonicalSignedMutation,
    stored_public_key: &[u8],
    repository_receipt: repository::auth::RepositoryAuthorityReceipt,
) -> Result<dpop::VerifiedChatDeviceRequest, model::AuthPrimitiveError> {
    dpop::mint_signed_repository_authority(
        pre_replay,
        canonical,
        stored_public_key,
        repository_receipt,
    )
}

#[allow(dead_code)]
pub(crate) fn mint_unsigned_repository_authority(
    pre_replay: dpop::PreReplayCryptographicVerification,
    repository_receipt: repository::auth::RepositoryAuthorityReceipt,
) -> dpop::VerifiedChatDeviceRequest {
    dpop::mint_unsigned_repository_authority(pre_replay, repository_receipt)
}
