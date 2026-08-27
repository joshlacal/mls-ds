//! Clean-cutover chat protocol primitives.

use std::panic::AssertUnwindSafe;

use libcrux_kem::{Algorithm as KemAlgorithm, PublicKey as KemPublicKey};

pub(crate) const XWING_PUBLIC_KEY_BYTES: usize = 1_216;
pub(crate) const XWING_KEM_OUTPUT_BYTES: usize = 1_120;
// Canonical BasicCredential identity is `actorDid + "#" + deviceId`.
// Protocol v1 supports exact `did:plc:[a-z2-7]{24}` identities or hostname-only
// production `did:web` identities. `did:web:a.co` is the shortest supported DID,
// while `did:web:` plus a 253-byte hostname is the longest; device IDs are
// canonical textual UUIDv4 values.
pub(crate) const MIN_BARE_DID_BYTES: usize = 12;
pub(crate) const MAX_BARE_DID_BYTES: usize = 8 + 253;
pub(crate) const MIN_BASIC_CREDENTIAL_BYTES: usize = MIN_BARE_DID_BYTES + 1 + 36;
pub(crate) const MAX_BASIC_CREDENTIAL_BYTES: usize = MAX_BARE_DID_BYTES + 1 + 36;
const XWING_X25519_PUBLIC_KEY_OFFSET: usize = 1_184;
const XWING_X25519_KEM_OUTPUT_OFFSET: usize = 1_088;
const X25519_FIELD_MODULUS_LE: [u8; 32] = [
    0xED, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x7F,
];

/// Reject RFC 7748 aliases and low-order points before a component can enter
/// XWing's raw-byte combiner. The pinned libcrux decoder masks noncanonical
/// encodings, while XWing hashes their original bytes, which otherwise makes
/// encapsulation and decapsulation derive different secrets.
fn x25519_component_is_canonical_and_usable(bytes: &[u8]) -> bool {
    let Ok(component) = <[u8; 32]>::try_from(bytes) else {
        return false;
    };
    let mut less_than_modulus = false;
    for index in (0..component.len()).rev() {
        if component[index] < X25519_FIELD_MODULUS_LE[index] {
            less_than_modulus = true;
            break;
        }
        if component[index] > X25519_FIELD_MODULUS_LE[index] {
            return false;
        }
    }
    if !less_than_modulus {
        return false;
    }
    x25519_dalek::x25519([0xA5; 32], component) != [0; 32]
}

pub(crate) fn xwing_public_key_is_valid(bytes: &[u8]) -> bool {
    if bytes.len() != XWING_PUBLIC_KEY_BYTES
        || !x25519_component_is_canonical_and_usable(&bytes[XWING_X25519_PUBLIC_KEY_OFFSET..])
    {
        return false;
    }
    // `decode` alone is the whole check. It runs `mlkem768::validate_public_key`,
    // which IS the FIPS 203 encapsulation-key check (deserialize-reduced,
    // re-serialize, byte-compare), and `mlkem768::encapsulate` returns a plain
    // tuple rather than a `Result`, so the ML-KEM half of an encapsulation can
    // reject nothing. The X-Wing half's only fallible step is `x25519_derive`,
    // which errs exactly on an all-zero shared secret -- the probe the length and
    // canonicality guard above already performs with the same clamped `[0xA5; 32]`
    // scalar, plus a canonicality check `decode` does not do at all. Encapsulating
    // here cost ~66% of a per-key validation that runs 2L+N times per snapshot
    // decode, under the conversation head lock, and rejected nothing.
    std::panic::catch_unwind(AssertUnwindSafe(|| {
        KemPublicKey::decode(KemAlgorithm::XWingKemDraft06, bytes).map(|_| ())
    }))
    .is_ok_and(|result| result.is_ok())
}

pub(crate) fn xwing_kem_output_is_valid(bytes: &[u8]) -> bool {
    bytes.len() == XWING_KEM_OUTPUT_BYTES
        && x25519_component_is_canonical_and_usable(&bytes[XWING_X25519_KEM_OUTPUT_OFFSET..])
}

#[cfg(not(any(test, feature = "test-support")))]
mod cursor;
#[cfg(any(test, feature = "test-support"))]
pub mod cursor;

pub(crate) use cursor::{
    mint_capability_token, CursorCodecError, CursorSealer, OsSecureRandom, SealedCapability,
    SealerBinding, SecureRandom,
};
/// Trusted-Nest token and DPoP cryptographic verification for clean chat.
///
/// Successful values are deliberately pre-replay evidence. They are
/// non-Clone, cannot be constructed outside this module, and do not represent
/// device authority until the repository atomically consumes all replay keys
/// and validates stored device state in the same transaction.
#[cfg(not(any(test, feature = "test-support")))]
pub(crate) mod dpop;
#[cfg(any(test, feature = "test-support"))]
pub mod dpop;

pub mod error;
pub mod federation_routing;
pub use federation_routing::{
    resolve_participant_routing, ConversationRoutingIntent, FederationRoutingError,
    ParticipantRoutingIntent,
};

#[cfg(not(any(test, feature = "test-support")))]
pub(crate) mod model;
#[cfg(any(test, feature = "test-support"))]
pub mod model;

#[cfg(not(any(test, feature = "test-support")))]
pub(crate) mod public_state;
#[cfg(any(test, feature = "test-support"))]
pub mod public_state;

#[cfg(not(any(test, feature = "test-support")))]
pub(crate) mod read_authority;
#[cfg(any(test, feature = "test-support"))]
pub mod read_authority;

#[cfg(not(any(test, feature = "test-support")))]
pub(crate) mod read_projection;
#[cfg(any(test, feature = "test-support"))]
pub mod read_projection;

#[cfg(not(any(test, feature = "test-support")))]
pub(crate) mod relationship_policy;
#[cfg(any(test, feature = "test-support"))]
pub mod relationship_policy;

#[cfg(not(any(test, feature = "test-support")))]
pub(crate) mod repository;
#[cfg(any(test, feature = "test-support"))]
pub mod repository;

pub mod snapshot;

#[cfg(not(any(test, feature = "test-support")))]
pub(crate) mod state_machine;
#[cfg(any(test, feature = "test-support"))]
pub mod state_machine;

#[cfg(any(test, feature = "test-support"))]
pub mod test_support;

pub mod transcript;

#[cfg(not(any(test, feature = "test-support")))]
pub(crate) mod validation;
#[cfg(any(test, feature = "test-support"))]
pub mod validation;

pub mod wire;

/// Non-shipping executable proof runners. Only zero-authority scenario
/// functions are exported; opaque protocol authorities and prepared graphs
/// remain crate-private.
#[cfg(all(
    feature = "chat-protocol-production-proof",
    not(feature = "server-bin")
))]
#[doc(hidden)]
pub mod production_proof {
    pub use super::repository::recovery::production_composition_proof::{
        commit_open_recovery_request, mint_singleton_recovery_reservation_fallback,
        mint_two_party_recovery_fallbacks, run_aggregate_graph_drift_negative,
        run_foreign_transaction_negative, run_leaf_recovery_cancellation_due_for_expiry_ordering,
        run_leaf_recovery_cancellation_happy_path,
        run_leaf_recovery_fulfillment_due_for_expiry_ordering,
        run_leaf_recovery_fulfillment_happy_path, run_package_row_drift_negative,
        run_postwrite_cancellation_rollback_negative, run_postwrite_panic_rollback_negative,
        run_prepare_abandon_negative, run_public_snapshot_drift_negative,
        run_request_leaf_recovery_completion_rollback_negative,
        run_request_leaf_recovery_happy_path,
        run_request_leaf_recovery_operation_claim_drift_negative,
        run_request_leaf_recovery_scope_drift_negative, run_request_row_drift_negative,
        run_reservation_row_drift_negative, run_scheduler_expiry_lifecycle,
        run_terminal_head_cas_rollback_negative,
    };

    /// Execute the real metadata executor's sealed pure preflight against one
    /// exact fixture and the canonical payload, audience, spine, and avatar
    /// drift negatives. This is compiled out of every shipping server binary.
    pub fn run_metadata_executor_semantic_proof() -> Result<(), String> {
        super::state_machine::executor::run_metadata_semantic_proof()
    }

    /// Execute the real Welcome terminal hydrator's pure context-family
    /// classifier. This is compiled out of every shipping server binary.
    pub fn run_welcome_terminal_context_family_semantic_proof() -> Result<(), String> {
        super::repository::execution_context::run_welcome_terminal_context_family_semantic_proof()
    }
}
