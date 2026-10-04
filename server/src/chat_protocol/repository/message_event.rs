//! Application event append parity with the deployed7ad source.
//! Source helper SHA256: b14506719c6ce7baa5d4f22911bfb562c6aed00bd4d737369788232e87bc5438
//! Preserve the existing device-row, foreign-key, and deferred-chain fences.
//!
//! The merged lines carried byte-identical copies of this helper (main kept it
//! in `delivery`, encrypted-requests moved it here); this module now re-exports
//! the single `delivery` definition so the two cannot drift.
pub(crate) use super::delivery::append_message_available_event;
