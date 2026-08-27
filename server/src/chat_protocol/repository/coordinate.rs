// Canonical JSON representation for coordinate-bearing response DTOs.
//
// The chat lexicon declares these fields as `bytes`. Jacquard's generated
// `ConversationCoordinates` uses `serde_bytes_helper`, whose JSON contract is
// an object containing `$bytes` and a standard-base64 string. It is not the
// bare string form. Every response endpoint carrying coordinates must use
// this helper so creation, submitTransition, acceptance, leave, and reset
// cannot drift independently.
//
// Two entry points, because the callers do not share a lifecycle
// precondition. `submitTransition` legitimately reports a superseded
// coordinate — superseding prior state is what a transition does. Creation and
// acceptance must not: a non-active coordinate there is a violated invariant,
// and both rejected it before this logic was centralised. Keeping that guard
// here rather than at the call sites means it cannot drift either, which is
// the same reason the encoding lives here.

use base64::{engine::general_purpose::STANDARD, Engine};
use serde_json::{json, Value};
use uuid::Uuid;

use crate::chat_protocol::snapshot::{PublicGroupSnapshotCoordinate, PublicGroupSnapshotLifecycle};

/// Canonical JSON for a coordinate in any lifecycle state.
///
/// Integer fields use checked conversion: a width overflow is an error, never a
/// wrapped value.
pub(crate) fn canonical_coordinate_json(
    coordinate: &PublicGroupSnapshotCoordinate,
) -> Result<Value, ()> {
    let generation = i64::try_from(coordinate.generation()).map_err(|_| ())?;
    let state_version = i64::try_from(coordinate.state_version()).map_err(|_| ())?;
    let epoch = i64::try_from(coordinate.epoch()).map_err(|_| ())?;
    let lifecycle = match coordinate.lifecycle() {
        PublicGroupSnapshotLifecycle::Active => "active",
        PublicGroupSnapshotLifecycle::Superseded => "superseded",
    };

    Ok(json!({
        "conversationId": Uuid::from_bytes(*coordinate.conversation_id()).hyphenated().to_string(),
        "generation": generation,
        "stateVersion": state_version,
        "groupId": { "$bytes": STANDARD.encode(coordinate.group_id()) },
        "epoch": epoch,
        "groupContextHash": { "$bytes": STANDARD.encode(coordinate.group_context_hash()) },
        "confirmationTag": { "$bytes": STANDARD.encode(coordinate.confirmation_tag()) },
        "lifecycle": lifecycle,
    }))
}

/// Canonical JSON for a coordinate that MUST be active.
///
/// Used by conversation creation and acceptance, where a superseded coordinate
/// is an invariant violation rather than a reportable state. Emitting one would
/// hand the client a response describing a conversation it cannot act on.
pub(crate) fn canonical_active_coordinate_json(
    coordinate: &PublicGroupSnapshotCoordinate,
) -> Result<Value, ()> {
    if coordinate.lifecycle() != PublicGroupSnapshotLifecycle::Active {
        return Err(());
    }
    canonical_coordinate_json(coordinate)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture(lifecycle: PublicGroupSnapshotLifecycle) -> PublicGroupSnapshotCoordinate {
        PublicGroupSnapshotCoordinate::new(
            [7u8; 16], 3, 9, [1u8; 32], 4, [2u8; 32], [3u8; 32], lifecycle,
        )
    }

    fn active_fixture() -> PublicGroupSnapshotCoordinate {
        fixture(PublicGroupSnapshotLifecycle::Active)
    }

    fn superseded_fixture() -> PublicGroupSnapshotCoordinate {
        fixture(PublicGroupSnapshotLifecycle::Superseded)
    }
    /// The `$bytes` wrapper is the entire reason this module exists: the bare
    /// base64 string form is a different wire contract and Jacquard's generated
    /// deserializer rejects it.
    #[test]
    fn byte_fields_are_dollar_bytes_objects_not_bare_strings() {
        let coordinate = active_fixture();
        let value = canonical_coordinate_json(&coordinate).expect("canonical json");

        for field in ["groupId", "groupContextHash", "confirmationTag"] {
            assert!(
                value[field].is_object(),
                "{field} must be a $bytes object, got {:?}",
                value[field]
            );
            assert!(
                value[field]["$bytes"].is_string(),
                "{field} must carry a $bytes string"
            );
        }
    }

    /// Pins the guard that the centralisation of this logic originally dropped:
    /// creation and acceptance rejected non-active coordinates, and must still.
    #[test]
    fn active_only_entry_point_rejects_a_superseded_coordinate() {
        let superseded = superseded_fixture();
        assert!(
            canonical_active_coordinate_json(&superseded).is_err(),
            "a superseded coordinate must not be serialised for creation or acceptance"
        );
        // The unguarded entry point still accepts it, for submitTransition.
        assert_eq!(
            canonical_coordinate_json(&superseded).expect("unguarded json")["lifecycle"],
            "superseded"
        );
    }

    #[test]
    fn active_lifecycle_round_trips_through_both_entry_points() {
        let coordinate = active_fixture();
        let guarded = canonical_active_coordinate_json(&coordinate).expect("guarded json");
        let unguarded = canonical_coordinate_json(&coordinate).expect("unguarded json");
        assert_eq!(
            guarded, unguarded,
            "for an active coordinate the two entry points must agree byte for byte"
        );
        assert_eq!(guarded["lifecycle"], "active");
    }
}
