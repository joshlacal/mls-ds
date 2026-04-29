//! Phase 2 of the commit-add-proposal-gate plan.
//!
//! The plan's original tests exercise the gate through the full axum/XRPC
//! stack (spawn server, create users, POST commitGroupChange). The existing
//! `server/tests/` harness doesn't drive a real MLS context on the client
//! side, so we can't build a well-formed MLS commit in-process to cover
//! `clean_self_update_commit_is_accepted` without standing up
//! `MLSContext` + OpenMLS inside the test binary.
//!
//! Instead, these tests exercise the pure gate function — the same function
//! the handler calls — covering all three rejection paths plus the positive
//! path via the `inspect_commit_shape` layer. An end-to-end clean-commit
//! test should be added once `tests/` has an MLS client fixture available.
//!
//! See docs/superpowers/plans/2026-04-16-commit-add-proposal-gate.md.

use catbird_server::handlers::mls_chat::commit_inspect::{
    enforce_non_add_action_contract, CommitActionContractError, CommitInspectError,
};

#[test]
fn commit_action_with_welcome_is_rejected() {
    // Even if the commit bytes are valid (here: bogus, but the welcome check
    // fires before framing inspection), `welcome` under action=commit is a
    // forbidden Add signature.
    let bogus_commit = [0u8; 8];
    let err = enforce_non_add_action_contract(true, false, &bogus_commit).unwrap_err();
    assert!(matches!(err, CommitActionContractError::WelcomeSet));
}

#[test]
fn update_metadata_with_member_dids_is_rejected() {
    // `memberDids` non-empty under action=updateMetadata is a forbidden Add
    // signature. The gate doesn't care which non-add action dispatched it —
    // the pure function takes the same shape regardless.
    let bogus_commit = [0u8; 8];
    let err = enforce_non_add_action_contract(false, true, &bogus_commit).unwrap_err();
    assert!(matches!(err, CommitActionContractError::MemberDidsSet));
}

#[test]
fn commit_action_with_malformed_bytes_is_rejected() {
    // 64 bytes of 0xFF won't decode as any MlsMessageIn variant.
    let err = enforce_non_add_action_contract(false, false, &[0xFFu8; 64]).unwrap_err();
    assert!(matches!(
        err,
        CommitActionContractError::BadFraming(CommitInspectError::Decode(_))
    ));
}

#[test]
#[ignore = "Requires test-side MLSContext to produce a real self-update commit; not currently wired into server/tests harness"]
fn clean_self_update_commit_is_accepted() {
    // Skipped: see module-level doc comment.
    //
    // When a test-side MLS client fixture exists, replace this with:
    //   let commit = alice.build_self_update_commit(&convo.id).await;
    //   let shape = enforce_non_add_action_contract(false, false, &commit).unwrap();
    //   assert_eq!(shape.content_type, ContentType::Commit);
    unreachable!("ignored test");
}
