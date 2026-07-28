use std::fs;

const STATE_MACHINE_PATH: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/src/chat_protocol/state_machine.rs"
);

fn state_machine_source() -> String {
    fs::read_to_string(STATE_MACHINE_PATH).expect("read state-machine source")
}

#[test]
fn task6_metadata_dispatches_to_the_atomic_executor_arm() {
    let source = state_machine_source();

    for required in [
        "PlanKind::Metadata => {",
        "apply_metadata_transition(",
        "preflight_metadata_transition(plan, ctx, transition_id, seq_i64)",
        "GenerationStateKind::Metadata",
        "TransitionKind::Metadata",
        "write_metadata_update_snapshot(",
    ] {
        assert!(
            source.contains(required),
            "metadata execution must retain `{required}`"
        );
    }
    assert!(
        !source
            .contains("PlanKind::Metadata => Err(ExecutorError::UnsupportedEffect(\"metadata\"))"),
        "a valid signedMetadataTransition must not terminate at the old unsupported branch"
    );
}

#[test]
fn task6_metadata_preflight_rebinds_all_sealed_authority_families() {
    let source = state_machine_source();

    for required in [
        "Some(PlanAuthority::Transition(authority)) if authority == producer",
        "Some(TransitionBodyBinding::Metadata {",
        "metadata_author_matches_evidence(after, authority)",
        "after.nonce() == before.nonce()",
        "metadata recovery request/reservation/package families are not bijective",
        "metadata recovery package CAS authority drift",
        "metadata Welcome dispositions are not complete/bijective",
        "MetadataAvatarPersistence::Reuse",
        "MetadataAvatarPersistence::Fresh",
        "metadata fresh avatar lock/binding authority drifted",
        "bind_metadata_avatar_blob",
        "terminal_is_exact_due_expiry",
        "metadata primary event/audience/spine shape drifted",
        "run_metadata_semantic_proof",
    ] {
        assert!(
            source.contains(required),
            "metadata preflight must retain `{required}`"
        );
    }
}
