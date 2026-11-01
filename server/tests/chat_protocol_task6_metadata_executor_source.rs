use std::fs;
use std::path::Path;

fn append_non_test_rs_files(dir: &Path, out: &mut String) {
    let mut entries: Vec<_> = fs::read_dir(dir)
        .expect("read module dir")
        .map(|entry| entry.expect("dir entry").path())
        .filter(|path| {
            path.extension().and_then(|ext| ext.to_str()) == Some("rs")
                && !path
                    .file_name()
                    .and_then(|name| name.to_str())
                    .is_some_and(|name| name.contains("test"))
        })
        .collect();
    entries.sort();
    for path in entries {
        out.push_str(&fs::read_to_string(&path).expect("read submodule source"));
    }
}

fn state_machine_source() -> String {
    let manifest_dir = Path::new(env!("CARGO_MANIFEST_DIR"));
    let mut source = fs::read_to_string(manifest_dir.join("src/chat_protocol/state_machine.rs"))
        .expect("read state-machine source");
    append_non_test_rs_files(
        &manifest_dir.join("src/chat_protocol/state_machine"),
        &mut source,
    );
    append_non_test_rs_files(
        &manifest_dir.join("src/chat_protocol/state_machine/executor"),
        &mut source,
    );
    source
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
        "write_metadata_update_snapshot",
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
