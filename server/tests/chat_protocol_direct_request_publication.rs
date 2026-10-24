//! Real-client public-artifact interoperability. This is deliberately separate
//! from the PostgreSQL transaction qualification: no database success is implied.
use base64::{engine::general_purpose::STANDARD, Engine};
use catbird_server::chat_protocol::{
    direct_request_transcript as transcript,
    snapshot::{self, PublicGroupSnapshotCoordinate, PublicGroupSnapshotLifecycle},
    wire::{self, GroupInfoValidationPolicy, PublicCommitValidationPolicy},
};
use serde_json::Value;
fn run(leaves: usize) {
    run_named(leaves, &format!("leaves-{leaves}"));
}
fn run_named(leaves: usize, name: &str) {
    let directory = std::env::var("T02_CORPUS_DIR")
        .expect("T02_CORPUS_DIR must name retained real client corpus");
    let directory = std::path::Path::new(&directory).join(name);
    let read = |name: &str| std::fs::read(directory.join(name)).unwrap();
    let ctx: Value = serde_json::from_slice(&read("context.json")).unwrap();
    let next: Value = serde_json::from_slice(&read("coordinates.json")).unwrap();
    let lifetime: Value = serde_json::from_slice(&read("lifetimes.json")).unwrap();
    let hash = |value: &Value| -> [u8; 32] {
        STANDARD
            .decode(value.as_str().unwrap())
            .unwrap()
            .try_into()
            .unwrap()
    };
    let credential = format!(
        "{}#{}",
        ctx["actorDid"].as_str().unwrap(),
        ctx["actorDeviceId"].as_str().unwrap()
    );
    let key = read("actor-signature-public-key.bin");
    let policy = GroupInfoValidationPolicy {
        expected_basic_credential: credential.as_bytes(),
        expected_signature_key: &key,
        now_unix_seconds: lifetime["now"].as_u64().unwrap(),
        max_bytes: 1_048_576,
        max_ratchet_tree_bytes: 1_048_576,
        max_members: 40,
    };
    let genesis = wire::validate_group_info(&read("genesis.mls"), policy)
        .expect("real client genesis accepted");
    let initial = PublicGroupSnapshotCoordinate::new(
        *uuid::Uuid::parse_str(next["conversationId"].as_str().unwrap())
            .unwrap()
            .as_bytes(),
        next["generation"].as_u64().unwrap(),
        0,
        hash(&next["groupId"]),
        0,
        *genesis.group_context_hash(),
        *genesis.confirmation_tag(),
        PublicGroupSnapshotLifecycle::Active,
    );
    let final_coordinate = PublicGroupSnapshotCoordinate::new(
        *initial.conversation_id(),
        initial.generation(),
        1,
        *initial.group_id(),
        1,
        hash(&next["groupContextHash"]),
        hash(&next["confirmationTag"]),
        PublicGroupSnapshotLifecycle::Active,
    );
    assert_eq!(next["stateVersion"], 1, "fresh successor Add is state one");
    if name.ends_with("legacy") {
        let prior: Value = serde_json::from_slice(&read("prior.json")).unwrap();
        let old = wire::validate_group_info(&read("prior-genesis.mls"), policy).unwrap();
        assert_eq!(prior, ctx["origin"]["exactPrior"]);
        assert_eq!(prior["conversationId"], next["conversationId"]);
        assert_eq!(
            prior["generation"].as_u64().unwrap() + 1,
            initial.generation()
        );
        assert_ne!(old.group_id(), genesis.group_id());
        assert_eq!(old.group_context_hash(), &hash(&prior["groupContextHash"]));
    }
    let snapshot = snapshot::encode_public_group_snapshot(genesis.public_state()).unwrap();
    let binding =
        snapshot::public_group_snapshot_binding(genesis.public_state(), &snapshot, &initial)
            .unwrap();
    let context_hash = transcript::direct_request_context_hash(&read("context.json")).unwrap();
    let aad = transcript::direct_request_commit_aad(&context_hash).unwrap();
    let commit = wire::validate_public_commit(&read("add.mls"), 1_048_576).unwrap();
    let result = wire::process_public_commit(
        genesis.public_state(),
        commit,
        PublicCommitValidationPolicy {
            expected_aad: &aad,
            trusted_prior_binding: &binding,
            expected_next_coordinate: &final_coordinate,
            now_unix_seconds: policy.now_unix_seconds,
            max_members: 40,
        },
    )
    .expect("real client Add accepted");
    let final_bytes = read("final.mls");
    let final_info =
        wire::direct_request::verify_final_group_info(&final_bytes, policy, result.next_binding())
            .expect("real client final tree accepted");
    assert_eq!(result.adds().len(), leaves - 1);
    assert_eq!(
        final_info.earliest_key_package_expiry(),
        lifetime["minimumImportUntil"].as_u64().unwrap()
    );
    let welcome = wire::validate_welcome(&read("welcome.mls"), 1_048_576).unwrap();
    let expected = lifetime["expectedAddedPackageRefs"]
        .as_array()
        .unwrap()
        .iter()
        .map(hash)
        .collect::<std::collections::BTreeSet<_>>();
    assert_eq!(
        welcome
            .key_package_refs()
            .iter()
            .copied()
            .collect::<std::collections::BTreeSet<_>>(),
        expected
    );
    let app = wire::validate_private_application(&read("application.mls"), 98304).unwrap();
    assert_eq!(
        app.aad(),
        transcript::direct_request_application_aad(
            &context_hash,
            &read("coordinates.json"),
            ctx["firstMessageId"].as_str().unwrap()
        )
        .unwrap()
    );
    assert_eq!(app.group_id(), final_coordinate.group_id());
    assert_eq!(app.epoch(), 1);
    let mut corrupt = final_bytes.clone();
    let last = corrupt.len() - 1;
    corrupt[last] ^= 1;
    assert!(
        wire::direct_request::verify_final_group_info(&corrupt, policy, result.next_binding())
            .is_err()
    );
    assert!(
        wire::validate_group_info(&final_bytes, policy).is_err(),
        "generic genesis rules remain singleton-only"
    );
}
#[test]
fn real_two_leaf_public_artifacts() {
    run(2)
}
#[test]
fn real_forty_leaf_public_artifacts() {
    run(40)
}
#[test]
fn real_short_lived_sibling_bounds_import() {
    run(3)
}

#[test]
fn real_legacy_successor_public_artifacts() {
    run_named(2, "leaves-2-legacy")
}
