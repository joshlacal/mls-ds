//! Safe source gate for the frozen Task 6 Welcome facade amendment.

const SOURCE: &str = include_str!("../src/chat_protocol/repository/welcome_terminal.rs");

fn position(haystack: &str, needle: &str) -> usize {
    haystack
        .find(needle)
        .unwrap_or_else(|| panic!("missing required Welcome facade seam: {needle}"))
}

#[test]
fn welcome_facade_consumes_sealed_operation_and_releases_replay_last() {
    let facade = position(SOURCE, "pub(crate) async fn prepare_welcome_terminal(");
    let first = position(SOURCE, "async fn prepare_first_welcome_terminal(");
    let signature = &SOURCE[facade..first];
    assert!(signature.contains("operation: PreparedSignedOperation"));
    assert!(!signature.contains("mutation: VerifiedSignedMutation"));
    assert!(!signature.contains("prelude: PreparedBusinessPrelude"));
    assert!(!signature.contains("TrustedRequestInstant"));
    assert!(SOURCE.contains("let trusted_instant = authority.trusted_instant();"));

    let replay = position(SOURCE, "async fn prepare_completed_welcome_replay(");
    let replay_source = &SOURCE[replay..position(SOURCE, "fn validate_locked_welcome_replay(")];
    let aggregate = position(replay_source, "hydrate_locked_conversation_state(");
    let welcome = position(replay_source, "lock_welcome_terminal(");
    let release = position(replay_source, "release_signed_operation_replay(");
    assert!(aggregate < welcome && welcome < release);
    assert!(replay_source
        .contains("SignedOperationReplayPostStateProof::WelcomeAcknowledgement(proof)"));
    assert!(replay_source.contains("SignedOperationReplayPostStateProof::WelcomeRejection(proof)"));
}

#[test]
fn welcome_replay_proof_seals_terminal_and_expected_wire_material() {
    assert!(SOURCE.contains("struct WelcomeReplayPostStateProof"));
    assert!(SOURCE.contains("fn expected_response_sha256(&self) -> &[u8; 32]"));
    assert!(SOURCE.contains("fn validates_seal(&self) -> bool"));
    assert!(SOURCE.contains("fn locked_welcome_replay_digest("));
    assert!(SOURCE.contains("response.response_sha256() != expected_response.sha256()"));
    assert!(SOURCE.contains("response.sha256() != &self.expected_response_sha256"));

    for variant in ["Acknowledged", "Rejected", "ExactReplay"] {
        let variant = position(SOURCE, &format!("{variant} {{"));
        let tail = &SOURCE[variant..];
        assert!(
            tail.lines()
                .take(6)
                .any(|line| line.contains("terminal_at")),
            "{variant} must retain terminal_at"
        );
    }
}

#[test]
fn welcome_facade_has_no_post_head_identity_reread_or_commit_escape() {
    for forbidden in [
        "recheck_business_authority",
        "load_validated_completed_business_replay",
        "ExecutionContextArtifacts",
        ".commit(",
        "SELECT ",
    ] {
        assert!(
            !SOURCE.contains(forbidden),
            "Welcome facade must not contain forbidden seam {forbidden}"
        );
    }
}
