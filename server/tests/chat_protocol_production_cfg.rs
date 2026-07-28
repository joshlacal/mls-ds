#[test]
fn production_cfg_target_is_proof_feature_gated() {
    assert!(cfg!(feature = "chat-protocol-production-proof"));
}
