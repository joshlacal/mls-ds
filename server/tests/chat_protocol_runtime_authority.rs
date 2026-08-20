//! Focused production-runtime construction proof for the clean-chat
//! relationship authority.

use catbird_server::handlers::chat::ChatRuntime;

#[test]
fn runtime_owns_the_fixed_relationship_authority_without_an_injection_path() {
    std::env::remove_var("CHAT_CUTOVER_ENABLED");
    std::env::remove_var("CHAT_NEST_ISSUER");

    let runtime = ChatRuntime::from_env(std::sync::Arc::new(
        catbird_server::realtime::SseState::new(8),
    ))
    .expect("fixed relationship authority constructs");
    assert!(
        format!("{runtime:?}").contains("fixed-production-authority"),
        "the mandatory fixed authority must be present in runtime state"
    );

    let source = include_str!("../src/handlers/chat/runtime.rs");
    assert!(source.contains("relationship_authority: Arc<ProductionRelationshipAuthority>"));
    assert!(source.contains("load_fixed_relationship_authority_startup_guard()"));
    assert!(!source.contains("Option<ProductionRelationshipAuthority>"));
    assert!(!source.contains("relationship_authority: Option<"));
    assert!(!source.contains("fn for_test("));
}
