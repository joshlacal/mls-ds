//! Database-free ownership checks for the thin Welcome HTTP compositor.

const SOURCE: &str = include_str!("../src/handlers/chat/welcome.rs");

fn block<'a>(source: &'a str, start: &str, end: &str) -> &'a str {
    source
        .split_once(start)
        .unwrap_or_else(|| panic!("missing start boundary: {start}"))
        .1
        .split_once(end)
        .unwrap_or_else(|| panic!("missing end boundary: {end}"))
        .0
}

#[test]
fn welcome_handler_is_an_operation_only_one_transaction_compositor() {
    let handler = block(SOURCE, "async fn handle(", "fn welcome_failure(");
    let admission = handler
        .find("context::admit_signed_operation_only")
        .expect("operation-only admission");
    let begin = handler
        .find("pool\n        .begin()")
        .expect("outer transaction");
    let prepare = handler
        .find("prelude::prepare_signed_operation")
        .expect("operation prelude");
    let facade = handler
        .find("welcome_terminal::prepare_welcome_terminal")
        .expect("Welcome facade");
    let commit = handler
        .rfind("transaction\n        .commit()")
        .expect("commit");
    assert!(admission < begin && begin < prepare && prepare < facade && facade < commit);

    assert!(handler.contains("WelcomeTerminalTransactionOutcome::Replay"));
    assert!(handler.contains("context::replay_response(&response)"));
    assert!(handler.contains("WelcomeTerminalTransactionOutcome::Prepared"));
    assert!(handler.contains("WelcomeTerminalTransactionOutcome::Classified"));
    assert_eq!(handler.matches(".complete(&mut transaction").count(), 2);
    assert_eq!(handler.matches(".commit()").count(), 1);
    assert!(!handler.contains("serde_json"));
    assert!(!handler.contains("sqlx::query"));
    assert!(!handler.contains("repository::"));
}

#[test]
fn welcome_handler_returns_facade_sealed_wire_material_verbatim() {
    let handler = block(SOURCE, "async fn handle(", "fn welcome_failure(");
    assert_eq!(
        handler.matches("context::canonical_json_response(").count(),
        2
    );
    assert_eq!(handler.matches("response.status()").count(), 2);
    assert_eq!(handler.matches("response.as_bytes().to_vec()").count(), 2);
    assert!(!handler.contains("serde_json"));
    assert!(!handler.contains("StatusCode::OK"));
}

#[test]
fn welcome_failure_mapper_exposes_only_declared_semantic_input_errors() {
    let mapper = SOURCE
        .split_once("fn welcome_failure(")
        .expect("failure mapper")
        .1;
    assert!(
        mapper.contains("E::InvalidRequest => ChatFailure::protocol(endpoint, C::InvalidRequest)")
    );
    assert!(
        mapper.contains("E::Prelude(error) => context::operation_prelude_failure(endpoint, error)")
    );
    assert!(mapper.contains("E::WelcomeLock"));
    assert!(mapper.contains("E::ExecutionHydration"));
    assert!(mapper.contains("ChatFailure::storage(endpoint)"));
    assert!(mapper.contains("ChatFailure::invariant(endpoint)"));
    assert!(mapper.contains(
        "E::Aggregate(crate::chat_protocol::repository::core::ConversationStateHydrationError::ReadSetMismatch)"
    ));
    assert!(mapper.contains("C::AcknowledgementConflict"));
    assert!(mapper.contains("C::RejectionConflict"));
    for forbidden in [
        "C::WelcomeExpired",
        "C::WelcomeNotFound",
        "C::WelcomeSuperseded",
    ] {
        assert!(
            !mapper.contains(forbidden),
            "terminal semantics must come from facade-sealed response, not handler mapper: {forbidden}"
        );
    }
}
