const PROTECTED_TABLES: &[&str] = &[
    "chat.conversations",
    "chat.entries",
    "chat.transitions",
    "chat.generation_states",
    "chat.participants",
    "chat.message_sends",
    "chat.generations",
    "chat.member_devices",
    "chat.application_intervals",
    "chat.metadata_snapshots",
    "chat.leaf_recovery_requests",
    "chat.key_package_reservations",
    "chat.welcome_bundles",
    "chat.welcome_deliveries",
];

fn direct_protected_dml(source: &str) -> Vec<String> {
    let normalized = source
        .split_ascii_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
        .to_ascii_lowercase();

    PROTECTED_TABLES
        .iter()
        .flat_map(|table| {
            [
                format!("insert into {table}"),
                format!("update {table}"),
                format!("delete from {table}"),
            ]
        })
        .filter(|needle| normalized.contains(needle))
        .collect()
}

#[test]
fn two_node_scenario_has_no_direct_protected_table_dml() {
    let source = include_str!("federation_two_node.rs");
    let violations = direct_protected_dml(source);
    assert!(
        violations.is_empty(),
        "two-node scenario contains protected-table DML: {violations:?}"
    );
}

#[test]
fn guard_detects_split_ascii_whitespace() {
    let source = format!(
        "InSeRt\n\tInTo   {} (conversation_id) values ($1)",
        PROTECTED_TABLES[0]
    );
    assert_eq!(
        direct_protected_dml(&source),
        vec![format!("insert into {}", PROTECTED_TABLES[0])]
    );
}

#[test]
fn guard_allows_selects_and_test_fence_initialization() {
    let source = "SELECT * FROM chat.entries; INSERT INTO chat.protocol_instances(singleton) VALUES (TRUE); INSERT INTO chat.event_retention(retained_floor) VALUES (0);";
    assert!(direct_protected_dml(source).is_empty());
}
