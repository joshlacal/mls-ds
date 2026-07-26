use std::fs;
use std::path::{Path, PathBuf};

const CHAT_TABLES: &[&str] = &[
    "protocol_instances",
    "principals",
    "devices",
    "device_keys",
    "dpop_replays",
    "idempotency_records",
    "key_packages",
    "conversations",
    "generations",
    "generation_states",
    "participants",
    "member_devices",
    "metadata_snapshots",
    "key_package_reservations",
    "reset_requests",
    "leaf_recovery_requests",
    "leave_requests",
    "relationship_projection_snapshots",
    "relationship_projection_relationships",
    "relationship_projection_declarations",
    "transitions",
    "entries",
    "message_sends",
    "application_intervals",
    "application_schedule_terminal_proofs",
    "entry_recipients",
    "welcome_bundles",
    "welcome_deliveries",
    "welcome_dispositions",
    "recovery_work_items",
    "events",
    "event_recipients",
    "outbox",
    "event_retention",
    "inventory_sessions",
    "inventory_conversation_items",
    "inventory_welcome_items",
    "inventory_recovery_items",
    "device_inventory_sessions",
    "device_inventory_items",
    "subscription_tickets",
    "blob_usage",
    "blobs",
    "blob_upload_tickets",
    "blob_bindings",
];

fn source_files(root: &Path) -> Vec<PathBuf> {
    let mut pending = vec![root.to_path_buf()];
    let mut files = Vec::new();
    while let Some(path) = pending.pop() {
        for entry in fs::read_dir(path).expect("read clean-chat source directory") {
            let path = entry.expect("read clean-chat source entry").path();
            if path.is_dir() {
                pending.push(path);
            } else if matches!(
                path.extension().and_then(|extension| extension.to_str()),
                Some("rs" | "sql")
            ) {
                files.push(path);
            }
        }
    }
    files.sort();
    files
}

fn collapsed_lowercase(source: &str) -> String {
    source
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
        .to_ascii_lowercase()
}

#[test]
fn clean_authority_has_no_legacy_namespace_or_repository_escape_hatch() {
    let source_root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src/chat_protocol");
    for path in source_files(&source_root) {
        let source = fs::read_to_string(&path).expect("read clean-chat source");
        for forbidden in [
            "blue.catbird.mlsChat",
            "blue_catbird::mls_chat",
            "handlers::mls_chat",
            "crate::repositories::",
            "SET search_path",
            "set_config('search_path'",
            "public.",
        ] {
            assert!(
                !source.contains(forbidden),
                "{} contains forbidden legacy/isolation token {forbidden:?}",
                path.display()
            );
        }
    }
}

#[test]
fn every_clean_table_reference_is_schema_qualified() {
    let source_root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src/chat_protocol");
    for path in source_files(&source_root) {
        let source = collapsed_lowercase(
            &fs::read_to_string(&path).expect("read clean-chat source for SQL qualification"),
        );
        for table in CHAT_TABLES {
            for prefix in [" from ", " join ", " update ", " into ", "delete from "] {
                let unqualified = format!("{prefix}{table}");
                assert!(
                    !source.contains(&unqualified),
                    "{} contains unqualified clean table reference {unqualified:?}",
                    path.display()
                );
            }
        }
    }
}

#[test]
fn exactly_eight_clean_migration_files_and_deploy_gate_are_the_only_migration_boundary() {
    let migration_root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("migrations");
    let mut clean_migrations = fs::read_dir(migration_root)
        .expect("read migration directory")
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .filter(|path| {
            path.file_name()
                .and_then(|name| name.to_str())
                .is_some_and(|name| {
                    name.starts_with("202607220000")
                        || name == "20260725000001_prepare_welcome_provenance_backfill.sql"
                        || name == "20260725000002_refine_welcome_provenance_quarantine.sql"
                        || name == "20260726000001_welcome_supersession_provenance.sql"
                        || name == "20260726000002_restore_welcome_provenance_deferred_triggers.sql"
                        || name == "20260726000003_finalize_welcome_provenance_triggers.sql"
                })
        })
        .collect::<Vec<_>>();
    clean_migrations.sort();

    let names = clean_migrations
        .iter()
        .map(|path| path.file_name().unwrap().to_string_lossy().into_owned())
        .collect::<Vec<_>>();
    assert_eq!(
        names,
        [
            "20260722000001_chat_protocol_core.sql",
            "20260722000002_chat_protocol_delivery.sql",
            "20260722000003_chat_protocol_blobs.sql",
            "20260725000001_prepare_welcome_provenance_backfill.sql",
            "20260725000002_refine_welcome_provenance_quarantine.sql",
            "20260726000001_welcome_supersession_provenance.sql",
            "20260726000002_restore_welcome_provenance_deferred_triggers.sql",
            "20260726000003_finalize_welcome_provenance_triggers.sql",
        ]
    );

    for path in clean_migrations {
        let source = fs::read_to_string(&path).expect("read clean-chat migration");
        assert!(!source.to_ascii_lowercase().contains("search_path"));
        assert!(!source.contains("public."));
    }

    let deploy = fs::read_to_string(
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("..")
            .join("deploy.sh"),
    )
    .expect("read host deployment script");
    let prerequisite = deploy
        .find("[1/7] Verifying deployment prerequisites")
        .expect("prerequisite gate");
    let pull = deploy.find("[2/7] Pulling latest code").expect("pull step");
    let stop = deploy
        .find("sudo systemctl stop \"$SERVICE_NAME\"")
        .expect("maintenance stop");
    let bootstrap = deploy
        .rfind("\"$MLS_ROOT/server/scripts/bootstrap-sqlx-migrations.sh\"")
        .expect("bootstrap invocation");
    let migration = deploy
        .rfind("\"$MLS_ROOT/server/scripts/run-migrations.sh\"")
        .expect("migration invocation");
    let start = deploy
        .find("sudo systemctl start \"$SERVICE_NAME\"")
        .expect("post-migration start");
    assert!(
        prerequisite < pull && stop < bootstrap && bootstrap < migration && migration < start,
        "deployment must preflight first, stop before bootstrap/migration, and start only afterward"
    );
    assert!(
        !deploy.contains("systemctl restart"),
        "deployment must not restart across the migration sequence"
    );
    assert!(
        deploy.matches("remains stopped").count() >= 3,
        "bootstrap, migration, and start failures must explicitly leave the service stopped"
    );
}
