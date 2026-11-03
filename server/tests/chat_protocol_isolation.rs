use std::collections::{BTreeMap, BTreeSet};
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

/// Top-level comma-separated terms of a compact `cfg` predicate list.
fn top_level_terms(list: &str) -> Vec<&str> {
    let (mut depth, mut start, mut terms) = (0, 0, Vec::new());
    for (index, character) in list.char_indices() {
        match character {
            '(' => depth += 1,
            ')' => depth -= 1,
            ',' if depth == 0 => {
                terms.push(&list[start..index]);
                start = index + 1;
            }
            _ => {}
        }
    }
    terms.push(&list[start..]);
    terms
}

/// `test`, or an `all(…)` with a top-level `test` term: never compiled outside tests.
fn cfg_is_test_only(predicate: &str) -> bool {
    predicate == "test"
        || predicate
            .strip_prefix("all(")
            .and_then(|terms| terms.strip_suffix(')'))
            .is_some_and(|terms| top_level_terms(terms).into_iter().any(cfg_is_test_only))
}

/// Out-of-line `mod name;` declarations in `file`: the mounted file and whether
/// that mount is gated by a test-only `cfg`.
fn module_mounts(file: &Path, source: &str) -> Vec<(PathBuf, bool)> {
    let code = source
        .lines()
        .map(|line| line.split("//").next().unwrap_or_default())
        .collect::<Vec<_>>()
        .join("\n");
    let dir = file.parent().expect("source file directory");
    let stem = file
        .file_stem()
        .and_then(|stem| stem.to_str())
        .expect("source file stem");
    let child_dir = if matches!(stem, "mod" | "lib" | "main") {
        dir.to_path_buf()
    } else {
        dir.join(stem)
    };
    let mut mounts = Vec::new();
    let mut item_start = 0;
    for (index, byte) in code.bytes().enumerate() {
        if !matches!(byte, b';' | b'{' | b'}') {
            continue;
        }
        let mut item = code[item_start..index].trim();
        item_start = index + 1;
        if byte != b';' {
            continue;
        }
        let (mut cfg_test, mut path) = (false, None);
        while let Some(attribute) = item.strip_prefix("#[") {
            let mut depth = 1;
            let Some(end) = attribute
                .char_indices()
                .find(|&(_, character)| {
                    depth += match character {
                        '[' => 1,
                        ']' => -1,
                        _ => 0,
                    };
                    depth == 0
                })
                .map(|(end, _)| end)
            else {
                break;
            };
            let compact: String = attribute[..end]
                .chars()
                .filter(|character| !character.is_whitespace())
                .collect();
            if let Some(predicate) = compact
                .strip_prefix("cfg(")
                .and_then(|predicate| predicate.strip_suffix(')'))
            {
                cfg_test |= cfg_is_test_only(predicate);
            }
            if let Some(value) = compact.strip_prefix("path=") {
                path = Some(value.trim_matches('"').to_owned());
            }
            item = attribute[end + 1..].trim_start();
        }
        let tokens: Vec<&str> = item.split_whitespace().collect();
        let [visibility @ .., "mod", name] = tokens.as_slice() else {
            continue;
        };
        if !name
            .chars()
            .all(|character| character.is_ascii_alphanumeric() || character == '_')
            || !visibility
                .first()
                .map_or(true, |token| token.starts_with("pub"))
        {
            continue;
        }
        let mounted = match path {
            Some(path) => dir.join(path),
            None if child_dir.join(format!("{name}.rs")).exists() => {
                child_dir.join(format!("{name}.rs"))
            }
            None => child_dir.join(name).join("mod.rs"),
        };
        mounts.push((mounted, cfg_test));
    }
    mounts
}

/// Crate files whose every mount is test-only: a `cfg(test)`/`cfg(all(test, …))`
/// declaration, or any declaration inside an already test-only file. Fails
/// closed: a mount this parser cannot resolve (e.g. nested in an inline module)
/// only removes an exemption, never adds one.
fn cfg_test_only_module_files(src: &Path) -> BTreeSet<PathBuf> {
    let mut mounts: BTreeMap<PathBuf, Vec<(PathBuf, bool)>> = BTreeMap::new();
    for file in source_files(src)
        .into_iter()
        .filter(|path| path.extension().and_then(|extension| extension.to_str()) == Some("rs"))
    {
        let source = fs::read_to_string(&file).expect("read crate source for module mounts");
        let declaring = fs::canonicalize(&file).expect("canonical declaring module");
        for (mounted, cfg_test) in module_mounts(&file, &source) {
            let Ok(mounted) = fs::canonicalize(&mounted) else {
                continue;
            };
            mounts
                .entry(mounted)
                .or_default()
                .push((declaring.clone(), cfg_test));
        }
    }
    let mut test_only = BTreeSet::new();
    loop {
        let before = test_only.len();
        for (file, declarations) in &mounts {
            if declarations
                .iter()
                .all(|(declaring, cfg_test)| *cfg_test || test_only.contains(declaring))
            {
                test_only.insert(file.clone());
            }
        }
        if test_only.len() == before {
            return test_only;
        }
    }
}

#[test]
fn clean_authority_has_no_legacy_namespace_or_repository_escape_hatch() {
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    // F29 (2026-09-24) moved integration suites in-crate as cfg(test)-only
    // modules; they read the sqlx ledger `public._sqlx_migrations` and
    // `*-public.mls` corpus fixtures. Only files whose every mount is
    // test-only are exempt, and only from "public."; production files and
    // inline `#[cfg(test)] mod tests { … }` blocks stay fully guarded.
    let test_only = cfg_test_only_module_files(&manifest_dir.join("src"));
    let canonical = |relative: &str| {
        fs::canonicalize(manifest_dir.join(relative)).expect("canonical classifier witness")
    };
    assert!(
        test_only.contains(&canonical(
            "src/chat_protocol/state_machine/executor_tests.rs"
        )),
        "mount classifier missed a cfg(test)-only suite"
    );
    assert!(
        !test_only.contains(&canonical(
            "src/chat_protocol/repository/direct_request_receipts.rs"
        )),
        "mount classifier exempted a production module"
    );
    let source_root = manifest_dir.join("src/chat_protocol");
    for path in source_files(&source_root) {
        let source = fs::read_to_string(&path).expect("read clean-chat source");
        let test_only_file =
            test_only.contains(&fs::canonicalize(&path).expect("canonical clean-chat source"));
        for forbidden in [
            "blue.catbird.mlsChat",
            "blue_catbird::mls_chat",
            "handlers::mls_chat",
            "crate::repositories::",
            "SET search_path",
            "set_config('search_path'",
            "public.",
        ] {
            if forbidden == "public." && test_only_file {
                continue;
            }
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
