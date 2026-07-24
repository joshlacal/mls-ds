//! Catalog, isolation, and fail-closed behavior contract for `blue.catbird.chat`.
//!
//! This test is intentionally destructive only inside one dedicated local
//! database. Every run proves rollback, ordered migration boundaries, the SQLx
//! ledger path, normalized catalog identity, and representative cross-table
//! protocol invariants from a fresh `chat` schema.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use chrono::{DateTime, Duration, Utc};
use sha2::{Digest, Sha256};
use sqlx::postgres::PgPoolOptions;
use sqlx::{Executor, PgPool};

const TEST_DATABASE_NAME: &str = "catbird_chat_protocol_test_20260722";
const MIGRATION_VERSIONS: [i64; 3] = [20260722000001, 20260722000002, 20260722000003];
const MIGRATION_FILES: [&str; 3] = [
    "20260722000001_chat_protocol_core.sql",
    "20260722000002_chat_protocol_delivery.sql",
    "20260722000003_chat_protocol_blobs.sql",
];
const MIGRATION_DESCRIPTIONS: [&str; 3] = [
    "chat protocol core",
    "chat protocol delivery",
    "chat protocol blobs",
];

// These are regenerated only from a reviewed, freshly applied migration
// snapshot. They deliberately make unreviewed catalog drift loud.
const COLUMN_CATALOG_SHA256: &str =
    "fbb673fe1eb495ddb5b08f0818fd566225a95a3fbf7729b384e4ef88570f002e";
const CONSTRAINT_CATALOG_SHA256: &str =
    "f53c8157cedc5fad401a56a2538974859c71f269ad8dc716cef2a58eda33edc6";
const INDEX_CATALOG_SHA256: &str =
    "4eb4de367adc3591c12bc758c125899818bb7f0104a65d7469102bda76616759";
const FUNCTION_CATALOG_SHA256: &str =
    "755000ae4667e0448fdb001be3a0448237954759a8a80f5e0c44ba32e0d8fba9";
const TRIGGER_CATALOG_SHA256: &str =
    "c179499a10d3ac474de660a6f473bd4840fac400fd742d1f343f0c5f35e2fa87";
const SEQUENCE_CATALOG_SHA256: &str =
    "0f5fdcab044481afeaca50ac88cff13edd4b583df914da2c798e4a4194464abe";

const CORE_TABLES: [&str; 23] = [
    "conversations",
    "device_keys",
    "device_revocations",
    "devices",
    "dpop_replays",
    "generation_states",
    "generations",
    "idempotency_records",
    "key_package_reservations",
    "key_packages",
    "leaf_recovery_requests",
    "leave_requests",
    "member_devices",
    "metadata_snapshots",
    "participants",
    "principals",
    "protocol_instances",
    "relationship_projection_declarations",
    "relationship_projection_relationships",
    "relationship_projection_revision_allocations",
    "relationship_projection_snapshots",
    "reset_requests",
    "transitions",
];

const DELIVERY_TABLES: [&str; 20] = [
    "application_intervals",
    "application_schedule_terminal_proofs",
    "device_inventory_items",
    "device_inventory_sessions",
    "entries",
    "entry_recipients",
    "event_recipients",
    "event_retention",
    "events",
    "inventory_conversation_items",
    "inventory_recovery_items",
    "inventory_sessions",
    "inventory_welcome_items",
    "message_sends",
    "outbox",
    "recovery_work_items",
    "subscription_tickets",
    "welcome_bundles",
    "welcome_deliveries",
    "welcome_dispositions",
];

const BLOB_TABLES: [&str; 4] = [
    "blob_bindings",
    "blob_upload_tickets",
    "blob_usage",
    "blobs",
];

fn fixture_uuid(suffix: u128) -> uuid::Uuid {
    uuid::Uuid::from_u128(0x11111111111141118111111111111000 + suffix)
}

fn expected_tables() -> BTreeSet<String> {
    CORE_TABLES
        .iter()
        .chain(DELIVERY_TABLES.iter())
        .chain(BLOB_TABLES.iter())
        .map(|name| (*name).to_owned())
        .collect()
}

fn migration_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("migrations")
}

fn migration_path(version: i64, suffix: &str) -> PathBuf {
    migration_dir().join(format!("{version}_{suffix}.sql"))
}

fn declared_chat_tables(sql: &str) -> BTreeSet<String> {
    sql.lines()
        .filter_map(|line| {
            line.trim()
                .strip_prefix("CREATE TABLE chat.")
                .and_then(|tail| tail.split_whitespace().next())
                .map(|name| name.trim_end_matches('(').to_owned())
        })
        .collect()
}

fn compact_sql(sql: &str) -> String {
    sql.split_whitespace().collect::<Vec<_>>().join(" ")
}

fn create_table_block<'a>(sql: &'a str, table: &str, next: &str) -> &'a str {
    sql.split_once(&format!("CREATE TABLE chat.{table} ("))
        .unwrap_or_else(|| panic!("missing chat.{table} table"))
        .1
        .split_once(next)
        .unwrap_or_else(|| panic!("missing end marker for chat.{table}"))
        .0
}

fn function_block<'a>(sql: &'a str, function: &str, next: &str) -> &'a str {
    sql.split_once(function)
        .unwrap_or_else(|| panic!("missing function marker: {function}"))
        .1
        .split_once(next)
        .unwrap_or_else(|| panic!("missing end marker after {function}: {next}"))
        .0
}

fn assert_source_contract(cluster: &str, checks: &[(&str, bool)]) {
    let missing = checks
        .iter()
        .filter_map(|(contract, present)| (!present).then_some(*contract))
        .collect::<Vec<_>>();
    assert!(
        missing.is_empty(),
        "{cluster} source contract is incomplete:\n- {}",
        missing.join("\n- ")
    );
}

#[test]
fn audit_delivery_audiences_require_control_entries_and_exact_provenance() {
    let sql =
        std::fs::read_to_string(migration_dir().join("20260722000002_chat_protocol_delivery.sql"))
            .expect("read delivery migration");
    let compact = compact_sql(&sql);
    let entries = compact_sql(create_table_block(
        &sql,
        "entries",
        "ALTER TABLE chat.transitions",
    ));
    let recipients = compact_sql(create_table_block(
        &sql,
        "entry_recipients",
        "CREATE INDEX entry_recipients_device_scan_idx",
    ));
    let mapping = compact_sql(function_block(
        &sql,
        "CREATE FUNCTION chat.assert_entry_recipient_mapping(",
        "CREATE FUNCTION chat.enforce_entry_recipient_mapping()",
    ));

    assert_source_contract(
        "delivery audience",
        &[
            (
                "entry recipients retain the closed control/intervalClose/scheduleTerminal arms",
                recipients
                    .contains("entitlement_kind IN ('control','intervalClose','scheduleTerminal')"),
            ),
            (
                "application entries cannot acquire any entry_recipients audience row",
                mapping.contains("JOIN chat.entries entry")
                    && mapping.contains(
                        "entry.entry_kind <> 'blue.catbird.chat.defs#applicationEntry'",
                    ),
            ),
            (
                "the control arm is positively checked against a non-application entry",
                mapping.contains("recipient_kind = 'control'")
                    && mapping.contains("entry.entry_kind")
                    && mapping.contains("applicationEntry"),
            ),
            (
                // Relocated enforcement: the intervalClose "binds the exact closing
                // transition and outer fingerprint" invariant is now a hard composite
                // FK from chat.application_intervals -> chat.entries' transition/
                // fingerprint unique key, not inline plpgsql in
                // assert_entry_recipient_mapping. Assert the FK + its unique target.
                "intervalClose routing binds the exact closing transition and outer fingerprint",
                compact.contains(
                    "CONSTRAINT application_intervals_closing_provenance_fk FOREIGN KEY ( conversation_id, terminal_seq, closing_transition_id, closing_outer_entry_fingerprint ) REFERENCES chat.entries( conversation_id, seq, transition_id, outer_entry_fingerprint )",
                ) && compact.contains(
                    "CONSTRAINT entries_transition_fingerprint_uq UNIQUE ( conversation_id, seq, transition_id, outer_entry_fingerprint )",
                ),
            ),
            (
                // Relocated enforcement: the scheduleTerminal "binds the exact terminal
                // transition and outer fingerprint" invariant is now a hard composite
                // FK from chat.application_schedule_terminal_proofs -> chat.entries'
                // transition/fingerprint unique key. Assert the FK + its unique target.
                "scheduleTerminal routing binds the exact terminal transition and outer fingerprint",
                compact.contains(
                    "CONSTRAINT application_schedule_terminal_proofs_provenance_fk FOREIGN KEY ( conversation_id, terminal_seq, transition_id, outer_entry_fingerprint ) REFERENCES chat.entries( conversation_id, seq, transition_id, outer_entry_fingerprint )",
                ) && compact.contains(
                    "CONSTRAINT entries_transition_fingerprint_uq UNIQUE ( conversation_id, seq, transition_id, outer_entry_fingerprint )",
                ),
            ),
            (
                "entry fingerprints and signatures remain fixed-size protocol authority",
                entries.contains("octet_length(request_digest) = 32")
                    && entries.contains("octet_length(signature) = 64")
                    && entries.contains("octet_length(outer_entry_fingerprint) = 32"),
            ),
            (
                "schedule terminal proof completeness remains exact-device and once-per-schedule",
                compact.contains(
                    "PRIMARY KEY (conversation_id, recipient_did, recipient_device_id)",
                ) && compact.contains(
                    "CREATE FUNCTION chat.assert_conversation_terminal_schedules(target_conversation UUID)",
                ),
            ),
        ],
    );
}

#[test]
fn audit_inventory_items_bind_exact_device_sources_and_typed_terminal_proofs() {
    let sql =
        std::fs::read_to_string(migration_dir().join("20260722000002_chat_protocol_delivery.sql"))
            .expect("read delivery migration");
    let conversation_items = compact_sql(create_table_block(
        &sql,
        "inventory_conversation_items",
        "CREATE TABLE chat.inventory_welcome_items",
    ));
    let welcome_items = compact_sql(create_table_block(
        &sql,
        "inventory_welcome_items",
        "CREATE TABLE chat.inventory_recovery_items",
    ));
    let recovery_items = compact_sql(create_table_block(
        &sql,
        "inventory_recovery_items",
        "CREATE TABLE chat.device_inventory_sessions",
    ));
    let device_items = compact_sql(create_table_block(
        &sql,
        "device_inventory_items",
        "CREATE TABLE chat.subscription_tickets",
    ));
    let materialization = compact_sql(function_block(
        &sql,
        "CREATE FUNCTION chat.assert_inventory_materialization(target_session UUID)",
        "CREATE FUNCTION chat.enforce_inventory_materialization()",
    ));

    assert_source_contract(
        "inventory provenance",
        &[
            (
                "conversation inventory items repeat their exact recipient DID/device",
                conversation_items.contains("recipient_did TEXT NOT NULL")
                    && conversation_items.contains("recipient_device_id UUID NOT NULL"),
            ),
            (
                "conversation inventory has typed all-or-none schedule-terminal proof columns",
                conversation_items.contains("schedule_terminal_seq BIGINT")
                    && conversation_items.contains("schedule_terminal_transition_id UUID")
                    && conversation_items
                        .contains("schedule_terminal_outer_entry_fingerprint BYTEA")
                    && conversation_items
                        .contains("inventory_conversation_items_schedule_terminal_shape_check"),
            ),
            (
                "conversation inventory proof identity has an exact composite FK",
                conversation_items.contains(
                    "FOREIGN KEY ( conversation_id, recipient_did, recipient_device_id, schedule_terminal_seq, schedule_terminal_transition_id, schedule_terminal_outer_entry_fingerprint ) REFERENCES chat.application_schedule_terminal_proofs",
                ),
            ),
            (
                "Welcome inventory items repeat the source recipient and bind that delivery",
                welcome_items.contains("recipient_did TEXT NOT NULL")
                    && welcome_items.contains("recipient_device_id UUID NOT NULL")
                    && welcome_items.contains(
                        "FOREIGN KEY (welcome_id, recipient_did, recipient_device_id)",
                    ),
            ),
            (
                "recovery inventory items repeat the source recipient and bind either exact source",
                recovery_items.contains("recipient_did TEXT NOT NULL")
                    && recovery_items.contains("recipient_device_id UUID NOT NULL")
                    && recovery_items.contains(
                        "leaf_recovery_request_id, recipient_did, recipient_device_id",
                    )
                    && recovery_items
                        .contains("recovery_work_id, recipient_did, recipient_device_id"),
            ),
            (
                "device inventory items repeat the requesting exact-device session identity",
                device_items.contains("requester_did TEXT NOT NULL")
                    && device_items.contains("requester_device_id UUID NOT NULL"),
            ),
            (
                "materialization verifies session/device/source joins, not only hashes and counts",
                materialization.contains("JOIN chat.inventory_sessions session")
                    && materialization.contains("recipient_did = session.user_did")
                    && materialization.contains("recipient_device_id = session.device_id")
                    && materialization.contains("JOIN chat.application_schedule_terminal_proofs"),
            ),
            (
                "inventory tokens remain hash-only",
                sql.contains("token_hash BYTEA NOT NULL UNIQUE")
                    && !sql.contains("inventory_token TEXT"),
            ),
        ],
    );
}

#[test]
fn audit_inventory_is_bounded_gc_controlled_all_status_indexed_and_strictly_expiring() {
    let core =
        std::fs::read_to_string(migration_dir().join("20260722000001_chat_protocol_core.sql"))
            .expect("read core migration");
    let sql =
        std::fs::read_to_string(migration_dir().join("20260722000002_chat_protocol_delivery.sql"))
            .expect("read delivery migration");
    let compact = compact_sql(&sql);
    let sessions = compact_sql(create_table_block(
        &sql,
        "inventory_sessions",
        "CREATE TABLE chat.inventory_conversation_items",
    ));
    let device_sessions = compact_sql(create_table_block(
        &sql,
        "device_inventory_sessions",
        "CREATE TABLE chat.device_inventory_items",
    ));
    let tickets = compact_sql(create_table_block(
        &sql,
        "subscription_tickets",
        "CREATE FUNCTION chat.assert_inventory_session_identity",
    ));
    let welcomes = compact_sql(create_table_block(
        &sql,
        "welcome_deliveries",
        "CREATE INDEX welcome_deliveries_pending_device_idx",
    ));

    assert_source_contract(
        "bounded inventory lifecycle",
        &[
            (
                "item inserts do not invoke whole-session materialization rescans",
                !sql.contains("inventory_conversation_items_materialization_deferred")
                    && !sql.contains("inventory_welcome_items_materialization_deferred")
                    && !sql.contains("inventory_recovery_items_materialization_deferred")
                    && !sql.contains("device_inventory_items_materialization_deferred"),
            ),
            (
                "historical schedule close fanout has a structural configured ceiling",
                compact.contains("CREATE FUNCTION chat.max_historical_schedule_fanout()")
                    && compact.contains(
                        "CREATE FUNCTION chat.assert_historical_schedule_fanout(target_conversation UUID)",
                    )
                    && compact.contains("historical_schedule_fanout_exceeded"),
            ),
            (
                "shared inventory sessions have a finite maximum lifetime",
                sessions.contains("expires_at <= created_at + INTERVAL"),
            ),
            (
                "device inventory sessions have a finite maximum lifetime",
                device_sessions.contains("expires_at <= created_at + INTERVAL"),
            ),
            (
                "expired shared/device inventory sessions have bounded SKIP LOCKED GC",
                compact.contains(
                    "CREATE FUNCTION chat.gc_expired_inventory_sessions(batch_limit INTEGER",
                ) && compact.contains("FOR UPDATE SKIP LOCKED")
                    && compact.contains("LIMIT batch_limit")
                    && compact.contains("inventory_sessions_expiry_gc_idx")
                    && compact.contains("device_inventory_sessions_expiry_gc_idx"),
            ),
            (
                "active retained sessions per exact DID/device are capped under a device lock",
                compact.contains(
                    "CREATE FUNCTION chat.assert_exact_device_inventory_session_cap(",
                ) && compact.contains("max_active_inventory_sessions")
                    && compact.contains("FOR UPDATE"),
            ),
            (
                "leaf recovery has a non-partial exact-device all-status lookup index",
                core.contains("CREATE INDEX leaf_recovery_requests_device_all_status_idx")
                    && core.contains(
                        "ON chat.leaf_recovery_requests (requester_did, requester_device_id, status",
                    ),
            ),
            (
                "Welcome and recovery-work lookups have non-partial exact-device all-status indexes",
                compact.contains("CREATE INDEX welcome_deliveries_device_all_status_idx")
                    && compact.contains(
                        "ON chat.welcome_deliveries (recipient_did, recipient_device_id, status",
                    )
                    && compact.contains("CREATE INDEX recovery_work_items_device_all_status_idx")
                    && compact.contains(
                        "ON chat.recovery_work_items (recipient_did, recipient_device_id, status",
                    ),
            ),
            (
                "subscription ticket consumption rejects exact expiry",
                tickets.contains("consumed_at >= created_at AND consumed_at < expires_at")
                    && !tickets.contains("BETWEEN created_at AND expires_at"),
            ),
            (
                "non-expiry Welcome terminal decisions reject exact expiry",
                welcomes.contains("terminal_at < expires_at")
                    && !welcomes.contains("terminal_at <= expires_at"),
            ),
            (
                "protocol-instance event fencing remains present",
                compact.contains("events_protocol_instance_fk")
                    && compact.contains("event_retention_instance_fk"),
            ),
        ],
    );
}

#[test]
fn audit_blob_keys_binding_lifetimes_and_object_gc_are_unambiguous() {
    let sql =
        std::fs::read_to_string(migration_dir().join("20260722000003_chat_protocol_blobs.sql"))
            .expect("read blob migration");
    let compact = compact_sql(&sql);
    let blobs = compact_sql(create_table_block(
        &sql,
        "blobs",
        "CREATE INDEX blobs_live_owner_idx",
    ));
    let tickets = compact_sql(create_table_block(
        &sql,
        "blob_upload_tickets",
        "ALTER TABLE chat.metadata_snapshots",
    ));
    let bindings = compact_sql(create_table_block(
        &sql,
        "blob_bindings",
        "CREATE FUNCTION chat.assert_blob_binding_lifecycle",
    ));
    let lifecycle = compact_sql(function_block(
        &sql,
        "CREATE FUNCTION chat.enforce_blob_lifecycle_transition()",
        "CREATE UNIQUE INDEX blob_bindings_application_entry_uq",
    ));

    assert_source_contract(
        "blob identity and lifetime",
        &[
            (
                "non-null object-store keys uniquely identify one blob row",
                compact.contains("CREATE UNIQUE INDEX blobs_object_store_key_uq")
                    && compact.contains("ON chat.blobs (object_store_key)")
                    && compact.contains("WHERE object_store_key IS NOT NULL"),
            ),
            (
                "upload completion rejects the exact upload expiry instant",
                lifecycle.contains("NEW.uploaded_at >= NEW.upload_expires_at")
                    && !lifecycle.contains("NEW.uploaded_at > NEW.upload_expires_at"),
            ),
            (
                "blob-ticket consumption rejects exact expiry",
                tickets.contains("consumed_at >= created_at AND consumed_at < expires_at")
                    && !tickets.contains("BETWEEN created_at AND expires_at"),
            ),
            (
                "completedUnbound to bound proves uploaded_at <= bound_at < unbound_expires_at",
                blobs.contains("uploaded_at <= bound_at")
                    && blobs.contains("bound_at < unbound_expires_at"),
            ),
            (
                "the binding row carries the same strict bind-time ordering",
                bindings.contains("blob_bindings_bound_at_check")
                    && bindings.contains("bound_at <")
                    && bindings.contains("unbound_expires_at"),
            ),
            (
                "zero-reference object GC has explicit status/times and a claimable index",
                blobs.contains("object_gc_status TEXT")
                    && blobs.contains("object_gc_after TIMESTAMPTZ")
                    && blobs.contains("object_deleted_at TIMESTAMPTZ")
                    && compact.contains("CREATE INDEX blobs_object_gc_claim_idx")
                    && compact.contains("WHERE object_gc_status = 'pending'"),
            ),
            (
                "object GC is bounded and uses locked claims",
                compact.contains("CREATE FUNCTION chat.claim_blob_object_gc(batch_limit INTEGER")
                    && compact.contains("FOR UPDATE SKIP LOCKED")
                    && compact.contains("LIMIT batch_limit"),
            ),
            (
                "application/metadata binding purpose split remains closed",
                bindings.contains("binding_kind IN ('application','metadataAvatar')")
                    && bindings.contains("binding_kind = 'application' AND purpose = 'attachment'")
                    && bindings
                        .contains("binding_kind = 'metadataAvatar' AND purpose = 'metadata'"),
            ),
            (
                "blob upload secrets remain hash-only",
                tickets.contains("ticket_hash BYTEA PRIMARY KEY")
                    && !tickets.contains("ticket_token TEXT"),
            ),
        ],
    );
}

#[test]
fn audit_blob_accounting_is_incremental_bounded_and_cleanup_controlled() {
    let sql =
        std::fs::read_to_string(migration_dir().join("20260722000003_chat_protocol_blobs.sql"))
            .expect("read blob migration");
    let compact = compact_sql(&sql);
    let usage = compact_sql(create_table_block(
        &sql,
        "blob_usage",
        "CREATE TABLE chat.blobs",
    ));
    let reconciliation = compact_sql(function_block(
        &sql,
        "CREATE FUNCTION chat.assert_blob_usage(target_did TEXT)",
        "CREATE FUNCTION chat.enforce_blob_usage()",
    ));

    assert_source_contract(
        "blob accounting and cleanup",
        &[
            (
                "per-row blob mutations do not rescan full owner history",
                !reconciliation.contains("FROM chat.blobs")
                    && !reconciliation.contains("sum(ciphertext_size)")
                    && !reconciliation.contains("count(*) FILTER"),
            ),
            (
                "usage deltas are applied atomically under the principal anchor",
                compact.contains("CREATE FUNCTION chat.apply_blob_usage_delta(")
                    && compact.contains("UPDATE chat.blob_usage")
                    && compact.contains("FOR UPDATE"),
            ),
            (
                "the existing 500 MiB and 100-live-unbound owner caps remain",
                usage.contains("used_ciphertext_bytes + reserved_ciphertext_bytes <= 524288000")
                    && usage.contains("live_unbound_count <= 100"),
            ),
            (
                "active blobs have a bounded exact-device lookup index",
                compact.contains("CREATE INDEX blobs_active_device_idx")
                    && compact.contains("ON chat.blobs (owner_did, owner_device_id, status")
                    && compact.contains("WHERE status IN ('prepared','completedUnbound')"),
            ),
            (
                "active prepared/unbound rows per exact device have a hard cap",
                compact.contains("CREATE FUNCTION chat.assert_blob_device_active_cap(")
                    && compact.contains("max_active_blobs_per_device")
                    && compact.contains("FOR UPDATE"),
            ),
            (
                "terminal upload tickets have controlled bounded GC",
                compact.contains("blob_upload_tickets_terminal_gc_idx")
                    && compact.contains(
                        "CREATE FUNCTION chat.gc_terminal_blob_upload_tickets(batch_limit INTEGER",
                    )
                    && compact.contains("FOR UPDATE SKIP LOCKED")
                    && compact.contains("LIMIT batch_limit"),
            ),
            (
                "pending-CAS lifecycle remains terminal after ticket consumption",
                compact.contains("OLD.consumed_at IS NOT NULL AND NEW IS DISTINCT FROM OLD"),
            ),
        ],
    );
}

#[test]
fn recovery_schema_declares_closed_sources_and_collision_free_inventory_arms() {
    let sql =
        std::fs::read_to_string(migration_dir().join("20260722000002_chat_protocol_delivery.sql"))
            .expect("read delivery migration");
    let compact = compact_sql(&sql);
    let work = compact_sql(create_table_block(
        &sql,
        "recovery_work_items",
        "CREATE INDEX recovery_work_items_pending_device_idx",
    ));
    let inventory = compact_sql(create_table_block(
        &sql,
        "inventory_recovery_items",
        "CREATE TABLE chat.device_inventory_sessions",
    ));

    for required in [
        "terminal_revocation_id UUID",
        "CONSTRAINT recovery_work_items_coordinate_fk FOREIGN KEY (conversation_id, generation, state_version)",
        "REFERENCES chat.generation_states(conversation_id, generation, state_version) DEFERRABLE INITIALLY DEFERRED",
        "CONSTRAINT recovery_work_items_source_fk FOREIGN KEY (source_id) REFERENCES chat.welcome_dispositions(welcome_id) DEFERRABLE INITIALLY DEFERRED",
        "CONSTRAINT recovery_work_items_source_uq UNIQUE (source_id)",
        "CONSTRAINT recovery_work_items_terminal_revocation_fk FOREIGN KEY (recipient_did, recipient_device_id, terminal_revocation_id, terminal_at)",
        "num_nonnulls(terminal_transition_id, terminal_revocation_id) = 1",
    ] {
        assert!(work.contains(required), "missing recovery-work invariant: {required}");
    }
    assert!(
        work.contains("source_kind IN ('welcomeExpired','welcomeRejected')"),
        "recovery-work sources must be the two closed Welcome disposition arms"
    );
    for forbidden in ["poisonedState", "joinFailure"] {
        assert!(
            !work.contains(forbidden),
            "unmodeled recovery-work source remains admitted: {forbidden}"
        );
    }

    for required in [
        "item_kind TEXT NOT NULL",
        "leaf_recovery_request_id UUID",
        "recovery_work_id UUID",
        "item_kind IN ('leafRecoveryRequest','recoveryWork')",
        "octet_length(item_key_bytes) = 17",
        "decode('00', 'hex') || uuid_send(leaf_recovery_request_id)",
        "decode('01', 'hex') || uuid_send(recovery_work_id)",
        "CONSTRAINT inventory_recovery_items_request_fk FOREIGN KEY (leaf_recovery_request_id)",
        "CONSTRAINT inventory_recovery_items_work_fk FOREIGN KEY (recovery_work_id)",
        "CONSTRAINT inventory_recovery_items_request_uq UNIQUE (inventory_session_id, leaf_recovery_request_id)",
        "CONSTRAINT inventory_recovery_items_work_uq UNIQUE (inventory_session_id, recovery_work_id)",
    ] {
        assert!(inventory.contains(required), "missing recovery inventory invariant: {required}");
    }

    for required in [
        "CREATE FUNCTION chat.assert_recovery_work_integrity(target_welcome UUID)",
        "CREATE CONSTRAINT TRIGGER welcome_dispositions_recovery_work_deferred",
        "CREATE CONSTRAINT TRIGGER recovery_work_items_integrity_deferred",
        "work_row.status = 'superseded'",
        "transition.prior_generation = work_row.generation",
        "transition.prior_state_version = work_row.state_version",
        "(transition.next_generation, transition.next_state_version) IS DISTINCT FROM (work_row.generation, work_row.state_version)",
        "revocation.target_did = work_row.recipient_did",
        "revocation.target_device_id = work_row.recipient_device_id",
        "request.requester_did = work_row.recipient_did",
        "request.requester_device_id = work_row.recipient_device_id",
        "request.fulfilling_transition_id = work_row.terminal_transition_id",
        "transition.kind = 'leafRecovery'",
        "CREATE FUNCTION chat.assert_inventory_materialization(target_session UUID)",
        "int8send(ordinal) || item_key_bytes || payload_sha256",
        "'status', 'terminal_transition_id', 'terminal_revocation_id', 'terminal_at'",
    ] {
        assert!(
            compact.contains(required),
            "missing deferred/catalog invariant: {required}"
        );
    }
}

#[test]
fn relationship_schema_declares_bounded_fallback_and_revision_fences() {
    let sql =
        std::fs::read_to_string(migration_dir().join("20260722000001_chat_protocol_core.sql"))
            .expect("read core migration");
    let compact = compact_sql(&sql);
    let snapshots = compact_sql(create_table_block(
        &sql,
        "relationship_projection_snapshots",
        "CREATE INDEX relationship_projection_fallback_lookup_idx",
    ));
    let allocations = compact_sql(create_table_block(
        &sql,
        "relationship_projection_revision_allocations",
        "CREATE FUNCTION chat.allocate_relationship_projection_revision",
    ));
    let assertion = compact_sql(
        sql.split_once(
            "CREATE FUNCTION chat.assert_relationship_projection(target_projection UUID)",
        )
        .expect("missing relationship projection assertion")
        .1
        .split_once("CREATE FUNCTION chat.enforce_relationship_projection()")
        .expect("missing relationship projection enforcement function")
        .0,
    );

    assert!(
        compact.contains(
            "CREATE INDEX relationship_projection_fallback_lookup_idx ON chat.relationship_projection_snapshots (operation_scope, scope_digest, configuration_fingerprint, completed_at DESC, projection_revision DESC) WHERE evidence_kind = 'fallback';"
        ),
        "fallback lookup must be partial, scope-bound, and newest-first"
    );
    assert!(
        snapshots.contains("completed_at <= started_at + INTERVAL '30 seconds'"),
        "relationship collection window must be at most 30 seconds"
    );
    assert!(
        !snapshots.contains("completed_at <= started_at + INTERVAL '60 seconds'"),
        "stale 60-second relationship collection window remains"
    );
    for required in [
        "relation.fetch_revision = snapshot_row.projection_revision",
        "declaration.fetch_revision = snapshot_row.projection_revision",
    ] {
        assert!(
            assertion.contains(required),
            "child fetch revision can alias snapshot revision: {required}"
        );
    }
    for required in [
        "Direct-writer boundary:",
        "owner-only allocator function",
        "no raw DML or sequence privileges",
    ] {
        assert!(
            compact.contains(required),
            "missing documented projection persistence gate: {required}"
        );
    }
    for required in [
        "allocation_id UUID PRIMARY KEY",
        "projection_revision BIGINT NOT NULL",
        "CONSTRAINT relationship_projection_revision_allocations_revision_uq UNIQUE ( projection_revision )",
        "CONSTRAINT relationship_projection_revision_allocations_pair_uq UNIQUE ( allocation_id, projection_revision )",
        "consumed_projection_id UUID",
        "CONSTRAINT relationship_projection_revision_allocations_consumed_uq UNIQUE ( consumed_projection_id )",
        "(consumed_projection_id IS NULL AND consumed_at IS NULL)",
        "(consumed_projection_id IS NOT NULL AND consumed_at IS NOT NULL)",
    ] {
        assert!(
            allocations.contains(required),
            "missing durable projection allocation invariant: {required}"
        );
    }
    for required in [
        "CREATE FUNCTION chat.allocate_relationship_projection_revision() RETURNS TABLE(allocation_id UUID, projection_revision BIGINT)",
        "nextval('chat.relationship_projection_revision_seq')",
        "gen_random_uuid()",
        "REVOKE ALL ON FUNCTION chat.allocate_relationship_projection_revision() FROM PUBLIC",
        "projection_allocation_id UUID NOT NULL",
        "CONSTRAINT relationship_projection_snapshots_revision_uq UNIQUE (projection_revision)",
        "CONSTRAINT relationship_projection_snapshots_allocation_uq UNIQUE (projection_allocation_id)",
        "FOREIGN KEY ( projection_allocation_id, projection_revision ) REFERENCES chat.relationship_projection_revision_allocations( allocation_id, projection_revision )",
        "CREATE FUNCTION chat.consume_relationship_projection_revision_allocation()",
        "consumed_projection_id = NEW.projection_id",
        "allocation_id = NEW.projection_allocation_id",
        "projection_revision = NEW.projection_revision",
        "consumed_projection_id IS NULL",
        "TG_TABLE_NAME = 'relationship_projection_revision_allocations'",
        "OLD.consumed_projection_id IS NOT NULL",
        "CREATE TRIGGER relationship_projection_revision_allocations_identity_immutable",
        "CREATE TRIGGER relationship_projection_allocations_lifecycle_monotonic",
        "CREATE TRIGGER relationship_projection_snapshots_allocation_consumed",
        "CONSTRAINT relationship_projection_revision_allocations_snapshot_fk FOREIGN KEY (consumed_projection_id, allocation_id, projection_revision)",
        "REFERENCES chat.relationship_projection_snapshots( projection_id, projection_allocation_id, projection_revision ) DEFERRABLE INITIALLY DEFERRED",
    ] {
        assert!(
            compact.contains(required),
            "missing one-use projection allocation authority: {required}"
        );
    }
}

fn catalog_fingerprint(lines: &[String]) -> String {
    hex::encode(Sha256::digest(lines.join("\n").as_bytes()))
}

async fn catalog_lines(pool: &PgPool, query: &str) -> Vec<String> {
    sqlx::query_scalar(query)
        .fetch_all(pool)
        .await
        .expect("read normalized PostgreSQL catalog")
}

fn assert_catalog(label: &str, lines: &[String], expected: &str) {
    let actual = catalog_fingerprint(lines);
    assert_eq!(
        actual,
        expected,
        "{label} catalog drifted; normalized catalog:\n{}",
        lines.join("\n")
    );
}

async fn chat_tables<'e, E>(executor: E) -> BTreeSet<String>
where
    E: Executor<'e, Database = sqlx::Postgres>,
{
    sqlx::query_scalar(
        r#"
        SELECT table_name
          FROM information_schema.tables
         WHERE table_schema = 'chat' AND table_type = 'BASE TABLE'
         ORDER BY table_name
        "#,
    )
    .fetch_all(executor)
    .await
    .expect("read chat table catalog")
    .into_iter()
    .collect()
}

async fn allocate_relationship_projection_revision(pool: &PgPool) -> (uuid::Uuid, i64) {
    sqlx::query_as(
        "SELECT allocation_id, projection_revision FROM chat.allocate_relationship_projection_revision()",
    )
    .fetch_one(pool)
    .await
    .expect("mint durable relationship projection allocation")
}

async fn assert_reset_is_scoped(pool: &PgPool) {
    let crossing_fks: Vec<String> = sqlx::query_scalar(
        r#"
        SELECT src_ns.nspname || '.' || src.relname || ' -> '
               || dst_ns.nspname || '.' || dst.relname
          FROM pg_constraint con
          JOIN pg_class src ON src.oid = con.conrelid
          JOIN pg_namespace src_ns ON src_ns.oid = src.relnamespace
          JOIN pg_class dst ON dst.oid = con.confrelid
          JOIN pg_namespace dst_ns ON dst_ns.oid = dst.relnamespace
         WHERE con.contype = 'f'
           AND ((src_ns.nspname = 'chat') <> (dst_ns.nspname = 'chat'))
         ORDER BY 1
        "#,
    )
    .fetch_all(pool)
    .await
    .expect("preflight cross-schema foreign keys");
    assert!(
        crossing_fks.is_empty(),
        "refusing reset because cross-schema FKs depend on chat: {crossing_fks:?}"
    );

    let external_views: Vec<String> = sqlx::query_scalar(
        r#"
        SELECT schemaname || '.' || viewname
          FROM pg_views
         WHERE schemaname <> 'chat'
           AND schemaname NOT IN ('pg_catalog','information_schema')
           AND strpos(lower(definition), 'chat.') > 0
         ORDER BY 1
        "#,
    )
    .fetch_all(pool)
    .await
    .expect("preflight external views");
    assert!(
        external_views.is_empty(),
        "refusing reset because external views depend on chat: {external_views:?}"
    );

    let external_functions: Vec<String> = sqlx::query_scalar(
        r#"
        SELECT n.nspname || '.' || p.proname
          FROM pg_proc p
          JOIN pg_namespace n ON n.oid = p.pronamespace
         WHERE n.nspname NOT IN ('chat','pg_catalog','information_schema')
           AND p.prokind = 'f'
           AND strpos(lower(pg_get_functiondef(p.oid)), 'chat.') > 0
         ORDER BY 1
        "#,
    )
    .fetch_all(pool)
    .await
    .expect("preflight external function bodies");
    assert!(
        external_functions.is_empty(),
        "refusing reset because external functions depend on chat: {external_functions:?}"
    );
}

async fn reset_chat(pool: &PgPool) {
    let schema_exists: bool =
        sqlx::query_scalar("SELECT EXISTS (SELECT 1 FROM pg_namespace WHERE nspname='chat')")
            .fetch_one(pool)
            .await
            .expect("probe chat schema");
    if schema_exists {
        assert_reset_is_scoped(pool).await;
        sqlx::query("DROP SCHEMA chat CASCADE")
            .execute(pool)
            .await
            .expect("drop only the preflighted chat schema");
    }

    let migration_table_exists: bool =
        sqlx::query_scalar("SELECT to_regclass('public._sqlx_migrations') IS NOT NULL")
            .fetch_one(pool)
            .await
            .expect("probe SQLx migration ledger");
    if migration_table_exists {
        sqlx::query("DELETE FROM public._sqlx_migrations WHERE version = ANY($1::bigint[])")
            .bind(MIGRATION_VERSIONS.as_slice())
            .execute(pool)
            .await
            .expect("remove only the three chat-protocol ledger rows");
    }
}

async fn fresh_pool() -> PgPool {
    let url = std::env::var("TEST_DATABASE_URL")
        .expect("TEST_DATABASE_URL must explicitly name catbird_chat_protocol_test_20260722");
    let pool = PgPoolOptions::new()
        .max_connections(1)
        .connect(&url)
        .await
        .expect("connect to dedicated chat-protocol PostgreSQL database");

    let current_database: String = sqlx::query_scalar("SELECT current_database()")
        .fetch_one(&pool)
        .await
        .expect("read current database");
    assert_eq!(
        current_database, TEST_DATABASE_NAME,
        "refusing to reset any other database"
    );
    let (current_user, owner, server_address): (String, String, Option<String>) = sqlx::query_as(
        r#"
        SELECT current_user, pg_get_userbyid(d.datdba), inet_server_addr()::text
          FROM pg_database d WHERE d.datname = current_database()
        "#,
    )
    .fetch_one(&pool)
    .await
    .expect("validate database owner and host");
    assert_eq!(
        current_user, owner,
        "connected role must own the test database"
    );
    assert!(
        server_address.as_deref().is_none_or(|address| matches!(
            address,
            "127.0.0.1/32" | "127.0.0.1" | "::1/128" | "::1"
        )),
        "refusing to reset non-local PostgreSQL at {server_address:?}"
    );

    sqlx::query("SELECT pg_advisory_lock(20260722, 2)")
        .execute(&pool)
        .await
        .expect("serialize schema tests");
    sqlx::query("CREATE TEMP TABLE task2_unrelated_sentinel(marker TEXT PRIMARY KEY)")
        .execute(&pool)
        .await
        .expect("create reset sentinel");
    sqlx::query("INSERT INTO task2_unrelated_sentinel VALUES ('preserve-me')")
        .execute(&pool)
        .await
        .expect("seed reset sentinel");

    reset_chat(&pool).await;

    let core_sql = std::fs::read_to_string(migration_dir().join(MIGRATION_FILES[0]))
        .expect("read core migration for rollback probe");
    let mut failed = pool.begin().await.expect("begin rollback probe");
    failed
        .execute(core_sql.as_str())
        .await
        .expect("apply core inside rollback probe");
    let injected = failed
        .execute("SELECT 1 / 0")
        .await
        .expect_err("injected migration failure must fail");
    assert_eq!(
        injected
            .as_database_error()
            .and_then(|error| error.code())
            .as_deref(),
        Some("22012")
    );
    failed.rollback().await.expect("roll back injected failure");
    let residue: bool =
        sqlx::query_scalar("SELECT EXISTS (SELECT 1 FROM pg_namespace WHERE nspname='chat')")
            .fetch_one(&pool)
            .await
            .expect("probe rollback residue");
    assert!(!residue, "failed migration left a partial chat schema");

    let mut cumulative = BTreeSet::new();
    for (index, filename) in MIGRATION_FILES.iter().enumerate() {
        let sql = std::fs::read_to_string(migration_dir().join(filename))
            .unwrap_or_else(|error| panic!("read {filename}: {error}"));
        let mut tx = pool.begin().await.expect("begin ordered migration");
        tx.execute(sql.as_str())
            .await
            .unwrap_or_else(|error| panic!("apply {filename}: {error}"));
        tx.commit()
            .await
            .unwrap_or_else(|error| panic!("commit {filename}: {error}"));
        cumulative.extend(
            [
                CORE_TABLES.as_slice(),
                DELIVERY_TABLES.as_slice(),
                BLOB_TABLES.as_slice(),
            ][index]
                .iter()
                .map(|name| (*name).to_owned()),
        );
        assert_eq!(
            chat_tables(&pool).await,
            cumulative,
            "wrong table boundary after {filename}"
        );
    }

    let manual_ledger_rows: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM public._sqlx_migrations WHERE version=ANY($1::bigint[])",
    )
    .bind(MIGRATION_VERSIONS.as_slice())
    .fetch_one(&pool)
    .await
    .unwrap_or(0);
    assert_eq!(manual_ledger_rows, 0, "manual SQL spoofed the SQLx ledger");

    reset_chat(&pool).await;
    sqlx::migrate!("./migrations")
        .run(&pool)
        .await
        .expect("apply production SQLx migrator path");
    let sentinel: String = sqlx::query_scalar("SELECT marker FROM task2_unrelated_sentinel")
        .fetch_one(&pool)
        .await
        .expect("verify reset isolation sentinel");
    assert_eq!(sentinel, "preserve-me");
    pool
}

#[derive(Clone)]
struct ConversationFixture {
    conversation_id: uuid::Uuid,
    creation_transition_id: uuid::Uuid,
    creation_entry_id: uuid::Uuid,
    metadata_snapshot_id: uuid::Uuid,
    participant_period_id: uuid::Uuid,
    leaf_period_id: uuid::Uuid,
    group_id: Vec<u8>,
    group_context_hash: Vec<u8>,
    confirmation_tag: Vec<u8>,
    creation_fingerprint: Vec<u8>,
}

async fn create_conversation_fixture(
    pool: &PgPool,
    principal: &str,
    actor_device_id: uuid::Uuid,
    actor_key_id: &str,
    actor_public_key: &[u8],
) -> ConversationFixture {
    let conversation_id = fixture_uuid(1);
    let creation_transition_id = fixture_uuid(2);
    let creation_entry_id = fixture_uuid(3);
    let participant_period_id = fixture_uuid(4);
    let leaf_period_id = fixture_uuid(5);
    let metadata_snapshot_id = fixture_uuid(6);
    let group_id = vec![1_u8; 32];
    let group_context_hash = vec![2_u8; 32];
    let confirmation_tag = vec![3_u8; 32];
    let group_info = vec![4_u8; 8];
    let snapshot = vec![5_u8; 8];
    let tree_summary = vec![6_u8; 8];
    let signed_request = vec![7_u8; 8];
    let unsigned_projection = vec![8_u8; 8];
    let signing_transcript = vec![9_u8; 8];
    let request_digest = Sha256::digest(&signing_transcript).to_vec();
    let signature = vec![10_u8; 64];
    let accepted_payload = vec![11_u8; 8];
    let creation_fingerprint = vec![12_u8; 32];
    let metadata_ciphertext = vec![13_u8; 16];
    let basic_credential = format!("{principal}#{actor_device_id}").into_bytes();
    let accepted_at: DateTime<Utc> = sqlx::query_scalar("SELECT clock_timestamp()")
        .fetch_one(pool)
        .await
        .expect("capture one trusted acceptance time");

    let mut tx = pool.begin().await.expect("begin coherent creation fixture");
    sqlx::query(
        "INSERT INTO chat.conversations(conversation_id,kind,lifecycle,current_generation,current_state_version,next_entry_seq,created_at) VALUES($1,'group','active',0,0,2,$2)",
    )
    .bind(conversation_id)
    .bind(&accepted_at)
    .execute(&mut *tx)
    .await
    .expect("insert conversation");
    sqlx::query(
        "INSERT INTO chat.generations(conversation_id,generation,group_id,lifecycle,genesis_group_info_bytes,genesis_group_info_sha256,current_state_version,activated_seq,activated_at) VALUES($1,0,$2,'active',$3,$4,0,1,$5)",
    )
    .bind(conversation_id)
    .bind(&group_id)
    .bind(&group_info)
    .bind(Sha256::digest(&group_info).to_vec())
    .bind(&accepted_at)
    .execute(&mut *tx)
    .await
    .expect("insert generation");
    sqlx::query(
        r#"
        INSERT INTO chat.transitions(
            transition_id,conversation_id,kind,actor_did,actor_device_id,actor_key_id,
            actor_auth_generation,actor_role,actor_device_status,signed_request_bytes,
            unsigned_projection_bytes,signing_transcript_bytes,request_digest,signature,
            next_generation,next_state_version,metadata_snapshot_id,entry_seq,accepted_at
        ) VALUES($1,$2,'creation',$3,$4,$5,1,'admin','active',$6,$7,$8,$9,$10,0,0,$11,1,$12)
        "#,
    )
    .bind(creation_transition_id)
    .bind(conversation_id)
    .bind(principal)
    .bind(actor_device_id)
    .bind(actor_key_id)
    .bind(&signed_request)
    .bind(&unsigned_projection)
    .bind(&signing_transcript)
    .bind(&request_digest)
    .bind(&signature)
    .bind(metadata_snapshot_id)
    .bind(&accepted_at)
    .execute(&mut *tx)
    .await
    .expect("insert creation transition");
    sqlx::query(
        r#"
        INSERT INTO chat.generation_states(
            conversation_id,generation,state_version,group_id,epoch,group_context_hash,
            confirmation_tag,lifecycle,state_kind,producing_transition_id,
            public_snapshot_bytes,snapshot_sha256,tree_summary_bytes,tree_summary_sha256,
            leaf_count,created_at
        ) VALUES($1,0,0,$2,0,$3,$4,'active','creation',$5,$6,$7,$8,$9,1,$10)
        "#,
    )
    .bind(conversation_id)
    .bind(&group_id)
    .bind(&group_context_hash)
    .bind(&confirmation_tag)
    .bind(creation_transition_id)
    .bind(&snapshot)
    .bind(Sha256::digest(&snapshot).to_vec())
    .bind(&tree_summary)
    .bind(Sha256::digest(&tree_summary).to_vec())
    .bind(&accepted_at)
    .execute(&mut *tx)
    .await
    .expect("insert creation state");
    sqlx::query(
        r#"
        INSERT INTO chat.participants(
            participant_period_id,conversation_id,user_did,status,role,role_transition_id,
            role_changed_at,created_by_did,created_by_device_id,current_membership,created_at
        ) VALUES($1,$2,$3,'active','admin',$4,$5,$3,$6,true,$5)
        "#,
    )
    .bind(participant_period_id)
    .bind(conversation_id)
    .bind(principal)
    .bind(creation_transition_id)
    .bind(&accepted_at)
    .bind(actor_device_id)
    .execute(&mut *tx)
    .await
    .expect("insert creator participant");
    sqlx::query(
        r#"
        INSERT INTO chat.member_devices(
            leaf_period_id,participant_period_id,conversation_id,generation,user_did,
            device_id,leaf_index,basic_credential,leaf_signature_key,leaf_key_id,
            leaf_auth_generation,origin,joined_state_version,joined_transition_id,
            joined_seq,active,created_at
        ) VALUES($1,$2,$3,0,$4,$5,0,$6,$7,$8,1,'genesis',0,$9,1,true,$10)
        "#,
    )
    .bind(leaf_period_id)
    .bind(participant_period_id)
    .bind(conversation_id)
    .bind(principal)
    .bind(actor_device_id)
    .bind(&basic_credential)
    .bind(actor_public_key)
    .bind(actor_key_id)
    .bind(creation_transition_id)
    .bind(&accepted_at)
    .execute(&mut *tx)
    .await
    .expect("insert genesis leaf");
    sqlx::query(
        r#"
        INSERT INTO chat.metadata_snapshots(
            metadata_snapshot_id,conversation_id,generation,state_version,group_id,epoch,
            group_context_hash,confirmation_tag,producing_transition_id,origin_transition_id,
            metadata_version,nonce,ciphertext,ciphertext_sha256,ciphertext_size,author_did,
            author_device_id,author_key_id,author_public_key,author_auth_generation,
            author_origin_seq,author_role,author_device_status,created_at
        ) VALUES($1,$2,0,0,$3,0,$4,$5,$6,$6,1,$7,$8,$9,16,$10,$11,$12,$13,1,1,'admin','active',$14)
        "#,
    )
    .bind(metadata_snapshot_id)
    .bind(conversation_id)
    .bind(&group_id)
    .bind(&group_context_hash)
    .bind(&confirmation_tag)
    .bind(creation_transition_id)
    .bind(vec![14_u8; 12])
    .bind(&metadata_ciphertext)
    .bind(Sha256::digest(&metadata_ciphertext).to_vec())
    .bind(principal)
    .bind(actor_device_id)
    .bind(actor_key_id)
    .bind(actor_public_key)
    .bind(&accepted_at)
    .execute(&mut *tx)
    .await
    .expect("insert creation metadata");
    sqlx::query(
        r#"
        INSERT INTO chat.entries(
            conversation_id,seq,entry_id,entry_kind,accepted_payload_bytes,
            accepted_payload_sha256,signed_request_bytes,request_digest,signature,
            server_fields_bytes,outer_entry_fingerprint,actor_did,actor_device_id,
            actor_key_id,actor_auth_generation,generation,state_version,transition_id,received_at
        ) VALUES($1,1,$2,'blue.catbird.chat.defs#creationEntry',$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,1,0,0,$13,$14)
        "#,
    )
    .bind(conversation_id)
    .bind(creation_entry_id)
    .bind(&accepted_payload)
    .bind(Sha256::digest(&accepted_payload).to_vec())
    .bind(&signed_request)
    .bind(&request_digest)
    .bind(&signature)
    .bind(vec![0_u8])
    .bind(&creation_fingerprint)
    .bind(principal)
    .bind(actor_device_id)
    .bind(actor_key_id)
    .bind(creation_transition_id)
    .bind(&accepted_at)
    .execute(&mut *tx)
    .await
    .expect("insert creation entry");
    sqlx::query(
        r#"
        INSERT INTO chat.application_intervals(
            membership_interval_id,conversation_id,generation,recipient_did,
            recipient_device_id,start_seq,opening_kind,opening_transition_id,
            opening_outer_entry_fingerprint,opening_state_version,opening_group_id,
            opening_epoch,opening_group_context_hash,opening_confirmation_tag,
            opening_leaf_period_id,created_at
        ) VALUES($1,$2,0,$3,$4,1,'creation',$1,$5,0,$6,0,$7,$8,$9,$10)
        "#,
    )
    .bind(creation_transition_id)
    .bind(conversation_id)
    .bind(principal)
    .bind(actor_device_id)
    .bind(&creation_fingerprint)
    .bind(&group_id)
    .bind(&group_context_hash)
    .bind(&confirmation_tag)
    .bind(leaf_period_id)
    .bind(&accepted_at)
    .execute(&mut *tx)
    .await
    .expect("insert creation application interval");
    tx.commit().await.expect("commit coherent creation fixture");

    ConversationFixture {
        conversation_id,
        creation_transition_id,
        creation_entry_id,
        metadata_snapshot_id,
        participant_period_id,
        leaf_period_id,
        group_id,
        group_context_hash,
        confirmation_tag,
        creation_fingerprint,
    }
}

#[tokio::test]
async fn clean_chat_schema_is_exact_isolated_and_fail_closed() {
    let pool = fresh_pool().await;

    let actual_tables = chat_tables(&pool).await;
    assert_eq!(
        actual_tables,
        expected_tables(),
        "unexpected chat table set"
    );
    assert_eq!(actual_tables.len(), 47, "clean protocol must own 47 tables");

    let applied: Vec<(i64, String, bool)> = sqlx::query_as(
        "SELECT version,description,success FROM public._sqlx_migrations WHERE version=ANY($1::bigint[]) ORDER BY version",
    )
    .bind(MIGRATION_VERSIONS.as_slice())
    .fetch_all(&pool)
    .await
    .expect("read migration ledger");
    let expected_applied: Vec<_> = MIGRATION_VERSIONS
        .into_iter()
        .zip(MIGRATION_DESCRIPTIONS)
        .map(|(version, description)| (version, description.to_owned(), true))
        .collect();
    assert_eq!(
        applied, expected_applied,
        "wrong chat migration ledger rows"
    );

    let migration_files: BTreeSet<String> = std::fs::read_dir(migration_dir())
        .expect("read migration directory")
        .map(|entry| entry.expect("read migration entry").path())
        .filter(|path| {
            path.file_name()
                .and_then(|name| name.to_str())
                .is_some_and(|name| name.contains("_chat_protocol_"))
        })
        .map(|path| {
            path.file_name()
                .and_then(|name| name.to_str())
                .expect("UTF-8 migration name")
                .to_owned()
        })
        .collect();
    assert_eq!(
        migration_files,
        MIGRATION_FILES
            .iter()
            .map(|name| (*name).to_owned())
            .collect(),
        "clean schema must be exactly three ordered files"
    );

    for (version, suffix, expected) in [
        (
            MIGRATION_VERSIONS[0],
            "chat_protocol_core",
            CORE_TABLES.as_slice(),
        ),
        (
            MIGRATION_VERSIONS[1],
            "chat_protocol_delivery",
            DELIVERY_TABLES.as_slice(),
        ),
        (
            MIGRATION_VERSIONS[2],
            "chat_protocol_blobs",
            BLOB_TABLES.as_slice(),
        ),
    ] {
        let sql = std::fs::read_to_string(migration_path(version, suffix))
            .unwrap_or_else(|error| panic!("read migration {version}: {error}"));
        let lower = sql.to_ascii_lowercase();
        for forbidden in [
            "search_path",
            "public.",
            "blue.catbird.mlschat",
            "mls_chat",
            "chatv2",
        ] {
            assert!(
                !lower.contains(forbidden),
                "migration {version} contains forbidden token {forbidden}"
            );
        }
        let expected: BTreeSet<String> = expected.iter().map(|name| (*name).to_owned()).collect();
        assert_eq!(
            declared_chat_tables(&sql),
            expected,
            "migration {version} owns the wrong tables"
        );
    }

    let cross_schema_fks: Vec<String> = sqlx::query_scalar(
        r#"
        SELECT src_ns.nspname || '.' || src.relname || ' -> '
               || dst_ns.nspname || '.' || dst.relname
          FROM pg_constraint con
          JOIN pg_class src ON src.oid=con.conrelid
          JOIN pg_namespace src_ns ON src_ns.oid=src.relnamespace
          JOIN pg_class dst ON dst.oid=con.confrelid
          JOIN pg_namespace dst_ns ON dst_ns.oid=dst.relnamespace
         WHERE con.contype='f'
           AND ((src_ns.nspname='chat') <> (dst_ns.nspname='chat'))
         ORDER BY 1
        "#,
    )
    .fetch_all(&pool)
    .await
    .expect("inspect FK isolation");
    assert!(
        cross_schema_fks.is_empty(),
        "cross-schema FKs: {cross_schema_fks:?}"
    );

    let (foreign_keys, unvalidated_foreign_keys): (i64, i64) = sqlx::query_as(
        r#"
        SELECT count(*), count(*) FILTER (WHERE NOT con.convalidated)
          FROM pg_constraint con
          JOIN pg_class c ON c.oid=con.conrelid
          JOIN pg_namespace n ON n.oid=c.relnamespace
         WHERE n.nspname='chat' AND con.contype='f'
        "#,
    )
    .fetch_one(&pool)
    .await
    .expect("count chat FKs");
    assert_eq!(foreign_keys, 183, "unexpected FK coverage");
    assert_eq!(unvalidated_foreign_keys, 0, "all FKs must be validated");

    let enum_count: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM pg_type t JOIN pg_namespace n ON n.oid=t.typnamespace WHERE n.nspname='chat' AND t.typtype='e'",
    )
    .fetch_one(&pool)
    .await
    .expect("count chat enums");
    assert_eq!(enum_count, 0, "closed values use visible CHECK constraints");

    let sequence_catalog = catalog_lines(
        &pool,
        r#"
        SELECT concat_ws('|',schemaname,sequencename,data_type,start_value::text,
                         min_value::text,max_value::text,increment_by::text,
                         cycle::text,cache_size::text)
          FROM pg_sequences
         WHERE schemaname='chat'
         ORDER BY sequencename
        "#,
    )
    .await;
    let sequence_names: BTreeSet<String> = sequence_catalog
        .iter()
        .map(|line| {
            line.split('|')
                .nth(1)
                .expect("normalized sequence row contains a name")
                .to_owned()
        })
        .collect();
    assert_eq!(
        sequence_names,
        [
            "events_event_position_seq".to_owned(),
            "relationship_projection_revision_seq".to_owned(),
        ]
        .into_iter()
        .collect(),
        "chat must own exactly its event-position and projection-revision allocators"
    );
    assert_catalog("sequence", &sequence_catalog, SEQUENCE_CATALOG_SHA256);
    let projection_revision_default: Option<String> = sqlx::query_scalar(
        r#"
        SELECT column_default
          FROM information_schema.columns
         WHERE table_schema='chat'
           AND table_name='relationship_projection_snapshots'
           AND column_name='projection_revision'
        "#,
    )
    .fetch_one(&pool)
    .await
    .expect("inspect projection revision default");
    assert!(
        projection_revision_default.is_none(),
        "repository must allocate revision before collection; the column has no default"
    );
    let projection_revision_is_serial: bool = sqlx::query_scalar(
        "SELECT pg_get_serial_sequence('chat.relationship_projection_snapshots','projection_revision') IS NOT NULL",
    )
    .fetch_one(&pool)
    .await
    .expect("inspect sequence ownership coupling");
    assert!(
        !projection_revision_is_serial,
        "durable allocator must not be an insert-time serial default"
    );
    let external_sequence_privileges: Vec<String> = sqlx::query_scalar(
        r#"
        SELECT coalesce(grantee.rolname,'PUBLIC') || ':' || acl.privilege_type
          FROM pg_class sequence
          JOIN pg_namespace n ON n.oid=sequence.relnamespace
          CROSS JOIN LATERAL aclexplode(
              coalesce(sequence.relacl,acldefault('S',sequence.relowner))
          ) acl
          LEFT JOIN pg_roles grantee ON grantee.oid=acl.grantee
         WHERE n.nspname='chat' AND sequence.relkind='S'
           AND acl.grantee<>sequence.relowner
         ORDER BY 1
        "#,
    )
    .fetch_all(&pool)
    .await
    .expect("inspect sequence privileges");
    assert!(
        external_sequence_privileges.is_empty(),
        "projection revision sequence leaked privileges: {external_sequence_privileges:?}"
    );
    let external_projection_table_privileges: Vec<String> = sqlx::query_scalar(
        r#"
        SELECT c.relname || ':' || coalesce(grantee.rolname,'PUBLIC') || ':' || acl.privilege_type
          FROM pg_class c
          JOIN pg_namespace n ON n.oid=c.relnamespace
          CROSS JOIN LATERAL aclexplode(
              coalesce(c.relacl,acldefault('r',c.relowner))
          ) acl
          LEFT JOIN pg_roles grantee ON grantee.oid=acl.grantee
         WHERE n.nspname='chat'
           AND c.relname IN (
                'relationship_projection_revision_allocations',
                'relationship_projection_snapshots',
                'relationship_projection_relationships',
                'relationship_projection_declarations'
           )
           AND acl.grantee<>c.relowner
         ORDER BY 1
        "#,
    )
    .fetch_all(&pool)
    .await
    .expect("inspect relationship projection table privileges");
    assert!(
        external_projection_table_privileges.is_empty(),
        "relationship projection tables leaked direct-write privileges: \
         {external_projection_table_privileges:?}"
    );
    let external_allocator_privileges: Vec<String> = sqlx::query_scalar(
        r#"
        SELECT coalesce(grantee.rolname,'PUBLIC') || ':' || acl.privilege_type
          FROM pg_proc p
          JOIN pg_namespace n ON n.oid=p.pronamespace
          CROSS JOIN LATERAL aclexplode(
              coalesce(p.proacl,acldefault('f',p.proowner))
          ) acl
          LEFT JOIN pg_roles grantee ON grantee.oid=acl.grantee
         WHERE n.nspname='chat'
           AND p.proname='allocate_relationship_projection_revision'
           AND pg_get_function_identity_arguments(p.oid)=''
           AND acl.grantee<>p.proowner
         ORDER BY 1
        "#,
    )
    .fetch_all(&pool)
    .await
    .expect("inspect relationship projection allocator privileges");
    assert!(
        external_allocator_privileges.is_empty(),
        "relationship projection allocator leaked execute privileges: \
         {external_allocator_privileges:?}"
    );

    let column_catalog = catalog_lines(
        &pool,
        r#"
        SELECT concat_ws('|',c.relname,a.attnum::text,a.attname,
                         format_type(a.atttypid,a.atttypmod),a.attnotnull::text,
                         coalesce(pg_get_expr(ad.adbin,ad.adrelid,true),''),
                         a.attidentity::text,a.attgenerated::text,
                         coalesce(coll.collname,''))
          FROM pg_attribute a
          JOIN pg_class c ON c.oid=a.attrelid
          JOIN pg_namespace n ON n.oid=c.relnamespace
          LEFT JOIN pg_attrdef ad ON ad.adrelid=a.attrelid AND ad.adnum=a.attnum
          LEFT JOIN pg_collation coll ON coll.oid=a.attcollation AND a.attcollation<>0
         WHERE n.nspname='chat' AND c.relkind='r' AND a.attnum>0 AND NOT a.attisdropped
         ORDER BY c.relname,a.attnum
        "#,
    )
    .await;
    assert_catalog(
        "column/type/null/default",
        &column_catalog,
        COLUMN_CATALOG_SHA256,
    );

    let constraint_catalog = catalog_lines(
        &pool,
        r#"
        SELECT concat_ws('|',c.relname,con.conname,con.contype::text,
                         con.condeferrable::text,con.condeferred::text,
                         con.convalidated::text,pg_get_constraintdef(con.oid,false))
          FROM pg_constraint con
          JOIN pg_class c ON c.oid=con.conrelid
          JOIN pg_namespace n ON n.oid=c.relnamespace
         WHERE n.nspname='chat'
         ORDER BY c.relname,con.conname
        "#,
    )
    .await;
    assert_catalog(
        "PK/unique/FK/check",
        &constraint_catalog,
        CONSTRAINT_CATALOG_SHA256,
    );

    let index_catalog = catalog_lines(
        &pool,
        r#"
        SELECT concat_ws('|',t.relname,i.relname,x.indisunique::text,
                         x.indisprimary::text,x.indisvalid::text,x.indisready::text,
                         x.indisclustered::text,x.indisreplident::text,
                         pg_get_indexdef(i.oid),
                         coalesce(pg_get_expr(x.indpred,x.indrelid,false),''))
          FROM pg_index x
          JOIN pg_class i ON i.oid=x.indexrelid
          JOIN pg_class t ON t.oid=x.indrelid
          JOIN pg_namespace n ON n.oid=t.relnamespace
         WHERE n.nspname='chat'
         ORDER BY t.relname,i.relname
        "#,
    )
    .await;
    assert_catalog("index", &index_catalog, INDEX_CATALOG_SHA256);

    let function_catalog = catalog_lines(
        &pool,
        r#"
        SELECT concat_ws('|',p.proname,pg_get_function_identity_arguments(p.oid),
                         pg_get_function_result(p.oid),l.lanname,p.provolatile::text,
                         p.proisstrict::text,p.proparallel::text,p.prosecdef::text,
                         p.proleakproof::text,coalesce(array_to_string(p.proconfig,','),''),
                         encode(digest(pg_get_functiondef(p.oid),'sha256'),'hex'))
          FROM pg_proc p
          JOIN pg_namespace n ON n.oid=p.pronamespace
          JOIN pg_language l ON l.oid=p.prolang
         WHERE n.nspname='chat'
         ORDER BY p.proname,pg_get_function_identity_arguments(p.oid)
        "#,
    )
    .await;
    assert_catalog(
        "authored function",
        &function_catalog,
        FUNCTION_CATALOG_SHA256,
    );

    let trigger_catalog = catalog_lines(
        &pool,
        r#"
        SELECT concat_ws('|',c.relname,t.tgname,t.tgenabled::text,t.tgtype::text,
                         t.tgdeferrable::text,t.tginitdeferred::text,p.proname,
                         pg_get_triggerdef(t.oid,false))
          FROM pg_trigger t
          JOIN pg_class c ON c.oid=t.tgrelid
          JOIN pg_namespace n ON n.oid=c.relnamespace
          JOIN pg_proc p ON p.oid=t.tgfoid
         WHERE n.nspname='chat' AND NOT t.tgisinternal
         ORDER BY c.relname,t.tgname
        "#,
    )
    .await;
    assert_catalog("trigger", &trigger_catalog, TRIGGER_CATALOG_SHA256);
    assert_eq!(
        trigger_catalog.len(),
        151,
        "unexpected authored trigger coverage"
    );

    let invalid_constraint_triggers: Vec<String> = sqlx::query_scalar(
        r#"
        SELECT c.relname || '.' || t.tgname
          FROM pg_trigger t
          JOIN pg_class c ON c.oid=t.tgrelid
          JOIN pg_namespace n ON n.oid=c.relnamespace
         WHERE n.nspname='chat' AND NOT t.tgisinternal AND t.tgconstraint<>0
           AND (NOT t.tgdeferrable OR NOT t.tginitdeferred)
         ORDER BY 1
        "#,
    )
    .fetch_all(&pool)
    .await
    .expect("inspect constraint triggers");
    assert!(
        invalid_constraint_triggers.is_empty(),
        "cross-row triggers must be initially deferred: {invalid_constraint_triggers:?}"
    );

    let required_constraints: BTreeSet<String> = [
        "devices_capabilities_check",
        "device_keys_key_id_binding_check",
        "device_revocations_signature_check",
        "idempotency_records_payload_sizes_check",
        "transitions_actor_authority_check",
        "participants_role_transition_check",
        "member_devices_leaf_key_id_check",
        "metadata_snapshots_author_authority_check",
        "entries_crypto_shape_check",
        "application_intervals_close_shape_check",
        "recovery_work_items_coordinate_fk",
        "recovery_work_items_source_fk",
        "recovery_work_items_source_uq",
        "recovery_work_items_terminal_transition_fk",
        "recovery_work_items_terminal_revocation_fk",
        "recovery_work_items_terminal_shape_check",
        "inventory_sessions_completion_evidence_check",
        "inventory_recovery_items_kind_check",
        "inventory_recovery_items_identity_check",
        "inventory_recovery_items_request_fk",
        "inventory_recovery_items_work_fk",
        "inventory_recovery_items_request_uq",
        "inventory_recovery_items_work_uq",
        "inventory_recovery_items_key_uq",
        "device_inventory_sessions_completion_evidence_check",
        "subscription_tickets_expiry_check",
        "relationship_projection_revision_allocations_pair_uq",
        "relationship_projection_revision_allocations_revision_uq",
        "relationship_projection_revision_allocations_consumed_uq",
        "relationship_projection_revision_allocations_snapshot_fk",
        "relationship_projection_snapshots_allocation_fk",
        "relationship_projection_snapshots_allocation_pair_uq",
        "relationship_projection_snapshots_revision_uq",
        "relationship_projection_snapshots_allocation_uq",
        "relationship_projection_snapshots_completion_check",
        "relationship_projection_declarations_policy_check",
        "blob_upload_tickets_expiry_check",
        "blob_bindings_descriptor_hash_check",
    ]
    .into_iter()
    .map(str::to_owned)
    .collect();
    let actual_constraints: BTreeSet<String> = sqlx::query_scalar(
        r#"
        SELECT con.conname
          FROM pg_constraint con
          JOIN pg_class c ON c.oid=con.conrelid
          JOIN pg_namespace n ON n.oid=c.relnamespace
         WHERE n.nspname='chat'
        "#,
    )
    .fetch_all(&pool)
    .await
    .expect("read constraint names")
    .into_iter()
    .collect();
    assert!(
        required_constraints.is_subset(&actual_constraints),
        "missing required constraints: {:?}",
        required_constraints
            .difference(&actual_constraints)
            .collect::<Vec<_>>()
    );

    let required_indexes: BTreeSet<String> = [
        "devices_active_dpop_jkt_uq",
        "key_packages_live_by_device_idx",
        "conversations_active_direct_pair_uq",
        "generations_one_active_uq",
        "participants_one_current_uq",
        "member_devices_current_device_uq",
        "key_package_reservations_active_package_uq",
        "reset_requests_one_pending_uq",
        "leaf_recovery_requests_one_open_uq",
        "leave_requests_one_pending_uq",
        "relationship_projection_fallback_lookup_idx",
        "outbox_claim_order_idx",
        "outbox_expired_lease_reclaim_idx",
        "welcome_deliveries_pending_global_expiry_idx",
        "recovery_work_items_source_uq",
        "inventory_recovery_items_request_uq",
        "inventory_recovery_items_work_uq",
        "inventory_recovery_items_key_uq",
    ]
    .into_iter()
    .map(str::to_owned)
    .collect();
    let actual_indexes: BTreeSet<String> =
        sqlx::query_scalar("SELECT indexname FROM pg_indexes WHERE schemaname='chat'")
            .fetch_all(&pool)
            .await
            .expect("read index names")
            .into_iter()
            .collect();
    assert!(
        required_indexes.is_subset(&actual_indexes),
        "missing required indexes: {:?}",
        required_indexes
            .difference(&actual_indexes)
            .collect::<Vec<_>>()
    );

    for value in [0_i64, 9_007_199_254_740_991] {
        assert!(
            sqlx::query_scalar::<_, bool>("SELECT chat.is_safe_integer($1)")
                .bind(value)
                .fetch_one(&pool)
                .await
                .expect("evaluate safe integer")
        );
    }
    for value in [-1_i64, 9_007_199_254_740_992] {
        assert!(
            !sqlx::query_scalar::<_, bool>("SELECT chat.is_safe_integer($1)")
                .bind(value)
                .fetch_one(&pool)
                .await
                .expect("evaluate unsafe integer")
        );
    }
    for final_character in "AEIMQUYcgkosw048".chars() {
        let value = format!("{}{}", "A".repeat(42), final_character);
        assert!(
            sqlx::query_scalar::<_, bool>("SELECT chat.is_base64url_sha256($1)")
                .bind(value)
                .fetch_one(&pool)
                .await
                .expect("evaluate canonical digest ID")
        );
    }
    for value in [
        format!("{}B", "A".repeat(42)),
        format!("{}=", "A".repeat(42)),
        "A".repeat(42),
        "A".repeat(44),
    ] {
        assert!(
            !sqlx::query_scalar::<_, bool>("SELECT chat.is_base64url_sha256($1)")
                .bind(value)
                .fetch_one(&pool)
                .await
                .expect("evaluate noncanonical digest ID")
        );
    }

    let principal = "did:plc:abcdefghijklmnopqrstuvwx";
    let other_principal = "did:plc:zyxwvutsrqponmlkjihgfedc";
    let admitted_at: DateTime<Utc> = sqlx::query_scalar("SELECT clock_timestamp()")
        .fetch_one(&pool)
        .await
        .expect("capture device admission time");
    for did in [principal, other_principal] {
        sqlx::query("INSERT INTO chat.principals(user_did,created_at) VALUES($1,$2)")
            .bind(did)
            .bind(&admitted_at)
            .execute(&pool)
            .await
            .expect("insert principal");
    }

    let missing_capabilities = sqlx::query(
        "INSERT INTO chat.devices(user_did,device_id,device_name,status,dpop_jkt,auth_generation,capabilities,created_at,updated_at) VALUES($1,$2,'missing-capabilities','active',$3,1,'{}'::jsonb,$4,$4)",
    )
    .bind(principal)
    .bind(fixture_uuid(80))
    .bind(format!("{}A", "M".repeat(42)))
    .bind(&admitted_at)
    .execute(&pool)
    .await
    .expect_err("missing protocol capabilities must reject");
    assert_eq!(
        missing_capabilities
            .as_database_error()
            .and_then(|error| error.constraint()),
        Some("devices_capabilities_check")
    );
    let extra_capabilities = sqlx::query(
        "INSERT INTO chat.devices(user_did,device_id,device_name,status,dpop_jkt,auth_generation,capabilities,created_at,updated_at) VALUES($1,$2,'extra-capabilities','active',$3,1,chat.protocol_capabilities() || '{\"extra\":true}'::jsonb,$4,$4)",
    )
    .bind(principal)
    .bind(fixture_uuid(81))
    .bind(format!("{}A", "N".repeat(42)))
    .bind(&admitted_at)
    .execute(&pool)
    .await
    .expect_err("extra protocol capability must reject");
    assert_eq!(
        extra_capabilities
            .as_database_error()
            .and_then(|error| error.constraint()),
        Some("devices_capabilities_check")
    );

    let actor_device_id = fixture_uuid(100);
    let second_device_id = fixture_uuid(101);
    let actor_jkt = format!("{:042}A", 0_u128);
    let second_jkt = format!("{:042}A", 1_u128);
    let mut devices = pool.begin().await.expect("begin 20-device boundary");
    for index in 0..20_u128 {
        let name = if index == 19 {
            "x".repeat(128)
        } else {
            format!("device-{index}")
        };
        sqlx::query(
            "INSERT INTO chat.devices(user_did,device_id,device_name,status,dpop_jkt,auth_generation,capabilities,created_at,updated_at) VALUES($1,$2,$3,'active',$4,1,chat.protocol_capabilities(),$5,$5)",
        )
        .bind(principal)
        .bind(fixture_uuid(100 + index))
        .bind(name)
        .bind(format!("{index:042}A"))
        .bind(&admitted_at)
        .execute(&mut *devices)
        .await
        .expect("queue exact-capability device");
    }
    devices
        .commit()
        .await
        .expect("20 active devices must commit");

    let name_too_long = sqlx::query(
        "INSERT INTO chat.devices(user_did,device_id,device_name,status,dpop_jkt,auth_generation,capabilities,created_at,updated_at) VALUES($1,$2,$3,'active',$4,1,chat.protocol_capabilities(),$5,$5)",
    )
    .bind(principal)
    .bind(fixture_uuid(90))
    .bind("x".repeat(129))
    .bind(format!("{}A", "P".repeat(42)))
    .bind(&admitted_at)
    .execute(&pool)
    .await
    .expect_err("129-byte device name must reject");
    assert_eq!(
        name_too_long
            .as_database_error()
            .and_then(|error| error.constraint()),
        Some("devices_name_check")
    );

    let mut overflow = pool.begin().await.expect("begin active-device overflow");
    sqlx::query(
        "INSERT INTO chat.devices(user_did,device_id,device_name,status,dpop_jkt,auth_generation,capabilities,created_at,updated_at) VALUES($1,$2,'overflow','active',$3,1,chat.protocol_capabilities(),$4,$4)",
    )
    .bind(principal)
    .bind(fixture_uuid(120))
    .bind(format!("{:042}A", 20_u128))
    .bind(&admitted_at)
    .execute(&mut *overflow)
    .await
    .expect("deferred limit accepts statement");
    assert!(
        overflow.commit().await.is_err(),
        "21st active device must reject"
    );

    let other_device_id = fixture_uuid(200);
    sqlx::query(
        "INSERT INTO chat.devices(user_did,device_id,device_name,status,dpop_jkt,auth_generation,capabilities,created_at,updated_at) VALUES($1,$2,'other-principal','active',$3,1,chat.protocol_capabilities(),$4,$4)",
    )
    .bind(other_principal)
    .bind(other_device_id)
    .bind(format!("{}A", "O".repeat(42)))
    .bind(&admitted_at)
    .execute(&pool)
    .await
    .expect("insert other-principal device");

    let actor_public_key = vec![2_u8; 32];
    let actor_key_id: String = sqlx::query_scalar("SELECT chat.ed25519_key_id($1)")
        .bind(&actor_public_key)
        .fetch_one(&pool)
        .await
        .expect("derive actor key ID");
    sqlx::query(
        "INSERT INTO chat.device_keys(user_did,device_id,key_id,signing_public_key,enrollment_auth_generation,created_at) VALUES($1,$2,$3,$4,1,$5)",
    )
    .bind(principal)
    .bind(actor_device_id)
    .bind(&actor_key_id)
    .bind(&actor_public_key)
    .bind(&admitted_at)
    .execute(&pool)
    .await
    .expect("insert actor key");

    let short_key = vec![3_u8; 31];
    let short_key_error = sqlx::query(
        "INSERT INTO chat.device_keys(user_did,device_id,key_id,signing_public_key,enrollment_auth_generation,created_at) VALUES($1,$2,chat.ed25519_key_id($3),$3,1,$4)",
    )
    .bind(principal)
    .bind(second_device_id)
    .bind(&short_key)
    .bind(&admitted_at)
    .execute(&pool)
    .await
    .expect_err("31-byte Ed25519 key must reject");
    assert_eq!(
        short_key_error
            .as_database_error()
            .and_then(|error| error.constraint()),
        Some("device_keys_public_key_length_check")
    );

    let second_public_key = vec![3_u8; 32];
    let wrong_key_id = format!("{}A", "B".repeat(42));
    let wrong_binding = sqlx::query(
        "INSERT INTO chat.device_keys(user_did,device_id,key_id,signing_public_key,enrollment_auth_generation,created_at) VALUES($1,$2,$3,$4,1,$5)",
    )
    .bind(principal)
    .bind(second_device_id)
    .bind(wrong_key_id)
    .bind(&second_public_key)
    .bind(&admitted_at)
    .execute(&pool)
    .await
    .expect_err("arbitrary key ID must reject");
    assert_eq!(
        wrong_binding
            .as_database_error()
            .and_then(|error| error.constraint()),
        Some("device_keys_key_id_binding_check")
    );
    let second_key_id: String = sqlx::query_scalar("SELECT chat.ed25519_key_id($1)")
        .bind(&second_public_key)
        .fetch_one(&pool)
        .await
        .expect("derive second key ID");
    sqlx::query(
        "INSERT INTO chat.device_keys(user_did,device_id,key_id,signing_public_key,enrollment_auth_generation,created_at) VALUES($1,$2,$3,$4,1,$5)",
    )
    .bind(principal)
    .bind(second_device_id)
    .bind(&second_key_id)
    .bind(&second_public_key)
    .bind(&admitted_at)
    .execute(&pool)
    .await
    .expect("insert second device key");

    let fixture = create_conversation_fixture(
        &pool,
        principal,
        actor_device_id,
        &actor_key_id,
        &actor_public_key,
    )
    .await;
    let fixture_is_coherent: bool = sqlx::query_scalar(
        r#"
        SELECT EXISTS(
            SELECT 1
              FROM chat.conversations c
              JOIN chat.transitions t ON t.conversation_id=c.conversation_id
              JOIN chat.entries e ON e.conversation_id=t.conversation_id
                                 AND e.seq=t.entry_seq AND e.transition_id=t.transition_id
              JOIN chat.generation_states s ON s.producing_transition_id=t.transition_id
              JOIN chat.metadata_snapshots m ON m.producing_transition_id=t.transition_id
              JOIN chat.participants p ON p.conversation_id=c.conversation_id
              JOIN chat.member_devices leaf ON leaf.participant_period_id=p.participant_period_id
              JOIN chat.application_intervals i ON i.opening_leaf_period_id=leaf.leaf_period_id
             WHERE c.conversation_id=$1 AND t.transition_id=$2 AND e.entry_id=$3
               AND m.metadata_snapshot_id=$4 AND p.participant_period_id=$5
               AND leaf.leaf_period_id=$6 AND i.membership_interval_id=$2
               AND c.created_at=t.accepted_at AND s.created_at=t.accepted_at
               AND m.created_at=t.accepted_at AND p.created_at=t.accepted_at
               AND leaf.created_at=t.accepted_at AND i.created_at=t.accepted_at
        )
        "#,
    )
    .bind(fixture.conversation_id)
    .bind(fixture.creation_transition_id)
    .bind(fixture.creation_entry_id)
    .bind(fixture.metadata_snapshot_id)
    .bind(fixture.participant_period_id)
    .bind(fixture.leaf_period_id)
    .fetch_one(&pool)
    .await
    .expect("verify coherent fixture graph");
    assert!(
        fixture_is_coherent,
        "creation fixture lost exact provenance"
    );
    assert_eq!(fixture.group_id.len(), 32);
    assert_eq!(fixture.group_context_hash.len(), 32);
    assert_eq!(fixture.confirmation_tag.len(), 32);
    assert_eq!(fixture.creation_fingerprint.len(), 32);

    let mut pointer_probe = pool.begin().await.expect("begin pointer probe");
    sqlx::query("UPDATE chat.conversations SET current_state_version=99 WHERE conversation_id=$1")
        .bind(fixture.conversation_id)
        .execute(&mut *pointer_probe)
        .await
        .expect("queue invalid deferred state pointer");
    assert!(
        pointer_probe.commit().await.is_err(),
        "fabricated current-state pointer must reject"
    );
    let current_state: i64 = sqlx::query_scalar(
        "SELECT current_state_version FROM chat.conversations WHERE conversation_id=$1",
    )
    .bind(fixture.conversation_id)
    .fetch_one(&pool)
    .await
    .expect("read pointer after rollback");
    assert_eq!(current_state, 0);

    let mut sequence_probe = pool.begin().await.expect("begin sequence probe");
    sqlx::query("UPDATE chat.conversations SET next_entry_seq=3 WHERE conversation_id=$1")
        .bind(fixture.conversation_id)
        .execute(&mut *sequence_probe)
        .await
        .expect("queue noncontiguous next sequence");
    assert!(
        sequence_probe.commit().await.is_err(),
        "conversation entry sequence gap must reject"
    );

    let immutable_transition =
        sqlx::query("UPDATE chat.transitions SET actor_role='member' WHERE transition_id=$1")
            .bind(fixture.creation_transition_id)
            .execute(&pool)
            .await
            .expect_err("accepted transition authority is immutable");
    assert!(
        immutable_transition
            .to_string()
            .contains("immutable chat identity/provenance changed"),
        "unexpected transition immutability failure: {immutable_transition:?}"
    );

    // Revocation is a signed, receipt-backed terminal event. It revokes the
    // transport/device key without rewriting already accepted MLS history.
    let revocation_id = fixture_uuid(250);
    let revocation_request = vec![21_u8; 8];
    let revocation_transcript = vec![22_u8; 8];
    let revocation_digest = Sha256::digest(&revocation_transcript).to_vec();
    let revocation_signature = vec![23_u8; 64];
    let revocation_response = vec![24_u8; 8];
    let revoked_at: DateTime<Utc> = sqlx::query_scalar("SELECT clock_timestamp()")
        .fetch_one(&pool)
        .await
        .expect("capture revocation acceptance time");
    let mut revoke = pool.begin().await.expect("begin exact revocation mapping");
    sqlx::query(
        r#"
        INSERT INTO chat.idempotency_records(
            principal_did,endpoint_nsid,operation_id,request_digest,
            accepted_request_bytes,signing_transcript_bytes,signature,completed_status,
            response_bytes,response_sha256,historical_jkt,completed_at
        ) VALUES($1,'blue.catbird.chat.revokeDevice',$2,$3,$4,$5,$6,200,$7,$8,$9,$10)
        "#,
    )
    .bind(principal)
    .bind(revocation_id)
    .bind(&revocation_digest)
    .bind(&revocation_request)
    .bind(&revocation_transcript)
    .bind(&revocation_signature)
    .bind(&revocation_response)
    .bind(Sha256::digest(&revocation_response).to_vec())
    .bind(&actor_jkt)
    .bind(&revoked_at)
    .execute(&mut *revoke)
    .await
    .expect("insert revocation idempotency receipt");
    sqlx::query(
        r#"
        INSERT INTO chat.device_revocations(
            revocation_id,actor_did,actor_device_id,actor_key_id,actor_auth_generation,
            target_did,target_device_id,target_auth_generation,accepted_request_bytes,
            signing_transcript_bytes,request_digest,signature,signed_at,accepted_at
        ) VALUES($1,$2,$3,$4,1,$2,$5,1,$6,$7,$8,$9,$10,$10)
        "#,
    )
    .bind(revocation_id)
    .bind(principal)
    .bind(actor_device_id)
    .bind(&actor_key_id)
    .bind(actor_device_id)
    .bind(&revocation_request)
    .bind(&revocation_transcript)
    .bind(&revocation_digest)
    .bind(&revocation_signature)
    .bind(&revoked_at)
    .execute(&mut *revoke)
    .await
    .expect("insert signed device revocation");
    sqlx::query(
        "UPDATE chat.devices SET status='revoked',revoked_at=$3,revocation_id=$4,updated_at=$3 WHERE user_did=$1 AND device_id=$2",
    )
    .bind(principal)
    .bind(actor_device_id)
    .bind(&revoked_at)
    .bind(revocation_id)
    .execute(&mut *revoke)
    .await
    .expect("terminally revoke device");
    sqlx::query(
        "UPDATE chat.device_keys SET revoked_at=$3,revocation_id=$4 WHERE user_did=$1 AND device_id=$2",
    )
    .bind(principal)
    .bind(actor_device_id)
    .bind(&revoked_at)
    .bind(revocation_id)
    .execute(&mut *revoke)
    .await
    .expect("terminally revoke device key");
    revoke
        .commit()
        .await
        .expect("commit signed revocation evidence graph");

    let (device_status, key_revoked, live_leaf): (String, bool, bool) = sqlx::query_as(
        r#"
        SELECT d.status, k.revocation_id IS NOT NULL,
               EXISTS(SELECT 1 FROM chat.member_devices leaf
                       WHERE leaf.leaf_period_id=$3 AND leaf.active)
          FROM chat.devices d
          JOIN chat.device_keys k USING(user_did,device_id)
         WHERE d.user_did=$1 AND d.device_id=$2
        "#,
    )
    .bind(principal)
    .bind(actor_device_id)
    .bind(fixture.leaf_period_id)
    .fetch_one(&pool)
    .await
    .expect("verify terminal revocation and preserved MLS history");
    assert_eq!(device_status, "revoked");
    assert!(key_revoked);
    assert!(
        live_leaf,
        "revocation must not rewrite accepted MLS leaf history"
    );

    let arbitrary_revocation_id = fixture_uuid(251);
    let third_device_id = fixture_uuid(102);
    let mut fabricated_revocation = pool.begin().await.expect("begin fabricated revocation");
    sqlx::query(
        "UPDATE chat.devices SET status='revoked',revoked_at=$3,revocation_id=$4,updated_at=$3 WHERE user_did=$1 AND device_id=$2",
    )
    .bind(principal)
    .bind(third_device_id)
    .bind(&revoked_at)
    .bind(arbitrary_revocation_id)
    .execute(&mut *fabricated_revocation)
    .await
    .expect("queue revocation lacking signed evidence");
    assert!(
        fabricated_revocation.commit().await.is_err(),
        "device status cannot fabricate revocation evidence"
    );

    let immutable_revocation =
        sqlx::query("UPDATE chat.device_revocations SET signature=$2 WHERE revocation_id=$1")
            .bind(revocation_id)
            .bind(vec![25_u8; 64])
            .execute(&pool)
            .await
            .expect_err("revocation evidence must be immutable");
    assert!(immutable_revocation
        .to_string()
        .contains("immutable chat identity/provenance changed"));

    // Continue new authenticated work through a still-active sibling device;
    // the revoked creator remains only as immutable historical MLS evidence.
    let actor_device_id = second_device_id;
    let actor_jkt = second_jkt.clone();
    let actor_key_id = second_key_id.clone();

    let empty_digest = Sha256::digest([]).to_vec();
    let inventory_session_id = fixture_uuid(300);
    let device_inventory_session_id = fixture_uuid(301);
    let inventory_cursor = b"inventory-cursor".to_vec();
    let inventory_cursor_digest = Sha256::digest(&inventory_cursor).to_vec();
    let inventory_at: DateTime<Utc> = sqlx::query_scalar("SELECT clock_timestamp()")
        .fetch_one(&pool)
        .await
        .expect("capture inventory fence time");
    let inventory_expires = inventory_at + Duration::minutes(5);
    let mut inventory = pool
        .begin()
        .await
        .expect("begin complete empty inventories");
    sqlx::query(
        r#"
        INSERT INTO chat.inventory_sessions(
            inventory_session_id,token_hash,user_did,device_id,jkt,auth_generation,
            snapshot_event_position,snapshot_event_cursor_bytes,snapshot_event_cursor_sha256,
            created_at,expires_at,conversations_complete,welcomes_complete,recovery_complete,
            conversation_item_count,conversation_items_sha256,welcome_item_count,
            welcome_items_sha256,recovery_item_count,recovery_items_sha256
        ) VALUES($1,$2,$3,$4,$5,1,7,$6,$7,$8,$9,true,true,true,0,$10,0,$10,0,$10)
        "#,
    )
    .bind(inventory_session_id)
    .bind(vec![31_u8; 32])
    .bind(principal)
    .bind(actor_device_id)
    .bind(&actor_jkt)
    .bind(&inventory_cursor)
    .bind(&inventory_cursor_digest)
    .bind(&inventory_at)
    .bind(&inventory_expires)
    .bind(&empty_digest)
    .execute(&mut *inventory)
    .await
    .expect("insert complete empty conversation inventory");
    let ticket_created = inventory_at + Duration::seconds(1);
    let ticket_expires = ticket_created + Duration::seconds(30);
    sqlx::query(
        r#"
        INSERT INTO chat.subscription_tickets(
            ticket_hash,user_did,device_id,jkt,auth_generation,inventory_session_id,
            event_position,event_cursor_bytes,event_cursor_sha256,subscription_path,
            created_at,expires_at
        ) VALUES($1,$2,$3,$4,1,$5,7,$6,$7,
                 '/xrpc/blue.catbird.chat.subscribeEvents',$8,$9)
        "#,
    )
    .bind(vec![32_u8; 32])
    .bind(principal)
    .bind(actor_device_id)
    .bind(&actor_jkt)
    .bind(inventory_session_id)
    .bind(&inventory_cursor)
    .bind(&inventory_cursor_digest)
    .bind(&ticket_created)
    .bind(&ticket_expires)
    .execute(&mut *inventory)
    .await
    .expect("insert exactly bound short-lived subscription ticket");
    sqlx::query(
        r#"
        INSERT INTO chat.device_inventory_sessions(
            device_inventory_session_id,user_did,device_id,jkt,auth_generation,
            fence_revision,created_at,expires_at,complete,item_count,items_sha256
        ) VALUES($1,$2,$3,$4,1,9,$5,$6,true,0,$7)
        "#,
    )
    .bind(device_inventory_session_id)
    .bind(principal)
    .bind(actor_device_id)
    .bind(&actor_jkt)
    .bind(&inventory_at)
    .bind(&inventory_expires)
    .bind(&empty_digest)
    .execute(&mut *inventory)
    .await
    .expect("insert complete empty device inventory");
    inventory
        .commit()
        .await
        .expect("commit materialized inventories and bound ticket");

    let null_completion_evidence = sqlx::query(
        r#"
        INSERT INTO chat.inventory_sessions(
            inventory_session_id,token_hash,user_did,device_id,jkt,auth_generation,
            snapshot_event_position,snapshot_event_cursor_bytes,snapshot_event_cursor_sha256,
            created_at,expires_at,conversations_complete,welcomes_complete,recovery_complete
        ) VALUES($1,$2,$3,$4,$5,1,10,$6,$7,$8,$9,true,false,false)
        "#,
    )
    .bind(fixture_uuid(302))
    .bind(vec![33_u8; 32])
    .bind(principal)
    .bind(actor_device_id)
    .bind(&actor_jkt)
    .bind(&inventory_cursor)
    .bind(&inventory_cursor_digest)
    .bind(&inventory_at)
    .bind(&inventory_expires)
    .execute(&pool)
    .await
    .expect_err("completed inventory with NULL count/hash must reject");
    assert_eq!(
        null_completion_evidence
            .as_database_error()
            .and_then(|error| error.constraint()),
        Some("inventory_sessions_completion_evidence_check")
    );

    let null_device_evidence = sqlx::query(
        r#"
        INSERT INTO chat.device_inventory_sessions(
            device_inventory_session_id,user_did,device_id,jkt,auth_generation,
            fence_revision,created_at,expires_at,complete
        ) VALUES($1,$2,$3,$4,1,10,$5,$6,true)
        "#,
    )
    .bind(fixture_uuid(303))
    .bind(principal)
    .bind(actor_device_id)
    .bind(&actor_jkt)
    .bind(&inventory_at)
    .bind(&inventory_expires)
    .execute(&pool)
    .await
    .expect_err("completed device inventory with NULL evidence must reject");
    assert_eq!(
        null_device_evidence
            .as_database_error()
            .and_then(|error| error.constraint()),
        Some("device_inventory_sessions_completion_evidence_check")
    );

    let inventory_payload = vec![34_u8; 8];
    let mut post_completion_item = pool
        .begin()
        .await
        .expect("begin post-completion inventory mutation");
    // The O(1) session-freeze guard (BEFORE INSERT) rejects this row at
    // execute() time because the session's conversation domain is already
    // complete, so the item never reaches commit. Capture the Result rather
    // than expecting it.
    let post_completion_result = sqlx::query(
        r#"
        INSERT INTO chat.inventory_conversation_items(
            inventory_session_id,ordinal,conversation_id,recipient_did,recipient_device_id,item_key_bytes,payload_bytes,payload_sha256
        ) VALUES($1,0,$2,$3,$4,uuid_send($2),$5,$6)
        "#,
    )
    .bind(inventory_session_id)
    .bind(fixture.conversation_id)
    .bind(principal)
    .bind(actor_device_id)
    .bind(&inventory_payload)
    .bind(Sha256::digest(&inventory_payload).to_vec())
    .execute(&mut *post_completion_item)
    .await;
    assert!(
        post_completion_result.is_err(),
        "completed session domain must reject a new inventory item"
    );
    post_completion_item
        .rollback()
        .await
        .expect("roll back rejected post-completion inventory mutation");

    let crossing_inventory_session = fixture_uuid(304);
    let crossing_payload = vec![35_u8; 8];
    let mut crossing_inventory = pool.begin().await.expect("begin principal crossing probe");
    sqlx::query(
        r#"
        INSERT INTO chat.device_inventory_sessions(
            device_inventory_session_id,user_did,device_id,jkt,auth_generation,
            fence_revision,created_at,expires_at,complete
        ) VALUES($1,$2,$3,$4,1,11,$5,$6,false)
        "#,
    )
    .bind(crossing_inventory_session)
    .bind(principal)
    .bind(actor_device_id)
    .bind(&actor_jkt)
    .bind(&inventory_at)
    .bind(&inventory_expires)
    .execute(&mut *crossing_inventory)
    .await
    .expect("insert open device inventory");
    // A device-inventory item owned by `principal` cannot describe another
    // principal's device. The recipient device here is other_principal's real
    // device (so the recipient device FK is satisfied), which means the
    // rejection is the explicit principal-binding CHECK — recipient_did must
    // equal requester_did — and not an incidental NOT-NULL/FK typo. The
    // composite bindings enforce this at execute() time, so capture the
    // rejection directly rather than deferring it to commit.
    let crossing_rejection = sqlx::query(
        r#"
        INSERT INTO chat.device_inventory_items(
            device_inventory_session_id,ordinal,subject_device_id,requester_did,requester_device_id,
            recipient_did,recipient_device_id,payload_bytes,payload_sha256
        ) VALUES($1,0,$2,$3,$4,$5,$6,$7,$8)
        "#,
    )
    .bind(crossing_inventory_session)
    .bind(other_device_id)
    .bind(principal)
    .bind(actor_device_id)
    .bind(other_principal)
    .bind(other_device_id)
    .bind(&crossing_payload)
    .bind(Sha256::digest(&crossing_payload).to_vec())
    .execute(&mut *crossing_inventory)
    .await
    .expect_err("device inventory cannot cross principal boundary");
    assert_eq!(
        crossing_rejection
            .as_database_error()
            .and_then(|error| error.constraint()),
        Some("device_inventory_items_principal_binding_check")
    );
    crossing_inventory
        .rollback()
        .await
        .expect("roll back rejected cross-principal device item");

    let projection_at: DateTime<Utc> = sqlx::query_scalar("SELECT clock_timestamp()")
        .fetch_one(&pool)
        .await
        .expect("capture projection time");
    let canonical_dids = format!("{principal}\n{other_principal}").into_bytes();
    let aggregate_evidence = vec![41_u8; 8];
    let traffic_projection = fixture_uuid(400);
    let (traffic_projection_allocation_id, traffic_projection_revision) =
        allocate_relationship_projection_revision(&pool).await;
    let mut projection = pool.begin().await.expect("begin traffic projection");
    sqlx::query(
        r#"
        INSERT INTO chat.relationship_projection_snapshots(
            projection_id,projection_revision,operation_scope,canonical_did_set_bytes,
            canonical_did_set_sha256,scope_digest,appview_base,configuration_fingerprint,
            aggregate_evidence_bytes,aggregate_evidence_sha256,source_call_count,
            evidence_kind,started_at,completed_at,projection_allocation_id
        ) VALUES($1,$2,'traffic',$3,$4,$5,'https://appview.example.net',$6,$7,$8,1,'live',$9,$9,$10)
        "#,
    )
    .bind(traffic_projection)
    .bind(traffic_projection_revision)
    .bind(&canonical_dids)
    .bind(Sha256::digest(&canonical_dids).to_vec())
    .bind(vec![42_u8; 32])
    .bind(vec![43_u8; 32])
    .bind(&aggregate_evidence)
    .bind(Sha256::digest(&aggregate_evidence).to_vec())
    .bind(&projection_at)
    .bind(traffic_projection_allocation_id)
    .execute(&mut *projection)
    .await
    .expect("insert traffic projection snapshot");
    sqlx::query(
        r#"
        INSERT INTO chat.relationship_projection_relationships(
            projection_id,actor_did,other_did,blocking,blocked_by,blocking_by_list,
            blocked_by_list,following,followed_by,batch_ordinal,fetch_revision,
            request_digest,response_digest,evidence_kind,fetched_at
        ) VALUES($1,$2,$3,false,false,false,false,true,false,0,101,$4,$5,'live',$6)
        "#,
    )
    .bind(traffic_projection)
    .bind(principal)
    .bind(other_principal)
    .bind(vec![44_u8; 32])
    .bind(vec![45_u8; 32])
    .bind(&projection_at)
    .execute(&mut *projection)
    .await
    .expect("insert one complete relationship batch");
    projection
        .commit()
        .await
        .expect("commit complete traffic projection");

    let bad_projection = fixture_uuid(401);
    let (bad_projection_allocation_id, bad_projection_revision) =
        allocate_relationship_projection_revision(&pool).await;
    let mut ordinal_gap = pool.begin().await.expect("begin relationship ordinal gap");
    sqlx::query(
        r#"
        INSERT INTO chat.relationship_projection_snapshots(
            projection_id,projection_revision,operation_scope,canonical_did_set_bytes,
            canonical_did_set_sha256,scope_digest,appview_base,configuration_fingerprint,
            aggregate_evidence_bytes,aggregate_evidence_sha256,source_call_count,
            evidence_kind,started_at,completed_at,projection_allocation_id
        ) VALUES($1,$2,'traffic',$3,$4,$5,'https://appview.example.net',$6,$7,$8,1,'live',$9,$9,$10)
        "#,
    )
    .bind(bad_projection)
    .bind(bad_projection_revision)
    .bind(&canonical_dids)
    .bind(Sha256::digest(&canonical_dids).to_vec())
    .bind(vec![46_u8; 32])
    .bind(vec![47_u8; 32])
    .bind(&aggregate_evidence)
    .bind(Sha256::digest(&aggregate_evidence).to_vec())
    .bind(&projection_at)
    .bind(bad_projection_allocation_id)
    .execute(&mut *ordinal_gap)
    .await
    .expect("insert projection for ordinal-gap probe");
    sqlx::query(
        r#"
        INSERT INTO chat.relationship_projection_relationships(
            projection_id,actor_did,other_did,blocking,blocked_by,blocking_by_list,
            blocked_by_list,following,followed_by,batch_ordinal,fetch_revision,
            request_digest,response_digest,evidence_kind,fetched_at
        ) VALUES($1,$2,$3,false,false,false,false,false,false,1,102,$4,$5,'live',$6)
        "#,
    )
    .bind(bad_projection)
    .bind(principal)
    .bind(other_principal)
    .bind(vec![48_u8; 32])
    .bind(vec![49_u8; 32])
    .bind(&projection_at)
    .execute(&mut *ordinal_gap)
    .await
    .expect("queue relationship batch starting at ordinal one");
    assert!(
        ordinal_gap.commit().await.is_err(),
        "relationship batch ordinals must be contiguous from zero"
    );
    let failed_projection_claim: Option<uuid::Uuid> = sqlx::query_scalar(
        "SELECT consumed_projection_id FROM chat.relationship_projection_revision_allocations WHERE allocation_id=$1",
    )
    .bind(bad_projection_allocation_id)
    .fetch_one(&pool)
    .await
    .expect("inspect allocation after deferred projection failure");
    assert_eq!(
        failed_projection_claim, None,
        "deferred transaction failure must roll allocation consumption back"
    );

    let declaration_projection = fixture_uuid(402);
    let (declaration_projection_allocation_id, declaration_projection_revision) =
        allocate_relationship_projection_revision(&pool).await;
    let declaration_evidence = vec![50_u8; 8];
    let mut declaration = pool.begin().await.expect("begin declaration projection");
    sqlx::query(
        r#"
        INSERT INTO chat.relationship_projection_snapshots(
            projection_id,projection_revision,operation_scope,canonical_did_set_bytes,
            canonical_did_set_sha256,scope_digest,appview_base,configuration_fingerprint,
            aggregate_evidence_bytes,aggregate_evidence_sha256,source_call_count,
            evidence_kind,started_at,completed_at,projection_allocation_id
        ) VALUES($1,$2,'creation',$3,$4,$5,'https://appview.example.net',$6,$7,$8,2,'fallback',$9,$9,$10)
        "#,
    )
    .bind(declaration_projection)
    .bind(declaration_projection_revision)
    .bind(&canonical_dids)
    .bind(Sha256::digest(&canonical_dids).to_vec())
    .bind(vec![51_u8; 32])
    .bind(vec![52_u8; 32])
    .bind(&declaration_evidence)
    .bind(Sha256::digest(&declaration_evidence).to_vec())
    .bind(&projection_at)
    .bind(declaration_projection_allocation_id)
    .execute(&mut *declaration)
    .await
    .expect("insert declaration projection snapshot");
    sqlx::query(
        r#"
        INSERT INTO chat.relationship_projection_declarations(
            projection_id,recipient_did,resolved_pds_origin,service_id,fetch_revision,
            did_request_digest,did_document_digest,record_request_digest,
            record_response_digest,record_evidence_kind,incoming_policy,
            allow_group_invites,resolved_group_policy,evidence_kind,fetched_at
        ) VALUES($1,$2,'https://pds.example.net','#atproto_pds',103,$3,$4,$5,$6,
                 'structuredRecordNotFound','following',NULL,'following','fallback',$7)
        "#,
    )
    .bind(declaration_projection)
    .bind(other_principal)
    .bind(vec![53_u8; 32])
    .bind(vec![54_u8; 32])
    .bind(vec![55_u8; 32])
    .bind(vec![56_u8; 32])
    .bind(&projection_at)
    .execute(&mut *declaration)
    .await
    .expect("insert structured-not-found declaration evidence");
    declaration
        .commit()
        .await
        .expect("commit fallback declaration projection");

    let empty_projection_insert = r#"
        INSERT INTO chat.relationship_projection_snapshots(
            projection_id,projection_revision,projection_allocation_id,operation_scope,
            canonical_did_set_bytes,canonical_did_set_sha256,scope_digest,appview_base,
            configuration_fingerprint,aggregate_evidence_bytes,aggregate_evidence_sha256,
            source_call_count,evidence_kind,started_at,completed_at
        ) VALUES($1,$2,$3,'traffic',$4,$5,$6,'https://appview.example.net',$7,$8,$9,0,'live',$10,$10)
    "#;
    let burned_raw_revision: i64 =
        sqlx::query_scalar("SELECT nextval('chat.relationship_projection_revision_seq')")
            .fetch_one(&pool)
            .await
            .expect("burn a raw projection revision without an allocation claim");
    let (retry_allocation_id, retry_revision) =
        allocate_relationship_projection_revision(&pool).await;
    assert!(
        burned_raw_revision < retry_revision,
        "raw burned revision must be below the allocator high-water mark"
    );
    assert_eq!(
        retry_allocation_id.get_version_num(),
        4,
        "allocator must mint a UUIDv4 capability"
    );

    let raw_burn_error = sqlx::query(empty_projection_insert)
        .bind(fixture_uuid(408))
        .bind(burned_raw_revision)
        .bind(fixture_uuid(508))
        .bind(&canonical_dids)
        .bind(Sha256::digest(&canonical_dids).to_vec())
        .bind(vec![57_u8; 32])
        .bind(vec![58_u8; 32])
        .bind(&aggregate_evidence)
        .bind(Sha256::digest(&aggregate_evidence).to_vec())
        .bind(&projection_at)
        .execute(&pool)
        .await
        .expect_err("raw nextval below high-water must not authorize a projection");
    assert!(
        raw_burn_error
            .to_string()
            .contains("relationship projection allocation is absent, mismatched, or consumed"),
        "unexpected raw-revision failure: {raw_burn_error:?}"
    );

    let wrong_allocation_error = sqlx::query(empty_projection_insert)
        .bind(fixture_uuid(409))
        .bind(retry_revision)
        .bind(fixture_uuid(509))
        .bind(&canonical_dids)
        .bind(Sha256::digest(&canonical_dids).to_vec())
        .bind(vec![57_u8; 32])
        .bind(vec![58_u8; 32])
        .bind(&aggregate_evidence)
        .bind(Sha256::digest(&aggregate_evidence).to_vec())
        .bind(&projection_at)
        .execute(&pool)
        .await
        .expect_err("wrong allocation UUID must not authorize an allocated revision");
    assert!(
        wrong_allocation_error
            .to_string()
            .contains("relationship projection allocation is absent, mismatched, or consumed"),
        "unexpected wrong-allocation failure: {wrong_allocation_error:?}"
    );

    let (_other_allocation_id, other_revision) =
        allocate_relationship_projection_revision(&pool).await;
    let mismatched_pair_error = sqlx::query(empty_projection_insert)
        .bind(fixture_uuid(410))
        .bind(other_revision)
        .bind(retry_allocation_id)
        .bind(&canonical_dids)
        .bind(Sha256::digest(&canonical_dids).to_vec())
        .bind(vec![57_u8; 32])
        .bind(vec![58_u8; 32])
        .bind(&aggregate_evidence)
        .bind(Sha256::digest(&aggregate_evidence).to_vec())
        .bind(&projection_at)
        .execute(&pool)
        .await
        .expect_err("allocation UUID stolen from another revision must reject");
    assert!(
        mismatched_pair_error
            .to_string()
            .contains("relationship projection allocation is absent, mismatched, or consumed"),
        "unexpected mismatched-pair failure: {mismatched_pair_error:?}"
    );

    let retry_projection = fixture_uuid(411);
    let mut rolled_back_claim = pool.begin().await.expect("begin allocation rollback probe");
    sqlx::query(empty_projection_insert)
        .bind(retry_projection)
        .bind(retry_revision)
        .bind(retry_allocation_id)
        .bind(&canonical_dids)
        .bind(Sha256::digest(&canonical_dids).to_vec())
        .bind(vec![57_u8; 32])
        .bind(vec![58_u8; 32])
        .bind(&aggregate_evidence)
        .bind(Sha256::digest(&aggregate_evidence).to_vec())
        .bind(&projection_at)
        .execute(&mut *rolled_back_claim)
        .await
        .expect("consume exact allocation inside rollback probe");
    let claimed_projection: Option<uuid::Uuid> = sqlx::query_scalar(
        "SELECT consumed_projection_id FROM chat.relationship_projection_revision_allocations WHERE allocation_id=$1",
    )
    .bind(retry_allocation_id)
    .fetch_one(&mut *rolled_back_claim)
    .await
    .expect("inspect transaction-local allocation consumption");
    assert_eq!(claimed_projection, Some(retry_projection));
    rolled_back_claim
        .rollback()
        .await
        .expect("roll back allocation consumption");
    let claim_after_rollback: (Option<uuid::Uuid>, Option<DateTime<Utc>>) = sqlx::query_as(
        "SELECT consumed_projection_id, consumed_at FROM chat.relationship_projection_revision_allocations WHERE allocation_id=$1",
    )
    .bind(retry_allocation_id)
    .fetch_one(&pool)
    .await
    .expect("inspect allocation after rollback");
    assert_eq!(
        claim_after_rollback,
        (None, None),
        "rollback must restore the exact allocation claim"
    );

    let mut exact_retry = pool.begin().await.expect("begin exact allocation retry");
    sqlx::query(empty_projection_insert)
        .bind(retry_projection)
        .bind(retry_revision)
        .bind(retry_allocation_id)
        .bind(&canonical_dids)
        .bind(Sha256::digest(&canonical_dids).to_vec())
        .bind(vec![57_u8; 32])
        .bind(vec![58_u8; 32])
        .bind(&aggregate_evidence)
        .bind(Sha256::digest(&aggregate_evidence).to_vec())
        .bind(&projection_at)
        .execute(&mut *exact_retry)
        .await
        .expect("reuse restored allocation for exact retry");
    exact_retry
        .commit()
        .await
        .expect("commit exact retry after rollback");

    let conflicting_reuse_error = sqlx::query(empty_projection_insert)
        .bind(fixture_uuid(412))
        .bind(retry_revision)
        .bind(retry_allocation_id)
        .bind(&canonical_dids)
        .bind(Sha256::digest(&canonical_dids).to_vec())
        .bind(vec![57_u8; 32])
        .bind(vec![58_u8; 32])
        .bind(&aggregate_evidence)
        .bind(Sha256::digest(&aggregate_evidence).to_vec())
        .bind(&projection_at)
        .execute(&pool)
        .await
        .expect_err("consumed allocation cannot authorize a conflicting projection");
    assert!(
        conflicting_reuse_error
            .to_string()
            .contains("relationship projection allocation is absent, mismatched, or consumed"),
        "unexpected conflicting-reuse failure: {conflicting_reuse_error:?}"
    );

    let (stale_window_allocation_id, stale_window_revision) =
        allocate_relationship_projection_revision(&pool).await;
    let stale_window_projection = fixture_uuid(405);
    let stale_window_completed_at = projection_at + Duration::seconds(31);
    let stale_window_error = sqlx::query(
        r#"
        INSERT INTO chat.relationship_projection_snapshots(
            projection_id,projection_revision,operation_scope,canonical_did_set_bytes,
            canonical_did_set_sha256,scope_digest,appview_base,configuration_fingerprint,
            aggregate_evidence_bytes,aggregate_evidence_sha256,source_call_count,
            evidence_kind,started_at,completed_at,projection_allocation_id
        ) VALUES($1,$2,'traffic',$3,$4,$5,'https://appview.example.net',$6,$7,$8,0,'live',$9,$10,$11)
        "#,
    )
    .bind(stale_window_projection)
    .bind(stale_window_revision)
    .bind(&canonical_dids)
    .bind(Sha256::digest(&canonical_dids).to_vec())
    .bind(vec![75_u8; 32])
    .bind(vec![76_u8; 32])
    .bind(&aggregate_evidence)
    .bind(Sha256::digest(&aggregate_evidence).to_vec())
    .bind(&projection_at)
    .bind(&stale_window_completed_at)
    .bind(stale_window_allocation_id)
    .execute(&pool)
    .await
    .expect_err("relationship evidence collected over 30 seconds must reject");
    assert_eq!(
        stale_window_error
            .as_database_error()
            .and_then(|error| error.constraint()),
        Some("relationship_projection_snapshots_completion_check")
    );
    let stale_window_claim: Option<uuid::Uuid> = sqlx::query_scalar(
        "SELECT consumed_projection_id FROM chat.relationship_projection_revision_allocations WHERE allocation_id=$1",
    )
    .bind(stale_window_allocation_id)
    .fetch_one(&pool)
    .await
    .expect("inspect allocation after snapshot check failure");
    assert_eq!(
        stale_window_claim, None,
        "failed snapshot statement must not consume its allocation"
    );

    let (graph_alias_allocation_id, graph_alias_revision) =
        allocate_relationship_projection_revision(&pool).await;
    let graph_alias_projection = fixture_uuid(406);
    let mut graph_alias = pool
        .begin()
        .await
        .expect("begin graph revision-alias probe");
    sqlx::query(
        r#"
        INSERT INTO chat.relationship_projection_snapshots(
            projection_id,projection_revision,operation_scope,canonical_did_set_bytes,
            canonical_did_set_sha256,scope_digest,appview_base,configuration_fingerprint,
            aggregate_evidence_bytes,aggregate_evidence_sha256,source_call_count,
            evidence_kind,started_at,completed_at,projection_allocation_id
        ) VALUES($1,$2,'traffic',$3,$4,$5,'https://appview.example.net',$6,$7,$8,1,'live',$9,$9,$10)
        "#,
    )
    .bind(graph_alias_projection)
    .bind(graph_alias_revision)
    .bind(&canonical_dids)
    .bind(Sha256::digest(&canonical_dids).to_vec())
    .bind(vec![77_u8; 32])
    .bind(vec![78_u8; 32])
    .bind(&aggregate_evidence)
    .bind(Sha256::digest(&aggregate_evidence).to_vec())
    .bind(&projection_at)
    .bind(graph_alias_allocation_id)
    .execute(&mut *graph_alias)
    .await
    .expect("insert graph revision-alias snapshot");
    sqlx::query(
        r#"
        INSERT INTO chat.relationship_projection_relationships(
            projection_id,actor_did,other_did,blocking,blocked_by,blocking_by_list,
            blocked_by_list,following,followed_by,batch_ordinal,fetch_revision,
            request_digest,response_digest,evidence_kind,fetched_at
        ) VALUES($1,$2,$3,false,false,false,false,false,false,0,$4,$5,$6,'live',$7)
        "#,
    )
    .bind(graph_alias_projection)
    .bind(principal)
    .bind(other_principal)
    .bind(graph_alias_revision)
    .bind(vec![79_u8; 32])
    .bind(vec![80_u8; 32])
    .bind(&projection_at)
    .execute(&mut *graph_alias)
    .await
    .expect("queue graph child reusing snapshot revision");
    let graph_alias_error = graph_alias
        .commit()
        .await
        .expect_err("graph fetch revision cannot equal snapshot revision");
    assert!(
        graph_alias_error
            .to_string()
            .contains("relationship projection evidence mismatch"),
        "unexpected graph revision-alias failure: {graph_alias_error:?}"
    );
    let graph_alias_residue: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM chat.relationship_projection_snapshots WHERE projection_id=$1)",
    )
    .bind(graph_alias_projection)
    .fetch_one(&pool)
    .await
    .expect("inspect graph revision-alias residue");
    assert!(
        !graph_alias_residue,
        "failed graph alias left durable residue"
    );

    let (declaration_alias_allocation_id, declaration_alias_revision) =
        allocate_relationship_projection_revision(&pool).await;
    let declaration_alias_projection = fixture_uuid(407);
    let mut declaration_alias = pool
        .begin()
        .await
        .expect("begin declaration revision-alias probe");
    sqlx::query(
        r#"
        INSERT INTO chat.relationship_projection_snapshots(
            projection_id,projection_revision,operation_scope,canonical_did_set_bytes,
            canonical_did_set_sha256,scope_digest,appview_base,configuration_fingerprint,
            aggregate_evidence_bytes,aggregate_evidence_sha256,source_call_count,
            evidence_kind,started_at,completed_at,projection_allocation_id
        ) VALUES($1,$2,'creation',$3,$4,$5,'https://appview.example.net',$6,$7,$8,2,'live',$9,$9,$10)
        "#,
    )
    .bind(declaration_alias_projection)
    .bind(declaration_alias_revision)
    .bind(&canonical_dids)
    .bind(Sha256::digest(&canonical_dids).to_vec())
    .bind(vec![81_u8; 32])
    .bind(vec![82_u8; 32])
    .bind(&aggregate_evidence)
    .bind(Sha256::digest(&aggregate_evidence).to_vec())
    .bind(&projection_at)
    .bind(declaration_alias_allocation_id)
    .execute(&mut *declaration_alias)
    .await
    .expect("insert declaration revision-alias snapshot");
    sqlx::query(
        r#"
        INSERT INTO chat.relationship_projection_declarations(
            projection_id,recipient_did,resolved_pds_origin,service_id,fetch_revision,
            did_request_digest,did_document_digest,record_request_digest,
            record_response_digest,record_evidence_kind,incoming_policy,
            allow_group_invites,resolved_group_policy,evidence_kind,fetched_at
        ) VALUES($1,$2,'https://pds.example.net','#atproto_pds',$3,$4,$5,$6,$7,
                 'structuredRecordNotFound','following',NULL,'following','live',$8)
        "#,
    )
    .bind(declaration_alias_projection)
    .bind(other_principal)
    .bind(declaration_alias_revision)
    .bind(vec![83_u8; 32])
    .bind(vec![84_u8; 32])
    .bind(vec![85_u8; 32])
    .bind(vec![86_u8; 32])
    .bind(&projection_at)
    .execute(&mut *declaration_alias)
    .await
    .expect("queue declaration child reusing snapshot revision");
    let declaration_alias_error = declaration_alias
        .commit()
        .await
        .expect_err("declaration fetch revision cannot equal snapshot revision");
    assert!(
        declaration_alias_error
            .to_string()
            .contains("relationship projection evidence mismatch"),
        "unexpected declaration revision-alias failure: {declaration_alias_error:?}"
    );
    let declaration_alias_residue: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM chat.relationship_projection_snapshots WHERE projection_id=$1)",
    )
    .bind(declaration_alias_projection)
    .fetch_one(&pool)
    .await
    .expect("inspect declaration revision-alias residue");
    assert!(
        !declaration_alias_residue,
        "failed declaration alias left durable residue"
    );

    let (invalid_declaration_allocation_id, invalid_declaration_revision) =
        allocate_relationship_projection_revision(&pool).await;
    let invalid_declaration_projection = fixture_uuid(404);
    let mut invalid_declaration = pool
        .begin()
        .await
        .expect("begin invalid declaration policy probe");
    sqlx::query(
        r#"
        INSERT INTO chat.relationship_projection_snapshots(
            projection_id,projection_revision,operation_scope,canonical_did_set_bytes,
            canonical_did_set_sha256,scope_digest,appview_base,configuration_fingerprint,
            aggregate_evidence_bytes,aggregate_evidence_sha256,source_call_count,
            evidence_kind,started_at,completed_at,projection_allocation_id
        ) VALUES($1,$2,'creation',$3,$4,$5,'https://appview.example.net',$6,$7,$8,2,'live',$9,$9,$10)
        "#,
    )
    .bind(invalid_declaration_projection)
    .bind(invalid_declaration_revision)
    .bind(&canonical_dids)
    .bind(Sha256::digest(&canonical_dids).to_vec())
    .bind(vec![59_u8; 32])
    .bind(vec![60_u8; 32])
    .bind(&aggregate_evidence)
    .bind(Sha256::digest(&aggregate_evidence).to_vec())
    .bind(&projection_at)
    .bind(invalid_declaration_allocation_id)
    .execute(&mut *invalid_declaration)
    .await
    .expect("insert invalid-declaration projection snapshot");
    let wrong_resolved_policy = sqlx::query(
        r#"
        INSERT INTO chat.relationship_projection_declarations(
            projection_id,recipient_did,resolved_pds_origin,service_id,fetch_revision,
            did_request_digest,did_document_digest,record_request_digest,
            record_response_digest,record_cid,record_evidence_kind,incoming_policy,
            allow_group_invites,resolved_group_policy,evidence_kind,fetched_at
        ) VALUES($1,$2,'https://pds.example.net','#atproto_pds',104,$3,$4,$5,$6,$7,
                 'recordPresent','following',NULL,'none','live',$8)
        "#,
    )
    .bind(invalid_declaration_projection)
    .bind(other_principal)
    .bind(vec![67_u8; 32])
    .bind(vec![68_u8; 32])
    .bind(vec![69_u8; 32])
    .bind(vec![70_u8; 32])
    .bind("fixture-cid")
    .bind(&projection_at)
    .execute(&mut *invalid_declaration)
    .await
    .expect_err("resolved policy must equal explicit/defaulted declaration policy");
    assert_eq!(
        wrong_resolved_policy
            .as_database_error()
            .and_then(|error| error.constraint()),
        Some("relationship_projection_declarations_policy_check")
    );
    invalid_declaration
        .rollback()
        .await
        .expect("roll back invalid declaration probe");

    let request_bytes = vec![61_u8; 8];
    let request_transcript = vec![62_u8; 8];
    let request_digest = Sha256::digest(&request_transcript).to_vec();
    let response_bytes = vec![63_u8; 8];
    let completed_at: DateTime<Utc> = sqlx::query_scalar("SELECT clock_timestamp()")
        .fetch_one(&pool)
        .await
        .expect("capture idempotency completion time");
    sqlx::query(
        r#"
        INSERT INTO chat.idempotency_records(
            principal_did,endpoint_nsid,operation_id,request_digest,
            accepted_request_bytes,signing_transcript_bytes,signature,completed_status,
            response_bytes,response_sha256,completed_at
        ) VALUES($1,'blue.catbird.chat.requestReset',$2,$3,$4,$5,$6,202,$7,$8,$9)
        "#,
    )
    .bind(principal)
    .bind(fixture_uuid(500))
    .bind(&request_digest)
    .bind(&request_bytes)
    .bind(&request_transcript)
    .bind(vec![64_u8; 64])
    .bind(&response_bytes)
    .bind(Sha256::digest(&response_bytes).to_vec())
    .bind(&completed_at)
    .execute(&pool)
    .await
    .expect("insert admitted idempotency receipt");

    let excluded_endpoint = sqlx::query(
        r#"
        INSERT INTO chat.idempotency_records(
            principal_did,endpoint_nsid,operation_id,request_digest,
            accepted_request_bytes,signing_transcript_bytes,signature,completed_status,
            response_bytes,response_sha256,completed_at
        ) VALUES($1,'blue.catbird.chat.sendMessage',$2,$3,$4,$5,$6,200,$7,$8,$9)
        "#,
    )
    .bind(principal)
    .bind(fixture_uuid(501))
    .bind(&request_digest)
    .bind(&request_bytes)
    .bind(&request_transcript)
    .bind(vec![65_u8; 64])
    .bind(&response_bytes)
    .bind(Sha256::digest(&response_bytes).to_vec())
    .bind(&completed_at)
    .execute(&pool)
    .await
    .expect_err("non-idempotent sendMessage endpoint must reject generic receipts");
    assert_eq!(
        excluded_endpoint
            .as_database_error()
            .and_then(|error| error.constraint()),
        Some("idempotency_records_endpoint_check")
    );

    let mismatched_digest = sqlx::query(
        r#"
        INSERT INTO chat.idempotency_records(
            principal_did,endpoint_nsid,operation_id,request_digest,
            accepted_request_bytes,signing_transcript_bytes,signature,completed_status,
            response_bytes,response_sha256,completed_at
        ) VALUES($1,'blue.catbird.chat.requestReset',$2,$3,$4,$5,$6,200,$7,$8,$9)
        "#,
    )
    .bind(principal)
    .bind(fixture_uuid(502))
    .bind(vec![0_u8; 32])
    .bind(&request_bytes)
    .bind(&request_transcript)
    .bind(vec![66_u8; 64])
    .bind(&response_bytes)
    .bind(Sha256::digest(&response_bytes).to_vec())
    .bind(&completed_at)
    .execute(&pool)
    .await
    .expect_err("idempotency digest mismatch must reject");
    assert_eq!(
        mismatched_digest
            .as_database_error()
            .and_then(|error| error.constraint()),
        Some("idempotency_records_hashes_check")
    );

    let blob_id = fixture_uuid(600);
    let blob_hash = vec![71_u8; 32];
    let blob_at: DateTime<Utc> = sqlx::query_scalar("SELECT clock_timestamp()")
        .fetch_one(&pool)
        .await
        .expect("capture blob admission time");
    let blob_expiry = blob_at + Duration::minutes(5);
    let mut blob = pool.begin().await.expect("begin prepared blob graph");
    sqlx::query(
        r#"
        INSERT INTO chat.blob_usage(
            user_did,used_ciphertext_bytes,reserved_ciphertext_bytes,
            live_unbound_count,blob_count,updated_at
        ) VALUES($1,0,17,1,1,$2)
        "#,
    )
    .bind(principal)
    .bind(&blob_at)
    .execute(&mut *blob)
    .await
    .expect("insert exact blob usage counters");
    sqlx::query(
        r#"
        INSERT INTO chat.blobs(
            blob_id,owner_did,owner_device_id,owner_key_id,owner_auth_generation,
            purpose,media_type,plaintext_size,ciphertext_size,ciphertext_sha256,
            status,prepared_at,upload_expires_at
        ) VALUES($1,$2,$3,$4,1,'attachment','image/jpeg',1,17,$5,'prepared',$6,$7)
        "#,
    )
    .bind(blob_id)
    .bind(principal)
    .bind(actor_device_id)
    .bind(&actor_key_id)
    .bind(&blob_hash)
    .bind(&blob_at)
    .bind(&blob_expiry)
    .execute(&mut *blob)
    .await
    .expect("insert prepared blob");
    sqlx::query(
        r#"
        INSERT INTO chat.blob_upload_tickets(
            ticket_hash,blob_id,owner_did,owner_device_id,created_at,expires_at
        ) VALUES($1,$2,$3,$4,$5,$6)
        "#,
    )
    .bind(vec![72_u8; 32])
    .bind(blob_id)
    .bind(principal)
    .bind(actor_device_id)
    .bind(&blob_at)
    .bind(&blob_expiry)
    .execute(&mut *blob)
    .await
    .expect("insert exact blob upload ticket");
    blob.commit().await.expect("commit prepared blob graph");

    let second_blob_id = fixture_uuid(601);
    let mut spliced_ticket = pool.begin().await.expect("begin blob ticket splice");
    sqlx::query(
        "UPDATE chat.blob_usage SET reserved_ciphertext_bytes=34,live_unbound_count=2,blob_count=2,updated_at=$2 WHERE user_did=$1",
    )
    .bind(principal)
    .bind(&blob_at)
    .execute(&mut *spliced_ticket)
    .await
    .expect("queue exact counters for second prepared blob");
    sqlx::query(
        r#"
        INSERT INTO chat.blobs(
            blob_id,owner_did,owner_device_id,owner_key_id,owner_auth_generation,
            purpose,media_type,plaintext_size,ciphertext_size,ciphertext_sha256,
            status,prepared_at,upload_expires_at
        ) VALUES($1,$2,$3,$4,1,'attachment','image/png',1,17,$5,'prepared',$6,$7)
        "#,
    )
    .bind(second_blob_id)
    .bind(principal)
    .bind(actor_device_id)
    .bind(&actor_key_id)
    .bind(vec![73_u8; 32])
    .bind(&blob_at)
    .bind(&blob_expiry)
    .execute(&mut *spliced_ticket)
    .await
    .expect("insert second prepared blob");
    let ticket_splice_error = sqlx::query(
        r#"
        INSERT INTO chat.blob_upload_tickets(
            ticket_hash,blob_id,owner_did,owner_device_id,created_at,expires_at
        ) VALUES($1,$2,$3,$4,$5,$6)
        "#,
    )
    .bind(vec![74_u8; 32])
    .bind(second_blob_id)
    .bind(principal)
    .bind(third_device_id)
    .bind(&blob_at)
    .bind(&blob_expiry)
    .execute(&mut *spliced_ticket)
    .await
    .expect_err("ticket cannot splice a sibling device onto a blob");
    assert_eq!(
        ticket_splice_error
            .as_database_error()
            .and_then(|error| error.constraint()),
        Some("blob_upload_tickets_blob_owner_fk")
    );
    spliced_ticket
        .rollback()
        .await
        .expect("roll back blob ticket splice");

    let mut usage_drift = pool.begin().await.expect("begin usage drift probe");
    sqlx::query(
        "UPDATE chat.blob_usage SET reserved_ciphertext_bytes=18,updated_at=$2 WHERE user_did=$1",
    )
    .bind(principal)
    .bind(&blob_at)
    .execute(&mut *usage_drift)
    .await
    .expect("queue incorrect usage counters");
    // The per-row structural guard no longer re-derives counters from owner
    // history, so drifted counters now survive commit; the authoritative O(n)
    // rescan moved to the periodic chat.reconcile_blob_usage sweep, which must
    // reject the inconsistency when it runs.
    usage_drift
        .commit()
        .await
        .expect("structural guard permits committed usage drift");
    let reconcile_drift = sqlx::query("SELECT chat.reconcile_blob_usage($1)")
        .bind(principal)
        .execute(&pool)
        .await
        .expect_err("periodic reconciliation must reject drifted usage counters");
    assert!(
        reconcile_drift
            .to_string()
            .contains("blob usage counters disagree with authoritative blobs"),
        "authoritative blob rows must reconcile usage counters"
    );
    // Restoring the authoritative counter makes the same sweep pass, proving the
    // probe detects genuine drift rather than always failing.
    sqlx::query(
        "UPDATE chat.blob_usage SET reserved_ciphertext_bytes=17,updated_at=$2 WHERE user_did=$1",
    )
    .bind(principal)
    .bind(&blob_at)
    .execute(&pool)
    .await
    .expect("restore authoritative usage counters");
    sqlx::query("SELECT chat.reconcile_blob_usage($1)")
        .bind(principal)
        .execute(&pool)
        .await
        .expect("reconciliation passes once counters match authoritative blobs");

    let immutable_blob = sqlx::query("UPDATE chat.blobs SET ciphertext_size=18 WHERE blob_id=$1")
        .bind(blob_id)
        .execute(&pool)
        .await
        .expect_err("blob cryptographic identity must be immutable");
    assert!(immutable_blob
        .to_string()
        .contains("immutable chat identity/provenance changed"));

    let pgcrypto_schema: String = sqlx::query_scalar(
        r#"
        SELECT n.nspname
          FROM pg_extension e JOIN pg_namespace n ON n.oid=e.extnamespace
         WHERE e.extname='pgcrypto'
        "#,
    )
    .fetch_one(&pool)
    .await
    .expect("read pgcrypto placement");
    assert_eq!(pgcrypto_schema, "public");

    let legacy_objects: Vec<String> = sqlx::query_scalar(
        r#"
        SELECT object_name FROM (
            SELECT c.relname AS object_name
              FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
             WHERE n.nspname='chat'
            UNION ALL
            SELECT p.proname
              FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace
             WHERE n.nspname='chat'
        ) objects
        WHERE lower(object_name) LIKE '%v2%'
           OR lower(object_name) LIKE '%mlschat%'
           OR lower(object_name) LIKE '%mls_chat%'
        ORDER BY object_name
        "#,
    )
    .fetch_all(&pool)
    .await
    .expect("inspect legacy-branded catalog objects");
    assert!(
        legacy_objects.is_empty(),
        "legacy-branded objects: {legacy_objects:?}"
    );
}
