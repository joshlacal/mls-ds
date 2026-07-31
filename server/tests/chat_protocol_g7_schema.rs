//! G7 inventory-entitlement schema and forward-migration contract.
//!
//! The source-level test is the first TDD gate: it names the durable authority
//! shapes that the forward migration must install. The live tests below it
//! exercise those shapes through PostgreSQL rather than trusting SQL text.

mod common;

use std::path::{Path, PathBuf};

use chrono::{DateTime, Utc};
use uuid::Uuid;

const G7_MIGRATION: &str = "20260729000001_chat_g7_inventory_entitlement.sql";

fn migration_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("migrations")
}

fn g7_sql() -> String {
    std::fs::read_to_string(migration_dir().join(G7_MIGRATION))
        .unwrap_or_else(|error| panic!("read {G7_MIGRATION}: {error}"))
}

fn compact_sql(sql: &str) -> String {
    sql.split_whitespace().collect::<Vec<_>>().join(" ")
}

#[test]
fn g7_migration_declares_hash_only_entitlement_and_replay_schema() {
    // Mutations caught by this test:
    // - removing any exact source-provenance coordinate,
    // - retaining a plaintext event cursor,
    // - collapsing materialization-complete and client-consumed state,
    // - omitting either random-capability receipt table,
    // - weakening the insert-time precedence and immutable-history boundary.
    let sql = g7_sql();
    let compact = compact_sql(&sql);

    for required in [
        "ADD COLUMN item_kind TEXT",
        "ADD COLUMN participant_period_id UUID",
        "ADD COLUMN membership_interval_id UUID",
        "ADD COLUMN interval_terminal_seq BIGINT",
        "ADD COLUMN interval_closing_transition_id UUID",
        "ADD COLUMN interval_closing_outer_entry_fingerprint BYTEA",
        "ADD COLUMN interval_removed_at TIMESTAMPTZ",
        "ADD COLUMN protocol_instance_id UUID",
        "ADD COLUMN cursor_key_id TEXT",
        "ADD COLUMN cursor_format_version SMALLINT NOT NULL DEFAULT 1",
        "ADD COLUMN snapshot_retained_floor BIGINT",
        "ADD COLUMN conversation_payload_bytes BIGINT",
        "ADD COLUMN welcome_payload_bytes BIGINT",
        "ADD COLUMN recovery_payload_bytes BIGINT",
        "ADD COLUMN conversations_consumed BOOLEAN NOT NULL DEFAULT FALSE",
        "ADD COLUMN welcomes_consumed BOOLEAN NOT NULL DEFAULT FALSE",
        "ADD COLUMN recovery_consumed BOOLEAN NOT NULL DEFAULT FALSE",
        "ADD COLUMN conversations_consumed_at TIMESTAMPTZ",
        "ADD COLUMN welcomes_consumed_at TIMESTAMPTZ",
        "ADD COLUMN recovery_consumed_at TIMESTAMPTZ",
        "ADD COLUMN snapshot_event_cursor_nonce BYTEA",
        "ADD COLUMN snapshot_event_cursor_ciphertext BYTEA",
        "ADD COLUMN legacy_cursor_invalidated_at TIMESTAMPTZ",
        "CREATE TABLE chat.inventory_page_receipts",
        "CREATE TABLE chat.event_cursor_receipts",
        "successor_cursor_nonce BYTEA",
        "successor_cursor_ciphertext BYTEA",
        "cursor_nonce BYTEA NOT NULL",
        "cursor_ciphertext BYTEA NOT NULL",
        "canonical_envelope_sha256 BYTEA",
        "CREATE FUNCTION chat.validate_inventory_conversation_item_source()",
        "CREATE TRIGGER inventory_conversation_items_source_precedence",
        "CONSTRAINT inventory_page_receipts_request_boundary_fk FOREIGN KEY",
        "CREATE FUNCTION chat.validate_inventory_page_receipt_boundary()",
        "CREATE TRIGGER inventory_page_receipts_boundary",
        "CREATE FUNCTION chat.validate_event_cursor_receipt_chain()",
        "CREATE TRIGGER event_cursor_receipts_chain",
        "CREATE OR REPLACE FUNCTION chat.assert_inventory_materialization(target_session UUID)",
        "CREATE FUNCTION chat.enforce_inventory_consumption_monotonic()",
        "CREATE TRIGGER inventory_sessions_consumption_monotonic",
        "CREATE INDEX participants_current_user_conversation_idx",
        "snapshot_event_cursor_nonce IS NOT NULL",
        "snapshot_event_cursor_ciphertext IS NOT NULL",
        "conversations_consumed_at IS NOT NULL",
        "welcomes_consumed_at IS NOT NULL",
        "recovery_consumed_at IS NOT NULL",
        "served_at IS NOT NULL",
        "ticket_row.protocol_instance_id IS DISTINCT FROM session_row.protocol_instance_id",
        "ticket_row.cursor_key_id IS DISTINCT FROM session_row.cursor_key_id",
        "ticket_row.snapshot_retained_floor IS DISTINCT FROM session_row.snapshot_retained_floor",
        "participant.invitation_transition_id IS NULL",
        "conversation_row.kind = 'group'",
        "proof.received_at <= session_row.created_at",
        "ORDER BY finite_interval.start_seq DESC, finite_interval.membership_interval_id DESC",
        "later.removed_at IS NULL OR later.removed_at > session_row.created_at",
        "ROW( later.start_seq, later.membership_interval_id ) > ROW( exact_interval.start_seq, exact_interval.membership_interval_id )",
        "has_more IS TRUE",
        "has_more IS FALSE",
        "conversations_consumed IS TRUE",
        "conversations_consumed IS FALSE",
        "welcomes_consumed IS TRUE",
        "welcomes_consumed IS FALSE",
        "recovery_consumed IS TRUE",
        "recovery_consumed IS FALSE",
        "receipt.has_more IS FALSE",
    ] {
        assert!(
            compact.contains(required),
            "G7 migration is missing locked schema fragment: {required}"
        );
    }

    for tag in [
        "blue.catbird.chat.defs#conversationInventoryState",
        "blue.catbird.chat.defs#conversationRemovalTombstone",
        "blue.catbird.chat.defs#conversationCloseTombstone",
    ] {
        assert!(sql.contains(tag), "missing exact inventory arm tag {tag}");
    }

    assert!(
        compact.contains("DROP COLUMN snapshot_event_cursor_bytes"),
        "G7 must remove the legacy plaintext snapshot cursor"
    );
    assert!(
        compact.contains("DROP COLUMN event_cursor_bytes"),
        "G7 must remove the legacy plaintext ticket cursor"
    );
    assert!(
        !compact.contains("CREATE TABLE chat.inventory_page_receipts ( plaintext")
            && !compact.contains("CREATE TABLE chat.event_cursor_receipts ( plaintext"),
        "receipt tables must not introduce plaintext capability columns"
    );
    let removal_branch = compact
        .split("ELSIF NEW.item_kind = 'blue.catbird.chat.defs#conversationRemovalTombstone'")
        .nth(1)
        .expect("removal source-precedence branch")
        .split("ELSIF NEW.item_kind = 'blue.catbird.chat.defs#conversationInventoryState'")
        .next()
        .expect("bounded removal source-precedence branch");
    assert!(
        !removal_branch.contains("later.start_seq >= NEW.interval_terminal_seq"),
        "removal precedence must never compare a later start to the prior terminal sequence"
    );
    for forbidden_nullable_boolean in [
        "NOT conversations_consumed",
        "NOT welcomes_consumed",
        "NOT recovery_consumed",
        "NOT NEW.conversations_complete",
        "NOT NEW.welcomes_complete",
        "NOT NEW.recovery_complete",
        "receipt.has_more = FALSE",
    ] {
        assert!(
            !compact.contains(forbidden_nullable_boolean),
            "G7 receipt/consumption authority retained nullable boolean coercion: \
             {forbidden_nullable_boolean}"
        );
    }
}

#[derive(Clone, Copy)]
struct RemovalInterval {
    start_seq: i64,
    membership_interval_id: Uuid,
    finite_at_snapshot: bool,
    valid_at_snapshot: bool,
}

fn removal_interval_is_authoritative(
    candidate: RemovalInterval,
    intervals: &[RemovalInterval],
) -> bool {
    let latest_finite = intervals
        .iter()
        .filter(|interval| interval.finite_at_snapshot)
        .max_by_key(|interval| (interval.start_seq, interval.membership_interval_id));
    latest_finite.is_some_and(|latest| {
        latest.membership_interval_id == candidate.membership_interval_id
            && !intervals.iter().any(|later| {
                later.valid_at_snapshot
                    && (later.start_seq, later.membership_interval_id)
                        > (candidate.start_seq, candidate.membership_interval_id)
            })
    })
}

#[test]
fn g7_removal_precedence_uses_latest_finite_start_and_uuid_tie_break() {
    let lower = RemovalInterval {
        start_seq: 9,
        membership_interval_id: Uuid::from_u128(1),
        finite_at_snapshot: true,
        valid_at_snapshot: false,
    };
    let higher_same_start = RemovalInterval {
        start_seq: 9,
        membership_interval_id: Uuid::from_u128(2),
        finite_at_snapshot: true,
        valid_at_snapshot: false,
    };
    assert!(!removal_interval_is_authoritative(
        lower,
        &[lower, higher_same_start]
    ));
    assert!(removal_interval_is_authoritative(
        higher_same_start,
        &[lower, higher_same_start]
    ));

    let open_readd_before_snapshot = RemovalInterval {
        start_seq: 10,
        membership_interval_id: Uuid::from_u128(3),
        finite_at_snapshot: false,
        valid_at_snapshot: true,
    };
    assert!(!removal_interval_is_authoritative(
        higher_same_start,
        &[lower, higher_same_start, open_readd_before_snapshot],
    ));

    let open_readd_after_snapshot = RemovalInterval {
        valid_at_snapshot: false,
        ..open_readd_before_snapshot
    };
    assert!(removal_interval_is_authoritative(
        higher_same_start,
        &[lower, higher_same_start, open_readd_after_snapshot],
    ));
}

#[test]
fn g7_interval_negative_exercises_the_installed_validator() {
    let test_source = std::fs::read_to_string(
        Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/chat_protocol_g7_schema.rs"),
    )
    .expect("read G7 schema test source");
    for required in [
        "INSERT INTO chat.inventory_conversation_items",
        "'chat.validate_inventory_conversation_item_source()'::regprocedure",
        "inventory_conversation_items_source_precedence",
        "chat.inventory_conversation_items_interval_source_fk IMMEDIATE",
        "ROLLBACK TO SAVEPOINT installed_interval_case",
    ] {
        assert!(
            test_source.contains(required),
            "installed-validator proof is missing source fragment: {required}"
        );
    }
    for forbidden in [
        ["actual_sql_", "removal_authority"].concat(),
        ["FROM ", "unnest("].concat(),
    ] {
        assert!(
            !test_source.contains(&forbidden),
            "G7 interval negative retained a duplicate authority algorithm: {forbidden}"
        );
    }
}

#[derive(Clone)]
struct InstalledValidatorFixture {
    session_id: Uuid,
    conversation_id: Uuid,
    participant_period_id: Uuid,
    recipient_did: String,
    recipient_device_id: Uuid,
    leaf_key_id: String,
    leaf_signature_key: Vec<u8>,
    group_id: Vec<u8>,
    snapshot: DateTime<Utc>,
}

#[derive(Clone, Copy)]
struct InstalledInterval {
    membership_interval_id: Uuid,
    start_seq: i64,
    created_at: DateTime<Utc>,
    removed_at: Option<DateTime<Utc>>,
}

#[derive(Clone)]
struct InstalledIntervalSource {
    membership_interval_id: Uuid,
    terminal_seq: i64,
    closing_transition_id: Uuid,
    closing_outer_entry_fingerprint: Vec<u8>,
    removed_at: DateTime<Utc>,
}

async fn seed_installed_validator_fixture(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
) -> InstalledValidatorFixture {
    sqlx::query("SET CONSTRAINTS ALL DEFERRED")
        .execute(&mut **transaction)
        .await
        .expect("defer unrelated graph constraints inside rollback fixture");
    let snapshot: DateTime<Utc> =
        sqlx::query_scalar("SELECT date_trunc('milliseconds',clock_timestamp())")
            .fetch_one(&mut **transaction)
            .await
            .expect("sample installed-validator snapshot");
    let protocol: Option<(Uuid, String)> = sqlx::query_as(
        "SELECT protocol_instance_id,cursor_key_id \
         FROM chat.protocol_instances WHERE singleton FOR SHARE",
    )
    .fetch_optional(&mut **transaction)
    .await
    .expect("read installed protocol singleton");
    let (protocol_instance_id, cursor_key_id) = if let Some(protocol) = protocol {
        protocol
    } else {
        let protocol_instance_id = Uuid::new_v4();
        let cursor_key_id = "A".repeat(43);
        sqlx::query(
            "INSERT INTO chat.protocol_instances(\
                singleton,protocol_version,protocol_instance_id,cursor_key_id,created_at\
             ) VALUES(TRUE,'1',$1,$2,$3)",
        )
        .bind(protocol_instance_id)
        .bind(&cursor_key_id)
        .bind(snapshot)
        .execute(&mut **transaction)
        .await
        .expect("insert rollback-only protocol singleton");
        (protocol_instance_id, cursor_key_id)
    };
    let retained_floor: Option<i64> = sqlx::query_scalar(
        "SELECT retained_floor FROM chat.event_retention \
         WHERE protocol_instance_id=$1 FOR SHARE",
    )
    .bind(protocol_instance_id)
    .fetch_optional(&mut **transaction)
    .await
    .expect("read installed retention fence");
    let retained_floor = retained_floor.unwrap_or(0);
    if retained_floor == 0 {
        sqlx::query(
            "INSERT INTO chat.event_retention(\
                protocol_instance_id,retained_floor,updated_at\
             ) VALUES($1,0,$2) ON CONFLICT (protocol_instance_id) DO NOTHING",
        )
        .bind(protocol_instance_id)
        .bind(snapshot)
        .execute(&mut **transaction)
        .await
        .expect("insert rollback-only retention fence");
    }

    let recipient_did = format!("did:web:g7-interval-{}.example.com", Uuid::new_v4());
    let recipient_device_id = Uuid::new_v4();
    let leaf_signature_key = vec![7; 32];
    let leaf_key_id: String = sqlx::query_scalar("SELECT chat.ed25519_key_id($1)")
        .bind(&leaf_signature_key)
        .fetch_one(&mut **transaction)
        .await
        .expect("derive rollback-only fixture key id");
    sqlx::query("INSERT INTO chat.principals(user_did,created_at) VALUES($1,$2)")
        .bind(&recipient_did)
        .bind(snapshot - chrono::Duration::seconds(100))
        .execute(&mut **transaction)
        .await
        .expect("insert rollback-only principal");
    sqlx::query(
        "INSERT INTO chat.devices(\
            user_did,device_id,device_name,status,dpop_jkt,auth_generation,\
            capabilities,created_at,updated_at\
         ) VALUES($1,$2,'g7-installed-validator','active',$3,1,\
                  chat.protocol_capabilities(),$4,$4)",
    )
    .bind(&recipient_did)
    .bind(recipient_device_id)
    .bind(&leaf_key_id)
    .bind(snapshot - chrono::Duration::seconds(100))
    .execute(&mut **transaction)
    .await
    .expect("insert rollback-only device");
    sqlx::query(
        "INSERT INTO chat.device_keys(\
            user_did,device_id,key_id,signing_public_key,\
            enrollment_auth_generation,created_at\
         ) VALUES($1,$2,$3,$4,1,$5)",
    )
    .bind(&recipient_did)
    .bind(recipient_device_id)
    .bind(&leaf_key_id)
    .bind(&leaf_signature_key)
    .bind(snapshot - chrono::Duration::seconds(100))
    .execute(&mut **transaction)
    .await
    .expect("insert rollback-only device key");

    let conversation_id = Uuid::new_v4();
    let group_id = vec![8; 32];
    sqlx::query(
        "INSERT INTO chat.conversations(\
            conversation_id,kind,lifecycle,current_generation,\
            current_state_version,next_entry_seq,created_at\
         ) VALUES($1,'group','active',0,0,100,$2)",
    )
    .bind(conversation_id)
    .bind(snapshot - chrono::Duration::seconds(100))
    .execute(&mut **transaction)
    .await
    .expect("insert rollback-only conversation");
    sqlx::query(
        "INSERT INTO chat.generations(\
            conversation_id,generation,group_id,lifecycle,\
            genesis_group_info_bytes,genesis_group_info_sha256,\
            current_state_version,activated_seq,activated_at\
         ) VALUES($1,0,$2,'active',$3,digest($3,'sha256'),0,1,$4)",
    )
    .bind(conversation_id)
    .bind(&group_id)
    .bind(vec![9u8; 8])
    .bind(snapshot - chrono::Duration::seconds(100))
    .execute(&mut **transaction)
    .await
    .expect("insert rollback-only generation");
    let participant_period_id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO chat.participants(\
            participant_period_id,conversation_id,user_did,status,role,\
            role_transition_id,role_changed_at,created_by_did,\
            created_by_device_id,current_membership,created_at\
         ) VALUES($1,$2,$3,'active','admin',$4,$5,$3,$6,TRUE,$5)",
    )
    .bind(participant_period_id)
    .bind(conversation_id)
    .bind(&recipient_did)
    .bind(Uuid::new_v4())
    .bind(snapshot - chrono::Duration::seconds(100))
    .bind(recipient_device_id)
    .execute(&mut **transaction)
    .await
    .expect("insert rollback-only participant");

    let session_id = Uuid::new_v4();
    let snapshot_event_position = retained_floor.max(100);
    sqlx::query(
        "INSERT INTO chat.inventory_sessions(\
            inventory_session_id,token_hash,user_did,device_id,jkt,\
            auth_generation,snapshot_event_position,\
            snapshot_event_cursor_sha256,created_at,expires_at,\
            protocol_instance_id,cursor_key_id,snapshot_retained_floor,\
            snapshot_event_cursor_nonce,snapshot_event_cursor_ciphertext\
         ) VALUES($1,$2,$3,$4,$5,1,$6,$7,$8,$8 + interval '10 minutes',\
                  $9,$10,$11,$12,$13)",
    )
    .bind(session_id)
    .bind(vec![10u8; 32])
    .bind(&recipient_did)
    .bind(recipient_device_id)
    .bind(&leaf_key_id)
    .bind(snapshot_event_position)
    .bind(vec![11u8; 32])
    .bind(snapshot)
    .bind(protocol_instance_id)
    .bind(&cursor_key_id)
    .bind(retained_floor)
    .bind(vec![12u8; 12])
    .bind(vec![13u8])
    .execute(&mut **transaction)
    .await
    .expect("insert rollback-only inventory session");

    InstalledValidatorFixture {
        session_id,
        conversation_id,
        participant_period_id,
        recipient_did,
        recipient_device_id,
        leaf_key_id,
        leaf_signature_key,
        group_id,
        snapshot,
    }
}

async fn insert_installed_interval(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    fixture: &InstalledValidatorFixture,
    interval: InstalledInterval,
) -> Option<InstalledIntervalSource> {
    let leaf_period_id = Uuid::new_v4();
    let closing_transition_id = interval.removed_at.map(|_| Uuid::new_v4());
    let terminal_seq = interval.removed_at.map(|_| interval.start_seq + 1);
    let closing_state_version = interval.removed_at.map(|_| interval.start_seq * 2 + 1);
    let closing_outer_entry_fingerprint = interval.removed_at.map(|_| vec![15; 32]);
    let active = interval.removed_at.is_none();
    let basic_credential =
        format!("{}#{}", fixture.recipient_did, fixture.recipient_device_id).into_bytes();
    sqlx::query(
        "INSERT INTO chat.member_devices(\
            leaf_period_id,participant_period_id,conversation_id,generation,\
            user_did,device_id,leaf_index,basic_credential,leaf_signature_key,\
            leaf_key_id,leaf_auth_generation,origin,joined_state_version,\
            joined_transition_id,joined_seq,removed_state_version,\
            removed_transition_id,removed_seq,removed_at,active,created_at\
         ) VALUES($1,$2,$3,0,$4,$5,$6,$7,$8,$9,1,'genesis',$10,$11,$12,\
                  $13,$14,$15,$16,$17,$18)",
    )
    .bind(leaf_period_id)
    .bind(fixture.participant_period_id)
    .bind(fixture.conversation_id)
    .bind(&fixture.recipient_did)
    .bind(fixture.recipient_device_id)
    .bind(interval.start_seq)
    .bind(basic_credential)
    .bind(&fixture.leaf_signature_key)
    .bind(&fixture.leaf_key_id)
    .bind(interval.start_seq * 2)
    .bind(interval.membership_interval_id)
    .bind(interval.start_seq)
    .bind(closing_state_version)
    .bind(closing_transition_id)
    .bind(terminal_seq)
    .bind(interval.removed_at)
    .bind(active)
    .bind(interval.created_at)
    .execute(&mut **transaction)
    .await
    .expect("insert rollback-only interval leaf");
    sqlx::query(
        "INSERT INTO chat.application_intervals(\
            membership_interval_id,conversation_id,generation,recipient_did,\
            recipient_device_id,start_seq,opening_kind,opening_transition_id,\
            opening_outer_entry_fingerprint,opening_state_version,\
            opening_group_id,opening_epoch,opening_group_context_hash,\
            opening_confirmation_tag,opening_leaf_period_id,terminal_seq,\
            closing_state_version,closing_transition_id,\
            closing_outer_entry_fingerprint,closing_kind,\
            closing_leaf_period_id,removed_at,created_at\
         ) VALUES($1,$2,0,$3,$4,$5,'add',$1,$6,$7,$8,$5,$9,$10,$11,$12,\
                  $13,$14,$15,$16,$17,$18,$19)",
    )
    .bind(interval.membership_interval_id)
    .bind(fixture.conversation_id)
    .bind(&fixture.recipient_did)
    .bind(fixture.recipient_device_id)
    .bind(interval.start_seq)
    .bind(vec![14u8; 32])
    .bind(interval.start_seq * 2)
    .bind(&fixture.group_id)
    .bind(vec![16u8; 32])
    .bind(vec![17u8; 32])
    .bind(leaf_period_id)
    .bind(terminal_seq)
    .bind(closing_state_version)
    .bind(closing_transition_id)
    .bind(closing_outer_entry_fingerprint.clone())
    .bind(interval.removed_at.map(|_| "remove"))
    .bind(interval.removed_at.map(|_| leaf_period_id))
    .bind(interval.removed_at)
    .bind(interval.created_at)
    .execute(&mut **transaction)
    .await
    .expect("insert rollback-only application interval");
    interval
        .removed_at
        .map(|removed_at| InstalledIntervalSource {
            membership_interval_id: interval.membership_interval_id,
            terminal_seq: terminal_seq.expect("finite interval terminal sequence"),
            closing_transition_id: closing_transition_id.expect("finite interval close transition"),
            closing_outer_entry_fingerprint: closing_outer_entry_fingerprint
                .expect("finite interval close fingerprint"),
            removed_at,
        })
}

async fn installed_interval_case(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    fixture: &InstalledValidatorFixture,
    intervals: &[InstalledInterval],
    candidate: Uuid,
    expect_authorized: bool,
    label: &str,
) {
    sqlx::query("SAVEPOINT installed_interval_case")
        .execute(&mut **transaction)
        .await
        .expect("create installed-interval savepoint");
    let mut candidate_source = None;
    for interval in intervals {
        let source = insert_installed_interval(transaction, fixture, *interval).await;
        if interval.membership_interval_id == candidate {
            candidate_source = source;
        }
    }
    let source = candidate_source.expect("removal candidate must be a finite interval");
    let result = sqlx::query(
        "INSERT INTO chat.inventory_conversation_items(\
            inventory_session_id,ordinal,conversation_id,recipient_did,\
            recipient_device_id,item_key_bytes,payload_bytes,payload_sha256,\
            item_kind,participant_period_id,membership_interval_id,\
            interval_terminal_seq,interval_closing_transition_id,\
            interval_closing_outer_entry_fingerprint,interval_removed_at\
         ) VALUES($1,0,$2,$3,$4,uuid_send($2),$5,digest($5,'sha256'),\
                  'blue.catbird.chat.defs#conversationRemovalTombstone',\
                  NULL,$6,$7,$8,$9,$10)",
    )
    .bind(fixture.session_id)
    .bind(fixture.conversation_id)
    .bind(&fixture.recipient_did)
    .bind(fixture.recipient_device_id)
    .bind(label.as_bytes())
    .bind(source.membership_interval_id)
    .bind(source.terminal_seq)
    .bind(source.closing_transition_id)
    .bind(&source.closing_outer_entry_fingerprint)
    .bind(source.removed_at)
    .execute(&mut **transaction)
    .await;
    if expect_authorized {
        result.unwrap_or_else(|error| panic!("{label} installed validator rejected: {error}"));
        sqlx::query(
            "SET CONSTRAINTS \
             chat.inventory_conversation_items_interval_source_fk IMMEDIATE",
        )
        .execute(&mut **transaction)
        .await
        .unwrap_or_else(|error| panic!("{label} exact source FK failed: {error}"));
    } else {
        let error = result.expect_err("installed validator must reject negative interval case");
        let database_error = error
            .as_database_error()
            .expect("installed validator rejection is a PostgreSQL error");
        assert_eq!(database_error.code().as_deref(), Some("23514"), "{label}");
        assert!(
            database_error
                .message()
                .contains("conversation removal inventory source or precedence mismatch"),
            "{label}: unexpected installed-validator classification: {}",
            database_error.message()
        );
    }
    sqlx::query("ROLLBACK TO SAVEPOINT installed_interval_case")
        .execute(&mut **transaction)
        .await
        .expect("roll back installed-interval case");
    sqlx::query(
        "SET CONSTRAINTS \
         chat.inventory_conversation_items_interval_source_fk DEFERRED",
    )
    .execute(&mut **transaction)
    .await
    .expect("restore source FK deferral after rollback-isolated case");
}

#[tokio::test]
async fn g7_installed_interval_validator_is_snapshot_bound_and_deterministic() {
    let pool = common::chat_protocol::setup_chat_protocol_db(1).await;
    let mut transaction = pool
        .begin()
        .await
        .expect("begin installed interval-validator probe");
    let fixture = seed_installed_validator_fixture(&mut transaction).await;
    let installed: (String, String, String, i16, String) = sqlx::query_as(
        r#"
        SELECT function_namespace.nspname,function_row.proname,
               pg_get_function_identity_arguments(function_row.oid),
               trigger_row.tgtype,trigger_row.tgenabled::text
          FROM pg_trigger trigger_row
          JOIN pg_class relation ON relation.oid=trigger_row.tgrelid
          JOIN pg_namespace relation_namespace
            ON relation_namespace.oid=relation.relnamespace
          JOIN pg_proc function_row ON function_row.oid=trigger_row.tgfoid
          JOIN pg_namespace function_namespace
            ON function_namespace.oid=function_row.pronamespace
         WHERE relation_namespace.nspname='chat'
           AND relation.relname='inventory_conversation_items'
           AND trigger_row.tgname='inventory_conversation_items_source_precedence'
           AND NOT trigger_row.tgisinternal
        "#,
    )
    .fetch_one(&mut *transaction)
    .await
    .expect("read installed interval-validator trigger");
    assert_eq!(
        installed,
        (
            "chat".to_owned(),
            "validate_inventory_conversation_item_source".to_owned(),
            "".to_owned(),
            7,
            "O".to_owned(),
        ),
        "test must exercise the enabled installed BEFORE INSERT ROW validator"
    );
    let function_definition: String = sqlx::query_scalar(
        "SELECT pg_get_functiondef('chat.validate_inventory_conversation_item_source()'::regprocedure)",
    )
    .fetch_one(&mut *transaction)
    .await
    .expect("read installed interval-validator definition");
    for authority_fragment in [
        "NEW.membership_interval_id IS DISTINCT FROM",
        "ORDER BY finite_interval.start_seq DESC",
        "finite_interval.membership_interval_id DESC",
        "later.created_at <= session_row.created_at",
    ] {
        assert!(
            function_definition.contains(authority_fragment),
            "installed interval validator omitted {authority_fragment}"
        );
    }

    let snapshot = fixture.snapshot;
    let low = Uuid::parse_str("11111111-1111-4111-8111-111111111101").unwrap();
    let high = Uuid::parse_str("11111111-1111-4111-8111-111111111102").unwrap();
    let open = Uuid::parse_str("11111111-1111-4111-8111-111111111103").unwrap();
    installed_interval_case(
        &mut transaction,
        &fixture,
        &[InstalledInterval {
            membership_interval_id: low,
            start_seq: 20,
            created_at: snapshot + chrono::Duration::seconds(1),
            removed_at: Some(snapshot + chrono::Duration::seconds(2)),
        }],
        low,
        false,
        "future-created interval",
    )
    .await;
    installed_interval_case(
        &mut transaction,
        &fixture,
        &[InstalledInterval {
            membership_interval_id: low,
            start_seq: 1,
            created_at: snapshot - chrono::Duration::seconds(3),
            removed_at: Some(snapshot + chrono::Duration::seconds(1)),
        }],
        low,
        false,
        "post-snapshot removal",
    )
    .await;
    let two_finite = [
        InstalledInterval {
            membership_interval_id: low,
            start_seq: 1,
            created_at: snapshot - chrono::Duration::seconds(9),
            removed_at: Some(snapshot - chrono::Duration::seconds(7)),
        },
        InstalledInterval {
            membership_interval_id: high,
            start_seq: 5,
            created_at: snapshot - chrono::Duration::seconds(5),
            removed_at: Some(snapshot - chrono::Duration::seconds(2)),
        },
    ];
    installed_interval_case(
        &mut transaction,
        &fixture,
        &two_finite,
        low,
        false,
        "older of two finite intervals",
    )
    .await;
    installed_interval_case(
        &mut transaction,
        &fixture,
        &two_finite,
        high,
        true,
        "latest of two finite intervals",
    )
    .await;
    installed_interval_case(
        &mut transaction,
        &fixture,
        &[
            two_finite[1],
            InstalledInterval {
                membership_interval_id: open,
                start_seq: 7,
                created_at: snapshot - chrono::Duration::seconds(1),
                removed_at: None,
            },
        ],
        high,
        false,
        "open re-add before snapshot",
    )
    .await;
    installed_interval_case(
        &mut transaction,
        &fixture,
        &[
            two_finite[1],
            InstalledInterval {
                membership_interval_id: open,
                start_seq: 7,
                created_at: snapshot + chrono::Duration::seconds(1),
                removed_at: None,
            },
        ],
        high,
        true,
        "open re-add after snapshot",
    )
    .await;
    let equal_start = [
        InstalledInterval {
            membership_interval_id: low,
            start_seq: 5,
            created_at: snapshot - chrono::Duration::seconds(7),
            removed_at: Some(snapshot - chrono::Duration::seconds(4)),
        },
        InstalledInterval {
            membership_interval_id: high,
            start_seq: 5,
            created_at: snapshot - chrono::Duration::seconds(6),
            removed_at: Some(snapshot - chrono::Duration::seconds(3)),
        },
    ];
    installed_interval_case(
        &mut transaction,
        &fixture,
        &equal_start,
        low,
        false,
        "equal-start lower UUID",
    )
    .await;
    installed_interval_case(
        &mut transaction,
        &fixture,
        &equal_start,
        high,
        true,
        "equal-start higher UUID",
    )
    .await;
    // Scoped narrower than `SET CONSTRAINTS ALL IMMEDIATE`: ALL would fire the
    // deferred provenance/contiguity/pointer constraint triggers queued by the
    // minimal seed fixture (deliberately not a full protocol graph), not just
    // the interval-validator constraints under test.
    sqlx::query(
        "SET CONSTRAINTS \
         chat.inventory_conversation_items_interval_source_fk, \
         chat.inventory_conversation_items_participant_source_fk IMMEDIATE",
    )
    .execute(&mut *transaction)
    .await
    .expect("force installed interval-validator constraints");
    transaction
        .rollback()
        .await
        .expect("roll back installed interval-validator probe without residue");
    pool.close().await;
}

async fn force_constraints_and_rollback(mut transaction: sqlx::Transaction<'_, sqlx::Postgres>) {
    sqlx::query("SET CONSTRAINTS ALL IMMEDIATE")
        .execute(&mut *transaction)
        .await
        .expect("force all deferred G7 constraints");
    transaction
        .rollback()
        .await
        .expect("roll back G7 schema probe");
}

async fn assert_page_receipt_shape_rejected(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    has_more: Option<bool>,
    successor_hash: Option<Vec<u8>>,
    successor_nonce: Option<Vec<u8>>,
    successor_ciphertext: Option<Vec<u8>>,
) {
    sqlx::query("SAVEPOINT malformed_page_receipt")
        .execute(&mut **transaction)
        .await
        .expect("create malformed-page-receipt savepoint");
    let error = sqlx::query(
        r#"
        WITH fixture_clock AS (
            SELECT date_trunc('milliseconds',clock_timestamp()) AS now
        )
        INSERT INTO chat.inventory_page_receipts(
            page_receipt_id,request_cursor_hash,inventory_session_id,
            domain,endpoint_nsid,cursor_format_version,page_limit,
            canonical_filter_sha256,user_did,device_id,jkt,auth_generation,
            protocol_instance_id,cursor_key_id,snapshot_event_position,
            snapshot_event_cursor_sha256,snapshot_retained_floor,
            after_ordinal,first_ordinal,item_count,items_sha256,has_more,
            successor_cursor_hash,successor_cursor_nonce,
            successor_cursor_ciphertext,canonical_response_sha256,
            created_at,expires_at,served_at
        )
        SELECT
            $1,NULL,'11111111-1111-4111-8111-111111111111',
            'conversations','blue.catbird.chat.getConversations',1,1,
            decode(repeat('01',32),'hex'),'did:web:g7-shape.example.com',
            '22222222-2222-4222-8222-222222222222',repeat('A',43),1,
            '33333333-3333-4333-8333-333333333333',repeat('B',42) || 'A',0,
            decode(repeat('02',32),'hex'),0,
            NULL,0,1,decode(repeat('03',32),'hex'),$2,$3,$4,$5,
            decode(repeat('04',32),'hex'),
            fixture_clock.now,fixture_clock.now + interval '1 minute',
            fixture_clock.now
          FROM fixture_clock
        "#,
    )
    .bind(Uuid::new_v4())
    .bind(has_more)
    .bind(successor_hash)
    .bind(successor_nonce)
    .bind(successor_ciphertext)
    .execute(&mut **transaction)
    .await
    .expect_err("nullable or mixed successor shape must fail closed");
    assert_eq!(
        error
            .as_database_error()
            .and_then(|database_error| database_error.constraint()),
        Some("inventory_page_receipts_shape_check")
    );
    sqlx::query("ROLLBACK TO SAVEPOINT malformed_page_receipt")
        .execute(&mut **transaction)
        .await
        .expect("recover from expected malformed-page-receipt rejection");
}

#[tokio::test]
async fn g7_receipt_shape_rejects_null_boolean_and_mixed_successor() {
    let pool = common::chat_protocol::setup_chat_protocol_db(1).await;
    let mut transaction = pool.begin().await.expect("begin receipt-negative probe");
    assert_page_receipt_shape_rejected(&mut transaction, None, None, None, None).await;
    assert_page_receipt_shape_rejected(
        &mut transaction,
        Some(true),
        Some(vec![5; 32]),
        None,
        Some(vec![6]),
    )
    .await;
    sqlx::query("SET CONSTRAINTS ALL IMMEDIATE")
        .execute(&mut *transaction)
        .await
        .expect("force receipt-negative constraints");
    transaction
        .rollback()
        .await
        .expect("roll back receipt-negative probe");
    pool.close().await;
}

#[tokio::test]
async fn g7_live_catalog_has_closed_arms_receipts_and_trigger_guards() {
    let pool = common::chat_protocol::setup_chat_protocol_db(1).await;

    let plaintext_columns: Vec<String> = sqlx::query_scalar(
        r#"
        SELECT table_name || '.' || column_name
          FROM information_schema.columns
         WHERE table_schema = 'chat'
           AND (
                column_name IN ('snapshot_event_cursor_bytes', 'event_cursor_bytes')
                OR (
                    table_name IN ('inventory_page_receipts', 'event_cursor_receipts')
                    AND column_name LIKE '%plaintext%'
                )
           )
         ORDER BY 1
        "#,
    )
    .fetch_all(&pool)
    .await
    .expect("inspect plaintext capability columns");
    assert!(
        plaintext_columns.is_empty(),
        "plaintext cursor capability columns survived G7: {plaintext_columns:?}"
    );

    let expected_columns = [
        ("inventory_conversation_items", "item_kind"),
        ("inventory_conversation_items", "participant_period_id"),
        ("inventory_conversation_items", "membership_interval_id"),
        ("inventory_conversation_items", "interval_terminal_seq"),
        (
            "inventory_conversation_items",
            "interval_closing_transition_id",
        ),
        (
            "inventory_conversation_items",
            "interval_closing_outer_entry_fingerprint",
        ),
        ("inventory_conversation_items", "interval_removed_at"),
        ("inventory_sessions", "protocol_instance_id"),
        ("inventory_sessions", "cursor_key_id"),
        ("inventory_sessions", "cursor_format_version"),
        ("inventory_sessions", "snapshot_retained_floor"),
        ("inventory_sessions", "conversation_payload_bytes"),
        ("inventory_sessions", "welcome_payload_bytes"),
        ("inventory_sessions", "recovery_payload_bytes"),
        ("inventory_sessions", "conversations_consumed"),
        ("inventory_sessions", "welcomes_consumed"),
        ("inventory_sessions", "recovery_consumed"),
        ("inventory_sessions", "snapshot_event_cursor_nonce"),
        ("inventory_sessions", "snapshot_event_cursor_ciphertext"),
        ("inventory_sessions", "legacy_cursor_invalidated_at"),
        ("inventory_page_receipts", "successor_cursor_nonce"),
        ("inventory_page_receipts", "successor_cursor_ciphertext"),
        ("event_cursor_receipts", "cursor_nonce"),
        ("event_cursor_receipts", "cursor_ciphertext"),
        ("event_cursor_receipts", "canonical_envelope_sha256"),
    ];
    for (table, column) in expected_columns {
        let present: bool = sqlx::query_scalar(
            r#"
            SELECT EXISTS (
                SELECT 1
                  FROM information_schema.columns
                 WHERE table_schema='chat' AND table_name=$1 AND column_name=$2
            )
            "#,
        )
        .bind(table)
        .bind(column)
        .fetch_one(&pool)
        .await
        .expect("inspect G7 column");
        assert!(present, "missing chat.{table}.{column}");
    }

    let required_constraints = [
        "inventory_conversation_items_participant_source_fk",
        "inventory_conversation_items_interval_source_fk",
        "inventory_conversation_items_arm_shape_check",
        "inventory_sessions_g7_binding_check",
        "inventory_sessions_consumption_check",
        "inventory_page_receipts_shape_check",
        "inventory_page_receipts_session_binding_fk",
        "event_cursor_receipts_shape_check",
        "event_cursor_receipts_session_binding_fk",
        "subscription_tickets_inventory_identity_fk",
    ];
    for constraint in required_constraints {
        let state: Option<bool> = sqlx::query_scalar(
            r#"
            SELECT con.convalidated
              FROM pg_constraint con
              JOIN pg_class c ON c.oid=con.conrelid
              JOIN pg_namespace n ON n.oid=c.relnamespace
             WHERE n.nspname='chat' AND con.conname=$1
            "#,
        )
        .bind(constraint)
        .fetch_optional(&pool)
        .await
        .expect("inspect G7 constraint");
        assert_eq!(state, Some(true), "missing or unvalidated {constraint}");
    }

    for trigger in [
        "inventory_sessions_identity_immutable",
        "inventory_sessions_lifecycle_monotonic",
        "inventory_sessions_materialization_deferred",
        "inventory_sessions_consumption_monotonic",
        "inventory_conversation_items_immutable",
        "inventory_conversation_items_source_precedence",
        "inventory_page_receipts_boundary",
        "inventory_page_receipts_immutable",
        "inventory_page_receipts_lifecycle_monotonic",
        "event_cursor_receipts_chain",
        "event_cursor_receipts_immutable",
    ] {
        let enabled: Option<String> = sqlx::query_scalar(
            r#"
            SELECT t.tgenabled::text
              FROM pg_trigger t
              JOIN pg_class c ON c.oid=t.tgrelid
              JOIN pg_namespace n ON n.oid=c.relnamespace
             WHERE n.nspname='chat' AND NOT t.tgisinternal AND t.tgname=$1
            "#,
        )
        .bind(trigger)
        .fetch_optional(&pool)
        .await
        .expect("inspect G7 trigger");
        assert_eq!(enabled.as_deref(), Some("O"), "trigger {trigger} disabled");
    }

    let mut transaction = pool.begin().await.expect("begin receipt shape probe");
    sqlx::query("SAVEPOINT malformed_receipt")
        .execute(&mut *transaction)
        .await
        .expect("create malformed-receipt savepoint");
    let malformed = sqlx::query(
        r#"
        INSERT INTO chat.event_cursor_receipts(
            cursor_hash, inventory_session_id, user_did, device_id, jkt,
            auth_generation, protocol_instance_id, cursor_key_id, event_position,
            predecessor_cursor_hash, retained_floor_at_issue, cursor_nonce,
            cursor_ciphertext, canonical_envelope_sha256, created_at, expires_at
        ) VALUES(
            decode(repeat('01',32),'hex'),
            '11111111-1111-4111-8111-111111111111',
            'did:web:g7-schema.example.com',
            '22222222-2222-4222-8222-222222222222',
            repeat('A',43), 1,
            '33333333-3333-4333-8333-333333333333',
            repeat('B',42) || 'A', 0, NULL, 0,
            decode(repeat('04',11),'hex'), decode('05','hex'), NULL,
            clock_timestamp(), clock_timestamp() + interval '1 minute'
        )
        "#,
    )
    .execute(&mut *transaction)
    .await
    .expect_err("11-byte AEAD nonce must fail before any FK can authorize it");
    assert_eq!(
        malformed
            .as_database_error()
            .and_then(|error| error.constraint()),
        Some("event_cursor_receipts_shape_check")
    );
    sqlx::query("ROLLBACK TO SAVEPOINT malformed_receipt")
        .execute(&mut *transaction)
        .await
        .expect("recover from expected malformed-receipt rejection");
    force_constraints_and_rollback(transaction).await;

    pool.close().await;
}
