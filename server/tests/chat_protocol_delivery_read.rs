//! Live-PostgreSQL verification of the clean-chat delivery READ path
//! (`chat_protocol::repository::delivery::{get_entries, conversation_snapshot_seq,
//! fetch_device_application_intervals, fetch_schedule_terminal_proof,
//! fetch_control_entry_for_device}` and the closed `#applicationEntry` /
//! `#conversationEntry` projections).
//!
//! The write authority (the transition executor + the E1/E2b-1 writers) is
//! certified elsewhere; this file proves the READ side returns EXACTLY what those
//! writers froze, on the exact entitlement seams, with gap-safe paging.
//!
//! Every case writes coherent rows and reads them back inside ONE transaction
//! that is ROLLED BACK — so the migration's DEFERRED cross-table triggers (which
//! fire only at COMMIT) never run, and each case only has to satisfy the
//! IMMEDIATE FK/CHECK graph against the committed `seed_fixture` base. This is
//! the same read-back+rollback discipline the executor primitive tests use.
//!
//! The production repository module is gated `#[cfg(not(test))]` (see
//! `src/chat_protocol/repository/mod.rs`), so — mirroring the sibling repository
//! harnesses — this test `include!`s it directly. Live cases run under the
//! standard whole-suite gate: they hard-fail (panic in `setup_chat_protocol_db`)
//! without `TEST_DATABASE_URL` rather than skipping:
//!   CHAT_OPERATION_CLAIM_ACTIVATION_APPROVED=handlers-and-legacy-apis-sealed \
//!   TEST_DATABASE_URL=postgres://localhost/catbird_chat_protocol_test_20260722 \
//!   cargo test --test chat_protocol_delivery_read -- --test-threads=1

#![allow(dead_code)]

mod common;

mod repository {
    pub(crate) mod delivery {
        include!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/src/chat_protocol/repository/delivery.rs"
        ));
    }
}

use base64::{
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
    Engine as _,
};
use chrono::{DateTime, Utc};
use serde_json::Value;
use sha2::{Digest, Sha256};
use sqlx::PgPool;
use uuid::Uuid;

use repository::delivery::{
    append_entry, close_application_interval, conversation_snapshot_seq,
    fetch_control_entry_for_device, fetch_device_application_intervals,
    fetch_schedule_terminal_proof, get_entries, insert_entry_recipients,
    insert_schedule_terminal_proof, AppendEntry, ApplicationIntervalClose, DeliveryRepositoryError,
    EntryEntitlementKind, EntryRecipient, IntervalCloseKind, NewScheduleTerminalProof,
    APPLICATION_ENTRY_KIND,
};

const COMMIT_ENTRY_KIND: &str = "blue.catbird.chat.defs#commitEntry";
// Kinds whose `entries_reference_shape_check` arm requires BOTH transition_id and
// message_id NULL. Every other control kind requires transition_id NOT NULL.
const REQUEST_FAMILY_KINDS: [&str; 3] = [
    "blue.catbird.chat.defs#resetRequestEntry",
    "blue.catbird.chat.defs#leaveRequestEntry",
    "blue.catbird.chat.defs#leaveCancellationEntry",
];

fn control_needs_transition_id(kind: &str) -> bool {
    !REQUEST_FAMILY_KINDS.contains(&kind)
}

// ---------------------------------------------------------------------------
// Base fixture (adapted verbatim from tests/chat_protocol_delivery.rs): a
// committed conversation whose genesis creation entry occupies seq 1 (so
// `next_entry_seq` starts at 2), the creator's `chat.device_keys` row, and the
// creator's OPEN creation application interval (start_seq 1).
// ---------------------------------------------------------------------------

struct DeliveryFixture {
    conversation_id: Uuid,
    actor_did: String,
    actor_device_id: Uuid,
    actor_key_id: String,
    actor_public_key: Vec<u8>,
}

fn random_plc_did() -> String {
    const ALPHABET: &[u8] = b"abcdefghijklmnopqrstuvwxyz234567";
    let mut bytes = Uuid::new_v4().as_bytes().to_vec();
    bytes.extend_from_slice(Uuid::new_v4().as_bytes());
    let suffix: String = bytes
        .iter()
        .take(24)
        .map(|byte| ALPHABET[(*byte % 32) as usize] as char)
        .collect();
    format!("did:plc:{suffix}")
}

async fn clock_now(pool: &PgPool) -> DateTime<Utc> {
    sqlx::query_scalar("SELECT clock_timestamp()")
        .fetch_one(pool)
        .await
        .expect("sample trusted database clock")
}

async fn next_entry_seq(pool: &PgPool, conversation_id: Uuid) -> i64 {
    sqlx::query_scalar("SELECT next_entry_seq FROM chat.conversations WHERE conversation_id = $1")
        .bind(conversation_id)
        .fetch_one(pool)
        .await
        .expect("read conversation append counter")
}

async fn leaf_period_of(pool: &PgPool, conversation_id: Uuid) -> Uuid {
    sqlx::query_scalar("SELECT leaf_period_id FROM chat.member_devices WHERE conversation_id = $1")
        .bind(conversation_id)
        .fetch_one(pool)
        .await
        .expect("read genesis leaf period id")
}

/// The committed genesis creation transition id — a real `chat.transitions` row
/// the immediate `application_schedule_terminal_proofs_transition_fk` can bind to.
async fn creation_transition_of(pool: &PgPool, conversation_id: Uuid) -> Uuid {
    sqlx::query_scalar(
        "SELECT transition_id FROM chat.transitions WHERE conversation_id = $1 AND kind = 'creation'",
    )
    .bind(conversation_id)
    .fetch_one(pool)
    .await
    .expect("read creation transition id")
}

async fn seed_fixture(pool: &PgPool) -> DeliveryFixture {
    let actor_did = random_plc_did();
    let actor_device_id = Uuid::new_v4();
    let mut actor_public_key = Uuid::new_v4().as_bytes().to_vec();
    actor_public_key.extend_from_slice(Uuid::new_v4().as_bytes());
    let actor_key_id: String = sqlx::query_scalar("SELECT chat.ed25519_key_id($1)")
        .bind(&actor_public_key)
        .fetch_one(pool)
        .await
        .expect("derive actor key id");

    let admitted_at = clock_now(pool).await;
    sqlx::query("INSERT INTO chat.principals(user_did,created_at) VALUES($1,$2)")
        .bind(&actor_did)
        .bind(admitted_at)
        .execute(pool)
        .await
        .expect("insert principal");
    sqlx::query(
        "INSERT INTO chat.devices(user_did,device_id,device_name,status,dpop_jkt,auth_generation,capabilities,created_at,updated_at) \
         VALUES($1,$2,'read-actor','active',$3,1,chat.protocol_capabilities(),$4,$4)",
    )
    .bind(&actor_did)
    .bind(actor_device_id)
    .bind(format!("{:042}A", 0_u128))
    .bind(admitted_at)
    .execute(pool)
    .await
    .expect("insert actor device");
    sqlx::query(
        "INSERT INTO chat.device_keys(user_did,device_id,key_id,signing_public_key,enrollment_auth_generation,created_at) \
         VALUES($1,$2,$3,$4,1,$5)",
    )
    .bind(&actor_did)
    .bind(actor_device_id)
    .bind(&actor_key_id)
    .bind(&actor_public_key)
    .bind(admitted_at)
    .execute(pool)
    .await
    .expect("insert actor device key");

    let conversation_id = create_conversation_fixture(
        pool,
        &actor_did,
        actor_device_id,
        &actor_key_id,
        &actor_public_key,
    )
    .await;

    DeliveryFixture {
        conversation_id,
        actor_did,
        actor_device_id,
        actor_key_id,
        actor_public_key,
    }
}

async fn create_conversation_fixture(
    pool: &PgPool,
    principal: &str,
    actor_device_id: Uuid,
    actor_key_id: &str,
    actor_public_key: &[u8],
) -> Uuid {
    let conversation_id = Uuid::new_v4();
    let creation_transition_id = Uuid::new_v4();
    let creation_entry_id = Uuid::new_v4();
    let participant_period_id = Uuid::new_v4();
    let leaf_period_id = Uuid::new_v4();
    let metadata_snapshot_id = Uuid::new_v4();
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
    let accepted_at = clock_now(pool).await;

    let mut tx = pool.begin().await.expect("begin coherent creation fixture");
    sqlx::query(
        "INSERT INTO chat.conversations(conversation_id,kind,lifecycle,current_generation,current_state_version,next_entry_seq,created_at) VALUES($1,'group','active',0,0,2,$2)",
    )
    .bind(conversation_id)
    .bind(accepted_at)
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
    .bind(accepted_at)
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
    .bind(accepted_at)
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
    .bind(accepted_at)
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
    .bind(accepted_at)
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
    .bind(accepted_at)
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
    .bind(accepted_at)
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
    .bind(accepted_at)
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
    .bind(accepted_at)
    .execute(&mut *tx)
    .await
    .expect("insert creation application interval");
    tx.commit().await.expect("commit coherent creation fixture");

    conversation_id
}

/// Seed a SECOND active device of the same DID (a sibling leaf). It has a
/// `chat.devices` row so it can carry `entry_recipients`, but NO application
/// interval — proving a same-DID sibling sees control audience only.
async fn seed_sibling_device(pool: &PgPool, user_did: &str) -> Uuid {
    let device_id = Uuid::new_v4();
    let at = clock_now(pool).await;
    // A canonical 43-char base64url SHA-256 thumbprint (its terminal char is
    // always a legal 2-bit base64 tail), unique per fixture.
    let mut jkt_bytes = Uuid::new_v4().as_bytes().to_vec();
    jkt_bytes.extend_from_slice(Uuid::new_v4().as_bytes());
    let dpop_jkt = URL_SAFE_NO_PAD.encode(&jkt_bytes);
    sqlx::query(
        "INSERT INTO chat.devices(user_did,device_id,device_name,status,dpop_jkt,auth_generation,capabilities,created_at,updated_at) \
         VALUES($1,$2,'read-sibling','active',$3,1,chat.protocol_capabilities(),$4,$4)",
    )
    .bind(user_did)
    .bind(device_id)
    .bind(dpop_jkt)
    .bind(at)
    .execute(pool)
    .await
    .expect("insert sibling device");
    device_id
}

// ---------------------------------------------------------------------------
// In-transaction row builders (all rolled back). Each satisfies the IMMEDIATE
// FK/CHECK graph; the entry `transition_id` FK is DEFERRED, so a synthetic
// control transition id resolves only at COMMIT (which never happens here).
// ---------------------------------------------------------------------------

fn application_append(
    fixture: &DeliveryFixture,
    entry_id: Uuid,
    signed_request: Vec<u8>,
    request_digest: Vec<u8>,
    signature: Vec<u8>,
    fingerprint: Vec<u8>,
    received_at: DateTime<Utc>,
) -> AppendEntry {
    let payload = vec![0xA1_u8; 8];
    AppendEntry {
        conversation_id: fixture.conversation_id,
        entry_id,
        entry_kind: APPLICATION_ENTRY_KIND.to_owned(),
        accepted_payload_bytes: payload.clone(),
        accepted_payload_sha256: Sha256::digest(&payload).to_vec(),
        signed_request_bytes: signed_request,
        request_digest,
        signature,
        server_fields_bytes: vec![0xA0_u8],
        outer_entry_fingerprint: fingerprint,
        actor_did: fixture.actor_did.clone(),
        actor_device_id: fixture.actor_device_id,
        actor_key_id: fixture.actor_key_id.clone(),
        actor_auth_generation: 1,
        generation: Some(0),
        state_version: Some(0),
        transition_id: None,
        message_id: Some(Uuid::new_v4()),
        received_at,
    }
}

fn control_append(
    fixture: &DeliveryFixture,
    kind: &str,
    entry_id: Uuid,
    request_digest: Vec<u8>,
    signature: Vec<u8>,
    server_fields_bytes: Vec<u8>,
    fingerprint: Vec<u8>,
    received_at: DateTime<Utc>,
) -> AppendEntry {
    let payload = vec![0xC1_u8; 8];
    AppendEntry {
        conversation_id: fixture.conversation_id,
        entry_id,
        entry_kind: kind.to_owned(),
        accepted_payload_bytes: payload.clone(),
        accepted_payload_sha256: Sha256::digest(&payload).to_vec(),
        signed_request_bytes: vec![0xB2_u8; 8],
        request_digest,
        signature,
        server_fields_bytes,
        outer_entry_fingerprint: fingerprint,
        actor_did: fixture.actor_did.clone(),
        actor_device_id: fixture.actor_device_id,
        actor_key_id: fixture.actor_key_id.clone(),
        actor_auth_generation: 1,
        generation: Some(0),
        state_version: Some(0),
        transition_id: control_needs_transition_id(kind).then(Uuid::new_v4),
        message_id: None,
        received_at,
    }
}

fn control_recipient(user_did: &str, device_id: Uuid) -> EntryRecipient {
    EntryRecipient {
        user_did: user_did.to_owned(),
        device_id,
        entitlement_kind: EntryEntitlementKind::Control,
    }
}

fn parse_ts(text: &str) -> DateTime<Utc> {
    DateTime::parse_from_rfc3339(text)
        .expect("canonical timestamp")
        .with_timezone(&Utc)
}

fn load_contract_vectors() -> Value {
    serde_json::from_str(include_str!("fixtures/mls_chat_contract_vectors.json"))
        .expect("contract vectors fixture")
}

// ===========================================================================
// #applicationEntry projection through delivery.
// ===========================================================================

/// The read returns the closed five-field `#applicationEntry` projection —
/// `{entryId, conversationId, seq, signedRequest, receivedAt}` — carrying no
/// duplicated unsigned field, and losslessly preserves the frozen 32-byte outer
/// fingerprint plus the request digest + signature the fingerprint commits. The
/// exact Task-1 `applicationEntryFingerprint` golden supplies the committed
/// scalars. The control projection is rejected on an application row.
#[tokio::test]
async fn application_projection_returns_exactly_the_five_golden_fields() {
    let pool = common::chat_protocol::setup_chat_protocol_db(4).await;
    let fixture = seed_fixture(&pool).await;
    let vectors = load_contract_vectors();
    let golden = &vectors["applicationEntryFingerprint"];

    let entry_id = Uuid::parse_str(golden["entryId"].as_str().unwrap()).unwrap();
    let request_digest = STANDARD
        .decode(golden["requestDigest"].as_str().unwrap())
        .unwrap();
    let signature = STANDARD
        .decode(golden["signature"].as_str().unwrap())
        .unwrap();
    let fingerprint = hex::decode(golden["fingerprintSha256Hex"].as_str().unwrap()).unwrap();
    let received_at = parse_ts(golden["receivedAt"].as_str().unwrap());
    let signed_request = b"golden-signed-application-wrapper".to_vec();

    let mut tx = pool.begin().await.expect("begin read tx");
    let entry = application_append(
        &fixture,
        entry_id,
        signed_request.clone(),
        request_digest.clone(),
        signature.clone(),
        fingerprint.clone(),
        received_at,
    );
    let seq = append_entry(&mut tx, &entry)
        .await
        .expect("append app entry");
    assert_eq!(seq, 2, "genesis at seq 1, this app entry at seq 2");

    // Open the creator's interval already spans seq >= 1, so the entry is visible.
    let page = get_entries(
        &mut tx,
        fixture.conversation_id,
        &fixture.actor_did,
        fixture.actor_device_id,
        1,
        10,
    )
    .await
    .expect("read page");
    let row = page
        .entries
        .iter()
        .find(|row| row.seq == 2)
        .expect("application entry visible via interval");
    assert!(row.is_application());
    assert_eq!(row.outer_entry_fingerprint(), fingerprint.as_slice());
    assert_eq!(row.request_digest, request_digest);
    assert_eq!(row.signature, signature);

    let projection = row
        .application_projection()
        .expect("application projection");
    assert_eq!(projection.entry_id, entry_id);
    assert_eq!(projection.conversation_id, fixture.conversation_id);
    assert_eq!(projection.seq, 2);
    assert_eq!(projection.signed_request_bytes, signed_request);
    assert_eq!(projection.received_at, received_at);
    // The disjoint control projection is rejected on an application row.
    assert!(matches!(
        row.control_projection(),
        Err(DeliveryRepositoryError::EntryKindMismatch)
    ));

    tx.rollback().await.expect("rollback read tx");
}

// ===========================================================================
// The thirteen #conversationEntry control projections through delivery.
// ===========================================================================

/// Each of the 13 control kinds round-trips through the read as the closed
/// eight-field control projection `{entryKind, entryId, conversationId, seq,
/// requestDigest, signature, serverFields, receivedAt}`, preserving the exact
/// serverFields bytes (`{}` / `{recovery}` / `{tombstone}` shapes) and the frozen
/// golden fingerprint. Request-digest + signature bytes come from the Task-1
/// `controlEntryFingerprints` golden. The application projection is rejected on a
/// control row.
#[tokio::test]
async fn thirteen_control_projections_preserve_serverfields_and_golden_fingerprint() {
    let pool = common::chat_protocol::setup_chat_protocol_db(4).await;
    let fixture = seed_fixture(&pool).await;
    let vectors = load_contract_vectors();
    let cases = vectors["controlEntryFingerprints"]["cases"]
        .as_array()
        .expect("13 control cases");
    assert_eq!(cases.len(), 13);

    let mut nonempty_server_fields_seen = 0_u32;
    for case in cases {
        let kind = case["entryKind"].as_str().unwrap().to_owned();
        let entry_id = Uuid::parse_str(case["entryId"].as_str().unwrap()).unwrap();
        let request_digest = STANDARD
            .decode(case["requestDigest"].as_str().unwrap())
            .unwrap();
        let signature = STANDARD
            .decode(case["signature"].as_str().unwrap())
            .unwrap();
        let fingerprint = hex::decode(case["fingerprintSha256Hex"].as_str().unwrap()).unwrap();
        let received_at = parse_ts(case["receivedAt"].as_str().unwrap());
        // The delivery service is blind to serverFields DAG-CBOR; it stores and
        // returns the exact bytes. `{}` is the empty map; the two nonempty arms
        // (recovery / tombstone) carry a distinctive shape-specific blob so the
        // read is proven to preserve each of the three shapes distinctly.
        let server_fields = &case["serverFields"];
        let server_fields_bytes = if server_fields.as_object().map(|m| m.is_empty()) == Some(true) {
            vec![0xA0_u8]
        } else {
            nonempty_server_fields_seen += 1;
            let mut blob = vec![0xD0_u8, nonempty_server_fields_seen as u8];
            blob.extend_from_slice(kind.as_bytes());
            blob
        };

        let mut tx = pool.begin().await.expect("begin control read tx");
        let entry = control_append(
            &fixture,
            &kind,
            entry_id,
            request_digest.clone(),
            signature.clone(),
            server_fields_bytes.clone(),
            fingerprint.clone(),
            received_at,
        );
        let seq = append_entry(&mut tx, &entry)
            .await
            .expect("append control entry");
        insert_entry_recipients(
            &mut tx,
            fixture.conversation_id,
            seq,
            &[control_recipient(
                &fixture.actor_did,
                fixture.actor_device_id,
            )],
        )
        .await
        .expect("freeze control audience");

        let fetched = fetch_control_entry_for_device(
            &mut tx,
            fixture.conversation_id,
            seq,
            &fixture.actor_did,
            fixture.actor_device_id,
        )
        .await
        .expect("fetch control entry")
        .expect("entitled control entry present");
        assert!(!fetched.is_application());
        assert_eq!(fetched.outer_entry_fingerprint(), fingerprint.as_slice());

        let projection = fetched.control_projection().expect("control projection");
        assert_eq!(projection.entry_kind, kind);
        assert_eq!(projection.entry_id, entry_id);
        assert_eq!(projection.conversation_id, fixture.conversation_id);
        assert_eq!(projection.seq, seq);
        assert_eq!(projection.request_digest, request_digest);
        assert_eq!(projection.signature, signature);
        assert_eq!(projection.server_fields_bytes, server_fields_bytes);
        assert_eq!(projection.received_at, received_at);
        // The disjoint application projection is rejected on a control row.
        assert!(matches!(
            fetched.application_projection(),
            Err(DeliveryRepositoryError::EntryKindMismatch)
        ));

        tx.rollback().await.expect("rollback control read tx");
    }
    assert_eq!(
        nonempty_server_fields_seen, 2,
        "exactly the recovery + tombstone arms carry nonempty serverFields"
    );
}

/// Delivery-seam one-field sensitivity: two control entries that differ in only
/// one projection scalar (the request digest) read back distinct, and their
/// distinct frozen fingerprints flow through unchanged. (The cryptographic
/// SHA-256-over-canonical-DAG-CBOR recompute and the full mutation matrix are the
/// transcript-layer golden's job; this proves the read never collapses the
/// distinction.)
#[tokio::test]
async fn control_projection_is_one_field_sensitive_through_delivery() {
    let pool = common::chat_protocol::setup_chat_protocol_db(4).await;
    let fixture = seed_fixture(&pool).await;
    let received_at = clock_now(&pool).await;

    let base_digest = vec![0x11_u8; 32];
    let mut mutated_digest = base_digest.clone();
    mutated_digest[0] ^= 0x01;
    let base_fp = vec![0x21_u8; 32];
    let mut mutated_fp = base_fp.clone();
    mutated_fp[0] ^= 0x01;
    let signature = vec![0x33_u8; 64];

    let mut tx = pool.begin().await.expect("begin sensitivity tx");
    let a = control_append(
        &fixture,
        COMMIT_ENTRY_KIND,
        Uuid::new_v4(),
        base_digest.clone(),
        signature.clone(),
        vec![0xA0_u8],
        base_fp.clone(),
        received_at,
    );
    let seq_a = append_entry(&mut tx, &a).await.expect("append entry a");
    insert_entry_recipients(
        &mut tx,
        fixture.conversation_id,
        seq_a,
        &[control_recipient(
            &fixture.actor_did,
            fixture.actor_device_id,
        )],
    )
    .await
    .expect("audience a");

    let b = control_append(
        &fixture,
        COMMIT_ENTRY_KIND,
        Uuid::new_v4(),
        mutated_digest.clone(),
        signature.clone(),
        vec![0xA0_u8],
        mutated_fp.clone(),
        received_at,
    );
    let seq_b = append_entry(&mut tx, &b).await.expect("append entry b");
    insert_entry_recipients(
        &mut tx,
        fixture.conversation_id,
        seq_b,
        &[control_recipient(
            &fixture.actor_did,
            fixture.actor_device_id,
        )],
    )
    .await
    .expect("audience b");

    let page = get_entries(
        &mut tx,
        fixture.conversation_id,
        &fixture.actor_did,
        fixture.actor_device_id,
        1,
        10,
    )
    .await
    .expect("read page");
    let proj_a = page
        .entries
        .iter()
        .find(|row| row.seq == seq_a as i64)
        .unwrap()
        .control_projection()
        .unwrap();
    let proj_b = page
        .entries
        .iter()
        .find(|row| row.seq == seq_b as i64)
        .unwrap()
        .control_projection()
        .unwrap();
    assert_ne!(proj_a.request_digest, proj_b.request_digest);
    assert_eq!(proj_a.request_digest, base_digest);
    assert_eq!(proj_b.request_digest, mutated_digest);
    // The distinct frozen fingerprints flow through unchanged.
    let fp_a = page.entries.iter().find(|r| r.seq == seq_a as i64).unwrap();
    let fp_b = page.entries.iter().find(|r| r.seq == seq_b as i64).unwrap();
    assert_eq!(fp_a.outer_entry_fingerprint(), base_fp.as_slice());
    assert_eq!(fp_b.outer_entry_fingerprint(), mutated_fp.as_slice());
    assert_ne!(
        fp_a.outer_entry_fingerprint(),
        fp_b.outer_entry_fingerprint()
    );

    tx.rollback().await.expect("rollback sensitivity tx");
}

// ===========================================================================
// getEntries gap-safe paging.
// ===========================================================================

/// `afterSeq` is a global scan position, not an entitlement cursor: it may name a
/// hidden seq; hidden rows are skipped; an empty page returns the input cursor; a
/// nonempty page returns the greatest visible seq; and `hasMore` reflects only a
/// later CALLER-visible row, never the unfiltered global log. The genesis
/// creation control at seq 1 is unentitled to the caller and never surfaces.
#[tokio::test]
async fn get_entries_is_gap_safe_and_hides_unentitled_rows() {
    let pool = common::chat_protocol::setup_chat_protocol_db(4).await;
    let fixture = seed_fixture(&pool).await;
    let now = clock_now(&pool).await;

    let mut tx = pool.begin().await.expect("begin paging tx");
    // seq 2: application entry (visible via the creator's open creation interval).
    let app2 = application_append(
        &fixture,
        Uuid::new_v4(),
        b"w2".to_vec(),
        vec![0x02_u8; 32],
        vec![0x02_u8; 64],
        vec![0x02_u8; 32],
        now,
    );
    let seq2 = append_entry(&mut tx, &app2).await.unwrap();
    // seq 3: control entry, caller entitled via entry_recipients.
    let ctl3 = control_append(
        &fixture,
        COMMIT_ENTRY_KIND,
        Uuid::new_v4(),
        vec![0x03_u8; 32],
        vec![0x03_u8; 64],
        vec![0xA0_u8],
        vec![0x03_u8; 32],
        now,
    );
    let seq3 = append_entry(&mut tx, &ctl3).await.unwrap();
    insert_entry_recipients(
        &mut tx,
        fixture.conversation_id,
        seq3,
        &[control_recipient(
            &fixture.actor_did,
            fixture.actor_device_id,
        )],
    )
    .await
    .unwrap();
    // seq 4: application entry (visible via interval).
    let app4 = application_append(
        &fixture,
        Uuid::new_v4(),
        b"w4".to_vec(),
        vec![0x04_u8; 32],
        vec![0x04_u8; 64],
        vec![0x04_u8; 32],
        now,
    );
    let seq4 = append_entry(&mut tx, &app4).await.unwrap();
    assert_eq!((seq2, seq3, seq4), (2, 3, 4));

    // Full scan from 0: seq 1 (unentitled creation control) is hidden; the caller
    // sees exactly 2,3,4.
    let full = get_entries(
        &mut tx,
        fixture.conversation_id,
        &fixture.actor_did,
        fixture.actor_device_id,
        0,
        10,
    )
    .await
    .unwrap();
    assert_eq!(
        full.entries.iter().map(|r| r.seq).collect::<Vec<_>>(),
        vec![2, 3, 4]
    );
    assert!(!full.has_more);
    assert_eq!(full.next_after_seq, 4);

    // First page of size 2: [2,3], hasMore because a later visible row (4) exists;
    // nextAfterSeq is the greatest returned seq.
    let first = get_entries(
        &mut tx,
        fixture.conversation_id,
        &fixture.actor_did,
        fixture.actor_device_id,
        0,
        2,
    )
    .await
    .unwrap();
    assert_eq!(
        first.entries.iter().map(|r| r.seq).collect::<Vec<_>>(),
        vec![2, 3]
    );
    assert!(first.has_more);
    assert_eq!(first.next_after_seq, 3);

    // Continue from the returned cursor: [4], no more.
    let second = get_entries(
        &mut tx,
        fixture.conversation_id,
        &fixture.actor_did,
        fixture.actor_device_id,
        first.next_after_seq,
        2,
    )
    .await
    .unwrap();
    assert_eq!(
        second.entries.iter().map(|r| r.seq).collect::<Vec<_>>(),
        vec![4]
    );
    assert!(!second.has_more);
    assert_eq!(second.next_after_seq, 4);

    // Empty page beyond the tail returns the INPUT cursor unchanged.
    let empty = get_entries(
        &mut tx,
        fixture.conversation_id,
        &fixture.actor_did,
        fixture.actor_device_id,
        4,
        10,
    )
    .await
    .unwrap();
    assert!(empty.entries.is_empty());
    assert!(!empty.has_more);
    assert_eq!(empty.next_after_seq, 4);

    // `afterSeq` may name the HIDDEN seq 1; the scan simply continues past it.
    let from_hidden = get_entries(
        &mut tx,
        fixture.conversation_id,
        &fixture.actor_did,
        fixture.actor_device_id,
        1,
        10,
    )
    .await
    .unwrap();
    assert_eq!(
        from_hidden
            .entries
            .iter()
            .map(|r| r.seq)
            .collect::<Vec<_>>(),
        vec![2, 3, 4]
    );

    tx.rollback().await.expect("rollback paging tx");
}

/// Application visibility binds ONE exact device: the genesis leaf sees the
/// application entry through its interval; a same-DID sibling with no interval
/// sees the control entry (via its own entry_recipients row) but NOT the
/// application entry.
#[tokio::test]
async fn application_visibility_binds_one_device_sibling_sees_control_only() {
    let pool = common::chat_protocol::setup_chat_protocol_db(4).await;
    let fixture = seed_fixture(&pool).await;
    let sibling_device = seed_sibling_device(&pool, &fixture.actor_did).await;
    let now = clock_now(&pool).await;

    let mut tx = pool.begin().await.expect("begin visibility tx");
    // seq 2: application entry — only the genesis leaf's interval spans it.
    let app2 = application_append(
        &fixture,
        Uuid::new_v4(),
        b"app".to_vec(),
        vec![0x02_u8; 32],
        vec![0x02_u8; 64],
        vec![0x02_u8; 32],
        now,
    );
    let seq2 = append_entry(&mut tx, &app2).await.unwrap();
    // seq 3: control entry with BOTH devices in its frozen audience.
    let ctl3 = control_append(
        &fixture,
        COMMIT_ENTRY_KIND,
        Uuid::new_v4(),
        vec![0x03_u8; 32],
        vec![0x03_u8; 64],
        vec![0xA0_u8],
        vec![0x03_u8; 32],
        now,
    );
    let seq3 = append_entry(&mut tx, &ctl3).await.unwrap();
    // Recipients must be in canonical (DID, device) order; same DID, so order by
    // device UUID bytes.
    let mut recipients = vec![
        control_recipient(&fixture.actor_did, fixture.actor_device_id),
        control_recipient(&fixture.actor_did, sibling_device),
    ];
    recipients.sort_by(|a, b| a.device_id.as_bytes().cmp(b.device_id.as_bytes()));
    insert_entry_recipients(&mut tx, fixture.conversation_id, seq3, &recipients)
        .await
        .unwrap();

    let genesis = get_entries(
        &mut tx,
        fixture.conversation_id,
        &fixture.actor_did,
        fixture.actor_device_id,
        1,
        10,
    )
    .await
    .unwrap();
    assert_eq!(
        genesis.entries.iter().map(|r| r.seq).collect::<Vec<_>>(),
        vec![seq2 as i64, seq3 as i64],
        "genesis leaf sees both its application entry and the control entry"
    );

    let sibling = get_entries(
        &mut tx,
        fixture.conversation_id,
        &fixture.actor_did,
        sibling_device,
        1,
        10,
    )
    .await
    .unwrap();
    assert_eq!(
        sibling.entries.iter().map(|r| r.seq).collect::<Vec<_>>(),
        vec![seq3 as i64],
        "sibling sees control audience only, never the application entry"
    );

    tx.rollback().await.expect("rollback visibility tx");
}

// ===========================================================================
// Interval read: five-field opening binding, all-or-none close, former-device
// close-row fetchability.
// ===========================================================================

/// The interval read returns the exact immutable five-field opening binding and
/// verified opening context; an OPEN interval has all-NULL closing columns; a
/// FINITE interval (closed by the writer) carries the all-present
/// `{terminalSeq, closingTransitionId, closingOuterEntryFingerprint, closingKind}`
/// with `terminalSeq > openingSeq`; and the former device stays entitled to fetch
/// the exact signed closing control at `terminalSeq` while an unentitled device
/// gets nothing.
#[tokio::test]
async fn interval_read_opening_binding_all_or_none_close_and_former_device_row() {
    let pool = common::chat_protocol::setup_chat_protocol_db(4).await;
    let fixture = seed_fixture(&pool).await;
    let sibling_device = seed_sibling_device(&pool, &fixture.actor_did).await;
    let leaf_period_id = leaf_period_of(&pool, fixture.conversation_id).await;
    let now = clock_now(&pool).await;

    let mut tx = pool.begin().await.expect("begin interval tx");

    // The OPEN creation interval reads back with the exact five-field opening
    // binding and all-NULL close.
    let open = fetch_device_application_intervals(
        &mut tx,
        fixture.conversation_id,
        &fixture.actor_did,
        fixture.actor_device_id,
    )
    .await
    .unwrap();
    assert_eq!(open.len(), 1);
    let interval = &open[0];
    assert!(!interval.is_finite());
    assert!(interval.close_columns_are_all_or_none());
    assert_eq!(interval.start_seq, 1);
    assert_eq!(interval.opening_kind, "creation");
    assert_eq!(
        interval.opening_transition_id,
        interval.membership_interval_id
    );
    assert_eq!(interval.opening_outer_entry_fingerprint, vec![12_u8; 32]);
    assert_eq!(interval.opening_state_version, 0);
    assert_eq!(interval.opening_group_id, vec![1_u8; 32]);
    assert_eq!(interval.opening_epoch, 0);
    assert_eq!(interval.opening_group_context_hash, vec![2_u8; 32]);
    assert_eq!(interval.opening_confirmation_tag, vec![3_u8; 32]);
    assert_eq!(interval.opening_leaf_period_id, leaf_period_id);
    assert!(interval.terminal_seq.is_none());
    assert!(interval.closing_transition_id.is_none());
    assert!(interval.closing_outer_entry_fingerprint.is_none());

    // Append the signed closing control at seq 2, entitle the former device to it
    // (intervalClose arm), then close the interval finitely at that seq.
    let closing_fp = vec![0x77_u8; 32];
    let closing_transition_id = Uuid::new_v4();
    let closing_entry = control_append(
        &fixture,
        COMMIT_ENTRY_KIND,
        Uuid::new_v4(),
        vec![0x07_u8; 32],
        vec![0x07_u8; 64],
        vec![0xA0_u8],
        closing_fp.clone(),
        now,
    );
    let terminal_seq = append_entry(&mut tx, &closing_entry).await.unwrap();
    assert_eq!(terminal_seq, 2);
    insert_entry_recipients(
        &mut tx,
        fixture.conversation_id,
        terminal_seq,
        &[EntryRecipient {
            user_did: fixture.actor_did.clone(),
            device_id: fixture.actor_device_id,
            entitlement_kind: EntryEntitlementKind::IntervalClose,
        }],
    )
    .await
    .unwrap();
    close_application_interval(
        &mut tx,
        &ApplicationIntervalClose {
            membership_interval_id: interval.membership_interval_id,
            terminal_seq: terminal_seq as i64,
            closing_state_version: 1,
            closing_transition_id,
            closing_outer_entry_fingerprint: closing_fp.clone(),
            closing_kind: IntervalCloseKind::Remove,
            closing_leaf_period_id: leaf_period_id,
            removed_at: now,
        },
    )
    .await
    .expect("close interval");

    // The FINITE interval reads back all-present, coherent, terminal_seq > start.
    let finite = fetch_device_application_intervals(
        &mut tx,
        fixture.conversation_id,
        &fixture.actor_did,
        fixture.actor_device_id,
    )
    .await
    .unwrap();
    assert_eq!(finite.len(), 1);
    let closed = &finite[0];
    assert!(closed.is_finite());
    assert!(closed.close_columns_are_all_or_none());
    assert_eq!(closed.terminal_seq, Some(terminal_seq as i64));
    assert!(closed.terminal_seq.unwrap() > closed.start_seq);
    assert_eq!(closed.closing_transition_id, Some(closing_transition_id));
    assert_eq!(
        closed.closing_outer_entry_fingerprint,
        Some(closing_fp.clone())
    );
    assert_eq!(closed.closing_kind.as_deref(), Some("remove"));
    // The opening five fields are immutable across the close.
    assert_eq!(closed.start_seq, 1);
    assert_eq!(closed.opening_kind, "creation");
    assert_eq!(closed.opening_outer_entry_fingerprint, vec![12_u8; 32]);

    // The former device stays entitled to fetch the signed closing control at
    // terminal_seq even though its application interval no longer spans it.
    let former = fetch_control_entry_for_device(
        &mut tx,
        fixture.conversation_id,
        terminal_seq,
        &fixture.actor_did,
        fixture.actor_device_id,
    )
    .await
    .unwrap()
    .expect("former device fetches its signed close row");
    assert_eq!(former.outer_entry_fingerprint(), closing_fp.as_slice());
    assert_eq!(former.seq, terminal_seq as i64);
    // A device with no recipient row at that seq gets nothing.
    let unentitled = fetch_control_entry_for_device(
        &mut tx,
        fixture.conversation_id,
        terminal_seq,
        &fixture.actor_did,
        sibling_device,
    )
    .await
    .unwrap();
    assert!(unentitled.is_none());

    tx.rollback().await.expect("rollback interval tx");
}

// ===========================================================================
// Schedule terminal proof: exact-device zero-or-one, no cross-device.
// ===========================================================================

/// The schedule-terminal-proof read is authenticated to one EXACT device: it
/// returns zero-or-one proof for that `(conversation, did, device)`, and a
/// same-DID sibling (or any other device) reads `None`. No cross-device listing
/// exists.
#[tokio::test]
async fn schedule_terminal_proof_is_exact_device_zero_or_one() {
    let pool = common::chat_protocol::setup_chat_protocol_db(4).await;
    let fixture = seed_fixture(&pool).await;
    let sibling_device = seed_sibling_device(&pool, &fixture.actor_did).await;
    let proof_transition = creation_transition_of(&pool, fixture.conversation_id).await;
    let now = clock_now(&pool).await;

    let mut tx = pool.begin().await.expect("begin proof tx");
    // Before any proof: the exact device reads None.
    assert!(fetch_schedule_terminal_proof(
        &mut tx,
        fixture.conversation_id,
        &fixture.actor_did,
        fixture.actor_device_id,
    )
    .await
    .unwrap()
    .is_none());

    // Materialize the Terminal entry the proof references (immediate entry FK),
    // then insert the exact-device proof.
    let terminal_entry = control_append(
        &fixture,
        COMMIT_ENTRY_KIND,
        Uuid::new_v4(),
        vec![0x09_u8; 32],
        vec![0x09_u8; 64],
        vec![0xA0_u8],
        vec![0x09_u8; 32],
        now,
    );
    let terminal_seq = append_entry(&mut tx, &terminal_entry).await.unwrap();
    let proof_fp = vec![0x55_u8; 32];
    insert_schedule_terminal_proof(
        &mut tx,
        &NewScheduleTerminalProof {
            conversation_id: fixture.conversation_id,
            recipient_did: fixture.actor_did.clone(),
            recipient_device_id: fixture.actor_device_id,
            terminal_seq: terminal_seq as i64,
            transition_id: proof_transition,
            outer_entry_fingerprint: proof_fp.clone(),
            received_at: now,
        },
    )
    .await
    .expect("insert schedule terminal proof");

    // Exact device: exactly one proof, fields verbatim.
    let proof = fetch_schedule_terminal_proof(
        &mut tx,
        fixture.conversation_id,
        &fixture.actor_did,
        fixture.actor_device_id,
    )
    .await
    .unwrap()
    .expect("exact-device proof present");
    assert_eq!(proof.recipient_device_id, fixture.actor_device_id);
    assert_eq!(proof.terminal_seq, terminal_seq as i64);
    assert_eq!(proof.transition_id, proof_transition);
    assert_eq!(proof.outer_entry_fingerprint, proof_fp);

    // Same-DID sibling device: no proof of its own, no cross-device enumeration.
    assert!(fetch_schedule_terminal_proof(
        &mut tx,
        fixture.conversation_id,
        &fixture.actor_did,
        sibling_device,
    )
    .await
    .unwrap()
    .is_none());
    // A different DID entirely: also None.
    assert!(fetch_schedule_terminal_proof(
        &mut tx,
        fixture.conversation_id,
        &random_plc_did(),
        fixture.actor_device_id,
    )
    .await
    .unwrap()
    .is_none());

    tx.rollback().await.expect("rollback proof tx");
}

// ===========================================================================
// conversationState.snapshotSeq.
// ===========================================================================

/// `snapshotSeq` is `next_entry_seq - 1` from the conversation head — the whole
/// log's high-water mark, independent of the caller's `afterSeq` cursor and of
/// what the caller can see. It advances as entries are appended.
#[tokio::test]
async fn snapshot_seq_is_next_entry_seq_minus_one_not_an_entry_cursor() {
    let pool = common::chat_protocol::setup_chat_protocol_db(4).await;
    let fixture = seed_fixture(&pool).await;
    let now = clock_now(&pool).await;

    let mut tx = pool.begin().await.expect("begin snapshot tx");
    // Genesis only: next_entry_seq = 2, snapshotSeq = 1.
    let at_genesis = conversation_snapshot_seq(&mut tx, fixture.conversation_id)
        .await
        .unwrap();
    assert_eq!(at_genesis, Some(1));

    // Append two more entries in this snapshot; snapshotSeq tracks the head.
    let app2 = application_append(
        &fixture,
        Uuid::new_v4(),
        b"s2".to_vec(),
        vec![0x02_u8; 32],
        vec![0x02_u8; 64],
        vec![0x02_u8; 32],
        now,
    );
    append_entry(&mut tx, &app2).await.unwrap();
    let app3 = application_append(
        &fixture,
        Uuid::new_v4(),
        b"s3".to_vec(),
        vec![0x03_u8; 32],
        vec![0x03_u8; 64],
        vec![0x03_u8; 32],
        now,
    );
    append_entry(&mut tx, &app3).await.unwrap();
    let advanced = conversation_snapshot_seq(&mut tx, fixture.conversation_id)
        .await
        .unwrap();
    assert_eq!(advanced, Some(3));

    // It is NOT the caller's afterSeq: reading a page with afterSeq=3 does not
    // change the head's snapshotSeq.
    let _ = get_entries(
        &mut tx,
        fixture.conversation_id,
        &fixture.actor_did,
        fixture.actor_device_id,
        3,
        10,
    )
    .await
    .unwrap();
    let still = conversation_snapshot_seq(&mut tx, fixture.conversation_id)
        .await
        .unwrap();
    assert_eq!(still, Some(3));

    // An unknown conversation has no head and therefore no snapshotSeq.
    assert_eq!(
        conversation_snapshot_seq(&mut tx, Uuid::new_v4())
            .await
            .unwrap(),
        None
    );

    tx.rollback().await.expect("rollback snapshot tx");
}
