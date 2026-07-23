//! Live-PostgreSQL end-to-end verification of the E2b-2/E2b-3 transition
//! executor `apply_conversation_persistence_plan` and the spine/seq-seam writers
//! it composes.
//!
//! Two kinds of coverage:
//!  * The NEW dumb-SQL writers (conversation-head insert/CAS/close, generation
//!    insert/state-version-CAS/supersede, `append_entry_at`) — column fidelity +
//!    CAS advance/conflict, inside one transaction with read-back + ROLLBACK.
//!  * The executor driven end-to-end: a REAL creation plan built through the
//!    production `plan_creation` path (with the E2b-3 `#[cfg(test)]`
//!    metadata-bearing evidence + head-CAS synthesis), applied and COMMITTED,
//!    then the full committed graph SELECT-verified past every DEFERRED trigger;
//!    plus re-apply -> conflict with zero residue, and mid-transaction failure
//!    injection -> whole-graph rollback.
//!
//! Run:
//!   TEST_DATABASE_URL=postgres://localhost/catbird_chat_protocol_test_20260722 \
//!   cargo test --test chat_protocol_executor -- --test-threads=1

#![allow(dead_code)]

mod common;

#[allow(dead_code)]
#[path = "../src/chat_protocol/model.rs"]
mod model;
#[allow(dead_code)]
#[path = "../src/chat_protocol/transcript.rs"]
mod transcript;
#[allow(dead_code)]
#[path = "../src/chat_protocol/validation.rs"]
mod validation;

mod chat_protocol {
    pub mod validation {
        pub use crate::validation::*;
    }
    pub mod transcript {
        pub use crate::transcript::*;
    }
    pub mod snapshot {
        pub use catbird_server::chat_protocol::snapshot::*;
    }
    pub mod wire {
        pub use catbird_server::chat_protocol::wire::*;
    }
    pub mod public_state {
        #![allow(dead_code)]
        include!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/src/chat_protocol/public_state.rs"
        ));
    }
    pub mod repository {
        pub mod transition {
            #![allow(dead_code)]
            include!(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/src/chat_protocol/repository/transition.rs"
            ));
        }
        pub mod delivery {
            #![allow(dead_code)]
            include!(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/src/chat_protocol/repository/delivery.rs"
            ));
        }
    }
    pub mod state_machine {
        #![allow(dead_code)]
        include!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/src/chat_protocol/state_machine.rs"
        ));
    }
}

use std::{fs, path::PathBuf};

use chrono::{DateTime, Duration, Utc};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use sqlx::PgPool;
use uuid::Uuid;

use chat_protocol::public_state::{
    verify_genesis_group_info, ActivePublicState, GenesisGroupInfoExpectations,
};
use chat_protocol::repository::delivery::{
    append_entry_at, AppendEntry, DeliveryRepositoryError, EntryEntitlementKind,
    EventEntitlementKind, EventKind, OutboxWorkKind,
};
use chat_protocol::repository::transition::ResetReason;
use chat_protocol::repository::transition::{
    cas_conversation_head, cas_generation_state_version, supersede_generation, ConversationHeadCas,
    ConversationHeadClose, GenerationStateVersionCas, GenerationSupersede, TransitionActorRole,
    TransitionRepositoryError,
};
use chat_protocol::snapshot::{PublicGroupSnapshotCoordinate, PublicGroupSnapshotLifecycle};
use chat_protocol::state_machine::{
    apply_conversation_persistence_plan, persistence_plan_for_test, plan_accept_conversation,
    plan_close, plan_creation, plan_policy, plan_reset_activation, plan_reset_request,
    AcceptConversation, CloseConversation, ControlEntryContent, ConversationHeadCasBinding,
    ConversationKind, CreationCommand, CreationDecision, DeviceIdentity, EventFanout,
    ExecutionActor, ExecutionContext, ExecutorError, LeafPersistenceColumns, MetadataAuthorColumns,
    MetadataSnapshotBinding, PrincipalId, RecoveryOpenContext, RequestEntryKind, RequestEvidence,
    ResetActivation, ResetRequestCommand, ResetRequestRow, ServerTimestamp, SpineArtifacts,
    TransitionEvidence,
};
use chat_protocol::validation::ed25519_key_id;

// ---------------------------------------------------------------------------
// Harness + corpus fixtures (adapted from tests/chat_protocol_state_machine.rs).
// ---------------------------------------------------------------------------

async fn setup() -> PgPool {
    common::chat_protocol::setup_chat_protocol_db(4).await
}

async fn clock_now(pool: &PgPool) -> DateTime<Utc> {
    sqlx::query_scalar("SELECT clock_timestamp()")
        .fetch_one(pool)
        .await
        .expect("sample trusted database clock")
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct CorpusManifest {
    evaluation_unix_seconds: u64,
    identifiers: CorpusIdentifiers,
    identity: CorpusIdentity,
    chain: CorpusChain,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct CorpusIdentifiers {
    conversation_id_hex: String,
}
#[derive(Deserialize)]
struct CorpusIdentity {
    alice: CorpusActor,
    bob: CorpusActor,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct CorpusActor {
    actor_did: String,
    device_id: String,
    credential_identity: String,
    signature_public_key_hex: String,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct CorpusChain {
    generation: u64,
    genesis_state_version: u64,
    genesis_epoch: u64,
    genesis_group_context_hash_hex: String,
    genesis_confirmation_tag_hex: String,
    group_id_hex: String,
}

fn corpus_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../docs/generated-artifacts/mls-chat-v1/crypto-wire")
}
fn corpus_file(name: &str) -> Vec<u8> {
    fs::read(corpus_dir().join(name)).expect("read frozen crypto-wire corpus")
}
fn corpus_manifest() -> CorpusManifest {
    serde_json::from_slice(&corpus_file("manifest.json")).expect("parse frozen manifest")
}
fn hex_array<const N: usize>(value: &str) -> [u8; N] {
    hex::decode(value)
        .expect("valid fixture hex")
        .try_into()
        .unwrap_or_else(|_| panic!("expected {N}-byte fixture"))
}
fn uuid_bytes(value: &str) -> [u8; 16] {
    *Uuid::parse_str(value).expect("fixture UUID").as_bytes()
}
fn uuid_v4_bytes(byte: u8) -> [u8; 16] {
    let mut value = [byte; 16];
    value[6] = 0x40 | (byte & 0x0f);
    value[8] = 0x80 | (byte & 0x3f);
    value
}

fn genesis_coordinate(manifest: &CorpusManifest) -> PublicGroupSnapshotCoordinate {
    PublicGroupSnapshotCoordinate::new(
        hex_array(&manifest.identifiers.conversation_id_hex),
        manifest.chain.generation,
        manifest.chain.genesis_state_version,
        hex_array(&manifest.chain.group_id_hex),
        manifest.chain.genesis_epoch,
        hex_array(&manifest.chain.genesis_group_context_hash_hex),
        hex_array(&manifest.chain.genesis_confirmation_tag_hex),
        PublicGroupSnapshotLifecycle::Active,
    )
}

fn coordinate_with_conversation(
    source: &PublicGroupSnapshotCoordinate,
    conversation_id: [u8; 16],
) -> PublicGroupSnapshotCoordinate {
    PublicGroupSnapshotCoordinate::new(
        conversation_id,
        source.generation(),
        source.state_version(),
        *source.group_id(),
        source.epoch(),
        *source.group_context_hash(),
        *source.confirmation_tag(),
        source.lifecycle(),
    )
}

fn alice(manifest: &CorpusManifest) -> DeviceIdentity {
    DeviceIdentity::new(
        PrincipalId::new(manifest.identity.alice.actor_did.as_bytes().to_vec()).unwrap(),
        uuid_bytes(&manifest.identity.alice.device_id),
    )
    .unwrap()
}
/// A FRESH invitee each run. Only the creator (alice) must match the corpus
/// genesis leaf; the pending invitee is an arbitrary principal, so a random DID
/// keeps the direct-pair unique index (and bob's global event chain) collision-
/// free across runs of this never-truncated, delete-forbidding database.
fn fresh_bob() -> (DeviceIdentity, String) {
    let did = random_plc_did();
    let device = DeviceIdentity::new(
        PrincipalId::new(did.as_bytes().to_vec()).unwrap(),
        *Uuid::new_v4().as_bytes(),
    )
    .unwrap();
    (device, did)
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

fn verified_genesis(manifest: &CorpusManifest) -> ActivePublicState {
    verify_genesis_group_info(
        &corpus_file("group-info.mls"),
        GenesisGroupInfoExpectations {
            coordinate: genesis_coordinate(manifest),
            expected_basic_credential: manifest.identity.alice.credential_identity.as_bytes(),
            expected_signature_key: &hex::decode(&manifest.identity.alice.signature_public_key_hex)
                .expect("signature key"),
            now_unix_seconds: manifest.evaluation_unix_seconds,
            max_wire_bytes: 1_048_576,
            max_ratchet_tree_bytes: 1_048_576,
            max_members: 100,
        },
    )
    .expect("frozen GroupInfo verifies and binds")
}

/// Idempotently seed a principal + active device + device-key row (committed).
async fn seed_actor(
    pool: &PgPool,
    user_did: &str,
    device_id: Uuid,
    signing_public_key: &[u8],
) -> String {
    let now = clock_now(pool).await;
    let key_id: String = sqlx::query_scalar("SELECT chat.ed25519_key_id($1)")
        .bind(signing_public_key)
        .fetch_one(pool)
        .await
        .expect("derive key id");
    sqlx::query(
        "INSERT INTO chat.principals(user_did,created_at) VALUES($1,$2) ON CONFLICT DO NOTHING",
    )
    .bind(user_did)
    .bind(now)
    .execute(pool)
    .await
    .expect("seed principal");
    sqlx::query(
        "INSERT INTO chat.devices(user_did,device_id,device_name,status,dpop_jkt,auth_generation,capabilities,created_at,updated_at) \
         VALUES($1,$2,'actor','active',$3,1,chat.protocol_capabilities(),$4,$4) ON CONFLICT DO NOTHING",
    )
    .bind(user_did)
    .bind(device_id)
    .bind(&key_id)
    .bind(now)
    .execute(pool)
    .await
    .expect("seed device");
    sqlx::query(
        "INSERT INTO chat.device_keys(user_did,device_id,key_id,signing_public_key,enrollment_auth_generation,created_at) \
         VALUES($1,$2,$3,$4,1,$5) ON CONFLICT DO NOTHING",
    )
    .bind(user_did)
    .bind(device_id)
    .bind(&key_id)
    .bind(signing_public_key)
    .bind(now)
    .execute(pool)
    .await
    .expect("seed device key");
    key_id
}

async fn seed_protocol_instance(pool: &PgPool) -> Uuid {
    let id = uuid_v4_bytes(0x51);
    let cursor_key: String = sqlx::query_scalar("SELECT chat.ed25519_key_id($1)")
        .bind(vec![0x51_u8; 32])
        .fetch_one(pool)
        .await
        .expect("derive cursor key");
    sqlx::query(
        "INSERT INTO chat.protocol_instances(singleton,protocol_version,protocol_instance_id,cursor_key_id) \
         VALUES(TRUE,'1',$1,$2) ON CONFLICT DO NOTHING",
    )
    .bind(Uuid::from_bytes(id))
    .bind(&cursor_key)
    .execute(pool)
    .await
    .expect("seed protocol instance");
    sqlx::query_scalar("SELECT protocol_instance_id FROM chat.protocol_instances")
        .fetch_one(pool)
        .await
        .expect("read protocol instance id")
}

/// Everything a creation apply needs: the built plan + a coherent ctx + the
/// identifiers a SELECT-verify uses.
struct CreationApply {
    plan: chat_protocol::state_machine::ConversationPersistencePlan,
    ctx: ExecutionContext,
    conversation_id: Uuid,
    alice_did: String,
    alice_device: Uuid,
    // Carried for the follow-on policy edge.
    state: chat_protocol::state_machine::ConversationState,
    alice_id: DeviceIdentity,
    alice_key_id: String,
    bob_id: DeviceIdentity,
    bob_did: String,
    bob_key_id: String,
    coordinate: PublicGroupSnapshotCoordinate,
    protocol_instance_id: Uuid,
    /// The creation transition id — the invitation provenance a later acceptance
    /// must echo (bob's pending invitation was minted by this transition).
    creation_transition_id: [u8; 16],
}

async fn build_creation(pool: &PgPool, kind: ConversationKind) -> CreationApply {
    let manifest = corpus_manifest();
    let alice_id = alice(&manifest);
    let (bob_id, bob_did) = fresh_bob();
    let alice_did = manifest.identity.alice.actor_did.clone();
    let alice_device = Uuid::from_bytes(*alice_id.device_id());
    let bob_device = Uuid::from_bytes(*bob_id.device_id());
    let alice_sig_key: Vec<u8> =
        hex::decode(&manifest.identity.alice.signature_public_key_hex).unwrap();
    // Alice's MLS leaf signature key is also her device signing key here, so
    // member_devices.leaf_key_id == device_keys.key_id == actor_key_id.
    let alice_key_id = seed_actor(pool, &alice_did, alice_device, &alice_sig_key).await;
    // Bob is a FRESH principal each run; give him a fresh unique signing key so his
    // `chat.device_keys` row (unique on `key_id`) is always present this run — a
    // constant key would collide with a prior run's bob and be skipped, leaving
    // this bob with no device key (which the recovery mapping trigger requires).
    let bob_sig_key = random_ref32().to_vec();
    let bob_key_id = seed_actor(pool, &bob_did, bob_device, &bob_sig_key).await;
    let protocol_instance_id = seed_protocol_instance(pool).await;

    // Fresh conversation id per run (the corpus id is fixed; rebind onto a fresh
    // one so committed rows never collide across runs).
    let conversation_id = Uuid::new_v4();
    let template = verified_genesis(&manifest);
    let coordinate =
        coordinate_with_conversation(&genesis_coordinate(&manifest), *conversation_id.as_bytes());
    let public_state = ActivePublicState::for_test(&template, coordinate);

    let transition_id = Uuid::new_v4();
    let entry_id = Uuid::new_v4();
    let received_at = ServerTimestamp::from_unix_millis_for_test(
        manifest.evaluation_unix_seconds as i64 * 1_000 + 1_000,
    )
    .unwrap();
    let nonce = [0x77_u8; 12];
    let ciphertext = vec![0x88_u8; 48];
    let alice_key_id_bytes: [u8; 32] = {
        let mut buf = [0u8; 32];
        let digest = Sha256::digest(&alice_sig_key);
        buf.copy_from_slice(&digest);
        buf
    };
    let metadata = MetadataSnapshotBinding::for_test_creation(
        *conversation_id.as_bytes(),
        0,
        *coordinate.group_context_hash(),
        *transition_id.as_bytes(),
        1,
        alice_id.clone(),
        alice_key_id_bytes,
        alice_sig_key.clone().try_into().unwrap(),
        1,
        1,
        nonce,
        ciphertext.clone(),
    );
    let evidence = TransitionEvidence::for_test_creation_with_metadata(
        1,
        *transition_id.as_bytes(),
        [0x11_u8; 32],
        received_at,
        kind,
        coordinate,
        alice_id.clone(),
        metadata,
    )
    .unwrap();

    let decision = plan_creation(
        None,
        CreationCommand {
            kind,
            creator: alice_id.clone(),
            invitees: vec![bob_id.principal().clone()],
            transition: evidence,
            public_state,
        },
    )
    .expect("valid creation plan");
    let planned = match decision {
        CreationDecision::Create(planned) => planned,
        CreationDecision::ExistingDirect { .. } => panic!("fresh creation expected"),
    };
    let creation_state = planned.resulting_state().clone();
    let head_cas = ConversationHeadCasBinding::for_test_creation(
        *conversation_id.as_bytes(),
        *entry_id.as_bytes(),
        received_at,
    );
    let plan = persistence_plan_for_test(planned, head_cas);

    let applied_at = clock_now(pool).await;
    let accepted_payload = vec![0x21_u8; 24];
    let transcript = vec![0x22_u8; 24];
    let ctx = ExecutionContext {
        protocol_instance_id,
        applied_at,
        actor: ExecutionActor {
            user_did: alice_did.clone(),
            device_id: alice_device,
            key_id: alice_key_id.clone(),
            auth_generation: 1,
            role: TransitionActorRole::Admin,
            device_status: "active".to_owned(),
        },
        entry: ControlEntryContent {
            entry_id,
            entry_kind: "blue.catbird.chat.defs#creationEntry".to_owned(),
            accepted_payload_bytes: accepted_payload.clone(),
            accepted_payload_sha256: Sha256::digest(&accepted_payload).to_vec(),
            signed_request_bytes: transcript.clone(),
            unsigned_projection_bytes: vec![0x23_u8; 16],
            signing_transcript_bytes: transcript.clone(),
            request_digest: Sha256::digest(&transcript).to_vec(),
            signature: vec![0x24_u8; 64],
            server_fields_bytes: vec![0x25_u8; 8],
            outer_entry_fingerprint: vec![0x11_u8; 32],
        },
        spine: SpineArtifacts {
            public_snapshot_bytes: vec![0x31_u8; 16],
            public_snapshot_sha256: Sha256::digest([0x31_u8; 16]).to_vec(),
            tree_summary_bytes: vec![0x32_u8; 16],
            tree_summary_sha256: Sha256::digest([0x32_u8; 16]).to_vec(),
            leaf_count: 1,
            genesis_group_info_bytes: vec![0x33_u8; 16],
            genesis_group_info_sha256: Sha256::digest([0x33_u8; 16]).to_vec(),
        },
        opened_leaves: vec![LeafPersistenceColumns {
            device: alice_id.clone(),
            leaf_key_id: alice_key_id.clone(),
            leaf_auth_generation: 1,
        }],
        metadata_author: Some(MetadataAuthorColumns {
            author_role: "admin".to_owned(),
            author_device_status: "active".to_owned(),
            author_public_key: alice_sig_key.clone(),
            metadata_snapshot_id: Uuid::new_v4(),
        }),
        participant_period_ids: vec![Uuid::new_v4(), Uuid::new_v4()],
        leaf_period_ids: vec![Uuid::new_v4()],
        entry_recipients: entry_audience(&alice_id, &alice_did, &bob_id, &bob_did),
        events: vec![EventFanout {
            event_id: Uuid::new_v4(),
            event_kind: EventKind::ConversationChanged,
            payload_bytes: vec![0x41_u8; 8],
            recipients: event_audience(pool, &alice_id, &alice_did, &bob_id, &bob_did).await,
            outbox: vec![(Uuid::new_v4(), OutboxWorkKind::Stream)],
        }],
        closing_leaf_periods: Vec::new(),
        reset_request_row: None,
        recovery_open: None,
    };

    CreationApply {
        plan,
        ctx,
        conversation_id,
        alice_did,
        alice_device,
        state: creation_state,
        alice_id,
        alice_key_id,
        bob_id,
        bob_did,
        bob_key_id,
        coordinate,
        protocol_instance_id,
        creation_transition_id: *transition_id.as_bytes(),
    }
}

fn entry_audience(
    a: &DeviceIdentity,
    a_did: &str,
    b: &DeviceIdentity,
    b_did: &str,
) -> Vec<(DeviceIdentity, EntryEntitlementKind)> {
    let mut rows = vec![(a.clone(), a_did.to_owned()), (b.clone(), b_did.to_owned())];
    rows.sort_by(|l, r| (l.1.as_bytes(), l.0.device_id()).cmp(&(r.1.as_bytes(), r.0.device_id())));
    rows.into_iter()
        .map(|(d, _)| (d, EntryEntitlementKind::Control))
        .collect()
}

/// The `chat.event_recipients` chain trigger requires each device's new audience
/// row to point at that device's current max `event_position` (NULL only for a
/// device with no prior events). The fixed corpus DIDs accumulate events across
/// runs, so chain each recipient to its real predecessor — exactly what the
/// facade would compute.
async fn event_audience(
    pool: &PgPool,
    a: &DeviceIdentity,
    a_did: &str,
    b: &DeviceIdentity,
    b_did: &str,
) -> Vec<(DeviceIdentity, EventEntitlementKind, Option<i64>)> {
    let mut rows = vec![(a.clone(), a_did.to_owned()), (b.clone(), b_did.to_owned())];
    rows.sort_by(|l, r| (l.1.as_bytes(), l.0.device_id()).cmp(&(r.1.as_bytes(), r.0.device_id())));
    let mut out = Vec::with_capacity(rows.len());
    for (device, did) in rows {
        let predecessor: Option<i64> = sqlx::query_scalar(
            "SELECT max(event_position) FROM chat.event_recipients WHERE user_did=$1 AND device_id=$2",
        )
        .bind(&did)
        .bind(Uuid::from_bytes(*device.device_id()))
        .fetch_one(pool)
        .await
        .expect("read device event predecessor");
        out.push((device, EventEntitlementKind::Participant, predecessor));
    }
    out
}

/// Pre-clean any leftover ACTIVE direct conversation for the fixed corpus pair
/// so the `conversations_active_direct_pair_uq` does not collide across runs.
async fn preclean_direct_pair(pool: &PgPool, did_a: &str, did_b: &str) {
    let (low, high) = if did_a <= did_b {
        (did_a, did_b)
    } else {
        (did_b, did_a)
    };
    let ids: Vec<Uuid> = sqlx::query_scalar(
        "SELECT conversation_id FROM chat.conversations WHERE direct_did_low=$1 AND direct_did_high=$2",
    )
    .bind(low)
    .bind(high)
    .fetch_all(pool)
    .await
    .unwrap_or_default();
    for id in ids {
        cleanup(pool, id).await;
    }
}

fn rand_byte() -> u8 {
    use std::cell::Cell;
    thread_local!(static SEED: Cell<u64> = Cell::new(0x9E37_79B9_7F4A_7C15));
    SEED.with(|s| {
        let mut x = s.get();
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        s.set(x);
        ((x >> 24) as u8) | 0x40
    })
}

// ===========================================================================
// New-writer verification (tx + read-back + ROLLBACK).
// ===========================================================================

async fn seed_group_head_tx(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    at: DateTime<Utc>,
) -> Uuid {
    let conversation_id = Uuid::new_v4();
    let group_id = vec![1_u8; 32];
    let group_info = vec![4_u8; 8];
    let transition_id = Uuid::new_v4();
    let snapshot = vec![5_u8; 8];
    let tree = vec![6_u8; 8];
    sqlx::query(
        "INSERT INTO chat.conversations(conversation_id,kind,lifecycle,current_generation,current_state_version,next_entry_seq,created_at) \
         VALUES($1,'group','active',0,0,2,$2)",
    )
    .bind(conversation_id)
    .bind(at)
    .execute(&mut **tx)
    .await
    .expect("seed head");
    sqlx::query(
        "INSERT INTO chat.generations(conversation_id,generation,group_id,lifecycle,genesis_group_info_bytes,genesis_group_info_sha256,current_state_version,activated_seq,activated_at) \
         VALUES($1,0,$2,'active',$3,$4,0,1,$5)",
    )
    .bind(conversation_id)
    .bind(&group_id)
    .bind(&group_info)
    .bind(Sha256::digest(&group_info).to_vec())
    .bind(at)
    .execute(&mut **tx)
    .await
    .expect("seed generation");
    sqlx::query(
        r#"INSERT INTO chat.generation_states(
            conversation_id,generation,state_version,group_id,epoch,group_context_hash,
            confirmation_tag,lifecycle,state_kind,producing_transition_id,public_snapshot_bytes,
            snapshot_sha256,tree_summary_bytes,tree_summary_sha256,leaf_count,created_at
        ) VALUES($1,0,0,$2,0,$3,$4,'active','creation',$5,$6,$7,$8,$9,1,$10)"#,
    )
    .bind(conversation_id)
    .bind(&group_id)
    .bind(vec![2_u8; 32])
    .bind(vec![3_u8; 32])
    .bind(transition_id)
    .bind(&snapshot)
    .bind(Sha256::digest(&snapshot).to_vec())
    .bind(&tree)
    .bind(Sha256::digest(&tree).to_vec())
    .bind(at)
    .execute(&mut **tx)
    .await
    .expect("seed generation state");
    conversation_id
}

#[tokio::test]
async fn conversation_head_cas_advances_and_conflicts_on_drift() {
    let pool = setup().await;
    let mut tx = pool.begin().await.expect("begin");
    let at = clock_now(&pool).await;
    let conversation_id = seed_group_head_tx(&mut tx, at).await;
    cas_conversation_head(
        &mut tx,
        &ConversationHeadCas {
            conversation_id,
            expected_generation: 0,
            expected_state_version: 0,
            expected_next_entry_seq: 2,
            successor_generation: 0,
            successor_state_version: 1,
            successor_next_entry_seq: 3,
            close: None,
        },
    )
    .await
    .expect("advance head");
    let (sv, next_seq): (i64, i64) = sqlx::query_as(
        "SELECT current_state_version,next_entry_seq FROM chat.conversations WHERE conversation_id=$1",
    )
    .bind(conversation_id)
    .fetch_one(&mut *tx)
    .await
    .expect("read advanced head");
    assert_eq!((sv, next_seq), (1, 3));
    let conflict = cas_conversation_head(
        &mut tx,
        &ConversationHeadCas {
            conversation_id,
            expected_generation: 0,
            expected_state_version: 0,
            expected_next_entry_seq: 2,
            successor_generation: 0,
            successor_state_version: 1,
            successor_next_entry_seq: 3,
            close: None,
        },
    )
    .await;
    assert!(matches!(
        conflict,
        Err(TransitionRepositoryError::CompareAndSetConflict)
    ));
    tx.rollback().await.expect("rollback");
}

#[tokio::test]
async fn conversation_head_close_and_generation_supersede() {
    let pool = setup().await;
    let mut tx = pool.begin().await.expect("begin");
    let at = clock_now(&pool).await;
    let conversation_id = seed_group_head_tx(&mut tx, at).await;
    let close_transition_id = Uuid::new_v4();
    cas_conversation_head(
        &mut tx,
        &ConversationHeadCas {
            conversation_id,
            expected_generation: 0,
            expected_state_version: 0,
            expected_next_entry_seq: 2,
            successor_generation: 0,
            successor_state_version: 1,
            successor_next_entry_seq: 3,
            close: Some(ConversationHeadClose {
                close_transition_id,
                close_generation: 0,
                close_state_version: 1,
                close_seq: 2,
                closed_at: at,
            }),
        },
    )
    .await
    .expect("close head");
    supersede_generation(
        &mut tx,
        &GenerationSupersede {
            conversation_id,
            generation: 0,
            expected_state_version: 0,
            successor_state_version: 1,
            superseded_seq: 2,
            superseded_at: at,
        },
    )
    .await
    .expect("supersede generation");
    let (lifecycle, ct): (String, Option<Uuid>) = sqlx::query_as(
        "SELECT lifecycle,close_transition_id FROM chat.conversations WHERE conversation_id=$1",
    )
    .bind(conversation_id)
    .fetch_one(&mut *tx)
    .await
    .expect("read closed head");
    assert_eq!(lifecycle, "superseded");
    assert_eq!(ct, Some(close_transition_id));
    let gen_life: String = sqlx::query_scalar(
        "SELECT lifecycle FROM chat.generations WHERE conversation_id=$1 AND generation=0",
    )
    .bind(conversation_id)
    .fetch_one(&mut *tx)
    .await
    .expect("read gen");
    assert_eq!(gen_life, "superseded");
    tx.rollback().await.expect("rollback");
}

#[tokio::test]
async fn generation_state_version_cas_is_guarded() {
    let pool = setup().await;
    let mut tx = pool.begin().await.expect("begin");
    let at = clock_now(&pool).await;
    let conversation_id = seed_group_head_tx(&mut tx, at).await;
    cas_generation_state_version(
        &mut tx,
        &GenerationStateVersionCas {
            conversation_id,
            generation: 0,
            expected_state_version: 0,
            successor_state_version: 1,
        },
    )
    .await
    .expect("advance pointer");
    let conflict = cas_generation_state_version(
        &mut tx,
        &GenerationStateVersionCas {
            conversation_id,
            generation: 0,
            expected_state_version: 0,
            successor_state_version: 1,
        },
    )
    .await;
    assert!(matches!(
        conflict,
        Err(TransitionRepositoryError::CompareAndSetConflict)
    ));
    tx.rollback().await.expect("rollback");
}

#[tokio::test]
async fn append_entry_at_inserts_at_exact_seq_without_touching_head() {
    let pool = setup().await;
    let mut tx = pool.begin().await.expect("begin");
    let at = clock_now(&pool).await;
    let conversation_id = seed_group_head_tx(&mut tx, at).await;
    let user_did = format!("did:plc:{}", "a".repeat(24));
    sqlx::query(
        "INSERT INTO chat.principals(user_did,created_at) VALUES($1,$2) ON CONFLICT DO NOTHING",
    )
    .bind(&user_did)
    .bind(at)
    .execute(&mut *tx)
    .await
    .expect("principal");
    let device_id = Uuid::new_v4();
    let pubkey = vec![0x99_u8; 32];
    let key_id: String = sqlx::query_scalar("SELECT chat.ed25519_key_id($1)")
        .bind(&pubkey)
        .fetch_one(&mut *tx)
        .await
        .expect("key id");
    sqlx::query(
        "INSERT INTO chat.devices(user_did,device_id,device_name,status,dpop_jkt,auth_generation,capabilities,created_at,updated_at) \
         VALUES($1,$2,'a','active',$3,1,chat.protocol_capabilities(),$4,$4) ON CONFLICT DO NOTHING",
    )
    .bind(&user_did)
    .bind(device_id)
    .bind(&key_id)
    .bind(at)
    .execute(&mut *tx)
    .await
    .expect("device");
    sqlx::query(
        "INSERT INTO chat.device_keys(user_did,device_id,key_id,signing_public_key,enrollment_auth_generation,created_at) \
         VALUES($1,$2,$3,$4,1,$5)",
    )
    .bind(&user_did)
    .bind(device_id)
    .bind(&key_id)
    .bind(&pubkey)
    .bind(at)
    .execute(&mut *tx)
    .await
    .expect("device key");

    let payload = vec![21_u8; 8];
    let transcript = vec![22_u8; 8];
    let returned = append_entry_at(
        &mut tx,
        &AppendEntry {
            conversation_id,
            entry_id: Uuid::new_v4(),
            entry_kind: "blue.catbird.chat.defs#creationEntry".to_owned(),
            accepted_payload_bytes: payload.clone(),
            accepted_payload_sha256: Sha256::digest(&payload).to_vec(),
            signed_request_bytes: transcript.clone(),
            request_digest: Sha256::digest(&transcript).to_vec(),
            signature: vec![23_u8; 64],
            server_fields_bytes: vec![24_u8; 4],
            outer_entry_fingerprint: vec![25_u8; 32],
            actor_did: user_did.clone(),
            actor_device_id: device_id,
            actor_key_id: key_id.clone(),
            actor_auth_generation: 1,
            generation: Some(0),
            state_version: Some(0),
            transition_id: Some(Uuid::new_v4()),
            message_id: None,
            received_at: at,
        },
        1,
    )
    .await
    .expect("append entry at seq 1");
    assert_eq!(returned, 1);
    let head_seq: i64 = sqlx::query_scalar(
        "SELECT next_entry_seq FROM chat.conversations WHERE conversation_id=$1",
    )
    .bind(conversation_id)
    .fetch_one(&mut *tx)
    .await
    .expect("read head seq");
    assert_eq!(head_seq, 2);
    let _ = DeliveryRepositoryError::SequenceOverflow;
    tx.rollback().await.expect("rollback");
}

// ===========================================================================
// Executor end-to-end: creation -> COMMIT -> SELECT-verify.
// ===========================================================================

async fn count(pool: &PgPool, sql: &str, conversation_id: Uuid) -> i64 {
    sqlx::query_scalar(sql)
        .bind(conversation_id)
        .fetch_one(pool)
        .await
        .expect("count")
}

#[tokio::test]
async fn group_creation_commits_full_graph_past_all_deferred_triggers() {
    let pool = setup().await;
    let fixture = build_creation(&pool, ConversationKind::Group).await;
    let conversation_id = fixture.conversation_id;

    let mut tx = pool.begin().await.expect("begin");
    let applied = apply_conversation_persistence_plan(&mut tx, &fixture.plan, &fixture.ctx)
        .await
        .expect("creation applies");
    tx.commit()
        .await
        .expect("COMMIT past all deferred triggers");

    assert_eq!(applied.allocated_seq, 1);
    assert_eq!(applied.event_positions.len(), 1);

    let (kind, lifecycle, gen, sv, next_seq): (String, String, i64, i64, i64) = sqlx::query_as(
        "SELECT kind,lifecycle,current_generation,current_state_version,next_entry_seq FROM chat.conversations WHERE conversation_id=$1",
    )
    .bind(conversation_id)
    .fetch_one(&pool)
    .await
    .expect("head");
    assert_eq!(
        (kind.as_str(), lifecycle.as_str(), gen, sv, next_seq),
        ("group", "active", 0, 0, 2)
    );

    assert_eq!(
        count(
            &pool,
            "SELECT count(*) FROM chat.generations WHERE conversation_id=$1",
            conversation_id
        )
        .await,
        1
    );
    let (state_kind, leaf_count): (String, i64) = sqlx::query_as(
        "SELECT state_kind,leaf_count FROM chat.generation_states WHERE conversation_id=$1",
    )
    .bind(conversation_id)
    .fetch_one(&pool)
    .await
    .expect("gen state");
    assert_eq!((state_kind.as_str(), leaf_count), ("creation", 1));

    let (tkind, entry_seq): (String, i64) =
        sqlx::query_as("SELECT kind,entry_seq FROM chat.transitions WHERE conversation_id=$1")
            .bind(conversation_id)
            .fetch_one(&pool)
            .await
            .expect("transition");
    assert_eq!((tkind.as_str(), entry_seq), ("creation", 1));
    let (eseq, ekind): (i64, String) =
        sqlx::query_as("SELECT seq,entry_kind FROM chat.entries WHERE conversation_id=$1")
            .bind(conversation_id)
            .fetch_one(&pool)
            .await
            .expect("entry");
    assert_eq!(
        (eseq, ekind.as_str()),
        (1, "blue.catbird.chat.defs#creationEntry")
    );

    assert_eq!(
        count(
            &pool,
            "SELECT count(*) FROM chat.metadata_snapshots WHERE conversation_id=$1",
            conversation_id
        )
        .await,
        1
    );

    let (active_admin, pending_member): (i64, i64) = sqlx::query_as(
        "SELECT count(*) FILTER (WHERE status='active' AND role='admin'), count(*) FILTER (WHERE status='pending' AND role='member') \
         FROM chat.participants WHERE conversation_id=$1 AND current_membership",
    )
    .bind(conversation_id)
    .fetch_one(&pool)
    .await
    .expect("participants");
    assert_eq!((active_admin, pending_member), (1, 1));

    let leaf_origin: String =
        sqlx::query_scalar("SELECT origin FROM chat.member_devices WHERE conversation_id=$1")
            .bind(conversation_id)
            .fetch_one(&pool)
            .await
            .expect("leaf");
    assert_eq!(leaf_origin, "genesis");

    let (start_seq, opening_kind, terminal): (i64, String, Option<i64>) = sqlx::query_as(
        "SELECT start_seq,opening_kind,terminal_seq FROM chat.application_intervals WHERE conversation_id=$1",
    )
    .bind(conversation_id)
    .fetch_one(&pool)
    .await
    .expect("interval");
    assert_eq!(
        (start_seq, opening_kind.as_str(), terminal),
        (1, "creation", None)
    );

    assert_eq!(
        count(
            &pool,
            "SELECT count(*) FROM chat.entry_recipients WHERE conversation_id=$1 AND seq=1",
            conversation_id
        )
        .await,
        2
    );
    let position = applied.event_positions[0];
    let evt_kind: String =
        sqlx::query_scalar("SELECT event_kind FROM chat.events WHERE event_position=$1")
            .bind(position)
            .fetch_one(&pool)
            .await
            .expect("event");
    assert_eq!(evt_kind, "conversationChanged");
    let evt_recips: i64 =
        sqlx::query_scalar("SELECT count(*) FROM chat.event_recipients WHERE event_position=$1")
            .bind(position)
            .fetch_one(&pool)
            .await
            .expect("event recips");
    assert_eq!(evt_recips, 2);
    let outbox: i64 =
        sqlx::query_scalar("SELECT count(*) FROM chat.outbox WHERE event_position=$1")
            .bind(position)
            .fetch_one(&pool)
            .await
            .expect("outbox");
    assert_eq!(outbox, 1);

    // Re-apply the SAME plan -> the head INSERT collides on the conversation PK
    // (true-absence CAS), the whole transaction rolls back, zero new residue.
    let before: i64 =
        sqlx::query_scalar("SELECT count(*) FROM chat.transitions WHERE conversation_id=$1")
            .bind(conversation_id)
            .fetch_one(&pool)
            .await
            .unwrap();
    let mut tx2 = pool.begin().await.expect("begin re-apply");
    let reapply = apply_conversation_persistence_plan(&mut tx2, &fixture.plan, &fixture.ctx).await;
    assert!(
        matches!(reapply, Err(ExecutorError::Transition(_))),
        "re-apply must conflict on the head PK"
    );
    tx2.rollback().await.expect("rollback re-apply");
    let after: i64 =
        sqlx::query_scalar("SELECT count(*) FROM chat.transitions WHERE conversation_id=$1")
            .bind(conversation_id)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(before, after, "re-apply left zero residue");
}

#[tokio::test]
async fn group_policy_add_participant_commits_state_version_plus_one() {
    let pool = setup().await;
    let fixture = build_creation(&pool, ConversationKind::Group).await;
    let conversation_id = fixture.conversation_id;

    // 1. Commit the creation the policy edge builds on.
    let mut tx = pool.begin().await.expect("begin creation");
    apply_conversation_persistence_plan(&mut tx, &fixture.plan, &fixture.ctx)
        .await
        .expect("creation applies");
    tx.commit().await.expect("creation COMMIT");

    // 2. A fresh third principal to add; seed it (participant + audience FKs).
    let (bob2_id, bob2_did) = fresh_bob();
    let bob2_device = Uuid::from_bytes(*bob2_id.device_id());
    let _ = seed_actor(&pool, &bob2_did, bob2_device, &[0x63_u8; 32]).await;

    // 3. Build the REAL policy plan through the production planner.
    let received_at = ServerTimestamp::from_unix_millis_for_test(
        corpus_manifest().evaluation_unix_seconds as i64 * 1_000 + 2_000,
    )
    .unwrap();
    let entry_id = Uuid::new_v4();
    let transition_id = Uuid::new_v4();
    let policy_evidence = TransitionEvidence::for_test_policy_add(
        2,
        *transition_id.as_bytes(),
        [0x12_u8; 32],
        received_at,
        fixture.coordinate,
        vec![bob2_id.principal().clone()],
    )
    .unwrap();
    let planned = plan_policy(
        &fixture.state,
        fixture.alice_id.clone(),
        policy_evidence,
        [0x99_u8; 32],
    )
    .expect("valid policy plan");
    let head_cas = ConversationHeadCasBinding::for_test_edge(
        *conversation_id.as_bytes(),
        *entry_id.as_bytes(),
        fixture.coordinate,
        2,
        received_at,
    );
    let plan = persistence_plan_for_test(planned, head_cas);

    // 4. Policy ctx: same actor (alice), policyEntry at seq 2, no metadata, one
    //    new pending participant, audience = the three current devices.
    let applied_at = clock_now(&pool).await;
    let payload = vec![0x51_u8; 12];
    let transcript = vec![0x52_u8; 12];
    let recipients_devices = [
        (fixture.alice_id.clone(), fixture.alice_did.clone()),
        (fixture.bob_id.clone(), fixture.bob_did.clone()),
        (bob2_id.clone(), bob2_did.clone()),
    ];
    let mut sorted = recipients_devices.to_vec();
    sorted
        .sort_by(|l, r| (l.1.as_bytes(), l.0.device_id()).cmp(&(r.1.as_bytes(), r.0.device_id())));
    let entry_recipients = sorted
        .iter()
        .map(|(d, _)| (d.clone(), EntryEntitlementKind::Control))
        .collect();
    let mut event_recips = Vec::new();
    for (device, did) in &sorted {
        let predecessor: Option<i64> = sqlx::query_scalar(
            "SELECT max(event_position) FROM chat.event_recipients WHERE user_did=$1 AND device_id=$2",
        )
        .bind(did)
        .bind(Uuid::from_bytes(*device.device_id()))
        .fetch_one(&pool)
        .await
        .expect("predecessor");
        event_recips.push((
            device.clone(),
            EventEntitlementKind::Participant,
            predecessor,
        ));
    }
    let ctx = ExecutionContext {
        protocol_instance_id: fixture.protocol_instance_id,
        applied_at,
        actor: ExecutionActor {
            user_did: fixture.alice_did.clone(),
            device_id: fixture.alice_device,
            key_id: fixture.alice_key_id.clone(),
            auth_generation: 1,
            role: TransitionActorRole::Admin,
            device_status: "active".to_owned(),
        },
        entry: ControlEntryContent {
            entry_id,
            entry_kind: "blue.catbird.chat.defs#policyEntry".to_owned(),
            accepted_payload_bytes: payload.clone(),
            accepted_payload_sha256: Sha256::digest(&payload).to_vec(),
            signed_request_bytes: transcript.clone(),
            unsigned_projection_bytes: vec![0x53_u8; 8],
            signing_transcript_bytes: transcript.clone(),
            request_digest: Sha256::digest(&transcript).to_vec(),
            signature: vec![0x54_u8; 64],
            server_fields_bytes: vec![0x55_u8; 8],
            outer_entry_fingerprint: vec![0x12_u8; 32],
        },
        spine: SpineArtifacts {
            public_snapshot_bytes: vec![0x61_u8; 16],
            public_snapshot_sha256: Sha256::digest([0x61_u8; 16]).to_vec(),
            tree_summary_bytes: vec![0x62_u8; 16],
            tree_summary_sha256: Sha256::digest([0x62_u8; 16]).to_vec(),
            leaf_count: 1,
            genesis_group_info_bytes: vec![],
            genesis_group_info_sha256: vec![],
        },
        opened_leaves: vec![],
        metadata_author: None,
        participant_period_ids: vec![Uuid::new_v4()],
        leaf_period_ids: vec![],
        entry_recipients,
        events: vec![EventFanout {
            event_id: Uuid::new_v4(),
            event_kind: EventKind::ConversationChanged,
            payload_bytes: vec![0x71_u8; 8],
            recipients: event_recips,
            outbox: vec![(Uuid::new_v4(), OutboxWorkKind::Stream)],
        }],
        closing_leaf_periods: Vec::new(),
        reset_request_row: None,
        recovery_open: None,
    };

    // 5. Apply + COMMIT the policy edge.
    let mut tx2 = pool.begin().await.expect("begin policy");
    let applied = apply_conversation_persistence_plan(&mut tx2, &plan, &ctx)
        .await
        .expect("policy applies");
    tx2.commit()
        .await
        .expect("policy COMMIT past deferred triggers");
    assert_eq!(applied.allocated_seq, 2);

    // 6. Verify: stateVersion+1 at the same crypto coordinate, seq 2 contiguity.
    let (sv, next_seq): (i64, i64) = sqlx::query_as(
        "SELECT current_state_version,next_entry_seq FROM chat.conversations WHERE conversation_id=$1",
    )
    .bind(conversation_id)
    .fetch_one(&pool)
    .await
    .expect("head");
    assert_eq!((sv, next_seq), (1, 3));
    let gen_sv: i64 = sqlx::query_scalar(
        "SELECT current_state_version FROM chat.generations WHERE conversation_id=$1 AND generation=0",
    )
    .bind(conversation_id)
    .fetch_one(&pool)
    .await
    .expect("gen pointer");
    assert_eq!(gen_sv, 1);
    let (skind, slife): (String, String) = sqlx::query_as(
        "SELECT state_kind,lifecycle FROM chat.generation_states WHERE conversation_id=$1 AND state_version=1",
    )
    .bind(conversation_id)
    .fetch_one(&pool)
    .await
    .expect("policy state");
    assert_eq!((skind.as_str(), slife.as_str()), ("policy", "active"));
    let (tkind, eseq): (String, i64) = sqlx::query_as(
        "SELECT kind,entry_seq FROM chat.transitions WHERE conversation_id=$1 AND kind='policy'",
    )
    .bind(conversation_id)
    .fetch_one(&pool)
    .await
    .expect("policy transition");
    assert_eq!((tkind.as_str(), eseq), ("policy", 2));
    let added: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM chat.participants WHERE conversation_id=$1 AND user_did=$2 AND status='pending' AND role='member' AND current_membership",
    )
    .bind(conversation_id)
    .bind(&bob2_did)
    .fetch_one(&pool)
    .await
    .expect("added participant");
    assert_eq!(added, 1);
    // No metadata snapshot for a policy edge.
    let policy_snap: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM chat.metadata_snapshots m JOIN chat.transitions t ON t.transition_id=m.producing_transition_id WHERE t.conversation_id=$1 AND t.kind='policy'",
    )
    .bind(conversation_id)
    .fetch_one(&pool)
    .await
    .expect("policy snapshot count");
    assert_eq!(policy_snap, 0);

    // Reviewer's existing-edge re-apply variant: re-applying the committed POLICY
    // plan hits the head CAS (the head already advanced to stateVersion 1) →
    // typed conflict, whole transaction rolls back with zero residue.
    let before: i64 =
        sqlx::query_scalar("SELECT count(*) FROM chat.transitions WHERE conversation_id=$1")
            .bind(conversation_id)
            .fetch_one(&pool)
            .await
            .unwrap();
    let mut tx3 = pool.begin().await.expect("begin re-apply policy");
    let reapply = apply_conversation_persistence_plan(&mut tx3, &plan, &ctx).await;
    assert!(
        matches!(reapply, Err(ExecutorError::Transition(_))),
        "policy re-apply must conflict on the head CAS, got {reapply:?}"
    );
    tx3.rollback().await.expect("rollback re-apply policy");
    let after: i64 =
        sqlx::query_scalar("SELECT count(*) FROM chat.transitions WHERE conversation_id=$1")
            .bind(conversation_id)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(before, after, "policy re-apply left zero residue");
}

#[tokio::test]
async fn direct_creation_commits_with_direct_pair_shape() {
    let pool = setup().await;
    let fixture = build_creation(&pool, ConversationKind::Direct).await;
    let conversation_id = fixture.conversation_id;
    let mut tx = pool.begin().await.expect("begin");
    apply_conversation_persistence_plan(&mut tx, &fixture.plan, &fixture.ctx)
        .await
        .expect("direct creation applies");
    tx.commit().await.expect("COMMIT");

    let (kind, low, high): (String, Option<String>, Option<String>) = sqlx::query_as(
        "SELECT kind,direct_did_low,direct_did_high FROM chat.conversations WHERE conversation_id=$1",
    )
    .bind(conversation_id)
    .fetch_one(&pool)
    .await
    .expect("head");
    assert_eq!(kind, "direct");
    assert!(low.is_some() && high.is_some());
    assert!(low.as_deref() < high.as_deref());
    let admins: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM chat.participants WHERE conversation_id=$1 AND current_membership AND role='admin'",
    )
    .bind(conversation_id)
    .fetch_one(&pool)
    .await
    .expect("admins");
    assert_eq!(admins, 2);
}

#[tokio::test]
async fn creation_failure_injection_rolls_back_whole_graph() {
    let pool = setup().await;
    let fixture = build_creation(&pool, ConversationKind::Group).await;
    let conversation_id = fixture.conversation_id;
    let mut tx = pool.begin().await.expect("begin");
    apply_conversation_persistence_plan(&mut tx, &fixture.plan, &fixture.ctx)
        .await
        .expect("apply");
    // Force a mid-transaction failure: a duplicate entry at (conversation_id, 1).
    let dup = sqlx::query(
        r#"INSERT INTO chat.entries(conversation_id,seq,entry_id,entry_kind,accepted_payload_bytes,
            accepted_payload_sha256,signed_request_bytes,request_digest,signature,server_fields_bytes,
            outer_entry_fingerprint,actor_did,actor_device_id,actor_key_id,actor_auth_generation,
            generation,state_version,transition_id,received_at)
           VALUES($1,1,$2,'blue.catbird.chat.defs#creationEntry',$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,1,0,0,$13,$14)"#,
    )
    .bind(conversation_id)
    .bind(Uuid::new_v4())
    .bind(vec![1_u8; 4])
    .bind(Sha256::digest([1_u8; 4]).to_vec())
    .bind(vec![2_u8; 4])
    .bind(Sha256::digest([2_u8; 4]).to_vec())
    .bind(vec![3_u8; 64])
    .bind(vec![4_u8; 8])
    .bind(vec![5_u8; 32])
    .bind(&fixture.alice_did)
    .bind(fixture.alice_device)
    .bind(Uuid::new_v4())
    .bind(clock_now(&pool).await)
    .execute(&mut *tx)
    .await;
    assert!(
        dup.is_err(),
        "duplicate seq must violate the primary key mid-tx"
    );
    tx.rollback().await.expect("rollback");
    assert_eq!(
        count(
            &pool,
            "SELECT count(*) FROM chat.conversations WHERE conversation_id=$1",
            conversation_id
        )
        .await,
        0
    );
    assert_eq!(
        count(
            &pool,
            "SELECT count(*) FROM chat.transitions WHERE conversation_id=$1",
            conversation_id
        )
        .await,
        0
    );
    assert_eq!(
        count(
            &pool,
            "SELECT count(*) FROM chat.participants WHERE conversation_id=$1",
            conversation_id
        )
        .await,
        0
    );
}

async fn commit_creation(pool: &PgPool, kind: ConversationKind) -> CreationApply {
    let fixture = build_creation(pool, kind).await;
    let mut tx = pool.begin().await.expect("begin creation");
    apply_conversation_persistence_plan(&mut tx, &fixture.plan, &fixture.ctx)
        .await
        .expect("creation applies");
    tx.commit().await.expect("creation COMMIT");
    fixture
}

async fn device_event_predecessor(pool: &PgPool, did: &str, device: Uuid) -> Option<i64> {
    sqlx::query_scalar(
        "SELECT max(event_position) FROM chat.event_recipients WHERE user_did=$1 AND device_id=$2",
    )
    .bind(did)
    .bind(device)
    .fetch_one(pool)
    .await
    .expect("predecessor")
}

#[tokio::test]
async fn direct_close_commits_terminal_graph_and_reapply_conflicts() {
    let pool = setup().await;
    let fixture = commit_creation(&pool, ConversationKind::Direct).await;
    let conversation_id = fixture.conversation_id;

    // The creator's committed genesis leaf period (the interval's closing leaf).
    let leaf_period_id: Uuid = sqlx::query_scalar(
        "SELECT leaf_period_id FROM chat.member_devices WHERE conversation_id=$1",
    )
    .bind(conversation_id)
    .fetch_one(&pool)
    .await
    .expect("genesis leaf period");

    // Build the REAL close plan. Close entry is seq 2 (> the creation seq 1).
    let received_at = ServerTimestamp::from_unix_millis_for_test(
        corpus_manifest().evaluation_unix_seconds as i64 * 1_000 + 3_000,
    )
    .unwrap();
    let entry_id = Uuid::new_v4();
    let transition_id = Uuid::new_v4();
    let close_evidence =
        TransitionEvidence::for_test_at(2, *transition_id.as_bytes(), [0x13_u8; 32], received_at)
            .unwrap();
    let planned = plan_close(
        &fixture.state,
        CloseConversation {
            actor: fixture.alice_id.clone(),
            transition: close_evidence,
        },
    )
    .expect("valid close plan");
    let head_cas = ConversationHeadCasBinding::for_test_edge(
        *conversation_id.as_bytes(),
        *entry_id.as_bytes(),
        fixture.coordinate,
        2,
        received_at,
    );
    let plan = persistence_plan_for_test(planned, head_cas);

    let applied_at = clock_now(&pool).await;
    let alice_pred =
        device_event_predecessor(&pool, &fixture.alice_did, fixture.alice_device).await;
    let ctx = close_ctx(&fixture, entry_id, applied_at, leaf_period_id, alice_pred);

    let mut tx = pool.begin().await.expect("begin close");
    let applied = apply_conversation_persistence_plan(&mut tx, &plan, &ctx)
        .await
        .expect("close applies");
    tx.commit()
        .await
        .expect("close COMMIT past all deferred triggers");
    assert_eq!(applied.allocated_seq, 2);

    // Head superseded with the close coordinate.
    let (lifecycle, ct, cseq): (String, Option<Uuid>, Option<i64>) = sqlx::query_as(
        "SELECT lifecycle,close_transition_id,close_seq FROM chat.conversations WHERE conversation_id=$1",
    )
    .bind(conversation_id)
    .fetch_one(&pool)
    .await
    .expect("head");
    assert_eq!(lifecycle, "superseded");
    assert_eq!(ct, Some(transition_id));
    assert_eq!(cseq, Some(2));
    // Generation superseded; superseded closeConversation state at sv 1.
    let gen_life: String = sqlx::query_scalar(
        "SELECT lifecycle FROM chat.generations WHERE conversation_id=$1 AND generation=0",
    )
    .bind(conversation_id)
    .fetch_one(&pool)
    .await
    .expect("gen");
    assert_eq!(gen_life, "superseded");
    let (skind, slife): (String, String) = sqlx::query_as(
        "SELECT state_kind,lifecycle FROM chat.generation_states WHERE conversation_id=$1 AND state_version=1",
    )
    .bind(conversation_id)
    .fetch_one(&pool)
    .await
    .expect("close state");
    assert_eq!(
        (skind.as_str(), slife.as_str()),
        ("closeConversation", "superseded")
    );
    // Interval closed with a Terminal proof at the close seq.
    let (tseq, ckind): (Option<i64>, Option<String>) = sqlx::query_as(
        "SELECT terminal_seq,closing_kind FROM chat.application_intervals WHERE conversation_id=$1",
    )
    .bind(conversation_id)
    .fetch_one(&pool)
    .await
    .expect("interval");
    assert_eq!((tseq, ckind.as_deref()), (Some(2), Some("terminal")));
    // One schedule terminal proof; a retained scheduleTerminal audience row.
    assert_eq!(count(&pool, "SELECT count(*) FROM chat.application_schedule_terminal_proofs WHERE conversation_id=$1", conversation_id).await, 1);
    let sched_recips: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM chat.entry_recipients WHERE conversation_id=$1 AND seq=2 AND entitlement_kind='scheduleTerminal'",
    )
    .bind(conversation_id)
    .fetch_one(&pool)
    .await
    .expect("sched recipients");
    assert_eq!(sched_recips, 1);
    // The single conversation-close tombstone event.
    let evt_kind: String =
        sqlx::query_scalar("SELECT event_kind FROM chat.events WHERE event_position=$1")
            .bind(applied.event_positions[0])
            .fetch_one(&pool)
            .await
            .expect("event");
    assert_eq!(evt_kind, "conversationClosed");

    // Re-apply the same close plan -> head CAS conflict (the head is already
    // superseded), whole transaction rolls back with zero residue.
    let before: i64 =
        sqlx::query_scalar("SELECT count(*) FROM chat.transitions WHERE conversation_id=$1")
            .bind(conversation_id)
            .fetch_one(&pool)
            .await
            .unwrap();
    let mut tx2 = pool.begin().await.expect("begin re-close");
    let reapply = apply_conversation_persistence_plan(&mut tx2, &plan, &ctx).await;
    assert!(
        matches!(reapply, Err(ExecutorError::Transition(_))),
        "re-close must conflict, got {reapply:?}"
    );
    tx2.rollback().await.expect("rollback");
    let after: i64 =
        sqlx::query_scalar("SELECT count(*) FROM chat.transitions WHERE conversation_id=$1")
            .bind(conversation_id)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(before, after, "re-close left zero residue");
}

fn close_ctx(
    fixture: &CreationApply,
    entry_id: Uuid,
    applied_at: DateTime<Utc>,
    leaf_period_id: Uuid,
    alice_pred: Option<i64>,
) -> ExecutionContext {
    let payload = vec![0x31_u8; 12];
    let transcript = vec![0x32_u8; 12];
    ExecutionContext {
        protocol_instance_id: fixture.protocol_instance_id,
        applied_at,
        actor: ExecutionActor {
            user_did: fixture.alice_did.clone(),
            device_id: fixture.alice_device,
            key_id: fixture.alice_key_id.clone(),
            auth_generation: 1,
            role: chat_protocol::repository::transition::TransitionActorRole::Admin,
            device_status: "active".to_owned(),
        },
        entry: ControlEntryContent {
            entry_id,
            entry_kind: "blue.catbird.chat.defs#conversationCloseEntry".to_owned(),
            accepted_payload_bytes: payload.clone(),
            accepted_payload_sha256: Sha256::digest(&payload).to_vec(),
            signed_request_bytes: transcript.clone(),
            unsigned_projection_bytes: vec![0x33_u8; 8],
            signing_transcript_bytes: transcript.clone(),
            request_digest: Sha256::digest(&transcript).to_vec(),
            signature: vec![0x34_u8; 64],
            server_fields_bytes: vec![0x35_u8; 8],
            outer_entry_fingerprint: vec![0x13_u8; 32],
        },
        spine: SpineArtifacts {
            public_snapshot_bytes: vec![0x41_u8; 16],
            public_snapshot_sha256: Sha256::digest([0x41_u8; 16]).to_vec(),
            tree_summary_bytes: vec![0x42_u8; 16],
            tree_summary_sha256: Sha256::digest([0x42_u8; 16]).to_vec(),
            leaf_count: 1,
            genesis_group_info_bytes: vec![],
            genesis_group_info_sha256: vec![],
        },
        opened_leaves: vec![],
        metadata_author: None,
        participant_period_ids: vec![],
        leaf_period_ids: vec![],
        entry_recipients: vec![(
            fixture.alice_id.clone(),
            chat_protocol::repository::delivery::EntryEntitlementKind::ScheduleTerminal,
        )],
        events: vec![EventFanout {
            event_id: Uuid::new_v4(),
            event_kind: EventKind::ConversationClosed,
            payload_bytes: vec![0x51_u8; 8],
            recipients: vec![(
                fixture.alice_id.clone(),
                EventEntitlementKind::Participant,
                alice_pred,
            )],
            outbox: vec![(Uuid::new_v4(), OutboxWorkKind::Stream)],
        }],
        closing_leaf_periods: vec![(fixture.alice_id.clone(), leaf_period_id)],
        reset_request_row: None,
        recovery_open: None,
    }
}

#[tokio::test]
async fn reset_request_commits_without_changing_the_coordinate() {
    let pool = setup().await;
    let fixture = commit_creation(&pool, ConversationKind::Group).await;
    let conversation_id = fixture.conversation_id;

    // A reset request by the active admin (alice). Non-mutating: seq advances, the
    // (generation,state_version) coordinate must be untouched.
    let request_id = Uuid::new_v4();
    let received_at = ServerTimestamp::from_unix_millis_for_test(
        corpus_manifest().evaluation_unix_seconds as i64 * 1_000 + 3_000,
    )
    .unwrap();
    let evidence = RequestEvidence::for_test(
        RequestEntryKind::ResetRequest,
        2,
        *request_id.as_bytes(),
        fixture.alice_id.clone(),
        *conversation_id.as_bytes(),
        received_at,
        0x61,
    )
    .unwrap();
    let planned = plan_reset_request(
        &fixture.state,
        ResetRequestCommand {
            actor: fixture.alice_id.clone(),
            reset_request_id: *request_id.as_bytes(),
            received_at,
            evidence,
        },
    )
    .expect("valid reset request plan");
    let entry_id = Uuid::new_v4();
    let head_cas = ConversationHeadCasBinding::for_test_edge(
        *conversation_id.as_bytes(),
        *entry_id.as_bytes(),
        fixture.coordinate,
        2,
        received_at,
    );
    let plan = persistence_plan_for_test(planned, head_cas);

    // The reset-request entry and the reset_requests row MUST carry identical
    // signed bytes / digest / signature / received_at (the entry↔request mapping
    // trigger); source both from the same values.
    let applied_at = clock_now(&pool).await;
    let transcript = vec![0x62_u8; 16];
    let request_digest = Sha256::digest(&transcript).to_vec();
    let signature = vec![0x63_u8; 64];
    let alice_pred =
        device_event_predecessor(&pool, &fixture.alice_did, fixture.alice_device).await;
    let ctx = ExecutionContext {
        protocol_instance_id: fixture.protocol_instance_id,
        applied_at,
        actor: ExecutionActor {
            user_did: fixture.alice_did.clone(),
            device_id: fixture.alice_device,
            key_id: fixture.alice_key_id.clone(),
            auth_generation: 1,
            role: chat_protocol::repository::transition::TransitionActorRole::Admin,
            device_status: "active".to_owned(),
        },
        entry: ControlEntryContent {
            entry_id,
            entry_kind: "blue.catbird.chat.defs#resetRequestEntry".to_owned(),
            accepted_payload_bytes: vec![0x64_u8; 8],
            accepted_payload_sha256: Sha256::digest([0x64_u8; 8]).to_vec(),
            signed_request_bytes: transcript.clone(),
            unsigned_projection_bytes: vec![0x65_u8; 8],
            signing_transcript_bytes: transcript.clone(),
            request_digest: request_digest.clone(),
            signature: signature.clone(),
            server_fields_bytes: vec![0x66_u8; 8],
            outer_entry_fingerprint: vec![0x14_u8; 32],
        },
        spine: SpineArtifacts {
            public_snapshot_bytes: vec![],
            public_snapshot_sha256: vec![],
            tree_summary_bytes: vec![],
            tree_summary_sha256: vec![],
            leaf_count: 1,
            genesis_group_info_bytes: vec![],
            genesis_group_info_sha256: vec![],
        },
        opened_leaves: vec![],
        metadata_author: None,
        participant_period_ids: vec![],
        leaf_period_ids: vec![],
        entry_recipients: vec![(
            fixture.alice_id.clone(),
            chat_protocol::repository::delivery::EntryEntitlementKind::Control,
        )],
        events: vec![EventFanout {
            event_id: Uuid::new_v4(),
            event_kind: EventKind::ResetRequested,
            payload_bytes: vec![0x67_u8; 8],
            recipients: vec![(
                fixture.alice_id.clone(),
                EventEntitlementKind::Participant,
                alice_pred,
            )],
            outbox: vec![(Uuid::new_v4(), OutboxWorkKind::Stream)],
        }],
        closing_leaf_periods: vec![],
        reset_request_row: Some(ResetRequestRow {
            reset_request_id: request_id,
            reason: ResetReason::PoisonedState,
            signed_request_bytes: transcript.clone(),
            signing_transcript_bytes: transcript.clone(),
            request_digest,
            signature,
            expires_at: applied_at + Duration::hours(24),
        }),
        recovery_open: None,
    };

    let mut tx = pool.begin().await.expect("begin reset");
    apply_conversation_persistence_plan(&mut tx, &plan, &ctx)
        .await
        .expect("reset request applies");
    tx.commit().await.expect("reset request COMMIT");

    // Coordinate UNTOUCHED (still 0,0 active); only the seq advanced.
    let (gen, sv, next_seq, lifecycle): (i64, i64, i64, String) = sqlx::query_as(
        "SELECT current_generation,current_state_version,next_entry_seq,lifecycle FROM chat.conversations WHERE conversation_id=$1",
    )
    .bind(conversation_id)
    .fetch_one(&pool)
    .await
    .expect("head");
    assert_eq!((gen, sv, next_seq, lifecycle.as_str()), (0, 0, 3, "active"));
    // A pending reset request row + a resetRequestEntry, no new transition.
    let (status,): (String,) =
        sqlx::query_as("SELECT status FROM chat.reset_requests WHERE reset_request_id=$1")
            .bind(request_id)
            .fetch_one(&pool)
            .await
            .expect("reset request row");
    assert_eq!(status, "pending");
    let entry_kind: String = sqlx::query_scalar(
        "SELECT entry_kind FROM chat.entries WHERE conversation_id=$1 AND seq=2",
    )
    .bind(conversation_id)
    .fetch_one(&pool)
    .await
    .expect("entry");
    assert_eq!(entry_kind, "blue.catbird.chat.defs#resetRequestEntry");
    // No transition row was produced by the reset request (it is non-mutating).
    let transitions: i64 =
        sqlx::query_scalar("SELECT count(*) FROM chat.transitions WHERE conversation_id=$1")
            .bind(conversation_id)
            .fetch_one(&pool)
            .await
            .expect("transitions");
    assert_eq!(transitions, 1, "only the creation transition exists");
}

/// Build + commit a reset request by the active admin (alice) and return the
/// resulting in-memory state (with the pending request) + the request id.
async fn commit_reset_request(
    pool: &PgPool,
    fixture: &CreationApply,
    request_seq: u64,
    received_at: ServerTimestamp,
) -> (chat_protocol::state_machine::ConversationState, Uuid) {
    let conversation_id = fixture.conversation_id;
    let request_id = Uuid::new_v4();
    let evidence = RequestEvidence::for_test(
        RequestEntryKind::ResetRequest,
        request_seq,
        *request_id.as_bytes(),
        fixture.alice_id.clone(),
        *conversation_id.as_bytes(),
        received_at,
        0x61,
    )
    .unwrap();
    let planned = plan_reset_request(
        &fixture.state,
        ResetRequestCommand {
            actor: fixture.alice_id.clone(),
            reset_request_id: *request_id.as_bytes(),
            received_at,
            evidence,
        },
    )
    .expect("valid reset request plan");
    let state = planned.resulting_state().clone();
    let entry_id = Uuid::new_v4();
    let head_cas = ConversationHeadCasBinding::for_test_edge(
        *conversation_id.as_bytes(),
        *entry_id.as_bytes(),
        fixture.coordinate,
        request_seq,
        received_at,
    );
    let plan = persistence_plan_for_test(planned, head_cas);
    let applied_at = clock_now(pool).await;
    let transcript = vec![0x62_u8; 16];
    let request_digest = Sha256::digest(&transcript).to_vec();
    let signature = vec![0x63_u8; 64];
    let pred = device_event_predecessor(pool, &fixture.alice_did, fixture.alice_device).await;
    let ctx = ExecutionContext {
        protocol_instance_id: fixture.protocol_instance_id,
        applied_at,
        actor: ExecutionActor {
            user_did: fixture.alice_did.clone(),
            device_id: fixture.alice_device,
            key_id: fixture.alice_key_id.clone(),
            auth_generation: 1,
            role: chat_protocol::repository::transition::TransitionActorRole::Admin,
            device_status: "active".to_owned(),
        },
        entry: ControlEntryContent {
            entry_id,
            entry_kind: "blue.catbird.chat.defs#resetRequestEntry".to_owned(),
            accepted_payload_bytes: vec![0x64_u8; 8],
            accepted_payload_sha256: Sha256::digest([0x64_u8; 8]).to_vec(),
            signed_request_bytes: transcript.clone(),
            unsigned_projection_bytes: vec![0x65_u8; 8],
            signing_transcript_bytes: transcript.clone(),
            request_digest: request_digest.clone(),
            signature: signature.clone(),
            server_fields_bytes: vec![0x66_u8; 8],
            outer_entry_fingerprint: vec![0x14_u8; 32],
        },
        spine: SpineArtifacts {
            public_snapshot_bytes: vec![],
            public_snapshot_sha256: vec![],
            tree_summary_bytes: vec![],
            tree_summary_sha256: vec![],
            leaf_count: 1,
            genesis_group_info_bytes: vec![],
            genesis_group_info_sha256: vec![],
        },
        opened_leaves: vec![],
        metadata_author: None,
        participant_period_ids: vec![],
        leaf_period_ids: vec![],
        entry_recipients: vec![(
            fixture.alice_id.clone(),
            chat_protocol::repository::delivery::EntryEntitlementKind::Control,
        )],
        events: vec![EventFanout {
            event_id: Uuid::new_v4(),
            event_kind: EventKind::ResetRequested,
            payload_bytes: vec![0x67_u8; 8],
            recipients: vec![(
                fixture.alice_id.clone(),
                EventEntitlementKind::Participant,
                pred,
            )],
            outbox: vec![(Uuid::new_v4(), OutboxWorkKind::Stream)],
        }],
        closing_leaf_periods: vec![],
        reset_request_row: Some(ResetRequestRow {
            reset_request_id: request_id,
            reason: ResetReason::PoisonedState,
            signed_request_bytes: transcript.clone(),
            signing_transcript_bytes: transcript,
            request_digest,
            signature,
            expires_at: applied_at + Duration::hours(24),
        }),
        recovery_open: None,
    };
    let mut tx = pool.begin().await.expect("begin reset request");
    apply_conversation_persistence_plan(&mut tx, &plan, &ctx)
        .await
        .expect("reset request applies");
    tx.commit().await.expect("reset request COMMIT");
    (state, request_id)
}

#[tokio::test]
async fn reset_activation_commits_two_generation_graph_and_conflicts_on_replay() {
    let pool = setup().await;
    let fixture = commit_creation(&pool, ConversationKind::Group).await;
    let conversation_id = fixture.conversation_id;
    let manifest = corpus_manifest();

    // Reset request (seq 2) by the active admin, committed; returns the state that
    // carries the pending request (the activation's prior).
    let req_received = ServerTimestamp::from_unix_millis_for_test(
        manifest.evaluation_unix_seconds as i64 * 1_000 + 3_000,
    )
    .unwrap();
    let (reset_state, request_id) = commit_reset_request(&pool, &fixture, 2, req_received).await;

    // Committed old-generation identifiers the activation reuses/closes.
    let old_leaf_period: Uuid = sqlx::query_scalar(
        "SELECT leaf_period_id FROM chat.member_devices WHERE conversation_id=$1 AND generation=0",
    )
    .bind(conversation_id)
    .fetch_one(&pool)
    .await
    .expect("old leaf period");
    let participant_rows: Vec<(String, Uuid)> = sqlx::query_as(
        "SELECT user_did,participant_period_id FROM chat.participants WHERE conversation_id=$1 AND current_membership",
    )
    .bind(conversation_id)
    .fetch_all(&pool)
    .await
    .expect("participant periods");

    // Successor coordinate: generation+1, sv0, epoch0, FRESH group/hash/tag.
    let successor_coordinate = chat_protocol::snapshot::PublicGroupSnapshotCoordinate::new(
        *conversation_id.as_bytes(),
        fixture.coordinate.generation() + 1,
        0,
        [0x71; 32],
        0,
        [0x72; 32],
        [0x73; 32],
        chat_protocol::snapshot::PublicGroupSnapshotLifecycle::Active,
    );
    let successor_public_state =
        ActivePublicState::for_test(&verified_genesis(&manifest), successor_coordinate);
    let retired_coordinate = chat_protocol::snapshot::PublicGroupSnapshotCoordinate::new(
        *conversation_id.as_bytes(),
        fixture.coordinate.generation(),
        fixture.coordinate.state_version() + 1,
        *fixture.coordinate.group_id(),
        fixture.coordinate.epoch(),
        *fixture.coordinate.group_context_hash(),
        *fixture.coordinate.confirmation_tag(),
        chat_protocol::snapshot::PublicGroupSnapshotLifecycle::Superseded,
    );

    let act_received = ServerTimestamp::from_unix_millis_for_test(
        manifest.evaluation_unix_seconds as i64 * 1_000 + 4_000,
    )
    .unwrap();
    let transition_id = Uuid::new_v4();
    let entry_id = Uuid::new_v4();
    let alice_sig_key: Vec<u8> =
        hex::decode(&manifest.identity.alice.signature_public_key_hex).unwrap();
    let nonce = [0x78_u8; 12];
    let ciphertext = vec![0x79_u8; 48];
    let metadata = MetadataSnapshotBinding::for_test_creation(
        *conversation_id.as_bytes(),
        1,
        [0x72; 32],
        *transition_id.as_bytes(),
        3,
        fixture.alice_id.clone(),
        Sha256::digest(&alice_sig_key).into(),
        alice_sig_key.clone().try_into().unwrap(),
        1,
        2,
        nonce,
        ciphertext,
    );
    let evidence = TransitionEvidence::for_test_reset_activation_with_metadata(
        3,
        *transition_id.as_bytes(),
        [0x15_u8; 32],
        act_received,
        ConversationKind::Group,
        *request_id.as_bytes(),
        fixture.coordinate,
        retired_coordinate,
        successor_coordinate,
        fixture.alice_id.clone(),
        metadata,
    )
    .unwrap();
    let planned = plan_reset_activation(
        &reset_state,
        ResetActivation {
            actor: fixture.alice_id.clone(),
            reset_request_id: *request_id.as_bytes(),
            transition: evidence,
            successor_public_state,
        },
    )
    .expect("valid reset activation plan");
    let head_cas = ConversationHeadCasBinding::for_test_edge(
        *conversation_id.as_bytes(),
        *entry_id.as_bytes(),
        fixture.coordinate,
        3,
        act_received,
    );
    let plan = persistence_plan_for_test(planned, head_cas);

    // Participant periods in hydration (sorted-DID) order.
    let mut sorted_participants = participant_rows.clone();
    sorted_participants.sort_by(|l, r| l.0.as_bytes().cmp(r.0.as_bytes()));
    let participant_period_ids: Vec<Uuid> = sorted_participants.iter().map(|(_, id)| *id).collect();

    let applied_at = clock_now(&pool).await;
    let payload = vec![0x81_u8; 12];
    let transcript = vec![0x82_u8; 12];
    let pred = device_event_predecessor(&pool, &fixture.alice_did, fixture.alice_device).await;
    let ctx = ExecutionContext {
        protocol_instance_id: fixture.protocol_instance_id,
        applied_at,
        actor: ExecutionActor {
            user_did: fixture.alice_did.clone(),
            device_id: fixture.alice_device,
            key_id: fixture.alice_key_id.clone(),
            auth_generation: 1,
            role: chat_protocol::repository::transition::TransitionActorRole::Admin,
            device_status: "active".to_owned(),
        },
        entry: ControlEntryContent {
            entry_id,
            entry_kind: "blue.catbird.chat.defs#resetActivationEntry".to_owned(),
            accepted_payload_bytes: payload.clone(),
            accepted_payload_sha256: Sha256::digest(&payload).to_vec(),
            signed_request_bytes: transcript.clone(),
            unsigned_projection_bytes: vec![0x83_u8; 8],
            signing_transcript_bytes: transcript.clone(),
            request_digest: Sha256::digest(&transcript).to_vec(),
            signature: vec![0x84_u8; 64],
            server_fields_bytes: vec![0x85_u8; 8],
            outer_entry_fingerprint: vec![0x15_u8; 32],
        },
        spine: SpineArtifacts {
            public_snapshot_bytes: vec![0x91_u8; 16],
            public_snapshot_sha256: Sha256::digest([0x91_u8; 16]).to_vec(),
            tree_summary_bytes: vec![0x92_u8; 16],
            tree_summary_sha256: Sha256::digest([0x92_u8; 16]).to_vec(),
            leaf_count: 1,
            genesis_group_info_bytes: vec![0x93_u8; 16],
            genesis_group_info_sha256: Sha256::digest([0x93_u8; 16]).to_vec(),
        },
        opened_leaves: vec![LeafPersistenceColumns {
            device: fixture.alice_id.clone(),
            leaf_key_id: fixture.alice_key_id.clone(),
            leaf_auth_generation: 1,
        }],
        metadata_author: Some(MetadataAuthorColumns {
            author_role: "admin".to_owned(),
            author_device_status: "active".to_owned(),
            author_public_key: alice_sig_key,
            metadata_snapshot_id: Uuid::new_v4(),
        }),
        participant_period_ids,
        leaf_period_ids: vec![Uuid::new_v4()],
        // The activator's OLD interval closes with kind=reset at this seq, so her
        // audience row is intervalClose (the DB binds intervalClose to a
        // remove/replace/reset-closed interval at that terminal seq).
        entry_recipients: vec![(
            fixture.alice_id.clone(),
            chat_protocol::repository::delivery::EntryEntitlementKind::IntervalClose,
        )],
        events: vec![EventFanout {
            event_id: Uuid::new_v4(),
            event_kind: EventKind::ConversationChanged,
            payload_bytes: vec![0x94_u8; 8],
            recipients: vec![(
                fixture.alice_id.clone(),
                EventEntitlementKind::Participant,
                pred,
            )],
            outbox: vec![(Uuid::new_v4(), OutboxWorkKind::Stream)],
        }],
        closing_leaf_periods: vec![(fixture.alice_id.clone(), old_leaf_period)],
        reset_request_row: None,
        recovery_open: None,
    };

    let mut tx = pool.begin().await.expect("begin activation");
    let applied = apply_conversation_persistence_plan(&mut tx, &plan, &ctx)
        .await
        .expect("reset activation applies");
    tx.commit()
        .await
        .expect("reset activation COMMIT past all deferred triggers");
    assert_eq!(applied.allocated_seq, 3);

    // Head moved to the successor pointer.
    let (gen, sv, next_seq, lifecycle): (i64, i64, i64, String) = sqlx::query_as(
        "SELECT current_generation,current_state_version,next_entry_seq,lifecycle FROM chat.conversations WHERE conversation_id=$1",
    )
    .bind(conversation_id)
    .fetch_one(&pool)
    .await
    .expect("head");
    assert_eq!((gen, sv, next_seq, lifecycle.as_str()), (1, 0, 4, "active"));
    // Old generation superseded; new generation active.
    let (g0_life, g1_life): (String, String) = sqlx::query_as(
        "SELECT (SELECT lifecycle FROM chat.generations WHERE conversation_id=$1 AND generation=0), \
                (SELECT lifecycle FROM chat.generations WHERE conversation_id=$1 AND generation=1)",
    )
    .bind(conversation_id)
    .fetch_one(&pool)
    .await
    .expect("generations");
    assert_eq!(
        (g0_life.as_str(), g1_life.as_str()),
        ("superseded", "active")
    );
    // Retired resetRetirement state (superseded) + resetSuccessor state (active).
    let (retired_kind, retired_life): (String, String) = sqlx::query_as(
        "SELECT state_kind,lifecycle FROM chat.generation_states WHERE conversation_id=$1 AND generation=0 AND state_version=1",
    )
    .bind(conversation_id)
    .fetch_one(&pool)
    .await
    .expect("retired state");
    assert_eq!(
        (retired_kind.as_str(), retired_life.as_str()),
        ("resetRetirement", "superseded")
    );
    let (succ_kind, succ_life, succ_epoch): (String, String, i64) = sqlx::query_as(
        "SELECT state_kind,lifecycle,epoch FROM chat.generation_states WHERE conversation_id=$1 AND generation=1 AND state_version=0",
    )
    .bind(conversation_id)
    .fetch_one(&pool)
    .await
    .expect("successor state");
    assert_eq!(
        (succ_kind.as_str(), succ_life.as_str(), succ_epoch),
        ("resetSuccessor", "active", 0)
    );
    // Old interval closed at reset seq (kind reset); activator's new interval open at reset seq.
    let closed_at_reset: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM chat.application_intervals WHERE conversation_id=$1 AND terminal_seq=3 AND closing_kind='reset'",
    )
    .bind(conversation_id)
    .fetch_one(&pool)
    .await
    .expect("closed interval");
    assert_eq!(closed_at_reset, 1);
    let opened_at_reset: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM chat.application_intervals WHERE conversation_id=$1 AND start_seq=3 AND opening_kind='reset' AND terminal_seq IS NULL",
    )
    .bind(conversation_id)
    .fetch_one(&pool)
    .await
    .expect("opened interval");
    assert_eq!(opened_at_reset, 1);
    // New genesis leaf at generation 1; the reset request consumed.
    let g1_leaf: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM chat.member_devices WHERE conversation_id=$1 AND generation=1 AND active",
    )
    .bind(conversation_id)
    .fetch_one(&pool)
    .await
    .expect("g1 leaf");
    assert_eq!(g1_leaf, 1);
    let req_status: String =
        sqlx::query_scalar("SELECT status FROM chat.reset_requests WHERE reset_request_id=$1")
            .bind(request_id)
            .fetch_one(&pool)
            .await
            .expect("reset request status");
    assert_eq!(req_status, "consumed");

    // Replay the activation on the OLD coordinate -> head CAS conflict (head is
    // now at generation 1), whole transaction rolls back with zero residue.
    let before: i64 =
        sqlx::query_scalar("SELECT count(*) FROM chat.transitions WHERE conversation_id=$1")
            .bind(conversation_id)
            .fetch_one(&pool)
            .await
            .unwrap();
    let mut tx2 = pool.begin().await.expect("begin replay");
    let replay = apply_conversation_persistence_plan(&mut tx2, &plan, &ctx).await;
    assert!(
        matches!(replay, Err(ExecutorError::Transition(_))),
        "second activation must conflict on the head CAS, got {replay:?}"
    );
    tx2.rollback().await.expect("rollback replay");
    let after: i64 =
        sqlx::query_scalar("SELECT count(*) FROM chat.transitions WHERE conversation_id=$1")
            .bind(conversation_id)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(before, after, "activation replay left zero residue");
}

#[tokio::test]
async fn creation_plan_without_invitation_quota_binding_is_rejected() {
    let pool = setup().await;
    let fixture = build_creation(&pool, ConversationKind::Group).await;
    let conversation_id = fixture.conversation_id;
    // A Creation plan MUST carry the invitation-quota CAS binding (production
    // `into_persistence_plan` rejects it as InvalidHydrationAuthority otherwise).
    // The executor rejects the stripped plan as InconsistentPlan BEFORE any write.
    let stripped = fixture.plan.with_invitation_quota_cleared_for_test();
    let mut tx = pool.begin().await.expect("begin");
    let result = apply_conversation_persistence_plan(&mut tx, &stripped, &fixture.ctx).await;
    assert!(
        matches!(result, Err(ExecutorError::InconsistentPlan(_))),
        "missing invitation-quota binding must be an InconsistentPlan, got {result:?}"
    );
    tx.rollback().await.expect("rollback");
    assert_eq!(
        count(
            &pool,
            "SELECT count(*) FROM chat.conversations WHERE conversation_id=$1",
            conversation_id
        )
        .await,
        0,
        "a rejected plan writes nothing"
    );
}

#[tokio::test]
async fn creation_mid_executor_metadata_conflict_rolls_back_whole_graph() {
    let pool = setup().await;

    // A real creation that COMMITS — its metadata snapshot id is a global primary
    // key we then force a collision against.
    let first = build_creation(&pool, ConversationKind::Group).await;
    let mut tx0 = pool.begin().await.expect("begin first");
    apply_conversation_persistence_plan(&mut tx0, &first.plan, &first.ctx)
        .await
        .expect("first creation applies");
    tx0.commit().await.expect("first COMMIT");
    let existing_snapshot_id: Uuid = sqlx::query_scalar(
        "SELECT metadata_snapshot_id FROM chat.metadata_snapshots WHERE conversation_id=$1",
    )
    .bind(first.conversation_id)
    .fetch_one(&pool)
    .await
    .expect("first snapshot id");

    // Second creation whose metadata snapshot id collides with the committed one.
    // The executor's OWN metadata insert (step 5, AFTER the head insert at step 1)
    // fails on the metadata_snapshots primary key mid-executor; the whole graph
    // must roll back.
    let mut second = build_creation(&pool, ConversationKind::Group).await;
    let conversation_id = second.conversation_id;
    second
        .ctx
        .metadata_author
        .as_mut()
        .expect("creation carries a metadata author")
        .metadata_snapshot_id = existing_snapshot_id;

    let mut tx = pool.begin().await.expect("begin second");
    let result = apply_conversation_persistence_plan(&mut tx, &second.plan, &second.ctx).await;
    assert!(
        matches!(result, Err(ExecutorError::Transition(_))),
        "mid-executor metadata PK collision must surface as a Transition error, got {result:?}"
    );
    tx.rollback().await.expect("rollback second");

    // The head insert (step 1) executed inside the same transaction BEFORE the
    // failing metadata insert (step 5): confirm it — and every other row — rolled
    // back, proving executor atomicity across the whole graph.
    assert_eq!(
        count(
            &pool,
            "SELECT count(*) FROM chat.conversations WHERE conversation_id=$1",
            conversation_id
        )
        .await,
        0
    );
    assert_eq!(
        count(
            &pool,
            "SELECT count(*) FROM chat.generations WHERE conversation_id=$1",
            conversation_id
        )
        .await,
        0
    );
    assert_eq!(
        count(
            &pool,
            "SELECT count(*) FROM chat.participants WHERE conversation_id=$1",
            conversation_id
        )
        .await,
        0
    );
    assert_eq!(
        count(
            &pool,
            "SELECT count(*) FROM chat.entries WHERE conversation_id=$1",
            conversation_id
        )
        .await,
        0
    );
}

fn random_ref32() -> [u8; 32] {
    let mut bytes = [0u8; 32];
    bytes[..16].copy_from_slice(Uuid::new_v4().as_bytes());
    bytes[16..].copy_from_slice(Uuid::new_v4().as_bytes());
    bytes
}

/// Seed one `available` key package owned by `(owner_did, owner_device)` and
/// return its exact `not_after` (the value the reservation's
/// `expires_at = LEAST(created_at + 5 min, not_after)` mapping check needs).
async fn seed_key_package(
    pool: &PgPool,
    owner_did: &str,
    owner_device: Uuid,
    owner_key_id: &str,
    key_package_ref: &[u8],
) -> DateTime<Utc> {
    let now = clock_now(pool).await;
    let not_before = now - Duration::hours(1);
    let not_after = now + Duration::hours(24);
    let wrapper = vec![0xC1_u8; 32];
    let init_key = {
        let mut key = vec![0u8; 32];
        key[..16].copy_from_slice(Uuid::new_v4().as_bytes());
        key[16..].copy_from_slice(Uuid::new_v4().as_bytes());
        key
    };
    sqlx::query(
        "INSERT INTO chat.key_packages(key_package_ref,wrapper_bytes,wrapper_sha256,init_key,owner_did,owner_device_id,owner_key_id,owner_auth_generation,not_before,not_after,status,created_at) \
         VALUES($1,$2,$3,$4,$5,$6,$7,1,$8,$9,'available',$10)",
    )
    .bind(key_package_ref)
    .bind(&wrapper)
    .bind(Sha256::digest(&wrapper).to_vec())
    .bind(&init_key)
    .bind(owner_did)
    .bind(owner_device)
    .bind(owner_key_id)
    .bind(not_before)
    .bind(not_after)
    .bind(now)
    .execute(pool)
    .await
    .expect("seed key package");
    not_after
}

#[tokio::test]
async fn acceptance_commits_recovery_open_and_promotes_participant() {
    let pool = setup().await;
    let fixture = commit_creation(&pool, ConversationKind::Group).await;
    let conversation_id = fixture.conversation_id;
    let bob_device = Uuid::from_bytes(*fixture.bob_id.device_id());

    // bob's pending participant period (the acceptance CAS target).
    let bob_period: Uuid = sqlx::query_scalar(
        "SELECT participant_period_id FROM chat.participants WHERE conversation_id=$1 AND user_did=$2 AND current_membership",
    )
    .bind(conversation_id)
    .bind(&fixture.bob_did)
    .fetch_one(&pool)
    .await
    .expect("bob participant period");
    let bob_key_id = fixture.bob_key_id.clone();

    // The key package bob's acceptance reserves.
    let key_package_ref = random_ref32();
    let package_not_after = seed_key_package(
        &pool,
        &fixture.bob_did,
        bob_device,
        &bob_key_id,
        &key_package_ref,
    )
    .await;

    let received_at = ServerTimestamp::from_unix_millis_for_test(
        corpus_manifest().evaluation_unix_seconds as i64 * 1_000 + 3_000,
    )
    .unwrap();
    let pkg_not_after_ts = ServerTimestamp::from_unix_millis_for_test(
        corpus_manifest().evaluation_unix_seconds as i64 * 1_000 + 3_600_000,
    )
    .unwrap();
    let entry_id = Uuid::new_v4();
    let transition_id = Uuid::new_v4();
    let recovery_request_id = *Uuid::new_v4().as_bytes();
    let evidence = TransitionEvidence::for_test_acceptance(
        2,
        *transition_id.as_bytes(),
        [0x16_u8; 32],
        received_at,
        fixture.coordinate,
        recovery_request_id,
        fixture.bob_id.clone(),
        fixture.creation_transition_id,
        fixture.alice_id.clone(),
        key_package_ref,
        Sha256::digest([0x62_u8; 32]).into(),
        1,
        pkg_not_after_ts,
    )
    .unwrap();
    let planned = plan_accept_conversation(
        &fixture.state,
        AcceptConversation {
            actor: fixture.bob_id.clone(),
            transition: evidence,
            recovery_request_id,
            key_package_ref,
            package_not_after: pkg_not_after_ts,
        },
    )
    .expect("valid acceptance plan");
    let head_cas = ConversationHeadCasBinding::for_test_edge(
        *conversation_id.as_bytes(),
        *entry_id.as_bytes(),
        fixture.coordinate,
        2,
        received_at,
    );
    let plan = persistence_plan_for_test(planned, head_cas);

    let applied_at = clock_now(&pool).await;
    let payload = vec![0xA1_u8; 12];
    let transcript = vec![0xA2_u8; 12];
    let ctx = ExecutionContext {
        protocol_instance_id: fixture.protocol_instance_id,
        applied_at,
        actor: ExecutionActor {
            user_did: fixture.bob_did.clone(),
            device_id: bob_device,
            key_id: bob_key_id.clone(),
            auth_generation: 1,
            role: TransitionActorRole::Member,
            device_status: "active".to_owned(),
        },
        entry: ControlEntryContent {
            entry_id,
            entry_kind: "blue.catbird.chat.defs#participantAcceptanceEntry".to_owned(),
            accepted_payload_bytes: payload.clone(),
            accepted_payload_sha256: Sha256::digest(&payload).to_vec(),
            signed_request_bytes: transcript.clone(),
            unsigned_projection_bytes: vec![0xA3_u8; 8],
            signing_transcript_bytes: transcript.clone(),
            request_digest: Sha256::digest(&transcript).to_vec(),
            signature: vec![0xA4_u8; 64],
            server_fields_bytes: vec![0xA5_u8; 8],
            outer_entry_fingerprint: vec![0x16_u8; 32],
        },
        spine: SpineArtifacts {
            public_snapshot_bytes: vec![0xB1_u8; 16],
            public_snapshot_sha256: Sha256::digest([0xB1_u8; 16]).to_vec(),
            tree_summary_bytes: vec![0xB2_u8; 16],
            tree_summary_sha256: Sha256::digest([0xB2_u8; 16]).to_vec(),
            leaf_count: 1,
            genesis_group_info_bytes: vec![],
            genesis_group_info_sha256: vec![],
        },
        opened_leaves: vec![],
        metadata_author: None,
        participant_period_ids: vec![],
        leaf_period_ids: vec![],
        entry_recipients: entry_audience(
            &fixture.alice_id,
            &fixture.alice_did,
            &fixture.bob_id,
            &fixture.bob_did,
        ),
        events: vec![EventFanout {
            event_id: Uuid::new_v4(),
            event_kind: EventKind::ConversationChanged,
            payload_bytes: vec![0xB4_u8; 8],
            recipients: event_audience(
                &pool,
                &fixture.alice_id,
                &fixture.alice_did,
                &fixture.bob_id,
                &fixture.bob_did,
            )
            .await,
            outbox: vec![(Uuid::new_v4(), OutboxWorkKind::Stream)],
        }],
        closing_leaf_periods: vec![],
        reset_request_row: None,
        recovery_open: Some(RecoveryOpenContext {
            participant_period_id: Some(bob_period),
            package_not_after,
            replaced_leaf_period_id: None,
        }),
    };

    let mut tx = pool.begin().await.expect("begin acceptance");
    let applied = apply_conversation_persistence_plan(&mut tx, &plan, &ctx)
        .await
        .expect("acceptance applies");
    tx.commit()
        .await
        .expect("acceptance COMMIT past all deferred triggers");
    assert_eq!(applied.allocated_seq, 2);

    // stateVersion+1 at the same crypto coordinate; seq 2->3.
    let (sv, next_seq): (i64, i64) = sqlx::query_as(
        "SELECT current_state_version,next_entry_seq FROM chat.conversations WHERE conversation_id=$1",
    )
    .bind(conversation_id)
    .fetch_one(&pool)
    .await
    .expect("head");
    assert_eq!((sv, next_seq), (1, 3));
    let (skind, slife): (String, String) = sqlx::query_as(
        "SELECT state_kind,lifecycle FROM chat.generation_states WHERE conversation_id=$1 AND state_version=1",
    )
    .bind(conversation_id)
    .fetch_one(&pool)
    .await
    .expect("accept state");
    assert_eq!(
        (skind.as_str(), slife.as_str()),
        ("acceptConversation", "active")
    );
    // bob promoted to active with acceptance provenance.
    let (status, has_accept): (String, bool) = sqlx::query_as(
        "SELECT status, acceptance_transition_id IS NOT NULL FROM chat.participants WHERE conversation_id=$1 AND user_did=$2 AND current_membership",
    )
    .bind(conversation_id)
    .bind(&fixture.bob_did)
    .fetch_one(&pool)
    .await
    .expect("bob participant");
    assert_eq!((status.as_str(), has_accept), ("active", true));
    // The atomic recovery open: request open, reservation active, package reserved.
    let (req_status, req_source, req_kind): (String, String, String) = sqlx::query_as(
        "SELECT status,source,recovery_kind FROM chat.leaf_recovery_requests WHERE recovery_request_id=$1",
    )
    .bind(Uuid::from_bytes(recovery_request_id))
    .fetch_one(&pool)
    .await
    .expect("recovery request");
    assert_eq!(
        (req_status.as_str(), req_source.as_str(), req_kind.as_str()),
        ("open", "acceptConversation", "add")
    );
    let res_status: String = sqlx::query_scalar(
        "SELECT status FROM chat.key_package_reservations WHERE recovery_request_id=$1",
    )
    .bind(Uuid::from_bytes(recovery_request_id))
    .fetch_one(&pool)
    .await
    .expect("reservation");
    assert_eq!(res_status, "active");
    let pkg_status: String =
        sqlx::query_scalar("SELECT status FROM chat.key_packages WHERE key_package_ref=$1")
            .bind(key_package_ref.to_vec())
            .fetch_one(&pool)
            .await
            .expect("package");
    assert_eq!(pkg_status, "reserved");
    // The acceptance transition (prior 0,0 -> next 0,1).
    let (tkind, eseq): (String, i64) = sqlx::query_as(
        "SELECT kind,entry_seq FROM chat.transitions WHERE conversation_id=$1 AND kind='acceptConversation'",
    )
    .bind(conversation_id)
    .fetch_one(&pool)
    .await
    .expect("acceptance transition");
    assert_eq!((tkind.as_str(), eseq), ("acceptConversation", 2));
}

/// Remove one conversation's committed graph so the shared, never-truncated
/// clean-chat DB stays clean across runs. Runs inside ONE transaction: the
/// `chat.entries` <-> `chat.transitions` provenance FKs are circular and
/// DEFERRABLE INITIALLY DEFERRED, so both must be deleted before the (single)
/// commit-time check fires. Global `chat.events`/`chat.outbox` rows are not
/// conversation-scoped and are left in place (the event-recipient chain is
/// re-derived per run, so their accumulation is harmless).
async fn cleanup(pool: &PgPool, conversation_id: Uuid) {
    let mut tx = match pool.begin().await {
        Ok(tx) => tx,
        Err(_) => return,
    };
    for stmt in [
        "DELETE FROM chat.application_intervals WHERE conversation_id=$1",
        "DELETE FROM chat.member_devices WHERE conversation_id=$1",
        "DELETE FROM chat.participants WHERE conversation_id=$1",
        "DELETE FROM chat.metadata_snapshots WHERE conversation_id=$1",
        "DELETE FROM chat.entry_recipients WHERE conversation_id=$1",
        "DELETE FROM chat.entries WHERE conversation_id=$1",
        "DELETE FROM chat.transitions WHERE conversation_id=$1",
        "DELETE FROM chat.generation_states WHERE conversation_id=$1",
        "DELETE FROM chat.generations WHERE conversation_id=$1",
        "DELETE FROM chat.conversations WHERE conversation_id=$1",
    ] {
        if sqlx::query(stmt)
            .bind(conversation_id)
            .execute(&mut *tx)
            .await
            .is_err()
        {
            let _ = tx.rollback().await;
            return;
        }
    }
    let _ = tx.commit().await;
}
