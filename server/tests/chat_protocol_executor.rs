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
use sqlx::postgres::PgPoolOptions;
use sqlx::PgPool;
use uuid::Uuid;

use chat_protocol::public_state::{
    process_commit, verify_genesis_group_info, verify_recovery_welcome, ActivePublicState,
    GenesisGroupInfoExpectations,
};
use chat_protocol::repository::delivery::WelcomeRejectionReason;
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
    plan_close, plan_commit, plan_creation, plan_leaf_recovery_cancellation,
    plan_leaf_recovery_fulfillment, plan_leaf_recovery_request, plan_leave_cancellation,
    plan_leave_fulfillment, plan_leave_request, plan_policy, plan_reset_activation,
    plan_reset_request, plan_welcome_expiry_for_test, plan_welcome_response_for_test,
    plan_zero_leaf_leave, AcceptConversation, CloseConversation, CommitCommand,
    ControlEntryContent, ConversationHeadCasBinding, ConversationKind, ConversationState,
    CreationCommand, CreationDecision, DeviceIdentity, EventFanout, ExecutionActor,
    ExecutionContext, ExecutorError, LeafPersistenceColumns, LeafRecoveryCancellation,
    LeafRecoveryFulfillment, LeafRecoveryKind, LeafRecoveryRequestCommand, LeaveCancellation,
    LeaveFulfillment, LeaveRequestCommand, LockedRegistrationProjection, MetadataAuthorColumns,
    MetadataSnapshotBinding, PrincipalId, RecoveryOpenContext, RequestEntryKind, RequestEvidence,
    ResetActivation, ResetRequestCommand, ResetRequestRow, ServerTimestamp, SpineArtifacts,
    TransitionEvidence, WelcomeDispositionInput, WelcomeExpiryContext, WelcomeRejectionWork,
    WelcomeResponseContext, WelcomeStatus, ZeroLeafLeave,
};
use chat_protocol::validation::ed25519_key_id;
use chat_protocol::wire::{validate_public_commit, MAX_PUBLIC_MESSAGE_WIRE_BYTES};

// ---------------------------------------------------------------------------
// Harness + corpus fixtures (adapted from tests/chat_protocol_state_machine.rs).
// ---------------------------------------------------------------------------

/// Drops a uniquely-named per-run executor database (best-effort) when it falls
/// out of scope. Every executor test binds this guard so its private DB is torn
/// down at the end; a leaked `chat_exec_<uuid>` DB from a crashed run is
/// acceptable and identifiable by name. A fresh DB per run makes the whole
/// executor suite perfectly rerun-idempotent — no cross-run accumulation of the
/// fixed corpus creator's pending invitations (the shared-DB quota trip), and no
/// global `key_package_ref` / corpus-identity collisions — which is exactly what
/// unblocks the fixed-corpus-identity fulfillment test. The shared-DB harness
/// (`common::chat_protocol::setup_chat_protocol_db`, used by every OTHER test
/// file) is left untouched.
struct FreshDbGuard {
    maintenance_url: String,
    db_name: String,
}

impl Drop for FreshDbGuard {
    fn drop(&mut self) {
        let maintenance_url = self.maintenance_url.clone();
        let db_name = self.db_name.clone();
        // Own thread + runtime so teardown runs during panic unwind too.
        let _ = std::thread::spawn(move || {
            let Ok(rt) = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
            else {
                return;
            };
            rt.block_on(async move {
                let Ok(admin) = PgPoolOptions::new()
                    .max_connections(1)
                    .connect(&maintenance_url)
                    .await
                else {
                    return;
                };
                // Terminate the test's still-open connections so DROP is not blocked.
                let _ = sqlx::query(
                    "SELECT pg_terminate_backend(pid) FROM pg_stat_activity \
                     WHERE datname = $1 AND pid <> pg_backend_pid()",
                )
                .bind(&db_name)
                .execute(&admin)
                .await;
                let _ = sqlx::query(&format!("DROP DATABASE IF EXISTS \"{db_name}\""))
                    .execute(&admin)
                    .await;
            });
        })
        .join();
    }
}

/// Derive the maintenance connection URL (the server's `postgres` database) from
/// `TEST_DATABASE_URL`, enforcing loopback safety exactly as the shared gate does.
fn maintenance_url_from_env() -> String {
    let database_url = std::env::var("TEST_DATABASE_URL")
        .expect("TEST_DATABASE_URL must name the loopback clean-chat test database");
    common::chat_protocol::validate_chat_protocol_database_url(Some(&database_url))
        .expect("unsafe TEST_DATABASE_URL for the fresh-DB executor harness");
    let mut parsed = url::Url::parse(&database_url).expect("valid TEST_DATABASE_URL");
    parsed.set_path("/postgres");
    parsed.into()
}

async fn fresh_executor_db() -> (PgPool, FreshDbGuard) {
    let maintenance_url = maintenance_url_from_env();
    let admin = PgPoolOptions::new()
        .max_connections(1)
        .connect(&maintenance_url)
        .await
        .expect("connect to the loopback maintenance database");
    let db_name = format!("chat_exec_{}", Uuid::new_v4().simple());
    sqlx::query(&format!("CREATE DATABASE \"{db_name}\""))
        .execute(&admin)
        .await
        .expect("create a fresh per-run executor database");
    admin.close().await;

    let mut db_url = url::Url::parse(&maintenance_url).expect("maintenance url");
    db_url.set_path(&format!("/{db_name}"));
    let pool = PgPoolOptions::new()
        .max_connections(4)
        .connect(db_url.as_str())
        .await
        .expect("connect to the fresh per-run executor database");
    sqlx::migrate!("./migrations")
        .run(&pool)
        .await
        .expect("run the production migration set on the fresh executor database");
    (
        pool,
        FreshDbGuard {
            maintenance_url,
            db_name,
        },
    )
}

async fn setup() -> (PgPool, FreshDbGuard) {
    fresh_executor_db().await
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
    // Committed (post-ADD-commit) coordinate + the recovered inner key-package ref
    // — used only by the fulfillment scenario.
    committed_epoch: u64,
    committed_group_context_hash_hex: String,
    committed_confirmation_tag_hex: String,
    inner_key_package_ref_hex: String,
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
    // Default invitee: a FRESH principal each run with a fresh unique device key so
    // his `chat.device_keys` row (unique on `key_id`) is always present this run.
    let (bob_id, bob_did) = fresh_bob();
    build_creation_with_invitee(pool, kind, bob_id, bob_did, random_ref32().to_vec()).await
}

/// Creation with an explicit pending invitee — the fulfillment scenario passes the
/// FIXED corpus bob (whose credential the frozen ADD commit adds); on the fresh-DB
/// harness a fixed identity no longer collides across runs.
async fn build_creation_with_invitee(
    pool: &PgPool,
    kind: ConversationKind,
    bob_id: DeviceIdentity,
    bob_did: String,
    bob_sig_key: Vec<u8>,
) -> CreationApply {
    let manifest = corpus_manifest();
    let alice_id = alice(&manifest);
    let alice_did = manifest.identity.alice.actor_did.clone();
    let alice_device = Uuid::from_bytes(*alice_id.device_id());
    let bob_device = Uuid::from_bytes(*bob_id.device_id());
    let alice_sig_key: Vec<u8> =
        hex::decode(&manifest.identity.alice.signature_public_key_hex).unwrap();
    // Alice's MLS leaf signature key is also her device signing key here, so
    // member_devices.leaf_key_id == device_keys.key_id == actor_key_id.
    let alice_key_id = seed_actor(pool, &alice_did, alice_device, &alice_sig_key).await;
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
            author_key_id: alice_key_id.clone(),
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
        closing_participant_periods: Vec::new(),
        reset_request_row: None,
        recovery_open: None,
        welcome_expiry: None,
        welcome_response: None,
        welcome_dispositions: vec![],
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
    let (pool, _db) = setup().await;
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
    let (pool, _db) = setup().await;
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
    let (pool, _db) = setup().await;
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
    let (pool, _db) = setup().await;
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
    let (pool, _db) = setup().await;
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
    let (pool, _db) = setup().await;
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
        closing_participant_periods: Vec::new(),
        reset_request_row: None,
        recovery_open: None,
        welcome_expiry: None,
        welcome_response: None,
        welcome_dispositions: vec![],
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
    let (pool, _db) = setup().await;
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
    let (pool, _db) = setup().await;
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
    let (pool, _db) = setup().await;
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
        closing_participant_periods: vec![],
        reset_request_row: None,
        recovery_open: None,
        welcome_expiry: None,
        welcome_response: None,
        welcome_dispositions: vec![],
    }
}

#[tokio::test]
async fn reset_request_commits_without_changing_the_coordinate() {
    let (pool, _db) = setup().await;
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
        closing_participant_periods: vec![],
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
        welcome_expiry: None,
        welcome_response: None,
        welcome_dispositions: vec![],
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
        closing_participant_periods: vec![],
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
        welcome_expiry: None,
        welcome_response: None,
        welcome_dispositions: vec![],
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
    let (pool, _db) = setup().await;
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
        0,
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
            author_key_id: fixture.alice_key_id.clone(),
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
        closing_participant_periods: vec![],
        reset_request_row: None,
        recovery_open: None,
        welcome_expiry: None,
        welcome_response: None,
        welcome_dispositions: vec![],
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

/// Arm 3 #3 (reset shared-path supersession): a reset activation that retires a
/// generation carrying a PENDING WELCOME supersedes it through the same shared
/// `write_prior_bound_supersessions` + `write_welcome_supersessions` + reconcile
/// path the commit/fulfillment/leave arms use (own counts 0). Builds on
/// `run_fulfillment_scenario` (bob added at gen0/sv2 with a pending welcome bound to
/// gen0/sv2), opens an alice reset request, then activates: gen0 retires, a fresh
/// gen1 forms with alice's genesis leaf, both old intervals Reset-close, and bob's
/// pending welcome terminalizes `superseded`. (The open-recovery-request supersession
/// branch is COVERED-BY-EQUIVALENCE by the shared writer, already exercised by
/// `generic_commit_supersedes_prior_open_recovery_request`.)
#[tokio::test]
async fn reset_activation_supersedes_prior_pending_welcome() {
    let (pool, _db) = setup().await;
    let manifest = corpus_manifest();
    let scenario = run_fulfillment_scenario(&pool).await;
    let conversation_id = scenario.conversation_id;
    let alice_id = scenario.fixture.alice_id.clone();
    let alice_did = scenario.fixture.alice_did.clone();
    let alice_device = scenario.fixture.alice_device;
    let alice_key_id = scenario.fixture.alice_key_id.clone();
    let alice_sig_key = scenario.alice_sig_key.clone();
    let bob_id = scenario.bob_id.clone();
    let bob_did = scenario.bob_did.clone();
    let bob_device = Uuid::from_bytes(*bob_id.device_id());
    let protocol_instance_id = scenario.fixture.protocol_instance_id;
    let scenario_welcome_id = scenario.welcome_id;

    // The gen0 leaf periods the reset closes (alice + bob).
    let alice_leaf_period: Uuid = sqlx::query_scalar(
        "SELECT leaf_period_id FROM chat.member_devices WHERE conversation_id=$1 AND user_did=$2 AND active",
    )
    .bind(conversation_id)
    .bind(&alice_did)
    .fetch_one(&pool)
    .await
    .expect("alice leaf period");
    let bob_leaf_period: Uuid = sqlx::query_scalar(
        "SELECT leaf_period_id FROM chat.member_devices WHERE conversation_id=$1 AND user_did=$2 AND active",
    )
    .bind(conversation_id)
    .bind(&bob_did)
    .fetch_one(&pool)
    .await
    .expect("bob leaf period");

    // 1. Alice opens a reset request (seq 4) against the fulfillment coordinate.
    let req_received = ServerTimestamp::from_unix_millis_for_test(
        manifest.evaluation_unix_seconds as i64 * 1_000 + 5_000,
    )
    .unwrap();
    let reset_request_id = Uuid::new_v4();
    let req_evidence = RequestEvidence::for_test(
        RequestEntryKind::ResetRequest,
        4,
        *reset_request_id.as_bytes(),
        alice_id.clone(),
        *conversation_id.as_bytes(),
        req_received,
        0x91,
    )
    .unwrap();
    let req_planned = plan_reset_request(
        &scenario.fulfillment_state,
        ResetRequestCommand {
            actor: alice_id.clone(),
            reset_request_id: *reset_request_id.as_bytes(),
            received_at: req_received,
            evidence: req_evidence,
        },
    )
    .expect("valid reset request plan");
    let reset_state = req_planned.resulting_state().clone();
    let req_entry = Uuid::new_v4();
    let req_head = ConversationHeadCasBinding::for_test_edge(
        *conversation_id.as_bytes(),
        *req_entry.as_bytes(),
        scenario.coordinate,
        4,
        req_received,
    );
    let req_plan = persistence_plan_for_test(req_planned, req_head);
    let req_applied_at = clock_now(&pool).await;
    let req_transcript = vec![0x92_u8; 16];
    let req_digest = Sha256::digest(&req_transcript).to_vec();
    let req_signature = vec![0x93_u8; 64];
    let alice_pred_req = device_event_predecessor(&pool, &alice_did, alice_device).await;
    let req_ctx = ExecutionContext {
        protocol_instance_id,
        applied_at: req_applied_at,
        actor: ExecutionActor {
            user_did: alice_did.clone(),
            device_id: alice_device,
            key_id: alice_key_id.clone(),
            auth_generation: 1,
            role: TransitionActorRole::Admin,
            device_status: "active".to_owned(),
        },
        entry: ControlEntryContent {
            entry_id: req_entry,
            entry_kind: "blue.catbird.chat.defs#resetRequestEntry".to_owned(),
            accepted_payload_bytes: vec![0x94_u8; 8],
            accepted_payload_sha256: Sha256::digest([0x94_u8; 8]).to_vec(),
            signed_request_bytes: req_transcript.clone(),
            unsigned_projection_bytes: vec![0x95_u8; 8],
            signing_transcript_bytes: req_transcript.clone(),
            request_digest: req_digest.clone(),
            signature: req_signature.clone(),
            server_fields_bytes: vec![0x96_u8; 8],
            outer_entry_fingerprint: vec![0x1A_u8; 32],
        },
        spine: SpineArtifacts {
            public_snapshot_bytes: vec![],
            public_snapshot_sha256: vec![],
            tree_summary_bytes: vec![],
            tree_summary_sha256: vec![],
            leaf_count: 2,
            genesis_group_info_bytes: vec![],
            genesis_group_info_sha256: vec![],
        },
        opened_leaves: vec![],
        metadata_author: None,
        participant_period_ids: vec![],
        leaf_period_ids: vec![],
        entry_recipients: vec![(alice_id.clone(), EntryEntitlementKind::Control)],
        events: vec![EventFanout {
            event_id: Uuid::new_v4(),
            event_kind: EventKind::ResetRequested,
            payload_bytes: vec![0x97_u8; 8],
            recipients: vec![(
                alice_id.clone(),
                EventEntitlementKind::Participant,
                alice_pred_req,
            )],
            outbox: vec![(Uuid::new_v4(), OutboxWorkKind::Stream)],
        }],
        closing_leaf_periods: vec![],
        closing_participant_periods: vec![],
        reset_request_row: Some(ResetRequestRow {
            reset_request_id,
            reason: ResetReason::PoisonedState,
            signed_request_bytes: req_transcript.clone(),
            signing_transcript_bytes: req_transcript,
            request_digest: req_digest,
            signature: req_signature,
            expires_at: req_applied_at + Duration::hours(24),
        }),
        recovery_open: None,
        welcome_expiry: None,
        welcome_response: None,
        welcome_dispositions: vec![],
    };
    {
        let mut tx = pool.begin().await.expect("begin reset request");
        apply_conversation_persistence_plan(&mut tx, &req_plan, &req_ctx)
            .await
            .expect("reset request applies");
        tx.commit()
            .await
            .expect("reset request COMMIT past all deferred triggers");
    }

    // 2. Alice activates the reset (seq 5): gen0 retires, gen1 forms with alice's
    //    genesis leaf, and bob's pending welcome supersedes.
    let successor_coordinate = PublicGroupSnapshotCoordinate::new(
        *conversation_id.as_bytes(),
        scenario.coordinate.generation() + 1,
        0,
        [0xA1_u8; 32],
        0,
        [0xA2_u8; 32],
        [0xA3_u8; 32],
        PublicGroupSnapshotLifecycle::Active,
    );
    let successor_public_state =
        ActivePublicState::for_test(&verified_genesis(&manifest), successor_coordinate);
    let retired_coordinate = PublicGroupSnapshotCoordinate::new(
        *conversation_id.as_bytes(),
        scenario.coordinate.generation(),
        scenario.coordinate.state_version() + 1,
        *scenario.coordinate.group_id(),
        scenario.coordinate.epoch(),
        *scenario.coordinate.group_context_hash(),
        *scenario.coordinate.confirmation_tag(),
        PublicGroupSnapshotLifecycle::Superseded,
    );
    let act_received = ServerTimestamp::from_unix_millis_for_test(
        manifest.evaluation_unix_seconds as i64 * 1_000 + 6_000,
    )
    .unwrap();
    let act_transition = Uuid::new_v4();
    let act_entry = Uuid::new_v4();
    let metadata = MetadataSnapshotBinding::for_test_creation(
        *conversation_id.as_bytes(),
        1,
        0,
        [0xA2_u8; 32],
        *act_transition.as_bytes(),
        3,
        alice_id.clone(),
        Sha256::digest(&alice_sig_key).into(),
        alice_sig_key.clone().try_into().unwrap(),
        1,
        2,
        [0xA8_u8; 12],
        vec![0xA9_u8; 48],
    );
    let act_evidence = TransitionEvidence::for_test_reset_activation_with_metadata(
        5,
        *act_transition.as_bytes(),
        [0x1B_u8; 32],
        act_received,
        ConversationKind::Group,
        *reset_request_id.as_bytes(),
        scenario.coordinate,
        retired_coordinate,
        successor_coordinate,
        alice_id.clone(),
        metadata,
    )
    .unwrap();
    let planned = plan_reset_activation(
        &reset_state,
        ResetActivation {
            actor: alice_id.clone(),
            reset_request_id: *reset_request_id.as_bytes(),
            transition: act_evidence,
            successor_public_state,
        },
    )
    .expect("valid reset activation plan");
    let head_cas = ConversationHeadCasBinding::for_test_edge(
        *conversation_id.as_bytes(),
        *act_entry.as_bytes(),
        scenario.coordinate,
        5,
        act_received,
    );
    let plan = persistence_plan_for_test(planned, head_cas);

    // Participant periods in hydration (sorted-DID) order — alice AND bob remain
    // participants in the reset state (bob without a gen1 leaf until he re-joins).
    let mut participant_rows: Vec<(String, Uuid)> = sqlx::query_as(
        "SELECT user_did,participant_period_id FROM chat.participants WHERE conversation_id=$1 AND current_membership",
    )
    .bind(conversation_id)
    .fetch_all(&pool)
    .await
    .expect("participant periods");
    participant_rows.sort_by(|l, r| l.0.as_bytes().cmp(r.0.as_bytes()));
    let participant_period_ids: Vec<Uuid> = participant_rows.iter().map(|(_, id)| *id).collect();

    let applied_at = clock_now(&pool).await;
    let payload = vec![0xAA_u8; 12];
    let transcript = vec![0xAB_u8; 12];
    let alice_pred = device_event_predecessor(&pool, &alice_did, alice_device).await;
    let bob_pred = device_event_predecessor(&pool, &bob_did, bob_device).await;
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
            entry_id: act_entry,
            entry_kind: "blue.catbird.chat.defs#resetActivationEntry".to_owned(),
            accepted_payload_bytes: payload.clone(),
            accepted_payload_sha256: Sha256::digest(&payload).to_vec(),
            signed_request_bytes: transcript.clone(),
            unsigned_projection_bytes: vec![0xAC_u8; 8],
            signing_transcript_bytes: transcript.clone(),
            request_digest: Sha256::digest(&transcript).to_vec(),
            signature: vec![0xAD_u8; 64],
            server_fields_bytes: vec![0xAE_u8; 8],
            outer_entry_fingerprint: vec![0x1B_u8; 32],
        },
        spine: SpineArtifacts {
            public_snapshot_bytes: vec![0xB1_u8; 16],
            public_snapshot_sha256: Sha256::digest([0xB1_u8; 16]).to_vec(),
            tree_summary_bytes: vec![0xB2_u8; 16],
            tree_summary_sha256: Sha256::digest([0xB2_u8; 16]).to_vec(),
            leaf_count: 1,
            genesis_group_info_bytes: vec![0xB3_u8; 16],
            genesis_group_info_sha256: Sha256::digest([0xB3_u8; 16]).to_vec(),
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
            author_key_id: alice_key_id.clone(),
            metadata_snapshot_id: Uuid::new_v4(),
        }),
        participant_period_ids,
        leaf_period_ids: vec![Uuid::new_v4()],
        // Both gen0 devices' intervals Reset-close at this seq, so both route via
        // intervalClose; bob's single event this transition is the welcome disposition.
        entry_recipients: vec![
            (alice_id.clone(), EntryEntitlementKind::IntervalClose),
            (bob_id.clone(), EntryEntitlementKind::IntervalClose),
        ],
        events: vec![EventFanout {
            event_id: Uuid::new_v4(),
            event_kind: EventKind::ConversationChanged,
            payload_bytes: vec![0xB4_u8; 8],
            recipients: vec![(
                alice_id.clone(),
                EventEntitlementKind::Participant,
                alice_pred,
            )],
            outbox: vec![(Uuid::new_v4(), OutboxWorkKind::Stream)],
        }],
        closing_leaf_periods: vec![
            (alice_id.clone(), alice_leaf_period),
            (bob_id.clone(), bob_leaf_period),
        ],
        closing_participant_periods: vec![],
        reset_request_row: None,
        recovery_open: None,
        welcome_expiry: None,
        welcome_response: None,
        welcome_dispositions: vec![WelcomeDispositionInput {
            welcome_id: scenario_welcome_id,
            event: EventFanout {
                event_id: Uuid::new_v4(),
                event_kind: EventKind::WelcomeDisposition,
                payload_bytes: vec![0xB5_u8; 8],
                recipients: vec![(bob_id.clone(), EventEntitlementKind::Welcome, bob_pred)],
                outbox: vec![(Uuid::new_v4(), OutboxWorkKind::Stream)],
            },
        }],
    };

    let mut tx = pool.begin().await.expect("begin reset activation");
    let applied = apply_conversation_persistence_plan(&mut tx, &plan, &ctx)
        .await
        .expect("reset activation applies");
    tx.commit()
        .await
        .expect("reset activation COMMIT past all deferred triggers");
    assert_eq!(applied.allocated_seq, 5);

    // Head at the gen1 successor pointer; bob's pending welcome superseded.
    let (gen, sv, next_seq): (i64, i64, i64) = sqlx::query_as(
        "SELECT current_generation,current_state_version,next_entry_seq FROM chat.conversations WHERE conversation_id=$1",
    )
    .bind(conversation_id)
    .fetch_one(&pool)
    .await
    .expect("head");
    assert_eq!((gen, sv, next_seq), (1, 0, 6));
    let welcome_status: String =
        sqlx::query_scalar("SELECT status FROM chat.welcome_deliveries WHERE welcome_id=$1")
            .bind(scenario_welcome_id)
            .fetch_one(&pool)
            .await
            .expect("welcome");
    assert_eq!(welcome_status, "superseded");
    // gen1 active with alice's genesis leaf; the reset request consumed.
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
            .bind(reset_request_id)
            .fetch_one(&pool)
            .await
            .expect("reset request status");
    assert_eq!(req_status, "consumed");
    // Both gen0 intervals Reset-closed at the activation seq.
    let closed_at_reset: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM chat.application_intervals WHERE conversation_id=$1 AND terminal_seq=5 AND closing_kind='reset'",
    )
    .bind(conversation_id)
    .fetch_one(&pool)
    .await
    .expect("closed intervals");
    assert_eq!(closed_at_reset, 2);

    // Replay -> head CAS conflict (head at gen1), zero residue.
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
        "reset activation replay must conflict on the head CAS, got {replay:?}"
    );
    tx2.rollback().await.expect("rollback replay");
    let after: i64 =
        sqlx::query_scalar("SELECT count(*) FROM chat.transitions WHERE conversation_id=$1")
            .bind(conversation_id)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(before, after, "reset activation replay left zero residue");
}

#[tokio::test]
async fn creation_plan_without_invitation_quota_binding_is_rejected() {
    let (pool, _db) = setup().await;
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
    let (pool, _db) = setup().await;

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
    // Align `not_after` to whole milliseconds: the Welcome delivery's `expires_at`
    // (a `ServerTimestamp`, millisecond-precision) is FK-bound to this exact value,
    // so a sub-millisecond `not_after` would never match the round-tripped instant.
    let not_after =
        DateTime::from_timestamp_millis((now + Duration::hours(24)).timestamp_millis()).unwrap();
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
    let (pool, _db) = setup().await;
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
        closing_participant_periods: vec![],
        reset_request_row: None,
        recovery_open: Some(RecoveryOpenContext {
            participant_period_id: Some(bob_period),
            package_not_after,
            replaced_leaf_period_id: None,
        }),
        welcome_expiry: None,
        welcome_response: None,
        welcome_dispositions: vec![],
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

    // Review MINOR-3: re-apply the committed acceptance plan -> the head CAS
    // conflicts (the head already advanced to stateVersion 1), the whole
    // transaction rolls back with zero residue.
    let before: i64 =
        sqlx::query_scalar("SELECT count(*) FROM chat.transitions WHERE conversation_id=$1")
            .bind(conversation_id)
            .fetch_one(&pool)
            .await
            .unwrap();
    let mut tx2 = pool.begin().await.expect("begin re-apply acceptance");
    let reapply = apply_conversation_persistence_plan(&mut tx2, &plan, &ctx).await;
    assert!(
        matches!(reapply, Err(ExecutorError::Transition(_))),
        "acceptance re-apply must conflict on the head CAS, got {reapply:?}"
    );
    tx2.rollback().await.expect("rollback re-apply acceptance");
    let after: i64 =
        sqlx::query_scalar("SELECT count(*) FROM chat.transitions WHERE conversation_id=$1")
            .bind(conversation_id)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(before, after, "acceptance re-apply left zero residue");
}

#[tokio::test]
async fn leaf_recovery_replace_request_commits_without_advancing_coordinate() {
    let (pool, _db) = setup().await;
    let fixture = commit_creation(&pool, ConversationKind::Group).await;
    let conversation_id = fixture.conversation_id;

    // alice's committed genesis leaf period (the leaf a `replace` recovers).
    let alice_leaf_period: Uuid = sqlx::query_scalar(
        "SELECT leaf_period_id FROM chat.member_devices WHERE conversation_id=$1 AND user_did=$2",
    )
    .bind(conversation_id)
    .bind(&fixture.alice_did)
    .fetch_one(&pool)
    .await
    .expect("alice leaf period");

    // A fresh available key package owned by alice to reserve.
    let key_package_ref = random_ref32();
    let package_not_after = seed_key_package(
        &pool,
        &fixture.alice_did,
        fixture.alice_device,
        &fixture.alice_key_id,
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
    let recovery_request_id = Uuid::new_v4();
    let evidence = RequestEvidence::for_test(
        RequestEntryKind::LeafRecoveryRequest,
        2,
        *recovery_request_id.as_bytes(),
        fixture.alice_id.clone(),
        *conversation_id.as_bytes(),
        received_at,
        0x71,
    )
    .unwrap();
    let planned = plan_leaf_recovery_request(
        &fixture.state,
        LeafRecoveryRequestCommand {
            actor: fixture.alice_id.clone(),
            recovery_request_id: *recovery_request_id.as_bytes(),
            kind: LeafRecoveryKind::Replace,
            key_package_ref,
            received_at,
            package_not_after: pkg_not_after_ts,
            evidence,
        },
    )
    .expect("valid leaf recovery request plan");
    let head_cas = ConversationHeadCasBinding::for_test_internal(
        *conversation_id.as_bytes(),
        fixture.coordinate,
        2,
        received_at,
    );
    let plan = persistence_plan_for_test(planned, head_cas);

    let applied_at = clock_now(&pool).await;
    let transcript = vec![0x72_u8; 16];
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
            role: TransitionActorRole::Admin,
            device_status: "active".to_owned(),
        },
        // Internal op: the executor appends no control entry, but write_recovery_open
        // sources the leaf_recovery_requests signed material from ctx.entry.
        entry: ControlEntryContent {
            entry_id: Uuid::new_v4(),
            entry_kind: "blue.catbird.chat.defs#applicationEntry".to_owned(),
            accepted_payload_bytes: vec![0x73_u8; 8],
            accepted_payload_sha256: Sha256::digest([0x73_u8; 8]).to_vec(),
            signed_request_bytes: transcript.clone(),
            unsigned_projection_bytes: vec![0x74_u8; 8],
            signing_transcript_bytes: transcript.clone(),
            request_digest: Sha256::digest(&transcript).to_vec(),
            signature: vec![0x75_u8; 64],
            server_fields_bytes: vec![0x76_u8; 8],
            outer_entry_fingerprint: vec![0x17_u8; 32],
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
        entry_recipients: vec![],
        events: vec![EventFanout {
            event_id: Uuid::new_v4(),
            event_kind: EventKind::ConversationChanged,
            payload_bytes: vec![0x77_u8; 8],
            recipients: vec![(
                fixture.alice_id.clone(),
                EventEntitlementKind::Participant,
                alice_pred,
            )],
            outbox: vec![(Uuid::new_v4(), OutboxWorkKind::Stream)],
        }],
        closing_leaf_periods: vec![],
        closing_participant_periods: vec![],
        reset_request_row: None,
        recovery_open: Some(RecoveryOpenContext {
            participant_period_id: None,
            package_not_after,
            replaced_leaf_period_id: Some(alice_leaf_period),
        }),
        welcome_expiry: None,
        welcome_response: None,
        welcome_dispositions: vec![],
    };

    let mut tx = pool.begin().await.expect("begin leaf recovery request");
    apply_conversation_persistence_plan(&mut tx, &plan, &ctx)
        .await
        .expect("leaf recovery request applies");
    tx.commit()
        .await
        .expect("leaf recovery request COMMIT past all deferred triggers");

    // Coordinate + seq counter UNCHANGED (still 0,0,active,next_seq 2).
    let (gen, sv, next_seq, lifecycle): (i64, i64, i64, String) = sqlx::query_as(
        "SELECT current_generation,current_state_version,next_entry_seq,lifecycle FROM chat.conversations WHERE conversation_id=$1",
    )
    .bind(conversation_id)
    .fetch_one(&pool)
    .await
    .expect("head");
    assert_eq!((gen, sv, next_seq, lifecycle.as_str()), (0, 0, 2, "active"));
    // No new transition (internal op authored none).
    let transitions: i64 =
        sqlx::query_scalar("SELECT count(*) FROM chat.transitions WHERE conversation_id=$1")
            .bind(conversation_id)
            .fetch_one(&pool)
            .await
            .expect("transitions");
    assert_eq!(transitions, 1, "only the creation transition exists");
    // Open replace recovery request + active reservation + reserved package.
    let (req_status, req_source, req_kind, replaced): (String, String, String, Option<Uuid>) = sqlx::query_as(
        "SELECT status,source,recovery_kind,replaced_leaf_period_id FROM chat.leaf_recovery_requests WHERE recovery_request_id=$1",
    )
    .bind(recovery_request_id)
    .fetch_one(&pool)
    .await
    .expect("recovery request");
    assert_eq!(
        (req_status.as_str(), req_source.as_str(), req_kind.as_str()),
        ("open", "requestLeafRecovery", "replace")
    );
    assert_eq!(replaced, Some(alice_leaf_period));
    let res_status: String = sqlx::query_scalar(
        "SELECT status FROM chat.key_package_reservations WHERE recovery_request_id=$1",
    )
    .bind(recovery_request_id)
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
}

struct CommittedRecoveryRequest {
    state: ConversationState,
    request_id: Uuid,
    key_package_ref: [u8; 32],
    package_not_after: DateTime<Utc>,
}

/// Build + commit a `replace` leaf-recovery request by the active creator (alice)
/// and return the resulting state (carrying the open request) + its identifiers.
struct BuiltReplaceRequest {
    plan: chat_protocol::state_machine::ConversationPersistencePlan,
    ctx: ExecutionContext,
    committed: CommittedRecoveryRequest,
}

async fn commit_replace_recovery_request(
    pool: &PgPool,
    fixture: &CreationApply,
    request_byte: u8,
) -> CommittedRecoveryRequest {
    let built = build_replace_recovery_request(pool, fixture, request_byte).await;
    let mut tx = pool.begin().await.expect("begin recovery request");
    apply_conversation_persistence_plan(&mut tx, &built.plan, &built.ctx)
        .await
        .expect("recovery request applies");
    tx.commit().await.expect("recovery request COMMIT");
    built.committed
}

async fn build_replace_recovery_request(
    pool: &PgPool,
    fixture: &CreationApply,
    request_byte: u8,
) -> BuiltReplaceRequest {
    let conversation_id = fixture.conversation_id;
    let alice_leaf_period: Uuid = sqlx::query_scalar(
        "SELECT leaf_period_id FROM chat.member_devices WHERE conversation_id=$1 AND user_did=$2",
    )
    .bind(conversation_id)
    .bind(&fixture.alice_did)
    .fetch_one(pool)
    .await
    .expect("alice leaf period");
    let key_package_ref = random_ref32();
    let package_not_after = seed_key_package(
        pool,
        &fixture.alice_did,
        fixture.alice_device,
        &fixture.alice_key_id,
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
    let request_id = Uuid::new_v4();
    let evidence = RequestEvidence::for_test(
        RequestEntryKind::LeafRecoveryRequest,
        2,
        *request_id.as_bytes(),
        fixture.alice_id.clone(),
        *conversation_id.as_bytes(),
        received_at,
        request_byte,
    )
    .unwrap();
    let planned = plan_leaf_recovery_request(
        &fixture.state,
        LeafRecoveryRequestCommand {
            actor: fixture.alice_id.clone(),
            recovery_request_id: *request_id.as_bytes(),
            kind: LeafRecoveryKind::Replace,
            key_package_ref,
            received_at,
            package_not_after: pkg_not_after_ts,
            evidence,
        },
    )
    .expect("valid leaf recovery request plan");
    let state = planned.resulting_state().clone();
    let head_cas = ConversationHeadCasBinding::for_test_internal(
        *conversation_id.as_bytes(),
        fixture.coordinate,
        2,
        received_at,
    );
    let plan = persistence_plan_for_test(planned, head_cas);
    let applied_at = clock_now(pool).await;
    let transcript = vec![request_byte; 16];
    let alice_pred = device_event_predecessor(pool, &fixture.alice_did, fixture.alice_device).await;
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
            entry_id: Uuid::new_v4(),
            entry_kind: "blue.catbird.chat.defs#applicationEntry".to_owned(),
            accepted_payload_bytes: vec![request_byte; 8],
            accepted_payload_sha256: Sha256::digest([request_byte; 8]).to_vec(),
            signed_request_bytes: transcript.clone(),
            unsigned_projection_bytes: vec![request_byte; 8],
            signing_transcript_bytes: transcript.clone(),
            request_digest: Sha256::digest(&transcript).to_vec(),
            signature: vec![request_byte; 64],
            server_fields_bytes: vec![request_byte; 8],
            outer_entry_fingerprint: vec![request_byte; 32],
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
        entry_recipients: vec![],
        events: vec![EventFanout {
            event_id: Uuid::new_v4(),
            event_kind: EventKind::ConversationChanged,
            payload_bytes: vec![request_byte; 8],
            recipients: vec![(
                fixture.alice_id.clone(),
                EventEntitlementKind::Participant,
                alice_pred,
            )],
            outbox: vec![(Uuid::new_v4(), OutboxWorkKind::Stream)],
        }],
        closing_leaf_periods: vec![],
        closing_participant_periods: vec![],
        reset_request_row: None,
        recovery_open: Some(RecoveryOpenContext {
            participant_period_id: None,
            package_not_after,
            replaced_leaf_period_id: Some(alice_leaf_period),
        }),
        welcome_expiry: None,
        welcome_response: None,
        welcome_dispositions: vec![],
    };
    BuiltReplaceRequest {
        plan,
        ctx,
        committed: CommittedRecoveryRequest {
            state,
            request_id,
            key_package_ref,
            package_not_after,
        },
    }
}

#[tokio::test]
async fn recovery_package_cas_desync_is_rejected() {
    let (pool, _db) = setup().await;
    let fixture = commit_creation(&pool, ConversationKind::Group).await;
    let conversation_id = fixture.conversation_id;
    // A valid replace-request plan, then STRIP its recovery_package_cas so it
    // desyncs from package_transitions. Production requires the two bijective
    // (package_cas_bijection_valid); the executor's load-bearing
    // verify_recovery_package_consistency must reject BEFORE any write — removing
    // that assert fails this test.
    let built = build_replace_recovery_request(&pool, &fixture, 0x93).await;
    let stripped = built.plan.with_recovery_package_cas_cleared_for_test();
    let mut tx = pool.begin().await.expect("begin");
    let result = apply_conversation_persistence_plan(&mut tx, &stripped, &built.ctx).await;
    assert!(
        matches!(result, Err(ExecutorError::InconsistentPlan(_))),
        "a desynced recovery_package_cas must be an InconsistentPlan, got {result:?}"
    );
    tx.rollback().await.expect("rollback");
    let reservations: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM chat.key_package_reservations WHERE conversation_id=$1",
    )
    .bind(conversation_id)
    .fetch_one(&pool)
    .await
    .expect("reservations");
    assert_eq!(reservations, 0, "a rejected plan writes nothing");
}

#[tokio::test]
async fn leaf_recovery_cancellation_releases_reservation_and_reactivates_package() {
    let (pool, _db) = setup().await;
    let fixture = commit_creation(&pool, ConversationKind::Group).await;
    let conversation_id = fixture.conversation_id;
    let req = commit_replace_recovery_request(&pool, &fixture, 0x71).await;

    // Cancel the open request: received AFTER the request, a DISTINCT digest.
    let cancel_received = ServerTimestamp::from_unix_millis_for_test(
        corpus_manifest().evaluation_unix_seconds as i64 * 1_000 + 4_000,
    )
    .unwrap();
    let cancel_evidence = RequestEvidence::for_test(
        RequestEntryKind::LeafRecoveryCancellation,
        2,
        *req.request_id.as_bytes(),
        fixture.alice_id.clone(),
        *conversation_id.as_bytes(),
        cancel_received,
        0x81,
    )
    .unwrap();
    let planned = plan_leaf_recovery_cancellation(
        &req.state,
        LeafRecoveryCancellation {
            actor: fixture.alice_id.clone(),
            recovery_request_id: *req.request_id.as_bytes(),
            received_at: cancel_received,
            evidence: cancel_evidence,
        },
    )
    .expect("valid cancellation plan");
    let head_cas = ConversationHeadCasBinding::for_test_internal(
        *conversation_id.as_bytes(),
        fixture.coordinate,
        2,
        cancel_received,
    );
    let plan = persistence_plan_for_test(planned, head_cas);

    let applied_at = clock_now(&pool).await;
    let cancel_transcript = vec![0x82_u8; 16];
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
            role: TransitionActorRole::Admin,
            device_status: "active".to_owned(),
        },
        entry: ControlEntryContent {
            entry_id: Uuid::new_v4(),
            entry_kind: "blue.catbird.chat.defs#applicationEntry".to_owned(),
            accepted_payload_bytes: vec![0x83_u8; 8],
            accepted_payload_sha256: Sha256::digest([0x83_u8; 8]).to_vec(),
            signed_request_bytes: cancel_transcript.clone(),
            unsigned_projection_bytes: vec![0x84_u8; 8],
            signing_transcript_bytes: cancel_transcript.clone(),
            request_digest: Sha256::digest(&cancel_transcript).to_vec(),
            signature: vec![0x85_u8; 64],
            server_fields_bytes: vec![0x86_u8; 8],
            outer_entry_fingerprint: vec![0x18_u8; 32],
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
        entry_recipients: vec![],
        events: vec![EventFanout {
            event_id: Uuid::new_v4(),
            event_kind: EventKind::ConversationChanged,
            payload_bytes: vec![0x87_u8; 8],
            recipients: vec![(
                fixture.alice_id.clone(),
                EventEntitlementKind::Participant,
                alice_pred,
            )],
            outbox: vec![(Uuid::new_v4(), OutboxWorkKind::Stream)],
        }],
        closing_leaf_periods: vec![],
        closing_participant_periods: vec![],
        reset_request_row: None,
        recovery_open: None,
        welcome_expiry: None,
        welcome_response: None,
        welcome_dispositions: vec![],
    };

    let mut tx = pool.begin().await.expect("begin cancellation");
    apply_conversation_persistence_plan(&mut tx, &plan, &ctx)
        .await
        .expect("cancellation applies");
    tx.commit()
        .await
        .expect("cancellation COMMIT past all deferred triggers");

    // Coordinate + seq counter still byte-untouched.
    let (gen, sv, next_seq): (i64, i64, i64) = sqlx::query_as(
        "SELECT current_generation,current_state_version,next_entry_seq FROM chat.conversations WHERE conversation_id=$1",
    )
    .bind(conversation_id)
    .fetch_one(&pool)
    .await
    .expect("head");
    assert_eq!((gen, sv, next_seq), (0, 0, 2));
    // Request cancelled, reservation released, package back to available.
    let req_status: String = sqlx::query_scalar(
        "SELECT status FROM chat.leaf_recovery_requests WHERE recovery_request_id=$1",
    )
    .bind(req.request_id)
    .fetch_one(&pool)
    .await
    .expect("recovery request");
    assert_eq!(req_status, "cancelled");
    let res_status: String = sqlx::query_scalar(
        "SELECT status FROM chat.key_package_reservations WHERE recovery_request_id=$1",
    )
    .bind(req.request_id)
    .fetch_one(&pool)
    .await
    .expect("reservation");
    assert_eq!(res_status, "released");
    let (pkg_status, terminal_at): (String, Option<DateTime<Utc>>) =
        sqlx::query_as("SELECT status,terminal_at FROM chat.key_packages WHERE key_package_ref=$1")
            .bind(req.key_package_ref.to_vec())
            .fetch_one(&pool)
            .await
            .expect("package");
    assert_eq!((pkg_status.as_str(), terminal_at), ("available", None));

    // Replay the cancellation -> the request is no longer 'open', the terminalize
    // CAS conflicts, whole transaction rolls back with zero residue.
    let mut tx2 = pool.begin().await.expect("begin replay");
    let replay = apply_conversation_persistence_plan(&mut tx2, &plan, &ctx).await;
    assert!(
        matches!(replay, Err(ExecutorError::Transition(_))),
        "cancellation replay must conflict on the terminalize CAS, got {replay:?}"
    );
    tx2.rollback().await.expect("rollback replay");
    // The package stayed available (no double re-activation).
    let pkg_after: String =
        sqlx::query_scalar("SELECT status FROM chat.key_packages WHERE key_package_ref=$1")
            .bind(req.key_package_ref.to_vec())
            .fetch_one(&pool)
            .await
            .expect("package after replay");
    assert_eq!(pkg_after, "available");
    let _ = req.package_not_after;
}

/// The acceptance `ExecutionContext` for an invitee accepting (used by the
/// fulfillment scenario). Actor = the invitee (member/active), audience = the two
/// current devices, recovery_open bound to the invitee's participant period.
#[allow(clippy::too_many_arguments)]
async fn acceptance_ctx(
    pool: &PgPool,
    fixture: &CreationApply,
    bob_id: &DeviceIdentity,
    bob_did: &str,
    bob_key_id: &str,
    entry_id: Uuid,
    bob_period: Uuid,
    package_not_after: DateTime<Utc>,
) -> ExecutionContext {
    let applied_at = clock_now(pool).await;
    let payload = vec![0xA1_u8; 12];
    let transcript = vec![0xA2_u8; 12];
    ExecutionContext {
        protocol_instance_id: fixture.protocol_instance_id,
        applied_at,
        actor: ExecutionActor {
            user_did: bob_did.to_owned(),
            device_id: Uuid::from_bytes(*bob_id.device_id()),
            key_id: bob_key_id.to_owned(),
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
        entry_recipients: entry_audience(&fixture.alice_id, &fixture.alice_did, bob_id, bob_did),
        events: vec![EventFanout {
            event_id: Uuid::new_v4(),
            event_kind: EventKind::ConversationChanged,
            payload_bytes: vec![0xB4_u8; 8],
            recipients: event_audience(
                pool,
                &fixture.alice_id,
                &fixture.alice_did,
                bob_id,
                bob_did,
            )
            .await,
            outbox: vec![(Uuid::new_v4(), OutboxWorkKind::Stream)],
        }],
        closing_leaf_periods: vec![],
        closing_participant_periods: vec![],
        reset_request_row: None,
        recovery_open: Some(RecoveryOpenContext {
            participant_period_id: Some(bob_period),
            package_not_after,
            replaced_leaf_period_id: None,
        }),
        welcome_expiry: None,
        welcome_response: None,
        welcome_dispositions: vec![],
    }
}

fn bob_corpus(manifest: &CorpusManifest) -> DeviceIdentity {
    DeviceIdentity::new(
        PrincipalId::new(manifest.identity.bob.actor_did.as_bytes().to_vec()).unwrap(),
        uuid_bytes(&manifest.identity.bob.device_id),
    )
    .unwrap()
}

/// The committed (post-ADD-commit) coordinate: same generation/group_id, the
/// committed epoch/hash/tag, at `state_version`.
fn committed_coordinate(
    manifest: &CorpusManifest,
    conversation_id: [u8; 16],
    state_version: u64,
) -> PublicGroupSnapshotCoordinate {
    PublicGroupSnapshotCoordinate::new(
        conversation_id,
        manifest.chain.generation,
        state_version,
        hex_array(&manifest.chain.group_id_hex),
        manifest.chain.committed_epoch,
        hex_array(&manifest.chain.committed_group_context_hash_hex),
        hex_array(&manifest.chain.committed_confirmation_tag_hex),
        PublicGroupSnapshotLifecycle::Active,
    )
}

/// Process the frozen corpus ADD commit against the accepted state's public state,
/// producing the verified committed public state the fulfillment consumes.
fn verified_add_commit(
    state: &chat_protocol::state_machine::ConversationState,
    manifest: &CorpusManifest,
    conversation_id: [u8; 16],
) -> chat_protocol::public_state::VerifiedCommitPublicState {
    let commit_bytes = corpus_file("commit-public.mls");
    let parsed = validate_public_commit(&commit_bytes, MAX_PUBLIC_MESSAGE_WIRE_BYTES)
        .expect("frozen Commit parses");
    let aad = parsed.aad().to_vec();
    process_commit(
        state.public_state(),
        &commit_bytes,
        &aad,
        committed_coordinate(
            manifest,
            conversation_id,
            state.coordinate().state_version() + 1,
        ),
        manifest.evaluation_unix_seconds,
        100,
    )
    .expect("frozen Commit processes against the rebound accepted state")
}

/// A committed fulfillment scenario (creation → acceptance → fulfillment, all
/// COMMITTED on a fresh DB) at coordinate sv 2 / epoch 1 with alice + bob leaves —
/// the prior state for the epoch-changing generic-commit / remove follow-ons.
struct FulfillmentScenario {
    fulfillment_state: chat_protocol::state_machine::ConversationState,
    fixture: CreationApply,
    conversation_id: Uuid,
    bob_id: DeviceIdentity,
    bob_did: String,
    coordinate: PublicGroupSnapshotCoordinate,
    alice_sig_key: Vec<u8>,
    fulfill_transition: Uuid,
    welcome_id: Uuid,
    recovery_request_id: Uuid,
    corpus_ref: [u8; 32],
    event_positions: Vec<i64>,
}

/// The uncommitted leaf-recovery fulfillment plan + ctx (create + acceptance are
/// already COMMITTED). Extracted so the reconciliation negative test can apply a
/// MUTATED plan against the same accepted state without run_fulfillment_scenario
/// committing it first.
struct BuiltFulfillment {
    plan: chat_protocol::state_machine::ConversationPersistencePlan,
    ctx: ExecutionContext,
    fixture: CreationApply,
    conversation_id: Uuid,
    bob_id: DeviceIdentity,
    bob_did: String,
    alice_sig_key: Vec<u8>,
    fulfill_transition: Uuid,
    welcome_id: Uuid,
    recovery_request_id: Uuid,
    corpus_ref: [u8; 32],
    fulfillment_state: chat_protocol::state_machine::ConversationState,
}

async fn build_fulfillment(pool: &PgPool) -> BuiltFulfillment {
    let pool = pool.clone();
    let manifest = corpus_manifest();
    let bob_id = bob_corpus(&manifest);
    let bob_did = manifest.identity.bob.actor_did.clone();
    let bob_device = Uuid::from_bytes(*bob_id.device_id());

    // 1. Create the group (alice creator, CORPUS bob invitee) and commit it.
    //    Bob's DEVICE signing key = his CORPUS MLS leaf signature key, so his
    //    `device_keys.key_id` equals `ed25519_key_id(leaf_signature_key)` — the
    //    exact `member_devices.leaf_key_id` the recovered keyPackage leaf requires.
    let bob_leaf_sig_key: Vec<u8> =
        hex::decode(&manifest.identity.bob.signature_public_key_hex).unwrap();
    let fixture = build_creation_with_invitee(
        &pool,
        ConversationKind::Group,
        bob_id.clone(),
        bob_did.clone(),
        bob_leaf_sig_key.clone(),
    )
    .await;
    let conversation_id = fixture.conversation_id;
    {
        let mut tx = pool.begin().await.expect("begin creation");
        apply_conversation_persistence_plan(&mut tx, &fixture.plan, &fixture.ctx)
            .await
            .expect("creation applies");
        tx.commit().await.expect("creation COMMIT");
    }

    // 2. Acceptance (bob), opening the add-request bound to sv1 with the CORPUS
    //    key-package ref (so the ADD commit's added member matches the request).
    let corpus_ref: [u8; 32] = hex_array(&manifest.chain.inner_key_package_ref_hex);
    let bob_period: Uuid = sqlx::query_scalar(
        "SELECT participant_period_id FROM chat.participants WHERE conversation_id=$1 AND user_did=$2 AND current_membership",
    )
    .bind(conversation_id)
    .bind(&bob_did)
    .fetch_one(&pool)
    .await
    .expect("bob participant period");
    let package_not_after = seed_key_package(
        &pool,
        &bob_did,
        bob_device,
        &fixture.bob_key_id,
        &corpus_ref,
    )
    .await;

    let accept_received = ServerTimestamp::from_unix_millis_for_test(
        manifest.evaluation_unix_seconds as i64 * 1_000 + 3_000,
    )
    .unwrap();
    // The protocol package_not_after MUST be the exact instant the seeded key
    // package's `not_after` is: the Welcome delivery's `expires_at` (the plan's
    // reservation `package_not_after`) is FK-bound to `key_packages.not_after`.
    let pkg_not_after_ts =
        ServerTimestamp::from_unix_millis_for_test(package_not_after.timestamp_millis()).unwrap();
    let recovery_request_id = Uuid::new_v4();
    let accept_transition = Uuid::new_v4();
    let accept_entry = Uuid::new_v4();
    let bob_sig_digest: [u8; 32] = Sha256::digest([0x62_u8; 32]).into();
    let accept_evidence = TransitionEvidence::for_test_acceptance(
        2,
        *accept_transition.as_bytes(),
        [0x16_u8; 32],
        accept_received,
        fixture.coordinate,
        *recovery_request_id.as_bytes(),
        bob_id.clone(),
        fixture.creation_transition_id,
        fixture.alice_id.clone(),
        corpus_ref,
        bob_sig_digest,
        1,
        pkg_not_after_ts,
    )
    .unwrap();
    let accept_planned = plan_accept_conversation(
        &fixture.state,
        AcceptConversation {
            actor: bob_id.clone(),
            transition: accept_evidence,
            recovery_request_id: *recovery_request_id.as_bytes(),
            key_package_ref: corpus_ref,
            package_not_after: pkg_not_after_ts,
        },
    )
    .expect("valid acceptance plan");
    let accepted_state = accept_planned.resulting_state().clone();
    let accept_head = ConversationHeadCasBinding::for_test_edge(
        *conversation_id.as_bytes(),
        *accept_entry.as_bytes(),
        fixture.coordinate,
        2,
        accept_received,
    );
    let accept_plan = persistence_plan_for_test(accept_planned, accept_head);
    let accept_ctx = acceptance_ctx(
        &pool,
        &fixture,
        &bob_id,
        &bob_did,
        &fixture.bob_key_id,
        accept_entry,
        bob_period,
        package_not_after,
    )
    .await;
    {
        let mut tx = pool.begin().await.expect("begin acceptance");
        apply_conversation_persistence_plan(&mut tx, &accept_plan, &accept_ctx)
            .await
            .expect("acceptance applies");
        tx.commit().await.expect("acceptance COMMIT");
    }

    // 3. Build the fulfillment: process the corpus ADD commit + welcome against the
    //    accepted state, then plan the fulfillment.
    let commit = verified_add_commit(&accepted_state, &manifest, *conversation_id.as_bytes());
    let welcome = verify_recovery_welcome(&corpus_file("welcome.mls"), corpus_ref, 1_048_576)
        .expect("one-recipient Welcome is request-bound");
    let welcome_wire = welcome.wire_bytes().to_vec();
    let welcome_id = Uuid::new_v4();
    let fulfill_transition = Uuid::new_v4();
    let fulfill_entry = Uuid::new_v4();
    let fulfill_received = ServerTimestamp::from_unix_millis_for_test(
        manifest.evaluation_unix_seconds as i64 * 1_000 + 4_000,
    )
    .unwrap();
    let successor_coord = committed_coordinate(&manifest, *conversation_id.as_bytes(), 2);
    let alice_sig_key: Vec<u8> =
        hex::decode(&manifest.identity.alice.signature_public_key_hex).unwrap();
    let alice_key_id_bytes: [u8; 32] = Sha256::digest(&alice_sig_key).into();
    // The metadata RE-ENCRYPTION: SAME author/origin/version/size as the creation
    // snapshot (alice, creation transition, v1, 48 bytes), a FRESH nonce + ciphertext.
    let reencryption = MetadataSnapshotBinding::for_test_creation(
        *conversation_id.as_bytes(),
        0,
        successor_coord.epoch(),
        *successor_coord.group_context_hash(),
        fixture.creation_transition_id,
        1,
        fixture.alice_id.clone(),
        alice_key_id_bytes,
        alice_sig_key.clone().try_into().unwrap(),
        1,
        1,
        [0x9A_u8; 12],
        vec![0x9B_u8; 48],
    );
    let fulfill_evidence = TransitionEvidence::for_test_leaf_recovery_fulfillment_with_metadata(
        3,
        *fulfill_transition.as_bytes(),
        [0x19_u8; 32],
        fulfill_received,
        *recovery_request_id.as_bytes(),
        *accepted_state.coordinate(),
        successor_coord,
        bob_id.clone(),
        corpus_ref,
        *welcome_id.as_bytes(),
        welcome_wire.clone(),
        reencryption,
    )
    .unwrap();
    let planned = plan_leaf_recovery_fulfillment(
        &accepted_state,
        LeafRecoveryFulfillment {
            actor: fixture.alice_id.clone(),
            target: bob_id.clone(),
            recovery_request_id: *recovery_request_id.as_bytes(),
            welcome_id: *welcome_id.as_bytes(),
            transition: fulfill_evidence,
            commit,
            welcome,
        },
    )
    .expect("valid fulfillment plan");
    let fulfillment_state = planned.resulting_state().clone();
    let head_cas = ConversationHeadCasBinding::for_test_edge(
        *conversation_id.as_bytes(),
        *fulfill_entry.as_bytes(),
        *accepted_state.coordinate(),
        3,
        fulfill_received,
    );
    let plan = persistence_plan_for_test(planned, head_cas);

    // Participant periods in hydration (sorted-DID) order for the new leaf's owner.
    let mut participant_rows: Vec<(String, Uuid)> = sqlx::query_as(
        "SELECT user_did,participant_period_id FROM chat.participants WHERE conversation_id=$1 AND current_membership",
    )
    .bind(conversation_id)
    .fetch_all(&pool)
    .await
    .expect("participant periods");
    participant_rows.sort_by(|l, r| l.0.as_bytes().cmp(r.0.as_bytes()));
    let participant_period_ids: Vec<Uuid> = participant_rows.iter().map(|(_, id)| *id).collect();

    let applied_at = clock_now(&pool).await;
    let payload = vec![0xC2_u8; 12];
    let transcript = vec![0xC3_u8; 12];
    let alice_pred =
        device_event_predecessor(&pool, &fixture.alice_did, fixture.alice_device).await;
    let bob_pred = device_event_predecessor(&pool, &bob_did, bob_device).await;
    let entry_recipients = entry_audience(&fixture.alice_id, &fixture.alice_did, &bob_id, &bob_did);
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
            entry_id: fulfill_entry,
            entry_kind: "blue.catbird.chat.defs#leafRecoveryFulfillmentEntry".to_owned(),
            accepted_payload_bytes: payload.clone(),
            accepted_payload_sha256: Sha256::digest(&payload).to_vec(),
            signed_request_bytes: transcript.clone(),
            unsigned_projection_bytes: vec![0xC4_u8; 8],
            signing_transcript_bytes: transcript.clone(),
            request_digest: Sha256::digest(&transcript).to_vec(),
            signature: vec![0xC5_u8; 64],
            server_fields_bytes: vec![0xC6_u8; 8],
            outer_entry_fingerprint: vec![0x19_u8; 32],
        },
        spine: SpineArtifacts {
            public_snapshot_bytes: vec![0xD1_u8; 16],
            public_snapshot_sha256: Sha256::digest([0xD1_u8; 16]).to_vec(),
            tree_summary_bytes: vec![0xD2_u8; 16],
            tree_summary_sha256: Sha256::digest([0xD2_u8; 16]).to_vec(),
            leaf_count: 2,
            genesis_group_info_bytes: vec![],
            genesis_group_info_sha256: vec![],
        },
        opened_leaves: vec![LeafPersistenceColumns {
            device: bob_id.clone(),
            leaf_key_id: fixture.bob_key_id.clone(),
            leaf_auth_generation: 1,
        }],
        metadata_author: Some(MetadataAuthorColumns {
            author_role: "admin".to_owned(),
            author_device_status: "active".to_owned(),
            author_public_key: alice_sig_key.clone(),
            author_key_id: fixture.alice_key_id.clone(),
            metadata_snapshot_id: Uuid::new_v4(),
        }),
        participant_period_ids,
        leaf_period_ids: vec![Uuid::new_v4()],
        entry_recipients,
        events: vec![EventFanout {
            event_id: Uuid::new_v4(),
            event_kind: EventKind::WelcomeAvailable,
            payload_bytes: vec![0xD4_u8; 8],
            recipients: vec![
                (
                    fixture.alice_id.clone(),
                    EventEntitlementKind::Participant,
                    alice_pred,
                ),
                (bob_id.clone(), EventEntitlementKind::Participant, bob_pred),
            ],
            outbox: vec![(Uuid::new_v4(), OutboxWorkKind::Stream)],
        }],
        closing_leaf_periods: vec![],
        closing_participant_periods: vec![],
        reset_request_row: None,
        recovery_open: None,
        welcome_expiry: None,
        welcome_response: None,
        welcome_dispositions: vec![],
    };

    BuiltFulfillment {
        plan,
        ctx,
        fixture,
        conversation_id,
        bob_id,
        bob_did,
        alice_sig_key,
        fulfill_transition,
        welcome_id,
        recovery_request_id,
        corpus_ref,
        fulfillment_state,
    }
}

/// Create + acceptance + fulfillment, all COMMITTED on a fresh DB, at sv 2 /
/// epoch 1 with alice + bob leaves — the prior for the epoch-changing follow-ons.
async fn run_fulfillment_scenario(pool: &PgPool) -> FulfillmentScenario {
    let BuiltFulfillment {
        plan,
        ctx,
        fixture,
        conversation_id,
        bob_id,
        bob_did,
        alice_sig_key,
        fulfill_transition,
        welcome_id,
        recovery_request_id,
        corpus_ref,
        fulfillment_state,
    } = build_fulfillment(pool).await;
    let pool = pool.clone();

    let mut tx = pool.begin().await.expect("begin fulfillment");
    let applied = apply_conversation_persistence_plan(&mut tx, &plan, &ctx)
        .await
        .expect("fulfillment applies");
    tx.commit()
        .await
        .expect("fulfillment COMMIT past all deferred triggers");
    assert_eq!(applied.allocated_seq, 3);

    // Head at the committed successor (sv 2, epoch bump lives in gen_state).
    let (sv, next_seq): (i64, i64) = sqlx::query_as(
        "SELECT current_state_version,next_entry_seq FROM chat.conversations WHERE conversation_id=$1",
    )
    .bind(conversation_id)
    .fetch_one(&pool)
    .await
    .expect("head");
    assert_eq!((sv, next_seq), (2, 4));
    let (skind, sepoch, sleaf): (String, i64, i64) = sqlx::query_as(
        "SELECT state_kind,epoch,leaf_count FROM chat.generation_states WHERE conversation_id=$1 AND state_version=2",
    )
    .bind(conversation_id)
    .fetch_one(&pool)
    .await
    .expect("commit gen state");
    assert_eq!((skind.as_str(), sepoch, sleaf), ("commit", 1, 2));
    // Exactly one addLeafByRecovery: bob's keyPackage-origin leaf at generation 0.
    let (origin, join_ref): (String, Option<Vec<u8>>) = sqlx::query_as(
        "SELECT origin,join_key_package_ref FROM chat.member_devices WHERE conversation_id=$1 AND user_did=$2 AND active",
    )
    .bind(conversation_id)
    .bind(&bob_did)
    .fetch_one(&pool)
    .await
    .expect("bob leaf");
    assert_eq!(
        (origin.as_str(), join_ref),
        ("keyPackage", Some(corpus_ref.to_vec()))
    );
    // Bob's add-opened interval at the fulfillment seq.
    let (start_seq, opening_kind): (i64, String) = sqlx::query_as(
        "SELECT start_seq,opening_kind FROM chat.application_intervals WHERE conversation_id=$1 AND recipient_did=$2",
    )
    .bind(conversation_id)
    .bind(&bob_did)
    .fetch_one(&pool)
    .await
    .expect("bob interval");
    assert_eq!((start_seq, opening_kind.as_str()), (3, "add"));
    // Request fulfilled, reservation consumed, package consumed.
    let req_status: String = sqlx::query_scalar(
        "SELECT status FROM chat.leaf_recovery_requests WHERE recovery_request_id=$1",
    )
    .bind(recovery_request_id)
    .fetch_one(&pool)
    .await
    .expect("request");
    assert_eq!(req_status, "fulfilled");
    let res_status: String = sqlx::query_scalar(
        "SELECT status FROM chat.key_package_reservations WHERE recovery_request_id=$1",
    )
    .bind(recovery_request_id)
    .fetch_one(&pool)
    .await
    .expect("reservation");
    assert_eq!(res_status, "consumed");
    let pkg_status: String =
        sqlx::query_scalar("SELECT status FROM chat.key_packages WHERE key_package_ref=$1")
            .bind(corpus_ref.to_vec())
            .fetch_one(&pool)
            .await
            .expect("package");
    assert_eq!(pkg_status, "consumed");
    // Welcome bundle + pending delivery with expires_at == the package not_after.
    let bundle_count: i64 =
        sqlx::query_scalar("SELECT count(*) FROM chat.welcome_bundles WHERE welcome_id=$1")
            .bind(welcome_id)
            .fetch_one(&pool)
            .await
            .expect("bundle");
    assert_eq!(bundle_count, 1);
    let (del_status, del_expires): (String, DateTime<Utc>) =
        sqlx::query_as("SELECT status,expires_at FROM chat.welcome_deliveries WHERE welcome_id=$1")
            .bind(welcome_id)
            .fetch_one(&pool)
            .await
            .expect("delivery");
    assert_eq!(del_status, "pending");
    let pkg_not_after_db: DateTime<Utc> =
        sqlx::query_scalar("SELECT not_after FROM chat.key_packages WHERE key_package_ref=$1")
            .bind(corpus_ref.to_vec())
            .fetch_one(&pool)
            .await
            .expect("not_after");
    assert_eq!(del_expires, pkg_not_after_db);
    // The re-encryption metadata snapshot for the fulfillment transition.
    let snap_count: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM chat.metadata_snapshots WHERE producing_transition_id=$1",
    )
    .bind(fulfill_transition)
    .fetch_one(&pool)
    .await
    .expect("snapshot");
    assert_eq!(snap_count, 1);
    // The welcomeAvailable event.
    let evt_kind: String =
        sqlx::query_scalar("SELECT event_kind FROM chat.events WHERE event_position=$1")
            .bind(applied.event_positions[0])
            .fetch_one(&pool)
            .await
            .expect("event");
    assert_eq!(evt_kind, "welcomeAvailable");

    // Replay the fulfillment -> head CAS conflict (head already at sv 2), zero residue.
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
        "fulfillment replay must conflict on the head CAS, got {replay:?}"
    );
    tx2.rollback().await.expect("rollback replay");
    let after: i64 =
        sqlx::query_scalar("SELECT count(*) FROM chat.transitions WHERE conversation_id=$1")
            .bind(conversation_id)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(before, after, "fulfillment replay left zero residue");

    // MINOR: the re-encryption snapshot's author is the ORIGINAL creation author
    // (carried forward), and its author_key_id is the creation author's key — NOT
    // the fulfiller's. (Here fulfiller == author == alice per the corpus commit
    // sender; see the report for why a fulfiller != author DB test is not
    // corpus-reachable. The executor CODE sources author from the binding's
    // author-proof, verified in write_commit_metadata_snapshot.)
    let (snap_author_did, snap_author_key): (String, String) = sqlx::query_as(
        "SELECT author_did,author_key_id FROM chat.metadata_snapshots WHERE producing_transition_id=$1",
    )
    .bind(fulfill_transition)
    .fetch_one(&pool)
    .await
    .expect("snapshot author");
    assert_eq!(snap_author_did, fixture.alice_did);
    assert_eq!(snap_author_key, fixture.alice_key_id);

    let scenario_coordinate = *fulfillment_state.coordinate();
    FulfillmentScenario {
        fulfillment_state,
        conversation_id,
        bob_id,
        bob_did,
        coordinate: scenario_coordinate,
        alice_sig_key,
        fulfill_transition,
        welcome_id,
        recovery_request_id,
        corpus_ref,
        event_positions: applied.event_positions.clone(),
        fixture,
    }
}

#[tokio::test]
async fn leaf_recovery_fulfillment_commits_add_leaf_and_welcome() {
    let (pool, _db) = setup().await;
    let _ = run_fulfillment_scenario(&pool).await;
}

/// Arm 4 (welcome expiry): a pending Welcome whose `expires_at` has passed is
/// terminalized `expired` (server-authored disposition + `welcomeDisposition`
/// event) and a `welcomeExpired` recovery-work item is materialized — atomically,
/// past every deferred trigger (`assert_welcome_disposition_cas` +
/// `assert_recovery_work_integrity`). The op is ENTRY-LESS: the coordinate and seq
/// counter are byte-untouched (head CAS verify). Builds on `run_fulfillment_scenario`,
/// which leaves bob a pending Welcome at the fulfillment coordinate (gen 0, sv 2).
#[tokio::test]
async fn welcome_expiry_terminalizes_delivery_and_materializes_recovery_work() {
    let (pool, _db) = setup().await;
    let scenario = run_fulfillment_scenario(&pool).await;
    let conversation_id = scenario.conversation_id;
    let welcome_id = scenario.welcome_id;

    // The pending Welcome's expiry instant (== the reserved package `not_after`).
    // The delivery terminal_at, the disposition + its event's created_at, and the
    // recovery-work item's created_at must ALL equal this (the DB cross-checks), so
    // the executor's applied_at for an expiry is exactly the welcome's expires_at.
    let expires_at: DateTime<Utc> =
        sqlx::query_scalar("SELECT expires_at FROM chat.welcome_deliveries WHERE welcome_id=$1")
            .bind(welcome_id)
            .fetch_one(&pool)
            .await
            .expect("pending welcome expires_at");

    let planned = plan_welcome_expiry_for_test(&scenario.fulfillment_state, *welcome_id.as_bytes())
        .expect("valid welcome expiry plan");
    let locked_at = ServerTimestamp::from_unix_millis_for_test(expires_at.timestamp_millis())
        .expect("locked_at");
    // Entry-less head: prior = the fulfillment coordinate, counter UNCHANGED at 4.
    let head_cas = ConversationHeadCasBinding::for_test_internal(
        *conversation_id.as_bytes(),
        scenario.coordinate,
        4,
        locked_at,
    );
    let plan = persistence_plan_for_test(planned, head_cas);

    // applied_at == the welcome's expires_at (the disposition event created_at must
    // equal the delivery terminal_at per `assert_welcome_disposition_cas`).
    let applied_at = expires_at;
    let bob_device = Uuid::from_bytes(*scenario.bob_id.device_id());
    let bob_pred = device_event_predecessor(&pool, &scenario.bob_did, bob_device).await;
    let recovery_work_id = Uuid::new_v4();
    let disposition_event_id = Uuid::new_v4();
    let fixture = &scenario.fixture;
    let ctx = ExecutionContext {
        protocol_instance_id: fixture.protocol_instance_id,
        applied_at,
        // Server-observed expiry: the actor fields are not written (no transition).
        actor: ExecutionActor {
            user_did: fixture.alice_did.clone(),
            device_id: fixture.alice_device,
            key_id: fixture.alice_key_id.clone(),
            auth_generation: 1,
            role: TransitionActorRole::Admin,
            device_status: "active".to_owned(),
        },
        // No control entry (internal op); only the entry_id is echoed back.
        entry: ControlEntryContent {
            entry_id: Uuid::new_v4(),
            entry_kind: "blue.catbird.chat.defs#applicationEntry".to_owned(),
            accepted_payload_bytes: vec![0x7A_u8; 8],
            accepted_payload_sha256: Sha256::digest([0x7A_u8; 8]).to_vec(),
            signed_request_bytes: vec![0x7B_u8; 16],
            unsigned_projection_bytes: vec![0x7C_u8; 8],
            signing_transcript_bytes: vec![0x7B_u8; 16],
            request_digest: Sha256::digest([0x7B_u8; 16]).to_vec(),
            signature: vec![0x7D_u8; 64],
            server_fields_bytes: vec![0x7E_u8; 8],
            outer_entry_fingerprint: vec![0x18_u8; 32],
        },
        spine: SpineArtifacts {
            public_snapshot_bytes: vec![],
            public_snapshot_sha256: vec![],
            tree_summary_bytes: vec![],
            tree_summary_sha256: vec![],
            leaf_count: 2,
            genesis_group_info_bytes: vec![],
            genesis_group_info_sha256: vec![],
        },
        opened_leaves: vec![],
        metadata_author: None,
        participant_period_ids: vec![],
        leaf_period_ids: vec![],
        entry_recipients: vec![],
        events: vec![],
        closing_leaf_periods: vec![],
        closing_participant_periods: vec![],
        reset_request_row: None,
        recovery_open: None,
        // The recovery-work id + the welcomeDisposition event (recipient = bob, the
        // welcome recipient, entitlement `welcome`, a `stream` outbox row).
        welcome_expiry: Some(WelcomeExpiryContext {
            recovery_work_id,
            event: EventFanout {
                event_id: disposition_event_id,
                event_kind: EventKind::WelcomeDisposition,
                payload_bytes: vec![0xF8_u8; 8],
                recipients: vec![(
                    scenario.bob_id.clone(),
                    EventEntitlementKind::Welcome,
                    bob_pred,
                )],
                outbox: vec![(Uuid::new_v4(), OutboxWorkKind::Stream)],
            },
        }),
        welcome_response: None,
        welcome_dispositions: vec![],
    };

    let mut tx = pool.begin().await.expect("begin welcome expiry");
    let applied = apply_conversation_persistence_plan(&mut tx, &plan, &ctx)
        .await
        .expect("welcome expiry applies");
    tx.commit()
        .await
        .expect("welcome expiry COMMIT past all deferred triggers");
    // No seq allocated (internal op): the counter is echoed unchanged.
    assert_eq!(applied.allocated_seq, 4);

    // Coordinate + seq counter byte-untouched (still gen 0, sv 2, next_seq 4).
    let (gen, sv, next_seq): (i64, i64, i64) = sqlx::query_as(
        "SELECT current_generation,current_state_version,next_entry_seq FROM chat.conversations WHERE conversation_id=$1",
    )
    .bind(conversation_id)
    .fetch_one(&pool)
    .await
    .expect("head");
    assert_eq!((gen, sv, next_seq), (0, 2, 4));

    // The delivery is `expired`, terminal_at == expires_at.
    let (del_status, del_terminal): (String, Option<DateTime<Utc>>) = sqlx::query_as(
        "SELECT status,terminal_at FROM chat.welcome_deliveries WHERE welcome_id=$1",
    )
    .bind(welcome_id)
    .fetch_one(&pool)
    .await
    .expect("delivery");
    assert_eq!(
        (del_status.as_str(), del_terminal),
        ("expired", Some(expires_at))
    );

    // Exactly one disposition row, winner `expired`, bound to the welcomeDisposition event.
    let (winner, disp_terminal): (String, DateTime<Utc>) = sqlx::query_as(
        "SELECT winner_kind,terminal_at FROM chat.welcome_dispositions WHERE welcome_id=$1",
    )
    .bind(welcome_id)
    .fetch_one(&pool)
    .await
    .expect("disposition");
    assert_eq!((winner.as_str(), disp_terminal), ("expired", expires_at));
    let disp_event_kind: String = sqlx::query_scalar(
        "SELECT event.event_kind FROM chat.welcome_dispositions disposition \
         JOIN chat.events event ON event.event_position = disposition.event_position \
         WHERE disposition.welcome_id=$1",
    )
    .bind(welcome_id)
    .fetch_one(&pool)
    .await
    .expect("disposition event");
    assert_eq!(disp_event_kind, "welcomeDisposition");

    // The `welcomeExpired` recovery-work item: pending, at the welcome BUNDLE's
    // coordinate (gen 0, sv 2), created_at == the disposition terminal_at, for bob.
    let (rw_kind, rw_status, rw_gen, rw_sv, rw_created, rw_recipient): (
        String,
        String,
        i64,
        i64,
        DateTime<Utc>,
        String,
    ) = sqlx::query_as(
        "SELECT source_kind,status,generation,state_version,created_at,recipient_did \
         FROM chat.recovery_work_items WHERE source_id=$1",
    )
    .bind(welcome_id)
    .fetch_one(&pool)
    .await
    .expect("recovery work item");
    assert_eq!(
        (rw_kind.as_str(), rw_status.as_str(), rw_gen, rw_sv),
        ("welcomeExpired", "pending", 0, 2)
    );
    assert_eq!(rw_created, expires_at);
    assert_eq!(rw_recipient, scenario.bob_did);
    let rw_id: Uuid = sqlx::query_scalar(
        "SELECT recovery_work_id FROM chat.recovery_work_items WHERE source_id=$1",
    )
    .bind(welcome_id)
    .fetch_one(&pool)
    .await
    .expect("recovery work id");
    assert_eq!(rw_id, recovery_work_id);

    // Replay -> conflict (the disposition event id + the pending-only delivery CAS
    // are both already consumed), whole transaction rolls back, zero residue.
    let before: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM chat.recovery_work_items WHERE conversation_id=$1",
    )
    .bind(conversation_id)
    .fetch_one(&pool)
    .await
    .unwrap();
    let mut tx2 = pool.begin().await.expect("begin replay");
    let replay = apply_conversation_persistence_plan(&mut tx2, &plan, &ctx).await;
    assert!(
        matches!(replay, Err(ExecutorError::Delivery(_))),
        "welcome expiry replay must conflict, got {replay:?}"
    );
    tx2.rollback().await.expect("rollback replay");
    let after: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM chat.recovery_work_items WHERE conversation_id=$1",
    )
    .bind(conversation_id)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(before, after, "welcome expiry replay left zero residue");
}

/// Build (but do not apply) a client-authored welcome response (acknowledge /
/// reject) against the fulfillment scenario's pending Welcome for bob. Returns the
/// plan + ctx + the delivery's `expires_at` (for verification). `applied_at` (the
/// request instant, used for every timestamp) is set just before `expires_at` so
/// the DB `terminal_at < expires_at` shape holds.
async fn build_welcome_response(
    pool: &PgPool,
    scenario: &FulfillmentScenario,
    kind: RequestEntryKind,
    successor: WelcomeStatus,
    rejection: Option<WelcomeRejectionWork>,
    byte: u8,
) -> (
    chat_protocol::state_machine::ConversationPersistencePlan,
    ExecutionContext,
    DateTime<Utc>,
) {
    let conversation_id = scenario.conversation_id;
    let bob_id = scenario.bob_id.clone();
    let bob_did = scenario.bob_did.clone();
    let bob_device = Uuid::from_bytes(*bob_id.device_id());
    let welcome_id = scenario.welcome_id;
    let fixture = &scenario.fixture;

    let expires_at: DateTime<Utc> =
        sqlx::query_scalar("SELECT expires_at FROM chat.welcome_deliveries WHERE welcome_id=$1")
            .bind(welcome_id)
            .fetch_one(pool)
            .await
            .expect("pending welcome expires_at");
    let transition_seq: i64 =
        sqlx::query_scalar("SELECT entry_seq FROM chat.welcome_bundles WHERE welcome_id=$1")
            .bind(welcome_id)
            .fetch_one(pool)
            .await
            .expect("welcome bundle entry_seq");
    // The request instant: 1s before the welcome's expiry (the plan requires
    // `received_at < expires_at`, and the DB requires the terminal_at `< expires_at`).
    let received_ms = expires_at.timestamp_millis() - 1_000;
    let received_at = ServerTimestamp::from_unix_millis_for_test(received_ms).unwrap();
    let applied_at = DateTime::from_timestamp_millis(received_ms).unwrap();

    let evidence = RequestEvidence::for_test_welcome_response(
        kind,
        *welcome_id.as_bytes(),
        bob_id.clone(),
        *conversation_id.as_bytes(),
        scenario.coordinate,
        transition_seq as u64,
        received_at,
        byte,
    )
    .unwrap();
    let planned = plan_welcome_response_for_test(&scenario.fulfillment_state, evidence, successor)
        .expect("valid welcome response plan");
    let head_cas = ConversationHeadCasBinding::for_test_internal(
        *conversation_id.as_bytes(),
        scenario.coordinate,
        4,
        received_at,
    );
    let plan = persistence_plan_for_test(planned, head_cas);

    let bob_pred = device_event_predecessor(pool, &bob_did, bob_device).await;
    // The client's signed authorization the disposition row binds (from ctx.entry).
    let transcript = vec![byte; 24];
    let ctx = ExecutionContext {
        protocol_instance_id: fixture.protocol_instance_id,
        applied_at,
        actor: ExecutionActor {
            user_did: bob_did.clone(),
            device_id: bob_device,
            key_id: fixture.bob_key_id.clone(),
            auth_generation: 1,
            role: TransitionActorRole::Member,
            device_status: "active".to_owned(),
        },
        entry: ControlEntryContent {
            entry_id: Uuid::new_v4(),
            entry_kind: "blue.catbird.chat.defs#applicationEntry".to_owned(),
            accepted_payload_bytes: vec![byte.wrapping_add(1); 8],
            accepted_payload_sha256: Sha256::digest([byte.wrapping_add(1); 8]).to_vec(),
            signed_request_bytes: transcript.clone(),
            unsigned_projection_bytes: vec![byte.wrapping_add(2); 8],
            signing_transcript_bytes: transcript.clone(),
            request_digest: Sha256::digest(&transcript).to_vec(),
            signature: vec![byte.wrapping_add(3); 64],
            server_fields_bytes: vec![byte.wrapping_add(4); 8],
            outer_entry_fingerprint: vec![byte.wrapping_add(5); 32],
        },
        spine: SpineArtifacts {
            public_snapshot_bytes: vec![],
            public_snapshot_sha256: vec![],
            tree_summary_bytes: vec![],
            tree_summary_sha256: vec![],
            leaf_count: 2,
            genesis_group_info_bytes: vec![],
            genesis_group_info_sha256: vec![],
        },
        opened_leaves: vec![],
        metadata_author: None,
        participant_period_ids: vec![],
        leaf_period_ids: vec![],
        entry_recipients: vec![],
        events: vec![],
        closing_leaf_periods: vec![],
        closing_participant_periods: vec![],
        reset_request_row: None,
        recovery_open: None,
        welcome_expiry: None,
        welcome_response: Some(WelcomeResponseContext {
            event: EventFanout {
                event_id: Uuid::new_v4(),
                event_kind: EventKind::WelcomeDisposition,
                payload_bytes: vec![byte.wrapping_add(6); 8],
                recipients: vec![(bob_id.clone(), EventEntitlementKind::Welcome, bob_pred)],
                outbox: vec![(Uuid::new_v4(), OutboxWorkKind::Stream)],
            },
            rejection,
        }),
        welcome_dispositions: vec![],
    };
    (plan, ctx, expires_at)
}

#[tokio::test]
async fn welcome_acknowledgement_terminalizes_delivery_without_recovery_work() {
    let (pool, _db) = setup().await;
    let scenario = run_fulfillment_scenario(&pool).await;
    let conversation_id = scenario.conversation_id;
    let welcome_id = scenario.welcome_id;
    let (plan, ctx, _expires) = build_welcome_response(
        &pool,
        &scenario,
        RequestEntryKind::WelcomeAcknowledgement,
        WelcomeStatus::Acknowledged,
        None,
        0x51,
    )
    .await;

    let mut tx = pool.begin().await.expect("begin ack");
    apply_conversation_persistence_plan(&mut tx, &plan, &ctx)
        .await
        .expect("welcome acknowledgement applies");
    tx.commit().await.expect("welcome acknowledgement COMMIT");

    // Coordinate + seq untouched.
    let (sv, next_seq): (i64, i64) = sqlx::query_as(
        "SELECT current_state_version,next_entry_seq FROM chat.conversations WHERE conversation_id=$1",
    )
    .bind(conversation_id)
    .fetch_one(&pool)
    .await
    .expect("head");
    assert_eq!((sv, next_seq), (2, 4));
    // Delivery acknowledged; disposition winner acknowledged with the signed bytes,
    // NO rejection reason.
    let del_status: String =
        sqlx::query_scalar("SELECT status FROM chat.welcome_deliveries WHERE welcome_id=$1")
            .bind(welcome_id)
            .fetch_one(&pool)
            .await
            .expect("delivery");
    assert_eq!(del_status, "acknowledged");
    let (winner, has_sig, reason): (String, bool, Option<String>) = sqlx::query_as(
        "SELECT winner_kind, signed_request_bytes IS NOT NULL, rejection_reason FROM chat.welcome_dispositions WHERE welcome_id=$1",
    )
    .bind(welcome_id)
    .fetch_one(&pool)
    .await
    .expect("disposition");
    assert_eq!(winner, "acknowledged");
    assert!(
        has_sig,
        "acknowledgement disposition binds the signed request"
    );
    assert_eq!(reason, None);
    // NO recovery work for an acknowledgement.
    let rw_count: i64 =
        sqlx::query_scalar("SELECT count(*) FROM chat.recovery_work_items WHERE source_id=$1")
            .bind(welcome_id)
            .fetch_one(&pool)
            .await
            .expect("recovery work");
    assert_eq!(rw_count, 0);

    // Replay -> delivery-CAS conflict, zero residue.
    let mut tx2 = pool.begin().await.expect("begin replay");
    let replay = apply_conversation_persistence_plan(&mut tx2, &plan, &ctx).await;
    assert!(
        matches!(replay, Err(ExecutorError::Delivery(_))),
        "acknowledgement replay must conflict on the delivery CAS, got {replay:?}"
    );
    tx2.rollback().await.expect("rollback replay");
}

#[tokio::test]
async fn welcome_rejection_terminalizes_delivery_and_creates_recovery_work() {
    let (pool, _db) = setup().await;
    let scenario = run_fulfillment_scenario(&pool).await;
    let conversation_id = scenario.conversation_id;
    let welcome_id = scenario.welcome_id;
    let bob_did = scenario.bob_did.clone();
    let recovery_work_id = Uuid::new_v4();
    let (plan, ctx, _expires) = build_welcome_response(
        &pool,
        &scenario,
        RequestEntryKind::WelcomeRejection,
        WelcomeStatus::Rejected,
        Some(WelcomeRejectionWork {
            recovery_work_id,
            reason: WelcomeRejectionReason::NoMatchingKeyPackage,
        }),
        0x61,
    )
    .await;

    let mut tx = pool.begin().await.expect("begin reject");
    apply_conversation_persistence_plan(&mut tx, &plan, &ctx)
        .await
        .expect("welcome rejection applies");
    tx.commit().await.expect("welcome rejection COMMIT");

    // Delivery rejected; disposition winner rejected with signed bytes + the reason.
    let del_status: String =
        sqlx::query_scalar("SELECT status FROM chat.welcome_deliveries WHERE welcome_id=$1")
            .bind(welcome_id)
            .fetch_one(&pool)
            .await
            .expect("delivery");
    assert_eq!(del_status, "rejected");
    let (winner, has_sig, reason): (String, bool, Option<String>) = sqlx::query_as(
        "SELECT winner_kind, signed_request_bytes IS NOT NULL, rejection_reason FROM chat.welcome_dispositions WHERE welcome_id=$1",
    )
    .bind(welcome_id)
    .fetch_one(&pool)
    .await
    .expect("disposition");
    assert_eq!(winner, "rejected");
    assert!(has_sig);
    assert_eq!(reason.as_deref(), Some("noMatchingKeyPackage"));
    // A welcomeRejected recovery work item for bob, pending.
    let (rw_kind, rw_status, rw_recipient, rw_id): (String, String, String, Uuid) = sqlx::query_as(
        "SELECT source_kind,status,recipient_did,recovery_work_id FROM chat.recovery_work_items WHERE source_id=$1",
    )
    .bind(welcome_id)
    .fetch_one(&pool)
    .await
    .expect("recovery work");
    assert_eq!(
        (rw_kind.as_str(), rw_status.as_str(), rw_recipient.as_str()),
        ("welcomeRejected", "pending", bob_did.as_str())
    );
    assert_eq!(rw_id, recovery_work_id);
    let _ = conversation_id;

    // Replay -> delivery-CAS conflict, no duplicate recovery work.
    let mut tx2 = pool.begin().await.expect("begin replay");
    let replay = apply_conversation_persistence_plan(&mut tx2, &plan, &ctx).await;
    assert!(
        matches!(replay, Err(ExecutorError::Delivery(_))),
        "rejection replay must conflict on the delivery CAS, got {replay:?}"
    );
    tx2.rollback().await.expect("rollback replay");
    let rw_count: i64 =
        sqlx::query_scalar("SELECT count(*) FROM chat.recovery_work_items WHERE source_id=$1")
            .bind(welcome_id)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(rw_count, 1, "replay wrote no duplicate recovery work");
}

/// The welcome-disposition arms validate the `welcome_cas` binding LOAD-BEARING
/// against the `welcome_changes` delta. A corrupted binding (mismatched welcome id)
/// must be a hard `InconsistentPlan`, never a silently-unread witness — removing the
/// 6-field validation fails this test. (`persistence_plan_for_test` always
/// synthesizes a MATCHING binding, so corruption is the only way to drive it red.)
#[tokio::test]
async fn welcome_response_corrupted_cas_binding_is_rejected() {
    let (pool, _db) = setup().await;
    let scenario = run_fulfillment_scenario(&pool).await;
    let welcome_id = scenario.welcome_id;
    let (plan, ctx, _expires) = build_welcome_response(
        &pool,
        &scenario,
        RequestEntryKind::WelcomeAcknowledgement,
        WelcomeStatus::Acknowledged,
        None,
        0x71,
    )
    .await;
    let bad = plan.with_welcome_cas_corrupted_for_test();
    let mut tx = pool.begin().await.expect("begin");
    let result = apply_conversation_persistence_plan(&mut tx, &bad, &ctx).await;
    assert!(
        matches!(result, Err(ExecutorError::InconsistentPlan(_))),
        "a corrupted welcome_cas binding must be an InconsistentPlan, got {result:?}"
    );
    tx.rollback().await.expect("rollback");
    // Zero residue: the pending delivery is untouched.
    let status: String =
        sqlx::query_scalar("SELECT status FROM chat.welcome_deliveries WHERE welcome_id=$1")
            .bind(welcome_id)
            .fetch_one(&pool)
            .await
            .expect("delivery");
    assert_eq!(status, "pending");
}

/// Silent-drop guard (fulfillment arm): a plan carrying an EXTRA recovery-request
/// delta that is neither the arm's own `Open->Fulfilled` edge nor a valid
/// `Open->Superseded` supersession must be REJECTED, never silently dropped.
/// `write_prior_bound_supersessions` skips it; `reconcile_coordinate_change_families`
/// catches the `own + superseded != total` mismatch. Removing that reconciliation
/// makes this fulfillment COMMIT with the extra delta lost.
#[tokio::test]
async fn fulfillment_untracked_recovery_request_delta_is_rejected() {
    let (pool, _db) = setup().await;
    let built = build_fulfillment(&pool).await;
    let conversation_id = built.conversation_id;
    let recovery_request_id = built.recovery_request_id;
    let bad = built.plan.with_extra_untracked_recovery_request_for_test();
    let mut tx = pool.begin().await.expect("begin");
    let result = apply_conversation_persistence_plan(&mut tx, &bad, &built.ctx).await;
    assert!(
        matches!(result, Err(ExecutorError::InconsistentPlan(_))),
        "an untracked recovery-request delta must be an InconsistentPlan, got {result:?}"
    );
    tx.rollback().await.expect("rollback");

    // Zero residue: the accepted-state coordinate (sv 1) is untouched, the request
    // is still open, and no fulfillment transition landed.
    let sv: i64 = sqlx::query_scalar(
        "SELECT current_state_version FROM chat.conversations WHERE conversation_id=$1",
    )
    .bind(conversation_id)
    .fetch_one(&pool)
    .await
    .expect("head");
    assert_eq!(sv, 1);
    let req_status: String = sqlx::query_scalar(
        "SELECT status FROM chat.leaf_recovery_requests WHERE recovery_request_id=$1",
    )
    .bind(recovery_request_id)
    .fetch_one(&pool)
    .await
    .expect("request");
    assert_eq!(
        req_status, "open",
        "a rejected fulfillment leaves the request open"
    );
    let transitions: i64 =
        sqlx::query_scalar("SELECT count(*) FROM chat.transitions WHERE conversation_id=$1")
            .bind(conversation_id)
            .fetch_one(&pool)
            .await
            .expect("transitions");
    assert_eq!(
        transitions, 2,
        "only creation + acceptance transitions exist"
    );
}

/// The uncommitted generic (epoch-only) commit plan + ctx on top of a COMMITTED
/// fulfillment scenario — extracted so the reconciliation negative test can apply
/// a MUTATED plan (a corrupted welcome supersession) without committing it first.
struct BuiltGenericCommit {
    plan: chat_protocol::state_machine::ConversationPersistencePlan,
    ctx: ExecutionContext,
    conversation_id: Uuid,
    commit_transition: Uuid,
}

async fn build_generic_commit(pool: &PgPool, scenario: &FulfillmentScenario) -> BuiltGenericCommit {
    let pool = pool.clone();
    let manifest = corpus_manifest();
    let fixture = &scenario.fixture;
    let conversation_id = scenario.conversation_id;
    let prior = &scenario.fulfillment_state; // sv 2, epoch 1, alice + bob.

    // The frozen ZERO-PROPOSAL commit (epoch 1 -> 2) parses as a valid public
    // commit; the executor arm is driven by a SYNTHETIC zero-proposal commit — the
    // same pure public-state seam the state-machine suite uses for generic/remove
    // commits (a `process_commit` reconstruction of a NON-authoritative prior from
    // an earlier public commit diverges cryptographically; see the report).
    let commit_bytes = corpus_file("commit-generic-public.mls");
    validate_public_commit(&commit_bytes, MAX_PUBLIC_MESSAGE_WIRE_BYTES)
        .expect("frozen generic Commit parses as a valid public commit");
    let successor_coord = PublicGroupSnapshotCoordinate::new(
        *conversation_id.as_bytes(),
        manifest.chain.generation,
        prior.coordinate().state_version() + 1,
        *prior.coordinate().group_id(),
        prior.coordinate().epoch() + 1,
        [0xAB_u8; 32],
        [0xCD_u8; 32],
        PublicGroupSnapshotLifecycle::Active,
    );
    let commit = chat_protocol::public_state::VerifiedCommitPublicState::for_test_generic(
        prior.public_state(),
        successor_coord,
        0,
    )
    .expect("synthetic zero-proposal commit");
    assert_eq!(successor_coord.epoch(), 2);
    assert_eq!(successor_coord.state_version(), 3);

    let commit_transition = Uuid::new_v4();
    let commit_entry = Uuid::new_v4();
    let commit_received = ServerTimestamp::from_unix_millis_for_test(
        manifest.evaluation_unix_seconds as i64 * 1_000 + 5_000,
    )
    .unwrap();
    let alice_key_id_bytes: [u8; 32] = Sha256::digest(&scenario.alice_sig_key).into();
    // Re-encryption: SAME author/origin/version/size as the prior snapshot; a fresh
    // nonce + 48-byte ciphertext; coordinate epoch = 2 (validate_state).
    let reencryption = MetadataSnapshotBinding::for_test_creation(
        *conversation_id.as_bytes(),
        0,
        successor_coord.epoch(),
        *successor_coord.group_context_hash(),
        fixture.creation_transition_id,
        1,
        fixture.alice_id.clone(),
        alice_key_id_bytes,
        scenario.alice_sig_key.clone().try_into().unwrap(),
        1,
        1,
        [0xE1_u8; 12],
        vec![0xE2_u8; 48],
    );
    let commit_evidence = TransitionEvidence::for_test_commit_with_metadata(
        4,
        *commit_transition.as_bytes(),
        [0x1A_u8; 32],
        commit_received,
        *prior.coordinate(),
        successor_coord,
        reencryption,
    )
    .unwrap();
    let planned = plan_commit(
        prior,
        CommitCommand {
            actor: fixture.alice_id.clone(),
            transition: commit_evidence,
            commit,
        },
    )
    .expect("valid generic commit plan");
    let head_cas = ConversationHeadCasBinding::for_test_edge(
        *conversation_id.as_bytes(),
        *commit_entry.as_bytes(),
        *prior.coordinate(),
        4,
        commit_received,
    );
    let plan = persistence_plan_for_test(planned, head_cas);

    let applied_at = clock_now(&pool).await;
    let payload = vec![0xE3_u8; 12];
    let transcript = vec![0xE4_u8; 12];
    let alice_pred =
        device_event_predecessor(&pool, &fixture.alice_did, fixture.alice_device).await;
    let bob_device = Uuid::from_bytes(*scenario.bob_id.device_id());
    let bob_pred = device_event_predecessor(&pool, &scenario.bob_did, bob_device).await;
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
            entry_id: commit_entry,
            entry_kind: "blue.catbird.chat.defs#commitEntry".to_owned(),
            accepted_payload_bytes: payload.clone(),
            accepted_payload_sha256: Sha256::digest(&payload).to_vec(),
            signed_request_bytes: transcript.clone(),
            unsigned_projection_bytes: vec![0xE5_u8; 8],
            signing_transcript_bytes: transcript.clone(),
            request_digest: Sha256::digest(&transcript).to_vec(),
            signature: vec![0xE6_u8; 64],
            server_fields_bytes: vec![0xE7_u8; 8],
            outer_entry_fingerprint: vec![0x1A_u8; 32],
        },
        spine: SpineArtifacts {
            public_snapshot_bytes: vec![0xF1_u8; 16],
            public_snapshot_sha256: Sha256::digest([0xF1_u8; 16]).to_vec(),
            tree_summary_bytes: vec![0xF2_u8; 16],
            tree_summary_sha256: Sha256::digest([0xF2_u8; 16]).to_vec(),
            leaf_count: 2,
            genesis_group_info_bytes: vec![],
            genesis_group_info_sha256: vec![],
        },
        opened_leaves: vec![],
        metadata_author: Some(MetadataAuthorColumns {
            author_role: "admin".to_owned(),
            author_device_status: "active".to_owned(),
            author_public_key: scenario.alice_sig_key.clone(),
            author_key_id: fixture.alice_key_id.clone(),
            metadata_snapshot_id: Uuid::new_v4(),
        }),
        participant_period_ids: vec![],
        leaf_period_ids: vec![],
        entry_recipients: entry_audience(
            &fixture.alice_id,
            &fixture.alice_did,
            &scenario.bob_id,
            &scenario.bob_did,
        ),
        events: vec![EventFanout {
            event_id: Uuid::new_v4(),
            event_kind: EventKind::ConversationChanged,
            payload_bytes: vec![0xF4_u8; 8],
            recipients: vec![(
                fixture.alice_id.clone(),
                EventEntitlementKind::Participant,
                alice_pred,
            )],
            outbox: vec![(Uuid::new_v4(), OutboxWorkKind::Stream)],
        }],
        closing_leaf_periods: vec![],
        closing_participant_periods: vec![],
        reset_request_row: None,
        recovery_open: None,
        // The epoch change supersedes the fulfillment's pending Welcome; provide its
        // welcomeDisposition event (recipient = bob, the welcome recipient).
        welcome_expiry: None,
        welcome_response: None,
        welcome_dispositions: vec![WelcomeDispositionInput {
            welcome_id: scenario.welcome_id,
            event: EventFanout {
                event_id: Uuid::new_v4(),
                event_kind: EventKind::WelcomeDisposition,
                payload_bytes: vec![0xF5_u8; 8],
                recipients: vec![(
                    scenario.bob_id.clone(),
                    EventEntitlementKind::Welcome,
                    bob_pred,
                )],
                outbox: vec![(Uuid::new_v4(), OutboxWorkKind::Stream)],
            },
        }],
    };

    BuiltGenericCommit {
        plan,
        ctx,
        conversation_id,
        commit_transition,
    }
}

#[tokio::test]
async fn generic_commit_commits_epoch_bump_and_reencrypts_metadata() {
    let (pool, _db) = setup().await;
    let scenario = run_fulfillment_scenario(&pool).await;
    let BuiltGenericCommit {
        plan,
        ctx,
        conversation_id,
        commit_transition,
    } = build_generic_commit(&pool, &scenario).await;

    let mut tx = pool.begin().await.expect("begin generic commit");
    let applied = apply_conversation_persistence_plan(&mut tx, &plan, &ctx)
        .await
        .expect("generic commit applies");
    tx.commit()
        .await
        .expect("generic commit COMMIT past all deferred triggers");
    assert_eq!(applied.allocated_seq, 4);

    // sv 2 -> 3, seq 4 -> 5; commit gen_state at the NEW epoch 2, leaf_count 2.
    let (sv, next_seq): (i64, i64) = sqlx::query_as(
        "SELECT current_state_version,next_entry_seq FROM chat.conversations WHERE conversation_id=$1",
    )
    .bind(conversation_id)
    .fetch_one(&pool)
    .await
    .expect("head");
    assert_eq!((sv, next_seq), (3, 5));
    let (skind, sepoch, sleaf): (String, i64, i64) = sqlx::query_as(
        "SELECT state_kind,epoch,leaf_count FROM chat.generation_states WHERE conversation_id=$1 AND state_version=3",
    )
    .bind(conversation_id)
    .fetch_one(&pool)
    .await
    .expect("commit gen state");
    assert_eq!((skind.as_str(), sepoch, sleaf), ("commit", 2, 2));
    // New hash/tag differ from the prior state.
    let (prior_hash, new_hash): (Vec<u8>, Vec<u8>) = sqlx::query_as(
        "SELECT (SELECT group_context_hash FROM chat.generation_states WHERE conversation_id=$1 AND state_version=2), \
                (SELECT group_context_hash FROM chat.generation_states WHERE conversation_id=$1 AND state_version=3)",
    )
    .bind(conversation_id)
    .fetch_one(&pool)
    .await
    .expect("hashes");
    assert_ne!(
        prior_hash, new_hash,
        "generic commit rotates the group context hash"
    );
    // No membership change: still exactly 2 active leaves, no new participant.
    let leaves: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM chat.member_devices WHERE conversation_id=$1 AND active",
    )
    .bind(conversation_id)
    .fetch_one(&pool)
    .await
    .expect("leaves");
    assert_eq!(leaves, 2);
    // The re-encryption snapshot for the commit transition.
    let snap_count: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM chat.metadata_snapshots WHERE producing_transition_id=$1",
    )
    .bind(commit_transition)
    .fetch_one(&pool)
    .await
    .expect("snapshot");
    assert_eq!(snap_count, 1);
    let (tkind, eseq): (String, i64) = sqlx::query_as(
        "SELECT kind,entry_seq FROM chat.transitions WHERE conversation_id=$1 AND kind='commit'",
    )
    .bind(conversation_id)
    .fetch_one(&pool)
    .await
    .expect("commit transition");
    assert_eq!((tkind.as_str(), eseq), ("commit", 4));

    // Replay -> head CAS conflict, zero residue.
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
        "generic commit replay must conflict on the head CAS, got {replay:?}"
    );
    tx2.rollback().await.expect("rollback replay");
    let after: i64 =
        sqlx::query_scalar("SELECT count(*) FROM chat.transitions WHERE conversation_id=$1")
            .bind(conversation_id)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(before, after, "generic commit replay left zero residue");
}

/// Silent-drop guard (generic commit arm — the welcome MINOR): a generic commit
/// whose ONLY welcome delta is a non-supersession shape (`Pending->Expired`, which
/// `write_welcome_supersessions` skips) must be REJECTED, not committed with the
/// durable Welcome delivery left un-terminalized. `reconcile_coordinate_change_families`
/// catches `own(0) + superseded(0) != total(1)`. Removing the welcome reconciliation
/// makes this generic commit COMMIT while silently dropping the welcome supersession.
#[tokio::test]
async fn generic_commit_untracked_welcome_delta_is_rejected() {
    let (pool, _db) = setup().await;
    let scenario = run_fulfillment_scenario(&pool).await;
    let conversation_id = scenario.conversation_id;
    let welcome_id = scenario.welcome_id;
    let built = build_generic_commit(&pool, &scenario).await;
    let bad = built.plan.with_welcome_supersession_corrupted_for_test();
    let mut tx = pool.begin().await.expect("begin");
    let result = apply_conversation_persistence_plan(&mut tx, &bad, &built.ctx).await;
    assert!(
        matches!(result, Err(ExecutorError::InconsistentPlan(_))),
        "a corrupted welcome supersession must be an InconsistentPlan, got {result:?}"
    );
    tx.rollback().await.expect("rollback");

    // Zero residue: the epoch commit never landed (head still at sv 2), and the
    // prior pending Welcome delivery is UNTOUCHED (still pending, not superseded).
    let sv: i64 = sqlx::query_scalar(
        "SELECT current_state_version FROM chat.conversations WHERE conversation_id=$1",
    )
    .bind(conversation_id)
    .fetch_one(&pool)
    .await
    .expect("head");
    assert_eq!(sv, 2);
    let welcome_status: String =
        sqlx::query_scalar("SELECT status FROM chat.welcome_deliveries WHERE welcome_id=$1")
            .bind(welcome_id)
            .fetch_one(&pool)
            .await
            .expect("welcome delivery");
    assert_eq!(
        welcome_status, "pending",
        "a rejected commit leaves the prior Welcome delivery pending"
    );
}

/// Build + COMMIT a `leaveRequest` by the active member `bob` (leafed at the
/// fulfillment-scenario sv 2 / epoch 1 coordinate), returning the resulting
/// in-memory state (with the pending consent) + the leave-request id + the seq
/// the entry landed at, so the cancellation test can build on it.
async fn commit_leave_request(
    pool: &PgPool,
    scenario: &FulfillmentScenario,
    request_seq: u64,
    received_at: ServerTimestamp,
) -> (
    ConversationState,
    Uuid,
    u64,
    chat_protocol::state_machine::ConversationPersistencePlan,
    ExecutionContext,
) {
    let fixture = &scenario.fixture;
    let conversation_id = scenario.conversation_id;
    let bob_id = scenario.bob_id.clone();
    let bob_did = scenario.bob_did.clone();
    let bob_device = Uuid::from_bytes(*bob_id.device_id());
    let request_id = Uuid::new_v4();
    let evidence = RequestEvidence::for_test(
        RequestEntryKind::LeaveRequest,
        request_seq,
        *request_id.as_bytes(),
        bob_id.clone(),
        *conversation_id.as_bytes(),
        received_at,
        0x71,
    )
    .unwrap();
    let registration = LockedRegistrationProjection::for_test(&evidence);
    let planned = plan_leave_request(
        &scenario.fulfillment_state,
        LeaveRequestCommand {
            actor: bob_id.clone(),
            leave_request_id: *request_id.as_bytes(),
            received_at,
            evidence,
            registration,
        },
    )
    .expect("valid leave request plan");
    let state = planned.resulting_state().clone();
    let entry_id = Uuid::new_v4();
    let head_cas = ConversationHeadCasBinding::for_test_edge(
        *conversation_id.as_bytes(),
        *entry_id.as_bytes(),
        scenario.coordinate,
        request_seq,
        received_at,
    );
    let plan = persistence_plan_for_test(planned, head_cas);
    let applied_at = clock_now(pool).await;
    let transcript = vec![0x72_u8; 16];
    let ctx = ExecutionContext {
        protocol_instance_id: fixture.protocol_instance_id,
        applied_at,
        actor: ExecutionActor {
            user_did: bob_did.clone(),
            device_id: bob_device,
            key_id: fixture.bob_key_id.clone(),
            auth_generation: 1,
            role: TransitionActorRole::Member,
            device_status: "active".to_owned(),
        },
        entry: ControlEntryContent {
            entry_id,
            entry_kind: "blue.catbird.chat.defs#leaveRequestEntry".to_owned(),
            accepted_payload_bytes: vec![0x74_u8; 8],
            accepted_payload_sha256: Sha256::digest([0x74_u8; 8]).to_vec(),
            signed_request_bytes: transcript.clone(),
            unsigned_projection_bytes: vec![0x75_u8; 8],
            signing_transcript_bytes: transcript.clone(),
            request_digest: Sha256::digest(&transcript).to_vec(),
            signature: vec![0x76_u8; 64],
            server_fields_bytes: vec![0x77_u8; 8],
            outer_entry_fingerprint: vec![0x1A_u8; 32],
        },
        spine: SpineArtifacts {
            public_snapshot_bytes: vec![],
            public_snapshot_sha256: vec![],
            tree_summary_bytes: vec![],
            tree_summary_sha256: vec![],
            leaf_count: 2,
            genesis_group_info_bytes: vec![],
            genesis_group_info_sha256: vec![],
        },
        opened_leaves: vec![],
        metadata_author: None,
        participant_period_ids: vec![],
        leaf_period_ids: vec![],
        entry_recipients: entry_audience(&fixture.alice_id, &fixture.alice_did, &bob_id, &bob_did),
        events: vec![EventFanout {
            event_id: Uuid::new_v4(),
            event_kind: EventKind::LeaveRequest,
            payload_bytes: vec![0x78_u8; 8],
            recipients: event_audience(
                pool,
                &fixture.alice_id,
                &fixture.alice_did,
                &bob_id,
                &bob_did,
            )
            .await,
            outbox: vec![(Uuid::new_v4(), OutboxWorkKind::Stream)],
        }],
        closing_leaf_periods: vec![],
        closing_participant_periods: vec![],
        reset_request_row: None,
        recovery_open: None,
        welcome_expiry: None,
        welcome_response: None,
        welcome_dispositions: vec![],
    };
    let mut tx = pool.begin().await.expect("begin leave request");
    let applied = apply_conversation_persistence_plan(&mut tx, &plan, &ctx)
        .await
        .expect("leave request applies");
    tx.commit().await.expect("leave request COMMIT");
    (state, request_id, applied.allocated_seq, plan, ctx)
}

#[tokio::test]
async fn leave_request_commits_pending_consent_without_advancing_coordinate() {
    let (pool, _db) = setup().await;
    let scenario = run_fulfillment_scenario(&pool).await;
    let conversation_id = scenario.conversation_id;
    let bob_did = scenario.bob_did.clone();
    let received_at = ServerTimestamp::from_unix_millis_for_test(
        corpus_manifest().evaluation_unix_seconds as i64 * 1_000 + 5_000,
    )
    .unwrap();
    let (_state, request_id, seq, plan, ctx) =
        commit_leave_request(&pool, &scenario, 4, received_at).await;
    assert_eq!(seq, 4);

    // Coordinate UNTOUCHED (still gen 0, sv 2, active); only the seq advanced 4->5.
    let (gen, sv, next_seq, lifecycle): (i64, i64, i64, String) = sqlx::query_as(
        "SELECT current_generation,current_state_version,next_entry_seq,lifecycle FROM chat.conversations WHERE conversation_id=$1",
    )
    .bind(conversation_id)
    .fetch_one(&pool)
    .await
    .expect("head");
    assert_eq!((gen, sv, next_seq, lifecycle.as_str()), (0, 2, 5, "active"));

    // A pending, 24h-consent leave_requests row for bob; expires_at == received_at + 24h.
    let (status, req_did, rcv, exp): (String, String, DateTime<Utc>, DateTime<Utc>) = sqlx::query_as(
        "SELECT status,requester_did,received_at,expires_at FROM chat.leave_requests WHERE leave_request_id=$1",
    )
    .bind(request_id)
    .fetch_one(&pool)
    .await
    .expect("leave request row");
    assert_eq!(status, "pending");
    assert_eq!(req_did, bob_did);
    assert_eq!(exp, rcv + Duration::hours(24));

    // The leaveRequestEntry at seq 4 carries NO transition (non-mutating).
    let (entry_kind, transition): (String, Option<Uuid>) = sqlx::query_as(
        "SELECT entry_kind,transition_id FROM chat.entries WHERE conversation_id=$1 AND seq=4",
    )
    .bind(conversation_id)
    .fetch_one(&pool)
    .await
    .expect("entry");
    assert_eq!(entry_kind, "blue.catbird.chat.defs#leaveRequestEntry");
    assert!(transition.is_none());

    // Replay -> the head CAS conflicts (seq already advanced 4->5), zero residue
    // (symmetric with the cancellation + zero-leaf happy paths).
    let mut tx2 = pool.begin().await.expect("begin replay");
    let replay = apply_conversation_persistence_plan(&mut tx2, &plan, &ctx).await;
    assert!(
        matches!(replay, Err(ExecutorError::Transition(_))),
        "leave request replay must conflict on the head CAS, got {replay:?}"
    );
    tx2.rollback().await.expect("rollback replay");
    let leave_requests: i64 =
        sqlx::query_scalar("SELECT count(*) FROM chat.leave_requests WHERE conversation_id=$1")
            .bind(conversation_id)
            .fetch_one(&pool)
            .await
            .expect("leave requests");
    assert_eq!(leave_requests, 1, "replay wrote no duplicate leave request");
}

#[tokio::test]
async fn leave_cancellation_terminalizes_pending_request_and_conflicts_on_replay() {
    let (pool, _db) = setup().await;
    let scenario = run_fulfillment_scenario(&pool).await;
    let conversation_id = scenario.conversation_id;
    let fixture = &scenario.fixture;
    let bob_id = scenario.bob_id.clone();
    let bob_did = scenario.bob_did.clone();
    let bob_device = Uuid::from_bytes(*bob_id.device_id());

    // 1. Bob opens a pending leave request (seq 4).
    let req_received = ServerTimestamp::from_unix_millis_for_test(
        corpus_manifest().evaluation_unix_seconds as i64 * 1_000 + 5_000,
    )
    .unwrap();
    let (pending_state, request_id, _seq, _plan, _ctx) =
        commit_leave_request(&pool, &scenario, 4, req_received).await;

    // 2. Bob cancels it (a later control seq 5, same coordinate).
    let cancel_received = ServerTimestamp::from_unix_millis_for_test(
        corpus_manifest().evaluation_unix_seconds as i64 * 1_000 + 6_000,
    )
    .unwrap();
    let cancel_evidence = RequestEvidence::for_test(
        RequestEntryKind::LeaveCancellation,
        5,
        *request_id.as_bytes(),
        bob_id.clone(),
        *conversation_id.as_bytes(),
        cancel_received,
        0x81,
    )
    .unwrap();
    let registration = LockedRegistrationProjection::for_test(&cancel_evidence);
    let planned = plan_leave_cancellation(
        &pending_state,
        LeaveCancellation {
            actor: bob_id.clone(),
            leave_request_id: *request_id.as_bytes(),
            received_at: cancel_received,
            evidence: cancel_evidence,
            registration,
        },
    )
    .expect("valid leave cancellation plan");
    let entry_id = Uuid::new_v4();
    let head_cas = ConversationHeadCasBinding::for_test_edge(
        *conversation_id.as_bytes(),
        *entry_id.as_bytes(),
        scenario.coordinate,
        5,
        cancel_received,
    );
    let plan = persistence_plan_for_test(planned, head_cas);
    let applied_at = clock_now(&pool).await;
    let transcript = vec![0x82_u8; 16];
    let ctx = ExecutionContext {
        protocol_instance_id: fixture.protocol_instance_id,
        applied_at,
        actor: ExecutionActor {
            user_did: bob_did.clone(),
            device_id: bob_device,
            key_id: fixture.bob_key_id.clone(),
            auth_generation: 1,
            role: TransitionActorRole::Member,
            device_status: "active".to_owned(),
        },
        entry: ControlEntryContent {
            entry_id,
            entry_kind: "blue.catbird.chat.defs#leaveCancellationEntry".to_owned(),
            accepted_payload_bytes: vec![0x84_u8; 8],
            accepted_payload_sha256: Sha256::digest([0x84_u8; 8]).to_vec(),
            signed_request_bytes: transcript.clone(),
            unsigned_projection_bytes: vec![0x85_u8; 8],
            signing_transcript_bytes: transcript.clone(),
            request_digest: Sha256::digest(&transcript).to_vec(),
            signature: vec![0x86_u8; 64],
            server_fields_bytes: vec![0x87_u8; 8],
            outer_entry_fingerprint: vec![0x1B_u8; 32],
        },
        spine: SpineArtifacts {
            public_snapshot_bytes: vec![],
            public_snapshot_sha256: vec![],
            tree_summary_bytes: vec![],
            tree_summary_sha256: vec![],
            leaf_count: 2,
            genesis_group_info_bytes: vec![],
            genesis_group_info_sha256: vec![],
        },
        opened_leaves: vec![],
        metadata_author: None,
        participant_period_ids: vec![],
        leaf_period_ids: vec![],
        entry_recipients: entry_audience(&fixture.alice_id, &fixture.alice_did, &bob_id, &bob_did),
        events: vec![EventFanout {
            event_id: Uuid::new_v4(),
            event_kind: EventKind::LeaveRequest,
            payload_bytes: vec![0x88_u8; 8],
            recipients: event_audience(
                &pool,
                &fixture.alice_id,
                &fixture.alice_did,
                &bob_id,
                &bob_did,
            )
            .await,
            outbox: vec![(Uuid::new_v4(), OutboxWorkKind::Stream)],
        }],
        closing_leaf_periods: vec![],
        closing_participant_periods: vec![],
        reset_request_row: None,
        recovery_open: None,
        welcome_expiry: None,
        welcome_response: None,
        welcome_dispositions: vec![],
    };
    let mut tx = pool.begin().await.expect("begin leave cancellation");
    let applied = apply_conversation_persistence_plan(&mut tx, &plan, &ctx)
        .await
        .expect("leave cancellation applies");
    tx.commit().await.expect("leave cancellation COMMIT");
    assert_eq!(applied.allocated_seq, 5);

    // The request is cancelled: terminal digest == the cancellation entry's digest,
    // terminal_at set, no terminal transition (non-mutating).
    let (status, term_digest, term_transition, term_at): (
        String,
        Option<Vec<u8>>,
        Option<Uuid>,
        Option<DateTime<Utc>>,
    ) = sqlx::query_as(
        "SELECT status,terminal_request_digest,terminal_transition_id,terminal_at FROM chat.leave_requests WHERE leave_request_id=$1",
    )
    .bind(request_id)
    .fetch_one(&pool)
    .await
    .expect("cancelled leave request");
    assert_eq!(status, "cancelled");
    assert_eq!(term_digest, Some(Sha256::digest(&transcript).to_vec()));
    assert!(term_transition.is_none());
    assert!(term_at.is_some());

    // The leaveCancellationEntry landed at seq 5, coordinate still sv 2, seq now 6.
    let entry_kind: String = sqlx::query_scalar(
        "SELECT entry_kind FROM chat.entries WHERE conversation_id=$1 AND seq=5",
    )
    .bind(conversation_id)
    .fetch_one(&pool)
    .await
    .expect("entry");
    assert_eq!(entry_kind, "blue.catbird.chat.defs#leaveCancellationEntry");
    let next_seq: i64 = sqlx::query_scalar(
        "SELECT next_entry_seq FROM chat.conversations WHERE conversation_id=$1",
    )
    .bind(conversation_id)
    .fetch_one(&pool)
    .await
    .expect("head");
    assert_eq!(next_seq, 6);

    // Replay -> the head CAS conflicts (seq already advanced to 6), zero residue.
    let mut tx2 = pool.begin().await.expect("begin replay");
    let replay = apply_conversation_persistence_plan(&mut tx2, &plan, &ctx).await;
    assert!(
        matches!(replay, Err(ExecutorError::Transition(_))),
        "leave cancellation replay must conflict on the head CAS, got {replay:?}"
    );
    tx2.rollback().await.expect("rollback replay");
}

#[tokio::test]
async fn zero_leaf_leave_commits_immediate_self_removal() {
    let (pool, _db) = setup().await;
    let fixture = build_creation(&pool, ConversationKind::Group).await;
    let conversation_id = fixture.conversation_id;
    let bob_id = fixture.bob_id.clone();
    let bob_did = fixture.bob_did.clone();
    let bob_device = Uuid::from_bytes(*bob_id.device_id());

    // Commit the creation (alice active/admin + bob pending/member, no leaf).
    {
        let mut tx = pool.begin().await.expect("begin creation");
        apply_conversation_persistence_plan(&mut tx, &fixture.plan, &fixture.ctx)
            .await
            .expect("creation applies");
        tx.commit().await.expect("creation COMMIT");
    }

    // Bob's existing pending participant period — the DB fact the plan can't carry
    // (the leaver is removed from the successor hydration).
    let bob_period: Uuid = sqlx::query_scalar(
        "SELECT participant_period_id FROM chat.participants WHERE conversation_id=$1 AND user_did=$2 AND current_membership",
    )
    .bind(conversation_id)
    .bind(&bob_did)
    .fetch_one(&pool)
    .await
    .expect("bob participant period");

    // Bob (pending, leafless) self-removes immediately via a zeroLeafLeave.
    let received_at = ServerTimestamp::from_unix_millis_for_test(
        corpus_manifest().evaluation_unix_seconds as i64 * 1_000 + 2_000,
    )
    .unwrap();
    let transition_id = Uuid::new_v4();
    let evidence =
        TransitionEvidence::for_test_at(2, *transition_id.as_bytes(), [0x82_u8; 32], received_at)
            .unwrap();
    let planned = plan_zero_leaf_leave(
        &fixture.state,
        ZeroLeafLeave {
            actor: bob_id.clone(),
            transition: evidence,
        },
    )
    .expect("valid zero-leaf leave plan");
    assert_eq!(planned.resulting_state().coordinate().state_version(), 1);
    let entry_id = Uuid::new_v4();
    let head_cas = ConversationHeadCasBinding::for_test_edge(
        *conversation_id.as_bytes(),
        *entry_id.as_bytes(),
        fixture.coordinate,
        2,
        received_at,
    );
    let plan = persistence_plan_for_test(planned, head_cas);
    let applied_at = clock_now(&pool).await;
    let transcript = vec![0x92_u8; 16];
    let ctx = ExecutionContext {
        protocol_instance_id: fixture.protocol_instance_id,
        applied_at,
        actor: ExecutionActor {
            user_did: bob_did.clone(),
            device_id: bob_device,
            key_id: fixture.bob_key_id.clone(),
            auth_generation: 1,
            role: TransitionActorRole::Member,
            device_status: "active".to_owned(),
        },
        entry: ControlEntryContent {
            entry_id,
            entry_kind: "blue.catbird.chat.defs#zeroLeafLeaveEntry".to_owned(),
            accepted_payload_bytes: vec![0x94_u8; 8],
            accepted_payload_sha256: Sha256::digest([0x94_u8; 8]).to_vec(),
            signed_request_bytes: transcript.clone(),
            unsigned_projection_bytes: vec![0x95_u8; 8],
            signing_transcript_bytes: transcript.clone(),
            request_digest: Sha256::digest(&transcript).to_vec(),
            signature: vec![0x96_u8; 64],
            server_fields_bytes: vec![0x97_u8; 8],
            outer_entry_fingerprint: vec![0x1C_u8; 32],
        },
        spine: SpineArtifacts {
            public_snapshot_bytes: vec![0xE1_u8; 16],
            public_snapshot_sha256: Sha256::digest([0xE1_u8; 16]).to_vec(),
            tree_summary_bytes: vec![0xE2_u8; 16],
            tree_summary_sha256: Sha256::digest([0xE2_u8; 16]).to_vec(),
            leaf_count: 1,
            genesis_group_info_bytes: vec![],
            genesis_group_info_sha256: vec![],
        },
        opened_leaves: vec![],
        metadata_author: None,
        participant_period_ids: vec![],
        leaf_period_ids: vec![],
        entry_recipients: entry_audience(&fixture.alice_id, &fixture.alice_did, &bob_id, &bob_did),
        events: vec![EventFanout {
            event_id: Uuid::new_v4(),
            event_kind: EventKind::ConversationChanged,
            payload_bytes: vec![0x98_u8; 8],
            recipients: event_audience(
                &pool,
                &fixture.alice_id,
                &fixture.alice_did,
                &bob_id,
                &bob_did,
            )
            .await,
            outbox: vec![(Uuid::new_v4(), OutboxWorkKind::Stream)],
        }],
        closing_leaf_periods: vec![],
        closing_participant_periods: vec![(bob_id.clone(), bob_period)],
        reset_request_row: None,
        recovery_open: None,
        welcome_expiry: None,
        welcome_response: None,
        welcome_dispositions: vec![],
    };

    let mut tx = pool.begin().await.expect("begin zero-leaf leave");
    let applied = apply_conversation_persistence_plan(&mut tx, &plan, &ctx)
        .await
        .expect("zero-leaf leave applies");
    tx.commit()
        .await
        .expect("zero-leaf leave COMMIT past all deferred triggers");
    assert_eq!(applied.allocated_seq, 2);

    // Coordinate advanced sv 0 -> 1 (same generation/epoch), seq 2 -> 3.
    let (gen, sv, next_seq, lifecycle): (i64, i64, i64, String) = sqlx::query_as(
        "SELECT current_generation,current_state_version,next_entry_seq,lifecycle FROM chat.conversations WHERE conversation_id=$1",
    )
    .bind(conversation_id)
    .fetch_one(&pool)
    .await
    .expect("head");
    assert_eq!((gen, sv, next_seq, lifecycle.as_str()), (0, 1, 3, "active"));

    // A leavePolicy generation state at sv 1.
    let skind: String = sqlx::query_scalar(
        "SELECT state_kind FROM chat.generation_states WHERE conversation_id=$1 AND state_version=1",
    )
    .bind(conversation_id)
    .fetch_one(&pool)
    .await
    .expect("gen state");
    assert_eq!(skind, "leavePolicy");

    // Bob's participant period is closed, bound to the leave transition; no metadata.
    let (membership, removing): (bool, Option<Uuid>) = sqlx::query_as(
        "SELECT current_membership,removing_transition_id FROM chat.participants WHERE participant_period_id=$1",
    )
    .bind(bob_period)
    .fetch_one(&pool)
    .await
    .expect("bob period");
    assert!(!membership);
    assert_eq!(removing, Some(transition_id));
    let (tkind, meta): (String, Option<Uuid>) = sqlx::query_as(
        "SELECT kind,metadata_snapshot_id FROM chat.transitions WHERE transition_id=$1",
    )
    .bind(transition_id)
    .fetch_one(&pool)
    .await
    .expect("transition");
    assert_eq!(tkind, "leavePolicy");
    assert!(meta.is_none());

    // The zeroLeafLeaveEntry landed at seq 2.
    let entry_kind: String = sqlx::query_scalar(
        "SELECT entry_kind FROM chat.entries WHERE conversation_id=$1 AND seq=2",
    )
    .bind(conversation_id)
    .fetch_one(&pool)
    .await
    .expect("entry");
    assert_eq!(entry_kind, "blue.catbird.chat.defs#zeroLeafLeaveEntry");

    // Replay -> head CAS conflict (sv already 1), zero residue.
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
        "zero-leaf leave replay must conflict on the head CAS, got {replay:?}"
    );
    tx2.rollback().await.expect("rollback replay");
    let after: i64 =
        sqlx::query_scalar("SELECT count(*) FROM chat.transitions WHERE conversation_id=$1")
            .bind(conversation_id)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(before, after, "zero-leaf leave replay left zero residue");
}

#[tokio::test]
async fn leave_fulfillment_commits_remove_and_supersedes_pending_welcome() {
    let (pool, _db) = setup().await;
    let manifest = corpus_manifest();
    let scenario = run_fulfillment_scenario(&pool).await;
    let conversation_id = scenario.conversation_id;
    let bob_id = scenario.bob_id.clone();
    let bob_did = scenario.bob_did.clone();
    let bob_device = Uuid::from_bytes(*bob_id.device_id());
    let welcome_id = scenario.welcome_id;
    let alice_id = scenario.fixture.alice_id.clone();
    let alice_did = scenario.fixture.alice_did.clone();
    let alice_device = scenario.fixture.alice_device;
    let alice_key_id = scenario.fixture.alice_key_id.clone();
    let creation_transition_id = scenario.fixture.creation_transition_id;
    let protocol_instance_id = scenario.fixture.protocol_instance_id;

    // 1. Bob opens a pending leave request (seq 4).
    let req_received = ServerTimestamp::from_unix_millis_for_test(
        manifest.evaluation_unix_seconds as i64 * 1_000 + 5_000,
    )
    .unwrap();
    let (pending_state, leave_request_id, _seq, _plan, _ctx) =
        commit_leave_request(&pool, &scenario, 4, req_received).await;

    // Bob's existing leaf + participant periods — the DB facts the successor
    // hydration can't carry (bob is removed from it).
    let bob_leaf_period: Uuid = sqlx::query_scalar(
        "SELECT leaf_period_id FROM chat.member_devices WHERE conversation_id=$1 AND user_did=$2 AND active",
    )
    .bind(conversation_id)
    .bind(&bob_did)
    .fetch_one(&pool)
    .await
    .expect("bob leaf period");
    let bob_participant_period: Uuid = sqlx::query_scalar(
        "SELECT participant_period_id FROM chat.participants WHERE conversation_id=$1 AND user_did=$2 AND current_membership",
    )
    .bind(conversation_id)
    .bind(&bob_did)
    .fetch_one(&pool)
    .await
    .expect("bob participant period");

    // 2. Alice fulfills the retained consent with a Remove commit removing bob.
    let alice_leaf_index = pending_state
        .leaf(&alice_id)
        .expect("alice leaf")
        .leaf_index();
    let bob_leaf_index = pending_state.leaf(&bob_id).expect("bob leaf").leaf_index();
    let successor_coord = PublicGroupSnapshotCoordinate::new(
        *conversation_id.as_bytes(),
        manifest.chain.generation,
        pending_state.coordinate().state_version() + 1,
        *pending_state.coordinate().group_id(),
        pending_state.coordinate().epoch() + 1,
        [0xD1_u8; 32],
        [0xD2_u8; 32],
        PublicGroupSnapshotLifecycle::Active,
    );
    assert_eq!(successor_coord.state_version(), 3);
    assert_eq!(successor_coord.epoch(), 2);
    let commit = chat_protocol::public_state::VerifiedCommitPublicState::for_test_remove(
        pending_state.public_state(),
        successor_coord,
        alice_leaf_index,
        &[bob_leaf_index],
    )
    .expect("synthetic sealed remove evidence");

    let fulfill_transition = Uuid::new_v4();
    let fulfill_entry = Uuid::new_v4();
    let fulfill_received = ServerTimestamp::from_unix_millis_for_test(
        manifest.evaluation_unix_seconds as i64 * 1_000 + 6_000,
    )
    .unwrap();
    let alice_key_id_bytes: [u8; 32] = Sha256::digest(&scenario.alice_sig_key).into();
    // Re-encryption: SAME author/origin/version/size as the creation snapshot; a
    // fresh nonce + ciphertext; coordinate epoch = 2 (validate_state).
    let reencryption = MetadataSnapshotBinding::for_test_creation(
        *conversation_id.as_bytes(),
        0,
        successor_coord.epoch(),
        *successor_coord.group_context_hash(),
        creation_transition_id,
        1,
        alice_id.clone(),
        alice_key_id_bytes,
        scenario.alice_sig_key.clone().try_into().unwrap(),
        1,
        1,
        [0xF7_u8; 12],
        vec![0xF8_u8; 48],
    );
    let fulfill_evidence = TransitionEvidence::for_test_leave_fulfillment_with_metadata(
        5,
        *fulfill_transition.as_bytes(),
        [0x1D_u8; 32],
        fulfill_received,
        *leave_request_id.as_bytes(),
        *pending_state.coordinate(),
        successor_coord,
        bob_id.clone(),
        reencryption,
    )
    .unwrap();
    let planned = plan_leave_fulfillment(
        &pending_state,
        LeaveFulfillment {
            actor: alice_id.clone(),
            requester: bob_id.principal().clone(),
            leave_request_id: *leave_request_id.as_bytes(),
            transition: fulfill_evidence,
            commit,
        },
    )
    .expect("valid leave fulfillment plan");
    let head_cas = ConversationHeadCasBinding::for_test_edge(
        *conversation_id.as_bytes(),
        *fulfill_entry.as_bytes(),
        *pending_state.coordinate(),
        5,
        fulfill_received,
    );
    let plan = persistence_plan_for_test(planned, head_cas);

    let applied_at = clock_now(&pool).await;
    let payload = vec![0xFA_u8; 12];
    let transcript = vec![0xFB_u8; 12];
    let alice_pred = device_event_predecessor(&pool, &alice_did, alice_device).await;
    let bob_pred = device_event_predecessor(&pool, &bob_did, bob_device).await;
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
            entry_id: fulfill_entry,
            entry_kind: "blue.catbird.chat.defs#leaveCommitFulfillmentEntry".to_owned(),
            accepted_payload_bytes: payload.clone(),
            accepted_payload_sha256: Sha256::digest(&payload).to_vec(),
            signed_request_bytes: transcript.clone(),
            unsigned_projection_bytes: vec![0xFC_u8; 8],
            signing_transcript_bytes: transcript.clone(),
            request_digest: Sha256::digest(&transcript).to_vec(),
            signature: vec![0xFD_u8; 64],
            server_fields_bytes: vec![0xFE_u8; 8],
            outer_entry_fingerprint: vec![0x1D_u8; 32],
        },
        spine: SpineArtifacts {
            public_snapshot_bytes: vec![0xC1_u8; 16],
            public_snapshot_sha256: Sha256::digest([0xC1_u8; 16]).to_vec(),
            tree_summary_bytes: vec![0xC2_u8; 16],
            tree_summary_sha256: Sha256::digest([0xC2_u8; 16]).to_vec(),
            leaf_count: 1,
            genesis_group_info_bytes: vec![],
            genesis_group_info_sha256: vec![],
        },
        opened_leaves: vec![],
        metadata_author: Some(MetadataAuthorColumns {
            author_role: "admin".to_owned(),
            author_device_status: "active".to_owned(),
            author_public_key: scenario.alice_sig_key.clone(),
            author_key_id: alice_key_id.clone(),
            metadata_snapshot_id: Uuid::new_v4(),
        }),
        participant_period_ids: vec![],
        leaf_period_ids: vec![],
        // Alice (remaining) fetches the control entry; bob (removed) fetches the
        // closing control via the `intervalClose` entitlement the interval-close
        // provenance trigger requires at the terminal seq.
        entry_recipients: vec![
            (alice_id.clone(), EntryEntitlementKind::Control),
            (bob_id.clone(), EntryEntitlementKind::IntervalClose),
        ],
        events: vec![EventFanout {
            event_id: Uuid::new_v4(),
            event_kind: EventKind::LeaveRequest,
            payload_bytes: vec![0xC4_u8; 8],
            recipients: vec![(
                alice_id.clone(),
                EventEntitlementKind::Participant,
                alice_pred,
            )],
            outbox: vec![(Uuid::new_v4(), OutboxWorkKind::Stream)],
        }],
        closing_leaf_periods: vec![(bob_id.clone(), bob_leaf_period)],
        closing_participant_periods: vec![(bob_id.clone(), bob_participant_period)],
        reset_request_row: None,
        recovery_open: None,
        // The epoch change supersedes the fulfillment scenario's pending Welcome.
        welcome_expiry: None,
        welcome_response: None,
        welcome_dispositions: vec![WelcomeDispositionInput {
            welcome_id,
            event: EventFanout {
                event_id: Uuid::new_v4(),
                event_kind: EventKind::WelcomeDisposition,
                payload_bytes: vec![0xC5_u8; 8],
                recipients: vec![(bob_id.clone(), EventEntitlementKind::Welcome, bob_pred)],
                outbox: vec![(Uuid::new_v4(), OutboxWorkKind::Stream)],
            },
        }],
    };

    let mut tx = pool.begin().await.expect("begin leave fulfillment");
    let applied = apply_conversation_persistence_plan(&mut tx, &plan, &ctx)
        .await
        .expect("leave fulfillment applies");
    tx.commit()
        .await
        .expect("leave fulfillment COMMIT past all deferred triggers");
    assert_eq!(applied.allocated_seq, 5);

    // Head at the committed successor (sv 3, seq 6).
    let (sv, next_seq): (i64, i64) = sqlx::query_as(
        "SELECT current_state_version,next_entry_seq FROM chat.conversations WHERE conversation_id=$1",
    )
    .bind(conversation_id)
    .fetch_one(&pool)
    .await
    .expect("head");
    assert_eq!((sv, next_seq), (3, 6));
    // commit gen_state at epoch 2, one leaf (bob removed).
    let (skind, sepoch, sleaf): (String, i64, i64) = sqlx::query_as(
        "SELECT state_kind,epoch,leaf_count FROM chat.generation_states WHERE conversation_id=$1 AND state_version=3",
    )
    .bind(conversation_id)
    .fetch_one(&pool)
    .await
    .expect("commit gen state");
    assert_eq!((skind.as_str(), sepoch, sleaf), ("commit", 2, 1));
    // Bob's leaf is closed, bound to the leave transition.
    let (bob_active, removed_transition): (bool, Option<Uuid>) = sqlx::query_as(
        "SELECT active,removed_transition_id FROM chat.member_devices WHERE leaf_period_id=$1",
    )
    .bind(bob_leaf_period)
    .fetch_one(&pool)
    .await
    .expect("bob leaf");
    assert!(!bob_active);
    assert_eq!(removed_transition, Some(fulfill_transition));
    // Bob's interval is Remove-closed at the fulfillment seq.
    let (interval_end, close_kind): (Option<i64>, Option<String>) = sqlx::query_as(
        "SELECT terminal_seq,closing_kind FROM chat.application_intervals WHERE conversation_id=$1 AND recipient_did=$2",
    )
    .bind(conversation_id)
    .bind(&bob_did)
    .fetch_one(&pool)
    .await
    .expect("bob interval");
    assert_eq!(interval_end, Some(5));
    assert_eq!(close_kind.as_deref(), Some("remove"));
    // Bob's participant is closed; the leave request is fulfilled.
    let bob_membership: bool = sqlx::query_scalar(
        "SELECT current_membership FROM chat.participants WHERE participant_period_id=$1",
    )
    .bind(bob_participant_period)
    .fetch_one(&pool)
    .await
    .expect("bob participant");
    assert!(!bob_membership);
    let (leave_status, leave_terminal): (String, Option<Uuid>) = sqlx::query_as(
        "SELECT status,terminal_transition_id FROM chat.leave_requests WHERE leave_request_id=$1",
    )
    .bind(leave_request_id)
    .fetch_one(&pool)
    .await
    .expect("leave request");
    assert_eq!(leave_status, "fulfilled");
    assert_eq!(leave_terminal, Some(fulfill_transition));
    // The prior pending Welcome is superseded.
    let welcome_status: String =
        sqlx::query_scalar("SELECT status FROM chat.welcome_deliveries WHERE welcome_id=$1")
            .bind(welcome_id)
            .fetch_one(&pool)
            .await
            .expect("welcome");
    assert_eq!(welcome_status, "superseded");
    // The re-encryption metadata snapshot for the fulfillment transition.
    let snap_count: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM chat.metadata_snapshots WHERE producing_transition_id=$1",
    )
    .bind(fulfill_transition)
    .fetch_one(&pool)
    .await
    .expect("snapshot");
    assert_eq!(snap_count, 1);

    // Replay -> head CAS conflict (head already at sv 3), zero residue.
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
        "leave fulfillment replay must conflict on the head CAS, got {replay:?}"
    );
    tx2.rollback().await.expect("rollback replay");
    let after: i64 =
        sqlx::query_scalar("SELECT count(*) FROM chat.transitions WHERE conversation_id=$1")
            .bind(conversation_id)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(before, after, "leave fulfillment replay left zero residue");
}

/// The uncommitted `replace` leaf-recovery fulfillment plan + ctx (create +
/// acceptance + add-fulfillment + the bob `replace` request are already COMMITTED).
/// Extracted so a desync negative can apply a MUTATED ctx against the same state.
struct BuiltReplaceFulfillment {
    plan: chat_protocol::state_machine::ConversationPersistencePlan,
    ctx: ExecutionContext,
    conversation_id: Uuid,
    bob_did: String,
    bob_signature_key: Vec<u8>,
    bob_old_leaf_period: Uuid,
    replace_transition: Uuid,
    replace_request_id: Uuid,
    replace_welcome_id: Uuid,
    scenario_welcome_id: Uuid,
    new_ref: [u8; 32],
    new_package_not_after: DateTime<Utc>,
}

async fn build_replace_fulfillment(pool: &PgPool) -> BuiltReplaceFulfillment {
    let pool = pool.clone();
    let manifest = corpus_manifest();
    let scenario = run_fulfillment_scenario(&pool).await;
    let conversation_id = scenario.conversation_id;
    let bob_id = scenario.bob_id.clone();
    let bob_did = scenario.bob_did.clone();
    let bob_device = Uuid::from_bytes(*bob_id.device_id());
    let bob_key_id = scenario.fixture.bob_key_id.clone();
    let alice_id = scenario.fixture.alice_id.clone();
    let alice_did = scenario.fixture.alice_did.clone();
    let alice_device = scenario.fixture.alice_device;
    let alice_key_id = scenario.fixture.alice_key_id.clone();
    let creation_transition_id = scenario.fixture.creation_transition_id;
    let protocol_instance_id = scenario.fixture.protocol_instance_id;
    let scenario_welcome_id = scenario.welcome_id;

    // Bob's current (add-fulfillment) leaf period — the OLD leaf a `replace` closes.
    let bob_old_leaf_period: Uuid = sqlx::query_scalar(
        "SELECT leaf_period_id FROM chat.member_devices WHERE conversation_id=$1 AND user_did=$2 AND active",
    )
    .bind(conversation_id)
    .bind(&bob_did)
    .fetch_one(&pool)
    .await
    .expect("bob old leaf period");

    // 1. Bob opens a REPLACE recovery request for his own leaf (bound to sv 2),
    //    reserving a FRESH key package. A leaf recovery keeps the device's signing
    //    identity, so the fresh package is owned by bob's EXISTING key. Internal op
    //    — the coordinate + seq counter are byte-untouched.
    let new_ref = random_ref32();
    let new_package_not_after =
        seed_key_package(&pool, &bob_did, bob_device, &bob_key_id, &new_ref).await;
    let req_received = ServerTimestamp::from_unix_millis_for_test(
        manifest.evaluation_unix_seconds as i64 * 1_000 + 5_000,
    )
    .unwrap();
    let pkg_not_after_ts =
        ServerTimestamp::from_unix_millis_for_test(new_package_not_after.timestamp_millis())
            .unwrap();
    let replace_request_id = Uuid::new_v4();
    let req_evidence = RequestEvidence::for_test(
        RequestEntryKind::LeafRecoveryRequest,
        4,
        *replace_request_id.as_bytes(),
        bob_id.clone(),
        *conversation_id.as_bytes(),
        req_received,
        0x81,
    )
    .unwrap();
    let req_planned = plan_leaf_recovery_request(
        &scenario.fulfillment_state,
        LeafRecoveryRequestCommand {
            actor: bob_id.clone(),
            recovery_request_id: *replace_request_id.as_bytes(),
            kind: LeafRecoveryKind::Replace,
            key_package_ref: new_ref,
            received_at: req_received,
            package_not_after: pkg_not_after_ts,
            evidence: req_evidence,
        },
    )
    .expect("valid bob replace request plan");
    let requested_state = req_planned.resulting_state().clone();
    let req_head = ConversationHeadCasBinding::for_test_internal(
        *conversation_id.as_bytes(),
        scenario.coordinate,
        4,
        req_received,
    );
    let req_plan = persistence_plan_for_test(req_planned, req_head);
    let req_applied_at = clock_now(&pool).await;
    let req_transcript = vec![0x82_u8; 16];
    let bob_pred_req = device_event_predecessor(&pool, &bob_did, bob_device).await;
    let req_ctx = ExecutionContext {
        protocol_instance_id,
        applied_at: req_applied_at,
        actor: ExecutionActor {
            user_did: bob_did.clone(),
            device_id: bob_device,
            key_id: bob_key_id.clone(),
            auth_generation: 1,
            role: TransitionActorRole::Member,
            device_status: "active".to_owned(),
        },
        entry: ControlEntryContent {
            entry_id: Uuid::new_v4(),
            entry_kind: "blue.catbird.chat.defs#applicationEntry".to_owned(),
            accepted_payload_bytes: vec![0x83_u8; 8],
            accepted_payload_sha256: Sha256::digest([0x83_u8; 8]).to_vec(),
            signed_request_bytes: req_transcript.clone(),
            unsigned_projection_bytes: vec![0x84_u8; 8],
            signing_transcript_bytes: req_transcript.clone(),
            request_digest: Sha256::digest(&req_transcript).to_vec(),
            signature: vec![0x85_u8; 64],
            server_fields_bytes: vec![0x86_u8; 8],
            outer_entry_fingerprint: vec![0x18_u8; 32],
        },
        spine: SpineArtifacts {
            public_snapshot_bytes: vec![],
            public_snapshot_sha256: vec![],
            tree_summary_bytes: vec![],
            tree_summary_sha256: vec![],
            leaf_count: 2,
            genesis_group_info_bytes: vec![],
            genesis_group_info_sha256: vec![],
        },
        opened_leaves: vec![],
        metadata_author: None,
        participant_period_ids: vec![],
        leaf_period_ids: vec![],
        entry_recipients: vec![],
        events: vec![EventFanout {
            event_id: Uuid::new_v4(),
            event_kind: EventKind::ConversationChanged,
            payload_bytes: vec![0x87_u8; 8],
            recipients: vec![(
                bob_id.clone(),
                EventEntitlementKind::Participant,
                bob_pred_req,
            )],
            outbox: vec![(Uuid::new_v4(), OutboxWorkKind::Stream)],
        }],
        closing_leaf_periods: vec![],
        closing_participant_periods: vec![],
        reset_request_row: None,
        recovery_open: Some(RecoveryOpenContext {
            participant_period_id: None,
            package_not_after: new_package_not_after,
            replaced_leaf_period_id: Some(bob_old_leaf_period),
        }),
        welcome_expiry: None,
        welcome_response: None,
        welcome_dispositions: vec![],
    };
    {
        let mut tx = pool.begin().await.expect("begin replace request");
        apply_conversation_persistence_plan(&mut tx, &req_plan, &req_ctx)
            .await
            .expect("replace request applies");
        tx.commit()
            .await
            .expect("replace request COMMIT past all deferred triggers");
    }

    // 2. Alice fulfills the `replace` with a synthetic rotation commit (bob's old
    //    leaf removed + a fresh bob leaf carrying `new_ref`), sv 2 -> 3, epoch 1 -> 2.
    let alice_leaf_index = requested_state
        .leaf(&alice_id)
        .expect("alice leaf")
        .leaf_index();
    let bob_leaf_index = requested_state
        .leaf(&bob_id)
        .expect("bob leaf")
        .leaf_index();
    let successor_coord = PublicGroupSnapshotCoordinate::new(
        *conversation_id.as_bytes(),
        manifest.chain.generation,
        requested_state.coordinate().state_version() + 1,
        *requested_state.coordinate().group_id(),
        requested_state.coordinate().epoch() + 1,
        [0xB1_u8; 32],
        [0xB2_u8; 32],
        PublicGroupSnapshotLifecycle::Active,
    );
    assert_eq!(successor_coord.state_version(), 3);
    assert_eq!(successor_coord.epoch(), 2);
    let new_encryption_key = vec![0xB6_u8; 32];
    let commit = chat_protocol::public_state::VerifiedCommitPublicState::for_test_replace(
        requested_state.public_state(),
        successor_coord,
        alice_leaf_index,
        bob_leaf_index,
        new_encryption_key,
        new_ref,
    )
    .expect("synthetic sealed replace evidence");
    let welcome_wire = corpus_file("welcome.mls");
    let welcome = chat_protocol::public_state::VerifiedRecoveryWelcome::for_test_bound(
        welcome_wire.clone(),
        new_ref,
    );
    let replace_welcome_id = Uuid::new_v4();
    let replace_transition = Uuid::new_v4();
    let replace_entry = Uuid::new_v4();
    let replace_received = ServerTimestamp::from_unix_millis_for_test(
        manifest.evaluation_unix_seconds as i64 * 1_000 + 6_000,
    )
    .unwrap();
    let alice_key_id_bytes: [u8; 32] = Sha256::digest(&scenario.alice_sig_key).into();
    let reencryption = MetadataSnapshotBinding::for_test_creation(
        *conversation_id.as_bytes(),
        0,
        successor_coord.epoch(),
        *successor_coord.group_context_hash(),
        creation_transition_id,
        1,
        alice_id.clone(),
        alice_key_id_bytes,
        scenario.alice_sig_key.clone().try_into().unwrap(),
        1,
        1,
        [0xB7_u8; 12],
        vec![0xB8_u8; 48],
    );
    let fulfill_evidence =
        TransitionEvidence::for_test_leaf_recovery_replace_fulfillment_with_metadata(
            4,
            *replace_transition.as_bytes(),
            [0x1E_u8; 32],
            replace_received,
            *replace_request_id.as_bytes(),
            *requested_state.coordinate(),
            successor_coord,
            bob_id.clone(),
            new_ref,
            *replace_welcome_id.as_bytes(),
            welcome_wire.clone(),
            reencryption,
        )
        .unwrap();
    let planned = plan_leaf_recovery_fulfillment(
        &requested_state,
        LeafRecoveryFulfillment {
            actor: alice_id.clone(),
            target: bob_id.clone(),
            recovery_request_id: *replace_request_id.as_bytes(),
            welcome_id: *replace_welcome_id.as_bytes(),
            transition: fulfill_evidence,
            commit,
            welcome,
        },
    )
    .expect("valid replace fulfillment plan");
    let head_cas = ConversationHeadCasBinding::for_test_edge(
        *conversation_id.as_bytes(),
        *replace_entry.as_bytes(),
        *requested_state.coordinate(),
        4,
        replace_received,
    );
    let plan = persistence_plan_for_test(planned, head_cas);

    // Participant periods in hydration (sorted-DID) order — bob's participant
    // period is UNCHANGED by a rotation (the new leaf reuses it).
    let mut participant_rows: Vec<(String, Uuid)> = sqlx::query_as(
        "SELECT user_did,participant_period_id FROM chat.participants WHERE conversation_id=$1 AND current_membership",
    )
    .bind(conversation_id)
    .fetch_all(&pool)
    .await
    .expect("participant periods");
    participant_rows.sort_by(|l, r| l.0.as_bytes().cmp(r.0.as_bytes()));
    let participant_period_ids: Vec<Uuid> = participant_rows.iter().map(|(_, id)| *id).collect();

    let applied_at = clock_now(&pool).await;
    let payload = vec![0xBA_u8; 12];
    let transcript = vec![0xBB_u8; 12];
    let alice_pred = device_event_predecessor(&pool, &alice_did, alice_device).await;
    let bob_pred = device_event_predecessor(&pool, &bob_did, bob_device).await;
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
            entry_id: replace_entry,
            entry_kind: "blue.catbird.chat.defs#leafRecoveryFulfillmentEntry".to_owned(),
            accepted_payload_bytes: payload.clone(),
            accepted_payload_sha256: Sha256::digest(&payload).to_vec(),
            signed_request_bytes: transcript.clone(),
            unsigned_projection_bytes: vec![0xBC_u8; 8],
            signing_transcript_bytes: transcript.clone(),
            request_digest: Sha256::digest(&transcript).to_vec(),
            signature: vec![0xBD_u8; 64],
            server_fields_bytes: vec![0xBE_u8; 8],
            outer_entry_fingerprint: vec![0x1E_u8; 32],
        },
        spine: SpineArtifacts {
            public_snapshot_bytes: vec![0xC1_u8; 16],
            public_snapshot_sha256: Sha256::digest([0xC1_u8; 16]).to_vec(),
            tree_summary_bytes: vec![0xC2_u8; 16],
            tree_summary_sha256: Sha256::digest([0xC2_u8; 16]).to_vec(),
            leaf_count: 2,
            genesis_group_info_bytes: vec![],
            genesis_group_info_sha256: vec![],
        },
        // The rotated-in leaf's persistence columns: bob's SAME signing identity.
        opened_leaves: vec![LeafPersistenceColumns {
            device: bob_id.clone(),
            leaf_key_id: bob_key_id.clone(),
            leaf_auth_generation: 1,
        }],
        metadata_author: Some(MetadataAuthorColumns {
            author_role: "admin".to_owned(),
            author_device_status: "active".to_owned(),
            author_public_key: scenario.alice_sig_key.clone(),
            author_key_id: alice_key_id.clone(),
            metadata_snapshot_id: Uuid::new_v4(),
        }),
        participant_period_ids,
        // The FRESH leaf period for bob's rotated-in leaf.
        leaf_period_ids: vec![Uuid::new_v4()],
        // Alice (remaining) fetches the control entry; bob's OLD interval close
        // routes to him via the `intervalClose` entitlement the interval-close
        // provenance trigger requires at the fulfillment seq.
        entry_recipients: vec![
            (alice_id.clone(), EntryEntitlementKind::Control),
            (bob_id.clone(), EntryEntitlementKind::IntervalClose),
        ],
        // The remaining member (alice) observes the rotation via WelcomeAvailable;
        // bob's single event this transition is the WelcomeDisposition below (the
        // per-device event predecessor chain forbids a device in two events at once).
        events: vec![EventFanout {
            event_id: Uuid::new_v4(),
            event_kind: EventKind::WelcomeAvailable,
            payload_bytes: vec![0xBF_u8; 8],
            recipients: vec![(
                alice_id.clone(),
                EventEntitlementKind::Participant,
                alice_pred,
            )],
            outbox: vec![(Uuid::new_v4(), OutboxWorkKind::Stream)],
        }],
        // The OLD leaf period closed by the rotation.
        closing_leaf_periods: vec![(bob_id.clone(), bob_old_leaf_period)],
        closing_participant_periods: vec![],
        reset_request_row: None,
        recovery_open: None,
        welcome_expiry: None,
        welcome_response: None,
        // The epoch change supersedes the scenario's prior pending Welcome for bob.
        welcome_dispositions: vec![WelcomeDispositionInput {
            welcome_id: scenario_welcome_id,
            event: EventFanout {
                event_id: Uuid::new_v4(),
                event_kind: EventKind::WelcomeDisposition,
                payload_bytes: vec![0xC5_u8; 8],
                recipients: vec![(bob_id.clone(), EventEntitlementKind::Welcome, bob_pred)],
                outbox: vec![(Uuid::new_v4(), OutboxWorkKind::Stream)],
            },
        }],
    };

    let bob_signature_key = hex::decode(&manifest.identity.bob.signature_public_key_hex).unwrap();
    BuiltReplaceFulfillment {
        plan,
        ctx,
        conversation_id,
        bob_did,
        bob_signature_key,
        bob_old_leaf_period,
        replace_transition,
        replace_request_id,
        replace_welcome_id,
        scenario_welcome_id,
        new_ref,
        new_package_not_after,
    }
}

/// Arm 3 #1 (`replace` fulfillment): a leaf-recovery `replace` ROTATES the
/// target's leaf in place. Because the state diff is keyed by DEVICE (not leaf
/// index), the rotation surfaces as ONE (Some,Some) leaf change for bob (new
/// key-package origin + HPKE key, SAME signing identity) — the executor closes
/// bob's OLD leaf period + Replace-closes his OLD interval at the fulfillment
/// seq, AND opens a fresh leaf period + Add interval, all past the deferred
/// `assert_application_interval_provenance` (which requires the `replace` close
/// to route an `intervalClose` entitlement to bob and be authored by a
/// `leafRecovery` transition). Builds on `run_fulfillment_scenario` (bob added at
/// sv 2 / epoch 1), opens a bob-authored `replace` request reserving a FRESH key
/// package, then fulfills sv 2 -> 3 / epoch 1 -> 2.
#[tokio::test]
async fn leaf_recovery_replace_fulfillment_rotates_leaf_and_closes_prior_interval() {
    let (pool, _db) = setup().await;
    let BuiltReplaceFulfillment {
        plan,
        ctx,
        conversation_id,
        bob_did,
        bob_signature_key,
        bob_old_leaf_period,
        replace_transition,
        replace_request_id,
        replace_welcome_id,
        scenario_welcome_id,
        new_ref,
        new_package_not_after,
    } = Box::pin(build_replace_fulfillment(&pool)).await;

    let mut tx = pool.begin().await.expect("begin replace fulfillment");
    let applied = apply_conversation_persistence_plan(&mut tx, &plan, &ctx)
        .await
        .expect("replace fulfillment applies");
    tx.commit()
        .await
        .expect("replace fulfillment COMMIT past all deferred triggers");
    assert_eq!(applied.allocated_seq, 4);

    // Head at the committed successor (sv 3, seq 5); commit gen_state epoch 2, 2 leaves.
    let (sv, next_seq): (i64, i64) = sqlx::query_as(
        "SELECT current_state_version,next_entry_seq FROM chat.conversations WHERE conversation_id=$1",
    )
    .bind(conversation_id)
    .fetch_one(&pool)
    .await
    .expect("head");
    assert_eq!((sv, next_seq), (3, 5));
    let (skind, sepoch, sleaf): (String, i64, i64) = sqlx::query_as(
        "SELECT state_kind,epoch,leaf_count FROM chat.generation_states WHERE conversation_id=$1 AND state_version=3",
    )
    .bind(conversation_id)
    .fetch_one(&pool)
    .await
    .expect("commit gen state");
    assert_eq!((skind.as_str(), sepoch, sleaf), ("commit", 2, 2));

    // Bob's OLD leaf period is closed, bound to the fulfillment transition.
    let (old_active, old_removed): (bool, Option<Uuid>) = sqlx::query_as(
        "SELECT active,removed_transition_id FROM chat.member_devices WHERE leaf_period_id=$1",
    )
    .bind(bob_old_leaf_period)
    .fetch_one(&pool)
    .await
    .expect("bob old leaf");
    assert!(!old_active);
    assert_eq!(old_removed, Some(replace_transition));
    // Bob's NEW active leaf carries the fresh key package + the SAME signing key.
    let (new_active, new_origin, new_join_ref, new_sig): (bool, String, Option<Vec<u8>>, Vec<u8>) =
        sqlx::query_as(
            "SELECT active,origin,join_key_package_ref,leaf_signature_key FROM chat.member_devices WHERE conversation_id=$1 AND user_did=$2 AND active",
        )
        .bind(conversation_id)
        .bind(&bob_did)
        .fetch_one(&pool)
        .await
        .expect("bob new leaf");
    assert!(new_active);
    assert_eq!(
        (new_origin.as_str(), new_join_ref),
        ("keyPackage", Some(new_ref.to_vec()))
    );
    assert_eq!(new_sig, bob_signature_key);
    // Bob's OLD interval is Replace-closed at the fulfillment seq; his NEW interval
    // is Add-opened at the same seq.
    let (old_start, old_end, old_kind): (i64, Option<i64>, Option<String>) = sqlx::query_as(
        "SELECT start_seq,terminal_seq,closing_kind FROM chat.application_intervals WHERE conversation_id=$1 AND recipient_did=$2 AND terminal_seq IS NOT NULL",
    )
    .bind(conversation_id)
    .bind(&bob_did)
    .fetch_one(&pool)
    .await
    .expect("bob closed interval");
    assert_eq!(old_start, 3);
    assert_eq!(old_end, Some(4));
    assert_eq!(old_kind.as_deref(), Some("replace"));
    let (new_start, new_open): (i64, String) = sqlx::query_as(
        "SELECT start_seq,opening_kind FROM chat.application_intervals WHERE conversation_id=$1 AND recipient_did=$2 AND terminal_seq IS NULL",
    )
    .bind(conversation_id)
    .bind(&bob_did)
    .fetch_one(&pool)
    .await
    .expect("bob open interval");
    assert_eq!((new_start, new_open.as_str()), (4, "add"));

    // Request fulfilled, reservation consumed, fresh package consumed.
    let req_status: String = sqlx::query_scalar(
        "SELECT status FROM chat.leaf_recovery_requests WHERE recovery_request_id=$1",
    )
    .bind(replace_request_id)
    .fetch_one(&pool)
    .await
    .expect("request");
    assert_eq!(req_status, "fulfilled");
    let res_status: String = sqlx::query_scalar(
        "SELECT status FROM chat.key_package_reservations WHERE recovery_request_id=$1",
    )
    .bind(replace_request_id)
    .fetch_one(&pool)
    .await
    .expect("reservation");
    assert_eq!(res_status, "consumed");
    let pkg_status: String =
        sqlx::query_scalar("SELECT status FROM chat.key_packages WHERE key_package_ref=$1")
            .bind(new_ref.to_vec())
            .fetch_one(&pool)
            .await
            .expect("package");
    assert_eq!(pkg_status, "consumed");
    // A fresh pending Welcome for bob; the scenario's prior Welcome is superseded.
    let (new_del_status, new_expires): (String, DateTime<Utc>) =
        sqlx::query_as("SELECT status,expires_at FROM chat.welcome_deliveries WHERE welcome_id=$1")
            .bind(replace_welcome_id)
            .fetch_one(&pool)
            .await
            .expect("new delivery");
    assert_eq!(new_del_status, "pending");
    assert_eq!(new_expires, new_package_not_after);
    let prior_welcome_status: String =
        sqlx::query_scalar("SELECT status FROM chat.welcome_deliveries WHERE welcome_id=$1")
            .bind(scenario_welcome_id)
            .fetch_one(&pool)
            .await
            .expect("prior welcome");
    assert_eq!(prior_welcome_status, "superseded");
    // The re-encryption metadata snapshot for the fulfillment transition.
    let snap_count: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM chat.metadata_snapshots WHERE producing_transition_id=$1",
    )
    .bind(replace_transition)
    .fetch_one(&pool)
    .await
    .expect("snapshot");
    assert_eq!(snap_count, 1);

    // Replay -> head CAS conflict (head already at sv 3), zero residue.
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
        "replace fulfillment replay must conflict on the head CAS, got {replay:?}"
    );
    tx2.rollback().await.expect("rollback replay");
    let after: i64 =
        sqlx::query_scalar("SELECT count(*) FROM chat.transitions WHERE conversation_id=$1")
            .bind(conversation_id)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(
        before, after,
        "replace fulfillment replay left zero residue"
    );
}

/// Desync negative for the `replace` composition: with the OLD leaf period absent
/// from `ctx.closing_leaf_periods`, the executor must HARD-ERROR (`MissingContext`)
/// rather than silently opening bob's new leaf while leaving the old one active —
/// the exact half-rotation silent-bug this arm guards against. The whole
/// transaction rolls back (zero residue).
#[tokio::test]
async fn leaf_recovery_replace_fulfillment_without_old_leaf_period_is_rejected() {
    let (pool, _db) = setup().await;
    let built = Box::pin(build_replace_fulfillment(&pool)).await;
    let conversation_id = built.conversation_id;
    let plan = built.plan;
    let mut ctx = built.ctx;
    // Drop the OLD leaf period the rotation must close.
    ctx.closing_leaf_periods.clear();

    let before: i64 =
        sqlx::query_scalar("SELECT count(*) FROM chat.transitions WHERE conversation_id=$1")
            .bind(conversation_id)
            .fetch_one(&pool)
            .await
            .unwrap();
    let mut tx = pool
        .begin()
        .await
        .expect("begin rejected replace fulfillment");
    let result = apply_conversation_persistence_plan(&mut tx, &plan, &ctx).await;
    assert!(
        matches!(result, Err(ExecutorError::MissingContext(_))),
        "replace fulfillment without the old leaf period must hard-error, got {result:?}"
    );
    tx.rollback().await.expect("rollback rejected replace");
    let after: i64 =
        sqlx::query_scalar("SELECT count(*) FROM chat.transitions WHERE conversation_id=$1")
            .bind(conversation_id)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(
        before, after,
        "rejected replace fulfillment left zero residue"
    );
}

#[tokio::test]
async fn generic_commit_supersedes_prior_open_recovery_request() {
    let (pool, _db) = setup().await;
    let manifest = corpus_manifest();
    let scenario = run_fulfillment_scenario(&pool).await;
    let fixture = &scenario.fixture;
    let conversation_id = scenario.conversation_id;
    let prior = &scenario.fulfillment_state; // sv 2, epoch 1.

    // 1. Open a REPLACE leaf-recovery request by alice, bound to the fulfillment
    //    coordinate (sv 2). Seed alice's key package.
    let alice_leaf_period: Uuid = sqlx::query_scalar(
        "SELECT leaf_period_id FROM chat.member_devices WHERE conversation_id=$1 AND user_did=$2 AND active",
    )
    .bind(conversation_id)
    .bind(&fixture.alice_did)
    .fetch_one(&pool)
    .await
    .expect("alice leaf period");
    let req_ref = random_ref32();
    let req_pkg_not_after = seed_key_package(
        &pool,
        &fixture.alice_did,
        fixture.alice_device,
        &fixture.alice_key_id,
        &req_ref,
    )
    .await;
    let req_pkg_not_after_ts =
        ServerTimestamp::from_unix_millis_for_test(req_pkg_not_after.timestamp_millis()).unwrap();
    let req_received = ServerTimestamp::from_unix_millis_for_test(
        manifest.evaluation_unix_seconds as i64 * 1_000 + 5_000,
    )
    .unwrap();
    let request_id = Uuid::new_v4();
    let req_evidence = RequestEvidence::for_test(
        RequestEntryKind::LeafRecoveryRequest,
        4,
        *request_id.as_bytes(),
        fixture.alice_id.clone(),
        *conversation_id.as_bytes(),
        req_received,
        0xC1,
    )
    .unwrap();
    let req_planned = plan_leaf_recovery_request(
        prior,
        LeafRecoveryRequestCommand {
            actor: fixture.alice_id.clone(),
            recovery_request_id: *request_id.as_bytes(),
            kind: LeafRecoveryKind::Replace,
            key_package_ref: req_ref,
            received_at: req_received,
            package_not_after: req_pkg_not_after_ts,
            evidence: req_evidence,
        },
    )
    .expect("valid leaf recovery request plan");
    let request_state = req_planned.resulting_state().clone();
    let req_head = ConversationHeadCasBinding::for_test_internal(
        *conversation_id.as_bytes(),
        *prior.coordinate(),
        4,
        req_received,
    );
    let req_plan = persistence_plan_for_test(req_planned, req_head);
    let req_applied_at = clock_now(&pool).await;
    let req_transcript = vec![0xC1_u8; 16];
    let req_pred = device_event_predecessor(&pool, &fixture.alice_did, fixture.alice_device).await;
    let req_ctx = ExecutionContext {
        protocol_instance_id: fixture.protocol_instance_id,
        applied_at: req_applied_at,
        actor: ExecutionActor {
            user_did: fixture.alice_did.clone(),
            device_id: fixture.alice_device,
            key_id: fixture.alice_key_id.clone(),
            auth_generation: 1,
            role: TransitionActorRole::Admin,
            device_status: "active".to_owned(),
        },
        entry: ControlEntryContent {
            entry_id: Uuid::new_v4(),
            entry_kind: "blue.catbird.chat.defs#applicationEntry".to_owned(),
            accepted_payload_bytes: vec![0xC1_u8; 8],
            accepted_payload_sha256: Sha256::digest([0xC1_u8; 8]).to_vec(),
            signed_request_bytes: req_transcript.clone(),
            unsigned_projection_bytes: vec![0xC1_u8; 8],
            signing_transcript_bytes: req_transcript.clone(),
            request_digest: Sha256::digest(&req_transcript).to_vec(),
            signature: vec![0xC1_u8; 64],
            server_fields_bytes: vec![0xC1_u8; 8],
            outer_entry_fingerprint: vec![0xC1_u8; 32],
        },
        spine: SpineArtifacts {
            public_snapshot_bytes: vec![],
            public_snapshot_sha256: vec![],
            tree_summary_bytes: vec![],
            tree_summary_sha256: vec![],
            leaf_count: 2,
            genesis_group_info_bytes: vec![],
            genesis_group_info_sha256: vec![],
        },
        opened_leaves: vec![],
        metadata_author: None,
        participant_period_ids: vec![],
        leaf_period_ids: vec![],
        entry_recipients: vec![],
        events: vec![EventFanout {
            event_id: Uuid::new_v4(),
            event_kind: EventKind::ConversationChanged,
            payload_bytes: vec![0xC1_u8; 8],
            recipients: vec![(
                fixture.alice_id.clone(),
                EventEntitlementKind::Participant,
                req_pred,
            )],
            outbox: vec![(Uuid::new_v4(), OutboxWorkKind::Stream)],
        }],
        closing_leaf_periods: vec![],
        closing_participant_periods: vec![],
        reset_request_row: None,
        recovery_open: Some(RecoveryOpenContext {
            participant_period_id: None,
            package_not_after: req_pkg_not_after,
            replaced_leaf_period_id: Some(alice_leaf_period),
        }),
        welcome_expiry: None,
        welcome_response: None,
        welcome_dispositions: vec![],
    };
    {
        let mut tx = pool.begin().await.expect("begin request");
        apply_conversation_persistence_plan(&mut tx, &req_plan, &req_ctx)
            .await
            .expect("recovery request applies");
        tx.commit().await.expect("recovery request COMMIT");
    }
    // The request is OPEN, its package RESERVED before the commit.
    let pre: (String, String) = sqlx::query_as(
        "SELECT (SELECT status FROM chat.leaf_recovery_requests WHERE recovery_request_id=$1), \
                (SELECT status FROM chat.key_packages WHERE key_package_ref=$2)",
    )
    .bind(request_id)
    .bind(req_ref.to_vec())
    .fetch_one(&pool)
    .await
    .expect("pre state");
    assert_eq!((pre.0.as_str(), pre.1.as_str()), ("open", "reserved"));

    // 2. Generic commit on the request state (sv 2 -> 3) — supersedes the open
    //    request + its reservation + package, AND the fulfillment's pending welcome.
    validate_public_commit(
        &corpus_file("commit-generic-public.mls"),
        MAX_PUBLIC_MESSAGE_WIRE_BYTES,
    )
    .expect("generic commit parses");
    let successor_coord = PublicGroupSnapshotCoordinate::new(
        *conversation_id.as_bytes(),
        manifest.chain.generation,
        request_state.coordinate().state_version() + 1,
        *request_state.coordinate().group_id(),
        request_state.coordinate().epoch() + 1,
        [0xB1_u8; 32],
        [0xB2_u8; 32],
        PublicGroupSnapshotLifecycle::Active,
    );
    let commit = chat_protocol::public_state::VerifiedCommitPublicState::for_test_generic(
        request_state.public_state(),
        successor_coord,
        0,
    )
    .expect("synthetic zero-proposal commit");
    let commit_transition = Uuid::new_v4();
    let commit_entry = Uuid::new_v4();
    let commit_received = ServerTimestamp::from_unix_millis_for_test(
        manifest.evaluation_unix_seconds as i64 * 1_000 + 6_000,
    )
    .unwrap();
    let alice_key_id_bytes: [u8; 32] = Sha256::digest(&scenario.alice_sig_key).into();
    let reencryption = MetadataSnapshotBinding::for_test_creation(
        *conversation_id.as_bytes(),
        0,
        successor_coord.epoch(),
        *successor_coord.group_context_hash(),
        fixture.creation_transition_id,
        1,
        fixture.alice_id.clone(),
        alice_key_id_bytes,
        scenario.alice_sig_key.clone().try_into().unwrap(),
        1,
        1,
        [0xB3_u8; 12],
        vec![0xB4_u8; 48],
    );
    let commit_evidence = TransitionEvidence::for_test_commit_with_metadata(
        4,
        *commit_transition.as_bytes(),
        [0x1B_u8; 32],
        commit_received,
        *request_state.coordinate(),
        successor_coord,
        reencryption,
    )
    .unwrap();
    let planned = plan_commit(
        &request_state,
        CommitCommand {
            actor: fixture.alice_id.clone(),
            transition: commit_evidence,
            commit,
        },
    )
    .expect("valid generic commit plan");
    let head_cas = ConversationHeadCasBinding::for_test_edge(
        *conversation_id.as_bytes(),
        *commit_entry.as_bytes(),
        *request_state.coordinate(),
        4,
        commit_received,
    );
    let plan = persistence_plan_for_test(planned, head_cas);

    let applied_at = clock_now(&pool).await;
    let alice_pred =
        device_event_predecessor(&pool, &fixture.alice_did, fixture.alice_device).await;
    let bob_device = Uuid::from_bytes(*scenario.bob_id.device_id());
    let bob_pred = device_event_predecessor(&pool, &scenario.bob_did, bob_device).await;
    let commit_transcript = vec![0xB5_u8; 12];
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
            entry_id: commit_entry,
            entry_kind: "blue.catbird.chat.defs#commitEntry".to_owned(),
            accepted_payload_bytes: vec![0xB6_u8; 12],
            accepted_payload_sha256: Sha256::digest([0xB6_u8; 12]).to_vec(),
            signed_request_bytes: commit_transcript.clone(),
            unsigned_projection_bytes: vec![0xB7_u8; 8],
            signing_transcript_bytes: commit_transcript.clone(),
            request_digest: Sha256::digest(&commit_transcript).to_vec(),
            signature: vec![0xB8_u8; 64],
            server_fields_bytes: vec![0xB9_u8; 8],
            outer_entry_fingerprint: vec![0x1B_u8; 32],
        },
        spine: SpineArtifacts {
            public_snapshot_bytes: vec![0xBA_u8; 16],
            public_snapshot_sha256: Sha256::digest([0xBA_u8; 16]).to_vec(),
            tree_summary_bytes: vec![0xBB_u8; 16],
            tree_summary_sha256: Sha256::digest([0xBB_u8; 16]).to_vec(),
            leaf_count: 2,
            genesis_group_info_bytes: vec![],
            genesis_group_info_sha256: vec![],
        },
        opened_leaves: vec![],
        metadata_author: Some(MetadataAuthorColumns {
            author_role: "admin".to_owned(),
            author_device_status: "active".to_owned(),
            author_public_key: scenario.alice_sig_key.clone(),
            author_key_id: fixture.alice_key_id.clone(),
            metadata_snapshot_id: Uuid::new_v4(),
        }),
        participant_period_ids: vec![],
        leaf_period_ids: vec![],
        entry_recipients: entry_audience(
            &fixture.alice_id,
            &fixture.alice_did,
            &scenario.bob_id,
            &scenario.bob_did,
        ),
        events: vec![EventFanout {
            event_id: Uuid::new_v4(),
            event_kind: EventKind::ConversationChanged,
            payload_bytes: vec![0xBC_u8; 8],
            recipients: vec![(
                fixture.alice_id.clone(),
                EventEntitlementKind::Participant,
                alice_pred,
            )],
            outbox: vec![(Uuid::new_v4(), OutboxWorkKind::Stream)],
        }],
        closing_leaf_periods: vec![],
        closing_participant_periods: vec![],
        reset_request_row: None,
        recovery_open: None,
        welcome_expiry: None,
        welcome_response: None,
        welcome_dispositions: vec![WelcomeDispositionInput {
            welcome_id: scenario.welcome_id,
            event: EventFanout {
                event_id: Uuid::new_v4(),
                event_kind: EventKind::WelcomeDisposition,
                payload_bytes: vec![0xBD_u8; 8],
                recipients: vec![(
                    scenario.bob_id.clone(),
                    EventEntitlementKind::Welcome,
                    bob_pred,
                )],
                outbox: vec![(Uuid::new_v4(), OutboxWorkKind::Stream)],
            },
        }],
    };

    let mut tx = pool.begin().await.expect("begin generic commit");
    apply_conversation_persistence_plan(&mut tx, &plan, &ctx)
        .await
        .expect("generic commit with supersession applies");
    tx.commit()
        .await
        .expect("generic commit COMMIT past all deferred triggers");

    // The superseded request + released reservation + re-available package.
    let (req_status, res_status, pkg_status): (String, String, String) = sqlx::query_as(
        "SELECT (SELECT status FROM chat.leaf_recovery_requests WHERE recovery_request_id=$1), \
                (SELECT status FROM chat.key_package_reservations WHERE recovery_request_id=$1), \
                (SELECT status FROM chat.key_packages WHERE key_package_ref=$2)",
    )
    .bind(request_id)
    .bind(req_ref.to_vec())
    .fetch_one(&pool)
    .await
    .expect("superseded state");
    assert_eq!(
        (
            req_status.as_str(),
            res_status.as_str(),
            pkg_status.as_str()
        ),
        ("superseded", "released", "available")
    );
    // The superseding transition is recorded on the request.
    let terminal_tid: Option<Uuid> = sqlx::query_scalar(
        "SELECT terminal_transition_id FROM chat.leaf_recovery_requests WHERE recovery_request_id=$1",
    )
    .bind(request_id)
    .fetch_one(&pool)
    .await
    .expect("terminal transition");
    assert_eq!(terminal_tid, Some(commit_transition));
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
