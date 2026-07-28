//! Shared executor-seed harness: the frozen-corpus creation -> acceptance ->
//! leaf-recovery fulfillment graph builders extracted from
//! `tests/chat_protocol_executor.rs` so populated-domain live tests in other
//! integration crates (welcome, inventory) can seed a coherent pending-Welcome /
//! recovery-work / conversation graph.
//!
//! This file is `#[path]`-included per consumer (NOT declared in `common/mod.rs`),
//! so each consuming test crate provides its own `mod chat_protocol { .. }`
//! (`include!` of the production modules), `mod model/transcript/validation`, and
//! `mod common`. The builders reference `crate::chat_protocol::*` so they unify
//! with the consumer's own included module types (no cross-crate type drift).

#![allow(dead_code, unused_imports, clippy::too_many_arguments)]

use std::{fs, path::PathBuf};

use chrono::{DateTime, Duration, Utc};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use sqlx::postgres::PgPoolOptions;
use sqlx::PgPool;
use tokio::sync::Barrier;
use uuid::Uuid;

use crate::chat_protocol::public_state::{verify_recovery_welcome, ActivePublicState};
use crate::chat_protocol::repository::delivery::WelcomeRejectionReason;
use crate::chat_protocol::repository::delivery::{
    append_entry_at, AppendEntry, DeliveryRepositoryError, EntryEntitlementKind,
    EventEntitlementKind, EventKind, OutboxWorkKind,
};
use crate::chat_protocol::repository::transition::ResetReason;
use crate::chat_protocol::repository::transition::{
    cas_conversation_head, cas_generation_state_version, supersede_generation, ConversationHeadCas,
    ConversationHeadClose, GenerationStateVersionCas, GenerationSupersede, TransitionActorRole,
    TransitionRepositoryError,
};
use crate::chat_protocol::snapshot::{PublicGroupSnapshotCoordinate, PublicGroupSnapshotLifecycle};
use crate::chat_protocol::state_machine::{
    apply_conversation_persistence_plan_unscoped_for_test,
    apply_device_revocation_batch_unscoped_for_test, device_revocation_plan_for_test,
    persistence_plan_for_test, plan_accept_conversation, plan_close, plan_commit, plan_creation,
    plan_device_revocation, plan_leaf_recovery_cancellation, plan_leaf_recovery_fulfillment,
    plan_leaf_recovery_request, plan_leave_cancellation, plan_leave_fulfillment,
    plan_leave_request, plan_policy, plan_reset_activation, plan_reset_request,
    plan_welcome_expiry_for_test, plan_welcome_response_for_test, plan_zero_leaf_leave,
    AcceptConversation, CloseConversation, CommitCommand, ControlEntryContent,
    ConversationHeadCasBinding, ConversationKind, ConversationState, CreationCommand,
    CreationDecision, DeviceIdentity, DeviceRevocationBatchPersistencePlan,
    DeviceRevocationEvidence, EventFanout, ExecutionActor, ExecutionAuthority, ExecutionContext,
    ExecutorError, LeafPersistenceColumns, LeafRecoveryCancellation, LeafRecoveryFulfillment,
    LeafRecoveryKind, LeafRecoveryRequestCommand, LeaveCancellation, LeaveFulfillment,
    LeaveRequestCommand, LockedRegistrationProjection, MetadataAuthorColumns,
    MetadataSnapshotBinding, PrincipalId, RecoveryOpenContext, RequestEntryKind, RequestEvidence,
    ResetActivation, ResetRequestCommand, ResetRequestRow, RevocationPackageCasBinding,
    RevocationTargetCasBinding, ServerTimestamp, SpineArtifacts, TransitionEvidence,
    WelcomeDispositionInput, WelcomeExpiryContext, WelcomeRejectionWork, WelcomeResponseContext,
    WelcomeStatus, ZeroLeafLeave,
};
use crate::chat_protocol::validation::ed25519_key_id;
#[path = "frozen_public_state.rs"]
mod frozen_public_state;

/// Drops a uniquely-named per-run executor database (best-effort) when it falls
/// out of scope. Every executor test binds this guard so its private DB is torn
/// down at the end; a leaked `chat_exec_<uuid>` DB from a crashed run is
/// acceptable and identifiable by name. A fresh DB per run makes the whole
/// executor suite perfectly rerun-idempotent — no cross-run accumulation of the
/// fixed corpus creator's pending invitations (the shared-DB quota trip), and no
/// global `key_package_ref` / corpus-identity collisions — which is exactly what
/// unblocks the fixed-corpus-identity fulfillment test. The shared-DB harness
/// (`crate::common::chat_protocol::setup_chat_protocol_db`, used by every OTHER test
/// file) is left untouched.
pub struct FreshDbGuard {
    pub maintenance_url: String,
    pub db_name: String,
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
pub fn maintenance_url_from_env() -> String {
    let database_url = std::env::var("TEST_DATABASE_URL")
        .expect("TEST_DATABASE_URL must name the loopback clean-chat test database");
    crate::common::chat_protocol::validate_chat_protocol_database_url(Some(&database_url))
        .expect("unsafe TEST_DATABASE_URL for the fresh-DB executor harness");
    let mut parsed = url::Url::parse(&database_url).expect("valid TEST_DATABASE_URL");
    parsed.set_path("/postgres");
    parsed.into()
}

pub async fn fresh_executor_db() -> (PgPool, FreshDbGuard) {
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

pub async fn setup() -> (PgPool, FreshDbGuard) {
    fresh_executor_db().await
}

pub async fn clock_now(pool: &PgPool) -> DateTime<Utc> {
    sqlx::query_scalar("SELECT clock_timestamp()")
        .fetch_one(pool)
        .await
        .expect("sample trusted database clock")
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CorpusManifest {
    pub evaluation_unix_seconds: u64,
    pub identifiers: CorpusIdentifiers,
    pub identity: CorpusIdentity,
    pub chain: CorpusChain,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CorpusIdentifiers {
    pub conversation_id_hex: String,
}
#[derive(Deserialize)]
pub struct CorpusIdentity {
    pub alice: CorpusActor,
    pub bob: CorpusActor,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CorpusActor {
    pub actor_did: String,
    pub device_id: String,
    pub credential_identity: String,
    pub signature_public_key_hex: String,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CorpusChain {
    pub generation: u64,
    pub genesis_state_version: u64,
    pub genesis_epoch: u64,
    pub genesis_group_context_hash_hex: String,
    pub genesis_confirmation_tag_hex: String,
    pub group_id_hex: String,
    // Committed (post-ADD-commit) coordinate + the recovered inner key-package ref
    // — used only by the fulfillment scenario.
    pub committed_epoch: u64,
    pub committed_group_context_hash_hex: String,
    pub committed_confirmation_tag_hex: String,
    pub inner_key_package_ref_hex: String,
}

pub fn corpus_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../docs/generated-artifacts/mls-chat-v1/crypto-wire")
}
pub fn corpus_file(name: &str) -> Vec<u8> {
    fs::read(corpus_dir().join(name)).expect("read frozen crypto-wire corpus")
}
pub fn corpus_manifest() -> CorpusManifest {
    serde_json::from_slice(&corpus_file("manifest.json")).expect("parse frozen manifest")
}
pub fn hex_array<const N: usize>(value: &str) -> [u8; N] {
    hex::decode(value)
        .expect("valid fixture hex")
        .try_into()
        .unwrap_or_else(|_| panic!("expected {N}-byte fixture"))
}
pub fn uuid_bytes(value: &str) -> [u8; 16] {
    *Uuid::parse_str(value).expect("fixture UUID").as_bytes()
}
pub fn uuid_v4_bytes(byte: u8) -> [u8; 16] {
    let mut value = [byte; 16];
    value[6] = 0x40 | (byte & 0x0f);
    value[8] = 0x80 | (byte & 0x3f);
    value
}

pub fn genesis_coordinate(manifest: &CorpusManifest) -> PublicGroupSnapshotCoordinate {
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

pub fn coordinate_with_conversation(
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

pub fn alice(manifest: &CorpusManifest) -> DeviceIdentity {
    DeviceIdentity::new(
        PrincipalId::new(manifest.identity.alice.actor_did.as_bytes().to_vec()).unwrap(),
        uuid_bytes(&manifest.identity.alice.device_id),
    )
    .unwrap()
}
pub fn verified_genesis(manifest: &CorpusManifest) -> ActivePublicState {
    let state = frozen_public_state::restore_genesis();
    assert_eq!(state.coordinate(), &genesis_coordinate(manifest));
    state
}

/// Idempotently seed a principal + active device + device-key row (committed).
pub async fn seed_actor(
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

pub async fn seed_protocol_instance(pool: &PgPool) -> Uuid {
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
pub struct CreationApply {
    pub plan: crate::chat_protocol::state_machine::ConversationPersistencePlan,
    pub ctx: ExecutionContext,
    pub conversation_id: Uuid,
    pub alice_did: String,
    pub alice_device: Uuid,
    // Carried for the follow-on policy edge.
    pub state: crate::chat_protocol::state_machine::ConversationState,
    pub alice_id: DeviceIdentity,
    pub alice_key_id: String,
    pub bob_id: DeviceIdentity,
    pub bob_did: String,
    pub bob_key_id: String,
    pub coordinate: PublicGroupSnapshotCoordinate,
    pub protocol_instance_id: Uuid,
    /// The creation transition id — the invitation provenance a later acceptance
    /// must echo (bob's pending invitation was minted by this transition).
    pub creation_transition_id: [u8; 16],
}

/// Creation with an explicit pending invitee — the fulfillment scenario passes the
/// FIXED corpus bob (whose credential the frozen ADD commit adds); on the fresh-DB
/// harness a fixed identity no longer collides across runs.
pub async fn build_creation_with_invitee(
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
        authority: ExecutionAuthority::ControlEntry(ControlEntryContent {
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
        }),
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

pub fn entry_audience(
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
pub async fn event_audience(
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

pub async fn device_event_predecessor(pool: &PgPool, did: &str, device: Uuid) -> Option<i64> {
    sqlx::query_scalar(
        "SELECT max(event_position) FROM chat.event_recipients WHERE user_did=$1 AND device_id=$2",
    )
    .bind(did)
    .bind(device)
    .fetch_one(pool)
    .await
    .expect("predecessor")
}

/// Seed one `available` key package owned by `(owner_did, owner_device)` and
/// return its exact `not_after` (the value the reservation's
/// `expires_at = LEAST(created_at + 5 min, not_after)` mapping check needs).
pub async fn seed_key_package(
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

/// The acceptance `ExecutionContext` for an invitee accepting (used by the
/// fulfillment scenario). Actor = the invitee (member/active), audience = the two
/// current devices, recovery_open bound to the invitee's participant period.
#[allow(clippy::too_many_arguments)]
pub async fn acceptance_ctx(
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
        authority: ExecutionAuthority::ControlEntry(ControlEntryContent {
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
        }),
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

pub fn bob_corpus(manifest: &CorpusManifest) -> DeviceIdentity {
    DeviceIdentity::new(
        PrincipalId::new(manifest.identity.bob.actor_did.as_bytes().to_vec()).unwrap(),
        uuid_bytes(&manifest.identity.bob.device_id),
    )
    .unwrap()
}

/// The committed (post-ADD-commit) coordinate: same generation/group_id, the
/// committed epoch/hash/tag, at `state_version`.
pub fn committed_coordinate(
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

/// Restore the frozen corpus ADD snapshot against the accepted state's exact
/// manifest-bound genesis snapshot, producing the verified committed public
/// state the fulfillment consumes.
pub fn verified_add_commit(
    state: &crate::chat_protocol::state_machine::ConversationState,
    manifest: &CorpusManifest,
) -> crate::chat_protocol::public_state::VerifiedCommitPublicState {
    let sender_leaf_index = state
        .leaf(&alice(manifest))
        .expect("Alice sender leaf")
        .leaf_index();
    frozen_public_state::restore_add_commit(state.public_state(), sender_leaf_index)
}

/// A committed fulfillment scenario (creation → acceptance → fulfillment, all
/// COMMITTED on a fresh DB) at coordinate sv 2 / epoch 1 with alice + bob leaves —
/// the prior state for the epoch-changing generic-commit / remove follow-ons.
pub struct FulfillmentScenario {
    pub fulfillment_state: crate::chat_protocol::state_machine::ConversationState,
    pub fixture: CreationApply,
    pub conversation_id: Uuid,
    pub bob_id: DeviceIdentity,
    pub bob_did: String,
    pub coordinate: PublicGroupSnapshotCoordinate,
    pub alice_sig_key: Vec<u8>,
    pub fulfill_transition: Uuid,
    pub welcome_id: Uuid,
    pub recovery_request_id: Uuid,
    pub corpus_ref: [u8; 32],
    pub event_positions: Vec<i64>,
}

/// The uncommitted leaf-recovery fulfillment plan + ctx (create + acceptance are
/// already COMMITTED). Extracted so the reconciliation negative test can apply a
/// MUTATED plan against the same accepted state without run_fulfillment_scenario
/// committing it first.
pub struct BuiltFulfillment {
    pub plan: crate::chat_protocol::state_machine::ConversationPersistencePlan,
    pub ctx: ExecutionContext,
    pub fixture: CreationApply,
    pub conversation_id: Uuid,
    pub bob_id: DeviceIdentity,
    pub bob_did: String,
    pub alice_sig_key: Vec<u8>,
    pub fulfill_transition: Uuid,
    pub welcome_id: Uuid,
    pub recovery_request_id: Uuid,
    pub corpus_ref: [u8; 32],
    pub fulfillment_state: crate::chat_protocol::state_machine::ConversationState,
}

pub async fn build_fulfillment(pool: &PgPool) -> BuiltFulfillment {
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
        apply_conversation_persistence_plan_unscoped_for_test(&mut tx, &fixture.plan, &fixture.ctx)
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
        apply_conversation_persistence_plan_unscoped_for_test(&mut tx, &accept_plan, &accept_ctx)
            .await
            .expect("acceptance applies");
        tx.commit().await.expect("acceptance COMMIT");
    }

    // 3. Build the fulfillment: restore the corpus ADD snapshot and bind the
    //    Welcome against the accepted state, then plan the fulfillment.
    let commit = verified_add_commit(&accepted_state, &manifest);
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
        authority: ExecutionAuthority::ControlEntry(ControlEntryContent {
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
        }),
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
pub async fn run_fulfillment_scenario(pool: &PgPool) -> FulfillmentScenario {
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
    let applied = apply_conversation_persistence_plan_unscoped_for_test(&mut tx, &plan, &ctx)
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
    let replay = apply_conversation_persistence_plan_unscoped_for_test(&mut tx2, &plan, &ctx).await;
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
