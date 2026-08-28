//! Live S3 lifecycle fixture (Server Task 2): proves the production clean-chat
//! blob-store lifecycle against a disposable local MinIO container.
//!
//! Fetch side: the production HTTP handler (`blue.catbird.chat.getBlob`) wired
//! to a REAL S3-backed `BlobStore` (`BlobStore::for_s3_fixture`, sharing the
//! exact `put_for_blob` / `get_authorized` / `delete` code paths of production
//! `BlobStore::new()`). Nest/DPoP admission, `authorize_blob_read`, the one-use
//! capability, `consume_authorized_blob_fetch`, and the bounded S3 fetch all run
//! inside the library exactly as in production. The repository-layer cases that
//! need direct capability handles (replay, membership fence) drive the production
//! repository source through the established `include!` harness. The bucket
//! follows Server T1's DB-namespaced route-test pattern
//! (`catbird-blobs-route-test-<dbname>`); every object lives under the single
//! disposable prefix `clean-chat-rc-<timestamp>-<uuid>/`, which the cleanup test
//! lists, verifies, and deletes.
//!
//! The fixture refuses non-local S3 endpoints and records endpoint, region,
//! bucket, and prefix as sanitized evidence.
//!
//! These tests require a running disposable MinIO fixture and the seeded
//! Postgres test database; like the sibling
//! `s3_fixture_upload_read_and_object_swap_target` they are `#[ignore]`d for the
//! default suite and run explicitly:
//!
//! ```text
//! CHAT_OPERATION_CLAIM_ACTIVATION_APPROVED=handlers-and-legacy-apis-sealed \
//! TEST_DATABASE_URL=postgresql://127.0.0.1:5432/catbird_chat_protocol_test_20260722 \
//! S3_ENDPOINT=http://127.0.0.1:9000 S3_ACCESS_KEY=minioadmin S3_SECRET_KEY=minioadmin \
//! S3_REGION=us-east-1 \
//! cargo test --test chat_protocol_s3_lifecycle s3_ -- --ignored --test-threads=1 --nocapture
//! ```
//!
//! (`s3_` filters to this file's lifecycle tests; the included production
//! repository module contributes its own ignored drift fixtures that require a
//! separate `TEST_BLOB_ID` fixture.)
//!
//! The fixture container (disposable, non-production):
//!
//! ```text
//! docker run -d --name mls-v2-minio-<initials> -p 9000:9000 -p 9001:9001 \
//!   -e MINIO_ROOT_USER=minioadmin -e MINIO_ROOT_PASSWORD=minioadmin \
//!   quay.io/minio/minio server /data --console-address :9001
//! ```
//!
//! Nothing here touches production; the database is the shared disposable
//! `catbird_chat_protocol_test_20260722` and fixture rows use random UUIDs/DIDs.

#![allow(dead_code)]

mod common;
use common::http_acceptance as http;

mod chat_protocol {
    pub mod dpop {
        pub struct VerifiedReadAdmission;
    }
    pub mod read_authority {
        pub enum OrdinaryReadEndpoint {}
        pub enum ReadAuthorityError {
            Storage,
        }
        pub struct Attempt;
        pub struct LockedDevice;
        pub struct Admission;
        impl Admission {
            pub fn into_attempt(self) -> Attempt {
                Attempt
            }
        }
        pub fn into_single_read_admission(
            _admission: super::dpop::VerifiedReadAdmission,
            _endpoint: OrdinaryReadEndpoint,
        ) -> Result<Admission, ()> {
            Err(())
        }
        pub async fn lock_read_device_authority_once(
            _transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
            _attempt: Attempt,
        ) -> Result<LockedDevice, ReadAuthorityError> {
            Err(ReadAuthorityError::Storage)
        }
        impl LockedDevice {
            pub fn user_did(&self) -> &str {
                ""
            }
            pub fn device_id(&self) -> uuid::Uuid {
                uuid::Uuid::nil()
            }
            pub fn auth_generation(&self) -> i64 {
                0
            }
        }
    }
    pub mod snapshot {
        #[derive(PartialEq, Eq)]
        pub enum PublicGroupSnapshotLifecycle {
            Active,
        }
    }
    pub mod state_machine {
        #[derive(PartialEq, Eq)]
        pub enum WelcomeStatus {
            Pending,
            Acknowledged,
            Rejected,
            Expired,
        }
        use super::snapshot::PublicGroupSnapshotLifecycle;
        pub struct Principal;
        static PRINCIPAL: Principal = Principal;
        impl Principal {
            pub fn as_bytes(&self) -> &'static [u8] {
                &[]
            }
        }
        pub struct Recipient;
        static RECIPIENT: Recipient = Recipient;
        impl Recipient {
            pub fn principal(&self) -> &'static Principal {
                &PRINCIPAL
            }
            pub fn device_id(&self) -> &'static [u8; 16] {
                &[0; 16]
            }
        }
        pub struct Coordinate;
        impl Coordinate {
            pub fn lifecycle(&self) -> PublicGroupSnapshotLifecycle {
                PublicGroupSnapshotLifecycle::Active
            }
            pub fn generation(&self) -> u64 {
                0
            }
            pub fn state_version(&self) -> u64 {
                0
            }
            pub fn epoch(&self) -> u64 {
                0
            }
            pub fn group_id(&self) -> &[u8] {
                &[]
            }
            pub fn group_context_hash(&self) -> &[u8] {
                &[]
            }
            pub fn confirmation_tag(&self) -> &[u8] {
                &[]
            }
            pub fn conversation_id(&self) -> &[u8; 16] {
                &[0; 16]
            }
        }
        pub struct WelcomeCasBinding;
        impl WelcomeCasBinding {
            pub fn conversation_id(&self) -> &[u8; 16] {
                &[0; 16]
            }
            pub fn recipient(&self) -> &'static Recipient {
                &RECIPIENT
            }
            pub fn expires_at(&self) -> Timestamp {
                Timestamp
            }
            pub fn verify_seal(&self) -> bool {
                false
            }
            pub fn transaction_id(&self) -> &str {
                ""
            }
            pub fn expected_status(&self) -> WelcomeStatus {
                WelcomeStatus::Pending
            }
            pub fn successor_status(&self) -> WelcomeStatus {
                WelcomeStatus::Pending
            }
            pub fn coordinate(&self) -> Coordinate {
                Coordinate
            }
            pub fn transition_seq(&self) -> u64 {
                0
            }
            pub fn welcome_id(&self) -> &[u8; 16] {
                &[0; 16]
            }
            pub fn recovery_request_id(&self) -> &[u8; 16] {
                &[0; 16]
            }
            pub fn opaque_welcome_sha256(&self) -> &[u8; 32] {
                &[0; 32]
            }
            pub fn key_package_ref(&self) -> &[u8] {
                &[]
            }
            pub fn locked_at(&self) -> Timestamp {
                Timestamp
            }
        }
        pub struct WelcomeWork;
        impl WelcomeWork {
            pub fn status(&self) -> WelcomeStatus {
                WelcomeStatus::Expired
            }
            pub fn coordinate(&self) -> Coordinate {
                Coordinate
            }
            pub fn expires_at(&self) -> Timestamp {
                Timestamp
            }
            pub fn welcome_id(&self) -> &[u8; 16] {
                &[0; 16]
            }
            pub fn recovery_request_id(&self) -> &[u8; 16] {
                &[0; 16]
            }
            pub fn transition_seq(&self) -> u64 {
                0
            }
            pub fn sha256(&self) -> &[u8; 32] {
                &[0; 32]
            }
            pub fn recipient(&self) -> &'static Recipient {
                &RECIPIENT
            }
            pub fn key_package_ref(&self) -> &[u8] {
                &[]
            }
        }
        pub struct Timestamp;
        impl Timestamp {
            pub fn unix_millis(&self) -> i64 {
                0
            }
        }
    }
}

mod repository {
    pub(crate) mod blobs {
        include!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/src/chat_protocol/repository/blobs.rs"
        ));
    }
    pub(crate) mod delivery {
        include!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/src/chat_protocol/repository/delivery.rs"
        ));
    }
    // The included blob module's ignored drift fixtures import the canonical
    // transition writer through `super::super::transition`. Keep this harness
    // self-contained: those ignored fixtures are not executed here, while the
    // production library continues to resolve the real transition module.
    pub(crate) mod transition {
        use chrono::{DateTime, Utc};
        use uuid::Uuid;

        #[derive(Debug)]
        pub(crate) struct HarnessTransitionError;

        pub(crate) enum IntervalCloseKind {
            Remove,
        }

        pub(crate) struct ApplicationIntervalClose {
            pub(crate) membership_interval_id: Uuid,
            pub(crate) terminal_seq: i64,
            pub(crate) closing_state_version: i64,
            pub(crate) closing_transition_id: Uuid,
            pub(crate) closing_outer_entry_fingerprint: Vec<u8>,
            pub(crate) closing_kind: IntervalCloseKind,
            pub(crate) closing_leaf_period_id: Uuid,
            pub(crate) removed_at: DateTime<Utc>,
        }

        pub(crate) struct LeafClose {
            pub(crate) leaf_period_id: Uuid,
            pub(crate) removed_state_version: i64,
            pub(crate) removed_transition_id: Uuid,
            pub(crate) removed_seq: i64,
            pub(crate) removed_at: DateTime<Utc>,
        }

        pub(crate) struct NewDeviceRevocation {
            pub(crate) revocation_id: Uuid,
            pub(crate) actor_did: String,
            pub(crate) actor_device_id: Uuid,
            pub(crate) actor_key_id: String,
            pub(crate) actor_auth_generation: i64,
            pub(crate) target_did: String,
            pub(crate) target_device_id: Uuid,
            pub(crate) target_auth_generation: i64,
            pub(crate) accepted_request_bytes: Vec<u8>,
            pub(crate) signing_transcript_bytes: Vec<u8>,
            pub(crate) request_digest: Vec<u8>,
            pub(crate) signature: Vec<u8>,
            pub(crate) signed_at: DateTime<Utc>,
            pub(crate) accepted_at: DateTime<Utc>,
        }

        pub(crate) struct RegistrationRevoke {
            pub(crate) target_did: String,
            pub(crate) target_device_id: Uuid,
            pub(crate) expected_auth_generation: i64,
            pub(crate) revocation_id: Uuid,
            pub(crate) revoked_at: DateTime<Utc>,
        }

        pub(crate) async fn close_application_interval<T>(
            _transaction: &mut T,
            _close: &ApplicationIntervalClose,
        ) -> Result<(), HarnessTransitionError> {
            Ok(())
        }

        pub(crate) async fn close_leaf_period<T>(
            _transaction: &mut T,
            _close: &LeafClose,
        ) -> Result<(), HarnessTransitionError> {
            Ok(())
        }

        pub(crate) async fn insert_device_revocation<T>(
            _transaction: &mut T,
            _revocation: &NewDeviceRevocation,
        ) -> Result<(), HarnessTransitionError> {
            Ok(())
        }

        pub(crate) async fn cas_registration_revoke<T>(
            _transaction: &mut T,
            _revoke: &RegistrationRevoke,
        ) -> Result<(), HarnessTransitionError> {
            Ok(())
        }
    }
}

use std::sync::{Arc, LazyLock};
use std::time::{Duration as StdDuration, Instant as StdInstant};

use aws_sdk_s3::{
    config::{Builder as S3ConfigBuilder, Credentials, Region},
    primitives::ByteStream,
    Client as S3Client,
};
use base64::{
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
    Engine as _,
};
use catbird_server::{
    blob_store::{BlobStore, S3FixtureDeleteProbe},
    handlers::chat::ChatRuntime,
    realtime::SseState,
};
use chrono::{DateTime, Duration, Utc};
use sha2::{Digest, Sha256};
use sqlx::{PgPool, Postgres, Transaction};
use uuid::Uuid;

use repository::blobs::{
    authorize_blob_read, bind_application_blob, complete_upload, prepare_blob,
    AuthorizeBlobReadRequest, AuthorizedBlobFetch, BindingKind, BlobAuthorizationTransaction,
    BlobMediaType, BlobPurpose, BlobRepositoryError, NewBlobBinding, PrepareBlobRequest,
};
use repository::delivery::{
    resolve_application_send, AppendEntry, ApplicationSend, ApplicationSendDisposition,
    ApplicationSendOutcome,
};

// ===========================================================================
// Disposable S3 fixture plumbing.
// ===========================================================================

const MEDIA: BlobMediaType = BlobMediaType::ImagePng;
const MEDIA_STR: &str = "image/png";
const PLAINTEXT_SIZE: i64 = 1_000;
const CIPHERTEXT_SIZE: i64 = PLAINTEXT_SIZE + 16;

/// One shared disposable prefix for the whole fixture run. Printed so the
/// report can record it; the cleanup test lists and deletes exactly this prefix.
fn fixture_endpoint() -> String {
    let endpoint = std::env::var("S3_ENDPOINT").expect("S3_ENDPOINT must be set");
    assert!(
        endpoint.starts_with("http://127.0.0.1:")
            || endpoint.starts_with("http://localhost:")
            || endpoint.starts_with("http://[::1]:"),
        "S3 fixture endpoint must be local and disposable, got {endpoint}"
    );
    endpoint
}

fn fixture_region() -> String {
    let region = std::env::var("S3_REGION").unwrap_or_else(|_| "us-east-1".to_owned());
    assert!(
        region
            .chars()
            .all(|character| character.is_ascii_alphanumeric()
                || matches!(character, '-' | '_' | '.')),
        "S3 fixture region contains unsafe characters"
    );
    region
}

static FIXTURE_PREFIX: LazyLock<String> = LazyLock::new(|| {
    let endpoint = fixture_endpoint();
    let region = fixture_region();
    let bucket = fixture_bucket();
    let timestamp = Utc::now()
        .timestamp_nanos_opt()
        .expect("fixture timestamp in range");
    let prefix = format!("clean-chat-rc-{timestamp}-{}", Uuid::new_v4().simple());
    let prefix = format!("{prefix}/");
    println!(
        "S3_FIXTURE_EVIDENCE endpoint={endpoint} region={region} bucket={bucket} prefix={prefix}"
    );
    prefix
});

fn fixture_bucket() -> String {
    let suffix = std::env::var("TEST_DATABASE_URL")
        .expect("TEST_DATABASE_URL must be set")
        .rsplit('/')
        .next()
        .map(str::to_owned)
        .unwrap_or_else(|| "default".to_owned());
    let suffix: String = suffix
        .chars()
        .map(|character| {
            if character.is_ascii_lowercase() || character.is_ascii_digit() || character == '-' {
                character
            } else {
                '-'
            }
        })
        .collect();
    format!("catbird-blobs-route-test-{suffix}")
}

async fn fixture_store() -> BlobStore {
    BlobStore::for_s3_fixture(&FIXTURE_PREFIX).await
}

/// A raw S3 client for direct object inspection/listing (the production
/// `BlobStore` deliberately exposes no listing or raw-key surface).
fn raw_s3_client() -> S3Client {
    let endpoint = fixture_endpoint();
    let access_key = std::env::var("S3_ACCESS_KEY").expect("S3_ACCESS_KEY must be set");
    let secret_key = std::env::var("S3_SECRET_KEY").expect("S3_SECRET_KEY must be set");
    let region = fixture_region();
    let config = S3ConfigBuilder::new()
        .behavior_version_latest()
        .endpoint_url(&endpoint)
        .region(Region::new(region))
        .credentials_provider(Credentials::new(
            &access_key,
            &secret_key,
            None,
            None,
            "env",
        ))
        .force_path_style(true)
        .build();
    S3Client::from_conf(config)
}

async fn object_exists(client: &S3Client, key: &str) -> bool {
    let bucket = fixture_bucket();
    client
        .head_object()
        .bucket(&bucket)
        .key(key)
        .send()
        .await
        .is_ok()
}

async fn list_prefix(client: &S3Client, prefix: &str) -> Vec<String> {
    let bucket = fixture_bucket();
    let mut keys = Vec::new();
    let mut token: Option<String> = None;
    loop {
        let mut request = client.list_objects_v2().bucket(&bucket).prefix(prefix);
        if let Some(token) = &token {
            request = request.continuation_token(token);
        }
        let response = request.send().await.expect("list fixture prefix");
        for object in response.contents() {
            if let Some(key) = object.key() {
                keys.push(key.to_owned());
            }
        }
        if response.is_truncated() == Some(true) {
            token = response.next_continuation_token().map(str::to_owned);
        } else {
            break;
        }
    }
    keys
}

fn fixture_physical_key(cid: &str) -> String {
    format!("{}{}", *FIXTURE_PREFIX, cid)
}

/// Deterministic ciphertext for the fixture (1000 bytes plaintext + 16 AEAD tag).
fn ciphertext_bytes() -> Vec<u8> {
    vec![0x5A; CIPHERTEXT_SIZE as usize]
}

/// A unique upload-ticket hash per fixture (the shared DB keeps tickets).
fn fresh_ticket_hash() -> Vec<u8> {
    Sha256::digest(Uuid::new_v4().as_bytes()).to_vec()
}

// ===========================================================================
// Repository harness helpers (mirror `chat_protocol_blobs.rs`).
// ===========================================================================

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

fn random_ref() -> Vec<u8> {
    let mut bytes = Uuid::new_v4().as_bytes().to_vec();
    bytes.extend_from_slice(Uuid::new_v4().as_bytes());
    bytes
}

fn deterministic_object_key(blob_id: Uuid, ciphertext_sha256: &[u8]) -> String {
    let hash: [u8; 32] = ciphertext_sha256
        .try_into()
        .expect("ciphertext hash is exactly 32 bytes");
    repository::blobs::derive_blob_cid(blob_id, &hash)
}

async fn clock_now(tx: &mut Transaction<'_, Postgres>) -> DateTime<Utc> {
    sqlx::query_scalar("SELECT clock_timestamp()")
        .fetch_one(&mut **tx)
        .await
        .expect("sample trusted database clock")
}

/// Seed a principal + active device + device key INSIDE the caller's transaction.
async fn seed_owner_tx(tx: &mut Transaction<'_, Postgres>, user_did: &str) -> (Uuid, String) {
    let now = clock_now(tx).await;
    sqlx::query("INSERT INTO chat.principals(user_did,created_at) VALUES($1,$2)")
        .bind(user_did)
        .bind(now)
        .execute(&mut **tx)
        .await
        .expect("insert principal");
    let device_id = Uuid::new_v4();
    let public_key = random_ref();
    let key_id: String = sqlx::query_scalar("SELECT chat.ed25519_key_id($1)")
        .bind(&public_key)
        .fetch_one(&mut **tx)
        .await
        .expect("derive key id");
    sqlx::query(
        "INSERT INTO chat.devices(user_did,device_id,device_name,status,dpop_jkt,auth_generation,capabilities,created_at,updated_at) \
         VALUES($1,$2,'device','active',$3,1,chat.protocol_capabilities(),$4,$4)",
    )
    .bind(user_did)
    .bind(device_id)
    .bind(&key_id)
    .bind(now)
    .execute(&mut **tx)
    .await
    .expect("insert device");
    sqlx::query(
        "INSERT INTO chat.device_keys(user_did,device_id,key_id,signing_public_key,enrollment_auth_generation,created_at) \
         VALUES($1,$2,$3,$4,1,$5)",
    )
    .bind(user_did)
    .bind(device_id)
    .bind(&key_id)
    .bind(&public_key)
    .bind(now)
    .execute(&mut **tx)
    .await
    .expect("insert device key");
    (device_id, key_id)
}

#[derive(Clone)]
struct CreationGraph {
    conversation_id: Uuid,
    actor_did: String,
    actor_device_id: Uuid,
    actor_key_id: String,
    actor_public_key: Vec<u8>,
    leaf_period_id: Uuid,
    creation_transition_id: Uuid,
    creation_entry_id: Uuid,
    group_id: Vec<u8>,
    group_context_hash: Vec<u8>,
    confirmation_tag: Vec<u8>,
    creation_fingerprint: Vec<u8>,
    accepted_at: DateTime<Utc>,
}

/// Seed a coherent genesis conversation (creator active/admin/sole-leaf, one open
/// application interval at start_seq 1, next_entry_seq=2) INSIDE the caller's
/// transaction. With `existing`, the creator is the given HTTP device (already
/// committed by `http::seed_device`); otherwise a fresh principal+device+key is
/// seeded in the transaction. Mirrors the proven `seed_fixture` graph.
async fn seed_creation_graph_tx(
    tx: &mut Transaction<'_, Postgres>,
    actor_did: &str,
    existing: Option<&http::Device>,
) -> CreationGraph {
    let now = clock_now(tx).await;
    let actor_device_id = existing.map_or_else(Uuid::new_v4, |device| device.device_id);
    let (actor_key_id, actor_public_key): (String, Vec<u8>) = if let Some(device) = existing {
        sqlx::query_as(
            "SELECT key_id, signing_public_key FROM chat.device_keys WHERE user_did = $1 AND device_id = $2",
        )
        .bind(&device.did)
        .bind(device.device_id)
        .fetch_one(&mut **tx)
        .await
        .expect("existing HTTP device key")
    } else {
        let public_key = random_ref();
        let key_id: String = sqlx::query_scalar("SELECT chat.ed25519_key_id($1)")
            .bind(&public_key)
            .fetch_one(&mut **tx)
            .await
            .expect("key id");
        (key_id, public_key)
    };
    if existing.is_none() {
        sqlx::query("INSERT INTO chat.principals(user_did,created_at) VALUES($1,$2)")
            .bind(actor_did)
            .bind(now)
            .execute(&mut **tx)
            .await
            .expect("principal");
        sqlx::query(
            "INSERT INTO chat.devices(user_did,device_id,device_name,status,dpop_jkt,auth_generation,capabilities,created_at,updated_at) \
             VALUES($1,$2,'creator','active',$3,1,chat.protocol_capabilities(),$4,$4)",
        )
        .bind(actor_did)
        .bind(actor_device_id)
        .bind(&actor_key_id)
        .bind(now)
        .execute(&mut **tx)
        .await
        .expect("device");
        sqlx::query(
            "INSERT INTO chat.device_keys(user_did,device_id,key_id,signing_public_key,enrollment_auth_generation,created_at) \
             VALUES($1,$2,$3,$4,1,$5)",
        )
        .bind(actor_did)
        .bind(actor_device_id)
        .bind(&actor_key_id)
        .bind(&actor_public_key)
        .bind(now)
        .execute(&mut **tx)
        .await
        .expect("device key");
    }

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
    let basic_credential = format!("{actor_did}#{actor_device_id}").into_bytes();

    sqlx::query(
        "INSERT INTO chat.conversations(conversation_id,kind,lifecycle,current_generation,current_state_version,next_entry_seq,created_at) VALUES($1,'group','active',0,0,2,$2)",
    ).bind(conversation_id).bind(now).execute(&mut **tx).await.expect("conversation");
    sqlx::query(
        "INSERT INTO chat.generations(conversation_id,generation,group_id,lifecycle,genesis_group_info_bytes,genesis_group_info_sha256,current_state_version,activated_seq,activated_at) VALUES($1,0,$2,'active',$3,$4,0,1,$5)",
    ).bind(conversation_id).bind(&group_id).bind(&group_info).bind(Sha256::digest(&group_info).to_vec()).bind(now).execute(&mut **tx).await.expect("generation");
    sqlx::query(
        r#"INSERT INTO chat.transitions(transition_id,conversation_id,kind,actor_did,actor_device_id,actor_key_id,actor_auth_generation,actor_role,actor_device_status,signed_request_bytes,unsigned_projection_bytes,signing_transcript_bytes,request_digest,signature,next_generation,next_state_version,metadata_snapshot_id,entry_seq,accepted_at) VALUES($1,$2,'creation',$3,$4,$5,1,'admin','active',$6,$7,$8,$9,$10,0,0,$11,1,$12)"#,
    ).bind(creation_transition_id).bind(conversation_id).bind(actor_did).bind(actor_device_id).bind(&actor_key_id).bind(&signed_request).bind(&unsigned_projection).bind(&signing_transcript).bind(&request_digest).bind(&signature).bind(metadata_snapshot_id).bind(now).execute(&mut **tx).await.expect("transition");
    sqlx::query(
        r#"INSERT INTO chat.generation_states(conversation_id,generation,state_version,group_id,epoch,group_context_hash,confirmation_tag,lifecycle,state_kind,producing_transition_id,public_snapshot_bytes,snapshot_sha256,tree_summary_bytes,tree_summary_sha256,leaf_count,created_at) VALUES($1,0,0,$2,0,$3,$4,'active','creation',$5,$6,$7,$8,$9,1,$10)"#,
    ).bind(conversation_id).bind(&group_id).bind(&group_context_hash).bind(&confirmation_tag).bind(creation_transition_id).bind(&snapshot).bind(Sha256::digest(&snapshot).to_vec()).bind(&tree_summary).bind(Sha256::digest(&tree_summary).to_vec()).bind(now).execute(&mut **tx).await.expect("state");
    sqlx::query(
        r#"INSERT INTO chat.participants(participant_period_id,conversation_id,user_did,status,role,role_transition_id,role_changed_at,created_by_did,created_by_device_id,current_membership,created_at) VALUES($1,$2,$3,'active','admin',$4,$5,$3,$6,true,$5)"#,
    ).bind(participant_period_id).bind(conversation_id).bind(actor_did).bind(creation_transition_id).bind(now).bind(actor_device_id).execute(&mut **tx).await.expect("participant");
    sqlx::query(
        r#"INSERT INTO chat.member_devices(leaf_period_id,participant_period_id,conversation_id,generation,user_did,device_id,leaf_index,basic_credential,leaf_signature_key,leaf_key_id,leaf_auth_generation,origin,joined_state_version,joined_transition_id,joined_seq,active,created_at) VALUES($1,$2,$3,0,$4,$5,0,$6,$7,$8,1,'genesis',0,$9,1,true,$10)"#,
    ).bind(leaf_period_id).bind(participant_period_id).bind(conversation_id).bind(actor_did).bind(actor_device_id).bind(&basic_credential).bind(&actor_public_key).bind(&actor_key_id).bind(creation_transition_id).bind(now).execute(&mut **tx).await.expect("leaf");
    sqlx::query(
        r#"INSERT INTO chat.metadata_snapshots(metadata_snapshot_id,conversation_id,generation,state_version,group_id,epoch,group_context_hash,confirmation_tag,producing_transition_id,origin_transition_id,metadata_version,nonce,ciphertext,ciphertext_sha256,ciphertext_size,author_did,author_device_id,author_key_id,author_public_key,author_auth_generation,author_origin_seq,author_role,author_device_status,created_at) VALUES($1,$2,0,0,$3,0,$4,$5,$6,$6,1,$7,$8,$9,16,$10,$11,$12,$13,1,1,'admin','active',$14)"#,
    ).bind(metadata_snapshot_id).bind(conversation_id).bind(&group_id).bind(&group_context_hash).bind(&confirmation_tag).bind(creation_transition_id).bind(vec![14_u8; 12]).bind(&metadata_ciphertext).bind(Sha256::digest(&metadata_ciphertext).to_vec()).bind(actor_did).bind(actor_device_id).bind(&actor_key_id).bind(&actor_public_key).bind(now).execute(&mut **tx).await.expect("metadata");
    sqlx::query(
        r#"INSERT INTO chat.entries(conversation_id,seq,entry_id,entry_kind,accepted_payload_bytes,accepted_payload_sha256,signed_request_bytes,request_digest,signature,server_fields_bytes,outer_entry_fingerprint,actor_did,actor_device_id,actor_key_id,actor_auth_generation,generation,state_version,transition_id,received_at) VALUES($1,1,$2,'blue.catbird.chat.defs#creationEntry',$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,1,0,0,$13,$14)"#,
    ).bind(conversation_id).bind(creation_entry_id).bind(&accepted_payload).bind(Sha256::digest(&accepted_payload).to_vec()).bind(&signed_request).bind(&request_digest).bind(&signature).bind(vec![0_u8]).bind(&creation_fingerprint).bind(actor_did).bind(actor_device_id).bind(&actor_key_id).bind(creation_transition_id).bind(now).execute(&mut **tx).await.expect("creation entry");
    sqlx::query(
        r#"INSERT INTO chat.application_intervals(membership_interval_id,conversation_id,generation,recipient_did,recipient_device_id,start_seq,opening_kind,opening_transition_id,opening_outer_entry_fingerprint,opening_state_version,opening_group_id,opening_epoch,opening_group_context_hash,opening_confirmation_tag,opening_leaf_period_id,created_at) VALUES($1,$2,0,$3,$4,1,'creation',$1,$5,0,$6,0,$7,$8,$9,$10)"#,
    ).bind(creation_transition_id).bind(conversation_id).bind(actor_did).bind(actor_device_id).bind(&creation_fingerprint).bind(&group_id).bind(&group_context_hash).bind(&confirmation_tag).bind(leaf_period_id).bind(now).execute(&mut **tx).await.expect("interval");

    CreationGraph {
        conversation_id,
        actor_did: actor_did.to_owned(),
        actor_device_id,
        actor_key_id,
        actor_public_key,
        leaf_period_id,
        creation_transition_id,
        creation_entry_id,
        group_id,
        group_context_hash,
        confirmation_tag,
        creation_fingerprint,
        accepted_at: now,
    }
}

/// Build an accepted application `ApplicationSend` for the given actor on the
/// graph's conversation at the given head state version.
fn app_send_for(
    graph: &CreationGraph,
    did: &str,
    device_id: Uuid,
    key_id: &str,
    salt: u8,
    received_at: DateTime<Utc>,
    state_version: i64,
) -> ApplicationSend {
    let signing_transcript_bytes = vec![salt ^ 0x5a; 16];
    let request_digest = Sha256::digest(&signing_transcript_bytes).to_vec();
    ApplicationSend {
        entry: AppendEntry {
            conversation_id: graph.conversation_id,
            entry_id: Uuid::new_v4(),
            entry_kind: "blue.catbird.chat.defs#applicationEntry".to_owned(),
            accepted_payload_bytes: vec![salt; 8],
            accepted_payload_sha256: Sha256::digest([salt; 8]).to_vec(),
            signed_request_bytes: vec![salt ^ 0x33; 8],
            request_digest,
            signature: vec![salt; 64],
            server_fields_bytes: vec![salt; 1],
            outer_entry_fingerprint: vec![salt; 32],
            actor_did: did.to_owned(),
            actor_device_id: device_id,
            actor_key_id: key_id.to_owned(),
            actor_auth_generation: 1,
            generation: Some(0),
            state_version: Some(state_version),
            transition_id: None,
            message_id: Some(Uuid::new_v4()),
            received_at,
        },
        signing_transcript_bytes,
        outcome_bytes: vec![salt ^ 0x0f; 8],
    }
}

fn coherent_app_send(
    graph: &CreationGraph,
    salt: u8,
    received_at: DateTime<Utc>,
) -> ApplicationSend {
    app_send_for(
        graph,
        &graph.actor_did,
        graph.actor_device_id,
        &graph.actor_key_id,
        salt,
        received_at,
        0,
    )
}

/// A bound application blob committed against the shared test DB. The physical
/// object is stored through the production `BlobStore` under the fixture prefix.
/// `seed_now` shifts the whole graph into the past (used by the expired-window
/// case); `unbound_expires_after_uploaded` defaults to the 1h convention.
struct BoundFixture {
    graph: CreationGraph,
    blob_id: Uuid,
    ciphertext: Vec<u8>,
    ct_sha: [u8; 32],
    cid: String,
    owner_did: String,
    owner_device_id: Uuid,
    entry_seq: i64,
}

/// Seed the full lifecycle graph for `owner` (an HTTP device) and COMMIT it:
/// creation -> app send (seq 2) -> prepare -> store exact ciphertext (real S3)
/// -> complete -> bind. Used by the route-driven tests.
async fn seed_bound_blob_route(
    pool: &PgPool,
    owner: &http::Device,
    seed_now: DateTime<Utc>,
    unbound_expires_after_uploaded: Duration,
) -> BoundFixture {
    let mut tx = pool.begin().await.expect("begin route fixture graph");
    let graph = seed_creation_graph_tx(&mut tx, &owner.did, Some(owner)).await;
    let now = seed_now;

    let send = coherent_app_send(&graph, 0x42, now);
    let message_id = send.entry.message_id.expect("message id");
    let outcome = resolve_application_send(&mut tx, &send, ApplicationSendDisposition::Accept)
        .await
        .expect("accept send");
    assert_eq!(outcome, ApplicationSendOutcome::Accepted { seq: 2 });

    let ciphertext = ciphertext_bytes();
    let ct_sha: [u8; 32] = Sha256::digest(&ciphertext).into();
    let blob_id = Uuid::new_v4();
    let request = PrepareBlobRequest {
        blob_id,
        owner_did: owner.did.clone(),
        owner_device_id: owner.device_id,
        owner_key_id: graph.actor_key_id.clone(),
        owner_auth_generation: 1,
        purpose: BlobPurpose::Attachment,
        media_type: MEDIA,
        plaintext_size: PLAINTEXT_SIZE,
        ciphertext_size: CIPHERTEXT_SIZE,
        ciphertext_sha256: ct_sha.to_vec(),
        ticket_hash: fresh_ticket_hash(),
        prepared_at: now,
    };
    prepare_blob(&mut tx, &request).await.expect("prepare");

    let store = fixture_store().await;
    let cid = deterministic_object_key(blob_id, &ct_sha);
    store
        .put_for_blob(blob_id, ciphertext.clone(), &ct_sha, MEDIA_STR)
        .await
        .expect("store exact ciphertext");

    let uploaded_at = now + Duration::seconds(10);
    complete_upload(
        &mut tx,
        blob_id,
        &owner.did,
        owner.device_id,
        CIPHERTEXT_SIZE,
        &request.ticket_hash,
        uploaded_at,
        &cid,
    )
    .await
    .expect("complete upload");

    let bound_at = now + Duration::seconds(20);
    let descriptor_bytes = vec![0xAB; 40];
    let aad_bytes = vec![0xCD; 24];
    bind_application_blob(
        &mut tx,
        &NewBlobBinding {
            blob_id,
            binding_kind: BindingKind::Application,
            conversation_id: graph.conversation_id,
            entry_seq: Some(2),
            message_id: Some(message_id),
            metadata_origin_transition_id: None,
            metadata_version: None,
            owner_did: owner.did.clone(),
            owner_device_id: owner.device_id,
            descriptor_bytes: descriptor_bytes.clone(),
            descriptor_sha256: Sha256::digest(&descriptor_bytes).to_vec(),
            aad_bytes: aad_bytes.clone(),
            aad_sha256: Sha256::digest(&aad_bytes).to_vec(),
            ciphertext_sha256: ct_sha.to_vec(),
            plaintext_size: PLAINTEXT_SIZE,
            ciphertext_size: CIPHERTEXT_SIZE,
            purpose: BlobPurpose::Attachment,
            bound_at,
            uploaded_at,
            unbound_expires_at: uploaded_at + unbound_expires_after_uploaded,
        },
    )
    .await
    .expect("bind application blob");
    tx.commit().await.expect("commit route fixture graph");
    BoundFixture {
        graph,
        blob_id,
        ciphertext,
        ct_sha,
        cid,
        owner_did: owner.did.clone(),
        owner_device_id: owner.device_id,
        entry_seq: 2,
    }
}

/// Same lifecycle, but the owner is a repository-only device (no HTTP/DPoP
/// material) — for the capability-level cases (replay) that never cross the
/// route boundary.
async fn seed_bound_blob_repo(
    pool: &PgPool,
    seed_now: DateTime<Utc>,
    unbound_expires_after_uploaded: Duration,
) -> BoundFixture {
    let mut tx = pool.begin().await.expect("begin repo fixture graph");
    let owner = random_plc_did();
    let graph = seed_creation_graph_tx(&mut tx, &owner, None).await;
    let now = seed_now;

    let send = coherent_app_send(&graph, 0x42, now);
    let message_id = send.entry.message_id.expect("message id");
    let outcome = resolve_application_send(&mut tx, &send, ApplicationSendDisposition::Accept)
        .await
        .expect("accept send");
    assert_eq!(outcome, ApplicationSendOutcome::Accepted { seq: 2 });

    let ciphertext = ciphertext_bytes();
    let ct_sha: [u8; 32] = Sha256::digest(&ciphertext).into();
    let blob_id = Uuid::new_v4();
    let request = PrepareBlobRequest {
        blob_id,
        owner_did: owner.clone(),
        owner_device_id: graph.actor_device_id,
        owner_key_id: graph.actor_key_id.clone(),
        owner_auth_generation: 1,
        purpose: BlobPurpose::Attachment,
        media_type: MEDIA,
        plaintext_size: PLAINTEXT_SIZE,
        ciphertext_size: CIPHERTEXT_SIZE,
        ciphertext_sha256: ct_sha.to_vec(),
        ticket_hash: fresh_ticket_hash(),
        prepared_at: now,
    };
    prepare_blob(&mut tx, &request).await.expect("prepare");

    let store = fixture_store().await;
    let cid = deterministic_object_key(blob_id, &ct_sha);
    store
        .put_for_blob(blob_id, ciphertext.clone(), &ct_sha, MEDIA_STR)
        .await
        .expect("store exact ciphertext");

    let uploaded_at = now + Duration::seconds(10);
    complete_upload(
        &mut tx,
        blob_id,
        &owner,
        graph.actor_device_id,
        CIPHERTEXT_SIZE,
        &request.ticket_hash,
        uploaded_at,
        &cid,
    )
    .await
    .expect("complete upload");

    let descriptor_bytes = vec![0xAB; 40];
    let aad_bytes = vec![0xCD; 24];
    bind_application_blob(
        &mut tx,
        &NewBlobBinding {
            blob_id,
            binding_kind: BindingKind::Application,
            conversation_id: graph.conversation_id,
            entry_seq: Some(2),
            message_id: Some(message_id),
            metadata_origin_transition_id: None,
            metadata_version: None,
            owner_did: owner.clone(),
            owner_device_id: graph.actor_device_id,
            descriptor_bytes: descriptor_bytes.clone(),
            descriptor_sha256: Sha256::digest(&descriptor_bytes).to_vec(),
            aad_bytes: aad_bytes.clone(),
            aad_sha256: Sha256::digest(&aad_bytes).to_vec(),
            ciphertext_sha256: ct_sha.to_vec(),
            plaintext_size: PLAINTEXT_SIZE,
            ciphertext_size: CIPHERTEXT_SIZE,
            purpose: BlobPurpose::Attachment,
            bound_at: now + Duration::seconds(20),
            uploaded_at,
            unbound_expires_at: uploaded_at + unbound_expires_after_uploaded,
        },
    )
    .await
    .expect("bind application blob");
    tx.commit().await.expect("commit repo fixture graph");
    BoundFixture {
        graph: graph.clone(),
        blob_id,
        ciphertext,
        ct_sha,
        cid,
        owner_did: owner,
        owner_device_id: graph.actor_device_id,
        entry_seq: 2,
    }
}

async fn seed_bound_blob(pool: &PgPool) -> BoundFixture {
    let now: DateTime<Utc> = sqlx::query_scalar("SELECT clock_timestamp()::timestamptz")
        .fetch_one(pool)
        .await
        .expect("sample trusted database clock");
    seed_bound_blob_repo(pool, now, Duration::hours(1)).await
}

/// Repository-level authorization (the production `authorize_blob_read` source,
/// included) for the capability-level cases.
async fn authorize(
    pool: &PgPool,
    fixture: &BoundFixture,
    did: &str,
    device_id: Uuid,
    auth_generation: i64,
) -> Result<AuthorizedBlobFetch, BlobRepositoryError> {
    let transaction = BlobAuthorizationTransaction::begin(pool).await?;
    let pending = authorize_blob_read(
        transaction,
        &AuthorizeBlobReadRequest {
            blob_id: fixture.blob_id,
            caller_did: did.to_owned(),
            caller_device_id: device_id,
            auth_generation,
        },
    )
    .await?;
    pending.publicize().await
}

/// Drive the production `blue.catbird.chat.getBlob` handler with the REAL
/// S3-backed blob store and return the raw response bytes.
async fn route_fetch_bytes(
    router: &axum::Router,
    device: &http::Device,
    blob_id: Uuid,
) -> (axum::http::StatusCode, Vec<u8>) {
    http::send_bytes(
        router.clone(),
        http::unsigned_request(
            device,
            "blue.catbird.chat.getBlob",
            "GET",
            &format!("?actorDeviceId={}&blobId={blob_id}", device.device_id),
        ),
    )
    .await
}

/// Build the route harness wired to the real S3 fixture store.
async fn route_router(pool: PgPool) -> axum::Router {
    http::router_for_authenticated_acceptance_with_blob_store(pool, fixture_store().await).await
}

// ===========================================================================
// Positive lifecycle: prepare -> store exact ciphertext -> complete -> bind
// -> authorize/publicize -> fetch once -> verify CID/hash/size at S3 + DB.
// The fetch runs through the PRODUCTION handler + PRODUCTION BlobStore.
// ===========================================================================

#[tokio::test]
#[ignore = "requires the disposable local MinIO fixture (see file docs); run explicitly with --ignored"]
async fn s3_positive_lifecycle_prepare_store_complete_bind_authorize_fetch() {
    let pool: PgPool = common::chat_protocol::setup_chat_protocol_db(4).await;
    http::ensure_fence(&pool).await;
    let owner = http::seed_device(&pool).await;
    let client = raw_s3_client();
    let store = fixture_store().await;

    // Prepare -> store -> complete -> bind -> commit (through the production
    // BlobStore for the object side).
    let fixture = seed_bound_blob_route(&pool, &owner, Utc::now(), Duration::hours(1)).await;
    let blob_id = fixture.blob_id;
    let cid = fixture.cid.clone();

    // The physical object exists under the disposable prefix with the exact
    // atomic identity metadata; the bare CID is NOT addressable.
    assert!(object_exists(&client, &fixture_physical_key(&cid)).await);
    assert!(
        !object_exists(&client, &cid).await,
        "bare CID not addressable"
    );
    let head = client
        .head_object()
        .bucket(&fixture_bucket())
        .key(&fixture_physical_key(&cid))
        .send()
        .await
        .expect("head stored object");
    assert_eq!(head.content_length(), Some(CIPHERTEXT_SIZE), "exact size");
    let metadata = head.metadata().expect("stored metadata");
    assert_eq!(metadata.get("cid").map(String::as_str), Some(cid.as_str()));
    assert_eq!(
        metadata.get("sha256").map(String::as_str),
        Some(hex::encode(fixture.ct_sha).as_str())
    );
    assert_eq!(
        metadata.get("size").map(String::as_str),
        Some(CIPHERTEXT_SIZE.to_string().as_str())
    );
    assert_eq!(
        metadata.get("media-type").map(String::as_str),
        Some(MEDIA_STR)
    );
    let (status, db_key): (String, Option<String>) =
        sqlx::query_as("SELECT status, object_store_key FROM chat.blobs WHERE blob_id = $1")
            .bind(blob_id)
            .fetch_one(&pool)
            .await
            .expect("blob row");
    assert_eq!(status, "bound");
    assert_eq!(
        db_key.as_deref(),
        Some(cid.as_str()),
        "DB stores the bare CID"
    );

    // Authorize + publicize + fetch exactly once through the production handler
    // and production `BlobStore::get_authorized` against real MinIO.
    let router = route_router(pool.clone()).await;
    let (fetch_status, fetched) = route_fetch_bytes(&router, &owner, blob_id).await;
    assert_eq!(
        fetch_status,
        axum::http::StatusCode::OK,
        "fetch status={fetch_status} body={:?}",
        String::from_utf8_lossy(&fetched)
    );
    assert_eq!(fetched, fixture.ciphertext, "exact ciphertext bytes");
    assert_eq!(
        Sha256::digest(&fetched).to_vec(),
        fixture.ct_sha.to_vec(),
        "hash verified"
    );
    assert_eq!(fetched.len() as i64, CIPHERTEXT_SIZE, "size verified");

    println!(
        "s3_positive_lifecycle: blob_id={blob_id} cid={cid} object={} status={status} fetched_bytes={}",
        fixture_physical_key(&cid),
        fetched.len()
    );

    // Cleanup: the production delete path removes the exact object.
    store.delete(&cid).await.expect("production delete path");
    assert!(!object_exists(&client, &fixture_physical_key(&cid)).await);
}

// ===========================================================================
// Adversarial matrix — every denial happens before any object-store request.
// ===========================================================================

#[tokio::test]
#[ignore = "requires the disposable local MinIO fixture (see file docs); run explicitly with --ignored"]
async fn s3_denies_wrong_devices_without_disclosing_the_object() {
    let pool: PgPool = common::chat_protocol::setup_chat_protocol_db(4).await;
    http::ensure_fence(&pool).await;
    let owner = http::seed_device(&pool).await;
    let fixture = seed_bound_blob_route(&pool, &owner, Utc::now(), Duration::hours(1)).await;
    let router = route_router(pool.clone()).await;

    // Same-DID SIBLING device (real DPoP material, but NO application interval).
    let sibling_signing = http::random_p256();
    let sibling_jwk = http::public_jwk(&sibling_signing);
    let sibling_jkt = http::jwk_thumbprint(&sibling_jwk);
    let sibling_device_id = Uuid::new_v4();
    let sibling_key = random_ref();
    let sibling_key_id: String = sqlx::query_scalar("SELECT chat.ed25519_key_id($1)")
        .bind(&sibling_key)
        .fetch_one(&pool)
        .await
        .expect("sibling key id");
    sqlx::query(
        "INSERT INTO chat.devices(user_did,device_id,device_name,status,dpop_jkt,auth_generation,capabilities,created_at,updated_at) VALUES($1,$2,'sibling','active',$3,1,chat.protocol_capabilities(),clock_timestamp(),clock_timestamp())",
    )
    .bind(&owner.did)
    .bind(sibling_device_id)
    .bind(&sibling_jkt)
    .execute(&pool)
    .await
    .expect("sibling device");
    sqlx::query(
        "INSERT INTO chat.device_keys(user_did,device_id,key_id,signing_public_key,enrollment_auth_generation,created_at) VALUES($1,$2,$3,$4,1,clock_timestamp())",
    )
    .bind(&owner.did)
    .bind(sibling_device_id)
    .bind(&sibling_key_id)
    .bind(&sibling_key)
    .execute(&pool)
    .await
    .expect("sibling key");
    let sibling = http::Device {
        did: owner.did.clone(),
        device_id: sibling_device_id,
        signing: sibling_signing,
        jwk: sibling_jwk,
        jkt: sibling_jkt,
    };
    // A fully foreign device (different DID).
    let foreign = http::seed_device(&pool).await;

    // The exact device fetches the exact ciphertext.
    let (owner_status, owner_bytes) = route_fetch_bytes(&router, &owner, fixture.blob_id).await;
    assert_eq!(owner_status, axum::http::StatusCode::OK);
    assert_eq!(owner_bytes, fixture.ciphertext);

    // Both wrong devices are denied at the production handler; the response is
    // a JSON error that never carries any object bytes.
    for (label, device) in [("sibling", &sibling), ("foreign", &foreign)] {
        let (status, denied) = route_fetch_bytes(&router, device, fixture.blob_id).await;
        assert_eq!(
            status,
            axum::http::StatusCode::UNAUTHORIZED,
            "{label} must be denied"
        );
        assert!(
            !denied
                .windows(fixture.ciphertext.len())
                .any(|window| window == fixture.ciphertext),
            "{label} response must not disclose the object"
        );
        let parsed: serde_json::Value = serde_json::from_slice(&denied).unwrap_or_default();
        assert_eq!(parsed["error"], "NotAuthorized", "{label} error code");
        assert!(parsed.get("blob").is_none(), "{label} has no blob payload");
        println!(
            "s3_denies_wrong_devices: blob_id={} {label}_device={} -> 401 NotAuthorized (no storage oracle)",
            fixture.blob_id, device.device_id
        );
    }

    let store = fixture_store().await;
    store.delete(&fixture.cid).await.expect("cleanup delete");
}

#[tokio::test]
#[ignore = "requires the disposable local MinIO fixture (see file docs); run explicitly with --ignored"]
async fn s3_rejects_replayed_capability() {
    let pool: PgPool = common::chat_protocol::setup_chat_protocol_db(4).await;
    let fixture = seed_bound_blob(&pool).await;
    let capability = authorize(
        &pool,
        &fixture,
        &fixture.owner_did,
        fixture.owner_device_id,
        1,
    )
    .await
    .expect("authorize exact device");

    // First consume through the exact production capability path succeeds and
    // seals the physical identity.
    let storage = capability
        .consume_for_storage(&pool)
        .await
        .expect("first consume");
    assert_eq!(storage.expected_size(), CIPHERTEXT_SIZE);
    assert_eq!(storage.object_store_key(), fixture.cid.as_str());
    assert_eq!(storage.derived_cid(), fixture.cid.as_str());
    assert_eq!(storage.expected_sha256(), &fixture.ct_sha);
    assert_eq!(storage.media_type(), MEDIA_STR);

    // Replay of the SAME one-use capability is rejected (atomic in-process
    // claim plus the database one-use contract). The route boundary can never
    // be replayed: the capability is created and consumed inside one handler
    // call and is never exposed to clients.
    let replay = capability.consume_for_storage(&pool).await;
    assert!(
        matches!(replay, Err(BlobRepositoryError::FetchAlreadyConsumed)),
        "replay must fail with FetchAlreadyConsumed, got {replay:?}"
    );
    println!(
        "s3_rejects_replayed_capability: blob_id={} -> FetchAlreadyConsumed on replay",
        fixture.blob_id
    );

    let store = fixture_store().await;
    store.delete(&fixture.cid).await.expect("cleanup delete");
}

#[tokio::test]
#[ignore = "requires the disposable local MinIO fixture (see file docs); run explicitly with --ignored"]
async fn s3_rejects_expired_capability_window() {
    let pool: PgPool = common::chat_protocol::setup_chat_protocol_db(4).await;
    http::ensure_fence(&pool).await;
    let owner = http::seed_device(&pool).await;
    // The whole fixture graph is seeded in the past and the unbound window is
    // short, so at authorization time `issued_at >= unbound_expires_at`: the
    // blob's authorization window has expired.
    let seed_now: DateTime<Utc> = sqlx::query_scalar("SELECT clock_timestamp()::timestamptz")
        .fetch_one(&pool)
        .await
        .expect("clock");
    let fixture = seed_bound_blob_route(
        &pool,
        &owner,
        seed_now - Duration::hours(2),
        Duration::hours(1),
    )
    .await;
    let (unbound_expires_at, status): (Option<DateTime<Utc>>, String) =
        sqlx::query_as("SELECT unbound_expires_at, status FROM chat.blobs WHERE blob_id = $1")
            .bind(fixture.blob_id)
            .fetch_one(&pool)
            .await
            .expect("blob row");
    assert_eq!(status, "bound");
    let unbound_expires_at = unbound_expires_at.expect("unbound window");
    let now: DateTime<Utc> = sqlx::query_scalar("SELECT clock_timestamp()::timestamptz")
        .fetch_one(&pool)
        .await
        .expect("clock");
    assert!(
        now >= unbound_expires_at,
        "fixture window must already have expired (window {unbound_expires_at} vs now {now})"
    );

    // Repository-level: authorization is denied before any storage identity is
    // revealed.
    let result = authorize(
        &pool,
        &fixture,
        &fixture.owner_did,
        fixture.owner_device_id,
        1,
    )
    .await;
    assert!(
        matches!(result, Err(BlobRepositoryError::NotAuthorized)),
        "expired window must deny authorization, got {result:?}"
    );
    // Route-level: the production handler also denies (401, no object bytes).
    let router = route_router(pool.clone()).await;
    let (route_status, denied) = route_fetch_bytes(&router, &owner, fixture.blob_id).await;
    assert_eq!(route_status, axum::http::StatusCode::UNAUTHORIZED);
    assert!(
        !denied
            .windows(fixture.ciphertext.len())
            .any(|window| window == fixture.ciphertext),
        "expired fetch must not disclose the object"
    );
    println!(
        "s3_rejects_expired_capability_window: blob_id={} unbound_expires_at={unbound_expires_at} -> NotAuthorized (repo + route)",
        fixture.blob_id
    );

    let store = fixture_store().await;
    store.delete(&fixture.cid).await.expect("cleanup delete");
}

#[tokio::test]
#[ignore = "requires the disposable local MinIO fixture (see file docs); run explicitly with --ignored"]
async fn s3_detects_tampered_object_body() {
    let pool: PgPool = common::chat_protocol::setup_chat_protocol_db(4).await;
    http::ensure_fence(&pool).await;
    let owner = http::seed_device(&pool).await;
    let client = raw_s3_client();
    let fixture = seed_bound_blob_route(&pool, &owner, Utc::now(), Duration::hours(1)).await;
    let key = fixture_physical_key(&fixture.cid);
    let bucket = fixture_bucket();

    // Capture the exact production metadata, then overwrite the SAME key with a
    // different body of the SAME size while keeping the metadata identical — the
    // only remaining guard is the bounded hash check.
    let head = client
        .head_object()
        .bucket(&bucket)
        .key(&key)
        .send()
        .await
        .expect("head original");
    let metadata = head.metadata().cloned().expect("original metadata");
    let tampered: Vec<u8> = vec![0x6B; CIPHERTEXT_SIZE as usize];
    client
        .put_object()
        .bucket(&bucket)
        .key(&key)
        .set_content_type(Some(MEDIA_STR.to_owned()))
        .set_metadata(Some(metadata))
        .body(ByteStream::from(tampered))
        .send()
        .await
        .expect("tamper object");

    let router = route_router(pool.clone()).await;
    let (route_status, denied) = route_fetch_bytes(&router, &owner, fixture.blob_id).await;
    assert_eq!(
        route_status,
        axum::http::StatusCode::INTERNAL_SERVER_ERROR,
        "tampered body must surface an invariant failure, got {route_status}"
    );
    assert!(
        !denied
            .windows(fixture.ciphertext.len())
            .any(|window| window == fixture.ciphertext),
        "tampered fetch must not return the wrong bytes"
    );
    println!(
        "s3_detects_tampered_object_body: blob_id={} cid={} -> 500 InvariantViolation (same size + metadata, wrong body)",
        fixture.blob_id, fixture.cid
    );

    // Cleanup: restore the exact object, then delete it through production.
    let store = fixture_store().await;
    store
        .put_for_blob(
            fixture.blob_id,
            fixture.ciphertext.clone(),
            &fixture.ct_sha,
            MEDIA_STR,
        )
        .await
        .expect("restore");
    store.delete(&fixture.cid).await.expect("cleanup delete");
}

#[tokio::test]
#[ignore = "requires the disposable local MinIO fixture (see file docs); run explicitly with --ignored"]
async fn s3_rejects_wrong_size_object_before_body_fetch() {
    let pool: PgPool = common::chat_protocol::setup_chat_protocol_db(4).await;
    http::ensure_fence(&pool).await;
    let owner = http::seed_device(&pool).await;
    let client = raw_s3_client();
    let fixture = seed_bound_blob_route(&pool, &owner, Utc::now(), Duration::hours(1)).await;
    let key = fixture_physical_key(&fixture.cid);
    let bucket = fixture_bucket();

    // Preserve the valid identity metadata but replace the object with a
    // different-length body. This reaches BlobStore::get_authorized's
    // content-length guard before the bounded body/hash checks.
    let head = client
        .head_object()
        .bucket(&bucket)
        .key(&key)
        .send()
        .await
        .expect("head original");
    let metadata = head.metadata().cloned().expect("original metadata");
    let wrong_size = vec![0x7C; CIPHERTEXT_SIZE as usize + 1];
    client
        .put_object()
        .bucket(&bucket)
        .key(&key)
        .set_content_type(Some(MEDIA_STR.to_owned()))
        .set_metadata(Some(metadata))
        .body(ByteStream::from(wrong_size))
        .send()
        .await
        .expect("store wrong-size object");

    let router = route_router(pool.clone()).await;
    let (route_status, denied) = route_fetch_bytes(&router, &owner, fixture.blob_id).await;
    assert_eq!(
        route_status,
        axum::http::StatusCode::INTERNAL_SERVER_ERROR,
        "wrong-size object must fail the content-length guard, got {route_status}"
    );
    assert!(
        !denied
            .windows(fixture.ciphertext.len())
            .any(|window| window == fixture.ciphertext),
        "wrong-size fetch must not return any object bytes"
    );
    println!(
        "s3_rejects_wrong_size_object_before_body_fetch: blob_id={} cid={} -> MetadataMismatch(content-length) (expected={} actual={})",
        fixture.blob_id,
        fixture.cid,
        CIPHERTEXT_SIZE,
        CIPHERTEXT_SIZE + 1
    );

    let store = fixture_store().await;
    store.delete(&fixture.cid).await.expect("cleanup delete");
}

#[tokio::test]
#[ignore = "requires the disposable local MinIO fixture (see file docs); run explicitly with --ignored"]
async fn s3_fails_closed_on_missing_exact_object_key() {
    let pool: PgPool = common::chat_protocol::setup_chat_protocol_db(4).await;
    http::ensure_fence(&pool).await;
    let owner = http::seed_device(&pool).await;
    let client = raw_s3_client();
    let fixture = seed_bound_blob_route(&pool, &owner, Utc::now(), Duration::hours(1)).await;
    let key = fixture_physical_key(&fixture.cid);

    // An attacker (or drift) removes the exact object; the capability names the
    // deterministic key and there is no fallback or alternative lookup.
    client
        .delete_object()
        .bucket(&fixture_bucket())
        .key(&key)
        .send()
        .await
        .expect("remove exact object");
    assert!(!object_exists(&client, &key).await);

    let router = route_router(pool.clone()).await;
    let (route_status, denied) = route_fetch_bytes(&router, &owner, fixture.blob_id).await;
    assert_eq!(
        route_status,
        axum::http::StatusCode::BAD_REQUEST,
        "missing exact object must fail closed, got {route_status}"
    );
    let parsed: serde_json::Value = serde_json::from_slice(&denied).unwrap_or_default();
    assert_eq!(parsed["error"], "BlobNotFound");
    assert!(
        !denied
            .windows(fixture.ciphertext.len())
            .any(|window| window == fixture.ciphertext),
        "missing fetch must not disclose anything"
    );
    println!(
        "s3_fails_closed_on_missing_exact_object_key: blob_id={} cid={} -> 400 BlobNotFound",
        fixture.blob_id, fixture.cid
    );
}

#[tokio::test]
#[ignore = "requires the disposable local MinIO fixture (see file docs); run explicitly with --ignored"]
async fn s3_denies_revoked_device_generation() {
    let pool: PgPool = common::chat_protocol::setup_chat_protocol_db(4).await;
    http::ensure_fence(&pool).await;
    let owner = http::seed_device(&pool).await;
    let fixture = seed_bound_blob_route(&pool, &owner, Utc::now(), Duration::hours(1)).await;
    let did = &fixture.owner_did;
    let target_device = fixture.owner_device_id;

    // A revoked/re-keyed device: the lifecycle trigger requires the auth
    // generation to bump by exactly one together with a dpop_jkt rotation, so
    // the pre-rotation credentials (generation 1, old jkt) are dead.
    let mut tx = pool.begin().await.expect("begin revocation");
    let rotated_jkt = URL_SAFE_NO_PAD.encode(Sha256::digest([0x99_u8; 8]));
    let updated = sqlx::query(
        "UPDATE chat.devices \
            SET auth_generation=2, dpop_jkt=$2, updated_at=clock_timestamp() \
          WHERE user_did=$1 AND device_id=$3 AND status='active' AND auth_generation=1",
    )
    .bind(did)
    .bind(&rotated_jkt)
    .bind(target_device)
    .execute(&mut *tx)
    .await
    .expect("rotate target device generation");
    assert_eq!(
        updated.rows_affected(),
        1,
        "exactly the target device rotated"
    );
    tx.commit().await.expect("commit revocation graph");

    // Repository-level: the pre-rotation auth generation no longer matches the
    // live device, so authorization is denied before any object-store request.
    let result = authorize(&pool, &fixture, did, target_device, 1).await;
    assert!(
        matches!(result, Err(BlobRepositoryError::NotAuthorized)),
        "revoked generation must deny authorization, got {result:?}"
    );
    println!(
        "s3_denies_revoked_device_generation: blob_id={} target_device={target_device} -> NotAuthorized (auth_generation fence 1 vs rotated 2)",
        fixture.blob_id
    );

    let store = fixture_store().await;
    store.delete(&fixture.cid).await.expect("cleanup delete");
}

// ===========================================================================
// Lost membership: a committed Add (seq 3) + remove (seq 5) graph. The member
// mints a capability while its interval is open, then loses membership; the
// consume revalidation sees the closed interval (terminal_seq 5 vs the minted
// fence NULL) and denies before any object-store request.
// ===========================================================================

/// Committed leafRecovery (Add) edge at seq 3: advances the head (0,0)->(0,1)
/// and opens `did`'s application interval at start_seq 3.
#[allow(clippy::too_many_arguments)]
async fn commit_add_member(
    tx: &mut Transaction<'_, Postgres>,
    graph: &CreationGraph,
    did: &str,
    device_id: Uuid,
    key_id: &str,
    public_key: &[u8],
    leaf_period_id: Uuid,
    participant_period_id: Uuid,
    key_package_ref: &[u8],
    at: DateTime<Utc>,
) -> (Uuid, Vec<u8>) {
    let cid = graph.conversation_id;
    let transition_id = Uuid::new_v4();
    let entry_id = Uuid::new_v4();
    let metadata_snapshot_id = Uuid::new_v4();
    let fingerprint = vec![0x33_u8; 32];
    let wrapper = Sha256::digest(Uuid::new_v4().as_bytes()).to_vec();
    let snapshot = vec![0x35_u8; 8];
    let tree_summary = vec![0x36_u8; 8];
    let payload = vec![0x37_u8; 8];
    let signed_request = vec![0x38_u8; 8];
    let signing_transcript = vec![0x39_u8; 16];
    let request_digest = Sha256::digest(&signing_transcript).to_vec();
    let signature = vec![0x3A_u8; 64];
    let metadata_ciphertext = vec![0x3B_u8; 16];
    let basic_credential = format!("{did}#{device_id}").into_bytes();

    // seq 3: committed acceptance edge. An invited participant can only become
    // 'active' through a participantAcceptanceEntry produced by an
    // acceptConversation transition by the invitee.
    let acceptance_transition_id = Uuid::new_v4();
    let acceptance_entry_id = Uuid::new_v4();
    let acceptance_fingerprint = vec![0x2E_u8; 32];
    let acceptance_payload = vec![0x2F_u8; 8];
    let acceptance_request = vec![0x30_u8; 8];
    let acceptance_transcript = vec![0x31_u8; 16];
    let acceptance_digest = Sha256::digest(&acceptance_transcript).to_vec();
    let acceptance_signature = vec![0x32_u8; 64];
    let updated = sqlx::query(
        "UPDATE chat.conversations SET current_state_version=1,next_entry_seq=4 \
             WHERE conversation_id=$1 AND current_generation=0 \
               AND current_state_version=0 AND next_entry_seq=3",
    )
    .bind(cid)
    .execute(&mut **tx)
    .await
    .expect("advance head through acceptance");
    assert_eq!(updated.rows_affected(), 1, "exact acceptance head CAS");
    let updated = sqlx::query(
        "UPDATE chat.generations SET current_state_version=1 \
             WHERE conversation_id=$1 AND generation=0 AND current_state_version=0",
    )
    .bind(cid)
    .execute(&mut **tx)
    .await
    .expect("advance generation through acceptance");
    assert_eq!(
        updated.rows_affected(),
        1,
        "exact acceptance generation CAS"
    );
    sqlx::query(
        r#"INSERT INTO chat.transitions(
            transition_id,conversation_id,kind,actor_did,actor_device_id,actor_key_id,
            actor_auth_generation,actor_role,actor_device_status,signed_request_bytes,
            unsigned_projection_bytes,signing_transcript_bytes,request_digest,signature,
            prior_generation,prior_state_version,next_generation,next_state_version,
            metadata_snapshot_id,entry_seq,accepted_at
        ) VALUES($1,$2,'acceptConversation',$3,$4,$5,1,'member','active',$6,$7,$8,$9,$10,
            0,0,0,1,NULL,3,$11)"#,
    )
    .bind(acceptance_transition_id)
    .bind(cid)
    .bind(did)
    .bind(device_id)
    .bind(key_id)
    .bind(&acceptance_request)
    .bind(&acceptance_request)
    .bind(&acceptance_transcript)
    .bind(&acceptance_digest)
    .bind(&acceptance_signature)
    .bind(at)
    .execute(&mut **tx)
    .await
    .expect("acceptance transition");
    sqlx::query(
        r#"INSERT INTO chat.generation_states(
            conversation_id,generation,state_version,group_id,epoch,group_context_hash,
            confirmation_tag,lifecycle,state_kind,producing_transition_id,
            public_snapshot_bytes,snapshot_sha256,tree_summary_bytes,tree_summary_sha256,
            leaf_count,created_at
        ) VALUES($1,0,1,$2,0,$3,$4,'active','acceptConversation',$5,$6,$7,$8,$9,1,$10)"#,
    )
    .bind(cid)
    .bind(&graph.group_id)
    .bind(&graph.group_context_hash)
    .bind(&graph.confirmation_tag)
    .bind(acceptance_transition_id)
    .bind(vec![0x5B_u8; 8])
    .bind(Sha256::digest([0x5B_u8; 8]).to_vec())
    .bind(vec![0x5C_u8; 8])
    .bind(Sha256::digest([0x5C_u8; 8]).to_vec())
    .bind(at)
    .execute(&mut **tx)
    .await
    .expect("acceptance generation state");
    sqlx::query(
        r#"INSERT INTO chat.entries(
            conversation_id,seq,entry_id,entry_kind,accepted_payload_bytes,
            accepted_payload_sha256,signed_request_bytes,request_digest,signature,
            server_fields_bytes,outer_entry_fingerprint,actor_did,actor_device_id,
            actor_key_id,actor_auth_generation,generation,state_version,transition_id,
            received_at
        ) VALUES($1,3,$2,'blue.catbird.chat.defs#participantAcceptanceEntry',
            $3,$4,$5,$6,$7,$8,$9,$10,$11,$12,1,0,1,$13,$14)"#,
    )
    .bind(cid)
    .bind(acceptance_entry_id)
    .bind(&acceptance_payload)
    .bind(Sha256::digest(&acceptance_payload).to_vec())
    .bind(&acceptance_request)
    .bind(&acceptance_digest)
    .bind(&acceptance_signature)
    .bind(vec![0x00_u8])
    .bind(&acceptance_fingerprint)
    .bind(did)
    .bind(device_id)
    .bind(key_id)
    .bind(acceptance_transition_id)
    .bind(at)
    .execute(&mut **tx)
    .await
    .expect("acceptance entry");
    sqlx::query(
        r#"INSERT INTO chat.entry_recipients(
            conversation_id,seq,user_did,device_id,entitlement_kind
        ) VALUES($1,3,$2,$3,'control')"#,
    )
    .bind(cid)
    .bind(did)
    .bind(device_id)
    .execute(&mut **tx)
    .await
    .expect("route acceptance to invitee");
    sqlx::query(
        r#"INSERT INTO chat.participants(
            participant_period_id,conversation_id,user_did,status,role,role_transition_id,
            role_changed_at,created_by_did,created_by_device_id,invitation_transition_id,
            invitation_entry_id,invited_at,current_membership,created_at
        ) VALUES($1,$2,$3,'pending','member',$4,$5,$6,$7,$4,$8,$5,true,$5)"#,
    )
    .bind(participant_period_id)
    .bind(cid)
    .bind(did)
    .bind(graph.creation_transition_id)
    .bind(graph.accepted_at)
    .bind(&graph.actor_did)
    .bind(graph.actor_device_id)
    .bind(graph.creation_entry_id)
    .execute(&mut **tx)
    .await
    .expect("insert pending participant");
    let updated = sqlx::query(
        "UPDATE chat.participants SET status='active',acceptance_transition_id=$2,\
             acceptance_entry_id=$3,accepted_at=$4 \
             WHERE participant_period_id=$1 AND status='pending'",
    )
    .bind(participant_period_id)
    .bind(acceptance_transition_id)
    .bind(acceptance_entry_id)
    .bind(at)
    .execute(&mut **tx)
    .await
    .expect("promote participant");
    assert_eq!(updated.rows_affected(), 1, "exact acceptance promotion");

    let updated = sqlx::query(
        "UPDATE chat.conversations SET current_state_version=2,next_entry_seq=5 \
             WHERE conversation_id=$1 AND current_generation=0 \
               AND current_state_version=1 AND next_entry_seq=4",
    )
    .bind(cid)
    .execute(&mut **tx)
    .await
    .expect("advance head through Add");
    assert_eq!(updated.rows_affected(), 1, "exact Add head CAS");
    let updated = sqlx::query(
        "UPDATE chat.generations SET current_state_version=2 \
             WHERE conversation_id=$1 AND generation=0 AND current_state_version=1",
    )
    .bind(cid)
    .execute(&mut **tx)
    .await
    .expect("advance generation through Add");
    assert_eq!(updated.rows_affected(), 1, "exact Add generation CAS");

    sqlx::query(
        r#"INSERT INTO chat.transitions(
            transition_id,conversation_id,kind,actor_did,actor_device_id,actor_key_id,
            actor_auth_generation,actor_role,actor_device_status,signed_request_bytes,
            unsigned_projection_bytes,signing_transcript_bytes,request_digest,signature,
            prior_generation,prior_state_version,next_generation,next_state_version,
            metadata_snapshot_id,entry_seq,accepted_at
        ) VALUES($1,$2,'leafRecovery',$3,$4,$5,1,'admin','active',$6,$7,$8,$9,$10,
            0,1,0,2,$11,4,$12)"#,
    )
    .bind(transition_id)
    .bind(cid)
    .bind(&graph.actor_did)
    .bind(graph.actor_device_id)
    .bind(&graph.actor_key_id)
    .bind(&signed_request)
    .bind(&signed_request)
    .bind(&signing_transcript)
    .bind(&request_digest)
    .bind(&signature)
    .bind(metadata_snapshot_id)
    .bind(at)
    .execute(&mut **tx)
    .await
    .expect("Add transition");
    sqlx::query(
        r#"INSERT INTO chat.generation_states(
            conversation_id,generation,state_version,group_id,epoch,group_context_hash,
            confirmation_tag,lifecycle,state_kind,producing_transition_id,
            public_snapshot_bytes,snapshot_sha256,tree_summary_bytes,tree_summary_sha256,
            leaf_count,created_at
        ) VALUES($1,0,2,$2,1,$3,$4,'active','commit',$5,$6,$7,$8,$9,2,$10)"#,
    )
    .bind(cid)
    .bind(&graph.group_id)
    .bind(vec![0x21_u8; 32])
    .bind(vec![0x22_u8; 32])
    .bind(transition_id)
    .bind(&snapshot)
    .bind(Sha256::digest(&snapshot).to_vec())
    .bind(&tree_summary)
    .bind(Sha256::digest(&tree_summary).to_vec())
    .bind(at)
    .execute(&mut **tx)
    .await
    .expect("Add generation state");
    sqlx::query(
        r#"INSERT INTO chat.metadata_snapshots(
            metadata_snapshot_id,conversation_id,generation,state_version,group_id,epoch,
            group_context_hash,confirmation_tag,producing_transition_id,
            origin_transition_id,metadata_version,nonce,ciphertext,ciphertext_sha256,
            ciphertext_size,author_did,author_device_id,author_key_id,author_public_key,
            author_auth_generation,author_origin_seq,author_role,author_device_status,created_at
        ) VALUES($1,$2,0,2,$3,1,$4,$5,$6,$7,1,$8,$9,$10,16,$11,$12,$13,$14,
            1,1,'admin','active',$15)"#,
    )
    .bind(metadata_snapshot_id)
    .bind(cid)
    .bind(&graph.group_id)
    .bind(vec![0x21_u8; 32])
    .bind(vec![0x22_u8; 32])
    .bind(transition_id)
    .bind(graph.creation_transition_id)
    .bind(vec![0x3C_u8; 12])
    .bind(&metadata_ciphertext)
    .bind(Sha256::digest(&metadata_ciphertext).to_vec())
    .bind(&graph.actor_did)
    .bind(graph.actor_device_id)
    .bind(&graph.actor_key_id)
    .bind(&graph.actor_public_key)
    .bind(at)
    .execute(&mut **tx)
    .await
    .expect("Add metadata snapshot");
    sqlx::query(
        r#"INSERT INTO chat.entries(
            conversation_id,seq,entry_id,entry_kind,accepted_payload_bytes,
            accepted_payload_sha256,signed_request_bytes,request_digest,signature,
            server_fields_bytes,outer_entry_fingerprint,actor_did,actor_device_id,
            actor_key_id,actor_auth_generation,generation,state_version,transition_id,
            received_at
        ) VALUES($1,4,$2,'blue.catbird.chat.defs#leafRecoveryFulfillmentEntry',
            $3,$4,$5,$6,$7,$8,$9,$10,$11,$12,1,0,2,$13,$14)"#,
    )
    .bind(cid)
    .bind(entry_id)
    .bind(&payload)
    .bind(Sha256::digest(&payload).to_vec())
    .bind(&signed_request)
    .bind(&request_digest)
    .bind(&signature)
    .bind(vec![0x00_u8])
    .bind(&fingerprint)
    .bind(&graph.actor_did)
    .bind(graph.actor_device_id)
    .bind(&graph.actor_key_id)
    .bind(transition_id)
    .bind(at)
    .execute(&mut **tx)
    .await
    .expect("Add entry");
    sqlx::query(
        r#"INSERT INTO chat.entry_recipients(
            conversation_id,seq,user_did,device_id,entitlement_kind
        ) VALUES($1,4,$2,$3,'control')"#,
    )
    .bind(cid)
    .bind(&graph.actor_did)
    .bind(graph.actor_device_id)
    .execute(&mut **tx)
    .await
    .expect("route Add fulfillment to admin");

    // Consumed key package (the member-leaf mapping requires it).
    let not_before = at - Duration::hours(1);
    let not_after = at + Duration::hours(24);
    sqlx::query(
        r#"INSERT INTO chat.key_packages(
            key_package_ref,wrapper_bytes,wrapper_sha256,init_key,owner_did,
            owner_device_id,owner_key_id,owner_auth_generation,not_before,not_after,
            status,created_at
        ) VALUES($1,$2,$3,$4,$5,$6,$7,1,$8,$9,'reserved',$10)"#,
    )
    .bind(key_package_ref)
    .bind(&wrapper)
    .bind(Sha256::digest(&wrapper).to_vec())
    .bind(Sha256::digest(Uuid::new_v4().as_bytes()).to_vec())
    .bind(did)
    .bind(device_id)
    .bind(key_id)
    .bind(not_before)
    .bind(not_after)
    .bind(at)
    .execute(&mut **tx)
    .await
    .expect("insert reserved key package");
    let recovery_request_id = Uuid::new_v4();
    let package_expires_at = at + Duration::minutes(5);
    let request_transcript = vec![0x3E_u8; 16];
    let request_digest = Sha256::digest(&request_transcript).to_vec();
    sqlx::query(
        r#"INSERT INTO chat.key_package_reservations(
            recovery_request_id,key_package_ref,conversation_id,generation,requester_did,
            requester_device_id,requester_key_id,requester_auth_generation,recipient_did,
            recipient_device_id,bound_state_version,bound_group_id,bound_epoch,
            bound_group_context_hash,bound_confirmation_tag,purpose,expires_at,status,created_at
        ) VALUES($1,$2,$3,0,$4,$5,$6,1,$4,$5,1,$7,0,$8,$9,'leafRecovery',$10,'active',$11)"#,
    )
    .bind(recovery_request_id)
    .bind(key_package_ref)
    .bind(cid)
    .bind(did)
    .bind(device_id)
    .bind(key_id)
    .bind(&graph.group_id)
    .bind(&graph.group_context_hash)
    .bind(&graph.confirmation_tag)
    .bind(package_expires_at)
    .bind(at)
    .execute(&mut **tx)
    .await
    .expect("insert active reservation");
    sqlx::query(
        r#"INSERT INTO chat.leaf_recovery_requests(
            recovery_request_id,conversation_id,generation,requester_did,requester_device_id,
            requester_key_id,requester_auth_generation,recovery_kind,source,bound_state_version,
            bound_group_id,bound_epoch,bound_group_context_hash,bound_confirmation_tag,
            reservation_request_id,status,signed_request_bytes,signing_transcript_bytes,
            request_digest,signature,requested_at,expires_at
        ) VALUES($1,$2,0,$3,$4,$5,1,'add','acceptConversation',1,$6,0,$7,$8,$1,
            'open',$9,$10,$11,$12,$13,$14)"#,
    )
    .bind(recovery_request_id)
    .bind(cid)
    .bind(did)
    .bind(device_id)
    .bind(key_id)
    .bind(&graph.group_id)
    .bind(&graph.group_context_hash)
    .bind(&graph.confirmation_tag)
    .bind(vec![0x3F_u8; 8])
    .bind(&request_transcript)
    .bind(&request_digest)
    .bind(vec![0x40_u8; 64])
    .bind(at)
    .bind(package_expires_at)
    .execute(&mut **tx)
    .await
    .expect("insert open leaf recovery request");
    sqlx::query(
        "UPDATE chat.key_packages SET status='consumed',terminal_transition_id=$1,\
             terminal_at=$2 WHERE key_package_ref=$3 AND status='reserved'",
    )
    .bind(transition_id)
    .bind(at)
    .bind(key_package_ref)
    .execute(&mut **tx)
    .await
    .expect("consume key package");
    sqlx::query(
        "UPDATE chat.key_package_reservations SET status='consumed',\
             consumed_transition_id=$1,terminal_at=$2 \
             WHERE recovery_request_id=$3 AND status='active'",
    )
    .bind(transition_id)
    .bind(at)
    .bind(recovery_request_id)
    .execute(&mut **tx)
    .await
    .expect("consume reservation");
    sqlx::query(
        "UPDATE chat.leaf_recovery_requests SET status='fulfilled',\
             fulfilling_transition_id=$1,terminal_at=$2 \
             WHERE recovery_request_id=$3 AND status='open'",
    )
    .bind(transition_id)
    .bind(at)
    .bind(recovery_request_id)
    .execute(&mut **tx)
    .await
    .expect("fulfill leaf recovery request");
    // The fulfilled 'add' recovery must own exactly one Welcome delivery.
    let welcome_id = Uuid::new_v4();
    let welcome_wrapper = vec![0x41_u8; 16];
    sqlx::query(
        r#"INSERT INTO chat.welcome_bundles(
            welcome_id,conversation_id,transition_id,entry_seq,generation,state_version,
            group_id,epoch,group_context_hash,confirmation_tag,wrapper_bytes,
            wrapper_sha256,created_at
        ) VALUES($1,$2,$3,4,0,2,$4,1,$5,$6,$7,$8,$9)"#,
    )
    .bind(welcome_id)
    .bind(cid)
    .bind(transition_id)
    .bind(&graph.group_id)
    .bind(vec![0x21_u8; 32])
    .bind(vec![0x22_u8; 32])
    .bind(&welcome_wrapper)
    .bind(Sha256::digest(&welcome_wrapper).to_vec())
    .bind(at)
    .execute(&mut **tx)
    .await
    .expect("insert welcome bundle");
    sqlx::query(
        r#"INSERT INTO chat.welcome_deliveries(
            welcome_id,recipient_did,recipient_device_id,recovery_request_id,
            key_package_ref,expires_at,status
        ) VALUES($1,$2,$3,$4,$5,$6,'pending')"#,
    )
    .bind(welcome_id)
    .bind(did)
    .bind(device_id)
    .bind(recovery_request_id)
    .bind(key_package_ref)
    .bind(not_after)
    .execute(&mut **tx)
    .await
    .expect("insert pending welcome delivery");

    sqlx::query(
        r#"INSERT INTO chat.member_devices(
            leaf_period_id,participant_period_id,conversation_id,generation,user_did,
            device_id,leaf_index,basic_credential,leaf_signature_key,leaf_key_id,
            leaf_auth_generation,origin,join_key_package_ref,joined_state_version,
            joined_transition_id,joined_seq,active,created_at
        ) VALUES($1,$2,$3,0,$4,$5,1,$6,$7,$8,1,'keyPackage',$9,2,$10,4,true,$11)"#,
    )
    .bind(leaf_period_id)
    .bind(participant_period_id)
    .bind(cid)
    .bind(did)
    .bind(device_id)
    .bind(&basic_credential)
    .bind(public_key)
    .bind(key_id)
    .bind(key_package_ref)
    .bind(transition_id)
    .bind(at)
    .execute(&mut **tx)
    .await
    .expect("Add member leaf");
    sqlx::query(
        r#"INSERT INTO chat.application_intervals(
            membership_interval_id,conversation_id,generation,recipient_did,
            recipient_device_id,start_seq,opening_kind,opening_transition_id,
            opening_outer_entry_fingerprint,opening_state_version,opening_group_id,
            opening_epoch,opening_group_context_hash,opening_confirmation_tag,
            opening_leaf_period_id,created_at
        ) VALUES($1,$2,0,$3,$4,4,'add',$1,$5,2,$6,1,$7,$8,$9,$10)"#,
    )
    .bind(transition_id)
    .bind(cid)
    .bind(did)
    .bind(device_id)
    .bind(&fingerprint)
    .bind(&graph.group_id)
    .bind(vec![0x21_u8; 32])
    .bind(vec![0x22_u8; 32])
    .bind(leaf_period_id)
    .bind(at)
    .execute(&mut **tx)
    .await
    .expect("open Add interval");

    (transition_id, fingerprint)
}

/// Committed leaveRequest control edge at seq 5: appends the
/// `leaveRequestEntry` (transition_id NULL, coordinate unchanged at (0,2)),
/// inserts the pending 24h-consent `leave_requests` row bound to the current
/// coordinate, and routes the control entry to the requester. Mirrors the
/// production `apply_leave_request` executor arm exactly: the head CAS advances
/// ONLY the seq counter, the entry carries NULL generation/state_version/
/// transition_id, and the row's signed material is byte-equal to the entry's
/// (`assert_leave_request_mapping` / `assert_control_request_entry`).
async fn commit_leave_request(
    tx: &mut Transaction<'_, Postgres>,
    graph: &CreationGraph,
    did: &str,
    device_id: Uuid,
    key_id: &str,
    at: DateTime<Utc>,
) -> (Uuid, Vec<u8>) {
    let cid = graph.conversation_id;
    let leave_request_id = Uuid::new_v4();
    let entry_id = Uuid::new_v4();
    let fingerprint = vec![0x43_u8; 32];
    let signed_request = vec![0x48_u8; 8];
    let signing_transcript = vec![0x49_u8; 16];
    let request_digest = Sha256::digest(&signing_transcript).to_vec();
    let signature = vec![0x4A_u8; 64];

    // Head CAS: advance ONLY the seq counter (coordinate unchanged at (0,2)).
    let updated = sqlx::query(
        "UPDATE chat.conversations SET next_entry_seq=6 \
             WHERE conversation_id=$1 AND current_generation=0 \
               AND current_state_version=2 AND next_entry_seq=5",
    )
    .bind(cid)
    .execute(&mut **tx)
    .await
    .expect("advance head through leave request");
    assert_eq!(updated.rows_affected(), 1, "exact leave request head CAS");

    // The request entry (leaveRequestEntry carries no transition_id; the
    // coordinate columns are NULL, exactly as `apply_leave_request` nulls them).
    sqlx::query(
        r#"INSERT INTO chat.entries(
            conversation_id,seq,entry_id,entry_kind,accepted_payload_bytes,
            accepted_payload_sha256,signed_request_bytes,request_digest,signature,
            server_fields_bytes,outer_entry_fingerprint,actor_did,actor_device_id,
            actor_key_id,actor_auth_generation,generation,state_version,transition_id,
            received_at
        ) VALUES($1,5,$2,'blue.catbird.chat.defs#leaveRequestEntry',
            $3,$4,$5,$6,$7,$8,$9,$10,$11,$12,1,NULL,NULL,NULL,$13)"#,
    )
    .bind(cid)
    .bind(entry_id)
    .bind(&signed_request)
    .bind(Sha256::digest(&signed_request).to_vec())
    .bind(&signed_request)
    .bind(&request_digest)
    .bind(&signature)
    .bind(vec![0x00_u8])
    .bind(&fingerprint)
    .bind(did)
    .bind(device_id)
    .bind(key_id)
    .bind(at)
    .execute(&mut **tx)
    .await
    .expect("leave request entry");

    // Pending leave request for the requester, bound to the current coordinate
    // (0,2) with the Add state's epoch-1 context; signed material is byte-equal
    // to the entry's and `expires_at = received_at + 24h` (DB-required).
    sqlx::query(
        r#"INSERT INTO chat.leave_requests(
            leave_request_id,conversation_id,requester_did,requester_device_id,
            requester_key_id,requester_auth_generation,prior_generation,prior_state_version,
            prior_group_id,prior_epoch,prior_group_context_hash,prior_confirmation_tag,
            status,signed_request_bytes,signing_transcript_bytes,request_digest,signature,
            received_at,expires_at
        ) VALUES($1,$2,$3,$4,$5,1,0,2,$6,1,$7,$8,'pending',$9,$10,$11,$12,$13,$14)"#,
    )
    .bind(leave_request_id)
    .bind(cid)
    .bind(did)
    .bind(device_id)
    .bind(key_id)
    .bind(&graph.group_id)
    .bind(vec![0x21_u8; 32])
    .bind(vec![0x22_u8; 32])
    .bind(&signed_request)
    .bind(&signing_transcript)
    .bind(&request_digest)
    .bind(&signature)
    .bind(at)
    .bind(at + Duration::hours(24))
    .execute(&mut **tx)
    .await
    .expect("insert pending leave request");

    // Control audience: the requester's device can fetch the leaveRequestEntry.
    sqlx::query(
        r#"INSERT INTO chat.entry_recipients(
            conversation_id,seq,user_did,device_id,entitlement_kind
        ) VALUES($1,5,$2,$3,'control')"#,
    )
    .bind(cid)
    .bind(did)
    .bind(device_id)
    .execute(&mut **tx)
    .await
    .expect("route leave request to requester");

    (leave_request_id, request_digest)
}

/// Committed leaveCommit (remove) edge at seq 7: closes `did`'s leaf,
/// interval, and participant and fulfills the pending leave request seeded at
/// seq 5 by `commit_leave_request`.
#[allow(clippy::too_many_arguments)]
async fn commit_remove_member(
    tx: &mut Transaction<'_, Postgres>,
    graph: &CreationGraph,
    did: &str,
    device_id: Uuid,
    leaf_period_id: Uuid,
    participant_period_id: Uuid,
    leave_request_id: Uuid,
    at: DateTime<Utc>,
) -> Uuid {
    let cid = graph.conversation_id;
    let transition_id = Uuid::new_v4();
    let entry_id = Uuid::new_v4();
    let metadata_snapshot_id = Uuid::new_v4();
    let fingerprint = vec![0x44_u8; 32];
    let snapshot = vec![0x45_u8; 8];
    let tree_summary = vec![0x46_u8; 8];
    let payload = vec![0x47_u8; 8];
    let signed_request = vec![0x48_u8; 8];
    let signing_transcript = vec![0x49_u8; 16];
    let request_digest = Sha256::digest(&signing_transcript).to_vec();
    let signature = vec![0x4A_u8; 64];
    let metadata_ciphertext = vec![0x4B_u8; 16];

    let updated = sqlx::query(
        "UPDATE chat.conversations SET current_state_version=3,next_entry_seq=8 \
             WHERE conversation_id=$1 AND current_generation=0 \
               AND current_state_version=2 AND next_entry_seq=7",
    )
    .bind(cid)
    .execute(&mut **tx)
    .await
    .expect("advance head through remove");
    assert_eq!(updated.rows_affected(), 1, "exact remove head CAS");
    let updated = sqlx::query(
        "UPDATE chat.generations SET current_state_version=3 \
             WHERE conversation_id=$1 AND generation=0 AND current_state_version=2",
    )
    .bind(cid)
    .execute(&mut **tx)
    .await
    .expect("advance generation through remove");
    assert_eq!(updated.rows_affected(), 1, "exact remove generation CAS");

    sqlx::query(
        r#"INSERT INTO chat.transitions(
            transition_id,conversation_id,kind,actor_did,actor_device_id,actor_key_id,
            actor_auth_generation,actor_role,actor_device_status,signed_request_bytes,
            unsigned_projection_bytes,signing_transcript_bytes,request_digest,signature,
            prior_generation,prior_state_version,next_generation,next_state_version,
            metadata_snapshot_id,entry_seq,accepted_at
        ) VALUES($1,$2,'leaveCommit',$3,$4,$5,1,'admin','active',$6,$7,$8,$9,$10,
            0,2,0,3,$11,7,$12)"#,
    )
    .bind(transition_id)
    .bind(cid)
    .bind(&graph.actor_did)
    .bind(graph.actor_device_id)
    .bind(&graph.actor_key_id)
    .bind(&signed_request)
    .bind(&signed_request)
    .bind(&signing_transcript)
    .bind(&request_digest)
    .bind(&signature)
    .bind(metadata_snapshot_id)
    .bind(at)
    .execute(&mut **tx)
    .await
    .expect("remove transition");
    sqlx::query(
        r#"INSERT INTO chat.generation_states(
            conversation_id,generation,state_version,group_id,epoch,group_context_hash,
            confirmation_tag,lifecycle,state_kind,producing_transition_id,
            public_snapshot_bytes,snapshot_sha256,tree_summary_bytes,tree_summary_sha256,
            leaf_count,created_at
        ) VALUES($1,0,3,$2,2,$3,$4,'active','commit',$5,$6,$7,$8,$9,1,$10)"#,
    )
    .bind(cid)
    .bind(&graph.group_id)
    .bind(vec![0x23_u8; 32])
    .bind(vec![0x24_u8; 32])
    .bind(transition_id)
    .bind(&snapshot)
    .bind(Sha256::digest(&snapshot).to_vec())
    .bind(&tree_summary)
    .bind(Sha256::digest(&tree_summary).to_vec())
    .bind(at)
    .execute(&mut **tx)
    .await
    .expect("remove generation state");
    sqlx::query(
        r#"INSERT INTO chat.metadata_snapshots(
            metadata_snapshot_id,conversation_id,generation,state_version,group_id,epoch,
            group_context_hash,confirmation_tag,producing_transition_id,
            origin_transition_id,metadata_version,nonce,ciphertext,ciphertext_sha256,
            ciphertext_size,author_did,author_device_id,author_key_id,author_public_key,
            author_auth_generation,author_origin_seq,author_role,author_device_status,created_at
        ) VALUES($1,$2,0,3,$3,2,$4,$5,$6,$7,1,$8,$9,$10,16,$11,$12,$13,$14,
            1,1,'admin','active',$15)"#,
    )
    .bind(metadata_snapshot_id)
    .bind(cid)
    .bind(&graph.group_id)
    .bind(vec![0x23_u8; 32])
    .bind(vec![0x24_u8; 32])
    .bind(transition_id)
    .bind(graph.creation_transition_id)
    .bind(vec![0x4C_u8; 12])
    .bind(&metadata_ciphertext)
    .bind(Sha256::digest(&metadata_ciphertext).to_vec())
    .bind(&graph.actor_did)
    .bind(graph.actor_device_id)
    .bind(&graph.actor_key_id)
    .bind(&graph.actor_public_key)
    .bind(at)
    .execute(&mut **tx)
    .await
    .expect("remove metadata snapshot");
    sqlx::query(
        r#"INSERT INTO chat.entries(
            conversation_id,seq,entry_id,entry_kind,accepted_payload_bytes,
            accepted_payload_sha256,signed_request_bytes,request_digest,signature,
            server_fields_bytes,outer_entry_fingerprint,actor_did,actor_device_id,
            actor_key_id,actor_auth_generation,generation,state_version,transition_id,
            received_at
        ) VALUES($1,7,$2,'blue.catbird.chat.defs#leaveCommitFulfillmentEntry',
            $3,$4,$5,$6,$7,$8,$9,$10,$11,$12,1,0,3,$13,$14)"#,
    )
    .bind(cid)
    .bind(entry_id)
    .bind(&payload)
    .bind(Sha256::digest(&payload).to_vec())
    .bind(&signed_request)
    .bind(&request_digest)
    .bind(&signature)
    .bind(vec![0x00_u8])
    .bind(&fingerprint)
    .bind(&graph.actor_did)
    .bind(graph.actor_device_id)
    .bind(&graph.actor_key_id)
    .bind(transition_id)
    .bind(at)
    .execute(&mut **tx)
    .await
    .expect("remove entry");
    sqlx::query(
        r#"INSERT INTO chat.entry_recipients(
            conversation_id,seq,user_did,device_id,entitlement_kind
        ) VALUES($1,7,$2,$3,'control')"#,
    )
    .bind(cid)
    .bind(&graph.actor_did)
    .bind(graph.actor_device_id)
    .execute(&mut **tx)
    .await
    .expect("route remove fulfillment to admin");
    sqlx::query(
        r#"INSERT INTO chat.entry_recipients(
            conversation_id,seq,user_did,device_id,entitlement_kind
        ) VALUES($1,7,$2,$3,'intervalClose')"#,
    )
    .bind(cid)
    .bind(did)
    .bind(device_id)
    .execute(&mut **tx)
    .await
    .expect("route interval close to removed member");

    let updated = sqlx::query(
        r#"UPDATE chat.member_devices
                  SET removed_state_version=3,removed_transition_id=$2,removed_seq=7,
                      removed_at=$3,active=FALSE
                WHERE leaf_period_id=$1 AND active"#,
    )
    .bind(leaf_period_id)
    .bind(transition_id)
    .bind(at)
    .execute(&mut **tx)
    .await
    .expect("close removed leaf");
    assert_eq!(updated.rows_affected(), 1);
    let updated = sqlx::query(
        r#"UPDATE chat.application_intervals
                  SET terminal_seq=7,closing_state_version=3,closing_transition_id=$2,
                      closing_outer_entry_fingerprint=$3,closing_kind='remove',
                      closing_leaf_period_id=$1,removed_at=$4
                WHERE opening_leaf_period_id=$1 AND terminal_seq IS NULL"#,
    )
    .bind(leaf_period_id)
    .bind(transition_id)
    .bind(&fingerprint)
    .bind(at)
    .execute(&mut **tx)
    .await
    .expect("close removed interval");
    assert_eq!(updated.rows_affected(), 1);
    let updated = sqlx::query(
        r#"UPDATE chat.participants
                  SET removing_transition_id=$2,removing_seq=7,removed_at=$3,
                      current_membership=FALSE
                WHERE participant_period_id=$1 AND current_membership"#,
    )
    .bind(participant_period_id)
    .bind(transition_id)
    .bind(at)
    .execute(&mut **tx)
    .await
    .expect("remove participant period");
    assert_eq!(updated.rows_affected(), 1);
    let updated = sqlx::query(
        r#"UPDATE chat.leave_requests
                  SET status='fulfilled',terminal_request_digest=$2,
                      terminal_transition_id=$3,terminal_at=$4
                WHERE leave_request_id=$1 AND status='pending'"#,
    )
    .bind(leave_request_id)
    .bind(&request_digest)
    .bind(transition_id)
    .bind(at)
    .execute(&mut **tx)
    .await
    .expect("fulfill leave request");
    assert_eq!(updated.rows_affected(), 1);

    transition_id
}

#[tokio::test]
#[ignore = "requires the disposable local MinIO fixture (see file docs); run explicitly with --ignored"]
async fn s3_denies_lost_membership_after_committed_removal() {
    let pool: PgPool = common::chat_protocol::setup_chat_protocol_db(4).await;
    http::ensure_fence(&pool).await;
    let mut tx = pool.begin().await.expect("begin membership graph");
    let owner = random_plc_did();
    let graph = seed_creation_graph_tx(&mut tx, &owner, None).await;
    let now = graph.accepted_at;

    // seq 2: the creator sends an application entry.
    resolve_application_send(
        &mut tx,
        &coherent_app_send(&graph, 0x31, now),
        ApplicationSendDisposition::Accept,
    )
    .await
    .expect("creator send at seq 2");

    // seq 3: committed Add — Bob joins with an open interval at start_seq 3.
    // Bob is route-capable (real DPoP p256 material) so the pre/post-removal
    // fetches can cross the production handler too.
    let bob_did = random_plc_did();
    let bob_signing = http::random_p256();
    let bob_jwk = http::public_jwk(&bob_signing);
    let bob_jkt = http::jwk_thumbprint(&bob_jwk);
    let bob_device = Uuid::new_v4();
    let bob_public_key = random_ref();
    let bob_key: String = sqlx::query_scalar("SELECT chat.ed25519_key_id($1)")
        .bind(&bob_public_key)
        .fetch_one(&mut *tx)
        .await
        .expect("bob key id");
    sqlx::query("INSERT INTO chat.principals(user_did,created_at) VALUES($1,$2)")
        .bind(&bob_did)
        .bind(now)
        .execute(&mut *tx)
        .await
        .expect("bob principal");
    sqlx::query(
        "INSERT INTO chat.devices(user_did,device_id,device_name,status,dpop_jkt,auth_generation,capabilities,created_at,updated_at) VALUES($1,$2,'bob','active',$3,1,chat.protocol_capabilities(),$4,$4)",
    )
    .bind(&bob_did)
    .bind(bob_device)
    .bind(&bob_jkt)
    .bind(now)
    .execute(&mut *tx)
    .await
    .expect("bob device");
    sqlx::query(
        "INSERT INTO chat.device_keys(user_did,device_id,key_id,signing_public_key,enrollment_auth_generation,created_at) VALUES($1,$2,$3,$4,1,$5)",
    )
    .bind(&bob_did)
    .bind(bob_device)
    .bind(&bob_key)
    .bind(&bob_public_key)
    .bind(now)
    .execute(&mut *tx)
    .await
    .expect("bob device key");
    let bob = http::Device {
        did: bob_did.clone(),
        device_id: bob_device,
        signing: bob_signing,
        jwk: bob_jwk,
        jkt: bob_jkt,
    };
    http::cache_device_did(&bob).await;
    let bob_leaf = Uuid::new_v4();
    let bob_participant = Uuid::new_v4();
    let bob_key_package_ref = Sha256::digest(Uuid::new_v4().as_bytes()).to_vec();
    commit_add_member(
        &mut tx,
        &graph,
        &bob_did,
        bob_device,
        &bob_key,
        &bob_public_key,
        bob_leaf,
        bob_participant,
        &bob_key_package_ref,
        now + Duration::seconds(5),
    )
    .await;

    // seq 5: Bob's committed leaveRequest control edge — the pending
    // 24h-consent leave_requests row + its leaveRequestEntry (transition_id
    // NULL, coordinate unchanged at (0,2)), exactly as production materializes
    // it. The leaveCommit that fulfills it lands at seq 7.
    let (bob_leave_request_id, _) = commit_leave_request(
        &mut tx,
        &graph,
        &bob_did,
        bob_device,
        &bob_key,
        now + Duration::seconds(15),
    )
    .await;

    // seq 6: Bob sends an application entry on head state (0,2) and binds a
    // real ciphertext blob to it.
    let send_bob = app_send_for(&graph, &bob_did, bob_device, &bob_key, 0x32, now, 2);
    let bob_message_id = send_bob.entry.message_id.expect("bob message id");
    let outcome = resolve_application_send(&mut tx, &send_bob, ApplicationSendDisposition::Accept)
        .await
        .expect("bob send at seq 6");
    assert_eq!(outcome, ApplicationSendOutcome::Accepted { seq: 6 });

    let ciphertext = ciphertext_bytes();
    let ct_sha: [u8; 32] = Sha256::digest(&ciphertext).into();
    let blob_id = Uuid::new_v4();
    let request = PrepareBlobRequest {
        blob_id,
        owner_did: bob_did.clone(),
        owner_device_id: bob_device,
        owner_key_id: bob_key.clone(),
        owner_auth_generation: 1,
        purpose: BlobPurpose::Attachment,
        media_type: MEDIA,
        plaintext_size: PLAINTEXT_SIZE,
        ciphertext_size: CIPHERTEXT_SIZE,
        ciphertext_sha256: ct_sha.to_vec(),
        ticket_hash: fresh_ticket_hash(),
        prepared_at: now,
    };
    prepare_blob(&mut tx, &request).await.expect("bob prepare");
    let store = fixture_store().await;
    let cid = deterministic_object_key(blob_id, &ct_sha);
    store
        .put_for_blob(blob_id, ciphertext.clone(), &ct_sha, MEDIA_STR)
        .await
        .expect("bob store exact ciphertext");
    let uploaded_at = now + Duration::seconds(10);
    complete_upload(
        &mut tx,
        blob_id,
        &bob_did,
        bob_device,
        CIPHERTEXT_SIZE,
        &request.ticket_hash,
        uploaded_at,
        &cid,
    )
    .await
    .expect("bob complete");
    let descriptor_bytes = vec![0xAB; 40];
    let aad_bytes = vec![0xCD; 24];
    bind_application_blob(
        &mut tx,
        &NewBlobBinding {
            blob_id,
            binding_kind: BindingKind::Application,
            conversation_id: graph.conversation_id,
            entry_seq: Some(6),
            message_id: Some(bob_message_id),
            metadata_origin_transition_id: None,
            metadata_version: None,
            owner_did: bob_did.clone(),
            owner_device_id: bob_device,
            descriptor_bytes: descriptor_bytes.clone(),
            descriptor_sha256: Sha256::digest(&descriptor_bytes).to_vec(),
            aad_bytes: aad_bytes.clone(),
            aad_sha256: Sha256::digest(&aad_bytes).to_vec(),
            ciphertext_sha256: ct_sha.to_vec(),
            plaintext_size: PLAINTEXT_SIZE,
            ciphertext_size: CIPHERTEXT_SIZE,
            purpose: BlobPurpose::Attachment,
            bound_at: now + Duration::seconds(20),
            uploaded_at,
            unbound_expires_at: uploaded_at + Duration::hours(1),
        },
    )
    .await
    .expect("bob bind");
    tx.commit().await.expect("commit add + bob send + bind");

    // Bob fetches through the production handler while still a member.
    let router = route_router(pool.clone()).await;
    let (pre_status, pre_bytes) = route_fetch_bytes(&router, &bob, blob_id).await;
    assert_eq!(
        pre_status,
        axum::http::StatusCode::OK,
        "Bob must fetch while a member, got {pre_status}"
    );
    assert_eq!(pre_bytes, ciphertext);

    // Bob mints a one-use capability while his interval [4, open] spans seq 6.
    let fixture = BoundFixture {
        graph: graph.clone(),
        blob_id,
        ciphertext: ciphertext.clone(),
        ct_sha,
        cid: cid.clone(),
        owner_did: bob_did.clone(),
        owner_device_id: bob_device,
        entry_seq: 6,
    };
    let capability = authorize(&pool, &fixture, &bob_did, bob_device, 1)
        .await
        .expect("bob authorizes while a member");

    // seq 7: committed removal — Bob's interval closes at terminal_seq 7.
    let mut tx = pool.begin().await.expect("begin removal");
    commit_remove_member(
        &mut tx,
        &graph,
        &bob_did,
        bob_device,
        bob_leaf,
        bob_participant,
        bob_leave_request_id,
        now + Duration::seconds(30),
    )
    .await;
    tx.commit().await.expect("commit removal");
    let (terminal_seq, active): (Option<i64>, bool) = sqlx::query_as(
        "SELECT i.terminal_seq, m.active \
           FROM chat.application_intervals i \
           JOIN chat.member_devices m ON m.leaf_period_id = i.opening_leaf_period_id \
          WHERE i.recipient_did = $1 AND i.recipient_device_id = $2 AND i.start_seq = 4",
    )
    .bind(&bob_did)
    .bind(bob_device)
    .fetch_one(&pool)
    .await
    .expect("closed interval");
    assert_eq!(terminal_seq, Some(7), "interval must be closed at seq 7");
    assert!(!active, "leaf must be closed");

    // The pre-removal capability is revalidated against the closed interval:
    // fence terminal_seq (NULL at mint) no longer matches -> deny, with no
    // object-store request made. This is the lost-membership denial.
    let result = capability.consume_for_storage(&pool).await;
    assert!(
        matches!(result, Err(BlobRepositoryError::NotAuthorized)),
        "lost membership must deny the consume revalidation, got {result:?}"
    );
    // Route-level: a FRESH authorization re-checks the interval span, and the
    // blob's entry_seq 6 lies inside Bob's now-closed interval [4,7] — the
    // production entitlement model keeps a removed member's read access to
    // blobs bound to entries within their interval. The pre-minted capability
    // is dead (fence mismatch above); the fresh fetch is production-correct
    // and must return the exact bytes, never a different tenant's object.
    let (post_status, post_bytes) = route_fetch_bytes(&router, &bob, blob_id).await;
    assert_eq!(
        post_status,
        axum::http::StatusCode::OK,
        "interval-span entitlement must still authorize the fresh fetch"
    );
    assert_eq!(
        post_bytes, ciphertext,
        "fresh fetch must return the exact bound ciphertext"
    );
    println!(
        "s3_denies_lost_membership: blob_id={blob_id} cid={cid} bob_removed_terminal_seq=7 -> capability NotAuthorized (fence mismatch, no disclosure); fresh route fetch OK (interval [4,7] spans entry_seq 6)"
    );

    let store = fixture_store().await;
    store.delete(&cid).await.expect("cleanup delete");
}

// ===========================================================================
// Expiry GC: the production expiry sweeper terminalizes the overdue blob
// (24h grace already elapsed because the fixture is seeded in the past), then
// the production object-GC deletes the exact S3 object and marks the row
// reclaimed in the same transaction. Rerun is a no-op (idempotent).
// ===========================================================================

async fn cutover_runtime(pool: &PgPool) -> Arc<ChatRuntime> {
    // The clean-chat runtime requires the cursor sealer configuration that the
    // route harness also installs (fence row + sealing secret).
    http::ensure_fence(pool).await;
    let key_id: String = sqlx::query_scalar(
        "SELECT cursor_key_id FROM chat.protocol_instances WHERE singleton=TRUE",
    )
    .fetch_one(pool)
    .await
    .expect("cursor key");
    std::env::set_var("CHAT_NEST_ISSUER", "did:web:api.catbird.blue");
    std::env::set_var("CHAT_NEST_AUDIENCE", "did:web:chat.catbird.blue");
    std::env::set_var("CHAT_NEST_KEY_ID", http::NEST_KEY_ID);
    let point = p256::ecdsa::SigningKey::from_bytes((&[0x5a_u8; 32]).into())
        .expect("nest signing key")
        .verifying_key()
        .to_encoded_point(false);
    std::env::set_var("CHAT_NEST_VERIFYING_KEY", STANDARD.encode(point.as_bytes()));
    std::env::set_var("CHAT_INSTANCE_ID", "018f3f6a-7b2c-4d91-8a5e-0f123456789a");
    std::env::set_var("CHAT_EXTERNAL_BASE", "https://chat.example.net");
    std::env::set_var("CHAT_CURSOR_KEY_ID", key_id);
    std::env::set_var(
        "CHAT_CURSOR_SEALING_SECRET",
        URL_SAFE_NO_PAD.encode([0xA5_u8; 32]),
    );
    std::env::set_var(
        "CHAT_SUBSCRIPTION_ENDPOINT",
        "wss://chat.example.net/xrpc/blue.catbird.chat.subscribeEvents",
    );
    std::env::set_var("CHAT_CUTOVER_ENABLED", "1");
    std::env::set_var("CHAT_EXPIRY_SWEEP_INTERVAL_SECS", "1");
    let runtime =
        Arc::new(ChatRuntime::from_env(Arc::new(SseState::new(64))).expect("cutover runtime"));
    std::env::set_var("CHAT_CUTOVER_ENABLED", "0");
    runtime
}

#[tokio::test]
#[ignore = "requires the disposable local MinIO fixture (see file docs); run explicitly with --ignored"]
async fn s3_expiry_gc_deletes_exact_object_then_reclaims_idempotently() {
    let _ = tracing_subscriber::fmt()
        .with_test_writer()
        .with_max_level(tracing::Level::DEBUG)
        .try_init();
    let pool: PgPool = common::chat_protocol::setup_chat_protocol_db(4).await;
    let client = raw_s3_client();
    let store = fixture_store().await;

    // Seed a completedUnbound blob whose unbound window expired ~25.5h ago, so
    // `expired_at + 24h` (the trigger's GC grace) is already ~1.5h in the past:
    // the very first sweep cycle can expire it AND reclaim the object.
    let mut tx = pool.begin().await.expect("begin gc fixture");
    let now = clock_now(&mut tx).await;
    let seed_now = now - Duration::hours(25) - Duration::minutes(30);
    let prepared_at = seed_now - Duration::minutes(4);
    let uploaded_at = seed_now;
    let owner = random_plc_did();
    let (device_id, key_id) = seed_owner_tx(&mut tx, &owner).await;
    let ciphertext = ciphertext_bytes();
    let ct_sha: [u8; 32] = Sha256::digest(&ciphertext).into();
    let blob_id = Uuid::new_v4();
    let request = PrepareBlobRequest {
        blob_id,
        owner_did: owner.clone(),
        owner_device_id: device_id,
        owner_key_id: key_id.clone(),
        owner_auth_generation: 1,
        purpose: BlobPurpose::Attachment,
        media_type: MEDIA,
        plaintext_size: PLAINTEXT_SIZE,
        ciphertext_size: CIPHERTEXT_SIZE,
        ciphertext_sha256: ct_sha.to_vec(),
        ticket_hash: fresh_ticket_hash(),
        prepared_at,
    };
    prepare_blob(&mut tx, &request).await.expect("gc prepare");

    let cid = deterministic_object_key(blob_id, &ct_sha);
    store
        .put_for_blob(blob_id, ciphertext.clone(), &ct_sha, MEDIA_STR)
        .await
        .expect("gc store exact ciphertext");
    complete_upload(
        &mut tx,
        blob_id,
        &owner,
        device_id,
        CIPHERTEXT_SIZE,
        &request.ticket_hash,
        uploaded_at,
        &cid,
    )
    .await
    .expect("gc complete");
    tx.commit().await.expect("commit gc fixture");

    let physical_key = fixture_physical_key(&cid);
    assert!(
        object_exists(&client, &physical_key).await,
        "object must exist before the sweep"
    );
    let (status, gc_status, unbound): (String, String, DateTime<Utc>) = sqlx::query_as(
        "SELECT status, object_gc_status, unbound_expires_at FROM chat.blobs WHERE blob_id = $1",
    )
    .bind(blob_id)
    .fetch_one(&pool)
    .await
    .expect("pre-sweep row");
    assert_eq!(status, "completedUnbound");
    assert_eq!(gc_status, "none");
    assert!(
        unbound + Duration::hours(24) <= now,
        "fixture must already be past the 24h GC grace"
    );

    // Production sweeper (real `run_chat_expiry_sweeper_with_blob_store`).
    // The fixture probe pauses inside BlobStore::delete after the S3 DELETE
    // succeeds and before reclaim_due_blob_objects can commit its DB UPDATE.
    let runtime = cutover_runtime(&pool).await;
    let delete_probe = Arc::new(S3FixtureDeleteProbe::new());
    let handle = tokio::spawn({
        let pool = pool.clone();
        let store = store
            .clone()
            .with_s3_fixture_delete_probe(delete_probe.clone());
        let runtime = runtime.clone();
        async move {
            catbird_server::handlers::chat::run_chat_expiry_sweeper_with_blob_store(
                pool, runtime, store,
            )
            .await;
        }
    });

    tokio::time::timeout(
        StdDuration::from_secs(45),
        delete_probe.wait_until_deleted(),
    )
    .await
    .expect("production reclaim must reach the post-S3-delete probe");
    assert!(
        !object_exists(&client, &physical_key).await,
        "production reclaim must delete S3 before its DB reclaim UPDATE"
    );
    let during_delete: (String, String, Option<String>, Option<DateTime<Utc>>) = sqlx::query_as(
        "SELECT status, object_gc_status, object_store_key, object_deleted_at \
             FROM chat.blobs WHERE blob_id = $1",
    )
    .bind(blob_id)
    .fetch_one(&pool)
    .await
    .expect("observe production reclaim row while delete probe is paused");
    assert_eq!(during_delete.0, "expired");
    assert_eq!(during_delete.1, "pending");
    assert_eq!(during_delete.2.as_deref(), Some(cid.as_str()));
    assert!(during_delete.3.is_none());
    println!(
        "s3_expiry_gc_ordering: blob_id={blob_id} production_reclaim=true s3_object_absent=true db_gc_status=pending db_key_retained=true before_reclaim_commit"
    );
    delete_probe.release();
    let started = StdInstant::now();
    let deadline = started + StdDuration::from_secs(45);
    let (reclaimed_gc, reclaimed_deleted): (String, Option<DateTime<Utc>>) = loop {
        let row: Option<(String, Option<DateTime<Utc>>)> = sqlx::query_as(
            "SELECT object_gc_status, object_deleted_at FROM chat.blobs WHERE blob_id = $1",
        )
        .bind(blob_id)
        .fetch_optional(&pool)
        .await
        .expect("poll gc row");
        if let Some((gc, deleted_at)) = row {
            if gc == "reclaimed" {
                println!(
                    "s3_expiry_gc: blob_id={blob_id} reclaimed after {:?}",
                    StdInstant::now().duration_since(started)
                );
                break (gc, deleted_at);
            }
        }
        assert!(
            StdInstant::now() < deadline,
            "sweeper must reclaim the overdue blob within 45s"
        );
        tokio::time::sleep(StdDuration::from_millis(250)).await;
    };
    handle.abort();
    let _ = handle.await;

    // After the production reclaim resumes, the row is terminal + reclaimed
    // with the exact object key cleared.
    assert!(
        !object_exists(&client, &physical_key).await,
        "exact S3 object must be gone once the row is reclaimed"
    );
    let (status, gc, db_key, deleted_at): (String, String, Option<String>, Option<DateTime<Utc>>) =
        sqlx::query_as(
            "SELECT status, object_gc_status, object_store_key, object_deleted_at \
             FROM chat.blobs WHERE blob_id = $1",
        )
        .bind(blob_id)
        .fetch_one(&pool)
        .await
        .expect("reclaimed row");
    assert_eq!(status, "expired");
    assert_eq!(gc, "reclaimed");
    assert_eq!(reclaimed_gc, "reclaimed");
    assert!(db_key.is_none(), "object_store_key cleared on reclaim");
    assert!(reclaimed_deleted.is_some(), "object_deleted_at stamped");
    assert_eq!(deleted_at, reclaimed_deleted);

    // Idempotent rerun: a second sweeper pass finds nothing due for this blob
    // (row already terminal/reclaimed) and S3 DELETE remains idempotent.
    let handle = tokio::spawn({
        let pool = pool.clone();
        let store = store.clone();
        let runtime = runtime.clone();
        async move {
            catbird_server::handlers::chat::run_chat_expiry_sweeper_with_blob_store(
                pool, runtime, store,
            )
            .await;
        }
    });
    tokio::time::sleep(StdDuration::from_secs(3)).await;
    handle.abort();
    let _ = handle.await;
    let after: (String, Option<DateTime<Utc>>, Option<String>) = sqlx::query_as(
        "SELECT object_gc_status, object_deleted_at, object_store_key \
         FROM chat.blobs WHERE blob_id = $1",
    )
    .bind(blob_id)
    .fetch_one(&pool)
    .await
    .expect("post-rerun row");
    assert_eq!(after.0, "reclaimed");
    assert_eq!(after.1, deleted_at, "reclaim timestamp unchanged by rerun");
    assert!(after.2.is_none());
    // S3 DELETE on the already-deleted object is a no-op success.
    store.delete(&cid).await.expect("idempotent S3 delete");
    assert!(!object_exists(&client, &physical_key).await);
    println!(
        "s3_expiry_gc: blob_id={blob_id} cid={cid} status=expired gc=reclaimed object_deleted_at={} rerun=noop",
        deleted_at.expect("stamped")
    );
}

// ===========================================================================
// Cleanup (Step 5): list the exact fixture prefix, verify it contains ONLY
// this fixture's objects, delete them, and prove the prefix is empty. The
// report records the listing; the MinIO container itself is removed by the
// operator after the run (`docker rm -f mls-v2-minio-<initials>`).
// ===========================================================================

#[tokio::test]
#[ignore = "requires the disposable local MinIO fixture (see file docs); run explicitly with --ignored"]
async fn s3_fixture_prefix_cleanup_lists_verifies_and_deletes() {
    let client = raw_s3_client();
    let prefix = FIXTURE_PREFIX.clone();
    let keys = list_prefix(&client, &prefix).await;
    println!("FIXTURE_PREFIX_CLEANUP_LISTING: {keys:?}");
    for key in &keys {
        assert!(
            key.starts_with(&prefix),
            "foreign object inside the fixture prefix: {key}"
        );
        assert!(
            !key[prefix.len()..].contains('/'),
            "unexpected nested key inside the fixture prefix: {key}"
        );
    }
    for key in &keys {
        client
            .delete_object()
            .bucket(&fixture_bucket())
            .key(key)
            .send()
            .await
            .expect("delete fixture object");
    }
    let after = list_prefix(&client, &prefix).await;
    assert!(
        after.is_empty(),
        "fixture prefix must be empty after cleanup, still has {after:?}"
    );
    println!(
        "FIXTURE_PREFIX_CLEANUP: prefix={prefix} objects_before={} objects_after=0",
        keys.len()
    );
}
