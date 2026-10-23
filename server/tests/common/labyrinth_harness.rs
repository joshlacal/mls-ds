//! Shared harness of the Labyrinth backend suites (`tests/labyrinth_*.rs`).
//!
//! Every test owns a fresh, fully migrated database (`labyrinth_srv_`
//! prefix) and drives the real `labyrinth_router` over HTTP with real
//! standard service-auth JWTs (ES256, DID document cached through the
//! test-support hook) and real signed `labyrinthWriteBody` headers.
//!
//! Chat fixtures (principals, devices, keys, conversations, participants,
//! leaves, blobs) are seeded with plain SQL. Conversation-shaped rows are
//! written with `session_replication_role = replica`, which suspends the
//! chat schema's FK and deferred-invariant triggers for that one seeding
//! transaction only (CHECK constraints still apply). That needs a superuser
//! test role, which the local disposable cluster has. Labyrinth rows are
//! never seeded this way: they always go through the handlers.

#![allow(dead_code)]

use std::sync::{Arc, Once};

use axum::{body::Body, extract::FromRef, http::Request, http::StatusCode, Router};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use chrono::{DateTime, Utc};
use ed25519_dalek::{Signer as _, SigningKey as EdKey};
use p256::ecdsa::{Signature as P256Signature, SigningKey as P256Key};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use sqlx::PgPool;
use tower_util::ServiceExt;
use uuid::Uuid;

use catbird_server::blob_store::BlobStore;
use catbird_server::federation::outbound::OutboundClient;
use catbird_server::federation::resolver::ValidatedRemoteDestination;
use catbird_server::federation::{DsResolver, ServiceAuthClient};
use catbird_server::handlers::chat::ChatRuntime;
use catbird_server::handlers::labyrinth::labyrinth_router;
use catbird_server::handlers::labyrinth::relay_client::RelayClient;
use catbird_server::storage::DbPool;

use crate::common::fresh_db::{fresh_fully_migrated_db, DisposableDatabase};

pub const PREFIX: &str = "blue.catbird.labyrinth.";
/// The DS redaction signing seed every test process configures.
pub const REDACTION_SEED: [u8; 32] = [0x5E; 32];

#[derive(Clone)]
struct TestState {
    pool: DbPool,
    runtime: Arc<ChatRuntime>,
    blob_store: BlobStore,
    resolver: Arc<DsResolver>,
    outbound: Arc<OutboundClient>,
    service_auth: Option<Arc<ServiceAuthClient>>,
}

impl FromRef<TestState> for Arc<DsResolver> {
    fn from_ref(state: &TestState) -> Arc<DsResolver> {
        state.resolver.clone()
    }
}
impl FromRef<TestState> for Arc<OutboundClient> {
    fn from_ref(state: &TestState) -> Arc<OutboundClient> {
        state.outbound.clone()
    }
}
impl FromRef<TestState> for Option<Arc<ServiceAuthClient>> {
    fn from_ref(state: &TestState) -> Option<Arc<ServiceAuthClient>> {
        state.service_auth.clone()
    }
}

/// This DS's federation identity in a two-DS relay test: its DID, its
/// service-auth key, and where its one peer (the sequencer) listens.
pub struct Federation {
    pub self_did: String,
    pub key: P256Key,
    pub peer: Option<std::net::SocketAddr>,
}

impl FromRef<TestState> for DbPool {
    fn from_ref(state: &TestState) -> DbPool {
        state.pool.clone()
    }
}
impl FromRef<TestState> for Arc<ChatRuntime> {
    fn from_ref(state: &TestState) -> Arc<ChatRuntime> {
        state.runtime.clone()
    }
}
impl FromRef<TestState> for BlobStore {
    fn from_ref(state: &TestState) -> BlobStore {
        state.blob_store.clone()
    }
}

fn ensure_runtime_env() {
    static ENV: Once = Once::new();
    ENV.call_once(|| {
        std::env::set_var("CHAT_CURSOR_KEY_ID", URL_SAFE_NO_PAD.encode([0x11_u8; 32]));
        std::env::set_var(
            "CHAT_CURSOR_SEALING_SECRET",
            URL_SAFE_NO_PAD.encode([0xA5_u8; 32]),
        );
        std::env::set_var(
            "LABYRINTH_REDACTION_SIGNING_KEY",
            URL_SAFE_NO_PAD.encode(REDACTION_SEED),
        );
        std::env::set_var(
            "LABYRINTH_ATTACHMENT_DIGEST_KEY",
            URL_SAFE_NO_PAD.encode([0x3C_u8; 32]),
        );
        std::env::set_var(
            "CHAT_SUBSCRIPTION_ENDPOINT",
            "wss://chat.example.net/xrpc/blue.catbird.chat.subscribeEvents",
        );
    });
}

/// A chat runtime with the cutover gate as requested.
pub fn runtime(cutover: bool) -> Arc<ChatRuntime> {
    use std::sync::Mutex;
    static LOCK: Mutex<()> = Mutex::new(());
    ensure_runtime_env();
    let _guard = LOCK.lock().unwrap_or_else(|p| p.into_inner());
    if cutover {
        std::env::set_var("CHAT_CUTOVER_ENABLED", "1");
    } else {
        std::env::remove_var("CHAT_CUTOVER_ENABLED");
    }
    Arc::new(
        ChatRuntime::from_env(Arc::new(catbird_server::realtime::SseState::new(8)))
            .expect("chat runtime"),
    )
}

/// One test's database and router.
pub struct Env {
    pub pool: PgPool,
    pub router: Router,
    /// This DS's federation client (federated envs), for draining the
    /// Labyrinth relay outbox.
    pub relay: Option<RelayClient>,
    _db: DisposableDatabase,
}

/// A stored attachment object served by the route-test blob store.
pub struct TestObject {
    pub key: String,
    pub data: Vec<u8>,
}

impl Env {
    pub async fn new() -> Self {
        Self::with(true, None).await
    }

    pub async fn with(cutover: bool, object: Option<&TestObject>) -> Self {
        Self::build(cutover, object, None).await
    }

    /// An env with a federation identity (see [`Federation`]).
    pub async fn federated(federation: Federation, object: Option<&TestObject>) -> Self {
        Self::build(true, object, Some(federation)).await
    }

    async fn build(
        cutover: bool,
        object: Option<&TestObject>,
        federation: Option<Federation>,
    ) -> Self {
        let db = fresh_fully_migrated_db("labyrinth_srv_").await;
        let pool = db.connect(8).await;
        let blob_store = match object {
            None => BlobStore::for_route_tests(),
            Some(o) => BlobStore::for_route_tests_with_object(
                o.key.clone(),
                o.data.clone(),
                Sha256::digest(&o.data).into(),
                String::new(),
                "image/png".to_owned(),
            ),
        };
        let self_did = federation
            .as_ref()
            .map(|f| f.self_did.clone())
            .unwrap_or_else(|| "did:web:labyrinth-test.invalid".to_owned());
        let mut resolver = DsResolver::new(
            pool.clone(),
            reqwest::Client::new(),
            self_did.clone(),
            "https://labyrinth-test.invalid".to_owned(),
            None,
            3600,
        );
        if let Some(addr) = federation.as_ref().and_then(|f| f.peer) {
            resolver = resolver.with_destination_resolver_hook(Arc::new(move |_did| {
                Some(Box::pin(async move {
                    Ok(ValidatedRemoteDestination {
                        url: url::Url::parse(&format!("http://{addr}")).unwrap(),
                        host: "127.0.0.1".to_owned(),
                        addrs: vec![addr],
                    })
                }))
            }));
        }
        let service_auth = federation.as_ref().map(|f| {
            use p256::pkcs8::EncodePrivateKey;
            let pem = f.key.to_pkcs8_pem(p256::pkcs8::LineEnding::LF).unwrap();
            Arc::new(
                ServiceAuthClient::from_es256_pem(f.self_did.clone(), pem.as_bytes(), None)
                    .unwrap(),
            )
        });
        let resolver = Arc::new(resolver);
        let outbound = Arc::new(OutboundClient::new(2, 10));
        let relay = service_auth
            .clone()
            .map(|sa| RelayClient::new(resolver.clone(), outbound.clone(), sa));
        let router = labyrinth_router::<TestState>().with_state(TestState {
            pool: pool.clone(),
            runtime: runtime(cutover),
            blob_store,
            resolver,
            outbound,
            service_auth,
        });
        Self {
            pool,
            router,
            relay,
            _db: db,
        }
    }

    /// Deliver every due relay-outbox job once.
    pub async fn drain_outbox(&self) -> catbird_server::handlers::labyrinth::outbox::Drained {
        let client = self.relay.as_ref().expect("a federated env");
        catbird_server::handlers::labyrinth::outbox::drain_once(&self.pool, client, 100)
            .await
            .expect("outbox pass")
    }

    pub async fn now(&self) -> DateTime<Utc> {
        sqlx::query_scalar("SELECT date_trunc('milliseconds', clock_timestamp())")
            .fetch_one(&self.pool)
            .await
            .expect("clock")
    }

    /// A new account with one active chat device.
    pub async fn account(&self) -> Device {
        self.device_for(&random_did(), random_seed()).await
    }

    /// Another active chat device of `did`, with chat key `seed`.
    pub async fn device_for(&self, did: &str, seed: [u8; 32]) -> Device {
        let device = Device {
            did: did.to_owned(),
            device_id: Uuid::new_v4(),
            chat_key: EdKey::from_bytes(&seed),
            jwt_key: jwt_key_for(did),
            router: self.router.clone(),
        };
        self.insert_device(&device).await;
        device
    }

    /// `device` (registered on another DS) replicated into this DS's chat
    /// device tables, as federation leaves a remote member's device on the
    /// sequencer; the returned handle drives this env's router.
    pub async fn replicate(&self, device: &Device) -> Device {
        let mut copy = device.clone();
        copy.router = self.router.clone();
        self.insert_device(&copy).await;
        copy
    }

    async fn insert_device(&self, device: &Device) {
        let did = device.did.as_str();
        let key = device.chat_pub();
        let now = self.now().await;
        sqlx::query(
            "INSERT INTO chat.principals(user_did, created_at) VALUES ($1, $2) \
             ON CONFLICT DO NOTHING",
        )
        .bind(did)
        .bind(now)
        .execute(&self.pool)
        .await
        .expect("principal");
        let key_id: String = sqlx::query_scalar("SELECT chat.ed25519_key_id($1)")
            .bind(key.as_slice())
            .fetch_one(&self.pool)
            .await
            .expect("key id");
        sqlx::query(
            "INSERT INTO chat.devices(user_did, device_id, device_name, status, dpop_jkt, \
               auth_generation, capabilities, created_at, updated_at) \
             VALUES ($1, $2, 'labyrinth', 'active', $3, 1, chat.protocol_capabilities(), $4, $4)",
        )
        .bind(did)
        .bind(device.device_id)
        .bind(&key_id)
        .bind(now)
        .execute(&self.pool)
        .await
        .expect("device");
        sqlx::query(
            "INSERT INTO chat.device_keys(user_did, device_id, key_id, signing_public_key, \
               enrollment_auth_generation, created_at) VALUES ($1, $2, $3, $4, 1, $5)",
        )
        .bind(did)
        .bind(device.device_id)
        .bind(&key_id)
        .bind(key.as_slice())
        .bind(now)
        .execute(&self.pool)
        .await
        .expect("device key");
        device.cache_did_document().await;
    }

    /// Serve this env's router on loopback (a peer DS for relay tests).
    pub async fn serve(&self) -> std::net::SocketAddr {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let router = self.router.clone();
        tokio::spawn(async move {
            let _ = axum::serve(listener, router).await;
        });
        addr
    }

    /// Revoke a chat device the way chat revocation leaves it.
    pub async fn revoke(&self, device: &Device) {
        let mut tx = self.pool.begin().await.unwrap();
        replica(&mut tx).await;
        let now = self.now().await;
        let revocation = Uuid::new_v4();
        sqlx::query(
            "UPDATE chat.devices SET status = 'revoked', revoked_at = $3, revocation_id = $4 \
              WHERE user_did = $1 AND device_id = $2",
        )
        .bind(&device.did)
        .bind(device.device_id)
        .bind(now)
        .bind(revocation)
        .execute(&mut *tx)
        .await
        .expect("revoke device");
        sqlx::query(
            "UPDATE chat.device_keys SET revoked_at = $3, revocation_id = $4 \
              WHERE user_did = $1 AND device_id = $2",
        )
        .bind(&device.did)
        .bind(device.device_id)
        .bind(now)
        .bind(revocation)
        .execute(&mut *tx)
        .await
        .expect("revoke key");
        tx.commit().await.unwrap();
    }
}

async fn replica(tx: &mut sqlx::Transaction<'_, sqlx::Postgres>) {
    sqlx::query("SET LOCAL session_replication_role = replica")
        .execute(&mut **tx)
        .await
        .expect("replica seeding needs a superuser test role");
}

/// One leaf of a seeded conversation.
pub struct Leaf<'a> {
    pub device: &'a Device,
    pub joined_seq: i64,
    pub removed_seq: Option<i64>,
}

/// A seeded group conversation: participants (current unless every leaf of
/// the DID was removed) and their leaves; `next_entry_seq` positions the
/// chat sequence.
pub async fn seed_conversation(env: &Env, leaves: &[Leaf<'_>], next_entry_seq: i64) -> Uuid {
    seed_conversation_with_id(env, Uuid::new_v4(), leaves, next_entry_seq).await
}

/// [`seed_conversation`] under a given conversation id.
pub async fn seed_conversation_with_id(
    env: &Env,
    conversation_id: Uuid,
    leaves: &[Leaf<'_>],
    next_entry_seq: i64,
) -> Uuid {
    seed_conversation_with_storage(env, conversation_id, leaves, next_entry_seq, None).await
}

/// Fixture creator runs the production immutable storage initializer in the
/// same transaction as the new conversation; no mutable placement override.
pub async fn seed_conversation_with_storage(
    env: &Env,
    conversation_id: Uuid,
    leaves: &[Leaf<'_>],
    next_entry_seq: i64,
    authority: Option<&str>,
) -> Uuid {
    let now = env.now().await;
    let mut tx = env.pool.begin().await.unwrap();
    replica(&mut tx).await;
    sqlx::query(
        "INSERT INTO chat.conversations(conversation_id, kind, lifecycle, current_generation, \
           current_state_version, next_entry_seq, created_at) \
         VALUES ($1, 'group', 'active', 1, 1, $2, $3)",
    )
    .bind(conversation_id)
    .bind(next_entry_seq)
    .bind(now)
    .execute(&mut *tx)
    .await
    .expect("conversation");
    catbird_server::labyrinth::repo::space::initialize(&mut tx, conversation_id, authority)
        .await
        .unwrap();
    insert_members(&mut tx, conversation_id, leaves, now, 0).await;
    tx.commit().await.unwrap();
    conversation_id
}

/// Add participants and their leaves to an existing conversation (a join).
pub async fn add_member(env: &Env, conversation_id: Uuid, leaves: &[Leaf<'_>]) {
    let now = env.now().await;
    let mut tx = env.pool.begin().await.unwrap();
    replica(&mut tx).await;
    insert_members(&mut tx, conversation_id, leaves, now, 1000).await;
    tx.commit().await.unwrap();
}

async fn insert_members(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    conversation_id: Uuid,
    leaves: &[Leaf<'_>],
    now: DateTime<Utc>,
    leaf_index_base: i64,
) {
    let mut periods: Vec<(String, Uuid)> = Vec::new();
    for (index, leaf) in leaves.iter().enumerate() {
        let did = &leaf.device.did;
        let period = match periods.iter().find(|(d, _)| d == did) {
            Some((_, p)) => *p,
            None => {
                let p = Uuid::new_v4();
                let current = leaves
                    .iter()
                    .any(|l| &l.device.did == did && l.removed_seq.is_none());
                let removed_seq = leaves
                    .iter()
                    .filter(|l| &l.device.did == did)
                    .filter_map(|l| l.removed_seq)
                    .max();
                sqlx::query(
                    "INSERT INTO chat.participants(participant_period_id, conversation_id, \
                       user_did, status, role, role_transition_id, role_changed_at, \
                       created_by_did, created_by_device_id, removing_transition_id, \
                       removing_seq, removed_at, current_membership, created_at) \
                     VALUES ($1, $2, $3, 'active', 'admin', $4, $5, $3, $6, $7, $8, $9, $10, $5)",
                )
                .bind(p)
                .bind(conversation_id)
                .bind(did)
                .bind(Uuid::new_v4())
                .bind(now)
                .bind(leaf.device.device_id)
                .bind((!current).then(Uuid::new_v4))
                .bind(if current { None } else { removed_seq })
                .bind((!current).then_some(now))
                .bind(current)
                .execute(&mut **tx)
                .await
                .expect("participant");
                periods.push((did.clone(), p));
                p
            }
        };
        let key = leaf.device.chat_pub();
        let active = leaf.removed_seq.is_none();
        sqlx::query(
            "INSERT INTO chat.member_devices(leaf_period_id, participant_period_id, \
               conversation_id, generation, user_did, device_id, leaf_index, basic_credential, \
               leaf_signature_key, leaf_key_id, leaf_auth_generation, origin, \
               joined_state_version, joined_transition_id, joined_seq, removed_state_version, \
               removed_transition_id, removed_seq, removed_at, active, created_at) \
             VALUES ($1, $2, $3, 1, $4, $5, $6, $7, $8, chat.ed25519_key_id($8), 1, 'genesis', \
               1, $9, $10, $11, $12, $13, $14, $15, $16)",
        )
        .bind(Uuid::new_v4())
        .bind(period)
        .bind(conversation_id)
        .bind(&leaf.device.did)
        .bind(leaf.device.device_id)
        .bind(leaf_index_base + index as i64)
        .bind(format!("{}#{}", leaf.device.did, leaf.device.device_id).into_bytes())
        .bind(key.as_slice())
        .bind(Uuid::new_v4())
        .bind(leaf.joined_seq)
        .bind((!active).then_some(2_i64))
        .bind((!active).then(Uuid::new_v4))
        .bind(leaf.removed_seq)
        .bind((!active).then_some(now))
        .bind(active)
        .bind(now)
        .execute(&mut **tx)
        .await
        .expect("leaf");
    }
}

/// Remove every leaf of `device`'s DID from the conversation at chat seq
/// `removed_seq` and end its participation (a leave).
pub async fn remove_member(env: &Env, conversation_id: Uuid, device: &Device, removed_seq: i64) {
    let now = env.now().await;
    let mut tx = env.pool.begin().await.unwrap();
    replica(&mut tx).await;
    sqlx::query(
        "UPDATE chat.member_devices SET active = FALSE, removed_state_version = 2, \
           removed_transition_id = $3, removed_seq = $4, removed_at = $5 \
          WHERE conversation_id = $1 AND user_did = $2 AND active",
    )
    .bind(conversation_id)
    .bind(&device.did)
    .bind(Uuid::new_v4())
    .bind(removed_seq)
    .bind(now)
    .execute(&mut *tx)
    .await
    .unwrap();
    sqlx::query(
        "UPDATE chat.participants SET current_membership = FALSE, removing_transition_id = $3, \
           removing_seq = $4, removed_at = $5 \
          WHERE conversation_id = $1 AND user_did = $2 AND current_membership",
    )
    .bind(conversation_id)
    .bind(&device.did)
    .bind(Uuid::new_v4())
    .bind(removed_seq)
    .bind(now)
    .execute(&mut *tx)
    .await
    .unwrap();
    tx.commit().await.unwrap();
}

/// Advance a conversation's chat sequence (as MLS entries would).
pub async fn set_next_entry_seq(env: &Env, conversation_id: Uuid, next: i64) {
    let mut tx = env.pool.begin().await.unwrap();
    replica(&mut tx).await;
    sqlx::query("UPDATE chat.conversations SET next_entry_seq = $2 WHERE conversation_id = $1")
        .bind(conversation_id)
        .bind(next)
        .execute(&mut *tx)
        .await
        .unwrap();
    tx.commit().await.unwrap();
}

/// Mark a conversation as sequenced by another DS.
pub async fn make_remote(env: &Env, conversation_id: Uuid) {
    let mut tx = env.pool.begin().await.unwrap();
    replica(&mut tx).await;
    sqlx::query(
        "UPDATE chat.conversations SET is_remote = TRUE, sequencer_ds = 'did:web:other.catbird.blue' \
          WHERE conversation_id = $1",
    )
    .bind(conversation_id)
    .execute(&mut *tx)
    .await
    .unwrap();
    tx.commit().await.unwrap();
}

/// An uploaded attachment blob owned by `owner`, stored at `object.key`.
pub async fn seed_attachment_blob(env: &Env, owner: &Device, object: &TestObject) -> Uuid {
    let blob_id = Uuid::new_v4();
    let now = env.now().await;
    let mut tx = env.pool.begin().await.unwrap();
    replica(&mut tx).await;
    let size = object.data.len() as i64;
    sqlx::query(
        "INSERT INTO chat.blobs(blob_id, owner_did, owner_device_id, owner_key_id, \
           owner_auth_generation, purpose, media_type, plaintext_size, ciphertext_size, \
           ciphertext_sha256, object_store_key, status, prepared_at, upload_expires_at, \
           uploaded_at, unbound_expires_at) \
         VALUES ($1, $2, $3, chat.ed25519_key_id($4), 1, 'attachment', 'image/png', $5, $6, $7, \
           $8, 'completedUnbound', $9, $9 + INTERVAL '5 minutes', $9, $9 + INTERVAL '1 hour')",
    )
    .bind(blob_id)
    .bind(&owner.did)
    .bind(owner.device_id)
    .bind(owner.chat_pub().as_slice())
    .bind(size - 16)
    .bind(size)
    .bind(Sha256::digest(&object.data).to_vec())
    .bind(&object.key)
    .bind(now)
    .execute(&mut *tx)
    .await
    .expect("blob");
    tx.commit().await.unwrap();
    blob_id
}

/// A bound attachment blob of `conversation`: uploaded by `owner`, stored at
/// `object.key`, bound to chat message `message_id` at entry `entry_seq`.
pub async fn seed_bound_attachment(
    env: &Env,
    owner: &Device,
    conversation: Uuid,
    object: &TestObject,
    entry_seq: i64,
) -> (Uuid, Uuid) {
    let (blob_id, message_id) = (Uuid::new_v4(), Uuid::new_v4());
    let now = env.now().await;
    let size = object.data.len() as i64;
    let hash = Sha256::digest(&object.data).to_vec();
    let mut tx = env.pool.begin().await.unwrap();
    replica(&mut tx).await;
    sqlx::query(
        "INSERT INTO chat.blobs(blob_id, owner_did, owner_device_id, owner_key_id, \
           owner_auth_generation, purpose, media_type, plaintext_size, ciphertext_size, \
           ciphertext_sha256, object_store_key, status, prepared_at, upload_expires_at, \
           uploaded_at, unbound_expires_at, bound_at) \
         VALUES ($1, $2, $3, chat.ed25519_key_id($4), 1, 'attachment', 'image/png', $5, $6, $7, \
           $8, 'bound', $9, $9 + INTERVAL '5 minutes', $9, $9 + INTERVAL '1 hour', \
           $9 + INTERVAL '1 second')",
    )
    .bind(blob_id)
    .bind(&owner.did)
    .bind(owner.device_id)
    .bind(owner.chat_pub().as_slice())
    .bind(size - 16)
    .bind(size)
    .bind(&hash)
    .bind(&object.key)
    .bind(now)
    .execute(&mut *tx)
    .await
    .expect("bound blob");
    sqlx::query(
        "INSERT INTO chat.blob_bindings(blob_id, binding_kind, conversation_id, entry_seq, \
           message_id, owner_did, owner_device_id, descriptor_bytes, descriptor_sha256, \
           aad_bytes, aad_sha256, ciphertext_sha256, plaintext_size, ciphertext_size, purpose, \
           bound_at, uploaded_at, unbound_expires_at) \
         VALUES ($1, 'application', $2, $3, $4, $5, $6, '\\x01', digest('\\x01'::bytea, 'sha256'), \
           '\\x02', digest('\\x02'::bytea, 'sha256'), $7, $8, $9, 'attachment', \
           $10 + INTERVAL '1 second', $10, $10 + INTERVAL '1 hour')",
    )
    .bind(blob_id)
    .bind(conversation)
    .bind(entry_seq)
    .bind(message_id)
    .bind(&owner.did)
    .bind(owner.device_id)
    .bind(&hash)
    .bind(size - 16)
    .bind(size)
    .bind(now)
    .execute(&mut *tx)
    .await
    .expect("blob binding");
    tx.commit().await.unwrap();
    (blob_id, message_id)
}

/// An application interval of `device` in `conversation` from `start_seq`,
/// closed at `terminal_seq` when given.
pub async fn grant_interval(
    env: &Env,
    conversation: Uuid,
    device: &Device,
    start_seq: i64,
    terminal_seq: Option<i64>,
) {
    let id = Uuid::new_v4();
    let now = env.now().await;
    let closed = terminal_seq.is_some();
    let mut tx = env.pool.begin().await.unwrap();
    replica(&mut tx).await;
    sqlx::query(
        "INSERT INTO chat.application_intervals(membership_interval_id, conversation_id, \
           generation, recipient_did, recipient_device_id, start_seq, opening_kind, \
           opening_transition_id, opening_outer_entry_fingerprint, opening_state_version, \
           opening_group_id, opening_epoch, opening_group_context_hash, \
           opening_confirmation_tag, opening_leaf_period_id, terminal_seq, \
           closing_state_version, closing_transition_id, closing_outer_entry_fingerprint, \
           closing_kind, closing_leaf_period_id, removed_at, created_at) \
         VALUES ($1, $2, 1, $3, $4, $5, 'creation', $1, $6, 1, $6, 0, $6, $6, $7, $8, \
           $9, $10, $11, $12, $13, $14, $15)",
    )
    .bind(id)
    .bind(conversation)
    .bind(&device.did)
    .bind(device.device_id)
    .bind(start_seq)
    .bind(vec![0x77_u8; 32])
    .bind(Uuid::new_v4())
    .bind(terminal_seq)
    .bind(closed.then_some(2_i64))
    .bind(closed.then(Uuid::new_v4))
    .bind(closed.then(|| vec![0x78_u8; 32]))
    .bind(closed.then_some("remove"))
    .bind(closed.then(Uuid::new_v4))
    .bind(closed.then_some(now))
    .bind(now)
    .execute(&mut *tx)
    .await
    .expect("application interval");
    tx.commit().await.unwrap();
}

/// Rewrite a chat blob's lifecycle columns below the API (`expired` with
/// its object kept, or `reclaimed` by object GC).
pub async fn force_blob_state(env: &Env, blob_id: Uuid, state: &str) {
    let mut tx = env.pool.begin().await.unwrap();
    replica(&mut tx).await;
    let sql = match state {
        "expired" => {
            "UPDATE chat.blobs SET status = 'expired', bound_at = NULL, \
               expired_at = unbound_expires_at WHERE blob_id = $1"
        }
        "reclaimed" => {
            "UPDATE chat.blobs SET status = 'expired', bound_at = NULL, \
               expired_at = unbound_expires_at, object_store_key = NULL, \
               object_gc_status = 'reclaimed', object_gc_after = unbound_expires_at, \
               object_deleted_at = unbound_expires_at WHERE blob_id = $1"
        }
        other => panic!("unknown blob state {other}"),
    };
    sqlx::query(sql)
        .bind(blob_id)
        .execute(&mut *tx)
        .await
        .expect("blob state");
    tx.commit().await.unwrap();
}

/// An authenticated chat device driving the router.
#[derive(Clone)]
pub struct Device {
    pub did: String,
    pub device_id: Uuid,
    pub chat_key: EdKey,
    jwt_key: P256Key,
    router: Router,
}

/// A decoded response.
#[derive(Debug)]
pub struct Reply {
    pub status: StatusCode,
    pub bytes: Vec<u8>,
    pub json: Value,
}

impl Reply {
    pub fn error(&self) -> &str {
        self.json["error"].as_str().unwrap_or("")
    }

    #[track_caller]
    pub fn ok(&self) -> &Value {
        assert_eq!(
            self.status,
            StatusCode::OK,
            "expected success: {}",
            self.json
        );
        &self.json
    }

    #[track_caller]
    pub fn fails(&self, status: u16, error: &str) {
        assert_eq!(
            (self.status.as_u16(), self.error()),
            (status, error),
            "unexpected reply: {}",
            self.json
        );
    }
}

impl Device {
    pub fn chat_pub(&self) -> [u8; 32] {
        self.chat_key.verifying_key().to_bytes()
    }

    pub async fn cache_did_document(&self) {
        cache_did_key(&self.did, &self.jwt_key).await;
    }

    /// Ephemeral fixture key only, for the opt-in loopback issuer integration.
    pub fn service_auth_secret_bytes(&self) -> Vec<u8> {
        self.jwt_key.to_bytes().to_vec()
    }

    /// A standard service-auth token for `nsid`.
    pub fn token(&self, nsid: &str) -> String {
        let now = Utc::now().timestamp();
        let header = json!({"alg": "ES256", "typ": "JWT", "kid": format!("{}#atproto", self.did)});
        let claims = json!({
            "iss": self.did,
            "sub": self.did,
            "aud": catbird_server::auth::expected_mls_service_ref(),
            "lxm": nsid,
            "iat": now,
            "exp": now + 60,
            "jti": Uuid::new_v4().to_string(),
        });
        let input = format!(
            "{}.{}",
            URL_SAFE_NO_PAD.encode(serde_json::to_vec(&header).unwrap()),
            URL_SAFE_NO_PAD.encode(serde_json::to_vec(&claims).unwrap())
        );
        let sig: P256Signature = self.jwt_key.sign(input.as_bytes());
        format!("{input}.{}", URL_SAFE_NO_PAD.encode(sig.to_bytes()))
    }

    /// The `[CB-36]` chatBinding of Labyrinth device `key` by this chat
    /// device.
    pub fn chat_binding(&self, key: [u8; 32]) -> Value {
        let message = [
            format!("catbird.labyrinth.device_binding:{}:", self.did).as_bytes(),
            key.as_slice(),
        ]
        .concat();
        json!({
            "transportPubkey": b(&self.chat_pub()),
            "sig": b(&self.chat_key.sign(&message).to_bytes()),
        })
    }

    /// A physical Labyrinth `device` record for `key`, bound to this chat
    /// device.
    pub fn device_record(&self, key: [u8; 32]) -> Value {
        let mut record = unbound_device_record(key);
        record["chatBinding"] = self.chat_binding(key);
        record
    }

    /// Register Labyrinth device `key` bound to this chat device.
    pub async fn enroll(&self, key: [u8; 32]) {
        self.call(
            "createDevice",
            &json!({ "record": self.device_record(key) }),
        )
        .await
        .ok();
    }

    /// `GET` a Labyrinth query as this device.
    pub async fn query(&self, name: &str, params: &[(&str, String)]) -> Reply {
        let nsid = format!("{PREFIX}{name}");
        let mut query = url::form_urlencoded::Serializer::new(String::new());
        query.append_pair("actorDeviceId", &self.device_id.to_string());
        for (k, v) in params {
            query.append_pair(k, v);
        }
        let query = query.finish();
        let (read, read_sig) = self.read_headers(&nsid, &query);
        let request = Request::get(format!("/xrpc/{nsid}?{query}"))
            .header("authorization", format!("Bearer {}", self.token(&nsid)))
            .header("catbird-labyrinth-read", read)
            .header("catbird-labyrinth-read-signature", read_sig)
            .body(Body::empty())
            .unwrap();
        send(&self.router, request).await
    }

    /// The device-signed read headers for `query` on `nsid` (finding 3).
    pub fn read_headers(&self, nsid: &str, query: &str) -> (String, String) {
        self.read_headers_at(nsid, query, Utc::now().timestamp_millis())
    }

    pub fn read_headers_at(&self, nsid: &str, query: &str, issued_at: i64) -> (String, String) {
        use catbird_server::labyrinth::read_auth::{canonical_query, signing_input, ReadClaim};
        let claim = ReadClaim {
            v: 1,
            nsid: nsid.to_owned(),
            query: canonical_query(Some(query)),
            did: self.did.clone(),
            device_id: self.device_id.to_string(),
            issued_at,
        };
        let bytes = serde_json::to_vec(&claim).unwrap();
        let sig = self.chat_key.sign(&signing_input(&bytes));
        (
            URL_SAFE_NO_PAD.encode(&bytes),
            URL_SAFE_NO_PAD.encode(sig.to_bytes()),
        )
    }

    /// The signed write headers for `body` under `operation_id`.
    pub fn write_headers(
        &self,
        nsid: &str,
        body: &[u8],
        operation_id: [u8; 16],
    ) -> (String, String) {
        self.write_headers_at(nsid, body, operation_id, Utc::now())
    }

    /// [`write_headers`](Self::write_headers) signed at `signed_at`.
    pub fn write_headers_at(
        &self,
        nsid: &str,
        body: &[u8],
        operation_id: [u8; 16],
        signed_at: DateTime<Utc>,
    ) -> (String, String) {
        let write = json!({
            "operationId": hex::encode(operation_id),
            "actorDeviceId": self.device_id.to_string(),
            "endpointNsid": nsid,
            "payloadSha256": hex::encode(Sha256::digest(body)),
            "signedAt": signed_at.to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
        });
        let write = serde_json::to_vec(&write).unwrap();
        let sig = self
            .chat_key
            .sign(&[b"CATBIRD-LABYRINTH-WRITE\0".as_slice(), &write].concat());
        (
            URL_SAFE_NO_PAD.encode(&write),
            URL_SAFE_NO_PAD.encode(sig.to_bytes()),
        )
    }

    /// `POST` a procedure with a fresh operation id.
    pub async fn call(&self, name: &str, input: &Value) -> Reply {
        self.call_op(name, input, *Uuid::new_v4().as_bytes()).await
    }

    /// `POST` a procedure under `operation_id`.
    pub async fn call_op(&self, name: &str, input: &Value, operation_id: [u8; 16]) -> Reply {
        let nsid = format!("{PREFIX}{name}");
        let body = serde_json::to_vec(input).unwrap();
        let (write, sig) = self.write_headers(&nsid, &body, operation_id);
        let request = Request::post(format!("/xrpc/{nsid}"))
            .header("content-type", "application/json")
            .header("authorization", format!("Bearer {}", self.token(&nsid)))
            .header("catbird-labyrinth-write", write)
            .header("catbird-labyrinth-write-signature", sig)
            .body(Body::from(body))
            .unwrap();
        send(&self.router, request).await
    }
}

pub async fn send(router: &Router, request: Request<Body>) -> Reply {
    let response = router.clone().oneshot(request).await.expect("router");
    let status = response.status();
    let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("body")
        .to_vec();
    let json = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
    Reply {
        status,
        bytes,
        json,
    }
}

/// Publish `key` as `did`'s `#atproto` verification method in the
/// process-wide DID-document cache.
pub async fn cache_did_key(did: &str, key: &P256Key) {
    let point = key.verifying_key().to_encoded_point(false);
    let jwk = json!({
        "kty": "EC",
        "crv": "P-256",
        "x": URL_SAFE_NO_PAD.encode(point.x().unwrap()),
        "y": URL_SAFE_NO_PAD.encode(point.y().unwrap()),
    });
    let document = catbird_server::auth::DidDocument {
        id: did.to_owned(),
        verification_method: vec![catbird_server::auth::VerificationMethod {
            id: format!("{did}#atproto"),
            key_type: "JsonWebKey2020".to_string(),
            controller: did.to_owned(),
            public_key_jwk: Some(serde_json::from_value(jwk).unwrap()),
            public_key_multibase: None,
        }],
        service: None,
    };
    catbird_server::auth::cache_test_did_document(document).await;
}

/// Record `ds` as `device`'s home DS in the conversation (the sequencer's
/// view of a remote participant).
pub async fn set_home_ds(env: &Env, conversation_id: Uuid, device: &Device, ds: &str) {
    let mut tx = env.pool.begin().await.unwrap();
    replica(&mut tx).await;
    sqlx::query(
        "UPDATE chat.participants SET ds_did = $3 WHERE conversation_id = $1 AND user_did = $2",
    )
    .bind(conversation_id)
    .bind(&device.did)
    .bind(ds)
    .execute(&mut *tx)
    .await
    .unwrap();
    tx.commit().await.unwrap();
}

/// Mark a conversation as sequenced by `sequencer`.
pub async fn make_remote_to(env: &Env, conversation_id: Uuid, sequencer: &str) {
    let mut tx = env.pool.begin().await.unwrap();
    replica(&mut tx).await;
    sqlx::query(
        "UPDATE chat.conversations SET is_remote = TRUE, sequencer_ds = $2 \
          WHERE conversation_id = $1",
    )
    .bind(conversation_id)
    .bind(sequencer)
    .execute(&mut *tx)
    .await
    .unwrap();
    tx.commit().await.unwrap();
}

/// Allow `ds` in this DS's federation peer table.
pub async fn allow_peer(env: &Env, ds: &str) {
    sqlx::query(
        "INSERT INTO federation_peers (ds_did, status, updated_at) VALUES ($1, 'allow', NOW()) \
         ON CONFLICT (ds_did) DO UPDATE SET status = 'allow', updated_at = NOW()",
    )
    .bind(catbird_server::identity::canonical_did(ds))
    .execute(&env.pool)
    .await
    .unwrap();
}

pub fn random_seed() -> [u8; 32] {
    let mut seed = [0u8; 32];
    seed[..16].copy_from_slice(Uuid::new_v4().as_bytes());
    seed[16..].copy_from_slice(Uuid::new_v4().as_bytes());
    seed
}

/// One deterministic service-auth key per DID: the DID-document cache is
/// process-wide, so concurrent tests sharing a DID must agree on it.
pub fn jwt_key_for(did: &str) -> P256Key {
    let mut counter = 0u32;
    loop {
        let seed: [u8; 32] = Sha256::digest(format!("labyrinth-jwt:{did}:{counter}")).into();
        if let Ok(key) = P256Key::from_slice(&seed) {
            return key;
        }
        counter += 1;
    }
}

/// A fresh `did:plc:` identifier (24 base32 characters).
pub fn random_did() -> String {
    const ALPHABET: &[u8] = b"abcdefghijklmnopqrstuvwxyz234567";
    let seed = random_seed();
    let id: String = seed[..24]
        .iter()
        .map(|b| ALPHABET[(*b % 32) as usize] as char)
        .collect();
    format!("did:plc:{id}")
}

/// atproto `{"$bytes"}` JSON for `bytes`.
pub fn b(bytes: &[u8]) -> Value {
    json!({ "$bytes": base64::engine::general_purpose::STANDARD_NO_PAD.encode(bytes) })
}

/// The epochPublic golden vectors exported from the labyrinth crate
/// (`tests/fixtures/labyrinth_epoch_heads.json`, generator in the lane's
/// `vectorgen/`): a three-epoch chain of one DID (epochs 0–1 attested by
/// transport seed 0, epoch 2 by seed 1) and a fork of epoch 1.
pub struct Vectors {
    pub did: String,
    pub seeds: [[u8; 32]; 2],
    pub chain: Vec<Value>,
    pub fork: Value,
}

pub fn vectors() -> Vectors {
    let v: Value =
        serde_json::from_str(include_str!("../fixtures/labyrinth_epoch_heads.json")).unwrap();
    let seed = |i: usize| -> [u8; 32] {
        hex::decode(v["transportSeeds"][i].as_str().unwrap())
            .unwrap()
            .try_into()
            .unwrap()
    };
    Vectors {
        did: v["did"].as_str().unwrap().to_owned(),
        seeds: [seed(0), seed(1)],
        chain: v["chain"].as_array().unwrap().clone(),
        fork: v["forkOfEpoch1"].clone(),
    }
}

/// Decode a `{"$bytes"}` JSON value.
pub fn unb(value: &Value) -> Vec<u8> {
    let text = value["$bytes"].as_str().expect("$bytes");
    base64::engine::general_purpose::STANDARD_NO_PAD
        .decode(text)
        .or_else(|_| base64::engine::general_purpose::STANDARD.decode(text))
        .unwrap()
}

/// A physical Labyrinth `device` record for key `key` without a
/// `chatBinding` (refused by `createDevice`; see [`Device::device_record`]).
pub fn unbound_device_record(key: [u8; 32]) -> Value {
    json!({
        "$type": "blue.catbird.labyrinth.device",
        "deviceKeyPubkey": b(&key),
        "epochStorageKeyPubkey": b(&[7; 32]),
        "epochStorageKeySig": b(&[8; 64]),
        "epochStorageAuthKeyPubkey": b(&[9; 32]),
        "epochStorageAuthKeySig": b(&[10; 64]),
        "virtual": false,
        "createdAt": "2026-10-04T12:00:00.000Z",
    })
}

/// A virtual (recovery) Labyrinth `device` record for key `key`.
pub fn virtual_device_record(key: [u8; 32]) -> Value {
    json!({
        "$type": "blue.catbird.labyrinth.device",
        "deviceKeyPubkey": b(&key),
        "epochStorageKeyPubkey": b(&[7; 32]),
        "epochStorageKeySig": b(&[8; 64]),
        "virtual": true,
        "createdAt": "2026-10-04T12:00:00.000Z",
    })
}

/// An `epoch` record carrying `public`.
pub fn epoch_record(public: &Value, opened_by: [u8; 32]) -> Value {
    json!({
        "$type": "blue.catbird.labyrinth.epoch",
        "public": public,
        "openedBy": b(&opened_by),
        "createdAt": "2026-10-04T12:00:00.000Z",
    })
}

/// An `epochMember` record.
pub fn member_record(epoch_number: u64, key: [u8; 32]) -> Value {
    json!({
        "$type": "blue.catbird.labyrinth.epochMember",
        "epochNumber": epoch_number,
        "deviceKeyPubkey": b(&key),
        "deviceMac": b(&[3; 32]),
        "createdAt": "2026-10-04T12:00:00.000Z",
    })
}

/// A `virtualDevice` record.
pub fn vdevice_record(id: [u8; 16], key: [u8; 32]) -> Value {
    json!({
        "$type": "blue.catbird.labyrinth.virtualDevice",
        "vdeviceId": b(&id),
        "encryptedDeviceKeyPriv": b(&[1; 48]),
        "encryptedEpochStorageKeyPriv": b(&[2; 48]),
        "encryptedOrfClientState": b(&[3; 48]),
        "encryptedMailboxRootSalt": b(&[4; 48]),
        "encryptedEpochRootKey": b(&[5; 48]),
        "encryptedEpochNumber": b(&[6; 24]),
        "deviceKeyPubkey": b(&key),
        "epochStorageKeyPubkey": b(&[7; 32]),
        "epochStorageKeySig": b(&[8; 64]),
        "mechanism": "code",
        "createdAt": "2026-10-04T12:00:00.000Z",
    })
}

/// An `ownerBatch` record with items at `timestamps`.
pub fn owner_batch_record(thread_id: &str, timestamps: &[u64]) -> Value {
    let items: Vec<Value> = timestamps
        .iter()
        .enumerate()
        .map(|(i, ts)| {
            json!({
                "threadId": thread_id,
                "messageId": format!("m{i}-{ts}"),
                "timestamp": ts,
                "epochNumber": 0,
                "version": 3,
                "encrypted": b(&[0xEE; 40]),
            })
        })
        .collect();
    json!({
        "$type": "blue.catbird.labyrinth.ownerBatch",
        "threadId": thread_id,
        "items": items,
        "createdAt": "2026-10-04T12:00:00.000Z",
    })
}

/// A `mek` record from a transport sender (`sender`'s chat key) addressed to
/// `recipients`.
pub fn transport_mek(
    thread: Uuid,
    mek_id: [u8; 12],
    sender: [u8; 32],
    recipients: &[&str],
) -> Value {
    mek_with_sender(
        thread,
        mek_id,
        json!({
            "$type": "blue.catbird.labyrinth.mek#transportSender",
            "transportPubkey": b(&sender),
            "ephemeralAuthPubkey": b(&[0x21; 32]),
            "sig": b(&[0x22; 64]),
        }),
        recipients,
    )
}

/// A `mek` record from a Labyrinth sender (`did`, epoch `public`).
pub fn labyrinth_mek(
    thread: Uuid,
    mek_id: [u8; 12],
    did: &str,
    public: &Value,
    recipients: &[&str],
) -> Value {
    mek_with_sender(
        thread,
        mek_id,
        json!({
            "$type": "blue.catbird.labyrinth.mek#labyrinthSender",
            "did": did,
            "senderEpochHead": public["epochHead"],
            "senderEpoch": public,
        }),
        recipients,
    )
}

fn mek_with_sender(thread: Uuid, mek_id: [u8; 12], sender: Value, recipients: &[&str]) -> Value {
    let recipients: Vec<Value> = recipients
        .iter()
        .map(|did| {
            json!({
                "did": did,
                "recipientEpochHead": b(&[0x31; 32]),
                "ciphertext": b(&[0x41; 120]),
            })
        })
        .collect();
    json!({
        "$type": "blue.catbird.labyrinth.mek",
        "threadId": thread.to_string(),
        "mekId": b(&mek_id),
        "rosterHash": b(&[0x51; 32]),
        "sender": sender,
        "recipients": recipients,
        "createdAt": "2026-10-04T12:00:00.000Z",
    })
}

/// A `batch` record: one sealed message per `(mekId, timestamp)`, sent by
/// chat key `sender`.
pub fn batch_record(thread: Uuid, sender: [u8; 32], items: &[([u8; 12], u64)]) -> Value {
    let items: Vec<Value> = items
        .iter()
        .enumerate()
        .map(|(i, (mek_id, ts))| {
            json!({
                "messageId": format!("msg-{i}-{ts}"),
                "timestamp": ts,
                "mekId": b(mek_id),
                "senderTransportPubkey": b(&sender),
                "signedEncMessage": b(&[0x61; 96]),
            })
        })
        .collect();
    json!({
        "$type": "blue.catbird.labyrinth.batch",
        "threadId": thread.to_string(),
        "items": items,
        "createdAt": "2026-10-04T12:00:00.000Z",
    })
}
