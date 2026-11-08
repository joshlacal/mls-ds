//! `deliverTransportControlEntry` regressions on real PostgreSQL. A C33
//! coordinator's receipted control entries reach the peer's transport-only
//! home through the production queue, behind the pair's earlier delivery
//! there. The home verifies them before any effect, returns them verbatim from
//! `getEntries`, and applies the account-deletion-specific prune.

use super::super::super::entry_ack_relay::transport_control_entry::{
    accept_transport_control_entry, DeliverTransportControlEntry,
};
use super::*;
use crate::{
    chat_protocol::{repository::delivery, test_support::CleanSlateApplicationFixture},
    common::{fresh_db::DisposableDatabase, http_acceptance as http},
    federation::{
        canonical_relay::{coordinator_handle_message, DeliverMessageEntryInput},
        queue::{claim_due_heads, mark_item_delivered},
        receipt::AccountDeletion,
    },
    labyrinth::repo::retention::purge_account,
};

const CONTROL_PREFIX: &str = "transport-control-";

impl Network {
    /// Publish `did`'s dedicated `#mls-receipt-1` key, as a sequencer's DID
    /// document does.
    fn publish_receipt_key(&self, did: &str, key: &SigningKey) {
        self.documents
            .lock()
            .unwrap()
            .get_mut(host(did))
            .expect("a published DS DID document")["verificationMethod"]
            .as_array_mut()
            .unwrap()
            .push(json!({
                "id": format!("{did}#mls-receipt-1"),
                "type": "Multikey",
                "controller": did,
                "publicKeyMultibase":
                    crate::identity::did_doc::encode_p256_multikey(key.verifying_key()),
            }));
    }
}

/// A direct pair C33_SEQ coordinates: the deleted account D is the sender homed
/// there, its peer P the recipient homed at C33_HOME, which holds the pair's
/// transport inbox and every entry before D's application. D's application is
/// sequenced and queued for P's home.
struct Pair {
    _dbs: [DisposableDatabase; 2],
    seq_pool: DbPool,
    home_pool: DbPool,
    fixture: CleanSlateApplicationFixture,
    cid: Uuid,
    /// A second conversation of the same pair this home holds.
    twin: Uuid,
    network: Network,
    clock: Arc<ManualDsClock>,
    seq_hooks: Arc<SimDsHooks>,
    home_hooks: Arc<SimDsHooks>,
    seq_key: SigningKey,
    receipt: I13ReceiptSigner,
    other_receipt: I13ReceiptSigner,
    home: GroupRelayState,
    router: Router,
    /// D's application: its seq and the entry `deliverMessageEntry` carries.
    seq: i64,
    message: Value,
    /// P's device key id, which also binds its DPoP key here.
    peer_key_id: String,
}

impl Pair {
    async fn new() -> Self {
        crate::federation::open_federation_for_test();
        let seq_db = fresh_fully_migrated_db("chat_fed_relay_").await;
        let seq_pool = seq_db.connect(4).await;
        let home_db = fresh_fully_migrated_db("chat_fed_relay_").await;
        let home_pool = home_db.connect(4).await;
        for (pool, peers) in [
            (&seq_pool, [C33_HOME, C33_OTHER]),
            (&home_pool, [C33_SEQ, C33_OTHER]),
        ] {
            ensure_fence(pool).await;
            for peer in peers {
                sqlx::query("INSERT INTO federation_peers(ds_did,status) VALUES($1,'allow')")
                    .bind(peer)
                    .execute(pool)
                    .await
                    .unwrap();
            }
        }
        let fixture = seed_clean_slate_application_fixture_with_sender_home(
            &seq_pool,
            true,
            C33_HOME,
            Some([0x5e; 32]),
            Some(C33_SEQ),
        )
        .await
        .unwrap();
        let cid = fixture.conversation_id;
        let (seq_key, home_key, other_key) = (key(0x51), key(0x52), key(0x53));
        let network = Network::new(&[
            (C33_SEQ, &seq_key),
            (C33_HOME, &home_key),
            (C33_OTHER, &other_key),
        ]);
        for ds in [C33_SEQ, C33_HOME, C33_OTHER] {
            network.declare_delivery_service(ds);
        }
        network.declare_user(&fixture.sender_did, C33_SEQ);
        network.declare_user(&fixture.recipient_did, C33_HOME);
        network.authorize_device(
            &fixture.sender_did,
            &ed25519_dalek::SigningKey::from_bytes(&fixture.sender_ed25519_seed)
                .verifying_key()
                .to_bytes(),
        );
        network.authorize_device(
            &fixture.recipient_did,
            &ed25519_dalek::SigningKey::from_bytes(&fixture.recipient_ed25519_seed)
                .verifying_key()
                .to_bytes(),
        );
        network.publish_receipt_key(C33_SEQ, &key(0x54));
        network.publish_receipt_key(C33_OTHER, &key(0x55));
        let receipt = I13ReceiptSigner::new(key(0x54), C33_SEQ.to_owned());
        let other_receipt = I13ReceiptSigner::new(key(0x55), C33_OTHER.to_owned());
        let clock = manual_clock();
        let seq_hooks = hooks(C33_SEQ, Some(&seq_key), false, &network);
        let home_hooks = hooks(C33_HOME, Some(&home_key), false, &network);
        let runtime = Arc::new(
            crate::handlers::chat::ChatRuntime::from_env(Arc::new(crate::realtime::SseState::new(
                8,
            )))
            .unwrap()
            .with_sim_allow_all_relationships()
            .unwrap()
            .with_i13_receipt_signer(receipt.clone()),
        );
        let router = {
            let (hooks, clock, receipt) =
                (Arc::clone(&seq_hooks), Arc::clone(&clock), receipt.clone());
            http::router_for_authenticated_acceptance_with(seq_pool.clone(), move |runtime| {
                runtime
                    .with_sim_allow_all_relationships()
                    .unwrap()
                    .with_sim_hooks(hooks)
                    .with_clock(clock)
                    .with_i13_receipt_signer(receipt)
            })
            .await
        };

        // D's message, relayed by nobody: D is homed at its coordinator.
        let sequenced = scope_ds_clock(
            clock.clone(),
            scope_sim_ds(
                Arc::clone(&seq_hooks),
                coordinator_handle_message(
                    &seq_pool,
                    &runtime,
                    C33_SEQ,
                    cid,
                    &fixture.signed_request,
                ),
            ),
        )
        .await
        .expect("coordinate D's application");
        let seq = sequenced["entry"]["seq"].as_i64().unwrap();
        let queued = queue_rows(&seq_pool, cid).await;
        assert_eq!(
            queued
                .iter()
                .map(|row| (row.0.as_str(), row.1.as_str(), row.2.as_str()))
                .collect::<Vec<_>>(),
            [(
                format!("msg-delivery-{cid}-{seq}").as_str(),
                C33_HOME,
                "pending"
            )]
        );
        let message = serde_json::from_slice::<DeliverMessageEntryInput>(&queued[0].5)
            .unwrap()
            .entry;

        let home = GroupRelayState::for_test(
            home_pool.clone(),
            C33_HOME.to_owned(),
            HMAC.as_bytes(),
            None,
        )
        .with_sim_hooks(Arc::clone(&home_hooks))
        .with_clock(clock.clone());
        let peer_public = ed25519_dalek::SigningKey::from_bytes(&fixture.recipient_ed25519_seed)
            .verifying_key()
            .to_bytes();
        let peer_key_id = seed_actor_at(
            &home_pool,
            &fixture.recipient_did,
            fixture.recipient_device_id,
            &peer_public,
            clock_now(&home_pool).await,
        )
        .await;
        let twin = Uuid::new_v4();
        let pair = Self {
            _dbs: [seq_db, home_db],
            seq_pool,
            home_pool,
            fixture,
            cid,
            twin,
            network,
            clock,
            seq_hooks,
            home_hooks,
            seq_key,
            receipt,
            other_receipt,
            home,
            router,
            seq,
            message,
            peer_key_id,
        };
        for conversation_id in [cid, twin] {
            c33_inbox(
                &pair.home_pool,
                conversation_id,
                C33_SEQ,
                (pair.deleted(), pair.fixture.sender_device_id),
                (pair.peer(), pair.fixture.recipient_device_id),
            )
            .await;
        }
        let predecessors: Vec<Vec<u8>> = sqlx::query_scalar(
            "SELECT accepted_payload_bytes FROM chat.entries \
              WHERE conversation_id=$1 AND seq<$2 ORDER BY seq",
        )
        .bind(cid)
        .bind(seq)
        .fetch_all(&pair.seq_pool)
        .await
        .unwrap();
        for bytes in predecessors {
            pair.store(cid, &serde_json::from_slice(&bytes).unwrap())
                .await;
        }
        // The second conversation exercises deletion fanout only; its preceding rows do not
        // participate in a coordinate-bearing application/Commit sequence.
        for earlier in 1..seq {
            pair.store(
                twin,
                &json!({
                    "conversationId": twin,
                    "entryId": Uuid::new_v4(),
                    "seq": earlier,
                }),
            )
            .await;
        }
        pair
    }

    fn deleted(&self) -> &str {
        &self.fixture.sender_did
    }

    fn peer(&self) -> &str {
        &self.fixture.recipient_did
    }

    /// Store `entry` at this home exactly as its single transport writer does.
    async fn store(&self, conversation_id: Uuid, entry: &Value) {
        let mut tx = self.home_pool.begin().await.unwrap();
        let stored = delivery::insert_transport_entry(
            &mut tx,
            conversation_id,
            entry["seq"].as_i64().unwrap(),
            entry["entryId"].as_str().unwrap().parse().unwrap(),
            &serde_json::to_vec(entry).unwrap(),
            current_utc(),
        )
        .await
        .unwrap();
        assert_eq!(stored, delivery::TransportEntryInsert::Inserted);
        tx.commit().await.unwrap();
    }

    /// `signer`'s signed `accountDeletedEntry`.
    fn entry(
        signer: &I13ReceiptSigner,
        conversation_id: Uuid,
        deleted_did: &str,
        seq: i64,
        entry_id: Uuid,
        deleted_at: DateTime<Utc>,
    ) -> Value {
        let deletion = AccountDeletion {
            sequencer_did: signer.sequencer_did().to_owned(),
            conversation_id,
            deleted_did: deleted_did.to_owned(),
            seq,
            entry_id,
            deleted_at,
        };
        deletion.entry(&signer.sign_account_deletion(&deletion).unwrap())
    }

    async fn accept(&self, caller: &str, entry: &Value) -> Result<Value, Response> {
        let body = serde_json::to_vec(&DeliverTransportControlEntry {
            entry: entry.clone(),
        })
        .unwrap();
        scope_sim_ds(
            Arc::clone(&self.home_hooks),
            accept_transport_control_entry(&self.home, caller, &body),
        )
        .await
    }

    async fn submit_metadata(&self) -> (StatusCode, Value) {
        self.submit_metadata_at(&self.router, false).await
    }

    async fn submit_metadata_at(&self, router: &Router, peer_actor: bool) -> (StatusCode, Value) {
        self.submit_metadata_sized_at(router, peer_actor, 16).await
    }

    async fn submit_metadata_sized_at(
        &self,
        router: &Router,
        peer_actor: bool,
        ciphertext_bytes: usize,
    ) -> (StatusCode, Value) {
        let (status, response, _) = self
            .submit_metadata_sized_with_request_at(router, peer_actor, ciphertext_bytes)
            .await;
        (status, response)
    }

    async fn submit_metadata_with_request_at(
        &self,
        router: &Router,
        peer_actor: bool,
    ) -> (StatusCode, Value, Value) {
        self.submit_metadata_sized_with_request_at(router, peer_actor, 16)
            .await
    }

    async fn submit_metadata_sized_with_request_at(
        &self,
        router: &Router,
        peer_actor: bool,
        ciphertext_bytes: usize,
    ) -> (StatusCode, Value, Value) {
        let wall = DateTime::from_timestamp_millis(Utc::now().timestamp_millis()).unwrap();
        self.clock.set_utc(wall.max(current_utc()));
        use ed25519_dalek::Signer as _;
        use tower_util::ServiceExt as _;

        let (
            generation,
            state_version,
            group_id,
            epoch,
            group_context_hash,
            confirmation_tag,
            metadata_version,
            next_seq,
        ): (i64, i64, Vec<u8>, i64, Vec<u8>, Vec<u8>, i64, i64) = sqlx::query_as(
            "SELECT c.current_generation,c.current_state_version,g.group_id,g.epoch,\
                    g.group_context_hash,g.confirmation_tag,m.metadata_version,c.next_entry_seq \
               FROM chat.conversations c \
               JOIN chat.generation_states g \
                 ON g.conversation_id=c.conversation_id \
                AND g.generation=c.current_generation \
                AND g.state_version=c.current_state_version \
               JOIN LATERAL (SELECT metadata_version FROM chat.metadata_snapshots \
                              WHERE conversation_id=c.conversation_id \
                              ORDER BY generation DESC,state_version DESC LIMIT 1) m ON TRUE \
              WHERE c.conversation_id=$1",
        )
        .bind(self.cid)
        .fetch_one(&self.seq_pool)
        .await
        .unwrap();
        let transition_id = Uuid::new_v4();
        let ciphertext = vec![0x63_u8; ciphertext_bytes];
        let (actor_did, actor_device_id, actor_key_id, actor_seed) = if peer_actor {
            (
                &self.fixture.recipient_did,
                self.fixture.recipient_device_id,
                &self.fixture.recipient_key_id,
                self.fixture.recipient_ed25519_seed,
            )
        } else {
            (
                &self.fixture.sender_did,
                self.fixture.sender_device_id,
                &self.fixture.sender_key_id,
                self.fixture.sender_ed25519_seed,
            )
        };
        let actor_key = ed25519_dalek::SigningKey::from_bytes(&actor_seed);
        let coordinate = json!({
            "conversationId": self.cid,
            "generation": generation,
            "stateVersion": state_version,
            "groupId": STANDARD.encode(&group_id),
            "epoch": epoch,
            "groupContextHash": STANDARD.encode(&group_context_hash),
            "confirmationTag": STANDARD.encode(&confirmation_tag),
            "lifecycle": "active",
        });
        let mut next = coordinate.clone();
        next["stateVersion"] = json!(state_version + 1);
        let body = json!({
            "$type": "blue.catbird.chat.defs#metadataTransitionBody",
            "signatureDomain": "CATBIRD-CHAT-METADATA\u{0}",
            "transitionId": transition_id,
            "actorDid": actor_did,
            "actorDeviceId": actor_device_id,
            "keyId": actor_key_id,
            "authGeneration": 1,
            "prior": coordinate,
            "next": next,
            "metadataSnapshot": {
                "coordinate": {
                    "conversationId": STANDARD.encode(self.cid.as_bytes()),
                    "generation": generation,
                    "groupId": STANDARD.encode(&group_id),
                    "epoch": epoch,
                    "groupContextHash": STANDARD.encode(&group_context_hash),
                    "confirmationTag": STANDARD.encode(&confirmation_tag),
                },
                "originTransitionId": transition_id,
                "metadataVersion": metadata_version + 1,
                "nonce": STANDARD.encode([0x64_u8; 12]),
                "ciphertext": STANDARD.encode(&ciphertext),
                "ciphertextSha256": STANDARD.encode(Sha256::digest(&ciphertext)),
                "ciphertextSize": ciphertext.len(),
                "authorProof": {
                    "authorDid": actor_did,
                    "authorDeviceId": actor_device_id,
                    "authorKeyId": actor_key_id,
                    "signaturePublicKey": STANDARD.encode(actor_key.verifying_key().to_bytes()),
                    "authGenerationAtOrigin": 1,
                    "originTransitionId": transition_id,
                    "originSeq": next_seq,
                    "roleAtOrigin": "admin",
                    "deviceStatusAtOrigin": "active",
                },
            },
            "idempotencyKey": transition_id,
            "signedAt": current_utc().to_rfc3339_opts(SecondsFormat::Millis, true),
        });
        let mut signed = json!({
            "body": body,
            "signature": STANDARD.encode([0_u8; 64]),
        });
        let mutation = crate::chat_protocol::transcript::decode_canonical_signed_mutation(
            &serde_json::to_vec(&signed).unwrap(),
        )
        .unwrap();
        signed["signature"] =
            json!(STANDARD.encode(actor_key.sign(mutation.transcript_bytes()).to_bytes()));

        let p256 = p256::ecdsa::SigningKey::from_slice(&Sha256::digest([0xa6_u8; 32])).unwrap();
        let jwk = http::public_jwk(&p256);
        self.network
            .documents
            .lock()
            .unwrap()
            .get_mut(host(actor_did))
            .unwrap()["verificationMethod"] = json!([{
            "id": format!("{actor_did}#atproto"),
            "type": "JsonWebKey2020",
            "controller": actor_did,
            "publicKeyJwk": jwk,
        }]);
        let device = http::Device {
            did: actor_did.clone(),
            device_id: actor_device_id,
            jkt: http::jwk_thumbprint(&jwk),
            jwk,
            signing: p256,
        };
        let body = serde_json::to_vec(&json!({ "signedRequest": signed.clone() })).unwrap();
        let hooks = if peer_actor {
            Arc::clone(&self.home_hooks)
        } else {
            Arc::clone(&self.seq_hooks)
        };
        let response = scope_sim_ds(hooks, async {
            router
                .clone()
                .oneshot(http::unsigned_json_request(
                    &device,
                    "blue.catbird.chat.submitTransition",
                    body,
                ))
                .await
                .unwrap()
        })
        .await;
        let status = response.status();
        let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        (
            status,
            serde_json::from_slice(&bytes).unwrap_or(Value::Null),
            signed,
        )
    }

    async fn submit_sender_request(
        &self,
        nsid: &str,
        signed_request: &Value,
    ) -> (StatusCode, Value) {
        self.submit_sender_request_at(&self.router, nsid, signed_request)
            .await
    }

    async fn submit_sender_request_at(
        &self,
        router: &Router,
        nsid: &str,
        signed_request: &Value,
    ) -> (StatusCode, Value) {
        use tower_util::ServiceExt as _;

        let p256 = p256::ecdsa::SigningKey::from_slice(&Sha256::digest([0xa7_u8; 32])).unwrap();
        let jwk = http::public_jwk(&p256);
        self.network
            .documents
            .lock()
            .unwrap()
            .get_mut(host(self.deleted()))
            .unwrap()["verificationMethod"] = json!([{
            "id": format!("{}#atproto", self.deleted()),
            "type": "JsonWebKey2020",
            "controller": self.deleted(),
            "publicKeyJwk": jwk,
        }]);
        let device = http::Device {
            did: self.deleted().to_owned(),
            device_id: self.fixture.sender_device_id,
            jkt: http::jwk_thumbprint(&jwk),
            jwk,
            signing: p256,
        };
        let body = serde_json::to_vec(&json!({ "signedRequest": signed_request })).unwrap();
        let response = scope_sim_ds(Arc::clone(&self.seq_hooks), async {
            router
                .clone()
                .oneshot(http::unsigned_json_request(&device, nsid, body))
                .await
                .unwrap()
        })
        .await;
        let status = response.status();
        let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        (
            status,
            serde_json::from_slice(&bytes).unwrap_or(Value::Null),
        )
    }

    async fn submit_peer_request(
        &self,
        router: &Router,
        nsid: &str,
        signed_request: &Value,
    ) -> (StatusCode, Value) {
        use tower_util::ServiceExt as _;

        let p256 = p256::ecdsa::SigningKey::from_slice(&Sha256::digest([0xa6_u8; 32])).unwrap();
        let jwk = http::public_jwk(&p256);
        self.network
            .documents
            .lock()
            .unwrap()
            .get_mut(host(self.peer()))
            .unwrap()["verificationMethod"] = json!([{
            "id": format!("{}#atproto", self.peer()),
            "type": "JsonWebKey2020",
            "controller": self.peer(),
            "publicKeyJwk": jwk,
        }]);
        let device = http::Device {
            did: self.peer().to_owned(),
            device_id: self.fixture.recipient_device_id,
            jkt: http::jwk_thumbprint(&jwk),
            jwk,
            signing: p256,
        };
        let body = serde_json::to_vec(&json!({ "signedRequest": signed_request })).unwrap();
        let response = scope_sim_ds(Arc::clone(&self.home_hooks), async {
            router
                .clone()
                .oneshot(http::unsigned_json_request(&device, nsid, body))
                .await
                .unwrap()
        })
        .await;
        let status = response.status();
        let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        (
            status,
            serde_json::from_slice(&bytes).unwrap_or(Value::Null),
        )
    }

    async fn assert_refused(
        &self,
        caller: &str,
        entry: &Value,
        (status, code): (StatusCode, &str),
    ) {
        let before = home_state(&self.home_pool).await;
        let response = self.accept(caller, entry).await.expect_err("refused");
        let actual = response.status();
        let body: Value = serde_json::from_slice(
            &axum::body::to_bytes(response.into_body(), 1 << 16)
                .await
                .unwrap(),
        )
        .unwrap();
        assert_eq!(
            (actual, body["error"].as_str()),
            (status, Some(code)),
            "{caller}: {entry}: {body}"
        );
        assert_eq!(
            home_state(&self.home_pool).await,
            before,
            "{caller}: {entry}"
        );
    }

    /// P's `getEntries` page after `after_seq`, read through its real admission.
    async fn peer_entries(&self, after_seq: i64) -> Vec<Value> {
        let trusted = clock_now(&self.home_pool)
            .await
            .to_rfc3339_opts(SecondsFormat::Millis, true);
        let proof_jti: [u8; 12] = Uuid::new_v4().as_bytes()[..12].try_into().unwrap();
        let authority = crate::chat_protocol::repository::auth::authorize_unsigned_request(
            &self.home_pool,
            crate::chat_protocol::dpop::repository_test_evidence::ordinary_device_with_binding(
                Uuid::new_v4(),
                proof_jti,
                "blue.catbird.chat.getEntries",
                &trusted,
                self.peer(),
                self.fixture.recipient_device_id,
                &self.peer_key_id,
            ),
        )
        .await
        .expect("P's device reads here");
        let admission = crate::chat_protocol::dpop::seal_read_admission(authority).unwrap();
        let page = crate::chat_protocol::repository::entry_read::get_entries_for_admission(
            &self.home_pool,
            admission,
            self.cid,
            after_seq as u64,
            100,
        )
        .await
        .expect("P's getEntries");
        let page: Value = serde_json::from_slice(&page.into_response_bytes()).unwrap();
        page["entries"].as_array().unwrap().clone()
    }

    async fn coordinator_entries(&self, after_seq: i64) -> Vec<Value> {
        let trusted = clock_now(&self.seq_pool)
            .await
            .to_rfc3339_opts(SecondsFormat::Millis, true);
        let proof_jti: [u8; 12] = Uuid::new_v4().as_bytes()[..12].try_into().unwrap();
        let dpop_jkt: String = sqlx::query_scalar(
            "SELECT dpop_jkt FROM chat.devices WHERE user_did=$1 AND device_id=$2",
        )
        .bind(self.deleted())
        .bind(self.fixture.sender_device_id)
        .fetch_one(&self.seq_pool)
        .await
        .unwrap();
        let authority = crate::chat_protocol::repository::auth::authorize_unsigned_request(
            &self.seq_pool,
            crate::chat_protocol::dpop::repository_test_evidence::ordinary_device_with_binding(
                Uuid::new_v4(),
                proof_jti,
                "blue.catbird.chat.getEntries",
                &trusted,
                self.deleted(),
                self.fixture.sender_device_id,
                &dpop_jkt,
            ),
        )
        .await
        .expect("coordinator-homed participant reads here");
        let admission = crate::chat_protocol::dpop::seal_read_admission(authority).unwrap();
        let page = crate::chat_protocol::repository::entry_read::get_entries_for_admission(
            &self.seq_pool,
            admission,
            self.cid,
            after_seq as u64,
            100,
        )
        .await
        .expect("coordinator getEntries");
        let page: Value = serde_json::from_slice(&page.into_response_bytes()).unwrap();
        page["entries"].as_array().unwrap().clone()
    }
}

/// `(conversation, seq, original digest, pruned)` of every entry this home holds.
async fn home_state(pool: &DbPool) -> Vec<(String, i64, Vec<u8>, bool)> {
    sqlx::query_as(
        "SELECT conversation_id::text, seq, original_entry_sha256, payload_pruned_at IS NOT NULL \
           FROM chat.direct_request_transport_entries ORDER BY 1, 2",
    )
    .fetch_all(pool)
    .await
    .unwrap()
}

async fn add_second_recipient_delivery(p: &Pair) {
    let device_id = Uuid::new_v4();
    let key = ed25519_dalek::SigningKey::from_bytes(&[0x6f; 32]);
    for pool in [&p.seq_pool, &p.home_pool] {
        seed_actor_at(
            pool,
            p.peer(),
            device_id,
            &key.verifying_key().to_bytes(),
            clock_now(pool).await,
        )
        .await;
    }
    c33_inbox(
        &p.home_pool,
        p.cid,
        C33_SEQ,
        (p.deleted(), p.fixture.sender_device_id),
        (p.peer(), device_id),
    )
    .await;
}

fn edited(entry: &Value, edit: impl FnOnce(&mut Value)) -> Value {
    let mut entry = entry.clone();
    edit(&mut entry);
    entry
}

/// The queued control entries of `conversation_id`.
async fn control_rows(pool: &DbPool, conversation_id: Uuid) -> Vec<QueueRow> {
    queue_rows(pool, conversation_id)
        .await
        .into_iter()
        .filter(|row| row.0.starts_with(CONTROL_PREFIX))
        .collect()
}

fn transport_home_delivery_router(p: &Pair) -> Router {
    let (pool, hooks) = (p.home_pool.clone(), Arc::clone(&p.home_hooks));
    let message_router = Router::new().route(
        "/xrpc/blue.catbird.mlsDS.deliverMessageEntry",
        axum::routing::post(move |Json(input): Json<DeliverMessageEntryInput>| {
            let (pool, hooks) = (pool.clone(), Arc::clone(&hooks));
            async move {
                scope_sim_ds(
                    hooks,
                    crate::federation::canonical_relay::ingest_remote_message_entry(
                        &pool,
                        None,
                        C33_SEQ,
                        input.conversation_id,
                        &input.entry,
                    ),
                )
                .await
                .map(|()| Json(json!({ "accepted": true })))
            }
        }),
    );
    group_relay_router(p.home.clone()).merge(message_router)
}

async fn transport_home_chat_router(p: &Pair) -> Router {
    let resolver = Arc::new(DsResolver::new(
        p.home_pool.clone(),
        crate::federation::resolver::build_resolver_http_client(),
        C33_HOME.to_owned(),
        format!("https://{}", host(C33_HOME)),
        None,
        300,
    ));
    let (hooks, clock) = (Arc::clone(&p.home_hooks), Arc::clone(&p.clock));
    http::router_for_authenticated_acceptance_with(p.home_pool.clone(), move |runtime| {
        runtime
            .with_sim_allow_all_relationships()
            .unwrap()
            .with_sim_hooks(hooks)
            .with_clock(clock)
            .with_resolver(resolver)
    })
    .await
}

#[tokio::test]
async fn c33_real_commit_then_application_reaches_transport_home_contiguously() {
    let p = Pair::new().await;
    let queue = OutboundQueue::new(
        p.seq_pool.clone(),
        AuthMiddleware::new(),
        Arc::new(DsResolver::new(
            p.seq_pool.clone(),
            crate::federation::resolver::build_resolver_http_client(),
            C33_SEQ.to_owned(),
            format!("https://{}", host(C33_SEQ)),
            None,
            300,
        )),
    );
    p.network
        .serve(C33_HOME, transport_home_delivery_router(&p));

    scope_ds_clock(p.clock.clone(), async {
        let self_update = p.fixture.self_update_signed_request.clone();
        let (status, commit_response) = p
            .submit_sender_request("blue.catbird.chat.submitTransition", &self_update)
            .await;
        assert_eq!(status, StatusCode::OK, "{commit_response}");
        let commit_entry = commit_response["entry"].clone();
        assert_eq!(commit_entry["$type"], "blue.catbird.chat.defs#commitEntry");
        assert!(commit_entry["sequencerReceipt"].is_object());

        let runtime = Arc::new(
            crate::handlers::chat::ChatRuntime::from_env(Arc::new(crate::realtime::SseState::new(
                8,
            )))
            .unwrap()
            .with_sim_allow_all_relationships()
            .unwrap()
            .with_i13_receipt_signer(p.receipt.clone()),
        );
        let post_update = p.fixture.post_update_signed_request.clone();
        let message_response = scope_sim_ds(
            Arc::clone(&p.seq_hooks),
            coordinator_handle_message(&p.seq_pool, &runtime, C33_SEQ, p.cid, &post_update),
        )
        .await
        .expect("coordinate application after self-update");
        let message_entry = message_response["entry"].clone();
        assert_eq!(
            message_entry["$type"],
            "blue.catbird.chat.defs#applicationEntry"
        );
        assert_eq!(
            message_entry["seq"].as_i64(),
            commit_entry["seq"].as_i64().map(|seq| seq + 1)
        );

        let controls = control_rows(&p.seq_pool, p.cid).await;
        assert_eq!(controls.len(), 1);
        assert_eq!(
            controls[0].0,
            format!("transport-control-{}-{}", p.cid, commit_entry["seq"])
        );
        assert_eq!(queue_rows(&p.seq_pool, p.cid).await.len(), 3);
        p.clock
            .set_utc(latest_due(&p.seq_pool).await.max(current_utc()));
        let mut delivered = 0;
        for _ in 0..3 {
            p.clock
                .set_utc(latest_due(&p.seq_pool).await.max(current_utc()));
            delivered += drain(&queue, &p.seq_hooks, C33_SEQ, &p.seq_key).await;
        }
        assert_eq!(delivered, 3);
        let stored_seqs: Vec<i64> = sqlx::query_scalar(
            "SELECT seq FROM chat.direct_request_transport_entries \
              WHERE conversation_id=$1 ORDER BY seq",
        )
        .bind(p.cid)
        .fetch_all(&p.home_pool)
        .await
        .unwrap();
        let queue_state: Vec<(String, String, i32, Option<String>)> = sqlx::query_as(
            "SELECT id,status,retry_count,last_error FROM outbound_queue \
              WHERE convo_id=$1 ORDER BY id",
        )
        .bind(p.cid.to_string())
        .fetch_all(&p.seq_pool)
        .await
        .unwrap();
        assert_eq!(
            stored_seqs,
            (1..=p.seq + 2).collect::<Vec<_>>(),
            "{queue_state:?}"
        );

        let entries = p.peer_entries(p.seq - 1).await;
        assert_eq!(entries.len(), 3, "{entries:?}");
        assert_eq!(
            entries
                .iter()
                .map(|entry| entry["seq"].as_i64().unwrap())
                .collect::<Vec<_>>(),
            [p.seq, p.seq + 1, p.seq + 2]
        );
        assert_eq!(
            entries
                .iter()
                .map(|entry| entry["$type"].as_str().unwrap())
                .collect::<Vec<_>>(),
            [
                "blue.catbird.chat.defs#applicationEntry",
                "blue.catbird.chat.defs#commitEntry",
                "blue.catbird.chat.defs#applicationEntry",
            ]
        );
        assert!(entries[1]["sequencerReceipt"].is_object());

        let stored: Vec<u8> = sqlx::query_scalar(
            "SELECT entry_bytes FROM chat.direct_request_transport_entries \
              WHERE conversation_id=$1 AND seq=$2",
        )
        .bind(p.cid)
        .bind(p.seq + 1)
        .fetch_one(&p.home_pool)
        .await
        .unwrap();
        assert_eq!(
            serde_json::from_slice::<Value>(&stored).unwrap(),
            commit_entry
        );
        let replay = p.accept(C33_SEQ, &commit_entry).await.unwrap();
        assert_eq!(replay["applied"], false);
        let count: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM chat.direct_request_transport_entries \
              WHERE conversation_id=$1 AND seq=$2",
        )
        .bind(p.cid)
        .bind(p.seq + 1)
        .fetch_one(&p.home_pool)
        .await
        .unwrap();
        assert_eq!(count, 1);
    })
    .await;
}

#[tokio::test]
async fn c33_http_transition_queues_and_home_verifies_its_receipted_control_entry() {
    let p = Pair::new().await;
    let queue = OutboundQueue::new(
        p.seq_pool.clone(),
        AuthMiddleware::new(),
        Arc::new(DsResolver::new(
            p.seq_pool.clone(),
            crate::federation::resolver::build_resolver_http_client(),
            C33_SEQ.to_owned(),
            format!("https://{}", host(C33_SEQ)),
            None,
            300,
        )),
    );
    let resolved = scope_sim_ds(Arc::clone(&p.seq_hooks), async {
        let resolver = DsResolver::new(
            p.seq_pool.clone(),
            crate::federation::resolver::build_resolver_http_client(),
            C33_SEQ.to_owned(),
            format!("https://{}", host(C33_SEQ)),
            None,
            300,
        );
        (
            resolver
                .resolve_authoritative_ds(p.deleted())
                .await
                .unwrap()
                .did,
            resolver
                .resolve_authoritative_ds(p.peer())
                .await
                .unwrap()
                .did,
        )
    })
    .await;
    assert_eq!(resolved, (C33_SEQ.to_owned(), C33_HOME.to_owned()));
    assert_eq!(
        scope_sim_ds(
            Arc::clone(&p.seq_hooks),
            C33PeerHomes::transition_peer_home(&p.seq_pool, p.cid, p.deleted()),
        )
        .await
        .unwrap(),
        Some(C33_HOME.to_owned())
    );
    scope_ds_clock(p.clock.clone(), async {
        let ciphertext_bytes = 16_384;
        let (status, response) = p
            .submit_metadata_sized_at(&p.router, false, ciphertext_bytes)
            .await;
        assert_eq!(status, StatusCode::OK, "{response}");
        let entry = response["entry"].clone();
        assert!(entry["sequencerReceipt"].is_object(), "{response}");
        let rows = control_rows(&p.seq_pool, p.cid).await;
        assert_eq!(rows.len(), 1, "sequenced control was not relayed: {rows:?}");
        let delivery: DeliverTransportControlEntry = serde_json::from_slice(&rows[0].5).unwrap();
        assert_eq!(delivery.entry, entry);
        assert_eq!(rows[0].1, C33_HOME);
        assert!(
            rows[0].5.len() > 16_384
                && rows[0].5.len() <= crate::SINGLE_MLS_ARTIFACT_BODY_LIMIT_BYTES,
            "full metadata entry size: {}",
            rows[0].5.len()
        );

        p.assert_refused(C33_OTHER, &entry, (StatusCode::FORBIDDEN, "NotAuthorized"))
            .await;
        p.assert_refused(
            C33_SEQ,
            &entry,
            (StatusCode::CONFLICT, "PredecessorMissing"),
        )
        .await;

        p.store(p.cid, &p.message).await;
        let forged = edited(&entry, |entry| {
            entry["sequencerReceipt"]["signature"] = json!(STANDARD.encode([0_u8; 64]));
        });
        p.assert_refused(
            C33_SEQ,
            &forged,
            (StatusCode::FORBIDDEN, "InvalidSignature"),
        )
        .await;
        let wrong_seq = edited(&entry, |entry| {
            let seq = entry["sequencerReceipt"]["seq"].as_u64().unwrap();
            entry["sequencerReceipt"]["seq"] = json!(seq + 1);
        });
        p.assert_refused(
            C33_SEQ,
            &wrong_seq,
            (StatusCode::FORBIDDEN, "InvalidSignature"),
        )
        .await;
        let wrong_digest = edited(&entry, |entry| {
            let ciphertext = [0x65_u8; 16];
            entry["signedRequest"]["body"]["metadataSnapshot"]["ciphertext"] =
                json!(STANDARD.encode(ciphertext));
            entry["signedRequest"]["body"]["metadataSnapshot"]["ciphertextSha256"] =
                json!(STANDARD.encode(Sha256::digest(ciphertext)));
        });
        p.assert_refused(
            C33_SEQ,
            &wrong_digest,
            (StatusCode::FORBIDDEN, "InvalidSignature"),
        )
        .await;
        p.clock
            .set_utc(latest_due(&p.seq_pool).await.max(current_utc()));
        let due = claim_due_heads(&p.seq_pool, 10, None).await.unwrap();
        assert_eq!(due.len(), 1);
        assert!(
            mark_item_delivered(&p.seq_pool, &due[0].id, due[0].claim_token)
                .await
                .unwrap()
        );
        p.network
            .serve(C33_HOME, group_relay_router(p.home.clone()));
        p.clock
            .set_utc(latest_due(&p.seq_pool).await.max(current_utc()));
        assert_eq!(drain(&queue, &p.seq_hooks, C33_SEQ, &p.seq_key).await, 1);
        assert_eq!(control_rows(&p.seq_pool, p.cid).await[0].2, "delivered");
        let replay = p.accept(C33_SEQ, &entry).await.unwrap();
        assert_eq!(replay["applied"], false);
        let entries = p.peer_entries(p.seq - 1).await;
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0]["seq"], p.seq);
        assert_eq!(entries[1]["seq"], p.seq + 1);
        assert_eq!(entries[1]["$type"], "blue.catbird.chat.defs#metadataEntry");
        assert!(entries[1]["sequencerReceipt"].is_object());
        let stored: Vec<u8> = sqlx::query_scalar(
            "SELECT entry_bytes FROM chat.direct_request_transport_entries \
              WHERE conversation_id=$1 AND seq=$2",
        )
        .bind(p.cid)
        .bind(p.seq + 1)
        .fetch_one(&p.home_pool)
        .await
        .unwrap();
        assert_eq!(serde_json::from_slice::<Value>(&stored).unwrap(), entry);
        let stored_at_seq: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM chat.direct_request_transport_entries \
              WHERE conversation_id=$1 AND seq=$2",
        )
        .bind(p.cid)
        .bind(p.seq + 1)
        .fetch_one(&p.home_pool)
        .await
        .unwrap();
        assert_eq!(stored_at_seq, 1);
    })
    .await;
}

#[tokio::test]
async fn receipt_key_resolution_never_holds_the_transport_inbox_lock() {
    let p = Pair::new().await;
    let (status, response) = p.submit_metadata().await;
    assert_eq!(status, StatusCode::OK, "{response}");
    let entry = response["entry"].clone();
    p.store(p.cid, &p.message).await;

    let resolution_started = Arc::new(tokio::sync::Notify::new());
    let release_resolution = Arc::new(tokio::sync::Notify::new());
    let base_transport = p.network.transport();
    let delayed_transport: SimHttpTransport = {
        let resolution_started = Arc::clone(&resolution_started);
        let release_resolution = Arc::clone(&release_resolution);
        Arc::new(move |request| {
            let base_transport = Arc::clone(&base_transport);
            let resolution_started = Arc::clone(&resolution_started);
            let release_resolution = Arc::clone(&release_resolution);
            Box::pin(async move {
                if request.method == axum::http::Method::GET
                    && request.url.host_str() == Some(host(C33_SEQ))
                {
                    resolution_started.notify_one();
                    release_resolution.notified().await;
                }
                base_transport(request).await
            })
        })
    };
    let delayed_hooks = Arc::new(SimDsHooks {
        service_did: p.home_hooks.service_did.clone(),
        self_endpoint: p.home_hooks.self_endpoint.clone(),
        signing_key_pem: p.home_hooks.signing_key_pem.clone(),
        group_relay_hmac_secret: p.home_hooks.group_relay_hmac_secret.clone(),
        http_transport: delayed_transport,
        dns_resolver: Arc::clone(&p.home_hooks.dns_resolver),
        retain_application_ciphertext: false,
    });
    let state = GroupRelayState::for_test(
        p.home_pool.clone(),
        C33_HOME.to_owned(),
        HMAC.as_bytes(),
        None,
    )
    .with_sim_hooks(Arc::clone(&delayed_hooks))
    .with_clock(p.clock.clone());
    let body = serde_json::to_vec(&DeliverTransportControlEntry {
        entry: entry.clone(),
    })
    .unwrap();
    let clock = p.clock.clone();
    let accepting = tokio::spawn(async move {
        scope_ds_clock(
            clock,
            scope_sim_ds(
                delayed_hooks,
                accept_transport_control_entry(&state, C33_SEQ, &body),
            ),
        )
        .await
    });
    tokio::time::timeout(
        std::time::Duration::from_secs(5),
        resolution_started.notified(),
    )
    .await
    .expect("receipt DID resolution started");

    let mut probe = p.home_pool.begin().await.unwrap();
    let unlocked = sqlx::query(
        "SELECT 1 FROM chat.direct_request_transport_inbox \
          WHERE conversation_id=$1 ORDER BY delivery_id FOR UPDATE NOWAIT",
    )
    .bind(p.cid)
    .execute(&mut *probe)
    .await;
    assert!(
        unlocked.is_ok(),
        "receipt-key HTTP held the transport inbox lock: {unlocked:?}"
    );
    probe.rollback().await.unwrap();
    release_resolution.notify_one();

    let accepted = accepting.await.unwrap().unwrap();
    assert_eq!(accepted["applied"], true);
    assert_eq!(p.accept(C33_SEQ, &entry).await.unwrap()["applied"], false);
}

#[tokio::test]
async fn c33_signerless_coordinator_refuses_before_sequencing() {
    let p = Pair::new().await;
    let before: (i64, i64) = sqlx::query_as(
        "SELECT current_state_version,next_entry_seq FROM chat.conversations WHERE conversation_id=$1",
    )
    .bind(p.cid)
    .fetch_one(&p.seq_pool)
    .await
    .unwrap();
    let router = http::router_for_authenticated_acceptance_without_i13(p.seq_pool.clone()).await;
    scope_ds_clock(p.clock.clone(), async {
        let (status, _) = p.submit_metadata_at(&router, false).await;
        assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
    })
    .await;
    let after: (i64, i64) = sqlx::query_as(
        "SELECT current_state_version,next_entry_seq FROM chat.conversations WHERE conversation_id=$1",
    )
    .bind(p.cid)
    .fetch_one(&p.seq_pool)
    .await
    .unwrap();
    assert_eq!(after, before);
    assert!(control_rows(&p.seq_pool, p.cid).await.is_empty());
}

#[tokio::test]
async fn c33_reset_request_and_activation_are_queued_as_controls() {
    let p = Pair::new().await;
    let signer = ed25519_dalek::SigningKey::from_bytes(&p.fixture.sender_ed25519_seed);
    let queue = OutboundQueue::new(
        p.seq_pool.clone(),
        AuthMiddleware::new(),
        Arc::new(DsResolver::new(
            p.seq_pool.clone(),
            crate::federation::resolver::build_resolver_http_client(),
            C33_SEQ.to_owned(),
            format!("https://{}", host(C33_SEQ)),
            None,
            300,
        )),
    );
    let control_router = {
        let (hooks, clock, receipt) = (
            Arc::clone(&p.seq_hooks),
            Arc::clone(&p.clock),
            p.receipt.clone(),
        );
        http::router_for_authenticated_acceptance_with(p.seq_pool.clone(), move |runtime| {
            runtime
                .with_sim_hooks(hooks)
                .with_clock(clock)
                .with_i13_receipt_signer(receipt)
        })
        .await
    };

    scope_ds_clock(p.clock.clone(), async {
        let prior = p.fixture.self_update_signed_request["body"]["prior"].clone();
        let reset_request_id = Uuid::new_v4();
        let reset = crate::chat_protocol::test_support::sign_mutation_json_for_test(
            &json!({
                "$type": "blue.catbird.chat.defs#resetRequestBody",
                "signatureDomain": "CATBIRD-CHAT-RESET-REQUEST\u{0000}",
                "resetRequestId": reset_request_id,
                "idempotencyKey": reset_request_id,
                "actorDid": p.deleted(),
                "actorDeviceId": p.fixture.sender_device_id,
                "keyId": p.fixture.sender_key_id,
                "authGeneration": 1,
                "prior": prior,
                "reason": "manualRecovery",
                "signedAt": current_utc().to_rfc3339_opts(SecondsFormat::Millis, true),
            }),
            &signer,
        )
        .unwrap();
        let (status, reset_response) = p
            .submit_sender_request_at(&control_router, "blue.catbird.chat.requestReset", &reset)
            .await;
        assert_eq!(status, StatusCode::OK, "{reset_response}");

        let participant_rows: Vec<(String, String, String, Option<Uuid>, String, Uuid)> =
            sqlx::query_as(
                "SELECT user_did,status,role,invitation_transition_id,created_by_did,\
                        created_by_device_id \
                   FROM chat.participants \
                  WHERE conversation_id=$1 AND current_membership \
                  ORDER BY convert_to(user_did,'UTF8')",
            )
            .bind(p.cid)
            .fetch_all(&p.seq_pool)
            .await
            .unwrap();
        let participants = participant_rows
            .into_iter()
            .map(
                |(user_did, status, role, invitation_id, invited_by_did, invited_by_device_id)| {
                    let mut participant =
                        json!({"userDid": user_did, "status": status, "role": role});
                    if let Some(invitation_transition_id) = invitation_id {
                        participant["invitationProvenance"] = json!({
                            "invitationTransitionId": invitation_transition_id,
                            "invitedByDid": invited_by_did,
                            "invitedByDeviceId": invited_by_device_id,
                        });
                    }
                    participant
                },
            )
            .collect::<Vec<_>>();
        let origin_seq: i64 = sqlx::query_scalar(
            "SELECT next_entry_seq FROM chat.conversations WHERE conversation_id=$1",
        )
        .bind(p.cid)
        .fetch_one(&p.seq_pool)
        .await
        .unwrap();
        let activation = crate::chat_protocol::test_support::sign_direct_reset_activation_for_test(
            reset_request_id,
            &p.fixture.self_update_signed_request["body"]["prior"],
            json!(participants),
            origin_seq as u64,
            p.deleted(),
            p.fixture.sender_device_id,
            &p.fixture.sender_key_id,
            p.fixture.sender_ed25519_seed,
        )
        .unwrap();
        let (status, activation_response) = p
            .submit_sender_request_at(
                &control_router,
                "blue.catbird.chat.activateReset",
                &activation,
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{activation_response}");

        let rows = control_rows(&p.seq_pool, p.cid).await;
        assert_eq!(rows.len(), 2, "{rows:?}");
        for (row, response) in rows.iter().zip([&reset_response, &activation_response]) {
            let queued: DeliverTransportControlEntry = serde_json::from_slice(&row.5).unwrap();
            assert_eq!(queued.entry, response["entry"]);
            assert!(queued.entry["sequencerReceipt"].is_object());
        }

        p.store(p.cid, &p.message).await;
        p.network
            .serve(C33_HOME, transport_home_delivery_router(&p));
        for _ in 0..16 {
            p.clock
                .set_utc(latest_due(&p.seq_pool).await.max(current_utc()));
            drain(&queue, &p.seq_hooks, C33_SEQ, &p.seq_key).await;
            if control_rows(&p.seq_pool, p.cid)
                .await
                .iter()
                .all(|row| row.2 == "delivered")
            {
                break;
            }
        }
        let outcomes: Vec<(String, Option<String>)> = sqlx::query_as(
            "SELECT status,last_error FROM outbound_queue \
             WHERE convo_id=$1 AND id LIKE $2 ORDER BY id",
        )
        .bind(p.cid.to_string())
        .bind(format!("{CONTROL_PREFIX}%"))
        .fetch_all(&p.seq_pool)
        .await
        .unwrap();
        assert_eq!(
            outcomes
                .iter()
                .map(|(status, _)| status.as_str())
                .collect::<Vec<_>>(),
            ["delivered", "delivered"],
            "{outcomes:?}"
        );
        let home_entries = p.peer_entries(p.seq - 1).await;
        let mut expected = [
            p.message.clone(),
            reset_response["entry"].clone(),
            activation_response["entry"].clone(),
        ];
        for entry in &mut expected {
            let definition = entry["$type"]
                .as_str()
                .and_then(|value| value.split_once('#'))
                .map(|(_, definition)| definition.to_owned())
                .unwrap();
            crate::chat_protocol::direct_request_transcript::present_read_presentation(
                &definition,
                entry,
            )
            .unwrap();
        }
        assert_eq!(
            home_entries, expected,
            "the transport-only home must store the exact sequencer-verified stream"
        );
    })
    .await;
}

#[tokio::test]
async fn c33_transport_home_transition_is_relayed_back_with_receipt_and_contiguous_state() {
    let p = Pair::new().await;
    add_second_recipient_delivery(&p).await;
    let seq_state = GroupRelayState::for_test(
        p.seq_pool.clone(),
        C33_SEQ.to_owned(),
        HMAC.as_bytes(),
        Some(Arc::new(p.receipt.clone())),
    )
    .with_sim_hooks(Arc::clone(&p.seq_hooks))
    .with_clock(p.clock.clone());
    p.network.serve(C33_SEQ, group_relay_router(seq_state));
    let home_router = transport_home_chat_router(&p).await;
    scope_ds_clock(p.clock.clone(), async {
        let (status, response, request) =
            p.submit_metadata_with_request_at(&home_router, true).await;
        assert_eq!(status, StatusCode::OK, "{response}");
        let entry = response["entry"].clone();
        assert!(entry["sequencerReceipt"].is_object(), "{response}");
        let next_after_accept: i64 = sqlx::query_scalar(
            "SELECT next_entry_seq FROM chat.conversations WHERE conversation_id=$1",
        )
        .bind(p.cid)
        .fetch_one(&p.seq_pool)
        .await
        .unwrap();
        let (replay_status, replay) = p
            .submit_peer_request(&home_router, "blue.catbird.chat.submitTransition", &request)
            .await;
        assert_eq!((replay_status, replay), (StatusCode::OK, response));
        assert_eq!(
            sqlx::query_scalar::<_, i64>(
                "SELECT next_entry_seq FROM chat.conversations WHERE conversation_id=$1",
            )
            .bind(p.cid)
            .fetch_one(&p.seq_pool)
            .await
            .unwrap(),
            next_after_accept
        );
        let rows = control_rows(&p.seq_pool, p.cid).await;
        assert_eq!(rows.len(), 1, "{rows:?}");
        assert_eq!(rows[0].1, C33_HOME);
        p.store(p.cid, &p.message).await;
        assert_eq!(p.accept(C33_SEQ, &entry).await.unwrap()["applied"], true);
        assert_eq!(p.accept(C33_SEQ, &entry).await.unwrap()["applied"], false);
        let home_entries = p.peer_entries(p.seq - 1).await;
        assert_eq!(home_entries.len(), 2);
        assert_eq!(home_entries[0]["seq"], p.seq);
        assert_eq!(home_entries[1]["seq"], p.seq + 1);
        assert_eq!(
            home_entries[1]["$type"],
            "blue.catbird.chat.defs#metadataEntry"
        );
        let coordinator_entries = p.coordinator_entries(p.seq).await;
        assert_eq!(coordinator_entries.len(), 1);
        assert_eq!(coordinator_entries[0]["seq"], p.seq + 1);
        assert_eq!(
            coordinator_entries[0]["$type"],
            "blue.catbird.chat.defs#metadataEntry"
        );
    })
    .await;
}

#[tokio::test]
async fn c33_transport_home_real_commit_returns_receipt_and_is_stored_on_both_sides() {
    let p = Pair::new().await;
    add_second_recipient_delivery(&p).await;
    let seq_state = GroupRelayState::for_test(
        p.seq_pool.clone(),
        C33_SEQ.to_owned(),
        HMAC.as_bytes(),
        Some(Arc::new(p.receipt.clone())),
    )
    .with_sim_hooks(Arc::clone(&p.seq_hooks))
    .with_clock(p.clock.clone());
    p.network.serve(C33_SEQ, group_relay_router(seq_state));
    let home_router = transport_home_chat_router(&p).await;
    let queue = OutboundQueue::new(
        p.seq_pool.clone(),
        AuthMiddleware::new(),
        Arc::new(DsResolver::new(
            p.seq_pool.clone(),
            crate::federation::resolver::build_resolver_http_client(),
            C33_SEQ.to_owned(),
            format!("https://{}", host(C33_SEQ)),
            None,
            300,
        )),
    );

    scope_ds_clock(p.clock.clone(), async {
        let request = p.fixture.peer_self_update_signed_request.clone();
        let (status, response) = p
            .submit_peer_request(&home_router, "blue.catbird.chat.submitTransition", &request)
            .await;
        assert_eq!(status, StatusCode::OK, "{response}");
        let entry = response["entry"].clone();
        assert_eq!(entry["$type"], "blue.catbird.chat.defs#commitEntry");
        assert!(entry["sequencerReceipt"].is_object());
        let next_after_accept: i64 = sqlx::query_scalar(
            "SELECT next_entry_seq FROM chat.conversations WHERE conversation_id=$1",
        )
        .bind(p.cid)
        .fetch_one(&p.seq_pool)
        .await
        .unwrap();
        let (replay_status, replay) = p
            .submit_peer_request(&home_router, "blue.catbird.chat.submitTransition", &request)
            .await;
        assert_eq!((replay_status, replay), (StatusCode::OK, response));
        assert_eq!(
            sqlx::query_scalar::<_, i64>(
                "SELECT next_entry_seq FROM chat.conversations WHERE conversation_id=$1",
            )
            .bind(p.cid)
            .fetch_one(&p.seq_pool)
            .await
            .unwrap(),
            next_after_accept
        );
        let rows = control_rows(&p.seq_pool, p.cid).await;
        assert_eq!(rows.len(), 1, "{rows:?}");
        assert_eq!(rows[0].1, C33_HOME);

        p.network
            .serve(C33_HOME, transport_home_delivery_router(&p));
        assert_eq!(queue_rows(&p.seq_pool, p.cid).await.len(), 2);
        p.clock
            .set_utc(latest_due(&p.seq_pool).await.max(current_utc()));
        let mut delivered = 0;
        for _ in 0..2 {
            p.clock
                .set_utc(latest_due(&p.seq_pool).await.max(current_utc()));
            delivered += drain(&queue, &p.seq_hooks, C33_SEQ, &p.seq_key).await;
        }
        assert_eq!(delivered, 2);
        let home_entries = p.peer_entries(p.seq - 1).await;
        assert_eq!(home_entries.len(), 2, "{home_entries:?}");
        assert_eq!(home_entries[0]["seq"], p.seq);
        assert_eq!(home_entries[1]["seq"], p.seq + 1);
        assert_eq!(
            home_entries[1]["$type"],
            "blue.catbird.chat.defs#commitEntry"
        );
        assert!(home_entries[1]["sequencerReceipt"].is_object());
        let coordinator_entries = p.coordinator_entries(p.seq).await;
        assert_eq!(coordinator_entries.len(), 1);
        assert_eq!(coordinator_entries[0]["seq"], p.seq + 1);
        assert_eq!(
            coordinator_entries[0]["$type"],
            "blue.catbird.chat.defs#commitEntry"
        );
        assert!(coordinator_entries[0]["sequencerReceipt"].is_object());

        let stored: Vec<u8> = sqlx::query_scalar(
            "SELECT entry_bytes FROM chat.direct_request_transport_entries \
              WHERE conversation_id=$1 AND seq=$2",
        )
        .bind(p.cid)
        .bind(p.seq + 1)
        .fetch_one(&p.home_pool)
        .await
        .unwrap();
        assert_eq!(serde_json::from_slice::<Value>(&stored).unwrap(), entry);
        assert_eq!(p.accept(C33_SEQ, &entry).await.unwrap()["applied"], false);
    })
    .await;
}

#[tokio::test]
async fn survivor_metadata_never_resolves_or_queues_to_a_deleted_peer() {
    let p = Pair::new().await;
    scope_ds_clock(p.clock.clone(), async {
        let sequenced = scope_sim_ds(
            Arc::clone(&p.seq_hooks),
            crate::labyrinth::repo::retention::delete_account_data_with_conversations(
                &p.seq_pool,
                p.deleted(),
                current_utc(),
                Some(&p.receipt),
            ),
        )
        .await
        .unwrap();
        assert_eq!(sequenced, 1);
        let controls_before = control_rows(&p.seq_pool, p.cid).await;
        assert_eq!(controls_before.len(), 1, "{controls_before:?}");
        p.network
            .serve(&format!("pds-{}", host(p.deleted())), Router::new());
        let seq_state = GroupRelayState::for_test(
            p.seq_pool.clone(),
            C33_SEQ.to_owned(),
            HMAC.as_bytes(),
            Some(Arc::new(p.receipt.clone())),
        )
        .with_sim_hooks(Arc::clone(&p.seq_hooks))
        .with_clock(p.clock.clone());
        p.network.serve(C33_SEQ, group_relay_router(seq_state));
        let home_router = transport_home_chat_router(&p).await;

        let (status, response, request) =
            p.submit_metadata_with_request_at(&home_router, true).await;
        assert_eq!(status, StatusCode::OK, "{response}");
        assert!(response["entry"]["sequencerReceipt"].is_object());
        let next_after_accept: i64 = sqlx::query_scalar(
            "SELECT next_entry_seq FROM chat.conversations WHERE conversation_id=$1",
        )
        .bind(p.cid)
        .fetch_one(&p.seq_pool)
        .await
        .unwrap();
        let (status, replay) = p
            .submit_peer_request(&home_router, "blue.catbird.chat.submitTransition", &request)
            .await;
        assert_eq!((status, replay), (StatusCode::OK, response));
        assert_eq!(
            sqlx::query_scalar::<_, i64>(
                "SELECT next_entry_seq FROM chat.conversations WHERE conversation_id=$1",
            )
            .bind(p.cid)
            .fetch_one(&p.seq_pool)
            .await
            .unwrap(),
            next_after_accept
        );
        assert_eq!(
            control_rows(&p.seq_pool, p.cid)
                .await
                .iter()
                .map(|row| (&row.0, &row.1))
                .collect::<Vec<_>>(),
            controls_before
                .iter()
                .map(|row| (&row.0, &row.1))
                .collect::<Vec<_>>()
        );
    })
    .await;
}

#[tokio::test]
async fn a_transport_only_home_verifies_a_control_entry_before_any_effect() {
    let p = Pair::new().await;
    let (cid, seq) = (p.cid, p.seq);
    let deleted = p.deleted().to_owned();
    let peer = p.peer().to_owned();
    scope_ds_clock(p.clock.clone(), async {
        let at = current_utc();
        let entry_id = Uuid::new_v4();
        let genuine = Pair::entry(&p.receipt, cid, &deleted, seq + 1, entry_id, at);
        let forbidden = (StatusCode::FORBIDDEN, "NotAuthorized");
        let unsigned = (StatusCode::FORBIDDEN, "InvalidSignature");
        let impostor = I13ReceiptSigner::new(key(0x56), C33_SEQ.to_owned());
        // An authority naming a receipt method the coordinator never published.
        let unpublished = I13ReceiptSigner::new_with_key_id(
            key(0x57),
            C33_SEQ.to_owned(),
            format!("{C33_SEQ}#mls-receipt-2"),
        )
        .unwrap();
        let cases = [
            // Not the pair's coordinator, with the coordinator's entry or its own.
            (C33_OTHER, genuine.clone(), forbidden),
            (
                C33_OTHER,
                Pair::entry(&p.other_receipt, cid, &deleted, seq + 1, entry_id, at),
                forbidden,
            ),
            // The coordinator forwarding an entry another DS sequenced.
            (
                C33_SEQ,
                Pair::entry(&p.other_receipt, cid, &deleted, seq + 1, entry_id, at),
                forbidden,
            ),
            // A conversation this home holds no pair for.
            (
                C33_SEQ,
                Pair::entry(&p.receipt, Uuid::new_v4(), &deleted, seq + 1, entry_id, at),
                (StatusCode::NOT_FOUND, "ConversationNotFound"),
            ),
            // Only the pair's counterparty, never a stranger or this home's own party.
            (
                C33_SEQ,
                Pair::entry(
                    &p.receipt,
                    cid,
                    "did:web:stranger.example.com",
                    seq + 1,
                    entry_id,
                    at,
                ),
                forbidden,
            ),
            (
                C33_SEQ,
                Pair::entry(&p.receipt, cid, &peer, seq + 1, entry_id, at),
                forbidden,
            ),
            // The coordinator's name over another key.
            (
                C33_SEQ,
                Pair::entry(&impostor, cid, &deleted, seq + 1, entry_id, at),
                unsigned,
            ),
            (
                C33_SEQ,
                Pair::entry(&unpublished, cid, &deleted, seq + 1, entry_id, at),
                unsigned,
            ),
            // Every signed field, altered after signing.
            (
                C33_SEQ,
                edited(&genuine, |e| {
                    e["sequencerDid"] = json!(C33_OTHER);
                    e["sequencerAuthority"]["sequencerDid"] = json!(C33_OTHER);
                }),
                forbidden,
            ),
            (
                C33_SEQ,
                edited(&genuine, |e| e["conversationId"] = json!(p.twin)),
                unsigned,
            ),
            (
                C33_SEQ,
                edited(&genuine, |e| e["deletedDid"] = json!(peer)),
                forbidden,
            ),
            (
                C33_SEQ,
                edited(&genuine, |e| e["seq"] = json!(seq + 2)),
                unsigned,
            ),
            (
                C33_SEQ,
                edited(&genuine, |e| e["entryId"] = json!(Uuid::new_v4())),
                unsigned,
            ),
            (
                C33_SEQ,
                edited(&genuine, |e| {
                    e["receivedAt"] = json!((at + chrono::TimeDelta::milliseconds(1))
                        .to_rfc3339_opts(SecondsFormat::Millis, true))
                }),
                unsigned,
            ),
            (
                C33_SEQ,
                edited(&genuine, |e| {
                    e["sequencerAuthority"]["keyId"] = json!(format!("{C33_SEQ}#atproto"))
                }),
                unsigned,
            ),
            (
                C33_SEQ,
                edited(&genuine, |e| {
                    let mut signature = STANDARD
                        .decode(
                            e["sequencerAuthority"]["signature"]["$bytes"]
                                .as_str()
                                .unwrap(),
                        )
                        .unwrap();
                    signature[31] ^= 1;
                    e["sequencerAuthority"]["signature"]["$bytes"] =
                        json!(STANDARD.encode(signature));
                }),
                unsigned,
            ),
        ];
        for (caller, entry, refusal) in cases {
            p.assert_refused(caller, &entry, refusal).await;
        }

        // D's application, the entry's predecessor, has not reached this home:
        // a retryable predecessor refusal that changes nothing.
        let before = home_state(&p.home_pool).await;
        let gap = p.accept(C33_SEQ, &genuine).await.expect_err("a gap");
        assert_eq!(gap.status(), StatusCode::CONFLICT);
        let body: Value = serde_json::from_slice(
            &axum::body::to_bytes(gap.into_body(), 1 << 16)
                .await
                .unwrap(),
        )
        .unwrap();
        assert_eq!(
            body["error"],
            crate::federation::errors::PREDECESSOR_MISSING_ERROR
        );
        assert_eq!(home_state(&p.home_pool).await, before);

        // After the earlier delivery the same entry applies, pruning D's held
        // ciphertext; its redelivery changes nothing, and another entry at its
        // seq is a definitive conflict.
        p.store(cid, &p.message).await;
        assert_eq!(
            p.accept(C33_SEQ, &genuine).await.unwrap(),
            json!({ "accepted": true, "applied": true, "prunedCount": 1 })
        );
        let settled = home_state(&p.home_pool).await;
        assert_eq!(
            p.accept(C33_SEQ, &genuine).await.unwrap(),
            json!({ "accepted": true, "applied": false, "prunedCount": 0 })
        );
        assert_eq!(home_state(&p.home_pool).await, settled);
        p.assert_refused(
            C33_SEQ,
            &Pair::entry(&p.receipt, cid, &deleted, seq + 1, Uuid::new_v4(), at),
            (StatusCode::CONFLICT, "EntryConflict"),
        )
        .await;
    })
    .await;
}

/// D, homed at its pair's coordinator, deletes its account. The coordinator
/// sequences the signed entry and queues it for P's transport-only home in the
/// same transaction, behind D's earlier delivery there and ahead of any later
/// one, and retries it through a partition and an undeclared 404. P's home
/// applies it: P's `getEntries` returns it verbatim at its seq, and D's held
/// ciphertext there is pruned.
#[tokio::test]
async fn a_c33_coordinator_delivers_its_own_partys_deletion_to_the_peers_home() {
    let p = Pair::new().await;
    let (cid, seq) = (p.cid, p.seq);
    let deleted = p.deleted().to_owned();
    // A C33 delivery resolves its home's declared endpoint from that home's DID
    // document, so its queue resolves through the sim network, not a DID pin.
    let queue = OutboundQueue::new(
        p.seq_pool.clone(),
        AuthMiddleware::new(),
        Arc::new(DsResolver::new(
            p.seq_pool.clone(),
            crate::federation::resolver::build_resolver_http_client(),
            C33_SEQ.to_owned(),
            format!("https://{}", host(C33_SEQ)),
            None,
            300,
        )),
    );
    scope_ds_clock(p.clock.clone(), async {
        let at = current_utc();
        let chain_before = chain(&p.seq_pool, cid).await;
        let head: (i64, i64) = sqlx::query_as(
            "SELECT current_generation, current_state_version FROM chat.conversations \
              WHERE conversation_id = $1",
        )
        .bind(cid)
        .fetch_one(&p.seq_pool)
        .await
        .unwrap();
        // Without the dedicated receipt signer, or with a pair whose peer home
        // was not resolved before the transaction, the deletion commits nothing.
        let unsigned = scope_sim_ds(
            Arc::clone(&p.seq_hooks),
            delete_account_data_with_conversations(&p.seq_pool, &deleted, at, None),
        )
        .await
        .expect_err("no receipt signer");
        assert_eq!(
            (unsigned.status(), unsigned.name()),
            (StatusCode::SERVICE_UNAVAILABLE, "SignerUnavailable")
        );
        let mut conn = p.seq_pool.acquire().await.unwrap();
        let unresolved = scope_sim_ds(
            Arc::clone(&p.seq_hooks),
            purge_account(
                &mut conn,
                &deleted,
                at,
                Some(&p.receipt),
                &C33PeerHomes::default(),
            ),
        )
        .await
        .expect_err("an unresolved peer home");
        assert_eq!(
            (unresolved.status(), unresolved.name()),
            (StatusCode::SERVICE_UNAVAILABLE, "PeerHomeUnavailable")
        );
        drop(conn);
        assert_eq!(chain(&p.seq_pool, cid).await, chain_before);
        assert!(control_rows(&p.seq_pool, cid).await.is_empty());

        assert_eq!(
            scope_sim_ds(
                Arc::clone(&p.seq_hooks),
                delete_account_data_with_conversations(&p.seq_pool, &deleted, at, Some(&p.receipt)),
            )
            .await
            .unwrap(),
            1
        );
        assert_eq!(
            deletions(&p.seq_pool, cid).await,
            [(seq + 1, deleted.clone())]
        );
        // Sequencing it moves no coordinates: only the coordinator's seq head
        // advances, so its pair's next message is sequenced right after it.
        assert_eq!(
            chain(&p.seq_pool, cid).await,
            (chain_before.0 + 1, Some(seq + 1), seq + 2)
        );
        let head_after: (i64, i64) = sqlx::query_as(
            "SELECT current_generation, current_state_version FROM chat.conversations \
              WHERE conversation_id = $1",
        )
        .bind(cid)
        .fetch_one(&p.seq_pool)
        .await
        .unwrap();
        assert_eq!(head_after, head);
        let rows = control_rows(&p.seq_pool, cid).await;
        assert_eq!(rows.len(), 1, "one control entry for P's home");
        let (id, target, status, _, _, payload) = &rows[0];
        assert_eq!(
            (id.as_str(), target.as_str(), status.as_str()),
            (
                format!("{CONTROL_PREFIX}{cid}-{}", seq + 1).as_str(),
                C33_HOME,
                "pending"
            )
        );
        let entry = serde_json::from_slice::<DeliverTransportControlEntry>(payload)
            .unwrap()
            .entry;
        let (deletion, authority) = AccountDeletion::from_entry(&entry).unwrap();
        let entry_id: Uuid = sqlx::query_scalar(
            "SELECT entry_id FROM chat.entries WHERE conversation_id = $1 AND seq = $2",
        )
        .bind(cid)
        .bind(seq + 1)
        .fetch_one(&p.seq_pool)
        .await
        .unwrap();
        assert_eq!(
            deletion,
            AccountDeletion {
                sequencer_did: C33_SEQ.to_owned(),
                conversation_id: cid,
                deleted_did: deleted.clone(),
                seq: seq + 1,
                entry_id,
                deleted_at: at,
            }
        );
        authority
            .verify(&p.receipt.verifying_key(), &deletion)
            .expect("signed by the coordinator's #mls-receipt-1 key");

        // Only the stream's head, D's earlier delivery, is ever due first.
        p.clock.set_utc(latest_due(&p.seq_pool).await);
        let due = claim_due_heads(&p.seq_pool, 10, None).await.unwrap();
        assert_eq!(
            due.iter().map(|item| item.id.as_str()).collect::<Vec<_>>(),
            [format!("msg-delivery-{cid}-{seq}").as_str()]
        );
        // That delivery lands, as P's home stores it.
        p.store(cid, &p.message).await;
        assert!(
            mark_item_delivered(&p.seq_pool, &due[0].id, due[0].claim_token)
                .await
                .unwrap()
        );
        // A later send of D's other device, queued to that home before the
        // entry leaves, never overtakes it: the stream orders by seq. (Its body
        // is never sent here; only its queue position is under test.)
        let mut tx = p.seq_pool.begin().await.unwrap();
        crate::federation::queue::enqueue_c33_in_tx(
            &p.seq_pool,
            &mut tx,
            &format!("msg-delivery-{cid}-{}", seq + 2),
            C33_HOME,
            &format!("https://{}", host(C33_HOME)),
            "blue.catbird.mlsDS.deliverMessageEntry",
            &serde_json::to_vec(&json!({ "conversationId": cid, "entry": { "seq": seq + 2 } }))
                .unwrap(),
            &cid.to_string(),
            "",
        )
        .await
        .unwrap();
        tx.commit().await.unwrap();

        // Unreachable, the home is retried past the queue's retry limit.
        p.network.partition(true);
        for attempt in 1..=6 {
            p.clock
                .set_utc(latest_due(&p.seq_pool).await.max(current_utc()));
            assert_eq!(drain(&queue, &p.seq_hooks, C33_SEQ, &p.seq_key).await, 1);
            let rows = control_rows(&p.seq_pool, cid).await;
            let last_error: Option<String> =
                sqlx::query_scalar("SELECT last_error FROM outbound_queue WHERE id = $1")
                    .bind(&rows[0].0)
                    .fetch_one(&p.seq_pool)
                    .await
                    .unwrap();
            assert_eq!(
                (rows[0].2.as_str(), rows[0].3),
                ("pending", attempt),
                "attempt {attempt}: {last_error:?}"
            );
        }
        // A home answering an undeclared 404 may still hold the pair: retried.
        p.network.partition(false);
        p.network.serve(C33_HOME, Router::new());
        p.clock
            .set_utc(latest_due(&p.seq_pool).await.max(current_utc()));
        assert_eq!(drain(&queue, &p.seq_hooks, C33_SEQ, &p.seq_key).await, 1);
        let rows = control_rows(&p.seq_pool, cid).await;
        assert_eq!((rows[0].2.as_str(), rows[0].3), ("pending", 7));
        p.network
            .serve(C33_HOME, group_relay_router(p.home.clone()));
        p.clock
            .set_utc(latest_due(&p.seq_pool).await.max(current_utc()));
        assert_eq!(drain(&queue, &p.seq_hooks, C33_SEQ, &p.seq_key).await, 1);
        assert_eq!(control_rows(&p.seq_pool, cid).await[0].2, "delivered");

        // P reads the coordinator's exact entry at its seq, after D's pruned message.
        let stored: (Vec<u8>, bool) = sqlx::query_as(
            "SELECT entry_bytes, payload_pruned_at IS NOT NULL \
               FROM chat.direct_request_transport_entries WHERE conversation_id = $1 AND seq = $2",
        )
        .bind(cid)
        .bind(seq)
        .fetch_one(&p.home_pool)
        .await
        .unwrap();
        assert!(stored.1, "D's held ciphertext is pruned");
        assert!(serde_json::from_slice::<Value>(&stored.0).unwrap()["payloadPruned"] == true);
        let entries = p.peer_entries(seq - 1).await;
        assert_eq!(entries.len(), 2, "{entries:?}");
        assert_eq!(
            (
                entries[0]["seq"].as_i64(),
                entries[0]["payloadPruned"].as_bool()
            ),
            (Some(seq), Some(true))
        );
        assert_eq!(entries[1], entry);

        // Redelivered, it changes nothing.
        let settled = home_state(&p.home_pool).await;
        assert_eq!(
            p.accept(C33_SEQ, &entry).await.unwrap(),
            json!({ "accepted": true, "applied": false, "prunedCount": 0 })
        );
        assert_eq!(home_state(&p.home_pool).await, settled);
    })
    .await;
}

impl Pair {
    /// P's own signed application at `seq`, its body edited by `edit` before
    /// P's device signs it.
    fn peer_message(&self, seq: i64, edit: impl FnOnce(&mut Value)) -> Value {
        let message_id = Uuid::new_v4();
        let mut body = self.fixture.signed_request["body"].clone();
        body["messageId"] = json!(message_id);
        body["actorDid"] = json!(self.peer());
        body["actorDeviceId"] = json!(self.fixture.recipient_device_id);
        body["keyId"] = json!(self.fixture.recipient_key_id);
        body["aad"]["messageId"] = json!(STANDARD.encode(message_id.as_bytes()));
        edit(&mut body);
        let signed = crate::chat_protocol::test_support::sign_mutation_json_for_test(
            &body,
            &ed25519_dalek::SigningKey::from_bytes(&self.fixture.recipient_ed25519_seed),
        )
        .unwrap();
        json!({
            "$type": "blue.catbird.chat.defs#applicationEntry",
            "entryId": Uuid::new_v4(),
            "conversationId": self.cid,
            "seq": seq,
            "receivedAt": current_utc().to_rfc3339_opts(SecondsFormat::Millis, true),
            "signedRequest": signed,
        })
    }

    /// This home ingesting `entry` from the pair's coordinator.
    async fn ingest(&self, entry: &Value) -> Result<(), crate::federation::FederationError> {
        scope_sim_ds(
            Arc::clone(&self.home_hooks),
            crate::federation::canonical_relay::ingest_remote_message_entry(
                &self.home_pool,
                None,
                C33_SEQ,
                self.cid,
                entry,
            ),
        )
        .await
    }
}

/// A control entry carries no coordinates: the next message of a deleted
/// account's peer is compared with the nearest entry that does, including a
/// predecessor whose application payload was pruned through the real transport
/// prune path. A wrong prior is still refused, and a missing predecessor is
/// still the retryable gap.
#[tokio::test]
async fn a_transport_home_keeps_its_pairs_stream_after_a_deletion_entry() {
    let p = Pair::new().await;
    let (cid, seq) = (p.cid, p.seq);
    scope_ds_clock(p.clock.clone(), async {
        p.store(cid, &p.message).await;
        let deletion = Pair::entry(
            &p.receipt,
            cid,
            p.deleted(),
            seq + 1,
            Uuid::new_v4(),
            current_utc(),
        );
        p.accept(C33_SEQ, &deletion)
            .await
            .expect("the deletion applies");
        let refusal = |result: Result<(), crate::federation::FederationError>| match result {
            Err(crate::federation::FederationError::InvalidRequest(reason)) => reason,
            other => panic!("expected a refusal, got {other:?}"),
        };

        let before = home_state(&p.home_pool).await;
        let wrong = p.peer_message(seq + 2, |body| {
            let epoch = body["prior"]["epoch"].as_i64().unwrap() + 1;
            body["prior"]["epoch"] = json!(epoch);
            body["aad"]["prior"]["epoch"] = json!(epoch);
        });
        assert_eq!(
            refusal(p.ingest(&wrong).await),
            "message coordinates differ from retained predecessor"
        );
        assert_eq!(home_state(&p.home_pool).await, before);

        p.ingest(&p.peer_message(seq + 2, |_| {}))
            .await
            .expect("the pair's next message follows the deletion entry");
        let mut tx = p.home_pool.begin().await.unwrap();
        assert!(delivery::prune_expired_transport_application_payload(
            &mut tx,
            cid,
            seq + 2,
            current_utc(),
            current_utc(),
        )
        .await
        .unwrap());
        tx.commit().await.unwrap();
        let later = p.peer_message(seq + 4, |_| {});
        // The gap is the typed, retried predecessor conflict, not a refusal.
        let gap = p.ingest(&later).await.expect_err("a gap");
        assert!(
            matches!(
                &gap,
                crate::federation::FederationError::PredecessorMissing { .. }
            ),
            "{gap:?}"
        );
        assert_eq!(
            gap.reason_code(),
            crate::federation::errors::PREDECESSOR_MISSING_REASON
        );
        p.ingest(&p.peer_message(seq + 3, |_| {}))
            .await
            .expect("the gap's predecessor arrives");
        p.ingest(&later).await.expect("the gap closes");
        let held: Vec<i64> = sqlx::query_scalar(
            "SELECT seq FROM chat.direct_request_transport_entries \
              WHERE conversation_id = $1 ORDER BY seq",
        )
        .bind(cid)
        .fetch_all(&p.home_pool)
        .await
        .unwrap();
        assert_eq!(held, (1..=seq + 4).collect::<Vec<_>>());
    })
    .await;
}

#[path = "c33_deleted_peer_tests.rs"]
mod deleted_peer;

#[path = "c33_deleted_acceptance_tests.rs"]
mod deleted_acceptance;
