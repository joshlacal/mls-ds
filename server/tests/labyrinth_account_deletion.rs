//! `deleteAccountData` on the sequencer prunes the deleted account's application
//! ciphertext, so a member that has not fetched one of its messages can never decrypt,
//! show or witness-archive it. The `seq` skeleton, digests and I13 receipt stay, and each
//! home the messages were fanned out to is queued the same signed entries-pruned notice
//! as an ACK prune. Its `accountDeletedEntry` is the sequencer's signed evidence, served
//! to every device of a current member DID, so even a fresh device can hide the deleted
//! account's restored history.
#![cfg(feature = "test-support")]

mod common;

use axum::{http::StatusCode, Router};
use catbird_server::{
    chat_protocol::test_support::{
        seed_clean_slate_application_fixture, seed_remote_clean_slate_application_fixture,
        CleanSlateApplicationFixture,
    },
    federation::receipt::{AccountDeletion, I13ReceiptSigner},
    labyrinth::repo::retention::delete_account_data_with_conversations,
};
use chrono::{DateTime, Utc};
use common::http_acceptance as http;
use serde_json::{json, Value};
use uuid::Uuid;

const ACCOUNT_DELETED: &str = "blue.catbird.chat.defs#accountDeletedEntry";

const SELF_DID: &str = "did:web:ds-deletion.selfhost.example.com";
const SELF_ENDPOINT: &str = "https://ds-deletion.selfhost.example.com";

/// Every test sets the process-wide `SERVICE_DID` the acceptance router reads.
static ENV_LOCK: std::sync::LazyLock<tokio::sync::Mutex<()>> =
    std::sync::LazyLock::new(|| tokio::sync::Mutex::new(()));

/// `(payload_pruned_at, ciphertext held, send payload held, I13 receipt held)` of an entry.
type Held = (Option<DateTime<Utc>>, bool, bool, bool);
const HELD: Held = (None, true, true, true);

fn pruned(at: DateTime<Utc>) -> Held {
    (Some(at), false, false, true)
}

struct Sequencer {
    pool: sqlx::PgPool,
    router: Router,
    signer: I13ReceiptSigner,
    _db: common::fresh_db::DisposableDatabase,
}

async fn sequencer() -> Sequencer {
    std::env::set_var("SERVICE_DID", SELF_DID);
    std::env::set_var("SELF_ENDPOINT", SELF_ENDPOINT);
    let db = common::fresh_db::fresh_fully_migrated_db("labyrinth_srv_").await;
    let pool = db.connect(6).await;
    http::ensure_fence(&pool).await;
    let signer = common::proof_i13_signer();
    let router = http::router_for_authenticated_acceptance(pool.clone()).await;
    Sequencer {
        pool,
        router,
        signer,
        _db: db,
    }
}

async fn device(did: &str, device_id: Uuid) -> http::Device {
    let signing = http::random_p256();
    let jwk = http::public_jwk(&signing);
    let device = http::Device {
        did: did.to_owned(),
        device_id,
        jkt: http::jwk_thumbprint(&jwk),
        signing,
        jwk,
    };
    http::cache_device_did(&device).await;
    device
}

/// The `seq` of the fixture's application, sequenced through the real `sendMessage` route.
async fn send(s: &Sequencer, fixture: &CleanSlateApplicationFixture) -> i64 {
    let sender = device(&fixture.sender_did, fixture.sender_device_id).await;
    let body = serde_json::to_vec(&json!({ "signedRequest": fixture.signed_request })).unwrap();
    let (status, reply) = http::send(
        s.router.clone(),
        http::unsigned_json_request(&sender, "blue.catbird.chat.sendMessage", body),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "sendMessage: {reply}");
    reply["entry"]["seq"].as_i64().expect("entry seq")
}

async fn held(pool: &sqlx::PgPool, conversation_id: Uuid, seq: i64) -> Held {
    sqlx::query_as(
        "SELECT e.payload_pruned_at, e.accepted_payload_bytes IS NOT NULL, \
                EXISTS(SELECT 1 FROM chat.message_sends s \
                        WHERE s.conversation_id = e.conversation_id \
                          AND s.accepted_entry_seq = e.seq \
                          AND s.signed_request_bytes IS NOT NULL), \
                e.sequencer_receipt_bytes IS NOT NULL \
           FROM chat.entries e WHERE e.conversation_id = $1 AND e.seq = $2",
    )
    .bind(conversation_id)
    .bind(seq)
    .fetch_one(pool)
    .await
    .unwrap()
}

async fn now(pool: &sqlx::PgPool) -> DateTime<Utc> {
    sqlx::query_scalar("SELECT date_trunc('milliseconds', clock_timestamp())")
        .fetch_one(pool)
        .await
        .unwrap()
}

/// `reader`'s authenticated GET of `nsid` for conversation `cid`.
async fn read(s: &Sequencer, reader: &http::Device, nsid: &str, cid: Uuid) -> (StatusCode, Value) {
    http::cache_device_did(reader).await;
    let mut query = format!("actorDeviceId={}&conversationId={cid}", reader.device_id);
    if nsid == "blue.catbird.chat.getEntries" {
        query.push_str("&afterSeq=0&limit=50");
    }
    http::send(
        s.router.clone(),
        http::unsigned_get_request(reader, nsid, &query),
    )
    .await
}

/// A fresh chat device of `did`: enrolled, but in no MLS group and entitled to no entry.
async fn fresh_device(pool: &sqlx::PgPool, did: &str) -> http::Device {
    let fresh = device(did, Uuid::new_v4()).await;
    let key = [
        Uuid::new_v4().as_bytes().to_vec(),
        Uuid::new_v4().as_bytes().to_vec(),
    ]
    .concat();
    let key_id: String = sqlx::query_scalar("SELECT chat.ed25519_key_id($1)")
        .bind(&key)
        .fetch_one(pool)
        .await
        .unwrap();
    sqlx::query(
        "INSERT INTO chat.devices(user_did,device_id,device_name,status,dpop_jkt,auth_generation, \
             capabilities,created_at,updated_at) \
         VALUES($1,$2,'fresh-recovery','active',$3,1,chat.protocol_capabilities(), \
             clock_timestamp(),clock_timestamp())",
    )
    .bind(did)
    .bind(fresh.device_id)
    .bind(&fresh.jkt)
    .execute(pool)
    .await
    .unwrap();
    sqlx::query(
        "INSERT INTO chat.device_keys(user_did,device_id,key_id,signing_public_key, \
             enrollment_auth_generation,created_at) \
         VALUES($1,$2,$3,$4,1,clock_timestamp())",
    )
    .bind(did)
    .bind(fresh.device_id)
    .bind(&key_id)
    .bind(&key)
    .execute(pool)
    .await
    .unwrap();
    fresh
}

/// The `getConversationState` ref form of a `getEntries` union entry: no `$type`.
fn evidence(entry: &Value) -> Value {
    let mut evidence = entry.clone();
    evidence.as_object_mut().unwrap().remove("$type");
    evidence
}

/// The `accountDeletions` every reader of `cid` gets, asserting each is a member's.
async fn account_deletions(s: &Sequencer, readers: &[&http::Device], cid: Uuid) -> Value {
    let mut served = Vec::new();
    for reader in readers {
        let (status, state) = read(s, reader, "blue.catbird.chat.getConversationState", cid).await;
        assert_eq!(status, StatusCode::OK, "{state}");
        served.push(state["accountDeletions"].clone());
    }
    assert!(
        served.windows(2).all(|pair| pair[0] == pair[1]),
        "{served:?}"
    );
    served.remove(0)
}

#[tokio::test]
async fn deleting_an_account_prunes_only_its_application_ciphertext() {
    let _env = ENV_LOCK.lock().await;
    let s = sequencer().await;
    let deleted = seed_clean_slate_application_fixture(&s.pool, false, SELF_DID, Some([0x41; 32]))
        .await
        .unwrap();
    let kept = seed_clean_slate_application_fixture(&s.pool, false, SELF_DID, Some([0x42; 32]))
        .await
        .unwrap();
    let deleted_seq = send(&s, &deleted).await;
    let kept_seq = send(&s, &kept).await;
    assert_eq!(
        held(&s.pool, deleted.conversation_id, deleted_seq).await,
        HELD
    );

    let at = now(&s.pool).await;
    let sequenced =
        delete_account_data_with_conversations(&s.pool, &deleted.sender_did, at, Some(&s.signer))
            .await
            .unwrap();
    assert_eq!(sequenced, 1);
    assert_eq!(
        held(&s.pool, deleted.conversation_id, deleted_seq).await,
        pruned(at)
    );
    assert_eq!(held(&s.pool, kept.conversation_id, kept_seq).await, HELD);

    // The member that never fetched the message gets its skeleton, then the deletion.
    let recipient = device(&deleted.recipient_did, deleted.recipient_device_id).await;
    let (status, page) = http::send(
        s.router.clone(),
        http::unsigned_get_request(
            &recipient,
            "blue.catbird.chat.getEntries",
            &format!(
                "actorDeviceId={}&conversationId={}&afterSeq=0&limit=50",
                deleted.recipient_device_id, deleted.conversation_id
            ),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "getEntries: {page}");
    let entries = page["entries"].as_array().expect("entries");
    let message = entries
        .iter()
        .find(|entry| entry["seq"] == deleted_seq)
        .expect("the pruned message keeps its seq");
    assert_eq!(message["payloadPruned"], true);
    assert!(message.get("signedRequest").is_none(), "{message}");
    assert_eq!(message["sequencerReceipt"]["sequencerDid"], SELF_DID);
    assert!(entries.iter().any(|entry| {
        entry["$type"] == "blue.catbird.chat.defs#accountDeletedEntry"
            && entry["deletedDid"] == deleted.sender_did.as_str()
    }));

    // A retry prunes nothing more and keeps the first prune's evidence.
    delete_account_data_with_conversations(
        &s.pool,
        &deleted.sender_did,
        now(&s.pool).await,
        Some(&s.signer),
    )
    .await
    .unwrap();
    assert_eq!(
        held(&s.pool, deleted.conversation_id, deleted_seq).await,
        pruned(at)
    );
    assert_eq!(held(&s.pool, kept.conversation_id, kept_seq).await, HELD);
}

#[cfg(feature = "sim")]
#[tokio::test]
async fn a_federated_audience_is_told_of_the_prune_and_nothing_is_pruned_without_a_signer() {
    use catbird_server::sim_hooks::{scope_sim_ds, SimDsHooks, SimHttpRequest};
    use p256::pkcs8::{EncodePrivateKey as _, LineEnding};
    use std::{future::Future, pin::Pin, sync::Arc};

    const HOME: &str = "did:web:deletion-home.example.com";

    type Reply = Pin<Box<dyn Future<Output = Result<::http::Response<Vec<u8>>, String>> + Send>>;
    fn offline(_: SimHttpRequest) -> Reply {
        Box::pin(async { Err("offline".to_owned()) })
    }
    fn hooks(signing_key_pem: Option<String>) -> Arc<SimDsHooks> {
        Arc::new(SimDsHooks {
            service_did: SELF_DID.to_owned(),
            self_endpoint: SELF_ENDPOINT.to_owned(),
            signing_key_pem,
            group_relay_hmac_secret: None,
            http_transport: Arc::new(offline),
            dns_resolver: Arc::new(|_: &str| -> Result<Vec<std::net::IpAddr>, String> {
                Err("offline".to_owned())
            }),
            retain_application_ciphertext: false,
        })
    }
    async fn notices(pool: &sqlx::PgPool, conversation_id: Uuid) -> Vec<(String, String, Vec<u8>)> {
        sqlx::query_as(
            "SELECT id, target_ds_did, payload FROM outbound_queue \
              WHERE convo_id = $1 AND starts_with(id, 'entries-pruned-') ORDER BY id",
        )
        .bind(conversation_id.to_string())
        .fetch_all(pool)
        .await
        .unwrap()
    }

    let _env = ENV_LOCK.lock().await;
    let s = sequencer().await;
    // The recipient is homed at HOME, so the message was fanned out to HOME.
    let fixture = seed_clean_slate_application_fixture(&s.pool, false, HOME, Some([0x43; 32]))
        .await
        .unwrap();
    let seq = send(&s, &fixture).await;
    let cid = fixture.conversation_id;
    let delete = |signing_key_pem: Option<String>, at: DateTime<Utc>| {
        scope_sim_ds(
            hooks(signing_key_pem),
            delete_account_data_with_conversations(
                &s.pool,
                &fixture.sender_did,
                at,
                Some(&s.signer),
            ),
        )
    };

    // Without its S2S signer the sequencer prunes nothing it would have to tell HOME.
    std::env::remove_var("SIGNING_KEY_PEM");
    delete(None, now(&s.pool).await).await.unwrap();
    assert_eq!(held(&s.pool, cid, seq).await, HELD);
    assert!(notices(&s.pool, cid).await.is_empty());
    // HOME is still queued the deletion entry itself, in seq order after the message.
    let fanned_out: Vec<Vec<u8>> = sqlx::query_scalar(
        "SELECT payload FROM outbound_queue \
          WHERE convo_id = $1 AND target_ds_did = $2 \
            AND method = 'blue.catbird.mlsDS.deliverGroupEntry'",
    )
    .bind(cid.to_string())
    .bind(HOME)
    .fetch_all(&s.pool)
    .await
    .unwrap();
    let deletions: Vec<serde_json::Value> = fanned_out
        .iter()
        .map(|payload| {
            serde_json::from_slice::<serde_json::Value>(payload).unwrap()["entry"].clone()
        })
        .filter(|entry| entry["$type"] == "blue.catbird.chat.defs#accountDeletedEntry")
        .collect();
    assert_eq!(deletions.len(), 1, "HOME is queued the accountDeletedEntry");
    assert_eq!(deletions[0]["deletedDid"], fixture.sender_did.as_str());
    assert!(deletions[0]["seq"].as_i64() > Some(seq));

    // With it, the prune and HOME's signed notice commit together.
    let pem = http::random_p256()
        .to_pkcs8_pem(LineEnding::LF)
        .unwrap()
        .to_string();
    let at = now(&s.pool).await;
    delete(Some(pem.clone()), at).await.unwrap();
    assert_eq!(held(&s.pool, cid, seq).await, pruned(at));
    let queued = notices(&s.pool, cid).await;
    assert_eq!(queued.len(), 1, "one notice for HOME");
    let (id, target, payload) = &queued[0];
    assert_eq!(id, &format!("entries-pruned-{cid}-{seq:020}-{HOME}"));
    assert_eq!(target, HOME);
    let notice: serde_json::Value = serde_json::from_slice(payload).unwrap();
    assert_eq!(
        (&notice["sequencerDid"], &notice["homeDid"], &notice["seqs"]),
        (&json!(SELF_DID), &json!(HOME), &json!([seq]))
    );

    // A retry prunes and notifies nothing more.
    delete(Some(pem), now(&s.pool).await).await.unwrap();
    assert_eq!(held(&s.pool, cid, seq).await, pruned(at));
    assert_eq!(notices(&s.pool, cid).await.len(), 1);
}

#[tokio::test]
async fn an_account_deletion_is_signed_evidence_every_member_device_reads_and_no_one_else() {
    let _env = ENV_LOCK.lock().await;
    let s = sequencer().await;
    let fixture = seed_clean_slate_application_fixture(&s.pool, false, SELF_DID, Some([0x44; 32]))
        .await
        .unwrap();
    let cid = fixture.conversation_id;
    let deleted = fixture.sender_did.as_str();
    let deletion_rows = || async {
        sqlx::query_scalar::<_, i64>(
            "SELECT count(*) FROM chat.entries WHERE conversation_id = $1 AND entry_kind = $2",
        )
        .bind(cid)
        .bind(ACCOUNT_DELETED)
        .fetch_one(&s.pool)
        .await
        .unwrap()
    };

    // Without its #mls-receipt-1 signer the sequencer refuses the deletion whole.
    let refused =
        delete_account_data_with_conversations(&s.pool, deleted, now(&s.pool).await, None)
            .await
            .expect_err("an unsigned accountDeletedEntry is never sequenced");
    assert_eq!(
        (refused.status(), refused.name()),
        (StatusCode::SERVICE_UNAVAILABLE, "SignerUnavailable")
    );
    assert_eq!(deletion_rows().await, 0);

    let at = now(&s.pool).await;
    assert_eq!(
        delete_account_data_with_conversations(&s.pool, deleted, at, Some(&s.signer))
            .await
            .unwrap(),
        1
    );

    // The member's leaf device reads the signed entry in getEntries.
    let member = device(&fixture.recipient_did, fixture.recipient_device_id).await;
    let (status, page) = read(&s, &member, "blue.catbird.chat.getEntries", cid).await;
    assert_eq!(status, StatusCode::OK, "{page}");
    let entry = page["entries"]
        .as_array()
        .unwrap()
        .iter()
        .find(|entry| entry["$type"] == ACCOUNT_DELETED)
        .cloned()
        .expect("the accountDeletedEntry");
    let (deletion, authority) = AccountDeletion::from_entry(&entry).expect("the exact entry");
    authority
        .verify(&s.signer.verifying_key(), &deletion)
        .expect("signed by the sequencer's #mls-receipt-1 key");
    assert_eq!(
        (
            deletion.sequencer_did.as_str(),
            deletion.conversation_id,
            deletion.deleted_did.as_str(),
            deletion.deleted_at,
        ),
        (SELF_DID, cid, deleted, at)
    );
    assert_eq!(authority.key_id, format!("{SELF_DID}#mls-receipt-1"));

    // The same evidence reaches the leaf device and a fresh device of the member
    // DID through getConversationState, though the fresh device reads no entry.
    let fresh = fresh_device(&s.pool, &fixture.recipient_did).await;
    assert_eq!(
        account_deletions(&s, &[&member, &fresh], cid).await,
        json!([evidence(&entry)])
    );
    let (status, page) = read(&s, &fresh, "blue.catbird.chat.getEntries", cid).await;
    assert_ne!(status, StatusCode::OK, "{page}");

    // A DID that is no member of the conversation reads nothing.
    let stranger = http::seed_device(&s.pool).await;
    let (status, body) = read(&s, &stranger, "blue.catbird.chat.getConversationState", cid).await;
    assert_ne!(status, StatusCode::OK, "{body}");
    assert!(body.get("accountDeletions").is_none(), "{body}");
}

#[tokio::test]
async fn a_group_mirror_serves_its_stored_deletion_evidence_to_every_member_device() {
    const SEQ: &str = "did:web:ds-deletion-sequencer.example.com";
    let _env = ENV_LOCK.lock().await;
    let s = sequencer().await;
    // This DS mirrors SEQ's group for its local member.
    let mirror = seed_remote_clean_slate_application_fixture(&s.pool, SELF_DID, SEQ, None)
        .await
        .unwrap();
    let cid = mirror.conversation_id;
    let member = device(&mirror.recipient_did, mirror.recipient_device_id).await;
    assert_eq!(account_deletions(&s, &[&member], cid).await, json!([]));

    // The entry SEQ signed, stored verbatim once deliverGroupEntry verified it.
    let signer = I13ReceiptSigner::new(http::random_p256(), SEQ.to_owned());
    let deletion = AccountDeletion {
        sequencer_did: SEQ.to_owned(),
        conversation_id: cid,
        deleted_did: mirror.sender_did.clone(),
        seq: 9,
        entry_id: Uuid::new_v4(),
        deleted_at: now(&s.pool).await,
        evidence: None,
    };
    let entry = deletion.entry(&signer.sign_account_deletion(&deletion).unwrap());
    catbird_server::chat_protocol::repository::delivery::insert_transport_entry(
        &mut s.pool.acquire().await.unwrap(),
        cid,
        deletion.seq,
        deletion.entry_id,
        &serde_json::to_vec(&entry).unwrap(),
        Utc::now(),
    )
    .await
    .unwrap();

    let fresh = fresh_device(&s.pool, &mirror.recipient_did).await;
    let served = account_deletions(&s, &[&member, &fresh], cid).await;
    assert_eq!(served, json!([evidence(&entry)]));
    let mut union_entry = served[0].clone();
    union_entry["$type"] = json!(ACCOUNT_DELETED);
    let (verified, authority) = AccountDeletion::from_entry(&union_entry).unwrap();
    authority
        .verify(&signer.verifying_key(), &verified)
        .expect("served exactly as signed");
    assert_eq!(verified, deletion);
}

const DELETE_ACCOUNT_DATA: &str = "blue.catbird.labyrinth.deleteAccountData";

/// A service-auth token `device`'s DID signs for `nsid`, issued at `iat` and
/// valid for `lifetime` seconds.
fn service_token(device: &http::Device, nsid: &str, iat: i64, lifetime: i64) -> String {
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
    use p256::ecdsa::{signature::Signer as _, Signature};
    let encode = |value: Value| URL_SAFE_NO_PAD.encode(serde_json::to_vec(&value).unwrap());
    let input = format!(
        "{}.{}",
        encode(json!({"alg": "ES256", "typ": "JWT", "kid": format!("{}#atproto", device.did)})),
        encode(json!({
            "iss": device.did,
            "aud": catbird_server::auth::expected_mls_service_ref(),
            "lxm": nsid,
            "iat": iat,
            "exp": iat + lifetime,
            "jti": Uuid::new_v4().to_string(),
        })),
    );
    let signature: Signature = device.signing.sign(input.as_bytes());
    format!("{input}.{}", URL_SAFE_NO_PAD.encode(signature.to_bytes()))
}

/// One signed `deleteAccountData`: the device's `labyrinthWriteBody` and signature,
/// and an optional base64url key proof. Each request carries a fresh service-auth token.
struct SignedDeletion {
    write_body: Vec<u8>,
    signature: Vec<u8>,
    key_proof: Option<String>,
}

impl SignedDeletion {
    fn new(
        device: &http::Device,
        chat_key: &ed25519_dalek::SigningKey,
        operation_id: [u8; 16],
        key_proof: Option<String>,
    ) -> Self {
        use ed25519_dalek::Signer as _;
        use sha2::{Digest as _, Sha256};
        let write_body = serde_json::to_vec(&json!({
            "operationId": hex::encode(operation_id),
            "actorDeviceId": device.device_id.to_string(),
            "endpointNsid": DELETE_ACCOUNT_DATA,
            "payloadSha256": hex::encode(Sha256::digest(b"{}")),
            "signedAt": Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
        }))
        .unwrap();
        let signature = chat_key
            .sign(&[b"CATBIRD-LABYRINTH-WRITE\0".as_slice(), &write_body].concat())
            .to_bytes()
            .to_vec();
        Self {
            write_body,
            signature,
            key_proof,
        }
    }

    fn request(&self, device: &http::Device) -> axum::http::Request<axum::body::Body> {
        self.request_with(&service_token(
            device,
            DELETE_ACCOUNT_DATA,
            Utc::now().timestamp(),
            60,
        ))
    }

    fn request_with(&self, token: &str) -> axum::http::Request<axum::body::Body> {
        use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
        let mut request = axum::http::Request::post(format!("/xrpc/{DELETE_ACCOUNT_DATA}"))
            .header("content-type", "application/json")
            .header("authorization", format!("Bearer {token}"))
            .header(
                "catbird-labyrinth-write",
                URL_SAFE_NO_PAD.encode(&self.write_body),
            )
            .header(
                "catbird-labyrinth-write-signature",
                URL_SAFE_NO_PAD.encode(&self.signature),
            );
        if let Some(key_proof) = &self.key_proof {
            request = request.header("catbird-labyrinth-key-proof", key_proof);
        }
        request.body(axum::body::Body::from("{}")).unwrap()
    }
}

/// The real Labyrinth router over `s`'s database, with the sequencer's receipt signer.
async fn labyrinth(s: &Sequencer) -> Router {
    let (_, runtime) = http::router_and_runtime_for_authenticated_acceptance(s.pool.clone()).await;
    catbird_server::handlers::labyrinth::labyrinth_router::<http::TestState>().with_state(
        http::TestState {
            pool: s.pool.clone(),
            runtime,
        },
    )
}

/// The `accountDeletedEntry` rows of `cid`.
async fn deletion_rows(pool: &sqlx::PgPool, cid: Uuid) -> i64 {
    sqlx::query_scalar(
        "SELECT count(*) FROM chat.entries WHERE conversation_id = $1 AND entry_kind = $2",
    )
    .bind(cid)
    .bind(ACCOUNT_DELETED)
    .fetch_one(pool)
    .await
    .unwrap()
}

#[tokio::test]
async fn a_signed_deletion_carries_the_devices_exact_write_and_key_proof_and_replays_once() {
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
    let _env = ENV_LOCK.lock().await;
    let s = sequencer().await;
    let fixture = seed_clean_slate_application_fixture(&s.pool, false, SELF_DID, Some([0x45; 32]))
        .await
        .unwrap();
    let cid = fixture.conversation_id;
    let lab = labyrinth(&s).await;
    let sender = device(&fixture.sender_did, fixture.sender_device_id).await;
    let chat_key = ed25519_dalek::SigningKey::from_bytes(&fixture.sender_ed25519_seed);
    let key_proof = vec![0x9A_u8; 2500];

    // A key proof that is not base64url, or longer than the lexicon admits, is
    // refused before anything is sequenced.
    for bad in [
        "not base64url!".to_owned(),
        URL_SAFE_NO_PAD.encode(vec![0_u8; 16_385]),
    ] {
        let refused = SignedDeletion::new(&sender, &chat_key, [0xB0; 16], Some(bad));
        let (status, body) = http::send(lab.clone(), refused.request(&sender)).await;
        assert_eq!(
            (status, body["error"].as_str()),
            (StatusCode::BAD_REQUEST, Some("InvalidRequest")),
            "{body}"
        );
        assert_eq!(deletion_rows(&s.pool, cid).await, 0);
    }

    let signed = SignedDeletion::new(
        &sender,
        &chat_key,
        [0xDA; 16],
        Some(URL_SAFE_NO_PAD.encode(&key_proof)),
    );
    let (status, body) = http::send(lab.clone(), signed.request(&sender)).await;
    assert_eq!((status, &body), (StatusCode::OK, &json!({})));
    assert_eq!(deletion_rows(&s.pool, cid).await, 1);

    // Every member read serves the exact bytes the device signed and sent.
    let member = device(&fixture.recipient_did, fixture.recipient_device_id).await;
    let (status, page) = read(&s, &member, "blue.catbird.chat.getEntries", cid).await;
    assert_eq!(status, StatusCode::OK, "{page}");
    let entry = page["entries"]
        .as_array()
        .unwrap()
        .iter()
        .find(|entry| entry["$type"] == ACCOUNT_DELETED)
        .cloned()
        .expect("the accountDeletedEntry");
    let (deletion, authority) = AccountDeletion::from_entry(&entry).expect("the exact entry");
    authority
        .verify(&s.signer.verifying_key(), &deletion)
        .expect("signed by the sequencer's #mls-receipt-1 key");
    let carried = deletion.evidence.expect("the device's evidence");
    assert_eq!(carried.actor_write.write_body, signed.write_body);
    assert_eq!(carried.actor_write.signature, signed.signature);
    assert_eq!(carried.key_proof, Some(key_proof));
    assert_eq!(
        account_deletions(&s, &[&member], cid).await,
        json!([evidence(&entry)])
    );

    // The identical request replays its recorded answer and sequences nothing more.
    let (status, body) = http::send(lab.clone(), signed.request(&sender)).await;
    assert_eq!((status, &body), (StatusCode::OK, &json!({})));
    assert_eq!(deletion_rows(&s.pool, cid).await, 1);
    let (_, again) = read(&s, &member, "blue.catbird.chat.getEntries", cid).await;
    assert_eq!(
        again["entries"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|entry| entry["$type"] == ACCOUNT_DELETED)
            .collect::<Vec<_>>(),
        [&entry]
    );
}
