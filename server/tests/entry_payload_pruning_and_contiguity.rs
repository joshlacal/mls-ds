//! Clean-slate Task 2 integration suite:
//! - Dynamic `SERVICE_DID` DID document generation (`did:web` + `did:plc`) and `I13` sequencer
//!   receipts (`{SERVICE_DID}#mls-receipt-1`, `CATBIRD-MLS-RECEIPT-V1:`);
//! - `blue.catbird.chat.acknowledgeEntries` (`CATBIRD-CHAT-ACK-ENTRIES\0`), active/dormant/revoked
//!   device ACK accounting, `chat.entries` + `chat.message_sends` ciphertext pruning with strict
//!   `seq` contiguity, and `payloadPruned: true` + `sequencerReceipt` preservation on `getEntries`;
//! - 60-day `mark_inactive_devices` dormancy sweep and 30-day hard ceiling payload pruning sweep;
//! - `blue.catbird.labyrinth.deleteAccountData` sequencing `accountDeletedEntry` across active
//!   conversations while preserving sibling non-deleted leaves' recovery eligibility.

mod common;

use axum::{body::Body, http::Request, http::StatusCode, Router};
use base64::{
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
    Engine as _,
};
use catbird_server::{
    chat_protocol::{
        repository::expiry_sweep::{mark_inactive_devices, prune_expired_application_payloads},
        test_support::seed_clean_slate_application_fixture,
    },
    federation::receipt::{
        configured_receipt_signer, validate_receipt_did_document_method_for_service,
        I13ReceiptSigner,
    },
    identity::did_doc::{build_service_did_document, did_web_document_path},
};
use chrono::{Duration, SecondsFormat, Utc};
use common::http_acceptance as http;
use ed25519_dalek::{Signer as _, SigningKey as EdSigningKey};
use labyrinth_protocol::receipt::{verify_sequencer_receipt, SequencerReceiptPayload};
use p256::{ecdsa::SigningKey as P256SigningKey, pkcs8::EncodePrivateKey, SecretKey as P256Secret};
use rand::rngs::OsRng;
use serde_json::{json, Value};
use sha2::{Digest as _, Sha256};
use uuid::Uuid;

fn p256_pem(sk: &P256SigningKey) -> String {
    let secret = P256Secret::from_slice(&sk.to_bytes()).expect("p256 secret");
    secret
        .to_pkcs8_pem(p256::pkcs8::LineEnding::LF)
        .expect("pkcs8 pem")
        .to_string()
}

fn sign_ack_entries_request(
    actor_device_id: Uuid,
    key_id: &str,
    auth_generation: i64,
    signing_key: &EdSigningKey,
    conversation_id: Uuid,
    generation: i64,
    up_to_seq: i64,
) -> Value {
    #[derive(serde::Serialize)]
    struct AckTranscriptPayload<'a> {
        #[serde(rename = "keyId")]
        key_id: &'a str,
        #[serde(rename = "upToSeq")]
        up_to_seq: i64,
        #[serde(rename = "signedAt")]
        signed_at: &'a str,
        generation: i64,
        #[serde(rename = "actorDeviceId")]
        actor_device_id: String,
        #[serde(rename = "authGeneration")]
        auth_generation: i64,
        #[serde(rename = "conversationId")]
        conversation_id: String,
    }
    let signed_at = Utc::now().to_rfc3339_opts(SecondsFormat::Millis, true);
    let payload = AckTranscriptPayload {
        key_id,
        up_to_seq,
        signed_at: &signed_at,
        generation,
        actor_device_id: actor_device_id.to_string(),
        auth_generation,
        conversation_id: conversation_id.to_string(),
    };
    let cbor = serde_ipld_dagcbor::to_vec(&payload).expect("cbor");
    let mut transcript = b"CATBIRD-CHAT-ACK-ENTRIES\0".to_vec();
    transcript.extend_from_slice(&cbor);
    let sig = signing_key.sign(&transcript);
    json!({
        "conversationId": conversation_id,
        "generation": generation,
        "actorDeviceId": actor_device_id,
        "keyId": key_id,
        "authGeneration": auth_generation,
        "upToSeq": up_to_seq,
        "signedAt": signed_at,
        "signature": { "$bytes": STANDARD.encode(sig.to_bytes()) }
    })
}

#[test]
fn dynamic_service_did_doc_and_i13_receipt_signer_support_self_hosted_web_and_plc_dids() {
    let service_auth_key = P256SigningKey::random(&mut OsRng);
    let receipt_key = P256SigningKey::random(&mut OsRng);

    for (service_did, endpoint, expected_web_path) in [
        (
            "did:web:ds2.selfhost.example",
            "https://ds2.selfhost.example",
            Some("/.well-known/did.json".to_string()),
        ),
        (
            "did:web:selfhost.example:chat:ds1",
            "https://selfhost.example/chat/ds1",
            Some("/chat/ds1/did.json".to_string()),
        ),
        (
            "did:plc:z72i7hdynmk6r22z27h6tvur",
            "https://plc-ds.selfhost.example",
            None,
        ),
    ] {
        assert_eq!(did_web_document_path(service_did), expected_web_path);
        let doc = build_service_did_document(
            service_did,
            endpoint,
            service_auth_key.verifying_key(),
            Some(receipt_key.verifying_key()),
        );
        let methods = doc["verificationMethod"]
            .as_array()
            .expect("verification methods");
        let method = |suffix: &str| {
            methods
                .iter()
                .find(|method| method["id"] == format!("{service_did}{suffix}"))
                .unwrap_or_else(|| panic!("missing {suffix} verification method"))
        };
        assert_eq!(
            method("#atproto_kem")["publicKeyMultibase"],
            method("#atproto")["publicKeyMultibase"],
            "the advertised KEM key must match SpaceHostConfig"
        );
        let doc_str = serde_json::to_string(&doc).expect("did doc json");
        let vm = format!("{service_did}#mls-receipt-1");
        validate_receipt_did_document_method_for_service(
            &doc_str,
            service_did,
            &vm,
            receipt_key.verifying_key(),
            Some(service_auth_key.verifying_key()),
        )
        .expect("dynamic DID doc validates receipt method");

        let signer = configured_receipt_signer(
            Some("issue"),
            Some(&p256_pem(&receipt_key)),
            Some(&vm),
            Some(&p256_pem(&service_auth_key)),
            service_did,
            Some(&doc_str),
        )
        .expect("configured_receipt_signer accepts dynamic SERVICE_DID")
        .expect("issue mode yields signer");
        assert_eq!(signer.verifying_key(), *receipt_key.verifying_key());

        let i13 = I13ReceiptSigner::new(receipt_key.clone(), service_did.to_string());
        let convo_id = Uuid::new_v4();
        let entry_id = Uuid::new_v4();
        let group_id = vec![0x33_u8; 32];
        let commitment = [0x5A_u8; 32];
        let sender_did = "did:plc:senderuseraaaaaaaaaaaaaa";
        let sender_device_id = Uuid::new_v4();
        let signed = i13
            .sign_application_receipt(
                &convo_id.to_string(),
                &group_id,
                3,
                sender_did,
                &sender_device_id.to_string(),
                &entry_id.to_string(),
                &commitment,
                7,
                1_793_000_000_000,
            )
            .expect("sign_application_receipt");
        assert_eq!(signed.payload.sequencer_did, service_did);
        assert_eq!(signed.key_id, format!("{service_did}#mls-receipt-1"));
        verify_sequencer_receipt(receipt_key.verifying_key(), service_did, &signed)
            .expect("labyrinth_protocol verifies dynamic SERVICE_DID I13 receipt");
    }
}

static ENV_LOCK: std::sync::LazyLock<tokio::sync::Mutex<()>> =
    std::sync::LazyLock::new(|| tokio::sync::Mutex::new(()));

#[tokio::test]
async fn i13_receipt_survives_all_device_ack_payload_pruning_and_preserves_seq_contiguity() {
    let _env_guard = ENV_LOCK.lock().await;
    let self_did = "did:web:ds-pruning.selfhost.example.com";
    std::env::set_var("SERVICE_DID", self_did);
    std::env::set_var("SELF_ENDPOINT", "https://ds-pruning.selfhost.example.com");

    let db = common::fresh_db::fresh_fully_migrated_db("chat_pruning_").await;
    let pool = db.connect(6).await;
    http::ensure_fence(&pool).await;

    let commitment = [0x42_u8; 32];
    let fixture = seed_clean_slate_application_fixture(&pool, false, self_did, Some(commitment))
        .await
        .expect("clean-slate application fixture");

    let receipt_verifying_key = common::proof_i13_signer().verifying_key();

    let sender_p256 = http::random_p256();
    let sender_jwk = http::public_jwk(&sender_p256);
    let sender_dev = http::Device {
        did: fixture.sender_did.clone(),
        device_id: fixture.sender_device_id,
        jkt: http::jwk_thumbprint(&sender_jwk),
        signing: sender_p256,
        jwk: sender_jwk,
    };
    http::cache_device_did(&sender_dev).await;

    let recipient_p256 = http::random_p256();
    let recipient_jwk = http::public_jwk(&recipient_p256);
    let recipient_dev = http::Device {
        did: fixture.recipient_did.clone(),
        device_id: fixture.recipient_device_id,
        jkt: http::jwk_thumbprint(&recipient_jwk),
        signing: recipient_p256,
        jwk: recipient_jwk,
    };
    http::cache_device_did(&recipient_dev).await;

    let router: Router = http::router_for_authenticated_acceptance(pool.clone()).await;

    // 1. Send application message carrying archiveCommitment -> receives I13 sequencerReceipt
    let (send_status, send_body) = http::send(
        router.clone(),
        http::unsigned_json_request(
            &sender_dev,
            "blue.catbird.chat.sendMessage",
            serde_json::to_vec(&json!({ "signedRequest": fixture.signed_request })).unwrap(),
        ),
    )
    .await;
    assert_eq!(
        send_status,
        StatusCode::OK,
        "sendMessage failed: {send_body}"
    );
    let app_seq = send_body["entry"]["seq"].as_i64().expect("entry seq");
    let entry_id_str = send_body["entry"]["entryId"].as_str().expect("entryId");
    let receipt_json = send_body
        .get("sequencerReceipt")
        .or_else(|| send_body["entry"].get("sequencerReceipt"))
        .expect("sendMessage must return I13 sequencerReceipt");
    assert_eq!(receipt_json["sequencerDid"], self_did);
    assert_eq!(receipt_json["seq"], app_seq);
    assert_eq!(receipt_json["kid"], format!("{self_did}#mls-receipt-1"));
    let sig_b64 = receipt_json["signature"]["$bytes"]
        .as_str()
        .expect("sig $bytes");
    let sig_raw: [u8; 64] = STANDARD.decode(sig_b64).unwrap().try_into().unwrap();
    let group_id_b64 = receipt_json["groupId"]["$bytes"]
        .as_str()
        .expect("groupId $bytes");
    let group_id_raw = STANDARD.decode(group_id_b64).unwrap();
    let issued_at_ms = receipt_json["issuedAtMs"].as_i64().expect("issuedAtMs");
    let epoch = fixture.signed_request["body"]["prior"]["epoch"]
        .as_u64()
        .unwrap();
    let reconstructed = labyrinth_protocol::receipt::SignedSequencerReceipt {
        payload: SequencerReceiptPayload {
            sequencer_did: self_did.to_string(),
            conversation_id: fixture.conversation_id.to_string(),
            group_id: group_id_raw,
            epoch,
            sender_device_did_url: format!("{}#{}", fixture.sender_did, fixture.sender_device_id),
            entry_id: entry_id_str.to_string(),
            archive_commitment: commitment,
            seq: app_seq as u64,
            issued_at_ms,
        },
        key_id: format!("{self_did}#mls-receipt-1"),
        signature: sig_raw,
    };
    verify_sequencer_receipt(&receipt_verifying_key, self_did, &reconstructed)
        .expect("I13 sequencerReceipt verifies cryptographically");

    // 2. Partial ACK (sender only) does NOT prune ciphertext while recipient is active & non-dormant
    let sender_ed = EdSigningKey::from_bytes(&fixture.sender_ed25519_seed);
    let ack1 = sign_ack_entries_request(
        fixture.sender_device_id,
        &fixture.sender_key_id,
        1,
        &sender_ed,
        fixture.conversation_id,
        0,
        app_seq,
    );
    let (ack1_status, ack1_body) = http::send(
        router.clone(),
        http::unsigned_json_request(
            &sender_dev,
            "blue.catbird.chat.acknowledgeEntries",
            serde_json::to_vec(&ack1).unwrap(),
        ),
    )
    .await;
    assert_eq!(
        ack1_status,
        StatusCode::OK,
        "sender ack failed: {ack1_body}"
    );
    assert_eq!(ack1_body["acknowledgedSeq"], app_seq);
    assert_eq!(ack1_body["prunedCount"], 0);

    let (pruned_after_one,): (bool,) = sqlx::query_as(
        "SELECT payload_pruned_at IS NOT NULL FROM chat.entries WHERE conversation_id = $1 AND seq = $2",
    )
    .bind(fixture.conversation_id)
    .bind(app_seq)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert!(
        !pruned_after_one,
        "must not prune before all active devices ack"
    );

    // 3. Recipient ACKs -> all active devices have acked -> payload_pruned_at set, bytes NULL
    let recipient_ed = EdSigningKey::from_bytes(&fixture.recipient_ed25519_seed);
    let ack2 = sign_ack_entries_request(
        fixture.recipient_device_id,
        &fixture.recipient_key_id,
        1,
        &recipient_ed,
        fixture.conversation_id,
        0,
        app_seq,
    );
    let (ack2_status, ack2_body) = http::send(
        router.clone(),
        http::unsigned_json_request(
            &recipient_dev,
            "blue.catbird.chat.acknowledgeEntries",
            serde_json::to_vec(&ack2).unwrap(),
        ),
    )
    .await;
    assert_eq!(
        ack2_status,
        StatusCode::OK,
        "recipient ack failed: {ack2_body}"
    );
    assert_eq!(ack2_body["acknowledgedSeq"], app_seq);
    assert_eq!(ack2_body["prunedCount"], 1);

    let row: (Option<Vec<u8>>, Option<Vec<u8>>, bool) = sqlx::query_as(
        "SELECT accepted_payload_bytes, signed_request_bytes, payload_pruned_at IS NOT NULL \
         FROM chat.entries WHERE conversation_id = $1 AND seq = $2",
    )
    .bind(fixture.conversation_id)
    .bind(app_seq)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert!(
        row.0.is_none(),
        "accepted_payload_bytes must be NULL after pruning"
    );
    assert!(
        row.1.is_none(),
        "signed_request_bytes must be NULL after pruning"
    );
    assert!(row.2, "payload_pruned_at must be set");

    // 4. getEntries still returns contiguous seqs with payloadPruned: true + verifiable sequencerReceipt!
    let (entries_status, entries_body) = http::send(
        router.clone(),
        http::unsigned_get_request(
            &recipient_dev,
            "blue.catbird.chat.getEntries",
            &format!(
                "actorDeviceId={}&conversationId={}&afterSeq=0&limit=50",
                fixture.recipient_device_id, fixture.conversation_id
            ),
        ),
    )
    .await;
    assert_eq!(
        entries_status,
        StatusCode::OK,
        "getEntries after prune: {entries_body}"
    );
    let entries = entries_body["entries"].as_array().expect("entries array");
    let seqs: Vec<i64> = entries.iter().map(|e| e["seq"].as_i64().unwrap()).collect();
    for (idx, s) in seqs.iter().enumerate() {
        assert_eq!(
            *s,
            (idx + 1) as i64,
            "seq contiguity must hold after payload pruning"
        );
    }
    let pruned_entry = entries
        .iter()
        .find(|e| e["seq"].as_i64() == Some(app_seq))
        .expect("pruned applicationEntry present at original seq");
    assert_eq!(pruned_entry["payloadPruned"], true);
    assert!(pruned_entry.get("signedRequest").is_none());
    assert_eq!(pruned_entry["sequencerReceipt"]["sequencerDid"], self_did);
    assert_c33_transport_only_home_prunes_application(
        &pool,
        &fixture,
        &sender_dev,
        &send_body["entry"],
        receipt_json,
    )
    .await;
}

#[tokio::test]
async fn dormant_60d_devices_and_30d_ceiling_prune_without_stalling_active_conversations() {
    let _env_guard = ENV_LOCK.lock().await;
    std::env::set_var("SERVICE_DID", "did:web:chat.catbird.blue");
    std::env::set_var("SELF_ENDPOINT", "https://chat.catbird.blue");

    let db = common::fresh_db::fresh_fully_migrated_db("chat_dormant_").await;
    let pool = db.connect(4).await;
    http::ensure_fence(&pool).await;

    let fixture = seed_clean_slate_application_fixture(
        &pool,
        false,
        "did:web:chat.catbird.blue",
        Some([0x45; 32]),
    )
    .await
    .expect("fixture");

    let sender_p256 = http::random_p256();
    let sender_jwk = http::public_jwk(&sender_p256);
    let sender_dev = http::Device {
        did: fixture.sender_did.clone(),
        device_id: fixture.sender_device_id,
        jkt: http::jwk_thumbprint(&sender_jwk),
        signing: sender_p256,
        jwk: sender_jwk,
    };
    http::cache_device_did(&sender_dev).await;
    let router = http::router_for_authenticated_acceptance(pool.clone()).await;

    let (status, send_body) = http::send(
        router.clone(),
        http::unsigned_json_request(
            &sender_dev,
            "blue.catbird.chat.sendMessage",
            serde_json::to_vec(&json!({ "signedRequest": fixture.signed_request })).unwrap(),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let app_seq = send_body["entry"]["seq"].as_i64().unwrap();

    // Age recipient device past 60 days and run dormancy sweep
    sqlx::query("UPDATE chat.devices SET last_active_at = clock_timestamp() - INTERVAL '61 days' WHERE user_did = $1 AND device_id = $2")
        .bind(&fixture.recipient_did)
        .bind(fixture.recipient_device_id)
        .execute(&pool)
        .await
        .unwrap();
    let marked = mark_inactive_devices(&pool, Utc::now()).await.unwrap();
    assert_eq!(marked, 1, "61-day inactive device marked dormant");

    // B1(a–b): Without an attested Space archive watermark, sender ACK alone MUST NOT prune
    // when all recipient devices are dormant — ciphertext survives until Space archive or 30d ceiling!
    let sender_ed = EdSigningKey::from_bytes(&fixture.sender_ed25519_seed);
    let ack = sign_ack_entries_request(
        fixture.sender_device_id,
        &fixture.sender_key_id,
        1,
        &sender_ed,
        fixture.conversation_id,
        0,
        app_seq,
    );
    let (ack_status, _) = http::send(
        router.clone(),
        http::unsigned_json_request(
            &sender_dev,
            "blue.catbird.chat.acknowledgeEntries",
            serde_json::to_vec(&ack).unwrap(),
        ),
    )
    .await;
    assert_eq!(ack_status, StatusCode::OK);

    let is_pruned_before_archive: bool = sqlx::query_scalar(
        "SELECT payload_pruned_at IS NOT NULL FROM chat.entries WHERE conversation_id = $1 AND seq = $2",
    )
    .bind(fixture.conversation_id)
    .bind(app_seq)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert!(
        !is_pruned_before_archive,
        "B1: sender ACK alone must NOT prune un-archived conversation when all recipient devices are dormant"
    );

    // At 31 days (`> 720h` I14 ceiling), unacked applicationEntry row expires cleanly and idempotently:
    let pruned_30d = prune_expired_application_payloads(&pool, Utc::now() + Duration::days(31))
        .await
        .unwrap();
    assert_eq!(pruned_30d, 1, "30-day I14 ceiling prunes un-archived entry");
    let pruned_30d_repeat =
        prune_expired_application_payloads(&pool, Utc::now() + Duration::days(32))
            .await
            .unwrap();
    assert_eq!(pruned_30d_repeat, 0, "already pruned row is idempotent");
}

#[tokio::test]
async fn delete_account_data_sequences_account_deleted_entry_in_active_conversations() {
    let _env_guard = ENV_LOCK.lock().await;
    std::env::set_var("SERVICE_DID", "did:web:chat.catbird.blue");
    std::env::set_var("SELF_ENDPOINT", "https://chat.catbird.blue");

    let db = common::fresh_db::fresh_fully_migrated_db("chat_acct_del_").await;
    let pool = db.connect(4).await;
    http::ensure_fence(&pool).await;

    let fixture =
        seed_clean_slate_application_fixture(&pool, false, "did:web:chat.catbird.blue", None)
            .await
            .expect("fixture");

    let recipient_p256 = http::random_p256();
    let recipient_jwk = http::public_jwk(&recipient_p256);
    let recipient_dev = http::Device {
        did: fixture.recipient_did.clone(),
        device_id: fixture.recipient_device_id,
        jkt: http::jwk_thumbprint(&recipient_jwk),
        signing: recipient_p256,
        jwk: recipient_jwk,
    };
    http::cache_device_did(&recipient_dev).await;

    let sender_p256 = http::random_p256();
    let sender_jwk = http::public_jwk(&sender_p256);
    let sender_dev = http::Device {
        did: fixture.sender_did.clone(),
        device_id: fixture.sender_device_id,
        jkt: http::jwk_thumbprint(&sender_jwk),
        signing: sender_p256,
        jwk: sender_jwk,
    };
    http::cache_device_did(&sender_dev).await;

    // Invoke deleteAccountData for sender_did via labyrinth retention repo
    let deleted_seqs =
        catbird_server::labyrinth::repo::retention::delete_account_data_with_conversations(
            &pool,
            &fixture.sender_did,
            Utc::now(),
            Some(&I13ReceiptSigner::new(
                http::random_p256(),
                "did:web:chat.catbird.blue".to_owned(),
            )),
        )
        .await
        .expect("delete_account_data_with_conversations");
    assert_eq!(
        deleted_seqs, 1,
        "one active conversation must receive accountDeletedEntry"
    );

    let chat_router = http::router_for_authenticated_acceptance(pool.clone()).await;
    let (status, body) = http::send(
        chat_router,
        http::unsigned_get_request(
            &recipient_dev,
            "blue.catbird.chat.getEntries",
            &format!(
                "actorDeviceId={}&conversationId={}&afterSeq=0&limit=50",
                fixture.recipient_device_id, fixture.conversation_id
            ),
        ),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "recipient getEntries after peer deleteAccountData: {body}"
    );
    let entries = body["entries"].as_array().expect("entries");
    let acct_del = entries
        .iter()
        .find(|e| e["$type"] == "blue.catbird.chat.defs#accountDeletedEntry")
        .expect("accountDeletedEntry sequenced and visible to surviving participant");
    assert_eq!(acct_del["deletedDid"], fixture.sender_did);
    assert_eq!(acct_del["sequencerDid"], "did:web:chat.catbird.blue");

    // Surviving participant's device remains active and eligible in chat.devices
    let recipient_status: String = sqlx::query_scalar(
        "SELECT status FROM chat.devices WHERE user_did = $1 AND device_id = $2",
    )
    .bind(&fixture.recipient_did)
    .bind(fixture.recipient_device_id)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(recipient_status, "active");
    let _ = URL_SAFE_NO_PAD;
    let _ = Request::builder().body(Body::empty());
    let _ = Router::<()>::new;
}

async fn assert_c33_transport_only_home_prunes_application(
    source: &sqlx::PgPool,
    fixture: &catbird_server::chat_protocol::test_support::CleanSlateApplicationFixture,
    sender: &http::Device,
    accepted_entry: &Value,
    receipt: &Value,
) {
    let home_db = common::fresh_db::fresh_fully_migrated_db("chat_pruning_").await;
    let home = home_db.connect(4).await;
    http::ensure_fence(&home).await;
    // This is a storage/ACK regression, not an opening-acceptance fixture. Copy
    // the enrolled local sender; the other inbox device lives at another home.
    // The application and I13 evidence below are the real sendMessage outcome.
    for table in ["principals", "devices", "device_keys"] {
        let rows: Vec<sqlx::types::Json<Value>> = sqlx::query_scalar(&format!(
            "SELECT to_jsonb(source_row) FROM chat.{table} source_row WHERE user_did = $1"
        ))
        .bind(&fixture.sender_did)
        .fetch_all(source)
        .await
        .unwrap();
        for row in rows {
            sqlx::query(&format!(
                "INSERT INTO chat.{table} SELECT * FROM jsonb_populate_record(NULL::chat.{table}, $1)"
            ))
            .bind(row)
            .execute(&home)
            .await
            .unwrap();
        }
    }
    let control: Vec<u8> = sqlx::query_scalar(
        "SELECT accepted_payload_bytes FROM chat.entries WHERE conversation_id = $1 AND seq = 3",
    )
    .bind(fixture.conversation_id)
    .fetch_one(source)
    .await
    .unwrap();
    let control_json: Value = serde_json::from_slice(&control).unwrap();
    let welcome = control_json
        .pointer("/signedRequest/body/manifest/welcomeBundle/opaqueWelcome")
        .and_then(Value::as_str)
        .expect("genuine native Welcome in fixture history");
    let welcome = STANDARD.decode(welcome).unwrap();
    let now = Utc::now();
    sqlx::query(
        "INSERT INTO chat.direct_request_transport_inbox \
         (request_id, conversation_id, first_message_id, coordinator_did, sender_did, sender_device_id, \
          recipient_did, recipient_device_id, request_entry, signed_publication, full_welcome, \
          full_welcome_sha256, provenance, publication_receipt, import_until, status) \
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$9,$10,$11,$9,$12,$13,'accepted')",
    )
    .bind(Uuid::new_v4())
    .bind(fixture.conversation_id)
    .bind(fixture.message_id)
    .bind(catbird_server::identity::service_did_base())
    .bind(&fixture.sender_did)
    .bind(fixture.sender_device_id)
    .bind(&fixture.recipient_did)
    .bind(fixture.recipient_device_id)
    .bind(&control)
    .bind(&welcome)
    .bind(Sha256::digest(&welcome).to_vec())
    .bind(serde_json::to_vec(receipt).unwrap())
    .bind(now + Duration::days(30))
    .execute(&home)
    .await
    .unwrap();
    let mut entry = accepted_entry.clone();
    entry["$type"] = json!("blue.catbird.chat.defs#applicationEntry");
    entry["sequencerReceipt"] = receipt.clone();
    let original = serde_json::to_vec(&entry).unwrap();
    let seq = entry["seq"].as_i64().unwrap();
    let entry_id = Uuid::parse_str(entry["entryId"].as_str().unwrap()).unwrap();
    assert!(
        original.windows(6).any(|window| window == b"\\u0000"),
        "the genuine signed request keeps its NUL-terminated domain"
    );
    assert_eq!(
        catbird_server::chat_protocol::repository::delivery::insert_transport_entry(
            &mut home.acquire().await.unwrap(),
            fixture.conversation_id,
            seq,
            entry_id,
            &original,
            now,
        )
        .await
        .unwrap(),
        catbird_server::chat_protocol::repository::delivery::TransportEntryInsert::Inserted
    );
    let conversation_count: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM chat.conversations WHERE conversation_id = $1")
            .bind(fixture.conversation_id)
            .fetch_one(&home)
            .await
            .unwrap();
    assert_eq!(conversation_count, 0, "C33 home must be transport-only");
    let router = http::router_for_authenticated_acceptance(home.clone()).await;
    let key = EdSigningKey::from_bytes(&fixture.sender_ed25519_seed);
    let ack = sign_ack_entries_request(
        fixture.sender_device_id,
        &fixture.sender_key_id,
        1,
        &key,
        fixture.conversation_id,
        0,
        seq,
    );
    for expected_pruned in [1_i64, 0] {
        let (status, body) = http::send(
            router.clone(),
            http::unsigned_json_request(
                sender,
                "blue.catbird.chat.acknowledgeEntries",
                serde_json::to_vec(&ack).unwrap(),
            ),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "C33 ACK: {body}");
        assert_eq!(body["acknowledgedSeq"], seq);
        assert_eq!(body["prunedCount"], expected_pruned);
    }
    let watermark: i64 = sqlx::query_scalar(
        "SELECT acked_through_seq FROM chat.device_entry_acks \
          WHERE conversation_id = $1 AND user_did = $2 AND device_id = $3",
    )
    .bind(fixture.conversation_id)
    .bind(&fixture.sender_did)
    .bind(fixture.sender_device_id)
    .fetch_one(&home)
    .await
    .unwrap();
    assert_eq!(watermark, seq, "transport-only ACK must be durable");
    let (digest, metadata, bytes, pruned): (Vec<u8>, Vec<u8>, Vec<u8>, bool) = sqlx::query_as(
        "SELECT original_entry_sha256, application_metadata_bytes, entry_bytes, \
                payload_pruned_at IS NOT NULL FROM chat.direct_request_transport_entries \
          WHERE conversation_id = $1 AND seq = $2",
    )
    .bind(fixture.conversation_id)
    .bind(seq)
    .fetch_one(&home)
    .await
    .unwrap();
    assert!(pruned);
    assert_eq!(digest, Sha256::digest(&original).to_vec());
    // The stored entry carries the presented (`$bytes`) form of the request.
    let mut expected_metadata = entry["signedRequest"].clone();
    expected_metadata["body"]["applicationMessage"]
        .as_object_mut()
        .unwrap()
        .remove("bytes");
    assert_eq!(
        serde_json::from_slice::<Value>(&metadata).unwrap(),
        expected_metadata
    );
    let projection: Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(projection["seq"], seq);
    assert_eq!(projection["payloadPruned"], true);
    assert_eq!(&projection["sequencerReceipt"], receipt);
    assert!(projection.get("signedRequest").is_none());
    let (status, page) = http::send(
        router.clone(),
        http::unsigned_get_request(
            sender,
            "blue.catbird.chat.getEntries",
            &format!(
                "actorDeviceId={}&conversationId={}&afterSeq={}&limit=50",
                fixture.sender_device_id,
                fixture.conversation_id,
                seq - 1,
            ),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "pruned C33 getEntries: {page}");
    assert_eq!(page["entries"][0]["seq"], seq);
    assert_eq!(page["entries"][0]["payloadPruned"], true);
    assert_eq!(&page["entries"][0]["sequencerReceipt"], receipt);
    assert!(page["entries"][0].get("signedRequest").is_none());
    let (status, replay) = http::send(
        router.clone(),
        http::unsigned_json_request(
            sender,
            "blue.catbird.chat.sendMessage",
            serde_json::to_vec(&json!({"signedRequest": fixture.signed_request})).unwrap(),
        ),
    )
    .await;
    // The same signed send replays as its accepted outcome (binding contract):
    // exactly the pruned entry `getEntries` serves here, with its I13 receipt.
    assert_eq!(status, StatusCode::OK, "pruned retry: {replay}");
    let mut served = page["entries"][0].clone();
    served.as_object_mut().unwrap().remove("$type");
    assert_eq!(
        replay,
        json!({ "entry": served, "sequencerReceipt": receipt }),
        "pruned retry"
    );
    let mut changed_body = fixture.signed_request["body"].clone();
    changed_body["signedAt"] =
        json!((now + Duration::seconds(1)).to_rfc3339_opts(SecondsFormat::Millis, true));
    let changed = catbird_server::chat_protocol::test_support::sign_mutation_json_for_test(
        &changed_body,
        &key,
    )
    .unwrap();
    let (_, conflict) = http::send(
        router,
        http::unsigned_json_request(
            sender,
            "blue.catbird.chat.sendMessage",
            serde_json::to_vec(&json!({"signedRequest": changed})).unwrap(),
        ),
    )
    .await;
    assert_eq!(
        conflict["error"], "IdempotencyConflict",
        "changed retry: {conflict}"
    );
    assert!(sqlx::query(
        "UPDATE chat.direct_request_transport_entries SET entry_bytes = $3, payload_pruned_at = NULL \
          WHERE conversation_id = $1 AND seq = $2",
    )
    .bind(fixture.conversation_id)
    .bind(seq)
    .bind(&original)
    .execute(&home)
    .await
    .is_err());
}
