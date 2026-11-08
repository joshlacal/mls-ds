//! O7 for `sendMessage` receipts on real PostgreSQL (migration 20261104000005):
//! every prune of a message's ciphertext erases its receipt's request,
//! transcript and response in the same transaction, keeps its digests and
//! signature; the same signed send then replays as its accepted, pruned entry,
//! and another request under its key is refused with `IdempotencyConflict`.

use super::delivery::{prune_acknowledged_application_payloads, APPLICATION_ENTRY_KIND};
use crate::{
    chat_protocol::{
        repository::{
            direct_request_opening_tests::residue, expiry_sweep::prune_expired_application_payloads,
        },
        test_support::{seed_clean_slate_application_fixture, CleanSlateApplicationFixture},
    },
    common::{fresh_db::fresh_fully_migrated_db, http_acceptance as http},
    federation::receipt::I13ReceiptSigner,
    labyrinth::repo::retention::delete_account_data_with_conversations,
};
use axum::{http::StatusCode, Router};
use base64::{engine::general_purpose::STANDARD, Engine as _};
use chrono::{DateTime, Duration, SecondsFormat, Utc};
use serde_json::{json, Value};
use sqlx::PgPool;
use std::future::Future;
use uuid::Uuid;

const DS: &str = "did:web:chat.catbird.blue";

/// Runs `work` as this DS, optionally with the P8 retention plant.
async fn as_ds<T>(retain: bool, work: impl Future<Output = T>) -> T {
    let hooks = std::sync::Arc::new(crate::sim_hooks::SimDsHooks {
        service_did: DS.into(),
        self_endpoint: "https://chat.catbird.blue".into(),
        signing_key_pem: None,
        group_relay_hmac_secret: None,
        http_transport: std::sync::Arc::new(|_| {
            Box::pin(async { Err("unexpected receipt-erasure network request".into()) })
        }),
        dns_resolver: std::sync::Arc::new(|_| Err("unexpected receipt-erasure DNS".into())),
        retain_application_ciphertext: retain,
    });
    crate::sim_hooks::scope_sim_ds(hooks, work).await
}

struct Ds {
    pool: PgPool,
    router: Router,
    signer: I13ReceiptSigner,
    _db: crate::common::fresh_db::DisposableDatabase,
}

async fn ds() -> Ds {
    let db = fresh_fully_migrated_db("chat_pruning_").await;
    let pool = db.connect(6).await;
    http::ensure_fence(&pool).await;
    let signer = I13ReceiptSigner::new(http::random_p256(), DS.to_owned());
    let router = http::router_for_authenticated_acceptance_with(pool.clone(), |runtime| {
        runtime.with_i13_receipt_signer(signer.clone())
    })
    .await;
    Ds {
        pool,
        router,
        signer,
        _db: db,
    }
}

/// One message sequenced through the real `sendMessage` route.
struct Sent {
    fixture: CleanSlateApplicationFixture,
    seq: i64,
    ciphertext: Vec<u8>,
    /// Its first response.
    reply: Value,
}

async fn send(ds: &Ds, commitment: u8) -> Sent {
    let fixture = seed_clean_slate_application_fixture(&ds.pool, false, DS, Some([commitment; 32]))
        .await
        .unwrap();
    let (status, reply) = submit(ds, &fixture).await;
    assert_eq!(status, StatusCode::OK, "sendMessage: {reply}");
    let ciphertext = STANDARD
        .decode(
            fixture.signed_request["body"]["applicationMessage"]["bytes"]
                .as_str()
                .unwrap(),
        )
        .unwrap();
    Sent {
        seq: reply["entry"]["seq"].as_i64().unwrap(),
        fixture,
        ciphertext,
        reply,
    }
}

/// The fixture's exact signed send: a first execution or a replay.
async fn submit(ds: &Ds, fixture: &CleanSlateApplicationFixture) -> (StatusCode, Value) {
    submit_signed(ds, fixture, &fixture.signed_request).await
}

/// `signed`, sent by the fixture's sender device.
async fn submit_signed(
    ds: &Ds,
    fixture: &CleanSlateApplicationFixture,
    signed: &Value,
) -> (StatusCode, Value) {
    let sender = device(&fixture.sender_did, fixture.sender_device_id).await;
    let body = serde_json::to_vec(&json!({ "signedRequest": signed })).unwrap();
    http::send(
        ds.router.clone(),
        http::unsigned_json_request(&sender, "blue.catbird.chat.sendMessage", body),
    )
    .await
}

/// `did`'s device `device_id`, with a service-auth key published for it.
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

/// `sent`'s entry exactly as `getEntries` serves it to the recipient's device.
async fn served(ds: &Ds, sent: &Sent) -> Value {
    let f = &sent.fixture;
    let reader = device(&f.recipient_did, f.recipient_device_id).await;
    let query = format!(
        "actorDeviceId={}&conversationId={}&afterSeq={}&limit=1",
        f.recipient_device_id,
        f.conversation_id,
        sent.seq - 1
    );
    let (status, page) = http::send(
        ds.router.clone(),
        http::unsigned_get_request(&reader, "blue.catbird.chat.getEntries", &query),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "getEntries: {page}");
    assert_eq!(page["entries"][0]["seq"], sent.seq, "{page}");
    page["entries"][0].clone()
}

/// `(erased, request held, transcript held, response held, request digest,
/// response digest, signature)` of a message's receipt.
type Receipt = (bool, bool, bool, bool, Vec<u8>, Vec<u8>, Vec<u8>);

async fn receipt(pool: &PgPool, sent: &Sent) -> Receipt {
    sqlx::query_as(
        "SELECT payload_erased_at IS NOT NULL, accepted_request_bytes IS NOT NULL, \
                signing_transcript_bytes IS NOT NULL, response_bytes IS NOT NULL, \
                request_digest, response_sha256, signature \
           FROM chat.idempotency_records \
          WHERE principal_did = $1 AND endpoint_nsid = 'blue.catbird.chat.sendMessage' \
            AND operation_id = $2",
    )
    .bind(&sent.fixture.sender_did)
    .bind(sent.fixture.message_id)
    .fetch_one(pool)
    .await
    .unwrap()
}

fn erased(held: &Receipt) -> Receipt {
    (
        true,
        false,
        false,
        false,
        held.4.clone(),
        held.5.clone(),
        held.6.clone(),
    )
}

async fn entry_count(pool: &PgPool, conversation_id: Uuid) -> i64 {
    sqlx::query_scalar("SELECT count(*) FROM chat.entries WHERE conversation_id = $1")
        .bind(conversation_id)
        .fetch_one(pool)
        .await
        .unwrap()
}

/// Both devices of the fixture acknowledge `seq`, then the ACK prune runs.
async fn acknowledge(pool: &PgPool, sent: &Sent, at: DateTime<Utc>) -> Vec<i64> {
    let f = &sent.fixture;
    for (did, device) in [
        (&f.sender_did, f.sender_device_id),
        (&f.recipient_did, f.recipient_device_id),
    ] {
        sqlx::query(
            "INSERT INTO chat.device_entry_acks \
             (conversation_id, user_did, device_id, acked_through_seq, updated_at) \
             VALUES ($1, $2, $3, $4, clock_timestamp())",
        )
        .bind(f.conversation_id)
        .bind(did)
        .bind(device)
        .bind(sent.seq)
        .execute(pool)
        .await
        .unwrap();
    }
    let generation = f.signed_request["body"]["prior"]["generation"]
        .as_i64()
        .unwrap();
    let mut tx = pool.begin().await.unwrap();
    let pruned = prune_acknowledged_application_payloads(
        &mut tx,
        f.conversation_id,
        generation,
        sent.seq,
        false,
        at,
    )
    .await
    .unwrap();
    tx.commit().await.unwrap();
    pruned
}

/// The same signed send, replayed once its receipt is erased, returns its
/// accepted outcome and executes nothing: the pruned entry `getEntries` serves
/// and its I13 receipt, no ciphertext anywhere. Another request under its
/// idempotency key is still refused.
async fn assert_replay_accepted(ds: &Ds, sent: &Sent) {
    let entries = entry_count(&ds.pool, sent.fixture.conversation_id).await;
    let (status, reply) = submit(ds, &sent.fixture).await;
    assert_eq!(status, StatusCode::OK, "{reply}");
    let mut entry = served(ds, sent).await;
    entry.as_object_mut().unwrap().remove("$type");
    assert_eq!(entry["payloadPruned"], true, "{entry}");
    assert!(entry.get("signedRequest").is_none(), "{entry}");
    for field in [
        "entryId",
        "conversationId",
        "seq",
        "receivedAt",
        "sequencerReceipt",
    ] {
        assert_eq!(entry[field], sent.reply["entry"][field], "{field}");
    }
    assert!(sent.reply["sequencerReceipt"].is_object(), "{}", sent.reply);
    assert_eq!(
        reply,
        json!({ "entry": entry, "sequencerReceipt": sent.reply["sequencerReceipt"] })
    );

    let mut body = sent.fixture.signed_request["body"].clone();
    body["signedAt"] = json!(Utc::now().to_rfc3339_opts(SecondsFormat::Millis, true));
    let changed = crate::chat_protocol::test_support::sign_mutation_json_for_test(
        &body,
        &ed25519_dalek::SigningKey::from_bytes(&sent.fixture.sender_ed25519_seed),
    )
    .unwrap();
    let (status, conflict) = submit_signed(ds, &sent.fixture, &changed).await;
    assert!(status.is_client_error(), "{status}: {conflict}");
    assert_eq!(conflict["error"], "IdempotencyConflict", "{conflict}");
    assert_eq!(
        entry_count(&ds.pool, sent.fixture.conversation_id).await,
        entries,
        "a replay executes nothing"
    );
    assert_eq!(
        residue(&ds.pool, &sent.ciphertext).await,
        Vec::<String>::new()
    );
}

#[tokio::test]
async fn an_ack_prune_erases_the_receipt_and_its_replay_returns_the_pruned_entry() {
    let ds = ds().await;
    as_ds(false, async {
        let sent = send(&ds, 0x61).await;
        let held = receipt(&ds.pool, &sent).await;
        assert!(!held.0 && held.1 && held.2 && held.3, "{held:?}");
        assert!(residue(&ds.pool, &sent.ciphertext)
            .await
            .contains(&"chat.idempotency_records.accepted_request_bytes".to_owned()));
        // The exact replay of a held receipt returns the stored response.
        assert_eq!(submit(&ds, &sent.fixture).await.0, StatusCode::OK);

        assert_eq!(
            acknowledge(&ds.pool, &sent, Utc::now()).await,
            vec![sent.seq]
        );
        assert_eq!(receipt(&ds.pool, &sent).await, erased(&held));
        assert_eq!(
            residue(&ds.pool, &sent.ciphertext).await,
            Vec::<String>::new()
        );
        assert_replay_accepted(&ds, &sent).await;
    })
    .await;
}

/// Seed 2323 through the real `sendMessage` route: a held send arriving after
/// the same device's newer send is `StaleSend` (400) and writes nothing, while
/// exact replays of the accepted sends still return their stored 200 replies.
#[tokio::test]
async fn a_late_send_is_stale_send_and_accepted_replays_still_succeed() {
    let ds = ds().await;
    as_ds(false, async {
        let sent = send(&ds, 0x51).await;
        let f = &sent.fixture;
        let held = f.next_sender_signed_request();
        let newer = f.next_sender_signed_request();
        assert!(newer["body"]["sendCounter"].as_u64() > held["body"]["sendCounter"].as_u64());
        let (status, accepted) = submit_signed(&ds, f, &newer).await;
        assert_eq!(status, StatusCode::OK, "{accepted}");

        let entries = entry_count(&ds.pool, f.conversation_id).await;
        let (status, refused) = submit_signed(&ds, f, &held).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{refused}");
        assert_eq!(refused["error"], "StaleSend", "{refused}");
        assert_eq!(entry_count(&ds.pool, f.conversation_id).await, entries);
        let stored: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM chat.message_sends WHERE conversation_id = $1 AND message_id = $2",
        )
        .bind(f.conversation_id)
        .bind(Uuid::parse_str(held["body"]["messageId"].as_str().unwrap()).unwrap())
        .fetch_one(&ds.pool)
        .await
        .unwrap();
        assert_eq!(stored, 0, "a refused send retires nothing");

        assert_eq!(submit(&ds, f).await, (StatusCode::OK, sent.reply.clone()));
        assert_eq!(
            submit_signed(&ds, f, &newer).await,
            (StatusCode::OK, accepted)
        );
    })
    .await;
}

#[tokio::test]
async fn the_30_day_sweep_erases_every_receipt_it_reaches() {
    let ds = ds().await;
    as_ds(false, async {
        // Pruned by the sweep itself.
        let swept = send(&ds, 0x62).await;
        // Its entry pruned without its receipt, as before this migration.
        let legacy = send(&ds, 0x63).await;
        let mut tx = ds.pool.begin().await.unwrap();
        for statement in [
            "UPDATE chat.entries SET accepted_payload_bytes = NULL, signed_request_bytes = NULL, \
                    payload_pruned_at = clock_timestamp() \
              WHERE conversation_id = $1 AND seq = $2",
            "UPDATE chat.message_sends SET signed_request_bytes = NULL, \
                    signing_transcript_bytes = NULL, outcome_bytes = NULL, \
                    payload_pruned_at = clock_timestamp() \
              WHERE conversation_id = $1 AND accepted_entry_seq = $2",
        ] {
            sqlx::query(statement)
                .bind(legacy.fixture.conversation_id)
                .bind(legacy.seq)
                .execute(&mut *tx)
                .await
                .unwrap();
        }
        tx.commit().await.unwrap();
        let (swept_held, legacy_held) = (
            receipt(&ds.pool, &swept).await,
            receipt(&ds.pool, &legacy).await,
        );
        assert!(legacy_held.1, "{legacy_held:?}");

        prune_expired_application_payloads(&ds.pool, Utc::now() + Duration::days(31))
            .await
            .unwrap();
        assert_eq!(receipt(&ds.pool, &swept).await, erased(&swept_held));
        assert_eq!(receipt(&ds.pool, &legacy).await, erased(&legacy_held));
        for sent in [&swept, &legacy] {
            assert_eq!(
                residue(&ds.pool, &sent.ciphertext).await,
                Vec::<String>::new()
            );
        }
        for sent in [&swept, &legacy] {
            assert_replay_accepted(&ds, sent).await;
        }
    })
    .await;
}

#[tokio::test]
async fn deleting_an_account_erases_only_its_receipts() {
    let ds = ds().await;
    as_ds(false, async {
        let deleted = send(&ds, 0x64).await;
        let kept = send(&ds, 0x65).await;
        let (deleted_held, kept_held) = (
            receipt(&ds.pool, &deleted).await,
            receipt(&ds.pool, &kept).await,
        );
        delete_account_data_with_conversations(
            &ds.pool,
            &deleted.fixture.sender_did,
            Utc::now(),
            Some(&ds.signer),
        )
        .await
        .unwrap();
        assert_eq!(receipt(&ds.pool, &deleted).await, erased(&deleted_held));
        assert_eq!(receipt(&ds.pool, &kept).await, kept_held);
        assert_eq!(
            residue(&ds.pool, &deleted.ciphertext).await,
            Vec::<String>::new()
        );
        assert!(residue(&ds.pool, &kept.ciphertext)
            .await
            .contains(&"chat.idempotency_records.accepted_request_bytes".to_owned()));
        assert_replay_accepted(&ds, &deleted).await;
        assert_eq!(submit(&ds, &kept.fixture).await.0, StatusCode::OK);
    })
    .await;
}

#[tokio::test]
async fn an_erased_receipt_never_changes_again() {
    let ds = ds().await;
    as_ds(false, async {
        let sent = send(&ds, 0x66).await;
        let original: (Vec<u8>, Vec<u8>, Vec<u8>) = sqlx::query_as(
            "SELECT accepted_request_bytes, signing_transcript_bytes, response_bytes \
               FROM chat.idempotency_records WHERE operation_id = $1",
        )
        .bind(sent.fixture.message_id)
        .fetch_one(&ds.pool)
        .await
        .unwrap();
        acknowledge(&ds.pool, &sent, Utc::now()).await;
        let erased_row = receipt(&ds.pool, &sent).await;
        for (statement, restored) in [
            (
                "UPDATE chat.idempotency_records SET accepted_request_bytes = $2, \
                        signing_transcript_bytes = $3, response_bytes = $4, \
                        payload_erased_at = NULL WHERE operation_id = $1",
                true,
            ),
            (
                "UPDATE chat.idempotency_records SET accepted_request_bytes = $2, \
                        signing_transcript_bytes = $3, response_bytes = $4 \
                  WHERE operation_id = $1",
                true,
            ),
            (
                "UPDATE chat.idempotency_records \
                    SET payload_erased_at = payload_erased_at + INTERVAL '1 second' \
                  WHERE operation_id = $1",
                false,
            ),
            (
                "UPDATE chat.idempotency_records SET completed_status = 201 \
                  WHERE operation_id = $1",
                false,
            ),
            (
                "DELETE FROM chat.idempotency_records WHERE operation_id = $1",
                false,
            ),
        ] {
            let query = sqlx::query(statement).bind(sent.fixture.message_id);
            let query = if restored {
                query.bind(&original.0).bind(&original.1).bind(&original.2)
            } else {
                query
            };
            let error = query.execute(&ds.pool).await.unwrap_err();
            assert_eq!(
                error.as_database_error().and_then(|e| e.code()).as_deref(),
                Some("23514"),
                "{statement}: {error}"
            );
        }
        assert_eq!(receipt(&ds.pool, &sent).await, erased_row);
    })
    .await;
}

#[tokio::test]
async fn the_p8_plant_retains_every_receipt_payload() {
    let ds = ds().await;
    let sent = as_ds(false, send(&ds, 0x67)).await;
    let held = receipt(&ds.pool, &sent).await;
    as_ds(true, async {
        assert_eq!(
            acknowledge(&ds.pool, &sent, Utc::now()).await,
            Vec::<i64>::new()
        );
        prune_expired_application_payloads(&ds.pool, Utc::now() + Duration::days(31))
            .await
            .unwrap();
        delete_account_data_with_conversations(
            &ds.pool,
            &sent.fixture.sender_did,
            Utc::now(),
            Some(&ds.signer),
        )
        .await
        .unwrap();
    })
    .await;
    assert_eq!(receipt(&ds.pool, &sent).await, held);
    let pruned: bool = sqlx::query_scalar(
        "SELECT payload_pruned_at IS NOT NULL FROM chat.entries \
          WHERE conversation_id = $1 AND seq = $2 AND entry_kind = $3",
    )
    .bind(sent.fixture.conversation_id)
    .bind(sent.seq)
    .bind(APPLICATION_ENTRY_KIND)
    .fetch_one(&ds.pool)
    .await
    .unwrap();
    assert!(!pruned);
}

/// Queue `sent`'s entry, signed request and ciphertext included, under each id
/// its writers use: sendMessage's `message-delivery-…`, the C33 relay's
/// `msg-delivery-…`, group fan-out's `group-entry-…` and a legacy
/// `deliverMessage` outbox job. Only rows nothing sends again are queued, plus,
/// with `ordered`, the copies an ordered delivery still needs (pending or in
/// flight); returns those copies' ids.
async fn queue_copies(pool: &PgPool, sent: &Sent, ordered: bool) -> Vec<String> {
    let cid = sent.fixture.conversation_id;
    let entry: Uuid = sqlx::query_scalar(
        "SELECT entry_id FROM chat.entries WHERE conversation_id = $1 AND seq = $2",
    )
    .bind(cid)
    .bind(sent.seq)
    .fetch_one(pool)
    .await
    .unwrap();
    let payload = serde_json::to_vec(&json!({
        "conversationId": cid,
        "entry": {"entryId": entry, "seq": sent.seq, "signedRequest": sent.fixture.signed_request},
    }))
    .unwrap();
    let (group, c33, legacy) = (
        "blue.catbird.mlsDS.deliverGroupEntry",
        "blue.catbird.mlsDS.deliverMessageEntry",
        "blue.catbird.mlsDS.deliverMessage",
    );
    let seq = sent.seq;
    let sent_by = |home: &str| format!("message-delivery-{entry}-did:web:{home}");
    let fanned = |home: &str| format!("group-entry-{cid}-{seq}-did:web:{home}");
    let mut copies = vec![
        (true, format!("msg-delivery-{cid}-{seq}"), c33, "delivered"),
        (true, sent_by("a.example"), c33, "failed"),
        (true, fanned("b.example"), group, "failed"),
        (true, fanned("c.example"), group, "dead"),
        (false, Uuid::new_v4().to_string(), legacy, "done"),
    ];
    let held = vec![
        (true, sent_by("d.example"), c33, "pending"),
        (true, fanned("f.example"), group, "pending"),
        (true, fanned("e.example"), group, "in_flight"),
        (false, Uuid::new_v4().to_string(), legacy, "pending"),
    ];
    let mut needed: Vec<String> = Vec::new();
    if ordered {
        needed.extend(held.iter().map(|copy| copy.1.clone()));
        copies.extend(held);
    }
    for (queue, id, method, status) in copies {
        sqlx::query(if queue {
            "INSERT INTO outbound_queue (id, target_ds_did, target_endpoint, method, payload, \
                 convo_id, status) VALUES ($1, 'did:web:peer.example', '', $2, $3, $4, $5)"
        } else {
            "INSERT INTO federation_outbox (id, conversation_id, target_service_did, method, \
                 payload, status) VALUES ($1, $4, 'did:web:peer.example', $2, $3, $5)"
        })
        .bind(id)
        .bind(method)
        .bind(&payload)
        .bind(cid.to_string())
        .bind(status)
        .execute(pool)
        .await
        .unwrap();
    }
    needed.sort();
    needed
}

#[tokio::test]
async fn every_prune_drops_the_queued_copies_no_ordered_delivery_needs() {
    let ds = ds().await;
    as_ds(false, async {
        let acked = send(&ds, 0x71).await;
        let deleted = send(&ds, 0x72).await;
        let swept = send(&ds, 0x73).await;
        let held = send(&ds, 0x74).await;
        for sent in [&acked, &deleted, &swept] {
            assert!(queue_copies(&ds.pool, sent, false).await.is_empty());
        }
        let needed = queue_copies(&ds.pool, &held, true).await;
        for sent in [&acked, &deleted, &swept, &held] {
            let found = residue(&ds.pool, &sent.ciphertext).await;
            assert!(
                found.contains(&"public.federation_outbox.payload".to_owned())
                    && found.contains(&"public.outbound_queue.payload".to_owned()),
                "{found:?}"
            );
        }

        assert_eq!(
            acknowledge(&ds.pool, &acked, Utc::now()).await,
            vec![acked.seq]
        );
        delete_account_data_with_conversations(
            &ds.pool,
            &deleted.fixture.sender_did,
            Utc::now(),
            Some(&ds.signer),
        )
        .await
        .unwrap();
        assert_eq!(
            acknowledge(&ds.pool, &held, Utc::now()).await,
            vec![held.seq]
        );
        prune_expired_application_payloads(&ds.pool, Utc::now() + Duration::days(31))
            .await
            .unwrap();
        for sent in [&acked, &deleted, &swept] {
            assert_eq!(
                residue(&ds.pool, &sent.ciphertext).await,
                Vec::<String>::new()
            );
        }

        // A copy still to be sent stays whole: no receiver accepts a pruned
        // copy, and dropping it would break its home's seq contiguity or the
        // predecessor every later delivery there needs.
        let mut left: Vec<String> = sqlx::query_scalar(
            "SELECT id FROM outbound_queue WHERE convo_id = $1 \
             UNION ALL SELECT id FROM federation_outbox WHERE conversation_id = $1",
        )
        .bind(held.fixture.conversation_id.to_string())
        .fetch_all(&ds.pool)
        .await
        .unwrap();
        left.sort();
        assert_eq!(left, needed);
        assert_eq!(
            residue(&ds.pool, &held.ciphertext).await,
            [
                "public.federation_outbox.payload",
                "public.outbound_queue.payload"
            ]
        );
    })
    .await;
}

/// O7 late settle: the copies a prune keeps because they are still in flight
/// (claimed outbound rows, outbox jobs not yet handed off) hold no ciphertext
/// once they settle, however their delivery ends; the copy a handoff leaves to
/// be sent stays whole until it settles too.
#[tokio::test]
async fn a_copy_in_flight_at_its_prune_holds_no_ciphertext_once_it_settles() {
    use crate::federation::queue::{
        claim_due_heads, mark_delivered_by_id, mark_item_delivered, OutboundQueue, StreamHead,
    };
    use crate::workers::{federation_outbox, record_failure};

    let ds = ds().await;
    as_ds(false, async {
        let sent = send(&ds, 0x75).await;
        let (cid, seq) = (sent.fixture.conversation_id.to_string(), sent.seq);
        let entry: Uuid = sqlx::query_scalar(
            "SELECT entry_id FROM chat.entries WHERE conversation_id = $1 AND seq = $2",
        )
        .bind(sent.fixture.conversation_id)
        .bind(seq)
        .fetch_one(&ds.pool)
        .await
        .unwrap();
        let payload = serde_json::to_vec(&json!({
            "conversationId": cid,
            "entry": {"entryId": entry, "seq": seq, "signedRequest": sent.fixture.signed_request},
        }))
        .unwrap();
        let (group, c33, legacy) = (
            "blue.catbird.mlsDS.deliverGroupEntry",
            "blue.catbird.mlsDS.deliverMessageEntry",
            "blue.catbird.mlsDS.deliverMessage",
        );
        // One outbound stream per settle, its head claimed in flight.
        let mut claimed = Vec::new();
        for (id, home, method) in [
            (
                format!("msg-delivery-{cid}-{seq}"),
                "did:web:a.example",
                c33,
            ),
            (
                format!("message-delivery-{entry}-did:web:b.example"),
                "did:web:b.example",
                c33,
            ),
            (
                format!("group-entry-{cid}-{seq}-did:web:c.example"),
                "did:web:c.example",
                group,
            ),
            (
                format!("message-delivery-{entry}-did:web:d.example"),
                "did:web:d.example",
                c33,
            ),
        ] {
            sqlx::query(
                "INSERT INTO outbound_queue (id, target_ds_did, target_endpoint, method, payload, \
                     convo_id, next_retry_at) \
                 VALUES ($1, $2, '', $3, $4, $5, now() - interval '1 minute')",
            )
            .bind(&id)
            .bind(home)
            .bind(method)
            .bind(&payload)
            .bind(&cid)
            .execute(&ds.pool)
            .await
            .unwrap();
            let head = StreamHead {
                convo_id: &cid,
                target_ds_did: home,
                method,
            };
            let mut items = claim_due_heads(&ds.pool, 1, Some(head)).await.unwrap();
            assert_eq!(items.len(), 1, "{id}");
            claimed.push(items.remove(0));
        }
        // Two legacy outbox jobs in flight: one is handed off, one dies.
        let home = "did:web:e.example";
        sqlx::query(
            "INSERT INTO federation_peers (ds_did, status, trust_score, created_at, updated_at) \
             VALUES ($1, 'allow', 100, now(), now())",
        )
        .bind(home)
        .execute(&ds.pool)
        .await
        .unwrap();
        for _ in 0..2 {
            sqlx::query(
                "INSERT INTO federation_outbox (id, conversation_id, target_service_did, method, \
                     payload, status, next_attempt_at) \
                 VALUES ($1, $2, $3, $4, $5, 'pending', now() - interval '1 minute')",
            )
            .bind(Uuid::new_v4().to_string())
            .bind(&cid)
            .bind(home)
            .bind(legacy)
            .bind(&payload)
            .execute(&ds.pool)
            .await
            .unwrap();
        }
        let mut jobs = federation_outbox::claim_due_rows(&ds.pool, 10)
            .await
            .unwrap();
        jobs.retain(|job| job.conversation_id == cid);
        assert_eq!(jobs.len(), 2);

        assert_eq!(acknowledge(&ds.pool, &sent, Utc::now()).await, vec![seq]);
        // The prune keeps every copy in flight: each may still reach its home.
        assert_eq!(
            residue(&ds.pool, &sent.ciphertext).await,
            [
                "public.federation_outbox.payload",
                "public.outbound_queue.payload"
            ]
        );

        let resolver = std::sync::Arc::new(crate::federation::resolver::DsResolver::new(
            ds.pool.clone(),
            reqwest::Client::new(),
            DS.to_owned(),
            "https://chat.catbird.blue".to_owned(),
            None,
            3600,
        ));
        let queue = OutboundQueue::new(
            ds.pool.clone(),
            crate::auth::AuthMiddleware::new(),
            resolver,
        );
        let [delivered, failed, dead, delivered_by_id] = &claimed[..] else {
            unreachable!()
        };
        assert!(queue
            .mark_delivered(&delivered.id, delivered.claim_token)
            .await
            .unwrap());
        assert!(queue
            .mark_failed(&failed.id, failed.claim_token, "peer policy denied")
            .await
            .unwrap());
        assert!(queue
            .mark_dead(&dead.id, dead.claim_token, "permanent failure")
            .await
            .unwrap());
        mark_delivered_by_id(&ds.pool, &delivered_by_id.id)
            .await
            .unwrap();
        federation_outbox::handoff_to_outbound_queue(&ds.pool, &jobs[0])
            .await
            .unwrap();
        let dying = &jobs[1];
        let status = record_failure(
            &ds.pool,
            "federation_outbox",
            &dying.id,
            dying.claim_token,
            dying.attempts,
            "permanent failure",
            true,
        )
        .await
        .unwrap();
        assert_eq!(status, "dead");

        // Only the handed-off copy, still to be sent, holds the ciphertext...
        let left: Vec<(String, String)> = sqlx::query_as(
            "SELECT id, status FROM outbound_queue WHERE convo_id = $1 \
             UNION ALL SELECT id, status FROM federation_outbox WHERE conversation_id = $1",
        )
        .bind(&cid)
        .fetch_all(&ds.pool)
        .await
        .unwrap();
        assert_eq!(left, [(jobs[0].id.clone(), "pending".to_owned())]);
        assert_eq!(
            residue(&ds.pool, &sent.ciphertext).await,
            ["public.outbound_queue.payload"]
        );
        // ...until it settles too.
        let head = StreamHead {
            convo_id: &cid,
            target_ds_did: home,
            method: legacy,
        };
        let handed = claim_due_heads(&ds.pool, 1, Some(head)).await.unwrap();
        assert_eq!(handed.len(), 1);
        assert!(
            mark_item_delivered(&ds.pool, &handed[0].id, handed[0].claim_token)
                .await
                .unwrap()
        );
        assert_eq!(
            residue(&ds.pool, &sent.ciphertext).await,
            Vec::<String>::new()
        );
    })
    .await;
}
