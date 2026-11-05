//! O7 opening-prune regressions on real PostgreSQL, for both C33 homes.

use super::delivery::{insert_transport_entry, prune_acknowledged_application_payloads};
use super::direct_request_opening::*;
use crate::chat_protocol::repository::delivery::TransportEntryInsert;
use crate::chat_protocol::repository::direct_request_receipts::DirectRequestReceiptSigner;
use crate::chat_protocol::test_support::{
    seed_clean_slate_expired_direct_request_fixture, CleanSlateExpiredDirectRequestFixture,
};
use base64::{engine::general_purpose::STANDARD, Engine as _};
use chrono::{DateTime, Utc};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use sqlx::PgPool;
use std::future::Future;
use uuid::Uuid;

fn pem(key: &p256::ecdsa::SigningKey) -> String {
    use p256::pkcs8::EncodePrivateKey as _;
    p256::SecretKey::from_slice(&key.to_bytes())
        .unwrap()
        .to_pkcs8_pem(p256::pkcs8::LineEnding::LF)
        .unwrap()
        .to_string()
}

struct Seeded {
    fixture: CleanSlateExpiredDirectRequestFixture,
    actor_device: Uuid,
    recipient_device: Uuid,
    signer: DirectRequestReceiptSigner,
}

/// A published opening at its coordinator, with both leaves' devices registered.
async fn seeded(pool: &PgPool) -> Seeded {
    let cursor_key: String = sqlx::query_scalar("SELECT chat.ed25519_key_id($1)")
        .bind(vec![0x51_u8; 32])
        .fetch_one(pool)
        .await
        .unwrap();
    sqlx::query(
        "INSERT INTO chat.protocol_instances(singleton,protocol_version,protocol_instance_id,cursor_key_id) \
         VALUES(TRUE,'1',$1,$2) ON CONFLICT DO NOTHING",
    )
    .bind(Uuid::new_v4())
    .bind(&cursor_key)
    .execute(pool)
    .await
    .unwrap();
    sqlx::query(
        "INSERT INTO chat.event_retention(protocol_instance_id,retained_floor,updated_at) \
         SELECT protocol_instance_id,0,clock_timestamp() FROM chat.protocol_instances \
         ON CONFLICT DO NOTHING",
    )
    .execute(pool)
    .await
    .unwrap();
    let receipt_key = p256::ecdsa::SigningKey::from_slice(&[21; 32]).unwrap();
    let service_key = p256::ecdsa::SigningKey::from_slice(&[22; 32]).unwrap();
    let document = crate::identity::did_doc::build_direct_request_receipt_did_document(
        "did:web:chat.catbird.blue",
        receipt_key.verifying_key(),
    );
    let signer = DirectRequestReceiptSigner::configured(
        &pem(&receipt_key),
        &pem(&service_key),
        &serde_json::to_string(&document).unwrap(),
    )
    .unwrap();
    let fixture = seed_clean_slate_expired_direct_request_fixture(pool, &signer)
        .await
        .unwrap();
    let device = |did: String| async move {
        sqlx::query_scalar::<_, Uuid>("SELECT device_id FROM chat.devices WHERE user_did = $1")
            .bind(did)
            .fetch_one(pool)
            .await
            .unwrap()
    };
    Seeded {
        actor_device: device(fixture.actor_did.clone()).await,
        recipient_device: device(fixture.recipient_did.clone()).await,
        fixture,
        signer,
    }
}

async fn ack(pool: &PgPool, conversation_id: Uuid, did: &str, device: Uuid) {
    sqlx::query(
        "INSERT INTO chat.device_entry_acks \
         (conversation_id, user_did, device_id, acked_through_seq, updated_at) \
         VALUES ($1, $2, $3, 1, clock_timestamp())",
    )
    .bind(conversation_id)
    .bind(did)
    .bind(device)
    .execute(pool)
    .await
    .unwrap();
}

async fn rejected(pool: &PgPool, sql: &str, conversation_id: Uuid) -> bool {
    sqlx::query(sql)
        .bind(conversation_id)
        .execute(pool)
        .await
        .is_err()
}

/// Runs `work` as this home's service, optionally with the P8 retention plant.
async fn as_service<T>(retain: bool, work: impl Future<Output = T>) -> T {
    let hooks = std::sync::Arc::new(crate::sim_hooks::SimDsHooks {
        service_did: "did:web:chat.catbird.blue".into(),
        self_endpoint: "https://chat.catbird.blue".into(),
        signing_key_pem: None,
        group_relay_hmac_secret: None,
        http_transport: std::sync::Arc::new(|_| {
            Box::pin(async { Err("unexpected opening network request".into()) })
        }),
        dns_resolver: std::sync::Arc::new(|_| Err("unexpected opening DNS".into())),
        retain_application_ciphertext: retain,
    });
    crate::sim_hooks::scope_sim_ds(hooks, work).await
}

#[tokio::test]
async fn coordinator_opening_waits_for_every_frozen_device_then_loses_every_ciphertext_copy() {
    let db = crate::common::fresh_db::fresh_fully_migrated_db("chat_pruning_").await;
    let pool = db.connect(4).await;
    let seeded = seeded(&pool).await;
    let (cid, request) = (seeded.fixture.conversation_id, seeded.fixture.request_id);
    let delivery = format!("direct-request-delivery-{request}");
    sqlx::query(
        "INSERT INTO outbound_queue (id, target_ds_did, target_endpoint, method, payload, convo_id, \
             next_retry_at, created_at) \
         VALUES ($1, 'did:web:peer.example.com', '', 'blue.catbird.mlsDS.deliverDirectRequest', \
             '\\x01', $2, clock_timestamp(), clock_timestamp())",
    )
    .bind(&delivery)
    .bind(cid.to_string())
    .execute(&pool)
    .await
    .unwrap();
    type Evidence = (Vec<u8>, Vec<u8>, Vec<u8>, Option<Vec<u8>>);
    let evidence = || async {
        sqlx::query_as::<_, Evidence>(
            "SELECT accepted_payload_sha256, request_digest, outer_entry_fingerprint, \
                    sequencer_receipt_bytes FROM chat.entries WHERE conversation_id = $1 AND seq = 1",
        )
        .bind(cid)
        .fetch_one(&pool)
        .await
        .unwrap()
    };
    let before = evidence().await;
    let original: Vec<u8> = sqlx::query_scalar(
        "SELECT accepted_payload_bytes FROM chat.entries WHERE conversation_id = $1 AND seq = 1",
    )
    .bind(cid)
    .fetch_one(&pool)
    .await
    .unwrap();
    let ciphertext: Vec<u8> = sqlx::query_scalar(
        "SELECT initial_ciphertext FROM chat.direct_request_publications WHERE request_id = $1",
    )
    .bind(request)
    .fetch_one(&pool)
    .await
    .unwrap();

    let prune = || async {
        let mut tx = pool.begin().await.unwrap();
        let pruned = as_service(
            false,
            prune_acknowledged_application_payloads(&mut tx, cid, 0, 1, false, Utc::now()),
        )
        .await
        .unwrap();
        tx.commit().await.unwrap();
        pruned
    };
    ack(
        &pool,
        cid,
        &seeded.fixture.recipient_did,
        seeded.recipient_device,
    )
    .await;
    assert!(
        prune().await.is_empty(),
        "the sender's frozen device has not acked"
    );
    ack(&pool, cid, &seeded.fixture.actor_did, seeded.actor_device).await;
    assert_eq!(prune().await, vec![1]);
    assert!(prune().await.is_empty(), "a pruned opening is pruned once");

    let (entry_gone, redacted): (bool, Vec<u8>) = sqlx::query_as(
        "SELECT accepted_payload_bytes IS NULL AND signed_request_bytes IS NULL \
                AND payload_pruned_at IS NOT NULL, pruned_payload_bytes \
           FROM chat.entries WHERE conversation_id = $1 AND seq = 1",
    )
    .bind(cid)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert!(entry_gone);
    assert_eq!(
        evidence().await,
        before,
        "digests, fingerprint and I13 receipt stay"
    );
    let redacted: Value = serde_json::from_slice(&redacted).unwrap();
    let mut expected: Value = serde_json::from_slice(&original).unwrap();
    expected["signedRequest"]["body"]["artifacts"]["initialCiphertext"] =
        json!(STANDARD.encode(Sha256::digest(&ciphertext)));
    assert_eq!(
        redacted, expected,
        "only the ciphertext is replaced, by its digest"
    );
    let (transition_gone, publication_gone, kept): (bool, bool, bool) = sqlx::query_as(
        "SELECT (SELECT signed_request_bytes IS NULL AND unsigned_projection_bytes IS NULL \
                        AND signing_transcript_bytes IS NULL AND payload_pruned_at IS NOT NULL \
                        AND octet_length(request_digest) = 32 \
                   FROM chat.transitions WHERE transition_id = $2), \
                (SELECT signed_publication IS NULL AND request_entry IS NULL \
                        AND initial_ciphertext IS NULL AND opening_pruned_at IS NOT NULL \
                   FROM chat.direct_request_publications WHERE request_id = $2), \
                (SELECT initial_ciphertext_sha256 = $3 AND full_welcome IS NOT NULL \
                   FROM chat.direct_request_publications WHERE request_id = $2)",
    )
    .bind(cid)
    .bind(request)
    .bind(Sha256::digest(&ciphertext).as_slice())
    .fetch_one(&pool)
    .await
    .unwrap();
    assert!(transition_gone && publication_gone && kept);
    let queued: bool =
        sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM outbound_queue WHERE id = $1)")
            .bind(&delivery)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert!(
        !queued,
        "a queued delivery cannot carry the bytes back later"
    );

    // Pruned bytes never return, and nothing is pruned twice.
    for sql in [
        "UPDATE chat.entries SET accepted_payload_bytes = '\\x7b7d' WHERE conversation_id = $1 AND seq = 1",
        "UPDATE chat.entries SET pruned_payload_bytes = '\\x7b7d' WHERE conversation_id = $1 AND seq = 1",
        "UPDATE chat.entries SET payload_pruned_at = NULL WHERE conversation_id = $1 AND seq = 1",
        "UPDATE chat.transitions SET signed_request_bytes = '\\x01' WHERE conversation_id = $1 \
            AND kind = 'directRequestPublication'",
        "UPDATE chat.direct_request_publications SET initial_ciphertext = '\\x01' WHERE conversation_id = $1",
        "UPDATE chat.direct_request_publications SET opening_pruned_at = NULL WHERE conversation_id = $1",
    ] {
        assert!(rejected(&pool, sql, cid).await, "{sql}");
    }
    let mut tx = pool.begin().await.unwrap();
    assert!(!prune_coordinator_opening(&mut tx, cid, 1, Utc::now())
        .await
        .unwrap());
    let (served, pruned) = coordinator_opening_response(&mut tx, request)
        .await
        .unwrap()
        .unwrap();
    assert!(pruned);
    assert_eq!(served, pruned_opening_entry(&redacted));
    assert!(served.get("signedRequest").is_none() && served["payloadPruned"] == true);
}

#[tokio::test]
async fn deleting_the_sender_prunes_its_coordinated_opening_and_the_recipient_does_not() {
    let db = crate::common::fresh_db::fresh_fully_migrated_db("chat_pruning_").await;
    let pool = db.connect(4).await;
    let seeded = seeded(&pool).await;
    let cid = seeded.fixture.conversation_id;
    let pruned = || async {
        sqlx::query_scalar::<_, bool>(
            "SELECT payload_pruned_at IS NOT NULL FROM chat.entries WHERE conversation_id = $1 AND seq = 1",
        )
        .bind(cid)
        .fetch_one(&pool)
        .await
        .unwrap()
    };
    for (did, expected) in [
        (&seeded.fixture.recipient_did, false),
        (&seeded.fixture.actor_did, true),
    ] {
        let mut tx = pool.begin().await.unwrap();
        as_service(
            false,
            crate::labyrinth::repo::retention::prune_account_ciphertext(
                &mut tx,
                cid,
                did,
                Utc::now(),
            ),
        )
        .await
        .unwrap();
        tx.commit().await.unwrap();
        assert_eq!(pruned().await, expected, "{did}");
    }
}

#[tokio::test]
async fn p8_plant_retains_every_opening_copy() {
    let db = crate::common::fresh_db::fresh_fully_migrated_db("chat_pruning_").await;
    let pool = db.connect(4).await;
    let seeded = seeded(&pool).await;
    let cid = seeded.fixture.conversation_id;
    let mut tx = pool.begin().await.unwrap();
    let retained = as_service(true, async {
        (
            prune_coordinator_opening(&mut tx, cid, 1, Utc::now())
                .await
                .unwrap(),
            prune_held_transport_openings_sent_by(&mut tx, &seeded.fixture.actor_did, Utc::now())
                .await
                .unwrap(),
        )
    })
    .await;
    assert_eq!(retained, (false, 0), "P8 cannot report fake pruning");
    let whole: bool = sqlx::query_scalar(
        "SELECT accepted_payload_bytes IS NOT NULL AND payload_pruned_at IS NULL \
           FROM chat.entries WHERE conversation_id = $1 AND seq = 1",
    )
    .bind(cid)
    .fetch_one(&mut *tx)
    .await
    .unwrap();
    assert!(whole);
}

fn opening(conversation_id: Uuid, request_id: Uuid, ciphertext: &[u8]) -> Value {
    json!({
        "$type": DIRECT_REQUEST_ENTRY_KIND,
        "entryId": Uuid::new_v4(),
        "conversationId": conversation_id,
        "seq": 1,
        "receivedAt": "2026-11-03T12:00:00.000Z",
        "signedRequest": {
            "body": {
                "$type": "blue.catbird.chat.defs#directRequestPublicationBody",
                "signatureDomain": "CATBIRD-DIRECT-REQUEST-PUBLISH\u{0}",
                "requestId": request_id,
                "conversationId": conversation_id,
                "artifacts": {
                    "initialCiphertext": STANDARD.encode(ciphertext),
                    "welcome": {"opaqueWelcome": STANDARD.encode(b"welcome")}
                }
            },
            "signature": STANDARD.encode([7_u8; 64])
        },
        "sequencerReceipt": {"seq": 1, "signature": STANDARD.encode([8_u8; 64])},
        "publicationReceipt": {
            "$type": "blue.catbird.chat.defs#signedDirectRequestReceipt",
            "body": {"receipt": {"requestId": request_id}},
            "signature": STANDARD.encode([9_u8; 64])
        }
    })
}

/// A transport-only C33 home's copies of one opening: the recipient's inbox row
/// and the opening's transport entry, stored through the production writer.
async fn transport_opening(
    pool: &PgPool,
    seeded: &Seeded,
    ciphertext: &[u8],
    now: DateTime<Utc>,
) -> (Uuid, Uuid, Value) {
    transport_opening_as(pool, seeded, ciphertext, now, "pending").await
}

/// [`transport_opening`] whose inbox row is in `status`.
async fn transport_opening_as(
    pool: &PgPool,
    seeded: &Seeded,
    ciphertext: &[u8],
    now: DateTime<Utc>,
    status: &str,
) -> (Uuid, Uuid, Value) {
    let (cid, request) = (Uuid::new_v4(), Uuid::new_v4());
    let entry = opening(cid, request, ciphertext);
    let entry_bytes = serde_json::to_vec(&entry).unwrap();
    sqlx::query(
        "INSERT INTO chat.direct_request_transport_inbox(request_id,conversation_id,first_message_id, \
             coordinator_did,sender_did,sender_device_id,recipient_did,recipient_device_id,request_entry, \
             signed_publication,full_welcome,full_welcome_sha256,provenance,publication_receipt, \
             import_until,status) \
         VALUES($1,$2,$3,'did:web:coordinator.example.com',$4,$5,$6,$7,$8,$9,$10,$11,$10,$10,$12,$13)",
    )
    .bind(request)
    .bind(cid)
    .bind(Uuid::new_v4())
    .bind(&seeded.fixture.actor_did)
    .bind(seeded.actor_device)
    .bind(&seeded.fixture.recipient_did)
    .bind(seeded.recipient_device)
    .bind(&entry_bytes)
    .bind(serde_json::to_vec(&entry["signedRequest"]).unwrap())
    .bind(b"welcome".as_slice())
    .bind(Sha256::digest(b"welcome").as_slice())
    .bind(now + chrono::Duration::days(7))
    .bind(status)
    .execute(pool)
    .await
    .unwrap();
    let entry_id = Uuid::parse_str(entry["entryId"].as_str().unwrap()).unwrap();
    let mut connection = pool.acquire().await.unwrap();
    assert_eq!(
        insert_transport_entry(&mut connection, cid, 1, entry_id, &entry_bytes, now)
            .await
            .unwrap(),
        TransportEntryInsert::Inserted
    );
    (cid, request, entry)
}

#[tokio::test]
async fn transport_home_opening_waits_for_its_local_audience_and_replays_never_restore_it() {
    let db = crate::common::fresh_db::fresh_fully_migrated_db("chat_pruning_").await;
    let pool = db.connect(4).await;
    let seeded = seeded(&pool).await;
    let now = Utc::now();
    let ciphertext = b"peer-held opening ciphertext";
    let (cid, request, entry) = transport_opening(&pool, &seeded, ciphertext, now).await;
    let entry_bytes = serde_json::to_vec(&entry).unwrap();
    let captured: (Option<Uuid>, Vec<u8>) = sqlx::query_as(
        "SELECT opening_request_id, pruned_entry_bytes FROM chat.direct_request_transport_entries \
          WHERE conversation_id = $1 AND seq = 1",
    )
    .bind(cid)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(captured.0, Some(request));
    let projection: Value = serde_json::from_slice(&captured.1).unwrap();
    assert_eq!(projection, pruned_opening_entry(&entry));

    let prune = || async {
        let mut tx = pool.begin().await.unwrap();
        let pruned = as_service(
            false,
            prune_acknowledged_application_payloads(&mut tx, cid, 0, 1, true, now),
        )
        .await
        .unwrap();
        tx.commit().await.unwrap();
        pruned
    };
    ack(
        &pool,
        cid,
        &seeded.fixture.recipient_did,
        seeded.recipient_device,
    )
    .await;
    assert!(
        prune().await.is_empty(),
        "the local sender device has not acked"
    );
    ack(&pool, cid, &seeded.fixture.actor_did, seeded.actor_device).await;
    assert_eq!(prune().await, vec![1]);

    let (served, original_sha256): (Vec<u8>, Vec<u8>) = sqlx::query_as(
        "SELECT entry_bytes, original_entry_sha256 FROM chat.direct_request_transport_entries \
          WHERE conversation_id = $1 AND seq = 1 AND payload_pruned_at IS NOT NULL",
    )
    .bind(cid)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(served, captured.1);
    assert_eq!(original_sha256, Sha256::digest(&entry_bytes).to_vec());
    type Inbox = (
        Option<Vec<u8>>,
        Option<Vec<u8>>,
        Vec<u8>,
        Vec<u8>,
        Vec<u8>,
        Vec<u8>,
    );
    let (request_entry, signed, entry_sha, signed_sha, redacted, receipt): Inbox = sqlx::query_as(
        "SELECT request_entry, signed_publication, request_entry_sha256, signed_publication_sha256, \
                redacted_request_entry, publication_receipt \
           FROM chat.direct_request_transport_inbox WHERE request_id = $1",
    )
    .bind(request)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!((request_entry, signed), (None, None));
    assert_eq!(entry_sha, Sha256::digest(&entry_bytes).to_vec());
    assert_eq!(
        signed_sha,
        Sha256::digest(serde_json::to_vec(&entry["signedRequest"]).unwrap()).to_vec()
    );
    assert!(!receipt.is_empty());
    let mut expected = entry.clone();
    expected["signedRequest"]["body"]["artifacts"]["initialCiphertext"] =
        json!(STANDARD.encode(Sha256::digest(ciphertext)));
    assert_eq!(
        serde_json::from_slice::<Value>(&redacted).unwrap(),
        expected
    );

    // A duplicate redelivery is recognized by its retained digest; a conflicting
    // one is refused; neither restores the ciphertext.
    let mut connection = pool.acquire().await.unwrap();
    let entry_id = Uuid::parse_str(entry["entryId"].as_str().unwrap()).unwrap();
    assert_eq!(
        insert_transport_entry(&mut connection, cid, 1, entry_id, &entry_bytes, now)
            .await
            .unwrap(),
        TransportEntryInsert::Duplicate
    );
    let conflicting = serde_json::to_vec(&opening(cid, request, b"other bytes")).unwrap();
    assert_eq!(
        insert_transport_entry(&mut connection, cid, 1, entry_id, &conflicting, now)
            .await
            .unwrap(),
        TransportEntryInsert::Conflict
    );
    drop(connection);
    let still: Vec<u8> = sqlx::query_scalar(
        "SELECT entry_bytes FROM chat.direct_request_transport_entries WHERE conversation_id = $1 AND seq = 1",
    )
    .bind(cid)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(still, captured.1);
    for sql in [
        "UPDATE chat.direct_request_transport_inbox SET request_entry = '\\x7b7d' WHERE conversation_id = $1",
        "UPDATE chat.direct_request_transport_inbox SET redacted_request_entry = '\\x7b7d' WHERE conversation_id = $1",
        "UPDATE chat.direct_request_transport_inbox SET opening_pruned_at = NULL WHERE conversation_id = $1",
        "UPDATE chat.direct_request_transport_inbox SET request_entry_sha256 = '\\x00' WHERE conversation_id = $1",
        "UPDATE chat.direct_request_transport_entries SET entry_bytes = '\\x7b7d', payload_pruned_at = NULL \
            WHERE conversation_id = $1",
    ] {
        assert!(rejected(&pool, sql, cid).await, "{sql}");
    }
}

#[tokio::test]
async fn transport_home_prunes_a_deleted_senders_opening_but_not_for_its_recipient() {
    let db = crate::common::fresh_db::fresh_fully_migrated_db("chat_pruning_").await;
    let pool = db.connect(4).await;
    let seeded = seeded(&pool).await;
    let now = Utc::now();
    let (cid, request, _) = transport_opening(&pool, &seeded, b"held opening", now).await;
    let pruned = || async {
        sqlx::query_scalar::<_, bool>(
            "SELECT (SELECT opening_pruned_at IS NOT NULL FROM chat.direct_request_transport_inbox \
                      WHERE request_id = $1) \
                AND (SELECT payload_pruned_at IS NOT NULL FROM chat.direct_request_transport_entries \
                      WHERE opening_request_id = $1)",
        )
        .bind(request)
        .fetch_one(&pool)
        .await
        .unwrap()
    };
    let mut tx = pool.begin().await.unwrap();
    assert_eq!(
        prune_transport_openings_sent_by(&mut tx, cid, &seeded.fixture.recipient_did, now)
            .await
            .unwrap(),
        0
    );
    tx.commit().await.unwrap();
    assert!(!pruned().await);
    // The sender's own home prunes on its local deletion; its coordinator's
    // control entry reaches the same function at a recipient's home.
    let mut tx = pool.begin().await.unwrap();
    assert_eq!(
        prune_held_transport_openings_sent_by(&mut tx, &seeded.fixture.actor_did, now)
            .await
            .unwrap(),
        1
    );
    tx.commit().await.unwrap();
    assert!(pruned().await);
    let mut tx = pool.begin().await.unwrap();
    assert_eq!(
        prune_transport_openings_sent_by(&mut tx, cid, &seeded.fixture.actor_did, now)
            .await
            .unwrap(),
        0,
        "a retry prunes nothing more"
    );
}

use crate::chat_protocol::repository::close_terminal::append_remote_close_event;
use crate::chat_protocol::repository::expiry_sweep::{
    expire_due_published_requests, prune_expired_application_payloads,
    prune_terminal_request_artifacts,
};

/// Every `schema.table.column` of this DS that still holds `needle`, as bytes or
/// as its base64 text.
pub(crate) async fn residue(pool: &PgPool, needle: &[u8]) -> Vec<String> {
    assert!(needle.len() >= 16, "a short needle could match by chance");
    let encoded = STANDARD.encode(needle);
    let columns: Vec<(String, String, String, String)> = sqlx::query_as(
        "SELECT c.table_schema::text, c.table_name::text, c.column_name::text, c.data_type::text \
           FROM information_schema.columns c \
           JOIN information_schema.tables t USING (table_schema, table_name) \
           JOIN pg_namespace n ON n.nspname = c.table_schema \
           JOIN pg_class r ON r.relnamespace = n.oid AND r.relname = c.table_name \
          WHERE c.table_schema IN ('chat', 'public') AND t.table_type = 'BASE TABLE' \
            AND NOT r.relispartition \
            AND c.data_type IN ('bytea', 'text', 'json', 'jsonb', 'character varying') \
          ORDER BY 1, 2, 3",
    )
    .fetch_all(pool)
    .await
    .unwrap();
    let mut found = Vec::new();
    for (schema, table, column, data_type) in columns {
        let predicate = if data_type == "bytea" {
            format!(
                "position($1 IN \"{column}\") > 0 \
                 OR position(convert_to($2, 'UTF8') IN \"{column}\") > 0"
            )
        } else {
            format!("$1 IS NOT NULL AND strpos(\"{column}\"::text, $2) > 0")
        };
        let hit: bool = sqlx::query_scalar(&format!(
            "SELECT EXISTS(SELECT 1 FROM \"{schema}\".\"{table}\" WHERE {predicate})"
        ))
        .bind(needle)
        .bind(&encoded)
        .fetch_one(pool)
        .await
        .unwrap();
        if hit {
            found.push(format!("{schema}.{table}.{column}"));
        }
    }
    found
}

async fn coordinator_ciphertext(pool: &PgPool, request_id: Uuid) -> Vec<u8> {
    sqlx::query_scalar(
        "SELECT initial_ciphertext FROM chat.direct_request_publications WHERE request_id = $1",
    )
    .bind(request_id)
    .fetch_one(pool)
    .await
    .unwrap()
}

#[tokio::test]
async fn expiry_prunes_the_coordinators_opening_in_the_expiry_transaction() {
    let db = crate::common::fresh_db::fresh_fully_migrated_db("chat_pruning_").await;
    let pool = db.connect(4).await;
    let seeded = seeded(&pool).await;
    let request = seeded.fixture.request_id;
    let ciphertext = coordinator_ciphertext(&pool, request).await;
    let digest = || async {
        sqlx::query_scalar::<_, Vec<u8>>(
            "SELECT accepted_payload_sha256 FROM chat.entries \
              WHERE transition_id = $1 AND entry_kind = $2",
        )
        .bind(request)
        .bind(DIRECT_REQUEST_ENTRY_KIND)
        .fetch_one(&pool)
        .await
        .unwrap()
    };
    let before = digest().await;
    assert_eq!(
        as_service(
            false,
            expire_due_published_requests(&pool, &seeded.signer, 10)
        )
        .await
        .unwrap(),
        1
    );
    let pruned_at_expiry: bool = sqlx::query_scalar(
        "SELECT COALESCE(p.opening_pruned_at = l.expired_at AND e.payload_pruned_at = l.expired_at \
                AND e.accepted_payload_bytes IS NULL AND p.initial_ciphertext IS NULL, FALSE) \
           FROM chat.direct_request_publications p \
           JOIN chat.direct_request_lifecycle l USING (request_id) \
           JOIN chat.entries e ON e.transition_id = p.request_id AND e.entry_kind = $2 \
          WHERE p.request_id = $1 AND l.consent = 'expired'",
    )
    .bind(request)
    .bind(DIRECT_REQUEST_ENTRY_KIND)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert!(
        pruned_at_expiry,
        "the expiry transaction prunes the opening"
    );
    assert_eq!(digest().await, before, "its digest stays");
    assert_eq!(residue(&pool, &ciphertext).await, Vec::<String>::new());
}

#[tokio::test]
async fn the_periodic_sweep_prunes_a_transport_opening_nobody_can_import_any_more() {
    let db = crate::common::fresh_db::fresh_fully_migrated_db("chat_pruning_").await;
    let pool = db.connect(4).await;
    let seeded = seeded(&pool).await;
    let now = Utc::now();
    let ciphertext = b"an opening whose import window closes";
    let (_, request, _) = transport_opening(&pool, &seeded, ciphertext, now).await;
    let pruned = || async {
        sqlx::query_scalar::<_, bool>(
            "SELECT (SELECT opening_pruned_at IS NOT NULL FROM chat.direct_request_transport_inbox \
                      WHERE request_id = $1) \
                AND (SELECT payload_pruned_at IS NOT NULL FROM chat.direct_request_transport_entries \
                      WHERE opening_request_id = $1)",
        )
        .bind(request)
        .fetch_one(&pool)
        .await
        .unwrap()
    };
    let sweep =
        |at: DateTime<Utc>| as_service(false, prune_expired_application_payloads(&pool, at));
    sweep(now + chrono::Duration::days(1)).await.unwrap();
    assert!(!pruned().await, "its recipient can still import it");
    sweep(now + chrono::Duration::days(8)).await.unwrap();
    assert!(pruned().await, "no device can import or read it any more");
    assert_eq!(residue(&pool, ciphertext).await, Vec::<String>::new());
}

#[tokio::test]
async fn the_30_day_ceiling_prunes_unacknowledged_openings_on_both_homes() {
    let db = crate::common::fresh_db::fresh_fully_migrated_db("chat_pruning_").await;
    let pool = db.connect(4).await;
    let seeded = seeded(&pool).await;
    let now = Utc::now();
    let coordinator = coordinator_ciphertext(&pool, seeded.fixture.request_id).await;
    let ciphertext = b"an accepted opening nobody acknowledged";
    let (_, request, _) = transport_opening_as(&pool, &seeded, ciphertext, now, "accepted").await;
    let state = || async {
        sqlx::query_as::<_, (bool, bool)>(
            "SELECT (SELECT payload_pruned_at IS NOT NULL FROM chat.entries \
                      WHERE transition_id = $1 AND entry_kind = $3), \
                    (SELECT payload_pruned_at IS NOT NULL FROM chat.direct_request_transport_entries \
                      WHERE opening_request_id = $2)",
        )
        .bind(seeded.fixture.request_id)
        .bind(request)
        .bind(DIRECT_REQUEST_ENTRY_KIND)
        .fetch_one(&pool)
        .await
        .unwrap()
    };
    let sweep = |retain: bool, days: i64| {
        as_service(
            retain,
            prune_expired_application_payloads(&pool, now + chrono::Duration::days(days)),
        )
    };
    sweep(true, 31).await.unwrap();
    assert_eq!(state().await, (false, false), "the P8 plant retains both");
    sweep(false, 29).await.unwrap();
    assert!(
        !state().await.1,
        "inside the ceiling, unacknowledged and readable"
    );
    sweep(false, 31).await.unwrap();
    assert_eq!(state().await, (true, true));
    assert_eq!(residue(&pool, &coordinator).await, Vec::<String>::new());
    assert_eq!(residue(&pool, ciphertext).await, Vec::<String>::new());
}

#[tokio::test]
async fn a_close_wipe_leaves_no_opening_bytes_on_either_home() {
    let db = crate::common::fresh_db::fresh_fully_migrated_db("chat_pruning_").await;
    let pool = db.connect(4).await;
    let seeded = seeded(&pool).await;
    let now = Utc::now();
    let cid = seeded.fixture.conversation_id;
    let coordinator = coordinator_ciphertext(&pool, seeded.fixture.request_id).await;
    // Expire under the P8 plant so the opening is still held when the wipe that
    // every real close runs reaches it.
    assert_eq!(
        as_service(
            true,
            expire_due_published_requests(&pool, &seeded.signer, 10)
        )
        .await
        .unwrap(),
        1
    );
    assert!(!residue(&pool, &coordinator).await.is_empty());
    let wipe = "SELECT chat.wipe_closed_conversation_operational_rows($1)";
    let wiped: bool = sqlx::query_scalar(wipe)
        .bind(cid)
        .fetch_one(&pool)
        .await
        .unwrap();
    assert!(wiped);
    assert_eq!(residue(&pool, &coordinator).await, Vec::<String>::new());

    // A transport-only home wipes once its close terminal entry is recorded.
    let ciphertext = b"a transport opening when its pair closes";
    let (transport_cid, _, _) = transport_opening(&pool, &seeded, ciphertext, now).await;
    let mut tx = pool.begin().await.unwrap();
    append_remote_close_event(
        &mut tx,
        transport_cid,
        "did:web:coordinator.example.com",
        None,
        "direct",
        2,
        &[(
            seeded.fixture.recipient_did.clone(),
            seeded.recipient_device,
        )],
        &json!({"entryId": Uuid::new_v4(), "conversationId": transport_cid, "seq": 2}),
        now,
    )
    .await
    .unwrap();
    let wiped: bool = sqlx::query_scalar(wipe)
        .bind(transport_cid)
        .fetch_one(&mut *tx)
        .await
        .unwrap();
    tx.commit().await.unwrap();
    assert!(wiped);
    assert_eq!(residue(&pool, ciphertext).await, Vec::<String>::new());
}

#[tokio::test]
async fn an_early_opening_prune_still_releases_every_charged_byte_at_the_terminal_prune() {
    let db = crate::common::fresh_db::fresh_fully_migrated_db("chat_pruning_").await;
    let pool = db.connect(4).await;
    let seeded = seeded(&pool).await;
    let (cid, request) = (seeded.fixture.conversation_id, seeded.fixture.request_id);
    // What the terminal prune releases for artifacts when nothing was pruned
    // early: every column and delivery provenance the charge counted.
    let (artifacts, opening_bytes): (i64, i64) = sqlx::query_as(
        "SELECT (octet_length(signed_publication) + octet_length(request_entry) \
                 + octet_length(final_group_info) + octet_length(full_welcome) \
                 + octet_length(initial_ciphertext) + octet_length(metadata_snapshot) \
                 + COALESCE((SELECT sum(octet_length(d.provenance)) \
                               FROM chat.direct_request_device_deliveries d \
                              WHERE d.request_id = $1), 0))::bigint, \
                (octet_length(signed_publication) + octet_length(request_entry) \
                 + octet_length(initial_ciphertext))::bigint \
           FROM chat.direct_request_publications WHERE request_id = $1",
    )
    .bind(request)
    .fetch_one(&pool)
    .await
    .unwrap();
    ack(
        &pool,
        cid,
        &seeded.fixture.recipient_did,
        seeded.recipient_device,
    )
    .await;
    ack(&pool, cid, &seeded.fixture.actor_did, seeded.actor_device).await;
    let mut tx = pool.begin().await.unwrap();
    let early = as_service(
        false,
        prune_acknowledged_application_payloads(&mut tx, cid, 0, 1, false, Utc::now()),
    )
    .await
    .unwrap();
    tx.commit().await.unwrap();
    assert_eq!(
        early,
        vec![1],
        "the opening is pruned before the request ends"
    );
    let (recorded, cleared): (Option<i64>, bool) = sqlx::query_as(
        "SELECT opening_pruned_bytes, signed_publication IS NULL AND request_entry IS NULL \
                AND initial_ciphertext IS NULL \
           FROM chat.direct_request_publications WHERE request_id = $1",
    )
    .bind(request)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!((recorded, cleared), (Some(opening_bytes), true));
    assert!(
        rejected(
            &pool,
            "UPDATE chat.direct_request_publications SET opening_pruned_bytes = 0 \
              WHERE conversation_id = $1",
            cid,
        )
        .await,
        "the recorded count never changes"
    );
    assert_eq!(
        as_service(
            false,
            expire_due_published_requests(&pool, &seeded.signer, 10)
        )
        .await
        .unwrap(),
        1
    );
    // Age the expiry past the terminal prune's 14-day horizon.
    for sql in [
        "ALTER TABLE chat.direct_request_lifecycle DISABLE TRIGGER USER",
        "UPDATE chat.direct_request_lifecycle SET expired_at = expired_at - INTERVAL '15 days'",
        "ALTER TABLE chat.direct_request_lifecycle ENABLE TRIGGER USER",
    ] {
        sqlx::query(sql).execute(&pool).await.unwrap();
    }
    let (charged, unused_reserve): (i64, i64) = sqlx::query_as(
        "SELECT c.charged_bytes, \
                GREATEST(0, r.decision_bytes + r.welcome_bytes_per_delivery * r.delivery_count \
                 - COALESCE((SELECT sum(s.charged_bytes) FROM chat.direct_request_decision_slots s \
                              WHERE s.request_id = $1), 0) \
                 - COALESCE((SELECT sum(w.charged_bytes) FROM chat.direct_request_welcome_slots w \
                              WHERE w.request_id = $1), 0))::bigint \
           FROM chat.direct_request_retained_charges c \
           JOIN chat.direct_request_lifecycle_reserves r USING (request_id) \
          WHERE c.request_id = $1",
    )
    .bind(request)
    .fetch_one(&pool)
    .await
    .unwrap();
    let retained = || async {
        sqlx::query_scalar::<_, i64>(
            "SELECT retained_bytes FROM chat.direct_request_effective_budget WHERE singleton",
        )
        .fetch_one(&pool)
        .await
        .unwrap()
    };
    let before = retained().await;
    assert_eq!(
        prune_terminal_request_artifacts(&pool, 10).await.unwrap(),
        1
    );
    let released: i64 = sqlx::query_scalar(
        "SELECT released_bytes FROM chat.direct_request_retained_releases WHERE request_id = $1",
    )
    .bind(request)
    .fetch_one(&pool)
    .await
    .unwrap();
    let expected = (artifacts + unused_reserve).min(charged);
    assert_eq!(
        released, expected,
        "the early prune's bytes are released too"
    );
    assert_eq!(before - retained().await, expected);
}

/// How much of a request's retained charge was released before its wipe.
#[derive(Clone, Copy, Debug)]
enum PriorRelease {
    Nothing,
    /// The terminal prune's own partial release.
    TerminalPrune,
    /// The cap the terminal prune applies: the whole charge.
    WholeCharge,
}

/// The wipe deletes a request's retained charge together with its release, so
/// the effective retained budget must return exactly to where it stood before
/// that request was charged, whatever share an earlier release already freed.
async fn wipe_returns_the_retained_budget_to_its_baseline(prior: PriorRelease) {
    let db = crate::common::fresh_db::fresh_fully_migrated_db("chat_pruning_").await;
    let pool = db.connect(4).await;
    let seeded = seeded(&pool).await;
    let (cid, request) = (seeded.fixture.conversation_id, seeded.fixture.request_id);
    let retained = || async {
        sqlx::query_scalar::<_, i64>(
            "SELECT retained_bytes FROM chat.direct_request_effective_budget WHERE singleton",
        )
        .fetch_one(&pool)
        .await
        .unwrap()
    };
    let charged: i64 = sqlx::query_scalar(
        "SELECT charged_bytes FROM chat.direct_request_retained_charges WHERE request_id = $1",
    )
    .bind(request)
    .fetch_one(&pool)
    .await
    .unwrap();
    let baseline = retained().await - charged;
    assert_eq!(
        as_service(
            false,
            expire_due_published_requests(&pool, &seeded.signer, 10)
        )
        .await
        .unwrap(),
        1
    );
    match prior {
        PriorRelease::Nothing => {}
        PriorRelease::TerminalPrune => {
            // Age the expiry past the terminal prune's 14-day horizon.
            for sql in [
                "ALTER TABLE chat.direct_request_lifecycle DISABLE TRIGGER USER",
                "UPDATE chat.direct_request_lifecycle SET expired_at = expired_at - INTERVAL '15 days'",
                "ALTER TABLE chat.direct_request_lifecycle ENABLE TRIGGER USER",
            ] {
                sqlx::query(sql).execute(&pool).await.unwrap();
            }
            assert_eq!(
                prune_terminal_request_artifacts(&pool, 10).await.unwrap(),
                1
            );
        }
        PriorRelease::WholeCharge => {
            sqlx::query(
                "INSERT INTO chat.direct_request_retained_releases \
                     (request_id, released_bytes, released_at, reason) \
                 VALUES ($1, $2, clock_timestamp(), 'expired_pruned')",
            )
            .bind(request)
            .bind(charged)
            .execute(&pool)
            .await
            .unwrap();
        }
    }
    let released: i64 = sqlx::query_scalar(
        "SELECT COALESCE(sum(released_bytes), 0)::bigint \
           FROM chat.direct_request_retained_releases WHERE request_id = $1",
    )
    .bind(request)
    .fetch_one(&pool)
    .await
    .unwrap();
    match prior {
        PriorRelease::Nothing => assert_eq!(released, 0),
        PriorRelease::TerminalPrune => assert!(0 < released && released < charged, "{released}"),
        PriorRelease::WholeCharge => assert_eq!(released, charged),
    }
    assert_eq!(retained().await, baseline + charged - released);
    let wiped: bool =
        sqlx::query_scalar("SELECT chat.wipe_closed_conversation_operational_rows($1)")
            .bind(cid)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert!(wiped);
    assert_eq!(
        retained().await,
        baseline,
        "{prior:?}: the wipe must return the whole {charged}-byte charge, {released} of it \
         released earlier"
    );
}

#[tokio::test]
async fn a_wipe_returns_an_unreleased_charge_to_the_retained_budget() {
    wipe_returns_the_retained_budget_to_its_baseline(PriorRelease::Nothing).await;
}

#[tokio::test]
async fn a_wipe_after_the_terminal_prune_returns_exactly_the_charge() {
    wipe_returns_the_retained_budget_to_its_baseline(PriorRelease::TerminalPrune).await;
}

#[tokio::test]
async fn a_wipe_after_a_whole_charge_release_returns_exactly_the_charge() {
    wipe_returns_the_retained_budget_to_its_baseline(PriorRelease::WholeCharge).await;
}
