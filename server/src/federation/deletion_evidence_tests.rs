//! `accountDeletedEntry` deletion evidence at the homes that never sequence it:
//! a group mirror stores only its sequencer's signed entry, verbatim, and a
//! group mirror or C33 transport home serves its stored deletions to every
//! device of a current member DID and to no one else.

use super::*;
use crate::chat_protocol::read_projection::encode_canonical_generated_chat_json_v1;
use crate::chat_protocol::repository::conversation::{
    load_account_deletions, transport_home_reader,
};
use crate::federation::receipt::AccountDeletion;

const DELIVER: &str = "blue.catbird.mlsDS.deliverGroupEntry";

/// `caller`'s HMAC-authenticated `deliverGroupEntry` headers for HOME.
fn deliver_headers(caller: &str, body: &[u8]) -> HeaderMap {
    let mut headers = HeaderMap::new();
    headers.insert(S2S_CALLER_DID_HEADER, caller.parse().unwrap());
    headers.insert(S2S_TARGET_DID_HEADER, HOME.parse().unwrap());
    headers.insert(
        S2S_MAC_HEADER,
        compute_s2s_mac(HMAC.as_bytes(), caller, HOME, DELIVER, body)
            .parse()
            .unwrap(),
    );
    headers
}

/// The canonical `#accountDeletedEntry` ref form of a union `entry`, without `$type`.
fn evidence(mut entry: Value) -> Vec<u8> {
    entry.as_object_mut().unwrap().remove("$type");
    encode_canonical_generated_chat_json_v1(&entry, "blue.catbird.chat.defs#accountDeletedEntry")
        .unwrap()
        .bytes()
        .to_vec()
}

async fn served(pool: &DbPool, conversation_id: Uuid) -> Vec<Vec<u8>> {
    let mut tx = pool.begin().await.unwrap();
    let deletions = load_account_deletions(&mut tx, conversation_id)
        .await
        .unwrap()
        .iter()
        .map(|entry| {
            encode_canonical_generated_chat_json_v1(
                entry,
                "blue.catbird.chat.defs#accountDeletedEntry",
            )
            .unwrap()
            .bytes()
            .to_vec()
        })
        .collect();
    tx.rollback().await.unwrap();
    deletions
}

#[tokio::test]
async fn a_group_mirror_stores_only_its_sequencers_signed_account_deletion_verbatim() {
    crate::federation::open_federation_for_test();
    let db = fresh_fully_migrated_db("chat_fed_relay_").await;
    let pool = db.connect(4).await;
    prepare(&pool).await;
    let mirror = seed_remote_clean_slate_application_fixture(&pool, HOME, SEQ, None)
        .await
        .unwrap();
    let cid = mirror.conversation_id;
    let (seq_key, home_key, other_key, receipt_key) = (key(0x31), key(0x32), key(0x33), key(0x34));
    let network = Network::new(&[(SEQ, &seq_key), (HOME, &home_key), (OTHER, &other_key)]);
    // SEQ publishes its dedicated receipt key beside its service key.
    network
        .documents
        .lock()
        .unwrap()
        .get_mut(host(SEQ))
        .unwrap()["verificationMethod"]
        .as_array_mut()
        .unwrap()
        .push(json!({
            "id": format!("{SEQ}#mls-receipt-1"),
            "type": "Multikey",
            "controller": SEQ,
            "publicKeyMultibase":
                crate::identity::did_doc::encode_p256_multikey(receipt_key.verifying_key()),
        }));
    let home_hooks = hooks(HOME, Some(&home_key), true, &network);
    let state = GroupRelayState::for_test(pool.clone(), HOME.to_owned(), HMAC.as_bytes(), None)
        .with_sim_hooks(Arc::clone(&home_hooks))
        .with_clock(manual_clock());
    let deletion = AccountDeletion {
        sequencer_did: SEQ.to_owned(),
        conversation_id: cid,
        deleted_did: mirror.sender_did.clone(),
        seq: 9,
        entry_id: Uuid::new_v4(),
        deleted_at: DateTime::from_timestamp_millis(Utc::now().timestamp_millis()).unwrap(),
        evidence: None,
    };
    let sign = |key: &SigningKey, sequencer: &str, deletion: &AccountDeletion| {
        I13ReceiptSigner::new(key.clone(), sequencer.to_owned())
            .sign_account_deletion(deletion)
            .unwrap()
    };
    let genuine = deletion.entry(&sign(&receipt_key, SEQ, &deletion));
    let deliver = |caller: &'static str, entry: Value| {
        let body = serde_json::to_vec(&DeliverGroupEntryRequest {
            conversation_id: cid,
            generation: 0,
            space_uri: format!("at://{SEQ}/space/blue.catbird.labyrinth.conversation/{cid}-0"),
            recipient_dids: vec![mirror.recipient_did.clone()],
            recipient_devices: vec![(mirror.recipient_did.clone(), mirror.recipient_device_id)],
            entry,
            close_authority: None,
        })
        .unwrap();
        scope_sim_ds(
            Arc::clone(&home_hooks),
            handle_deliver_group_entry(
                State(state.clone()),
                deliver_headers(caller, &body),
                Bytes::from(body),
            ),
        )
    };
    let stored = || async {
        sqlx::query_scalar::<_, Vec<u8>>(
            "SELECT entry_bytes FROM chat.direct_request_transport_entries \
              WHERE conversation_id = $1 AND seq = 9",
        )
        .bind(cid)
        .fetch_optional(&pool)
        .await
        .unwrap()
    };

    let mut tampered = genuine.clone();
    tampered["deletedDid"] = json!(mirror.recipient_did);
    let mut unsigned = genuine.clone();
    unsigned
        .as_object_mut()
        .unwrap()
        .remove("sequencerAuthority");
    let mut foreign = deletion.clone();
    foreign.sequencer_did = OTHER.to_owned();
    let cases = [
        // Signed with a key SEQ does not publish as its receipt key.
        (SEQ, deletion.entry(&sign(&other_key, SEQ, &deletion))),
        // Signed with SEQ's service-auth key, never a receipt key.
        (SEQ, deletion.entry(&sign(&seq_key, SEQ, &deletion))),
        // A signed field altered after signing.
        (SEQ, tampered),
        // No authority at all.
        (SEQ, unsigned),
        // Another DS's genuine deletion, relayed by the sequencer.
        (SEQ, foreign.entry(&sign(&other_key, OTHER, &foreign))),
        // The sequencer's genuine deletion, delivered by another DS.
        (OTHER, genuine.clone()),
    ];
    for (caller, entry) in cases {
        let response = deliver(caller, entry.clone()).await;
        let status = response.status();
        let body: Value = serde_json::from_slice(
            &axum::body::to_bytes(response.into_body(), 1 << 16)
                .await
                .unwrap(),
        )
        .unwrap();
        assert_eq!(
            (status, body["error"].as_str()),
            (StatusCode::FORBIDDEN, Some("NotAuthorized")),
            "{caller}: {entry}: {body}"
        );
        assert_eq!(stored().await, None, "a refused deletion stores nothing");
    }

    let response = deliver(SEQ, genuine.clone()).await;
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        stored().await,
        Some(serde_json::to_vec(&genuine).unwrap()),
        "stored verbatim"
    );
    assert_eq!(served(&pool, cid).await, [evidence(genuine)]);
}

/// A group mirror receives SEQ's deletion carrying the deleting device's signed
/// write, padded to `pad_to` bytes, and a `key_proof_len`-byte key proof through
/// `deliverGroupEntry`, stores it verbatim and serves exactly that evidence.
async fn mirror_serves_device_evidence(pad_to: usize, key_proof_len: usize) {
    crate::federation::open_federation_for_test();
    let db = fresh_fully_migrated_db("chat_fed_relay_").await;
    let pool = db.connect(4).await;
    prepare(&pool).await;
    let mirror = seed_remote_clean_slate_application_fixture(&pool, HOME, SEQ, None)
        .await
        .unwrap();
    let cid = mirror.conversation_id;
    let (seq_key, home_key, receipt_key) = (key(0x51), key(0x52), key(0x54));
    let network = Network::new(&[(SEQ, &seq_key), (HOME, &home_key)]);
    network
        .documents
        .lock()
        .unwrap()
        .get_mut(host(SEQ))
        .unwrap()["verificationMethod"]
        .as_array_mut()
        .unwrap()
        .push(json!({
            "id": format!("{SEQ}#mls-receipt-1"),
            "type": "Multikey",
            "controller": SEQ,
            "publicKeyMultibase":
                crate::identity::did_doc::encode_p256_multikey(receipt_key.verifying_key()),
        }));
    let home_hooks = hooks(HOME, Some(&home_key), true, &network);
    let state = GroupRelayState::for_test(pool.clone(), HOME.to_owned(), HMAC.as_bytes(), None)
        .with_sim_hooks(Arc::clone(&home_hooks))
        .with_clock(manual_clock());
    let deleted_at = DateTime::from_timestamp_millis(Utc::now().timestamp_millis()).unwrap();
    let device_evidence = crate::federation::receipt::AccountDeletionEvidence::signed_for_test(
        &ed25519_dalek::SigningKey::from_bytes(&mirror.sender_ed25519_seed),
        mirror.sender_device_id,
        [0x4D; 16],
        deleted_at,
        pad_to,
        Some(vec![0xE7; key_proof_len]),
    )
    .with_revocation_proof(Some(vec![0xE8; key_proof_len]));
    let deletion = AccountDeletion {
        sequencer_did: SEQ.to_owned(),
        conversation_id: cid,
        deleted_did: mirror.sender_did.clone(),
        seq: 9,
        entry_id: Uuid::new_v4(),
        deleted_at,
        evidence: Some(device_evidence.clone()),
    };
    let genuine = deletion.entry(
        &I13ReceiptSigner::new(receipt_key.clone(), SEQ.to_owned())
            .sign_account_deletion(&deletion)
            .unwrap(),
    );
    let body = serde_json::to_vec(&DeliverGroupEntryRequest {
        conversation_id: cid,
        generation: 0,
        space_uri: format!("at://{SEQ}/space/blue.catbird.labyrinth.conversation/{cid}-0"),
        recipient_dids: vec![mirror.recipient_did.clone()],
        recipient_devices: vec![(mirror.recipient_did.clone(), mirror.recipient_device_id)],
        entry: genuine.clone(),
        close_authority: None,
    })
    .unwrap();
    let response = scope_sim_ds(
        Arc::clone(&home_hooks),
        handle_deliver_group_entry(
            State(state.clone()),
            deliver_headers(SEQ, &body),
            Bytes::from(body),
        ),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    let stored: Vec<u8> = sqlx::query_scalar(
        "SELECT entry_bytes FROM chat.direct_request_transport_entries \
          WHERE conversation_id = $1 AND seq = 9",
    )
    .bind(cid)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(
        stored,
        serde_json::to_vec(&genuine).unwrap(),
        "stored verbatim"
    );
    assert_eq!(served(&pool, cid).await, [evidence(genuine)]);
    let mut tx = pool.begin().await.unwrap();
    let loaded = load_account_deletions(&mut tx, cid).await.unwrap();
    tx.rollback().await.unwrap();
    let mut union_entry = serde_json::to_value(&loaded[0]).unwrap();
    union_entry["$type"] = json!("blue.catbird.chat.defs#accountDeletedEntry");
    assert_eq!(
        AccountDeletion::from_entry(&union_entry)
            .unwrap()
            .0
            .evidence,
        Some(device_evidence),
        "served byte for byte"
    );
}

#[tokio::test]
async fn a_group_mirror_serves_the_deleting_devices_signed_write_and_key_proof_verbatim() {
    mirror_serves_device_evidence(0, 512).await;
}

/// The largest deletion the lexicon admits, a 1024-byte writeBody and a
/// 16384-byte keyProof, is replicated and served like any other.
#[tokio::test]
async fn a_group_mirror_serves_a_maximum_size_account_deletion() {
    mirror_serves_device_evidence(
        crate::federation::receipt::ACTOR_WRITE_BODY_MAX_BYTES,
        crate::federation::receipt::KEY_PROOF_MAX_BYTES,
    )
    .await;
}

/// MLS-R3-02: SEQ rotated its receipt key to `#mls-receipt-2` and retains `#1`.
/// The home verifies a new `#2` deletion and an archived `#1` one against SEQ's
/// published history, never requiring the archived method to be current; a key
/// signing under the other method's `kid` is refused and stores nothing.
#[tokio::test]
async fn a_group_mirror_verifies_new_and_archived_deletions_after_a_key_rotation() {
    crate::federation::open_federation_for_test();
    let db = fresh_fully_migrated_db("chat_fed_relay_").await;
    let pool = db.connect(4).await;
    prepare(&pool).await;
    let mirror = seed_remote_clean_slate_application_fixture(&pool, HOME, SEQ, None)
        .await
        .unwrap();
    let cid = mirror.conversation_id;
    let (seq_key, home_key, first, second) = (key(0x41), key(0x42), key(0x43), key(0x44));
    let network = Network::new(&[(SEQ, &seq_key), (HOME, &home_key)]);
    for (generation, receipt_key) in [(1, &first), (2, &second)] {
        network
            .documents
            .lock()
            .unwrap()
            .get_mut(host(SEQ))
            .unwrap()["verificationMethod"]
            .as_array_mut()
            .unwrap()
            .push(json!({
                "id": format!("{SEQ}#mls-receipt-{generation}"),
                "type": "Multikey",
                "controller": SEQ,
                "publicKeyMultibase":
                    crate::identity::did_doc::encode_p256_multikey(receipt_key.verifying_key()),
            }));
    }
    let home_hooks = hooks(HOME, Some(&home_key), true, &network);
    let state = GroupRelayState::for_test(pool.clone(), HOME.to_owned(), HMAC.as_bytes(), None)
        .with_sim_hooks(Arc::clone(&home_hooks))
        .with_clock(manual_clock());
    let deletion = |seq: i64, deleted_did: &str| AccountDeletion {
        sequencer_did: SEQ.to_owned(),
        conversation_id: cid,
        deleted_did: deleted_did.to_owned(),
        seq,
        entry_id: Uuid::new_v4(),
        deleted_at: DateTime::from_timestamp_millis(Utc::now().timestamp_millis()).unwrap(),
        evidence: None,
    };
    let sign = |deletion: &AccountDeletion, generation: u8, receipt_key: &SigningKey| {
        let signer = I13ReceiptSigner::new_with_key_id(
            receipt_key.clone(),
            SEQ.to_owned(),
            format!("{SEQ}#mls-receipt-{generation}"),
        )
        .unwrap();
        deletion.entry(&signer.sign_account_deletion(deletion).unwrap())
    };
    let deliver = |entry: Value| {
        let body = serde_json::to_vec(&DeliverGroupEntryRequest {
            conversation_id: cid,
            generation: 0,
            space_uri: format!("at://{SEQ}/space/blue.catbird.labyrinth.conversation/{cid}-0"),
            recipient_dids: vec![mirror.recipient_did.clone()],
            recipient_devices: vec![(mirror.recipient_did.clone(), mirror.recipient_device_id)],
            entry,
            close_authority: None,
        })
        .unwrap();
        scope_sim_ds(
            Arc::clone(&home_hooks),
            handle_deliver_group_entry(
                State(state.clone()),
                deliver_headers(SEQ, &body),
                Bytes::from(body),
            ),
        )
    };

    let (current, archived) = (
        deletion(9, &mirror.sender_did),
        deletion(10, &mirror.recipient_did),
    );
    for crossed in [sign(&current, 2, &first), sign(&archived, 1, &second)] {
        let response = deliver(crossed.clone()).await;
        assert_eq!(response.status(), StatusCode::FORBIDDEN, "{crossed}");
        assert!(served(&pool, cid).await.is_empty(), "{crossed}");
    }
    let (new_proof, archived_proof) = (sign(&current, 2, &second), sign(&archived, 1, &first));
    for proof in [&new_proof, &archived_proof] {
        let response = deliver(proof.clone()).await;
        assert_eq!(response.status(), StatusCode::OK, "{proof}");
    }
    assert_eq!(
        served(&pool, cid).await,
        [evidence(new_proof), evidence(archived_proof)]
    );
}

#[tokio::test]
async fn a_c33_transport_home_serves_its_pairs_deletions_to_every_recipient_device_only() {
    let db = fresh_fully_migrated_db("chat_fed_relay_").await;
    let pool = db.connect(4).await;
    prepare(&pool).await;
    const RECIPIENT: &str = "did:web:c33-recipient.example.com";
    const SENDER: &str = "did:web:c33-sender.example.com";
    let (device, fresh, sender_device) = (Uuid::new_v4(), Uuid::new_v4(), Uuid::new_v4());
    let (accepted, pending) = (Uuid::new_v4(), Uuid::new_v4());
    let opening = b"c33-deletion-evidence-fixture";
    for (conversation_id, status) in [(accepted, "accepted"), (pending, "pending")] {
        sqlx::query(
            "INSERT INTO chat.direct_request_transport_inbox(request_id,conversation_id, \
                 first_message_id,coordinator_did,sender_did,sender_device_id,recipient_did, \
                 recipient_device_id,request_entry,signed_publication,full_welcome, \
                 full_welcome_sha256,provenance,publication_receipt,import_until,status) \
             VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$9,$9,$10,$9,$9,$11,$12)",
        )
        .bind(Uuid::new_v4())
        .bind(conversation_id)
        .bind(Uuid::new_v4())
        .bind(C33_SEQ)
        .bind(SENDER)
        .bind(sender_device)
        .bind(RECIPIENT)
        .bind(device)
        .bind(opening.as_slice())
        .bind(Sha256::digest(opening).as_slice())
        .bind(Utc::now() + chrono::Duration::days(1))
        .bind(status)
        .execute(&pool)
        .await
        .unwrap();
    }

    let reader = |conversation_id: Uuid, did: &'static str, device_id: Uuid| {
        let pool = pool.clone();
        async move {
            let mut tx = pool.begin().await.unwrap();
            let reader = transport_home_reader(&mut tx, conversation_id, did, device_id)
                .await
                .unwrap();
            tx.rollback().await.unwrap();
            reader
        }
    };
    // The recipient's own device reads its row; a fresh device of the same DID,
    // with no row of its own, reads the accepted pair's row. Both are members.
    assert_eq!(
        reader(accepted, RECIPIENT, device).await,
        Some((device, true))
    );
    assert_eq!(
        reader(accepted, RECIPIENT, fresh).await,
        Some((device, true))
    );
    // An invitation not yet accepted makes no member: its own device still
    // reads its state, a fresh device reads nothing.
    assert_eq!(
        reader(pending, RECIPIENT, device).await,
        Some((device, false))
    );
    assert_eq!(reader(pending, RECIPIENT, fresh).await, None);
    // No other DID reads anything.
    for (did, device_id) in [(SENDER, sender_device), (OTHER, fresh)] {
        assert_eq!(reader(accepted, did, device_id).await, None);
    }

    // The home serves exactly the coordinator's stored signed deletion: never a
    // control entry that merely mentions the kind; ciphertext-sized rows go unread.
    let signer = I13ReceiptSigner::new(key(0x41), C33_SEQ.to_owned());
    let deletion = AccountDeletion {
        sequencer_did: C33_SEQ.to_owned(),
        conversation_id: accepted,
        deleted_did: SENDER.to_owned(),
        seq: 3,
        entry_id: Uuid::new_v4(),
        deleted_at: DateTime::from_timestamp_millis(Utc::now().timestamp_millis()).unwrap(),
        evidence: None,
    };
    let genuine = deletion.entry(&signer.sign_account_deletion(&deletion).unwrap());
    let mention = json!({
        "$type": "blue.catbird.chat.defs#commitEntry",
        "conversationId": accepted,
        "entryId": Uuid::new_v4(),
        "seq": 2,
        "note": ACCOUNT_DELETED,
    });
    let mut oversized = mention.clone();
    oversized["seq"] = json!(1);
    oversized["padding"] = json!("x".repeat(5000));
    for entry in [&oversized, &mention, &genuine] {
        crate::chat_protocol::repository::delivery::insert_transport_entry(
            &mut pool.acquire().await.unwrap(),
            accepted,
            entry["seq"].as_i64().unwrap(),
            Uuid::parse_str(entry["entryId"].as_str().unwrap()).unwrap(),
            &serde_json::to_vec(entry).unwrap(),
            Utc::now(),
        )
        .await
        .unwrap();
    }
    assert_eq!(served(&pool, accepted).await, [evidence(genuine)]);
    assert!(served(&pool, pending).await.is_empty());
}
