//! Fast pure C2 unit tests for `reconciliation.rs` receipt and account-deletion
//! bindings (`StrictCleanRemoteEvent::try_from`, `verify_application_event_receipt`,
//! and `parse_bound_account_deletion`).

use super::*;
use crate::chat_protocol::test_support::sign_mutation_json_for_test;
use crate::federation::receipt::{AccountDeletion, I13ReceiptSigner};
use base64::{engine::general_purpose::STANDARD, Engine as _};
use chrono::{SecondsFormat, TimeZone as _, Utc};
use serde_json::{json, Value};
use uuid::Uuid;

fn c2_complete_app_event() -> RemoteEvent {
    let ciphertext = vec![1, 2, 3];
    let created_at = Utc.with_ymd_and_hms(2026, 11, 13, 12, 0, 0).unwrap();
    RemoteEvent {
        seq: 1,
        epoch: 0,
        msg_id: "msg-1".to_string(),
        message_type: CleanEntryKind::Application.type_id().to_string(),
        accepted_payload_sha256: Some(Sha256::digest(&ciphertext).to_vec()),
        ciphertext,
        padded_size: 3,
        created_at,
        entry_id: Some("00000000-0000-0000-0000-000000000001".to_string()),
        entry_kind: Some(CleanEntryKind::Application.type_id().to_string()),
        signed_request: Some(vec![1; 64]),
        outer_fingerprint: Some(vec![2; 32]),
        sequencer_receipt: Some(vec![3; 64]),
        account_deleted_entry: None,
    }
}

#[test]
fn c2_strict_clean_remote_event_account_deletion_and_receipt_bounds() {
    let created_at = Utc.with_ymd_and_hms(2026, 11, 13, 12, 0, 0).unwrap();
    let entry_id = Uuid::new_v4();
    let make_deletion = || {
        let payload = br#"{"$type":"blue.catbird.chat.defs#accountDeletedEntry"}"#.to_vec();
        RemoteEvent {
            seq: 3,
            epoch: 1,
            msg_id: entry_id.to_string(),
            message_type: CleanEntryKind::AccountDeletion.type_id().to_string(),
            accepted_payload_sha256: Some(Sha256::digest(&payload).to_vec()),
            ciphertext: payload.clone(),
            padded_size: payload.len() as i64,
            created_at,
            entry_id: Some(entry_id.to_string()),
            entry_kind: Some(CleanEntryKind::AccountDeletion.type_id().to_string()),
            signed_request: Some(payload),
            outer_fingerprint: Some(vec![0x5a; 32]),
            sequencer_receipt: None,
            account_deleted_entry: Some(
                json!({"$type": "blue.catbird.chat.defs#accountDeletedEntry"}),
            ),
        }
    };

    let strict = StrictCleanRemoteEvent::try_from(make_deletion()).unwrap();
    assert_eq!(strict.received_at(), created_at);
    assert!(strict.sequencer_receipt().is_empty());
    assert!(strict.account_deleted_entry().is_some());

    let mut with_receipt = make_deletion();
    with_receipt.sequencer_receipt = Some(vec![1]);
    assert_eq!(
        StrictCleanRemoteEvent::try_from(with_receipt),
        Err(StrictCleanRemoteEventError::UnexpectedSequencerReceipt)
    );

    let mut missing_entry = make_deletion();
    missing_entry.account_deleted_entry = None;
    assert_eq!(
        StrictCleanRemoteEvent::try_from(missing_entry),
        Err(StrictCleanRemoteEventError::MissingField(
            "accountDeletedEntry"
        ))
    );

    let mut non_object_entry = make_deletion();
    non_object_entry.account_deleted_entry = Some(json!(["not-an-object"]));
    assert_eq!(
        StrictCleanRemoteEvent::try_from(non_object_entry),
        Err(StrictCleanRemoteEventError::InvalidAccountDeletedEntry)
    );

    // Non-AccountDeletion events reject `accountDeletedEntry` and enforce `1..=1_048_576` receipt bytes.
    assert!(StrictCleanRemoteEvent::try_from(c2_complete_app_event())
        .unwrap()
        .account_deleted_entry()
        .is_none());

    let mut with_del_entry = c2_complete_app_event();
    with_del_entry.account_deleted_entry = Some(json!({}));
    assert_eq!(
        StrictCleanRemoteEvent::try_from(with_del_entry),
        Err(StrictCleanRemoteEventError::UnexpectedAccountDeletedEntry)
    );

    let mut empty_rcpt = c2_complete_app_event();
    empty_rcpt.sequencer_receipt = Some(Vec::new());
    assert_eq!(
        StrictCleanRemoteEvent::try_from(empty_rcpt),
        Err(StrictCleanRemoteEventError::InvalidSequencerReceiptLength(
            0
        ))
    );
    let mut big_rcpt = c2_complete_app_event();
    big_rcpt.sequencer_receipt = Some(vec![b'r'; 1_048_577]);
    assert_eq!(
        StrictCleanRemoteEvent::try_from(big_rcpt),
        Err(StrictCleanRemoteEventError::InvalidSequencerReceiptLength(
            1_048_577
        ))
    );
    let mut max_ok = c2_complete_app_event();
    max_ok.sequencer_receipt = Some(vec![b'r'; 1_048_576]);
    max_ok.signed_request = Some(vec![b's'; 1_048_576]);
    assert!(StrictCleanRemoteEvent::try_from(max_ok).is_ok());
}

#[test]
fn c2_verify_application_event_receipt_binds_every_field() {
    let sequencer = "did:web:seq-reconcile.example.com";
    let receipt_key = p256::ecdsa::SigningKey::from_slice(&[0x61; 32]).unwrap();
    let signer =
        I13ReceiptSigner::from_signing_key_for_test(sequencer.to_owned(), receipt_key.clone());

    let actor_key = ed25519_dalek::SigningKey::from_bytes(&[0x72; 32]);
    let actor_pub = actor_key.verifying_key().to_bytes();
    let key_id = crate::chat_protocol::validation::ed25519_key_id(&actor_pub)
        .unwrap()
        .as_str()
        .to_owned();
    let sender_did = "did:plc:abcdefghijklmnopqrstuvwx";
    let sender_device_id = Uuid::new_v4();
    let conversation_id = Uuid::new_v4();
    let message_id = Uuid::new_v4();
    let entry_id = Uuid::new_v4();
    let group_id = [0x31_u8; 32];
    let archive_commitment = [0x44_u8; 32];
    let frame_bytes = [0x99_u8; 16];
    let created_at = Utc.with_ymd_and_hms(2026, 11, 13, 15, 30, 0).unwrap();
    let signed_at = created_at.to_rfc3339_opts(SecondsFormat::Millis, true);

    let make_signed_send = |cid: Uuid, generation: u64, epoch: u64, gid: [u8; 32]| -> Vec<u8> {
        let body = json!({
            "$type": "blue.catbird.chat.defs#applicationSendBody",
            "signatureDomain": "CATBIRD-CHAT-MESSAGE\u{0000}",
            "messageId": message_id,
            "actorDid": sender_did,
            "actorDeviceId": sender_device_id,
            "keyId": key_id,
            "authGeneration": 1,
            "sendCounter": 1,
            "prior": {
                "conversationId": cid,
                "generation": generation,
                "stateVersion": 1,
                "groupId": STANDARD.encode(gid),
                "epoch": epoch,
                "groupContextHash": STANDARD.encode([0x32_u8; 32]),
                "confirmationTag": STANDARD.encode([0x33_u8; 32]),
                "lifecycle": "active",
            },
            "aad": {
                "protocolVersion": "1",
                "conversationId": STANDARD.encode(cid.as_bytes()),
                "generation": generation,
                "messageId": STANDARD.encode(message_id.as_bytes()),
                "prior": {
                    "conversationId": STANDARD.encode(cid.as_bytes()),
                    "generation": generation,
                    "stateVersion": 1,
                    "groupId": STANDARD.encode(gid),
                    "epoch": epoch,
                    "groupContextHash": STANDARD.encode([0x32_u8; 32]),
                    "confirmationTag": STANDARD.encode([0x33_u8; 32]),
                    "lifecycle": "active",
                },
                "archiveCommitment": STANDARD.encode(archive_commitment),
            },
            "applicationMessage": {
                "framing": "mlsMessage",
                "contentType": "privateMessageApplication",
                "bytes": STANDARD.encode(frame_bytes),
                "sha256": STANDARD.encode(Sha256::digest(frame_bytes)),
            },
            "blobBindings": [],
            "signedAt": signed_at,
        });
        let signed = sign_mutation_json_for_test(&body, &actor_key).unwrap();
        serde_json::to_vec(&signed).unwrap()
    };

    let signed_request = make_signed_send(conversation_id, 2, 5, group_id);
    let signed_receipt = signer
        .sign_application_receipt(
            &conversation_id.to_string(),
            &group_id,
            5,
            sender_did,
            &sender_device_id.to_string(),
            &entry_id.to_string(),
            &archive_commitment,
            9,
            created_at.timestamp_millis(),
        )
        .unwrap();
    let receipt_json = I13ReceiptSigner::receipt_wire_json(
        &signed_receipt,
        2,
        sender_did,
        &sender_device_id.to_string(),
    );

    let make_event = |sr: Vec<u8>, rcpt: &Value, seq: i64, gen: i64| -> StrictCleanRemoteEvent {
        let ciphertext = vec![1, 2, 3, 4];
        StrictCleanRemoteEvent::try_from(RemoteEvent {
            seq,
            epoch: gen,
            msg_id: message_id.to_string(),
            message_type: CleanEntryKind::Application.type_id().to_string(),
            accepted_payload_sha256: Some(Sha256::digest(&ciphertext).to_vec()),
            ciphertext,
            padded_size: 4,
            created_at,
            entry_id: Some(entry_id.to_string()),
            entry_kind: Some(CleanEntryKind::Application.type_id().to_string()),
            signed_request: Some(sr),
            outer_fingerprint: Some(vec![0x77; 32]),
            sequencer_receipt: Some(serde_json::to_vec(rcpt).unwrap()),
            account_deleted_entry: None,
        })
        .unwrap()
    };

    let valid_event = make_event(signed_request.clone(), &receipt_json, 9, 2);
    let verified = verify_application_event_receipt(
        &valid_event,
        &receipt_json,
        receipt_key.verifying_key(),
        sequencer,
        conversation_id,
    )
    .expect("exact application receipt verifies");
    // A verified receipt answers the signed send's own prior coordinate.
    let signed_value: Value = serde_json::from_slice(&signed_request).unwrap();
    assert_eq!(verified, signed_value["body"]["prior"]);
    assert_eq!(verified["generation"], 2);
    assert_eq!(verified["epoch"], 5);

    // Wrong expected sequencer or wrong conversation fails closed.
    assert!(verify_application_event_receipt(
        &valid_event,
        &receipt_json,
        receipt_key.verifying_key(),
        "did:web:other-seq.example.com",
        conversation_id,
    )
    .is_err());
    assert!(verify_application_event_receipt(
        &valid_event,
        &receipt_json,
        receipt_key.verifying_key(),
        sequencer,
        Uuid::new_v4(),
    )
    .is_err());

    // Mismatched prior generation in signedRequest fails closed.
    let wrong_prior_gen = make_event(
        make_signed_send(conversation_id, 3, 5, group_id),
        &receipt_json,
        9,
        2,
    );
    assert!(verify_application_event_receipt(
        &wrong_prior_gen,
        &receipt_json,
        receipt_key.verifying_key(),
        sequencer,
        conversation_id,
    )
    .is_err());

    // Non-ApplicationSend signed mutation (e.g. typingBody) fails closed.
    let typing_body = json!({
        "$type": "blue.catbird.chat.defs#typingBody",
        "signatureDomain": "CATBIRD-CHAT-TYPING\u{0000}",
        "typingId": Uuid::new_v4(),
        "actorDid": sender_did,
        "actorDeviceId": sender_device_id,
        "keyId": key_id,
        "authGeneration": 1,
        "coordinates": {
            "conversationId": conversation_id,
            "generation": 2,
            "stateVersion": 1,
            "groupId": STANDARD.encode(group_id),
            "epoch": 5,
            "groupContextHash": STANDARD.encode([0x32_u8; 32]),
            "confirmationTag": STANDARD.encode([0x33_u8; 32]),
            "lifecycle": "active",
        },
        "isTyping": true,
        "signedAt": signed_at,
    });
    let typing_event = make_event(
        serde_json::to_vec(&sign_mutation_json_for_test(&typing_body, &actor_key).unwrap())
            .unwrap(),
        &receipt_json,
        9,
        2,
    );
    assert!(verify_application_event_receipt(
        &typing_event,
        &receipt_json,
        receipt_key.verifying_key(),
        sequencer,
        conversation_id,
    )
    .is_err());

    // Every single receipt wire field must match independently.
    for mutate in [
        (|r: &mut Value| r["sequencerDid"] = json!("did:web:other.example.com")) as fn(&mut Value),
        |r| r["conversationId"] = json!(Uuid::new_v4()),
        |r| r["entryId"] = json!(Uuid::new_v4()),
        |r| r["seq"] = json!(10),
        |r| r["issuedAtMs"] = json!(r["issuedAtMs"].as_i64().unwrap() + 1),
        |r| r["senderDid"] = json!("did:plc:222222222222222222222222"),
        |r| r["senderDeviceId"] = json!(Uuid::new_v4()),
        |r| r["archiveCommitment"] = json!(STANDARD.encode([0x45_u8; 32])),
        |r| r["generation"] = json!(3),
        |r| r["epoch"] = json!(6),
        |r| r["groupId"] = json!(STANDARD.encode([0x39_u8; 32])),
    ] {
        let mut tampered = receipt_json.clone();
        mutate(&mut tampered);
        assert!(
            verify_application_event_receipt(
                &valid_event,
                &tampered,
                receipt_key.verifying_key(),
                sequencer,
                conversation_id,
            )
            .is_err(),
            "{tampered}"
        );
    }
}

#[test]
fn c2_parse_bound_account_deletion_binds_every_field() {
    let sequencer = "did:web:seq-del.example.com";
    let receipt_key = p256::ecdsa::SigningKey::from_slice(&[0x65; 32]).unwrap();
    let signer = I13ReceiptSigner::from_signing_key_for_test(sequencer.to_owned(), receipt_key);
    let conversation_id = Uuid::new_v4();
    let entry_id = Uuid::new_v4();
    let deleted_did = "did:plc:abcdefghijklmnopqrstuvwx";
    let deleted_at = Utc.with_ymd_and_hms(2026, 11, 13, 16, 0, 0).unwrap();

    let deletion = AccountDeletion {
        sequencer_did: sequencer.to_owned(),
        conversation_id,
        deleted_did: deleted_did.to_owned(),
        seq: 4,
        entry_id,
        deleted_at,
    };
    let authority = signer.sign_account_deletion(&deletion).unwrap();
    let entry_json = deletion.entry(&authority);
    let mut payload_json = entry_json.clone();
    payload_json["generation"] = json!(2);
    payload_json["stateVersion"] = json!(5);

    let make_strict = |payload: &Value,
                       signed_req: Vec<u8>,
                       acct_entry: Value,
                       seq: i64,
                       gen: i64,
                       eid: Uuid,
                       at: DateTime<Utc>| {
        let bytes = serde_json::to_vec(payload).unwrap();
        StrictCleanRemoteEvent::try_from(RemoteEvent {
            seq,
            epoch: gen,
            msg_id: eid.to_string(),
            message_type: CleanEntryKind::AccountDeletion.type_id().to_string(),
            accepted_payload_sha256: Some(Sha256::digest(&bytes).to_vec()),
            ciphertext: bytes,
            padded_size: 64,
            created_at: at,
            entry_id: Some(eid.to_string()),
            entry_kind: Some(CleanEntryKind::AccountDeletion.type_id().to_string()),
            signed_request: Some(signed_req),
            outer_fingerprint: Some(vec![0x88; 32]),
            sequencer_receipt: None,
            account_deleted_entry: Some(acct_entry),
        })
        .unwrap()
    };

    let payload_bytes = serde_json::to_vec(&payload_json).unwrap();
    let valid = make_strict(
        &payload_json,
        payload_bytes.clone(),
        entry_json.clone(),
        4,
        2,
        entry_id,
        deleted_at,
    );
    let (parsed, _) = parse_bound_account_deletion(&valid, sequencer, conversation_id)
        .expect("bound account deletion parses");
    assert_eq!(parsed, deletion);

    // Mismatched expected sequencer, conversation, signed_request bytes, seq, generation, entry_id, timestamp.
    assert!(
        parse_bound_account_deletion(&valid, "did:web:other.example.com", conversation_id).is_err()
    );
    assert!(parse_bound_account_deletion(&valid, sequencer, Uuid::new_v4()).is_err());

    let diff_signed_req = make_strict(
        &payload_json,
        serde_json::to_vec(&entry_json).unwrap(),
        entry_json.clone(),
        4,
        2,
        entry_id,
        deleted_at,
    );
    assert!(parse_bound_account_deletion(&diff_signed_req, sequencer, conversation_id).is_err());

    let diff_seq = make_strict(
        &payload_json,
        payload_bytes.clone(),
        entry_json.clone(),
        5,
        2,
        entry_id,
        deleted_at,
    );
    assert!(parse_bound_account_deletion(&diff_seq, sequencer, conversation_id).is_err());

    let diff_gen = make_strict(
        &payload_json,
        payload_bytes.clone(),
        entry_json.clone(),
        4,
        3,
        entry_id,
        deleted_at,
    );
    assert!(parse_bound_account_deletion(&diff_gen, sequencer, conversation_id).is_err());

    let diff_eid = make_strict(
        &payload_json,
        payload_bytes.clone(),
        entry_json.clone(),
        4,
        2,
        Uuid::new_v4(),
        deleted_at,
    );
    assert!(parse_bound_account_deletion(&diff_eid, sequencer, conversation_id).is_err());

    let diff_time = make_strict(
        &payload_json,
        payload_bytes,
        entry_json.clone(),
        4,
        2,
        entry_id,
        deleted_at + chrono::Duration::milliseconds(1),
    );
    assert!(parse_bound_account_deletion(&diff_time, sequencer, conversation_id).is_err());

    // Payload field-by-field tampering.
    for mutate in [
        (|p: &mut Value| p["$type"] = json!("blue.catbird.chat.defs#applicationEntry"))
            as fn(&mut Value),
        |p| p["conversationId"] = json!(Uuid::new_v4()),
        |p| p["entryId"] = json!(Uuid::new_v4()),
        |p| p["seq"] = json!(99),
        |p| p["generation"] = json!(99),
        |p| {
            p.as_object_mut().unwrap().remove("stateVersion");
        },
        |p| p["deletedDid"] = json!("did:plc:222222222222222222222222"),
        |p| p["sequencerDid"] = json!("did:web:other.example.com"),
        |p| p["receivedAt"] = json!("2026-11-13T16:00:00.001Z"),
    ] {
        let mut bad_payload = payload_json.clone();
        mutate(&mut bad_payload);
        let bad_bytes = serde_json::to_vec(&bad_payload).unwrap();
        let bad_event = make_strict(
            &bad_payload,
            bad_bytes,
            entry_json.clone(),
            4,
            2,
            entry_id,
            deleted_at,
        );
        assert!(
            parse_bound_account_deletion(&bad_event, sequencer, conversation_id).is_err(),
            "{bad_payload}"
        );
    }
}
