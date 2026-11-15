//! Fast pure/lazy-pool C2 unit tests for `entry_ack_relay.rs`,
//! `account_deletion_relay.rs`, and `transport_control_entry.rs` (all routed
//! through `federation::group_relay::entry_ack_relay::` first).

use super::*;
use serde_json::json;

fn c2_state(self_did: &str) -> GroupRelayState {
    let pool = sqlx::postgres::PgPoolOptions::new()
        .connect_lazy("postgres://127.0.0.1:1/c2_entry_ack_unit")
        .unwrap();
    GroupRelayState::for_test(pool, self_did.to_owned(), b"c2-secret", None)
}

#[tokio::test]
async fn c2_signing_bytes_and_pre_db_validation_for_ack_prune_and_deletion_relays() {
    let home = "did:web:home-ack.example.com";
    let seq_did = "did:web:seq-ack.example.com";
    let user = "did:plc:abcdefghijklmnopqrstuvwx";
    let cid = Uuid::new_v4();
    let dev = Uuid::new_v4();

    // 1. Domain-separated signing bytes are non-empty and sensitive to every field.
    let base_ack = EntryAckRelay {
        home_did: home.to_owned(),
        sequencer_did: seq_did.to_owned(),
        conversation_id: cid,
        generation: 1,
        user_did: user.to_owned(),
        device_id: dev,
        acked_through_seq: 5,
        signature: "sig".to_owned(),
    };
    assert!(base_ack.signing_bytes().starts_with(RELAY_SIGNING_DOMAIN));
    let mut moved_boundary = base_ack.clone();
    moved_boundary.home_did = format!("{home}x");
    moved_boundary.sequencer_did = seq_did[1..].to_owned();
    assert_ne!(base_ack.signing_bytes(), moved_boundary.signing_bytes());

    let base_notice = EntriesPrunedNotice {
        sequencer_did: seq_did.to_owned(),
        home_did: home.to_owned(),
        conversation_id: cid,
        generation: 0,
        seqs: vec![1, 3, 7],
        signature: "sig".to_owned(),
    };
    assert!(base_notice
        .signing_bytes()
        .starts_with(NOTICE_SIGNING_DOMAIN));
    let mut other_notice = base_notice.clone();
    other_notice.seqs = vec![1, 3, 8];
    assert_ne!(base_notice.signing_bytes(), other_notice.signing_bytes());

    let base_del = account_deletion_relay::AccountDeletionRelay {
        home_did: home.to_owned(),
        sequencer_did: seq_did.to_owned(),
        conversation_id: cid,
        deleted_did: user.to_owned(),
        deleted_at: "2026-11-13T12:00:00.000Z".to_owned(),
        signature: "sig".to_owned(),
    };
    assert!(base_del.signing_bytes().len() > 32);
    let mut other_del = base_del.clone();
    other_del.conversation_id = Uuid::new_v4();
    assert_ne!(base_del.signing_bytes(), other_del.signing_bytes());

    // 2. Pre-DB validation in `accept_entry_ack_relay`.
    let state = c2_state(seq_did);
    for bad in [
        EntryAckRelay {
            conversation_id: Uuid::nil(),
            ..base_ack.clone()
        },
        EntryAckRelay {
            device_id: Uuid::nil(),
            ..base_ack.clone()
        },
        EntryAckRelay {
            generation: -1,
            ..base_ack.clone()
        },
        EntryAckRelay {
            acked_through_seq: 0,
            ..base_ack.clone()
        },
        EntryAckRelay {
            user_did: "not-a-did".to_owned(),
            ..base_ack.clone()
        },
    ] {
        let resp = accept_entry_ack_relay(&state, home, &serde_json::to_vec(&bad).unwrap())
            .await
            .unwrap_err();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }
    for (caller, relay) in [
        ("did:web:wrong-caller.example.com", base_ack.clone()),
        (
            home,
            EntryAckRelay {
                sequencer_did: "did:web:wrong-seq.example.com".to_owned(),
                ..base_ack
            },
        ),
    ] {
        let resp = accept_entry_ack_relay(&state, caller, &serde_json::to_vec(&relay).unwrap())
            .await
            .unwrap_err();
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    }

    // 3. Pre-DB validation in `accept_entries_pruned_notice`.
    let home_state = c2_state(home);
    for bad in [
        EntriesPrunedNotice {
            conversation_id: Uuid::nil(),
            ..base_notice.clone()
        },
        EntriesPrunedNotice {
            generation: -1,
            ..base_notice.clone()
        },
        EntriesPrunedNotice {
            seqs: vec![],
            ..base_notice.clone()
        },
        EntriesPrunedNotice {
            seqs: vec![0, 1],
            ..base_notice.clone()
        },
        EntriesPrunedNotice {
            seqs: vec![2, 2],
            ..base_notice.clone()
        },
        EntriesPrunedNotice {
            seqs: vec![3, 2],
            ..base_notice.clone()
        },
        EntriesPrunedNotice {
            seqs: (1..=(MAX_NOTICE_SEQS as i64 + 1)).collect(),
            ..base_notice.clone()
        },
    ] {
        let resp =
            accept_entries_pruned_notice(&home_state, seq_did, &serde_json::to_vec(&bad).unwrap())
                .await
                .unwrap_err();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }
    for (caller, notice) in [
        ("did:web:wrong-seq.example.com", base_notice.clone()),
        (
            seq_did,
            EntriesPrunedNotice {
                home_did: "did:web:wrong-home.example.com".to_owned(),
                ..base_notice
            },
        ),
    ] {
        let resp = accept_entries_pruned_notice(
            &home_state,
            caller,
            &serde_json::to_vec(&notice).unwrap(),
        )
        .await
        .unwrap_err();
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    }

    // 4. Pre-DB validation in `account_deletion_relay::accept_account_deletion_relay`.
    for bad in [
        account_deletion_relay::AccountDeletionRelay {
            deleted_at: "2026-11-13T12:00:00Z".to_owned(),
            ..base_del.clone()
        },
        account_deletion_relay::AccountDeletionRelay {
            deleted_at: "2026-11-13T12:00:00.000+00:00".to_owned(),
            ..base_del.clone()
        },
        account_deletion_relay::AccountDeletionRelay {
            conversation_id: Uuid::nil(),
            ..base_del.clone()
        },
        account_deletion_relay::AccountDeletionRelay {
            deleted_did: "bad-did".to_owned(),
            ..base_del.clone()
        },
    ] {
        let resp = account_deletion_relay::accept_account_deletion_relay(
            &state,
            home,
            &serde_json::to_vec(&bad).unwrap(),
        )
        .await
        .unwrap_err();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }
    for (caller, relay) in [
        ("did:web:wrong-home.example.com", base_del.clone()),
        (
            home,
            account_deletion_relay::AccountDeletionRelay {
                sequencer_did: "did:web:wrong-seq.example.com".to_owned(),
                ..base_del
            },
        ),
    ] {
        let resp = account_deletion_relay::accept_account_deletion_relay(
            &state,
            caller,
            &serde_json::to_vec(&relay).unwrap(),
        )
        .await
        .unwrap_err();
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    }

    // 5. Pre-DB locator validation in `transport_control_entry::accept_transport_control_entry`.
    for entry in [
        json!({"conversationId": "not-uuid", "entryId": Uuid::new_v4(), "seq": 1}),
        json!({"conversationId": cid, "entryId": "not-uuid", "seq": 1}),
        json!({"conversationId": cid, "entryId": Uuid::new_v4(), "seq": 0}),
        json!({"conversationId": cid, "entryId": Uuid::new_v4(), "seq": -1}),
    ] {
        let body = serde_json::to_vec(&json!({"entry": entry})).unwrap();
        let resp =
            transport_control_entry::accept_transport_control_entry(&home_state, seq_did, &body)
                .await
                .unwrap_err();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }
}
