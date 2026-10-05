//! Labyrinth backend: the personal mailbox, write idempotency, quotas and
//! the immutability of stored rows (labyrinth `docs/MLSDS_BACKEND.md` §2
//! "Mailbox", §3, §4).

mod common;

#[path = "common/labyrinth_harness.rs"]
mod harness;

use harness::*;
use serde_json::json;

#[tokio::test]
async fn devices_create_read_list_and_revoke_once() {
    let env = Env::new().await;
    let alice = env.account().await;
    let other_device = env.device_for(&alice.did, random_seed()).await;

    let created = alice
        .call(
            "createDevice",
            &json!({ "record": alice.device_record([1; 32]) }),
        )
        .await;
    assert_eq!(created.ok()["rkey"], hex::encode([1u8; 32]));
    // A second bound device keeps alice able to revoke after [1] is revoked.
    alice.enroll([2; 32]).await;
    // Any current chat device of the DID reads the same mailbox.
    let got = other_device
        .query("getDevice", &[("deviceKeyPubkey", hex::encode([1u8; 32]))])
        .await;
    assert_eq!(got.ok()["record"], alice.device_record([1; 32]));
    alice
        .call(
            "createDevice",
            &json!({ "record": alice.device_record([1; 32]) }),
        )
        .await
        .fails(409, "RecordAlreadyExists");
    alice
        .query("getDevice", &[("deviceKeyPubkey", hex::encode([6u8; 32]))])
        .await
        .fails(404, "DeviceNotFound");

    // Another DID's mailbox is separate.
    let bob = env.account().await;
    bob.query("getDevice", &[("deviceKeyPubkey", hex::encode([1u8; 32]))])
        .await
        .fails(404, "DeviceNotFound");

    let revoke = |at: &str| json!({ "deviceKeyPubkey": b(&[1; 32]), "revokedAt": at });
    alice
        .call("markDeviceRevoked", &revoke("2026-10-04T13:00:00.000Z"))
        .await
        .ok();
    // Set once: a later revocation time is ignored.
    alice
        .call("markDeviceRevoked", &revoke("2026-10-05T13:00:00.000Z"))
        .await
        .ok();
    let got = alice
        .query("getDevice", &[("deviceKeyPubkey", hex::encode([1u8; 32]))])
        .await;
    assert_eq!(got.ok()["record"]["revokedAt"], "2026-10-04T13:00:00.000Z");
    alice
        .call(
            "markDeviceRevoked",
            &json!({ "deviceKeyPubkey": b(&[9; 32]), "revokedAt": "2026-10-04T13:00:00.000Z" }),
        )
        .await
        .fails(404, "DeviceNotFound");

    for k in 3..5u8 {
        alice.enroll([k; 32]).await;
    }
    let page = alice.query("listDevices", &[("limit", "3".into())]).await;
    assert_eq!(page.ok()["items"].as_array().unwrap().len(), 3);
    let cursor = page.json["cursor"].as_str().unwrap().to_owned();
    let rest = alice.query("listDevices", &[("cursor", cursor)]).await;
    assert_eq!(rest.ok()["items"].as_array().unwrap().len(), 1);
}

#[tokio::test]
async fn records_are_validated_against_the_lexicon() {
    let env = Env::new().await;
    let alice = env.account().await;
    let mut short_key = alice.device_record([1; 32]);
    short_key["deviceKeyPubkey"] = b(&[1; 31]);
    let mut wrong_type = alice.device_record([1; 32]);
    wrong_type["$type"] = json!("blue.catbird.labyrinth.epoch");
    let mut extra = alice.device_record([1; 32]);
    extra["surprise"] = json!(true);
    for record in [short_key, wrong_type, extra] {
        alice
            .call("createDevice", &json!({ "record": record }))
            .await
            .fails(400, "InvalidRequest");
    }
}

#[tokio::test]
async fn procedure_retries_replay_the_exact_response_and_reject_reuse() {
    let env = Env::new().await;
    let alice = env.account().await;
    let op = [0x42; 16];
    let input = json!({ "record": owner_batch_record("thread-a", &[10, 20]) });
    let first = alice.call_op("appendOwnerBatch", &input, op).await;
    first.ok();
    let again = alice.call_op("appendOwnerBatch", &input, op).await;
    assert_eq!(again.bytes, first.bytes, "replay must be byte-identical");
    // Exactly one batch was written.
    let listed = alice
        .query("listOwnerBatches", &[("threadId", "thread-a".into())])
        .await;
    assert_eq!(listed.ok()["items"].as_array().unwrap().len(), 1);
    // The same operation id with another payload is refused.
    let other = json!({ "record": owner_batch_record("thread-a", &[30]) });
    alice
        .call_op("appendOwnerBatch", &other, op)
        .await
        .fails(409, "IdempotencyConflict");
    // A new operation on an existing rkey is RecordAlreadyExists.
    alice
        .call(
            "createDevice",
            &json!({ "record": alice.device_record([5; 32]) }),
        )
        .await
        .ok();
    alice
        .call(
            "createDevice",
            &json!({ "record": alice.device_record([5; 32]) }),
        )
        .await
        .fails(409, "RecordAlreadyExists");
}

#[tokio::test]
async fn epochs_are_created_with_members_and_their_directory_head() {
    let env = Env::new().await;
    let v = vectors();
    let d0 = env.device_for(&v.did, v.seeds[0]).await;
    let d1 = env.device_for(&v.did, v.seeds[1]).await;
    d0.enroll([0xD0; 32]).await;
    d1.enroll([0xD1; 32]).await;
    d0.enroll([0xD2; 32]).await;

    let input = json!({
        "epoch": epoch_record(&v.chain[0], [0xD0; 32]),
        "members": [member_record(0, [0xD0; 32]), member_record(0, [0xD1; 32])],
    });
    let created = d0.call("createEpoch", &input).await;
    assert_eq!(created.ok()["epochNumber"], 0);
    let epoch_id = created.json["epochId"].as_str().unwrap().to_owned();
    assert!(
        epoch_id.parse::<i64>().is_ok(),
        "epochId is a decimal bigserial"
    );

    // createEpoch recorded the head in the directory (design §1a).
    let head = d0.query("getEpochHead", &[("did", v.did.clone())]).await;
    assert_eq!(head.ok()["epoch"], v.chain[0]);

    let got = d0.query("getEpoch", &[("epochNumber", "0".into())]).await;
    assert_eq!(got.ok()["epochId"], epoch_id);
    assert_eq!(got.json["record"], epoch_record(&v.chain[0], [0xD0; 32]));
    let members = d0
        .query("listEpochMembers", &[("epochNumber", "0".into())])
        .await;
    assert_eq!(members.ok()["items"].as_array().unwrap().len(), 2);
    d0.query("listEpochMembers", &[("epochNumber", "1".into())])
        .await
        .fails(404, "EpochNotFound");

    // A member added mid-epoch; duplicates and unknown epochs refused.
    d0.call(
        "createEpochMember",
        &json!({ "record": member_record(0, [0xD2; 32]) }),
    )
    .await
    .ok();
    d0.call(
        "createEpochMember",
        &json!({ "record": member_record(0, [0xD2; 32]) }),
    )
    .await
    .fails(409, "RecordAlreadyExists");
    d0.call(
        "createEpochMember",
        &json!({ "record": member_record(3, [0xD2; 32]) }),
    )
    .await
    .fails(404, "EpochNotFound");

    // The next epoch extends the chain; a number already taken is refused.
    d0.call(
        "createEpoch",
        &json!({ "epoch": epoch_record(&v.chain[1], [0xD0; 32]), "members": [] }),
    )
    .await
    .ok();
    d0.call(
        "createEpoch",
        &json!({ "epoch": epoch_record(&v.fork, [0xD0; 32]), "members": [] }),
    )
    .await
    .fails(409, "RecordAlreadyExists");
    // A renumbered epoch no longer recomputes its head.
    let mut gap = v.chain[2].clone();
    gap["epochNumber"] = json!(3);
    d0.call(
        "createEpoch",
        &json!({ "epoch": epoch_record(&gap, [0xD0; 32]), "members": [] }),
    )
    .await
    .fails(400, "InvalidRequest");
    let listed = d0.query("listEpochs", &[]).await;
    let numbers: Vec<_> = listed.ok()["items"]
        .as_array()
        .unwrap()
        .iter()
        .map(|e| e["record"]["public"]["epochNumber"].as_u64().unwrap())
        .collect();
    assert_eq!(numbers, vec![0, 1]);
}

#[tokio::test]
async fn concurrent_create_epoch_for_one_number_admits_exactly_one() {
    let env = Env::new().await;
    let v = vectors();
    let d0 = env.device_for(&v.did, v.seeds[0]).await;
    let d1 = env.device_for(&v.did, v.seeds[1]).await;
    d0.enroll([0xD0; 32]).await;
    d1.enroll([0xD1; 32]).await;
    d0.call(
        "createEpoch",
        &json!({ "epoch": epoch_record(&v.chain[0], [0xD0; 32]), "members": [] }),
    )
    .await
    .ok();
    let a = json!({ "epoch": epoch_record(&v.chain[1], [0xD0; 32]), "members": [] });
    let b_input = json!({ "epoch": epoch_record(&v.fork, [0xD1; 32]), "members": [] });
    let (ra, rb) = tokio::join!(d0.call("createEpoch", &a), d1.call("createEpoch", &b_input));
    let outcomes = [ra.status.as_u16(), rb.status.as_u16()];
    assert!(
        outcomes.contains(&200),
        "{outcomes:?}: {} / {}",
        ra.json,
        rb.json
    );
    let loser = if ra.status.as_u16() == 200 { &rb } else { &ra };
    loser.fails(409, "RecordAlreadyExists");
}

#[tokio::test]
async fn virtual_devices_register_member_and_orf_state_atomically() {
    let env = Env::new().await;
    let v = vectors();
    let d0 = env.device_for(&v.did, v.seeds[0]).await;
    d0.enroll([0xD0; 32]).await;
    d0.call(
        "createDevice",
        &json!({ "record": virtual_device_record([0xBB; 32]) }),
    )
    .await
    .ok();
    d0.call(
        "createEpoch",
        &json!({ "epoch": epoch_record(&v.chain[0], [0xD0; 32]), "members": [] }),
    )
    .await
    .ok();
    d0.call(
        "registerOrfState",
        &json!({ "deviceKeyPubkey": b(&[0xD0; 32]) }),
    )
    .await
    .ok();
    let input = json!({
        "record": vdevice_record([0xAA; 16], [0xBB; 32]),
        "member": member_record(0, [0xBB; 32]),
        "orf": { "deviceKeyPubkey": b(&[0xD0; 32]), "evolveToken": b(&scalar_token(5)) },
    });
    d0.call("createVirtualDevice", &input).await.ok();
    let got = d0
        .query(
            "getVirtualDevice",
            &[("vdeviceId", hex::encode([0xAAu8; 16]))],
        )
        .await;
    // The server projects its lastUsedAt stamp (J2) into the record.
    let mut record = got.ok()["record"].clone();
    assert!(record["lastUsedAt"].as_str().unwrap().ends_with('Z'));
    record.as_object_mut().unwrap().remove("lastUsedAt");
    assert_eq!(record, vdevice_record([0xAA; 16], [0xBB; 32]));
    // The evolved ORF state exists: registering it again conflicts.
    d0.call(
        "registerOrfState",
        &json!({ "deviceKeyPubkey": b(&[0xBB; 32]) }),
    )
    .await
    .fails(409, "RecordAlreadyExists");
    let members = d0
        .query("listEpochMembers", &[("epochNumber", "0".into())])
        .await;
    assert_eq!(members.ok()["items"].as_array().unwrap().len(), 1);

    // Atomic: a failing ORF parent leaves no virtual device behind.
    let failing = json!({
        "record": vdevice_record([0xAC; 16], [0xBC; 32]),
        "orf": { "deviceKeyPubkey": b(&[0x99; 32]), "evolveToken": b(&scalar_token(5)) },
    });
    d0.call("createVirtualDevice", &failing)
        .await
        .fails(404, "OrfStateNotFound");
    d0.query(
        "getVirtualDevice",
        &[("vdeviceId", hex::encode([0xACu8; 16]))],
    )
    .await
    .fails(404, "VirtualDeviceNotFound");
    let listed = d0.query("listVirtualDevices", &[]).await;
    assert_eq!(listed.ok()["items"].as_array().unwrap().len(), 1);
}

/// A canonical scalar `n` (little-endian), usable as an evolve token.
pub fn scalar_token(n: u8) -> [u8; 32] {
    let mut t = [0u8; 32];
    t[0] = n;
    t
}

#[tokio::test]
async fn owner_batches_are_stamped_in_order_and_filtered_by_time() {
    let env = Env::new().await;
    let alice = env.account().await;
    let mut seqs = Vec::new();
    for (i, ts) in [[100u64, 150], [200, 250], [300, 350]].iter().enumerate() {
        let thread = if i == 1 { "thread-b" } else { "thread-a" };
        let reply = alice
            .call(
                "appendOwnerBatch",
                &json!({ "record": owner_batch_record(thread, ts) }),
            )
            .await;
        let order = &reply.ok()["order"];
        assert!(
            order.get("chatSeq").is_none(),
            "owner batches carry no chatSeq"
        );
        assert!(order["receivedAt"].as_str().unwrap().ends_with('Z'));
        assert_eq!(reply.json["rkey"].as_str().unwrap().len(), 13);
        seqs.push(order["seq"].as_i64().unwrap());
    }
    assert_eq!(seqs, vec![1, 2, 3], "per-mailbox seq");

    let list = |params: Vec<(&'static str, String)>| {
        let alice = alice.clone();
        async move {
            let mut p = vec![("threadId", "thread-a".to_owned())];
            p.extend(params);
            alice.query("listOwnerBatches", &p).await
        }
    };
    let all = list(vec![]).await;
    let seqs: Vec<_> = all.ok()["items"]
        .as_array()
        .unwrap()
        .iter()
        .map(|i| i["order"]["seq"].as_i64().unwrap())
        .collect();
    assert_eq!(seqs, vec![1, 3]);
    // An item must fall in [fromMs, untilMs).
    let window = list(vec![("fromMs", "151".into()), ("untilMs", "301".into())]).await;
    let items = window.ok()["items"].as_array().unwrap();
    assert_eq!(items.len(), 1);
    assert_eq!(items[0]["order"]["seq"], 3);
    let none = list(vec![("fromMs", "151".into()), ("untilMs", "300".into())]).await;
    assert!(none.ok()["items"].as_array().unwrap().is_empty());
}

#[tokio::test]
async fn mailbox_and_virtual_device_quotas_are_enforced() {
    let env = Env::new().await;
    let alice = env.account().await;
    alice
        .call(
            "createDevice",
            &json!({ "record": alice.device_record([1; 32]) }),
        )
        .await
        .ok();
    // Fill the mailbox to just under 256 MiB through the counter column the
    // immutability trigger leaves writable.
    sqlx::query("UPDATE labyrinth.mailboxes SET bytes_used = 268435456 - 10 WHERE owner_did = $1")
        .bind(&alice.did)
        .execute(&env.pool)
        .await
        .unwrap();
    alice
        .call(
            "createDevice",
            &json!({ "record": alice.device_record([2; 32]) }),
        )
        .await
        .fails(400, "QuotaExceeded");

    sqlx::query(
        "UPDATE labyrinth.mailboxes SET bytes_used = 0, vdevice_count = 64 WHERE owner_did = $1",
    )
    .bind(&alice.did)
    .execute(&env.pool)
    .await
    .unwrap();
    alice
        .call(
            "createVirtualDevice",
            &json!({ "record": vdevice_record([0xAA; 16], [0xBB; 32]) }),
        )
        .await
        .fails(400, "QuotaExceeded");
}

#[tokio::test]
async fn stored_rows_are_immutable() {
    let env = Env::new().await;
    let v = vectors();
    let d0 = env.device_for(&v.did, v.seeds[0]).await;
    d0.enroll([0xD0; 32]).await;
    d0.call("createEpoch", &json!({ "epoch": epoch_record(&v.chain[0], [0xD0; 32]), "members": [member_record(0, [0xD0; 32])] }))
        .await
        .ok();
    d0.enroll([1; 32]).await;
    d0.call(
        "appendOwnerBatch",
        &json!({ "record": owner_batch_record("t", &[1]) }),
    )
    .await
    .ok();
    d0.call(
        "registerOrfState",
        &json!({ "deviceKeyPubkey": b(&[1; 32]) }),
    )
    .await
    .ok();
    for (table, set) in [
        ("labyrinth.epochs", "record_bytes = record_bytes + 1"),
        ("labyrinth.epoch_members", "record_bytes = record_bytes + 1"),
        (
            "labyrinth.epoch_heads",
            "epoch_public_bytes = epoch_public_bytes + 1",
        ),
        ("labyrinth.owner_batches", "thread_id = 'x'"),
        ("labyrinth.devices", "is_virtual = TRUE"),
        (
            "labyrinth.operations",
            "endpoint_nsid = 'blue.catbird.labyrinth.x'",
        ),
        ("labyrinth.orf_states", "created_at = created_at"),
    ] {
        let update = sqlx::query(&format!("UPDATE {table} SET {set}"))
            .execute(&env.pool)
            .await;
        // orf_states refuses any UPDATE outright; the immutable-identity
        // tables refuse any change outside their counter whitelist.
        assert!(update.is_err(), "{table} accepted UPDATE {set}");
        if table != "labyrinth.orf_states" && table != "labyrinth.devices" {
            let delete = sqlx::query(&format!("DELETE FROM {table}"))
                .execute(&env.pool)
                .await;
            assert!(delete.is_err(), "{table} accepted DELETE");
        }
    }
    // revokedAt is set once even below the API.
    sqlx::query("UPDATE labyrinth.devices SET revoked_at = '2026-10-04T00:00:00Z'")
        .execute(&env.pool)
        .await
        .unwrap();
    assert!(
        sqlx::query("UPDATE labyrinth.devices SET revoked_at = '2026-10-05T00:00:00Z'")
            .execute(&env.pool)
            .await
            .is_err()
    );
    assert!(sqlx::query("DELETE FROM labyrinth.devices")
        .execute(&env.pool)
        .await
        .is_err());
    // ORF states are the one deletable row (revocation).
    sqlx::query("DELETE FROM labyrinth.orf_states")
        .execute(&env.pool)
        .await
        .unwrap();
}
