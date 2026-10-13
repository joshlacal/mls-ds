//! Labyrinth backend: binding Labyrinth devices to chat devices (gap audit
//! G-P0-2, migration `20261004100004`, `labyrinth::repo::binding`).
//!
//! The attack these pin: any active chat device of a DID used to be able to
//! create an epoch or an epoch member naming arbitrary keys. Rows are
//! immutable, so one squatted epoch number or planted member aborted every
//! later rotation, and the account could never revoke a device.

mod common;

#[path = "common/labyrinth_harness.rs"]
mod harness;

use harness::*;
use serde_json::json;

fn epoch(v: &Vectors, n: usize, opened_by: [u8; 32], members: &[[u8; 32]]) -> serde_json::Value {
    let members: Vec<_> = members
        .iter()
        .map(|k| member_record(v.chain[n]["epochNumber"].as_u64().unwrap(), *k))
        .collect();
    json!({ "epoch": epoch_record(&v.chain[n], opened_by), "members": members })
}

#[tokio::test]
async fn create_device_requires_a_valid_binding_to_the_calling_chat_device() {
    let env = Env::new().await;
    let alice = env.account().await;
    let other = env.device_for(&alice.did, random_seed()).await;

    alice
        .call(
            "createDevice",
            &json!({ "record": unbound_device_record([1; 32]) }),
        )
        .await
        .fails(400, "InvalidChatBinding");
    // Bound by another chat device of the same DID: not the caller's key.
    alice
        .call(
            "createDevice",
            &json!({ "record": other.device_record([1; 32]) }),
        )
        .await
        .fails(400, "InvalidChatBinding");
    // The caller's key, but a signature over another device key.
    let mut forged = alice.device_record([1; 32]);
    forged["chatBinding"] = alice.chat_binding([2; 32]);
    alice
        .call("createDevice", &json!({ "record": forged }))
        .await
        .fails(400, "InvalidChatBinding");
    // A virtual device carries no binding.
    let mut virtual_bound = virtual_device_record([3; 32]);
    virtual_bound["chatBinding"] = alice.chat_binding([3; 32]);
    alice
        .call("createDevice", &json!({ "record": virtual_bound }))
        .await
        .fails(400, "InvalidChatBinding");

    alice.enroll([1; 32]).await;
    alice
        .call(
            "createDevice",
            &json!({ "record": virtual_device_record([3; 32]) }),
        )
        .await
        .ok();
}

#[tokio::test]
async fn a_chat_device_without_its_own_labyrinth_device_cannot_write_epochs() {
    let env = Env::new().await;
    let v = vectors();
    let d0 = env.device_for(&v.did, v.seeds[0]).await;
    // d1 is an active chat device of the DID (it could be compromised) that
    // never registered a Labyrinth device of its own.
    let d1 = env.device_for(&v.did, v.seeds[1]).await;
    d0.enroll([0xD0; 32]).await;

    // Squatting genesis or the next epoch, even naming d0's device.
    d1.call("createEpoch", &epoch(&v, 0, [0xD0; 32], &[]))
        .await
        .fails(403, "LabyrinthDeviceNotBound");
    d0.call("createEpoch", &epoch(&v, 0, [0xD0; 32], &[[0xD0; 32]]))
        .await
        .ok();
    d1.call("createEpoch", &epoch(&v, 1, [0xD0; 32], &[]))
        .await
        .fails(403, "LabyrinthDeviceNotBound");
    // Planting a member, or revoking the real device.
    d1.call(
        "createEpochMember",
        &json!({ "record": member_record(0, [0xD0; 32]) }),
    )
    .await
    .fails(403, "LabyrinthDeviceNotBound");
    d1.call(
        "markDeviceRevoked",
        &json!({ "deviceKeyPubkey": b(&[0xD0; 32]), "revokedAt": "2026-10-04T13:00:00.000Z" }),
    )
    .await
    .fails(403, "LabyrinthDeviceNotBound");

    // Once d1 holds its own device it still cannot open as d0's device.
    d1.enroll([0xD1; 32]).await;
    d1.call("createEpoch", &epoch(&v, 1, [0xD0; 32], &[]))
        .await
        .fails(403, "LabyrinthDeviceNotBound");
    // Bound and naming its own device, d1 still cannot open an epoch whose
    // head another chat device attested (review 2, finding 1).
    d1.call(
        "createEpoch",
        &epoch(&v, 1, [0xD1; 32], &[[0xD0; 32], [0xD1; 32]]),
    )
    .await
    .fails(400, "AttestationNotCaller");
    d0.call(
        "createEpoch",
        &epoch(&v, 1, [0xD0; 32], &[[0xD0; 32], [0xD1; 32]]),
    )
    .await
    .ok();
}

#[tokio::test]
async fn members_must_be_current_labyrinth_devices_of_the_account() {
    let env = Env::new().await;
    let v = vectors();
    let d0 = env.device_for(&v.did, v.seeds[0]).await;
    d0.enroll([0xD0; 32]).await;
    d0.enroll([0xD5; 32]).await;

    d0.call(
        "createEpoch",
        &epoch(&v, 0, [0xD0; 32], &[[0xD0; 32], [0xEE; 32]]),
    )
    .await
    .fails(400, "MemberDeviceNotRegistered");
    // Another account's device does not count.
    let bob = env.account().await;
    bob.enroll([0xB0; 32]).await;
    d0.call("createEpoch", &epoch(&v, 0, [0xD0; 32], &[[0xB0; 32]]))
        .await
        .fails(400, "MemberDeviceNotRegistered");
    d0.call("createEpoch", &epoch(&v, 0, [0xD0; 32], &[[0xD0; 32]]))
        .await
        .ok();
    d0.call(
        "createEpochMember",
        &json!({ "record": member_record(0, [0xEE; 32]) }),
    )
    .await
    .fails(400, "MemberDeviceNotRegistered");

    // A revoked device can be neither a member nor the opener.
    d0.call(
        "markDeviceRevoked",
        &json!({ "deviceKeyPubkey": b(&[0xD5; 32]), "revokedAt": "2026-10-04T13:00:00.000Z" }),
    )
    .await
    .ok();
    d0.call(
        "createEpochMember",
        &json!({ "record": member_record(0, [0xD5; 32]) }),
    )
    .await
    .fails(400, "MemberDeviceNotRegistered");
    d0.call(
        "markDeviceRevoked",
        &json!({ "deviceKeyPubkey": b(&[0xD0; 32]), "revokedAt": "2026-10-04T13:00:00.000Z" }),
    )
    .await
    .ok();
    d0.call("createEpoch", &epoch(&v, 1, [0xD0; 32], &[]))
        .await
        .fails(403, "LabyrinthDeviceNotBound");
}

#[tokio::test]
async fn a_virtual_device_never_opens_an_epoch() {
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
    d0.call("createEpoch", &epoch(&v, 0, [0xBB; 32], &[[0xBB; 32]]))
        .await
        .fails(403, "LabyrinthDeviceNotBound");
    // A virtual device may be a member.
    d0.call(
        "createEpoch",
        &epoch(&v, 0, [0xD0; 32], &[[0xD0; 32], [0xBB; 32]]),
    )
    .await
    .ok();
}

// ---------------------------------------------------------------------------
// Mailbox existence gate (review findings MLSDS-C1, MLSDS-I1, MLSDS-I2)
// ---------------------------------------------------------------------------

async fn mailbox_rows(env: &Env, did: &str) -> i64 {
    sqlx::query_scalar("SELECT count(*) FROM labyrinth.mailboxes WHERE owner_did = $1")
        .bind(did)
        .fetch_one(&env.pool)
        .await
        .unwrap()
}

/// MLSDS-C1(b): the mailbox writes that create no bound device (a virtual
/// device, a recovery bundle, an owner batch) need a bound caller. An
/// unbound chat device of an account whose mailbox lives in its PDS Space
/// therefore cannot plant an empty mailbox row here, which would lock the
/// account out of its binding-free head, ORF and purge paths.
#[tokio::test]
async fn an_unbound_chat_device_cannot_plant_a_mailbox_for_a_space_account() {
    let env = Env::new().await;
    let alice = env.account().await;
    let other = env.device_for(&alice.did, random_seed()).await;

    other
        .call(
            "createDevice",
            &json!({ "record": virtual_device_record([0xBB; 32]) }),
        )
        .await
        .fails(403, "LabyrinthDeviceNotBound");
    other
        .call(
            "createVirtualDevice",
            &json!({ "record": vdevice_record([0xAA; 16], [0xBB; 32]) }),
        )
        .await
        .fails(403, "LabyrinthDeviceNotBound");
    other
        .call(
            "appendOwnerBatch",
            &json!({ "record": owner_batch_record("thread-a", &[10]) }),
        )
        .await
        .fails(403, "LabyrinthDeviceNotBound");
    assert_eq!(mailbox_rows(&env, &alice.did).await, 0, "no mailbox planted");

    // The account keeps its binding-free paths.
    let key = [0xA5; 32];
    alice
        .call("registerOrfState", &json!({ "deviceKeyPubkey": b(&key) }))
        .await
        .ok();
    other
        .call("deleteOrfState", &json!({ "deviceKeyPubkey": b(&key) }))
        .await
        .ok();
    other.call("purgeMailbox", &json!({})).await.ok();
}

/// MLSDS-C1(b): the legitimate order still works: the first physical device
/// bootstraps the mailbox unbound, then that bound chat device writes the
/// virtual device, its bundle and owner batches.
#[tokio::test]
async fn a_bound_device_writes_virtual_devices_and_owner_batches() {
    let env = Env::new().await;
    let alice = env.account().await;
    alice.enroll([0xA0; 32]).await;
    alice
        .call(
            "createDevice",
            &json!({ "record": virtual_device_record([0xBB; 32]) }),
        )
        .await
        .ok();
    alice
        .call(
            "createVirtualDevice",
            &json!({ "record": vdevice_record([0xAA; 16], [0xBB; 32]) }),
        )
        .await
        .ok();
    alice
        .call(
            "appendOwnerBatch",
            &json!({ "record": owner_batch_record("thread-a", &[10]) }),
        )
        .await
        .ok();
}

/// MLSDS-I1: `createDevice` accepts a virtual device (the lexicon's device
/// record is "physical or virtual", and only `labyrinth.devices` rows can be
/// epoch members), but a virtual row carries no chat binding.
#[tokio::test]
async fn a_virtual_device_row_records_no_chat_binding() {
    let env = Env::new().await;
    let alice = env.account().await;
    alice.enroll([0xA0; 32]).await;
    alice
        .call(
            "createDevice",
            &json!({ "record": virtual_device_record([0xBB; 32]) }),
        )
        .await
        .ok();
    let (device, key): (Option<uuid::Uuid>, Option<String>) = sqlx::query_as(
        "SELECT chat_device_id, chat_key_id FROM labyrinth.devices \
          WHERE owner_did = $1 AND device_key = $2",
    )
    .bind(&alice.did)
    .bind([0xBB_u8; 32].as_slice())
    .fetch_one(&env.pool)
    .await
    .unwrap();
    assert_eq!((device, key), (None, None));
}

/// MLSDS-I2: on an account whose mailbox is here, registering ORF state
/// needs a bound device, like deleting it.
#[tokio::test]
async fn an_unbound_chat_device_cannot_register_orf_state_on_a_hosted_mailbox() {
    let env = Env::new().await;
    let alice = env.account().await;
    alice.enroll([0xA0; 32]).await;
    let other = env.device_for(&alice.did, random_seed()).await;
    other
        .call(
            "registerOrfState",
            &json!({ "deviceKeyPubkey": b(&[0xA5; 32]) }),
        )
        .await
        .fails(403, "LabyrinthDeviceNotBound");
    alice
        .call(
            "registerOrfState",
            &json!({ "deviceKeyPubkey": b(&[0xA0; 32]) }),
        )
        .await
        .ok();
}

/// MLSDS-I2: ORF states are capped per account, so a Space account (which
/// registers without a binding) cannot grow them without bound.
#[tokio::test]
async fn orf_states_are_capped_per_account() {
    let env = Env::new().await;
    let alice = env.account().await;
    let max = catbird_server::labyrinth::repo::orf::MAX_ORF_STATES;
    sqlx::query(
        "INSERT INTO labyrinth.orf_states (owner_did, device_key, server_state, created_at) \
         SELECT $1, sha256(int4send(i)), sha256(int4send(i)), now() \
           FROM generate_series(1, $2) AS i",
    )
    .bind(&alice.did)
    .bind(max as i32)
    .execute(&env.pool)
    .await
    .unwrap();
    alice
        .call(
            "registerOrfState",
            &json!({ "deviceKeyPubkey": b(&[0xA5; 32]) }),
        )
        .await
        .fails(400, "QuotaExceeded");
    // Dropping one frees a slot.
    alice
        .call(
            "deleteOrfState",
            &json!({ "deviceKeyPubkey": b(&sha256_of_int(1)) }),
        )
        .await
        .ok();
    alice
        .call(
            "registerOrfState",
            &json!({ "deviceKeyPubkey": b(&[0xA5; 32]) }),
        )
        .await
        .ok();
}

fn sha256_of_int(i: i32) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    Sha256::digest(i.to_be_bytes()).into()
}

/// MLSDS-C1(a): a destructive request that found no mailbox here must not
/// wipe one a concurrent first `createDevice` commits while it runs. The
/// `createDevice` transaction is held open (the real repository call) and
/// also holds a row lock the purge needs, so without serialization the
/// purge decides "no mailbox, no binding needed" first, then blocks, then
/// deletes the freshly committed mailbox.
#[tokio::test]
async fn a_purge_never_wipes_a_mailbox_created_after_its_check() {
    use catbird_server::labyrinth::auth::Caller;
    use catbird_server::labyrinth::repo::mailbox;
    use catbird_server::labyrinth::wire::io::Received;
    use catbird_server::labyrinth::wire::records::Device as DeviceRecord;

    let env = Env::new().await;
    let alice = env.account().await;
    let other = env.device_for(&alice.did, random_seed()).await;
    // Space-account state this DS holds: one ORF state.
    alice
        .call(
            "registerOrfState",
            &json!({ "deviceKeyPubkey": b(&[0xA5; 32]) }),
        )
        .await
        .ok();

    let key_id: String = sqlx::query_scalar("SELECT chat.ed25519_key_id($1)")
        .bind(alice.chat_pub().as_slice())
        .fetch_one(&env.pool)
        .await
        .unwrap();
    let caller = Caller {
        did: alice.did.clone(),
        device_id: alice.device_id,
        key_id,
        signing_key: alice.chat_pub(),
    };
    let raw = serde_json::value::to_raw_value(&alice.device_record([0xA0; 32])).unwrap();
    let rec = Received::<DeviceRecord>::parse(&raw, "record").unwrap();

    let mut create = env.pool.begin().await.unwrap();
    sqlx::query("SELECT 1 FROM labyrinth.orf_states WHERE owner_did = $1 FOR UPDATE")
        .bind(&alice.did)
        .fetch_all(&mut *create)
        .await
        .unwrap();
    mailbox::create_device(&mut create, &caller, &rec, env.now().await)
        .await
        .unwrap();

    let purge = tokio::spawn({
        let other = other.clone();
        async move { other.call("purgeMailbox", &json!({})).await }
    });
    // Wait until the purge is blocked behind the open createDevice.
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(20);
    loop {
        let waiting: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM pg_stat_activity \
              WHERE datname = current_database() AND wait_event_type = 'Lock'",
        )
        .fetch_one(&env.pool)
        .await
        .unwrap();
        if waiting > 0 {
            break;
        }
        assert!(
            !purge.is_finished(),
            "the purge ran without waiting for createDevice"
        );
        assert!(std::time::Instant::now() < deadline, "purge never blocked");
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }
    create.commit().await.unwrap();

    let reply = purge.await.unwrap();
    let devices: i64 =
        sqlx::query_scalar("SELECT count(*) FROM labyrinth.devices WHERE owner_did = $1")
            .bind(&alice.did)
            .fetch_one(&env.pool)
            .await
            .unwrap();
    assert_eq!(devices, 1, "the new device survived");
    assert_eq!(mailbox_rows(&env, &alice.did).await, 1);
    reply.fails(403, "LabyrinthDeviceNotBound");
}
