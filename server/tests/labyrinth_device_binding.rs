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
