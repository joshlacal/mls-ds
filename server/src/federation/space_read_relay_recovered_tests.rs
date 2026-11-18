use super::test_car_builder::build_signed_repo_car;
use super::*;
use base64::{engine::general_purpose::STANDARD, Engine as _};
use ed25519_dalek::Signer as _;

#[test]
fn recovered_read_requires_exact_enrollment_and_revocation_absence_at_current_head() {
    let did = "did:plc:aaaaaaaaaaaaaaaaaaaaaaaa";
    let device = "00000000-0000-4000-8000-00000000cafe";
    let sibling = "00000000-0000-4000-8000-00000000beef";
    let created = "2026-11-16T00:00:00.000Z";
    let repository = p256::SecretKey::from_slice(&[0x36; 32]).unwrap();
    let key = SpaceVerifyingKey::P256(p256::ecdsa::VerifyingKey::from(repository.public_key()));
    let actor = ed25519_dalek::SigningKey::from_bytes(&[0x37; 32]);
    let public = actor.verifying_key().to_bytes();
    let device_path = format!("blue.catbird.chat.device/{device}");
    let enrollment = json!({"$type":"blue.catbird.chat.device","algorithm":"ed25519",
        "createdAt":created, "mlsSignaturePublicKey":{"$bytes":STANDARD.encode(public)}});
    let revocation = |target| {
        let payload = PdsDeviceRevocationTranscriptPayload {
            repo_did: did,
            created_at: created,
            actor_device_id: device,
            target_device_id: target,
        };
        let body = serde_ipld_dagcbor::to_vec(&payload).unwrap();
        let signable = [
            b"CATBIRD-CHAT-PDS-DEVICE-REVOCATION-V1\0".as_slice(),
            body.as_slice(),
        ]
        .concat();
        json!({"$type":"blue.catbird.chat.deviceRevocation","actorDeviceId":device,"targetDeviceId":target,
            "algorithm":"ed25519","createdAt":created,"reason":"retired","signerPublicKey":{"$bytes":STANDARD.encode(public)},
            "signature":{"$bytes":STANDARD.encode(actor.sign(&signable).to_bytes())}})
    };
    let sibling_path = format!("blue.catbird.chat.deviceRevocation/{sibling}");
    let live_records = [
        (device_path.as_str(), &enrollment),
        (sibling_path.as_str(), &revocation(sibling)),
    ];
    let live = build_signed_repo_car(did, "3l2aaaaaaaaaa", &repository, &live_records).0;
    let head = |car: &[u8]| {
        parse_verified_car_v1(car, CHAT_DEVICE_KEY_PROOF_MAX_BYTES)
            .unwrap()
            .0
    };
    let current = head(&live);
    let verify = |enrolled: &[u8], revoked: &[u8], observed| {
        verify_current_recovered_device(enrolled, revoked, observed, did, device, &public, &key)
    };

    // The other device's real revocation does not bar this enrollment.
    verify(&live, &live, current).unwrap();
    let own_path = format!("blue.catbird.chat.deviceRevocation/{device}");
    let retired_records = [
        (device_path.as_str(), &enrollment),
        (own_path.as_str(), &revocation(device)),
    ];
    let retired = build_signed_repo_car(did, "3l2aaaaaaaaab", &repository, &retired_records).0;
    let latest = head(&retired);
    assert!(matches!(
        verify(&retired, &retired, latest),
        Err(SpaceRelayError::DeviceRevoked(_))
    ));
    for (enrolled, revoked, observed) in [
        (&live, &live, latest),
        (&live, &retired, latest),
        (&retired, &live, latest),
    ] {
        assert!(matches!(
            verify(enrolled, revoked, observed),
            Err(SpaceRelayError::UpstreamUnavailable(_))
        ));
    }
    // Both paths must be proven even at the expected head.
    assert!(verify(&live, &[], current).is_err());
    assert!(verify(&[], &live, current).is_err());
    assert!(
        verify_current_recovered_device(&live, &live, current, did, sibling, &public, &key)
            .is_err()
    );
    let foreign = build_signed_repo_car(
        "did:plc:bbbbbbbbbbbbbbbbbbbbbbbb",
        "3l2aaaaaaaaaa",
        &repository,
        &live_records,
    )
    .0;
    assert!(verify(&foreign, &foreign, head(&foreign)).is_err());
    assert!(
        verify_current_recovered_device(&live, &live, current, did, device, &[0x38; 32], &key)
            .is_err()
    );
}
