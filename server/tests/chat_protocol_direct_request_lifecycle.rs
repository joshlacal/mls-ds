//! Cryptographic acceptance boundary regressions. Runtime policy/DB races are
//! require separate delivery-service integration qualification.
use catbird_server::chat_protocol::direct_request_transcript::{
    direct_request_acceptance_endpoint_is_v2, verify_direct_request_acceptance_proof,
};
use serde_json::json;
#[test]
fn membership_or_unsigned_consent_is_not_an_acceptance_proof() {
    for forged in [
        json!({"consent":"accepted"}),
        json!({"participantStatus":"active","leafCount":1}),
        json!({"entry":{},"receipt":{}}),
    ] {
        assert!(verify_direct_request_acceptance_proof(
            &serde_json::to_vec(&forged).unwrap(),
            &[0; 33],
            &[0; 32]
        )
        .is_err());
    }
}
#[test]
fn acceptance_version_presence_is_exclusive() {
    for input in [
        json!({}),
        json!({"signedRequest":{},"directRequest":{}}),
        json!({"accepted":true}),
    ] {
        assert!(
            direct_request_acceptance_endpoint_is_v2(&serde_json::to_vec(&input).unwrap()).is_err()
        );
    }
}
