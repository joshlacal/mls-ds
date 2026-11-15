//! Fast pure C2 unit tests for `group_membership.rs` unscored classifiers and
//! `decode_member_devices_relay`.

use super::*;
use crate::federation::bootstrap::RemotePrefixBootstrapError;
use crate::federation::errors::ResolutionFailureKind;
use crate::federation::outbound::OutboundError;
use crate::labyrinth::auth::Admission;
use axum::response::IntoResponse as _;

fn c2_status_and_code(response: Response) -> (StatusCode, String) {
    let status = response.status();
    let bytes =
        futures::executor::block_on(axum::body::to_bytes(response.into_body(), 16 * 1024)).unwrap();
    let body: Value = serde_json::from_slice(&bytes).unwrap_or_default();
    (
        status,
        body.get("error")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_owned(),
    )
}

#[test]
fn c2_relay_failure_federation_outbound_and_bootstrap_classifications() {
    // RelayFailure::federation: Database -> 500, retryable -> 503, 5xx -> 500, 4xx -> 403.
    assert_eq!(
        c2_status_and_code(
            RelayFailure::federation(FederationError::Database(sqlx::Error::PoolTimedOut))
                .into_response()
        ),
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            "InternalServerError".into()
        )
    );
    assert_eq!(
        c2_status_and_code(
            RelayFailure::federation(FederationError::DsUnreachable {
                endpoint: "https://home.example.com".into(),
                reason: "timeout".into(),
            })
            .into_response()
        ),
        (StatusCode::SERVICE_UNAVAILABLE, "ServiceUnavailable".into())
    );
    assert_eq!(
        c2_status_and_code(
            RelayFailure::federation(FederationError::ConfigError {
                reason: "missing key".into(),
            })
            .into_response()
        ),
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            "InternalServerError".into()
        )
    );
    assert_eq!(
        c2_status_and_code(
            RelayFailure::federation(FederationError::Forbidden("denied".into())).into_response()
        ),
        (StatusCode::FORBIDDEN, "NotAuthorized".into())
    );

    // RelayFailure::outbound
    assert_eq!(
        c2_status_and_code(
            RelayFailure::outbound(OutboundError::Timeout {
                endpoint: "https://home.example.com".into(),
                method: "getGroupState".into(),
            })
            .into_response()
        ),
        (StatusCode::SERVICE_UNAVAILABLE, "ServiceUnavailable".into())
    );
    assert_eq!(
        c2_status_and_code(
            RelayFailure::outbound(OutboundError::InvalidResponse {
                reason: "bad json".into(),
            })
            .into_response()
        ),
        (StatusCode::FORBIDDEN, "NotAuthorized".into())
    );

    // RelayFailure::bootstrap
    for internal in [
        RemotePrefixBootstrapError::Database,
        RemotePrefixBootstrapError::ServiceAuth,
    ] {
        assert_eq!(
            c2_status_and_code(RelayFailure::bootstrap(internal).into_response()),
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                "InternalServerError".into()
            )
        );
    }
    assert_eq!(
        c2_status_and_code(
            RelayFailure::bootstrap(RemotePrefixBootstrapError::Unavailable).into_response()
        ),
        (StatusCode::SERVICE_UNAVAILABLE, "ServiceUnavailable".into())
    );
    assert_eq!(
        c2_status_and_code(
            RelayFailure::bootstrap(RemotePrefixBootstrapError::Authority).into_response()
        ),
        (StatusCode::FORBIDDEN, "NotAuthorized".into())
    );

    // Remaining labyrinth_relay_failure & labyrinth_peer_failure arms (5xx ConfigError, InvalidSignature, DeviceRevoked).
    assert_eq!(
        c2_status_and_code(
            labyrinth_relay_failure(FederationError::ResolutionFailed {
                did: "did:web:home.example.com".into(),
                kind: ResolutionFailureKind::InvalidConfiguration("bad".into()),
            })
            .into_response()
        ),
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            "InternalServerError".into()
        )
    );
    assert_eq!(
        c2_status_and_code(
            labyrinth_peer_failure(401, br#"{"error":"InvalidSignature","message":"sig"}"#)
                .into_response()
        ),
        (StatusCode::UNAUTHORIZED, "InvalidSignature".into())
    );
    assert_eq!(
        c2_status_and_code(
            labyrinth_peer_failure(403, br#"{"error":"DeviceRevoked","message":"revoked"}"#)
                .into_response()
        ),
        (StatusCode::FORBIDDEN, "DeviceRevoked".into())
    );
}

#[test]
fn c2_decode_member_devices_relay_enforces_every_binding_and_page_bound() {
    let sequencer = "did:web:seq.example.com";
    let term = 7_i64;
    let actor_did = "did:plc:abcdefghijklmnopqrstuvwx";
    let actor_device_id = Uuid::new_v4();
    let conversation_id = Uuid::new_v4();
    let subject_did = "did:plc:yzabcdefghijklmnopqrstuv";
    let query = "conversationId=test&subjectDid=subject";
    let admission = Admission {
        did: actor_did.to_owned(),
        device_id: actor_device_id,
        instant: Utc::now(),
        write: None,
        read: None,
    };

    let pub_key = ed25519_dalek::SigningKey::from_bytes(&[0x55; 32])
        .verifying_key()
        .to_bytes();
    let key_id = crate::chat_protocol::validation::ed25519_key_id(&pub_key)
        .unwrap()
        .as_str()
        .to_owned();
    let encoded_key = STANDARD.encode(pub_key);

    let valid_item = json!({
        "keyId": key_id,
        "signingPublicKey": {"$bytes": encoded_key},
        "joinedSeq": 0,
        "removedSeq": 0,
    });
    let max_seq_item = json!({
        "keyId": key_id,
        "signingPublicKey": {"$bytes": encoded_key},
        "joinedSeq": 9_007_199_254_740_991_i64,
        "removedSeq": 9_007_199_254_740_991_i64,
    });
    let base = json!({
        "endpoint": LABYRINTH_MEMBER_DEVICES_ENDPOINT,
        "query": query,
        "sequencerDid": sequencer,
        "sequencerTerm": term,
        "actorDid": actor_did,
        "actorDeviceId": actor_device_id,
        "conversationId": conversation_id,
        "subjectDid": subject_did,
        "page": {
            "items": [valid_item.clone(), max_seq_item],
            "cursor": "c".repeat(64),
        }
    });

    let decoded = decode_member_devices_relay(
        &serde_json::to_vec(&base).unwrap(),
        sequencer,
        term,
        &admission,
        conversation_id,
        subject_did,
        query,
    )
    .expect("valid relay page decodes");
    let page_json: Value = serde_json::from_slice(&decoded).unwrap();
    assert_eq!(page_json["items"].as_array().unwrap().len(), 2);

    // Exact MAX_PAGE items succeeds; MAX_PAGE + 1 fails.
    let mut max_page = base.clone();
    max_page["page"]["items"] = Value::Array(vec![
        valid_item.clone();
        crate::labyrinth::repo::MAX_PAGE as usize
    ]);
    assert!(decode_member_devices_relay(
        &serde_json::to_vec(&max_page).unwrap(),
        sequencer,
        term,
        &admission,
        conversation_id,
        subject_did,
        query,
    )
    .is_ok());

    for mutate in [
        (|v: &mut Value| v["endpoint"] = json!("blue.catbird.labyrinth.other")) as fn(&mut Value),
        |v| v["query"] = json!("other=1"),
        |v| v["sequencerDid"] = json!("did:web:other.example.com"),
        |v| v["sequencerTerm"] = json!(8),
        |v| v["actorDid"] = json!("did:plc:222222222222222222222222"),
        |v| v["actorDeviceId"] = json!(Uuid::new_v4()),
        |v| v["conversationId"] = json!(Uuid::new_v4()),
        |v| v["subjectDid"] = json!("did:plc:333333333333333333333333"),
        |v| v["page"]["cursor"] = json!("c".repeat(65)),
        |v| {
            v["page"]["items"][0]["keyId"] = json!("");
        },
        |v| {
            v["page"]["items"][0]["keyId"] = json!("k".repeat(129));
        },
        |v| {
            v["page"]["items"][0]["keyId"] = json!("a".repeat(43));
        },
        |v| {
            v["page"]["items"][0]["signingPublicKey"] =
                json!({"$bytes": STANDARD.encode([0x11; 31])});
        },
        |v| {
            v["page"]["items"][0]["joinedSeq"] = json!(-1);
        },
        |v| {
            v["page"]["items"][0]["joinedSeq"] = json!(9_007_199_254_740_992_i64);
        },
        |v| {
            v["page"]["items"][0]["joinedSeq"] = json!(5);
            v["page"]["items"][0]["removedSeq"] = json!(4);
        },
        |v| {
            v["page"]["items"][0]["removedSeq"] = json!(9_007_199_254_740_992_i64);
        },
    ] {
        let mut bad = base.clone();
        mutate(&mut bad);
        let err = decode_member_devices_relay(
            &serde_json::to_vec(&bad).unwrap(),
            sequencer,
            term,
            &admission,
            conversation_id,
            subject_did,
            query,
        )
        .unwrap_err();
        assert_eq!(err.name(), "NotAuthorized", "{bad}");
    }

    let mut overflow_page = base;
    overflow_page["page"]["items"] = Value::Array(vec![
        valid_item;
        crate::labyrinth::repo::MAX_PAGE as usize
            + 1
    ]);
    assert!(decode_member_devices_relay(
        &serde_json::to_vec(&overflow_page).unwrap(),
        sequencer,
        term,
        &admission,
        conversation_id,
        subject_did,
        query,
    )
    .is_err());
}
