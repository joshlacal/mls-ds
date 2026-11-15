//! Fast pure/in-memory C2 unit tests for `canonical_relay.rs` unscored helpers.

use super::*;
use crate::federation::outbound::OutboundError;
use crate::federation::resolver::{DsEndpoint, DsResolver};
#[cfg(feature = "sim")]
use p256::ecdsa::SigningKey;
#[cfg(feature = "sim")]
use p256::pkcs8::{EncodePrivateKey as _, LineEnding};
use serde_json::json;

fn c2_endpoint(did: &str, endpoint: &str) -> DsEndpoint {
    DsEndpoint {
        did: did.to_owned(),
        endpoint: endpoint.to_owned(),
        supported_cipher_suites: None,
        federation_capabilities: None,
    }
}

fn c2_resolver(self_did: &str) -> DsResolver {
    let pool = sqlx::postgres::PgPoolOptions::new()
        .connect_lazy("postgres://127.0.0.1:1/c2_canonical_relay_unit")
        .unwrap();
    DsResolver::new(
        pool,
        crate::federation::resolver::build_resolver_http_client(),
        self_did.to_owned(),
        "https://self-ds.example.com".to_owned(),
        None,
        300,
    )
}

#[tokio::test]
async fn c2_pair_coordinator_and_endpoint_selection_boundaries() {
    let low = "did:web:alpha.example.com";
    let high = "did:web:omega.example.com";
    let low_ep = c2_endpoint(low, "https://alpha.example.com");
    let high_ep = c2_endpoint(high, "https://omega.example.com");

    // Sender <= recipient picks sender as coordinator and sender endpoint.
    let by_low = pair_coordinator(&c2_resolver(low), low_ep.clone(), high_ep.clone());
    assert_eq!(by_low.coordinator_did, low);
    assert!(by_low.is_coordinator);
    assert!(by_low.is_sender_home);
    assert!(!by_low.is_recipient_home);
    assert_eq!(by_low.coordinator_endpoint(), "https://alpha.example.com");

    // Sender > recipient picks recipient as coordinator and recipient endpoint.
    let by_high = pair_coordinator(&c2_resolver(low), high_ep.clone(), low_ep.clone());
    assert_eq!(by_high.coordinator_did, low);
    assert!(by_high.is_coordinator);
    assert!(!by_high.is_sender_home);
    assert!(by_high.is_recipient_home);
    assert_eq!(by_high.coordinator_endpoint(), "https://alpha.example.com");

    // Equal DIDs pick sender (`<=` boundary) and mark both homes local when self matches.
    let same = pair_coordinator(
        &c2_resolver(low),
        c2_endpoint(low, "https://sender-same.example.com"),
        c2_endpoint(low, "https://recipient-same.example.com"),
    );
    assert_eq!(same.coordinator_did, low);
    assert!(same.is_coordinator);
    assert!(same.is_sender_home);
    assert!(same.is_recipient_home);
    assert_eq!(
        same.coordinator_endpoint(),
        "https://sender-same.example.com"
    );

    // Observer on third DS sees neither flag set.
    let third = pair_coordinator(&c2_resolver("did:web:third.example.com"), high_ep, low_ep);
    assert!(!third.is_coordinator);
    assert!(!third.is_sender_home);
    assert!(!third.is_recipient_home);
}

#[test]
fn c2_relay_error_and_queue_full_classification() {
    let remote = |status: u16, error_name: &str, body: &str| OutboundError::RemoteError {
        status,
        body: body.to_owned(),
        endpoint: "https://peer.example.com".to_owned(),
        method: "rpc".to_owned(),
        reason_code: None,
        error_name: Some(error_name.to_owned()),
    };
    assert!(matches!(
        relay_error(
            "https://peer.example.com",
            "prepare",
            remote(400, "BlockedRelationship", "blocked")
        ),
        FederationError::BlockedRelationship
    ));
    assert!(matches!(
        relay_error(
            "https://peer.example.com",
            "prepare",
            remote(400, "InvalidRequest", "bad")
        ),
        FederationError::RemoteError { status: 400, .. }
    ));
    assert!(matches!(
        relay_error(
            "https://peer.example.com",
            "send",
            remote(409, "StaleSend", "stale")
        ),
        FederationError::StaleSend
    ));
    assert!(matches!(
        relay_error(
            "https://peer.example.com",
            "send",
            remote(409, "Conflict", "conflict")
        ),
        FederationError::RemoteError { status: 409, .. }
    ));
    assert!(matches!(
        relay_error(
            "https://peer.example.com",
            "send",
            OutboundError::Timeout {
                endpoint: "https://peer.example.com".into(),
                method: "send".into(),
            }
        ),
        FederationError::DsUnreachable { .. }
    ));
    assert!(matches!(
        relay_error(
            "https://peer.example.com",
            "send",
            OutboundError::InvalidResponse {
                reason: "oversized".into(),
            }
        ),
        FederationError::InvalidRequest(_)
    ));

    for capped in [
        FederationError::OutboundQueuePeerCapExceeded {
            target_ds_did: "did:web:peer.example.com".into(),
            pending: 10,
            limit: 10,
        },
        FederationError::OutboundQueueConvoPeerCapExceeded {
            convo_id: "c1".into(),
            target_ds_did: "did:web:peer.example.com".into(),
            pending: 5,
            limit: 5,
        },
    ] {
        assert!(matches!(
            queue_full_unavailable(capped),
            FederationError::RemoteError { status: 503, .. }
        ));
    }
    assert!(matches!(
        queue_full_unavailable(FederationError::Forbidden("denied".into())),
        FederationError::Forbidden(_)
    ));

    let foreign = PairFenceConflict::ForeignCoordinator {
        coordinator_did: "did:web:coord.example.com".into(),
        source: "attempts",
        status: "pending".into(),
    }
    .to_string();
    assert!(foreign.contains("did:web:coord.example.com") && foreign.contains("attempts"));
    let local = PairFenceConflict::LocalConflict {
        source: "conversations",
        status: "active".into(),
    }
    .to_string();
    assert!(local.contains("conversations") && local.contains("active"));
}

#[cfg(feature = "sim")]
fn c2_sim_hooks(signing_key_pem: Option<String>) -> std::sync::Arc<crate::sim_hooks::SimDsHooks> {
    std::sync::Arc::new(crate::sim_hooks::SimDsHooks {
        service_did: "did:web:issuer.example.com".into(),
        self_endpoint: "https://issuer.example.com".into(),
        signing_key_pem,
        group_relay_hmac_secret: None,
        http_transport: std::sync::Arc::new(|_req| {
            Box::pin(async { Err("unexpected outbound HTTP in unit test".into()) })
        }),
        dns_resolver: std::sync::Arc::new(|_host| Err("unexpected DNS in unit test".into())),
        retain_application_ciphertext: false,
    })
}

#[cfg(feature = "sim")]
#[tokio::test]
async fn c2_s2s_signing_key_and_token_minting_boundaries() {
    let key = SigningKey::from_slice(&[0x42; 32]).unwrap();
    let pem = key.to_pkcs8_pem(LineEnding::LF).unwrap().to_string();
    let hooks = c2_sim_hooks(Some(pem.clone()));
    crate::sim_hooks::scope_sim_ds(hooks, async {
        assert_eq!(configured_s2s_signing_key_pem().unwrap(), pem);
        let token = mint_s2s_auth_token(
            "did:web:target.example.com",
            "blue.catbird.mlsDS.deliverMessage",
        )
        .unwrap();
        assert_eq!(token.split('.').count(), 3);
        let payload_b64 = token.split('.').nth(1).unwrap();
        let claims: Value =
            serde_json::from_slice(&URL_SAFE_NO_PAD.decode(payload_b64).unwrap()).unwrap();
        assert_eq!(claims["iss"], "did:web:issuer.example.com");
        assert_eq!(claims["aud"], "did:web:target.example.com");
        assert_eq!(claims["lxm"], "blue.catbird.mlsDS.deliverMessage");
    })
    .await;

    let bad_hooks = c2_sim_hooks(Some("not-a-valid-pem".into()));
    crate::sim_hooks::scope_sim_ds(bad_hooks, async {
        assert!(matches!(
            mint_s2s_auth_token(
                "did:web:target.example.com",
                "blue.catbird.mlsDS.deliverMessage"
            ),
            Err(FederationError::ConfigError { .. })
        ));
    })
    .await;

    let missing_hooks = c2_sim_hooks(None);
    crate::sim_hooks::scope_sim_ds(missing_hooks, async {
        assert!(matches!(
            configured_s2s_signing_key_pem(),
            Err(FederationError::ConfigError { .. })
        ));
    })
    .await;
}

#[test]
fn c2_authorized_device_key_and_peer_delivery_boundaries() {
    let first = vec![0x21; 32];
    let second = vec![0x34; 32];
    let both = vec![first.clone(), second.clone()];

    let sha_b64url = URL_SAFE_NO_PAD.encode(Sha256::digest(&second));
    let raw_std = STANDARD.encode(&second);
    let ed_id = crate::chat_protocol::validation::ed25519_key_id(&first)
        .unwrap()
        .as_str()
        .to_owned();

    assert_eq!(
        authorized_device_key(&both, &sha_b64url),
        Some(second.as_slice())
    );
    assert_eq!(
        authorized_device_key(&both, &raw_std),
        Some(second.as_slice())
    );
    assert_eq!(authorized_device_key(&both, &ed_id), Some(first.as_slice()));
    assert_eq!(authorized_device_key(&both, "unmatched"), None);
    assert_eq!(authorized_device_key(&[], "unmatched"), None);

    assert!(distinct_nonempty_peer("did:plc:bob", "did:plc:alice"));
    assert!(!distinct_nonempty_peer("", "did:plc:alice"));
    assert!(!distinct_nonempty_peer("did:plc:alice", "did:plc:alice"));
    assert!(should_deliver_to_peer(
        "did:plc:bob",
        "did:plc:alice",
        false
    ));
    assert!(!should_deliver_to_peer(
        "did:plc:bob",
        "did:plc:alice",
        true
    ));
}

#[test]
fn c2_same_transport_coordinate_binds_every_field() {
    let base = json!({
        "conversationId": "11111111-1111-4111-8111-111111111111",
        "generation": 2,
        "stateVersion": 5,
        "epoch": 3,
        "lifecycle": "active",
        "groupId": STANDARD.encode([0xaa; 32]),
        "groupContextHash": {"$bytes": STANDARD.encode([0xbb; 32])},
        "confirmationTag": URL_SAFE_NO_PAD.encode([0xcc; 32]),
    });
    assert!(same_transport_coordinate(&base, &base));

    // Encoding equivalence ($bytes vs bare string) holds for identical 32-byte values.
    let mut alt_encoding = base.clone();
    alt_encoding["groupContextHash"] = json!(URL_SAFE_NO_PAD.encode([0xbb; 32]));
    assert!(same_transport_coordinate(&base, &alt_encoding));

    for mutate in [
        (|v: &mut Value| v["conversationId"] = json!("22222222-2222-4222-8222-222222222222"))
            as fn(&mut Value),
        |v| v["generation"] = json!(3),
        |v| v["stateVersion"] = json!(6),
        |v| v["epoch"] = json!(4),
        |v| v["lifecycle"] = json!("superseded"),
        |v| v["groupId"] = json!(STANDARD.encode([0xab; 32])),
        |v| v["groupContextHash"] = json!(STANDARD.encode([0xbc; 32])),
        |v| v["confirmationTag"] = json!(STANDARD.encode([0xcd; 32])),
        |v| v["groupId"] = json!(STANDARD.encode([0xaa; 31])),
    ] {
        let mut changed = base.clone();
        mutate(&mut changed);
        assert!(
            !same_transport_coordinate(&base, &changed),
            "must reject {changed}"
        );
    }
}
