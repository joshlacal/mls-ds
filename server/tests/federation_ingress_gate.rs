//! The inbound federation gate on every peer route family. While the emergency
//! kill switch is on, or the effective (runtime-override) federation mode is
//! off, each route answers a retryable `503 FederationDisabled`, so peers keep
//! durable relays queued instead of dead-lettering them. Once the gate opens,
//! the same unauthenticated request reaches peer authentication and stays 401.
//! The gate runs before any query, so the lazy pool never connects.
//!
//! The kill switch and the mode override are process-global; this binary's gate
//! test owns them. Peer authentication itself needs no gate: a DID document
//! that cannot be fetched now answers a retryable 503, a bad token 401.

use axum::{
    body::Body,
    http::{Request, StatusCode},
    response::{IntoResponse, Response},
    Router,
};
use catbird_server::{
    auth::{AtProtoClaims, AuthUser},
    federation::{
        group_relay::{group_relay_router, GroupRelayState},
        FederationMode,
    },
    handlers::ds::{deliver_message::enforce_ds_request_security, health_check},
    storage::DbPool,
};
use serde_json::Value;
use tower_util::ServiceExt;

const KILL_SWITCH: &str = "FEDERATION_EMERGENCY_KILL_SWITCH";
const SELF_DID: &str = "did:web:ingress-gate.example";
const PEER_DID: &str = "did:web:ingress-gate-peer.example";

/// Every `group_relay_router` route: group relay, membership, Labyrinth
/// directory, entry ACK, prune notice, account deletion, transport control.
const GROUP_RELAY_ROUTES: &[&str] = &[
    "blue.catbird.mlsDS.relayGroupMutation",
    "blue.catbird.mlsDS.deliverGroupEntry",
    "blue.catbird.mlsDS.resolveGroupDevices",
    "blue.catbird.mlsDS.fetchKeyPackage",
    "blue.catbird.mlsDS.getLabyrinthDirectory",
    "blue.catbird.mlsDS.getGroupConversationState",
    "blue.catbird.mlsDS.getGroupPendingWelcomes",
    "blue.catbird.mlsDS.relayEntryAck",
    "blue.catbird.mlsDS.notifyEntriesPruned",
    "blue.catbird.mlsDS.relayAccountDeletion",
    "blue.catbird.mlsDS.deliverTransportControlEntry",
];

/// Every route that admits its peer through `enforce_ds_request_security`.
const DS_ROUTES: &[&str] = &[
    "blue.catbird.mlsDS.deliverMessage",
    "blue.catbird.mlsDS.deliverWelcome",
    "blue.catbird.mlsDS.submitCommit",
    "blue.catbird.mlsDS.fetchKeyPackage",
    "blue.catbird.mlsDS.getConvoDigest",
    "blue.catbird.mlsDS.getConvoEvents",
    "blue.catbird.mlsDS.transferSequencer",
    "blue.catbird.mlsDS.reserveRecipientBootstrap",
    "blue.catbird.mlsDS.releaseRecipientBootstrap",
    "blue.catbird.mlsDS.prepareDirectRequest",
    "blue.catbird.mlsDS.publishDirectRequest",
    "blue.catbird.mlsDS.deliverDirectRequest",
    "blue.catbird.mlsDS.deliverAcceptance",
    "blue.catbird.mlsDS.deliverAcceptanceEntry",
    "blue.catbird.mlsDS.relaySendMessage",
    "blue.catbird.mlsDS.deliverMessageEntry",
    "blue.catbird.mlsDS.getDirectRequestOutcome",
];

async fn status_and_body(response: Response) -> (StatusCode, Value) {
    let status = response.status();
    let bytes = axum::body::to_bytes(response.into_body(), 1 << 16)
        .await
        .expect("response body");
    (status, serde_json::from_slice(&bytes).expect("JSON body"))
}

/// Each route's answer to an unauthenticated peer; a ds-family peer presents
/// a token minted for another method.
async fn answers(router: &Router, pool: &DbPool) -> Vec<(String, StatusCode, Value)> {
    let mut answers = Vec::new();
    for nsid in GROUP_RELAY_ROUTES {
        let request = Request::post(format!("/xrpc/{nsid}"))
            .body(Body::empty())
            .expect("request");
        let response = router.clone().oneshot(request).await.expect("route");
        let (status, body) = status_and_body(response).await;
        answers.push((format!("group relay {nsid}"), status, body));
    }
    for nsid in DS_ROUTES {
        let peer = AuthUser {
            did: PEER_DID.into(),
            claims: AtProtoClaims {
                iss: PEER_DID.into(),
                aud: SELF_DID.into(),
                exp: i64::MAX,
                iat: None,
                sub: None,
                lxm: Some("blue.catbird.mlsDS.anotherMethod".into()),
                jti: None,
            },
        };
        let response = match enforce_ds_request_security(pool, &peer, nsid, None).await {
            Ok(_) => panic!("{nsid} admitted a token minted for another method"),
            Err(error) => error.into_response(),
        };
        let (status, body) = status_and_body(response).await;
        answers.push((format!("ds {nsid}"), status, body));
    }
    let response = health_check()
        .await
        .map_or_else(|error| error.into_response(), |ok| ok.into_response());
    let (status, body) = status_and_body(response).await;
    answers.push(("healthCheck".into(), status, body));
    answers
}

#[tokio::test]
async fn every_inbound_peer_route_closes_with_a_retryable_503_and_reopens_to_authentication() {
    std::env::set_var("SERVICE_DID", SELF_DID);
    let pool = sqlx::postgres::PgPoolOptions::new()
        .max_connections(1)
        .connect_lazy("postgres://127.0.0.1/federation_ingress_gate")
        .expect("lazy pool");
    let router = group_relay_router(GroupRelayState::new(
        pool.clone(),
        SELF_DID.into(),
        None,
        None,
    ));

    // The kill switch wins over an open mode; an off runtime override closes
    // the gate on its own.
    for (closed_by, kill_switch, mode) in [
        ("kill switch", true, FederationMode::OpenIntelligent),
        ("runtime mode off", false, FederationMode::Off),
    ] {
        if kill_switch {
            std::env::set_var(KILL_SWITCH, "1");
        } else {
            std::env::remove_var(KILL_SWITCH);
        }
        FederationMode::set_runtime_override(Some(mode));
        for (route, status, body) in answers(&router, &pool).await {
            assert_eq!(
                status,
                StatusCode::SERVICE_UNAVAILABLE,
                "{closed_by}: {route} {body}"
            );
            assert_eq!(body["error"], "FederationDisabled", "{closed_by}: {route}");
        }
    }

    std::env::remove_var(KILL_SWITCH);
    FederationMode::set_runtime_override(Some(FederationMode::Allowlist));
    for (route, status, body) in answers(&router, &pool).await {
        let expected = if route == "healthCheck" {
            StatusCode::OK
        } else {
            StatusCode::UNAUTHORIZED
        };
        assert_eq!(status, expected, "open: {route} {body}");
    }
}

/// `deliverMessage` authenticates its peer through `AuthUser`, as every
/// `enforce_ds_request_security` route does. The peer's DID host first does not
/// resolve, then its authority answers 503, then 404, then the document a
/// forged token does not verify against.
#[cfg(feature = "sim")]
#[tokio::test]
async fn peer_did_document_outage_answers_retryable_503_and_a_bad_token_401() {
    use axum::{extract::FromRef, routing::post};
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
    use catbird_server::{
        federation::AckSigner,
        handlers::ds::deliver_message,
        sim_hooks::{scope_sim_ds, SimDsHooks, SimHttpRequest},
    };
    use p256::ecdsa::{signature::Signer as _, Signature, SigningKey};
    use std::{
        future::Future,
        pin::Pin,
        sync::{Arc, Mutex},
    };

    const SIM_SELF: &str = "did:web:ingress-auth.example";
    const SIM_PEER: &str = "did:web:ingress-auth-peer.example";
    const NSID: &str = "blue.catbird.mlsDS.deliverMessage";
    type Reply = Pin<Box<dyn Future<Output = Result<::http::Response<Vec<u8>>, String>> + Send>>;

    #[derive(Clone)]
    struct DsState {
        pool: DbPool,
    }
    impl FromRef<DsState> for DbPool {
        fn from_ref(state: &DsState) -> Self {
            state.pool.clone()
        }
    }
    impl FromRef<DsState> for Option<Arc<AckSigner>> {
        fn from_ref(_: &DsState) -> Self {
            None
        }
    }

    let peer_point = SigningKey::from_bytes((&[0x41u8; 32]).into())
        .unwrap()
        .verifying_key()
        .to_encoded_point(false);
    let document = serde_json::json!({
        "id": SIM_PEER,
        "verificationMethod": [{
            "id": "#atproto",
            "type": "JsonWebKey2020",
            "controller": SIM_PEER,
            "publicKeyJwk": {
                "kty": "EC",
                "crv": "P-256",
                "x": URL_SAFE_NO_PAD.encode(peer_point.x().unwrap()),
                "y": URL_SAFE_NO_PAD.encode(peer_point.y().unwrap()),
            },
        }],
    });
    // `None`: the peer's DID host does not resolve now.
    let authority: Arc<Mutex<Option<(u16, Value)>>> = Arc::new(Mutex::new(None));
    let hooks = Arc::new(SimDsHooks {
        service_did: SIM_SELF.into(),
        self_endpoint: "https://ingress-auth.example".into(),
        signing_key_pem: None,
        group_relay_hmac_secret: None,
        http_transport: Arc::new({
            let authority = authority.clone();
            move |request: SimHttpRequest| -> Reply {
                let path = request.url.path();
                assert_eq!(path, /* did-web-test */ "/.well-known/did.json");
                let (status, body) = authority.lock().unwrap().clone().expect("a resolved host");
                Box::pin(async move {
                    Ok(::http::Response::builder()
                        .status(status)
                        .header("content-type", "application/json")
                        .body(serde_json::to_vec(&body).unwrap())
                        .unwrap())
                })
            }
        }),
        dns_resolver: Arc::new({
            let authority = authority.clone();
            move |_: &str| -> Result<Vec<std::net::IpAddr>, String> {
                match *authority.lock().unwrap() {
                    Some(_) => Ok(vec!["93.184.216.34".parse().unwrap()]),
                    None => Err("SERVFAIL".into()),
                }
            }
        }),
        retain_application_ciphertext: false,
    });
    let pool = sqlx::postgres::PgPoolOptions::new()
        .max_connections(1)
        .connect_lazy("postgres://127.0.0.1/federation_ingress_gate")
        .expect("lazy pool");
    let router = Router::new()
        .route(&format!("/xrpc/{NSID}"), post(deliver_message))
        .with_state(DsState { pool });
    // Signed by a key the peer's document does not declare.
    let now = chrono::Utc::now().timestamp();
    let claims = serde_json::json!({
        "iss": SIM_PEER, "aud": SIM_SELF, "lxm": NSID,
        "iat": now, "exp": now + 60, "jti": "ingress-auth-forged",
    });
    let signing_input = format!(
        "{}.{}",
        URL_SAFE_NO_PAD.encode(br#"{"alg":"ES256","typ":"JWT"}"#),
        URL_SAFE_NO_PAD.encode(serde_json::to_vec(&claims).unwrap())
    );
    let forged: Signature = SigningKey::from_bytes((&[0x42u8; 32]).into())
        .unwrap()
        .sign(signing_input.as_bytes());
    let token = format!(
        "{signing_input}.{}",
        URL_SAFE_NO_PAD.encode(forged.to_bytes())
    );

    scope_sim_ds(hooks, async {
        for (authority_answer, status, error, retry_after) in [
            (
                None,
                StatusCode::SERVICE_UNAVAILABLE,
                "DidResolutionUnavailable",
                Some("5"),
            ),
            (
                Some((503, Value::Null)),
                StatusCode::SERVICE_UNAVAILABLE,
                "DidResolutionUnavailable",
                Some("5"),
            ),
            (
                Some((404, Value::Null)),
                StatusCode::BAD_REQUEST,
                "DidResolutionFailed",
                None,
            ),
            (
                Some((200, document.clone())),
                StatusCode::UNAUTHORIZED,
                "InvalidSignature",
                None,
            ),
        ] {
            *authority.lock().unwrap() = authority_answer;
            let request = Request::post(format!("/xrpc/{NSID}"))
                .header("authorization", format!("Bearer {token}"))
                .body(Body::empty())
                .expect("request");
            let response = router.clone().oneshot(request).await.expect("route");
            let header = response
                .headers()
                .get(axum::http::header::RETRY_AFTER)
                .map(|value| value.to_str().unwrap().to_owned());
            let (actual, body) = status_and_body(response).await;
            assert_eq!(actual, status, "{body}");
            assert_eq!(body["error"], error, "{body}");
            assert_eq!(header.as_deref(), retry_after, "{body}");
        }
    })
    .await;
}
