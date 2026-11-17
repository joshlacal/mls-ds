//! C2 `fed-relay` survivor kills for `group_relay.rs` (w0a2 widened mutant
//! campaign, `mls-ds@4c0a4db2`).
//!
//! Each test names the scored survivors (`fr-…`) it kills; the remaining
//! assertions pin the sibling boundaries of the same predicates (unscored
//! specs in the same functions). No test here touches a database: states
//! carry a lazy pool aimed at a closed port, so a test that wrongly reached
//! the store fails instead of connecting anywhere. Nothing here edits
//! `group_relay.rs`, so every mutant span in
//! `w0a2-widened-mutant-specs.json` stays byte-identical.

use super::*;
use crate::chat_protocol::error::ChatProtocolErrorCode;
use crate::federation::errors::FederationError;

/// The status and JSON error body of an S2S answer.
async fn c2_answer(response: Response) -> (StatusCode, Value) {
    let status = response.status();
    let body = axum::body::to_bytes(response.into_body(), 64 * 1024)
        .await
        .unwrap();
    (status, serde_json::from_slice(&body).unwrap_or(Value::Null))
}

fn c2_expect(answer: &(StatusCode, Value), status: StatusCode, code: &str, message: &str) {
    assert_eq!(answer.0, status, "{}", answer.1);
    assert_eq!(answer.1["error"], code, "{}", answer.1);
    assert_eq!(answer.1["message"], message, "{}", answer.1);
}

fn c2_lazy_pool(name: &str) -> DbPool {
    sqlx::postgres::PgPoolOptions::new()
        .connect_lazy(&format!("postgres://127.0.0.1:1/{name}"))
        .unwrap()
}

fn c2_runtime() -> Arc<crate::handlers::chat::ChatRuntime> {
    Arc::new(
        crate::handlers::chat::ChatRuntime::from_env(Arc::new(crate::realtime::SseState::new(8)))
            .unwrap(),
    )
}

// ---------------------------------------------------------------------------
// Pure classifiers (no database)
// ---------------------------------------------------------------------------

/// Kills `fr-b75aa013570cd23c` (`group_relay.rs:532` Database arm deleted:
/// `Database` is also retryable, so it would answer 503) and
/// `fr-d184b819a205950c` (`:537` guard `error.is_retryable()` → `false`: a
/// member home that could not answer now would become a 403 refusal).
#[tokio::test]
async fn c2_added_member_failure_separates_store_retryable_and_refusal() {
    let cases = [
        (
            FederationError::Database(sqlx::Error::PoolTimedOut),
            StatusCode::INTERNAL_SERVER_ERROR,
            "InternalServerError",
        ),
        (
            FederationError::DsUnreachable {
                endpoint: "https://member-home.example.com".to_owned(),
                reason: "connect timeout".to_owned(),
            },
            StatusCode::SERVICE_UNAVAILABLE,
            "RelationshipPolicyUnavailable",
        ),
        (
            FederationError::RelationshipPolicyUnavailable {
                reason: "graph outage".to_owned(),
            },
            StatusCode::SERVICE_UNAVAILABLE,
            "RelationshipPolicyUnavailable",
        ),
        (
            FederationError::BlockedRelationship,
            StatusCode::FORBIDDEN,
            "NotAuthorized",
        ),
    ];
    for (error, status, code) in cases {
        let message = format!("added member: {error}");
        let answer = c2_answer(added_member_failure(&error, message.clone())).await;
        c2_expect(&answer, status, code, &message);
    }
    // `lookup_failure` keeps the same retryable/refusal split.
    let retryable = c2_answer(lookup_failure(FederationError::DsUnreachable {
        endpoint: "https://home.example.com".to_owned(),
        reason: "reset".to_owned(),
    }))
    .await;
    assert_eq!(retryable.0, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(retryable.1["error"], "ServiceUnavailable");
    let refused = c2_answer(lookup_failure(FederationError::BlockedRelationship)).await;
    assert_eq!(refused.0, StatusCode::FORBIDDEN);
    assert_eq!(refused.1["error"], "NotAuthorized");
}

/// Pins every `GroupRelayError::from_local` branch and the
/// `from_response` 4xx/5xx/429 boundaries (unscored `:562`, `:567`,
/// `:578`-`:581` specs).
#[test]
fn c2_group_relay_error_classifies_local_failures_and_status_boundaries() {
    assert!(matches!(
        GroupRelayError::from_local(FederationError::Database(sqlx::Error::PoolTimedOut)),
        GroupRelayError::Internal(_)
    ));
    assert!(matches!(
        GroupRelayError::from_local(FederationError::DsUnreachable {
            endpoint: "https://sequencer.example.com".to_owned(),
            reason: "reset".to_owned(),
        }),
        GroupRelayError::Unavailable(_)
    ));
    assert!(matches!(
        GroupRelayError::from_local(FederationError::ConfigError {
            reason: "signer".to_owned(),
        }),
        GroupRelayError::Internal(_)
    ));
    assert!(matches!(
        GroupRelayError::from_local(FederationError::BlockedRelationship),
        GroupRelayError::Rejected(ChatProtocolErrorCode::NotAuthorized)
    ));
    let named = br#"{"error":"NotAuthorized"}"#;
    for status in [400_u16, 403, 428, 499] {
        assert!(
            matches!(
                GroupRelayError::from_response(status, named),
                GroupRelayError::Rejected(ChatProtocolErrorCode::NotAuthorized)
            ),
            "{status}"
        );
        assert!(
            matches!(
                GroupRelayError::from_response(status, b"not json"),
                GroupRelayError::Rejected(ChatProtocolErrorCode::InvalidRequest)
            ),
            "{status}"
        );
    }
    for status in [429_u16, 500, 501, 599] {
        assert!(
            matches!(
                GroupRelayError::from_response(status, named),
                GroupRelayError::Unavailable(_)
            ),
            "{status}"
        );
    }
    // A named code outside 4xx (a refused redirect) is never trusted.
    for status in [302_u16, 399] {
        assert!(
            matches!(
                GroupRelayError::from_response(status, named),
                GroupRelayError::Rejected(ChatProtocolErrorCode::InvalidRequest)
            ),
            "{status}"
        );
    }
}

/// Kills `fr-cf7cf54a8fd3c9c7` (`group_relay.rs:628:46` `*` → `/`, which
/// shrinks the 2 MiB Welcome/coordinate headroom to zero bytes).
#[test]
fn c2_relay_answer_budget_keeps_two_mebibytes_of_headroom() {
    assert_eq!(
        RELAY_GROUP_MUTATION_RESPONSE_MAX_BYTES - SINGLE_MLS_ARTIFACT_BODY_LIMIT_BYTES,
        2_097_152
    );
    assert_eq!(RELAY_GROUP_MUTATION_RESPONSE_MAX_BYTES, 17 * 1024 * 1024);
}

fn c2_bearer_headers(authorization: &str) -> HeaderMap {
    let mut headers = HeaderMap::new();
    headers.insert(
        axum::http::header::AUTHORIZATION,
        authorization.parse().unwrap(),
    );
    headers
}

fn c2_token(claims: &[u8]) -> String {
    format!(
        "Bearer {}.{}.{}",
        URL_SAFE_NO_PAD.encode(br#"{"alg":"ES256"}"#),
        URL_SAFE_NO_PAD.encode(claims),
        URL_SAFE_NO_PAD.encode([7_u8; 64])
    )
}

/// Pins every `require_exact_s2s_scope` refusal (unscored `:388`, `:397`,
/// `:403` specs): framing, payload, audience and method each refuse alone.
#[test]
fn c2_exact_s2s_scope_refuses_each_malformed_or_foreign_token_alone() {
    use crate::auth::AuthError;
    const LXM: &str = "blue.catbird.mlsDS.deliverGroupEntry";
    assert!(matches!(
        require_exact_s2s_scope(&HeaderMap::new(), HOME, LXM),
        Err(AuthError::MissingAuthHeader)
    ));
    assert!(matches!(
        require_exact_s2s_scope(&c2_bearer_headers("Basic abc"), HOME, LXM),
        Err(AuthError::InvalidAuthFormat)
    ));
    for token in [
        "Bearer a.b",
        "Bearer a.b.c.d",
        "Bearer .b.c",
        "Bearer a..c",
        "Bearer a.b.",
        "Bearer a.!!!.c",
    ] {
        assert!(
            matches!(
                require_exact_s2s_scope(&c2_bearer_headers(token), HOME, LXM),
                Err(AuthError::InvalidToken(_))
            ),
            "{token}"
        );
    }
    assert!(matches!(
        require_exact_s2s_scope(&c2_bearer_headers(&c2_token(b"not-json")), HOME, LXM),
        Err(AuthError::InvalidToken(_))
    ));
    let claims = |aud: &str, lxm: Option<&str>| {
        let mut value = json!({ "aud": aud, "iss": SOURCE });
        if let Some(lxm) = lxm {
            value["lxm"] = json!(lxm);
        }
        c2_bearer_headers(&c2_token(&serde_json::to_vec(&value).unwrap()))
    };
    assert!(matches!(
        require_exact_s2s_scope(
            &claims(&format!("{HOME}#atproto_mls"), Some(LXM)),
            HOME,
            LXM
        ),
        Err(AuthError::InvalidToken(_))
    ));
    assert!(matches!(
        require_exact_s2s_scope(
            &claims(HOME, Some("blue.catbird.mlsDS.relayGroupMutation")),
            HOME,
            LXM
        ),
        Err(AuthError::LxmMismatch)
    ));
    assert!(matches!(
        require_exact_s2s_scope(&claims(HOME, None), HOME, LXM),
        Err(AuthError::MissingLxm)
    ));
    assert!(require_exact_s2s_scope(&claims(HOME, Some(LXM)), HOME, LXM).is_ok());
}

/// The simulation HMAC branch is taken only with both a caller and a MAC
/// (unscored `:435`/`:436` specs): either alone falls through to the bearer
/// path, a foreign target is refused before the MAC, and a wrong MAC is
/// refused. None of these reaches the pool.
#[tokio::test]
async fn c2_s2s_hmac_branch_needs_both_caller_and_mac_and_this_target() {
    crate::federation::open_federation_for_test();
    let state =
        GroupRelayState::for_test(c2_lazy_pool("c2_s2s_hmac"), HOME.to_string(), SECRET, None);
    let body = b"{}";
    let missing_bearer = crate::auth::AuthError::MissingAuthHeader.to_string();

    let mut caller_only = HeaderMap::new();
    caller_only.insert(S2S_CALLER_DID_HEADER, SOURCE.parse().unwrap());
    caller_only.insert(S2S_TARGET_DID_HEADER, HOME.parse().unwrap());
    let mut mac_only = HeaderMap::new();
    mac_only.insert(
        S2S_MAC_HEADER,
        compute_s2s_mac(SECRET, SOURCE, HOME, DELIVER, body)
            .parse()
            .unwrap(),
    );
    for headers in [caller_only, mac_only] {
        let answer = c2_answer(
            verify_s2s_caller(&state, &headers, DELIVER, body)
                .await
                .unwrap_err(),
        )
        .await;
        c2_expect(
            &answer,
            StatusCode::UNAUTHORIZED,
            "NotAuthorized",
            &missing_bearer,
        );
    }

    let mut foreign_target = hmac_headers(SOURCE, DELIVER, body);
    foreign_target.insert(S2S_TARGET_DID_HEADER, OTHER.parse().unwrap());
    let answer = c2_answer(
        verify_s2s_caller(&state, &foreign_target, DELIVER, body)
            .await
            .unwrap_err(),
    )
    .await;
    c2_expect(
        &answer,
        StatusCode::UNAUTHORIZED,
        "NotAuthorized",
        "target DID mismatch",
    );

    let wrong_mac = hmac_headers(SOURCE, DELIVER, b"{\"other\":true}");
    let answer = c2_answer(
        verify_s2s_caller(&state, &wrong_mac, DELIVER, body)
            .await
            .unwrap_err(),
    )
    .await;
    c2_expect(
        &answer,
        StatusCode::UNAUTHORIZED,
        "NotAuthorized",
        "invalid S2S MAC",
    );
}

/// Kills `fr-c3bc79f9c359f462` (`group_relay.rs:1260:73` `&&` → `||`: the
/// `error` name would admit `_`) and `fr-f1efd60a372fda0f` (`:1260:81`
/// `==` → `!=`: `reasonCode` would refuse `_` and admit any other byte),
/// plus the `1..=64` length window (unscored `:1258`). No database.
#[tokio::test]
async fn c2_remote_home_refusal_keeps_only_declared_identifier_shapes() {
    use crate::federation::outbound::OutboundError;
    const METHOD: &str = "/xrpc/blue.catbird.mlsDS.deliverGroupEntry";
    crate::federation::open_federation_for_test();
    let long = "A".repeat(64);
    let too_long = "A".repeat(65);
    let cases: Vec<(String, Option<&str>, Option<&str>)> = vec![
        (
            json!({"error":"NotAuthorized","reasonCode":"peer_blocked_2"}).to_string(),
            Some("NotAuthorized"),
            Some("peer_blocked_2"),
        ),
        (
            json!({"error":"Not_Authorized","reasonCode":"peerblocked"}).to_string(),
            None,
            Some("peerblocked"),
        ),
        (
            json!({"error":"NotAuthorized","reasonCode":"peer-blocked"}).to_string(),
            Some("NotAuthorized"),
            None,
        ),
        (
            json!({"error":"Not.Authorized","reasonCode":"peer blocked"}).to_string(),
            None,
            None,
        ),
        (
            json!({"error":long,"reasonCode":long}).to_string(),
            Some(long.as_str()),
            Some(long.as_str()),
        ),
        (
            json!({"error":too_long,"reasonCode":too_long}).to_string(),
            None,
            None,
        ),
        (json!({"error":"","reasonCode":""}).to_string(), None, None),
        (
            json!({"error":7,"reasonCode":["x"]}).to_string(),
            None,
            None,
        ),
        ("not json".to_owned(), None, None),
    ];
    let mut router = Router::new().route(
        &format!("/ok{METHOD}"),
        post(|| async { Json(json!({"accepted": true})) }),
    );
    for (index, (body, _, _)) in cases.iter().enumerate() {
        let body = body.clone();
        router = router.route(
            &format!("/c{index}{METHOD}"),
            post(move || {
                let body = body.clone();
                async move { (StatusCode::BAD_REQUEST, body) }
            }),
        );
    }
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let base = format!("http://{}", listener.local_addr().unwrap());
    let server = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
    let request = DeliverGroupEntryRequest {
        conversation_id: Uuid::new_v4(),
        generation: 0,
        space_uri: "at://did:web:relay-source.example.com/space/x".to_owned(),
        recipient_dids: Vec::new(),
        recipient_devices: Vec::new(),
        entry: json!({}),
        close_authority: None,
    };
    deliver_group_entry_to_remote_home(&format!("{base}/ok"), SOURCE, HOME, SECRET, &request)
        .await
        .expect("a 2xx home answer is delivered");
    for (index, (_, error, reason)) in cases.iter().enumerate() {
        match deliver_group_entry_to_remote_home(
            &format!("{base}/c{index}"),
            SOURCE,
            HOME,
            SECRET,
            &request,
        )
        .await
        {
            Err(OutboundError::RemoteError {
                status,
                error_name,
                reason_code,
                ..
            }) => {
                assert_eq!(status, 400, "case {index}");
                assert_eq!(error_name.as_deref(), *error, "case {index}");
                assert_eq!(reason_code.as_deref(), *reason, "case {index}");
            }
            other => panic!("case {index}: {other:?}"),
        }
    }
    server.abort();
}

/// Kills `fr-cc2c5407a17ca54f` (`group_relay.rs:3200` `||` → `&&`): a
/// deletion signed for another conversation, or by another sequencer, is
/// refused even when the receipt key would verify it. No database.
#[tokio::test]
async fn c2_account_deletion_binds_both_conversation_and_sequencer() {
    let sequencer = format!(
        "did:web:c2-deletion-{}.example.com",
        Uuid::new_v4().simple()
    );
    let impostor = format!(
        "did:web:c2-impostor-{}.example.com",
        Uuid::new_v4().simple()
    );
    let receipt_key = SigningKey::from_slice(&[0x63; 32]).unwrap();
    let receipt_document = |did: &str| {
        json!({
            "id": did,
            "verificationMethod": [{
                "id": format!("{did}#mls-receipt-1"),
                "type": "Multikey",
                "controller": did,
                "publicKeyMultibase":
                    crate::identity::did_doc::encode_p256_multikey(receipt_key.verifying_key()),
            }],
        })
    };
    let documents = HashMap::from([
        (sequencer.clone(), receipt_document(&sequencer)),
        (impostor.clone(), receipt_document(&impostor)),
    ]);
    let conversation_id = Uuid::new_v4();
    let deletion = crate::federation::receipt::AccountDeletion {
        sequencer_did: sequencer.clone(),
        conversation_id,
        deleted_did: "did:web:deleted.example.com".to_owned(),
        seq: 3,
        entry_id: Uuid::new_v4(),
        deleted_at: chrono::DateTime::from_timestamp_millis(chrono::Utc::now().timestamp_millis())
            .unwrap(),
        evidence: None,
    };
    let authority = I13ReceiptSigner::new(receipt_key.clone(), sequencer.clone())
        .sign_account_deletion(&deletion)
        .unwrap();
    let request = |conversation_id: Uuid| DeliverGroupEntryRequest {
        conversation_id,
        generation: 0,
        space_uri: format!(
            "at://{sequencer}/space/blue.catbird.labyrinth.conversation/{conversation_id}-0"
        ),
        recipient_dids: Vec::new(),
        recipient_devices: Vec::new(),
        entry: deletion.entry(&authority),
        close_authority: None,
    };
    let state = GroupRelayState::for_test(
        c2_lazy_pool("c2_deletion_binding"),
        HOME.to_string(),
        SECRET,
        None,
    );
    scope_sim_ds(hooks(documents), async {
        verify_account_deletion(&state, &sequencer, &request(conversation_id))
            .await
            .expect("the deletion's own conversation and sequencer verify");
        for (caller, conversation) in [
            (sequencer.as_str(), Uuid::new_v4()),
            (impostor.as_str(), conversation_id),
        ] {
            let answer = c2_answer(
                verify_account_deletion(&state, caller, &request(conversation))
                    .await
                    .unwrap_err(),
            )
            .await;
            c2_expect(
                &answer,
                StatusCode::FORBIDDEN,
                "NotAuthorized",
                "account deletion is not this conversation's sequencer's",
            );
        }
    })
    .await;
}

fn c2_device_revocation(
    actor: &str,
    device: Uuid,
    key: &ed25519_dalek::SigningKey,
) -> (Value, Vec<u8>) {
    let key_id =
        crate::chat_protocol::validation::ed25519_key_id(&key.verifying_key().to_bytes()).unwrap();
    let body = json!({
        "$type": "blue.catbird.chat.defs#deviceRevocationBody",
        "signatureDomain": "CATBIRD-CHAT-DEVICE-REVOKE\u{0}",
        "actorDid": actor, "actorDeviceId": device, "keyId": key_id.as_str(),
        "authGeneration": 1, "targetDeviceId": device, "targetAuthGeneration": 1,
        "idempotencyKey": Uuid::new_v4(),
        "signedAt": "2026-11-15T12:00:00.000Z",
    });
    let signed = sign_mutation_json_for_test(&body, key).unwrap();
    let bytes = serde_json::to_vec(&signed).unwrap();
    (signed, bytes)
}

/// Kills `fr-eadd1dca2fb49f2f` (`group_relay.rs:1428` guard
/// `value == request.signed_request` → `true`) and `fr-f3b22b3fc8e16f41`
/// (`:1456` `||` → `&&`: a matching DID would admit another device), with
/// the endpoint, bytes and DID refusals before any store access (unscored
/// `:1384`-`:1455`). No database.
#[tokio::test]
async fn c2_relayed_lifecycle_binds_exact_bytes_and_actor_device_before_admission() {
    let state = GroupRelayState::for_test(
        c2_lazy_pool("c2_lifecycle_binding"),
        HOME.to_string(),
        SECRET,
        None,
    )
    .with_chat_runtime(c2_runtime());
    let actor = "did:web:c2-lifecycle-actor.example.com";
    let device = Uuid::new_v4();
    let key = ed25519_dalek::SigningKey::from_bytes(&[0x64; 32]);
    let (signed, bytes) = c2_device_revocation(actor, device, &key);
    let request =
        |endpoint: &str, signed_request: Value, bytes: Option<String>, did: &str, device: Uuid| {
            RelayGroupMutationRequest {
                conversation_id: Uuid::new_v4(),
                endpoint: endpoint.to_owned(),
                actor_did: did.to_owned(),
                actor_device_id: device,
                signed_request,
                signed_request_bytes: bytes,
            }
        };
    let encoded = Some(STANDARD.encode(&bytes));
    const LEAVE: &str = "blue.catbird.chat.requestLeave";

    let unsupported = request(
        "blue.catbird.chat.sendMessage",
        signed.clone(),
        encoded.clone(),
        actor,
        device,
    );
    let answer = c2_answer(sequence_relayed_lifecycle(&state, SOURCE, &unsupported).await).await;
    c2_expect(
        &answer,
        StatusCode::BAD_REQUEST,
        "InvalidRequest",
        "unsupported relayed lifecycle endpoint",
    );

    let bare = request(LEAVE, signed.clone(), None, actor, device);
    let answer = c2_answer(sequence_relayed_lifecycle(&state, SOURCE, &bare).await).await;
    c2_expect(
        &answer,
        StatusCode::BAD_REQUEST,
        "InvalidRequest",
        "relayed lifecycle request lacks exact signed bytes",
    );

    // Parseable exact bytes whose value differs from the relayed value.
    let mut other_value = signed.clone();
    other_value["relayed"] = json!(true);
    let mismatched = request(LEAVE, other_value, encoded.clone(), actor, device);
    let answer = c2_answer(sequence_relayed_lifecycle(&state, SOURCE, &mismatched).await).await;
    c2_expect(
        &answer,
        StatusCode::BAD_REQUEST,
        "InvalidRequest",
        "signed request value does not match its exact bytes",
    );
    // Exact bytes that are not a signed mutation reach the canonical decoder.
    let junk = br#"{"junk":true}"#;
    let not_signed = request(
        LEAVE,
        serde_json::from_slice(junk).unwrap(),
        Some(STANDARD.encode(junk)),
        actor,
        device,
    );
    let answer = c2_answer(sequence_relayed_lifecycle(&state, SOURCE, &not_signed).await).await;
    assert_eq!(answer.0, StatusCode::BAD_REQUEST, "{}", answer.1);
    assert!(
        answer.1["message"]
            .as_str()
            .is_some_and(|message| message.starts_with("invalid signed request: ")),
        "{}",
        answer.1
    );

    for (did, device) in [
        (actor, Uuid::new_v4()),
        ("did:web:c2-other-actor.example.com", device),
    ] {
        let foreign = request(LEAVE, signed.clone(), encoded.clone(), did, device);
        let answer = c2_answer(sequence_relayed_lifecycle(&state, SOURCE, &foreign).await).await;
        c2_expect(
            &answer,
            StatusCode::FORBIDDEN,
            "NotAuthorized",
            "relayed lifecycle actor binding mismatch",
        );
    }
    // The bound actor passes the binding (a revocation then has no conversation).
    let bound = request(LEAVE, signed, encoded, actor, device);
    let answer = c2_answer(sequence_relayed_lifecycle(&state, SOURCE, &bound).await).await;
    c2_expect(
        &answer,
        StatusCode::BAD_REQUEST,
        "InvalidRequest",
        "signed lifecycle request has no conversation id",
    );
}

/// Unscored pure boundaries in `group_relay.rs` (`nonempty_group_relay_secret`
/// `:336`, `require_exact_s2s_scope` `:388`-`:406`, `verify_s2s_caller` HMAC
/// header guards `:435`-`:445`).
#[tokio::test]
async fn c2_nonempty_secret_and_exact_s2s_scope_boundaries() {
    assert_eq!(nonempty_group_relay_secret(String::new()), None);
    assert_eq!(
        nonempty_group_relay_secret(" \t\n ".to_owned()).as_deref(),
        Some(" \t\n ")
    );
    assert_eq!(
        nonempty_group_relay_secret("relay-secret".to_owned()).as_deref(),
        Some("relay-secret")
    );

    let auth_hdr = |token: &str| {
        let mut h = HeaderMap::new();
        h.insert(
            axum::http::header::AUTHORIZATION,
            axum::http::HeaderValue::from_str(&format!("Bearer {token}")).unwrap(),
        );
        h
    };
    let make_jwt = |claims: Value| {
        let header = URL_SAFE_NO_PAD.encode(br#"{"alg":"ES256","typ":"JWT"}"#);
        let payload = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&claims).unwrap());
        format!("{header}.{payload}.c2sig")
    };
    let ok_headers = auth_hdr(&make_jwt(json!({"aud": HOME, "lxm": DELIVER})));
    assert!(require_exact_s2s_scope(&ok_headers, HOME, DELIVER).is_ok());
    assert!(matches!(
        require_exact_s2s_scope(&HeaderMap::new(), HOME, DELIVER),
        Err(crate::auth::AuthError::MissingAuthHeader)
    ));

    for malformed in [
        "",
        "only-two.segments",
        ".payload.sig",
        "hdr..sig",
        "hdr.payload.",
        "hdr.payload.sig.extra",
        "hdr.%%%bad-b64%%%.sig",
        &format!(
            "{}.{}.sig",
            URL_SAFE_NO_PAD.encode(b"{}"),
            URL_SAFE_NO_PAD.encode(b"not-json")
        ),
    ] {
        assert!(
            matches!(
                require_exact_s2s_scope(&auth_hdr(malformed), HOME, DELIVER),
                Err(crate::auth::AuthError::InvalidToken(_))
            ),
            "{malformed}"
        );
    }
    assert!(matches!(
        require_exact_s2s_scope(&ok_headers, OTHER, DELIVER),
        Err(crate::auth::AuthError::InvalidToken(_))
    ));
    assert!(matches!(
        require_exact_s2s_scope(
            &auth_hdr(&make_jwt(
                json!({"aud": HOME, "lxm": "blue.catbird.mlsDS.other"})
            )),
            HOME,
            DELIVER
        ),
        Err(crate::auth::AuthError::LxmMismatch)
    ));
    assert!(matches!(
        require_exact_s2s_scope(&auth_hdr(&make_jwt(json!({"aud": HOME}))), HOME, DELIVER),
        Err(crate::auth::AuthError::MissingLxm)
    ));

    crate::federation::open_federation_for_test();
    let state = GroupRelayState::for_test(
        c2_lazy_pool("c2_s2s_hmac_guards"),
        HOME.to_owned(),
        SECRET,
        None,
    );
    let body = br#"{"hello":"world"}"#;
    let mut wrong_target = hmac_headers(SOURCE, DELIVER, body);
    wrong_target.insert(
        S2S_TARGET_DID_HEADER,
        axum::http::HeaderValue::from_static(OTHER),
    );
    let answer = c2_answer(
        verify_s2s_caller(&state, &wrong_target, DELIVER, body)
            .await
            .unwrap_err(),
    )
    .await;
    c2_expect(
        &answer,
        StatusCode::UNAUTHORIZED,
        "NotAuthorized",
        "target DID mismatch",
    );

    let mut empty_caller = hmac_headers(SOURCE, DELIVER, body);
    empty_caller.insert(
        S2S_CALLER_DID_HEADER,
        axum::http::HeaderValue::from_static("   "),
    );
    let answer = c2_answer(
        verify_s2s_caller(&state, &empty_caller, DELIVER, body)
            .await
            .unwrap_err(),
    )
    .await;
    assert_eq!(answer.0, StatusCode::UNAUTHORIZED);

    let mut empty_mac = hmac_headers(SOURCE, DELIVER, body);
    empty_mac.insert(S2S_MAC_HEADER, axum::http::HeaderValue::from_static(""));
    let answer = c2_answer(
        verify_s2s_caller(&state, &empty_mac, DELIVER, body)
            .await
            .unwrap_err(),
    )
    .await;
    assert_eq!(answer.0, StatusCode::UNAUTHORIZED);
}

/// Unscored pure classifiers in `GroupRelayError::from_response` (`:562`) and
/// `GroupRelayError::from_local` (`:578`-`:582`).
#[test]
fn c2_group_relay_error_response_and_local_classification() {
    for status in [429_u16, 500, 502, 503] {
        assert!(
            matches!(
                GroupRelayError::from_response(status, br#"{"error":"NotAuthorized"}"#),
                GroupRelayError::Unavailable(_)
            ),
            "{status}"
        );
    }
    assert!(matches!(
        GroupRelayError::from_response(403, br#"{"error":"NotAuthorized"}"#),
        GroupRelayError::Rejected(ChatProtocolErrorCode::NotAuthorized)
    ));
    assert!(matches!(
        GroupRelayError::from_response(400, br#"{"error":"UndeclaredCode"}"#),
        GroupRelayError::Rejected(ChatProtocolErrorCode::InvalidRequest)
    ));
    assert!(matches!(
        GroupRelayError::from_response(302, br#"{"error":"NotAuthorized"}"#),
        GroupRelayError::Rejected(ChatProtocolErrorCode::InvalidRequest)
    ));

    assert!(matches!(
        GroupRelayError::from_local(FederationError::Database(sqlx::Error::PoolTimedOut)),
        GroupRelayError::Internal(_)
    ));
    assert!(matches!(
        GroupRelayError::from_local(FederationError::DsUnreachable {
            endpoint: "https://peer.example.com".into(),
            reason: "timeout".into(),
        }),
        GroupRelayError::Unavailable(_)
    ));
    assert!(matches!(
        GroupRelayError::from_local(FederationError::ConfigError {
            reason: "missing key".into(),
        }),
        GroupRelayError::Internal(_)
    ));
    assert!(matches!(
        GroupRelayError::from_local(FederationError::Forbidden("blocked".into())),
        GroupRelayError::Rejected(ChatProtocolErrorCode::NotAuthorized)
    ));
}
