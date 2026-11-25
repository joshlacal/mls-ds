use super::*;
use crate::{
    chat_protocol::test_support::{
        seed_clean_slate_application_fixture_unsealed,
        seed_clean_slate_application_fixture_with_sender_home,
        seed_remote_clean_slate_application_fixture, sign_mutation_json_for_test,
        CleanSlateApplicationFixture,
    },
    sim_hooks::{scope_ds_clock, scope_sim_ds, ManualDsClock, SimDsHooks},
};
use p256::ecdsa::{signature::Signer as _, Signature, SigningKey};
use std::collections::HashMap;

// `chat.is_bare_did` (participant and remote routing checks) needs a dotted host.
const HOME: &str = "did:web:relay-home.example.com";
const HOME_URL: &str = "https://relay-home.example.com";
const SOURCE: &str = "did:web:relay-source.example.com";
const OTHER: &str = "did:web:relay-other.example.com";
const SECRET: &[u8] = b"group-relay-security-regression-secret";
const DELIVER: &str = "blue.catbird.mlsDS.deliverGroupEntry";

fn manual_clock() -> Arc<ManualDsClock> {
    let now =
        chrono::DateTime::from_timestamp_millis(chrono::Utc::now().timestamp_millis()).unwrap();
    Arc::new(ManualDsClock::new(now))
}

fn hooks(documents: HashMap<String, Value>) -> Arc<SimDsHooks> {
    hooks_with_device_records(documents, HashMap::new())
}

fn hooks_with_device_records(
    documents: HashMap<String, Value>,
    device_keys: HashMap<String, [u8; 32]>,
) -> Arc<SimDsHooks> {
    Arc::new(SimDsHooks {
        service_did: HOME.to_string(),
        self_endpoint: HOME_URL.to_string(),
        signing_key_pem: None,
        group_relay_hmac_secret: None,
        http_transport: Arc::new(move |request| {
            let did = format!("did:web:{}", request.url.host_str().unwrap_or_default());
            let repo = request
                .url
                .query_pairs()
                .find_map(|(key, value)| (key == "repo").then(|| value.into_owned()));
            let response = if request.url.path() == /* did-web-test */ "/.well-known/did.json" {
                documents.get(&did).cloned()
            } else {
                repo.and_then(|repo| {
                    device_keys.get(&repo).map(|key| match request.url.path() {
                        "/xrpc/com.atproto.repo.getRecord" => json!({
                            "uri": format!("at://{repo}/blue.catbird.chat.declaration/self"),
                            "value": {
                                "$type": "blue.catbird.chat.declaration",
                                "protocolVersion": "2",
                                "allowIncoming": "all",
                                "deliveryService": HOME,
                                "createdAt": "2026-07-15T12:00:00Z",
                            },
                        }),
                        "/xrpc/com.atproto.repo.listRecords" => json!({"records": [{"value": {
                            "mlsSignaturePublicKey": {"$bytes": STANDARD.encode(key)},
                            "algorithm": "ed25519",
                            "createdAt": "2026-07-15T12:00:00Z",
                        }}]}),
                        _ => Value::Null,
                    })
                })
            }
            .filter(|value| !value.is_null())
            .map(|value| serde_json::to_vec(&value).unwrap());
            Box::pin(async move {
                let body =
                    response.ok_or_else(|| format!("unexpected server HTTP: {}", request.url))?;
                Ok(http::Response::builder()
                    .header("content-type", "application/json")
                    .body(body)
                    .unwrap())
            })
        }),
        dns_resolver: Arc::new(|_| Ok(vec!["93.184.216.34".parse().unwrap()])),
        retain_application_ciphertext: false,
    })
}

fn service_document(did: &str, key: &SigningKey) -> Value {
    json!({
        "id": did,
        "verificationMethod": [{
            "id": format!("{did}#atproto"),
            "type": "Multikey", "controller": did,
            "publicKeyMultibase": crate::identity::did_doc::encode_p256_multikey(key.verifying_key()),
        }],
    })
}

fn bearer_for_audience(issuer: &str, key: &SigningKey, audience: &str, method: &str) -> HeaderMap {
    let now = crate::sim_hooks::current_utc().timestamp();
    let header = URL_SAFE_NO_PAD.encode(br##"{"alg":"ES256","typ":"JWT","kid":"#atproto"}"##);
    let payload = URL_SAFE_NO_PAD.encode(
        serde_json::to_vec(&json!({
            "iss": issuer, "aud": audience,
            "iat": now, "exp": now + 60, "lxm": method, "jti": Uuid::new_v4(),
        }))
        .unwrap(),
    );
    let input = format!("{header}.{payload}");
    let signature: Signature = key.sign(input.as_bytes());
    let mut headers = HeaderMap::new();
    headers.insert(
        "authorization",
        format!(
            "Bearer {input}.{}",
            URL_SAFE_NO_PAD.encode(signature.to_bytes())
        )
        .parse()
        .unwrap(),
    );
    headers
}

fn bearer(issuer: &str, key: &SigningKey, method: &str) -> HeaderMap {
    bearer_for_audience(issuer, key, HOME, method)
}

fn hmac_headers(caller: &str, method: &str, body: &[u8]) -> HeaderMap {
    let mut headers = HeaderMap::new();
    headers.insert(S2S_CALLER_DID_HEADER, caller.parse().unwrap());
    headers.insert(S2S_TARGET_DID_HEADER, HOME.parse().unwrap());
    headers.insert(
        S2S_MAC_HEADER,
        compute_s2s_mac(SECRET, caller, HOME, method, body)
            .parse()
            .unwrap(),
    );
    headers
}

async fn protocol_error(response: Response, status: StatusCode, code: &str) {
    let actual = response.status();
    let body = axum::body::to_bytes(response.into_body(), 64 * 1024)
        .await
        .unwrap();
    let error: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(actual, status, "{error}");
    assert_eq!(error["error"], code, "{error}");
}

async fn effects(pool: &DbPool, cid: Uuid) -> Vec<i64> {
    sqlx::query_scalar(
        "SELECT ARRAY[ \
            (SELECT count(*) FROM chat.events), \
            (SELECT count(*) FROM chat.event_recipients), \
            (SELECT count(*) FROM chat.conversation_close_terminal_entries), \
            (SELECT count(*) FROM chat.conversations WHERE conversation_id=$1), \
            (SELECT count(*) FROM chat.entries WHERE conversation_id=$1), \
            (SELECT count(*) FROM chat.message_sends WHERE conversation_id=$1), \
            (SELECT count(*) FROM chat.participants WHERE conversation_id=$1), \
            (SELECT count(*) FROM chat.member_devices WHERE conversation_id=$1), \
            (SELECT count(*) FROM chat.application_intervals WHERE conversation_id=$1), \
            (SELECT count(*) FROM chat.entry_recipients WHERE conversation_id=$1), \
            (SELECT count(*) FROM chat.direct_request_transport_inbox WHERE conversation_id=$1), \
            (SELECT count(*) FROM chat.direct_request_transport_entries WHERE conversation_id=$1), \
            (SELECT count(*) FROM federation_outbox), (SELECT count(*) FROM outbound_queue), \
            COALESCE((SELECT next_entry_seq FROM chat.conversations WHERE conversation_id=$1),-1), \
            COALESCE((SELECT current_state_version FROM chat.conversations WHERE conversation_id=$1),-1) \
         ]::bigint[]",
    ).bind(cid).fetch_one(pool).await.unwrap()
}

async fn allow(pool: &DbPool, did: &str) {
    sqlx::query("INSERT INTO federation_peers(ds_did,status) VALUES($1,'allow') ON CONFLICT(ds_did) DO UPDATE SET status='allow'")
        .bind(did).execute(pool).await.unwrap();
}

#[tokio::test]
async fn s2s_bearer_and_hmac_cannot_bypass_peer_allowlist() {
    struct RestoreMode(Option<String>);
    impl Drop for RestoreMode {
        fn drop(&mut self) {
            match &self.0 {
                Some(value) => std::env::set_var("FEDERATION_MODE", value),
                None => std::env::remove_var("FEDERATION_MODE"),
            }
        }
    }
    let database = crate::common::fresh_db::fresh_fully_migrated_db("chat_fed_relay_").await;
    let pool = database.connect(2).await;
    crate::common::http_acceptance::ensure_fence(&pool).await;
    let _restore = RestoreMode(std::env::var("FEDERATION_MODE").ok());
    std::env::set_var("FEDERATION_MODE", "allowlist");
    let key = SigningKey::from_slice(&[17; 32]).unwrap();
    let clock = manual_clock();
    scope_ds_clock(clock, scope_sim_ds(hooks(HashMap::new()), async {
        crate::sim_hooks::seed_sim_did_document(serde_json::from_value(service_document(SOURCE, &key)).unwrap()).await;
        let state = GroupRelayState::for_test(pool.clone(), HOME.to_string(), SECRET, None);
        let body = b"{}";
        for policy in ["allow", "block", "absent"] {
            if policy == "absent" {
                sqlx::query("DELETE FROM federation_peers WHERE ds_did=$1").bind(SOURCE).execute(&pool).await.unwrap();
            } else {
                sqlx::query("INSERT INTO federation_peers(ds_did,status) VALUES($1,$2) ON CONFLICT(ds_did) DO UPDATE SET status=EXCLUDED.status")
                    .bind(SOURCE).bind(policy).execute(&pool).await.unwrap();
            }
            let before = effects(&pool, Uuid::nil()).await;
            for headers in [
                bearer(SOURCE, &key, DELIVER),
                hmac_headers(SOURCE, DELIVER, body),
            ] {
                let result = verify_s2s_caller(&state, &headers, DELIVER, body).await;
                if policy == "allow" {
                    assert_eq!(result.unwrap(), SOURCE);
                } else {
                    protocol_error(result.unwrap_err(), StatusCode::FORBIDDEN, "NotAuthorized").await;
                }
                assert_eq!(effects(&pool, Uuid::nil()).await, before);
            }
        }
        let admitted_tokens: i64 = sqlx::query_scalar("SELECT count(*) FROM auth_jti_nonce WHERE issuer_did=$1")
            .bind(SOURCE).fetch_one(&pool).await.unwrap();
        assert_eq!(admitted_tokens, 3, "the exact Bearer token passed cryptographic/replay admission before peer policy in all three cases");
    })).await;
    pool.close().await;
}

#[tokio::test]
async fn s2s_bearer_requires_the_exact_target_and_method() {
    crate::federation::open_federation_for_test();
    let pool = sqlx::postgres::PgPoolOptions::new()
        .connect_lazy("postgres://127.0.0.1/s2s_exact_scope")
        .unwrap();
    let state = GroupRelayState::for_test(pool, HOME.to_string(), SECRET, None);
    let key = SigningKey::from_slice(&[18; 32]).unwrap();
    for headers in [
        bearer_for_audience(SOURCE, &key, &format!("{HOME}#atproto_mls"), DELIVER),
        bearer(SOURCE, &key, "blue.catbird.mlsDS.relayGroupMutation"),
    ] {
        let response = verify_s2s_caller(&state, &headers, DELIVER, b"{}")
            .await
            .expect_err("non-exact service scope must be refused before issuer admission");
        protocol_error(response, StatusCode::UNAUTHORIZED, "NotAuthorized").await;
    }
}

fn application_request(
    fixture: &CleanSlateApplicationFixture,
    signed_request: Value,
) -> RelayGroupMutationRequest {
    RelayGroupMutationRequest {
        conversation_id: fixture.conversation_id,
        endpoint: "blue.catbird.chat.sendMessage".to_string(),
        actor_did: fixture.sender_did.clone(),
        actor_device_id: signed_request["body"]["actorDeviceId"]
            .as_str()
            .unwrap()
            .parse()
            .unwrap(),
        signed_request,
        signed_request_bytes: None,
    }
}

async fn reject_application_unchanged(
    state: &GroupRelayState,
    caller: &str,
    request: &RelayGroupMutationRequest,
    status: StatusCode,
) {
    let before = effects(&state.pool, request.conversation_id).await;
    let error = sequence_relayed_group_application_send(state, caller, request)
        .await
        .unwrap_err();
    protocol_error(error, status, "NotAuthorized").await;
    assert_eq!(effects(&state.pool, request.conversation_id).await, before);
}

#[tokio::test]
async fn group_application_relay_checks_home_leaf_device_key_and_pruned_replay() {
    crate::federation::open_federation_for_test();
    let database = crate::common::fresh_db::fresh_fully_migrated_db("chat_fed_relay_").await;
    let pool = database.connect(4).await;
    crate::common::http_acceptance::ensure_fence(&pool).await;
    let fixture = seed_clean_slate_application_fixture_with_sender_home(
        &pool,
        false,
        OTHER,
        Some([31; 32]),
        Some(SOURCE),
    )
    .await
    .unwrap();
    let direct = seed_clean_slate_application_fixture_with_sender_home(
        &pool,
        true,
        OTHER,
        Some([32; 32]),
        Some(SOURCE),
    )
    .await
    .unwrap();
    let state = GroupRelayState::for_test(pool.clone(), HOME.to_string(), SECRET, None);
    let key = ed25519_dalek::SigningKey::from_bytes(&fixture.sender_ed25519_seed);
    let clock = manual_clock();
    scope_ds_clock(clock, scope_sim_ds(hooks(HashMap::new()), async {
        let request = application_request(&fixture, fixture.signed_request.clone());
        reject_application_unchanged(&state, OTHER, &request, StatusCode::FORBIDDEN).await;
        reject_application_unchanged(&state, SOURCE, &application_request(&direct, direct.signed_request.clone()), StatusCode::UNAUTHORIZED).await;

        let mut body = fixture.signed_request["body"].clone();
        body["authGeneration"] = json!(2);
        let wrong_generation = sign_mutation_json_for_test(&body, &key).unwrap();
        reject_application_unchanged(&state, SOURCE, &application_request(&fixture, wrong_generation), StatusCode::FORBIDDEN).await;

        let nonmember_key = ed25519_dalek::SigningKey::from_bytes(&[41; 32]);
        let nonmember_device = Uuid::new_v4();
        let nonmember_key_id = crate::common::executor_seed::seed_actor(&pool, &fixture.sender_did, nonmember_device, &nonmember_key.verifying_key().to_bytes()).await;
        let mut body = fixture.signed_request["body"].clone();
        body["actorDeviceId"] = json!(nonmember_device);
        body["keyId"] = json!(nonmember_key_id);
        let missing_leaf = sign_mutation_json_for_test(&body, &nonmember_key).unwrap();
        reject_application_unchanged(&state, SOURCE, &application_request(&fixture, missing_leaf), StatusCode::FORBIDDEN).await;

        let before = effects(&pool, fixture.conversation_id).await;
        let accepted = sequence_relayed_group_application_send(&state, SOURCE, &request).await.unwrap();
        let seq = accepted.entry["seq"].as_i64().unwrap();
        assert_eq!(seq, before[14]);
        let mut tx = pool.begin().await.unwrap();
        assert!(crate::chat_protocol::repository::delivery::prune_application_entry_payload(&mut tx, fixture.conversation_id, seq, crate::sim_hooks::current_utc()).await.unwrap());
        tx.commit().await.unwrap();
        let pruned = effects(&pool, fixture.conversation_id).await;
        // The same signed send replays as its accepted outcome (binding contract):
        // the pruned entry `getEntries` serves, with nothing fanned out again.
        let mut served = accepted.entry.clone();
        served.as_object_mut().unwrap().remove("signedRequest");
        served["payloadPruned"] = json!(true);
        let replayed = sequence_relayed_group_application_send(&state, SOURCE, &request).await.unwrap();
        assert_eq!(replayed.entry, served);
        assert_eq!(effects(&pool, fixture.conversation_id).await, pruned);
        let payloads_absent: bool = sqlx::query_scalar("SELECT e.accepted_payload_bytes IS NULL AND e.signed_request_bytes IS NULL AND s.outcome_bytes IS NULL AND s.signed_request_bytes IS NULL FROM chat.entries e JOIN chat.message_sends s ON s.conversation_id=e.conversation_id AND s.accepted_entry_seq=e.seq WHERE e.conversation_id=$1 AND e.seq=$2")
            .bind(fixture.conversation_id).bind(seq).fetch_one(&pool).await.unwrap();
        assert!(payloads_absent, "a replay must never repopulate pruned ciphertext");

        let rotated = ed25519_dalek::SigningKey::from_bytes(&[42; 32]);
        let rotated_id = crate::chat_protocol::validation::ed25519_key_id(&rotated.verifying_key().to_bytes()).unwrap();
        let now = crate::sim_hooks::current_utc();
        let mut tx = pool.begin().await.unwrap();
        sqlx::query("UPDATE chat.devices SET auth_generation=2,dpop_jkt=$3,updated_at=$4 WHERE user_did=$1 AND device_id=$2")
            .bind(&fixture.sender_did).bind(fixture.sender_device_id).bind(URL_SAFE_NO_PAD.encode([43; 32])).bind(now).execute(&mut *tx).await.unwrap();
        sqlx::query("INSERT INTO chat.device_keys(user_did,device_id,key_id,signing_public_key,enrollment_auth_generation,created_at) VALUES($1,$2,$3,$4,2,$5)")
            .bind(&fixture.sender_did).bind(fixture.sender_device_id).bind(rotated_id.as_str()).bind(rotated.verifying_key().to_bytes().as_slice()).bind(now).execute(&mut *tx).await.unwrap();
        tx.commit().await.unwrap();
        let mut body = fixture.signed_request["body"].clone();
        body["authGeneration"] = json!(2);
        let stale_key = sign_mutation_json_for_test(&body, &key).unwrap();
        reject_application_unchanged(&state, SOURCE, &application_request(&fixture, stale_key), StatusCode::FORBIDDEN).await;

        revoke_sender(&pool, &fixture, &rotated, rotated_id.as_str(), 2).await;
        body["keyId"] = json!(rotated_id.as_str());
        let revoked = sign_mutation_json_for_test(&body, &rotated).unwrap();
        reject_application_unchanged(&state, SOURCE, &application_request(&fixture, revoked), StatusCode::FORBIDDEN).await;
    })).await;
    pool.close().await;
}

/// A member home's relayed group application send runs the traffic
/// relationship check a local send runs, for the verified sender under the
/// sequencer's locks and before anything is stored: a block is the declared
/// `BlockedRelationship` refusal (never the caller's authentication failure),
/// a source that could not answer now is the retryable 503, this store failing
/// is 500, and none writes anything. The identical send then sequences once
/// and replays unchanged even after a block appears; another body under its
/// message ID is still the idempotency conflict.
#[tokio::test]
async fn relayed_application_send_runs_the_local_traffic_relationship_check() {
    use crate::chat_protocol::relationship_policy::{
        PublicResponse, SimSourceFault, TransportError,
    };
    crate::federation::open_federation_for_test();
    let database = crate::common::fresh_db::fresh_fully_migrated_db("chat_fed_relay_").await;
    let pool = database.connect(4).await;
    crate::common::http_acceptance::ensure_fence(&pool).await;
    // Unsealed: the sequencer's own authority collects the sender's evidence.
    let fixture =
        seed_clean_slate_application_fixture_unsealed(&pool, false, OTHER, None, Some(SOURCE))
            .await
            .unwrap();
    let relationships = SimSourceFault::default();
    let runtime =
        crate::handlers::chat::ChatRuntime::from_env(Arc::new(crate::realtime::SseState::new(8)))
            .unwrap()
            .with_sim_faulty_relationships(relationships.clone())
            .unwrap();
    let state = GroupRelayState::for_test(pool.clone(), HOME.to_string(), SECRET, None)
        .with_relationship_authority_of(&runtime);
    let (cid, request) = (
        fixture.conversation_id,
        application_request(&fixture, fixture.signed_request.clone()),
    );
    let blocked = Ok(PublicResponse::json(
        200,
        json!({ "relationships": [{
            "$type": "app.bsky.graph.defs#relationship",
            "did": fixture.recipient_did,
            "blocking": format!("at://{}/app.bsky.graph.block/relay", fixture.sender_did),
        }]}),
    ));
    let written = || async {
        let evidence: i64 =
            sqlx::query_scalar("SELECT count(*) FROM chat.relationship_projection_snapshots")
                .fetch_one(&pool)
                .await
                .unwrap();
        (effects(&pool, cid).await, evidence)
    };
    scope_ds_clock(manual_clock(), scope_sim_ds(hooks(HashMap::new()), async {
        let before = written().await;
        for (answer, status, code) in [
            (blocked.clone(), StatusCode::BAD_REQUEST, "BlockedRelationship"),
            (Err(TransportError::Network), StatusCode::SERVICE_UNAVAILABLE, "RelationshipPolicyUnavailable"),
            (Ok(PublicResponse::new(503, Vec::new())), StatusCode::SERVICE_UNAVAILABLE, "RelationshipPolicyUnavailable"),
            (Ok(PublicResponse::new(429, Vec::new())), StatusCode::SERVICE_UNAVAILABLE, "RelationshipPolicyUnavailable"),
        ] {
            *relationships.lock().unwrap() = Some(answer);
            let error = sequence_relayed_group_application_send(&state, SOURCE, &request).await.unwrap_err();
            protocol_error(error, status, code).await;
            assert_eq!(written().await, before, "{code}: nothing is stored");
        }
        *relationships.lock().unwrap() = None;
        // This store failing while the check reads its evidence decided nothing.
        sqlx::query("ALTER TABLE chat.relationship_projection_snapshots RENAME TO relationship_projection_offline")
            .execute(&pool).await.unwrap();
        let failed = sequence_relayed_group_application_send(&state, SOURCE, &request).await;
        sqlx::query("ALTER TABLE chat.relationship_projection_offline RENAME TO relationship_projection_snapshots")
            .execute(&pool).await.unwrap();
        protocol_error(failed.unwrap_err(), StatusCode::INTERNAL_SERVER_ERROR, "InternalServerError").await;
        assert_eq!(written().await, before, "store failure: nothing is stored");
        // A caller that does not home the sender, or a request naming another
        // actor than the signed one, is refused before the check.
        reject_application_unchanged(&state, OTHER, &request, StatusCode::FORBIDDEN).await;
        let mut forged = request.clone();
        forged.actor_did = fixture.recipient_did.clone();
        reject_application_unchanged(&state, SOURCE, &forged, StatusCode::UNAUTHORIZED).await;

        let accepted = sequence_relayed_group_application_send(&state, SOURCE, &request).await.unwrap();
        assert_eq!(accepted.entry["seq"].as_i64(), Some(before.0[14]));
        let sequenced = written().await;
        assert_ne!(sequenced, before);
        *relationships.lock().unwrap() = Some(blocked);
        let replayed = sequence_relayed_group_application_send(&state, SOURCE, &request).await.unwrap();
        assert_eq!(replayed.entry, accepted.entry, "an accepted send replays unchanged");
        assert_eq!(written().await, sequenced);
        let mut body = fixture.signed_request["body"].clone();
        body["signedAt"] = json!(crate::sim_hooks::current_utc().to_rfc3339_opts(chrono::SecondsFormat::Millis, true));
        let key = ed25519_dalek::SigningKey::from_bytes(&fixture.sender_ed25519_seed);
        let other_body = application_request(&fixture, sign_mutation_json_for_test(&body, &key).unwrap());
        let error = sequence_relayed_group_application_send(&state, SOURCE, &other_body).await.unwrap_err();
        protocol_error(error, StatusCode::CONFLICT, "IdempotencyConflict").await;
        assert_eq!(written().await, sequenced);
    })).await;
    pool.close().await;
}

/// A relationship source under which the queried actor blocks every member.
#[derive(Clone)]
struct BlockingGraph;

#[async_trait::async_trait]
impl crate::chat_protocol::relationship_policy::PublicTransport for BlockingGraph {
    async fn get(
        &self,
        request: crate::chat_protocol::relationship_policy::PublicGet,
    ) -> Result<
        crate::chat_protocol::relationship_policy::PublicResponse,
        crate::chat_protocol::relationship_policy::TransportError,
    > {
        if request.url.path() != "/xrpc/app.bsky.graph.getRelationships" {
            return crate::chat_protocol::test_support::DeterministicTestTransport
                .get(request)
                .await;
        }
        let query = |name: &str| {
            request
                .url
                .query_pairs()
                .filter(|(key, _)| key == name)
                .map(|(_, value)| value.into_owned())
                .collect::<Vec<_>>()
        };
        let actor = query("actor").remove(0);
        let relationships = query("others")
            .into_iter()
            .map(|did| {
                json!({
                    "$type": "app.bsky.graph.defs#relationship",
                    "did": did,
                    "blocking": format!("at://{actor}/app.bsky.graph.block/relay"),
                })
            })
            .collect::<Vec<_>>();
        Ok(
            crate::chat_protocol::relationship_policy::PublicResponse::json(
                200,
                json!({ "actor": actor, "relationships": relationships }),
            ),
        )
    }
}

/// A relayed policy add the relationship policy refuses is the refusal a
/// local add answers, `BlockedRelationship`: neither `InvalidRequest` nor an
/// authentication failure.
#[tokio::test]
async fn a_relayed_policy_add_across_a_block_is_the_local_refusal() {
    crate::federation::open_federation_for_test();
    let database = crate::common::fresh_db::fresh_fully_migrated_db("chat_fed_relay_").await;
    let pool = database.connect(4).await;
    crate::common::http_acceptance::ensure_fence(&pool).await;
    let fixture =
        seed_clean_slate_application_fixture_unsealed(&pool, false, OTHER, None, Some(SOURCE))
            .await
            .unwrap();
    let invitee = format!(
        "did:web:relay-invitee-{}.example.com",
        Uuid::new_v4().simple()
    );
    sqlx::query(
        "INSERT INTO chat.principals (user_did, created_at) VALUES ($1, clock_timestamp())",
    )
    .bind(&invitee)
    .execute(&pool)
    .await
    .unwrap();
    let prior = fixture.signed_request["body"]["prior"].clone();
    let mut next = prior.clone();
    next["stateVersion"] = json!(prior["stateVersion"].as_u64().unwrap() + 1);
    let transition_id = Uuid::new_v4();
    let body = json!({
        "$type": "blue.catbird.chat.defs#policyTransitionBody",
        "signatureDomain": "CATBIRD-CHAT-POLICY\u{0000}",
        "transitionId": transition_id,
        "actorDid": fixture.sender_did,
        "actorDeviceId": fixture.sender_device_id,
        "keyId": fixture.sender_key_id,
        "authGeneration": 1,
        "prior": prior,
        "next": next,
        "participantChanges": [{
            "$type": "blue.catbird.chat.defs#addParticipant",
            "userDid": invitee,
            "status": "pending",
            "role": "member",
            "invitationProvenance": {
                "invitedByDid": fixture.sender_did,
                "invitedByDeviceId": fixture.sender_device_id,
                "invitationTransitionId": transition_id,
            },
        }],
        "idempotencyKey": transition_id,
        "signedAt": crate::sim_hooks::current_utc().to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
    });
    let key = ed25519_dalek::SigningKey::from_bytes(&fixture.sender_ed25519_seed);
    let signed = serde_json::to_vec(&sign_mutation_json_for_test(&body, &key).unwrap()).unwrap();
    let authority = crate::chat_protocol::relationship_policy::RelationshipAuthority::new(
        crate::chat_protocol::relationship_policy::fixed_production_relationship_policy_config()
            .unwrap(),
        BlockingGraph,
    );
    let mut tx = pool.begin().await.unwrap();
    // As the sequencer HOME: its identity scopes the relayed sequencing.
    let refused = scope_sim_ds(
        hooks(HashMap::new()),
        crate::chat_protocol::repository::federation::sequence_relayed_group_transition(
            &mut tx,
            SOURCE,
            fixture.conversation_id,
            signed,
            None,
            &authority,
            None,
        ),
    )
    .await;
    tx.rollback().await.unwrap();
    assert!(
        matches!(
            refused,
            Err(crate::federation::FederationError::BlockedRelationship)
        ),
        "{refused:?}"
    );
    pool.close().await;
}

async fn revoke_sender(
    pool: &DbPool,
    fixture: &CleanSlateApplicationFixture,
    key: &ed25519_dalek::SigningKey,
    key_id: &str,
    generation: i64,
) {
    let at = crate::sim_hooks::current_utc();
    let operation = Uuid::new_v4();
    let body = json!({
        "$type":"blue.catbird.chat.defs#deviceRevocationBody", "signatureDomain":"CATBIRD-CHAT-DEVICE-REVOKE\u{0}",
        "actorDid":fixture.sender_did, "actorDeviceId":fixture.sender_device_id,
        "keyId":key_id,"authGeneration":generation,"targetDeviceId":fixture.sender_device_id,
        "targetAuthGeneration":generation,"idempotencyKey":operation,
        "signedAt":at.to_rfc3339_opts(chrono::SecondsFormat::Millis,true),
    });
    let wrapper = serde_json::to_vec(&sign_mutation_json_for_test(&body, key).unwrap()).unwrap();
    let signed = crate::chat_protocol::transcript::decode_and_verify_signed_mutation(
        &wrapper,
        &key.verifying_key().to_bytes(),
    )
    .unwrap();
    let response = br#"{"revoked":true}"#;
    let jkt: Option<String> =
        sqlx::query_scalar("SELECT dpop_jkt FROM chat.devices WHERE user_did=$1 AND device_id=$2")
            .bind(&fixture.sender_did)
            .bind(fixture.sender_device_id)
            .fetch_one(pool)
            .await
            .unwrap();
    let mut tx = pool.begin().await.unwrap();
    sqlx::query("INSERT INTO chat.operation_claims(operation_id,principal_did,endpoint_nsid,mutation_kind,request_digest,accepted_request_sha256,signature,claimed_at) VALUES($1,$2,'blue.catbird.chat.revokeDevice','blue.catbird.chat.defs#deviceRevocationBody',$3,$4,$5,$6)")
        .bind(operation).bind(&fixture.sender_did).bind(signed.request_digest().as_slice()).bind(Sha256::digest(&wrapper).as_slice()).bind(signed.signature().as_slice()).bind(at).execute(&mut *tx).await.unwrap();
    sqlx::query("INSERT INTO chat.idempotency_records(principal_did,endpoint_nsid,operation_id,request_digest,accepted_request_bytes,signing_transcript_bytes,signature,completed_status,response_bytes,response_sha256,historical_jkt,completed_at) VALUES($1,'blue.catbird.chat.revokeDevice',$2,$3,$4,$5,$6,200,$7,$8,$9,$10)")
        .bind(&fixture.sender_did).bind(operation).bind(signed.request_digest().as_slice()).bind(&wrapper).bind(signed.transcript_bytes()).bind(signed.signature().as_slice()).bind(response.as_slice()).bind(Sha256::digest(response).as_slice()).bind(jkt).bind(at).execute(&mut *tx).await.unwrap();
    sqlx::query("INSERT INTO chat.device_revocations(revocation_id,actor_did,actor_device_id,actor_key_id,actor_auth_generation,target_did,target_device_id,target_auth_generation,accepted_request_bytes,signing_transcript_bytes,request_digest,signature,signed_at,accepted_at) VALUES($1,$2,$3,$4,$5,$2,$3,$5,$6,$7,$8,$9,$10,$10)")
        .bind(operation).bind(&fixture.sender_did).bind(fixture.sender_device_id).bind(key_id).bind(generation).bind(&wrapper).bind(signed.transcript_bytes()).bind(signed.request_digest().as_slice()).bind(signed.signature().as_slice()).bind(at).execute(&mut *tx).await.unwrap();
    sqlx::query("UPDATE chat.devices SET status='revoked',revoked_at=$3,updated_at=$3,revocation_id=$4 WHERE user_did=$1 AND device_id=$2")
        .bind(&fixture.sender_did).bind(fixture.sender_device_id).bind(at).bind(operation).execute(&mut *tx).await.unwrap();
    sqlx::query("UPDATE chat.device_keys SET revoked_at=$4,revocation_id=$5 WHERE user_did=$1 AND device_id=$2 AND key_id=$3")
        .bind(&fixture.sender_did).bind(fixture.sender_device_id).bind(key_id).bind(at).bind(operation).execute(&mut *tx).await.unwrap();
    sqlx::query("UPDATE chat.key_packages SET status='revoked',terminal_revocation_id=$3,terminal_at=$4 WHERE owner_did=$1 AND owner_device_id=$2 AND status='available'")
        .bind(&fixture.sender_did).bind(fixture.sender_device_id).bind(operation).bind(at).execute(&mut *tx).await.unwrap();
    tx.commit().await.unwrap();
}

fn close_entry(
    fixture: &CleanSlateApplicationFixture,
    cid: Uuid,
    kind: &str,
    actor: &str,
    device: Uuid,
    key_id: &str,
    key: &ed25519_dalek::SigningKey,
) -> Value {
    let mut prior = fixture.signed_request["body"]["prior"].clone();
    prior["conversationId"] = json!(cid);
    let mut retired = prior.clone();
    retired["stateVersion"] = json!(prior["stateVersion"].as_u64().unwrap() + 1);
    retired["lifecycle"] = json!("superseded");
    let at = crate::sim_hooks::current_utc().to_rfc3339_opts(chrono::SecondsFormat::Millis, true);
    let body = json!({
        "$type":"blue.catbird.chat.defs#conversationCloseBody", "signatureDomain":"CATBIRD-CHAT-CLOSE\u{0}",
        "actorDid":actor,"actorDeviceId":device,"keyId":key_id,"authGeneration":1,
        "signedAt":at,"idempotencyKey":Uuid::new_v4(),"transitionId":Uuid::new_v4(),
        "conversationKind":kind,"prior":prior,"retired":retired,
    });
    let signed = sign_mutation_json_for_test(&body, key).unwrap();
    let entry = json!({
        "$type":"blue.catbird.chat.defs#conversationCloseEntry","conversationId":cid,
        "entryId":Uuid::new_v4(),"seq":10,"receivedAt":at,"signedRequest":signed,
        "tombstone":{"conversationId":cid,"conversationKind":kind,"retired":retired,
            "closedByDid":actor,"closedByDeviceId":device,"terminalSeq":10,"closedAt":at},
    });
    crate::chat_protocol::transcript::decode_and_verify_control_entry(
        &serde_json::to_vec(&entry).unwrap(),
        &key.verifying_key().to_bytes(),
    )
    .unwrap();
    entry
}

fn close_request(fixture: &CleanSlateApplicationFixture, entry: Value) -> DeliverGroupEntryRequest {
    let cid = entry["conversationId"].as_str().unwrap().parse().unwrap();
    DeliverGroupEntryRequest {
        conversation_id: cid,
        generation: entry["signedRequest"]["body"]["prior"]["generation"]
            .as_i64()
            .unwrap(),
        space_uri: format!("at:space/{SOURCE}/blue.catbird.labyrinth.conversation/{cid}-0"),
        recipient_dids: vec![fixture.sender_did.clone()],
        recipient_devices: vec![(fixture.sender_did.clone(), fixture.sender_device_id)],
        entry,
        close_authority: None,
    }
}

async fn reject_close_unchanged(
    state: &GroupRelayState,
    caller: &str,
    request: &DeliverGroupEntryRequest,
    status: StatusCode,
    code: &str,
) {
    let before = effects(&state.pool, request.conversation_id).await;
    let bytes = serde_json::to_vec(request).unwrap();
    protocol_error(
        handle_deliver_group_entry(
            State(state.clone()),
            hmac_headers(caller, DELIVER, &bytes),
            Bytes::from(bytes),
        )
        .await,
        status,
        code,
    )
    .await;
    assert_eq!(effects(&state.pool, request.conversation_id).await, before);
}

#[tokio::test]
async fn terminal_close_checks_stored_authority_and_freezes_only_local_audiences() {
    crate::federation::open_federation_for_test();
    let database = crate::common::fresh_db::fresh_fully_migrated_db("chat_fed_relay_").await;
    let pool = database.connect(4).await;
    crate::common::http_acceptance::ensure_fence(&pool).await;
    let fixture = seed_remote_clean_slate_application_fixture(&pool, OTHER, SOURCE, Some([51; 32]))
        .await
        .unwrap();
    let key = ed25519_dalek::SigningKey::from_bytes(&fixture.sender_ed25519_seed);
    let outsider_key = ed25519_dalek::SigningKey::from_bytes(&[52; 32]);
    let outsider = "did:web:relay-outsider.example.com";
    let outsider_device = Uuid::new_v4();
    let outsider_key_id = crate::common::executor_seed::seed_actor(
        &pool,
        outsider,
        outsider_device,
        &outsider_key.verifying_key().to_bytes(),
    )
    .await;
    let receipt_key = SigningKey::from_slice(&[53; 32]).unwrap();
    let signer = I13ReceiptSigner::new(receipt_key.clone(), SOURCE.to_string());
    let other_key = SigningKey::from_slice(&[54; 32]).unwrap();
    let other_signer = I13ReceiptSigner::new(other_key.clone(), OTHER.to_string());
    let other_doc = json!({"id":OTHER,"verificationMethod":[{
        "id":format!("{OTHER}#mls-receipt-1"),"type":"Multikey","controller":OTHER,
        "publicKeyMultibase":crate::identity::did_doc::encode_p256_multikey(other_key.verifying_key()),
    }]});
    let source_doc = json!({"id":SOURCE,"verificationMethod":[{
        "id":format!("{SOURCE}#mls-receipt-1"),"type":"Multikey","controller":SOURCE,
        "publicKeyMultibase":crate::identity::did_doc::encode_p256_multikey(receipt_key.verifying_key()),
    }]});
    let actor_doc = json!({"id":fixture.sender_did,"service":[{
        "id":format!("{}#atproto_mls",fixture.sender_did),"type":"AtprotoMLSDeliveryService","serviceEndpoint":HOME_URL,
    },{
        "id":format!("{}#atproto_pds",fixture.sender_did),"type":"AtprotoPersonalDataServer","serviceEndpoint":"https://pds.routing.example.com",
    }]});
    let outsider_doc = json!({"id":outsider,"service":[{
        "id":format!("{outsider}#atproto_mls"),"type":"AtprotoMLSDeliveryService","serviceEndpoint":HOME_URL,
    },{
        "id":format!("{outsider}#atproto_pds"),"type":"AtprotoPersonalDataServer","serviceEndpoint":"https://pds.routing.example.com",
    }]});
    let documents = HashMap::from([
        (SOURCE.to_string(), source_doc),
        (OTHER.to_string(), other_doc),
        (fixture.sender_did.clone(), actor_doc),
        (outsider.to_string(), outsider_doc),
    ]);
    let device_keys = HashMap::from([
        (fixture.sender_did.clone(), key.verifying_key().to_bytes()),
        (
            outsider.to_string(),
            outsider_key.verifying_key().to_bytes(),
        ),
    ]);
    // The same world with SOURCE's DID document unreachable.
    let without_source: HashMap<String, Value> = documents
        .iter()
        .filter(|(did, _)| did.as_str() != SOURCE)
        .map(|(did, document)| (did.clone(), document.clone()))
        .collect();
    for peer in [SOURCE, OTHER] {
        allow(&pool, peer).await;
    }
    let state = GroupRelayState::for_test(pool.clone(), HOME.to_string(), SECRET, None);
    let clock = manual_clock();
    scope_ds_clock(clock,scope_sim_ds(hooks_with_device_records(documents, device_keys.clone()),async {
        let unknown = close_request(&fixture,close_entry(&fixture,Uuid::new_v4(),"group",&fixture.sender_did,fixture.sender_device_id,&fixture.sender_key_id,&key));
        reject_close_unchanged(&state,SOURCE,&unknown,StatusCode::NOT_FOUND,"ConversationNotFound").await;
        let entry = close_entry(&fixture,fixture.conversation_id,"group",&fixture.sender_did,fixture.sender_device_id,&fixture.sender_key_id,&key);
        let mut request = close_request(&fixture,entry);
        // This other sequencer has a valid key/proof and an allowlisted S2S
        // identity; only the stored-sequencer binding may reject it here.
        request.close_authority = Some(other_signer.sign_terminal_close_authority(fixture.conversation_id,&request.entry).unwrap());
        reject_close_unchanged(&state,OTHER,&request,StatusCode::FORBIDDEN,"NotAuthorized").await;
        request.close_authority = None;
        reject_close_unchanged(&state,SOURCE,&request,StatusCode::FORBIDDEN,"NotAuthorized").await;
        let proof = signer.sign_terminal_close_authority(fixture.conversation_id,&request.entry).unwrap();
        let mut bad_proof = proof.clone();
        bad_proof.final_roster_sha256[0] ^= 1;
        request.close_authority = Some(bad_proof);
        reject_close_unchanged(&state,SOURCE,&request,StatusCode::FORBIDDEN,"NotAuthorized").await;

        // This is deliberately an identity-only inbox guard fixture, NOT C33
        // opening/receipt/MLS acceptance evidence (those run in native E2E).
        let inbox_cid = Uuid::new_v4();
        let opening = b"identity-only-c33-guard-fixture";
        sqlx::query("INSERT INTO chat.direct_request_transport_inbox(request_id,conversation_id,first_message_id,coordinator_did,sender_did,sender_device_id,recipient_did,recipient_device_id,request_entry,signed_publication,full_welcome,full_welcome_sha256,provenance,publication_receipt,import_until) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$9,$9,$10,$9,$9,$11)")
            .bind(Uuid::new_v4()).bind(inbox_cid).bind(Uuid::new_v4()).bind(SOURCE)
            .bind(&fixture.sender_did).bind(fixture.sender_device_id).bind(&fixture.recipient_did).bind(fixture.recipient_device_id)
            .bind(opening.as_slice()).bind(Sha256::digest(opening).as_slice()).bind(crate::sim_hooks::current_utc()+chrono::Duration::days(1))
            .execute(&pool).await.unwrap();
        let identity_before: Value = sqlx::query_scalar("SELECT to_jsonb(inbox) FROM chat.direct_request_transport_inbox inbox WHERE conversation_id=$1")
            .bind(inbox_cid).fetch_one(&pool).await.unwrap();
        let c33 = close_request(&fixture,close_entry(&fixture,inbox_cid,"direct",&fixture.sender_did,fixture.sender_device_id,&fixture.sender_key_id,&key));
        reject_close_unchanged(&state,OTHER,&c33,StatusCode::FORBIDDEN,"NotAuthorized").await;
        let outsider_close = close_request(&fixture,close_entry(&fixture,inbox_cid,"direct",outsider,outsider_device,&outsider_key_id,&outsider_key));
        reject_close_unchanged(&state,SOURCE,&outsider_close,StatusCode::FORBIDDEN,"NotAuthorized").await;
        let identity_after: Value = sqlx::query_scalar("SELECT to_jsonb(inbox) FROM chat.direct_request_transport_inbox inbox WHERE conversation_id=$1")
            .bind(inbox_cid).fetch_one(&pool).await.unwrap();
        assert_eq!(identity_before,identity_after);

        // SOURCE's receipt key cannot be fetched now: that decided nothing, so
        // this home answers 503 and SOURCE keeps the close queued.
        request.close_authority = Some(proof.clone());
        scope_sim_ds(hooks_with_device_records(without_source.clone(), device_keys.clone()),reject_close_unchanged(&state,SOURCE,&request,StatusCode::SERVICE_UNAVAILABLE,"ServiceUnavailable")).await;

        request.close_authority = Some(proof);
        request.recipient_dids = vec![outsider.to_string(),fixture.recipient_did.clone()];
        request.recipient_devices.extend([
            (outsider.to_string(),outsider_device),
            (fixture.recipient_did.clone(),fixture.recipient_device_id),
        ]);
        let before = effects(&pool,fixture.conversation_id).await;
        let bytes = serde_json::to_vec(&request).unwrap();
        let response = handle_deliver_group_entry(State(state.clone()),hmac_headers(SOURCE,DELIVER,&bytes),Bytes::from(bytes)).await;
        let status = response.status();
        let body = axum::body::to_bytes(response.into_body(),64*1024).await.unwrap();
        assert_eq!(status,StatusCode::OK,"{}",String::from_utf8_lossy(&body));
        let after = effects(&pool,fixture.conversation_id).await;
        assert_eq!(after[0],before[0]+1,"one real immutable close event");
        assert_eq!(after[2],before[2]+1,"one retained signed terminal attachment");
        assert!(after[3..10].iter().all(|count|*count==0),"the real wipe must remove the mirrored operational graph: {after:?}");
        let recipients: Vec<(String,Uuid)> = sqlx::query_as("SELECT r.user_did,r.device_id FROM chat.event_recipients r JOIN chat.events e USING(event_position) WHERE e.event_kind='conversationClosed' AND convert_from(e.payload_bytes,'UTF8')::jsonb->>'conversationId'=$1 ORDER BY r.user_did,r.device_id")
            .bind(fixture.conversation_id.to_string()).fetch_all(&pool).await.unwrap();
        assert_eq!(recipients,vec![(fixture.sender_did.clone(),fixture.sender_device_id)],"spoofed outsider and remote-home devices receive no local entitlement");
        let retained: (Option<String>,Option<Vec<u8>>) = sqlx::query_as("SELECT terminal.source_ds_did,terminal.source_authority_bytes FROM chat.conversation_close_terminal_entries terminal JOIN chat.events e USING(event_position) WHERE convert_from(e.payload_bytes,'UTF8')::jsonb->>'conversationId'=$1")
            .bind(fixture.conversation_id.to_string()).fetch_one(&pool).await.unwrap();
        assert_eq!(retained.0.as_deref(),Some(SOURCE));
        assert_eq!(serde_json::from_slice::<crate::federation::receipt::TerminalCloseAuthority>(&retained.1.unwrap()).unwrap(),request.close_authority.clone().unwrap());
        let stable = effects(&pool,fixture.conversation_id).await;
        let bytes = serde_json::to_vec(&request).unwrap();
        let response = handle_deliver_group_entry(State(state.clone()),hmac_headers(SOURCE,DELIVER,&bytes),Bytes::from(bytes)).await;
        assert_eq!(response.status(),StatusCode::OK);
        assert_eq!(effects(&pool,fixture.conversation_id).await,stable,"identical close redelivery does not append or wipe again");
    })).await;
    pool.close().await;
}

/// An account deletion whose sequencer's receipt key cannot be fetched now
/// decided nothing: this home answers 503, so the sequencer keeps the ordered
/// delivery queued (a 4xx would end it). A document without that key refuses.
#[tokio::test]
async fn account_deletion_key_outage_stays_retryable() {
    let sequencer = format!(
        "did:web:deletion-seq-{}.example.com",
        Uuid::new_v4().simple()
    );
    let (service_key, receipt_key) = (
        SigningKey::from_slice(&[61; 32]).unwrap(),
        SigningKey::from_slice(&[62; 32]).unwrap(),
    );
    let without_receipt_key = service_document(&sequencer, &service_key);
    let mut document = without_receipt_key.clone();
    document["verificationMethod"]
        .as_array_mut()
        .unwrap()
        .push(json!({
            "id": format!("{sequencer}#mls-receipt-1"),
            "type": "Multikey",
            "controller": sequencer,
            "publicKeyMultibase":
                crate::identity::did_doc::encode_p256_multikey(receipt_key.verifying_key()),
        }));
    let conversation_id = Uuid::new_v4();
    let deletion = super::super::receipt::AccountDeletion {
        sequencer_did: sequencer.clone(),
        conversation_id,
        deleted_did: "did:web:deleted.example.com".to_owned(),
        seq: 3,
        entry_id: Uuid::new_v4(),
        deleted_at: chrono::DateTime::from_timestamp_millis(chrono::Utc::now().timestamp_millis())
            .unwrap(),
        evidence: None,
    };
    let authority = I13ReceiptSigner::new(receipt_key, sequencer.clone())
        .sign_account_deletion(&deletion)
        .unwrap();
    let request = DeliverGroupEntryRequest {
        conversation_id,
        generation: 0,
        space_uri: format!(
            "at:space/{sequencer}/blue.catbird.labyrinth.conversation/{conversation_id}-0"
        ),
        recipient_dids: Vec::new(),
        recipient_devices: Vec::new(),
        entry: deletion.entry(&authority),
        close_authority: None,
    };
    let pool = sqlx::postgres::PgPoolOptions::new()
        .connect_lazy("postgres://127.0.0.1/deletion_key_outage")
        .unwrap();
    let state = GroupRelayState::for_test(pool, HOME.to_string(), SECRET, None);
    let verify = |documents: HashMap<String, Value>| {
        scope_sim_ds(
            hooks(documents),
            verify_account_deletion(&state, &sequencer, &request),
        )
    };

    let unreachable = verify(HashMap::new()).await.unwrap_err();
    protocol_error(
        unreachable,
        StatusCode::SERVICE_UNAVAILABLE,
        "ServiceUnavailable",
    )
    .await;
    let refused = verify(HashMap::from([(sequencer.clone(), without_receipt_key)]))
        .await
        .unwrap_err();
    protocol_error(refused, StatusCode::FORBIDDEN, "NotAuthorized").await;
    verify(HashMap::from([(sequencer.clone(), document)]))
        .await
        .expect("the sequencer's receipt key verifies its deletion");
}

/// A member home's device directory (`resolveGroupDevices`) answers 503 while
/// its user's PDS cannot list the device keys, so the calling home keeps the
/// add retryable (it holds every 4xx as a refusal); a PDS not authorizing the
/// user's device is still refused with `NotAuthorized`.
#[tokio::test]
async fn member_home_directory_answers_a_pds_outage_retryably() {
    use tower_util::ServiceExt as _;
    const DIRECTORY: &str = "blue.catbird.mlsDS.resolveGroupDevices";
    const DID_DOCUMENT: &str = /* did-web-test */ "/.well-known/did.json";
    crate::federation::open_federation_for_test();
    let database = crate::common::fresh_db::fresh_fully_migrated_db("chat_fed_relay_").await;
    let pool = database.connect(4).await;
    crate::common::http_acceptance::ensure_fence(&pool).await;
    let fixture = seed_clean_slate_application_fixture_with_sender_home(
        &pool,
        false,
        OTHER,
        Some([34; 32]),
        None,
    )
    .await
    .unwrap();
    allow(&pool, SOURCE).await;
    let user = fixture.sender_did.clone();
    let key = ed25519_dalek::SigningKey::from_bytes(&fixture.sender_ed25519_seed)
        .verifying_key()
        .to_bytes();
    // What the user's PDS lists: this key, or an outage's status.
    let listed = Arc::new(std::sync::Mutex::new(Err::<[u8; 32], u16>(503)));
    let (pds, did) = (listed.clone(), user.clone());
    let hooks = Arc::new(SimDsHooks {
        service_did: HOME.to_string(),
        self_endpoint: HOME_URL.to_string(),
        signing_key_pem: None,
        group_relay_hmac_secret: None,
        http_transport: Arc::new(move |request| {
            let host = request.url.host_str().unwrap_or_default().to_owned();
            let answer = match request.url.path() {
                DID_DOCUMENT if format!("did:web:{host}") == did => Ok(json!({
                    "id": did,
                    "service": [{
                        "id": "#atproto_pds",
                        "type": "AtprotoPersonalDataServer",
                        "serviceEndpoint": "https://pds.routing.example.com",
                    }],
                })),
                "/xrpc/com.atproto.repo.getRecord" if host == "pds.routing.example.com" => {
                    Ok(json!({
                        "uri": format!("at://{did}/blue.catbird.chat.declaration/self"),
                        "value": {
                            "$type": "blue.catbird.chat.declaration",
                            "protocolVersion": "2",
                            "allowIncoming": "all",
                            "deliveryService": HOME,
                            "createdAt": "2026-07-15T12:00:00Z",
                        },
                    }))
                }
                "/xrpc/com.atproto.repo.listRecords" if host == "pds.routing.example.com" => {
                    (*pds.lock().unwrap()).map(|key| {
                        json!({"records": [{"value": {
                            "mlsSignaturePublicKey": {"$bytes": STANDARD.encode(key)},
                            "algorithm": "ed25519",
                            "createdAt": "2026-07-15T12:00:00Z",
                        }}]})
                    })
                }
                _ => Err(404),
            };
            Box::pin(async move {
                let (status, body) = match answer {
                    Ok(body) => (200, body),
                    Err(status) => (status, json!({ "error": "Unavailable" })),
                };
                Ok(http::Response::builder()
                    .status(status)
                    .header("content-type", "application/json")
                    .body(serde_json::to_vec(&body).unwrap())
                    .unwrap())
            })
        }),
        dns_resolver: Arc::new(|_| Ok(vec!["93.184.216.34".parse().unwrap()])),
        retain_application_ciphertext: false,
    });
    scope_sim_ds(hooks, async {
        super::super::resolver::DsResolver::new(
            pool.clone(),
            reqwest::Client::new(),
            HOME.to_string(),
            HOME_URL.to_string(),
            None,
            300,
        )
        .cache_mapping(
            &user,
            &super::super::resolver::DsEndpoint {
                did: HOME.to_string(),
                endpoint: HOME_URL.to_string(),
                supported_cipher_suites: None,
                federation_capabilities: None,
            },
        )
        .await
        .unwrap();
        let router = group_relay_router(GroupRelayState::for_test(
            pool.clone(),
            HOME.to_string(),
            SECRET,
            None,
        ));
        let call = |method: &'static str, payload: Value| {
            let router = router.clone();
            async move {
                let body = serde_json::to_vec(&payload).unwrap();
                let mut request = axum::http::Request::builder()
                    .method("POST")
                    .uri(format!("/xrpc/{method}"))
                    .body(axum::body::Body::from(body.clone()))
                    .unwrap();
                *request.headers_mut() = hmac_headers(SOURCE, method, &body);
                let response = router.oneshot(request).await.unwrap();
                let status = response.status();
                let body = axum::body::to_bytes(response.into_body(), 64 * 1024)
                    .await
                    .unwrap();
                (status, serde_json::from_slice::<Value>(&body).unwrap())
            }
        };
        let directory = || call(DIRECTORY, json!({ "userDid": user }));
        // A group KeyPackage export first reads the same PDS-authorized
        // directory of the package owner's devices.
        let package = || {
            call(
                "blue.catbird.mlsDS.fetchKeyPackage",
                json!({
                    "conversationId": Uuid::new_v4(),
                    "userDid": user,
                    "deviceId": fixture.sender_device_id,
                    "keyId": "unused",
                    "recoveryRequestId": Uuid::new_v4(),
                    "signedRequest": {},
                }),
            )
        };

        for status in [503, 429, 502] {
            *listed.lock().unwrap() = Err(status);
            for (status, body) in [directory().await, package().await] {
                assert_eq!(
                    (status, body["error"].as_str()),
                    (StatusCode::SERVICE_UNAVAILABLE, Some("ServiceUnavailable")),
                    "{body}"
                );
            }
        }
        *listed.lock().unwrap() = Ok([0x5c; 32]);
        for (status, body) in [directory().await, package().await] {
            assert_eq!(
                (status, body["error"].as_str()),
                (StatusCode::FORBIDDEN, Some("NotAuthorized")),
                "{body}"
            );
        }
        *listed.lock().unwrap() = Ok(key);
        let (status, body) = directory().await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(
            body["devices"][0]["deviceId"],
            fixture.sender_device_id.to_string()
        );
    })
    .await;
    pool.close().await;
}

/// An authenticated caller's admission that this DS could not decide is never
/// a refusal (the caller holds every 4xx but 429 as definitive and would end
/// its ordered delivery): a caller DID document that cannot be fetched now is
/// 503; this DS's replay or peer-policy store failing is 500.
#[tokio::test]
async fn s2s_caller_admission_this_ds_could_not_decide_is_not_a_refusal() {
    crate::federation::open_federation_for_test();
    // Every query against this pool fails at once.
    let pool = sqlx::postgres::PgPoolOptions::new()
        .connect_lazy("postgres://127.0.0.1/s2s_admission_outage")
        .unwrap();
    pool.close().await;
    let state = GroupRelayState::for_test(pool, HOME.to_string(), SECRET, None);
    let caller = format!("did:web:admission-{}.example.com", Uuid::new_v4().simple());
    let key = SigningKey::from_slice(&[19; 32]).unwrap();
    let body = b"{}";
    scope_ds_clock(
        manual_clock(),
        scope_sim_ds(hooks(HashMap::new()), async {
            let error = verify_s2s_caller(&state, &bearer(&caller, &key, DELIVER), DELIVER, body)
                .await
                .unwrap_err();
            protocol_error(error, StatusCode::SERVICE_UNAVAILABLE, "ServiceUnavailable").await;
            crate::sim_hooks::seed_sim_did_document(
                serde_json::from_value(service_document(&caller, &key)).unwrap(),
            )
            .await;
            for headers in [
                bearer(&caller, &key, DELIVER),
                hmac_headers(&caller, DELIVER, body),
            ] {
                let error = verify_s2s_caller(&state, &headers, DELIVER, body)
                    .await
                    .unwrap_err();
                protocol_error(
                    error,
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "InternalServerError",
                )
                .await;
            }
        }),
    )
    .await;
}

#[path = "group_relay_c2_survivor_tests.rs"]
mod c2_survivor_tests;
