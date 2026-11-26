//! `D1` Federated Cross-Server Group Relay & `3A` Stateless Space Relays integration tests.
//!
//! Pins:
//! 1. `D1`: Remote group member talks ONLY to their own home `mls-ds`, which relays group
//!    mutations (`relayGroupMutation`) to the sequencing `mls-ds` and ingests `deliverGroupEntry`
//!    fan-out (with `I13` sequencer receipt!) on remote member home `mls-ds` instances.
//! 2. `3A` `blue.catbird.chat.relaySpaceCredential`: Stateless home-`mls-ds` relay exchanging a
//!    PDS delegation token with a remote Space authority, returning `{credential, expiresAt}` and
//!    writing ZERO operational DB rows on the home `mls-ds`.
//! 3. `3A` `blue.catbird.chat.relaySpaceRead`:
//!    - Enforces strict read-only `com.atproto.space.*` NSID allowlist (`400 InvalidNsid` on writes),
//!    - Enforces DNS-pinned SSRF guard (`400 InvalidTargetEndpoint` on `169.254.169.254` / `10.0.0.1`),
//!    - Forwards `Authorization: Atproto-Space-Credential ...`, `Atproto-Space-Audience`,
//!      `Atproto-Space-Want-Mac`, `Signature-Input`, and `Signature` untouched,
//!    - Preserves upstream `Atproto-Space-Mac` and exposes `Access-Control-Expose-Headers: Atproto-Space-Mac`,
//!    - Writes ZERO rows on the home `mls-ds`!

mod common;

use atproto_spaces::{
    http_signature::sign_credential_request,
    kem::encode_p256_did_key,
    tokens::{mint_space_token, SpaceSigningKey, SpaceTokenClaims, SpaceTokenKind},
};
use axum::{
    extract::Query,
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
    routing::get,
};
use catbird_server::handlers::ds::get_convo_digest::CleanConvoDigestHasher;
use catbird_server::{
    chat_protocol::{
        repository::remote_prefix::test_support::test_apply_remote_clean_prefix,
        test_support::{
            seed_clean_slate_application_fixture,
            seed_clean_slate_application_fixture_with_sender_home, CleanSlateApplicationFixture,
        },
    },
    federation::{
        bootstrap::{
            RemoteDigestAnchor, RemotePrefixApplyOutcome, RemotePrefixBootstrapSelector,
            VerifiedRemotePrefixAdmission,
        },
        group_relay::{
            deliver_group_entry_to_remote_home, group_relay_router,
            relay_group_mutation_to_sequencer, DeliverGroupEntryRequest, GroupRelayState,
            RelayGroupMutationRequest,
        },
        outbound::OutboundError,
        receipt::I13ReceiptSigner,
        reconciliation::{RemoteEvent, StrictCleanRemoteEvent},
        resolver::ValidatedRemoteDestination,
        space_read_relay::register_test_space_relay_target,
    },
    space_host::{space_host_router, SpaceHostConfig, SpaceHostRuntime},
};
use chrono::Utc;
use common::http_acceptance as http;
use p256::{
    ecdsa::SigningKey as P256SigningKey, PublicKey as P256PublicKey, SecretKey as P256Secret,
};
use serde_json::json;
use sqlx::Row;
use std::{
    collections::{BTreeMap, BTreeSet},
    sync::{Arc, Mutex},
};
use tokio::net::TcpListener;
use uuid::Uuid;

#[derive(Clone, Default)]
struct CapturedUpstreamRead {
    auth: Option<String>,
    audience: Option<String>,
    want_mac: Option<String>,
    sig_input: Option<String>,
    sig: Option<String>,
    query: Option<String>,
}

async fn count_mutable_chat_rows(pool: &sqlx::PgPool) -> i64 {
    let tables: Vec<String> = sqlx::query_scalar(
        "SELECT table_name FROM information_schema.tables WHERE table_schema = 'chat' AND table_type = 'BASE TABLE' ORDER BY table_name",
    )
    .fetch_all(pool)
    .await
    .unwrap();
    let mut total = 0_i64;
    for table in tables {
        let count: i64 = sqlx::query_scalar(&format!("SELECT COUNT(*) FROM chat.\"{table}\""))
            .fetch_one(pool)
            .await
            .unwrap();
        total += count;
    }
    total
}
/// Mirror the sequencer's group at `home`: a member whose home is `None` is
/// homed there and gets an active local leaf.
async fn mirror_group_membership(
    sequencer: &sqlx::PgPool,
    home: &sqlx::PgPool,
    fixture: &CleanSlateApplicationFixture,
    sequencer_did: &str,
    (sender_home_did, recipient_home_did): (Option<&str>, Option<&str>),
    sequencer_destination: ValidatedRemoteDestination,
) {
    // Stage the exact registered identities and real package which the
    // sequencer accepted, then replay its signed Creation/Acceptance/Add
    // through the production prefix reducer. A bare is_remote row is not a
    // membership mirror and would leave the exact-device grant empty.
    for table in ["principals", "devices", "device_keys"] {
        let rows: serde_json::Value = sqlx::query_scalar(&format!(
            "SELECT jsonb_agg(to_jsonb(r)) FROM chat.{table} r"
        ))
        .fetch_one(sequencer)
        .await
        .unwrap();
        sqlx::query(&format!(
            "INSERT INTO chat.{table} SELECT * FROM jsonb_populate_recordset(NULL::chat.{table}, $1)"
        )).bind(rows).execute(home).await.unwrap();
    }
    let packages: serde_json::Value = sqlx::query_scalar(
        "SELECT jsonb_agg(to_jsonb(kp) || jsonb_build_object( \
             'status','available','terminal_transition_id',NULL, \
             'terminal_revocation_id',NULL,'terminal_at',NULL)) \
         FROM chat.key_packages kp",
    )
    .fetch_one(sequencer)
    .await
    .unwrap();
    sqlx::query(
        "INSERT INTO chat.key_packages \
         SELECT * FROM jsonb_populate_recordset(NULL::chat.key_packages, $1)",
    )
    .bind(packages)
    .execute(home)
    .await
    .unwrap();

    let rows = sqlx::query(
        "SELECT seq,generation,entry_id,entry_kind,accepted_payload_bytes,accepted_payload_sha256, \
                signed_request_bytes,outer_entry_fingerprint,sequencer_receipt_bytes,received_at \
         FROM chat.entries WHERE conversation_id=$1 AND seq < 4 ORDER BY seq",
    ).bind(fixture.conversation_id).fetch_all(sequencer).await.unwrap();
    assert_eq!(
        rows.len(),
        3,
        "mirror the real membership prefix, not the application send"
    );
    let mut events = Vec::with_capacity(rows.len());
    let mut hasher = CleanConvoDigestHasher::new();
    let mut material_bytes = 0;
    for row in rows {
        let entry_id: Uuid = row.get("entry_id");
        let entry_kind: String = row.get("entry_kind");
        let event = StrictCleanRemoteEvent::try_from(RemoteEvent {
            seq: row.get("seq"),
            epoch: row.get("generation"),
            msg_id: entry_id.to_string(),
            message_type: entry_kind.clone(),
            ciphertext: row.get("accepted_payload_bytes"),
            padded_size: 0,
            created_at: row.get("received_at"),
            entry_id: Some(entry_id.to_string()),
            entry_kind: Some(entry_kind.clone()),
            accepted_payload_sha256: Some(row.get("accepted_payload_sha256")),
            signed_request: Some(row.get("signed_request_bytes")),
            outer_fingerprint: Some(row.get("outer_entry_fingerprint")),
            sequencer_receipt: Some(row.get("sequencer_receipt_bytes")),
            account_deleted_entry: None,
        })
        .unwrap();
        hasher.update_event(
            event.seq(),
            event.generation(),
            event.entry_id(),
            &entry_kind,
            event.accepted_payload_bytes(),
            event.signed_request(),
            event.outer_fingerprint(),
            event.received_at(),
        );
        material_bytes += event.accepted_payload_bytes().len() + event.signed_request().len();
        events.push(event);
    }
    let last = events.last().unwrap();
    let digest = RemoteDigestAnchor::new_for_test(
        fixture.conversation_id,
        sequencer_did.to_owned(),
        0,
        last.seq(),
        events.len() as i64,
        last.generation(),
        hex::decode(hasher.finalize()).unwrap().try_into().unwrap(),
    );
    let admission = VerifiedRemotePrefixAdmission::new_for_test(
        RemotePrefixBootstrapSelector::new(fixture.conversation_id, sequencer_did.to_owned(), 0)
            .unwrap(),
        sequencer_destination,
        digest,
        events,
        BTreeMap::from([
            (
                fixture.sender_did.clone(),
                sender_home_did.map(str::to_owned),
            ),
            (
                fixture.recipient_did.clone(),
                recipient_home_did.map(str::to_owned),
            ),
        ]),
        material_bytes,
    );
    let mut tx = home.begin().await.unwrap();
    let outcome = test_apply_remote_clean_prefix(&mut tx, admission)
        .await
        .expect("replay real signed membership into Bob's home");
    assert!(matches!(
        outcome,
        RemotePrefixApplyOutcome::Applied { last_seq: 3, .. }
    ));
    tx.commit().await.unwrap();
    for (did, device_id, member_home) in [
        (
            &fixture.sender_did,
            fixture.sender_device_id,
            sender_home_did,
        ),
        (
            &fixture.recipient_did,
            fixture.recipient_device_id,
            recipient_home_did,
        ),
    ] {
        let active_local_leaf: bool = sqlx::query_scalar(
            "SELECT EXISTS(SELECT 1 FROM chat.conversations c \
              JOIN chat.participants p USING(conversation_id) \
              JOIN chat.member_devices m USING(conversation_id,user_did) \
              WHERE c.conversation_id=$1 AND c.is_remote AND c.sequencer_ds=$2 \
                AND p.user_did=$3 AND p.ds_did IS NULL AND p.current_membership \
                AND p.status='active' AND m.device_id=$4 AND m.active)",
        )
        .bind(fixture.conversation_id)
        .bind(sequencer_did)
        .bind(did)
        .bind(device_id)
        .fetch_one(home)
        .await
        .unwrap();
        assert_eq!(
            active_local_leaf,
            member_home.is_none(),
            "only a member homed here has an active local mirrored leaf"
        );
    }
}

static ENV_LOCK: std::sync::LazyLock<tokio::sync::Mutex<()>> =
    std::sync::LazyLock::new(|| tokio::sync::Mutex::new(()));

#[tokio::test]
async fn d1_cross_server_group_relay_sequences_on_authority_and_fans_out_with_i13_receipt() {
    let _env_guard = ENV_LOCK.lock().await;
    catbird_server::federation::open_federation_for_test();
    let seq_did = "did:web:ds-seq.example.com";
    let home_a_did = "did:web:ds-home-a.example.com";
    let home_b_did = "did:web:ds-home-b.example.com";
    std::env::set_var("SERVICE_DID", seq_did);
    std::env::set_var("SELF_ENDPOINT", "https://ds-seq.example.com");

    let db_seq = common::fresh_db::fresh_fully_migrated_db("chat_fed_relay_").await;
    let pool_seq = db_seq.connect(4).await;
    http::ensure_fence(&pool_seq).await;

    let db_home_b = common::fresh_db::fresh_fully_migrated_db("chat_fed_relay_").await;
    let pool_home_b = db_home_b.connect(4).await;
    http::ensure_fence(&pool_home_b).await;

    let i13_key = P256SigningKey::from_bytes((&[0x61u8; 32]).into()).unwrap();
    let i13_signer = Arc::new(I13ReceiptSigner::from_signing_key_for_test(
        seq_did.to_string(),
        i13_key.clone(),
    ));

    let fixture = seed_clean_slate_application_fixture_with_sender_home(
        &pool_seq,
        false,
        home_b_did,
        Some([0xAB; 32]),
        Some(home_a_did),
    )
    .await
    .expect("seed sequencer group with immutable remote sender routing");
    for (pool, peer) in [(&pool_seq, home_a_did), (&pool_home_b, seq_did)] {
        sqlx::query(
            "INSERT INTO federation_peers(ds_did,status,trust_score,max_requests_per_minute) \
             VALUES($1,'allow',100,100) ON CONFLICT(ds_did) DO UPDATE SET status='allow'",
        )
        .bind(peer)
        .execute(pool)
        .await
        .unwrap();
    }

    // Spawn sequencer S2S group_relay_router + home-B S2S group_relay_router
    let s2s_secret = b"shared-federation-s2s-test-key!!";
    let seq_state = GroupRelayState::for_test(
        pool_seq.clone(),
        seq_did.to_string(),
        s2s_secret,
        Some(i13_signer.clone()),
    );
    let seq_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let seq_addr = seq_listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(seq_listener, group_relay_router(seq_state))
            .await
            .unwrap();
    });

    let home_b_state = GroupRelayState::for_test(
        pool_home_b.clone(),
        home_b_did.to_string(),
        s2s_secret,
        None,
    );
    let home_b_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let home_b_addr = home_b_listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(home_b_listener, group_relay_router(home_b_state))
            .await
            .unwrap();
    });

    // Sender on remote home_a relays real OpenMLS PrivateMessage sendMessage via home_a -> sequencer!
    let relay_out = relay_group_mutation_to_sequencer(
        &format!("http://{seq_addr}"),
        home_a_did,
        seq_did,
        s2s_secret,
        &RelayGroupMutationRequest {
            conversation_id: fixture.conversation_id,
            endpoint: "blue.catbird.chat.sendMessage".to_string(),
            actor_did: fixture.sender_did.clone(),
            actor_device_id: fixture.sender_device_id,
            signed_request: fixture.signed_request.clone(),
            signed_request_bytes: None,
        },
    )
    .await
    .expect("relay group sendMessage to sequencer");

    assert_eq!(relay_out.entry["seq"].as_u64(), Some(4));
    assert_eq!(
        relay_out.entry["sequencerReceipt"]["sequencerDid"], seq_did,
        "sequenced cross-server group entry must carry I13 receipt"
    );

    let delivery = DeliverGroupEntryRequest {
        conversation_id: fixture.conversation_id,
        generation: 0,
        space_uri: format!(
            "at:space/{seq_did}/blue.catbird.labyrinth.conversation/{}-0",
            fixture.conversation_id
        ),
        recipient_dids: vec![fixture.recipient_did.clone()],
        recipient_devices: vec![(fixture.recipient_did.clone(), fixture.recipient_device_id)],
        entry: relay_out.entry.clone(),
        close_authority: None,
    };
    let gap = deliver_group_entry_to_remote_home(
        &format!("http://{home_b_addr}"),
        seq_did,
        home_b_did,
        s2s_secret,
        &delivery,
    )
    .await
    .expect_err("application fan-out must not invent remote membership");
    assert!(
        matches!(
            &gap,
            OutboundError::RemoteError { status: 409, error_name: Some(name), .. }
                if name == "PredecessorMissing"
        ),
        "an unknown mirror is a predecessor gap the sequencer retries in order: {gap:?}"
    );
    mirror_group_membership(
        &pool_seq,
        &pool_home_b,
        &fixture,
        seq_did,
        (Some(home_a_did), None),
        ValidatedRemoteDestination {
            url: format!("http://{seq_addr}").parse().unwrap(),
            host: "127.0.0.1".to_owned(),
            addrs: vec![seq_addr],
        },
    )
    .await;
    // Sequencer fans out to the registered member on Bob's home DS.
    deliver_group_entry_to_remote_home(
        &format!("http://{home_b_addr}"),
        seq_did,
        home_b_did,
        s2s_secret,
        &delivery,
    )
    .await
    .expect("deliverGroupEntry to a real remote membership mirror");

    let replicated_count: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM chat.direct_request_transport_entries WHERE conversation_id = $1 AND seq = 4",
    )
    .bind(fixture.conversation_id)
    .fetch_one(&pool_home_b)
    .await
    .unwrap();
    assert_eq!(
        replicated_count, 1,
        "remote home DS must replicate delivered group entry"
    );
    let granted_count: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM chat.group_transport_entry_recipients \
         WHERE conversation_id=$1 AND seq=4 AND user_did=$2 AND device_id=$3",
    )
    .bind(fixture.conversation_id)
    .bind(&fixture.recipient_did)
    .bind(fixture.recipient_device_id)
    .fetch_one(&pool_home_b)
    .await
    .unwrap();
    assert_eq!(
        granted_count, 1,
        "fan-out grants only the actual local member device"
    );

    pool_seq.close().await;
    pool_home_b.close().await;
}

/// One digest per durable table, but the replay caches each authenticated
/// attempt consumes with its fresh token.
#[cfg(feature = "sim")]
async fn durable_rows(pool: &sqlx::PgPool) -> BTreeMap<String, String> {
    let tables: Vec<String> = sqlx::query_scalar(
        "SELECT format('%I.%I', table_schema, table_name) FROM information_schema.tables \
          WHERE table_type = 'BASE TABLE' AND table_schema IN ('chat', 'public') \
            AND (table_schema, table_name) NOT IN \
                (('chat', 'service_auth_admissions'), ('chat', 'dpop_replays'), \
                 ('public', 'auth_jti_nonce')) \
          ORDER BY 1",
    )
    .fetch_all(pool)
    .await
    .unwrap();
    let mut rows = BTreeMap::new();
    for table in tables {
        let digest: String = sqlx::query_scalar(&format!(
            "SELECT md5(coalesce(string_agg(to_jsonb(t)::text, ',' ORDER BY to_jsonb(t)::text), '')) \
               FROM {table} t"
        ))
        .fetch_one(pool)
        .await
        .unwrap();
        rows.insert(table, digest);
    }
    rows
}

/// Three homes, one group: SEQ sequences it, HOME mirrors it and relays its
/// member's `sendMessage`, PEER homes the other member and receives SEQ's
/// fan-out. SEQ runs the traffic relationship check a local send runs before
/// it stores or fans out anything. Across a block the sender's client gets the
/// declared `BlockedRelationship`, never an authentication failure; while the
/// relationship source or SEQ's store cannot answer, the retryable
/// `RelationshipPolicyUnavailable`; and nothing persists at either home or
/// reaches PEER. A DS not homing the sender, or another principal at HOME,
/// is refused. Allowed, the send sequences and reaches PEER once; its
/// identical retry replays it even across a later block, and another body
/// under its message ID is the idempotency conflict.
#[cfg(feature = "sim")]
#[tokio::test]
async fn a_relayed_group_send_runs_the_sequencers_traffic_check_across_three_homes() {
    use axum::body::Body;
    use catbird_server::chat_protocol::error::ChatProtocolErrorCode;
    use catbird_server::chat_protocol::relationship_policy::{
        PublicResponse, SimSourceFault, TransportError,
    };
    use catbird_server::chat_protocol::test_support::{
        seed_clean_slate_application_fixture_unsealed, sign_mutation_json_for_test,
    };
    use catbird_server::federation::{group_relay::GroupRelayError, resolver::DsResolver};
    use catbird_server::handlers::chat::ChatRuntime;
    use catbird_server::sim_hooks::{scope_sim_ds, SimDsHooks, SimHttpRequest};
    use serde_json::Value;
    use std::sync::atomic::{AtomicUsize, Ordering::SeqCst};
    use std::{future::Future, pin::Pin};
    use tower_util::ServiceExt as _;
    type Reply = Pin<Box<dyn Future<Output = Result<::http::Response<Vec<u8>>, String>> + Send>>;
    const SEQ: &str = "did:web:relay-seq.example.com";
    const HOME: &str = "did:web:relay-sender-home.example.com";
    const PEER: &str = "did:web:relay-recipient-home.example.com";
    const FORGER: &str = "did:web:relay-forger.example.com";
    const SECRET: &str = "three-home-group-send-secret";
    const SEND: &str = "blue.catbird.chat.sendMessage";
    const DELIVER: &str = "/xrpc/blue.catbird.mlsDS.deliverGroupEntry";
    fn host(did: &str) -> &str {
        did.trim_start_matches("did:web:")
    }
    fn destination(did: &str) -> ValidatedRemoteDestination {
        ValidatedRemoteDestination {
            url: format!("https://{}", host(did)).parse().unwrap(),
            host: host(did).to_owned(),
            addrs: vec!["93.184.216.35:443".parse().unwrap()],
        }
    }
    let _env_guard = ENV_LOCK.lock().await;
    catbird_server::federation::open_federation_for_test();

    // SEQ: the group, its sender homed at HOME and recipient at PEER, whose
    // relationship sources allow everything unless `relationships` answers.
    let db_seq = common::fresh_db::fresh_fully_migrated_db("chat_fed_relay_").await;
    let seq_pool = db_seq.connect(4).await;
    http::ensure_fence(&seq_pool).await;
    let fixture = seed_clean_slate_application_fixture_unsealed(
        &seq_pool,
        false,
        PEER,
        Some([0xac; 32]),
        Some(HOME),
    )
    .await
    .expect("seed SEQ's group");
    for peer in [HOME, FORGER] {
        sqlx::query("INSERT INTO federation_peers(ds_did,status) VALUES($1,'allow')")
            .bind(peer)
            .execute(&seq_pool)
            .await
            .unwrap();
    }
    let relationships = SimSourceFault::default();
    let seq_rt = ChatRuntime::from_env(Arc::new(catbird_server::realtime::SseState::new(8)))
        .unwrap()
        .with_i13_receipt_signer(common::proof_i13_signer_for(SEQ))
        .with_sim_faulty_relationships(relationships.clone())
        .unwrap();
    // What reached each member home's `deliverGroupEntry`: (host, seq).
    let fanned_out = Arc::new(Mutex::new(Vec::<(String, i64)>::new()));
    let reached = fanned_out.clone();
    let seq_hooks = Arc::new(SimDsHooks {
        service_did: SEQ.to_owned(),
        self_endpoint: format!("https://{}", host(SEQ)),
        signing_key_pem: None,
        group_relay_hmac_secret: Some(SECRET.to_owned()),
        http_transport: Arc::new(move |request: SimHttpRequest| -> Reply {
            let reached = reached.clone();
            Box::pin(async move {
                let host = request.url.host_str().unwrap_or_default().to_owned();
                let body = match request.url.path() {
                    /* did-web-test */
                    "/.well-known/did.json" => json!({
                        "id": format!("did:web:{host}"),
                        "service": [{
                            "id": "#atproto_mls",
                            "type": "AtprotoMLSDeliveryService",
                            "serviceEndpoint": format!("https://{host}"),
                        }],
                    }),
                    DELIVER => {
                        let delivered: DeliverGroupEntryRequest =
                            serde_json::from_slice(&request.body).map_err(|e| e.to_string())?;
                        reached
                            .lock()
                            .unwrap()
                            .push((host, delivered.entry["seq"].as_i64().unwrap()));
                        json!({})
                    }
                    path => return Err(format!("unexpected SEQ request {path}")),
                };
                Ok(::http::Response::builder()
                    .header("content-type", "application/json")
                    .body(serde_json::to_vec(&body).unwrap())
                    .unwrap())
            })
        }),
        dns_resolver: Arc::new(|_| Ok(vec!["93.184.216.36".parse().unwrap()])),
        retain_application_ciphertext: false,
    });
    let sequencer = group_relay_router(
        GroupRelayState::for_test(
            seq_pool.clone(),
            SEQ.to_owned(),
            SECRET.as_bytes(),
            Some(Arc::new(common::proof_i13_signer_for(SEQ))),
        )
        .with_sim_hooks(seq_hooks)
        .with_relationship_authority_of(&seq_rt),
    );

    // HOME and FORGER reach only SEQ.
    let relays = Arc::new(AtomicUsize::new(0));
    let caller_hooks = |did: &'static str| {
        let (sequencer, counted) = (sequencer.clone(), relays.clone());
        Arc::new(SimDsHooks {
            service_did: did.to_owned(),
            self_endpoint: format!("https://{}", host(did)),
            signing_key_pem: None,
            group_relay_hmac_secret: Some(SECRET.to_owned()),
            http_transport: Arc::new(move |request: SimHttpRequest| -> Reply {
                let sequencer = sequencer.clone();
                counted.fetch_add(1, SeqCst);
                Box::pin(async move {
                    if request.url.host_str() != Some(host(SEQ)) {
                        return Err("unreachable".to_owned());
                    }
                    let mut relayed = axum::http::Request::new(Body::from(request.body));
                    *relayed.method_mut() = request.method;
                    *relayed.uri_mut() = request.url.path().parse().unwrap();
                    *relayed.headers_mut() = request.headers;
                    let (parts, body) = sequencer.oneshot(relayed).await.unwrap().into_parts();
                    let body = axum::body::to_bytes(body, usize::MAX)
                        .await
                        .map_err(|error| error.to_string())?;
                    Ok(::http::Response::from_parts(parts, body.to_vec()))
                })
            }),
            dns_resolver: Arc::new(|host: &str| Err(format!("{host} is not resolved here"))),
            retain_application_ciphertext: false,
        })
    };
    let (home_hooks, forger_hooks) = (caller_hooks(HOME), caller_hooks(FORGER));

    // HOME: SEQ's group mirrored with the sender local, its registered device
    // authenticating with its own service-auth key.
    let db_home = common::fresh_db::fresh_fully_migrated_db("chat_fed_relay_").await;
    let home_pool = db_home.connect(4).await;
    http::ensure_fence(&home_pool).await;
    sqlx::query("INSERT INTO federation_peers(ds_did,status) VALUES($1,'allow')")
        .bind(SEQ)
        .execute(&home_pool)
        .await
        .unwrap();
    scope_sim_ds(
        home_hooks.clone(),
        mirror_group_membership(
            &seq_pool,
            &home_pool,
            &fixture,
            SEQ,
            (None, Some(PEER)),
            destination(SEQ),
        ),
    )
    .await;
    let resolver = DsResolver::new(
        home_pool.clone(),
        reqwest::Client::new(),
        HOME.to_owned(),
        format!("https://{}", host(HOME)),
        None,
        300,
    )
    .with_destination_resolver_hook(Arc::new(move |_| {
        Some(Box::pin(async move { Ok(destination(SEQ)) }))
    }));
    let home = http::router_for_authenticated_acceptance_with(home_pool.clone(), |runtime| {
        runtime.with_resolver(Arc::new(resolver))
    })
    .await;
    let auth = P256SigningKey::from_bytes((&[0x47u8; 32]).into()).unwrap();
    let jwk = http::public_jwk(&auth);
    let sender = http::Device {
        did: fixture.sender_did.clone(),
        device_id: fixture.sender_device_id,
        jkt: http::jwk_thumbprint(&jwk),
        jwk,
        signing: auth,
    };
    http::cache_device_did(&sender).await;
    let impostor = http::seed_device(&home_pool).await;
    let answer = |reply: &(StatusCode, Option<String>, Value)| {
        (
            reply.0,
            reply.1.clone(),
            reply.2["error"].as_str().map(str::to_owned),
        )
    };
    let state = || async {
        let fanned_out = fanned_out.lock().unwrap().len();
        (
            durable_rows(&seq_pool).await,
            durable_rows(&home_pool).await,
            fanned_out,
        )
    };
    let signed = fixture.signed_request.clone();
    let blocked = Ok(PublicResponse::json(
        200,
        json!({ "relationships": [{
            "$type": "app.bsky.graph.defs#relationship",
            "did": fixture.recipient_did,
            "blocking": format!("at://{}/app.bsky.graph.block/relay", fixture.sender_did),
        }]}),
    ));
    let retryable = (
        StatusCode::SERVICE_UNAVAILABLE,
        Some("5".to_owned()),
        Some("RelationshipPolicyUnavailable".to_owned()),
    );

    let before = state().await;
    for (fault, expected, attempt) in [
        (
            blocked.clone(),
            (
                StatusCode::BAD_REQUEST,
                None,
                Some("BlockedRelationship".to_owned()),
            ),
            "across a block",
        ),
        (
            Err(TransportError::Network),
            retryable.clone(),
            "source unreachable",
        ),
        (
            Ok(PublicResponse::new(503, Vec::new())),
            retryable.clone(),
            "source answering 503",
        ),
        (
            Ok(PublicResponse::new(429, Vec::new())),
            retryable.clone(),
            "source answering 429",
        ),
    ] {
        *relationships.lock().unwrap() = Some(fault);
        let relayed = relays.load(SeqCst);
        let reply = send_at(&home, &home_hooks, &sender, &signed).await;
        assert_eq!(answer(&reply), expected, "{attempt}");
        assert_eq!(relays.load(SeqCst), relayed + 1, "{attempt}: relayed once");
        assert!(
            state().await == before,
            "{attempt}: nothing persisted or fanned out"
        );
    }
    *relationships.lock().unwrap() = None;
    sqlx::query("ALTER TABLE chat.relationship_projection_snapshots RENAME TO relationship_projection_offline")
        .execute(&seq_pool)
        .await
        .unwrap();
    let failed = send_at(&home, &home_hooks, &sender, &signed).await;
    sqlx::query("ALTER TABLE chat.relationship_projection_offline RENAME TO relationship_projection_snapshots")
        .execute(&seq_pool)
        .await
        .unwrap();
    assert_eq!(answer(&failed), retryable, "SEQ's store failing");
    assert!(
        state().await == before,
        "SEQ's store failing: nothing persisted"
    );

    // FORGER homes neither member: refused as unauthorized, never sequenced.
    let forged = scope_sim_ds(
        forger_hooks,
        relay_group_mutation_to_sequencer(
            &format!("https://{}", host(SEQ)),
            FORGER,
            SEQ,
            SECRET.as_bytes(),
            &RelayGroupMutationRequest {
                conversation_id: fixture.conversation_id,
                endpoint: SEND.to_owned(),
                actor_did: fixture.sender_did.clone(),
                actor_device_id: fixture.sender_device_id,
                signed_request: signed.clone(),
                signed_request_bytes: None,
            },
        ),
    )
    .await;
    assert!(
        matches!(
            forged,
            Err(GroupRelayError::Rejected(
                ChatProtocolErrorCode::NotAuthorized
            ))
        ),
        "{forged:?}"
    );
    // Another principal at HOME presenting the sender's signed send: HOME's
    // admission refuses a signed request naming another principal's device
    // before it relays anything.
    let relayed = relays.load(SeqCst);
    let (status, _, body) = send_at(&home, &home_hooks, &impostor, &signed).await;
    assert_eq!(
        (status, body["error"].as_str()),
        (StatusCode::BAD_REQUEST, Some("InvalidRequest")),
        "impostor: {body}"
    );
    assert_eq!(
        relays.load(SeqCst),
        relayed,
        "the impostor's send is not relayed"
    );
    assert!(state().await == before, "forged: nothing persisted");

    let (status, _, sequenced) = send_at(&home, &home_hooks, &sender, &signed).await;
    assert_eq!(status, StatusCode::OK, "allowed: {sequenced}");
    let seq = sequenced["entry"]["seq"].as_i64().unwrap();
    assert_eq!(
        fanned_out
            .lock()
            .unwrap()
            .iter()
            .filter(|(to, _)| to == host(PEER))
            .map(|(_, seq)| *seq)
            .collect::<Vec<_>>(),
        [seq],
        "the recipient's home receives the sequenced entry once"
    );
    let entries = || async {
        sqlx::query_scalar::<_, i64>("SELECT count(*) FROM chat.entries WHERE conversation_id = $1")
            .bind(fixture.conversation_id)
            .fetch_one(&seq_pool)
            .await
            .unwrap()
    };
    let sequenced_entries = entries().await;
    *relationships.lock().unwrap() = Some(blocked);
    let (status, _, replayed) = send_at(&home, &home_hooks, &sender, &signed).await;
    assert_eq!(
        (status, &replayed),
        (StatusCode::OK, &sequenced),
        "the identical retry replays"
    );
    assert_eq!(
        entries().await,
        sequenced_entries,
        "the replay sequences nothing"
    );
    let mut body = signed["body"].clone();
    body["signedAt"] = json!(Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true));
    let conflicting = sign_mutation_json_for_test(
        &body,
        &ed25519_dalek::SigningKey::from_bytes(&fixture.sender_ed25519_seed),
    )
    .unwrap();
    assert_eq!(
        answer(&send_at(&home, &home_hooks, &sender, &conflicting).await),
        (
            StatusCode::BAD_REQUEST,
            None,
            Some("IdempotencyConflict".to_owned())
        ),
        "another body under the message ID"
    );
    assert_eq!(entries().await, sequenced_entries);

    seq_pool.close().await;
    home_pool.close().await;
}

/// `device`'s `sendMessage` of `signed` at `home`, under its DS's `hooks`:
/// status, `Retry-After` and JSON body.
#[cfg(feature = "sim")]
async fn send_at(
    home: &axum::Router,
    hooks: &Arc<catbird_server::sim_hooks::SimDsHooks>,
    device: &http::Device,
    signed: &serde_json::Value,
) -> (StatusCode, Option<String>, serde_json::Value) {
    use tower_util::ServiceExt as _;
    let body = serde_json::to_vec(&json!({ "signedRequest": signed })).unwrap();
    catbird_server::sim_hooks::scope_sim_ds(Arc::clone(hooks), async {
        let request = http::unsigned_json_request(device, "blue.catbird.chat.sendMessage", body);
        let response = home.clone().oneshot(request).await.unwrap();
        let status = response.status();
        let retry_after = response
            .headers()
            .get(axum::http::header::RETRY_AFTER)
            .and_then(|value| value.to_str().ok())
            .map(str::to_owned);
        let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        (
            status,
            retry_after,
            serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null),
        )
    })
    .await
}

/// The invitee's scoped `getConversations` session identity at its home.
async fn scoped_inventory_session(router: &axum::Router, device: &http::Device) -> String {
    let query = format!(
        "actorDeviceId={}&limit=100&supportedProtocolVersions=1&supportedProtocolVersions=2",
        device.device_id
    );
    let (status, page) = http::send(
        router.clone(),
        http::unsigned_get_request(device, "blue.catbird.chat.getConversations", &query),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "getConversations: {page}");
    page["inventorySessionId"]
        .as_str()
        .expect("inventorySessionId")
        .to_owned()
}

/// A home learns remote-group membership only from its sequencer's
/// `deliverGroupEntry`, which writes `chat.remote_group_memberships` and
/// `chat.remote_group_pending_welcomes` but appends no `chat.events`. The
/// invitee's scoped inventory session must follow that index and its device's
/// Welcome markers (else the home keeps serving the pre-invitation snapshot
/// until it expires and the invitation never appears), keep its identity while
/// nothing changes, and not depend on the order the rows were written.
#[tokio::test]
async fn a_remote_group_index_change_rotates_the_invitees_scoped_inventory_session() {
    let _env_guard = ENV_LOCK.lock().await;
    let seq_did = "did:web:ds-seq.example.com";
    std::env::set_var("SERVICE_DID", "did:web:ds-home-b.example.com");
    std::env::set_var("SELF_ENDPOINT", "https://ds-home-b.example.com");
    let db = common::fresh_db::fresh_fully_migrated_db("chat_fed_relay_").await;
    let pool = db.connect(2).await;
    http::ensure_fence(&pool).await;
    let router = http::router_for_authenticated_acceptance(pool.clone()).await;
    let invitee = http::seed_device(&pool).await;
    let (group_a, group_b, welcome) = (Uuid::new_v4(), Uuid::new_v4(), Uuid::new_v4());
    // Exactly the rows `apply_membership_evidence` writes for a verified entry.
    let index = |conversation_id: Uuid, status: &'static str, evidence_seq: i64| {
        sqlx::query(
            "INSERT INTO chat.remote_group_memberships \
                 (conversation_id, user_did, sequencer_did, status, evidence_seq, \
                  evidence_entry_id, updated_at) \
             VALUES ($1, $2, $3, $4, $5, $6, now()) \
             ON CONFLICT (conversation_id, user_did) DO UPDATE \
                SET status = EXCLUDED.status, evidence_seq = EXCLUDED.evidence_seq, \
                    evidence_entry_id = EXCLUDED.evidence_entry_id",
        )
        .bind(conversation_id)
        .bind(&invitee.did)
        .bind(seq_did)
        .bind(status)
        .bind(evidence_seq)
        .bind(Uuid::new_v4())
        .execute(&pool)
    };
    let mark_welcome = || {
        sqlx::query(
            "INSERT INTO chat.remote_group_pending_welcomes \
                 (conversation_id, user_did, device_id, welcome_id, evidence_seq, created_at) \
             VALUES ($1, $2, $3, $4, 6, now())",
        )
        .bind(group_a)
        .bind(&invitee.did)
        .bind(invitee.device_id)
        .bind(welcome)
        .execute(&pool)
    };

    let before = scoped_inventory_session(&router, &invitee).await;
    assert_eq!(
        scoped_inventory_session(&router, &invitee).await,
        before,
        "an unchanged home keeps the session"
    );
    index(group_a, "pending", 4).await.unwrap();
    let invited = scoped_inventory_session(&router, &invitee).await;
    assert_ne!(invited, before, "the invitation rotates the session");
    assert_eq!(scoped_inventory_session(&router, &invitee).await, invited);
    index(group_a, "active", 5).await.unwrap();
    let accepted = scoped_inventory_session(&router, &invitee).await;
    assert_ne!(accepted, invited, "the acceptance evidence rotates it");
    mark_welcome().await.unwrap();
    let welcomed = scoped_inventory_session(&router, &invitee).await;
    assert_ne!(welcomed, accepted, "the device's Welcome marker rotates it");
    index(group_b, "pending", 7).await.unwrap();
    let both = scoped_inventory_session(&router, &invitee).await;
    assert_ne!(both, welcomed, "a second group rotates it");

    // The same index rewritten in the opposite order is the same session.
    sqlx::query("DELETE FROM chat.remote_group_memberships WHERE user_did = $1")
        .bind(&invitee.did)
        .execute(&pool)
        .await
        .unwrap();
    index(group_b, "pending", 7).await.unwrap();
    index(group_a, "active", 5).await.unwrap();
    mark_welcome().await.unwrap();
    assert_eq!(scoped_inventory_session(&router, &invitee).await, both);

    // The signed removal and the settled Welcome rotate it once more.
    index(group_a, "removed", 8).await.unwrap();
    sqlx::query("DELETE FROM chat.remote_group_pending_welcomes WHERE welcome_id = $1")
        .bind(welcome)
        .execute(&pool)
        .await
        .unwrap();
    let removed = scoped_inventory_session(&router, &invitee).await;
    let sessions = BTreeSet::from([before, invited, accepted, welcomed, both, removed]);
    assert_eq!(sessions.len(), 6, "every index change is its own session");

    pool.close().await;
}

#[tokio::test]
async fn stateless_3a_space_credential_and_read_relays_preserve_headers_reject_ssrf_and_write_zero_rows(
) {
    let _env_guard = ENV_LOCK.lock().await;
    let authority_did = "did:web:remote-space.example.com";
    let home_did = "did:web:chat.catbird.blue";
    std::env::set_var("SERVICE_DID", authority_did);
    std::env::set_var("SELF_ENDPOINT", "https://remote-space.example.com");

    let db_remote = common::fresh_db::fresh_fully_migrated_db("chat_fed_relay_").await;
    let pool_remote = db_remote.connect(2).await;
    http::ensure_fence(&pool_remote).await;
    let remote_fixture =
        seed_clean_slate_application_fixture(&pool_remote, false, authority_did, None)
            .await
            .unwrap();
    let space_uri: String = sqlx::query_scalar(
        "SELECT space_uri FROM chat.conversation_spaces WHERE conversation_id = $1 AND generation = 0",
    )
    .bind(remote_fixture.conversation_id)
    .fetch_one(&pool_remote)
    .await
    .unwrap();

    std::env::set_var("SERVICE_DID", home_did);
    std::env::set_var("SELF_ENDPOINT", "https://chat.catbird.blue");

    // Start remote SpaceHost + mock writer PDS returning Atproto-Space-Mac!
    let authority_key = P256SigningKey::from_bytes((&[0x71u8; 32]).into()).unwrap();
    let user_pds_key = P256SigningKey::from_bytes((&[0x72u8; 32]).into()).unwrap();
    let remote_host = Arc::new(SpaceHostRuntime::new(
        pool_remote.clone(),
        SpaceHostConfig::for_test(authority_did.to_string(), authority_key.clone()),
    ));
    remote_host.register_test_did_endpoint(
        &remote_fixture.sender_did,
        user_pds_key.verifying_key(),
        "http://127.0.0.1:9",
    );

    let captured_read: Arc<Mutex<Option<CapturedUpstreamRead>>> = Arc::new(Mutex::new(None));
    let cap_clone = captured_read.clone();
    let authority_multibase = encode_p256_did_key(
        &P256PublicKey::from_sec1_bytes(
            authority_key
                .verifying_key()
                .to_encoded_point(true)
                .as_bytes(),
        )
        .unwrap(),
    );
    let authority_document = json!({
        "id": authority_did,
        "verificationMethod": [{
            "id": format!("{authority_did}#atproto"),
            "type": "Multikey",
            "controller": authority_did,
            "publicKeyMultibase": authority_multibase.strip_prefix("did:key:").unwrap(),
        }],
    });
    let remote_router = space_host_router(remote_host)
        .route(
            "/.well-known/did.json",
            get(move || {
                let document = authority_document.clone();
                async move { axum::Json(document) }
            }),
        )
        .route(
            "/xrpc/com.atproto.space.getBlob",
            get(
                move |headers: HeaderMap, Query(q): Query<BTreeMap<String, String>>| {
                    let cap = cap_clone.clone();
                    async move {
                        *cap.lock().unwrap() = Some(CapturedUpstreamRead {
                            auth: headers
                                .get("authorization")
                                .and_then(|v| v.to_str().ok())
                                .map(str::to_owned),
                            audience: headers
                                .get("atproto-space-audience")
                                .and_then(|v| v.to_str().ok())
                                .map(str::to_owned),
                            want_mac: headers
                                .get("atproto-space-want-mac")
                                .and_then(|v| v.to_str().ok())
                                .map(str::to_owned),
                            sig_input: headers
                                .get("signature-input")
                                .and_then(|v| v.to_str().ok())
                                .map(str::to_owned),
                            sig: headers
                                .get("signature")
                                .and_then(|v| v.to_str().ok())
                                .map(str::to_owned),
                            query: Some(
                                q.iter()
                                    .map(|(k, v)| format!("{k}={v}"))
                                    .collect::<Vec<_>>()
                                    .join("&"),
                            ),
                        });
                        (
                            StatusCode::OK,
                            [
                                ("content-type", "application/octet-stream"),
                                ("atproto-space-mac", "enc=:AAECAw==:,mac=:BAUGBw==:"),
                            ],
                            b"ciphertext-space-blob-bytes".as_slice(),
                        )
                            .into_response()
                    }
                },
            ),
        );
    let remote_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let remote_addr = remote_listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(remote_listener, remote_router).await.unwrap();
    });

    register_test_space_relay_target(authority_did, &format!("http://{remote_addr}"));

    // Home mls-ds for sender_did
    let db_home = common::fresh_db::fresh_fully_migrated_db("chat_fed_relay_").await;
    let pool_home = db_home.connect(4).await;
    http::ensure_fence(&pool_home).await;
    let home_fixture = seed_clean_slate_application_fixture(&pool_home, false, home_did, None)
        .await
        .unwrap();
    // Align sender DID on home_db to remote_fixture.sender_did by enrolling a device for remote_fixture.sender_did
    let user_did = remote_fixture.sender_did.clone();
    let device_id = Uuid::new_v4();
    sqlx::query("INSERT INTO chat.principals (user_did, created_at) VALUES ($1, clock_timestamp()) ON CONFLICT DO NOTHING")
        .bind(&user_did)
        .execute(&pool_home)
        .await
        .unwrap();
    let dev_p256 = http::random_p256();
    let dev_jwk = http::public_jwk(&dev_p256);
    let dev_jkt = http::jwk_thumbprint(&dev_jwk);
    sqlx::query(
        "INSERT INTO chat.devices (user_did, device_id, device_name, status, dpop_jkt, auth_generation, capabilities, created_at, updated_at) \
         VALUES ($1, $2, 'Mac', 'active', $3, 1, chat.protocol_capabilities(), clock_timestamp(), clock_timestamp())",
    )
    .bind(&user_did)
    .bind(device_id)
    .bind(&dev_jkt)
    .execute(&pool_home)
    .await
    .unwrap();
    let user_dev = http::Device {
        did: user_did.clone(),
        device_id,
        jkt: dev_jkt,
        signing: dev_p256,
        jwk: dev_jwk,
    };
    http::cache_device_did(&user_dev).await;
    let _ = home_fixture;

    let home_router = http::router_for_authenticated_acceptance(pool_home.clone()).await;

    let rows_before = count_mutable_chat_rows(&pool_home).await;

    // 1. relaySpaceCredential exchanges delegation token via home mls-ds with ZERO DB writes!
    let now_sec = Utc::now().timestamp() as u64;
    let pop_key = P256SigningKey::from_bytes((&[0x73u8; 32]).into()).unwrap();
    let cnf_kid = encode_p256_did_key(&P256PublicKey::from(pop_key.verifying_key()));
    let del_token = mint_space_token(
        SpaceTokenKind::Delegation,
        &SpaceSigningKey::P256 {
            signing_key: user_pds_key,
            kid: "#atproto".to_string(),
        },
        &SpaceTokenClaims {
            iss: user_did.clone(),
            sub: space_uri.clone(),
            aud: Some(format!("{authority_did}#atproto_pds")),
            iat: now_sec,
            exp: now_sec + 60,
            jti: "relay-del-1".into(),
            cnf_kid: None,
        },
    )
    .unwrap();

    let (cred_status, cred_resp) = http::send(
        home_router.clone(),
        http::unsigned_json_request(
            &user_dev,
            "blue.catbird.chat.relaySpaceCredential",
            serde_json::to_vec(&json!({
                "actorDeviceId": device_id,
                "authorityDid": authority_did,
                "space": space_uri,
                "delegationToken": del_token,
                "cnfKey": cnf_kid,
            }))
            .unwrap(),
        ),
    )
    .await;
    assert_eq!(
        cred_status,
        StatusCode::OK,
        "relaySpaceCredential failed: {cred_resp}"
    );
    let cred_jwt = cred_resp["credential"].as_str().unwrap().to_string();
    assert!(cred_resp["expiresAt"].as_str().is_some());

    // 2. relaySpaceRead rejects disallowed write NSID (`com.atproto.space.putRecord`) with 400 InvalidNsid!
    let pop_secret = P256Secret::from_slice(&pop_key.to_bytes()).unwrap();
    let signed_hdrs = sign_credential_request(
        &pop_secret,
        &cred_jwt,
        authority_did,
        now_sec,
        "relay-read-1",
    )
    .unwrap();
    let sig_input = signed_hdrs.signature_input.clone();
    let sig_val = signed_hdrs.signature.clone();

    let (bad_nsid_status, bad_nsid_body) = http::send(
        home_router.clone(),
        http::unsigned_json_request(
            &user_dev,
            "blue.catbird.chat.relaySpaceRead",
            serde_json::to_vec(&json!({
                "actorDeviceId": device_id,
                "targetDid": authority_did,
                "nsid": "com.atproto.space.putRecord",
                "credential": cred_jwt,
                "spaceAudience": authority_did,
                "signatureInput": sig_input,
                "signature": sig_val,
            }))
            .unwrap(),
        ),
    )
    .await;
    assert_eq!(bad_nsid_status, StatusCode::BAD_REQUEST);
    assert_eq!(bad_nsid_body["error"], "InvalidNsid");

    // 3. relaySpaceRead rejects SSRF target DID (`did:web:169.254.169.254`) with 400 InvalidTargetEndpoint!
    let (ssrf_status, ssrf_body) = http::send(
        home_router.clone(),
        http::unsigned_json_request(
            &user_dev,
            "blue.catbird.chat.relaySpaceRead",
            serde_json::to_vec(&json!({
                "actorDeviceId": device_id,
                "targetDid": "did:web:169.254.169.254",
                "nsid": "com.atproto.space.getBlob",
                "credential": cred_jwt,
                "spaceAudience": authority_did,
                "signatureInput": sig_input,
                "signature": sig_val,
            }))
            .unwrap(),
        ),
    )
    .await;
    assert_eq!(ssrf_status, StatusCode::BAD_REQUEST);
    assert_eq!(ssrf_body["error"], "InvalidTargetEndpoint");

    // 4. Valid relaySpaceRead forwards exact headers, returns raw bytes, preserves Atproto-Space-Mac,
    //    sets Access-Control-Expose-Headers: Atproto-Space-Mac, and writes ZERO DB rows!
    let want_mac = "did:key:zDnaerx9CtbPJ1q36T5Ln5wYt3MQYeGRG5ehnPAmxcf5mDZpv";
    let read_req = http::unsigned_json_request(
        &user_dev,
        "blue.catbird.chat.relaySpaceRead",
        serde_json::to_vec(&json!({
            "actorDeviceId": device_id,
            "targetDid": authority_did,
            "nsid": "com.atproto.space.getBlob",
            "query": format!("space={}&cid=bafkreiaaaa", urlencoding::encode(&space_uri)),
            "credential": cred_jwt,
            "spaceAudience": authority_did,
            "wantMac": want_mac,
            "signatureInput": sig_input,
            "signature": sig_val,
        }))
        .unwrap(),
    );
    let read_resp = tower_util::ServiceExt::oneshot(home_router, read_req)
        .await
        .unwrap();
    assert_eq!(read_resp.status(), StatusCode::OK);
    assert_eq!(
        read_resp
            .headers()
            .get("atproto-space-mac")
            .and_then(|v| v.to_str().ok()),
        Some("enc=:AAECAw==:,mac=:BAUGBw==:")
    );
    let expose = read_resp
        .headers()
        .get("access-control-expose-headers")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    assert!(
        expose.to_ascii_lowercase().contains("atproto-space-mac"),
        "Access-Control-Expose-Headers must expose Atproto-Space-Mac, got {expose:?}"
    );
    let raw_bytes = axum::body::to_bytes(read_resp.into_body(), 65536)
        .await
        .unwrap();
    assert_eq!(&raw_bytes[..], b"ciphertext-space-blob-bytes");

    let upstream = captured_read.lock().unwrap().clone().expect("upstream hit");
    assert_eq!(
        upstream.auth.as_deref(),
        Some(format!("Atproto-Space-Credential {cred_jwt}").as_str())
    );
    assert_eq!(upstream.audience.as_deref(), Some(authority_did));
    assert_eq!(upstream.want_mac.as_deref(), Some(want_mac));
    assert_eq!(upstream.sig_input.as_deref(), Some(sig_input.as_str()));
    assert_eq!(upstream.sig.as_deref(), Some(sig_val.as_str()));
    assert!(upstream
        .query
        .as_deref()
        .unwrap_or("")
        .contains("cid=bafkreiaaaa"));

    let rows_after = count_mutable_chat_rows(&pool_home).await;
    assert_eq!(
        rows_after, rows_before,
        "3A Space credential & read relays MUST write zero rows in home mls-ds DB"
    );

    pool_home.close().await;
    pool_remote.close().await;
}
