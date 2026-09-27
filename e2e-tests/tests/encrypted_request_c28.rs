//! C28: Group-note separation live end-to-end qualification.
//!
//! Runs against the shipping server fixture, guarded PostgreSQL database,
//! and independent MLS engines.
//!
//! Observed:
//! 1. Note is bound to an authentic group invitation and recipient.
//! 2. Live dedicated-DB shipping-router commits publication before losing its response.
//! 3. Manual byte-identical publish retry acknowledges the committed request idempotently.
//! 4. Exactly one pending invitation transition survives in the target group.
//! 5. Bob decrypts the direct note but has no target-group MLS context or leaf.
//!
//! Target-group Welcome/secret/history disclosure and production outbox recovery
//! require separate recipient-path evidence; this test does not assert them.
#![allow(dead_code)]

#[path = "support/encrypted_requests.rs"]
mod encrypted_requests;
#[path = "support/live_orchestrator.rs"]
mod live_orchestrator;
#[path = "../../../catbird-mls/tests/epoch_secret_test_support.rs"]
mod epoch_secret_test_support;

use anyhow::Context as _;
use base64::{
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
    Engine as _,
};
use catbird_mls::{
    chat_v2::transcript::direct_request::{self as protocol, DirectRequestKind},
    metadata::GroupMetadataV1,
    orchestrator::{
        direct_request_bootstrap::{
            metadata_coordinate, DirectRequestBootstrapInput, DirectRequestIntroductionResult,
            DirectRequestWelcomeInput,
        },
        MlsCryptoContext,
    },
    GroupInvitationReference, MLSError,
};
use encrypted_requests::{
    canonical_future, canonical_now, connect_guarded_request_database, request_database_url,
    seed_service_device, signed_mls_request, DeterministicFaultTransport, FaultBoundary,
    HttpsDidFixture, ServiceIdentity, ShippingServerFixture,
};
use live_orchestrator::mock_credentials::MockCredentials;
use mls_e2e_tests::mls_engine::MlsEngine;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use uuid::Uuid;

/// Read-only projection of the guarded database.
fn psql(sql: &str) -> anyhow::Result<String> {
    let out = std::process::Command::new("psql")
        .args([request_database_url(), "-X", "-A", "-t", "-v", "ON_ERROR_STOP=1", "-c", sql])
        .output()?;
    anyhow::ensure!(out.status.success(), "psql: {}", String::from_utf8_lossy(&out.stderr));
    Ok(String::from_utf8(out.stdout)?.trim().to_owned())
}

#[tokio::test(flavor = "multi_thread")]
async fn c28_live_committed_note_publication_lost_response_retry_no_duplicate_invitation(
) -> anyhow::Result<()> {
    // 1. Connect to guarded database and run migrations
    connect_guarded_request_database(5).await?;

    let did_port = HttpsDidFixture::reserve_port()?;
    let run = Uuid::new_v4().simple().to_string();
    let alice = ServiceIdentity::new(format!("did:web:alice-{run}.request-fixture.catbird.blue"));
    let bob = ServiceIdentity::new(format!("did:web:bob-{run}.request-fixture.catbird.blue"));
    let https = HttpsDidFixture::start(
        did_port,
        &[
            (alice.did.clone(), alice.did_document()),
            (bob.did.clone(), bob.did_document()),
        ],
    )?;

    let alice_engine = MlsEngine::new(&format!("c28-alice-{run}"))?;
    let bob_engine = MlsEngine::new(&format!("c28-bob-{run}"))?;
    epoch_secret_test_support::install(&alice_engine.context());
    let alice_identity = format!("{}#{}", alice.did, alice.device_id);
    let bob_identity = format!("{}#{}", bob.did, bob.device_id);
    alice_engine.create_key_package(&alice_identity)?;
    let (bob_package, bob_package_ref) = bob_engine.create_key_package(&bob_identity)?;
    let (bob_group_package, _) = bob_engine.create_key_package(&bob_identity)?;
    let alice_public = alice_engine.identity_public_key(&alice_identity)?;
    let bob_public = bob_engine.identity_public_key(&bob_identity)?;
    seed_service_device(&alice, &alice_public)?;
    seed_service_device(&bob, &bob_public)?;

    let server = ShippingServerFixture::start(&https)?;
    let client = reqwest::Client::builder().build()?;

    // 2. Bob publishes direct request keys with key package and grant
    let bob_key_id = URL_SAFE_NO_PAD.encode(Sha256::digest(&bob_public));
    let grant_id = Uuid::new_v4();
    let grant = signed_mls_request(
        &bob_engine,
        &bob_identity,
        DirectRequestKind::Grant,
        json!({
            "$type": "blue.catbird.chat.defs#directRequestGrantBody",
            "signatureDomain": "CATBIRD-DIRECT-REQUEST-GRANT\0",
            "protocolVersion": "2",
            "actorDid": bob.did,
            "actorDeviceId": bob.device_id.to_string(),
            "keyId": bob_key_id,
            "authGeneration": 1,
            "grantId": grant_id.to_string(),
            "grantRevision": 1,
            "purpose": "direct-request-bootstrap",
            "profile": "encryptedIntroduction1",
            "keyPackageRef": STANDARD.encode(&bob_package_ref),
            "keyPackageSha256": STANDARD.encode(Sha256::digest(&bob_package)),
            "expiresAt": canonical_future(29),
            "idempotencyKey": grant_id.to_string(),
            "signedAt": canonical_now(),
        }),
    )?;
    let keys = signed_mls_request(
        &bob_engine,
        &bob_identity,
        DirectRequestKind::Keys,
        json!({
            "$type": "blue.catbird.chat.defs#directRequestKeysPublicationBody",
            "signatureDomain": "CATBIRD-DIRECT-REQUEST-KEYS\0",
            "protocolVersion": "2",
            "actorDid": bob.did,
            "actorDeviceId": bob.device_id.to_string(),
            "keyId": bob_key_id,
            "authGeneration": 1,
            "revision": 1,
            "enabled": true,
            "keys": [{
                "keyPackage": {
                    "framing": "mlsMessage",
                    "contentType": "keyPackage",
                    "bytes": STANDARD.encode(&bob_package),
                    "sha256": STANDARD.encode(Sha256::digest(&bob_package)),
                    "keyPackageRef": STANDARD.encode(&bob_package_ref),
                },
                "grant": grant,
            }],
            "idempotencyKey": Uuid::new_v4().to_string(),
            "signedAt": canonical_now(),
        }),
    )?;
    let (keys_status, keys_response) = bob
        .post(
            &client,
            &server.base_url,
            "blue.catbird.chat.publishDirectRequestKeys",
            &json!({"signedRequest": keys}),
            true,
        )
        .await?;
    anyhow::ensure!(
        keys_status == reqwest::StatusCode::OK,
        "publish keys: {keys_status}: {}",
        String::from_utf8_lossy(&keys_response)
    );

    // 3. Alice creates a target group on the live server and invites Bob
    let directory_key = |owner: &ServiceIdentity, key: Vec<u8>| {
        let (client, base, alice) = (client.clone(), server.base_url.clone(), alice.clone());
        let owner = owner.clone();
        async move {
            let key_id = URL_SAFE_NO_PAD.encode(Sha256::digest(&key));
            let (status, body) = alice
                .get_device_key(&client, &base, &owner.did, owner.device_id, &key_id)
                .await?;
            anyhow::ensure!(status == reqwest::StatusCode::OK, "getDeviceKey {status}");
            let served: Value = serde_json::from_slice(&body)?;
            anyhow::Ok(STANDARD.decode(
                served["signaturePublicKey"]["$bytes"]
                    .as_str()
                    .context("signaturePublicKey")?,
            )?)
        }
    };
    let credentials = MockCredentials::new();
    credentials.set_request_authority_document(server.receipt_document.clone());
    credentials.set_authorized_device_keys(
        &alice.did,
        vec![directory_key(&alice, alice_public.clone()).await?],
    );
    credentials.set_authorized_device_keys(
        &bob.did,
        vec![directory_key(&bob, bob_engine.identity_public_key(&bob_identity)?).await?],
    );
    let alice_orchestrator = live_orchestrator::live_orchestrator_with_key_packages(
        alice_engine.context(),
        &alice,
        &client,
        &server.base_url,
        credentials,
        vec![catbird_mls::orchestrator::KeyPackageRef {
            did: bob.did.clone(),
            key_package_data: bob_group_package,
            hash: None,
            cipher_suite: "MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519".into(),
        }],
    )
    .await?;

    let created = alice_orchestrator
        .create_group("C28 Target Group", None, None)
        .await
        .context("create target group")?;
    let target_cid = created.conversation_id.clone();
    alice_orchestrator
        .add_members(&target_cid, &[bob.did.clone()])
        .await
        .context("add bob as pending invitee")?;

    // Verify initial target group invitation state in PostgreSQL
    let initial_transitions = psql(&format!(
        "SELECT count(*) FROM chat.transitions WHERE conversation_id='{target_cid}' AND kind='policy'"
    ))?;
    assert_eq!(
        initial_transitions, "1",
        "target group must have exactly one policy transition from add_members"
    );
    let initial_participant_status = psql(&format!(
        "SELECT status FROM chat.participants WHERE conversation_id='{target_cid}' AND user_did='{}'",
        bob.did
    ))?;
    assert_eq!(
        initial_participant_status, "pending",
        "Bob must be pending in target group"
    );

    // Retrieve authentic invitation reference
    let invitation_ref = alice_orchestrator
        .get_group_invitation_reference(&target_cid, &bob.did)
        .await?
        .context("invitation reference must exist for bob")?;
    assert_eq!(invitation_ref.conversation_id, target_cid);
    assert_eq!(invitation_ref.recipient_did, bob.did);
    assert_eq!(invitation_ref.invited_by_did, alice.did);

    // 4. Alice prepares direct request with Bob
    let (request_id, first_message_id, conversation_id) =
        (Uuid::new_v4(), Uuid::new_v4(), Uuid::new_v4());
    let alice_key_id = URL_SAFE_NO_PAD.encode(Sha256::digest(&alice_public));
    let signed_prepare = signed_mls_request(
        &alice_engine,
        &alice_identity,
        DirectRequestKind::Prepare,
        json!({
            "$type": "blue.catbird.chat.defs#directRequestPreparationBody",
            "signatureDomain": "CATBIRD-DIRECT-REQUEST-PREPARE\0",
            "protocolVersion": "2",
            "actorDid": alice.did,
            "actorDeviceId": alice.device_id.to_string(),
            "keyId": alice_key_id,
            "authGeneration": 1,
            "requestId": request_id.to_string(),
            "firstMessageId": first_message_id.to_string(),
            "conversationId": conversation_id.to_string(),
            "recipientDid": bob.did,
            "origin": {"$type": "blue.catbird.chat.defs#freshDirectOrigin"},
            "profile": "encryptedIntroduction1",
            "idempotencyKey": request_id.to_string(),
            "signedAt": canonical_now(),
        }),
    )?;
    let (prepare_status, prepare_bytes) = alice
        .post(
            &client,
            &server.base_url,
            "blue.catbird.chat.prepareDirectRequest",
            &json!({"signedRequest": signed_prepare}),
            true,
        )
        .await?;
    anyhow::ensure!(
        prepare_status == reqwest::StatusCode::OK,
        "prepareDirectRequest failed {prepare_status}: {}",
        String::from_utf8_lossy(&prepare_bytes)
    );
    let prepare_response: Value = serde_json::from_slice(&prepare_bytes)?;
    let preparation = prepare_response
        .pointer("/outcome/preparation")
        .context("preparation snapshot")?;
    let snapshot = protocol::verify_direct_request_preparation(
        &serde_json::to_vec(preparation)?,
        &server.receipt_public_key,
    )?;
    let selected = snapshot["selectedDevices"]
        .as_array()
        .context("selectedDevices")?;
    let verified_prepare = protocol::verify_signed_request(
        DirectRequestKind::Prepare,
        &serde_json::to_vec(&signed_prepare)?,
        &alice_public,
    )?;

    // 5. Alice bootstraps the 1:1 request group carrying the invitation note
    let context = json!({
        "protocolVersion": "2",
        "requestId": request_id.to_string(),
        "firstMessageId": first_message_id.to_string(),
        "conversationId": conversation_id.to_string(),
        "origin": {"$type": "blue.catbird.chat.defs#freshDirectOrigin"},
        "actorDid": alice.did,
        "actorDeviceId": alice.device_id.to_string(),
        "actorKeyId": alice_key_id,
        "recipientDid": bob.did,
        "preparationDigest": snapshot["preparationDigest"],
    });
    let decode_pkg = |d: &Value, k: &str| -> anyhow::Result<Vec<u8>> {
        Ok(STANDARD.decode(
            d["keyPackage"][k]
                .as_str()
                .context("package field")?,
        )?)
    };
    let journal = alice_engine.prepare_direct_request(&DirectRequestBootstrapInput {
        draft_id: Uuid::new_v4().to_string(),
        context_json: serde_json::to_vec(&context)?,
        group_id: rand::random::<[u8; 32]>().to_vec(),
        generation: 0,
        state_version: 1,
        key_packages: selected
            .iter()
            .map(|d| decode_pkg(d, "bytes"))
            .collect::<anyhow::Result<_>>()?,
        expected_package_refs: selected
            .iter()
            .map(|d| decode_pkg(d, "keyPackageRef"))
            .collect::<anyhow::Result<_>>()?,
        authority_import_until: u64::try_from(
            chrono::DateTime::parse_from_rfc3339(
                snapshot["minimumImportUntil"]
                    .as_str()
                    .context("minimumImportUntil")?,
            )?
            .timestamp(),
        )?,
        preparation_request_digest: *verified_prepare.request_digest(),
        receipt_authority_key: server.receipt_public_key.clone(),
        text: "Please join our group chat".into(),
        invitation: Some(invitation_ref.clone()),
        metadata: GroupMetadataV1 {
            version: 1,
            title: String::new(),
            description: String::new(),
            avatar_blob_locator: None,
            avatar_content_type: None,
        },
    })?;
    let b = &journal.bootstrap;

    // 6. Build the signed publication body
    let mut body = signed_prepare["body"].clone();
    body["$type"] = json!("blue.catbird.chat.defs#directRequestPublicationBody");
    body["signatureDomain"] = json!("CATBIRD-DIRECT-REQUEST-PUBLISH\0");
    body["signedAt"] = json!(canonical_now());
    body["preparationDigest"] = snapshot["preparationDigest"].clone();
    body["preparationRequestDigest"] = json!(STANDARD.encode(verified_prepare.request_digest()));
    body["contextHash"] = json!(STANDARD.encode(b.context_hash));
    body["next"] = b.coordinates.clone();
    body["importUntil"] = json!(chrono::DateTime::from_timestamp(b.import_until as i64, 0)
        .context("import timestamp")?
        .to_rfc3339_opts(chrono::SecondsFormat::Millis, true));
    let artifact = |data: &[u8], kind: &str| {
        json!({
            "framing": "mlsMessage",
            "contentType": kind,
            "bytes": STANDARD.encode(data),
            "sha256": STANDARD.encode(Sha256::digest(data)),
        })
    };
    let deliveries = selected
        .iter()
        .map(|d| {
            json!({
                "recipientDid": d["actorDid"],
                "recipientDeviceId": d["actorDeviceId"],
                "provenance": {
                    "requestId": request_id.to_string(),
                    "preparationDigest": snapshot["preparationDigest"],
                    "contextHash": STANDARD.encode(b.context_hash),
                    "grantId": d["grant"]["body"]["grantId"],
                    "grantRevision": d["grant"]["body"]["grantRevision"],
                    "keyPackageRef": d["keyPackage"]["keyPackageRef"],
                    "importUntil": body["importUntil"],
                }
            })
        })
        .collect::<Vec<_>>();
    let author = json!({
        "authorDid": alice.did,
        "authorDeviceId": alice.device_id.to_string(),
        "authorKeyId": alice_key_id,
        "signaturePublicKey": STANDARD.encode(&alice_public),
        "authGenerationAtOrigin": 1,
        "originTransitionId": request_id.to_string(),
        "originSeq": 1,
        "roleAtOrigin": "admin",
        "deviceStatusAtOrigin": "active",
    });
    body["artifacts"] = json!({
        "genesisGroupInfo": artifact(&b.genesis_group_info, "groupInfo"),
        "addCommit": artifact(&b.add_commit, "publicMessageCommit"),
        "finalGroupInfo": artifact(&b.final_group_info, "groupInfo"),
        "welcome": {
            "opaqueWelcome": STANDARD.encode(&b.welcome),
            "sha256": STANDARD.encode(Sha256::digest(&b.welcome)),
            "deliveries": deliveries,
        },
        "initialCiphertext": STANDARD.encode(&b.initial_ciphertext),
        "metadataSnapshot": {
            "coordinate": metadata_coordinate(&b.coordinates)?,
            "originTransitionId": request_id.to_string(),
            "metadataVersion": 1,
            "nonce": STANDARD.encode(&b.metadata_nonce),
            "ciphertext": STANDARD.encode(&b.metadata_ciphertext),
            "ciphertextSha256": STANDARD.encode(Sha256::digest(&b.metadata_ciphertext)),
            "ciphertextSize": b.metadata_ciphertext.len(),
            "authorProof": author,
        }
    });
    let signed_publish = signed_mls_request(
        &alice_engine,
        &alice_identity,
        DirectRequestKind::Publish,
        body,
    )?;
    let exact_publication = serde_json::to_vec(&json!({"signedRequest": signed_publish}))?;

    // 7. Fault boundary: send publication through DeterministicFaultTransport.
    // The server commits the publication transaction, then the transport drops the HTTP response.
    let mut transport = DeterministicFaultTransport::default()
        .fail_on(FaultBoundary::AfterRequestBeforeResponse, 1)?;
    let mut headers = reqwest::header::HeaderMap::new();
    headers.insert(
        reqwest::header::AUTHORIZATION,
        format!(
            "Bearer {}",
            alice.scoped_jwt_with_jti("blue.catbird.chat.publishDirectRequest", Uuid::new_v4())
        )
        .parse()?,
    );
    let fault_client = reqwest::Client::builder()
        .default_headers(headers)
        .build()?;
    let body_val: Value = serde_json::from_slice(&exact_publication)?;
    let lost_res = transport
        .post_json(
            &fault_client,
            &format!("{}/xrpc/blue.catbird.chat.publishDirectRequest", server.base_url),
            &body_val,
        )
        .await;
    let lost_err = lost_res.expect_err("response must be lost after server commits");
    assert!(
        lost_err.to_string().contains("AfterRequestBeforeResponse"),
        "unexpected transport failure: {lost_err:#}"
    );
    assert_eq!(
        transport.trace(),
        &[FaultBoundary::BeforeRequest, FaultBoundary::AfterRequestBeforeResponse]
    );

    // 8. Server check after lost response:
    // The server committed the publication, but target group transitions are untouched.
    let pub_count_after_lost = psql(&format!(
        "SELECT count(*) FROM chat.direct_request_publications WHERE request_id='{request_id}'"
    ))?;
    assert_eq!(
        pub_count_after_lost, "1",
        "server must have committed publication despite lost response"
    );
    let trans_count_after_lost = psql(&format!(
        "SELECT count(*) FROM chat.transitions WHERE conversation_id='{target_cid}' AND kind='policy'"
    ))?;
    assert_eq!(
        trans_count_after_lost, "1",
        "target group must still have exactly one invitation transition after lost response"
    );

    // 9. Retry: Alice replays the exact same publication bytes
    let (retry_status, retry_bytes) = alice
        .post(
            &client,
            &server.base_url,
            "blue.catbird.chat.publishDirectRequest",
            &body_val,
            true,
        )
        .await?;
    assert_eq!(
        retry_status,
        reqwest::StatusCode::OK,
        "retry should succeed with 200 OK: {}",
        String::from_utf8_lossy(&retry_bytes)
    );
    let retry_response: Value = serde_json::from_slice(&retry_bytes)?;
    let outcome = &retry_response["outcome"];

    // 10. Cardinality assertions:
    // Exactly one publication row for this request
    let pub_count_after_retry = psql(&format!(
        "SELECT count(*) FROM chat.direct_request_publications WHERE request_id='{request_id}'"
    ))?;
    assert_eq!(
        pub_count_after_retry, "1",
        "retry must not duplicate publication"
    );

    // Exactly one invitation transition in the target group (no duplication)
    let trans_count_after_retry = psql(&format!(
        "SELECT count(*) FROM chat.transitions WHERE conversation_id='{target_cid}' AND kind='policy'"
    ))?;
    assert_eq!(
        trans_count_after_retry, "1",
        "retry must not duplicate target-group invitation transition"
    );

    // Exactly one participant row for Bob in the target group
    let participant_rows = psql(&format!(
        "SELECT count(*) FROM chat.participants WHERE conversation_id='{target_cid}' AND user_did='{}'",
        bob.did
    ))?;
    assert_eq!(
        participant_rows, "1",
        "Bob must have exactly one participant row in target group"
    );

    // Bob's participant status in target group remains pending before consent
    let participant_status = psql(&format!(
        "SELECT status FROM chat.participants WHERE conversation_id='{target_cid}' AND user_did='{}'",
        bob.did
    ))?;
    assert_eq!(
        participant_status, "pending",
        "Bob must remain pending in target group before consent"
    );

    // 11. Recipient decryption: Bob imports direct request Welcome and decrypts the note
    let mut normalized_receipt = outcome.clone();
    normalized_receipt
        .as_object_mut()
        .context("outcome")?
        .remove("$type");
    let welcome_input = DirectRequestWelcomeInput {
        bootstrap: b.clone(),
        local_identity: bob_identity.as_bytes().to_vec(),
        local_package_ref: bob_package_ref.clone(),
        publication_request: exact_publication.clone(),
        actor_signature_public_key: alice_public.clone(),
        published_receipt: serde_json::to_vec(&normalized_receipt)?,
        receipt_authority_key: server.receipt_public_key.clone(),
        preparation_request_digest: *verified_prepare.request_digest(),
    };
    bob_engine.process_direct_request(&welcome_input)?;
    let decrypted = bob_engine.decrypt_direct_request(&welcome_input)?;
    let DirectRequestIntroductionResult::Ready { plaintext } = decrypted else {
        anyhow::bail!("recipient introduction unavailable")
    };
    let intro = protocol::decode_direct_request_introduction(&plaintext)?;
    assert_eq!(intro["text"], "Please join our group chat");
    let intro_invitation = intro["invitation"]
        .as_object()
        .context("invitation in intro")?;
    assert_eq!(intro_invitation["conversationId"], target_cid);
    assert_eq!(
        intro_invitation["invitationTransitionId"],
        invitation_ref.invitation_transition_id
    );

    // 12. Invariant: NO TARGET-GROUP MLS IMPORT BEFORE CONSENT
    // Bob has NOT imported the target group MLS group!
    let target_gid = hex::decode(&created.group_id)?;
    assert!(
        matches!(
            bob_engine.context().get_epoch(target_gid.clone()),
            Err(MLSError::GroupNotFound { .. })
        ),
        "Bob must have no target-group epoch before consent"
    );
    assert!(
        matches!(
            bob_engine.context().group_is_active(target_gid.clone()),
            Err(MLSError::GroupNotFound { .. })
        ),
        "Bob must have no target-group context before consent"
    );
    let target_members = alice_engine.context().group_member_identities(target_gid)?;
    assert!(
        !target_members.iter().any(|identity| {
            identity
                .windows(bob.did.len())
                .any(|bytes| bytes == bob.did.as_bytes())
        }),
        "Target group leaves must NOT include Bob before group consent: {target_members:?}"
    );

    Ok(())
}
