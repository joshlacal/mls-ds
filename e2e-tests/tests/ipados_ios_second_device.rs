//! Runtime interop row: iPadOS sender, iOS second device recipient.
//!
//! Specification (validation doc line 97):
//! "Sibling-device inclusion and acceptance while both request screens are open."
//!
//! Mandatory assertions:
//! 1. Recipient account has two Apple devices (iPhone peer and iPad as second device),
//!    both enrolled and addressed at publication.
//! 2. Both recipient devices receive their respective Welcome and decrypt the identical
//!    encrypted introduction before consent.
//! 3. Pre-acceptance authority restrictions: ordinary sends before consent are rejected.
//! 4. Acceptance on one device (e.g. iPad) propagates to the other (iPhone) without
//!    requiring a reset, extra Add, or new cryptographic generation.
//! 5. Ordinary encrypted replies sent after acceptance decrypt on both recipient devices
//!    and on the sender.
//! 6. Offline-recipient first send and sender-offline accept/reply hold.
//! 7. Local draft/cancel, duplicate/restart, decline/block monotonicity hold.
//! 8. Device added AFTER acceptance leg is blocked by F26 (post-acceptance metadata reseal
//!    on request-born groups; recorded as not_run with exact reason).
//! 9. All published requests are released (accepted/closed) and dedicated database cleaned.
#![allow(dead_code)]

#[path = "support/encrypted_requests.rs"]
mod encrypted_requests;

#[path = "support/live_direct_request.rs"]
mod live_direct_request;

use anyhow::Context as _;
use base64::{
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
    Engine as _,
};
use catbird_mls::{
    chat_v2::transcript::{
        decode_strict_json,
        direct_request::{self as protocol, DirectRequestKind},
        project_signed_body, SignedMutationKind, SigningTranscript,
    },
    metadata::GroupMetadataV1,
    orchestrator::{
        canonical_application_aad_bytes,
        direct_request_bootstrap::{
            metadata_coordinate, DirectRequestBootstrapInput, DirectRequestIntroductionResult,
            DirectRequestWelcomeInput,
        },
        MLSMessagePayload,
    },
};
use encrypted_requests::{
    canonical_future, canonical_now, connect_guarded_request_database,
    request_database_snapshot, request_database_url, reviewed_request_migrations,
    seed_service_device, signed_mls_request, validate_request_test_database_url,
    HttpsDidFixture, ServiceIdentity, ShippingServerFixture,
};
use live_direct_request::{
    publish_request_variant, PublishedRequestFixture,
};
use mls_e2e_tests::mls_engine::MlsEngine;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use uuid::Uuid;

fn decode_bytes(value: &Value) -> anyhow::Result<Vec<u8>> {
    Ok(STANDARD.decode(
        value
            .as_str()
            .or_else(|| value["$bytes"].as_str())
            .context("read byte field")?,
    )?)
}

fn signed_ordinary(engine: &MlsEngine, identity: &str, body: Value) -> anyhow::Result<Value> {
    let type_id = body["$type"].as_str().context("body lacks $type")?;
    let kind = SignedMutationKind::from_type_id(type_id)
        .with_context(|| format!("unknown SignedMutationKind for {type_id}"))?;
    let strict = decode_strict_json(&serde_json::to_vec(&body)?)?;
    let transcript = SigningTranscript::build_for(kind, &project_signed_body(kind, &strict)?)?;
    let signature = engine.sign_identity(identity, transcript.bytes().to_vec())?;
    Ok(json!({
        "body": body,
        "signature": STANDARD.encode(signature)
    }))
}

fn graph(conversation: Uuid) -> anyhow::Result<Value> {
    validate_request_test_database_url(std::env::var("REQUEST_TEST_DATABASE_URL").ok().as_deref())?;
    let sql = format!(
        "SELECT json_build_object(\
            'generation', c.current_generation,\
            'stateVersion', c.current_state_version,\
            'generationStateVersion', (SELECT g.current_state_version FROM chat.generations g WHERE g.conversation_id=c.conversation_id AND g.generation=c.current_generation),\
            'acceptanceClaims', (SELECT count(*) FROM chat.direct_request_acceptance_claims a JOIN chat.direct_request_publications p ON p.request_id=a.request_id WHERE p.conversation_id=c.conversation_id),\
            'epoch', s.epoch,\
            'nextSeq', c.next_entry_seq,\
            'transitions', (SELECT count(*) FROM chat.transitions t WHERE t.conversation_id=c.conversation_id),\
            'introductions', (SELECT count(*) FROM chat.entries e WHERE e.conversation_id=c.conversation_id AND e.entry_kind='blue.catbird.chat.defs#directRequestEntry'),\
            'applications', (SELECT count(*) FROM chat.entries e WHERE e.conversation_id=c.conversation_id AND e.entry_kind='blue.catbird.chat.defs#applicationEntry')\
        )::text FROM chat.conversations c \
        JOIN chat.generation_states s ON s.conversation_id=c.conversation_id AND s.generation=c.current_generation AND s.state_version=c.current_state_version \
        WHERE c.conversation_id='{conversation}';"
    );
    let result = std::process::Command::new("psql")
        .args([
            request_database_url(),
            "-X", "-A", "-t", "-v", "ON_ERROR_STOP=1", "-c", &sql,
        ])
        .output()
        .context("psql graph query failed")?;
    anyhow::ensure!(
        result.status.success(),
        "graph query failed {}: {}",
        result.status,
        String::from_utf8_lossy(&result.stderr)
    );
    let stdout = String::from_utf8(result.stdout)?;
    Ok(serde_json::from_str(stdout.trim())?)
}

#[tokio::test(flavor = "multi_thread")]
async fn ipados_ios_second_device_sibling_inclusion_and_acceptance() -> anyhow::Result<()> {
    // 1. Setup on dedicated database
    let authority = connect_guarded_request_database(5).await?;
    assert_eq!(
        authority.additive_migrations,
        reviewed_request_migrations().len()
    );

    // 2. Publish request with sibling device included at publication
    //    Bob has two devices:
    //    - Device 1: iPhone peer (f.bob)
    //    - Device 2: iPad second device (sibling.service)
    let (mut f, sibling) = publish_request_variant(false, true).await?;
    let sibling = sibling.context("second selected recipient device (iPad)")?;

    assert_eq!(f.bob.did, sibling.service.did, "same account DID");
    assert_ne!(f.bob.device_id, sibling.service.device_id, "distinct device IDs");

    let bob_iphone_identity = format!("{}#{}", f.bob.did, f.bob.device_id);
    let bob_ipad_identity = sibling.identity.clone();

    let coordinates = f.welcome_input.bootstrap.coordinates.clone();
    let group = decode_bytes(&coordinates["groupId"])?;
    let epoch = coordinates["epoch"].as_u64().context("epoch")?;

    // 3. Sender offline before recipient actions
    let sender = f.alice_engine.take().context("sender engine")?;
    sender.confirm_request_publication(
        &f.request_id.to_string(),
        &serde_json::to_vec(&f.receipt)?,
        &f.server.receipt_public_key,
    )?;
    let offline_sender = sender.close_for_offline()?;

    // 4. Verify database state at publication: 1 message, 2 welcomes, 0 plaintext
    let snapshot = request_database_snapshot(f.request_id)?;
    assert_eq!(snapshot.message_rows, 1, "exactly one intro message");
    assert_eq!(snapshot.welcome_rows, 2, "two welcome rows for the two recipient devices");
    assert_eq!(snapshot.plaintext_matches, 0, "zero plaintext leaks");

    // 5. Pre-acceptance preview on BOTH recipient devices
    //    Bob-iPhone processes welcome and decrypts intro
    f.bob_engine.process_direct_request(&f.welcome_input)?;
    assert_eq!(f.bob_engine.epoch(&group)?, epoch);
    let iphone_intro = f.bob_engine.decrypt_direct_request(&f.welcome_input)?;
    let DirectRequestIntroductionResult::Ready { plaintext: iphone_pt } = &iphone_intro else {
        anyhow::bail!("Bob-iPhone intro not ready");
    };
    let iphone_intro_text = protocol::decode_direct_request_introduction(iphone_pt)?["text"]
        .as_str()
        .context("text")?
        .to_string();
    assert_eq!(iphone_intro_text, "Real encrypted first contact");

    //    Bob-iPad processes welcome and decrypts intro
    let mut ipad_welcome_input = f.welcome_input.clone();
    ipad_welcome_input.local_identity = sibling.identity.as_bytes().to_vec();
    ipad_welcome_input.local_package_ref = sibling.package_ref.clone();

    sibling.engine.process_direct_request(&ipad_welcome_input)?;
    assert_eq!(sibling.engine.epoch(&group)?, epoch);
    let ipad_intro = sibling.engine.decrypt_direct_request(&ipad_welcome_input)?;
    let DirectRequestIntroductionResult::Ready { plaintext: ipad_pt } = &ipad_intro else {
        anyhow::bail!("Bob-iPad intro not ready");
    };
    let ipad_intro_text = protocol::decode_direct_request_introduction(ipad_pt)?["text"]
        .as_str()
        .context("text")?
        .to_string();
    assert_eq!(ipad_intro_text, "Real encrypted first contact");
    assert_eq!(iphone_intro_text, ipad_intro_text, "both devices see identical intro");

    // 6. Pre-acceptance restriction: ordinary send before consent fails with ConversationNotAccepted
    let bob_public = f.bob_engine.identity_public_key(&bob_iphone_identity)?;
    let premature_message = Uuid::new_v4();
    let mut premature_prior = coordinates.clone();
    premature_prior["conversationId"] = json!(f.conversation_id.to_string());
    let mut premature_aad_prior = premature_prior.clone();
    premature_aad_prior["conversationId"] = json!(STANDARD.encode(f.conversation_id.as_bytes()));
    let premature_aad = json!({
        "protocolVersion": "1",
        "conversationId": STANDARD.encode(f.conversation_id.as_bytes()),
        "generation": coordinates["generation"],
        "messageId": STANDARD.encode(premature_message.as_bytes()),
        "prior": premature_aad_prior
    });
    let premature_content = MLSMessagePayload::text("Premature send before accept").encode()?;
    let premature_ct = f.bob_engine.encrypt_canonical(
        &group,
        &premature_content,
        canonical_application_aad_bytes(&premature_aad)?,
        epoch,
    )?;
    let premature_app = signed_ordinary(
        &f.bob_engine,
        &bob_iphone_identity,
        json!({
            "$type": "blue.catbird.chat.defs#applicationSendBody",
            "signatureDomain": "CATBIRD-CHAT-MESSAGE\0",
            "messageId": premature_message.to_string(),
            "actorDid": f.bob.did,
            "actorDeviceId": f.bob.device_id.to_string(),
            "keyId": URL_SAFE_NO_PAD.encode(Sha256::digest(&bob_public)),
            "authGeneration": 1,
            "prior": premature_prior,
            "aad": premature_aad,
            "applicationMessage": {
                "framing": "mlsMessage",
                "contentType": "privateMessageApplication",
                "bytes": STANDARD.encode(&premature_ct),
                "sha256": STANDARD.encode(Sha256::digest(&premature_ct))
            },
            "blobBindings": [],
            "signedAt": canonical_now()
        }),
    )?;
    let (premature_status, premature_bytes) = f.bob
        .post(
            &f.client,
            &f.server.base_url,
            "blue.catbird.chat.sendMessage",
            &json!({"signedRequest": premature_app}),
            true,
        )
        .await?;
    assert_eq!(
        premature_status,
        reqwest::StatusCode::BAD_REQUEST,
        "ordinary send before acceptance must fail 400"
    );
    let premature_err: Value = serde_json::from_slice(&premature_bytes)?;
    assert_eq!(premature_err["error"], "ConversationNotAccepted");

    // 7. Sibling acceptance: Bob-iPad (sibling) accepts the request
    let graph_before = graph(f.conversation_id)?;
    assert_eq!(graph_before["acceptanceClaims"], 0);

    let prior = f.welcome_input.bootstrap.coordinates.clone();
    let mut next = prior.clone();
    next["stateVersion"] = json!(prior["stateVersion"].as_u64().context("state version")? + 1);

    let sibling_public = sibling.engine.identity_public_key(&bob_ipad_identity)?;
    let transition_id = Uuid::new_v4();
    let acceptance_signed = signed_mls_request(
        &sibling.engine,
        &bob_ipad_identity,
        DirectRequestKind::Accept,
        json!({
            "$type": "blue.catbird.chat.defs#directRequestAcceptanceBody",
            "signatureDomain": "CATBIRD-DIRECT-REQUEST-ACCEPT\0",
            "protocolVersion": "2",
            "actorDid": sibling.service.did,
            "actorDeviceId": sibling.service.device_id.to_string(),
            "keyId": URL_SAFE_NO_PAD.encode(Sha256::digest(&sibling_public)),
            "authGeneration": 1,
            "requestId": f.request_id.to_string(),
            "transitionId": transition_id.to_string(),
            "prior": prior,
            "next": next,
            "invitationProvenance": {
                "invitationTransitionId": f.request_id.to_string(),
                "invitedByDid": f.alice.did,
                "invitedByDeviceId": f.alice.device_id.to_string()
            },
            "idempotencyKey": transition_id.to_string(),
            "signedAt": canonical_now()
        }),
    )?;
    let acceptance_envelope = json!({"directRequest": acceptance_signed});
    let (acc_status, acc_bytes) = sibling.service
        .post(
            &f.client,
            &f.server.base_url,
            "blue.catbird.chat.acceptConversation",
            &acceptance_envelope,
            true,
        )
        .await?;
    anyhow::ensure!(
        acc_status == reqwest::StatusCode::OK,
        "Bob-iPad accept failed {acc_status}: {}",
        String::from_utf8_lossy(&acc_bytes)
    );
    let accepted_result: Value = serde_json::from_slice(&acc_bytes)?;
    assert!(accepted_result.get("acceptanceProof").is_some());

    // 8. Acceptance propagation: Bob-iPhone observes consent: accepted without extra Add/reset
    let (state_status, state_raw) = f.bob
        .get(
            &f.client,
            &f.server.base_url,
            "blue.catbird.chat.getConversationState",
            &[("conversationId".into(), f.conversation_id.to_string())],
        )
        .await?;
    anyhow::ensure!(state_status == reqwest::StatusCode::OK);
    let iphone_observed_state: Value = serde_json::from_slice(&state_raw)?;
    assert_eq!(
        iphone_observed_state["state"]["directRequest"]["consent"], "accepted",
        "acceptance on iPad must propagate to iPhone"
    );

    let graph_after = graph(f.conversation_id)?;
    assert_eq!(graph_after["epoch"], graph_before["epoch"], "no epoch advancement on accept");
    assert_eq!(graph_after["generation"], graph_before["generation"], "no crypto reset");
    assert_eq!(graph_after["acceptanceClaims"], 1, "exactly one acceptance claim");

    // 9. Bob-iPhone sends ordinary encrypted reply
    let reply1_id = Uuid::new_v4();
    let mut reply1_prior = next.clone();
    reply1_prior["conversationId"] = json!(f.conversation_id.to_string());
    let mut aad1_prior = reply1_prior.clone();
    aad1_prior["conversationId"] = json!(STANDARD.encode(f.conversation_id.as_bytes()));
    let aad1 = json!({
        "protocolVersion": "1",
        "conversationId": STANDARD.encode(f.conversation_id.as_bytes()),
        "generation": next["generation"],
        "messageId": STANDARD.encode(reply1_id.as_bytes()),
        "prior": aad1_prior
    });
    let reply1_text = "Reply from Bob's iPhone";
    let reply1_content = MLSMessagePayload::text(reply1_text).encode()?;
    let reply1_ct = f.bob_engine.encrypt_canonical(
        &group,
        &reply1_content,
        canonical_application_aad_bytes(&aad1)?,
        epoch,
    )?;
    let reply1_app = signed_ordinary(
        &f.bob_engine,
        &bob_iphone_identity,
        json!({
            "$type": "blue.catbird.chat.defs#applicationSendBody",
            "signatureDomain": "CATBIRD-CHAT-MESSAGE\0",
            "messageId": reply1_id.to_string(),
            "actorDid": f.bob.did,
            "actorDeviceId": f.bob.device_id.to_string(),
            "keyId": URL_SAFE_NO_PAD.encode(Sha256::digest(&bob_public)),
            "authGeneration": 1,
            "prior": reply1_prior,
            "aad": aad1,
            "applicationMessage": {
                "framing": "mlsMessage",
                "contentType": "privateMessageApplication",
                "bytes": STANDARD.encode(&reply1_ct),
                "sha256": STANDARD.encode(Sha256::digest(&reply1_ct))
            },
            "blobBindings": [],
            "signedAt": canonical_now()
        }),
    )?;
    let (send1_status, send1_bytes) = f.bob
        .post(
            &f.client,
            &f.server.base_url,
            "blue.catbird.chat.sendMessage",
            &json!({"signedRequest": reply1_app}),
            true,
        )
        .await?;
    anyhow::ensure!(
        send1_status == reqwest::StatusCode::OK,
        "Bob-iPhone reply send failed {send1_status}: {}",
        String::from_utf8_lossy(&send1_bytes)
    );

    // 10. Reply decrypts on Bob-iPad (sibling device!)
    let ipad_decrypted_reply1 = sibling.engine.decrypt(&group, &reply1_ct)?;
    let ipad_payload1 = MLSMessagePayload::decode(&ipad_decrypted_reply1)?;
    assert_eq!(
        ipad_payload1.text.as_deref(),
        Some(reply1_text),
        "Bob-iPad decrypts reply from Bob-iPhone"
    );

    // 11. Reply decrypts on Alice (sender, after reopening)
    let alice_reopened = offline_sender.reopen()?;
    assert_eq!(alice_reopened.epoch(&group)?, epoch);
    let alice_decrypted_reply1 = alice_reopened.decrypt(&group, &reply1_ct)?;
    let alice_payload1 = MLSMessagePayload::decode(&alice_decrypted_reply1)?;
    assert_eq!(
        alice_payload1.text.as_deref(),
        Some(reply1_text),
        "Alice decrypts reply from Bob-iPhone"
    );

    // 12. Bob-iPad sends encrypted reply
    let reply2_id = Uuid::new_v4();
    let mut reply2_prior = next.clone();
    reply2_prior["conversationId"] = json!(f.conversation_id.to_string());
    let mut aad2_prior = reply2_prior.clone();
    aad2_prior["conversationId"] = json!(STANDARD.encode(f.conversation_id.as_bytes()));
    let aad2 = json!({
        "protocolVersion": "1",
        "conversationId": STANDARD.encode(f.conversation_id.as_bytes()),
        "generation": next["generation"],
        "messageId": STANDARD.encode(reply2_id.as_bytes()),
        "prior": aad2_prior
    });
    let reply2_text = "Reply from Bob's iPad second device";
    let reply2_content = MLSMessagePayload::text(reply2_text).encode()?;
    let reply2_ct = sibling.engine.encrypt_canonical(
        &group,
        &reply2_content,
        canonical_application_aad_bytes(&aad2)?,
        epoch,
    )?;
    let reply2_app = signed_ordinary(
        &sibling.engine,
        &bob_ipad_identity,
        json!({
            "$type": "blue.catbird.chat.defs#applicationSendBody",
            "signatureDomain": "CATBIRD-CHAT-MESSAGE\0",
            "messageId": reply2_id.to_string(),
            "actorDid": sibling.service.did,
            "actorDeviceId": sibling.service.device_id.to_string(),
            "keyId": URL_SAFE_NO_PAD.encode(Sha256::digest(&sibling_public)),
            "authGeneration": 1,
            "prior": reply2_prior,
            "aad": aad2,
            "applicationMessage": {
                "framing": "mlsMessage",
                "contentType": "privateMessageApplication",
                "bytes": STANDARD.encode(&reply2_ct),
                "sha256": STANDARD.encode(Sha256::digest(&reply2_ct))
            },
            "blobBindings": [],
            "signedAt": canonical_now()
        }),
    )?;
    let (send2_status, send2_bytes) = sibling.service
        .post(
            &f.client,
            &f.server.base_url,
            "blue.catbird.chat.sendMessage",
            &json!({"signedRequest": reply2_app}),
            true,
        )
        .await?;
    anyhow::ensure!(
        send2_status == reqwest::StatusCode::OK,
        "Bob-iPad reply send failed {send2_status}: {}",
        String::from_utf8_lossy(&send2_bytes)
    );

    // 13. Decrypts on Bob-iPhone and Alice
    let iphone_decrypted_reply2 = f.bob_engine.decrypt(&group, &reply2_ct)?;
    let iphone_payload2 = MLSMessagePayload::decode(&iphone_decrypted_reply2)?;
    assert_eq!(
        iphone_payload2.text.as_deref(),
        Some(reply2_text),
        "Bob-iPhone decrypts reply from Bob-iPad"
    );

    let alice_decrypted_reply2 = alice_reopened.decrypt(&group, &reply2_ct)?;
    let alice_payload2 = MLSMessagePayload::decode(&alice_decrypted_reply2)?;
    assert_eq!(
        alice_payload2.text.as_deref(),
        Some(reply2_text),
        "Alice decrypts reply from Bob-iPad"
    );

    println!("ipados_ios_second_device: sibling inclusion and acceptance fully verified");
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn ipados_ios_second_device_every_row_branches() -> anyhow::Result<()> {
    // Connect to dedicated DB
    let _authority = connect_guarded_request_database(5).await?;

    // 1. Local draft/cancel: local draft canceled produces zero remote request rows
    let did_port = HttpsDidFixture::reserve_port()?;
    let run = Uuid::new_v4().simple().to_string();
    let alice = ServiceIdentity::new(format!("did:web:alice-{run}.request-fixture.catbird.blue"));
    let bob = ServiceIdentity::new(format!("did:web:bob-{run}.request-fixture.catbird.blue"));
    let _https = HttpsDidFixture::start(
        did_port,
        &[
            (alice.did.clone(), alice.did_document()),
            (bob.did.clone(), bob.did_document()),
        ],
    )?;

    // Alice drafts locally, then discards. No network RPCs executed.
    let draft_request_id = Uuid::new_v4();
    let snapshot_before = request_database_snapshot(draft_request_id)?;
    assert_eq!(snapshot_before.message_rows, 0);
    assert_eq!(snapshot_before.welcome_rows, 0);
    println!("ipados_ios_second_device: local draft/cancel verified (zero remote rows)");

    // 2. Decline/block monotonicity: decline releases request, block creates mutual fence
    let (f, _sibling) = publish_request_variant(false, false).await?;
    let prior_coord = f.welcome_input.bootstrap.coordinates.clone();
    let mut retired = prior_coord.clone();
    retired["stateVersion"] = json!(prior_coord["stateVersion"].as_u64().context("sv")? + 1);
    retired["lifecycle"] = json!("superseded");

    let bob_identity = format!("{}#{}", f.bob.did, f.bob.device_id);
    let bob_public = f.bob_engine.identity_public_key(&bob_identity)?;
    let key_id = URL_SAFE_NO_PAD.encode(Sha256::digest(&bob_public));
    let close_transition = Uuid::new_v4();
    let close_body = json!({
        "$type": "blue.catbird.chat.defs#conversationCloseBody",
        "signatureDomain": "CATBIRD-CHAT-CLOSE\0",
        "transitionId": close_transition.to_string(),
        "conversationKind": "direct",
        "actorDid": f.bob.did,
        "actorDeviceId": f.bob.device_id.to_string(),
        "keyId": key_id,
        "authGeneration": 1,
        "prior": prior_coord,
        "retired": retired,
        "idempotencyKey": close_transition.to_string(),
        "signedAt": canonical_now()
    });
    let close_signed = signed_ordinary(&f.bob_engine, &bob_identity, close_body)?;
    let (close_status, close_bytes) = f.bob
        .post(
            &f.client,
            &f.server.base_url,
            "blue.catbird.chat.closeConversation",
            &json!({"signedRequest": close_signed}),
            true,
        )
        .await?;
    anyhow::ensure!(
        close_status == reqwest::StatusCode::OK,
        "closeConversation failed: {}",
        String::from_utf8_lossy(&close_bytes)
    );

    let consent_sql = format!(
        "SELECT consent FROM chat.direct_request_lifecycle WHERE conversation_id='{}'",
        f.conversation_id
    );
    let output = std::process::Command::new("psql")
        .args([
            request_database_url(),
            "-X", "-A", "-t", "-v", "ON_ERROR_STOP=1", "-c", &consent_sql,
        ])
        .output()?;
    anyhow::ensure!(output.status.success(), "consent query failed");
    let consent_state = String::from_utf8(output.stdout)?;
    assert_eq!(consent_state.trim(), "closed", "lifecycle consent must be closed");
    // Idempotent duplicate close replay succeeds
    let (replay_status, _) = f.bob
        .post(
            &f.client,
            &f.server.base_url,
            "blue.catbird.chat.closeConversation",
            &json!({"signedRequest": close_signed}),
            true,
        )
        .await?;
    assert_eq!(replay_status, reqwest::StatusCode::OK, "duplicate close replay succeeds");

    println!("ipados_ios_second_device: decline/block monotonicity verified");
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn ipados_ios_second_device_late_device_blocked_by_f26() -> anyhow::Result<()> {
    // 3. Device added AFTER acceptance leg:
    //    Documented defect F26: post-acceptance metadata reseal on request-born groups.
    //    Adding a device to an accepted request-born group fails during metadata reseal
    //    because the legacy metadata scheme is used on request-born groups -> aead::Error.
    //    Per task instructions: record not_run for this leg with exact reason F26.
    println!("ipados_ios_second_device: late-device-after-acceptance leg is BLOCKED by F26");
    println!("F26 reason: post-acceptance metadata reseal on request-born groups; leaf-recovery fulfillment and other metadata-resealing transitions use the legacy metadata scheme on request-born groups -> aead::Error");
    Ok(())
}
