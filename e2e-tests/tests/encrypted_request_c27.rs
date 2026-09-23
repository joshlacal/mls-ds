//! C27 live shipping-router clauses:
//! - no second introduction via another RPC (signed ordinary send while
//!   pending) or via the group-note path (a second publication carrying a
//!   group-invitation reference) — both refused with no new conversation,
//!   Welcome, entry or delivery;
//! - capacity refusal (live pair quota → CapacityUnavailable) never evicts the
//!   existing published history, and the original Welcome stays importable;
//! - the only pending-capacity release for a published request is a consent
//!   transition (acceptance here), which writes exactly its published charge.
//! Repository-level quota/budget clauses: server/tests/chat_protocol_direct_request_c27.rs.
#![allow(dead_code, unused_imports)]
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
        project_signed_body, SignedMutationKind, SigningTranscript, VerifiedMutation,
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
    GroupInvitationReference,
};
use encrypted_requests::{
    canonical_future, canonical_now, connect_guarded_request_database, request_database_snapshot,
    reviewed_request_migrations, seed_service_device, signed_mls_request,
    validate_request_test_database_url, HttpsDidFixture, ServiceIdentity, ShippingServerFixture,
    REQUEST_TEST_DATABASE_URL,
};
use live_direct_request::PublishedRequestFixture;
use mls_e2e_tests::mls_engine::MlsEngine;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use uuid::Uuid;

/// Read-only projection of the guarded database.
fn psql(sql: &str) -> anyhow::Result<String> {
    let out = std::process::Command::new("psql")
        .args([REQUEST_TEST_DATABASE_URL, "-X", "-A", "-t", "-v", "ON_ERROR_STOP=1", "-c", sql])
        .output()?;
    anyhow::ensure!(out.status.success(), "psql: {}", String::from_utf8_lossy(&out.stderr));
    Ok(String::from_utf8(out.stdout)?.trim().to_owned())
}

/// Every durable row of the published request and its conversation, plus the
/// recipient's pending-Welcome state.
fn durable(f: &PublishedRequestFixture) -> anyhow::Result<String> {
    let (r, c) = (f.request_id, f.conversation_id);
    psql(&format!(r#"SELECT jsonb_build_object(
      'conversation',(SELECT to_jsonb(x) FROM chat.conversations x WHERE conversation_id='{c}'),
      'attempt',(SELECT to_jsonb(a) FROM chat.direct_request_attempts a WHERE request_id='{r}'),
      'charge',(SELECT to_jsonb(g) FROM chat.direct_request_retained_charges g WHERE request_id='{r}'),
      'publication',(SELECT to_jsonb(p) FROM chat.direct_request_publications p WHERE request_id='{r}'),
      'reserve',(SELECT to_jsonb(v) FROM chat.direct_request_lifecycle_reserves v WHERE request_id='{r}'),
      'selected',(SELECT jsonb_agg(to_jsonb(s) ORDER BY owner_device_id) FROM chat.direct_request_selected_devices s WHERE request_id='{r}'),
      'deliveries',(SELECT jsonb_agg(to_jsonb(d) ORDER BY owner_device_id) FROM chat.direct_request_device_deliveries d WHERE request_id='{r}'),
      'welcomeOutcomes',(SELECT count(*) FROM chat.direct_request_welcome_outcomes WHERE request_id='{r}'),
      'packages',(SELECT jsonb_agg(to_jsonb(k) ORDER BY k.key_package_ref) FROM chat.key_packages k JOIN chat.direct_request_selected_devices s USING(key_package_ref) WHERE s.request_id='{r}'),
      'participants',(SELECT jsonb_agg(to_jsonb(p) ORDER BY user_did) FROM chat.participants p WHERE conversation_id='{c}'),
      'entries',(SELECT jsonb_agg(to_jsonb(e) ORDER BY seq) FROM chat.entries e WHERE conversation_id='{c}'),
      'transitions',(SELECT jsonb_agg(to_jsonb(t) ORDER BY transition_id) FROM chat.transitions t WHERE conversation_id='{c}')
    )::text"#))
}

fn signed_ordinary(engine: &mls_e2e_tests::mls_engine::MlsEngine, identity: &str, body: Value) -> anyhow::Result<Value> {
    let canonical = project_signed_body(
        SignedMutationKind::from_type_id(body["$type"].as_str().context("type")?).context("kind")?,
        &decode_strict_json(&serde_json::to_vec(&body)?)?,
    )?;
    let transcript = SigningTranscript::build(&canonical)?;
    let signature = engine.sign_identity(identity, transcript.bytes().to_vec())?;
    VerifiedMutation::verify(canonical, signature.clone().try_into().map_err(|_| anyhow::anyhow!("signature"))?, &engine.identity_public_key(identity)?)?;
    Ok(json!({"body":body,"signature":STANDARD.encode(signature)}))
}

async fn post(f: &PublishedRequestFixture, alice: bool, nsid: &str, body: &Value) -> anyhow::Result<(reqwest::StatusCode, Value)> {
    let who = if alice { &f.alice } else { &f.bob };
    let (status, bytes) = who.post(&f.client, &f.server.base_url, nsid, body, true).await?;
    Ok((status, serde_json::from_slice(&bytes).with_context(|| format!("{nsid} {status}: {}", String::from_utf8_lossy(&bytes)))?))
}

/// Bob publishes `n` further request-only packages (revision 2).
async fn bob_publishes_request_keys(f: &PublishedRequestFixture, n: usize) -> anyhow::Result<()> {
    let identity = format!("{}#{}", f.bob.did, f.bob.device_id);
    let key_id = URL_SAFE_NO_PAD.encode(Sha256::digest(f.bob_engine.identity_public_key(&identity)?));
    let mut keys = Vec::new();
    for _ in 0..n {
        let (package, reference) = f.bob_engine.create_key_package(&identity)?;
        let grant_id = Uuid::new_v4();
        let grant = signed_mls_request(&f.bob_engine, &identity, DirectRequestKind::Grant, json!({
            "$type":"blue.catbird.chat.defs#directRequestGrantBody","signatureDomain":"CATBIRD-DIRECT-REQUEST-GRANT\0","protocolVersion":"2",
            "actorDid":f.bob.did,"actorDeviceId":f.bob.device_id.to_string(),"keyId":key_id,"authGeneration":1,
            "grantId":grant_id.to_string(),"grantRevision":1,"purpose":"direct-request-bootstrap","profile":"encryptedIntroduction1",
            "keyPackageRef":STANDARD.encode(&reference),"keyPackageSha256":STANDARD.encode(Sha256::digest(&package)),
            "expiresAt":canonical_future(29),"idempotencyKey":grant_id.to_string(),"signedAt":canonical_now()
        }))?;
        keys.push(json!({"keyPackage":{"framing":"mlsMessage","contentType":"keyPackage","bytes":STANDARD.encode(&package),
            "sha256":STANDARD.encode(Sha256::digest(&package)),"keyPackageRef":STANDARD.encode(&reference)},"grant":grant}));
    }
    let signed = signed_mls_request(&f.bob_engine, &identity, DirectRequestKind::Keys, json!({
        "$type":"blue.catbird.chat.defs#directRequestKeysPublicationBody","signatureDomain":"CATBIRD-DIRECT-REQUEST-KEYS\0","protocolVersion":"2",
        "actorDid":f.bob.did,"actorDeviceId":f.bob.device_id.to_string(),"keyId":key_id,"authGeneration":1,"revision":2,"enabled":true,
        "keys":keys,"idempotencyKey":Uuid::new_v4().to_string(),"signedAt":canonical_now()
    }))?;
    let (status, body) = post(f, false, "blue.catbird.chat.publishDirectRequestKeys", &json!({"signedRequest":signed})).await?;
    anyhow::ensure!(status == reqwest::StatusCode::OK, "bob keys {status}: {body}");
    Ok(())
}

struct Prepared {
    request_id: Uuid,
    first_message_id: Uuid,
    conversation_id: Uuid,
    signed: Value,
    response: (reqwest::StatusCode, Value),
}

async fn alice_prepares(f: &PublishedRequestFixture) -> anyhow::Result<Prepared> {
    let engine = f.alice_engine.as_ref().context("alice engine")?;
    let identity = format!("{}#{}", f.alice.did, f.alice.device_id);
    let key_id = URL_SAFE_NO_PAD.encode(Sha256::digest(engine.identity_public_key(&identity)?));
    let (request_id, first_message_id, conversation_id) = (Uuid::new_v4(), Uuid::new_v4(), Uuid::new_v4());
    let signed = signed_mls_request(engine, &identity, DirectRequestKind::Prepare, json!({
        "$type":"blue.catbird.chat.defs#directRequestPreparationBody","signatureDomain":"CATBIRD-DIRECT-REQUEST-PREPARE\0","protocolVersion":"2",
        "actorDid":f.alice.did,"actorDeviceId":f.alice.device_id.to_string(),"keyId":key_id,"authGeneration":1,
        "requestId":request_id.to_string(),"firstMessageId":first_message_id.to_string(),"conversationId":conversation_id.to_string(),
        "recipientDid":f.bob.did,"origin":{"$type":"blue.catbird.chat.defs#freshDirectOrigin"},"profile":"encryptedIntroduction1",
        "idempotencyKey":request_id.to_string(),"signedAt":canonical_now()
    }))?;
    let response = post(f, true, "blue.catbird.chat.prepareDirectRequest", &json!({"signedRequest":signed})).await?;
    Ok(Prepared { request_id, first_message_id, conversation_id, signed, response })
}

/// Real client bootstrap + signed publication of a prepared attempt whose
/// introduction carries a group-invitation note reference.
async fn alice_publishes_with_note(f: &PublishedRequestFixture, p: &Prepared, note: GroupInvitationReference) -> anyhow::Result<(reqwest::StatusCode, Value)> {
    let engine = f.alice_engine.as_ref().context("alice engine")?;
    let identity = format!("{}#{}", f.alice.did, f.alice.device_id);
    let public = engine.identity_public_key(&identity)?;
    let key_id = URL_SAFE_NO_PAD.encode(Sha256::digest(&public));
    let snapshot = p.response.1.pointer("/outcome/preparation").context("preparation snapshot")?;
    let selected = snapshot["selectedDevices"].as_array().context("selectedDevices")?;
    let verified = protocol::verify_signed_request(DirectRequestKind::Prepare, &serde_json::to_vec(&p.signed)?, &public)?;
    let context = json!({
        "protocolVersion":"2","requestId":p.request_id.to_string(),"firstMessageId":p.first_message_id.to_string(),
        "conversationId":p.conversation_id.to_string(),"origin":{"$type":"blue.catbird.chat.defs#freshDirectOrigin"},
        "actorDid":f.alice.did,"actorDeviceId":f.alice.device_id.to_string(),"actorKeyId":key_id,"recipientDid":f.bob.did,
        "preparationDigest":snapshot["preparationDigest"]
    });
    let decode = |d: &Value, k: &str| -> anyhow::Result<Vec<u8>> { Ok(STANDARD.decode(d["keyPackage"][k].as_str().context("package field")?)?) };
    let journal = engine.prepare_direct_request(&DirectRequestBootstrapInput {
        draft_id: Uuid::new_v4().to_string(),
        context_json: serde_json::to_vec(&context)?,
        group_id: rand::random::<[u8; 32]>().to_vec(),
        generation: 0,
        state_version: 1,
        key_packages: selected.iter().map(|d| decode(d, "bytes")).collect::<anyhow::Result<_>>()?,
        expected_package_refs: selected.iter().map(|d| decode(d, "keyPackageRef")).collect::<anyhow::Result<_>>()?,
        authority_import_until: u64::try_from(chrono::DateTime::parse_from_rfc3339(snapshot["minimumImportUntil"].as_str().context("minimumImportUntil")?)?.timestamp())?,
        preparation_request_digest: *verified.request_digest(),
        receipt_authority_key: f.server.receipt_public_key.clone(),
        text: "Second introduction smuggled with a group note".into(),
        invitation: Some(note),
        metadata: GroupMetadataV1 { version: 1, title: String::new(), description: String::new(), avatar_blob_locator: None, avatar_content_type: None },
    })?;
    let b = &journal.bootstrap;
    let mut body = p.signed["body"].clone();
    body["$type"] = json!("blue.catbird.chat.defs#directRequestPublicationBody");
    body["signatureDomain"] = json!("CATBIRD-DIRECT-REQUEST-PUBLISH\0");
    body["signedAt"] = json!(canonical_now());
    body["preparationDigest"] = snapshot["preparationDigest"].clone();
    body["preparationRequestDigest"] = json!(STANDARD.encode(verified.request_digest()));
    body["contextHash"] = json!(STANDARD.encode(b.context_hash));
    body["next"] = b.coordinates.clone();
    body["importUntil"] = json!(chrono::DateTime::from_timestamp(b.import_until as i64, 0).context("import")?.to_rfc3339_opts(chrono::SecondsFormat::Millis, true));
    let artifact = |data: &[u8], kind: &str| json!({"framing":"mlsMessage","contentType":kind,"bytes":STANDARD.encode(data),"sha256":STANDARD.encode(Sha256::digest(data))});
    let deliveries = selected.iter().map(|d| json!({"recipientDid":d["actorDid"],"recipientDeviceId":d["actorDeviceId"],"provenance":{
        "requestId":p.request_id.to_string(),"preparationDigest":snapshot["preparationDigest"],"contextHash":STANDARD.encode(b.context_hash),
        "grantId":d["grant"]["body"]["grantId"],"grantRevision":d["grant"]["body"]["grantRevision"],"keyPackageRef":d["keyPackage"]["keyPackageRef"],
        "importUntil":body["importUntil"]}})).collect::<Vec<_>>();
    let author = json!({"authorDid":f.alice.did,"authorDeviceId":f.alice.device_id.to_string(),"authorKeyId":key_id,"signaturePublicKey":STANDARD.encode(&public),
        "authGenerationAtOrigin":1,"originTransitionId":p.request_id.to_string(),"originSeq":1,"roleAtOrigin":"admin","deviceStatusAtOrigin":"active"});
    body["artifacts"] = json!({
        "genesisGroupInfo":artifact(&b.genesis_group_info,"groupInfo"),"addCommit":artifact(&b.add_commit,"publicMessageCommit"),
        "finalGroupInfo":artifact(&b.final_group_info,"groupInfo"),
        "welcome":{"opaqueWelcome":STANDARD.encode(&b.welcome),"sha256":STANDARD.encode(Sha256::digest(&b.welcome)),"deliveries":deliveries},
        "initialCiphertext":STANDARD.encode(&b.initial_ciphertext),
        "metadataSnapshot":{"coordinate":metadata_coordinate(&b.coordinates)?,"originTransitionId":p.request_id.to_string(),"metadataVersion":1,
            "nonce":STANDARD.encode(&b.metadata_nonce),"ciphertext":STANDARD.encode(&b.metadata_ciphertext),
            "ciphertextSha256":STANDARD.encode(Sha256::digest(&b.metadata_ciphertext)),"ciphertextSize":b.metadata_ciphertext.len(),"authorProof":author}
    });
    let signed = signed_mls_request(engine, &identity, DirectRequestKind::Publish, body)?;
    post(f, true, "blue.catbird.chat.publishDirectRequest", &json!({"signedRequest":signed})).await
}

#[tokio::test(flavor = "multi_thread")]
async fn c27_live_no_second_introduction_and_capacity_refusal_preserve_history() -> anyhow::Result<()> {
    // A real published request; Bob has not imported its Welcome.
    let f = live_direct_request::publish_request(false).await?;
    // The sender installs its published group from the signed receipt (real client flow).
    f.alice_engine.as_ref().context("alice engine")?.confirm_request_publication(
        &f.request_id.to_string(),
        &serde_json::to_vec(&f.receipt)?,
        &f.server.receipt_public_key,
    )?;
    let before = durable(&f)?;
    let (low, high) = if f.alice.did < f.bob.did { (&f.alice.did, &f.bob.did) } else { (&f.bob.did, &f.alice.did) };
    let directs = || psql(&format!("SELECT count(*) FROM chat.conversations WHERE kind='direct' AND direct_did_low='{low}' AND direct_did_high='{high}'"));
    assert_eq!(directs()?, "1");
    bob_publishes_request_keys(&f, 2).await?;

    // Group-note path: a second prepared introduction carrying a
    // group-invitation reference is published → ExistingDirect, nothing new.
    let second = alice_prepares(&f).await?;
    assert_eq!(second.response.0, reqwest::StatusCode::OK, "{}", second.response.1);
    let note = GroupInvitationReference {
        authority_did: "did:web:chat.catbird.blue".into(),
        conversation_id: Uuid::new_v4().to_string(),
        invitation_transition_id: Uuid::new_v4().to_string(),
        invited_by_did: f.alice.did.clone(),
        invited_by_device_id: f.alice.device_id.to_string(),
        recipient_did: f.bob.did.clone(),
    };
    let (status, published) = alice_publishes_with_note(&f, &second, note).await?;
    assert_eq!(status, reqwest::StatusCode::OK, "{published}");
    let receipt = &published["outcome"]["body"]["receipt"];
    assert_eq!(receipt["$type"], "blue.catbird.chat.defs#directRequestExistingDirectReceipt", "{published}");
    assert_eq!(receipt["conversationId"], f.conversation_id.to_string());
    assert_eq!(receipt["requiresAcceptance"], false, "the sender is the active creator of the pending direct");
    assert_eq!(directs()?, "1");
    let r2 = second.request_id;
    assert_eq!(psql(&format!("SELECT status FROM chat.direct_request_attempts WHERE request_id='{r2}'"))?, "existing-direct");
    assert_eq!(psql(&format!("SELECT (SELECT count(*) FROM chat.conversations WHERE conversation_id='{}')+(SELECT count(*) FROM chat.direct_request_publications WHERE request_id='{r2}')+(SELECT count(*) FROM chat.direct_request_device_deliveries WHERE request_id='{r2}')+(SELECT count(*) FROM chat.entries WHERE transition_id='{r2}')", second.conversation_id))?, "0",
        "no conversation, publication, Welcome delivery or entry for the second introduction");

    // Another RPC: a real signed MLS application send on the pending
    // conversation is refused by pending consent.
    let engine = f.alice_engine.as_ref().context("alice engine")?;
    let identity = format!("{}#{}", f.alice.did, f.alice.device_id);
    let public = engine.identity_public_key(&identity)?;
    let prior = f.welcome_input.bootstrap.coordinates.clone();
    let group = STANDARD.decode(prior["groupId"].as_str().context("group")?)?;
    let epoch = prior["epoch"].as_u64().context("epoch")?;
    let message = Uuid::new_v4();
    let mut aad_prior = prior.clone();
    aad_prior["conversationId"] = json!(STANDARD.encode(f.conversation_id.as_bytes()));
    let aad = json!({"protocolVersion":"1","conversationId":STANDARD.encode(f.conversation_id.as_bytes()),"generation":prior["generation"],"messageId":STANDARD.encode(message.as_bytes()),"prior":aad_prior});
    let ciphertext = engine.encrypt_canonical(&group, &MLSMessagePayload::text("Second introduction before consent").encode()?, canonical_application_aad_bytes(&aad)?, epoch)?;
    let application = signed_ordinary(engine, &identity, json!({
        "$type":"blue.catbird.chat.defs#applicationSendBody","signatureDomain":"CATBIRD-CHAT-MESSAGE\0","messageId":message.to_string(),
        "actorDid":f.alice.did,"actorDeviceId":f.alice.device_id.to_string(),"keyId":URL_SAFE_NO_PAD.encode(Sha256::digest(&public)),"authGeneration":1,
        "prior":prior,"aad":aad,"applicationMessage":{"framing":"mlsMessage","contentType":"privateMessageApplication","bytes":STANDARD.encode(&ciphertext),"sha256":STANDARD.encode(Sha256::digest(&ciphertext))},
        "blobBindings":[],"signedAt":canonical_now()
    }))?;
    let (status, refused) = post(&f, true, "blue.catbird.chat.sendMessage", &json!({"signedRequest":application})).await?;
    assert_eq!(status, reqwest::StatusCode::BAD_REQUEST, "{refused}");
    assert_eq!(refused["error"], "ConversationNotAccepted", "pending consent refusal must use the declared sendMessage code: {refused}");
    assert_eq!(psql(&format!("SELECT count(*) FROM chat.entries WHERE conversation_id='{}' AND message_id='{message}'", f.conversation_id))?, "0");
    // Typing is likewise refused with its declared code (no durable effect;
    // the byte-identical history check below covers every row).
    let typing = signed_ordinary(engine, &identity, json!({
        "$type":"blue.catbird.chat.defs#typingBody","signatureDomain":"CATBIRD-CHAT-TYPING\0","typingId":Uuid::new_v4().to_string(),
        "actorDid":f.alice.did,"actorDeviceId":f.alice.device_id.to_string(),"keyId":URL_SAFE_NO_PAD.encode(Sha256::digest(&public)),"authGeneration":1,
        "coordinates":f.publication["body"]["next"],"isTyping":true,"signedAt":canonical_now()
    }))?;
    let (status, refused) = post(&f, true, "blue.catbird.chat.publishTyping", &json!({"signedRequest":typing})).await?;
    assert_eq!(status, reqwest::StatusCode::BAD_REQUEST, "{refused}");
    assert_eq!(refused["error"], "ConversationNotAccepted", "{refused}");

    // Capacity refusal: one live preparation holds the pair; the next is
    // refused with CapacityUnavailable and evicts nothing.
    let third = alice_prepares(&f).await?;
    assert_eq!(third.response.0, reqwest::StatusCode::OK, "{}", third.response.1);
    assert!(third.response.1.pointer("/outcome/preparation").is_some(), "{}", third.response.1);
    let fourth = alice_prepares(&f).await?;
    assert_eq!(fourth.response.0, reqwest::StatusCode::OK, "{}", fourth.response.1);
    assert_eq!(fourth.response.1.pointer("/outcome/body/receipt/code").and_then(Value::as_str), Some("CapacityUnavailable"), "{}", fourth.response.1);
    assert_eq!(durable(&f)?, before, "second introduction, refused send and capacity refusal leave the published history byte-identical");

    // Release the live reservation through the real cancellation RPC.
    let cancel = signed_mls_request(engine, &identity, DirectRequestKind::Cancel, json!({
        "$type":"blue.catbird.chat.defs#directRequestCancellationBody","signatureDomain":"CATBIRD-DIRECT-REQUEST-CANCEL\0","protocolVersion":"2",
        "actorDid":f.alice.did,"actorDeviceId":f.alice.device_id.to_string(),"keyId":URL_SAFE_NO_PAD.encode(Sha256::digest(&public)),"authGeneration":1,
        "requestId":third.request_id.to_string(),"recipientDid":f.bob.did,
        "preparationRequestDigest":STANDARD.encode(protocol::verify_signed_request(DirectRequestKind::Prepare, &serde_json::to_vec(&third.signed)?, &public)?.request_digest()),
        "idempotencyKey":third.request_id.to_string(),"signedAt":canonical_now()
    }))?;
    let (status, cancelled) = post(&f, true, "blue.catbird.chat.cancelDirectRequestPreparation", &json!({"signedRequest":cancel})).await?;
    assert_eq!(status, reqwest::StatusCode::OK, "{cancelled}");
    assert_eq!(psql(&format!("SELECT status FROM chat.direct_request_attempts WHERE request_id='{}'", third.request_id))?, "cancelled");

    // The original Welcome is still importable and decrypts the original intro.
    f.bob_engine.process_direct_request(&f.welcome_input)?;
    let DirectRequestIntroductionResult::Ready { plaintext } = f.bob_engine.decrypt_direct_request(&f.welcome_input)? else {
        anyhow::bail!("original introduction unavailable after refusals")
    };
    assert_eq!(protocol::decode_direct_request_introduction(&plaintext)?["text"], "Real encrypted first contact");

    // Pending capacity of a published request is released only by a consent
    // transition; acceptance writes a release equal to its published charge.
    let r1 = f.request_id;
    assert_eq!(psql(&format!("SELECT count(*) FROM chat.direct_request_pending_releases WHERE request_id='{r1}'"))?, "0");
    live_direct_request::accept_existing_fixture(&f).await?;
    assert_eq!(
        psql(&format!("SELECT r.reason||':'||(r.released_bytes=a.reserved_bytes AND a.reserved_bytes=c.charged_bytes)::text FROM chat.direct_request_pending_releases r JOIN chat.direct_request_attempts a USING(request_id) JOIN chat.direct_request_retained_charges c USING(request_id) WHERE request_id='{r1}'"))?,
        "accepted:true"
    );
    Ok(())
}
