//! Reusable real first-contact fixture; all original C01 assertions remain active.
use super::*;

pub struct PublishedRequestFixture {
    pub alice: ServiceIdentity,
    pub bob: ServiceIdentity,
    pub alice_engine: Option<MlsEngine>,
    pub bob_engine: MlsEngine,
    pub server: ShippingServerFixture,
    pub client: reqwest::Client,
    pub request_id: Uuid,
    pub conversation_id: Uuid,
    pub first_message_id: Uuid,
    pub welcome_input: DirectRequestWelcomeInput,
    pub publication: Value,
    pub receipt: Value,
    pub push_event_id: Uuid,
    // Synthetic provider token is retained only in this process-local object.
    pub push_registration_request: Value,
    pub push_registration_ack: Value,
    pub _https: HttpsDidFixture,
}

#[path = "live_direct_request_siblings.rs"]
mod siblings;
pub use siblings::accept_before_both_recipient_imports;

pub async fn publish_request(import_recipient: bool) -> anyhow::Result<PublishedRequestFixture> {
    Ok(publish_request_variant(import_recipient, false).await?.0)
}

async fn publish_request_variant(
    import_recipient: bool,
    include_sibling: bool,
) -> anyhow::Result<(PublishedRequestFixture, Option<siblings::RecipientSibling>)> {
    let authority = connect_guarded_request_database(5).await?;
    assert_eq!(
        authority.additive_migrations,
        reviewed_request_migrations().len()
    );

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

    let alice_engine = MlsEngine::new("c01-alice")?;
    let bob_engine = MlsEngine::new("c01-bob")?;
    let alice_identity = format!("{}#{}", alice.did, alice.device_id);
    let bob_identity = format!("{}#{}", bob.did, bob.device_id);
    let (_alice_package, _alice_package_ref) = alice_engine.create_key_package(&alice_identity)?;
    let (bob_package, bob_package_ref) = bob_engine.create_key_package(&bob_identity)?;
    let alice_public = alice_engine.identity_public_key(&alice_identity)?;
    let bob_public = bob_engine.identity_public_key(&bob_identity)?;
    seed_service_device(&alice, &alice_public)?;
    seed_service_device(&bob, &bob_public)?;

    let server = ShippingServerFixture::start(&https)?;
    let client = reqwest::Client::builder().build()?;
    let synthetic_token = format!("request-fixture-{}", Uuid::new_v4().simple());
    let registration_body: catbird_mls::atproto::blue_catbird::chat::PushRegistrationBody =
        serde_json::from_value(json!({
            "protocolVersion":"2", "signatureDomain":"CATBIRD-CHAT-PUSH-BINDING\0",
            "authorityDid":"did:web:chat.catbird.blue", "actorDid":bob.did,
            "actorDeviceId":bob.device_id.to_string(), "keyId":URL_SAFE_NO_PAD.encode(Sha256::digest(&bob_public)),
            "authGeneration":1,"registrationId":Uuid::new_v4().to_string(),"provider":"apns",
            "appId":"blue.catbird","tokenGeneration":1,"tokenSha256":{"$bytes":STANDARD.encode(Sha256::digest(synthetic_token.as_bytes()))},
            "enabled":true,"signedAt":canonical_now()
        }))?;
    let registration_transcript =
        catbird_mls::atproto::push_registration::transcript(&registration_body)?;
    let signature = bob_engine.sign_identity(&bob_identity, registration_transcript.clone())?;
    let registration = catbird_mls::atproto::blue_catbird::chat::SignedPushRegistration {
        body: registration_body.clone(),
        signature: signature.into(),
        extra_data: None,
    };
    let push_registration_request = json!({"token":synthetic_token,"registration":registration});
    let (registration_status, registration_bytes) = bob
        .post(
            &client,
            &server.base_url,
            "blue.catbird.chat.updatePushToken",
            &push_registration_request,
            true,
        )
        .await?;
    anyhow::ensure!(
        registration_status == reqwest::StatusCode::OK,
        "real signed push registration failed {registration_status}"
    );
    let push_registration_ack: Value = serde_json::from_slice(&registration_bytes)?;
    let binding: catbird_mls::atproto::blue_catbird::chat::PushRegistrationBinding =
        serde_json::from_value(push_registration_ack["pushBinding"].clone())?;
    assert_eq!(binding.body, registration_body);
    assert_eq!(
        binding.binding_digest.as_ref(),
        Sha256::digest(&registration_transcript).as_slice()
    );
    let bob_key_id = URL_SAFE_NO_PAD.encode(Sha256::digest(&bob_public));
    let alice_key_id = URL_SAFE_NO_PAD.encode(Sha256::digest(&alice_public));
    let (device_key_status, device_key_response) = alice
        .get_device_key(
            &client,
            &server.base_url,
            &bob.did,
            bob.device_id,
            &bob_key_id,
        )
        .await?;
    anyhow::ensure!(
        device_key_status == reqwest::StatusCode::OK,
        "get device key failed {device_key_status}: {}",
        String::from_utf8_lossy(&device_key_response)
    );
    let device_key: Value = serde_json::from_slice(&device_key_response)?;
    let mut device_key_mismatches = Vec::new();
    for (field, matches) in [
        ("ownerDid", device_key["ownerDid"] == bob.did),
        (
            "deviceId",
            device_key["deviceId"] == bob.device_id.to_string(),
        ),
        ("keyId", device_key["keyId"] == bob_key_id),
        (
            "signaturePublicKey",
            device_key["signaturePublicKey"]["$bytes"] == STANDARD.encode(&bob_public)
                && device_key["signaturePublicKey"]
                    .as_object()
                    .is_some_and(|bytes| bytes.len() == 1),
        ),
    ] {
        if !matches {
            device_key_mismatches.push(field);
        }
    }
    anyhow::ensure!(
        device_key_mismatches.is_empty(),
        "get device key response differed in fields: {device_key_mismatches:?}"
    );
    for (owner_did, device_id, key_id) in [
        (alice.did.as_str(), bob.device_id, bob_key_id.as_str()),
        (bob.did.as_str(), alice.device_id, bob_key_id.as_str()),
        (bob.did.as_str(), bob.device_id, alice_key_id.as_str()),
    ] {
        let (status, body) = alice
            .get_device_key(&client, &server.base_url, owner_did, device_id, key_id)
            .await?;
        let error: Value = serde_json::from_slice(&body)?;
        anyhow::ensure!(
            status == reqwest::StatusCode::BAD_REQUEST && error["error"] == "DeviceKeyNotFound",
            "mismatched device-key tuple did not fail closed"
        );
    }
    let grant_id = Uuid::new_v4();
    let grant = json!({
        "$type":"blue.catbird.chat.defs#directRequestGrantBody",
        "signatureDomain":"CATBIRD-DIRECT-REQUEST-GRANT\0",
        "protocolVersion":"2",
        "actorDid":bob.did,
        "actorDeviceId":bob.device_id.to_string(),
        "keyId":bob_key_id,
        "authGeneration":1,
        "grantId":grant_id.to_string(),
        "grantRevision":1,
        "purpose":"direct-request-bootstrap",
        "profile":"encryptedIntroduction1",
        "keyPackageRef":STANDARD.encode(&bob_package_ref),
        "keyPackageSha256":STANDARD.encode(Sha256::digest(&bob_package)),
        "expiresAt":canonical_future(29),
        "idempotencyKey":grant_id.to_string(),
        "signedAt":canonical_now()
    });
    let grant = signed_mls_request(&bob_engine, &bob_identity, DirectRequestKind::Grant, grant)?;
    let keys_operation = Uuid::new_v4();
    let keys = signed_mls_request(
        &bob_engine,
        &bob_identity,
        DirectRequestKind::Keys,
        json!({
            "$type":"blue.catbird.chat.defs#directRequestKeysPublicationBody",
            "signatureDomain":"CATBIRD-DIRECT-REQUEST-KEYS\0",
            "protocolVersion":"2",
            "actorDid":bob.did,
            "actorDeviceId":bob.device_id.to_string(),
            "keyId":bob_key_id,
            "authGeneration":1,
            "revision":1,
            "enabled":true,
            "keys":[{
                "keyPackage":{
                    "framing":"mlsMessage",
                    "contentType":"keyPackage",
                    "bytes":STANDARD.encode(&bob_package),
                    "sha256":STANDARD.encode(Sha256::digest(&bob_package)),
                    "keyPackageRef":STANDARD.encode(&bob_package_ref)
                },
                "grant":grant
            }],
            "idempotencyKey":keys_operation.to_string(),
            "signedAt":canonical_now()
        }),
    )?;
    let keys_envelope = json!({"signedRequest":keys});
    let (bad_status, _) = bob
        .post(
            &client,
            &server.base_url,
            "blue.catbird.chat.publishDirectRequestKeys",
            &keys_envelope,
            false,
        )
        .await?;
    assert_eq!(bad_status, reqwest::StatusCode::UNAUTHORIZED);
    let (keys_status, keys_response) = bob
        .post(
            &client,
            &server.base_url,
            "blue.catbird.chat.publishDirectRequestKeys",
            &keys_envelope,
            true,
        )
        .await?;
    anyhow::ensure!(
        keys_status == reqwest::StatusCode::OK,
        "publish keys failed {keys_status}: {}",
        String::from_utf8_lossy(&keys_response)
    );

    let sibling = if include_sibling {
        Some(siblings::enroll(&bob, &client, &server.base_url).await?)
    } else {
        None
    };

    let request_id = Uuid::new_v4();
    let first_message_id = Uuid::new_v4();
    let conversation_id = Uuid::new_v4();
    let prepare = signed_mls_request(
        &alice_engine,
        &alice_identity,
        DirectRequestKind::Prepare,
        json!({
            "$type":"blue.catbird.chat.defs#directRequestPreparationBody",
            "signatureDomain":"CATBIRD-DIRECT-REQUEST-PREPARE\0",
            "protocolVersion":"2",
            "actorDid":alice.did,
            "actorDeviceId":alice.device_id.to_string(),
            "keyId":alice_key_id,
            "authGeneration":1,
            "requestId":request_id.to_string(),
            "firstMessageId":first_message_id.to_string(),
            "conversationId":conversation_id.to_string(),
            "recipientDid":bob.did,
            "origin":{"$type":"blue.catbird.chat.defs#freshDirectOrigin"},
            "profile":"encryptedIntroduction1",
            "idempotencyKey":request_id.to_string(),
            "signedAt":canonical_now()
        }),
    )?;
    let (prepare_status, prepare_response) = alice
        .post(
            &client,
            &server.base_url,
            "blue.catbird.chat.prepareDirectRequest",
            &json!({"signedRequest":prepare}),
            true,
        )
        .await?;
    anyhow::ensure!(
        prepare_status == reqwest::StatusCode::OK,
        "prepare failed {prepare_status}: {}",
        String::from_utf8_lossy(&prepare_response)
    );
    let response: Value = serde_json::from_slice(&prepare_response)?;
    let preparation = response
        .pointer("/outcome/preparation")
        .filter(|value| !value.is_null())
        .cloned()
        .with_context(|| format!("prepare returned no live preparation: {response}"))?;
    let preparation_bytes = serde_json::to_vec(&preparation)?;
    protocol::verify_direct_request_preparation(&preparation_bytes, &server.receipt_public_key)?;
    let verified_prepare = protocol::verify_signed_request(
        DirectRequestKind::Prepare,
        &serde_json::to_vec(&prepare)?,
        &alice_public,
    )?;
    let selected = preparation["selectedDevices"]
        .as_array()
        .context("preparation selectedDevices")?;
    anyhow::ensure!(
        selected.len() == 1 + usize::from(include_sibling),
        "preparation selected an unexpected recipient audience"
    );
    let minimum_import_until = u64::try_from(
        chrono::DateTime::parse_from_rfc3339(
            preparation["minimumImportUntil"]
                .as_str()
                .context("minimumImportUntil")?,
        )?
        .timestamp(),
    )?;
    let mut authority_import_until = u64::MAX;
    for device in selected {
        let selected_public = if device["actorDeviceId"] == bob.device_id.to_string() {
            bob_public.clone()
        } else {
            let sibling = sibling.as_ref().context("unexpected selected sibling")?;
            anyhow::ensure!(
                device["actorDeviceId"] == sibling.service.device_id.to_string(),
                "unknown selected device"
            );
            sibling.engine.identity_public_key(&sibling.identity)?
        };
        let grant = protocol::verify_signed_request(
            DirectRequestKind::Grant,
            &serde_json::to_vec(&device["grant"])?,
            &selected_public,
        )?;
        let expires_at = u64::try_from(
            chrono::DateTime::parse_from_rfc3339(
                grant.body()["expiresAt"]
                    .as_str()
                    .context("selected grant expiresAt")?,
            )?
            .timestamp(),
        )?;
        authority_import_until = authority_import_until.min(expires_at);
    }
    anyhow::ensure!(
        authority_import_until >= minimum_import_until,
        "selected authenticated grant expires before preparation import floor"
    );
    let context = json!({
        "protocolVersion":"2",
        "requestId":request_id.to_string(),
        "firstMessageId":first_message_id.to_string(),
        "conversationId":conversation_id.to_string(),
        "origin":{"$type":"blue.catbird.chat.defs#freshDirectOrigin"},
        "actorDid":alice.did,
        "actorDeviceId":alice.device_id.to_string(),
        "actorKeyId":alice_key_id,
        "recipientDid":bob.did,
        "preparationDigest":preparation["preparationDigest"]
    });
    let journal = alice_engine.prepare_direct_request(&DirectRequestBootstrapInput {
        draft_id: Uuid::new_v4().to_string(),
        context_json: serde_json::to_vec(&context)?,
        group_id: rand::random::<[u8; 32]>().to_vec(),
        generation: 0,
        state_version: 1,
        key_packages: selected
            .iter()
            .map(|device| {
                Ok(STANDARD.decode(
                    device["keyPackage"]["bytes"]
                        .as_str()
                        .context("selected package bytes")?,
                )?)
            })
            .collect::<anyhow::Result<Vec<_>>>()?,
        expected_package_refs: selected
            .iter()
            .map(|device| {
                Ok(STANDARD.decode(
                    device["keyPackage"]["keyPackageRef"]
                        .as_str()
                        .context("selected package ref")?,
                )?)
            })
            .collect::<anyhow::Result<Vec<_>>>()?,
        authority_import_until,
        preparation_request_digest: *verified_prepare.request_digest(),
        receipt_authority_key: server.receipt_public_key.clone(),
        text: "Real encrypted first contact".into(),
        invitation: None,
        metadata: GroupMetadataV1 {
            version: 1,
            title: String::new(),
            description: String::new(),
            avatar_blob_locator: None,
            avatar_content_type: None,
        },
    })?;
    let bootstrap = &journal.bootstrap;
    let mut publish_body = prepare["body"].clone();
    publish_body["$type"] = json!("blue.catbird.chat.defs#directRequestPublicationBody");
    publish_body["signatureDomain"] = json!("CATBIRD-DIRECT-REQUEST-PUBLISH\0");
    publish_body["signedAt"] = json!(canonical_now());
    publish_body["preparationDigest"] = preparation["preparationDigest"].clone();
    publish_body["preparationRequestDigest"] =
        json!(STANDARD.encode(verified_prepare.request_digest()));
    publish_body["contextHash"] = json!(STANDARD.encode(bootstrap.context_hash));
    publish_body["next"] = bootstrap.coordinates.clone();
    publish_body["importUntil"] = json!(chrono::DateTime::from_timestamp(
        bootstrap.import_until as i64,
        0
    )
    .context("import timestamp")?
    .to_rfc3339_opts(chrono::SecondsFormat::Millis, true));
    let artifact = |data: &[u8], content_type: &str| {
        json!({
            "framing":"mlsMessage","contentType":content_type,
            "bytes":STANDARD.encode(data),"sha256":STANDARD.encode(Sha256::digest(data))
        })
    };
    let deliveries = selected
        .iter()
        .map(|device| {
            json!({
                "recipientDid":device["actorDid"],
                "recipientDeviceId":device["actorDeviceId"],
                "provenance":{
                    "requestId":request_id.to_string(),
                    "preparationDigest":preparation["preparationDigest"],
                    "contextHash":STANDARD.encode(bootstrap.context_hash),
                    "grantId":device["grant"]["body"]["grantId"],
                    "grantRevision":device["grant"]["body"]["grantRevision"],
                    "keyPackageRef":device["keyPackage"]["keyPackageRef"],
                    "importUntil":publish_body["importUntil"]
                }
            })
        })
        .collect::<Vec<_>>();
    let author = json!({
        "authorDid":alice.did,"authorDeviceId":alice.device_id.to_string(),"authorKeyId":alice_key_id,
        "signaturePublicKey":STANDARD.encode(&alice_public),"authGenerationAtOrigin":1,
        "originTransitionId":request_id.to_string(),"originSeq":1,"roleAtOrigin":"admin",
        "deviceStatusAtOrigin":"active"
    });
    publish_body["artifacts"] = json!({
        "genesisGroupInfo":artifact(&bootstrap.genesis_group_info,"groupInfo"),
        "addCommit":artifact(&bootstrap.add_commit,"publicMessageCommit"),
        "finalGroupInfo":artifact(&bootstrap.final_group_info,"groupInfo"),
        "welcome":{"opaqueWelcome":STANDARD.encode(&bootstrap.welcome),"sha256":STANDARD.encode(Sha256::digest(&bootstrap.welcome)),"deliveries":deliveries},
        "initialCiphertext":STANDARD.encode(&bootstrap.initial_ciphertext),
        "metadataSnapshot":{
            "coordinate":metadata_coordinate(&bootstrap.coordinates)?,
            "originTransitionId":request_id.to_string(),"metadataVersion":1,
            "nonce":STANDARD.encode(&bootstrap.metadata_nonce),
            "ciphertext":STANDARD.encode(&bootstrap.metadata_ciphertext),
            "ciphertextSha256":STANDARD.encode(Sha256::digest(&bootstrap.metadata_ciphertext)),
            "ciphertextSize":bootstrap.metadata_ciphertext.len(),"authorProof":author
        }
    });
    let publication = signed_mls_request(
        &alice_engine,
        &alice_identity,
        DirectRequestKind::Publish,
        publish_body,
    )?;
    alice_engine.persist_request_publication(
        &request_id.to_string(),
        &serde_json::to_vec(&json!({"signedRequest":publication}))?,
    )?;
    let (publish_status, publish_response) = alice
        .post(
            &client,
            &server.base_url,
            "blue.catbird.chat.publishDirectRequest",
            &json!({"signedRequest":publication}),
            true,
        )
        .await?;
    anyhow::ensure!(
        publish_status == reqwest::StatusCode::OK,
        "publish failed {publish_status}: {}",
        String::from_utf8_lossy(&publish_response)
    );
    let published: Value = serde_json::from_slice(&publish_response)?;
    let mut receipt = published["outcome"].clone();
    receipt
        .as_object_mut()
        .context("published outcome object")?
        .remove("$type");
    let verified_publication = protocol::verify_signed_request(
        DirectRequestKind::Publish,
        &serde_json::to_vec(&publication)?,
        &alice_public,
    )?;
    let verified_receipt = protocol::verify_signed_request(
        DirectRequestKind::Outcome,
        &serde_json::to_vec(&receipt)?,
        &server.receipt_public_key,
    )?;
    let proof = &verified_receipt.body()["receipt"];
    let expected_publication_digest = STANDARD.encode(verified_publication.request_digest());
    let expected_preparation_digest = STANDARD.encode(verified_prepare.request_digest());
    let mut receipt_mismatches = Vec::new();
    for (field, matches) in [
        (
            "$type",
            proof["$type"] == "blue.catbird.chat.defs#directRequestPublishedReceipt",
        ),
        ("requestId", proof["requestId"] == request_id.to_string()),
        ("requestKind", proof["requestKind"] == "publish"),
        ("coordinates", proof["coordinates"] == bootstrap.coordinates),
        (
            "conversationId",
            proof["conversationId"] == conversation_id.to_string(),
        ),
        (
            "firstMessageId",
            proof["firstMessageId"] == first_message_id.to_string(),
        ),
        (
            "requestDigest",
            proof["requestDigest"] == expected_publication_digest,
        ),
        (
            "preparationRequestDigest",
            proof["preparationRequestDigest"] == expected_preparation_digest,
        ),
    ] {
        if !matches {
            receipt_mismatches.push(field);
        }
    }
    anyhow::ensure!(
        receipt_mismatches.is_empty(),
        "shipping receipt differs from native Welcome contract in fields: {receipt_mismatches:?}"
    );
    let welcome_input = DirectRequestWelcomeInput {
        bootstrap: bootstrap.clone(),
        local_identity: bob_identity.as_bytes().to_vec(),
        local_package_ref: bob_package_ref,
        publication_request: serde_json::to_vec(&publication)?,
        actor_signature_public_key: alice_public,
        published_receipt: serde_json::to_vec(&receipt)?,
        receipt_authority_key: server.receipt_public_key.clone(),
        preparation_request_digest: *verified_prepare.request_digest(),
    };
    if import_recipient {
        bob_engine.process_direct_request(&welcome_input)?;
        let decrypted = bob_engine.decrypt_direct_request(&welcome_input)?;
        let DirectRequestIntroductionResult::Ready { plaintext } = decrypted else {
            anyhow::bail!("recipient introduction unavailable")
        };
        let introduction = protocol::decode_direct_request_introduction(&plaintext)?;
        assert_eq!(introduction["text"], "Real encrypted first contact");
    }
    let snapshot = request_database_snapshot(request_id)?;
    assert_eq!(snapshot.request_rows, 1);
    assert_eq!(snapshot.message_rows, 1);
    assert_eq!(snapshot.welcome_rows, 1 + usize::from(include_sibling));
    assert_eq!(snapshot.plaintext_matches, 0);
    Ok((
        PublishedRequestFixture {
            alice,
            bob,
            alice_engine: Some(alice_engine),
            bob_engine,
            server,
            client,
            request_id,
            conversation_id,
            first_message_id,
            welcome_input,
            publication,
            receipt,
            push_event_id: super::encrypted_requests::request_push_event_id(request_id)?,
            push_registration_request,
            push_registration_ack,
            _https: https,
        },
        sibling,
    ))
}

fn signed_ordinary(engine: &MlsEngine, identity: &str, body: Value) -> anyhow::Result<Value> {
    use catbird_mls::chat_v2::transcript::{
        decode_strict_json, project_signed_body, SignedMutationKind, SigningTranscript,
        VerifiedMutation,
    };
    let canonical = project_signed_body(
        SignedMutationKind::from_type_id(body["$type"].as_str().context("signed type")?)
            .context("signed kind")?,
        &decode_strict_json(&serde_json::to_vec(&body)?)?,
    )?;
    let transcript = SigningTranscript::build(&canonical)?;
    let signature = engine.sign_identity(identity, transcript.bytes().to_vec())?;
    VerifiedMutation::verify(
        canonical,
        signature
            .clone()
            .try_into()
            .map_err(|_| anyhow::anyhow!("signature length"))?,
        &engine.identity_public_key(identity)?,
    )?;
    Ok(json!({"body":body,"signature":STANDARD.encode(signature)}))
}

async fn checked_post(
    f: &PublishedRequestFixture,
    who: &ServiceIdentity,
    nsid: &str,
    envelope: &Value,
) -> anyhow::Result<Vec<u8>> {
    let (status, bytes) = who
        .post(&f.client, &f.server.base_url, nsid, envelope, true)
        .await?;
    anyhow::ensure!(
        status == reqwest::StatusCode::OK,
        "{nsid} failed {status}: {}",
        String::from_utf8_lossy(&bytes)
    );
    Ok(bytes)
}

fn graph(conversation: Uuid) -> anyhow::Result<Value> {
    validate_request_test_database_url(std::env::var("REQUEST_TEST_DATABASE_URL").ok().as_deref())?;
    let sql = format!("SELECT json_build_object('generation',c.current_generation,'stateVersion',c.current_state_version,'generationStateVersion',(SELECT g.current_state_version FROM chat.generations g WHERE g.conversation_id=c.conversation_id AND g.generation=c.current_generation),'acceptanceClaims',(SELECT count(*) FROM chat.direct_request_acceptance_claims a JOIN chat.direct_request_publications p ON p.request_id=a.request_id WHERE p.conversation_id=c.conversation_id),'epoch',s.epoch,'nextSeq',c.next_entry_seq,'transitions',(SELECT count(*) FROM chat.transitions t WHERE t.conversation_id=c.conversation_id),'introductions',(SELECT count(*) FROM chat.entries e WHERE e.conversation_id=c.conversation_id AND e.entry_kind='blue.catbird.chat.defs#directRequestEntry'),'applications',(SELECT count(*) FROM chat.entries e WHERE e.conversation_id=c.conversation_id AND e.entry_kind='blue.catbird.chat.defs#applicationEntry'))::text FROM chat.conversations c JOIN chat.generation_states s ON s.conversation_id=c.conversation_id AND s.generation=c.current_generation AND s.state_version=c.current_state_version WHERE c.conversation_id='{conversation}'");
    let result = std::process::Command::new("psql")
        .args([
            REQUEST_TEST_DATABASE_URL,
            "-X",
            "-A",
            "-t",
            "-v",
            "ON_ERROR_STOP=1",
            "-c",
            &sql,
        ])
        .output()?;
    anyhow::ensure!(
        result.status.success(),
        "guarded graph read failed: {}",
        String::from_utf8_lossy(&result.stderr)
    );
    Ok(serde_json::from_slice(&result.stdout)?)
}

pub async fn accept_reply_offline(accept_before_import: bool) -> anyhow::Result<()> {
    use catbird_mls::chat_v2::transcript::{decode_strict_json, VerifiedApplicationEntry};
    use catbird_mls::orchestrator::{canonical_application_aad_bytes, MLSMessagePayload};
    // Both scenarios start with an unimported recipient. The sender must be
    // offline before the first recipient Welcome import, not merely before
    // acceptance and reply.
    let mut f = publish_request(false).await?;
    // Exercise pending point-read and retained Welcome presentation through
    // the shipping HTTP facade before account consent changes.
    let (pending_status, pending_bytes) = f
        .bob
        .get(
            &f.client,
            &f.server.base_url,
            "blue.catbird.chat.getConversationState",
            &[("conversationId".into(), f.conversation_id.to_string())],
        )
        .await?;
    anyhow::ensure!(
        pending_status == reqwest::StatusCode::OK,
        "pending state failed {pending_status}: {}",
        String::from_utf8_lossy(&pending_bytes)
    );
    let pending: Value = serde_json::from_slice(&pending_bytes)?;
    assert_eq!(
        pending["state"]["directRequest"]["consent"],
        "incomingPending"
    );
    assert_eq!(
        pending["state"]["directRequest"]["contextHash"],
        f.publication["body"]["contextHash"]
    );
    let (inventory_status, inventory_bytes) = f
        .bob
        .get(
            &f.client,
            &f.server.base_url,
            "blue.catbird.chat.getConversations",
            &[
                ("limit".into(), "100".into()),
                ("supportedProtocolVersions".into(), "1".into()),
                ("supportedProtocolVersions".into(), "2".into()),
            ],
        )
        .await?;
    anyhow::ensure!(
        inventory_status == reqwest::StatusCode::OK,
        "pending inventory failed {inventory_status}: {}",
        String::from_utf8_lossy(&inventory_bytes)
    );
    let inventory: Value = serde_json::from_slice(&inventory_bytes)?;
    let (welcomes_status, welcomes_bytes) = f
        .bob
        .get(
            &f.client,
            &f.server.base_url,
            "blue.catbird.chat.getPendingWelcomes",
            &[
                ("limit".into(), "100".into()),
                (
                    "inventorySessionId".into(),
                    inventory["inventorySessionId"]
                        .as_str()
                        .context("inventory session")?
                        .into(),
                ),
                ("supportedProtocolVersions".into(), "1".into()),
                ("supportedProtocolVersions".into(), "2".into()),
            ],
        )
        .await?;
    anyhow::ensure!(
        welcomes_status == reqwest::StatusCode::OK,
        "pending Welcomes failed {welcomes_status}: {}",
        String::from_utf8_lossy(&welcomes_bytes)
    );
    let welcomes: Value = serde_json::from_slice(&welcomes_bytes)?;
    assert_eq!(
        welcomes["items"].as_array().context("Welcome items")?.len(),
        1
    );
    let welcome = &welcomes["items"][0];
    assert_eq!(
        welcome["$type"],
        "blue.catbird.chat.defs#directRequestWelcomeView"
    );
    assert_eq!(welcome["welcomeId"], f.request_id.to_string());
    let wire_bytes = |value: &Value| -> anyhow::Result<Vec<u8>> {
        Ok(STANDARD.decode(
            value
                .as_str()
                .or_else(|| value["$bytes"].as_str())
                .context("wire bytes")?,
        )?)
    };
    assert_eq!(
        wire_bytes(&welcome["opaqueWelcome"])?,
        STANDARD.decode(
            f.publication["body"]["artifacts"]["welcome"]["opaqueWelcome"]
                .as_str()
                .unwrap()
        )?
    );
    assert_eq!(
        wire_bytes(&welcome["provenance"]["contextHash"])?,
        wire_bytes(&f.publication["body"]["contextHash"])?
    );
    let prior = f.welcome_input.bootstrap.coordinates.clone();
    let group = STANDARD.decode(prior["groupId"].as_str().context("group ID")?)?;
    let epoch = prior["epoch"].as_u64().context("epoch")?;
    let before = graph(f.conversation_id)?;
    assert_eq!(before["introductions"], 1);
    assert_eq!(before["applications"], 0);
    let alice_engine = f.alice_engine.take().context("sender native store")?;
    alice_engine.confirm_request_publication(
        &f.request_id.to_string(),
        &serde_json::to_vec(&f.receipt)?,
        &f.server.receipt_public_key,
    )?;
    assert_eq!(alice_engine.epoch(&group)?, epoch);
    assert!(
        f.bob_engine.epoch(&group).is_err(),
        "recipient imported while sender was still online"
    );
    // No sender context exists during import, acceptance or reply; reopen is deferred.
    let offline_sender = alice_engine.close_for_offline()?;
    assert!(f.alice_engine.is_none());
    if !accept_before_import {
        f.bob_engine.process_direct_request(&f.welcome_input)?;
        let DirectRequestIntroductionResult::Ready { plaintext } =
            f.bob_engine.decrypt_direct_request(&f.welcome_input)?
        else {
            anyhow::bail!("pending introduction unavailable with sender offline")
        };
        assert_eq!(
            protocol::decode_direct_request_introduction(&plaintext)?["text"],
            "Real encrypted first contact"
        );
        assert_eq!(graph(f.conversation_id)?, before);
    }
    let bob_identity = format!("{}#{}", f.bob.did, f.bob.device_id);
    let bob_public = f.bob_engine.identity_public_key(&bob_identity)?;
    let transition = Uuid::new_v4();
    let mut next = prior.clone();
    next["stateVersion"] = json!(prior["stateVersion"].as_u64().context("state version")? + 1);
    let acceptance = signed_mls_request(
        &f.bob_engine,
        &bob_identity,
        DirectRequestKind::Accept,
        json!({
            "$type":"blue.catbird.chat.defs#directRequestAcceptanceBody", "signatureDomain":"CATBIRD-DIRECT-REQUEST-ACCEPT\0", "protocolVersion":"2",
            "actorDid":f.bob.did, "actorDeviceId":f.bob.device_id.to_string(), "keyId":URL_SAFE_NO_PAD.encode(Sha256::digest(&bob_public)), "authGeneration":1,
            "requestId":f.request_id.to_string(), "transitionId":transition.to_string(), "prior":prior, "next":next,
            "invitationProvenance":{"invitationTransitionId":f.request_id.to_string(),"invitedByDid":f.alice.did,"invitedByDeviceId":f.alice.device_id.to_string()},
            "idempotencyKey":transition.to_string(),"signedAt":canonical_now()
        }),
    )?;
    // A correctly signed but stale successor must leave the complete durable
    // graph unchanged, including both pointers and the exact replay claim.
    let stale_operation = Uuid::new_v4();
    let mut stale_body = acceptance["body"].clone();
    stale_body["transitionId"] = json!(stale_operation.to_string());
    stale_body["idempotencyKey"] = json!(stale_operation.to_string());
    stale_body["prior"]["stateVersion"] = next["stateVersion"].clone();
    stale_body["next"]["stateVersion"] = json!(next["stateVersion"].as_u64().unwrap() + 1);
    let stale = signed_mls_request(
        &f.bob_engine,
        &bob_identity,
        DirectRequestKind::Accept,
        stale_body,
    )?;
    let (stale_status, stale_bytes) = f
        .bob
        .post(
            &f.client,
            &f.server.base_url,
            "blue.catbird.chat.acceptConversation",
            &json!({"directRequest":stale}),
            true,
        )
        .await?;
    assert_eq!(stale_status, reqwest::StatusCode::BAD_REQUEST);
    assert_eq!(
        serde_json::from_slice::<Value>(&stale_bytes)?["error"],
        "StaleCoordinates"
    );
    assert_eq!(
        graph(f.conversation_id)?,
        before,
        "stale acceptance leaked durable effects"
    );
    let envelope = json!({"directRequest":acceptance});
    let accepted_bytes = checked_post(
        &f,
        &f.bob,
        "blue.catbird.chat.acceptConversation",
        &envelope,
    )
    .await?;
    let accepted: Value = serde_json::from_slice(&accepted_bytes)?;
    let proof = protocol::verify_direct_request_acceptance_proof(
        &serde_json::to_vec(&accepted["acceptanceProof"])?,
        &f.server.receipt_public_key,
        &bob_public,
    )?;
    assert_eq!(
        proof["receipt"]["body"]["requestId"],
        f.request_id.to_string()
    );
    assert_eq!(proof["receipt"]["body"]["prior"], prior);
    assert_eq!(proof["receipt"]["body"]["next"], next);
    assert_eq!(proof["entry"]["signedRequest"], acceptance);
    let replay = checked_post(
        &f,
        &f.bob,
        "blue.catbird.chat.acceptConversation",
        &envelope,
    )
    .await?;
    assert_eq!(
        replay, accepted_bytes,
        "acceptance replay must be byte-identical"
    );
    if accept_before_import {
        assert!(
            f.bob_engine.epoch(&group).is_err(),
            "recipient already imported before acceptance"
        );
        f.bob_engine.process_direct_request(&f.welcome_input)?;
    }
    assert_eq!(f.bob_engine.epoch(&group)?, epoch);
    let introduction = f.bob_engine.decrypt_direct_request(&f.welcome_input)?;
    let DirectRequestIntroductionResult::Ready { plaintext } = &introduction else {
        anyhow::bail!("introduction unavailable after acceptance")
    };
    assert_eq!(
        protocol::decode_direct_request_introduction(plaintext)?["text"],
        "Real encrypted first contact"
    );
    assert_eq!(
        f.bob_engine.decrypt_direct_request(&f.welcome_input)?,
        introduction,
        "native replay must reuse protected preview"
    );

    let message = Uuid::new_v4();
    let mut aad_prior = next.clone();
    aad_prior["conversationId"] = json!(STANDARD.encode(f.conversation_id.as_bytes()));
    let aad = json!({"protocolVersion":"1","conversationId":STANDARD.encode(f.conversation_id.as_bytes()),"generation":next["generation"],"messageId":STANDARD.encode(message.as_bytes()),"prior":aad_prior});
    let text = "Reply while the original sender is offline";
    let content = MLSMessagePayload::text(text).encode()?;
    let ciphertext = f.bob_engine.encrypt_canonical(
        &group,
        &content,
        canonical_application_aad_bytes(&aad)?,
        epoch,
    )?;
    let application = signed_ordinary(
        &f.bob_engine,
        &bob_identity,
        json!({
            "$type":"blue.catbird.chat.defs#applicationSendBody","signatureDomain":"CATBIRD-CHAT-MESSAGE\0","messageId":message.to_string(),
            "actorDid":f.bob.did,"actorDeviceId":f.bob.device_id.to_string(),"keyId":URL_SAFE_NO_PAD.encode(Sha256::digest(&bob_public)),"authGeneration":1,
            "prior":next,"aad":aad,"applicationMessage":{"framing":"mlsMessage","contentType":"privateMessageApplication","bytes":STANDARD.encode(&ciphertext),"sha256":STANDARD.encode(Sha256::digest(&ciphertext))},"blobBindings":[],"signedAt":canonical_now()
        }),
    )?;
    let send_envelope = json!({"signedRequest":application});
    let sent_bytes =
        checked_post(&f, &f.bob, "blue.catbird.chat.sendMessage", &send_envelope).await?;
    let sent: Value = serde_json::from_slice(&sent_bytes)?;
    assert_eq!(
        checked_post(&f, &f.bob, "blue.catbird.chat.sendMessage", &send_envelope).await?,
        sent_bytes
    );
    let after = graph(f.conversation_id)?;
    assert_eq!(after["generation"], before["generation"]);
    assert_eq!(after["epoch"], before["epoch"]);
    assert_eq!(after["stateVersion"], next["stateVersion"]);
    assert_eq!(after["generationStateVersion"], next["stateVersion"]);
    assert_eq!(after["acceptanceClaims"], 1);
    assert_eq!(
        after["transitions"].as_u64(),
        before["transitions"].as_u64().map(|n| n + 1)
    );
    assert_eq!(after["introductions"], 1);
    assert_eq!(after["applications"], 1);

    let sender = offline_sender.reopen()?;
    assert_eq!(sender.epoch(&group)?, epoch);
    let (state_status, state_bytes) = f
        .alice
        .get(
            &f.client,
            &f.server.base_url,
            "blue.catbird.chat.getConversationState",
            &[("conversationId".into(), f.conversation_id.to_string())],
        )
        .await?;
    anyhow::ensure!(
        state_status == reqwest::StatusCode::OK,
        "sender state catch-up failed {state_status}: {}",
        String::from_utf8_lossy(&state_bytes)
    );
    let state: Value = serde_json::from_slice(&state_bytes)?;
    let sender_proof = protocol::verify_direct_request_acceptance_proof(
        &serde_json::to_vec(&state["state"]["directRequest"]["acceptanceProof"])?,
        &f.server.receipt_public_key,
        &bob_public,
    )?;
    assert_eq!(sender_proof, proof);
    assert_eq!(state["state"]["directRequest"]["consent"], "accepted");
    let (status, bytes) = f
        .alice
        .get(
            &f.client,
            &f.server.base_url,
            "blue.catbird.chat.getEntries",
            &[
                ("conversationId".into(), f.conversation_id.to_string()),
                ("afterSeq".into(), "0".into()),
                ("limit".into(), "100".into()),
            ],
        )
        .await?;
    anyhow::ensure!(
        status == reqwest::StatusCode::OK,
        "sender catch-up failed {status}: {}",
        String::from_utf8_lossy(&bytes)
    );
    let page: Value = serde_json::from_slice(&bytes)?;
    let entries = page["entries"].as_array().context("entries")?;
    assert_eq!(
        entries.len(),
        3,
        "only publication, acceptance and reply are present"
    );
    assert_eq!(page["hasMore"], false);
    assert_eq!(page["nextAfterSeq"], 3);
    assert_eq!(
        entries
            .iter()
            .filter(|e| e["$type"] == "blue.catbird.chat.defs#directRequestEntry")
            .count(),
        1
    );
    assert_eq!(
        entries
            .iter()
            .filter(|e| e["$type"] == "blue.catbird.chat.defs#directRequestAcceptanceEntry")
            .count(),
        1
    );
    let introduction_entry = entries
        .iter()
        .find(|e| e["$type"] == "blue.catbird.chat.defs#directRequestEntry")
        .context("introduction entry")?;
    assert_eq!(introduction_entry["signedRequest"], f.publication);
    assert_eq!(
        introduction_entry["signedRequest"]["body"]["firstMessageId"],
        f.first_message_id.to_string()
    );
    let response_entry = entries
        .iter()
        .find(|e| e["$type"] == "blue.catbird.chat.defs#applicationEntry")
        .context("reply entry")?;
    let mut row = response_entry.clone();
    row.as_object_mut().context("entry object")?.remove("$type");
    assert_eq!(row, sent["entry"]);
    let verified_entry = VerifiedApplicationEntry::verify(
        &decode_strict_json(&serde_json::to_vec(&row)?)?,
        &bob_public,
    )?;
    assert_eq!(row["signedRequest"], application);
    let authenticated = sender.decrypt_authenticated(&group, &ciphertext)?;
    verified_entry.bind_sender(&authenticated.sender_credential.identity)?;
    assert_eq!(authenticated.epoch, epoch);
    assert_eq!(
        MLSMessagePayload::decode(&authenticated.plaintext)?.display_text(),
        text
    );
    assert_eq!(sender.epoch(&group)?, epoch);
    assert_eq!(request_database_snapshot(f.request_id)?.message_rows, 1);
    Ok(())
}

/// Accept a retained live fixture without importing a Welcome or dropping its
/// processes. Used to prove canonical suppression of its original push event.
pub async fn accept_existing_fixture(f: &PublishedRequestFixture) -> anyhow::Result<()> {
    let prior = f.welcome_input.bootstrap.coordinates.clone();
    let before = graph(f.conversation_id)?;
    let identity = format!("{}#{}", f.bob.did, f.bob.device_id);
    let public_key = f.bob_engine.identity_public_key(&identity)?;
    let transition = Uuid::new_v4();
    let mut next = prior.clone();
    next["stateVersion"] = json!(prior["stateVersion"].as_u64().context("state version")? + 1);
    let signed = signed_mls_request(
        &f.bob_engine,
        &identity,
        DirectRequestKind::Accept,
        json!({
            "$type":"blue.catbird.chat.defs#directRequestAcceptanceBody",
            "signatureDomain":"CATBIRD-DIRECT-REQUEST-ACCEPT\0", "protocolVersion":"2",
            "actorDid":f.bob.did, "actorDeviceId":f.bob.device_id.to_string(),
            "keyId":URL_SAFE_NO_PAD.encode(Sha256::digest(&public_key)), "authGeneration":1,
            "requestId":f.request_id.to_string(), "transitionId":transition.to_string(),
            "prior":prior, "next":next,
            "invitationProvenance":{"invitationTransitionId":f.request_id.to_string(),
                "invitedByDid":f.alice.did,"invitedByDeviceId":f.alice.device_id.to_string()},
            "idempotencyKey":transition.to_string(),"signedAt":canonical_now()
        }),
    )?;
    let envelope = json!({"directRequest":signed});
    let bytes = checked_post(f, &f.bob, "blue.catbird.chat.acceptConversation", &envelope).await?;
    let accepted: Value = serde_json::from_slice(&bytes)?;
    let proof = protocol::verify_direct_request_acceptance_proof(
        &serde_json::to_vec(&accepted["acceptanceProof"])?,
        &f.server.receipt_public_key,
        &public_key,
    )?;
    assert_eq!(
        proof["receipt"]["body"]["requestId"],
        f.request_id.to_string()
    );
    assert_eq!(proof["receipt"]["body"]["prior"], prior);
    assert_eq!(proof["receipt"]["body"]["next"], next);
    assert_eq!(proof["entry"]["signedRequest"], signed);
    assert_eq!(
        checked_post(f, &f.bob, "blue.catbird.chat.acceptConversation", &envelope).await?,
        bytes
    );
    let after = graph(f.conversation_id)?;
    assert_eq!(after["generation"], before["generation"]);
    assert_eq!(after["epoch"], before["epoch"]);
    assert_eq!(after["applications"], before["applications"]);
    assert_eq!(after["introductions"], before["introductions"]);
    assert_eq!(after["stateVersion"], next["stateVersion"]);
    assert_eq!(after["generationStateVersion"], next["stateVersion"]);
    assert_eq!(after["acceptanceClaims"], 1);
    assert_eq!(
        after["transitions"].as_u64(),
        before["transitions"].as_u64().map(|n| n + 1)
    );
    Ok(())
}
