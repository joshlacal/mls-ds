//! F37: an ordinary send through the real `MLSOrchestrator` against the live
//! shipping router. The router echoes the accepted signed request with lexicon
//! `{"$bytes"}` byte fields while the client submitted some declared bytes as
//! bare base64 (the identifierBytes AAD fields). The send must succeed, keep
//! its submitted form, record its own-echo proof and read back through the
//! generated types and the canonical host entry mapping.
#![allow(dead_code)]

#[path = "support/encrypted_requests.rs"]
mod encrypted_requests;
#[path = "../../../catbird-mls/tests/epoch_secret_test_support.rs"]
mod epoch_secret_test_support;
#[path = "support/live_orchestrator.rs"]
mod live_orchestrator;

use anyhow::Context as _;
use catbird_mls::orchestrator::reset_flow::ResetOutcome;
use catbird_mls::orchestrator::MLSAPIClient;
use encrypted_requests::{
    connect_guarded_request_database, reviewed_request_migrations, seed_service_device,
    HttpsDidFixture, ServiceIdentity, ShippingServerFixture,
};
use live_orchestrator::mock_credentials::MockCredentials;
use mls_e2e_tests::mls_engine::MlsEngine;
use petrel_catbird::generated::blue::catbird::chat::{
    accept_conversation::Output as AcceptConversationOutput,
    activate_reset::Output as ActivateResetOutput,
    create_conversation::Output as CreateConversationOutput, defs::ConversationEntry,
    get_entries::Output as GetEntriesOutput,
    get_subscription_ticket::Output as GetSubscriptionTicketOutput,
    request_reset::Output as RequestResetOutput, send_message::Output as SendMessageOutput,
    submit_transition::Output as SubmitTransitionOutput,
};
use serde_json::Value;
use uuid::Uuid;

#[tokio::test(flavor = "multi_thread")]
async fn live_orchestrator_send_accepts_the_presented_echo_of_its_signed_request(
) -> anyhow::Result<()> {
    let authority = connect_guarded_request_database(5).await?;
    anyhow::ensure!(authority.additive_migrations == reviewed_request_migrations().len());
    let run = Uuid::new_v4().simple().to_string();
    let alice = ServiceIdentity::new(format!(
        "did:web:f37-alice-{run}.request-fixture.catbird.blue"
    ));
    let bob = ServiceIdentity::new(format!(
        "did:web:f37-bob-{run}.request-fixture.catbird.blue"
    ));
    let https = HttpsDidFixture::start(
        HttpsDidFixture::reserve_port()?,
        &[
            (alice.did.clone(), alice.did_document()),
            (bob.did.clone(), bob.did_document()),
        ],
    )?;
    // The client admits only the canonical subscription authority.
    let server = ShippingServerFixture::start_with_client_runtime(
        &https,
        "wss://chat.catbird.blue/xrpc/blue.catbird.chat.subscribeEvents",
    )?;
    let client = reqwest::Client::builder().build()?;

    let engine = MlsEngine::new("f37-alice")?;
    // The platform installs durable epoch-secret storage before MLS writes.
    epoch_secret_test_support::install(&engine.context());
    let identity = format!("{}#{}", alice.did, alice.device_id);
    engine.create_key_package(&identity)?;
    let public = engine.identity_public_key(&identity)?;
    seed_service_device(&alice, &public)?;
    // A second real device so the send has an addressed recipient leaf.
    let bob_engine = MlsEngine::new("f37-bob")?;
    let bob_identity = format!("{}#{}", bob.did, bob.device_id);
    let (bob_package, _) = bob_engine.create_key_package(&bob_identity)?;
    seed_service_device(&bob, &bob_engine.identity_public_key(&bob_identity)?)?;
    // Authorized device keys come from the live device directory.
    let directory_key = |owner: &ServiceIdentity, key: Vec<u8>| {
        let (client, base, alice) = (client.clone(), server.base_url.clone(), alice.clone());
        let owner = owner.clone();
        async move {
            use base64::Engine as _;
            use sha2::Digest as _;
            let key_id =
                base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(sha2::Sha256::digest(&key));
            let (status, body) = alice
                .get_device_key(&client, &base, &owner.did, owner.device_id, &key_id)
                .await?;
            anyhow::ensure!(status == reqwest::StatusCode::OK, "getDeviceKey {status}");
            let served: Value = serde_json::from_slice(&body)?;
            anyhow::Ok(
                base64::engine::general_purpose::STANDARD.decode(
                    served["signaturePublicKey"]["$bytes"]
                        .as_str()
                        .context("signaturePublicKey")?,
                )?,
            )
        }
    };
    let credentials = MockCredentials::new();
    credentials.set_authorized_device_keys(
        &alice.did,
        vec![directory_key(&alice, public.clone()).await?],
    );
    credentials.set_authorized_device_keys(
        &bob.did,
        vec![directory_key(&bob, bob_engine.identity_public_key(&bob_identity)?).await?],
    );
    let orchestrator = live_orchestrator::live_orchestrator_with_key_packages(
        engine.context(),
        &alice,
        &client,
        &server.base_url,
        credentials,
        vec![catbird_mls::orchestrator::KeyPackageRef {
            did: bob.did.clone(),
            key_package_data: bob_package,
            hash: None,
            cipher_suite: "MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519".into(),
        }],
    )
    .await?;

    let created = orchestrator
        .create_group("F37 live send", None, None)
        .await
        .context("live create_group")?;
    let cid = created.conversation_id.clone();
    orchestrator
        .add_members(&cid, std::slice::from_ref(&bob.did))
        .await
        .context("live add_members through submitTransition")?;
    // Bob's real orchestrator accepts the invitation (acceptConversation's
    // presented response goes through the core accept path).
    epoch_secret_test_support::install(&bob_engine.context());
    let bob_orchestrator = live_orchestrator::live_orchestrator_with_credentials(
        bob_engine.context(),
        &bob,
        &client,
        &server.base_url,
        MockCredentials::new(),
    )
    .await?;
    bob_orchestrator
        .publish_key_package()
        .await
        .context("live replenishKeyPackages")?;
    bob_orchestrator
        .accept_conversation(&cid)
        .await
        .context("live accept_conversation")?;
    // The legacy orchestrator holds no roster and refuses the acceptance-created
    // recovery (catbird-mls R4 c045032d); a native fulfiller on Alice's device
    // admits Bob (real recovery view read and signed submitTransition fulfilment).
    let refused = orchestrator.fulfill_leaf_recovery(&cid).await;
    assert!(
        matches!(
            refused,
            Err(catbird_mls::orchestrator::OrchestratorError::Mls(
                catbird_mls::MLSError::Cryptography(_)
            ))
        ),
        "{refused:?}"
    );
    let fulfilled = admit_as_native_fulfiller(
        &orchestrator,
        &alice,
        &client,
        &server.base_url,
        &cid,
        &bob.did,
    )
    .await
    .context("live leaf recovery fulfilment")?;
    assert_eq!(
        fulfilled["entry"]["$type"], "blue.catbird.chat.defs#leafRecoveryFulfillmentEntry",
        "{fulfilled}"
    );
    // The success response carries Bob's pending Welcome view, presented.
    let welcomes = fulfilled["welcomes"].as_array().context("welcomes")?;
    assert_eq!(welcomes.len(), 1, "{fulfilled}");
    assert!(
        welcomes[0]["opaqueWelcome"]["$bytes"].is_string(),
        "{fulfilled}"
    );

    // F41 replay regression: re-submitting the exact fulfillment mutation request
    // returns 200 and decodes into SubmitTransitionOutput with presented $bytes.
    let fulfillment_req = orchestrator
        .api_client()
        .last_request_body("blue.catbird.chat.submitTransition")
        .context("fulfillment request body")?;
    let (replay_status, replay_body) = alice
        .forward_exact_service_request(
            &client,
            &server.base_url,
            reqwest::Method::POST,
            "blue.catbird.chat.submitTransition",
            None,
            Some(&fulfillment_req),
        )
        .await
        .context("replay fulfillment request")?;
    anyhow::ensure!(
        replay_status == reqwest::StatusCode::OK,
        "replay fulfillment status {replay_status}: {}",
        String::from_utf8_lossy(&replay_body)
    );
    let replayed: SubmitTransitionOutput = serde_json::from_slice(&replay_body)
        .context("replayed fulfillment must decode into generated SubmitTransitionOutput")?;
    assert_eq!(replayed.welcomes.len(), 1, "replayed welcomes count");
    let replay_raw: Value = serde_json::from_slice(&replay_body)?;
    assert!(
        replay_raw["welcomes"][0]["opaqueWelcome"]["$bytes"].is_string(),
        "replayed opaqueWelcome must be $bytes: {replay_raw}"
    );
    assert!(
        replay_raw["welcomes"][0]["sha256"]["$bytes"].is_string(),
        "replayed sha256 must be $bytes: {replay_raw}"
    );
    assert!(
        replay_raw["welcomes"][0]["provenance"]["keyPackageRef"]["$bytes"].is_string(),
        "replayed keyPackageRef must be $bytes: {replay_raw}"
    );
    assert!(
        replay_raw["coordinates"]["groupId"]["$bytes"].is_string(),
        "replayed groupId must be $bytes: {replay_raw}"
    );
    let sent = orchestrator
        .send_message(&cid, "F37 live send through the real orchestrator")
        .await
        .context("live send_message through encrypt_and_send_message_prepared")?;
    assert_eq!(sent.conversation_id, cid);
    println!(
        "F37 live send accepted: conversation={cid} message={}",
        sent.id
    );
    assert_eq!(sent.sender_did, alice.did);

    // The router presented the echoed signed request with lexicon bytes.
    let (status, body) = alice
        .get(
            &client,
            &server.base_url,
            "blue.catbird.chat.getEntries",
            &[
                ("conversationId".into(), cid.clone()),
                ("afterSeq".into(), "0".into()),
                ("limit".into(), "100".into()),
            ],
        )
        .await?;
    anyhow::ensure!(
        status == reqwest::StatusCode::OK,
        "getEntries {status}: {}",
        String::from_utf8_lossy(&body)
    );
    let raw: Value = serde_json::from_slice(&body)?;
    let application = raw["entries"]
        .as_array()
        .context("entries")?
        .iter()
        .find(|entry| entry["$type"] == "blue.catbird.chat.defs#applicationEntry")
        .context("application entry")?;
    let aad = &application["signedRequest"]["body"]["aad"];
    assert!(
        aad["conversationId"]["$bytes"].is_string(),
        "presented identifierBytes: {aad}"
    );
    assert!(
        aad["messageId"]["$bytes"].is_string(),
        "presented identifierBytes: {aad}"
    );
    let page: GetEntriesOutput =
        serde_json::from_slice(&body).context("getEntries does not decode into generated types")?;
    assert!(page
        .entries
        .iter()
        .any(|entry| matches!(entry, ConversationEntry::ApplicationEntry(_))));

    // The canonical host entry mapping decodes the same presented page.
    let (envelopes, _) =
        live_orchestrator::LiveApiClient::for_test(&alice, &client, &server.base_url)
            .get_messages(&cid, None, 100, None, None, None)
            .await?;
    assert!(
        envelopes
            .iter()
            .any(|envelope| !envelope.ciphertext.is_empty()),
        "application entry maps to an MLS envelope"
    );

    // Reset success path: requestReset then activateReset from the admin.
    let reset = orchestrator
        .reset_conversation(&cid, "localStateLost")
        .await
        .context("live reset_conversation (requestReset + activateReset)")?;
    assert!(matches!(reset, ResetOutcome::Activated { .. }), "{reset:?}");

    // Subscription ticket success path over the authenticated inventory scope.
    let ticket = match orchestrator.prepare_subscription().await {
        Ok(ticket) => ticket,
        Err(error) => {
            let responses = orchestrator
                .api_client()
                .responses("blue.catbird.chat.getSubscriptionTicket");
            let body = responses
                .last()
                .map(|(status, body)| format!("{status}: {}", String::from_utf8_lossy(body)));
            anyhow::bail!("live prepare_subscription (getSubscriptionTicket): {error}; {body:?}");
        }
    };
    anyhow::ensure!(!ticket.ticket.is_empty(), "subscription ticket");

    // Every mutation/ticket SUCCESS response the real client consumed is 200
    // and decodes into its generated output type.
    let api = orchestrator.api_client();
    fn typed<T: serde::de::DeserializeOwned>(
        api: &live_orchestrator::LiveApiClient,
        nsid: &str,
    ) -> anyhow::Result<T> {
        let responses = api.responses(nsid);
        let (status, body) = responses
            .last()
            .with_context(|| format!("no {nsid} exchange"))?;
        anyhow::ensure!(
            *status == 200,
            "{nsid} {status}: {}",
            String::from_utf8_lossy(body)
        );
        serde_json::from_slice(body)
            .with_context(|| format!("{nsid} success body does not decode into generated types"))
    }
    let _: CreateConversationOutput = typed(api, "blue.catbird.chat.createConversation")?;
    let _: SubmitTransitionOutput = typed(api, "blue.catbird.chat.submitTransition")?;
    let _: SendMessageOutput = typed(api, "blue.catbird.chat.sendMessage")?;
    let _: RequestResetOutput = typed(api, "blue.catbird.chat.requestReset")?;
    let _: ActivateResetOutput = typed(api, "blue.catbird.chat.activateReset")?;
    let _: GetSubscriptionTicketOutput = typed(api, "blue.catbird.chat.getSubscriptionTicket")?;
    let _: AcceptConversationOutput = typed(
        bob_orchestrator.api_client(),
        "blue.catbird.chat.acceptConversation",
    )?;
    println!("F37 live typed success: createConversation submitTransition sendMessage acceptConversation requestReset activateReset getSubscriptionTicket");

    orchestrator.shutdown().await;
    bob_orchestrator.shutdown().await;
    Ok(())
}

/// A native fulfiller on the orchestrator's own device admits `joiner_did`
/// through its open acceptance-created leaf recovery: catbird-mls
/// `tests/e2e_harness.rs` `admit_as_native_fulfiller` over the live router. The
/// signed body is the one `fulfill_leaf_recovery_with_target` builds; it goes
/// out through the orchestrator's own transport and lands as the orchestrator
/// lands its own transitions. Returns the `submitTransition` answer.
async fn admit_as_native_fulfiller(
    orchestrator: &live_orchestrator::LiveOrchestrator,
    actor: &ServiceIdentity,
    client: &reqwest::Client,
    base_url: &str,
    cid: &str,
    joiner_did: &str,
) -> anyhow::Result<Value> {
    use base64::{engine::general_purpose::STANDARD, Engine as _};
    use catbird_mls::orchestrator::canonical_transport::{
        canonical_commit_aad_bytes, derive_key_id, CanonicalOperation, CleanChatSigningContext,
    };
    use catbird_mls::orchestrator::{
        CredentialStore as _, MLSStorageBackend as _, MlsCryptoContext,
    };
    use sha2::{Digest as _, Sha256};
    let bytes = |value: &Value| -> anyhow::Result<Vec<u8>> {
        let text = value
            .as_str()
            .or_else(|| value["$bytes"].as_str())
            .context("bytes field")?;
        Ok(STANDARD.decode(text)?)
    };
    let context = orchestrator.mls_context().as_ref();
    let device = orchestrator.require_actor_device_id().await?;
    let auth_generation = orchestrator
        .credentials()
        .get_auth_generation(&actor.did)
        .await?
        .context("auth generation")?;
    let (status, body) = actor
        .get(
            client,
            base_url,
            "blue.catbird.chat.getConversationState",
            &[("conversationId".into(), cid.to_owned())],
        )
        .await?;
    anyhow::ensure!(
        status == reqwest::StatusCode::OK,
        "getConversationState {status}: {}",
        String::from_utf8_lossy(&body)
    );
    let answer: Value = serde_json::from_slice(&body)?;
    let view = answer["pendingLeafRecoveryRequests"]
        .as_array()
        .into_iter()
        .flatten()
        .find(|view| view["requesterDid"] == joiner_did && view["status"] == "open")
        .context("the joiner's open leaf recovery")?;
    let state = &answer["state"];
    let prior = state["coordinates"].clone();
    let group_id = bytes(&prior["groupId"])?;
    let generation = prior["generation"].as_i64().context("generation")?;
    let snapshot = &state["metadataSnapshot"];
    let version = snapshot["metadataVersion"]
        .as_u64()
        .context("metadataVersion")?;
    let metadata_key = |epoch| -> anyhow::Result<[u8; 32]> {
        MlsCryptoContext::export_metadata_key(context, group_id.clone(), epoch)?
            .try_into()
            .map_err(|_| anyhow::anyhow!("metadata key length"))
    };
    let snapshot_epoch = snapshot["coordinate"]["epoch"]
        .as_u64()
        .context("snapshot epoch")?;
    let metadata = catbird_mls::metadata::decrypt_metadata_snapshot(
        &metadata_key(snapshot_epoch)?,
        &group_id,
        snapshot_epoch,
        version,
        &bytes(&snapshot["nonce"])?
            .try_into()
            .map_err(|_| anyhow::anyhow!("nonce length"))?,
        &bytes(&snapshot["ciphertext"])?,
    )?;

    let convo_uuid = STANDARD.encode(Uuid::parse_str(cid)?.as_bytes());
    let transition_id = Uuid::new_v4();
    let mut aad_prior = prior.clone();
    aad_prior["conversationId"] = serde_json::json!(convo_uuid);
    let aad = serde_json::json!({
        "conversationId": convo_uuid, "generation": generation, "protocolVersion": "1",
        "transitionId": STANDARD.encode(transition_id.as_bytes()), "prior": aad_prior,
    });
    let added = MlsCryptoContext::add_members_with_aad(
        context,
        group_id.clone(),
        vec![catbird_mls::KeyPackageData {
            data: bytes(&view["reservation"]["keyPackage"]["bytes"])?,
        }],
        Some(canonical_commit_aad_bytes(&aad)?),
    )?;
    let epoch = MlsCryptoContext::merge_pending_commit(context, group_id.clone())?;
    let tag = MlsCryptoContext::get_confirmation_tag(context, group_id.clone())?;
    let hash = MlsCryptoContext::get_group_context_hash(context, group_id.clone())?;
    let nonce: [u8; 12] = rand::random();
    let ciphertext = catbird_mls::metadata::encrypt_metadata_snapshot_with_nonce(
        &metadata_key(epoch)?,
        &group_id,
        epoch,
        version,
        &nonce,
        &metadata,
    )?;
    let next = serde_json::json!({
        "conversationId": cid, "groupId": {"$bytes": STANDARD.encode(&group_id)},
        "epoch": epoch, "generation": generation,
        "stateVersion": prior["stateVersion"].as_u64().context("stateVersion")? + 1,
        "groupContextHash": {"$bytes": STANDARD.encode(&hash)},
        "confirmationTag": {"$bytes": STANDARD.encode(&tag)}, "lifecycle": "active",
    });
    let mut metadata_snapshot = serde_json::json!({
        "coordinate": {
            "conversationId": convo_uuid, "generation": generation,
            "groupId": {"$bytes": STANDARD.encode(&group_id)}, "epoch": epoch,
            "groupContextHash": {"$bytes": STANDARD.encode(&hash)},
            "confirmationTag": {"$bytes": STANDARD.encode(&tag)},
        },
        "originTransitionId": snapshot["originTransitionId"],
        "metadataVersion": version,
        "nonce": {"$bytes": STANDARD.encode(nonce)},
        "ciphertext": {"$bytes": STANDARD.encode(&ciphertext)},
        "ciphertextSha256": STANDARD.encode(Sha256::digest(&ciphertext)),
        "ciphertextSize": ciphertext.len(),
        "authorProof": snapshot["authorProof"],
    });
    if let Some(binding) = snapshot.get("avatarBinding") {
        metadata_snapshot["avatarBinding"] = binding.clone();
    }
    let request_id = &view["recoveryRequestId"];
    let joiner_device = &view["requesterDeviceId"];
    let key_package_ref = STANDARD.encode(bytes(&view["reservation"]["keyPackageRef"])?);
    let welcome = &added.welcome_data;
    let public_key = MlsCryptoContext::identity_public_key(
        context,
        format!("{}#{device}", actor.did).into_bytes(),
    )?;
    let body = serde_json::json!({
        "$type": "blue.catbird.chat.defs#leafRecoveryFulfillmentBody",
        "signatureDomain": "CATBIRD-CHAT-LEAF-RECOVERY-FULFILL\0",
        "transitionId": transition_id.to_string(), "recoveryRequestId": request_id,
        "actorDid": actor.did, "actorDeviceId": device,
        "keyId": derive_key_id(&public_key), "authGeneration": auth_generation,
        "prior": prior, "next": next, "aad": aad,
        "manifest": {
            "participantChanges": [],
            "leafChanges": [{
                "$type": "blue.catbird.chat.defs#addLeafByRecovery", "userDid": joiner_did,
                "deviceId": joiner_device, "recoveryRequestId": request_id,
                "keyPackageRef": {"$bytes": key_package_ref},
            }],
            "leafRecoveryRequestId": request_id,
            "welcomeBundle": {
                "welcomeId": Uuid::new_v4().to_string(), "framing": "mlsMessage",
                "contentType": "welcome", "opaqueWelcome": {"$bytes": STANDARD.encode(welcome)},
                "sha256": STANDARD.encode(Sha256::digest(welcome)),
                "deliveries": [{
                    "recipientDid": joiner_did, "recipientDeviceId": joiner_device,
                    "provenance": {"recoveryRequestId": request_id, "keyPackageRef": key_package_ref},
                }],
            },
        },
        "commit": {
            "framing": "mlsMessage", "contentType": "publicMessageCommit",
            "bytes": {"$bytes": STANDARD.encode(&added.commit_data)},
            "sha256": STANDARD.encode(Sha256::digest(&added.commit_data)),
        },
        "metadataSnapshot": metadata_snapshot,
        "idempotencyKey": transition_id.to_string(),
        "signedAt": catbird_mls::client::chat_wire::now_rfc3339_millis(),
    });
    let prepared = orchestrator
        .prepare_clean_chat_signed_request(
            CleanChatSigningContext {
                actor_did: actor.did.clone(),
                device_id: device.clone(),
                auth_generation: Some(auth_generation),
            },
            CanonicalOperation::SubmitTransition,
            serde_json::to_vec(&body)?,
        )
        .await?;
    let response = orchestrator
        .api_client()
        .submit_prepared_request(prepared)
        .await?;
    anyhow::ensure!(
        response.status == 200,
        "fulfilment submitTransition {}: {}",
        response.status,
        String::from_utf8_lossy(&response.body)
    );
    // Land the accepted transition as the orchestrator lands its own:
    // projection from the merged tree and the cached view at the new epoch.
    let gid = hex::encode(&group_id);
    let mut projection = orchestrator
        .storage()
        .get_group_state(&gid)
        .await?
        .context("group projection")?;
    projection.epoch = epoch;
    projection.members = MlsCryptoContext::group_member_identities(context, group_id.clone())?
        .into_iter()
        .map(String::from_utf8)
        .collect::<Result<_, _>>()?;
    orchestrator.storage().set_group_state(&projection).await?;
    orchestrator
        .group_states()
        .lock()
        .await
        .insert(gid, projection);
    if let Some(conversation) = orchestrator.conversations().lock().await.get_mut(cid) {
        conversation.epoch = epoch;
    }
    Ok(serde_json::from_slice(&response.body)?)
}
