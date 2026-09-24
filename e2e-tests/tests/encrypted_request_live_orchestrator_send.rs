//! F37: an ordinary send through the real `MLSOrchestrator` against the live
//! shipping router. The router echoes the accepted signed request with lexicon
//! `{"$bytes"}` byte fields while the client submitted some declared bytes as
//! bare base64 (the identifierBytes AAD fields). The send must succeed, keep
//! its submitted form, record its own-echo proof and read back through the
//! generated types and the canonical host entry mapping.
#![allow(dead_code)]

#[path = "support/encrypted_requests.rs"]
mod encrypted_requests;
#[path = "support/live_orchestrator.rs"]
mod live_orchestrator;
#[path = "../../../catbird-mls/tests/epoch_secret_test_support.rs"]
mod epoch_secret_test_support;

use anyhow::Context as _;
use catbird_mls::atproto::generated::blue_catbird::chat::{
    accept_conversation::AcceptConversationOutput, activate_reset::ActivateResetOutput,
    create_conversation::CreateConversationOutput, get_entries::GetEntriesOutput,
    get_subscription_ticket::GetSubscriptionTicketOutput, request_reset::RequestResetOutput,
    send_message::SendMessageOutput, submit_transition::SubmitTransitionOutput, ConversationEntry,
};
use catbird_mls::orchestrator::reset_flow::ResetOutcome;
use catbird_mls::orchestrator::MLSAPIClient;
use encrypted_requests::{
    connect_guarded_request_database, reviewed_request_migrations, seed_service_device,
    HttpsDidFixture, ServiceIdentity, ShippingServerFixture,
};
use live_orchestrator::mock_credentials::MockCredentials;
use mls_e2e_tests::mls_engine::MlsEngine;
use serde_json::Value;
use uuid::Uuid;

#[tokio::test(flavor = "multi_thread")]
async fn live_orchestrator_send_accepts_the_presented_echo_of_its_signed_request() -> anyhow::Result<()> {
    let authority = connect_guarded_request_database(5).await?;
    anyhow::ensure!(authority.additive_migrations == reviewed_request_migrations().len());
    let run = Uuid::new_v4().simple().to_string();
    let alice = ServiceIdentity::new(format!("did:web:f37-alice-{run}.request-fixture.catbird.blue"));
    let bob = ServiceIdentity::new(format!("did:web:f37-bob-{run}.request-fixture.catbird.blue"));
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
            let key_id = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(sha2::Sha256::digest(&key));
            let (status, body) = alice
                .get_device_key(&client, &base, &owner.did, owner.device_id, &key_id)
                .await?;
            anyhow::ensure!(status == reqwest::StatusCode::OK, "getDeviceKey {status}");
            let served: Value = serde_json::from_slice(&body)?;
            anyhow::Ok(base64::engine::general_purpose::STANDARD.decode(
                served["signaturePublicKey"]["$bytes"].as_str().context("signaturePublicKey")?,
            )?)
        }
    };
    let credentials = MockCredentials::new();
    credentials.set_authorized_device_keys(&alice.did, vec![directory_key(&alice, public.clone()).await?]);
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
        .add_members(&cid, &[bob.did.clone()])
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
    // Alice fulfils Bob's accepted-participant leaf recovery (real
    // recovery inbox read and signed submitTransition fulfilment).
    let fulfilled = orchestrator
        .fulfill_leaf_recovery(&cid)
        .await
        .context("live leaf recovery fulfilment")?;
    assert_eq!(
        fulfilled["entry"]["$type"],
        "blue.catbird.chat.defs#leafRecoveryFulfillmentEntry",
        "{fulfilled}"
    );
    // The success response carries Bob's pending Welcome view, presented.
    let welcomes = fulfilled["welcomes"].as_array().context("welcomes")?;
    assert_eq!(welcomes.len(), 1, "{fulfilled}");
    assert!(welcomes[0]["opaqueWelcome"]["$bytes"].is_string(), "{fulfilled}");

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
    println!("F37 live send accepted: conversation={cid} message={}", sent.id);
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
    anyhow::ensure!(status == reqwest::StatusCode::OK, "getEntries {status}: {}", String::from_utf8_lossy(&body));
    let raw: Value = serde_json::from_slice(&body)?;
    let application = raw["entries"]
        .as_array()
        .context("entries")?
        .iter()
        .find(|entry| entry["$type"] == "blue.catbird.chat.defs#applicationEntry")
        .context("application entry")?;
    let aad = &application["signedRequest"]["body"]["aad"];
    assert!(aad["conversationId"]["$bytes"].is_string(), "presented identifierBytes: {aad}");
    assert!(aad["messageId"]["$bytes"].is_string(), "presented identifierBytes: {aad}");
    let page: GetEntriesOutput = serde_json::from_slice(&body)
        .context("getEntries does not decode into generated types")?;
    assert!(page
        .entries
        .iter()
        .any(|entry| matches!(entry, ConversationEntry::ApplicationEntry(_))));

    // The canonical host entry mapping decodes the same presented page.
    let (envelopes, _) = live_orchestrator::LiveApiClient::for_test(&alice, &client, &server.base_url)
        .get_messages(&cid, None, 100, None, None, None)
        .await?;
    assert!(
        envelopes.iter().any(|envelope| !envelope.ciphertext.is_empty()),
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
        let (status, body) = responses.last().with_context(|| format!("no {nsid} exchange"))?;
        anyhow::ensure!(*status == 200, "{nsid} {status}: {}", String::from_utf8_lossy(body));
        serde_json::from_slice(body)
            .with_context(|| format!("{nsid} success body does not decode into generated types"))
    }
    let _: CreateConversationOutput = typed(api, "blue.catbird.chat.createConversation")?;
    let _: SubmitTransitionOutput = typed(api, "blue.catbird.chat.submitTransition")?;
    let _: SendMessageOutput = typed(api, "blue.catbird.chat.sendMessage")?;
    let _: RequestResetOutput = typed(api, "blue.catbird.chat.requestReset")?;
    let _: ActivateResetOutput = typed(api, "blue.catbird.chat.activateReset")?;
    let _: GetSubscriptionTicketOutput = typed(api, "blue.catbird.chat.getSubscriptionTicket")?;
    let _: AcceptConversationOutput =
        typed(bob_orchestrator.api_client(), "blue.catbird.chat.acceptConversation")?;
    println!("F37 live typed success: createConversation submitTransition sendMessage acceptConversation requestReset activateReset getSubscriptionTicket");

    orchestrator.shutdown().await;
    bob_orchestrator.shutdown().await;
    Ok(())
}
