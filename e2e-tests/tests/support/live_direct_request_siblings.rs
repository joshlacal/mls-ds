//! Actual C06: account consent precedes both independent recipient imports.
use super::*;

pub struct RecipientSibling {
    pub service: ServiceIdentity,
    pub engine: MlsEngine,
    pub identity: String,
    pub package_ref: Vec<u8>,
}

pub async fn enroll(
    account: &ServiceIdentity,
    client: &reqwest::Client,
    server: &str,
) -> anyhow::Result<RecipientSibling> {
    // Enrollment is the same explicit database fixture boundary as C01. Each
    // device has its own DPoP enrollment JWK; account service JWTs use the same
    // PDS authority. Native signing keys and encrypted stores are independent.
    let enrollment = ServiceIdentity::new(account.did.clone());
    let mut service = account.clone();
    service.device_id = enrollment.device_id;
    let identity = format!("{}#{}", service.did, service.device_id);
    let engine = MlsEngine::new("c06-bob-sibling")?;
    let (package, package_ref) = engine.create_key_package(&identity)?;
    let public = engine.identity_public_key(&identity)?;
    seed_service_device(&enrollment, &public)?;
    let key_id = URL_SAFE_NO_PAD.encode(Sha256::digest(&public));
    let grant_id = Uuid::new_v4();
    let grant = signed_mls_request(
        &engine,
        &identity,
        DirectRequestKind::Grant,
        json!({
            "$type":"blue.catbird.chat.defs#directRequestGrantBody",
            "signatureDomain":"CATBIRD-DIRECT-REQUEST-GRANT\0","protocolVersion":"2",
            "actorDid":service.did,"actorDeviceId":service.device_id.to_string(),
            "keyId":key_id,"authGeneration":1,"grantId":grant_id.to_string(),"grantRevision":1,
            "purpose":"direct-request-bootstrap","profile":"encryptedIntroduction1",
            "keyPackageRef":STANDARD.encode(&package_ref),
            "keyPackageSha256":STANDARD.encode(Sha256::digest(&package)),
            "expiresAt":canonical_future(29),"idempotencyKey":grant_id.to_string(),"signedAt":canonical_now()
        }),
    )?;
    let keys = signed_mls_request(
        &engine,
        &identity,
        DirectRequestKind::Keys,
        json!({
            "$type":"blue.catbird.chat.defs#directRequestKeysPublicationBody",
            "signatureDomain":"CATBIRD-DIRECT-REQUEST-KEYS\0","protocolVersion":"2",
            "actorDid":service.did,"actorDeviceId":service.device_id.to_string(),
            "keyId":key_id,"authGeneration":1,"revision":1,"enabled":true,
            "keys":[{"keyPackage":{"framing":"mlsMessage","contentType":"keyPackage",
                "bytes":STANDARD.encode(&package),"sha256":STANDARD.encode(Sha256::digest(&package)),
                "keyPackageRef":STANDARD.encode(&package_ref)},"grant":grant}],
            "idempotencyKey":Uuid::new_v4().to_string(),"signedAt":canonical_now()
        }),
    )?;
    let (status, bytes) = service
        .post(
            client,
            server,
            "blue.catbird.chat.publishDirectRequestKeys",
            &json!({"signedRequest":keys}),
            true,
        )
        .await?;
    anyhow::ensure!(
        status == reqwest::StatusCode::OK,
        "sibling signed key publication failed {status}: {}",
        String::from_utf8_lossy(&bytes)
    );
    Ok(RecipientSibling {
        service,
        engine,
        identity,
        package_ref,
    })
}

fn bytes(value: &Value) -> anyhow::Result<Vec<u8>> {
    Ok(STANDARD.decode(
        value
            .as_str()
            .or_else(|| value["$bytes"].as_str())
            .context("read byte field")?,
    )?)
}

async fn retained_welcome(
    f: &PublishedRequestFixture,
    device: &ServiceIdentity,
    expected_ref: &[u8],
) -> anyhow::Result<Vec<u8>> {
    let (status, raw) = device
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
        status == reqwest::StatusCode::OK,
        "sibling inventory failed {status}: {}",
        String::from_utf8_lossy(&raw)
    );
    let inventory: Value = serde_json::from_slice(&raw)?;
    let (status, raw) = device
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
        status == reqwest::StatusCode::OK,
        "accepted retained Welcome failed {status}: {}",
        String::from_utf8_lossy(&raw)
    );
    let page: Value = serde_json::from_slice(&raw)?;
    let items = page["items"].as_array().context("retained Welcome items")?;
    assert_eq!(items.len(), 1);
    let welcome = &items[0];
    assert_eq!(
        welcome["$type"],
        "blue.catbird.chat.defs#directRequestWelcomeView"
    );
    assert_eq!(welcome["welcomeId"], f.request_id.to_string());
    assert_eq!(
        bytes(&welcome["provenance"]["keyPackageRef"])?,
        expected_ref
    );
    assert_eq!(
        bytes(&welcome["provenance"]["contextHash"])?,
        f.welcome_input.bootstrap.context_hash
    );
    let (status, raw) = device
        .get(
            &f.client,
            &f.server.base_url,
            "blue.catbird.chat.getConversationState",
            &[("conversationId".into(), f.conversation_id.to_string())],
        )
        .await?;
    anyhow::ensure!(
        status == reqwest::StatusCode::OK,
        "accepted sibling state failed {status}: {}",
        String::from_utf8_lossy(&raw)
    );
    let state: Value = serde_json::from_slice(&raw)?;
    assert_eq!(state["state"]["directRequest"]["consent"], "accepted");
    let accepting_identity = format!("{}#{}", f.bob.did, f.bob.device_id);
    let proof = protocol::verify_direct_request_acceptance_proof(
        &serde_json::to_vec(&state["state"]["directRequest"]["acceptanceProof"])?,
        &f.server.receipt_public_key,
        &f.bob_engine.identity_public_key(&accepting_identity)?,
    )?;
    assert_eq!(
        proof["receipt"]["body"]["requestId"],
        f.request_id.to_string()
    );
    bytes(&welcome["opaqueWelcome"])
}

pub async fn accept_before_both_recipient_imports() -> anyhow::Result<()> {
    let (mut f, sibling) = publish_request_variant(false, true).await?;
    let sibling = sibling.context("second selected recipient device")?;
    assert_ne!(f.bob.device_id, sibling.service.device_id);
    let bob_identity = format!("{}#{}", f.bob.did, f.bob.device_id);
    assert_ne!(
        f.bob_engine.identity_public_key(&bob_identity)?,
        sibling.engine.identity_public_key(&sibling.identity)?
    );
    let coordinates = f.welcome_input.bootstrap.coordinates.clone();
    let group = bytes(&coordinates["groupId"])?;
    let epoch = coordinates["epoch"].as_u64().context("epoch")?;
    assert!(f.bob_engine.epoch(&group).is_err());
    assert!(sibling.engine.epoch(&group).is_err());
    // Drop the sender's live native context before consent and both imports.
    let sender = f.alice_engine.take().context("sender engine")?;
    sender.confirm_request_publication(
        &f.request_id.to_string(),
        &serde_json::to_vec(&f.receipt)?,
        &f.server.receipt_public_key,
    )?;
    let offline_sender = sender.close_for_offline()?;
    let before = graph(f.conversation_id)?;
    accept_existing_fixture(&f).await?;
    assert!(f.bob_engine.epoch(&group).is_err());
    assert!(sibling.engine.epoch(&group).is_err());
    let accepted = graph(f.conversation_id)?;
    assert_eq!(accepted["epoch"], before["epoch"]);
    assert_eq!(accepted["generation"], before["generation"]);
    assert_eq!(
        accepted["transitions"].as_u64(),
        before["transitions"].as_u64().map(|n| n + 1)
    );
    let own_welcome = retained_welcome(&f, &f.bob, &f.welcome_input.local_package_ref).await?;
    let sibling_welcome = retained_welcome(&f, &sibling.service, &sibling.package_ref).await?;
    assert_eq!(
        own_welcome, sibling_welcome,
        "both devices must receive one identical full Welcome"
    );
    assert_eq!(own_welcome, f.welcome_input.bootstrap.welcome);
    let mut sibling_input = f.welcome_input.clone();
    sibling_input.local_identity = sibling.identity.as_bytes().to_vec();
    sibling_input.local_package_ref = sibling.package_ref;
    for (engine, input) in [
        (&f.bob_engine, &f.welcome_input),
        (&sibling.engine, &sibling_input),
    ] {
        engine.process_direct_request(input)?;
        assert_eq!(engine.epoch(&group)?, epoch);
        let preview = engine.decrypt_direct_request(input)?;
        let DirectRequestIntroductionResult::Ready { plaintext } = &preview else {
            anyhow::bail!("recipient introduction unavailable after account acceptance");
        };
        assert_eq!(
            protocol::decode_direct_request_introduction(plaintext)?["text"],
            "Real encrypted first contact"
        );
        assert_eq!(engine.decrypt_direct_request(input)?, preview);
        assert_eq!(
            graph(f.conversation_id)?,
            accepted,
            "recipient import must not add a server transition"
        );
    }
    let sender = offline_sender.reopen()?;
    assert_eq!(sender.epoch(&group)?, epoch);
    let snapshot = request_database_snapshot(f.request_id)?;
    assert_eq!(snapshot.message_rows, 1);
    assert_eq!(snapshot.welcome_rows, 2);
    Ok(())
}
