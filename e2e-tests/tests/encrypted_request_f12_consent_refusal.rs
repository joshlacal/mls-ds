//! F12 consent refusal qualification (dedicated fault DB, real shipping router):
//! every signed ordinary mutation endpoint called while a direct request is
//! pending returns a typed HTTP 400 (never 500) and leaves the durable graph
//! byte-identical. Conversation-scoped endpoints return `ConversationNotAccepted`.
#![allow(dead_code, unused_imports)]

#[path = "support/encrypted_requests.rs"]
mod encrypted_requests;

use anyhow::Context as _;
use base64::{
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
    Engine as _,
};
use catbird_mls::{
    chat_v2::transcript::{
        decode_strict_json, direct_request::{self as protocol, DirectRequestKind},
        project_signed_body, SignedMutationKind, SigningTranscript,
    },
    metadata::GroupMetadataV1,
    orchestrator::direct_request_bootstrap::{
        metadata_coordinate, DirectRequestBootstrapInput, DirectRequestIntroductionResult,
        DirectRequestWelcomeInput,
    },
    orchestrator::{canonical_application_aad_bytes, MLSMessagePayload},
};
use encrypted_requests::{
    canonical_future, canonical_now, connect_guarded_request_database, request_database_snapshot,
    reviewed_request_migrations, route_to_dedicated_database, seed_service_device,
    signed_mls_request, validate_request_test_database_url, HttpsDidFixture,
    ServiceIdentity, ShippingServerFixture, REQUEST_TEST_DATABASE_URL, request_database_url,
};
use mls_e2e_tests::mls_engine::MlsEngine;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::process::Command;
use uuid::Uuid;

#[path = "support/live_direct_request.rs"]
mod live_direct_request;

const MAINTENANCE_URL: &str = "postgresql://127.0.0.1:5432/postgres";

fn maintenance(sql: &str) -> anyhow::Result<()> {
    let output = Command::new("psql")
        .args([MAINTENANCE_URL, "-X", "-q", "-v", "ON_ERROR_STOP=1", "-c", sql])
        .output()?;
    anyhow::ensure!(
        output.status.success(),
        "maintenance psql failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    Ok(())
}

struct DedicatedDatabase(String);
impl Drop for DedicatedDatabase {
    fn drop(&mut self) {
        let name = &self.0;
        let _ = maintenance(&format!(
            "SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE datname='{name}' AND pid<>pg_backend_pid()"
        ));
        let _ = maintenance(&format!("DROP DATABASE IF EXISTS {name}"));
    }
}

fn psql_cmd(sql: &str) -> anyhow::Result<String> {
    let output = Command::new("psql")
        .args([
            request_database_url(),
            "-X",
            "-A",
            "-t",
            "-q",
            "-v",
            "ON_ERROR_STOP=1",
            "-c",
            sql,
        ])
        .output()?;
    anyhow::ensure!(
        output.status.success(),
        "psql error: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    Ok(String::from_utf8(output.stdout)?.trim().to_owned())
}

fn durable_comprehensive(f: &live_direct_request::PublishedRequestFixture) -> anyhow::Result<String> {
    let (r, c, a, b) = (f.request_id, f.conversation_id, &f.alice.did, &f.bob.did);
    psql_cmd(&format!(
        r#"SELECT jsonb_build_object(
      'conversation',(SELECT to_jsonb(x) FROM chat.conversations x WHERE conversation_id='{c}'),
      'attempt',(SELECT to_jsonb(a) FROM chat.direct_request_attempts a WHERE request_id='{r}'),
      'publication',(SELECT to_jsonb(p) FROM chat.direct_request_publications p WHERE request_id='{r}'),
      'selected',(SELECT jsonb_agg(to_jsonb(s) ORDER BY owner_device_id) FROM chat.direct_request_selected_devices s WHERE request_id='{r}'),
      'deliveries',(SELECT jsonb_agg(to_jsonb(d) ORDER BY owner_device_id) FROM chat.direct_request_device_deliveries d WHERE request_id='{r}'),
      'welcomeOutcomes',(SELECT count(*) FROM chat.direct_request_welcome_outcomes WHERE request_id='{r}'),
      'participants',(SELECT jsonb_agg(to_jsonb(p) ORDER BY user_did) FROM chat.participants p WHERE conversation_id='{c}'),
      'entries',(SELECT jsonb_agg(to_jsonb(e) ORDER BY seq) FROM chat.entries e WHERE conversation_id='{c}'),
      'transitions',(SELECT jsonb_agg(to_jsonb(t) ORDER BY transition_id) FROM chat.transitions t WHERE conversation_id='{c}'),
      'blobs',(SELECT count(*) FROM chat.blobs WHERE owner_did IN ('{a}', '{b}')),
      'blobBindings',(SELECT count(*) FROM chat.blob_bindings WHERE conversation_id='{c}'),
      'resets',(SELECT count(*) FROM chat.reset_requests WHERE conversation_id='{c}'),
      'recoveries',(SELECT count(*) FROM chat.leaf_recovery_requests WHERE conversation_id='{c}')
    )::text"#
    ))
}

fn sign_mutation(
    engine: &MlsEngine,
    identity: &str,
    kind: SignedMutationKind,
    body: Value,
) -> anyhow::Result<Value> {
    let strict = decode_strict_json(&serde_json::to_vec(&body)?)?;
    let transcript = SigningTranscript::build_for(kind, &project_signed_body(kind, &strict)?)?;
    let signature = engine.sign_identity(identity, transcript.bytes().to_vec())?;
    Ok(json!({
        "body": body,
        "signature": STANDARD.encode(signature)
    }))
}

fn signed_ordinary(engine: &MlsEngine, identity: &str, body: Value) -> anyhow::Result<Value> {
    let type_id = body["$type"].as_str().context("body lacks $type")?;
    let kind = SignedMutationKind::from_type_id(type_id)
        .with_context(|| format!("unknown SignedMutationKind for {type_id}"))?;
    sign_mutation(engine, identity, kind, body)
}

#[tokio::test(flavor = "multi_thread")]
async fn f12_pending_direct_request_consent_refusal_returns_typed_400_and_no_writes() -> anyhow::Result<()> {
    // 1. Establish dedicated fault database
    let name = format!(
        "catbird_direct_requests_fault_{}",
        &Uuid::new_v4().simple().to_string()[..16]
    );
    maintenance(&format!("CREATE DATABASE {name}"))?;
    let _dedicated = DedicatedDatabase(name.clone());
    route_to_dedicated_database(&format!("postgresql://127.0.0.1:5432/{name}"))?;
    anyhow::ensure!(request_database_url().ends_with(&name));

    let authority = connect_guarded_request_database(5).await?;
    assert_eq!(
        authority.additive_migrations,
        reviewed_request_migrations().len()
    );

    // 2. Publish real encrypted direct request (pending consent state)
    let f = live_direct_request::publish_request(false).await?;
    let alice_identity = format!("{}#{}", f.alice.did, f.alice.device_id);
    let alice_engine = f.alice_engine.as_ref().context("alice engine")?;
    let alice_public = alice_engine.identity_public_key(&alice_identity)?;
    let alice_key_id = URL_SAFE_NO_PAD.encode(Sha256::digest(&alice_public));
    let prior = f.welcome_input.bootstrap.coordinates.clone();

    // 3. Capture baseline database state
    let before = durable_comprehensive(&f)?;

    // ========================================================================
    // 4. Test each of the 8 endpoints that previously returned HTTP 500
    // ========================================================================

    // 4.1 submitTransition (e.g. metadata transition while pending)
    let mut next_coord = prior.clone();
    next_coord["stateVersion"] = json!(prior["stateVersion"].as_u64().unwrap() + 1);
    let metadata_transition_id = Uuid::new_v4().to_string();
    let alice_metadata_trans = signed_ordinary(alice_engine, &alice_identity, json!({
        "$type": "blue.catbird.chat.defs#metadataTransitionBody",
        "signatureDomain": "CATBIRD-CHAT-METADATA\0",
        "transitionId": metadata_transition_id,
        "actorDid": f.alice.did,
        "actorDeviceId": f.alice.device_id.to_string(),
        "keyId": alice_key_id,
        "authGeneration": 1,
        "prior": prior,
        "next": next_coord,
        "metadataSnapshot": f.publication["body"]["artifacts"]["metadataSnapshot"],
        "idempotencyKey": metadata_transition_id,
        "signedAt": canonical_now()
    }))?;
    let (status, resp_bytes) = f.alice.post(
        &f.client,
        &f.server.base_url,
        "blue.catbird.chat.submitTransition",
        &json!({"signedRequest": alice_metadata_trans}),
        true,
    ).await?;
    assert_eq!(status, reqwest::StatusCode::BAD_REQUEST, "submitTransition must return 400 Bad Request, got {status}: {}", String::from_utf8_lossy(&resp_bytes));
    let resp: Value = serde_json::from_slice(&resp_bytes)?;
    assert_eq!(resp["error"], "ConversationNotAccepted", "submitTransition must return ConversationNotAccepted: {resp}");
    assert_eq!(durable_comprehensive(&f)?, before, "submitTransition must produce no write");

    // 4.2 requestReset
    let reset_id = Uuid::new_v4();
    let alice_reset = signed_ordinary(alice_engine, &alice_identity, json!({
        "$type": "blue.catbird.chat.defs#resetRequestBody",
        "signatureDomain": "CATBIRD-CHAT-RESET-REQUEST\0",
        "resetRequestId": reset_id.to_string(),
        "actorDid": f.alice.did,
        "actorDeviceId": f.alice.device_id.to_string(),
        "keyId": alice_key_id,
        "authGeneration": 1,
        "prior": prior,
        "reason": "manualRecovery",
        "idempotencyKey": reset_id.to_string(),
        "signedAt": canonical_now()
    }))?;
    let (status, resp_bytes) = f.alice.post(
        &f.client,
        &f.server.base_url,
        "blue.catbird.chat.requestReset",
        &json!({"signedRequest": alice_reset}),
        true,
    ).await?;
    assert_eq!(status, reqwest::StatusCode::BAD_REQUEST, "requestReset must return 400 Bad Request, got {status}: {}", String::from_utf8_lossy(&resp_bytes));
    let resp: Value = serde_json::from_slice(&resp_bytes)?;
    assert_eq!(resp["error"], "ConversationNotAccepted", "requestReset must return ConversationNotAccepted: {resp}");
    assert_eq!(durable_comprehensive(&f)?, before, "requestReset must produce no write");

    // 4.3 activateReset
    let act_id = Uuid::new_v4();
    let alice_act_reset = signed_ordinary(alice_engine, &alice_identity, json!({
        "$type": "blue.catbird.chat.defs#resetActivationBody",
        "signatureDomain": "CATBIRD-CHAT-RESET-ACTIVATE\0",
        "resetRequestId": reset_id.to_string(),
        "transitionId": act_id.to_string(),
        "conversationKind": "direct",
        "actorDid": f.alice.did,
        "actorDeviceId": f.alice.device_id.to_string(),
        "keyId": alice_key_id,
        "authGeneration": 1,
        "prior": prior,
        "retired": prior,
        "successor": prior,
        "manifest": {
            "participants": [
                {"userDid": f.alice.did, "role": "admin", "status": "active"},
                {"userDid": f.bob.did, "role": "member", "status": "pending"}
            ],
            "actorLeaf": {"userDid": f.alice.did, "deviceId": f.alice.device_id.to_string(), "leafOrigin": "genesis"}
        },
        "genesisGroupInfo": f.publication["body"]["artifacts"]["genesisGroupInfo"],
        "metadataSnapshot": f.publication["body"]["artifacts"]["metadataSnapshot"],
        "idempotencyKey": act_id.to_string(),
        "signedAt": canonical_now()
    }))?;
    let (status, resp_bytes) = f.alice.post(
        &f.client,
        &f.server.base_url,
        "blue.catbird.chat.activateReset",
        &json!({"signedRequest": alice_act_reset}),
        true,
    ).await?;
    assert_eq!(status, reqwest::StatusCode::BAD_REQUEST, "activateReset must return 400 Bad Request, got {status}: {}", String::from_utf8_lossy(&resp_bytes));
    let resp: Value = serde_json::from_slice(&resp_bytes)?;
    assert_eq!(resp["error"], "ConversationNotAccepted", "activateReset must return ConversationNotAccepted: {resp}");
    assert_eq!(durable_comprehensive(&f)?, before, "activateReset must produce no write");

    // 4.4 requestLeave
    let leave_id = Uuid::new_v4();
    let alice_leave = signed_ordinary(alice_engine, &alice_identity, json!({
        "$type": "blue.catbird.chat.defs#leaveRequestBody",
        "signatureDomain": "CATBIRD-CHAT-LEAVE-REQUEST\0",
        "leaveRequestId": leave_id.to_string(),
        "actorDid": f.alice.did,
        "actorDeviceId": f.alice.device_id.to_string(),
        "keyId": alice_key_id,
        "authGeneration": 1,
        "prior": prior,
        "idempotencyKey": leave_id.to_string(),
        "signedAt": canonical_now()
    }))?;
    let (status, resp_bytes) = f.alice.post(
        &f.client,
        &f.server.base_url,
        "blue.catbird.chat.requestLeave",
        &json!({"signedRequest": alice_leave}),
        true,
    ).await?;
    assert_eq!(status, reqwest::StatusCode::BAD_REQUEST, "requestLeave must return 400 Bad Request, got {status}: {}", String::from_utf8_lossy(&resp_bytes));
    let resp: Value = serde_json::from_slice(&resp_bytes)?;
    assert_eq!(resp["error"], "ConversationNotAccepted", "requestLeave must return ConversationNotAccepted: {resp}");
    assert_eq!(durable_comprehensive(&f)?, before, "requestLeave must produce no write");

    // 4.5 cancelLeave
    let cancel_leave_id = Uuid::new_v4();
    let alice_cancel_leave = signed_ordinary(alice_engine, &alice_identity, json!({
        "$type": "blue.catbird.chat.defs#leaveCancellationBody",
        "signatureDomain": "CATBIRD-CHAT-LEAVE-CANCEL\0",
        "actorDid": f.alice.did,
        "actorDeviceId": f.alice.device_id.to_string(),
        "keyId": alice_key_id,
        "authGeneration": 1,
        "conversationId": f.conversation_id.to_string(),
        "leaveRequestId": leave_id.to_string(),
        "idempotencyKey": cancel_leave_id.to_string(),
        "signedAt": canonical_now()
    }))?;
    let (status, resp_bytes) = f.alice.post(
        &f.client,
        &f.server.base_url,
        "blue.catbird.chat.cancelLeave",
        &json!({"signedRequest": alice_cancel_leave}),
        true,
    ).await?;
    assert_eq!(status, reqwest::StatusCode::BAD_REQUEST, "cancelLeave must return 400 Bad Request, got {status}: {}", String::from_utf8_lossy(&resp_bytes));
    let resp: Value = serde_json::from_slice(&resp_bytes)?;
    assert_eq!(resp["error"], "ConversationNotAccepted", "cancelLeave must return ConversationNotAccepted: {resp}");
    assert_eq!(durable_comprehensive(&f)?, before, "cancelLeave must produce no write");

    // 4.6 cancelLeafRecovery
    let cancel_recovery_id = Uuid::new_v4();
    let alice_cancel_rec = signed_ordinary(alice_engine, &alice_identity, json!({
        "$type": "blue.catbird.chat.defs#leafRecoveryCancellationBody",
        "signatureDomain": "CATBIRD-CHAT-LEAF-RECOVERY-CANCEL\0",
        "recoveryRequestId": Uuid::new_v4().to_string(),
        "actorDid": f.alice.did,
        "actorDeviceId": f.alice.device_id.to_string(),
        "keyId": alice_key_id,
        "authGeneration": 1,
        "idempotencyKey": cancel_recovery_id.to_string(),
        "signedAt": canonical_now()
    }))?;
    let (status, resp_bytes) = f.alice.post(
        &f.client,
        &f.server.base_url,
        "blue.catbird.chat.cancelLeafRecovery",
        &json!({"signedRequest": alice_cancel_rec}),
        true,
    ).await?;
    assert_eq!(status, reqwest::StatusCode::BAD_REQUEST, "cancelLeafRecovery must return 400 Bad Request, got {status}: {}", String::from_utf8_lossy(&resp_bytes));
    let resp: Value = serde_json::from_slice(&resp_bytes)?;
    // requestLeafRecovery is itself refused while pending, so no recovery row can
    // reference this conversation; the reachable outcome is the declared miss.
    // The pending-consent branch mapping is proven by the handler unit test.
    assert_eq!(resp["error"], "LeafRecoveryNotFound", "cancelLeafRecovery must return a typed code, never 500: {resp}");
    assert_eq!(durable_comprehensive(&f)?, before, "cancelLeafRecovery must produce no write");

    // 4.7 prepareBlobUpload
    let alice_blob_prep = signed_ordinary(alice_engine, &alice_identity, json!({
        "$type": "blue.catbird.chat.defs#blobUploadPreparationBody",
        "signatureDomain": "CATBIRD-CHAT-BLOB-PREPARE\0",
        "blobId": Uuid::new_v4().to_string(),
        "conversationId": f.conversation_id.to_string(),
        "actorDid": f.alice.did,
        "actorDeviceId": f.alice.device_id.to_string(),
        "keyId": alice_key_id,
        "authGeneration": 1,
        "prior": prior,
        "ciphertextSha256": STANDARD.encode(Sha256::digest(b"test-attachment-payload")),
        "ciphertextSize": 4096,
        "mediaType": "image/png",
        "plaintextSize": 1024,
        "purpose": "attachment",
        "idempotencyKey": Uuid::new_v4().to_string(),
        "signedAt": canonical_now()
    }))?;
    let (status, resp_bytes) = f.alice.post(
        &f.client,
        &f.server.base_url,
        "blue.catbird.chat.prepareBlobUpload",
        &json!({"signedRequest": alice_blob_prep}),
        true,
    ).await?;
    assert_eq!(status, reqwest::StatusCode::BAD_REQUEST, "prepareBlobUpload must return 400 Bad Request, got {status}: {}", String::from_utf8_lossy(&resp_bytes));
    let resp: Value = serde_json::from_slice(&resp_bytes)?;
    assert_eq!(resp["error"], "ConversationNotAccepted", "prepareBlobUpload must return ConversationNotAccepted: {resp}");
    assert_eq!(durable_comprehensive(&f)?, before, "prepareBlobUpload must produce no write");

    // 4.8 deleteBlob
    let alice_delete_blob = signed_ordinary(alice_engine, &alice_identity, json!({
        "$type": "blue.catbird.chat.defs#blobDeletionBody",
        "signatureDomain": "CATBIRD-CHAT-BLOB-DELETE\0",
        "blobId": Uuid::new_v4().to_string(),
        "actorDid": f.alice.did,
        "actorDeviceId": f.alice.device_id.to_string(),
        "keyId": alice_key_id,
        "authGeneration": 1,
        "idempotencyKey": Uuid::new_v4().to_string(),
        "signedAt": canonical_now()
    }))?;
    let (status, resp_bytes) = f.alice.post(
        &f.client,
        &f.server.base_url,
        "blue.catbird.chat.deleteBlob",
        &json!({"signedRequest": alice_delete_blob}),
        true,
    ).await?;
    assert_eq!(status, reqwest::StatusCode::BAD_REQUEST, "deleteBlob must return 400 Bad Request, got {status}: {}", String::from_utf8_lossy(&resp_bytes));
    let resp: Value = serde_json::from_slice(&resp_bytes)?;
    // Nothing can be bound into a pending conversation (send/prepare refused), so an
    // unbound/unknown blob has no conversation to gate. Before this fix the gate
    // queried the nonexistent chat.blobs.conversation_id column and every
    // deleteBlob returned HTTP 500.
    assert_eq!(resp["error"], "BlobNotFound", "deleteBlob must return a typed code, never 500: {resp}");
    assert_eq!(durable_comprehensive(&f)?, before, "deleteBlob must produce no write");

    // Final check: the whole refusal barrage leaves the durable graph byte-identical.
    assert_eq!(
        durable_comprehensive(&f)?,
        before,
        "all eight refusal cases must leave database state byte-identical"
    );

    Ok(())
}
