// Non-shipping signed-facade regression: retained recovery terminals must
// survive later reservation and consumption of the exact same KeyPackage.
use super::production_proof_fixture::{
    admit_lifecycle, coordinate_json, leaf_recovery_cancellation, leaf_recovery_fulfillment,
    leaf_recovery_request, seed_recovery_package_reuse_fixture, sign_canonical_wrapper,
    DurableRecoveryFulfillmentFixture, FixtureIdentity, SignedRecoveryEnvelope,
};
use super::*;
use crate::chat_protocol::snapshot::PublicGroupSnapshotCoordinate;
use crate::chat_protocol::transcript::SignedMutationKind;
use base64::{engine::general_purpose::STANDARD, Engine as _};
use serde_json::json;
use sha2::{Digest as _, Sha256};

async fn execute(
    pool: &PgPool,
    actor: &FixtureIdentity,
    endpoint: &str,
    signed: &SignedRecoveryEnvelope,
    trusted: &TrustedRequestInstant,
    relationship: &crate::chat_protocol::relationship_policy::ProductionRelationshipAuthority,
) -> Result<Vec<u8>, String> {
    let admission = admit_lifecycle(pool, actor, endpoint, signed, trusted).await?;
    let mut tx = pool.begin().await.map_err(|e| e.to_string())?;
    let prepared =
        crate::chat_protocol::repository::prelude::prepare_signed_operation(&mut tx, admission)
            .await
            .map_err(|e| format!("prepare {endpoint}: {e:?}"))?;
    let is_policy = serde_json::from_slice::<Value>(&signed.raw_wrapper)
        .map_err(|e| e.to_string())?["body"]["$type"]
        == "blue.catbird.chat.defs#policyTransitionBody";
    let (status, bytes) = if is_policy {
        let outcome =
        crate::chat_protocol::repository::submit_transition::execute_prepared_submit_transition(
            &mut tx, prepared, relationship,
        ).await.map_err(|e| format!("execute {endpoint}: {e:?}"))?;
        (outcome.status(), outcome.response_bytes().to_vec())
    } else {
        let outcome = execute_prepared_recovery(&mut tx, prepared, relationship)
            .await
            .map_err(|e| format!("execute {endpoint}: {e:?}"))?;
        (outcome.status(), outcome.response_bytes().to_vec())
    };
    if status != 200 {
        return Err(format!(
            "{endpoint} returned {status}: {}",
            String::from_utf8_lossy(&bytes)
        ));
    }
    tx.commit()
        .await
        .map_err(|e| format!("commit {endpoint}: {e}"))?;
    Ok(bytes)
}

// This is the complete production loader, including real OpenMLS persisted
// snapshot decoding, retained signed controls, recovery validation and Welcome
// assembly. A row-only loader would miss downstream state-machine invariants.
async fn hydrate(pool: &PgPool, cid: Uuid, stage: &str, version: u64) -> Result<(), String> {
    let trusted = TrustedRequestInstant::capture().map_err(|e| format!("clock: {e:?}"))?;
    let mut tx = pool.begin().await.map_err(|e| e.to_string())?;
    let guard = crate::chat_protocol::repository::core::hydrate_locked_conversation_state(
        &mut tx,
        cid,
        trusted.datetime(),
    )
    .await
    .map_err(|e| format!("complete aggregate after {stage}: {e:?}"))?;
    if guard.state().coordinate().state_version() != version
        || guard.state().active_public_state().is_none()
    {
        return Err(format!("wrong active aggregate after {stage}"));
    }
    tx.rollback().await.map_err(|e| e.to_string())
}

async fn package_state(
    pool: &PgPool,
    request: Uuid,
) -> Result<(String, String, String, Vec<u8>), String> {
    sqlx::query_as("SELECT r.status,k.status,p.status,k.key_package_ref FROM chat.leaf_recovery_requests r JOIN chat.key_package_reservations k USING(recovery_request_id) JOIN chat.key_packages p USING(key_package_ref) WHERE r.recovery_request_id=$1")
        .bind(request).fetch_one(pool).await.map_err(|e| e.to_string())
}

// Exact durable bytes and terminal references are retained, not reconstructed.
async fn terminal_proof(pool: &PgPool, request: Uuid) -> Result<Value, String> {
    sqlx::query_scalar("SELECT jsonb_build_object('request',to_jsonb(r),'reservation',to_jsonb(k)) FROM chat.leaf_recovery_requests r JOIN chat.key_package_reservations k USING(recovery_request_id) WHERE r.recovery_request_id=$1")
        .bind(request).fetch_one(pool).await.map_err(|e| e.to_string())
}

pub(super) async fn run_package_reuse(pool: &PgPool, after_policy: bool) -> Result<(), String> {
    require_local_owned_gate(pool).await?;
    let requester = FixtureIdentity::fresh(b"package-reuse-requester")?;
    let fulfiller = FixtureIdentity::fresh(b"package-reuse-fulfiller")?;
    mint_two_party_recovery_fallbacks(pool, &requester.did, &fulfiller.did).await?;
    let trusted = TrustedRequestInstant::capture().map_err(|e| format!("clock: {e:?}"))?;
    let fulfillment_id = Uuid::new_v4();
    let fixture = seed_recovery_package_reuse_fixture(
        pool,
        &trusted,
        requester,
        fulfiller,
        fulfillment_id,
        after_policy,
    )
    .await?;
    let relationship = crate::chat_protocol::relationship_policy::ProductionRelationshipAuthority::from_startup_guard(
        crate::chat_protocol::repository::relationship::load_fixed_relationship_authority_startup_guard()
            .map_err(|e| format!("relationship guard: {e:?}"))?,
    );
    hydrate(pool, fixture.conversation_id, "fixture creation", 2).await?;
    let original = leaf_recovery_request(
        &fixture.requester,
        Uuid::new_v4(),
        coordinate_json(&fixture.prior),
        trusted.as_str(),
    )?;
    execute(
        pool,
        &fixture.requester,
        "blue.catbird.chat.requestLeafRecovery",
        &original,
        &trusted,
        &relationship,
    )
    .await?;
    let (request_status, reservation_status, package_status, package_ref) =
        package_state(pool, original.operation_id).await?;
    if (
        request_status.as_str(),
        reservation_status.as_str(),
        package_status.as_str(),
    ) != ("open", "active", "reserved")
        || package_ref != fixture.requester_key_package_ref
    {
        return Err("initial request did not reserve the real replacement package".into());
    }
    let trusted = TrustedRequestInstant::capture().map_err(|e| format!("clock: {e:?}"))?;
    let mut prior = fixture.prior.clone();
    if after_policy {
        let id = Uuid::new_v4();
        let mut next = coordinate_json(&prior);
        next["stateVersion"] = json!(3);
        let body = json!({
            "$type": "blue.catbird.chat.defs#policyTransitionBody", "signatureDomain": "CATBIRD-CHAT-POLICY\0",
            "transitionId": id.to_string(), "idempotencyKey": id.to_string(), "actorDid": fixture.requester.did,
            "actorDeviceId": fixture.requester.device_id.to_string(), "keyId": fixture.requester.key_id,
            "authGeneration": 1, "signedAt": trusted.as_str(), "prior": coordinate_json(&prior), "next": next,
            "participantChanges": [{"$type":"blue.catbird.chat.defs#changeParticipantRole", "userDid":fixture.fulfiller.did, "role":"admin"}],
        });
        let policy = sign_canonical_wrapper(
            &fixture.requester,
            body,
            SignedMutationKind::PolicyTransition,
        )?;
        execute(
            pool,
            &fixture.requester,
            "blue.catbird.chat.submitTransition",
            &policy,
            &trusted,
            &relationship,
        )
        .await?;
        prior = PublicGroupSnapshotCoordinate::new(
            *prior.conversation_id(),
            prior.generation(),
            3,
            *prior.group_id(),
            prior.epoch(),
            *prior.group_context_hash(),
            *prior.confirmation_tag(),
            prior.lifecycle(),
        );
    } else {
        let cancellation = leaf_recovery_cancellation(
            &fixture.requester,
            original.operation_id,
            trusted.as_str(),
        )?;
        execute(
            pool,
            &fixture.requester,
            "blue.catbird.chat.cancelLeafRecovery",
            &cancellation,
            &trusted,
            &relationship,
        )
        .await?;
    }
    let terminal_status = if after_policy {
        "superseded"
    } else {
        "cancelled"
    };
    let state = package_state(pool, original.operation_id).await?;
    if (state.0.as_str(), state.1.as_str(), state.2.as_str())
        != (terminal_status, "released", "available")
    {
        return Err(format!("incorrect initial terminal: {state:?}"));
    }
    let exact_terminal = terminal_proof(pool, original.operation_id).await?;
    hydrate(
        pool,
        fixture.conversation_id,
        "original terminal",
        prior.state_version(),
    )
    .await?;
    let trusted = TrustedRequestInstant::capture().map_err(|e| format!("clock: {e:?}"))?;
    let renewed = leaf_recovery_request(
        &fixture.requester,
        Uuid::new_v4(),
        coordinate_json(&prior),
        trusted.as_str(),
    )?;
    execute(
        pool,
        &fixture.requester,
        "blue.catbird.chat.requestLeafRecovery",
        &renewed,
        &trusted,
        &relationship,
    )
    .await?;
    let state = package_state(pool, renewed.operation_id).await?;
    if (state.0.as_str(), state.1.as_str(), state.2.as_str()) != ("open", "active", "reserved")
        || state.3 != package_ref
    {
        return Err(format!(
            "renewal did not reserve the exact same package: {state:?}"
        ));
    }
    hydrate(
        pool,
        fixture.conversation_id,
        "same-package renewal",
        prior.state_version(),
    )
    .await?;
    if terminal_proof(pool, original.operation_id).await? != exact_terminal {
        return Err("renewal changed original signed terminal proof".into());
    }
    let trusted = TrustedRequestInstant::capture().map_err(|e| format!("clock: {e:?}"))?;
    let (body, welcome_id) = fulfillment_body(
        &fixture,
        &prior,
        renewed.operation_id,
        fulfillment_id,
        &trusted,
    );
    let fulfillment = leaf_recovery_fulfillment(&fixture.fulfiller, body)?;
    execute(
        pool,
        &fixture.fulfiller,
        "blue.catbird.chat.submitTransition",
        &fulfillment,
        &trusted,
        &relationship,
    )
    .await?;
    hydrate(
        pool,
        fixture.conversation_id,
        "same-package fulfillment",
        prior.state_version() + 1,
    )
    .await?;
    let state = package_state(pool, renewed.operation_id).await?;
    if (state.0.as_str(), state.1.as_str(), state.2.as_str())
        != ("fulfilled", "consumed", "consumed")
        || state.3 != package_ref
    {
        return Err(format!(
            "renewed request did not consume the same package: {state:?}"
        ));
    }
    if terminal_proof(pool, original.operation_id).await? != exact_terminal {
        return Err("fulfillment changed original signed terminal proof".into());
    }
    let exact: bool = sqlx::query_scalar("SELECT r.fulfilling_transition_id=$2 AND k.consumed_transition_id=$2 AND p.terminal_transition_id=$2 AND w.transition_id=$2 AND d.key_package_ref=k.key_package_ref AND d.recovery_request_id=r.recovery_request_id FROM chat.leaf_recovery_requests r JOIN chat.key_package_reservations k USING(recovery_request_id) JOIN chat.key_packages p USING(key_package_ref) JOIN chat.welcome_deliveries d ON d.recovery_request_id=r.recovery_request_id JOIN chat.welcome_bundles w USING(welcome_id) WHERE r.recovery_request_id=$1 AND w.welcome_id=$3")
        .bind(renewed.operation_id).bind(fulfillment_id).bind(welcome_id).fetch_one(pool).await.map_err(|e|e.to_string())?;
    if !exact {
        return Err("fulfillment/Welcome/package did not retain exact terminal binding".into());
    }
    Ok(())
}

fn fulfillment_body(
    fixture: &DurableRecoveryFulfillmentFixture,
    prior: &PublicGroupSnapshotCoordinate,
    request_id: Uuid,
    transition_id: Uuid,
    trusted: &TrustedRequestInstant,
) -> (Value, Uuid) {
    let requester = &fixture.requester;
    let welcome_id = Uuid::new_v4();
    let metadata_ciphertext = vec![0x64_u8; 16];
    let body = json!({
        "recoveryRequestId": request_id.hyphenated().to_string(),
        "transitionId": transition_id.hyphenated().to_string(),
        "prior": coordinate_json(&prior),
        "next": coordinate_json(fixture.next.coordinate()),
        "aad": {
            "protocolVersion": "1",
            "conversationId": STANDARD.encode(fixture.conversation_id.as_bytes()),
            "generation": prior.generation(),
            "transitionId": STANDARD.encode(transition_id.as_bytes()),
            "prior": {
                "conversationId": STANDARD.encode(fixture.conversation_id.as_bytes()),
                "generation": prior.generation(),
                "stateVersion": prior.state_version(),
                "groupId": STANDARD.encode(prior.group_id()),
                "epoch": prior.epoch(),
                "groupContextHash": STANDARD.encode(prior.group_context_hash()),
                "confirmationTag": STANDARD.encode(prior.confirmation_tag()),
                "lifecycle": "active",
            },
        },
        "manifest": {
            "participantChanges": [],
            "leafChanges": [
                {
                    "$type": "blue.catbird.chat.defs#removeLeaf",
                    "userDid": requester.did,
                    "deviceId": requester.device_id.hyphenated().to_string(),
                },
                {
                    "$type": "blue.catbird.chat.defs#addLeafByRecovery",
                    "userDid": requester.did,
                    "deviceId": requester.device_id.hyphenated().to_string(),
                    "recoveryRequestId": request_id.hyphenated().to_string(),
                    "keyPackageRef": STANDARD.encode(fixture.requester_key_package_ref),
                }
            ],
            "leafRecoveryRequestId": request_id.hyphenated().to_string(),
            "welcomeBundle": {
                "welcomeId": welcome_id.hyphenated().to_string(),
                "framing": "mlsMessage",
                "contentType": "welcome",
                "opaqueWelcome": STANDARD.encode(&fixture.welcome),
                "sha256": STANDARD.encode(Sha256::digest(&fixture.welcome)),
                "deliveries": [{
                    "recipientDid": requester.did,
                    "recipientDeviceId": requester.device_id.hyphenated().to_string(),
                    "provenance": {
                        "recoveryRequestId": request_id.hyphenated().to_string(),
                        "keyPackageRef": STANDARD.encode(fixture.requester_key_package_ref),
                    },
                }],
            },
        },
        "commit": {
            "framing": "mlsMessage",
            "contentType": "publicMessageCommit",
            "bytes": STANDARD.encode(&fixture.commit),
            "sha256": STANDARD.encode(Sha256::digest(&fixture.commit)),
        },
        "metadataSnapshot": {
            "coordinate": {
                "conversationId": STANDARD.encode(fixture.conversation_id.as_bytes()),
                "generation": fixture.next.coordinate().generation(),
                "groupId": STANDARD.encode(fixture.next.coordinate().group_id()),
                "epoch": fixture.next.coordinate().epoch(),
                "groupContextHash": STANDARD.encode(
                    fixture.next.coordinate().group_context_hash()
                ),
                "confirmationTag": STANDARD.encode(
                    fixture.next.coordinate().confirmation_tag()
                ),
            },
            "originTransitionId": fixture.creation_transition_id.hyphenated().to_string(),
            "metadataVersion": 1,
            "nonce": STANDARD.encode([0x63_u8; 12]),
            "ciphertext": STANDARD.encode(&metadata_ciphertext),
            "ciphertextSha256": STANDARD.encode(Sha256::digest(&metadata_ciphertext)),
            "ciphertextSize": metadata_ciphertext.len(),
            "authorProof": {
                "authorDid": requester.did,
                "authorDeviceId": requester.device_id.hyphenated().to_string(),
                "authorKeyId": requester.key_id,
                "signaturePublicKey": STANDARD.encode(requester.signing_public_key()),
                "authGenerationAtOrigin": 1,
                "originTransitionId": fixture.creation_transition_id.hyphenated().to_string(),
                "originSeq": 1,
                "roleAtOrigin": "admin",
                "deviceStatusAtOrigin": "active",
            },
        },
        "idempotencyKey": transition_id.hyphenated().to_string(),
        "signedAt": trusted.as_str(),
    });
    (body, welcome_id)
}
