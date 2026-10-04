// Non-shipping proofs over real cryptographic fixtures and the production
// discovery/lock routines. Candidate discovery never grants membership.
use super::production_proof_fixture::{
    admit_lifecycle, coordinate_json, seed_durable_recovery_fixture_with_pending,
    seed_durable_recovery_fulfillment_fixture_for_identities, seed_identity,
    sign_canonical_wrapper, FixtureIdentity,
};
use super::*;
use crate::chat_protocol::repository::{leave, prelude, reset, submit_transition};
use serde_json::json;

fn has(scope: &prelude::CanonicalLockScope, identity: &FixtureIdentity) -> bool {
    scope
        .devices()
        .iter()
        .any(|device| device.did() == identity.did && device.device_id() == identity.device_id)
}

pub(super) async fn run_control_prospective_scope_and_drift(pool: &PgPool) -> Result<(), String> {
    require_local_owned_gate(pool).await?;
    let at = TrustedRequestInstant::capture().map_err(|e| format!("clock: {e:?}"))?;
    let owner = FixtureIdentity::fresh(b"control-scope-owner")?;
    let invited = FixtureIdentity::fresh(b"control-scope-invited")?;
    let sibling = FixtureIdentity::fresh_for_did(&invited.did, b"control-scope-sibling")?;
    let unrelated = FixtureIdentity::fresh(b"control-scope-unrelated")?;
    for identity in [&invited, &sibling, &unrelated] {
        seed_identity(pool, identity, &at).await?;
    }
    let fixture = seed_durable_recovery_fixture_with_pending(pool, &at, owner, None, false).await?;
    let mut tx = pool.begin().await.map_err(|e| e.to_string())?;
    let prospective = [invited.did.clone()];
    let first = submit_transition::discover_control_scope_for_proof(
        &mut tx,
        fixture.conversation_id,
        &fixture.identity.did,
        fixture.identity.device_id,
        &prospective,
    )
    .await?;
    if !has(&first, &invited)
        || !has(&first, &sibling)
        || has(&first, &unrelated)
        || first.devices().len() != 3
    {
        return Err(
            "pending-account addition did not include exactly owner plus all prospective devices"
                .into(),
        );
    }
    tx.rollback().await.map_err(|e| e.to_string())?;

    // A device appears after non-authoritative discovery, before the canonical
    // identity prefix is acquired. The actual held witness cannot bless it.
    let later = FixtureIdentity::fresh_for_did(&invited.did, b"control-scope-late-sibling")?;
    seed_identity(pool, &later, &at).await?;
    let mut tx = pool.begin().await.map_err(|e| e.to_string())?;
    let held = prelude::lock_conversation_event_scope(&mut tx, &first)
        .await
        .map_err(|e| format!("hold discovered prefix: {e:?}"))?;
    sqlx::query(
        "SELECT conversation_id FROM chat.conversations WHERE conversation_id=$1 FOR UPDATE",
    )
    .bind(fixture.conversation_id)
    .execute(&mut *tx)
    .await
    .map_err(|e| e.to_string())?;
    let after = submit_transition::discover_control_scope_for_proof(
        &mut tx,
        fixture.conversation_id,
        &fixture.identity.did,
        fixture.identity.device_id,
        &prospective,
    )
    .await?;
    let txid: String = sqlx::query_scalar("SELECT txid_current()::text")
        .fetch_one(&mut *tx)
        .await
        .map_err(|e| e.to_string())?;
    if !has(&after, &later)
        || first == after
        || !matches!(
            held.require_subset(&txid, &after),
            Err(prelude::PreludeError::ScopeDrift)
        )
    {
        return Err("new device drift escaped the real held-scope fence".into());
    }
    tx.rollback().await.map_err(|e| e.to_string())?;
    Ok(())
}

pub(super) async fn run_control_pending_welcome_scope(pool: &PgPool) -> Result<(), String> {
    require_local_owned_gate(pool).await?;
    let at = TrustedRequestInstant::capture().map_err(|e| format!("clock: {e:?}"))?;
    let creator = FixtureIdentity::fresh(b"control-welcome-creator")?;
    let recipient = FixtureIdentity::fresh(b"control-welcome-recipient")?;
    let fixture = seed_durable_recovery_fulfillment_fixture_for_identities(
        pool,
        &at,
        creator,
        recipient,
        Uuid::new_v4(),
    )
    .await?;
    // This is an actual native Add Welcome with committed package/request/
    // interval constraints, not an invented recipient row.
    let pending: Vec<(String, Uuid)> = sqlx::query_as("SELECT wd.recipient_did,wd.recipient_device_id FROM chat.welcome_bundles wb JOIN chat.welcome_deliveries wd USING(welcome_id) WHERE wb.conversation_id=$1 AND wd.status='pending'")
        .bind(fixture.conversation_id).fetch_all(pool).await.map_err(|e| e.to_string())?;
    if pending != vec![(fixture.fulfiller.did.clone(), fixture.fulfiller.device_id)] {
        return Err(format!(
            "genuine Add fixture lacks exact pending Welcome: {pending:?}"
        ));
    }
    let mut tx = pool.begin().await.map_err(|e| e.to_string())?;
    let reset_scope = reset::discover_control_scope_for_proof(
        &mut tx,
        fixture.conversation_id,
        &fixture.requester.did,
        fixture.requester.device_id,
    )
    .await?;
    let submit_scope = submit_transition::discover_control_scope_for_proof(
        &mut tx,
        fixture.conversation_id,
        &fixture.requester.did,
        fixture.requester.device_id,
        &[],
    )
    .await?;
    if reset_scope != submit_scope
        || !has(&reset_scope, &fixture.fulfiller)
        || reset_scope.devices().len() != 2
    {
        return Err("reset/submit discovery dropped genuine pending Welcome recipient".into());
    }
    tx.rollback().await.map_err(|e| e.to_string())?;
    let (welcome_id, expires_at): (Uuid, chrono::DateTime<chrono::Utc>) = sqlx::query_as(
        "SELECT wd.welcome_id,wd.expires_at FROM chat.welcome_bundles wb JOIN chat.welcome_deliveries wd USING(welcome_id) WHERE wb.conversation_id=$1 AND wd.status='pending'",
    ).bind(fixture.conversation_id).fetch_one(pool).await.map_err(|e| e.to_string())?;
    // Exercise the scheduler's exact-recipient lock-only witness through both
    // the no-op dueness gate and a real terminal write/deferred FK commit.
    use crate::chat_protocol::repository::expiry_sweep::{
        expire_due_welcome_delivery, WelcomeSweepOutcome,
    };
    let mut tx = pool.begin().await.map_err(|e| e.to_string())?;
    let outcome =
        expire_due_welcome_delivery(&mut tx, fixture.conversation_id, welcome_id, at.datetime())
            .await
            .map_err(|e| format!("early Welcome expiry: {e:?}"))?;
    if outcome != WelcomeSweepOutcome::NotDue {
        return Err(format!("early Welcome was terminalized: {outcome:?}"));
    }
    tx.rollback().await.map_err(|e| e.to_string())?;
    let mut tx = pool.begin().await.map_err(|e| e.to_string())?;
    let outcome =
        expire_due_welcome_delivery(&mut tx, fixture.conversation_id, welcome_id, expires_at)
            .await
            .map_err(|e| format!("due Welcome expiry: {e:?}"))?;
    if outcome != WelcomeSweepOutcome::Expired {
        return Err(format!("due Welcome was not expired: {outcome:?}"));
    }
    tx.commit()
        .await
        .map_err(|e| format!("commit Welcome expiry: {e}"))?;
    let terminal: (String, chrono::DateTime<chrono::Utc>) = sqlx::query_as(
        "SELECT status,terminal_at FROM chat.welcome_deliveries WHERE welcome_id=$1",
    )
    .bind(welcome_id)
    .fetch_one(pool)
    .await
    .map_err(|e| e.to_string())?;
    if terminal != ("expired".to_owned(), expires_at) {
        return Err(format!("Welcome terminal instant changed: {terminal:?}"));
    }
    Ok(())
}

pub(super) async fn run_control_close_historical_scope(pool: &PgPool) -> Result<(), String> {
    use super::production_proof_fixture::authorize;
    use base64::{engine::general_purpose::STANDARD, Engine as _};
    use sha2::{Digest, Sha256};
    require_local_owned_gate(pool).await?;
    let creator = FixtureIdentity::fresh(b"control-close-admin")?;
    let removed = FixtureIdentity::fresh(b"control-close-removed")?;
    let trusted = TrustedRequestInstant::capture().map_err(|e| format!("clock: {e:?}"))?;
    let transition = Uuid::new_v4();
    let fixture = seed_durable_recovery_fulfillment_fixture_for_identities(
        pool, &trusted, creator, removed, transition,
    )
    .await?;
    let creator = &fixture.requester;
    let removed = &fixture.fulfiller;
    let prior = coordinate_json(&fixture.prior);
    let next = coordinate_json(fixture.removal_next.coordinate());
    let mut aad_prior = prior.clone();
    aad_prior["conversationId"] = json!(STANDARD.encode(fixture.conversation_id.as_bytes()));
    let cipher = vec![0x45u8; 16];
    let mut metadata_coordinate = next.clone();
    metadata_coordinate
        .as_object_mut()
        .unwrap()
        .remove("stateVersion");
    metadata_coordinate
        .as_object_mut()
        .unwrap()
        .remove("lifecycle");
    metadata_coordinate["conversationId"] =
        json!(STANDARD.encode(fixture.conversation_id.as_bytes()));
    let body = json!({"$type":"blue.catbird.chat.defs#commitTransitionBody","signatureDomain":"CATBIRD-CHAT-COMMIT\0",
        "transitionId":transition.to_string(),"idempotencyKey":transition.to_string(),
        "actorDid":creator.did,"actorDeviceId":creator.device_id.to_string(),"keyId":creator.key_id,"authGeneration":1,
        "prior":prior,"next":next,"signedAt":trusted.as_str(),
        "aad":{"conversationId":STANDARD.encode(fixture.conversation_id.as_bytes()),"generation":0,"protocolVersion":"1","transitionId":STANDARD.encode(transition.as_bytes()),"prior":aad_prior},
        "manifest":{"participantChanges":[],"leafChanges":[{"$type":"blue.catbird.chat.defs#removeLeaf","userDid":removed.did,"deviceId":removed.device_id.to_string()}]},
        "commit":{"framing":"mlsMessage","contentType":"publicMessageCommit","bytes":STANDARD.encode(&fixture.removal_commit),"sha256":STANDARD.encode(Sha256::digest(&fixture.removal_commit))},
        "metadataSnapshot":{"coordinate":metadata_coordinate,"originTransitionId":fixture.creation_transition_id.to_string(),"metadataVersion":1,"nonce":STANDARD.encode([0x44u8;12]),"ciphertext":STANDARD.encode(&cipher),"ciphertextSha256":STANDARD.encode(Sha256::digest(&cipher)),"ciphertextSize":cipher.len(),
            "authorProof":{"authorDid":creator.did,"authorDeviceId":creator.device_id.to_string(),"authorKeyId":creator.key_id,"signaturePublicKey":STANDARD.encode(creator.signing_public_key()),"authGenerationAtOrigin":1,"originTransitionId":fixture.creation_transition_id.to_string(),"originSeq":1,"roleAtOrigin":"admin","deviceStatusAtOrigin":"active"}}
    });
    let envelope = sign_canonical_wrapper(creator, body, SignedMutationKind::CommitTransition)?;
    let admission = admit_lifecycle(
        pool,
        creator,
        "blue.catbird.chat.submitTransition",
        &envelope,
        &trusted,
    )
    .await?;
    let mut tx = pool.begin().await.map_err(|e| e.to_string())?;
    let prepared =
        crate::chat_protocol::repository::prelude::prepare_signed_operation(&mut tx, admission)
            .await
            .map_err(|e| format!("prepare Remove: {e:?}"))?;
    let relationship=crate::chat_protocol::relationship_policy::ProductionRelationshipAuthority::from_startup_guard(
        crate::chat_protocol::repository::relationship::load_fixed_relationship_authority_startup_guard().map_err(|e|format!("relationship authority: {e:?}"))?);
    let outcome =
        crate::chat_protocol::repository::submit_transition::execute_prepared_submit_transition(
            &mut tx,
            prepared,
            &relationship,
        )
        .await
        .map_err(|e| format!("execute real signed Remove: {e:?}"))?;
    if outcome.status() != 200 {
        return Err(format!("Remove status {}", outcome.status()));
    }
    tx.commit()
        .await
        .map_err(|e| format!("commit signed Remove: {e}"))?;
    // A later genuine policy control is not part of the removed leaf's MLS
    // catch-up interval, even if a separate exact control recipient row exists.
    let policy_id = Uuid::new_v4();
    let mut policy_next = next.clone();
    policy_next["stateVersion"] = json!(4);
    let policy_body = json!({"$type":"blue.catbird.chat.defs#policyTransitionBody","signatureDomain":"CATBIRD-CHAT-POLICY\0",
        "transitionId":policy_id.to_string(),"idempotencyKey":policy_id.to_string(),"actorDid":creator.did,"actorDeviceId":creator.device_id.to_string(),"keyId":creator.key_id,"authGeneration":1,"signedAt":trusted.as_str(),"prior":next,"next":policy_next,
        "participantChanges":[{"$type":"blue.catbird.chat.defs#removeParticipant","userDid":removed.did}]});
    let policy =
        sign_canonical_wrapper(creator, policy_body, SignedMutationKind::PolicyTransition)?;
    let admission = admit_lifecycle(
        pool,
        creator,
        "blue.catbird.chat.submitTransition",
        &policy,
        &trusted,
    )
    .await?;
    let mut tx = pool.begin().await.map_err(|e| e.to_string())?;
    let prepared =
        crate::chat_protocol::repository::prelude::prepare_signed_operation(&mut tx, admission)
            .await
            .map_err(|e| format!("prepare policy: {e:?}"))?;
    let outcome =
        crate::chat_protocol::repository::submit_transition::execute_prepared_submit_transition(
            &mut tx,
            prepared,
            &relationship,
        )
        .await
        .map_err(|e| format!("execute later signed policy: {e:?}"))?;
    if outcome.status() != 200 {
        return Err("later policy did not execute".into());
    }
    tx.commit()
        .await
        .map_err(|e| format!("commit later policy: {e}"))?;

    // The historical recipient has now left both the MLS tree and the account
    // roster through genuine signed operations. Ordinary reset/submit scope
    // must omit it, while Close must retain its exact historical schedule.
    let before: (i64,i64,i64) = sqlx::query_as("SELECT (SELECT count(*) FROM chat.participants WHERE conversation_id=$1 AND current_membership), (SELECT count(*) FROM chat.member_devices WHERE conversation_id=$1 AND active), (SELECT count(*) FROM chat.application_intervals WHERE conversation_id=$1 AND terminal_seq IS NOT NULL)")
        .bind(fixture.conversation_id).fetch_one(pool).await.map_err(|e|e.to_string())?;
    if before != (1, 1, 1) {
        return Err(format!(
            "real Remove and account removal prerequisites missing: {before:?}"
        ));
    }
    let scope_envelope = close_envelope(creator, &policy_next, "group", &trusted)?;
    let scope_authority = authorize(
        pool,
        creator,
        "blue.catbird.chat.closeConversation",
        &scope_envelope,
        &trusted,
    )
    .await?;
    let mut tx = pool.begin().await.map_err(|e| e.to_string())?;
    let close_scope =
        leave::discover_control_scope_for_proof(&mut tx, &scope_authority, fixture.conversation_id)
            .await?;
    let reset_scope = reset::discover_control_scope_for_proof(
        &mut tx,
        fixture.conversation_id,
        &creator.did,
        creator.device_id,
    )
    .await?;
    if !has(&close_scope, removed)
        || has(&reset_scope, removed)
        || close_scope.devices().len() != 2
        || reset_scope.devices().len() != 1
    {
        return Err(
            "Close historical discovery lost removed recipient or broadened ordinary reset scope"
                .into(),
        );
    }
    tx.rollback().await.map_err(|e| e.to_string())?;
    let envelope = close_envelope(creator, &policy_next, "group", &trusted)?;
    let admission = admit_lifecycle(
        pool,
        creator,
        "blue.catbird.chat.closeConversation",
        &envelope,
        &trusted,
    )
    .await?;
    let mut tx = pool.begin().await.map_err(|e| e.to_string())?;
    let prepared = prelude::prepare_signed_operation(&mut tx, admission)
        .await
        .map_err(|e| format!("prepare historical Close: {e:?}"))?;
    let result = leave::execute_prepared_leave(&mut tx, prepared)
        .await
        .map_err(|e| format!("execute historical Close: {e:?}"))?;
    let completion = result.completion.ok_or("Close completion absent")?;
    let (authority, scope, guard) = completion.into_parts();
    prelude::complete_operation(
        &mut tx,
        &authority,
        scope,
        guard,
        result.status,
        &result.response_bytes,
        result.event_position,
    )
    .await
    .map_err(|e| format!("complete historical Close: {e:?}"))?;
    tx.commit()
        .await
        .map_err(|e| format!("commit historical Close: {e}"))?;
    let terminal: (i64,i64,i64)=sqlx::query_as("SELECT (SELECT count(*) FROM chat.member_devices WHERE conversation_id=$1 AND active), (SELECT count(*) FROM chat.application_intervals WHERE conversation_id=$1 AND terminal_seq IS NOT NULL), (SELECT count(*) FROM chat.application_schedule_terminal_proofs WHERE conversation_id=$1)")
        .bind(fixture.conversation_id).fetch_one(pool).await.map_err(|e|e.to_string())?;
    if terminal != (0, 2, 2) {
        return Err(format!(
            "Close lost current or historical terminal evidence: {terminal:?}"
        ));
    }
    Ok(())
}

fn close_envelope(
    identity: &FixtureIdentity,
    prior: &serde_json::Value,
    conversation_kind: &str,
    at: &TrustedRequestInstant,
) -> Result<super::production_proof_fixture::SignedRecoveryEnvelope, String> {
    let id = Uuid::new_v4();
    let mut retired = prior.clone();
    retired["stateVersion"] = json!(
        prior["stateVersion"]
            .as_u64()
            .ok_or("prior version absent")?
            + 1
    );
    retired["lifecycle"] = json!("superseded");
    sign_canonical_wrapper(
        identity,
        json!({
            "$type":"blue.catbird.chat.defs#conversationCloseBody","signatureDomain":"CATBIRD-CHAT-CLOSE\0",
            "transitionId":id.to_string(),"actorDid":identity.did,"actorDeviceId":identity.device_id.to_string(),
            "keyId":identity.key_id,"authGeneration":1,"conversationKind":conversation_kind,"prior":prior,
            "retired":retired,"idempotencyKey":id.to_string(),"signedAt":at.as_str(),
        }),
        SignedMutationKind::ConversationClose,
    )
}
