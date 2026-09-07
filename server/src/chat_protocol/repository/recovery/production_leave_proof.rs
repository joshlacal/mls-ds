// Non-shipping proof through the real signed-operation admission and leave
// facade, including PostgreSQL's deferred recovery/package constraints.

use super::production_proof_fixture::{
    admit_lifecycle, coordinate_json, leaf_recovery_request,
    seed_durable_recovery_fixture_with_pending, sign_canonical_wrapper, FixtureIdentity,
};
use super::*;
use serde_json::json;

pub(super) async fn run_leafless_lifecycle_with_open_recovery(
    pool: &PgPool,
    direct: bool,
    acceptance: bool,
) -> Result<(), String> {
    require_local_owned_gate(pool).await?;
    let creator = FixtureIdentity::fresh(b"leave-terminal-creator")?;
    let departing = if acceptance {
        let did = std::env::var("CHAT_LEAVE_PROOF_ACCEPTING_DID")
            .map_err(|_| "set CHAT_LEAVE_PROOF_ACCEPTING_DID to an opted-in test account for read-only consent verification".to_owned())?;
        FixtureIdentity::fresh_for_did(&did, b"acceptance-terminal-leafless")?
    } else {
        FixtureIdentity::fresh(b"leave-terminal-leafless")?
    };
    // The reviewed local schema may be installed without a runtime fence yet.
    // Seed only its absent singleton, as the existing route fixtures do.
    let cursor_key: String = sqlx::query_scalar("SELECT chat.ed25519_key_id($1)")
        .bind(creator.signing_public_key().to_vec())
        .fetch_one(pool)
        .await
        .map_err(|e| e.to_string())?;
    sqlx::query("INSERT INTO chat.protocol_instances(singleton,protocol_version,protocol_instance_id,cursor_key_id) VALUES(TRUE,'1',$1,$2) ON CONFLICT DO NOTHING")
        .bind(Uuid::new_v4()).bind(cursor_key).execute(pool).await.map_err(|e| e.to_string())?;
    sqlx::query("INSERT INTO chat.event_retention(protocol_instance_id,retained_floor,updated_at) SELECT protocol_instance_id,0,clock_timestamp() FROM chat.protocol_instances WHERE singleton ON CONFLICT DO NOTHING")
        .execute(pool).await.map_err(|e| e.to_string())?;
    mint_two_party_recovery_fallbacks(pool, &creator.did, &departing.did).await?;
    let trusted = TrustedRequestInstant::capture().map_err(|e| format!("clock: {e:?}"))?;
    let fixture = seed_durable_recovery_fixture_with_pending(
        pool,
        &trusted,
        creator,
        Some(&departing),
        direct,
    )
    .await?;

    // Open genuine reserved work for the other participant. The departing
    // device has no leaf; changing the coordinate must still release ALL prior
    // reservations, rather than just requests owned by the departing account.
    let request = leaf_recovery_request(
        &fixture.identity,
        Uuid::new_v4(),
        coordinate_json(&fixture.prior),
        trusted.as_str(),
    )?;
    let admission = admit_lifecycle(
        pool,
        &fixture.identity,
        "blue.catbird.chat.requestLeafRecovery",
        &request,
        &trusted,
    )
    .await?;
    let relationship = crate::chat_protocol::relationship_policy::ProductionRelationshipAuthority::from_startup_guard(
        crate::chat_protocol::repository::relationship::load_fixed_relationship_authority_startup_guard()
            .map_err(|e| format!("relationship authority: {e:?}"))?,
    );
    let mut tx = pool.begin().await.map_err(|e| e.to_string())?;
    let prepared =
        crate::chat_protocol::repository::prelude::prepare_signed_operation(&mut tx, admission)
            .await
            .map_err(|e| format!("prepare recovery: {e:?}"))?;
    let opened = execute_prepared_recovery(&mut tx, prepared, &relationship)
        .await
        .map_err(|e| format!("open recovery: {e:?}"))?;
    if opened.status() != 200 {
        return Err("recovery did not return HTTP 200".into());
    }
    tx.commit()
        .await
        .map_err(|e| format!("commit recovery: {e}"))?;
    let prior_status: (String, String, String) = sqlx::query_as(
        "SELECT r.status,k.status,p.status FROM chat.leaf_recovery_requests r \
         JOIN chat.key_package_reservations k USING(recovery_request_id) \
         JOIN chat.key_packages p ON p.key_package_ref=k.key_package_ref \
         WHERE r.recovery_request_id=$1",
    )
    .bind(request.operation_id)
    .fetch_one(pool)
    .await
    .map_err(|e| e.to_string())?;
    if prior_status != ("open".into(), "active".into(), "reserved".into()) {
        return Err(format!(
            "fixture did not commit open reserved work: {prior_status:?}"
        ));
    }

    let trusted = TrustedRequestInstant::capture().map_err(|e| format!("clock: {e:?}"))?;
    let operation_id = Uuid::new_v4();
    let mut next = coordinate_json(&fixture.prior);
    next["stateVersion"] = json!(fixture.prior.state_version() + 1);
    if direct {
        next["lifecycle"] = json!("superseded");
    }
    let (endpoint, kind, domain, body_type) = if acceptance {
        (
            "blue.catbird.chat.acceptConversation",
            SignedMutationKind::ParticipantAcceptance,
            "CATBIRD-CHAT-ACCEPT\0",
            "blue.catbird.chat.defs#participantAcceptanceBody",
        )
    } else if direct {
        (
            "blue.catbird.chat.closeConversation",
            SignedMutationKind::ConversationClose,
            "CATBIRD-CHAT-CLOSE\0",
            "blue.catbird.chat.defs#conversationCloseBody",
        )
    } else {
        (
            "blue.catbird.chat.requestLeave",
            SignedMutationKind::ZeroLeafLeave,
            "CATBIRD-CHAT-LEAVE-ZERO-LEAF\0",
            "blue.catbird.chat.defs#zeroLeafLeaveBody",
        )
    };
    let mut body = json!({
        "$type": body_type, "signatureDomain": domain,
        "transitionId": operation_id.to_string(), "actorDid": &departing.did,
        "actorDeviceId": departing.device_id.to_string(), "keyId": &departing.key_id,
        "authGeneration": 1, "prior": coordinate_json(&fixture.prior),
        "idempotencyKey": operation_id.to_string(), "signedAt": trusted.as_str(),
    });
    if direct {
        body["conversationKind"] = json!("direct");
        body["retired"] = next;
    } else {
        body["next"] = next;
    }
    let accepting_recovery_id = Uuid::new_v4();
    if acceptance {
        body["recoveryRequestId"] = json!(accepting_recovery_id.to_string());
        body["invitationProvenance"] = json!({
            "invitationTransitionId": fixture.creation_transition_id.to_string(),
            "invitedByDid": &fixture.identity.did,
            "invitedByDeviceId": fixture.identity.device_id.to_string(),
        });
    }
    let envelope = sign_canonical_wrapper(&departing, body, kind)?;
    let admission = admit_lifecycle(pool, &departing, endpoint, &envelope, &trusted).await?;
    let mut tx = pool.begin().await.map_err(|e| e.to_string())?;
    let prepared =
        crate::chat_protocol::repository::prelude::prepare_signed_operation(&mut tx, admission)
            .await
            .map_err(|e| format!("prepare lifecycle: {e:?}"))?;
    let response_bytes = if acceptance {
        let result = crate::chat_protocol::repository::acceptance::execute_prepared_acceptance(
            &mut tx,
            prepared,
            &relationship,
        )
        .await
        .map_err(|e| format!("accept with reserved recovery: {e:?}"))?;
        if result.status() != 200 {
            return Err(format!("accept status {}", result.status()));
        }
        let response: Value =
            serde_json::from_slice(result.response_bytes()).map_err(|e| e.to_string())?;
        if response["entry"]["conversationId"] != json!(fixture.conversation_id.to_string()) {
            return Err(format!("unexpected acceptance response: {response}"));
        }
        result.response_bytes().to_vec()
    } else {
        let result =
            crate::chat_protocol::repository::leave::execute_prepared_leave(&mut tx, prepared)
                .await
                .map_err(|e| format!("execute {endpoint} with reserved recovery: {e:?}"))?;
        if result.status != 200 {
            return Err(format!("{endpoint} status {}", result.status));
        }
        let response: Value =
            serde_json::from_slice(&result.response_bytes).map_err(|e| e.to_string())?;
        if response["result"]["entry"]["conversationId"]
            != json!(fixture.conversation_id.to_string())
        {
            return Err(format!("unexpected lifecycle response: {response}"));
        }
        let completion = result
            .completion
            .ok_or_else(|| "missing lifecycle completion".to_owned())?;
        let (authority, scope, guard) = completion.into_parts();
        crate::chat_protocol::repository::prelude::complete_operation(
            &mut tx,
            &authority,
            scope,
            guard,
            result.status,
            &result.response_bytes,
            result.event_position,
        )
        .await
        .map_err(|e| format!("complete lifecycle: {e:?}"))?;
        result.response_bytes
    };
    tx.commit()
        .await
        .map_err(|e| format!("commit lifecycle including deferred constraints: {e}"))?;

    let statuses: (String, String, String, Option<Uuid>) = sqlx::query_as(
        "SELECT r.status,k.status,p.status,r.terminal_transition_id \
         FROM chat.leaf_recovery_requests r \
         JOIN chat.key_package_reservations k USING(recovery_request_id) \
         JOIN chat.key_packages p ON p.key_package_ref=k.key_package_ref \
         WHERE r.recovery_request_id=$1",
    )
    .bind(request.operation_id)
    .fetch_one(pool)
    .await
    .map_err(|e| e.to_string())?;
    if statuses
        != (
            "superseded".into(),
            "released".into(),
            "available".into(),
            Some(operation_id),
        )
    {
        return Err(format!("incorrect recovery terminal state: {statuses:?}"));
    }
    let (lifecycle, version): (String, i64) = sqlx::query_as(
        "SELECT lifecycle,current_state_version FROM chat.conversations WHERE conversation_id=$1",
    )
    .bind(fixture.conversation_id)
    .fetch_one(pool)
    .await
    .map_err(|e| e.to_string())?;
    if lifecycle != if direct { "superseded" } else { "active" } || version != 1 {
        return Err(format!(
            "incorrect conversation terminal state: {lifecycle}/{version}"
        ));
    }
    if !direct && !acceptance {
        let member: bool = sqlx::query_scalar(
            "SELECT EXISTS(SELECT 1 FROM chat.participants WHERE conversation_id=$1 AND user_did=$2 AND current_membership)"
        ).bind(fixture.conversation_id).bind(&departing.did).fetch_one(pool).await.map_err(|e| e.to_string())?;
        if member {
            return Err("zero-leaf departing participant remains current".into());
        }
    }
    if acceptance {
        let added: (String, String, String, i64) = sqlx::query_as(
            "SELECT participant.status,request.status,reservation.status,request.bound_state_version FROM chat.participants participant JOIN chat.leaf_recovery_requests request ON request.conversation_id=participant.conversation_id AND request.requester_did=participant.user_did JOIN chat.key_package_reservations reservation USING(recovery_request_id) WHERE request.recovery_request_id=$1 AND participant.current_membership"
        ).bind(accepting_recovery_id).fetch_one(pool).await.map_err(|e| e.to_string())?;
        if added != ("active".into(), "open".into(), "active".into(), 1) {
            return Err(format!("acceptance successor recovery invalid: {added:?}"));
        }
    }
    let stored: Vec<u8> = sqlx::query_scalar(
        "SELECT response_bytes FROM chat.idempotency_records WHERE operation_id=$1",
    )
    .bind(operation_id)
    .fetch_one(pool)
    .await
    .map_err(|e| e.to_string())?;
    if stored != response_bytes {
        return Err("completion response bytes differ".into());
    }
    if direct {
        assert_exact_terminal_entry_read(pool, &fixture.identity, &departing,
            fixture.conversation_id, operation_id).await?;
    }
    Ok(())
}

async fn assert_exact_terminal_entry_read(
    pool: &PgPool,
    recipient: &FixtureIdentity,
    signer: &FixtureIdentity,
    conversation_id: Uuid,
    terminal_id: Uuid,
) -> Result<(), String> {
    use super::production_proof_fixture::{admit_entry_read, seed_identity};
    use crate::chat_protocol::repository::entry_read::{get_entries_for_admission, EntryReadFacadeError};
    let trusted = TrustedRequestInstant::capture().map_err(|e| format!("clock: {e:?}"))?;
    let admission = admit_entry_read(pool, recipient, &trusted).await?;
    let read = get_entries_for_admission(pool, admission, conversation_id, 0, 100).await
        .map_err(|e| format!("offline terminal recipient read: {e:?}"))?;
    let body: Value = serde_json::from_slice(&read.into_response_bytes()).map_err(|e| e.to_string())?;
    let entries = body["entries"].as_array().ok_or("missing terminal entries")?;
    let entry = entries.iter().find(|entry| entry["signedRequest"]["body"]["transitionId"] == terminal_id.to_string())
        .ok_or_else(|| format!("terminal signed entry {terminal_id} absent from {} entries", entries.len()))?;
    crate::chat_protocol::transcript::decode_and_verify_control_entry(
        &serde_json::to_vec(entry).map_err(|e|e.to_string())?, &signer.signing_public_key())
        .map_err(|e|format!("terminal read lost valid signed control: {e:?}"))?;
    let terminal_seq = entry["seq"].as_u64().ok_or("missing terminal seq")?;
    let start_seq:i64=sqlx::query_scalar("SELECT start_seq FROM chat.application_intervals WHERE conversation_id=$1 AND recipient_did=$2 AND recipient_device_id=$3 ORDER BY start_seq DESC LIMIT 1")
        .bind(conversation_id).bind(&recipient.did).bind(recipient.device_id).fetch_one(pool).await.map_err(|e|e.to_string())?;
    if entries.iter().any(|entry|entry["seq"].as_u64().is_none_or(|seq|seq < start_seq as u64)) {
        return Err("terminal control read leaked pre-admission controls".into());
    }

    if entries.iter().any(|entry| entry["$type"] == "blue.catbird.chat.defs#applicationEntry"
        || entry["seq"].as_u64().is_none_or(|seq| seq > terminal_seq)) {
        return Err("terminal control read escaped its type/sequence scope".into());
    }
    let admission = admit_entry_read(pool, recipient, &trusted).await?;
    let after = get_entries_for_admission(pool, admission, conversation_id, terminal_seq, 100).await
        .map_err(|e|format!("terminal tail read: {e:?}"))?;
    let after: Value=serde_json::from_slice(&after.into_response_bytes()).map_err(|e|e.to_string())?;
    if after["entries"].as_array().is_none_or(|entries|!entries.is_empty()) { return Err("terminal tail leaked entries".into()); }
    let state_admission=super::production_proof_fixture::admit_read(pool,recipient,"blue.catbird.chat.getConversationState",&trusted).await?;
    if !matches!(crate::chat_protocol::repository::conversation::read_conversation_state_for_admission(pool,state_admission,conversation_id).await,
        Err(crate::chat_protocol::repository::conversation::ConversationStateReadError::AccessOutsideMembershipInterval)) {
        return Err("terminal control permission leaked current-state authority".into());
    }
    let sibling=FixtureIdentity::fresh_for_did(&recipient.did,b"terminal-read-wrong-sibling")?;
    seed_identity(pool,&sibling,&trusted).await?;
    let admission=admit_entry_read(pool,&sibling,&trusted).await?;
    if !matches!(get_entries_for_admission(pool,admission,conversation_id,0,100).await,
        Err(EntryReadFacadeError::NotEntitled)) {
        return Err("same-DID unadmitted sibling inherited terminal read authority".into());
    }
    // A previously sealed read does not survive revocation of its exact key.
    let admission=admit_entry_read(pool,recipient,&trusted).await?;
    sqlx::query("UPDATE chat.device_keys SET revoked_at=clock_timestamp() WHERE user_did=$1 AND device_id=$2")
        .bind(&recipient.did).bind(recipient.device_id).execute(pool).await.map_err(|e|format!("revoke terminal read key: {e}"))?;
    if !matches!(get_entries_for_admission(pool,admission,conversation_id,0,100).await,
        Err(EntryReadFacadeError::DeviceRevoked)) {
        return Err("terminal capability survived exact key revocation".into());
    }
    Ok(())
}

pub(super) async fn run_removed_device_terminal_entry_read(pool: &PgPool) -> Result<(), String> {
    use super::production_proof_fixture::seed_durable_recovery_fulfillment_fixture_for_identities;
    require_local_owned_gate(pool).await?;
    let creator=FixtureIdentity::fresh(b"terminal-read-admin")?;
    let removed=FixtureIdentity::fresh(b"terminal-read-removed")?;
    mint_two_party_recovery_fallbacks(pool,&creator.did,&removed.did).await?;
    let trusted=TrustedRequestInstant::capture().map_err(|e|format!("clock: {e:?}"))?;
    let transition=Uuid::new_v4();
    let fixture=seed_durable_recovery_fulfillment_fixture_for_identities(pool,&trusted,creator,removed,transition).await?;
    let creator=&fixture.requester;
    let removed=&fixture.fulfiller;
    let prior=coordinate_json(&fixture.prior);
    let next=coordinate_json(fixture.removal_next.coordinate());
    let mut aad_prior=prior.clone();
    aad_prior["conversationId"]=json!(STANDARD.encode(fixture.conversation_id.as_bytes()));
    let cipher=vec![0x45u8;16];
    let mut metadata_coordinate=next.clone();
    metadata_coordinate.as_object_mut().unwrap().remove("stateVersion");
    metadata_coordinate.as_object_mut().unwrap().remove("lifecycle");
    metadata_coordinate["conversationId"]=json!(STANDARD.encode(fixture.conversation_id.as_bytes()));
    let body=json!({"$type":"blue.catbird.chat.defs#commitTransitionBody","signatureDomain":"CATBIRD-CHAT-COMMIT\0",
        "transitionId":transition.to_string(),"idempotencyKey":transition.to_string(),
        "actorDid":creator.did,"actorDeviceId":creator.device_id.to_string(),"keyId":creator.key_id,"authGeneration":1,
        "prior":prior,"next":next,"signedAt":trusted.as_str(),
        "aad":{"conversationId":STANDARD.encode(fixture.conversation_id.as_bytes()),"generation":0,"protocolVersion":"1","transitionId":STANDARD.encode(transition.as_bytes()),"prior":aad_prior},
        "manifest":{"participantChanges":[],"leafChanges":[{"$type":"blue.catbird.chat.defs#removeLeaf","userDid":removed.did,"deviceId":removed.device_id.to_string()}]},
        "commit":{"framing":"mlsMessage","contentType":"publicMessageCommit","bytes":STANDARD.encode(&fixture.removal_commit),"sha256":STANDARD.encode(Sha256::digest(&fixture.removal_commit))},
        "metadataSnapshot":{"coordinate":metadata_coordinate,"originTransitionId":fixture.creation_transition_id.to_string(),"metadataVersion":1,"nonce":STANDARD.encode([0x44u8;12]),"ciphertext":STANDARD.encode(&cipher),"ciphertextSha256":STANDARD.encode(Sha256::digest(&cipher)),"ciphertextSize":cipher.len(),
            "authorProof":{"authorDid":creator.did,"authorDeviceId":creator.device_id.to_string(),"authorKeyId":creator.key_id,"signaturePublicKey":STANDARD.encode(creator.signing_public_key()),"authGenerationAtOrigin":1,"originTransitionId":fixture.creation_transition_id.to_string(),"originSeq":1,"roleAtOrigin":"admin","deviceStatusAtOrigin":"active"}}
    });
    // Actual signed send while the target is an open leaf: the retained row
    // is genuinely inside its prior application interval before removal.
    let message_id=Uuid::new_v4();
    let app_body=json!({"$type":"blue.catbird.chat.defs#applicationSendBody","signatureDomain":"CATBIRD-CHAT-MESSAGE\0",
        "messageId":message_id.to_string(),"actorDid":creator.did,"actorDeviceId":creator.device_id.to_string(),"keyId":creator.key_id,"authGeneration":1,
        "prior":prior,"signedAt":trusted.as_str(),"blobBindings":[],
        "aad":{"conversationId":STANDARD.encode(fixture.conversation_id.as_bytes()),"generation":0,"protocolVersion":"1","messageId":STANDARD.encode(message_id.as_bytes()),"prior":aad_prior},
        "applicationMessage":{"framing":"mlsMessage","contentType":"privateMessageApplication","bytes":STANDARD.encode(&fixture.application_message),"sha256":STANDARD.encode(Sha256::digest(&fixture.application_message))}});
    let app=sign_canonical_wrapper(creator,app_body,SignedMutationKind::ApplicationSend)?;
    let app_admission=admit_lifecycle(pool,creator,"blue.catbird.chat.sendMessage",&app,&trusted).await?;
    let relationship=crate::chat_protocol::relationship_policy::ProductionRelationshipAuthority::from_startup_guard(
        crate::chat_protocol::repository::relationship::load_fixed_relationship_authority_startup_guard().map_err(|e|format!("relationship authority: {e:?}"))?);
    let mut app_tx=pool.begin().await.map_err(|e|e.to_string())?;
    let app_prepared=crate::chat_protocol::repository::prelude::prepare_chat_admission(&mut app_tx,app_admission).await.map_err(|e|format!("prepare application: {e:?}"))?;
    let crate::chat_protocol::repository::prelude::PreparedChatAdmission::First(first)=app_prepared else {return Err("fresh application unexpectedly replayed".into())};
    let (authority,scope,completion)=first.into_execution_parts();
    let (app_response,event)=crate::chat_protocol::repository::message_delivery::send(&mut app_tx,&authority,&scope,&relationship).await.map_err(|e|format!("actual signed application send: {e:?}"))?;
    crate::chat_protocol::repository::prelude::complete_operation(&mut app_tx,&authority,scope,completion,200,&app_response,event).await.map_err(|e|format!("complete application: {e:?}"))?;
    app_tx.commit().await.map_err(|e|format!("commit application: {e}"))?;
    let open_read=super::production_proof_fixture::admit_entry_read(pool,removed,&trusted).await?;
    let open_rows=crate::chat_protocol::repository::entry_read::get_entries_for_admission(pool,open_read,fixture.conversation_id,0,100).await.map_err(|e|format!("current leaf read: {e:?}"))?;
    let open_rows:Value=serde_json::from_slice(&open_rows.into_response_bytes()).map_err(|e|e.to_string())?;
    if !open_rows["entries"].as_array().unwrap().iter().any(|entry|entry["$type"]=="blue.catbird.chat.defs#applicationEntry") {return Err("fixture application was not readable while device remained admitted".into())}
    let envelope=sign_canonical_wrapper(creator,body,SignedMutationKind::CommitTransition)?;
    let admission=admit_lifecycle(pool,creator,"blue.catbird.chat.submitTransition",&envelope,&trusted).await?;
    let mut tx=pool.begin().await.map_err(|e|e.to_string())?;
    let prepared=crate::chat_protocol::repository::prelude::prepare_signed_operation(&mut tx,admission).await.map_err(|e|format!("prepare Remove: {e:?}"))?;
    let relationship=crate::chat_protocol::relationship_policy::ProductionRelationshipAuthority::from_startup_guard(
        crate::chat_protocol::repository::relationship::load_fixed_relationship_authority_startup_guard().map_err(|e|format!("relationship authority: {e:?}"))?);
    let outcome=crate::chat_protocol::repository::submit_transition::execute_prepared_submit_transition(&mut tx,prepared,&relationship).await.map_err(|e|format!("execute real signed Remove: {e:?}"))?;
    if outcome.status()!=200 { return Err(format!("Remove status {}",outcome.status())); }
    tx.commit().await.map_err(|e|format!("commit signed Remove: {e}"))?;
    // A later genuine policy control is not part of the removed leaf's MLS
    // catch-up interval, even if a separate exact control recipient row exists.
    let policy_id=Uuid::new_v4();
    let mut policy_next=next.clone();policy_next["stateVersion"]=json!(4);
    let policy_body=json!({"$type":"blue.catbird.chat.defs#policyTransitionBody","signatureDomain":"CATBIRD-CHAT-POLICY\0",
        "transitionId":policy_id.to_string(),"idempotencyKey":policy_id.to_string(),"actorDid":creator.did,"actorDeviceId":creator.device_id.to_string(),"keyId":creator.key_id,"authGeneration":1,"signedAt":trusted.as_str(),"prior":next,"next":policy_next,
        "participantChanges":[{"$type":"blue.catbird.chat.defs#removeParticipant","userDid":removed.did}]});
    let policy=sign_canonical_wrapper(creator,policy_body,SignedMutationKind::PolicyTransition)?;
    let admission=admit_lifecycle(pool,creator,"blue.catbird.chat.submitTransition",&policy,&trusted).await?;
    let mut tx=pool.begin().await.map_err(|e|e.to_string())?;
    let prepared=crate::chat_protocol::repository::prelude::prepare_signed_operation(&mut tx,admission).await.map_err(|e|format!("prepare policy: {e:?}"))?;
    let outcome=crate::chat_protocol::repository::submit_transition::execute_prepared_submit_transition(&mut tx,prepared,&relationship).await.map_err(|e|format!("execute later signed policy: {e:?}"))?;
    if outcome.status()!=200 {return Err("later policy did not execute".into())}
    tx.commit().await.map_err(|e|format!("commit later policy: {e}"))?;
    sqlx::query("INSERT INTO chat.entry_recipients(conversation_id,seq,user_did,device_id,entitlement_kind) SELECT conversation_id,seq,$2,$3,'control' FROM chat.entries WHERE conversation_id=$1 AND transition_id=$4 ON CONFLICT DO NOTHING")
        .bind(fixture.conversation_id).bind(&removed.did).bind(removed.device_id).bind(policy_id).execute(pool).await.map_err(|e|format!("seed separate later control entitlement: {e}"))?;
    assert_exact_terminal_entry_read(pool,removed,creator,fixture.conversation_id,transition).await?;
    let row:(bool,String)=sqlx::query_as("SELECT md.active,ai.closing_kind FROM chat.member_devices md JOIN chat.application_intervals ai ON ai.conversation_id=md.conversation_id AND ai.recipient_did=md.user_did AND ai.recipient_device_id=md.device_id WHERE md.conversation_id=$1 AND md.user_did=$2 AND md.device_id=$3")
        .bind(fixture.conversation_id).bind(&removed.did).bind(removed.device_id).fetch_one(pool).await.map_err(|e|e.to_string())?;
    if row!=(false,"remove".into()) { return Err(format!("device not terminally removed: {row:?}")); }
    Ok(())
}
