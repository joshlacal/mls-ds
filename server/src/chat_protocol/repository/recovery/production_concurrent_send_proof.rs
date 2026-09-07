// Non-shipping regression through real signed admission, PostgreSQL row locks,
// application append, device-global event fanout and deferred chain triggers.
use super::production_proof_fixture::{admit_lifecycle,coordinate_json,seed_durable_recovery_fulfillment_fixture_for_identities,sign_canonical_wrapper,FixtureIdentity};
use super::*;
use serde_json::json;

pub(super) async fn run_concurrent_signed_sends(pool:&PgPool)->Result<(),String> {
    require_local_owned_gate(pool).await?;
    let first=FixtureIdentity::fresh(b"concurrent-send-first")?;
    let second=FixtureIdentity::fresh(b"concurrent-send-second")?;
    let cursor_key:String=sqlx::query_scalar("SELECT chat.ed25519_key_id($1)").bind(first.signing_public_key().to_vec()).fetch_one(pool).await.map_err(|e|e.to_string())?;
    sqlx::query("INSERT INTO chat.protocol_instances(singleton,protocol_version,protocol_instance_id,cursor_key_id) VALUES(TRUE,'1',$1,$2) ON CONFLICT DO NOTHING").bind(Uuid::new_v4()).bind(cursor_key).execute(pool).await.map_err(|e|e.to_string())?;
    mint_two_party_recovery_fallbacks(pool,&first.did,&second.did).await?;
    let trusted=TrustedRequestInstant::capture().map_err(|e|format!("clock: {e:?}"))?;
    let fixture=seed_durable_recovery_fulfillment_fixture_for_identities(pool,&trusted,first,second,Uuid::new_v4()).await?;
    let actors=[&fixture.requester,&fixture.fulfiller];
    let mut admissions=Vec::new();
    let mut message_ids=Vec::new();
    for actor in actors {
        let message=Uuid::new_v4();
        message_ids.push(message);
        let prior=coordinate_json(&fixture.prior);
        let mut aad_prior=prior.clone();
        aad_prior["conversationId"]=json!(STANDARD.encode(fixture.conversation_id.as_bytes()));
        let body=json!({"$type":"blue.catbird.chat.defs#applicationSendBody","signatureDomain":"CATBIRD-CHAT-MESSAGE\0","messageId":message.to_string(),"actorDid":actor.did,"actorDeviceId":actor.device_id.to_string(),"keyId":actor.key_id,"authGeneration":1,"prior":prior,"signedAt":trusted.as_str(),"blobBindings":[],"aad":{"conversationId":STANDARD.encode(fixture.conversation_id.as_bytes()),"generation":prior["generation"],"protocolVersion":"1","messageId":STANDARD.encode(message.as_bytes()),"prior":aad_prior},"applicationMessage":{"framing":"mlsMessage","contentType":"privateMessageApplication","bytes":STANDARD.encode(&fixture.application_message),"sha256":STANDARD.encode(Sha256::digest(&fixture.application_message))}});
        let envelope=sign_canonical_wrapper(actor,body,SignedMutationKind::ApplicationSend)?;
        admissions.push(admit_lifecycle(pool,actor,"blue.catbird.chat.sendMessage",&envelope,&trusted).await?);
    }
    let relationship=crate::chat_protocol::relationship_policy::ProductionRelationshipAuthority::from_startup_guard(crate::chat_protocol::repository::relationship::load_fixed_relationship_authority_startup_guard().map_err(|e|format!("relationship authority: {e:?}"))?);
    // Hold only the head while both independent send transactions reach their
    // first blocking lock. Old code lets both actor prefixes land before this
    // gate opens; correct code blocks the second at the shared identity prefix.
    let mut gate=pool.begin().await.map_err(|e|e.to_string())?;
    sqlx::query("SELECT 1 FROM chat.conversations WHERE conversation_id=$1 FOR UPDATE").bind(fixture.conversation_id).fetch_one(&mut *gate).await.map_err(|e|e.to_string())?;
    let (sender,mut receiver)=tokio::sync::mpsc::channel(2);
    let run=|admission,sender:tokio::sync::mpsc::Sender<i32>| {
        let relationship=&relationship;
        async move {
            let mut tx=pool.begin().await.map_err(|e|e.to_string())?;
            let pid:i32=sqlx::query_scalar("SELECT pg_backend_pid()").fetch_one(&mut *tx).await.map_err(|e|e.to_string())?;
            sender.send(pid).await.map_err(|e|e.to_string())?;
            let prepared=crate::chat_protocol::repository::prelude::prepare_chat_admission(&mut tx,admission).await.map_err(|e|format!("signed prelude: {e:?}"))?;
            let crate::chat_protocol::repository::prelude::PreparedChatAdmission::First(first)=prepared else {return Err("fresh send unexpectedly replayed".into())};
            let (authority,scope,completion)=first.into_execution_parts();
            let (bytes,event)=crate::chat_protocol::repository::message_delivery::send(&mut tx,&authority,&scope,relationship).await.map_err(|e|format!("signed concurrent send: {e:?}"))?;
            crate::chat_protocol::repository::prelude::complete_operation(&mut tx,&authority,scope,completion,200,&bytes,event).await.map_err(|e|format!("complete signed send: {e:?}"))?;
            tx.commit().await.map_err(|e|format!("commit signed send: {e}"))?;
            Ok::<_,String>(event.ok_or("missing event position")?)
        }
    };
    let release=async {
        let mut pids=Vec::new();
        for _ in 0..2 { pids.push(receiver.recv().await.ok_or("send connection was not reported")?); }
        let mut observed=false;
        for _ in 0..300 {
            let blocked:i64=sqlx::query_scalar("SELECT count(*) FROM pg_stat_activity WHERE pid=ANY($1::int[]) AND wait_event_type='Lock'").bind(&pids).fetch_one(pool).await.map_err(|e|e.to_string())?;
            if blocked==2 { observed=true;break; }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
        gate.rollback().await.map_err(|e|e.to_string())?;
        if !observed { return Err("both send transactions did not reach the deterministic lock gate".to_string()); }
        Ok::<_,String>(())
    };
    let second=admissions.pop().unwrap();let first=admissions.pop().unwrap();
    let (a,b,released)=tokio::time::timeout(std::time::Duration::from_secs(15),async {tokio::join!(run(first,sender.clone()),run(second,sender),release)}).await.map_err(|_|"concurrent sends did not finish within deadline")?;
    released?;
    let events=vec![a?,b?];
    if events[0]==events[1] {return Err("distinct messages shared an event position".into());}
    let seqs:Vec<i64>=sqlx::query_scalar("SELECT seq FROM chat.entries WHERE conversation_id=$1 AND message_id=ANY($2::uuid[]) ORDER BY seq").bind(fixture.conversation_id).bind(&message_ids).fetch_all(pool).await.map_err(|e|e.to_string())?;
    if seqs.len()!=2 || seqs[1]!=seqs[0]+1 {return Err(format!("accepted sequences were not exactly two contiguous entries: {seqs:?}"));}
    for actor in actors {
        let rows:Vec<(i64,Option<i64>)>=sqlx::query_as("SELECT event_position,audience_predecessor_position FROM chat.event_recipients WHERE user_did=$1 AND device_id=$2 ORDER BY event_position").bind(&actor.did).bind(actor.device_id).fetch_all(pool).await.map_err(|e|e.to_string())?;
        let mut tail=None;let mut delivered=0;
        for (position,previous) in rows {if previous!=tail {return Err("device-global event predecessor chain forked".into());}if events.contains(&position){delivered+=1;}tail=Some(position);}
        if delivered!=2 {return Err("recipient did not receive both message events".into());}
    }
    Ok(())
}

pub(super) async fn run_unlocked_send_audience_rejected(pool:&PgPool)->Result<(),String> {
    require_local_owned_gate(pool).await?;
    let first=FixtureIdentity::fresh(b"concurrent-send-first")?;
    let second=FixtureIdentity::fresh(b"concurrent-send-second")?;
    let cursor_key:String=sqlx::query_scalar("SELECT chat.ed25519_key_id($1)").bind(first.signing_public_key().to_vec()).fetch_one(pool).await.map_err(|e|e.to_string())?;
    sqlx::query("INSERT INTO chat.protocol_instances(singleton,protocol_version,protocol_instance_id,cursor_key_id) VALUES(TRUE,'1',$1,$2) ON CONFLICT DO NOTHING").bind(Uuid::new_v4()).bind(cursor_key).execute(pool).await.map_err(|e|e.to_string())?;
    mint_two_party_recovery_fallbacks(pool,&first.did,&second.did).await?;
    let trusted=TrustedRequestInstant::capture().map_err(|e|format!("clock: {e:?}"))?;
    let fixture=seed_durable_recovery_fulfillment_fixture_for_identities(pool,&trusted,first,second,Uuid::new_v4()).await?;
    let actors=[&fixture.requester,&fixture.fulfiller];
    let mut admissions=Vec::new();
    let mut message_ids=Vec::new();
    for actor in actors {
        let message=Uuid::new_v4();
        message_ids.push(message);
        let prior=coordinate_json(&fixture.prior);
        let mut aad_prior=prior.clone();
        aad_prior["conversationId"]=json!(STANDARD.encode(fixture.conversation_id.as_bytes()));
        let body=json!({"$type":"blue.catbird.chat.defs#applicationSendBody","signatureDomain":"CATBIRD-CHAT-MESSAGE\0","messageId":message.to_string(),"actorDid":actor.did,"actorDeviceId":actor.device_id.to_string(),"keyId":actor.key_id,"authGeneration":1,"prior":prior,"signedAt":trusted.as_str(),"blobBindings":[],"aad":{"conversationId":STANDARD.encode(fixture.conversation_id.as_bytes()),"generation":prior["generation"],"protocolVersion":"1","messageId":STANDARD.encode(message.as_bytes()),"prior":aad_prior},"applicationMessage":{"framing":"mlsMessage","contentType":"privateMessageApplication","bytes":STANDARD.encode(&fixture.application_message),"sha256":STANDARD.encode(Sha256::digest(&fixture.application_message))}});
        let envelope=sign_canonical_wrapper(actor,body,SignedMutationKind::ApplicationSend)?;
        admissions.push(admit_lifecycle(pool,actor,"blue.catbird.chat.sendMessage",&envelope,&trusted).await?);
    }
    let relationship=crate::chat_protocol::relationship_policy::ProductionRelationshipAuthority::from_startup_guard(crate::chat_protocol::repository::relationship::load_fixed_relationship_authority_startup_guard().map_err(|e|format!("relationship authority: {e:?}"))?);
    let admission=admissions.remove(0);
    let mut tx=pool.begin().await.map_err(|e|e.to_string())?;
    let prepared=crate::chat_protocol::repository::prelude::prepare_signed_operation(&mut tx,admission).await.map_err(|e|format!("prepare genuine signed scope-drift send: {e:?}"))?;
    let crate::chat_protocol::repository::prelude::PreparedSignedOperationState::First {authority,reservation}=prepared.into_state() else {return Err("fresh scope-drift send replayed".into())};
    // Simulate a previously discovered actor-only audience. This is still a
    // real signed request and sealed actor authority; it lacks the peer lock.
    let business=crate::chat_protocol::repository::prelude::prepare_actor_prelude(&mut tx,&authority,reservation).await.map_err(|e|format!("seal old actor-only scope: {e:?}"))?;
    let (scope,_completion)=business.into_execution_parts();
    let result=crate::chat_protocol::repository::message_delivery::send(&mut tx,&authority,&scope,&relationship).await;
    if !matches!(result,Err(crate::chat_protocol::repository::message_delivery::MessageDeliveryError::InvalidCoordinates)) {return Err(format!("unlocked peer audience was not rejected: {result:?}"));}
    let rows:i64=sqlx::query_scalar("SELECT count(*) FROM chat.entries WHERE conversation_id=$1 AND message_id=ANY($2::uuid[])").bind(fixture.conversation_id).bind(&message_ids).fetch_one(&mut *tx).await.map_err(|e|e.to_string())?;
    if rows!=0 {return Err("scope drift appended a message before rejection".into());}
    tx.rollback().await.map_err(|e|e.to_string())?;
    Ok(())
}
