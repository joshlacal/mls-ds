use super::*;
use crate::common::http_acceptance as http;

async fn member_device(s: &GroupStream, mls_seed: u8) -> (Uuid, String) {
    let device = Uuid::new_v4();
    let key = ed25519_dalek::SigningKey::from_bytes(&[mls_seed; 32]);
    let key_id = seed_actor_at(
        &s.home_pool,
        &s.recipient_did,
        device,
        &key.verifying_key().to_bytes(),
        clock_now(&s.home_pool).await,
    )
    .await;
    (device, key_id)
}

#[tokio::test]
async fn restored_leafless_device_reads_only_its_pending_fulfillment_on_its_home() {
    let s = GroupStream::new().await;
    let cid = s.cid;
    let admin = Actor::at_home(&s, ADMIN, 0x29).await;
    let member = s.recipient_did.as_str();
    let (target, target_key) = member_device(&s, 0x2a).await;
    let (sibling, sibling_key) = member_device(&s, 0x2b).await;
    s.network.declare_delivery_service(HOME);
    s.network.declare_user(member, HOME);
    s.network.declare_user(LATE, HOME);

    // This home has the member's original leaf in its clean graph. Its signed
    // membership index also records the account as active before the new device joins.
    sqlx::query(
        "INSERT INTO chat.remote_group_memberships(conversation_id,user_did,sequencer_did,status,\
         evidence_seq,evidence_entry_id,updated_at) VALUES($1,$2,$3,'active',2,$4,$5)",
    )
    .bind(cid)
    .bind(member)
    .bind(SEQ)
    .bind(Uuid::new_v4())
    .bind(current_utc())
    .execute(&s.home_pool)
    .await
    .unwrap();
    assert_eq!(s.standing(member).await, RemoteGroupStanding::CleanMember);
    let welcome = Uuid::new_v4();
    let fulfillment = fulfilment_entry(&admin, (member, target), cid, 5, welcome);
    scope_ds_clock(
        s.clock.clone(),
        scope_sim_ds(s.seq_hooks.clone(), async {
            let earlier = unsigned_entry(
                cid,
                4,
                "blue.catbird.chat.defs#metadataEntry",
                "blue.catbird.chat.defs#metadataTransitionBody",
            );
            s.send(s.queued(earlier, &[(member, target)]).await)
                .await
                .unwrap();
            s.send(s.queued(fulfillment.clone(), &[(member, target)]).await)
                .await
                .unwrap();
            let transition = Uuid::new_v4();
            let following = policy_entry(&admin, cid, 6, transition, invite(&admin, transition));
            s.send(s.queued(following, &[(member, target)]).await)
                .await
                .unwrap();
            let sibling_only = policy_entry(&admin, cid, 7, Uuid::new_v4(), remove(LATE));
            s.send(s.queued(sibling_only, &[(member, sibling)]).await)
                .await
                .unwrap();
        }),
    )
    .await;
    assert_eq!(s.granted(member, target).await, [4, 5, 6]);
    assert_eq!(s.welcome_markers(member, target).await, [(welcome, 5)]);

    let router = http::router_for_authenticated_acceptance(s.home_pool.clone()).await;
    let signing = http::random_p256();
    let jwk = http::public_jwk(&signing);
    let reader = |device_id| http::Device {
        did: member.to_owned(),
        device_id,
        signing: signing.clone(),
        jkt: http::jwk_thumbprint(&jwk),
        jwk: jwk.clone(),
    };
    http::cache_device_did(&reader(target)).await;
    let read = |id, after, limit| {
        let query =
            format!("conversationId={cid}&actorDeviceId={id}&afterSeq={after}&limit={limit}");
        http::send(
            router.clone(),
            http::unsigned_get_request(&reader(id), "blue.catbird.chat.getEntries", &query),
        )
    };
    let (status, page) = read(target, 4, 1).await;
    assert_eq!(status, StatusCode::OK, "{page}");
    assert_eq!(page["nextAfterSeq"], 5);
    assert_eq!(page["hasMore"], false);
    let entries = page["entries"].as_array().unwrap();
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0]["entryId"], fulfillment["entryId"]);
    let signature = &entries[0]["signedRequest"]["signature"];
    assert_eq!(
        signature.get("$bytes").unwrap_or(signature),
        &fulfillment["signedRequest"]["signature"]
    );
    for (id, after, limit) in [
        (target, 3, 1),
        (target, 3, 2),
        (target, 4, 2),
        (sibling, 4, 1),
    ] {
        let (status, error) = read(id, after, limit).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{error}");
        assert_eq!(error["error"], "NotEntitled");
    }
    forget_pending_welcomes(&s.home_pool, cid, member, target, &[welcome])
        .await
        .unwrap();
    let (_status, error) = read(target, 4, 1).await;
    assert_eq!(error["error"], "NotEntitled");

    // An ACK attested by the sequencer carries only the current leaf's opening and
    // head. Even when the same registered user has multiple leaves and this
    // device received an older grant, its page starts at this exact opening.
    use crate::chat_protocol::repository::entry_read::{
        granted_recovery_page, EntryReadFacadeError, RecoveryReadWindow,
    };
    let window = |device: Uuid, key_id: &str, opening: Uuid, first: i64| -> RecoveryReadWindow {
        serde_json::from_value(json!({
            "conversation": cid, "did": member, "device": device, "authGeneration": 1,
            "keyId": key_id, "welcome": opening, "firstSeq": first, "lastSeq": 7
        }))
        .unwrap()
    };
    let grant = |win, device, after, limit| {
        granted_recovery_page(&s.home_pool, win, SEQ, cid, member, device, after, limit)
    };
    let target_window = || window(target, &target_key, welcome, 5);
    for (after, expected) in [(0, vec![5, 6]), (5, vec![6]), (6, vec![])] {
        let body = grant(target_window(), target, after, 100).await.unwrap();
        let body: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(
            body["entries"]
                .as_array()
                .unwrap()
                .iter()
                .map(|e| e["seq"].as_u64().unwrap())
                .collect::<Vec<_>>(),
            expected
        );
        assert_eq!(body["hasMore"], false);
        assert_eq!(body["nextAfterSeq"], 6);
    }
    let body: Value =
        serde_json::from_slice(&grant(target_window(), target, 0, 1).await.unwrap()).unwrap();
    assert_eq!(body["nextAfterSeq"], 5);
    assert_eq!(body["hasMore"], true);
    for (device, win) in [
        (sibling, target_window()),
        (sibling, window(sibling, &sibling_key, welcome, 5)),
        (target, window(target, &sibling_key, welcome, 5)),
        (target, window(target, &target_key, welcome, 4)),
        (target, window(target, &target_key, Uuid::new_v4(), 5)),
    ] {
        assert!(matches!(
            grant(win, device, 5, 100).await,
            Err(EntryReadFacadeError::NotEntitled)
        ));
    }

    let revoke = crate::chat_protocol::test_support::sign_mutation_json_for_test(
        &json!({
            "$type": "blue.catbird.chat.defs#deviceRevocationBody",
            "signatureDomain": "CATBIRD-CHAT-DEVICE-REVOKE\u{0}",
            "actorDid": member, "actorDeviceId": sibling, "keyId": sibling_key, "authGeneration": 1,
            "targetDeviceId": target, "targetAuthGeneration": 1, "idempotencyKey": Uuid::new_v4(),
            "signedAt": Utc::now().to_rfc3339_opts(SecondsFormat::Millis, true),
        }),
        &ed25519_dalek::SigningKey::from_bytes(&[0x2b; 32]),
    )
    .unwrap();
    let (status, output) = http::send(
        router.clone(),
        http::unsigned_json_request(
            &reader(sibling),
            "blue.catbird.chat.revokeDevice",
            serde_json::to_vec(&json!({"signedRequest": revoke})).unwrap(),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{output}");
    assert!(matches!(
        grant(target_window(), target, 5, 100).await,
        Err(EntryReadFacadeError::NotEntitled)
    ));

    scope_ds_clock(
        s.clock.clone(),
        scope_sim_ds(s.seq_hooks.clone(), async {
            let removal = policy_entry(&admin, cid, 8, Uuid::new_v4(), remove(member));
            s.send(s.queued(removal, &[(member, target)]).await)
                .await
                .unwrap();
        }),
    )
    .await;
    assert_eq!(s.standing(member).await, RemoteGroupStanding::Removed);
    let (_, error) = read(sibling, 5, 100).await;
    assert_eq!(error["error"], "ConversationNotFound");
}
