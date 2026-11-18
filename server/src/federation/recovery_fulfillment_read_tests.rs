use super::*;
use crate::common::http_acceptance as http;

async fn member_device(s: &GroupStream, mls_seed: u8) -> Uuid {
    let device = Uuid::new_v4();
    let key = ed25519_dalek::SigningKey::from_bytes(&[mls_seed; 32]);
    seed_actor_at(
        &s.home_pool,
        &s.recipient_did,
        device,
        &key.verifying_key().to_bytes(),
        clock_now(&s.home_pool).await,
    )
    .await;
    device
}

#[tokio::test]
async fn restored_leafless_device_reads_only_its_pending_fulfillment_on_its_home() {
    let s = GroupStream::new().await;
    let cid = s.cid;
    let admin = Actor::at_home(&s, ADMIN, 0x29).await;
    let member = s.recipient_did.as_str();
    let target = member_device(&s, 0x2a).await;
    let sibling = member_device(&s, 0x2b).await;
    s.network.declare_delivery_service(HOME);
    s.network.declare_user(member, HOME);

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
        }),
    )
    .await;
    assert_eq!(s.granted(member, target).await, [4, 5]);
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
    assert_eq!(
        entries[0]["signedRequest"]["signature"],
        fulfillment["signedRequest"]["signature"]
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
}
