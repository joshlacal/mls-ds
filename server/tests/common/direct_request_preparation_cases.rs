use base64::Engine as _;
// These rows exercise repository storage selection only. Deliberately labelled
// synthetic wrapper bytes: not a claim of MLS or HTTP signature qualification.
async fn seed_request_device(
    tx: &mut Transaction<'_, Postgres>,
    did: &str,
    scope: &str,
    grant: bool,
) -> SelectedDevice {
    let now = Utc::now();
    let device = Uuid::new_v4();
    let signing_key = Sha256::digest(device.as_bytes()).to_vec();
    let key_id =
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(Sha256::digest(&signing_key));
    sqlx::query(
        "INSERT INTO chat.principals(user_did,created_at) VALUES($1,$2) ON CONFLICT DO NOTHING",
    )
    .bind(did)
    .bind(now)
    .execute(&mut **tx)
    .await
    .unwrap();
    sqlx::query("INSERT INTO chat.devices(user_did,device_id,device_name,status,dpop_jkt,auth_generation,capabilities,created_at,updated_at) VALUES($1,$2,'test','active',$3,1,chat.protocol_capabilities(),$4,$4)")
        .bind(did).bind(device).bind(&key_id).bind(now).execute(&mut **tx).await.unwrap();
    sqlx::query("INSERT INTO chat.device_keys(user_did,device_id,key_id,signing_public_key,enrollment_auth_generation,created_at) VALUES($1,$2,$3,$4,1,$5)")
        .bind(did).bind(device).bind(&key_id).bind(&signing_key).bind(now).execute(&mut **tx).await.unwrap();
    let package_ref = Sha256::digest(Uuid::new_v4().as_bytes()).to_vec();
    let wrapper = vec![7; 40];
    let expiry = now + Duration::days(10);
    sqlx::query("INSERT INTO chat.key_packages(key_package_ref,wrapper_bytes,wrapper_sha256,init_key,owner_did,owner_device_id,owner_key_id,owner_auth_generation,not_before,not_after,status,created_at,usage_scope) VALUES($1,$2,$3,$4,$5,$6,$7,1,$8,$9,'available',$10,$11)")
        .bind(&package_ref).bind(&wrapper).bind(Sha256::digest(&wrapper).to_vec()).bind(Uuid::new_v4().as_bytes().as_slice()).bind(did).bind(device).bind(&key_id).bind(now-Duration::seconds(1)).bind(expiry).bind(now).bind(scope).execute(&mut **tx).await.unwrap();
    sqlx::query("INSERT INTO chat.direct_request_capabilities(owner_did,owner_device_id,owner_key_id,auth_generation,revision,enabled,protocol_version,signed_publication,publication_digest,updated_at) VALUES($1,$2,$3,1,1,TRUE,'2','test',$4,$5)")
        .bind(did).bind(device).bind(&key_id).bind(vec![1;32]).bind(now).execute(&mut **tx).await.unwrap();
    let grant_id = Uuid::new_v4();
    if grant {
        sqlx::query("INSERT INTO chat.direct_request_grants(grant_id,revision,owner_did,owner_device_id,owner_key_id,auth_generation,capability_revision,key_package_ref,purpose,protocol_version,profile,signed_grant,grant_digest,expires_at,created_at) VALUES($1,1,$2,$3,$4,1,1,$5,'direct-request-bootstrap','2','encryptedIntroduction1','test',$6,$7,$8)")
            .bind(grant_id).bind(did).bind(device).bind(&key_id).bind(&package_ref).bind(vec![1;32]).bind(expiry).bind(now).execute(&mut **tx).await.unwrap();
    }
    SelectedDevice {
        owner_did: did.to_owned(),
        owner_device_id: device,
        owner_key_id: key_id,
        auth_generation: 1,
        grant_id,
        grant_digest: vec![1; 32],
        capability_revision: 1,
        key_package_ref: package_ref,
        wrapper_bytes: wrapper,
        signed_grant: b"test".to_vec(),
        expires_at: expiry,
    }
}
fn seed_identity(actor: &SelectedDevice) -> AttemptIdentity {
    AttemptIdentity {
        request_id: Uuid::new_v4(),
        actor_did: actor.owner_did.clone(),
        actor_device_id: actor.owner_device_id,
        actor_key_id: actor.owner_key_id.clone(),
        actor_auth_generation: 1,
        recipient_did: "did:plc:bbbbbbbbbbbbbbbbbbbbbbbb".into(),
        prepare_digest: vec![2; 32],
    }
}
async fn locked(tx: &mut Transaction<'_, Postgres>, i: AttemptIdentity) -> LockedAttempt {
    let op = super::prelude::lock_direct_request_operation(tx, i.request_id)
        .await
        .unwrap();
    super::prelude::lock_direct_request_identity_scope(
        tx,
        &[i.actor_did.clone(), i.recipient_did.clone()],
    )
    .await
    .unwrap();
    load_locked_attempt(tx, i, &op).await.unwrap()
}
#[tokio::test]
async fn ordinary_recovery_packages_and_missing_grants_cannot_prepare() {
    let pool = crate::common::direct_request_database::setup().await;
    let mut tx = pool.begin().await.unwrap();
    let actor = seed_request_device(
        &mut tx,
        "did:plc:aaaaaaaaaaaaaaaaaaaaaaaa",
        "recovery",
        false,
    )
    .await;
    seed_request_device(
        &mut tx,
        "did:plc:bbbbbbbbbbbbbbbbbbbbbbbb",
        "recovery",
        false,
    )
    .await;
    seed_request_device(
        &mut tx,
        "did:plc:bbbbbbbbbbbbbbbbbbbbbbbb",
        "direct-request",
        false,
    )
    .await;
    let lock = locked(&mut tx, seed_identity(&actor)).await;
    assert!(matches!(
        select_devices(&mut tx, &lock, Utc::now()).await,
        Err(DirectRequestStoreError::RecipientKeysUnavailable)
    ));
    tx.rollback().await.unwrap();
}
#[tokio::test]
async fn complete_snapshot_reserves_all_deliverable_devices_and_never_recovery_pool() {
    let pool = crate::common::direct_request_database::setup().await;
    let mut tx = pool.begin().await.unwrap();
    let actor = seed_request_device(
        &mut tx,
        "did:plc:aaaaaaaaaaaaaaaaaaaaaaaa",
        "recovery",
        false,
    )
    .await;
    let sibling = seed_request_device(
        &mut tx,
        "did:plc:aaaaaaaaaaaaaaaaaaaaaaaa",
        "direct-request",
        true,
    )
    .await;
    let recipient = seed_request_device(
        &mut tx,
        "did:plc:bbbbbbbbbbbbbbbbbbbbbbbb",
        "direct-request",
        true,
    )
    .await;
    let recovery = seed_request_device(
        &mut tx,
        "did:plc:bbbbbbbbbbbbbbbbbbbbbbbb",
        "recovery",
        false,
    )
    .await;
    let i = seed_identity(&actor);
    let lock = locked(&mut tx, i.clone()).await;
    let now = Utc::now();
    let selected = select_devices(&mut tx, &lock, now).await.unwrap();
    assert_eq!(selected.len(), 2);
    assert!(selected
        .iter()
        .any(|d| d.owner_device_id == sibling.owner_device_id));
    assert!(selected
        .iter()
        .any(|d| d.owner_device_id == recipient.owner_device_id));
    reserve_preparation(
        &mut tx,
        lock,
        &selected,
        b"signed-snapshot-test",
        &[9; 32],
        now,
    )
    .await
    .unwrap();
    let state: String =
        sqlx::query_scalar("SELECT status FROM chat.key_packages WHERE key_package_ref=$1")
            .bind(&recovery.key_package_ref)
            .fetch_one(&mut *tx)
            .await
            .unwrap();
    assert_eq!(state, "available");
    let lock = locked(&mut tx, i.clone()).await;
    finish_terminal(
        &mut tx,
        lock,
        TerminalOutcome::Cancelled,
        b"cancel-test",
        None,
        now,
    )
    .await
    .unwrap();
    for d in selected {
        let state: String =
            sqlx::query_scalar("SELECT status FROM chat.key_packages WHERE key_package_ref=$1")
                .bind(d.key_package_ref)
                .fetch_one(&mut *tx)
                .await
                .unwrap();
        assert_eq!(state, "reserved");
    }
    tx.rollback().await.unwrap();
}
#[tokio::test]
async fn unrelated_enrollment_and_replenishment_preserve_snapshot_but_disable_invalidates() {
    let pool = crate::common::direct_request_database::setup().await;
    let mut tx = pool.begin().await.unwrap();
    let actor = seed_request_device(
        &mut tx,
        "did:plc:aaaaaaaaaaaaaaaaaaaaaaaa",
        "recovery",
        false,
    )
    .await;
    let recipient = seed_request_device(
        &mut tx,
        "did:plc:bbbbbbbbbbbbbbbbbbbbbbbb",
        "direct-request",
        true,
    )
    .await;
    let i = seed_identity(&actor);
    let lock = locked(&mut tx, i.clone()).await;
    let now = Utc::now();
    let selected = select_devices(&mut tx, &lock, now).await.unwrap();
    reserve_preparation(&mut tx, lock, &selected, b"snapshot", &[9; 32], now)
        .await
        .unwrap();
    seed_request_device(
        &mut tx,
        "did:plc:bbbbbbbbbbbbbbbbbbbbbbbb",
        "direct-request",
        true,
    )
    .await;
    sqlx::query("UPDATE chat.direct_request_capabilities SET revision=2 WHERE owner_did=$1 AND owner_device_id=$2").bind(&recipient.owner_did).bind(recipient.owner_device_id).execute(&mut *tx).await.unwrap();
    let lock = locked(&mut tx, i.clone()).await;
    validate_selected_authority(&mut tx, &lock, now)
        .await
        .unwrap();
    sqlx::query("UPDATE chat.direct_request_capabilities SET enabled=FALSE,revision=3 WHERE owner_did=$1 AND owner_device_id=$2").bind(&recipient.owner_did).bind(recipient.owner_device_id).execute(&mut *tx).await.unwrap();
    assert!(matches!(
        validate_selected_authority(&mut tx, &lock, now).await,
        Err(DirectRequestStoreError::IncludedAuthorityChanged)
    ));
    tx.rollback().await.unwrap();
}
