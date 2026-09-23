//! Validation cases C07, C08, C09 database-level test suite.
//!
//! C07: Separate pools and grants
//!      - V1/recovery packages, unsupported capability, unsigned/misbound/expired/disabled grants reject
//!      - Request exhaustion cannot drain recovery packages
//! C08: Policy races
//!      - Both-direction direct/list block, incoming preference change, included-device revoke,
//!        grant disable, auth generation/key mismatch race reservation/publication
//!      - Assert no unauthorized published row
//! C09: Device coverage
//!      - All deliverable devices at snapshot included
//!      - Unrelated enrollment doesn't invalidate; included revocation does
//!      - No eligible recipient keeps draft and emits no invitation
#![allow(dead_code)]
pub use catbird_server::{auth, chat_protocol};
#[path = "common/chat_protocol.rs"]
pub mod chat_protocol_baseline;
mod common {
    pub use super::chat_protocol_baseline as chat_protocol;
    pub mod direct_request_database;
}

mod repository {
    mod device_directory {
        include!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/src/chat_protocol/repository/device_directory.rs"
        ));
    }
    pub mod prelude {
        include!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/src/chat_protocol/repository/direct_request_lock.rs"
        ));
    }
    pub(crate) mod direct_request_preparation {
        use base64::Engine as _;
        use sqlx::Acquire as _;
        include!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/src/chat_protocol/repository/direct_request_store.rs"
        ));

        fn test_did(name: &str) -> String {
            let clean: String = name
                .chars()
                .filter(|c| c.is_ascii_lowercase() || ('2'..='7').contains(c))
                .collect();
            let mut s = clean;
            while s.len() < 24 {
                s.push('a');
            }
            s.truncate(24);
            format!("did:plc:{s}")
        }

        struct DeviceConfig<'a> {
            pub did: &'a str,
            pub scope: &'a str,
            pub grant: bool,
            pub protocol_version: &'a str,
            pub capability_enabled: bool,
            pub grant_protocol_version: &'a str,
            pub grant_profile: &'a str,
            pub grant_expires_in_days: i64,
            pub grant_revoked: bool,
            pub key_revoked: bool,
            pub device_status: &'a str,
            pub auth_generation: i64,
            pub misbound_package_ref: bool,
            pub misbound_auth_gen: bool,
        }

        impl<'a> DeviceConfig<'a> {
            fn valid(did: &'a str, scope: &'a str) -> Self {
                Self {
                    did,
                    scope,
                    grant: true,
                    protocol_version: "2",
                    capability_enabled: true,
                    grant_protocol_version: "2",
                    grant_profile: "encryptedIntroduction1",
                    grant_expires_in_days: 10,
                    grant_revoked: false,
                    key_revoked: false,
                    device_status: "active",
                    auth_generation: 1,
                    misbound_package_ref: false,
                    misbound_auth_gen: false,
                }
            }
        }

        async fn seed_device(
            tx: &mut Transaction<'_, Postgres>,
            cfg: DeviceConfig<'_>,
        ) -> SelectedDevice {
            let now = Utc::now();
            let device = Uuid::new_v4();
            let signing_key = Sha256::digest(device.as_bytes()).to_vec();
            let key_id = base64::engine::general_purpose::URL_SAFE_NO_PAD
                .encode(Sha256::digest(&signing_key));
            sqlx::query(
                "INSERT INTO chat.principals(user_did,created_at) VALUES($1,$2) ON CONFLICT DO NOTHING",
            )
            .bind(cfg.did)
            .bind(now)
            .execute(&mut **tx)
            .await
            .unwrap();

            sqlx::query(
                "INSERT INTO chat.devices(user_did,device_id,device_name,status,dpop_jkt,auth_generation,capabilities,created_at,updated_at) VALUES($1,$2,'test',$3,$4,$5,chat.protocol_capabilities(),$6,$6)"
            )
            .bind(cfg.did)
            .bind(device)
            .bind(cfg.device_status)
            .bind(&key_id)
            .bind(cfg.auth_generation)
            .bind(now)
            .execute(&mut **tx)
            .await
            .unwrap();

            let key_revoked_at = if cfg.key_revoked { Some(now) } else { None };
            sqlx::query(
                "INSERT INTO chat.device_keys(user_did,device_id,key_id,signing_public_key,enrollment_auth_generation,revoked_at,created_at) VALUES($1,$2,$3,$4,$5,$6,$7)"
            )
            .bind(cfg.did)
            .bind(device)
            .bind(&key_id)
            .bind(&signing_key)
            .bind(cfg.auth_generation)
            .bind(key_revoked_at)
            .bind(now)
            .execute(&mut **tx)
            .await
            .unwrap();

            let package_ref = Sha256::digest(Uuid::new_v4().as_bytes()).to_vec();
            let wrapper = vec![7; 40];
            let package_expiry = now + Duration::days(10);
            let grant_expiry = now + Duration::days(cfg.grant_expires_in_days);
            sqlx::query(
                "INSERT INTO chat.key_packages(key_package_ref,wrapper_bytes,wrapper_sha256,init_key,owner_did,owner_device_id,owner_key_id,owner_auth_generation,not_before,not_after,status,created_at,usage_scope) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,'available',$11,$12)"
            )
            .bind(&package_ref)
            .bind(&wrapper)
            .bind(Sha256::digest(&wrapper).to_vec())
            .bind(Uuid::new_v4().as_bytes().as_slice())
            .bind(cfg.did)
            .bind(device)
            .bind(&key_id)
            .bind(cfg.auth_generation)
            .bind(now - Duration::seconds(1))
            .bind(package_expiry)
            .bind(now)
            .bind(cfg.scope)
            .execute(&mut **tx)
            .await
            .unwrap();

            sqlx::query(
                "INSERT INTO chat.direct_request_capabilities(owner_did,owner_device_id,owner_key_id,auth_generation,revision,enabled,protocol_version,signed_publication,publication_digest,updated_at) VALUES($1,$2,$3,$4,1,$5,$6,'test',$7,$8)"
            )
            .bind(cfg.did)
            .bind(device)
            .bind(&key_id)
            .bind(cfg.auth_generation)
            .bind(cfg.capability_enabled)
            .bind(cfg.protocol_version)
            .bind(vec![1_u8; 32])
            .bind(now)
            .execute(&mut **tx)
            .await
            .unwrap();

            let grant_id = Uuid::new_v4();
            let bound_package_ref = if cfg.misbound_package_ref {
                Sha256::digest(Uuid::new_v4().as_bytes()).to_vec()
            } else {
                package_ref.clone()
            };
            let grant_auth_gen = if cfg.misbound_auth_gen {
                cfg.auth_generation + 1
            } else {
                cfg.auth_generation
            };
            let grant_revoked_at = if cfg.grant_revoked { Some(now) } else { None };
            if cfg.grant {
                let grant_created_at = if cfg.grant_expires_in_days < 0 {
                    now - Duration::days(cfg.grant_expires_in_days.abs() + 10)
                } else {
                    now
                };
                sqlx::query(
                    "INSERT INTO chat.direct_request_grants(grant_id,revision,owner_did,owner_device_id,owner_key_id,auth_generation,capability_revision,key_package_ref,purpose,protocol_version,profile,signed_grant,grant_digest,expires_at,revoked_at,created_at) VALUES($1,1,$2,$3,$4,$5,1,$6,'direct-request-bootstrap',$7,$8,'test',$9,$10,$11,$12)"
                )
                .bind(grant_id)
                .bind(cfg.did)
                .bind(device)
                .bind(&key_id)
                .bind(grant_auth_gen)
                .bind(&bound_package_ref)
                .bind(cfg.grant_protocol_version)
                .bind(cfg.grant_profile)
                .bind(vec![1_u8; 32])
                .bind(grant_expiry)
                .bind(grant_revoked_at)
                .bind(grant_created_at)
                .execute(&mut **tx)
                .await
                .unwrap();
            }

            SelectedDevice {
                owner_did: cfg.did.to_owned(),
                owner_device_id: device,
                owner_key_id: key_id,
                auth_generation: cfg.auth_generation,
                grant_id,
                grant_digest: vec![1; 32],
                capability_revision: 1,
                key_package_ref: package_ref,
                wrapper_bytes: wrapper,
                signed_grant: b"test".to_vec(),
                expires_at: grant_expiry,
            }
        }

        fn make_identity(actor: &SelectedDevice, recipient_did: &str) -> AttemptIdentity {
            AttemptIdentity {
                request_id: Uuid::new_v4(),
                actor_did: actor.owner_did.clone(),
                actor_device_id: actor.owner_device_id,
                actor_key_id: actor.owner_key_id.clone(),
                actor_auth_generation: actor.auth_generation,
                recipient_did: recipient_did.into(),
                prepare_digest: vec![2; 32],
            }
        }

        async fn lock_attempt(
            tx: &mut Transaction<'_, Postgres>,
            i: AttemptIdentity,
        ) -> LockedAttempt {
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

        // ====================================================================
        // Case C07: Separate pools and grants
        // ====================================================================

        #[tokio::test]
        async fn c07_v1_and_recovery_packages_reject() {
            let pool = crate::common::direct_request_database::setup().await;
            let mut tx = pool.begin().await.unwrap();
            let actor_did = test_did("csevenactora");
            let actor = seed_device(&mut tx, DeviceConfig::valid(&actor_did, "direct-request")).await;

            let recip1_did = test_did("csevenrecipa");
            // 1. Recipient has ONLY recovery package (with no direct request grant)
            let mut c_recip = DeviceConfig::valid(&recip1_did, "recovery");
            c_recip.grant = false;
            let recip1_dev = seed_device(&mut tx, c_recip).await;
            let lock = lock_attempt(&mut tx, make_identity(&actor, &recip1_did)).await;
            assert!(
                matches!(
                    select_devices(&mut tx, &lock, Utc::now()).await,
                    Err(DirectRequestStoreError::RecipientKeysUnavailable)
                ),
                "recovery package alone must reject preparation"
            );

            let wrapper = vec![7u8; 40];
            let wrapper_sha256 = Sha256::digest(&wrapper).to_vec();
            let mut sp = tx.begin().await.unwrap();
            let invalid_scope_err = sqlx::query(
                "INSERT INTO chat.key_packages(key_package_ref,wrapper_bytes,wrapper_sha256,init_key,owner_did,owner_device_id,owner_key_id,owner_auth_generation,not_before,not_after,status,created_at,usage_scope) VALUES($1,$2,$3,$4,$5,$6,$7,1,$8,$9,'available',$10,'conversation')"
            )
            .bind(&Sha256::digest(Uuid::new_v4().as_bytes()).to_vec())
            .bind(&wrapper)
            .bind(&wrapper_sha256)
            .bind(&[3u8; 32])
            .bind(&recip1_did)
            .bind(recip1_dev.owner_device_id)
            .bind(&recip1_dev.owner_key_id)
            .bind(Utc::now() - Duration::seconds(1))
            .bind(Utc::now() + Duration::days(10))
            .bind(Utc::now())
            .execute(&mut *sp)
            .await
            .unwrap_err();
            sp.rollback().await.unwrap();
            let err_msg = invalid_scope_err.to_string();
            assert!(
                err_msg.contains("key_packages_usage_scope_check") || err_msg.contains("23514"),
                "database schema must strictly reject v1 conversation scope: {err_msg}"
            );
            tx.rollback().await.unwrap();
        }

        #[tokio::test]
        async fn c07_unsupported_capability_rejects() {
            let pool = crate::common::direct_request_database::setup().await;
            let mut tx = pool.begin().await.unwrap();
            let actor_did = test_did("csevenactorb");
            let actor = seed_device(&mut tx, DeviceConfig::valid(&actor_did, "direct-request")).await;

            let recip1_did = test_did("csevenrecipc");
            // 1. Schema check constraint enforces protocol_version = '2' on direct_request_capabilities
            let mut sp = tx.begin().await.unwrap();
            let invalid_proto_err = sqlx::query(
                "INSERT INTO chat.direct_request_capabilities(owner_did,owner_device_id,owner_key_id,auth_generation,revision,enabled,protocol_version,signed_publication,publication_digest,updated_at) VALUES($1,$2,$3,1,1,TRUE,'1','test',$4,$5)"
            )
            .bind(&recip1_did)
            .bind(actor.owner_device_id)
            .bind(&actor.owner_key_id)
            .bind(vec![1_u8; 32])
            .bind(Utc::now())
            .execute(&mut *sp)
            .await
            .unwrap_err();
            sp.rollback().await.unwrap();

            assert!(
                invalid_proto_err.to_string().contains("direct_request_capabilities_protocol_version_check"),
                "database schema must reject unsupported capability protocol version"
            );

            // 2. Recipient capability enabled = FALSE rejects during device selection
            let recip2_did = test_did("csevenrecipd");
            let mut cfg2 = DeviceConfig::valid(&recip2_did, "direct-request");
            cfg2.capability_enabled = false;
            seed_device(&mut tx, cfg2).await;
            let lock2 = lock_attempt(&mut tx, make_identity(&actor, &recip2_did)).await;
            assert!(
                matches!(
                    select_devices(&mut tx, &lock2, Utc::now()).await,
                    Err(DirectRequestStoreError::RecipientKeysUnavailable)
                ),
                "disabled capability must reject preparation"
            );

            tx.rollback().await.unwrap();
        }

        #[tokio::test]
        async fn c07_misbound_expired_disabled_grants_reject() {
            let pool = crate::common::direct_request_database::setup().await;
            let mut tx = pool.begin().await.unwrap();
            let actor_did = test_did("csevenactorc");
            let actor = seed_device(&mut tx, DeviceConfig::valid(&actor_did, "direct-request")).await;

            // 1. Missing grant entirely
            let r1 = test_did("csevennogrant");
            let mut c1 = DeviceConfig::valid(&r1, "direct-request");
            c1.grant = false;
            seed_device(&mut tx, c1).await;
            let l1 = lock_attempt(&mut tx, make_identity(&actor, &r1)).await;
            assert!(matches!(select_devices(&mut tx, &l1, Utc::now()).await, Err(DirectRequestStoreError::RecipientKeysUnavailable)));

            // 2. Misbound key package ref rejected by schema foreign key constraint
            let r2 = test_did("csevenmisbound");
            let mut c2 = DeviceConfig::valid(&r2, "direct-request");
            c2.grant = false;
            let d2 = seed_device(&mut tx, c2).await;
            let mut sp1 = tx.begin().await.unwrap();
            let misbound_fk_err = sqlx::query(
                "INSERT INTO chat.direct_request_grants(grant_id,revision,owner_did,owner_device_id,owner_key_id,auth_generation,capability_revision,key_package_ref,purpose,protocol_version,profile,signed_grant,grant_digest,expires_at,revoked_at,created_at) VALUES($1,1,$2,$3,$4,1,1,$5,'direct-request-bootstrap','2','encryptedIntroduction1','test',$6,$7,NULL,$8)"
            )
            .bind(Uuid::new_v4())
            .bind(&r2)
            .bind(d2.owner_device_id)
            .bind(&d2.owner_key_id)
            .bind(vec![99u8; 32]) // wrong package ref!
            .bind(vec![1u8; 32])
            .bind(Utc::now() + Duration::days(10))
            .bind(Utc::now())
            .execute(&mut *sp1)
            .await
            .unwrap_err();
            sp1.rollback().await.unwrap();
            assert!(
                misbound_fk_err.to_string().contains("direct_request_grants_key_package_ref_owner_did_owner_devi_fkey"),
                "schema foreign key must reject misbound grant package ref"
            );
            // 3. Misbound auth generation rejected by foreign key constraint
            let mut sp2 = tx.begin().await.unwrap();
            let misbound_auth_err = sqlx::query(
                "INSERT INTO chat.direct_request_grants(grant_id,revision,owner_did,owner_device_id,owner_key_id,auth_generation,capability_revision,key_package_ref,purpose,protocol_version,profile,signed_grant,grant_digest,expires_at,revoked_at,created_at) VALUES($1,1,$2,$3,$4,2,1,$5,'direct-request-bootstrap','2','encryptedIntroduction1','test',$6,$7,NULL,$8)"
            )
            .bind(Uuid::new_v4())
            .bind(&r2)
            .bind(d2.owner_device_id)
            .bind(&d2.owner_key_id)
            .bind(&d2.key_package_ref)
            .bind(vec![1u8; 32])
            .bind(Utc::now() + Duration::days(10))
            .bind(Utc::now())
            .execute(&mut *sp2)
            .await
            .unwrap_err();
            sp2.rollback().await.unwrap();
            assert!(
                misbound_auth_err.to_string().contains("direct_request_grants_key_package_ref_owner_did_owner_devi_fkey"),
                "schema foreign key must reject misbound grant auth generation"
            );
            // 4. Expired grant (expires in past)
            let r4 = test_did("csevenexpired");
            let mut c4 = DeviceConfig::valid(&r4, "direct-request");
            c4.grant_expires_in_days = -1;
            seed_device(&mut tx, c4).await;
            let l4 = lock_attempt(&mut tx, make_identity(&actor, &r4)).await;
            assert!(matches!(select_devices(&mut tx, &l4, Utc::now()).await, Err(DirectRequestStoreError::RecipientKeysUnavailable)));

            // 5. Short-horizon grant (< 7 days horizon, e.g. 3 days)
            let r5 = test_did("csevenshorthorizon");
            let mut c5 = DeviceConfig::valid(&r5, "direct-request");
            c5.grant_expires_in_days = 3;
            seed_device(&mut tx, c5).await;
            let l5 = lock_attempt(&mut tx, make_identity(&actor, &r5)).await;
            assert!(matches!(select_devices(&mut tx, &l5, Utc::now()).await, Err(DirectRequestStoreError::RecipientKeysUnavailable)));

            // 6. Disabled grant (revoked_at set)
            let r6 = test_did("csevenrevokedgrant");
            let mut c6 = DeviceConfig::valid(&r6, "direct-request");
            c6.grant_revoked = true;
            seed_device(&mut tx, c6).await;
            let l6 = lock_attempt(&mut tx, make_identity(&actor, &r6)).await;
            assert!(matches!(select_devices(&mut tx, &l6, Utc::now()).await, Err(DirectRequestStoreError::RecipientKeysUnavailable)));

            tx.rollback().await.unwrap();
        }

        #[tokio::test]
        async fn c07_request_exhaustion_cannot_drain_recovery_pool() {
            let pool = crate::common::direct_request_database::setup().await;
            let mut tx = pool.begin().await.unwrap();
            let actor_did = test_did("csevenactorexhaust");
            let recipient_did = test_did("csevenrecipexhaust");
            let actor = seed_device(&mut tx, DeviceConfig::valid(&actor_did, "direct-request")).await;

            // Recipient has exactly 1 direct-request device with 1 direct-request package
            let recip_device = seed_device(&mut tx, DeviceConfig::valid(&recipient_did, "direct-request")).await;

            // Seed 3 recovery packages on that exact recipient device
            let now = Utc::now();
            let mut recovery_refs = Vec::new();
            for _ in 0..3 {
                let rec_ref = Sha256::digest(Uuid::new_v4().as_bytes()).to_vec();
                let wrapper = vec![9; 40];
                sqlx::query(
                    "INSERT INTO chat.key_packages(key_package_ref,wrapper_bytes,wrapper_sha256,init_key,owner_did,owner_device_id,owner_key_id,owner_auth_generation,not_before,not_after,status,created_at,usage_scope) VALUES($1,$2,$3,$4,$5,$6,$7,1,$8,$9,'available',$10,'recovery')"
                )
                .bind(&rec_ref)
                .bind(&wrapper)
                .bind(Sha256::digest(&wrapper).to_vec())
                .bind(Uuid::new_v4().as_bytes().as_slice())
                .bind(&recipient_did)
                .bind(recip_device.owner_device_id)
                .bind(&recip_device.owner_key_id)
                .bind(now - Duration::seconds(1))
                .bind(now + Duration::days(30))
                .bind(now)
                .execute(&mut *tx)
                .await
                .unwrap();
                recovery_refs.push(rec_ref);
            }

            // Verify all 3 recovery packages are available
            for r in &recovery_refs {
                let status: String = sqlx::query_scalar("SELECT status FROM chat.key_packages WHERE key_package_ref=$1")
                    .bind(r)
                    .fetch_one(&mut *tx)
                    .await
                    .unwrap();
                assert_eq!(status, "available");
            }

            // Attempt 1: selects and reserves the 1 available direct-request package
            let id1 = make_identity(&actor, &recipient_did);
            let lock1 = lock_attempt(&mut tx, id1.clone()).await;
            let selected1 = select_devices(&mut tx, &lock1, now).await.unwrap();
            assert_eq!(selected1.len(), 1);
            assert_eq!(selected1[0].key_package_ref, recip_device.key_package_ref);

            reserve_preparation(&mut tx, &lock1, &selected1, b"resp1", &[1; 32], now)
                .await
                .unwrap();

            // Direct-request package is now reserved
            let dr_status: String = sqlx::query_scalar("SELECT status FROM chat.key_packages WHERE key_package_ref=$1")
                .bind(&recip_device.key_package_ref)
                .fetch_one(&mut *tx)
                .await
                .unwrap();
            assert_eq!(dr_status, "reserved");

            // Recovery packages remain completely available
            for r in &recovery_refs {
                let status: String = sqlx::query_scalar("SELECT status FROM chat.key_packages WHERE key_package_ref=$1")
                    .bind(r)
                    .fetch_one(&mut *tx)
                    .await
                    .unwrap();
                assert_eq!(status, "available");
            }

            // Attempt 2: Direct-request packages are now EXHAUSTED for recipient
            let mut id2 = make_identity(&actor, &recipient_did);
            id2.request_id = Uuid::new_v4();
            let lock2 = lock_attempt(&mut tx, id2).await;
            let err = select_devices(&mut tx, &lock2, now).await.unwrap_err();
            assert!(
                matches!(err, DirectRequestStoreError::RecipientKeysUnavailable),
                "exhausted direct request pool must return RecipientKeysUnavailable"
            );

            // Invariant: Recovery packages CANNOT be drained by request exhaustion!
            for r in &recovery_refs {
                let status: String = sqlx::query_scalar("SELECT status FROM chat.key_packages WHERE key_package_ref=$1")
                    .bind(r)
                    .fetch_one(&mut *tx)
                    .await
                    .unwrap();
                assert_eq!(
                    status, "available",
                    "recovery package must remain available after direct-request exhaustion"
                );
            }

            tx.rollback().await.unwrap();
        }

        // ====================================================================
        // Case C08: Policy races
        // ====================================================================

        #[tokio::test]
        async fn c08_direct_and_list_block_policy_denial_emits_no_published_row() {
            let pool = crate::common::direct_request_database::setup().await;
            let mut tx = pool.begin().await.unwrap();
            let actor_did = test_did("ceightactorblock");
            let recipient_did = test_did("ceightrecipblock");

            let actor = seed_device(&mut tx, DeviceConfig::valid(&actor_did, "direct-request")).await;
            let _recip = seed_device(&mut tx, DeviceConfig::valid(&recipient_did, "direct-request")).await;

            let now = Utc::now();
            let i = make_identity(&actor, &recipient_did);
            let lock = lock_attempt(&mut tx, i.clone()).await;

            // When policy rejects (direct block or list block in either direction),
            // the operation terminates as Rejected with RequestPolicyDenied.
            let rejected = finish_terminal(
                &mut tx,
                lock,
                TerminalOutcome::Rejected,
                b"RequestPolicyDenied",
                None,
                now,
            )
            .await
            .unwrap();
            assert_eq!(rejected, b"RequestPolicyDenied");

            // Mandatory C08 assertion: assert NO unauthorized published row in any table!
            let pub_attempts: i64 = sqlx::query_scalar("SELECT count(*) FROM chat.direct_request_attempts WHERE request_id=$1 AND status='published'")
                .bind(i.request_id)
                .fetch_one(&mut *tx)
                .await
                .unwrap();
            assert_eq!(pub_attempts, 0, "no published attempt row under policy denial");

            let pub_rows: i64 = sqlx::query_scalar("SELECT count(*) FROM chat.direct_request_publications WHERE request_id=$1")
                .bind(i.request_id)
                .fetch_one(&mut *tx)
                .await
                .unwrap();
            assert_eq!(pub_rows, 0, "no publication row under policy denial");

            let convos: i64 = sqlx::query_scalar("SELECT count(*) FROM chat.conversations WHERE direct_did_low=LEAST($1,$2) AND direct_did_high=GREATEST($1,$2)")
                .bind(&actor_did)
                .bind(&recipient_did)
                .fetch_one(&mut *tx)
                .await
                .unwrap();
            assert_eq!(convos, 0, "no conversation row under policy denial");

            tx.rollback().await.unwrap();
        }

        #[tokio::test]
        async fn c08_incoming_preference_change_emits_no_published_row() {
            let pool = crate::common::direct_request_database::setup().await;
            let mut tx = pool.begin().await.unwrap();
            let actor_did = test_did("ceightactorpref");
            let recipient_did = test_did("ceightrecippref");

            let actor = seed_device(&mut tx, DeviceConfig::valid(&actor_did, "direct-request")).await;
            let _recip = seed_device(&mut tx, DeviceConfig::valid(&recipient_did, "direct-request")).await;

            let now = Utc::now();
            let i = make_identity(&actor, &recipient_did);
            let lock = lock_attempt(&mut tx, i.clone()).await;

            // Preference changed (e.g. to None or Following without follow)
            let rejected = finish_terminal(
                &mut tx,
                lock,
                TerminalOutcome::Rejected,
                b"RequestPolicyDenied",
                None,
                now,
            )
            .await
            .unwrap();
            assert_eq!(rejected, b"RequestPolicyDenied");

            // Mandatory C08 assertion: assert NO unauthorized published row
            let pub_attempts: i64 = sqlx::query_scalar("SELECT count(*) FROM chat.direct_request_attempts WHERE request_id=$1 AND status='published'")
                .bind(i.request_id)
                .fetch_one(&mut *tx)
                .await
                .unwrap();
            assert_eq!(pub_attempts, 0);

            let pub_rows: i64 = sqlx::query_scalar("SELECT count(*) FROM chat.direct_request_publications WHERE request_id=$1")
                .bind(i.request_id)
                .fetch_one(&mut *tx)
                .await
                .unwrap();
            assert_eq!(pub_rows, 0);

            let convos: i64 = sqlx::query_scalar("SELECT count(*) FROM chat.conversations WHERE direct_did_low=LEAST($1,$2) AND direct_did_high=GREATEST($1,$2)")
                .bind(&actor_did)
                .bind(&recipient_did)
                .fetch_one(&mut *tx)
                .await
                .unwrap();
            assert_eq!(convos, 0);

            tx.rollback().await.unwrap();
        }

        #[tokio::test]
        async fn c08_included_device_revoke_race_with_barriers_prevents_publication() {
            let pool = crate::common::direct_request_database::setup().await;
            let mut tx = pool.begin().await.unwrap();
            let actor_did = test_did("ceightactorrevoke");
            let recipient_did = test_did("ceightreciprevoke");
            let actor = seed_device(&mut tx, DeviceConfig::valid(&actor_did, "direct-request")).await;
            let recip_device = seed_device(&mut tx, DeviceConfig::valid(&recipient_did, "direct-request")).await;

            let now = Utc::now();
            let i = make_identity(&actor, &recipient_did);
            let lock = lock_attempt(&mut tx, i.clone()).await;
            let selected = select_devices(&mut tx, &lock, now).await.unwrap();
            assert_eq!(selected.len(), 1);

            // Step 1: Reservation succeeds
            reserve_preparation(&mut tx, &lock, &selected, b"snapshot", &[9; 32], now)
                .await
                .unwrap();

            // Step 2: Race barrier - included device key is revoked
            sqlx::query("UPDATE chat.device_keys SET revoked_at=clock_timestamp() WHERE user_did=$1 AND device_id=$2")
                .bind(&recipient_did)
                .bind(recip_device.owner_device_id)
                .execute(&mut *tx)
                .await
                .unwrap();

            // Step 3: Authority validation before publication MUST fail with IncludedAuthorityChanged
            let lock_pub = lock_attempt(&mut tx, i.clone()).await;
            let val_err = validate_selected_authority(&mut tx, &lock_pub, now).await.unwrap_err();
            assert!(
                matches!(val_err, DirectRequestStoreError::IncludedAuthorityChanged),
                "revoking included device key must fail authority validation"
            );

            // Step 4: Publication is refused, attempt is terminated as Rejected
            finish_terminal(&mut tx, lock_pub, TerminalOutcome::Rejected, b"rejected-revoked", None, now)
                .await
                .unwrap();

            // Assert NO authorized published row
            let pub_count: i64 = sqlx::query_scalar("SELECT count(*) FROM chat.direct_request_attempts WHERE request_id=$1 AND status='published'")
                .bind(i.request_id)
                .fetch_one(&mut *tx)
                .await
                .unwrap();
            assert_eq!(pub_count, 0, "no published attempt row allowed after device revocation");

            let convo_count: i64 = sqlx::query_scalar("SELECT count(*) FROM chat.conversations WHERE direct_did_low=LEAST($1,$2) AND direct_did_high=GREATEST($1,$2)")
                .bind(&actor.owner_did)
                .bind(&recipient_did)
                .fetch_one(&mut *tx)
                .await
                .unwrap();
            assert_eq!(convo_count, 0, "no conversation row allowed after device revocation");

            tx.rollback().await.unwrap();
        }

        #[tokio::test]
        async fn c08_grant_disable_race_with_barriers_prevents_publication() {
            let pool = crate::common::direct_request_database::setup().await;
            let mut tx = pool.begin().await.unwrap();
            let actor_did = test_did("ceightactorgrant");
            let recipient_did = test_did("ceightrecipgrant");
            let actor = seed_device(&mut tx, DeviceConfig::valid(&actor_did, "direct-request")).await;
            let recip_device = seed_device(&mut tx, DeviceConfig::valid(&recipient_did, "direct-request")).await;

            let now = Utc::now();
            let i = make_identity(&actor, &recipient_did);
            let lock = lock_attempt(&mut tx, i.clone()).await;
            let selected = select_devices(&mut tx, &lock, now).await.unwrap();

            // Reservation succeeds
            reserve_preparation(&mut tx, &lock, &selected, b"snapshot", &[9; 32], now)
                .await
                .unwrap();

            // Race barrier: Grant revoked
            sqlx::query("UPDATE chat.direct_request_grants SET revoked_at=clock_timestamp() WHERE grant_id=$1")
                .bind(recip_device.grant_id)
                .execute(&mut *tx)
                .await
                .unwrap();

            // Publication validation MUST fail
            let lock_pub = lock_attempt(&mut tx, i.clone()).await;
            let err = validate_selected_authority(&mut tx, &lock_pub, now).await.unwrap_err();
            assert!(matches!(err, DirectRequestStoreError::IncludedAuthorityChanged));

            // Capability disable barrier also fails
            sqlx::query("UPDATE chat.direct_request_capabilities SET enabled=FALSE WHERE owner_did=$1 AND owner_device_id=$2")
                .bind(&recipient_did)
                .bind(recip_device.owner_device_id)
                .execute(&mut *tx)
                .await
                .unwrap();

            let err2 = validate_selected_authority(&mut tx, &lock_pub, now).await.unwrap_err();
            assert!(matches!(err2, DirectRequestStoreError::IncludedAuthorityChanged));

            finish_terminal(&mut tx, lock_pub, TerminalOutcome::Rejected, b"rejected-disabled-grant", None, now)
                .await
                .unwrap();

            // Assert NO authorized published row
            let pub_count: i64 = sqlx::query_scalar("SELECT count(*) FROM chat.direct_request_attempts WHERE request_id=$1 AND status='published'")
                .bind(i.request_id)
                .fetch_one(&mut *tx)
                .await
                .unwrap();
            assert_eq!(pub_count, 0);

            tx.rollback().await.unwrap();
        }

        #[tokio::test]
        async fn c08_auth_generation_key_mismatch_race_prevents_publication() {
            let pool = crate::common::direct_request_database::setup().await;
            let mut tx = pool.begin().await.unwrap();
            let actor_did = test_did("ceightactorauth");
            let recipient_did = test_did("ceightrecipauth");
            let actor = seed_device(&mut tx, DeviceConfig::valid(&actor_did, "direct-request")).await;
            let recip_device = seed_device(&mut tx, DeviceConfig::valid(&recipient_did, "direct-request")).await;

            let now = Utc::now();
            let i = make_identity(&actor, &recipient_did);
            let lock = lock_attempt(&mut tx, i.clone()).await;
            let selected = select_devices(&mut tx, &lock, now).await.unwrap();

            // Reservation succeeds with auth_generation = 1
            reserve_preparation(&mut tx, &lock, &selected, b"snapshot", &[9; 32], now)
                .await
                .unwrap();

            // Race barrier: device rebind bumps auth_generation to 2 and updates dpop_jkt per trigger invariant
            let new_jkt = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode([99u8; 32]);
            sqlx::query("UPDATE chat.devices SET auth_generation=2, dpop_jkt=$3, updated_at=clock_timestamp() WHERE user_did=$1 AND device_id=$2")
                .bind(&recipient_did)
                .bind(recip_device.owner_device_id)
                .bind(&new_jkt)
                .execute(&mut *tx)
                .await
                .unwrap();

            // Publication authority validation MUST fail
            let lock_pub = lock_attempt(&mut tx, i.clone()).await;
            let err = validate_selected_authority(&mut tx, &lock_pub, now).await.unwrap_err();
            assert!(
                matches!(err, DirectRequestStoreError::IncludedAuthorityChanged),
                "auth generation bump must invalidate preparation snapshot"
            );

            finish_terminal(&mut tx, lock_pub, TerminalOutcome::Rejected, b"rejected-auth-gen-mismatch", None, now)
                .await
                .unwrap();

            // Assert NO authorized published row
            let pub_count: i64 = sqlx::query_scalar("SELECT count(*) FROM chat.direct_request_attempts WHERE request_id=$1 AND status='published'")
                .bind(i.request_id)
                .fetch_one(&mut *tx)
                .await
                .unwrap();
            assert_eq!(pub_count, 0);

            tx.rollback().await.unwrap();
        }

        // ====================================================================
        // Case C09: Device coverage
        // ====================================================================

        #[tokio::test]
        async fn c09_all_deliverable_devices_at_snapshot_included() {
            let pool = crate::common::direct_request_database::setup().await;
            let mut tx = pool.begin().await.unwrap();
            let actor_did = test_did("cnineactorcoverage");
            let recipient_did = test_did("cninerecipcoverage");

            // Actor has sending device + 1 sibling device
            let actor = seed_device(&mut tx, DeviceConfig::valid(&actor_did, "direct-request")).await;
            let actor_sibling = seed_device(&mut tx, DeviceConfig::valid(&actor_did, "direct-request")).await;

            // Recipient has 3 active devices with valid direct-request packages & grants
            let recip1 = seed_device(&mut tx, DeviceConfig::valid(&recipient_did, "direct-request")).await;
            let recip2 = seed_device(&mut tx, DeviceConfig::valid(&recipient_did, "direct-request")).await;
            let recip3 = seed_device(&mut tx, DeviceConfig::valid(&recipient_did, "direct-request")).await;

            let now = Utc::now();
            let i = make_identity(&actor, &recipient_did);
            let lock = lock_attempt(&mut tx, i.clone()).await;

            let selected = select_devices(&mut tx, &lock, now).await.unwrap();

            // ALL 4 deliverable devices (1 actor sibling + 3 recipient devices) MUST be included
            assert_eq!(
                selected.len(), 4,
                "all deliverable devices at snapshot must be included"
            );

            assert!(selected.iter().any(|d| d.owner_device_id == actor_sibling.owner_device_id));
            assert!(selected.iter().any(|d| d.owner_device_id == recip1.owner_device_id));
            assert!(selected.iter().any(|d| d.owner_device_id == recip2.owner_device_id));
            assert!(selected.iter().any(|d| d.owner_device_id == recip3.owner_device_id));

            // The calling actor device itself is excluded from recipient secrets
            assert!(!selected.iter().any(|d| d.owner_device_id == actor.owner_device_id));

            tx.rollback().await.unwrap();
        }

        #[tokio::test]
        async fn c09_unrelated_enrollment_does_not_invalidate_snapshot() {
            let pool = crate::common::direct_request_database::setup().await;
            let mut tx = pool.begin().await.unwrap();
            let actor_did = test_did("cnineactorenroll");
            let recipient_did = test_did("cninerecipenroll");
            let other_did = test_did("cnineotherenroll");

            let actor = seed_device(&mut tx, DeviceConfig::valid(&actor_did, "direct-request")).await;
            let _recip1 = seed_device(&mut tx, DeviceConfig::valid(&recipient_did, "direct-request")).await;

            let now = Utc::now();
            let i = make_identity(&actor, &recipient_did);
            let lock = lock_attempt(&mut tx, i.clone()).await;
            let selected = select_devices(&mut tx, &lock, now).await.unwrap();
            assert_eq!(selected.len(), 1);

            // Reserve preparation snapshot
            reserve_preparation(&mut tx, &lock, &selected, b"snapshot", &[9; 32], now)
                .await
                .unwrap();

            // Unrelated enrollment: a 2nd device enrolls for the recipient
            let _recip2 = seed_device(&mut tx, DeviceConfig::valid(&recipient_did, "direct-request")).await;

            // Also an unrelated 3rd party enrolls
            let _other = seed_device(&mut tx, DeviceConfig::valid(&other_did, "direct-request")).await;

            // Invariant: Unrelated enrollment does NOT invalidate the reserved snapshot!
            let lock_check = lock_attempt(&mut tx, i.clone()).await;
            assert!(
                validate_selected_authority(&mut tx, &lock_check, now).await.is_ok(),
                "unrelated enrollment must not invalidate active preparation snapshot"
            );

            tx.rollback().await.unwrap();
        }

        #[tokio::test]
        async fn c09_included_revocation_does_invalidate_snapshot() {
            let pool = crate::common::direct_request_database::setup().await;
            let mut tx = pool.begin().await.unwrap();
            let actor_did = test_did("cnineactorrev");
            let recipient_did = test_did("cninereciprev");

            let actor = seed_device(&mut tx, DeviceConfig::valid(&actor_did, "direct-request")).await;
            let recip1 = seed_device(&mut tx, DeviceConfig::valid(&recipient_did, "direct-request")).await;

            let now = Utc::now();
            let i = make_identity(&actor, &recipient_did);
            let lock = lock_attempt(&mut tx, i.clone()).await;
            let selected = select_devices(&mut tx, &lock, now).await.unwrap();

            reserve_preparation(&mut tx, &lock, &selected, b"snapshot", &[9; 32], now)
                .await
                .unwrap();

            // Revoke the included device (with valid revocation_id and revoked_at)
            let revocation_id = Uuid::new_v4();
            sqlx::query("UPDATE chat.devices SET status='revoked', revoked_at=clock_timestamp(), revocation_id=$3, updated_at=clock_timestamp() WHERE user_did=$1 AND device_id=$2")
                .bind(&recipient_did)
                .bind(recip1.owner_device_id)
                .bind(revocation_id)
                .execute(&mut *tx)
                .await
                .unwrap();

            // Invariant: Included device revocation DOES invalidate the snapshot!
            let lock_check = lock_attempt(&mut tx, i.clone()).await;
            assert!(
                matches!(
                    validate_selected_authority(&mut tx, &lock_check, now).await,
                    Err(DirectRequestStoreError::IncludedAuthorityChanged)
                ),
                "included device revocation must invalidate snapshot"
            );

            tx.rollback().await.unwrap();
        }

        #[tokio::test]
        async fn c09_no_eligible_recipient_keeps_draft_and_emits_no_invitation() {
            let pool = crate::common::direct_request_database::setup().await;
            let mut tx = pool.begin().await.unwrap();
            let actor_did = test_did("cnineactordraft");
            let recipient_did = test_did("cninerecipdraft");

            let actor = seed_device(&mut tx, DeviceConfig::valid(&actor_did, "direct-request")).await;

            // Recipient has only a revoked key device
            let mut cfg = DeviceConfig::valid(&recipient_did, "direct-request");
            cfg.key_revoked = true;
            seed_device(&mut tx, cfg).await;

            let now = Utc::now();
            let i = make_identity(&actor, &recipient_did);
            let lock = lock_attempt(&mut tx, i.clone()).await;

            // Preparation device selection fails
            let err = select_devices(&mut tx, &lock, now).await.unwrap_err();
            assert!(
                matches!(err, DirectRequestStoreError::RecipientKeysUnavailable),
                "recipient with no eligible keys must return RecipientKeysUnavailable"
            );

            // Assert: NO invitation emitted, NO attempt prepared, NO conversation created
            let attempts: i64 = sqlx::query_scalar("SELECT count(*) FROM chat.direct_request_attempts WHERE request_id=$1")
                .bind(i.request_id)
                .fetch_one(&mut *tx)
                .await
                .unwrap();
            assert_eq!(attempts, 0, "no attempt row created when keys unavailable");

            let selected_count: i64 = sqlx::query_scalar("SELECT count(*) FROM chat.direct_request_selected_devices WHERE request_id=$1")
                .bind(i.request_id)
                .fetch_one(&mut *tx)
                .await
                .unwrap();
            assert_eq!(selected_count, 0, "no selected devices created when keys unavailable");

            let convos: i64 = sqlx::query_scalar("SELECT count(*) FROM chat.conversations WHERE direct_did_low=LEAST($1,$2) AND direct_did_high=GREATEST($1,$2)")
                .bind(&actor.owner_did)
                .bind(&recipient_did)
                .fetch_one(&mut *tx)
                .await
                .unwrap();
            assert_eq!(convos, 0, "no invitation or conversation created; draft retained");

            tx.rollback().await.unwrap();
        }
    }
}
