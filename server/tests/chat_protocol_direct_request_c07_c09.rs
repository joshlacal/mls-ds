//! Validation case C07 database-level test suite.
//!
//! C07: Separate pools and grants
//!      - V1/recovery packages, unsupported capability, unsigned/misbound/expired/disabled grants reject
//!      - Request exhaustion cannot drain recovery packages
//! C08/C09 moved to e2e `encrypted_request_c08_c09.rs` (live router, real policy
//! projection and concurrent barrier races) and catbird-mls
//! `clean_chat_direct_request_c09_draft.rs` (core draft retention).
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
        async fn c07_v1_and_recovery_packages_never_serve_the_request_pool() {
            let pool = crate::common::direct_request_database::setup().await;
            let mut tx = pool.begin().await.unwrap();
            let actor_did = test_did("csevenactora");
            let actor = seed_device(&mut tx, DeviceConfig::valid(&actor_did, "direct-request")).await;

            // (1) Schema truth: the migration default is 'recovery', so an
            // ordinary/legacy publication never lands in the request pool.
            let legacy_did = test_did("csevenlegacy");
            let mut legacy_cfg = DeviceConfig::valid(&legacy_did, "recovery");
            legacy_cfg.grant = false;
            let legacy = seed_device(&mut tx, legacy_cfg).await;
            // Insert exactly as the ordinary/legacy publisher does: omit
            // usage_scope entirely and read back whatever the schema assigned.
            let unscoped_wrapper = vec![6u8; 40];
            let unscoped_ref = Sha256::digest(Uuid::new_v4().as_bytes()).to_vec();
            sqlx::query(
                "INSERT INTO chat.key_packages(key_package_ref,wrapper_bytes,wrapper_sha256,init_key,owner_did,owner_device_id,owner_key_id,owner_auth_generation,not_before,not_after,status,created_at) VALUES($1,$2,$3,$4,$5,$6,$7,1,$8,$9,'available',$10)"
            )
            .bind(&unscoped_ref)
            .bind(&unscoped_wrapper)
            .bind(Sha256::digest(&unscoped_wrapper).to_vec())
            .bind(&[4u8; 32])
            .bind(&legacy_did)
            .bind(legacy.owner_device_id)
            .bind(&legacy.owner_key_id)
            .bind(Utc::now() - Duration::seconds(1))
            .bind(Utc::now() + Duration::days(10))
            .bind(Utc::now())
            .execute(&mut *tx)
            .await
            .unwrap();
            let default_scope: String =
                sqlx::query_scalar("SELECT usage_scope FROM chat.key_packages WHERE key_package_ref=$1")
                    .bind(&unscoped_ref)
                    .fetch_one(&mut *tx)
                    .await
                    .unwrap();
            assert_eq!(
                default_scope, "recovery",
                "a package published without an explicit scope defaults to recovery"
            );

            // (2) Scope is the deciding predicate, not absent grants: this device
            // has an enabled direct-request capability, one current direct-request
            // package (with its grant) AND an additional legacy recovery package.
            // Only the direct-request package may be selected.
            let mixed_did = test_did("csevenmixed");
            let mixed = seed_device(&mut tx, DeviceConfig::valid(&mixed_did, "direct-request")).await;
            let legacy_wrapper = vec![9u8; 40];
            let legacy_ref = Sha256::digest(Uuid::new_v4().as_bytes()).to_vec();
            sqlx::query(
                "INSERT INTO chat.key_packages(key_package_ref,wrapper_bytes,wrapper_sha256,init_key,owner_did,owner_device_id,owner_key_id,owner_auth_generation,not_before,not_after,status,created_at) VALUES($1,$2,$3,$4,$5,$6,$7,1,$8,$9,'available',$10)"
            )
            .bind(&legacy_ref)
            .bind(&legacy_wrapper)
            .bind(Sha256::digest(&legacy_wrapper).to_vec())
            .bind(&[5u8; 32])
            .bind(&mixed_did)
            .bind(mixed.owner_device_id)
            .bind(&mixed.owner_key_id)
            .bind(Utc::now() - Duration::seconds(1))
            .bind(Utc::now() + Duration::days(10))
            .bind(Utc::now())
            .execute(&mut *tx)
            .await
            .unwrap();

            let now = Utc::now();
            let mixed_identity = make_identity(&actor, &mixed_did);
            let mixed_lock = lock_attempt(&mut tx, mixed_identity.clone()).await;
            let selected = select_devices(&mut tx, &mixed_lock, now).await.unwrap();
            assert_eq!(
                selected.len(),
                1,
                "the recovery-scoped package must not join the request selection"
            );
            assert_eq!(selected[0].key_package_ref, mixed.key_package_ref);
            assert_eq!(selected[0].owner_device_id, mixed.owner_device_id);

            // (3) The request pool is genuinely exhausted while the recovery pool
            // remains intact: reserving the direct-request package must not fall
            // back to the recovery package on the same device.
            reserve_preparation(&mut tx, &mixed_lock, &selected, b"resp1", &[1; 32], now)
                .await
                .unwrap();
            let reserved: String =
                sqlx::query_scalar("SELECT status FROM chat.key_packages WHERE key_package_ref=$1")
                    .bind(&mixed.key_package_ref)
                    .fetch_one(&mut *tx)
                    .await
                    .unwrap();
            assert_eq!(reserved, "reserved");

            let mut second = make_identity(&actor, &mixed_did);
            second.request_id = Uuid::new_v4();
            let exhausted_lock = lock_attempt(&mut tx, second).await;
            assert!(
                matches!(
                    select_devices(&mut tx, &exhausted_lock, now).await,
                    Err(DirectRequestStoreError::RecipientKeysUnavailable)
                ),
                "an exhausted request pool must not fall back to recovery packages"
            );
            let legacy_still_available: String =
                sqlx::query_scalar("SELECT status FROM chat.key_packages WHERE key_package_ref=$1")
                    .bind(&legacy_ref)
                    .fetch_one(&mut *tx)
                    .await
                    .unwrap();
            assert_eq!(
                legacy_still_available, "available",
                "the recovery package must be untouched by request-pool exhaustion"
            );

            // (4) A grant can never confer request authority on recovery material:
            // the composite foreign key includes usage_scope, so binding a
            // recovery-scoped package is rejected by the schema itself.
            let mut sp = tx.begin().await.unwrap();
            let misbound_scope_err = sqlx::query(
                "INSERT INTO chat.direct_request_grants(grant_id,revision,owner_did,owner_device_id,owner_key_id,auth_generation,capability_revision,key_package_ref,purpose,protocol_version,profile,signed_grant,grant_digest,expires_at,revoked_at,created_at) VALUES($1,1,$2,$3,$4,1,1,$5,'direct-request-bootstrap','2','encryptedIntroduction1','test',$6,$7,NULL,$8)"
            )
            .bind(Uuid::new_v4())
            .bind(&legacy_did)
            .bind(legacy.owner_device_id)
            .bind(&legacy.owner_key_id)
            .bind(&legacy.key_package_ref)
            .bind(vec![1u8; 32])
            .bind(Utc::now() + Duration::days(10))
            .bind(Utc::now())
            .execute(&mut *sp)
            .await
            .unwrap_err();
            sp.rollback().await.unwrap();
            assert!(
                misbound_scope_err
                    .to_string()
                    .contains("direct_request_grants_key_package_ref_owner_did_owner_devi_fkey"),
                "schema must refuse a grant bound to recovery-scoped material: {misbound_scope_err}"
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
    }
}
