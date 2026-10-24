//! Regression tests for capacity abuse, quota separation, and replay fencing.
//!
//! Target: docs/design-docs/2026-09-23-request-capacity-abuse-fix.md
//! All tests run on dedicated databases (catbird_direct_requests_fault_<16hex>)
//! with migration 20260919000021 installed.

#![allow(dead_code)]
pub use catbird_server::{auth, chat_protocol};
#[path = "common/chat_protocol.rs"]
pub mod chat_protocol_baseline;
mod common {
    pub use super::chat_protocol_baseline as chat_protocol;
    pub mod direct_request_database;
    // main's chat_protocol harness serializes migrations via fresh_db.
    pub mod fresh_db;
}

mod repository {
    pub mod prelude {
        include!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/src/chat_protocol/repository/direct_request_lock.rs"
        ));
    }
    mod direct_request_preparation {
        include!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/src/chat_protocol/repository/direct_request_store.rs"
        ));

        use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
        use sqlx::PgPool;

        type R<T> = Result<T, DirectRequestStoreError>;

        fn did() -> String {
            const A: &[u8] = b"abcdefghijklmnopqrstuvwxyz234567";
            let b = Uuid::new_v4().into_bytes();
            let s: String = (0..24)
                .map(|i| A[(b[i % 16] as usize + i * 7) % 32] as char)
                .collect();
            format!("did:plc:{s}")
        }

        async fn device(
            tx: &mut Transaction<'_, Postgres>,
            owner: &str,
            scope: &str,
            grant: bool,
        ) -> SelectedDevice {
            let now = Utc::now();
            let id = Uuid::new_v4();
            let signing = Sha256::digest(id.as_bytes()).to_vec();
            let key = URL_SAFE_NO_PAD.encode(Sha256::digest(&signing));
            sqlx::query(
                "INSERT INTO chat.principals(user_did,created_at) VALUES($1,$2) ON CONFLICT DO NOTHING",
            )
            .bind(owner)
            .bind(now)
            .execute(&mut **tx)
            .await
            .unwrap();
            sqlx::query("INSERT INTO chat.devices(user_did,device_id,device_name,status,dpop_jkt,auth_generation,capabilities,created_at,updated_at) VALUES($1,$2,'c27','active',$3,1,chat.protocol_capabilities(),$4,$4)")
                .bind(owner).bind(id).bind(&key).bind(now).execute(&mut **tx).await.unwrap();
            sqlx::query("INSERT INTO chat.device_keys(user_did,device_id,key_id,signing_public_key,enrollment_auth_generation,created_at) VALUES($1,$2,$3,$4,1,$5)")
                .bind(owner).bind(id).bind(&key).bind(&signing).bind(now).execute(&mut **tx).await.unwrap();
            sqlx::query("INSERT INTO chat.direct_request_capabilities(owner_did,owner_device_id,owner_key_id,auth_generation,revision,enabled,protocol_version,signed_publication,publication_digest,updated_at) VALUES($1,$2,$3,1,1,TRUE,'2','c27',$4,$5)")
                .bind(owner).bind(id).bind(&key).bind(vec![1_u8; 32]).bind(now).execute(&mut **tx).await.unwrap();
            let mut d = SelectedDevice {
                owner_did: owner.into(),
                owner_device_id: id,
                owner_key_id: key,
                auth_generation: 1,
                grant_id: Uuid::nil(),
                grant_digest: vec![1; 32],
                capability_revision: 1,
                key_package_ref: vec![],
                wrapper_bytes: vec![],
                signed_grant: b"c27".to_vec(),
                expires_at: now,
            };
            package(tx, &mut d, scope, grant).await;
            d
        }

        async fn package(
            tx: &mut Transaction<'_, Postgres>,
            d: &mut SelectedDevice,
            scope: &str,
            grant: bool,
        ) -> Vec<u8> {
            let now = Utc::now();
            let reference = Sha256::digest(Uuid::new_v4().as_bytes()).to_vec();
            let wrapper = vec![7_u8; 40];
            let expiry = now + Duration::days(10);
            sqlx::query("INSERT INTO chat.key_packages(key_package_ref,wrapper_bytes,wrapper_sha256,init_key,owner_did,owner_device_id,owner_key_id,owner_auth_generation,not_before,not_after,status,created_at,usage_scope) VALUES($1,$2,$3,$4,$5,$6,$7,1,$8,$9,'available',$10,$11)")
                .bind(&reference).bind(&wrapper).bind(Sha256::digest(&wrapper).to_vec()).bind(Uuid::new_v4().as_bytes().as_slice())
                .bind(&d.owner_did).bind(d.owner_device_id).bind(&d.owner_key_id).bind(now - Duration::seconds(5)).bind(expiry).bind(now).bind(scope)
                .execute(&mut **tx).await.unwrap();
            if grant {
                d.grant_id = Uuid::new_v4();
                sqlx::query("INSERT INTO chat.direct_request_grants(grant_id,revision,owner_did,owner_device_id,owner_key_id,auth_generation,capability_revision,key_package_ref,purpose,protocol_version,profile,signed_grant,grant_digest,expires_at,created_at) VALUES($1,1,$2,$3,$4,1,1,$5,'direct-request-bootstrap','2','encryptedIntroduction1','c27',$6,$7,$8)")
                    .bind(d.grant_id).bind(&d.owner_did).bind(d.owner_device_id).bind(&d.owner_key_id).bind(&reference)
                    .bind(vec![1_u8; 32]).bind(expiry).bind(now).execute(&mut **tx).await.unwrap();
            }
            d.key_package_ref = reference.clone();
            reference
        }

        fn identity(actor: &SelectedDevice, recipient: &str) -> AttemptIdentity {
            AttemptIdentity {
                request_id: Uuid::new_v4(),
                actor_did: actor.owner_did.clone(),
                actor_device_id: actor.owner_device_id,
                actor_key_id: actor.owner_key_id.clone(),
                actor_auth_generation: 1,
                recipient_did: recipient.into(),
                prepare_digest: Sha256::digest(Uuid::new_v4().as_bytes()).to_vec(),
            }
        }

        async fn lock(
            tx: &mut Transaction<'_, Postgres>,
            i: &AttemptIdentity,
        ) -> R<LockedAttempt> {
            let op = super::prelude::lock_direct_request_operation(tx, i.request_id).await?;
            super::prelude::lock_direct_request_identity_scope(
                tx,
                &[i.actor_did.clone(), i.recipient_did.clone()],
            )
            .await?;
            load_locked_attempt(tx, i.clone(), &op).await
        }

        async fn prepare_sized(
            tx: &mut Transaction<'_, Postgres>,
            i: &AttemptIdentity,
            snapshot: &[u8],
        ) -> R<Vec<u8>> {
            let l = lock(tx, i).await?;
            let now = Utc::now();
            let selected = select_devices(tx, &l, now).await?;
            reserve_preparation(tx, &l, &selected, snapshot, &Sha256::digest(snapshot), now).await
        }

        async fn prepare(tx: &mut Transaction<'_, Postgres>, i: &AttemptIdentity) -> R<Vec<u8>> {
            prepare_sized(tx, i, b"c27-signed-preparation-snapshot").await
        }

        async fn cancel(tx: &mut Transaction<'_, Postgres>, i: &AttemptIdentity) -> R<Vec<u8>> {
            let l = lock(tx, i).await?;
            finish_terminal(
                tx,
                l,
                TerminalOutcome::Cancelled,
                format!("cancel:{}", i.request_id).as_bytes(),
                None,
                Utc::now(),
            )
            .await
        }

        struct Isolated {
            name: String,
            pool: PgPool,
        }

        impl Drop for Isolated {
            fn drop(&mut self) {
                let _ = std::process::Command::new("psql")
                    .args([
                        "-X",
                        "-q",
                        "postgresql://127.0.0.1:5432/postgres",
                        "-c",
                        &format!("DROP DATABASE IF EXISTS {} WITH (FORCE)", self.name),
                    ])
                    .status();
            }
        }

        async fn isolated() -> Isolated {
            let name = format!(
                "catbird_direct_requests_fault_{}",
                &Uuid::new_v4().simple().to_string()[..16]
            );
            let admin = PgPool::connect("postgresql://127.0.0.1:5432/postgres")
                .await
                .unwrap();
            sqlx::query(&format!("CREATE DATABASE {name}"))
                .execute(&admin)
                .await
                .unwrap();
            admin.close().await;

            let clone = std::process::Command::new("sh")
                .arg("-c")
                .arg(format!(
                    "pg_dump -s postgresql://127.0.0.1:5432/catbird_direct_requests_test_20260919 | psql -X -q -v ON_ERROR_STOP=1 postgresql://127.0.0.1:5432/{name} >/dev/null"
                ))
                .status()
                .unwrap();
            assert!(clone.success(), "schema clone into {name}");

            let url = format!("postgresql://127.0.0.1:5432/{name}");
            let migration_path = concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/migrations/20260919000021_direct_request_capacity_abuse_fix.sql"
            );
            let m21 = std::process::Command::new("psql")
                .args(["-X", "-v", "ON_ERROR_STOP=1", &url, "-f", migration_path])
                .status()
                .unwrap();
            assert!(m21.success(), "apply migration 21 on {name}");

            let pool = sqlx::postgres::PgPoolOptions::new()
                .max_connections(8)
                .connect(&url)
                .await
                .unwrap();
            let iso = Isolated {
                name: name.clone(),
                pool,
            };
            sqlx::query(
                "INSERT INTO chat.direct_request_budget(singleton) VALUES(TRUE) ON CONFLICT DO NOTHING",
            )
            .execute(&iso.pool)
            .await
            .unwrap();
            iso
        }

        // -------------------------------------------------------------------
        // Test 1: published_request_leaves_no_pending_charge
        // -------------------------------------------------------------------
        #[tokio::test]
        async fn published_request_leaves_no_pending_charge() {
            let iso = isolated().await;
            let pool = iso.pool.clone();

            let (initial_pending, initial_retained): (i64, i64) = sqlx::query_as(
                "SELECT pending_bytes, retained_bytes FROM chat.direct_request_effective_budget WHERE singleton",
            )
            .fetch_one(&pool)
            .await
            .unwrap();

            let mut tx = pool.begin().await.unwrap();
            let alice = device(&mut tx, &did(), "recovery", false).await;
            let bob_did = did();
            device(&mut tx, &bob_did, "direct-request", true).await;
            let req = identity(&alice, &bob_did);

            let prep = prepare(&mut tx, &req).await.unwrap();
            assert!(!prep.is_empty());

            let (pending_during_prep, _): (i64, i64) = sqlx::query_as(
                "SELECT pending_bytes, retained_bytes FROM chat.direct_request_effective_budget WHERE singleton",
            )
            .fetch_one(&mut *tx)
            .await
            .unwrap();
            assert!(
                pending_during_prep >= initial_pending + 8_388_608,
                "pending_bytes must increase by at least MAX_BUNDLE_BYTES during preparation"
            );

            let lock = lock(&mut tx, &req).await.unwrap();
            let published_receipt = b"c27-published-receipt-test-1";
            let pub_digest = [9u8; 32];
            let publication_charge = 5_486_435i64;
            finish_terminal_charged(
                &mut tx,
                lock,
                TerminalOutcome::Published,
                published_receipt,
                Some(&pub_digest),
                Utc::now(),
                Some(publication_charge),
            )
            .await
            .unwrap();

            let (final_pending, final_retained): (i64, i64) = sqlx::query_as(
                "SELECT pending_bytes, retained_bytes FROM chat.direct_request_effective_budget WHERE singleton",
            )
            .fetch_one(&mut *tx)
            .await
            .unwrap();

            assert_eq!(
                final_pending, initial_pending,
                "pending_bytes MUST return to pre-preparation level upon publication (holds 0 pending bytes)"
            );
            assert_eq!(
                final_retained,
                initial_retained + publication_charge,
                "retained_bytes MUST equal the exact publication charge"
            );
            tx.rollback().await.unwrap();
        }

        // -------------------------------------------------------------------
        // Test 2: victim_outbound_unblocked_by_inbound_flood
        // -------------------------------------------------------------------
        #[tokio::test]
        async fn victim_outbound_unblocked_by_inbound_flood() {
            let iso = isolated().await;
            let pool = iso.pool.clone();

            let mut tx = pool.begin().await.unwrap();
            let victim_did = did();
            let mut victim = device(&mut tx, &victim_did, "direct-request", true).await;
            for _ in 0..35 {
                package(&mut tx, &mut victim, "direct-request", true).await;
            }

            let publication_charge = 5_486_435i64;

            // Send 32 inbound requests to the victim from distinct sender accounts in tx.
            for n in 0..32 {
                let sender = device(&mut tx, &did(), "recovery", false).await;
                let req = identity(&sender, &victim_did);
                prepare(&mut tx, &req).await.unwrap();
                let l = lock(&mut tx, &req).await.unwrap();
                finish_terminal_charged(
                    &mut tx,
                    l,
                    TerminalOutcome::Published,
                    format!("receipt-{n}").as_bytes(),
                    Some(&[n as u8; 32]),
                    Utc::now(),
                    Some(publication_charge),
                )
                .await
                .unwrap();
            }

            // 1. Assert the victim's own outbound prepareDirectRequest to an independent contact succeeds!
            let charlie_did = did();
            device(&mut tx, &charlie_did, "direct-request", true).await;
            let victim_outbound = identity(&victim, &charlie_did);
            let outbound_res = prepare(&mut tx, &victim_outbound).await;
            assert!(
                outbound_res.is_ok(),
                "victim outbound preparation MUST succeed even with 32 unanswered inbound requests"
            );

            // 2. Assert the 33rd inbound preparation targeting the victim is refused with RecipientKeysUnavailable.
            let sender_33 = device(&mut tx, &did(), "recovery", false).await;
            let inbound_33 = identity(&sender_33, &victim_did);
            let res_33 = prepare(&mut tx, &inbound_33).await;
            assert!(
                matches!(
                    res_33,
                    Err(DirectRequestStoreError::RecipientKeysUnavailable)
                ),
                "33rd inbound request must be refused with RecipientKeysUnavailable, got {res_33:?}"
            );

            // 3. Assert the 11th unanswered outbound request from one sender is refused with QuotaExceeded.
            let spammer = device(&mut tx, &did(), "recovery", false).await;
            let mut targets = Vec::new();
            for _ in 0..11 {
                let t = did();
                device(&mut tx, &t, "direct-request", true).await;
                targets.push(t);
            }

            // Spammer publishes 10 requests.
            for n in 0..10 {
                let req = identity(&spammer, &targets[n]);
                prepare(&mut tx, &req).await.unwrap();
                let l = lock(&mut tx, &req).await.unwrap();
                finish_terminal_charged(
                    &mut tx,
                    l,
                    TerminalOutcome::Published,
                    format!("spammer-receipt-{n}").as_bytes(),
                    Some(&[n as u8; 32]),
                    Utc::now(),
                    Some(publication_charge),
                )
                .await
                .unwrap();
            }

            // 11th outbound request from spammer must fail with QuotaExceeded.
            let req_11 = identity(&spammer, &targets[10]);
            let res_11 = prepare(&mut tx, &req_11).await;
            assert!(
                matches!(res_11, Err(DirectRequestStoreError::QuotaExceeded)),
                "11th outbound unanswered request must be refused with QuotaExceeded, got {res_11:?}"
            );
            tx.rollback().await.unwrap();
        }

        // -------------------------------------------------------------------
        // Test 3: global_pending_is_bounded_by_preparation_lease
        // -------------------------------------------------------------------
        #[tokio::test]
        async fn global_pending_is_bounded_by_preparation_lease() {
            let iso = isolated().await;
            let pool = iso.pool.clone();

            let mut tx = pool.begin().await.unwrap();
            let alice = device(&mut tx, &did(), "recovery", false).await;
            let bob_did = did();
            let mut bob = device(&mut tx, &bob_did, "direct-request", true).await;
            package(&mut tx, &mut bob, "direct-request", true).await;

            let req1 = identity(&alice, &bob_did);
            prepare(&mut tx, &req1).await.unwrap();

            let (pending_before_cancel, _): (i64, i64) = sqlx::query_as(
                "SELECT pending_bytes, retained_bytes FROM chat.direct_request_effective_budget WHERE singleton",
            )
            .fetch_one(&mut *tx)
            .await
            .unwrap();
            assert!(pending_before_cancel > 0);

            cancel(&mut tx, &req1).await.unwrap();

            let (pending_after_cancel, _): (i64, i64) = sqlx::query_as(
                "SELECT pending_bytes, retained_bytes FROM chat.direct_request_effective_budget WHERE singleton",
            )
            .fetch_one(&mut *tx)
            .await
            .unwrap();
            assert_eq!(
                pending_after_cancel, 0,
                "pending bytes must return to 0 after cancellation"
            );
            tx.rollback().await.unwrap();
        }

        // -------------------------------------------------------------------
        // Test 4: post_prune_replay_is_fenced_not_retryable
        // -------------------------------------------------------------------
        #[tokio::test]
        async fn post_prune_replay_is_fenced_not_retryable() {
            let iso = isolated().await;
            let pool = iso.pool.clone();

            let mut tx = pool.begin().await.unwrap();
            let alice = device(&mut tx, &did(), "recovery", false).await;
            let bob_did = did();
            device(&mut tx, &bob_did, "direct-request", true).await;
            let req = identity(&alice, &bob_did);

            prepare(&mut tx, &req).await.unwrap();
            let terminal_receipt = cancel(&mut tx, &req).await.unwrap();

            // Replay prepare with the same prepare_digest.
            let replay_lock = lock(&mut tx, &req).await.unwrap();
            let replay_res = reserve_preparation(
                &mut tx,
                &replay_lock,
                &[],
                b"replay-snapshot",
                &Sha256::digest(b"replay-snapshot"),
                Utc::now(),
            )
            .await;

            // Must return the stored terminal response (fenced) rather than creating fresh preparation.
            assert!(
                replay_res.is_ok(),
                "replay must return stored terminal response"
            );
            assert_eq!(
                replay_res.unwrap(),
                terminal_receipt,
                "must return the exact stored terminal receipt"
            );

            // Verify status is still terminal in attempts table.
            let status: String = sqlx::query_scalar(
                "SELECT status FROM chat.direct_request_attempts WHERE request_id = $1",
            )
            .bind(req.request_id)
            .fetch_one(&mut *tx)
            .await
            .unwrap();
            assert_eq!(status, "cancelled");
            tx.rollback().await.unwrap();
        }
    }
}
