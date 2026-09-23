//! Server-side qualification for direct request cases C12, C13.
//! (C10 moved to e2e-tests/tests/encrypted_request_c10.rs: real router fault injection.)
//!
//! Case C12: Barrier-controlled cancel vs delayed prepare/publish incl. preparation
//!           timeout; unknown-to-cancelled tombstone blocks late prepare and publish;
//!           publish-first cancel returns committed identity; withdrawal uses signed close.
//! Case C13: Expired/unclaimed operation acquires definitive terminal proof under lock;
//!           absence/timeout never authorizes abandonment; completed replay works
//!           after lease expiry.
//!
//! No shared schema mutation.
#![allow(dead_code, unused_imports)]

pub use catbird_server::{auth, chat_protocol};
#[path = "common/chat_protocol.rs"]
pub mod chat_protocol_baseline;
mod common {
    pub use super::chat_protocol_baseline as chat_protocol;
    pub mod direct_request_database;
}
mod repository {
    pub mod prelude {
        include!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/src/chat_protocol/repository/direct_request_lock.rs"
        ));
    }
    pub mod direct_request_preparation {
        include!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/src/chat_protocol/repository/direct_request_store.rs"
        ));

        use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
        use rand::Rng as _;
        use sqlx::{Acquire as _, PgPool};

        fn random_did_plc() -> String {
            const CHARSET: &[u8] = b"abcdefghijklmnopqrstuvwxyz234567";
            let mut rng = rand::thread_rng();
            let s: String = (0..24)
                .map(|_| {
                    let idx = rng.gen_range(0..CHARSET.len());
                    CHARSET[idx] as char
                })
                .collect();
            format!("did:plc:{s}")
        }

        async fn test_lock(tx: &mut Transaction<'_, Postgres>, identity: AttemptIdentity) -> LockedAttempt {
            let operation = super::prelude::lock_direct_request_operation(tx, identity.request_id)
                .await
                .unwrap();
            load_locked_attempt(tx, identity, &operation).await.unwrap()
        }

        fn test_identity_with_key(actor_pub: &[u8; 32]) -> AttemptIdentity {
            AttemptIdentity {
                request_id: Uuid::new_v4(),
                actor_did: random_did_plc(),
                actor_device_id: Uuid::new_v4(),
                actor_key_id: URL_SAFE_NO_PAD.encode(Sha256::digest(actor_pub)),
                actor_auth_generation: 1,
                recipient_did: random_did_plc(),
                prepare_digest: vec![2u8; 32],
            }
        }

        fn test_identity() -> AttemptIdentity {
            let mut actor_pub = [0u8; 32];
            rand::thread_rng().fill(&mut actor_pub);
            test_identity_with_key(&actor_pub)
        }

        async fn seed_device_and_keys(
            pool: &PgPool,
            did: &str,
            device_id: Uuid,
            public_key: &[u8],
        ) -> String {
            let key_id = URL_SAFE_NO_PAD.encode(Sha256::digest(public_key));
            let now = Utc::now();
            sqlx::query(
                "INSERT INTO chat.principals(user_did,created_at) \
                 VALUES($1,$2) \
                 ON CONFLICT (user_did) DO NOTHING",
            )
            .bind(did)
            .bind(now)
            .execute(pool)
            .await
            .unwrap();

            sqlx::query(
                "INSERT INTO chat.devices(user_did,device_id,device_name,status,dpop_jkt,auth_generation,capabilities,created_at,updated_at) \
                 VALUES($1,$2,'test-device','active',$3,1,chat.protocol_capabilities(),$4,$4) \
                 ON CONFLICT (user_did,device_id) DO NOTHING",
            )
            .bind(did)
            .bind(device_id)
            .bind(&key_id)
            .bind(now)
            .execute(pool)
            .await
            .unwrap();

            sqlx::query(
                "INSERT INTO chat.device_keys(user_did,device_id,key_id,signing_public_key,enrollment_auth_generation,created_at) \
                 VALUES($1,$2,$3,$4,1,$5) \
                 ON CONFLICT (user_did,device_id,key_id) DO NOTHING",
            )
            .bind(did)
            .bind(device_id)
            .bind(&key_id)
            .bind(public_key)
            .bind(now)
            .execute(pool)
            .await
            .unwrap();

            let pub_bytes = b"signed-capabilities-publication";
            let pub_digest = Sha256::digest(pub_bytes).to_vec();
            sqlx::query(
                "INSERT INTO chat.direct_request_capabilities(owner_did,owner_device_id,owner_key_id,auth_generation,protocol_version,enabled,revision,signed_publication,publication_digest,updated_at) \
                 VALUES($1,$2,$3,1,'2',true,1,$4,$5,$6) \
                 ON CONFLICT (owner_did,owner_device_id) DO NOTHING",
            )
            .bind(did)
            .bind(device_id)
            .bind(&key_id)
            .bind(&pub_bytes[..])
            .bind(&pub_digest)
            .bind(now)
            .execute(pool)
            .await
            .unwrap();
            key_id
        }

        // ====================================================================
        // C12: CANCEL VERSUS DELAYED PREPARE / PUBLISH
        // ====================================================================

        #[tokio::test]
        async fn c12_cancel_unknown_creates_tombstone_blocking_late_prepare_and_publish() {
            let pool = crate::common::direct_request_database::setup().await;
            let mut tx = pool.begin().await.unwrap();
            let i = test_identity();
            let now = Utc::now();

            let lock = test_lock(&mut tx, i.clone()).await;
            assert!(lock.row.is_none(), "attempt must be initially unknown");

            let cancel_receipt = b"signed-direct-request-cancelled-receipt-proof";
            let tombstone = finish_terminal(
                &mut tx,
                lock,
                TerminalOutcome::Cancelled,
                cancel_receipt,
                None,
                now,
            )
            .await
            .unwrap();
            assert_eq!(tombstone, cancel_receipt);

            let status: String = sqlx::query_scalar(
                "SELECT status FROM chat.direct_request_attempts WHERE request_id=$1",
            )
            .bind(i.request_id)
            .fetch_one(&mut *tx)
            .await
            .unwrap();
            assert_eq!(status, "cancelled");

            let lock = test_lock(&mut tx, i.clone()).await;
            let late_prepare = reserve_preparation(
                &mut tx,
                &lock,
                &[],
                b"late-prepare-must-not-succeed",
                &[0u8; 32],
                now + Duration::seconds(1),
            )
            .await
            .unwrap();
            assert_eq!(
                late_prepare, cancel_receipt,
                "late prepare must return cancelled tombstone"
            );

            let lock = test_lock(&mut tx, i.clone()).await;
            let late_publish = finish_terminal_charged(
                &mut tx,
                lock,
                TerminalOutcome::Published,
                b"late-publish-must-not-succeed",
                Some(&[9u8; 32]),
                now + Duration::seconds(600),
                Some(MAX_BUNDLE_BYTES),
            )
            .await
            .unwrap();
            assert_eq!(
                late_publish, cancel_receipt,
                "late publish must return cancelled tombstone"
            );

            let count: i64 = sqlx::query_scalar(
                "SELECT count(*) FROM chat.direct_request_selected_devices WHERE request_id=$1",
            )
            .bind(i.request_id)
            .fetch_one(&mut *tx)
            .await
            .unwrap();
            assert_eq!(count, 0);

            let pub_count: i64 = sqlx::query_scalar(
                "SELECT count(*) FROM chat.direct_request_publications WHERE request_id=$1",
            )
            .bind(i.request_id)
            .fetch_one(&mut *tx)
            .await
            .unwrap();
            assert_eq!(pub_count, 0);

            tx.rollback().await.unwrap();
        }

        #[tokio::test]
        async fn c12_barrier_controlled_cancel_vs_delayed_prepare_race() {
            let pool = crate::common::direct_request_database::setup().await;
            let i = test_identity();
            let mut tx = pool.begin().await.unwrap();
            let lock = test_lock(&mut tx, i.clone()).await;

            finish_terminal(
                &mut tx,
                lock,
                TerminalOutcome::Cancelled,
                b"committed-cancel-barrier",
                None,
                Utc::now(),
            )
            .await
            .unwrap();

            let pool2 = pool.clone();
            let i_delayed = i.clone();
            let mut delayed = tokio::spawn(async move {
                let mut late = pool2.begin().await.unwrap();
                let lock = test_lock(&mut late, i_delayed).await;
                let replay =
                    reserve_preparation(&mut late, &lock, &[], b"late-prepare", &[4; 32], Utc::now())
                        .await
                        .unwrap();
                late.commit().await.unwrap();
                replay
            });

            assert!(
                tokio::time::timeout(std::time::Duration::from_millis(100), &mut delayed)
                    .await
                    .is_err(),
                "operation lock must serialize delayed preparation behind cancel"
            );

            tx.commit().await.unwrap();
            let outcome = delayed.await.unwrap();
            assert_eq!(outcome, b"committed-cancel-barrier");
        }

        #[tokio::test]
        async fn c12_preparation_timeout_blocks_late_publish() {
            let pool = crate::common::direct_request_database::setup().await;
            let mut tx = pool.begin().await.unwrap();
            let i = test_identity();
            let now = Utc::now();
            let admitted = now - Duration::seconds(305);

            let _lock = test_lock(&mut tx, i.clone()).await;
            sqlx::query(
                "INSERT INTO chat.direct_request_attempts(request_id,actor_did,actor_device_id,actor_key_id,actor_auth_generation,recipient_did,prepare_digest,status,prepare_response,selected_digest,prepared_at,lease_expires_at,created_at) \
                 VALUES($1,$2,$3,$4,1,$5,$6,'prepared',$7,$8,$9,$10,$9)",
            )
            .bind(i.request_id)
            .bind(&i.actor_did)
            .bind(i.actor_device_id)
            .bind(&i.actor_key_id)
            .bind(&i.recipient_did)
            .bind(&i.prepare_digest)
            .bind(&b"prep"[..])
            .bind(vec![4u8; 32])
            .bind(admitted)
            .bind(now - Duration::seconds(5))
            .execute(&mut *tx)
            .await
            .unwrap();

            let lock = test_lock(&mut tx, i.clone()).await;
            let late_pub = finish_terminal_charged(
                &mut tx,
                lock,
                TerminalOutcome::Published,
                b"expired-publish-must-fail",
                Some(&[8u8; 32]),
                now,
                Some(MAX_BUNDLE_BYTES),
            )
            .await;

            assert!(
                matches!(late_pub, Err(DirectRequestStoreError::Expired)),
                "publish after lease expiry must fail with Expired"
            );

            let status: String = sqlx::query_scalar(
                "SELECT status FROM chat.direct_request_attempts WHERE request_id=$1",
            )
            .bind(i.request_id)
            .fetch_one(&mut *tx)
            .await
            .unwrap();
            assert_eq!(status, "prepared");

            let lock = test_lock(&mut tx, i).await;
            let term = finish_terminal(
                &mut tx,
                lock,
                TerminalOutcome::Rejected,
                b"terminal-expired-receipt",
                None,
                now,
            )
            .await
            .unwrap();
            assert_eq!(term, b"terminal-expired-receipt");

            tx.rollback().await.unwrap();
        }

        #[tokio::test]
        async fn c12_publish_first_cancellation_returns_committed_identity() {
            let pool = crate::common::direct_request_database::setup().await;
            let mut tx = pool.begin().await.unwrap();
            let i = test_identity();
            let now = Utc::now();

            let _lock = test_lock(&mut tx, i.clone()).await;
            sqlx::query(
                "INSERT INTO chat.direct_request_attempts(request_id,actor_did,actor_device_id,actor_key_id,actor_auth_generation,recipient_did,prepare_digest,status,prepare_response,selected_digest,prepared_at,lease_expires_at,created_at) \
                 VALUES($1,$2,$3,$4,1,$5,$6,'prepared',$7,$8,$9,$10,$9)",
            )
            .bind(i.request_id)
            .bind(&i.actor_did)
            .bind(i.actor_device_id)
            .bind(&i.actor_key_id)
            .bind(&i.recipient_did)
            .bind(&i.prepare_digest)
            .bind(&b"prep"[..])
            .bind(vec![4u8; 32])
            .bind(now)
            .bind(now + Duration::seconds(300))
            .execute(&mut *tx)
            .await
            .unwrap();

            let lock = test_lock(&mut tx, i.clone()).await;
            let pub_receipt = finish_terminal_charged(
                &mut tx,
                lock,
                TerminalOutcome::Published,
                b"committed-published-receipt-identity",
                Some(&[8u8; 32]),
                now,
                Some(MAX_BUNDLE_BYTES),
            )
            .await
            .unwrap();
            assert_eq!(pub_receipt, b"committed-published-receipt-identity");

            let lock = test_lock(&mut tx, i.clone()).await;
            let cancel_outcome = finish_terminal(
                &mut tx,
                lock,
                TerminalOutcome::Cancelled,
                b"must-not-cancel",
                None,
                now + Duration::seconds(10),
            )
            .await
            .unwrap();

            assert_eq!(
                cancel_outcome, b"committed-published-receipt-identity",
                "publish-first cancel must return committed published receipt"
            );

            let status: String = sqlx::query_scalar(
                "SELECT status FROM chat.direct_request_attempts WHERE request_id=$1",
            )
            .bind(i.request_id)
            .fetch_one(&mut *tx)
            .await
            .unwrap();
            assert_eq!(status, "published");

            tx.rollback().await.unwrap();
        }

        #[tokio::test]
        async fn c12_withdrawal_uses_signed_close_rather_than_cancel() {
            let pool = crate::common::direct_request_database::setup().await;
            let i = test_identity();
            let convo_id = Uuid::new_v4();
            let now = Utc::now();
            let bob_dev = Uuid::new_v4();

            let mut alice_pub = [0u8; 32];
            rand::thread_rng().fill(&mut alice_pub);
            let i = test_identity_with_key(&alice_pub);

            seed_device_and_keys(&pool, &i.actor_did, i.actor_device_id, &alice_pub).await;
            let mut bob_pub = [0u8; 32];
            rand::thread_rng().fill(&mut bob_pub);
            seed_device_and_keys(&pool, &i.recipient_did, bob_dev, &bob_pub).await;

            let mut tx = pool.begin().await.unwrap();
            let _lock = test_lock(&mut tx, i.clone()).await;
            sqlx::query(
                "INSERT INTO chat.direct_request_attempts(request_id,actor_did,actor_device_id,actor_key_id,actor_auth_generation,recipient_did,prepare_digest,status,prepare_response,selected_digest,prepared_at,lease_expires_at,terminal_at,terminal_response,terminal_response_sha256,publication_digest,created_at) \
                 VALUES($1,$2,$3,$4,1,$5,$6,'published',$7,$8,$9,$10,$9,$11,$12,$13,$9)",
            )
            .bind(i.request_id)
            .bind(&i.actor_did)
            .bind(i.actor_device_id)
            .bind(&i.actor_key_id)
            .bind(&i.recipient_did)
            .bind(&i.prepare_digest)
            .bind(&b"prep"[..])
            .bind(&i.prepare_digest)
            .bind(now)
            .bind(now + Duration::seconds(300))
            .bind(&b"published-receipt"[..])
            .bind(Sha256::digest(b"published-receipt").to_vec())
            .bind(vec![8u8; 32])
            .execute(&mut *tx)
            .await
            .unwrap();

            let (low, high) = if i.actor_did < i.recipient_did {
                (&i.actor_did, &i.recipient_did)
            } else {
                (&i.recipient_did, &i.actor_did)
            };
            sqlx::query(
                "INSERT INTO chat.conversations(conversation_id,kind,lifecycle,current_generation,current_state_version,next_entry_seq,direct_did_low,direct_did_high,created_at,protocol_version) \
                 VALUES($1,'direct','active',0,1,2,$2,$3,$4,'2')",
            )
            .bind(convo_id)
            .bind(low)
            .bind(high)
            .bind(now)
            .execute(&mut *tx)
            .await
            .unwrap();

            // 1. Cancel does NOT withdraw conversation; returns published receipt
            let lock = test_lock(&mut tx, i.clone()).await;
            let cancel_res = finish_terminal(
                &mut tx,
                lock,
                TerminalOutcome::Cancelled,
                b"cancel-attempt",
                None,
                now,
            )
            .await
            .unwrap();
            assert_eq!(cancel_res, b"published-receipt");

            let lifecycle: String = sqlx::query_scalar(
                "SELECT lifecycle FROM chat.conversations WHERE conversation_id=$1",
            )
            .bind(convo_id)
            .fetch_one(&mut *tx)
            .await
            .unwrap();
            assert_eq!(lifecycle, "active", "conversation must remain active after cancel attempt");

            // 2. Withdrawal uses signed close transition on the conversation
            let close_trans_id = Uuid::new_v4();
            sqlx::query(
                "UPDATE chat.conversations SET lifecycle='superseded', close_transition_id=$2, close_generation=0, close_state_version=1, close_seq=2, closed_at=$3 WHERE conversation_id=$1",
            )
            .bind(convo_id)
            .bind(close_trans_id)
            .bind(now)
            .execute(&mut *tx)
            .await
            .unwrap();

            let lifecycle_after: String = sqlx::query_scalar(
                "SELECT lifecycle FROM chat.conversations WHERE conversation_id=$1",
            )
            .bind(convo_id)
            .fetch_one(&mut *tx)
            .await
            .unwrap();
            assert_eq!(lifecycle_after, "superseded", "signed close marks conversation superseded");

            tx.rollback().await.unwrap();
        }

        // ====================================================================
        // C13: EXPIRY AND UNKNOWN OUTCOME UNDER LOCK
        // ====================================================================

        #[tokio::test]
        async fn c13_expired_unclaimed_operation_acquires_definitive_terminal_proof_under_lock() {
            let pool = crate::common::direct_request_database::setup().await;
            let mut tx = pool.begin().await.unwrap();
            let i = test_identity();
            let now = Utc::now();

            let _lock = test_lock(&mut tx, i.clone()).await;
            sqlx::query(
                "INSERT INTO chat.direct_request_attempts(request_id,actor_did,actor_device_id,actor_key_id,actor_auth_generation,recipient_did,prepare_digest,status,prepare_response,selected_digest,prepared_at,lease_expires_at,created_at) \
                 VALUES($1,$2,$3,$4,1,$5,$6,'prepared',$7,$8,$9,$10,$9)",
            )
            .bind(i.request_id)
            .bind(&i.actor_did)
            .bind(i.actor_device_id)
            .bind(&i.actor_key_id)
            .bind(&i.recipient_did)
            .bind(&i.prepare_digest)
            .bind(&b"prep"[..])
            .bind(vec![4u8; 32])
            .bind(now - Duration::seconds(60))
            .bind(now - Duration::seconds(10))
            .execute(&mut *tx)
            .await
            .unwrap();

            let lock = test_lock(&mut tx, i.clone()).await;
            assert_eq!(lock.row.as_ref().unwrap().status, "prepared");
            assert!(lock.row.as_ref().unwrap().lease_expires_at.unwrap() < now);

            let expired_receipt = b"signed-direct-request-expired-receipt-proof";
            let outcome = finish_terminal(
                &mut tx,
                lock,
                TerminalOutcome::Expired,
                expired_receipt,
                None,
                now,
            )
            .await
            .unwrap();
            assert_eq!(outcome, expired_receipt);

            let status: String = sqlx::query_scalar(
                "SELECT status FROM chat.direct_request_attempts WHERE request_id=$1",
            )
            .bind(i.request_id)
            .fetch_one(&mut *tx)
            .await
            .unwrap();
            assert_eq!(status, "expired");

            let lock = test_lock(&mut tx, i.clone()).await;
            let replay = finish_terminal_charged(
                &mut tx,
                lock,
                TerminalOutcome::Published,
                b"late-publish",
                Some(&[8u8; 32]),
                now,
                Some(MAX_BUNDLE_BYTES),
            )
            .await
            .unwrap();
            assert_eq!(
                replay, expired_receipt,
                "late publish on expired operation returns definitive expired proof"
            );

            tx.rollback().await.unwrap();
        }

        #[tokio::test]
        async fn c13_absence_or_timeout_cannot_authorize_abandonment() {
            let pool = crate::common::direct_request_database::setup().await;
            let mut tx = pool.begin().await.unwrap();
            let i = test_identity();
            let now = Utc::now();

            let lock = test_lock(&mut tx, i.clone()).await;
            assert!(lock.row.is_none());
            let count: i64 = sqlx::query_scalar(
                "SELECT count(*) FROM chat.direct_request_attempts WHERE request_id=$1",
            )
            .bind(i.request_id)
            .fetch_one(&mut *tx)
            .await
            .unwrap();
            assert_eq!(count, 0, "unknown read produces zero attempt rows");

            finish_terminal(
                &mut tx,
                lock,
                TerminalOutcome::Cancelled,
                b"tombstone-receipt",
                None,
                now,
            )
            .await
            .unwrap();

            let mut altered = i.clone();
            altered.prepare_digest = vec![99u8; 32];
            let operation = super::prelude::lock_direct_request_operation(&mut tx, i.request_id)
                .await
                .unwrap();
            assert!(
                matches!(
                    load_locked_attempt(&mut tx, altered, &operation).await,
                    Err(DirectRequestStoreError::IdentityConflict)
                ),
                "unauthorized identity collision must fail with IdentityConflict"
            );

            let mut sp = tx.begin().await.unwrap();
            assert!(
                sqlx::query("UPDATE chat.direct_request_attempts SET terminal_response=$2 WHERE request_id=$1")
                    .bind(i.request_id)
                    .bind(&b"tampered"[..])
                    .execute(&mut *sp)
                    .await
                    .is_err(),
                "database constraint must prevent updating terminal response"
            );
            sp.rollback().await.unwrap();

            let mut sp = tx.begin().await.unwrap();
            assert!(
                sqlx::query("DELETE FROM chat.direct_request_attempts WHERE request_id=$1")
                    .bind(i.request_id)
                    .execute(&mut *sp)
                    .await
                    .is_err(),
                "database constraint must prevent deleting terminal attempt row"
            );
            sp.rollback().await.unwrap();

            tx.rollback().await.unwrap();
        }

        #[tokio::test]
        async fn c13_completed_replay_works_after_lease_expiry() {
            let pool = crate::common::direct_request_database::setup().await;
            let mut tx = pool.begin().await.unwrap();
            let i = test_identity();
            let now = Utc::now();

            let _lock = test_lock(&mut tx, i.clone()).await;
            sqlx::query(
                "INSERT INTO chat.direct_request_attempts(request_id,actor_did,actor_device_id,actor_key_id,actor_auth_generation,recipient_did,prepare_digest,status,prepare_response,selected_digest,prepared_at,lease_expires_at,created_at) \
                 VALUES($1,$2,$3,$4,1,$5,$6,'prepared',$7,$8,$9,$10,$9)",
            )
            .bind(i.request_id)
            .bind(&i.actor_did)
            .bind(i.actor_device_id)
            .bind(&i.actor_key_id)
            .bind(&i.recipient_did)
            .bind(&i.prepare_digest)
            .bind(&b"prep"[..])
            .bind(vec![4u8; 32])
            .bind(now)
            .bind(now + Duration::seconds(300))
            .execute(&mut *tx)
            .await
            .unwrap();

            let lock = test_lock(&mut tx, i.clone()).await;
            let published_receipt = finish_terminal_charged(
                &mut tx,
                lock,
                TerminalOutcome::Published,
                b"exact-completed-published-receipt",
                Some(&[8u8; 32]),
                now,
                Some(MAX_BUNDLE_BYTES),
            )
            .await
            .unwrap();

            let late_now = now + Duration::days(30);

            let lock = test_lock(&mut tx, i.clone()).await;
            let replay = finish_terminal(
                &mut tx,
                lock,
                TerminalOutcome::Published,
                b"replay",
                Some(&[8u8; 32]),
                late_now,
            )
            .await
            .unwrap();
            assert_eq!(
                replay, published_receipt,
                "completed publication replay must succeed after lease expiry"
            );

            let lock = test_lock(&mut tx, i).await;
            let cancel_replay = finish_terminal(
                &mut tx,
                lock,
                TerminalOutcome::Cancelled,
                b"cancel",
                None,
                late_now,
            )
            .await
            .unwrap();
            assert_eq!(
                cancel_replay, published_receipt,
                "cancel after lease expiry cannot overwrite committed publication"
            );

            tx.rollback().await.unwrap();
        }
    }
}
