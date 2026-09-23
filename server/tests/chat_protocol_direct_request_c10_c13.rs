//! Server-side qualification for direct request cases C10, C12, C13.
//!
//! Case C10: Inject failure at each publication write boundary; observer sees no
//!           empty invitation, partial Welcome, partial interval, first ciphertext
//!           without bootstrap, or notification before commit.
//! Case C12: Barrier-controlled cancel vs delayed prepare/publish incl. preparation
//!           timeout; unknown-to-cancelled tombstone blocks late prepare and publish;
//!           publish-first cancel returns committed identity; withdrawal uses signed close.
//! Case C13: Expired/unclaimed operation acquires definitive terminal proof under lock;
//!           absence/timeout never authorizes abandonment; completed replay works
//!           after lease expiry.
//!
//! No shared schema mutation; dedicated loopback database used for fault injection.
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

        async fn seed_key_package_and_grant(
            pool: &PgPool,
            did: &str,
            device_id: Uuid,
            key_id: &str,
            package_ref: &[u8],
            grant_id: Uuid,
        ) {
            let now = Utc::now();
            let not_before = now - Duration::hours(1);
            let not_after = now + Duration::days(28);
            let init_key = Sha256::digest(format!("init-{}", Uuid::new_v4()).as_bytes()).to_vec();
            sqlx::query(
                "INSERT INTO chat.key_packages(key_package_ref,wrapper_bytes,wrapper_sha256,init_key,owner_did,owner_device_id,owner_key_id,owner_auth_generation,usage_scope,status,not_before,not_after,created_at) \
                 VALUES($1,$2,$3,$4,$5,$6,$7,1,'direct-request','available',$8,$9,$10) \
                 ON CONFLICT (key_package_ref) DO NOTHING",
            )
            .bind(package_ref)
            .bind(&b"key-package-wrapper"[..])
            .bind(Sha256::digest(b"key-package-wrapper").as_slice())
            .bind(&init_key)
            .bind(did)
            .bind(device_id)
            .bind(key_id)
            .bind(not_before)
            .bind(not_after)
            .bind(now)
            .execute(pool)
            .await
            .unwrap();

            sqlx::query(
                "INSERT INTO chat.direct_request_grants(grant_id,revision,owner_did,owner_device_id,owner_key_id,auth_generation,capability_revision,purpose,protocol_version,profile,key_package_ref,signed_grant,grant_digest,expires_at,created_at) \
                 VALUES($1,1,$2,$3,$4,1,1,'direct-request-bootstrap','2','encryptedIntroduction1',$5,$6,$7,$8,$9) \
                 ON CONFLICT (grant_id) DO NOTHING",
            )
            .bind(grant_id)
            .bind(did)
            .bind(device_id)
            .bind(key_id)
            .bind(package_ref)
            .bind(&b"signed-grant-bytes"[..])
            .bind(Sha256::digest(b"signed-grant-bytes").as_slice())
            .bind(not_after)
            .bind(now)
            .execute(pool)
            .await
            .unwrap();
        }

        async fn assert_observer_invariants(
            observer: &PgPool,
            convo_id: Uuid,
            request_id: Uuid,
            package_ref: &[u8],
        ) {
            let pending_invitations: i64 = sqlx::query_scalar(
                "SELECT count(*) FROM chat.participants WHERE conversation_id=$1 AND status='pending'",
            )
            .bind(convo_id)
            .fetch_one(observer)
            .await
            .unwrap();
            assert_eq!(
                pending_invitations, 0,
                "observer must never see empty invitation"
            );

            let publications: i64 = sqlx::query_scalar(
                "SELECT count(*) FROM chat.direct_request_publications WHERE request_id=$1",
            )
            .bind(request_id)
            .fetch_one(observer)
            .await
            .unwrap();
            assert_eq!(
                publications, 0,
                "observer must never see uncommitted publication"
            );

            let deliveries: i64 = sqlx::query_scalar(
                "SELECT count(*) FROM chat.direct_request_device_deliveries WHERE request_id=$1",
            )
            .bind(request_id)
            .fetch_one(observer)
            .await
            .unwrap();
            assert_eq!(
                deliveries, 0,
                "observer must never see partial welcome deliveries"
            );

            let intervals: i64 = sqlx::query_scalar(
                "SELECT count(*) FROM chat.application_intervals WHERE conversation_id=$1",
            )
            .bind(convo_id)
            .fetch_one(observer)
            .await
            .unwrap();
            assert_eq!(
                intervals, 0,
                "observer must never see partial application intervals"
            );

            let entries: i64 = sqlx::query_scalar(
                "SELECT count(*) FROM chat.entries WHERE conversation_id=$1",
            )
            .bind(convo_id)
            .fetch_one(observer)
            .await
            .unwrap();
            assert_eq!(
                entries, 0,
                "observer must never see ciphertext without bootstrap"
            );

            let push_events: i64 = sqlx::query_scalar(
                "SELECT count(*) FROM chat.direct_request_push_events WHERE request_id=$1",
            )
            .bind(request_id)
            .fetch_one(observer)
            .await
            .unwrap();
            assert_eq!(
                push_events, 0,
                "observer must never see notification before commit"
            );

            let outbox: i64 = sqlx::query_scalar(
                "SELECT count(*) FROM chat.outbox o JOIN chat.events e ON e.event_position=o.event_position WHERE e.payload_bytes::text LIKE $1",
            )
            .bind(format!("%{convo_id}%"))
            .fetch_one(observer)
            .await
            .unwrap();
            assert_eq!(
                outbox, 0,
                "observer must never see notification outbox before commit"
            );

            let package_status: String = sqlx::query_scalar(
                "SELECT status FROM chat.key_packages WHERE key_package_ref=$1",
            )
            .bind(package_ref)
            .fetch_one(observer)
            .await
            .unwrap();
            assert_ne!(
                package_status, "consumed",
                "key package must not be consumed before commit"
            );
        }

        // ====================================================================
        // C10: ATOMIC PUBLICATION FAILURES
        // ====================================================================

        #[tokio::test]
        async fn c10_atomic_publication_write_boundaries_observer_invariants() {
            let pool = crate::common::direct_request_database::setup().await;
            let observer = pool.clone();

            let cursor_key = URL_SAFE_NO_PAD.encode([1u8; 32]);
            let instance_id = Uuid::new_v4();
            sqlx::query(
                "INSERT INTO chat.protocol_instances(singleton,protocol_version,protocol_instance_id,cursor_key_id) \
                 VALUES(TRUE,'1',$1,$2) ON CONFLICT DO NOTHING",
            )
            .bind(instance_id)
            .bind(&cursor_key)
            .execute(&pool)
            .await
            .unwrap();

            for fail_boundary in 1..=16 {
                let i = test_identity();
                let convo_id = Uuid::new_v4();
                let entry_id = Uuid::new_v4();
                let metadata_id = Uuid::new_v4();
                let event_id = Uuid::new_v4();
                let outbox_id = Uuid::new_v4();
                let leaf_alice = Uuid::new_v4();
                let leaf_bob = Uuid::new_v4();
                let participant_alice = Uuid::new_v4();
                let participant_bob = Uuid::new_v4();
                let bob_device_id = Uuid::new_v4();
                let pkg_ref = Sha256::digest(format!("pkg-{}", Uuid::new_v4()).as_bytes()).to_vec();
                let grant_id = Uuid::new_v4();
                let now = Utc::now();
                let horizon = now + Duration::days(25);
                let mut alice_pub = [0u8; 32];
                rand::thread_rng().fill(&mut alice_pub);
                let i = test_identity_with_key(&alice_pub);

                seed_device_and_keys(&pool, &i.actor_did, i.actor_device_id, &alice_pub).await;
                let mut bob_pub = [0u8; 32];
                rand::thread_rng().fill(&mut bob_pub);
                let bob_key_id = seed_device_and_keys(&pool, &i.recipient_did, bob_device_id, &bob_pub).await;
                seed_key_package_and_grant(&pool, &i.recipient_did, bob_device_id, &bob_key_id, &pkg_ref, grant_id).await;

                let mut tx = pool.begin().await.unwrap();

                sqlx::query(
                    "INSERT INTO chat.direct_request_attempts(request_id,actor_did,actor_device_id,actor_key_id,actor_auth_generation,recipient_did,prepare_digest,status,prepare_response,selected_digest,prepared_at,lease_expires_at,reserved_bytes,created_at) \
                     VALUES($1,$2,$3,$4,1,$5,$6,'prepared',$7,$6,$8,$9,16384,$8)",
                )
                .bind(i.request_id)
                .bind(&i.actor_did)
                .bind(i.actor_device_id)
                .bind(&i.actor_key_id)
                .bind(&i.recipient_did)
                .bind(&i.prepare_digest)
                .bind(&b"prep"[..])
                .bind(now)
                .bind(now + Duration::seconds(300))
                .execute(&mut *tx)
                .await
                .unwrap();
                sqlx::query(
                    "INSERT INTO chat.direct_request_selected_devices(request_id,owner_did,owner_device_id,owner_key_id,auth_generation,grant_id,grant_digest,capability_revision,key_package_ref) \
                     VALUES($1,$2,$3,$4,1,$5,$6,1,$7)",
                )
                .bind(i.request_id)
                .bind(&i.recipient_did)
                .bind(bob_device_id)
                .bind(&bob_key_id)
                .bind(grant_id)
                .bind(Sha256::digest(b"signed-grant-bytes").as_slice())
                .bind(&pkg_ref)
                .execute(&mut *tx)
                .await
                .unwrap();

                sqlx::query("UPDATE chat.key_packages SET status='reserved' WHERE key_package_ref=$1")
                    .bind(&pkg_ref)
                    .execute(&mut *tx)
                    .await
                    .unwrap();


                // Boundary 1: direct_request_attempts status update
                sqlx::query(
                    "UPDATE chat.direct_request_attempts \
                     SET status='published',terminal_at=$2,terminal_response=$5,terminal_response_sha256=$3,publication_digest=$4 \
                     WHERE request_id=$1",
                )
                .bind(i.request_id)
                .bind(now)
                .bind(Sha256::digest(b"term").to_vec())
                .bind(vec![9u8; 32])
                .bind(&b"term"[..])
                .execute(&mut *tx)
                .await
                .unwrap();

                if fail_boundary == 1 {
                    assert_observer_invariants(&observer, convo_id, i.request_id, &pkg_ref).await;
                    tx.rollback().await.unwrap();
                    assert_observer_invariants(&observer, convo_id, i.request_id, &pkg_ref).await;
                    continue;
                }

                // Boundary 2: chat.conversations
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

                if fail_boundary == 2 {
                    assert_observer_invariants(&observer, convo_id, i.request_id, &pkg_ref).await;
                    tx.rollback().await.unwrap();
                    assert_observer_invariants(&observer, convo_id, i.request_id, &pkg_ref).await;
                    continue;
                }

                // Boundary 3: chat.generations
                sqlx::query(
                    "INSERT INTO chat.generations(conversation_id,generation,group_id,lifecycle,genesis_group_info_bytes,genesis_group_info_sha256,current_state_version,activated_seq,activated_at) \
                     VALUES($1,0,$2,'active',$5,$3,1,1,$4)",
                )
                .bind(convo_id)
                .bind(&[1u8; 32])
                .bind(Sha256::digest(b"genesis_group_info").to_vec())
                .bind(now)
                .bind(&b"genesis_group_info"[..])
                .execute(&mut *tx)
                .await
                .unwrap();

                if fail_boundary == 3 {
                    assert_observer_invariants(&observer, convo_id, i.request_id, &pkg_ref).await;
                    tx.rollback().await.unwrap();
                    assert_observer_invariants(&observer, convo_id, i.request_id, &pkg_ref).await;
                    continue;
                }

                // Boundary 4: chat.generation_states
                sqlx::query(
                    "INSERT INTO chat.generation_states(conversation_id,generation,state_version,group_id,epoch,group_context_hash,confirmation_tag,lifecycle,state_kind,producing_transition_id,public_snapshot_bytes,snapshot_sha256,tree_summary_bytes,tree_summary_sha256,leaf_count,created_at) \
                     VALUES($1,0,1,$2,1,$3,$4,'active','directRequestPublication',$5,$9,$6,$10,$7,2,$8)",
                )
                .bind(convo_id)
                .bind(&[1u8; 32])
                .bind(&[2u8; 32])
                .bind(&[3u8; 32])
                .bind(i.request_id)
                .bind(Sha256::digest(b"snap").to_vec())
                .bind(Sha256::digest(b"tree").to_vec())
                .bind(now)
                .bind(&b"snap"[..])
                .bind(&b"tree"[..])
                .execute(&mut *tx)
                .await
                .unwrap();

                if fail_boundary == 4 {
                    assert_observer_invariants(&observer, convo_id, i.request_id, &pkg_ref).await;
                    tx.rollback().await.unwrap();
                    assert_observer_invariants(&observer, convo_id, i.request_id, &pkg_ref).await;
                    continue;
                }

                // Boundary 5: chat.transitions
                sqlx::query(
                    "INSERT INTO chat.transitions(transition_id,conversation_id,kind,actor_did,actor_device_id,actor_key_id,actor_auth_generation,actor_role,actor_device_status,signed_request_bytes,unsigned_projection_bytes,signing_transcript_bytes,request_digest,signature,next_generation,next_state_version,metadata_snapshot_id,entry_seq,accepted_at) \
                     VALUES($1,$2,'directRequestPublication',$3,$4,$5,1,'admin','active',$9,$10,$11,$6,$12,0,1,$7,1,$8)",
                )
                .bind(i.request_id)
                .bind(convo_id)
                .bind(&i.actor_did)
                .bind(i.actor_device_id)
                .bind(&i.actor_key_id)
                .bind(Sha256::digest(b"trans").to_vec())
                .bind(metadata_id)
                .bind(now)
                .bind(&b"signed"[..])
                .bind(&b"proj"[..])
                .bind(&b"trans"[..])
                .bind(vec![7u8; 64])
                .execute(&mut *tx)
                .await
                .unwrap();

                if fail_boundary == 5 {
                    assert_observer_invariants(&observer, convo_id, i.request_id, &pkg_ref).await;
                    tx.rollback().await.unwrap();
                    assert_observer_invariants(&observer, convo_id, i.request_id, &pkg_ref).await;
                    continue;
                }

                // Boundary 6: chat.entries
                sqlx::query(
                    "INSERT INTO chat.entries(conversation_id,seq,entry_id,entry_kind,accepted_payload_bytes,accepted_payload_sha256,signed_request_bytes,request_digest,signature,server_fields_bytes,outer_entry_fingerprint,actor_did,actor_device_id,actor_key_id,actor_auth_generation,generation,state_version,transition_id,received_at) \
                     VALUES($1,1,$2,'blue.catbird.chat.defs#directRequestEntry',$11,$3,$12,$4,$13,$14,$5,$6,$7,$8,1,0,1,$9,$10)",
                )
                .bind(convo_id)
                .bind(entry_id)
                .bind(Sha256::digest(b"entry").to_vec())
                .bind(Sha256::digest(b"trans").to_vec())
                .bind(&[8u8; 32])
                .bind(&i.actor_did)
                .bind(i.actor_device_id)
                .bind(&i.actor_key_id)
                .bind(i.request_id)
                .bind(now)
                .bind(&b"entry"[..])
                .bind(&b"signed"[..])
                .bind(vec![7u8; 64])
                .bind(&b"fields"[..])
                .execute(&mut *tx)
                .await
                .unwrap();

                if fail_boundary == 6 {
                    assert_observer_invariants(&observer, convo_id, i.request_id, &pkg_ref).await;
                    tx.rollback().await.unwrap();
                    assert_observer_invariants(&observer, convo_id, i.request_id, &pkg_ref).await;
                    continue;
                }

                // Boundary 7: chat.entry_recipients
                sqlx::query(
                    "INSERT INTO chat.entry_recipients(conversation_id,seq,user_did,device_id,entitlement_kind) \
                     VALUES($1,1,$2,$3,'control')",
                )
                .bind(convo_id)
                .bind(&i.actor_did)
                .bind(i.actor_device_id)
                .execute(&mut *tx)
                .await
                .unwrap();

                if fail_boundary == 7 {
                    assert_observer_invariants(&observer, convo_id, i.request_id, &pkg_ref).await;
                    tx.rollback().await.unwrap();
                    assert_observer_invariants(&observer, convo_id, i.request_id, &pkg_ref).await;
                    continue;
                }

                // Boundary 8: chat.metadata_snapshots
                sqlx::query(
                    "INSERT INTO chat.metadata_snapshots(metadata_snapshot_id,conversation_id,generation,state_version,group_id,epoch,group_context_hash,confirmation_tag,producing_transition_id,origin_transition_id,metadata_version,nonce,ciphertext,ciphertext_sha256,ciphertext_size,author_did,author_device_id,author_key_id,author_public_key,author_auth_generation,author_origin_seq,author_role,author_device_status,created_at) \
                     VALUES($1,$2,0,1,$3,1,$4,$5,$6,$6,1,$12,$13,$7,23,$8,$9,$10,$14,1,1,'admin','active',$11)",
                )
                .bind(metadata_id)
                .bind(convo_id)
                .bind(&[1u8; 32])
                .bind(&[2u8; 32])
                .bind(&[3u8; 32])
                .bind(i.request_id)
                .bind(Sha256::digest(b"metadata_ciphertext_16b").to_vec())
                .bind(&i.actor_did)
                .bind(i.actor_device_id)
                .bind(&i.actor_key_id)
                .bind(now)
                .bind(&b"nonce_12byte"[..])
                .bind(&b"metadata_ciphertext_16b"[..])
                .bind(&alice_pub)
                .execute(&mut *tx)
                .await
                .unwrap();

                if fail_boundary == 8 {
                    assert_observer_invariants(&observer, convo_id, i.request_id, &pkg_ref).await;
                    tx.rollback().await.unwrap();
                    assert_observer_invariants(&observer, convo_id, i.request_id, &pkg_ref).await;
                    continue;
                }

                // Boundary 9: chat.participants (empty invitation check!)
                sqlx::query(
                    "INSERT INTO chat.participants(participant_period_id,conversation_id,user_did,status,role,role_transition_id,role_changed_at,created_by_did,created_by_device_id,invitation_transition_id,invitation_entry_id,invited_at,current_membership,created_at) \
                     VALUES($1,$2,$3,'active','admin',$4,$5,$3,$6,NULL,NULL,NULL,true,$5), \
                           ($7,$2,$8,'pending','admin',$4,$5,$3,$6,$4,$9,$5,true,$5)",
                )
                .bind(participant_alice)
                .bind(convo_id)
                .bind(&i.actor_did)
                .bind(i.request_id)
                .bind(now)
                .bind(i.actor_device_id)
                .bind(participant_bob)
                .bind(&i.recipient_did)
                .bind(entry_id)
                .execute(&mut *tx)
                .await
                .unwrap();

                if fail_boundary == 9 {
                    assert_observer_invariants(&observer, convo_id, i.request_id, &pkg_ref).await;
                    tx.rollback().await.unwrap();
                    assert_observer_invariants(&observer, convo_id, i.request_id, &pkg_ref).await;
                    continue;
                }

                // Boundary 10: chat.direct_request_publications
                sqlx::query(
                    "INSERT INTO chat.direct_request_publications(request_id,conversation_id,generation,state_version,first_message_id,actor_did,actor_device_id,actor_key_id,recipient_did,context_hash,preparation_digest,publication_digest,signed_publication,request_entry,request_entry_sha256,final_group_info,final_group_info_sha256,full_welcome,full_welcome_sha256,initial_ciphertext,initial_ciphertext_sha256,metadata_snapshot,metadata_snapshot_sha256,import_until,created_at,actor_auth_generation) \
                     VALUES($1,$2,0,1,$3,$4,$5,$6,$7,$8,$9,$10,$18,$19,$11,$20,$12,$21,$13,$22,$14,$23,$15,$16,$17,1)",
                )
                .bind(i.request_id)
                .bind(convo_id)
                .bind(Uuid::new_v4())
                .bind(&i.actor_did)
                .bind(i.actor_device_id)
                .bind(&i.actor_key_id)
                .bind(&i.recipient_did)
                .bind(&[4u8; 32])
                .bind(&i.prepare_digest)
                .bind(&[9u8; 32])
                .bind(Sha256::digest(b"entry").to_vec())
                .bind(Sha256::digest(b"final_group_info").to_vec())
                .bind(Sha256::digest(b"full_welcome_bytes").to_vec())
                .bind(Sha256::digest(b"initial_ciphertext_bytes").to_vec())
                .bind(Sha256::digest(b"metadata_snapshot_bytes").to_vec())
                .bind(horizon)
                .bind(now)
                .bind(&b"signed"[..])
                .bind(&b"entry"[..])
                .bind(&b"final_group_info"[..])
                .bind(&b"full_welcome_bytes"[..])
                .bind(&b"initial_ciphertext_bytes"[..])
                .bind(&b"metadata_snapshot_bytes"[..])
                .execute(&mut *tx)
                .await
                .unwrap();

                if fail_boundary == 10 {
                    assert_observer_invariants(&observer, convo_id, i.request_id, &pkg_ref).await;
                    tx.rollback().await.unwrap();
                    assert_observer_invariants(&observer, convo_id, i.request_id, &pkg_ref).await;
                    continue;
                }

                // Boundary 11: chat.direct_request_retained_charges
                sqlx::query(
                    "INSERT INTO chat.direct_request_retained_charges(request_id,charged_bytes,model_version,recorded_at) \
                     VALUES($1,16384,1,$2)",
                )
                .bind(i.request_id)
                .bind(now)
                .execute(&mut *tx)
                .await
                .unwrap();

                if fail_boundary == 11 {
                    assert_observer_invariants(&observer, convo_id, i.request_id, &pkg_ref).await;
                    tx.rollback().await.unwrap();
                    assert_observer_invariants(&observer, convo_id, i.request_id, &pkg_ref).await;
                    continue;
                }

                // Boundary 12: chat.member_devices
                let cred_alice = format!("{}#{}", i.actor_did, i.actor_device_id).into_bytes();
                let cred_bob = format!("{}#{}", i.recipient_did, bob_device_id).into_bytes();
                sqlx::query(
                    "INSERT INTO chat.member_devices(leaf_period_id,participant_period_id,conversation_id,generation,user_did,device_id,leaf_index,basic_credential,leaf_signature_key,leaf_key_id,leaf_auth_generation,origin,join_key_package_ref,joined_state_version,joined_transition_id,joined_seq,active,created_at) \
                     VALUES($1,$2,$3,0,$4,$5,0,$14,$15,$6,1,'genesis',NULL,1,$7,1,true,$8), \
                           ($9,$10,$3,0,$11,$12,1,$16,$17,$18,1,'keyPackage',$13,1,$7,1,true,$8)",
                )
                .bind(leaf_alice)
                .bind(participant_alice)
                .bind(convo_id)
                .bind(&i.actor_did)
                .bind(i.actor_device_id)
                .bind(&i.actor_key_id)
                .bind(i.request_id)
                .bind(now)
                .bind(leaf_bob)
                .bind(participant_bob)
                .bind(&i.recipient_did)
                .bind(bob_device_id)
                .bind(&pkg_ref)
                .bind(&cred_alice[..])
                .bind(&alice_pub)
                .bind(&cred_bob[..])
                .bind(&bob_pub)
                .bind(&bob_key_id)
                .execute(&mut *tx)
                .await
                .unwrap();

                if fail_boundary == 12 {
                    assert_observer_invariants(&observer, convo_id, i.request_id, &pkg_ref).await;
                    tx.rollback().await.unwrap();
                    assert_observer_invariants(&observer, convo_id, i.request_id, &pkg_ref).await;
                    continue;
                }

                // Boundary 13: chat.application_intervals
                sqlx::query(
                    "INSERT INTO chat.application_intervals(membership_interval_id,conversation_id,generation,recipient_did,recipient_device_id,start_seq,opening_kind,opening_transition_id,opening_outer_entry_fingerprint,opening_state_version,opening_group_id,opening_epoch,opening_group_context_hash,opening_confirmation_tag,opening_leaf_period_id,created_at) \
                     VALUES($1,$2,0,$3,$4,1,'directRequest',$5,$6,1,$7,1,$8,$9,$10,$11), \
                           ($12,$2,0,$13,$14,1,'directRequest',$5,$6,1,$7,1,$8,$9,$15,$11)",
                )
                .bind(Uuid::new_v4())
                .bind(convo_id)
                .bind(&i.actor_did)
                .bind(i.actor_device_id)
                .bind(i.request_id)
                .bind(&[8u8; 32])
                .bind(&[1u8; 32])
                .bind(&[2u8; 32])
                .bind(&[3u8; 32])
                .bind(leaf_alice)
                .bind(now)
                .bind(Uuid::new_v4())
                .bind(&i.recipient_did)
                .bind(bob_device_id)
                .bind(leaf_bob)
                .execute(&mut *tx)
                .await
                .unwrap();

                if fail_boundary == 13 {
                    assert_observer_invariants(&observer, convo_id, i.request_id, &pkg_ref).await;
                    tx.rollback().await.unwrap();
                    assert_observer_invariants(&observer, convo_id, i.request_id, &pkg_ref).await;
                    continue;
                }

                // Boundary 14: chat.direct_request_device_deliveries
                sqlx::query(
                    "INSERT INTO chat.direct_request_device_deliveries(request_id,owner_did,owner_device_id,owner_key_id,auth_generation,key_package_ref,grant_id,grant_revision,grant_digest,leaf_index,import_until,provenance,provenance_sha256) \
                     VALUES($1,$2,$3,$10,1,$4,$5,1,$6,1,$7,$9,$8)",
                )
                .bind(i.request_id)
                .bind(&i.recipient_did)
                .bind(bob_device_id)
                .bind(&pkg_ref)
                .bind(grant_id)
                .bind(Sha256::digest(b"signed-grant-bytes").to_vec())
                .bind(horizon)
                .bind(Sha256::digest(b"prov").to_vec())
                .bind(&b"prov"[..])
                .bind(&bob_key_id)
                .execute(&mut *tx)
                .await
                .unwrap();

                if fail_boundary == 14 {
                    assert_observer_invariants(&observer, convo_id, i.request_id, &pkg_ref).await;
                    tx.rollback().await.unwrap();
                    assert_observer_invariants(&observer, convo_id, i.request_id, &pkg_ref).await;
                    continue;
                }

                // Boundary 15: chat.key_packages update
                sqlx::query(
                    "UPDATE chat.key_packages SET status='consumed',terminal_transition_id=$2,terminal_at=$3 WHERE key_package_ref=$1",
                )
                .bind(&pkg_ref)
                .bind(i.request_id)
                .bind(now)
                .execute(&mut *tx)
                .await
                .unwrap();

                if fail_boundary == 15 {
                    assert_observer_invariants(&observer, convo_id, i.request_id, &pkg_ref).await;
                    tx.rollback().await.unwrap();
                    assert_observer_invariants(&observer, convo_id, i.request_id, &pkg_ref).await;
                    continue;
                }

                // Boundary 16: events, outbox, push events
                let event_payload = serde_json::to_vec(&serde_json::json!({
                    "$type": "blue.catbird.chat.defs#conversationChangedEvent",
                    "conversationId": convo_id.to_string(),
                }))
                .unwrap();
                let position: i64 = sqlx::query_scalar(
                    "INSERT INTO chat.events(event_id,event_kind,payload_bytes,payload_sha256,created_at,protocol_instance_id) \
                     SELECT $1,'conversationChanged',$2,$3,$4,protocol_instance_id FROM chat.protocol_instances RETURNING event_position",
                )
                .bind(event_id)
                .bind(&event_payload)
                .bind(Sha256::digest(&event_payload).to_vec())
                .bind(now)
                .fetch_one(&mut *tx)
                .await
                .unwrap();

                sqlx::query(
                    "INSERT INTO chat.outbox(outbox_id,event_position,work_kind,status,next_attempt_at,created_at) \
                     VALUES($1,$2,'notification','pending',$3,$3)",
                )
                .bind(outbox_id)
                .bind(position)
                .bind(now)
                .execute(&mut *tx)
                .await
                .unwrap();

                sqlx::query(
                    "INSERT INTO chat.direct_request_push_events(event_id,request_id,event_position,outbox_id,conversation_id,first_message_id,sender_did,recipient_did,payload_digest,created_at) \
                     VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)",
                )
                .bind(event_id)
                .bind(i.request_id)
                .bind(position)
                .bind(outbox_id)
                .bind(convo_id)
                .bind(Uuid::new_v4())
                .bind(&i.actor_did)
                .bind(&i.recipient_did)
                .bind(&[5u8; 32])
                .bind(now)
                .execute(&mut *tx)
                .await
                .unwrap();

                // Check invariants before final commit
                assert_observer_invariants(&observer, convo_id, i.request_id, &pkg_ref).await;
                // Rollback simulating crash at final boundary
                tx.rollback().await.unwrap();
                // Verify post-rollback consistency
                assert_observer_invariants(&observer, convo_id, i.request_id, &pkg_ref).await;
            }
        }

        #[tokio::test]
        async fn c10_schema_fault_triggers_in_dedicated_loopback_db() {
            let fault_db_name = format!("catbird_dr_fault_{}", &Uuid::new_v4().simple().to_string()[..16]);
            let admin_pool = sqlx::PgPool::connect("postgresql://127.0.0.1:5432/postgres")
                .await
                .unwrap();

            // Create dedicated empty loopback database
            sqlx::query(&format!("CREATE DATABASE {fault_db_name};"))
                .execute(&admin_pool)
                .await
                .unwrap();

            // Clone schema via pg_dump without requiring exclusive lock on source
            let dump_status = std::process::Command::new("sh")
                .arg("-c")
                .arg(format!(
                    "pg_dump -s postgresql://127.0.0.1:5432/catbird_direct_requests_test_20260919 | psql postgresql://127.0.0.1:5432/{fault_db_name} >/dev/null"
                ))
                .status()
                .expect("pg_dump schema clone failed");
            assert!(dump_status.success(), "pg_dump schema transfer failed");

            let fault_db_url = format!("postgresql://127.0.0.1:5432/{fault_db_name}");
            let fault_pool = sqlx::PgPool::connect(&fault_db_url).await.unwrap();

            // Install schema-level fault trigger on direct_request_publications
            sqlx::query(
                r#"
                CREATE OR REPLACE FUNCTION chat.c10_fault_injection() RETURNS TRIGGER AS $$
                BEGIN
                    RAISE EXCEPTION 'injected schema-level write failure at %', TG_TABLE_NAME
                        USING ERRCODE = '23514';
                END;
                $$ LANGUAGE plpgsql;
                "#,
            )
            .execute(&fault_pool)
            .await
            .unwrap();

            sqlx::query(
                "CREATE TRIGGER fault_dr_publications BEFORE INSERT ON chat.direct_request_publications \
                 FOR EACH ROW EXECUTE FUNCTION chat.c10_fault_injection();",
            )
            .execute(&fault_pool)
            .await
            .unwrap();

            let i = test_identity();
            let convo_id = Uuid::new_v4();
            let bob_device_id = Uuid::new_v4();
            let pkg_ref = Sha256::digest(format!("fault-pkg-{}", Uuid::new_v4()).as_bytes()).to_vec();
            let grant_id = Uuid::new_v4();
            let now = Utc::now();
            let mut alice_pub = [0u8; 32];
            rand::thread_rng().fill(&mut alice_pub);
            let i = test_identity_with_key(&alice_pub);

            seed_device_and_keys(&fault_pool, &i.actor_did, i.actor_device_id, &alice_pub).await;
            let mut bob_pub = [0u8; 32];
            rand::thread_rng().fill(&mut bob_pub);
            let bob_key_id = seed_device_and_keys(&fault_pool, &i.recipient_did, bob_device_id, &bob_pub).await;
            seed_key_package_and_grant(&fault_pool, &i.recipient_did, bob_device_id, &bob_key_id, &pkg_ref, grant_id).await;

            let mut tx = fault_pool.begin().await.unwrap();

            sqlx::query(
                "INSERT INTO chat.direct_request_attempts(request_id,actor_did,actor_device_id,actor_key_id,actor_auth_generation,recipient_did,prepare_digest,status,prepare_response,selected_digest,prepared_at,lease_expires_at,reserved_bytes,created_at) \
                 VALUES($1,$2,$3,$4,1,$5,$6,'prepared',$7,$6,$8,$9,16384,$8)",
            )
            .bind(i.request_id)
            .bind(&i.actor_did)
            .bind(i.actor_device_id)
            .bind(&i.actor_key_id)
            .bind(&i.recipient_did)
            .bind(&i.prepare_digest)
            .bind(&b"prep"[..])
            .bind(now)
            .bind(now + Duration::seconds(300))
            .execute(&mut *tx)
            .await
            .unwrap();
            sqlx::query(
                "INSERT INTO chat.direct_request_selected_devices(request_id,owner_did,owner_device_id,owner_key_id,auth_generation,grant_id,grant_digest,capability_revision,key_package_ref) \
                 VALUES($1,$2,$3,$4,1,$5,$6,1,$7)",
            )
            .bind(i.request_id)
            .bind(&i.recipient_did)
            .bind(bob_device_id)
            .bind(&bob_key_id)
            .bind(grant_id)
            .bind(Sha256::digest(b"signed-grant-bytes").as_slice())
            .bind(&pkg_ref)
            .execute(&mut *tx)
            .await
            .unwrap();

            sqlx::query("UPDATE chat.key_packages SET status='reserved' WHERE key_package_ref=$1")
                .bind(&pkg_ref)
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

            // Inserting into direct_request_publications MUST fail due to trigger
            let pub_result = sqlx::query(
                "INSERT INTO chat.direct_request_publications(request_id,conversation_id,generation,state_version,first_message_id,actor_did,actor_device_id,actor_key_id,recipient_did,context_hash,preparation_digest,publication_digest,signed_publication,request_entry,request_entry_sha256,final_group_info,final_group_info_sha256,full_welcome,full_welcome_sha256,initial_ciphertext,initial_ciphertext_sha256,metadata_snapshot,metadata_snapshot_sha256,import_until,created_at,actor_auth_generation) \
                 VALUES($1,$2,0,1,$3,$4,$5,$6,$7,$8,$9,$10,$18,$19,$11,$20,$12,$21,$13,$22,$14,$23,$15,$16,$17,1)",
            )
            .bind(i.request_id)
            .bind(convo_id)
            .bind(Uuid::new_v4())
            .bind(&i.actor_did)
            .bind(i.actor_device_id)
            .bind(&i.actor_key_id)
            .bind(&i.recipient_did)
            .bind(&[4u8; 32])
            .bind(&i.prepare_digest)
            .bind(&[9u8; 32])
            .bind(Sha256::digest(b"entry").to_vec())
            .bind(Sha256::digest(b"final_group_info").to_vec())
            .bind(Sha256::digest(b"full_welcome_bytes").to_vec())
            .bind(Sha256::digest(b"initial_ciphertext_bytes").to_vec())
            .bind(Sha256::digest(b"metadata_snapshot_bytes").to_vec())
            .bind(now + Duration::days(25))
            .bind(now)
            .bind(&b"signed"[..])
            .bind(&b"entry"[..])
            .bind(&b"final_group_info"[..])
            .bind(&b"full_welcome_bytes"[..])
            .bind(&b"initial_ciphertext_bytes"[..])
            .bind(&b"metadata_snapshot_bytes"[..])
            .execute(&mut *tx)
            .await;

            assert!(pub_result.is_err(), "trigger must reject publication write");
            tx.rollback().await.unwrap();

            // Assert observer sees 0 rows in dedicated DB
            assert_observer_invariants(&fault_pool, convo_id, i.request_id, &pkg_ref).await;

            // Teardown dedicated DB
            drop(fault_pool);
            sqlx::query(&format!(
                "SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE datname='{fault_db_name}';"
            ))
            .execute(&admin_pool)
            .await
            .ok();
            sqlx::query(&format!("DROP DATABASE {fault_db_name};"))
                .execute(&admin_pool)
                .await
                .unwrap();
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
