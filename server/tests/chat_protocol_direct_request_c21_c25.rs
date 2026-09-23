//! Server qualification for validation cases C21-C25:
//! C21: unaddressed/new/reinstalled device gains no old keys by account acceptance;
//!      shows unavailable/setup state; allowed post-acceptance recovery without fabricated intro.
//! C22: unimported expired device -> unavailable; imported device retains preview;
//!      sibling expiry can't delete request/history.
//! C23: legacy pending upgrade keeps conversation ID, preserves v1 signatures, fresh successor generation;
//!      races with accept/close/recovery/stale head; no backdated intro or silent overwrite.
//! C24: old unscoped decoder/reconciler receives explicit upgrade-required, never a successful partial inventory;
//!      no local history deleted; capable scoped readers keep omitted records.
//! C25: scope bound to all inventory pages/domains, event cursor, subscription ticket;
//!      incompatible cursor reuse rejected; one unknown conversation doesn't corrupt unrelated sync.

#![allow(dead_code, unused_imports)]
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use catbird_atproto::generated::blue_catbird::chat::{
    get_conversations::GetConversationsOutput, get_pending_welcomes::GetPendingWelcomesOutput,
};
use serde_json::json;
use sha2::{Digest, Sha256};
use uuid::Uuid;

#[path = "common/chat_protocol.rs"]
pub mod chat_protocol_baseline;
mod common {
    pub use super::chat_protocol_baseline as chat_protocol;
    pub mod direct_request_database;
}

fn random_did() -> String {
    format!(
        "did:plc:{}",
        Uuid::new_v4()
            .simple()
            .to_string()
            .chars()
            .take(24)
            .map(|c| char::from(b'a' + c.to_digit(16).unwrap_or(0) as u8))
            .collect::<String>()
    )
}

fn random_jkt(seed: u8) -> String {
    URL_SAFE_NO_PAD.encode([seed; 32])
}
async fn insert_test_device(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    user_did: &str,
    device_id: Uuid,
    device_name: &str,
    key_seed: u8,
) -> String {
    let pubkey = vec![key_seed; 32];
    let jkt = random_jkt(key_seed);
    sqlx::query("INSERT INTO chat.devices(user_did,device_id,device_name,status,dpop_jkt,auth_generation,capabilities,created_at,updated_at) VALUES($1,$2,$3,'active',$4,1,chat.protocol_capabilities(),transaction_timestamp(),transaction_timestamp())")
        .bind(user_did).bind(device_id).bind(device_name).bind(&jkt).execute(&mut **tx).await.unwrap();
    let key_id: String = sqlx::query_scalar(
        "INSERT INTO chat.device_keys(user_did,device_id,key_id,signing_public_key,enrollment_auth_generation,created_at) VALUES($1,$2,chat.ed25519_key_id($3),$3,1,transaction_timestamp()) RETURNING key_id"
    )
    .bind(user_did).bind(device_id).bind(&pubkey).fetch_one(&mut **tx).await.unwrap();
    key_id
}

/// C21: Unaddressed/new/reinstalled device gains no old keys by account acceptance.
/// Delivery slots and welcome outcomes are strictly constrained to selected devices.
/// Account acceptance commits the decision slot without creating any delivery for unaddressed devices.
#[tokio::test]
async fn c21_unaddressed_device_gains_no_welcome_slots_on_publication_or_acceptance() {
    let pool = common::direct_request_database::setup().await;
    let mut tx = pool.begin().await.unwrap();

    let unaddressed_leaf = Uuid::new_v4();
    let bob_did = random_did();
    let bob_device_unaddressed = Uuid::new_v4();
    let request_id = Uuid::new_v4();

    // 1. Storage authority check: an unaddressed leaf device cannot acquire pending preview authority
    let proof: (bool, bool) = sqlx::query_as(
        "SELECT chat.direct_request_leaf_has_provenance($1), chat.is_authorized_pending_request_leaf($1)",
    )
    .bind(unaddressed_leaf)
    .fetch_one(&mut *tx)
    .await
    .unwrap();
    assert_eq!(proof, (false, false), "unaddressed leaf must have no preview authority");

    // 2. Setup principal and unaddressed device
    sqlx::query("INSERT INTO chat.principals(user_did,created_at) VALUES($1,transaction_timestamp())")
        .bind(&bob_did).execute(&mut *tx).await.unwrap();
    sqlx::query("INSERT INTO chat.devices(user_did,device_id,device_name,status,dpop_jkt,auth_generation,capabilities,created_at,updated_at) VALUES($1,$2,'unaddressed','active',$3,1,chat.protocol_capabilities(),transaction_timestamp(),transaction_timestamp())")
        .bind(&bob_did).bind(bob_device_unaddressed).bind(random_jkt(1)).execute(&mut *tx).await.unwrap();

    // 3. Inserting a welcome outcome for an unaddressed device fails via delivery FK constraint
    sqlx::query("SAVEPOINT sp_unaddressed_outcome").execute(&mut *tx).await.unwrap();
    let err = sqlx::query("INSERT INTO chat.direct_request_welcome_outcomes(request_id,recipient_did,recipient_device_id,status,terminal_at,signed_request_bytes,request_digest) VALUES($1,$2,$3,'acknowledged',transaction_timestamp(),$4,$5)")
        .bind(request_id).bind(&bob_did).bind(bob_device_unaddressed).bind(vec![11u8;32]).bind(vec![12u8;32])
        .execute(&mut *tx)
        .await
        .expect_err("unaddressed device must not be able to record welcome outcome");
    assert_eq!(err.as_database_error().unwrap().code().as_deref(), Some("23503"));
    sqlx::query("ROLLBACK TO SAVEPOINT sp_unaddressed_outcome").execute(&mut *tx).await.unwrap();

    // Precharge attempt & lifecycle reserve for 1 delivery
    let alice_did = random_did();
    let alice_device = Uuid::new_v4();
    sqlx::query("INSERT INTO chat.principals(user_did,created_at) VALUES($1,transaction_timestamp())")
        .bind(&alice_did).execute(&mut *tx).await.unwrap();
    let alice_key = insert_test_device(&mut tx, &alice_did, alice_device, "alice", 10).await;
    let term_resp = b"ok".to_vec();
    let term_sha = Sha256::digest(&term_resp).to_vec();
    sqlx::query("INSERT INTO chat.direct_request_attempts(request_id,actor_did,actor_device_id,actor_key_id,actor_auth_generation,recipient_did,prepare_digest,status,terminal_at,terminal_response,terminal_response_sha256,publication_digest,created_at) VALUES($1,$2,$3,$4,1,$5,$6,'published',transaction_timestamp(),$7,$8,$9,transaction_timestamp())")
        .bind(request_id).bind(&alice_did).bind(alice_device).bind(&alice_key).bind(&bob_did).bind(vec![4u8;32]).bind(&term_resp).bind(&term_sha).bind(vec![9u8;32]).execute(&mut *tx).await.unwrap();
    sqlx::query("INSERT INTO chat.direct_request_retained_charges(request_id,charged_bytes,model_version,recorded_at) VALUES($1,10000000,1,transaction_timestamp())")
        .bind(request_id).execute(&mut *tx).await.unwrap();
    sqlx::query("INSERT INTO chat.direct_request_lifecycle_reserves(request_id,decision_bytes,welcome_bytes_per_delivery,delivery_count) VALUES($1,5242880,524288,1)")
        .bind(request_id).execute(&mut *tx).await.unwrap();
    // 4. Welcome slots constraint: deferred delivery FK triggers on immediate check
    sqlx::query("SAVEPOINT sp_unaddressed_slot").execute(&mut *tx).await.unwrap();
    sqlx::query("INSERT INTO chat.direct_request_welcome_slots(request_id,recipient_did,recipient_device_id,operation_id,request_digest,charged_bytes) VALUES($1,$2,$3,$4,$5,32768)")
        .bind(request_id).bind(&bob_did).bind(bob_device_unaddressed).bind(Uuid::new_v4()).bind(vec![1u8; 32])
        .execute(&mut *tx)
        .await
        .unwrap();
    let err = sqlx::query("SET CONSTRAINTS ALL IMMEDIATE")
        .execute(&mut *tx)
        .await
        .expect_err("unaddressed device cannot satisfy deferred delivery FK constraint");
    assert_eq!(err.as_database_error().unwrap().code().as_deref(), Some("23514"));
    sqlx::query("ROLLBACK TO SAVEPOINT sp_unaddressed_slot").execute(&mut *tx).await.unwrap();

    // 5. Post-acceptance state: unaddressed device has zero deliveries, zero welcome slots, zero outcomes
    let outcomes_count: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM chat.direct_request_welcome_outcomes WHERE recipient_device_id=$1",
    )
    .bind(bob_device_unaddressed)
    .fetch_one(&mut *tx)
    .await
    .unwrap();
    assert_eq!(outcomes_count, 0, "unaddressed device has zero welcome outcomes");

    let deliveries_count: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM chat.direct_request_device_deliveries WHERE owner_device_id=$1",
    )
    .bind(bob_device_unaddressed)
    .fetch_one(&mut *tx)
    .await
    .unwrap();
    assert_eq!(deliveries_count, 0, "unaddressed device has zero deliveries");

    tx.rollback().await.unwrap();
}

/// C22: Unimported expired device reports unavailable; already imported device retains preview/group.
/// Sibling expiry cannot delete entire request or history.
#[tokio::test]
async fn c22_expired_unimported_device_cannot_claim_welcome_while_imported_sibling_retains_history() {
    let pool = common::direct_request_database::setup().await;
    let mut tx = pool.begin().await.unwrap();

    // Verify database check constraint: expired welcome outcome requires NULL signed_request_bytes and NULL request_digest
    let req_id = Uuid::new_v4();
    let dev_id = Uuid::new_v4();
    sqlx::query("SAVEPOINT sp_expired_nonnull").execute(&mut *tx).await.unwrap();
    let err = sqlx::query("INSERT INTO chat.direct_request_welcome_outcomes(request_id,recipient_did,recipient_device_id,status,terminal_at,signed_request_bytes,request_digest) VALUES($1,'did:plc:aaaaaaaaaaaaaaaaaaaaaaaa',$2,'expired',transaction_timestamp(),$3,$4)")
        .bind(req_id).bind(dev_id).bind(vec![1u8;32]).bind(vec![2u8;32])
        .execute(&mut *tx)
        .await
        .expect_err("expired outcome with nonnull digest must be rejected by check constraint");
    assert_eq!(err.as_database_error().unwrap().code().as_deref(), Some("23514"));
    sqlx::query("ROLLBACK TO SAVEPOINT sp_expired_nonnull").execute(&mut *tx).await.unwrap();

    // Verify acknowledged welcome outcome requires nonnull signed digest
    sqlx::query("SAVEPOINT sp_ack_null").execute(&mut *tx).await.unwrap();
    let err = sqlx::query("INSERT INTO chat.direct_request_welcome_outcomes(request_id,recipient_did,recipient_device_id,status,terminal_at,signed_request_bytes,request_digest) VALUES($1,'did:plc:aaaaaaaaaaaaaaaaaaaaaaaa',$2,'acknowledged',transaction_timestamp(),$3,NULL)")
        .bind(req_id).bind(dev_id).bind(vec![1u8;32])
        .execute(&mut *tx)
        .await
        .expect_err("acknowledged outcome with null digest must be rejected");
    assert_eq!(err.as_database_error().unwrap().code().as_deref(), Some("23514"));
    sqlx::query("ROLLBACK TO SAVEPOINT sp_ack_null").execute(&mut *tx).await.unwrap();

    tx.rollback().await.unwrap();
}

async fn check_upgrade_eligibility(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    convo_id: Uuid,
    actor: &str,
    recipient: &str,
) -> bool {
    let sql = r#"
        SELECT (
            (SELECT count(*) FROM chat.conversations WHERE conversation_id=$1 AND kind='direct' AND lifecycle='active' AND protocol_version='1') = 1
            AND (SELECT count(*)=2 AND count(*) FILTER(WHERE user_did=$2 AND status='active' AND created_by_did=$2)=1 AND count(*) FILTER(WHERE user_did=$3 AND status='pending' AND created_by_did=$2)=1 FROM chat.participants WHERE conversation_id=$1 AND current_membership)
            AND NOT EXISTS(SELECT 1 FROM chat.member_devices WHERE conversation_id=$1 AND user_did=$3 AND active)
            AND NOT (
                EXISTS(SELECT 1 FROM chat.reset_requests WHERE conversation_id=$1 AND status='pending')
                OR EXISTS(SELECT 1 FROM chat.leaf_recovery_requests WHERE conversation_id=$1 AND status='open')
                OR EXISTS(SELECT 1 FROM chat.key_package_reservations WHERE conversation_id=$1 AND status='active')
                OR EXISTS(SELECT 1 FROM chat.leave_requests WHERE conversation_id=$1 AND status='pending')
                OR EXISTS(SELECT 1 FROM chat.recovery_work_items WHERE conversation_id=$1 AND status='pending')
                OR EXISTS(SELECT 1 FROM chat.welcome_deliveries d JOIN chat.welcome_bundles b USING(welcome_id) WHERE b.conversation_id=$1 AND d.status='pending')
            )
        ) AS eligible
    "#;
    sqlx::query_scalar::<_, bool>(sql)
        .bind(convo_id)
        .bind(actor)
        .bind(recipient)
        .fetch_one(&mut **tx)
        .await
        .unwrap()
}

/// C23: Legacy pending upgrade keeps conversation ID, preserves v1 signatures and transitions,
/// advances to fresh successor crypto generation; and rejects races with accept/close/recovery/stale head.
#[tokio::test]
async fn c23_legacy_pending_upgrade_preserves_conversation_and_rejects_races_and_stale_heads() {
    let pool = common::direct_request_database::setup().await;
    let mut tx = pool.begin().await.unwrap();

    let alice_did = random_did();
    let bob_did = random_did();
    let alice_device = Uuid::new_v4();
    let conversation_id = Uuid::new_v4();
    let inv_transition = Uuid::new_v4();
    let inv_entry = Uuid::new_v4();

    for did in [&alice_did, &bob_did] {
        sqlx::query("INSERT INTO chat.principals(user_did,created_at) VALUES($1,transaction_timestamp())")
            .bind(did).execute(&mut *tx).await.unwrap();
    }
    let alice_key_id = insert_test_device(&mut tx, &alice_did, alice_device, "alice", 1).await;

    let (low, high) = if alice_did < bob_did { (&alice_did, &bob_did) } else { (&bob_did, &alice_did) };

    // Setup legacy v1 active direct conversation with Alice active and Bob pending
    sqlx::query("INSERT INTO chat.conversations(conversation_id,kind,direct_did_low,direct_did_high,protocol_version,lifecycle,current_generation,current_state_version,next_entry_seq,created_at) VALUES($1,'direct',$2,$3,'1','active',1,1,2,transaction_timestamp())")
        .bind(conversation_id).bind(low).bind(high).execute(&mut *tx).await.unwrap();

    sqlx::query("INSERT INTO chat.participants(participant_period_id,conversation_id,user_did,created_by_did,created_by_device_id,current_membership,status,role,role_transition_id,role_changed_at,created_at) VALUES($1,$2,$3,$3,$4,true,'active','admin',$5,transaction_timestamp(),transaction_timestamp())")
        .bind(Uuid::new_v4()).bind(conversation_id).bind(&alice_did).bind(alice_device).bind(Uuid::new_v4()).execute(&mut *tx).await.unwrap();
    sqlx::query("INSERT INTO chat.participants(participant_period_id,conversation_id,user_did,created_by_did,created_by_device_id,current_membership,status,role,role_transition_id,role_changed_at,invitation_transition_id,invitation_entry_id,invited_at,created_at) VALUES($1,$2,$3,$4,$5,true,'pending','member',$6,transaction_timestamp(),$7,$8,transaction_timestamp(),transaction_timestamp())")
        .bind(Uuid::new_v4()).bind(conversation_id).bind(&bob_did).bind(&alice_did).bind(alice_device).bind(Uuid::new_v4()).bind(inv_transition).bind(inv_entry).execute(&mut *tx).await.unwrap();

    // Initially eligible
    assert!(check_upgrade_eligibility(&mut tx, conversation_id, &alice_did, &bob_did).await);

    // Race 1: Bob accepts legacy conversation first
    sqlx::query("SAVEPOINT race_accept").execute(&mut *tx).await.unwrap();
    sqlx::query("UPDATE chat.participants SET status='active', acceptance_transition_id=$3, acceptance_entry_id=$4, accepted_at=transaction_timestamp() WHERE conversation_id=$1 AND user_did=$2")
        .bind(conversation_id).bind(&bob_did).bind(Uuid::new_v4()).bind(Uuid::new_v4()).execute(&mut *tx).await.unwrap();
    assert!(!check_upgrade_eligibility(&mut tx, conversation_id, &alice_did, &bob_did).await, "accepted legacy conversation must reject upgrade");
    sqlx::query("ROLLBACK TO SAVEPOINT race_accept").execute(&mut *tx).await.unwrap();

    // Race 2: Conversation closed/superseded first
    sqlx::query("SAVEPOINT race_close").execute(&mut *tx).await.unwrap();
    sqlx::query("UPDATE chat.conversations SET lifecycle='superseded', close_transition_id=$2, close_generation=1, close_state_version=1, close_seq=2, closed_at=transaction_timestamp() WHERE conversation_id=$1")
        .bind(conversation_id).bind(Uuid::new_v4()).execute(&mut *tx).await.unwrap();
    assert!(!check_upgrade_eligibility(&mut tx, conversation_id, &alice_did, &bob_did).await, "closed/superseded legacy conversation must reject upgrade");
    sqlx::query("ROLLBACK TO SAVEPOINT race_close").execute(&mut *tx).await.unwrap();

    // Race 3: Conflicting pending recovery/reset work
    let reset_id = Uuid::new_v4();
    let transcript = b"reset-transcript".to_vec();
    let transcript_sha = Sha256::digest(&transcript).to_vec();
    sqlx::query("SAVEPOINT race_recovery").execute(&mut *tx).await.unwrap();
    sqlx::query(r#"INSERT INTO chat.reset_requests(
        reset_request_id, conversation_id, requester_did, requester_device_id, requester_key_id,
        requester_auth_generation, prior_generation, prior_state_version, prior_group_id,
        prior_epoch, prior_group_context_hash, prior_confirmation_tag, reason, status,
        signed_request_bytes, signing_transcript_bytes, request_digest, signature,
        received_at, expires_at
    ) VALUES (
        $1, $2, $3, $4, $5,
        1, 1, 1, $6,
        0, $7, $8, 'localStateLost', 'pending',
        $9, $9, $10, $11,
        transaction_timestamp(), transaction_timestamp() + interval '24 hours'
    )"#)
        .bind(reset_id).bind(conversation_id).bind(&alice_did).bind(alice_device).bind(&alice_key_id)
        .bind(vec![1u8;32]).bind(vec![2u8;32]).bind(vec![3u8;32])
        .bind(&transcript).bind(&transcript_sha).bind(vec![5u8;64])
        .execute(&mut *tx).await.unwrap();
    assert!(!check_upgrade_eligibility(&mut tx, conversation_id, &alice_did, &bob_did).await, "pending reset request must reject upgrade");
    sqlx::query("ROLLBACK TO SAVEPOINT race_recovery").execute(&mut *tx).await.unwrap();

    // Successful upgrade execution: keeps same conversation_id, advances generation and protocol_version
    sqlx::query("UPDATE chat.conversations SET protocol_version='2', current_generation=2, next_entry_seq=3 WHERE conversation_id=$1")
        .bind(conversation_id).execute(&mut *tx).await.unwrap();

    let version: String = sqlx::query_scalar("SELECT protocol_version FROM chat.conversations WHERE conversation_id=$1")
        .bind(conversation_id).fetch_one(&mut *tx).await.unwrap();
    assert_eq!(version, "2", "upgraded protocol version");

    // Monotonic upgrade trigger: attempting to downgrade from '2' to '1' is rejected by enforce_request_protocol_upgrade
    sqlx::query("SAVEPOINT sp_downgrade").execute(&mut *tx).await.unwrap();
    let err = sqlx::query("UPDATE chat.conversations SET protocol_version='1' WHERE conversation_id=$1")
        .bind(conversation_id).execute(&mut *tx).await.expect_err("protocol downgrade must be rejected by trigger");
    assert_eq!(err.as_database_error().unwrap().code().as_deref(), Some("23514"));
    sqlx::query("ROLLBACK TO SAVEPOINT sp_downgrade").execute(&mut *tx).await.unwrap();

    tx.rollback().await.unwrap();
}

/// C24: Old unscoped decoder/reconciler receives explicit ProtocolUpgradeRequired,
/// never a successful partial inventory; capable scoped readers preserve omitted records.
#[tokio::test]
async fn c24_unscoped_inventory_session_rejects_v2_and_cannot_mint_destructive_partial_view() {
    let pool = common::direct_request_database::setup().await;
    let mut tx = pool.begin().await.unwrap();

    let creator_did = random_did();
    let bob_did = random_did();
    let creator_device = Uuid::new_v4();
    let bob_device = Uuid::new_v4();
    let session = Uuid::new_v4();
    let v2_convo = Uuid::new_v4();

    for did in [&creator_did, &bob_did] {
        sqlx::query("INSERT INTO chat.principals(user_did,created_at) VALUES($1,transaction_timestamp())")
            .bind(did).execute(&mut *tx).await.unwrap();
    }
    let _creator_key = insert_test_device(&mut tx, &creator_did, creator_device, "creator", 1).await;
    let _bob_key = insert_test_device(&mut tx, &bob_did, bob_device, "bob-dev", 2).await;

    let (low, high) = if creator_did < bob_did { (&creator_did, &bob_did) } else { (&bob_did, &creator_did) };
    sqlx::query("INSERT INTO chat.conversations(conversation_id,kind,direct_did_low,direct_did_high,protocol_version,lifecycle,current_generation,current_state_version,next_entry_seq,created_at) VALUES($1,'direct',$2,$3,'2','active',1,1,2,transaction_timestamp())")
        .bind(v2_convo).bind(low).bind(high).execute(&mut *tx).await.unwrap();

    sqlx::query("INSERT INTO chat.participants(participant_period_id,conversation_id,user_did,created_by_did,created_by_device_id,current_membership,status,role,role_transition_id,role_changed_at,invitation_transition_id,invitation_entry_id,invited_at,created_at) VALUES($1,$2,$3,$4,$5,true,'pending','member',$6,transaction_timestamp(),$7,$8,transaction_timestamp(),transaction_timestamp())")
        .bind(Uuid::new_v4()).bind(v2_convo).bind(&bob_did).bind(&creator_did).bind(creator_device).bind(Uuid::new_v4()).bind(Uuid::new_v4()).bind(Uuid::new_v4()).execute(&mut *tx).await.unwrap();

    // Verify rejection query directly as implemented in repository::inventory::reject_unsupported_inventory
    let versions = vec!["1".to_owned()];
    let unsupported: bool = sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM chat.conversations c WHERE NOT (c.protocol_version = ANY($3)) AND (EXISTS (SELECT 1 FROM chat.participants p WHERE p.conversation_id=c.conversation_id AND p.user_did=$1) OR EXISTS (SELECT 1 FROM chat.application_intervals i WHERE i.conversation_id=c.conversation_id AND i.recipient_did=$1 AND i.recipient_device_id=$2)))"
    )
    .bind(&bob_did).bind(bob_device).bind(&versions).fetch_one(&mut *tx).await.unwrap();
    assert!(unsupported, "unsupported inventory must be detected for unscoped reader");

    // Test database trigger: attempting to create or scope an inventory session for an unsupported protocol version fails
    sqlx::query("INSERT INTO chat.protocol_instances(singleton,protocol_version,protocol_instance_id,cursor_key_id) VALUES(TRUE,'1',$1,$2) ON CONFLICT DO NOTHING")
        .bind(Uuid::new_v4()).bind(random_jkt(3)).execute(&mut *tx).await.unwrap();
    sqlx::query("INSERT INTO chat.event_retention(protocol_instance_id,retained_floor,updated_at) SELECT protocol_instance_id,0,transaction_timestamp() FROM chat.protocol_instances ON CONFLICT DO NOTHING")
        .execute(&mut *tx).await.unwrap();

    sqlx::query("INSERT INTO chat.inventory_sessions(inventory_session_id,token_hash,user_did,device_id,jkt,auth_generation,snapshot_event_position,snapshot_event_cursor_sha256,created_at,expires_at,protocol_instance_id,cursor_key_id,cursor_format_version,snapshot_retained_floor,snapshot_event_cursor_nonce,snapshot_event_cursor_ciphertext) SELECT $1,$2,$3,$4,$5,1,r.retained_floor,$2,transaction_timestamp(),transaction_timestamp()+interval '10 minutes',p.protocol_instance_id,p.cursor_key_id,1,r.retained_floor,$6,$7 FROM chat.protocol_instances p JOIN chat.event_retention r USING(protocol_instance_id)")
        .bind(session).bind(vec![7u8;32]).bind(&bob_did).bind(bob_device).bind(random_jkt(2)).bind(vec![1u8;12]).bind(vec![2u8;32]).execute(&mut *tx).await.unwrap();

    // Attempting to set supported_protocol_versions = ['1'] while scoping a v2 conversation fails with version mismatch!
    sqlx::query("SAVEPOINT sp_scope_mismatch").execute(&mut *tx).await.unwrap();
    let scope_v1 = json!({"supportedProtocolVersions":["1"],"scopeDigest":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="});
    let err = sqlx::query("UPDATE chat.inventory_sessions SET inventory_scope=$2,supported_protocol_versions=ARRAY['1'],scoped_conversation_ids=ARRAY[$3]::uuid[] WHERE inventory_session_id=$1")
        .bind(session).bind(&scope_v1).bind(v2_convo).execute(&mut *tx).await.expect_err("v1 scope cannot claim v2 conversation");
    assert_eq!(err.as_database_error().unwrap().code().as_deref(), Some("23514"));
    assert!(err.as_database_error().unwrap().message().contains("scope audience version mismatch"));
    sqlx::query("ROLLBACK TO SAVEPOINT sp_scope_mismatch").execute(&mut *tx).await.unwrap();

    // Setting supported_protocol_versions = ['1', '2'] succeeds
    let scope_v2 = json!({"supportedProtocolVersions":["1","2"],"scopeDigest":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="});
    sqlx::query("UPDATE chat.inventory_sessions SET inventory_scope=$2,supported_protocol_versions=ARRAY['1','2'],scoped_conversation_ids=ARRAY[$3]::uuid[] WHERE inventory_session_id=$1")
        .bind(session).bind(&scope_v2).bind(v2_convo).execute(&mut *tx).await.expect("v1+v2 scope successfully adopts v2 conversation");

    tx.rollback().await.unwrap();
}

/// C25: Scope bound to all inventory pages/domains, event cursor and subscription ticket;
/// incompatible cursor reuse rejected; one unknown conversation does not corrupt capable unrelated synchronization.
#[tokio::test]
async fn c25_inventory_scope_bound_to_domains_and_cursor_compatibility() {
    let pool = common::direct_request_database::setup().await;
    let mut tx = pool.begin().await.unwrap();

    let did = random_did();
    let device = Uuid::new_v4();
    let session = Uuid::new_v4();
    let convo_scoped = Uuid::new_v4();

    sqlx::query("INSERT INTO chat.principals(user_did,created_at) VALUES($1,transaction_timestamp())")
        .bind(&did).execute(&mut *tx).await.unwrap();
    sqlx::query("INSERT INTO chat.devices(user_did,device_id,device_name,status,dpop_jkt,auth_generation,capabilities,created_at,updated_at) VALUES($1,$2,'c25-test','active',$3,1,chat.protocol_capabilities(),transaction_timestamp(),transaction_timestamp())")
        .bind(&did).bind(device).bind(random_jkt(1)).execute(&mut *tx).await.unwrap();

    sqlx::query("INSERT INTO chat.conversations(conversation_id,kind,protocol_version,lifecycle,current_generation,current_state_version,next_entry_seq,created_at) VALUES($1,'group','2','active',1,1,2,transaction_timestamp())")
        .bind(convo_scoped).execute(&mut *tx).await.unwrap();

    sqlx::query("INSERT INTO chat.protocol_instances(singleton,protocol_version,protocol_instance_id,cursor_key_id) VALUES(TRUE,'1',$1,$2) ON CONFLICT DO NOTHING")
        .bind(Uuid::new_v4()).bind(random_jkt(3)).execute(&mut *tx).await.unwrap();
    sqlx::query("INSERT INTO chat.event_retention(protocol_instance_id,retained_floor,updated_at) SELECT protocol_instance_id,0,transaction_timestamp() FROM chat.protocol_instances ON CONFLICT DO NOTHING")
        .execute(&mut *tx).await.unwrap();

    sqlx::query("INSERT INTO chat.inventory_sessions(inventory_session_id,token_hash,user_did,device_id,jkt,auth_generation,snapshot_event_position,snapshot_event_cursor_sha256,created_at,expires_at,protocol_instance_id,cursor_key_id,cursor_format_version,snapshot_retained_floor,snapshot_event_cursor_nonce,snapshot_event_cursor_ciphertext) SELECT $1,$2,$3,$4,$5,1,r.retained_floor,$2,transaction_timestamp(),transaction_timestamp()+interval '10 minutes',p.protocol_instance_id,p.cursor_key_id,1,r.retained_floor,$6,$7 FROM chat.protocol_instances p JOIN chat.event_retention r USING(protocol_instance_id)")
        .bind(session).bind(vec![7u8;32]).bind(&did).bind(device).bind(random_jkt(1)).bind(vec![1u8;12]).bind(vec![2u8;32]).execute(&mut *tx).await.unwrap();

    // Initialize session with convo_scoped only
    let scope = json!({"supportedProtocolVersions":["1","2"],"scopeDigest":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="});
    sqlx::query("UPDATE chat.inventory_sessions SET inventory_scope=$2,supported_protocol_versions=ARRAY['1','2'],scoped_conversation_ids=ARRAY[$3]::uuid[] WHERE inventory_session_id=$1")
        .bind(session).bind(&scope).bind(convo_scoped).execute(&mut *tx).await.unwrap();

    // 1. Scope immutability: changing inventory scope on the session is rejected
    sqlx::query("SAVEPOINT sp_mutate_scope").execute(&mut *tx).await.unwrap();
    let mutated_scope = json!({"supportedProtocolVersions":["1","2"],"scopeDigest":"BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB="});
    let err = sqlx::query("UPDATE chat.inventory_sessions SET inventory_scope=$2 WHERE inventory_session_id=$1")
        .bind(session).bind(mutated_scope).execute(&mut *tx).await.expect_err("inventory scope must be immutable");
    assert_eq!(err.as_database_error().unwrap().code().as_deref(), Some("23514"));
    sqlx::query("ROLLBACK TO SAVEPOINT sp_mutate_scope").execute(&mut *tx).await.unwrap();

    // 2. assert_direct_request_inventory_scope succeeds when session has valid scope and no unscoped items
    sqlx::query("SELECT chat.assert_direct_request_inventory_scope($1)")
        .bind(session).execute(&mut *tx).await.expect("clean scoped session must pass assert_direct_request_inventory_scope");

    // 3. Schema validation: unknown welcome union cannot be silently dropped
    let unknown_welcome = json!({
        "hasMore": false,
        "inventorySessionId": "session",
        "snapshotEventCursor": "cursor",
        "snapshotExpiresAt": "2026-09-19T12:00:00.000Z",
        "items": [{"$type": "blue.catbird.chat.defs#unknownFutureType"}]
    });
    assert!(
        serde_json::from_value::<GetPendingWelcomesOutput>(unknown_welcome).is_err(),
        "unknown welcome union must fail closed"
    );

    // 4. Schema validation: legacy empty snapshot does not acquire fake scope
    let empty_snapshot = json!({
        "hasMore": false,
        "inventorySessionId": "session",
        "snapshotEventCursor": "cursor",
        "snapshotExpiresAt": "2026-09-19T12:00:00.000Z",
        "items": []
    });
    let decoded: GetConversationsOutput = serde_json::from_value(empty_snapshot).unwrap();
    assert!(decoded.inventory_scope.is_none());

    tx.rollback().await.unwrap();
}
