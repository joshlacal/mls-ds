//! Fulfiller discovery, distinct from the exact-target-device recovery inbox.
//! Caller authority and conversation head remain locked by the parent read.
//! Requests are advisory: the signed fulfillment transaction revalidates all
//! identities, reserved packages, consent, and coordinates before committing.

use chrono::{DateTime, Utc};
use sha2::{Digest, Sha256};
use sqlx::{FromRow, Postgres, Transaction};
use uuid::Uuid;

use super::ConversationStateReadError;
use crate::chat_protocol::{
    read_authority::ConversationStateReadAuthority,
    read_projection::{
        leaf_recovery_view, CheckedConversationCoordinates, CheckedKeyPackageArtifact,
        CheckedLeafRecoveryReservation, RetainedLeafRecoveryProjectionSource,
    },
};

type RecoveryView = catbird_atproto::generated::blue_catbird::chat::LeafRecoveryView;

const PENDING_LEAF_RECOVERIES_SQL: &str = r#"
        SELECT request.recovery_request_id, request.conversation_id,
               request.generation, request.requester_did,
               request.requester_device_id, request.requester_key_id,
               request.requester_auth_generation, request.recovery_kind,
               request.bound_state_version, request.bound_group_id,
               request.bound_epoch, request.bound_group_context_hash,
               request.bound_confirmation_tag, request.status,
               request.requested_at, request.expires_at,
               conversation.lifecycle AS conversation_lifecycle,
               reservation.conversation_id AS reservation_conversation_id,
               reservation.generation AS reservation_generation,
               reservation.requester_did AS reservation_requester_did,
               reservation.requester_device_id AS reservation_requester_device_id,
               reservation.requester_key_id AS reservation_requester_key_id,
               reservation.requester_auth_generation
                   AS reservation_requester_auth_generation,
               reservation.key_package_ref AS reservation_key_package_ref,
               reservation.bound_state_version AS reservation_bound_state_version,
               reservation.bound_group_id AS reservation_bound_group_id,
               reservation.bound_epoch AS reservation_bound_epoch,
               reservation.bound_group_context_hash
                   AS reservation_bound_group_context_hash,
               reservation.bound_confirmation_tag AS reservation_bound_confirmation_tag,
               reservation.status AS reservation_status,
               reservation.expires_at AS reservation_expires_at,
               package.wrapper_bytes AS package_wrapper_bytes,
               package.wrapper_sha256 AS package_wrapper_sha256
          FROM chat.leaf_recovery_requests AS request
          JOIN chat.key_package_reservations AS reservation
            ON reservation.recovery_request_id = request.recovery_request_id
          JOIN chat.key_packages AS package
            ON package.key_package_ref = reservation.key_package_ref
          JOIN chat.conversations AS conversation
            ON conversation.conversation_id = request.conversation_id
          JOIN chat.generation_states AS state
            ON state.conversation_id = conversation.conversation_id
           AND state.generation = conversation.current_generation
           AND state.state_version = conversation.current_state_version
          JOIN chat.devices AS device
            ON device.user_did = request.requester_did
           AND device.device_id = request.requester_device_id
          JOIN chat.device_keys AS device_key
            ON device_key.user_did = request.requester_did
           AND device_key.device_id = request.requester_device_id
          JOIN chat.participants AS participant
            ON participant.conversation_id = request.conversation_id
           AND participant.user_did = request.requester_did
           AND participant.current_membership
         WHERE request.conversation_id = $1
           AND NOT (request.requester_did = $2 AND request.requester_device_id = $3)
           AND conversation.lifecycle = 'active'
           AND state.lifecycle = 'active'
           AND request.status = 'open' AND request.expires_at > statement_timestamp()
           AND reservation.status = 'active' AND reservation.expires_at > statement_timestamp()
           AND request.generation = state.generation
           AND request.bound_state_version = state.state_version
           AND request.bound_group_id = state.group_id
           AND request.bound_epoch = state.epoch
           AND request.bound_group_context_hash = state.group_context_hash
           AND request.bound_confirmation_tag = state.confirmation_tag
           AND request.reservation_request_id = request.recovery_request_id
           AND reservation.recipient_did = request.requester_did
           AND reservation.recipient_device_id = request.requester_device_id
           AND reservation.purpose = 'leafRecovery'
           AND package.status = 'reserved'
           AND package.owner_did = request.requester_did
           AND package.owner_device_id = request.requester_device_id
           AND package.owner_key_id = request.requester_key_id
           AND package.owner_auth_generation = request.requester_auth_generation
           AND package.not_before <= statement_timestamp()
           AND package.not_after > statement_timestamp()
           AND reservation.expires_at <= package.not_after
           AND participant.status = 'active'
           AND device.status = 'active' AND device.revoked_at IS NULL
           AND device.auth_generation = request.requester_auth_generation
           AND device_key.revoked_at IS NULL
           AND device_key.key_id = request.requester_key_id
           AND device_key.enrollment_auth_generation = request.requester_auth_generation
         ORDER BY request.requested_at, request.recovery_request_id
         LIMIT 100
"#;

pub(super) async fn load_pending_leaf_recoveries(
    transaction: &mut Transaction<'_, Postgres>,
    authority: &ConversationStateReadAuthority,
) -> Result<Vec<RecoveryView>, ConversationStateReadError> {
    // Logical account membership (including a sibling device's leaf) is not
    // enough. Only this exact concrete leaf can discover fulfillment work.
    if authority.relationship().leaf_period_id().is_none() {
        return Ok(Vec::new());
    }
    let rows: Vec<LeafRecoverySourceRow> = sqlx::query_as(PENDING_LEAF_RECOVERIES_SQL)
        .bind(authority.conversation_id())
        .bind(authority.user_did())
        .bind(authority.device_id())
        .fetch_all(&mut **transaction)
        .await
        .map_err(|_| ConversationStateReadError::Storage)?;
    rows.into_iter().map(project_recovery).collect()
}

fn canonical_datetime(value: DateTime<Utc>) -> String {
    value.format("%Y-%m-%dT%H:%M:%S%.3fZ").to_string()
}

fn project_recovery(
    row: LeafRecoverySourceRow,
) -> Result<RecoveryView, ConversationStateReadError> {
    // These fields are not carried in the public request view, so explicitly
    // cross-check them before the checked constructors bind the rest.
    if row.package_wrapper_sha256.as_slice()
        != Sha256::digest(&row.package_wrapper_bytes).as_slice()
        || row.requester_key_id != row.reservation_requester_key_id
        || row.requester_auth_generation != row.reservation_requester_auth_generation
        || row.expires_at != row.reservation_expires_at
    {
        return Err(ConversationStateReadError::Invariant);
    }
    // The reservation's coordinate, identity, and status come from the
    // RESERVATION row's OWN columns; the view's coordinate comes from the
    // REQUEST row's own bound columns. The C1 checked constructors then
    // cross-check the two durable sources (request row vs reservation
    // row), so a durable drift fails closed instead of being normalized
    // into canonical bytes.
    let reservation_bound_coordinate = CheckedConversationCoordinates::new(
        &row.reservation_conversation_id.to_string(),
        row.reservation_generation,
        row.reservation_bound_state_version,
        &row.reservation_bound_group_id,
        row.reservation_bound_epoch,
        &row.reservation_bound_group_context_hash,
        &row.reservation_bound_confirmation_tag,
        &row.conversation_lifecycle,
    )
    .map_err(|_| ConversationStateReadError::Invariant)?;
    let key_package = CheckedKeyPackageArtifact::new(
        "mlsMessage",
        "keyPackage",
        &row.package_wrapper_bytes,
        &row.package_wrapper_sha256,
        &row.reservation_key_package_ref,
    )
    .map_err(|_| ConversationStateReadError::Invariant)?;
    let reservation = CheckedLeafRecoveryReservation::new(
        &row.recovery_request_id.to_string(),
        &row.reservation_conversation_id.to_string(),
        reservation_bound_coordinate,
        &row.reservation_requester_did,
        &row.reservation_requester_device_id.to_string(),
        &row.reservation_requester_key_id,
        row.reservation_requester_auth_generation,
        &row.reservation_key_package_ref,
        "MLS_256_XWING_CHACHA20POLY1305_SHA256_Ed25519",
        "leafRecovery",
        &row.reservation_status,
        &canonical_datetime(row.reservation_expires_at),
        key_package,
    )
    .map_err(|_| ConversationStateReadError::Invariant)?;
    // The view's bound coordinate is re-derived from the REQUEST row; the
    // C1 constructor cross-checks the reservation's coordinate against it
    // and fails closed on any divergence.
    let bound_coordinate = CheckedConversationCoordinates::new(
        &row.conversation_id.to_string(),
        row.generation,
        row.bound_state_version,
        &row.bound_group_id,
        row.bound_epoch,
        &row.bound_group_context_hash,
        &row.bound_confirmation_tag,
        &row.conversation_lifecycle,
    )
    .map_err(|_| ConversationStateReadError::Invariant)?;
    let source = RetainedLeafRecoveryProjectionSource::new(
        &row.recovery_request_id.to_string(),
        &row.conversation_id.to_string(),
        &row.requester_did,
        &row.requester_device_id.to_string(),
        &row.recovery_kind,
        bound_coordinate,
        &row.status,
        &canonical_datetime(row.requested_at),
        &canonical_datetime(row.expires_at),
        reservation,
    )
    .map_err(|_| ConversationStateReadError::Invariant)?;
    leaf_recovery_view(&source).map_err(|_| ConversationStateReadError::Invariant)
}

#[derive(Debug, FromRow)]
struct LeafRecoverySourceRow {
    recovery_request_id: Uuid,
    conversation_id: Uuid,
    generation: i64,
    requester_did: String,
    requester_device_id: Uuid,
    requester_key_id: String,
    requester_auth_generation: i64,
    recovery_kind: String,
    bound_state_version: i64,
    bound_group_id: Vec<u8>,
    bound_epoch: i64,
    bound_group_context_hash: Vec<u8>,
    bound_confirmation_tag: Vec<u8>,
    status: String,
    requested_at: DateTime<Utc>,
    expires_at: DateTime<Utc>,
    conversation_lifecycle: String,
    reservation_conversation_id: Uuid,
    reservation_generation: i64,
    reservation_requester_did: String,
    reservation_requester_device_id: Uuid,
    reservation_requester_key_id: String,
    reservation_requester_auth_generation: i64,
    reservation_key_package_ref: Vec<u8>,
    reservation_bound_state_version: i64,
    reservation_bound_group_id: Vec<u8>,
    reservation_bound_epoch: i64,
    reservation_bound_group_context_hash: Vec<u8>,
    reservation_bound_confirmation_tag: Vec<u8>,
    reservation_status: String,
    reservation_expires_at: DateTime<Utc>,
    package_wrapper_bytes: Vec<u8>,
    package_wrapper_sha256: Vec<u8>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Duration;
    use sha2::{Digest, Sha256};

    fn source_row() -> LeafRecoverySourceRow {
        let now = Utc::now();
        let cid = Uuid::new_v4();
        let device = Uuid::new_v4();
        let package = vec![7; 12];
        LeafRecoverySourceRow {
            recovery_request_id: Uuid::new_v4(),
            conversation_id: cid,
            generation: 2,
            requester_did: "did:plc:alice".into(),
            requester_device_id: device,
            requester_key_id: "key".into(),
            requester_auth_generation: 3,
            recovery_kind: "add".into(),
            bound_state_version: 4,
            bound_group_id: vec![1; 32],
            bound_epoch: 5,
            bound_group_context_hash: vec![2; 32],
            bound_confirmation_tag: vec![3; 32],
            status: "open".into(),
            requested_at: now,
            expires_at: now + Duration::minutes(5),
            conversation_lifecycle: "active".into(),
            reservation_conversation_id: cid,
            reservation_generation: 2,
            reservation_requester_did: "did:plc:alice".into(),
            reservation_requester_device_id: device,
            reservation_requester_key_id: "key".into(),
            reservation_requester_auth_generation: 3,
            reservation_key_package_ref: vec![4; 32],
            reservation_bound_state_version: 4,
            reservation_bound_group_id: vec![1; 32],
            reservation_bound_epoch: 5,
            reservation_bound_group_context_hash: vec![2; 32],
            reservation_bound_confirmation_tag: vec![3; 32],
            reservation_status: "active".into(),
            reservation_expires_at: now + Duration::minutes(5),
            package_wrapper_sha256: Sha256::digest(&package).to_vec(),
            package_wrapper_bytes: package,
        }
    }

    #[test]
    fn pending_recovery_preserves_target_device_and_current_generation() {
        let row = source_row();
        let target = row.requester_device_id.to_string();
        let view = project_recovery(row).unwrap();
        assert_eq!(view.requester_device_id.as_str(), target);
        assert_eq!(view.bound_coordinate.generation, 2);
        assert_eq!(view.reservation.requester_auth_generation, 3);
    }

    #[test]
    fn pending_recovery_rejects_cross_source_binding_drift() {
        for mutate in [
            |row: &mut LeafRecoverySourceRow| row.reservation_bound_epoch += 1,
            |row: &mut LeafRecoverySourceRow| row.reservation_requester_device_id = Uuid::new_v4(),
            |row: &mut LeafRecoverySourceRow| row.reservation_requester_key_id = "other".into(),
            |row: &mut LeafRecoverySourceRow| row.reservation_requester_auth_generation += 1,
            |row: &mut LeafRecoverySourceRow| row.reservation_expires_at += Duration::seconds(1),
            |row: &mut LeafRecoverySourceRow| row.package_wrapper_sha256[0] ^= 1,
        ] {
            let mut row = source_row();
            mutate(&mut row);
            assert!(project_recovery(row).is_err());
        }
    }

    #[test]
    fn pending_recovery_requires_concrete_leaf_authority() {
        use crate::chat_protocol::read_authority::CurrentConversationRelationshipWitness as R;
        let id = Uuid::new_v4();
        assert!(R::CurrentActiveParticipant {
            participant_period_id: id
        }
        .leaf_period_id()
        .is_none());
        assert!(R::CurrentPendingParticipant {
            participant_period_id: id
        }
        .leaf_period_id()
        .is_none());
        assert!(R::CurrentOpenLeaf {
            participant_period_id: id,
            leaf_period_id: id,
            open_membership_interval_id: id
        }
        .leaf_period_id()
        .is_some());
    }

    #[tokio::test]
    #[ignore = "requires the loopback clean-chat test database"]
    async fn pending_recovery_sql_enforces_target_coordinate_and_liveness() {
        // Copy column types into transaction-local temporary tables only. This
        // exercises production SQL without resetting or mutating durable rows.
        let url = std::env::var("TEST_DATABASE_URL").expect("TEST_DATABASE_URL");
        assert_eq!(
            url,
            "postgresql://127.0.0.1:5432/catbird_chat_protocol_test_20260722"
        );
        let pool = sqlx::PgPool::connect(&url).await.unwrap();
        let mut tx = pool.begin().await.unwrap();
        for table in [
            "leaf_recovery_requests",
            "key_package_reservations",
            "key_packages",
            "conversations",
            "generation_states",
            "devices",
            "device_keys",
            "participants",
        ] {
            sqlx::query(&format!(
                "CREATE TEMP TABLE {table} AS SELECT * FROM chat.{table} WITH NO DATA"
            ))
            .execute(&mut *tx)
            .await
            .unwrap();
        }
        let cid = Uuid::new_v4();
        let target = Uuid::new_v4();
        let sibling = Uuid::new_v4();
        let rid = Uuid::new_v4();
        let now = Utc::now();
        let expiry = now + Duration::minutes(4);
        let b = format!("\\x{}", "01".repeat(32));
        let records = [
            (
                "conversations",
                serde_json::json!({"conversation_id":cid,"lifecycle":"active","current_generation":0,"current_state_version":1}),
            ),
            (
                "generation_states",
                serde_json::json!({"conversation_id":cid,"generation":0,"state_version":1,"group_id":b,"epoch":0,"group_context_hash":b,"confirmation_tag":b,"lifecycle":"active"}),
            ),
            (
                "leaf_recovery_requests",
                serde_json::json!({"recovery_request_id":rid,"reservation_request_id":rid,"conversation_id":cid,"generation":0,"requester_did":"did:plc:alice","requester_device_id":target,"requester_key_id":"key","requester_auth_generation":1,"recovery_kind":"add","bound_state_version":1,"bound_group_id":b,"bound_epoch":0,"bound_group_context_hash":b,"bound_confirmation_tag":b,"status":"open","requested_at":now,"expires_at":expiry}),
            ),
            (
                "key_package_reservations",
                serde_json::json!({"recovery_request_id":rid,"conversation_id":cid,"generation":0,"requester_did":"did:plc:alice","requester_device_id":target,"requester_key_id":"key","requester_auth_generation":1,"recipient_did":"did:plc:alice","recipient_device_id":target,"key_package_ref":b,"bound_state_version":1,"bound_group_id":b,"bound_epoch":0,"bound_group_context_hash":b,"bound_confirmation_tag":b,"status":"active","expires_at":expiry,"purpose":"leafRecovery"}),
            ),
            (
                "key_packages",
                serde_json::json!({"key_package_ref":b,"wrapper_bytes":b,"wrapper_sha256":b,"owner_did":"did:plc:alice","owner_device_id":target,"owner_key_id":"key","owner_auth_generation":1,"not_before":now-Duration::seconds(1),"not_after":now+Duration::minutes(10),"status":"reserved"}),
            ),
            (
                "devices",
                serde_json::json!({"user_did":"did:plc:alice","device_id":target,"status":"active","auth_generation":1}),
            ),
            (
                "device_keys",
                serde_json::json!({"user_did":"did:plc:alice","device_id":target,"key_id":"key","enrollment_auth_generation":1}),
            ),
            (
                "participants",
                serde_json::json!({"conversation_id":cid,"user_did":"did:plc:alice","current_membership":true,"status":"active"}),
            ),
        ];
        for (table, record) in records {
            sqlx::query(&format!("INSERT INTO pg_temp.{table} SELECT * FROM jsonb_populate_record(NULL::pg_temp.{table}, $1)"))
                .bind(record).execute(&mut *tx).await.unwrap();
        }
        let query = PENDING_LEAF_RECOVERIES_SQL.replace("chat.", "pg_temp.");
        let rows: Vec<LeafRecoverySourceRow> = sqlx::query_as(&query)
            .bind(cid)
            .bind("did:plc:alice")
            .bind(sibling)
            .fetch_all(&mut *tx)
            .await
            .unwrap();
        assert_eq!(rows.len(), 1, "same-account sibling may discover Add");
        let rows: Vec<LeafRecoverySourceRow> = sqlx::query_as(&query)
            .bind(cid)
            .bind("did:plc:alice")
            .bind(target)
            .fetch_all(&mut *tx)
            .await
            .unwrap();
        assert!(rows.is_empty(), "exact target cannot fulfill itself");
        for mutation in [
            "UPDATE pg_temp.devices SET status='revoked'",
            "UPDATE pg_temp.device_keys SET revoked_at=clock_timestamp()",
            "UPDATE pg_temp.devices SET auth_generation=2",
            "UPDATE pg_temp.leaf_recovery_requests SET bound_epoch=3",
            "UPDATE pg_temp.leaf_recovery_requests SET expires_at=clock_timestamp()-interval '1 second'",
            "UPDATE pg_temp.key_package_reservations SET status='released'",
            "UPDATE pg_temp.key_packages SET status='consumed'",
            "UPDATE pg_temp.participants SET status='removed'",
        ] {
            sqlx::query("SAVEPOINT mutation").execute(&mut *tx).await.unwrap();
            sqlx::query(mutation).execute(&mut *tx).await.unwrap();
            let rows: Vec<LeafRecoverySourceRow> = sqlx::query_as(&query).bind(cid).bind("did:plc:alice").bind(sibling).fetch_all(&mut *tx).await.unwrap();
            assert!(rows.is_empty(), "{mutation}");
            sqlx::query("ROLLBACK TO SAVEPOINT mutation").execute(&mut *tx).await.unwrap();
        }
        tx.rollback().await.unwrap();
    }

    #[test]
    fn live_conversation_state_response_encodes_nonempty_recovery_bytes_canonically() {
        let fixture: serde_json::Value = serde_json::from_str(include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/chat_protocol_g7_canonical_json_v1.json"
        ))).expect("fixture");
        let state: catbird_atproto::generated::blue_catbird::chat::ConversationState =
            serde_json::from_value(fixture["vectors"][0]["value"].clone()).expect("state");
        let recovery = project_recovery(source_row()).expect("recovery view");
        let expected_device = recovery.requester_device_id.to_string();
        let encoded = super::super::canonical_conversation_state_response(
            &state, &[recovery], &[], &[]
        ).expect("canonical response");
        assert!(encoded.starts_with(br#"{"pendingLeafRecoveryRequests":["#));
        let decoded: serde_json::Value = serde_json::from_slice(&encoded).expect("decode response");
        assert_eq!(decoded["pendingLeafRecoveryRequests"][0]["requesterDeviceId"], expected_device);
        assert!(decoded.pointer("/pendingLeafRecoveryRequests/0/boundCoordinate/groupId/$bytes")
            .and_then(serde_json::Value::as_str).is_some());
        assert!(decoded.pointer("/pendingLeafRecoveryRequests/0/reservation/keyPackage/bytes/$bytes")
            .and_then(serde_json::Value::as_str).is_some());
    }
}
