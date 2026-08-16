//! Live-PostgreSQL tests for the clean-chat inventory session, receipt, and
//! capability surfaces (lane D, ordinal 35).
//!
//! The D-2 create path (`create_inventory_session` and the
//! `create_inventory_snapshot_and_first_page` facade) is `#[cfg(not(test))]`
//! (it consumes `dpop`/`read_projection` surfaces the partial include trees
//! cannot mount), so session rows are seeded with the exact statement shapes
//! the create path issues (quoted from `inventory.rs`). The PAGING bodies —
//! `serve_initial_inventory_page`, `issue_next_inventory_page_cursor`,
//! `complete_inventory_page`, and the serve/replay machinery they compose —
//! are compiled UNCONDITIONALLY since the final-review fix round and are
//! driven DIRECTLY as production code by
//! `production_paging_entrypoints_serve_and_replay_the_full_receipt_chain`;
//! the older receipt tests additionally prove the schema's receipt,
//! consumption, materialization, immutability, and expiry semantics at the
//! SQL boundary with the real D-1 `CursorSealer`/`SecureRandom` machinery.
//!
//! The B-read admission seam (`dpop`/`read_authority`) IS test-visible and is
//! driven for real in the C-1 expiry tests: the initial-page request's
//! fail-closed gate (`verify_inventory_fence`) is exercised through the real
//! admission -> lock -> loader -> fence chain.
//!
//! Run with:
//!   CHAT_OPERATION_CLAIM_ACTIVATION_APPROVED=handlers-and-legacy-apis-sealed \
//!   TEST_DATABASE_URL=postgres://localhost/catbird_chat_protocol_test_20260722 \
//!   cargo test --test chat_protocol_inventory -- --test-threads=1

#![allow(dead_code)]

mod common;

#[path = "../src/chat_protocol/model.rs"]
mod model;
#[path = "../src/chat_protocol/transcript.rs"]
mod transcript;
#[path = "../src/chat_protocol/validation.rs"]
mod validation;

#[path = "../src/chat_protocol/cursor.rs"]
mod cursor;
#[path = "../src/chat_protocol/relationship_policy.rs"]
mod relationship_policy_source;

// Full production-module prelude (mirrors `chat_protocol_g7_entitlement.rs`)
// so the shared `common::executor_seed` fulfillment-graph builders compile
// here and can seed a coherent conversation + membership graph for the
// populated materialization tests, and so the B-read admission seam
// (`dpop`/`read_authority`/`repository::auth`) is drivable for real.
mod chat_protocol {
    pub mod cursor {
        pub use crate::cursor::*;
    }
    pub mod model {
        pub use crate::model::*;
    }
    pub mod validation {
        pub use crate::validation::*;
    }
    pub mod transcript {
        pub use crate::transcript::*;
    }
    pub mod dpop {
        #![allow(dead_code)]
        include!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/src/chat_protocol/dpop.rs"
        ));
    }
    pub mod snapshot {
        pub use catbird_server::chat_protocol::snapshot::*;
    }
    pub mod error {
        pub use catbird_server::chat_protocol::error::*;
    }
    pub mod wire {
        pub use catbird_server::chat_protocol::wire::*;
    }
    pub mod public_state {
        #![allow(dead_code)]
        include!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/src/chat_protocol/public_state.rs"
        ));
    }
    pub mod read_authority {
        #![allow(dead_code)]
        include!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/src/chat_protocol/read_authority.rs"
        ));
    }
    pub mod relationship_policy {
        pub use crate::relationship_policy_source::*;
    }
    pub mod repository {
        pub mod auth {
            #![allow(dead_code)]
            include!(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/src/chat_protocol/repository/auth.rs"
            ));
        }
        pub mod blobs {
            #![allow(dead_code)]
            include!(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/src/chat_protocol/repository/blobs.rs"
            ));
        }
        pub mod core {
            #![allow(dead_code)]
            include!(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/src/chat_protocol/repository/core.rs"
            ));
        }
        pub mod delivery {
            #![allow(dead_code)]
            include!(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/src/chat_protocol/repository/delivery.rs"
            ));
        }
        pub mod execution_context {
            #![allow(dead_code)]
            include!(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/src/chat_protocol/repository/execution_context.rs"
            ));
        }
        pub mod inventory {
            #![allow(dead_code)]
            include!(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/src/chat_protocol/repository/inventory.rs"
            ));
        }
        pub mod key_packages {
            #![allow(dead_code)]
            include!(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/src/chat_protocol/repository/key_packages.rs"
            ));
        }
        pub mod prelude {
            #![allow(dead_code)]
            include!(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/src/chat_protocol/repository/prelude.rs"
            ));
        }
        pub mod recovery {
            #![allow(dead_code)]
            include!(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/src/chat_protocol/repository/recovery.rs"
            ));
        }
        pub mod relationship {
            #![allow(dead_code)]
            include!(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/src/chat_protocol/repository/relationship.rs"
            ));
        }
        pub mod ticket {
            #![allow(dead_code)]
            include!(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/src/chat_protocol/repository/ticket.rs"
            ));
        }
        pub mod transition {
            #![allow(dead_code)]
            include!(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/src/chat_protocol/repository/transition.rs"
            ));
        }
    }
    pub mod state_machine {
        #![allow(dead_code)]
        include!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/src/chat_protocol/state_machine.rs"
        ));
    }

    /// Test-crate visibility bridge for the B-read inventory admission.
    ///
    /// `VerifiedReadAdmission`, `ReadAdmissionAttempt`, `LockedReadDeviceAuthority`,
    /// and the fence constructors are `pub(in crate::chat_protocol)`. A
    /// `#[test] fn` lives at the crate root, which is outside that visibility,
    /// so this module — INSIDE `crate::chat_protocol` — drives the real
    /// admission -> lock -> loader -> fence chain and hands the crate root
    /// only a closed outcome enum. It adds **no constructor** and widens no
    /// production visibility.
    pub mod inventory_bridge {
        use super::dpop::{seal_read_admission, ReadAdmissionAttempt};
        use super::read_authority::{
            from_locked_inventory_fence_record, lock_read_device_authority_once,
            LockedInventoryFenceRecord, LockedReadDeviceAuthority, VerifiedInventoryFence,
        };
        use sqlx::{Postgres, Transaction};
        use uuid::Uuid;

        pub(crate) const GET_CONVERSATIONS_NSID: &str = "blue.catbird.chat.getConversations";
        pub(crate) const FIXED_TEST_DID: &str = "did:plc:ewvi7nxzyoun6zhxrhs64oiz";
        pub(crate) const FIXED_TEST_DEVICE: &str = "3b241101-e2bb-4255-8caf-4136c566a962";
        pub(crate) const FIXED_TEST_JKT: &str = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
        pub(crate) const FIXED_TEST_INSTANT: &str = "2026-07-22T12:00:00.000Z";

        #[derive(Clone, Copy, Debug, Eq, PartialEq)]
        pub(crate) enum FenceOutcome {
            /// The fence verified: the session is live and servable.
            Accepted,
            /// The fence was rejected (temporal, device, protocol, or storage).
            Rejected,
        }

        /// Drive the REAL B-read chain for one inventory initial-page request
        /// against the fixed registered device, lock the session row, and
        /// verify its fence (`verify_locked_inventory_fence` composition:
        /// loader seam -> `from_lock_material` -> durable-row constructor ->
        /// consuming verification). `captured_at` is the session row's
        /// `created_at`; a session older than 15 minutes fails the temporal
        /// bound exactly as the production request does.
        pub(crate) async fn verify_session_fence_for_test(
            pool: &sqlx::PgPool,
            inventory_session_id: Uuid,
        ) -> FenceOutcome {
            let authority = match crate::repository::auth::authorize_unsigned_request(
                pool,
                super::dpop::repository_test_evidence::ordinary_registered_device(
                    Uuid::new_v4(),
                    Uuid::new_v4().as_bytes()[..12]
                        .try_into()
                        .expect("proof JTI window"),
                    GET_CONVERSATIONS_NSID,
                    FIXED_TEST_INSTANT,
                ),
            )
            .await
            {
                Ok(authority) => authority,
                Err(_) => return FenceOutcome::Rejected,
            };
            let admission = match seal_read_admission(authority) {
                Ok(admission) => admission,
                Err(_) => return FenceOutcome::Rejected,
            };
            let attempts: [ReadAdmissionAttempt; 3] =
                match admission.into_inventory_read_attempts(GET_CONVERSATIONS_NSID, "GET") {
                    Ok(attempts) => attempts,
                    Err(_) => return FenceOutcome::Rejected,
                };
            let mut transaction = match pool.begin().await {
                Ok(transaction) => transaction,
                Err(_) => return FenceOutcome::Rejected,
            };
            let device = match lock_read_device_authority_once(
                &mut transaction,
                attempts.into_iter().next().unwrap(),
            )
            .await
            {
                Ok(device) => device,
                Err(_) => return FenceOutcome::Rejected,
            };
            match verify_session_fence_in_transaction(
                &mut transaction,
                device,
                inventory_session_id,
            )
            .await
            {
                Ok(_) => {
                    let _ = transaction.rollback().await;
                    FenceOutcome::Accepted
                }
                Err(_) => {
                    let _ = transaction.rollback().await;
                    FenceOutcome::Rejected
                }
            }
        }

        /// The loader seam: `SELECT ... FOR UPDATE` over the retained session
        /// row, `from_lock_material`, the durable-row constructor, and the
        /// consuming `verify_inventory_fence` — the same chain
        /// `verify_locked_inventory_fence` (inventory.rs) composes. `device`
        /// is consumed by the verification.
        pub(crate) async fn verify_session_fence_in_transaction(
            transaction: &mut Transaction<'_, Postgres>,
            device: LockedReadDeviceAuthority,
            inventory_session_id: Uuid,
        ) -> Result<VerifiedInventoryFence, ()> {
            let row: Option<(
                Uuid,
                String,
                i64,
                Vec<u8>,
                i64,
                chrono::DateTime<chrono::Utc>,
            )> = sqlx::query_as(
                r#"
                SELECT protocol_instance_id, cursor_key_id, snapshot_event_position,
                       snapshot_event_cursor_sha256, snapshot_retained_floor, created_at
                  FROM chat.inventory_sessions
                 WHERE inventory_session_id = $1
                 FOR UPDATE
                "#,
            )
            .bind(inventory_session_id)
            .fetch_optional(&mut **transaction)
            .await
            .map_err(|_| ())?;
            let (
                protocol_instance_id,
                cursor_key_id,
                event_position,
                cursor_sha256,
                floor,
                captured_at,
            ) = row.ok_or(())?;
            let event_position = u64::try_from(event_position).map_err(|_| ())?;
            let floor = u64::try_from(floor).map_err(|_| ())?;
            let cursor_sha256: [u8; 32] = cursor_sha256.try_into().map_err(|_| ())?;
            let record = LockedInventoryFenceRecord::from_lock_material(
                protocol_instance_id,
                cursor_key_id,
                event_position,
                cursor_sha256,
                floor,
                captured_at,
            )
            .map_err(|_| ())?;
            let durable_row = from_locked_inventory_fence_record(record);
            super::read_authority::verify_inventory_fence(transaction, device, durable_row)
                .await
                .map_err(|_| ())
        }
    }
}

#[path = "common/executor_seed.rs"]
mod executor_seed;

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use chat_protocol::cursor::{
    decode_capability_token, mint_capability_token, CapabilityToken, CursorSealer,
    SealedCapability, SealerBinding, SecureRandom, SecureRandomError,
};
use chrono::{DateTime, Duration, TimeZone, Utc};
use repository::inventory::{
    create_device_inventory_session, get_devices, CreateDeviceInventorySessionRequest,
    DeviceInventorySubject, EventTerminalHint, IntervalSummaryTerminalHint, InventoryDomain,
    InventoryPublicRequestBinding, InventoryRepositoryError, InventorySummaryTerminalHint,
    TombstoneTerminalHint, INVENTORY_CONVERSATIONS_NSID, MAX_GET_DEVICES_DIDS,
};
use repository::ticket::{ticket_hash, SUBSCRIBE_EVENTS_PATH};
use sha2::{Digest, Sha256};
use sqlx::PgPool;
use uuid::Uuid;
use zeroize::Zeroizing;

mod repository {
    pub use crate::chat_protocol::repository::*;
}

fn random_plc_did() -> String {
    const ALPHABET: &[u8] = b"abcdefghijklmnopqrstuvwxyz234567";
    let mut bytes = Uuid::new_v4().as_bytes().to_vec();
    bytes.extend_from_slice(Uuid::new_v4().as_bytes());
    let suffix: String = bytes
        .iter()
        .take(24)
        .map(|byte| ALPHABET[(*byte % 32) as usize] as char)
        .collect();
    format!("did:plc:{suffix}")
}

async fn clock_now(pool: &PgPool) -> DateTime<Utc> {
    sqlx::query_scalar("SELECT clock_timestamp()")
        .fetch_one(pool)
        .await
        .expect("sample trusted database clock")
}

async fn fresh_jkt(pool: &PgPool) -> String {
    let mut blob = Uuid::new_v4().as_bytes().to_vec();
    blob.extend_from_slice(Uuid::new_v4().as_bytes());
    sqlx::query_scalar("SELECT chat.ed25519_key_id($1)")
        .bind(blob)
        .fetch_one(pool)
        .await
        .expect("derive jkt")
}

async fn seed_principal(pool: &PgPool, did: &str, at: DateTime<Utc>) {
    sqlx::query(
        "INSERT INTO chat.principals(user_did,created_at) VALUES($1,$2) ON CONFLICT DO NOTHING",
    )
    .bind(did)
    .bind(at)
    .execute(pool)
    .await
    .expect("insert principal");
}

async fn seed_active_device(pool: &PgPool, did: &str, at: DateTime<Utc>) -> Uuid {
    let device_id = Uuid::new_v4();
    let jkt = fresh_jkt(pool).await;
    sqlx::query(
        "INSERT INTO chat.devices(user_did,device_id,device_name,status,dpop_jkt,auth_generation,capabilities,created_at,updated_at) \
         VALUES($1,$2,'dev-active','active',$3,1,chat.protocol_capabilities(),$4,$4)",
    )
    .bind(did)
    .bind(device_id)
    .bind(&jkt)
    .bind(at)
    .execute(pool)
    .await
    .expect("insert active device");
    device_id
}

fn fresh_blob() -> Vec<u8> {
    let mut b = Uuid::new_v4().as_bytes().to_vec();
    b.extend_from_slice(Uuid::new_v4().as_bytes());
    b
}

/// Seed a coherent REVOKED device (self-revocation) for `did`: an active device
/// with its single device key, then the full revocation graph the deferred
/// `assert_device_revocation_mapping` trigger requires — a `revokeDevice`
/// operation claim + idempotency receipt pair (the claim is the receipt's FK
/// parent and the deferred `assert_operation_claim_mapping` requires the
/// classifiable wrapper/transcript kinds to agree), the `device_revocations`
/// row, and the target device/key terminalization. `get_devices` must exclude
/// the result (status `<> 'active'` / `revoked_at IS NOT NULL`).
async fn seed_revoked_device(pool: &PgPool, did: &str, created_at: DateTime<Utc>) -> Uuid {
    let device_id = Uuid::new_v4();
    let jkt = fresh_jkt(pool).await;
    let public_key = fresh_blob();
    let key_id: String = sqlx::query_scalar("SELECT chat.ed25519_key_id($1)")
        .bind(&public_key)
        .fetch_one(pool)
        .await
        .expect("derive key id");

    sqlx::query(
        "INSERT INTO chat.devices(user_did,device_id,device_name,status,dpop_jkt,auth_generation,capabilities,created_at,updated_at) \
         VALUES($1,$2,'dev-revoked','active',$3,1,chat.protocol_capabilities(),$4,$4)",
    )
    .bind(did)
    .bind(device_id)
    .bind(&jkt)
    .bind(created_at)
    .execute(pool)
    .await
    .expect("insert active device to revoke");
    sqlx::query(
        "INSERT INTO chat.device_keys(user_did,device_id,key_id,signing_public_key,enrollment_auth_generation,created_at) \
         VALUES($1,$2,$3,$4,1,$5)",
    )
    .bind(did)
    .bind(device_id)
    .bind(&key_id)
    .bind(&public_key)
    .bind(created_at)
    .execute(pool)
    .await
    .expect("insert device key");

    // Self-revocation: the actor is the same device/key as the target. The
    // revocation is accepted strictly after creation so every `created_at <=
    // accepted_at` binding holds.
    //
    // The receipt/claim byte shapes must be CLASSIFIABLE, not random: the
    // deferred `assert_operation_claim_mapping` (migration 20260728000002)
    // derives the mutation kind from BOTH the wrapper JSON (`body.$type`) and
    // the transcript's NUL-terminated signature domain, and requires claim ==
    // wrapper == transcript kind with an endpoint that accepts it.
    let accepted_at = created_at + Duration::seconds(30);
    let revocation_id = Uuid::new_v4();
    let accepted_request_bytes =
        br#"{"body":{"$type":"blue.catbird.chat.defs#deviceRevocationBody"}}"#.to_vec();
    let accepted_request_sha256: [u8; 32] = Sha256::digest(&accepted_request_bytes).into();
    let mut signing_transcript_bytes = b"CATBIRD-CHAT-DEVICE-REVOKE\0".to_vec();
    signing_transcript_bytes.extend_from_slice(&fresh_blob());
    let request_digest: [u8; 32] = Sha256::digest(&signing_transcript_bytes).into();
    let signature = [3_u8; 64];
    let response = br#"{"revoked":true}"#;
    let response_sha256: [u8; 32] = Sha256::digest(response).into();

    let mut tx = pool.begin().await.expect("begin revocation");
    // The operation claim is the receipt's parent row
    // (`idempotency_records_operation_claim_fk` is IMMEDIATE), inserted first
    // in the same transaction with the exact receipt-matching authority
    // columns the deferred mapping assert re-joins on.
    sqlx::query(
        r#"
        INSERT INTO chat.operation_claims (
            operation_id, principal_did, endpoint_nsid, mutation_kind,
            request_digest, accepted_request_sha256, signature, claimed_at
        ) VALUES ($1,$2,'blue.catbird.chat.revokeDevice',
                  'blue.catbird.chat.defs#deviceRevocationBody',$3,$4,$5,$6)
        "#,
    )
    .bind(revocation_id)
    .bind(did)
    .bind(request_digest.as_slice())
    .bind(accepted_request_sha256.as_slice())
    .bind(signature.as_slice())
    .bind(accepted_at)
    .execute(&mut *tx)
    .await
    .expect("insert revokeDevice operation claim");
    sqlx::query(
        r#"
        INSERT INTO chat.idempotency_records (
            principal_did, endpoint_nsid, operation_id, request_digest,
            accepted_request_bytes, signing_transcript_bytes, signature,
            completed_status, response_bytes, response_sha256,
            historical_jkt, completed_at
        ) VALUES ($1,'blue.catbird.chat.revokeDevice',$2,$3,$4,$5,$6,200,$7,$8,$9,$10)
        "#,
    )
    .bind(did)
    .bind(revocation_id)
    .bind(request_digest.as_slice())
    .bind(&accepted_request_bytes)
    .bind(&signing_transcript_bytes)
    .bind(signature.as_slice())
    .bind(response.as_slice())
    .bind(response_sha256.as_slice())
    .bind(&jkt)
    .bind(accepted_at)
    .execute(&mut *tx)
    .await
    .expect("insert revokeDevice receipt");
    sqlx::query(
        r#"
        INSERT INTO chat.device_revocations (
            revocation_id, actor_did, actor_device_id, actor_key_id,
            actor_auth_generation, target_did, target_device_id,
            target_auth_generation, accepted_request_bytes,
            signing_transcript_bytes, request_digest, signature,
            signed_at, accepted_at
        ) VALUES ($1,$2,$3,$4,1,$2,$3,1,$5,$6,$7,$8,$9,$9)
        "#,
    )
    .bind(revocation_id)
    .bind(did)
    .bind(device_id)
    .bind(&key_id)
    .bind(&accepted_request_bytes)
    .bind(&signing_transcript_bytes)
    .bind(request_digest.as_slice())
    .bind(signature.as_slice())
    .bind(accepted_at)
    .execute(&mut *tx)
    .await
    .expect("insert device revocation");
    sqlx::query(
        "UPDATE chat.devices SET status='revoked', updated_at=$3, revoked_at=$3, revocation_id=$4 \
         WHERE user_did=$1 AND device_id=$2",
    )
    .bind(did)
    .bind(device_id)
    .bind(accepted_at)
    .bind(revocation_id)
    .execute(&mut *tx)
    .await
    .expect("revoke target device");
    sqlx::query(
        "UPDATE chat.device_keys SET revoked_at=$3, revocation_id=$4 WHERE user_did=$1 AND device_id=$2",
    )
    .bind(did)
    .bind(device_id)
    .bind(accepted_at)
    .bind(revocation_id)
    .execute(&mut *tx)
    .await
    .expect("revoke target device key");
    tx.commit().await.expect("commit revocation");

    device_id
}

#[tokio::test]
async fn get_devices_rejects_zero_or_too_many_dids() {
    let pool = common::chat_protocol::setup_chat_protocol_db(2).await;

    let mut tx = pool.begin().await.expect("begin");
    let empty = get_devices(&mut tx, &[]).await;
    assert!(
        matches!(empty, Err(InventoryRepositoryError::RequestTooBroad)),
        "zero DIDs must be rejected, got {empty:?}"
    );

    let too_many: Vec<String> = (0..=MAX_GET_DEVICES_DIDS)
        .map(|_| random_plc_did())
        .collect();
    let over = get_devices(&mut tx, &too_many).await;
    assert!(
        matches!(over, Err(InventoryRepositoryError::RequestTooBroad)),
        "more than {MAX_GET_DEVICES_DIDS} DIDs must be rejected, got {over:?}"
    );
    tx.rollback().await.expect("rollback");
}

#[tokio::test]
async fn get_devices_returns_active_devices_scoped_to_requested_dids() {
    let pool = common::chat_protocol::setup_chat_protocol_db(2).await;
    let now = clock_now(&pool).await;

    let did_a = random_plc_did();
    let did_b = random_plc_did();
    let did_c = random_plc_did();
    seed_principal(&pool, &did_a, now).await;
    seed_principal(&pool, &did_b, now).await;
    seed_principal(&pool, &did_c, now).await;

    let a1 = seed_active_device(&pool, &did_a, now).await;
    let a2 = seed_active_device(&pool, &did_a, now).await;
    let b1 = seed_active_device(&pool, &did_b, now).await;
    let c1 = seed_active_device(&pool, &did_c, now).await;

    let mut tx = pool.begin().await.expect("begin");
    let devices = get_devices(&mut tx, &[did_a.clone(), did_b.clone()])
        .await
        .expect("get_devices executes");
    tx.rollback().await.expect("rollback");

    let returned: std::collections::HashSet<Uuid> = devices.iter().map(|d| d.device_id).collect();
    assert!(
        returned.contains(&a1) && returned.contains(&a2),
        "both of A's active devices"
    );
    assert!(returned.contains(&b1), "B's active device");
    assert!(
        !returned.contains(&c1),
        "a device of a DID that was not requested must be excluded"
    );
    // Every returned row is active and belongs to a requested DID.
    for d in &devices {
        assert_eq!(d.status, "active");
        assert!(d.user_did == did_a || d.user_did == did_b);
    }
    assert_eq!(
        devices.len(),
        3,
        "exactly the three active in-scope devices"
    );
}

#[tokio::test]
async fn get_devices_excludes_revoked_devices() {
    let pool = common::chat_protocol::setup_chat_protocol_db(2).await;
    let now = clock_now(&pool).await;

    let did = random_plc_did();
    seed_principal(&pool, &did, now).await;
    let active = seed_active_device(&pool, &did, now).await;
    let revoked = seed_revoked_device(&pool, &did, now).await;

    let mut tx = pool.begin().await.expect("begin");
    let devices = get_devices(&mut tx, &[did.clone()])
        .await
        .expect("get_devices executes");
    tx.rollback().await.expect("rollback");

    let returned: std::collections::HashSet<Uuid> = devices.iter().map(|d| d.device_id).collect();
    assert!(returned.contains(&active), "the active device is returned");
    assert!(
        !returned.contains(&revoked),
        "a revoked device must be excluded by the status/revoked_at predicate"
    );
    for d in &devices {
        assert_eq!(d.status, "active", "every returned device is active");
        assert_eq!(d.user_did, did);
    }
}

// ===========================================================================
// D-3 seeded-session machinery: the D-2 create/serve statement shapes,
// replicated so the capability/receipt contract can be proven against the
// fixed target without the `#[cfg(not(test))]` facade. Every row written here
// is a test-owned row (b-auth DB-test ownership/classification rules).
// ===========================================================================

fn whole_second(dt: DateTime<Utc>) -> DateTime<Utc> {
    Utc.timestamp_opt(dt.timestamp(), 0)
        .single()
        .expect("whole-second instant")
}

/// The seed bytes for the protocol singleton's cursor key. The durable
/// `cursor_key_id` TEXT is `chat.ed25519_key_id(seed)` — base64url of the
/// SHA-256 DIGEST of these bytes, NOT of the bytes themselves — and it is the
/// same `0x51` constant the shared `executor_seed` fixtures use, so a
/// fixture-seeded singleton and an `ensure_fence`-seeded one carry the
/// identical key text. The sealer's 32-byte `key_id` must therefore be the
/// DECODED durable text (`CursorSealer::matches_binding_key` compares
/// decode(cursor_key_id) against `key_id`); building the sealer from the raw
/// seed bytes was exactly the DB-window `WrongKey` failure.
const CURSOR_KEY_ID_SEED: [u8; 32] = [0x51; 32];

/// The D sealing secret (test-owned; independent of the key id).
const SEALER_SECRET: [u8; 32] = [0xA5; 32];

/// Build the D sealer for the DURABLE singleton cursor-key text: `key_id` =
/// the decoded base64url of the text — matching whatever actor seeded the
/// singleton (this suite's `ensure_fence` or a shared fixture).
fn sealer_for_cursor_key(cursor_key_id: &str) -> CursorSealer {
    let decoded = URL_SAFE_NO_PAD
        .decode(cursor_key_id)
        .expect("the durable cursor_key_id is canonical base64url");
    let key_id: [u8; 32] = decoded
        .try_into()
        .expect("the durable cursor_key_id decodes to 32 bytes");
    CursorSealer::new(key_id, Zeroizing::new(SEALER_SECRET))
        .expect("a non-zero sealing secret is a valid configuration")
}

struct Fence {
    protocol_instance_id: Uuid,
    cursor_key_id: String,
    sealer: CursorSealer,
}

/// Ensure the protocol singleton + retention floor exist (a concurrent suite
/// may have seeded them already) and return a `Fence` bound to the singleton's
/// exact `protocol_instance_id` + `cursor_key_id`, with the matching sealer.
async fn ensure_fence(pool: &PgPool) -> Fence {
    let cursor_key: String = sqlx::query_scalar("SELECT chat.ed25519_key_id($1)")
        .bind(CURSOR_KEY_ID_SEED.to_vec())
        .fetch_one(pool)
        .await
        .expect("derive cursor key");
    sqlx::query(
        "INSERT INTO chat.protocol_instances(singleton,protocol_version,protocol_instance_id,cursor_key_id) \
         VALUES(TRUE,'1',$1,$2) ON CONFLICT DO NOTHING",
    )
    .bind(Uuid::new_v4())
    .bind(&cursor_key)
    .execute(pool)
    .await
    .expect("seed protocol instance");
    let (protocol_instance_id, cursor_key_id): (Uuid, String) = sqlx::query_as(
        "SELECT protocol_instance_id, cursor_key_id FROM chat.protocol_instances WHERE singleton = TRUE",
    )
    .fetch_one(pool)
    .await
    .expect("read protocol instance");
    sqlx::query(
        "INSERT INTO chat.event_retention(protocol_instance_id,retained_floor,updated_at) \
         VALUES($1,0,clock_timestamp()) ON CONFLICT DO NOTHING",
    )
    .bind(protocol_instance_id)
    .execute(pool)
    .await
    .expect("seed retention floor");
    Fence {
        protocol_instance_id,
        sealer: sealer_for_cursor_key(&cursor_key_id),
        cursor_key_id,
    }
}

/// The current `chat.events` head, used as the D-2 snapshot position (the
/// create path snapshots at the head; the final fence revalidation requires
/// `snapshot_event_position <= max(event_position)`).
async fn event_head(pool: &PgPool) -> i64 {
    sqlx::query_scalar("SELECT coalesce(max(event_position),0)::bigint FROM chat.events")
        .fetch_one(pool)
        .await
        .expect("read the current event head")
}

/// Deterministic session identity (replica of the D-2
/// `derive_inventory_session_uuid`): v4-masked SHA-256 over the verified
/// `(DID, device, JKT, auth generation)` coordinates. The retained session row
/// is keyed by this identity, so repeated initial-page calls and concurrent
/// second creators deterministically select the SAME session.
fn derive_inventory_session_uuid(
    user_did: &str,
    device_id: Uuid,
    jkt: &str,
    auth_generation: u64,
) -> Uuid {
    let mut digest = Sha256::new();
    digest.update(b"CATBIRD-CHAT-INVENTORY-SESSION-IDENTITY\0");
    digest.update((user_did.len() as u64).to_be_bytes());
    digest.update(user_did.as_bytes());
    digest.update(device_id.as_bytes());
    digest.update((jkt.len() as u64).to_be_bytes());
    digest.update(jkt.as_bytes());
    digest.update(auth_generation.to_be_bytes());
    let bytes: [u8; 32] = digest.finalize().into();
    let mut uuid_bytes = [0u8; 16];
    uuid_bytes.copy_from_slice(&bytes[..16]);
    uuid_bytes[6] = (uuid_bytes[6] & 0x0F) | 0x40;
    uuid_bytes[8] = (uuid_bytes[8] & 0x3F) | 0x80;
    Uuid::from_bytes(uuid_bytes)
}

/// The event-cursor receipt binding for one session row (replica of the D-2
/// `verify_successor_capability` binding derivation; the AAD field list is the
/// frozen `SealerBinding::for_event_cursor_receipt` shape).
#[allow(clippy::too_many_arguments)]
fn event_cursor_binding(
    fence: &Fence,
    session_id: Uuid,
    user_did: &str,
    device_id: Uuid,
    jkt: &str,
    auth_generation: u64,
    event_position: u64,
    retained_floor: u64,
    created_at: u64,
    expires_at: u64,
) -> SealerBinding {
    SealerBinding::for_event_cursor_receipt(
        session_id,
        user_did.as_bytes(),
        device_id,
        jkt.as_bytes(),
        auth_generation,
        fence.protocol_instance_id,
        fence.cursor_key_id.as_bytes(),
        event_position,
        None,
        retained_floor,
        created_at,
        expires_at,
    )
    .expect("event-cursor binding fields are the seeded row's own columns")
}

struct SessionDevice {
    did: String,
    device_id: Uuid,
    jkt: String,
}

/// Seed an active device WITH its single device key (the create path joins
/// `device_keys`), returning the identity fields a session row binds.
async fn seed_device_with_key(pool: &PgPool, at: DateTime<Utc>) -> SessionDevice {
    let did = random_plc_did();
    let device_id = Uuid::new_v4();
    let jkt = fresh_jkt(pool).await;
    let public_key = fresh_blob();
    let key_id: String = sqlx::query_scalar("SELECT chat.ed25519_key_id($1)")
        .bind(&public_key)
        .fetch_one(pool)
        .await
        .expect("derive key id");
    seed_principal(pool, &did, at).await;
    sqlx::query(
        "INSERT INTO chat.devices(user_did,device_id,device_name,status,dpop_jkt,auth_generation,capabilities,created_at,updated_at) \
         VALUES($1,$2,'dev-session','active',$3,1,chat.protocol_capabilities(),$4,$4)",
    )
    .bind(&did)
    .bind(device_id)
    .bind(&jkt)
    .bind(at)
    .execute(pool)
    .await
    .expect("insert device");
    sqlx::query(
        "INSERT INTO chat.device_keys(user_did,device_id,key_id,signing_public_key,enrollment_auth_generation,created_at) \
         VALUES($1,$2,$3,$4,1,$5)",
    )
    .bind(&did)
    .bind(device_id)
    .bind(&key_id)
    .bind(&public_key)
    .bind(at)
    .execute(pool)
    .await
    .expect("insert device key");
    SessionDevice {
        did,
        device_id,
        jkt,
    }
}

/// Seed the FIXED B-read device identity (the `ordinary_registered_device`
/// evidence subject) so the real admission seam can lock it.
async fn seed_fixed_admission_device(pool: &PgPool) {
    let fixed_at = Utc.timestamp_opt(1_753_190_400, 0).unwrap(); // 2026-07-22T12:00:00Z
    seed_principal(
        pool,
        chat_protocol::inventory_bridge::FIXED_TEST_DID,
        fixed_at,
    )
    .await;
    let public_key = fresh_blob();
    let key_id: String = sqlx::query_scalar("SELECT chat.ed25519_key_id($1)")
        .bind(&public_key)
        .fetch_one(pool)
        .await
        .expect("derive key id");
    sqlx::query(
        "INSERT INTO chat.devices(user_did,device_id,device_name,status,dpop_jkt,auth_generation,capabilities,created_at,updated_at) \
         VALUES($1,$2,'dev-b-read','active',$3,1,chat.protocol_capabilities(),$4,$4) ON CONFLICT DO NOTHING",
    )
    .bind(chat_protocol::inventory_bridge::FIXED_TEST_DID)
    .bind(Uuid::parse_str(chat_protocol::inventory_bridge::FIXED_TEST_DEVICE).unwrap())
    .bind(chat_protocol::inventory_bridge::FIXED_TEST_JKT)
    .bind(fixed_at)
    .execute(pool)
    .await
    .expect("insert fixed B-read device");
    sqlx::query(
        "INSERT INTO chat.device_keys(user_did,device_id,key_id,signing_public_key,enrollment_auth_generation,created_at) \
         VALUES($1,$2,$3,$4,1,$5) ON CONFLICT DO NOTHING",
    )
    .bind(chat_protocol::inventory_bridge::FIXED_TEST_DID)
    .bind(Uuid::parse_str(chat_protocol::inventory_bridge::FIXED_TEST_DEVICE).unwrap())
    .bind(&key_id)
    .bind(&public_key)
    .bind(fixed_at)
    .execute(pool)
    .await
    .expect("insert fixed B-read device key");
}

/// One seeded conversation item row (state arm), with the arm-provenance
/// columns the source-precedence trigger and the materialization transcript
/// require.
struct ConversationItemSeed {
    conversation_id: Uuid,
    participant_period_id: Uuid,
    recipient_did: String,
    recipient_device_id: Uuid,
    payload: Vec<u8>,
}

/// One seeded Welcome item row.
struct WelcomeItemSeed {
    welcome_id: Uuid,
    recipient_did: String,
    recipient_device_id: Uuid,
    payload: Vec<u8>,
}

/// One seeded recovery item row (leafRecoveryRequest arm).
struct RecoveryItemSeed {
    recovery_request_id: Uuid,
    recipient_did: String,
    recipient_device_id: Uuid,
    payload: Vec<u8>,
}

/// The G7 conversation transcript (replica of `assert_inventory_materialization`):
/// `int8send(ordinal) || item_key_bytes || int4(len(item_kind)) || item_kind ||
/// tagged participant_period_id || tagged membership_interval_id ||
/// tagged interval_terminal_seq || tagged interval_closing_transition_id ||
/// tagged interval_closing_outer_entry_fingerprint || tagged interval_removed_at ||
/// tagged schedule_terminal_seq || tagged schedule_terminal_transition_id ||
/// tagged schedule_terminal_outer_entry_fingerprint || payload_sha256 ||
/// int8(len(payload))`, concatenated in ordinal order, SHA-256.
fn conversation_transcript_digest(items: &[ConversationItemSeed]) -> [u8; 32] {
    let mut digest = Sha256::new();
    let item_kind = "blue.catbird.chat.defs#conversationInventoryState";
    for (ordinal, item) in items.iter().enumerate() {
        digest.update((ordinal as u64).to_be_bytes());
        digest.update(item.conversation_id.as_bytes());
        digest.update((item_kind.len() as u32).to_be_bytes());
        digest.update(item_kind.as_bytes());
        digest.update([1]);
        digest.update(item.participant_period_id.as_bytes());
        digest.update([0]); // membership_interval_id
        digest.update([0]); // interval_terminal_seq
        digest.update([0]); // interval_closing_transition_id
        digest.update([0]); // interval_closing_outer_entry_fingerprint
        digest.update([0]); // interval_removed_at
        digest.update([0]); // schedule_terminal_seq
        digest.update([0]); // schedule_terminal_transition_id
        digest.update([0]); // schedule_terminal_outer_entry_fingerprint
        digest.update(Sha256::digest(&item.payload));
        digest.update((item.payload.len() as u64).to_be_bytes());
    }
    digest.finalize().into()
}

/// The G7 Welcome transcript: `ordinal || item_key_bytes || payload_sha256 ||
/// int8(len(payload))`, SHA-256.
fn welcome_transcript_digest(items: &[WelcomeItemSeed]) -> [u8; 32] {
    let mut digest = Sha256::new();
    for (ordinal, item) in items.iter().enumerate() {
        digest.update((ordinal as u64).to_be_bytes());
        digest.update(item.welcome_id.as_bytes());
        digest.update(Sha256::digest(&item.payload));
        digest.update((item.payload.len() as u64).to_be_bytes());
    }
    digest.finalize().into()
}

/// The G7 recovery transcript: `ordinal || item_key_bytes || payload_sha256 ||
/// int8(len(payload))`, SHA-256 (the 0x00-prefixed request key).
fn recovery_transcript_digest(items: &[RecoveryItemSeed]) -> [u8; 32] {
    let mut digest = Sha256::new();
    for (ordinal, item) in items.iter().enumerate() {
        digest.update((ordinal as u64).to_be_bytes());
        digest.update([0x00]);
        digest.update(item.recovery_request_id.as_bytes());
        digest.update(Sha256::digest(&item.payload));
        digest.update((item.payload.len() as u64).to_be_bytes());
    }
    digest.finalize().into()
}

struct SeededSession {
    session_id: Uuid,
    user_did: String,
    device_id: Uuid,
    jkt: String,
    auth_generation: u64,
    capability: CapabilityToken,
    capability_hash: [u8; 32],
    sealed: SealedCapability,
    created_at: DateTime<Utc>,
    expires_at: DateTime<Utc>,
    snapshot_event_position: i64,
    retained_floor: i64,
}

/// Seed one retained inventory session row in the EXACT D-2 create shape
/// (inventory.rs `create_inventory_session`): one random capability minted and
/// sealed under the event-cursor binding, only the SHA-256 lookup hash + the
/// nonce/ciphertext pair at rest, all three `*_complete` proven true with the
/// exact transcript evidence, and all three `*_consumed` false. The domain
/// item rows are seeded first; the completion evidence is computed with the
/// same transcripts `assert_inventory_materialization` recomputes.
#[allow(clippy::too_many_arguments)]
async fn seed_session_via_create_shape(
    pool: &PgPool,
    fence: &Fence,
    device: &SessionDevice,
    session_id: Uuid,
    created_at: DateTime<Utc>,
    expires_at: DateTime<Utc>,
    random: &mut dyn SecureRandom,
    conversations: &[ConversationItemSeed],
    welcomes: &[WelcomeItemSeed],
    recovery: &[RecoveryItemSeed],
) -> SeededSession {
    seed_session_shape(
        pool,
        fence,
        device,
        session_id,
        created_at,
        expires_at,
        random,
        conversations,
        welcomes,
        recovery,
        true,
    )
    .await
}

/// The OPEN-domain variant: the identical create-shape session row, but the
/// three domains STAY MATERIALIZING (`*_complete = FALSE`, no completion
/// evidence). This is the only durable state in which the per-item identity
/// CHECKs and deferred source FKs are reachable — the
/// `assert_inventory_item_session_open` trigger rejects any item insert into a
/// completed domain before those are evaluated.
async fn seed_open_session_via_create_shape(
    pool: &PgPool,
    fence: &Fence,
    device: &SessionDevice,
    session_id: Uuid,
    created_at: DateTime<Utc>,
    expires_at: DateTime<Utc>,
    random: &mut dyn SecureRandom,
) -> SeededSession {
    seed_session_shape(
        pool,
        fence,
        device,
        session_id,
        created_at,
        expires_at,
        random,
        &[],
        &[],
        &[],
        false,
    )
    .await
}

#[allow(clippy::too_many_arguments)]
async fn seed_session_shape(
    pool: &PgPool,
    fence: &Fence,
    device: &SessionDevice,
    session_id: Uuid,
    created_at: DateTime<Utc>,
    expires_at: DateTime<Utc>,
    random: &mut dyn SecureRandom,
    conversations: &[ConversationItemSeed],
    welcomes: &[WelcomeItemSeed],
    recovery: &[RecoveryItemSeed],
    prove_complete: bool,
) -> SeededSession {
    let created_at = whole_second(created_at);
    let expires_at = whole_second(expires_at);
    let snapshot_event_position = event_head(pool).await;
    let retained_floor: i64 = sqlx::query_scalar(
        "SELECT retained_floor FROM chat.event_retention WHERE protocol_instance_id = $1",
    )
    .bind(fence.protocol_instance_id)
    .fetch_one(pool)
    .await
    .expect("read the seeded retention floor");

    let capability = mint_capability_token(random).expect("mint the session capability");
    let capability_hash = capability.lookup_hash();
    let binding = event_cursor_binding(
        fence,
        session_id,
        &device.did,
        device.device_id,
        &device.jkt,
        1,
        u64::try_from(snapshot_event_position).expect("head fits u64"),
        u64::try_from(retained_floor).expect("floor fits u64"),
        u64::try_from(created_at.timestamp()).expect("created fits u64"),
        u64::try_from(expires_at.timestamp()).expect("expiry fits u64"),
    );
    let sealed = fence
        .sealer
        .seal_successor(capability.as_bytes(), &binding, random)
        .expect("seal the session capability at rest");

    let conversation_digest = conversation_transcript_digest(conversations);
    let welcome_digest = welcome_transcript_digest(welcomes);
    let recovery_digest = recovery_transcript_digest(recovery);
    let conversation_payload: i64 = conversations.iter().map(|i| i.payload.len() as i64).sum();
    let welcome_payload: i64 = welcomes.iter().map(|i| i.payload.len() as i64).sum();
    let recovery_payload: i64 = recovery.iter().map(|i| i.payload.len() as i64).sum();

    let mut tx = pool.begin().await.expect("begin session seed");
    sqlx::query(
        r#"
        INSERT INTO chat.inventory_sessions(
            inventory_session_id, token_hash, user_did, device_id, jkt,
            auth_generation, snapshot_event_position, snapshot_event_cursor_sha256,
            created_at, expires_at, protocol_instance_id, cursor_key_id,
            cursor_format_version, snapshot_retained_floor,
            snapshot_event_cursor_nonce, snapshot_event_cursor_ciphertext,
            conversations_complete, welcomes_complete, recovery_complete,
            conversations_consumed, welcomes_consumed, recovery_consumed
        ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,1,$13,$14,$15,
                  FALSE,FALSE,FALSE,FALSE,FALSE,FALSE)
        "#,
    )
    .bind(session_id)
    .bind(capability_hash.as_slice())
    .bind(&device.did)
    .bind(device.device_id)
    .bind(&device.jkt)
    .bind(1_i64)
    .bind(snapshot_event_position)
    .bind(capability_hash.as_slice())
    .bind(created_at)
    .bind(expires_at)
    .bind(fence.protocol_instance_id)
    .bind(&fence.cursor_key_id)
    .bind(retained_floor)
    .bind(&sealed.nonce)
    .bind(&sealed.ciphertext)
    .execute(&mut *tx)
    .await
    .expect("insert the session row");

    for (ordinal, item) in conversations.iter().enumerate() {
        let payload_sha256: [u8; 32] = Sha256::digest(&item.payload).into();
        sqlx::query(
            r#"
            INSERT INTO chat.inventory_conversation_items(
                inventory_session_id, ordinal, conversation_id, recipient_did,
                recipient_device_id, item_kind, participant_period_id,
                membership_interval_id, interval_terminal_seq,
                interval_closing_transition_id,
                interval_closing_outer_entry_fingerprint, interval_removed_at,
                schedule_terminal_seq, schedule_terminal_transition_id,
                schedule_terminal_outer_entry_fingerprint,
                item_key_bytes, payload_bytes, payload_sha256
            ) VALUES ($1,$2,$3,$4,$5,$6,$7,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,
                      uuid_send($3),$8,$9)
            "#,
        )
        .bind(session_id)
        .bind(ordinal as i64)
        .bind(item.conversation_id)
        .bind(&item.recipient_did)
        .bind(item.recipient_device_id)
        .bind("blue.catbird.chat.defs#conversationInventoryState")
        .bind(item.participant_period_id)
        .bind(&item.payload)
        .bind(payload_sha256.as_slice())
        .execute(&mut *tx)
        .await
        .expect("insert conversation item");
    }
    for (ordinal, item) in welcomes.iter().enumerate() {
        let payload_sha256: [u8; 32] = Sha256::digest(&item.payload).into();
        sqlx::query(
            r#"
            INSERT INTO chat.inventory_welcome_items(
                inventory_session_id, ordinal, welcome_id, recipient_did,
                recipient_device_id, item_key_bytes, payload_bytes, payload_sha256
            ) VALUES ($1,$2,$3,$4,$5,uuid_send($3),$6,$7)
            "#,
        )
        .bind(session_id)
        .bind(ordinal as i64)
        .bind(item.welcome_id)
        .bind(&item.recipient_did)
        .bind(item.recipient_device_id)
        .bind(&item.payload)
        .bind(payload_sha256.as_slice())
        .execute(&mut *tx)
        .await
        .expect("insert welcome item");
    }
    for (ordinal, item) in recovery.iter().enumerate() {
        let payload_sha256: [u8; 32] = Sha256::digest(&item.payload).into();
        let mut item_key = vec![0x00u8];
        item_key.extend_from_slice(item.recovery_request_id.as_bytes());
        sqlx::query(
            r#"
            INSERT INTO chat.inventory_recovery_items(
                inventory_session_id, ordinal, item_kind, leaf_recovery_request_id,
                recovery_work_id, recipient_did, recipient_device_id,
                item_key_bytes, payload_bytes, payload_sha256
            ) VALUES ($1,$2,'leafRecoveryRequest',$3,NULL,$4,$5,$6,$7,$8)
            "#,
        )
        .bind(session_id)
        .bind(ordinal as i64)
        .bind(item.recovery_request_id)
        .bind(&item.recipient_did)
        .bind(item.recipient_device_id)
        .bind(&item_key)
        .bind(&item.payload)
        .bind(payload_sha256.as_slice())
        .execute(&mut *tx)
        .await
        .expect("insert recovery item");
    }

    if prove_complete {
        sqlx::query(
            r#"
        UPDATE chat.inventory_sessions
           SET conversations_complete = TRUE,
               conversation_item_count = $2, conversation_items_sha256 = $3,
               conversation_payload_bytes = $4,
               welcomes_complete = TRUE,
               welcome_item_count = $5, welcome_items_sha256 = $6,
               welcome_payload_bytes = $7,
               recovery_complete = TRUE,
               recovery_item_count = $8, recovery_items_sha256 = $9,
               recovery_payload_bytes = $10
         WHERE inventory_session_id = $1
        "#,
        )
        .bind(session_id)
        .bind(conversations.len() as i64)
        .bind(conversation_digest.as_slice())
        .bind(conversation_payload)
        .bind(welcomes.len() as i64)
        .bind(welcome_digest.as_slice())
        .bind(welcome_payload)
        .bind(recovery.len() as i64)
        .bind(recovery_digest.as_slice())
        .bind(recovery_payload)
        .execute(&mut *tx)
        .await
        .expect("record completion evidence");
    }
    sqlx::query(
        "SET CONSTRAINTS chat.inventory_sessions_materialization_deferred, \
         chat.inventory_sessions_auth_identity_deferred IMMEDIATE",
    )
    .execute(&mut *tx)
    .await
    .expect("force the G7 session triggers");
    tx.commit().await.expect("commit the seeded session");

    SeededSession {
        session_id,
        user_did: device.did.clone(),
        device_id: device.device_id,
        jkt: device.jkt.clone(),
        auth_generation: 1,
        capability,
        capability_hash,
        sealed,
        created_at,
        expires_at,
        snapshot_event_position,
        retained_floor,
    }
}

// ===========================================================================
// Page-receipt machinery: the D-2 serve/replay statement shapes + the
// deterministic response assembly, replicated from inventory.rs so the
// receipt/replay contract can be proven against real rows.
// ===========================================================================

const MAX_RESPONSE_BYTES: usize = 16 * 1024 * 1024 + 64 * 1024;

fn conversations_request(limit: u16) -> InventoryPublicRequestBinding {
    InventoryPublicRequestBinding::new(
        INVENTORY_CONVERSATIONS_NSID,
        1,
        InventoryDomain::Conversations,
        limit,
        Sha256::digest([]).into(),
    )
    .expect("the canonical no-filter conversations binding is valid")
}

/// The full session capability text (the presented `inventorySessionId` AND
/// `snapshotEventCursor`).
fn session_capability_text(session: &SeededSession) -> String {
    session.capability.encode()
}

/// The page-receipt binding (replica of inventory.rs `page_receipt_binding`):
/// the receipt row's own columns derive every AAD field.
#[allow(clippy::too_many_arguments)]
fn page_receipt_binding(
    fence: &Fence,
    request: &InventoryPublicRequestBinding,
    session: &SeededSession,
    receipt_created_at: u64,
    receipt_expires_at: u64,
    after_ordinal: Option<u64>,
    successor_cursor_hash: Option<[u8; 32]>,
) -> SealerBinding {
    SealerBinding::for_page_receipt(
        request.domain().receipt_domain_text().as_bytes(),
        request.endpoint_nsid().as_bytes(),
        request.cursor_format_version(),
        session.session_id,
        session.user_did.as_bytes(),
        session.device_id,
        session.jkt.as_bytes(),
        session.auth_generation,
        fence.protocol_instance_id,
        fence.cursor_key_id.as_bytes(),
        u64::try_from(session.snapshot_event_position).expect("position fits u64"),
        session.capability_hash,
        u64::try_from(session.retained_floor).expect("floor fits u64"),
        request.canonical_filter_sha256(),
        request.limit(),
        after_ordinal,
        successor_cursor_hash,
        receipt_created_at,
        receipt_expires_at,
    )
    .expect("page-receipt binding fields are the seeded row's own columns")
}

fn canonical_datetime(value: DateTime<Utc>) -> String {
    value.format("%Y-%m-%dT%H:%M:%S%.3fZ").to_string()
}

fn append_json_string(out: &mut Vec<u8>, value: &str) {
    for byte in value.bytes() {
        match byte {
            b'"' => out.extend_from_slice(b"\\\""),
            b'\\' => out.extend_from_slice(b"\\\\"),
            0x08 => out.extend_from_slice(b"\\b"),
            0x09 => out.extend_from_slice(b"\\t"),
            0x0A => out.extend_from_slice(b"\\n"),
            0x0C => out.extend_from_slice(b"\\f"),
            0x0D => out.extend_from_slice(b"\\r"),
            0x00..=0x1F => {
                out.extend_from_slice(format!("\\u{byte:04x}").as_bytes());
            }
            _ => out.push(byte),
        }
    }
}

/// Deterministic response assembly (replica of inventory.rs
/// `assemble_inventory_page_response`): the generated `*Output` wrapper shape
/// with the retained canonical item bytes spliced verbatim. The stored
/// `canonical_response_sha256` is the digest of these bytes, so a replay that
/// reassembles them and compares digests proves byte-for-byte identity.
fn assemble_inventory_page_response(
    has_more: bool,
    capability_text: &str,
    items: &[Vec<u8>],
    next_page_cursor: Option<&str>,
    expires_at: DateTime<Utc>,
) -> Vec<u8> {
    let mut out = Vec::with_capacity(
        256 + items.iter().map(Vec::len).sum::<usize>() + 2 * capability_text.len(),
    );
    out.extend_from_slice(b"{\"hasMore\":");
    out.extend_from_slice(if has_more { b"true" } else { b"false" });
    out.extend_from_slice(b",\"inventorySessionId\":\"");
    append_json_string(&mut out, capability_text);
    out.extend_from_slice(b"\",\"items\":[");
    for (index, item) in items.iter().enumerate() {
        if index > 0 {
            out.push(b',');
        }
        out.extend_from_slice(item);
    }
    out.extend_from_slice(b"]");
    if let Some(cursor) = next_page_cursor {
        out.extend_from_slice(b",\"nextPageCursor\":\"");
        append_json_string(&mut out, cursor);
        out.push(b'"');
    }
    out.extend_from_slice(b",\"snapshotEventCursor\":\"");
    append_json_string(&mut out, capability_text);
    out.extend_from_slice(b"\",\"snapshotExpiresAt\":\"");
    append_json_string(&mut out, &canonical_datetime(expires_at));
    out.extend_from_slice(b"\"}");
    assert!(
        out.len() <= MAX_RESPONSE_BYTES,
        "the assembled response respects the 16 MiB + 64 KiB ceiling"
    );
    out
}

/// One minted + sealed successor page capability (only for `has_more=true`).
struct SealedSuccessorSeed {
    hash: [u8; 32],
    sealed: SealedCapability,
    text: String,
}

/// Mint and seal the next page capability under the page-receipt binding
/// (replica of inventory.rs `mint_and_seal_successor`).
fn mint_and_seal_successor_seed(
    fence: &Fence,
    random: &mut DeterministicRandom,
    request: &InventoryPublicRequestBinding,
    session: &SeededSession,
    receipt_created_at: DateTime<Utc>,
    receipt_expires_at: DateTime<Utc>,
    after_ordinal: Option<i64>,
) -> SealedSuccessorSeed {
    let token = mint_capability_token(random).expect("mint the successor capability");
    let hash = token.lookup_hash();
    let binding = page_receipt_binding(
        fence,
        request,
        session,
        u64::try_from(receipt_created_at.timestamp()).expect("created fits u64"),
        u64::try_from(receipt_expires_at.timestamp()).expect("expiry fits u64"),
        after_ordinal.map(|ordinal| u64::try_from(ordinal).expect("ordinal fits u64")),
        Some(hash),
    );
    let sealed = fence
        .sealer
        .seal_successor(token.as_bytes(), &binding, random)
        .expect("seal the successor capability");
    SealedSuccessorSeed {
        hash,
        sealed,
        text: token.encode(),
    }
}

/// Insert one unserved page receipt (replica of inventory.rs
/// `insert_page_receipt_unserved`), mint + seal the successor under the
/// receipt's OWN created/expires instants (replica of `mint_and_seal_successor`
/// + `serve_page_receipt_row`), and mark the receipt served. `domain_text` +
/// `endpoint_nsid` are the receipt row's own columns (the served shape check
/// binds them to the closed set). Returns the served whole-second instant and
/// the sealed successor (only when `has_more=true`).
#[allow(clippy::too_many_arguments)]
async fn serve_page_receipt_seed(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    fence: &Fence,
    session: &SeededSession,
    domain_text: &str,
    endpoint_nsid: &str,
    request: &InventoryPublicRequestBinding,
    request_cursor_hash: Option<[u8; 32]>,
    after_ordinal: Option<i64>,
    page_items: &[Vec<u8>],
    has_more: bool,
    random: &mut DeterministicRandom,
) -> (DateTime<Utc>, Option<SealedSuccessorSeed>) {
    let now: DateTime<Utc> =
        sqlx::query_scalar("SELECT date_trunc('second', transaction_timestamp())")
            .fetch_one(&mut **tx)
            .await
            .expect("repository-owned whole-second serve instant");
    // A receipt never precedes its session in production, and the receipt
    // binding CHECK requires `expires_at <= created_at + 15 minutes` with
    // `expires_at` = the session's expiry ceiling. Sessions are seeded one
    // whole second in the future (so every prior graph row precedes them), so
    // the serve instant is clamped up to the session's creation instant —
    // otherwise the seeded receipt's window exceeds 15 minutes by that skew.
    let served_at = now.max(session.created_at);
    let receipt_created_at = served_at;
    let receipt_expires_at = session.expires_at;
    // The served shape check requires item_count > 0 on a has_more receipt,
    // so a has_more page always carries at least one retained item.
    assert!(
        !has_more || !page_items.is_empty(),
        "a has_more page serves items"
    );
    let successor = if has_more {
        Some(mint_and_seal_successor_seed(
            fence,
            random,
            request,
            session,
            receipt_created_at,
            receipt_expires_at,
            after_ordinal,
        ))
    } else {
        None
    };
    let receipt_id = Uuid::new_v4();
    sqlx::query(
        r#"
        INSERT INTO chat.inventory_page_receipts(
            page_receipt_id, request_cursor_hash, inventory_session_id, domain,
            endpoint_nsid, cursor_format_version, page_limit,
            canonical_filter_sha256, user_did, device_id, jkt, auth_generation,
            protocol_instance_id, cursor_key_id, snapshot_event_position,
            snapshot_event_cursor_sha256, snapshot_retained_floor, after_ordinal,
            created_at, expires_at
        ) VALUES ($1,$2,$3,$4,$5,1,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19)
        "#,
    )
    .bind(receipt_id)
    .bind(request_cursor_hash.map(|hash| hash.to_vec()))
    .bind(session.session_id)
    .bind(domain_text)
    .bind(endpoint_nsid)
    .bind(i16::try_from(request.limit()).expect("limit fits i16"))
    .bind(request.canonical_filter_sha256().as_slice())
    .bind(&session.user_did)
    .bind(session.device_id)
    .bind(&session.jkt)
    .bind(session.auth_generation as i64)
    .bind(fence.protocol_instance_id)
    .bind(&fence.cursor_key_id)
    .bind(session.snapshot_event_position)
    .bind(session.capability_hash.as_slice())
    .bind(session.retained_floor)
    .bind(after_ordinal)
    .bind(receipt_created_at)
    .bind(receipt_expires_at)
    .execute(&mut **tx)
    .await
    .expect("insert the unserved page receipt");

    let first_ordinal = if page_items.is_empty() {
        None
    } else {
        Some(after_ordinal.map(|after| after + 1).unwrap_or(0))
    };
    let item_count = i64::try_from(page_items.len()).expect("item count fits i64");
    let mut items_digest = Sha256::new();
    for item in page_items {
        items_digest.update(Sha256::digest(item));
    }
    let items_sha256: [u8; 32] = items_digest.finalize().into();
    let capability_text = session_capability_text(session);
    let response_bytes = assemble_inventory_page_response(
        has_more,
        &capability_text,
        page_items,
        successor.as_ref().map(|successor| successor.text.as_str()),
        session.expires_at,
    );
    let response_sha256: [u8; 32] = Sha256::digest(&response_bytes).into();

    sqlx::query(
        r#"
        UPDATE chat.inventory_page_receipts
           SET served_at = $2, first_ordinal = $3, item_count = $4,
               items_sha256 = $5, has_more = $6,
               successor_cursor_hash = $7, successor_cursor_nonce = $8,
               successor_cursor_ciphertext = $9, canonical_response_sha256 = $10
         WHERE page_receipt_id = $1
        "#,
    )
    .bind(receipt_id)
    .bind(served_at)
    .bind(first_ordinal)
    .bind(item_count)
    .bind(items_sha256.as_slice())
    .bind(has_more)
    .bind(
        successor
            .as_ref()
            .map(|successor| successor.hash.as_slice()),
    )
    .bind(
        successor
            .as_ref()
            .map(|successor| successor.sealed.nonce.as_slice()),
    )
    .bind(
        successor
            .as_ref()
            .map(|successor| successor.sealed.ciphertext.as_slice()),
    )
    .bind(response_sha256.as_slice())
    .execute(&mut **tx)
    .await
    .expect("mark the page receipt served");
    (served_at, successor)
}

/// The closed `(domain, endpoint NSID)` pairs the receipts shape check binds.
const DOMAIN_ENDPOINTS: [(&str, &str); 3] = [
    (
        "conversations",
        repository::inventory::INVENTORY_CONVERSATIONS_NSID,
    ),
    ("welcomes", repository::inventory::INVENTORY_WELCOMES_NSID),
    ("recovery", repository::inventory::INVENTORY_RECOVERY_NSID),
];

/// The reassembled canonical response for one served receipt, proven to match
/// the stored `canonical_response_sha256` byte-for-byte.
struct ReassembledResponse {
    bytes: Vec<u8>,
    sha256: [u8; 32],
    successor_text: Option<String>,
}

/// Reassemble the canonical response for a served receipt (replica of
/// inventory.rs `replay_served_receipt`'s pure half): decrypt the session
/// capability from ITS seal, decrypt the identical successor from ITS seal,
/// and splice the retained bytes; the digest must match the stored
/// `canonical_response_sha256` before any bytes are returned.
#[allow(clippy::too_many_arguments)]
async fn reassemble_served_receipt(
    pool: &PgPool,
    fence: &Fence,
    session: &SeededSession,
    request: &InventoryPublicRequestBinding,
    receipt_created_at: DateTime<Utc>,
    receipt_expires_at: DateTime<Utc>,
    after_ordinal: Option<i64>,
    item_count: i64,
    has_more: bool,
    successor: Option<&SealedSuccessorSeed>,
) -> ReassembledResponse {
    let items: Vec<Vec<u8>> = {
        let domain = request.domain().page_domain();
        let sql = match domain {
            chat_protocol::cursor::InventoryPageDomain::Conversations => {
                "SELECT payload_bytes FROM chat.inventory_conversation_items \
                 WHERE inventory_session_id = $1 AND ordinal > $2 ORDER BY ordinal LIMIT $3"
            }
            chat_protocol::cursor::InventoryPageDomain::PendingWelcomes => {
                "SELECT payload_bytes FROM chat.inventory_welcome_items \
                 WHERE inventory_session_id = $1 AND ordinal > $2 ORDER BY ordinal LIMIT $3"
            }
            chat_protocol::cursor::InventoryPageDomain::LeafRecovery => {
                "SELECT payload_bytes FROM chat.inventory_recovery_items \
                 WHERE inventory_session_id = $1 AND ordinal > $2 ORDER BY ordinal LIMIT $3"
            }
        };
        let after = after_ordinal.unwrap_or(-1);
        let rows: Vec<Vec<u8>> = sqlx::query_scalar(sql)
            .bind(session.session_id)
            .bind(after)
            .bind(item_count)
            .fetch_all(pool)
            .await
            .expect("read the retained page bytes");
        rows
    };

    let successor_text = match successor {
        Some(successor) => {
            let binding = page_receipt_binding(
                fence,
                request,
                session,
                u64::try_from(receipt_created_at.timestamp()).expect("created fits u64"),
                u64::try_from(receipt_expires_at.timestamp()).expect("expiry fits u64"),
                after_ordinal.map(|ordinal| u64::try_from(ordinal).expect("ordinal fits u64")),
                Some(successor.hash),
            );
            let plaintext = fence
                .sealer
                .verify_successor(&successor.sealed, &binding)
                .expect("the identical decrypted successor is recovered from ITS seal");
            assert_eq!(
                <[u8; 32]>::from(Sha256::digest(plaintext.as_slice())),
                successor.hash,
                "the decrypted successor hashes to the receipt's successor hash"
            );
            Some(URL_SAFE_NO_PAD.encode(plaintext.as_slice()))
        }
        None => None,
    };

    let capability_plaintext = {
        let binding = event_cursor_binding(
            fence,
            session.session_id,
            &session.user_did,
            session.device_id,
            &session.jkt,
            session.auth_generation,
            u64::try_from(session.snapshot_event_position).expect("position fits u64"),
            u64::try_from(session.retained_floor).expect("floor fits u64"),
            u64::try_from(session.created_at.timestamp()).expect("created fits u64"),
            u64::try_from(session.expires_at.timestamp()).expect("expiry fits u64"),
        );
        fence
            .sealer
            .verify_successor(&session.sealed, &binding)
            .expect("the session capability decrypts under the row-derived binding")
    };
    let capability_text = URL_SAFE_NO_PAD.encode(capability_plaintext.as_slice());
    assert_eq!(
        <[u8; 32]>::from(Sha256::digest(capability_plaintext.as_slice())),
        session.capability_hash,
        "the decrypted session capability hashes to the durable token_hash"
    );

    let bytes = assemble_inventory_page_response(
        has_more,
        &capability_text,
        &items,
        successor_text.as_deref(),
        session.expires_at,
    );
    let sha256: [u8; 32] = Sha256::digest(&bytes).into();
    ReassembledResponse {
        bytes,
        sha256,
        successor_text,
    }
}

/// The stored `canonical_response_sha256` of the served receipt for a session.
async fn stored_response_sha256(pool: &PgPool, session_id: Uuid) -> [u8; 32] {
    let stored: Vec<u8> = sqlx::query_scalar(
        "SELECT canonical_response_sha256 FROM chat.inventory_page_receipts \
         WHERE inventory_session_id = $1 ORDER BY created_at",
    )
    .bind(session_id)
    .fetch_one(pool)
    .await
    .expect("the served receipt row is retained");
    stored.try_into().expect("32-byte stored digest")
}

/// The final-page `*_consumed` compare-and-set (replica of inventory.rs
/// `consume_final_page`), returning rows affected.
async fn consume_final_page_cas(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    session_id: Uuid,
    domain: &str,
    consumed_at: DateTime<Utc>,
) -> u64 {
    let (consumed_column, consumed_at_column) = match domain {
        "conversations" => ("conversations_consumed", "conversations_consumed_at"),
        "welcomes" => ("welcomes_consumed", "welcomes_consumed_at"),
        "recovery" => ("recovery_consumed", "recovery_consumed_at"),
        _ => panic!("closed domain set"),
    };
    let sql = format!(
        "UPDATE chat.inventory_sessions SET {consumed_column} = TRUE, \
         {consumed_at_column} = $2 WHERE inventory_session_id = $1 \
         AND {consumed_column} = FALSE"
    );
    sqlx::query(&sql)
        .bind(session_id)
        .bind(consumed_at)
        .execute(&mut **tx)
        .await
        .expect("the consumption CAS executes")
        .rows_affected()
}

/// Deterministic `SecureRandom` for reproducible seeds (xorshift64*, bijective,
/// so consecutive nonce windows are distinct).
struct DeterministicRandom {
    state: u64,
}

impl DeterministicRandom {
    fn new(seed: u64) -> Self {
        Self { state: seed }
    }
}

/// Per-run-unique random seed for tests that COMMIT durable rows to the SHARED
/// fixed-target database. Every globally-unique durable identity minted from
/// the random stream (the session capability's `token_hash`, page-receipt
/// `request_cursor_hash`/`successor_cursor_hash`) must differ across runs: the
/// custody pattern tolerates committed test-owned residue, and the
/// identity-immutable triggers forbid reclaiming it, so a fixed seed collides
/// with the test's own prior committed rows on the second window. The tag
/// keeps streams distinct within one run; the entropy makes them distinct
/// across runs. Fresh-per-test-database tests may keep fully fixed seeds
/// (their residue is dropped with the database), and the expiry/GC tests'
/// deterministic SESSION IDENTITY contract is untouched (that determinism is
/// the row handle, not the random stream).
fn per_run_seed(tag: u64) -> u64 {
    let entropy = u64::from_be_bytes(
        Uuid::new_v4().as_bytes()[..8]
            .try_into()
            .expect("uuid entropy"),
    );
    entropy ^ tag
}

impl SecureRandom for DeterministicRandom {
    fn fill(&mut self, out: &mut [u8]) -> Result<(), SecureRandomError> {
        for chunk in out.chunks_mut(8) {
            self.state ^= self.state >> 12;
            self.state ^= self.state << 25;
            self.state ^= self.state >> 27;
            self.state = self.state.wrapping_mul(0x2545_F491_4F6C_DD1D);
            let bytes = self.state.to_be_bytes();
            chunk.copy_from_slice(&bytes[..chunk.len()]);
        }
        Ok(())
    }
}

fn empty_sha256() -> Vec<u8> {
    Sha256::digest([]).to_vec()
}

// ===========================================================================
// Inventory-session capability/receipt tests (the D-2 contract).
// ===========================================================================

/// The D-2 create shape proves all three materialization `*_complete` fields
/// (with the exact transcript evidence the G7 materialization trigger
/// recomputes) and initializes all three `*_consumed` fields false; only the
/// SHA-256 lookup hash and the sealed nonce/ciphertext pair live at rest.
#[tokio::test]
async fn session_creation_shape_proves_all_three_complete_and_false_consumed() {
    let pool = common::chat_protocol::setup_chat_protocol_db(3).await;
    let fence = ensure_fence(&pool).await;
    let now = whole_second(clock_now(&pool).await);
    let device = seed_device_with_key(&pool, now - Duration::seconds(120)).await;
    let session_id = Uuid::new_v4();
    let mut random = DeterministicRandom::new(per_run_seed(0xD3D3));

    let session = seed_session_via_create_shape(
        &pool,
        &fence,
        &device,
        session_id,
        now,
        now + Duration::minutes(15),
        &mut random,
        &[],
        &[],
        &[],
    )
    .await;

    // Only the SHA-256 lookup hash + the seal live at rest; the capability
    // plaintext is recoverable ONLY through the row-derived binding.
    assert_eq!(session.capability.as_bytes().len(), 32);
    assert_eq!(session.capability.encode().len(), 43);
    let binding = event_cursor_binding(
        &fence,
        session_id,
        &session.user_did,
        session.device_id,
        &session.jkt,
        session.auth_generation,
        u64::try_from(session.snapshot_event_position).unwrap(),
        u64::try_from(session.retained_floor).unwrap(),
        u64::try_from(session.created_at.timestamp()).unwrap(),
        u64::try_from(session.expires_at.timestamp()).unwrap(),
    );
    let decrypted = fence
        .sealer
        .verify_successor(&session.sealed, &binding)
        .expect("the sealed session capability decrypts under the row-derived binding");
    assert_eq!(
        decrypted.as_slice(),
        session.capability.as_bytes(),
        "the identical capability plaintext is recovered from the seal"
    );

    let (token_hash, cursor_sha256, nonce_len, ciphertext_len): (Vec<u8>, Vec<u8>, i32, i32) =
        sqlx::query_as(
            "SELECT token_hash, snapshot_event_cursor_sha256, \
                octet_length(snapshot_event_cursor_nonce), \
                octet_length(snapshot_event_cursor_ciphertext) \
           FROM chat.inventory_sessions WHERE inventory_session_id = $1",
        )
        .bind(session_id)
        .fetch_one(&pool)
        .await
        .expect("the session row is retained");

    assert_eq!(
        token_hash,
        session.capability_hash.to_vec(),
        "the durable token_hash is the SHA-256 of the capability plaintext"
    );
    assert_eq!(
        cursor_sha256, token_hash,
        "snapshot_event_cursor_sha256 holds the same lookup hash (the schema's \
         token-lookup-hash note)"
    );
    assert_eq!(nonce_len, 12, "the seal carries a 12-byte nonce");
    assert!(
        (1..=512).contains(&ciphertext_len),
        "the seal carries a bounded ciphertext"
    );

    // The six proofs: all three *_complete true with count-0/empty-digest
    // evidence, all three *_consumed false with NULL consumed instants.
    let (
        conversations_complete,
        welcomes_complete,
        recovery_complete,
        conversations_consumed,
        welcomes_consumed,
        recovery_consumed,
        conversation_count,
        conversation_items_sha256,
        conversation_payload_bytes,
    ): (
        bool,
        bool,
        bool,
        bool,
        bool,
        bool,
        Option<i64>,
        Option<Vec<u8>>,
        Option<i64>,
    ) = sqlx::query_as(
        "SELECT conversations_complete, welcomes_complete, recovery_complete, \
                conversations_consumed, welcomes_consumed, recovery_consumed, \
                conversation_item_count, conversation_items_sha256, \
                conversation_payload_bytes \
           FROM chat.inventory_sessions WHERE inventory_session_id = $1",
    )
    .bind(session_id)
    .fetch_one(&pool)
    .await
    .expect("the six proofs are retained");
    assert!(conversations_complete && welcomes_complete && recovery_complete);
    assert!(!conversations_consumed && !welcomes_consumed && !recovery_consumed);
    assert_eq!(conversation_count, Some(0));
    assert_eq!(conversation_items_sha256, Some(empty_sha256()));
    assert_eq!(conversation_payload_bytes, Some(0));

    // The G7 materialization trigger accepts the seeded materialization: the
    // evidence matches what the schema recomputes.
    sqlx::query("SELECT chat.assert_inventory_materialization($1)")
        .bind(session_id)
        .execute(&pool)
        .await
        .expect("the G7 materialization transcript validates the seeded session");

    // The 15-minute expiry check holds exactly at the bound.
    let (created_at, expires_at): (DateTime<Utc>, DateTime<Utc>) = sqlx::query_as(
        "SELECT created_at, expires_at FROM chat.inventory_sessions WHERE inventory_session_id = $1",
    )
    .bind(session_id)
    .fetch_one(&pool)
    .await
    .expect("lifetime columns");
    assert_eq!(
        expires_at - created_at,
        Duration::minutes(15),
        "the exact 15-minute inventory session lifetime"
    );
}

/// The G7 subscription-ticket binding accepts a ticket against a FULLY
/// CONSUMED session (all three `*_consumed` true with the exact final
/// receipts) and rejects drift: an unconsumed session fails closed at the
/// deferred trigger.
#[tokio::test]
async fn g7_ticket_binding_accepts_a_fully_consumed_session_and_rejects_drift() {
    let pool = common::chat_protocol::setup_chat_protocol_db(3).await;
    let fence = ensure_fence(&pool).await;
    let now = whole_second(clock_now(&pool).await);
    let device = seed_device_with_key(&pool, now - Duration::seconds(120)).await;
    let session_id = Uuid::new_v4();
    let mut random = DeterministicRandom::new(per_run_seed(0xD3D4));

    let session = seed_session_via_create_shape(
        &pool,
        &fence,
        &device,
        session_id,
        now,
        now + Duration::minutes(15),
        &mut random,
        &[],
        &[],
        &[],
    )
    .await;
    let request = conversations_request(100);

    // Consume all three domains: each requires a served FINAL receipt for the
    // exact domain whose served_at equals the consumed instant.
    let mut tx = pool.begin().await.expect("begin consume loop");
    for (domain, endpoint_nsid) in DOMAIN_ENDPOINTS {
        let (served_at, successor) = serve_page_receipt_seed(
            &mut tx,
            &fence,
            &session,
            domain,
            endpoint_nsid,
            &request,
            None,
            None,
            &[],
            false,
            &mut random,
        )
        .await;
        assert!(successor.is_none(), "a final page carries no successor");
        let affected = consume_final_page_cas(&mut tx, session_id, domain, served_at).await;
        assert_eq!(affected, 1, "each domain consumes exactly once");
    }
    // A second CAS on the same domain is a no-op (0 rows) — the one-way
    // consumption never repeats.
    let affected = consume_final_page_cas(&mut tx, session_id, "conversations", now).await;
    assert_eq!(affected, 0, "the consumed CAS is a no-op on replay");
    tx.commit().await.expect("commit the consumed session");

    // The G7 ticket binding (live-session arm): protocol/key/floor columns
    // populated, all three consumed, exact identity + position + lifetime.
    let opaque = fresh_blob();
    let ticket_hash_bytes = ticket_hash(&opaque).to_vec();
    let mut tx = pool.begin().await.expect("begin ticket");
    sqlx::query(
        r#"
        INSERT INTO chat.subscription_tickets(
            ticket_hash, user_did, device_id, jkt, auth_generation,
            inventory_session_id, event_position, event_cursor_sha256,
            subscription_path, created_at, expires_at, consumed_at,
            protocol_instance_id, cursor_key_id, snapshot_retained_floor
        ) VALUES ($1,$2,$3,$4,1,$5,$6,$7,$8,$9,$10,NULL,$11,$12,$13)
        "#,
    )
    .bind(ticket_hash_bytes.as_slice())
    .bind(&device.did)
    .bind(device.device_id)
    .bind(&device.jkt)
    .bind(session_id)
    .bind(session.snapshot_event_position)
    .bind(session.capability_hash.as_slice())
    .bind(SUBSCRIBE_EVENTS_PATH)
    .bind(now)
    .bind(now + Duration::seconds(60))
    .bind(fence.protocol_instance_id)
    .bind(&fence.cursor_key_id)
    .bind(session.retained_floor)
    .execute(&mut *tx)
    .await
    .expect("insert the G7-shaped ticket");
    tx.commit()
        .await
        .expect("the deferred ticket-binding trigger accepts the fully consumed session");

    // Drift negative: a ticket against an UNCONSUMED session is rejected at
    // the deferred binding trigger (commit-time fail closed).
    let unconsumed_id = Uuid::new_v4();
    let _unconsumed = seed_session_via_create_shape(
        &pool,
        &fence,
        &device,
        unconsumed_id,
        now,
        now + Duration::minutes(15),
        &mut random,
        &[],
        &[],
        &[],
    )
    .await;
    let drift_ticket = ticket_hash(&fresh_blob()).to_vec();
    let mut tx = pool.begin().await.expect("begin drift ticket");
    sqlx::query(
        r#"
        INSERT INTO chat.subscription_tickets(
            ticket_hash, user_did, device_id, jkt, auth_generation,
            inventory_session_id, event_position, event_cursor_sha256,
            subscription_path, created_at, expires_at, consumed_at,
            protocol_instance_id, cursor_key_id, snapshot_retained_floor
        ) VALUES ($1,$2,$3,$4,1,$5,$6,$7,$8,$9,$10,NULL,$11,$12,$13)
        "#,
    )
    .bind(drift_ticket.as_slice())
    .bind(&device.did)
    .bind(device.device_id)
    .bind(&device.jkt)
    .bind(unconsumed_id)
    .bind(session.snapshot_event_position)
    .bind(session.capability_hash.as_slice())
    .bind(SUBSCRIBE_EVENTS_PATH)
    .bind(now)
    .bind(now + Duration::seconds(60))
    .bind(fence.protocol_instance_id)
    .bind(&fence.cursor_key_id)
    .bind(session.retained_floor)
    .execute(&mut *tx)
    .await
    .expect("insert the drift ticket");
    let commit = tx.commit().await;
    assert!(
        commit.is_err(),
        "the deferred ticket-binding trigger must reject a ticket bound to an \
         unconsumed session"
    );
}

/// A retained session row is immutable OUTSIDE the GC: the identity-immutable
/// trigger forbids DELETE and any rewrite of the completion/consumption
/// evidence columns; the consumption trigger rejects a consumed transition
/// without the exact served final receipt.
#[tokio::test]
async fn retained_session_rows_are_immutable_outside_the_gc() {
    let pool = common::chat_protocol::setup_chat_protocol_db(3).await;
    let fence = ensure_fence(&pool).await;
    let now = whole_second(clock_now(&pool).await);
    let device = seed_device_with_key(&pool, now - Duration::seconds(120)).await;
    let session_id = Uuid::new_v4();
    let mut random = DeterministicRandom::new(per_run_seed(0xD3D5));

    let _session = seed_session_via_create_shape(
        &pool,
        &fence,
        &device,
        session_id,
        now,
        now + Duration::minutes(15),
        &mut random,
        &[],
        &[],
        &[],
    )
    .await;

    let deleted =
        sqlx::query("DELETE FROM chat.inventory_sessions WHERE inventory_session_id = $1")
            .bind(session_id)
            .execute(&pool)
            .await;
    assert!(
        deleted.is_err(),
        "the identity-immutable trigger forbids a plain DELETE of the retained session"
    );

    let cleared = sqlx::query(
        "UPDATE chat.inventory_sessions SET conversations_complete = FALSE \
         WHERE inventory_session_id = $1",
    )
    .bind(session_id)
    .execute(&pool)
    .await;
    assert!(
        cleared.is_err(),
        "a completion cannot be cleared (lifecycle + identity triggers)"
    );

    let drifted = sqlx::query(
        "UPDATE chat.inventory_sessions SET conversations_consumed = TRUE, \
         conversations_consumed_at = $2 WHERE inventory_session_id = $1 \
         AND conversations_consumed = FALSE",
    )
    .bind(session_id)
    .bind(now)
    .execute(&pool)
    .await;
    assert!(
        drifted.is_err(),
        "the consumption trigger rejects a consumed transition without the exact \
         served final receipt"
    );

    // The row still exists, complete and unconsumed.
    let (complete, consumed): (bool, bool) = sqlx::query_as(
        "SELECT conversations_complete, conversations_consumed \
         FROM chat.inventory_sessions WHERE inventory_session_id = $1",
    )
    .bind(session_id)
    .fetch_one(&pool)
    .await
    .expect("the row survives");
    assert!(complete);
    assert!(!consumed);
}

/// Read a seeded device's inventory-session identity fields (jkt + auth
/// generation) straight from `chat.devices`, so a test binds the exact durable
/// authority the create path re-validates.
async fn device_session_identity(pool: &PgPool, did: &str, device_id: Uuid) -> (String, u64) {
    let (jkt, auth_generation): (String, i64) = sqlx::query_as(
        "SELECT dpop_jkt, auth_generation FROM chat.devices WHERE user_did = $1 AND device_id = $2",
    )
    .bind(did)
    .bind(device_id)
    .fetch_one(pool)
    .await
    .expect("seeded device identity");
    (
        jkt,
        u64::try_from(auth_generation).expect("auth generation fits u64"),
    )
}

/// The populated conversation-domain materialization: a state-arm item whose
/// provenance matches the exact participant + open interval is accepted by the
/// source-precedence trigger, the transcript evidence matches what
/// `assert_inventory_materialization` recomputes, and the retained item bytes
/// are immutable even after the source later transitions.
#[tokio::test]
async fn conversation_materialization_matches_the_g7_transcript_and_is_immutable() {
    let (pool, _guard) = executor_seed::setup().await;
    let scenario = executor_seed::run_fulfillment_scenario(&pool).await;
    let fence = ensure_fence(&pool).await;
    let now = whole_second(clock_now(&pool).await) + Duration::seconds(1);

    let alice_did = scenario.fixture.alice_did.clone();
    let alice_device = scenario.fixture.alice_device;
    let alice_jkt = scenario.fixture.alice_key_id.clone();
    let conversation_id = scenario.conversation_id;
    let participant_period_id: Uuid = sqlx::query_scalar(
        "SELECT participant_period_id FROM chat.participants \
         WHERE conversation_id = $1 AND user_did = $2 AND current_membership",
    )
    .bind(conversation_id)
    .bind(&alice_did)
    .fetch_one(&pool)
    .await
    .expect("alice's current participant period");

    let device = SessionDevice {
        did: alice_did,
        device_id: alice_device,
        jkt: alice_jkt,
    };
    let session_id = Uuid::new_v4();
    let mut random = DeterministicRandom::new(0xD3D6);
    let mut payload = b"canonical-conversation-item".to_vec();
    payload.extend_from_slice(&[0xAB; 64]);
    let item = ConversationItemSeed {
        conversation_id,
        participant_period_id,
        recipient_did: device.did.clone(),
        recipient_device_id: device.device_id,
        payload,
    };
    let _session = seed_session_via_create_shape(
        &pool,
        &fence,
        &device,
        session_id,
        now,
        now + Duration::minutes(15),
        &mut random,
        std::slice::from_ref(&item),
        &[],
        &[],
    )
    .await;

    // The materialization trigger validates the seeded evidence (item_kind,
    // arm provenance, and payload bytes all participate in the transcript).
    sqlx::query("SELECT chat.assert_inventory_materialization($1)")
        .bind(session_id)
        .execute(&pool)
        .await
        .expect("the conversation transcript validates");

    // The retained item bytes are immutable: an UPDATE to the payload is
    // rejected by the item immutability trigger, and a DELETE too.
    let payload_update = sqlx::query(
        "UPDATE chat.inventory_conversation_items SET payload_bytes = $2 \
         WHERE inventory_session_id = $1 AND ordinal = 0",
    )
    .bind(session_id)
    .bind(vec![0xCD; 16])
    .execute(&pool)
    .await;
    assert!(
        payload_update.is_err(),
        "retained item bytes never change after creation"
    );
    let item_delete = sqlx::query(
        "DELETE FROM chat.inventory_conversation_items \
         WHERE inventory_session_id = $1 AND ordinal = 0",
    )
    .bind(session_id)
    .execute(&pool)
    .await;
    assert!(
        item_delete.is_err(),
        "retained item rows are not deletable outside the GC"
    );

    // A drifted provenance (foreign participant period) is rejected by the
    // source-precedence trigger before the row lands.
    let drifted = sqlx::query(
        "INSERT INTO chat.inventory_conversation_items(\
            inventory_session_id, ordinal, conversation_id, recipient_did,\
            recipient_device_id, item_kind, participant_period_id,\
            item_key_bytes, payload_bytes, payload_sha256\
        ) VALUES ($1,$2,$3,$4,$5,'blue.catbird.chat.defs#conversationInventoryState',$6,\
                  uuid_send($3),$7,$8)",
    )
    .bind(session_id)
    .bind(99_i64)
    .bind(conversation_id)
    .bind(&device.did)
    .bind(device.device_id)
    .bind(Uuid::new_v4())
    .bind(vec![0xEE; 16])
    .bind(Sha256::digest(vec![0xEE; 16]).to_vec())
    .execute(&pool)
    .await;
    assert!(
        drifted.is_err(),
        "a foreign participant provenance fails closed at the source-precedence trigger"
    );
}

/// The Welcome-domain materialization: the item payload is the server-derived
/// `welcome_bundles.wrapper_bytes` for the exact pending delivery, the
/// transcript validates, and the item is immutable.
#[tokio::test]
async fn welcome_materialization_derives_the_server_payload_and_is_immutable() {
    let (pool, _guard) = executor_seed::setup().await;
    let scenario = executor_seed::run_fulfillment_scenario(&pool).await;
    let fence = ensure_fence(&pool).await;

    let bob_did = scenario.bob_did.clone();
    let bob_device = Uuid::from_bytes(*scenario.bob_id.device_id());
    let (bob_jkt, _bob_auth_gen) = device_session_identity(&pool, &bob_did, bob_device).await;
    let welcome_id = scenario.welcome_id;
    let now = whole_second(clock_now(&pool).await) + Duration::seconds(1);

    let wrapper_bytes: Vec<u8> =
        sqlx::query_scalar("SELECT wrapper_bytes FROM chat.welcome_bundles WHERE welcome_id = $1")
            .bind(welcome_id)
            .fetch_one(&pool)
            .await
            .expect("welcome bundle wrapper bytes");

    let device = SessionDevice {
        did: bob_did,
        device_id: bob_device,
        jkt: bob_jkt,
    };
    let session_id = Uuid::new_v4();
    let mut random = DeterministicRandom::new(0xD3D7);
    let item = WelcomeItemSeed {
        welcome_id,
        recipient_did: device.did.clone(),
        recipient_device_id: device.device_id,
        payload: wrapper_bytes.clone(),
    };
    let _session = seed_session_via_create_shape(
        &pool,
        &fence,
        &device,
        session_id,
        now,
        now + Duration::minutes(15),
        &mut random,
        &[],
        std::slice::from_ref(&item),
        &[],
    )
    .await;

    sqlx::query("SELECT chat.assert_inventory_materialization($1)")
        .bind(session_id)
        .execute(&pool)
        .await
        .expect("the Welcome transcript validates");

    let materialized: Vec<u8> = sqlx::query_scalar(
        "SELECT payload_bytes FROM chat.inventory_welcome_items \
         WHERE inventory_session_id = $1 AND welcome_id = $2",
    )
    .bind(session_id)
    .bind(welcome_id)
    .fetch_one(&pool)
    .await
    .expect("materialized welcome payload");
    assert_eq!(
        materialized, wrapper_bytes,
        "the retained Welcome payload is the server-derived wrapper bytes"
    );

    // The retained Welcome item is immutable.
    let payload_update = sqlx::query(
        "UPDATE chat.inventory_welcome_items SET payload_bytes = $2 \
         WHERE inventory_session_id = $1 AND welcome_id = $3",
    )
    .bind(session_id)
    .bind(vec![0xCD; 16])
    .bind(welcome_id)
    .execute(&pool)
    .await;
    assert!(
        payload_update.is_err(),
        "retained Welcome bytes never change after creation"
    );
}

/// The recovery-domain materialization: a leafRecoveryRequest item derives its
/// payload from the persisted `signed_request_bytes` and the 0x00-prefixed
/// identity key; the transcript validates.
#[tokio::test]
async fn recovery_materialization_derives_the_signed_request_bytes() {
    let (pool, _guard) = executor_seed::setup().await;
    let built = executor_seed::build_fulfillment(&pool).await;
    let fence = ensure_fence(&pool).await;

    let bob_did = built.bob_did.clone();
    let bob_device = Uuid::from_bytes(*built.bob_id.device_id());
    let (bob_jkt, _bob_auth_gen) = device_session_identity(&pool, &bob_did, bob_device).await;
    let request_id = built.recovery_request_id;
    let now = whole_second(clock_now(&pool).await) + Duration::seconds(1);

    let status: String = sqlx::query_scalar(
        "SELECT status FROM chat.leaf_recovery_requests WHERE recovery_request_id = $1",
    )
    .bind(request_id)
    .fetch_one(&pool)
    .await
    .expect("request status");
    assert_eq!(status, "open");
    let signed_request_bytes: Vec<u8> = sqlx::query_scalar(
        "SELECT signed_request_bytes FROM chat.leaf_recovery_requests WHERE recovery_request_id = $1",
    )
    .bind(request_id)
    .fetch_one(&pool)
    .await
    .expect("signed request bytes");

    let device = SessionDevice {
        did: bob_did,
        device_id: bob_device,
        jkt: bob_jkt,
    };
    let session_id = Uuid::new_v4();
    let mut random = DeterministicRandom::new(0xD3D8);
    let item = RecoveryItemSeed {
        recovery_request_id: request_id,
        recipient_did: device.did.clone(),
        recipient_device_id: device.device_id,
        payload: signed_request_bytes.clone(),
    };
    let _session = seed_session_via_create_shape(
        &pool,
        &fence,
        &device,
        session_id,
        now,
        now + Duration::minutes(15),
        &mut random,
        &[],
        &[],
        std::slice::from_ref(&item),
    )
    .await;

    sqlx::query("SELECT chat.assert_inventory_materialization($1)")
        .bind(session_id)
        .execute(&pool)
        .await
        .expect("the recovery transcript validates");

    let materialized: Vec<u8> = sqlx::query_scalar(
        "SELECT payload_bytes FROM chat.inventory_recovery_items \
         WHERE inventory_session_id = $1 AND leaf_recovery_request_id = $2",
    )
    .bind(session_id)
    .bind(request_id)
    .fetch_one(&pool)
    .await
    .expect("materialized recovery request payload");
    assert_eq!(
        materialized, signed_request_bytes,
        "the retained request payload is the server-derived signed_request_bytes"
    );
}

/// Recovery item identity checks: the 0x00/0x01-prefixed key CHECK and the
/// source FK reject foreign rows; a failed seed leaves zero item residue.
///
/// The probes run against an OPEN recovery domain (`recovery_complete =
/// FALSE`): item inserts into a completed domain are rejected by the
/// `assert_inventory_item_session_open` trigger BEFORE the identity CHECK or
/// the deferred source FK is ever evaluated, so a completed session cannot
/// exercise either.
#[tokio::test]
async fn recovery_item_identity_checks_reject_foreign_and_duplicate_rows() {
    let (pool, _guard) = executor_seed::setup().await;
    let fence = ensure_fence(&pool).await;
    let now = whole_second(clock_now(&pool).await) + Duration::seconds(1);
    let device = seed_device_with_key(&pool, clock_now(&pool).await).await;
    let session_id = Uuid::new_v4();
    let mut random = DeterministicRandom::new(0xD3D9);

    let _session = seed_open_session_via_create_shape(
        &pool,
        &fence,
        &device,
        session_id,
        now,
        now + Duration::minutes(15),
        &mut random,
    )
    .await;
    let recovery_complete: bool = sqlx::query_scalar(
        "SELECT recovery_complete FROM chat.inventory_sessions WHERE inventory_session_id = $1",
    )
    .bind(session_id)
    .fetch_one(&pool)
    .await
    .expect("read the probe session's recovery completeness");
    assert!(
        !recovery_complete,
        "the probe session's recovery domain must still be materializing"
    );

    // A recoveryWork item with a nonexistent work row passes the immediate
    // identity CHECK, then fails the deferred source FK at commit (zero
    // residue: the whole seed rolls back).
    let work_id = Uuid::new_v4();
    let mut tx = pool.begin().await.expect("begin foreign work");
    let payload = vec![0x01u8; 16];
    let mut item_key = vec![0x01u8];
    item_key.extend_from_slice(work_id.as_bytes());
    sqlx::query(
        r#"
        INSERT INTO chat.inventory_recovery_items(
            inventory_session_id, ordinal, item_kind, leaf_recovery_request_id,
            recovery_work_id, recipient_did, recipient_device_id,
            item_key_bytes, payload_bytes, payload_sha256
        ) VALUES ($1,0,'recoveryWork',NULL,$2,$3,$4,$5,$6,$7)
        "#,
    )
    .bind(session_id)
    .bind(work_id)
    .bind(&device.did)
    .bind(device.device_id)
    .bind(&item_key)
    .bind(&payload)
    .bind(Sha256::digest(&payload).to_vec())
    .execute(&mut *tx)
    .await
    .expect("the identity CHECK accepts the 0x01-prefixed work key");
    let commit_error = tx
        .commit()
        .await
        .expect_err("a recoveryWork item without its source work row fails closed at commit");
    assert!(
        format!("{commit_error}").contains("inventory_recovery_items_work"),
        "the commit failure is the deferred work-source FK, got: {commit_error}"
    );
    let residual: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM chat.inventory_recovery_items WHERE inventory_session_id = $1",
    )
    .bind(session_id)
    .fetch_one(&pool)
    .await
    .expect("count recovery items");
    assert_eq!(
        residual, 0,
        "the failed seed left zero recovery-item residue"
    );

    // A 0x00-prefixed key with a recoveryWork id is rejected by the identity
    // CHECK (the arms' keys are not interchangeable).
    let request_id = Uuid::new_v4();
    let mut tx = pool.begin().await.expect("begin crossed arm");
    let mut item_key = vec![0x00u8];
    item_key.extend_from_slice(request_id.as_bytes());
    let insert = sqlx::query(
        r#"
        INSERT INTO chat.inventory_recovery_items(
            inventory_session_id, ordinal, item_kind, leaf_recovery_request_id,
            recovery_work_id, recipient_did, recipient_device_id,
            item_key_bytes, payload_bytes, payload_sha256
        ) VALUES ($1,0,'recoveryWork',NULL,$2,$3,$4,$5,$6,$7)
        "#,
    )
    .bind(session_id)
    .bind(request_id)
    .bind(&device.did)
    .bind(device.device_id)
    .bind(&item_key)
    .bind(&payload)
    .bind(Sha256::digest(&payload).to_vec())
    .execute(&mut *tx)
    .await;
    assert!(
        insert.is_err(),
        "a recoveryWork item must carry the 0x01-prefixed work key"
    );
    tx.rollback().await.expect("rollback crossed arm");
}

/// Sibling-device isolation: an item row must bind to the exact owning
/// recipient device of its session; a session owned by device A cannot hold an
/// item for a same-DID sibling device B (the recipient composite FKs fail
/// closed).
#[tokio::test]
async fn sibling_device_sessions_cannot_share_item_rows() {
    let (pool, _guard) = executor_seed::setup().await;
    let scenario = executor_seed::run_fulfillment_scenario(&pool).await;
    let fence = ensure_fence(&pool).await;

    let alice_did = scenario.fixture.alice_did.clone();
    let alice_device = scenario.fixture.alice_device;
    let conversation_id = scenario.conversation_id;
    let participant_period_id: Uuid = sqlx::query_scalar(
        "SELECT participant_period_id FROM chat.participants \
         WHERE conversation_id = $1 AND user_did = $2 AND current_membership",
    )
    .bind(conversation_id)
    .bind(&alice_did)
    .fetch_one(&pool)
    .await
    .expect("alice's current participant period");

    // Alice's primary device owns the session rows; a same-DID SIBLING device
    // owns none of them, so its snapshot must be empty and it cannot absorb
    // alice's conversation item.
    let sibling_device = Uuid::new_v4();
    let sibling_key = fresh_blob();
    let sibling_jkt =
        executor_seed::seed_actor(&pool, &alice_did, sibling_device, &sibling_key).await;
    let now = whole_second(clock_now(&pool).await) + Duration::seconds(1);

    let sibling = SessionDevice {
        did: alice_did.clone(),
        device_id: sibling_device,
        jkt: sibling_jkt,
    };
    let session_id = Uuid::new_v4();
    let mut random = DeterministicRandom::new(0xD3DA);
    let _session = seed_session_via_create_shape(
        &pool,
        &fence,
        &sibling,
        session_id,
        now,
        now + Duration::minutes(15),
        &mut random,
        &[],
        &[],
        &[],
    )
    .await;
    sqlx::query("SELECT chat.assert_inventory_materialization($1)")
        .bind(session_id)
        .execute(&pool)
        .await
        .expect("the sibling's empty snapshot validates");

    // The sibling cannot hold alice's conversation item: the recipient
    // composite FK binds every item to the session's owning device.
    let mut tx = pool.begin().await.expect("begin cross-device item");
    let payload = vec![0xAB; 16];
    let insert = sqlx::query(
        "INSERT INTO chat.inventory_conversation_items(\
            inventory_session_id, ordinal, conversation_id, recipient_did,\
            recipient_device_id, item_kind, participant_period_id,\
            item_key_bytes, payload_bytes, payload_sha256\
        ) VALUES ($1,0,$2,$3,$4,'blue.catbird.chat.defs#conversationInventoryState',$5,\
                  uuid_send($2),$6,$7)",
    )
    .bind(session_id)
    .bind(conversation_id)
    .bind(&alice_did)
    .bind(alice_device)
    .bind(participant_period_id)
    .bind(&payload)
    .bind(Sha256::digest(&payload).to_vec())
    .execute(&mut *tx)
    .await;
    assert!(
        insert.is_err(),
        "an item for alice's primary device cannot land in the sibling's session \
         (recipient-session binding)"
    );
    tx.rollback().await.expect("rollback cross-device item");
}

/// getOwnDevices uses the SEPARATE device fence and never writes the shared
/// session tables.
#[tokio::test]
async fn get_own_devices_uses_separate_device_fence() {
    let pool = common::chat_protocol::setup_chat_protocol_db(3).await;
    let now = whole_second(clock_now(&pool).await);
    // The requester device (with its key) plus a sibling device of the SAME
    // principal — both are subjects of the own-device snapshot.
    let requester = seed_device_with_key(&pool, now - Duration::seconds(120)).await;
    let sibling = seed_active_device(&pool, &requester.did, now - Duration::seconds(90)).await;
    let session_id = Uuid::new_v4();

    let mut tx = pool.begin().await.expect("begin create");
    let created = create_device_inventory_session(
        &mut tx,
        CreateDeviceInventorySessionRequest {
            device_inventory_session_id: session_id,
            user_did: &requester.did,
            device_id: requester.device_id,
            jkt: &requester.jkt,
            auth_generation: 1,
            fence_revision: 0,
            created_at: now,
            expires_at: now + Duration::minutes(10),
            subjects: vec![
                DeviceInventorySubject {
                    subject_device_id: requester.device_id,
                    payload_bytes: b"own-device-self".to_vec(),
                },
                DeviceInventorySubject {
                    subject_device_id: sibling,
                    payload_bytes: b"own-device-sibling".to_vec(),
                },
            ],
        },
    )
    .await
    .expect("create the separate own-device fence");
    tx.commit()
        .await
        .expect("commit past device_inventory materialization + principal triggers");

    assert_eq!(created.item_count, 2);

    // Materialized into the SEPARATE device fence tables, not the shared session.
    let subjects: Vec<(i64, Uuid)> = sqlx::query_as(
        "SELECT ordinal, subject_device_id FROM chat.device_inventory_items \
           WHERE device_inventory_session_id = $1 ORDER BY ordinal",
    )
    .bind(session_id)
    .fetch_all(&pool)
    .await
    .expect("read materialized own-device items");
    assert_eq!(subjects.len(), 2);
    assert_eq!(subjects[0], (0, requester.device_id));
    assert_eq!(subjects[1], (1, sibling));

    let (complete, count): (bool, Option<i64>) = sqlx::query_as(
        "SELECT complete, item_count FROM chat.device_inventory_sessions \
           WHERE device_inventory_session_id = $1",
    )
    .bind(session_id)
    .fetch_one(&pool)
    .await
    .expect("read device fence row");
    assert!(complete);
    assert_eq!(count, Some(2));

    // The id is NOT a shared inventory session — the two fences never collide.
    let shared: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM chat.inventory_sessions WHERE inventory_session_id = $1",
    )
    .bind(session_id)
    .fetch_one(&pool)
    .await
    .expect("count shared sessions");
    assert_eq!(
        shared, 0,
        "getOwnDevices never writes the shared session fence"
    );
}

#[test]
fn terminal_seq_hints_carry_no_fingerprint() {
    // The DTOs expose a `terminal_seq` (wake/navigation) and nothing else that
    // could authorize a close: constructing each proves the field exists and is
    // the only seq carried.
    let tombstone = TombstoneTerminalHint {
        conversation_id: Uuid::new_v4(),
        terminal_seq: 7,
    };
    let event = EventTerminalHint {
        conversation_id: Uuid::new_v4(),
        terminal_seq: 7,
    };
    let inventory = InventorySummaryTerminalHint {
        conversation_id: Uuid::new_v4(),
        terminal_seq: 7,
    };
    let interval = IntervalSummaryTerminalHint {
        conversation_id: Uuid::new_v4(),
        terminal_seq: 7,
    };
    assert_eq!(tombstone.terminal_seq, 7);
    assert_eq!(event.terminal_seq, 7);
    assert_eq!(inventory.terminal_seq, 7);
    assert_eq!(interval.terminal_seq, 7);

    // No hint DTO carries an outer-entry fingerprint (a hint must never duplicate
    // one, nor authorize a close/schedule-terminalize). Assert structurally over
    // the hint DTO block in the production source.
    let source = include_str!("../src/chat_protocol/repository/inventory.rs");
    let hint_block = source
        .split_once("terminalSeq wake/navigation hint DTOs")
        .expect("hint DTO section exists")
        .1;
    for hint in [
        "pub(crate) struct TombstoneTerminalHint",
        "pub(crate) struct EventTerminalHint",
        "pub(crate) struct InventorySummaryTerminalHint",
        "pub(crate) struct IntervalSummaryTerminalHint",
    ] {
        let body = hint_block
            .split_once(hint)
            .expect("hint struct present")
            .1
            .split_once("\n}")
            .expect("hint struct body closed")
            .0;
        assert!(body.contains("terminal_seq"), "{hint} exposes terminal_seq");
        assert!(
            !body.contains("fingerprint"),
            "{hint} must NOT carry an outer-entry fingerprint"
        );
    }
}

// ===========================================================================
// Deterministic barrier races (one receipt/CAS winner, byte-identical replay
// for the loser). The handshake uses a tokio oneshot channel — no sleeps —
// so the winner/loser split is deterministic in every run: the loser signals
// just BEFORE issuing its contended statement, and the winner commits only
// after that signal, so the loser's statement is guaranteed to be issued after
// the winner's and to block on the winner's uncommitted unique-index row.
// ===========================================================================

/// A one-shot handshake: the designated winner commits its unique boundary
/// row, then releases the loser to issue the contended statement. This removes
/// scheduler-dependent ordering without sleeps.
fn winner_commit_barrier() -> (
    tokio::sync::oneshot::Sender<()>,
    tokio::sync::oneshot::Receiver<()>,
) {
    let (sender, receiver) = tokio::sync::oneshot::channel::<()>();
    (sender, receiver)
}

/// The session value shared by the two race transactions. `SeededSession`
/// carries the `CapabilityToken` by value and is deliberately not `Clone`, so
/// the racers share it behind an `Arc` (they only read it).
type SharedSession = std::sync::Arc<SeededSession>;

fn shared_session(session: SeededSession) -> SharedSession {
    std::sync::Arc::new(session)
}

/// Two initial creators race the SAME deterministic initial receipt
/// `(session, domain, limit, filter)` (the partial unique index
/// `inventory_page_receipts_initial_uq`). Exactly one serves; the loser's
/// unique violation rolls back with zero residue and replays the winner's
/// served receipt byte-for-byte.
#[tokio::test]
async fn initial_creator_barrier_one_receipt_winner_and_byte_identical_replay() {
    let pool = common::chat_protocol::setup_chat_protocol_db(4).await;
    let fence = ensure_fence(&pool).await;
    let now = whole_second(clock_now(&pool).await);
    let device = seed_device_with_key(&pool, now - Duration::seconds(120)).await;
    let session_id = Uuid::new_v4();
    let mut random = DeterministicRandom::new(per_run_seed(0xD3E1));
    let session = shared_session(
        seed_session_via_create_shape(
            &pool,
            &fence,
            &device,
            session_id,
            now,
            now + Duration::minutes(15),
            &mut random,
            &[],
            &[],
            &[],
        )
        .await,
    );
    let request = conversations_request(100);

    let (winner_committed, loser_go) = winner_commit_barrier();

    let winner_pool = pool.clone();
    let winner_fence = Fence {
        protocol_instance_id: fence.protocol_instance_id,
        cursor_key_id: fence.cursor_key_id.clone(),
        sealer: sealer_for_cursor_key(&fence.cursor_key_id),
    };
    let winner_session = session.clone();
    let winner_request = request.clone();
    let winner = tokio::spawn(async move {
        let mut tx = winner_pool.begin().await.expect("winner begins");
        let mut random = DeterministicRandom::new(per_run_seed(0xD3E2));
        let (served_at, successor) = serve_page_receipt_seed(
            &mut tx,
            &winner_fence,
            &winner_session,
            "conversations",
            "blue.catbird.chat.getConversations",
            &winner_request,
            None,
            None,
            &[],
            false,
            &mut random,
        )
        .await;
        assert!(
            successor.is_none(),
            "the single-page initial serve is final"
        );
        tx.commit().await.expect("winner commits");
        winner_committed
            .send(())
            .expect("release the loser after commit");
        served_at
    });

    let loser_pool = pool.clone();
    let loser_fence = Fence {
        protocol_instance_id: fence.protocol_instance_id,
        cursor_key_id: fence.cursor_key_id.clone(),
        sealer: sealer_for_cursor_key(&fence.cursor_key_id),
    };
    let loser_session = session.clone();
    let loser_request = request.clone();
    let loser = tokio::spawn(async move {
        loser_go
            .await
            .expect("winner commits before the loser contends");
        let mut tx = loser_pool.begin().await.expect("loser begins");
        let insert = sqlx::query(
            r#"
            INSERT INTO chat.inventory_page_receipts(
                page_receipt_id, request_cursor_hash, inventory_session_id, domain,
                endpoint_nsid, cursor_format_version, page_limit,
                canonical_filter_sha256, user_did, device_id, jkt, auth_generation,
                protocol_instance_id, cursor_key_id, snapshot_event_position,
                snapshot_event_cursor_sha256, snapshot_retained_floor, after_ordinal,
                created_at, expires_at
            ) VALUES ($1,NULL,$2,'conversations','blue.catbird.chat.getConversations',1,$3,$4,$5,$6,$7,1,$8,$9,$10,$11,$12,NULL,$13,$14)
            "#,
        )
        .bind(Uuid::new_v4())
        .bind(loser_session.session_id)
        .bind(100_i16)
        .bind(loser_request.canonical_filter_sha256().as_slice())
        .bind(&loser_session.user_did)
        .bind(loser_session.device_id)
        .bind(&loser_session.jkt)
        .bind(loser_fence.protocol_instance_id)
        .bind(&loser_fence.cursor_key_id)
        .bind(loser_session.snapshot_event_position)
        .bind(loser_session.capability_hash.as_slice())
        .bind(loser_session.retained_floor)
        // Clamped like every seeded serve instant: the receipt binding
        // CHECK (`expires_at <= created_at + 15 minutes`) and, on the
        // continuation arm, the boundary trigger's
        // `created_at >= predecessor.served_at` both anchor on instants at
        // or after the session's whole-second creation instant.
        .bind(whole_second(Utc::now()).max(loser_session.created_at))
        .bind(loser_session.expires_at)
        .execute(&mut *tx)
        .await;
        match insert {
            Err(sqlx::Error::Database(error)) if error.code().as_deref() == Some("23505") => {
                // The deterministic loser: the winner's receipt wins the
                // partial unique index. Zero residue from this transaction.
                tx.rollback().await.expect("loser rolls back");
                reassemble_served_receipt(
                    &loser_pool,
                    &loser_fence,
                    &loser_session,
                    &loser_request,
                    loser_session.created_at,
                    loser_session.expires_at,
                    None,
                    0,
                    false,
                    None,
                )
                .await
                .bytes
            }
            other => panic!("the second initial creator must lose the barrier: {other:?}"),
        }
    });

    let (winner_served_at, loser_replay_bytes) = tokio::join!(winner, loser);
    let winner_served_at = winner_served_at.expect("winner joined");
    let loser_replay_bytes = loser_replay_bytes.expect("loser joined");

    // Exactly ONE served initial receipt exists, with the winner's evidence.
    let receipts: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM chat.inventory_page_receipts WHERE inventory_session_id = $1",
    )
    .bind(session_id)
    .fetch_one(&pool)
    .await
    .expect("count receipts");
    assert_eq!(
        receipts, 1,
        "one receipt winner leaves exactly one receipt row"
    );

    // The loser replays the winner's served receipt byte-for-byte: the
    // reassembled bytes hash to the stored canonical response SHA-256.
    let stored = stored_response_sha256(&pool, session_id).await;
    let replayed = reassemble_served_receipt(
        &pool,
        &fence,
        &session,
        &request,
        winner_served_at,
        session.expires_at,
        None,
        0,
        false,
        None,
    )
    .await;
    assert_eq!(
        replayed.sha256, stored,
        "the replayed initial page is byte-identical to the winner's served response"
    );
    assert_eq!(
        loser_replay_bytes, replayed.bytes,
        "the designated SQL loser returns the winner's replay bytes"
    );

    // A re-request (the same-identity initial page) is a deterministic replay:
    // it never mints a second receipt and returns the identical bytes.
    let mut tx = pool.begin().await.expect("begin re-request");
    let replay_insert = sqlx::query(
        r#"
        INSERT INTO chat.inventory_page_receipts(
            page_receipt_id, request_cursor_hash, inventory_session_id, domain,
            endpoint_nsid, cursor_format_version, page_limit,
            canonical_filter_sha256, user_did, device_id, jkt, auth_generation,
            protocol_instance_id, cursor_key_id, snapshot_event_position,
            snapshot_event_cursor_sha256, snapshot_retained_floor, after_ordinal,
            created_at, expires_at
        ) VALUES ($1,NULL,$2,'conversations','blue.catbird.chat.getConversations',1,$3,$4,$5,$6,$7,1,$8,$9,$10,$11,$12,NULL,$13,$14)
        "#,
    )
    .bind(Uuid::new_v4())
    .bind(session_id)
    .bind(100_i16)
    .bind(request.canonical_filter_sha256().as_slice())
    .bind(&session.user_did)
    .bind(session.device_id)
    .bind(&session.jkt)
    .bind(fence.protocol_instance_id)
    .bind(&fence.cursor_key_id)
    .bind(session.snapshot_event_position)
    .bind(session.capability_hash.as_slice())
    .bind(session.retained_floor)
    // Clamped like every seeded serve instant (receipt binding CHECK).
    .bind(whole_second(Utc::now()).max(session.created_at))
    .bind(session.expires_at)
    .execute(&mut *tx)
    .await;
    assert!(
        matches!(
            replay_insert,
            Err(sqlx::Error::Database(error)) if error.code().as_deref() == Some("23505")
        ),
        "the re-request deterministically replays the winner's initial receipt"
    );
    tx.rollback().await.expect("rollback re-request");
}

/// Two continuation consumers present the SAME successor capability. The
/// unique `request_cursor_hash` index admits exactly one continuation receipt;
/// the loser replays the winner's served continuation byte-for-byte, and the
/// presented capability decrypts identically from the predecessor's seal.
#[tokio::test]
async fn continuation_consumer_barrier_one_receipt_winner_and_byte_identical_replay() {
    let (pool, _guard) = executor_seed::setup().await;
    let scenario = executor_seed::run_fulfillment_scenario(&pool).await;
    let fence = ensure_fence(&pool).await;
    let now = whole_second(clock_now(&pool).await) + Duration::seconds(1);
    let device = SessionDevice {
        did: scenario.fixture.alice_did.clone(),
        device_id: scenario.fixture.alice_device,
        jkt: scenario.fixture.alice_key_id.clone(),
    };
    let participant_period_id: Uuid = sqlx::query_scalar(
        "SELECT participant_period_id FROM chat.participants \
         WHERE conversation_id = $1 AND user_did = $2 AND current_membership",
    )
    .bind(scenario.conversation_id)
    .bind(&device.did)
    .fetch_one(&pool)
    .await
    .expect("the continuation fixture's participant period");
    let session_id = Uuid::new_v4();
    let mut random = DeterministicRandom::new(0xD3E3);
    let retained_item = b"retained-continuation-item".to_vec();
    let retained_items = vec![retained_item.clone()];
    let conversation_item = ConversationItemSeed {
        conversation_id: scenario.conversation_id,
        participant_period_id,
        recipient_did: device.did.clone(),
        recipient_device_id: device.device_id,
        payload: retained_item,
    };
    let session = shared_session(
        seed_session_via_create_shape(
            &pool,
            &fence,
            &device,
            session_id,
            now,
            now + Duration::minutes(15),
            &mut random,
            std::slice::from_ref(&conversation_item),
            &[],
            &[],
        )
        .await,
    );
    let request = conversations_request(100);

    // The served initial receipt with has_more=true, whose successor (C1) is
    // sealed under the receipt's own binding and stored on the row — the
    // capability BOTH consumers present.
    let (initial_served_at, presented) = {
        let mut tx = pool.begin().await.expect("begin initial receipt");
        let mut random = DeterministicRandom::new(0xD3E4);
        let (served, successor) = serve_page_receipt_seed(
            &mut tx,
            &fence,
            &session,
            "conversations",
            "blue.catbird.chat.getConversations",
            &request,
            None,
            None,
            &retained_items,
            true,
            &mut random,
        )
        .await;
        tx.commit().await.expect("commit initial receipt");
        (
            served,
            successor.expect("a has_more page mints its successor"),
        )
    };
    let presented_token = decode_capability_token(&presented.text).expect("canonical successor");
    let request_cursor_hash = presented_token.lookup_hash();

    let (winner_committed, loser_go) = winner_commit_barrier();

    let winner_pool = pool.clone();
    let winner_fence = Fence {
        protocol_instance_id: fence.protocol_instance_id,
        cursor_key_id: fence.cursor_key_id.clone(),
        sealer: sealer_for_cursor_key(&fence.cursor_key_id),
    };
    let winner_session = session.clone();
    let winner_request = request.clone();
    let winner = tokio::spawn(async move {
        let mut tx = winner_pool.begin().await.expect("winner begins");
        let mut random = DeterministicRandom::new(0xD3E5);
        let (served_at, successor) = serve_page_receipt_seed(
            &mut tx,
            &winner_fence,
            &winner_session,
            "conversations",
            "blue.catbird.chat.getConversations",
            &winner_request,
            Some(request_cursor_hash),
            Some(0),
            &[],
            false,
            &mut random,
        )
        .await;
        tx.commit().await.expect("winner commits");
        winner_committed
            .send(())
            .expect("release the loser after commit");
        assert!(
            successor.is_none(),
            "the final continuation carries no successor"
        );
        served_at
    });

    let loser_pool = pool.clone();
    let loser_fence = Fence {
        protocol_instance_id: fence.protocol_instance_id,
        cursor_key_id: fence.cursor_key_id.clone(),
        sealer: sealer_for_cursor_key(&fence.cursor_key_id),
    };
    let loser_session = session.clone();
    let loser_request = request.clone();
    let loser = tokio::spawn(async move {
        loser_go
            .await
            .expect("winner commits before the loser contends");
        let mut tx = loser_pool.begin().await.expect("loser begins");
        let insert = sqlx::query(
            r#"
            INSERT INTO chat.inventory_page_receipts(
                page_receipt_id, request_cursor_hash, inventory_session_id, domain,
                endpoint_nsid, cursor_format_version, page_limit,
                canonical_filter_sha256, user_did, device_id, jkt, auth_generation,
                protocol_instance_id, cursor_key_id, snapshot_event_position,
                snapshot_event_cursor_sha256, snapshot_retained_floor, after_ordinal,
                created_at, expires_at
            ) VALUES ($1,$2,$3,'conversations','blue.catbird.chat.getConversations',1,$4,$5,$6,$7,$8,1,$9,$10,$11,$12,$13,$14,$15,$16)
            "#,
        )
        .bind(Uuid::new_v4())
        .bind(request_cursor_hash.as_slice())
        .bind(loser_session.session_id)
        .bind(100_i16)
        .bind(loser_request.canonical_filter_sha256().as_slice())
        .bind(&loser_session.user_did)
        .bind(loser_session.device_id)
        .bind(&loser_session.jkt)
        .bind(loser_fence.protocol_instance_id)
        .bind(&loser_fence.cursor_key_id)
        .bind(loser_session.snapshot_event_position)
        .bind(loser_session.capability_hash.as_slice())
        .bind(loser_session.retained_floor)
        .bind(0_i64)
        // The boundary trigger requires `created_at >= predecessor.served_at`
        // BEFORE the unique index is reached, and the predecessor (R0) was
        // served at the session's one-second-in-the-future creation instant —
        // the same clamp `serve_page_receipt_seed` applies. An unclamped wall
        // instant sits one second behind it and turns the intended 23505
        // unique-violation loss into a 23514 boundary mismatch.
        .bind(whole_second(Utc::now()).max(loser_session.created_at))
        .bind(loser_session.expires_at)
        .execute(&mut *tx)
        .await;
        match insert {
            Err(sqlx::Error::Database(error)) if error.code().as_deref() == Some("23505") => {
                tx.rollback().await.expect("loser rolls back");
                let served_at: DateTime<Utc> = sqlx::query_scalar(
                    "SELECT served_at FROM chat.inventory_page_receipts \
                     WHERE inventory_session_id = $1 AND request_cursor_hash = $2",
                )
                .bind(loser_session.session_id)
                .bind(request_cursor_hash.as_slice())
                .fetch_one(&loser_pool)
                .await
                .expect("the committed winner receipt is visible to the loser");
                reassemble_served_receipt(
                    &loser_pool,
                    &loser_fence,
                    &loser_session,
                    &loser_request,
                    served_at,
                    loser_session.expires_at,
                    Some(0),
                    0,
                    false,
                    None,
                )
                .await
                .bytes
            }
            other => panic!("the second continuation consumer must lose the barrier: {other:?}"),
        }
    });

    let (winner_served_at, loser_replay_bytes) = tokio::join!(winner, loser);
    let winner_served_at = winner_served_at.expect("winner joined");
    let loser_replay_bytes = loser_replay_bytes.expect("loser joined");

    // Exactly two receipts (initial + one continuation), the winner's only.
    let receipts: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM chat.inventory_page_receipts WHERE inventory_session_id = $1",
    )
    .bind(session_id)
    .fetch_one(&pool)
    .await
    .expect("count receipts");
    assert_eq!(
        receipts, 2,
        "one continuation winner leaves exactly two receipt rows"
    );

    // The presented successor decrypts IDENTICALLY from the predecessor's
    // seal, and its hash is the continuation's request hash.
    let initial_stored: Vec<u8> = sqlx::query_scalar::<_, Vec<u8>>(
        "SELECT canonical_response_sha256 FROM chat.inventory_page_receipts \
         WHERE inventory_session_id = $1 AND request_cursor_hash IS NULL",
    )
    .bind(session_id)
    .fetch_one(&pool)
    .await
    .expect("the initial receipt is retained")
    .to_vec();
    let initial_stored: [u8; 32] = initial_stored.try_into().expect("32-byte initial digest");
    let replayed = reassemble_served_receipt(
        &pool,
        &fence,
        &session,
        &request,
        initial_served_at,
        session.expires_at,
        None,
        1,
        true,
        Some(&presented),
    )
    .await;
    assert_eq!(
        replayed.successor_text.as_deref(),
        Some(presented.text.as_str()),
        "the identical decrypted successor is recovered from the initial receipt's seal"
    );
    assert_eq!(
        replayed.sha256, initial_stored,
        "the initial winner's retained item bytes replay byte-for-byte"
    );

    // The continuation winner's response reassembles byte-for-byte.
    let stored: Vec<u8> = sqlx::query_scalar(
        "SELECT canonical_response_sha256 FROM chat.inventory_page_receipts \
         WHERE inventory_session_id = $1 AND after_ordinal = 0",
    )
    .bind(session_id)
    .fetch_one(&pool)
    .await
    .expect("the continuation receipt is retained");
    let stored: [u8; 32] = stored.try_into().expect("32-byte stored digest");
    let replayed = reassemble_served_receipt(
        &pool,
        &fence,
        &session,
        &request,
        winner_served_at,
        session.expires_at,
        Some(0),
        0,
        false,
        None,
    )
    .await;
    assert_eq!(
        replayed.sha256, stored,
        "the replayed continuation page is byte-identical to the winner's served response"
    );
    assert_eq!(
        loser_replay_bytes, replayed.bytes,
        "the designated SQL loser returns the winner's continuation replay bytes"
    );
}

/// Two final consumers present the final-page successor. One serves the final
/// receipt and wins the first-final-page `*_consumed` compare-and-set exactly
/// once; the loser replays the winner's final page byte-for-byte and never
/// repeats the CAS. The whole chain runs over REAL retained item rows: R0 and
/// R1 serve the durable `inventory_conversation_items` payloads, so the winner
/// and the loser reconstruct byte-identical retained responses through the
/// real page SQL path.
#[tokio::test]
async fn final_consumer_barrier_one_cas_winner_and_byte_identical_replay() {
    let (pool, _guard) = executor_seed::setup().await;
    let scenario = executor_seed::run_fulfillment_scenario(&pool).await;
    let fence = ensure_fence(&pool).await;
    let device = SessionDevice {
        did: scenario.fixture.alice_did.clone(),
        device_id: scenario.fixture.alice_device,
        jkt: scenario.fixture.alice_key_id.clone(),
    };
    let participant_period_id: Uuid = sqlx::query_scalar(
        "SELECT participant_period_id FROM chat.participants \
         WHERE conversation_id = $1 AND user_did = $2 AND current_membership",
    )
    .bind(scenario.conversation_id)
    .bind(&device.did)
    .fetch_one(&pool)
    .await
    .expect("the final-consumer fixture's participant period");
    // Item 1 lives in a DISTINCT real conversation (the schema allows one item
    // row per (session, conversation)); it is seeded BEFORE the session's
    // whole-second instant is sampled so every source row predates the
    // snapshot.
    let (second_conversation_id, second_participant_period_id) =
        seed_pending_invited_conversation(&pool, &device).await;
    let now = whole_second(clock_now(&pool).await) + Duration::seconds(1);
    let session_id = Uuid::new_v4();
    let mut random = DeterministicRandom::new(0xD3E6);
    let item0 = b"retained-final-item-0".to_vec();
    let item1 = b"retained-final-item-1".to_vec();
    let conversation_items = vec![
        ConversationItemSeed {
            conversation_id: scenario.conversation_id,
            participant_period_id,
            recipient_did: device.did.clone(),
            recipient_device_id: device.device_id,
            payload: item0.clone(),
        },
        ConversationItemSeed {
            conversation_id: second_conversation_id,
            participant_period_id: second_participant_period_id,
            recipient_did: device.did.clone(),
            recipient_device_id: device.device_id,
            payload: item1.clone(),
        },
    ];
    let session = shared_session(
        seed_session_via_create_shape(
            &pool,
            &fence,
            &device,
            session_id,
            now,
            now + Duration::minutes(15),
            &mut random,
            &conversation_items,
            &[],
            &[],
        )
        .await,
    );
    let request = conversations_request(100);

    // R0: served initial (has_more=true, successor C1) over item 0; R1: served
    // continuation (request H(C1), after 0, has_more=true, successor C2 — the
    // final-page cursor BOTH consumers present) over item 1. Both receipts are
    // seeded from the REAL retained item rows (the boundary trigger requires
    // the continuation arm's request_cursor_hash to name the predecessor's
    // successor seal, and after_ordinal to equal the predecessor's boundary).
    let (r0_served_at, r1_served_at, c1, c2) = {
        let mut tx = pool.begin().await.expect("begin chain");
        let mut random = DeterministicRandom::new(0xD3E7);
        let (r0_served, c1) = serve_page_receipt_seed(
            &mut tx,
            &fence,
            &session,
            "conversations",
            "blue.catbird.chat.getConversations",
            &request,
            None,
            None,
            &[item0],
            true,
            &mut random,
        )
        .await;
        let c1 = c1.expect("R0 mints its successor");
        let (r1_served, c2) = serve_page_receipt_seed(
            &mut tx,
            &fence,
            &session,
            "conversations",
            "blue.catbird.chat.getConversations",
            &request,
            Some(c1.hash),
            Some(0),
            &[item1],
            true,
            &mut random,
        )
        .await;
        tx.commit().await.expect("commit the receipt chain");
        (
            r0_served,
            r1_served,
            c1,
            c2.expect("the continuation mints its successor"),
        )
    };
    let final_request_hash = c2.hash;

    let (winner_committed, loser_go) = winner_commit_barrier();

    let winner_pool = pool.clone();
    let winner_fence = Fence {
        protocol_instance_id: fence.protocol_instance_id,
        cursor_key_id: fence.cursor_key_id.clone(),
        sealer: sealer_for_cursor_key(&fence.cursor_key_id),
    };
    let winner_session = session.clone();
    let winner_request = request.clone();
    let winner = tokio::spawn(async move {
        let mut tx = winner_pool.begin().await.expect("winner begins");
        let mut random = DeterministicRandom::new(0xD3E8);
        let (served_at, successor) = serve_page_receipt_seed(
            &mut tx,
            &winner_fence,
            &winner_session,
            "conversations",
            "blue.catbird.chat.getConversations",
            &winner_request,
            Some(final_request_hash),
            Some(1),
            &[],
            false,
            &mut random,
        )
        .await;
        assert!(successor.is_none(), "the final page carries no successor");
        // The first-final-page CAS fires only in the fresh winner's
        // transaction, at the final receipt's exact serve instant.
        let affected = consume_final_page_cas(
            &mut tx,
            winner_session.session_id,
            "conversations",
            served_at,
        )
        .await;
        assert_eq!(affected, 1, "the final-page CAS wins exactly once");
        tx.commit().await.expect("winner commits");
        winner_committed
            .send(())
            .expect("release the loser after commit");
        served_at
    });

    let loser_pool = pool.clone();
    let loser_fence = Fence {
        protocol_instance_id: fence.protocol_instance_id,
        cursor_key_id: fence.cursor_key_id.clone(),
        sealer: sealer_for_cursor_key(&fence.cursor_key_id),
    };
    let loser_session = session.clone();
    let loser_request = request.clone();
    let loser = tokio::spawn(async move {
        loser_go
            .await
            .expect("winner commits before the loser contends");
        let mut tx = loser_pool.begin().await.expect("loser begins");
        let insert = sqlx::query(
            r#"
            INSERT INTO chat.inventory_page_receipts(
                page_receipt_id, request_cursor_hash, inventory_session_id, domain,
                endpoint_nsid, cursor_format_version, page_limit,
                canonical_filter_sha256, user_did, device_id, jkt, auth_generation,
                protocol_instance_id, cursor_key_id, snapshot_event_position,
                snapshot_event_cursor_sha256, snapshot_retained_floor, after_ordinal,
                created_at, expires_at
            ) VALUES ($1,$2,$3,'conversations','blue.catbird.chat.getConversations',1,$4,$5,$6,$7,$8,1,$9,$10,$11,$12,$13,$14,$15,$16)
            "#,
        )
        .bind(Uuid::new_v4())
        .bind(final_request_hash.as_slice())
        .bind(loser_session.session_id)
        .bind(100_i16)
        .bind(loser_request.canonical_filter_sha256().as_slice())
        .bind(&loser_session.user_did)
        .bind(loser_session.device_id)
        .bind(&loser_session.jkt)
        .bind(loser_fence.protocol_instance_id)
        .bind(&loser_fence.cursor_key_id)
        .bind(loser_session.snapshot_event_position)
        .bind(loser_session.capability_hash.as_slice())
        .bind(loser_session.retained_floor)
        .bind(1_i64)
        // Clamped like every seeded serve instant: the receipt binding
        // CHECK (`expires_at <= created_at + 15 minutes`) and, on the
        // continuation arm, the boundary trigger's
        // `created_at >= predecessor.served_at` both anchor on instants at
        // or after the session's whole-second creation instant.
        .bind(whole_second(Utc::now()).max(loser_session.created_at))
        .bind(loser_session.expires_at)
        .execute(&mut *tx)
        .await;
        match insert {
            Err(sqlx::Error::Database(error)) if error.code().as_deref() == Some("23505") => {
                // The loser replays the winner's final page; it never CASes.
                tx.rollback().await.expect("loser rolls back");
                let served_at: DateTime<Utc> = sqlx::query_scalar(
                    "SELECT served_at FROM chat.inventory_page_receipts \
                     WHERE inventory_session_id = $1 AND request_cursor_hash = $2",
                )
                .bind(loser_session.session_id)
                .bind(final_request_hash.as_slice())
                .fetch_one(&loser_pool)
                .await
                .expect("the committed final winner is visible to the loser");
                reassemble_served_receipt(
                    &loser_pool,
                    &loser_fence,
                    &loser_session,
                    &loser_request,
                    served_at,
                    loser_session.expires_at,
                    Some(1),
                    0,
                    false,
                    None,
                )
                .await
                .bytes
            }
            other => panic!("the second final consumer must lose the barrier: {other:?}"),
        }
    });

    let (winner_served_at, loser_replay_bytes) = tokio::join!(winner, loser);
    let winner_served_at = winner_served_at.expect("winner joined");
    let loser_replay_bytes = loser_replay_bytes.expect("loser joined");

    // Exactly three receipts (initial + continuation + one final).
    let receipts: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM chat.inventory_page_receipts WHERE inventory_session_id = $1",
    )
    .bind(session_id)
    .fetch_one(&pool)
    .await
    .expect("count receipts");
    assert_eq!(
        receipts, 3,
        "one final winner leaves exactly three receipt rows"
    );

    // The consumed CAS fired exactly once, at the final receipt's served_at.
    let (consumed, consumed_at, final_served_at): (bool, Option<DateTime<Utc>>, DateTime<Utc>) =
        sqlx::query_as(
            "SELECT session.conversations_consumed, session.conversations_consumed_at, \
                    receipt.served_at \
               FROM chat.inventory_sessions session \
               JOIN chat.inventory_page_receipts receipt \
                 ON receipt.inventory_session_id = session.inventory_session_id \
              WHERE session.inventory_session_id = $1 \
                AND receipt.after_ordinal = 1",
        )
        .bind(session_id)
        .fetch_one(&pool)
        .await
        .expect("the consumed proof and the final receipt");
    assert!(consumed, "the final-page CAS marks the domain consumed");
    assert_eq!(
        consumed_at,
        Some(final_served_at),
        "the consumed instant is the final receipt's exact serve instant"
    );
    assert_eq!(
        final_served_at, winner_served_at,
        "the final receipt served by the race winner"
    );

    // A second CAS attempt is a no-op (0 rows) — the loser never repeats it.
    let mut tx = pool.begin().await.expect("begin no-op CAS");
    let affected =
        consume_final_page_cas(&mut tx, session_id, "conversations", winner_served_at).await;
    assert_eq!(affected, 0, "the consumed CAS is a no-op after the winner");
    tx.rollback().await.expect("rollback no-op CAS");

    // The loser's byte-identical replay of the final page.
    let stored: Vec<u8> = sqlx::query_scalar::<_, Vec<u8>>(
        "SELECT canonical_response_sha256 FROM chat.inventory_page_receipts \
         WHERE inventory_session_id = $1 AND request_cursor_hash = $2",
    )
    .bind(session_id)
    .bind(final_request_hash.as_slice())
    .fetch_one(&pool)
    .await
    .expect("the final receipt response digest is retained");
    let stored: [u8; 32] = stored.try_into().expect("32-byte final digest");
    let replayed = reassemble_served_receipt(
        &pool,
        &fence,
        &session,
        &request,
        winner_served_at,
        session.expires_at,
        Some(1),
        0,
        false,
        None,
    )
    .await;
    assert_eq!(
        replayed.sha256, stored,
        "the replayed final page is byte-identical to the winner's served response"
    );
    assert_eq!(
        loser_replay_bytes, replayed.bytes,
        "the designated SQL loser returns the winner's final replay bytes"
    );

    // The retained chain replays byte-for-byte through the real page SQL path:
    // R0 over item 0 (ordinal 0) with the identical decrypted C1, R1 over item
    // 1 (ordinal 1) with the identical decrypted C2. The stored canonical
    // response SHA-256 of each served receipt is verified before bytes return.
    let r0_stored: Vec<u8> = sqlx::query_scalar::<_, Vec<u8>>(
        "SELECT canonical_response_sha256 FROM chat.inventory_page_receipts \
         WHERE inventory_session_id = $1 AND request_cursor_hash IS NULL",
    )
    .bind(session_id)
    .fetch_one(&pool)
    .await
    .expect("the R0 receipt response digest is retained")
    .to_vec();
    let r0_stored: [u8; 32] = r0_stored.try_into().expect("32-byte R0 digest");
    let r0_replayed = reassemble_served_receipt(
        &pool,
        &fence,
        &session,
        &request,
        r0_served_at,
        session.expires_at,
        None,
        1,
        true,
        Some(&c1),
    )
    .await;
    assert_eq!(
        r0_replayed.successor_text.as_deref(),
        Some(c1.text.as_str()),
        "R0's identical decrypted successor is recovered from ITS seal"
    );
    assert_eq!(
        r0_replayed.sha256, r0_stored,
        "R0 replays byte-for-byte over the retained item-0 row"
    );

    let r1_stored: Vec<u8> = sqlx::query_scalar::<_, Vec<u8>>(
        "SELECT canonical_response_sha256 FROM chat.inventory_page_receipts \
         WHERE inventory_session_id = $1 AND request_cursor_hash = $2",
    )
    .bind(session_id)
    .bind(c1.hash.as_slice())
    .fetch_one(&pool)
    .await
    .expect("the R1 receipt response digest is retained")
    .to_vec();
    let r1_stored: [u8; 32] = r1_stored.try_into().expect("32-byte R1 digest");
    let r1_replayed = reassemble_served_receipt(
        &pool,
        &fence,
        &session,
        &request,
        r1_served_at,
        session.expires_at,
        Some(0),
        1,
        true,
        Some(&c2),
    )
    .await;
    assert_eq!(
        r1_replayed.successor_text.as_deref(),
        Some(c2.text.as_str()),
        "R1's identical decrypted successor is recovered from ITS seal"
    );
    assert_eq!(
        r1_replayed.sha256, r1_stored,
        "R1 replays byte-for-byte over the retained item-1 row"
    );
}

/// One additional REAL conversation the recipient can hold a
/// `conversationInventoryState` item for: a genuine creation graph (fresh
/// random creator, group kind) plus a PENDING invitation participant row for
/// the recipient, in the exact column shape the graph's own signed-invitee
/// path uses. The item-source trigger accepts a pending-invited participant
/// of a group conversation (invitation provenance present, acceptance
/// absent), and a pending participant carries no leaf, so the roster/leaf
/// invariants hold. Pagination REQUIRES distinct conversations: the schema
/// allows one item row per `(inventory_session_id, conversation_id)`.
///
/// Must be seeded BEFORE the session's whole-second creation instant is
/// sampled — the item-source trigger requires every conversation/participant
/// row to predate the session snapshot.
async fn seed_pending_invited_conversation(pool: &PgPool, invitee: &SessionDevice) -> (Uuid, Uuid) {
    let conversation_id = Uuid::new_v4();
    let entry = executor_seed::build_real_creation_entry(*conversation_id.as_bytes());
    let graph = executor_seed::seed_genuine_creation_graph(pool, &entry, None, None).await;
    let participant_period_id = Uuid::new_v4();
    // The role/invitation provenance instants must be the CREATION
    // TRANSITION's own accepted instant: `participants_role_transition_fk` is
    // the exact triple (conversation_id, role_transition_id, role_changed_at)
    // -> transitions(conversation_id, transition_id, accepted_at), and the
    // graph's signed-invitee path binds the same instant for invited_at and
    // created_at.
    let invited_at: DateTime<Utc> = sqlx::query_scalar(
        "SELECT accepted_at FROM chat.transitions \
         WHERE conversation_id = $1 AND transition_id = $2",
    )
    .bind(conversation_id)
    .bind(graph.creation_transition_id)
    .fetch_one(pool)
    .await
    .expect("the creation transition backs the invitation provenance");
    sqlx::query(
        r#"INSERT INTO chat.participants(
            participant_period_id,conversation_id,user_did,status,role,role_transition_id,
            role_changed_at,created_by_did,created_by_device_id,invitation_transition_id,
            invitation_entry_id,invited_at,current_membership,created_at
        ) VALUES($1,$2,$3,'pending','member',$4,$5,$6,$7,$4,$8,$5,true,$5)"#,
    )
    .bind(participant_period_id)
    .bind(conversation_id)
    .bind(&invitee.did)
    .bind(graph.creation_transition_id)
    .bind(invited_at)
    .bind(&graph.creator_did)
    .bind(graph.creator_device_id)
    .bind(entry.entry_id)
    .execute(pool)
    .await
    .expect("insert the pending invited recipient participant");
    (conversation_id, participant_period_id)
}

/// The paging device authority for the PRODUCTION entrypoints under the
/// include harness (`repository::inventory::PagingDeviceAuthority`, the
/// `cfg(test)` identity arm of the production alias). Built fresh per call —
/// the entrypoints consume it.
fn paging_device(device: &SessionDevice) -> repository::inventory::PagingDeviceAuthority {
    repository::inventory::PagingDeviceAuthority {
        user_did: device.did.clone(),
        device_id: device.device_id,
        jkt: device.jkt.clone(),
        auth_generation: 1,
    }
}

/// Extract the `nextPageCursor` capability text from a canonical response.
fn extract_next_page_cursor(bytes: &[u8]) -> Option<String> {
    let text = std::str::from_utf8(bytes).expect("the canonical response is UTF-8");
    let (_, tail) = text.split_once("\"nextPageCursor\":\"")?;
    let (cursor, _) = tail.split_once('"')?;
    Some(cursor.to_owned())
}

/// The `(conversations_consumed, conversations_consumed_at)` pair.
async fn conversations_consumed_state(
    pool: &PgPool,
    session_id: Uuid,
) -> (bool, Option<DateTime<Utc>>) {
    sqlx::query_as(
        "SELECT conversations_consumed, conversations_consumed_at \
         FROM chat.inventory_sessions WHERE inventory_session_id = $1",
    )
    .bind(session_id)
    .fetch_one(pool)
    .await
    .expect("read the consumption state")
}

/// Final-review fix-round coverage (C-1/C-2): the PRODUCTION paging
/// entrypoints — `serve_initial_inventory_page`,
/// `issue_next_inventory_page_cursor`, `complete_inventory_page`, and through
/// them `serve_page_receipt`/`replay_served_receipt` — are driven directly
/// (no SQL replicas) across a three-item, limit-1 conversations domain:
/// initial -> continuation -> final under the sealed boundary trigger, the
/// final-page `*_consumed` CAS exactly once, then a byte-identical replay of
/// EVERY arm (including the identical decrypted successor embedded in the
/// bytes) through the production unique-violation loser path, and a
/// fabricated capability failing closed.
#[tokio::test]
async fn production_paging_entrypoints_serve_and_replay_the_full_receipt_chain() {
    let (pool, _guard) = executor_seed::setup().await;
    let scenario = executor_seed::run_fulfillment_scenario(&pool).await;
    let fence = ensure_fence(&pool).await;
    let device = SessionDevice {
        did: scenario.fixture.alice_did.clone(),
        device_id: scenario.fixture.alice_device,
        jkt: scenario.fixture.alice_key_id.clone(),
    };
    let participant_period_id: Uuid = sqlx::query_scalar(
        "SELECT participant_period_id FROM chat.participants \
         WHERE conversation_id = $1 AND user_did = $2 AND current_membership",
    )
    .bind(scenario.conversation_id)
    .bind(&device.did)
    .fetch_one(&pool)
    .await
    .expect("the fixture's participant period");
    // Pagination is across DISTINCT conversations (the schema allows one item
    // row per (session, conversation)): item 0 is the fulfillment conversation
    // with alice's current-membership period; items 1 and 2 are additional
    // REAL conversations alice is pending-invited to, seeded BEFORE the
    // session instant is sampled so every source row predates the snapshot.
    let mut conversation_sources = vec![(scenario.conversation_id, participant_period_id)];
    for _ in 0..2 {
        conversation_sources.push(seed_pending_invited_conversation(&pool, &device).await);
    }
    // DETERMINISTIC session instant (round 8): the item-source trigger's
    // state arm compares session.created_at against SOURCE-ROW instants that
    // the shared executor seeding stamps at WALL-CLOCK time
    // (`applied_at = clock_now`), so neither trunc-down(now) (a source in the
    // same second can exceed it — the window-4 flake) nor a wall-relative
    // future offset is structurally ordered. The session instant is instead
    // derived FROM the compared instants themselves: one whole second past
    // the LATEST of them (`trunc(max)+1 > max` for any sub-second part).
    // The trigger's full compared set for `conversationInventoryState`,
    // enumerated: conversations.created_at (<= session; in GREATEST),
    // conversations.closed_at (NULL for all three — clause passes
    // structurally), the exact participant row's created_at (<=; in
    // GREATEST), accepted_at (moot: the scenario creator has NULL invitation
    // provenance, the pending rows have NULL acceptance + group kind; still
    // folded into GREATEST), removed_at (NULL), and the finite-interval
    // clause (alice has NO removed application_intervals in any of the three
    // conversations, so it passes regardless of the open-interval instants;
    // interval created_at folded into GREATEST anyway).
    let paged_conversation_ids: Vec<Uuid> =
        conversation_sources.iter().map(|(id, _)| *id).collect();
    let latest_source: DateTime<Utc> = sqlx::query_scalar(
        "SELECT GREATEST( \
             (SELECT max(created_at) FROM chat.conversations \
               WHERE conversation_id = ANY($1)), \
             (SELECT max(GREATEST(created_at, COALESCE(accepted_at, created_at))) \
                FROM chat.participants \
               WHERE conversation_id = ANY($1) AND user_did = $2), \
             (SELECT max(created_at) FROM chat.application_intervals \
               WHERE conversation_id = ANY($1) AND recipient_did = $2) \
         )",
    )
    .bind(&paged_conversation_ids)
    .bind(&device.did)
    .fetch_one(&pool)
    .await
    .expect("the latest trigger-compared source instant");
    let now = whole_second(latest_source) + Duration::seconds(1);
    let session_id = Uuid::new_v4();
    let mut random = DeterministicRandom::new(0xC1F1);
    let conversation_items: Vec<ConversationItemSeed> = conversation_sources
        .iter()
        .enumerate()
        .map(|(index, (conversation_id, period))| ConversationItemSeed {
            conversation_id: *conversation_id,
            participant_period_id: *period,
            recipient_did: device.did.clone(),
            recipient_device_id: device.device_id,
            payload: format!("retained-production-item-{index}").into_bytes(),
        })
        .collect();
    let session = seed_session_via_create_shape(
        &pool,
        &fence,
        &device,
        session_id,
        now,
        now + Duration::minutes(15),
        &mut random,
        &conversation_items,
        &[],
        &[],
    )
    .await;
    let request = conversations_request(1);

    // The other structural half: production stamps receipts and the
    // `*_consumed` CAS from `transaction_timestamp()`, and the schema anchors
    // them on the session (`consumed_at >= created_at`; receipt window
    // `expires_at <= created_at + 15 minutes`). Wait until the database
    // clock's whole second reaches the session instant before the FIRST
    // production call — bounded by construction to at most one second past
    // the latest source row (this is clock alignment against a derived
    // instant, not a race-masking sleep).
    loop {
        if whole_second(clock_now(&pool).await) >= now {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(25)).await;
    }

    // Initial page: PRODUCTION serve over the retained item rows.
    let mut random = DeterministicRandom::new(0xC1F2);
    let mut tx = pool.begin().await.expect("begin the initial serve");
    let r0 = repository::inventory::serve_initial_inventory_page(
        &mut tx,
        Some(paging_device(&device)),
        session_id,
        &request,
        &fence.sealer,
        &mut random,
    )
    .await
    .expect("the production initial serve succeeds");
    tx.commit().await.expect("commit the initial serve");
    let c1 = extract_next_page_cursor(r0.bytes()).expect("the initial page mints a successor");
    let session_capability_text = URL_SAFE_NO_PAD.encode(session.capability.as_bytes());
    assert!(
        std::str::from_utf8(r0.bytes())
            .expect("canonical response is UTF-8")
            .contains(&format!(
                "\"inventorySessionId\":\"{session_capability_text}\""
            )),
        "the served response embeds the identical decrypted session capability"
    );
    assert_eq!(
        conversations_consumed_state(&pool, session_id).await.0,
        false,
        "a nonfinal initial serve never consumes the domain"
    );

    // Continuation: the PRODUCTION hash-located boundary (predecessor by
    // successor hash; the sealed boundary trigger validates the forwarded
    // after_ordinal on the INSERT).
    let mut tx = pool.begin().await.expect("begin the continuation");
    let r1 = repository::inventory::issue_next_inventory_page_cursor(
        &mut tx,
        paging_device(&device),
        &c1,
        &request,
        &fence.sealer,
        &mut random,
    )
    .await
    .expect("the production continuation succeeds against the sealed trigger");
    tx.commit().await.expect("commit the continuation");
    let c2 = extract_next_page_cursor(r1.bytes()).expect("the continuation mints a successor");
    assert_ne!(c1, c2, "each page mints a fresh successor capability");

    // Final page: PRODUCTION serve + the one-way `*_consumed` CAS.
    let mut tx = pool.begin().await.expect("begin the final page");
    let r2 = repository::inventory::complete_inventory_page(
        &mut tx,
        paging_device(&device),
        &c2,
        &request,
        None,
        &fence.sealer,
    )
    .await
    .expect("the production final page succeeds");
    tx.commit().await.expect("commit the final page");
    assert_eq!(
        extract_next_page_cursor(r2.bytes()),
        None,
        "the final page mints no successor"
    );
    let (consumed, consumed_at) = conversations_consumed_state(&pool, session_id).await;
    assert!(
        consumed,
        "the fresh final serve performs the CAS exactly once"
    );
    let consumed_at = consumed_at.expect("the CAS stamps its serve instant");

    // Replay EVERY arm through the production loser path (the unique-violation
    // -> hash-located replay): byte-identical responses, including the
    // identical decrypted successor embedded in the bytes; the CAS never
    // repeats.
    let mut tx = pool.begin().await.expect("begin the initial replay");
    let r0_replay = repository::inventory::serve_initial_inventory_page(
        &mut tx,
        Some(paging_device(&device)),
        session_id,
        &request,
        &fence.sealer,
        &mut random,
    )
    .await
    .expect("the initial replay succeeds");
    tx.commit().await.expect("commit the initial replay");
    assert_eq!(
        r0_replay.bytes(),
        r0.bytes(),
        "the initial page replays byte-for-byte (identical decrypted successor included)"
    );

    let mut tx = pool.begin().await.expect("begin the continuation replay");
    let r1_replay = repository::inventory::issue_next_inventory_page_cursor(
        &mut tx,
        paging_device(&device),
        &c1,
        &request,
        &fence.sealer,
        &mut random,
    )
    .await
    .expect("the continuation replay succeeds");
    tx.commit().await.expect("commit the continuation replay");
    assert_eq!(
        r1_replay.bytes(),
        r1.bytes(),
        "the continuation replays byte-for-byte (identical decrypted successor included)"
    );

    let mut tx = pool.begin().await.expect("begin the final replay");
    let r2_replay = repository::inventory::complete_inventory_page(
        &mut tx,
        paging_device(&device),
        &c2,
        &request,
        None,
        &fence.sealer,
    )
    .await
    .expect("the final replay succeeds");
    tx.commit().await.expect("commit the final replay");
    assert_eq!(
        r2_replay.bytes(),
        r2.bytes(),
        "the final page replays byte-for-byte"
    );
    assert_eq!(
        conversations_consumed_state(&pool, session_id).await,
        (true, Some(consumed_at)),
        "the replay never repeats the consumption CAS"
    );

    // A fabricated capability locates no predecessor and fails closed.
    let fabricated = mint_capability_token(&mut random).expect("mint an unrelated capability");
    let mut tx = pool.begin().await.expect("begin the fabricated attempt");
    let denied = repository::inventory::issue_next_inventory_page_cursor(
        &mut tx,
        paging_device(&device),
        &fabricated.encode(),
        &request,
        &fence.sealer,
        &mut random,
    )
    .await;
    tx.rollback()
        .await
        .expect("roll back the fabricated attempt");
    assert!(
        matches!(
            denied,
            Err(InventoryRepositoryError::SessionPresentationMismatch)
        ),
        "a capability no receipt minted fails closed"
    );

    // A foreign device identity fails the paging fence before any serve.
    let foreign = repository::inventory::PagingDeviceAuthority {
        user_did: device.did.clone(),
        device_id: Uuid::new_v4(),
        jkt: device.jkt.clone(),
        auth_generation: 1,
    };
    let mut tx = pool.begin().await.expect("begin the foreign attempt");
    let denied = repository::inventory::issue_next_inventory_page_cursor(
        &mut tx,
        foreign,
        &c1,
        &request,
        &fence.sealer,
        &mut random,
    )
    .await;
    tx.rollback().await.expect("roll back the foreign attempt");
    assert!(
        matches!(
            denied,
            Err(InventoryRepositoryError::DeviceAuthorityMismatch)
        ),
        "another device can never redeem this session's page capability"
    );
}

// ===========================================================================
// C-1 expiry acceptance tests (routed from the D-2 review Critical): an
// expired retained session FAILS CLOSED for the same-identity initial-page
// request while the row exists (no bytes, no `*_consumed` transition), and a
// NEW session IS creatable under the same deterministic identity after the
// sealed `chat.gc_expired_inventory_sessions` reclaims the row.
// ===========================================================================

/// The fixed B-read identity as a `SessionDevice` (the evidence subject of
/// `ordinary_registered_device`).
fn fixed_admission_device() -> SessionDevice {
    SessionDevice {
        did: chat_protocol::inventory_bridge::FIXED_TEST_DID.to_owned(),
        device_id: Uuid::parse_str(chat_protocol::inventory_bridge::FIXED_TEST_DEVICE).unwrap(),
        jkt: chat_protocol::inventory_bridge::FIXED_TEST_JKT.to_owned(),
    }
}

/// (a) After the 15-minute expiry, the same-identity client's initial-page
/// request FAILS CLOSED while the expired row exists: the real B-read chain
/// (`verify_inventory_fence`) rejects the aged fence, no page bytes are
/// produced, the served-receipt write fails the schema's temporal shape check,
/// and no `*_consumed` transition occurs.
#[tokio::test]
async fn expired_session_initial_page_request_fails_closed_while_the_row_exists() {
    // A fresh per-test database: the deterministic identity seeds never collide
    // across runs, and the guard drops the whole database at test end (the
    // identity-immutable trigger forbids any other cleanup of the expired row).
    let (pool, _guard) = executor_seed::setup().await;
    let fence = ensure_fence(&pool).await;
    seed_fixed_admission_device(&pool).await;
    let device = fixed_admission_device();
    let session_id = derive_inventory_session_uuid(&device.did, device.device_id, &device.jkt, 1);
    let now = whole_second(clock_now(&pool).await);
    let mut random = DeterministicRandom::new(0xD3F1);

    // Seed an already-expired row via the real-machinery statement shapes,
    // keyed by the deterministic session identity. Timestamps are set at
    // INSERT time; immutable durable rows are never edited to manufacture
    // expiry.
    let session = seed_session_via_create_shape(
        &pool,
        &fence,
        &device,
        session_id,
        now - Duration::minutes(30),
        now - Duration::minutes(15),
        &mut random,
        &[],
        &[],
        &[],
    )
    .await;

    // The same-identity initial-page request now FAILS CLOSED at the fence
    // (the loader seam's captured_at is older than the 15-minute temporal
    // bound of `verify_inventory_fence`).
    assert_eq!(
        chat_protocol::inventory_bridge::verify_session_fence_for_test(&pool, session_id).await,
        chat_protocol::inventory_bridge::FenceOutcome::Rejected,
        "the expired session's initial-page request fails closed"
    );

    // No bytes and no *_consumed transition: no receipt row was ever served
    // for this session and the consumed proofs stayed false/NULL.
    let (consumed, consumed_at): (bool, Option<DateTime<Utc>>) = sqlx::query_as(
        "SELECT conversations_consumed, conversations_consumed_at \
           FROM chat.inventory_sessions WHERE inventory_session_id = $1",
    )
    .bind(session_id)
    .fetch_one(&pool)
    .await
    .expect("the expired row still exists");
    assert!(!consumed, "no *_consumed transition on the failed request");
    assert_eq!(
        consumed_at, None,
        "no consumed instant on the failed request"
    );
    let receipts: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM chat.inventory_page_receipts WHERE inventory_session_id = $1",
    )
    .bind(session_id)
    .fetch_one(&pool)
    .await
    .expect("count receipts");
    assert_eq!(
        receipts, 0,
        "no page bytes were served for the expired session"
    );

    // The serve path itself fails closed at the schema's temporal shape check
    // (`served_at < expires_at` can no longer hold), with zero residue: the
    // unserved receipt is rolled back with the transaction. The row's own
    // expired timestamps are used directly.
    let request = conversations_request(100);
    let mut tx = pool.begin().await.expect("begin expired serve attempt");
    let insert = sqlx::query(
        r#"
        INSERT INTO chat.inventory_page_receipts(
            page_receipt_id, request_cursor_hash, inventory_session_id, domain,
            endpoint_nsid, cursor_format_version, page_limit,
            canonical_filter_sha256, user_did, device_id, jkt, auth_generation,
            protocol_instance_id, cursor_key_id, snapshot_event_position,
            snapshot_event_cursor_sha256, snapshot_retained_floor, after_ordinal,
            created_at, expires_at
        ) VALUES ($1,NULL,$2,'conversations','blue.catbird.chat.getConversations',1,$3,$4,$5,$6,$7,1,$8,$9,$10,$11,$12,NULL,$13,$14)
        "#,
    )
    .bind(Uuid::new_v4())
    .bind(session_id)
    .bind(100_i16)
    .bind(request.canonical_filter_sha256().as_slice())
    .bind(&session.user_did)
    .bind(session.device_id)
    .bind(&session.jkt)
    .bind(fence.protocol_instance_id)
    .bind(&fence.cursor_key_id)
    .bind(session.snapshot_event_position)
    .bind(session.capability_hash.as_slice())
    .bind(session.retained_floor)
    .bind(session.created_at)
    .bind(session.expires_at)
    .execute(&mut *tx)
    .await
    .expect("the unserved receipt shape is still satisfiable (expiry is a served-side bound)");
    let _ = insert;
    let served = sqlx::query(
        r#"
        UPDATE chat.inventory_page_receipts
           SET served_at = $2, first_ordinal = NULL, item_count = 0,
               items_sha256 = $3, has_more = FALSE,
               successor_cursor_hash = NULL, successor_cursor_nonce = NULL,
               successor_cursor_ciphertext = NULL, canonical_response_sha256 = $4
         WHERE inventory_session_id = $1 AND request_cursor_hash IS NULL
        "#,
    )
    .bind(session_id)
    .bind(now)
    .bind(Sha256::digest([]).to_vec())
    .bind([0x42; 32].to_vec())
    .execute(&mut *tx)
    .await;
    assert!(
        served.is_err(),
        "serving the expired session's receipt fails the served_at < expires_at \
         temporal bound"
    );
    tx.rollback()
        .await
        .expect("rollback the failed serve attempt");
    let receipts: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM chat.inventory_page_receipts WHERE inventory_session_id = $1",
    )
    .bind(session_id)
    .fetch_one(&pool)
    .await
    .expect("count receipts");
    assert_eq!(receipts, 0, "the failed serve left zero receipt residue");
}

/// (b) After the expired session is reclaimed via the sealed GC function
/// `chat.gc_expired_inventory_sessions(batch_limit)` (called directly), a NEW
/// session IS creatable under the same deterministic identity and is fully
/// functional. The schema's identity-immutable trigger forbids UPDATE/DELETE
/// outside the GC, so reclamation proves the GC path. The session identity is
/// the FIXED B-read device's deterministic identity — the fence bridge
/// authorizes and locks exactly that device — so the fail-closed-before-GC and
/// success-after-GC fence outcomes are asserted end-to-end.
#[tokio::test]
async fn gc_reclaim_of_the_expired_session_permits_a_new_session_under_the_same_identity() {
    // A fresh per-test database: the re-inserted LIVE session under the same
    // deterministic identity cannot be removed by any sanctioned path (it is
    // not expired), so the per-test database guard is the deterministic
    // cleanup that keeps the suite re-runnable.
    let (pool, _guard) = executor_seed::setup().await;
    let fence = ensure_fence(&pool).await;
    seed_fixed_admission_device(&pool).await;
    let device = fixed_admission_device();
    let now = whole_second(clock_now(&pool).await);
    let session_id = derive_inventory_session_uuid(&device.did, device.device_id, &device.jkt, 1);
    let mut random = DeterministicRandom::new(0xD3F2);

    // Seed the session ALREADY EXPIRED (created 30 minutes ago, the exact
    // 15-minute window ending 15 minutes ago).
    let _expired = seed_session_via_create_shape(
        &pool,
        &fence,
        &device,
        session_id,
        now - Duration::minutes(30),
        now - Duration::minutes(15),
        &mut random,
        &[],
        &[],
        &[],
    )
    .await;
    let expired: bool = sqlx::query_scalar(
        "SELECT expires_at <= clock_timestamp() FROM chat.inventory_sessions \
         WHERE inventory_session_id = $1",
    )
    .bind(session_id)
    .fetch_one(&pool)
    .await
    .expect("the already-expired session exists");
    assert!(expired, "the GC fixture is expired before reclamation");

    // Fail closed BEFORE the GC: the same-identity initial-page request is
    // refused at the real B-read fence while the expired row exists (the
    // bridge authorizes and locks the fixed device the identity is bound to).
    assert_eq!(
        chat_protocol::inventory_bridge::verify_session_fence_for_test(&pool, session_id).await,
        chat_protocol::inventory_bridge::FenceOutcome::Rejected,
        "the expired session's initial-page request fails closed before the GC"
    );

    // The identity-immutable trigger forbids UPDATE/DELETE outside the GC: a
    // plain DELETE of the test-owned row is refused.
    let deleted =
        sqlx::query("DELETE FROM chat.inventory_sessions WHERE inventory_session_id = $1")
            .bind(session_id)
            .execute(&pool)
            .await;
    assert!(
        deleted.is_err(),
        "the identity-immutable trigger forbids a plain DELETE outside the GC"
    );

    // The sealed GC reclaims the expired row (children before parents; the
    // GC's session_replication_role switch skips the immutable triggers).
    let removed: i64 = sqlx::query_scalar("SELECT chat.gc_expired_inventory_sessions($1)")
        .bind(100_i32)
        .fetch_one(&pool)
        .await
        .expect("the sealed GC function executes");
    assert!(
        removed >= 1,
        "the GC reclaimed the expired test-owned session"
    );

    // Zero residue: no session, item, receipt, or token-hash residue remains.
    let (sessions, items, receipts): (i64, i64, i64) = sqlx::query_as(
        "SELECT \
            (SELECT count(*) FROM chat.inventory_sessions WHERE inventory_session_id = $1), \
            (SELECT count(*) FROM chat.inventory_conversation_items WHERE inventory_session_id = $1) \
                + (SELECT count(*) FROM chat.inventory_welcome_items WHERE inventory_session_id = $1) \
                + (SELECT count(*) FROM chat.inventory_recovery_items WHERE inventory_session_id = $1), \
            (SELECT count(*) FROM chat.inventory_page_receipts WHERE inventory_session_id = $1)",
    )
    .bind(session_id)
    .fetch_one(&pool)
    .await
    .expect("zero-residue probe");
    assert_eq!(sessions, 0, "the expired session row is gone");
    assert_eq!(items, 0, "no item residue");
    assert_eq!(receipts, 0, "no receipt residue");

    // A NEW session under the SAME deterministic identity is creatable and
    // fully functional: the fence verifies and a page serves + replays.
    let live = seed_session_via_create_shape(
        &pool,
        &fence,
        &device,
        session_id,
        now,
        now + Duration::minutes(15),
        &mut random,
        &[],
        &[],
        &[],
    )
    .await;
    assert_eq!(
        chat_protocol::inventory_bridge::verify_session_fence_for_test(&pool, session_id).await,
        chat_protocol::inventory_bridge::FenceOutcome::Accepted,
        "the new session under the same identity is live and servable"
    );
    let request = conversations_request(100);
    let served_at = {
        let mut tx = pool.begin().await.expect("begin serve");
        let mut random = DeterministicRandom::new(0xD3F3);
        let (served, successor) = serve_page_receipt_seed(
            &mut tx,
            &fence,
            &live,
            "conversations",
            "blue.catbird.chat.getConversations",
            &request,
            None,
            None,
            &[],
            false,
            &mut random,
        )
        .await;
        assert!(successor.is_none(), "the new session's first page is final");
        tx.commit().await.expect("commit the served page");
        served
    };
    let stored = stored_response_sha256(&pool, session_id).await;
    let replayed = reassemble_served_receipt(
        &pool,
        &fence,
        &live,
        &request,
        served_at,
        live.expires_at,
        None,
        0,
        false,
        None,
    )
    .await;
    assert_eq!(
        replayed.sha256, stored,
        "the new session's first page serves and replays byte-identically"
    );
}

// ===========================================================================
// Production-contract source pins (findings round): the SQL statement shapes,
// the response-assembly field order, and the response ceiling duplicated in
// this integration crate are pinned byte-for-byte (modulo whitespace) to the
// actual D-2 production bodies in inventory.rs, so a drift in the production
// SQL/assembly fails this gate instead of silently diverging the replica.
// ===========================================================================

/// The source region between `start_marker` and the next `end_marker`.
fn source_region<'a>(source: &'a str, start_marker: &str, end_marker: &str) -> &'a str {
    let start = source
        .split_once(start_marker)
        .unwrap_or_else(|| panic!("missing production marker: {start_marker}"))
        .1;
    start
        .split_once(end_marker)
        .unwrap_or_else(|| panic!("missing production terminator: {end_marker}"))
        .0
}

/// Collapse all whitespace so the two copies of a SQL statement can be
/// compared byte-for-byte independent of line wrapping and indentation.
fn whitespace_collapsed(text: &str) -> String {
    text.chars().filter(|c| !c.is_whitespace()).collect()
}

#[test]
fn d2_receipt_sql_and_response_shapes_are_source_pinned() {
    let production = include_str!("../src/chat_protocol/repository/inventory.rs");
    let test_source = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/chat_protocol_inventory.rs"
    ));
    let production_flat = whitespace_collapsed(production);

    // (1) The seeded-session INSERT is the production create INSERT, statement
    // for statement (the identity, G7 binding, sealed cursor, and six-proof
    // columns in the exact production order).
    assert_eq!(
        whitespace_collapsed(source_region(
            test_source,
            "INSERT INTO chat.inventory_sessions(",
            "\"#,"
        )),
        whitespace_collapsed(source_region(
            production,
            "INSERT INTO chat.inventory_sessions(",
            "\"#,"
        )),
        "the seeded-session INSERT must be the production create INSERT verbatim"
    );

    // (2) The unserved page-receipt INSERT is the production
    // `insert_page_receipt_unserved` statement.
    assert_eq!(
        whitespace_collapsed(source_region(
            test_source,
            "INSERT INTO chat.inventory_page_receipts(",
            "\"#,"
        )),
        whitespace_collapsed(source_region(
            production,
            "INSERT INTO chat.inventory_page_receipts(",
            "\"#,"
        )),
        "the seeded unserved-receipt INSERT must be the production statement verbatim"
    );

    // (3) The served-receipt UPDATE is the production `serve_page_receipt_row`
    // statement (the exact page evidence + successor seal columns).
    assert_eq!(
        whitespace_collapsed(source_region(
            test_source,
            "UPDATE chat.inventory_page_receipts",
            "\"#,"
        )),
        whitespace_collapsed(source_region(
            production,
            "UPDATE chat.inventory_page_receipts",
            "\"#,"
        )),
        "the seeded served-receipt UPDATE must be the production statement verbatim"
    );

    // (4) The `*_consumed` CAS UPDATE is the production `consume_final_page`
    // statement (per-domain column names, static strings). The statement is a
    // `format!` argument, so it terminates with the string close + `);`.
    assert_eq!(
        whitespace_collapsed(source_region(
            test_source,
            "UPDATE chat.inventory_sessions SET {consumed_column} = TRUE",
            "\n    );"
        )),
        whitespace_collapsed(source_region(
            production,
            "UPDATE chat.inventory_sessions SET {consumed_column} = TRUE",
            "\n    );"
        )),
        "the seeded consumption CAS must be the production statement verbatim"
    );

    // (5) The retained-page item query the replay reassembly uses is the
    // production `fetch_page_items` predicate, per domain table.
    for table in [
        "inventory_conversation_items",
        "inventory_welcome_items",
        "inventory_recovery_items",
    ] {
        let replica_predicate = format!(
            "FROM chat.{table} WHERE inventory_session_id = $1 AND ordinal > $2 ORDER BY ordinal LIMIT $3"
        );
        assert!(
            production_flat.contains(&whitespace_collapsed(&replica_predicate)),
            "the replay item query for {table} must match the production fetch predicate"
        );
    }

    // (6) The deterministic response assembly is the production
    // `assemble_inventory_page_response` field order: the generated `*Output`
    // wrapper shape (`hasMore`, `inventorySessionId`, `items`, optional
    // `nextPageCursor`, `snapshotEventCursor`, `snapshotExpiresAt`).
    let assembly_body = source_region(production, "fn assemble_inventory_page_response(", "\n}\n");
    // The production body spells each JSON fragment as `b"{\"hasMore\":"`, so
    // the pinned fragments carry the source-level backslash-quote escapes.
    let fragments = [
        "{\\\"hasMore\\\":",
        ",\\\"inventorySessionId\\\":\\\"",
        "\\\",\\\"items\\\":[",
        ",\\\"nextPageCursor\\\":\\\"",
        ",\\\"snapshotEventCursor\\\":\\\"",
        ",\\\"snapshotExpiresAt\\\":\\\"",
    ];
    let mut position = 0usize;
    for fragment in fragments {
        position = assembly_body[position..]
            .find(fragment)
            .unwrap_or_else(|| panic!("production assembly missing field fragment: {fragment}"))
            + position
            + fragment.len();
    }

    // (7) The duplicated response ceiling constant is the production constant.
    assert!(
        production.contains("const MAX_RESPONSE_BYTES: usize = 16 * 1024 * 1024 + 64 * 1024;"),
        "the duplicated 16 MiB + 64 KiB response ceiling is the production constant"
    );
    // And the production assembly fails closed above it.
    assert!(assembly_body.contains("if out.len() > MAX_RESPONSE_BYTES"));
    assert!(assembly_body.contains("return Err(InventoryRepositoryError::InvalidMaterialization)"));
}


// ===========================================================================
// HTTP-level authenticated acceptance (server/cutover Task 1).
// ===========================================================================

use common::http_acceptance as http;

#[tokio::test]
async fn http_get_devices_accepts_exact_device_and_rejects_did_device_and_jkt_drift() {
    let pool = common::chat_protocol::setup_chat_protocol_db(4).await;
    http::ensure_fence(&pool).await;
    let device = http::seed_device(&pool).await;
    let router = http::router(pool.clone()).await;
    let query = format!("?userDids={}", device.did);

    let (status, body) = http::send(
        router.clone(),
        http::unsigned_request(&device, "blue.catbird.chat.getDevices", "GET", &query),
    )
    .await;
    assert_eq!(status, axum::http::StatusCode::OK, "valid exact-device read: {body}");

    let wrong_did = http::random_did();
    let (status, body) = http::send(
        router.clone(),
        http::unsigned_request_as(
            &device, "blue.catbird.chat.getDevices", "GET", &query,
            &wrong_did, device.device_id, &device.jkt, &device.signing, &device.jwk,
        ),
    )
    .await;
    assert_eq!(status, axum::http::StatusCode::UNAUTHORIZED);
    assert_eq!(body["error"], "DeviceNotRegistered");

    let (status, body) = http::send(
        router.clone(),
        http::unsigned_request_as(
            &device, "blue.catbird.chat.getDevices", "GET", &query,
            &device.did, Uuid::new_v4(), &device.jkt, &device.signing, &device.jwk,
        ),
    )
    .await;
    assert_eq!(status, axum::http::StatusCode::UNAUTHORIZED);
    assert_eq!(body["error"], "DeviceNotRegistered");

    let wrong_proof = http::random_p256();
    let wrong_jwk = http::public_jwk(&wrong_proof);
    let wrong_jkt = http::jwk_thumbprint(&wrong_jwk);
    let (status, body) = http::send(
        router,
        http::unsigned_request_as(
            &device, "blue.catbird.chat.getDevices", "GET", &query,
            &device.did, device.device_id, &wrong_jkt, &wrong_proof, &wrong_jwk,
        ),
    )
    .await;
    assert_eq!(status, axum::http::StatusCode::UNAUTHORIZED);
    assert_eq!(body["error"], "InvalidDPoP");
}