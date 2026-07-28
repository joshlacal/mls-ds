//! Repository-boundary tests for clean chat authentication.
//!
//! Database cases remain ignored until the schema owner clears the dedicated
//! `catbird_chat_protocol_test_20260722` database gate. They stay `#[ignore]`d
//! (not de-ignored into the standard whole-suite gate) because each seeds
//! replay/idempotency rows that collide on a shared, never-truncated database;
//! they need a pristine schema per run, which the standard harness does not
//! provide. Run them explicitly against a freshly-migrated dedicated database:
//!   TEST_DATABASE_URL=postgres://localhost/catbird_chat_protocol_test_20260722 \
//!   cargo test --test chat_protocol_auth_repository -- --ignored --test-threads=1

mod common;

#[allow(dead_code)]
#[path = "../src/chat_protocol/cursor.rs"]
mod cursor;
#[allow(dead_code)]
#[path = "../src/chat_protocol/dpop.rs"]
mod dpop;
#[allow(dead_code)]
#[path = "../src/chat_protocol/model.rs"]
mod model;
#[allow(dead_code)]
#[path = "../src/chat_protocol/relationship_policy.rs"]
mod relationship_policy_source;
#[allow(dead_code)]
mod snapshot {
    pub use catbird_server::chat_protocol::snapshot::*;
}
#[allow(dead_code)]
#[path = "../src/chat_protocol/repository/mod.rs"]
mod repository;
#[allow(dead_code)]
#[path = "../src/chat_protocol/transcript.rs"]
mod transcript;
#[allow(dead_code)]
#[path = "../src/chat_protocol/validation.rs"]
mod validation;

// The production repository module now includes Welcome CAS writers that
// consume the nested `crate::chat_protocol` authority types. Mirror the
// production-shaped module graph used by the transition harness so this
// repository-boundary target compiles without weakening production paths.
#[allow(dead_code)]
mod chat_protocol {
    pub mod validation {
        pub use crate::validation::*;
    }
    pub mod transcript {
        pub use crate::transcript::*;
    }
    pub mod snapshot {
        pub use catbird_server::chat_protocol::snapshot::*;
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
    pub mod dpop {
        pub use crate::dpop::*;
    }
    pub mod relationship_policy {
        pub use crate::relationship_policy_source::*;
    }
    pub mod repository {
        pub mod execution_context {
            pub(crate) struct ExecutionContextHydrationProof;
            pub(crate) struct RevocationBatchHydrationProof;
        }
        pub mod auth {
            pub use crate::repository::auth::*;
        }
        pub mod prelude {
            pub use crate::repository::prelude::*;
        }
        pub mod recovery {
            pub use crate::repository::recovery::*;
        }
        pub mod core {
            #![allow(dead_code)]
            include!(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/src/chat_protocol/repository/core.rs"
            ));
        }
        pub mod relationship {
            #![allow(dead_code)]
            include!(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/src/chat_protocol/repository/relationship.rs"
            ));
        }
        pub mod transition {
            pub use crate::repository::transition::*;
        }
        pub mod delivery {
            #![allow(dead_code)]
            include!(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/src/chat_protocol/repository/delivery.rs"
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
}

use base64::{
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
    Engine,
};
use ed25519_dalek::{Signer, SigningKey};
use repository::auth::{
    authorize_enrollment_operation_only, authorize_rebind_operation_only,
    authorize_replenishment_operation_only, authorize_signed_request, authorize_unsigned_request,
    test_arbitrate_business_idempotency, test_recheck_business_authority,
    test_record_completed_idempotency, AuthRepositoryError, AuthorizationOutcome,
    EnrollmentOperationAdmission, RebindOperationAdmission, SignedOperationAdmission,
    TestBusinessIdempotencyOutcome,
};
use repository::key_packages::NewKeyPackage;
use repository::prelude::{self, PreludeError};
use serde_json::json;
use sha2::{Digest, Sha256};
use transcript::{
    decode_and_verify_enrollment_body, decode_canonical_signed_mutation, decode_rebind_bootstrap,
};

const REGISTERED_DID: &str = "did:plc:ewvi7nxzyoun6zhxrhs64oiz";
const REGISTERED_DEVICE: &str = "3b241101-e2bb-4255-8caf-4136c566a962";
const REGISTERED_JKT: &str = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
const REGISTERED_KEY_ID: &str = "If4x36FUomFia_hUBG_SJxt77UtqvkWqWId-9H-XIbk";
const RFC8032_SEED: &str = "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60";
const FIRST_T: &str = "2026-07-22T14:05:09.123Z";
const ENROLLMENT_PACKAGE_REF: [u8; 32] = [7_u8; 32];
const ENROLLMENT_PACKAGE_WRAPPER: [u8; 8] = [7_u8; 8];
const REPLENISHMENT_PACKAGE_REF: [u8; 32] = [11_u8; 32];
const REPLENISHMENT_PACKAGE_WRAPPER: [u8; 8] = [11_u8; 8];
const TEST_PACKAGE_INIT_KEY: [u8; 32] = [19_u8; 32];

fn test_package<'a>(key_package_ref: &'a [u8], wrapper_bytes: &'a [u8]) -> NewKeyPackage<'a> {
    NewKeyPackage {
        key_package_ref,
        wrapper_bytes,
        init_key: &TEST_PACKAGE_INIT_KEY,
        not_before_unix: 1_700_000_000,
        not_after_unix: 2_000_000_000,
    }
}

fn registered_signing_key() -> SigningKey {
    let bytes: [u8; 32] = hex::decode(RFC8032_SEED).unwrap().try_into().unwrap();
    SigningKey::from_bytes(&bytes)
}

struct DeviceFixture {
    device_id: uuid::Uuid,
    dpop_jkt: String,
    signing_key: SigningKey,
    key_id: String,
}

impl DeviceFixture {
    fn fresh() -> Self {
        let seed: [u8; 32] = Sha256::digest(uuid::Uuid::new_v4().as_bytes()).into();
        let signing_key = SigningKey::from_bytes(&seed);
        let key_id = validation::ed25519_key_id(signing_key.verifying_key().as_bytes())
            .unwrap()
            .as_str()
            .to_owned();
        let dpop_jkt = URL_SAFE_NO_PAD.encode(Sha256::digest(uuid::Uuid::new_v4().as_bytes()));
        Self {
            device_id: uuid::Uuid::new_v4(),
            dpop_jkt,
            signing_key,
            key_id,
        }
    }
}

fn random_proof_jti() -> [u8; 12] {
    uuid::Uuid::new_v4().as_bytes()[..12]
        .try_into()
        .expect("UUID prefix has the fixed proof-JTI length")
}

async fn setup_auth_repository_db(max_connections: u32) -> sqlx::PgPool {
    let pool = common::chat_protocol::setup_chat_protocol_db(max_connections).await;
    sqlx::query(
        r#"
        DO $$
        DECLARE
            table_list text;
        BEGIN
            SELECT string_agg(format('%I.%I', schemaname, tablename), ', ')
              INTO table_list
              FROM pg_tables
             WHERE schemaname = 'chat';
            IF table_list IS NOT NULL THEN
                EXECUTE 'TRUNCATE TABLE ' || table_list || ' RESTART IDENTITY CASCADE';
            END IF;
        END
        $$;
        "#,
    )
    .execute(&pool)
    .await
    .expect("reset the exclusive clean-chat test schema before an auth repository case");
    pool
}

fn signed_blob_deletion(operation_id: uuid::Uuid, blob_id: uuid::Uuid, signed_at: &str) -> Vec<u8> {
    let body = json!({
        "$type": "blue.catbird.chat.defs#blobDeletionBody",
        "signatureDomain": "CATBIRD-CHAT-BLOB-DELETE\u{0000}",
        "blobId": blob_id,
        "actorDid": REGISTERED_DID,
        "actorDeviceId": REGISTERED_DEVICE,
        "keyId": REGISTERED_KEY_ID,
        "authGeneration": 1,
        "idempotencyKey": operation_id,
        "signedAt": signed_at,
    });
    sign_exact_body(body)
}

fn signed_replenishment(operation_id: uuid::Uuid, signed_at: &str) -> Vec<u8> {
    let package_bytes = [11_u8; 8];
    let body = json!({
        "$type": "blue.catbird.chat.defs#keyPackageReplenishmentBody",
        "signatureDomain": "CATBIRD-CHAT-DEVICE-REPLENISH\u{0000}",
        "actorDid": REGISTERED_DID,
        "actorDeviceId": REGISTERED_DEVICE,
        "authGeneration": 1,
        "dpopJkt": REGISTERED_JKT,
        "keyId": REGISTERED_KEY_ID,
        "keyPackages": [{
            "framing": "mlsMessage",
            "contentType": "keyPackage",
            "bytes": STANDARD.encode(package_bytes),
            "sha256": STANDARD.encode(Sha256::digest(package_bytes)),
            "keyPackageRef": STANDARD.encode([11_u8; 32]),
        }],
        "signaturePublicKey": STANDARD.encode(registered_signing_key().verifying_key().as_bytes()),
        "idempotencyKey": operation_id,
        "signedAt": signed_at,
    });
    sign_exact_body(body)
}

async fn replenishment_admission(
    pool: &sqlx::PgPool,
    raw: &[u8],
    trusted_at: &str,
) -> SignedOperationAdmission {
    authorize_replenishment_operation_only(
        pool,
        dpop::repository_test_evidence::ordinary_registered_device(
            uuid::Uuid::new_v4(),
            random_proof_jti(),
            "blue.catbird.chat.replenishKeyPackages",
            trusted_at,
        ),
        decode_canonical_signed_mutation(raw).unwrap(),
    )
    .await
    .unwrap()
}

fn sign_exact_body(body: serde_json::Value) -> Vec<u8> {
    sign_exact_body_with_key(body, &registered_signing_key())
}

fn sign_exact_body_with_key(body: serde_json::Value, signing_key: &SigningKey) -> Vec<u8> {
    let placeholder = serde_json::to_vec(&json!({
        "body": body.clone(),
        "signature": STANDARD.encode([0_u8; 64]),
    }))
    .unwrap();
    let canonical = decode_canonical_signed_mutation(&placeholder).unwrap();
    let signature = signing_key.sign(canonical.transcript_bytes());
    serde_json::to_vec(&json!({
        "body": body,
        "signature": STANDARD.encode(signature.to_bytes()),
    }))
    .unwrap()
}

fn signed_blob_deletion_for(
    fixture: &DeviceFixture,
    operation_id: uuid::Uuid,
    blob_id: uuid::Uuid,
    signed_at: &str,
) -> Vec<u8> {
    let body = json!({
        "$type": "blue.catbird.chat.defs#blobDeletionBody",
        "signatureDomain": "CATBIRD-CHAT-BLOB-DELETE\u{0000}",
        "blobId": blob_id,
        "actorDid": REGISTERED_DID,
        "actorDeviceId": fixture.device_id,
        "keyId": fixture.key_id,
        "authGeneration": 1,
        "idempotencyKey": operation_id,
        "signedAt": signed_at,
    });
    sign_exact_body_with_key(body, &fixture.signing_key)
}

fn ordinary_evidence(
    fixture: &DeviceFixture,
    endpoint: &str,
    trusted_at: &str,
    dpop_jkt: &str,
) -> dpop::PreReplayCryptographicVerification {
    dpop::repository_test_evidence::ordinary_device_with_binding(
        uuid::Uuid::new_v4(),
        random_proof_jti(),
        endpoint,
        trusted_at,
        REGISTERED_DID,
        fixture.device_id,
        dpop_jkt,
    )
}

async fn seed_device(pool: &sqlx::PgPool, fixture: &DeviceFixture) {
    sqlx::query(
        "INSERT INTO chat.principals(user_did, created_at) VALUES($1,$2::timestamptz) ON CONFLICT DO NOTHING",
    )
    .bind(REGISTERED_DID)
    .bind(FIRST_T)
    .execute(pool)
    .await
    .unwrap();
    sqlx::query(
        r#"
        INSERT INTO chat.devices (
            user_did, device_id, device_name, status, dpop_jkt,
            auth_generation, capabilities, created_at, updated_at
        ) VALUES ($1,$2,$3,'active',$4,1,chat.protocol_capabilities(),
                  $5::timestamptz,$5::timestamptz)
        "#,
    )
    .bind(REGISTERED_DID)
    .bind(fixture.device_id)
    .bind("repository-replay-test-device")
    .bind(&fixture.dpop_jkt)
    .bind(FIRST_T)
    .execute(pool)
    .await
    .unwrap();
    sqlx::query(
        r#"
        INSERT INTO chat.device_keys (
            user_did, device_id, key_id, signing_public_key,
            enrollment_auth_generation, created_at
        ) VALUES ($1,$2,$3,$4,1,$5::timestamptz)
        "#,
    )
    .bind(REGISTERED_DID)
    .bind(fixture.device_id)
    .bind(&fixture.key_id)
    .bind(fixture.signing_key.verifying_key().as_bytes().as_slice())
    .bind(FIRST_T)
    .execute(pool)
    .await
    .unwrap();
}

async fn complete_blob_deletion(
    pool: &sqlx::PgPool,
    fixture: &DeviceFixture,
    raw: &[u8],
    response: &[u8],
) {
    let authority = match authorize_signed_request(
        pool,
        ordinary_evidence(
            fixture,
            "blue.catbird.chat.deleteBlob",
            FIRST_T,
            &fixture.dpop_jkt,
        ),
        decode_canonical_signed_mutation(raw).unwrap(),
    )
    .await
    .unwrap()
    {
        AuthorizationOutcome::FirstExecution(authority) => authority,
        AuthorizationOutcome::CompletedReplay(_) => panic!("fresh operation replayed"),
    };
    let mut transaction = pool.begin().await.unwrap();
    let TestBusinessIdempotencyOutcome::FirstExecution(idempotency_guard) =
        test_arbitrate_business_idempotency(&mut transaction, &authority)
            .await
            .unwrap()
    else {
        panic!("fresh operation completed before execution");
    };
    let _authority_guard = test_recheck_business_authority(&mut transaction, &authority)
        .await
        .unwrap();
    test_record_completed_idempotency(
        &mut transaction,
        &authority,
        &idempotency_guard,
        200,
        response,
        None,
    )
    .await
    .unwrap();
    transaction.commit().await.unwrap();
}

async fn insert_completed_delete_fixture(
    pool: &sqlx::PgPool,
    operation_id: uuid::Uuid,
    raw: &[u8],
    response: &[u8],
) {
    let canonical = decode_canonical_signed_mutation(raw).unwrap();
    let response_sha256: [u8; 32] = Sha256::digest(response).into();
    sqlx::query(
        r#"
        INSERT INTO chat.idempotency_records (
            principal_did, endpoint_nsid, operation_id, request_digest,
            accepted_request_bytes, signing_transcript_bytes, signature,
            completed_status, response_bytes, response_sha256, completed_at
        ) VALUES ($1,'blue.catbird.chat.deleteBlob',$2,$3,$4,$5,$6,200,$7,$8,$9::timestamptz)
        "#,
    )
    .bind(REGISTERED_DID)
    .bind(operation_id)
    .bind(canonical.request_digest().as_slice())
    .bind(raw)
    .bind(canonical.transcript_bytes())
    .bind(canonical.signature().as_slice())
    .bind(response)
    .bind(response_sha256.as_slice())
    .bind(FIRST_T)
    .execute(pool)
    .await
    .unwrap();
}

async fn insert_completed_bootstrap_fixture(
    pool: &sqlx::PgPool,
    endpoint: &str,
    operation_id: uuid::Uuid,
    raw: &[u8],
    historical_jkt: Option<&str>,
    current_jkt: Option<&str>,
    response: &[u8],
) {
    sqlx::query(
        "INSERT INTO chat.principals(user_did, created_at) VALUES($1,$2::timestamptz) ON CONFLICT DO NOTHING",
    )
    .bind(REGISTERED_DID)
    .bind(FIRST_T)
    .execute(pool)
    .await
    .unwrap();
    let canonical = decode_canonical_signed_mutation(raw).unwrap();
    let response_sha256: [u8; 32] = Sha256::digest(response).into();
    sqlx::query(
        r#"
        INSERT INTO chat.idempotency_records (
            principal_did, endpoint_nsid, operation_id, request_digest,
            accepted_request_bytes, signing_transcript_bytes, signature,
            completed_status, response_bytes, response_sha256,
            historical_jkt, current_jkt, completed_at
        ) VALUES ($1,$2,$3,$4,$5,$6,$7,200,$8,$9,$10,$11,$12::timestamptz)
        "#,
    )
    .bind(REGISTERED_DID)
    .bind(endpoint)
    .bind(operation_id)
    .bind(canonical.request_digest().as_slice())
    .bind(raw)
    .bind(canonical.transcript_bytes())
    .bind(canonical.signature().as_slice())
    .bind(response)
    .bind(response_sha256.as_slice())
    .bind(historical_jkt)
    .bind(current_jkt)
    .bind(FIRST_T)
    .execute(pool)
    .await
    .unwrap();
}

async fn revoke_fixture(pool: &sqlx::PgPool, fixture: &DeviceFixture) {
    let revocation_id = uuid::Uuid::new_v4();
    let accepted_at = "2026-07-22T14:06:09.123Z";
    let accepted_request_bytes = b"repository-test-revocation";
    let signing_transcript_bytes = b"repository-test-revocation-transcript";
    let request_digest: [u8; 32] = Sha256::digest(signing_transcript_bytes).into();
    let signature = [3_u8; 64];
    let response = br#"{"revoked":true}"#;
    let response_sha256: [u8; 32] = Sha256::digest(response).into();
    let mut transaction = pool.begin().await.unwrap();
    sqlx::query(
        r#"
        INSERT INTO chat.idempotency_records (
            principal_did, endpoint_nsid, operation_id, request_digest,
            accepted_request_bytes, signing_transcript_bytes, signature,
            completed_status, response_bytes, response_sha256,
            historical_jkt, completed_at
        ) VALUES (
            $1,'blue.catbird.chat.revokeDevice',$2,$3,$4,$5,$6,
            200,$7,$8,$9,$10::timestamptz
        )
        "#,
    )
    .bind(REGISTERED_DID)
    .bind(revocation_id)
    .bind(request_digest.as_slice())
    .bind(accepted_request_bytes.as_slice())
    .bind(signing_transcript_bytes.as_slice())
    .bind(signature.as_slice())
    .bind(response.as_slice())
    .bind(response_sha256.as_slice())
    .bind(&fixture.dpop_jkt)
    .bind(accepted_at)
    .execute(&mut *transaction)
    .await
    .unwrap();
    sqlx::query(
        r#"
        INSERT INTO chat.device_revocations (
            revocation_id, actor_did, actor_device_id, actor_key_id,
            actor_auth_generation, target_did, target_device_id,
            target_auth_generation, accepted_request_bytes,
            signing_transcript_bytes, request_digest, signature,
            signed_at, accepted_at
        ) VALUES ($1,$2,$3,$4,1,$2,$3,1,$5,$6,$7,$8,$9::timestamptz,$9::timestamptz)
        "#,
    )
    .bind(revocation_id)
    .bind(REGISTERED_DID)
    .bind(fixture.device_id)
    .bind(&fixture.key_id)
    .bind(accepted_request_bytes.as_slice())
    .bind(signing_transcript_bytes.as_slice())
    .bind(request_digest.as_slice())
    .bind(signature.as_slice())
    .bind(accepted_at)
    .execute(&mut *transaction)
    .await
    .unwrap();
    sqlx::query(
        r#"
        UPDATE chat.devices
           SET status = 'revoked', updated_at = $4::timestamptz,
               revoked_at = $4::timestamptz, revocation_id = $3
         WHERE user_did = $1 AND device_id = $2
        "#,
    )
    .bind(REGISTERED_DID)
    .bind(fixture.device_id)
    .bind(revocation_id)
    .bind(accepted_at)
    .execute(&mut *transaction)
    .await
    .unwrap();
    sqlx::query(
        r#"
        UPDATE chat.device_keys
           SET revoked_at = $4::timestamptz, revocation_id = $3
         WHERE user_did = $1 AND device_id = $2
        "#,
    )
    .bind(REGISTERED_DID)
    .bind(fixture.device_id)
    .bind(revocation_id)
    .bind(accepted_at)
    .execute(&mut *transaction)
    .await
    .unwrap();
    transaction.commit().await.unwrap();
}

fn enrollment_body(
    fixture: &DeviceFixture,
    operation_id: uuid::Uuid,
    device_name: &str,
    signed_at: &str,
) -> Vec<u8> {
    let package_bytes = [7_u8; 8];
    let body = json!({
        "$type": "blue.catbird.chat.defs#deviceEnrollmentBody",
        "signatureDomain": "CATBIRD-CHAT-DEVICE-ENROLL\u{0000}",
        "actorDid": REGISTERED_DID,
        "deviceId": fixture.device_id,
        "deviceName": device_name,
        "keyId": fixture.key_id,
        "signaturePublicKey": STANDARD.encode(fixture.signing_key.verifying_key().as_bytes()),
        "dpopJkt": fixture.dpop_jkt,
        "expectedAuthGeneration": 0,
        "capability": {
            "protocolVersion": "1",
            "mlsVersion": "1.0",
            "cipherSuite": "MLS_256_XWING_CHACHA20POLY1305_SHA256_Ed25519",
            "credentialType": "basic",
            "addByValue": "supported",
            "updatePath": "supported",
            "removeByValue": "supported",
            "ratchetTreeGroupInfo": "supported",
            "externalPubGroupInfo": "presentButExternalCommitsForbidden",
            "applicationFrameProfile": "dagCborApplication1",
            "controlProfile": "publicGroup1",
            "attachmentProfile": "aes256GcmBlob1",
            "metadataProfile": "exporterAes256Gcm1",
            "typingProfile": "signedClearEphemeral1"
        },
        "keyPackages": [{
            "framing": "mlsMessage",
            "contentType": "keyPackage",
            "bytes": STANDARD.encode(package_bytes),
            "sha256": STANDARD.encode(Sha256::digest(package_bytes)),
            "keyPackageRef": STANDARD.encode([7_u8; 32]),
        }],
        "idempotencyKey": operation_id,
        "signedAt": signed_at,
    });
    sign_exact_body_with_key(body, &fixture.signing_key)
}

fn enrollment_evidence(
    raw: &[u8],
    token_jti: uuid::Uuid,
    proof_jti: [u8; 12],
    auth_txn: uuid::Uuid,
    trusted_at: &str,
) -> dpop::PreReplayCryptographicVerification {
    dpop::repository_test_evidence::enrollment_with_replay(
        decode_and_verify_enrollment_body(raw).unwrap(),
        token_jti,
        proof_jti,
        auth_txn,
        trusted_at,
    )
}

fn rebind_body(
    fixture: &DeviceFixture,
    operation_id: uuid::Uuid,
    current_jkt: &str,
    new_jkt: &str,
    expected_auth_generation: u64,
    signed_at: &str,
) -> Vec<u8> {
    let body = json!({
        "$type": "blue.catbird.chat.defs#deviceAuthenticationRebindBody",
        "signatureDomain": "CATBIRD-CHAT-DEVICE-REBIND\u{0000}",
        "actorDid": REGISTERED_DID,
        "actorDeviceId": fixture.device_id,
        "keyId": fixture.key_id,
        "expectedAuthGeneration": expected_auth_generation,
        "currentDpopJkt": current_jkt,
        "newDpopJkt": new_jkt,
        "idempotencyKey": operation_id,
        "signedAt": signed_at,
    });
    sign_exact_body_with_key(body, &fixture.signing_key)
}

fn rebind_evidence(
    raw: &[u8],
    token_jti: uuid::Uuid,
    proof_jti: [u8; 12],
    trusted_at: &str,
) -> dpop::PreReplayCryptographicVerification {
    dpop::repository_test_evidence::rebind_with_replay(
        decode_rebind_bootstrap(raw).unwrap(),
        token_jti,
        proof_jti,
        trusted_at,
    )
}

fn first_authority(outcome: AuthorizationOutcome) -> dpop::VerifiedChatDeviceRequest {
    match outcome {
        AuthorizationOutcome::FirstExecution(authority) => authority,
        AuthorizationOutcome::CompletedReplay(_) => panic!("fresh request replayed"),
    }
}

async fn prepare_enrollment_first(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    admission: EnrollmentOperationAdmission,
) -> Result<repository::prelude::PreparedEnrollmentBootstrapPrelude, PreludeError> {
    match prelude::prepare_enrollment_operation(transaction, admission).await? {
        prelude::PreparedEnrollmentOperation::First(prepared) => Ok(prepared),
        prelude::PreparedEnrollmentOperation::Replay(_) => {
            panic!("fresh enrollment unexpectedly replayed")
        }
    }
}

async fn prepare_rebind_first(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    admission: RebindOperationAdmission,
) -> Result<repository::prelude::PreparedRebindBootstrapPrelude, PreludeError> {
    match prelude::prepare_rebind_operation(transaction, admission).await? {
        prelude::PreparedRebindOperation::First(prepared) => Ok(prepared),
        prelude::PreparedRebindOperation::Replay(_) => {
            panic!("fresh rebind unexpectedly replayed")
        }
    }
}

async fn persist_and_complete_enrollment(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    admission: EnrollmentOperationAdmission,
    status: i32,
    response: &[u8],
) -> Result<(), PreludeError> {
    let prepared = prepare_enrollment_first(transaction, admission).await?;
    {
        let effect = prepared.effect_authority();
        prelude::persist_enrollment_bootstrap_effects(transaction, &effect).await?;
        prelude::publish_enrollment_key_packages(
            transaction,
            &effect,
            &[test_package(
                &ENROLLMENT_PACKAGE_REF,
                &ENROLLMENT_PACKAGE_WRAPPER,
            )],
        )
        .await
        .map_err(|_| PreludeError::ClaimIntegrity)?;
    }
    prelude::complete_enrollment_bootstrap_operation(
        transaction,
        prepared.into_completion_guard(),
        status,
        response,
        None,
    )
    .await
}

async fn persist_and_complete_rebind(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    admission: RebindOperationAdmission,
    status: i32,
    response: &[u8],
) -> Result<(), PreludeError> {
    let prepared = prepare_rebind_first(transaction, admission).await?;
    {
        let effect = prepared.effect_authority();
        prelude::persist_rebind_bootstrap_effects(transaction, &effect).await?;
    }
    prelude::complete_rebind_bootstrap_operation(
        transaction,
        prepared.into_completion_guard(),
        status,
        response,
        None,
    )
    .await
}

async fn validate_enrollment_replay(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    admission: EnrollmentOperationAdmission,
) -> Result<repository::auth::CompletedIdempotentResponse, PreludeError> {
    match prelude::prepare_enrollment_operation(transaction, admission).await? {
        prelude::PreparedEnrollmentOperation::Replay(response) => Ok(response),
        prelude::PreparedEnrollmentOperation::First(_) => {
            panic!("completed enrollment unexpectedly executed")
        }
    }
}

async fn validate_rebind_replay(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    admission: RebindOperationAdmission,
) -> Result<repository::auth::CompletedIdempotentResponse, PreludeError> {
    match prelude::prepare_rebind_operation(transaction, admission).await? {
        prelude::PreparedRebindOperation::Replay(response) => Ok(response),
        prelude::PreparedRebindOperation::First(_) => {
            panic!("completed rebind unexpectedly executed")
        }
    }
}

async fn seed_registered_device(pool: &sqlx::PgPool) {
    let public_key = registered_signing_key().verifying_key().to_bytes();
    sqlx::query(
        "INSERT INTO chat.principals(user_did, created_at) VALUES($1,$2::timestamptz) ON CONFLICT DO NOTHING",
    )
        .bind(REGISTERED_DID)
        .bind(FIRST_T)
        .execute(pool)
        .await
        .unwrap();
    sqlx::query(
        r#"
        INSERT INTO chat.devices (
            user_did, device_id, device_name, status, dpop_jkt,
            auth_generation, capabilities, created_at, updated_at
        ) VALUES ($1,$2,$3,'active',$4,1,chat.protocol_capabilities(),
                  $5::timestamptz,$5::timestamptz)
        ON CONFLICT (user_did, device_id) DO NOTHING
        "#,
    )
    .bind(REGISTERED_DID)
    .bind(uuid::Uuid::parse_str(REGISTERED_DEVICE).unwrap())
    .bind("repository-test-device")
    .bind(REGISTERED_JKT)
    .bind(FIRST_T)
    .execute(pool)
    .await
    .unwrap();
    sqlx::query(
        r#"
        INSERT INTO chat.device_keys (
            user_did, device_id, key_id, signing_public_key,
            enrollment_auth_generation, created_at
        ) VALUES ($1,$2,$3,$4,1,$5::timestamptz)
        ON CONFLICT (user_did, device_id) DO NOTHING
        "#,
    )
    .bind(REGISTERED_DID)
    .bind(uuid::Uuid::parse_str(REGISTERED_DEVICE).unwrap())
    .bind(REGISTERED_KEY_ID)
    .bind(public_key.as_slice())
    .bind(FIRST_T)
    .execute(pool)
    .await
    .unwrap();
}

#[test]
fn final_authority_constructor_requires_the_concrete_repository_receipt() {
    let constructor: fn(
        dpop::PreReplayCryptographicVerification,
        repository::auth::RepositoryAuthorityReceipt,
    ) -> dpop::VerifiedChatDeviceRequest = dpop::mint_unsigned_repository_authority;
    let _ = constructor;
}

#[tokio::test]
#[ignore = "schema-clear gate has not been granted"]
async fn valid_replay_evidence_is_burned_even_when_device_lookup_fails() {
    let pool = setup_auth_repository_db(2).await;
    let token_jti = uuid::Uuid::new_v4();
    let proof_jti = random_proof_jti();
    let evidence =
        dpop::repository_test_evidence::ordinary_missing_device_with_replay(token_jti, proof_jti);

    let error = authorize_unsigned_request(&pool, evidence)
        .await
        .unwrap_err();
    assert!(
        matches!(error, AuthRepositoryError::DeviceNotRegistered),
        "unexpected missing-device authorization error: {error:?}"
    );

    let burned: i64 = sqlx::query_scalar(
        r#"
        SELECT count(*) FROM chat.dpop_replays
        WHERE (replay_namespace = 'token' AND token_jti = $1)
           OR (replay_namespace = 'proof' AND proof_jti_bytes = $2)
        "#,
    )
    .bind(token_jti)
    .bind(proof_jti.as_slice())
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(burned, 2, "semantic denial rolled back replay evidence");

    let conflicting_proof_jti = random_proof_jti();
    let conflicting_set = dpop::repository_test_evidence::ordinary_missing_device_with_replay(
        token_jti,
        conflicting_proof_jti,
    );
    let error = authorize_unsigned_request(&pool, conflicting_set)
        .await
        .unwrap_err();
    assert!(matches!(error, AuthRepositoryError::ReplayDetected));
    let partial_new_proof: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM chat.dpop_replays WHERE replay_namespace = 'proof' AND proof_jti_bytes = $1",
    )
    .bind(conflicting_proof_jti.as_slice())
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(
        partial_new_proof, 0,
        "unique conflict left a partial proof replay row"
    );
}

#[tokio::test]
#[ignore = "schema-clear gate has not been granted"]
async fn replay_audit_commits_independently_of_business_rollback() {
    let pool = setup_auth_repository_db(2).await;
    seed_registered_device(&pool).await;
    let token_jti = uuid::Uuid::new_v4();
    let proof_jti = random_proof_jti();
    let operation_id = uuid::Uuid::new_v4();
    let raw = signed_blob_deletion(operation_id, uuid::Uuid::new_v4(), FIRST_T);
    let canonical = decode_canonical_signed_mutation(&raw).unwrap();
    let evidence = dpop::repository_test_evidence::ordinary_registered_device(
        token_jti,
        proof_jti,
        "blue.catbird.chat.deleteBlob",
        FIRST_T,
    );
    let authority = match authorize_signed_request(&pool, evidence, canonical)
        .await
        .unwrap()
    {
        AuthorizationOutcome::FirstExecution(authority) => authority,
        AuthorizationOutcome::CompletedReplay(_) => panic!("fresh operation replayed"),
    };

    let mut business = pool.begin().await.unwrap();
    let idempotency = test_arbitrate_business_idempotency(&mut business, &authority)
        .await
        .unwrap();
    let TestBusinessIdempotencyOutcome::FirstExecution(idempotency_guard) = idempotency else {
        panic!("fresh operation completed before its business transaction");
    };
    let device_guard = test_recheck_business_authority(&mut business, &authority)
        .await
        .unwrap();
    let current_transaction_id: String = sqlx::query_scalar("SELECT txid_current()::text")
        .fetch_one(&mut *business)
        .await
        .unwrap();
    assert_eq!(device_guard.transaction_id(), current_transaction_id);
    test_record_completed_idempotency(
        &mut business,
        &authority,
        &idempotency_guard,
        200,
        br#"{"ok":true}"#,
        None,
    )
    .await
    .unwrap();
    business.rollback().await.unwrap();

    let replay_count: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM chat.dpop_replays WHERE token_jti = $1 OR proof_jti_bytes = $2",
    )
    .bind(token_jti)
    .bind(proof_jti.as_slice())
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(replay_count, 2);
    let completion_count: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM chat.idempotency_records WHERE principal_did = $1 AND endpoint_nsid = $2 AND operation_id = $3",
    )
    .bind(REGISTERED_DID)
    .bind("blue.catbird.chat.deleteBlob")
    .bind(operation_id)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(completion_count, 0);
}

#[tokio::test]
#[ignore = "schema-clear gate has not been granted"]
async fn identical_business_racers_converge_and_exact_replay_bypasses_only_age() {
    let pool = setup_auth_repository_db(4).await;
    seed_registered_device(&pool).await;
    let operation_id = uuid::Uuid::new_v4();
    let raw = signed_blob_deletion(operation_id, uuid::Uuid::new_v4(), FIRST_T);

    let first = authorize_signed_request(
        &pool,
        dpop::repository_test_evidence::ordinary_registered_device(
            uuid::Uuid::new_v4(),
            random_proof_jti(),
            "blue.catbird.chat.deleteBlob",
            FIRST_T,
        ),
        decode_canonical_signed_mutation(&raw).unwrap(),
    )
    .await
    .unwrap();
    let second = authorize_signed_request(
        &pool,
        dpop::repository_test_evidence::ordinary_registered_device(
            uuid::Uuid::new_v4(),
            random_proof_jti(),
            "blue.catbird.chat.deleteBlob",
            FIRST_T,
        ),
        decode_canonical_signed_mutation(&raw).unwrap(),
    )
    .await
    .unwrap();
    let AuthorizationOutcome::FirstExecution(first) = first else {
        panic!("first request unexpectedly replayed");
    };
    let AuthorizationOutcome::FirstExecution(second) = second else {
        panic!("second pre-business request unexpectedly replayed");
    };

    let mut first_tx = pool.begin().await.unwrap();
    let TestBusinessIdempotencyOutcome::FirstExecution(first_guard) =
        test_arbitrate_business_idempotency(&mut first_tx, &first)
            .await
            .unwrap()
    else {
        panic!("first racer did not claim the operation");
    };

    let second_pool = pool.clone();
    let second_task = tokio::spawn(async move {
        let mut second_tx = second_pool.begin().await.unwrap();
        let result = test_arbitrate_business_idempotency(&mut second_tx, &second)
            .await
            .unwrap();
        let bytes = match result {
            TestBusinessIdempotencyOutcome::CompletedReplay(response) => {
                response.response_bytes().to_vec()
            }
            TestBusinessIdempotencyOutcome::FirstExecution(_) => {
                panic!("identical losing racer executed twice")
            }
        };
        second_tx.rollback().await.unwrap();
        bytes
    });
    tokio::task::yield_now().await;

    let _device_guard = test_recheck_business_authority(&mut first_tx, &first)
        .await
        .unwrap();
    let response = br#"{"winner":1}"#;
    test_record_completed_idempotency(&mut first_tx, &first, &first_guard, 201, response, None)
        .await
        .unwrap();
    first_tx.commit().await.unwrap();
    assert_eq!(second_task.await.unwrap(), response);

    let completed_at: chrono::DateTime<chrono::Utc> = sqlx::query_scalar(
        "SELECT completed_at FROM chat.idempotency_records WHERE principal_did = $1 AND endpoint_nsid = $2 AND operation_id = $3",
    )
    .bind(REGISTERED_DID)
    .bind("blue.catbird.chat.deleteBlob")
    .bind(operation_id)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(
        completed_at,
        chrono::DateTime::parse_from_rfc3339(FIRST_T)
            .unwrap()
            .with_timezone(&chrono::Utc),
        "completion did not reuse the authority's one trusted instant"
    );

    let late_t = "2026-07-23T14:05:09.123Z";
    let exact_late = authorize_signed_request(
        &pool,
        dpop::repository_test_evidence::ordinary_registered_device(
            uuid::Uuid::new_v4(),
            random_proof_jti(),
            "blue.catbird.chat.deleteBlob",
            late_t,
        ),
        decode_canonical_signed_mutation(&raw).unwrap(),
    )
    .await
    .unwrap();
    let AuthorizationOutcome::CompletedReplay(exact_late) = exact_late else {
        panic!("exact completed replay was subjected to signedAt freshness");
    };
    assert_eq!(exact_late.response_bytes(), response);

    let whitespace_raw = [b" \n".as_slice(), raw.as_slice(), b" \n".as_slice()].concat();
    let whitespace_error = authorize_signed_request(
        &pool,
        dpop::repository_test_evidence::ordinary_registered_device(
            uuid::Uuid::new_v4(),
            random_proof_jti(),
            "blue.catbird.chat.deleteBlob",
            late_t,
        ),
        decode_canonical_signed_mutation(&whitespace_raw).unwrap(),
    )
    .await
    .unwrap_err();
    assert!(matches!(
        whitespace_error,
        AuthRepositoryError::IdempotencyConflict
    ));

    let mut changed_signature: serde_json::Value = serde_json::from_slice(&raw).unwrap();
    changed_signature["signature"] = json!(STANDARD.encode([9_u8; 64]));
    let changed_signature_raw = serde_json::to_vec(&changed_signature).unwrap();
    let signature_error = authorize_signed_request(
        &pool,
        dpop::repository_test_evidence::ordinary_registered_device(
            uuid::Uuid::new_v4(),
            random_proof_jti(),
            "blue.catbird.chat.deleteBlob",
            late_t,
        ),
        decode_canonical_signed_mutation(&changed_signature_raw).unwrap(),
    )
    .await
    .unwrap_err();
    assert!(matches!(
        signature_error,
        AuthRepositoryError::IdempotencyConflict
    ));

    let mut changed_body: serde_json::Value = serde_json::from_slice(&raw).unwrap();
    changed_body["body"]["blobId"] = json!(uuid::Uuid::new_v4());
    let changed_body_raw = serde_json::to_vec(&changed_body).unwrap();
    let digest_error = authorize_signed_request(
        &pool,
        dpop::repository_test_evidence::ordinary_registered_device(
            uuid::Uuid::new_v4(),
            random_proof_jti(),
            "blue.catbird.chat.deleteBlob",
            late_t,
        ),
        decode_canonical_signed_mutation(&changed_body_raw).unwrap(),
    )
    .await
    .unwrap_err();
    assert!(matches!(
        digest_error,
        AuthRepositoryError::IdempotencyConflict
    ));
}

#[tokio::test]
#[ignore = "requires the isolated clean-chat PostgreSQL database"]
async fn completed_ordinary_replay_rechecks_current_jkt_and_auth_generation() {
    let pool = setup_auth_repository_db(2).await;
    let fixture = DeviceFixture::fresh();
    seed_device(&pool, &fixture).await;
    let operation_id = uuid::Uuid::new_v4();
    let raw = signed_blob_deletion_for(&fixture, operation_id, uuid::Uuid::new_v4(), FIRST_T);
    complete_blob_deletion(&pool, &fixture, &raw, br#"{"completed":true}"#).await;

    let rebound_jkt = URL_SAFE_NO_PAD.encode(Sha256::digest(uuid::Uuid::new_v4().as_bytes()));
    sqlx::query(
        r#"
        UPDATE chat.devices
           SET dpop_jkt = $3, auth_generation = 2, updated_at = $4::timestamptz
         WHERE user_did = $1 AND device_id = $2
        "#,
    )
    .bind(REGISTERED_DID)
    .bind(fixture.device_id)
    .bind(&rebound_jkt)
    .bind("2026-07-22T14:06:09.123Z")
    .execute(&pool)
    .await
    .unwrap();

    let stale_jkt = authorize_signed_request(
        &pool,
        ordinary_evidence(
            &fixture,
            "blue.catbird.chat.deleteBlob",
            "2026-07-24T14:05:09.123Z",
            &fixture.dpop_jkt,
        ),
        decode_canonical_signed_mutation(&raw).unwrap(),
    )
    .await
    .unwrap_err();
    assert!(
        matches!(stale_jkt, AuthRepositoryError::DpopBindingMismatch),
        "completed replay escaped the current JKT lock: {stale_jkt:?}"
    );

    let stale_generation = authorize_signed_request(
        &pool,
        ordinary_evidence(
            &fixture,
            "blue.catbird.chat.deleteBlob",
            "2026-07-23T14:05:10.123Z",
            &rebound_jkt,
        ),
        decode_canonical_signed_mutation(&raw).unwrap(),
    )
    .await
    .unwrap_err();
    assert!(
        matches!(
            stale_generation,
            AuthRepositoryError::AuthenticationGenerationMismatch
        ),
        "completed replay escaped the current auth-generation check: {stale_generation:?}"
    );
}

#[tokio::test]
#[ignore = "requires the isolated clean-chat PostgreSQL database"]
async fn completed_ordinary_replay_rechecks_current_immutable_signing_key() {
    let pool = setup_auth_repository_db(2).await;
    let fixture = DeviceFixture::fresh();
    seed_device(&pool, &fixture).await;
    let operation_id = uuid::Uuid::new_v4();
    let attacker_seed: [u8; 32] = Sha256::digest(uuid::Uuid::new_v4().as_bytes()).into();
    let attacker_key = SigningKey::from_bytes(&attacker_seed);
    let attacker_key_id = validation::ed25519_key_id(attacker_key.verifying_key().as_bytes())
        .unwrap()
        .as_str()
        .to_owned();
    let body = json!({
        "$type": "blue.catbird.chat.defs#blobDeletionBody",
        "signatureDomain": "CATBIRD-CHAT-BLOB-DELETE\u{0000}",
        "blobId": uuid::Uuid::new_v4(),
        "actorDid": REGISTERED_DID,
        "actorDeviceId": fixture.device_id,
        "keyId": attacker_key_id,
        "authGeneration": 1,
        "idempotencyKey": operation_id,
        "signedAt": FIRST_T,
    });
    let raw = sign_exact_body_with_key(body, &attacker_key);
    insert_completed_delete_fixture(&pool, operation_id, &raw, br#"{"forged":true}"#).await;

    let error = authorize_signed_request(
        &pool,
        ordinary_evidence(
            &fixture,
            "blue.catbird.chat.deleteBlob",
            "2026-07-24T14:05:09.123Z",
            &fixture.dpop_jkt,
        ),
        decode_canonical_signed_mutation(&raw).unwrap(),
    )
    .await
    .unwrap_err();
    assert!(
        matches!(error, AuthRepositoryError::RequestBindingMismatch),
        "completed replay escaped the immutable key-ID check: {error:?}"
    );
}

#[tokio::test]
#[ignore = "requires the isolated clean-chat PostgreSQL database"]
async fn completed_ordinary_replay_reverifies_signature_under_the_current_key() {
    let pool = setup_auth_repository_db(2).await;
    let fixture = DeviceFixture::fresh();
    seed_device(&pool, &fixture).await;
    let operation_id = uuid::Uuid::new_v4();
    let attacker_seed: [u8; 32] = Sha256::digest(uuid::Uuid::new_v4().as_bytes()).into();
    let attacker_key = SigningKey::from_bytes(&attacker_seed);
    let body = json!({
        "$type": "blue.catbird.chat.defs#blobDeletionBody",
        "signatureDomain": "CATBIRD-CHAT-BLOB-DELETE\u{0000}",
        "blobId": uuid::Uuid::new_v4(),
        "actorDid": REGISTERED_DID,
        "actorDeviceId": fixture.device_id,
        "keyId": fixture.key_id,
        "authGeneration": 1,
        "idempotencyKey": operation_id,
        "signedAt": FIRST_T,
    });
    let raw = sign_exact_body_with_key(body, &attacker_key);
    insert_completed_delete_fixture(&pool, operation_id, &raw, br#"{"forged":true}"#).await;

    let error = authorize_signed_request(
        &pool,
        ordinary_evidence(
            &fixture,
            "blue.catbird.chat.deleteBlob",
            "2026-07-23T14:05:09.123Z",
            &fixture.dpop_jkt,
        ),
        decode_canonical_signed_mutation(&raw).unwrap(),
    )
    .await
    .unwrap_err();
    assert!(
        matches!(error, AuthRepositoryError::Primitive(_)),
        "completed replay escaped current-key signature verification: {error:?}"
    );
}

#[tokio::test]
#[ignore = "requires the isolated clean-chat PostgreSQL database"]
async fn completed_ordinary_replay_rejects_a_now_revoked_device() {
    let pool = setup_auth_repository_db(2).await;
    let fixture = DeviceFixture::fresh();
    seed_device(&pool, &fixture).await;
    let operation_id = uuid::Uuid::new_v4();
    let raw = signed_blob_deletion_for(&fixture, operation_id, uuid::Uuid::new_v4(), FIRST_T);
    complete_blob_deletion(&pool, &fixture, &raw, br#"{"completed":true}"#).await;
    revoke_fixture(&pool, &fixture).await;

    let error = authorize_signed_request(
        &pool,
        ordinary_evidence(
            &fixture,
            "blue.catbird.chat.deleteBlob",
            "2026-07-23T14:05:09.123Z",
            &fixture.dpop_jkt,
        ),
        decode_canonical_signed_mutation(&raw).unwrap(),
    )
    .await
    .unwrap_err();
    assert!(
        matches!(error, AuthRepositoryError::DeviceRevoked),
        "completed replay escaped current device status: {error:?}"
    );
}

#[tokio::test]
#[ignore = "requires the isolated clean-chat PostgreSQL database"]
async fn completed_ordinary_replay_survives_a_fresh_pool_but_only_for_active_authority() {
    let pool = setup_auth_repository_db(2).await;
    let fixture = DeviceFixture::fresh();
    seed_device(&pool, &fixture).await;
    let operation_id = uuid::Uuid::new_v4();
    let raw = signed_blob_deletion_for(&fixture, operation_id, uuid::Uuid::new_v4(), FIRST_T);
    let response = br#"{"afterRestart":true}"#;
    complete_blob_deletion(&pool, &fixture, &raw, response).await;
    pool.close().await;

    let restarted = common::chat_protocol::setup_chat_protocol_db(2).await;
    let outcome = authorize_signed_request(
        &restarted,
        ordinary_evidence(
            &fixture,
            "blue.catbird.chat.deleteBlob",
            "2026-07-23T14:05:09.123Z",
            &fixture.dpop_jkt,
        ),
        decode_canonical_signed_mutation(&raw).unwrap(),
    )
    .await
    .unwrap();
    let AuthorizationOutcome::CompletedReplay(outcome) = outcome else {
        panic!("fresh-pool exact replay did not return its durable completion");
    };
    assert_eq!(outcome.response_bytes(), response);
}

#[tokio::test]
#[ignore = "requires the isolated clean-chat PostgreSQL database"]
async fn enrollment_adapter_commits_generation_one_and_durable_exact_completion() {
    let pool = setup_auth_repository_db(3).await;
    let fixture = DeviceFixture::fresh();
    let operation_id = uuid::Uuid::new_v4();
    let raw = enrollment_body(&fixture, operation_id, "Fresh enrollment", FIRST_T);
    let admission = authorize_enrollment_operation_only(
        &pool,
        enrollment_evidence(
            &raw,
            uuid::Uuid::new_v4(),
            random_proof_jti(),
            uuid::Uuid::new_v4(),
            FIRST_T,
        ),
    )
    .await
    .unwrap();

    let mut transaction = pool.begin().await.unwrap();
    let response = br#"{"authGeneration":1}"#;
    persist_and_complete_enrollment(&mut transaction, admission, 201, response)
        .await
        .unwrap();
    transaction.commit().await.unwrap();

    let device: (String, String, i64, String) = sqlx::query_as(
        "SELECT status, dpop_jkt, auth_generation, device_name FROM chat.devices WHERE user_did = $1 AND device_id = $2",
    )
    .bind(REGISTERED_DID)
    .bind(fixture.device_id)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(
        device,
        (
            "active".to_owned(),
            fixture.dpop_jkt.clone(),
            1,
            "Fresh enrollment".to_owned(),
        )
    );
    let key: (String, Vec<u8>, i64) = sqlx::query_as(
        "SELECT key_id, signing_public_key, enrollment_auth_generation FROM chat.device_keys WHERE user_did = $1 AND device_id = $2",
    )
    .bind(REGISTERED_DID)
    .bind(fixture.device_id)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(key.0, fixture.key_id);
    assert_eq!(
        key.1,
        fixture.signing_key.verifying_key().as_bytes().as_slice()
    );
    assert_eq!(key.2, 1);
    pool.close().await;

    let restarted = common::chat_protocol::setup_chat_protocol_db(2).await;
    let replay_admission = authorize_enrollment_operation_only(
        &restarted,
        enrollment_evidence(
            &raw,
            uuid::Uuid::new_v4(),
            random_proof_jti(),
            uuid::Uuid::new_v4(),
            "2026-07-24T14:05:09.123Z",
        ),
    )
    .await
    .unwrap();
    let mut replay_transaction = restarted.begin().await.unwrap();
    let prelude::PreparedEnrollmentOperation::Replay(replay) =
        prelude::prepare_enrollment_operation(&mut replay_transaction, replay_admission)
            .await
            .unwrap()
    else {
        panic!("completed enrollment was not durable across a fresh pool");
    };
    replay_transaction.commit().await.unwrap();
    assert_eq!(replay.response_bytes(), response);

    let changed = enrollment_body(&fixture, operation_id, "Changed enrollment", FIRST_T);
    let conflict_admission = authorize_enrollment_operation_only(
        &restarted,
        enrollment_evidence(
            &changed,
            uuid::Uuid::new_v4(),
            random_proof_jti(),
            uuid::Uuid::new_v4(),
            "2026-07-23T14:05:10.123Z",
        ),
    )
    .await
    .unwrap();
    let mut conflict_transaction = restarted.begin().await.unwrap();
    let conflict =
        prelude::prepare_enrollment_operation(&mut conflict_transaction, conflict_admission)
            .await
            .unwrap_err();
    assert!(matches!(conflict, PreludeError::OperationIdConflict));
    conflict_transaction.rollback().await.unwrap();
}

#[tokio::test]
#[ignore = "requires the isolated clean-chat PostgreSQL database"]
async fn rebind_adapter_cas_updates_only_jkt_and_generation_and_replays_after_restart() {
    let pool = setup_auth_repository_db(3).await;
    let fixture = DeviceFixture::fresh();
    seed_device(&pool, &fixture).await;
    let operation_id = uuid::Uuid::new_v4();
    let new_jkt = URL_SAFE_NO_PAD.encode(Sha256::digest(uuid::Uuid::new_v4().as_bytes()));
    let raw = rebind_body(
        &fixture,
        operation_id,
        &fixture.dpop_jkt,
        &new_jkt,
        1,
        FIRST_T,
    );
    let conflicting_new_jkt =
        URL_SAFE_NO_PAD.encode(Sha256::digest(uuid::Uuid::new_v4().as_bytes()));
    let conflicting_raw = rebind_body(
        &fixture,
        operation_id,
        &fixture.dpop_jkt,
        &conflicting_new_jkt,
        1,
        FIRST_T,
    );
    let admission = authorize_rebind_operation_only(
        &pool,
        rebind_evidence(&raw, uuid::Uuid::new_v4(), random_proof_jti(), FIRST_T),
    )
    .await
    .unwrap();
    // Both exact old-state requests are admitted before either one changes the
    // row. Their immutable bodies differ under one operation ID, so arbitration
    // (not post-CAS admission) must reject the second request.
    let conflicting_admission = authorize_rebind_operation_only(
        &pool,
        rebind_evidence(
            &conflicting_raw,
            uuid::Uuid::new_v4(),
            random_proof_jti(),
            FIRST_T,
        ),
    )
    .await
    .unwrap();

    let mut transaction = pool.begin().await.unwrap();
    let response = br#"{"authGeneration":2}"#;
    persist_and_complete_rebind(&mut transaction, admission, 200, response)
        .await
        .unwrap();
    transaction.commit().await.unwrap();

    let mut conflict_transaction = pool.begin().await.unwrap();
    let conflict =
        prelude::prepare_rebind_operation(&mut conflict_transaction, conflicting_admission)
            .await
            .unwrap_err();
    assert!(matches!(conflict, PreludeError::OperationIdConflict));
    conflict_transaction.rollback().await.unwrap();

    let device: (String, i64) = sqlx::query_as(
        "SELECT dpop_jkt, auth_generation FROM chat.devices WHERE user_did = $1 AND device_id = $2",
    )
    .bind(REGISTERED_DID)
    .bind(fixture.device_id)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(device, (new_jkt.clone(), 2));
    let key: (String, Vec<u8>, i64) = sqlx::query_as(
        "SELECT key_id, signing_public_key, enrollment_auth_generation FROM chat.device_keys WHERE user_did = $1 AND device_id = $2",
    )
    .bind(REGISTERED_DID)
    .bind(fixture.device_id)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(key.0, fixture.key_id);
    assert_eq!(
        key.1,
        fixture.signing_key.verifying_key().as_bytes().as_slice()
    );
    assert_eq!(key.2, 1, "rebind rewrote immutable enrollment provenance");
    pool.close().await;

    let restarted = common::chat_protocol::setup_chat_protocol_db(2).await;
    let replay_admission = authorize_rebind_operation_only(
        &restarted,
        rebind_evidence(
            &raw,
            uuid::Uuid::new_v4(),
            random_proof_jti(),
            "2026-07-24T14:05:09.123Z",
        ),
    )
    .await
    .unwrap();
    let mut replay_transaction = restarted.begin().await.unwrap();
    let prelude::PreparedRebindOperation::Replay(replay) =
        prelude::prepare_rebind_operation(&mut replay_transaction, replay_admission)
            .await
            .unwrap()
    else {
        panic!("completed rebind was not durable across a fresh pool");
    };
    replay_transaction.commit().await.unwrap();
    assert_eq!(replay.response_bytes(), response);

    let changed_jkt = URL_SAFE_NO_PAD.encode(Sha256::digest(uuid::Uuid::new_v4().as_bytes()));
    let changed = rebind_body(
        &fixture,
        operation_id,
        &fixture.dpop_jkt,
        &changed_jkt,
        1,
        FIRST_T,
    );
    let conflict = match authorize_rebind_operation_only(
        &restarted,
        rebind_evidence(
            &changed,
            uuid::Uuid::new_v4(),
            random_proof_jti(),
            "2026-07-23T14:05:10.123Z",
        ),
    )
    .await
    {
        Ok(_) => panic!("changed completed rebind unexpectedly admitted"),
        Err(error) => error,
    };
    assert!(matches!(
        conflict,
        AuthRepositoryError::RequestBindingMismatch
    ));
}

#[tokio::test]
#[ignore = "requires the isolated clean-chat PostgreSQL database"]
async fn replenishment_exact_replay_survives_next_day_but_stale_first_creates_no_claim() {
    let pool = setup_auth_repository_db(3).await;
    seed_registered_device(&pool).await;
    let operation_id = uuid::Uuid::new_v4();
    let raw = signed_replenishment(operation_id, FIRST_T);
    let first = authorize_replenishment_operation_only(
        &pool,
        dpop::repository_test_evidence::ordinary_registered_device(
            uuid::Uuid::new_v4(),
            random_proof_jti(),
            "blue.catbird.chat.replenishKeyPackages",
            FIRST_T,
        ),
        decode_canonical_signed_mutation(&raw).unwrap(),
    )
    .await
    .unwrap();
    let mut first_tx = pool.begin().await.unwrap();
    let prelude::PreparedReplenishmentOperation::First(prepared) =
        prelude::prepare_replenishment_operation(&mut first_tx, first)
            .await
            .unwrap()
    else {
        panic!("fresh replenishment unexpectedly replayed");
    };
    {
        let effect = prepared.key_package_authority();
        prelude::publish_replenishment_key_packages(
            &mut first_tx,
            &effect,
            &[test_package(
                &REPLENISHMENT_PACKAGE_REF,
                &REPLENISHMENT_PACKAGE_WRAPPER,
            )],
        )
        .await
        .unwrap();
    }
    let response = br#"{"device":{"availablePackageCount":1}}"#;
    prelude::complete_replenishment_operation(
        &mut first_tx,
        prepared.into_completion_guard(),
        200,
        response,
        None,
    )
    .await
    .unwrap();
    first_tx.commit().await.unwrap();

    let replay = authorize_replenishment_operation_only(
        &pool,
        dpop::repository_test_evidence::ordinary_registered_device(
            uuid::Uuid::new_v4(),
            random_proof_jti(),
            "blue.catbird.chat.replenishKeyPackages",
            "2026-07-24T14:05:09.123Z",
        ),
        decode_canonical_signed_mutation(&raw).unwrap(),
    )
    .await
    .unwrap();
    let mut replay_tx = pool.begin().await.unwrap();
    let prelude::PreparedReplenishmentOperation::Replay(completed) =
        prelude::prepare_replenishment_operation(&mut replay_tx, replay)
            .await
            .unwrap()
    else {
        panic!("next-day exact replenishment replay was treated as first");
    };
    assert_eq!(completed.response_bytes(), response);
    replay_tx.rollback().await.unwrap();

    let stale_operation_id = uuid::Uuid::new_v4();
    let stale_raw = signed_replenishment(stale_operation_id, FIRST_T);
    let stale = authorize_replenishment_operation_only(
        &pool,
        dpop::repository_test_evidence::ordinary_registered_device(
            uuid::Uuid::new_v4(),
            random_proof_jti(),
            "blue.catbird.chat.replenishKeyPackages",
            "2026-07-24T14:05:09.123Z",
        ),
        decode_canonical_signed_mutation(&stale_raw).unwrap(),
    )
    .await
    .unwrap();
    let mut stale_tx = pool.begin().await.unwrap();
    let error = prelude::prepare_replenishment_operation(&mut stale_tx, stale)
        .await
        .unwrap_err();
    assert!(matches!(
        error,
        PreludeError::Authorization(AuthRepositoryError::Primitive(_))
    ));
    stale_tx.rollback().await.unwrap();
    let claim_count: i64 =
        sqlx::query_scalar("SELECT count(*) FROM chat.operation_claims WHERE operation_id=$1")
            .bind(stale_operation_id)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(claim_count, 0, "stale first execution created a claim");
}

#[tokio::test]
#[ignore = "requires the isolated clean-chat PostgreSQL database"]
async fn replenishment_replay_rejects_missing_ref_hash_and_owner_manifest_drift() {
    let pool = setup_auth_repository_db(4).await;
    seed_registered_device(&pool).await;
    let foreign_owner = DeviceFixture::fresh();
    seed_device(&pool, &foreign_owner).await;
    let operation_id = uuid::Uuid::new_v4();
    let raw = signed_replenishment(operation_id, FIRST_T);

    let first = replenishment_admission(&pool, &raw, FIRST_T).await;
    let mut first_tx = pool.begin().await.unwrap();
    let prelude::PreparedReplenishmentOperation::First(prepared) =
        prelude::prepare_replenishment_operation(&mut first_tx, first)
            .await
            .unwrap()
    else {
        panic!("fresh replenishment unexpectedly replayed");
    };
    {
        let effect = prepared.key_package_authority();
        prelude::publish_replenishment_key_packages(
            &mut first_tx,
            &effect,
            &[test_package(
                &REPLENISHMENT_PACKAGE_REF,
                &REPLENISHMENT_PACKAGE_WRAPPER,
            )],
        )
        .await
        .unwrap();
    }
    prelude::complete_replenishment_operation(
        &mut first_tx,
        prepared.into_completion_guard(),
        200,
        br#"{"device":{"availablePackageCount":1}}"#,
        None,
    )
    .await
    .unwrap();
    first_tx.commit().await.unwrap();

    let assert_corrupt = |error: PreludeError| {
        assert!(
            matches!(
                error,
                PreludeError::Authorization(AuthRepositoryError::CorruptIdempotencyRecord)
            ),
            "manifest drift escaped exact replay validation: {error:?}"
        );
    };

    let admission = replenishment_admission(&pool, &raw, "2026-07-24T14:05:09.123Z").await;
    let mut tx = pool.begin().await.unwrap();
    sqlx::query("DELETE FROM chat.key_packages WHERE key_package_ref=$1")
        .bind(REPLENISHMENT_PACKAGE_REF.as_slice())
        .execute(&mut *tx)
        .await
        .unwrap();
    assert_corrupt(
        prelude::prepare_replenishment_operation(&mut tx, admission)
            .await
            .unwrap_err(),
    );
    tx.rollback().await.unwrap();

    let admission = replenishment_admission(&pool, &raw, "2026-07-24T14:05:10.123Z").await;
    let mut tx = pool.begin().await.unwrap();
    sqlx::query("UPDATE chat.key_packages SET key_package_ref=$2 WHERE key_package_ref=$1")
        .bind(REPLENISHMENT_PACKAGE_REF.as_slice())
        .bind([12_u8; 32].as_slice())
        .execute(&mut *tx)
        .await
        .unwrap();
    assert_corrupt(
        prelude::prepare_replenishment_operation(&mut tx, admission)
            .await
            .unwrap_err(),
    );
    tx.rollback().await.unwrap();

    let admission = replenishment_admission(&pool, &raw, "2026-07-24T14:05:11.123Z").await;
    let mut tx = pool.begin().await.unwrap();
    let drifted_wrapper = [12_u8; 8];
    sqlx::query(
        "UPDATE chat.key_packages SET wrapper_bytes=$2,wrapper_sha256=$3 \
         WHERE key_package_ref=$1",
    )
    .bind(REPLENISHMENT_PACKAGE_REF.as_slice())
    .bind(drifted_wrapper.as_slice())
    .bind(Sha256::digest(drifted_wrapper).as_slice())
    .execute(&mut *tx)
    .await
    .unwrap();
    assert_corrupt(
        prelude::prepare_replenishment_operation(&mut tx, admission)
            .await
            .unwrap_err(),
    );
    tx.rollback().await.unwrap();

    let admission = replenishment_admission(&pool, &raw, "2026-07-24T14:05:12.123Z").await;
    let mut tx = pool.begin().await.unwrap();
    sqlx::query(
        "UPDATE chat.key_packages \
            SET owner_device_id=$2,owner_key_id=$3,owner_auth_generation=1 \
          WHERE key_package_ref=$1",
    )
    .bind(REPLENISHMENT_PACKAGE_REF.as_slice())
    .bind(foreign_owner.device_id)
    .bind(&foreign_owner.key_id)
    .execute(&mut *tx)
    .await
    .unwrap();
    assert_corrupt(
        prelude::prepare_replenishment_operation(&mut tx, admission)
            .await
            .unwrap_err(),
    );
    tx.rollback().await.unwrap();
}

#[tokio::test]
#[ignore = "requires the isolated clean-chat PostgreSQL database"]
async fn stale_enrollment_and_rebind_first_execution_create_no_operation_claim() {
    let pool = setup_auth_repository_db(3).await;
    let late = "2026-07-24T14:05:09.123Z";

    let enrollment_fixture = DeviceFixture::fresh();
    let enrollment_id = uuid::Uuid::new_v4();
    let enrollment_raw =
        enrollment_body(&enrollment_fixture, enrollment_id, "Stale first", FIRST_T);
    let enrollment = authorize_enrollment_operation_only(
        &pool,
        enrollment_evidence(
            &enrollment_raw,
            uuid::Uuid::new_v4(),
            random_proof_jti(),
            uuid::Uuid::new_v4(),
            late,
        ),
    )
    .await
    .unwrap();
    let mut enrollment_tx = pool.begin().await.unwrap();
    let error = prelude::prepare_enrollment_operation(&mut enrollment_tx, enrollment)
        .await
        .unwrap_err();
    assert!(matches!(
        error,
        PreludeError::Authorization(AuthRepositoryError::Primitive(_))
    ));
    enrollment_tx.rollback().await.unwrap();

    let rebind_fixture = DeviceFixture::fresh();
    seed_device(&pool, &rebind_fixture).await;
    let rebind_id = uuid::Uuid::new_v4();
    let new_jkt = URL_SAFE_NO_PAD.encode(Sha256::digest(uuid::Uuid::new_v4().as_bytes()));
    let rebind_raw = rebind_body(
        &rebind_fixture,
        rebind_id,
        &rebind_fixture.dpop_jkt,
        &new_jkt,
        1,
        FIRST_T,
    );
    let rebind = authorize_rebind_operation_only(
        &pool,
        rebind_evidence(&rebind_raw, uuid::Uuid::new_v4(), random_proof_jti(), late),
    )
    .await
    .unwrap();
    let mut rebind_tx = pool.begin().await.unwrap();
    let error = prelude::prepare_rebind_operation(&mut rebind_tx, rebind)
        .await
        .unwrap_err();
    assert!(matches!(
        error,
        PreludeError::Authorization(AuthRepositoryError::Primitive(_))
    ));
    rebind_tx.rollback().await.unwrap();

    for operation_id in [enrollment_id, rebind_id] {
        let claim_count: i64 =
            sqlx::query_scalar("SELECT count(*) FROM chat.operation_claims WHERE operation_id=$1")
                .bind(operation_id)
                .fetch_one(&pool)
                .await
                .unwrap();
        assert_eq!(claim_count, 0, "stale first execution created a claim");
    }
}

#[tokio::test]
#[ignore = "requires the isolated clean-chat PostgreSQL database"]
async fn enrollment_adapter_rolls_back_business_state_without_unburning_replay() {
    let pool = setup_auth_repository_db(3).await;
    let fixture = DeviceFixture::fresh();
    let operation_id = uuid::Uuid::new_v4();
    let raw = enrollment_body(&fixture, operation_id, "Rollback enrollment", FIRST_T);
    let token_jti = uuid::Uuid::new_v4();
    let proof_jti = random_proof_jti();
    let auth_txn = uuid::Uuid::new_v4();
    let admission = authorize_enrollment_operation_only(
        &pool,
        enrollment_evidence(&raw, token_jti, proof_jti, auth_txn, FIRST_T),
    )
    .await
    .unwrap();
    let mut transaction = pool.begin().await.unwrap();
    persist_and_complete_enrollment(&mut transaction, admission, 201, br#"{"rolledBack":true}"#)
        .await
        .unwrap();
    transaction.rollback().await.unwrap();

    let device_count: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM chat.devices WHERE user_did = $1 AND device_id = $2",
    )
    .bind(REGISTERED_DID)
    .bind(fixture.device_id)
    .fetch_one(&pool)
    .await
    .unwrap();
    let completion_count: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM chat.idempotency_records WHERE principal_did = $1 AND endpoint_nsid = 'blue.catbird.chat.enrollDevice' AND operation_id = $2",
    )
    .bind(REGISTERED_DID)
    .bind(operation_id)
    .fetch_one(&pool)
    .await
    .unwrap();
    let replay_count: i64 = sqlx::query_scalar(
        r#"
        SELECT count(*) FROM chat.dpop_replays
         WHERE (replay_namespace = 'token' AND token_jti = $1)
            OR (replay_namespace = 'proof' AND proof_jti_bytes = $2)
            OR (replay_namespace = 'authTxn' AND auth_txn = $3)
        "#,
    )
    .bind(token_jti)
    .bind(proof_jti.as_slice())
    .bind(auth_txn)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(device_count, 0);
    assert_eq!(completion_count, 0);
    assert_eq!(replay_count, 3);
}

#[tokio::test]
#[ignore = "requires the isolated clean-chat PostgreSQL database"]
async fn identical_enrollment_business_racers_converge_on_one_device_and_response() {
    let pool = setup_auth_repository_db(4).await;
    let fixture = DeviceFixture::fresh();
    let operation_id = uuid::Uuid::new_v4();
    let raw = enrollment_body(&fixture, operation_id, "Racing enrollment", FIRST_T);
    let first = authorize_enrollment_operation_only(
        &pool,
        enrollment_evidence(
            &raw,
            uuid::Uuid::new_v4(),
            random_proof_jti(),
            uuid::Uuid::new_v4(),
            FIRST_T,
        ),
    )
    .await
    .unwrap();
    let second = authorize_enrollment_operation_only(
        &pool,
        enrollment_evidence(
            &raw,
            uuid::Uuid::new_v4(),
            random_proof_jti(),
            uuid::Uuid::new_v4(),
            FIRST_T,
        ),
    )
    .await
    .unwrap();

    let mut first_tx = pool.begin().await.unwrap();
    let prepared = prepare_enrollment_first(&mut first_tx, first)
        .await
        .unwrap();
    let second_pool = pool.clone();
    let second_task = tokio::spawn(async move {
        let mut second_tx = second_pool.begin().await.unwrap();
        let result = prelude::prepare_enrollment_operation(&mut second_tx, second)
            .await
            .unwrap();
        let prelude::PreparedEnrollmentOperation::Replay(response) = result else {
            panic!("identical enrollment loser executed twice");
        };
        let bytes = response.response_bytes().to_vec();
        second_tx.rollback().await.unwrap();
        bytes
    });
    tokio::task::yield_now().await;
    let response = br#"{"winner":"enrollment"}"#;
    {
        let effect = prepared.effect_authority();
        prelude::persist_enrollment_bootstrap_effects(&mut first_tx, &effect)
            .await
            .unwrap();
        prelude::publish_enrollment_key_packages(
            &mut first_tx,
            &effect,
            &[test_package(
                &ENROLLMENT_PACKAGE_REF,
                &ENROLLMENT_PACKAGE_WRAPPER,
            )],
        )
        .await
        .unwrap();
    }
    prelude::complete_enrollment_bootstrap_operation(
        &mut first_tx,
        prepared.into_completion_guard(),
        201,
        response,
        None,
    )
    .await
    .unwrap();
    first_tx.commit().await.unwrap();
    assert_eq!(second_task.await.unwrap(), response);

    let row_counts: (i64, i64) = sqlx::query_as(
        r#"
        SELECT
          (SELECT count(*) FROM chat.devices WHERE user_did = $1 AND device_id = $2),
          (SELECT count(*) FROM chat.device_keys WHERE user_did = $1 AND device_id = $2)
        "#,
    )
    .bind(REGISTERED_DID)
    .bind(fixture.device_id)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(row_counts, (1, 1));
}

#[tokio::test]
#[ignore = "requires the isolated clean-chat PostgreSQL database"]
async fn rebind_adapter_rolls_back_cas_without_unburning_replay() {
    let pool = setup_auth_repository_db(3).await;
    let fixture = DeviceFixture::fresh();
    seed_device(&pool, &fixture).await;
    let operation_id = uuid::Uuid::new_v4();
    let new_jkt = URL_SAFE_NO_PAD.encode(Sha256::digest(uuid::Uuid::new_v4().as_bytes()));
    let raw = rebind_body(
        &fixture,
        operation_id,
        &fixture.dpop_jkt,
        &new_jkt,
        1,
        FIRST_T,
    );
    let token_jti = uuid::Uuid::new_v4();
    let proof_jti = random_proof_jti();
    let admission = authorize_rebind_operation_only(
        &pool,
        rebind_evidence(&raw, token_jti, proof_jti, FIRST_T),
    )
    .await
    .unwrap();
    let mut transaction = pool.begin().await.unwrap();
    persist_and_complete_rebind(&mut transaction, admission, 200, br#"{"rolledBack":true}"#)
        .await
        .unwrap();
    transaction.rollback().await.unwrap();

    let device: (String, i64) = sqlx::query_as(
        "SELECT dpop_jkt, auth_generation FROM chat.devices WHERE user_did = $1 AND device_id = $2",
    )
    .bind(REGISTERED_DID)
    .bind(fixture.device_id)
    .fetch_one(&pool)
    .await
    .unwrap();
    let completion_count: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM chat.idempotency_records WHERE principal_did = $1 AND endpoint_nsid = 'blue.catbird.chat.rebindDeviceAuthentication' AND operation_id = $2",
    )
    .bind(REGISTERED_DID)
    .bind(operation_id)
    .fetch_one(&pool)
    .await
    .unwrap();
    let replay_count: i64 = sqlx::query_scalar(
        r#"
        SELECT count(*) FROM chat.dpop_replays
         WHERE (replay_namespace = 'token' AND token_jti = $1)
            OR (replay_namespace = 'proof' AND proof_jti_bytes = $2)
        "#,
    )
    .bind(token_jti)
    .bind(proof_jti.as_slice())
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(device, (fixture.dpop_jkt.clone(), 1));
    assert_eq!(completion_count, 0);
    assert_eq!(replay_count, 2);
}

#[tokio::test]
#[ignore = "requires the isolated clean-chat PostgreSQL database"]
async fn identical_rebind_business_racers_converge_on_one_cas_and_response() {
    let pool = setup_auth_repository_db(4).await;
    let fixture = DeviceFixture::fresh();
    seed_device(&pool, &fixture).await;
    let operation_id = uuid::Uuid::new_v4();
    let new_jkt = URL_SAFE_NO_PAD.encode(Sha256::digest(uuid::Uuid::new_v4().as_bytes()));
    let raw = rebind_body(
        &fixture,
        operation_id,
        &fixture.dpop_jkt,
        &new_jkt,
        1,
        FIRST_T,
    );
    let first = authorize_rebind_operation_only(
        &pool,
        rebind_evidence(&raw, uuid::Uuid::new_v4(), random_proof_jti(), FIRST_T),
    )
    .await
    .unwrap();
    let second = authorize_rebind_operation_only(
        &pool,
        rebind_evidence(&raw, uuid::Uuid::new_v4(), random_proof_jti(), FIRST_T),
    )
    .await
    .unwrap();

    let mut first_tx = pool.begin().await.unwrap();
    let prepared = prepare_rebind_first(&mut first_tx, first).await.unwrap();
    let second_pool = pool.clone();
    let second_task = tokio::spawn(async move {
        let mut second_tx = second_pool.begin().await.unwrap();
        let result = prelude::prepare_rebind_operation(&mut second_tx, second)
            .await
            .unwrap();
        let prelude::PreparedRebindOperation::Replay(response) = result else {
            panic!("identical rebind loser executed twice");
        };
        let bytes = response.response_bytes().to_vec();
        second_tx.rollback().await.unwrap();
        bytes
    });
    tokio::task::yield_now().await;
    let response = br#"{"winner":"rebind"}"#;
    {
        let effect = prepared.effect_authority();
        prelude::persist_rebind_bootstrap_effects(&mut first_tx, &effect)
            .await
            .unwrap();
    }
    prelude::complete_rebind_bootstrap_operation(
        &mut first_tx,
        prepared.into_completion_guard(),
        200,
        response,
        None,
    )
    .await
    .unwrap();
    first_tx.commit().await.unwrap();
    assert_eq!(second_task.await.unwrap(), response);

    let device: (String, i64) = sqlx::query_as(
        "SELECT dpop_jkt, auth_generation FROM chat.devices WHERE user_did = $1 AND device_id = $2",
    )
    .bind(REGISTERED_DID)
    .bind(fixture.device_id)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(device, (new_jkt, 2));
}

#[tokio::test]
#[ignore = "requires the isolated clean-chat PostgreSQL database"]
async fn dedicated_bootstrap_conflicts_burn_replay_without_mutating_authority_rows() {
    let pool = setup_auth_repository_db(3).await;

    let enrolled = DeviceFixture::fresh();
    seed_device(&pool, &enrolled).await;
    let enrollment_raw =
        enrollment_body(&enrolled, uuid::Uuid::new_v4(), "Already present", FIRST_T);
    let enrollment_token = uuid::Uuid::new_v4();
    let enrollment_proof = random_proof_jti();
    let enrollment_auth_txn = uuid::Uuid::new_v4();
    let admission = authorize_enrollment_operation_only(
        &pool,
        enrollment_evidence(
            &enrollment_raw,
            enrollment_token,
            enrollment_proof,
            enrollment_auth_txn,
            FIRST_T,
        ),
    )
    .await
    .unwrap();
    let mut enrollment_transaction = pool.begin().await.unwrap();
    let error = match prepare_enrollment_first(&mut enrollment_transaction, admission).await {
        Ok(_) => panic!("registered enrollment unexpectedly acquired absence scope"),
        Err(error) => error,
    };
    assert!(matches!(
        error,
        PreludeError::Authorization(AuthRepositoryError::DeviceAlreadyRegistered)
    ));
    enrollment_transaction.rollback().await.unwrap();
    let enrollment_replays: i64 = sqlx::query_scalar(
        r#"
        SELECT count(*) FROM chat.dpop_replays
         WHERE (replay_namespace = 'token' AND token_jti = $1)
            OR (replay_namespace = 'proof' AND proof_jti_bytes = $2)
            OR (replay_namespace = 'authTxn' AND auth_txn = $3)
        "#,
    )
    .bind(enrollment_token)
    .bind(enrollment_proof.as_slice())
    .bind(enrollment_auth_txn)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(enrollment_replays, 3);

    let rebind = DeviceFixture::fresh();
    seed_device(&pool, &rebind).await;
    let new_jkt = URL_SAFE_NO_PAD.encode(Sha256::digest(uuid::Uuid::new_v4().as_bytes()));
    let stale_raw = rebind_body(
        &rebind,
        uuid::Uuid::new_v4(),
        &rebind.dpop_jkt,
        &new_jkt,
        2,
        FIRST_T,
    );
    let stale_token = uuid::Uuid::new_v4();
    let stale_proof = random_proof_jti();
    let error = match authorize_rebind_operation_only(
        &pool,
        rebind_evidence(&stale_raw, stale_token, stale_proof, FIRST_T),
    )
    .await
    {
        Ok(_) => panic!("stale rebind unexpectedly admitted"),
        Err(error) => error,
    };
    assert!(matches!(
        error,
        AuthRepositoryError::AuthenticationGenerationMismatch
    ));
    let stale_replays: i64 = sqlx::query_scalar(
        r#"
        SELECT count(*) FROM chat.dpop_replays
         WHERE (replay_namespace = 'token' AND token_jti = $1)
            OR (replay_namespace = 'proof' AND proof_jti_bytes = $2)
        "#,
    )
    .bind(stale_token)
    .bind(stale_proof.as_slice())
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(stale_replays, 2);

    let attacker_seed: [u8; 32] = Sha256::digest(uuid::Uuid::new_v4().as_bytes()).into();
    let attacker_key = SigningKey::from_bytes(&attacker_seed);
    let attacker_key_id = validation::ed25519_key_id(attacker_key.verifying_key().as_bytes())
        .unwrap()
        .as_str()
        .to_owned();
    let attacker_jkt = URL_SAFE_NO_PAD.encode(Sha256::digest(uuid::Uuid::new_v4().as_bytes()));
    let attacker_body = json!({
        "$type": "blue.catbird.chat.defs#deviceAuthenticationRebindBody",
        "signatureDomain": "CATBIRD-CHAT-DEVICE-REBIND\u{0000}",
        "actorDid": REGISTERED_DID,
        "actorDeviceId": rebind.device_id,
        "keyId": attacker_key_id,
        "expectedAuthGeneration": 1,
        "currentDpopJkt": rebind.dpop_jkt,
        "newDpopJkt": attacker_jkt,
        "idempotencyKey": uuid::Uuid::new_v4(),
        "signedAt": FIRST_T,
    });
    let attacker_raw = sign_exact_body_with_key(attacker_body, &attacker_key);
    let attacker_token = uuid::Uuid::new_v4();
    let attacker_proof = random_proof_jti();
    let error = match authorize_rebind_operation_only(
        &pool,
        rebind_evidence(&attacker_raw, attacker_token, attacker_proof, FIRST_T),
    )
    .await
    {
        Ok(_) => panic!("forged rebind unexpectedly admitted"),
        Err(error) => error,
    };
    assert!(matches!(error, AuthRepositoryError::RequestBindingMismatch));
    let attacker_replays: i64 = sqlx::query_scalar(
        r#"
        SELECT count(*) FROM chat.dpop_replays
         WHERE (replay_namespace = 'token' AND token_jti = $1)
            OR (replay_namespace = 'proof' AND proof_jti_bytes = $2)
        "#,
    )
    .bind(attacker_token)
    .bind(attacker_proof.as_slice())
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(attacker_replays, 2);

    let unchanged: (String, i64, String) = sqlx::query_as(
        "SELECT dpop_jkt, auth_generation, status FROM chat.devices WHERE user_did = $1 AND device_id = $2",
    )
    .bind(REGISTERED_DID)
    .bind(rebind.device_id)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(unchanged, (rebind.dpop_jkt, 1, "active".to_owned()));
}

#[tokio::test]
#[ignore = "requires the isolated clean-chat PostgreSQL database"]
async fn enrollment_business_guard_cannot_cross_postgres_transactions() {
    let pool = setup_auth_repository_db(2).await;
    let fixture = DeviceFixture::fresh();
    let operation_id = uuid::Uuid::new_v4();
    let raw = enrollment_body(&fixture, operation_id, "Transaction bound", FIRST_T);
    let admission = authorize_enrollment_operation_only(
        &pool,
        enrollment_evidence(
            &raw,
            uuid::Uuid::new_v4(),
            random_proof_jti(),
            uuid::Uuid::new_v4(),
            FIRST_T,
        ),
    )
    .await
    .unwrap();
    let mut first_transaction = pool.begin().await.unwrap();
    let prepared = prepare_enrollment_first(&mut first_transaction, admission)
        .await
        .unwrap();
    let completion = prepared.into_completion_guard();
    first_transaction.rollback().await.unwrap();

    let mut different_transaction = pool.begin().await.unwrap();
    let error = prelude::complete_enrollment_bootstrap_operation(
        &mut different_transaction,
        completion,
        201,
        br#"{"invalid":true}"#,
        None,
    )
    .await
    .unwrap_err();
    assert!(matches!(error, PreludeError::ForeignTransaction));
    different_transaction.rollback().await.unwrap();
}

#[tokio::test]
#[ignore = "requires the isolated clean-chat PostgreSQL database"]
async fn completed_enrollment_replay_requires_exact_installed_generation_one_authority() {
    let pool = setup_auth_repository_db(3).await;

    let orphan = DeviceFixture::fresh();
    let orphan_operation = uuid::Uuid::new_v4();
    let orphan_raw = enrollment_body(&orphan, orphan_operation, "Orphan completion", FIRST_T);
    insert_completed_bootstrap_fixture(
        &pool,
        "blue.catbird.chat.enrollDevice",
        orphan_operation,
        &orphan_raw,
        None,
        Some(&orphan.dpop_jkt),
        br#"{"orphan":true}"#,
    )
    .await;
    let admission = authorize_enrollment_operation_only(
        &pool,
        enrollment_evidence(
            &orphan_raw,
            uuid::Uuid::new_v4(),
            random_proof_jti(),
            uuid::Uuid::new_v4(),
            "2026-07-23T14:05:09.123Z",
        ),
    )
    .await
    .unwrap();
    let mut transaction = pool.begin().await.unwrap();
    let error = validate_enrollment_replay(&mut transaction, admission)
        .await
        .unwrap_err();
    assert!(
        matches!(
            error,
            PreludeError::Authorization(AuthRepositoryError::DeviceNotRegistered)
        ),
        "orphan enrollment completion was replayed: {error:?}"
    );
    transaction.rollback().await.unwrap();

    let expected = DeviceFixture::fresh();
    let wrong_key_fresh = DeviceFixture::fresh();
    let wrong_key = DeviceFixture {
        device_id: expected.device_id,
        dpop_jkt: expected.dpop_jkt.clone(),
        signing_key: wrong_key_fresh.signing_key,
        key_id: wrong_key_fresh.key_id,
    };
    seed_device(&pool, &wrong_key).await;
    let wrong_key_operation = uuid::Uuid::new_v4();
    let wrong_key_raw = enrollment_body(
        &expected,
        wrong_key_operation,
        "Wrong installed key",
        FIRST_T,
    );
    insert_completed_bootstrap_fixture(
        &pool,
        "blue.catbird.chat.enrollDevice",
        wrong_key_operation,
        &wrong_key_raw,
        None,
        Some(&expected.dpop_jkt),
        br#"{"wrongKey":true}"#,
    )
    .await;
    let admission = authorize_enrollment_operation_only(
        &pool,
        enrollment_evidence(
            &wrong_key_raw,
            uuid::Uuid::new_v4(),
            random_proof_jti(),
            uuid::Uuid::new_v4(),
            "2026-07-23T14:05:10.123Z",
        ),
    )
    .await
    .unwrap();
    let mut transaction = pool.begin().await.unwrap();
    let error = validate_enrollment_replay(&mut transaction, admission)
        .await
        .unwrap_err();
    assert!(
        matches!(
            error,
            PreludeError::Authorization(AuthRepositoryError::RequestBindingMismatch)
        ),
        "enrollment completion ignored the installed immutable key: {error:?}"
    );
    transaction.rollback().await.unwrap();
}

#[tokio::test]
#[ignore = "requires the isolated clean-chat PostgreSQL database"]
async fn completed_rebind_replay_requires_exact_post_cas_authority_and_signature() {
    let pool = setup_auth_repository_db(3).await;

    let orphan = DeviceFixture::fresh();
    seed_device(&pool, &orphan).await;
    let orphan_operation = uuid::Uuid::new_v4();
    let orphan_new_jkt = URL_SAFE_NO_PAD.encode(Sha256::digest(uuid::Uuid::new_v4().as_bytes()));
    let orphan_raw = rebind_body(
        &orphan,
        orphan_operation,
        &orphan.dpop_jkt,
        &orphan_new_jkt,
        1,
        FIRST_T,
    );
    insert_completed_bootstrap_fixture(
        &pool,
        "blue.catbird.chat.rebindDeviceAuthentication",
        orphan_operation,
        &orphan_raw,
        Some(&orphan.dpop_jkt),
        Some(&orphan_new_jkt),
        br#"{"orphan":true}"#,
    )
    .await;
    let admission = authorize_rebind_operation_only(
        &pool,
        rebind_evidence(
            &orphan_raw,
            uuid::Uuid::new_v4(),
            random_proof_jti(),
            "2026-07-23T14:05:09.123Z",
        ),
    )
    .await
    .unwrap();
    let mut transaction = pool.begin().await.unwrap();
    let error = validate_rebind_replay(&mut transaction, admission)
        .await
        .unwrap_err();
    assert!(
        matches!(
            error,
            PreludeError::Authorization(AuthRepositoryError::DpopBindingMismatch)
        ),
        "pre-CAS rebind completion was replayed: {error:?}"
    );
    transaction.rollback().await.unwrap();

    let forged = DeviceFixture::fresh();
    seed_device(&pool, &forged).await;
    let forged_operation = uuid::Uuid::new_v4();
    let forged_new_jkt = URL_SAFE_NO_PAD.encode(Sha256::digest(uuid::Uuid::new_v4().as_bytes()));
    sqlx::query(
        r#"
        UPDATE chat.devices
           SET dpop_jkt = $3, auth_generation = 2, updated_at = $4::timestamptz
         WHERE user_did = $1 AND device_id = $2
        "#,
    )
    .bind(REGISTERED_DID)
    .bind(forged.device_id)
    .bind(&forged_new_jkt)
    .bind("2026-07-22T14:06:09.123Z")
    .execute(&pool)
    .await
    .unwrap();
    let attacker_seed: [u8; 32] = Sha256::digest(uuid::Uuid::new_v4().as_bytes()).into();
    let attacker_key = SigningKey::from_bytes(&attacker_seed);
    let forged_body = json!({
        "$type": "blue.catbird.chat.defs#deviceAuthenticationRebindBody",
        "signatureDomain": "CATBIRD-CHAT-DEVICE-REBIND\u{0000}",
        "actorDid": REGISTERED_DID,
        "actorDeviceId": forged.device_id,
        "keyId": forged.key_id,
        "expectedAuthGeneration": 1,
        "currentDpopJkt": forged.dpop_jkt,
        "newDpopJkt": forged_new_jkt,
        "idempotencyKey": forged_operation,
        "signedAt": FIRST_T,
    });
    let forged_raw = sign_exact_body_with_key(forged_body, &attacker_key);
    insert_completed_bootstrap_fixture(
        &pool,
        "blue.catbird.chat.rebindDeviceAuthentication",
        forged_operation,
        &forged_raw,
        Some(&forged.dpop_jkt),
        Some(&forged_new_jkt),
        br#"{"forged":true}"#,
    )
    .await;
    let error = match authorize_rebind_operation_only(
        &pool,
        rebind_evidence(
            &forged_raw,
            uuid::Uuid::new_v4(),
            random_proof_jti(),
            "2026-07-23T14:05:10.123Z",
        ),
    )
    .await
    {
        Ok(_) => panic!("forged completed rebind unexpectedly admitted"),
        Err(error) => error,
    };
    assert!(
        matches!(error, AuthRepositoryError::Primitive(_)),
        "rebind completion escaped immutable-key signature verification: {error:?}"
    );
}

#[tokio::test]
#[ignore = "requires the isolated clean-chat PostgreSQL database"]
async fn business_convergence_revalidates_completed_authority_and_post_state() {
    let pool = setup_auth_repository_db(4).await;

    let ordinary = DeviceFixture::fresh();
    seed_device(&pool, &ordinary).await;
    let ordinary_operation = uuid::Uuid::new_v4();
    let ordinary_raw =
        signed_blob_deletion_for(&ordinary, ordinary_operation, uuid::Uuid::new_v4(), FIRST_T);
    let ordinary_authority = first_authority(
        authorize_signed_request(
            &pool,
            ordinary_evidence(
                &ordinary,
                "blue.catbird.chat.deleteBlob",
                FIRST_T,
                &ordinary.dpop_jkt,
            ),
            decode_canonical_signed_mutation(&ordinary_raw).unwrap(),
        )
        .await
        .unwrap(),
    );
    insert_completed_delete_fixture(
        &pool,
        ordinary_operation,
        &ordinary_raw,
        br#"{"alreadyCompleted":true}"#,
    )
    .await;
    revoke_fixture(&pool, &ordinary).await;
    let mut ordinary_transaction = pool.begin().await.unwrap();
    let error = test_arbitrate_business_idempotency(&mut ordinary_transaction, &ordinary_authority)
        .await
        .unwrap_err();
    assert!(
        matches!(error, AuthRepositoryError::DeviceRevoked),
        "business convergence replay ignored revoked ordinary authority: {error:?}"
    );
    ordinary_transaction.rollback().await.unwrap();

    let enrollment = DeviceFixture::fresh();
    let enrollment_operation = uuid::Uuid::new_v4();
    let enrollment_raw = enrollment_body(
        &enrollment,
        enrollment_operation,
        "Missing post-state",
        FIRST_T,
    );
    let enrollment_admission = authorize_enrollment_operation_only(
        &pool,
        enrollment_evidence(
            &enrollment_raw,
            uuid::Uuid::new_v4(),
            random_proof_jti(),
            uuid::Uuid::new_v4(),
            FIRST_T,
        ),
    )
    .await
    .unwrap();
    insert_completed_bootstrap_fixture(
        &pool,
        "blue.catbird.chat.enrollDevice",
        enrollment_operation,
        &enrollment_raw,
        None,
        Some(&enrollment.dpop_jkt),
        br#"{"alreadyCompleted":true}"#,
    )
    .await;
    let mut enrollment_transaction = pool.begin().await.unwrap();
    let error = validate_enrollment_replay(&mut enrollment_transaction, enrollment_admission)
        .await
        .unwrap_err();
    assert!(
        matches!(
            error,
            PreludeError::Authorization(AuthRepositoryError::DeviceNotRegistered)
        ),
        "business convergence replay ignored missing enrollment post-state: {error:?}"
    );
    enrollment_transaction.rollback().await.unwrap();

    let rebind = DeviceFixture::fresh();
    seed_device(&pool, &rebind).await;
    let rebind_operation = uuid::Uuid::new_v4();
    let rebind_new_jkt = URL_SAFE_NO_PAD.encode(Sha256::digest(uuid::Uuid::new_v4().as_bytes()));
    let rebind_raw = rebind_body(
        &rebind,
        rebind_operation,
        &rebind.dpop_jkt,
        &rebind_new_jkt,
        1,
        FIRST_T,
    );
    let rebind_admission = authorize_rebind_operation_only(
        &pool,
        rebind_evidence(
            &rebind_raw,
            uuid::Uuid::new_v4(),
            random_proof_jti(),
            FIRST_T,
        ),
    )
    .await
    .unwrap();
    insert_completed_bootstrap_fixture(
        &pool,
        "blue.catbird.chat.rebindDeviceAuthentication",
        rebind_operation,
        &rebind_raw,
        Some(&rebind.dpop_jkt),
        Some(&rebind_new_jkt),
        br#"{"alreadyCompleted":true}"#,
    )
    .await;
    let mut rebind_transaction = pool.begin().await.unwrap();
    let error = validate_rebind_replay(&mut rebind_transaction, rebind_admission)
        .await
        .unwrap_err();
    assert!(
        matches!(
            error,
            PreludeError::Authorization(AuthRepositoryError::DpopBindingMismatch)
        ),
        "business convergence replay ignored missing rebind CAS post-state: {error:?}"
    );
    rebind_transaction.rollback().await.unwrap();
}
