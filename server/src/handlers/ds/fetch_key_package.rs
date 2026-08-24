use axum::{extract::State, Json};
use serde_json::json;
use std::sync::Arc;
use tracing::{debug, warn};

use crate::{
    auth::AuthUser, crypto::redact_for_log, federation::FederationError, identity::canonical_did,
    storage::DbPool,
};
const NSID: &str = "blue.catbird.mlsDS.fetchKeyPackage";

async fn claim_current_authorized_key_package(
    pool: &DbPool,
    resolver: &crate::federation::DsResolver,
    recipient_did: &str,
    convo_id: &str,
    last_resort: bool,
) -> Result<Option<(Vec<u8>, String)>, FederationError> {
    claim_current_authorized_key_package_with(pool, recipient_did, convo_id, last_resort, || {
        resolver.resolve_authorized_device_keys(recipient_did)
    })
    .await
}

async fn claim_current_authorized_key_package_with<Resolve, ResolveFuture>(
    pool: &DbPool,
    recipient_did: &str,
    convo_id: &str,
    last_resort: bool,
    mut resolve_authoritative_keys: Resolve,
) -> Result<Option<(Vec<u8>, String)>, FederationError>
where
    Resolve: FnMut() -> ResolveFuture,
    ResolveFuture:
        std::future::Future<Output = Result<Vec<Vec<u8>>, crate::federation::FederationError>>,
{
    loop {
        let authoritative_keys = resolve_authoritative_keys().await.map_err(|_| {
            warn!(
                recipient = %redact_for_log(recipient_did),
                "Authoritative device resolution failed for federated KeyPackage fetch"
            );
            FederationError::AuthFailed {
                reason: "recipient device authority is unavailable".to_string(),
            }
        })?;
        if authoritative_keys.is_empty() {
            return Err(FederationError::AuthFailed {
                reason: "recipient has no authoritative MLS device".to_string(),
            });
        }

        match crate::db::claim_authorized_key_package_candidate_for_federation(
            pool,
            recipient_did,
            convo_id,
            &authoritative_keys,
            last_resort,
        )
        .await
        .map_err(|_| FederationError::ConfigError {
            reason: "authorized KeyPackage claim failed".to_string(),
        })? {
            crate::db::FederationKeyPackageClaim::Claimed(bytes, hash) => {
                return Ok(Some((bytes, hash)));
            }
            crate::db::FederationKeyPackageClaim::RejectedCandidate => continue,
            crate::db::FederationKeyPackageClaim::Exhausted => return Ok(None),
        }
    }
}

/// GET /xrpc/blue.catbird.mlsDS.fetchKeyPackage
///
/// Return and consume a key package for a local user, requested by a remote DS.
#[tracing::instrument(skip(pool, resolver, auth_user, query))]
pub async fn fetch_key_package(
    State(pool): State<DbPool>,
    State(resolver): State<Arc<crate::federation::DsResolver>>,
    auth_user: AuthUser,
    axum::extract::Query(query): axum::extract::Query<FetchKeyPackageParams>,
) -> Result<Json<serde_json::Value>, FederationError> {
    let security =
        super::deliver_message::enforce_ds_request_security(&pool, &auth_user, NSID, None).await?;
    let requester_ds = security.requester_ds.clone();

    let recipient_did = &query.recipient_did;
    let convo_id = &query.convo_id;
    // N31: fail-loudly service identity — no hardcoded fallback DID.
    let self_did = crate::identity::service_did_base();

    let result: Result<Json<serde_json::Value>, FederationError> = async {
        // Greenfield strict mode: convoId is required and caller must be authorized for that convo.
        let row = sqlx::query_as::<_, (Option<String>, bool, bool)>(
            "SELECT \
               c.sequencer_ds, \
               EXISTS( \
                 SELECT 1 FROM members recipient \
                 WHERE recipient.convo_id = c.id \
                   AND recipient.left_at IS NULL \
                   AND (recipient.member_did = $4 OR recipient.user_did = $4) \
               ) AS recipient_is_member, \
               EXISTS( \
                 SELECT 1 FROM members requester \
                 WHERE requester.convo_id = c.id \
                   AND requester.left_at IS NULL \
                   AND COALESCE(split_part(requester.ds_did, '#', 1), $2) = $3 \
               ) AS caller_is_member_ds \
             FROM conversations c \
             WHERE c.id = $1",
        )
        .bind(convo_id)
        .bind(&self_did)
        .bind(&requester_ds)
        .bind(recipient_did)
        .fetch_optional(&pool)
        .await
        .map_err(FederationError::Database)?;

        let Some((sequencer_ds, recipient_is_member, caller_is_member_ds)) = row else {
            return Err(FederationError::ConversationNotFound {
                convo_id: convo_id.to_string(),
            });
        };

        if !recipient_is_member {
            return Err(FederationError::RecipientNotFound {
                did: recipient_did.clone(),
            });
        }

        let expected_sequencer =
            canonical_did(&sequencer_ds.unwrap_or(self_did.clone())).to_string();
        let caller_is_authorized = requester_ds == expected_sequencer || caller_is_member_ds;
        if !caller_is_authorized {
            return Err(FederationError::AuthFailed {
                reason: "requesting delivery service is not authorized for this conversation"
                    .to_string(),
            });
        }

        let row =
            claim_current_authorized_key_package(&pool, &resolver, recipient_did, convo_id, false)
                .await?;

        let row = match row {
            Some(r) => Some(r),
            None => {
                let lr_row = claim_current_authorized_key_package(
                    &pool,
                    &resolver,
                    recipient_did,
                    convo_id,
                    true,
                )
                .await?;
                if lr_row.is_some() {
                    crate::metrics::record_key_package_last_resort_use();
                }
                lr_row
            }
        };

        match row {
            Some((key_package_data, key_package_hash)) => {
                crate::metrics::record_key_package_claim("claimed");
                debug!(
                    recipient = %redact_for_log(recipient_did),
                    key_package_hash = %redact_for_log(&key_package_hash),
                    requester = %redact_for_log(&requester_ds),
                    convo = %redact_for_log(convo_id),
                    "Key package consumed for federation"
                );

                let encoded = base64::engine::general_purpose::STANDARD.encode(&key_package_data);

                Ok(Json(json!({
                    "keyPackage": encoded,
                    "keyPackageHash": key_package_hash
                })))
            }
            None => {
                crate::metrics::record_key_package_claim("no_match");
                crate::metrics::record_key_package_exhaustion();
                warn!(
                    recipient = %redact_for_log(recipient_did),
                    "No available key packages for federation request"
                );
                Err(FederationError::NoKeyPackagesAvailable {
                    did: recipient_did.clone(),
                })
            }
        }
    }
    .await;

    super::deliver_message::record_ds_outcome(&pool, &requester_ds, result.is_ok()).await;
    result
}

use base64::Engine;

#[derive(Debug, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FetchKeyPackageParams {
    pub recipient_did: String,
    pub convo_id: String,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::{init_db, DbConfig};
    use chrono::{Duration, Utc};
    use openmls::prelude::{tls_codec::Serialize as TlsSerialize, *};
    use openmls_basic_credential::SignatureKeyPair;
    use openmls_traits::OpenMlsProvider;
    use std::sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    };
    use tokio::sync::Barrier;
    use uuid::Uuid;

    const CIPHER_SUITE: &str = "MLS_256_XWING_CHACHA20POLY1305_SHA256_Ed25519";

    async fn setup_test_db() -> DbPool {
        let database_url = std::env::var("TEST_DATABASE_URL")
            .unwrap_or_else(|_| "postgresql://catbird:changeme@localhost:5433/catbird".to_string());
        init_db(DbConfig {
            database_url,
            max_connections: 8,
            min_connections: 2,
            acquire_timeout: std::time::Duration::from_secs(10),
            idle_timeout: std::time::Duration::from_secs(60),
        })
        .await
        .expect("initialize test database")
    }

    fn generate_key_package(identity: &str) -> (Vec<u8>, Vec<u8>) {
        let provider = openmls_libcrux_crypto::Provider::new().expect("libcrux provider");
        let ciphersuite = Ciphersuite::MLS_256_XWING_CHACHA20POLY1305_SHA256_Ed25519;
        let credential = BasicCredential::new(identity.as_bytes().to_vec());
        let signer =
            SignatureKeyPair::new(ciphersuite.signature_algorithm()).expect("signature keypair");
        signer.store(provider.storage()).expect("store signer");
        let signature_key = signer.to_public_vec();
        let bundle = KeyPackage::builder()
            .build(
                ciphersuite,
                &provider,
                &signer,
                CredentialWithKey {
                    credential: credential.into(),
                    signature_key: signature_key.clone().into(),
                },
            )
            .expect("build KeyPackage");
        (
            bundle
                .key_package()
                .tls_serialize_detached()
                .expect("serialize KeyPackage"),
            signature_key,
        )
    }

    async fn seed_user(pool: &DbPool, did: &str) {
        sqlx::query("INSERT INTO users (did) VALUES ($1) ON CONFLICT DO NOTHING")
            .bind(did)
            .execute(pool)
            .await
            .expect("seed user");
    }

    async fn seed_device(pool: &DbPool, did: &str, device_id: &str, key: &[u8], active: bool) {
        sqlx::query(
            "INSERT INTO devices \
             (id, user_did, device_id, credential_did, signature_public_key, active) \
             VALUES ($1, $2, $3, $4, $5, $6)",
        )
        .bind(Uuid::new_v4().to_string())
        .bind(did)
        .bind(device_id)
        .bind(format!("{did}#{device_id}"))
        .bind(hex::encode(key))
        .bind(active)
        .execute(pool)
        .await
        .expect("seed device");
    }

    async fn seed_package(
        pool: &DbPool,
        did: &str,
        device_id: Option<&str>,
        bytes: &[u8],
        last_resort: bool,
    ) -> String {
        let hash = crate::crypto::sha256_hex(bytes);
        sqlx::query(
            "INSERT INTO key_packages \
             (id, owner_did, device_id, credential_did, cipher_suite, key_package, \
              key_package_hash, created_at, expires_at, state, is_last_resort) \
             VALUES ($1, $2, $3, $2, $4, $5, $6, NOW(), $7, 'available', $8)",
        )
        .bind(Uuid::new_v4().to_string())
        .bind(did)
        .bind(device_id)
        .bind(CIPHER_SUITE)
        .bind(bytes)
        .bind(&hash)
        .bind(Utc::now() + Duration::days(30))
        .bind(last_resort)
        .execute(pool)
        .await
        .expect("seed KeyPackage");
        hash
    }

    async fn cleanup(pool: &DbPool, did: &str) {
        let _ = sqlx::query("DELETE FROM key_packages WHERE owner_did = $1")
            .bind(did)
            .execute(pool)
            .await;
        let _ = sqlx::query("DELETE FROM devices WHERE user_did = $1")
            .bind(did)
            .execute(pool)
            .await;
        let _ = sqlx::query("DELETE FROM users WHERE did = $1")
            .bind(did)
            .execute(pool)
            .await;
    }

    #[tokio::test]
    #[ignore = "requires live Postgres (TEST_DATABASE_URL)"]
    async fn federation_fetch_skips_and_quarantines_legacy_or_stale_regular_row() {
        let pool = setup_test_db().await;
        let did = format!("did:plc:w2regular{}", Uuid::new_v4().simple());
        seed_user(&pool, &did).await;

        let (stale_bytes, _) = generate_key_package(&did);
        let stale_hash = seed_package(&pool, &did, None, &stale_bytes, false).await;
        let (valid_bytes, valid_key) = generate_key_package(&did);
        seed_device(&pool, &did, "device-valid", &valid_key, true).await;
        let valid_hash = seed_package(&pool, &did, Some("device-valid"), &valid_bytes, false).await;

        let fetched = crate::db::claim_authorized_key_package_for_federation(
            &pool,
            &did,
            "convo-w2",
            std::slice::from_ref(&valid_key),
            false,
        )
        .await
        .expect("fetch authorized regular package")
        .expect("valid package remains available");

        assert_eq!(fetched.1, valid_hash);
        let stale_state: (String, bool) = sqlx::query_as(
            "SELECT state, dead_at IS NOT NULL FROM key_packages WHERE key_package_hash = $1",
        )
        .bind(stale_hash)
        .fetch_one(&pool)
        .await
        .expect("fetch stale state");
        assert_eq!(stale_state, ("revoked".to_string(), true));
        cleanup(&pool, &did).await;
    }

    #[tokio::test]
    #[ignore = "requires live Postgres (TEST_DATABASE_URL)"]
    async fn production_fetch_loop_reresolves_authority_after_quarantining_candidate() {
        let pool = setup_test_db().await;
        let did = format!("did:plc:w2resolveagain{}", Uuid::new_v4().simple());
        seed_user(&pool, &did).await;

        let (invalid_bytes, _) = generate_key_package(&did);
        seed_package(&pool, &did, Some("missing-device"), &invalid_bytes, false).await;
        let (valid_bytes, valid_key) = generate_key_package(&did);
        seed_device(&pool, &did, "device-valid", &valid_key, true).await;
        let valid_hash = seed_package(&pool, &did, Some("device-valid"), &valid_bytes, false).await;

        let resolution_count = Arc::new(AtomicUsize::new(0));
        let count_for_resolver = resolution_count.clone();
        let key_for_resolver = valid_key.clone();
        let fetched = claim_current_authorized_key_package_with(
            &pool,
            &did,
            "convo-w2-reresolve",
            false,
            move || {
                count_for_resolver.fetch_add(1, Ordering::SeqCst);
                let key = key_for_resolver.clone();
                async move { Ok(vec![key]) }
            },
        )
        .await
        .expect("fetch through quarantined candidate")
        .expect("valid candidate remains available");

        assert_eq!(fetched.1, valid_hash);
        assert_eq!(resolution_count.load(Ordering::SeqCst), 2);
        cleanup(&pool, &did).await;
    }

    #[tokio::test]
    #[ignore = "requires live Postgres (TEST_DATABASE_URL)"]
    async fn incomplete_authority_does_not_quarantine_candidate() {
        let pool = setup_test_db().await;
        let did = format!("did:plc:w2incomplete{}", Uuid::new_v4().simple());
        seed_user(&pool, &did).await;

        let (candidate_bytes, _) = generate_key_package(&did);
        let candidate_hash = seed_package(
            &pool,
            &did,
            Some("device-unresolved"),
            &candidate_bytes,
            false,
        )
        .await;

        let result = claim_current_authorized_key_package_with(
            &pool,
            &did,
            "convo-w2-incomplete-authority",
            false,
            || async {
                Err(FederationError::ResolutionFailed {
                    did: String::new(),
                    kind: crate::federation::ResolutionFailureKind::InvalidPayload(
                        "pagination incomplete".to_string(),
                    ),
                })
            },
        )
        .await;

        assert!(matches!(result, Err(FederationError::AuthFailed { .. })));
        let state: (String, bool) = sqlx::query_as(
            "SELECT state, dead_at IS NOT NULL FROM key_packages WHERE key_package_hash = $1",
        )
        .bind(candidate_hash)
        .fetch_one(&pool)
        .await
        .expect("fetch unresolved candidate state");
        assert_eq!(state, ("available".to_string(), false));
        cleanup(&pool, &did).await;
    }

    async fn assert_candidate_expiring_during_device_validation_is_never_returned(
        last_resort: bool,
    ) {
        let pool = setup_test_db().await;
        let kind = if last_resort { "lastresort" } else { "regular" };
        let did = format!("did:plc:w2nearexpiry{kind}{}", Uuid::new_v4().simple());
        seed_user(&pool, &did).await;

        let (candidate_bytes, signature_key) = generate_key_package(&did);
        seed_device(&pool, &did, "device-near-expiry", &signature_key, true).await;
        let candidate_hash = seed_package(
            &pool,
            &did,
            Some("device-near-expiry"),
            &candidate_bytes,
            last_resort,
        )
        .await;
        sqlx::query(
            "UPDATE key_packages \
             SET expires_at = clock_timestamp() + INTERVAL '1 second' \
             WHERE key_package_hash = $1",
        )
        .bind(&candidate_hash)
        .execute(&pool)
        .await
        .expect("set near-term candidate expiry");

        let mut device_lock = pool.begin().await.expect("begin device lock");
        sqlx::query(
            "SELECT id FROM devices \
             WHERE user_did = $1 AND device_id = 'device-near-expiry' \
             FOR UPDATE",
        )
        .bind(&did)
        .fetch_one(&mut *device_lock)
        .await
        .expect("lock candidate device row");

        let claim_pool = pool.clone();
        let claim_did = did.clone();
        let claim_key = signature_key.clone();
        let claim = tokio::spawn(async move {
            crate::db::claim_authorized_key_package_for_federation(
                &claim_pool,
                &claim_did,
                "convo-w2-near-expiry",
                std::slice::from_ref(&claim_key),
                last_resort,
            )
            .await
        });

        let mut candidate_locked = false;
        for _ in 0..20 {
            let mut probe = pool.begin().await.expect("begin candidate lock probe");
            let result = sqlx::query(
                "SELECT id FROM key_packages \
                 WHERE key_package_hash = $1 \
                 FOR UPDATE NOWAIT",
            )
            .bind(&candidate_hash)
            .fetch_one(&mut *probe)
            .await;
            probe.rollback().await.ok();
            if result.is_err() {
                candidate_locked = true;
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(25)).await;
        }
        assert!(candidate_locked, "claim transaction never locked candidate");

        tokio::time::sleep(std::time::Duration::from_millis(1100)).await;
        device_lock.commit().await.expect("release device lock");

        let fetched = claim
            .await
            .expect("join near-expiry claim")
            .expect("finish near-expiry claim");
        assert!(fetched.is_none(), "expired candidate must not be returned");

        let state: (String, bool, bool) = sqlx::query_as(
            "SELECT state, dead_at IS NOT NULL, consumed_at IS NOT NULL \
             FROM key_packages WHERE key_package_hash = $1",
        )
        .bind(candidate_hash)
        .fetch_one(&pool)
        .await
        .expect("fetch expired candidate state");
        assert_eq!(state, ("revoked".to_string(), true, false));
        cleanup(&pool, &did).await;
    }

    #[tokio::test]
    #[ignore = "requires live Postgres (TEST_DATABASE_URL)"]
    async fn regular_candidate_expiring_during_device_validation_is_never_returned() {
        assert_candidate_expiring_during_device_validation_is_never_returned(false).await;
    }

    #[tokio::test]
    #[ignore = "requires live Postgres (TEST_DATABASE_URL)"]
    async fn last_resort_candidate_expiring_during_device_validation_is_never_returned() {
        assert_candidate_expiring_during_device_validation_is_never_returned(true).await;
    }

    #[tokio::test]
    #[ignore = "requires live Postgres (TEST_DATABASE_URL)"]
    async fn federation_fetch_revalidates_reusable_last_resort_rows() {
        let pool = setup_test_db().await;
        let did = format!("did:plc:w2lastresort{}", Uuid::new_v4().simple());
        seed_user(&pool, &did).await;

        let (stale_bytes, stale_key) = generate_key_package(&did);
        seed_device(&pool, &did, "device-stale", &stale_key, false).await;
        seed_package(&pool, &did, Some("device-stale"), &stale_bytes, true).await;
        let (valid_bytes, valid_key) = generate_key_package(&did);
        seed_device(&pool, &did, "device-valid", &valid_key, true).await;
        let valid_hash = seed_package(&pool, &did, Some("device-valid"), &valid_bytes, true).await;

        for _ in 0..2 {
            let fetched = crate::db::claim_authorized_key_package_for_federation(
                &pool,
                &did,
                "convo-w2",
                std::slice::from_ref(&valid_key),
                true,
            )
            .await
            .expect("fetch authorized last-resort package")
            .expect("valid last-resort package remains reusable");
            assert_eq!(fetched.1, valid_hash);
        }
        cleanup(&pool, &did).await;
    }

    #[tokio::test]
    #[ignore = "requires live Postgres (TEST_DATABASE_URL)"]
    async fn concurrent_authorized_regular_fetch_has_exactly_one_winner() {
        let pool = setup_test_db().await;
        let did = format!("did:plc:w2race{}", Uuid::new_v4().simple());
        seed_user(&pool, &did).await;
        let (bytes, key) = generate_key_package(&did);
        seed_device(&pool, &did, "device-race", &key, true).await;
        seed_package(&pool, &did, Some("device-race"), &bytes, false).await;

        let barrier = Arc::new(Barrier::new(2));
        let mut tasks = Vec::new();
        for _ in 0..2 {
            let pool = pool.clone();
            let did = did.clone();
            let key = key.clone();
            let barrier = barrier.clone();
            tasks.push(tokio::spawn(async move {
                barrier.wait().await;
                crate::db::claim_authorized_key_package_for_federation(
                    &pool,
                    &did,
                    "convo-w2-race",
                    &[key],
                    false,
                )
                .await
            }));
        }
        let first = tasks
            .remove(0)
            .await
            .expect("first join")
            .expect("first fetch");
        let second = tasks
            .remove(0)
            .await
            .expect("second join")
            .expect("second fetch");
        assert!(
            first.is_some() ^ second.is_some(),
            "exactly one regular fetch may claim the row"
        );
        cleanup(&pool, &did).await;
    }

    #[tokio::test]
    #[ignore = "requires live Postgres (TEST_DATABASE_URL)"]
    async fn concurrent_regular_fetches_quarantine_invalid_rows_and_keep_one_winner() {
        let pool = setup_test_db().await;
        let did = format!("did:plc:w2invalidrace{}", Uuid::new_v4().simple());
        seed_user(&pool, &did).await;
        for device_id in ["legacy-a", "legacy-b"] {
            let (invalid_bytes, _) = generate_key_package(&did);
            seed_package(&pool, &did, Some(device_id), &invalid_bytes, false).await;
        }
        let (valid_bytes, key) = generate_key_package(&did);
        seed_device(&pool, &did, "device-valid", &key, true).await;
        seed_package(&pool, &did, Some("device-valid"), &valid_bytes, false).await;

        let barrier = Arc::new(Barrier::new(2));
        let mut tasks = Vec::new();
        for _ in 0..2 {
            let pool = pool.clone();
            let did = did.clone();
            let key = key.clone();
            let barrier = barrier.clone();
            tasks.push(tokio::spawn(async move {
                barrier.wait().await;
                crate::db::claim_authorized_key_package_for_federation(
                    &pool,
                    &did,
                    "convo-w2-invalid-race",
                    &[key],
                    false,
                )
                .await
            }));
        }
        let results = futures::future::try_join_all(tasks)
            .await
            .expect("join concurrent invalid-row fetches");
        let mut winners = 0;
        for result in results {
            if result.expect("fetch through invalid rows").is_some() {
                winners += 1;
            }
        }
        assert_eq!(winners, 1);
        let quarantined: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM key_packages WHERE owner_did = $1 AND state = 'revoked' AND dead_at IS NOT NULL",
        )
        .bind(&did)
        .fetch_one(&pool)
        .await
        .expect("count quarantined rows");
        assert_eq!(quarantined, 2);
        cleanup(&pool, &did).await;
    }

    #[tokio::test]
    #[ignore = "requires live Postgres (TEST_DATABASE_URL)"]
    async fn concurrent_authorized_last_resort_fetches_both_reuse_the_row() {
        let pool = setup_test_db().await;
        let did = format!("did:plc:w2lrrace{}", Uuid::new_v4().simple());
        seed_user(&pool, &did).await;
        let (bytes, key) = generate_key_package(&did);
        seed_device(&pool, &did, "device-lr-race", &key, true).await;
        seed_package(&pool, &did, Some("device-lr-race"), &bytes, true).await;

        let barrier = Arc::new(Barrier::new(2));
        let mut tasks = Vec::new();
        for _ in 0..2 {
            let pool = pool.clone();
            let did = did.clone();
            let key = key.clone();
            let barrier = barrier.clone();
            tasks.push(tokio::spawn(async move {
                barrier.wait().await;
                crate::db::claim_authorized_key_package_for_federation(
                    &pool,
                    &did,
                    "convo-w2-lr-race",
                    &[key],
                    true,
                )
                .await
            }));
        }
        for task in tasks {
            assert!(
                task.await
                    .expect("join last-resort fetch")
                    .expect("fetch last-resort")
                    .is_some(),
                "both concurrent fetches must reuse the last-resort row"
            );
        }
        cleanup(&pool, &did).await;
    }

    #[tokio::test]
    #[ignore = "requires live Postgres (TEST_DATABASE_URL)"]
    async fn last_resort_fetch_waits_for_concurrent_reuse_instead_of_skipping() {
        let pool = setup_test_db().await;
        let did = format!("did:plc:w2lrlock{}", Uuid::new_v4().simple());
        seed_user(&pool, &did).await;
        let (bytes, key) = generate_key_package(&did);
        seed_device(&pool, &did, "device-lr-lock", &key, true).await;
        let hash = seed_package(&pool, &did, Some("device-lr-lock"), &bytes, true).await;

        let mut locking_tx = pool.begin().await.expect("begin locking transaction");
        sqlx::query("SELECT id FROM key_packages WHERE key_package_hash = $1 FOR UPDATE")
            .bind(&hash)
            .fetch_one(&mut *locking_tx)
            .await
            .expect("lock last-resort row");

        let fetch_pool = pool.clone();
        let fetch_did = did.clone();
        let task = tokio::spawn(async move {
            crate::db::claim_authorized_key_package_for_federation(
                &fetch_pool,
                &fetch_did,
                "convo-w2-lr-lock",
                &[key],
                true,
            )
            .await
        });
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        locking_tx.commit().await.expect("release last-resort row");

        assert!(
            task.await
                .expect("join waiting fetch")
                .expect("fetch after lock release")
                .is_some(),
            "a reusable last-resort row must not look exhausted while another fetch holds it"
        );
        cleanup(&pool, &did).await;
    }
}
