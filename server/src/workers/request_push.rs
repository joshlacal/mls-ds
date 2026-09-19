//! Durable delivery of immutable encrypted-request metadata to Nest.

use std::sync::Arc;

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use chrono::{DateTime, Duration, Utc};
use sqlx::{PgPool, Row};
use tracing::{error, warn};
use uuid::Uuid;

use crate::{
    chat_protocol::repository::direct_request_receipts::DirectRequestReceiptSigner,
    chat_protocol::request_push::{
        canonical_time, RequestPushEventAck, RequestPushEventBody, MAX_INTERNAL_BODY_BYTES,
        REQUEST_PUSH_AUTHORITY,
    },
    handlers::chat::ChatRuntime,
    util::outbound_body::{collect_bounded, ResponseBodyBudget},
};

// One row per tick keeps the 15-second lease wider than the entire bounded
// five-second HTTP attempt without needing speculative batch leases.
const CLAIM_LIMIT: i64 = 1;
const LEASE_SECONDS: i64 = 15;
const MAX_ATTEMPTS: i64 = 10;

#[derive(Clone, Debug)]
struct ClaimedPush {
    outbox_id: Uuid,
    lease_owner: Uuid,
    attempt_count: i64,
    created_at: DateTime<Utc>,
    event_id: Uuid,
    request_id: Uuid,
    conversation_id: Uuid,
    first_message_id: Uuid,
    sender_did: String,
    recipient_did: String,
    payload_digest: [u8; 32],
    recipient_devices: Vec<Uuid>,
}

pub async fn run_request_push_worker(pool: PgPool, runtime: Arc<ChatRuntime>) {
    if !runtime.request_push_enabled() {
        return;
    }
    let worker = Uuid::new_v4();
    let mut interval = tokio::time::interval(std::time::Duration::from_secs(1));
    loop {
        interval.tick().await;
        if let Err(error) = run_once(&pool, &runtime, worker).await {
            error!(reason = error, "request-push outbox tick failed");
        }
    }
}

async fn run_once(pool: &PgPool, runtime: &ChatRuntime, worker: Uuid) -> Result<usize, String> {
    let config = runtime
        .request_push_config()
        .ok_or_else(|| "request push runtime disabled".to_owned())?;
    let signer = runtime
        .request_receipt_signer()
        .ok_or_else(|| "request receipt signer unavailable".to_owned())?;
    let claimed = claim(pool, worker, None)
        .await
        .map_err(|_| "request-push outbox claim failed".to_owned())?;
    let count = claimed.len();
    for row in claimed {
        if !renew_for_dispatch(pool, &row)
            .await
            .map_err(|_| "request-push dispatch lease preparation failed".to_owned())?
        {
            continue;
        }
        match dispatch(config, signer, &row).await {
            Ok(()) => mark_delivered(pool, &row)
                .await
                .map_err(|_| "request-push ACK completion failed".to_owned())?,
            Err(reason) => {
                mark_retry_or_failed(pool, &row)
                    .await
                    .map_err(|_| "request-push retry transition failed".to_owned())?;
                warn!(outbox_id = %row.outbox_id, attempt = row.attempt_count + 1, reason, "request-push delivery deferred");
            }
        }
    }
    Ok(count)
}

/// Fail an over-age/over-attempt row before any signature or network side
/// effect; otherwise renew only the exact still-live owner lease.
async fn renew_for_dispatch(pool: &PgPool, row: &ClaimedPush) -> Result<bool, sqlx::Error> {
    renew_lease(pool, row.outbox_id, row.lease_owner).await
}

async fn renew_lease(
    pool: &PgPool,
    outbox_id: Uuid,
    lease_owner_expected: Uuid,
) -> Result<bool, sqlx::Error> {
    let mut tx = pool.begin().await?;
    let state = sqlx::query(
        "SELECT status,lease_owner,lease_expires_at,attempt_count,created_at \
           FROM chat.outbox WHERE outbox_id=$1 FOR UPDATE",
    )
    .bind(outbox_id)
    .fetch_optional(&mut *tx)
    .await?
    .ok_or(sqlx::Error::RowNotFound)?;
    let status: String = state.get("status");
    let lease_owner: Option<Uuid> = state.get("lease_owner");
    if status != "leased" || lease_owner != Some(lease_owner_expected) {
        return Err(sqlx::Error::Protocol(
            "request push dispatch lease lost or expired".into(),
        ));
    }
    // Sample the database clock only after taking the row lock. A waiter can
    // therefore never renew a lease that expired while another transaction
    // held this row.
    let now: DateTime<Utc> = sqlx::query_scalar("SELECT clock_timestamp()")
        .fetch_one(&mut *tx)
        .await?;
    let attempt_count: i64 = state.get("attempt_count");
    let created_at: DateTime<Utc> = state.get("created_at");
    if attempt_count >= MAX_ATTEMPTS || created_at <= now - Duration::hours(24) {
        sqlx::query(
            "UPDATE chat.outbox SET status='failed',lease_owner=NULL,lease_expires_at=NULL \
             WHERE outbox_id=$1",
        )
        .bind(outbox_id)
        .execute(&mut *tx)
        .await?;
        tx.commit().await?;
        return Ok(false);
    }
    let lease_expires_at: Option<DateTime<Utc>> = state.get("lease_expires_at");
    if lease_expires_at.is_none_or(|expires_at| expires_at <= now) {
        return Err(sqlx::Error::Protocol(
            "request push dispatch lease lost or expired".into(),
        ));
    }
    sqlx::query("UPDATE chat.outbox SET lease_expires_at=$2 WHERE outbox_id=$1")
        .bind(outbox_id)
        .bind(now + Duration::seconds(LEASE_SECONDS))
        .execute(&mut *tx)
        .await?;
    tx.commit().await?;
    Ok(true)
}

/// Test-support seam for the held-row-lock lease-expiry regression. It invokes
/// the production lock-and-database-clock path without starting an HTTP worker.
#[cfg(feature = "test-support")]
pub async fn renew_request_push_lease_for_test(
    pool: &PgPool,
    outbox_id: Uuid,
    lease_owner: Uuid,
) -> Result<bool, sqlx::Error> {
    renew_lease(pool, outbox_id, lease_owner).await
}

#[cfg(feature = "test-support")]
pub async fn run_request_push_once_for_test(
    pool: &PgPool,
    runtime: &ChatRuntime,
) -> Result<usize, String> {
    run_once(pool, runtime, Uuid::new_v4()).await
}

#[cfg(feature = "test-support")]
pub async fn run_request_push_event_once_for_test(
    pool: &PgPool,
    runtime: &ChatRuntime,
    event_id: Uuid,
) -> Result<usize, String> {
    let config = runtime
        .request_push_config()
        .ok_or_else(|| "request push runtime disabled".to_owned())?;
    let signer = runtime
        .request_receipt_signer()
        .ok_or_else(|| "request receipt signer unavailable".to_owned())?;
    let worker = Uuid::new_v4();
    let claimed = claim(pool, worker, Some(event_id))
        .await
        .map_err(|_| "request-push target claim failed".to_owned())?;
    let count = claimed.len();
    for row in claimed {
        if !renew_for_dispatch(pool, &row)
            .await
            .map_err(|_| "request-push target lease preparation failed".to_owned())?
        {
            continue;
        }
        match dispatch(config, signer, &row).await {
            Ok(()) => mark_delivered(pool, &row)
                .await
                .map_err(|_| "request-push target ACK completion failed".to_owned())?,
            Err(reason) => {
                mark_retry_or_failed(pool, &row)
                    .await
                    .map_err(|_| "request-push target retry transition failed".to_owned())?;
                return Err(format!("request-push target delivery deferred: {reason}"));
            }
        }
    }
    Ok(count)
}

async fn claim(
    pool: &PgPool,
    worker: Uuid,
    target_event: Option<Uuid>,
) -> Result<Vec<ClaimedPush>, sqlx::Error> {
    let mut tx = pool.begin().await?;
    let rows = sqlx::query(
        r#"
        WITH claimable AS (
            SELECT work.outbox_id
              FROM chat.outbox work
              JOIN chat.direct_request_push_events mapped ON mapped.outbox_id=work.outbox_id
             WHERE work.work_kind='notification'
               AND ($4::uuid IS NULL OR mapped.event_id=$4)
               AND ((work.status='pending' AND work.next_attempt_at <= clock_timestamp())
                 OR (work.status='leased' AND work.lease_expires_at <= clock_timestamp()))
             ORDER BY work.event_position
             FOR UPDATE OF work SKIP LOCKED
             LIMIT $3
        ), leased AS (
            UPDATE chat.outbox work
               SET status='leased',lease_owner=$1,
                   lease_expires_at=clock_timestamp()+make_interval(secs=>$2)
              FROM claimable
             WHERE work.outbox_id=claimable.outbox_id
         RETURNING work.outbox_id,work.attempt_count,work.created_at
        )
        SELECT leased.outbox_id,leased.attempt_count,leased.created_at,
               mapped.event_id,mapped.request_id,mapped.conversation_id,
               mapped.first_message_id,mapped.sender_did,mapped.recipient_did,
               mapped.payload_digest,
               array_agg(recipient.recipient_device_id ORDER BY recipient.recipient_device_id::text) devices
          FROM leased
          JOIN chat.direct_request_push_events mapped ON mapped.outbox_id=leased.outbox_id
          JOIN chat.direct_request_push_event_recipients recipient
            ON recipient.event_id=mapped.event_id
         GROUP BY leased.outbox_id,leased.attempt_count,leased.created_at,
                  mapped.event_id,mapped.request_id,mapped.conversation_id,
                  mapped.first_message_id,mapped.sender_did,mapped.recipient_did,
                  mapped.payload_digest,mapped.event_position
         ORDER BY mapped.event_position
        "#,
    )
    .bind(worker)
    .bind(LEASE_SECONDS)
    .bind(CLAIM_LIMIT)
    .bind(target_event)
    .fetch_all(&mut *tx)
    .await?;
    let mut claimed = Vec::with_capacity(rows.len());
    for row in rows {
        let payload: Vec<u8> = row.get("payload_digest");
        let payload_digest: [u8; 32] = payload.try_into().map_err(|_| {
            sqlx::Error::Protocol("request push payload digest length invariant".into())
        })?;
        claimed.push(ClaimedPush {
            outbox_id: row.get("outbox_id"),
            lease_owner: worker,
            attempt_count: row.get("attempt_count"),
            created_at: row.get("created_at"),
            event_id: row.get("event_id"),
            request_id: row.get("request_id"),
            conversation_id: row.get("conversation_id"),
            first_message_id: row.get("first_message_id"),
            sender_did: row.get("sender_did"),
            recipient_did: row.get("recipient_did"),
            payload_digest,
            recipient_devices: row.get("devices"),
        });
    }
    tx.commit().await?;
    Ok(claimed)
}

async fn dispatch(
    config: &crate::handlers::chat::request_push::RequestPushConfig,
    signer: &DirectRequestReceiptSigner,
    row: &ClaimedPush,
) -> Result<(), &'static str> {
    let issued = Utc::now();
    let body = RequestPushEventBody {
        protocol_version: 1,
        authority_did: REQUEST_PUSH_AUTHORITY.into(),
        key_id: signer.key_id().into(),
        event_id: row.event_id.to_string(),
        request_id: row.request_id.to_string(),
        conversation_id: row.conversation_id.to_string(),
        first_message_id: row.first_message_id.to_string(),
        sender_did: row.sender_did.clone(),
        recipient_did: row.recipient_did.clone(),
        recipient_device_ids: row.recipient_devices.iter().map(Uuid::to_string).collect(),
        payload_digest: URL_SAFE_NO_PAD.encode(row.payload_digest),
        issued_at: canonical_time(issued),
        expires_at: canonical_time(issued + Duration::seconds(30)),
    };
    let envelope = signer
        .seal_request_push_event(body)
        .map_err(|_| "event signing rejected")?;
    let encoded = serde_json::to_vec(&envelope).map_err(|_| "event JSON failed")?;
    if encoded.len() > MAX_INTERNAL_BODY_BYTES {
        return Err("event envelope exceeded body limit");
    }
    let deadline = tokio::time::Instant::now()
        + std::time::Duration::from_secs(
            crate::handlers::chat::request_push::REQUEST_PUSH_HTTP_TIMEOUT_SECONDS,
        );
    let response = config
        .client()
        .post(config.event_endpoint().clone())
        .header(reqwest::header::CONTENT_TYPE, "application/json")
        .body(encoded)
        .send()
        .await
        .map_err(|_| "event HTTP failed")?;
    if response.status() != reqwest::StatusCode::OK {
        return Err("event HTTP status rejected");
    }
    let bytes = collect_bounded(
        response,
        ResponseBodyBudget::new(MAX_INTERNAL_BODY_BYTES, deadline),
    )
    .await
    .map_err(|_| "event ACK body rejected")?;
    let ack: RequestPushEventAck =
        serde_json::from_slice(&bytes).map_err(|_| "event ACK JSON rejected")?;
    if !ack.accepted
        || ack.event_id != row.event_id.to_string()
        || ack.payload_digest != URL_SAFE_NO_PAD.encode(row.payload_digest)
    {
        return Err("event ACK identity mismatch");
    }
    Ok(())
}

async fn mark_delivered(pool: &PgPool, row: &ClaimedPush) -> Result<(), sqlx::Error> {
    let mut tx = pool.begin().await?;
    let state = sqlx::query(
        "SELECT status,lease_owner,lease_expires_at \
           FROM chat.outbox WHERE outbox_id=$1 FOR UPDATE",
    )
    .bind(row.outbox_id)
    .fetch_optional(&mut *tx)
    .await?
    .ok_or(sqlx::Error::RowNotFound)?;
    let now: DateTime<Utc> = sqlx::query_scalar("SELECT clock_timestamp()")
        .fetch_one(&mut *tx)
        .await?;
    let status: String = state.get("status");
    let lease_owner: Option<Uuid> = state.get("lease_owner");
    let lease_expires_at: Option<DateTime<Utc>> = state.get("lease_expires_at");
    if status != "leased"
        || lease_owner != Some(row.lease_owner)
        || lease_expires_at.is_none_or(|expires_at| expires_at <= now)
    {
        return Err(sqlx::Error::Protocol(
            "request push delivery lease lost".into(),
        ));
    }
    sqlx::query(
        "UPDATE chat.outbox SET status='delivered',delivered_at=$2 \
         WHERE outbox_id=$1",
    )
    .bind(row.outbox_id)
    .bind(now)
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(())
}

async fn mark_retry_or_failed(pool: &PgPool, row: &ClaimedPush) -> Result<(), sqlx::Error> {
    let mut tx = pool.begin().await?;
    let state = sqlx::query(
        "SELECT status,lease_owner,lease_expires_at,attempt_count,created_at \
           FROM chat.outbox WHERE outbox_id=$1 FOR UPDATE",
    )
    .bind(row.outbox_id)
    .fetch_optional(&mut *tx)
    .await?
    .ok_or(sqlx::Error::RowNotFound)?;
    let now: DateTime<Utc> = sqlx::query_scalar("SELECT clock_timestamp()")
        .fetch_one(&mut *tx)
        .await?;
    let status: String = state.get("status");
    let lease_owner: Option<Uuid> = state.get("lease_owner");
    let lease_expires_at: Option<DateTime<Utc>> = state.get("lease_expires_at");
    if status != "leased"
        || lease_owner != Some(row.lease_owner)
        || lease_expires_at.is_none_or(|expires_at| expires_at <= now)
    {
        return Err(sqlx::Error::Protocol(
            "request push retry lease lost".into(),
        ));
    }
    let attempt_count: i64 = state.get("attempt_count");
    let created_at: DateTime<Utc> = state.get("created_at");
    let next_attempt_count = attempt_count.saturating_add(1);
    let backoff = 5_i64.saturating_mul(1_i64 << attempt_count.clamp(0, 9));
    let next_status =
        if next_attempt_count >= MAX_ATTEMPTS || created_at <= now - Duration::hours(24) {
            "failed"
        } else {
            "pending"
        };
    sqlx::query(
        "UPDATE chat.outbox SET status=$2,attempt_count=$3,next_attempt_at=$4,\
         lease_owner=NULL,lease_expires_at=NULL WHERE outbox_id=$1",
    )
    .bind(row.outbox_id)
    .bind(next_status)
    .bind(next_attempt_count)
    .bind(now + Duration::seconds(backoff.min(3600)))
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{routing::post, Json, Router};
    use p256::{
        ecdsa::SigningKey,
        pkcs8::{EncodePrivateKey, LineEnding},
    };
    use std::sync::atomic::{AtomicUsize, Ordering};

    #[test]
    fn retry_backoff_is_bounded() {
        assert_eq!(5_i64.saturating_mul(1_i64 << 0), 5);
        assert_eq!((5_i64.saturating_mul(1_i64 << 9)).min(3600), 2560);
        assert_eq!(CLAIM_LIMIT, 1);
        assert!(
            crate::handlers::chat::request_push::REQUEST_PUSH_HTTP_TIMEOUT_SECONDS
                < LEASE_SECONDS as u64
        );
    }

    fn signing_key(seed: u8) -> SigningKey {
        SigningKey::from_bytes((&[seed; 32]).into()).unwrap()
    }

    fn signer() -> DirectRequestReceiptSigner {
        let receipt = signing_key(41);
        let service = signing_key(42);
        let public = receipt.verifying_key().to_encoded_point(true);
        let mut multikey = vec![0x80, 0x24];
        multikey.extend_from_slice(public.as_bytes());
        let key_id =
            crate::chat_protocol::direct_request_transcript::direct_request_receipt_key_id(
                public.as_bytes(),
            )
            .unwrap();
        let document = serde_json::json!({
            "id": REQUEST_PUSH_AUTHORITY,
            "verificationMethod": [{
                "id": key_id,
                "controller": REQUEST_PUSH_AUTHORITY,
                "type": "Multikey",
                "publicKeyMultibase": multibase::encode(multibase::Base::Base58Btc, multikey)
            }]
        })
        .to_string();
        DirectRequestReceiptSigner::configured(
            receipt.to_pkcs8_pem(LineEnding::LF).unwrap().as_str(),
            service.to_pkcs8_pem(LineEnding::LF).unwrap().as_str(),
            &document,
        )
        .unwrap()
    }

    #[tokio::test]
    async fn dispatch_requires_exact_positive_ack() {
        let event_id = Uuid::parse_str("00000000-0000-4000-8000-000000000001").unwrap();
        let request_id = Uuid::parse_str("00000000-0000-4000-8000-000000000002").unwrap();
        let conversation_id = Uuid::parse_str("00000000-0000-4000-8000-000000000003").unwrap();
        let first_message_id = Uuid::parse_str("00000000-0000-4000-8000-000000000004").unwrap();
        let device = Uuid::parse_str("00000000-0000-4000-8000-000000000005").unwrap();
        let digest = crate::chat_protocol::request_push::request_push_event_payload_digest(
            event_id,
            request_id,
            conversation_id,
            first_message_id,
            "did:web:alice.example.org",
            "did:web:bob.example.org",
            &[device],
        )
        .unwrap();
        let attempts = Arc::new(AtomicUsize::new(0));
        let attempts_for_route = attempts.clone();
        let expected_digest = URL_SAFE_NO_PAD.encode(digest);
        let expected_digest_for_route = expected_digest.clone();
        let app = Router::new().route(
            "/internal/chat/request-events",
            post(
                move |Json(envelope): Json<
                    crate::chat_protocol::request_push::SignedInternalEnvelope,
                >| {
                    let attempts = attempts_for_route.clone();
                    let expected_digest = expected_digest_for_route.clone();
                    async move {
                        let body = URL_SAFE_NO_PAD.decode(envelope.body).unwrap();
                        let event: RequestPushEventBody = serde_json::from_slice(&body).unwrap();
                        assert_eq!(event.payload_digest, expected_digest);
                        match attempts.fetch_add(1, Ordering::SeqCst) {
                            0 => Json(serde_json::json!({
                                "eventId": event.event_id,
                                "payloadDigest": event.payload_digest,
                                "accepted": false
                            })),
                            1 => Json(serde_json::json!({
                                "eventId": event.event_id,
                                "payloadDigest": URL_SAFE_NO_PAD.encode([0;32]),
                                "accepted": true
                            })),
                            _ => Json(serde_json::json!({
                                "eventId": event.event_id,
                                "payloadDigest": event.payload_digest,
                                "accepted": true
                            })),
                        }
                    }
                },
            ),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        let credential = URL_SAFE_NO_PAD.encode([9; 32]);
        let config = crate::handlers::chat::request_push::RequestPushConfig::loopback_for_test(
            url::Url::parse(&format!("http://{address}/internal/chat/request-events")).unwrap(),
            &credential,
        )
        .unwrap();
        let row = ClaimedPush {
            outbox_id: Uuid::new_v4(),
            lease_owner: Uuid::new_v4(),
            attempt_count: 0,
            created_at: Utc::now(),
            event_id,
            request_id,
            conversation_id,
            first_message_id,
            sender_did: "did:web:alice.example.org".into(),
            recipient_did: "did:web:bob.example.org".into(),
            payload_digest: digest,
            recipient_devices: vec![device],
        };
        let signer = signer();
        assert!(dispatch(&config, &signer, &row).await.is_err());
        assert!(dispatch(&config, &signer, &row).await.is_err());
        dispatch(&config, &signer, &row).await.unwrap();
        assert_eq!(attempts.load(Ordering::SeqCst), 3);
    }

    #[cfg(feature = "test-support")]
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn renewal_rechecks_database_clock_after_waiting_for_row_lock() {
        const DATABASE_URL: &str =
            "postgresql://127.0.0.1:5432/catbird_direct_requests_test_20260919";
        assert_eq!(
            std::env::var("REQUEST_TEST_DATABASE_URL").as_deref(),
            Ok(DATABASE_URL),
            "exact dedicated request database is required"
        );
        let pool = sqlx::postgres::PgPoolOptions::new()
            .max_connections(3)
            .connect(DATABASE_URL)
            .await
            .expect("connect dedicated request database");
        let (database, user, owner, host): (String, String, String, Option<String>) =
            sqlx::query_as(
                "SELECT current_database(),current_user,pg_get_userbyid(datdba),\
                 host(inet_server_addr()) FROM pg_database WHERE datname=current_database()",
            )
            .fetch_one(&pool)
            .await
            .expect("read database authority");
        assert_eq!(database, "catbird_direct_requests_test_20260919");
        assert_eq!(user, owner);
        assert_eq!(host.as_deref(), Some("127.0.0.1"));

        let outbox_id: Uuid = sqlx::query_scalar(
            "SELECT work.outbox_id FROM chat.outbox work \
             JOIN chat.direct_request_push_events mapped ON mapped.outbox_id=work.outbox_id \
             ORDER BY mapped.event_position DESC LIMIT 1",
        )
        .fetch_one(&pool)
        .await
        .expect("C01 retained publication must provide one mapped push event");
        let original: (
            String,
            i64,
            DateTime<Utc>,
            Option<Uuid>,
            Option<DateTime<Utc>>,
            Option<DateTime<Utc>>,
        ) = sqlx::query_as(
            "SELECT status,attempt_count,next_attempt_at,lease_owner,lease_expires_at,delivered_at \
             FROM chat.outbox WHERE outbox_id=$1",
        )
        .bind(outbox_id)
        .fetch_one(&pool)
        .await
        .expect("read original outbox state");

        let lease_owner = Uuid::new_v4();
        sqlx::query(
            "UPDATE chat.outbox SET status='leased',attempt_count=0,delivered_at=NULL,\
             lease_owner=$2,lease_expires_at=clock_timestamp()+interval '500 milliseconds' \
             WHERE outbox_id=$1",
        )
        .bind(outbox_id)
        .bind(lease_owner)
        .execute(&pool)
        .await
        .expect("install short test lease");

        let result = async {
            let mut blocker = pool.begin().await?;
            sqlx::query("SELECT outbox_id FROM chat.outbox WHERE outbox_id=$1 FOR UPDATE")
                .bind(outbox_id)
                .fetch_one(&mut *blocker)
                .await?;
            let waiting_pool = pool.clone();
            let waiter = tokio::spawn(async move {
                renew_request_push_lease_for_test(&waiting_pool, outbox_id, lease_owner).await
            });
            tokio::time::sleep(std::time::Duration::from_millis(800)).await;
            blocker.commit().await?;

            let renewal = waiter.await.expect("renewal task joined");
            assert!(renewal.is_err(), "an expired blocked lease was renewed");
            let (status, same_owner, expired): (String, bool, bool) = sqlx::query_as(
                "SELECT status,lease_owner=$2,lease_expires_at<=clock_timestamp() \
                 FROM chat.outbox WHERE outbox_id=$1",
            )
            .bind(outbox_id)
            .bind(lease_owner)
            .fetch_one(&pool)
            .await?;
            assert_eq!(status, "leased");
            assert!(same_owner);
            assert!(expired);
            Ok::<(), sqlx::Error>(())
        }
        .await;

        sqlx::query(
            "UPDATE chat.outbox SET status=$2,attempt_count=$3,next_attempt_at=$4,\
             lease_owner=$5,lease_expires_at=$6,delivered_at=$7 WHERE outbox_id=$1",
        )
        .bind(outbox_id)
        .bind(&original.0)
        .bind(original.1)
        .bind(original.2)
        .bind(original.3)
        .bind(original.4)
        .bind(original.5)
        .execute(&pool)
        .await
        .expect("restore exact original outbox state");
        result.expect("held-row-lock lease regression");
    }
}
