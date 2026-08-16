use aws_sdk_s3::{
    config::{Builder, Credentials, Region},
    primitives::ByteStream,
    Client as S3Client,
};
use sha2::{Digest, Sha256};
use tracing::{error, info, instrument};

use crate::chat_protocol::repository::blobs::{
    consume_authorized_blob_fetch, derive_blob_cid, AuthorizedBlobFetch, BlobRepositoryError,
};
use crate::storage::DbPool;

const BUCKET: &str = "catbird-blobs";
const MAX_BLOB_SIZE: i64 = 10 * 1024 * 1024; // 10MB
const QUOTA_BYTES: i64 = 500 * 1024 * 1024; // 500MB per user
const TTL_DAYS: i64 = 90;

struct BoundedPayload {
    expected: usize,
    bytes: Vec<u8>,
}

impl BoundedPayload {
    fn new(expected: usize) -> Self {
        Self {
            expected,
            bytes: Vec::with_capacity(expected.saturating_add(1)),
        }
    }

    /// Append at most one byte beyond the commitment. Returning `true` tells
    /// the caller that no more body needs to be read.
    fn push(&mut self, chunk: &[u8]) -> bool {
        let limit = self.expected.saturating_add(1);
        let remaining = limit.saturating_sub(self.bytes.len());
        if chunk.len() > remaining {
            self.bytes.extend_from_slice(&chunk[..remaining]);
            true
        } else {
            self.bytes.extend_from_slice(chunk);
            self.bytes.len() >= limit
        }
    }

    fn finish(self, expected_sha256: &[u8; 32]) -> Result<Vec<u8>, BlobStoreError> {
        if self.bytes.len() < self.expected {
            return Err(BlobStoreError::Truncated {
                expected: self.expected,
                actual: self.bytes.len(),
            });
        }
        if self.bytes.len() > self.expected {
            return Err(BlobStoreError::Oversize {
                expected: self.expected,
            });
        }
        let digest: [u8; 32] = Sha256::digest(&self.bytes).into();
        if &digest != expected_sha256 {
            return Err(BlobStoreError::HashMismatch);
        }
        Ok(self.bytes)
    }
}

#[derive(Clone)]
pub struct BlobStore {
    s3: S3Client,
    bucket: String,
}

impl BlobStore {
    /// Construct a client for route-harness tests without contacting S3.
    /// The client is inert until a route reaches an authorized object call.
    /// Its bucket is explicitly disposable and namespaced by the test DB.
    pub fn for_route_tests() -> Self {
        let suffix = std::env::var("TEST_DATABASE_URL")
            .ok()
            .and_then(|url| url.rsplit('/').next().map(str::to_owned))
            .unwrap_or_else(|| "default".to_owned());
        let suffix: String = suffix
            .chars()
            .map(|character| {
                if character.is_ascii_lowercase() || character.is_ascii_digit() || character == '-'
                {
                    character
                } else {
                    '-'
                }
            })
            .collect();
        let bucket = format!("catbird-blobs-route-test-{suffix}");
        let config = Builder::new()
            .behavior_version_latest()
            .endpoint_url("http://127.0.0.1:8333")
            .region(Region::new("us-east-1"))
            .credentials_provider(Credentials::new(
                "route-test",
                "route-test",
                None,
                None,
                "test",
            ))
            .force_path_style(true)
            .build();
        Self {
            s3: S3Client::from_conf(config),
            bucket,
        }
    }

    pub async fn new() -> Self {
        let endpoint =
            std::env::var("S3_ENDPOINT").unwrap_or_else(|_| "http://127.0.0.1:8333".to_string());
        let access_key = std::env::var("S3_ACCESS_KEY").expect("S3_ACCESS_KEY must be set");
        let secret_key = std::env::var("S3_SECRET_KEY").expect("S3_SECRET_KEY must be set");
        let region = std::env::var("S3_REGION").unwrap_or_else(|_| "us-east-1".to_string());

        let creds = Credentials::new(&access_key, &secret_key, None, None, "env");
        let config = Builder::new()
            .behavior_version_latest()
            .endpoint_url(&endpoint)
            .region(Region::new(region))
            .credentials_provider(creds)
            .force_path_style(true)
            .build();

        let s3 = S3Client::from_conf(config);

        // Ensure bucket exists (ignore error if it already exists)
        let _ = s3.create_bucket().bucket(BUCKET).send().await;

        info!("BlobStore initialized (endpoint={})", endpoint);
        Self {
            s3,
            bucket: BUCKET.to_owned(),
        }
    }

    #[instrument(skip(self, data))]
    pub async fn put(&self, blob_id: &str, data: Vec<u8>) -> Result<(), BlobStoreError> {
        let size = data.len() as i64;
        if size > MAX_BLOB_SIZE {
            return Err(BlobStoreError::TooLarge(size));
        }

        self.s3
            .put_object()
            .bucket(&self.bucket)
            .key(blob_id)
            .body(ByteStream::from(data))
            .content_type("application/octet-stream")
            .send()
            .await
            .map_err(|e| {
                error!("S3 put failed for blob {}: {}", blob_id, e);
                BlobStoreError::S3Error(e.to_string())
            })?;

        info!("Stored blob {} ({} bytes)", blob_id, size);
        Ok(())
    }

    /// Safe upload primitive for the clean blob path. The physical key is
    /// derived here from the immutable blob id and ciphertext hash; callers
    /// cannot supply or swap a raw object key. All identity metadata is written
    /// with the same S3 object PUT, and completion accepts only this CID.
    #[instrument(skip(self, data, expected_sha256))]
    pub async fn put_for_blob(
        &self,
        blob_id: uuid::Uuid,
        data: Vec<u8>,
        expected_sha256: &[u8; 32],
        media_type: &str,
    ) -> Result<(), BlobStoreError> {
        let size = data.len() as i64;
        if size <= 0 {
            return Err(BlobStoreError::InvalidExpectedSize);
        }
        if size > MAX_BLOB_SIZE {
            return Err(BlobStoreError::TooLarge(size));
        }
        let digest: [u8; 32] = Sha256::digest(&data).into();
        if &digest != expected_sha256 {
            return Err(BlobStoreError::HashMismatch);
        }
        let cid = derive_blob_cid(blob_id, expected_sha256);
        let expected_size = size.to_string();
        self.s3
            .put_object()
            .bucket(&self.bucket)
            .key(&cid)
            .body(ByteStream::from(data))
            .content_type(media_type)
            .metadata("cid", &cid)
            .metadata("sha256", hex::encode(expected_sha256))
            .metadata("size", expected_size)
            .metadata("media-type", media_type)
            .send()
            .await
            .map_err(|error| BlobStoreError::S3Error(error.to_string()))?;
        Ok(())
    }

    #[instrument(skip(self))]
    pub async fn get(&self, blob_id: &str) -> Result<Vec<u8>, BlobStoreError> {
        let resp = self
            .s3
            .get_object()
            .bucket(&self.bucket)
            .key(blob_id)
            .send()
            .await
            .map_err(|e| {
                error!("S3 get failed for blob {}: {}", blob_id, e);
                BlobStoreError::NotFound
            })?;

        let data = resp
            .body
            .collect()
            .await
            .map_err(|e| BlobStoreError::S3Error(e.to_string()))?
            .into_bytes()
            .to_vec();

        Ok(data)
    }

    /// Consume a repository authorization capability and stream exactly the
    /// immutable object it names. The response is bounded to `expected_size +
    /// 1`, which detects both truncation and oversize without allowing an
    /// untrusted object to allocate beyond the database commitment.
    #[instrument(skip(self, authorization))]
    pub async fn get_authorized(
        &self,
        pool: &DbPool,
        authorization: AuthorizedBlobFetch,
    ) -> Result<Vec<u8>, BlobStoreError> {
        let storage = consume_authorized_blob_fetch(pool, &authorization)
            .await
            .map_err(BlobStoreError::Authorization)?;
        if storage.expected_size() <= 0 || storage.expected_size() > MAX_BLOB_SIZE {
            return Err(BlobStoreError::InvalidExpectedSize);
        }
        let expected_size = usize::try_from(storage.expected_size())
            .map_err(|_| BlobStoreError::InvalidExpectedSize)?;

        let response = self
            .s3
            .get_object()
            .bucket(&self.bucket)
            .key(storage.object_store_key())
            .send()
            .await
            .map_err(|error| {
                error!("S3 authorized get failed: {}", error);
                BlobStoreError::NotFound
            })?;

        if response.content_length() != Some(storage.expected_size()) {
            return Err(BlobStoreError::MetadataMismatch("content-length"));
        }
        let metadata = response
            .metadata()
            .ok_or(BlobStoreError::MetadataMismatch("metadata"))?;
        if metadata.get("cid").map(String::as_str) != Some(storage.derived_cid())
            || metadata.get("sha256").map(String::as_str)
                != Some(&hex::encode(storage.expected_sha256()))
            || metadata.get("size").map(String::as_str)
                != Some(&storage.expected_size().to_string())
            || metadata.get("media-type").map(String::as_str) != Some(storage.media_type())
        {
            return Err(BlobStoreError::MetadataMismatch("blob identity"));
        }

        let mut body = response.body;
        let mut payload = BoundedPayload::new(expected_size);
        while let Some(chunk) = body.next().await {
            let chunk = chunk.map_err(|error| BlobStoreError::S3Error(error.to_string()))?;
            if payload.push(&chunk) {
                break;
            }
        }
        payload.finish(storage.expected_sha256())
    }

    #[instrument(skip(self))]
    pub async fn delete(&self, blob_id: &str) -> Result<(), BlobStoreError> {
        self.s3
            .delete_object()
            .bucket(&self.bucket)
            .key(blob_id)
            .send()
            .await
            .map_err(|e| {
                error!("S3 delete failed for blob {}: {}", blob_id, e);
                BlobStoreError::S3Error(e.to_string())
            })?;

        info!("Deleted blob {} from S3", blob_id);
        Ok(())
    }

    pub fn max_blob_size(&self) -> i64 {
        MAX_BLOB_SIZE
    }

    pub fn quota_bytes(&self) -> i64 {
        QUOTA_BYTES
    }

    pub fn ttl_days(&self) -> i64 {
        TTL_DAYS
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::chat_protocol::repository::blobs::{
        authorize_blob_read, AuthorizeBlobReadRequest, BlobAuthorizationTransaction,
    };
    use sqlx::postgres::PgPoolOptions;

    fn digest(bytes: &[u8]) -> [u8; 32] {
        Sha256::digest(bytes).into()
    }

    #[test]
    fn bounded_payload_accepts_exact_chunked_body() {
        let mut payload = BoundedPayload::new(5);
        assert!(!payload.push(b"ab"));
        assert!(!payload.push(b"cde"));
        assert_eq!(payload.finish(&digest(b"abcde")).unwrap(), b"abcde");
    }

    #[test]
    fn bounded_payload_rejects_truncation_and_oversize() {
        let mut truncated = BoundedPayload::new(5);
        truncated.push(b"abcd");
        assert!(matches!(
            truncated.finish(&digest(b"abcd")),
            Err(BlobStoreError::Truncated {
                expected: 5,
                actual: 4
            })
        ));

        let mut oversized = BoundedPayload::new(5);
        assert!(oversized.push(b"abcdef"));
        assert!(matches!(
            oversized.finish(&digest(b"abcde")),
            Err(BlobStoreError::Oversize { expected: 5 })
        ));
    }

    #[test]
    fn bounded_payload_rejects_corruption_after_size_check() {
        let mut payload = BoundedPayload::new(5);
        payload.push(b"abcde");
        assert!(matches!(
            payload.finish(&digest(b"abXde")),
            Err(BlobStoreError::HashMismatch)
        ));
    }

    #[tokio::test]
    #[ignore = "requires S3_ENDPOINT, S3_ACCESS_KEY, S3_SECRET_KEY, TEST_DATABASE_URL, and TEST_BLOB_* seeded fixture; run explicitly with cargo test -- --ignored"]
    async fn s3_fixture_upload_read_and_object_swap_target() {
        for variable in [
            "S3_ENDPOINT",
            "S3_ACCESS_KEY",
            "S3_SECRET_KEY",
            "TEST_DATABASE_URL",
            "TEST_BLOB_ID",
            "TEST_BLOB_CALLER_DID",
            "TEST_BLOB_CALLER_DEVICE_ID",
            "TEST_BLOB_AUTH_GENERATION",
            "TEST_BLOB_PAYLOAD_HEX",
        ] {
            assert!(
                std::env::var(variable).is_ok(),
                "{variable} is required for this ignored S3 integration test"
            );
        }
        let database_url = std::env::var("TEST_DATABASE_URL").unwrap();
        let blob_id: uuid::Uuid = std::env::var("TEST_BLOB_ID")
            .unwrap()
            .parse()
            .expect("TEST_BLOB_ID must be a UUID");
        let caller_did = std::env::var("TEST_BLOB_CALLER_DID").unwrap();
        let caller_device_id: uuid::Uuid = std::env::var("TEST_BLOB_CALLER_DEVICE_ID")
            .unwrap()
            .parse()
            .expect("TEST_BLOB_CALLER_DEVICE_ID must be a UUID");
        let auth_generation: i64 = std::env::var("TEST_BLOB_AUTH_GENERATION")
            .unwrap()
            .parse()
            .expect("TEST_BLOB_AUTH_GENERATION must be an integer");
        let data = hex::decode(std::env::var("TEST_BLOB_PAYLOAD_HEX").unwrap())
            .expect("TEST_BLOB_PAYLOAD_HEX must be valid hex");
        assert!(!data.is_empty(), "seeded payload must not be empty");
        let pool = PgPoolOptions::new()
            .max_connections(4)
            .connect(&database_url)
            .await
            .expect("TEST_DATABASE_URL must name a reachable Postgres instance");
        let (stored_hash, expected_size, media_type): (Vec<u8>, i64, String) = sqlx::query_as(
            "SELECT ciphertext_sha256, ciphertext_size, media_type FROM chat.blobs WHERE blob_id = $1",
        )
        .bind(blob_id)
        .fetch_one(&pool)
        .await
        .expect("seeded TEST_BLOB_ID must exist");
        let expected_sha256: [u8; 32] = stored_hash
            .as_slice()
            .try_into()
            .expect("seeded ciphertext hash must be SHA-256");
        assert_eq!(
            expected_size,
            data.len() as i64,
            "payload must match DB size"
        );
        assert_eq!(Sha256::digest(&data).as_slice(), &expected_sha256);
        let store = BlobStore::new().await;
        store
            .put_for_blob(blob_id, data.clone(), &expected_sha256, &media_type)
            .await
            .expect("fixture upload");
        let cid = derive_blob_cid(blob_id, &expected_sha256);
        async fn authorize_fixture(
            pool: &crate::storage::DbPool,
            blob_id: uuid::Uuid,
            caller_did: &str,
            caller_device_id: uuid::Uuid,
            auth_generation: i64,
        ) -> AuthorizedBlobFetch {
            let authority = BlobAuthorizationTransaction::begin(pool)
                .await
                .expect("begin top-level authority transaction");
            authorize_blob_read(
                authority,
                &AuthorizeBlobReadRequest {
                    blob_id,
                    caller_did: caller_did.to_owned(),
                    caller_device_id,
                    auth_generation,
                },
            )
            .await
            .expect("seeded fixture must authorize")
            .publicize()
            .await
            .expect("authorization must be minted only after commit")
        }

        let authorization = authorize_fixture(
            &pool,
            blob_id,
            &caller_did,
            caller_device_id,
            auth_generation,
        )
        .await;
        assert_eq!(
            store
                .get_authorized(&pool, authorization)
                .await
                .expect("authorized fixture read"),
            data
        );

        // A swapped identity metadata value is rejected through the complete
        // authorize -> commit -> consume -> S3 path, before bytes are returned.
        store
            .s3
            .put_object()
            .bucket(BUCKET)
            .key(&cid)
            .body(ByteStream::from(data.clone()))
            .metadata("cid", "attacker-cid")
            .metadata("sha256", hex::encode(expected_sha256))
            .metadata("size", expected_size.to_string())
            .metadata("media-type", &media_type)
            .send()
            .await
            .expect("fixture metadata swap");
        assert!(matches!(
            store
                .get_authorized(
                    &pool,
                    authorize_fixture(
                        &pool,
                        blob_id,
                        &caller_did,
                        caller_device_id,
                        auth_generation,
                    )
                    .await,
                )
                .await,
            Err(BlobStoreError::MetadataMismatch("blob identity"))
        ));

        // A body swap with truthful metadata reaches the bounded stream
        // verifier and is rejected by the immutable ciphertext hash.
        let mut swapped_body = data.clone();
        swapped_body[0] ^= 0xFF;
        store
            .s3
            .put_object()
            .bucket(BUCKET)
            .key(&cid)
            .body(ByteStream::from(swapped_body))
            .metadata("cid", &cid)
            .metadata("sha256", hex::encode(expected_sha256))
            .metadata("size", expected_size.to_string())
            .metadata("media-type", &media_type)
            .send()
            .await
            .expect("fixture body swap");
        assert!(matches!(
            store
                .get_authorized(
                    &pool,
                    authorize_fixture(
                        &pool,
                        blob_id,
                        &caller_did,
                        caller_device_id,
                        auth_generation,
                    )
                    .await,
                )
                .await,
            Err(BlobStoreError::HashMismatch)
        ));

        // An attacker-controlled key is never consulted: authorization keeps
        // the deterministic CID, so moving the body to another key fails as a
        // not-found read rather than following a caller-supplied object key.
        let attacker_key = format!("attacker/{}", uuid::Uuid::new_v4());
        store
            .delete(&cid)
            .await
            .expect("remove deterministic object");
        store
            .s3
            .put_object()
            .bucket(BUCKET)
            .key(&attacker_key)
            .body(ByteStream::from(data))
            .send()
            .await
            .expect("fixture attacker key");
        assert!(matches!(
            store
                .get_authorized(
                    &pool,
                    authorize_fixture(
                        &pool,
                        blob_id,
                        &caller_did,
                        caller_device_id,
                        auth_generation,
                    )
                    .await,
                )
                .await,
            Err(BlobStoreError::NotFound)
        ));
        store.delete(&cid).await.expect("fixture cleanup");
        store.delete(&attacker_key).await.expect("fixture cleanup");
    }
}

#[derive(Debug, thiserror::Error)]
pub enum BlobStoreError {
    #[error("Blob not found")]
    NotFound,
    #[error("Blob too large: {0} bytes (max {MAX_BLOB_SIZE})")]
    TooLarge(i64),
    #[error("S3 error: {0}")]
    S3Error(String),
    #[error("authorized fetch denied: {0:?}")]
    Authorization(BlobRepositoryError),
    #[error("invalid expected blob size")]
    InvalidExpectedSize,
    #[error("blob stream truncated: expected {expected} bytes, got {actual}")]
    Truncated { expected: usize, actual: usize },
    #[error("blob stream exceeds expected size of {expected} bytes")]
    Oversize { expected: usize },
    #[error("blob ciphertext hash mismatch")]
    HashMismatch,
    #[error("blob object metadata mismatch: {0}")]
    MetadataMismatch(&'static str),
}
