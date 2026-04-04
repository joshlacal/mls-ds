use aws_sdk_s3::{
    config::{Builder, Credentials, Region},
    primitives::ByteStream,
    Client as S3Client,
};
use tracing::{error, info, instrument};

const BUCKET: &str = "catbird-blobs";
const MAX_BLOB_SIZE: i64 = 10 * 1024 * 1024; // 10MB
const QUOTA_BYTES: i64 = 500 * 1024 * 1024; // 500MB per user
const TTL_DAYS: i64 = 90;

#[derive(Clone)]
pub struct BlobStore {
    s3: S3Client,
}

impl BlobStore {
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
        Self { s3 }
    }

    #[instrument(skip(self, data))]
    pub async fn put(&self, blob_id: &str, data: Vec<u8>) -> Result<(), BlobStoreError> {
        let size = data.len() as i64;
        if size > MAX_BLOB_SIZE {
            return Err(BlobStoreError::TooLarge(size));
        }

        self.s3
            .put_object()
            .bucket(BUCKET)
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

    #[instrument(skip(self))]
    pub async fn get(&self, blob_id: &str) -> Result<Vec<u8>, BlobStoreError> {
        let resp = self
            .s3
            .get_object()
            .bucket(BUCKET)
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

    #[instrument(skip(self))]
    pub async fn delete(&self, blob_id: &str) -> Result<(), BlobStoreError> {
        self.s3
            .delete_object()
            .bucket(BUCKET)
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

#[derive(Debug, thiserror::Error)]
pub enum BlobStoreError {
    #[error("Blob not found")]
    NotFound,
    #[error("Blob too large: {0} bytes (max {MAX_BLOB_SIZE})")]
    TooLarge(i64),
    #[error("S3 error: {0}")]
    S3Error(String),
}
