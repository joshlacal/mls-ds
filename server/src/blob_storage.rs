use anyhow::{Context, Result};
use aws_sdk_s3::Client as S3Client;
use aws_sdk_s3::config::{Credentials, Region};
use aws_sdk_s3::primitives::ByteStream;
use std::time::Duration;
use tracing::{info, warn};

/// Configuration for blob storage (Cloudflare R2)
#[derive(Debug, Clone)]
pub struct BlobStorageConfig {
    pub endpoint: String,
    pub bucket: String,
    pub access_key_id: String,
    pub secret_access_key: String,
    pub region: String,
}

impl Default for BlobStorageConfig {
    fn default() -> Self {
        Self {
            endpoint: std::env::var("R2_ENDPOINT")
                .unwrap_or_else(|_| "https://your-account-id.r2.cloudflarestorage.com".to_string()),
            bucket: std::env::var("R2_BUCKET").unwrap_or_else(|_| "catbird-messages".to_string()),
            access_key_id: std::env::var("R2_ACCESS_KEY_ID").unwrap_or_default(),
            secret_access_key: std::env::var("R2_SECRET_ACCESS_KEY").unwrap_or_default(),
            region: std::env::var("R2_REGION").unwrap_or_else(|_| "auto".to_string()),
        }
    }
}

/// Blob storage client for encrypted message storage
pub struct BlobStorage {
    client: S3Client,
    bucket: String,
}

impl BlobStorage {
    /// Create a new blob storage client
    pub async fn new(config: BlobStorageConfig) -> Result<Self> {
        info!("Initializing R2 blob storage");
        
        // Validate configuration
        if config.access_key_id.is_empty() || config.secret_access_key.is_empty() {
            warn!("R2 credentials not configured, blob storage will fail");
        }

        // Configure R2 client (S3-compatible)
        let credentials = Credentials::new(
            &config.access_key_id,
            &config.secret_access_key,
            None,
            None,
            "r2-credentials",
        );

        let s3_config = aws_sdk_s3::Config::builder()
            .endpoint_url(&config.endpoint)
            .region(Region::new(config.region))
            .credentials_provider(credentials)
            .behavior_version_latest()
            .build();

        let client = S3Client::from_conf(s3_config);

        Ok(Self {
            client,
            bucket: config.bucket,
        })
    }

    /// Store an encrypted message blob
    /// Returns the blob key (UUID-based)
    pub async fn store_blob(&self, blob_id: &str, data: Vec<u8>) -> Result<String> {
        let key = format!("messages/{}", blob_id);
        
        self.client
            .put_object()
            .bucket(&self.bucket)
            .key(&key)
            .body(ByteStream::from(data))
            .content_type("application/octet-stream")
            .send()
            .await
            .context("Failed to upload blob to R2")?;

        info!(blob_id = %blob_id, size = key.len(), "Stored blob in R2");
        Ok(key)
    }

    /// Retrieve an encrypted message blob
    pub async fn get_blob(&self, blob_id: &str) -> Result<Vec<u8>> {
        let key = format!("messages/{}", blob_id);
        
        let response = self.client
            .get_object()
            .bucket(&self.bucket)
            .key(&key)
            .send()
            .await
            .context("Failed to fetch blob from R2")?;

        let data = response.body.collect().await?.into_bytes().to_vec();
        
        info!(blob_id = %blob_id, size = data.len(), "Retrieved blob from R2");
        Ok(data)
    }

    /// Delete an encrypted message blob
    pub async fn delete_blob(&self, blob_id: &str) -> Result<()> {
        let key = format!("messages/{}", blob_id);
        
        self.client
            .delete_object()
            .bucket(&self.bucket)
            .key(&key)
            .send()
            .await
            .context("Failed to delete blob from R2")?;

        info!(blob_id = %blob_id, "Deleted blob from R2");
        Ok(())
    }

    /// Delete multiple blobs (batch cleanup)
    pub async fn delete_blobs(&self, blob_ids: Vec<String>) -> Result<()> {
        for blob_id in blob_ids {
            if let Err(e) = self.delete_blob(&blob_id).await {
                warn!(blob_id = %blob_id, error = %e, "Failed to delete blob");
            }
        }
        Ok(())
    }

    /// Get a presigned URL for direct client upload (optional optimization)
    pub async fn presign_upload(&self, blob_id: &str, ttl: Duration) -> Result<String> {
        let key = format!("messages/{}", blob_id);
        
        let presigned = self.client
            .put_object()
            .bucket(&self.bucket)
            .key(&key)
            .presigned(
                aws_sdk_s3::presigning::PresigningConfig::expires_in(ttl)
                    .context("Invalid presigning duration")?,
            )
            .await
            .context("Failed to generate presigned URL")?;

        Ok(presigned.uri().to_string())
    }

    /// Get a presigned URL for direct client download (optional optimization)
    pub async fn presign_download(&self, blob_id: &str, ttl: Duration) -> Result<String> {
        let key = format!("messages/{}", blob_id);
        
        let presigned = self.client
            .get_object()
            .bucket(&self.bucket)
            .key(&key)
            .presigned(
                aws_sdk_s3::presigning::PresigningConfig::expires_in(ttl)
                    .context("Invalid presigning duration")?,
            )
            .await
            .context("Failed to generate presigned URL")?;

        Ok(presigned.uri().to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    #[ignore] // Requires R2 credentials
    async fn test_blob_storage() {
        let config = BlobStorageConfig::default();
        let storage = BlobStorage::new(config).await.unwrap();

        let blob_id = uuid::Uuid::new_v4().to_string();
        let data = b"encrypted message data".to_vec();

        // Store
        storage.store_blob(&blob_id, data.clone()).await.unwrap();

        // Retrieve
        let retrieved = storage.get_blob(&blob_id).await.unwrap();
        assert_eq!(data, retrieved);

        // Delete
        storage.delete_blob(&blob_id).await.unwrap();
    }
}
