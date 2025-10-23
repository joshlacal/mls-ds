use crate::models::ExternalAsset;

/// Validation configuration for external assets
pub struct AssetValidationConfig {
    pub max_size_bytes: u64,
    pub providers_allowlist: Vec<String>,
}

impl Default for AssetValidationConfig {
    fn default() -> Self {
        Self {
            max_size_bytes: 50 * 1024 * 1024, // 50MB default
            providers_allowlist: vec![
                "cloudkit".to_string(),
                "firestore".to_string(),
                "gdrive".to_string(),
                "s3".to_string(),
                "custom".to_string(),
            ],
        }
    }
}

/// Validate ExternalAsset pointer according to policy
pub fn validate_asset(asset: &ExternalAsset, config: &AssetValidationConfig) -> Result<(), String> {
    // Check provider allowlist
    if !config.providers_allowlist.contains(&asset.provider) {
        return Err(format!(
            "Provider '{}' not in allowlist: {:?}",
            asset.provider, config.providers_allowlist
        ));
    }

    // Check size limit
    if asset.size < 0 {
        return Err("Asset size cannot be negative".to_string());
    }
    if asset.size as u64 > config.max_size_bytes {
        return Err(format!(
            "Asset size {} exceeds max {} bytes",
            asset.size, config.max_size_bytes
        ));
    }

    // Validate SHA-256 hash is exactly 32 bytes
    if asset.sha256.len() != 32 {
        return Err(format!(
            "SHA-256 hash must be 32 bytes, got {}",
            asset.sha256.len()
        ));
    }

    // Validate URI is not empty and has proper format
    if asset.uri.is_empty() {
        return Err("Asset URI cannot be empty".to_string());
    }

    // Provider-specific URI validation
    match asset.provider.as_str() {
        "cloudkit" => {
            if !asset.uri.starts_with("cloudkit://") {
                return Err("CloudKit URI must start with 'cloudkit://'".to_string());
            }
        }
        "firestore" => {
            if !asset.uri.starts_with("firestore://") {
                return Err("Firestore URI must start with 'firestore://'".to_string());
            }
        }
        "gdrive" => {
            if !asset.uri.starts_with("gdrive://") {
                return Err("Google Drive URI must start with 'gdrive://'".to_string());
            }
        }
        "s3" => {
            if !asset.uri.starts_with("s3://") {
                return Err("S3 URI must start with 's3://'".to_string());
            }
        }
        _ => {} // Custom providers don't have strict format
    }

    // Validate MIME type is present
    if asset.mime_type.is_empty() {
        return Err("Asset MIME type cannot be empty".to_string());
    }

    Ok(())
}

/// Validate a list of assets (e.g., message attachments)
pub fn validate_assets(
    assets: &[ExternalAsset],
    config: &AssetValidationConfig,
    max_attachments: usize,
) -> Result<(), String> {
    if assets.len() > max_attachments {
        return Err(format!(
            "Too many attachments: {} (max {})",
            assets.len(),
            max_attachments
        ));
    }

    for (i, asset) in assets.iter().enumerate() {
        validate_asset(asset, config).map_err(|e| format!("Attachment {}: {}", i, e))?;
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_asset() -> ExternalAsset {
        ExternalAsset {
            provider: "cloudkit".to_string(),
            uri: "cloudkit://container/zone/record".to_string(),
            size: 1024,
            mime_type: "image/jpeg".to_string(),
            sha256: vec![0u8; 32], // 32 bytes
        }
    }

    #[test]
    fn test_valid_asset() {
        let config = AssetValidationConfig::default();
        let asset = test_asset();
        assert!(validate_asset(&asset, &config).is_ok());
    }

    #[test]
    fn test_invalid_provider() {
        let config = AssetValidationConfig::default();
        let mut asset = test_asset();
        asset.provider = "forbidden".to_string();
        assert!(validate_asset(&asset, &config).is_err());
    }

    #[test]
    fn test_size_too_large() {
        let config = AssetValidationConfig::default();
        let mut asset = test_asset();
        asset.size = 100 * 1024 * 1024; // 100MB
        assert!(validate_asset(&asset, &config).is_err());
    }

    #[test]
    fn test_invalid_sha256_length() {
        let config = AssetValidationConfig::default();
        let mut asset = test_asset();
        asset.sha256 = vec![0u8; 16]; // Wrong length
        assert!(validate_asset(&asset, &config).is_err());
    }

    #[test]
    fn test_empty_uri() {
        let config = AssetValidationConfig::default();
        let mut asset = test_asset();
        asset.uri = "".to_string();
        assert!(validate_asset(&asset, &config).is_err());
    }
    
    #[test]
    fn test_invalid_uri_format() {
        let config = AssetValidationConfig::default();
        let mut asset = test_asset();
        asset.uri = "invalid://format".to_string();
        assert!(validate_asset(&asset, &config).is_err());
    }

    #[test]
    fn test_multiple_assets() {
        let config = AssetValidationConfig::default();
        let assets = vec![test_asset(), test_asset()];
        assert!(validate_assets(&assets, &config, 5).is_ok());
    }

    #[test]
    fn test_too_many_attachments() {
        let config = AssetValidationConfig::default();
        let assets = vec![test_asset(); 10];
        assert!(validate_assets(&assets, &config, 5).is_err());
    }
}
