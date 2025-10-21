use sha2::{Digest, Sha256};

/// Hash a value for logging/privacy (8-byte truncated SHA256)
pub fn hash_for_log(input: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(input.as_bytes());
    let result = hasher.finalize();
    format!("{:x}", &result[..8].iter().fold(0u64, |acc, &b| (acc << 8) | b as u64))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hash_for_log() {
        let hash = hash_for_log("test-convo-id");
        assert_eq!(hash.len(), 16); // 8 bytes = 16 hex chars
    }
}
