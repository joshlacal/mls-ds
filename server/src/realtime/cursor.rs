use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use ulid::Ulid;

/// Monotonic ULID generator maintaining strict ordering per (convoId, eventType)
/// Ensures cursor strictly increases even within same millisecond by incrementing randomness
#[derive(Clone)]
pub struct CursorGenerator {
    /// Last generated ULID per stream key (convo_id:event_type)
    last_ulids: Arc<RwLock<HashMap<String, Ulid>>>,
}

impl CursorGenerator {
    pub fn new() -> Self {
        Self {
            last_ulids: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Generate next monotonic ULID for the given conversation and event type
    /// Algorithm per SUBSCRIPTIONS.md:
    /// - If timestamp > last timestamp, use new random bits
    /// - Else (same ms or clock skew), increment last random bits to preserve order
    pub async fn next(&self, convo_id: &str, event_type: &str) -> String {
        let stream_key = format!("{}:{}", convo_id, event_type);
        let mut last_ulids = self.last_ulids.write().await;

        let new_ulid = match last_ulids.get(&stream_key) {
            Some(last_ulid) => {
                let now = Ulid::new();

                // If new timestamp is greater, use it with new randomness
                if now.timestamp_ms() > last_ulid.timestamp_ms() {
                    now
                } else {
                    // Same or earlier timestamp: increment last ULID to maintain monotonicity
                    // ULID increment will handle overflow gracefully
                    match last_ulid.increment() {
                        Some(incremented) => incremented,
                        None => {
                            // Extremely rare: randomness overflow, force new timestamp
                            // Wait 1ms to ensure timestamp advances
                            tokio::time::sleep(tokio::time::Duration::from_millis(1)).await;
                            Ulid::new()
                        }
                    }
                }
            }
            None => {
                // First cursor for this stream
                Ulid::new()
            }
        };

        last_ulids.insert(stream_key, new_ulid);
        new_ulid.to_string()
    }

    /// Parse and validate a cursor string
    pub fn validate(cursor: &str) -> Result<Ulid, String> {
        Ulid::from_string(cursor).map_err(|e| format!("Invalid cursor format: {}", e))
    }

    /// Compare two cursors (returns true if a > b)
    pub fn is_greater(a: &str, b: &str) -> bool {
        match (Ulid::from_string(a), Ulid::from_string(b)) {
            (Ok(ulid_a), Ok(ulid_b)) => ulid_a > ulid_b,
            _ => false,
        }
    }

    /// Get timestamp from cursor for retention policy checks
    pub fn timestamp_ms(cursor: &str) -> Option<u64> {
        Ulid::from_string(cursor).ok().map(|u| u.timestamp_ms())
    }
}

impl Default for CursorGenerator {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_monotonic_generation() {
        let gen = CursorGenerator::new();

        // Generate multiple cursors in same millisecond
        let mut cursors = Vec::new();
        for _ in 0..10 {
            let cursor = gen.next("convo1", "messageEvent").await;
            cursors.push(cursor);
        }

        // Verify strictly increasing
        for i in 1..cursors.len() {
            assert!(
                CursorGenerator::is_greater(&cursors[i], &cursors[i - 1]),
                "Cursor {} should be > cursor {}",
                cursors[i],
                cursors[i - 1]
            );
        }
    }

    #[tokio::test]
    async fn test_different_streams() {
        let gen = CursorGenerator::new();

        let cursor1 = gen.next("convo1", "messageEvent").await;
        let cursor2 = gen.next("convo2", "messageEvent").await;

        // Different streams can have independent cursors
        assert_ne!(cursor1, cursor2);
    }

    #[test]
    fn test_cursor_validation() {
        // Valid ULID
        assert!(CursorGenerator::validate("01ARZ3NDEKTSV4RRFFQ69G5FAV").is_ok());

        // Invalid format
        assert!(CursorGenerator::validate("not-a-ulid").is_err());
        assert!(CursorGenerator::validate("").is_err());
    }

    #[test]
    fn test_timestamp_extraction() {
        let cursor = "01ARZ3NDEKTSV4RRFFQ69G5FAV";
        assert!(CursorGenerator::timestamp_ms(cursor).is_some());

        let invalid = "invalid";
        assert!(CursorGenerator::timestamp_ms(invalid).is_none());
    }
}
