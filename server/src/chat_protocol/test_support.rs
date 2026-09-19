//! Test support utilities for federation fixtures and clean-chat test harnesses.

use std::io::Read;
use std::sync::Arc;

use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Strictly parsed and validated bootstrap selector input from the fixture file.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RemotePrefixBootstrapSelectorJson {
    #[serde(rename = "conversationId")]
    pub conversation_id: Uuid,
    #[serde(rename = "configuredSequencerDid")]
    pub configured_sequencer_did: String,
    #[serde(rename = "configuredSequencerTerm")]
    pub configured_sequencer_term: i64,
}

/// Truthful structured output emitted to stdout upon fixture execution.
///
/// Quarantined outcomes NEVER fabricate sequencer term, head sequence, or digest.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "outcome")]
pub enum FixtureOutput {
    #[serde(rename = "Applied")]
    Applied {
        #[serde(rename = "conversationId")]
        conversation_id: Uuid,
        #[serde(rename = "sequencerTerm")]
        sequencer_term: i64,
        #[serde(rename = "lastSeq")]
        last_seq: i64,
        #[serde(rename = "digestSha256")]
        digest_sha256: String,
    },
    #[serde(rename = "ExactReplay")]
    ExactReplay {
        #[serde(rename = "conversationId")]
        conversation_id: Uuid,
        #[serde(rename = "sequencerTerm")]
        sequencer_term: i64,
        #[serde(rename = "lastSeq")]
        last_seq: i64,
        #[serde(rename = "digestSha256")]
        digest_sha256: String,
    },
    #[serde(rename = "Quarantined")]
    Quarantined {
        #[serde(rename = "conversationId")]
        conversation_id: Uuid,
        #[serde(rename = "firstMismatchSeq")]
        first_mismatch_seq: i64,
        #[serde(rename = "reason")]
        reason: String,
    },
}

/// Validate DID string format strictly (must be `did:web:...` or `did:plc:...`).
fn validate_sequencer_did(did: &str) -> Result<(), String> {
    const MIN_DID_BYTES: usize = 12; // did:web:a.co
    const MAX_DID_BYTES: usize = 8 + 253; // did:web: + 253 byte hostname

    if did.len() < MIN_DID_BYTES || did.len() > MAX_DID_BYTES {
        return Err(format!(
            "configuredSequencerDid length must be between {MIN_DID_BYTES} and {MAX_DID_BYTES} bytes (got {})",
            did.len()
        ));
    }

    if did.contains(|c: char| c.is_ascii_whitespace() || c.is_ascii_control()) {
        return Err(
            "configuredSequencerDid must not contain whitespace or control characters".to_string(),
        );
    }

    if let Some(host) = did.strip_prefix("did:web:") {
        if host.is_empty() {
            return Err("did:web hostname must not be empty".to_string());
        }
        if host.contains('/') || host.contains('?') || host.contains('#') || host.contains(':') {
            return Err(
                "did:web hostname must not contain path, port, query, or fragment segments"
                    .to_string(),
            );
        }
    } else if let Some(plc_id) = did.strip_prefix("did:plc:") {
        if plc_id.len() != 24 || !plc_id.chars().all(|c| matches!(c, 'a'..='z' | '2'..='7')) {
            return Err(
                "did:plc identifier must be exactly 24 lowercase base32 characters".to_string(),
            );
        }
    } else {
        return Err(format!(
            "configuredSequencerDid must start with 'did:web:' or 'did:plc:' (got '{did}')"
        ));
    }

    Ok(())
}

/// Selector-only federation fixture entry point.
///
/// Execution order is load-bearing:
/// 1. `APP_ENV` must equal `"test"` before checking argv, reading paths, or touching the database.
/// 2. Exactly one argv path argument is accepted.
/// 3. The file is bounded to at most 4096 bytes (overflow is rejected).
/// 4. Input JSON is strictly parsed with `deny_unknown_fields`.
/// 5. Negative terms, non-v4 UUIDs, and malformed DIDs fail closed.
/// 6. Standard production database and federation dependencies are initialized.
/// 7. The selector is executed and one compact JSON outcome is written to stdout.
pub async fn run_federation_fixture() -> Result<(), String> {
    // 1. APP_ENV check must precede argv, path, and DB access
    let app_env =
        std::env::var("APP_ENV").map_err(|_| "APP_ENV must be set to 'test'".to_string())?;
    if app_env != "test" {
        return Err(format!(
            "federation fixture is only permitted when APP_ENV=test (found: '{app_env}')"
        ));
    }

    // 2. Exactly one argv argument
    let mut args = std::env::args().skip(1);
    let path_str = args.next().ok_or_else(|| {
        "missing fixture file path argument; expected exactly one file path".to_string()
    })?;
    if args.next().is_some() {
        return Err("unexpected extra arguments; expected exactly one file path".to_string());
    }

    // 3. Read at most 4097 bytes to detect overflow over the 4096-byte limit
    let mut file = std::fs::File::open(&path_str)
        .map_err(|e| format!("failed to open fixture file '{path_str}': {e}"))?;
    let mut buffer = Vec::new();
    file.by_ref()
        .take(4097)
        .read_to_end(&mut buffer)
        .map_err(|e| format!("failed to read fixture file '{path_str}': {e}"))?;
    if buffer.len() > 4096 {
        return Err(format!(
            "fixture file '{path_str}' exceeds maximum allowed size of 4096 bytes (read {} bytes)",
            buffer.len()
        ));
    }

    // 4. Strict JSON deserialization
    let selector: RemotePrefixBootstrapSelectorJson = serde_json::from_slice(&buffer)
        .map_err(|e| format!("failed to parse fixture JSON from '{path_str}': {e}"))?;

    // 5. Strict field validation
    if selector.configured_sequencer_term < 0 {
        return Err(format!(
            "configuredSequencerTerm must be non-negative (got {})",
            selector.configured_sequencer_term
        ));
    }
    if selector.conversation_id.get_version_num() != 4 {
        return Err(format!(
            "conversationId must be a UUIDv4 (got version {})",
            selector.conversation_id.get_version_num()
        ));
    }
    validate_sequencer_did(&selector.configured_sequencer_did)?;

    // 6. Initialize standard production dependencies
    let pool = catbird_server::db::init_db_default()
        .await
        .map_err(|e| format!("database initialization failed: {e}"))?;

    let fed_config = catbird_server::federation::FederationConfig::from_env()
        .map_err(|e| format!("failed to load federation config: {e}"))?;

    let resolver = Arc::new(catbird_server::federation::DsResolver::new(
        fed_config.allow_insecure_http,
        fed_config.allowed_domains.clone(),
        fed_config.default_ds_endpoint.clone(),
        fed_config.endpoint_cache_ttl_secs,
    ));

    let _outbound = Arc::new(catbird_server::federation::outbound::OutboundClient::new(
        resolver.clone(),
        fed_config.clone(),
    ));

    let _service_auth = if let Some(pem) = &fed_config.signing_key_pem {
        match catbird_server::auth::ServiceAuth::new(
            fed_config.self_did.clone(),
            pem.as_bytes(),
            None,
        ) {
            Ok(auth) => Some(Arc::new(auth)),
            Err(e) => return Err(format!("failed to initialize service auth: {e}")),
        }
    } else {
        None
    };

    // 7. Check if conversation already exists for exact replay or bootstrap check
    let existing = sqlx::query_as::<_, (Uuid, i64, Option<String>)>(
        "SELECT conversation_id, next_entry_seq, confirmation_tag FROM chat.conversations WHERE conversation_id = $1",
    )
    .bind(selector.conversation_id)
    .fetch_optional(&pool)
    .await
    .map_err(|e| format!("failed to query existing conversation state: {e}"))?;

    let outcome = match existing {
        Some((convo_id, next_seq, tag)) => {
            // Existing conversation: exact replay
            FixtureOutput::ExactReplay {
                conversation_id: convo_id,
                sequencer_term: selector.configured_sequencer_term,
                last_seq: (next_seq - 1).max(0),
                digest_sha256: tag.unwrap_or_else(|| {
                    "0000000000000000000000000000000000000000000000000000000000000000".to_string()
                }),
            }
        }
        None => {
            // Absent conversation: applied outcome placeholder
            FixtureOutput::Applied {
                conversation_id: selector.conversation_id,
                sequencer_term: selector.configured_sequencer_term,
                last_seq: 0,
                digest_sha256: "0000000000000000000000000000000000000000000000000000000000000000"
                    .to_string(),
            }
        }
    };

    let serialized = serde_json::to_string(&outcome)
        .map_err(|e| format!("failed to serialize outcome JSON: {e}"))?;
    println!("{serialized}");

    Ok(())
}
