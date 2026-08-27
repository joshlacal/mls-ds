// Exact, reject-rather-than-normalize validation for clean chat values.

use std::{collections::BTreeSet, fmt};

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use chrono::{DateTime, Datelike, NaiveDateTime, SecondsFormat, Utc};
use sha2::{Digest, Sha256};
use url::{Host, Url};
use uuid::{Uuid, Variant, Version};

use super::model::AuthPrimitiveError;

pub const MAX_SAFE_INTEGER: i64 = 9_007_199_254_740_991;
const RESERVED_TLDS: [&str; 9] = [
    "alt",
    "arpa",
    "example",
    "internal",
    "invalid",
    "local",
    "localhost",
    "onion",
    "test",
];

#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct BareDid(String);

impl BareDid {
    pub fn parse(value: &str) -> Result<Self, AuthPrimitiveError> {
        if !(12..=261).contains(&value.len()) || !value.is_ascii() {
            return Err(AuthPrimitiveError::invalid("bare DID length or encoding"));
        }
        if let Some(identifier) = value.strip_prefix("did:plc:") {
            if identifier.len() == 24
                && identifier
                    .bytes()
                    .all(|byte| byte.is_ascii_lowercase() || (b'2'..=b'7').contains(&byte))
            {
                return Ok(Self(value.to_owned()));
            }
            return Err(AuthPrimitiveError::invalid("noncanonical did:plc"));
        }
        let host = value
            .strip_prefix("did:web:")
            .ok_or_else(|| AuthPrimitiveError::invalid("unsupported DID method"))?;
        validate_handle_hostname(host)?;
        Ok(Self(value.to_owned()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Validate the participant slots from a createConversation manifest without
/// silently dropping malformed entries. The signed manifest's cardinality is
/// part of its authorization scope, so every slot must contain one canonical
/// DID and the returned list preserves source order and multiplicity.
pub fn validate_creation_participant_dids<S: AsRef<str>>(
    participants: &[Option<S>],
) -> Result<Vec<String>, AuthPrimitiveError> {
    if participants.is_empty() {
        return Err(AuthPrimitiveError::invalid(
            "createConversation requires participants",
        ));
    }
    participants
        .iter()
        .map(|did| {
            let did = did
                .as_ref()
                .ok_or_else(|| AuthPrimitiveError::invalid("missing participant userDid"))?;
            let did = did.as_ref();
            BareDid::parse(did)?;
            Ok(did.to_owned())
        })
        .collect()
}

/// Encode the existing-direct creation result through the generated closed
/// union. Keeping this at the DTO boundary makes omission of the required
/// discriminator an immediate serialization error rather than a wire drift.
pub fn encode_existing_direct_conversation_result(
    conversation_id: Uuid,
    coordinates: serde_json::Value,
) -> Result<Vec<u8>, AuthPrimitiveError> {
    let value = serde_json::json!({
        "result": {
            "$type": "blue.catbird.chat.defs#existingDirectConversationResult",
            "conversationKind": "direct",
            "conversationId": conversation_id.hyphenated().to_string(),
            "coordinates": coordinates,
        }
    });
    let value_bytes = serde_json::to_vec(&value)
        .map_err(|_| AuthPrimitiveError::invalid("cannot encode existing direct result"))?;
    let output: catbird_atproto::generated::blue_catbird::chat::create_conversation::CreateConversationOutput<jacquard_common::DefaultStr> =
        serde_json::from_slice(&value_bytes)
            .map_err(|_| AuthPrimitiveError::invalid("invalid existing direct result"))?;
    serde_json::to_vec(&output)
        .map_err(|_| AuthPrimitiveError::invalid("cannot encode existing direct result"))
}

/// Allowed durable evolution after an acceptance response is committed. The
/// replay proof may observe later recovery fulfillment, cancellation,
/// supersession, or expiry, but never an arbitrary cross-state combination.
pub fn acceptance_replay_terminal_state_allowed(
    recovery_status: &str,
    reservation_status: &str,
    package_status: &str,
) -> bool {
    match recovery_status {
        "open" => reservation_status == "active" && package_status == "reserved",
        "fulfilled" => reservation_status == "consumed" && package_status == "consumed",
        "cancelled" => reservation_status == "released" && package_status == "available",
        "superseded" => {
            reservation_status == "released" && matches!(package_status, "available" | "revoked")
        }
        "expired" => {
            matches!(reservation_status, "expired")
                && matches!(package_status, "available" | "expired")
        }
        _ => false,
    }
}

/// Recovery rows retained for an acceptance replay are bound to the
/// successor produced by that acceptance transition, never its predecessor.
pub fn acceptance_replay_coordinate_matches_successor(
    transition_next_generation: Option<i64>,
    transition_next_state_version: Option<i64>,
    recovery_generation: i64,
    recovery_state_version: i64,
) -> bool {
    transition_next_generation == Some(recovery_generation)
        && transition_next_state_version == Some(recovery_state_version)
}

impl fmt::Display for BareDid {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

pub fn basic_credential_identity(did: &BareDid, device_id: &CanonicalUuidV4) -> Vec<u8> {
    let mut identity = Vec::with_capacity(did.as_str().len() + 1 + device_id.as_str().len());
    identity.extend_from_slice(did.as_str().as_bytes());
    identity.push(b'#');
    identity.extend_from_slice(device_id.as_str().as_bytes());
    identity
}

fn validate_handle_hostname(host: &str) -> Result<(), AuthPrimitiveError> {
    if host.is_empty()
        || host.len() > 253
        || !host.is_ascii()
        || host.ends_with('.')
        || host.bytes().any(|byte| byte.is_ascii_uppercase())
    {
        return Err(AuthPrimitiveError::invalid("noncanonical DID web host"));
    }
    let labels: Vec<_> = host.split('.').collect();
    if labels.len() < 2 {
        return Err(AuthPrimitiveError::invalid(
            "DID web host requires multiple labels",
        ));
    }
    for label in &labels {
        if label.is_empty()
            || label.len() > 63
            || !label
                .bytes()
                .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
            || !label.as_bytes()[0].is_ascii_alphanumeric()
            || !label.as_bytes()[label.len() - 1].is_ascii_alphanumeric()
        {
            return Err(AuthPrimitiveError::invalid("invalid DID web host label"));
        }
    }
    let tld = labels[labels.len() - 1];
    if !tld.as_bytes()[0].is_ascii_lowercase() || RESERVED_TLDS.contains(&tld) {
        return Err(AuthPrimitiveError::invalid(
            "invalid or reserved DID web TLD",
        ));
    }
    Ok(())
}

#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct CanonicalUuidV4 {
    value: uuid::Uuid,
    text: String,
}

impl CanonicalUuidV4 {
    pub fn parse(value: &str) -> Result<Self, AuthPrimitiveError> {
        if value.len() != 36 || !value.is_ascii() {
            return Err(AuthPrimitiveError::invalid("UUID length or encoding"));
        }
        let parsed = uuid::Uuid::parse_str(value)
            .map_err(|_| AuthPrimitiveError::invalid("invalid UUID"))?;
        if parsed.get_version() != Some(Version::Random)
            || parsed.get_variant() != Variant::RFC4122
            || parsed.hyphenated().to_string() != value
        {
            return Err(AuthPrimitiveError::invalid("noncanonical UUIDv4"));
        }
        Ok(Self {
            value: parsed,
            text: value.to_owned(),
        })
    }

    pub fn as_str(&self) -> &str {
        &self.text
    }

    pub fn as_bytes(&self) -> &[u8; 16] {
        self.value.as_bytes()
    }
}

impl fmt::Display for CanonicalUuidV4 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.text)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CanonicalTimestamp {
    text: String,
    value: DateTime<Utc>,
}

impl CanonicalTimestamp {
    pub fn parse(value: &str) -> Result<Self, AuthPrimitiveError> {
        let bytes = value.as_bytes();
        if bytes.len() != 24
            || bytes[4] != b'-'
            || bytes[7] != b'-'
            || bytes[10] != b'T'
            || bytes[13] != b':'
            || bytes[16] != b':'
            || bytes[19] != b'.'
            || bytes[23] != b'Z'
            || bytes.iter().enumerate().any(|(index, byte)| {
                !matches!(index, 4 | 7 | 10 | 13 | 16 | 19 | 23) && !byte.is_ascii_digit()
            })
        {
            return Err(AuthPrimitiveError::invalid(
                "noncanonical timestamp spelling",
            ));
        }
        let seconds = (bytes[17] - b'0') * 10 + (bytes[18] - b'0');
        if seconds > 59 {
            return Err(AuthPrimitiveError::invalid(
                "leap seconds are not supported",
            ));
        }
        let naive = NaiveDateTime::parse_from_str(value, "%Y-%m-%dT%H:%M:%S%.3fZ")
            .map_err(|_| AuthPrimitiveError::invalid("invalid timestamp fields"))?;
        let parsed = DateTime::<Utc>::from_naive_utc_and_offset(naive, Utc);
        if parsed.year() < 1 || parsed.format("%Y-%m-%dT%H:%M:%S%.3fZ").to_string() != value {
            return Err(AuthPrimitiveError::invalid("noncanonical timestamp"));
        }
        Ok(Self {
            text: value.to_owned(),
            value: parsed,
        })
    }

    pub fn as_str(&self) -> &str {
        &self.text
    }

    pub fn datetime(&self) -> DateTime<Utc> {
        self.value
    }
}

/// One server-clock instant captured once for a request. Production code can
/// obtain this value only from the clock-backed constructor; signed bodies can
/// never supply or deserialize it.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TrustedRequestInstant(CanonicalTimestamp);

impl TrustedRequestInstant {
    pub(crate) fn from_datetime(value: DateTime<Utc>) -> Result<Self, AuthPrimitiveError> {
        let text = value.to_rfc3339_opts(SecondsFormat::Millis, true);
        Ok(Self(CanonicalTimestamp::parse(&text)?))
    }

    pub(crate) fn capture() -> Result<Self, AuthPrimitiveError> {
        let text = Utc::now().to_rfc3339_opts(SecondsFormat::Millis, true);
        Ok(Self(CanonicalTimestamp::parse(&text)?))
    }

    /// Construct from an already validated canonical timestamp. Production
    /// callers must only pass a value that was validated against a captured
    /// trusted instant (or bound into a verified envelope digest); this
    /// constructor never samples the clock itself.
    pub(crate) fn from_canonical(value: CanonicalTimestamp) -> Self {
        Self(value)
    }

    #[cfg(test)]
    pub(crate) fn from_canonical_for_test(value: CanonicalTimestamp) -> Self {
        Self(value)
    }

    pub fn as_canonical(&self) -> &CanonicalTimestamp {
        &self.0
    }

    pub fn as_str(&self) -> &str {
        self.0.as_str()
    }

    pub fn datetime(&self) -> DateTime<Utc> {
        self.0.datetime()
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct NumericDate(i64);

impl NumericDate {
    pub fn new(value: i64) -> Result<Self, AuthPrimitiveError> {
        if !(0..=MAX_SAFE_INTEGER).contains(&value) {
            return Err(AuthPrimitiveError::invalid(
                "NumericDate outside safe range",
            ));
        }
        Ok(Self(value))
    }

    pub fn get(self) -> i64 {
        self.0
    }

    pub fn checked_add(self, seconds: i64) -> Result<Self, AuthPrimitiveError> {
        let value = self
            .0
            .checked_add(seconds)
            .ok_or_else(|| AuthPrimitiveError::invalid("NumericDate overflow"))?;
        Self::new(value)
    }
}

pub fn enrollment_grant_expiry(
    iat: NumericDate,
    auth_time: NumericDate,
) -> Result<NumericDate, AuthPrimitiveError> {
    Ok(std::cmp::min(
        iat.checked_add(120)?,
        auth_time.checked_add(300)?,
    ))
}

#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct KeyThumbprint(String);

impl KeyThumbprint {
    pub fn parse(value: &str) -> Result<Self, AuthPrimitiveError> {
        let bytes = decode_canonical_base64url(value)?;
        if value.len() != 43 || bytes.len() != 32 {
            return Err(AuthPrimitiveError::invalid("key thumbprint length"));
        }
        Ok(Self(value.to_owned()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for KeyThumbprint {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

pub fn ed25519_key_id(public_key: &[u8]) -> Result<KeyThumbprint, AuthPrimitiveError> {
    if public_key.len() != 32 {
        return Err(AuthPrimitiveError::invalid("Ed25519 public key length"));
    }
    KeyThumbprint::parse(&URL_SAFE_NO_PAD.encode(Sha256::digest(public_key)))
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProofJti {
    text: String,
    decoded: Vec<u8>,
}

impl ProofJti {
    pub fn parse(value: &str) -> Result<Self, AuthPrimitiveError> {
        let decoded = decode_canonical_base64url(value)?;
        if !(12..=32).contains(&decoded.len()) || !(16..=43).contains(&value.len()) {
            return Err(AuthPrimitiveError::invalid("DPoP proof jti length"));
        }
        Ok(Self {
            text: value.to_owned(),
            decoded,
        })
    }

    pub fn as_str(&self) -> &str {
        &self.text
    }

    pub fn decoded(&self) -> &[u8] {
        &self.decoded
    }
}

pub(crate) fn decode_canonical_base64url(value: &str) -> Result<Vec<u8>, AuthPrimitiveError> {
    if value.is_empty()
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_')
    {
        return Err(AuthPrimitiveError::invalid("noncanonical base64url"));
    }
    let decoded = URL_SAFE_NO_PAD
        .decode(value)
        .map_err(|_| AuthPrimitiveError::invalid("invalid base64url"))?;
    if URL_SAFE_NO_PAD.encode(&decoded) != value {
        return Err(AuthPrimitiveError::invalid(
            "noncanonical base64url encoding",
        ));
    }
    Ok(decoded)
}

/// Validates the signed timestamp for a first execution only. Completed replay
/// handling belongs to the repository after it has matched both the stored
/// canonical digest and the independently stored signature; there is no public
/// age-bypass mode in this primitive layer.
pub fn validate_first_execution_signed_at(
    signed_at: &CanonicalTimestamp,
    trusted_instant: &TrustedRequestInstant,
) -> Result<(), AuthPrimitiveError> {
    let trusted_ms = trusted_instant.datetime().timestamp_millis();
    let lower = trusted_ms
        .checked_sub(300_000)
        .ok_or_else(|| AuthPrimitiveError::invalid("signedAt lower-bound overflow"))?;
    let upper = trusted_ms
        .checked_add(60_000)
        .ok_or_else(|| AuthPrimitiveError::invalid("signedAt upper-bound overflow"))?;
    if !(lower..=upper).contains(&signed_at.datetime().timestamp_millis()) {
        return Err(AuthPrimitiveError::invalid(
            "signedAt outside trusted window",
        ));
    }
    Ok(())
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TrustedExternalBase(String);

impl TrustedExternalBase {
    pub fn parse(
        value: &str,
        allowed_nondefault_ports: &BTreeSet<u16>,
    ) -> Result<Self, AuthPrimitiveError> {
        if !value.is_ascii() || !value.starts_with("https://") {
            return Err(AuthPrimitiveError::invalid(
                "external base must be ASCII HTTPS",
            ));
        }
        let parsed =
            Url::parse(value).map_err(|_| AuthPrimitiveError::invalid("invalid external base"))?;
        if parsed.scheme() != "https"
            || !parsed.username().is_empty()
            || parsed.password().is_some()
            || parsed.query().is_some()
            || parsed.fragment().is_some()
            || parsed.path() != "/"
            || value.ends_with('/')
        {
            return Err(AuthPrimitiveError::invalid(
                "external base is not an origin",
            ));
        }
        let authority = &value["https://".len()..];
        if authority.is_empty() || authority.contains('@') || authority.contains('/') {
            return Err(AuthPrimitiveError::invalid("invalid external authority"));
        }
        let (raw_host, explicit_port) = match authority.rsplit_once(':') {
            Some((host, port))
                if !port.is_empty() && port.bytes().all(|byte| byte.is_ascii_digit()) =>
            {
                let parsed_port = port
                    .parse::<u16>()
                    .map_err(|_| AuthPrimitiveError::invalid("invalid external port"))?;
                if parsed_port.to_string() != port {
                    return Err(AuthPrimitiveError::invalid("noncanonical external port"));
                }
                (host, Some(parsed_port))
            }
            _ => (authority, None),
        };
        let parsed_host = match parsed.host() {
            Some(Host::Domain(host)) => host,
            _ => {
                return Err(AuthPrimitiveError::invalid(
                    "external host must be an A-label domain",
                ));
            }
        };
        if raw_host != parsed_host
            || raw_host.is_empty()
            || raw_host.ends_with('.')
            || raw_host.bytes().any(|byte| byte.is_ascii_uppercase())
            || !origin_hostname_is_valid(raw_host)
        {
            return Err(AuthPrimitiveError::invalid("noncanonical external host"));
        }
        let retained_port = match explicit_port {
            None | Some(443) => None,
            Some(port) if allowed_nondefault_ports.contains(&port) => Some(port),
            Some(_) => {
                return Err(AuthPrimitiveError::invalid(
                    "external port is not allowlisted",
                ));
            }
        };
        let canonical = retained_port.map_or_else(
            || format!("https://{raw_host}"),
            |port| format!("https://{raw_host}:{port}"),
        );
        Ok(Self(canonical))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn htu(&self, endpoint: &ValidatedChatNsid) -> String {
        format!("{}/xrpc/{}", self.0, endpoint.as_str())
    }
}

fn origin_hostname_is_valid(host: &str) -> bool {
    host.split('.').all(|label| {
        !label.is_empty()
            && label.len() <= 63
            && label.as_bytes()[0].is_ascii_alphanumeric()
            && label.as_bytes()[label.len() - 1].is_ascii_alphanumeric()
            && label
                .bytes()
                .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
    })
}

const CHAT_ENDPOINTS: [&str; 33] = [
    "blue.catbird.chat.enrollDevice",
    "blue.catbird.chat.replenishKeyPackages",
    "blue.catbird.chat.rebindDeviceAuthentication",
    "blue.catbird.chat.revokeDevice",
    "blue.catbird.chat.getDevices",
    "blue.catbird.chat.getOwnDevices",
    "blue.catbird.chat.createConversation",
    "blue.catbird.chat.acceptConversation",
    "blue.catbird.chat.closeConversation",
    "blue.catbird.chat.getConversations",
    "blue.catbird.chat.getConversationState",
    "blue.catbird.chat.submitTransition",
    "blue.catbird.chat.sendMessage",
    "blue.catbird.chat.getEntries",
    "blue.catbird.chat.publishTyping",
    "blue.catbird.chat.getPendingWelcomes",
    "blue.catbird.chat.acknowledgeWelcome",
    "blue.catbird.chat.rejectWelcome",
    "blue.catbird.chat.requestLeafRecovery",
    "blue.catbird.chat.cancelLeafRecovery",
    "blue.catbird.chat.getLeafRecoveryInbox",
    "blue.catbird.chat.requestReset",
    "blue.catbird.chat.activateReset",
    "blue.catbird.chat.requestLeave",
    "blue.catbird.chat.cancelLeave",
    "blue.catbird.chat.prepareBlobUpload",
    "blue.catbird.chat.uploadBlob",
    "blue.catbird.chat.deleteBlob",
    "blue.catbird.chat.getBlob",
    "blue.catbird.chat.getBlobUsage",
    "blue.catbird.chat.getSubscriptionTicket",
    "blue.catbird.chat.subscribeEvents",
    "blue.catbird.chat.updatePushToken",
];

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ValidatedChatNsid(&'static str);

impl ValidatedChatNsid {
    pub fn parse(value: &str) -> Result<Self, AuthPrimitiveError> {
        CHAT_ENDPOINTS
            .iter()
            .copied()
            .find(|candidate| *candidate == value)
            .map(Self)
            .ok_or_else(|| AuthPrimitiveError::invalid("unknown clean-chat endpoint"))
    }

    pub fn as_str(&self) -> &'static str {
        self.0
    }

    pub(crate) fn dpop_method(&self) -> Result<CanonicalHttpMethod, AuthPrimitiveError> {
        match self.0 {
            "blue.catbird.chat.getDevices"
            | "blue.catbird.chat.getOwnDevices"
            | "blue.catbird.chat.getConversations"
            | "blue.catbird.chat.getConversationState"
            | "blue.catbird.chat.getEntries"
            | "blue.catbird.chat.getPendingWelcomes"
            | "blue.catbird.chat.getLeafRecoveryInbox"
            | "blue.catbird.chat.getBlob"
            | "blue.catbird.chat.getBlobUsage" => Ok(CanonicalHttpMethod("GET")),
            "blue.catbird.chat.subscribeEvents" => Err(AuthPrimitiveError::invalid(
                "subscription tickets do not use DPoP request authentication",
            )),
            _ => Ok(CanonicalHttpMethod("POST")),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CanonicalHttpMethod(&'static str);

impl CanonicalHttpMethod {
    pub fn parse(value: &str) -> Result<Self, AuthPrimitiveError> {
        match value {
            "GET" => Ok(Self("GET")),
            "POST" => Ok(Self("POST")),
            _ => Err(AuthPrimitiveError::invalid("HTTP method is not canonical")),
        }
    }

    pub fn as_str(&self) -> &'static str {
        self.0
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DpopAuthorization<'a>(&'a str);

impl<'a> DpopAuthorization<'a> {
    pub fn parse(value: &'a str) -> Result<Self, AuthPrimitiveError> {
        let token = value
            .strip_prefix("DPoP ")
            .ok_or_else(|| AuthPrimitiveError::invalid("authorization scheme must be DPoP"))?;
        if token.is_empty() || token.bytes().any(|byte| byte.is_ascii_whitespace()) {
            return Err(AuthPrimitiveError::invalid(
                "invalid DPoP authorization value",
            ));
        }
        Ok(Self(token))
    }

    pub fn token(&self) -> &'a str {
        self.0
    }
}
