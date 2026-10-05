//! Device-signed Labyrinth reads (second security review, finding 3).
//!
//! A service-auth JWT authenticates only the *account*; `actorDeviceId` on a
//! query was an unsigned claim. Every Labyrinth query therefore also carries
//! a claim signed by the named chat device's Ed25519 key:
//!
//! * header `catbird-labyrinth-read` = base64url (no padding) of the claim,
//!   the compact JSON object
//!   `{"v":1,"nsid":<NSID>,"query":<canonical query>,"did":<did>,"deviceId":<uuid>,"issuedAt":<ms>}`
//!   with exactly that key order and serde_json escaping (only `"`, `\` and
//!   control characters escaped; `/` and non-ASCII raw);
//! * header `catbird-labyrinth-read-signature` = base64url (no padding) of
//!   Ed25519 over `CATBIRD-LABYRINTH-READ\0 || claim bytes`.
//!
//! The canonical query is every query parameter of the request (including
//! `actorDeviceId`), form-decoded, sorted by (key, value) on the decoded
//! UTF-8 bytes, each key and value percent-encoded per RFC 3986 (unreserved
//! `A-Z a-z 0-9 - . _ ~` kept, every other byte `%XX` uppercase), joined as
//! `k=v` with `&`. The server checks the claim is byte-canonical, `did` is
//! the JWT issuer, `nsid` is the route, `query` is this request's,
//! `deviceId` is `actorDeviceId` and a current device whose key signed it,
//! and `issuedAt` is within 300 s of the server clock. Golden vector:
//! `tests/fixtures/labyrinth_read_header.json` (shared with the crate).
//!
//! `labyrinthRelay` forwards both header values; the sequencer re-verifies
//! them against its replicated device keys (`handlers::labyrinth::relay`).

use axum::http::HeaderMap;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use chrono::{DateTime, Utc};
use ed25519_dalek::{Signature, VerifyingKey};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use super::auth::{load_current_device, parse_device_id};
use super::error::{LabyrinthError, LabyrinthResult};
use crate::storage::DbPool;

pub const READ_HEADER: &str = "catbird-labyrinth-read";
pub const READ_SIGNATURE_HEADER: &str = "catbird-labyrinth-read-signature";
pub const READ_DOMAIN: &[u8] = b"CATBIRD-LABYRINTH-READ\0";
/// Accepted distance between `issuedAt` and the server instant.
pub const READ_SKEW_MS: i64 = 300_000;

/// The signed read claim, in its canonical field order.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ReadClaim {
    pub v: u8,
    pub nsid: String,
    pub query: String,
    pub did: String,
    pub device_id: String,
    pub issued_at: i64,
}

/// The two header values as received, kept for relaying.
#[derive(Clone, Debug)]
pub struct ReadProof {
    pub header: String,
    pub signature: String,
}

fn encode_component(value: &str, out: &mut String) {
    for b in value.bytes() {
        if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_' | b'~') {
            out.push(b as char);
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
}

/// The canonical form of a raw query string.
pub fn canonical_query(query: Option<&str>) -> String {
    let mut pairs: Vec<(String, String)> =
        url::form_urlencoded::parse(query.unwrap_or_default().as_bytes())
            .map(|(k, v)| (k.into_owned(), v.into_owned()))
            .collect();
    pairs.sort_by(|a, b| (a.0.as_bytes(), a.1.as_bytes()).cmp(&(b.0.as_bytes(), b.1.as_bytes())));
    let mut out = String::new();
    for (i, (k, v)) in pairs.iter().enumerate() {
        if i > 0 {
            out.push('&');
        }
        encode_component(k, &mut out);
        out.push('=');
        encode_component(v, &mut out);
    }
    out
}

/// The claim's signing input.
pub fn signing_input(claim_bytes: &[u8]) -> Vec<u8> {
    [READ_DOMAIN, claim_bytes].concat()
}

fn invalid_read(message: &str) -> LabyrinthError {
    LabyrinthError::invalid(format!("device-signed read: {message}"))
}

fn bad_signature() -> LabyrinthError {
    LabyrinthError::new(
        axum::http::StatusCode::UNAUTHORIZED,
        "InvalidSignature",
        "the read claim signature does not verify under the device key",
    )
}

/// Both read headers of a request.
pub fn read_proof(headers: &HeaderMap) -> LabyrinthResult<ReadProof> {
    let get = |name: &str| {
        headers
            .get(name)
            .and_then(|v| v.to_str().ok())
            .map(str::to_owned)
            .ok_or_else(|| invalid_read(&format!("missing {name} header")))
    };
    Ok(ReadProof {
        header: get(READ_HEADER)?,
        signature: get(READ_SIGNATURE_HEADER)?,
    })
}

/// Decode and canonicality-check a claim (no signature check).
pub fn parse_claim(header: &str) -> LabyrinthResult<(Vec<u8>, ReadClaim)> {
    let bytes = URL_SAFE_NO_PAD
        .decode(header)
        .map_err(|_| invalid_read("claim is not base64url"))?;
    let claim: ReadClaim =
        serde_json::from_slice(&bytes).map_err(|_| invalid_read("claim does not parse"))?;
    let canonical = serde_json::to_vec(&claim).map_err(|_| LabyrinthError::internal())?;
    if canonical != bytes || claim.v != 1 {
        return Err(invalid_read("claim is not canonical v1 JSON"));
    }
    Ok((bytes, claim))
}

/// What a verified claim must match.
pub struct Expected<'a> {
    pub did: &'a str,
    pub nsid: &'a str,
    /// The canonical query the claim must carry; `None` when the caller
    /// checks the claim's query itself (relayed `messageLive`).
    pub query: Option<&'a str>,
}

/// Verify a read proof; returns the device and the claim.
pub async fn verify(
    pool: &DbPool,
    proof: &ReadProof,
    expected: Expected<'_>,
    now: DateTime<Utc>,
) -> LabyrinthResult<(Uuid, ReadClaim)> {
    let (bytes, claim) = parse_claim(&proof.header)?;
    if claim.did != expected.did {
        return Err(invalid_read("did is not the authenticated account"));
    }
    if claim.nsid != expected.nsid {
        return Err(invalid_read("nsid does not name this endpoint"));
    }
    if expected.query.is_some_and(|q| q != claim.query) {
        return Err(invalid_read("query does not match the request"));
    }
    if (now.timestamp_millis() - claim.issued_at).abs() > READ_SKEW_MS {
        return Err(invalid_read("issuedAt is outside the accepted window"));
    }
    let device_id = parse_device_id(&claim.device_id)?;
    let sig: [u8; 64] = URL_SAFE_NO_PAD
        .decode(&proof.signature)
        .ok()
        .and_then(|s| s.try_into().ok())
        .ok_or_else(|| invalid_read("signature is not 64 base64url bytes"))?;
    let mut conn = pool.acquire().await?;
    let device = load_current_device(&mut conn, expected.did, device_id, false).await?;
    VerifyingKey::from_bytes(&device.signing_key)
        .map_err(|_| LabyrinthError::internal())?
        .verify_strict(&signing_input(&bytes), &Signature::from_bytes(&sig))
        .map_err(|_| bad_signature())?;
    Ok((device_id, claim))
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};

    #[test]
    fn golden_vector_shared_with_the_crate() {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures/labyrinth_read_header.json");
        let v: serde_json::Value =
            serde_json::from_slice(&std::fs::read(path).expect("vector")).expect("json");
        let (input, output) = (&v["input"], &v["output"]);
        let mut wire = url::form_urlencoded::Serializer::new(String::new());
        for p in input["params"].as_array().unwrap() {
            wire.append_pair(p[0].as_str().unwrap(), p[1].as_str().unwrap());
        }
        let query = canonical_query(Some(&wire.finish()));
        assert_eq!(query, output["canonicalQuery"].as_str().unwrap());
        let claim = ReadClaim {
            v: 1,
            nsid: input["nsid"].as_str().unwrap().into(),
            query,
            did: input["did"].as_str().unwrap().into(),
            device_id: input["deviceId"].as_str().unwrap().into(),
            issued_at: input["issuedAt"].as_i64().unwrap(),
        };
        let bytes = serde_json::to_vec(&claim).unwrap();
        assert_eq!(hex::encode(&bytes), output["claimHex"].as_str().unwrap());
        let header = URL_SAFE_NO_PAD.encode(&bytes);
        assert_eq!(header, output["readHeader"].as_str().unwrap());
        assert_eq!(parse_claim(&header).unwrap().1, claim);
        let seed: [u8; 32] = hex::decode(input["ed25519SeedHex"].as_str().unwrap())
            .unwrap()
            .try_into()
            .unwrap();
        let sig = SigningKey::from_bytes(&seed).sign(&signing_input(&bytes));
        assert_eq!(
            URL_SAFE_NO_PAD.encode(sig.to_bytes()),
            output["readSignatureHeader"].as_str().unwrap()
        );
    }

    #[test]
    fn non_canonical_claims_are_refused() {
        let spaced = URL_SAFE_NO_PAD
            .encode(br#"{"v":1, "nsid":"n","query":"","did":"d","deviceId":"x","issuedAt":1}"#);
        assert!(parse_claim(&spaced).is_err());
        let reordered = URL_SAFE_NO_PAD
            .encode(br#"{"nsid":"n","v":1,"query":"","did":"d","deviceId":"x","issuedAt":1}"#);
        assert!(parse_claim(&reordered).is_err());
    }
}
