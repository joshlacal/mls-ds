//! ADR-016 authenticated-device foundation.
//!
//! This module deliberately does not activate transition enforcement. Callers
//! must opt into [`verify_gateway_device_request`] and recheck the returned
//! generation inside their mutation transaction before it becomes authority.

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use chrono::{DateTime, Duration, Utc};
use ed25519_dalek::{Signature as Ed25519Signature, VerifyingKey as Ed25519Key};
use p256::ecdsa::{signature::Verifier, Signature as P256Signature, VerifyingKey as P256Key};
use rand::RngCore;
use serde::{
    de::{self, IgnoredAny, MapAccess, Visitor},
    Deserialize, Deserializer,
};
use sha2::{Digest, Sha256};
use sqlx::{PgPool, Postgres, Transaction};
use thiserror::Error;
use url::Url;
use uuid::Uuid;

use crate::auth::{AtProtoClaims, VerifiedGatewayBearer};

const CHALLENGE_VERSION: u16 = 1;
const CHALLENGE_TTL_SECONDS: i64 = 300;
const DPOP_MAX_CLOCK_SKEW_SECONDS: i64 = 60;
const DPOP_REPLAY_TTL_SECONDS: i64 = 120;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum DeviceAuthError {
    #[error("trusted gateway device claims are missing or malformed")]
    MissingDeviceClaims,
    #[error("issuer is not an authorized device-delegating gateway")]
    UntrustedDelegation,
    #[error("DPoP proof is missing or malformed")]
    MalformedProof,
    #[error("DPoP JWK is missing, malformed, or unsupported")]
    InvalidJwk,
    #[error("DPoP signature is invalid")]
    InvalidProofSignature,
    #[error("DPoP proof does not match the token confirmation thumbprint")]
    ThumbprintMismatch,
    #[error("DPoP proof does not match the access token")]
    TokenHashMismatch,
    #[error("DPoP proof request target mismatch")]
    RequestTargetMismatch,
    #[error("DPoP proof is outside the accepted time window")]
    ProofTimeInvalid,
    #[error("DPoP proof replay detected")]
    Replay,
    #[error("device registration is absent, inactive, rekeyed, or rebound")]
    RegistryMismatch,
    #[error("binding challenge was not found")]
    ChallengeNotFound,
    #[error("binding challenge has expired")]
    ChallengeExpired,
    #[error("binding challenge was already used")]
    ChallengeAlreadyUsed,
    #[error("binding challenge does not match the authenticated device")]
    BindingMismatch,
    #[error("MLS identity signature is invalid")]
    InvalidIdentitySignature,
    #[error("device authentication storage failure: {0}")]
    Storage(String),
}

#[derive(Debug, Clone, Deserialize)]
struct DpopHeader {
    typ: String,
    alg: String,
    jwk: P256Jwk,
}

#[derive(Debug, Clone)]
struct P256Jwk {
    kty: String,
    crv: String,
    x: String,
    y: String,
}

impl<'de> Deserialize<'de> for P256Jwk {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct P256JwkVisitor;

        impl<'de> Visitor<'de> for P256JwkVisitor {
            type Value = P256Jwk;

            fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                formatter.write_str("an RFC 7517 public EC JWK")
            }

            fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
            where
                A: MapAccess<'de>,
            {
                let mut kty = None;
                let mut crv = None;
                let mut x = None;
                let mut y = None;
                while let Some(key) = map.next_key::<String>()? {
                    match key.as_str() {
                        "kty" => set_once(&mut kty, map.next_value()?, "kty")?,
                        "crv" => set_once(&mut crv, map.next_value()?, "crv")?,
                        "x" => set_once(&mut x, map.next_value()?, "x")?,
                        "y" => set_once(&mut y, map.next_value()?, "y")?,
                        // Reject private material for every standard JWK key
                        // family, even though only public P-256 is accepted.
                        "d" | "k" | "p" | "q" | "dp" | "dq" | "qi" | "oth" => {
                            return Err(de::Error::custom("private JWK material is forbidden"));
                        }
                        // RFC 7517 public metadata (kid/use/key_ops/alg/x5*) and
                        // future public members do not affect the RFC 7638
                        // thumbprint and are intentionally ignored.
                        _ => {
                            map.next_value::<IgnoredAny>()?;
                        }
                    }
                }
                Ok(P256Jwk {
                    kty: kty.ok_or_else(|| de::Error::missing_field("kty"))?,
                    crv: crv.ok_or_else(|| de::Error::missing_field("crv"))?,
                    x: x.ok_or_else(|| de::Error::missing_field("x"))?,
                    y: y.ok_or_else(|| de::Error::missing_field("y"))?,
                })
            }
        }

        deserializer.deserialize_map(P256JwkVisitor)
    }
}

fn set_once<E>(slot: &mut Option<String>, value: String, field: &'static str) -> Result<(), E>
where
    E: de::Error,
{
    if slot.replace(value).is_some() {
        return Err(E::duplicate_field(field));
    }
    Ok(())
}

#[derive(Debug, Clone, Deserialize)]
struct DpopPayload {
    htm: String,
    htu: String,
    ath: String,
    iat: i64,
    jti: String,
}

#[derive(Debug, Deserialize)]
struct DeviceTokenPayload {
    iss: String,
    sub: Option<String>,
    device_id: Option<String>,
    cnf: Option<DeviceConfirmation>,
}

#[derive(Debug, Deserialize)]
struct DeviceConfirmation {
    jkt: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GatewayDeviceClaims {
    pub user_did: String,
    pub device_id: String,
    pub dpop_jkt: String,
}

/// Fresh, replay-protected gateway proof suitable for device enrollment.
/// Fields are private so handlers cannot construct authority from wire input.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedEnrollmentRequest {
    user_did: String,
    device_id: String,
    dpop_jkt: String,
}

/// Method and path/query captured from Axum request parts after bearer
/// authentication. The public origin is resolved from server-owned config at
/// verification time; forwarded/browser headers never participate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedRequestTarget {
    method: String,
    path: String,
    path_and_query: String,
}

impl VerifiedRequestTarget {
    pub(super) fn from_request_parts(method: &http::Method, uri: &http::Uri) -> Self {
        Self {
            method: method.as_str().to_string(),
            path: uri.path().to_string(),
            path_and_query: uri
                .path_and_query()
                .map(|value| value.as_str())
                .unwrap_or("/")
                .to_string(),
        }
    }

    fn dpop_uri(&self) -> Result<String, DeviceAuthError> {
        let endpoint = crate::identity::self_endpoint();
        self.dpop_uri_for_origin(&endpoint)
    }

    fn dpop_uri_for_origin(&self, endpoint: &str) -> Result<String, DeviceAuthError> {
        let parsed = Url::parse(endpoint).map_err(|_| DeviceAuthError::RequestTargetMismatch)?;
        if parsed.scheme() != "https"
            || parsed.username() != ""
            || parsed.password().is_some()
            || parsed.query().is_some()
            || parsed.fragment().is_some()
            || parsed.host_str().is_none()
            || !self.path.starts_with('/')
        {
            return Err(DeviceAuthError::RequestTargetMismatch);
        }
        let base_path = parsed.path().trim_end_matches('/');
        let request_already_has_base = !base_path.is_empty()
            && (self.path == base_path
                || self
                    .path
                    .strip_prefix(base_path)
                    .is_some_and(|suffix| suffix.starts_with('/')));
        if request_already_has_base {
            return Ok(format!(
                "{}{}",
                parsed.origin().ascii_serialization(),
                self.path
            ));
        }
        Ok(format!(
            "{}{}{}",
            parsed.origin().ascii_serialization(),
            base_path,
            self.path
        ))
    }
}

impl VerifiedEnrollmentRequest {
    pub fn device_id(&self) -> &str {
        &self.device_id
    }
}

/// Device authority minted only by [`verify_gateway_device_request`]. The
/// private fields prevent handlers from bypassing bearer, DPoP, target, time,
/// and replay verification by assembling a registry tuple themselves.
///
/// ```compile_fail
/// use catbird_server::auth::device_auth::VerifiedDeviceRequest;
///
/// let forged = VerifiedDeviceRequest {
///     user_did: "did:plc:alice".to_string(),
///     device_id: "device-a".to_string(),
///     dpop_jkt: "a".repeat(43),
///     auth_generation: 1,
/// };
/// ```
#[derive(Debug, PartialEq, Eq)]
pub struct VerifiedDeviceRequest {
    user_did: String,
    device_id: String,
    dpop_jkt: String,
    auth_generation: i64,
}

impl VerifiedDeviceRequest {
    pub fn user_did(&self) -> &str {
        &self.user_did
    }

    pub fn device_id(&self) -> &str {
        &self.device_id
    }

    pub fn dpop_jkt(&self) -> &str {
        &self.dpop_jkt
    }

    pub fn auth_generation(&self) -> i64 {
        self.auth_generation
    }
}

#[derive(Debug, Clone)]
pub struct BindingChallenge {
    pub challenge_id: Uuid,
    pub binding_version: u16,
    pub user_did: String,
    pub device_id: String,
    pub dpop_jkt: String,
    pub nonce: [u8; 32],
    pub expires_at: DateTime<Utc>,
}

impl BindingChallenge {
    /// Canonical length-prefixed bytes signed by the registered MLS identity
    /// key. Values cannot change field boundaries through delimiter injection.
    pub fn challenge_bytes(&self) -> Vec<u8> {
        let mut out = b"catbird-mls-device-auth\0".to_vec();
        push_u16(&mut out, self.binding_version);
        push_field(&mut out, self.user_did.as_bytes());
        push_field(&mut out, self.device_id.as_bytes());
        push_field(&mut out, self.dpop_jkt.as_bytes());
        push_field(&mut out, &self.nonce);
        push_field(&mut out, &self.expires_at.timestamp().to_be_bytes());
        out
    }
}

/// Parse a wire challenge identifier without exposing UUID parser details.
/// Handlers can map malformed values to the declared not-found outcome.
pub fn parse_binding_challenge_id(value: &str) -> Result<Uuid, DeviceAuthError> {
    Uuid::parse_str(value).map_err(|_| DeviceAuthError::ChallengeNotFound)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompletedBinding {
    pub device_id: String,
    pub bound_at: DateTime<Utc>,
    pub version: u16,
    pub auth_generation: i64,
}

fn push_u16(out: &mut Vec<u8>, value: u16) {
    out.extend_from_slice(&value.to_be_bytes());
}

fn push_field(out: &mut Vec<u8>, value: &[u8]) {
    out.extend_from_slice(&(value.len() as u32).to_be_bytes());
    out.extend_from_slice(value);
}

fn valid_jkt(value: &str) -> bool {
    value.len() == 43
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
}

fn canonical_did_claim(value: &str) -> Option<&str> {
    if value.trim() != value || value.chars().any(char::is_whitespace) {
        return None;
    }
    let did = value.split_once('#').map_or(value, |(did, fragment)| {
        if fragment.is_empty() || fragment.contains('#') {
            ""
        } else {
            did
        }
    });
    let mut parts = did.splitn(3, ':');
    match (parts.next(), parts.next(), parts.next()) {
        (Some("did"), Some(method), Some(id)) if !method.is_empty() && !id.is_empty() => Some(did),
        _ => None,
    }
}

/// Parse device claims only after the caller has established explicit
/// trusted-gateway delegation. This stays private so raw bearer material can
/// never become transition authority outside the opaque verified artifact.
fn resolve_gateway_device_claims(
    claims: &AtProtoClaims,
    trusted_gateway_dids: Option<&str>,
    gateway_token: &str,
) -> Result<GatewayDeviceClaims, DeviceAuthError> {
    let subject = claims.sub.as_deref().and_then(canonical_did_claim);
    let issuer = canonical_did_claim(&claims.iss);
    let delegated = matches!((subject, issuer), (Some(sub), Some(iss)) if sub != iss);
    if !delegated {
        return Err(DeviceAuthError::UntrustedDelegation);
    }
    let configured_gateways: Option<Vec<&str>> = trusted_gateway_dids
        .into_iter()
        .flat_map(|raw| raw.split(','))
        .map(str::trim)
        .map(canonical_did_claim)
        .collect();
    let trusted = configured_gateways
        .filter(|gateways| !gateways.is_empty())
        .is_some_and(|gateways| {
            gateways
                .into_iter()
                .any(|candidate| Some(candidate) == issuer)
        });
    if !trusted {
        return Err(DeviceAuthError::UntrustedDelegation);
    }
    let mut token_segments = gateway_token.split('.');
    let (Some(_header), Some(payload), Some(_signature), None) = (
        token_segments.next(),
        token_segments.next(),
        token_segments.next(),
        token_segments.next(),
    ) else {
        return Err(DeviceAuthError::MissingDeviceClaims);
    };
    let token_payload: DeviceTokenPayload = serde_json::from_slice(&decode_segment(payload)?)
        .map_err(|_| DeviceAuthError::MissingDeviceClaims)?;
    if token_payload.iss != claims.iss || token_payload.sub != claims.sub {
        return Err(DeviceAuthError::MissingDeviceClaims);
    }
    let device_id = token_payload
        .device_id
        .as_deref()
        .filter(|v| !v.is_empty() && v.len() <= 200 && v.trim() == *v)
        .ok_or(DeviceAuthError::MissingDeviceClaims)?;
    let jkt = token_payload
        .cnf
        .as_ref()
        .map(|cnf| cnf.jkt.as_str())
        .filter(|value| valid_jkt(value))
        .ok_or(DeviceAuthError::MissingDeviceClaims)?;
    Ok(GatewayDeviceClaims {
        user_did: subject.expect("delegated subject checked").to_string(),
        device_id: device_id.to_string(),
        dpop_jkt: jkt.to_string(),
    })
}

fn resolve_verified_gateway_device_claims(
    bearer: &VerifiedGatewayBearer,
) -> Result<GatewayDeviceClaims, DeviceAuthError> {
    if !bearer.delegated_gateway {
        return Err(DeviceAuthError::UntrustedDelegation);
    }
    // The opaque artifact exists only after the parent auth module applied the
    // configured trusted-gateway policy to this exact token.
    let device =
        resolve_gateway_device_claims(&bearer.claims, Some(&bearer.claims.iss), &bearer.token)?;
    if device.user_did != bearer.effective_user_did {
        return Err(DeviceAuthError::MissingDeviceClaims);
    }
    Ok(device)
}

fn decode_segment(segment: &str) -> Result<Vec<u8>, DeviceAuthError> {
    if segment.is_empty() || segment.contains('=') {
        return Err(DeviceAuthError::MalformedProof);
    }
    URL_SAFE_NO_PAD
        .decode(segment)
        .map_err(|_| DeviceAuthError::MalformedProof)
}

fn jwk_key_and_thumbprint(jwk: &P256Jwk) -> Result<(P256Key, String), DeviceAuthError> {
    if jwk.kty != "EC" || jwk.crv != "P-256" {
        return Err(DeviceAuthError::InvalidJwk);
    }
    let x = decode_canonical_p256_coordinate(&jwk.x)?;
    let y = decode_canonical_p256_coordinate(&jwk.y)?;
    let mut encoded = Vec::with_capacity(65);
    encoded.push(4);
    encoded.extend_from_slice(&x);
    encoded.extend_from_slice(&y);
    let key = P256Key::from_sec1_bytes(&encoded).map_err(|_| DeviceAuthError::InvalidJwk)?;
    let canonical = format!(
        "{{\"crv\":\"P-256\",\"kty\":\"EC\",\"x\":\"{}\",\"y\":\"{}\"}}",
        jwk.x, jwk.y
    );
    let thumbprint = URL_SAFE_NO_PAD.encode(Sha256::digest(canonical.as_bytes()));
    Ok((key, thumbprint))
}

fn decode_canonical_p256_coordinate(value: &str) -> Result<[u8; 32], DeviceAuthError> {
    if value.len() != 43 || value.contains('=') {
        return Err(DeviceAuthError::InvalidJwk);
    }
    let decoded = URL_SAFE_NO_PAD
        .decode(value)
        .map_err(|_| DeviceAuthError::InvalidJwk)?;
    let coordinate: [u8; 32] = decoded
        .try_into()
        .map_err(|_| DeviceAuthError::InvalidJwk)?;
    if URL_SAFE_NO_PAD.encode(coordinate) != value {
        return Err(DeviceAuthError::InvalidJwk);
    }
    Ok(coordinate)
}

fn validate_exact_uri(uri: &str) -> Result<(), DeviceAuthError> {
    let parsed = Url::parse(uri).map_err(|_| DeviceAuthError::RequestTargetMismatch)?;
    if parsed.scheme() != "https"
        || parsed.username() != ""
        || parsed.password().is_some()
        || parsed.query().is_some()
        || parsed.fragment().is_some()
        || parsed.host_str().is_none()
    {
        return Err(DeviceAuthError::RequestTargetMismatch);
    }
    Ok(())
}

#[derive(Debug)]
struct ValidatedDpop {
    replay_id: String,
    uri_hash: [u8; 32],
}

fn validate_dpop(
    proof: &str,
    token: &str,
    expected_method: &str,
    expected_uri: &str,
    expected_jkt: &str,
    now: DateTime<Utc>,
) -> Result<ValidatedDpop, DeviceAuthError> {
    validate_exact_uri(expected_uri)?;
    let mut segments = proof.split('.');
    let (Some(h), Some(p), Some(s), None) = (
        segments.next(),
        segments.next(),
        segments.next(),
        segments.next(),
    ) else {
        return Err(DeviceAuthError::MalformedProof);
    };
    let header: DpopHeader =
        serde_json::from_slice(&decode_segment(h)?).map_err(|_| DeviceAuthError::InvalidJwk)?;
    if header.typ != "dpop+jwt" || header.alg != "ES256" {
        return Err(DeviceAuthError::InvalidJwk);
    }
    let (key, thumbprint) = jwk_key_and_thumbprint(&header.jwk)?;
    if thumbprint != expected_jkt {
        return Err(DeviceAuthError::ThumbprintMismatch);
    }
    let payload: DpopPayload =
        serde_json::from_slice(&decode_segment(p)?).map_err(|_| DeviceAuthError::MalformedProof)?;
    if payload.htm != expected_method.to_ascii_uppercase() || payload.htu != expected_uri {
        return Err(DeviceAuthError::RequestTargetMismatch);
    }
    if payload.jti.len() < 16 || payload.jti.len() > 200 {
        return Err(DeviceAuthError::MalformedProof);
    }
    if now.timestamp().abs_diff(payload.iat) > DPOP_MAX_CLOCK_SKEW_SECONDS as u64 {
        return Err(DeviceAuthError::ProofTimeInvalid);
    }
    let expected_ath = URL_SAFE_NO_PAD.encode(Sha256::digest(token.as_bytes()));
    if payload.ath != expected_ath {
        return Err(DeviceAuthError::TokenHashMismatch);
    }
    let signature = P256Signature::from_slice(&decode_segment(s)?)
        .map_err(|_| DeviceAuthError::InvalidProofSignature)?;
    key.verify(format!("{h}.{p}").as_bytes(), &signature)
        .map_err(|_| DeviceAuthError::InvalidProofSignature)?;
    Ok(ValidatedDpop {
        replay_id: payload.jti,
        uri_hash: Sha256::digest(expected_uri.as_bytes()).into(),
    })
}

/// Verify proof, consume its replay ID, and resolve the exact active binding.
pub async fn verify_gateway_enrollment_request(
    pool: &PgPool,
    proof: &str,
    verified_bearer: &VerifiedGatewayBearer,
    request_target: &VerifiedRequestTarget,
    now: DateTime<Utc>,
) -> Result<VerifiedEnrollmentRequest, DeviceAuthError> {
    let device = resolve_verified_gateway_device_claims(verified_bearer)?;
    let uri = request_target.dpop_uri()?;
    let validated = validate_dpop(
        proof,
        &verified_bearer.token,
        &request_target.method,
        &uri,
        &device.dpop_jkt,
        now,
    )?;
    let replay_inserted: Option<i32> = sqlx::query_scalar(
        "INSERT INTO device_auth_dpop_replay
         (dpop_jkt, replay_id, method, uri_hash, expires_at)
         VALUES ($1, $2, $3, $4, $5)
         ON CONFLICT (dpop_jkt, replay_id) DO NOTHING RETURNING 1",
    )
    .bind(&device.dpop_jkt)
    .bind(&validated.replay_id)
    .bind(&request_target.method)
    .bind(validated.uri_hash.as_slice())
    .bind(now + Duration::seconds(DPOP_REPLAY_TTL_SECONDS))
    .fetch_optional(pool)
    .await
    .map_err(|e| DeviceAuthError::Storage(e.to_string()))?;
    if replay_inserted.is_none() {
        return Err(DeviceAuthError::Replay);
    }
    Ok(VerifiedEnrollmentRequest {
        user_did: device.user_did,
        device_id: device.device_id,
        dpop_jkt: device.dpop_jkt,
    })
}

/// Verify proof, consume its replay ID, and resolve the exact active binding.
pub async fn verify_gateway_device_request(
    pool: &PgPool,
    proof: &str,
    verified_bearer: &VerifiedGatewayBearer,
    request_target: &VerifiedRequestTarget,
    now: DateTime<Utc>,
) -> Result<VerifiedDeviceRequest, DeviceAuthError> {
    let enrollment =
        verify_gateway_enrollment_request(pool, proof, verified_bearer, request_target, now)
            .await?;
    let generation: Option<i64> = sqlx::query_scalar(
        "SELECT auth_generation FROM devices
         WHERE user_did = $1 AND device_id = $2 AND dpop_jkt = $3
           AND active AND auth_bound_at IS NOT NULL
         FOR SHARE",
    )
    .bind(&enrollment.user_did)
    .bind(&enrollment.device_id)
    .bind(&enrollment.dpop_jkt)
    .fetch_optional(pool)
    .await
    .map_err(|e| DeviceAuthError::Storage(e.to_string()))?;
    let auth_generation = generation.ok_or(DeviceAuthError::RegistryMismatch)?;
    Ok(VerifiedDeviceRequest {
        user_did: enrollment.user_did,
        device_id: enrollment.device_id,
        dpop_jkt: enrollment.dpop_jkt,
        auth_generation,
    })
}

pub async fn begin_binding(
    pool: &PgPool,
    enrollment: &VerifiedEnrollmentRequest,
    now: DateTime<Utc>,
) -> Result<BindingChallenge, DeviceAuthError> {
    let user_did = enrollment.user_did.as_str();
    let device_id = enrollment.device_id.as_str();
    let dpop_jkt = enrollment.dpop_jkt.as_str();
    if canonical_did_claim(user_did).is_none() || device_id.is_empty() || !valid_jkt(dpop_jkt) {
        return Err(DeviceAuthError::BindingMismatch);
    }
    let mut tx = pool
        .begin()
        .await
        .map_err(|e| DeviceAuthError::Storage(e.to_string()))?;
    let signature_key_hex = sqlx::query_scalar::<_, Option<String>>(
        "SELECT signature_public_key FROM devices
         WHERE user_did = $1 AND device_id = $2 AND active FOR SHARE",
    )
    .bind(user_did)
    .bind(device_id)
    .fetch_optional(&mut *tx)
    .await
    .map_err(|e| DeviceAuthError::Storage(e.to_string()))?
    .flatten()
    .ok_or(DeviceAuthError::RegistryMismatch)?;
    let signature_key: [u8; 32] = hex::decode(signature_key_hex)
        .ok()
        .and_then(|key| key.try_into().ok())
        .ok_or(DeviceAuthError::RegistryMismatch)?;
    Ed25519Key::from_bytes(&signature_key).map_err(|_| DeviceAuthError::RegistryMismatch)?;
    let mut nonce = [0_u8; 32];
    rand::thread_rng().fill_bytes(&mut nonce);
    let challenge = BindingChallenge {
        challenge_id: Uuid::new_v4(),
        binding_version: CHALLENGE_VERSION,
        user_did: user_did.to_string(),
        device_id: device_id.to_string(),
        dpop_jkt: dpop_jkt.to_string(),
        nonce,
        expires_at: now + Duration::seconds(CHALLENGE_TTL_SECONDS),
    };
    let challenge_bytes = challenge.challenge_bytes();
    if challenge_bytes.is_empty() || challenge_bytes.len() > 512 {
        return Err(DeviceAuthError::BindingMismatch);
    }
    sqlx::query(
        "INSERT INTO device_auth_binding_challenges
         (id, version, user_did, device_id, dpop_jkt, nonce, expires_at)
         VALUES ($1, $2, $3, $4, $5, $6, $7)",
    )
    .bind(challenge.challenge_id)
    .bind(challenge.binding_version as i16)
    .bind(&challenge.user_did)
    .bind(&challenge.device_id)
    .bind(&challenge.dpop_jkt)
    .bind(challenge.nonce.as_slice())
    .bind(challenge.expires_at)
    .execute(&mut *tx)
    .await
    .map_err(|e| DeviceAuthError::Storage(e.to_string()))?;
    tx.commit()
        .await
        .map_err(|e| DeviceAuthError::Storage(e.to_string()))?;
    Ok(challenge)
}

pub async fn complete_binding(
    pool: &PgPool,
    enrollment: &VerifiedEnrollmentRequest,
    challenge_id: Uuid,
    identity_signature: &[u8],
    now: DateTime<Utc>,
) -> Result<CompletedBinding, DeviceAuthError> {
    let expected_user_did = enrollment.user_did.as_str();
    let expected_device_id = enrollment.device_id.as_str();
    let expected_jkt = enrollment.dpop_jkt.as_str();
    let mut tx = pool
        .begin()
        .await
        .map_err(|e| DeviceAuthError::Storage(e.to_string()))?;
    // Resolve the challenge owner first, then serialize all completions for
    // that authoritative device before locking the individual challenge row.
    // Every completion follows the same lock order, while attacker-supplied
    // enrollment fields cannot redirect which device row is locked.
    let challenge_owner: Option<(String, String)> = sqlx::query_as(
        "SELECT user_did, device_id FROM device_auth_binding_challenges WHERE id = $1",
    )
    .bind(challenge_id)
    .fetch_optional(&mut *tx)
    .await
    .map_err(|e| DeviceAuthError::Storage(e.to_string()))?;
    let (challenge_user_did, challenge_device_id) =
        challenge_owner.ok_or(DeviceAuthError::ChallengeNotFound)?;
    let signature_key_hex: Option<String> = sqlx::query_scalar(
        "SELECT signature_public_key FROM devices
         WHERE user_did = $1 AND device_id = $2 AND active FOR UPDATE",
    )
    .bind(&challenge_user_did)
    .bind(&challenge_device_id)
    .fetch_optional(&mut *tx)
    .await
    .map_err(|e| DeviceAuthError::Storage(e.to_string()))?
    .flatten();
    let key_bytes = signature_key_hex
        .and_then(|encoded| hex::decode(encoded).ok())
        .ok_or(DeviceAuthError::RegistryMismatch)?;
    let key_bytes: [u8; 32] = key_bytes
        .try_into()
        .map_err(|_| DeviceAuthError::RegistryMismatch)?;
    let row: Option<(
        i16,
        String,
        String,
        String,
        Vec<u8>,
        DateTime<Utc>,
        Option<DateTime<Utc>>,
    )> = sqlx::query_as(
        "SELECT version, user_did, device_id, dpop_jkt, nonce, expires_at, used_at
             FROM device_auth_binding_challenges WHERE id = $1 FOR UPDATE",
    )
    .bind(challenge_id)
    .fetch_optional(&mut *tx)
    .await
    .map_err(|e| DeviceAuthError::Storage(e.to_string()))?;
    let (version, user_did, device_id, dpop_jkt, nonce, expires_at, used_at) =
        row.ok_or(DeviceAuthError::ChallengeNotFound)?;
    if version != CHALLENGE_VERSION as i16
        || user_did != expected_user_did
        || device_id != expected_device_id
        || dpop_jkt != expected_jkt
        || nonce.len() != 32
    {
        return Err(DeviceAuthError::BindingMismatch);
    }
    if used_at.is_some() {
        return Err(DeviceAuthError::ChallengeAlreadyUsed);
    }
    if expires_at <= now {
        return Err(DeviceAuthError::ChallengeExpired);
    }
    let nonce_array: [u8; 32] = nonce
        .try_into()
        .map_err(|_| DeviceAuthError::BindingMismatch)?;
    let challenge = BindingChallenge {
        challenge_id,
        binding_version: version as u16,
        user_did: user_did.clone(),
        device_id: device_id.clone(),
        dpop_jkt: dpop_jkt.clone(),
        nonce: nonce_array,
        expires_at,
    };
    let public_key =
        Ed25519Key::from_bytes(&key_bytes).map_err(|_| DeviceAuthError::RegistryMismatch)?;
    let signature = Ed25519Signature::from_slice(identity_signature)
        .map_err(|_| DeviceAuthError::InvalidIdentitySignature)?;
    public_key
        .verify(&challenge.challenge_bytes(), &signature)
        .map_err(|_| DeviceAuthError::InvalidIdentitySignature)?;

    let generation: i64 = sqlx::query_scalar(
        "UPDATE devices SET dpop_jkt = $3, auth_bound_at = $4,
             auth_generation = auth_generation + 1
         WHERE user_did = $1 AND device_id = $2 AND active
         RETURNING auth_generation",
    )
    .bind(&user_did)
    .bind(&device_id)
    .bind(&dpop_jkt)
    .bind(now)
    .fetch_one(&mut *tx)
    .await
    .map_err(|e| DeviceAuthError::Storage(e.to_string()))?;
    let consumed = sqlx::query(
        "UPDATE device_auth_binding_challenges SET used_at = $2
         WHERE id = $1 AND used_at IS NULL",
    )
    .bind(challenge_id)
    .bind(now)
    .execute(&mut *tx)
    .await
    .map_err(|e| DeviceAuthError::Storage(e.to_string()))?;
    if consumed.rows_affected() != 1 {
        return Err(DeviceAuthError::ChallengeAlreadyUsed);
    }
    sqlx::query(
        "UPDATE device_auth_binding_challenges SET used_at = $3
         WHERE user_did = $1 AND device_id = $2 AND used_at IS NULL AND id <> $4",
    )
    .bind(&user_did)
    .bind(&device_id)
    .bind(now)
    .bind(challenge_id)
    .execute(&mut *tx)
    .await
    .map_err(|e| DeviceAuthError::Storage(e.to_string()))?;
    tx.commit()
        .await
        .map_err(|e| DeviceAuthError::Storage(e.to_string()))?;
    Ok(CompletedBinding {
        device_id,
        bound_at: now,
        version: CHALLENGE_VERSION,
        auth_generation: generation,
    })
}

/// CAS-time registry recheck used by future transition integration.
pub async fn recheck_binding_in_transaction(
    tx: &mut Transaction<'_, Postgres>,
    device: &VerifiedDeviceRequest,
) -> Result<(), DeviceAuthError> {
    let present: Option<i32> = sqlx::query_scalar(
        "SELECT 1 FROM devices WHERE user_did = $1 AND device_id = $2
         AND dpop_jkt = $3 AND auth_generation = $4 AND active FOR SHARE",
    )
    .bind(&device.user_did)
    .bind(&device.device_id)
    .bind(&device.dpop_jkt)
    .bind(device.auth_generation)
    .fetch_optional(&mut **tx)
    .await
    .map_err(|e| DeviceAuthError::Storage(e.to_string()))?;
    present.map(|_| ()).ok_or(DeviceAuthError::RegistryMismatch)
}

pub async fn cleanup_expired_auth_material(pool: &PgPool) -> Result<u64, sqlx::Error> {
    let challenges = sqlx::query(
        "DELETE FROM device_auth_binding_challenges WHERE expires_at < NOW() - INTERVAL '1 hour'",
    )
    .execute(pool)
    .await?
    .rows_affected();
    let replays = sqlx::query("DELETE FROM device_auth_dpop_replay WHERE expires_at < NOW()")
        .execute(pool)
        .await?
        .rows_affected();
    Ok(challenges + replays)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};
    use p256::ecdsa::SigningKey as P256SigningKey;
    use serde_json::json;

    fn claims(issuer: &str, subject: Option<&str>) -> AtProtoClaims {
        AtProtoClaims {
            iss: issuer.into(),
            aud: "did:web:mls.example".into(),
            exp: Utc::now().timestamp() + 60,
            iat: Some(Utc::now().timestamp()),
            sub: subject.map(str::to_string),
            lxm: Some("blue.catbird.mlsDS.commitGroupChange".into()),
            jti: Some("token-jti-123456".into()),
        }
    }

    fn device_token(
        issuer: &str,
        subject: Option<&str>,
        device: Option<&str>,
        jkt: Option<&str>,
    ) -> String {
        let payload = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&json!({
            "iss": issuer, "sub": subject, "device_id": device, "cnf": jkt.map(|value| json!({"jkt": value}))
        })).unwrap());
        format!("e30.{payload}.signature")
    }

    fn enrollment(user_did: &str, device_id: &str, dpop_jkt: &str) -> VerifiedEnrollmentRequest {
        VerifiedEnrollmentRequest {
            user_did: user_did.to_string(),
            device_id: device_id.to_string(),
            dpop_jkt: dpop_jkt.to_string(),
        }
    }

    fn verified_bearer(
        issuer: &str,
        subject: &str,
        device_id: &str,
        dpop_jkt: &str,
    ) -> VerifiedGatewayBearer {
        VerifiedGatewayBearer {
            claims: claims(issuer, Some(subject)),
            token: device_token(issuer, Some(subject), Some(device_id), Some(dpop_jkt)),
            effective_user_did: subject.to_string(),
            delegated_gateway: true,
        }
    }

    fn request_target(method: &str, path_and_query: &str) -> VerifiedRequestTarget {
        let method = method.parse::<http::Method>().unwrap();
        let uri = path_and_query.parse::<http::Uri>().unwrap();
        VerifiedRequestTarget::from_request_parts(&method, &uri)
    }

    async fn mint_verified_device(
        pool: &PgPool,
        gateway: &str,
        user_did: &str,
        device_id: &str,
        dpop_key: &P256SigningKey,
        dpop_jkt: &str,
        now: DateTime<Utc>,
        replay_id: &str,
    ) -> VerifiedDeviceRequest {
        let bearer = verified_bearer(gateway, user_did, device_id, dpop_jkt);
        let target = request_target("POST", "/xrpc/blue.catbird.mlsDS.commitGroupChange");
        let uri = target.dpop_uri_for_origin("https://mls.example").unwrap();
        let (dpop, computed_jkt) = proof(dpop_key, &bearer.token, "POST", &uri, now, replay_id);
        assert_eq!(computed_jkt, dpop_jkt);
        verify_gateway_device_request(pool, &dpop, &bearer, &target, now)
            .await
            .unwrap()
    }

    fn proof(
        signing_key: &P256SigningKey,
        token: &str,
        method: &str,
        uri: &str,
        now: DateTime<Utc>,
        jti: &str,
    ) -> (String, String) {
        let point = signing_key.verifying_key().to_encoded_point(false);
        let x = URL_SAFE_NO_PAD.encode(point.x().unwrap());
        let y = URL_SAFE_NO_PAD.encode(point.y().unwrap());
        let header = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&json!({"typ":"dpop+jwt","alg":"ES256","jwk":{"kty":"EC","crv":"P-256","x":x,"y":y}})).unwrap());
        let payload = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&json!({"htm":method,"htu":uri,"ath":URL_SAFE_NO_PAD.encode(Sha256::digest(token.as_bytes())),"iat":now.timestamp(),"jti":jti})).unwrap());
        let message = format!("{header}.{payload}");
        let signature: P256Signature = signing_key.sign(message.as_bytes());
        let compact = format!("{message}.{}", URL_SAFE_NO_PAD.encode(signature.to_bytes()));
        let jwk = P256Jwk {
            kty: "EC".into(),
            crv: "P-256".into(),
            x,
            y,
        };
        (compact, jwk_key_and_thumbprint(&jwk).unwrap().1)
    }

    #[test]
    fn gateway_claims_require_trusted_delegation_and_exact_device_material() {
        let jkt = "a".repeat(43);
        let trusted = claims("did:web:nest.example", Some("did:plc:alice"));
        assert!(resolve_gateway_device_claims(
            &trusted,
            Some("did:web:nest.example"),
            &device_token(
                "did:web:nest.example",
                Some("did:plc:alice"),
                Some("device-a"),
                Some(&jkt)
            )
        )
        .is_ok());
        let direct = claims("did:plc:alice", None);
        assert_eq!(
            resolve_gateway_device_claims(
                &direct,
                Some("did:web:nest.example"),
                &device_token("did:plc:alice", None, Some("device-a"), Some(&jkt))
            )
            .unwrap_err(),
            DeviceAuthError::UntrustedDelegation
        );
        let evil = claims("did:web:evil.example", Some("did:plc:alice"));
        assert_eq!(
            resolve_gateway_device_claims(
                &evil,
                Some("did:web:nest.example"),
                &device_token(
                    "did:web:evil.example",
                    Some("did:plc:alice"),
                    Some("device-a"),
                    Some(&jkt)
                )
            )
            .unwrap_err(),
            DeviceAuthError::UntrustedDelegation
        );
        assert_eq!(
            resolve_gateway_device_claims(
                &trusted,
                Some("did:web:nest.example"),
                &device_token(
                    "did:web:nest.example",
                    Some("did:plc:alice"),
                    None,
                    Some(&jkt)
                )
            )
            .unwrap_err(),
            DeviceAuthError::MissingDeviceClaims
        );

        let fragmented = claims(
            "did:web:nest.example#atproto-signing-key",
            Some("did:plc:alice"),
        );
        let fragmented_token = device_token(
            "did:web:nest.example#atproto-signing-key",
            Some("did:plc:alice"),
            Some("device-a"),
            Some(&jkt),
        );
        assert!(resolve_gateway_device_claims(
            &fragmented,
            Some("did:web:other.example, did:web:nest.example#configured-key"),
            &fragmented_token,
        )
        .is_ok());
        for rejected in [
            "did:web:nest.example.evil",
            "did:web:",
            "did:web:nest.example#",
            "not-a-did,did:web:other.example",
            "not-a-did,did:web:nest.example",
        ] {
            assert_eq!(
                resolve_gateway_device_claims(&fragmented, Some(rejected), &fragmented_token)
                    .unwrap_err(),
                DeviceAuthError::UntrustedDelegation
            );
        }
    }

    #[test]
    fn substituted_token_with_same_issuer_and_subject_cannot_change_opaque_bearer_claims() {
        let accepted = verified_bearer(
            "did:web:nest.example",
            "did:plc:alice",
            "device-a",
            &"a".repeat(43),
        );
        let substituted = device_token(
            "did:web:nest.example",
            Some("did:plc:alice"),
            Some("device-b"),
            Some(&"b".repeat(43)),
        );

        let resolved = resolve_verified_gateway_device_claims(&accepted).unwrap();
        assert_eq!(resolved.device_id, "device-a");
        assert_eq!(resolved.dpop_jkt, "a".repeat(43));
        assert_ne!(accepted.token, substituted);
        assert!(!format!("{accepted:?}").contains(&accepted.token));
    }

    #[test]
    fn request_target_is_sealed_from_request_parts_and_server_origin() {
        let target = request_target(
            "POST",
            "/xrpc/blue.catbird.mlsDS.commitGroupChange?epoch=7%2F8",
        );
        assert_eq!(
            target
                .dpop_uri_for_origin("https://mls.example:8443")
                .unwrap(),
            "https://mls.example:8443/xrpc/blue.catbird.mlsDS.commitGroupChange"
        );
        assert_eq!(
            target
                .dpop_uri_for_origin("https://mls.example:443")
                .unwrap(),
            "https://mls.example/xrpc/blue.catbird.mlsDS.commitGroupChange"
        );
        for endpoint in [
            "https://mls.example/user/alice",
            "https://mls.example/user/alice/",
            "https://mls.example:8443/user/alice/",
        ] {
            let expected_origin = if endpoint.contains(":8443") {
                "https://mls.example:8443"
            } else {
                "https://mls.example"
            };
            assert_eq!(
                target.dpop_uri_for_origin(endpoint).unwrap(),
                format!("{expected_origin}/user/alice/xrpc/blue.catbird.mlsDS.commitGroupChange")
            );
        }
        let already_prefixed = request_target(
            "POST",
            "/user/alice/xrpc/blue.catbird.mlsDS.commitGroupChange?epoch=7",
        );
        assert_eq!(
            already_prefixed
                .dpop_uri_for_origin("https://mls.example/user/alice")
                .unwrap(),
            "https://mls.example/user/alice/xrpc/blue.catbird.mlsDS.commitGroupChange"
        );
        assert_eq!(
            target.path_and_query,
            "/xrpc/blue.catbird.mlsDS.commitGroupChange?epoch=7%2F8"
        );

        let request = http::Request::builder()
            .method("POST")
            .uri("/xrpc/real?value=%2F")
            .header("forwarded", "host=evil.example;proto=http")
            .header("x-forwarded-host", "evil.example")
            .body(())
            .unwrap();
        let (parts, _) = request.into_parts();
        let sealed = VerifiedRequestTarget::from_request_parts(&parts.method, &parts.uri);
        assert_eq!(
            sealed.dpop_uri_for_origin("https://mls.example").unwrap(),
            "https://mls.example/xrpc/real"
        );
        assert_eq!(sealed.path_and_query, "/xrpc/real?value=%2F");

        for invalid_origin in [
            "http://mls.example",
            "https://user@mls.example",
            "https://mls.example?x=1",
            "https://mls.example/#fragment",
        ] {
            assert_eq!(
                target.dpop_uri_for_origin(invalid_origin).unwrap_err(),
                DeviceAuthError::RequestTargetMismatch
            );
        }
    }

    #[test]
    fn sealed_request_target_rejects_cross_route_but_rfc9449_htu_ignores_query() {
        let key = P256SigningKey::random(&mut rand::thread_rng());
        let now = Utc::now();
        let token = "gateway-token";
        let accepted_uri = "https://mls.example/xrpc/route";
        let (compact, jkt) = proof(
            &key,
            token,
            "POST",
            accepted_uri,
            now,
            "sealed-target-proof-1234",
        );
        for path in ["/xrpc/route?a=1", "/xrpc/route?a=2"] {
            let target = request_target("POST", path);
            let uri = target.dpop_uri_for_origin("https://mls.example").unwrap();
            assert!(validate_dpop(&compact, token, &target.method, &uri, &jkt, now).is_ok());
        }
        let cross_route = request_target("POST", "/xrpc/other?a=1");
        let cross_route_uri = cross_route
            .dpop_uri_for_origin("https://mls.example")
            .unwrap();
        assert_eq!(
            validate_dpop(
                &compact,
                token,
                &cross_route.method,
                &cross_route_uri,
                &jkt,
                now,
            )
            .unwrap_err(),
            DeviceAuthError::RequestTargetMismatch
        );
        let (query_bearing_proof, query_jkt) = proof(
            &key,
            token,
            "POST",
            "https://mls.example/xrpc/route?a=1",
            now,
            "query-bearing-proof-1234",
        );
        assert_eq!(
            validate_dpop(
                &query_bearing_proof,
                token,
                "POST",
                "https://mls.example/xrpc/route?a=1",
                &query_jkt,
                now,
            )
            .unwrap_err(),
            DeviceAuthError::RequestTargetMismatch
        );
    }

    #[test]
    fn dpop_binds_signature_thumbprint_token_method_uri_time_and_replay_shape() {
        let key = P256SigningKey::random(&mut rand::thread_rng());
        let now = Utc::now();
        let token = "gateway-token";
        let uri = "https://mls.example/xrpc/blue.catbird.mlsDS.commitGroupChange";
        let (compact, jkt) = proof(&key, token, "POST", uri, now, "proof-replay-id-1234");
        assert_eq!(
            validate_dpop(&compact, token, "POST", uri, &jkt, now)
                .unwrap()
                .replay_id,
            "proof-replay-id-1234"
        );
        assert_eq!(
            validate_dpop(&compact, "wrong", "POST", uri, &jkt, now).unwrap_err(),
            DeviceAuthError::TokenHashMismatch
        );
        assert_eq!(
            validate_dpop(&compact, token, "GET", uri, &jkt, now).unwrap_err(),
            DeviceAuthError::RequestTargetMismatch
        );
        assert_eq!(
            validate_dpop(
                &compact,
                token,
                "POST",
                "https://mls.example/other",
                &jkt,
                now
            )
            .unwrap_err(),
            DeviceAuthError::RequestTargetMismatch
        );
        assert_eq!(
            validate_dpop(&compact, token, "POST", uri, &"b".repeat(43), now).unwrap_err(),
            DeviceAuthError::ThumbprintMismatch
        );
        assert_eq!(
            validate_dpop(
                &compact,
                token,
                "POST",
                uri,
                &jkt,
                now + Duration::seconds(61)
            )
            .unwrap_err(),
            DeviceAuthError::ProofTimeInvalid
        );
        let mut segments = compact.split('.');
        let header = segments.next().unwrap();
        let payload = segments.next().unwrap();
        let mut signature = URL_SAFE_NO_PAD.decode(segments.next().unwrap()).unwrap();
        signature[0] ^= 1;
        let bad = format!("{header}.{payload}.{}", URL_SAFE_NO_PAD.encode(signature));
        assert_eq!(
            validate_dpop(&bad, token, "POST", uri, &jkt, now).unwrap_err(),
            DeviceAuthError::InvalidProofSignature
        );
    }

    #[test]
    fn malformed_or_unsupported_jwk_is_rejected() {
        let unsupported_header = URL_SAFE_NO_PAD.encode(
            serde_json::to_vec(&json!({"typ":"dpop+jwt","alg":"ES256","jwk":{"kty":"OKP","crv":"Ed25519","x":"a","y":"b"}})).unwrap(),
        );
        let payload = URL_SAFE_NO_PAD.encode(b"{}");
        assert_eq!(
            validate_dpop(
                &format!("{unsupported_header}.{payload}.AA"),
                "t",
                "POST",
                "https://mls.example/x",
                &"a".repeat(43),
                Utc::now()
            )
            .unwrap_err(),
            DeviceAuthError::InvalidJwk
        );
        assert_eq!(
            validate_dpop(
                "a.b.c",
                "t",
                "POST",
                "https://mls.example/x",
                &"a".repeat(43),
                Utc::now()
            )
            .unwrap_err(),
            DeviceAuthError::MalformedProof
        );
        assert_eq!(
            validate_dpop(
                "",
                "t",
                "POST",
                "https://mls.example/x",
                &"a".repeat(43),
                Utc::now()
            )
            .unwrap_err(),
            DeviceAuthError::MalformedProof
        );

        let key = P256SigningKey::random(&mut rand::thread_rng());
        let point = key.verifying_key().to_encoded_point(false);
        let x = URL_SAFE_NO_PAD.encode(point.x().unwrap());
        let y = URL_SAFE_NO_PAD.encode(point.y().unwrap());
        let public_with_metadata = serde_json::from_value::<P256Jwk>(json!({
            "kty": "EC", "crv": "P-256", "x": x, "y": y,
            "kid": "device-key", "use": "sig", "key_ops": ["verify"],
            "alg": "ES256", "x5t#S256": "public-certificate-thumbprint",
            "future-public-member": {"ignored": true}
        }))
        .unwrap();
        assert!(jwk_key_and_thumbprint(&public_with_metadata).is_ok());
        for private_member in ["d", "k", "p", "q", "dp", "dq", "qi", "oth"] {
            let mut value = json!({"kty":"EC", "crv":"P-256", "x":x, "y":y});
            value
                .as_object_mut()
                .unwrap()
                .insert(private_member.to_string(), json!("private-material"));
            assert!(
                serde_json::from_value::<P256Jwk>(value).is_err(),
                "accepted private JWK member {private_member}"
            );
        }
        for duplicate in ["kty", "crv", "x", "y"] {
            let duplicate_jwk = match duplicate {
                "kty" => format!(r#"{{"kty":"EC","kty":"EC","crv":"P-256","x":"{x}","y":"{y}"}}"#),
                "crv" => {
                    format!(r#"{{"kty":"EC","crv":"P-256","crv":"P-256","x":"{x}","y":"{y}"}}"#)
                }
                "x" => format!(r#"{{"kty":"EC","crv":"P-256","x":"{x}","x":"{x}","y":"{y}"}}"#),
                "y" => format!(r#"{{"kty":"EC","crv":"P-256","x":"{x}","y":"{y}","y":"{y}"}}"#),
                _ => unreachable!(),
            };
            assert!(
                serde_json::from_str::<P256Jwk>(&duplicate_jwk).is_err(),
                "accepted duplicate security-critical JWK member {duplicate}"
            );
        }
        assert_eq!(
            decode_canonical_p256_coordinate(&format!("{x}=")).unwrap_err(),
            DeviceAuthError::InvalidJwk
        );
        assert_eq!(
            decode_canonical_p256_coordinate(&x[..42]).unwrap_err(),
            DeviceAuthError::InvalidJwk
        );

        // The final base64url character for 32 bytes contains two required
        // zero padding bits. Flip only those bits; strict RFC 7638 input must
        // reject the noncanonical spelling.
        const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
        let final_index = ALPHABET
            .iter()
            .position(|candidate| *candidate == x.as_bytes()[42])
            .unwrap();
        assert_eq!(final_index & 0b11, 0);
        let mut noncanonical = x.clone().into_bytes();
        noncanonical[42] = ALPHABET[final_index + 1];
        let noncanonical = String::from_utf8(noncanonical).unwrap();
        assert_eq!(
            decode_canonical_p256_coordinate(&noncanonical).unwrap_err(),
            DeviceAuthError::InvalidJwk
        );
    }

    #[test]
    fn canonical_challenge_binds_every_field() {
        let base = BindingChallenge {
            challenge_id: Uuid::nil(),
            binding_version: 1,
            user_did: "did:plc:alice".into(),
            device_id: "device-a".into(),
            dpop_jkt: "a".repeat(43),
            nonce: [7; 32],
            expires_at: DateTime::from_timestamp(1_800_000_000, 0).unwrap(),
        };
        let bytes = base.challenge_bytes();
        let mut changed = base.clone();
        changed.device_id = "device-b".into();
        assert_ne!(bytes, changed.challenge_bytes());
        changed = base.clone();
        changed.user_did = "did:plc:bob".into();
        assert_ne!(bytes, changed.challenge_bytes());
        changed = base.clone();
        changed.dpop_jkt = "b".repeat(43);
        assert_ne!(bytes, changed.challenge_bytes());
        changed = base.clone();
        changed.nonce[0] ^= 1;
        assert_ne!(bytes, changed.challenge_bytes());
    }

    #[test]
    fn malformed_wire_challenge_ids_map_to_not_found() {
        assert_eq!(
            parse_binding_challenge_id("not-a-uuid").unwrap_err(),
            DeviceAuthError::ChallengeNotFound
        );
        let valid = Uuid::new_v4();
        assert_eq!(
            parse_binding_challenge_id(&valid.to_string()).unwrap(),
            valid
        );
    }

    #[tokio::test]
    #[ignore = "requires TEST_DATABASE_URL with migration privileges"]
    async fn postgres_challenge_is_single_use_rebinds_and_rolls_back_bad_signature() {
        let url = std::env::var("TEST_DATABASE_URL").expect("TEST_DATABASE_URL required");
        let pool = PgPool::connect(&url).await.unwrap();
        sqlx::migrate!("./migrations").run(&pool).await.unwrap();
        let challenge_device_index: String = sqlx::query_scalar(
            "SELECT indexdef FROM pg_indexes
             WHERE schemaname=current_schema()
               AND tablename='device_auth_binding_challenges'
               AND indexname='idx_device_auth_challenges_device'",
        )
        .fetch_one(&pool)
        .await
        .unwrap();
        assert!(challenge_device_index.contains("(user_did, device_id)"));
        let suffix = Uuid::new_v4().simple().to_string();
        let user = format!("did:plc:test{suffix}");
        let device = format!("device-{suffix}");
        let key = SigningKey::generate(&mut rand::thread_rng());
        sqlx::query("INSERT INTO users(did) VALUES($1)")
            .bind(&user)
            .execute(&pool)
            .await
            .unwrap();
        sqlx::query("INSERT INTO devices(id,user_did,device_id,credential_did,signature_public_key) VALUES($1,$2,$3,$4,$5)")
            .bind(Uuid::new_v4().to_string()).bind(&user).bind(&device).bind(format!("{user}#{device}")).bind(hex::encode(key.verifying_key().as_bytes())).execute(&pool).await.unwrap();
        let now = Utc::now();
        let jkt_a = URL_SAFE_NO_PAD.encode(Sha256::digest(b"jkt-a"));
        let enrollment_a = enrollment(&user, &device, &jkt_a);
        let challenge = begin_binding(&pool, &enrollment_a, now).await.unwrap();
        assert_eq!(
            complete_binding(&pool, &enrollment_a, Uuid::new_v4(), &[0; 64], now)
                .await
                .unwrap_err(),
            DeviceAuthError::ChallengeNotFound
        );
        for (wrong_user, wrong_device, wrong_jkt, expected) in [
            (
                "did:plc:other",
                device.as_str(),
                jkt_a.as_str(),
                DeviceAuthError::BindingMismatch,
            ),
            (
                user.as_str(),
                "device-other",
                jkt_a.as_str(),
                DeviceAuthError::BindingMismatch,
            ),
            (
                user.as_str(),
                device.as_str(),
                "z012345678901234567890123456789012345678901",
                DeviceAuthError::BindingMismatch,
            ),
        ] {
            assert_eq!(
                complete_binding(
                    &pool,
                    &enrollment(wrong_user, wrong_device, wrong_jkt),
                    challenge.challenge_id,
                    &[0; 64],
                    now,
                )
                .await
                .unwrap_err(),
                expected
            );
        }
        assert_eq!(
            complete_binding(&pool, &enrollment_a, challenge.challenge_id, &[0; 64], now,)
                .await
                .unwrap_err(),
            DeviceAuthError::InvalidIdentitySignature
        );
        let sig = key.sign(&challenge.challenge_bytes());
        assert_eq!(
            complete_binding(
                &pool,
                &enrollment_a,
                challenge.challenge_id,
                &sig.to_bytes(),
                now
            )
            .await
            .unwrap()
            .auth_generation,
            1
        );
        assert_eq!(
            complete_binding(
                &pool,
                &enrollment_a,
                challenge.challenge_id,
                &sig.to_bytes(),
                now
            )
            .await
            .unwrap_err(),
            DeviceAuthError::ChallengeAlreadyUsed
        );
        let jkt_b = URL_SAFE_NO_PAD.encode(Sha256::digest(b"jkt-b"));
        let enrollment_b = enrollment(&user, &device, &jkt_b);
        let second = begin_binding(&pool, &enrollment_b, now).await.unwrap();
        let sig2 = key.sign(&second.challenge_bytes());
        assert_eq!(
            complete_binding(
                &pool,
                &enrollment_b,
                second.challenge_id,
                &sig2.to_bytes(),
                now
            )
            .await
            .unwrap()
            .auth_generation,
            2
        );
        let row: (String, i64) = sqlx::query_as(
            "SELECT dpop_jkt,auth_generation FROM devices WHERE user_did=$1 AND device_id=$2",
        )
        .bind(&user)
        .bind(&device)
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(row, (jkt_b.clone(), 2));

        let expired = begin_binding(&pool, &enrollment_b, now).await.unwrap();
        let expired_sig = key.sign(&expired.challenge_bytes());
        assert_eq!(
            complete_binding(
                &pool,
                &enrollment_b,
                expired.challenge_id,
                &expired_sig.to_bytes(),
                now + Duration::seconds(CHALLENGE_TTL_SECONDS + 1),
            )
            .await
            .unwrap_err(),
            DeviceAuthError::ChallengeExpired
        );

        let dpop_key = P256SigningKey::random(&mut rand::thread_rng());
        let (_, jkt_c) = proof(
            &dpop_key,
            "thumbprint-only",
            "POST",
            "https://mls.example/thumbprint-only",
            now,
            "thumbprint-proof-1234",
        );
        let enrollment_c = enrollment(&user, &device, &jkt_c);
        let concurrent_a = begin_binding(&pool, &enrollment_c, now).await.unwrap();
        let concurrent_b = begin_binding(&pool, &enrollment_c, now).await.unwrap();
        let concurrent_sig_a = key.sign(&concurrent_a.challenge_bytes()).to_bytes();
        let concurrent_sig_b = key.sign(&concurrent_b.challenge_bytes()).to_bytes();
        let first = complete_binding(
            &pool,
            &enrollment_c,
            concurrent_a.challenge_id,
            &concurrent_sig_a,
            now,
        );
        let second = complete_binding(
            &pool,
            &enrollment_c,
            concurrent_b.challenge_id,
            &concurrent_sig_b,
            now,
        );
        let (first, second) = tokio::join!(first, second);
        assert_eq!(first.is_ok() as u8 + second.is_ok() as u8, 1);
        assert!(matches!(
            first.err().or_else(|| second.err()),
            Some(DeviceAuthError::ChallengeAlreadyUsed)
        ));

        let gateway = "did:web:nest.example";
        let verified_bearer = verified_bearer(gateway, &user, &device, &jkt_c);
        let token = verified_bearer.token.clone();
        let uri = "https://mls.example/xrpc/blue.catbird.mlsDS.commitGroupChange";
        let request_target = request_target("POST", "/xrpc/blue.catbird.mlsDS.commitGroupChange");
        std::env::set_var("SERVICE_DID", "did:web:mls.example");
        std::env::set_var("SELF_ENDPOINT", "https://mls.example");
        let (dpop, computed_jkt) = proof(
            &dpop_key,
            &token,
            "POST",
            uri,
            now,
            "postgres-replay-id-1234",
        );
        assert_eq!(computed_jkt, jkt_c);
        let resolved =
            verify_gateway_device_request(&pool, &dpop, &verified_bearer, &request_target, now)
                .await
                .unwrap();
        assert_eq!(resolved.user_did(), user);
        assert_eq!(resolved.device_id(), device);
        assert_eq!(resolved.auth_generation(), 3);
        assert_eq!(
            verify_gateway_device_request(&pool, &dpop, &verified_bearer, &request_target, now,)
                .await
                .unwrap_err(),
            DeviceAuthError::Replay
        );

        let mut tx = pool.begin().await.unwrap();
        recheck_binding_in_transaction(&mut tx, &resolved)
            .await
            .unwrap();
        tx.rollback().await.unwrap();

        // A speculative registry mutation must fail the recheck inside that
        // transaction and regain authority only after the mutation rolls back.
        let mut tx = pool.begin().await.unwrap();
        sqlx::query(
            "UPDATE devices SET dpop_jkt=$3, auth_generation=auth_generation+1
             WHERE user_did=$1 AND device_id=$2",
        )
        .bind(&user)
        .bind(&device)
        .bind("r012345678901234567890123456789012345678901")
        .execute(&mut *tx)
        .await
        .unwrap();
        assert_eq!(
            recheck_binding_in_transaction(&mut tx, &resolved)
                .await
                .unwrap_err(),
            DeviceAuthError::RegistryMismatch
        );
        tx.rollback().await.unwrap();
        let mut tx = pool.begin().await.unwrap();
        recheck_binding_in_transaction(&mut tx, &resolved)
            .await
            .unwrap();
        tx.rollback().await.unwrap();

        let dpop_key_d = P256SigningKey::random(&mut rand::thread_rng());
        let (_, jkt_d) = proof(
            &dpop_key_d,
            "thumbprint-only",
            "POST",
            "https://mls.example/thumbprint-only",
            now,
            "thumbprint-proof-d-1234",
        );
        let enrollment_d = enrollment(&user, &device, &jkt_d);
        let rebind = begin_binding(&pool, &enrollment_d, now).await.unwrap();
        let rebind_signature = key.sign(&rebind.challenge_bytes());
        let rebound = complete_binding(
            &pool,
            &enrollment_d,
            rebind.challenge_id,
            &rebind_signature.to_bytes(),
            now,
        )
        .await
        .unwrap();
        let rebound_device = mint_verified_device(
            &pool,
            gateway,
            &user,
            &device,
            &dpop_key_d,
            &jkt_d,
            now,
            "rebound-proof-replay-1234",
        )
        .await;
        assert_eq!(rebound_device.auth_generation(), rebound.auth_generation);
        let mut tx = pool.begin().await.unwrap();
        assert_eq!(
            recheck_binding_in_transaction(&mut tx, &resolved)
                .await
                .unwrap_err(),
            DeviceAuthError::RegistryMismatch
        );
        tx.rollback().await.unwrap();

        sqlx::query("UPDATE devices SET active=FALSE WHERE user_did=$1 AND device_id=$2")
            .bind(&user)
            .bind(&device)
            .execute(&pool)
            .await
            .unwrap();
        let mut tx = pool.begin().await.unwrap();
        assert_eq!(
            recheck_binding_in_transaction(&mut tx, &rebound_device)
                .await
                .unwrap_err(),
            DeviceAuthError::RegistryMismatch
        );
        tx.rollback().await.unwrap();

        sqlx::query("UPDATE devices SET active=TRUE WHERE user_did=$1 AND device_id=$2")
            .bind(&user)
            .bind(&device)
            .execute(&pool)
            .await
            .unwrap();
        let dpop_key_e = P256SigningKey::random(&mut rand::thread_rng());
        let (_, jkt_e) = proof(
            &dpop_key_e,
            "thumbprint-only",
            "POST",
            "https://mls.example/thumbprint-only",
            now,
            "thumbprint-proof-e-1234",
        );
        let enrollment_e = enrollment(&user, &device, &jkt_e);
        let after_activation = begin_binding(&pool, &enrollment_e, now).await.unwrap();
        let after_activation_signature = key.sign(&after_activation.challenge_bytes());
        let active_binding = complete_binding(
            &pool,
            &enrollment_e,
            after_activation.challenge_id,
            &after_activation_signature.to_bytes(),
            now,
        )
        .await
        .unwrap();
        let active_device = mint_verified_device(
            &pool,
            gateway,
            &user,
            &device,
            &dpop_key_e,
            &jkt_e,
            now,
            "active-proof-replay-1234",
        )
        .await;
        assert_eq!(
            active_device.auth_generation(),
            active_binding.auth_generation
        );

        let replacement_key = SigningKey::generate(&mut rand::thread_rng());
        sqlx::query(
            "UPDATE devices SET signature_public_key=$3 WHERE user_did=$1 AND device_id=$2",
        )
        .bind(&user)
        .bind(&device)
        .bind(hex::encode(replacement_key.verifying_key().as_bytes()))
        .execute(&pool)
        .await
        .unwrap();
        let invalidated: (Option<String>, Option<DateTime<Utc>>, i64) = sqlx::query_as(
            "SELECT dpop_jkt,auth_bound_at,auth_generation FROM devices WHERE user_did=$1 AND device_id=$2",
        )
        .bind(&user)
        .bind(&device)
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(invalidated.0, None);
        assert_eq!(invalidated.1, None);
        assert_eq!(invalidated.2, active_device.auth_generation() + 1);
        let mut tx = pool.begin().await.unwrap();
        assert_eq!(
            recheck_binding_in_transaction(&mut tx, &active_device)
                .await
                .unwrap_err(),
            DeviceAuthError::RegistryMismatch
        );
        tx.rollback().await.unwrap();

        let dpop_key_f = P256SigningKey::random(&mut rand::thread_rng());
        let (_, jkt_f) = proof(
            &dpop_key_f,
            "thumbprint-only",
            "POST",
            "https://mls.example/thumbprint-only",
            now,
            "thumbprint-proof-f-1234",
        );
        let enrollment_f = enrollment(&user, &device, &jkt_f);
        let after_rekey = begin_binding(&pool, &enrollment_f, now).await.unwrap();
        let after_rekey_signature = replacement_key.sign(&after_rekey.challenge_bytes());
        let replacement_binding = complete_binding(
            &pool,
            &enrollment_f,
            after_rekey.challenge_id,
            &after_rekey_signature.to_bytes(),
            now,
        )
        .await
        .unwrap();
        let replacement_device = mint_verified_device(
            &pool,
            gateway,
            &user,
            &device,
            &dpop_key_f,
            &jkt_f,
            now,
            "replacement-proof-replay-1234",
        )
        .await;
        assert_eq!(
            replacement_device.auth_generation(),
            replacement_binding.auth_generation
        );
        sqlx::query("DELETE FROM devices WHERE user_did=$1 AND device_id=$2")
            .bind(&user)
            .bind(&device)
            .execute(&pool)
            .await
            .unwrap();
        let mut tx = pool.begin().await.unwrap();
        assert_eq!(
            recheck_binding_in_transaction(&mut tx, &replacement_device)
                .await
                .unwrap_err(),
            DeviceAuthError::RegistryMismatch
        );
        tx.rollback().await.unwrap();
        sqlx::query("DELETE FROM users WHERE did=$1")
            .bind(&user)
            .execute(&pool)
            .await
            .unwrap();
    }

    #[tokio::test]
    #[ignore = "requires TEST_DATABASE_URL with migration privileges"]
    async fn postgres_begin_binding_serializes_registry_mutations_and_rolls_back() {
        let url = std::env::var("TEST_DATABASE_URL").expect("TEST_DATABASE_URL required");
        let pool = PgPool::connect(&url).await.unwrap();
        sqlx::migrate!("./migrations").run(&pool).await.unwrap();
        let now = Utc::now();

        async fn insert_device(
            pool: &PgPool,
            label: &str,
            signature_public_key: Option<String>,
        ) -> (String, String, VerifiedEnrollmentRequest) {
            let suffix = Uuid::new_v4().simple().to_string();
            let user = format!("did:plc:{label}{suffix}");
            let device = format!("device-{suffix}");
            sqlx::query("INSERT INTO users(did) VALUES($1)")
                .bind(&user)
                .execute(pool)
                .await
                .unwrap();
            sqlx::query(
                "INSERT INTO devices
                 (id,user_did,device_id,credential_did,signature_public_key)
                 VALUES($1,$2,$3,$4,$5)",
            )
            .bind(Uuid::new_v4().to_string())
            .bind(&user)
            .bind(&device)
            .bind(format!("{user}#{device}"))
            .bind(signature_public_key)
            .execute(pool)
            .await
            .unwrap();
            let jkt = URL_SAFE_NO_PAD.encode(Sha256::digest(format!("{label}-{suffix}")));
            let enrollment = enrollment(&user, &device, &jkt);
            (user, device, enrollment)
        }

        async fn challenge_count(pool: &PgPool, user: &str, device: &str) -> i64 {
            sqlx::query_scalar(
                "SELECT COUNT(*) FROM device_auth_binding_challenges
                 WHERE user_did=$1 AND device_id=$2",
            )
            .bind(user)
            .bind(device)
            .fetch_one(pool)
            .await
            .unwrap()
        }

        async fn await_begin(
            task: tokio::task::JoinHandle<Result<BindingChallenge, DeviceAuthError>>,
        ) -> Result<BindingChallenge, DeviceAuthError> {
            tokio::time::timeout(std::time::Duration::from_secs(5), task)
                .await
                .expect("begin_binding stayed blocked after registry mutation committed")
                .expect("begin_binding task panicked")
        }

        async fn named_pool(url: &str, application_name: &str) -> PgPool {
            let options: sqlx::postgres::PgConnectOptions = url
                .parse::<sqlx::postgres::PgConnectOptions>()
                .unwrap()
                .application_name(application_name);
            sqlx::postgres::PgPoolOptions::new()
                .max_connections(1)
                .connect_with(options)
                .await
                .unwrap()
        }

        async fn wait_for_lock(
            observer: &PgPool,
            application_name: &str,
            task: &tokio::task::JoinHandle<Result<BindingChallenge, DeviceAuthError>>,
        ) {
            for _ in 0..500 {
                assert!(
                    !task.is_finished(),
                    "begin_binding completed before reaching the contested device-row lock"
                );
                let waiting: Option<bool> = sqlx::query_scalar(
                    "SELECT COALESCE(wait_event_type = 'Lock', FALSE)
                     FROM pg_stat_activity
                     WHERE application_name = $1 AND state = 'active'",
                )
                .bind(application_name)
                .fetch_optional(observer)
                .await
                .unwrap();
                if waiting == Some(true) {
                    return;
                }
                tokio::time::sleep(std::time::Duration::from_millis(10)).await;
            }
            panic!("begin_binding did not reach the contested device-row lock");
        }

        let key = SigningKey::generate(&mut rand::thread_rng());
        let valid_signer = Some(hex::encode(key.verifying_key().as_bytes()));

        // A concurrent delete wins the device-row lock before begin_binding.
        // The caller must receive registry semantics, never a leaked FK error.
        let (delete_user, delete_device, delete_enrollment) =
            insert_device(&pool, "delete", valid_signer.clone()).await;
        let mut delete_tx = pool.begin().await.unwrap();
        sqlx::query("DELETE FROM devices WHERE user_did=$1 AND device_id=$2")
            .bind(&delete_user)
            .bind(&delete_device)
            .execute(&mut *delete_tx)
            .await
            .unwrap();
        let delete_application = format!("binding-delete-{delete_device}");
        let delete_pool = named_pool(&url, &delete_application).await;
        let delete_task =
            tokio::spawn(async move { begin_binding(&delete_pool, &delete_enrollment, now).await });
        wait_for_lock(&pool, &delete_application, &delete_task).await;
        delete_tx.commit().await.unwrap();
        assert_eq!(
            await_begin(delete_task).await.unwrap_err(),
            DeviceAuthError::RegistryMismatch
        );
        assert_eq!(
            challenge_count(&pool, &delete_user, &delete_device).await,
            0
        );

        // Deactivation must serialize before challenge insertion. A failed
        // begin leaves no challenge behind.
        let (inactive_user, inactive_device, inactive_enrollment) =
            insert_device(&pool, "inactive", valid_signer.clone()).await;
        let mut inactive_tx = pool.begin().await.unwrap();
        sqlx::query("UPDATE devices SET active=FALSE WHERE user_did=$1 AND device_id=$2")
            .bind(&inactive_user)
            .bind(&inactive_device)
            .execute(&mut *inactive_tx)
            .await
            .unwrap();
        let inactive_application = format!("binding-inactive-{inactive_device}");
        let inactive_pool = named_pool(&url, &inactive_application).await;
        let inactive_task =
            tokio::spawn(
                async move { begin_binding(&inactive_pool, &inactive_enrollment, now).await },
            );
        wait_for_lock(&pool, &inactive_application, &inactive_task).await;
        inactive_tx.commit().await.unwrap();
        assert_eq!(
            await_begin(inactive_task).await.unwrap_err(),
            DeviceAuthError::RegistryMismatch
        );
        assert_eq!(
            challenge_count(&pool, &inactive_user, &inactive_device).await,
            0
        );

        // Losing the row lock to an identity-key invalidation must recheck
        // the signer under that lock and roll back without a challenge.
        let (rekey_user, rekey_device, rekey_enrollment) =
            insert_device(&pool, "rekey", valid_signer).await;
        let mut rekey_tx = pool.begin().await.unwrap();
        sqlx::query(
            "UPDATE devices SET signature_public_key=NULL
             WHERE user_did=$1 AND device_id=$2",
        )
        .bind(&rekey_user)
        .bind(&rekey_device)
        .execute(&mut *rekey_tx)
        .await
        .unwrap();
        let rekey_application = format!("binding-rekey-{rekey_device}");
        let rekey_pool = named_pool(&url, &rekey_application).await;
        let rekey_task =
            tokio::spawn(async move { begin_binding(&rekey_pool, &rekey_enrollment, now).await });
        wait_for_lock(&pool, &rekey_application, &rekey_task).await;
        rekey_tx.commit().await.unwrap();
        assert_eq!(
            await_begin(rekey_task).await.unwrap_err(),
            DeviceAuthError::RegistryMismatch
        );
        assert_eq!(challenge_count(&pool, &rekey_user, &rekey_device).await, 0);

        // Invalid signer material is a registry mismatch and the failed
        // business transaction is atomic: no challenge can persist.
        let (invalid_user, invalid_device, invalid_enrollment) =
            insert_device(&pool, "invalidsigner", Some("not-hex".into())).await;
        assert_eq!(
            begin_binding(&pool, &invalid_enrollment, now)
                .await
                .unwrap_err(),
            DeviceAuthError::RegistryMismatch
        );
        assert_eq!(
            challenge_count(&pool, &invalid_user, &invalid_device).await,
            0
        );

        for user in [inactive_user, rekey_user, invalid_user] {
            sqlx::query("DELETE FROM users WHERE did=$1")
                .bind(user)
                .execute(&pool)
                .await
                .unwrap();
        }
        sqlx::query("DELETE FROM users WHERE did=$1")
            .bind(delete_user)
            .execute(&pool)
            .await
            .unwrap();
    }
}
