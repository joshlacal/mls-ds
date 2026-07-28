// Trusted-Nest token and DPoP cryptographic verification for clean chat.
//
// Successful values are deliberately *pre-replay* evidence. They are
// non-Clone, cannot be constructed outside this module, and do not represent
// device authority until the repository atomically consumes all replay keys
// and validates stored device state in the same transaction.

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use p256::{
    ecdsa::{signature::Verifier, Signature, VerifyingKey},
    EncodedPoint, FieldBytes,
};
use serde::de::DeserializeOwned;
use serde::Deserialize;
use sha2::{Digest, Sha256};

use super::{
    model::AuthPrimitiveError,
    repository::auth::RepositoryAuthorityReceipt,
    transcript::{
        verify_signed_mutation, CanonicalRebindBootstrap, CanonicalSignedMutation,
        VerifiedEnrollmentBody, VerifiedSignedMutation,
    },
    validation::{
        decode_canonical_base64url, enrollment_grant_expiry, validate_first_execution_signed_at,
        BareDid, CanonicalHttpMethod, CanonicalUuidV4, DpopAuthorization, KeyThumbprint,
        NumericDate, ProofJti, TrustedExternalBase, TrustedRequestInstant, ValidatedChatNsid,
    },
};

pub(crate) const MAX_TRUSTED_NEST_ISSUER_BYTES: usize = 2048;
pub(crate) const MAX_TRUSTED_NEST_AUDIENCE_BYTES: usize = 2048;
pub(crate) const MAX_TRUSTED_NEST_KEY_ID_BYTES: usize = 256;

#[derive(Debug)]
pub(crate) struct TrustedNestVerifier {
    issuer: String,
    audience: String,
    chat_instance: CanonicalUuidV4,
    key_id: String,
    verifying_key: VerifyingKey,
    external_base: TrustedExternalBase,
}

impl TrustedNestVerifier {
    pub(crate) fn new(
        issuer: &str,
        audience: &str,
        chat_instance: CanonicalUuidV4,
        key_id: &str,
        verifying_key: VerifyingKey,
        external_base: TrustedExternalBase,
    ) -> Result<Self, AuthPrimitiveError> {
        if issuer.is_empty()
            || issuer.len() > MAX_TRUSTED_NEST_ISSUER_BYTES
            || audience.is_empty()
            || audience.len() > MAX_TRUSTED_NEST_AUDIENCE_BYTES
            || key_id.is_empty()
            || key_id.len() > MAX_TRUSTED_NEST_KEY_ID_BYTES
            || !issuer.is_ascii()
            || !audience.is_ascii()
            || !key_id.is_ascii()
        {
            return Err(AuthPrimitiveError::invalid(
                "invalid trusted Nest configuration",
            ));
        }
        Ok(Self {
            issuer: issuer.to_owned(),
            audience: audience.to_owned(),
            chat_instance,
            key_id: key_id.to_owned(),
            verifying_key,
            external_base,
        })
    }

    pub(crate) fn external_base(&self) -> &TrustedExternalBase {
        &self.external_base
    }
}

#[derive(Debug, Eq, PartialEq)]
pub struct TokenReplayIdentity {
    issuer: String,
    jti: CanonicalUuidV4,
}

impl TokenReplayIdentity {
    pub fn issuer(&self) -> &str {
        &self.issuer
    }
    pub fn jti(&self) -> &CanonicalUuidV4 {
        &self.jti
    }
}

#[derive(Debug, Eq, PartialEq)]
pub struct ProofReplayIdentity {
    jkt: KeyThumbprint,
    jti: ProofJti,
}

impl ProofReplayIdentity {
    pub fn jkt(&self) -> &KeyThumbprint {
        &self.jkt
    }
    pub fn jti_bytes(&self) -> &[u8] {
        self.jti.decoded()
    }
}

#[derive(Debug, Eq, PartialEq)]
pub struct AuthTransactionReplayIdentity {
    issuer: String,
    auth_txn: CanonicalUuidV4,
}

impl AuthTransactionReplayIdentity {
    pub fn issuer(&self) -> &str {
        &self.issuer
    }
    pub fn auth_txn(&self) -> &CanonicalUuidV4 {
        &self.auth_txn
    }
}

#[derive(Debug, Eq, PartialEq)]
pub struct EnrollmentGrantEvidence {
    key_id: KeyThumbprint,
    signing_key_sha256: [u8; 32],
    enrollment_transcript_sha256: [u8; 32],
    auth_time: NumericDate,
}

impl EnrollmentGrantEvidence {
    pub fn key_id(&self) -> &KeyThumbprint {
        &self.key_id
    }
    pub fn signing_key_sha256(&self) -> &[u8; 32] {
        &self.signing_key_sha256
    }
    pub fn enrollment_transcript_sha256(&self) -> &[u8; 32] {
        &self.enrollment_transcript_sha256
    }
    pub fn auth_time(&self) -> NumericDate {
        self.auth_time
    }
}

/// Cryptographic evidence that still requires one atomic repository operation
/// to consume token/proof/auth-transaction identities and validate the exact
/// stored device row. It is neither final authority nor replay-consumed state.
#[derive(Debug)]
pub struct PreReplayCryptographicVerification {
    subject: BareDid,
    audience: String,
    device_id: CanonicalUuidV4,
    dpop_jkt: KeyThumbprint,
    token_replay: TokenReplayIdentity,
    proof_replay: ProofReplayIdentity,
    auth_transaction_replay: Option<AuthTransactionReplayIdentity>,
    enrollment: Option<EnrollmentGrantEvidence>,
    enrollment_body: Option<VerifiedEnrollmentBody>,
    rebind: Option<CanonicalRebindBootstrap>,
    endpoint: ValidatedChatNsid,
    method: CanonicalHttpMethod,
    htu: String,
    trusted_instant: TrustedRequestInstant,
    chat_instance: CanonicalUuidV4,
    token_iat: NumericDate,
    token_exp: NumericDate,
    proof_iat: NumericDate,
    token_sha256: [u8; 32],
    proof_sha256: [u8; 32],
}

impl PreReplayCryptographicVerification {
    pub fn subject(&self) -> &BareDid {
        &self.subject
    }
    pub fn audience(&self) -> &str {
        &self.audience
    }
    pub fn device_id(&self) -> &CanonicalUuidV4 {
        &self.device_id
    }
    pub fn dpop_jkt(&self) -> &KeyThumbprint {
        &self.dpop_jkt
    }
    pub fn token_replay(&self) -> &TokenReplayIdentity {
        &self.token_replay
    }
    pub fn proof_replay(&self) -> &ProofReplayIdentity {
        &self.proof_replay
    }
    pub fn auth_transaction_replay(&self) -> Option<&AuthTransactionReplayIdentity> {
        self.auth_transaction_replay.as_ref()
    }
    pub fn auth_time(&self) -> Option<NumericDate> {
        self.enrollment
            .as_ref()
            .map(EnrollmentGrantEvidence::auth_time)
    }
    pub fn enrollment(&self) -> Option<&EnrollmentGrantEvidence> {
        self.enrollment.as_ref()
    }
    pub fn enrollment_body(&self) -> Option<&VerifiedEnrollmentBody> {
        self.enrollment_body.as_ref()
    }
    pub fn validate_enrollment_first_execution_signed_at(&self) -> Result<(), AuthPrimitiveError> {
        let body = self
            .enrollment_body
            .as_ref()
            .ok_or_else(|| AuthPrimitiveError::invalid("authentication is not enrollment"))?;
        validate_first_execution_signed_at(body.signed_at(), &self.trusted_instant)
    }
    pub fn rebind_bootstrap(&self) -> Option<&CanonicalRebindBootstrap> {
        self.rebind.as_ref()
    }
    pub fn validate_rebind_first_execution_signed_at(&self) -> Result<(), AuthPrimitiveError> {
        let bootstrap = self
            .rebind
            .as_ref()
            .ok_or_else(|| AuthPrimitiveError::invalid("authentication is not a rebind"))?;
        validate_first_execution_signed_at(bootstrap.signed_at(), &self.trusted_instant)
    }
    pub fn verify_rebind_stored_signing_key(
        &self,
        stored_public_key: &[u8],
    ) -> Result<(), AuthPrimitiveError> {
        self.rebind
            .as_ref()
            .ok_or_else(|| AuthPrimitiveError::invalid("authentication is not a rebind"))?
            .verify_signature_with_stored_key(stored_public_key)
    }
    pub fn endpoint(&self) -> &ValidatedChatNsid {
        &self.endpoint
    }
    pub fn method(&self) -> &CanonicalHttpMethod {
        &self.method
    }
    pub fn htu(&self) -> &str {
        &self.htu
    }
    pub fn trusted_instant(&self) -> &TrustedRequestInstant {
        &self.trusted_instant
    }
    pub fn chat_instance(&self) -> &CanonicalUuidV4 {
        &self.chat_instance
    }
    pub fn token_iat(&self) -> NumericDate {
        self.token_iat
    }
    pub fn token_exp(&self) -> NumericDate {
        self.token_exp
    }
    pub fn proof_iat(&self) -> NumericDate {
        self.proof_iat
    }
    pub fn token_sha256(&self) -> &[u8; 32] {
        &self.token_sha256
    }
    pub fn proof_sha256(&self) -> &[u8; 32] {
        &self.proof_sha256
    }
    pub const fn requires_atomic_replay_consumption(&self) -> bool {
        true
    }
}

/// Final, non-Clone request authority. The only constructors require the
/// repository's sealed receipt proving that replay consumption committed.
#[derive(Debug)]
pub struct VerifiedChatDeviceRequest {
    pre_replay: PreReplayCryptographicVerification,
    mutation: Option<VerifiedSignedMutation>,
    repository_receipt: RepositoryAuthorityReceipt,
}

impl VerifiedChatDeviceRequest {
    pub fn subject(&self) -> &BareDid {
        self.pre_replay.subject()
    }

    pub fn device_id(&self) -> &CanonicalUuidV4 {
        self.pre_replay.device_id()
    }

    pub fn dpop_jkt(&self) -> &KeyThumbprint {
        self.pre_replay.dpop_jkt()
    }

    pub fn endpoint(&self) -> &ValidatedChatNsid {
        self.pre_replay.endpoint()
    }

    pub fn trusted_instant(&self) -> &TrustedRequestInstant {
        self.pre_replay.trusted_instant()
    }

    pub fn mutation(&self) -> Option<&VerifiedSignedMutation> {
        self.mutation.as_ref().or_else(|| {
            self.pre_replay
                .enrollment_body()
                .map(VerifiedEnrollmentBody::mutation)
        })
    }

    pub(super) fn repository_receipt(&self) -> &RepositoryAuthorityReceipt {
        &self.repository_receipt
    }

    pub(super) fn pre_replay(&self) -> &PreReplayCryptographicVerification {
        &self.pre_replay
    }
}

pub(super) fn mint_unsigned_repository_authority(
    pre_replay: PreReplayCryptographicVerification,
    repository_receipt: RepositoryAuthorityReceipt,
) -> VerifiedChatDeviceRequest {
    VerifiedChatDeviceRequest {
        pre_replay,
        mutation: None,
        repository_receipt,
    }
}

pub(super) fn mint_signed_repository_authority(
    pre_replay: PreReplayCryptographicVerification,
    canonical: CanonicalSignedMutation,
    stored_public_key: &[u8],
    repository_receipt: RepositoryAuthorityReceipt,
) -> Result<VerifiedChatDeviceRequest, AuthPrimitiveError> {
    validate_first_execution_signed_at(canonical.signed_at(), pre_replay.trusted_instant())?;
    let mutation = verify_signed_mutation(canonical, stored_public_key)?;
    Ok(VerifiedChatDeviceRequest {
        pre_replay,
        mutation: Some(mutation),
        repository_receipt,
    })
}

pub(super) fn mint_enrollment_repository_authority(
    pre_replay: PreReplayCryptographicVerification,
    repository_receipt: RepositoryAuthorityReceipt,
) -> Result<VerifiedChatDeviceRequest, AuthPrimitiveError> {
    pre_replay.validate_enrollment_first_execution_signed_at()?;
    Ok(VerifiedChatDeviceRequest {
        pre_replay,
        mutation: None,
        repository_receipt,
    })
}

pub(super) fn mint_rebind_repository_authority(
    mut pre_replay: PreReplayCryptographicVerification,
    stored_public_key: &[u8],
    repository_receipt: RepositoryAuthorityReceipt,
) -> Result<VerifiedChatDeviceRequest, AuthPrimitiveError> {
    pre_replay.validate_rebind_first_execution_signed_at()?;
    let bootstrap = pre_replay
        .rebind
        .take()
        .ok_or_else(|| AuthPrimitiveError::invalid("authentication is not a rebind"))?;
    let mutation = bootstrap.verify_with_stored_key(stored_public_key)?;
    Ok(VerifiedChatDeviceRequest {
        pre_replay,
        mutation: Some(mutation),
        repository_receipt,
    })
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct TokenHeader {
    alg: String,
    typ: String,
    kid: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ConfirmationClaim {
    jkt: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct OrdinaryClaims {
    iss: String,
    sub: String,
    aud: String,
    lxm: String,
    iat: i64,
    exp: i64,
    jti: String,
    cnf: ConfirmationClaim,
    device_id: String,
    chat_instance: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct EnrollmentClaims {
    iss: String,
    sub: String,
    aud: String,
    lxm: String,
    iat: i64,
    exp: i64,
    jti: String,
    cnf: ConfirmationClaim,
    device_id: String,
    chat_instance: String,
    key_id: String,
    signing_key_sha256: String,
    enrollment_transcript_sha256: String,
    auth_time: i64,
    auth_txn: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct DpopHeader {
    typ: String,
    alg: String,
    jwk: PublicP256Jwk,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct PublicP256Jwk {
    kty: String,
    crv: String,
    x: String,
    y: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct DpopClaims {
    htm: String,
    htu: String,
    ath: String,
    iat: i64,
    jti: String,
}

#[derive(Debug)]
struct CommonClaims {
    subject: BareDid,
    device_id: CanonicalUuidV4,
    dpop_jkt: KeyThumbprint,
    token_jti: CanonicalUuidV4,
    iat: NumericDate,
    exp: NumericDate,
}

#[derive(Debug)]
struct TokenClaims {
    common: CommonClaims,
    enrollment: Option<EnrollmentGrantEvidence>,
    auth_txn: Option<CanonicalUuidV4>,
}

enum AuthClass<'a> {
    Ordinary,
    Enrollment(&'a VerifiedEnrollmentBody),
    Rebind(&'a CanonicalRebindBootstrap),
}

pub(crate) fn verify_ordinary_request_auth(
    trust: &TrustedNestVerifier,
    authorization: &str,
    dpop_proof: &str,
    endpoint: &ValidatedChatNsid,
    method: &CanonicalHttpMethod,
    trusted_instant: &TrustedRequestInstant,
) -> Result<PreReplayCryptographicVerification, AuthPrimitiveError> {
    if matches!(
        endpoint.as_str(),
        "blue.catbird.chat.enrollDevice"
            | "blue.catbird.chat.rebindDeviceAuthentication"
            | "blue.catbird.chat.subscribeEvents"
    ) {
        return Err(AuthPrimitiveError::invalid(
            "endpoint has a non-ordinary authentication class",
        ));
    }
    if method != &endpoint.dpop_method()? {
        return Err(AuthPrimitiveError::invalid(
            "HTTP method does not match the endpoint-owned profile",
        ));
    }
    verify_for_class(
        trust,
        authorization,
        dpop_proof,
        endpoint,
        method,
        trusted_instant,
        AuthClass::Ordinary,
    )
}

pub(crate) fn verify_enrollment_request_auth(
    trust: &TrustedNestVerifier,
    authorization: &str,
    dpop_proof: &str,
    body: VerifiedEnrollmentBody,
    trusted_instant: &TrustedRequestInstant,
) -> Result<PreReplayCryptographicVerification, AuthPrimitiveError> {
    let endpoint = ValidatedChatNsid::parse("blue.catbird.chat.enrollDevice")?;
    let method = endpoint.dpop_method()?;
    let mut verified = verify_for_class(
        trust,
        authorization,
        dpop_proof,
        &endpoint,
        &method,
        trusted_instant,
        AuthClass::Enrollment(&body),
    )?;
    verified.enrollment_body = Some(body);
    Ok(verified)
}

pub(crate) fn verify_rebind_request_auth(
    trust: &TrustedNestVerifier,
    authorization: &str,
    dpop_proof: &str,
    body: CanonicalRebindBootstrap,
    trusted_instant: &TrustedRequestInstant,
) -> Result<PreReplayCryptographicVerification, AuthPrimitiveError> {
    let endpoint = ValidatedChatNsid::parse("blue.catbird.chat.rebindDeviceAuthentication")?;
    let method = endpoint.dpop_method()?;
    let mut verified = verify_for_class(
        trust,
        authorization,
        dpop_proof,
        &endpoint,
        &method,
        trusted_instant,
        AuthClass::Rebind(&body),
    )?;
    verified.rebind = Some(body);
    Ok(verified)
}

fn verify_for_class(
    trust: &TrustedNestVerifier,
    authorization: &str,
    dpop_proof: &str,
    endpoint: &ValidatedChatNsid,
    method: &CanonicalHttpMethod,
    trusted_instant: &TrustedRequestInstant,
    class: AuthClass<'_>,
) -> Result<PreReplayCryptographicVerification, AuthPrimitiveError> {
    let access_token = DpopAuthorization::parse(authorization)?.token();
    let token_parts = CompactJws::parse(access_token)?;
    let token_header: TokenHeader = token_parts.decode_header()?;
    if token_header.alg != "ES256" || token_header.typ != "JWT" || token_header.kid != trust.key_id
    {
        return Err(AuthPrimitiveError::invalid("untrusted Nest token header"));
    }
    token_parts.verify(&trust.verifying_key)?;
    let token_claims = match class {
        AuthClass::Ordinary => validate_ordinary_claims(
            trust,
            endpoint,
            trusted_instant,
            token_parts.decode_payload()?,
        )?,
        AuthClass::Enrollment(body) => validate_enrollment_claims(
            trust,
            endpoint,
            trusted_instant,
            body,
            token_parts.decode_payload()?,
        )?,
        AuthClass::Rebind(body) => {
            let claims = validate_ordinary_claims(
                trust,
                endpoint,
                trusted_instant,
                token_parts.decode_payload()?,
            )?;
            if claims.common.subject != *body.subject()
                || claims.common.device_id != *body.device_id()
                || claims.common.dpop_jkt != *body.new_dpop_jkt()
            {
                return Err(AuthPrimitiveError::invalid(
                    "rebind token/body bootstrap mismatch",
                ));
            }
            claims
        }
    };

    let proof_parts = CompactJws::parse(dpop_proof)?;
    let proof_header: DpopHeader = proof_parts.decode_header()?;
    if proof_header.typ != "dpop+jwt" || proof_header.alg != "ES256" {
        return Err(AuthPrimitiveError::invalid("invalid DPoP header"));
    }
    let (proof_key, proof_jkt) = proof_header.jwk.verifying_key_and_thumbprint()?;
    proof_parts.verify(&proof_key)?;
    if proof_jkt != token_claims.common.dpop_jkt {
        return Err(AuthPrimitiveError::invalid("token and proof JKT mismatch"));
    }
    let proof_claims: DpopClaims = proof_parts.decode_payload()?;
    let (proof_jti, proof_iat) = validate_dpop_claims(
        endpoint,
        method,
        trusted_instant,
        trust,
        access_token,
        proof_claims,
    )?;
    let token_hash = Sha256::digest(access_token.as_bytes()).into();
    let proof_hash = Sha256::digest(dpop_proof.as_bytes()).into();
    let token_replay = TokenReplayIdentity {
        issuer: trust.issuer.clone(),
        jti: token_claims.common.token_jti,
    };
    let proof_replay = ProofReplayIdentity {
        jkt: proof_jkt,
        jti: proof_jti,
    };
    let auth_transaction_replay =
        token_claims
            .auth_txn
            .map(|auth_txn| AuthTransactionReplayIdentity {
                issuer: trust.issuer.clone(),
                auth_txn,
            });
    Ok(PreReplayCryptographicVerification {
        subject: token_claims.common.subject,
        audience: trust.audience.clone(),
        device_id: token_claims.common.device_id,
        dpop_jkt: token_claims.common.dpop_jkt,
        token_replay,
        proof_replay,
        auth_transaction_replay,
        enrollment: token_claims.enrollment,
        enrollment_body: None,
        rebind: None,
        endpoint: endpoint.clone(),
        method: method.clone(),
        htu: trust.external_base.htu(endpoint),
        trusted_instant: trusted_instant.clone(),
        chat_instance: trust.chat_instance.clone(),
        token_iat: token_claims.common.iat,
        token_exp: token_claims.common.exp,
        proof_iat,
        token_sha256: token_hash,
        proof_sha256: proof_hash,
    })
}

fn validate_ordinary_claims(
    trust: &TrustedNestVerifier,
    endpoint: &ValidatedChatNsid,
    trusted_instant: &TrustedRequestInstant,
    claims: OrdinaryClaims,
) -> Result<TokenClaims, AuthPrimitiveError> {
    let common = validate_common_claims(
        trust,
        endpoint,
        trusted_instant,
        &claims.iss,
        &claims.sub,
        &claims.aud,
        &claims.lxm,
        claims.iat,
        claims.exp,
        &claims.jti,
        &claims.cnf.jkt,
        &claims.device_id,
        &claims.chat_instance,
    )?;
    Ok(TokenClaims {
        common,
        enrollment: None,
        auth_txn: None,
    })
}

fn validate_enrollment_claims(
    trust: &TrustedNestVerifier,
    endpoint: &ValidatedChatNsid,
    trusted_instant: &TrustedRequestInstant,
    body: &VerifiedEnrollmentBody,
    claims: EnrollmentClaims,
) -> Result<TokenClaims, AuthPrimitiveError> {
    let common = validate_common_claims(
        trust,
        endpoint,
        trusted_instant,
        &claims.iss,
        &claims.sub,
        &claims.aud,
        &claims.lxm,
        claims.iat,
        claims.exp,
        &claims.jti,
        &claims.cnf.jkt,
        &claims.device_id,
        &claims.chat_instance,
    )?;
    let iat = NumericDate::new(claims.iat)?;
    let auth_time = NumericDate::new(claims.auth_time)?;
    if NumericDate::new(claims.exp)? != enrollment_grant_expiry(iat, auth_time)? {
        return Err(AuthPrimitiveError::invalid("wrong enrollment grant expiry"));
    }
    let now = trusted_numeric_date(trusted_instant)?;
    let auth_age = now
        .get()
        .checked_sub(auth_time.get())
        .ok_or_else(|| AuthPrimitiveError::invalid("auth_time is in the future"))?;
    if !(0..=300).contains(&auth_age) {
        return Err(AuthPrimitiveError::invalid(
            "auth_time is outside enrollment window",
        ));
    }
    let key_id = KeyThumbprint::parse(&claims.key_id)?;
    let signing_key_sha256 = decode_fixed_sha256(&claims.signing_key_sha256)?;
    let enrollment_transcript_sha256 = decode_fixed_sha256(&claims.enrollment_transcript_sha256)?;
    if common.subject != *body.subject()
        || common.device_id != *body.device_id()
        || common.dpop_jkt != *body.dpop_jkt()
        || key_id != *body.key_id()
        || signing_key_sha256 != *body.signing_key_sha256()
        || enrollment_transcript_sha256 != *body.enrollment_transcript_sha256()
    {
        return Err(AuthPrimitiveError::invalid(
            "enrollment grant/body binding mismatch",
        ));
    }
    Ok(TokenClaims {
        common,
        enrollment: Some(EnrollmentGrantEvidence {
            key_id,
            signing_key_sha256,
            enrollment_transcript_sha256,
            auth_time,
        }),
        auth_txn: Some(CanonicalUuidV4::parse(&claims.auth_txn)?),
    })
}

#[allow(clippy::too_many_arguments)]
fn validate_common_claims(
    trust: &TrustedNestVerifier,
    endpoint: &ValidatedChatNsid,
    trusted_instant: &TrustedRequestInstant,
    issuer: &str,
    subject: &str,
    audience: &str,
    lxm: &str,
    iat: i64,
    exp: i64,
    token_jti: &str,
    dpop_jkt: &str,
    device_id: &str,
    chat_instance: &str,
) -> Result<CommonClaims, AuthPrimitiveError> {
    if issuer != trust.issuer
        || audience != trust.audience
        || lxm != endpoint.as_str()
        || chat_instance != trust.chat_instance.as_str()
    {
        return Err(AuthPrimitiveError::invalid(
            "Nest token configuration binding mismatch",
        ));
    }
    let iat = NumericDate::new(iat)?;
    let exp = NumericDate::new(exp)?;
    let lifetime = exp
        .get()
        .checked_sub(iat.get())
        .ok_or_else(|| AuthPrimitiveError::invalid("reversed token lifetime"))?;
    if !(1..=120).contains(&lifetime) {
        return Err(AuthPrimitiveError::invalid(
            "token lifetime exceeds profile",
        ));
    }
    let now = trusted_numeric_date(trusted_instant)?;
    if now < iat || now >= exp {
        return Err(AuthPrimitiveError::invalid("token is not currently valid"));
    }
    Ok(CommonClaims {
        subject: BareDid::parse(subject)?,
        device_id: CanonicalUuidV4::parse(device_id)?,
        dpop_jkt: KeyThumbprint::parse(dpop_jkt)?,
        token_jti: CanonicalUuidV4::parse(token_jti)?,
        iat,
        exp,
    })
}

fn validate_dpop_claims(
    endpoint: &ValidatedChatNsid,
    method: &CanonicalHttpMethod,
    trusted_instant: &TrustedRequestInstant,
    trust: &TrustedNestVerifier,
    access_token: &str,
    claims: DpopClaims,
) -> Result<(ProofJti, NumericDate), AuthPrimitiveError> {
    let expected_htu = trust.external_base.htu(endpoint);
    let expected_ath = URL_SAFE_NO_PAD.encode(Sha256::digest(access_token.as_bytes()));
    if claims.htm != method.as_str() || claims.htu != expected_htu || claims.ath != expected_ath {
        return Err(AuthPrimitiveError::invalid(
            "DPoP method, target, or ath mismatch",
        ));
    }
    let proof_iat = NumericDate::new(claims.iat)?;
    let now = trusted_numeric_date(trusted_instant)?;
    if proof_iat.get().abs_diff(now.get()) > 60 {
        return Err(AuthPrimitiveError::invalid(
            "DPoP proof outside trusted window",
        ));
    }
    Ok((ProofJti::parse(&claims.jti)?, proof_iat))
}

fn trusted_numeric_date(value: &TrustedRequestInstant) -> Result<NumericDate, AuthPrimitiveError> {
    NumericDate::new(value.datetime().timestamp())
}

fn decode_fixed_sha256(value: &str) -> Result<[u8; 32], AuthPrimitiveError> {
    decode_canonical_base64url(value)?
        .try_into()
        .map_err(|_| AuthPrimitiveError::invalid("SHA-256 claim length"))
}

impl PublicP256Jwk {
    fn verifying_key_and_thumbprint(
        &self,
    ) -> Result<(VerifyingKey, KeyThumbprint), AuthPrimitiveError> {
        if self.kty != "EC" || self.crv != "P-256" {
            return Err(AuthPrimitiveError::invalid("DPoP JWK is not P-256"));
        }
        let x: [u8; 32] = decode_canonical_base64url(&self.x)?
            .try_into()
            .map_err(|_| AuthPrimitiveError::invalid("DPoP JWK x length"))?;
        let y: [u8; 32] = decode_canonical_base64url(&self.y)?
            .try_into()
            .map_err(|_| AuthPrimitiveError::invalid("DPoP JWK y length"))?;
        let point = EncodedPoint::from_affine_coordinates(
            FieldBytes::from_slice(&x),
            FieldBytes::from_slice(&y),
            false,
        );
        let verifying_key = VerifyingKey::from_encoded_point(&point)
            .map_err(|_| AuthPrimitiveError::invalid("DPoP JWK point is invalid"))?;
        let canonical = format!(
            "{{\"crv\":\"P-256\",\"kty\":\"EC\",\"x\":\"{}\",\"y\":\"{}\"}}",
            self.x, self.y
        );
        let jkt = URL_SAFE_NO_PAD.encode(Sha256::digest(canonical.as_bytes()));
        Ok((verifying_key, KeyThumbprint::parse(&jkt)?))
    }
}

struct CompactJws<'a> {
    encoded_header: &'a str,
    encoded_payload: &'a str,
    signature: Signature,
}

impl<'a> CompactJws<'a> {
    fn parse(value: &'a str) -> Result<Self, AuthPrimitiveError> {
        let mut parts = value.split('.');
        let encoded_header = parts
            .next()
            .ok_or_else(|| AuthPrimitiveError::invalid("missing JWS header"))?;
        let encoded_payload = parts
            .next()
            .ok_or_else(|| AuthPrimitiveError::invalid("missing JWS payload"))?;
        let encoded_signature = parts
            .next()
            .ok_or_else(|| AuthPrimitiveError::invalid("missing JWS signature"))?;
        if parts.next().is_some()
            || encoded_header.len() > 4096
            || encoded_payload.len() > 16384
            || encoded_signature.len() != 86
        {
            return Err(AuthPrimitiveError::invalid("invalid compact JWS shape"));
        }
        let signature_bytes = decode_canonical_base64url(encoded_signature)?;
        let signature = Signature::from_slice(&signature_bytes)
            .map_err(|_| AuthPrimitiveError::invalid("invalid ES256 signature length"))?;
        Ok(Self {
            encoded_header,
            encoded_payload,
            signature,
        })
    }
    fn decode_header<T: DeserializeOwned>(&self) -> Result<T, AuthPrimitiveError> {
        decode_strict_json_segment(self.encoded_header, "invalid JWS header JSON")
    }
    fn decode_payload<T: DeserializeOwned>(&self) -> Result<T, AuthPrimitiveError> {
        decode_strict_json_segment(self.encoded_payload, "invalid JWS payload JSON")
    }
    fn verify(&self, key: &VerifyingKey) -> Result<(), AuthPrimitiveError> {
        let signing_input = format!("{}.{}", self.encoded_header, self.encoded_payload);
        key.verify(signing_input.as_bytes(), &self.signature)
            .map_err(|_| AuthPrimitiveError::invalid("invalid ES256 signature"))
    }
}

fn decode_strict_json_segment<T: DeserializeOwned>(
    encoded: &str,
    reason: &'static str,
) -> Result<T, AuthPrimitiveError> {
    let decoded = decode_canonical_base64url(encoded)?;
    serde_json::from_slice(&decoded).map_err(|_| AuthPrimitiveError::invalid(reason))
}

#[cfg(test)]
pub(crate) mod repository_test_evidence {
    use super::super::validation::CanonicalTimestamp;
    use super::*;

    pub(crate) fn ordinary_missing_device() -> PreReplayCryptographicVerification {
        ordinary_missing_device_with_replay(
            uuid::Uuid::parse_str("33333333-3333-4333-8333-333333333333").unwrap(),
            [0; 12],
        )
    }

    pub(crate) fn ordinary_missing_device_with_replay(
        token_jti_value: uuid::Uuid,
        proof_jti_bytes: [u8; 12],
    ) -> PreReplayCryptographicVerification {
        let subject = BareDid::parse("did:plc:aaaaaaaaaaaaaaaaaaaaaaaa")
            .expect("fixed test DID is canonical");
        let device_id = CanonicalUuidV4::parse("11111111-1111-4111-8111-111111111111")
            .expect("fixed test device UUID is canonical");
        let chat_instance = CanonicalUuidV4::parse("22222222-2222-4222-8222-222222222222")
            .expect("fixed test instance UUID is canonical");
        let token_jti = CanonicalUuidV4::parse(&token_jti_value.hyphenated().to_string())
            .expect("caller supplied a canonical UUIDv4");
        let dpop_jkt = KeyThumbprint::parse("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
            .expect("fixed test JKT is canonical");
        let trusted_instant = TrustedRequestInstant::from_canonical_for_test(
            CanonicalTimestamp::parse("2026-07-22T12:00:00.000Z")
                .expect("fixed trusted timestamp is canonical"),
        );
        let now = trusted_instant.datetime().timestamp();
        let endpoint = ValidatedChatNsid::parse("blue.catbird.chat.getDevices")
            .expect("fixed endpoint is canonical");
        PreReplayCryptographicVerification {
            subject,
            audience: "did:web:chat.catbird.blue".to_owned(),
            device_id,
            dpop_jkt: dpop_jkt.clone(),
            token_replay: TokenReplayIdentity {
                issuer: "did:web:api.catbird.blue".to_owned(),
                jti: token_jti,
            },
            proof_replay: ProofReplayIdentity {
                jkt: dpop_jkt,
                jti: ProofJti::parse(&URL_SAFE_NO_PAD.encode(proof_jti_bytes))
                    .expect("fixed proof JTI is canonical"),
            },
            auth_transaction_replay: None,
            enrollment: None,
            enrollment_body: None,
            rebind: None,
            endpoint,
            method: CanonicalHttpMethod::parse("GET").expect("fixed method is canonical"),
            htu: "https://chat.catbird.blue/xrpc/blue.catbird.chat.getDevices".to_owned(),
            trusted_instant,
            chat_instance,
            token_iat: NumericDate::new(now - 10).expect("fixed token iat is valid"),
            token_exp: NumericDate::new(now + 110).expect("fixed token exp is valid"),
            proof_iat: NumericDate::new(now).expect("fixed proof iat is valid"),
            token_sha256: Sha256::digest(token_jti_value.as_bytes()).into(),
            proof_sha256: Sha256::digest(proof_jti_bytes).into(),
        }
    }

    pub(crate) fn ordinary_registered_device(
        token_jti_value: uuid::Uuid,
        proof_jti_bytes: [u8; 12],
        endpoint_name: &str,
        trusted_at: &str,
    ) -> PreReplayCryptographicVerification {
        let subject = BareDid::parse("did:plc:ewvi7nxzyoun6zhxrhs64oiz")
            .expect("fixed test DID is canonical");
        let device_id = CanonicalUuidV4::parse("3b241101-e2bb-4255-8caf-4136c566a962")
            .expect("fixed test device UUID is canonical");
        let chat_instance = CanonicalUuidV4::parse("018f3f6a-7b2c-4d91-8a5e-0f123456789a")
            .expect("fixed test instance UUID is canonical");
        let token_jti = CanonicalUuidV4::parse(&token_jti_value.hyphenated().to_string())
            .expect("caller supplied a canonical UUIDv4");
        let dpop_jkt = KeyThumbprint::parse("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
            .expect("fixed test JKT is canonical");
        let trusted_instant = TrustedRequestInstant::from_canonical_for_test(
            CanonicalTimestamp::parse(trusted_at).expect("trusted test timestamp is canonical"),
        );
        let now = trusted_instant.datetime().timestamp();
        let endpoint =
            ValidatedChatNsid::parse(endpoint_name).expect("test endpoint is in the closed set");
        let method = endpoint
            .dpop_method()
            .expect("test endpoint uses request DPoP");
        PreReplayCryptographicVerification {
            subject,
            audience: "did:web:chat.catbird.blue".to_owned(),
            device_id,
            dpop_jkt: dpop_jkt.clone(),
            token_replay: TokenReplayIdentity {
                issuer: "did:web:api.catbird.blue".to_owned(),
                jti: token_jti,
            },
            proof_replay: ProofReplayIdentity {
                jkt: dpop_jkt,
                jti: ProofJti::parse(&URL_SAFE_NO_PAD.encode(proof_jti_bytes))
                    .expect("fixed proof JTI is canonical"),
            },
            auth_transaction_replay: None,
            enrollment: None,
            enrollment_body: None,
            rebind: None,
            htu: format!("https://chat.catbird.blue/xrpc/{endpoint_name}"),
            endpoint,
            method,
            trusted_instant,
            chat_instance,
            token_iat: NumericDate::new(now - 10).expect("fixed token iat is valid"),
            token_exp: NumericDate::new(now + 110).expect("fixed token exp is valid"),
            proof_iat: NumericDate::new(now).expect("fixed proof iat is valid"),
            token_sha256: Sha256::digest(token_jti_value.as_bytes()).into(),
            proof_sha256: Sha256::digest(proof_jti_bytes).into(),
        }
    }

    pub(crate) fn ordinary_device_with_binding(
        token_jti_value: uuid::Uuid,
        proof_jti_bytes: [u8; 12],
        endpoint_name: &str,
        trusted_at: &str,
        subject_value: &str,
        device_id_value: uuid::Uuid,
        dpop_jkt_value: &str,
    ) -> PreReplayCryptographicVerification {
        let subject = BareDid::parse(subject_value).expect("test DID is canonical");
        let device_id = CanonicalUuidV4::parse(&device_id_value.hyphenated().to_string())
            .expect("test device UUID is canonical");
        let chat_instance = CanonicalUuidV4::parse("018f3f6a-7b2c-4d91-8a5e-0f123456789a")
            .expect("fixed test instance UUID is canonical");
        let token_jti = CanonicalUuidV4::parse(&token_jti_value.hyphenated().to_string())
            .expect("caller supplied a canonical UUIDv4");
        let dpop_jkt = KeyThumbprint::parse(dpop_jkt_value).expect("test DPoP JKT is canonical");
        let trusted_instant = TrustedRequestInstant::from_canonical_for_test(
            CanonicalTimestamp::parse(trusted_at).expect("trusted test timestamp is canonical"),
        );
        let now = trusted_instant.datetime().timestamp();
        let endpoint =
            ValidatedChatNsid::parse(endpoint_name).expect("test endpoint is in the closed set");
        let method = endpoint
            .dpop_method()
            .expect("test endpoint uses request DPoP");
        PreReplayCryptographicVerification {
            subject,
            audience: "did:web:chat.catbird.blue".to_owned(),
            device_id,
            dpop_jkt: dpop_jkt.clone(),
            token_replay: TokenReplayIdentity {
                issuer: "did:web:api.catbird.blue".to_owned(),
                jti: token_jti,
            },
            proof_replay: ProofReplayIdentity {
                jkt: dpop_jkt,
                jti: ProofJti::parse(&URL_SAFE_NO_PAD.encode(proof_jti_bytes))
                    .expect("test proof JTI is canonical"),
            },
            auth_transaction_replay: None,
            enrollment: None,
            enrollment_body: None,
            rebind: None,
            htu: format!("https://chat.catbird.blue/xrpc/{endpoint_name}"),
            endpoint,
            method,
            trusted_instant,
            chat_instance,
            token_iat: NumericDate::new(now - 10).expect("test token iat is valid"),
            token_exp: NumericDate::new(now + 110).expect("test token exp is valid"),
            proof_iat: NumericDate::new(now).expect("test proof iat is valid"),
            token_sha256: Sha256::digest(token_jti_value.as_bytes()).into(),
            proof_sha256: Sha256::digest(proof_jti_bytes).into(),
        }
    }

    pub(crate) fn enrollment_with_replay(
        body: VerifiedEnrollmentBody,
        token_jti_value: uuid::Uuid,
        proof_jti_bytes: [u8; 12],
        auth_txn_value: uuid::Uuid,
        trusted_at: &str,
    ) -> PreReplayCryptographicVerification {
        let subject = BareDid::parse(body.subject().as_str()).expect("test DID is canonical");
        let device_id =
            CanonicalUuidV4::parse(body.device_id().as_str()).expect("test device is canonical");
        let dpop_jkt =
            KeyThumbprint::parse(body.dpop_jkt().as_str()).expect("test DPoP JKT is canonical");
        let key_id =
            KeyThumbprint::parse(body.key_id().as_str()).expect("test key ID is canonical");
        let signing_key_sha256 = *body.signing_key_sha256();
        let enrollment_transcript_sha256 = *body.enrollment_transcript_sha256();
        let trusted_instant = TrustedRequestInstant::from_canonical_for_test(
            CanonicalTimestamp::parse(trusted_at).expect("trusted test timestamp is canonical"),
        );
        let now = trusted_instant.datetime().timestamp();
        let token_jti = CanonicalUuidV4::parse(&token_jti_value.hyphenated().to_string())
            .expect("test token JTI is canonical");
        let auth_txn = CanonicalUuidV4::parse(&auth_txn_value.hyphenated().to_string())
            .expect("test auth transaction is canonical");
        let chat_instance = CanonicalUuidV4::parse("018f3f6a-7b2c-4d91-8a5e-0f123456789a")
            .expect("fixed test instance UUID is canonical");
        let endpoint = ValidatedChatNsid::parse("blue.catbird.chat.enrollDevice")
            .expect("enrollment endpoint is canonical");
        PreReplayCryptographicVerification {
            subject,
            audience: "did:web:chat.catbird.blue".to_owned(),
            device_id,
            dpop_jkt: dpop_jkt.clone(),
            token_replay: TokenReplayIdentity {
                issuer: "did:web:api.catbird.blue".to_owned(),
                jti: token_jti,
            },
            proof_replay: ProofReplayIdentity {
                jkt: dpop_jkt,
                jti: ProofJti::parse(&URL_SAFE_NO_PAD.encode(proof_jti_bytes))
                    .expect("test proof JTI is canonical"),
            },
            auth_transaction_replay: Some(AuthTransactionReplayIdentity {
                issuer: "did:web:api.catbird.blue".to_owned(),
                auth_txn,
            }),
            enrollment: Some(EnrollmentGrantEvidence {
                key_id,
                signing_key_sha256,
                enrollment_transcript_sha256,
                auth_time: NumericDate::new(now - 20).expect("test auth time is valid"),
            }),
            enrollment_body: Some(body),
            rebind: None,
            htu: "https://chat.catbird.blue/xrpc/blue.catbird.chat.enrollDevice".to_owned(),
            endpoint,
            method: CanonicalHttpMethod::parse("POST").expect("POST is canonical"),
            trusted_instant,
            chat_instance,
            token_iat: NumericDate::new(now - 10).expect("test token iat is valid"),
            token_exp: NumericDate::new(now + 110).expect("test token exp is valid"),
            proof_iat: NumericDate::new(now).expect("test proof iat is valid"),
            token_sha256: Sha256::digest(token_jti_value.as_bytes()).into(),
            proof_sha256: Sha256::digest(proof_jti_bytes).into(),
        }
    }

    pub(crate) fn rebind_with_replay(
        bootstrap: CanonicalRebindBootstrap,
        token_jti_value: uuid::Uuid,
        proof_jti_bytes: [u8; 12],
        trusted_at: &str,
    ) -> PreReplayCryptographicVerification {
        let subject = BareDid::parse(bootstrap.subject().as_str()).expect("test DID is canonical");
        let device_id = CanonicalUuidV4::parse(bootstrap.device_id().as_str())
            .expect("test device is canonical");
        let dpop_jkt = KeyThumbprint::parse(bootstrap.new_dpop_jkt().as_str())
            .expect("test new DPoP JKT is canonical");
        let trusted_instant = TrustedRequestInstant::from_canonical_for_test(
            CanonicalTimestamp::parse(trusted_at).expect("trusted test timestamp is canonical"),
        );
        let now = trusted_instant.datetime().timestamp();
        let token_jti = CanonicalUuidV4::parse(&token_jti_value.hyphenated().to_string())
            .expect("test token JTI is canonical");
        let chat_instance = CanonicalUuidV4::parse("018f3f6a-7b2c-4d91-8a5e-0f123456789a")
            .expect("fixed test instance UUID is canonical");
        let endpoint = ValidatedChatNsid::parse("blue.catbird.chat.rebindDeviceAuthentication")
            .expect("rebind endpoint is canonical");
        PreReplayCryptographicVerification {
            subject,
            audience: "did:web:chat.catbird.blue".to_owned(),
            device_id,
            dpop_jkt: dpop_jkt.clone(),
            token_replay: TokenReplayIdentity {
                issuer: "did:web:api.catbird.blue".to_owned(),
                jti: token_jti,
            },
            proof_replay: ProofReplayIdentity {
                jkt: dpop_jkt,
                jti: ProofJti::parse(&URL_SAFE_NO_PAD.encode(proof_jti_bytes))
                    .expect("test proof JTI is canonical"),
            },
            auth_transaction_replay: None,
            enrollment: None,
            enrollment_body: None,
            rebind: Some(bootstrap),
            htu: "https://chat.catbird.blue/xrpc/blue.catbird.chat.rebindDeviceAuthentication"
                .to_owned(),
            endpoint,
            method: CanonicalHttpMethod::parse("POST").expect("POST is canonical"),
            trusted_instant,
            chat_instance,
            token_iat: NumericDate::new(now - 10).expect("test token iat is valid"),
            token_exp: NumericDate::new(now + 110).expect("test token exp is valid"),
            proof_iat: NumericDate::new(now).expect("test proof iat is valid"),
            token_sha256: Sha256::digest(token_jti_value.as_bytes()).into(),
            proof_sha256: Sha256::digest(proof_jti_bytes).into(),
        }
    }
}
