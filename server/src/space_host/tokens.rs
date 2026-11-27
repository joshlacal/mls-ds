//! The deployed host accepts URL-based OAuth client attestations and credentials
//! lasting up to one hour. Keep that profile at the service boundary.
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use petrel_core::Did;
use petrel_crypto::{ATProtoJWTVerificationKey, ATProtoSignatureVerificationOptions, StrictJSON};
use petrel_spaces::{CnfClaim, JwtHeader, SpaceError, SpaceRef};
use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum SpaceTokenKind {
    Delegation,
    Credential,
    ClientAttestation,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub(crate) struct SpaceTokenClaims {
    pub iss: String,
    pub sub: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub aud: Option<String>,
    pub iat: u64,
    pub exp: u64,
    pub jti: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cnf: Option<CnfClaim>,
}

impl SpaceTokenClaims {
    pub fn cnf_kid(&self) -> Option<&str> {
        self.cnf.as_ref().map(|cnf| cnf.kid.as_str())
    }
}

pub(crate) struct ParsedToken<'a> {
    pub claims: SpaceTokenClaims,
    pub header: JwtHeader,
    signing_input: &'a [u8],
    signature: Vec<u8>,
}

impl<'a> ParsedToken<'a> {
    /// Parse and validate the application profile before resolving an issuer-controlled URL.
    pub fn parse(kind: SpaceTokenKind, jwt: &'a str, now: u64) -> petrel_spaces::Result<Self> {
        let invalid = || SpaceError::InvalidTokenFormat;
        if jwt.len() > 8192 {
            return Err(invalid());
        }
        let (signing_input, sig) = jwt.rsplit_once('.').ok_or_else(invalid)?;
        let (hdr, payload) = signing_input.split_once('.').ok_or_else(invalid)?;
        if hdr.len() > 4096 || payload.len() > 4096 {
            return Err(invalid());
        }
        let header_bytes = URL_SAFE_NO_PAD.decode(hdr).map_err(|_| invalid())?;
        let header_object: serde_json::Map<String, serde_json::Value> =
            StrictJSON::decode(&header_bytes).map_err(|_| invalid())?;
        if ["jwk", "crit", "b64", "x5c", "jku"]
            .iter()
            .any(|key| header_object.contains_key(*key))
        {
            return Err(invalid());
        }
        let header: JwtHeader =
            serde_json::from_value(header_object.into()).map_err(|_| invalid())?;
        let claims: SpaceTokenClaims =
            StrictJSON::decode(&URL_SAFE_NO_PAD.decode(payload).map_err(|_| invalid())?)
                .map_err(|_| invalid())?;
        let signature = URL_SAFE_NO_PAD.decode(sig).map_err(|_| invalid())?;
        if signature.len() != 64
            || claims.jti.is_empty()
            || claims.jti.len() > 512
            || !claims.jti.bytes().all(|b| b > 0x20 && b != 0x7f)
        {
            return Err(invalid());
        }
        let (typ, ttl, lead, skew) = match kind {
            SpaceTokenKind::Credential => (petrel_spaces::CREDENTIAL_JWT_TYP, 3600, 5, 60),
            SpaceTokenKind::Delegation => (petrel_spaces::DELEGATION_JWT_TYP, 60, 5, 5),
            SpaceTokenKind::ClientAttestation => {
                (petrel_spaces::CLIENT_ATTESTATION_JWT_TYP, 600, 60, 60)
            }
        };
        if header.typ != typ
            || claims.exp <= claims.iat
            || claims.exp - claims.iat > ttl
            || claims.iat > now.saturating_add(lead)
            || now > claims.exp.saturating_add(skew)
        {
            return Err(invalid());
        }
        let kid = header.kid.as_deref().ok_or_else(invalid)?;
        if kind == SpaceTokenKind::ClientAttestation {
            let url = url::Url::parse(&claims.iss).map_err(|_| invalid())?;
            let aud = claims
                .aud
                .as_deref()
                .and_then(|s| s.strip_suffix("#atproto_pds"))
                .ok_or_else(invalid)?;
            if header.alg != "ES256"
                || kid.is_empty()
                || kid.len() > 1024
                || kid.bytes().any(|b| b < 0x20 || b == 0x7f)
                || url.scheme() != "https"
                || url.as_str() != claims.iss
                || claims.sub != claims.iss
                || Did::parse(aud).is_err()
            {
                return Err(invalid());
            }
        } else {
            let space = SpaceRef::parse(&claims.sub).map_err(|_| invalid())?;
            if !matches!(header.alg.as_str(), "ES256" | "ES256K")
                || (kid != "#atproto" && kid != format!("{}#atproto", claims.iss))
                || Did::parse(&claims.iss).is_err()
            {
                return Err(invalid());
            }
            if kind == SpaceTokenKind::Credential {
                if space.space_did().as_str() != claims.iss || claims.aud.is_some() {
                    return Err(invalid());
                }
                petrel_spaces::decode_p256_did_key(claims.cnf_kid().ok_or_else(invalid)?)?;
            } else if claims.aud != Some(format!("{}#atproto_pds", space.space_did()))
                || claims.cnf.is_some()
            {
                return Err(invalid());
            }
        }
        Ok(Self {
            claims,
            header,
            signing_input: signing_input.as_bytes(),
            signature,
        })
    }

    pub fn verify(&self, key: &ATProtoJWTVerificationKey) -> bool {
        verify_compact(key, &self.header.alg, self.signing_input, &self.signature)
    }
}

pub(crate) fn verify_compact(
    key: &ATProtoJWTVerificationKey,
    alg: &str,
    input: &[u8],
    sig: &[u8],
) -> bool {
    key.verify_with_options(sig, input, alg, ATProtoSignatureVerificationOptions::JWT)
        .unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;

    const ISSUER: &str = "did:plc:ragtjsm2j2vknwk6zpkrhgah";
    const SPACE_DID: &str = "did:web:space.example.com";

    fn delegation_with_kid(kid: &str, now: u64) -> String {
        let header = serde_json::json!({
            "alg": "ES256",
            "typ": petrel_spaces::DELEGATION_JWT_TYP,
            "kid": kid,
        });
        let claims = serde_json::json!({
            "iss": ISSUER,
            "sub": format!("at:space/{SPACE_DID}/blue.catbird.circle/self"),
            "aud": format!("{SPACE_DID}#atproto_pds"),
            "iat": now,
            "exp": now + 30,
            "jti": "delegation-kid-pin",
        });
        let enc = |v: &serde_json::Value| URL_SAFE_NO_PAD.encode(v.to_string());
        format!(
            "{}.{}.{}",
            enc(&header),
            enc(&claims),
            URL_SAFE_NO_PAD.encode([7u8; 64])
        )
    }

    /// Pins the accepted delegation and credential `kid` forms. Every deployed
    /// producer (Swan's `PermissionedDataJWT.delegationKeyID` and
    /// `spaceCredentialKeyID`, catbird-mls, nest, this server) signs with the
    /// bare `#atproto`; the issuer-qualified form names the same key. A
    /// fragment naming another DID's key, which the pre-migration
    /// `ends_with("#atproto")` check let through, is refused.
    #[test]
    fn space_token_kid_must_be_issuer_atproto_key() {
        let now = 1_800_000_000;
        for kid in ["#atproto".to_string(), format!("{ISSUER}#atproto")] {
            let jwt = delegation_with_kid(&kid, now);
            assert!(
                ParsedToken::parse(SpaceTokenKind::Delegation, &jwt, now).is_ok(),
                "kid {kid} must be accepted"
            );
        }
        for kid in [
            "did:plc:aaaaaaaaaaaaaaaaaaaaaaaa#atproto",
            "other#atproto",
            "#atproto_pds",
            "",
        ] {
            let jwt = delegation_with_kid(kid, now);
            assert!(
                ParsedToken::parse(SpaceTokenKind::Delegation, &jwt, now).is_err(),
                "kid {kid:?} must be refused"
            );
        }
    }
}
