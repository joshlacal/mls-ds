//! Wire fixtures for the delivery service's Space token and response contracts.
#![allow(dead_code)]

use anyhow::{ensure, Context, Result};
use axum::http::HeaderMap;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use p256::{ecdsa::SigningKey, elliptic_curve::sec1::ToEncodedPoint, PublicKey, SecretKey};
use petrel_spaces::{MacProfile, SigningKeyPair, SpaceRequestHeaders, VerifiedCommitMac};
use serde_json::{json, Value};

pub fn did_key(key: &PublicKey) -> String {
    petrel_spaces::encode_p256_did_key(key.to_encoded_point(true).as_bytes())
        .expect("P-256 fixture key")
}

fn sign_fixture(key: &SigningKey, typ: &str, kid: &str, claims: Value) -> String {
    let encode = |value| URL_SAFE_NO_PAD.encode(serde_json::to_vec(&value).unwrap());
    let header = encode(json!({"alg": "ES256", "typ": typ, "kid": kid}));
    let input = format!("{header}.{}", encode(claims));
    let pair = SigningKeyPair::from_p256_bytes(&key.to_bytes()).unwrap();
    let signature = pair.sign(input.as_bytes()).unwrap();
    format!("{input}.{}", URL_SAFE_NO_PAD.encode(signature))
}

/// Keep the service fragment in the audience so existing tokens remain covered.
pub fn delegation(key: &SigningKey, issuer: &str, space: &str, jti: &str, now: u64) -> String {
    let space = petrel_spaces::parse_space_ref(space).unwrap();
    sign_fixture(
        key,
        petrel_spaces::DELEGATION_JWT_TYP,
        "#atproto",
        json!({
            "iss": issuer, "aud": format!("{}#atproto_pds", space.space_did()), "sub": space,
            "iat": now, "exp": now + 60, "jti": jti,
        }),
    )
}

/// The confidential OAuth client's attestation carries its HTTPS client ID.
pub fn client_attestation(
    key: &SigningKey,
    client_id: &str,
    authority: &str,
    jti: &str,
    now: u64,
) -> String {
    sign_fixture(
        key,
        petrel_spaces::CLIENT_ATTESTATION_JWT_TYP,
        "oauth-client-k1",
        json!({
            "iss": client_id, "aud": format!("{authority}#atproto_pds"), "sub": client_id,
            "iat": now, "exp": now + 120, "jti": jti,
        }),
    )
}

pub fn signed_headers(
    key: &SecretKey,
    jwt: &str,
    audience: &str,
    now: u64,
    nonce: &str,
) -> petrel_spaces::Result<SpaceRequestHeaders> {
    petrel_spaces::sign_credential_request(
        jwt,
        &SigningKeyPair::from_p256_bytes(&key.to_bytes())?,
        audience,
        now as i64,
        Some(nonce),
    )
}

fn header<'a>(headers: &'a HeaderMap, name: &'static str) -> Result<&'a str> {
    Ok(headers
        .get(name)
        .with_context(|| format!("missing {name}"))?
        .to_str()?)
}

pub fn verified_commit(
    secret: &[u8; 32],
    key: &str,
    headers: &HeaderMap,
    space: &str,
    repo: &str,
) -> Result<VerifiedCommitMac> {
    let commit = petrel_spaces::verify_commit_mac(
        secret,
        header(headers, MacProfile::Commit.response_header())?,
        header(headers, "signature-input")?,
        header(headers, "signature")?,
    )?;
    ensure!(
        commit.keyid == key && commit.space.as_str() == space && commit.repo.as_str() == repo,
        "commit MAC bound different key, Space or writer"
    );
    Ok(commit)
}

pub fn verify_record(
    secret: &[u8; 32],
    key: &str,
    headers: &HeaderMap,
    uri: &str,
    cid: &str,
) -> Result<()> {
    let record = petrel_spaces::verify_record_mac(
        secret,
        header(headers, MacProfile::Record.response_header())?,
        header(headers, "signature-input")?,
        header(headers, "signature")?,
    )?;
    ensure!(
        record.keyid == key && record.uri.as_str() == uri && record.cid.to_string() == cid,
        "record MAC bound different key, URI or CID"
    );
    Ok(())
}
