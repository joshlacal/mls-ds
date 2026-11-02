//! Dynamic `SERVICE_DID` DID document generation (`did:web` and `did:plc`) for
//! self-hosted and federated `mls-ds` deployments (`#atproto`, `#mls-receipt-1`,
//! `#atproto_mls`, and `#atproto_pds` Option A Space host).

use p256::ecdsa::VerifyingKey;
use serde_json::{json, Value};

use super::canonical_did;
pub use super::did_web_document_path;
use crate::chat_protocol::direct_request_transcript::direct_request_receipt_key_id_for_authority;

/// Encode a P-256 public key as a compressed `Multikey` (`0x80 0x24` `p256-pub` multicodec + 33-byte SEC1 compressed point in `base58btc`).
pub fn encode_p256_multikey(verifying_key: &VerifyingKey) -> String {
    let compressed = verifying_key.to_encoded_point(true);
    let mut multicodec = Vec::with_capacity(2 + compressed.as_bytes().len());
    multicodec.extend_from_slice(&[0x80, 0x24]);
    multicodec.extend_from_slice(compressed.as_bytes());
    multibase::encode(multibase::Base::Base58Btc, multicodec)
}

/// Build the canonical DID document for a `mls-ds` instance identified by `service_did`
/// (`did:web:...` or `did:plc:...`) at `service_endpoint`.
///
/// Advertises:
/// - `{service_did}#atproto`: P-256 `Multikey` used for S2S JWTs and Space-host credentials;
/// - `{service_did}#mls-receipt-1` (when `receipt_verifying_key` is provided): P-256 `Multikey`
///   used for `I13` sequencer receipts;
/// - `#atproto_mls` (`AtprotoMlsDeliveryService`) and `#atproto_pds` (`AtprotoPersonalDataServer`
///   Option A conversation Space host).
pub fn build_service_did_document(
    service_did: &str,
    service_endpoint: &str,
    service_auth_verifying_key: &VerifyingKey,
    receipt_verifying_key: Option<&VerifyingKey>,
) -> Value {
    let base_did = canonical_did(service_did);
    let endpoint = service_endpoint.trim_end_matches('/');
    let mut methods = vec![json!({
        "id": format!("{base_did}#atproto"),
        "type": "Multikey",
        "controller": base_did,
        "publicKeyMultibase": encode_p256_multikey(service_auth_verifying_key),
    })];
    if let Some(receipt_vk) = receipt_verifying_key {
        let receipt_multikey = encode_p256_multikey(receipt_vk);
        methods.push(json!({
            "id": format!("{base_did}#mls-receipt-1"),
            "type": "Multikey",
            "controller": base_did,
            "publicKeyMultibase": receipt_multikey,
        }));
        let compressed = receipt_vk.to_encoded_point(true);
        if let Ok(req_key_id) =
            direct_request_receipt_key_id_for_authority(base_did, compressed.as_bytes())
        {
            methods.push(json!({
                "id": req_key_id,
                "type": "Multikey",
                "controller": base_did,
                "publicKeyMultibase": encode_p256_multikey(receipt_vk),
            }));
        }
    }
    json!({
        "@context": [
            "https://www.w3.org/ns/did/v1",
            "https://w3id.org/security/multikey/v1"
        ],
        "id": base_did,
        "verificationMethod": methods,
        "service": [
            {
                "id": "#atproto_mls",
                "type": "AtprotoMLSDeliveryService",
                "serviceEndpoint": endpoint,
            },
            {
                "id": "#atproto_pds",
                "type": "AtprotoPersonalDataServer",
                "serviceEndpoint": endpoint,
            }
        ]
    })
}

/// Build a DID document advertising a `C33` direct-request receipt verification method
/// (`{authority_did}#chat-request-receipt-...`) for `DirectRequestReceiptSigner::configured`.
pub fn build_direct_request_receipt_did_document(
    authority_did: &str,
    receipt_verifying_key: &VerifyingKey,
) -> Value {
    let base_did = canonical_did(authority_did);
    let compressed = receipt_verifying_key.to_encoded_point(true);
    let key_id = direct_request_receipt_key_id_for_authority(base_did, compressed.as_bytes())
        .expect("compressed P-256 point produces valid direct-request receipt key_id");
    json!({
        "@context": [
            "https://www.w3.org/ns/did/v1",
            "https://w3id.org/security/multikey/v1"
        ],
        "id": base_did,
        "verificationMethod": [
            {
                "id": key_id,
                "type": "Multikey",
                "controller": base_did,
                "publicKeyMultibase": encode_p256_multikey(receipt_verifying_key),
            }
        ]
    })
}
