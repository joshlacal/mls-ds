// Dedicated protocol-two receipt authority. Never signs with service-auth or
// cursor keys, never trusts a public key supplied by a receipt.
use super::super::direct_request_transcript::{
    direct_request_preparation_signing_bytes, direct_request_receipt_key_id,
    direct_request_receipt_key_id_for_authority, direct_request_signing_bytes, DirectRequestKind,
};
use p256::{
    ecdsa::{signature::Signer, Signature, SigningKey, VerifyingKey},
    pkcs8::DecodePrivateKey,
};
use serde_json::Value;
use sqlx::PgPool;
use std::collections::BTreeMap;

pub const REQUEST_RECEIPT_AUTHORITY: &str = "did:web:chat.catbird.blue";

pub struct DirectRequestReceiptSigner {
    authority_did: String,
    signing_key: SigningKey,
    key_id: String,
    published_keys: BTreeMap<String, Vec<u8>>,
}
impl std::fmt::Debug for DirectRequestReceiptSigner {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DirectRequestReceiptSigner")
            .field("key_id", &self.key_id)
            .finish_non_exhaustive()
    }
}
impl DirectRequestReceiptSigner {
    /// The caller supplies an operations-managed authority DID document, exactly
    /// as the existing sequencer receipt configuration does. Its trust source is
    /// configuration, never a candidate receipt or request field.
    pub fn configured(
        receipt_pem: &str,
        service_pem: &str,
        document: &str,
    ) -> Result<Self, String> {
        let signing_key = SigningKey::from_pkcs8_pem(receipt_pem)
            .map_err(|_| "invalid request receipt P256 key")?;
        let service_key = SigningKey::from_pkcs8_pem(service_pem)
            .map_err(|_| "invalid service signing key for separation check")?;
        if signing_key.verifying_key() == service_key.verifying_key() {
            return Err("request receipt key must differ from service-auth key".into());
        }
        let public_key = signing_key.verifying_key().to_encoded_point(true);
        let document: Value =
            serde_json::from_str(document).map_err(|_| "invalid receipt DID document")?;
        let doc_id = document["id"]
            .as_str()
            .ok_or("missing receipt authority DID in document")?;
        let authority_did = doc_id.to_owned();
        let key_id =
            direct_request_receipt_key_id_for_authority(&authority_did, public_key.as_bytes())
                .map_err(|e| e.to_string())?;
        let methods = document["verificationMethod"]
            .as_array()
            .ok_or("missing receipt verification methods")?;
        let expected_prefix = format!("{}#chat-request-receipt-", authority_did);
        let mut published_keys = BTreeMap::new();
        for method in methods {
            let id = method["id"].as_str().ok_or("method missing ID")?;
            if !id.starts_with(&expected_prefix) {
                continue;
            }
            if method["controller"].as_str() != Some(&authority_did)
                || method["type"].as_str() != Some("Multikey")
            {
                return Err("invalid request receipt method controller/type".into());
            }
            let (_, key) = multibase::decode(
                method["publicKeyMultibase"]
                    .as_str()
                    .ok_or("missing method public key")?,
            )
            .map_err(|_| "invalid method multibase")?;
            if key.len() != 35 || key[..2] != [0x80, 0x24] {
                return Err("request receipt method must be compressed P256 Multikey".into());
            }
            let key = key[2..].to_vec();
            let verified = VerifyingKey::from_sec1_bytes(&key)
                .map_err(|_| "invalid request receipt P256 public key")?;
            if &verified == service_key.verifying_key() {
                return Err("historical receipt key reuses service-auth key".into());
            }
            if direct_request_receipt_key_id_for_authority(&authority_did, &key)
                .map_err(|e| e.to_string())?
                != id
            {
                return Err("request receipt method fingerprint mismatch".into());
            }
            if published_keys.insert(id.to_owned(), key).is_some() {
                return Err("duplicate receipt method".into());
            }
        }
        if published_keys.get(&key_id).map(Vec::as_slice) != Some(public_key.as_bytes()) {
            return Err("active receipt method is not published".into());
        }
        Ok(Self {
            authority_did,
            signing_key,
            key_id,
            published_keys,
        })
    }
    pub(crate) fn authority_did(&self) -> &str {
        &self.authority_did
    }
    pub(crate) fn key_id(&self) -> &str {
        &self.key_id
    }
    fn sign(&self, bytes: &[u8]) -> [u8; 64] {
        let signature: Signature = self.signing_key.sign(bytes);
        signature
            .normalize_s()
            .unwrap_or(signature)
            .to_bytes()
            .into()
    }
    pub(crate) fn sign_preparation(&self, snapshot: &[u8]) -> Result<([u8; 32], [u8; 64]), String> {
        use sha2::{Digest, Sha256};
        let value: Value =
            serde_json::from_slice(snapshot).map_err(|_| "invalid preparation JSON")?;
        if value["authorityDid"].as_str() != Some(self.authority_did())
            || value["receiptKeyId"].as_str() != Some(self.key_id())
        {
            return Err("preparation receipt authority mismatch".into());
        }
        let bytes =
            direct_request_preparation_signing_bytes(snapshot).map_err(|e| e.to_string())?;
        Ok((Sha256::digest(&bytes).into(), self.sign(&bytes)))
    }
    pub(crate) fn sign_outcome(&self, body: &[u8]) -> Result<[u8; 64], String> {
        let value: Value = serde_json::from_slice(body).map_err(|_| "invalid outcome JSON")?;
        if value["authorityDid"].as_str() != Some(self.authority_did())
            || value["keyId"].as_str() != Some(self.key_id())
        {
            return Err("outcome receipt authority mismatch".into());
        }
        Ok(self.sign(
            &direct_request_signing_bytes(DirectRequestKind::Outcome, body)
                .map_err(|e| e.to_string())?,
        ))
    }
    /// Run before route activation. Existing keys must remain published with
    /// identical bytes through rotation; the new active key is retained first.
    pub async fn validate_and_retain_keys(&self, pool: &PgPool) -> Result<(), String> {
        let mut tx = pool
            .begin()
            .await
            .map_err(|_| "receipt registry transaction")?;
        sqlx::query("SELECT singleton FROM chat.direct_request_budget WHERE singleton FOR UPDATE")
            .fetch_one(&mut *tx)
            .await
            .map_err(|_| "receipt registry lock")?;
        let stored: Vec<(String, Vec<u8>)> =
            sqlx::query_as("SELECT key_id,public_key FROM chat.direct_request_receipt_keys")
                .fetch_all(&mut *tx)
                .await
                .map_err(|_| "receipt registry read")?;
        for (id, key) in stored {
            if self.published_keys.get(&id) != Some(&key) {
                return Err("historical request receipt method missing or changed".into());
            }
        }
        sqlx::query("INSERT INTO chat.direct_request_receipt_keys(key_id,authority_did,public_key,created_at) VALUES($1,$2,$3,clock_timestamp()) ON CONFLICT(key_id) DO NOTHING")
            .bind(&self.key_id).bind(self.authority_did()).bind(self.signing_key.verifying_key().to_encoded_point(true).as_bytes()).execute(&mut *tx).await.map_err(|_|"receipt registry insert")?;
        tx.commit()
            .await
            .map_err(|_| "receipt registry commit".to_owned())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use p256::pkcs8::{EncodePrivateKey, LineEnding};
    fn key(seed: u8) -> SigningKey {
        SigningKey::from_bytes((&[seed; 32]).into()).unwrap()
    }
    fn document(keys: &[&SigningKey]) -> String {
        let methods=keys.iter().map(|key|{
            let public_key=key.verifying_key().to_encoded_point(true);
            let mut multikey=vec![0x80,0x24];multikey.extend_from_slice(public_key.as_bytes());
            serde_json::json!({"id":direct_request_receipt_key_id(public_key.as_bytes()).unwrap(),"controller":REQUEST_RECEIPT_AUTHORITY,"type":"Multikey","publicKeyMultibase":multibase::encode(multibase::Base::Base58Btc,multikey)})
        }).collect::<Vec<_>>();
        serde_json::json!({"id":REQUEST_RECEIPT_AUTHORITY,"verificationMethod":methods}).to_string()
    }
    #[test]
    fn dedicated_key_and_unique_fingerprint_method_required() {
        let receipt = key(1);
        let service = key(2);
        let pem = receipt.to_pkcs8_pem(LineEnding::LF).unwrap();
        let service_pem = service.to_pkcs8_pem(LineEnding::LF).unwrap();
        assert!(DirectRequestReceiptSigner::configured(
            pem.as_str(),
            pem.as_str(),
            &document(&[&receipt])
        )
        .is_err());
        assert!(DirectRequestReceiptSigner::configured(
            pem.as_str(),
            service_pem.as_str(),
            &document(&[&receipt, &receipt])
        )
        .is_err());
        assert!(DirectRequestReceiptSigner::configured(
            pem.as_str(),
            service_pem.as_str(),
            &document(&[&service])
        )
        .is_err());
        let signer = DirectRequestReceiptSigner::configured(
            pem.as_str(),
            service_pem.as_str(),
            &document(&[&receipt]),
        )
        .unwrap();
        assert_eq!(
            signer.key_id(),
            direct_request_receipt_key_id(
                receipt.verifying_key().to_encoded_point(true).as_bytes()
            )
            .unwrap()
        );
    }
    #[test]
    fn rotation_keeps_old_fingerprint_methods_and_signatures_use_low_s() {
        use p256::ecdsa::signature::Verifier;
        let old = key(1);
        let new = key(2);
        let service = key(3);
        let pem = new.to_pkcs8_pem(LineEnding::LF).unwrap();
        let service_pem = service.to_pkcs8_pem(LineEnding::LF).unwrap();
        let signer = DirectRequestReceiptSigner::configured(
            pem.as_str(),
            service_pem.as_str(),
            &document(&[&old, &new]),
        )
        .unwrap();
        assert_eq!(signer.published_keys.len(), 2);
        let signature =
            Signature::from_slice(&signer.sign(b"test-domain\0test-transcript")).unwrap();
        assert!(signature.normalize_s().is_none());
        new.verifying_key()
            .verify(b"test-domain\0test-transcript", &signature)
            .unwrap();
        assert!(old
            .verifying_key()
            .verify(b"test-domain\0test-transcript", &signature)
            .is_err());
    }

    #[test]
    fn variable_configured_authority_signer_signs_and_verifies_own_authority() {
        use super::super::super::direct_request_transcript::verify_signed_request;
        let receipt = key(21);
        let service = key(22);
        let pem = receipt.to_pkcs8_pem(LineEnding::LF).unwrap();
        let service_pem = service.to_pkcs8_pem(LineEnding::LF).unwrap();
        let authority = "did:web:federated-node.example.org";

        let public_key = receipt.verifying_key().to_encoded_point(true);
        let mut multikey = vec![0x80, 0x24];
        multikey.extend_from_slice(public_key.as_bytes());
        let key_id =
            direct_request_receipt_key_id_for_authority(authority, public_key.as_bytes()).unwrap();
        let methods = vec![serde_json::json!({
            "id": key_id,
            "controller": authority,
            "type": "Multikey",
            "publicKeyMultibase": multibase::encode(multibase::Base::Base58Btc, multikey)
        })];
        let doc = serde_json::json!({
            "id": authority,
            "verificationMethod": methods
        })
        .to_string();

        let signer =
            DirectRequestReceiptSigner::configured(pem.as_str(), service_pem.as_str(), &doc)
                .unwrap();

        assert_eq!(signer.authority_did(), authority);
        assert_eq!(signer.key_id(), key_id);

        // Outcome receipt signed with configured authority
        let body = serde_json::json!({
            "$type": "blue.catbird.chat.defs#directRequestReceiptBody",
            "signatureDomain": "CATBIRD-DIRECT-REQUEST-OUTCOME\0",
            "protocolVersion": "2",
            "authorityDid": authority,
            "keyId": signer.key_id(),
            "receipt": {
                "$type": "blue.catbird.chat.defs#directRequestCancelledReceipt",
                "requestId": "12345678-1234-4234-8234-123456789abc",
                "requestDigest": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
                "recordedAt": "2026-09-19T12:00:00.000Z",
                "preparationRequestDigest": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
                "actorDid": "did:plc:aaaaaaaaaaaaaaaaaaaaaaaa",
                "actorDeviceId": "12345678-1234-4234-8234-123456789abc",
                "actorKeyId": "Zmh6rfhivXdsj8GLjp-OIAiXFIVu4jOzkCpZHQ1fKSU",
                "authGeneration": 1,
                "requestKind": "cancel"
            }
        });
        let sealed = signer.seal_outcome(body.clone()).unwrap();

        // Verify passes with matching public key
        let verified = verify_signed_request(
            DirectRequestKind::Outcome,
            sealed.bytes(),
            public_key.as_bytes(),
        )
        .unwrap();
        assert_eq!(verified.body()["authorityDid"], authority);

        // Mismatched authority in body is rejected during signing
        let mut bad_body = body.clone();
        bad_body["authorityDid"] = serde_json::json!("did:web:chat.catbird.blue");
        assert!(signer.seal_outcome(bad_body).is_err());

        // Mismatched key_id is rejected during signing
        let mut bad_key_id = body.clone();
        bad_key_id["keyId"] = serde_json::json!("did:web:other#key-1");
        assert!(signer.seal_outcome(bad_key_id).is_err());
    }
}

/// Opaque receipt produced by the configured dedicated authority, not by a
/// candidate-supplied key. Completion consumers inspect its validated body.
pub(crate) struct SignedDirectRequestReceipt {
    body: Value,
    bytes: Vec<u8>,
}
impl SignedDirectRequestReceipt {
    pub(crate) fn body(&self) -> &Value {
        &self.body
    }
    pub(crate) fn bytes(&self) -> &[u8] {
        &self.bytes
    }
}
impl DirectRequestReceiptSigner {
    pub(crate) fn seal_outcome(&self, body: Value) -> Result<SignedDirectRequestReceipt, String> {
        use base64::Engine as _;
        let signature =
            self.sign_outcome(&serde_json::to_vec(&body).map_err(|_| "invalid outcome body")?)?;
        let bytes=serde_json::to_vec(&serde_json::json!({"body":body,"signature":base64::engine::general_purpose::STANDARD.encode(signature)})).map_err(|_|"invalid outcome envelope")?;
        Ok(SignedDirectRequestReceipt { body, bytes })
    }
}

impl DirectRequestReceiptSigner {
    pub(crate) fn sign_acceptance(&self, body: &[u8]) -> Result<[u8; 64], String> {
        let value: Value =
            serde_json::from_slice(body).map_err(|_| "invalid acceptance receipt JSON")?;
        if value["authorityDid"].as_str() != Some(self.authority_did())
            || value["keyId"].as_str() != Some(self.key_id())
        {
            return Err("acceptance receipt authority mismatch".into());
        }
        Ok(self.sign(
            &direct_request_signing_bytes(DirectRequestKind::AcceptanceCommit, body)
                .map_err(|e| e.to_string())?,
        ))
    }
}
