// Dedicated protocol-two receipt authority. Never signs with service-auth or
// cursor keys, never trusts a public key supplied by a receipt.
use super::super::direct_request_transcript::{
    direct_request_preparation_signing_bytes, direct_request_receipt_key_id,
    direct_request_signing_bytes, DirectRequestKind,
};
use p256::{
    ecdsa::{signature::Signer, Signature, SigningKey, VerifyingKey},
    pkcs8::DecodePrivateKey,
};
use serde_json::Value;
use sqlx::PgPool;
use std::collections::BTreeMap;

use super::super::request_push::{
    envelope_signing_bytes, RequestPushEligibilityBody, RequestPushEventBody,
    SignedInternalEnvelope, REQUEST_PUSH_ELIGIBILITY_DOMAIN, REQUEST_PUSH_EVENT_DOMAIN,
};

pub(crate) const REQUEST_RECEIPT_AUTHORITY: &str = "did:web:chat.catbird.blue";

pub(crate) struct DirectRequestReceiptSigner {
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
    pub(crate) fn configured(
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
        let public = signing_key.verifying_key().to_encoded_point(true);
        let key_id = direct_request_receipt_key_id(public.as_bytes()).map_err(|e| e.to_string())?;
        let document: Value =
            serde_json::from_str(document).map_err(|_| "invalid receipt DID document")?;
        if document["id"].as_str() != Some(REQUEST_RECEIPT_AUTHORITY) {
            return Err("receipt authority DID mismatch".into());
        }
        let methods = document["verificationMethod"]
            .as_array()
            .ok_or("missing receipt verification methods")?;
        let mut published_keys = BTreeMap::new();
        for method in methods {
            let id = method["id"].as_str().ok_or("method missing ID")?;
            if !id.starts_with("did:web:chat.catbird.blue#chat-request-receipt-") {
                continue;
            }
            if method["controller"].as_str() != Some(REQUEST_RECEIPT_AUTHORITY)
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
            if direct_request_receipt_key_id(&key).map_err(|e| e.to_string())? != id {
                return Err("request receipt method fingerprint mismatch".into());
            }
            if published_keys.insert(id.to_owned(), key).is_some() {
                return Err("duplicate receipt method".into());
            }
        }
        if published_keys.get(&key_id).map(Vec::as_slice) != Some(public.as_bytes()) {
            return Err("active receipt method is not published".into());
        }
        Ok(Self {
            signing_key,
            key_id,
            published_keys,
        })
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
        if value["authorityDid"].as_str() != Some(REQUEST_RECEIPT_AUTHORITY)
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
        if value["authorityDid"].as_str() != Some(REQUEST_RECEIPT_AUTHORITY)
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
    pub(crate) async fn validate_and_retain_keys(&self, pool: &PgPool) -> Result<(), String> {
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
            .bind(&self.key_id).bind(REQUEST_RECEIPT_AUTHORITY).bind(self.signing_key.verifying_key().to_encoded_point(true).as_bytes()).execute(&mut *tx).await.map_err(|_|"receipt registry insert")?;
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
            let public=key.verifying_key().to_encoded_point(true);
            let mut multikey=vec![0x80,0x24];multikey.extend_from_slice(public.as_bytes());
            serde_json::json!({"id":direct_request_receipt_key_id(public.as_bytes()).unwrap(),"controller":REQUEST_RECEIPT_AUTHORITY,"type":"Multikey","publicKeyMultibase":multibase::encode(multibase::Base::Base58Btc,multikey)})
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
    fn request_push_domains_are_distinct_and_sign_exact_base64url_body_bytes() {
        use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
        use chrono::{Duration, SecondsFormat, Utc};
        use p256::ecdsa::signature::Verifier;
        use uuid::Uuid;

        let receipt = key(41);
        let service = key(42);
        let pem = receipt.to_pkcs8_pem(LineEnding::LF).unwrap();
        let service_pem = service.to_pkcs8_pem(LineEnding::LF).unwrap();
        let signer = DirectRequestReceiptSigner::configured(
            pem.as_str(),
            service_pem.as_str(),
            &document(&[&receipt]),
        )
        .unwrap();
        let event = Uuid::new_v4();
        let request = Uuid::new_v4();
        let conversation = Uuid::new_v4();
        let first = Uuid::new_v4();
        let device = Uuid::new_v4();
        let now = Utc::now();
        let payload = super::super::super::request_push::request_push_event_payload_digest(
            event,
            request,
            conversation,
            first,
            "did:web:alice.example.org",
            "did:web:bob.example.org",
            &[device],
        )
        .unwrap();
        let envelope = signer
            .seal_request_push_event(RequestPushEventBody {
                protocol_version: 1,
                authority_did: REQUEST_RECEIPT_AUTHORITY.into(),
                key_id: signer.key_id().into(),
                event_id: event.to_string(),
                request_id: request.to_string(),
                conversation_id: conversation.to_string(),
                first_message_id: first.to_string(),
                sender_did: "did:web:alice.example.org".into(),
                recipient_did: "did:web:bob.example.org".into(),
                recipient_device_ids: vec![device.to_string()],
                payload_digest: URL_SAFE_NO_PAD.encode(payload),
                issued_at: now.to_rfc3339_opts(SecondsFormat::Millis, true),
                expires_at: (now + Duration::seconds(30))
                    .to_rfc3339_opts(SecondsFormat::Millis, true),
            })
            .unwrap();
        let body = URL_SAFE_NO_PAD.decode(&envelope.body).unwrap();
        let signature =
            Signature::from_slice(&URL_SAFE_NO_PAD.decode(&envelope.signature).unwrap()).unwrap();
        assert!(signature.normalize_s().is_none());
        let event_bytes = envelope_signing_bytes(REQUEST_PUSH_EVENT_DOMAIN, &body).unwrap();
        receipt
            .verifying_key()
            .verify(&event_bytes, &signature)
            .unwrap();
        let wrong_domain = envelope_signing_bytes(REQUEST_PUSH_ELIGIBILITY_DOMAIN, &body).unwrap();
        assert!(receipt
            .verifying_key()
            .verify(&wrong_domain, &signature)
            .is_err());
    }

    #[test]
    fn deterministic_request_push_interoperability_vector() {
        use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
        use p256::ecdsa::signature::Verifier;
        use uuid::Uuid;

        let receipt = key(41);
        let service = key(42);
        let pem = receipt.to_pkcs8_pem(LineEnding::LF).unwrap();
        let service_pem = service.to_pkcs8_pem(LineEnding::LF).unwrap();
        let authority_document = document(&[&receipt]);
        let signer = DirectRequestReceiptSigner::configured(
            pem.as_str(),
            service_pem.as_str(),
            &authority_document,
        )
        .unwrap();
        let event = Uuid::parse_str("00000000-0000-4000-8000-000000000001").unwrap();
        let request = Uuid::parse_str("00000000-0000-4000-8000-000000000002").unwrap();
        let conversation = Uuid::parse_str("00000000-0000-4000-8000-000000000003").unwrap();
        let first = Uuid::parse_str("00000000-0000-4000-8000-000000000004").unwrap();
        let device = Uuid::parse_str("00000000-0000-4000-8000-000000000005").unwrap();
        let registration = Uuid::parse_str("00000000-0000-4000-8000-000000000006").unwrap();
        let payload = super::super::super::request_push::request_push_event_payload_digest(
            event,
            request,
            conversation,
            first,
            "did:web:alice.example.org",
            "did:web:bob.example.org",
            &[device],
        )
        .unwrap();
        let event_body = RequestPushEventBody {
            protocol_version: 1,
            authority_did: REQUEST_RECEIPT_AUTHORITY.into(),
            key_id: signer.key_id().into(),
            event_id: event.to_string(),
            request_id: request.to_string(),
            conversation_id: conversation.to_string(),
            first_message_id: first.to_string(),
            sender_did: "did:web:alice.example.org".into(),
            recipient_did: "did:web:bob.example.org".into(),
            recipient_device_ids: vec![device.to_string()],
            payload_digest: URL_SAFE_NO_PAD.encode(payload),
            issued_at: "2026-09-19T12:00:00.000Z".into(),
            expires_at: "2026-09-19T12:00:30.000Z".into(),
        };
        let eligibility_body = RequestPushEligibilityBody {
            protocol_version: 1,
            authority_did: REQUEST_RECEIPT_AUTHORITY.into(),
            key_id: signer.key_id().into(),
            event_id: event.to_string(),
            request_id: request.to_string(),
            recipient_did: "did:web:bob.example.org".into(),
            device_id: device.to_string(),
            provider: "apns".into(),
            registration_id: registration.to_string(),
            token_generation: 7,
            binding_digest: URL_SAFE_NO_PAD.encode([7; 32]),
            target_key_id: URL_SAFE_NO_PAD.encode([8; 32]),
            device_auth_generation: 3,
            conversation_id: conversation.to_string(),
            first_message_id: first.to_string(),
            sender_did: "did:web:alice.example.org".into(),
            eligible: true,
            checked_at: "2026-09-19T12:00:01.000Z".into(),
            expires_at: "2026-09-19T12:00:06.000Z".into(),
        };
        let encode = |body: Vec<u8>, domain: &[u8]| {
            let signature = signer.sign(&envelope_signing_bytes(domain, &body).unwrap());
            let parsed = Signature::from_slice(&signature).unwrap();
            assert!(parsed.normalize_s().is_none());
            receipt
                .verifying_key()
                .verify(&envelope_signing_bytes(domain, &body).unwrap(), &parsed)
                .unwrap();
            SignedInternalEnvelope {
                body: URL_SAFE_NO_PAD.encode(body),
                signature: URL_SAFE_NO_PAD.encode(signature),
            }
        };
        let event_envelope = encode(
            serde_json::to_vec(&event_body).unwrap(),
            REQUEST_PUSH_EVENT_DOMAIN,
        );
        let eligibility_envelope = encode(
            serde_json::to_vec(&eligibility_body).unwrap(),
            REQUEST_PUSH_ELIGIBILITY_DOMAIN,
        );
        let vector = serde_json::json!({
            "version": 1,
            "authorityDidDocument": serde_json::from_str::<Value>(&authority_document).unwrap(),
            "compressedP256PublicKeyHex": hex::encode(receipt.verifying_key().to_encoded_point(true).as_bytes()),
            "keyId": signer.key_id(),
            "eventDomainBase64url": URL_SAFE_NO_PAD.encode(REQUEST_PUSH_EVENT_DOMAIN),
            "eligibilityDomainBase64url": URL_SAFE_NO_PAD.encode(REQUEST_PUSH_ELIGIBILITY_DOMAIN),
            "event": {"body": event_body, "envelope": event_envelope},
            "eligibility": {"body": eligibility_body, "envelope": eligibility_envelope}
        });
        println!(
            "REQUEST_PUSH_VECTOR={}",
            serde_json::to_string(&vector).unwrap()
        );
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
        if value["authorityDid"].as_str() != Some(REQUEST_RECEIPT_AUTHORITY)
            || value["keyId"].as_str() != Some(self.key_id())
        {
            return Err("acceptance receipt authority mismatch".into());
        }
        Ok(self.sign(
            &direct_request_signing_bytes(DirectRequestKind::AcceptanceCommit, body)
                .map_err(|e| e.to_string())?,
        ))
    }

    pub(crate) fn seal_request_push_event(
        &self,
        body: RequestPushEventBody,
    ) -> Result<SignedInternalEnvelope, String> {
        body.validate(chrono::Utc::now())
            .map_err(|e| e.to_string())?;
        self.seal_internal_push_body(body, REQUEST_PUSH_EVENT_DOMAIN)
    }

    pub(crate) fn seal_request_push_eligibility(
        &self,
        body: RequestPushEligibilityBody,
    ) -> Result<SignedInternalEnvelope, String> {
        body.validate(chrono::Utc::now())
            .map_err(|e| e.to_string())?;
        self.seal_internal_push_body(body, REQUEST_PUSH_ELIGIBILITY_DOMAIN)
    }

    fn seal_internal_push_body<T: serde::Serialize>(
        &self,
        body: T,
        domain: &[u8],
    ) -> Result<SignedInternalEnvelope, String> {
        use base64::engine::general_purpose::URL_SAFE_NO_PAD;
        use base64::Engine as _;
        let body = serde_json::to_vec(&body).map_err(|_| "invalid request push body")?;
        let value: Value =
            serde_json::from_slice(&body).map_err(|_| "invalid request push JSON")?;
        if value["authorityDid"].as_str() != Some(REQUEST_RECEIPT_AUTHORITY)
            || value["keyId"].as_str() != Some(self.key_id())
        {
            return Err("request push receipt authority mismatch".into());
        }
        let signing = envelope_signing_bytes(domain, &body).map_err(|e| e.to_string())?;
        Ok(SignedInternalEnvelope {
            body: URL_SAFE_NO_PAD.encode(&body),
            signature: URL_SAFE_NO_PAD.encode(self.sign(&signing)),
        })
    }
}
