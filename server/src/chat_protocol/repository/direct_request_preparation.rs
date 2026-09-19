include!("direct_request_store.rs");

mod signed_admission {
    use super::*;
    use crate::auth::VerifiedServicePrincipal;
    use crate::chat_protocol::direct_request_transcript::{
        self, DirectRequestKind, VerifiedDirectRequest,
    };
    use base64::{engine::general_purpose::STANDARD, Engine as _};
    use serde_json::{json, Value};

    pub(super) struct LockedRequestActor {
        transaction_id: String,
        pub(super) signed: VerifiedDirectRequest,
        signing_key: Vec<u8>,
        now: DateTime<Utc>,
    }

    fn invalid<T>() -> Result<T, DirectRequestStoreError> {
        Err(DirectRequestStoreError::IdentityConflict)
    }
    fn text_field<'a>(body: &'a Value, key: &str) -> Result<&'a str, DirectRequestStoreError> {
        body[key]
            .as_str()
            .ok_or(DirectRequestStoreError::IdentityConflict)
    }
    fn uuid_field(body: &Value, key: &str) -> Result<Uuid, DirectRequestStoreError> {
        Uuid::parse_str(text_field(body, key)?)
            .map_err(|_| DirectRequestStoreError::IdentityConflict)
    }
    fn integer_field(body: &Value, key: &str) -> Result<i64, DirectRequestStoreError> {
        body[key]
            .as_i64()
            .ok_or(DirectRequestStoreError::IdentityConflict)
    }
    fn bytes_field(body: &Value, key: &str) -> Result<Vec<u8>, DirectRequestStoreError> {
        STANDARD
            .decode(text_field(body, key)?)
            .map_err(|_| DirectRequestStoreError::IdentityConflict)
    }
    fn datetime_field(body: &Value, key: &str) -> Result<DateTime<Utc>, DirectRequestStoreError> {
        DateTime::parse_from_rfc3339(text_field(body, key)?)
            .map(|t| t.with_timezone(&Utc))
            .map_err(|_| DirectRequestStoreError::IdentityConflict)
    }

    /// Standard service authentication is an opaque capability, not a payload DID.
    /// Schema/signature validation precedes any row claim. Device registration and
    /// immutable signing-key proof are reread under the canonical identity locks.
    pub(super) async fn admit_request(
        tx: &mut Transaction<'_, Postgres>,
        principal: &VerifiedServicePrincipal,
        kind: DirectRequestKind,
        raw: &[u8],
        now: DateTime<Utc>,
    ) -> Result<
        (
            LockedRequestActor,
            super::super::prelude::DirectRequestOperationLock,
        ),
        DirectRequestStoreError,
    > {
        let endpoint = match kind {
            DirectRequestKind::Keys => "blue.catbird.chat.publishDirectRequestKeys",
            DirectRequestKind::Prepare => "blue.catbird.chat.prepareDirectRequest",
            DirectRequestKind::Cancel => "blue.catbird.chat.cancelDirectRequestPreparation",
            DirectRequestKind::Publish => "blue.catbird.chat.publishDirectRequest",
            _ => return invalid(),
        };
        if principal.endpoint_nsid() != endpoint || principal.exp() <= now.timestamp() {
            return invalid();
        }
        // Only route lookup before strict parser verification; no identity claim.
        let untrusted: Value =
            serde_json::from_slice(raw).map_err(|_| DirectRequestStoreError::IdentityConflict)?;
        let body = &untrusted["body"];
        if text_field(body, "actorDid")? != principal.did() {
            return invalid();
        }
        let device_id = uuid_field(body, "actorDeviceId")?;
        let public_key: Option<Vec<u8>> = sqlx::query_scalar(
            "SELECT signing_public_key FROM chat.device_keys WHERE user_did=$1 AND device_id=$2",
        )
        .bind(principal.did())
        .bind(device_id)
        .fetch_optional(&mut **tx)
        .await?;
        let public_key = public_key.ok_or(DirectRequestStoreError::IdentityConflict)?;
        let signed = direct_request_transcript::verify_signed_request(kind, raw, &public_key)
            .map_err(|_| DirectRequestStoreError::IdentityConflict)?;
        let operation_id = uuid_field(
            signed.body(),
            if kind == DirectRequestKind::Keys {
                "idempotencyKey"
            } else {
                "requestId"
            },
        )?;
        let operation =
            super::super::prelude::lock_direct_request_operation(tx, operation_id).await?;
        let mut dids = vec![principal.did().to_owned()];
        if let Some(recipient) = signed.body()["recipientDid"].as_str() {
            if recipient == principal.did() {
                return invalid();
            }
            dids.push(recipient.to_owned());
        }
        let devices = super::super::prelude::lock_direct_request_identity_scope(tx, &dids).await?;
        let actor = devices
            .iter()
            .find(|d| d.user_did == principal.did() && d.device_id == device_id)
            .ok_or(DirectRequestStoreError::IdentityConflict)?;
        if actor.status != "active"
            || actor.revoked_at.is_some()
            || actor.key_id != signed.key_id()
            || Some(actor.auth_generation as u64) != signed.auth_generation()
            || actor.signing_public_key != public_key
        {
            return invalid();
        }
        Ok((
            LockedRequestActor {
                transaction_id: transaction_id(tx).await?,
                signed,
                signing_key: public_key,
                now,
            },
            operation,
        ))
    }

    pub(super) fn require_fresh(actor: &LockedRequestActor) -> Result<(), DirectRequestStoreError> {
        let signed_at = datetime_field(actor.signed.body(), "signedAt")?;
        if signed_at < actor.now - Duration::seconds(300)
            || signed_at > actor.now + Duration::seconds(60)
        {
            return Err(DirectRequestStoreError::Expired);
        }
        Ok(())
    }

    async fn publish_request_keys(
        tx: &mut Transaction<'_, Postgres>,
        actor: LockedRequestActor,
    ) -> Result<Vec<u8>, DirectRequestStoreError> {
        if transaction_id(tx).await? != actor.transaction_id
            || actor.signed.kind() != DirectRequestKind::Keys
        {
            return invalid();
        }
        let b = actor.signed.body();
        let operation_id = uuid_field(b, "idempotencyKey")?;
        let did = text_field(b, "actorDid")?;
        let device = uuid_field(b, "actorDeviceId")?;
        let generation = integer_field(b, "authGeneration")?;
        let revision = integer_field(b, "revision")?;
        let existing:Option<(Vec<u8>,Vec<u8>,Vec<u8>)>=sqlx::query_as("SELECT request_digest,accepted_request,response_bytes FROM chat.direct_request_key_publications WHERE operation_id=$1")
        .bind(operation_id).fetch_optional(&mut **tx).await?;
        if let Some((digest, request, response)) = existing {
            if digest != actor.signed.request_digest()
                || request != actor.signed.accepted_wrapper_bytes()
            {
                return invalid();
            }
            return Ok(response);
        }
        require_fresh(&actor)?;
        let old:Option<i64>=sqlx::query_scalar("SELECT revision FROM chat.direct_request_capabilities WHERE owner_did=$1 AND owner_device_id=$2 FOR UPDATE")
        .bind(did).bind(device).fetch_optional(&mut **tx).await?;
        if revision != old.unwrap_or(0) + 1 {
            return invalid();
        }
        let enabled = b["enabled"]
            .as_bool()
            .ok_or(DirectRequestStoreError::IdentityConflict)?;
        let keys = b["keys"]
            .as_array()
            .ok_or(DirectRequestStoreError::IdentityConflict)?;
        if !enabled && !keys.is_empty() {
            return invalid();
        }
        let (available,live):(i64,i64)=sqlx::query_as("SELECT count(*) FILTER(WHERE usage_scope='direct-request' AND status='available'),count(*) FROM chat.key_packages WHERE owner_did=$1 AND owner_device_id=$2 AND status IN('available','reserved')")
        .bind(did).bind(device).fetch_one(&mut **tx).await?;
        if available + keys.len() as i64 > 128 || live + keys.len() as i64 > 1000 {
            return Err(DirectRequestStoreError::QuotaExceeded);
        }
        let credential = crate::chat_protocol::validation::basic_credential_identity(
            &crate::chat_protocol::validation::BareDid::parse(did)
                .map_err(|_| DirectRequestStoreError::IdentityConflict)?,
            &crate::chat_protocol::validation::CanonicalUuidV4::parse(&device.to_string())
                .map_err(|_| DirectRequestStoreError::IdentityConflict)?,
        );
        for key in keys {
            let raw_grant = serde_json::to_vec(&key["grant"])
                .map_err(|_| DirectRequestStoreError::InvalidReceipt)?;
            let grant = direct_request_transcript::verify_signed_request(
                DirectRequestKind::Grant,
                &raw_grant,
                &actor.signing_key,
            )
            .map_err(|_| DirectRequestStoreError::IdentityConflict)?;
            if grant.actor_did() != Some(did)
                || grant.actor_device_id() != Some(device.to_string().as_str())
                || grant.key_id() != actor.signed.key_id()
                || grant.auth_generation() != Some(generation as u64)
            {
                return invalid();
            }
            let wrapper = bytes_field(&key["keyPackage"], "bytes")?;
            let valid = crate::chat_protocol::wire::validate_key_package(
                &wrapper,
                crate::chat_protocol::wire::KeyPackageValidationPolicy {
                    expected_basic_credential: &credential,
                    expected_signature_key: &actor.signing_key,
                    now_unix_seconds: actor.now.timestamp() as u64,
                    max_bytes: 65536,
                },
            )
            .map_err(|_| DirectRequestStoreError::IdentityConflict)?;
            let package_ref = bytes_field(grant.body(), "keyPackageRef")?;
            if bytes_field(&key["keyPackage"], "keyPackageRef")? != package_ref
                || bytes_field(&key["keyPackage"], "sha256")? != Sha256::digest(&wrapper).as_slice()
                || valid.key_package_ref().as_slice() != package_ref
                || bytes_field(grant.body(), "keyPackageSha256")?
                    != Sha256::digest(&wrapper).as_slice()
            {
                return invalid();
            }
            let expires = datetime_field(grant.body(), "expiresAt")?;
            if expires < actor.now + Duration::seconds(MIN_PACKAGE_HORIZON_SECONDS)
                || valid.not_after()
                    < (actor.now + Duration::seconds(MIN_PACKAGE_HORIZON_SECONDS)).timestamp()
                        as u64
            {
                return invalid();
            }
            sqlx::query("INSERT INTO chat.key_packages(key_package_ref,wrapper_bytes,wrapper_sha256,init_key,owner_did,owner_device_id,owner_key_id,owner_auth_generation,not_before,not_after,status,created_at,usage_scope) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,'available',$11,'direct-request')")
            .bind(&package_ref).bind(&wrapper).bind(Sha256::digest(&wrapper).to_vec()).bind(valid.init_key()).bind(did).bind(device).bind(actor.signed.key_id()).bind(generation)
            .bind(DateTime::from_timestamp(valid.not_before() as i64,0).ok_or(DirectRequestStoreError::InvalidReceipt)?).bind(DateTime::from_timestamp(valid.not_after() as i64,0).ok_or(DirectRequestStoreError::InvalidReceipt)?).bind(actor.now).execute(&mut **tx).await?;
            sqlx::query("INSERT INTO chat.direct_request_grants(grant_id,revision,owner_did,owner_device_id,owner_key_id,auth_generation,capability_revision,key_package_ref,purpose,protocol_version,profile,signed_grant,grant_digest,expires_at,created_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,'direct-request-bootstrap','2','encryptedIntroduction1',$9,$10,$11,$12)")
            .bind(uuid_field(grant.body(),"grantId")?).bind(integer_field(grant.body(),"grantRevision")?).bind(did).bind(device).bind(actor.signed.key_id()).bind(generation).bind(revision).bind(package_ref).bind(raw_grant).bind(grant.request_digest().as_slice()).bind(expires).bind(actor.now).execute(&mut **tx).await?;
        }
        // Replenishment preserves the authority of previously selected grants.
        // Disable explicitly revokes all grants. Revision only changes the device
        // publication CAS; immutable grants remain package-bound.
        if !enabled {
            sqlx::query("UPDATE chat.direct_request_grants SET revoked_at=$3 WHERE owner_did=$1 AND owner_device_id=$2 AND revoked_at IS NULL")
            .bind(did).bind(device).bind(actor.now).execute(&mut **tx).await?;
        }
        sqlx::query("INSERT INTO chat.direct_request_capabilities(owner_did,owner_device_id,owner_key_id,auth_generation,revision,enabled,protocol_version,signed_publication,publication_digest,updated_at) VALUES($1,$2,$3,$4,$5,$6,'2',$7,$8,$9) ON CONFLICT(owner_did,owner_device_id) DO UPDATE SET owner_key_id=EXCLUDED.owner_key_id,auth_generation=EXCLUDED.auth_generation,revision=EXCLUDED.revision,enabled=EXCLUDED.enabled,signed_publication=EXCLUDED.signed_publication,publication_digest=EXCLUDED.publication_digest,updated_at=EXCLUDED.updated_at")
        .bind(did).bind(device).bind(actor.signed.key_id()).bind(generation).bind(revision).bind(enabled).bind(actor.signed.accepted_wrapper_bytes()).bind(actor.signed.request_digest().as_slice()).bind(actor.now).execute(&mut **tx).await?;
        let response = serde_json::to_vec(&json!({"revision":revision,"enabled":enabled}))
            .map_err(|_| DirectRequestStoreError::InvalidReceipt)?;
        sqlx::query("INSERT INTO chat.direct_request_key_publications(operation_id,owner_did,owner_device_id,owner_key_id,auth_generation,revision,request_digest,accepted_request,response_bytes,response_sha256,created_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)")
        .bind(operation_id).bind(did).bind(device).bind(actor.signed.key_id()).bind(generation).bind(revision).bind(actor.signed.request_digest().as_slice()).bind(actor.signed.accepted_wrapper_bytes()).bind(&response).bind(Sha256::digest(&response).to_vec()).bind(actor.now).execute(&mut **tx).await?;
        Ok(response)
    }
}

/// T04 consumes this single-use transaction-bound witness, never a caller-built
/// attempt identity. Completed replay is returned before timestamp/lease checks.
pub(super) enum DirectRequestPublicationAdmission {
    Terminal(Vec<u8>),
    Candidate(LockedDirectRequestPublication),
}
pub(super) struct LockedDirectRequestPublication {
    lock: LockedAttempt,
    signed: crate::chat_protocol::direct_request_transcript::VerifiedDirectRequest,
    now: DateTime<Utc>,
}
impl LockedDirectRequestPublication {
    pub(super) fn signed(
        &self,
    ) -> &crate::chat_protocol::direct_request_transcript::VerifiedDirectRequest {
        &self.signed
    }
    pub(super) fn preparation_response(&self) -> Option<&[u8]> {
        self.lock
            .row
            .as_ref()
            .and_then(|r| r.prepare_response.as_deref())
    }
    pub(super) fn preparation_request_digest(&self) -> &[u8] {
        &self.lock.identity.prepare_digest
    }
    pub(super) fn request_id(&self) -> Uuid {
        self.lock.identity.request_id
    }
    pub(super) fn trusted_instant(&self) -> DateTime<Utc> {
        self.now
    }
    /// Required immediately before any publication effect. This is additional
    /// to T04's final-tree, artifact, pair and relationship validations.
    pub(super) async fn validate_preparation(
        &self,
        tx: &mut Transaction<'_, Postgres>,
    ) -> Result<(), DirectRequestStoreError> {
        require_transaction(tx, &self.lock).await?;
        let row = self
            .lock
            .row
            .as_ref()
            .ok_or(DirectRequestStoreError::InvalidReceipt)?;
        if row.status != "prepared" || row.lease_expires_at.is_none_or(|e| e <= self.now) {
            return Err(DirectRequestStoreError::Expired);
        }
        use base64::Engine as _;
        let expected = base64::engine::general_purpose::STANDARD
            .decode(
                self.signed.body()["preparationDigest"]
                    .as_str()
                    .ok_or(DirectRequestStoreError::InvalidReceipt)?,
            )
            .map_err(|_| DirectRequestStoreError::InvalidReceipt)?;
        if row.selected_digest.as_deref() != Some(expected.as_slice()) {
            return Err(DirectRequestStoreError::IdentityConflict);
        }
        let snapshot: serde_json::Value = serde_json::from_slice(
            row.prepare_response
                .as_deref()
                .ok_or(DirectRequestStoreError::InvalidReceipt)?,
        )
        .map_err(|_| DirectRequestStoreError::InvalidReceipt)?;
        for field in [
            "requestId",
            "firstMessageId",
            "conversationId",
            "recipientDid",
            "origin",
            "profile",
        ] {
            if snapshot[field] != self.signed.body()[field] {
                return Err(DirectRequestStoreError::IdentityConflict);
            }
        }
        validate_selected_authority(tx, &self.lock, self.now).await
    }
}
pub(super) async fn admit_publication(
    tx: &mut Transaction<'_, Postgres>,
    principal: &crate::auth::VerifiedServicePrincipal,
    raw: &[u8],
    now: DateTime<Utc>,
) -> Result<DirectRequestPublicationAdmission, DirectRequestStoreError> {
    use crate::chat_protocol::direct_request_transcript::DirectRequestKind;
    use base64::Engine as _;
    let (actor, operation) =
        signed_admission::admit_request(tx, principal, DirectRequestKind::Publish, raw, now)
            .await?;
    let b = actor.signed.body();
    let identity = AttemptIdentity {
        request_id: Uuid::parse_str(
            actor
                .signed
                .request_id()
                .ok_or(DirectRequestStoreError::IdentityConflict)?,
        )
        .map_err(|_| DirectRequestStoreError::IdentityConflict)?,
        actor_did: actor
            .signed
            .actor_did()
            .ok_or(DirectRequestStoreError::IdentityConflict)?
            .to_owned(),
        actor_device_id: Uuid::parse_str(
            actor
                .signed
                .actor_device_id()
                .ok_or(DirectRequestStoreError::IdentityConflict)?,
        )
        .map_err(|_| DirectRequestStoreError::IdentityConflict)?,
        actor_key_id: actor.signed.key_id().to_owned(),
        actor_auth_generation: actor
            .signed
            .auth_generation()
            .ok_or(DirectRequestStoreError::IdentityConflict)?
            as i64,
        recipient_did: b["recipientDid"]
            .as_str()
            .ok_or(DirectRequestStoreError::IdentityConflict)?
            .to_owned(),
        prepare_digest: base64::engine::general_purpose::STANDARD
            .decode(
                b["preparationRequestDigest"]
                    .as_str()
                    .ok_or(DirectRequestStoreError::IdentityConflict)?,
            )
            .map_err(|_| DirectRequestStoreError::IdentityConflict)?,
    };
    let lock = load_locked_attempt(tx, identity, &operation).await?;
    if let Some(row) = &lock.row {
        if let Some(receipt) = row.terminal_bytes()? {
            if row.status == "published"
                && row.publication_digest.as_deref()
                    != Some(actor.signed.request_digest().as_slice())
            {
                return Err(DirectRequestStoreError::IdentityConflict);
            }
            return Ok(DirectRequestPublicationAdmission::Terminal(
                receipt.to_vec(),
            ));
        }
    }
    signed_admission::require_fresh(&actor)?;
    Ok(DirectRequestPublicationAdmission::Candidate(
        LockedDirectRequestPublication {
            lock,
            signed: actor.signed,
            now,
        },
    ))
}

#[derive(Clone, Copy)]
pub(super) enum PublicationDisposition {
    Published,
    Rejected,
    ExistingDirect,
    Expired,
}
pub(super) async fn complete_publication(
    tx: &mut Transaction<'_, Postgres>,
    candidate: LockedDirectRequestPublication,
    disposition: PublicationDisposition,
    receipt: &super::direct_request_receipts::SignedDirectRequestReceipt,
) -> Result<Vec<u8>, DirectRequestStoreError> {
    use base64::Engine as _;
    let body = &receipt.body()["receipt"];
    let bytes = |key: &str| {
        base64::engine::general_purpose::STANDARD
            .decode(body[key].as_str().unwrap_or_default())
            .unwrap_or_default()
    };
    if body["requestId"].as_str() != Some(candidate.lock.identity.request_id.to_string().as_str())
        || body["actorDid"].as_str() != Some(candidate.lock.identity.actor_did.as_str())
        || body["actorDeviceId"].as_str()
            != Some(candidate.lock.identity.actor_device_id.to_string().as_str())
        || body["authGeneration"].as_i64() != Some(candidate.lock.identity.actor_auth_generation)
        || bytes("preparationRequestDigest") != candidate.lock.identity.prepare_digest
        || body["requestKind"].as_str() != Some("publish")
        || bytes("requestDigest") != candidate.signed.request_digest()
    {
        return Err(DirectRequestStoreError::InvalidReceipt);
    }
    let (outcome, kind) = match disposition {
        PublicationDisposition::Published => {
            candidate.validate_preparation(tx).await?;
            (TerminalOutcome::Published, "directRequestPublishedReceipt")
        }
        PublicationDisposition::Rejected => {
            (TerminalOutcome::Rejected, "directRequestRejectedReceipt")
        }
        PublicationDisposition::ExistingDirect => (
            TerminalOutcome::ExistingDirect,
            "directRequestExistingDirectReceipt",
        ),
        PublicationDisposition::Expired => {
            (TerminalOutcome::Expired, "directRequestExpiredReceipt")
        }
    };
    if body["$type"].as_str() != Some(format!("blue.catbird.chat.defs#{kind}").as_str()) {
        return Err(DirectRequestStoreError::InvalidReceipt);
    }
    finish_terminal(
        tx,
        candidate.lock,
        outcome,
        receipt.bytes(),
        Some(candidate.signed.request_digest()),
        candidate.now,
    )
    .await
}
