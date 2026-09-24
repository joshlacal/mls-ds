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
        pub(super) signing_key: Vec<u8>,
        pub(super) now: DateTime<Utc>,
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
            DirectRequestKind::Accept => "blue.catbird.chat.acceptConversation",
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
            .map_err(|_| DirectRequestStoreError::InvalidSignature)?;
        let operation_id = uuid_field(
            signed.body(),
            if kind == DirectRequestKind::Keys {
                "idempotencyKey"
            } else {
                "requestId"
            },
        )?;
        let acceptance_operation = if kind == DirectRequestKind::Accept {
            let id = uuid_field(signed.body(), "transitionId")?;
            if uuid_field(signed.body(), "idempotencyKey")? != id || id == operation_id {
                return invalid();
            }
            Some(id)
        } else {
            None
        };
        let additional = acceptance_operation.into_iter().collect::<Vec<_>>();
        let operation =
            super::super::prelude::lock_direct_request_operation_set(tx, operation_id, &additional)
                .await?;
        let acceptance_collision:bool=sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM chat.direct_request_acceptance_claims WHERE operation_id=$1)")
            .bind(operation_id).fetch_one(&mut **tx).await?;
        if acceptance_collision {
            return invalid();
        }
        if let Some(id) = acceptance_operation {
            let conflict:bool=sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM chat.operation_claims WHERE operation_id=$1) OR EXISTS(SELECT 1 FROM chat.direct_request_attempts WHERE request_id=$1) OR EXISTS(SELECT 1 FROM chat.direct_request_key_publications WHERE operation_id=$1)")
                .bind(id).fetch_one(&mut **tx).await?;
            if conflict {
                return invalid();
            }
            load_acceptance_replay(tx, &signed).await?;
        }
        let collision: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM chat.operation_claims WHERE operation_id=$1) OR EXISTS(SELECT 1 FROM chat.direct_request_attempts WHERE request_id=$1 AND $2) OR EXISTS(SELECT 1 FROM chat.direct_request_key_publications WHERE operation_id=$1 AND NOT $2)")
            .bind(operation_id).bind(kind == DirectRequestKind::Keys).fetch_one(&mut **tx).await?;
        if collision {
            return Err(DirectRequestStoreError::IdentityConflict);
        }
        let mut dids = vec![principal.did().to_owned()];
        if let Some(recipient) = signed.body()["recipientDid"].as_str() {
            if recipient == principal.did() {
                return invalid();
            }
            dids.push(recipient.to_owned());
        }
        if kind == DirectRequestKind::Accept {
            let accounts: Option<(String,String)> = sqlx::query_as("SELECT actor_did,recipient_did FROM chat.direct_request_attempts WHERE request_id=$1")
                .bind(operation_id).fetch_optional(&mut **tx).await?;
            let (sender, recipient) = accounts.ok_or(DirectRequestStoreError::IdentityConflict)?;
            if principal.did() != recipient {
                return invalid();
            }
            dids.extend([sender, recipient]);
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
        let now = request_database_instant(tx).await?;
        if principal.exp() <= now.timestamp() {
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
        require_fresh_at(actor, actor.now)
    }
    pub(super) fn require_fresh_at(
        actor: &LockedRequestActor,
        now: DateTime<Utc>,
    ) -> Result<(), DirectRequestStoreError> {
        let signed_at = datetime_field(actor.signed.body(), "signedAt")?;
        if signed_at < now - Duration::seconds(300) || signed_at > now + Duration::seconds(60) {
            return Err(DirectRequestStoreError::Expired);
        }
        Ok(())
    }

    pub(super) async fn publish_request_keys(
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
        sqlx::query("UPDATE chat.key_packages SET status='expired',terminal_at=not_after WHERE owner_did=$1 AND owner_device_id=$2 AND usage_scope='direct-request' AND status IN('available','reserved') AND not_after<=$3")
            .bind(did).bind(device).bind(actor.now).execute(&mut **tx).await?;
        // Retire unusable request-only material under the one-time rule. These
        // packages never become available again, including after disable/enable.
        sqlx::query("INSERT INTO chat.direct_request_retired_packages(key_package_ref,retired_at,reason) SELECT p.key_package_ref,$5,'unusable' FROM chat.key_packages p WHERE owner_did=$1 AND owner_device_id=$2 AND usage_scope='direct-request' AND status='available' AND (owner_auth_generation<>$3 OR not_after<$4 OR NOT EXISTS(SELECT 1 FROM chat.direct_request_grants g WHERE g.key_package_ref=p.key_package_ref AND g.revoked_at IS NULL AND g.expires_at>=$4)) ON CONFLICT DO NOTHING")
            .bind(did).bind(device).bind(generation).bind(actor.now+Duration::seconds(MIN_PACKAGE_HORIZON_SECONDS)).bind(actor.now).execute(&mut **tx).await?;
        sqlx::query("UPDATE chat.key_packages p SET status='reserved' WHERE owner_did=$1 AND owner_device_id=$2 AND usage_scope='direct-request' AND status='available' AND (owner_auth_generation<>$3 OR not_after<$4 OR NOT EXISTS(SELECT 1 FROM chat.direct_request_grants g WHERE g.key_package_ref=p.key_package_ref AND g.revoked_at IS NULL AND g.expires_at>=$4))")
            .bind(did).bind(device).bind(generation).bind(actor.now+Duration::seconds(MIN_PACKAGE_HORIZON_SECONDS)).execute(&mut **tx).await?;
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
        require_fresh_at(&actor, request_database_instant(tx).await?)?;
        // Replenishment preserves the authority of previously selected grants.
        // Disable explicitly revokes all grants. Revision only changes the device
        // publication CAS; immutable grants remain package-bound.
        if !enabled {
            sqlx::query("INSERT INTO chat.direct_request_retired_packages(key_package_ref,retired_at,reason) SELECT key_package_ref,$3,'disabled' FROM chat.key_packages WHERE owner_did=$1 AND owner_device_id=$2 AND usage_scope='direct-request' AND status='available' ON CONFLICT DO NOTHING")
                .bind(did).bind(device).bind(actor.now).execute(&mut **tx).await?;
            sqlx::query("UPDATE chat.key_packages SET status='reserved' WHERE owner_did=$1 AND owner_device_id=$2 AND usage_scope='direct-request' AND status='available'")
                .bind(did).bind(device).execute(&mut **tx).await?;
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
    pub(super) async fn existing_artifact_bytes(
        &self,
        tx: &mut Transaction<'_, Postgres>,
    ) -> Result<u64, DirectRequestStoreError> {
        Ok(existing_attempt_artifact_bytes(tx, &self.lock).await? as u64)
    }

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
    pub(super) async fn refresh_instant(
        &mut self,
        tx: &mut Transaction<'_, Postgres>,
    ) -> Result<(), DirectRequestStoreError> {
        require_transaction(tx, &self.lock).await?;
        self.now = request_database_instant(tx).await?;
        Ok(())
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
        let now = request_database_instant(tx).await?;
        if row.status != "prepared" || row.lease_expires_at.is_none_or(|e| e <= now) {
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
        validate_selected_authority(tx, &self.lock, now).await
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
    let now = actor.now;
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
    if matches!(disposition, PublicationDisposition::Published) {
        return Err(DirectRequestStoreError::InvalidReceipt);
    }
    complete_publication_inner(tx, &candidate, disposition, receipt, None).await
}

async fn complete_publication_inner(
    tx: &mut Transaction<'_, Postgres>,
    candidate: &LockedDirectRequestPublication,
    disposition: PublicationDisposition,
    receipt: &super::direct_request_receipts::SignedDirectRequestReceipt,
    retained_artifact_bytes: Option<i64>,
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
        || body["actorKeyId"].as_str() != Some(candidate.lock.identity.actor_key_id.as_str())
        || body["authGeneration"].as_i64() != Some(candidate.lock.identity.actor_auth_generation)
        || bytes("preparationRequestDigest") != candidate.lock.identity.prepare_digest
        || body["recordedAt"].as_str() != Some(time_string(candidate.now).as_str())
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
    finish_terminal_charged(
        tx,
        candidate.lock.clone(),
        outcome,
        receipt.bytes(),
        Some(candidate.signed.request_digest()),
        candidate.now,
        retained_artifact_bytes,
    )
    .await
}

pub(super) enum PublicationCompletion {
    Published(Vec<u8>),
    Rejected(Vec<u8>),
}

/// Consumes the external publication capability exactly once. A failed final
/// lease/authority validation produces a durable rejection, and the distinct
/// arm prevents the caller from continuing with conversation effects.
pub(super) async fn complete_published_publication(
    tx: &mut Transaction<'_, Postgres>,
    mut candidate: LockedDirectRequestPublication,
    published_receipt: &super::direct_request_receipts::SignedDirectRequestReceipt,
    signer: &super::direct_request_receipts::DirectRequestReceiptSigner,
    retained_artifact_bytes: u64,
) -> Result<PublicationCompletion, DirectRequestStoreError> {
    match complete_publication_inner(
        tx,
        &candidate,
        PublicationDisposition::Published,
        published_receipt,
        i64::try_from(retained_artifact_bytes).ok(),
    )
    .await
    {
        Ok(bytes) => Ok(PublicationCompletion::Published(bytes)),
        Err(error) => {
            let code = match error {
                DirectRequestStoreError::QuotaExceeded => "CapacityUnavailable",
                DirectRequestStoreError::Expired => "PreparationExpired",
                DirectRequestStoreError::IncludedAuthorityChanged => "PreparationRevoked",
                DirectRequestStoreError::IdentityConflict => "PreparationConflict",
                other => return Err(other),
            };
            candidate.refresh_instant(tx).await?;
            let receipt = terminal_receipt(
                signer,
                &candidate.lock.identity,
                "directRequestRejectedReceipt",
                "publish",
                candidate.signed.request_digest(),
                candidate.now,
                serde_json::json!({"code":code}),
            )?;
            Ok(PublicationCompletion::Rejected(
                complete_publication_inner(
                    tx,
                    &candidate,
                    PublicationDisposition::Rejected,
                    &receipt,
                    None,
                )
                .await?,
            ))
        }
    }
}

/// Repository-minted relationship witness. No external constructor, no claimed
/// payload identity is accepted as locked authority.
pub(super) struct DirectRequestPolicyWitness {
    transaction_id: String,
    request: crate::chat_protocol::relationship_policy::AdmissionRequest,
    actor_digest: [u8; 32],
    read_set_digest: [u8; 32],
}
impl DirectRequestPolicyWitness {
    pub(super) fn parts(
        &self,
    ) -> (
        &str,
        &crate::chat_protocol::relationship_policy::AdmissionRequest,
        [u8; 32],
        [u8; 32],
    ) {
        (
            &self.transaction_id,
            &self.request,
            self.actor_digest,
            self.read_set_digest,
        )
    }
}

pub(crate) enum DirectRequestResult {
    Prepared(Vec<u8>),
    Terminal(Vec<u8>),
    Unknown(Uuid),
    Keys(Vec<u8>),
}

fn signed_identity(
    signed: &crate::chat_protocol::direct_request_transcript::VerifiedDirectRequest,
) -> Result<AttemptIdentity, DirectRequestStoreError> {
    use crate::chat_protocol::direct_request_transcript::DirectRequestKind;
    use base64::Engine as _;
    let body = signed.body();
    let string = |key: &str| {
        body[key]
            .as_str()
            .ok_or(DirectRequestStoreError::IdentityConflict)
    };
    Ok(AttemptIdentity {
        request_id: Uuid::parse_str(string("requestId")?)
            .map_err(|_| DirectRequestStoreError::IdentityConflict)?,
        actor_did: string("actorDid")?.to_owned(),
        actor_device_id: Uuid::parse_str(string("actorDeviceId")?)
            .map_err(|_| DirectRequestStoreError::IdentityConflict)?,
        actor_key_id: signed.key_id().to_owned(),
        actor_auth_generation: signed
            .auth_generation()
            .ok_or(DirectRequestStoreError::IdentityConflict)?
            as i64,
        recipient_did: string("recipientDid")?.to_owned(),
        prepare_digest: if signed.kind() == DirectRequestKind::Prepare {
            signed.request_digest().to_vec()
        } else {
            base64::engine::general_purpose::STANDARD
                .decode(string("preparationRequestDigest")?)
                .map_err(|_| DirectRequestStoreError::IdentityConflict)?
        },
    })
}
async fn request_database_instant(
    tx: &mut Transaction<'_, Postgres>,
) -> Result<DateTime<Utc>, DirectRequestStoreError> {
    Ok(
        sqlx::query_scalar("SELECT date_trunc('milliseconds',clock_timestamp())")
            .fetch_one(&mut **tx)
            .await?,
    )
}
fn time_string(now: DateTime<Utc>) -> String {
    now.to_rfc3339_opts(chrono::SecondsFormat::Millis, true)
}
fn terminal_receipt(
    signer: &super::direct_request_receipts::DirectRequestReceiptSigner,
    i: &AttemptIdentity,
    kind: &str,
    request_kind: &str,
    request_digest: &[u8],
    now: DateTime<Utc>,
    extra: serde_json::Value,
) -> Result<super::direct_request_receipts::SignedDirectRequestReceipt, DirectRequestStoreError> {
    use base64::Engine as _;
    let mut receipt = serde_json::json!({"$type":format!("blue.catbird.chat.defs#{kind}"),"requestId":i.request_id.to_string(),"requestDigest":base64::engine::general_purpose::STANDARD.encode(request_digest),"preparationRequestDigest":base64::engine::general_purpose::STANDARD.encode(&i.prepare_digest),"actorDid":i.actor_did,"actorDeviceId":i.actor_device_id.to_string(),"actorKeyId":i.actor_key_id,"authGeneration":i.actor_auth_generation,"requestKind":request_kind,"recordedAt":time_string(now)});
    if let Some(fields) = extra.as_object() {
        for (k, v) in fields {
            receipt[k] = v.clone();
        }
    }
    signer.seal_outcome(serde_json::json!({"$type":"blue.catbird.chat.defs#directRequestReceiptBody","signatureDomain":"CATBIRD-DIRECT-REQUEST-OUTCOME\u{0}","protocolVersion":"2","authorityDid":"did:web:chat.catbird.blue","keyId":signer.key_id(),"receipt":receipt})).map_err(|_|DirectRequestStoreError::InvalidReceipt)
}

pub(crate) async fn cancel_direct_request(
    tx: &mut Transaction<'_, Postgres>,
    principal: &crate::auth::VerifiedServicePrincipal,
    raw: &[u8],
    signer: &super::direct_request_receipts::DirectRequestReceiptSigner,
    now: DateTime<Utc>,
) -> Result<DirectRequestResult, DirectRequestStoreError> {
    use crate::chat_protocol::direct_request_transcript::DirectRequestKind;
    let (actor, operation) =
        signed_admission::admit_request(tx, principal, DirectRequestKind::Cancel, raw, now).await?;
    let now = actor.now;
    let identity = signed_identity(&actor.signed)?;
    let lock = load_locked_attempt(tx, identity, &operation).await?;
    if let Some(row) = &lock.row {
        if let Some(receipt) = row.terminal_bytes()? {
            return Ok(DirectRequestResult::Terminal(receipt.to_vec()));
        }
    }
    signed_admission::require_fresh(&actor)?;
    let receipt = terminal_receipt(
        signer,
        &lock.identity,
        "directRequestCancelledReceipt",
        "cancel",
        actor.signed.request_digest(),
        now,
        serde_json::json!({}),
    )?;
    Ok(DirectRequestResult::Terminal(
        finish_terminal(
            tx,
            lock,
            TerminalOutcome::Cancelled,
            receipt.bytes(),
            None,
            now,
        )
        .await?,
    ))
}

pub(crate) async fn publish_direct_request_keys(
    tx: &mut Transaction<'_, Postgres>,
    principal: &crate::auth::VerifiedServicePrincipal,
    raw: &[u8],
    now: DateTime<Utc>,
) -> Result<DirectRequestResult, DirectRequestStoreError> {
    let (actor, _) = signed_admission::admit_request(
        tx,
        principal,
        crate::chat_protocol::direct_request_transcript::DirectRequestKind::Keys,
        raw,
        now,
    )
    .await?;
    Ok(DirectRequestResult::Keys(
        signed_admission::publish_request_keys(tx, actor).await?,
    ))
}

pub(crate) async fn prepare_direct_request<
    T: crate::chat_protocol::relationship_policy::PublicTransport,
>(
    tx: &mut Transaction<'_, Postgres>,
    principal: &crate::auth::VerifiedServicePrincipal,
    raw: &[u8],
    signer: &super::direct_request_receipts::DirectRequestReceiptSigner,
    policy: &crate::chat_protocol::relationship_policy::RelationshipAuthority<T>,
    now: DateTime<Utc>,
) -> Result<DirectRequestResult, DirectRequestStoreError> {
    use crate::chat_protocol::{
        direct_request_transcript::DirectRequestKind,
        relationship_policy::{AdmissionOperation, AdmissionRequest},
    };
    use base64::Engine as _;
    let (actor, operation) =
        signed_admission::admit_request(tx, principal, DirectRequestKind::Prepare, raw, now)
            .await?;
    let now = actor.now;
    let identity = signed_identity(&actor.signed)?;
    let lock = load_locked_attempt(tx, identity, &operation).await?;
    if let Some(row) = &lock.row {
        if let Some(receipt) = row.terminal_bytes()? {
            return Ok(DirectRequestResult::Terminal(receipt.to_vec()));
        }
        if row.lease_expires_at.is_some_and(|expiry| expiry > now) {
            return Ok(DirectRequestResult::Prepared(
                row.prepare_response
                    .clone()
                    .ok_or(DirectRequestStoreError::InvalidReceipt)?,
            ));
        }
        let receipt = terminal_receipt(
            signer,
            &lock.identity,
            "directRequestExpiredReceipt",
            "expiry",
            &lock.identity.prepare_digest,
            now,
            serde_json::json!({}),
        )?;
        return Ok(DirectRequestResult::Terminal(
            finish_terminal(
                tx,
                lock,
                TerminalOutcome::Expired,
                receipt.bytes(),
                None,
                now,
            )
            .await?,
        ));
    }
    if signed_admission::require_fresh(&actor).is_err() {
        let receipt = terminal_receipt(
            signer,
            &lock.identity,
            "directRequestExpiredReceipt",
            "expiry",
            &lock.identity.prepare_digest,
            now,
            serde_json::json!({}),
        )?;
        return Ok(DirectRequestResult::Terminal(
            finish_terminal(
                tx,
                lock,
                TerminalOutcome::Expired,
                receipt.bytes(),
                None,
                now,
            )
            .await?,
        ));
    }
    sqlx::query("SAVEPOINT direct_request_prepare_body")
        .execute(&mut **tx)
        .await?;
    let prepared = async {
    let b = actor.signed.body();
    let i = &lock.identity;
    check_preparation_budget(tx,i,now,MAX_BUNDLE_BYTES).await?;
    let (recent,pair_pending,recipient_pending):(i64,i64,i64)=sqlx::query_as("SELECT (SELECT count(*) FROM chat.participants WHERE created_by_did=$1 AND invitation_transition_id IS NOT NULL AND created_at >= $3-INTERVAL '24 hours'),(SELECT count(*) FROM chat.participants WHERE created_by_did=$1 AND user_did=$2 AND current_membership AND status='pending'),(SELECT count(*) FROM chat.participants WHERE user_did=$2 AND current_membership AND status='pending')")
        .bind(&i.actor_did).bind(&i.recipient_did).bind(now).fetch_one(&mut **tx).await?;
    let quota_exceeded = recent >= 100 || pair_pending >= 5 || recipient_pending >= 100;
    let mut roster = vec![i.actor_did.clone(), i.recipient_did.clone()];
    roster.sort();
    let witness = DirectRequestPolicyWitness {
        transaction_id: transaction_id(tx).await?,
        request: AdmissionRequest {
            inviter: i.actor_did.clone(),
            roster,
            pending_recipients: vec![i.recipient_did.clone()],
            operation: AdmissionOperation::Direct,
        },
        actor_digest: Sha256::digest(
            [
                actor.signed.transcript_bytes(),
                actor.signing_key.as_slice(),
            ]
            .concat(),
        )
        .into(),
        read_set_digest: Sha256::digest(
            [
                i.request_id.as_bytes().as_slice(),
                i.prepare_digest.as_slice(),
                &recent.to_be_bytes(),
                &pair_pending.to_be_bytes(),
                &recipient_pending.to_be_bytes(),
            ]
            .concat(),
        )
        .into(),
    };
    super::relationship::verify_direct_request_policy(tx, &witness, policy, quota_exceeded)
        .await
        .map_err(|_| DirectRequestStoreError::PolicyDenied)?;
    // Atomic publication spans exactly one canonical authority. A recipient
    // whose public chat declaration names another delivery service has no
    // transaction here to join: refuse typed, before any package selection or
    // reservation, and never degrade to legacy federation delivery. An absent
    // declaration keeps the canonical path; an unreadable one fails closed
    // exactly like the consent declaration read above.
    match policy.recipient_chat_authority(&i.recipient_did).await {
        Ok(Some(authority))
            if authority != super::direct_request_receipts::REQUEST_RECEIPT_AUTHORITY =>
        {
            return Err(DirectRequestStoreError::RecipientAuthorityUnsupported);
        }
        Ok(_) => {}
        Err(_) => return Err(DirectRequestStoreError::PolicyDenied),
    }
    let now = request_database_instant(tx).await?;
    signed_admission::require_fresh_at(&actor, now)?;
    let selected = select_devices(tx, &lock, now).await?;
    let minimum_import_until = now + Duration::seconds(604_800 + 300);
    let minimum_import_until = DateTime::from_timestamp(
        minimum_import_until.timestamp()
            + i64::from(minimum_import_until.timestamp_subsec_nanos() != 0),
        0,
    )
    .ok_or(DirectRequestStoreError::InvalidReceipt)?;
    let devices=selected.iter().map(|d|Ok(serde_json::json!({"actorDid":d.owner_did,"actorDeviceId":d.owner_device_id.to_string(),"keyId":d.owner_key_id,"authGeneration":d.auth_generation,"keyPackage":{"framing":"mlsMessage","contentType":"keyPackage","bytes":base64::engine::general_purpose::STANDARD.encode(&d.wrapper_bytes),"sha256":base64::engine::general_purpose::STANDARD.encode(Sha256::digest(&d.wrapper_bytes)),"keyPackageRef":base64::engine::general_purpose::STANDARD.encode(&d.key_package_ref)},"grant":serde_json::from_slice::<serde_json::Value>(&d.signed_grant).map_err(|_|DirectRequestStoreError::InvalidReceipt)?}))).collect::<Result<Vec<_>,DirectRequestStoreError>>()?;
    let mut snapshot = serde_json::json!({"protocolVersion":"2","requestId":b["requestId"],"firstMessageId":b["firstMessageId"],"conversationId":b["conversationId"],"recipientDid":b["recipientDid"],"origin":b["origin"],"profile":b["profile"],"creator":{"actorDid":i.actor_did,"actorDeviceId":i.actor_device_id.to_string(),"keyId":i.actor_key_id,"authGeneration":i.actor_auth_generation},"selectedDevices":devices,"preparedAt":time_string(now),"leaseExpiresAt":time_string(now+Duration::seconds(300)),"minimumImportUntil":time_string(minimum_import_until),"preparationRequestDigest":base64::engine::general_purpose::STANDARD.encode(&i.prepare_digest),"authorityDid":"did:web:chat.catbird.blue","receiptKeyId":signer.key_id()});
    let (snapshot_digest, signature) = signer
        .sign_preparation(
            &serde_json::to_vec(&snapshot).map_err(|_| DirectRequestStoreError::InvalidReceipt)?,
        )
        .map_err(|_| DirectRequestStoreError::InvalidReceipt)?;
    snapshot["preparationDigest"] =
        serde_json::json!(base64::engine::general_purpose::STANDARD.encode(snapshot_digest));
    snapshot["preparationSignature"] =
        serde_json::json!(base64::engine::general_purpose::STANDARD.encode(signature));
    let response =
        serde_json::to_vec(&snapshot).map_err(|_| DirectRequestStoreError::InvalidReceipt)?;
    if response.len() > 8_388_608 {
        return Err(DirectRequestStoreError::QuotaExceeded);
    }
    Ok(DirectRequestResult::Prepared(
        reserve_preparation(tx, &lock, &selected, &response, &snapshot_digest, now).await?,
    ))
    }.await;
    match prepared {
        Ok(value) => {
            sqlx::query("RELEASE SAVEPOINT direct_request_prepare_body")
                .execute(&mut **tx)
                .await?;
            Ok(value)
        }
        Err(error) => {
            sqlx::query("ROLLBACK TO SAVEPOINT direct_request_prepare_body")
                .execute(&mut **tx)
                .await?;
            let code = match error {
                DirectRequestStoreError::PolicyDenied => "RequestPolicyDenied",
                DirectRequestStoreError::QuotaExceeded => "CapacityUnavailable",
                DirectRequestStoreError::RecipientKeysUnavailable => "RecipientKeysUnavailable",
                DirectRequestStoreError::RecipientAuthorityUnsupported => {
                    "RecipientAuthorityUnsupported"
                }
                DirectRequestStoreError::IncludedAuthorityChanged => "PreparationRevoked",
                DirectRequestStoreError::Expired => "PreparationExpired",
                DirectRequestStoreError::IdentityConflict => "PreparationConflict",
                other => return Err(other),
            };
            let receipt = terminal_receipt(
                signer,
                &lock.identity,
                "directRequestRejectedReceipt",
                "prepare",
                actor.signed.request_digest(),
                now,
                serde_json::json!({"code":code}),
            )?;
            Ok(DirectRequestResult::Terminal(
                finish_terminal(
                    tx,
                    lock,
                    TerminalOutcome::Rejected,
                    receipt.bytes(),
                    None,
                    now,
                )
                .await?,
            ))
        }
    }
}

async fn load_acceptance_replay(
    tx: &mut Transaction<'_, Postgres>,
    signed: &crate::chat_protocol::direct_request_transcript::VerifiedDirectRequest,
) -> Result<Option<Vec<u8>>, DirectRequestStoreError> {
    let id = Uuid::parse_str(
        signed.body()["transitionId"]
            .as_str()
            .ok_or(DirectRequestStoreError::IdentityConflict)?,
    )
    .map_err(|_| DirectRequestStoreError::IdentityConflict)?;
    let row:Option<(Uuid,String,Vec<u8>,Vec<u8>,Vec<u8>,Vec<u8>,Vec<u8>)>=sqlx::query_as("SELECT request_id,principal_did,request_digest,accepted_request,signature,response_bytes,response_sha256 FROM chat.direct_request_acceptance_claims WHERE operation_id=$1")
        .bind(id).fetch_optional(&mut **tx).await?;
    let Some((request, did, digest, raw, signature, response, response_hash)) = row else {
        return Ok(None);
    };
    if Some(request.to_string().as_str()) != signed.request_id()
        || Some(did.as_str()) != signed.actor_did()
        || digest != signed.request_digest()
        || raw != signed.accepted_wrapper_bytes()
        || signature != signed.signature()
        || response_hash != Sha256::digest(&response).as_slice()
    {
        return Err(DirectRequestStoreError::IdentityConflict);
    }
    Ok(Some(response))
}

pub(super) struct LockedDirectRequestAcceptance {
    transaction_id: String,
    operation_id: Uuid,
    recorded_response: Option<Vec<u8>>,
    signed: crate::chat_protocol::direct_request_transcript::VerifiedDirectRequest,
    now: DateTime<Utc>,
}
impl LockedDirectRequestAcceptance {
    pub(super) fn operation_id(&self) -> Uuid {
        self.operation_id
    }
    pub(super) fn recorded_response(&self) -> Option<&[u8]> {
        self.recorded_response.as_deref()
    }

    pub(super) fn signed(
        &self,
    ) -> &crate::chat_protocol::direct_request_transcript::VerifiedDirectRequest {
        &self.signed
    }
    pub(super) fn trusted_instant(&self) -> DateTime<Utc> {
        self.now
    }
    pub(super) async fn require_transaction(
        &self,
        tx: &mut Transaction<'_, Postgres>,
    ) -> Result<(), DirectRequestStoreError> {
        if transaction_id(tx).await? != self.transaction_id {
            return Err(DirectRequestStoreError::ForeignTransaction);
        }
        Ok(())
    }
}
pub(super) async fn admit_acceptance(
    tx: &mut Transaction<'_, Postgres>,
    principal: &crate::auth::VerifiedServicePrincipal,
    raw: &[u8],
    now: DateTime<Utc>,
) -> Result<LockedDirectRequestAcceptance, DirectRequestStoreError> {
    let (actor, _) = signed_admission::admit_request(
        tx,
        principal,
        crate::chat_protocol::direct_request_transcript::DirectRequestKind::Accept,
        raw,
        now,
    )
    .await?;
    // The consent owner must arbitrate exact completed replay before applying
    // first-execution age; this helper does not grant that bypass to effects.
    let operation_id = Uuid::parse_str(
        actor.signed.body()["transitionId"]
            .as_str()
            .ok_or(DirectRequestStoreError::IdentityConflict)?,
    )
    .map_err(|_| DirectRequestStoreError::IdentityConflict)?;
    let recorded_response = load_acceptance_replay(tx, &actor.signed).await?;
    Ok(LockedDirectRequestAcceptance {
        transaction_id: transaction_id(tx).await?,
        operation_id,
        recorded_response,
        now: actor.now,
        signed: actor.signed,
    })
}

impl LockedDirectRequestPublication {
    pub(super) async fn validate_policy<
        T: crate::chat_protocol::relationship_policy::PublicTransport,
    >(
        &self,
        tx: &mut Transaction<'_, Postgres>,
        policy: &crate::chat_protocol::relationship_policy::RelationshipAuthority<T>,
    ) -> Result<(), DirectRequestStoreError> {
        use crate::chat_protocol::relationship_policy::{AdmissionOperation, AdmissionRequest};
        require_transaction(tx, &self.lock).await?;
        let i = &self.lock.identity;
        let (mut recent,mut pair_pending,mut recipient_pending):(i64,i64,i64)=sqlx::query_as("SELECT (SELECT count(*) FROM chat.participants WHERE created_by_did=$1 AND invitation_transition_id IS NOT NULL AND created_at >= $3-INTERVAL '24 hours'),(SELECT count(*) FROM chat.participants WHERE created_by_did=$1 AND user_did=$2 AND current_membership AND status='pending'),(SELECT count(*) FROM chat.participants WHERE user_did=$2 AND current_membership AND status='pending')")
            .bind(&i.actor_did).bind(&i.recipient_did).bind(self.now).fetch_one(&mut **tx).await?;
        if self.signed.body()["origin"]["$type"].as_str()
            == Some("blue.catbird.chat.defs#legacyPendingDirectOrigin")
        {
            let prior_conversation = Uuid::parse_str(
                self.signed.body()["conversationId"]
                    .as_str()
                    .ok_or(DirectRequestStoreError::IdentityConflict)?,
            )
            .map_err(|_| DirectRequestStoreError::IdentityConflict)?;
            let existing:Option<DateTime<Utc>>=sqlx::query_scalar("SELECT created_at FROM chat.participants WHERE conversation_id=$1 AND user_did=$2 AND created_by_did=$3 AND current_membership AND status='pending' AND invitation_transition_id IS NOT NULL")
                .bind(prior_conversation).bind(&i.recipient_did).bind(&i.actor_did).fetch_optional(&mut **tx).await?;
            if let Some(created) = existing {
                pair_pending = pair_pending.saturating_sub(1);
                recipient_pending = recipient_pending.saturating_sub(1);
                if created >= self.now - Duration::hours(24) {
                    recent = recent.saturating_sub(1);
                }
            }
        }
        let mut roster = vec![i.actor_did.clone(), i.recipient_did.clone()];
        roster.sort();
        let witness = DirectRequestPolicyWitness {
            transaction_id: transaction_id(tx).await?,
            request: AdmissionRequest {
                inviter: i.actor_did.clone(),
                roster,
                pending_recipients: vec![i.recipient_did.clone()],
                operation: AdmissionOperation::Direct,
            },
            actor_digest: Sha256::digest(self.signed.transcript_bytes()).into(),
            read_set_digest: Sha256::digest(
                [
                    i.request_id.as_bytes().as_slice(),
                    i.prepare_digest.as_slice(),
                    &recent.to_be_bytes(),
                    &pair_pending.to_be_bytes(),
                    &recipient_pending.to_be_bytes(),
                ]
                .concat(),
            )
            .into(),
        };
        super::relationship::verify_direct_request_policy(
            tx,
            &witness,
            policy,
            recent >= 100 || pair_pending >= 5 || recipient_pending >= 100,
        )
        .await
        .map_err(|_| DirectRequestStoreError::PolicyDenied)
    }
}

pub(crate) async fn get_direct_request_outcome(
    tx: &mut Transaction<'_, Postgres>,
    principal: &crate::auth::VerifiedServicePrincipal,
    actor_device_id: Uuid,
    request_id: Uuid,
    signer: &super::direct_request_receipts::DirectRequestReceiptSigner,
    now: DateTime<Utc>,
) -> Result<DirectRequestResult, DirectRequestStoreError> {
    if principal.endpoint_nsid() != "blue.catbird.chat.getDirectRequestOutcome"
        || principal.exp() <= now.timestamp()
    {
        return Err(DirectRequestStoreError::IdentityConflict);
    }
    let operation = super::prelude::lock_direct_request_operation(tx, request_id).await?;
    let devices =
        super::prelude::lock_direct_request_identity_scope(tx, &[principal.did().to_owned()])
            .await?;
    if !devices.iter().any(|d| {
        d.user_did == principal.did()
            && d.device_id == actor_device_id
            && d.status == "active"
            && d.revoked_at.is_none()
    }) {
        return Err(DirectRequestStoreError::IdentityConflict);
    }
    let now = request_database_instant(tx).await?;
    let row:Option<(String,Uuid,String,i64,String,Vec<u8>,String)>=sqlx::query_as("SELECT actor_did,actor_device_id,actor_key_id,actor_auth_generation,recipient_did,prepare_digest,status FROM chat.direct_request_attempts WHERE request_id=$1")
        .bind(request_id).fetch_optional(&mut **tx).await?;
    let Some((actor_did, device, key, generation, recipient, prepare_digest, status)) = row else {
        return Ok(DirectRequestResult::Unknown(request_id));
    };
    if !((actor_did == principal.did() && device == actor_device_id)
        || (status == "published"
            && (actor_did == principal.did() || recipient == principal.did())))
    {
        return Err(DirectRequestStoreError::IdentityConflict);
    }
    let i = AttemptIdentity {
        request_id,
        actor_did,
        actor_device_id: device,
        actor_key_id: key,
        actor_auth_generation: generation,
        recipient_did: recipient,
        prepare_digest,
    };
    let lock = load_locked_attempt(tx, i, &operation).await?;
    let row = lock
        .row
        .as_ref()
        .ok_or(DirectRequestStoreError::InvalidReceipt)?;
    let expiry_receipt: Option<Vec<u8>> = sqlx::query_scalar(
        "SELECT signed_receipt FROM chat.direct_request_expiry_receipts WHERE request_id = $1",
    )
    .bind(request_id)
    .fetch_optional(&mut **tx)
    .await?;
    if let Some(receipt) = expiry_receipt {
        return Ok(DirectRequestResult::Terminal(receipt));
    }
    if let Some(receipt) = row.terminal_bytes()? {
        return Ok(DirectRequestResult::Terminal(receipt.to_vec()));
    }
    if row.lease_expires_at.is_some_and(|expiry| expiry > now) {
        return Ok(DirectRequestResult::Prepared(
            row.prepare_response
                .clone()
                .ok_or(DirectRequestStoreError::InvalidReceipt)?,
        ));
    }
    let receipt = terminal_receipt(
        signer,
        &lock.identity,
        "directRequestExpiredReceipt",
        "expiry",
        &lock.identity.prepare_digest,
        now,
        serde_json::json!({}),
    )?;
    Ok(DirectRequestResult::Terminal(
        finish_terminal(
            tx,
            lock,
            TerminalOutcome::Expired,
            receipt.bytes(),
            None,
            now,
        )
        .await?,
    ))
}

/// Background expiry uses the same request lock as prepare/publish/cancel.
/// Enumeration grants no authority; each target is reread under that lock and
/// the complete canonical account/device/key prefix before the receipt is made.
pub(crate) async fn expire_due_preparations(
    pool: &sqlx::PgPool,
    signer: &super::direct_request_receipts::DirectRequestReceiptSigner,
    limit: i64,
) -> Result<usize, DirectRequestStoreError> {
    let ids:Vec<Uuid>=sqlx::query_scalar("SELECT request_id FROM chat.direct_request_attempts WHERE status='prepared' AND lease_expires_at<=clock_timestamp() ORDER BY lease_expires_at,request_id LIMIT $1")
        .bind(limit.clamp(1,100)).fetch_all(pool).await?;
    let mut count = 0;
    for id in ids {
        let mut tx = pool.begin().await?;
        sqlx::query("SET LOCAL lock_timeout = '1s'").execute(&mut *tx).await?;
        let operation = match super::prelude::try_lock_direct_request_operation(&mut tx, id).await {
            Ok(Some(op)) => op,
            Ok(None) | Err(_) => {
                tx.rollback().await?;
                continue;
            }
        };
        let row:Option<(String,Uuid,String,i64,String,Vec<u8>)>=sqlx::query_as("SELECT actor_did,actor_device_id,actor_key_id,actor_auth_generation,recipient_did,prepare_digest FROM chat.direct_request_attempts WHERE request_id=$1 AND status='prepared' AND lease_expires_at<=clock_timestamp()")
            .bind(id).fetch_optional(&mut *tx).await?;
        let Some((actor_did, device, key, generation, recipient, prepare_digest)) = row else {
            tx.rollback().await?;
            continue;
        };
        if super::prelude::lock_direct_request_identity_scope(
            &mut tx,
            &[actor_did.clone(), recipient.clone()],
        )
        .await
        .is_err()
        {
            tx.rollback().await?;
            continue;
        }
        let i = AttemptIdentity {
            request_id: id,
            actor_did,
            actor_device_id: device,
            actor_key_id: key,
            actor_auth_generation: generation,
            recipient_did: recipient,
            prepare_digest,
        };
        let lock = match load_locked_attempt(&mut tx, i, &operation).await {
            Ok(l) => l,
            Err(_) => {
                tx.rollback().await?;
                continue;
            }
        };
        let now: DateTime<Utc> =
            sqlx::query_scalar("SELECT date_trunc('milliseconds',clock_timestamp())")
                .fetch_one(&mut *tx)
                .await?;
        let receipt = terminal_receipt(
            signer,
            &lock.identity,
            "directRequestExpiredReceipt",
            "expiry",
            &lock.identity.prepare_digest,
            now,
            serde_json::json!({}),
        )?;
        finish_terminal(
            &mut tx,
            lock,
            TerminalOutcome::Expired,
            receipt.bytes(),
            None,
            now,
        )
        .await?;
        tx.commit().await?;
        count += 1;
    }
    Ok(count)
}
