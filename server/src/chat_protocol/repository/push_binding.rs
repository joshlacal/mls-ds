//! Exact device-signed push bindings. Provider token custody belongs to Nest.
use super::device_directory::{read_device_view, DeviceDirectoryView};
use crate::chat_protocol::{
    error::ChatProtocolErrorCode as Code,
    validation::{BareDid, CanonicalTimestamp, CanonicalUuidV4, KeyThumbprint},
};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use catbird_atproto::{
    blue_catbird::chat::{PushRegistrationBinding, SignedPushRegistration},
    push_registration,
};
use chrono::{DateTime, Utc};
use ed25519_dalek::{Signature, VerifyingKey};
use sha2::{Digest, Sha256};
use sqlx::{PgPool, Row};
use uuid::Uuid;

#[derive(Debug)]
pub(crate) enum PushBindingError {
    Protocol(Code),
    Database(sqlx::Error),
    Invariant,
}
impl From<sqlx::Error> for PushBindingError {
    fn from(e: sqlx::Error) -> Self {
        Self::Database(e)
    }
}
fn invalid<T>() -> Result<T, PushBindingError> {
    Err(PushBindingError::Protocol(Code::InvalidRequest))
}

pub(crate) async fn register(
    pool: &PgPool,
    principal: &str,
    signed: SignedPushRegistration,
    token: Option<&str>,
) -> Result<(DeviceDirectoryView, PushRegistrationBinding), PushBindingError> {
    let mut tx = pool.begin().await?;
    let result = register_in_transaction(&mut tx, principal, signed, token).await?;
    tx.commit().await?;
    Ok(result)
}

async fn register_in_transaction(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    principal: &str,
    signed: SignedPushRegistration,
    token: Option<&str>,
) -> Result<(DeviceDirectoryView, PushRegistrationBinding), PushBindingError> {
    let body = &signed.body;
    if body.actor_did.as_str() != principal
        || signed.extra_data.as_ref().is_some_and(|x| !x.is_empty())
    {
        return invalid();
    }
    BareDid::parse(principal).map_err(|_| PushBindingError::Protocol(Code::InvalidRequest))?;
    CanonicalUuidV4::parse(body.actor_device_id.as_ref())
        .map_err(|_| PushBindingError::Protocol(Code::InvalidRequest))?;
    CanonicalUuidV4::parse(body.registration_id.as_ref())
        .map_err(|_| PushBindingError::Protocol(Code::InvalidRequest))?;
    KeyThumbprint::parse(body.key_id.as_ref())
        .map_err(|_| PushBindingError::Protocol(Code::InvalidRequest))?;
    let signed_at = CanonicalTimestamp::parse(body.signed_at.as_str())
        .map_err(|_| PushBindingError::Protocol(Code::InvalidRequest))?
        .datetime();
    let transcript = push_registration::transcript(body)
        .map_err(|_| PushBindingError::Protocol(Code::InvalidRequest))?;
    if body.enabled != token.is_some()
        || token.is_some_and(|t| {
            t.is_empty() || t.len() > 512 || t.chars().any(|c| c.is_control() || c.is_whitespace())
        })
    {
        return invalid();
    }
    if Sha256::digest(token.unwrap_or_default().as_bytes()).as_slice() != body.token_sha256.as_ref()
    {
        return invalid();
    }
    let wrapper = serde_json::to_vec(&signed).map_err(|_| PushBindingError::Invariant)?;
    if wrapper.len() > 8192 {
        return invalid();
    }
    let digest = Sha256::digest(&transcript).to_vec();
    let device = Uuid::parse_str(body.actor_device_id.as_ref())
        .map_err(|_| PushBindingError::Protocol(Code::InvalidRequest))?;
    let registration = Uuid::parse_str(body.registration_id.as_ref())
        .map_err(|_| PushBindingError::Protocol(Code::InvalidRequest))?;
    // A competing first INSERT may otherwise wait on the global UUID index
    // after the freshness check. Serialize that identity before any authority
    // locks, then read the decision clock after all possible lock waits.
    sqlx::query(
        "SELECT pg_advisory_xact_lock(hashtextextended('chat-request-push-registration:' || $1,0))",
    )
    .bind(registration.to_string())
    .execute(&mut **tx)
    .await?;
    let current=sqlx::query("SELECT status,auth_generation FROM chat.devices WHERE user_did=$1 AND device_id=$2 FOR UPDATE")
        .bind(principal).bind(device).fetch_optional(&mut **tx).await?
        .ok_or(PushBindingError::Protocol(Code::DeviceNotRegistered))?;
    if current.get::<String, _>("status") != "active" {
        return Err(PushBindingError::Protocol(Code::DeviceRevoked));
    }
    if current.get::<i64, _>("auth_generation") != body.auth_generation {
        return Err(PushBindingError::Protocol(Code::StaleAuthGeneration));
    }
    let public:Option<Vec<u8>>=sqlx::query_scalar("SELECT signing_public_key FROM chat.device_keys WHERE user_did=$1 AND device_id=$2 AND key_id=$3 AND revoked_at IS NULL FOR UPDATE")
        .bind(principal).bind(device).bind(body.key_id.as_str()).fetch_optional(&mut **tx).await?;
    let public = public.ok_or(PushBindingError::Protocol(Code::StaleAuthGeneration))?;
    if URL_SAFE_NO_PAD.encode(Sha256::digest(&public)) != body.key_id.as_str() {
        return Err(PushBindingError::Invariant);
    }
    let public: [u8; 32] = public.try_into().map_err(|_| PushBindingError::Invariant)?;
    let key = VerifyingKey::from_bytes(&public).map_err(|_| PushBindingError::Invariant)?;
    let signature = Signature::from_slice(&signed.signature)
        .map_err(|_| PushBindingError::Protocol(Code::InvalidSignature))?;
    key.verify_strict(&transcript, &signature)
        .map_err(|_| PushBindingError::Protocol(Code::InvalidSignature))?;
    let previous=sqlx::query("SELECT registration_id,token_generation,binding_digest FROM chat.request_push_bindings WHERE user_did=$1 AND device_id=$2 AND provider=$3 FOR UPDATE")
        .bind(principal).bind(device).bind(body.provider.as_str()).fetch_optional(&mut **tx).await?;
    let replay = if let Some(previous) = previous {
        if previous.get::<Uuid, _>("registration_id") != registration {
            return Err(PushBindingError::Protocol(Code::RegistrationConflict));
        }
        let generation = previous.get::<i64, _>("token_generation");
        if body.token_generation < generation
            || (body.token_generation == generation
                && previous.get::<Vec<u8>, _>("binding_digest") != digest)
        {
            return Err(PushBindingError::Protocol(Code::RegistrationConflict));
        }
        body.token_generation == generation
    } else {
        false
    };
    if !replay {
        // Evaluate freshness after every potentially blocking authority lock.
        let now: DateTime<Utc> = sqlx::query_scalar("SELECT clock_timestamp()")
            .fetch_one(&mut **tx)
            .await?;
        if (now - signed_at).num_milliseconds().abs() > 300_000 {
            return invalid();
        }
        // Gaps are valid after uncertain earlier writes or credential rebinding.
        // A committed higher generation permanently fences late older attempts.
        sqlx::query("INSERT INTO chat.request_push_bindings(user_did,device_id,provider,registration_id,key_id,auth_generation,app_id,token_generation,token_sha256,enabled,binding_digest,signed_binding,signed_at,updated_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14) ON CONFLICT(user_did,device_id,provider) DO UPDATE SET key_id=EXCLUDED.key_id,auth_generation=EXCLUDED.auth_generation,app_id=EXCLUDED.app_id,token_generation=EXCLUDED.token_generation,token_sha256=EXCLUDED.token_sha256,enabled=EXCLUDED.enabled,binding_digest=EXCLUDED.binding_digest,signed_binding=EXCLUDED.signed_binding,signed_at=EXCLUDED.signed_at,updated_at=EXCLUDED.updated_at")
            .bind(principal).bind(device).bind(body.provider.as_str()).bind(registration).bind(body.key_id.as_str()).bind(body.auth_generation).bind(body.app_id.as_str()).bind(body.token_generation).bind(body.token_sha256.as_ref()).bind(body.enabled).bind(&digest).bind(wrapper).bind(signed_at).bind(now).execute(&mut **tx).await.map_err(map_binding_write_error)?;
    }
    let view = read_device_view(tx, principal, device)
        .await
        .map_err(|_| PushBindingError::Invariant)?
        .ok_or(PushBindingError::Invariant)?;
    if view.key_id != body.key_id.as_str()
        || view.auth_generation != body.auth_generation
        || view.status != "active"
    {
        return Err(PushBindingError::Invariant);
    }
    Ok((
        view,
        PushRegistrationBinding {
            body: signed.body,
            binding_digest: digest.into(),
            extra_data: None,
        },
    ))
}

fn map_binding_write_error(error: sqlx::Error) -> PushBindingError {
    if error.as_database_error().is_some_and(|db| {
        db.code().as_deref() == Some("23505")
            && db.constraint() == Some("request_push_bindings_registration_id_key")
    }) {
        PushBindingError::Protocol(Code::RegistrationConflict)
    } else {
        PushBindingError::Database(error)
    }
}

#[cfg(test)]
#[path = "../../../tests/common/chat_protocol.rs"]
mod chat_protocol;
#[cfg(test)]
#[path = "../../../tests/common/direct_request_database.rs"]
mod direct_request_database;
#[cfg(test)]
mod tests {
    use super::*;
    use catbird_atproto::blue_catbird::chat::PushRegistrationBody;
    use ed25519_dalek::{Signer, SigningKey};
    fn signed(
        mut body: PushRegistrationBody,
        generation: i64,
        token: Option<&str>,
        key: &SigningKey,
    ) -> SignedPushRegistration {
        body.token_generation = generation;
        body.enabled = token.is_some();
        body.token_sha256 = Sha256::digest(token.unwrap_or_default().as_bytes())
            .to_vec()
            .into();
        let signature = key.sign(&push_registration::transcript(&body).unwrap());
        SignedPushRegistration {
            body,
            signature: signature.to_bytes().to_vec().into(),
            extra_data: None,
        }
    }
    #[tokio::test]
    async fn guarded_device_binding_rotation_retry_disable_and_authority_fences() {
        let pool = super::direct_request_database::setup().await;
        let mut tx = pool.begin().await.unwrap();
        // The guarded, explicit migration manifest installs the reviewed schema.
        let fixture: serde_json::Value = serde_json::from_str(include_str!(
            "../../../../../catbird-atproto/tests/fixtures/push-registration.json"
        ))
        .unwrap();
        let mut body: PushRegistrationBody =
            serde_json::from_value(fixture["body"].clone()).unwrap();
        let key = SigningKey::from_bytes(&std::array::from_fn(|i| i as u8));
        let public = key.verifying_key().to_bytes();
        let now = Utc::now();
        let did = body.actor_did.to_string();
        let device = Uuid::new_v4();
        body.actor_device_id = device.to_string().into();
        body.registration_id = Uuid::new_v4().to_string().into();
        body.auth_generation = 1;
        body.signed_at = now
            .to_rfc3339_opts(chrono::SecondsFormat::Millis, true)
            .parse()
            .unwrap();
        sqlx::query(
            "INSERT INTO chat.principals(user_did,created_at) VALUES($1,$2) ON CONFLICT DO NOTHING",
        )
        .bind(&did)
        .bind(now)
        .execute(&mut *tx)
        .await
        .unwrap();
        sqlx::query("INSERT INTO chat.devices(user_did,device_id,device_name,status,dpop_jkt,auth_generation,capabilities,created_at,updated_at) VALUES($1,$2,'push fixture','active',$3,1,chat.protocol_capabilities(),$4,$4)").bind(&did).bind(device).bind(body.key_id.as_str()).bind(now).execute(&mut *tx).await.unwrap();
        sqlx::query("INSERT INTO chat.device_keys(user_did,device_id,key_id,signing_public_key,enrollment_auth_generation,created_at) VALUES($1,$2,$3,$4,1,$5)").bind(&did).bind(device).bind(body.key_id.as_str()).bind(public.as_slice()).bind(now).execute(&mut *tx).await.unwrap();
        let first = signed(body.clone(), 1, Some("test-only-token"), &key);
        let (_, ack) =
            register_in_transaction(&mut tx, &did, first.clone(), Some("test-only-token"))
                .await
                .unwrap();
        assert_eq!(
            ack.binding_digest.as_ref(),
            Sha256::digest(
                push_registration::transcript(&body_with_token(&body, 1, Some("test-only-token")))
                    .unwrap()
            )
            .as_slice()
        );
        let (_, retry) =
            register_in_transaction(&mut tx, &did, first.clone(), Some("test-only-token"))
                .await
                .unwrap();
        assert_eq!(retry.binding_digest, ack.binding_digest);
        assert!(matches!(
            register_in_transaction(&mut tx, &did, first.clone(), Some("different-token")).await,
            Err(PushBindingError::Protocol(Code::InvalidRequest))
        ));
        let mut forged = first.clone();
        forged.signature = vec![0; 64].into();
        assert!(matches!(
            register_in_transaction(&mut tx, &did, forged, Some("test-only-token")).await,
            Err(PushBindingError::Protocol(Code::InvalidSignature))
        ));
        let rotated = signed(body.clone(), 4, Some("rotated-token"), &key);
        register_in_transaction(&mut tx, &did, rotated, Some("rotated-token"))
            .await
            .unwrap();
        assert!(matches!(
            register_in_transaction(
                &mut tx,
                &did,
                signed(body.clone(), 4, Some("different-token"), &key),
                Some("different-token")
            )
            .await,
            Err(PushBindingError::Protocol(Code::RegistrationConflict))
        ));
        assert!(matches!(
            register_in_transaction(&mut tx, &did, first, Some("test-only-token")).await,
            Err(PushBindingError::Protocol(Code::RegistrationConflict))
        ));
        let disable = signed(body.clone(), 5, None, &key);
        register_in_transaction(&mut tx, &did, disable.clone(), None)
            .await
            .unwrap();
        assert!(!sqlx::query_scalar::<_, bool>(
            "SELECT enabled FROM chat.request_push_bindings WHERE user_did=$1 AND device_id=$2"
        )
        .bind(&did)
        .bind(device)
        .fetch_one(&mut *tx)
        .await
        .unwrap());
        let other_device = Uuid::new_v4();
        let other_key = SigningKey::from_bytes(&[71; 32]);
        let other_public = other_key.verifying_key().to_bytes();
        let other_key_id = URL_SAFE_NO_PAD.encode(Sha256::digest(other_public));
        sqlx::query("INSERT INTO chat.devices(user_did,device_id,device_name,status,dpop_jkt,auth_generation,capabilities,created_at,updated_at) VALUES($1,$2,'push collision fixture','active',$3,1,chat.protocol_capabilities(),$4,$4)")
            .bind(&did).bind(other_device).bind(&other_key_id).bind(now).execute(&mut *tx).await.unwrap();
        sqlx::query("INSERT INTO chat.device_keys(user_did,device_id,key_id,signing_public_key,enrollment_auth_generation,created_at) VALUES($1,$2,$3,$4,1,$5)")
            .bind(&did).bind(other_device).bind(&other_key_id).bind(other_public.as_slice()).bind(now).execute(&mut *tx).await.unwrap();
        let mut collision = body.clone();
        collision.actor_device_id = other_device.to_string().into();
        collision.key_id = other_key_id.into();
        sqlx::query("SAVEPOINT registration_collision")
            .execute(&mut *tx)
            .await
            .unwrap();
        assert!(matches!(
            register_in_transaction(&mut tx, &did, signed(collision, 1, None, &other_key), None)
                .await,
            Err(PushBindingError::Protocol(Code::RegistrationConflict))
        ));
        sqlx::query("ROLLBACK TO SAVEPOINT registration_collision")
            .execute(&mut *tx)
            .await
            .unwrap();
        let mut stale_authority = body.clone();
        stale_authority.auth_generation = 2;
        assert!(matches!(
            register_in_transaction(&mut tx, &did, signed(stale_authority, 6, None, &key), None)
                .await,
            Err(PushBindingError::Protocol(Code::StaleAuthGeneration))
        ));
        body.signed_at = (now - chrono::Duration::minutes(10))
            .to_rfc3339_opts(chrono::SecondsFormat::Millis, true)
            .parse()
            .unwrap();
        assert!(matches!(
            register_in_transaction(&mut tx, &did, signed(body, 6, None, &key), None).await,
            Err(PushBindingError::Protocol(Code::InvalidRequest))
        ));
        tx.rollback().await.unwrap();
    }
    #[tokio::test]
    async fn guarded_registration_identity_wait_cannot_extend_signature_freshness() {
        let pool = super::direct_request_database::setup().await;
        let fixture: serde_json::Value = serde_json::from_str(include_str!(
            "../../../../../catbird-atproto/tests/fixtures/push-registration.json"
        ))
        .unwrap();
        let mut body: PushRegistrationBody =
            serde_json::from_value(fixture["body"].clone()).unwrap();
        let key = SigningKey::from_bytes(&std::array::from_fn(|i| i as u8));
        let device = Uuid::new_v4();
        let registration = Uuid::new_v4();
        let did = format!("did:web:push-lock-{}.example.org", device.simple());
        body.actor_did = did.parse().unwrap();
        body.actor_device_id = device.to_string().into();
        body.registration_id = registration.to_string().into();
        body.auth_generation = 1;
        let mut setup = pool.begin().await.unwrap();
        sqlx::query(
            "INSERT INTO chat.principals(user_did,created_at) VALUES($1,clock_timestamp())",
        )
        .bind(&did)
        .execute(&mut *setup)
        .await
        .unwrap();
        sqlx::query("INSERT INTO chat.devices(user_did,device_id,device_name,status,dpop_jkt,auth_generation,capabilities,created_at,updated_at) VALUES($1,$2,'push lock fixture','active',$3,1,chat.protocol_capabilities(),clock_timestamp(),clock_timestamp())")
            .bind(&did).bind(device).bind(body.key_id.as_str()).execute(&mut *setup).await.unwrap();
        sqlx::query("INSERT INTO chat.device_keys(user_did,device_id,key_id,signing_public_key,enrollment_auth_generation,created_at) VALUES($1,$2,$3,$4,1,clock_timestamp())")
            .bind(&did).bind(device).bind(body.key_id.as_str()).bind(key.verifying_key().to_bytes().as_slice()).execute(&mut *setup).await.unwrap();
        setup.commit().await.unwrap();
        // This fixture is retained in the dedicated test DB; no identity tombstone
        // or other test's data is deleted to clean up the contention scenario.
        let mut blocker = pool.begin().await.unwrap();
        sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended('chat-request-push-registration:' || $1,0))")
            .bind(registration.to_string()).execute(&mut *blocker).await.unwrap();
        let signed_at: DateTime<Utc> =
            sqlx::query_scalar("SELECT clock_timestamp() - interval '299 seconds'")
                .fetch_one(&mut *blocker)
                .await
                .unwrap();
        body.signed_at = signed_at
            .to_rfc3339_opts(chrono::SecondsFormat::Millis, true)
            .parse()
            .unwrap();
        let request = signed(body, 1, None, &key);
        let task_pool = pool.clone();
        let task_did = did.clone();
        let pending =
            tokio::spawn(async move { register(&task_pool, &task_did, request, None).await });
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        assert!(
            !pending.is_finished(),
            "registration bypassed the global identity lock"
        );
        loop {
            let now: DateTime<Utc> = sqlx::query_scalar("SELECT clock_timestamp()")
                .fetch_one(&mut *blocker)
                .await
                .unwrap();
            if now.signed_duration_since(signed_at).num_milliseconds() > 300_100 {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(25)).await;
        }
        blocker.rollback().await.unwrap();
        let result = tokio::time::timeout(std::time::Duration::from_secs(5), pending)
            .await
            .unwrap()
            .unwrap();
        assert!(matches!(
            result,
            Err(PushBindingError::Protocol(Code::InvalidRequest))
        ));
        let count: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM chat.request_push_bindings WHERE registration_id=$1",
        )
        .bind(registration)
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(count, 0);
    }

    fn body_with_token(
        body: &PushRegistrationBody,
        generation: i64,
        token: Option<&str>,
    ) -> PushRegistrationBody {
        let mut b = body.clone();
        b.token_generation = generation;
        b.enabled = token.is_some();
        b.token_sha256 = Sha256::digest(token.unwrap_or_default().as_bytes())
            .to_vec()
            .into();
        b
    }
}
