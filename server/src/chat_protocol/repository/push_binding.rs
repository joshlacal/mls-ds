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
    now: DateTime<Utc>,
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
    let mut tx = pool.begin().await?;
    let current=sqlx::query("SELECT status,auth_generation FROM chat.devices WHERE user_did=$1 AND device_id=$2 FOR UPDATE")
        .bind(principal).bind(device).fetch_optional(&mut *tx).await?
        .ok_or(PushBindingError::Protocol(Code::DeviceNotRegistered))?;
    if current.get::<String, _>("status") != "active" {
        return Err(PushBindingError::Protocol(Code::DeviceRevoked));
    }
    if current.get::<i64, _>("auth_generation") != body.auth_generation {
        return Err(PushBindingError::Protocol(Code::StaleAuthGeneration));
    }
    let public:Option<Vec<u8>>=sqlx::query_scalar("SELECT signing_public_key FROM chat.device_keys WHERE user_did=$1 AND device_id=$2 AND key_id=$3 AND revoked_at IS NULL FOR UPDATE")
        .bind(principal).bind(device).bind(body.key_id.as_str()).fetch_optional(&mut *tx).await?;
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
        .bind(principal).bind(device).bind(body.provider.as_str()).fetch_optional(&mut *tx).await?;
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
        if (now - signed_at).num_milliseconds().abs() > 300_000 {
            return invalid();
        }
        // Gaps are valid after uncertain earlier writes or credential rebinding.
        // A committed higher generation permanently fences late older attempts.
        sqlx::query("INSERT INTO chat.request_push_bindings(user_did,device_id,provider,registration_id,key_id,auth_generation,app_id,token_generation,token_sha256,enabled,binding_digest,signed_binding,signed_at,updated_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14) ON CONFLICT(user_did,device_id,provider) DO UPDATE SET key_id=EXCLUDED.key_id,auth_generation=EXCLUDED.auth_generation,app_id=EXCLUDED.app_id,token_generation=EXCLUDED.token_generation,token_sha256=EXCLUDED.token_sha256,enabled=EXCLUDED.enabled,binding_digest=EXCLUDED.binding_digest,signed_binding=EXCLUDED.signed_binding,signed_at=EXCLUDED.signed_at,updated_at=EXCLUDED.updated_at")
            .bind(principal).bind(device).bind(body.provider.as_str()).bind(registration).bind(body.key_id.as_str()).bind(body.auth_generation).bind(body.app_id.as_str()).bind(body.token_generation).bind(body.token_sha256.as_ref()).bind(body.enabled).bind(&digest).bind(wrapper).bind(signed_at).bind(now).execute(&mut *tx).await?;
    }
    let view = read_device_view(&mut tx, principal, device)
        .await
        .map_err(|_| PushBindingError::Invariant)?
        .ok_or(PushBindingError::Invariant)?;
    if view.key_id != body.key_id.as_str()
        || view.auth_generation != body.auth_generation
        || view.status != "active"
    {
        return Err(PushBindingError::Invariant);
    }
    tx.commit().await?;
    Ok((
        view,
        PushRegistrationBinding {
            body: signed.body,
            binding_digest: digest.into(),
            extra_data: None,
        },
    ))
}
