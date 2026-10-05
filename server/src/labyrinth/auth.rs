//! Admission for the Labyrinth endpoints (design §3).
//!
//! Labyrinth reuses the clean-chat transport identity, not its signed-
//! mutation transcript machinery:
//!
//! * every request carries a standard atproto service-auth JWT whose `lxm`
//!   is the Labyrinth NSID (`auth::verify_mls_service_principal`, which also
//!   consumes the `jti`), and names the calling chat device;
//! * the device and its key are locked `FOR SHARE` inside the request
//!   transaction and must be current (`chat.devices.status = 'active'`,
//!   `chat.device_keys.revoked_at IS NULL`), which linearizes every Labyrinth
//!   write against chat device revocation;
//! * procedures additionally carry a `labyrinthWriteBody` signed by that
//!   device's chat Ed25519 key (headers below), binding the operation id,
//!   device, NSID and the payload digest. The operation id drives
//!   idempotency in `labyrinth.operations`.
//!
//! Deviation from the design (logged): the write body travels in two HTTP
//! headers instead of a new `blue.catbird.chat.defs#labyrinthWriteBody`
//! signed-mutation kind, so the frozen chat transcript corpus is untouched
//! and the Labyrinth lexicon inputs stay exactly the crate's.

use axum::http::HeaderMap;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use chrono::{DateTime, Utc};
use ed25519_dalek::{Signature, VerifyingKey};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use sqlx::{PgConnection, Postgres, Transaction};
use uuid::Uuid;

use super::error::{LabyrinthError, LabyrinthResult};
use super::read_auth::{self, ReadProof};
use crate::auth::AuthError;
use crate::storage::DbPool;

/// Header carrying `base64url(labyrinthWriteBody JSON)`.
pub const WRITE_BODY_HEADER: &str = "catbird-labyrinth-write";
/// Header carrying `base64url(Ed25519 sig over WRITE_DOMAIN || body bytes)`.
pub const WRITE_SIGNATURE_HEADER: &str = "catbird-labyrinth-write-signature";
/// Signature domain of `labyrinthWriteBody`.
pub const WRITE_DOMAIN: &[u8] = b"CATBIRD-LABYRINTH-WRITE\0";
/// Accepted skew between `signedAt` and the server instant.
pub const WRITE_SKEW_SECONDS: i64 = 300;

/// The authenticated caller: an account DID and one of its current chat
/// devices.
#[derive(Clone, Debug)]
pub struct Caller {
    pub did: String,
    pub device_id: Uuid,
    pub key_id: String,
    pub signing_key: [u8; 32],
}

/// A verified request, before its transaction re-locks the device.
#[derive(Clone, Debug)]
pub struct Admission {
    pub did: String,
    pub device_id: Uuid,
    /// The single server-clock instant of this request (ms precision).
    pub instant: DateTime<Utc>,
    /// Present on procedures.
    pub write: Option<WriteBody>,
    /// Present on device-signed reads; forwarded by `labyrinthRelay`.
    pub read: Option<ReadProof>,
}

/// `labyrinthWriteBody`.
#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct WriteBodyWire {
    operation_id: String,
    actor_device_id: String,
    endpoint_nsid: String,
    payload_sha256: String,
    signed_at: String,
}

/// The verified parts of a `labyrinthWriteBody`.
#[derive(Clone, Debug)]
pub struct WriteBody {
    pub operation_id: [u8; 16],
    pub payload_sha256: [u8; 32],
    pub endpoint_nsid: String,
}

fn now_ms() -> DateTime<Utc> {
    let now = Utc::now();
    DateTime::from_timestamp_millis(now.timestamp_millis()).unwrap_or(now)
}

fn service_auth_failure(nsid: &str, error: AuthError) -> LabyrinthError {
    tracing::warn!(endpoint = nsid, ?error, "labyrinth service auth failed");
    match error {
        AuthError::TokenExpired => LabyrinthError::new(
            axum::http::StatusCode::UNAUTHORIZED,
            "AccountSessionExpired",
            "service-auth token expired",
        ),
        AuthError::RateLimitExceeded { retry_after_secs } => LabyrinthError::new(
            axum::http::StatusCode::TOO_MANY_REQUESTS,
            "RateLimited",
            "rate limited",
        )
        .with_retry_after(retry_after_secs),
        AuthError::Internal(_) => LabyrinthError::internal(),
        _ => LabyrinthError::not_authorized("service auth failed"),
    }
}

fn require_cutover(cutover_enabled: bool) -> LabyrinthResult<()> {
    if cutover_enabled {
        Ok(())
    } else {
        Err(LabyrinthError::new(
            axum::http::StatusCode::BAD_REQUEST,
            "CutoverRequired",
            "the clean-chat protocol is not active on this service",
        ))
    }
}

/// The `actorDeviceId` query parameter, exactly once.
pub fn actor_device_from_query(query: Option<&str>) -> LabyrinthResult<Uuid> {
    let values: Vec<String> = url::form_urlencoded::parse(query.unwrap_or_default().as_bytes())
        .filter_map(|(k, v)| (k == "actorDeviceId").then(|| v.into_owned()))
        .collect();
    match values.as_slice() {
        [one] => parse_device_id(one),
        _ => Err(LabyrinthError::invalid(
            "exactly one actorDeviceId is required",
        )),
    }
}

pub(crate) fn parse_device_id(value: &str) -> LabyrinthResult<Uuid> {
    let id = Uuid::parse_str(value)
        .map_err(|_| LabyrinthError::invalid("actorDeviceId is not a UUID"))?;
    if id.hyphenated().to_string() != value || id.get_version_num() != 4 {
        return Err(LabyrinthError::invalid(
            "actorDeviceId must be a canonical lowercase UUIDv4",
        ));
    }
    Ok(id)
}

/// Admit a query: service auth for `nsid`, the `actorDeviceId` param, and
/// the device-signed read claim over this exact query (`read_auth`).
pub async fn admit_query(
    pool: &DbPool,
    cutover_enabled: bool,
    nsid: &str,
    headers: &HeaderMap,
    query: Option<&str>,
) -> LabyrinthResult<Admission> {
    require_cutover(cutover_enabled)?;
    let principal = crate::auth::verify_mls_service_principal(headers, pool, nsid)
        .await
        .map_err(|e| service_auth_failure(nsid, e))?;
    let device_id = actor_device_from_query(query)?;
    let proof = read_auth::read_proof(headers)?;
    let instant = now_ms();
    let canonical = read_auth::canonical_query(query);
    let expected = read_auth::Expected {
        did: principal.did(),
        nsid,
        query: Some(&canonical),
    };
    let (signed_device, _) = read_auth::verify(pool, &proof, expected, instant).await?;
    if signed_device != device_id {
        return Err(LabyrinthError::invalid(
            "device-signed read: deviceId is not actorDeviceId",
        ));
    }
    Ok(Admission {
        did: principal.did().to_owned(),
        device_id,
        instant,
        write: None,
        read: Some(proof),
    })
}

fn header_b64(headers: &HeaderMap, name: &str) -> LabyrinthResult<Vec<u8>> {
    let value = headers
        .get(name)
        .and_then(|v| v.to_str().ok())
        .ok_or_else(|| LabyrinthError::invalid(format!("missing {name} header")))?;
    URL_SAFE_NO_PAD
        .decode(value)
        .map_err(|_| LabyrinthError::invalid(format!("{name} is not base64url")))
}

/// Admit a procedure: service auth for `nsid`, then the signed
/// `labyrinthWriteBody` over this exact `body`. The signature is verified
/// here against the device's registered key; the request transaction
/// re-locks that key before writing.
pub async fn admit_procedure(
    pool: &DbPool,
    cutover_enabled: bool,
    nsid: &str,
    headers: &HeaderMap,
    body: &[u8],
) -> LabyrinthResult<Admission> {
    require_cutover(cutover_enabled)?;
    let principal = crate::auth::verify_mls_service_principal(headers, pool, nsid)
        .await
        .map_err(|e| service_auth_failure(nsid, e))?;
    let signed = header_b64(headers, WRITE_BODY_HEADER)?;
    let sig = header_b64(headers, WRITE_SIGNATURE_HEADER)?;
    verify_signed_write(pool, principal.did(), nsid, &signed, &sig, body).await
}

/// The raw `labyrinthWriteBody` header values of a procedure, for the
/// federation relay to forward verbatim.
pub fn write_headers(headers: &HeaderMap) -> LabyrinthResult<(String, String)> {
    let get = |name: &str| {
        headers
            .get(name)
            .and_then(|v| v.to_str().ok())
            .map(str::to_owned)
            .ok_or_else(|| LabyrinthError::invalid(format!("missing {name} header")))
    };
    Ok((get(WRITE_BODY_HEADER)?, get(WRITE_SIGNATURE_HEADER)?))
}

/// Decode one forwarded base64url header value.
pub fn decode_b64(what: &str, value: &str) -> LabyrinthResult<Vec<u8>> {
    URL_SAFE_NO_PAD
        .decode(value)
        .map_err(|_| LabyrinthError::invalid(format!("{what} is not base64url")))
}

/// Verify a signed `labyrinthWriteBody` (decoded bytes `signed`, signature
/// `sig`) for `nsid` over `body`, by a current chat device of `did`. Used for
/// the device's own request and, on a sequencer, for one its home DS
/// relayed (design §3: the sequencer re-verifies against its replicated
/// device keys).
pub async fn verify_signed_write(
    pool: &DbPool,
    did: &str,
    nsid: &str,
    signed: &[u8],
    sig: &[u8],
    body: &[u8],
) -> LabyrinthResult<Admission> {
    let instant = now_ms();
    let wire: WriteBodyWire = serde_json::from_slice(signed)
        .map_err(|e| LabyrinthError::invalid(format!("labyrinthWriteBody: {e}")))?;
    let device_id = parse_device_id(&wire.actor_device_id)?;
    let write = check_write_body(&wire, nsid, body, instant)?;

    let mut conn = pool.acquire().await?;
    let caller = load_current_device(&mut conn, did, device_id, false).await?;
    let sig: [u8; 64] = sig
        .try_into()
        .map_err(|_| LabyrinthError::invalid("write signature must be 64 bytes"))?;
    let key =
        VerifyingKey::from_bytes(&caller.signing_key).map_err(|_| LabyrinthError::internal())?;
    key.verify_strict(
        &[WRITE_DOMAIN, signed].concat(),
        &Signature::from_bytes(&sig),
    )
    .map_err(|_| {
        LabyrinthError::new(
            axum::http::StatusCode::UNAUTHORIZED,
            "InvalidSignature",
            "labyrinthWriteBody signature does not verify under the device key",
        )
    })?;
    Ok(Admission {
        did: did.to_owned(),
        device_id,
        instant,
        write: Some(write),
        read: None,
    })
}

/// A relayed read: the device's own read claim, forwarded by its home DS,
/// re-verified here against this DS's replicated device keys. `expected`
/// names the endpoint the device called; `device_id` must be the signer.
pub async fn relayed_read(
    pool: &DbPool,
    proof: ReadProof,
    expected: read_auth::Expected<'_>,
    device_id: &str,
) -> LabyrinthResult<(Admission, read_auth::ReadClaim)> {
    let did = expected.did.to_owned();
    let instant = now_ms();
    let (signed, claim) = read_auth::verify(pool, &proof, expected, instant).await?;
    if signed != parse_device_id(device_id)? {
        return Err(LabyrinthError::invalid(
            "actorDeviceId differs from the signed read claim",
        ));
    }
    let admission = Admission {
        did,
        device_id: signed,
        instant,
        write: None,
        read: Some(proof),
    };
    Ok((admission, claim))
}

fn check_write_body(
    wire: &WriteBodyWire,
    nsid: &str,
    body: &[u8],
    instant: DateTime<Utc>,
) -> LabyrinthResult<WriteBody> {
    if wire.endpoint_nsid != nsid {
        return Err(LabyrinthError::invalid(
            "labyrinthWriteBody.endpointNsid does not name this endpoint",
        ));
    }
    let payload_sha256: [u8; 32] = Sha256::digest(body).into();
    if super::wire::bytes::hex_array::<32>("payloadSha256", &wire.payload_sha256)? != payload_sha256
    {
        return Err(LabyrinthError::invalid(
            "labyrinthWriteBody.payloadSha256 does not match the request body",
        ));
    }
    let operation_id = super::wire::bytes::hex_array::<16>("operationId", &wire.operation_id)?;
    let signed_at = DateTime::parse_from_rfc3339(&wire.signed_at)
        .map_err(|_| LabyrinthError::invalid("signedAt is not an RFC 3339 datetime"))?;
    if (signed_at.with_timezone(&Utc) - instant)
        .num_seconds()
        .abs()
        > WRITE_SKEW_SECONDS
    {
        return Err(LabyrinthError::invalid(
            "signedAt is outside the accepted window",
        ));
    }
    Ok(WriteBody {
        operation_id,
        payload_sha256,
        endpoint_nsid: nsid.to_owned(),
    })
}

#[derive(sqlx::FromRow)]
struct DeviceRow {
    status: String,
    key_id: String,
    signing_public_key: Vec<u8>,
    key_revoked: bool,
}

/// The caller's device and key, which must be current. With `lock`, both
/// rows are held `FOR SHARE` until the transaction ends.
pub async fn load_current_device(
    conn: &mut PgConnection,
    did: &str,
    device_id: Uuid,
    lock: bool,
) -> LabyrinthResult<Caller> {
    let sql = format!(
        "SELECT d.status, k.key_id, k.signing_public_key, \
                (k.revoked_at IS NOT NULL) AS key_revoked \
           FROM chat.devices d \
           JOIN chat.device_keys k \
             ON k.user_did = d.user_did AND k.device_id = d.device_id \
          WHERE d.user_did = $1 AND d.device_id = $2 {}",
        if lock { "FOR SHARE OF d, k" } else { "" }
    );
    let row: Option<DeviceRow> = sqlx::query_as(&sql)
        .bind(did)
        .bind(device_id)
        .fetch_optional(&mut *conn)
        .await?;
    let row = row.ok_or_else(|| LabyrinthError::not_authorized("device is not registered"))?;
    if row.status != "active" || row.key_revoked {
        return Err(LabyrinthError::device_revoked());
    }
    Ok(Caller {
        did: did.to_owned(),
        device_id,
        key_id: row.key_id,
        signing_key: row
            .signing_public_key
            .as_slice()
            .try_into()
            .map_err(|_| LabyrinthError::internal())?,
    })
}

/// An open request transaction holding the caller's device lock.
pub struct RequestTx {
    pub tx: Transaction<'static, Postgres>,
    pub caller: Caller,
    pub instant: DateTime<Utc>,
    write: Option<WriteBody>,
}

/// What opening a procedure's transaction found.
pub enum Begun {
    /// A completed operation with this id: replay its exact response.
    Replay(Vec<u8>),
    Fresh(Box<RequestTx>),
}

/// Open a read transaction and lock the caller's device.
pub async fn begin_read(pool: &DbPool, admission: Admission) -> LabyrinthResult<RequestTx> {
    let mut tx = pool.begin().await?;
    let caller = load_current_device(&mut tx, &admission.did, admission.device_id, true).await?;
    Ok(RequestTx {
        tx,
        caller,
        instant: admission.instant,
        write: None,
    })
}

/// Open a procedure transaction: lock the device, then replay a completed
/// operation with the same id, or refuse one whose payload or endpoint
/// differs.
pub async fn begin_write(pool: &DbPool, admission: Admission) -> LabyrinthResult<Begun> {
    let write = admission
        .write
        .clone()
        .ok_or_else(LabyrinthError::internal)?;
    let mut tx = pool.begin().await?;
    let caller = load_current_device(&mut tx, &admission.did, admission.device_id, true).await?;
    if let Some(response) = completed_operation(&mut tx, &caller.did, &write).await? {
        return Ok(Begun::Replay(response));
    }
    Ok(Begun::Fresh(Box::new(RequestTx {
        tx,
        caller,
        instant: admission.instant,
        write: Some(write),
    })))
}

async fn completed_operation(
    conn: &mut PgConnection,
    did: &str,
    write: &WriteBody,
) -> LabyrinthResult<Option<Vec<u8>>> {
    let row: Option<(String, Vec<u8>, Vec<u8>)> = sqlx::query_as(
        "SELECT endpoint_nsid, payload_sha256, response FROM labyrinth.operations \
          WHERE owner_did = $1 AND operation_id = $2",
    )
    .bind(did)
    .bind(write.operation_id.as_slice())
    .fetch_optional(&mut *conn)
    .await?;
    match row {
        None => Ok(None),
        Some((nsid, digest, response))
            if nsid == write.endpoint_nsid && digest == write.payload_sha256 =>
        {
            Ok(Some(response))
        }
        Some(_) => Err(LabyrinthError::new(
            axum::http::StatusCode::CONFLICT,
            "IdempotencyConflict",
            "operationId was already used for a different request",
        )),
    }
}

impl RequestTx {
    /// Commit a read.
    pub async fn finish_read(self) -> LabyrinthResult<()> {
        self.tx.commit().await?;
        Ok(())
    }

    /// Record the operation's response and commit. A concurrent retry of
    /// the same operation that committed first wins; its response replays.
    pub async fn finish_write(mut self, response: Vec<u8>) -> LabyrinthResult<Vec<u8>> {
        let write = self.write.take().ok_or_else(LabyrinthError::internal)?;
        let inserted = sqlx::query(
            "INSERT INTO labyrinth.operations \
               (owner_did, operation_id, endpoint_nsid, payload_sha256, actor_device_id, \
                response, created_at) \
             VALUES ($1, $2, $3, $4, $5, $6, $7) ON CONFLICT DO NOTHING",
        )
        .bind(&self.caller.did)
        .bind(write.operation_id.as_slice())
        .bind(&write.endpoint_nsid)
        .bind(write.payload_sha256.as_slice())
        .bind(self.caller.device_id)
        .bind(&response)
        .bind(self.instant)
        .execute(&mut *self.tx)
        .await?;
        if inserted.rows_affected() == 1 {
            self.tx.commit().await?;
            return Ok(response);
        }
        let did = self.caller.did.clone();
        self.tx.rollback().await?;
        Err(LabyrinthError::new(
            axum::http::StatusCode::CONFLICT,
            "IdempotencyConflict",
            format!("operation for {did} completed concurrently; retry to replay it"),
        ))
    }
}
