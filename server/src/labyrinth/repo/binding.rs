//! Labyrinth device ↔ chat device binding (gap audit G-P0-2, migration
//! `20261004100004`).
//!
//! `createDevice` records the calling chat device and key on the Labyrinth
//! device row. Epoch writes then require that binding, so a chat device can
//! only open epochs as its own Labyrinth device and only list registered,
//! current Labyrinth devices as members. A compromised chat device can still
//! act as its own Labyrinth device until it is revoked; clients therefore
//! revoke the chat device before rotating its Labyrinth device out.

use ed25519_dalek::{Signature, VerifyingKey};
use sqlx::PgConnection;

use crate::labyrinth::auth::Caller;
use crate::labyrinth::error::{LabyrinthError, LabyrinthResult};
use crate::labyrinth::wire::records::Device;

/// Signature prefix of `device.chatBinding` ([CB-36]).
pub const BINDING_PREFIX: &str = "catbird.labyrinth.device_binding:";

fn bad_binding(message: &str) -> LabyrinthError {
    LabyrinthError::invalid_named("InvalidChatBinding", message.to_owned())
}

/// `createDevice`: a physical device must carry a `chatBinding` by the
/// calling chat device's key over `prefix || did || ":" || deviceKeyPubkey`;
/// a virtual device must carry none.
pub fn verify_chat_binding(caller: &Caller, device: &Device) -> LabyrinthResult<()> {
    match (&device.chat_binding, device.r#virtual) {
        (None, true) => Ok(()),
        (Some(_), true) => Err(bad_binding("a virtual device carries no chatBinding")),
        (None, false) => Err(bad_binding("a physical device needs a chatBinding")),
        (Some(b), false) => {
            if b.transport_pubkey.0 != caller.signing_key {
                return Err(bad_binding(
                    "chatBinding.transportPubkey is not the calling chat device's key",
                ));
            }
            let key = VerifyingKey::from_bytes(&caller.signing_key)
                .map_err(|_| LabyrinthError::internal())?;
            let sig: [u8; 64] = b.sig.array("chatBinding.sig")?;
            let message = [
                format!("{BINDING_PREFIX}{}:", caller.did).as_bytes(),
                device.device_key_pubkey.0.as_slice(),
            ]
            .concat();
            key.verify_strict(&message, &Signature::from_bytes(&sig))
                .map_err(|_| bad_binding("chatBinding.sig does not verify"))
        }
    }
}

/// Whether `did` keeps its Labyrinth mailbox on this DS (a mailbox row
/// exists once any mailbox record was written). An account whose mailbox
/// lives in its own PDS Space (labyrinth SPEC §9, backend A) has none: this
/// DS is then only its independent head directory ([CB-28]) and ORF
/// server, and the binding rules, which need mailbox device rows, cannot
/// apply to it.
pub async fn hosts_mailbox(conn: &mut PgConnection, did: &str) -> LabyrinthResult<bool> {
    Ok(
        sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM labyrinth.mailboxes WHERE owner_did = $1)")
            .bind(did)
            .fetch_one(&mut *conn)
            .await?,
    )
}

fn not_bound() -> LabyrinthError {
    LabyrinthError::forbidden(
        "LabyrinthDeviceNotBound",
        "the calling chat device holds no current Labyrinth device",
    )
}

/// The caller must hold a current, non-virtual Labyrinth device bound to its
/// chat device and key; with `key`, that device must be exactly `key`.
pub async fn require_bound(
    conn: &mut PgConnection,
    caller: &Caller,
    key: Option<&[u8]>,
) -> LabyrinthResult<()> {
    let ok: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM labyrinth.devices \
                        WHERE owner_did = $1 AND chat_device_id = $2 AND chat_key_id = $3 \
                          AND revoked_at IS NULL AND NOT is_virtual \
                          AND ($4::bytea IS NULL OR device_key = $4))",
    )
    .bind(&caller.did)
    .bind(caller.device_id)
    .bind(&caller.key_id)
    .bind(key)
    .fetch_one(&mut *conn)
    .await?;
    if ok {
        Ok(())
    } else {
        Err(not_bound())
    }
}

/// Every key must be a current (non-revoked) Labyrinth device of `owner`.
pub async fn require_registered(
    conn: &mut PgConnection,
    owner: &str,
    keys: &[Vec<u8>],
) -> LabyrinthResult<()> {
    if keys.is_empty() {
        return Ok(());
    }
    let found: i64 = sqlx::query_scalar(
        "SELECT count(DISTINCT device_key) FROM labyrinth.devices \
          WHERE owner_did = $1 AND device_key = ANY($2) AND revoked_at IS NULL",
    )
    .bind(owner)
    .bind(keys)
    .fetch_one(&mut *conn)
    .await?;
    let distinct = keys.iter().collect::<std::collections::BTreeSet<_>>().len() as i64;
    if found == distinct {
        Ok(())
    } else {
        Err(LabyrinthError::invalid_named(
            "MemberDeviceNotRegistered",
            "an epoch member is not a current Labyrinth device of this account",
        ))
    }
}
