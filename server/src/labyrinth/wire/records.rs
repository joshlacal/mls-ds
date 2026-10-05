//! Strict shapes of the `blue.catbird.labyrinth.*` records and defs as the
//! server accepts them (lexicons in `lexicon/blue/catbird/labyrinth/`).
//!
//! Every struct denies unknown fields and every `validate` enforces the
//! lexicon's length and range limits, so whatever the server stores is
//! something the labyrinth crate's equally strict reader accepts back.

use serde::{Deserialize, Serialize};

use super::bytes::{check_datetime, check_did, check_epoch_number, check_str, check_type, Bytes};
use crate::labyrinth::error::{LabyrinthError, LabyrinthResult};

pub mod nsid {
    pub const DEVICE: &str = "blue.catbird.labyrinth.device";
    pub const EPOCH: &str = "blue.catbird.labyrinth.epoch";
    pub const EPOCH_MEMBER: &str = "blue.catbird.labyrinth.epochMember";
    pub const VIRTUAL_DEVICE: &str = "blue.catbird.labyrinth.virtualDevice";
    pub const OWNER_BATCH: &str = "blue.catbird.labyrinth.ownerBatch";
    pub const MEK: &str = "blue.catbird.labyrinth.mek";
    pub const BATCH: &str = "blue.catbird.labyrinth.batch";
}

/// `defs#transportAttestation`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TransportAttestation {
    pub transport_pubkey: Bytes,
    pub sig: Bytes,
}

/// `defs#epochPublic`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct EpochPublic {
    pub epoch_number: u64,
    pub auth_pubkey: Bytes,
    pub encryption_pubkey: Bytes,
    pub signing_pubkey: Bytes,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub previous_epoch_head: Option<Bytes>,
    pub epoch_head: Bytes,
    pub self_sig: Bytes,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub prev_sig: Option<Bytes>,
    pub attestation: TransportAttestation,
}

impl EpochPublic {
    pub fn validate(&self) -> LabyrinthResult<()> {
        check_epoch_number("epochNumber", self.epoch_number)?;
        self.auth_pubkey.check("authPubkey", 32, 32)?;
        self.encryption_pubkey
            .check("encryptionPubkey", 1216, 1216)?;
        self.signing_pubkey.check("signingPubkey", 32, 32)?;
        if let Some(h) = &self.previous_epoch_head {
            h.check("previousEpochHead", 32, 32)?;
        }
        self.epoch_head.check("epochHead", 32, 32)?;
        self.self_sig.check("selfSig", 64, 64)?;
        if let Some(s) = &self.prev_sig {
            s.check("prevSig", 64, 64)?;
        }
        self.attestation
            .transport_pubkey
            .check("attestation.transportPubkey", 32, 32)?;
        self.attestation.sig.check("attestation.sig", 64, 64)
    }
}

/// `device` record.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Device {
    #[serde(rename = "$type")]
    pub type_: String,
    pub device_key_pubkey: Bytes,
    pub epoch_storage_key_pubkey: Bytes,
    pub epoch_storage_key_sig: Bytes,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub epoch_storage_auth_key_pubkey: Option<Bytes>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub epoch_storage_auth_key_sig: Option<Bytes>,
    pub r#virtual: bool,
    /// [CB-36] The enrolling chat device's signature binding this physical
    /// device to it; absent on virtual devices.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub chat_binding: Option<TransportAttestation>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub revoked_at: Option<String>,
    pub created_at: String,
}

impl Device {
    pub fn validate(&self) -> LabyrinthResult<()> {
        check_type(&self.type_, nsid::DEVICE)?;
        self.device_key_pubkey.check("deviceKeyPubkey", 32, 32)?;
        self.epoch_storage_key_pubkey
            .check("epochStorageKeyPubkey", 32, 32)?;
        self.epoch_storage_key_sig
            .check("epochStorageKeySig", 64, 64)?;
        if let Some(b) = &self.epoch_storage_auth_key_pubkey {
            b.check("epochStorageAuthKeyPubkey", 32, 32)?;
        }
        if let Some(b) = &self.epoch_storage_auth_key_sig {
            b.check("epochStorageAuthKeySig", 64, 64)?;
        }
        if let Some(b) = &self.chat_binding {
            b.transport_pubkey
                .check("chatBinding.transportPubkey", 32, 32)?;
            b.sig.check("chatBinding.sig", 64, 64)?;
        }
        if let Some(t) = &self.revoked_at {
            check_datetime("revokedAt", t)?;
        }
        check_datetime("createdAt", &self.created_at)
    }
}

/// `epoch` record.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Epoch {
    #[serde(rename = "$type")]
    pub type_: String,
    pub public: EpochPublic,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub encrypted_previous_epoch_number: Option<Bytes>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub encrypted_previous_epoch_root_key: Option<Bytes>,
    pub opened_by: Bytes,
    pub created_at: String,
}

impl Epoch {
    pub fn validate(&self) -> LabyrinthResult<()> {
        check_type(&self.type_, nsid::EPOCH)?;
        self.public.validate()?;
        if let Some(b) = &self.encrypted_previous_epoch_number {
            b.check("encryptedPreviousEpochNumber", 0, 128)?;
        }
        if let Some(b) = &self.encrypted_previous_epoch_root_key {
            b.check("encryptedPreviousEpochRootKey", 0, 128)?;
        }
        self.opened_by.check("openedBy", 32, 32)?;
        check_datetime("createdAt", &self.created_at)
    }
}

/// `epochMember` record.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct EpochMember {
    #[serde(rename = "$type")]
    pub type_: String,
    pub epoch_number: u64,
    pub device_key_pubkey: Bytes,
    pub device_mac: Bytes,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub encrypted_entropy: Option<Bytes>,
    pub created_at: String,
}

impl EpochMember {
    pub fn validate(&self) -> LabyrinthResult<()> {
        check_type(&self.type_, nsid::EPOCH_MEMBER)?;
        check_epoch_number("epochNumber", self.epoch_number)?;
        self.device_key_pubkey.check("deviceKeyPubkey", 32, 32)?;
        self.device_mac.check("deviceMac", 32, 32)?;
        if let Some(b) = &self.encrypted_entropy {
            b.check("encryptedEntropy", 0, 128)?;
        }
        check_datetime("createdAt", &self.created_at)
    }
}

/// `virtualDevice` record.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct VirtualDevice {
    #[serde(rename = "$type")]
    pub type_: String,
    pub vdevice_id: Bytes,
    pub encrypted_device_key_priv: Bytes,
    pub encrypted_epoch_storage_key_priv: Bytes,
    pub encrypted_orf_client_state: Bytes,
    pub encrypted_mailbox_root_salt: Bytes,
    pub encrypted_epoch_root_key: Bytes,
    pub encrypted_epoch_number: Bytes,
    pub device_key_pubkey: Bytes,
    pub epoch_storage_key_pubkey: Bytes,
    pub epoch_storage_key_sig: Bytes,
    pub mechanism: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub passkey_wrapped_code: Option<Bytes>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub passkey_credential_id: Option<Bytes>,
    pub created_at: String,
}

impl VirtualDevice {
    pub fn validate(&self) -> LabyrinthResult<()> {
        check_type(&self.type_, nsid::VIRTUAL_DEVICE)?;
        self.vdevice_id.check("vdeviceId", 16, 16)?;
        for (what, b) in [
            ("encryptedDeviceKeyPriv", &self.encrypted_device_key_priv),
            (
                "encryptedEpochStorageKeyPriv",
                &self.encrypted_epoch_storage_key_priv,
            ),
            ("encryptedOrfClientState", &self.encrypted_orf_client_state),
            (
                "encryptedMailboxRootSalt",
                &self.encrypted_mailbox_root_salt,
            ),
            ("encryptedEpochRootKey", &self.encrypted_epoch_root_key),
            ("encryptedEpochNumber", &self.encrypted_epoch_number),
        ] {
            b.check(what, 0, 256)?;
        }
        self.device_key_pubkey.check("deviceKeyPubkey", 32, 32)?;
        self.epoch_storage_key_pubkey
            .check("epochStorageKeyPubkey", 32, 32)?;
        self.epoch_storage_key_sig
            .check("epochStorageKeySig", 64, 64)?;
        check_str("mechanism", &self.mechanism, 64)?;
        if let Some(b) = &self.passkey_wrapped_code {
            b.check("passkeyWrappedCode", 0, 256)?;
        }
        if let Some(b) = &self.passkey_credential_id {
            b.check("passkeyCredentialId", 0, 1024)?;
        }
        check_datetime("createdAt", &self.created_at)
    }
}

/// `defs#ownerMessage`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct OwnerMessage {
    pub thread_id: String,
    pub message_id: String,
    pub timestamp: u64,
    pub epoch_number: u64,
    pub version: u64,
    pub encrypted: Bytes,
}

/// `ownerBatch` record.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct OwnerBatch {
    #[serde(rename = "$type")]
    pub type_: String,
    pub thread_id: String,
    pub items: Vec<OwnerMessage>,
    pub created_at: String,
}

impl OwnerBatch {
    pub fn validate(&self) -> LabyrinthResult<()> {
        check_type(&self.type_, nsid::OWNER_BATCH)?;
        check_str("threadId", &self.thread_id, 256)?;
        check_items(self.items.len())?;
        for item in &self.items {
            check_str("items.threadId", &item.thread_id, 256)?;
            check_str("items.messageId", &item.message_id, 128)?;
            check_timestamp(item.timestamp)?;
            check_epoch_number("items.epochNumber", item.epoch_number)?;
            if item.version > 4 {
                return Err(LabyrinthError::invalid("items.version must be 0..=4"));
            }
            item.encrypted.check("items.encrypted", 0, 262_144)?;
        }
        check_datetime("createdAt", &self.created_at)
    }

    /// (min, max) item timestamp.
    pub fn ts_range(&self) -> (u64, u64) {
        ts_range(self.items.iter().map(|i| i.timestamp))
    }
}

/// `defs#mekRecipient`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MekRecipient {
    pub did: String,
    pub recipient_epoch_head: Bytes,
    pub ciphertext: Bytes,
}

/// `mek#labyrinthSender`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct LabyrinthSender {
    pub did: String,
    pub sender_epoch_head: Bytes,
    pub sender_epoch: EpochPublic,
}

/// `mek#transportSender`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TransportSender {
    pub transport_pubkey: Bytes,
    pub ephemeral_auth_pubkey: Bytes,
    pub sig: Bytes,
}

/// The closed `mek.sender` union.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "$type")]
pub enum MekSender {
    #[serde(rename = "blue.catbird.labyrinth.mek#labyrinthSender")]
    Labyrinth(LabyrinthSender),
    #[serde(rename = "blue.catbird.labyrinth.mek#transportSender")]
    Transport(TransportSender),
}

/// `mek` record.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Mek {
    #[serde(rename = "$type")]
    pub type_: String,
    pub thread_id: String,
    pub mek_id: Bytes,
    pub roster_hash: Bytes,
    pub sender: MekSender,
    pub recipients: Vec<MekRecipient>,
    pub created_at: String,
}

impl Mek {
    pub fn validate(&self) -> LabyrinthResult<()> {
        check_type(&self.type_, nsid::MEK)?;
        check_str("threadId", &self.thread_id, 256)?;
        self.mek_id.check("mekId", 12, 12)?;
        self.roster_hash.check("rosterHash", 32, 32)?;
        match &self.sender {
            MekSender::Labyrinth(s) => {
                check_did("sender.did", &s.did)?;
                s.sender_epoch_head
                    .check("sender.senderEpochHead", 32, 32)?;
                s.sender_epoch.validate()?;
                if s.sender_epoch.epoch_head != s.sender_epoch_head {
                    return Err(LabyrinthError::invalid(
                        "sender.senderEpochHead must equal sender.senderEpoch.epochHead",
                    ));
                }
            }
            MekSender::Transport(s) => {
                s.transport_pubkey.check("sender.transportPubkey", 32, 32)?;
                s.ephemeral_auth_pubkey
                    .check("sender.ephemeralAuthPubkey", 32, 32)?;
                s.sig.check("sender.sig", 64, 64)?;
            }
        }
        if self.recipients.len() > 512 {
            return Err(LabyrinthError::invalid("at most 512 recipients"));
        }
        for r in &self.recipients {
            check_did("recipients.did", &r.did)?;
            r.recipient_epoch_head
                .check("recipients.recipientEpochHead", 32, 32)?;
            r.ciphertext.check("recipients.ciphertext", 0, 1200)?;
        }
        check_datetime("createdAt", &self.created_at)
    }
}

/// `defs#redaction` ([CB-38]): present on a redacted sealed message. Writers
/// never send it; only the server's redaction adds it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Redaction {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub transport_pubkey: Option<Bytes>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sig: Option<Bytes>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub redacted_at: Option<String>,
    /// Server redactions (account deletion, finding 7): the redacting DS.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub by: Option<String>,
    /// Server redactions: why (`accountDeleted`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

/// `defs#sealedMessage`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SealedMessage {
    pub message_id: String,
    pub timestamp: u64,
    pub mek_id: Bytes,
    pub sender_transport_pubkey: Bytes,
    /// Empty exactly when `redaction` is present.
    pub signed_enc_message: Bytes,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub redaction: Option<Redaction>,
}

/// `batch` record.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Batch {
    #[serde(rename = "$type")]
    pub type_: String,
    pub thread_id: String,
    pub items: Vec<SealedMessage>,
    pub created_at: String,
}

impl Batch {
    pub fn validate(&self) -> LabyrinthResult<()> {
        check_type(&self.type_, nsid::BATCH)?;
        check_str("threadId", &self.thread_id, 256)?;
        check_items(self.items.len())?;
        for item in &self.items {
            check_str("items.messageId", &item.message_id, 128)?;
            check_timestamp(item.timestamp)?;
            item.mek_id.check("items.mekId", 12, 12)?;
            item.sender_transport_pubkey
                .check("items.senderTransportPubkey", 32, 32)?;
            item.signed_enc_message
                .check("items.signedEncMessage", 64, 262_144)?;
            if item.redaction.is_some() {
                return Err(LabyrinthError::invalid(
                    "items.redaction is set only by the server",
                ));
            }
        }
        check_datetime("createdAt", &self.created_at)
    }

    pub fn ts_range(&self) -> (u64, u64) {
        ts_range(self.items.iter().map(|i| i.timestamp))
    }
}

fn check_items(n: usize) -> LabyrinthResult<()> {
    if (1..=256).contains(&n) {
        Ok(())
    } else {
        Err(LabyrinthError::invalid("items must hold 1..=256 entries"))
    }
}

/// Item timestamps are stored as BIGINT and must stay JSON-safe integers.
fn check_timestamp(ts: u64) -> LabyrinthResult<()> {
    if ts < (1 << 53) {
        Ok(())
    } else {
        Err(LabyrinthError::invalid("items.timestamp exceeds 2^53 - 1"))
    }
}

fn ts_range(ts: impl Iterator<Item = u64>) -> (u64, u64) {
    ts.fold((u64::MAX, 0), |(lo, hi), t| (lo.min(t), hi.max(t)))
}
