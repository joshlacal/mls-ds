// G7 Checkpoint B-read: consuming read authority over the frozen G7 read
// endpoints.
//
// B-read accepts only [`VerifiedReadAdmission`] and never a caller-selected
// DID, device, JKT, generation, protocol ID, key ID, cursor digest, inventory
// fence, or authority boolean. Conversion against a closed repository-owned
// expected endpoint mints exactly one of two nonconstructible budgets:
// [`SingleReadAdmission`] (exactly one attempt for an ordinary read) or
// [`InventoryReadAdmission`] (exactly three attempts for the inventory
// facade). There is no general `begin_attempt`, raw counter constructor,
// unbudgeted attempt mint, or conversion from handler-selected endpoint text.
//
// ## Lock order (BREAD-06)
//
// Every protected read runs under the structural order frozen by the
// readiness amendment:
//
// ```text
// receipt-bound exact device row
//   -> exact device-key row
//   -> lock-free candidate/fence discovery
//   -> conversation head locks in ascending UUID byte order
//   -> head-pinned aggregate/source reads
//   -> final protocol/key/head/floor/cursor-session revalidation
// ```
//
// The device lock is `await`ed and matched before the key statement is even
// constructed (`lock_read_device_authority_once`), so the ordering is
// structural rather than documentary. No principal/device/key authority query
// (`chat.devices`, `chat.device_keys`) occurs after the first conversation
// head. The relationship/source reads that follow a head are head-pinned
// reads over participant/leaf/interval/proof rows, never fresh authority
// queries.
//
// ## Relationship classification
//
// `classify_current_relationship` implements the exact readiness-amendment
// matrix over the hydrated conversation aggregate:
//
// - a current exact open leaf authorizes state and entries;
// - an eligible active zero-leaf participant or group-pending participant
//   authorizes current state only;
// - direct-pending remains `NotEntitled`;
// - a finite reset/remove interval for the requesting exact device takes
//   precedence over same-DID current participation unless the same exact
//   device has a later valid open interval (BREAD-05);
// - a known former, post-reset-old, or exact terminal-proof holder receives
//   `AccessOutsideMembershipInterval`;
// - an unrelated requester for an active or terminal conversation receives
//   `NotEntitled` (BREAD-04: the historical-relationship check guards both
//   the active and the terminal branch);
// - conversation absence remains `ConversationNotFound`.
//
// ## Inventory arms
//
// For each candidate conversation exactly one arm is selected in this order:
// terminal conversation plus exact complete schedule proof (close tombstone),
// active conversation plus exact open membership interval (state), active
// conversation plus latest exact finite interval with no later open interval
// (removal tombstone), active conversation plus eligible current participant
// (state), no item.
//
// ## Fence types (seam authority amendment §8)
//
// B-read owns [`LockedInventoryFenceRecord`], [`LockedDurableInventoryFenceRow`],
// and [`VerifiedInventoryFence`] here. `from_locked_inventory_fence_record`
// is the sole constructor of the durable row and has zero production callers
// until D lands its durable loader at ordinal 35; the entitlement test's
// source guards prove that. `verify_inventory_fence` consumes both inputs,
// verifies the locked device and fence record were obtained under the same
// `txid_current()`, and mints the only value accepted by
// `inventory_authorities`. The inventory-session and event-cursor-receipt
// validation that requires D's durable loader is recorded as the D handoff:
// until the loader exists, the record carries only the protocol/key/event/
// floor/temporal material D's `SELECT ... FOR UPDATE` will return, and the
// session-level coordinates are bound by the same-transaction check plus the
// final protocol/key/head/floor revalidation.
//
// ## BREAD-08
//
// Every accessor on the B-read-owned authority types is
// `pub(in crate::chat_protocol)` — never `pub(crate)` — and exposes only the
// minimum immutable view required by C1's projection. The checked source
// types themselves stay `pub(crate)` per the frozen internal interfaces.

use chrono::{DateTime, Utc};
use sha2::{Digest, Sha256};
use sqlx::{FromRow, Postgres, Transaction};
use uuid::Uuid;

use crate::chat_protocol::{
    dpop::{
        LockedReadDatabaseRow, ReadAdmissionAttempt, ReadAdmissionBindingError,
        VerifiedExistingDeviceReadRow, VerifiedReadAdmission,
    },
    repository::core::{
        hydrate_locked_conversation_state, ConversationHeadHydrationError,
        ConversationStateHydrationError, LockedConversationStateGuard,
    },
    state_machine::{
        AccessInterval, AccessIntervalEnd, ConversationKind, ConversationState, DeviceIdentity,
        PrincipalId,
    },
};

/// The closed ordinary G7 read/event endpoints, excluding the inventory
/// endpoint. Each variant owns its exact NSID and canonical HTTP method; the
/// methods column of the downstream-readiness amendment's 32-endpoint
/// inventory is authoritative (`getSubscriptionTicket` and `publishTyping`
/// are POST, everything else GET).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum OrdinaryReadEndpoint {
    GetConversationState,
    GetEntries,
    GetPendingWelcomes,
    GetLeafRecoveryInbox,
    GetBlob,
    GetBlobUsage,
    UploadBlob,
    GetSubscriptionTicket,
    SubscribeEvents,
    PublishTyping,
}

impl OrdinaryReadEndpoint {
    pub(crate) const fn nsid(self) -> &'static str {
        match self {
            Self::GetConversationState => "blue.catbird.chat.getConversationState",
            Self::GetEntries => "blue.catbird.chat.getEntries",
            Self::GetPendingWelcomes => "blue.catbird.chat.getPendingWelcomes",
            Self::GetLeafRecoveryInbox => "blue.catbird.chat.getLeafRecoveryInbox",
            Self::GetBlob => "blue.catbird.chat.getBlob",
            Self::GetBlobUsage => "blue.catbird.chat.getBlobUsage",
            Self::UploadBlob => "blue.catbird.chat.uploadBlob",
            Self::GetSubscriptionTicket => "blue.catbird.chat.getSubscriptionTicket",
            Self::SubscribeEvents => "blue.catbird.chat.subscribeEvents",
            Self::PublishTyping => "blue.catbird.chat.publishTyping",
        }
    }

    pub(crate) const fn canonical_method(self) -> &'static str {
        match self {
            Self::GetSubscriptionTicket | Self::PublishTyping | Self::UploadBlob => "POST",
            _ => "GET",
        }
    }
}

/// The closed inventory endpoint. It contains ONLY the inventory endpoint:
/// no public/general endpoint enum can be converted into either budget without
/// the corresponding exhaustive closed match.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(in crate::chat_protocol) enum InventoryReadEndpoint {
    GetConversations,
}

impl InventoryReadEndpoint {
    pub(in crate::chat_protocol) const fn nsid(self) -> &'static str {
        "blue.catbird.chat.getConversations"
    }

    pub(in crate::chat_protocol) const fn canonical_method(self) -> &'static str {
        "GET"
    }
}

/// Redacted B-read failure. Every variant is a unit variant, so no `Debug`
/// rendering can carry requester DID, device, JKT, generation, key, proof,
/// cursor, transaction, or fence material. Deliberately non-serde.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ReadAuthorityError {
    /// The conversation row does not exist.
    ConversationNotFound,
    /// The conversation exists but the requester has no known qualifying
    /// relationship or proof.
    NotEntitled,
    /// The requester has a known former/post-reset relationship or proof but
    /// lacks the current-state capability.
    AccessOutsideMembershipInterval,
    /// The requesting device registration or bound authentication generation
    /// is revoked.
    DeviceRevoked,
    /// A storage failure with no declared wire code.
    Storage,
    /// An internal invariant failure (drift, splicing, foreign transaction,
    /// inconsistent authority) with no declared wire code. The endpoint maps
    /// it to an internal error through `ChatFailure`; no protocol code is
    /// invented.
    Invariant,
}

/// Closed one-attempt budget for an ordinary G7 read. Nonconstructible
/// outside this module: minted only by `into_single_read_admission`, spent by
/// `into_attempt`. Deliberately non-`Clone`, non-`Copy`, non-`Debug`,
/// non-serde.
pub(in crate::chat_protocol) struct SingleReadAdmission {
    attempt: ReadAdmissionAttempt,
}

/// Closed fixed three-attempt budget for the inventory facade. The fourth
/// attempt is unrepresentable because the field is a fixed-size array of
/// exactly this length and no push/reset/mint operation exists. Deliberately
/// non-`Clone`, non-`Copy`, non-`Debug`, non-serde.
pub(in crate::chat_protocol) struct InventoryReadAdmission {
    attempts: [ReadAdmissionAttempt; 3],
}

impl SingleReadAdmission {
    pub(in crate::chat_protocol) fn into_attempt(self) -> ReadAdmissionAttempt {
        self.attempt
    }
}

impl InventoryReadAdmission {
    pub(in crate::chat_protocol) fn into_attempts(self) -> [ReadAdmissionAttempt; 3] {
        self.attempts
    }
}

/// Convert a sealed admission into the ordinary-read budget against one exact
/// closed ordinary endpoint. The seam method validates the hidden
/// endpoint/method binding and fails before SQL on any mismatch.
pub(in crate::chat_protocol) fn into_single_read_admission(
    admission: VerifiedReadAdmission,
    endpoint: OrdinaryReadEndpoint,
) -> Result<SingleReadAdmission, ReadAuthorityError> {
    let attempt = admission
        .into_single_read_attempt(endpoint.nsid(), endpoint.canonical_method())
        .map_err(|_| ReadAuthorityError::Invariant)?;
    Ok(SingleReadAdmission { attempt })
}

/// Convert a sealed admission into the inventory budget against the exact
/// closed inventory endpoint. The seam method validates the hidden
/// endpoint/method binding and fails before SQL on any mismatch.
pub(in crate::chat_protocol) fn into_inventory_read_admission(
    admission: VerifiedReadAdmission,
    endpoint: InventoryReadEndpoint,
) -> Result<InventoryReadAdmission, ReadAuthorityError> {
    let attempts = admission
        .into_inventory_read_attempts(endpoint.nsid(), endpoint.canonical_method())
        .map_err(|_| ReadAuthorityError::Invariant)?;
    Ok(InventoryReadAdmission { attempts })
}

/// The verified requester lock for one read attempt. Per the frozen internal
/// interfaces it is `pub(crate)` with private fields; every accessor is
/// `pub(in crate::chat_protocol)` (BREAD-08).
pub(crate) struct LockedReadDeviceAuthority {
    txid: i64,
    user_did: String,
    device_id: Uuid,
    jkt: Option<String>,
    auth_generation: u64,
    active_key_id: String,
    device_row_sha256: [u8; 32],
}

impl LockedReadDeviceAuthority {
    pub(in crate::chat_protocol) fn txid(&self) -> i64 {
        self.txid
    }

    pub(in crate::chat_protocol) fn user_did(&self) -> &str {
        &self.user_did
    }

    pub(in crate::chat_protocol) fn device_id(&self) -> Uuid {
        self.device_id
    }

    pub(in crate::chat_protocol) fn jkt(&self) -> Option<&str> {
        self.jkt.as_deref()
    }

    pub(in crate::chat_protocol) fn auth_generation(&self) -> u64 {
        self.auth_generation
    }

    pub(in crate::chat_protocol) fn active_key_id(&self) -> &str {
        &self.active_key_id
    }

    pub(in crate::chat_protocol) fn device_row_sha256(&self) -> &[u8; 32] {
        &self.device_row_sha256
    }

    /// Checker, not a getter: the transaction identity never leaves the type.
    /// A guard minted under transaction A is terminal — never a retryable
    /// snapshot conflict — under transaction B.
    pub(in crate::chat_protocol) fn verify_same_transaction(
        &self,
        txid: i64,
    ) -> Result<(), ReadAuthorityError> {
        if self.txid == txid {
            Ok(())
        } else {
            Err(ReadAuthorityError::Invariant)
        }
    }
}

/// The exact requester `chat.devices` row. Deliberately a single-table
/// statement: the device barrier must complete before the key statement is
/// even issued, and a joined `FOR UPDATE OF device, device_key` is not proof
/// of that order (BREAD-06).
const LOCK_READ_DEVICE_SQL: &str = r#"
    SELECT user_did, device_id, status, dpop_jkt, auth_generation
      FROM chat.devices
     WHERE user_did = $1 AND device_id = $2
     FOR UPDATE
"#;

/// The exact requester `chat.device_keys` row, in a SEPARATE statement issued
/// only after the device lock above has already returned.
const LOCK_READ_DEVICE_KEY_SQL: &str = r#"
    SELECT key_id, signing_public_key, revoked_at
      FROM chat.device_keys
     WHERE user_did = $1 AND device_id = $2
     FOR UPDATE
"#;

#[derive(FromRow)]
struct LockedReadRequesterDeviceRow {
    user_did: String,
    device_id: Uuid,
    status: String,
    dpop_jkt: Option<String>,
    auth_generation: i64,
}

#[derive(FromRow)]
struct LockedReadRequesterKeyRow {
    key_id: String,
    signing_public_key: Vec<u8>,
    revoked_at: Option<DateTime<Utc>>,
}

/// Domain-separated binding digest over exactly the structural evidence the
/// consuming verifier accepted for the locked device/key rows. This is the
/// B-read definition of the device-row binding carried by the authority and
/// the inventory authorities; it commits DID, device, status, JKT, generation,
/// key ID, and signing-key digest.
fn locked_device_row_binding_digest(
    did: &str,
    device_id: Uuid,
    status: &str,
    textual_jkt: Option<&str>,
    auth_generation: i64,
    key_id: &str,
    signing_public_key_sha256: &[u8; 32],
) -> [u8; 32] {
    let mut digest = Sha256::new();
    digest.update(b"CATBIRD-CHAT-LOCKED-READ-DEVICE-ROW\0");
    digest.update((did.len() as u64).to_be_bytes());
    digest.update(did.as_bytes());
    digest.update(device_id.as_bytes());
    digest.update((status.len() as u64).to_be_bytes());
    digest.update(status.as_bytes());
    let jkt_str = textual_jkt.unwrap_or_default();
    digest.update((jkt_str.len() as u64).to_be_bytes());
    digest.update(jkt_str.as_bytes());
    digest.update(auth_generation.to_be_bytes());
    digest.update((key_id.len() as u64).to_be_bytes());
    digest.update(key_id.as_bytes());
    digest.update(signing_public_key_sha256);
    digest.finalize().into()
}

/// Map a hidden-binding rejection onto the redacted B-read outcome. Device
/// status and key revocation are the two `DeviceRevoked` shapes; every other
/// drift is an invariant (the admission's hidden binding and the locked row
/// disagree after a successful seal).
fn map_binding_error(error: ReadAdmissionBindingError) -> ReadAuthorityError {
    match error {
        ReadAdmissionBindingError::DeviceStatus | ReadAdmissionBindingError::KeyRevoked => {
            ReadAuthorityError::DeviceRevoked
        }
        _ => ReadAuthorityError::Invariant,
    }
}

/// Begin one read attempt: two ORDERED single-table `FOR UPDATE` statements,
/// then the B-read `LockedReadDatabaseRow::from_repository_lock` callsite,
/// then the consuming attempt verification, then the same-transaction check.
///
/// Ordering is structural, not documentary: the device lock is `await`ed and
/// matched before the key statement is constructed, and the constructor call
/// is unreachable unless BOTH `Some(..)` arms bind. A missing device row or a
/// missing key row returns BEFORE construction.
///
/// Every failure is terminal. Authority drift surfaces from the consuming
/// verifier and is never retried as a snapshot conflict. A failed or foreign
/// transaction retains no authority: the attempt was consumed by value.
pub(in crate::chat_protocol) async fn lock_read_device_authority_once(
    tx: &mut Transaction<'_, Postgres>,
    attempt: ReadAdmissionAttempt,
) -> Result<LockedReadDeviceAuthority, ReadAuthorityError> {
    // The borrow of `attempt` is authority-bearing: the lock-coordinate
    // carrier cannot outlive the attempt. Copy the two values out and drop the
    // borrow immediately so the attempt can still be consumed below.
    let (lock_did, lock_device_id) = {
        let coordinates = attempt.lock_coordinates();
        (coordinates.did.to_owned(), coordinates.device_id)
    };

    let transaction_id: String = sqlx::query_scalar("SELECT txid_current()::text")
        .fetch_one(&mut **tx)
        .await
        .map_err(|_| ReadAuthorityError::Storage)?;
    let txid: i64 = transaction_id
        .parse()
        .map_err(|_| ReadAuthorityError::Invariant)?;

    // BARRIER 1 — the exact requester device row.
    let device: Option<LockedReadRequesterDeviceRow> = sqlx::query_as(LOCK_READ_DEVICE_SQL)
        .bind(&lock_did)
        .bind(lock_device_id)
        .fetch_optional(&mut **tx)
        .await
        .map_err(|_| ReadAuthorityError::Storage)?;
    let Some(device) = device else {
        // Missing device row: return before construction.
        return Err(ReadAuthorityError::Invariant);
    };

    // BARRIER 2 — a SEPARATE statement for the exact requester key row, issued
    // only now that barrier 1 has completed.
    let key: Option<LockedReadRequesterKeyRow> = sqlx::query_as(LOCK_READ_DEVICE_KEY_SQL)
        .bind(&lock_did)
        .bind(lock_device_id)
        .fetch_optional(&mut **tx)
        .await
        .map_err(|_| ReadAuthorityError::Storage)?;
    let Some(key) = key else {
        // Missing key row: return before construction.
        return Err(ReadAuthorityError::Invariant);
    };

    let signing_public_key_sha256: [u8; 32] = Sha256::digest(&key.signing_public_key).into();

    // The B-read `from_repository_lock` callsite. Reachable only after BOTH
    // ordered locks succeeded, and it carries the row's OWN
    // `user_did`/`device_id` rather than the coordinates that addressed it.
    let locked_row = LockedReadDatabaseRow::from_repository_lock(
        transaction_id.clone().into_boxed_str(),
        device.user_did.clone().into_boxed_str(),
        device.device_id,
        device.status.clone().into_boxed_str(),
        device.dpop_jkt.clone().map(String::into_boxed_str),
        device.auth_generation,
        key.key_id.clone().into_boxed_str(),
        signing_public_key_sha256,
        key.revoked_at,
    )
    .map_err(|_| ReadAuthorityError::Invariant)?;

    // Constructing the row proved nothing. Only this consuming verification
    // mints authority, and it spends the attempt.
    let verified: VerifiedExistingDeviceReadRow = attempt
        .consume_verify_locked_row(locked_row)
        .map_err(map_binding_error)?;
    verified
        .verify_same_transaction(&transaction_id)
        .map_err(|_| ReadAuthorityError::Invariant)?;
    let device_row_sha256 = locked_device_row_binding_digest(
        &device.user_did,
        device.device_id,
        &device.status,
        device.dpop_jkt.as_deref(),
        device.auth_generation,
        &key.key_id,
        &signing_public_key_sha256,
    );
    Ok(LockedReadDeviceAuthority {
        txid,
        user_did: device.user_did,
        device_id: device.device_id,
        jkt: device.dpop_jkt,
        auth_generation: u64::try_from(device.auth_generation)
            .map_err(|_| ReadAuthorityError::Invariant)?,
        active_key_id: key.key_id,
        device_row_sha256,
    })
}

/// Read the current `txid_current()` and refuse any authority minted under a
/// different transaction. Every downstream authority runs this BEFORE any
/// conversation existence, state, entry, inventory, or fence query.
async fn assert_same_transaction(
    tx: &mut Transaction<'_, Postgres>,
    expected: i64,
) -> Result<(), ReadAuthorityError> {
    let current: i64 = sqlx::query_scalar("SELECT txid_current()::bigint")
        .fetch_one(&mut **tx)
        .await
        .map_err(|_| ReadAuthorityError::Storage)?;
    if current == expected {
        Ok(())
    } else {
        Err(ReadAuthorityError::Invariant)
    }
}

/// The exact-device interval facts the classification needs, derived from the
/// hydrated aggregate (head-pinned source reads). The aggregate's interval
/// shape is ordered and open-last by hydration; selection here only picks the
/// latest interval of each kind for the requesting exact device.
struct ExactDeviceIntervalFacts<'a> {
    /// The latest interval that is still open, if any.
    open: Option<&'a AccessInterval>,
    /// The latest finite (closed) interval, if no later open interval exists.
    latest_finite: Option<&'a AccessInterval>,
    /// The conversation is terminal (no active public state).
    terminal: bool,
    /// The exact device holds a schedule terminal proof.
    terminal_proof_holder: bool,
}

fn exact_device_identity(
    user_did: &str,
    device_id: Uuid,
) -> Result<DeviceIdentity, ReadAuthorityError> {
    let principal = PrincipalId::new(user_did.as_bytes().to_vec())
        .map_err(|_| ReadAuthorityError::Invariant)?;
    DeviceIdentity::new(principal, *device_id.as_bytes()).map_err(|_| ReadAuthorityError::Invariant)
}

fn exact_device_interval_facts<'a>(
    user_did: &str,
    device_id: Uuid,
    state: &'a ConversationState,
) -> Result<ExactDeviceIntervalFacts<'a>, ReadAuthorityError> {
    let identity = exact_device_identity(user_did, device_id)?;

    let intervals: &[AccessInterval] = state.intervals();
    let open = intervals
        .iter()
        .filter(|interval| interval.recipient() == &identity)
        .find(|interval| interval.end().is_none());
    let latest_finite = intervals
        .iter()
        .filter(|interval| interval.recipient() == &identity && interval.end().is_some())
        .max_by_key(|interval| interval.opening_seq());
    Ok(ExactDeviceIntervalFacts {
        open,
        latest_finite,
        terminal: state.active_public_state().is_none(),
        terminal_proof_holder: state.terminal_proof(&identity).is_some(),
    })
}

/// A private decision: which state-capable arm the matrix selected. The
/// durable period IDs are loaded under the locked head afterwards.
enum ClassifiedRelationshipArm {
    OpenLeaf { open_membership_interval_id: Uuid },
    ActiveParticipant,
    GroupPendingParticipant,
}

/// The exact readiness-amendment classification matrix, over the hydrated
/// aggregate. State-capable arms are returned as decisions; every denial is
/// mapped to its exact frozen wire error.
///
/// BREAD-04: the historical-relationship check (terminal proof / finite
/// interval) guards BOTH branches, so an unrelated requester for an active or
/// terminal conversation receives `NotEntitled`, never
/// `AccessOutsideMembershipInterval`.
///
/// BREAD-05: the requesting exact device's finite reset/remove interval is
/// classified BEFORE the DID-only zero-leaf participant arm, so a post-reset
/// old exact device never inherits the DID's current participation.
fn classify_current_relationship(
    user_did: &str,
    device_id: Uuid,
    state: &ConversationState,
) -> Result<ClassifiedRelationshipArm, ReadAuthorityError> {
    let facts = exact_device_interval_facts(user_did, device_id, state)?;

    if let Some(open_interval) = facts.open {
        // A later valid open interval for the exact device restores current
        // authorization; the membership interval id is the interval's opening
        // transition id (the schema CHECK constrains them equal).
        return Ok(ClassifiedRelationshipArm::OpenLeaf {
            open_membership_interval_id: interval_id(open_interval),
        });
    }
    if facts.latest_finite.is_some() {
        // Known former or post-reset-old exact device: the finite interval
        // takes precedence over same-DID current participation, and there is
        // no later open interval for this exact device.
        return Err(ReadAuthorityError::AccessOutsideMembershipInterval);
    }

    // No exact-device interval at all. A participant relationship is required
    // for state; an unrelated requester for an active or terminal conversation
    // receives NotEntitled (BREAD-04).
    let principal = PrincipalId::new(user_did.as_bytes().to_vec())
        .map_err(|_| ReadAuthorityError::Invariant)?;
    let participant = state.participant(&principal);
    let Some(participant) = participant else {
        if facts.terminal_proof_holder {
            return Err(ReadAuthorityError::AccessOutsideMembershipInterval);
        }
        return Err(ReadAuthorityError::NotEntitled);
    };

    if facts.terminal {
        // No one receives current state from a terminal conversation. An exact
        // schedule-proof holder reaches here only through a finite terminal
        // interval; a holder without one is treated as a known former
        // relationship.
        if facts.terminal_proof_holder {
            return Err(ReadAuthorityError::AccessOutsideMembershipInterval);
        }
        return Err(ReadAuthorityError::NotEntitled);
    }

    match (
        participant.is_active(),
        participant.is_pending(),
        state.kind(),
    ) {
        (true, _, _) => Ok(ClassifiedRelationshipArm::ActiveParticipant),
        (_, true, ConversationKind::Group) => {
            Ok(ClassifiedRelationshipArm::GroupPendingParticipant)
        }
        (_, true, ConversationKind::Direct) => Err(ReadAuthorityError::NotEntitled),
        _ => Err(ReadAuthorityError::NotEntitled),
    }
}

/// `AccessInterval` exposes its opening transition id as bytes; the schema
/// CHECK constrains `membership_interval_id = opening_transition_id`.
fn interval_id(interval: &AccessInterval) -> Uuid {
    Uuid::from_slice(interval.opening_transition_id())
        .expect("interval opening transition id is a canonical UUID")
}

/// The relationship witness arms. `pub(crate)` with `pub(crate)` variants so
/// C1's projection and the entitlement tests can name them; all field
/// accessors are `pub(in crate::chat_protocol)` (BREAD-08).
pub(crate) enum CurrentConversationRelationshipWitness {
    CurrentOpenLeaf {
        participant_period_id: Uuid,
        leaf_period_id: Uuid,
        open_membership_interval_id: Uuid,
    },
    CurrentActiveParticipant {
        participant_period_id: Uuid,
    },
    CurrentGroupPendingParticipant {
        participant_period_id: Uuid,
    },
}

impl CurrentConversationRelationshipWitness {
    pub(in crate::chat_protocol) fn participant_period_id(&self) -> Uuid {
        match self {
            Self::CurrentOpenLeaf {
                participant_period_id,
                ..
            }
            | Self::CurrentActiveParticipant {
                participant_period_id,
            }
            | Self::CurrentGroupPendingParticipant {
                participant_period_id,
            } => *participant_period_id,
        }
    }

    pub(in crate::chat_protocol) fn leaf_period_id(&self) -> Option<Uuid> {
        match self {
            Self::CurrentOpenLeaf { leaf_period_id, .. } => Some(*leaf_period_id),
            _ => None,
        }
    }

    pub(in crate::chat_protocol) fn open_membership_interval_id(&self) -> Option<Uuid> {
        match self {
            Self::CurrentOpenLeaf {
                open_membership_interval_id,
                ..
            } => Some(*open_membership_interval_id),
            _ => None,
        }
    }
}

/// The checked state authority for one conversation. `pub(crate)` per the
/// frozen internal interfaces; every accessor is `pub(in crate::chat_protocol)`
/// (BREAD-08).
pub(crate) struct ConversationStateReadAuthority {
    device: LockedReadDeviceAuthority,
    conversation: LockedConversationStateGuard,
    conversation_id: Uuid,
    graph_digest: [u8; 32],
    snapshot_digest: [u8; 32],
    relationship: CurrentConversationRelationshipWitness,
}

impl ConversationStateReadAuthority {
    pub(in crate::chat_protocol) fn conversation_id(&self) -> Uuid {
        self.conversation_id
    }

    pub(in crate::chat_protocol) fn graph_digest(&self) -> &[u8; 32] {
        &self.graph_digest
    }

    pub(in crate::chat_protocol) fn snapshot_digest(&self) -> &[u8; 32] {
        &self.snapshot_digest
    }

    pub(in crate::chat_protocol) fn relationship(&self) -> &CurrentConversationRelationshipWitness {
        &self.relationship
    }

    pub(in crate::chat_protocol) fn user_did(&self) -> &str {
        self.device.user_did()
    }

    pub(in crate::chat_protocol) fn device_id(&self) -> Uuid {
        self.device.device_id()
    }
}

fn map_hydration_error(error: ConversationStateHydrationError) -> ReadAuthorityError {
    match error {
        ConversationStateHydrationError::Head(
            ConversationHeadHydrationError::ConversationMissing,
        ) => ReadAuthorityError::ConversationNotFound,
        ConversationStateHydrationError::Database(_) => ReadAuthorityError::Storage,
        _ => ReadAuthorityError::Invariant,
    }
}

/// The durable participant period of the requesting DID's current-membership
/// row, loaded under the locked head.
async fn load_participant_period_id(
    tx: &mut Transaction<'_, Postgres>,
    conversation_id: Uuid,
    user_did: &str,
) -> Result<Uuid, ReadAuthorityError> {
    let period: Option<Uuid> = sqlx::query_scalar(
        "SELECT participant_period_id FROM chat.participants \
         WHERE conversation_id=$1 AND user_did=$2 AND current_membership",
    )
    .bind(conversation_id)
    .bind(user_did)
    .fetch_optional(&mut **tx)
    .await
    .map_err(|_| ReadAuthorityError::Storage)?;
    period.ok_or(ReadAuthorityError::Invariant)
}

/// The durable leaf period of the requesting exact device's active leaf,
/// loaded under the locked head.
async fn load_leaf_period_id(
    tx: &mut Transaction<'_, Postgres>,
    conversation_id: Uuid,
    user_did: &str,
    device_id: Uuid,
) -> Result<Uuid, ReadAuthorityError> {
    let period: Option<Uuid> = sqlx::query_scalar(
        "SELECT leaf_period_id FROM chat.member_devices \
         WHERE conversation_id=$1 AND user_did=$2 AND device_id=$3 AND active",
    )
    .bind(conversation_id)
    .bind(user_did)
    .bind(device_id)
    .fetch_optional(&mut **tx)
    .await
    .map_err(|_| ReadAuthorityError::Storage)?;
    period.ok_or(ReadAuthorityError::Invariant)
}

/// Lock and authorize the exact conversation state for one locked read
/// device. The same-transaction check runs BEFORE any conversation lookup, so
/// a guard minted under transaction A fails under transaction B before a
/// protected query.
pub(crate) async fn authorize_conversation_state(
    tx: &mut Transaction<'_, Postgres>,
    device: LockedReadDeviceAuthority,
    conversation_id: Uuid,
) -> Result<ConversationStateReadAuthority, ReadAuthorityError> {
    assert_same_transaction(tx, device.txid()).await?;

    let locked_at: DateTime<Utc> =
        sqlx::query_scalar("SELECT date_trunc('milliseconds', clock_timestamp())")
            .fetch_one(&mut **tx)
            .await
            .map_err(|_| ReadAuthorityError::Storage)?;
    let locked = hydrate_locked_conversation_state(tx, conversation_id, locked_at)
        .await
        .map_err(map_hydration_error)?;

    let graph_digest = *locked.locked_graph_digest();
    // The snapshot digest is required only on a GRANTABLE arm, so it is taken
    // after classification (below). Requiring it here made every terminal
    // conversation fail `Invariant` before it could be denied properly: a
    // terminal aggregate structurally carries no active snapshot, so hydration
    // returns `(None, None)` (repository/core.rs:10317) and the guard
    // constructor *requires* that pairing (core.rs:2881-2888) — absence is the
    // correct shape, not drift. The sibling authority already treats it that
    // way (`inventory_authorities`, :1815: "close tombstones carry no snapshot
    // digest").
    //
    // The effect was a denial turning into a 500: `Invariant` maps to an
    // internal error with no protocol code (:181-185), so a client reading a
    // closed conversation could not tell "closed" from "server broken" instead
    // of receiving the typed `AccessOutsideMembershipInterval` / `NotEntitled`.
    let arm = classify_current_relationship(device.user_did(), device.device_id(), locked.state())?;
    let participant_period_id =
        load_participant_period_id(tx, conversation_id, device.user_did()).await?;
    let relationship = match arm {
        ClassifiedRelationshipArm::OpenLeaf {
            open_membership_interval_id,
        } => {
            let leaf_period_id =
                load_leaf_period_id(tx, conversation_id, device.user_did(), device.device_id())
                    .await?;
            CurrentConversationRelationshipWitness::CurrentOpenLeaf {
                participant_period_id,
                leaf_period_id,
                open_membership_interval_id,
            }
        }
        ClassifiedRelationshipArm::ActiveParticipant => {
            CurrentConversationRelationshipWitness::CurrentActiveParticipant {
                participant_period_id,
            }
        }
        ClassifiedRelationshipArm::GroupPendingParticipant => {
            CurrentConversationRelationshipWitness::CurrentGroupPendingParticipant {
                participant_period_id,
            }
        }
    };

    // Every arm that reaches here is grantable, so the digest must be present.
    // `ActiveParticipant` and `GroupPendingParticipant` are reachable only past
    // the `facts.terminal` guard (:605), and `facts.terminal` is
    // `state.active_public_state().is_none()` (:545) — the same predicate the
    // guard constructor pairs the digest with. `OpenLeaf` cannot reach a
    // terminal conversation either: `load_leaf_period_id` (:757-774) already
    // rejected it, because hydration proved `active_leaf_count == 0` under the
    // same lock (core.rs:10341-10350).
    let snapshot_digest = *locked
        .locked_snapshot_digest()
        .ok_or(ReadAuthorityError::Invariant)?;

    Ok(ConversationStateReadAuthority {
        device,
        conversation: locked,
        conversation_id,
        graph_digest,
        snapshot_digest,
        relationship,
    })
}

/// A closed interval terminal witness. `pub(crate)` per the frozen internal
/// interfaces; every accessor is `pub(in crate::chat_protocol)` (BREAD-08).
pub(crate) enum EntryIntervalTerminalWitness {
    Open {
        observed_head_seq: u64,
        row_sha256: [u8; 32],
    },
    Closed {
        terminal_seq: u64,
        closing_transition_id: Uuid,
        closing_outer_entry_fingerprint: [u8; 32],
        closing_kind: String,
        row_sha256: [u8; 32],
    },
}

impl EntryIntervalTerminalWitness {
    pub(in crate::chat_protocol) fn is_open(&self) -> bool {
        matches!(self, Self::Open { .. })
    }

    pub(in crate::chat_protocol) fn terminal_seq(&self) -> Option<u64> {
        match self {
            Self::Open { .. } => None,
            Self::Closed { terminal_seq, .. } => Some(*terminal_seq),
        }
    }

    pub(in crate::chat_protocol) fn row_sha256(&self) -> &[u8; 32] {
        match self {
            Self::Open { row_sha256, .. } | Self::Closed { row_sha256, .. } => row_sha256,
        }
    }
}

/// One exact-device application interval witness. `pub(crate)` per the frozen
/// internal interfaces; every accessor is `pub(in crate::chat_protocol)`
/// (BREAD-08).
pub(crate) struct EntryIntervalWitness {
    membership_interval_id: Uuid,
    conversation_id: Uuid,
    recipient_did: String,
    recipient_device_id: Uuid,
    start_seq: u64,
    opening_transition_id: Uuid,
    opening_outer_entry_fingerprint: [u8; 32],
    terminal: EntryIntervalTerminalWitness,
}

impl EntryIntervalWitness {
    pub(in crate::chat_protocol) fn membership_interval_id(&self) -> Uuid {
        self.membership_interval_id
    }

    pub(in crate::chat_protocol) fn conversation_id(&self) -> Uuid {
        self.conversation_id
    }

    pub(in crate::chat_protocol) fn recipient_did(&self) -> &str {
        &self.recipient_did
    }

    pub(in crate::chat_protocol) fn recipient_device_id(&self) -> Uuid {
        self.recipient_device_id
    }

    pub(in crate::chat_protocol) fn start_seq(&self) -> u64 {
        self.start_seq
    }

    pub(in crate::chat_protocol) fn opening_transition_id(&self) -> Uuid {
        self.opening_transition_id
    }

    pub(in crate::chat_protocol) fn opening_outer_entry_fingerprint(&self) -> &[u8; 32] {
        &self.opening_outer_entry_fingerprint
    }

    pub(in crate::chat_protocol) fn terminal(&self) -> &EntryIntervalTerminalWitness {
        &self.terminal
    }
}

/// The exact control-recipient set bound at the same locked head/fence.
/// `pub(crate)` per the frozen internal interfaces; accessors are
/// `pub(in crate::chat_protocol)` (BREAD-08).
pub(crate) struct ControlRecipientFenceWitness {
    maximum_event_position: u64,
    maximum_entry_seq: u64,
    ordered_recipient_rows_sha256: [u8; 32],
}

impl ControlRecipientFenceWitness {
    pub(in crate::chat_protocol) fn maximum_event_position(&self) -> u64 {
        self.maximum_event_position
    }

    pub(in crate::chat_protocol) fn maximum_entry_seq(&self) -> u64 {
        self.maximum_entry_seq
    }

    pub(in crate::chat_protocol) fn ordered_recipient_rows_sha256(&self) -> &[u8; 32] {
        &self.ordered_recipient_rows_sha256
    }
}

/// The checked entry authority. `pub(crate)` per the frozen internal
/// interfaces; accessors are `pub(in crate::chat_protocol)` (BREAD-08).
pub(crate) struct EntryReadAuthority {
    conversation: ConversationStateReadAuthority,
    ordered_intervals: Box<[EntryIntervalWitness]>,
    ordered_intervals_sha256: [u8; 32],
    control_recipient_fence: ControlRecipientFenceWitness,
}

impl EntryReadAuthority {
    pub(in crate::chat_protocol) fn conversation(&self) -> &ConversationStateReadAuthority {
        &self.conversation
    }

    pub(in crate::chat_protocol) fn ordered_intervals(&self) -> &[EntryIntervalWitness] {
        &self.ordered_intervals
    }

    pub(in crate::chat_protocol) fn ordered_intervals_sha256(&self) -> &[u8; 32] {
        &self.ordered_intervals_sha256
    }

    pub(in crate::chat_protocol) fn control_recipient_fence(
        &self,
    ) -> &ControlRecipientFenceWitness {
        &self.control_recipient_fence
    }
}

/// The exact-device interval rows, in the deterministic
/// `(start_seq, membership_interval_id)` order the frozen interface requires.
#[derive(FromRow)]
struct ExactDeviceIntervalRow {
    membership_interval_id: Uuid,
    conversation_id: Uuid,
    generation: i64,
    recipient_did: String,
    recipient_device_id: Uuid,
    start_seq: i64,
    opening_transition_id: Uuid,
    opening_outer_entry_fingerprint: Vec<u8>,
    // Read only to mirror the schedule trigger's touching-boundary rule below.
    // Deliberately absent from `interval_row_binding_digest`: the frozen witness
    // bytes must not change, and `generation` already separates a reset touch.
    opening_kind: String,
    terminal_seq: Option<i64>,
    closing_transition_id: Option<Uuid>,
    closing_outer_entry_fingerprint: Option<Vec<u8>>,
    closing_kind: Option<String>,
}

async fn load_exact_device_interval_rows(
    tx: &mut Transaction<'_, Postgres>,
    conversation_id: Uuid,
    user_did: &str,
    device_id: Uuid,
) -> Result<Vec<ExactDeviceIntervalRow>, ReadAuthorityError> {
    let rows: Vec<ExactDeviceIntervalRow> = sqlx::query_as(
        r#"
        SELECT ai.membership_interval_id,
               ai.conversation_id,
               ai.generation,
               ai.recipient_did,
               ai.recipient_device_id,
               ai.start_seq,
               ai.opening_transition_id,
               ai.opening_outer_entry_fingerprint,
               ai.opening_kind,
               ai.terminal_seq,
               ai.closing_transition_id,
               ai.closing_outer_entry_fingerprint,
               ai.closing_kind
          FROM chat.application_intervals ai
         WHERE ai.conversation_id = $1
           AND ai.recipient_did = $2
           AND ai.recipient_device_id = $3
         ORDER BY ai.start_seq, ai.membership_interval_id
        "#,
    )
    .bind(conversation_id)
    .bind(user_did)
    .bind(device_id)
    .fetch_all(&mut **tx)
    .await
    .map_err(|_| ReadAuthorityError::Storage)?;
    Ok(rows)
}

/// Domain-separated row binding digest over one exact-device interval row's
/// evidence columns. The generation is committed here so intervals are
/// generation-bound even though the frozen witness shape carries no generation
/// field.
fn interval_row_binding_digest(
    row: &ExactDeviceIntervalRow,
) -> Result<[u8; 32], ReadAuthorityError> {
    let opening_fingerprint: [u8; 32] = row
        .opening_outer_entry_fingerprint
        .as_slice()
        .try_into()
        .map_err(|_| ReadAuthorityError::Invariant)?;
    let mut digest = Sha256::new();
    digest.update(b"CATBIRD-CHAT-ENTRY-INTERVAL-ROW\0");
    digest.update(row.membership_interval_id.as_bytes());
    digest.update(row.conversation_id.as_bytes());
    digest.update(row.generation.to_be_bytes());
    digest.update((row.recipient_did.len() as u64).to_be_bytes());
    digest.update(row.recipient_did.as_bytes());
    digest.update(row.recipient_device_id.as_bytes());
    digest.update(row.start_seq.to_be_bytes());
    digest.update(row.opening_transition_id.as_bytes());
    digest.update(&opening_fingerprint);
    match (
        &row.terminal_seq,
        &row.closing_transition_id,
        &row.closing_outer_entry_fingerprint,
        &row.closing_kind,
    ) {
        (None, None, None, None) => digest.update([0]),
        (
            Some(terminal_seq),
            Some(closing_transition_id),
            Some(closing_fingerprint),
            Some(closing_kind),
        ) => {
            digest.update([1]);
            digest.update(terminal_seq.to_be_bytes());
            digest.update(closing_transition_id.as_bytes());
            let closing_fingerprint: [u8; 32] = closing_fingerprint
                .as_slice()
                .try_into()
                .map_err(|_| ReadAuthorityError::Invariant)?;
            digest.update(&closing_fingerprint);
            digest.update((closing_kind.len() as u64).to_be_bytes());
            digest.update(closing_kind.as_bytes());
        }
        _ => return Err(ReadAuthorityError::Invariant),
    }
    Ok(digest.finalize().into())
}

/// Build the ordered, validated interval witnesses for one exact device.
///
/// The rows arrive in deterministic `(start_seq, membership_interval_id)`
/// order. The validator rejects overlaps, rejects an open interval that is
/// not last, and requires the open/closed shape and terminal provenance for
/// every row. A closed terminal sequence is inclusive; gaps between a
/// terminal sequence and a later opening remain invisible (no backfill).
///
/// An opening AT the previous terminal sequence is a touching boundary, not an
/// overlap: `chat.assert_application_interval_schedule` mandates it for
/// replace->add and reset->reset. It is accepted only with the same boundary
/// evidence the trigger requires, so the reader is exactly as strict as the
/// writer.
fn build_ordered_interval_witnesses(
    rows: Vec<ExactDeviceIntervalRow>,
    observed_head_seq: u64,
) -> Result<Box<[EntryIntervalWitness]>, ReadAuthorityError> {
    let mut witnesses: Vec<EntryIntervalWitness> = Vec::with_capacity(rows.len());
    let row_count = rows.len();
    for (index, row) in rows.into_iter().enumerate() {
        let row_sha256 = interval_row_binding_digest(&row)?;
        let start_seq = u64::try_from(row.start_seq).map_err(|_| ReadAuthorityError::Invariant)?;
        let opening_fingerprint: [u8; 32] = row
            .opening_outer_entry_fingerprint
            .as_slice()
            .try_into()
            .map_err(|_| ReadAuthorityError::Invariant)?;
        let terminal = match (
            row.terminal_seq,
            row.closing_transition_id,
            row.closing_outer_entry_fingerprint,
            row.closing_kind,
        ) {
            (None, None, None, None) => {
                if index + 1 != row_count {
                    // An open interval must be last: a later row would overlap
                    // or follow an open interval.
                    return Err(ReadAuthorityError::Invariant);
                }
                EntryIntervalTerminalWitness::Open {
                    observed_head_seq,
                    row_sha256,
                }
            }
            (
                Some(terminal_seq),
                Some(closing_transition_id),
                Some(closing_fingerprint),
                Some(closing_kind),
            ) => {
                let terminal_seq =
                    u64::try_from(terminal_seq).map_err(|_| ReadAuthorityError::Invariant)?;
                if terminal_seq <= start_seq {
                    return Err(ReadAuthorityError::Invariant);
                }
                let closing_fingerprint: [u8; 32] = closing_fingerprint
                    .as_slice()
                    .try_into()
                    .map_err(|_| ReadAuthorityError::Invariant)?;
                EntryIntervalTerminalWitness::Closed {
                    terminal_seq,
                    closing_transition_id,
                    closing_outer_entry_fingerprint: closing_fingerprint,
                    closing_kind,
                    row_sha256,
                }
            }
            _ => return Err(ReadAuthorityError::Invariant),
        };
        if let Some(previous) = witnesses.last() {
            if previous.start_seq >= start_seq {
                return Err(ReadAuthorityError::Invariant);
            }
            match &previous.terminal {
                EntryIntervalTerminalWitness::Closed {
                    terminal_seq,
                    closing_transition_id,
                    closing_outer_entry_fingerprint,
                    closing_kind,
                    ..
                } => {
                    if start_seq < *terminal_seq {
                        return Err(ReadAuthorityError::Invariant);
                    }
                    if start_seq == *terminal_seq {
                        // Not an overlap. `chat.assert_application_interval_schedule`
                        // treats only `terminal_seq > start_seq` as overlapping, and
                        // for replace->add and reset->reset it REQUIRES this touching
                        // boundary -- a non-touching successor is itself rejected, so
                        // every reset activator and every leaf-recovery-replaced
                        // device has one. Mirror the trigger's own predicate exactly.
                        // Nothing widens: the entry at the shared sequence is already
                        // visible through the closed interval's inclusive terminal.
                        let kinds_pair = matches!(
                            (closing_kind.as_str(), row.opening_kind.as_str()),
                            ("replace", "add") | ("reset", "reset")
                        );
                        if !kinds_pair
                            || *closing_transition_id != row.opening_transition_id
                            || *closing_outer_entry_fingerprint != opening_fingerprint
                        {
                            return Err(ReadAuthorityError::Invariant);
                        }
                    }
                }
                EntryIntervalTerminalWitness::Open { .. } => {
                    // A previous open interval means a duplicate tail; unreachable
                    // after the open-must-be-last check above, kept as defence in
                    // depth.
                    return Err(ReadAuthorityError::Invariant);
                }
            }
        }
        witnesses.push(EntryIntervalWitness {
            membership_interval_id: row.membership_interval_id,
            conversation_id: row.conversation_id,
            recipient_did: row.recipient_did,
            recipient_device_id: row.recipient_device_id,
            start_seq,
            opening_transition_id: row.opening_transition_id,
            opening_outer_entry_fingerprint: opening_fingerprint,
            terminal,
        });
    }
    Ok(witnesses.into_boxed_slice())
}

/// Derive the ordered digest over the interval witnesses under the same
/// transaction: SHA-256 over each witness's start sequence and row binding
/// digest in order.
fn ordered_intervals_digest(witnesses: &[EntryIntervalWitness]) -> [u8; 32] {
    let mut digest = Sha256::new();
    digest.update(b"CATBIRD-CHAT-ORDERED-ENTRY-INTERVALS\0");
    for witness in witnesses {
        digest.update(witness.start_seq.to_be_bytes());
        digest.update(witness.terminal.row_sha256());
    }
    digest.finalize().into()
}

/// Bind the exact control-recipient set at the same locked head: the maximum
/// observed entry sequence, the protocol-wide maximum event position, and the
/// ordered control-recipient row digest.
async fn load_control_recipient_fence(
    tx: &mut Transaction<'_, Postgres>,
    conversation_id: Uuid,
) -> Result<ControlRecipientFenceWitness, ReadAuthorityError> {
    let maximum_entry_seq: i64 = sqlx::query_scalar(
        "SELECT coalesce(max(seq),0)::bigint FROM chat.entries WHERE conversation_id=$1",
    )
    .bind(conversation_id)
    .fetch_one(&mut **tx)
    .await
    .map_err(|_| ReadAuthorityError::Storage)?;
    let maximum_event_position: i64 =
        sqlx::query_scalar("SELECT coalesce(max(event_position),0)::bigint FROM chat.events")
            .fetch_one(&mut **tx)
            .await
            .map_err(|_| ReadAuthorityError::Storage)?;
    let recipients: Vec<(i64, String, Uuid)> = sqlx::query_as(
        r#"
        SELECT seq, user_did, device_id
          FROM chat.entry_recipients
         WHERE conversation_id = $1 AND entitlement_kind = 'control'
         ORDER BY seq, user_did, device_id
        "#,
    )
    .bind(conversation_id)
    .fetch_all(&mut **tx)
    .await
    .map_err(|_| ReadAuthorityError::Storage)?;
    let mut digest = Sha256::new();
    digest.update(b"CATBIRD-CHAT-CONTROL-RECIPIENT-ROWS\0");
    for (seq, user_did, device_id) in &recipients {
        digest.update(seq.to_be_bytes());
        digest.update((user_did.len() as u64).to_be_bytes());
        digest.update(user_did.as_bytes());
        digest.update(device_id.as_bytes());
    }
    Ok(ControlRecipientFenceWitness {
        maximum_event_position: u64::try_from(maximum_event_position)
            .map_err(|_| ReadAuthorityError::Invariant)?,
        maximum_entry_seq: u64::try_from(maximum_entry_seq)
            .map_err(|_| ReadAuthorityError::Invariant)?,
        ordered_recipient_rows_sha256: digest.finalize().into(),
    })
}

/// Authorize exact application entries and the control-recipient fence for
/// one locked read device. Succeeds only for a `CurrentOpenLeaf` relationship;
/// a former-only, terminal-only, or post-reset-old device returns
/// `AccessOutsideMembershipInterval`, and a state-only witness (zero-leaf
/// participant, group-pending) returns `NotEntitled`.
pub(crate) async fn authorize_entries(
    tx: &mut Transaction<'_, Postgres>,
    device: LockedReadDeviceAuthority,
    conversation_id: Uuid,
) -> Result<EntryReadAuthority, ReadAuthorityError> {
    let state = authorize_conversation_state(tx, device, conversation_id).await?;
    if !matches!(
        state.relationship(),
        CurrentConversationRelationshipWitness::CurrentOpenLeaf { .. }
    ) {
        return Err(ReadAuthorityError::NotEntitled);
    }

    let rows =
        load_exact_device_interval_rows(tx, conversation_id, state.user_did(), state.device_id())
            .await?;
    let observed_head_seq: i64 = sqlx::query_scalar(
        "SELECT coalesce(max(seq),0)::bigint FROM chat.entries WHERE conversation_id=$1",
    )
    .bind(conversation_id)
    .fetch_one(&mut **tx)
    .await
    .map_err(|_| ReadAuthorityError::Storage)?;
    let ordered_intervals = build_ordered_interval_witnesses(
        rows,
        u64::try_from(observed_head_seq).map_err(|_| ReadAuthorityError::Invariant)?,
    )?;
    let ordered_intervals_sha256 = ordered_intervals_digest(&ordered_intervals);
    let control_recipient_fence = load_control_recipient_fence(tx, conversation_id).await?;

    Ok(EntryReadAuthority {
        conversation: state,
        ordered_intervals,
        ordered_intervals_sha256,
        control_recipient_fence,
    })
}

// ---------------------------------------------------------------------------
// Inventory fence and authorities
// ---------------------------------------------------------------------------

/// The durable fence material D's `SELECT ... FOR UPDATE` loader will return.
/// Private-field and constructible only through the validating lock-material
/// seam; a bare digest or caller-assembled coordinate bundle is never proof.
pub(in crate::chat_protocol) struct LockedInventoryFenceRecord {
    protocol_instance_id: Uuid,
    cursor_key_id: String,
    event_position: u64,
    event_cursor_sha256: [u8; 32],
    retained_floor: u64,
    captured_at: DateTime<Utc>,
}

impl LockedInventoryFenceRecord {
    /// The validating constructor from the durable row material. It is the
    /// seam D's loader will call; until D lands it has zero production callers
    /// and is exercised only by the entitlement tests. A nil protocol
    /// instance, empty key, zero cursor digest, or an event position below
    /// the retained floor is rejected here.
    pub(in crate::chat_protocol) fn from_lock_material(
        protocol_instance_id: Uuid,
        cursor_key_id: String,
        event_position: u64,
        event_cursor_sha256: [u8; 32],
        retained_floor: u64,
        captured_at: DateTime<Utc>,
    ) -> Result<Self, ReadAuthorityError> {
        if protocol_instance_id.is_nil()
            || cursor_key_id.is_empty()
            || event_cursor_sha256 == [0_u8; 32]
            || retained_floor > event_position
        {
            return Err(ReadAuthorityError::Invariant);
        }
        Ok(Self {
            protocol_instance_id,
            cursor_key_id,
            event_position,
            event_cursor_sha256,
            retained_floor,
            captured_at,
        })
    }
}

/// The durable fence row: nonconstructible outside the sole
/// `from_locked_inventory_fence_record` constructor. Private-field.
pub(in crate::chat_protocol) struct LockedDurableInventoryFenceRow {
    protocol_instance_id: Uuid,
    cursor_key_id: String,
    event_position: u64,
    event_cursor_sha256: [u8; 32],
    retained_floor: u64,
    captured_at: DateTime<Utc>,
}

/// The sole constructor of the durable fence row. Zero production callers
/// until D's loader lands at ordinal 35; the entitlement test's source guards
/// prove it.
pub(in crate::chat_protocol) fn from_locked_inventory_fence_record(
    record: LockedInventoryFenceRecord,
) -> LockedDurableInventoryFenceRow {
    LockedDurableInventoryFenceRow {
        protocol_instance_id: record.protocol_instance_id,
        cursor_key_id: record.cursor_key_id,
        event_position: record.event_position,
        event_cursor_sha256: record.event_cursor_sha256,
        retained_floor: record.retained_floor,
        captured_at: record.captured_at,
    }
}

/// The only fence value accepted by `inventory_authorities`. Minted only by
/// `verify_inventory_fence`, which consumes both the locked device and the
/// durable row. Private-field.
pub(crate) struct VerifiedInventoryFence {
    txid: i64,
    user_did: String,
    device_id: Uuid,
    device_binding_sha256: [u8; 32],
    protocol_instance_id: Uuid,
    cursor_key_id: String,
    event_position: u64,
    event_cursor_sha256: [u8; 32],
    retained_floor: u64,
    captured_at: DateTime<Utc>,
}

impl VerifiedInventoryFence {
    /// Checker, not a getter: the same-transaction identity never leaves the
    /// type.
    pub(in crate::chat_protocol) fn verify_same_transaction(
        &self,
        txid: i64,
    ) -> Result<(), ReadAuthorityError> {
        if self.txid == txid {
            Ok(())
        } else {
            Err(ReadAuthorityError::Invariant)
        }
    }
}

/// The session's snapshot fence witness bound into every inventory authority.
/// `pub(crate)` per the frozen internal interfaces; accessors are
/// `pub(in crate::chat_protocol)` (BREAD-08).
pub(crate) struct InventoryFenceWitness {
    protocol_instance_id: Uuid,
    cursor_key_id: String,
    event_position: u64,
    event_cursor_sha256: [u8; 32],
    retained_floor: u64,
    captured_at: DateTime<Utc>,
}

impl InventoryFenceWitness {
    pub(in crate::chat_protocol) fn protocol_instance_id(&self) -> Uuid {
        self.protocol_instance_id
    }

    pub(in crate::chat_protocol) fn cursor_key_id(&self) -> &str {
        &self.cursor_key_id
    }

    pub(in crate::chat_protocol) fn event_position(&self) -> u64 {
        self.event_position
    }

    pub(in crate::chat_protocol) fn event_cursor_sha256(&self) -> &[u8; 32] {
        &self.event_cursor_sha256
    }

    pub(in crate::chat_protocol) fn retained_floor(&self) -> u64 {
        self.retained_floor
    }

    pub(in crate::chat_protocol) fn captured_at(&self) -> DateTime<Utc> {
        self.captured_at
    }
}

/// Consume the locked device and the durable fence row, verify they were
/// obtained under the same `txid_current()`, verify the live protocol
/// instance, active cursor key, retention floor, and temporal bounds, and
/// mint the only fence accepted by `inventory_authorities`.
///
/// The inventory-session and event-cursor-receipt coordinates are D's loader
/// contract: the record itself is D's `SELECT ... FOR UPDATE` result, and the
/// session-level binding is revalidated by the final
/// protocol/key/head/floor re-read inside `inventory_authorities`.
pub(in crate::chat_protocol) async fn verify_inventory_fence(
    tx: &mut Transaction<'_, Postgres>,
    device: LockedReadDeviceAuthority,
    row: LockedDurableInventoryFenceRow,
) -> Result<VerifiedInventoryFence, ReadAuthorityError> {
    assert_same_transaction(tx, device.txid()).await?;

    // The live protocol instance owns the active cursor key; a record built
    // against a foreign instance or a drifted key fails before any head.
    let live: Option<(Uuid, String)> = sqlx::query_as(
        "SELECT protocol_instance_id, cursor_key_id FROM chat.protocol_instances \
         WHERE protocol_instance_id=$1",
    )
    .bind(row.protocol_instance_id)
    .fetch_optional(&mut **tx)
    .await
    .map_err(|_| ReadAuthorityError::Storage)?;
    let Some((_, live_cursor_key)) = live else {
        return Err(ReadAuthorityError::Invariant);
    };
    if live_cursor_key != row.cursor_key_id {
        return Err(ReadAuthorityError::Invariant);
    }

    // The retention floor must never sit above the snapshot event position.
    let live_floor: Option<i64> = sqlx::query_scalar(
        "SELECT retained_floor FROM chat.event_retention WHERE protocol_instance_id=$1",
    )
    .bind(row.protocol_instance_id)
    .fetch_optional(&mut **tx)
    .await
    .map_err(|_| ReadAuthorityError::Storage)?;
    if let Some(floor) = live_floor {
        if u64::try_from(floor).map_err(|_| ReadAuthorityError::Invariant)? > row.event_position {
            return Err(ReadAuthorityError::Invariant);
        }
    }

    // Temporal bounds: the fence was captured now or in the recent past, and
    // never in the future or beyond the schema's session expiry horizon.
    let now = Utc::now();
    if row.captured_at > now + chrono::Duration::seconds(5)
        || now.signed_duration_since(row.captured_at) > chrono::Duration::minutes(15)
    {
        return Err(ReadAuthorityError::Invariant);
    }
    Ok(VerifiedInventoryFence {
        txid: device.txid(),
        user_did: device.user_did().to_owned(),
        device_id: device.device_id(),
        device_binding_sha256: *device.device_row_sha256(),
        protocol_instance_id: row.protocol_instance_id,
        cursor_key_id: row.cursor_key_id,
        event_position: row.event_position,
        event_cursor_sha256: row.event_cursor_sha256,
        retained_floor: row.retained_floor,
        captured_at: row.captured_at,
    })
}

/// One per-conversation inventory authority. `pub(crate)` per the frozen
/// internal interfaces; accessors are `pub(in crate::chat_protocol)`
/// (BREAD-08).
pub(crate) struct ConversationInventoryAuthority {
    txid: i64,
    device_binding_sha256: [u8; 32],
    conversation_id: Uuid,
    graph_digest: [u8; 32],
    snapshot_digest: [u8; 32],
    fence: InventoryFenceWitness,
    arm: ConversationInventoryArm,
}

impl ConversationInventoryAuthority {
    pub(in crate::chat_protocol) fn txid(&self) -> i64 {
        self.txid
    }

    pub(in crate::chat_protocol) fn device_binding_sha256(&self) -> &[u8; 32] {
        &self.device_binding_sha256
    }

    pub(in crate::chat_protocol) fn conversation_id(&self) -> Uuid {
        self.conversation_id
    }

    pub(in crate::chat_protocol) fn graph_digest(&self) -> &[u8; 32] {
        &self.graph_digest
    }

    pub(in crate::chat_protocol) fn snapshot_digest(&self) -> &[u8; 32] {
        &self.snapshot_digest
    }

    pub(in crate::chat_protocol) fn fence(&self) -> &InventoryFenceWitness {
        &self.fence
    }

    pub(in crate::chat_protocol) fn arm(&self) -> &ConversationInventoryArm {
        &self.arm
    }
}

/// The selected inventory arm. `pub(crate)` per the frozen internal
/// interfaces; accessors are `pub(in crate::chat_protocol)` (BREAD-08).
pub(crate) enum ConversationInventoryArm {
    State {
        participant_period_id: Uuid,
    },
    Removal {
        membership_interval_id: Uuid,
        terminal_seq: u64,
        closing_transition_id: Uuid,
        closing_outer_entry_fingerprint: Vec<u8>,
        removed_at: DateTime<Utc>,
    },
    Close {
        terminal_seq: u64,
        closing_transition_id: Uuid,
        closing_outer_entry_fingerprint: Vec<u8>,
    },
}

impl ConversationInventoryArm {
    pub(in crate::chat_protocol) fn participant_period_id(&self) -> Option<Uuid> {
        match self {
            Self::State {
                participant_period_id,
            } => Some(*participant_period_id),
            _ => None,
        }
    }

    pub(in crate::chat_protocol) fn membership_interval_id(&self) -> Option<Uuid> {
        match self {
            Self::Removal {
                membership_interval_id,
                ..
            } => Some(*membership_interval_id),
            _ => None,
        }
    }

    pub(in crate::chat_protocol) fn terminal_seq(&self) -> u64 {
        match self {
            Self::Removal { terminal_seq, .. } | Self::Close { terminal_seq, .. } => *terminal_seq,
            Self::State { .. } => 0,
        }
    }
}

/// A private arm decision for one locked head; the durable IDs (participant
/// period, removed-at instant) are loaded under the same head afterwards.
enum InventoryArmDecision {
    Close {
        terminal_seq: u64,
        closing_transition_id: Uuid,
        closing_outer_entry_fingerprint: Vec<u8>,
    },
    Removal {
        membership_interval_id: Uuid,
        terminal_seq: u64,
        closing_transition_id: Uuid,
        closing_outer_entry_fingerprint: Vec<u8>,
    },
    State,
    None,
}

fn interval_end_transition(end: &AccessIntervalEnd) -> Uuid {
    Uuid::from_slice(end.transition_id()).expect("closing transition id is a canonical UUID")
}

fn interval_end_fingerprint(end: &AccessIntervalEnd) -> &[u8; 32] {
    end.outer_entry_fingerprint()
}

/// The exact inventory arm precedence for one locked conversation head:
/// close proof -> exact open interval -> exact finite interval -> eligible
/// participant -> none.
fn classify_inventory_arm(
    user_did: &str,
    device_id: Uuid,
    state: &ConversationState,
) -> Result<InventoryArmDecision, ReadAuthorityError> {
    let facts = exact_device_interval_facts(user_did, device_id, state)?;

    // 1. Terminal conversation plus exact complete schedule proof: close.
    if facts.terminal {
        if facts.terminal_proof_holder {
            let interval = facts
                .latest_finite
                .or(facts.open)
                .ok_or(ReadAuthorityError::Invariant)?;
            let end = interval.end().ok_or(ReadAuthorityError::Invariant)?;
            return Ok(InventoryArmDecision::Close {
                terminal_seq: end.seq(),
                closing_transition_id: interval_end_transition(end),
                closing_outer_entry_fingerprint: interval_end_fingerprint(end).to_vec(),
            });
        }
        return Ok(InventoryArmDecision::None);
    }

    // 2. Active conversation plus exact open membership interval: state.
    if facts.open.is_some() {
        return Ok(InventoryArmDecision::State);
    }

    // 3. Active conversation plus latest exact finite interval and no later
    //    open interval: removal tombstone.
    if let Some(finite) = facts.latest_finite {
        let end = finite.end().ok_or(ReadAuthorityError::Invariant)?;
        return Ok(InventoryArmDecision::Removal {
            membership_interval_id: interval_id(finite),
            terminal_seq: end.seq(),
            closing_transition_id: interval_end_transition(end),
            closing_outer_entry_fingerprint: interval_end_fingerprint(end).to_vec(),
        });
    }

    // 4. Active conversation plus eligible current participant: state.
    let principal = PrincipalId::new(user_did.as_bytes().to_vec())
        .map_err(|_| ReadAuthorityError::Invariant)?;
    let participant = state.participant(&principal);
    let Some(participant) = participant else {
        return Ok(InventoryArmDecision::None);
    };
    if participant.is_active() {
        return Ok(InventoryArmDecision::State);
    }
    if participant.is_pending() && state.kind() == ConversationKind::Group {
        return Ok(InventoryArmDecision::State);
    }
    // Direct-pending and unknown statuses yield no item.
    Ok(InventoryArmDecision::None)
}

/// The durable `removed_at` of the exact-device interval that closed the
/// removal, loaded under the locked head. An absent row after a hydrated
/// closed interval is an invariant.
async fn interval_removed_at(
    tx: &mut Transaction<'_, Postgres>,
    membership_interval_id: Uuid,
) -> Result<DateTime<Utc>, ReadAuthorityError> {
    let removed_at: Option<DateTime<Utc>> = sqlx::query_scalar(
        "SELECT removed_at FROM chat.application_intervals WHERE membership_interval_id=$1",
    )
    .bind(membership_interval_id)
    .fetch_optional(&mut **tx)
    .await
    .map_err(|_| ReadAuthorityError::Storage)?;
    removed_at.ok_or(ReadAuthorityError::Invariant)
}

/// Lock-free candidate discovery: every conversation the requesting device
/// has ANY relationship to (current participant, exact-device interval, or
/// exact schedule proof). Runs BEFORE the first conversation head.
async fn discover_inventory_candidates(
    tx: &mut Transaction<'_, Postgres>,
    user_did: &str,
    device_id: Uuid,
) -> Result<Vec<Uuid>, ReadAuthorityError> {
    let mut candidates: Vec<Uuid> = sqlx::query_scalar(
        r#"
        SELECT DISTINCT conversation_id FROM chat.participants
         WHERE user_did = $1 AND current_membership
        UNION
        SELECT DISTINCT conversation_id FROM chat.application_intervals
         WHERE recipient_did = $1 AND recipient_device_id = $2
        UNION
        SELECT DISTINCT conversation_id FROM chat.application_schedule_terminal_proofs
         WHERE recipient_did = $1 AND recipient_device_id = $2
        "#,
    )
    .bind(user_did)
    .bind(device_id)
    .fetch_all(&mut **tx)
    .await
    .map_err(|_| ReadAuthorityError::Storage)?;
    candidates.sort_unstable();
    Ok(candidates)
}

/// The final protocol/key/head/floor revalidation after all conversation
/// heads. The `FOR UPDATE` re-read of the protocol instance is the
/// deterministic barrier that makes concurrent key drift fail closed: a
/// writer holding an uncommitted change to the row blocks this statement
/// until it commits, and the committed drift is then observed and refused.
async fn revalidate_fence_after_heads(
    tx: &mut Transaction<'_, Postgres>,
    fence: &VerifiedInventoryFence,
) -> Result<(), ReadAuthorityError> {
    // Protocol instance and active cursor key, re-read FOR UPDATE.
    let live: Option<(Uuid, String)> = sqlx::query_as(
        "SELECT protocol_instance_id, cursor_key_id FROM chat.protocol_instances \
         WHERE protocol_instance_id=$1 FOR UPDATE",
    )
    .bind(fence.protocol_instance_id)
    .fetch_optional(&mut **tx)
    .await
    .map_err(|_| ReadAuthorityError::Storage)?;
    let Some((_, live_cursor_key)) = live else {
        return Err(ReadAuthorityError::Invariant);
    };
    if live_cursor_key != fence.cursor_key_id {
        return Err(ReadAuthorityError::Invariant);
    }

    // Retention floor, re-read FOR UPDATE: the live floor must never sit
    // above the fence's snapshot event position.
    let live_floor: Option<i64> = sqlx::query_scalar(
        "SELECT retained_floor FROM chat.event_retention \
         WHERE protocol_instance_id=$1 FOR UPDATE",
    )
    .bind(fence.protocol_instance_id)
    .fetch_optional(&mut **tx)
    .await
    .map_err(|_| ReadAuthorityError::Storage)?;
    if let Some(floor) = live_floor {
        if u64::try_from(floor).map_err(|_| ReadAuthorityError::Invariant)? > fence.event_position {
            return Err(ReadAuthorityError::Invariant);
        }
    }

    // Head/event-stream drift: the fence's snapshot event position can never
    // sit beyond the protocol's current maximum event position (events are
    // append-only), so a fence that claims a later position is spliced.
    let maximum_event_position: i64 =
        sqlx::query_scalar("SELECT coalesce(max(event_position),0)::bigint FROM chat.events")
            .fetch_one(&mut **tx)
            .await
            .map_err(|_| ReadAuthorityError::Storage)?;
    if fence.event_position
        > u64::try_from(maximum_event_position).map_err(|_| ReadAuthorityError::Invariant)?
    {
        return Err(ReadAuthorityError::Invariant);
    }

    // The device lock and the fence remain the same transaction.
    let current: i64 = sqlx::query_scalar("SELECT txid_current()::bigint")
        .fetch_one(&mut **tx)
        .await
        .map_err(|_| ReadAuthorityError::Storage)?;
    fence.verify_same_transaction(current)
}

/// The inventory authorities for one verified fence. Candidate conversations
/// are discovered lock-free, then conversation heads are locked in ascending
/// UUID byte order, arms are selected per head, and the protocol/key/head/
/// floor material is finally revalidated against the fence — any drift fails
/// the whole attempt.
pub(crate) async fn inventory_authorities(
    tx: &mut Transaction<'_, Postgres>,
    fence: VerifiedInventoryFence,
) -> Result<Box<[ConversationInventoryAuthority]>, ReadAuthorityError> {
    assert_same_transaction(tx, fence.txid).await?;

    // Lock-free candidate discovery before the first conversation head.
    let candidates = discover_inventory_candidates(tx, &fence.user_did, fence.device_id).await?;

    let fence_witness = InventoryFenceWitness {
        protocol_instance_id: fence.protocol_instance_id,
        cursor_key_id: fence.cursor_key_id.clone(),
        event_position: fence.event_position,
        event_cursor_sha256: fence.event_cursor_sha256,
        retained_floor: fence.retained_floor,
        captured_at: fence.captured_at,
    };

    let mut authorities: Vec<ConversationInventoryAuthority> = Vec::new();
    for conversation_id in candidates {
        // Conversation head lock, ascending UUID byte order.
        let locked_at: DateTime<Utc> =
            sqlx::query_scalar("SELECT date_trunc('milliseconds', clock_timestamp())")
                .fetch_one(&mut **tx)
                .await
                .map_err(|_| ReadAuthorityError::Storage)?;
        let locked = hydrate_locked_conversation_state(tx, conversation_id, locked_at)
            .await
            .map_err(map_hydration_error)?;
        let graph_digest = *locked.locked_graph_digest();
        // Close tombstones carry no snapshot digest: terminal aggregates seal
        // no active snapshot, so the zero digest is the structural sentinel.
        let snapshot_digest = *locked.locked_snapshot_digest().unwrap_or(&[0_u8; 32]);

        let decision = classify_inventory_arm(&fence.user_did, fence.device_id, locked.state())?;
        let arm = match decision {
            InventoryArmDecision::None => continue,
            InventoryArmDecision::Close {
                terminal_seq,
                closing_transition_id,
                closing_outer_entry_fingerprint,
            } => ConversationInventoryArm::Close {
                terminal_seq,
                closing_transition_id,
                closing_outer_entry_fingerprint,
            },
            InventoryArmDecision::Removal {
                membership_interval_id,
                terminal_seq,
                closing_transition_id,
                closing_outer_entry_fingerprint,
            } => {
                let removed_at = interval_removed_at(tx, membership_interval_id).await?;
                ConversationInventoryArm::Removal {
                    membership_interval_id,
                    terminal_seq,
                    closing_transition_id,
                    closing_outer_entry_fingerprint,
                    removed_at,
                }
            }
            InventoryArmDecision::State => {
                let participant_period_id =
                    load_participant_period_id(tx, conversation_id, &fence.user_did).await?;
                ConversationInventoryArm::State {
                    participant_period_id,
                }
            }
        };

        authorities.push(ConversationInventoryAuthority {
            txid: fence.txid,
            device_binding_sha256: fence.device_binding_sha256,
            conversation_id,
            graph_digest,
            snapshot_digest,
            fence: InventoryFenceWitness {
                protocol_instance_id: fence_witness.protocol_instance_id,
                cursor_key_id: fence_witness.cursor_key_id.clone(),
                event_position: fence_witness.event_position,
                event_cursor_sha256: fence_witness.event_cursor_sha256,
                retained_floor: fence_witness.retained_floor,
                captured_at: fence_witness.captured_at,
            },
            arm,
        });
    }

    // Final protocol/key/head/floor revalidation; any drift fails the whole
    // attempt.
    revalidate_fence_after_heads(tx, &fence).await?;
    Ok(authorities.into_boxed_slice())
}
