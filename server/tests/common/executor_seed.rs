//! Shared executor-seed harness: the frozen-corpus creation -> acceptance ->
//! leaf-recovery fulfillment graph builders extracted from
//! `tests/chat_protocol_executor.rs` so populated-domain live tests in other
//! integration crates (welcome, inventory) can seed a coherent pending-Welcome /
//! recovery-work / conversation graph.
//!
//! This file is `#[path]`-included per consumer (NOT declared in `common/mod.rs`),
//! so each consuming test crate provides its own `mod chat_protocol { .. }`
//! (`include!` of the production modules), `mod model/transcript/validation`, and
//! `mod common`. The builders reference `crate::chat_protocol::*` so they unify
//! with the consumer's own included module types (no cross-crate type drift).

#![allow(dead_code, unused_imports, clippy::too_many_arguments)]

use std::{fs, path::PathBuf};

use chrono::{DateTime, Duration, Utc};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use sqlx::postgres::PgPoolOptions;
use sqlx::PgPool;
use tokio::sync::Barrier;
use uuid::Uuid;

use crate::chat_protocol::public_state::{
    verify_genesis_group_info, verify_recovery_welcome, ActivePublicState,
    GenesisGroupInfoExpectations,
};
use crate::chat_protocol::repository::core::hydrate_locked_conversation_state;
use crate::chat_protocol::repository::delivery::WelcomeRejectionReason;
use crate::chat_protocol::repository::delivery::{
    append_entry_at, AppendEntry, DeliveryRepositoryError, EntryEntitlementKind,
    EventEntitlementKind, EventKind, OutboxWorkKind,
};
use crate::chat_protocol::repository::execution_context::{
    hydrate_execution_context_unscoped_for_test, ExecutionContextArtifacts,
};
use crate::chat_protocol::repository::transition::ResetReason;
use crate::chat_protocol::repository::transition::{
    cas_conversation_head, cas_generation_state_version, supersede_generation, ConversationHeadCas,
    ConversationHeadClose, GenerationStateVersionCas, GenerationSupersede, TransitionActorRole,
    TransitionRepositoryError,
};
use crate::chat_protocol::snapshot::{PublicGroupSnapshotCoordinate, PublicGroupSnapshotLifecycle};
use crate::chat_protocol::state_machine::{
    apply_conversation_persistence_plan_unscoped_for_test,
    apply_device_revocation_batch_unscoped_for_test, device_revocation_plan_for_test,
    persistence_plan_for_test, plan_accept_conversation, plan_close, plan_commit, plan_creation,
    plan_device_revocation, plan_leaf_recovery_cancellation, plan_leaf_recovery_fulfillment,
    plan_leaf_recovery_request, plan_leave_cancellation, plan_leave_fulfillment,
    plan_leave_request, plan_policy, plan_reset_activation, plan_reset_request,
    plan_welcome_expiry_for_test, plan_welcome_response_for_test, plan_zero_leaf_leave,
    AcceptConversation, CloseConversation, CommitCommand, ControlEntryContent,
    ConversationHeadCasBinding, ConversationKind, ConversationState, CreationCommand,
    CreationDecision, DeviceIdentity, DeviceRevocationBatchPersistencePlan,
    DeviceRevocationEvidence, EventFanout, ExecutionActor, ExecutionAuthority, ExecutionContext,
    ExecutorError, HistoricalRehydrationAuthority, LeafPersistenceColumns,
    LeafRecoveryCancellation, LeafRecoveryFulfillment, LeafRecoveryKind,
    LeafRecoveryRequestCommand, LeaveCancellation, LeaveFulfillment, LeaveRequestCommand,
    LockedRegistrationProjection, MetadataAuthorColumns, MetadataSnapshotBinding, PlanAuthority,
    PrincipalId, RecoveryOpenContext, RequestEntryKind, RequestEvidence, ResetActivation,
    ResetRequestCommand, ResetRequestRow, RevocationPackageCasBinding, RevocationTargetCasBinding,
    ServerTimestamp, SpineArtifacts, TransitionEvidence, WelcomeDispositionInput,
    WelcomeExpiryContext, WelcomeRejectionWork, WelcomeResponseContext, WelcomeStatus,
    ZeroLeafLeave,
};
use crate::chat_protocol::validation::ed25519_key_id;
#[path = "frozen_public_state.rs"]
mod frozen_public_state;

// The genuine Creation fixture is deliberately kept here, rather than in a
// single integration crate: entitlement/read tests need the exact same
// independently signed origin that the historical-control tests exercise.
// It is a test-only structural template, never an alternate protocol path.
mod genuine_creation_fixture {
    use std::{collections::BTreeMap, fmt};

    use base64::{engine::general_purpose::STANDARD, Engine};
    use ed25519_dalek::{Signer, SigningKey};
    use serde::de::{Deserializer, MapAccess, SeqAccess, Visitor};
    use serde::Deserialize;
    use serde_json::{json, Value};
    use sha2::{Digest, Sha256};
    use uuid::Uuid;

    use crate::chat_protocol::transcript::{
        decode_and_verify_control_entry, decode_canonical_signed_mutation,
    };
    use crate::chat_protocol::validation::ed25519_key_id;

    const CONTRACT_VECTORS: &str = include_str!("../fixtures/mls_chat_contract_vectors.json");
    const LEXICON: &str =
        include_str!("../../../lexicon/blue/catbird/chat/blue.catbird.chat.defs.json");

    /// A freshly rebound, production-verified signed Creation entry. Every
    /// durable origin row must be derived from these bytes, rather than from a
    /// fabricated execution context.
    #[derive(Clone)]
    pub struct RealCreationEntry {
        pub cid: [u8; 16],
        pub entry_id: Uuid,
        pub public_row_json: Vec<u8>,
        pub raw_wrapper: Vec<u8>,
        pub public_key: Vec<u8>,
        pub outer_entry_fingerprint: [u8; 32],
        pub actor_did: String,
        pub actor_device_id: Uuid,
        pub actor_key_id: String,
        pub signing_seed: [u8; 32],
        pub head_next_entry_seq: u64,
    }

    impl RealCreationEntry {
        pub fn signing_key(&self) -> SigningKey {
            SigningKey::from_bytes(&self.signing_seed)
        }
    }

    /// The registered zero-leaf device attached to a genuinely signed pending
    /// Creation manifest. Its private seed stays inside the shared fixture
    /// module; consumers receive only the exact durable authority coordinates.
    pub struct PendingCreationInvitee {
        pub did: String,
        pub device_id: Uuid,
        pub key_id: String,
        pub participant_period_id: Uuid,
        signing_seed: [u8; 32],
    }

    impl PendingCreationInvitee {
        pub fn public_key(&self) -> [u8; 32] {
            SigningKey::from_bytes(&self.signing_seed)
                .verifying_key()
                .to_bytes()
        }
    }

    /// Reconstruct the exact pending Bob identity signed into the frozen
    /// two-principal Creation corpus. Keeping the seed private to this module
    /// prevents callers from manufacturing a different durable authority row.
    pub fn corpus_pending_invitee() -> PendingCreationInvitee {
        const BOB_SIGNING_SEED: [u8; 32] = [
            0xd4, 0xa1, 0xc4, 0x8e, 0x33, 0x92, 0x40, 0x8e, 0x24, 0x40, 0x90, 0x3f, 0xc5, 0x67,
            0x8d, 0xa5, 0x69, 0x98, 0xeb, 0x66, 0xeb, 0xb8, 0xa9, 0x64, 0xa7, 0xe4, 0xe4, 0xc2,
            0xad, 0x82, 0xe9, 0xb5,
        ];
        let manifest: Value = serde_json::from_str(include_str!(
            "../../../../docs/generated-artifacts/mls-chat-v1/crypto-wire/manifest.json"
        ))
        .expect("parse frozen crypto-wire manifest");
        let bob = &manifest["identity"]["bob"];
        let signing_key = SigningKey::from_bytes(&BOB_SIGNING_SEED);
        let public_key = signing_key.verifying_key().to_bytes();
        let public_key_hex = hex::encode(public_key);
        assert_eq!(
            bob["signaturePublicKeyHex"].as_str(),
            Some(public_key_hex.as_str()),
            "frozen Bob seed remains bound to the signed corpus identity"
        );
        PendingCreationInvitee {
            did: bob["actorDid"].as_str().expect("frozen Bob DID").to_owned(),
            device_id: Uuid::parse_str(bob["deviceId"].as_str().expect("frozen Bob device"))
                .expect("frozen Bob device UUID"),
            key_id: ed25519_key_id(&public_key)
                .expect("derive frozen Bob key id")
                .as_str()
                .to_owned(),
            participant_period_id: Uuid::new_v4(),
            signing_seed: BOB_SIGNING_SEED,
        }
    }

    pub struct RealCloseEntry {
        pub entry_id: Uuid,
        pub transition_id: Uuid,
        pub public_row_json: Vec<u8>,
        pub raw_wrapper: Vec<u8>,
        pub canonical_projection: Vec<u8>,
        pub signing_transcript: Vec<u8>,
        pub request_digest: Vec<u8>,
        pub signature: Vec<u8>,
        pub server_fields_dag_cbor: Vec<u8>,
        pub outer_entry_fingerprint: [u8; 32],
        pub received_at: String,
    }

    pub fn build_real_close_entry(entry: &RealCreationEntry) -> RealCloseEntry {
        let signing_key = entry.signing_key();
        let creation_wrapper: Value =
            serde_json::from_slice(&entry.raw_wrapper).expect("parse genuine Creation wrapper");
        let prior = creation_wrapper["body"]["next"].clone();
        let mut retired = prior.clone();
        retired["stateVersion"] = json!(1);
        retired["lifecycle"] = json!("superseded");
        let tombstone_retired = retired.clone();
        let transition_id = Uuid::new_v4();
        let entry_id = Uuid::new_v4();
        let received_at = "2030-03-01T00:00:01.000Z".to_owned();
        let body = json!({
            "$type": "blue.catbird.chat.defs#conversationCloseBody",
            "actorDid": &entry.actor_did,
            "actorDeviceId": entry.actor_device_id,
            "authGeneration": 1,
            "keyId": &entry.actor_key_id,
            "signedAt": "2030-03-01T00:00:00.000Z",
            "signatureDomain": "CATBIRD-CHAT-CLOSE\u{0}",
            "idempotencyKey": Uuid::new_v4(),
            "conversationKind": "group",
            "transitionId": transition_id,
            "prior": prior,
            "retired": retired,
        });
        let raw_wrapper = resign(json!({ "body": body, "signature": "" }), &signing_key);
        let canonical = decode_canonical_signed_mutation(&raw_wrapper)
            .expect("genuine close wrapper canonicalizes");
        let signature = canonical.signature().to_vec();
        let signed_request: Value =
            serde_json::from_slice(&raw_wrapper).expect("parse signed close wrapper");
        let public_row = json!({
            "$type": "blue.catbird.chat.defs#conversationCloseEntry",
            "entryId": entry_id,
            "conversationId": Uuid::from_bytes(entry.cid),
            "seq": 2,
            "signedRequest": signed_request,
            "tombstone": {
                "conversationId": Uuid::from_bytes(entry.cid),
                "conversationKind": "group",
                "retired": tombstone_retired,
                "closedByDid": &entry.actor_did,
                "closedByDeviceId": entry.actor_device_id,
                "terminalSeq": 2,
                "closedAt": &received_at,
            },
            "receivedAt": &received_at,
        });
        let public_row_json = serde_json::to_vec(&public_row).expect("encode genuine close entry");
        let verified = decode_and_verify_control_entry(&public_row_json, &entry.public_key)
            .expect("genuine close entry verifies");
        RealCloseEntry {
            entry_id,
            transition_id,
            public_row_json,
            raw_wrapper,
            canonical_projection: canonical.canonical_projection().to_vec(),
            signing_transcript: canonical.transcript_bytes().to_vec(),
            request_digest: canonical.request_digest().to_vec(),
            signature,
            server_fields_dag_cbor: verified
                .server_fields_dag_cbor()
                .expect("genuine close server fields"),
            outer_entry_fingerprint: *verified.outer_control_fingerprint(),
            received_at,
        }
    }

    enum FixtureDagValue {
        String(String),
        Integer(u64),
        Bool(bool),
        Bytes(Vec<u8>),
        Array(Vec<Self>),
        Map(BTreeMap<String, Self>),
    }

    impl<'de> Deserialize<'de> for FixtureDagValue {
        fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
        where
            D: Deserializer<'de>,
        {
            deserializer.deserialize_any(FixtureDagVisitor)
        }
    }

    struct FixtureDagVisitor;

    impl<'de> Visitor<'de> for FixtureDagVisitor {
        type Value = FixtureDagValue;
        fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            formatter.write_str("the frozen clean-chat DAG-CBOR value profile")
        }
        fn visit_bool<E>(self, value: bool) -> Result<Self::Value, E> {
            Ok(FixtureDagValue::Bool(value))
        }
        fn visit_u64<E>(self, value: u64) -> Result<Self::Value, E> {
            Ok(FixtureDagValue::Integer(value))
        }
        fn visit_i64<E>(self, value: i64) -> Result<Self::Value, E>
        where
            E: serde::de::Error,
        {
            u64::try_from(value)
                .map(FixtureDagValue::Integer)
                .map_err(|_| E::custom("negative fixture integer"))
        }
        fn visit_str<E>(self, value: &str) -> Result<Self::Value, E> {
            Ok(FixtureDagValue::String(value.to_owned()))
        }
        fn visit_string<E>(self, value: String) -> Result<Self::Value, E> {
            Ok(FixtureDagValue::String(value))
        }
        fn visit_bytes<E>(self, value: &[u8]) -> Result<Self::Value, E> {
            Ok(FixtureDagValue::Bytes(value.to_vec()))
        }
        fn visit_byte_buf<E>(self, value: Vec<u8>) -> Result<Self::Value, E> {
            Ok(FixtureDagValue::Bytes(value))
        }
        fn visit_seq<A>(self, mut sequence: A) -> Result<Self::Value, A::Error>
        where
            A: SeqAccess<'de>,
        {
            let mut values = Vec::new();
            while let Some(value) = sequence.next_element()? {
                values.push(value);
            }
            Ok(FixtureDagValue::Array(values))
        }
        fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
        where
            A: MapAccess<'de>,
        {
            let mut values = BTreeMap::new();
            while let Some((key, value)) = map.next_entry()? {
                values.insert(key, value);
            }
            Ok(FixtureDagValue::Map(values))
        }
    }

    impl FixtureDagValue {
        fn into_json_for_schema(
            self,
            schema: &Value,
            definitions: &serde_json::Map<String, Value>,
        ) -> Value {
            match schema["type"].as_str().unwrap() {
                "ref" => {
                    let name = schema["ref"].as_str().unwrap().strip_prefix('#').unwrap();
                    if matches!(name, "operationId" | "deviceId") {
                        let Self::Bytes(value) = self else {
                            panic!("frozen UUID projection was not DAG-CBOR bytes");
                        };
                        Value::String(Uuid::from_slice(&value).unwrap().hyphenated().to_string())
                    } else {
                        self.into_json_for_schema(&definitions[name], definitions)
                    }
                }
                "union" => {
                    let name = {
                        let Self::Map(values) = &self else {
                            panic!("frozen union projection was not a DAG-CBOR map");
                        };
                        let Some(Self::String(type_id)) = values.get("$type") else {
                            panic!("frozen union projection omitted its type tag");
                        };
                        type_id
                            .strip_prefix("blue.catbird.chat.defs#")
                            .unwrap()
                            .to_owned()
                    };
                    assert!(
                        schema["refs"]
                            .as_array()
                            .unwrap()
                            .iter()
                            .any(|reference| reference.as_str() == Some(&format!("#{name}"))),
                        "frozen union selected a disallowed type"
                    );
                    self.into_json_for_schema(&definitions[&name], definitions)
                }
                "object" => {
                    let Self::Map(values) = self else {
                        panic!("frozen object projection was not a DAG-CBOR map");
                    };
                    let properties = schema["properties"].as_object().unwrap();
                    Value::Object(
                        values
                            .into_iter()
                            .map(|(name, value)| {
                                let value = if name == "$type" {
                                    let Self::String(type_id) = value else {
                                        panic!("frozen object type tag was not text");
                                    };
                                    Value::String(type_id)
                                } else {
                                    value.into_json_for_schema(&properties[&name], definitions)
                                };
                                (name, value)
                            })
                            .collect(),
                    )
                }
                "string" => {
                    let Self::String(value) = self else {
                        panic!("frozen string projection was not DAG-CBOR text");
                    };
                    Value::String(value)
                }
                "bytes" => {
                    let Self::Bytes(value) = self else {
                        panic!("frozen byte projection was not DAG-CBOR bytes");
                    };
                    Value::String(STANDARD.encode(value))
                }
                "integer" => {
                    let Self::Integer(value) = self else {
                        panic!("frozen integer projection was not a DAG-CBOR integer");
                    };
                    json!(value)
                }
                "boolean" => {
                    let Self::Bool(value) = self else {
                        panic!("frozen boolean projection was not a DAG-CBOR boolean");
                    };
                    json!(value)
                }
                "array" => {
                    let Self::Array(values) = self else {
                        panic!("frozen array projection was not a DAG-CBOR array");
                    };
                    Value::Array(
                        values
                            .into_iter()
                            .map(|value| value.into_json_for_schema(&schema["items"], definitions))
                            .collect(),
                    )
                }
                other => panic!("unsupported frozen fixture schema type {other}"),
            }
        }
    }

    fn rewrite_conversation_id(
        value: &mut Value,
        from_uuid: &str,
        to_uuid: &str,
        from_b64: &str,
        to_b64: &str,
    ) {
        match value {
            Value::String(text) if text == from_uuid => *text = to_uuid.to_owned(),
            Value::String(text) if text == from_b64 => *text = to_b64.to_owned(),
            Value::Array(items) => {
                for child in items {
                    rewrite_conversation_id(child, from_uuid, to_uuid, from_b64, to_b64);
                }
            }
            Value::Object(map) => {
                for child in map.values_mut() {
                    rewrite_conversation_id(child, from_uuid, to_uuid, from_b64, to_b64);
                }
            }
            _ => {}
        }
    }
    fn rewrite_exact_text(value: &mut Value, from: &str, to: &str) {
        match value {
            Value::String(text) if text == from => *text = to.to_owned(),
            Value::Array(items) => {
                for child in items {
                    rewrite_exact_text(child, from, to);
                }
            }
            Value::Object(map) => {
                for child in map.values_mut() {
                    rewrite_exact_text(child, from, to);
                }
            }
            _ => {}
        }
    }
    fn resign(mut wrapper: Value, signing_key: &SigningKey) -> Vec<u8> {
        wrapper["signature"] = Value::String(STANDARD.encode([0u8; 64]));
        let canonical =
            decode_canonical_signed_mutation(&serde_json::to_vec(&wrapper).unwrap()).unwrap();
        wrapper["signature"] = Value::String(
            STANDARD.encode(signing_key.sign(canonical.transcript_bytes()).to_bytes()),
        );
        serde_json::to_vec(&wrapper).unwrap()
    }
    fn repair_body_digests(value: &mut Value) {
        match value {
            Value::Object(map) => {
                if let (Some(Value::String(bytes_b64)), true) =
                    (map.get("bytes").cloned(), map.contains_key("sha256"))
                {
                    if let Ok(bytes) = STANDARD.decode(&bytes_b64) {
                        map.insert(
                            "sha256".to_owned(),
                            json!(STANDARD.encode(Sha256::digest(&bytes))),
                        );
                    }
                }
                if let (Some(Value::String(cipher_b64)), true) = (
                    map.get("ciphertext").cloned(),
                    map.contains_key("ciphertextSha256"),
                ) {
                    if let Ok(bytes) = STANDARD.decode(&cipher_b64) {
                        map.insert(
                            "ciphertextSha256".to_owned(),
                            json!(STANDARD.encode(Sha256::digest(&bytes))),
                        );
                        map.insert("ciphertextSize".to_owned(), json!(bytes.len()));
                    }
                }
                if let (Some(Value::String(pk_b64)), true) = (
                    map.get("signaturePublicKey").cloned(),
                    map.contains_key("authorKeyId"),
                ) {
                    if let Ok(pk) = STANDARD.decode(&pk_b64) {
                        if let Ok(pk) = <[u8; 32]>::try_from(pk.as_slice()) {
                            map.insert(
                                "authorKeyId".to_owned(),
                                json!(ed25519_key_id(&pk).unwrap().as_str()),
                            );
                        }
                    }
                }
                if let (Some(origin), true) = (
                    map.get("originTransitionId").cloned(),
                    map.get("authorProof")
                        .map(Value::is_object)
                        .unwrap_or(false),
                ) {
                    if let Some(Value::Object(proof)) = map.get_mut("authorProof") {
                        proof.insert("originTransitionId".to_owned(), origin);
                    }
                }
                for child in map.values_mut() {
                    repair_body_digests(child);
                }
            }
            Value::Array(items) => {
                for child in items {
                    repair_body_digests(child);
                }
            }
            _ => {}
        }
    }

    /// Rebind the already genuine Creation to one exact pending invitee and
    /// sign the entire manifest again. The durable seeder consumes the returned
    /// registration material in the same transaction as the signed Creation,
    /// so there is never a schema-only pending row.
    pub fn add_pending_invitee_to_creation(
        mut entry: RealCreationEntry,
        conversation_kind: &str,
    ) -> (RealCreationEntry, PendingCreationInvitee) {
        let role = match conversation_kind {
            "group" => "member",
            "direct" => "admin",
            other => panic!("unsupported pending Creation kind {other}"),
        };
        let mut seed_digest = Sha256::new();
        seed_digest.update(b"CATBIRD-CHAT-GENUINE-PENDING-INVITEE\0");
        seed_digest.update(conversation_kind.as_bytes());
        seed_digest.update(entry.cid);
        let signing_seed: [u8; 32] = seed_digest.finalize().into();
        let signing_key = SigningKey::from_bytes(&signing_seed);
        let public_key = signing_key.verifying_key().to_bytes();
        let key_id = ed25519_key_id(&public_key)
            .expect("pending invitee key id")
            .as_str()
            .to_owned();
        const PLC_ALPHABET: &[u8] = b"abcdefghijklmnopqrstuvwxyz234567";
        let suffix: String = signing_seed
            .iter()
            .take(24)
            .map(|byte| PLC_ALPHABET[usize::from(*byte % 32)] as char)
            .collect();
        let invitee = PendingCreationInvitee {
            did: format!("did:plc:{suffix}"),
            device_id: Uuid::new_v4(),
            key_id,
            participant_period_id: Uuid::new_v4(),
            signing_seed,
        };

        let mut wrapper: Value =
            serde_json::from_slice(&entry.raw_wrapper).expect("parse genuine Creation wrapper");
        let transition_id = wrapper["body"]["transitionId"].clone();
        wrapper["body"]["conversationKind"] = json!(conversation_kind);
        wrapper["body"]["manifest"]["participants"] = json!([
            {
                "userDid": &entry.actor_did,
                "status": "active",
                "role": "admin",
            },
            {
                "userDid": &invitee.did,
                "status": "pending",
                "role": role,
                "invitationProvenance": {
                    "invitationTransitionId": transition_id,
                    "invitedByDid": &entry.actor_did,
                    "invitedByDeviceId": entry.actor_device_id,
                },
            },
        ]);
        wrapper["body"]["manifest"]["participants"]
            .as_array_mut()
            .expect("Creation participant array")
            .sort_by(|left, right| {
                left["userDid"]
                    .as_str()
                    .expect("left participant DID")
                    .as_bytes()
                    .cmp(
                        right["userDid"]
                            .as_str()
                            .expect("right participant DID")
                            .as_bytes(),
                    )
            });
        repair_body_digests(&mut wrapper["body"]);
        entry.raw_wrapper = resign(wrapper, &entry.signing_key());
        let mut row: Value =
            serde_json::from_slice(&entry.public_row_json).expect("parse genuine Creation row");
        row["signedRequest"] =
            serde_json::from_slice(&entry.raw_wrapper).expect("parse resigned Creation wrapper");
        entry.public_row_json =
            serde_json::to_vec(&row).expect("encode pending genuine Creation row");
        entry.outer_entry_fingerprint =
            *decode_and_verify_control_entry(&entry.public_row_json, &entry.public_key)
                .expect("pending genuine Creation verifies")
                .outer_control_fingerprint();
        (entry, invitee)
    }

    pub fn build_real_creation_entry(fresh_cid: [u8; 16]) -> RealCreationEntry {
        let fixture: Value = serde_json::from_str(CONTRACT_VECTORS).unwrap();
        let contract: Value = serde_json::from_str(LEXICON).unwrap();
        let definitions = contract["defs"].as_object().unwrap();
        let case = fixture["controlEntryFingerprints"]["cases"]
            .as_array()
            .unwrap()
            .iter()
            .find(|c| c["entryKind"].as_str().unwrap().ends_with("creationEntry"))
            .expect("creation control vector present");
        let mut signing_seed_digest = Sha256::new();
        signing_seed_digest.update(b"CATBIRD-CHAT-REAL-CREATION-FIXTURE\0");
        signing_seed_digest.update(fresh_cid);
        let signing_seed: [u8; 32] = signing_seed_digest.finalize().into();
        let signing_key = SigningKey::from_bytes(&signing_seed);
        let verifying = signing_key.verifying_key().to_bytes();
        let body_cbor = hex::decode(
            case["unsignedSigningProjectionCanonicalDagCborHex"]
                .as_str()
                .unwrap(),
        )
        .unwrap();
        let body: FixtureDagValue = serde_ipld_dagcbor::from_slice(&body_cbor).unwrap();
        let signed_name = case["signedRequestRef"]
            .as_str()
            .unwrap()
            .strip_prefix("blue.catbird.chat.defs#")
            .unwrap();
        let body_name = definitions[signed_name]["properties"]["body"]["refs"][0]
            .as_str()
            .unwrap()
            .strip_prefix('#')
            .unwrap();
        let mut signing_body = body.into_json_for_schema(&definitions[body_name], definitions);
        signing_body["keyId"] = json!(ed25519_key_id(&verifying).unwrap().as_str());
        const FROZEN_CID: [u8; 16] = [
            0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x41, 0x11, 0x91, 0x11, 0x11, 0x11, 0x11, 0x11,
            0x11, 0x11,
        ];
        let from_uuid = Uuid::from_bytes(FROZEN_CID).hyphenated().to_string();
        let to_uuid = Uuid::from_bytes(fresh_cid).hyphenated().to_string();
        rewrite_conversation_id(
            &mut signing_body,
            &from_uuid,
            &to_uuid,
            &STANDARD.encode(FROZEN_CID),
            &STANDARD.encode(fresh_cid),
        );
        let frozen_transition_id =
            Uuid::parse_str(signing_body["transitionId"].as_str().unwrap()).unwrap();
        let fresh_transition_id = Uuid::new_v4();
        rewrite_conversation_id(
            &mut signing_body,
            &frozen_transition_id.hyphenated().to_string(),
            &fresh_transition_id.hyphenated().to_string(),
            &STANDARD.encode(frozen_transition_id.as_bytes()),
            &STANDARD.encode(fresh_transition_id.as_bytes()),
        );
        let frozen_actor_device_id = signing_body["actorDeviceId"].as_str().unwrap().to_owned();
        let fresh_actor_device_id = Uuid::new_v4().hyphenated().to_string();
        rewrite_exact_text(
            &mut signing_body,
            &frozen_actor_device_id,
            &fresh_actor_device_id,
        );
        const PLC_ALPHABET: &[u8] = b"abcdefghijklmnopqrstuvwxyz234567";
        let suffix: String = signing_seed
            .iter()
            .take(24)
            .map(|byte| PLC_ALPHABET[usize::from(*byte % 32)] as char)
            .collect();
        let fresh_actor_did = format!("did:plc:{suffix}");
        let frozen_actor_did = signing_body["actorDid"].as_str().unwrap().to_owned();
        rewrite_exact_text(&mut signing_body, &frozen_actor_did, &fresh_actor_did);
        let actor_did = signing_body["actorDid"].as_str().unwrap().to_owned();
        let actor_device_id =
            Uuid::parse_str(signing_body["actorDeviceId"].as_str().unwrap()).unwrap();
        let actor_key_id = ed25519_key_id(&verifying).unwrap().as_str().to_owned();
        signing_body["conversationKind"] = json!("group");
        signing_body["next"]["groupId"] = json!(STANDARD.encode([1_u8; 32]));
        signing_body["next"]["groupContextHash"] = json!(STANDARD.encode([2_u8; 32]));
        signing_body["next"]["confirmationTag"] = json!(STANDARD.encode([3_u8; 32]));
        signing_body["metadataSnapshot"]["coordinate"]["conversationId"] =
            json!(STANDARD.encode(fresh_cid));
        signing_body["metadataSnapshot"]["coordinate"]["generation"] = json!(0);
        signing_body["metadataSnapshot"]["coordinate"]["groupId"] =
            json!(STANDARD.encode([1_u8; 32]));
        signing_body["metadataSnapshot"]["coordinate"]["epoch"] = json!(0);
        signing_body["metadataSnapshot"]["coordinate"]["groupContextHash"] =
            json!(STANDARD.encode([2_u8; 32]));
        signing_body["metadataSnapshot"]["coordinate"]["confirmationTag"] =
            json!(STANDARD.encode([3_u8; 32]));
        signing_body["manifest"]["actorLeaf"]["userDid"] = json!(&actor_did);
        signing_body["manifest"]["actorLeaf"]["deviceId"] =
            json!(actor_device_id.hyphenated().to_string());
        signing_body["manifest"]["participants"] =
            json!([{"userDid": &actor_did, "status": "active", "role": "admin"}]);
        let transition_id = signing_body["transitionId"].clone();
        signing_body["metadataSnapshot"]["originTransitionId"] = transition_id.clone();
        signing_body["metadataSnapshot"]["authorProof"]["authorDid"] = json!(&actor_did);
        signing_body["metadataSnapshot"]["authorProof"]["authorDeviceId"] =
            json!(actor_device_id.hyphenated().to_string());
        signing_body["metadataSnapshot"]["authorProof"]["authorKeyId"] = json!(&actor_key_id);
        signing_body["metadataSnapshot"]["authorProof"]["signaturePublicKey"] =
            json!(STANDARD.encode(verifying));
        signing_body["metadataSnapshot"]["authorProof"]["authGenerationAtOrigin"] = json!(1);
        signing_body["metadataSnapshot"]["authorProof"]["originTransitionId"] = transition_id;
        signing_body["metadataSnapshot"]["authorProof"]["originSeq"] = json!(1);
        signing_body["metadataSnapshot"]["authorProof"]["roleAtOrigin"] = json!("admin");
        signing_body["metadataSnapshot"]["authorProof"]["deviceStatusAtOrigin"] = json!("active");
        // All authority-bearing mutations precede digest repair and signing.
        // This keeps the canonical request, signature, outer entry projection,
        // and fingerprint downstream of one internally consistent body.
        repair_body_digests(&mut signing_body);
        let raw_wrapper = resign(json!({"body": signing_body, "signature": ""}), &signing_key);
        let signed_request: Value = serde_json::from_slice(&raw_wrapper).unwrap();
        let entry_id = Uuid::new_v4();
        let public_row_json = serde_json::to_vec(&json!({"$type": case["entryKind"], "entryId": entry_id.hyphenated().to_string(), "conversationId": to_uuid, "seq": 1, "signedRequest": signed_request, "receivedAt": case["receivedAt"]})).unwrap();
        let decoded = decode_and_verify_control_entry(&public_row_json, &verifying)
            .expect("rewritten creation entry decodes under the test key");
        assert_eq!(decoded.conversation_id().as_bytes(), &fresh_cid);
        RealCreationEntry {
            cid: fresh_cid,
            entry_id,
            public_row_json,
            raw_wrapper,
            public_key: verifying.to_vec(),
            outer_entry_fingerprint: *decoded.outer_control_fingerprint(),
            actor_did,
            actor_device_id,
            actor_key_id,
            signing_seed,
            head_next_entry_seq: 2,
        }
    }

    const ALICE_SIGNING_SEED: [u8; 32] = [
        0x38, 0x8f, 0x37, 0x73, 0x57, 0x9e, 0x8a, 0x2b, 0x5d, 0x57, 0x2d, 0x3b, 0x19, 0x85, 0x55,
        0xa6, 0x93, 0x6f, 0xb7, 0xf0, 0x13, 0xb8, 0x58, 0xe2, 0x69, 0xf6, 0x4f, 0x6e, 0x8c, 0x6b,
        0x12, 0x8d,
    ];

    fn coordinate_json(
        coordinate: &crate::chat_protocol::snapshot::PublicGroupSnapshotCoordinate,
    ) -> Value {
        json!({
            "conversationId": Uuid::from_bytes(*coordinate.conversation_id()),
            "generation": coordinate.generation(),
            "stateVersion": coordinate.state_version(),
            "groupId": STANDARD.encode(coordinate.group_id()),
            "epoch": coordinate.epoch(),
            "groupContextHash": STANDARD.encode(coordinate.group_context_hash()),
            "confirmationTag": STANDARD.encode(coordinate.confirmation_tag()),
            "lifecycle": "active",
        })
    }

    /// Rebind the structural Creation template to the frozen corpus Alice
    /// identity. The caller still has to bind the exact GroupInfo and fresh
    /// outer coordinate before this entry is safe to persist.
    pub fn build_real_corpus_creation_entry(fresh_cid: [u8; 16]) -> RealCreationEntry {
        let manifest: Value = serde_json::from_slice(&super::corpus_file("manifest.json"))
            .expect("parse frozen corpus manifest");
        let alice = &manifest["identity"]["alice"];
        let actor_did = alice["actorDid"].as_str().expect("Alice DID").to_owned();
        let actor_device_id = Uuid::parse_str(alice["deviceId"].as_str().expect("Alice device"))
            .expect("Alice device UUID");
        let signing_key = SigningKey::from_bytes(&ALICE_SIGNING_SEED);
        let public_key = signing_key.verifying_key().to_bytes();
        assert_eq!(
            public_key.to_vec(),
            hex::decode(
                alice["signaturePublicKeyHex"]
                    .as_str()
                    .expect("Alice public key")
            )
            .expect("Alice public key hex"),
            "corpus Alice private seed remains bound to the frozen leaf key"
        );
        let actor_key_id = ed25519_key_id(&public_key)
            .expect("Alice key id")
            .as_str()
            .to_owned();
        assert_eq!(
            alice["keyId"].as_str(),
            Some(actor_key_id.as_str()),
            "corpus Alice private seed remains bound to the manifest key id"
        );

        let mut entry = build_real_creation_entry(fresh_cid);
        let mut wrapper: Value =
            serde_json::from_slice(&entry.raw_wrapper).expect("parse Creation wrapper");
        rewrite_exact_text(&mut wrapper, &entry.actor_did, &actor_did);
        rewrite_exact_text(
            &mut wrapper,
            &entry.actor_device_id.hyphenated().to_string(),
            &actor_device_id.hyphenated().to_string(),
        );
        rewrite_exact_text(&mut wrapper, &entry.actor_key_id, &actor_key_id);
        rewrite_exact_text(
            &mut wrapper,
            &STANDARD.encode(&entry.public_key),
            &STANDARD.encode(public_key),
        );
        let chain = &manifest["chain"];
        let corpus_coordinate = crate::chat_protocol::snapshot::PublicGroupSnapshotCoordinate::new(
            fresh_cid,
            chain["generation"].as_u64().expect("corpus generation"),
            chain["genesisStateVersion"]
                .as_u64()
                .expect("corpus genesis state version"),
            hex::decode(
                chain["groupIdHex"]
                    .as_str()
                    .expect("corpus genesis group id"),
            )
            .expect("corpus genesis group id hex")
            .try_into()
            .expect("corpus genesis group id is 32 bytes"),
            chain["genesisEpoch"]
                .as_u64()
                .expect("corpus genesis epoch"),
            hex::decode(
                chain["genesisGroupContextHashHex"]
                    .as_str()
                    .expect("corpus genesis context hash"),
            )
            .expect("corpus genesis context hash hex")
            .try_into()
            .expect("corpus genesis context hash is 32 bytes"),
            hex::decode(
                chain["genesisConfirmationTagHex"]
                    .as_str()
                    .expect("corpus genesis confirmation tag"),
            )
            .expect("corpus genesis confirmation tag hex")
            .try_into()
            .expect("corpus genesis confirmation tag is 32 bytes"),
            crate::chat_protocol::snapshot::PublicGroupSnapshotLifecycle::Active,
        );
        wrapper["body"]["next"] = coordinate_json(&corpus_coordinate);
        wrapper["body"]["metadataSnapshot"]["coordinate"]["conversationId"] =
            json!(STANDARD.encode(fresh_cid));
        wrapper["body"]["metadataSnapshot"]["coordinate"]["generation"] =
            json!(corpus_coordinate.generation());
        wrapper["body"]["metadataSnapshot"]["coordinate"]["groupId"] =
            json!(STANDARD.encode(corpus_coordinate.group_id()));
        wrapper["body"]["metadataSnapshot"]["coordinate"]["epoch"] =
            json!(corpus_coordinate.epoch());
        wrapper["body"]["metadataSnapshot"]["coordinate"]["groupContextHash"] =
            json!(STANDARD.encode(corpus_coordinate.group_context_hash()));
        wrapper["body"]["metadataSnapshot"]["coordinate"]["confirmationTag"] =
            json!(STANDARD.encode(corpus_coordinate.confirmation_tag()));
        wrapper["body"]["signedAt"] = manifest["creation"]["signedAt"].clone();
        repair_body_digests(&mut wrapper["body"]);
        entry.actor_did = actor_did;
        entry.actor_device_id = actor_device_id;
        entry.actor_key_id = actor_key_id;
        entry.public_key = public_key.to_vec();
        entry.signing_seed = ALICE_SIGNING_SEED;

        entry.raw_wrapper = resign(wrapper, &signing_key);
        let mut row: Value =
            serde_json::from_slice(&entry.public_row_json).expect("parse Creation row");
        row["signedRequest"] =
            serde_json::from_slice(&entry.raw_wrapper).expect("parse rebound Creation wrapper");
        row["receivedAt"] = manifest["creation"]["receivedAt"].clone();
        entry.public_row_json = serde_json::to_vec(&row).expect("encode rebound Creation row");
        entry.outer_entry_fingerprint =
            *decode_and_verify_control_entry(&entry.public_row_json, &entry.public_key)
                .expect("corpus-identity Creation verifies")
                .outer_control_fingerprint();
        entry
    }

    /// Bind a Creation entry to the exact verified genesis coordinate and
    /// GroupInfo. All metadata provenance is re-derived before the body is
    /// canonicalized and signed again.
    pub fn bind_creation_entry_to_group_info(
        mut entry: RealCreationEntry,
        group_info: &[u8],
        coordinate: &crate::chat_protocol::snapshot::PublicGroupSnapshotCoordinate,
        signed_at: &str,
        received_at: &str,
    ) -> RealCreationEntry {
        assert_eq!(
            coordinate.conversation_id(),
            &entry.cid,
            "Creation coordinate remains bound to the fresh conversation"
        );
        let mut wrapper: Value =
            serde_json::from_slice(&entry.raw_wrapper).expect("parse Creation wrapper");
        wrapper["body"]["signedAt"] = json!(signed_at);
        wrapper["body"]["conversationKind"] = json!("group");
        wrapper["body"]["next"] = coordinate_json(coordinate);
        wrapper["body"]["metadataSnapshot"]["coordinate"]["conversationId"] =
            json!(STANDARD.encode(entry.cid));
        wrapper["body"]["metadataSnapshot"]["coordinate"]["generation"] =
            json!(coordinate.generation());
        wrapper["body"]["metadataSnapshot"]["coordinate"]["groupId"] =
            json!(STANDARD.encode(coordinate.group_id()));
        wrapper["body"]["metadataSnapshot"]["coordinate"]["epoch"] = json!(coordinate.epoch());
        wrapper["body"]["metadataSnapshot"]["coordinate"]["groupContextHash"] =
            json!(STANDARD.encode(coordinate.group_context_hash()));
        wrapper["body"]["metadataSnapshot"]["coordinate"]["confirmationTag"] =
            json!(STANDARD.encode(coordinate.confirmation_tag()));
        let transition_id = wrapper["body"]["transitionId"].clone();
        wrapper["body"]["metadataSnapshot"]["originTransitionId"] = transition_id.clone();
        wrapper["body"]["metadataSnapshot"]["authorProof"]["authorDid"] = json!(&entry.actor_did);
        wrapper["body"]["metadataSnapshot"]["authorProof"]["authorDeviceId"] =
            json!(entry.actor_device_id);
        wrapper["body"]["metadataSnapshot"]["authorProof"]["authorKeyId"] =
            json!(&entry.actor_key_id);
        wrapper["body"]["metadataSnapshot"]["authorProof"]["signaturePublicKey"] =
            json!(STANDARD.encode(&entry.public_key));
        wrapper["body"]["metadataSnapshot"]["authorProof"]["authGenerationAtOrigin"] = json!(1);
        wrapper["body"]["metadataSnapshot"]["authorProof"]["originTransitionId"] = transition_id;
        wrapper["body"]["metadataSnapshot"]["authorProof"]["originSeq"] = json!(1);
        wrapper["body"]["metadataSnapshot"]["authorProof"]["roleAtOrigin"] = json!("admin");
        wrapper["body"]["metadataSnapshot"]["authorProof"]["deviceStatusAtOrigin"] =
            json!("active");
        wrapper["body"]["genesisGroupInfo"]["bytes"] = json!(STANDARD.encode(group_info));
        wrapper["body"]["genesisGroupInfo"]["sha256"] =
            json!(STANDARD.encode(Sha256::digest(group_info)));
        repair_body_digests(&mut wrapper["body"]);
        entry.raw_wrapper = resign(wrapper, &entry.signing_key());

        let mut row: Value =
            serde_json::from_slice(&entry.public_row_json).expect("parse Creation row");
        row["signedRequest"] =
            serde_json::from_slice(&entry.raw_wrapper).expect("parse bound Creation wrapper");
        row["receivedAt"] = json!(received_at);
        entry.public_row_json = serde_json::to_vec(&row).expect("encode bound Creation row");
        entry.outer_entry_fingerprint =
            *decode_and_verify_control_entry(&entry.public_row_json, &entry.public_key)
                .expect("GroupInfo-bound Creation verifies")
                .outer_control_fingerprint();
        entry
    }
}

pub use genuine_creation_fixture::{
    add_pending_invitee_to_creation, bind_creation_entry_to_group_info, build_real_close_entry,
    build_real_corpus_creation_entry, build_real_creation_entry, corpus_pending_invitee,
    PendingCreationInvitee, RealCloseEntry, RealCreationEntry,
};

/// Return the transition id embedded in the genuine signed Creation wrapper.
/// Keeping this derivation beside the builder prevents a durable graph from
/// silently substituting independently generated provenance.
pub fn signed_creation_transition_id(entry: &RealCreationEntry) -> Uuid {
    let wrapper: serde_json::Value =
        serde_json::from_slice(&entry.raw_wrapper).expect("creation wrapper JSON");
    Uuid::parse_str(
        wrapper["body"]["transitionId"]
            .as_str()
            .expect("creation transitionId"),
    )
    .expect("creation transitionId UUID")
}

/// The authority-bearing identity facts that an entitlement/read test needs
/// after it seeds the genuine active graph. Keeping this product narrow avoids
/// re-creating the old fabricated execution-context fixture in each consumer.
pub struct GenuineCreationGraph {
    pub conversation_id: Uuid,
    pub group_id: [u8; 32],
    pub creator_did: String,
    pub creator_device_id: Uuid,
    pub creator_dpop_jkt: String,
    pub creator_auth_generation: u64,
    pub protocol_instance_id: Uuid,
    pub creation_transition_id: Uuid,
}

/// Seed one active, genesis-only group whose immutable durable rows all derive
/// from `entry`'s verified Creation bytes. `Some(public_state)` and
/// `Some(exact_group_info)` are the production-hydratable path. `None` remains
/// only for explicit schema and historical-loader negative fixtures that do
/// not claim to reconstruct a production-valid MLS genesis.
async fn seed_genuine_creation_graph_inner(
    pool: &PgPool,
    entry: &RealCreationEntry,
    public_state: Option<&ActivePublicState>,
    exact_group_info: Option<&[u8]>,
    pending_invitee: Option<&PendingCreationInvitee>,
) -> GenuineCreationGraph {
    use crate::chat_protocol::public_state::encode_public_tree_summary;
    use crate::chat_protocol::snapshot::{PublicGroupSnapshotLeaf, PublicGroupSnapshotTreeSummary};
    use crate::chat_protocol::transcript::{
        decode_and_verify_control_entry, decode_and_verify_signed_mutation,
    };

    let creation_transition_id = signed_creation_transition_id(entry);
    let conversation_id = Uuid::from_bytes(entry.cid);
    let participant_period_id = Uuid::new_v4();
    let leaf_period_id = Uuid::new_v4();
    let metadata_snapshot_id = Uuid::new_v4();
    let actor_did = &entry.actor_did;
    let actor_device_id = entry.actor_device_id;
    let actor_key_id = &entry.actor_key_id;
    let actor_public_key = entry.public_key.clone();
    let group_info = if let Some(group_info) = exact_group_info {
        group_info.to_vec()
    } else if public_state.is_some() {
        fs::read(
            PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                .join("../../docs/generated-artifacts/mls-chat-v1/crypto-wire/group-info.mls"),
        )
        .expect("read genuine frozen genesis GroupInfo")
    } else {
        vec![4_u8; 8]
    };
    let verified_mutation =
        decode_and_verify_signed_mutation(&entry.raw_wrapper, &actor_public_key)
            .expect("creation wrapper passes production signature validation");
    let verified_entry = decode_and_verify_control_entry(&entry.public_row_json, &actor_public_key)
        .expect("creation entry passes production control validation");
    assert_eq!(
        verified_entry.mutation().request_digest(),
        verified_mutation.request_digest()
    );
    let basic_credential = format!("{actor_did}#{actor_device_id}").into_bytes();
    let (group_id, group_context_hash, confirmation_tag, snapshot, snapshot_sha256, tree) =
        match public_state {
            Some(public_state) => {
                assert_eq!(public_state.coordinate().conversation_id(), &entry.cid);
                (
                    public_state.coordinate().group_id().to_vec(),
                    public_state.coordinate().group_context_hash().to_vec(),
                    public_state.coordinate().confirmation_tag().to_vec(),
                    public_state.snapshot().to_vec(),
                    public_state.snapshot_sha256().to_vec(),
                    public_state.binding().tree_summary().clone(),
                )
            }
            None => {
                let snapshot = vec![0x5a_u8; 64];
                (
                    vec![1_u8; 32],
                    vec![2_u8; 32],
                    vec![3_u8; 32],
                    snapshot.clone(),
                    Sha256::digest(&snapshot).to_vec(),
                    PublicGroupSnapshotTreeSummary::new(
                        [0x63_u8; 32],
                        vec![PublicGroupSnapshotLeaf::new(
                            0,
                            basic_credential.clone(),
                            actor_public_key.clone(),
                            vec![0x64_u8; 1_216],
                        )],
                    ),
                )
            }
        };
    let (tree_summary, tree_summary_sha) = encode_public_tree_summary(&tree)
        .expect("genesis tree summary is canonical")
        .into_parts();
    let signed_request = entry.raw_wrapper.clone();
    let unsigned_projection = verified_mutation.canonical_projection().to_vec();
    let signing_transcript = verified_mutation.transcript_bytes().to_vec();
    let request_digest = verified_mutation.request_digest().to_vec();
    let signature = verified_mutation.signature().to_vec();
    let server_fields = verified_entry
        .server_fields_dag_cbor()
        .expect("canonical server fields");
    let entry_payload = entry.public_row_json.clone();
    let entry_payload_sha = Sha256::digest(&entry_payload).to_vec();
    let entry_outer_fingerprint = entry.outer_entry_fingerprint.to_vec();
    let at = verified_entry.received_at().datetime();
    let signed_wrapper: serde_json::Value =
        serde_json::from_slice(&entry.raw_wrapper).expect("parse signed Creation wrapper");
    let conversation_kind = signed_wrapper["body"]["conversationKind"]
        .as_str()
        .expect("signed Creation conversation kind");
    let signed_participants = signed_wrapper["body"]["manifest"]["participants"]
        .as_array()
        .expect("signed Creation participants");
    let expected_participant_count = 1 + usize::from(pending_invitee.is_some());
    assert_eq!(
        signed_participants.len(),
        expected_participant_count,
        "durable participant rows are sourced from the exact signed Creation manifest"
    );
    let direct_pair = match (conversation_kind, pending_invitee) {
        ("group", _) => None,
        ("direct", Some(invitee)) => {
            let mut dids = [actor_did.clone(), invitee.did.clone()];
            dids.sort_by(|left, right| left.as_bytes().cmp(right.as_bytes()));
            Some((dids[0].clone(), dids[1].clone()))
        }
        ("direct", None) => panic!("a direct Creation requires its signed pending invitee"),
        (other, _) => panic!("unsupported signed Creation kind {other}"),
    };
    for signed in signed_participants {
        let did = signed["userDid"]
            .as_str()
            .expect("signed Creation participant DID");
        if did == actor_did {
            assert_eq!(signed["status"].as_str(), Some("active"));
            assert_eq!(signed["role"].as_str(), Some("admin"));
            assert!(signed.get("invitationProvenance").is_none());
        } else {
            let invitee = pending_invitee.expect("signed pending participant has fixture identity");
            assert_eq!(did, invitee.did);
            assert_eq!(signed["status"].as_str(), Some("pending"));
            assert_eq!(
                signed["role"].as_str(),
                Some(if conversation_kind == "direct" {
                    "admin"
                } else {
                    "member"
                })
            );
            assert_eq!(
                signed["invitationProvenance"]["invitationTransitionId"],
                signed_wrapper["body"]["transitionId"]
            );
            assert_eq!(
                signed["invitationProvenance"]["invitedByDid"].as_str(),
                Some(actor_did.as_str())
            );
            assert_eq!(
                signed["invitationProvenance"]["invitedByDeviceId"].as_str(),
                Some(actor_device_id.hyphenated().to_string().as_str())
            );
        }
    }
    let signed_metadata = &signed_wrapper["body"]["metadataSnapshot"];
    let metadata_version = signed_metadata["metadataVersion"]
        .as_u64()
        .expect("signed metadata version");
    let metadata_nonce = {
        use base64::{engine::general_purpose::STANDARD, Engine};
        STANDARD
            .decode(
                signed_metadata["nonce"]
                    .as_str()
                    .expect("signed metadata nonce"),
            )
            .expect("decode signed metadata nonce")
    };
    let metadata_ciphertext = {
        use base64::{engine::general_purpose::STANDARD, Engine};
        STANDARD
            .decode(
                signed_metadata["ciphertext"]
                    .as_str()
                    .expect("signed metadata ciphertext"),
            )
            .expect("decode signed metadata ciphertext")
    };
    let metadata_ciphertext_sha = Sha256::digest(&metadata_ciphertext).to_vec();
    assert_eq!(
        signed_metadata["ciphertextSize"].as_u64(),
        Some(metadata_ciphertext.len() as u64),
        "signed metadata size binds the exact ciphertext"
    );
    {
        use base64::{engine::general_purpose::STANDARD, Engine};
        assert_eq!(
            STANDARD
                .decode(
                    signed_metadata["ciphertextSha256"]
                        .as_str()
                        .expect("signed metadata digest"),
                )
                .expect("decode signed metadata digest"),
            metadata_ciphertext_sha,
            "signed metadata digest binds the exact ciphertext"
        );
    }
    let metadata_author = &signed_metadata["authorProof"];
    assert_eq!(
        metadata_author["authorDid"].as_str(),
        Some(actor_did.as_str())
    );
    assert_eq!(
        metadata_author["authorDeviceId"].as_str(),
        Some(actor_device_id.hyphenated().to_string().as_str())
    );
    assert_eq!(
        metadata_author["authorKeyId"].as_str(),
        Some(actor_key_id.as_str())
    );
    assert_eq!(metadata_author["authGenerationAtOrigin"].as_u64(), Some(1));
    assert_eq!(metadata_author["originSeq"].as_u64(), Some(1));
    assert_eq!(metadata_author["roleAtOrigin"].as_str(), Some("admin"));
    assert_eq!(
        metadata_author["deviceStatusAtOrigin"].as_str(),
        Some("active")
    );

    let mut tx = pool.begin().await.expect("begin genuine creation");
    // A protocol instance is an independent immutable system root required by
    // the real executor/facade hydrators.  It is intentionally seeded inside
    // this fixture's transaction so a private fresh DB has no ambient state.
    let proposed_protocol_instance_id = Uuid::from_bytes(uuid_v4_bytes(0x51));
    let cursor_key: String = sqlx::query_scalar("SELECT chat.ed25519_key_id($1)")
        .bind(vec![0x51_u8; 32])
        .fetch_one(&mut *tx)
        .await
        .expect("derive protocol cursor key");
    sqlx::query("INSERT INTO chat.protocol_instances(singleton,protocol_version,protocol_instance_id,cursor_key_id) VALUES(TRUE,'1',$1,$2) ON CONFLICT DO NOTHING")
        .bind(proposed_protocol_instance_id).bind(&cursor_key).execute(&mut *tx).await.expect("seed protocol instance");
    let (protocol_instance_id, durable_cursor_key): (Uuid, String) = sqlx::query_as(
        "SELECT protocol_instance_id,cursor_key_id \
         FROM chat.protocol_instances WHERE singleton",
    )
    .fetch_one(&mut *tx)
    .await
    .expect("read durable protocol instance");
    if protocol_instance_id == proposed_protocol_instance_id {
        assert_eq!(
            durable_cursor_key, cursor_key,
            "newly seeded protocol instance retains its derived cursor-key binding"
        );
    }
    sqlx::query(
        "INSERT INTO chat.principals(user_did,created_at) VALUES($1,$2) ON CONFLICT DO NOTHING",
    )
    .bind(actor_did)
    .bind(at)
    .execute(&mut *tx)
    .await
    .expect("insert principal");
    sqlx::query("INSERT INTO chat.devices(user_did,device_id,device_name,status,dpop_jkt,auth_generation,capabilities,created_at,updated_at) VALUES($1,$2,'loader-actor','active',$3,1,chat.protocol_capabilities(),$4,$4) ON CONFLICT DO NOTHING")
        .bind(actor_did).bind(actor_device_id).bind(actor_key_id).bind(at).execute(&mut *tx).await.expect("insert device");
    sqlx::query("INSERT INTO chat.device_keys(user_did,device_id,key_id,signing_public_key,enrollment_auth_generation,created_at) VALUES($1,$2,$3,$4,1,$5) ON CONFLICT DO NOTHING")
        .bind(actor_did).bind(actor_device_id).bind(actor_key_id).bind(&actor_public_key).bind(at).execute(&mut *tx).await.expect("insert device key");
    if let Some(invitee) = pending_invitee {
        sqlx::query(
            "INSERT INTO chat.principals(user_did,created_at) VALUES($1,$2) ON CONFLICT DO NOTHING",
        )
        .bind(&invitee.did)
        .bind(at)
        .execute(&mut *tx)
        .await
        .expect("insert pending invitee principal");
        sqlx::query("INSERT INTO chat.devices(user_did,device_id,device_name,status,dpop_jkt,auth_generation,capabilities,created_at,updated_at) VALUES($1,$2,'pending-invitee','active',$3,1,chat.protocol_capabilities(),$4,$4) ON CONFLICT DO NOTHING")
            .bind(&invitee.did).bind(invitee.device_id).bind(&invitee.key_id).bind(at).execute(&mut *tx).await.expect("insert pending invitee device");
        sqlx::query("INSERT INTO chat.device_keys(user_did,device_id,key_id,signing_public_key,enrollment_auth_generation,created_at) VALUES($1,$2,$3,$4,1,$5) ON CONFLICT DO NOTHING")
            .bind(&invitee.did).bind(invitee.device_id).bind(&invitee.key_id).bind(invitee.public_key().to_vec()).bind(at).execute(&mut *tx).await.expect("insert pending invitee key");
    }
    match direct_pair {
        Some((did_low, did_high)) => {
            sqlx::query("INSERT INTO chat.conversations(conversation_id,kind,lifecycle,current_generation,current_state_version,next_entry_seq,direct_did_low,direct_did_high,created_at) VALUES($1,'direct','active',0,0,2,$2,$3,$4)")
                .bind(conversation_id).bind(did_low).bind(did_high).bind(at).execute(&mut *tx).await.expect("insert direct conversation");
        }
        None => {
            sqlx::query("INSERT INTO chat.conversations(conversation_id,kind,lifecycle,current_generation,current_state_version,next_entry_seq,created_at) VALUES($1,'group','active',0,0,2,$2)")
                .bind(conversation_id).bind(at).execute(&mut *tx).await.expect("insert group conversation");
        }
    }
    sqlx::query("INSERT INTO chat.generations(conversation_id,generation,group_id,lifecycle,genesis_group_info_bytes,genesis_group_info_sha256,current_state_version,activated_seq,activated_at) VALUES($1,0,$2,'active',$3,$4,0,1,$5)")
        .bind(conversation_id).bind(&group_id).bind(&group_info).bind(Sha256::digest(&group_info).to_vec()).bind(at).execute(&mut *tx).await.expect("insert generation");
    sqlx::query("INSERT INTO chat.transitions(transition_id,conversation_id,kind,actor_did,actor_device_id,actor_key_id,actor_auth_generation,actor_role,actor_device_status,signed_request_bytes,unsigned_projection_bytes,signing_transcript_bytes,request_digest,signature,next_generation,next_state_version,metadata_snapshot_id,entry_seq,accepted_at) VALUES($1,$2,'creation',$3,$4,$5,1,'admin','active',$6,$7,$8,$9,$10,0,0,$11,1,$12)")
        .bind(creation_transition_id).bind(conversation_id).bind(actor_did).bind(actor_device_id).bind(actor_key_id).bind(&signed_request).bind(&unsigned_projection).bind(&signing_transcript).bind(&request_digest).bind(&signature).bind(metadata_snapshot_id).bind(at).execute(&mut *tx).await.expect("insert creation transition");
    sqlx::query("INSERT INTO chat.generation_states(conversation_id,generation,state_version,group_id,epoch,group_context_hash,confirmation_tag,lifecycle,state_kind,producing_transition_id,public_snapshot_bytes,snapshot_sha256,tree_summary_bytes,tree_summary_sha256,leaf_count,created_at) VALUES($1,0,0,$2,0,$3,$4,'active','creation',$5,$6,$7,$8,$9,1,$10)")
        .bind(conversation_id).bind(&group_id).bind(&group_context_hash).bind(&confirmation_tag).bind(creation_transition_id).bind(&snapshot).bind(&snapshot_sha256).bind(&tree_summary).bind(&tree_summary_sha).bind(at).execute(&mut *tx).await.expect("insert creation state");
    sqlx::query("INSERT INTO chat.participants(participant_period_id,conversation_id,user_did,status,role,role_transition_id,role_changed_at,created_by_did,created_by_device_id,current_membership,created_at) VALUES($1,$2,$3,'active','admin',$4,$5,$3,$6,true,$5)")
        .bind(participant_period_id).bind(conversation_id).bind(actor_did).bind(creation_transition_id).bind(at).bind(actor_device_id).execute(&mut *tx).await.expect("insert participant");
    sqlx::query("INSERT INTO chat.member_devices(leaf_period_id,participant_period_id,conversation_id,generation,user_did,device_id,leaf_index,basic_credential,leaf_signature_key,leaf_key_id,leaf_auth_generation,origin,joined_state_version,joined_transition_id,joined_seq,active,created_at) VALUES($1,$2,$3,0,$4,$5,0,$6,$7,$8,1,'genesis',0,$9,1,true,$10)")
        .bind(leaf_period_id).bind(participant_period_id).bind(conversation_id).bind(actor_did).bind(actor_device_id).bind(&basic_credential).bind(&actor_public_key).bind(actor_key_id).bind(creation_transition_id).bind(at).execute(&mut *tx).await.expect("insert leaf");
    sqlx::query("INSERT INTO chat.metadata_snapshots(metadata_snapshot_id,conversation_id,generation,state_version,group_id,epoch,group_context_hash,confirmation_tag,producing_transition_id,origin_transition_id,metadata_version,nonce,ciphertext,ciphertext_sha256,ciphertext_size,author_did,author_device_id,author_key_id,author_public_key,author_auth_generation,author_origin_seq,author_role,author_device_status,created_at) VALUES($1,$2,0,0,$3,0,$4,$5,$6,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,1,1,'admin','active',$16)")
        .bind(metadata_snapshot_id).bind(conversation_id).bind(&group_id).bind(&group_context_hash).bind(&confirmation_tag).bind(creation_transition_id).bind(i64::try_from(metadata_version).expect("metadata version fits i64")).bind(&metadata_nonce).bind(&metadata_ciphertext).bind(&metadata_ciphertext_sha).bind(i64::try_from(metadata_ciphertext.len()).expect("metadata size fits i64")).bind(actor_did).bind(actor_device_id).bind(actor_key_id).bind(&actor_public_key).bind(at).execute(&mut *tx).await.expect("insert metadata");
    sqlx::query("INSERT INTO chat.entries(conversation_id,seq,entry_id,entry_kind,accepted_payload_bytes,accepted_payload_sha256,signed_request_bytes,request_digest,signature,server_fields_bytes,outer_entry_fingerprint,actor_did,actor_device_id,actor_key_id,actor_auth_generation,generation,state_version,transition_id,received_at) VALUES($1,1,$2,'blue.catbird.chat.defs#creationEntry',$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,1,0,0,$13,$14)")
        .bind(conversation_id).bind(entry.entry_id).bind(&entry_payload).bind(&entry_payload_sha).bind(&signed_request).bind(&request_digest).bind(&signature).bind(&server_fields).bind(&entry_outer_fingerprint).bind(actor_did).bind(actor_device_id).bind(actor_key_id).bind(creation_transition_id).bind(at).execute(&mut *tx).await.expect("insert creation entry");
    if let Some(invitee) = pending_invitee {
        let role = if conversation_kind == "direct" {
            "admin"
        } else {
            "member"
        };
        sqlx::query(
            r#"INSERT INTO chat.participants(
                participant_period_id,conversation_id,user_did,status,role,role_transition_id,
                role_changed_at,created_by_did,created_by_device_id,invitation_transition_id,
                invitation_entry_id,invited_at,current_membership,created_at
            ) VALUES($1,$2,$3,'pending',$4,$5,$6,$7,$8,$5,$9,$6,true,$6)"#,
        )
        .bind(invitee.participant_period_id)
        .bind(conversation_id)
        .bind(&invitee.did)
        .bind(role)
        .bind(creation_transition_id)
        .bind(at)
        .bind(actor_did)
        .bind(actor_device_id)
        .bind(entry.entry_id)
        .execute(&mut *tx)
        .await
        .expect("insert signed pending invitee");
    }
    sqlx::query("INSERT INTO chat.entry_recipients(conversation_id,seq,user_did,device_id,entitlement_kind) VALUES($1,1,$2,$3,'control')")
        .bind(conversation_id).bind(actor_did).bind(actor_device_id).execute(&mut *tx).await.expect("route creation entry to active creator");
    if let Some(invitee) = pending_invitee {
        sqlx::query("INSERT INTO chat.entry_recipients(conversation_id,seq,user_did,device_id,entitlement_kind) VALUES($1,1,$2,$3,'control')")
            .bind(conversation_id).bind(&invitee.did).bind(invitee.device_id).execute(&mut *tx).await.expect("route signed invitation control entry");
    }
    sqlx::query("INSERT INTO chat.application_intervals(membership_interval_id,conversation_id,generation,recipient_did,recipient_device_id,start_seq,opening_kind,opening_transition_id,opening_outer_entry_fingerprint,opening_state_version,opening_group_id,opening_epoch,opening_group_context_hash,opening_confirmation_tag,opening_leaf_period_id,created_at) VALUES($1,$2,0,$3,$4,1,'creation',$1,$5,0,$6,0,$7,$8,$9,$10)")
        .bind(creation_transition_id).bind(conversation_id).bind(actor_did).bind(actor_device_id).bind(&entry_outer_fingerprint).bind(&group_id).bind(&group_context_hash).bind(&confirmation_tag).bind(leaf_period_id).bind(at).execute(&mut *tx).await.expect("insert creation interval");
    tx.commit().await.expect("commit genuine creation");
    GenuineCreationGraph {
        conversation_id,
        group_id: group_id
            .try_into()
            .expect("genuine genesis group id is exactly 32 bytes"),
        creator_did: actor_did.clone(),
        creator_device_id: actor_device_id,
        creator_dpop_jkt: actor_key_id.clone(),
        creator_auth_generation: 1,
        protocol_instance_id,
        creation_transition_id,
    }
}

pub async fn seed_genuine_creation_graph(
    pool: &PgPool,
    entry: &RealCreationEntry,
    public_state: Option<&ActivePublicState>,
    exact_group_info: Option<&[u8]>,
) -> GenuineCreationGraph {
    seed_genuine_creation_graph_inner(pool, entry, public_state, exact_group_info, None).await
}

async fn seed_genuine_creation_graph_with_pending_invitee(
    pool: &PgPool,
    entry: &RealCreationEntry,
    public_state: &ActivePublicState,
    exact_group_info: Option<&[u8]>,
    pending_invitee: &PendingCreationInvitee,
) -> GenuineCreationGraph {
    seed_genuine_creation_graph_inner(
        pool,
        entry,
        Some(public_state),
        exact_group_info,
        Some(pending_invitee),
    )
    .await
}

/// Build and seed the one closed, production-hydratable genuine Creation
/// fixture. Every authority-bearing identity and every MLS artifact is proven
/// against the pinned corpus before `seed_genuine_creation_graph` begins its
/// first transaction.
async fn seed_hydratable_genuine_creation_graph_inner(
    pool: &PgPool,
    conversation_id: Uuid,
    pending_kind: Option<&str>,
) -> (
    GenuineCreationGraph,
    Option<PendingCreationInvitee>,
    RealCreationEntry,
) {
    use crate::chat_protocol::transcript::{
        decode_and_verify_control_entry, decode_and_verify_signed_mutation,
    };
    use crate::chat_protocol::wire::MAX_GROUP_INFO_WIRE_BYTES;
    use base64::{engine::general_purpose::STANDARD, Engine};

    let manifest = corpus_manifest();
    let manifest_value: serde_json::Value = serde_json::from_slice(&corpus_file("manifest.json"))
        .expect("parse pinned corpus manifest");
    let alice = &manifest.identity.alice;
    let alice_device_id = Uuid::parse_str(&alice.device_id).expect("pinned Alice device UUID");
    let alice_public_key = hex_array::<32>(&alice.signature_public_key_hex);
    let alice_key_id = ed25519_key_id(&alice_public_key)
        .expect("derive pinned Alice key id")
        .as_str()
        .to_owned();
    assert_eq!(
        manifest_value["identity"]["alice"]["keyId"].as_str(),
        Some(alice_key_id.as_str()),
        "pinned Alice key id is derived from the pinned signature key"
    );
    assert_eq!(
        alice.credential_identity,
        format!("{}#{}", alice.actor_did, alice_device_id),
        "pinned Alice credential is exactly did#device"
    );

    let group_info = corpus_file("group-info.mls");
    let group_info_manifest = &manifest_value["files"]["group-info.mls"];
    assert_eq!(
        group_info.len(),
        2_838,
        "the pinned genuine genesis GroupInfo has its reviewed wire length"
    );
    assert_eq!(
        group_info_manifest["length"].as_u64(),
        Some(group_info.len() as u64),
        "manifest length binds the exact GroupInfo"
    );
    assert_eq!(
        hex_array::<32>(
            group_info_manifest["sha256Hex"]
                .as_str()
                .expect("pinned GroupInfo digest")
        ),
        <[u8; 32]>::from(Sha256::digest(&group_info)),
        "manifest digest binds the exact GroupInfo"
    );

    let coordinate = PublicGroupSnapshotCoordinate::new(
        *conversation_id.as_bytes(),
        manifest.chain.generation,
        manifest.chain.genesis_state_version,
        hex_array(&manifest.chain.group_id_hex),
        manifest.chain.genesis_epoch,
        hex_array(&manifest.chain.genesis_group_context_hash_hex),
        hex_array(&manifest.chain.genesis_confirmation_tag_hex),
        PublicGroupSnapshotLifecycle::Active,
    );
    let public_state = verify_genesis_group_info(
        &group_info,
        GenesisGroupInfoExpectations {
            coordinate,
            expected_basic_credential: alice.credential_identity.as_bytes(),
            expected_signature_key: &alice_public_key,
            now_unix_seconds: manifest.evaluation_unix_seconds,
            max_wire_bytes: MAX_GROUP_INFO_WIRE_BYTES,
            max_ratchet_tree_bytes: MAX_GROUP_INFO_WIRE_BYTES,
            max_members: 2,
        },
    )
    .expect("production verifies the pinned genesis GroupInfo");
    let pinned_snapshot = corpus_file("genesis-public-state.bin");
    assert_eq!(
        public_state.snapshot(),
        pinned_snapshot,
        "production verification reproduces the pinned canonical genesis snapshot"
    );
    assert_eq!(
        public_state.snapshot_sha256(),
        &<[u8; 32]>::from(Sha256::digest(&pinned_snapshot)),
        "production verification reproduces the pinned snapshot digest"
    );
    assert_eq!(
        public_state.snapshot(),
        frozen_public_state::restore_genesis().snapshot(),
        "production verification and the pinned structural restore agree byte-for-byte"
    );

    let signed_at = manifest_value["creation"]["signedAt"]
        .as_str()
        .expect("pinned Creation signedAt");
    let received_at = manifest_value["creation"]["receivedAt"]
        .as_str()
        .expect("pinned Creation receivedAt");
    let entry = bind_creation_entry_to_group_info(
        build_real_corpus_creation_entry(*conversation_id.as_bytes()),
        &group_info,
        &coordinate,
        signed_at,
        received_at,
    );
    let (entry, pending_invitee) = match pending_kind {
        Some(kind) => {
            let (entry, invitee) = add_pending_invitee_to_creation(entry, kind);
            (entry, Some(invitee))
        }
        None => (entry, None),
    };

    // Closed fail-fast boundary. Nothing below this block may write until the
    // signed actor, authenticated leaf, coordinates, GroupInfo, and metadata
    // provenance all agree exactly.
    let verified_mutation =
        decode_and_verify_signed_mutation(&entry.raw_wrapper, &entry.public_key)
            .expect("corpus-bound Creation signature verifies");
    let verified_entry = decode_and_verify_control_entry(&entry.public_row_json, &entry.public_key)
        .expect("corpus-bound Creation outer entry verifies");
    assert_eq!(
        verified_entry.mutation().request_digest(),
        verified_mutation.request_digest(),
        "inner and outer Creation verification agree"
    );
    assert_eq!(entry.actor_did, alice.actor_did);
    assert_eq!(entry.actor_device_id, alice_device_id);
    assert_eq!(entry.actor_key_id, alice_key_id);
    assert_eq!(entry.public_key, alice_public_key);

    let leaves = public_state.binding().tree_summary().leaves();
    assert_eq!(
        leaves.len(),
        1,
        "genesis has exactly one authenticated leaf"
    );
    let leaf = &leaves[0];
    assert_eq!(leaf.leaf_index(), 0);
    assert_eq!(
        leaf.basic_credential(),
        alice.credential_identity.as_bytes(),
        "the sole authenticated leaf is the signed actor credential"
    );
    assert_eq!(
        leaf.signature_key(),
        entry.public_key,
        "the sole authenticated leaf is the signed actor key"
    );

    let wrapper: serde_json::Value =
        serde_json::from_slice(&entry.raw_wrapper).expect("parse sealed Creation wrapper");
    assert_eq!(
        wrapper["body"]["actorDid"].as_str(),
        Some(entry.actor_did.as_str())
    );
    assert_eq!(
        wrapper["body"]["actorDeviceId"].as_str(),
        Some(entry.actor_device_id.hyphenated().to_string().as_str())
    );
    assert_eq!(
        wrapper["body"]["keyId"].as_str(),
        Some(entry.actor_key_id.as_str())
    );
    assert_eq!(wrapper["body"]["authGeneration"].as_u64(), Some(1));
    assert_eq!(
        wrapper["body"]["manifest"]["actorLeaf"]["userDid"].as_str(),
        Some(entry.actor_did.as_str())
    );
    assert_eq!(
        wrapper["body"]["manifest"]["actorLeaf"]["deviceId"].as_str(),
        Some(entry.actor_device_id.hyphenated().to_string().as_str())
    );
    let participants = wrapper["body"]["manifest"]["participants"]
        .as_array()
        .expect("sealed Creation participants");
    assert_eq!(
        participants.len(),
        1 + usize::from(pending_invitee.is_some())
    );
    let creator = participants
        .iter()
        .find(|participant| participant["userDid"].as_str() == Some(entry.actor_did.as_str()))
        .expect("sealed Creation creator");
    assert_eq!(creator["status"].as_str(), Some("active"));
    assert_eq!(creator["role"].as_str(), Some("admin"));
    if let Some(invitee) = pending_invitee.as_ref() {
        let pending = participants
            .iter()
            .find(|participant| participant["userDid"].as_str() == Some(invitee.did.as_str()))
            .expect("sealed Creation pending invitee");
        assert_eq!(pending["status"].as_str(), Some("pending"));
        assert_eq!(
            pending["role"].as_str(),
            Some(if pending_kind == Some("direct") {
                "admin"
            } else {
                "member"
            })
        );
        assert_eq!(
            pending["invitationProvenance"]["invitationTransitionId"],
            wrapper["body"]["transitionId"]
        );
    }

    let next = &wrapper["body"]["next"];
    assert_eq!(
        next["conversationId"].as_str(),
        Some(conversation_id.hyphenated().to_string().as_str())
    );
    assert_eq!(next["generation"].as_u64(), Some(coordinate.generation()));
    assert_eq!(
        next["stateVersion"].as_u64(),
        Some(coordinate.state_version())
    );
    assert_eq!(
        STANDARD.decode(next["groupId"].as_str().expect("signed next group id")),
        Ok(coordinate.group_id().to_vec())
    );
    assert_eq!(next["epoch"].as_u64(), Some(coordinate.epoch()));
    assert_eq!(
        STANDARD.decode(
            next["groupContextHash"]
                .as_str()
                .expect("signed next context hash")
        ),
        Ok(coordinate.group_context_hash().to_vec())
    );
    assert_eq!(
        STANDARD.decode(
            next["confirmationTag"]
                .as_str()
                .expect("signed next confirmation tag")
        ),
        Ok(coordinate.confirmation_tag().to_vec())
    );
    assert_eq!(next["lifecycle"].as_str(), Some("active"));

    let signed_group_info = &wrapper["body"]["genesisGroupInfo"];
    assert_eq!(
        STANDARD.decode(
            signed_group_info["bytes"]
                .as_str()
                .expect("signed GroupInfo bytes")
        ),
        Ok(group_info.clone()),
        "signed Creation carries the exact durable GroupInfo bytes"
    );
    assert_eq!(
        STANDARD.decode(
            signed_group_info["sha256"]
                .as_str()
                .expect("signed GroupInfo digest")
        ),
        Ok(Sha256::digest(&group_info).to_vec()),
        "signed Creation carries the exact durable GroupInfo digest"
    );
    let metadata = &wrapper["body"]["metadataSnapshot"];
    let author = &metadata["authorProof"];
    assert_eq!(author["authorDid"].as_str(), Some(entry.actor_did.as_str()));
    assert_eq!(
        author["authorDeviceId"].as_str(),
        Some(entry.actor_device_id.hyphenated().to_string().as_str())
    );
    assert_eq!(
        author["authorKeyId"].as_str(),
        Some(entry.actor_key_id.as_str())
    );
    assert_eq!(
        STANDARD.decode(
            author["signaturePublicKey"]
                .as_str()
                .expect("signed metadata author key")
        ),
        Ok(entry.public_key.clone())
    );
    assert_eq!(author["authGenerationAtOrigin"].as_u64(), Some(1));
    assert_eq!(author["originSeq"].as_u64(), Some(1));
    assert_eq!(author["roleAtOrigin"].as_str(), Some("admin"));
    assert_eq!(author["deviceStatusAtOrigin"].as_str(), Some("active"));
    assert_eq!(
        metadata["originTransitionId"],
        wrapper["body"]["transitionId"]
    );
    assert_eq!(
        author["originTransitionId"],
        wrapper["body"]["transitionId"]
    );

    let graph = seed_genuine_creation_graph_inner(
        pool,
        &entry,
        Some(&public_state),
        Some(&group_info),
        pending_invitee.as_ref(),
    )
    .await;
    (graph, pending_invitee, entry)
}

pub async fn seed_hydratable_genuine_creation_graph(
    pool: &PgPool,
    conversation_id: Uuid,
) -> GenuineCreationGraph {
    seed_hydratable_genuine_creation_graph_inner(pool, conversation_id, None)
        .await
        .0
}

#[tokio::test]
#[ignore = "requires loopback PostgreSQL and creates a private executor database"]
async fn genuine_creation_graph_rebinds_metadata_author_and_preserves_the_preexisting_durable_protocol_instance(
) {
    use base64::{engine::general_purpose::STANDARD, Engine};

    let (pool, _guard) = setup().await;
    let expected_protocol_instance_id = Uuid::new_v4();
    let expected_cursor_key: String = sqlx::query_scalar("SELECT chat.ed25519_key_id($1)")
        .bind(vec![0xa7_u8; 32])
        .fetch_one(&pool)
        .await
        .expect("derive preexisting cursor key");
    sqlx::query(
        "INSERT INTO chat.protocol_instances(\
             singleton,protocol_version,protocol_instance_id,cursor_key_id\
         ) VALUES(TRUE,'1',$1,$2)",
    )
    .bind(expected_protocol_instance_id)
    .bind(&expected_cursor_key)
    .execute(&pool)
    .await
    .expect("seed a distinct preexisting protocol singleton");

    let conversation_id = Uuid::new_v4();
    let entry = build_real_creation_entry(*conversation_id.as_bytes());
    let wrapper: serde_json::Value =
        serde_json::from_slice(&entry.raw_wrapper).expect("parse structural Creation wrapper");
    let metadata = &wrapper["body"]["metadataSnapshot"];
    let author = &metadata["authorProof"];
    assert_eq!(author["authorDid"].as_str(), Some(entry.actor_did.as_str()));
    assert_eq!(
        author["authorDeviceId"].as_str(),
        Some(entry.actor_device_id.hyphenated().to_string().as_str())
    );
    assert_eq!(
        author["authorKeyId"].as_str(),
        Some(entry.actor_key_id.as_str())
    );
    assert_eq!(
        STANDARD
            .decode(
                author["signaturePublicKey"]
                    .as_str()
                    .expect("metadata author signature key"),
            )
            .expect("decode metadata author signature key"),
        entry.public_key
    );
    assert_eq!(
        metadata["originTransitionId"],
        wrapper["body"]["transitionId"]
    );
    assert_eq!(
        author["originTransitionId"],
        wrapper["body"]["transitionId"]
    );
    crate::chat_protocol::transcript::decode_and_verify_signed_mutation(
        &entry.raw_wrapper,
        &entry.public_key,
    )
    .expect("metadata-author-rebound structural Creation remains genuinely signed");

    let graph = seed_genuine_creation_graph(&pool, &entry, None, None).await;

    assert_eq!(graph.protocol_instance_id, expected_protocol_instance_id);
    let durable: (Uuid, String) = sqlx::query_as(
        "SELECT protocol_instance_id,cursor_key_id \
         FROM chat.protocol_instances WHERE singleton",
    )
    .fetch_one(&pool)
    .await
    .expect("read durable singleton after graph seed");
    assert_eq!(
        durable,
        (expected_protocol_instance_id, expected_cursor_key),
        "fixture must report and preserve the preexisting durable singleton"
    );
}

/// Drops a uniquely-named per-run executor database (best-effort) when it falls
/// out of scope. Every executor test binds this guard so its private DB is torn
/// down at the end; a leaked `chat_exec_<uuid>` DB from a crashed run is
/// acceptable and identifiable by name. A fresh DB per run makes the whole
/// executor suite perfectly rerun-idempotent — no cross-run accumulation of the
/// fixed corpus creator's pending invitations (the shared-DB quota trip), and no
/// global `key_package_ref` / corpus-identity collisions — which is exactly what
/// unblocks the fixed-corpus-identity fulfillment test. The shared-DB harness
/// (`crate::common::chat_protocol::setup_chat_protocol_db`, used by every OTHER test
/// file) is left untouched.
pub struct FreshDbGuard {
    pub maintenance_url: String,
    pub db_name: String,
}

impl Drop for FreshDbGuard {
    fn drop(&mut self) {
        let maintenance_url = self.maintenance_url.clone();
        let db_name = self.db_name.clone();
        // Own thread + runtime so teardown runs during panic unwind too.
        let _ = std::thread::spawn(move || {
            let Ok(rt) = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
            else {
                return;
            };
            rt.block_on(async move {
                let Ok(admin) = PgPoolOptions::new()
                    .max_connections(1)
                    .connect(&maintenance_url)
                    .await
                else {
                    return;
                };
                // Terminate the test's still-open connections so DROP is not blocked.
                let _ = sqlx::query(
                    "SELECT pg_terminate_backend(pid) FROM pg_stat_activity \
                     WHERE datname = $1 AND pid <> pg_backend_pid()",
                )
                .bind(&db_name)
                .execute(&admin)
                .await;
                let _ = sqlx::query(&format!("DROP DATABASE IF EXISTS \"{db_name}\""))
                    .execute(&admin)
                    .await;
            });
        })
        .join();
    }
}

/// Derive the maintenance connection URL (the server's `postgres` database) from
/// `TEST_DATABASE_URL`, enforcing loopback safety exactly as the shared gate does.
pub fn maintenance_url_from_env() -> String {
    let database_url = std::env::var("TEST_DATABASE_URL")
        .expect("TEST_DATABASE_URL must name the loopback clean-chat test database");
    crate::common::chat_protocol::validate_chat_protocol_database_url(Some(&database_url))
        .expect("unsafe TEST_DATABASE_URL for the fresh-DB executor harness");
    let activation_approval = std::env::var("CHAT_OPERATION_CLAIM_ACTIVATION_APPROVED")
        .expect("CHAT_OPERATION_CLAIM_ACTIVATION_APPROVED must authorize migration 00004");
    crate::common::chat_protocol::validate_chat_protocol_activation_approval(Some(
        &activation_approval,
    ))
    .expect("invalid operation-claim activation approval");
    let mut parsed = url::Url::parse(&database_url).expect("valid TEST_DATABASE_URL");
    parsed.set_path("/postgres");
    parsed.into()
}

pub async fn fresh_executor_db() -> (PgPool, FreshDbGuard) {
    let maintenance_url = maintenance_url_from_env();
    let admin = PgPoolOptions::new()
        .max_connections(1)
        .connect(&maintenance_url)
        .await
        .expect("connect to the loopback maintenance database");
    let db_name = format!("chat_exec_{}", Uuid::new_v4().simple());
    sqlx::query(&format!("CREATE DATABASE \"{db_name}\""))
        .execute(&admin)
        .await
        .expect("create a fresh per-run executor database");
    admin.close().await;

    let mut db_url = url::Url::parse(&maintenance_url).expect("maintenance url");
    db_url.set_path(&format!("/{db_name}"));
    let pool = PgPoolOptions::new()
        .max_connections(4)
        .connect(db_url.as_str())
        .await
        .expect("connect to the fresh per-run executor database");
    let mut migration_connection = pool
        .acquire()
        .await
        .expect("acquire the exact fresh-executor migration connection");
    sqlx::query(
        "SET chat.operation_claim_activation_approved = \
         'handlers-and-legacy-apis-sealed'",
    )
    .execute(&mut *migration_connection)
    .await
    .expect("authorize operation-claim activation on the exact migration connection");
    let migration_result = sqlx::migrate!("./migrations")
        .run(&mut *migration_connection)
        .await;
    sqlx::query("RESET chat.operation_claim_activation_approved")
        .execute(&mut *migration_connection)
        .await
        .expect("reset operation-claim activation approval on the migration connection");
    migration_connection
        .close()
        .await
        .expect("close the exact fresh-executor migration connection");
    migration_result.expect("run the production migration set on the fresh executor database");
    (
        pool,
        FreshDbGuard {
            maintenance_url,
            db_name,
        },
    )
}

pub async fn setup() -> (PgPool, FreshDbGuard) {
    fresh_executor_db().await
}

/// Exact registered device facts for the signed pending roster row. This type
/// deliberately exposes no signing seed and cannot manufacture a different
/// device or authentication generation.
pub struct GenuinePendingInvitee {
    pub did: String,
    pub device_id: Uuid,
    pub dpop_jkt: String,
    pub auth_generation: u64,
    pub participant_period_id: Uuid,
}

impl GenuinePendingInvitee {
    pub fn device_identity(&self) -> DeviceIdentity {
        DeviceIdentity::new(
            PrincipalId::new(self.did.as_bytes().to_vec()).expect("genuine pending DID"),
            *self.device_id.as_bytes(),
        )
        .expect("genuine pending device identity")
    }
}

/// A private-DB genuine signed pending-Creation graph. Retaining `_database`
/// keeps the RAII database alive for the exact lifetime of the fixture.
pub struct PrivateGenuinePendingGraph {
    pub pool: PgPool,
    _database: FreshDbGuard,
    pub graph: GenuineCreationGraph,
    pub invitee: GenuinePendingInvitee,
}

impl PrivateGenuinePendingGraph {
    pub fn creator_identity(&self) -> DeviceIdentity {
        DeviceIdentity::new(
            PrincipalId::new(self.graph.creator_did.as_bytes().to_vec())
                .expect("genuine creator DID"),
            *self.graph.creator_device_id.as_bytes(),
        )
        .expect("genuine creator device identity")
    }
}

async fn private_genuine_pending_graph(kind: &str) -> PrivateGenuinePendingGraph {
    let (pool, database) = setup().await;
    let conversation_id = Uuid::new_v4();
    let (graph, invitee, _entry) =
        seed_hydratable_genuine_creation_graph_inner(&pool, conversation_id, Some(kind)).await;
    let invitee = invitee.expect("pending fixture returns its exact invitee");

    let locked_at: DateTime<Utc> =
        sqlx::query_scalar("SELECT date_trunc('milliseconds', clock_timestamp())")
            .fetch_one(&pool)
            .await
            .expect("sample pending fixture hydration instant");
    let mut tx = pool
        .begin()
        .await
        .expect("begin pending fixture production hydration");
    let locked = hydrate_locked_conversation_state(&mut tx, conversation_id, locked_at)
        .await
        .expect("pending fixture passes production aggregate hydration");
    assert_eq!(
        locked.state().participants().len(),
        2,
        "signed pending Creation has an exact two-principal roster"
    );
    assert_eq!(
        locked.state().leaves().len(),
        1,
        "the pending invitee never gains an MLS leaf"
    );
    tx.rollback()
        .await
        .expect("rollback pending fixture hydration");

    PrivateGenuinePendingGraph {
        pool,
        _database: database,
        graph,
        invitee: GenuinePendingInvitee {
            did: invitee.did,
            device_id: invitee.device_id,
            dpop_jkt: invitee.key_id,
            auth_generation: 1,
            participant_period_id: invitee.participant_period_id,
        },
    }
}

pub async fn private_genuine_group_pending_graph() -> PrivateGenuinePendingGraph {
    private_genuine_pending_graph("group").await
}

pub async fn private_genuine_direct_pending_graph() -> PrivateGenuinePendingGraph {
    private_genuine_pending_graph("direct").await
}

pub struct PrivateGenuineTerminalCloseGraph {
    pub pool: PgPool,
    _database: FreshDbGuard,
    pub graph: GenuineCreationGraph,
    pub close_entry_id: Uuid,
    pub close_transition_id: Uuid,
    pub closing_outer_entry_fingerprint: [u8; 32],
    pub terminal_seq: u64,
}

impl PrivateGenuineTerminalCloseGraph {
    pub fn schedule_proof_holder(&self) -> DeviceIdentity {
        DeviceIdentity::new(
            PrincipalId::new(self.graph.creator_did.as_bytes().to_vec())
                .expect("terminal holder DID"),
            *self.graph.creator_device_id.as_bytes(),
        )
        .expect("terminal holder identity")
    }

    pub fn closing_transition_id(&self) -> Uuid {
        self.close_transition_id
    }
}

pub async fn private_genuine_terminal_close_graph() -> PrivateGenuineTerminalCloseGraph {
    let (pool, database) = setup().await;
    let conversation_id = Uuid::new_v4();
    let (graph, pending, entry) =
        seed_hydratable_genuine_creation_graph_inner(&pool, conversation_id, None).await;
    assert!(
        pending.is_none(),
        "one-participant genuine close has no pending roster"
    );

    let locked_at: DateTime<Utc> =
        sqlx::query_scalar("SELECT date_trunc('milliseconds', clock_timestamp())")
            .fetch_one(&pool)
            .await
            .expect("sample close pre-plan hydration instant");
    let mut read = pool.begin().await.expect("begin close pre-plan hydration");
    let locked = hydrate_locked_conversation_state(&mut read, conversation_id, locked_at)
        .await
        .expect("genuine active graph hydrates before close");
    let prior = locked.state().clone();
    read.rollback().await.expect("release close pre-plan locks");

    let close = build_real_close_entry(&entry);
    let historical =
        HistoricalRehydrationAuthority::new(entry.cid, 3).expect("close historical authority");
    let transition = historical
        .hydrate_historical_control_from_durable_bytes(
            close.public_row_json.clone(),
            close.raw_wrapper.clone(),
            &entry.public_key,
        )
        .expect("genuine close re-verifies")
        .into_transition()
        .expect("close is transition evidence");
    let actor = DeviceIdentity::new(
        PrincipalId::new(entry.actor_did.as_bytes().to_vec()).expect("close actor DID"),
        *entry.actor_device_id.as_bytes(),
    )
    .expect("close actor identity");
    let planned = plan_close(
        &prior,
        CloseConversation {
            actor,
            transition: transition.clone(),
        },
    )
    .expect("genuine one-participant close plans");
    let close_timestamp =
        ServerTimestamp::from_canonical_stored(&close.received_at).expect("close timestamp");
    let mut tx = pool.begin().await.expect("begin genuine close execution");
    sqlx::query("SELECT 1 FROM chat.conversations WHERE conversation_id=$1 FOR UPDATE")
        .bind(conversation_id)
        .fetch_one(&mut *tx)
        .await
        .expect("lock genuine close head");
    let transaction_id: String = sqlx::query_scalar("SELECT txid_current()::text")
        .fetch_one(&mut *tx)
        .await
        .expect("read genuine close transaction ID");
    let plan = persistence_plan_for_test(
        planned,
        ConversationHeadCasBinding::for_test_edge_with_transaction_id(
            transaction_id,
            entry.cid,
            *close.entry_id.as_bytes(),
            *prior.coordinate(),
            2,
            close_timestamp,
        ),
    )
    .with_execution_context_authority_for_test(PlanAuthority::Transition(transition));
    let context = hydrate_execution_context_unscoped_for_test(
        &mut tx,
        &plan,
        ExecutionContextArtifacts {
            accepted_control_entry_bytes: Some(close.public_row_json.clone()),
            genesis_group_info_bytes: None,
            primary_event_payload: Some(
                format!("conversation-closed-{conversation_id}").into_bytes(),
            ),
            welcome_disposition_event_payloads: Vec::new(),
        },
    )
    .await
    .expect("production facade hydrates genuine close context");
    assert_eq!(
        context.entry_recipients,
        vec![(
            DeviceIdentity::new(
                PrincipalId::new(entry.actor_did.as_bytes().to_vec())
                    .expect("schedule recipient DID"),
                *entry.actor_device_id.as_bytes(),
            )
            .expect("schedule recipient identity"),
            EntryEntitlementKind::ScheduleTerminal,
        )]
    );
    let applied = apply_conversation_persistence_plan_unscoped_for_test(&mut tx, &plan, &context)
        .await
        .expect("production executor applies genuine close");
    assert_eq!(applied.allocated_seq, 2);
    tx.commit()
        .await
        .expect("genuine close crosses deferred constraints");

    let verify_at: DateTime<Utc> =
        sqlx::query_scalar("SELECT date_trunc('milliseconds', clock_timestamp())")
            .fetch_one(&pool)
            .await
            .expect("sample terminal verification instant");
    let mut verify = pool
        .begin()
        .await
        .expect("begin terminal aggregate verification");
    let terminal = hydrate_locked_conversation_state(&mut verify, conversation_id, verify_at)
        .await
        .expect("genuine terminal graph rehydrates after commit");
    assert_eq!(terminal.state().terminal_proofs().len(), 1);
    assert_eq!(
        terminal
            .state()
            .terminal_proof(
                &DeviceIdentity::new(
                    PrincipalId::new(entry.actor_did.as_bytes().to_vec())
                        .expect("terminal proof DID"),
                    *entry.actor_device_id.as_bytes(),
                )
                .expect("terminal proof identity"),
            )
            .expect("creator terminal schedule proof")
            .seq(),
        2
    );
    verify
        .rollback()
        .await
        .expect("rollback terminal verification");

    PrivateGenuineTerminalCloseGraph {
        pool,
        _database: database,
        graph,
        close_entry_id: close.entry_id,
        close_transition_id: close.transition_id,
        closing_outer_entry_fingerprint: close.outer_entry_fingerprint,
        terminal_seq: 2,
    }
}

pub(crate) mod genuine_terminal_fixture {
    use super::*;

    use base64::{engine::general_purpose::STANDARD, Engine};
    use chrono::SecondsFormat;
    use ed25519_dalek::{Signer, SigningKey};
    use serde_json::{json, Value};
    use sqlx::{Postgres, Transaction};

    use crate::chat_protocol::public_state::{
        encode_public_tree_summary, process_commit, rebind_active_snapshot,
    };
    use crate::chat_protocol::state_machine::{HydrationAuthority, ParticipantRole};
    use crate::chat_protocol::transcript::{
        decode_and_verify_control_entry, decode_canonical_signed_mutation,
        rebind_persisted_control_entry, SignedMutationKind,
    };
    use crate::chat_protocol::wire::{validate_public_commit, MAX_PUBLIC_MESSAGE_WIRE_BYTES};

    use openmls::prelude::{
        tls_codec::Serialize as TlsSerialize, BasicCredential, Capabilities, CredentialType,
        CredentialWithKey, GroupId, KeyPackage, LeafNodeIndex, Lifetime, MlsGroup,
        MlsGroupCreateConfig, MlsMessageOut, ProtocolVersion,
    };
    use openmls_basic_credential::SignatureKeyPair;
    use openmls_traits::OpenMlsProvider;
    use serde::Serialize;

    use crate::chat_protocol::public_state::{
        verify_genesis_group_info, verify_recovery_welcome, verify_reset_successor_group_info,
        GenesisGroupInfoExpectations, ResetSuccessorGroupInfoExpectations,
    };
    use crate::chat_protocol::wire::{
        validate_group_info, validate_key_package, GroupInfoValidationPolicy,
        KeyPackageValidationPolicy, MAX_GROUP_INFO_WIRE_BYTES, MAX_KEY_PACKAGE_WIRE_BYTES,
        MAX_WELCOME_WIRE_BYTES, XWING_CIPHERSUITE,
    };

    pub(crate) fn exact_mls_capabilities() -> Capabilities {
        Capabilities::new(
            Some(&[ProtocolVersion::Mls10]),
            Some(&[XWING_CIPHERSUITE]),
            Some(&[]),
            Some(&[]),
            Some(&[CredentialType::Basic]),
        )
    }

    #[derive(Serialize)]
    #[serde(rename_all = "camelCase")]
    struct CommitAadCoordinate<'a> {
        #[serde(with = "serde_bytes")]
        conversation_id: &'a [u8],
        generation: u64,
        state_version: u64,
        #[serde(with = "serde_bytes")]
        group_id: &'a [u8],
        epoch: u64,
        #[serde(with = "serde_bytes")]
        group_context_hash: &'a [u8],
        #[serde(with = "serde_bytes")]
        confirmation_tag: &'a [u8],
        lifecycle: &'static str,
    }

    #[derive(Serialize)]
    #[serde(rename_all = "camelCase")]
    struct CommitAadProjection<'a> {
        protocol_version: &'static str,
        #[serde(with = "serde_bytes")]
        conversation_id: &'a [u8],
        generation: u64,
        #[serde(with = "serde_bytes")]
        transition_id: &'a [u8],
        prior: CommitAadCoordinate<'a>,
    }

    pub(crate) fn encode_commit_aad(
        conversation_id: &[u8; 16],
        transition_id: &Uuid,
        prior: &PublicGroupSnapshotCoordinate,
    ) -> Vec<u8> {
        assert_eq!(prior.conversation_id(), conversation_id);
        let projection = CommitAadProjection {
            protocol_version: "1",
            conversation_id,
            generation: prior.generation(),
            transition_id: transition_id.as_bytes(),
            prior: CommitAadCoordinate {
                conversation_id,
                generation: prior.generation(),
                state_version: prior.state_version(),
                group_id: prior.group_id(),
                epoch: prior.epoch(),
                group_context_hash: prior.group_context_hash(),
                confirmation_tag: prior.confirmation_tag(),
                lifecycle: "active",
            },
        };
        let mut aad = b"CATBIRD-CHAT-MLS-AAD-COMMIT\0".to_vec();
        aad.extend(
            serde_ipld_dagcbor::to_vec(&projection).expect("encode canonical protocol Commit AAD"),
        );
        aad
    }

    struct DynamicTwoLeafCryptoFixture {
        entry: RealCreationEntry,
        invitee: AcceptanceInvitee,
        genesis_group_info: Vec<u8>,
        genesis: ActivePublicState,
        committed: ActivePublicState,
        key_package_ref: [u8; 32],
        key_package_wrapper: Vec<u8>,
        commit: Vec<u8>,
        welcome: Vec<u8>,
        remove_transition_id: Uuid,
        remove_commit: Vec<u8>,
        removed: ActivePublicState,
    }

    #[allow(clippy::too_many_arguments)]
    fn build_dynamic_two_leaf_crypto_fixture(
        cid: Uuid,
        add_transition_id: Uuid,
        invitee: AcceptanceInvitee,
        creation_at: DateTime<Utc>,
        package_evaluated_at: DateTime<Utc>,
        fulfilled_at: DateTime<Utc>,
        package_not_before: DateTime<Utc>,
        package_not_after: DateTime<Utc>,
    ) -> DynamicTwoLeafCryptoFixture {
        // The caller owns the validity interval. G6 callers derive their
        // persisted and generated KeyPackage bounds from the same sampled
        // runtime instant; fixed-corpus callers retain their historical
        // durable bounds.
        assert!(
            package_not_before <= package_evaluated_at
                && package_evaluated_at <= package_not_after
                && package_not_before <= fulfilled_at
                && fulfilled_at <= package_not_after,
            "fresh Add crypto validity must cover its supplied evaluation and fulfillment instants"
        );
        let creation_signed_at = (creation_at - chrono::Duration::milliseconds(500))
            .to_rfc3339_opts(SecondsFormat::Millis, true);
        let creation_received_at = creation_at.to_rfc3339_opts(SecondsFormat::Millis, true);
        let mut entry = build_real_creation_entry(*cid.as_bytes());
        let provider = openmls_libcrux_crypto::Provider::new().expect("fresh Add Alice provider");
        let alice_signer = SignatureKeyPair::from_raw(
            XWING_CIPHERSUITE.signature_algorithm(),
            entry.signing_seed.to_vec(),
            entry.public_key.clone(),
        );
        alice_signer
            .store(provider.storage())
            .expect("store fresh Add Alice signer");
        let alice_credential =
            format!("{}#{}", entry.actor_did, entry.actor_device_id).into_bytes();
        let lifetime = Lifetime::init(
            u64::try_from(package_not_before.timestamp())
                .expect("test crypto lifetime starts after Unix epoch"),
            u64::try_from(package_not_after.timestamp())
                .expect("test crypto lifetime ends after Unix epoch"),
        );
        let config = MlsGroupCreateConfig::builder()
            .ciphersuite(XWING_CIPHERSUITE)
            .wire_format_policy(openmls::group::PURE_PLAINTEXT_WIRE_FORMAT_POLICY)
            .use_ratchet_tree_extension(true)
            .capabilities(exact_mls_capabilities())
            .lifetime(lifetime)
            .build();
        let group_id: [u8; 32] =
            Sha256::digest([b"CATBIRD-D2-FRESH-GROUP\0".as_ref(), cid.as_bytes()].concat()).into();
        let mut alice_group = MlsGroup::new_with_group_id(
            &provider,
            &alice_signer,
            &config,
            GroupId::from_slice(&group_id),
            CredentialWithKey {
                credential: BasicCredential::new(alice_credential.clone()).into(),
                signature_key: entry.public_key.clone().into(),
            },
        )
        .expect("create fresh Add Alice group");
        let genesis_group_info = alice_group
            .export_group_info(provider.crypto(), &alice_signer, true)
            .expect("export fresh Add genesis GroupInfo")
            .tls_serialize_detached()
            .expect("serialize fresh Add genesis GroupInfo");
        let validated_genesis = validate_group_info(
            &genesis_group_info,
            GroupInfoValidationPolicy {
                expected_basic_credential: &alice_credential,
                expected_signature_key: &entry.public_key,
                now_unix_seconds: u64::try_from(creation_at.timestamp()).unwrap(),
                max_bytes: MAX_GROUP_INFO_WIRE_BYTES,
                max_ratchet_tree_bytes: MAX_GROUP_INFO_WIRE_BYTES,
                max_members: 2,
            },
        )
        .expect("production validates fresh Add genesis GroupInfo");
        let genesis_coordinate = PublicGroupSnapshotCoordinate::new(
            *cid.as_bytes(),
            0,
            0,
            validated_genesis
                .group_id()
                .try_into()
                .expect("fresh group id is 32 bytes"),
            validated_genesis.epoch(),
            *validated_genesis.group_context_hash(),
            *validated_genesis.confirmation_tag(),
            PublicGroupSnapshotLifecycle::Active,
        );
        let genesis = verify_genesis_group_info(
            &genesis_group_info,
            GenesisGroupInfoExpectations {
                coordinate: genesis_coordinate,
                expected_basic_credential: &alice_credential,
                expected_signature_key: &entry.public_key,
                now_unix_seconds: u64::try_from(creation_at.timestamp()).unwrap(),
                max_wire_bytes: MAX_GROUP_INFO_WIRE_BYTES,
                max_ratchet_tree_bytes: MAX_GROUP_INFO_WIRE_BYTES,
                max_members: 2,
            },
        )
        .expect("fresh Add genesis becomes production public state");
        entry = bind_creation_entry_to_group_info(
            entry,
            &genesis_group_info,
            &genesis_coordinate,
            &creation_signed_at,
            &creation_received_at,
        );

        let bob_provider = openmls_libcrux_crypto::Provider::new().expect("fresh Add Bob provider");
        let bob_public_key = invitee.signing_key.verifying_key().to_bytes().to_vec();
        let bob_signer = SignatureKeyPair::from_raw(
            XWING_CIPHERSUITE.signature_algorithm(),
            invitee.signing_key.to_bytes().to_vec(),
            bob_public_key.clone(),
        );
        bob_signer
            .store(bob_provider.storage())
            .expect("store fresh Add Bob signer");
        let bob_credential = format!("{}#{}", invitee.did, invitee.device_id).into_bytes();
        let key_package = KeyPackage::builder()
            .key_package_lifetime(lifetime)
            .leaf_node_capabilities(exact_mls_capabilities())
            .build(
                XWING_CIPHERSUITE,
                &bob_provider,
                &bob_signer,
                CredentialWithKey {
                    credential: BasicCredential::new(bob_credential.clone()).into(),
                    signature_key: bob_public_key.clone().into(),
                },
            )
            .expect("build fresh Add Bob KeyPackage")
            .key_package()
            .clone();
        let key_package_wrapper = MlsMessageOut::from(key_package.clone())
            .tls_serialize_detached()
            .expect("serialize fresh Add Bob KeyPackage");
        let validated_package = validate_key_package(
            &key_package_wrapper,
            KeyPackageValidationPolicy {
                expected_basic_credential: &bob_credential,
                expected_signature_key: &bob_public_key,
                now_unix_seconds: u64::try_from(package_evaluated_at.timestamp()).unwrap(),
                max_bytes: MAX_KEY_PACKAGE_WIRE_BYTES,
            },
        )
        .expect("production validates fresh Add Bob KeyPackage");
        let validated_not_before = DateTime::<Utc>::from_timestamp(
            i64::try_from(validated_package.not_before())
                .expect("validated KeyPackage not-before fits Chrono"),
            0,
        )
        .expect("validated KeyPackage not-before is representable");
        let validated_not_after = DateTime::<Utc>::from_timestamp(
            i64::try_from(validated_package.not_after())
                .expect("validated KeyPackage not-after fits Chrono"),
            0,
        )
        .expect("validated KeyPackage not-after is representable");
        assert_eq!(
            validated_not_before.timestamp_millis(),
            package_not_before.timestamp_millis(),
            "validated KeyPackage not-before must equal the persisted millisecond bound"
        );
        assert_eq!(
            validated_not_after.timestamp_millis(),
            package_not_after.timestamp_millis(),
            "validated KeyPackage not-after must equal the persisted millisecond bound"
        );
        let key_package_ref = *validated_package.key_package_ref();

        let add_prior = rebound_state(&rebound_state(&genesis, 1), 2);
        let aad = encode_commit_aad(cid.as_bytes(), &add_transition_id, add_prior.coordinate());
        alice_group.set_aad(aad.clone());
        let (commit_out, welcome_out, post_commit_group_info) = alice_group
            .add_members(&provider, &alice_signer, std::slice::from_ref(&key_package))
            .expect("generate fresh Add Commit and Welcome");
        let commit = commit_out
            .tls_serialize_detached()
            .expect("serialize fresh Add Commit");
        let welcome = welcome_out
            .tls_serialize_detached()
            .expect("serialize fresh Add Welcome");
        alice_group
            .merge_pending_commit(&provider)
            .expect("merge fresh Add locally");
        let post_commit_group_info =
            post_commit_group_info.expect("ratchet-tree profile exports post-Commit GroupInfo");
        let group_context_hash: [u8; 32] = Sha256::digest(
            post_commit_group_info
                .group_context()
                .tls_serialize_detached()
                .expect("serialize fresh Add successor GroupContext"),
        )
        .into();
        let encoded_confirmation_tag = alice_group
            .confirmation_tag()
            .tls_serialize_detached()
            .expect("serialize fresh Add confirmation tag");
        assert_eq!(
            encoded_confirmation_tag.first(),
            Some(&32),
            "XWing confirmation tag uses canonical one-byte VL length"
        );
        let confirmation_tag: [u8; 32] = encoded_confirmation_tag[1..]
            .try_into()
            .expect("fresh Add confirmation tag is 32 bytes");
        let next_coordinate = PublicGroupSnapshotCoordinate::new(
            *cid.as_bytes(),
            0,
            3,
            group_id,
            alice_group.epoch().as_u64(),
            group_context_hash,
            confirmation_tag,
            PublicGroupSnapshotLifecycle::Active,
        );
        let processed = process_commit(
            &add_prior,
            &commit,
            &aad,
            next_coordinate,
            u64::try_from(fulfilled_at.timestamp()).unwrap(),
            100,
        )
        .expect("production processes fresh Add Commit");
        assert_eq!(processed.adds().len(), 1);
        assert_eq!(processed.adds()[0].key_package_ref(), &key_package_ref);
        verify_recovery_welcome(&welcome, key_package_ref, MAX_WELCOME_WIRE_BYTES)
            .expect("production binds fresh Welcome to fresh KeyPackageRef");
        let committed = processed.into_next();

        let remove_transition_id = Uuid::new_v4();
        let remove_aad = encode_commit_aad(
            cid.as_bytes(),
            &remove_transition_id,
            committed.coordinate(),
        );
        alice_group.set_aad(remove_aad.clone());
        let (remove_out, _, post_remove_group_info) = alice_group
            .remove_members(&provider, &alice_signer, &[LeafNodeIndex::new(1)])
            .expect("generate fresh Bob Remove Commit");
        let remove_commit = remove_out
            .tls_serialize_detached()
            .expect("serialize fresh Bob Remove Commit");
        alice_group
            .merge_pending_commit(&provider)
            .expect("merge fresh Bob Remove locally");
        let post_remove_group_info =
            post_remove_group_info.expect("ratchet-tree profile exports Remove GroupInfo");
        let remove_group_context_hash: [u8; 32] = Sha256::digest(
            post_remove_group_info
                .group_context()
                .tls_serialize_detached()
                .expect("serialize fresh Remove successor GroupContext"),
        )
        .into();
        let remove_confirmation = alice_group
            .confirmation_tag()
            .tls_serialize_detached()
            .expect("serialize fresh Remove confirmation tag");
        assert_eq!(remove_confirmation.first(), Some(&32));
        let remove_confirmation_tag: [u8; 32] = remove_confirmation[1..]
            .try_into()
            .expect("fresh Remove confirmation tag is 32 bytes");
        let removed_coordinate = PublicGroupSnapshotCoordinate::new(
            *cid.as_bytes(),
            0,
            4,
            group_id,
            alice_group.epoch().as_u64(),
            remove_group_context_hash,
            remove_confirmation_tag,
            PublicGroupSnapshotLifecycle::Active,
        );
        let removed = process_commit(
            &committed,
            &remove_commit,
            &remove_aad,
            removed_coordinate,
            u64::try_from((fulfilled_at + chrono::Duration::seconds(3)).timestamp()).unwrap(),
            100,
        )
        .expect("production processes fresh Bob Remove Commit")
        .into_next();

        DynamicTwoLeafCryptoFixture {
            entry,
            invitee,
            genesis_group_info,
            genesis,
            committed,
            key_package_ref,
            key_package_wrapper,
            commit,
            welcome,
            remove_transition_id,
            remove_commit,
            removed,
        }
    }

    const DYNAMIC_BOB_SIGNING_SEED: [u8; 32] = [
        0xd4, 0xa1, 0xc4, 0x8e, 0x33, 0x92, 0x40, 0x8e, 0x24, 0x40, 0x90, 0x3f, 0xc5, 0x67, 0x8d,
        0xa5, 0x69, 0x98, 0xeb, 0x66, 0xeb, 0xb8, 0xa9, 0x64, 0xa7, 0xe4, 0xe4, 0xc2, 0xad, 0x82,
        0xe9, 0xb5,
    ];

    pub(crate) struct GenuineCommitControl {
        pub(crate) entry_id: Uuid,
        pub(crate) transition_id: Uuid,
        pub(crate) public_row_json: Vec<u8>,
        pub(crate) raw_wrapper: Vec<u8>,
        pub(crate) canonical_projection: Vec<u8>,
        pub(crate) signing_transcript: Vec<u8>,
        pub(crate) request_digest: Vec<u8>,
        pub(crate) signature: Vec<u8>,
        pub(crate) server_fields: Vec<u8>,
        pub(crate) outer_fingerprint: [u8; 32],
        pub(crate) metadata_nonce: Vec<u8>,
        pub(crate) metadata_ciphertext: Vec<u8>,
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn build_genuine_commit_control_with_bytes(
        entry: &RealCreationEntry,
        creation_transition_id: Uuid,
        kind: SignedMutationKind,
        entry_kind: &str,
        transition_id: Uuid,
        prior: &PublicGroupSnapshotCoordinate,
        next: &PublicGroupSnapshotCoordinate,
        seq: u64,
        signed_at: &str,
        received_at: &str,
        commit_bytes: Vec<u8>,
        participant_changes: Vec<Value>,
        leaf_changes: Vec<Value>,
        leave_request_id: Option<Uuid>,
        nonce_byte: u8,
        ciphertext_byte: u8,
    ) -> GenuineCommitControl {
        let signing_key = entry.signing_key();
        let entry_id = Uuid::new_v4();
        let metadata_nonce = vec![nonce_byte; 12];
        let metadata_ciphertext = vec![ciphertext_byte; 16];
        let mut body = json!({
            "$type": kind.type_id(),
            "signatureDomain": String::from_utf8(kind.domain().to_vec()).unwrap(),
            "transitionId": transition_id,
            "actorDid": &entry.actor_did,
            "actorDeviceId": entry.actor_device_id,
            "keyId": &entry.actor_key_id,
            "authGeneration": 1,
            "prior": coordinate_json(prior),
            "next": coordinate_json(next),
            "aad": {
                "protocolVersion": "1",
                "conversationId": STANDARD.encode(entry.cid),
                "generation": prior.generation(),
                "transitionId": STANDARD.encode(transition_id.as_bytes()),
                "prior": {
                    "conversationId": STANDARD.encode(entry.cid),
                    "generation": prior.generation(),
                    "stateVersion": prior.state_version(),
                    "groupId": STANDARD.encode(prior.group_id()),
                    "epoch": prior.epoch(),
                    "groupContextHash": STANDARD.encode(prior.group_context_hash()),
                    "confirmationTag": STANDARD.encode(prior.confirmation_tag()),
                    "lifecycle": "active",
                },
            },
            "manifest": {
                "participantChanges": participant_changes,
                "leafChanges": leaf_changes,
            },
            "commit": {
                "framing": "mlsMessage",
                "contentType": "publicMessageCommit",
                "bytes": STANDARD.encode(&commit_bytes),
                "sha256": STANDARD.encode(Sha256::digest(&commit_bytes)),
            },
            "metadataSnapshot": {
                "coordinate": {
                    "conversationId": STANDARD.encode(entry.cid),
                    "generation": next.generation(),
                    "groupId": STANDARD.encode(next.group_id()),
                    "epoch": next.epoch(),
                    "groupContextHash": STANDARD.encode(next.group_context_hash()),
                    "confirmationTag": STANDARD.encode(next.confirmation_tag()),
                },
                "originTransitionId": creation_transition_id,
                "metadataVersion": 1,
                "nonce": STANDARD.encode(&metadata_nonce),
                "ciphertext": STANDARD.encode(&metadata_ciphertext),
                "ciphertextSha256": STANDARD.encode(Sha256::digest(&metadata_ciphertext)),
                "ciphertextSize": metadata_ciphertext.len(),
                "authorProof": {
                    "authorDid": &entry.actor_did,
                    "authorDeviceId": entry.actor_device_id,
                    "authorKeyId": &entry.actor_key_id,
                    "signaturePublicKey": STANDARD.encode(&entry.public_key),
                    "authGenerationAtOrigin": 1,
                    "originTransitionId": creation_transition_id,
                    "originSeq": 1,
                    "roleAtOrigin": "admin",
                    "deviceStatusAtOrigin": "active",
                },
            },
            "idempotencyKey": Uuid::new_v4(),
            "signedAt": signed_at,
        });
        if let Some(leave_request_id) = leave_request_id {
            body["leaveRequestId"] = json!(leave_request_id);
        }
        let mut wrapper = json!({"body": body, "signature": STANDARD.encode([0_u8; 64])});
        let unsigned = serde_json::to_vec(&wrapper).unwrap();
        let unsigned =
            decode_canonical_signed_mutation(&unsigned).expect("fixed-corpus Commit canonicalizes");
        wrapper["signature"] = Value::String(
            STANDARD.encode(signing_key.sign(unsigned.transcript_bytes()).to_bytes()),
        );
        let raw_wrapper = serde_json::to_vec(&wrapper).unwrap();
        let canonical = decode_canonical_signed_mutation(&raw_wrapper)
            .expect("signed fixed-corpus Commit canonicalizes");
        let public_row_json = serde_json::to_vec(&json!({
            "$type": entry_kind,
            "entryId": entry_id,
            "conversationId": Uuid::from_bytes(entry.cid),
            "seq": seq,
            "signedRequest": wrapper,
            "receivedAt": received_at,
        }))
        .unwrap();
        let decoded = decode_and_verify_control_entry(&public_row_json, &entry.public_key)
            .expect("fixed-corpus Commit control verifies");
        GenuineCommitControl {
            entry_id,
            transition_id,
            public_row_json,
            raw_wrapper,
            canonical_projection: canonical.canonical_projection().to_vec(),
            signing_transcript: canonical.transcript_bytes().to_vec(),
            request_digest: canonical.request_digest().to_vec(),
            signature: canonical.signature().to_vec(),
            server_fields: decoded
                .server_fields_dag_cbor()
                .expect("fixed-corpus Commit server fields"),
            outer_fingerprint: *decoded.outer_control_fingerprint(),
            metadata_nonce,
            metadata_ciphertext,
        }
    }

    pub(crate) struct GenuineLeaveRequest {
        pub(crate) request_id: Uuid,
        pub(crate) entry_id: Uuid,
        pub(crate) public_row_json: Vec<u8>,
        pub(crate) raw_wrapper: Vec<u8>,
        pub(crate) signing_transcript: Vec<u8>,
        pub(crate) request_digest: Vec<u8>,
        pub(crate) signature: Vec<u8>,
        pub(crate) server_fields: Vec<u8>,
        pub(crate) outer_fingerprint: [u8; 32],
    }

    pub(crate) fn build_genuine_leave_request(
        entry: &RealCreationEntry,
        invitee: &AcceptanceInvitee,
        prior: &PublicGroupSnapshotCoordinate,
        seq: u64,
        signed_at: &str,
        received_at: &str,
    ) -> GenuineLeaveRequest {
        let request_id = Uuid::new_v4();
        let entry_id = Uuid::new_v4();
        let kind = SignedMutationKind::LeaveRequest;
        let mut wrapper = json!({
            "body": {
                "$type": kind.type_id(),
                "signatureDomain": String::from_utf8(kind.domain().to_vec()).unwrap(),
                "leaveRequestId": request_id,
                "actorDid": &invitee.did,
                "actorDeviceId": invitee.device_id,
                "keyId": &invitee.key_id,
                "authGeneration": 1,
                "prior": coordinate_json(prior),
                "idempotencyKey": Uuid::new_v4(),
                "signedAt": signed_at,
            },
            "signature": STANDARD.encode([0_u8; 64]),
        });
        let unsigned = decode_canonical_signed_mutation(&serde_json::to_vec(&wrapper).unwrap())
            .expect("leave request canonicalizes");
        wrapper["signature"] = Value::String(
            STANDARD.encode(
                invitee
                    .signing_key
                    .sign(unsigned.transcript_bytes())
                    .to_bytes(),
            ),
        );
        let raw_wrapper = serde_json::to_vec(&wrapper).unwrap();
        let canonical = decode_canonical_signed_mutation(&raw_wrapper)
            .expect("signed leave request canonicalizes");
        let public_row_json = serde_json::to_vec(&json!({
            "$type": "blue.catbird.chat.defs#leaveRequestEntry",
            "entryId": entry_id,
            "conversationId": Uuid::from_bytes(entry.cid),
            "seq": seq,
            "signedRequest": wrapper,
            "receivedAt": received_at,
        }))
        .unwrap();
        let decoded = decode_and_verify_control_entry(
            &public_row_json,
            invitee.signing_key.verifying_key().as_bytes(),
        )
        .expect("genuine Bob leave request verifies");
        GenuineLeaveRequest {
            request_id,
            entry_id,
            public_row_json,
            raw_wrapper,
            signing_transcript: canonical.transcript_bytes().to_vec(),
            request_digest: canonical.request_digest().to_vec(),
            signature: canonical.signature().to_vec(),
            server_fields: decoded
                .server_fields_dag_cbor()
                .expect("leave request server fields"),
            outer_fingerprint: *decoded.outer_control_fingerprint(),
        }
    }

    struct GenuineResetRequest {
        request_id: Uuid,
        entry_id: Uuid,
        public_row_json: Vec<u8>,
        raw_wrapper: Vec<u8>,
        signing_transcript: Vec<u8>,
        request_digest: Vec<u8>,
        signature: Vec<u8>,
        server_fields: Vec<u8>,
        outer_fingerprint: [u8; 32],
    }

    fn build_genuine_reset_request(
        entry: &RealCreationEntry,
        prior: &PublicGroupSnapshotCoordinate,
        seq: u64,
        signed_at: &str,
        received_at: &str,
    ) -> GenuineResetRequest {
        let request_id = Uuid::new_v4();
        let entry_id = Uuid::new_v4();
        let kind = SignedMutationKind::ResetRequest;
        let mut wrapper = json!({
            "body": {
                "$type": kind.type_id(),
                "signatureDomain": String::from_utf8(kind.domain().to_vec()).unwrap(),
                "resetRequestId": request_id,
                "actorDid": &entry.actor_did,
                "actorDeviceId": entry.actor_device_id,
                "keyId": &entry.actor_key_id,
                "authGeneration": 1,
                "prior": coordinate_json(prior),
                "reason": "manualRecovery",
                "idempotencyKey": Uuid::new_v4(),
                "signedAt": signed_at,
            },
            "signature": STANDARD.encode([0_u8; 64]),
        });
        let unsigned = decode_canonical_signed_mutation(&serde_json::to_vec(&wrapper).unwrap())
            .expect("reset request canonicalizes");
        wrapper["signature"] = Value::String(
            STANDARD.encode(
                entry
                    .signing_key()
                    .sign(unsigned.transcript_bytes())
                    .to_bytes(),
            ),
        );
        let raw_wrapper = serde_json::to_vec(&wrapper).unwrap();
        let canonical = decode_canonical_signed_mutation(&raw_wrapper)
            .expect("signed reset request canonicalizes");
        let public_row_json = serde_json::to_vec(&json!({
            "$type": "blue.catbird.chat.defs#resetRequestEntry",
            "entryId": entry_id,
            "conversationId": Uuid::from_bytes(entry.cid),
            "seq": seq,
            "signedRequest": wrapper,
            "receivedAt": received_at,
        }))
        .unwrap();
        let decoded = decode_and_verify_control_entry(&public_row_json, &entry.public_key)
            .expect("genuine reset request verifies");
        GenuineResetRequest {
            request_id,
            entry_id,
            public_row_json,
            raw_wrapper,
            signing_transcript: canonical.transcript_bytes().to_vec(),
            request_digest: canonical.request_digest().to_vec(),
            signature: canonical.signature().to_vec(),
            server_fields: decoded
                .server_fields_dag_cbor()
                .expect("reset request server fields"),
            outer_fingerprint: *decoded.outer_control_fingerprint(),
        }
    }

    struct GenuineResetActivation {
        entry_id: Uuid,
        transition_id: Uuid,
        public_row_json: Vec<u8>,
        raw_wrapper: Vec<u8>,
        canonical_projection: Vec<u8>,
        signing_transcript: Vec<u8>,
        request_digest: Vec<u8>,
        signature: Vec<u8>,
        server_fields: Vec<u8>,
        outer_fingerprint: [u8; 32],
        group_info: Vec<u8>,
        successor_public_state: ActivePublicState,
    }

    fn reset_retired_coordinate_json(prior: &PublicGroupSnapshotCoordinate) -> Value {
        json!({
            "conversationId": Uuid::from_bytes(*prior.conversation_id()),
            "generation": prior.generation(),
            "stateVersion": prior.state_version() + 1,
            "groupId": STANDARD.encode(prior.group_id()),
            "epoch": prior.epoch(),
            "groupContextHash": STANDARD.encode(prior.group_context_hash()),
            "confirmationTag": STANDARD.encode(prior.confirmation_tag()),
            "lifecycle": "superseded",
        })
    }

    fn build_genuine_reset_activation(
        entry: &RealCreationEntry,
        request: &GenuineResetRequest,
        prior: &PublicGroupSnapshotCoordinate,
        participants: Value,
        at: DateTime<Utc>,
    ) -> GenuineResetActivation {
        let unix_seconds = u64::try_from(at.timestamp()).expect("reset time is positive");
        let provider = openmls_libcrux_crypto::Provider::new().expect("reset libcrux provider");
        let signer = SignatureKeyPair::from_raw(
            XWING_CIPHERSUITE.signature_algorithm(),
            entry.signing_seed.to_vec(),
            entry.public_key.clone(),
        );
        signer
            .store(provider.storage())
            .expect("store reset actor signer");
        let credential = format!("{}#{}", entry.actor_did, entry.actor_device_id).into_bytes();
        let config = MlsGroupCreateConfig::builder()
            .ciphersuite(XWING_CIPHERSUITE)
            .wire_format_policy(openmls::group::PURE_PLAINTEXT_WIRE_FORMAT_POLICY)
            .use_ratchet_tree_extension(true)
            .capabilities(exact_mls_capabilities())
            .lifetime(Lifetime::init(unix_seconds - 60, unix_seconds + 3_600))
            .build();
        let group_id: [u8; 32] = Sha256::digest(
            [
                b"CATBIRD-G7-RESET-SUCCESSOR\0".as_ref(),
                entry.cid.as_ref(),
                request.request_id.as_bytes(),
            ]
            .concat(),
        )
        .into();
        let group = MlsGroup::new_with_group_id(
            &provider,
            &signer,
            &config,
            GroupId::from_slice(&group_id),
            CredentialWithKey {
                credential: BasicCredential::new(credential.clone()).into(),
                signature_key: entry.public_key.clone().into(),
            },
        )
        .expect("create genuine reset successor group");
        let group_info = group
            .export_group_info(provider.crypto(), &signer, true)
            .expect("export genuine reset GroupInfo")
            .tls_serialize_detached()
            .expect("serialize genuine reset GroupInfo");
        let validated = validate_group_info(
            &group_info,
            GroupInfoValidationPolicy {
                expected_basic_credential: &credential,
                expected_signature_key: &entry.public_key,
                now_unix_seconds: unix_seconds,
                max_bytes: MAX_GROUP_INFO_WIRE_BYTES,
                max_ratchet_tree_bytes: MAX_GROUP_INFO_WIRE_BYTES,
                max_members: 1,
            },
        )
        .expect("genuine reset GroupInfo validates");
        let validated_group_id: [u8; 32] = validated
            .group_id()
            .try_into()
            .expect("reset group id is 32 bytes");
        let successor_coordinate = PublicGroupSnapshotCoordinate::new(
            entry.cid,
            prior.generation() + 1,
            0,
            validated_group_id,
            0,
            *validated.group_context_hash(),
            *validated.confirmation_tag(),
            PublicGroupSnapshotLifecycle::Active,
        );
        let successor_public_state = verify_reset_successor_group_info(
            &group_info,
            prior,
            ResetSuccessorGroupInfoExpectations {
                coordinate: successor_coordinate,
                expected_basic_credential: &credential,
                expected_signature_key: &entry.public_key,
                now_unix_seconds: unix_seconds,
                max_wire_bytes: MAX_GROUP_INFO_WIRE_BYTES,
                max_ratchet_tree_bytes: MAX_GROUP_INFO_WIRE_BYTES,
                max_members: 1,
            },
        )
        .expect("reset successor binds to exact signed coordinate");
        let transition_id = Uuid::new_v4();
        let entry_id = Uuid::new_v4();
        let received_at = at.to_rfc3339_opts(SecondsFormat::Millis, true);
        let signed_at =
            (at - chrono::Duration::milliseconds(500)).to_rfc3339_opts(SecondsFormat::Millis, true);
        let metadata_nonce = [0xb1_u8; 12];
        let metadata_ciphertext = [0xb2_u8; 16];
        let body = json!({
            "$type": SignedMutationKind::ResetActivation.type_id(),
            "signatureDomain": String::from_utf8(
                SignedMutationKind::ResetActivation.domain().to_vec()
            ).unwrap(),
            "resetRequestId": request.request_id,
            "transitionId": transition_id,
            "conversationKind": "group",
            "actorDid": &entry.actor_did,
            "actorDeviceId": entry.actor_device_id,
            "keyId": &entry.actor_key_id,
            "authGeneration": 1,
            "prior": coordinate_json(prior),
            "retired": reset_retired_coordinate_json(prior),
            "successor": coordinate_json(&successor_coordinate),
            "manifest": {
                "participants": participants,
                "actorLeaf": {
                    "userDid": &entry.actor_did,
                    "deviceId": entry.actor_device_id,
                    "leafOrigin": "genesis",
                },
            },
            "genesisGroupInfo": {
                "framing": "mlsMessage",
                "contentType": "groupInfo",
                "bytes": STANDARD.encode(&group_info),
                "sha256": STANDARD.encode(Sha256::digest(&group_info)),
            },
            "metadataSnapshot": {
                "coordinate": {
                    "conversationId": STANDARD.encode(entry.cid),
                    "generation": successor_coordinate.generation(),
                    "groupId": STANDARD.encode(successor_coordinate.group_id()),
                    "epoch": successor_coordinate.epoch(),
                    "groupContextHash": STANDARD.encode(successor_coordinate.group_context_hash()),
                    "confirmationTag": STANDARD.encode(successor_coordinate.confirmation_tag()),
                },
                "originTransitionId": transition_id,
                "metadataVersion": 2,
                "nonce": STANDARD.encode(metadata_nonce),
                "ciphertext": STANDARD.encode(metadata_ciphertext),
                "ciphertextSha256": STANDARD.encode(Sha256::digest(metadata_ciphertext)),
                "ciphertextSize": metadata_ciphertext.len(),
                "authorProof": {
                    "authorDid": &entry.actor_did,
                    "authorDeviceId": entry.actor_device_id,
                    "authorKeyId": &entry.actor_key_id,
                    "signaturePublicKey": STANDARD.encode(&entry.public_key),
                    "authGenerationAtOrigin": 1,
                    "originTransitionId": transition_id,
                    "originSeq": 6,
                    "roleAtOrigin": "admin",
                    "deviceStatusAtOrigin": "active",
                },
            },
            "idempotencyKey": Uuid::new_v4(),
            "signedAt": signed_at,
        });
        let mut wrapper = json!({"body": body, "signature": STANDARD.encode([0_u8; 64])});
        let unsigned = decode_canonical_signed_mutation(&serde_json::to_vec(&wrapper).unwrap())
            .expect("unsigned reset activation canonicalizes");
        wrapper["signature"] = Value::String(
            STANDARD.encode(
                entry
                    .signing_key()
                    .sign(unsigned.transcript_bytes())
                    .to_bytes(),
            ),
        );
        let raw_wrapper = serde_json::to_vec(&wrapper).expect("serialize signed reset");
        let canonical = decode_canonical_signed_mutation(&raw_wrapper)
            .expect("signed reset activation canonicalizes");
        let public_row_json = serde_json::to_vec(&json!({
            "$type": "blue.catbird.chat.defs#resetActivationEntry",
            "entryId": entry_id,
            "conversationId": Uuid::from_bytes(entry.cid),
            "seq": 6,
            "signedRequest": wrapper,
            "receivedAt": received_at,
        }))
        .expect("serialize reset activation entry");
        let decoded = decode_and_verify_control_entry(&public_row_json, &entry.public_key)
            .expect("genuine reset activation verifies");
        GenuineResetActivation {
            entry_id,
            transition_id,
            public_row_json,
            raw_wrapper,
            canonical_projection: canonical.canonical_projection().to_vec(),
            signing_transcript: canonical.transcript_bytes().to_vec(),
            request_digest: canonical.request_digest().to_vec(),
            signature: canonical.signature().to_vec(),
            server_fields: decoded
                .server_fields_dag_cbor()
                .expect("reset activation server fields"),
            outer_fingerprint: *decoded.outer_control_fingerprint(),
            group_info,
            successor_public_state,
        }
    }

    pub(crate) fn coordinate_json(coordinate: &PublicGroupSnapshotCoordinate) -> Value {
        json!({
            "conversationId": Uuid::from_bytes(*coordinate.conversation_id()),
            "generation": coordinate.generation(),
            "stateVersion": coordinate.state_version(),
            "groupId": STANDARD.encode(coordinate.group_id()),
            "epoch": coordinate.epoch(),
            "groupContextHash": STANDARD.encode(coordinate.group_context_hash()),
            "confirmationTag": STANDARD.encode(coordinate.confirmation_tag()),
            "lifecycle": "active",
        })
    }

    pub(crate) fn rebound_state(
        template: &ActivePublicState,
        state_version: u64,
    ) -> ActivePublicState {
        let prior = template.coordinate();
        assert_eq!(state_version, prior.state_version() + 1);
        rebind_active_snapshot(
            template,
            PublicGroupSnapshotCoordinate::new(
                *prior.conversation_id(),
                prior.generation(),
                state_version,
                *prior.group_id(),
                prior.epoch(),
                *prior.group_context_hash(),
                *prior.confirmation_tag(),
                PublicGroupSnapshotLifecycle::Active,
            ),
        )
        .expect("coordinate-only edge rebinds through production validation")
    }

    fn dynamic_invitee() -> AcceptanceInvitee {
        let signing_key = SigningKey::from_bytes(&DYNAMIC_BOB_SIGNING_SEED);
        let public_key = signing_key.verifying_key().to_bytes();
        AcceptanceInvitee {
            did: "did:plc:bobterminalccccccccccccc".to_owned(),
            device_id: Uuid::new_v4(),
            key_id: ed25519_key_id(&public_key)
                .expect("dynamic Bob key id")
                .as_str()
                .to_owned(),
            signing_key,
            participant_period_id: Uuid::new_v4(),
        }
    }

    fn instant(text: &str) -> DateTime<Utc> {
        DateTime::parse_from_rfc3339(text)
            .expect("canonical fixture instant")
            .with_timezone(&Utc)
    }

    pub(crate) enum GenuinePolicyChange<'a> {
        Add(&'a str),
        Remove(&'a str),
        ChangeRole(&'a str, ParticipantRole),
    }

    pub(crate) struct GenuinePolicyControl {
        pub(crate) transition: TransitionEvidence,
        pub(crate) entry: ControlEntryContent,
        pub(crate) transition_id: Uuid,
        pub(crate) received_at: ServerTimestamp,
        pub(crate) received_at_db: DateTime<Utc>,
    }

    pub(crate) fn genuine_policy_control(
        entry: &RealCreationEntry,
        prior: &PublicGroupSnapshotCoordinate,
        seq: u64,
        at: &str,
        mut changes: Vec<GenuinePolicyChange<'_>>,
    ) -> GenuinePolicyControl {
        changes.sort_by(|left, right| {
            let left = match left {
                GenuinePolicyChange::Add(did)
                | GenuinePolicyChange::Remove(did)
                | GenuinePolicyChange::ChangeRole(did, _) => did.as_bytes(),
            };
            let right = match right {
                GenuinePolicyChange::Add(did)
                | GenuinePolicyChange::Remove(did)
                | GenuinePolicyChange::ChangeRole(did, _) => did.as_bytes(),
            };
            left.cmp(right)
        });
        let transition_id = Uuid::new_v4();
        let entry_id = Uuid::new_v4();
        let next = PublicGroupSnapshotCoordinate::new(
            *prior.conversation_id(),
            prior.generation(),
            prior.state_version() + 1,
            *prior.group_id(),
            prior.epoch(),
            *prior.group_context_hash(),
            *prior.confirmation_tag(),
            PublicGroupSnapshotLifecycle::Active,
        );
        let participant_changes: Vec<Value> = changes
            .into_iter()
            .map(|change| match change {
                GenuinePolicyChange::Add(did) => json!({
                    "$type": "blue.catbird.chat.defs#addParticipant",
                    "userDid": did,
                    "status": "pending",
                    "role": "member",
                    "invitationProvenance": {
                        "invitedByDid": &entry.actor_did,
                        "invitedByDeviceId": entry.actor_device_id,
                        "invitationTransitionId": transition_id,
                    },
                }),
                GenuinePolicyChange::Remove(did) => json!({
                    "$type": "blue.catbird.chat.defs#removeParticipant",
                    "userDid": did,
                }),
                GenuinePolicyChange::ChangeRole(did, role) => json!({
                    "$type": "blue.catbird.chat.defs#changeParticipantRole",
                    "userDid": did,
                    "role": match role {
                        ParticipantRole::Member => "member",
                        ParticipantRole::Admin => "admin",
                    },
                }),
            })
            .collect();
        let signed_at = (instant(at) - chrono::Duration::milliseconds(500))
            .to_rfc3339_opts(SecondsFormat::Millis, true);
        let body = json!({
            "$type": SignedMutationKind::PolicyTransition.type_id(),
            "signatureDomain": String::from_utf8(
                SignedMutationKind::PolicyTransition.domain().to_vec()
            ).unwrap(),
            "transitionId": transition_id,
            "actorDid": &entry.actor_did,
            "actorDeviceId": entry.actor_device_id,
            "keyId": &entry.actor_key_id,
            "authGeneration": 1,
            "prior": coordinate_json(prior),
            "next": coordinate_json(&next),
            "participantChanges": participant_changes,
            "idempotencyKey": Uuid::new_v4(),
            "signedAt": signed_at,
        });
        let mut wrapper = json!({"body": body, "signature": STANDARD.encode([0_u8; 64])});
        let unsigned = serde_json::to_vec(&wrapper).unwrap();
        let unsigned_canonical =
            decode_canonical_signed_mutation(&unsigned).expect("policy canonicalizes");
        let signature = entry
            .signing_key()
            .sign(unsigned_canonical.transcript_bytes())
            .to_bytes();
        wrapper["signature"] = Value::String(STANDARD.encode(signature));
        let raw_wrapper = serde_json::to_vec(&wrapper).unwrap();
        let canonical =
            decode_canonical_signed_mutation(&raw_wrapper).expect("signed policy canonical");
        let row = json!({
            "$type": "blue.catbird.chat.defs#policyEntry",
            "entryId": entry_id,
            "conversationId": Uuid::from_bytes(entry.cid),
            "seq": seq,
            "signedRequest": wrapper,
            "receivedAt": at,
        });
        let accepted_payload = serde_json::to_vec(&row).unwrap();
        let verified = decode_and_verify_control_entry(&accepted_payload, &entry.public_key)
            .expect("genuine policy control verifies");
        let verified = rebind_persisted_control_entry(verified, &raw_wrapper, &entry.public_key)
            .expect("policy accepted wrapper rebinds");
        let outer = *verified.outer_control_fingerprint();
        let server_fields = verified
            .server_fields_dag_cbor()
            .expect("policy server fields");
        let authority = HydrationAuthority::new(entry.cid).expect("policy authority");
        let transition = authority
            .control_transition(verified)
            .expect("policy transition authority");
        GenuinePolicyControl {
            transition,
            entry: ControlEntryContent {
                entry_id,
                entry_kind: "blue.catbird.chat.defs#policyEntry".to_owned(),
                accepted_payload_bytes: accepted_payload.clone(),
                accepted_payload_sha256: Sha256::digest(&accepted_payload).to_vec(),
                signed_request_bytes: raw_wrapper,
                unsigned_projection_bytes: canonical.canonical_projection().to_vec(),
                signing_transcript_bytes: canonical.transcript_bytes().to_vec(),
                request_digest: canonical.request_digest().to_vec(),
                signature: signature.to_vec(),
                server_fields_bytes: server_fields,
                outer_entry_fingerprint: outer.to_vec(),
            },
            transition_id,
            received_at: ServerTimestamp::from_canonical_stored(at)
                .expect("policy server timestamp"),
            received_at_db: instant(at),
        }
    }

    pub(crate) struct AcceptanceInvitee {
        pub(crate) did: String,
        pub(crate) device_id: Uuid,
        pub(crate) key_id: String,
        pub(crate) signing_key: SigningKey,
        pub(crate) participant_period_id: Uuid,
    }

    pub(crate) struct RealAcceptanceEntry {
        pub(crate) entry_id: Uuid,
        pub(crate) transition_id: Uuid,
        pub(crate) request_id: [u8; 16],
        pub(crate) key_package_ref: [u8; 32],
        pub(crate) key_package_wrapper: Vec<u8>,
        pub(crate) public_row_json: Vec<u8>,
        pub(crate) raw_wrapper: Vec<u8>,
        pub(crate) unsigned_projection: Vec<u8>,
        pub(crate) signing_transcript: Vec<u8>,
        pub(crate) request_digest: Vec<u8>,
        pub(crate) signature: Vec<u8>,
        pub(crate) server_fields: Vec<u8>,
        pub(crate) outer_fingerprint: [u8; 32],
    }

    pub(crate) fn build_real_acceptance_entry_at(
        entry: &RealCreationEntry,
        invitee: &AcceptanceInvitee,
        invitation_transition_id: Uuid,
        prior: Value,
        seq: u64,
        signed_at: &str,
        received_at: &str,
        expires_at: &str,
        corpus_package: Option<([u8; 32], Vec<u8>)>,
    ) -> RealAcceptanceEntry {
        let entry_id = Uuid::new_v4();
        let transition_id = Uuid::new_v4();
        let request_id = *Uuid::new_v4().as_bytes();
        let (key_package_ref, key_package_wrapper) = corpus_package.unwrap_or_else(|| {
            (
                Sha256::digest([b"acceptance-kp".as_ref(), &request_id].concat()).into(),
                [b"genuine-acceptance-package".as_ref(), &request_id].concat(),
            )
        });
        let key_package_sha: [u8; 32] = Sha256::digest(&key_package_wrapper).into();
        let mut next = prior.clone();
        next["stateVersion"] = json!(prior["stateVersion"].as_u64().unwrap() + 1);
        let body = json!({
            "$type": SignedMutationKind::ParticipantAcceptance.type_id(),
            "signatureDomain": String::from_utf8(
                SignedMutationKind::ParticipantAcceptance.domain().to_vec()
            ).unwrap(),
            "actorDid": &invitee.did,
            "actorDeviceId": invitee.device_id.hyphenated().to_string(),
            "keyId": &invitee.key_id,
            "authGeneration": 1,
            "idempotencyKey": Uuid::new_v4().hyphenated().to_string(),
            "signedAt": signed_at,
            "transitionId": transition_id.hyphenated().to_string(),
            "prior": prior,
            "next": next.clone(),
            "recoveryRequestId": Uuid::from_bytes(request_id).hyphenated().to_string(),
            "invitationProvenance": {
                "invitationTransitionId": invitation_transition_id.hyphenated().to_string(),
                "invitedByDid": &entry.actor_did,
                "invitedByDeviceId": entry.actor_device_id.hyphenated().to_string(),
            }
        });
        let mut wrapper = json!({"body": body, "signature": STANDARD.encode([0_u8; 64])});
        let canonical =
            decode_canonical_signed_mutation(&serde_json::to_vec(&wrapper).unwrap()).unwrap();
        let signing_transcript = canonical.transcript_bytes().to_vec();
        let signature = invitee.signing_key.sign(&signing_transcript).to_bytes();
        wrapper["signature"] = Value::String(STANDARD.encode(signature));
        let raw_wrapper = serde_json::to_vec(&wrapper).unwrap();
        let recovery = json!({
            "recoveryRequestId": Uuid::from_bytes(request_id).hyphenated().to_string(),
            "conversationId": Uuid::from_bytes(entry.cid).hyphenated().to_string(),
            "requesterDid": &invitee.did,
            "requesterDeviceId": invitee.device_id.hyphenated().to_string(),
            "recoveryKind": "add",
            "boundCoordinate": next.clone(),
            "reservation": {
                "recoveryRequestId": Uuid::from_bytes(request_id).hyphenated().to_string(),
                "conversationId": Uuid::from_bytes(entry.cid).hyphenated().to_string(),
                "boundCoordinate": next,
                "requesterDid": &invitee.did,
                "requesterDeviceId": invitee.device_id.hyphenated().to_string(),
                "requesterKeyId": &invitee.key_id,
                "requesterAuthGeneration": 1,
                "keyPackageRef": STANDARD.encode(key_package_ref),
                "cipherSuite": "MLS_256_XWING_CHACHA20POLY1305_SHA256_Ed25519",
                "purpose": "leafRecovery",
                "status": "active",
                "expiresAt": expires_at,
                "keyPackage": {
                    "framing": "mlsMessage",
                    "contentType": "keyPackage",
                    "bytes": STANDARD.encode(&key_package_wrapper),
                    "sha256": STANDARD.encode(key_package_sha),
                    "keyPackageRef": STANDARD.encode(key_package_ref),
                }
            },
            "status": "open",
            "requestedAt": received_at,
            "expiresAt": expires_at,
        });
        let row = json!({
            "$type": "blue.catbird.chat.defs#participantAcceptanceEntry",
            "entryId": entry_id.hyphenated().to_string(),
            "conversationId": Uuid::from_bytes(entry.cid).hyphenated().to_string(),
            "seq": seq,
            "signedRequest": wrapper,
            "recovery": recovery,
            "receivedAt": received_at,
        });
        let public_row_json = serde_json::to_vec(&row).unwrap();
        let decoded = decode_and_verify_control_entry(
            &public_row_json,
            &invitee.signing_key.verifying_key().to_bytes(),
        )
        .expect("real acceptance entry verifies");
        let canonical = decode_canonical_signed_mutation(&raw_wrapper).unwrap();
        RealAcceptanceEntry {
            entry_id,
            transition_id,
            request_id,
            key_package_ref,
            key_package_wrapper,
            public_row_json,
            raw_wrapper,
            unsigned_projection: canonical.canonical_projection().to_vec(),
            signing_transcript,
            request_digest: Sha256::digest(canonical.transcript_bytes()).to_vec(),
            signature: signature.to_vec(),
            server_fields: decoded.server_fields_dag_cbor().unwrap(),
            outer_fingerprint: *decoded.outer_control_fingerprint(),
        }
    }

    pub(super) struct GenuinePolicyRoleGraph {
        creation_graph: GenuineCreationGraph,
        pub(super) entry: RealCreationEntry,
        pub(super) invitee: AcceptanceInvitee,
        acceptance: RealAcceptanceEntry,
        pub(super) fulfillment: RealLeafRecoveryFulfillmentEntry,
        pub(super) committed: ActivePublicState,
    }

    struct TerminalFamilyBActors {
        entry: RealCreationEntry,
        invitee: AcceptanceInvitee,
    }

    pub(crate) async fn insert_real_generation_state(
        tx: &mut Transaction<'_, Postgres>,
        cid: Uuid,
        state: &ActivePublicState,
        state_kind: &str,
        producer: Uuid,
        at: DateTime<Utc>,
    ) {
        let coordinate = state.coordinate();
        let encoded = encode_public_tree_summary(state.binding().tree_summary())
            .expect("real tree summary encodes");
        sqlx::query(
            r#"INSERT INTO chat.generation_states(
                    conversation_id,generation,state_version,group_id,epoch,group_context_hash,
                    confirmation_tag,lifecycle,state_kind,producing_transition_id,
                    public_snapshot_bytes,snapshot_sha256,tree_summary_bytes,tree_summary_sha256,
                    leaf_count,created_at
                ) VALUES($1,$2,$3,$4,$5,$6,$7,'active',$8,$9,$10,$11,$12,$13,$14,$15)"#,
        )
        .bind(cid)
        .bind(i64::try_from(coordinate.generation()).unwrap())
        .bind(i64::try_from(coordinate.state_version()).unwrap())
        .bind(coordinate.group_id().to_vec())
        .bind(i64::try_from(coordinate.epoch()).unwrap())
        .bind(coordinate.group_context_hash().to_vec())
        .bind(coordinate.confirmation_tag().to_vec())
        .bind(state_kind)
        .bind(producer)
        .bind(state.snapshot())
        .bind(state.snapshot_sha256().to_vec())
        .bind(encoded.bytes())
        .bind(encoded.sha256().to_vec())
        .bind(i64::try_from(state.binding().tree_summary().leaves().len()).unwrap())
        .bind(at)
        .execute(&mut **tx)
        .await
        .expect("insert real generation state");
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) async fn insert_genuine_commit_edge(
        tx: &mut Transaction<'_, Postgres>,
        entry: &RealCreationEntry,
        creation_transition_id: Uuid,
        control: &GenuineCommitControl,
        transition_kind: &str,
        entry_kind: &str,
        prior_state_version: u64,
        next_state: &ActivePublicState,
        seq: u64,
        accepted_at: DateTime<Utc>,
        recipient_devices: &[(&str, Uuid, &str)],
    ) {
        let cid = Uuid::from_bytes(entry.cid);
        let next_state_version = next_state.coordinate().state_version();
        assert_eq!(next_state_version, prior_state_version + 1);
        let updated = sqlx::query(
            "UPDATE chat.conversations SET current_state_version=$2,next_entry_seq=$3 \
                 WHERE conversation_id=$1 AND current_generation=0 \
                   AND current_state_version=$4 AND next_entry_seq=$5",
        )
        .bind(cid)
        .bind(i64::try_from(next_state_version).unwrap())
        .bind(i64::try_from(seq + 1).unwrap())
        .bind(i64::try_from(prior_state_version).unwrap())
        .bind(i64::try_from(seq).unwrap())
        .execute(&mut **tx)
        .await
        .expect("advance fixed-corpus conversation Commit edge");
        assert_eq!(updated.rows_affected(), 1, "exact conversation-head CAS");
        let updated = sqlx::query(
            "UPDATE chat.generations SET current_state_version=$2 \
                 WHERE conversation_id=$1 AND generation=0 AND current_state_version=$3",
        )
        .bind(cid)
        .bind(i64::try_from(next_state_version).unwrap())
        .bind(i64::try_from(prior_state_version).unwrap())
        .execute(&mut **tx)
        .await
        .expect("advance fixed-corpus generation Commit edge");
        assert_eq!(updated.rows_affected(), 1, "exact generation-head CAS");

        let metadata_snapshot_id = Uuid::new_v4();
        sqlx::query(
            r#"INSERT INTO chat.transitions(
                    transition_id,conversation_id,kind,actor_did,actor_device_id,actor_key_id,
                    actor_auth_generation,actor_role,actor_device_status,signed_request_bytes,
                    unsigned_projection_bytes,signing_transcript_bytes,request_digest,signature,
                    prior_generation,prior_state_version,next_generation,next_state_version,
                    metadata_snapshot_id,entry_seq,accepted_at
                ) VALUES($1,$2,$3,$4,$5,$6,1,'admin','active',$7,$8,$9,$10,$11,
                    0,$12,0,$13,$14,$15,$16)"#,
        )
        .bind(control.transition_id)
        .bind(cid)
        .bind(transition_kind)
        .bind(&entry.actor_did)
        .bind(entry.actor_device_id)
        .bind(&entry.actor_key_id)
        .bind(&control.raw_wrapper)
        .bind(&control.canonical_projection)
        .bind(&control.signing_transcript)
        .bind(&control.request_digest)
        .bind(&control.signature)
        .bind(i64::try_from(prior_state_version).unwrap())
        .bind(i64::try_from(next_state_version).unwrap())
        .bind(metadata_snapshot_id)
        .bind(i64::try_from(seq).unwrap())
        .bind(accepted_at)
        .execute(&mut **tx)
        .await
        .expect("insert fixed-corpus Commit transition");

        insert_real_generation_state(
            tx,
            cid,
            next_state,
            "commit",
            control.transition_id,
            accepted_at,
        )
        .await;
        let coordinate = next_state.coordinate();
        sqlx::query(
                r#"INSERT INTO chat.metadata_snapshots(
                    metadata_snapshot_id,conversation_id,generation,state_version,group_id,epoch,
                    group_context_hash,confirmation_tag,producing_transition_id,
                    origin_transition_id,metadata_version,nonce,ciphertext,ciphertext_sha256,
                    ciphertext_size,author_did,author_device_id,author_key_id,author_public_key,
                    author_auth_generation,author_origin_seq,author_role,author_device_status,created_at
                ) VALUES($1,$2,0,$3,$4,$5,$6,$7,$8,$9,1,$10,$11,$12,16,$13,$14,$15,$16,
                    1,1,'admin','active',$17)"#,
            )
            .bind(metadata_snapshot_id)
            .bind(cid)
            .bind(i64::try_from(next_state_version).unwrap())
            .bind(coordinate.group_id().to_vec())
            .bind(i64::try_from(coordinate.epoch()).unwrap())
            .bind(coordinate.group_context_hash().to_vec())
            .bind(coordinate.confirmation_tag().to_vec())
            .bind(control.transition_id)
            .bind(creation_transition_id)
            .bind(&control.metadata_nonce)
            .bind(&control.metadata_ciphertext)
            .bind(Sha256::digest(&control.metadata_ciphertext).to_vec())
            .bind(&entry.actor_did)
            .bind(entry.actor_device_id)
            .bind(&entry.actor_key_id)
            .bind(&entry.public_key)
            .bind(accepted_at)
            .execute(&mut **tx)
            .await
            .expect("insert fixed-corpus Commit metadata");

        sqlx::query(
            r#"INSERT INTO chat.entries(
                    conversation_id,seq,entry_id,entry_kind,accepted_payload_bytes,
                    accepted_payload_sha256,signed_request_bytes,request_digest,signature,
                    server_fields_bytes,outer_entry_fingerprint,actor_did,actor_device_id,
                    actor_key_id,actor_auth_generation,generation,state_version,transition_id,
                    received_at
                ) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,1,0,$15,$16,$17)"#,
        )
        .bind(cid)
        .bind(i64::try_from(seq).unwrap())
        .bind(control.entry_id)
        .bind(entry_kind)
        .bind(&control.public_row_json)
        .bind(Sha256::digest(&control.public_row_json).to_vec())
        .bind(&control.raw_wrapper)
        .bind(&control.request_digest)
        .bind(&control.signature)
        .bind(&control.server_fields)
        .bind(control.outer_fingerprint.to_vec())
        .bind(&entry.actor_did)
        .bind(entry.actor_device_id)
        .bind(&entry.actor_key_id)
        .bind(i64::try_from(next_state_version).unwrap())
        .bind(control.transition_id)
        .bind(accepted_at)
        .execute(&mut **tx)
        .await
        .expect("insert fixed-corpus Commit entry");
        for (did, device_id, entitlement_kind) in recipient_devices {
            sqlx::query(
                r#"INSERT INTO chat.entry_recipients(
                        conversation_id,seq,user_did,device_id,entitlement_kind
                    ) VALUES($1,$2,$3,$4,$5)"#,
            )
            .bind(cid)
            .bind(i64::try_from(seq).unwrap())
            .bind(*did)
            .bind(*device_id)
            .bind(*entitlement_kind)
            .execute(&mut **tx)
            .await
            .expect("route fixed-corpus Commit entry");
        }
    }

    pub(crate) async fn supersede_welcome_for_transition(
        tx: &mut Transaction<'_, Postgres>,
        entry: &RealCreationEntry,
        invitee: &AcceptanceInvitee,
        welcome_id: Uuid,
        transition_id: Uuid,
        at: DateTime<Utc>,
    ) {
        sqlx::query(
            r#"INSERT INTO chat.protocol_instances(
                    singleton,protocol_instance_id,cursor_key_id,created_at
                ) VALUES(TRUE,$1,$2,$3) ON CONFLICT (singleton) DO NOTHING"#,
        )
        .bind(Uuid::new_v4())
        .bind(&entry.actor_key_id)
        .bind(at)
        .execute(&mut **tx)
        .await
        .expect("ensure fixed-corpus protocol instance");
        let protocol_instance_id: Uuid =
            sqlx::query_scalar("SELECT protocol_instance_id FROM chat.protocol_instances")
                .fetch_one(&mut **tx)
                .await
                .expect("fixed-corpus protocol instance");
        let payload = b"fixed-corpus-welcome-superseded".to_vec();
        let event_position: i64 = sqlx::query_scalar(
            r#"INSERT INTO chat.events(
                    event_id,event_kind,payload_bytes,payload_sha256,created_at,protocol_instance_id
                ) VALUES($1,'welcomeDisposition',$2,$3,$4,$5) RETURNING event_position"#,
        )
        .bind(Uuid::new_v4())
        .bind(&payload)
        .bind(Sha256::digest(&payload).to_vec())
        .bind(at)
        .bind(protocol_instance_id)
        .fetch_one(&mut **tx)
        .await
        .expect("insert fixed-corpus Welcome disposition event");
        let updated = sqlx::query(
            "UPDATE chat.welcome_deliveries SET status='superseded',terminal_at=$2 \
                 WHERE welcome_id=$1 AND status='pending'",
        )
        .bind(welcome_id)
        .bind(at)
        .execute(&mut **tx)
        .await
        .expect("supersede fixed-corpus Welcome");
        assert_eq!(updated.rows_affected(), 1, "one pending Welcome superseded");
        sqlx::query(
            r#"INSERT INTO chat.welcome_dispositions(
                    welcome_id,winner_kind,signed_request_bytes,signing_transcript_bytes,
                    request_digest,signature,rejection_reason,terminal_at,event_position,
                    terminal_transition_id,terminal_revocation_id
                ) VALUES($1,'superseded',NULL,NULL,NULL,NULL,NULL,$2,$3,$4,NULL)"#,
        )
        .bind(welcome_id)
        .bind(at)
        .bind(event_position)
        .bind(transition_id)
        .execute(&mut **tx)
        .await
        .expect("insert fixed-corpus Welcome disposition");
        let predecessor: Option<i64> = sqlx::query_scalar(
            "SELECT max(event_position) FROM chat.event_recipients \
                 WHERE user_did=$1 AND device_id=$2",
        )
        .bind(&invitee.did)
        .bind(invitee.device_id)
        .fetch_one(&mut **tx)
        .await
        .expect("fixed-corpus Welcome audience predecessor");
        sqlx::query(
            r#"INSERT INTO chat.event_recipients(
                    event_position,user_did,device_id,entitlement_kind,
                    audience_predecessor_position
                ) VALUES($1,$2,$3,'welcome',$4)"#,
        )
        .bind(event_position)
        .bind(&invitee.did)
        .bind(invitee.device_id)
        .bind(predecessor)
        .execute(&mut **tx)
        .await
        .expect("insert fixed-corpus Welcome event recipient");
        sqlx::query(
            r#"INSERT INTO chat.outbox(
                    outbox_id,event_position,work_kind,status,next_attempt_at,created_at
                ) VALUES($1,$2,'stream','pending',$3,$3)"#,
        )
        .bind(Uuid::new_v4())
        .bind(event_position)
        .bind(at)
        .execute(&mut **tx)
        .await
        .expect("insert fixed-corpus Welcome outbox");
    }

    async fn commit_dynamic_leave_request(
        pool: &PgPool,
        graph: &GenuinePolicyRoleGraph,
        at: DateTime<Utc>,
    ) -> GenuineLeaveRequest {
        let signed_at =
            (at - chrono::Duration::milliseconds(500)).to_rfc3339_opts(SecondsFormat::Millis, true);
        let received_at = at.to_rfc3339_opts(SecondsFormat::Millis, true);
        let request = build_genuine_leave_request(
            &graph.entry,
            &graph.invitee,
            graph.committed.coordinate(),
            5,
            &signed_at,
            &received_at,
        );
        let cid = Uuid::from_bytes(graph.entry.cid);
        let expires_at = at + chrono::Duration::hours(24);
        let mut tx = pool.begin().await.expect("begin dynamic leave request");
        let updated = sqlx::query(
            "UPDATE chat.conversations SET next_entry_seq=6 \
                 WHERE conversation_id=$1 AND current_generation=0 \
                   AND current_state_version=3 AND next_entry_seq=5",
        )
        .bind(cid)
        .execute(&mut *tx)
        .await
        .expect("advance dynamic head through leave request");
        assert_eq!(updated.rows_affected(), 1, "exact dynamic leave head CAS");

        sqlx::query(
            r#"INSERT INTO chat.entries(
                    conversation_id,seq,entry_id,entry_kind,accepted_payload_bytes,
                    accepted_payload_sha256,signed_request_bytes,request_digest,signature,
                    server_fields_bytes,outer_entry_fingerprint,actor_did,actor_device_id,
                    actor_key_id,actor_auth_generation,generation,state_version,transition_id,
                    received_at
                ) VALUES($1,5,$2,'blue.catbird.chat.defs#leaveRequestEntry',$3,$4,$5,$6,$7,
                    $8,$9,$10,$11,$12,1,NULL,NULL,NULL,$13)"#,
        )
        .bind(cid)
        .bind(request.entry_id)
        .bind(&request.public_row_json)
        .bind(Sha256::digest(&request.public_row_json).to_vec())
        .bind(&request.raw_wrapper)
        .bind(&request.request_digest)
        .bind(&request.signature)
        .bind(&request.server_fields)
        .bind(request.outer_fingerprint.to_vec())
        .bind(&graph.invitee.did)
        .bind(graph.invitee.device_id)
        .bind(&graph.invitee.key_id)
        .bind(at)
        .execute(&mut *tx)
        .await
        .expect("insert dynamic Bob leave request entry");
        sqlx::query(
            r#"INSERT INTO chat.leave_requests(
                    leave_request_id,conversation_id,requester_did,requester_device_id,
                    requester_key_id,requester_auth_generation,prior_generation,prior_state_version,
                    prior_group_id,prior_epoch,prior_group_context_hash,prior_confirmation_tag,
                    status,signed_request_bytes,signing_transcript_bytes,request_digest,signature,
                    received_at,expires_at
                ) VALUES($1,$2,$3,$4,$5,1,0,3,$6,$7,$8,$9,'pending',$10,$11,$12,$13,$14,$15)"#,
        )
        .bind(request.request_id)
        .bind(cid)
        .bind(&graph.invitee.did)
        .bind(graph.invitee.device_id)
        .bind(&graph.invitee.key_id)
        .bind(graph.committed.coordinate().group_id().to_vec())
        .bind(i64::try_from(graph.committed.coordinate().epoch()).unwrap())
        .bind(graph.committed.coordinate().group_context_hash().to_vec())
        .bind(graph.committed.coordinate().confirmation_tag().to_vec())
        .bind(&request.raw_wrapper)
        .bind(&request.signing_transcript)
        .bind(&request.request_digest)
        .bind(&request.signature)
        .bind(at)
        .bind(expires_at)
        .execute(&mut *tx)
        .await
        .expect("insert dynamic Bob pending leave request");
        for (did, device_id) in [
            (graph.entry.actor_did.as_str(), graph.entry.actor_device_id),
            (graph.invitee.did.as_str(), graph.invitee.device_id),
        ] {
            sqlx::query(
                r#"INSERT INTO chat.entry_recipients(
                        conversation_id,seq,user_did,device_id,entitlement_kind
                    ) VALUES($1,5,$2,$3,'control')"#,
            )
            .bind(cid)
            .bind(did)
            .bind(device_id)
            .execute(&mut *tx)
            .await
            .expect("route dynamic Bob leave request");
        }
        tx.commit()
            .await
            .expect("dynamic Bob leave request crosses deferred mapping");
        request
    }

    async fn commit_dynamic_reset_request(
        pool: &PgPool,
        graph: &GenuinePolicyRoleGraph,
        at: DateTime<Utc>,
    ) -> GenuineResetRequest {
        let signed_at =
            (at - chrono::Duration::milliseconds(500)).to_rfc3339_opts(SecondsFormat::Millis, true);
        let received_at = at.to_rfc3339_opts(SecondsFormat::Millis, true);
        let request = build_genuine_reset_request(
            &graph.entry,
            graph.committed.coordinate(),
            5,
            &signed_at,
            &received_at,
        );
        let cid = Uuid::from_bytes(graph.entry.cid);
        let expires_at = at + chrono::Duration::hours(24);
        let mut tx = pool.begin().await.expect("begin dynamic reset request");
        let updated = sqlx::query(
            "UPDATE chat.conversations SET next_entry_seq=6 \
                 WHERE conversation_id=$1 AND current_generation=0 \
                   AND current_state_version=3 AND next_entry_seq=5",
        )
        .bind(cid)
        .execute(&mut *tx)
        .await
        .expect("advance dynamic head through reset request");
        assert_eq!(updated.rows_affected(), 1, "exact dynamic reset head CAS");
        sqlx::query(
            r#"INSERT INTO chat.entries(
                    conversation_id,seq,entry_id,entry_kind,accepted_payload_bytes,
                    accepted_payload_sha256,signed_request_bytes,request_digest,signature,
                    server_fields_bytes,outer_entry_fingerprint,actor_did,actor_device_id,
                    actor_key_id,actor_auth_generation,generation,state_version,transition_id,
                    received_at
                ) VALUES($1,5,$2,'blue.catbird.chat.defs#resetRequestEntry',$3,$4,$5,$6,$7,
                    $8,$9,$10,$11,$12,1,NULL,NULL,NULL,$13)"#,
        )
        .bind(cid)
        .bind(request.entry_id)
        .bind(&request.public_row_json)
        .bind(Sha256::digest(&request.public_row_json).to_vec())
        .bind(&request.raw_wrapper)
        .bind(&request.request_digest)
        .bind(&request.signature)
        .bind(&request.server_fields)
        .bind(request.outer_fingerprint.to_vec())
        .bind(&graph.entry.actor_did)
        .bind(graph.entry.actor_device_id)
        .bind(&graph.entry.actor_key_id)
        .bind(at)
        .execute(&mut *tx)
        .await
        .expect("insert dynamic reset request entry");
        let coordinate = graph.committed.coordinate();
        sqlx::query(
            r#"INSERT INTO chat.reset_requests(
                    reset_request_id,conversation_id,requester_did,requester_device_id,
                    requester_key_id,requester_auth_generation,prior_generation,prior_state_version,
                    prior_group_id,prior_epoch,prior_group_context_hash,prior_confirmation_tag,
                    reason,status,signed_request_bytes,signing_transcript_bytes,request_digest,
                    signature,received_at,expires_at
                ) VALUES($1,$2,$3,$4,$5,1,0,3,$6,$7,$8,$9,'manualRecovery','pending',
                    $10,$11,$12,$13,$14,$15)"#,
        )
        .bind(request.request_id)
        .bind(cid)
        .bind(&graph.entry.actor_did)
        .bind(graph.entry.actor_device_id)
        .bind(&graph.entry.actor_key_id)
        .bind(coordinate.group_id().to_vec())
        .bind(i64::try_from(coordinate.epoch()).unwrap())
        .bind(coordinate.group_context_hash().to_vec())
        .bind(coordinate.confirmation_tag().to_vec())
        .bind(&request.raw_wrapper)
        .bind(&request.signing_transcript)
        .bind(&request.request_digest)
        .bind(&request.signature)
        .bind(at)
        .bind(expires_at)
        .execute(&mut *tx)
        .await
        .expect("insert dynamic pending reset request");
        for (did, device_id) in [
            (graph.entry.actor_did.as_str(), graph.entry.actor_device_id),
            (graph.invitee.did.as_str(), graph.invitee.device_id),
        ] {
            sqlx::query(
                r#"INSERT INTO chat.entry_recipients(
                        conversation_id,seq,user_did,device_id,entitlement_kind
                    ) VALUES($1,5,$2,$3,'control')"#,
            )
            .bind(cid)
            .bind(did)
            .bind(device_id)
            .execute(&mut *tx)
            .await
            .expect("route dynamic reset request");
        }
        tx.commit()
            .await
            .expect("dynamic reset request crosses deferred mapping");
        request
    }

    #[allow(clippy::too_many_arguments)]
    async fn commit_dynamic_remove_fulfillment(
        pool: &PgPool,
        graph: &TerminalFamilyBActors,
        creation_transition_id: Uuid,
        committed: &ActivePublicState,
        removed: &ActivePublicState,
        leave: &GenuineLeaveRequest,
        transition_id: Uuid,
        commit_bytes: Vec<u8>,
        welcome_id: Uuid,
        at: DateTime<Utc>,
    ) {
        let signed_at =
            (at - chrono::Duration::milliseconds(500)).to_rfc3339_opts(SecondsFormat::Millis, true);
        let received_at = at.to_rfc3339_opts(SecondsFormat::Millis, true);
        let control = build_genuine_commit_control_with_bytes(
            &graph.entry,
            creation_transition_id,
            SignedMutationKind::LeaveCommitFulfillment,
            "blue.catbird.chat.defs#leaveCommitFulfillmentEntry",
            transition_id,
            committed.coordinate(),
            removed.coordinate(),
            6,
            &signed_at,
            &received_at,
            commit_bytes,
            vec![json!({
                "$type": "blue.catbird.chat.defs#removeParticipant",
                "userDid": &graph.invitee.did,
            })],
            vec![json!({
                "$type": "blue.catbird.chat.defs#removeLeaf",
                "userDid": &graph.invitee.did,
                "deviceId": graph.invitee.device_id,
            })],
            Some(leave.request_id),
            0x63,
            0x64,
        );
        let recipients = [
            (
                graph.entry.actor_did.as_str(),
                graph.entry.actor_device_id,
                "control",
            ),
            (
                graph.invitee.did.as_str(),
                graph.invitee.device_id,
                "intervalClose",
            ),
        ];
        let cid = Uuid::from_bytes(graph.entry.cid);
        let mut tx = pool
            .begin()
            .await
            .expect("begin dynamic Remove fulfillment");
        let (leaf_period_id, participant_period_id): (Uuid, Uuid) = sqlx::query_as(
            r#"SELECT leaf_period_id,participant_period_id
                     FROM chat.member_devices
                    WHERE conversation_id=$1 AND user_did=$2 AND device_id=$3 AND active
                    FOR UPDATE"#,
        )
        .bind(cid)
        .bind(&graph.invitee.did)
        .bind(graph.invitee.device_id)
        .fetch_one(&mut *tx)
        .await
        .expect("lock dynamic Bob leaf period");
        insert_genuine_commit_edge(
            &mut tx,
            &graph.entry,
            creation_transition_id,
            &control,
            "leaveCommit",
            "blue.catbird.chat.defs#leaveCommitFulfillmentEntry",
            3,
            removed,
            6,
            at,
            &recipients,
        )
        .await;
        let updated = sqlx::query(
            r#"UPDATE chat.member_devices
                      SET removed_state_version=4,removed_transition_id=$2,removed_seq=6,
                          removed_at=$3,active=FALSE
                    WHERE leaf_period_id=$1 AND active"#,
        )
        .bind(leaf_period_id)
        .bind(transition_id)
        .bind(at)
        .execute(&mut *tx)
        .await
        .expect("close dynamic Bob leaf period");
        assert_eq!(updated.rows_affected(), 1);
        let updated = sqlx::query(
            r#"UPDATE chat.application_intervals
                      SET terminal_seq=6,closing_state_version=4,closing_transition_id=$2,
                          closing_outer_entry_fingerprint=$3,closing_kind='remove',
                          closing_leaf_period_id=$1,removed_at=$4
                    WHERE opening_leaf_period_id=$1 AND terminal_seq IS NULL"#,
        )
        .bind(leaf_period_id)
        .bind(transition_id)
        .bind(control.outer_fingerprint.to_vec())
        .bind(at)
        .execute(&mut *tx)
        .await
        .expect("close dynamic Bob application interval");
        assert_eq!(updated.rows_affected(), 1);
        let updated = sqlx::query(
            r#"UPDATE chat.participants
                      SET removing_transition_id=$2,removing_seq=6,removed_at=$3,
                          current_membership=FALSE
                    WHERE participant_period_id=$1 AND current_membership"#,
        )
        .bind(participant_period_id)
        .bind(transition_id)
        .bind(at)
        .execute(&mut *tx)
        .await
        .expect("remove dynamic Bob participant period");
        assert_eq!(updated.rows_affected(), 1);
        let updated = sqlx::query(
            r#"UPDATE chat.leave_requests
                      SET status='fulfilled',terminal_request_digest=$2,
                          terminal_transition_id=$3,terminal_at=$4
                    WHERE leave_request_id=$1 AND status='pending'"#,
        )
        .bind(leave.request_id)
        .bind(&control.request_digest)
        .bind(transition_id)
        .bind(at)
        .execute(&mut *tx)
        .await
        .expect("fulfill dynamic Bob leave request");
        assert_eq!(updated.rows_affected(), 1);
        supersede_welcome_for_transition(
            &mut tx,
            &graph.entry,
            &graph.invitee,
            welcome_id,
            transition_id,
            at,
        )
        .await;
        tx.commit()
            .await
            .expect("dynamic Remove crosses deferred constraints");
    }

    async fn device_event_predecessor(pool: &PgPool, did: &str, device_id: Uuid) -> Option<i64> {
        sqlx::query_scalar(
            "SELECT max(event_position) FROM chat.event_recipients \
             WHERE user_did=$1 AND device_id=$2",
        )
        .bind(did)
        .bind(device_id)
        .fetch_one(pool)
        .await
        .expect("device event predecessor")
    }

    async fn commit_dynamic_reset_activation(
        pool: &PgPool,
        graph: &GenuinePolicyRoleGraph,
        request: &GenuineResetRequest,
        at: DateTime<Utc>,
    ) -> GenuineResetActivation {
        let cid = Uuid::from_bytes(graph.entry.cid);
        let invitation_transition_id: Uuid = sqlx::query_scalar(
            r#"SELECT invitation_transition_id FROM chat.participants
               WHERE conversation_id=$1 AND user_did=$2 AND current_membership"#,
        )
        .bind(cid)
        .bind(&graph.invitee.did)
        .fetch_one(pool)
        .await
        .expect("reset-retained invitation transition");
        let mut participants = vec![
            json!({
                "userDid": &graph.entry.actor_did,
                "role": "admin",
                "status": "active",
            }),
            json!({
                "userDid": &graph.invitee.did,
                "role": "member",
                "status": "active",
                "invitationProvenance": {
                    "invitedByDid": &graph.entry.actor_did,
                    "invitedByDeviceId": graph.entry.actor_device_id,
                    "invitationTransitionId": invitation_transition_id,
                },
            }),
        ];
        participants.sort_by(|left, right| {
            left["userDid"]
                .as_str()
                .expect("left reset participant DID")
                .as_bytes()
                .cmp(
                    right["userDid"]
                        .as_str()
                        .expect("right reset participant DID")
                        .as_bytes(),
                )
        });
        let activation = build_genuine_reset_activation(
            &graph.entry,
            request,
            graph.committed.coordinate(),
            Value::Array(participants),
            at,
        );

        let locked_at: DateTime<Utc> =
            sqlx::query_scalar("SELECT date_trunc('milliseconds', clock_timestamp())")
                .fetch_one(pool)
                .await
                .expect("sample pending-reset hydration instant");
        let mut read = pool.begin().await.expect("begin pending-reset hydration");
        let locked = hydrate_locked_conversation_state(&mut read, cid, locked_at)
            .await
            .expect("pending-reset graph hydrates");
        let prior = locked.state().clone();
        read.rollback()
            .await
            .expect("rollback pending-reset hydration");

        let historical = HistoricalRehydrationAuthority::new(graph.entry.cid, 7)
            .expect("reset activation authority");
        let evidence = historical
            .hydrate_historical_control_from_durable_bytes(
                activation.public_row_json.clone(),
                activation.raw_wrapper.clone(),
                &graph.entry.public_key,
            )
            .expect("genuine reset activation rehydrates")
            .into_transition()
            .expect("reset activation is a coordinate transition");
        let at_text = at.to_rfc3339_opts(SecondsFormat::Millis, true);
        let received =
            ServerTimestamp::from_canonical_stored(&at_text).expect("reset activation instant");
        let planned = plan_reset_activation(
            &prior,
            ResetActivation {
                actor: DeviceIdentity::new(
                    PrincipalId::new(graph.entry.actor_did.as_bytes().to_vec())
                        .expect("reset actor DID"),
                    *graph.entry.actor_device_id.as_bytes(),
                )
                .expect("reset actor device"),
                reset_request_id: *request.request_id.as_bytes(),
                transition: evidence,
                successor_public_state: activation.successor_public_state.clone(),
            },
        )
        .expect("genuine reset activation plans");
        let plan = persistence_plan_for_test(
            planned,
            ConversationHeadCasBinding::for_test_edge(
                graph.entry.cid,
                *activation.entry_id.as_bytes(),
                *prior.coordinate(),
                6,
                received,
            ),
        );

        let old_leaf_rows: Vec<(String, Uuid, Uuid)> = sqlx::query_as(
            r#"SELECT user_did,device_id,leaf_period_id FROM chat.member_devices
               WHERE conversation_id=$1 AND generation=0 AND removed_seq IS NULL
               ORDER BY convert_to(user_did, 'UTF8'),uuid_send(device_id)"#,
        )
        .bind(cid)
        .fetch_all(pool)
        .await
        .expect("old reset leaf periods");
        let old_leaves: Vec<(DeviceIdentity, Uuid)> = old_leaf_rows
            .into_iter()
            .map(|(did, device_id, leaf_period_id)| {
                (
                    DeviceIdentity::new(
                        PrincipalId::new(did.into_bytes()).expect("old reset leaf DID"),
                        *device_id.as_bytes(),
                    )
                    .expect("old reset leaf identity"),
                    leaf_period_id,
                )
            })
            .collect();
        assert_eq!(
            old_leaves.len(),
            2,
            "reset starts from exact two-leaf graph"
        );
        let participant_period_ids: Vec<Uuid> = sqlx::query_scalar(
            r#"SELECT participant_period_id FROM chat.participants
               WHERE conversation_id=$1 AND current_membership
               ORDER BY convert_to(user_did, 'UTF8')"#,
        )
        .bind(cid)
        .fetch_all(pool)
        .await
        .expect("reset participant periods");
        let prior_spine: (Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>, i64) = sqlx::query_as(
            r#"SELECT public_snapshot_bytes,snapshot_sha256,
                      tree_summary_bytes,tree_summary_sha256,leaf_count
                 FROM chat.generation_states
                WHERE conversation_id=$1 AND generation=0 AND state_version=3"#,
        )
        .bind(cid)
        .fetch_one(pool)
        .await
        .expect("capture exact active spine before reset");
        sqlx::query(
            r#"INSERT INTO chat.protocol_instances(
                    singleton,protocol_instance_id,cursor_key_id,created_at
                ) VALUES(TRUE,$1,$2,$3) ON CONFLICT (singleton) DO NOTHING"#,
        )
        .bind(Uuid::new_v4())
        .bind(&graph.entry.actor_key_id)
        .bind(at)
        .execute(pool)
        .await
        .expect("ensure reset protocol instance");
        let protocol_instance_id: Uuid =
            sqlx::query_scalar("SELECT protocol_instance_id FROM chat.protocol_instances")
                .fetch_one(pool)
                .await
                .expect("reset protocol instance");
        let actor = DeviceIdentity::new(
            PrincipalId::new(graph.entry.actor_did.as_bytes().to_vec()).expect("actor DID"),
            *graph.entry.actor_device_id.as_bytes(),
        )
        .expect("actor identity");
        let invitee_device = DeviceIdentity::new(
            PrincipalId::new(graph.invitee.did.as_bytes().to_vec()).expect("invitee DID"),
            *graph.invitee.device_id.as_bytes(),
        )
        .expect("invitee identity");
        let actor_predecessor =
            device_event_predecessor(pool, &graph.entry.actor_did, graph.entry.actor_device_id)
                .await;
        let invitee_predecessor =
            device_event_predecessor(pool, &graph.invitee.did, graph.invitee.device_id).await;
        let context = ExecutionContext {
            protocol_instance_id,
            applied_at: at,
            actor: ExecutionActor {
                user_did: graph.entry.actor_did.clone(),
                device_id: graph.entry.actor_device_id,
                key_id: graph.entry.actor_key_id.clone(),
                auth_generation: 1,
                role: TransitionActorRole::Admin,
                device_status: "active".to_owned(),
            },
            authority: ExecutionAuthority::ControlEntry(ControlEntryContent {
                entry_id: activation.entry_id,
                entry_kind: "blue.catbird.chat.defs#resetActivationEntry".to_owned(),
                accepted_payload_bytes: activation.public_row_json.clone(),
                accepted_payload_sha256: Sha256::digest(&activation.public_row_json).to_vec(),
                signed_request_bytes: activation.raw_wrapper.clone(),
                unsigned_projection_bytes: activation.canonical_projection.clone(),
                signing_transcript_bytes: activation.signing_transcript.clone(),
                request_digest: activation.request_digest.clone(),
                signature: activation.signature.clone(),
                server_fields_bytes: activation.server_fields.clone(),
                outer_entry_fingerprint: activation.outer_fingerprint.to_vec(),
            }),
            spine: SpineArtifacts {
                public_snapshot_bytes: prior_spine.0,
                public_snapshot_sha256: prior_spine.1,
                tree_summary_bytes: prior_spine.2,
                tree_summary_sha256: prior_spine.3,
                leaf_count: prior_spine.4,
                genesis_group_info_bytes: activation.group_info.clone(),
                genesis_group_info_sha256: Sha256::digest(&activation.group_info).to_vec(),
            },
            opened_leaves: vec![LeafPersistenceColumns {
                device: actor.clone(),
                leaf_key_id: graph.entry.actor_key_id.clone(),
                leaf_auth_generation: 1,
            }],
            metadata_author: Some(MetadataAuthorColumns {
                author_role: "admin".to_owned(),
                author_device_status: "active".to_owned(),
                author_public_key: graph.entry.public_key.clone(),
                author_key_id: graph.entry.actor_key_id.clone(),
                metadata_snapshot_id: Uuid::new_v4(),
            }),
            metadata_avatar: None,
            participant_period_ids,
            leaf_period_ids: vec![Uuid::new_v4()],
            entry_recipients: old_leaves
                .iter()
                .map(|(device, _)| (device.clone(), EntryEntitlementKind::IntervalClose))
                .collect(),
            events: vec![EventFanout {
                event_id: Uuid::new_v4(),
                event_kind: EventKind::ConversationChanged,
                payload_bytes: vec![0xd2_u8; 8],
                recipients: vec![(actor, EventEntitlementKind::Participant, actor_predecessor)],
                outbox: vec![(Uuid::new_v4(), OutboxWorkKind::Stream)],
            }],
            closing_leaf_periods: old_leaves,
            closing_participant_periods: Vec::new(),
            reset_request_row: None,
            recovery_open: None,
            welcome_expiry: None,
            welcome_response: None,
            welcome_dispositions: vec![WelcomeDispositionInput {
                welcome_id: graph.fulfillment.welcome_id,
                event: EventFanout {
                    event_id: Uuid::new_v4(),
                    event_kind: EventKind::WelcomeDisposition,
                    payload_bytes: vec![0xd3_u8; 8],
                    recipients: vec![(
                        invitee_device,
                        EventEntitlementKind::Welcome,
                        invitee_predecessor,
                    )],
                    outbox: vec![(Uuid::new_v4(), OutboxWorkKind::Stream)],
                },
            }],
        };
        let mut write = pool.begin().await.expect("begin genuine dynamic reset");
        let applied =
            apply_conversation_persistence_plan_unscoped_for_test(&mut write, &plan, &context)
                .await
                .expect("production executor applies genuine dynamic reset");
        assert_eq!(applied.allocated_seq, 6);
        write
            .commit()
            .await
            .expect("genuine dynamic reset crosses deferred constraints");
        activation
    }

    pub(crate) async fn commit_genuine_acceptance(
        pool: &PgPool,
        entry: &RealCreationEntry,
        invitee: &AcceptanceInvitee,
        acceptance: &RealAcceptanceEntry,
        state: &ActivePublicState,
        at: DateTime<Utc>,
        recovery_expires_at: DateTime<Utc>,
        key_package_not_before: DateTime<Utc>,
        key_package_not_after: DateTime<Utc>,
        key_package_created_at: DateTime<Utc>,
    ) {
        let cid = Uuid::from_bytes(entry.cid);
        let coordinate = state.coordinate();
        let mut tx = pool.begin().await.expect("begin genuine acceptance");
        sqlx::query(
            "UPDATE chat.conversations SET current_state_version=2,next_entry_seq=4 \
                 WHERE conversation_id=$1 AND current_generation=0 \
                   AND current_state_version=1 AND next_entry_seq=3",
        )
        .bind(cid)
        .execute(&mut *tx)
        .await
        .expect("advance head through acceptance");
        sqlx::query(
            "UPDATE chat.generations SET current_state_version=2 \
                 WHERE conversation_id=$1 AND generation=0 AND current_state_version=1",
        )
        .bind(cid)
        .execute(&mut *tx)
        .await
        .expect("advance generation through acceptance");
        sqlx::query(
            r#"INSERT INTO chat.transitions(
                    transition_id,conversation_id,kind,actor_did,actor_device_id,actor_key_id,
                    actor_auth_generation,actor_role,actor_device_status,signed_request_bytes,
                    unsigned_projection_bytes,signing_transcript_bytes,request_digest,signature,
                    prior_generation,prior_state_version,next_generation,next_state_version,
                    entry_seq,accepted_at
                ) VALUES($1,$2,'acceptConversation',$3,$4,$5,1,'member','active',$6,$7,$8,$9,$10,
                    0,1,0,2,3,$11)"#,
        )
        .bind(acceptance.transition_id)
        .bind(cid)
        .bind(&invitee.did)
        .bind(invitee.device_id)
        .bind(&invitee.key_id)
        .bind(&acceptance.raw_wrapper)
        .bind(&acceptance.unsigned_projection)
        .bind(&acceptance.signing_transcript)
        .bind(&acceptance.request_digest)
        .bind(&acceptance.signature)
        .bind(at)
        .execute(&mut *tx)
        .await
        .expect("insert genuine acceptance transition");
        insert_real_generation_state(
            &mut tx,
            cid,
            state,
            "acceptConversation",
            acceptance.transition_id,
            at,
        )
        .await;
        sqlx::query(
            r#"INSERT INTO chat.entries(
                    conversation_id,seq,entry_id,entry_kind,accepted_payload_bytes,
                    accepted_payload_sha256,signed_request_bytes,request_digest,signature,
                    server_fields_bytes,outer_entry_fingerprint,actor_did,actor_device_id,
                    actor_key_id,actor_auth_generation,generation,state_version,transition_id,
                    received_at
                ) VALUES($1,3,$2,'blue.catbird.chat.defs#participantAcceptanceEntry',
                    $3,$4,$5,$6,$7,$8,$9,$10,$11,$12,1,0,2,$13,$14)"#,
        )
        .bind(cid)
        .bind(acceptance.entry_id)
        .bind(&acceptance.public_row_json)
        .bind(Sha256::digest(&acceptance.public_row_json).to_vec())
        .bind(&acceptance.raw_wrapper)
        .bind(&acceptance.request_digest)
        .bind(&acceptance.signature)
        .bind(&acceptance.server_fields)
        .bind(acceptance.outer_fingerprint.to_vec())
        .bind(&invitee.did)
        .bind(invitee.device_id)
        .bind(&invitee.key_id)
        .bind(acceptance.transition_id)
        .bind(at)
        .execute(&mut *tx)
        .await
        .expect("insert genuine acceptance entry");
        sqlx::query(
            r#"INSERT INTO chat.entry_recipients(
                    conversation_id,seq,user_did,device_id,entitlement_kind
                ) VALUES($1,3,$2,$3,'control')"#,
        )
        .bind(cid)
        .bind(&entry.actor_did)
        .bind(entry.actor_device_id)
        .execute(&mut *tx)
        .await
        .expect("route genuine acceptance to Alice");
        sqlx::query(
            "UPDATE chat.participants SET status='active',acceptance_transition_id=$2,\
                 acceptance_entry_id=$3,accepted_at=$4 \
                 WHERE participant_period_id=$1 AND status='pending'",
        )
        .bind(invitee.participant_period_id)
        .bind(acceptance.transition_id)
        .bind(acceptance.entry_id)
        .bind(at)
        .execute(&mut *tx)
        .await
        .expect("promote genuine Bob");
        let init_key =
            Sha256::digest([b"genuine-acceptance-init".as_ref(), &acceptance.request_id].concat())
                .to_vec();
        sqlx::query(
            r#"INSERT INTO chat.key_packages(
                    key_package_ref,wrapper_bytes,wrapper_sha256,init_key,owner_did,
                    owner_device_id,owner_key_id,owner_auth_generation,not_before,not_after,
                    status,created_at
                ) VALUES($1,$2,$3,$4,$5,$6,$7,1,$8,$9,'reserved',$10)"#,
        )
        .bind(acceptance.key_package_ref.to_vec())
        .bind(&acceptance.key_package_wrapper)
        .bind(Sha256::digest(&acceptance.key_package_wrapper).to_vec())
        .bind(init_key)
        .bind(&invitee.did)
        .bind(invitee.device_id)
        .bind(&invitee.key_id)
        .bind(key_package_not_before)
        .bind(key_package_not_after)
        .bind(key_package_created_at)
        .execute(&mut *tx)
        .await
        .expect("insert genuine reserved package");
        let request_id = Uuid::from_bytes(acceptance.request_id);
        sqlx::query(
                r#"INSERT INTO chat.key_package_reservations(
                    recovery_request_id,key_package_ref,conversation_id,generation,requester_did,
                    requester_device_id,requester_key_id,requester_auth_generation,recipient_did,
                    recipient_device_id,bound_state_version,bound_group_id,bound_epoch,
                    bound_group_context_hash,bound_confirmation_tag,purpose,expires_at,status,created_at
                ) VALUES($1,$2,$3,0,$4,$5,$6,1,$4,$5,2,$7,$8,$9,$10,
                    'leafRecovery',$11,'active',$12)"#,
            )
            .bind(request_id)
            .bind(acceptance.key_package_ref.to_vec())
            .bind(cid)
            .bind(&invitee.did)
            .bind(invitee.device_id)
            .bind(&invitee.key_id)
            .bind(coordinate.group_id().to_vec())
            .bind(i64::try_from(coordinate.epoch()).unwrap())
            .bind(coordinate.group_context_hash().to_vec())
            .bind(coordinate.confirmation_tag().to_vec())
            .bind(recovery_expires_at)
            .bind(at)
            .execute(&mut *tx)
            .await
            .expect("insert genuine active reservation");
        sqlx::query(
                r#"INSERT INTO chat.leaf_recovery_requests(
                    recovery_request_id,conversation_id,generation,requester_did,requester_device_id,
                    requester_key_id,requester_auth_generation,recovery_kind,source,bound_state_version,
                    bound_group_id,bound_epoch,bound_group_context_hash,bound_confirmation_tag,
                    reservation_request_id,status,signed_request_bytes,signing_transcript_bytes,
                    request_digest,signature,requested_at,expires_at
                ) VALUES($1,$2,0,$3,$4,$5,1,'add','acceptConversation',2,$6,$7,$8,$9,$1,
                    'open',$10,$11,$12,$13,$14,$15)"#,
            )
            .bind(request_id)
            .bind(cid)
            .bind(&invitee.did)
            .bind(invitee.device_id)
            .bind(&invitee.key_id)
            .bind(coordinate.group_id().to_vec())
            .bind(i64::try_from(coordinate.epoch()).unwrap())
            .bind(coordinate.group_context_hash().to_vec())
            .bind(coordinate.confirmation_tag().to_vec())
            .bind(&acceptance.raw_wrapper)
            .bind(&acceptance.signing_transcript)
            .bind(&acceptance.request_digest)
            .bind(&acceptance.signature)
            .bind(at)
            .bind(recovery_expires_at)
            .execute(&mut *tx)
            .await
            .expect("insert genuine acceptance recovery");
        let mapping: (bool, bool, bool, bool, bool, bool, bool, bool) = sqlx::query_as(
                r#"SELECT
                    package.key_package_ref IS NOT NULL,
                    reservation.conversation_id=request.conversation_id
                      AND reservation.generation=request.generation
                      AND reservation.requester_did=request.requester_did
                      AND reservation.requester_device_id=request.requester_device_id
                      AND reservation.requester_key_id=request.requester_key_id
                      AND reservation.requester_auth_generation=request.requester_auth_generation
                      AND reservation.recipient_did=request.requester_did
                      AND reservation.recipient_device_id=request.requester_device_id,
                    reservation.bound_state_version=request.bound_state_version
                      AND reservation.bound_group_id=request.bound_group_id
                      AND reservation.bound_epoch=request.bound_epoch
                      AND reservation.bound_group_context_hash=request.bound_group_context_hash
                      AND reservation.bound_confirmation_tag=request.bound_confirmation_tag,
                    reservation.created_at=request.requested_at
                      AND reservation.expires_at=request.expires_at
                      AND reservation.expires_at=
                          LEAST(reservation.created_at + INTERVAL '5 minutes',package.not_after),
                    EXISTS(
                        SELECT 1 FROM chat.participants participant
                         WHERE participant.conversation_id=request.conversation_id
                           AND participant.user_did=request.requester_did
                           AND participant.status='active'
                           AND participant.created_at <= request.requested_at
                           AND (participant.accepted_at IS NULL
                                OR participant.accepted_at <= request.requested_at)
                           AND (participant.removed_at IS NULL
                                OR participant.removed_at >= request.requested_at)),
                    EXISTS(
                        SELECT 1 FROM chat.devices device
                        JOIN chat.device_keys device_key
                          ON device_key.user_did=device.user_did
                         AND device_key.device_id=device.device_id
                         AND device_key.key_id=request.requester_key_id
                        WHERE device.user_did=request.requester_did
                          AND device.device_id=request.requester_device_id
                          AND device.created_at <= request.requested_at
                          AND (device.revoked_at IS NULL OR device.revoked_at >= request.requested_at)
                          AND device_key.created_at <= request.requested_at
                          AND (device_key.revoked_at IS NULL
                               OR device_key.revoked_at >= request.requested_at)),
                    EXISTS(
                        SELECT 1 FROM chat.generation_states state
                         WHERE state.conversation_id=request.conversation_id
                           AND state.generation=request.generation
                           AND state.state_version=request.bound_state_version
                           AND state.created_at <= request.requested_at),
                    NOT EXISTS(
                        SELECT 1 FROM chat.member_devices member
                         WHERE member.conversation_id=request.conversation_id
                           AND member.generation=request.generation
                           AND member.user_did=request.requester_did
                           AND member.device_id=request.requester_device_id
                           AND member.joined_state_version <= request.bound_state_version
                           AND (member.removed_state_version IS NULL
                                OR member.removed_state_version > request.bound_state_version))
                 FROM chat.leaf_recovery_requests request
                 JOIN chat.key_package_reservations reservation
                   ON reservation.recovery_request_id=request.recovery_request_id
                 LEFT JOIN chat.key_packages package
                   ON package.key_package_ref=reservation.key_package_ref
                  AND package.owner_did=reservation.recipient_did
                  AND package.owner_device_id=reservation.recipient_device_id
                WHERE request.recovery_request_id=$1"#,
            )
            .bind(request_id)
            .fetch_one(&mut *tx)
            .await
            .expect("inspect genuine acceptance deferred mapping");
        assert_eq!(
            mapping,
            (true, true, true, true, true, true, true, true),
            "genuine acceptance mapping inputs are exact before deferred validation"
        );
        tx.commit()
            .await
            .expect("genuine acceptance crosses schema constraints");
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) async fn commit_genuine_add_fulfillment(
        pool: &PgPool,
        entry: &RealCreationEntry,
        invitee: &AcceptanceInvitee,
        acceptance: &RealAcceptanceEntry,
        fulfillment: &RealLeafRecoveryFulfillmentEntry,
        creation_transition_id: Uuid,
        state: &ActivePublicState,
        at: DateTime<Utc>,
        key_package_not_after: DateTime<Utc>,
    ) {
        let cid = Uuid::from_bytes(entry.cid);
        let coordinate = state.coordinate();
        let metadata_snapshot_id = Uuid::new_v4();
        let leaf_period_id = Uuid::new_v4();
        let bob_leaf = state
            .binding()
            .tree_summary()
            .leaves()
            .iter()
            .find(|leaf| {
                leaf.basic_credential()
                    == format!("{}#{}", invitee.did, invitee.device_id).as_bytes()
            })
            .expect("committed corpus tree contains Bob");
        assert_eq!(
            bob_leaf.signature_key(),
            invitee.signing_key.verifying_key().as_bytes()
        );
        let mut tx = pool.begin().await.expect("begin genuine Add fulfillment");
        sqlx::query(
            "UPDATE chat.conversations SET current_state_version=3,next_entry_seq=5 \
                 WHERE conversation_id=$1 AND current_generation=0 \
                   AND current_state_version=2 AND next_entry_seq=4",
        )
        .bind(cid)
        .execute(&mut *tx)
        .await
        .expect("advance head through Add fulfillment");
        sqlx::query(
            "UPDATE chat.generations SET current_state_version=3 \
                 WHERE conversation_id=$1 AND generation=0 AND current_state_version=2",
        )
        .bind(cid)
        .execute(&mut *tx)
        .await
        .expect("advance generation through Add fulfillment");
        sqlx::query(
            r#"INSERT INTO chat.transitions(
                    transition_id,conversation_id,kind,actor_did,actor_device_id,actor_key_id,
                    actor_auth_generation,actor_role,actor_device_status,signed_request_bytes,
                    unsigned_projection_bytes,signing_transcript_bytes,request_digest,signature,
                    prior_generation,prior_state_version,next_generation,next_state_version,
                    metadata_snapshot_id,entry_seq,accepted_at
                ) VALUES($1,$2,'leafRecovery',$3,$4,$5,1,'admin','active',$6,$7,$8,$9,$10,
                    0,2,0,3,$11,4,$12)"#,
        )
        .bind(fulfillment.transition_id)
        .bind(cid)
        .bind(&entry.actor_did)
        .bind(entry.actor_device_id)
        .bind(&entry.actor_key_id)
        .bind(&fulfillment.raw_wrapper)
        .bind(&fulfillment.canonical_projection)
        .bind(&fulfillment.signing_transcript)
        .bind(&fulfillment.request_digest)
        .bind(&fulfillment.signature)
        .bind(metadata_snapshot_id)
        .bind(at)
        .execute(&mut *tx)
        .await
        .expect("insert genuine Add fulfillment transition");
        insert_real_generation_state(&mut tx, cid, state, "commit", fulfillment.transition_id, at)
            .await;
        let metadata_ciphertext = vec![0x32_u8; 16];
        sqlx::query(
                r#"INSERT INTO chat.metadata_snapshots(
                    metadata_snapshot_id,conversation_id,generation,state_version,group_id,epoch,
                    group_context_hash,confirmation_tag,producing_transition_id,
                    origin_transition_id,metadata_version,nonce,ciphertext,ciphertext_sha256,
                    ciphertext_size,author_did,author_device_id,author_key_id,author_public_key,
                    author_auth_generation,author_origin_seq,author_role,author_device_status,created_at
                ) VALUES($1,$2,0,3,$3,$4,$5,$6,$7,$8,1,$9,$10,$11,16,$12,$13,$14,$15,
                    1,1,'admin','active',$16)"#,
            )
            .bind(metadata_snapshot_id)
            .bind(cid)
            .bind(coordinate.group_id().to_vec())
            .bind(i64::try_from(coordinate.epoch()).unwrap())
            .bind(coordinate.group_context_hash().to_vec())
            .bind(coordinate.confirmation_tag().to_vec())
            .bind(fulfillment.transition_id)
            .bind(creation_transition_id)
            .bind(vec![0x26_u8; 12])
            .bind(&metadata_ciphertext)
            .bind(Sha256::digest(&metadata_ciphertext).to_vec())
            .bind(&entry.actor_did)
            .bind(entry.actor_device_id)
            .bind(&entry.actor_key_id)
            .bind(&entry.public_key)
            .bind(at)
            .execute(&mut *tx)
            .await
            .expect("insert genuine fulfillment metadata");
        sqlx::query(
            r#"INSERT INTO chat.entries(
                    conversation_id,seq,entry_id,entry_kind,accepted_payload_bytes,
                    accepted_payload_sha256,signed_request_bytes,request_digest,signature,
                    server_fields_bytes,outer_entry_fingerprint,actor_did,actor_device_id,
                    actor_key_id,actor_auth_generation,generation,state_version,transition_id,
                    received_at
                ) VALUES($1,4,$2,'blue.catbird.chat.defs#leafRecoveryFulfillmentEntry',
                    $3,$4,$5,$6,$7,$8,$9,$10,$11,$12,1,0,3,$13,$14)"#,
        )
        .bind(cid)
        .bind(fulfillment.entry_id)
        .bind(&fulfillment.public_row_json)
        .bind(Sha256::digest(&fulfillment.public_row_json).to_vec())
        .bind(&fulfillment.raw_wrapper)
        .bind(&fulfillment.request_digest)
        .bind(&fulfillment.signature)
        .bind(&fulfillment.server_fields_dag_cbor)
        .bind(fulfillment.outer_entry_fingerprint.to_vec())
        .bind(&entry.actor_did)
        .bind(entry.actor_device_id)
        .bind(&entry.actor_key_id)
        .bind(fulfillment.transition_id)
        .bind(at)
        .execute(&mut *tx)
        .await
        .expect("insert genuine Add fulfillment entry");
        sqlx::query(
            r#"INSERT INTO chat.entry_recipients(
                    conversation_id,seq,user_did,device_id,entitlement_kind
                ) VALUES($1,4,$2,$3,'control')"#,
        )
        .bind(cid)
        .bind(&entry.actor_did)
        .bind(entry.actor_device_id)
        .execute(&mut *tx)
        .await
        .expect("route genuine Add fulfillment to Alice");
        sqlx::query(
            r#"INSERT INTO chat.member_devices(
                    leaf_period_id,participant_period_id,conversation_id,generation,user_did,
                    device_id,leaf_index,basic_credential,leaf_signature_key,leaf_key_id,
                    leaf_auth_generation,origin,join_key_package_ref,joined_state_version,
                    joined_transition_id,joined_seq,active,created_at
                ) VALUES($1,$2,$3,0,$4,$5,$6,$7,$8,$9,1,'keyPackage',$10,3,$11,4,true,$12)"#,
        )
        .bind(leaf_period_id)
        .bind(invitee.participant_period_id)
        .bind(cid)
        .bind(&invitee.did)
        .bind(invitee.device_id)
        .bind(i64::from(bob_leaf.leaf_index()))
        .bind(bob_leaf.basic_credential())
        .bind(bob_leaf.signature_key())
        .bind(&invitee.key_id)
        .bind(acceptance.key_package_ref.to_vec())
        .bind(fulfillment.transition_id)
        .bind(at)
        .execute(&mut *tx)
        .await
        .expect("insert genuine Bob leaf");
        sqlx::query(
            r#"INSERT INTO chat.application_intervals(
                    membership_interval_id,conversation_id,generation,recipient_did,
                    recipient_device_id,start_seq,opening_kind,opening_transition_id,
                    opening_outer_entry_fingerprint,opening_state_version,opening_group_id,
                    opening_epoch,opening_group_context_hash,opening_confirmation_tag,
                    opening_leaf_period_id,created_at
                ) VALUES($1,$2,0,$3,$4,4,'add',$1,$5,3,$6,$7,$8,$9,$10,$11)"#,
        )
        .bind(fulfillment.transition_id)
        .bind(cid)
        .bind(&invitee.did)
        .bind(invitee.device_id)
        .bind(fulfillment.outer_entry_fingerprint.to_vec())
        .bind(coordinate.group_id().to_vec())
        .bind(i64::try_from(coordinate.epoch()).unwrap())
        .bind(coordinate.group_context_hash().to_vec())
        .bind(coordinate.confirmation_tag().to_vec())
        .bind(leaf_period_id)
        .bind(at)
        .execute(&mut *tx)
        .await
        .expect("open genuine Bob interval");
        let request_id = Uuid::from_bytes(acceptance.request_id);
        sqlx::query(
            "UPDATE chat.leaf_recovery_requests SET status='fulfilled',\
                 fulfilling_transition_id=$1,terminal_at=$2 \
                 WHERE recovery_request_id=$3 AND status='open'",
        )
        .bind(fulfillment.transition_id)
        .bind(at)
        .bind(request_id)
        .execute(&mut *tx)
        .await
        .expect("fulfill genuine Add recovery");
        sqlx::query(
            "UPDATE chat.key_package_reservations SET status='consumed',\
                 consumed_transition_id=$1,terminal_at=$2 \
                 WHERE recovery_request_id=$3 AND status='active'",
        )
        .bind(fulfillment.transition_id)
        .bind(at)
        .bind(request_id)
        .execute(&mut *tx)
        .await
        .expect("consume genuine Add reservation");
        sqlx::query(
            "UPDATE chat.key_packages SET status='consumed',terminal_transition_id=$1,\
                 terminal_at=$2 WHERE key_package_ref=$3 AND status='reserved'",
        )
        .bind(fulfillment.transition_id)
        .bind(at)
        .bind(acceptance.key_package_ref.to_vec())
        .execute(&mut *tx)
        .await
        .expect("consume genuine Bob package");
        sqlx::query(
            r#"INSERT INTO chat.welcome_bundles(
                    welcome_id,conversation_id,transition_id,entry_seq,generation,state_version,
                    group_id,epoch,group_context_hash,confirmation_tag,wrapper_bytes,
                    wrapper_sha256,created_at
                ) VALUES($1,$2,$3,4,0,3,$4,$5,$6,$7,$8,$9,$10)"#,
        )
        .bind(fulfillment.welcome_id)
        .bind(cid)
        .bind(fulfillment.transition_id)
        .bind(coordinate.group_id().to_vec())
        .bind(i64::try_from(coordinate.epoch()).unwrap())
        .bind(coordinate.group_context_hash().to_vec())
        .bind(coordinate.confirmation_tag().to_vec())
        .bind(&fulfillment.opaque_welcome)
        .bind(Sha256::digest(&fulfillment.opaque_welcome).to_vec())
        .bind(at)
        .execute(&mut *tx)
        .await
        .expect("insert genuine Welcome bundle");
        sqlx::query(
            r#"INSERT INTO chat.welcome_deliveries(
                    welcome_id,recipient_did,recipient_device_id,recovery_request_id,
                    key_package_ref,expires_at,status
                ) VALUES($1,$2,$3,$4,$5,$6,'pending')"#,
        )
        .bind(fulfillment.welcome_id)
        .bind(&invitee.did)
        .bind(invitee.device_id)
        .bind(request_id)
        .bind(acceptance.key_package_ref.to_vec())
        .bind(key_package_not_after)
        .execute(&mut *tx)
        .await
        .expect("insert genuine pending Welcome");
        tx.commit()
            .await
            .expect("genuine Add fulfillment crosses deferred mappings");
    }

    pub(crate) struct RealLeafRecoveryFulfillmentEntry {
        pub(crate) entry_id: Uuid,
        pub(crate) transition_id: Uuid,
        pub(crate) welcome_id: Uuid,
        pub(crate) public_row_json: Vec<u8>,
        pub(crate) raw_wrapper: Vec<u8>,
        pub(crate) canonical_projection: Vec<u8>,
        pub(crate) signing_transcript: Vec<u8>,
        pub(crate) request_digest: Vec<u8>,
        pub(crate) signature: Vec<u8>,
        pub(crate) server_fields_dag_cbor: Vec<u8>,
        pub(crate) outer_entry_fingerprint: [u8; 32],
        pub(crate) opaque_welcome: Vec<u8>,
    }

    pub(crate) fn build_genuine_add_fulfillment_entry_with_bytes(
        entry: &RealCreationEntry,
        invitee: &AcceptanceInvitee,
        acceptance: &RealAcceptanceEntry,
        creation_transition_id: Uuid,
        prior: &PublicGroupSnapshotCoordinate,
        next: &PublicGroupSnapshotCoordinate,
        transition_id: Uuid,
        seq: u64,
        signed_at: &str,
        received_at: &str,
        commit_bytes: Vec<u8>,
        opaque_welcome: Vec<u8>,
        metadata_nonce_byte: u8,
        metadata_ciphertext_byte: u8,
    ) -> RealLeafRecoveryFulfillmentEntry {
        let signing_key = entry.signing_key();
        let entry_id = Uuid::new_v4();
        let welcome_id = Uuid::new_v4();
        let metadata_ciphertext = vec![metadata_ciphertext_byte; 16];
        let request_id = Uuid::from_bytes(acceptance.request_id);
        let body = json!({
            "$type": SignedMutationKind::LeafRecoveryFulfillment.type_id(),
            "signatureDomain": String::from_utf8(
                SignedMutationKind::LeafRecoveryFulfillment.domain().to_vec()
            ).unwrap(),
            "transitionId": transition_id,
            "actorDid": &entry.actor_did,
            "actorDeviceId": entry.actor_device_id,
            "keyId": &entry.actor_key_id,
            "authGeneration": 1,
            "prior": coordinate_json(prior),
            "next": coordinate_json(next),
            "aad": {
                "protocolVersion": "1",
                "conversationId": STANDARD.encode(entry.cid),
                "generation": prior.generation(),
                "transitionId": STANDARD.encode(transition_id.as_bytes()),
                "prior": {
                    "conversationId": STANDARD.encode(entry.cid),
                    "generation": prior.generation(),
                    "stateVersion": prior.state_version(),
                    "groupId": STANDARD.encode(prior.group_id()),
                    "epoch": prior.epoch(),
                    "groupContextHash": STANDARD.encode(prior.group_context_hash()),
                    "confirmationTag": STANDARD.encode(prior.confirmation_tag()),
                    "lifecycle": "active",
                },
            },
            "manifest": {
                "participantChanges": [],
                "leafChanges": [{
                    "$type": "blue.catbird.chat.defs#addLeafByRecovery",
                    "userDid": &invitee.did,
                    "deviceId": invitee.device_id,
                    "recoveryRequestId": request_id,
                    "keyPackageRef": STANDARD.encode(acceptance.key_package_ref),
                }],
                "leafRecoveryRequestId": request_id,
                "welcomeBundle": {
                    "welcomeId": welcome_id,
                    "framing": "mlsMessage",
                    "contentType": "welcome",
                    "opaqueWelcome": STANDARD.encode(&opaque_welcome),
                    "sha256": STANDARD.encode(Sha256::digest(&opaque_welcome)),
                    "deliveries": [{
                        "recipientDid": &invitee.did,
                        "recipientDeviceId": invitee.device_id,
                        "provenance": {
                            "recoveryRequestId": request_id,
                            "keyPackageRef": STANDARD.encode(acceptance.key_package_ref),
                        },
                    }],
                },
            },
            "commit": {
                "framing": "mlsMessage",
                "contentType": "publicMessageCommit",
                "bytes": STANDARD.encode(&commit_bytes),
                "sha256": STANDARD.encode(Sha256::digest(&commit_bytes)),
            },
            "metadataSnapshot": {
                "coordinate": {
                    "conversationId": STANDARD.encode(entry.cid),
                    "generation": next.generation(),
                    "groupId": STANDARD.encode(next.group_id()),
                    "epoch": next.epoch(),
                    "groupContextHash": STANDARD.encode(next.group_context_hash()),
                    "confirmationTag": STANDARD.encode(next.confirmation_tag()),
                },
                "originTransitionId": creation_transition_id,
                "metadataVersion": 1,
                "nonce": STANDARD.encode([metadata_nonce_byte; 12]),
                "ciphertext": STANDARD.encode(&metadata_ciphertext),
                "ciphertextSha256": STANDARD.encode(Sha256::digest(&metadata_ciphertext)),
                "ciphertextSize": metadata_ciphertext.len(),
                "authorProof": {
                    "authorDid": &entry.actor_did,
                    "authorDeviceId": entry.actor_device_id,
                    "authorKeyId": &entry.actor_key_id,
                    "signaturePublicKey": STANDARD.encode(&entry.public_key),
                    "authGenerationAtOrigin": 1,
                    "originTransitionId": creation_transition_id,
                    "originSeq": 1,
                    "roleAtOrigin": "admin",
                    "deviceStatusAtOrigin": "active",
                },
            },
            "recoveryRequestId": request_id,
            "idempotencyKey": Uuid::new_v4(),
            "signedAt": signed_at,
        });
        let mut wrapper = json!({"body": body, "signature": STANDARD.encode([0_u8; 64])});
        let unsigned = serde_json::to_vec(&wrapper).unwrap();
        let unsigned_canonical =
            decode_canonical_signed_mutation(&unsigned).expect("Add fulfillment canonical");
        let signature = signing_key
            .sign(unsigned_canonical.transcript_bytes())
            .to_bytes();
        wrapper["signature"] = Value::String(STANDARD.encode(signature));
        let raw_wrapper = serde_json::to_vec(&wrapper).unwrap();
        let canonical = decode_canonical_signed_mutation(&raw_wrapper)
            .expect("signed Add fulfillment canonical");
        let public_row_json = serde_json::to_vec(&json!({
            "$type": "blue.catbird.chat.defs#leafRecoveryFulfillmentEntry",
            "entryId": entry_id,
            "conversationId": Uuid::from_bytes(entry.cid),
            "seq": seq,
            "signedRequest": wrapper,
            "receivedAt": received_at,
        }))
        .unwrap();
        let decoded = decode_and_verify_control_entry(&public_row_json, &entry.public_key)
            .expect("genuine Add fulfillment control verifies");
        RealLeafRecoveryFulfillmentEntry {
            entry_id,
            transition_id,
            welcome_id,
            public_row_json,
            raw_wrapper,
            canonical_projection: canonical.canonical_projection().to_vec(),
            signing_transcript: canonical.transcript_bytes().to_vec(),
            request_digest: canonical.request_digest().to_vec(),
            signature: canonical.signature().to_vec(),
            server_fields_dag_cbor: decoded
                .server_fields_dag_cbor()
                .expect("fulfillment server fields"),
            outer_entry_fingerprint: *decoded.outer_control_fingerprint(),
            opaque_welcome,
        }
    }

    struct DynamicGenuineTwoLeafGraph {
        graph: GenuinePolicyRoleGraph,
        remove_transition_id: Uuid,
        remove_commit: Vec<u8>,
        removed: ActivePublicState,
        remove_at: DateTime<Utc>,
    }

    async fn seed_dynamic_genuine_two_leaf_graph(pool: &PgPool) -> DynamicGenuineTwoLeafGraph {
        let creation_at = DateTime::<Utc>::from_timestamp(Utc::now().timestamp(), 0)
            .expect("current fixture time is representable");
        let policy_at = creation_at + chrono::Duration::seconds(1);
        let acceptance_at = creation_at + chrono::Duration::seconds(2);
        let fulfillment_at = creation_at + chrono::Duration::seconds(3);
        let remove_at = creation_at + chrono::Duration::seconds(6);
        let package_not_before = creation_at - chrono::Duration::minutes(1);
        let package_not_after = creation_at + chrono::Duration::days(30);
        let cid = Uuid::new_v4();
        let add_transition_id = Uuid::new_v4();
        let invitee = dynamic_invitee();
        let fresh = build_dynamic_two_leaf_crypto_fixture(
            cid,
            add_transition_id,
            invitee,
            creation_at,
            acceptance_at,
            fulfillment_at,
            package_not_before,
            package_not_after,
        );
        let DynamicTwoLeafCryptoFixture {
            mut entry,
            invitee,
            genesis_group_info,
            genesis,
            committed,
            key_package_ref,
            key_package_wrapper,
            commit,
            welcome,
            remove_transition_id,
            remove_commit,
            removed,
        } = fresh;
        entry.head_next_entry_seq = 2;
        let creation_graph =
            seed_genuine_creation_graph(pool, &entry, Some(&genesis), Some(&genesis_group_info))
                .await;
        let creation_transition_id = creation_graph.creation_transition_id;

        let policy_at_text = policy_at.to_rfc3339_opts(SecondsFormat::Millis, true);
        let policy = genuine_policy_control(
            &entry,
            genesis.coordinate(),
            2,
            &policy_at_text,
            vec![GenuinePolicyChange::Add(&invitee.did)],
        );
        let policy_state = rebound_state(&genesis, 1);
        let mut tx = pool
            .begin()
            .await
            .expect("begin dynamic genuine Policy Add");
        sqlx::query(
            "INSERT INTO chat.principals(user_did,created_at) VALUES($1,$2) ON CONFLICT DO NOTHING",
        )
        .bind(&invitee.did)
        .bind(policy_at)
        .execute(&mut *tx)
        .await
        .expect("insert dynamic invitee principal");
        sqlx::query(
            r#"INSERT INTO chat.devices(
                user_did,device_id,device_name,status,dpop_jkt,auth_generation,
                capabilities,created_at,updated_at
            ) VALUES($1,$2,'genuine-former-leaf','active',$3,1,chat.protocol_capabilities(),$4,$4)"#,
        )
        .bind(&invitee.did)
        .bind(invitee.device_id)
        .bind(&invitee.key_id)
        .bind(policy_at)
        .execute(&mut *tx)
        .await
        .expect("insert dynamic invitee device");
        sqlx::query(
            r#"INSERT INTO chat.device_keys(
                user_did,device_id,key_id,signing_public_key,enrollment_auth_generation,created_at
            ) VALUES($1,$2,$3,$4,1,$5)"#,
        )
        .bind(&invitee.did)
        .bind(invitee.device_id)
        .bind(&invitee.key_id)
        .bind(invitee.signing_key.verifying_key().to_bytes().to_vec())
        .bind(policy_at)
        .execute(&mut *tx)
        .await
        .expect("insert dynamic invitee key");
        sqlx::query(
            "UPDATE chat.conversations SET current_state_version=1,next_entry_seq=3 \
             WHERE conversation_id=$1 AND current_generation=0 \
               AND current_state_version=0 AND next_entry_seq=2",
        )
        .bind(cid)
        .execute(&mut *tx)
        .await
        .expect("advance dynamic head through Policy Add");
        sqlx::query(
            "UPDATE chat.generations SET current_state_version=1 \
             WHERE conversation_id=$1 AND generation=0 AND current_state_version=0",
        )
        .bind(cid)
        .execute(&mut *tx)
        .await
        .expect("advance dynamic generation through Policy Add");
        sqlx::query(
            r#"INSERT INTO chat.transitions(
                transition_id,conversation_id,kind,actor_did,actor_device_id,actor_key_id,
                actor_auth_generation,actor_role,actor_device_status,signed_request_bytes,
                unsigned_projection_bytes,signing_transcript_bytes,request_digest,signature,
                prior_generation,prior_state_version,next_generation,next_state_version,
                entry_seq,accepted_at
            ) VALUES($1,$2,'policy',$3,$4,$5,1,'admin','active',$6,$7,$8,$9,$10,
                0,0,0,1,2,$11)"#,
        )
        .bind(policy.transition_id)
        .bind(cid)
        .bind(&entry.actor_did)
        .bind(entry.actor_device_id)
        .bind(&entry.actor_key_id)
        .bind(&policy.entry.signed_request_bytes)
        .bind(&policy.entry.unsigned_projection_bytes)
        .bind(&policy.entry.signing_transcript_bytes)
        .bind(&policy.entry.request_digest)
        .bind(&policy.entry.signature)
        .bind(policy_at)
        .execute(&mut *tx)
        .await
        .expect("insert dynamic Policy Add transition");
        insert_real_generation_state(
            &mut tx,
            cid,
            &policy_state,
            "policy",
            policy.transition_id,
            policy_at,
        )
        .await;
        sqlx::query(
            r#"INSERT INTO chat.entries(
                conversation_id,seq,entry_id,entry_kind,accepted_payload_bytes,
                accepted_payload_sha256,signed_request_bytes,request_digest,signature,
                server_fields_bytes,outer_entry_fingerprint,actor_did,actor_device_id,
                actor_key_id,actor_auth_generation,generation,state_version,transition_id,
                received_at
            ) VALUES($1,2,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,1,0,1,$14,$15)"#,
        )
        .bind(cid)
        .bind(policy.entry.entry_id)
        .bind(&policy.entry.entry_kind)
        .bind(&policy.entry.accepted_payload_bytes)
        .bind(&policy.entry.accepted_payload_sha256)
        .bind(&policy.entry.signed_request_bytes)
        .bind(&policy.entry.request_digest)
        .bind(&policy.entry.signature)
        .bind(&policy.entry.server_fields_bytes)
        .bind(&policy.entry.outer_entry_fingerprint)
        .bind(&entry.actor_did)
        .bind(entry.actor_device_id)
        .bind(&entry.actor_key_id)
        .bind(policy.transition_id)
        .bind(policy_at)
        .execute(&mut *tx)
        .await
        .expect("insert dynamic Policy Add entry");
        sqlx::query(
            "INSERT INTO chat.entry_recipients(conversation_id,seq,user_did,device_id,entitlement_kind) \
             VALUES($1,2,$2,$3,'control')",
        )
        .bind(cid)
        .bind(&entry.actor_did)
        .bind(entry.actor_device_id)
        .execute(&mut *tx)
        .await
        .expect("route dynamic Policy Add");
        sqlx::query(
            r#"INSERT INTO chat.participants(
                participant_period_id,conversation_id,user_did,status,role,role_transition_id,
                role_changed_at,created_by_did,created_by_device_id,invitation_transition_id,
                invitation_entry_id,invited_at,current_membership,created_at
            ) VALUES($1,$2,$3,'pending','member',$4,$5,$6,$7,$4,$8,$5,true,$5)"#,
        )
        .bind(invitee.participant_period_id)
        .bind(cid)
        .bind(&invitee.did)
        .bind(policy.transition_id)
        .bind(policy_at)
        .bind(&entry.actor_did)
        .bind(entry.actor_device_id)
        .bind(policy.entry.entry_id)
        .execute(&mut *tx)
        .await
        .expect("insert dynamically invited participant");
        tx.commit()
            .await
            .expect("dynamic genuine Policy Add crosses constraints");

        let acceptance_signed_at = (acceptance_at - chrono::Duration::milliseconds(500))
            .to_rfc3339_opts(SecondsFormat::Millis, true);
        let acceptance_at_text = acceptance_at.to_rfc3339_opts(SecondsFormat::Millis, true);
        let acceptance_expires_at = acceptance_at + chrono::Duration::minutes(5);
        let acceptance_expires_text =
            acceptance_expires_at.to_rfc3339_opts(SecondsFormat::Millis, true);
        let acceptance = build_real_acceptance_entry_at(
            &entry,
            &invitee,
            policy.transition_id,
            coordinate_json(policy_state.coordinate()),
            3,
            &acceptance_signed_at,
            &acceptance_at_text,
            &acceptance_expires_text,
            Some((key_package_ref, key_package_wrapper)),
        );
        let acceptance_state = rebound_state(&policy_state, 2);
        commit_genuine_acceptance(
            pool,
            &entry,
            &invitee,
            &acceptance,
            &acceptance_state,
            acceptance_at,
            acceptance_expires_at,
            package_not_before,
            package_not_after,
            acceptance_at,
        )
        .await;

        let fulfillment_signed_at = (fulfillment_at - chrono::Duration::milliseconds(500))
            .to_rfc3339_opts(SecondsFormat::Millis, true);
        let fulfillment_at_text = fulfillment_at.to_rfc3339_opts(SecondsFormat::Millis, true);
        let fulfillment = build_genuine_add_fulfillment_entry_with_bytes(
            &entry,
            &invitee,
            &acceptance,
            creation_transition_id,
            acceptance_state.coordinate(),
            committed.coordinate(),
            add_transition_id,
            4,
            &fulfillment_signed_at,
            &fulfillment_at_text,
            commit,
            welcome,
            0x56,
            0x57,
        );
        commit_genuine_add_fulfillment(
            pool,
            &entry,
            &invitee,
            &acceptance,
            &fulfillment,
            creation_transition_id,
            &committed,
            fulfillment_at,
            package_not_after,
        )
        .await;

        DynamicGenuineTwoLeafGraph {
            graph: GenuinePolicyRoleGraph {
                creation_graph,
                entry,
                invitee,
                acceptance,
                fulfillment,
                committed,
            },
            remove_transition_id,
            remove_commit,
            removed,
            remove_at,
        }
    }

    pub(super) struct RemovalFixtureData {
        pub creation_graph: GenuineCreationGraph,
        pub removed_did: String,
        pub removed_device_id: Uuid,
        pub removed_dpop_jkt: String,
        pub removed_auth_generation: u64,
        pub participant_period_id: Uuid,
        pub leaf_period_id: Uuid,
        pub membership_interval_id: Uuid,
        pub interval_start_seq: u64,
        pub terminal_seq: u64,
        pub terminal_transition_id: Uuid,
        pub terminal_outer_entry_fingerprint: [u8; 32],
        pub removed_at: DateTime<Utc>,
        pub current_generation: u64,
        pub current_state_version: u64,
        pub current_graph_digest: [u8; 32],
        pub current_snapshot_digest: [u8; 32],
    }

    pub(super) async fn seed_private_genuine_removal(pool: &PgPool) -> RemovalFixtureData {
        let dynamic = seed_dynamic_genuine_two_leaf_graph(pool).await;
        let creation_transition_id = dynamic.graph.creation_graph.creation_transition_id;
        let leave_at = dynamic.remove_at - chrono::Duration::seconds(1);
        let leave = commit_dynamic_leave_request(pool, &dynamic.graph, leave_at).await;
        let DynamicGenuineTwoLeafGraph {
            graph,
            remove_transition_id,
            remove_commit,
            removed,
            remove_at,
        } = dynamic;
        let GenuinePolicyRoleGraph {
            creation_graph,
            entry,
            invitee,
            acceptance: _,
            fulfillment,
            committed,
        } = graph;
        let actors = TerminalFamilyBActors { entry, invitee };
        commit_dynamic_remove_fulfillment(
            pool,
            &actors,
            creation_transition_id,
            &committed,
            &removed,
            &leave,
            remove_transition_id,
            remove_commit,
            fulfillment.welcome_id,
            remove_at,
        )
        .await;

        let cid = creation_graph.conversation_id;
        let row: (
            Uuid,
            Uuid,
            Uuid,
            i64,
            i64,
            Uuid,
            Vec<u8>,
            DateTime<Utc>,
            String,
            String,
            i64,
            i64,
        ) = sqlx::query_as(
            r#"SELECT participant.participant_period_id,
                      leaf.leaf_period_id,
                      interval.membership_interval_id,
                      interval.start_seq,
                      interval.terminal_seq,
                      interval.closing_transition_id,
                      interval.closing_outer_entry_fingerprint,
                      interval.removed_at,
                      device.status,
                      device.dpop_jkt,
                      device.auth_generation,
                      (
                        SELECT count(*)
                          FROM chat.application_intervals later
                         WHERE later.conversation_id=interval.conversation_id
                           AND later.recipient_did=interval.recipient_did
                           AND later.recipient_device_id=interval.recipient_device_id
                           AND later.start_seq > interval.terminal_seq
                      )
                 FROM chat.participants participant
                 JOIN chat.member_devices leaf
                   ON leaf.participant_period_id=participant.participant_period_id
                 JOIN chat.application_intervals interval
                   ON interval.opening_leaf_period_id=leaf.leaf_period_id
                 JOIN chat.devices device
                   ON device.user_did=leaf.user_did
                  AND device.device_id=leaf.device_id
                WHERE participant.conversation_id=$1
                  AND participant.user_did=$2
                  AND NOT participant.current_membership"#,
        )
        .bind(cid)
        .bind(&actors.invitee.did)
        .fetch_one(pool)
        .await
        .expect("load exact genuine removal provenance");
        assert_eq!(
            row.8, "active",
            "removed leaf device registration stays active"
        );
        assert_eq!(row.11, 0, "removed exact device has no later interval");
        assert_eq!(row.4, 6);
        assert_eq!(row.5, remove_transition_id);

        let locked_at: DateTime<Utc> =
            sqlx::query_scalar("SELECT date_trunc('milliseconds', clock_timestamp())")
                .fetch_one(pool)
                .await
                .expect("sample removal hydration instant");
        let mut tx = pool
            .begin()
            .await
            .expect("begin removal aggregate hydration");
        let locked = hydrate_locked_conversation_state(&mut tx, cid, locked_at)
            .await
            .expect("genuine removal graph passes production aggregate hydration");
        let interval = locked
            .state()
            .intervals()
            .iter()
            .find(|interval| {
                interval.recipient().principal().as_bytes() == actors.invitee.did.as_bytes()
                    && interval.recipient().device_id() == actors.invitee.device_id.as_bytes()
            })
            .expect("production aggregate retains removed exact-device interval");
        assert_eq!(interval.opening_transition_id(), row.2.as_bytes());
        let end = interval
            .end()
            .expect("removed exact-device interval is finite");
        assert_eq!(end.seq(), 6);
        assert_eq!(end.transition_id(), row.5.as_bytes());
        assert_eq!(end.outer_entry_fingerprint(), row.6.as_slice());
        let current_generation = locked.state().coordinate().generation();
        let current_state_version = locked.state().coordinate().state_version();
        let current_graph_digest = *locked.locked_graph_digest();
        let current_snapshot_digest = *locked
            .locked_snapshot_digest()
            .expect("active removal graph snapshot digest");
        tx.rollback()
            .await
            .expect("rollback removal aggregate hydration");

        RemovalFixtureData {
            creation_graph,
            removed_did: actors.invitee.did,
            removed_device_id: actors.invitee.device_id,
            removed_dpop_jkt: row.9,
            removed_auth_generation: u64::try_from(row.10).expect("auth generation"),
            participant_period_id: row.0,
            leaf_period_id: row.1,
            membership_interval_id: row.2,
            interval_start_seq: u64::try_from(row.3).expect("interval start"),
            terminal_seq: u64::try_from(row.4).expect("interval terminal"),
            terminal_transition_id: row.5,
            terminal_outer_entry_fingerprint: row
                .6
                .try_into()
                .expect("terminal outer fingerprint is 32 bytes"),
            removed_at: row.7,
            current_generation,
            current_state_version,
            current_graph_digest,
            current_snapshot_digest,
        }
    }

    pub(super) struct ResetFixtureData {
        pub creation_graph: GenuineCreationGraph,
        pub old_did: String,
        pub old_device_id: Uuid,
        pub old_key_id: String,
        pub old_dpop_jkt: String,
        pub old_auth_generation: u64,
        pub participant_period_id: Uuid,
        pub leaf_period_id: Uuid,
        pub membership_interval_id: Uuid,
        pub interval_start_seq: u64,
        pub terminal_seq: u64,
        pub terminal_transition_id: Uuid,
        pub terminal_outer_entry_fingerprint: [u8; 32],
        pub reset_at: DateTime<Utc>,
        pub old_generation: u64,
        pub current_generation: u64,
        pub current_state_version: u64,
        pub current_group_id: [u8; 32],
        pub current_graph_digest: [u8; 32],
        pub current_snapshot_digest: [u8; 32],
    }

    pub(super) async fn seed_private_genuine_reset(pool: &PgPool) -> ResetFixtureData {
        let dynamic = seed_dynamic_genuine_two_leaf_graph(pool).await;
        let request_at = dynamic.remove_at - chrono::Duration::seconds(1);
        let request = commit_dynamic_reset_request(pool, &dynamic.graph, request_at).await;
        let activation =
            commit_dynamic_reset_activation(pool, &dynamic.graph, &request, dynamic.remove_at)
                .await;
        let cid = dynamic.graph.creation_graph.conversation_id;
        let invitee = &dynamic.graph.invitee;
        let row: (
            Uuid,
            Uuid,
            Uuid,
            i64,
            i64,
            Uuid,
            Vec<u8>,
            DateTime<Utc>,
            String,
            String,
            i64,
            String,
            i64,
            i64,
        ) = sqlx::query_as(
            r#"SELECT participant.participant_period_id,
                      leaf.leaf_period_id,
                      interval.membership_interval_id,
                      interval.start_seq,
                      interval.terminal_seq,
                      interval.closing_transition_id,
                      interval.closing_outer_entry_fingerprint,
                      interval.removed_at,
                      device.status,
                      device.dpop_jkt,
                      device.auth_generation,
                      interval.closing_kind,
                      (
                        SELECT count(*)
                          FROM chat.application_intervals later
                         WHERE later.conversation_id=interval.conversation_id
                           AND later.recipient_did=interval.recipient_did
                           AND later.recipient_device_id=interval.recipient_device_id
                           AND later.start_seq > interval.terminal_seq
                      ),
                      (
                        SELECT count(*)
                          FROM chat.member_devices current_leaf
                         WHERE current_leaf.conversation_id=interval.conversation_id
                           AND current_leaf.user_did=interval.recipient_did
                           AND current_leaf.device_id=interval.recipient_device_id
                           AND current_leaf.active
                      )
                 FROM chat.participants participant
                 JOIN chat.member_devices leaf
                   ON leaf.participant_period_id=participant.participant_period_id
                 JOIN chat.application_intervals interval
                   ON interval.opening_leaf_period_id=leaf.leaf_period_id
                 JOIN chat.devices device
                   ON device.user_did=leaf.user_did
                  AND device.device_id=leaf.device_id
                WHERE participant.conversation_id=$1
                  AND participant.user_did=$2
                  AND participant.current_membership
                  AND interval.closing_kind='reset'"#,
        )
        .bind(cid)
        .bind(&invitee.did)
        .fetch_one(pool)
        .await
        .expect("load exact genuine reset provenance");
        assert_eq!(row.8, "active", "reset-retired device stays registered");
        assert_eq!(row.11, "reset");
        assert_eq!(row.12, 0, "old exact device has no later interval");
        assert_eq!(row.13, 0, "old exact device has no current leaf");
        assert_eq!(row.4, 6);
        assert_eq!(row.5, activation.transition_id);

        let old_generation_open_intervals: i64 = sqlx::query_scalar(
            r#"SELECT count(*) FROM chat.application_intervals
                WHERE conversation_id=$1 AND generation=0 AND terminal_seq IS NULL"#,
        )
        .bind(cid)
        .fetch_one(pool)
        .await
        .expect("prove no old-generation open interval");
        assert_eq!(old_generation_open_intervals, 0);
        let generation_lifecycle: String = sqlx::query_scalar(
            "SELECT lifecycle FROM chat.generations WHERE conversation_id=$1 AND generation=0",
        )
        .bind(cid)
        .fetch_one(pool)
        .await
        .expect("old generation lifecycle");
        assert_eq!(generation_lifecycle, "superseded");

        let locked_at: DateTime<Utc> =
            sqlx::query_scalar("SELECT date_trunc('milliseconds', clock_timestamp())")
                .fetch_one(pool)
                .await
                .expect("sample reset hydration instant");
        let mut tx = pool.begin().await.expect("begin reset aggregate hydration");
        let locked = hydrate_locked_conversation_state(&mut tx, cid, locked_at)
            .await
            .expect("genuine reset graph passes production aggregate hydration");
        let old_identity = DeviceIdentity::new(
            PrincipalId::new(invitee.did.as_bytes().to_vec()).expect("old reset DID"),
            *invitee.device_id.as_bytes(),
        )
        .expect("old reset identity");
        assert!(locked.state().leaf(&old_identity).is_none());
        let interval = locked
            .state()
            .intervals()
            .iter()
            .find(|interval| interval.recipient() == &old_identity)
            .expect("production aggregate retains reset-retired exact interval");
        let end = interval.end().expect("reset-retired interval is finite");
        assert_eq!(end.seq(), 6);
        assert_eq!(end.transition_id(), row.5.as_bytes());
        assert_eq!(end.outer_entry_fingerprint(), row.6.as_slice());
        let coordinate = *locked.state().coordinate();
        assert_eq!(coordinate.generation(), 1);
        assert_eq!(coordinate.state_version(), 0);
        assert_eq!(
            locked.state().leaves().len(),
            1,
            "reset successor contains only actor leaf"
        );
        let current_graph_digest = *locked.locked_graph_digest();
        let current_snapshot_digest = *locked
            .locked_snapshot_digest()
            .expect("active reset graph snapshot digest");
        tx.rollback()
            .await
            .expect("rollback reset aggregate hydration");

        ResetFixtureData {
            creation_graph: dynamic.graph.creation_graph,
            old_did: invitee.did.clone(),
            old_device_id: invitee.device_id,
            old_key_id: invitee.key_id.clone(),
            old_dpop_jkt: row.9,
            old_auth_generation: u64::try_from(row.10).expect("auth generation"),
            participant_period_id: row.0,
            leaf_period_id: row.1,
            membership_interval_id: row.2,
            interval_start_seq: u64::try_from(row.3).expect("interval start"),
            terminal_seq: u64::try_from(row.4).expect("interval terminal"),
            terminal_transition_id: row.5,
            terminal_outer_entry_fingerprint: row
                .6
                .try_into()
                .expect("terminal outer fingerprint is 32 bytes"),
            reset_at: row.7,
            old_generation: 0,
            current_generation: coordinate.generation(),
            current_state_version: coordinate.state_version(),
            current_group_id: *coordinate.group_id(),
            current_graph_digest,
            current_snapshot_digest,
        }
    }
}

pub struct GenuineFormerLeaf {
    pub did: String,
    pub device_id: Uuid,
    pub dpop_jkt: String,
    pub auth_generation: u64,
    pub participant_period_id: Uuid,
    pub leaf_period_id: Uuid,
    pub membership_interval_id: Uuid,
    pub interval_start_seq: u64,
    pub terminal_seq: u64,
    pub terminal_transition_id: Uuid,
    pub terminal_outer_entry_fingerprint: [u8; 32],
    pub removed_at: DateTime<Utc>,
}

impl GenuineFormerLeaf {
    pub fn device_identity(&self) -> DeviceIdentity {
        DeviceIdentity::new(
            PrincipalId::new(self.did.as_bytes().to_vec()).expect("former leaf DID"),
            *self.device_id.as_bytes(),
        )
        .expect("former leaf device identity")
    }
}

pub struct PrivateGenuineRemovalGraph {
    pub pool: PgPool,
    _database: FreshDbGuard,
    pub graph: GenuineCreationGraph,
    pub removed: GenuineFormerLeaf,
    pub current_generation: u64,
    pub current_state_version: u64,
    pub current_graph_digest: [u8; 32],
    pub current_snapshot_digest: [u8; 32],
}

pub async fn private_genuine_removal_graph() -> PrivateGenuineRemovalGraph {
    let (pool, database) = setup().await;
    let removed = genuine_terminal_fixture::seed_private_genuine_removal(&pool).await;
    PrivateGenuineRemovalGraph {
        pool,
        _database: database,
        graph: removed.creation_graph,
        removed: GenuineFormerLeaf {
            did: removed.removed_did,
            device_id: removed.removed_device_id,
            dpop_jkt: removed.removed_dpop_jkt,
            auth_generation: removed.removed_auth_generation,
            participant_period_id: removed.participant_period_id,
            leaf_period_id: removed.leaf_period_id,
            membership_interval_id: removed.membership_interval_id,
            interval_start_seq: removed.interval_start_seq,
            terminal_seq: removed.terminal_seq,
            terminal_transition_id: removed.terminal_transition_id,
            terminal_outer_entry_fingerprint: removed.terminal_outer_entry_fingerprint,
            removed_at: removed.removed_at,
        },
        current_generation: removed.current_generation,
        current_state_version: removed.current_state_version,
        current_graph_digest: removed.current_graph_digest,
        current_snapshot_digest: removed.current_snapshot_digest,
    }
}

pub struct GenuineResetRetiredLeaf {
    pub did: String,
    pub device_id: Uuid,
    pub key_id: String,
    pub dpop_jkt: String,
    pub auth_generation: u64,
    pub participant_period_id: Uuid,
    pub leaf_period_id: Uuid,
    pub membership_interval_id: Uuid,
    pub interval_start_seq: u64,
    pub terminal_seq: u64,
    pub terminal_transition_id: Uuid,
    pub terminal_outer_entry_fingerprint: [u8; 32],
    pub reset_at: DateTime<Utc>,
    pub old_generation: u64,
}

impl GenuineResetRetiredLeaf {
    pub fn device_identity(&self) -> DeviceIdentity {
        DeviceIdentity::new(
            PrincipalId::new(self.did.as_bytes().to_vec()).expect("reset-retired leaf DID"),
            *self.device_id.as_bytes(),
        )
        .expect("reset-retired leaf device identity")
    }
}

pub struct PrivateGenuineResetGraph {
    pub pool: PgPool,
    _database: FreshDbGuard,
    pub graph: GenuineCreationGraph,
    pub old: GenuineResetRetiredLeaf,
    pub current_generation: u64,
    pub current_state_version: u64,
    pub current_group_id: [u8; 32],
    pub current_graph_digest: [u8; 32],
    pub current_snapshot_digest: [u8; 32],
}

pub async fn private_genuine_reset_graph() -> PrivateGenuineResetGraph {
    let (pool, database) = setup().await;
    let reset = genuine_terminal_fixture::seed_private_genuine_reset(&pool).await;
    PrivateGenuineResetGraph {
        pool,
        _database: database,
        graph: reset.creation_graph,
        old: GenuineResetRetiredLeaf {
            did: reset.old_did,
            device_id: reset.old_device_id,
            key_id: reset.old_key_id,
            dpop_jkt: reset.old_dpop_jkt,
            auth_generation: reset.old_auth_generation,
            participant_period_id: reset.participant_period_id,
            leaf_period_id: reset.leaf_period_id,
            membership_interval_id: reset.membership_interval_id,
            interval_start_seq: reset.interval_start_seq,
            terminal_seq: reset.terminal_seq,
            terminal_transition_id: reset.terminal_transition_id,
            terminal_outer_entry_fingerprint: reset.terminal_outer_entry_fingerprint,
            reset_at: reset.reset_at,
            old_generation: reset.old_generation,
        },
        current_generation: reset.current_generation,
        current_state_version: reset.current_state_version,
        current_group_id: reset.current_group_id,
        current_graph_digest: reset.current_graph_digest,
        current_snapshot_digest: reset.current_snapshot_digest,
    }
}

pub async fn clock_now(pool: &PgPool) -> DateTime<Utc> {
    sqlx::query_scalar("SELECT clock_timestamp()")
        .fetch_one(pool)
        .await
        .expect("sample trusted database clock")
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CorpusManifest {
    pub evaluation_unix_seconds: u64,
    pub identifiers: CorpusIdentifiers,
    pub identity: CorpusIdentity,
    pub chain: CorpusChain,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CorpusIdentifiers {
    pub conversation_id_hex: String,
}
#[derive(Deserialize)]
pub struct CorpusIdentity {
    pub alice: CorpusActor,
    pub bob: CorpusActor,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CorpusActor {
    pub actor_did: String,
    pub device_id: String,
    pub credential_identity: String,
    pub signature_public_key_hex: String,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CorpusChain {
    pub generation: u64,
    pub genesis_state_version: u64,
    pub genesis_epoch: u64,
    pub genesis_group_context_hash_hex: String,
    pub genesis_confirmation_tag_hex: String,
    pub group_id_hex: String,
    // Committed (post-ADD-commit) coordinate + the recovered inner key-package ref
    // — used only by the fulfillment scenario.
    pub committed_epoch: u64,
    pub committed_group_context_hash_hex: String,
    pub committed_confirmation_tag_hex: String,
    pub inner_key_package_ref_hex: String,
}

pub fn corpus_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../docs/generated-artifacts/mls-chat-v1/crypto-wire")
}
pub fn corpus_file(name: &str) -> Vec<u8> {
    fs::read(corpus_dir().join(name)).expect("read frozen crypto-wire corpus")
}
pub fn corpus_manifest() -> CorpusManifest {
    serde_json::from_slice(&corpus_file("manifest.json")).expect("parse frozen manifest")
}
pub fn hex_array<const N: usize>(value: &str) -> [u8; N] {
    hex::decode(value)
        .expect("valid fixture hex")
        .try_into()
        .unwrap_or_else(|_| panic!("expected {N}-byte fixture"))
}
pub fn uuid_bytes(value: &str) -> [u8; 16] {
    *Uuid::parse_str(value).expect("fixture UUID").as_bytes()
}
pub fn uuid_v4_bytes(byte: u8) -> [u8; 16] {
    let mut value = [byte; 16];
    value[6] = 0x40 | (byte & 0x0f);
    value[8] = 0x80 | (byte & 0x3f);
    value
}

pub fn genesis_coordinate(manifest: &CorpusManifest) -> PublicGroupSnapshotCoordinate {
    PublicGroupSnapshotCoordinate::new(
        hex_array(&manifest.identifiers.conversation_id_hex),
        manifest.chain.generation,
        manifest.chain.genesis_state_version,
        hex_array(&manifest.chain.group_id_hex),
        manifest.chain.genesis_epoch,
        hex_array(&manifest.chain.genesis_group_context_hash_hex),
        hex_array(&manifest.chain.genesis_confirmation_tag_hex),
        PublicGroupSnapshotLifecycle::Active,
    )
}

pub fn coordinate_with_conversation(
    source: &PublicGroupSnapshotCoordinate,
    conversation_id: [u8; 16],
) -> PublicGroupSnapshotCoordinate {
    PublicGroupSnapshotCoordinate::new(
        conversation_id,
        source.generation(),
        source.state_version(),
        *source.group_id(),
        source.epoch(),
        *source.group_context_hash(),
        *source.confirmation_tag(),
        source.lifecycle(),
    )
}

pub fn alice(manifest: &CorpusManifest) -> DeviceIdentity {
    DeviceIdentity::new(
        PrincipalId::new(manifest.identity.alice.actor_did.as_bytes().to_vec()).unwrap(),
        uuid_bytes(&manifest.identity.alice.device_id),
    )
    .unwrap()
}
pub fn verified_genesis(manifest: &CorpusManifest) -> ActivePublicState {
    let state = frozen_public_state::restore_genesis();
    assert_eq!(state.coordinate(), &genesis_coordinate(manifest));
    state
}

/// Idempotently seed a principal + active device + device-key row (committed).
pub async fn seed_actor(
    pool: &PgPool,
    user_did: &str,
    device_id: Uuid,
    signing_public_key: &[u8],
) -> String {
    let now = clock_now(pool).await;
    let key_id: String = sqlx::query_scalar("SELECT chat.ed25519_key_id($1)")
        .bind(signing_public_key)
        .fetch_one(pool)
        .await
        .expect("derive key id");
    sqlx::query(
        "INSERT INTO chat.principals(user_did,created_at) VALUES($1,$2) ON CONFLICT DO NOTHING",
    )
    .bind(user_did)
    .bind(now)
    .execute(pool)
    .await
    .expect("seed principal");
    sqlx::query(
        "INSERT INTO chat.devices(user_did,device_id,device_name,status,dpop_jkt,auth_generation,capabilities,created_at,updated_at) \
         VALUES($1,$2,'actor','active',$3,1,chat.protocol_capabilities(),$4,$4) ON CONFLICT DO NOTHING",
    )
    .bind(user_did)
    .bind(device_id)
    .bind(&key_id)
    .bind(now)
    .execute(pool)
    .await
    .expect("seed device");
    sqlx::query(
        "INSERT INTO chat.device_keys(user_did,device_id,key_id,signing_public_key,enrollment_auth_generation,created_at) \
         VALUES($1,$2,$3,$4,1,$5) ON CONFLICT DO NOTHING",
    )
    .bind(user_did)
    .bind(device_id)
    .bind(&key_id)
    .bind(signing_public_key)
    .bind(now)
    .execute(pool)
    .await
    .expect("seed device key");
    key_id
}

pub async fn seed_protocol_instance(pool: &PgPool) -> Uuid {
    let id = uuid_v4_bytes(0x51);
    let cursor_key: String = sqlx::query_scalar("SELECT chat.ed25519_key_id($1)")
        .bind(vec![0x51_u8; 32])
        .fetch_one(pool)
        .await
        .expect("derive cursor key");
    sqlx::query(
        "INSERT INTO chat.protocol_instances(singleton,protocol_version,protocol_instance_id,cursor_key_id) \
         VALUES(TRUE,'1',$1,$2) ON CONFLICT DO NOTHING",
    )
    .bind(Uuid::from_bytes(id))
    .bind(&cursor_key)
    .execute(pool)
    .await
    .expect("seed protocol instance");
    sqlx::query_scalar("SELECT protocol_instance_id FROM chat.protocol_instances")
        .fetch_one(pool)
        .await
        .expect("read protocol instance id")
}

/// Everything a creation apply needs: the built plan + a coherent ctx + the
/// identifiers a SELECT-verify uses.
pub struct CreationApply {
    pub plan: crate::chat_protocol::state_machine::ConversationPersistencePlan,
    pub ctx: ExecutionContext,
    pub conversation_id: Uuid,
    pub alice_did: String,
    pub alice_device: Uuid,
    // Carried for the follow-on policy edge.
    pub state: crate::chat_protocol::state_machine::ConversationState,
    pub alice_id: DeviceIdentity,
    pub alice_key_id: String,
    pub bob_id: DeviceIdentity,
    pub bob_did: String,
    pub bob_key_id: String,
    pub coordinate: PublicGroupSnapshotCoordinate,
    pub protocol_instance_id: Uuid,
    /// The creation transition id — the invitation provenance a later acceptance
    /// must echo (bob's pending invitation was minted by this transition).
    pub creation_transition_id: [u8; 16],
}

/// Creation with an explicit pending invitee — the fulfillment scenario passes the
/// FIXED corpus bob (whose credential the frozen ADD commit adds); on the fresh-DB
/// harness a fixed identity no longer collides across runs.
pub async fn build_creation_with_invitee(
    pool: &PgPool,
    kind: ConversationKind,
    bob_id: DeviceIdentity,
    bob_did: String,
    bob_sig_key: Vec<u8>,
) -> CreationApply {
    let manifest = corpus_manifest();
    let alice_id = alice(&manifest);
    let alice_did = manifest.identity.alice.actor_did.clone();
    let alice_device = Uuid::from_bytes(*alice_id.device_id());
    let bob_device = Uuid::from_bytes(*bob_id.device_id());
    let alice_sig_key: Vec<u8> =
        hex::decode(&manifest.identity.alice.signature_public_key_hex).unwrap();
    // Alice's MLS leaf signature key is also her device signing key here, so
    // member_devices.leaf_key_id == device_keys.key_id == actor_key_id.
    let alice_key_id = seed_actor(pool, &alice_did, alice_device, &alice_sig_key).await;
    let bob_key_id = seed_actor(pool, &bob_did, bob_device, &bob_sig_key).await;
    let protocol_instance_id = seed_protocol_instance(pool).await;

    // Fresh conversation id per run (the corpus id is fixed; rebind onto a fresh
    // one so committed rows never collide across runs).
    let conversation_id = Uuid::new_v4();
    let template = verified_genesis(&manifest);
    let coordinate =
        coordinate_with_conversation(&genesis_coordinate(&manifest), *conversation_id.as_bytes());
    let public_state = ActivePublicState::for_test(&template, coordinate);

    let transition_id = Uuid::new_v4();
    let entry_id = Uuid::new_v4();
    let received_at = ServerTimestamp::from_unix_millis_for_test(
        manifest.evaluation_unix_seconds as i64 * 1_000 + 1_000,
    )
    .unwrap();
    let nonce = [0x77_u8; 12];
    let ciphertext = vec![0x88_u8; 48];
    let alice_key_id_bytes: [u8; 32] = {
        let mut buf = [0u8; 32];
        let digest = Sha256::digest(&alice_sig_key);
        buf.copy_from_slice(&digest);
        buf
    };
    let metadata = MetadataSnapshotBinding::for_test_creation(
        *conversation_id.as_bytes(),
        0,
        0,
        *coordinate.group_context_hash(),
        *transition_id.as_bytes(),
        1,
        alice_id.clone(),
        alice_key_id_bytes,
        alice_sig_key.clone().try_into().unwrap(),
        1,
        1,
        nonce,
        ciphertext.clone(),
    );
    let evidence = TransitionEvidence::for_test_creation_with_metadata(
        1,
        *transition_id.as_bytes(),
        [0x11_u8; 32],
        received_at,
        kind,
        coordinate,
        alice_id.clone(),
        metadata,
    )
    .unwrap();

    let decision = plan_creation(
        None,
        CreationCommand {
            kind,
            creator: alice_id.clone(),
            invitees: vec![bob_id.principal().clone()],
            transition: evidence,
            public_state,
        },
    )
    .expect("valid creation plan");
    let planned = match decision {
        CreationDecision::Create(planned) => planned,
        CreationDecision::ExistingDirect { .. } => panic!("fresh creation expected"),
    };
    let creation_state = planned.resulting_state().clone();
    let head_cas = ConversationHeadCasBinding::for_test_creation(
        *conversation_id.as_bytes(),
        *entry_id.as_bytes(),
        received_at,
    );
    let plan = persistence_plan_for_test(planned, head_cas);

    let applied_at = clock_now(pool).await;
    let accepted_payload = vec![0x21_u8; 24];
    let transcript = vec![0x22_u8; 24];
    let ctx = ExecutionContext {
        protocol_instance_id,
        applied_at,
        actor: ExecutionActor {
            user_did: alice_did.clone(),
            device_id: alice_device,
            key_id: alice_key_id.clone(),
            auth_generation: 1,
            role: TransitionActorRole::Admin,
            device_status: "active".to_owned(),
        },
        authority: ExecutionAuthority::ControlEntry(ControlEntryContent {
            entry_id,
            entry_kind: "blue.catbird.chat.defs#creationEntry".to_owned(),
            accepted_payload_bytes: accepted_payload.clone(),
            accepted_payload_sha256: Sha256::digest(&accepted_payload).to_vec(),
            signed_request_bytes: transcript.clone(),
            unsigned_projection_bytes: vec![0x23_u8; 16],
            signing_transcript_bytes: transcript.clone(),
            request_digest: Sha256::digest(&transcript).to_vec(),
            signature: vec![0x24_u8; 64],
            server_fields_bytes: vec![0x25_u8; 8],
            outer_entry_fingerprint: vec![0x11_u8; 32],
        }),
        spine: SpineArtifacts {
            public_snapshot_bytes: vec![0x31_u8; 16],
            public_snapshot_sha256: Sha256::digest([0x31_u8; 16]).to_vec(),
            tree_summary_bytes: vec![0x32_u8; 16],
            tree_summary_sha256: Sha256::digest([0x32_u8; 16]).to_vec(),
            leaf_count: 1,
            genesis_group_info_bytes: vec![0x33_u8; 16],
            genesis_group_info_sha256: Sha256::digest([0x33_u8; 16]).to_vec(),
        },
        opened_leaves: vec![LeafPersistenceColumns {
            device: alice_id.clone(),
            leaf_key_id: alice_key_id.clone(),
            leaf_auth_generation: 1,
        }],
        metadata_author: Some(MetadataAuthorColumns {
            author_role: "admin".to_owned(),
            author_device_status: "active".to_owned(),
            author_public_key: alice_sig_key.clone(),
            author_key_id: alice_key_id.clone(),
            metadata_snapshot_id: Uuid::new_v4(),
        }),
        metadata_avatar: None,
        participant_period_ids: vec![Uuid::new_v4(), Uuid::new_v4()],
        leaf_period_ids: vec![Uuid::new_v4()],
        entry_recipients: entry_audience(&alice_id, &alice_did, &bob_id, &bob_did),
        events: vec![EventFanout {
            event_id: Uuid::new_v4(),
            event_kind: EventKind::ConversationChanged,
            payload_bytes: vec![0x41_u8; 8],
            recipients: event_audience(pool, &alice_id, &alice_did, &bob_id, &bob_did).await,
            outbox: vec![(Uuid::new_v4(), OutboxWorkKind::Stream)],
        }],
        closing_leaf_periods: Vec::new(),
        closing_participant_periods: Vec::new(),
        reset_request_row: None,
        recovery_open: None,
        welcome_expiry: None,
        welcome_response: None,
        welcome_dispositions: vec![],
    };

    CreationApply {
        plan,
        ctx,
        conversation_id,
        alice_did,
        alice_device,
        state: creation_state,
        alice_id,
        alice_key_id,
        bob_id,
        bob_did,
        bob_key_id,
        coordinate,
        protocol_instance_id,
        creation_transition_id: *transition_id.as_bytes(),
    }
}

pub fn entry_audience(
    a: &DeviceIdentity,
    a_did: &str,
    b: &DeviceIdentity,
    b_did: &str,
) -> Vec<(DeviceIdentity, EntryEntitlementKind)> {
    let mut rows = vec![(a.clone(), a_did.to_owned()), (b.clone(), b_did.to_owned())];
    rows.sort_by(|l, r| (l.1.as_bytes(), l.0.device_id()).cmp(&(r.1.as_bytes(), r.0.device_id())));
    rows.into_iter()
        .map(|(d, _)| (d, EntryEntitlementKind::Control))
        .collect()
}

/// The `chat.event_recipients` chain trigger requires each device's new audience
/// row to point at that device's current max `event_position` (NULL only for a
/// device with no prior events). The fixed corpus DIDs accumulate events across
/// runs, so chain each recipient to its real predecessor — exactly what the
/// facade would compute.
pub async fn event_audience(
    pool: &PgPool,
    a: &DeviceIdentity,
    a_did: &str,
    b: &DeviceIdentity,
    b_did: &str,
) -> Vec<(DeviceIdentity, EventEntitlementKind, Option<i64>)> {
    let mut rows = vec![(a.clone(), a_did.to_owned()), (b.clone(), b_did.to_owned())];
    rows.sort_by(|l, r| (l.1.as_bytes(), l.0.device_id()).cmp(&(r.1.as_bytes(), r.0.device_id())));
    let mut out = Vec::with_capacity(rows.len());
    for (device, did) in rows {
        let predecessor: Option<i64> = sqlx::query_scalar(
            "SELECT max(event_position) FROM chat.event_recipients WHERE user_did=$1 AND device_id=$2",
        )
        .bind(&did)
        .bind(Uuid::from_bytes(*device.device_id()))
        .fetch_one(pool)
        .await
        .expect("read device event predecessor");
        out.push((device, EventEntitlementKind::Participant, predecessor));
    }
    out
}

pub async fn device_event_predecessor(pool: &PgPool, did: &str, device: Uuid) -> Option<i64> {
    sqlx::query_scalar(
        "SELECT max(event_position) FROM chat.event_recipients WHERE user_did=$1 AND device_id=$2",
    )
    .bind(did)
    .bind(device)
    .fetch_one(pool)
    .await
    .expect("predecessor")
}

/// Seed one `available` key package owned by `(owner_did, owner_device)` and
/// return its exact `not_after` (the value the reservation's
/// `expires_at = LEAST(created_at + 5 min, not_after)` mapping check needs).
pub async fn seed_key_package(
    pool: &PgPool,
    owner_did: &str,
    owner_device: Uuid,
    owner_key_id: &str,
    key_package_ref: &[u8],
) -> DateTime<Utc> {
    let now = clock_now(pool).await;
    let not_before = now - Duration::hours(1);
    // Align `not_after` to whole milliseconds: the Welcome delivery's `expires_at`
    // (a `ServerTimestamp`, millisecond-precision) is FK-bound to this exact value,
    // so a sub-millisecond `not_after` would never match the round-tripped instant.
    let not_after =
        DateTime::from_timestamp_millis((now + Duration::hours(24)).timestamp_millis()).unwrap();
    let wrapper = vec![0xC1_u8; 32];
    let init_key = {
        let mut key = vec![0u8; 32];
        key[..16].copy_from_slice(Uuid::new_v4().as_bytes());
        key[16..].copy_from_slice(Uuid::new_v4().as_bytes());
        key
    };
    sqlx::query(
        "INSERT INTO chat.key_packages(key_package_ref,wrapper_bytes,wrapper_sha256,init_key,owner_did,owner_device_id,owner_key_id,owner_auth_generation,not_before,not_after,status,created_at) \
         VALUES($1,$2,$3,$4,$5,$6,$7,1,$8,$9,'available',$10)",
    )
    .bind(key_package_ref)
    .bind(&wrapper)
    .bind(Sha256::digest(&wrapper).to_vec())
    .bind(&init_key)
    .bind(owner_did)
    .bind(owner_device)
    .bind(owner_key_id)
    .bind(not_before)
    .bind(not_after)
    .bind(now)
    .execute(pool)
    .await
    .expect("seed key package");
    not_after
}

/// The acceptance `ExecutionContext` for an invitee accepting (used by the
/// fulfillment scenario). Actor = the invitee (member/active), audience = the two
/// current devices, recovery_open bound to the invitee's participant period.
#[allow(clippy::too_many_arguments)]
pub async fn acceptance_ctx(
    pool: &PgPool,
    fixture: &CreationApply,
    bob_id: &DeviceIdentity,
    bob_did: &str,
    bob_key_id: &str,
    entry_id: Uuid,
    bob_period: Uuid,
    package_not_after: DateTime<Utc>,
) -> ExecutionContext {
    let applied_at = clock_now(pool).await;
    let payload = vec![0xA1_u8; 12];
    let transcript = vec![0xA2_u8; 12];
    ExecutionContext {
        protocol_instance_id: fixture.protocol_instance_id,
        applied_at,
        actor: ExecutionActor {
            user_did: bob_did.to_owned(),
            device_id: Uuid::from_bytes(*bob_id.device_id()),
            key_id: bob_key_id.to_owned(),
            auth_generation: 1,
            role: TransitionActorRole::Member,
            device_status: "active".to_owned(),
        },
        authority: ExecutionAuthority::ControlEntry(ControlEntryContent {
            entry_id,
            entry_kind: "blue.catbird.chat.defs#participantAcceptanceEntry".to_owned(),
            accepted_payload_bytes: payload.clone(),
            accepted_payload_sha256: Sha256::digest(&payload).to_vec(),
            signed_request_bytes: transcript.clone(),
            unsigned_projection_bytes: vec![0xA3_u8; 8],
            signing_transcript_bytes: transcript.clone(),
            request_digest: Sha256::digest(&transcript).to_vec(),
            signature: vec![0xA4_u8; 64],
            server_fields_bytes: vec![0xA5_u8; 8],
            outer_entry_fingerprint: vec![0x16_u8; 32],
        }),
        spine: SpineArtifacts {
            public_snapshot_bytes: vec![0xB1_u8; 16],
            public_snapshot_sha256: Sha256::digest([0xB1_u8; 16]).to_vec(),
            tree_summary_bytes: vec![0xB2_u8; 16],
            tree_summary_sha256: Sha256::digest([0xB2_u8; 16]).to_vec(),
            leaf_count: 1,
            genesis_group_info_bytes: vec![],
            genesis_group_info_sha256: vec![],
        },
        opened_leaves: vec![],
        metadata_author: None,
        metadata_avatar: None,
        participant_period_ids: vec![],
        leaf_period_ids: vec![],
        entry_recipients: entry_audience(&fixture.alice_id, &fixture.alice_did, bob_id, bob_did),
        events: vec![EventFanout {
            event_id: Uuid::new_v4(),
            event_kind: EventKind::ConversationChanged,
            payload_bytes: vec![0xB4_u8; 8],
            recipients: event_audience(
                pool,
                &fixture.alice_id,
                &fixture.alice_did,
                bob_id,
                bob_did,
            )
            .await,
            outbox: vec![(Uuid::new_v4(), OutboxWorkKind::Stream)],
        }],
        closing_leaf_periods: vec![],
        closing_participant_periods: vec![],
        reset_request_row: None,
        recovery_open: Some(RecoveryOpenContext {
            participant_period_id: Some(bob_period),
            package_not_after,
            replaced_leaf_period_id: None,
        }),
        welcome_expiry: None,
        welcome_response: None,
        welcome_dispositions: vec![],
    }
}

pub fn bob_corpus(manifest: &CorpusManifest) -> DeviceIdentity {
    DeviceIdentity::new(
        PrincipalId::new(manifest.identity.bob.actor_did.as_bytes().to_vec()).unwrap(),
        uuid_bytes(&manifest.identity.bob.device_id),
    )
    .unwrap()
}

/// The committed (post-ADD-commit) coordinate: same generation/group_id, the
/// committed epoch/hash/tag, at `state_version`.
pub fn committed_coordinate(
    manifest: &CorpusManifest,
    conversation_id: [u8; 16],
    state_version: u64,
) -> PublicGroupSnapshotCoordinate {
    PublicGroupSnapshotCoordinate::new(
        conversation_id,
        manifest.chain.generation,
        state_version,
        hex_array(&manifest.chain.group_id_hex),
        manifest.chain.committed_epoch,
        hex_array(&manifest.chain.committed_group_context_hash_hex),
        hex_array(&manifest.chain.committed_confirmation_tag_hex),
        PublicGroupSnapshotLifecycle::Active,
    )
}

/// Restore the frozen corpus ADD snapshot against the accepted state's exact
/// manifest-bound genesis snapshot, producing the verified committed public
/// state the fulfillment consumes.
pub fn verified_add_commit(
    state: &crate::chat_protocol::state_machine::ConversationState,
    manifest: &CorpusManifest,
) -> crate::chat_protocol::public_state::VerifiedCommitPublicState {
    let sender_leaf_index = state
        .leaf(&alice(manifest))
        .expect("Alice sender leaf")
        .leaf_index();
    frozen_public_state::restore_add_commit(state.public_state(), sender_leaf_index)
}

/// A committed fulfillment scenario (creation → acceptance → fulfillment, all
/// COMMITTED on a fresh DB) at coordinate sv 2 / epoch 1 with alice + bob leaves —
/// the prior state for the epoch-changing generic-commit / remove follow-ons.
pub struct FulfillmentScenario {
    pub fulfillment_state: crate::chat_protocol::state_machine::ConversationState,
    pub fixture: CreationApply,
    pub conversation_id: Uuid,
    pub bob_id: DeviceIdentity,
    pub bob_did: String,
    pub coordinate: PublicGroupSnapshotCoordinate,
    pub alice_sig_key: Vec<u8>,
    pub fulfill_transition: Uuid,
    pub welcome_id: Uuid,
    pub recovery_request_id: Uuid,
    pub corpus_ref: [u8; 32],
    pub event_positions: Vec<i64>,
}

/// The uncommitted leaf-recovery fulfillment plan + ctx (create + acceptance are
/// already COMMITTED). Extracted so the reconciliation negative test can apply a
/// MUTATED plan against the same accepted state without run_fulfillment_scenario
/// committing it first.
pub struct BuiltFulfillment {
    pub plan: crate::chat_protocol::state_machine::ConversationPersistencePlan,
    pub ctx: ExecutionContext,
    pub fixture: CreationApply,
    pub conversation_id: Uuid,
    pub bob_id: DeviceIdentity,
    pub bob_did: String,
    pub alice_sig_key: Vec<u8>,
    pub fulfill_transition: Uuid,
    pub welcome_id: Uuid,
    pub recovery_request_id: Uuid,
    pub corpus_ref: [u8; 32],
    pub fulfillment_state: crate::chat_protocol::state_machine::ConversationState,
}

pub async fn build_fulfillment(pool: &PgPool) -> BuiltFulfillment {
    let pool = pool.clone();
    let manifest = corpus_manifest();
    let bob_id = bob_corpus(&manifest);
    let bob_did = manifest.identity.bob.actor_did.clone();
    let bob_device = Uuid::from_bytes(*bob_id.device_id());

    // 1. Create the group (alice creator, CORPUS bob invitee) and commit it.
    //    Bob's DEVICE signing key = his CORPUS MLS leaf signature key, so his
    //    `device_keys.key_id` equals `ed25519_key_id(leaf_signature_key)` — the
    //    exact `member_devices.leaf_key_id` the recovered keyPackage leaf requires.
    let bob_leaf_sig_key: Vec<u8> =
        hex::decode(&manifest.identity.bob.signature_public_key_hex).unwrap();
    let fixture = build_creation_with_invitee(
        &pool,
        ConversationKind::Group,
        bob_id.clone(),
        bob_did.clone(),
        bob_leaf_sig_key.clone(),
    )
    .await;
    let conversation_id = fixture.conversation_id;
    {
        let mut tx = pool.begin().await.expect("begin creation");
        apply_conversation_persistence_plan_unscoped_for_test(&mut tx, &fixture.plan, &fixture.ctx)
            .await
            .expect("creation applies");
        tx.commit().await.expect("creation COMMIT");
    }

    // 2. Acceptance (bob), opening the add-request bound to sv1 with the CORPUS
    //    key-package ref (so the ADD commit's added member matches the request).
    let corpus_ref: [u8; 32] = hex_array(&manifest.chain.inner_key_package_ref_hex);
    let bob_period: Uuid = sqlx::query_scalar(
        "SELECT participant_period_id FROM chat.participants WHERE conversation_id=$1 AND user_did=$2 AND current_membership",
    )
    .bind(conversation_id)
    .bind(&bob_did)
    .fetch_one(&pool)
    .await
    .expect("bob participant period");
    let package_not_after = seed_key_package(
        &pool,
        &bob_did,
        bob_device,
        &fixture.bob_key_id,
        &corpus_ref,
    )
    .await;

    let accept_received = ServerTimestamp::from_unix_millis_for_test(
        manifest.evaluation_unix_seconds as i64 * 1_000 + 3_000,
    )
    .unwrap();
    // The protocol package_not_after MUST be the exact instant the seeded key
    // package's `not_after` is: the Welcome delivery's `expires_at` (the plan's
    // reservation `package_not_after`) is FK-bound to `key_packages.not_after`.
    let pkg_not_after_ts =
        ServerTimestamp::from_unix_millis_for_test(package_not_after.timestamp_millis()).unwrap();
    let recovery_request_id = Uuid::new_v4();
    let accept_transition = Uuid::new_v4();
    let accept_entry = Uuid::new_v4();
    let bob_sig_digest: [u8; 32] = Sha256::digest([0x62_u8; 32]).into();
    let accept_evidence = TransitionEvidence::for_test_acceptance(
        2,
        *accept_transition.as_bytes(),
        [0x16_u8; 32],
        accept_received,
        fixture.coordinate,
        *recovery_request_id.as_bytes(),
        bob_id.clone(),
        fixture.creation_transition_id,
        fixture.alice_id.clone(),
        corpus_ref,
        bob_sig_digest,
        1,
        pkg_not_after_ts,
    )
    .unwrap();
    let accept_planned = plan_accept_conversation(
        &fixture.state,
        AcceptConversation {
            actor: bob_id.clone(),
            transition: accept_evidence,
            recovery_request_id: *recovery_request_id.as_bytes(),
            key_package_ref: corpus_ref,
            package_not_after: pkg_not_after_ts,
        },
    )
    .expect("valid acceptance plan");
    let accepted_state = accept_planned.resulting_state().clone();
    let accept_head = ConversationHeadCasBinding::for_test_edge(
        *conversation_id.as_bytes(),
        *accept_entry.as_bytes(),
        fixture.coordinate,
        2,
        accept_received,
    );
    let accept_plan = persistence_plan_for_test(accept_planned, accept_head);
    let accept_ctx = acceptance_ctx(
        &pool,
        &fixture,
        &bob_id,
        &bob_did,
        &fixture.bob_key_id,
        accept_entry,
        bob_period,
        package_not_after,
    )
    .await;
    {
        let mut tx = pool.begin().await.expect("begin acceptance");
        apply_conversation_persistence_plan_unscoped_for_test(&mut tx, &accept_plan, &accept_ctx)
            .await
            .expect("acceptance applies");
        tx.commit().await.expect("acceptance COMMIT");
    }

    // 3. Build the fulfillment: restore the corpus ADD snapshot and bind the
    //    Welcome against the accepted state, then plan the fulfillment.
    let commit = verified_add_commit(&accepted_state, &manifest);
    let welcome = verify_recovery_welcome(&corpus_file("welcome.mls"), corpus_ref, 1_048_576)
        .expect("one-recipient Welcome is request-bound");
    let welcome_wire = welcome.wire_bytes().to_vec();
    let welcome_id = Uuid::new_v4();
    let fulfill_transition = Uuid::new_v4();
    let fulfill_entry = Uuid::new_v4();
    let fulfill_received = ServerTimestamp::from_unix_millis_for_test(
        manifest.evaluation_unix_seconds as i64 * 1_000 + 4_000,
    )
    .unwrap();
    let successor_coord = committed_coordinate(&manifest, *conversation_id.as_bytes(), 2);
    let alice_sig_key: Vec<u8> =
        hex::decode(&manifest.identity.alice.signature_public_key_hex).unwrap();
    let alice_key_id_bytes: [u8; 32] = Sha256::digest(&alice_sig_key).into();
    // The metadata RE-ENCRYPTION: SAME author/origin/version/size as the creation
    // snapshot (alice, creation transition, v1, 48 bytes), a FRESH nonce + ciphertext.
    let reencryption = MetadataSnapshotBinding::for_test_creation(
        *conversation_id.as_bytes(),
        0,
        successor_coord.epoch(),
        *successor_coord.group_context_hash(),
        fixture.creation_transition_id,
        1,
        fixture.alice_id.clone(),
        alice_key_id_bytes,
        alice_sig_key.clone().try_into().unwrap(),
        1,
        1,
        [0x9A_u8; 12],
        vec![0x9B_u8; 48],
    );
    let fulfill_evidence = TransitionEvidence::for_test_leaf_recovery_fulfillment_with_metadata(
        3,
        *fulfill_transition.as_bytes(),
        [0x19_u8; 32],
        fulfill_received,
        *recovery_request_id.as_bytes(),
        *accepted_state.coordinate(),
        successor_coord,
        bob_id.clone(),
        corpus_ref,
        *welcome_id.as_bytes(),
        welcome_wire.clone(),
        reencryption,
    )
    .unwrap();
    let planned = plan_leaf_recovery_fulfillment(
        &accepted_state,
        LeafRecoveryFulfillment {
            actor: fixture.alice_id.clone(),
            target: bob_id.clone(),
            recovery_request_id: *recovery_request_id.as_bytes(),
            welcome_id: *welcome_id.as_bytes(),
            transition: fulfill_evidence,
            commit,
            welcome,
        },
    )
    .expect("valid fulfillment plan");
    let fulfillment_state = planned.resulting_state().clone();
    let head_cas = ConversationHeadCasBinding::for_test_edge(
        *conversation_id.as_bytes(),
        *fulfill_entry.as_bytes(),
        *accepted_state.coordinate(),
        3,
        fulfill_received,
    );
    let plan = persistence_plan_for_test(planned, head_cas);

    // Participant periods in hydration (sorted-DID) order for the new leaf's owner.
    let mut participant_rows: Vec<(String, Uuid)> = sqlx::query_as(
        "SELECT user_did,participant_period_id FROM chat.participants WHERE conversation_id=$1 AND current_membership",
    )
    .bind(conversation_id)
    .fetch_all(&pool)
    .await
    .expect("participant periods");
    participant_rows.sort_by(|l, r| l.0.as_bytes().cmp(r.0.as_bytes()));
    let participant_period_ids: Vec<Uuid> = participant_rows.iter().map(|(_, id)| *id).collect();

    let applied_at = clock_now(&pool).await;
    let payload = vec![0xC2_u8; 12];
    let transcript = vec![0xC3_u8; 12];
    let alice_pred =
        device_event_predecessor(&pool, &fixture.alice_did, fixture.alice_device).await;
    let bob_pred = device_event_predecessor(&pool, &bob_did, bob_device).await;
    let entry_recipients = entry_audience(&fixture.alice_id, &fixture.alice_did, &bob_id, &bob_did);
    let ctx = ExecutionContext {
        protocol_instance_id: fixture.protocol_instance_id,
        applied_at,
        actor: ExecutionActor {
            user_did: fixture.alice_did.clone(),
            device_id: fixture.alice_device,
            key_id: fixture.alice_key_id.clone(),
            auth_generation: 1,
            role: TransitionActorRole::Admin,
            device_status: "active".to_owned(),
        },
        authority: ExecutionAuthority::ControlEntry(ControlEntryContent {
            entry_id: fulfill_entry,
            entry_kind: "blue.catbird.chat.defs#leafRecoveryFulfillmentEntry".to_owned(),
            accepted_payload_bytes: payload.clone(),
            accepted_payload_sha256: Sha256::digest(&payload).to_vec(),
            signed_request_bytes: transcript.clone(),
            unsigned_projection_bytes: vec![0xC4_u8; 8],
            signing_transcript_bytes: transcript.clone(),
            request_digest: Sha256::digest(&transcript).to_vec(),
            signature: vec![0xC5_u8; 64],
            server_fields_bytes: vec![0xC6_u8; 8],
            outer_entry_fingerprint: vec![0x19_u8; 32],
        }),
        spine: SpineArtifacts {
            public_snapshot_bytes: vec![0xD1_u8; 16],
            public_snapshot_sha256: Sha256::digest([0xD1_u8; 16]).to_vec(),
            tree_summary_bytes: vec![0xD2_u8; 16],
            tree_summary_sha256: Sha256::digest([0xD2_u8; 16]).to_vec(),
            leaf_count: 2,
            genesis_group_info_bytes: vec![],
            genesis_group_info_sha256: vec![],
        },
        opened_leaves: vec![LeafPersistenceColumns {
            device: bob_id.clone(),
            leaf_key_id: fixture.bob_key_id.clone(),
            leaf_auth_generation: 1,
        }],
        metadata_author: Some(MetadataAuthorColumns {
            author_role: "admin".to_owned(),
            author_device_status: "active".to_owned(),
            author_public_key: alice_sig_key.clone(),
            author_key_id: fixture.alice_key_id.clone(),
            metadata_snapshot_id: Uuid::new_v4(),
        }),
        metadata_avatar: None,
        participant_period_ids,
        leaf_period_ids: vec![Uuid::new_v4()],
        entry_recipients,
        events: vec![EventFanout {
            event_id: Uuid::new_v4(),
            event_kind: EventKind::WelcomeAvailable,
            payload_bytes: vec![0xD4_u8; 8],
            recipients: vec![
                (
                    fixture.alice_id.clone(),
                    EventEntitlementKind::Participant,
                    alice_pred,
                ),
                (bob_id.clone(), EventEntitlementKind::Participant, bob_pred),
            ],
            outbox: vec![(Uuid::new_v4(), OutboxWorkKind::Stream)],
        }],
        closing_leaf_periods: vec![],
        closing_participant_periods: vec![],
        reset_request_row: None,
        recovery_open: None,
        welcome_expiry: None,
        welcome_response: None,
        welcome_dispositions: vec![],
    };

    BuiltFulfillment {
        plan,
        ctx,
        fixture,
        conversation_id,
        bob_id,
        bob_did,
        alice_sig_key,
        fulfill_transition,
        welcome_id,
        recovery_request_id,
        corpus_ref,
        fulfillment_state,
    }
}

/// Create + acceptance + fulfillment, all COMMITTED on a fresh DB, at sv 2 /
/// epoch 1 with alice + bob leaves — the prior for the epoch-changing follow-ons.
pub async fn run_fulfillment_scenario(pool: &PgPool) -> FulfillmentScenario {
    let BuiltFulfillment {
        plan,
        ctx,
        fixture,
        conversation_id,
        bob_id,
        bob_did,
        alice_sig_key,
        fulfill_transition,
        welcome_id,
        recovery_request_id,
        corpus_ref,
        fulfillment_state,
    } = build_fulfillment(pool).await;
    let pool = pool.clone();

    let mut tx = pool.begin().await.expect("begin fulfillment");
    let applied = apply_conversation_persistence_plan_unscoped_for_test(&mut tx, &plan, &ctx)
        .await
        .expect("fulfillment applies");
    tx.commit()
        .await
        .expect("fulfillment COMMIT past all deferred triggers");
    assert_eq!(applied.allocated_seq, 3);

    // Head at the committed successor (sv 2, epoch bump lives in gen_state).
    let (sv, next_seq): (i64, i64) = sqlx::query_as(
        "SELECT current_state_version,next_entry_seq FROM chat.conversations WHERE conversation_id=$1",
    )
    .bind(conversation_id)
    .fetch_one(&pool)
    .await
    .expect("head");
    assert_eq!((sv, next_seq), (2, 4));
    let (skind, sepoch, sleaf): (String, i64, i64) = sqlx::query_as(
        "SELECT state_kind,epoch,leaf_count FROM chat.generation_states WHERE conversation_id=$1 AND state_version=2",
    )
    .bind(conversation_id)
    .fetch_one(&pool)
    .await
    .expect("commit gen state");
    assert_eq!((skind.as_str(), sepoch, sleaf), ("commit", 1, 2));
    // Exactly one addLeafByRecovery: bob's keyPackage-origin leaf at generation 0.
    let (origin, join_ref): (String, Option<Vec<u8>>) = sqlx::query_as(
        "SELECT origin,join_key_package_ref FROM chat.member_devices WHERE conversation_id=$1 AND user_did=$2 AND active",
    )
    .bind(conversation_id)
    .bind(&bob_did)
    .fetch_one(&pool)
    .await
    .expect("bob leaf");
    assert_eq!(
        (origin.as_str(), join_ref),
        ("keyPackage", Some(corpus_ref.to_vec()))
    );
    // Bob's add-opened interval at the fulfillment seq.
    let (start_seq, opening_kind): (i64, String) = sqlx::query_as(
        "SELECT start_seq,opening_kind FROM chat.application_intervals WHERE conversation_id=$1 AND recipient_did=$2",
    )
    .bind(conversation_id)
    .bind(&bob_did)
    .fetch_one(&pool)
    .await
    .expect("bob interval");
    assert_eq!((start_seq, opening_kind.as_str()), (3, "add"));
    // Request fulfilled, reservation consumed, package consumed.
    let req_status: String = sqlx::query_scalar(
        "SELECT status FROM chat.leaf_recovery_requests WHERE recovery_request_id=$1",
    )
    .bind(recovery_request_id)
    .fetch_one(&pool)
    .await
    .expect("request");
    assert_eq!(req_status, "fulfilled");
    let res_status: String = sqlx::query_scalar(
        "SELECT status FROM chat.key_package_reservations WHERE recovery_request_id=$1",
    )
    .bind(recovery_request_id)
    .fetch_one(&pool)
    .await
    .expect("reservation");
    assert_eq!(res_status, "consumed");
    let pkg_status: String =
        sqlx::query_scalar("SELECT status FROM chat.key_packages WHERE key_package_ref=$1")
            .bind(corpus_ref.to_vec())
            .fetch_one(&pool)
            .await
            .expect("package");
    assert_eq!(pkg_status, "consumed");
    // Welcome bundle + pending delivery with expires_at == the package not_after.
    let bundle_count: i64 =
        sqlx::query_scalar("SELECT count(*) FROM chat.welcome_bundles WHERE welcome_id=$1")
            .bind(welcome_id)
            .fetch_one(&pool)
            .await
            .expect("bundle");
    assert_eq!(bundle_count, 1);
    let (del_status, del_expires): (String, DateTime<Utc>) =
        sqlx::query_as("SELECT status,expires_at FROM chat.welcome_deliveries WHERE welcome_id=$1")
            .bind(welcome_id)
            .fetch_one(&pool)
            .await
            .expect("delivery");
    assert_eq!(del_status, "pending");
    let pkg_not_after_db: DateTime<Utc> =
        sqlx::query_scalar("SELECT not_after FROM chat.key_packages WHERE key_package_ref=$1")
            .bind(corpus_ref.to_vec())
            .fetch_one(&pool)
            .await
            .expect("not_after");
    assert_eq!(del_expires, pkg_not_after_db);
    // The re-encryption metadata snapshot for the fulfillment transition.
    let snap_count: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM chat.metadata_snapshots WHERE producing_transition_id=$1",
    )
    .bind(fulfill_transition)
    .fetch_one(&pool)
    .await
    .expect("snapshot");
    assert_eq!(snap_count, 1);
    // The welcomeAvailable event.
    let evt_kind: String =
        sqlx::query_scalar("SELECT event_kind FROM chat.events WHERE event_position=$1")
            .bind(applied.event_positions[0])
            .fetch_one(&pool)
            .await
            .expect("event");
    assert_eq!(evt_kind, "welcomeAvailable");

    // Replay the fulfillment -> head CAS conflict (head already at sv 2), zero residue.
    let before: i64 =
        sqlx::query_scalar("SELECT count(*) FROM chat.transitions WHERE conversation_id=$1")
            .bind(conversation_id)
            .fetch_one(&pool)
            .await
            .unwrap();
    let mut tx2 = pool.begin().await.expect("begin replay");
    let replay = apply_conversation_persistence_plan_unscoped_for_test(&mut tx2, &plan, &ctx).await;
    assert!(
        matches!(replay, Err(ExecutorError::Transition(_))),
        "fulfillment replay must conflict on the head CAS, got {replay:?}"
    );
    tx2.rollback().await.expect("rollback replay");
    let after: i64 =
        sqlx::query_scalar("SELECT count(*) FROM chat.transitions WHERE conversation_id=$1")
            .bind(conversation_id)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(before, after, "fulfillment replay left zero residue");

    // MINOR: the re-encryption snapshot's author is the ORIGINAL creation author
    // (carried forward), and its author_key_id is the creation author's key — NOT
    // the fulfiller's. (Here fulfiller == author == alice per the corpus commit
    // sender; see the report for why a fulfiller != author DB test is not
    // corpus-reachable. The executor CODE sources author from the binding's
    // author-proof, verified in write_commit_metadata_snapshot.)
    let (snap_author_did, snap_author_key): (String, String) = sqlx::query_as(
        "SELECT author_did,author_key_id FROM chat.metadata_snapshots WHERE producing_transition_id=$1",
    )
    .bind(fulfill_transition)
    .fetch_one(&pool)
    .await
    .expect("snapshot author");
    assert_eq!(snap_author_did, fixture.alice_did);
    assert_eq!(snap_author_key, fixture.alice_key_id);

    let scenario_coordinate = *fulfillment_state.coordinate();
    FulfillmentScenario {
        fulfillment_state,
        conversation_id,
        bob_id,
        bob_did,
        coordinate: scenario_coordinate,
        alice_sig_key,
        fulfill_transition,
        welcome_id,
        recovery_request_id,
        corpus_ref,
        event_positions: applied.event_positions.clone(),
        fixture,
    }
}
