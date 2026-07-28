// Real cryptographic inputs for the Recovery production-proof runners.
//
// This source is included in `recovery::production_composition_proof`. Its
// `pub(super)` surface is visible to that parent only; none of these helpers
// are a shipping capability. In particular, it never uses
// `repository_test_evidence`, nor can it mint a `VerifiedChatDeviceRequest`.
// Every such request below crosses the normal Nest JWT + DPoP verifier and the
// replay-consuming repository authorizer.

use std::{
    collections::{BTreeMap, BTreeSet},
    fmt,
};

use base64::{
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
    Engine as _,
};
use chrono::{DateTime, Utc};
use ed25519_dalek::{Signer as _, SigningKey as Ed25519SigningKey};
use p256::ecdsa::{Signature as P256Signature, SigningKey as P256SigningKey};
use serde::{
    de::{Deserializer, MapAccess, SeqAccess, Visitor},
    Deserialize, Serialize,
};
use serde_json::{json, Value};
use sha2::{Digest as _, Sha256};
use sqlx::PgPool;
use uuid::Uuid;

use openmls::prelude::{
    tls_codec::{Deserialize as TlsDeserialize, Serialize as TlsSerialize},
    BasicCredential, Capabilities, CredentialType, CredentialWithKey, GroupId, KeyPackage,
    LeafNodeIndex, Lifetime, MlsGroup, MlsGroupCreateConfig, MlsMessageBodyIn, MlsMessageBodyOut,
    MlsMessageIn, MlsMessageOut, ProtocolVersion, StagedWelcome,
};
use openmls_basic_credential::SignatureKeyPair;
use openmls_traits::OpenMlsProvider;

use crate::chat_protocol::{
    dpop::{self, TrustedNestVerifier, VerifiedChatDeviceRequest},
    public_state::{
        encode_public_tree_summary, process_commit, rebind_active_snapshot,
        verify_genesis_group_info, verify_recovery_welcome, ActivePublicState,
        GenesisGroupInfoExpectations,
    },
    repository::auth::{authorize_signed_request, AuthorizationOutcome},
    snapshot::{PublicGroupSnapshotCoordinate, PublicGroupSnapshotLifecycle},
    transcript::{
        decode_and_verify_control_entry, decode_and_verify_signed_mutation,
        decode_canonical_signed_mutation, SignedMutationKind,
    },
    validation::{
        ed25519_key_id, CanonicalUuidV4, TrustedExternalBase, TrustedRequestInstant,
        ValidatedChatNsid,
    },
    wire::{
        validate_group_info, validate_key_package, GroupInfoValidationPolicy,
        KeyPackageValidationPolicy, MAX_GROUP_INFO_WIRE_BYTES, MAX_KEY_PACKAGE_WIRE_BYTES,
        MAX_WELCOME_WIRE_BYTES, XWING_CIPHERSUITE,
    },
};

const NEST_ISSUER: &str = "did:web:recovery-proof.catbird.invalid";
const NEST_AUDIENCE: &str = "did:web:recovery-proof-client.catbird.invalid";
const NEST_KEY_ID: &str = "recovery-production-proof-nest";
const CHAT_INSTANCE: &str = "d9c68d9f-2cf3-45c2-8b5a-8fd599a3e940";
const EXTERNAL_BASE: &str = "https://recovery-proof.catbird.invalid";
const CONTRACT_VECTORS: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/tests/fixtures/mls_chat_contract_vectors.json"
));
const LEXICON: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../lexicon/blue/catbird/chat/blue.catbird.chat.defs.json"
));

struct FixtureDagValue {
    value: FixtureDagValueInner,
}

enum FixtureDagValueInner {
    String(String),
    Integer(u64),
    Bool(bool),
    Bytes(Vec<u8>),
    Array(Vec<FixtureDagValue>),
    Map(BTreeMap<String, FixtureDagValue>),
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
        Ok(FixtureDagValue {
            value: FixtureDagValueInner::Bool(value),
        })
    }
    fn visit_u64<E>(self, value: u64) -> Result<Self::Value, E> {
        Ok(FixtureDagValue {
            value: FixtureDagValueInner::Integer(value),
        })
    }
    fn visit_i64<E>(self, value: i64) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        u64::try_from(value)
            .map(|value| FixtureDagValue {
                value: FixtureDagValueInner::Integer(value),
            })
            .map_err(|_| E::custom("negative fixture integer"))
    }
    fn visit_str<E>(self, value: &str) -> Result<Self::Value, E> {
        Ok(FixtureDagValue {
            value: FixtureDagValueInner::String(value.to_owned()),
        })
    }
    fn visit_string<E>(self, value: String) -> Result<Self::Value, E> {
        Ok(FixtureDagValue {
            value: FixtureDagValueInner::String(value),
        })
    }
    fn visit_bytes<E>(self, value: &[u8]) -> Result<Self::Value, E> {
        Ok(FixtureDagValue {
            value: FixtureDagValueInner::Bytes(value.to_vec()),
        })
    }
    fn visit_byte_buf<E>(self, value: Vec<u8>) -> Result<Self::Value, E> {
        Ok(FixtureDagValue {
            value: FixtureDagValueInner::Bytes(value),
        })
    }
    fn visit_seq<A>(self, mut sequence: A) -> Result<Self::Value, A::Error>
    where
        A: SeqAccess<'de>,
    {
        let mut values = Vec::new();
        while let Some(value) = sequence.next_element()? {
            values.push(value);
        }
        Ok(FixtureDagValue {
            value: FixtureDagValueInner::Array(values),
        })
    }
    fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
    where
        A: MapAccess<'de>,
    {
        let mut values = BTreeMap::new();
        while let Some((key, value)) = map.next_entry()? {
            values.insert(key, value);
        }
        Ok(FixtureDagValue {
            value: FixtureDagValueInner::Map(values),
        })
    }
}

impl FixtureDagValue {
    fn into_json_for_schema(
        self,
        schema: &Value,
        definitions: &serde_json::Map<String, Value>,
    ) -> Result<Value, String> {
        match schema["type"]
            .as_str()
            .ok_or_else(|| "fixture schema lacks type".to_owned())?
        {
            "ref" => {
                let name = schema["ref"]
                    .as_str()
                    .ok_or_else(|| "fixture ref missing".to_owned())?
                    .strip_prefix('#')
                    .ok_or_else(|| "fixture ref lacks #".to_owned())?;
                if matches!(name, "operationId" | "deviceId") {
                    let FixtureDagValueInner::Bytes(value) = self.value else {
                        return Err("fixture UUID projection was not bytes".to_owned());
                    };
                    Ok(Value::String(
                        Uuid::from_slice(&value)
                            .map_err(|error| error.to_string())?
                            .hyphenated()
                            .to_string(),
                    ))
                } else {
                    self.into_json_for_schema(&definitions[name], definitions)
                }
            }
            "union" => {
                let name = {
                    let FixtureDagValueInner::Map(values) = &self.value else {
                        return Err("fixture union projection was not an object".to_owned());
                    };
                    let FixtureDagValueInner::String(type_id) = &values
                        .get("$type")
                        .ok_or_else(|| "fixture union lacks type".to_owned())?
                        .value
                    else {
                        return Err("fixture union type was not text".to_owned());
                    };
                    type_id
                        .strip_prefix("blue.catbird.chat.defs#")
                        .ok_or_else(|| "fixture union has foreign type".to_owned())?
                        .to_owned()
                };
                if !schema["refs"].as_array().is_some_and(|refs| {
                    refs.iter()
                        .any(|reference| reference.as_str() == Some(&format!("#{name}")))
                }) {
                    return Err("fixture union selected a disallowed type".to_owned());
                }
                self.into_json_for_schema(&definitions[&name], definitions)
            }
            "object" => {
                let FixtureDagValueInner::Map(values) = self.value else {
                    return Err("fixture object was not map".to_owned());
                };
                let properties = schema["properties"]
                    .as_object()
                    .ok_or_else(|| "fixture object lacks properties".to_owned())?;
                values
                    .into_iter()
                    .map(|(name, value)| {
                        if name == "$type" {
                            let FixtureDagValueInner::String(value) = value.value else {
                                return Err("fixture type was not text".to_owned());
                            };
                            Ok((name, Value::String(value)))
                        } else {
                            Ok((
                                name.clone(),
                                value.into_json_for_schema(&properties[&name], definitions)?,
                            ))
                        }
                    })
                    .collect::<Result<serde_json::Map<_, _>, _>>()
                    .map(Value::Object)
            }
            "string" => match self.value {
                FixtureDagValueInner::String(value) => Ok(Value::String(value)),
                _ => Err("fixture string was not text".to_owned()),
            },
            "bytes" => match self.value {
                FixtureDagValueInner::Bytes(value) => Ok(Value::String(STANDARD.encode(value))),
                _ => Err("fixture bytes were not bytes".to_owned()),
            },
            "integer" => match self.value {
                FixtureDagValueInner::Integer(value) => Ok(json!(value)),
                _ => Err("fixture integer was not integer".to_owned()),
            },
            "boolean" => match self.value {
                FixtureDagValueInner::Bool(value) => Ok(json!(value)),
                _ => Err("fixture bool was not boolean".to_owned()),
            },
            "array" => match self.value {
                FixtureDagValueInner::Array(values) => values
                    .into_iter()
                    .map(|value| value.into_json_for_schema(&schema["items"], definitions))
                    .collect::<Result<Vec<_>, _>>()
                    .map(Value::Array),
                _ => Err("fixture array was not array".to_owned()),
            },
            other => Err(format!("unsupported fixture schema type {other}")),
        }
    }
}

struct RealCreationEntry {
    entry_id: Uuid,
    transition_id: Uuid,
    raw_wrapper: Vec<u8>,
    public_row_json: Vec<u8>,
    outer_fingerprint: [u8; 32],
}

fn rewrite_exact_text(value: &mut Value, from: &str, to: &str) {
    match value {
        Value::String(text) if text == from => *text = to.to_owned(),
        Value::Array(values) => values
            .iter_mut()
            .for_each(|value| rewrite_exact_text(value, from, to)),
        Value::Object(values) => values
            .values_mut()
            .for_each(|value| rewrite_exact_text(value, from, to)),
        _ => {}
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
        Value::Array(values) => values
            .iter_mut()
            .for_each(|value| rewrite_conversation_id(value, from_uuid, to_uuid, from_b64, to_b64)),
        Value::Object(values) => values
            .values_mut()
            .for_each(|value| rewrite_conversation_id(value, from_uuid, to_uuid, from_b64, to_b64)),
        _ => {}
    }
}

fn repair_body_digests(value: &mut Value) {
    match value {
        Value::Object(map) => {
            if let Some(Value::String(bytes_b64)) = map.get("bytes") {
                if map.contains_key("sha256") {
                    if let Ok(bytes) = STANDARD.decode(bytes_b64) {
                        map.insert(
                            "sha256".to_owned(),
                            json!(STANDARD.encode(Sha256::digest(bytes))),
                        );
                    }
                }
            }
            if let Some(Value::String(ciphertext_b64)) = map.get("ciphertext") {
                if map.contains_key("ciphertextSha256") {
                    if let Ok(ciphertext) = STANDARD.decode(ciphertext_b64) {
                        map.insert(
                            "ciphertextSha256".to_owned(),
                            json!(STANDARD.encode(Sha256::digest(&ciphertext))),
                        );
                        map.insert("ciphertextSize".to_owned(), json!(ciphertext.len()));
                    }
                }
            }
            if let (Some(origin), Some(Value::Object(author))) = (
                map.get("originTransitionId").cloned(),
                map.get_mut("authorProof"),
            ) {
                author.insert("originTransitionId".to_owned(), origin);
            }
            for child in map.values_mut() {
                repair_body_digests(child);
            }
        }
        Value::Array(values) => {
            for value in values {
                repair_body_digests(value);
            }
        }
        _ => {}
    }
}

fn sign_wrapper(identity: &FixtureIdentity, body: Value) -> Result<Vec<u8>, String> {
    let mut wrapper = json!({"body": body, "signature": STANDARD.encode([0_u8; 64])});
    let unsigned = serde_json::to_vec(&wrapper).map_err(|error| error.to_string())?;
    let canonical = decode_canonical_signed_mutation(&unsigned)
        .map_err(|error| format!("canonicalize creation: {error:?}"))?;
    wrapper["signature"] = Value::String(
        STANDARD.encode(
            identity
                .signing_key
                .sign(canonical.transcript_bytes())
                .to_bytes(),
        ),
    );
    serde_json::to_vec(&wrapper).map_err(|error| error.to_string())
}

fn build_real_creation_entry(
    identity: &FixtureIdentity,
    conversation_id: Uuid,
    coordinate: &PublicGroupSnapshotCoordinate,
    genesis_group_info: &[u8],
    received_at: &str,
) -> Result<RealCreationEntry, String> {
    let fixture: Value =
        serde_json::from_str(CONTRACT_VECTORS).map_err(|error| error.to_string())?;
    let lexicon: Value = serde_json::from_str(LEXICON).map_err(|error| error.to_string())?;
    let definitions = lexicon["defs"]
        .as_object()
        .ok_or_else(|| "lexicon definitions missing".to_owned())?;
    let case = fixture["controlEntryFingerprints"]["cases"]
        .as_array()
        .ok_or_else(|| "creation vector cases missing".to_owned())?
        .iter()
        .find(|case| {
            case["entryKind"]
                .as_str()
                .is_some_and(|kind| kind.ends_with("creationEntry"))
        })
        .ok_or_else(|| "creation vector missing".to_owned())?;
    let body_cbor = hex::decode(
        case["unsignedSigningProjectionCanonicalDagCborHex"]
            .as_str()
            .ok_or_else(|| "creation vector body missing".to_owned())?,
    )
    .map_err(|error| error.to_string())?;
    let body: FixtureDagValue =
        serde_ipld_dagcbor::from_slice(&body_cbor).map_err(|error| error.to_string())?;
    let signed_name = case["signedRequestRef"]
        .as_str()
        .ok_or_else(|| "creation signed ref missing".to_owned())?
        .strip_prefix("blue.catbird.chat.defs#")
        .ok_or_else(|| "creation signed ref namespace".to_owned())?;
    let body_name = definitions[signed_name]["properties"]["body"]["refs"][0]
        .as_str()
        .ok_or_else(|| "creation body ref missing".to_owned())?
        .strip_prefix('#')
        .ok_or_else(|| "creation body ref namespace".to_owned())?;
    let mut body = body.into_json_for_schema(&definitions[body_name], definitions)?;
    repair_body_digests(&mut body);
    body["keyId"] = json!(&identity.key_id);
    const FROZEN_CID: [u8; 16] = [
        0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x41, 0x11, 0x91, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11,
        0x11,
    ];
    let from_uuid = Uuid::from_bytes(FROZEN_CID).hyphenated().to_string();
    let to_uuid = conversation_id.hyphenated().to_string();
    rewrite_conversation_id(
        &mut body,
        &from_uuid,
        &to_uuid,
        &STANDARD.encode(FROZEN_CID),
        &STANDARD.encode(conversation_id.as_bytes()),
    );
    let old_transition = body["transitionId"]
        .as_str()
        .ok_or_else(|| "creation transition missing".to_owned())?
        .to_owned();
    let transition_id = Uuid::new_v4();
    rewrite_conversation_id(
        &mut body,
        &old_transition,
        &transition_id.hyphenated().to_string(),
        &STANDARD.encode(
            Uuid::parse_str(&old_transition)
                .map_err(|error| error.to_string())?
                .as_bytes(),
        ),
        &STANDARD.encode(transition_id.as_bytes()),
    );
    let old_did = body["actorDid"]
        .as_str()
        .ok_or_else(|| "creation actor did missing".to_owned())?
        .to_owned();
    let old_device = body["actorDeviceId"]
        .as_str()
        .ok_or_else(|| "creation actor device missing".to_owned())?
        .to_owned();
    rewrite_exact_text(&mut body, &old_did, &identity.did);
    rewrite_exact_text(
        &mut body,
        &old_device,
        &identity.device_id.hyphenated().to_string(),
    );
    body["conversationKind"] = json!("group");
    body["next"] = coordinate_json(coordinate);
    body["metadataSnapshot"]["coordinate"]["conversationId"] =
        json!(STANDARD.encode(conversation_id.as_bytes()));
    body["metadataSnapshot"]["coordinate"]["generation"] = json!(coordinate.generation());
    body["metadataSnapshot"]["coordinate"]["groupId"] =
        json!(STANDARD.encode(coordinate.group_id()));
    body["metadataSnapshot"]["coordinate"]["epoch"] = json!(coordinate.epoch());
    body["metadataSnapshot"]["coordinate"]["groupContextHash"] =
        json!(STANDARD.encode(coordinate.group_context_hash()));
    body["metadataSnapshot"]["coordinate"]["confirmationTag"] =
        json!(STANDARD.encode(coordinate.confirmation_tag()));
    body["metadataSnapshot"]["originTransitionId"] = json!(transition_id.hyphenated().to_string());
    body["metadataSnapshot"]["authorProof"]["authorDid"] = json!(&identity.did);
    body["metadataSnapshot"]["authorProof"]["authorDeviceId"] =
        json!(identity.device_id.hyphenated().to_string());
    body["metadataSnapshot"]["authorProof"]["authorKeyId"] = json!(&identity.key_id);
    body["metadataSnapshot"]["authorProof"]["signaturePublicKey"] =
        json!(STANDARD.encode(identity.signing_public_key()));
    body["metadataSnapshot"]["authorProof"]["originTransitionId"] =
        json!(transition_id.hyphenated().to_string());
    body["manifest"]["actorLeaf"]["userDid"] = json!(&identity.did);
    body["manifest"]["actorLeaf"]["deviceId"] = json!(identity.device_id.hyphenated().to_string());
    body["manifest"]["participants"] =
        json!([{"userDid": &identity.did, "status":"active", "role":"admin"}]);
    body["genesisGroupInfo"]["bytes"] = json!(STANDARD.encode(genesis_group_info));
    body["genesisGroupInfo"]["sha256"] = json!(STANDARD.encode(Sha256::digest(genesis_group_info)));
    let raw_wrapper = sign_wrapper(identity, body)?;
    let entry_id = Uuid::new_v4();
    let public_row_json = serde_json::to_vec(&json!({
        "$type": case["entryKind"], "entryId": entry_id, "conversationId": conversation_id,
        "seq": 1, "signedRequest": serde_json::from_slice::<Value>(&raw_wrapper).map_err(|error| error.to_string())?,
        "receivedAt": received_at,
    })).map_err(|error| error.to_string())?;
    let decoded = decode_and_verify_control_entry(&public_row_json, &identity.signing_public_key())
        .map_err(|error| format!("verify dynamic creation control: {error:?}"))?;
    Ok(RealCreationEntry {
        entry_id,
        transition_id,
        raw_wrapper,
        public_row_json,
        outer_fingerprint: *decoded.outer_control_fingerprint(),
    })
}

pub(super) struct DurableRecoveryFixture {
    pub(super) identity: FixtureIdentity,
    pub(super) conversation_id: Uuid,
    pub(super) creation_transition_id: Uuid,
    pub(super) prior: PublicGroupSnapshotCoordinate,
    pub(super) available_key_package_ref: [u8; 32],
    pub(super) available_key_package_wrapper: Vec<u8>,
}

/// The durable prerequisite aggregate for a genuine two-member recovery
/// fulfillment. The returned coordinate is the state after a real invitation,
/// acceptance, and Add-kind recovery fulfillment. The target Replace request
/// itself is intentionally not opened here: the production runner must make,
/// authorize, and commit that client request.
pub(super) struct DurableRecoveryFulfillmentFixture {
    pub(super) requester: FixtureIdentity,
    pub(super) fulfiller: FixtureIdentity,
    pub(super) conversation_id: Uuid,
    pub(super) creation_transition_id: Uuid,
    pub(super) prior: PublicGroupSnapshotCoordinate,
    pub(super) next: ActivePublicState,
    pub(super) requester_key_package_ref: [u8; 32],
    pub(super) requester_key_package_wrapper: Vec<u8>,
    pub(super) commit: Vec<u8>,
    pub(super) welcome: Vec<u8>,
}

struct TwoMemberFulfillmentProducts {
    genesis_group_info: Vec<u8>,
    genesis: ActivePublicState,
    acceptance: ActivePublicState,
    prior: ActivePublicState,
    next: ActivePublicState,
    fulfiller_key_package_ref: [u8; 32],
    fulfiller_key_package_wrapper: Vec<u8>,
    fulfiller_key_package_init_key: Vec<u8>,
    add_commit: Vec<u8>,
    add_welcome: Vec<u8>,
    requester_key_package_ref: [u8; 32],
    requester_key_package_wrapper: Vec<u8>,
    requester_key_package_init_key: Vec<u8>,
    commit: Vec<u8>,
    welcome: Vec<u8>,
}

struct RealAcceptanceEntry {
    entry_id: Uuid,
    transition_id: Uuid,
    request_id: Uuid,
    raw_wrapper: Vec<u8>,
    canonical_projection: Vec<u8>,
    signing_transcript: Vec<u8>,
    request_digest: Vec<u8>,
    signature: Vec<u8>,
    public_row_json: Vec<u8>,
    server_fields: Vec<u8>,
    outer_fingerprint: [u8; 32],
    expires_at: DateTime<Utc>,
}

struct RealAddFulfillmentEntry {
    entry_id: Uuid,
    transition_id: Uuid,
    welcome_id: Uuid,
    raw_wrapper: Vec<u8>,
    canonical_projection: Vec<u8>,
    signing_transcript: Vec<u8>,
    request_digest: Vec<u8>,
    signature: Vec<u8>,
    public_row_json: Vec<u8>,
    server_fields: Vec<u8>,
    outer_fingerprint: [u8; 32],
    metadata_nonce: Vec<u8>,
    metadata_ciphertext: Vec<u8>,
}

fn build_real_creation_entry_with_pending(
    creator: &FixtureIdentity,
    pending: &FixtureIdentity,
    conversation_id: Uuid,
    coordinate: &PublicGroupSnapshotCoordinate,
    genesis_group_info: &[u8],
    received_at: &str,
) -> Result<RealCreationEntry, String> {
    let mut entry = build_real_creation_entry(
        creator,
        conversation_id,
        coordinate,
        genesis_group_info,
        received_at,
    )?;
    let mut wrapper: Value = serde_json::from_slice(&entry.raw_wrapper)
        .map_err(|error| format!("decode singleton Recovery creation wrapper: {error}"))?;
    let pending_participant = json!({
        "userDid": &pending.did,
        "status": "pending",
        "role": "member",
        "invitationProvenance": {
            "invitationTransitionId": entry.transition_id.hyphenated().to_string(),
            "invitedByDid": &creator.did,
            "invitedByDeviceId": creator.device_id.hyphenated().to_string(),
        }
    });
    let participants = wrapper["body"]["manifest"]["participants"]
        .as_array_mut()
        .ok_or_else(|| "singleton Recovery creation manifest lacks participants".to_owned())?;
    participants.push(pending_participant);
    participants.sort_by(|left, right| {
        left["userDid"]
            .as_str()
            .unwrap_or_default()
            .as_bytes()
            .cmp(right["userDid"].as_str().unwrap_or_default().as_bytes())
    });
    wrapper["signature"] = Value::String(STANDARD.encode([0_u8; 64]));
    let unsigned = serde_json::to_vec(&wrapper)
        .map_err(|error| format!("encode pending Recovery creation wrapper: {error}"))?;
    let canonical = decode_canonical_signed_mutation(&unsigned)
        .map_err(|error| format!("canonicalize pending Recovery creation: {error:?}"))?;
    wrapper["signature"] = Value::String(
        STANDARD.encode(
            creator
                .signing_key
                .sign(canonical.transcript_bytes())
                .to_bytes(),
        ),
    );
    entry.raw_wrapper = serde_json::to_vec(&wrapper)
        .map_err(|error| format!("encode signed pending Recovery creation: {error}"))?;
    let mut row: Value = serde_json::from_slice(&entry.public_row_json)
        .map_err(|error| format!("decode pending Recovery creation row: {error}"))?;
    row["signedRequest"] = wrapper;
    entry.public_row_json = serde_json::to_vec(&row)
        .map_err(|error| format!("encode pending Recovery creation row: {error}"))?;
    entry.outer_fingerprint =
        *decode_and_verify_control_entry(&entry.public_row_json, &creator.signing_public_key())
            .map_err(|error| format!("verify pending Recovery creation row: {error:?}"))?
            .outer_control_fingerprint();
    Ok(entry)
}

#[allow(clippy::too_many_arguments)]
fn build_real_acceptance_entry(
    creator: &FixtureIdentity,
    acceptor: &FixtureIdentity,
    conversation_id: Uuid,
    invitation_transition_id: Uuid,
    prior: &PublicGroupSnapshotCoordinate,
    next: &PublicGroupSnapshotCoordinate,
    key_package_ref: [u8; 32],
    key_package_wrapper: &[u8],
    received_at: DateTime<Utc>,
) -> Result<RealAcceptanceEntry, String> {
    let entry_id = Uuid::new_v4();
    let transition_id = Uuid::new_v4();
    let request_id = Uuid::new_v4();
    let expires_at = received_at + chrono::Duration::minutes(5);
    let received_at_text = received_at.to_rfc3339_opts(chrono::SecondsFormat::Millis, true);
    let expires_at_text = expires_at.to_rfc3339_opts(chrono::SecondsFormat::Millis, true);
    let body = json!({
        "$type": SignedMutationKind::ParticipantAcceptance.type_id(),
        "signatureDomain": String::from_utf8(
            SignedMutationKind::ParticipantAcceptance.domain().to_vec()
        ).map_err(|_| "participant acceptance domain is not UTF-8")?,
        "transitionId": transition_id.hyphenated().to_string(),
        "recoveryRequestId": request_id.hyphenated().to_string(),
        "actorDid": &acceptor.did,
        "actorDeviceId": acceptor.device_id.hyphenated().to_string(),
        "keyId": &acceptor.key_id,
        "authGeneration": 1,
        "prior": coordinate_json(prior),
        "next": coordinate_json(next),
        "invitationProvenance": {
            "invitationTransitionId": invitation_transition_id.hyphenated().to_string(),
            "invitedByDid": &creator.did,
            "invitedByDeviceId": creator.device_id.hyphenated().to_string(),
        },
        "idempotencyKey": transition_id.hyphenated().to_string(),
        "signedAt": &received_at_text,
    });
    let mut wrapper = json!({"body": body, "signature": STANDARD.encode([0_u8; 64])});
    let unsigned = serde_json::to_vec(&wrapper)
        .map_err(|error| format!("encode unsigned Recovery acceptance: {error}"))?;
    let canonical = decode_canonical_signed_mutation(&unsigned)
        .map_err(|error| format!("canonicalize Recovery acceptance: {error:?}"))?;
    let signature = acceptor
        .signing_key
        .sign(canonical.transcript_bytes())
        .to_bytes();
    wrapper["signature"] = Value::String(STANDARD.encode(signature));
    let raw_wrapper = serde_json::to_vec(&wrapper)
        .map_err(|error| format!("encode signed Recovery acceptance: {error}"))?;
    let verified = decode_and_verify_signed_mutation(&raw_wrapper, &acceptor.signing_public_key())
        .map_err(|error| format!("verify signed Recovery acceptance: {error:?}"))?;
    let key_package_sha = Sha256::digest(key_package_wrapper);
    let recovery = json!({
        "recoveryRequestId": request_id.hyphenated().to_string(),
        "conversationId": conversation_id.hyphenated().to_string(),
        "requesterDid": &acceptor.did,
        "requesterDeviceId": acceptor.device_id.hyphenated().to_string(),
        "recoveryKind": "add",
        "boundCoordinate": coordinate_json(next),
        "reservation": {
            "recoveryRequestId": request_id.hyphenated().to_string(),
            "conversationId": conversation_id.hyphenated().to_string(),
            "boundCoordinate": coordinate_json(next),
            "requesterDid": &acceptor.did,
            "requesterDeviceId": acceptor.device_id.hyphenated().to_string(),
            "requesterKeyId": &acceptor.key_id,
            "requesterAuthGeneration": 1,
            "keyPackageRef": STANDARD.encode(key_package_ref),
            "cipherSuite": "MLS_256_XWING_CHACHA20POLY1305_SHA256_Ed25519",
            "purpose": "leafRecovery",
            "status": "active",
            "expiresAt": &expires_at_text,
            "keyPackage": {
                "framing": "mlsMessage",
                "contentType": "keyPackage",
                "bytes": STANDARD.encode(key_package_wrapper),
                "sha256": STANDARD.encode(key_package_sha),
                "keyPackageRef": STANDARD.encode(key_package_ref),
            }
        },
        "status": "open",
        "requestedAt": &received_at_text,
        "expiresAt": &expires_at_text,
    });
    let public_row_json = serde_json::to_vec(&json!({
        "$type": "blue.catbird.chat.defs#participantAcceptanceEntry",
        "entryId": entry_id.hyphenated().to_string(),
        "conversationId": conversation_id.hyphenated().to_string(),
        "seq": 2,
        "signedRequest": wrapper,
        "recovery": recovery,
        "receivedAt": &received_at_text,
    }))
    .map_err(|error| format!("encode Recovery acceptance entry: {error}"))?;
    let control = decode_and_verify_control_entry(&public_row_json, &acceptor.signing_public_key())
        .map_err(|error| format!("verify Recovery acceptance entry: {error:?}"))?;
    Ok(RealAcceptanceEntry {
        entry_id,
        transition_id,
        request_id,
        raw_wrapper,
        canonical_projection: verified.canonical_projection().to_vec(),
        signing_transcript: verified.transcript_bytes().to_vec(),
        request_digest: verified.request_digest().to_vec(),
        signature: verified.signature().to_vec(),
        public_row_json,
        server_fields: control
            .server_fields_dag_cbor()
            .map_err(|error| format!("encode Recovery acceptance server fields: {error:?}"))?,
        outer_fingerprint: *control.outer_control_fingerprint(),
        expires_at,
    })
}

#[allow(clippy::too_many_arguments)]
fn build_real_add_fulfillment_entry(
    signer: &FixtureIdentity,
    added: &FixtureIdentity,
    metadata_author: &FixtureIdentity,
    conversation_id: Uuid,
    metadata_origin_transition_id: Uuid,
    recovery_request_id: Uuid,
    key_package_ref: [u8; 32],
    prior: &PublicGroupSnapshotCoordinate,
    next: &PublicGroupSnapshotCoordinate,
    transition_id: Uuid,
    commit: &[u8],
    welcome: &[u8],
    received_at: DateTime<Utc>,
) -> Result<RealAddFulfillmentEntry, String> {
    let entry_id = Uuid::new_v4();
    let welcome_id = Uuid::new_v4();
    let metadata_nonce = vec![0x54_u8; 12];
    let metadata_ciphertext = vec![0x55_u8; 16];
    let received_at_text = received_at.to_rfc3339_opts(chrono::SecondsFormat::Millis, true);
    let body = json!({
        "$type": SignedMutationKind::LeafRecoveryFulfillment.type_id(),
        "signatureDomain": String::from_utf8(
            SignedMutationKind::LeafRecoveryFulfillment.domain().to_vec()
        ).map_err(|_| "leaf Recovery fulfillment domain is not UTF-8")?,
        "recoveryRequestId": recovery_request_id.hyphenated().to_string(),
        "transitionId": transition_id.hyphenated().to_string(),
        "actorDid": &signer.did,
        "actorDeviceId": signer.device_id.hyphenated().to_string(),
        "keyId": &signer.key_id,
        "authGeneration": 1,
        "prior": coordinate_json(prior),
        "next": coordinate_json(next),
        "aad": {
            "protocolVersion": "1",
            "conversationId": STANDARD.encode(conversation_id.as_bytes()),
            "generation": prior.generation(),
            "transitionId": STANDARD.encode(transition_id.as_bytes()),
            "prior": {
                "conversationId": STANDARD.encode(conversation_id.as_bytes()),
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
                "userDid": &added.did,
                "deviceId": added.device_id.hyphenated().to_string(),
                "recoveryRequestId": recovery_request_id.hyphenated().to_string(),
                "keyPackageRef": STANDARD.encode(key_package_ref),
            }],
            "leafRecoveryRequestId": recovery_request_id.hyphenated().to_string(),
            "welcomeBundle": {
                "welcomeId": welcome_id.hyphenated().to_string(),
                "framing": "mlsMessage",
                "contentType": "welcome",
                "opaqueWelcome": STANDARD.encode(welcome),
                "sha256": STANDARD.encode(Sha256::digest(welcome)),
                "deliveries": [{
                    "recipientDid": &added.did,
                    "recipientDeviceId": added.device_id.hyphenated().to_string(),
                    "provenance": {
                        "recoveryRequestId": recovery_request_id.hyphenated().to_string(),
                        "keyPackageRef": STANDARD.encode(key_package_ref),
                    },
                }],
            },
        },
        "commit": {
            "framing": "mlsMessage",
            "contentType": "publicMessageCommit",
            "bytes": STANDARD.encode(commit),
            "sha256": STANDARD.encode(Sha256::digest(commit)),
        },
        "metadataSnapshot": {
            "coordinate": {
                "conversationId": STANDARD.encode(conversation_id.as_bytes()),
                "generation": next.generation(),
                "groupId": STANDARD.encode(next.group_id()),
                "epoch": next.epoch(),
                "groupContextHash": STANDARD.encode(next.group_context_hash()),
                "confirmationTag": STANDARD.encode(next.confirmation_tag()),
            },
            "originTransitionId": metadata_origin_transition_id.hyphenated().to_string(),
            "metadataVersion": 1,
            "nonce": STANDARD.encode(&metadata_nonce),
            "ciphertext": STANDARD.encode(&metadata_ciphertext),
            "ciphertextSha256": STANDARD.encode(Sha256::digest(&metadata_ciphertext)),
            "ciphertextSize": metadata_ciphertext.len(),
            "authorProof": {
                "authorDid": &metadata_author.did,
                "authorDeviceId": metadata_author.device_id.hyphenated().to_string(),
                "authorKeyId": &metadata_author.key_id,
                "signaturePublicKey": STANDARD.encode(metadata_author.signing_public_key()),
                "authGenerationAtOrigin": 1,
                "originTransitionId": metadata_origin_transition_id.hyphenated().to_string(),
                "originSeq": 1,
                "roleAtOrigin": "admin",
                "deviceStatusAtOrigin": "active",
            },
        },
        "idempotencyKey": transition_id.hyphenated().to_string(),
        "signedAt": &received_at_text,
    });
    let mut wrapper = json!({"body": body, "signature": STANDARD.encode([0_u8; 64])});
    let unsigned = serde_json::to_vec(&wrapper)
        .map_err(|error| format!("encode unsigned Add recovery fulfillment: {error}"))?;
    let canonical = decode_canonical_signed_mutation(&unsigned)
        .map_err(|error| format!("canonicalize Add recovery fulfillment: {error:?}"))?;
    let signature = signer
        .signing_key
        .sign(canonical.transcript_bytes())
        .to_bytes();
    wrapper["signature"] = Value::String(STANDARD.encode(signature));
    let raw_wrapper = serde_json::to_vec(&wrapper)
        .map_err(|error| format!("encode signed Add recovery fulfillment: {error}"))?;
    let verified = decode_and_verify_signed_mutation(&raw_wrapper, &signer.signing_public_key())
        .map_err(|error| format!("verify signed Add recovery fulfillment: {error:?}"))?;
    let public_row_json = serde_json::to_vec(&json!({
        "$type": "blue.catbird.chat.defs#leafRecoveryFulfillmentEntry",
        "entryId": entry_id.hyphenated().to_string(),
        "conversationId": conversation_id.hyphenated().to_string(),
        "seq": 3,
        "signedRequest": wrapper,
        "receivedAt": &received_at_text,
    }))
    .map_err(|error| format!("encode Add recovery fulfillment entry: {error}"))?;
    let control = decode_and_verify_control_entry(&public_row_json, &signer.signing_public_key())
        .map_err(|error| format!("verify Add recovery fulfillment entry: {error:?}"))?;
    Ok(RealAddFulfillmentEntry {
        entry_id,
        transition_id,
        welcome_id,
        raw_wrapper,
        canonical_projection: verified.canonical_projection().to_vec(),
        signing_transcript: verified.transcript_bytes().to_vec(),
        request_digest: verified.request_digest().to_vec(),
        signature: verified.signature().to_vec(),
        public_row_json,
        server_fields: control
            .server_fields_dag_cbor()
            .map_err(|error| format!("encode Add fulfillment server fields: {error:?}"))?,
        outer_fingerprint: *control.outer_control_fingerprint(),
        metadata_nonce,
        metadata_ciphertext,
    })
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct RecoveryCommitAad<'a> {
    protocol_version: &'static str,
    #[serde(with = "serde_bytes")]
    conversation_id: &'a [u8],
    generation: u64,
    #[serde(with = "serde_bytes")]
    transition_id: &'a [u8],
    prior: RecoveryCommitPriorAad<'a>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct RecoveryCommitPriorAad<'a> {
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

fn recovery_commit_aad(
    conversation_id: Uuid,
    transition_id: Uuid,
    prior: &PublicGroupSnapshotCoordinate,
) -> Result<Vec<u8>, String> {
    let canonical = serde_ipld_dagcbor::to_vec(&RecoveryCommitAad {
        protocol_version: "1",
        conversation_id: conversation_id.as_bytes(),
        generation: prior.generation(),
        transition_id: transition_id.as_bytes(),
        prior: RecoveryCommitPriorAad {
            conversation_id: conversation_id.as_bytes(),
            generation: prior.generation(),
            state_version: prior.state_version(),
            group_id: prior.group_id(),
            epoch: prior.epoch(),
            group_context_hash: prior.group_context_hash(),
            confirmation_tag: prior.confirmation_tag(),
            lifecycle: "active",
        },
    })
    .map_err(|error| format!("encode canonical Recovery fulfillment AAD: {error}"))?;
    let mut aad = b"CATBIRD-CHAT-MLS-AAD-COMMIT\0".to_vec();
    aad.extend_from_slice(&canonical);
    Ok(aad)
}

fn public_state_from_group_info(
    group_info: &[u8],
    identity: &FixtureIdentity,
    conversation_id: Uuid,
    generation: u64,
    state_version: u64,
    at: DateTime<Utc>,
) -> Result<ActivePublicState, String> {
    let credential = format!("{}#{}", identity.did, identity.device_id).into_bytes();
    let validated = validate_group_info(
        group_info,
        GroupInfoValidationPolicy {
            expected_basic_credential: &credential,
            expected_signature_key: &identity.signing_public_key(),
            now_unix_seconds: u64::try_from(at.timestamp())
                .map_err(|_| "negative Recovery fulfillment fixture clock".to_owned())?,
            max_bytes: MAX_GROUP_INFO_WIRE_BYTES,
            max_ratchet_tree_bytes: MAX_GROUP_INFO_WIRE_BYTES,
            max_members: 2,
        },
    )
    .map_err(|error| format!("validate two-member Recovery GroupInfo: {error:?}"))?;
    let coordinate = PublicGroupSnapshotCoordinate::new(
        *conversation_id.as_bytes(),
        generation,
        state_version,
        validated
            .group_id()
            .try_into()
            .map_err(|_| "two-member Recovery group id is not 32 bytes".to_owned())?,
        validated.epoch(),
        *validated.group_context_hash(),
        *validated.confirmation_tag(),
        PublicGroupSnapshotLifecycle::Active,
    );
    verify_genesis_group_info(
        group_info,
        GenesisGroupInfoExpectations {
            coordinate,
            expected_basic_credential: &credential,
            expected_signature_key: &identity.signing_public_key(),
            now_unix_seconds: u64::try_from(at.timestamp())
                .map_err(|_| "negative Recovery fulfillment fixture clock".to_owned())?,
            max_wire_bytes: MAX_GROUP_INFO_WIRE_BYTES,
            max_ratchet_tree_bytes: MAX_GROUP_INFO_WIRE_BYTES,
            max_members: 2,
        },
    )
    .map_err(|error| format!("verify two-member Recovery public state: {error:?}"))
}

fn coordinate_from_merged_group(
    group: &MlsGroup,
    successor_group_context: &[u8],
    conversation_id: Uuid,
    state_version: u64,
) -> Result<PublicGroupSnapshotCoordinate, String> {
    let group_context_hash: [u8; 32] = Sha256::digest(successor_group_context).into();
    let encoded_confirmation_tag = group
        .confirmation_tag()
        .tls_serialize_detached()
        .map_err(|error| format!("serialize Recovery successor confirmation tag: {error:?}"))?;
    if encoded_confirmation_tag.first() != Some(&32) || encoded_confirmation_tag.len() != 33 {
        return Err(
            "XWing Recovery successor confirmation tag is not canonical one-byte-VL bytes"
                .to_owned(),
        );
    }
    let confirmation_tag: [u8; 32] = encoded_confirmation_tag[1..]
        .try_into()
        .map_err(|_| "Recovery successor confirmation tag is not 32 bytes".to_owned())?;
    Ok(PublicGroupSnapshotCoordinate::new(
        *conversation_id.as_bytes(),
        0,
        state_version,
        group
            .group_id()
            .as_slice()
            .try_into()
            .map_err(|_| "Recovery successor group id is not 32 bytes".to_owned())?,
        group.epoch().as_u64(),
        group_context_hash,
        confirmation_tag,
        PublicGroupSnapshotLifecycle::Active,
    ))
}

fn build_key_package_material(
    identity: &FixtureIdentity,
    at: DateTime<Utc>,
    provider: &openmls_libcrux_crypto::Provider,
    signer: &SignatureKeyPair,
) -> Result<(KeyPackage, [u8; 32], Vec<u8>, Vec<u8>), String> {
    let credential = format!("{}#{}", identity.did, identity.device_id).into_bytes();
    let lifetime = Lifetime::init(
        u64::try_from((at - chrono::Duration::minutes(1)).timestamp())
            .map_err(|_| "negative Recovery fulfillment KeyPackage lifetime".to_owned())?,
        u64::try_from((at + chrono::Duration::hours(1)).timestamp())
            .map_err(|_| "negative Recovery fulfillment KeyPackage lifetime".to_owned())?,
    );
    let package = KeyPackage::builder()
        .key_package_lifetime(lifetime)
        .leaf_node_capabilities(exact_mls_capabilities())
        .build(
            XWING_CIPHERSUITE,
            provider,
            signer,
            CredentialWithKey {
                credential: BasicCredential::new(credential.clone()).into(),
                signature_key: identity.signing_public_key().to_vec().into(),
            },
        )
        .map_err(|error| format!("build Recovery fulfillment KeyPackage: {error:?}"))?
        .key_package()
        .clone();
    let wrapper = MlsMessageOut::from(package.clone())
        .tls_serialize_detached()
        .map_err(|error| format!("serialize Recovery fulfillment KeyPackage: {error:?}"))?;
    let validated = validate_key_package(
        &wrapper,
        KeyPackageValidationPolicy {
            expected_basic_credential: &credential,
            expected_signature_key: &identity.signing_public_key(),
            now_unix_seconds: u64::try_from(at.timestamp())
                .map_err(|_| "negative Recovery fulfillment fixture clock".to_owned())?,
            max_bytes: MAX_KEY_PACKAGE_WIRE_BYTES,
        },
    )
    .map_err(|error| format!("validate Recovery fulfillment KeyPackage: {error:?}"))?;
    Ok((
        package,
        *validated.key_package_ref(),
        wrapper,
        validated.init_key().to_vec(),
    ))
}

fn build_two_member_fulfillment_products(
    requester: &FixtureIdentity,
    fulfiller: &FixtureIdentity,
    conversation_id: Uuid,
    add_transition_id: Uuid,
    fulfillment_transition_id: Uuid,
    at: DateTime<Utc>,
) -> Result<TwoMemberFulfillmentProducts, String> {
    let provider = openmls_libcrux_crypto::Provider::new()
        .map_err(|error| format!("create Recovery fulfillment OpenMLS provider: {error:?}"))?;
    let requester_signer = SignatureKeyPair::from_raw(
        XWING_CIPHERSUITE.signature_algorithm(),
        requester.signing_key.to_bytes().to_vec(),
        requester.signing_public_key().to_vec(),
    );
    requester_signer
        .store(provider.storage())
        .map_err(|error| format!("store requester OpenMLS signer: {error:?}"))?;
    let fulfiller_signer = SignatureKeyPair::from_raw(
        XWING_CIPHERSUITE.signature_algorithm(),
        fulfiller.signing_key.to_bytes().to_vec(),
        fulfiller.signing_public_key().to_vec(),
    );
    fulfiller_signer
        .store(provider.storage())
        .map_err(|error| format!("store fulfiller OpenMLS signer: {error:?}"))?;
    let lifetime = Lifetime::init(
        u64::try_from((at - chrono::Duration::minutes(1)).timestamp())
            .map_err(|_| "negative Recovery fulfillment fixture lifetime".to_owned())?,
        u64::try_from((at + chrono::Duration::hours(1)).timestamp())
            .map_err(|_| "negative Recovery fulfillment fixture lifetime".to_owned())?,
    );
    let config = MlsGroupCreateConfig::builder()
        .ciphersuite(XWING_CIPHERSUITE)
        .wire_format_policy(openmls::group::PURE_PLAINTEXT_WIRE_FORMAT_POLICY)
        .use_ratchet_tree_extension(true)
        .capabilities(exact_mls_capabilities())
        .lifetime(lifetime)
        .build();
    let group_id: [u8; 32] = Sha256::digest(
        [
            b"CATBIRD-RECOVERY-FULFILLMENT-PRODUCTION-PROOF-GENESIS\0".as_ref(),
            conversation_id.as_bytes(),
        ]
        .concat(),
    )
    .into();
    let requester_credential = format!("{}#{}", requester.did, requester.device_id).into_bytes();
    let mut requester_group = MlsGroup::new_with_group_id(
        &provider,
        &requester_signer,
        &config,
        GroupId::from_slice(&group_id),
        CredentialWithKey {
            credential: BasicCredential::new(requester_credential).into(),
            signature_key: requester.signing_public_key().to_vec().into(),
        },
    )
    .map_err(|error| format!("create two-member Recovery MLS group: {error:?}"))?;
    let genesis_group_info = requester_group
        .export_group_info(provider.crypto(), &requester_signer, true)
        .map_err(|error| format!("export singleton Recovery GroupInfo: {error:?}"))?
        .tls_serialize_detached()
        .map_err(|error| format!("serialize singleton Recovery GroupInfo: {error:?}"))?;
    let genesis =
        public_state_from_group_info(&genesis_group_info, requester, conversation_id, 0, 0, at)?;
    let genesis_coordinate = genesis.coordinate();
    let acceptance_coordinate = PublicGroupSnapshotCoordinate::new(
        *genesis_coordinate.conversation_id(),
        genesis_coordinate.generation(),
        1,
        *genesis_coordinate.group_id(),
        genesis_coordinate.epoch(),
        *genesis_coordinate.group_context_hash(),
        *genesis_coordinate.confirmation_tag(),
        PublicGroupSnapshotLifecycle::Active,
    );
    let acceptance = rebind_active_snapshot(&genesis, acceptance_coordinate)
        .map_err(|error| format!("rebind Recovery acceptance public state: {error:?}"))?;
    let (
        fulfiller_package,
        fulfiller_key_package_ref,
        fulfiller_key_package_wrapper,
        fulfiller_key_package_init_key,
    ) = build_key_package_material(fulfiller, at, &provider, &fulfiller_signer)?;
    let add_aad = recovery_commit_aad(conversation_id, add_transition_id, acceptance.coordinate())?;
    requester_group.set_aad(add_aad.clone());
    let (add_commit, add_welcome, add_group_info) = requester_group
        .add_members(&provider, &requester_signer, &[fulfiller_package])
        .map_err(|error| format!("add fulfiller to Recovery MLS group: {error:?}"))?;
    let add_commit = add_commit
        .tls_serialize_detached()
        .map_err(|error| format!("serialize fulfiller Add recovery Commit: {error:?}"))?;
    let add_welcome = add_welcome
        .tls_serialize_detached()
        .map_err(|error| format!("serialize fulfiller Add recovery Welcome: {error:?}"))?;
    requester_group
        .merge_pending_commit(&provider)
        .map_err(|error| format!("merge fulfiller join Commit: {error:?}"))?;
    let add_group_info = add_group_info
        .ok_or_else(|| "ratchet-tree profile omitted Add successor GroupInfo".to_owned())?;
    let add_group_context = add_group_info
        .group_context()
        .tls_serialize_detached()
        .map_err(|error| format!("serialize Add successor GroupInfo context: {error:?}"))?;
    let add_coordinate =
        coordinate_from_merged_group(&requester_group, &add_group_context, conversation_id, 2)?;
    let add_verified = process_commit(
        &acceptance,
        &add_commit,
        &add_aad,
        add_coordinate,
        u64::try_from(at.timestamp())
            .map_err(|_| "negative Recovery Add commit fixture clock".to_owned())?,
        2,
    )
    .map_err(|error| format!("process genuine Recovery Add Commit: {error:?}"))?;
    if add_verified.removes().len() != 0
        || add_verified.adds().len() != 1
        || add_verified.adds()[0].key_package_ref() != &fulfiller_key_package_ref
    {
        return Err("genuine Recovery Add Commit has the wrong public effects".to_owned());
    }
    verify_recovery_welcome(
        &add_welcome,
        fulfiller_key_package_ref,
        MAX_WELCOME_WIRE_BYTES,
    )
    .map_err(|error| format!("verify genuine fulfiller Recovery Welcome: {error:?}"))?;
    let prior = add_verified.into_next();
    let join_message = MlsMessageIn::tls_deserialize_exact(&add_welcome)
        .map_err(|error| format!("parse fulfiller join Welcome: {error:?}"))?;
    let MlsMessageBodyIn::Welcome(join_welcome) = join_message.extract() else {
        return Err("fulfiller join artifact is not an MLS Welcome".to_owned());
    };
    let mut fulfiller_group = StagedWelcome::new_from_welcome(
        &provider,
        config.join_config(),
        join_welcome,
        Some(requester_group.export_ratchet_tree().into()),
    )
    .map_err(|error| format!("stage fulfiller Recovery Welcome: {error:?}"))?
    .into_group(&provider)
    .map_err(|error| format!("join fulfiller Recovery MLS group: {error:?}"))?;
    let (
        requester_recovery_package,
        requester_key_package_ref,
        requester_key_package_wrapper,
        requester_key_package_init_key,
    ) = build_key_package_material(requester, at, &provider, &requester_signer)?;
    let fulfillment_aad = recovery_commit_aad(
        conversation_id,
        fulfillment_transition_id,
        prior.coordinate(),
    )?;
    fulfiller_group.set_aad(fulfillment_aad.clone());
    // `swap_members` is OpenMLS's inline Remove+Add commit-builder path:
    // it never routes either proposal through the pending proposal store, so
    // the emitted Commit carries concrete proposals rather than proposal refs.
    let messages = fulfiller_group
        .swap_members(
            &provider,
            &fulfiller_signer,
            &[LeafNodeIndex::new(0)],
            &[requester_recovery_package],
        )
        .map_err(|error| format!("build inline Recovery remove/add Commit: {error:?}"))?;
    let commit = messages
        .commit
        .tls_serialize_detached()
        .map_err(|error| format!("serialize Recovery fulfillment Commit: {error:?}"))?;
    let welcome = messages
        .welcome
        .tls_serialize_detached()
        .map_err(|error| format!("serialize Recovery fulfillment Welcome: {error:?}"))?;
    let next_group_context = match messages
        .group_info
        .as_ref()
        .ok_or_else(|| "ratchet-tree profile omitted replacement successor GroupInfo".to_owned())?
        .body()
    {
        MlsMessageBodyOut::GroupInfo(group_info) => group_info
            .group_context()
            .tls_serialize_detached()
            .map_err(|error| {
                format!("serialize replacement successor GroupInfo context: {error:?}")
            })?,
        _ => return Err("replacement successor GroupInfo has the wrong MLS body".to_owned()),
    };
    fulfiller_group
        .merge_pending_commit(&provider)
        .map_err(|error| format!("merge Recovery fulfillment Commit: {error:?}"))?;
    let next_coordinate =
        coordinate_from_merged_group(&fulfiller_group, &next_group_context, conversation_id, 3)?;
    let fulfillment_verified = process_commit(
        &prior,
        &commit,
        &fulfillment_aad,
        next_coordinate,
        u64::try_from(at.timestamp())
            .map_err(|_| "negative Recovery replacement commit fixture clock".to_owned())?,
        2,
    )
    .map_err(|error| format!("process genuine Recovery replacement Commit: {error:?}"))?;
    if fulfillment_verified.removes().len() != 1
        || fulfillment_verified.adds().len() != 1
        || fulfillment_verified.adds()[0].key_package_ref() != &requester_key_package_ref
    {
        return Err("genuine Recovery replacement Commit has the wrong public effects".to_owned());
    }
    verify_recovery_welcome(&welcome, requester_key_package_ref, MAX_WELCOME_WIRE_BYTES)
        .map_err(|error| format!("verify genuine requester Recovery Welcome: {error:?}"))?;
    let next = fulfillment_verified.into_next();
    Ok(TwoMemberFulfillmentProducts {
        genesis_group_info,
        genesis,
        acceptance,
        prior,
        next,
        fulfiller_key_package_ref,
        fulfiller_key_package_wrapper,
        fulfiller_key_package_init_key,
        add_commit,
        add_welcome,
        requester_key_package_ref,
        requester_key_package_wrapper,
        requester_key_package_init_key,
        commit,
        welcome,
    })
}

fn exact_mls_capabilities() -> Capabilities {
    Capabilities::new(
        Some(&[ProtocolVersion::Mls10]),
        Some(&[XWING_CIPHERSUITE]),
        Some(&[]),
        Some(&[]),
        Some(&[CredentialType::Basic]),
    )
}

pub(super) fn coordinate_json(coordinate: &PublicGroupSnapshotCoordinate) -> Value {
    json!({
        "conversationId": Uuid::from_bytes(*coordinate.conversation_id()).hyphenated().to_string(),
        "generation": coordinate.generation(),
        "stateVersion": coordinate.state_version(),
        "groupId": STANDARD.encode(coordinate.group_id()),
        "epoch": coordinate.epoch(),
        "groupContextHash": STANDARD.encode(coordinate.group_context_hash()),
        "confirmationTag": STANDARD.encode(coordinate.confirmation_tag()),
        "lifecycle": "active",
    })
}

fn build_genesis_state(
    identity: &FixtureIdentity,
    conversation_id: Uuid,
    at: DateTime<Utc>,
) -> Result<(Vec<u8>, ActivePublicState), String> {
    let provider = openmls_libcrux_crypto::Provider::new()
        .map_err(|error| format!("create Recovery proof OpenMLS provider: {error:?}"))?;
    let signing_key = SignatureKeyPair::from_raw(
        XWING_CIPHERSUITE.signature_algorithm(),
        identity.signing_key.to_bytes().to_vec(),
        identity.signing_public_key().to_vec(),
    );
    signing_key
        .store(provider.storage())
        .map_err(|error| format!("store Recovery proof OpenMLS signer: {error:?}"))?;
    let credential = format!("{}#{}", identity.did, identity.device_id).into_bytes();
    let lifetime = Lifetime::init(
        u64::try_from((at - chrono::Duration::minutes(1)).timestamp())
            .map_err(|_| "negative fixture lifetime".to_owned())?,
        u64::try_from((at + chrono::Duration::hours(1)).timestamp())
            .map_err(|_| "negative fixture lifetime".to_owned())?,
    );
    let config = MlsGroupCreateConfig::builder()
        .ciphersuite(XWING_CIPHERSUITE)
        .wire_format_policy(openmls::group::PURE_PLAINTEXT_WIRE_FORMAT_POLICY)
        .use_ratchet_tree_extension(true)
        .capabilities(exact_mls_capabilities())
        .lifetime(lifetime)
        .build();
    let group_id: [u8; 32] = Sha256::digest(
        [
            b"CATBIRD-RECOVERY-PRODUCTION-PROOF-GENESIS\0".as_ref(),
            conversation_id.as_bytes(),
        ]
        .concat(),
    )
    .into();
    let group = MlsGroup::new_with_group_id(
        &provider,
        &signing_key,
        &config,
        GroupId::from_slice(&group_id),
        CredentialWithKey {
            credential: BasicCredential::new(credential.clone()).into(),
            signature_key: identity.signing_public_key().to_vec().into(),
        },
    )
    .map_err(|error| format!("create Recovery proof MLS group: {error:?}"))?;
    let group_info = group
        .export_group_info(provider.crypto(), &signing_key, true)
        .map_err(|error| format!("export Recovery proof GroupInfo: {error:?}"))?
        .tls_serialize_detached()
        .map_err(|error| format!("serialize Recovery proof GroupInfo: {error:?}"))?;
    let validated = validate_group_info(
        &group_info,
        GroupInfoValidationPolicy {
            expected_basic_credential: &credential,
            expected_signature_key: &identity.signing_public_key(),
            now_unix_seconds: u64::try_from(at.timestamp())
                .map_err(|_| "negative fixture clock".to_owned())?,
            max_bytes: MAX_GROUP_INFO_WIRE_BYTES,
            max_ratchet_tree_bytes: MAX_GROUP_INFO_WIRE_BYTES,
            max_members: 2,
        },
    )
    .map_err(|error| format!("validate Recovery proof GroupInfo: {error:?}"))?;
    let coordinate = PublicGroupSnapshotCoordinate::new(
        *conversation_id.as_bytes(),
        0,
        0,
        validated
            .group_id()
            .try_into()
            .map_err(|_| "Recovery proof group id is not 32 bytes".to_owned())?,
        validated.epoch(),
        *validated.group_context_hash(),
        *validated.confirmation_tag(),
        PublicGroupSnapshotLifecycle::Active,
    );
    let state = verify_genesis_group_info(
        &group_info,
        GenesisGroupInfoExpectations {
            coordinate,
            expected_basic_credential: &credential,
            expected_signature_key: &identity.signing_public_key(),
            now_unix_seconds: u64::try_from(at.timestamp())
                .map_err(|_| "negative fixture clock".to_owned())?,
            max_wire_bytes: MAX_GROUP_INFO_WIRE_BYTES,
            max_ratchet_tree_bytes: MAX_GROUP_INFO_WIRE_BYTES,
            max_members: 2,
        },
    )
    .map_err(|error| format!("construct Recovery proof public state: {error:?}"))?;
    Ok((group_info, state))
}

fn build_available_key_package(
    identity: &FixtureIdentity,
    at: DateTime<Utc>,
) -> Result<([u8; 32], Vec<u8>, Vec<u8>), String> {
    let provider = openmls_libcrux_crypto::Provider::new()
        .map_err(|error| format!("create Recovery proof KeyPackage provider: {error:?}"))?;
    let signer = SignatureKeyPair::from_raw(
        XWING_CIPHERSUITE.signature_algorithm(),
        identity.signing_key.to_bytes().to_vec(),
        identity.signing_public_key().to_vec(),
    );
    signer
        .store(provider.storage())
        .map_err(|error| format!("store Recovery proof KeyPackage signer: {error:?}"))?;
    let credential = format!("{}#{}", identity.did, identity.device_id).into_bytes();
    let lifetime = Lifetime::init(
        u64::try_from((at - chrono::Duration::minutes(1)).timestamp())
            .map_err(|_| "negative fixture lifetime".to_owned())?,
        u64::try_from((at + chrono::Duration::hours(1)).timestamp())
            .map_err(|_| "negative fixture lifetime".to_owned())?,
    );
    let package = KeyPackage::builder()
        .key_package_lifetime(lifetime)
        .leaf_node_capabilities(exact_mls_capabilities())
        .build(
            XWING_CIPHERSUITE,
            &provider,
            &signer,
            CredentialWithKey {
                credential: BasicCredential::new(credential.clone()).into(),
                signature_key: identity.signing_public_key().to_vec().into(),
            },
        )
        .map_err(|error| format!("build Recovery proof KeyPackage: {error:?}"))?
        .key_package()
        .clone();
    let wrapper = MlsMessageOut::from(package)
        .tls_serialize_detached()
        .map_err(|error| format!("serialize Recovery proof KeyPackage: {error:?}"))?;
    let validated = validate_key_package(
        &wrapper,
        KeyPackageValidationPolicy {
            expected_basic_credential: &credential,
            expected_signature_key: &identity.signing_public_key(),
            now_unix_seconds: u64::try_from(at.timestamp())
                .map_err(|_| "negative fixture clock".to_owned())?,
            max_bytes: MAX_KEY_PACKAGE_WIRE_BYTES,
        },
    )
    .map_err(|error| format!("validate Recovery proof KeyPackage: {error:?}"))?;
    Ok((
        *validated.key_package_ref(),
        wrapper,
        validated.init_key().to_vec(),
    ))
}

/// Seed the minimum real, immutable aggregate needed by a fresh client
/// `requestLeafRecovery` proof: creation provenance, active public state,
/// metadata provenance, actor membership/leaf, delivery interval, and one
/// production-validated available KeyPackage.  It intentionally does not open
/// a Recovery request; callers must obtain the real DPoP/repository authority
/// and take that path themselves.
pub(super) async fn seed_durable_recovery_fixture(
    pool: &PgPool,
    trusted_instant: &TrustedRequestInstant,
) -> Result<DurableRecoveryFixture, String> {
    let identity = FixtureIdentity::fresh(b"durable-recovery-fixture")?;
    seed_durable_recovery_fixture_for_identity(pool, trusted_instant, identity).await
}

/// The production-proof aggregate fixture for one caller-selected, genuine
/// cryptographic identity.  This seam controls only the fixture identity so a
/// pre-existing immutable relationship fallback can be used honestly; it does
/// not create relationship-policy rows, repository authorities, preludes, or
/// completion material.
pub(super) async fn seed_durable_recovery_fixture_for_identity(
    pool: &PgPool,
    trusted_instant: &TrustedRequestInstant,
    identity: FixtureIdentity,
) -> Result<DurableRecoveryFixture, String> {
    let conversation_id = Uuid::new_v4();
    let at = trusted_instant.datetime();
    let (group_info, state) = build_genesis_state(&identity, conversation_id, at)?;
    let prior = state.coordinate().clone();
    let creation = build_real_creation_entry(
        &identity,
        conversation_id,
        &prior,
        &group_info,
        trusted_instant.as_str(),
    )?;
    let (key_package_ref, key_package_wrapper, init_key) =
        build_available_key_package(&identity, at)?;
    seed_identity(pool, &identity, trusted_instant).await?;

    let verified =
        decode_and_verify_signed_mutation(&creation.raw_wrapper, &identity.signing_public_key())
            .map_err(|error| format!("verify durable fixture creation: {error:?}"))?;
    let control =
        decode_and_verify_control_entry(&creation.public_row_json, &identity.signing_public_key())
            .map_err(|error| format!("verify durable fixture creation control: {error:?}"))?;
    let basic_credential = format!("{}#{}", identity.did, identity.device_id).into_bytes();
    let (tree_summary, tree_summary_sha256) =
        encode_public_tree_summary(state.binding().tree_summary())
            .map_err(|error| format!("encode durable fixture public tree: {error:?}"))?
            .into_parts();
    let participant_period_id = Uuid::new_v4();
    let leaf_period_id = Uuid::new_v4();
    let metadata_snapshot_id = Uuid::new_v4();
    let metadata_ciphertext = vec![0x5a_u8; 16];
    let key_package_not_before = DateTime::<Utc>::from_timestamp(at.timestamp() - 60, 0)
        .ok_or_else(|| "Recovery KeyPackage not-before is out of range".to_owned())?;
    let key_package_not_after = DateTime::<Utc>::from_timestamp(at.timestamp() + 3_600, 0)
        .ok_or_else(|| "Recovery KeyPackage not-after is out of range".to_owned())?;
    let mut transaction = pool
        .begin()
        .await
        .map_err(|error| format!("begin durable fixture: {error}"))?;
    sqlx::query("INSERT INTO chat.conversations(conversation_id,kind,lifecycle,current_generation,current_state_version,next_entry_seq,created_at) VALUES($1,'group','active',0,0,2,$2)")
        .bind(conversation_id).bind(at).execute(&mut *transaction).await
        .map_err(|error| format!("insert durable fixture conversation: {error}"))?;
    sqlx::query("INSERT INTO chat.generations(conversation_id,generation,group_id,lifecycle,genesis_group_info_bytes,genesis_group_info_sha256,current_state_version,activated_seq,activated_at) VALUES($1,0,$2,'active',$3,$4,0,1,$5)")
        .bind(conversation_id).bind(prior.group_id()).bind(&group_info).bind(Sha256::digest(&group_info).to_vec()).bind(at)
        .execute(&mut *transaction).await.map_err(|error| format!("insert durable fixture generation: {error}"))?;
    sqlx::query(r#"INSERT INTO chat.transitions(transition_id,conversation_id,kind,actor_did,actor_device_id,actor_key_id,actor_auth_generation,actor_role,actor_device_status,signed_request_bytes,unsigned_projection_bytes,signing_transcript_bytes,request_digest,signature,next_generation,next_state_version,metadata_snapshot_id,entry_seq,accepted_at) VALUES($1,$2,'creation',$3,$4,$5,1,'admin','active',$6,$7,$8,$9,$10,0,0,$11,1,$12)"#)
        .bind(creation.transition_id).bind(conversation_id).bind(&identity.did).bind(identity.device_id).bind(&identity.key_id)
        .bind(&creation.raw_wrapper).bind(verified.canonical_projection()).bind(verified.transcript_bytes()).bind(verified.request_digest().to_vec()).bind(verified.signature().to_vec()).bind(metadata_snapshot_id).bind(at)
        .execute(&mut *transaction).await.map_err(|error| format!("insert durable fixture transition: {error}"))?;
    sqlx::query(r#"INSERT INTO chat.generation_states(conversation_id,generation,state_version,group_id,epoch,group_context_hash,confirmation_tag,lifecycle,state_kind,producing_transition_id,public_snapshot_bytes,snapshot_sha256,tree_summary_bytes,tree_summary_sha256,leaf_count,created_at) VALUES($1,0,0,$2,$3,$4,$5,'active','creation',$6,$7,$8,$9,$10,1,$11)"#)
        .bind(conversation_id).bind(prior.group_id()).bind(i64::try_from(prior.epoch()).map_err(|_| "epoch overflow".to_owned())?).bind(prior.group_context_hash()).bind(prior.confirmation_tag()).bind(creation.transition_id).bind(state.snapshot()).bind(state.snapshot_sha256()).bind(&tree_summary).bind(&tree_summary_sha256).bind(at)
        .execute(&mut *transaction).await.map_err(|error| format!("insert durable fixture state: {error}"))?;
    sqlx::query(r#"INSERT INTO chat.participants(participant_period_id,conversation_id,user_did,status,role,role_transition_id,role_changed_at,created_by_did,created_by_device_id,current_membership,created_at) VALUES($1,$2,$3,'active','admin',$4,$5,$3,$6,true,$5)"#)
        .bind(participant_period_id).bind(conversation_id).bind(&identity.did).bind(creation.transition_id).bind(at).bind(identity.device_id)
        .execute(&mut *transaction).await.map_err(|error| format!("insert durable fixture participant: {error}"))?;
    sqlx::query(r#"INSERT INTO chat.member_devices(leaf_period_id,participant_period_id,conversation_id,generation,user_did,device_id,leaf_index,basic_credential,leaf_signature_key,leaf_key_id,leaf_auth_generation,origin,joined_state_version,joined_transition_id,joined_seq,active,created_at) VALUES($1,$2,$3,0,$4,$5,0,$6,$7,$8,1,'genesis',0,$9,1,true,$10)"#)
        .bind(leaf_period_id).bind(participant_period_id).bind(conversation_id).bind(&identity.did).bind(identity.device_id).bind(&basic_credential).bind(identity.signing_public_key().to_vec()).bind(&identity.key_id).bind(creation.transition_id).bind(at)
        .execute(&mut *transaction).await.map_err(|error| format!("insert durable fixture leaf: {error}"))?;
    sqlx::query(r#"INSERT INTO chat.metadata_snapshots(metadata_snapshot_id,conversation_id,generation,state_version,group_id,epoch,group_context_hash,confirmation_tag,producing_transition_id,origin_transition_id,metadata_version,nonce,ciphertext,ciphertext_sha256,ciphertext_size,author_did,author_device_id,author_key_id,author_public_key,author_auth_generation,author_origin_seq,author_role,author_device_status,created_at) VALUES($1,$2,0,0,$3,$4,$5,$6,$7,$7,1,$8,$9,$10,16,$11,$12,$13,$14,1,1,'admin','active',$15)"#)
        .bind(metadata_snapshot_id).bind(conversation_id).bind(prior.group_id()).bind(i64::try_from(prior.epoch()).map_err(|_| "epoch overflow".to_owned())?).bind(prior.group_context_hash()).bind(prior.confirmation_tag()).bind(creation.transition_id).bind(vec![0x52_u8; 12]).bind(&metadata_ciphertext).bind(Sha256::digest(&metadata_ciphertext).to_vec()).bind(&identity.did).bind(identity.device_id).bind(&identity.key_id).bind(identity.signing_public_key().to_vec()).bind(at)
        .execute(&mut *transaction).await.map_err(|error| format!("insert durable fixture metadata: {error}"))?;
    sqlx::query(r#"INSERT INTO chat.entries(conversation_id,seq,entry_id,entry_kind,accepted_payload_bytes,accepted_payload_sha256,signed_request_bytes,request_digest,signature,server_fields_bytes,outer_entry_fingerprint,actor_did,actor_device_id,actor_key_id,actor_auth_generation,generation,state_version,transition_id,received_at) VALUES($1,1,$2,'blue.catbird.chat.defs#creationEntry',$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,1,0,0,$13,$14)"#)
        .bind(conversation_id).bind(creation.entry_id).bind(&creation.public_row_json).bind(Sha256::digest(&creation.public_row_json).to_vec()).bind(&creation.raw_wrapper).bind(verified.request_digest().to_vec()).bind(verified.signature().to_vec()).bind(control.server_fields_dag_cbor().map_err(|error| format!("encode durable fixture server fields: {error:?}"))?).bind(creation.outer_fingerprint.to_vec()).bind(&identity.did).bind(identity.device_id).bind(&identity.key_id).bind(creation.transition_id).bind(at)
        .execute(&mut *transaction).await.map_err(|error| format!("insert durable fixture entry: {error}"))?;
    sqlx::query("INSERT INTO chat.entry_recipients(conversation_id,seq,user_did,device_id,entitlement_kind) VALUES($1,1,$2,$3,'control')")
        .bind(conversation_id).bind(&identity.did).bind(identity.device_id).execute(&mut *transaction).await.map_err(|error| format!("insert durable fixture entry recipient: {error}"))?;
    sqlx::query(r#"INSERT INTO chat.application_intervals(membership_interval_id,conversation_id,generation,recipient_did,recipient_device_id,start_seq,opening_kind,opening_transition_id,opening_outer_entry_fingerprint,opening_state_version,opening_group_id,opening_epoch,opening_group_context_hash,opening_confirmation_tag,opening_leaf_period_id,created_at) VALUES($1,$2,0,$3,$4,1,'creation',$5,$6,0,$7,$8,$9,$10,$11,$12)"#)
        .bind(creation.transition_id).bind(conversation_id).bind(&identity.did).bind(identity.device_id).bind(creation.transition_id).bind(creation.outer_fingerprint.to_vec()).bind(prior.group_id()).bind(i64::try_from(prior.epoch()).map_err(|_| "epoch overflow".to_owned())?).bind(prior.group_context_hash()).bind(prior.confirmation_tag()).bind(leaf_period_id).bind(at)
        .execute(&mut *transaction).await.map_err(|error| format!("insert durable fixture interval: {error}"))?;
    sqlx::query(r#"INSERT INTO chat.key_packages(key_package_ref,wrapper_bytes,wrapper_sha256,init_key,owner_did,owner_device_id,owner_key_id,owner_auth_generation,not_before,not_after,status,created_at) VALUES($1,$2,$3,$4,$5,$6,$7,1,$8,$9,'available',$10)"#)
        .bind(key_package_ref.to_vec()).bind(&key_package_wrapper).bind(Sha256::digest(&key_package_wrapper).to_vec()).bind(init_key).bind(&identity.did).bind(identity.device_id).bind(&identity.key_id).bind(key_package_not_before).bind(key_package_not_after).bind(at)
        .execute(&mut *transaction).await.map_err(|error| format!("insert durable fixture KeyPackage: {error}"))?;
    transaction
        .commit()
        .await
        .map_err(|error| format!("commit durable Recovery fixture: {error}"))?;
    Ok(DurableRecoveryFixture {
        identity,
        conversation_id,
        creation_transition_id: creation.transition_id,
        prior,
        available_key_package_ref: key_package_ref,
        available_key_package_wrapper: key_package_wrapper,
    })
}

/// Seed the cryptographic and durable conversation prerequisites for the
/// recovery-fulfillment proof. The caller has already selected the fresh,
/// persisted two-party RecoveryReservation/RecoveryFulfillment fallback pair;
/// this helper deliberately neither manufactures nor copies relationship
/// evidence, and never constructs a relationship authority.
pub(super) async fn seed_durable_recovery_fulfillment_fixture_for_identities(
    pool: &PgPool,
    trusted_instant: &TrustedRequestInstant,
    requester: FixtureIdentity,
    fulfiller: FixtureIdentity,
    fulfillment_transition_id: Uuid,
) -> Result<DurableRecoveryFulfillmentFixture, String> {
    if requester.did == fulfiller.did {
        return Err("Recovery fulfillment fixture requires two distinct DIDs".to_owned());
    }
    let conversation_id = Uuid::new_v4();
    let at = trusted_instant.datetime();
    let add_transition_id = Uuid::new_v4();
    let products = build_two_member_fulfillment_products(
        &requester,
        &fulfiller,
        conversation_id,
        add_transition_id,
        fulfillment_transition_id,
        at,
    )?;
    let prior = products.prior.coordinate().clone();
    let creation = build_real_creation_entry_with_pending(
        &requester,
        &fulfiller,
        conversation_id,
        products.genesis.coordinate(),
        &products.genesis_group_info,
        trusted_instant.as_str(),
    )?;
    let acceptance = build_real_acceptance_entry(
        &requester,
        &fulfiller,
        conversation_id,
        creation.transition_id,
        products.genesis.coordinate(),
        products.acceptance.coordinate(),
        products.fulfiller_key_package_ref,
        &products.fulfiller_key_package_wrapper,
        at,
    )?;
    let add_fulfillment = build_real_add_fulfillment_entry(
        &requester,
        &fulfiller,
        &requester,
        conversation_id,
        creation.transition_id,
        acceptance.request_id,
        products.fulfiller_key_package_ref,
        products.acceptance.coordinate(),
        products.prior.coordinate(),
        add_transition_id,
        &products.add_commit,
        &products.add_welcome,
        at,
    )?;
    seed_identity(pool, &requester, trusted_instant).await?;
    seed_identity(pool, &fulfiller, trusted_instant).await?;
    let creation_verified =
        decode_and_verify_signed_mutation(&creation.raw_wrapper, &requester.signing_public_key())
            .map_err(|error| format!("verify singleton Recovery fixture creation: {error:?}"))?;
    let creation_control =
        decode_and_verify_control_entry(&creation.public_row_json, &requester.signing_public_key())
            .map_err(|error| format!("verify singleton Recovery fixture control: {error:?}"))?;
    let creation_wrapper: Value = serde_json::from_slice(&creation.raw_wrapper)
        .map_err(|error| format!("decode singleton Recovery creation metadata: {error}"))?;
    let creation_metadata = &creation_wrapper["body"]["metadataSnapshot"];
    let creation_nonce = STANDARD
        .decode(
            creation_metadata["nonce"]
                .as_str()
                .ok_or_else(|| "singleton Recovery creation nonce missing".to_owned())?,
        )
        .map_err(|error| format!("decode singleton Recovery creation nonce: {error}"))?;
    let creation_ciphertext = STANDARD
        .decode(
            creation_metadata["ciphertext"]
                .as_str()
                .ok_or_else(|| "singleton Recovery creation ciphertext missing".to_owned())?,
        )
        .map_err(|error| format!("decode singleton Recovery creation ciphertext: {error}"))?;
    let creation_metadata_version = creation_metadata["metadataVersion"]
        .as_u64()
        .ok_or_else(|| "singleton Recovery creation metadata version missing".to_owned())?;
    let requester_credential = format!("{}#{}", requester.did, requester.device_id).into_bytes();
    let fulfiller_credential = format!("{}#{}", fulfiller.did, fulfiller.device_id).into_bytes();
    let requester_genesis_leaf = products
        .genesis
        .binding()
        .tree_summary()
        .leaves()
        .iter()
        .find(|leaf| leaf.basic_credential() == requester_credential)
        .ok_or_else(|| "singleton Recovery genesis lacks requester leaf".to_owned())?;
    let fulfiller_added_leaf = products
        .prior
        .binding()
        .tree_summary()
        .leaves()
        .iter()
        .find(|leaf| leaf.basic_credential() == fulfiller_credential)
        .ok_or_else(|| "Recovery Add successor lacks fulfiller leaf".to_owned())?;
    if products.genesis.binding().tree_summary().leaves().len() != 1
        || products.acceptance.binding().tree_summary().leaves().len() != 1
        || products.prior.binding().tree_summary().leaves().len() != 2
        || products.genesis.coordinate().state_version() != 0
        || products.acceptance.coordinate().state_version() != 1
        || products.prior.coordinate().state_version() != 2
        || products.next.coordinate().state_version() != 3
        || products.genesis.coordinate().epoch() != 0
        || products.acceptance.coordinate().epoch() != 0
        || products.prior.coordinate().epoch() != 1
        || products.next.coordinate().epoch() != 2
    {
        return Err(
            "Recovery fulfillment fixture did not produce the exact singleton/accept/Add/swap history"
                .to_owned(),
        );
    }
    let requester_participant_period_id = Uuid::new_v4();
    let fulfiller_participant_period_id = Uuid::new_v4();
    let requester_leaf_period_id = Uuid::new_v4();
    let fulfiller_leaf_period_id = Uuid::new_v4();
    let creation_metadata_snapshot_id = Uuid::new_v4();
    let add_metadata_snapshot_id = Uuid::new_v4();
    // `Lifetime` is encoded in whole Unix seconds. Persist those exact values:
    // recovery hydration compares the durable timestamps to the validated
    // wrapper lifetime at millisecond precision.
    let key_package_not_before = DateTime::<Utc>::from_timestamp(at.timestamp() - 60, 0)
        .ok_or_else(|| "Recovery KeyPackage not-before is out of range".to_owned())?;
    let key_package_not_after = DateTime::<Utc>::from_timestamp(at.timestamp() + 3_600, 0)
        .ok_or_else(|| "Recovery KeyPackage not-after is out of range".to_owned())?;
    let mut transaction = pool
        .begin()
        .await
        .map_err(|error| format!("begin valid two-member Recovery history: {error}"))?;
    sqlx::query("INSERT INTO chat.conversations(conversation_id,kind,lifecycle,current_generation,current_state_version,next_entry_seq,created_at) VALUES($1,'group','active',0,2,4,$2)")
        .bind(conversation_id).bind(at).execute(&mut *transaction).await
        .map_err(|error| format!("insert valid Recovery conversation head: {error}"))?;
    sqlx::query("INSERT INTO chat.generations(conversation_id,generation,group_id,lifecycle,genesis_group_info_bytes,genesis_group_info_sha256,current_state_version,activated_seq,activated_at) VALUES($1,0,$2,'active',$3,$4,2,1,$5)")
        .bind(conversation_id).bind(products.genesis.coordinate().group_id()).bind(&products.genesis_group_info).bind(Sha256::digest(&products.genesis_group_info).to_vec()).bind(at)
        .execute(&mut *transaction).await.map_err(|error| format!("insert singleton Recovery generation: {error}"))?;
    sqlx::query(r#"INSERT INTO chat.transitions(transition_id,conversation_id,kind,actor_did,actor_device_id,actor_key_id,actor_auth_generation,actor_role,actor_device_status,signed_request_bytes,unsigned_projection_bytes,signing_transcript_bytes,request_digest,signature,next_generation,next_state_version,metadata_snapshot_id,entry_seq,accepted_at) VALUES($1,$2,'creation',$3,$4,$5,1,'admin','active',$6,$7,$8,$9,$10,0,0,$11,1,$12)"#)
        .bind(creation.transition_id).bind(conversation_id).bind(&requester.did).bind(requester.device_id).bind(&requester.key_id)
        .bind(&creation.raw_wrapper).bind(creation_verified.canonical_projection()).bind(creation_verified.transcript_bytes()).bind(creation_verified.request_digest().to_vec()).bind(creation_verified.signature().to_vec()).bind(creation_metadata_snapshot_id).bind(at)
        .execute(&mut *transaction).await.map_err(|error| format!("insert singleton Recovery creation transition: {error}"))?;
    sqlx::query(r#"INSERT INTO chat.transitions(transition_id,conversation_id,kind,actor_did,actor_device_id,actor_key_id,actor_auth_generation,actor_role,actor_device_status,signed_request_bytes,unsigned_projection_bytes,signing_transcript_bytes,request_digest,signature,prior_generation,prior_state_version,next_generation,next_state_version,entry_seq,accepted_at) VALUES($1,$2,'acceptConversation',$3,$4,$5,1,'member','active',$6,$7,$8,$9,$10,0,0,0,1,2,$11)"#)
        .bind(acceptance.transition_id).bind(conversation_id).bind(&fulfiller.did).bind(fulfiller.device_id).bind(&fulfiller.key_id)
        .bind(&acceptance.raw_wrapper).bind(&acceptance.canonical_projection).bind(&acceptance.signing_transcript).bind(&acceptance.request_digest).bind(&acceptance.signature).bind(at)
        .execute(&mut *transaction).await.map_err(|error| format!("insert genuine Recovery acceptance transition: {error}"))?;
    sqlx::query(r#"INSERT INTO chat.transitions(transition_id,conversation_id,kind,actor_did,actor_device_id,actor_key_id,actor_auth_generation,actor_role,actor_device_status,signed_request_bytes,unsigned_projection_bytes,signing_transcript_bytes,request_digest,signature,prior_generation,prior_state_version,next_generation,next_state_version,metadata_snapshot_id,entry_seq,accepted_at) VALUES($1,$2,'leafRecovery',$3,$4,$5,1,'admin','active',$6,$7,$8,$9,$10,0,1,0,2,$11,3,$12)"#)
        .bind(add_fulfillment.transition_id).bind(conversation_id).bind(&requester.did).bind(requester.device_id).bind(&requester.key_id)
        .bind(&add_fulfillment.raw_wrapper).bind(&add_fulfillment.canonical_projection).bind(&add_fulfillment.signing_transcript).bind(&add_fulfillment.request_digest).bind(&add_fulfillment.signature).bind(add_metadata_snapshot_id).bind(at)
        .execute(&mut *transaction).await.map_err(|error| format!("insert genuine Add Recovery transition: {error}"))?;
    for (state, state_kind, producer) in [
        (&products.genesis, "creation", creation.transition_id),
        (
            &products.acceptance,
            "acceptConversation",
            acceptance.transition_id,
        ),
        (&products.prior, "commit", add_fulfillment.transition_id),
    ] {
        let (tree_summary, tree_summary_sha256) =
            encode_public_tree_summary(state.binding().tree_summary())
                .map_err(|error| format!("encode valid Recovery public tree: {error:?}"))?
                .into_parts();
        let coordinate = state.coordinate();
        sqlx::query(r#"INSERT INTO chat.generation_states(conversation_id,generation,state_version,group_id,epoch,group_context_hash,confirmation_tag,lifecycle,state_kind,producing_transition_id,public_snapshot_bytes,snapshot_sha256,tree_summary_bytes,tree_summary_sha256,leaf_count,created_at) VALUES($1,0,$2,$3,$4,$5,$6,'active',$7,$8,$9,$10,$11,$12,$13,$14)"#)
            .bind(conversation_id)
            .bind(i64::try_from(coordinate.state_version()).map_err(|_| "Recovery state version overflow".to_owned())?)
            .bind(coordinate.group_id())
            .bind(i64::try_from(coordinate.epoch()).map_err(|_| "Recovery epoch overflow".to_owned())?)
            .bind(coordinate.group_context_hash())
            .bind(coordinate.confirmation_tag())
            .bind(state_kind)
            .bind(producer)
            .bind(state.snapshot())
            .bind(state.snapshot_sha256())
            .bind(&tree_summary)
            .bind(&tree_summary_sha256)
            .bind(i64::try_from(state.binding().tree_summary().leaves().len()).map_err(|_| "Recovery leaf count overflow".to_owned())?)
            .bind(at)
            .execute(&mut *transaction).await
            .map_err(|error| format!("insert valid Recovery state {state_kind}: {error}"))?;
    }
    sqlx::query(r#"INSERT INTO chat.participants(participant_period_id,conversation_id,user_did,status,role,role_transition_id,role_changed_at,created_by_did,created_by_device_id,current_membership,created_at) VALUES($1,$2,$3,'active',$4,$5,$6,$7,$8,true,$6)"#)
        .bind(requester_participant_period_id).bind(conversation_id).bind(&requester.did).bind("admin").bind(creation.transition_id).bind(at).bind(&requester.did).bind(requester.device_id)
        .execute(&mut *transaction).await.map_err(|error| format!("insert Recovery requester participant: {error}"))?;
    sqlx::query(r#"INSERT INTO chat.participants(participant_period_id,conversation_id,user_did,status,role,role_transition_id,role_changed_at,created_by_did,created_by_device_id,invitation_transition_id,invitation_entry_id,invited_at,acceptance_transition_id,acceptance_entry_id,accepted_at,current_membership,created_at) VALUES($1,$2,$3,'active','member',$4,$5,$6,$7,$4,$8,$5,$9,$10,$5,true,$5)"#)
        .bind(fulfiller_participant_period_id).bind(conversation_id).bind(&fulfiller.did).bind(creation.transition_id).bind(at).bind(&requester.did).bind(requester.device_id).bind(creation.entry_id).bind(acceptance.transition_id).bind(acceptance.entry_id)
        .execute(&mut *transaction).await.map_err(|error| format!("insert Recovery fulfiller participant: {error}"))?;
    sqlx::query(r#"INSERT INTO chat.member_devices(leaf_period_id,participant_period_id,conversation_id,generation,user_did,device_id,leaf_index,basic_credential,leaf_signature_key,leaf_key_id,leaf_auth_generation,origin,joined_state_version,joined_transition_id,joined_seq,active,created_at) VALUES($1,$2,$3,0,$4,$5,$6,$7,$8,$9,1,'genesis',0,$10,1,true,$11)"#)
        .bind(requester_leaf_period_id).bind(requester_participant_period_id).bind(conversation_id).bind(&requester.did).bind(requester.device_id).bind(i64::from(requester_genesis_leaf.leaf_index())).bind(requester_genesis_leaf.basic_credential()).bind(requester_genesis_leaf.signature_key()).bind(&requester.key_id).bind(creation.transition_id).bind(at)
        .execute(&mut *transaction).await.map_err(|error| format!("insert Recovery requester leaf: {error}"))?;
    sqlx::query(r#"INSERT INTO chat.member_devices(leaf_period_id,participant_period_id,conversation_id,generation,user_did,device_id,leaf_index,basic_credential,leaf_signature_key,leaf_key_id,leaf_auth_generation,origin,join_key_package_ref,joined_state_version,joined_transition_id,joined_seq,active,created_at) VALUES($1,$2,$3,0,$4,$5,$6,$7,$8,$9,1,'keyPackage',$10,2,$11,3,true,$12)"#)
        .bind(fulfiller_leaf_period_id).bind(fulfiller_participant_period_id).bind(conversation_id).bind(&fulfiller.did).bind(fulfiller.device_id).bind(i64::from(fulfiller_added_leaf.leaf_index())).bind(fulfiller_added_leaf.basic_credential()).bind(fulfiller_added_leaf.signature_key()).bind(&fulfiller.key_id).bind(products.fulfiller_key_package_ref.to_vec()).bind(add_fulfillment.transition_id).bind(at)
        .execute(&mut *transaction).await.map_err(|error| format!("insert Recovery fulfiller leaf: {error}"))?;
    sqlx::query(r#"INSERT INTO chat.metadata_snapshots(metadata_snapshot_id,conversation_id,generation,state_version,group_id,epoch,group_context_hash,confirmation_tag,producing_transition_id,origin_transition_id,metadata_version,nonce,ciphertext,ciphertext_sha256,ciphertext_size,author_did,author_device_id,author_key_id,author_public_key,author_auth_generation,author_origin_seq,author_role,author_device_status,created_at) VALUES($1,$2,0,0,$3,$4,$5,$6,$7,$7,1,$8,$9,$10,16,$11,$12,$13,$14,1,1,'admin','active',$15)"#)
        .bind(creation_metadata_snapshot_id).bind(conversation_id).bind(products.genesis.coordinate().group_id()).bind(i64::try_from(products.genesis.coordinate().epoch()).map_err(|_| "singleton Recovery epoch overflow".to_owned())?).bind(products.genesis.coordinate().group_context_hash()).bind(products.genesis.coordinate().confirmation_tag()).bind(creation.transition_id).bind(&creation_nonce).bind(&creation_ciphertext).bind(Sha256::digest(&creation_ciphertext).to_vec()).bind(&requester.did).bind(requester.device_id).bind(&requester.key_id).bind(requester.signing_public_key().to_vec()).bind(at)
        .execute(&mut *transaction).await.map_err(|error| format!("insert singleton Recovery metadata: {error}"))?;
    if creation_metadata_version != 1 || creation_ciphertext.len() != 16 {
        return Err("singleton Recovery creation metadata is not the frozen v1 shape".to_owned());
    }
    sqlx::query(r#"INSERT INTO chat.metadata_snapshots(metadata_snapshot_id,conversation_id,generation,state_version,group_id,epoch,group_context_hash,confirmation_tag,producing_transition_id,origin_transition_id,metadata_version,nonce,ciphertext,ciphertext_sha256,ciphertext_size,author_did,author_device_id,author_key_id,author_public_key,author_auth_generation,author_origin_seq,author_role,author_device_status,created_at) VALUES($1,$2,0,2,$3,$4,$5,$6,$7,$8,1,$9,$10,$11,16,$12,$13,$14,$15,1,1,'admin','active',$16)"#)
        .bind(add_metadata_snapshot_id).bind(conversation_id).bind(products.prior.coordinate().group_id()).bind(i64::try_from(products.prior.coordinate().epoch()).map_err(|_| "Add Recovery epoch overflow".to_owned())?).bind(products.prior.coordinate().group_context_hash()).bind(products.prior.coordinate().confirmation_tag()).bind(add_fulfillment.transition_id).bind(creation.transition_id).bind(&add_fulfillment.metadata_nonce).bind(&add_fulfillment.metadata_ciphertext).bind(Sha256::digest(&add_fulfillment.metadata_ciphertext).to_vec()).bind(&requester.did).bind(requester.device_id).bind(&requester.key_id).bind(requester.signing_public_key().to_vec()).bind(at)
        .execute(&mut *transaction).await.map_err(|error| format!("insert Add Recovery metadata: {error}"))?;
    sqlx::query(r#"INSERT INTO chat.entries(conversation_id,seq,entry_id,entry_kind,accepted_payload_bytes,accepted_payload_sha256,signed_request_bytes,request_digest,signature,server_fields_bytes,outer_entry_fingerprint,actor_did,actor_device_id,actor_key_id,actor_auth_generation,generation,state_version,transition_id,received_at) VALUES($1,1,$2,'blue.catbird.chat.defs#creationEntry',$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,1,0,0,$13,$14)"#)
        .bind(conversation_id).bind(creation.entry_id).bind(&creation.public_row_json).bind(Sha256::digest(&creation.public_row_json).to_vec()).bind(&creation.raw_wrapper).bind(creation_verified.request_digest().to_vec()).bind(creation_verified.signature().to_vec()).bind(creation_control.server_fields_dag_cbor().map_err(|error| format!("encode singleton Recovery server fields: {error:?}"))?).bind(creation.outer_fingerprint.to_vec()).bind(&requester.did).bind(requester.device_id).bind(&requester.key_id).bind(creation.transition_id).bind(at)
        .execute(&mut *transaction).await.map_err(|error| format!("insert singleton Recovery entry: {error}"))?;
    sqlx::query(r#"INSERT INTO chat.entries(conversation_id,seq,entry_id,entry_kind,accepted_payload_bytes,accepted_payload_sha256,signed_request_bytes,request_digest,signature,server_fields_bytes,outer_entry_fingerprint,actor_did,actor_device_id,actor_key_id,actor_auth_generation,generation,state_version,transition_id,received_at) VALUES($1,2,$2,'blue.catbird.chat.defs#participantAcceptanceEntry',$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,1,0,1,$13,$14)"#)
        .bind(conversation_id).bind(acceptance.entry_id).bind(&acceptance.public_row_json).bind(Sha256::digest(&acceptance.public_row_json).to_vec()).bind(&acceptance.raw_wrapper).bind(&acceptance.request_digest).bind(&acceptance.signature).bind(&acceptance.server_fields).bind(acceptance.outer_fingerprint.to_vec()).bind(&fulfiller.did).bind(fulfiller.device_id).bind(&fulfiller.key_id).bind(acceptance.transition_id).bind(at)
        .execute(&mut *transaction).await.map_err(|error| format!("insert genuine Recovery acceptance entry: {error}"))?;
    sqlx::query(r#"INSERT INTO chat.entries(conversation_id,seq,entry_id,entry_kind,accepted_payload_bytes,accepted_payload_sha256,signed_request_bytes,request_digest,signature,server_fields_bytes,outer_entry_fingerprint,actor_did,actor_device_id,actor_key_id,actor_auth_generation,generation,state_version,transition_id,received_at) VALUES($1,3,$2,'blue.catbird.chat.defs#leafRecoveryFulfillmentEntry',$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,1,0,2,$13,$14)"#)
        .bind(conversation_id).bind(add_fulfillment.entry_id).bind(&add_fulfillment.public_row_json).bind(Sha256::digest(&add_fulfillment.public_row_json).to_vec()).bind(&add_fulfillment.raw_wrapper).bind(&add_fulfillment.request_digest).bind(&add_fulfillment.signature).bind(&add_fulfillment.server_fields).bind(add_fulfillment.outer_fingerprint.to_vec()).bind(&requester.did).bind(requester.device_id).bind(&requester.key_id).bind(add_fulfillment.transition_id).bind(at)
        .execute(&mut *transaction).await.map_err(|error| format!("insert genuine Add Recovery entry: {error}"))?;
    for seq in 1_i64..=3_i64 {
        for identity in [&requester, &fulfiller] {
            sqlx::query("INSERT INTO chat.entry_recipients(conversation_id,seq,user_did,device_id,entitlement_kind) VALUES($1,$2,$3,$4,'control')")
                .bind(conversation_id).bind(seq).bind(&identity.did).bind(identity.device_id).execute(&mut *transaction).await
                .map_err(|error| format!("insert valid Recovery entry recipient: {error}"))?;
        }
    }
    sqlx::query(r#"INSERT INTO chat.application_intervals(membership_interval_id,conversation_id,generation,recipient_did,recipient_device_id,start_seq,opening_kind,opening_transition_id,opening_outer_entry_fingerprint,opening_state_version,opening_group_id,opening_epoch,opening_group_context_hash,opening_confirmation_tag,opening_leaf_period_id,created_at) VALUES($1,$2,0,$3,$4,1,'creation',$5,$6,0,$7,$8,$9,$10,$11,$12)"#)
        .bind(creation.transition_id).bind(conversation_id).bind(&requester.did).bind(requester.device_id).bind(creation.transition_id).bind(creation.outer_fingerprint.to_vec()).bind(products.genesis.coordinate().group_id()).bind(i64::try_from(products.genesis.coordinate().epoch()).map_err(|_| "singleton Recovery epoch overflow".to_owned())?).bind(products.genesis.coordinate().group_context_hash()).bind(products.genesis.coordinate().confirmation_tag()).bind(requester_leaf_period_id).bind(at)
        .execute(&mut *transaction).await.map_err(|error| format!("insert requester creation interval: {error}"))?;
    sqlx::query(r#"INSERT INTO chat.application_intervals(membership_interval_id,conversation_id,generation,recipient_did,recipient_device_id,start_seq,opening_kind,opening_transition_id,opening_outer_entry_fingerprint,opening_state_version,opening_group_id,opening_epoch,opening_group_context_hash,opening_confirmation_tag,opening_leaf_period_id,created_at) VALUES($1,$2,0,$3,$4,3,'add',$5,$6,2,$7,$8,$9,$10,$11,$12)"#)
        .bind(add_fulfillment.transition_id).bind(conversation_id).bind(&fulfiller.did).bind(fulfiller.device_id).bind(add_fulfillment.transition_id).bind(add_fulfillment.outer_fingerprint.to_vec()).bind(products.prior.coordinate().group_id()).bind(i64::try_from(products.prior.coordinate().epoch()).map_err(|_| "Add Recovery epoch overflow".to_owned())?).bind(products.prior.coordinate().group_context_hash()).bind(products.prior.coordinate().confirmation_tag()).bind(fulfiller_leaf_period_id).bind(at)
        .execute(&mut *transaction).await.map_err(|error| format!("insert fulfiller Add interval: {error}"))?;
    sqlx::query(r#"INSERT INTO chat.key_packages(key_package_ref,wrapper_bytes,wrapper_sha256,init_key,owner_did,owner_device_id,owner_key_id,owner_auth_generation,not_before,not_after,status,terminal_transition_id,terminal_at,created_at) VALUES($1,$2,$3,$4,$5,$6,$7,1,$8,$9,'consumed',$10,$11,$11)"#)
        .bind(products.fulfiller_key_package_ref.to_vec()).bind(&products.fulfiller_key_package_wrapper).bind(Sha256::digest(&products.fulfiller_key_package_wrapper).to_vec()).bind(&products.fulfiller_key_package_init_key).bind(&fulfiller.did).bind(fulfiller.device_id).bind(&fulfiller.key_id).bind(key_package_not_before).bind(key_package_not_after).bind(add_fulfillment.transition_id).bind(at)
        .execute(&mut *transaction).await.map_err(|error| format!("insert consumed fulfiller Recovery KeyPackage: {error}"))?;
    sqlx::query(r#"INSERT INTO chat.key_packages(key_package_ref,wrapper_bytes,wrapper_sha256,init_key,owner_did,owner_device_id,owner_key_id,owner_auth_generation,not_before,not_after,status,created_at) VALUES($1,$2,$3,$4,$5,$6,$7,1,$8,$9,'available',$10)"#)
        .bind(products.requester_key_package_ref.to_vec()).bind(&products.requester_key_package_wrapper).bind(Sha256::digest(&products.requester_key_package_wrapper).to_vec()).bind(&products.requester_key_package_init_key).bind(&requester.did).bind(requester.device_id).bind(&requester.key_id).bind(key_package_not_before).bind(key_package_not_after).bind(at)
        .execute(&mut *transaction).await.map_err(|error| format!("insert fresh requester Recovery KeyPackage: {error}"))?;
    sqlx::query(r#"INSERT INTO chat.key_package_reservations(recovery_request_id,key_package_ref,conversation_id,generation,requester_did,requester_device_id,requester_key_id,requester_auth_generation,recipient_did,recipient_device_id,bound_state_version,bound_group_id,bound_epoch,bound_group_context_hash,bound_confirmation_tag,purpose,expires_at,status,consumed_transition_id,terminal_at,created_at) VALUES($1,$2,$3,0,$4,$5,$6,1,$4,$5,1,$7,$8,$9,$10,'leafRecovery',$11,'consumed',$12,$13,$13)"#)
        .bind(acceptance.request_id).bind(products.fulfiller_key_package_ref.to_vec()).bind(conversation_id).bind(&fulfiller.did).bind(fulfiller.device_id).bind(&fulfiller.key_id).bind(products.acceptance.coordinate().group_id()).bind(i64::try_from(products.acceptance.coordinate().epoch()).map_err(|_| "acceptance epoch overflow".to_owned())?).bind(products.acceptance.coordinate().group_context_hash()).bind(products.acceptance.coordinate().confirmation_tag()).bind(acceptance.expires_at).bind(add_fulfillment.transition_id).bind(at)
        .execute(&mut *transaction).await.map_err(|error| format!("insert consumed acceptance reservation: {error}"))?;
    sqlx::query(r#"INSERT INTO chat.leaf_recovery_requests(recovery_request_id,conversation_id,generation,requester_did,requester_device_id,requester_key_id,requester_auth_generation,recovery_kind,source,bound_state_version,bound_group_id,bound_epoch,bound_group_context_hash,bound_confirmation_tag,reservation_request_id,status,signed_request_bytes,signing_transcript_bytes,request_digest,signature,requested_at,expires_at,fulfilling_transition_id,terminal_at) VALUES($1,$2,0,$3,$4,$5,1,'add','acceptConversation',1,$6,$7,$8,$9,$1,'fulfilled',$10,$11,$12,$13,$14,$15,$16,$14)"#)
        .bind(acceptance.request_id).bind(conversation_id).bind(&fulfiller.did).bind(fulfiller.device_id).bind(&fulfiller.key_id).bind(products.acceptance.coordinate().group_id()).bind(i64::try_from(products.acceptance.coordinate().epoch()).map_err(|_| "acceptance epoch overflow".to_owned())?).bind(products.acceptance.coordinate().group_context_hash()).bind(products.acceptance.coordinate().confirmation_tag()).bind(&acceptance.raw_wrapper).bind(&acceptance.signing_transcript).bind(&acceptance.request_digest).bind(&acceptance.signature).bind(at).bind(acceptance.expires_at).bind(add_fulfillment.transition_id)
        .execute(&mut *transaction).await.map_err(|error| format!("insert fulfilled acceptance Recovery request: {error}"))?;
    sqlx::query(r#"INSERT INTO chat.welcome_bundles(welcome_id,conversation_id,transition_id,entry_seq,generation,state_version,group_id,epoch,group_context_hash,confirmation_tag,wrapper_bytes,wrapper_sha256,created_at) VALUES($1,$2,$3,3,0,2,$4,$5,$6,$7,$8,$9,$10)"#)
        .bind(add_fulfillment.welcome_id).bind(conversation_id).bind(add_fulfillment.transition_id).bind(products.prior.coordinate().group_id()).bind(i64::try_from(products.prior.coordinate().epoch()).map_err(|_| "Add Recovery epoch overflow".to_owned())?).bind(products.prior.coordinate().group_context_hash()).bind(products.prior.coordinate().confirmation_tag()).bind(&products.add_welcome).bind(Sha256::digest(&products.add_welcome).to_vec()).bind(at)
        .execute(&mut *transaction).await.map_err(|error| format!("insert genuine Add Recovery Welcome: {error}"))?;
    sqlx::query(r#"INSERT INTO chat.welcome_deliveries(welcome_id,recipient_did,recipient_device_id,recovery_request_id,key_package_ref,expires_at,status) VALUES($1,$2,$3,$4,$5,$6,'pending')"#)
        .bind(add_fulfillment.welcome_id).bind(&fulfiller.did).bind(fulfiller.device_id).bind(acceptance.request_id).bind(products.fulfiller_key_package_ref.to_vec()).bind(key_package_not_after)
        .execute(&mut *transaction).await.map_err(|error| format!("insert genuine Add Recovery Welcome delivery: {error}"))?;
    transaction
        .commit()
        .await
        .map_err(|error| format!("commit valid two-member Recovery history: {error}"))?;
    Ok(DurableRecoveryFulfillmentFixture {
        requester,
        fulfiller,
        conversation_id,
        creation_transition_id: creation.transition_id,
        prior,
        next: products.next,
        requester_key_package_ref: products.requester_key_package_ref,
        requester_key_package_wrapper: products.requester_key_package_wrapper,
        commit: products.commit,
        welcome: products.welcome,
    })
}

/// One fresh, real cryptographic identity.  Database setup is intentionally
/// separate: runners seed this exact public tuple in the gate DB before asking
/// `authorize` to consume replay evidence.
pub(super) struct FixtureIdentity {
    pub(super) did: String,
    pub(super) device_id: Uuid,
    pub(super) key_id: String,
    pub(super) signing_key: Ed25519SigningKey,
    proof_signing_key: P256SigningKey,
    proof_jwk: Value,
    proof_jkt: String,
}

pub(super) struct SignedRecoveryEnvelope {
    pub(super) operation_id: Uuid,
    pub(super) raw_wrapper: Vec<u8>,
    pub(super) request_digest: [u8; 32],
    pub(super) signing_transcript: Vec<u8>,
    pub(super) signature: [u8; 64],
}

impl FixtureIdentity {
    pub(super) fn fresh(label: &[u8]) -> Result<Self, String> {
        let device_id = Uuid::new_v4();
        let seed: [u8; 32] = Sha256::digest(
            [
                b"CATBIRD-RECOVERY-PRODUCTION-PROOF-ED25519\0".as_ref(),
                label,
                device_id.as_bytes(),
            ]
            .concat(),
        )
        .into();
        let signing_key = Ed25519SigningKey::from_bytes(&seed);
        let public_key = signing_key.verifying_key().to_bytes();
        let key_id = ed25519_key_id(&public_key)
            .map_err(|error| format!("derive Recovery fixture key id: {error:?}"))?
            .as_str()
            .to_owned();

        let suffix = Sha256::digest(
            [
                b"CATBIRD-RECOVERY-PROOF-DID\0".as_ref(),
                label,
                device_id.as_bytes(),
            ]
            .concat(),
        );
        const ALPHABET: &[u8] = b"abcdefghijklmnopqrstuvwxyz234567";
        let did_suffix: String = suffix
            .iter()
            .take(24)
            .map(|byte| ALPHABET[usize::from(*byte & 31)] as char)
            .collect();

        Self::fresh_with_did(
            format!("did:plc:{did_suffix}"),
            label,
            device_id,
            signing_key,
            key_id,
        )
    }

    /// Bind a fresh device/key to a caller-selected canonical DID. This lets a
    /// gate runner use the DID set of an already-hardened persisted fallback
    /// projection without manufacturing any relationship authority.
    pub(super) fn fresh_for_did(did: &str, label: &[u8]) -> Result<Self, String> {
        crate::chat_protocol::validation::BareDid::parse(did)
            .map_err(|error| format!("parse Recovery fixture DID: {error:?}"))?;
        let device_id = Uuid::new_v4();
        let seed: [u8; 32] = Sha256::digest(
            [
                b"CATBIRD-RECOVERY-PRODUCTION-PROOF-EXTERNAL-DID\0".as_ref(),
                label,
                device_id.as_bytes(),
            ]
            .concat(),
        )
        .into();
        let signing_key = Ed25519SigningKey::from_bytes(&seed);
        let key_id = ed25519_key_id(&signing_key.verifying_key().to_bytes())
            .map_err(|error| format!("derive Recovery fixture key id: {error:?}"))?
            .as_str()
            .to_owned();
        Self::fresh_with_did(did.to_owned(), label, device_id, signing_key, key_id)
    }

    fn fresh_with_did(
        did: String,
        label: &[u8],
        device_id: Uuid,
        signing_key: Ed25519SigningKey,
        key_id: String,
    ) -> Result<Self, String> {
        let proof_signing_key = fresh_p256(label, device_id)?;
        let proof_jwk = public_jwk(&proof_signing_key);
        let proof_jkt = jwk_thumbprint(&proof_jwk)?;
        Ok(Self {
            did,
            device_id,
            key_id,
            signing_key,
            proof_signing_key,
            proof_jwk,
            proof_jkt,
        })
    }

    pub(super) fn signing_public_key(&self) -> [u8; 32] {
        self.signing_key.verifying_key().to_bytes()
    }

    pub(super) fn dpop_jkt(&self) -> &str {
        &self.proof_jkt
    }
}

/// Seed the exact device/key tuple consumed by the real repository authorizer.
/// This is test-fixture setup only; it does not create any repository authority.
pub(super) async fn seed_identity(
    pool: &PgPool,
    identity: &FixtureIdentity,
    at: &TrustedRequestInstant,
) -> Result<(), String> {
    sqlx::query(
        "INSERT INTO chat.principals(user_did,created_at) VALUES($1,$2) \
         ON CONFLICT (user_did) DO NOTHING",
    )
    .bind(&identity.did)
    .bind(at.datetime())
    .execute(pool)
    .await
    .map_err(|error| format!("seed Recovery proof principal: {error}"))?;
    sqlx::query(
        "INSERT INTO chat.devices(\
             user_did,device_id,device_name,status,dpop_jkt,auth_generation,\
             capabilities,created_at,updated_at)\
         VALUES($1,$2,'recovery-production-proof','active',$3,1,\
                chat.protocol_capabilities(),$4,$4)",
    )
    .bind(&identity.did)
    .bind(identity.device_id)
    .bind(&identity.proof_jkt)
    .bind(at.datetime())
    .execute(pool)
    .await
    .map_err(|error| format!("seed Recovery proof device: {error}"))?;
    sqlx::query(
        "INSERT INTO chat.device_keys(\
             user_did,device_id,key_id,signing_public_key,enrollment_auth_generation,created_at)\
         VALUES($1,$2,$3,$4,1,$5)",
    )
    .bind(&identity.did)
    .bind(identity.device_id)
    .bind(&identity.key_id)
    .bind(identity.signing_public_key().as_slice())
    .bind(at.datetime())
    .execute(pool)
    .await
    .map_err(|error| format!("seed Recovery proof device key: {error}"))?;
    Ok(())
}

/// Build an ordinary Nest JWT and DPoP proof, validate them with the actual
/// verifier, decode the exact canonical signed mutation, then have the real
/// authorizer consume both replay identities and lock the stored device/key.
pub(super) async fn authorize(
    pool: &PgPool,
    identity: &FixtureIdentity,
    endpoint_text: &str,
    envelope: &SignedRecoveryEnvelope,
    trusted_instant: &TrustedRequestInstant,
) -> Result<VerifiedChatDeviceRequest, String> {
    let endpoint = ValidatedChatNsid::parse(endpoint_text)
        .map_err(|error| format!("parse Recovery proof endpoint: {error:?}"))?;
    let method = endpoint
        .dpop_method()
        .map_err(|error| format!("derive Recovery proof endpoint method: {error:?}"))?;
    let nest_key = fresh_p256(b"nest", identity.device_id)?;
    let external_base = TrustedExternalBase::parse(EXTERNAL_BASE, &BTreeSet::new())
        .map_err(|error| format!("parse Recovery proof external base: {error:?}"))?;
    let chat_instance = CanonicalUuidV4::parse(CHAT_INSTANCE)
        .map_err(|error| format!("parse Recovery proof chat instance: {error:?}"))?;
    let trust = TrustedNestVerifier::new(
        NEST_ISSUER,
        NEST_AUDIENCE,
        chat_instance,
        NEST_KEY_ID,
        nest_key.verifying_key().to_owned(),
        external_base,
    )
    .map_err(|error| format!("construct Recovery proof Nest trust: {error:?}"))?;
    let now = trusted_instant.datetime().timestamp();
    let token = sign_jwt(
        json!({"alg":"ES256","typ":"JWT","kid":NEST_KEY_ID}),
        json!({
            "iss": NEST_ISSUER,
            "sub": &identity.did,
            "aud": NEST_AUDIENCE,
            "lxm": endpoint.as_str(),
            "iat": now - 1,
            "exp": now + 60,
            "jti": Uuid::new_v4().hyphenated().to_string(),
            "cnf": {"jkt": &identity.proof_jkt},
            "device_id": identity.device_id.hyphenated().to_string(),
            "chat_instance": CHAT_INSTANCE,
        }),
        &nest_key,
    )?;
    let dpop = sign_dpop(
        &identity.proof_signing_key,
        &identity.proof_jwk,
        method.as_str(),
        trust.external_base().htu(&endpoint),
        &token,
        now,
    )?;
    let pre_replay = dpop::verify_ordinary_request_auth(
        &trust,
        &format!("DPoP {token}"),
        &dpop,
        &endpoint,
        &method,
        trusted_instant,
    )
    .map_err(|error| format!("verify Recovery proof Nest/DPoP request: {error:?}"))?;
    let canonical = decode_canonical_signed_mutation(&envelope.raw_wrapper)
        .map_err(|error| format!("decode Recovery proof signed request: {error:?}"))?;
    match authorize_signed_request(pool, pre_replay, canonical)
        .await
        .map_err(|error| format!("authorize Recovery proof request: {error:?}"))?
    {
        AuthorizationOutcome::FirstExecution(authority) => Ok(authority),
        AuthorizationOutcome::CompletedReplay(_) => {
            Err("fresh Recovery production-proof request unexpectedly replayed".to_owned())
        }
    }
}

pub(super) fn leaf_recovery_request(
    identity: &FixtureIdentity,
    request_id: Uuid,
    prior: Value,
    signed_at: &str,
) -> Result<SignedRecoveryEnvelope, String> {
    signed_recovery_envelope(
        identity,
        SignedMutationKind::LeafRecoveryRequest,
        json!({
            "recoveryRequestId": request_id.hyphenated().to_string(),
            "idempotencyKey": request_id.hyphenated().to_string(),
            "prior": prior,
            "recoveryKind": "replace",
        }),
        signed_at,
    )
}

pub(super) fn leaf_recovery_cancellation(
    identity: &FixtureIdentity,
    request_id: Uuid,
    signed_at: &str,
) -> Result<SignedRecoveryEnvelope, String> {
    signed_recovery_envelope(
        identity,
        SignedMutationKind::LeafRecoveryCancellation,
        json!({"recoveryRequestId": request_id.hyphenated().to_string()}),
        signed_at,
    )
}

/// The fulfillment shape is owned by the caller because it contains the
/// independently-generated Commit, Welcome, and public-state artifacts.  This
/// wrapper still verifies that the resulting body is the exact canonical
/// `LeafRecoveryFulfillment` transcript before it becomes an auth input.
pub(super) fn leaf_recovery_fulfillment(
    identity: &FixtureIdentity,
    mut body: Value,
) -> Result<SignedRecoveryEnvelope, String> {
    let object = body
        .as_object_mut()
        .ok_or_else(|| "Recovery fulfillment body must be an object".to_owned())?;
    let kind = SignedMutationKind::LeafRecoveryFulfillment;
    object.insert("$type".to_owned(), Value::String(kind.type_id().to_owned()));
    object.insert(
        "signatureDomain".to_owned(),
        Value::String(String::from_utf8(kind.domain().to_vec()).map_err(|_| "invalid domain")?),
    );
    object.insert("actorDid".to_owned(), Value::String(identity.did.clone()));
    object.insert(
        "actorDeviceId".to_owned(),
        Value::String(identity.device_id.hyphenated().to_string()),
    );
    object.insert("keyId".to_owned(), Value::String(identity.key_id.clone()));
    object.insert("authGeneration".to_owned(), json!(1));
    object
        .entry("idempotencyKey".to_owned())
        .or_insert_with(|| Value::String(Uuid::new_v4().hyphenated().to_string()));
    object.entry("signedAt".to_owned()).or_insert_with(|| {
        Value::String(Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true))
    });
    sign_canonical_wrapper(identity, body, kind)
}

fn signed_recovery_envelope(
    identity: &FixtureIdentity,
    kind: SignedMutationKind,
    extra: Value,
    signed_at: &str,
) -> Result<SignedRecoveryEnvelope, String> {
    let operation_id = extra
        .as_object()
        .and_then(|fields| fields.get("idempotencyKey"))
        .and_then(|value| value.as_str())
        .map(Uuid::parse_str)
        .transpose()
        .map_err(|error| format!("invalid Recovery fixture idempotency key: {error}"))?
        .unwrap_or_else(Uuid::new_v4);
    let mut body = json!({
        "$type": kind.type_id(),
        "signatureDomain": String::from_utf8(kind.domain().to_vec())
            .map_err(|_| "Recovery signature domain is not UTF-8")?,
        "actorDid": &identity.did,
        "actorDeviceId": identity.device_id.hyphenated().to_string(),
        "keyId": &identity.key_id,
        "authGeneration": 1,
        "idempotencyKey": operation_id.hyphenated().to_string(),
        "signedAt": signed_at,
    });
    let target = body
        .as_object_mut()
        .ok_or_else(|| "internal Recovery body is not an object".to_owned())?;
    for (key, value) in extra
        .as_object()
        .ok_or_else(|| "Recovery extra fields are not an object".to_owned())?
    {
        if key == "idempotencyKey" {
            continue;
        }
        if target.insert(key.clone(), value.clone()).is_some() {
            return Err(format!(
                "Recovery fixture attempted to overwrite envelope key {key}"
            ));
        }
    }
    sign_canonical_wrapper(identity, body, kind)
}

fn sign_canonical_wrapper(
    identity: &FixtureIdentity,
    body: Value,
    expected_kind: SignedMutationKind,
) -> Result<SignedRecoveryEnvelope, String> {
    let operation_id = body["idempotencyKey"]
        .as_str()
        .ok_or_else(|| "Recovery fixture body is missing idempotencyKey".to_owned())
        .and_then(|value| {
            Uuid::parse_str(value)
                .map_err(|error| format!("parse Recovery fixture idempotencyKey: {error}"))
        })?;
    let mut wrapper = json!({"body": body, "signature": STANDARD.encode([0_u8; 64])});
    let unsigned = serde_json::to_vec(&wrapper)
        .map_err(|error| format!("serialize unsigned Recovery wrapper: {error}"))?;
    let canonical = decode_canonical_signed_mutation(&unsigned)
        .map_err(|error| format!("canonicalize unsigned Recovery wrapper: {error:?}"))?;
    if canonical.kind() != expected_kind {
        return Err("Recovery fixture canonicalized to the wrong signed-mutation kind".to_owned());
    }
    let signature = identity
        .signing_key
        .sign(canonical.transcript_bytes())
        .to_bytes();
    wrapper["signature"] = Value::String(STANDARD.encode(signature));
    let raw_wrapper = serde_json::to_vec(&wrapper)
        .map_err(|error| format!("serialize signed Recovery wrapper: {error}"))?;
    let verified = decode_and_verify_signed_mutation(&raw_wrapper, &identity.signing_public_key())
        .map_err(|error| format!("verify signed Recovery wrapper: {error:?}"))?;
    if verified.kind() != expected_kind {
        return Err("verified Recovery fixture has the wrong signed-mutation kind".to_owned());
    }
    Ok(SignedRecoveryEnvelope {
        operation_id,
        raw_wrapper,
        request_digest: *verified.request_digest(),
        signing_transcript: verified.transcript_bytes().to_vec(),
        signature: *verified.signature(),
    })
}

fn fresh_p256(label: &[u8], device_id: Uuid) -> Result<P256SigningKey, String> {
    for counter in 0_u8..=u8::MAX {
        let seed = Sha256::digest(
            [
                b"CATBIRD-RECOVERY-PRODUCTION-PROOF-P256\0".as_ref(),
                label,
                device_id.as_bytes(),
                &[counter],
            ]
            .concat(),
        );
        if let Ok(key) = P256SigningKey::from_slice(&seed) {
            return Ok(key);
        }
    }
    Err("could not derive a valid P-256 Recovery production-proof key".to_owned())
}

fn public_jwk(key: &P256SigningKey) -> Value {
    let point = key.verifying_key().to_encoded_point(false);
    json!({
        "kty": "EC",
        "crv": "P-256",
        "x": URL_SAFE_NO_PAD.encode(point.x().expect("uncompressed P-256 x")),
        "y": URL_SAFE_NO_PAD.encode(point.y().expect("uncompressed P-256 y")),
    })
}

fn jwk_thumbprint(jwk: &Value) -> Result<String, String> {
    let x = jwk["x"]
        .as_str()
        .ok_or_else(|| "missing P-256 JWK x".to_owned())?;
    let y = jwk["y"]
        .as_str()
        .ok_or_else(|| "missing P-256 JWK y".to_owned())?;
    Ok(URL_SAFE_NO_PAD.encode(Sha256::digest(
        format!("{{\"crv\":\"P-256\",\"kty\":\"EC\",\"x\":\"{x}\",\"y\":\"{y}\"}}").as_bytes(),
    )))
}

fn sign_jwt(header: Value, claims: Value, key: &P256SigningKey) -> Result<String, String> {
    let header = URL_SAFE_NO_PAD.encode(
        serde_json::to_vec(&header).map_err(|error| format!("serialize JWT header: {error}"))?,
    );
    let claims = URL_SAFE_NO_PAD.encode(
        serde_json::to_vec(&claims).map_err(|error| format!("serialize JWT claims: {error}"))?,
    );
    let input = format!("{header}.{claims}");
    let signature: P256Signature = key.sign(input.as_bytes());
    Ok(format!(
        "{input}.{}",
        URL_SAFE_NO_PAD.encode(signature.to_bytes())
    ))
}

fn sign_dpop(
    key: &P256SigningKey,
    jwk: &Value,
    htm: &str,
    htu: String,
    token: &str,
    iat: i64,
) -> Result<String, String> {
    sign_jwt(
        json!({"typ":"dpop+jwt","alg":"ES256","jwk":jwk}),
        json!({
            "htm": htm,
            "htu": htu,
            "ath": URL_SAFE_NO_PAD.encode(Sha256::digest(token.as_bytes())),
            "iat": iat,
            "jti": URL_SAFE_NO_PAD.encode(Uuid::new_v4().as_bytes()),
        }),
        key,
    )
}
