//! Compatibility shim for legacy `blue.catbird.mls.*` NSID types.
//!
//! The old `mls` generated module was deleted during the NSID cutover to `mlsChat`.
//! This hand-written module provides the types that v1 handlers still reference,
//! minimising changes to 30+ handler files.

#![allow(non_camel_case_types, clippy::derivable_impls)]

// ── Shared types ────────────────────────────────────────────────────────────

#[derive(
    serde::Serialize, serde::Deserialize, Debug, Clone, PartialEq, Eq, jacquard_derive::IntoStatic,
)]
#[serde(rename_all = "camelCase")]
pub struct ConvoView<'a> {
    #[serde(borrow)]
    pub group_id: jacquard_common::CowStr<'a>,
    #[serde(borrow)]
    pub creator: jacquard_common::types::string::Did<'a>,
    #[serde(borrow)]
    pub members: Vec<MemberView<'a>>,
    pub epoch: i64,
    #[serde(borrow)]
    pub cipher_suite: jacquard_common::CowStr<'a>,
    pub created_at: jacquard_common::types::string::Datetime,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_message_at: Option<jacquard_common::types::string::Datetime>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(borrow)]
    pub metadata: Option<ConvoMetadata<'a>>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    #[serde(borrow)]
    pub extra_data: Option<jacquard_common::types::value::Data<'a>>,
}

#[derive(
    serde::Serialize, serde::Deserialize, Debug, Clone, PartialEq, Eq, jacquard_derive::IntoStatic,
)]
#[serde(rename_all = "camelCase")]
pub struct ConvoMetadata<'a> {
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(borrow)]
    pub name: Option<jacquard_common::CowStr<'a>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(borrow)]
    pub description: Option<jacquard_common::CowStr<'a>>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    #[serde(borrow)]
    pub extra_data: Option<jacquard_common::types::value::Data<'a>>,
}

#[derive(
    serde::Serialize, serde::Deserialize, Debug, Clone, PartialEq, Eq, jacquard_derive::IntoStatic,
)]
#[serde(rename_all = "camelCase")]
pub struct MemberView<'a> {
    #[serde(borrow)]
    pub did: jacquard_common::types::string::Did<'a>,
    #[serde(borrow)]
    pub user_did: jacquard_common::types::string::Did<'a>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(borrow)]
    pub device_id: Option<jacquard_common::CowStr<'a>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(borrow)]
    pub device_name: Option<jacquard_common::CowStr<'a>>,
    pub joined_at: jacquard_common::types::string::Datetime,
    pub is_admin: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub is_moderator: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub leaf_index: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(borrow)]
    pub credential: Option<jacquard_common::CowStr<'a>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub promoted_at: Option<jacquard_common::types::string::Datetime>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(borrow)]
    pub promoted_by: Option<jacquard_common::types::string::Did<'a>>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    #[serde(borrow)]
    pub extra_data: Option<jacquard_common::types::value::Data<'a>>,
}

#[derive(
    serde::Serialize, serde::Deserialize, Debug, Clone, PartialEq, Eq, jacquard_derive::IntoStatic,
)]
#[serde(rename_all = "camelCase")]
pub struct MessageView<'a> {
    #[serde(borrow)]
    pub id: jacquard_common::CowStr<'a>,
    #[serde(borrow)]
    pub convo_id: jacquard_common::CowStr<'a>,
    #[serde(with = "jacquard_common::serde_bytes_helper")]
    pub ciphertext: bytes::Bytes,
    pub epoch: i64,
    pub seq: i64,
    pub created_at: jacquard_common::types::string::Datetime,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(borrow)]
    pub message_type: Option<jacquard_common::CowStr<'a>>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    #[serde(borrow)]
    pub extra_data: Option<jacquard_common::types::value::Data<'a>>,
}

#[derive(
    serde::Serialize, serde::Deserialize, Debug, Clone, PartialEq, Eq, jacquard_derive::IntoStatic,
)]
#[serde(rename_all = "camelCase")]
pub struct KeyPackageRef<'a> {
    #[serde(borrow)]
    pub did: jacquard_common::types::string::Did<'a>,
    #[serde(borrow)]
    pub key_package: jacquard_common::CowStr<'a>,
    #[serde(borrow)]
    pub cipher_suite: jacquard_common::CowStr<'a>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(borrow)]
    pub key_package_hash: Option<jacquard_common::CowStr<'a>>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    #[serde(borrow)]
    pub extra_data: Option<jacquard_common::types::value::Data<'a>>,
}

/// Shared struct for key-package hash entries (used by create_convo and add_members).
#[derive(
    serde::Serialize, serde::Deserialize, Debug, Clone, PartialEq, Eq, jacquard_derive::IntoStatic,
)]
#[serde(rename_all = "camelCase")]
pub struct KeyPackageHashEntry<'a> {
    #[serde(borrow)]
    pub did: jacquard_common::types::string::Did<'a>,
    #[serde(borrow)]
    pub hash: jacquard_common::CowStr<'a>,
}

// ── Sub-modules ─────────────────────────────────────────────────────────────

macro_rules! cow_error_enum {
    (
        $(#[$meta:meta])*
        pub enum $name:ident {
            $( $variant:ident ),+ $(,)?
        }
    ) => {
        $(#[$meta])*
        #[derive(Debug, Clone, PartialEq, Eq)]
        pub enum $name {
            $( $variant(Option<String>), )+
            Unknown(String),
        }

        impl serde::Serialize for $name {
            fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
                use serde::ser::SerializeMap;
                let mut map = s.serialize_map(Some(1))?;
                match self {
                    $( Self::$variant(msg) => {
                        map.serialize_entry("error", stringify!($variant))?;
                        if let Some(m) = msg {
                            map.serialize_entry("message", m)?;
                        }
                    } )+
                    Self::Unknown(s_val) => {
                        map.serialize_entry("error", s_val)?;
                    }
                }
                map.end()
            }
        }

        impl<'de> serde::Deserialize<'de> for $name {
            fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
                let v: serde_json::Value = serde::Deserialize::deserialize(d)?;
                let err = v.get("error").and_then(|e| e.as_str()).unwrap_or("");
                let msg = v.get("message").and_then(|m| m.as_str()).map(String::from);
                match err {
                    $( stringify!($variant) => Ok(Self::$variant(msg)), )+
                    other => Ok(Self::Unknown(other.to_string())),
                }
            }
        }

        impl std::fmt::Display for $name {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                match self {
                    $(
                        Self::$variant(msg) => {
                            write!(f, "{}", stringify!($variant))?;
                            if let Some(m) = msg { write!(f, ": {}", m)?; }
                            Ok(())
                        }
                    )+
                    Self::Unknown(s) => write!(f, "Unknown: {}", s),
                }
            }
        }
    };
}

// ── create_convo ──

pub mod create_convo {
    #[derive(
        serde::Serialize,
        serde::Deserialize,
        Debug,
        Clone,
        PartialEq,
        Eq,
        jacquard_derive::IntoStatic,
    )]
    #[serde(rename_all = "camelCase")]
    pub struct CreateConvo<'a> {
        #[serde(borrow)]
        pub group_id: jacquard_common::CowStr<'a>,
        #[serde(borrow)]
        pub cipher_suite: jacquard_common::CowStr<'a>,
        #[serde(skip_serializing_if = "Option::is_none")]
        #[serde(borrow)]
        pub initial_members: Option<Vec<jacquard_common::types::string::Did<'a>>>,
        #[serde(skip_serializing_if = "Option::is_none")]
        #[serde(borrow)]
        pub key_package_hashes: Option<Vec<super::KeyPackageHashEntry<'a>>>,
        #[serde(skip_serializing_if = "Option::is_none")]
        #[serde(borrow)]
        pub welcome_message: Option<jacquard_common::CowStr<'a>>,
        #[serde(skip_serializing_if = "Option::is_none")]
        #[serde(borrow)]
        pub metadata: Option<super::ConvoMetadata<'a>>,
        #[serde(skip_serializing_if = "Option::is_none")]
        #[serde(borrow)]
        pub idempotency_key: Option<jacquard_common::CowStr<'a>>,
        #[serde(skip_serializing_if = "Option::is_none")]
        #[serde(borrow)]
        pub commit: Option<jacquard_common::CowStr<'a>>,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub epoch: Option<i64>,
        #[serde(skip_serializing_if = "Option::is_none", default)]
        #[serde(borrow)]
        pub extra_data: Option<jacquard_common::types::value::Data<'a>>,
    }

    cow_error_enum! {
        pub enum CreateConvoError {
            InvalidCipherSuite,
            KeyPackageNotFound,
            TooManyMembers,
            MutualBlockDetected,
        }
    }
}

// ── send_message ──

pub mod send_message {
    #[derive(
        serde::Serialize,
        serde::Deserialize,
        Debug,
        Clone,
        PartialEq,
        Eq,
        jacquard_derive::IntoStatic,
    )]
    #[serde(rename_all = "camelCase")]
    pub struct SendMessage<'a> {
        #[serde(with = "jacquard_common::serde_bytes_helper")]
        pub ciphertext: bytes::Bytes,
        #[serde(borrow)]
        pub convo_id: jacquard_common::CowStr<'a>,
        pub epoch: i64,
        #[serde(borrow)]
        pub msg_id: jacquard_common::CowStr<'a>,
        pub padded_size: i64,
        #[serde(skip_serializing_if = "Option::is_none")]
        #[serde(borrow)]
        pub idempotency_key: Option<jacquard_common::CowStr<'a>>,
        #[serde(skip_serializing_if = "Option::is_none")]
        #[serde(borrow)]
        pub delivery: Option<jacquard_common::CowStr<'a>>,
        #[serde(skip_serializing_if = "Option::is_none", default)]
        #[serde(borrow)]
        pub extra_data: Option<jacquard_common::types::value::Data<'a>>,
    }

    #[derive(
        serde::Serialize,
        serde::Deserialize,
        Debug,
        Clone,
        PartialEq,
        Eq,
        jacquard_derive::IntoStatic,
    )]
    #[serde(rename_all = "camelCase")]
    pub struct SendMessageOutput<'a> {
        #[serde(borrow)]
        pub message_id: jacquard_common::CowStr<'a>,
        pub received_at: jacquard_common::types::string::Datetime,
        pub seq: i64,
        pub epoch: i64,
        #[serde(skip_serializing_if = "Option::is_none", default)]
        #[serde(borrow)]
        pub extra_data: Option<jacquard_common::types::value::Data<'a>>,
    }
}

// ── register_device ──

pub mod register_device {
    #[derive(
        serde::Serialize,
        serde::Deserialize,
        Debug,
        Clone,
        PartialEq,
        Eq,
        jacquard_derive::IntoStatic,
    )]
    #[serde(rename_all = "camelCase")]
    pub struct RegisterDevice<'a> {
        #[serde(with = "jacquard_common::serde_bytes_helper")]
        pub signature_public_key: bytes::Bytes,
        #[serde(borrow)]
        pub key_packages: Vec<KeyPackageItem<'a>>,
        #[serde(skip_serializing_if = "Option::is_none")]
        #[serde(borrow)]
        pub device_uuid: Option<jacquard_common::CowStr<'a>>,
        #[serde(skip_serializing_if = "Option::is_none")]
        #[serde(borrow)]
        pub device_name: Option<jacquard_common::CowStr<'a>>,
        #[serde(skip_serializing_if = "Option::is_none", default)]
        #[serde(borrow)]
        pub extra_data: Option<jacquard_common::types::value::Data<'a>>,
    }

    #[derive(
        serde::Serialize,
        serde::Deserialize,
        Debug,
        Clone,
        PartialEq,
        Eq,
        jacquard_derive::IntoStatic,
    )]
    #[serde(rename_all = "camelCase")]
    pub struct KeyPackageItem<'a> {
        #[serde(borrow)]
        pub key_package: jacquard_common::CowStr<'a>,
        #[serde(borrow)]
        pub cipher_suite: jacquard_common::CowStr<'a>,
        pub expires: jacquard_common::types::string::Datetime,
    }
}

// ── delete_device ──

pub mod delete_device {
    #[derive(
        serde::Serialize,
        serde::Deserialize,
        Debug,
        Clone,
        PartialEq,
        Eq,
        jacquard_derive::IntoStatic,
    )]
    #[serde(rename_all = "camelCase")]
    pub struct DeleteDevice<'a> {
        #[serde(borrow)]
        pub device_id: jacquard_common::CowStr<'a>,
        #[serde(skip_serializing_if = "Option::is_none", default)]
        #[serde(borrow)]
        pub extra_data: Option<jacquard_common::types::value::Data<'a>>,
    }
}

// ── publish_key_package ──

pub mod publish_key_package {
    #[derive(
        serde::Serialize,
        serde::Deserialize,
        Debug,
        Clone,
        PartialEq,
        Eq,
        jacquard_derive::IntoStatic,
    )]
    #[serde(rename_all = "camelCase")]
    pub struct PublishKeyPackage<'a> {
        #[serde(borrow)]
        pub key_package: jacquard_common::CowStr<'a>,
        #[serde(borrow)]
        pub cipher_suite: jacquard_common::CowStr<'a>,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub expires: Option<jacquard_common::types::string::Datetime>,
        #[serde(skip_serializing_if = "Option::is_none", default)]
        #[serde(borrow)]
        pub extra_data: Option<jacquard_common::types::value::Data<'a>>,
    }

    #[derive(
        serde::Serialize,
        serde::Deserialize,
        Debug,
        Clone,
        PartialEq,
        Eq,
        jacquard_derive::IntoStatic,
    )]
    #[serde(rename_all = "camelCase")]
    pub struct PublishKeyPackageOutput<'a> {
        #[serde(skip_serializing_if = "Option::is_none", default)]
        #[serde(borrow)]
        pub extra_data: Option<jacquard_common::types::value::Data<'a>>,
    }
}

// ── promote_admin ──

pub mod promote_admin {
    #[derive(
        serde::Serialize,
        serde::Deserialize,
        Debug,
        Clone,
        PartialEq,
        Eq,
        jacquard_derive::IntoStatic,
    )]
    #[serde(rename_all = "camelCase")]
    pub struct PromoteAdmin<'a> {
        #[serde(borrow)]
        pub convo_id: jacquard_common::CowStr<'a>,
        #[serde(borrow)]
        pub target_did: jacquard_common::types::string::Did<'a>,
        #[serde(skip_serializing_if = "Option::is_none", default)]
        #[serde(borrow)]
        pub extra_data: Option<jacquard_common::types::value::Data<'a>>,
    }

    #[derive(
        serde::Serialize,
        serde::Deserialize,
        Debug,
        Clone,
        PartialEq,
        Eq,
        jacquard_derive::IntoStatic,
    )]
    #[serde(rename_all = "camelCase")]
    pub struct PromoteAdminOutput<'a> {
        pub ok: bool,
        pub promoted_at: jacquard_common::types::string::Datetime,
        #[serde(skip_serializing_if = "Option::is_none", default)]
        #[serde(borrow)]
        pub extra_data: Option<jacquard_common::types::value::Data<'a>>,
    }
}

// ── demote_admin ──

pub mod demote_admin {
    #[derive(
        serde::Serialize,
        serde::Deserialize,
        Debug,
        Clone,
        PartialEq,
        Eq,
        jacquard_derive::IntoStatic,
    )]
    #[serde(rename_all = "camelCase")]
    pub struct DemoteAdmin<'a> {
        #[serde(borrow)]
        pub convo_id: jacquard_common::CowStr<'a>,
        #[serde(borrow)]
        pub target_did: jacquard_common::types::string::Did<'a>,
        #[serde(skip_serializing_if = "Option::is_none", default)]
        #[serde(borrow)]
        pub extra_data: Option<jacquard_common::types::value::Data<'a>>,
    }

    #[derive(
        serde::Serialize,
        serde::Deserialize,
        Debug,
        Clone,
        PartialEq,
        Eq,
        jacquard_derive::IntoStatic,
    )]
    #[serde(rename_all = "camelCase")]
    pub struct DemoteAdminOutput<'a> {
        pub ok: bool,
        #[serde(skip_serializing_if = "Option::is_none", default)]
        #[serde(borrow)]
        pub extra_data: Option<jacquard_common::types::value::Data<'a>>,
    }
}

// ── group_info_refresh ──

pub mod group_info_refresh {
    #[derive(
        serde::Serialize,
        serde::Deserialize,
        Debug,
        Clone,
        PartialEq,
        Eq,
        jacquard_derive::IntoStatic,
    )]
    #[serde(rename_all = "camelCase")]
    pub struct GroupInfoRefresh<'a> {
        #[serde(borrow)]
        pub convo_id: jacquard_common::CowStr<'a>,
        #[serde(skip_serializing_if = "Option::is_none", default)]
        #[serde(borrow)]
        pub extra_data: Option<jacquard_common::types::value::Data<'a>>,
    }

    #[derive(
        serde::Serialize,
        serde::Deserialize,
        Debug,
        Clone,
        PartialEq,
        Eq,
        jacquard_derive::IntoStatic,
    )]
    #[serde(rename_all = "camelCase")]
    pub struct GroupInfoRefreshOutput<'a> {
        pub requested: bool,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub active_members: Option<i64>,
        #[serde(skip_serializing_if = "Option::is_none", default)]
        #[serde(borrow)]
        pub extra_data: Option<jacquard_common::types::value::Data<'a>>,
    }
}

// ── update_group_info ──

pub mod update_group_info {
    #[derive(
        serde::Serialize,
        serde::Deserialize,
        Debug,
        Clone,
        PartialEq,
        Eq,
        jacquard_derive::IntoStatic,
    )]
    #[serde(rename_all = "camelCase")]
    pub struct UpdateGroupInfo<'a> {
        #[serde(borrow)]
        pub convo_id: jacquard_common::CowStr<'a>,
        #[serde(borrow)]
        pub group_info: jacquard_common::CowStr<'a>,
        pub epoch: i64,
        #[serde(skip_serializing_if = "Option::is_none", default)]
        #[serde(borrow)]
        pub extra_data: Option<jacquard_common::types::value::Data<'a>>,
    }

    #[derive(
        serde::Serialize,
        serde::Deserialize,
        Debug,
        Clone,
        PartialEq,
        Eq,
        jacquard_derive::IntoStatic,
    )]
    #[serde(rename_all = "camelCase")]
    pub struct UpdateGroupInfoOutput<'a> {
        pub updated: bool,
        #[serde(skip_serializing_if = "Option::is_none", default)]
        #[serde(borrow)]
        pub extra_data: Option<jacquard_common::types::value::Data<'a>>,
    }

    cow_error_enum! {
        pub enum UpdateGroupInfoError {
            Unauthorized,
            InvalidGroupInfo,
        }
    }
}

// ── add_members ──

pub mod add_members {
    #[derive(
        serde::Serialize,
        serde::Deserialize,
        Debug,
        Clone,
        PartialEq,
        Eq,
        jacquard_derive::IntoStatic,
    )]
    #[serde(rename_all = "camelCase")]
    pub struct AddMembers<'a> {
        #[serde(borrow)]
        pub convo_id: jacquard_common::CowStr<'a>,
        #[serde(borrow)]
        pub did_list: Vec<jacquard_common::types::string::Did<'a>>,
        #[serde(skip_serializing_if = "Option::is_none")]
        #[serde(borrow)]
        pub commit: Option<jacquard_common::CowStr<'a>>,
        #[serde(skip_serializing_if = "Option::is_none")]
        #[serde(borrow)]
        pub key_package_hashes: Option<Vec<super::KeyPackageHashEntry<'a>>>,
        #[serde(skip_serializing_if = "Option::is_none")]
        #[serde(borrow)]
        pub welcome_message: Option<jacquard_common::CowStr<'a>>,
        #[serde(skip_serializing_if = "Option::is_none")]
        #[serde(borrow)]
        pub idempotency_key: Option<jacquard_common::CowStr<'a>>,
        #[serde(skip_serializing_if = "Option::is_none", default)]
        #[serde(borrow)]
        pub extra_data: Option<jacquard_common::types::value::Data<'a>>,
    }

    #[derive(
        serde::Serialize,
        serde::Deserialize,
        Debug,
        Clone,
        PartialEq,
        Eq,
        jacquard_derive::IntoStatic,
    )]
    #[serde(rename_all = "camelCase")]
    pub struct AddMembersOutput<'a> {
        pub success: bool,
        pub new_epoch: i64,
        #[serde(skip_serializing_if = "Option::is_none", default)]
        #[serde(borrow)]
        pub extra_data: Option<jacquard_common::types::value::Data<'a>>,
    }

    cow_error_enum! {
        pub enum AddMembersError {
            ConvoNotFound,
            NotMember,
            KeyPackageNotFound,
            AlreadyMember,
            TooManyMembers,
            BlockedByMember,
        }
    }
}

// ── get_group_info ──

pub mod get_group_info {
    #[derive(
        serde::Serialize,
        serde::Deserialize,
        Debug,
        Clone,
        PartialEq,
        Eq,
        jacquard_derive::IntoStatic,
    )]
    #[serde(rename_all = "camelCase")]
    pub struct GetGroupInfo<'a> {
        #[serde(borrow)]
        pub convo_id: jacquard_common::CowStr<'a>,
        #[serde(skip_serializing_if = "Option::is_none", default)]
        #[serde(borrow)]
        pub extra_data: Option<jacquard_common::types::value::Data<'a>>,
    }

    #[derive(
        serde::Serialize,
        serde::Deserialize,
        Debug,
        Clone,
        PartialEq,
        Eq,
        jacquard_derive::IntoStatic,
    )]
    #[serde(rename_all = "camelCase")]
    pub struct GetGroupInfoOutput<'a> {
        #[serde(borrow)]
        pub group_info: jacquard_common::CowStr<'a>,
        pub epoch: i64,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub expires_at: Option<jacquard_common::types::string::Datetime>,
        #[serde(skip_serializing_if = "Option::is_none", default)]
        #[serde(borrow)]
        pub extra_data: Option<jacquard_common::types::value::Data<'a>>,
    }

    cow_error_enum! {
        pub enum GetGroupInfoError {
            GroupInfoUnavailable,
            NotFound,
            Unauthorized,
        }
    }
}

// ── check_blocks ──

pub mod check_blocks {
    #[derive(
        serde::Serialize,
        serde::Deserialize,
        Debug,
        Clone,
        PartialEq,
        Eq,
        jacquard_derive::IntoStatic,
    )]
    #[serde(rename_all = "camelCase")]
    pub struct CheckBlocks<'a> {
        #[serde(borrow)]
        pub dids: Vec<jacquard_common::types::string::Did<'a>>,
        #[serde(skip_serializing_if = "Option::is_none", default)]
        #[serde(borrow)]
        pub extra_data: Option<jacquard_common::types::value::Data<'a>>,
    }

    #[derive(
        serde::Serialize,
        serde::Deserialize,
        Debug,
        Clone,
        PartialEq,
        Eq,
        jacquard_derive::IntoStatic,
    )]
    #[serde(rename_all = "camelCase")]
    pub struct CheckBlocksOutput<'a> {
        #[serde(borrow)]
        pub blocks: Vec<BlockRelationship<'a>>,
        pub checked_at: jacquard_common::types::string::Datetime,
        #[serde(skip_serializing_if = "Option::is_none", default)]
        #[serde(borrow)]
        pub extra_data: Option<jacquard_common::types::value::Data<'a>>,
    }

    #[derive(
        serde::Serialize,
        serde::Deserialize,
        Debug,
        Clone,
        PartialEq,
        Eq,
        jacquard_derive::IntoStatic,
    )]
    #[serde(rename_all = "camelCase")]
    pub struct BlockRelationship<'a> {
        #[serde(borrow)]
        pub blocker_did: jacquard_common::types::string::Did<'a>,
        #[serde(borrow)]
        pub blocked_did: jacquard_common::types::string::Did<'a>,
        pub created_at: jacquard_common::types::string::Datetime,
        #[serde(skip_serializing_if = "Option::is_none")]
        #[serde(borrow)]
        pub block_uri: Option<jacquard_common::CowStr<'a>>,
        #[serde(skip_serializing_if = "Option::is_none", default)]
        #[serde(borrow)]
        pub extra_data: Option<jacquard_common::types::value::Data<'a>>,
    }
}

// ── get_block_status ──

pub mod get_block_status {
    use super::check_blocks::BlockRelationship;

    #[derive(
        serde::Serialize,
        serde::Deserialize,
        Debug,
        Clone,
        PartialEq,
        Eq,
        jacquard_derive::IntoStatic,
    )]
    #[serde(rename_all = "camelCase")]
    pub struct GetBlockStatus<'a> {
        #[serde(borrow)]
        pub convo_id: jacquard_common::CowStr<'a>,
        #[serde(skip_serializing_if = "Option::is_none", default)]
        #[serde(borrow)]
        pub extra_data: Option<jacquard_common::types::value::Data<'a>>,
    }

    #[derive(
        serde::Serialize,
        serde::Deserialize,
        Debug,
        Clone,
        PartialEq,
        Eq,
        jacquard_derive::IntoStatic,
    )]
    #[serde(rename_all = "camelCase")]
    pub struct GetBlockStatusOutput<'a> {
        #[serde(borrow)]
        pub convo_id: jacquard_common::CowStr<'a>,
        pub has_conflicts: bool,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub member_count: Option<i64>,
        #[serde(borrow)]
        pub blocks: Vec<BlockRelationship<'a>>,
        pub checked_at: jacquard_common::types::string::Datetime,
        #[serde(skip_serializing_if = "Option::is_none", default)]
        #[serde(borrow)]
        pub extra_data: Option<jacquard_common::types::value::Data<'a>>,
    }
}

// ── handle_block_change ──

pub mod handle_block_change {
    #[derive(
        serde::Serialize,
        serde::Deserialize,
        Debug,
        Clone,
        PartialEq,
        Eq,
        jacquard_derive::IntoStatic,
    )]
    #[serde(rename_all = "camelCase")]
    pub struct HandleBlockChange<'a> {
        #[serde(borrow)]
        pub blocker_did: jacquard_common::types::string::Did<'a>,
        #[serde(borrow)]
        pub blocked_did: jacquard_common::types::string::Did<'a>,
        #[serde(borrow)]
        pub action: jacquard_common::CowStr<'a>,
        #[serde(skip_serializing_if = "Option::is_none", default)]
        #[serde(borrow)]
        pub extra_data: Option<jacquard_common::types::value::Data<'a>>,
    }

    #[derive(
        serde::Serialize,
        serde::Deserialize,
        Debug,
        Clone,
        PartialEq,
        Eq,
        jacquard_derive::IntoStatic,
    )]
    #[serde(rename_all = "camelCase")]
    pub struct HandleBlockChangeOutput<'a> {
        #[serde(borrow)]
        pub affected_convos: Vec<AffectedConvo<'a>>,
        #[serde(skip_serializing_if = "Option::is_none", default)]
        #[serde(borrow)]
        pub extra_data: Option<jacquard_common::types::value::Data<'a>>,
    }

    #[derive(
        serde::Serialize,
        serde::Deserialize,
        Debug,
        Clone,
        PartialEq,
        Eq,
        jacquard_derive::IntoStatic,
    )]
    #[serde(rename_all = "camelCase")]
    pub struct AffectedConvo<'a> {
        #[serde(borrow)]
        pub convo_id: jacquard_common::CowStr<'a>,
        #[serde(borrow)]
        pub action: jacquard_common::CowStr<'a>,
        pub admin_notified: bool,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub notification_sent_at: Option<jacquard_common::types::string::Datetime>,
        #[serde(skip_serializing_if = "Option::is_none", default)]
        #[serde(borrow)]
        pub extra_data: Option<jacquard_common::types::value::Data<'a>>,
    }
}

// ── get_convos ──

pub mod get_convos {
    #[derive(
        serde::Serialize,
        serde::Deserialize,
        Debug,
        Clone,
        PartialEq,
        Eq,
        jacquard_derive::IntoStatic,
    )]
    #[serde(rename_all = "camelCase")]
    pub struct GetConvosOutput<'a> {
        #[serde(borrow)]
        pub conversations: Vec<super::ConvoView<'a>>,
        #[serde(skip_serializing_if = "Option::is_none")]
        #[serde(borrow)]
        pub cursor: Option<jacquard_common::CowStr<'a>>,
        #[serde(skip_serializing_if = "Option::is_none", default)]
        #[serde(borrow)]
        pub extra_data: Option<jacquard_common::types::value::Data<'a>>,
    }
}

// ── get_messages ──

pub mod get_messages {
    #[derive(
        serde::Serialize,
        serde::Deserialize,
        Debug,
        Clone,
        PartialEq,
        Eq,
        jacquard_derive::IntoStatic,
    )]
    #[serde(rename_all = "camelCase")]
    pub struct GetMessagesOutput<'a> {
        #[serde(borrow)]
        pub messages: Vec<super::MessageView<'a>>,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub last_seq: Option<i64>,
        #[serde(skip_serializing_if = "Option::is_none")]
        #[serde(borrow)]
        pub gap_info: Option<GapInfo<'a>>,
        #[serde(skip_serializing_if = "Option::is_none", default)]
        #[serde(borrow)]
        pub extra_data: Option<jacquard_common::types::value::Data<'a>>,
    }

    #[derive(
        serde::Serialize,
        serde::Deserialize,
        Debug,
        Clone,
        PartialEq,
        Eq,
        jacquard_derive::IntoStatic,
    )]
    #[serde(rename_all = "camelCase")]
    pub struct GapInfo<'a> {
        pub has_gaps: bool,
        pub missing_seqs: Vec<i64>,
        pub total_messages: i64,
        #[serde(skip_serializing_if = "Option::is_none", default)]
        #[serde(borrow)]
        pub extra_data: Option<jacquard_common::types::value::Data<'a>>,
    }
}

// ── get_key_packages ──

pub mod get_key_packages {
    #[derive(
        serde::Serialize,
        serde::Deserialize,
        Debug,
        Clone,
        PartialEq,
        Eq,
        jacquard_derive::IntoStatic,
    )]
    #[serde(rename_all = "camelCase")]
    pub struct GetKeyPackagesOutput<'a> {
        #[serde(borrow)]
        pub key_packages: Vec<super::KeyPackageRef<'a>>,
        #[serde(skip_serializing_if = "Option::is_none")]
        #[serde(borrow)]
        pub missing: Option<Vec<jacquard_common::types::string::Did<'a>>>,
        #[serde(skip_serializing_if = "Option::is_none", default)]
        #[serde(borrow)]
        pub extra_data: Option<jacquard_common::types::value::Data<'a>>,
    }
}

// ── invalidate_welcome ──

pub mod invalidate_welcome {
    #[derive(
        serde::Serialize,
        serde::Deserialize,
        Debug,
        Clone,
        PartialEq,
        Eq,
        jacquard_derive::IntoStatic,
    )]
    #[serde(rename_all = "camelCase")]
    pub struct InvalidateWelcome<'a> {
        #[serde(borrow)]
        pub convo_id: jacquard_common::CowStr<'a>,
        #[serde(borrow)]
        pub reason: jacquard_common::CowStr<'a>,
        #[serde(skip_serializing_if = "Option::is_none", default)]
        #[serde(borrow)]
        pub extra_data: Option<jacquard_common::types::value::Data<'a>>,
    }

    #[derive(
        serde::Serialize,
        serde::Deserialize,
        Debug,
        Clone,
        PartialEq,
        Eq,
        jacquard_derive::IntoStatic,
    )]
    #[serde(rename_all = "camelCase")]
    pub struct InvalidateWelcomeOutput<'a> {
        pub invalidated: bool,
        #[serde(skip_serializing_if = "Option::is_none")]
        #[serde(borrow)]
        pub welcome_id: Option<jacquard_common::CowStr<'a>>,
        #[serde(skip_serializing_if = "Option::is_none", default)]
        #[serde(borrow)]
        pub extra_data: Option<jacquard_common::types::value::Data<'a>>,
    }
}

// ── readdition ──

pub mod readdition {
    #[derive(
        serde::Serialize,
        serde::Deserialize,
        Debug,
        Clone,
        PartialEq,
        Eq,
        jacquard_derive::IntoStatic,
    )]
    #[serde(rename_all = "camelCase")]
    pub struct Readdition<'a> {
        #[serde(borrow)]
        pub convo_id: jacquard_common::CowStr<'a>,
        #[serde(skip_serializing_if = "Option::is_none", default)]
        #[serde(borrow)]
        pub extra_data: Option<jacquard_common::types::value::Data<'a>>,
    }

    #[derive(
        serde::Serialize,
        serde::Deserialize,
        Debug,
        Clone,
        PartialEq,
        Eq,
        jacquard_derive::IntoStatic,
    )]
    #[serde(rename_all = "camelCase")]
    pub struct ReadditionOutput<'a> {
        pub requested: bool,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub active_members: Option<i64>,
        #[serde(skip_serializing_if = "Option::is_none", default)]
        #[serde(borrow)]
        pub extra_data: Option<jacquard_common::types::value::Data<'a>>,
    }
}

// ── rejoin ──

pub mod rejoin {
    #[derive(
        serde::Serialize,
        serde::Deserialize,
        Debug,
        Clone,
        PartialEq,
        Eq,
        jacquard_derive::IntoStatic,
    )]
    #[serde(rename_all = "camelCase")]
    pub struct Rejoin<'a> {
        #[serde(borrow)]
        pub convo_id: jacquard_common::CowStr<'a>,
        #[serde(borrow)]
        pub key_package: jacquard_common::CowStr<'a>,
        #[serde(skip_serializing_if = "Option::is_none")]
        #[serde(borrow)]
        pub reason: Option<jacquard_common::CowStr<'a>>,
        #[serde(skip_serializing_if = "Option::is_none", default)]
        #[serde(borrow)]
        pub extra_data: Option<jacquard_common::types::value::Data<'a>>,
    }

    #[derive(
        serde::Serialize,
        serde::Deserialize,
        Debug,
        Clone,
        PartialEq,
        Eq,
        jacquard_derive::IntoStatic,
    )]
    #[serde(rename_all = "camelCase")]
    pub struct RejoinOutput<'a> {
        #[serde(borrow)]
        pub request_id: jacquard_common::CowStr<'a>,
        pub pending: bool,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub approved_at: Option<jacquard_common::types::string::Datetime>,
        #[serde(skip_serializing_if = "Option::is_none", default)]
        #[serde(borrow)]
        pub extra_data: Option<jacquard_common::types::value::Data<'a>>,
    }
}

// ── remove_member ──

pub mod remove_member {
    #[derive(
        serde::Serialize,
        serde::Deserialize,
        Debug,
        Clone,
        PartialEq,
        Eq,
        jacquard_derive::IntoStatic,
    )]
    #[serde(rename_all = "camelCase")]
    pub struct RemoveMember<'a> {
        #[serde(borrow)]
        pub convo_id: jacquard_common::CowStr<'a>,
        #[serde(borrow)]
        pub target_did: jacquard_common::types::string::Did<'a>,
        #[serde(skip_serializing_if = "Option::is_none")]
        #[serde(borrow)]
        pub commit: Option<jacquard_common::CowStr<'a>>,
        #[serde(skip_serializing_if = "Option::is_none")]
        #[serde(borrow)]
        pub reason: Option<jacquard_common::CowStr<'a>>,
        #[serde(skip_serializing_if = "Option::is_none", default)]
        #[serde(borrow)]
        pub extra_data: Option<jacquard_common::types::value::Data<'a>>,
    }

    #[derive(
        serde::Serialize,
        serde::Deserialize,
        Debug,
        Clone,
        PartialEq,
        Eq,
        jacquard_derive::IntoStatic,
    )]
    #[serde(rename_all = "camelCase")]
    pub struct RemoveMemberOutput<'a> {
        pub ok: bool,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub epoch_hint: Option<i64>,
        #[serde(skip_serializing_if = "Option::is_none", default)]
        #[serde(borrow)]
        pub extra_data: Option<jacquard_common::types::value::Data<'a>>,
    }
}

// ── report_member ──

pub mod report_member {
    #[derive(
        serde::Serialize,
        serde::Deserialize,
        Debug,
        Clone,
        PartialEq,
        Eq,
        jacquard_derive::IntoStatic,
    )]
    #[serde(rename_all = "camelCase")]
    pub struct ReportMember<'a> {
        #[serde(borrow)]
        pub convo_id: jacquard_common::CowStr<'a>,
        #[serde(borrow)]
        pub reported_did: jacquard_common::types::string::Did<'a>,
        #[serde(borrow)]
        pub category: jacquard_common::CowStr<'a>,
        #[serde(borrow)]
        pub encrypted_content: jacquard_common::CowStr<'a>,
        #[serde(skip_serializing_if = "Option::is_none")]
        #[serde(borrow)]
        pub message_ids: Option<Vec<jacquard_common::CowStr<'a>>>,
        #[serde(skip_serializing_if = "Option::is_none", default)]
        #[serde(borrow)]
        pub extra_data: Option<jacquard_common::types::value::Data<'a>>,
    }

    #[derive(
        serde::Serialize,
        serde::Deserialize,
        Debug,
        Clone,
        PartialEq,
        Eq,
        jacquard_derive::IntoStatic,
    )]
    #[serde(rename_all = "camelCase")]
    pub struct ReportMemberOutput<'a> {
        #[serde(borrow)]
        pub report_id: jacquard_common::CowStr<'a>,
        pub submitted_at: jacquard_common::types::string::Datetime,
        #[serde(skip_serializing_if = "Option::is_none", default)]
        #[serde(borrow)]
        pub extra_data: Option<jacquard_common::types::value::Data<'a>>,
    }
}

// ── resolve_report ──

pub mod resolve_report {
    #[derive(
        serde::Serialize,
        serde::Deserialize,
        Debug,
        Clone,
        PartialEq,
        Eq,
        jacquard_derive::IntoStatic,
    )]
    #[serde(rename_all = "camelCase")]
    pub struct ResolveReport<'a> {
        #[serde(borrow)]
        pub report_id: jacquard_common::CowStr<'a>,
        #[serde(borrow)]
        pub action: jacquard_common::CowStr<'a>,
        #[serde(skip_serializing_if = "Option::is_none")]
        #[serde(borrow)]
        pub notes: Option<jacquard_common::CowStr<'a>>,
        #[serde(skip_serializing_if = "Option::is_none", default)]
        #[serde(borrow)]
        pub extra_data: Option<jacquard_common::types::value::Data<'a>>,
    }

    #[derive(
        serde::Serialize,
        serde::Deserialize,
        Debug,
        Clone,
        PartialEq,
        Eq,
        jacquard_derive::IntoStatic,
    )]
    #[serde(rename_all = "camelCase")]
    pub struct ResolveReportOutput<'a> {
        pub ok: bool,
        #[serde(skip_serializing_if = "Option::is_none", default)]
        #[serde(borrow)]
        pub extra_data: Option<jacquard_common::types::value::Data<'a>>,
    }
}

// ── warn_member ──

pub mod warn_member {
    #[derive(
        serde::Serialize,
        serde::Deserialize,
        Debug,
        Clone,
        PartialEq,
        Eq,
        jacquard_derive::IntoStatic,
    )]
    #[serde(rename_all = "camelCase")]
    pub struct WarnMember<'a> {
        #[serde(borrow)]
        pub convo_id: jacquard_common::CowStr<'a>,
        #[serde(borrow)]
        pub member_did: jacquard_common::types::string::Did<'a>,
        #[serde(borrow)]
        pub reason: jacquard_common::CowStr<'a>,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub expires_at: Option<jacquard_common::types::string::Datetime>,
        #[serde(skip_serializing_if = "Option::is_none", default)]
        #[serde(borrow)]
        pub extra_data: Option<jacquard_common::types::value::Data<'a>>,
    }

    #[derive(
        serde::Serialize,
        serde::Deserialize,
        Debug,
        Clone,
        PartialEq,
        Eq,
        jacquard_derive::IntoStatic,
    )]
    #[serde(rename_all = "camelCase")]
    pub struct WarnMemberOutput<'a> {
        #[serde(borrow)]
        pub warning_id: jacquard_common::CowStr<'a>,
        pub delivered_at: jacquard_common::types::string::Datetime,
        #[serde(skip_serializing_if = "Option::is_none", default)]
        #[serde(borrow)]
        pub extra_data: Option<jacquard_common::types::value::Data<'a>>,
    }
}

// ── get_admin_stats ──

pub mod get_admin_stats {
    #[derive(
        serde::Serialize,
        serde::Deserialize,
        Debug,
        Clone,
        PartialEq,
        Eq,
        jacquard_derive::IntoStatic,
    )]
    #[serde(rename_all = "camelCase")]
    pub struct GetAdminStats<'a> {
        #[serde(skip_serializing_if = "Option::is_none")]
        #[serde(borrow)]
        pub convo_id: Option<jacquard_common::CowStr<'a>>,
        #[serde(skip_serializing_if = "Option::is_none")]
        #[serde(borrow)]
        pub since: Option<jacquard_common::CowStr<'a>>,
        #[serde(skip_serializing_if = "Option::is_none", default)]
        #[serde(borrow)]
        pub extra_data: Option<jacquard_common::types::value::Data<'a>>,
    }

    #[derive(
        serde::Serialize,
        serde::Deserialize,
        Debug,
        Clone,
        PartialEq,
        Eq,
        jacquard_derive::IntoStatic,
    )]
    #[serde(rename_all = "camelCase")]
    pub struct GetAdminStatsOutput<'a> {
        #[serde(borrow)]
        pub stats: ModerationStats<'a>,
        pub generated_at: jacquard_common::types::string::Datetime,
        #[serde(skip_serializing_if = "Option::is_none")]
        #[serde(borrow)]
        pub convo_id: Option<jacquard_common::CowStr<'a>>,
        #[serde(skip_serializing_if = "Option::is_none", default)]
        #[serde(borrow)]
        pub extra_data: Option<jacquard_common::types::value::Data<'a>>,
    }

    #[derive(
        serde::Serialize,
        serde::Deserialize,
        Debug,
        Clone,
        PartialEq,
        Eq,
        jacquard_derive::IntoStatic,
    )]
    #[serde(rename_all = "camelCase")]
    pub struct ModerationStats<'a> {
        pub total_reports: i64,
        pub pending_reports: i64,
        pub resolved_reports: i64,
        pub total_removals: i64,
        pub block_conflicts_resolved: i64,
        #[serde(skip_serializing_if = "Option::is_none")]
        #[serde(borrow)]
        pub reports_by_category: Option<ReportCategoryCounts<'a>>,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub average_resolution_time_hours: Option<i64>,
        #[serde(skip_serializing_if = "Option::is_none", default)]
        #[serde(borrow)]
        pub extra_data: Option<jacquard_common::types::value::Data<'a>>,
    }

    #[derive(
        serde::Serialize,
        serde::Deserialize,
        Debug,
        Clone,
        PartialEq,
        Eq,
        jacquard_derive::IntoStatic,
    )]
    #[serde(rename_all = "camelCase")]
    pub struct ReportCategoryCounts<'a> {
        #[serde(skip_serializing_if = "Option::is_none")]
        pub harassment: Option<i64>,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub spam: Option<i64>,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub hate_speech: Option<i64>,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub violence: Option<i64>,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub sexual_content: Option<i64>,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub impersonation: Option<i64>,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub privacy_violation: Option<i64>,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub other_category: Option<i64>,
        #[serde(skip_serializing_if = "Option::is_none", default)]
        #[serde(borrow)]
        pub extra_data: Option<jacquard_common::types::value::Data<'a>>,
    }
}

// ── get_reports ──

pub mod get_reports {
    #[derive(
        serde::Serialize,
        serde::Deserialize,
        Debug,
        Clone,
        PartialEq,
        Eq,
        jacquard_derive::IntoStatic,
    )]
    #[serde(rename_all = "camelCase")]
    pub struct GetReports<'a> {
        #[serde(borrow)]
        pub convo_id: jacquard_common::CowStr<'a>,
        #[serde(skip_serializing_if = "Option::is_none")]
        #[serde(borrow)]
        pub status: Option<jacquard_common::CowStr<'a>>,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub limit: Option<i64>,
        #[serde(skip_serializing_if = "Option::is_none", default)]
        #[serde(borrow)]
        pub extra_data: Option<jacquard_common::types::value::Data<'a>>,
    }

    #[derive(
        serde::Serialize,
        serde::Deserialize,
        Debug,
        Clone,
        PartialEq,
        Eq,
        jacquard_derive::IntoStatic,
    )]
    #[serde(rename_all = "camelCase")]
    pub struct GetReportsOutput<'a> {
        #[serde(borrow)]
        pub reports: Vec<ReportView<'a>>,
        #[serde(skip_serializing_if = "Option::is_none", default)]
        #[serde(borrow)]
        pub extra_data: Option<jacquard_common::types::value::Data<'a>>,
    }

    #[derive(
        serde::Serialize,
        serde::Deserialize,
        Debug,
        Clone,
        PartialEq,
        Eq,
        jacquard_derive::IntoStatic,
    )]
    #[serde(rename_all = "camelCase")]
    pub struct ReportView<'a> {
        #[serde(borrow)]
        pub id: jacquard_common::CowStr<'a>,
        #[serde(borrow)]
        pub reporter_did: jacquard_common::types::string::Did<'a>,
        #[serde(borrow)]
        pub reported_did: jacquard_common::types::string::Did<'a>,
        #[serde(borrow)]
        pub encrypted_content: jacquard_common::CowStr<'a>,
        pub created_at: jacquard_common::types::string::Datetime,
        #[serde(borrow)]
        pub status: jacquard_common::CowStr<'a>,
        #[serde(skip_serializing_if = "Option::is_none")]
        #[serde(borrow)]
        pub resolved_by: Option<jacquard_common::types::string::Did<'a>>,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub resolved_at: Option<jacquard_common::types::string::Datetime>,
        #[serde(skip_serializing_if = "Option::is_none", default)]
        #[serde(borrow)]
        pub extra_data: Option<jacquard_common::types::value::Data<'a>>,
    }
}

// ── request_key_package_replenish ──

pub mod request_key_package_replenish {
    #[derive(
        serde::Serialize,
        serde::Deserialize,
        Debug,
        Clone,
        PartialEq,
        Eq,
        jacquard_derive::IntoStatic,
    )]
    #[serde(rename_all = "camelCase")]
    pub struct RequestKeyPackageReplenish<'a> {
        #[serde(borrow)]
        pub dids: Vec<jacquard_common::types::string::Did<'a>>,
        #[serde(skip_serializing_if = "Option::is_none")]
        #[serde(borrow)]
        pub reason: Option<jacquard_common::CowStr<'a>>,
        #[serde(skip_serializing_if = "Option::is_none")]
        #[serde(borrow)]
        pub convo_id: Option<jacquard_common::CowStr<'a>>,
        #[serde(skip_serializing_if = "Option::is_none", default)]
        #[serde(borrow)]
        pub extra_data: Option<jacquard_common::types::value::Data<'a>>,
    }
}

// ── resolve_delivery_service ──

pub mod resolve_delivery_service {
    #[derive(
        serde::Serialize,
        serde::Deserialize,
        Debug,
        Clone,
        PartialEq,
        Eq,
        jacquard_derive::IntoStatic,
    )]
    #[serde(rename_all = "camelCase")]
    pub struct ResolveDeliveryServiceOutput<'a> {
        #[serde(borrow)]
        pub did: jacquard_common::types::string::Did<'a>,
        #[serde(borrow)]
        pub endpoint: jacquard_common::CowStr<'a>,
        #[serde(skip_serializing_if = "Option::is_none")]
        #[serde(borrow)]
        pub supported_cipher_suites: Option<Vec<jacquard_common::CowStr<'a>>>,
        #[serde(skip_serializing_if = "Option::is_none", default)]
        #[serde(borrow)]
        pub extra_data: Option<jacquard_common::types::value::Data<'a>>,
    }
}

// ── DS (federation) sub-module ──────────────────────────────────────────────

pub mod ds {
    pub mod deliver_message {
        #[derive(
            serde::Serialize,
            serde::Deserialize,
            Debug,
            Clone,
            PartialEq,
            Eq,
            jacquard_derive::IntoStatic,
        )]
        #[serde(rename_all = "camelCase")]
        pub struct DeliverMessage<'a> {
            #[serde(borrow)]
            pub convo_id: jacquard_common::CowStr<'a>,
            #[serde(borrow)]
            pub msg_id: jacquard_common::CowStr<'a>,
            pub epoch: i64,
            #[serde(borrow)]
            pub sender_ds_did: jacquard_common::CowStr<'a>,
            #[serde(with = "jacquard_common::serde_bytes_helper")]
            pub ciphertext: bytes::Bytes,
            pub padded_size: i64,
            #[serde(skip_serializing_if = "Option::is_none")]
            #[serde(borrow)]
            pub message_type: Option<jacquard_common::CowStr<'a>>,
            #[serde(skip_serializing_if = "Option::is_none", default)]
            #[serde(borrow)]
            pub extra_data: Option<jacquard_common::types::value::Data<'a>>,
        }
    }

    pub mod deliver_welcome {
        #[derive(
            serde::Serialize,
            serde::Deserialize,
            Debug,
            Clone,
            PartialEq,
            Eq,
            jacquard_derive::IntoStatic,
        )]
        #[serde(rename_all = "camelCase")]
        pub struct DeliverWelcome<'a> {
            #[serde(borrow)]
            pub convo_id: jacquard_common::CowStr<'a>,
            #[serde(borrow)]
            pub recipient_did: jacquard_common::CowStr<'a>,
            #[serde(borrow)]
            pub sender_ds_did: jacquard_common::CowStr<'a>,
            #[serde(borrow)]
            pub key_package_hash: jacquard_common::CowStr<'a>,
            #[serde(with = "jacquard_common::serde_bytes_helper")]
            pub welcome_data: bytes::Bytes,
            pub initial_epoch: i64,
            #[serde(skip_serializing_if = "Option::is_none")]
            #[serde(borrow)]
            pub group_info: Option<jacquard_common::CowStr<'a>>,
            #[serde(skip_serializing_if = "Option::is_none", default)]
            #[serde(borrow)]
            pub extra_data: Option<jacquard_common::types::value::Data<'a>>,
        }
    }

    pub mod submit_commit {
        #[derive(
            serde::Serialize,
            serde::Deserialize,
            Debug,
            Clone,
            PartialEq,
            Eq,
            jacquard_derive::IntoStatic,
        )]
        #[serde(rename_all = "camelCase")]
        pub struct SubmitCommit<'a> {
            #[serde(borrow)]
            pub convo_id: jacquard_common::CowStr<'a>,
            #[serde(borrow)]
            pub sender_ds_did: jacquard_common::CowStr<'a>,
            pub epoch: i64,
            pub proposed_epoch: i64,
            #[serde(with = "jacquard_common::serde_bytes_helper")]
            pub commit_data: bytes::Bytes,
            #[serde(skip_serializing_if = "Option::is_none", default)]
            #[serde(borrow)]
            pub extra_data: Option<jacquard_common::types::value::Data<'a>>,
        }
    }

    pub mod transfer_sequencer {
        #[derive(
            serde::Serialize,
            serde::Deserialize,
            Debug,
            Clone,
            PartialEq,
            Eq,
            jacquard_derive::IntoStatic,
        )]
        #[serde(rename_all = "camelCase")]
        pub struct TransferSequencer<'a> {
            #[serde(borrow)]
            pub convo_id: jacquard_common::CowStr<'a>,
            pub current_epoch: i64,
            #[serde(skip_serializing_if = "Option::is_none", default)]
            #[serde(borrow)]
            pub extra_data: Option<jacquard_common::types::value::Data<'a>>,
        }
    }
}
