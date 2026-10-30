//! Focused C04 wire audit using the exported production verifier, not the
//! legacy source-inclusion test harness. Requires retained real XWING bytes.
use catbird_server::chat_protocol::wire::{validate_welcome, WireValidationError};
use tls_codec::{Deserialize, Serialize, VLBytes};

// RFC 9420 framing mirror for controlled malformed-input construction only.
#[derive(Clone, Debug, tls_codec::TlsSerialize, tls_codec::TlsDeserialize, tls_codec::TlsSize)]
struct Envelope {
    version: u16,
    wire_format: u16,
    welcome: Welcome,
}
#[derive(Clone, Debug, tls_codec::TlsSerialize, tls_codec::TlsDeserialize, tls_codec::TlsSize)]
struct Welcome {
    ciphersuite: u16,
    secrets: Vec<Secret>,
    encrypted_group_info: VLBytes,
}
#[derive(Clone, Debug, tls_codec::TlsSerialize, tls_codec::TlsDeserialize, tls_codec::TlsSize)]
struct Secret {
    new_member: VLBytes,
    encrypted_group_secrets: Ciphertext,
}
#[derive(Clone, Debug, tls_codec::TlsSerialize, tls_codec::TlsDeserialize, tls_codec::TlsSize)]
struct Ciphertext {
    kem_output: VLBytes,
    ciphertext: VLBytes,
}

#[test]
fn maximum_common_welcome_rejects_duplicate_refs_without_changing_cardinality() {
    let root = std::env::var("T02_CORPUS_DIR").expect("retained real XWING corpus required");
    let raw = std::fs::read(std::path::Path::new(&root).join("leaves-40/welcome.mls")).unwrap();
    let maximum = 1_048_576;
    let valid = validate_welcome(&raw, maximum).expect("real maximum common Welcome");
    assert_eq!(valid.key_package_refs().len(), 39);
    let original = Envelope::tls_deserialize_exact(&raw).unwrap();
    assert_eq!(original.tls_serialize_detached().unwrap(), raw);
    assert_eq!(original.welcome.secrets.len(), 39);

    let mut duplicate = original.clone();
    duplicate.welcome.secrets[38].new_member = duplicate.welcome.secrets[0].new_member.clone();
    assert_eq!(duplicate.welcome.secrets.len(), 39);
    assert_eq!(
        validate_welcome(&duplicate.tls_serialize_detached().unwrap(), maximum),
        Err(WireValidationError::DuplicateWelcomeKeyPackageRef)
    );
    let mut malformed = original.clone();
    malformed.welcome.secrets[0].new_member = vec![0; 31].into();
    assert_eq!(
        validate_welcome(&malformed.tls_serialize_detached().unwrap(), maximum),
        Err(WireValidationError::WrongWelcomeKeyPackageRefLength { actual: 31 })
    );
    let mut empty = original;
    empty.welcome.secrets.clear();
    assert_eq!(
        validate_welcome(&empty.tls_serialize_detached().unwrap(), maximum),
        Err(WireValidationError::EmptyWelcome)
    );
}
