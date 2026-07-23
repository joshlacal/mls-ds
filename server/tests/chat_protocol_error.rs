#[path = "../src/chat_protocol/error.rs"]
mod error;

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::PathBuf;

use error::{ChatEndpoint, ChatProtocolErrorCode, EndpointProtocolError, ErrorExposure};

fn frozen_lexicon_contracts() -> BTreeMap<String, BTreeSet<String>> {
    let lexicon_dir =
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../lexicon/blue/catbird/chat");
    let mut contracts = BTreeMap::new();

    for entry in fs::read_dir(lexicon_dir).expect("read frozen chat lexicons") {
        let path = entry.expect("read lexicon directory entry").path();
        if path.extension().and_then(|value| value.to_str()) != Some("json") {
            continue;
        }
        let document: serde_json::Value =
            serde_json::from_slice(&fs::read(path).expect("read frozen lexicon"))
                .expect("parse frozen lexicon");
        let Some(endpoint_errors) = document
            .pointer("/defs/main/errors")
            .and_then(serde_json::Value::as_array)
        else {
            continue;
        };
        let nsid = document
            .get("id")
            .and_then(serde_json::Value::as_str)
            .expect("lexicon NSID")
            .to_owned();
        let mut errors = BTreeSet::new();
        for endpoint_error in endpoint_errors {
            errors.insert(
                endpoint_error
                    .get("name")
                    .and_then(serde_json::Value::as_str)
                    .expect("lexicon error name")
                    .to_owned(),
            );
        }
        contracts.insert(nsid, errors);
    }
    contracts
}

#[test]
fn typed_public_error_vocabulary_exactly_matches_frozen_lexicons() {
    let declared = frozen_lexicon_contracts()
        .into_values()
        .flatten()
        .collect::<BTreeSet<_>>();
    let implemented = ChatProtocolErrorCode::ALL
        .iter()
        .map(|error| error.as_str().to_owned())
        .collect::<BTreeSet<_>>();

    assert_eq!(implemented, declared);
    for code in declared {
        let parsed: ChatProtocolErrorCode = code.parse().expect("known frozen error");
        assert_eq!(parsed.as_str(), code);
        assert_eq!(
            serde_json::to_string(&parsed).unwrap(),
            format!("\"{code}\"")
        );
    }
    assert!("MadeUpProtocolError"
        .parse::<ChatProtocolErrorCode>()
        .is_err());
}

#[test]
fn endpoint_scopes_exactly_match_frozen_lexicons_and_cannot_be_invented() {
    let frozen = frozen_lexicon_contracts();
    let implemented_nsids = ChatEndpoint::ALL
        .iter()
        .map(|endpoint| endpoint.nsid().to_owned())
        .collect::<BTreeSet<_>>();
    assert_eq!(
        implemented_nsids,
        frozen.keys().cloned().collect::<BTreeSet<_>>()
    );

    for endpoint in ChatEndpoint::ALL.iter().copied() {
        assert_eq!(endpoint.nsid().parse::<ChatEndpoint>().unwrap(), endpoint);
        let expected = frozen
            .get(endpoint.nsid())
            .expect("implemented endpoint is frozen")
            .iter()
            .map(|code| code.parse::<ChatProtocolErrorCode>().unwrap())
            .collect::<BTreeSet<_>>();
        let implemented = endpoint
            .declared_errors()
            .iter()
            .copied()
            .collect::<BTreeSet<_>>();
        assert_eq!(implemented, expected, "{} error scope", endpoint.nsid());

        for code in ChatProtocolErrorCode::ALL.iter().copied() {
            assert_eq!(
                EndpointProtocolError::new(endpoint, code).is_ok(),
                expected.contains(&code),
                "{} must not invent {}",
                endpoint.nsid(),
                code
            );
        }
    }

    assert!("blue.catbird.chat.unknown".parse::<ChatEndpoint>().is_err());
    let rejected = EndpointProtocolError::new(
        ChatEndpoint::AcceptConversation,
        ChatProtocolErrorCode::BlobNotFound,
    )
    .unwrap_err();
    assert_eq!(rejected.endpoint(), ChatEndpoint::AcceptConversation);
    assert_eq!(rejected.code(), ChatProtocolErrorCode::BlobNotFound);
}

#[test]
fn internal_failures_never_expose_artifacts_as_protocol_codes() {
    let public = EndpointProtocolError::new(
        ChatEndpoint::AcceptConversation,
        ChatProtocolErrorCode::InvalidRequest,
    )
    .unwrap();
    assert_eq!(public.endpoint(), ChatEndpoint::AcceptConversation);
    assert_eq!(
        ErrorExposure::Protocol(public).public_code(),
        Some(ChatProtocolErrorCode::InvalidRequest)
    );
    assert_eq!(ErrorExposure::Protocol(public).public_error(), Some(public));
    assert_eq!(ErrorExposure::InvariantViolation.public_code(), None);
    assert_eq!(ErrorExposure::StorageFailure.public_code(), None);
}

#[test]
fn only_frozen_transient_errors_are_marked_retryable() {
    let retryable = ChatProtocolErrorCode::ALL
        .iter()
        .copied()
        .filter(ChatProtocolErrorCode::is_retryable)
        .collect::<BTreeSet<_>>();

    assert_eq!(
        retryable,
        BTreeSet::from([ChatProtocolErrorCode::RelationshipPolicyUnavailable])
    );
}
